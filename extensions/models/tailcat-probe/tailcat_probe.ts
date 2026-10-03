/**
 * Probe a tailcat server: reachability and path, throughput, a file transfer
 * round-trip, and a remote command — each recorded as one small summary.
 *
 * tailcat (github.com/tailscale/tailcat) is netcat over Tailscale's data plane
 * without its control plane. A tailcat address carries the server's WireGuard
 * key and pre-shared key, so the address IS the credential. This model treats
 * it that way: it is a sensitive global argument, it is redacted from every
 * captured stream, and only a SHA-256 fingerprint of it is ever persisted.
 *
 * Scope is deliberately one-shot. tailcat's long-running modes (`serve`,
 * `forward`, `socks`, `browse`, `recv`, interactive `ssh`) block until
 * interrupted; a method cannot own their lifecycle and would record nothing
 * worth keeping. Run a server as a service unit; probe it with this model.
 *
 * Datastore footprint is a design constraint, not an afterthought: every
 * resource is a fixed-size summary. Per-second perf samples, file bodies and
 * command output are never stored — sizes and hashes are.
 *
 * @module
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// tailcat runner
// ---------------------------------------------------------------------------

/**
 * Subcommands this model may invoke. Everything else — notably `serve`,
 * `forward`, `socks`, `browse`, `recv` and `genkey` — is refused: those are
 * long-running, interactive, or write key material.
 */
const ALLOWED_SUBCOMMANDS = new Set(["ping", "perf", "cp", "ssh"]);

export interface TailcatRunOptions {
  binary?: string;
  /** Saved client key name or path, passed as `--key=`. */
  clientKey?: string;
  derpmapUrl?: string;
  timeoutMs?: number;
}

export interface TailcatResult {
  code: number;
  stdout: string;
  stdoutBytes: Uint8Array;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

/**
 * Run tailcat once, to completion.
 *
 * tailcat has no environment or file input for a client's address, so the
 * address must travel in argv and is visible in `ps` for the life of the
 * process. That exposure is accepted and bounded rather than hidden: the
 * README requires probe targets to run with `--allow=<client-nodekey>`, so the
 * address alone does not grant a connection. What this runner does enforce:
 *
 *  - Only one-shot subcommands run (see ALLOWED_SUBCOMMANDS).
 *  - stdin is closed, so `ssh`/`scp` can never block waiting on a terminal.
 *  - The address is redacted from stdout and stderr before they are returned.
 *  - The environment is explicit. HOME is passed because tailcat reads saved
 *    keys from the user config dir and wraps the system ssh/scp;
 *    SSH_AUTH_SOCK is passed for `serve ssh` targets that check public keys.
 */
export async function runTailcat(
  address: string,
  rootFlags: string[],
  args: string[],
  options: TailcatRunOptions = {},
): Promise<TailcatResult> {
  const subcommand = args[0];
  if (!subcommand || !ALLOWED_SUBCOMMANDS.has(subcommand)) {
    throw new Error(
      `tailcat "${subcommand ?? ""}" is not a one-shot subcommand this model ` +
        `runs; allowed: ${[...ALLOWED_SUBCOMMANDS].join(", ")}`,
    );
  }

  const argv = [
    ...(options.clientKey ? [`--key=${options.clientKey}`] : []),
    ...(options.derpmapUrl ? [`--derpmap-url=${options.derpmapUrl}`] : []),
    ...rootFlags,
    ...args,
  ];

  const env: Record<string, string> = {
    PATH: Deno.env.get("PATH") ?? "/usr/bin:/bin:/usr/local/bin",
  };
  for (const name of ["HOME", "XDG_CONFIG_HOME", "SSH_AUTH_SOCK", "USER"]) {
    const value = Deno.env.get(name);
    if (value) env[name] = value;
  }

  const timeoutMs = options.timeoutMs ?? 120_000;
  const started = Date.now();
  const decoder = new TextDecoder();

  const child = new Deno.Command(options.binary ?? "tailcat", {
    args: argv,
    env,
    clearEnv: true,
    stdin: "null",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const readers = [child.stdout.getReader(), child.stderr.getReader()];

  // Killing the child is not enough on its own: a grandchild (the ProxyCommand
  // tailcat hands to ssh) inherits the pipes and holds them open, so reading to
  // EOF would block until it exits. Cancel the readers as well.
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    try {
      child.kill("SIGKILL");
    } catch {
      // already exited
    }
    for (const reader of readers) reader.cancel().catch(() => {});
  }, timeoutMs);

  try {
    const [status, stdoutBytes, stderrBytes] = await Promise.all([
      child.status,
      drain(readers[0]),
      drain(readers[1]),
    ]);
    if (timedOut) {
      return {
        code: 124,
        stdout: "",
        stdoutBytes: new Uint8Array(),
        stderr: `tailcat timed out after ${timeoutMs}ms`,
        durationMs: Date.now() - started,
        timedOut: true,
      };
    }
    return {
      code: status.code,
      stdout: redactAddress(decoder.decode(stdoutBytes), address),
      stdoutBytes,
      stderr: redactAddress(decoder.decode(stderrBytes), address),
      durationMs: Date.now() - started,
      timedOut: false,
    };
  } finally {
    clearTimeout(timer);
  }
}

/** Read a stream to EOF, or until its reader is cancelled. */
async function drain(
  reader: ReadableStreamDefaultReader<Uint8Array>,
): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
  } catch {
    // cancelled on timeout
  }
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/** Replace every occurrence of the address with a fixed placeholder. */
export function redactAddress(text: string, address: string): string {
  return address.length > 0 ? text.replaceAll(address, "<tc-addr>") : text;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** First 12 hex chars of SHA-256 — enough to correlate, useless to connect. */
export async function fingerprint(value: string): Promise<string> {
  return (await sha256Hex(new TextEncoder().encode(value))).slice(0, 12);
}

export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes as Uint8Array<ArrayBuffer>,
  );
  return Array.from(
    new Uint8Array(digest),
    (b) => b.toString(16).padStart(2, "0"),
  ).join("");
}

const GO_DURATION_UNITS: Record<string, number> = {
  ns: 1e-6,
  us: 1e-3,
  "µs": 1e-3,
  "μs": 1e-3,
  ms: 1,
  s: 1000,
  m: 60_000,
  h: 3_600_000,
};

/** Parse a Go `time.Duration` string ("1.2ms", "850µs", "1m2.5s") to ms. */
export function parseGoDurationMs(text: string): number | null {
  const parts = [...text.matchAll(/(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/g)];
  if (parts.length === 0 || parts.map((p) => p[0]).join("") !== text) {
    return null;
  }
  return parts.reduce(
    (sum, [, n, unit]) => sum + Number(n) * GO_DURATION_UNITS[unit],
    0,
  );
}

export interface Pong {
  rttMs: number;
  direct: boolean;
  endpoint: string | null;
  derpRegion: string | null;
}

/** Parse `pong in <duration> via <endpoint|DERP(region)>` lines. */
export function parsePongs(stdout: string): Pong[] {
  const pongs: Pong[] = [];
  for (const m of stdout.matchAll(/^pong in (\S+) via (.+)$/gm)) {
    const rttMs = parseGoDurationMs(m[1]);
    if (rttMs === null) continue;
    const derp = m[2].match(/^DERP\((.+)\)$/);
    pongs.push({
      rttMs,
      direct: derp === null,
      endpoint: derp === null ? m[2] : null,
      derpRegion: derp === null ? null : derp[1],
    });
  }
  return pongs;
}

const NS_PER_MS = 1e6;

/** Bits per second from a perf Stats block, or null when absent or empty. */
function bitsPerSecond(stats: PerfStats | undefined): number | null {
  if (!stats || stats.duration <= 0) return null;
  return Math.round((stats.bytes * 8) / (stats.duration / 1e9));
}

interface PerfStats {
  bytes: number;
  datagrams?: number;
  duration: number;
  reordered?: number;
  jitter?: number;
}

interface PerfJson {
  path: {
    direct: boolean;
    endpoint?: string;
    derpRegion?: string;
    rtt: number;
  };
  params: { proto: string; dir: string; streams: number };
  clientSent?: PerfStats;
  serverReceived?: PerfStats;
  serverSent?: PerfStats;
  clientReceived?: PerfStats;
  rtt?: { min: number; avg: number; max: number; count: number };
}

/**
 * Reduce `tailcat --json perf` output to a fixed-size summary.
 *
 * Throughput is taken from the RECEIVER of each direction — what arrived, not
 * what was offered. The per-interval sample arrays (`Stats.intervals`) are
 * dropped on purpose: they grow with test length and are the single largest
 * thing this model could write to the datastore.
 */
export function summarisePerf(raw: PerfJson) {
  const receivers = [raw.serverReceived, raw.clientReceived].filter(
    (s): s is PerfStats => s !== undefined,
  );
  const jitters = receivers.map((s) => s.jitter ?? 0).filter((j) => j > 0);
  return {
    proto: raw.params.proto,
    direction: raw.params.dir,
    streams: raw.params.streams,
    direct: raw.path.direct,
    endpoint: raw.path.endpoint ?? null,
    derpRegion: raw.path.derpRegion ?? null,
    pathRttMs: raw.path.rtt / NS_PER_MS,
    uploadBps: bitsPerSecond(raw.serverReceived),
    downloadBps: bitsPerSecond(raw.clientReceived),
    uploadBytes: raw.serverReceived?.bytes ?? null,
    downloadBytes: raw.clientReceived?.bytes ?? null,
    rttMinMs: raw.rtt ? raw.rtt.min / NS_PER_MS : null,
    rttAvgMs: raw.rtt ? raw.rtt.avg / NS_PER_MS : null,
    rttMaxMs: raw.rtt ? raw.rtt.max / NS_PER_MS : null,
    jitterMs: jitters.length ? Math.max(...jitters) / NS_PER_MS : null,
    reordered: receivers.length
      ? receivers.reduce((n, s) => n + (s.reordered ?? 0), 0)
      : null,
  };
}

/** Last `max` characters of a stream — enough to see why it failed. */
function tail(text: string, max = 500): string | null {
  const trimmed = text.trim();
  return trimmed.length === 0 ? null : trimmed.slice(-max);
}

// ---------------------------------------------------------------------------
// Platform types
// ---------------------------------------------------------------------------

type Logger = {
  info: (message: string, props?: Record<string, unknown>) => void;
  warn: (message: string, props?: Record<string, unknown>) => void;
};

type ExecuteContext<G> = {
  globalArgs: G;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
};

type Handles = { dataHandles: Array<{ name: string }> };

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

/** No leading dash: a value starting with "-" would be parsed as a flag. */
const NotAFlag = z.string().min(1).regex(/^[^-\s]\S*$/, {
  message: "must not start with '-' or contain whitespace",
});

const GlobalArgsSchema = z.object({
  target: z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/).describe(
    "Non-secret label for the server, used as the resource instance name.",
  ),
  address: NotAFlag.meta({ sensitive: true }).describe(
    "The tailcat address (tc…) or a DNS name with a tailcat= TXT record. " +
      "This is a bearer credential — wire it from a vault.",
  ),
  tailcatBinary: z.string().default("tailcat").describe(
    "Path to the tailcat binary.",
  ),
  clientKey: NotAFlag.optional().describe(
    "Saved client key name or path (tailcat genkey --client). When unset, " +
      "tailcat uses 'client-default' if it exists, else an ephemeral key.",
  ),
  derpmapUrl: z.string().url().optional().describe(
    "Custom DERP map URL, for self-hosted relays.",
  ),
  timeoutSeconds: z.number().int().positive().default(120).describe(
    "Hard ceiling on any single tailcat run.",
  ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

const Common = {
  target: z.string(),
  addressFingerprint: z.string().describe(
    "First 12 hex chars of SHA-256(address). Changes when the server's key does.",
  ),
  ok: z.boolean(),
  failure: z.string().nullable().describe(
    "Why the run failed (redacted stderr tail), or null.",
  ),
  durationMs: z.number(),
  measuredAt: z.string(),
};

const PingSchema = z.object({
  ...Common,
  direct: z.boolean().nullable(),
  endpoint: z.string().nullable(),
  derpRegion: z.string().nullable(),
  rttMs: z.number().nullable(),
  pongs: z.number().int().describe(
    "Pongs received (>1 only with untilDirect).",
  ),
});

const PerfSchema = z.object({
  ...Common,
  proto: z.string().nullable(),
  direction: z.string().nullable(),
  streams: z.number().int().nullable(),
  direct: z.boolean().nullable(),
  endpoint: z.string().nullable(),
  derpRegion: z.string().nullable(),
  pathRttMs: z.number().nullable(),
  uploadBps: z.number().nullable(),
  downloadBps: z.number().nullable(),
  uploadBytes: z.number().nullable(),
  downloadBytes: z.number().nullable(),
  rttMinMs: z.number().nullable(),
  rttAvgMs: z.number().nullable(),
  rttMaxMs: z.number().nullable(),
  jitterMs: z.number().nullable(),
  reordered: z.number().nullable(),
});

const TransferSchema = z.object({
  ...Common,
  direction: z.enum(["send", "receive"]),
  localPath: z.string(),
  remotePath: z.string(),
  bytes: z.number().nullable(),
  sha256: z.string().nullable().describe(
    "Hash of the local copy; null when the file exceeds maxHashBytes.",
  ),
});

const ExecSchema = z.object({
  ...Common,
  command: z.array(z.string()),
  exitCode: z.number().int(),
  stdoutBytes: z.number().int(),
  stdoutSha256: z.string(),
  stdoutHead: z.string().nullable().describe(
    "First captureStdoutBytes of stdout, only when explicitly requested.",
  ),
});

const PingArgsSchema = z.object({
  untilDirect: z.boolean().default(false).describe(
    "Keep pinging until a direct (non-DERP) path is found; fail if none " +
      "appears within timeoutSeconds.",
  ),
  timeoutSeconds: z.number().int().positive().default(10),
});

const PerfArgsSchema = z.object({
  udp: z.boolean().default(false),
  direction: z.enum(["upload", "download", "both"]).default("upload"),
  seconds: z.number().int().min(1).max(300).default(10),
  parallel: z.number().int().min(1).max(64).default(1),
  bitrate: z.string().regex(/^\d+[KMG]?$/).optional().describe(
    "Per-stream target bitrate, e.g. 50M. Unset: unpaced TCP, 1M UDP.",
  ),
  viaDerp: z.boolean().default(false).describe(
    "Allow a relayed test. tailcat refuses this through Tailscale's shared " +
      "DERP relays regardless; it is only for relays you run.",
  ),
  pathTimeoutSeconds: z.number().int().positive().default(10),
});

const TransferArgsSchema = z.object({
  direction: z.enum(["send", "receive"]),
  localPath: NotAFlag,
  remotePath: z.string().regex(/^\S*$/).default("").describe(
    "Path relative to the served directory. Empty sends to its root.",
  ),
  maxHashBytes: z.number().int().positive().default(1_073_741_824),
});

const ExecArgsSchema = z.object({
  command: z.array(z.string()).min(1).describe(
    "Remote command and arguments. Required: interactive ssh is refused. " +
      "Stored verbatim in the resource, so never put a secret in it.",
  ),
  user: z.string().regex(/^[a-z_][a-z0-9_-]*$/).optional(),
  captureStdoutBytes: z.number().int().min(0).max(65_536).default(0).describe(
    "Store this many leading bytes of stdout. 0 stores only size and hash.",
  ),
});

// ---------------------------------------------------------------------------
// Method plumbing
// ---------------------------------------------------------------------------

function runOptionsOf(g: GlobalArgs, timeoutMs?: number): TailcatRunOptions {
  return {
    binary: g.tailcatBinary ?? "tailcat",
    clientKey: g.clientKey,
    derpmapUrl: g.derpmapUrl,
    timeoutMs: timeoutMs ?? (g.timeoutSeconds ?? 120) * 1000,
  };
}

async function commonOf(g: GlobalArgs, run: TailcatResult) {
  return {
    target: g.target,
    addressFingerprint: await fingerprint(g.address),
    ok: run.code === 0,
    failure: run.code === 0
      ? null
      : tail(run.stderr) ?? `tailcat exited ${run.code}`,
    durationMs: run.durationMs,
    measuredAt: new Date().toISOString(),
  };
}

async function fileDigest(
  path: string,
  maxHashBytes: number,
): Promise<{ bytes: number | null; sha256: string | null }> {
  try {
    const info = await Deno.stat(path);
    if (info.size > maxHashBytes) return { bytes: info.size, sha256: null };
    return {
      bytes: info.size,
      sha256: await sha256Hex(await Deno.readFile(path)),
    };
  } catch {
    return { bytes: null, sha256: null };
  }
}

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

export const model = {
  type: "@sntxrr/tailcat/probe",
  version: "2026.10.03.1",
  globalArguments: GlobalArgsSchema,

  // Retention is sized for an S3-backed datastore: every version is a PUT and
  // an index entry. Probes that may be scheduled keep a short tail; perf keeps
  // a longer one because it is run rarely and is the series worth trending.
  resources: {
    "ping": {
      description: "Reachability and path (direct or DERP) to one server",
      schema: PingSchema,
      lifetime: "7d" as const,
      garbageCollection: 5,
    },
    "perf": {
      description:
        "Throughput, RTT and jitter summary of one perf run — no per-second samples",
      schema: PerfSchema,
      lifetime: "30d" as const,
      garbageCollection: 20,
    },
    "transfer": {
      description:
        "Size and hash of one file sent or received — never its body",
      schema: TransferSchema,
      lifetime: "7d" as const,
      garbageCollection: 5,
    },
    "exec": {
      description: "Exit code, size and hash of one remote command's output",
      schema: ExecSchema,
      lifetime: "7d" as const,
      garbageCollection: 5,
    },
  },

  methods: {
    "ping": {
      description:
        "Disco-ping the server once (or until a direct path appears) and " +
        "record RTT and whether the path is direct or relayed. Records an " +
        "unreachable server instead of throwing.",
      arguments: PingArgsSchema,
      execute: async (
        args: z.infer<typeof PingArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<Handles> => {
        const g = context.globalArgs;
        const timeout = args.timeoutSeconds ?? 10;
        const run = await runTailcat(
          g.address,
          [],
          [
            "ping",
            ...(args.untilDirect ? ["--until-direct"] : []),
            `--timeout=${timeout}s`,
            g.address,
          ],
          runOptionsOf(g, (timeout + 15) * 1000),
        );
        const pongs = parsePongs(run.stdout);
        const last = pongs.at(-1);
        const handle = await context.writeResource("ping", g.target, {
          ...(await commonOf(g, run)),
          direct: last?.direct ?? null,
          endpoint: last?.endpoint ?? null,
          derpRegion: last?.derpRegion ?? null,
          rttMs: last?.rttMs ?? null,
          pongs: pongs.length,
        });
        return { dataHandles: [handle] };
      },
    },

    "perf": {
      description:
        "Run a bounded throughput test and record a fixed-size summary: " +
        "receiver-side bits/s per direction, control RTT, UDP jitter and " +
        "reordering, and the path used.",
      arguments: PerfArgsSchema,
      execute: async (
        args: z.infer<typeof PerfArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<Handles> => {
        const g = context.globalArgs;
        const seconds = args.seconds ?? 10;
        const pathTimeout = args.pathTimeoutSeconds ?? 10;
        const direction = args.direction ?? "upload";
        const run = await runTailcat(
          g.address,
          ["--json"],
          [
            "perf",
            ...(args.udp ? ["--udp"] : []),
            ...(direction === "download" ? ["--reverse"] : []),
            ...(direction === "both" ? ["--bidir"] : []),
            `--time=${seconds}s`,
            `--parallel=${args.parallel ?? 1}`,
            ...(args.bitrate ? [`--bitrate=${args.bitrate}`] : []),
            ...(args.viaDerp ? ["--via-derp"] : []),
            // tailcat (b4dc28e) pings for a path about once a second and
            // stops only when under 0.5 s remain. With a whole-second timeout
            // the last check lands at ~1.0 s, sleeps past the deadline, and a
            // relayed path fails as "no reply to pings". The extra 500 ms puts
            // the last check inside that window.
            `--timeout=${pathTimeout * 1000 + 500}ms`,
            "--interval=0",
            g.address,
          ],
          runOptionsOf(g, (seconds + pathTimeout + 30) * 1000),
        );

        let summary: ReturnType<typeof summarisePerf> | null = null;
        let parseError: string | null = null;
        if (run.code === 0) {
          try {
            summary = summarisePerf(
              JSON.parse(run.stdout.slice(run.stdout.indexOf("{"))),
            );
          } catch (e) {
            parseError = `unparseable perf JSON: ${(e as Error).message}`;
          }
        }
        const common = await commonOf(g, run);
        const handle = await context.writeResource("perf", g.target, {
          ...common,
          ok: common.ok && summary !== null,
          failure: common.failure ?? parseError,
          proto: summary?.proto ?? null,
          direction: summary?.direction ?? null,
          streams: summary?.streams ?? null,
          direct: summary?.direct ?? null,
          endpoint: summary?.endpoint ?? null,
          derpRegion: summary?.derpRegion ?? null,
          pathRttMs: summary?.pathRttMs ?? null,
          uploadBps: summary?.uploadBps ?? null,
          downloadBps: summary?.downloadBps ?? null,
          uploadBytes: summary?.uploadBytes ?? null,
          downloadBytes: summary?.downloadBytes ?? null,
          rttMinMs: summary?.rttMinMs ?? null,
          rttAvgMs: summary?.rttAvgMs ?? null,
          rttMaxMs: summary?.rttMaxMs ?? null,
          jitterMs: summary?.jitterMs ?? null,
          reordered: summary?.reordered ?? null,
        });
        return { dataHandles: [handle] };
      },
    },

    "transfer": {
      description:
        "Send a local file to, or fetch one from, a server running " +
        "`tailcat serve files` (or an SSH service), via the system scp. " +
        "Records size and SHA-256 of the local copy — never the content.",
      arguments: TransferArgsSchema,
      execute: async (
        args: z.infer<typeof TransferArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<Handles> => {
        const g = context.globalArgs;
        const remotePath = args.remotePath ?? "";
        const maxHashBytes = args.maxHashBytes ?? 1_073_741_824;
        const remote = `${g.address}:${remotePath}`;

        // Hash before sending (what we offered) or after receiving (what
        // arrived), so the recorded hash always describes a real local file.
        const before = args.direction === "send"
          ? await fileDigest(args.localPath, maxHashBytes)
          : null;
        const run = await runTailcat(
          g.address,
          [],
          args.direction === "send"
            ? ["cp", args.localPath, remote]
            : ["cp", remote, args.localPath],
          runOptionsOf(g),
        );
        const digest = before ??
          (run.code === 0
            ? await fileDigest(args.localPath, maxHashBytes)
            : { bytes: null, sha256: null });

        const handle = await context.writeResource("transfer", g.target, {
          ...(await commonOf(g, run)),
          direction: args.direction,
          localPath: args.localPath,
          remotePath,
          bytes: digest.bytes,
          sha256: digest.sha256,
        });
        return { dataHandles: [handle] };
      },
    },

    "exec": {
      description:
        "Run one non-interactive command over `tailcat ssh` and record its " +
        "exit code plus the size and SHA-256 of stdout. Stdout itself is " +
        "stored only up to captureStdoutBytes, which defaults to 0.",
      arguments: ExecArgsSchema,
      execute: async (
        args: z.infer<typeof ExecArgsSchema>,
        context: ExecuteContext<GlobalArgs>,
      ): Promise<Handles> => {
        const g = context.globalArgs;
        const capture = args.captureStdoutBytes ?? 0;
        const run = await runTailcat(
          g.address,
          [],
          [
            "ssh",
            args.user ? `${args.user}@${g.address}` : g.address,
            ...args.command,
          ],
          runOptionsOf(g),
        );
        const handle = await context.writeResource("exec", g.target, {
          ...(await commonOf(g, run)),
          command: args.command,
          exitCode: run.code,
          stdoutBytes: run.stdoutBytes.length,
          stdoutSha256: await sha256Hex(run.stdoutBytes),
          stdoutHead: capture > 0 ? run.stdout.slice(0, capture) : null,
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
