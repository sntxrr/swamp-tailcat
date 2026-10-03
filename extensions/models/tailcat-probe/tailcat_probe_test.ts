import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
} from "jsr:@std/assert@1";
import { z } from "npm:zod@4";
import {
  fingerprint,
  model,
  parseGoDurationMs,
  parsePongs,
  redactAddress,
  runTailcat,
  stdoutHeadOf,
  summarisePerf,
} from "./tailcat_probe.ts";

/** Fictional, well-formed-looking address. Never a real one. */
const ADDRESS = "tcEXAMPLEexampleEXAMPLEexample0000";

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/**
 * A fake tailcat binary. Tests exercise the REAL subprocess boundary — argv
 * construction, environment, exit codes and parsing all execute for real.
 */
async function fakeTailcat(
  script: string,
): Promise<{ path: string; cleanup: () => void }> {
  const dir = await Deno.makeTempDir({ prefix: "tailcat-test-" });
  const path = `${dir}/tailcat`;
  await Deno.writeTextFile(path, `#!/bin/sh\n${script}\n`);
  await Deno.chmod(path, 0o755);
  return { path, cleanup: () => Deno.removeSync(dir, { recursive: true }) };
}

interface Written {
  spec: string;
  instance: string;
  data: Record<string, unknown>;
}

/** writeResource VALIDATES against the real schema; a recorder hides bugs. */
function makeContext(
  globalArgs: Record<string, unknown>,
): { context: never; written: Written[]; logs: string[] } {
  const written: Written[] = [];
  const logs: string[] = [];
  const resources = model.resources as Record<string, { schema: z.ZodType }>;
  const context = {
    globalArgs,
    logger: {
      info: (m: string, p?: unknown) => logs.push(m + JSON.stringify(p ?? {})),
      warn: (m: string, p?: unknown) => logs.push(m + JSON.stringify(p ?? {})),
    },
    writeResource(
      spec: string,
      instance: string,
      data: Record<string, unknown>,
    ) {
      const definition = resources[spec];
      if (!definition) throw new Error(`unknown resource "${spec}"`);
      const parsed = definition.schema.safeParse(data);
      if (!parsed.success) {
        throw new Error(
          `resource written to "${spec}" failed validation: ` +
            JSON.stringify(parsed.error.issues),
        );
      }
      written.push({ spec, instance, data });
      return Promise.resolve({ name: instance });
    },
  };
  return { context: context as never, written, logs };
}

// deno-lint-ignore no-explicit-any
const methods = model.methods as any;

function globalsFor(binary: string): Record<string, unknown> {
  return { target: "heron", address: ADDRESS, tailcatBinary: binary };
}

/** No persisted value may contain the address. */
function assertNoAddress(written: Written[]) {
  const all = JSON.stringify(written);
  assert(!all.includes(ADDRESS), `address leaked into a resource: ${all}`);
}

// ---------------------------------------------------------------------------
// Runner safety
// ---------------------------------------------------------------------------

for (const sub of ["serve", "forward", "socks", "browse", "recv", "genkey"]) {
  Deno.test(`runner refuses long-running/key-writing subcommand "${sub}"`, async () => {
    await assertRejects(
      () => runTailcat(ADDRESS, [], [sub, ADDRESS], { binary: "/bin/false" }),
      Error,
      "not a one-shot subcommand",
    );
  });
}

Deno.test("runner redacts the address from stdout and stderr", async () => {
  const fake = await fakeTailcat('echo "out $*"; echo "err $*" >&2');
  try {
    const run = await runTailcat(ADDRESS, [], ["ping", ADDRESS], {
      binary: fake.path,
    });
    assert(!run.stdout.includes(ADDRESS));
    assert(!run.stderr.includes(ADDRESS));
    assertStringIncludes(run.stdout, "<tc-addr>");
  } finally {
    fake.cleanup();
  }
});

Deno.test("runner closes stdin so ssh/scp cannot block", async () => {
  const fake = await fakeTailcat('cat; echo "eof"');
  try {
    const run = await runTailcat(ADDRESS, [], ["ssh", ADDRESS, "true"], {
      binary: fake.path,
      timeoutMs: 5000,
    });
    assertEquals(run.timedOut, false);
    assertStringIncludes(run.stdout, "eof");
  } finally {
    fake.cleanup();
  }
});

Deno.test("runner passes no unrelated parent environment", async () => {
  Deno.env.set("TAILCAT_TEST_UNRELATED", "leak");
  const fake = await fakeTailcat('echo "V:${TAILCAT_TEST_UNRELATED:-none}"');
  try {
    const run = await runTailcat(ADDRESS, [], ["ping", ADDRESS], {
      binary: fake.path,
    });
    assertStringIncludes(run.stdout, "V:none");
  } finally {
    Deno.env.delete("TAILCAT_TEST_UNRELATED");
    fake.cleanup();
  }
});

Deno.test("runner places --key before the subcommand", async () => {
  const fake = await fakeTailcat('echo "$*"');
  try {
    const run = await runTailcat(ADDRESS, ["--json"], ["perf", ADDRESS], {
      binary: fake.path,
      clientKey: "probe",
    });
    assertEquals(run.stdout.trim(), "--key=probe --json perf <tc-addr>");
  } finally {
    fake.cleanup();
  }
});

Deno.test("runner kills a hung process at the timeout", async () => {
  const fake = await fakeTailcat("sleep 30");
  try {
    const run = await runTailcat(ADDRESS, [], ["ping", ADDRESS], {
      binary: fake.path,
      timeoutMs: 200,
    });
    assertEquals(run.timedOut, true);
  } finally {
    fake.cleanup();
  }
});

Deno.test("address schema rejects a value that would parse as a flag", () => {
  const schema = model.globalArguments;
  assert(!schema.safeParse({ target: "heron", address: "--key=x" }).success);
  assert(schema.safeParse({ target: "heron", address: ADDRESS }).success);
});

// ---------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------

Deno.test("parseGoDurationMs handles Go duration forms", () => {
  assertEquals(parseGoDurationMs("1.2ms"), 1.2);
  assertEquals(parseGoDurationMs("850µs"), 0.85);
  assertEquals(parseGoDurationMs("1m2.5s"), 62_500);
  assertEquals(parseGoDurationMs("1.2xs"), null);
});

Deno.test("parsePongs distinguishes direct and DERP paths", () => {
  const pongs = parsePongs(
    "pong in 42.1ms via DERP(sfo)\npong in 1.2ms via 203.0.113.7:41641\n",
  );
  assertEquals(pongs.length, 2);
  assertEquals(pongs[0], {
    rttMs: 42.1,
    direct: false,
    endpoint: null,
    derpRegion: "sfo",
  });
  assertEquals(pongs[1].direct, true);
  assertEquals(pongs[1].endpoint, "203.0.113.7:41641");
});

Deno.test("summarisePerf uses receiver stats and drops intervals", () => {
  const s = summarisePerf({
    path: { direct: true, endpoint: "203.0.113.7:41641", rtt: 2_000_000 },
    params: { proto: "tcp", dir: "up", streams: 1 },
    clientSent: { bytes: 2_000_000_000, duration: 10e9 },
    serverReceived: { bytes: 1_000_000_000, duration: 10e9 },
    rtt: { min: 1e6, avg: 2e6, max: 5e6, count: 10 },
  });
  assertEquals(s.uploadBps, 800_000_000);
  assertEquals(s.downloadBps, null);
  assertEquals(s.rttAvgMs, 2);
  assertEquals(s.pathRttMs, 2);
  assert(!("intervals" in s));
});

Deno.test("fingerprint is 12 hex chars and stable", async () => {
  const fp = await fingerprint(ADDRESS);
  assertEquals(fp.length, 12);
  assertEquals(fp, await fingerprint(ADDRESS));
  assertEquals(redactAddress(`a ${ADDRESS} b`, ADDRESS), "a <tc-addr> b");
});

// ---------------------------------------------------------------------------
// Methods
// ---------------------------------------------------------------------------

Deno.test("ping records a direct path", async () => {
  const fake = await fakeTailcat('echo "pong in 1.2ms via 203.0.113.7:41641"');
  try {
    const { context, written } = makeContext(globalsFor(fake.path));
    await methods.ping.execute({}, context);
    assertEquals(written.length, 1);
    assertEquals(written[0].instance, "ping");
    assertEquals(written[0].data.ok, true);
    assertEquals(written[0].data.direct, true);
    assertEquals(written[0].data.rttMs, 1.2);
    assertNoAddress(written);
  } finally {
    fake.cleanup();
  }
});

Deno.test("ping records an unreachable server instead of throwing", async () => {
  const fake = await fakeTailcat(
    'echo "ping: dial failed for $3" >&2; exit 1',
  );
  try {
    const { context, written } = makeContext(globalsFor(fake.path));
    await methods.ping.execute({}, context);
    assertEquals(written[0].data.ok, false);
    assertEquals(written[0].data.pongs, 0);
    assertStringIncludes(String(written[0].data.failure), "dial failed");
    assertNoAddress(written);
  } finally {
    fake.cleanup();
  }
});

Deno.test("perf writes a summary with no per-second samples", async () => {
  const json = JSON.stringify({
    path: { direct: true, endpoint: "203.0.113.7:41641", rtt: 2e6 },
    params: { proto: "tcp", dir: "down", streams: 2 },
    serverSent: { bytes: 5e8, duration: 10e9, intervals: [{ bytes: 1 }] },
    clientReceived: { bytes: 5e8, duration: 10e9, intervals: [{ bytes: 1 }] },
  });
  const fake = await fakeTailcat(`echo '${json}'`);
  try {
    const { context, written } = makeContext(globalsFor(fake.path));
    await methods.perf.execute({ direction: "download" }, context);
    const data = written[0].data;
    assertEquals(data.ok, true);
    assertEquals(data.downloadBps, 400_000_000);
    assert(!JSON.stringify(data).includes("intervals"));
    assertNoAddress(written);
  } finally {
    fake.cleanup();
  }
});

Deno.test("perf passes --reverse for download and --interval=0", async () => {
  const fake = await fakeTailcat('echo "$*" >&2; exit 1');
  try {
    const { context, written } = makeContext(globalsFor(fake.path));
    await methods.perf.execute({ direction: "download", udp: true }, context);
    const failure = String(written[0].data.failure);
    assertStringIncludes(failure, "--json perf --udp --reverse");
    assertStringIncludes(failure, "--interval=0");
    // Default 10 s path timeout, offset so tailcat can return a relayed path.
    assertStringIncludes(failure, "--timeout=10500ms");
    assertEquals(written[0].data.ok, false);
  } finally {
    fake.cleanup();
  }
});

Deno.test("transfer receive records size and hash, never content", async () => {
  const dir = await Deno.makeTempDir();
  const dest = `${dir}/got.txt`;
  // Fake scp: the last argument is the local destination.
  const fake = await fakeTailcat(
    'for a; do last="$a"; done; printf "secret-body" > "$last"',
  );
  try {
    const { context, written } = makeContext(globalsFor(fake.path));
    await methods.transfer.execute(
      { direction: "receive", localPath: dest, remotePath: "got.txt" },
      context,
    );
    const data = written[0].data;
    assertEquals(data.ok, true);
    assertEquals(data.bytes, 11);
    assertEquals(String(data.sha256).length, 64);
    assert(!JSON.stringify(data).includes("secret-body"));
    assertNoAddress(written);
  } finally {
    fake.cleanup();
    Deno.removeSync(dir, { recursive: true });
  }
});

Deno.test("exec stores hash only unless capture is requested", async () => {
  const fake = await fakeTailcat('echo "hello from remote"; exit 3');
  try {
    const { context, written } = makeContext(globalsFor(fake.path));
    await methods.exec.execute({ command: ["uptime"] }, context);
    await methods.exec.execute(
      { command: ["uptime"], captureStdoutBytes: 5 },
      context,
    );
    assertEquals(written[0].data.exitCode, 3);
    assertEquals(written[0].data.ok, false);
    assertEquals(written[0].data.stdoutHead, null);
    assertEquals(written[1].data.stdoutHead, "hello");
    assertEquals(written[1].data.stdoutTruncated, true);
    assertEquals(written[0].data.stdoutTruncated, false);
    assertNoAddress(written);
  } finally {
    fake.cleanup();
  }
});

Deno.test("every resource sets lifetime and garbageCollection", () => {
  for (const [name, spec] of Object.entries(model.resources)) {
    assert(
      (spec.lifetime as string) !== "infinite",
      `${name} keeps versions forever`,
    );
    assert(spec.garbageCollection > 0, `${name} has no GC`);
  }
});

Deno.test("each method writes its own data name, so data.latest is unambiguous", async () => {
  // A shared instance name (e.g. the target) would make every method a new
  // version of one data item, and mix their GC counts.
  const fake = await fakeTailcat(
    'case "$1" in ping) echo "pong in 1ms via 203.0.113.7:41641";; ' +
      '--json) echo \'{"path":{"direct":true,"rtt":1},"params":{"proto":"tcp","dir":"up","streams":1}}\';; ' +
      'cp) for a; do last="$a"; done; printf x > "$last";; *) echo hi;; esac',
  );
  const dir = await Deno.makeTempDir();
  try {
    const { context, written, logs } = makeContext(globalsFor(fake.path));
    await methods.ping.execute({}, context);
    await methods.perf.execute({}, context);
    await methods.transfer.execute(
      { direction: "receive", localPath: `${dir}/x`, remotePath: "x" },
      context,
    );
    await methods.exec.execute({ command: ["true"] }, context);
    assertEquals(
      written.map((w) => `${w.spec}/${w.instance}`),
      ["ping/ping", "perf/perf", "transfer/transfer", "exec/exec"],
    );
    assertEquals(logs.length, 8, "entry + completion log per method");
    assert(!logs.join("\n").includes(ADDRESS), "address leaked into a log");
  } finally {
    fake.cleanup();
    Deno.removeSync(dir, { recursive: true });
  }
});

// deno-lint-ignore no-explicit-any
const checks = model.checks as any;

Deno.test("pre-flight check passes when tailcat runs", async () => {
  const fake = await fakeTailcat('[ "$1" = version ] && echo v0.0.0-test');
  try {
    const result = await checks["tailcat-binary-runs"].execute({
      globalArgs: globalsFor(fake.path),
    });
    assertEquals(result, { pass: true });
  } finally {
    fake.cleanup();
  }
});

Deno.test("pre-flight check fails on a missing or broken binary", async () => {
  const missing = await checks["tailcat-binary-runs"].execute({
    globalArgs: globalsFor("/nonexistent/tailcat"),
  });
  assertEquals(missing.pass, false);
  assertStringIncludes(missing.errors[0], "cannot run /nonexistent/tailcat");

  const fake = await fakeTailcat("exit 2");
  try {
    const broken = await checks["tailcat-binary-runs"].execute({
      globalArgs: globalsFor(fake.path),
    });
    assertEquals(broken.pass, false);
    assertStringIncludes(broken.errors[0], "exited 2");
  } finally {
    fake.cleanup();
  }
});

Deno.test("stdoutHeadOf cuts by bytes, flags truncation, never exposes the raw address", () => {
  assertEquals(stdoutHeadOf("héllo", 2), { text: "h\uFFFD", truncated: true });
  assertEquals(stdoutHeadOf("hi", 64), { text: "hi", truncated: false });
  assertEquals(stdoutHeadOf("hi", 0), { text: null, truncated: false });
  const redacted = redactAddress(`token ${ADDRESS} end`, ADDRESS);
  assert(!String(stdoutHeadOf(redacted, 64).text).includes(ADDRESS));
});
