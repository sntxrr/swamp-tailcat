/**
 * End-to-end tests of @sntxrr/tailcat-probe against real tailcat servers and
 * a real DERP relay, inside the compose lab (see compose.yaml). Each case
 * runs a model method exactly as swamp would, with a resource writer that
 * validates against the real schema.
 */

import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  model,
  sha256Hex,
} from "../extensions/models/tailcat-probe/tailcat_probe.ts";

const SHARED = "/shared";
const DERPMAP_URL = Deno.env.get("DERPMAP_URL")!;

// deno-lint-ignore no-explicit-any
const methods = model.methods as any;
const resources = model.resources as Record<
  string,
  {
    schema: {
      safeParse: (d: unknown) => { success: boolean; error?: unknown };
    };
  }
>;

/**
 * Run one method against server `server` ("direct" or "relay") using client
 * key `key`, and return the single resource it wrote.
 */
async function probe(
  server: "direct" | "relay",
  key: string,
  method: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const address = (await Deno.readTextFile(`${SHARED}/addr-${server}`)).trim();
  const written: Record<string, unknown>[] = [];
  await methods[method].execute(args, {
    globalArgs: {
      target: server,
      address,
      tailcatBinary: "tailcat",
      clientKey: `${SHARED}/keys/${key}.private.json`,
      derpmapUrl: DERPMAP_URL,
      timeoutSeconds: 60,
    },
    logger: { info: () => {}, warn: () => {} },
    writeResource(spec: string, name: string, data: Record<string, unknown>) {
      const parsed = resources[spec].schema.safeParse(data);
      if (!parsed.success) {
        throw new Error(
          `${spec} failed schema: ${JSON.stringify(parsed.error)}`,
        );
      }
      written.push(data);
      return Promise.resolve({ name });
    },
  });
  assertEquals(written.length, 1);
  assert(
    !JSON.stringify(written[0]).includes(address),
    "the tailcat address leaked into a resource",
  );
  console.log(
    `  ${method}@${server} [${key}] -> ${JSON.stringify(written[0])}`,
  );
  return written[0];
}

// ---------------------------------------------------------------------------
// Direct path: probe and srv-direct share a network
// ---------------------------------------------------------------------------

Deno.test("direct: ping finds a direct path", async () => {
  const r = await probe("direct", "ping-direct", "ping", {
    untilDirect: true,
    timeoutSeconds: 30,
  });
  assertEquals(r.ok, true);
  assertEquals(r.direct, true);
  assertEquals(r.derpRegion, null);
});

Deno.test("direct: perf measures throughput over the direct path", async () => {
  const r = await probe("direct", "perf-direct", "perf", { seconds: 2 });
  assertEquals(r.ok, true);
  assertEquals(r.direct, true);
  assert((r.uploadBps as number) > 0);
});

Deno.test("direct: transfer receive hashes the fetched file", async () => {
  const expected = await sha256Hex(
    await Deno.readFile(`${SHARED}/served/canary.bin`),
  );
  const r = await probe("direct", "transfer", "transfer", {
    direction: "receive",
    remotePath: "canary.bin",
    localPath: "/tmp/canary.bin",
  });
  assertEquals(r.ok, true);
  assertEquals(r.bytes, 65536);
  assertEquals(r.sha256, expected);
});

Deno.test("direct: exec records stdout hash and head", async () => {
  const r = await probe("direct", "exec-echo", "exec", {
    command: ["echo", "hello-from-lab"],
    captureStdoutBytes: 64,
  });
  assertEquals(r.ok, true);
  assertEquals(r.exitCode, 0);
  assertEquals(r.stdoutHead, "hello-from-lab\n");
  assertEquals(
    r.stdoutSha256,
    await sha256Hex(new TextEncoder().encode("hello-from-lab\n")),
  );
});

Deno.test("direct: exec records a non-zero exit code", async () => {
  const r = await probe("direct", "exec-exit", "exec", { command: ["exit 7"] });
  assertEquals(r.ok, false);
  assertEquals(r.exitCode, 7);
});

Deno.test("direct: exec with the wrong ssh key is refused", async () => {
  const good = Deno.env.get("SSH_AUTH_SOCK")!;
  Deno.env.set("SSH_AUTH_SOCK", Deno.env.get("WRONG_AUTH_SOCK")!);
  try {
    const r = await probe("direct", "exec-wrong-ssh", "exec", {
      command: ["echo", "must-not-run"],
    });
    assertEquals(r.ok, false);
    assertStringIncludes(String(r.failure), "Permission denied");
  } finally {
    Deno.env.set("SSH_AUTH_SOCK", good);
  }
});

Deno.test("direct: a client key outside --allow is refused", async () => {
  const r = await probe("direct", "denied", "ping", { timeoutSeconds: 8 });
  assertEquals(r.ok, false);
  assertEquals(r.pongs, 0);
});

// ---------------------------------------------------------------------------
// Relayed path: probe and srv-relay share no network; only derper bridges them
// ---------------------------------------------------------------------------

Deno.test("relay: ping succeeds through the lab DERP region", async () => {
  const r = await probe("relay", "ping-relay", "ping", { timeoutSeconds: 20 });
  assertEquals(r.ok, true);
  assertEquals(r.direct, false);
  assertEquals(r.derpRegion, "lab");
});

Deno.test("relay: perf refuses a relayed path without viaDerp", async () => {
  const r = await probe("relay", "perf-relay-refused", "perf", {
    seconds: 2,
    pathTimeoutSeconds: 5,
  });
  assertEquals(r.ok, false);
  assertStringIncludes(String(r.failure), "no direct path");
});

Deno.test("relay: perf with viaDerp measures the relayed path", async () => {
  const r = await probe("relay", "perf-relay", "perf", {
    seconds: 2,
    viaDerp: true,
    pathTimeoutSeconds: 5,
  });
  assertEquals(r.ok, true);
  assertEquals(r.direct, false);
  assertEquals(r.derpRegion, "lab");
  assert((r.uploadBps as number) > 0);
});
