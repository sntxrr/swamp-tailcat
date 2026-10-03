# @sntxrr/tailcat-probe

Probe a [tailcat](https://github.com/tailscale/tailcat) server from swamp.
tailcat is netcat over Tailscale's data plane (WireGuard + DERP relays) without
Tailscale's control plane: no account, no root, no tailnet.

| Method     | Runs                                    | Records                                                  |
| ---------- | --------------------------------------- | -------------------------------------------------------- |
| `ping`     | `tailcat ping [--until-direct]`         | RTT, direct or DERP, endpoint or relay region            |
| `perf`     | `tailcat --json perf`                   | receiver-side bits/s per direction, RTT, jitter, reorder |
| `transfer` | `tailcat cp` (system scp)               | bytes and SHA-256 of the local copy                      |
| `exec`     | `tailcat ssh <addr> <cmd>` (system ssh) | exit code, stdout size and SHA-256                       |

## What it does not do

tailcat's long-running modes — `serve` (files, ssh, exec, perf, exit-node),
`forward`, `socks`, `browse`, `recv` and interactive `ssh` — block until
interrupted. A method cannot own that lifecycle, and the only thing it could
record is "started". The runner refuses them, and `genkey` too, since it writes
key material.

Run the server side as a service with a saved key, and probe it:

```sh
# on heron, once
tailcat genkey --key=default
# as a service unit, with the probe's client key allowed (see Security)
tailcat serve --allow=nodekey:<probe-client-nodekey> perf files
```

## Security: the address is the credential

A tailcat address encodes the server's WireGuard public key and a pre-shared
key. Anyone holding it can open a tunnel.

- `address` is a **sensitive** global argument. Wire it from a vault, never as a
  literal in the model file.
- It is redacted from captured stdout/stderr. Resources carry only
  `addressFingerprint` — 12 hex chars of SHA-256 — which changes when the
  server's key does, and cannot be used to connect.
- **tailcat has no environment or file input for a client's address**, so it
  travels in argv and is visible in `ps` to every local user while a method
  runs. Treat that as given, and make it not matter:
  - **Every probe target must run with `--allow=nodekey:<client-key>`**, with
    the client key created by `tailcat genkey --client --key=probe` and passed
    as `clientKey`. A leaked address then does not grant a connection.
  - **Never point this model at `serve no-auth-ssh`.** There the address alone
    is a shell. The model cannot detect a server's mode from the client side, so
    this rule is yours to keep.
- `exec` stores `command` verbatim. Do not put a secret in it.

## Datastore footprint

Every resource is a fixed-size summary, sized for a remote (S3) datastore where
each version is a PUT and an index entry:

| Resource   | lifetime | GC versions | Never stored                                         |
| ---------- | -------- | ----------- | ---------------------------------------------------- |
| `ping`     | 7d       | 5           | individual pongs                                     |
| `perf`     | 30d      | 20          | per-second `intervals` samples                       |
| `transfer` | 7d       | 5           | file content                                         |
| `exec`     | 7d       | 5           | stdout, unless `captureStdoutBytes` > 0 (max 64 KiB) |

Each method writes under its own data name (`ping`, `perf`, `transfer`, `exec`),
so `data.latest(<model>, "ping")` is never ambiguous with another method's
output, and GC counts each method separately. Use one model per server.

A `live` pre-flight check, `tailcat-binary-runs`, runs `tailcat version` before
any method and stops the run if the binary is missing or broken.

If you schedule a probe, cadence is the multiplier: `*/5` is 288 versions a day.
Hourly or slower is plenty for reachability.

## Example

```yaml
# models/tailcat-heron.yaml
type: "@sntxrr/tailcat/probe"
name: tailcat-heron
globalArguments:
  target: heron
  address: ${{ vault.get("tailcat", "heron-address") }}
  clientKey: probe
```

```sh
swamp model method run tailcat-heron ping --input untilDirect=true
swamp model method run tailcat-heron perf --input direction=both --input seconds=5
swamp model method run tailcat-heron transfer \
  --input direction=receive --input remotePath=canary.txt --input localPath=/tmp/canary.txt
swamp model method run tailcat-heron exec --input 'command=["uptime"]'
```

## `transfer` and `exec` use your SSH config

tailcat runs the system `ssh`/`scp` with a `ProxyCommand`, and offers no way to
pass `-F` or `-i`. Your `~/.ssh/config` therefore applies, and a `Host *` block
that sets `IdentityAgent` (a 1Password agent, say) wins over the `SSH_AUTH_SOCK`
the runner passes. ssh uses the first value it finds, so an unattended probe
signs through your desktop agent, or fails.

tailcat names the ssh host `tailcat-<first 16 hex of sha256(address)>`. Put a
block for that pattern **above** `Host *`:

```
Host tailcat-*
    IdentityAgent SSH_AUTH_SOCK
```

## Back-to-back runs with the same client key

tailcat refuses a new session from a saved client key for a short window after
the previous session with that key closed. Measured against a local server, runs
started ~1 s apart alternated between success and a 10 s
`Dial: context deadline
exceeded`; with 15 s between them, 4 of 4 succeeded.
`perf` hides this with its own wait for a path. In a workflow that chains
methods on one model, leave a gap between steps, or give each model its own
client key.

## Requirements

`tailcat` on PATH (or `tailcatBinary`), plus the system `scp`/`ssh` for
`transfer`/`exec`. The runner passes `HOME` (tailcat's saved keys live under the
user config dir) and `SSH_AUTH_SOCK`, and nothing else from the parent
environment beyond `PATH`, `XDG_CONFIG_HOME` and `USER`.
