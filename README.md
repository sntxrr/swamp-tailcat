# swamp-tailcat

[swamp](https://github.com/swamp-club/swamp) extensions for
[tailcat](https://github.com/tailscale/tailcat) — netcat over Tailscale's data
plane, without its control plane.

| Extension                                                   | What it does                                                     |
| ----------------------------------------------------------- | ---------------------------------------------------------------- |
| [`@sntxrr/tailcat-probe`](extensions/models/tailcat-probe/) | ping, perf, scp round-trip and remote-command probes of a server |

Two design rules run through everything here:

1. **The address is a credential.** It is a sensitive argument, redacted from
   captured output, and persisted only as a fingerprint. Probe targets run with
   `--allow=<client-nodekey>` so that its unavoidable appearance in `ps` does
   not grant access.
2. **One-shot only, summaries only.** tailcat's long-running modes are not swamp
   methods. What the methods store is fixed-size — no samples, file bodies or
   command output — so a remote datastore stays cheap.

Model and vault instances are gitignored: an instance carries a live address.

## License

MIT — see [LICENSE.md](LICENSE.md).
