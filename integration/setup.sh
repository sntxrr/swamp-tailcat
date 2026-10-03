#!/bin/sh
# One-shot: mint every throwaway credential the harness needs into /shared.
# Nothing here outlives `docker compose down -v`.
set -eu

S=/shared
rm -rf "${S:?}"/*
mkdir -p "$S/keys" "$S/served" "$S/derp-certs"

# One client key per test case, so no two cases reconnect with the same key
# back-to-back (tailcat refuses that for a short window). "denied" is minted
# but deliberately left out of --allow.
ALLOWED="ping-direct perf-direct transfer exec-echo exec-exit exec-wrong-ssh
ping-relay perf-relay perf-relay-refused"
allow=""
for name in $ALLOWED denied; do
  nodekey="$(tailcat genkey --client --key="$S/keys/$name.private.json" 2>/dev/null \
    | grep '^nodekey:')"
  [ -n "$nodekey" ] || { echo "genkey $name printed no nodekey" >&2; exit 1; }
  if [ "$name" != denied ]; then allow="${allow:+$allow,}$nodekey"; fi
done
printf '%s' "$allow" > "$S/allow"

# SSH: the server authorises id_test only; id_wrong is the negative control.
ssh-keygen -q -t ed25519 -N '' -C tailcat-lab-test -f "$S/id_test"
ssh-keygen -q -t ed25519 -N '' -C tailcat-lab-wrong -f "$S/id_wrong"

# A file to fetch, and its hash for the probe to compare against.
head -c 65536 /dev/urandom > "$S/served/canary.bin"

# Self-signed cert for the relay. The DERP map marks the node
# InsecureForTests, so clients skip verification.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 1 -subj /CN=derper -addext subjectAltName=DNS:derper \
  -keyout "$S/derp-certs/derper.key" -out "$S/derp-certs/derper.crt" 2>/dev/null

chmod 600 "$S"/keys/* "$S/id_test" "$S/id_wrong" "$S/derp-certs/derper.key"
echo "setup: $(echo "$ALLOWED" | wc -w) allowed client keys + 1 denied, ssh keys, canary, relay cert"
