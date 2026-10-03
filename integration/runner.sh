#!/bin/sh
# The probe side. Two agents: the default holds the authorised key, the
# second holds the wrong one for the negative control.
set -eu

eval "$(ssh-agent -s)" >/dev/null
ssh-add -q /shared/id_test
WRONG_AUTH_SOCK="$(ssh-agent -s | sed -n 's/^SSH_AUTH_SOCK=\([^;]*\);.*/\1/p')"
SSH_AUTH_SOCK="$WRONG_AUTH_SOCK" ssh-add -q /shared/id_wrong
export WRONG_AUTH_SOCK

# The block the README tells users to add above any `Host *`.
mkdir -p "$HOME/.ssh"
printf 'Host tailcat-*\n    IdentityAgent SSH_AUTH_SOCK\n' > "$HOME/.ssh/config"

exec deno test --allow-all --cached-only integration/probe_test.ts
