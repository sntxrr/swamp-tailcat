#!/bin/sh
# A tailcat server restricted to the harness's allowed client keys.
# $1 names it; its address is written (0600) to /shared/addr-$1.
set -eu
name="$1"
export TAILCAT_ADDR_FILE="/shared/addr-$name"
exec tailcat --key=new --derpmap-url="$DERPMAP_URL" serve \
  --allow="$(cat /shared/allow)" \
  --ssh-authorized-keys=/shared/id_test.pub \
  --files=/shared/served \
  perf files ssh
