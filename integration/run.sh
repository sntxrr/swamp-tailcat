#!/usr/bin/env bash
# Build the lab, run the probe's end-to-end tests, and always tear down —
# including the volume holding every throwaway key and address.
set -euo pipefail
cd "$(dirname "$0")"

compose() { docker compose -f compose.yaml "$@"; }
trap 'compose down -v --remove-orphans >/dev/null 2>&1 || true' EXIT

compose build setup
# --exit-code-from stops the lab when the probe exits and returns its status.
compose up --exit-code-from probe --attach probe
