#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if test -f go.work; then
  echo 'FAIL: combined Go workspace is not supported' >&2
  exit 1
fi
ap_modules=$(GOWORK=off go list -m -f '{{.Path}}' all)
if printf '%s\n' "$ap_modules" | awk '$0 == "github.com/consensys/gnark" { found=1 } END { exit !found }'; then
  echo 'FAIL: experimental gnark entered the core module graph' >&2
  exit 1
fi
ap_crypto=$(GOWORK=off go list -m -f '{{.Version}}' github.com/consensys/gnark-crypto)
test "$ap_crypto" = v0.18.1
for ap_module in apostille/zkbudget cmd/apostille; do
  ap_versions=$(GOWORK=off go -C "$ap_module" list -m github.com/consensys/gnark github.com/consensys/gnark-crypto)
  test "$ap_versions" = 'github.com/consensys/gnark v0.16.3
github.com/consensys/gnark-crypto v0.21.0'
done
echo 'PASS: core excludes gnark; isolated CLI/ZK retain reviewed crypto pins'
