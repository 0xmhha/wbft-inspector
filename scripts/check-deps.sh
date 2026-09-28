#!/usr/bin/env bash
# Fails when a package of the inspector module depends on anything but the
# Go standard library and the module itself. The inspector decides from what
# implementations write, not from their code.
set -euo pipefail
cd "$(dirname "$0")/.."
extra=$(go list -deps -test -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./... \
  | grep -v '^github.com/0xmhha/wbft-inspector' || true)
if [ -n "$extra" ]; then
  echo "non-standard dependencies of the inspector module:" >&2
  echo "$extra" >&2
  exit 1
fi
echo "dependencies: standard library only"
