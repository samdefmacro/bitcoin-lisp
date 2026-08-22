#!/usr/bin/env bash
# Build the node executable inside the project container.
#
# Usage: scripts/build-node.sh [output-path]
#   output-path is relative to the repo root; default build/bitcoin-lisp-node.
#
# The binary this produces is what Core's functional test framework needs as
# $BITCOIND: it accepts Core's command line, serves RPC, and writes nothing to
# stderr on a normal run.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${1:-build/bitcoin-lisp-node}"

# The heap the saved image keeps: :save-runtime-options bakes it in, so it must
# be set on the BUILD invocation rather than at run time.
HEAP="${BL_BUILD_HEAP:-6144}"

exec scripts/docker-sbcl.sh \
  --dynamic-space-size "$HEAP" --disable-debugger --non-interactive \
  --load scripts/build-node-core.lisp "$OUT"
