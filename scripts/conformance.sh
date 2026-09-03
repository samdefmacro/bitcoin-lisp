#!/usr/bin/env bash
# Run Bitcoin Core's functional tests against this node, inside the project
# container.
#
# Core's test/functional suite is this project's behavioural oracle
# (docs/next-wave-2026-08-22.md track B): it drives a real node over RPC and
# P2P and asserts on what it observes, which is the class of defect a
# 33k-check unit suite structurally cannot see. The first run proved one test passes;
# this makes the whole suite runnable on demand, which is what turns it into an
# oracle rather than an anecdote.
#
# Usage:
#   scripts/conformance.sh rpc_uptime.py               # one Core test
#   scripts/conformance.sh build/diag/mine.py          # a repo-relative one
#   scripts/conformance.sh rpc_uptime.py feature_shutdown.py
#   scripts/conformance.sh --runner --extended         # Core's test_runner.py
#
# BL_CONFORMANCE_TIMEOUT caps each test (default 300s).
#
# Everything runs in the pinned project container. Nothing is published to a
# host port: Core's framework binds 127.0.0.1 inside the container's own
# network namespace, so concurrent runs — here or by another agent — cannot
# collide on a port or see each other's nodes.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=bitcoin-lisp-sbcl:2.6.5-4
BIN="$REPO/build/bitcoin-lisp-node"
TMPDIR_REL="build/conformance-tmp"

if [ ! -x "$BIN" ]; then
  echo "No node binary at $BIN — run scripts/build-node.sh first." >&2
  exit 1
fi
if [ ! -d "$REPO/refs/bitcoin/test/functional" ]; then
  echo "refs/bitcoin is missing Core's functional tests." >&2
  exit 1
fi

CONFORMANCE_ROOT=/workspace "$REPO/scripts/conformance-config.sh" "$BIN" >/dev/null

# Container identity: this checkout plus this run, so a second run (or another
# agent's) is a separate container with a separate tmpdir.
sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | awk '{print $1}'
  else echo "ERROR: sha256sum or shasum is required" >&2; exit 1; fi
}
CHECKOUT_SHORT="$(printf '%s' "$REPO" | sha256_stdin)"; CHECKOUT_SHORT="${CHECKOUT_SHORT:0:12}"
RUN_ID="$(date -u +%Y%m%dT%H%M%S)-$$"
SLUG="bitcoin-lisp-conformance-$CHECKOUT_SHORT-$RUN_ID"
OUT="$TMPDIR_REL/$RUN_ID"
mkdir -p "$REPO/$OUT"

MODE=tests
if [ "${1:-}" = "--runner" ]; then MODE=runner; shift; fi

if [ "$MODE" = runner ]; then
  # test_runner.py owns its own parallelism and per-test tmpdirs.
  CMD="python3 /workspace/refs/bitcoin/test/functional/test_runner.py \
        --configfile=/workspace/test/config.ini \
        --tmpdirprefix=/workspace/$OUT $*"
else
  [ $# -gt 0 ] || { echo "Usage: $0 <test.py> [test.py ...]  |  $0 --runner [args]" >&2; exit 2; }
  CMD=""
  for t in "$@"; do
    # Each test gets its own tmpdir; the framework refuses a non-empty one.
    name="$(basename "$t" .py)"
    # A per-test timeout, because an oracle you are afraid to run is not one.
    # A node that wedges takes the whole batch with it otherwise, and "wedged"
    # is exactly the kind of finding this suite exists to produce.
    CMD="$CMD echo '=== $name ==='; \
         timeout -k 10 ${BL_CONFORMANCE_TIMEOUT:-300} \
         python3 \$(case '$t' in /*) echo '$t';; */*) echo /workspace/'$t';; *) echo /workspace/refs/bitcoin/test/functional/'$t';; esac) \
           --configfile=/workspace/test/config.ini \
           --tmpdir=/workspace/$OUT/$name; \
         rc=\$?; \
         if [ \$rc = 0 ]; then echo 'RESULT $name PASS'; \
         elif [ \$rc = 77 ]; then echo 'RESULT $name SKIP'; \
         elif [ \$rc = 124 ] || [ \$rc = 137 ]; then echo 'RESULT $name TIMEOUT'; \
         else echo \"RESULT $name FAIL(\$rc)\"; fi;"
  done
fi

TTY_FLAGS="-i"; [ -t 0 ] && [ -t 1 ] && TTY_FLAGS="-it"

echo "conformance run $RUN_ID -> $OUT" >&2
docker run --rm $TTY_FLAGS \
  -v "$REPO:/workspace" \
  --label "agent=$SLUG" \
  --label "io.common-lisp-workbench.checkout=$CHECKOUT_SHORT" \
  -w /workspace \
  -e HOME=/tmp \
  "$IMAGE" bash -lc "$CMD"
