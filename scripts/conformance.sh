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
# BL_CONFORMANCE_ARGS is appended to every test's command line, e.g.
#   BL_CONFORMANCE_ARGS=--timeout-factor=4 for a test that starts a dozen nodes.
# BL_CONFORMANCE_REFERENCE=<tag> runs the test against Core's OWN bitcoind of
# that previous release (e.g. v28.2, see scripts/get-previous-releases.sh)
# instead of ours: when a test fails here, it says whether Core passes it.
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
NEEDS_LOCAL_ADDRS=0
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
    # The two -bind/-discover tests skip unless routable addresses are on an
    # interface and the test is told so; see scripts/conformance-local-addresses.py.
    extra=""
    case "$name" in
      feature_bind_port_discover) extra="--ihave1111and2222"; NEEDS_LOCAL_ADDRS=1 ;;
      feature_bind_port_externalip) extra="--ihave1111"; NEEDS_LOCAL_ADDRS=1 ;;
    esac
    # A per-test timeout, because an oracle you are afraid to run is not one.
    # A node that wedges takes the whole batch with it otherwise, and "wedged"
    # is exactly the kind of finding this suite exists to produce.
    CMD="$CMD echo '=== $name ==='; \
         timeout -k 10 ${BL_CONFORMANCE_TIMEOUT:-300} \
         python3 \$(case '$t' in /*) echo '$t';; */*) echo /workspace/'$t';; *) echo /workspace/refs/bitcoin/test/functional/'$t';; esac) \
           --configfile=/workspace/test/config.ini \
           --tmpdir=/workspace/$OUT/$name $extra ${BL_CONFORMANCE_ARGS:-}; \
         rc=\$?; \
         if [ \$rc = 0 ]; then echo 'RESULT $name PASS'; \
         elif [ \$rc = 77 ]; then echo 'RESULT $name SKIP'; \
         elif [ \$rc = 124 ] || [ \$rc = 137 ]; then echo 'RESULT $name TIMEOUT'; \
         else echo \"RESULT $name FAIL(\$rc)\"; fi;"
  done
fi

TTY_FLAGS="-i"; [ -t 0 ] && [ -t 1 ] && TTY_FLAGS="-it"

# NET_ADMIN is granted only to a run that includes one of the two tests above,
# and only inside the container's own network namespace (never --privileged,
# never host networking): it is what lets the helper add 1.1.1.1 and 2.2.2.2.
CAP_FLAGS=""
if [ "$NEEDS_LOCAL_ADDRS" = 1 ]; then
  CAP_FLAGS="--cap-add NET_ADMIN"
  CMD="python3 /workspace/scripts/conformance-local-addresses.py && $CMD"
fi

# Previous releases (Core test/get_previous_releases.py): the tests that
# add_nodes(versions=[...]) an old bitcoind skip with "previous releases not
# available" unless the framework finds them under PREVIOUS_RELEASES_DIR
# (test_framework.py:167-182). scripts/get-previous-releases.sh leaves the
# verified archives in refs/bitcoin/releases-archives/;
# scripts/previous-releases-volume.sh extracts them INSIDE the container into a
# per-checkout volume, which is mounted read-only for the run.
RELEASE_FLAGS=""
RELEASES_VOL="$("$REPO/scripts/previous-releases-volume.sh")"
if [ -n "$RELEASES_VOL" ]; then
  RELEASE_FLAGS="-v $RELEASES_VOL:/releases:ro -e PREVIOUS_RELEASES_DIR=/releases"
  # The framework takes a binary from $BITCOIND before config.ini
  # (test_framework/util.py:317-343).
  if [ -n "${BL_CONFORMANCE_REFERENCE:-}" ]; then
    RELEASE_FLAGS="$RELEASE_FLAGS -e BITCOIND=/workspace/scripts/conformance-reference-bitcoind.sh"
    RELEASE_FLAGS="$RELEASE_FLAGS -e BL_REFERENCE_BITCOIND=/releases/$BL_CONFORMANCE_REFERENCE/bin/bitcoind"
    echo "reference run: Core $BL_CONFORMANCE_REFERENCE's bitcoind, not ours" >&2
  fi
elif [ -n "${BL_CONFORMANCE_REFERENCE:-}" ]; then
  echo "BL_CONFORMANCE_REFERENCE needs scripts/get-previous-releases.sh first." >&2
  exit 1
fi

echo "conformance run $RUN_ID -> $OUT" >&2
docker run --rm $TTY_FLAGS \
  -v "$REPO:/workspace" \
  --label "agent=$SLUG" \
  --label "io.common-lisp-workbench.checkout=$CHECKOUT_SHORT" \
  -w /workspace \
  -e HOME=/tmp \
  $RELEASE_FLAGS $CAP_FLAGS \
  "$IMAGE" bash -lc "$CMD"
