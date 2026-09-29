#!/usr/bin/env bash
# The differential lanes against Bitcoin Core's own binaries (GA11 "Harness
# lanes", docs/gap-analysis-11.md), all against a previous release (v28.2 by
# default) from refs/bitcoin/releases-archives:
#
#   tx       the fiveam suite :core-binary-differential-tests with Core's
#            bitcoin-tx and bitcoin-util mounted at /releases, REQUIRING them
#            -- in the ordinary battery the same suite skips when the binaries
#            are absent, which is right there and a silent pass here;
#   datadir  scripts/interop/datadir_interop.py through scripts/conformance.sh
#            (Core's functional framework): our node's regtest datadir started
#            by Core v28.2 and Core's started by ours, every block and index
#            answer compared (ours-to-core, core-to-ours). Needs the node
#            binary, build/bitcoin-lisp-node (scripts/build-node.sh).
#
# Usage:
#   scripts/get-previous-releases.sh v28.2     # once: fetch + verify on the host
#   scripts/interop-test.sh                    # or: scripts/dev.sh interop,
#                                              #     cl-workbench validation run interop
#   BL_INTEROP_RELEASE=v25.0 scripts/interop-test.sh      (the tx lane only)
#   BL_INTEROP_LANES=datadir scripts/interop-test.sh      (one lane)
#   BL_INTEROP_COPY_CHAINSTATE=0 BL_INTEROP_COPY_INDEXES=0 scripts/interop-test.sh
#       -- copy only blocks/ and let each consumer rebuild its chainstate
#       (-reindex-chainstate) and its indexes. By default chainstate/ and
#       indexes/ are copied too: both are Core's formats since the coinsdb
#       batch and the tools batch's index-record port (2026-09-29).
#
# The tx lane is a cold container with its own FASL volume (never the cold
# battery's, which a concurrent battery would share) and a 2 GiB heap, so it
# is not mistaken for a battery by anyone polling for `dynamic-space-size
# 4096'. The exit status is non-zero when any lane fails; the last line is
# `Did N checks.' over every lane, which the adapter's counted gate reads.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="${BL_INTEROP_RELEASE:-v28.2}"

VOL="$("$REPO/scripts/previous-releases-volume.sh")"
if [ -z "$VOL" ]; then
  echo "ERROR: no previous releases -- run scripts/get-previous-releases.sh $RELEASE first." >&2
  exit 1
fi

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  else shasum -a 256 | awk '{print $1}'; fi
}
CHECKOUT_SHORT="$(printf '%s' "$REPO" | sha256_stdin)"; CHECKOUT_SHORT="${CHECKOUT_SHORT:0:12}"

LANES="${BL_INTEROP_LANES:-tx datadir}"
TOTAL=0
FAILED=""
LOG="$(mktemp -t bitcoin-lisp-interop)"
trap 'rm -f "$LOG"' EXIT

case " $LANES " in *" tx "*)
  echo "=== interop lane tx: bitcoin-tx / bitcoin-util $RELEASE ==="
  rc=0
  BITCOIN_LISP_FASL_VOLUME="bitcoin-lisp-fasl-interop-$CHECKOUT_SHORT" \
  BITCOIN_LISP_DOCKER_EXTRA="-v $VOL:/releases:ro -e BL_CORE_BIN_DIR=/releases/$RELEASE/bin/ -e BL_REQUIRE_CORE_BINARIES=1 --label agent=bitcoin-lisp-interop-$CHECKOUT_SHORT" \
  "$REPO/scripts/docker-sbcl.sh" --dynamic-space-size 2048 --non-interactive \
    --eval '(asdf:load-system "bitcoin-lisp/tests")' \
    --eval "(let ((r (fiveam:run :core-binary-differential-tests)))
              (fiveam:explain! r)
              (when (null r)
                (format t \"~&suite :core-binary-differential-tests selected no tests~%\")
                (sb-ext:exit :code 1))
              (unless (fiveam:results-status r) (sb-ext:exit :code 1)))" \
    2>&1 | tee "$LOG" || rc=$?
  n="$(grep -Eo 'Did [0-9]+ checks' "$LOG" | tail -1 | grep -Eo '[0-9]+' || true)"
  if [ "$rc" -ne 0 ] || [ -z "$n" ]; then FAILED="$FAILED tx"; fi
  TOTAL=$((TOTAL + ${n:-0}))
  echo "interop lane tx: rc=$rc checks=${n:-0}"
;; esac

case " $LANES " in *" datadir "*)
  echo "=== interop lane datadir: our datadir <-> Core v28.2 ==="
  rc=0
  if [ ! -x "$REPO/build/bitcoin-lisp-node" ]; then
    echo "ERROR: the datadir lane needs build/bitcoin-lisp-node -- run scripts/build-node.sh first." >&2
    rc=1
  else
    args=""
    [ "${BL_INTEROP_COPY_CHAINSTATE:-1}" = 1 ] && args="$args --copy-chainstate"
    [ "${BL_INTEROP_COPY_INDEXES:-1}" = 1 ] && args="$args --copy-indexes"
    BL_CONFORMANCE_TIMEOUT="${BL_CONFORMANCE_TIMEOUT:-1200}" \
    BL_CONFORMANCE_ARGS="$args ${BL_CONFORMANCE_ARGS:-}" \
      "$REPO/scripts/conformance.sh" scripts/interop/datadir_interop.py \
      2>&1 | tee "$LOG" || rc=$?
    grep -q 'RESULT datadir_interop PASS' "$LOG" || rc=1
  fi
  n="$(grep -Eo 'INTEROP total checks=[0-9]+' "$LOG" | tail -1 | grep -Eo '[0-9]+$' || true)"
  if [ "$rc" -ne 0 ] || [ -z "$n" ]; then FAILED="$FAILED datadir"; fi
  TOTAL=$((TOTAL + ${n:-0}))
  echo "interop lane datadir: rc=$rc checks=${n:-0}"
;; esac

echo "Did $TOTAL checks."
if [ -n "$FAILED" ]; then
  echo "interop: FAILED lanes:$FAILED" >&2
  exit 1
fi
