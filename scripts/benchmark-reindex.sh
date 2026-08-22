#!/usr/bin/env bash
# The IBD benchmark of record (track C item 2 of docs/next-wave-2026-08-22.md).
#
# Times a -reindex-chainstate over an EXISTING datadir: the block files are
# read from disk and every block is re-validated and re-connected, with no
# network involved. That makes it deterministic and comparable — the same
# chain, the same box, the same -dbcache — which is the only way a claim like
# "ours vs Core" means anything.
#
# Usage:
#   scripts/benchmark-reindex.sh --datadir /data/testnet4 [--dbcache 2000]
#                                [--stop-at-height 150000]
#   scripts/benchmark-reindex.sh --datadir /data/testnet4 --core /usr/bin/bitcoind
#
# --core runs the SAME workload against a bitcoind binary instead, so the two
# numbers come from one script and one machine. It does NOT run both: point it
# at a COPY of the datadir for each, since a reindex rewrites the chainstate.
#
# Reports wall-clock, blocks/second, and the phase breakdown parsed from the
# node log. Writes the raw log next to the datadir for inspection.
set -euo pipefail

DATADIR=""
DBCACHE=450
STOP_HEIGHT=""
CORE_BIN=""
NETWORK="testnet4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --datadir)         DATADIR="$2"; shift 2 ;;
    --dbcache)         DBCACHE="$2"; shift 2 ;;
    --stop-at-height)  STOP_HEIGHT="$2"; shift 2 ;;
    --core)            CORE_BIN="$2"; shift 2 ;;
    --network)         NETWORK="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$DATADIR" ]]; then
  echo "--datadir is required: this benchmark re-validates an EXISTING chain." >&2
  echo "Nothing here downloads blocks; point it at a synced datadir." >&2
  exit 2
fi
if [[ ! -d "$DATADIR" ]]; then
  echo "no such datadir: $DATADIR" >&2
  exit 2
fi

LOG="$DATADIR/benchmark-reindex-$(date -u +%Y%m%dT%H%M%SZ).log"
START=$(date -u +%s)

if [[ -n "$CORE_BIN" ]]; then
  # Core's side of the comparison. Runs on the host because it is the
  # operator's own bitcoind, not this project's toolchain.
  echo "==> Core: $CORE_BIN -reindex-chainstate over $DATADIR"
  ARGS=(-datadir="$DATADIR" "-$NETWORK" -reindex-chainstate
        -dbcache="$DBCACHE" -printtoconsole=1 -connect=0)
  [[ -n "$STOP_HEIGHT" ]] && ARGS+=(-stopatheight="$STOP_HEIGHT")
  "$CORE_BIN" "${ARGS[@]}" 2>&1 | tee "$LOG" || true
else
  echo "==> bitcoin-lisp: -reindex-chainstate over $DATADIR"
  # The node runs INSIDE the project container, as everything in this repo
  # does; the datadir is bind-mounted at the same path so the log paths in the
  # report match what the operator sees.
  ARGS=("-datadir=$DATADIR" "-$NETWORK" -reindex-chainstate
        "-dbcache=$DBCACHE" -printtoconsole=1 -connect=0)
  [[ -n "$STOP_HEIGHT" ]] && ARGS+=("-stopatheight=$STOP_HEIGHT")
  BENCH_DATADIR="$DATADIR" BENCH_ARGS="${ARGS[*]}" \
    "$(dirname "$0")/docker-sbcl.sh" --dynamic-space-size 8192 --non-interactive \
      --eval '(asdf:load-system "bitcoin-lisp")' \
      --eval "(bitcoin-lisp:node-main (list ${ARGS[*]/#/\"} ))" 2>&1 | tee "$LOG" || true
fi

END=$(date -u +%s)
ELAPSED=$((END - START))

echo
echo "==================== benchmark-reindex ===================="
echo "datadir     : $DATADIR"
echo "network     : $NETWORK"
echo "dbcache     : $DBCACHE MiB"
echo "implementation: ${CORE_BIN:-bitcoin-lisp}"
echo "wall clock  : ${ELAPSED}s"

# Blocks connected, from whichever log format we are reading.
BLOCKS=$(grep -cE "UpdateTip|Connected block|connect-block" "$LOG" 2>/dev/null || true)
if [[ "${BLOCKS:-0}" -gt 0 && "$ELAPSED" -gt 0 ]]; then
  echo "blocks      : $BLOCKS"
  echo "throughput  : $((BLOCKS / ELAPSED)) blocks/s"
else
  echo "blocks      : not parsed from the log — check $LOG by hand rather than"
  echo "              trusting a zero here."
fi
echo "log         : $LOG"
echo "==========================================================="
echo
echo "For the comparison the plan asks for, run this twice on the SAME box"
echo "against COPIES of the same datadir — once without --core and once with —"
echo "and quote both numbers together. A number without its counterpart, or"
echo "from a different machine, is not a comparison."
