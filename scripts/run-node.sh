#!/usr/bin/env bash
#
# run-node.sh — production supervisor/launcher for a bitcoin-lisp full node.
#
# Versions the previously-ad-hoc inline `bash -c` supervisors that ran on the
# test server, so the load-bearing launch logic lives in the repo (and a
# `pgrep -f`/kill accident can't lose it — 2026-07-22 deploy incident).
#
# It runs the node under a restart loop: SBCL is (re)launched, and the loop
# DISCRIMINATES ON THE EXIT CODE (bitcoin-lisp:run-node-watchdog chooses it):
#
#   0  a deliberate, COMPLETED stop (`stop` RPC, SIGTERM, -stopatheight).
#      Stop for good — respawning would undo what the operator just asked for,
#      and with -stopatheight it re-arms the trigger and oscillates.
#   1  a deterministic failure (bad config, unrecoverable chainstate, disk
#      space): bounded backoff, then give up. An unconditional 10s respawn
#      spins on such an error forever.
#   7  the in-image watchdog saw the node stop running unasked, or SBCL
#      crashed / was killed: respawn.
#
# Normal shutdown is a SIGTERM to the sbcl PID: start-node traps it and asks
# the MAIN thread (run-node-watchdog) to run stop-node, so the 3-phase
# chainstate flush, mempool.dat, peers.dat, banlist and wallet best-block
# markers all complete BEFORE the process exits. Send SIGTERM to THIS script's
# process group to stop for good.
#
# Usage:
#   scripts/run-node.sh <network>          # network: testnet4 | mainnet | regtest
#
# Override any default via environment, e.g.:
#   BL_DATA_ROOT=/srv/btc BL_SBCL=/opt/sbcl/bin/sbcl scripts/run-node.sh testnet4
#   BL_MAX_FAST_FAILURES=5 BL_HEALTHY_RUN_SECONDS=300   # exit-1 backoff policy
#
set -euo pipefail

NETWORK="${1:-testnet4}"

# --- Toolchain / paths (override via env) ------------------------------------
BL_ROOT="${BL_ROOT:-/data/bitcoin-lisp}"
BL_SBCL="${BL_SBCL:-$BL_ROOT/sbcl-final/bin/sbcl}"
BL_SBCL_HOME="${BL_SBCL_HOME:-$BL_ROOT/sbcl-final/lib/sbcl}"
BL_SECP_LIB="${BL_SECP_LIB:-$BL_ROOT/secp256k1-local/lib}"
BL_CODE="${BL_CODE:-$BL_ROOT/code}"
BL_DATA_ROOT="${BL_DATA_ROOT:-$BL_ROOT/data}"
BL_LOG_ROOT="${BL_LOG_ROOT:-$BL_ROOT/logs}"

# --- Per-network configuration ----------------------------------------------
# HEAP is --dynamic-space-size (MiB); it also serves as the process
# discriminator for pgrep/monitoring (mainnet 5120 vs testnet4 6144).
case "$NETWORK" in
  testnet4)
    HEAP=6144; RPC_PORT=18332
    DATA_DIR="$BL_DATA_ROOT/leveldb-test/"; LOG="$BL_LOG_ROOT/leveldb-test.log"
    # -txindex on testnet4 only: start-node refuses prune+txindex together
    # (pruned blocks cannot be looked up), and mainnet runs pruned. Enabled to
    # exercise the LevelDB txindex from GA9 S2-13 against a real chain -- the
    # previous in-memory implementation could not run at mainnet scale at all,
    # so this path has never had production exposure.
    # :flat-block-files on testnet4 ONLY. New blocks go into Core's numbered
    # blk?????.dat instead of one file per block; the existing per-block files
    # stay readable (dual read), and turning the flag back off leaves the flat
    # records readable too, so this is reversible in both directions. Mainnet
    # stays off until this has soaked here -- it is the pruned node, and
    # pruning a flat file is all-or-nothing.
    START_OPTS=':blockfilterindex t :v2transport t :coinstatsindex t :txindex t :flat-block-files t' ;;
  mainnet)
    HEAP=5120; RPC_PORT=8332
    DATA_DIR="$BL_DATA_ROOT/mainnet-prune/"; LOG="$BL_LOG_ROOT/mainnet.log"
    START_OPTS=':prune 4096 :listen nil :max-peers 16 :dbcache-mib 2048 :blockfilterindex t :v2transport t' ;;
  regtest)
    HEAP=4096; RPC_PORT=18443
    DATA_DIR="$BL_DATA_ROOT/regtest/"; LOG="$BL_LOG_ROOT/regtest.log"
    START_OPTS=':blockfilterindex t' ;;
  *)
    echo "run-node.sh: unknown network '$NETWORK' (want testnet4|mainnet|regtest)" >&2
    exit 2 ;;
esac

export SBCL_HOME="$BL_SBCL_HOME"
export LD_LIBRARY_PATH="$BL_SECP_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$BL_CODE"

# --- Build rev + FASL-cache invalidation -------------------------------------
# GITREV is the short git rev of the deployed code; it is stamped into the BIP14
# subversion (below) so getnetworkinfo reports exactly which commit is live.
# When it differs from the rev the on-disk FASL cache was last built for, clear
# that cache ONCE before launching: a struct/layout change across a redeploy
# otherwise boots into an "incompatible layout" error, and the respawn loop then
# spins on it forever. Clearing turns that into a clean recompile on first boot.
# (Skipped when git is unavailable — we don't nuke a cache we can't reason about.)
GITREV="$(git -C "$BL_CODE" rev-parse --short HEAD 2>/dev/null || echo unknown)"
BL_FASL_CACHE="${BL_FASL_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/common-lisp}"
BL_REV_MARKER="${BL_REV_MARKER:-$BL_ROOT/.fasl-build-rev}"
PREV_REV="$(cat "$BL_REV_MARKER" 2>/dev/null || true)"
if [ "$GITREV" != "unknown" ] && [ "$PREV_REV" != "$GITREV" ]; then
  echo "[$NETWORK-supervisor] build rev ${PREV_REV:-none} -> $GITREV; clearing FASL cache $BL_FASL_CACHE for a clean recompile"
  rm -rf "$BL_FASL_CACHE"
  mkdir -p "$(dirname "$BL_REV_MARKER")"
  printf '%s\n' "$GITREV" > "$BL_REV_MARKER"
fi

echo "[$NETWORK-supervisor] up at $(date) heap=${HEAP}MiB rpc=$RPC_PORT rev=$GITREV data=$DATA_DIR"
echo "[$NETWORK-supervisor] NOTE: a defstruct change needs the FASL cache cleared;"
echo "[$NETWORK-supervisor]       this script auto-clears it on a git-rev change. If"
echo "[$NETWORK-supervisor]       you edit without committing, clear manually:"
echo "[$NETWORK-supervisor]       rm -rf $BL_FASL_CACHE"

# Consecutive deterministic (exit 1) failures, and how long a run must last to
# count as healthy — a node that ran for a while and then died did not fail
# deterministically at startup, so its streak resets.
BL_MAX_FAST_FAILURES="${BL_MAX_FAST_FAILURES:-5}"
BL_HEALTHY_RUN_SECONDS="${BL_HEALTHY_RUN_SECONDS:-300}"
fail_streak=0

while true; do
  run_start=$SECONDS
  # No `|| true`: it swallowed the status and made the logged exit code always
  # 0, which is exactly the discrimination this loop needs. set +e instead, so
  # `set -e` cannot kill the supervisor on a non-zero child exit either.
  set +e
  "$BL_SBCL" --dynamic-space-size "$HEAP" --disable-debugger --non-interactive \
    --eval '(asdf:load-system :bitcoin-lisp)' \
    --eval "(bitcoin-lisp.serialization::stamp-build-git-rev \"$GITREV\")" \
    --eval "(setf bitcoin-lisp:*network* :$NETWORK)" \
    --eval "(bitcoin-lisp:start-node :data-directory \"$DATA_DIR\" :network :$NETWORK :rpc-port $RPC_PORT $START_OPTS :log-file \"$LOG\")" \
    --eval '(bitcoin-lisp:run-node-watchdog)'
  code=$?
  set -e
  elapsed=$(( SECONDS - run_start ))

  case "$code" in
    0)
      echo "[$NETWORK-supervisor] node stopped cleanly (exit 0) after ${elapsed}s at $(date); not restarting"
      exit 0
      ;;
    1)
      # Deterministic failure. A long run first means this was a runtime
      # crash, not a start-up error that will simply repeat.
      if [ "$elapsed" -ge "$BL_HEALTHY_RUN_SECONDS" ]; then
        fail_streak=0
      fi
      fail_streak=$(( fail_streak + 1 ))
      if [ "$fail_streak" -gt "$BL_MAX_FAST_FAILURES" ]; then
        echo "[$NETWORK-supervisor] exit 1 after ${elapsed}s at $(date); $fail_streak consecutive fast failures — giving up (fix the config/chainstate/disk, then restart)"
        exit 1
      fi
      backoff=$(( 10 * (1 << (fail_streak - 1)) ))
      if [ "$backoff" -gt 300 ]; then
        backoff=300
      fi
      echo "[$NETWORK-supervisor] exit 1 after ${elapsed}s at $(date); deterministic failure ${fail_streak}/${BL_MAX_FAST_FAILURES} — retrying in ${backoff}s"
      sleep "$backoff"
      ;;
    *)
      # 7 (watchdog: the node stopped running unasked) or a signal/crash code.
      fail_streak=0
      echo "[$NETWORK-supervisor] sbcl exited ($code) after ${elapsed}s at $(date); restarting in 10s"
      sleep 10
      ;;
  esac
done
