#!/usr/bin/env bash
#
# run-node.sh — production supervisor/launcher for a bitcoin-lisp full node.
#
# Versions the previously-ad-hoc inline `bash -c` supervisors that ran on the
# test server, so the load-bearing launch logic lives in the repo (and a
# `pgrep -f`/kill accident can't lose it — 2026-07-22 deploy incident).
#
# It runs the node under a restart loop: SBCL is (re)launched, and when it
# exits (graceful SIGTERM shutdown -> code 0, or the in-image watchdog -> code
# 7, or a crash), the loop waits briefly and respawns. Normal shutdown is a
# SIGTERM to the sbcl PID, which start-node traps -> stop-node (3-phase flush)
# -> exit; send SIGTERM to THIS script's process group to stop for good.
#
# Usage:
#   scripts/run-node.sh <network>          # network: testnet4 | mainnet | regtest
#
# Override any default via environment, e.g.:
#   BL_DATA_ROOT=/srv/btc BL_SBCL=/opt/sbcl/bin/sbcl scripts/run-node.sh testnet4
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
    START_OPTS=':blockfilterindex t :v2transport t :coinstatsindex t' ;;
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

while true; do
  "$BL_SBCL" --dynamic-space-size "$HEAP" --disable-debugger --non-interactive \
    --eval '(asdf:load-system :bitcoin-lisp)' \
    --eval "(bitcoin-lisp.serialization::stamp-build-git-rev \"$GITREV\")" \
    --eval "(setf bitcoin-lisp:*network* :$NETWORK)" \
    --eval "(bitcoin-lisp:start-node :data-directory \"$DATA_DIR\" :network :$NETWORK :rpc-port $RPC_PORT $START_OPTS :log-file \"$LOG\")" \
    --eval '(loop (sleep 10) (unless (ignore-errors (bitcoin-lisp::node-running bitcoin-lisp::*node*)) (sb-ext:exit :code 7)))' \
    || true
  code=$?
  echo "[$NETWORK-supervisor] sbcl exited ($code) at $(date); restarting in 10s"
  sleep 10
done
