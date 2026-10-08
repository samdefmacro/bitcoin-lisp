#!/usr/bin/env bash
# scripts/ops/soak-sample.sh: append one line per live node to a soak log.
# Runs ON the server (cron, hourly). Columns (tab-separated):
#   ts net rev blocks headers ibd peers rss_mib etime errors_total warnings_total reorgs_total
# The error/warning/reorg counts are cumulative over the node's log file since the
# soak started, so a growing errors_total between two samples is the thing to look at.
set -u
ROOT=/data/bitcoin-lisp
OUT=${SOAK_LOG:-$ROOT/logs/soak.tsv}
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
sample() {
  local net=$1 port=$2 dd=$3 log=$4 heap=$5
  local cookie="$dd/.cookie" bci ni rev blocks headers ibd peers rss etime pid
  bci=$(curl -s -m 20 -u "$(cat "$cookie" 2>/dev/null)" --data-binary '{"method":"getblockchaininfo"}' "http://127.0.0.1:$port/" 2>/dev/null)
  ni=$(curl -s -m 20 -u "$(cat "$cookie" 2>/dev/null)" --data-binary '{"method":"getnetworkinfo"}' "http://127.0.0.1:$port/" 2>/dev/null)
  read -r blocks headers ibd < <(python3 -c 'import sys,json
try:
  r=json.loads(sys.argv[1])["result"]; print(r["blocks"], r["headers"], r.get("initialblockdownload"))
except Exception: print("rpc-down rpc-down rpc-down")' "$bci")
  read -r rev peers < <(python3 -c 'import sys,json
try:
  r=json.loads(sys.argv[1])["result"]; print(r["subversion"], r["connections"])
except Exception: print("rpc-down rpc-down")' "$ni")
  pid=$(ps -eo pid,args | grep -E "sbcl.*dynamic-space-size $heap" | grep -v grep | awk '{print $1}' | head -1)
  if [ -n "$pid" ]; then
    rss=$(( $(ps -o rss= -p "$pid") / 1024 )); etime=$(ps -o etime= -p "$pid" | tr -d ' ')
  else rss=no-process; etime=no-process; fi
  local errs warns reorgs
  errs=$(grep -c '\[error\]' "$log" 2>/dev/null)
  warns=$(grep -c '\[warning\]' "$log" 2>/dev/null)
  reorgs=$(grep -ci 'reorg' "$log" 2>/dev/null)
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$TS" "$net" "$rev" "$blocks" "$headers" "$ibd" "$peers" "$rss" "$etime" "$errs" "$warns" "$reorgs" >> "$OUT"
}
sample testnet4 18332 "$ROOT/data/leveldb-test/testnet4" "$ROOT/logs/leveldb-test.log" 6144
sample mainnet  8332  "$ROOT/data/mainnet-prune/mainnet" "$ROOT/logs/mainnet.log"      5120
