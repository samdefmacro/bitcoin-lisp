#!/usr/bin/env bash
# Tapscript-only profile watcher with a wider range.
# Same SIGUSR1-toggle pattern as profile-regions.sh, but only one region
# spanning h=67100..70000 (~2900 blocks) so we get enough samples even
# when stress validation is slow (~30 b/s = ~100s of sampling).

set -euo pipefail

NODE_LOG=/data/bitcoin-lisp/logs/node.log
PROFILE_FILE=/data/bitcoin-lisp/logs/profile.txt
PROFILE_DIR=/data/bitcoin-lisp/logs/profiles
mkdir -p "$PROFILE_DIR"

REGION_NAME="tapscript"
REGION_START=67100
REGION_END=70000

pid_of_node() {
  pgrep -af 'sbcl --dynamic' | awk '$2=="sbcl"{print $1; exit}'
}

log() { echo "[$(date '+%F %T')] $*"; }

state="idle"

log "Tapscript watcher started; waiting for node pid..."
while [[ -z "$(pid_of_node)" ]]; do sleep 5; done
NODE_PID="$(pid_of_node)"
log "Node pid: $NODE_PID; window h=${REGION_START}..${REGION_END}"

tail -F -n0 "$NODE_LOG" 2>/dev/null | while IFS= read -r line; do
  case "$line" in
    *"IBD Progress:"*)
      h="$(echo "$line" | awk -F'Progress: ' 'NF>1 {split($2,a,"/"); print a[1]; exit}')"
      [[ -z "$h" ]] && continue
      if [[ "$state" == "idle" && "$h" -ge "$REGION_START" ]]; then
        log "Arming sprof at h=$h (window ${REGION_START}..${REGION_END})"
        kill -USR1 "$NODE_PID" || { log "kill -USR1 failed"; continue; }
        state="armed"
      elif [[ "$state" == "armed" && "$h" -ge "$REGION_END" ]]; then
        log "Stopping sprof at h=$h"
        kill -USR1 "$NODE_PID" || { log "kill -USR1 failed"; continue; }
        sleep 5
        out="$PROFILE_DIR/${REGION_NAME}.profile.txt"
        if [[ -f "$PROFILE_FILE" ]]; then
          cp "$PROFILE_FILE" "$out"
          log "Saved profile -> $out"
        else
          log "WARNING: $PROFILE_FILE missing"
        fi
        log "Done."
        exit 0
      fi
      ;;
  esac
done
