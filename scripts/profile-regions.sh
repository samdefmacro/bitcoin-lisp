#!/usr/bin/env bash
# Profile-region watcher for IBD speed-catchup phase A.2.
#
# Tails /data/bitcoin-lisp/logs/node.log and SIGUSR1-toggles sb-sprof at
# region boundaries during a fresh testnet4 sync. The node's SIGUSR1
# handler (src/node/shutdown.lisp install-shutdown-handler) toggles sb-sprof and writes the report
# to /data/bitcoin-lisp/logs/profile.txt on the SECOND USR1. We then
# rename the report so it isn't clobbered by the next region.
#
# Regions:
#   light      h=10000 .. h=20000   (small txs, typical workload)
#   stress     h=51000 .. h=67000   (busy zone, prior bottleneck)
#   tapscript  h=67100 .. h=67200   (heavy tapscript path)
#
# Usage (run on test-bitcoin-server):
#   nohup bash profile-regions.sh >> profile-watcher.log 2>&1 &
#
set -euo pipefail

NODE_LOG=/data/bitcoin-lisp/logs/node.log
PROFILE_FILE=/data/bitcoin-lisp/logs/profile.txt
PROFILE_DIR=/data/bitcoin-lisp/logs/profiles
mkdir -p "$PROFILE_DIR"

# Region table: name start end
# Stress region narrowed to 51k-55k (4000 blocks) so we stay under
# sb-sprof's :max-samples 200000 cap. Prior run with 51k-67k auto-stopped
# midway and the second SIGUSR1 wrote an empty report.
REGIONS=(
  "stress 51000 55000"
)

pid_of_node() {
  # Match the actual SBCL process by argv0 = "sbcl" with our specific args.
  # The launcher bash also matches `pgrep -f` so anchor on argv0.
  pgrep -af 'sbcl --dynamic' | awk '$2=="sbcl"{print $1; exit}'
}

log() {
  echo "[$(date '+%F %T')] $*"
}

# Watch the node log; for each "IBD Progress: H/total" line, decide.
declare -A REGION_STATE  # name -> "idle" | "armed" | "done"
for r in "${REGIONS[@]}"; do
  set -- $r
  REGION_STATE[$1]="idle"
done

extract_height() {
  # Parse "IBD Progress: NNNN/MMMM" → echo NNNN
  awk -F'Progress: ' 'NF>1 {split($2,a,"/"); print a[1]; exit}'
}

log "Watcher started; waiting for node pid..."
while [[ -z "$(pid_of_node)" ]]; do sleep 5; done
NODE_PID="$(pid_of_node)"
log "Node pid: $NODE_PID; tailing $NODE_LOG"

tail -F -n0 "$NODE_LOG" 2>/dev/null | while IFS= read -r line; do
  case "$line" in
    *"IBD Progress:"*)
      h="$(echo "$line" | extract_height)"
      [[ -z "$h" ]] && continue
      for r in "${REGIONS[@]}"; do
        set -- $r
        name=$1 ; rs=$2 ; re=$3
        st="${REGION_STATE[$name]}"
        if [[ "$st" == "idle" && "$h" -ge "$rs" ]]; then
          log "Arming sprof for region '$name' at h=$h (range $rs..$re)"
          kill -USR1 "$NODE_PID" || { log "kill -USR1 failed"; continue; }
          REGION_STATE[$name]="armed"
        elif [[ "$st" == "armed" && "$h" -ge "$re" ]]; then
          log "Stopping sprof for region '$name' at h=$h"
          kill -USR1 "$NODE_PID" || { log "kill -USR1 failed"; continue; }
          # Node writes profile.txt asynchronously; give it a few seconds.
          sleep 5
          out="$PROFILE_DIR/${name}.profile.txt"
          if [[ -f "$PROFILE_FILE" ]]; then
            cp "$PROFILE_FILE" "$out"
            log "Saved profile -> $out"
          else
            log "WARNING: $PROFILE_FILE missing after stop"
          fi
          REGION_STATE[$name]="done"
        fi
      done
      # All regions done? Exit.
      all_done=1
      for r in "${REGIONS[@]}"; do
        set -- $r
        if [[ "${REGION_STATE[$1]}" != "done" ]]; then all_done=0; break; fi
      done
      if [[ $all_done -eq 1 ]]; then
        log "All regions captured. Exiting watcher."
        exit 0
      fi
      ;;
  esac
done
