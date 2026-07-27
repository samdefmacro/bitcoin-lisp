#!/usr/bin/env bash
# dev.sh — warm-image development helper (cl-agent-repl).
# Fill the PROJECT ADAPTER block; everything below it is generic.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$ROOT/.dev-runtime/swank-dev"
PIDFILE="$RUNTIME_DIR/swank.pid"
LOGFILE="$RUNTIME_DIR/swank.log"
METRICS_LOG="$RUNTIME_DIR/eval-metrics.log"

### BEGIN PROJECT ADAPTER ####################################################
# bitcoin-lisp: ALL Lisp execution goes through the project container
# (bitcoin-lisp-sbcl:2.6.5, see scripts/docker-sbcl.sh). The warm image runs
# IN the container; only the Swank port is published, to the host's
# 127.0.0.1. Dedicated FASL volume (-devimage): the shared bitcoin-lisp-fasl
# volume must never be mounted by two concurrently running containers
# (silent FASL corruption).
PORT="${DEV_SWANK_PORT:-4007}"
HOST="127.0.0.1"

start_image() {
  exec docker run --rm -i --sig-proxy=true \
    --name "bitcoin-lisp-devimage-${PORT}" \
    -v "$ROOT:/workspace" \
    -v bitcoin-lisp-fasl-devimage:/fasl-cache \
    -p "127.0.0.1:${PORT}:${PORT}" \
    -w /workspace \
    -e DEV_SWANK_PORT="$PORT" \
    bitcoin-lisp-sbcl:2.6.5 \
    sbcl --dynamic-space-size 4096 --noinform \
      --load scripts/dev-swank-server.lisp
}

# fiveam: NAME is a raw suite designator, e.g. `dev.sh test :script-tests`;
# test-all runs the whole :bitcoin-lisp-tests suite (26k+ checks).
test_one() {
  DEV_EVAL_TIMEOUT="${DEV_EVAL_TIMEOUT:-600}" \
    eval_form "(let ((r (fiveam:run $1)))
  (fiveam:explain! r)
  (unless (fiveam:results-status r) (error \"suite $1 failed\")))"
}
test_all() {
  DEV_EVAL_TIMEOUT="${DEV_EVAL_TIMEOUT:-3600}" \
    eval_form '(let ((r (fiveam:run :bitcoin-lisp-tests)))
  (fiveam:explain! r)
  (unless (fiveam:results-status r) (error "bitcoin-lisp-tests failed")))'
}
### END PROJECT ADAPTER ######################################################

usage() {
  cat <<'USAGE'
Usage: scripts/dev.sh COMMAND [ARGS]

Commands:
  start | stop | status      Manage the warm Swank dev image
  eval FORM                  Evaluate FORM in the warm image (~0.1s)
  test NAME                  Run one test in the warm image
  test-all                   Run the full suite in the warm image
  docs-check                 Verify PAX documentation transcripts
  help                       Show this help

Eval exit codes: 0 ok, 1 lisp error, 2 connection error, 3 timed out
(interrupted, image survived), 4 hard hang (restart the image). Every eval
is logged to .dev-runtime/swank-dev/eval-metrics.log.
Env: DEV_EVAL_TIMEOUT (20), DEV_EVAL_MAX_OUTPUT (10000).
USAGE
}

is_pid_running() {
  [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

port_listener() {
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true
}

wait_for_port() {
  local i
  for i in {1..120}; do
    if port_listener | grep -q ":${PORT}"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

start_server() {
  mkdir -p "$RUNTIME_DIR"
  if is_pid_running; then
    echo "Dev image already running: pid $(cat "$PIDFILE")"
    return 0
  fi
  if port_listener | grep -q ":${PORT}"; then
    echo "Port ${PORT} already has a listener; reusing it."
    return 0
  fi
  : > "$LOGFILE"
  (
    cd "$ROOT"
    start_image >>"$LOGFILE" 2>&1
  ) &
  echo $! > "$PIDFILE"
  if ! wait_for_port; then
    echo "Timed out waiting for Swank on port ${PORT}" >&2
    echo "Log: $LOGFILE" >&2
    return 1
  fi
  # A listening port is NOT readiness: with docker-published ports the
  # docker-proxy listens on the host immediately, long before in-container
  # Swank answers. Probe with a real eval until it succeeds.
  local i
  for i in {1..120}; do
    if (cd "$ROOT" && DEV_SWANK_HOST="$HOST" DEV_SWANK_PORT="$PORT" DEV_EVAL_TIMEOUT=5 \
        sbcl --script scripts/dev-swank-eval.lisp '(+ 0 0)' >/dev/null 2>&1); then
      echo "Started dev image on ${HOST}:${PORT} (pid $(cat "$PIDFILE"))"
      echo "Log: $LOGFILE"
      return 0
    fi
    sleep 5
  done
  echo "Port ${PORT} is listening but Swank never answered a probe eval" >&2
  echo "Log: $LOGFILE" >&2
  return 1
}

stop_server() {
  if is_pid_running; then
    local pid
    pid="$(cat "$PIDFILE")"
    kill "$pid" 2>/dev/null || true
    rm -f "$PIDFILE"
    echo "Stopped dev image pid $pid"
  else
    rm -f "$PIDFILE"
    echo "No helper-managed dev image is running."
  fi
}

status_server() {
  if is_pid_running; then
    echo "Helper-managed process: running pid $(cat "$PIDFILE")"
  else
    echo "Helper-managed process: not running"
  fi
  if port_listener | grep -q ":${PORT}"; then
    echo "Port ${PORT}: listening"
  else
    echo "Port ${PORT}: not listening"
  fi
}

log_metrics() { # $1 rc, $2 start_epoch, $3 form
  local snip
  snip=$(printf '%s' "$3" | tr '\n' ' ' | cut -c1-80)
  mkdir -p "$RUNTIME_DIR"
  printf '%s rc=%s dur_s=%s form=%s\n' \
    "$(date '+%Y-%m-%dT%H:%M:%S')" "$1" "$(( $(date +%s) - $2 ))" "$snip" \
    >> "$METRICS_LOG" 2>/dev/null || true
}

eval_form() {
  if [[ $# -eq 0 ]]; then
    echo "eval requires a Lisp FORM argument" >&2
    return 2
  fi
  local start rc=0
  start=$(date +%s)
  (cd "$ROOT" && DEV_SWANK_HOST="$HOST" DEV_SWANK_PORT="$PORT" \
    sbcl --script scripts/dev-swank-eval.lisp "$@") || rc=$?
  log_metrics "$rc" "$start" "$*"
  return $rc
}

docs_check() {
  (cd "$ROOT" && sbcl --non-interactive --load scripts/docs-check.lisp)
}

cmd="${1:-help}"
shift || true
case "$cmd" in
  start) start_server ;;
  stop) stop_server ;;
  status) status_server ;;
  eval) eval_form "$@" ;;
  test) test_one "$@" ;;
  test-all) test_all ;;
  docs-check) docs_check ;;
  help|-h|--help) usage ;;
  *) echo "Unknown command: $cmd" >&2; usage >&2; exit 2 ;;
esac
