#!/usr/bin/env bash
# dev.sh — warm-image development helper (Common Lisp Workbench managed).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${DEV_SWANK_PORT:-4007}"   # Swank port INSIDE the container; never published
DOCKER=docker
IMAGE="bitcoin-lisp-sbcl:2.6.5-4"  # pinned project image (docker/Dockerfile)

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    echo "ERROR: sha256sum or shasum is required for runtime identity" >&2
    return 1
  fi
}

CHECKOUT_ID="$(printf '%s' "$ROOT" | sha256_stdin)"
CHECKOUT_SHORT="${CHECKOUT_ID:0:12}"
SESSION_ID="bitcoin-lisp-$CHECKOUT_SHORT"
CONTAINER="${BITCOIN_LISP_DEV_CONTAINER:-bitcoin-lisp-dev-$CHECKOUT_SHORT}"
FASL_VOLUME="bitcoin-lisp-fasl-dev-$CHECKOUT_SHORT"
PROJECT_ID="bitcoin-lisp"          # value of PROJECT_LABEL on everything we own
PROJECT_LABEL="io.common-lisp-workbench.project"
CHECKOUT_LABEL="io.common-lisp-workbench.checkout"
MANAGED_LABEL="io.common-lisp-workbench.managed"

usage() {
  cat <<'USAGE'
Usage: scripts/dev.sh COMMAND [ARGS]

Persistent Swank development helper for bitcoin-lisp. The warm image runs
INSIDE the pinned project container (bitcoin-lisp-sbcl:2.6.5-4): SBCL never
runs on the host. The container runs scripts/dev-swank-server.lisp
(bitcoin-lisp/tests loaded, Swank listening in-container) as its main
process; every eval is a `docker exec` of the Common Lisp Workbench
hardened eval client, so the Swank port is never published to the host.
Container, session, and FASL volume identities are checkout-specific, so
two checkouts never collide or share a writable FASL cache.

Commands:
  start              Start the warm dev container (tests loaded, Swank up)
  stop               Remove the dev container (the FASL volume persists)
  status             Show whether the dev container is running
  doctor             Verify the Docker boundary and required project assets
  identity FIELD     Print checkout-id|session-id|container|image|port|fasl-volume
  load FILE          Load a Lisp file into the warm image with warnings muffled,
                     reporting only a real ERROR (a probe's benign redefinition
                     warning must not abort the load).
  eval FORM          Evaluate FORM in the warm image (via cl-workbench)
  test NAME          Run one fiveam suite (raw designator, e.g. :script-tests)
  test-all           Run the full :bitcoin-lisp-tests suite (long)
  docs-check         Verify PAX documentation transcripts in a cold container
  ui-test [PATH...]  Run the web UI node harness (default tests/ui/)
  logs               Show the dev container's output
  help               Show this help

Environment:
  DEV_SWANK_PORT             Swank port INSIDE the container, default 4007
  BITCOIN_LISP_DEV_CONTAINER Container name, default is checkout-specific; an
                             override is accepted only when its ownership
                             labels match this physical checkout
  DEV_EVAL_TIMEOUT           Eval timeout seconds, default 20 (test: 600,
                             test-all: 3600); on timeout the form is
                             interrupted and the image survives
  DEV_EVAL_MAX_OUTPUT        Output cap in chars, default 10000
Eval exit codes: 0 ok, 1 lisp error, 2 connection error, 3 timed out
(interrupted, image survived), 4 hard hang (restart the image). NOTE: heavy
FFI calls (libsecp256k1, LevelDB) cannot be interrupted mid-call — a long
foreign call may show rc=4 although the image recovers when it returns.
Common Lisp Workbench records payload-free operation outcomes under
.cl-workbench/state; raw forms are not appended to any project log.

Cold verification of record stays with scripts/docker-test.sh (full
:bitcoin-lisp-tests battery in a fresh container).
USAGE
}

# One docker call reads an object's state and ownership labels into
# INSPECT_STATUS / INSPECT_PROJECT / INSPECT_CHECKOUT / INSPECT_MANAGED.
# Absence is the exit status, not the output: a missing object still prints
# an empty line under --format. Fields are `|`-separated, not whitespace,
# because `read` collapses whitespace runs and an empty label would shift
# its neighbours.
inspect_object() { # $1 docker object kind, $2 name, $3 --format template
  local line
  line="$("$DOCKER" "$1" inspect --format "$3" "$2" 2>/dev/null)" || return 1
  IFS='|' read -r INSPECT_STATUS INSPECT_PROJECT INSPECT_CHECKOUT INSPECT_MANAGED <<<"$line"
}

labels_template() { # $1 label-map path inside the template
  printf '{{ index %s "%s" }}|{{ index %s "%s" }}|{{ index %s "%s" }}' \
    "$1" "$PROJECT_LABEL" "$1" "$CHECKOUT_LABEL" "$1" "$MANAGED_LABEL"
}

inspect_container() {
  inspect_object container "$CONTAINER" \
    "{{ .State.Status }}|$(labels_template .Config.Labels)"
}

inspect_volume() { # volumes have no state; the status field stays empty
  inspect_object volume "$FASL_VOLUME" "|$(labels_template .Labels)"
}

# The labels every object we create carries (see the run/create sites); they
# are the guard against touching another checkout's container or volume on
# the shared daemon.
inspected_is_owned() {
  [ "$INSPECT_PROJECT" = "$PROJECT_ID" ] && \
    [ "$INSPECT_CHECKOUT" = "$CHECKOUT_ID" ] && \
    [ "$INSPECT_MANAGED" = "true" ]
}

refuse_foreign_container() {
  echo "ERROR: refusing foreign or unlabeled container: $CONTAINER" >&2
  echo "       expected checkout ownership: $CHECKOUT_ID" >&2
  return 2
}

container_owned() {
  inspect_container && inspected_is_owned
}

require_owned_container() {
  container_owned || refuse_foreign_container
}

container_state() { # prints running|stopped|absent
  inspect_container || {
    echo absent
    return 0
  }
  inspected_is_owned || {
    refuse_foreign_container
    return $?
  }
  case "$INSPECT_STATUS" in
    running) echo running ;;
    *) echo stopped ;;
  esac
}

# `docker image inspect NAME` fails to resolve short names on some
# containerd-store daemons even when the image exists; `image ls -q` resolves
# them correctly, so presence checks must use it.
image_present() {
  [ -n "$("$DOCKER" image ls -q "$IMAGE")" ]
}

ensure_image() {
  if ! image_present; then
    echo "Image $IMAGE not found — building (one-time, ~20-30 min)..." >&2
    "$DOCKER" build -f "$ROOT/docker/Dockerfile" -t "$IMAGE" "$ROOT"
  fi
}

ensure_volume() {
  if inspect_volume; then
    inspected_is_owned || {
      echo "ERROR: refusing foreign FASL volume: $FASL_VOLUME" >&2
      return 2
    }
  else
    "$DOCKER" volume create \
      --label "$PROJECT_LABEL=$PROJECT_ID" \
      --label "$CHECKOUT_LABEL=$CHECKOUT_ID" \
      --label "$MANAGED_LABEL=true" \
      "$FASL_VOLUME" >/dev/null
  fi
}

start_server() {
  local state
  state="$(container_state)" || return $?
  case "$state" in
    running)
      echo "Dev container already running: $CONTAINER"
      return 0
      ;;
    stopped)
      echo "Removing exited container $CONTAINER"
      require_owned_container
      "$DOCKER" rm -f "$CONTAINER" >/dev/null
      ;;
  esac
  ensure_image
  ensure_volume
  "$DOCKER" run --detach --init --name "$CONTAINER" \
    --label "$PROJECT_LABEL=$PROJECT_ID" \
    --label "$CHECKOUT_LABEL=$CHECKOUT_ID" \
    --label "$MANAGED_LABEL=true" \
    --volume "$ROOT:/workspace" \
    --volume "$FASL_VOLUME:/fasl-cache" \
    --workdir /workspace \
    --env DEV_SWANK_PORT="$PORT" \
    "$IMAGE" \
    sbcl --dynamic-space-size 4096 --noinform \
      --load scripts/dev-swank-server.lisp >/dev/null

  # Cold FASL volume: the Coalton build takes minutes; cap the wait at 15 min.
  local i state2
  for i in {1..900}; do
    if "$DOCKER" logs "$CONTAINER" 2>&1 | grep -q "Swank dev image ready"; then
      echo "Started bitcoin-lisp dev container $CONTAINER (Swank on :$PORT inside)"
      return 0
    fi
    state2="$(container_state)" || return $?
    if [[ "$state2" != running ]]; then
      echo "Dev container exited during startup:" >&2
      "$DOCKER" logs "$CONTAINER" 2>&1 | tail -40 >&2
      return 1
    fi
    sleep 1
  done
  echo "Timed out waiting for Swank in $CONTAINER" >&2
  "$DOCKER" logs "$CONTAINER" 2>&1 | tail -40 >&2
  return 1
}

stop_server() {
  local state
  state="$(container_state)" || return $?
  if [[ "$state" == absent ]]; then
    echo "No dev container is running."
  else
    require_owned_container
    "$DOCKER" rm -f "$CONTAINER" >/dev/null
    echo "Removed dev container $CONTAINER"
  fi
}

status_server() {
  local state
  state="$(container_state)" || return $?
  echo "Dev container $CONTAINER: $state"
  if image_present; then
    echo "Dev image $IMAGE: present"
  else
    echo "Dev image $IMAGE: absent (start builds it)"
  fi
  if inspect_volume; then
    if inspected_is_owned; then
      echo "FASL volume $FASL_VOLUME: present (ownership verified)"
    else
      echo "FASL volume $FASL_VOLUME: PRESENT BUT FOREIGN" >&2
      return 2
    fi
  else
    echo "FASL volume $FASL_VOLUME: absent (start creates it)"
  fi
  echo "Checkout identity: $CHECKOUT_ID"
  if [ "$state" = running ]; then
    local published
    published="$("$DOCKER" port "$CONTAINER")"
    if [ -z "$published" ]; then
      echo "Container boundary: no host ports published"
    else
      echo "ERROR: dev container publishes a host port:" >&2
      echo "$published" >&2
      return 1
    fi
  fi
}

doctor() {
  command -v "$DOCKER" >/dev/null 2>&1 || {
    echo "ERROR: Docker CLI is unavailable; host interpreter fallback is forbidden" >&2
    return 1
  }
  "$DOCKER" version >/dev/null 2>&1 || {
    echo "ERROR: Docker daemon is unavailable; host interpreter fallback is forbidden" >&2
    return 1
  }
  [ -e "$ROOT/refs/coalton" ] || {
    echo "ERROR: refs/coalton missing — run scripts/setup-coalton.sh first" >&2
    return 1
  }
  [ -f "$ROOT/scripts/dev-swank-server.lisp" ] || {
    echo "ERROR: scripts/dev-swank-server.lisp is missing" >&2
    return 1
  }
  status_server
}

require_running() {
  local state
  state="$(container_state)" || return $?
  if [[ "$state" != running ]]; then
    echo "Dev container $CONTAINER is not running; run: scripts/dev.sh start" >&2
    return 2
  fi
}

identity_field() {
  [ "$#" -eq 1 ] || return 2
  case "$1" in
    checkout-id) printf '%s\n' "$CHECKOUT_ID" ;;
    session-id) printf '%s\n' "$SESSION_ID" ;;
    container) printf '%s\n' "$CONTAINER" ;;
    image) printf '%s\n' "$IMAGE" ;;
    port) printf '%s\n' "$PORT" ;;
    fasl-volume) printf '%s\n' "$FASL_VOLUME" ;;
    *) echo "ERROR: unknown identity field: $1" >&2; return 2 ;;
  esac
}

# Workbench adapter-only path. The canonical client is streamed over stdin;
# it is never copied into this project or persisted in the container.
exec_workbench_eval_client() {
  [ "$#" -ge 2 ] || {
    echo "ERROR: adapter-eval requires CLIENT and FORM" >&2
    return 2
  }
  local client="$1"
  shift
  [ -f "$client" ] || { echo "ERROR: canonical eval client is unavailable" >&2; return 2; }
  require_running || return $?
  local args=(--interactive --workdir /workspace
              --env DEV_SWANK_HOST=127.0.0.1
              --env DEV_SWANK_PORT="$PORT")
  [[ -n "${DEV_EVAL_TIMEOUT:-}" ]] && args+=(--env DEV_EVAL_TIMEOUT="$DEV_EVAL_TIMEOUT")
  [[ -n "${DEV_EVAL_MAX_OUTPUT:-}" ]] && args+=(--env DEV_EVAL_MAX_OUTPUT="$DEV_EVAL_MAX_OUTPUT")
  [[ -n "${DEV_SWANK_PACKAGE:-}" ]] && args+=(--env DEV_SWANK_PACKAGE="$DEV_SWANK_PACKAGE")
  "$DOCKER" exec "${args[@]}" "$CONTAINER" \
    sbcl --script /dev/stdin "$@" <"$client"
}

# A batch eval is read in COMMON-LISP-USER, which has no package-local
# nicknames: a `bl.rpc:' prefix is a SIMPLE-READER-PACKAGE-ERROR whose
# ten-frame backtrace hides the offending token, so eval_form names the token
# before the image sees it. Prints the first nickname token in the form, or
# nothing; never fails (grep's no-match status must not reach set -e -- the
# first version of this guard did exactly that and every plain eval exited 1
# with empty output, observed 2026-09-05).
eval_nickname_in_form() {
  printf '%s ' "$@" | { grep -oE '(^|[^A-Za-z0-9.-])bl(\.[a-z]+)?::?' || true; } | head -1 | sed -E 's/^[^a-z]*//'
}

# Positive AND negative control for the detector, run before every eval: a
# guard that cannot fail either way is no guard.
eval_nickname_selftest() {
  local hit miss
  hit=$(eval_nickname_in_form '(bl.rpc:foo (bl:bar))')
  miss=$(eval_nickname_in_form '(+ 1 2) (bitcoin-lisp.rpc:foo "bl.x")')
  if [[ "$hit" != "bl.rpc:" || -n "$miss" ]]; then
    echo "ERROR: dev.sh eval nickname guard self-test failed (hit='$hit' miss='$miss')" >&2
    return 1
  fi
}

# Agents wrapping (load "probe.lisp") in a handler-case on CONDITION saw the
# load aborted by SBCL's benign redefinition / style warnings and read the
# abort as a failure of the probe -- observed three times on 2026-09-05 after
# the lesson was written. This is the guarded form; the file path is the
# container-visible one (the repo is mounted at /workspace).
load_file() {
  if [[ $# -ne 1 ]]; then
    echo "load requires exactly one FILE argument" >&2
    return 2
  fi
  local file="$1"
  case "$file" in
    /*) ;;
    *) file="/workspace/$file" ;;
  esac
  eval_form "(handler-case (handler-bind ((warning (function muffle-warning))) (load \"$file\") (list :loaded \"$file\")) (error (e) (list :load-error (princ-to-string e))))"
}

eval_form() {
  if [[ $# -eq 0 ]]; then
    echo "eval requires a Lisp FORM argument" >&2
    return 2
  fi
  local workbench="${CL_WORKBENCH_BIN:-cl-workbench}"
  if [[ "$workbench" = */* ]]; then
    [ -x "$workbench" ] || {
      echo "ERROR: Common Lisp Workbench CLI is not executable: $workbench" >&2
      return 2
    }
  elif ! command -v "$workbench" >/dev/null 2>&1; then
    echo "ERROR: cl-workbench is unavailable; host Lisp fallback is forbidden" >&2
    return 2
  fi
  eval_nickname_selftest || return 2
  local nick
  nick=$(eval_nickname_in_form "$@")
  if [[ -n "$nick" ]]; then
    echo "WARNING: '$nick' is a package-local nickname; dev.sh eval reads in CL-USER," >&2
    echo "         where it does not resolve -- write the full package name (bitcoin-lisp.rpc:, ...)." >&2
  fi
  "$workbench" repl eval "$@"
}

# fiveam: NAME is a suite designator, e.g. `dev.sh test :script-tests` or
# `dev.sh test bitcoin-lisp.tests::ibd-tests`; test-all runs the whole
# :bitcoin-lisp-tests suite (37k+ checks).
#
# The designator is spliced into the form, so a symbol-named suite given
# bare (`ibd-tests`, `pkg::ibd-tests`) would be EVALUATED as a variable and
# the runner would report a backtrace that reads as a red suite.  Quote it
# unless it is already a keyword or already quoted.
suite_designator() {
  case "$1" in
    :*|\'*) printf '%s' "$1" ;;
    *) printf "'%s" "$1" ;;
  esac
}

# A large suite's `Did N checks` summary is the LAST thing printed, and the
# default 10k-char output cap drops it; the test entry points raise the cap
# the way they raise the timeout.
test_one() {
  if [[ $# -ne 1 ]]; then
    echo "test requires one fiveam suite designator, e.g. :script-tests" >&2
    return 2
  fi
  local suite; suite=$(suite_designator "$1")
  DEV_EVAL_TIMEOUT="${DEV_EVAL_TIMEOUT:-600}" \
  DEV_EVAL_MAX_OUTPUT="${DEV_EVAL_MAX_OUTPUT:-400000}" \
    eval_form "(let ((r (fiveam:run $suite)))
  (fiveam:explain! r)
  (unless r (error \"suite $suite selected no tests\"))
  (unless (fiveam:results-status r) (error \"suite $suite failed\")))"
}

test_all() {
  DEV_EVAL_TIMEOUT="${DEV_EVAL_TIMEOUT:-3600}" \
  DEV_EVAL_MAX_OUTPUT="${DEV_EVAL_MAX_OUTPUT:-400000}" \
    eval_form '(let ((r (fiveam:run :bitcoin-lisp-tests)))
  (fiveam:explain! r)
  (unless r (error "suite :bitcoin-lisp-tests selected no tests"))
  (unless (fiveam:results-status r) (error "bitcoin-lisp-tests failed")))'
}

docs_check() {
  ensure_image
  exec "$ROOT/scripts/docker-sbcl.sh" --dynamic-space-size 4096 \
    --non-interactive --load scripts/docs-check.lisp
}

# Web UI harness (tests/ui/*.test.mjs): zero-dependency node tests that drive
# the real ui/js modules through a DOM shim. Runs in the SAME pinned image as
# every other suite — node is in the image for exactly this reason
# (docker/Dockerfile). A cold one-shot container, not the warm image: these
# tests touch no Lisp, so there is nothing to keep warm.
ui_test() {
  ensure_image
  local targets=("$@")
  [ ${#targets[@]} -eq 0 ] && targets=(tests/ui/)
  exec "$DOCKER" run --rm -i \
    -v "$ROOT:/workspace:ro" -w /workspace \
    --label "$PROJECT_LABEL=$PROJECT_ID" \
    --label "$CHECKOUT_LABEL=$CHECKOUT_SHORT" \
    --label "agent=$SESSION_ID" \
    --entrypoint node "$IMAGE" --test "${targets[@]}"
}

show_logs() {
  require_owned_container
  "$DOCKER" logs "$CONTAINER" "$@"
}

cmd="${1:-help}"
shift || true
case "$cmd" in
  start) start_server ;;
  stop) stop_server ;;
  status) status_server ;;
  doctor) doctor ;;
  identity) identity_field "$@" ;;
  adapter-eval) exec_workbench_eval_client "$@" ;;
  eval) eval_form "$@" ;;
  load) load_file "$@" ;;
  test) test_one "$@" ;;
  test-all) test_all ;;
  docs-check) docs_check ;;
  ui-test) ui_test "$@" ;;
  logs) show_logs "$@" ;;
  help|-h|--help) usage ;;
  *) echo "Unknown command: $cmd" >&2; usage >&2; exit 2 ;;
esac
