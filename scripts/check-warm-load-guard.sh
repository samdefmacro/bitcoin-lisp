#!/usr/bin/env bash
# Positive control for the warm-image load guard in scripts/dev.sh
# (exec_workbench_eval_client / guarded_load_form).
#
# An ASDF load through the warm image must FAIL, visibly and with a non-zero
# status, when it compiles a reference to an undefined variable that is not
# an earmuffed special defined in the tree -- the same line the cold lane
# fails on (scripts/check-undefined-variables.sh). SBCL defers that warning
# past compile-file's failure-p, so without the guard the load returns
# normally and the warm image silently holds a function that will signal
# UNBOUND-VARIABLE when it runs (a docstring cut short by an unescaped quote
# is the usual way to get one).
#
# The control loads a throwaway ASDF system from build/ (git-ignored) twice:
#   1. with a function that reads an undefined bare word -> must exit non-zero
#      and name the variable;
#   2. with the reference removed                        -> must exit 0.
# It needs the warm image (scripts/dev.sh start). Exit 0 = the guard works.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="$ROOT/scripts/dev.sh"
dir="$ROOT/build/warm-load-guard-probe"
mkdir -p "$dir"
trap 'rm -rf "$dir"' EXIT

cat >"$dir/warm-load-guard-probe.asd" <<'EOF'
(asdf:defsystem "warm-load-guard-probe" :components ((:file "probe")))
EOF
form='(progn (asdf:load-asd "/workspace/build/warm-load-guard-probe/warm-load-guard-probe.asd") (asdf:load-system "warm-load-guard-probe" :force t) :probe-loaded)'

cat >"$dir/probe.lisp" <<'EOF'
(in-package #:cl-user)
(defun warm-load-guard-probe-fn ()
  "A docstring whose remaining prose became code reads a word like this one."
  warm-load-guard-probe-undefined-word)
EOF
out=$("$DEV" eval "$form" 2>&1); rc=$?; dirty_rc=$rc
if [ "$rc" -eq 0 ] || ! printf '%s' "$out" | grep -q 'WARM-LOAD-GUARD-PROBE-UNDEFINED-WORD'; then
  printf '%s\n' "$out" | head -30
  echo "check-warm-load-guard: FAILED -- a load with an undefined variable exited $rc"
  exit 1
fi

cat >"$dir/probe.lisp" <<'EOF'
(in-package #:cl-user)
(defun warm-load-guard-probe-fn ()
  "The same function with the stray word removed."
  :clean)
EOF
out=$("$DEV" eval "$form" 2>&1); rc=$?
if [ "$rc" -ne 0 ] || ! printf '%s' "$out" | grep -q 'PROBE-LOADED'; then
  printf '%s\n' "$out" | head -30
  echo "check-warm-load-guard: FAILED -- the clean load exited $rc"
  exit 1
fi
"$DEV" eval '(progn (asdf:clear-system "warm-load-guard-probe") (fmakunbound (quote cl-user::warm-load-guard-probe-fn)) t)' >/dev/null 2>&1
echo "check-warm-load-guard: ok (undefined variable -> rc $dirty_rc, clean load -> rc 0)"
