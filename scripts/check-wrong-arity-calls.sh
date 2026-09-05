#!/usr/bin/env bash
# Gate a build transcript on SBCL's wrong-argument-count warnings.
#
# A call that hands a function SBCL ALREADY KNOWS the wrong number of
# arguments is only a STYLE-WARNING ("The function X is called with three
# arguments, but wants exactly one."), so COMPILE-FILE's failure-p stays NIL
# and the whole cold lane passes with the call buried in the transcript.  The
# call itself can never do anything but signal SB-INT:SIMPLE-PROGRAM-ERROR
# when it runs, and if it sits inside an ignore-errors it does not even do
# that -- observed 2026-09-05: a test's (bt:join-thread th :timeout 5) had
# been failing silently, so the thread it meant to join was never joined.
#
# (When the callee is defined in the SAME file, SBCL reports a full WARNING
# and the build fails on its own; this gate is for every other case.)
#
# Only warnings raised while compiling the project's own files count.  A
# dependency compiled from the same mount -- refs/coalton -- is not ours to
# fix, so attribution is by the file being compiled, not by the package of
# the function named: the join-thread case names BORDEAUX-THREADS:JOIN-THREAD
# and is entirely our bug.
#
#   check-wrong-arity-calls.sh TRANSCRIPT [SRC-ROOT]  exit 1 on a finding
#   check-wrong-arity-calls.sh --self-test [SRC-ROOT] positive control
#
# SRC-ROOT is the repository root as the transcript spells it, /workspace in
# the container the cold lane runs in.
set -u

if [ "${1:-}" = "--self-test" ]; then
  root=${2:-/workspace}
  tmp=$(mktemp)
  printf '; compiling file "%s/src/probe.lisp" (written today):\n;   The function BORDEAUX-THREADS:JOIN-THREAD is called with three arguments, but wants exactly one.\n' "$root" > "$tmp"
  if "$0" "$tmp" "$root" >/dev/null 2>&1; then
    echo "check-wrong-arity-calls: self-test FAILED (a wrong-arity call under src/ passed)"; rm -f "$tmp"; exit 2
  fi
  printf '; compiling file "%s/tests/probe.lisp" (written today):\n;   The function BITCOIN-LISP.TESTS::A-NAME-LONG-ENOUGH-TO-WRAP-THE-LINE is\n;   called with three arguments, but wants exactly one.\n' "$root" > "$tmp"
  if "$0" "$tmp" "$root" >/dev/null 2>&1; then
    echo "check-wrong-arity-calls: self-test FAILED (a message wrapped onto two lines passed)"; rm -f "$tmp"; exit 2
  fi
  printf '; compiling file "%s/refs/coalton/src/probe.lisp" (written today):\n;   The function COALTON-IMPL::F is called with three arguments, but wants exactly one.\n' "$root" > "$tmp"
  if ! "$0" "$tmp" "$root" >/dev/null 2>&1; then
    echo "check-wrong-arity-calls: self-test FAILED (a dependency's own warning was reported)"; rm -f "$tmp"; exit 2
  fi
  rm -f "$tmp"; echo "check-wrong-arity-calls: self-test ok"; exit 0
fi

transcript=$1; root=${2:-/workspace}
findings=$(awk -v pat="^$root/(src|tests)/" '
  # A compiler message body is indented under its own "; " prefix and a long
  # one wraps, so consecutive continuation lines are joined before matching.
  function flush(   ) {
    if (msg ~ /is called with/ && file ~ pat) print file ": " msg
    msg = ""
  }
  /^;   / { line = substr($0, 5); msg = (msg == "" ? line : msg " " line); next }
  {
    flush()
    if ($0 ~ /^; compiling file "/) { f = $0; sub(/^.*compiling file "/, "", f); sub(/".*$/, "", f); file = f }
    else if ($0 ~ /^; file: /) { file = substr($0, 9) }
  }
  END { flush() }
' "$transcript")

if [ -n "$findings" ]; then
  printf '%s\n' "$findings"
  echo "check-wrong-arity-calls: $(printf '%s\n' "$findings" | wc -l | tr -d ' ') call(s) with the wrong argument count -- SBCL reports these as style warnings only"
  exit 1
fi
exit 0
