#!/usr/bin/env bash
# Gate a build transcript on a structure defined AFTER code that uses it.
#
# SBCL inlines a DEFSTRUCT's accessors and predicate only into code compiled
# after the DEFSTRUCT itself; a caller compiled earlier -- above it in the same
# file, or in a file that loads before it -- gets a full call through the
# global function, and SBCL says so, as a STYLE-WARNING, only when it reaches
# the DEFSTRUCT: "Previously compiled calls to X could not be inlined because
# the structure definition for Y was not yet seen." compile-file's failure-p
# stays NIL, so the build passes with it buried in the transcript. Five such
# structs sat on the prune, mempool, versionbits and Erlay paths until
# 2026-09-30 (BLOCK-INDEX-ENTRY, CHAIN-STATE, MEMPOOL, VB-WARNING-CHECKER,
# PEER). A late struct is also a latent test trap: a test that stubs its
# accessor with (setf fdefinition) works only while the struct stays late.
# Fix a finding by moving the DEFSTRUCT ahead of its first reader -- earlier
# in its file, or into the sub-system's types.lisp -- or by loading the
# reading file after it.
#
# src/ and tests/ both count; refs/coalton is not ours. Attribution is by the
# file being compiled, which is the file holding the late DEFSTRUCT
# (scripts/transcript-messages.awk).
#
#   check-struct-order.sh TRANSCRIPT [SRC-ROOT]  exit 1 on a finding
#   check-struct-order.sh --self-test [SRC-ROOT] positive + negative control
#
# SRC-ROOT is the repository root as the transcript spells it, /workspace in
# the container the cold lane runs in.
set -u

if [ "${1:-}" = "--self-test" ]; then
  root=${2:-/workspace}
  tmp=$(mktemp)
  fail() { echo "check-struct-order: self-test FAILED ($1)"; rm -f "$tmp"; exit 2; }
  # SBCL's own wording, wrapped the way it prints it (SBCL 2.6.5).
  printf '; compiling file "%s/src/probe.lisp" (written today):\n; in: DEFSTRUCT CHAIN-STATE\n;     (DEFSTRUCT CHAIN-STATE)\n;\n; caught STYLE-WARNING:\n;   Previously compiled calls to BITCOIN-LISP.STORAGE:CHAIN-STATE-BEST-HEIGHT and\n;   BITCOIN-LISP.STORAGE:CHAIN-STATE-PRUNED-HEIGHT could not be inlined because the\n;   structure definition for BITCOIN-LISP.STORAGE:CHAIN-STATE was not yet\n;   seen. To avoid this warning, DEFSTRUCT should precede references to the\n;   affected functions, or they must be declared locally notinline at each call\n;   site.\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "a late struct under src/ passed"
  printf '; compiling file "%s/tests/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   Previously compiled call to BITCOIN-LISP.TESTS::PROBE-P could not be inlined\n;   because the structure definition for BITCOIN-LISP.TESTS::PROBE was not yet\n;   seen. To avoid this warning, DEFSTRUCT should precede references to the\n;   affected functions, or they must be declared locally notinline at each call\n;   site.\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "a late struct under tests/ passed"
  printf '; compiling file "%s/refs/coalton/src/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   Previously compiled call to COALTON::ENV-P could not be inlined because the\n;   structure definition for COALTON::ENV was not yet seen.\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 || fail "a dependency's own late struct was reported"
  printf '; compiling file "%s/src/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   The variable NODE is defined but never used.\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 || fail "an unrelated style warning was reported"
  rm -f "$tmp"; echo "check-struct-order: self-test ok"; exit 0
fi

transcript=$1; root=${2:-/workspace}
findings=$(awk -f "$(dirname "$0")/transcript-messages.awk" "$transcript" |
  awk -F'\t' -v ours="^$root/(src|tests)/" '
    $1 ~ ours && $2 ~ /could not be inlined because the structure definition for/ {
      print $1 ": " $2 }')

if [ -n "$findings" ]; then
  printf '%s\n' "$findings"
  echo "check-struct-order: $(printf '%s\n' "$findings" | wc -l | tr -d ' ') structure(s) defined after code that uses them -- SBCL reports this as a style warning only"
  exit 1
fi
exit 0
