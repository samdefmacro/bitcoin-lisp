#!/usr/bin/env bash
# Gate a build transcript on SBCL's unused-variable and IGNORE-declaration
# style warnings, and on a LEXICAL binding of an earmuffed name.
#
# Each of these is a STYLE-WARNING, so COMPILE-FILE's failure-p stays NIL and
# the cold lane passes with it buried in the transcript -- the same blind
# spot check-wrong-arity-calls.sh covers for argument counts. Most are dead
# parameters, but not all: "using the lexical binding of the symbol
# (*NAME*), not the dynamic binding" is a LET of a special compiled before
# its DEFVAR, which the callee can never see (observed 2026-09-29: every
# BIP125 replacement was announced with the caller's removal reason instead
# of :replaced). Fix a finding at its site: drop the dead parameter or
# binding, IGNORE a parameter a protocol fixes (a hook's lambda list), use
# IGNORABLE where a macro reads the variable (DOTIMES, WITH-OPEN-FILE), and
# move a DEFVAR ahead of its first binding.
#
# Warnings raised while compiling the project's src/ AND tests/ count;
# refs/coalton is not ours. tests/ was outside the gate until 2026-09-30 and
# had gathered 30 of these, three of them wrong answers rather than noise: a
# LET binding a test meant as a knob (a constant that no longer existed, so
# the callee never saw it), a LET* binding named IGNORE-ERRORS, and IGNORE
# declarations on variables of an outer scope that the body did use.
# Attribution is by the file being compiled (scripts/transcript-messages.awk).
#
#   check-unused-variables.sh TRANSCRIPT [SRC-ROOT]  exit 1 on a finding
#   check-unused-variables.sh --self-test [SRC-ROOT] positive + negative control
#
# SRC-ROOT is the repository root as the transcript spells it, /workspace in
# the container the cold lane runs in.
set -u

if [ "${1:-}" = "--self-test" ]; then
  root=${2:-/workspace}
  tmp=$(mktemp)
  fail() { echo "check-unused-variables: self-test FAILED ($1)"; rm -f "$tmp"; exit 2; }
  printf '; compiling file "%s/src/probe.lisp" (written today):\n; in: DEFUN F\n; caught STYLE-WARNING:\n;   The variable NODE is defined but never used.\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "an unused variable under src/ passed"
  printf '; compiling file "%s/src/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   reading an ignored variable: ROUND\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "a read of an ignored variable passed"
  printf '; compiling file "%s/tests/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   using the lexical binding of the symbol (BITCOIN-LISP::*SOME-SPECIAL*), not the\n;   dynamic binding, even though the name follows\n;   the usual naming convention (names like *FOO*) for special variables\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "a wrapped lexical binding of a special under tests/ passed"
  printf '; compiling file "%s/tests/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   The variable STATE is defined but never used.\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "an unused variable under tests/ passed"
  printf '; compiling file "%s/tests/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   IGNORE declaration for a variable from outer scope: DIR\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "an outer-scope IGNORE under tests/ passed"
  printf '; compiling file "%s/refs/coalton/src/probe.lisp" (written today):\n; caught STYLE-WARNING:\n;   The variable ENV is defined but never used.\n' "$root" > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 || fail "a dependency's own warning was reported"
  rm -f "$tmp"; echo "check-unused-variables: self-test ok"; exit 0
fi

transcript=$1; root=${2:-/workspace}
findings=$(awk -f "$(dirname "$0")/transcript-messages.awk" "$transcript" |
  awk -F'\t' -v ours="^$root/(src|tests)/" '
    $1 ~ ours && ($2 ~ /using the lexical binding of the symbol/ ||
                 $2 ~ /The variable [^ ]+ is defined but never used/ ||
                 $2 ~ /reading an ignored variable/ ||
                 $2 ~ /is being set even though it was declared to be ignored/ ||
                 $2 ~ /IGNORE declaration for an unknown variable/ ||
                 $2 ~ /IGNORE declaration for a variable from outer scope/ ||
                 $2 ~ /IGNORABLE declaration for a variable from outer scope/) { print $1 ": " $2 }')

if [ -n "$findings" ]; then
  printf '%s\n' "$findings"
  echo "check-unused-variables: $(printf '%s\n' "$findings" | wc -l | tr -d ' ') unused-variable / ignore-declaration warning(s) -- SBCL reports these as style warnings only"
  exit 1
fi
exit 0
