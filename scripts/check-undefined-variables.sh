#!/usr/bin/env bash
# Gate a build transcript on SBCL's "undefined variable" warnings.
#
# ASDF wraps the whole build in WITH-COMPILATION-UNIT, which defers these
# warnings to the end of the unit -- past COMPILE-FILE's failure-p -- so a
# from-scratch build passes with them buried in the transcript (observed
# 2026-08-28: 157 lines in a green build, four of them docstrings cut short
# by an unescaped inner quote, whose remaining prose had become code).
#
# EVERY such warning fails, a forward reference included. Until 2026-09-29
# an earmuffed name defined LATER in the load order was tolerated; the tree
# carried 19 of them, and one was a real defect: accept-validated-tx bound
# *mempool-removal-reason* before its DEFVAR had been read, so the binding
# was LEXICAL and every BIP125 replacement was announced with the caller's
# reason instead of :replaced (SBCL says so only as a style warning, "using
# the lexical binding of the symbol"). A definition goes ahead of its first
# use -- earlier in the same file, or into an earlier file of the same
# sub-system (src/config.lisp holds the node globals the lower layers name,
# src/networking/specials.lisp the protocol's) -- never a (declaim (special)).
#
# The message still says which case it is: a forward reference (the name is
# defined somewhere in the tree, just too late), a special that no longer
# exists, or a bare word (usually a docstring cut short).
#
#   check-undefined-variables.sh TRANSCRIPT [REPO-ROOT]   exit 1 on a finding
#   check-undefined-variables.sh --self-test [REPO-ROOT]  positive + negative control
set -u
if [ "${1:-}" = "--self-test" ]; then
  root=${2:-.}
  tmp=$(mktemp)
  fail() { echo "check-undefined-variables: self-test FAILED ($1)"; rm -f "$tmp"; exit 2; }
  printf ';   undefined variable: BITCOIN-LISP::*NO-SUCH-SPECIAL-EVER*\n' > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "a bogus special passed"
  printf ';   undefined variable: BITCOIN-LISP.STORAGE::PAIRS\n' > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 && fail "a bare word passed"
  # *NODE* is defined in the tree: a reference compiled before its DEFVAR is
  # a forward reference, and that fails too now.
  printf ';   undefined variable: BITCOIN-LISP:*NODE*\n' > "$tmp"
  out=$("$0" "$tmp" "$root" 2>&1) && fail "a forward reference passed"
  printf '%s' "$out" | grep -q 'forward reference' || fail "a forward reference was not named as one"
  printf '; compiling file "/workspace/src/probe.lisp":\n; caught STYLE-WARNING:\n;   The variable X is defined but never used.\n' > "$tmp"
  "$0" "$tmp" "$root" >/dev/null 2>&1 || fail "a transcript without the warning failed"
  rm -f "$tmp"; echo "check-undefined-variables: self-test ok"; exit 0
fi
transcript=$1; root=${2:-.}
scan() {
grep -o 'undefined variable: [^ ]*' "$transcript" | sort -u | while read -r _ _ sym; do
  name=${sym##*:}
  case "$name" in
    \*?*\*|+?*+) ;;   # earmuffed: a special or constant
    *) echo "undefined variable is not a special: $sym"; continue ;;
  esac
  lname=$(printf '%s' "$name" | tr 'A-Z' 'a-z')
  pat=${lname//\*/\\*}; pat=${pat//+/\\+}
  if grep -rqiE "\((alexandria:)?(defvar|defparameter|defconstant|define-constant|defglobal|sb-ext:defglobal|define-symbol-macro|defvar-unbound) ${pat}(\$|[[:space:]])" "$root/src" "$root/tests" 2>/dev/null; then
    echo "forward reference: $sym is used before its definition loads -- move the definition ahead of its first use"
  else
    echo "undefined variable has no definition in the tree: $sym"
  fi
done
}
findings=$(scan)
if [ -n "$findings" ]; then
  printf '%s\n' "$findings"
  echo "check-undefined-variables: $(printf '%s\n' "$findings" | wc -l | tr -d ' ') finding(s) -- see the transcript's 'undefined variable' lines"
  exit 1
fi
exit 0
