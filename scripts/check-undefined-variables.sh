#!/usr/bin/env bash
# Gate a build transcript on SBCL's "undefined variable" warnings.
#
# ASDF wraps the whole build in WITH-COMPILATION-UNIT, which defers these
# warnings to the end of the unit -- past COMPILE-FILE's failure-p -- so a
# from-scratch build passes with them buried in the transcript (observed
# 2026-08-28: 157 lines in a green build, four of them docstrings cut short
# by an unescaped inner quote, whose remaining prose had become code).
#
# A warning is tolerated only when the symbol is earmuffed (*name* / +name+)
# AND a defvar/defparameter/defconstant/define-constant/defglobal for it exists somewhere in
# the tree -- i.e. a forward reference across load order.  Anything else
# (a bare word, or a special that no longer exists) fails.
#
#   check-undefined-variables.sh TRANSCRIPT [SRC-ROOT]   exit 1 on a finding
#   check-undefined-variables.sh --self-test              positive control
set -u
if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp)
  printf ';   undefined variable: BITCOIN-LISP::*NO-SUCH-SPECIAL-EVER*\n' > "$tmp"
  if "$0" "$tmp" "${2:-.}" >/dev/null 2>&1; then
    echo "check-undefined-variables: self-test FAILED (a bogus special passed)"; rm -f "$tmp"; exit 2
  fi
  printf ';   undefined variable: BITCOIN-LISP.STORAGE::PAIRS\n' > "$tmp"
  if "$0" "$tmp" "${2:-.}" >/dev/null 2>&1; then
    echo "check-undefined-variables: self-test FAILED (a bare word passed)"; rm -f "$tmp"; exit 2
  fi
  rm -f "$tmp"; echo "check-undefined-variables: self-test ok"; exit 0
fi
transcript=$1; root=${2:-.}
scan() {
grep -o 'undefined variable: [^ ]*' "$transcript" | sort -u | while read -r _ _ sym; do
  name=${sym##*:}
  case "$name" in
    \*?*\*|+?*+) ;;   # earmuffed: a special or constant, maybe defined later
    *) echo "undefined variable is not a special: $sym"; continue ;;
  esac
  lname=$(printf '%s' "$name" | tr 'A-Z' 'a-z')
  pat=${lname//\*/\\*}; pat=${pat//+/\\+}
  if ! grep -rqiE "\((alexandria:)?(defvar|defparameter|defconstant|define-constant|defglobal|sb-ext:defglobal|define-symbol-macro|defvar-unbound) ${pat}(\$|[[:space:]])" "$root/src" "$root/tests" 2>/dev/null; then
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
