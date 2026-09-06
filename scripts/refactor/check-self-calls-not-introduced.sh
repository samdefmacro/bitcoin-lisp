#!/usr/bin/env bash
# Report a definition a mechanical rewrite turned into a call to ITSELF.
#
# Usage: scripts/refactor/check-self-calls-not-introduced.sh [BASE] [PATH...]
#   BASE defaults to HEAD; PATHs default to every .lisp file that differs
#   from BASE. Exit 1 when a DEFUN/DEFMACRO names itself in the working tree
#   and did not at BASE.
#   --self-test runs the positive and negative controls and exits.
#
# Why: a scripted consolidation that inserts a helper and then replaces every
# occurrence of the shape it wraps also rewrites the HELPER'S OWN body, so the
# helper becomes an unconditional self-call. The file still compiles; the first
# caller either loops forever or exhausts the control stack, and the failure
# reads as an unrelated hang. Recorded twice: folding six reaches into one
# helper (2026-09-04), and folding thirty-nine peer=<id> pairings into
# PEER-LOG-NAME (2026-09-07), where the helper's own body became
# (format nil "~A" (peer-log-name peer)).
#
# The comparison is DIFFERENTIAL on purpose: a genuinely recursive function
# names itself at BASE too, so it cancels out and only a NEW self-reference is
# reported. Host-only: git and awk, no Lisp.
set -euo pipefail

selfnames() {  # names of toplevel DEFUN/DEFMACRO forms whose body names themselves
  awk '
    # INSTR carries across lines: a Lisp docstring spans several, and one of
    # its lines starting with "(" would otherwise end the definition early --
    # which is how the first draft of this script missed the very rewrite it
    # was written for.
    function blank(line,   i, c, out) {
      out = "";
      for (i = 1; i <= length(line); i++) { c = substr(line, i, 1);
        if (INSTR) { if (c == "\\") { i++; continue } if (c == "\"") INSTR = 0; continue }
        if (c == "\"") { INSTR = 1; continue }
        if (c == "#" && substr(line, i+1, 1) == "\\") { i += 2; continue }
        if (c == ";") break
        out = out c }
      return out }
    function selfref(name, text,   n, pos, rest, before, after, consumed) {
      n = length(name); rest = text; consumed = 0;
      while ((pos = index(rest, name)) > 0) {
        before = (consumed + pos > 1) ? substr(text, consumed + pos - 1, 1) : "";
        after = substr(rest, pos + n, 1);
        if (before !~ /[A-Za-z0-9%*<>=?!+_.&$\/-]/ && before != ":" &&
            after !~ /[A-Za-z0-9%*<>=?!+_.&$\/-]/) return 1;
        consumed += pos + n - 1; rest = substr(rest, pos + n) }
      return 0 }
    function finish() { if (name != "" && body != "" && selfref(name, body)) print name;
                        name = ""; body = "" }
    { code = blank($0);
      if (substr(code, 1, 1) == "(") { finish();
        if (match(code, /^\(def(un|macro)[ \t]+[^ \t()]+/)) {
          name = substr(code, RSTART, RLENGTH);
          sub(/^\(def(un|macro)[ \t]+/, "", name) } }
      else if (name != "") body = body "\n" code }
    END { finish() }' | sort -u
}

if [ "${1:-}" = "--self-test" ]; then
  ok=0
  hit=$(printf '(defun wrapper (x)\n  (format nil "~A" (wrapper x)))\n' | selfnames)
  [ "$hit" = "wrapper" ] || { echo "self-test: MUST flag a self-delegating wrapper, got '$hit'"; ok=1; }
  miss=$(printf '(defun wrapper (x)\n  (bl::wrapper x))\n(defun plist (x)\n  (args->plist x))\n' | selfnames)
  [ -z "$miss" ] || { echo "self-test: must NOT flag '$miss' (qualified name / suffix match)"; ok=1; }
  quoted=$(printf '(defun wrapper (x)\n  ;; wrapper is the name\n  "wrapper here"\n  (identity x))\n' | selfnames)
  [ -z "$quoted" ] || { echo "self-test: must NOT flag a name in a comment or string"; ok=1; }
  doc=$(printf '(defun wrapper (x)\n  "line one\n(paren.h:1) line two"\n  (wrapper x))\n' | selfnames)
  [ "$doc" = "wrapper" ] || { echo "self-test: a docstring line starting with '(' must not end the form, got '$doc'"; ok=1; }
  [ $ok -eq 0 ] && echo "check-self-calls-not-introduced: self-test passed"
  exit $ok
fi

base="${1:-HEAD}"; shift || true
files=()
if [ $# -eq 0 ]; then
  while IFS= read -r line; do files+=("$line"); done < <(git diff --name-only "$base" -- '*.lisp')
else
  files=("$@")
fi
status=0
for f in ${files[@]+"${files[@]}"}; do
  [ -f "$f" ] || continue
  new=$(comm -13 <(git show "$base:$f" 2>/dev/null | selfnames) <(selfnames < "$f") || true)
  if [ -n "$new" ]; then
    status=1
    printf '%s: names itself in the working tree but not at %s:\n' "$f" "$base"
    printf '  %s\n' "$new"
  fi
done
[ $status -eq 0 ] && echo "check-self-calls-not-introduced: no new self-call (base $base)"
exit $status
