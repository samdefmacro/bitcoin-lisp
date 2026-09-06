#!/usr/bin/env bash
# Report comment lines a mechanical rewrite dropped.
#
# Usage: scripts/refactor/check-comments-kept.sh [BASE] [PATH...]
#   BASE defaults to HEAD; PATHs default to every .lisp file that differs
#   from BASE. Exit 1 when a comment text present in BASE is missing from the
#   working tree (a moved comment is fine: the comparison is a multiset of
#   trimmed comment texts per file, not positions).
#
# Why: a reader over the forms that swaps branches or deletes clauses takes
# the comments between them along, and nothing else notices -- the code is
# equivalent and every suite stays green. Twice in the second-round refactor
# (wave G: four if-branch swaps, three cond-clause deletions) the loss was
# found by review, after merge. Run this before committing any batch rewrite
# and account for every line it prints. Host-only: git and awk, no Lisp.
set -euo pipefail
base="${1:-HEAD}"; shift || true
files=()
if [ $# -eq 0 ]; then
  # Not mapfile: this script's own host runs bash 3.2, which has none.
  while IFS= read -r line; do files+=("$line"); done < <(git diff --name-only "$base" -- '*.lisp')
else
  files=("$@")
fi
comments() {  # comment texts, one per line, trimmed, sorted: ';' to end of line outside strings
  # INSTR carries across lines: a Lisp string spans them (a multi-line format
  # control with "~\n ...; foo" in it otherwise reads as a comment, and
  # rewording that string then reports a comment nobody wrote as lost).
  awk '
    { line=$0; out="";
      for (i=1;i<=length(line);i++) { c=substr(line,i,1);
        if (INSTR) { if (c=="\\") { i++; continue } if (c=="\"") INSTR=0; continue }
        if (c=="\"") { INSTR=1; continue }
        if (c=="#" && substr(line,i+1,1)=="\\") { i+=2; continue }
        if (c==";") { out=substr(line,i); break } }
      if (out!="") { gsub(/^[; \t]+|[ \t]+$/,"",out); if (out!="") print out } }' | sort
}
status=0
for f in ${files[@]+"${files[@]}"}; do
  [ -f "$f" ] || continue
  lost=$(comm -23 <(git show "$base:$f" 2>/dev/null | comments) <(comments < "$f") || true)
  if [ -n "$lost" ]; then
    status=1
    printf '%s: comment text present at %s, gone from the working tree:\n' "$f" "$base"
    printf '  ; %s\n' "$lost"
  fi
done
[ $status -eq 0 ] && echo "check-comments-kept: no comment text lost (base $base)"
exit $status
