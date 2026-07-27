#!/bin/bash
# Claude Code PostToolUse hook: delimiter-balance check on edited Lisp files.
# stdin: hook JSON. Exit 2 + stderr => fed back to the agent for a same-turn fix.
# The checker is a pure lexical scan (scripts/check-parens.lisp): no READ, so it
# is safe against #. and does not depend on packages existing. ~30ms per file.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
payload=$(cat)
f=$(printf '%s' "$payload" | jq -r '.tool_input.file_path // .tool_response.filePath // empty' 2>/dev/null)
[ -z "$f" ] && exit 0
case "$f" in
  *.lisp|*.asd) ;;
  *) exit 0 ;;
esac
[ -f "$f" ] || exit 0
# Metrics: one line per checked edit (ok/CAUGHT), so hook value is measurable.
HOOK_LOG="$DIR/../.dev-runtime/paren-hook.log"
mkdir -p "$DIR/../.dev-runtime" 2>/dev/null || true
if ! err=$(sbcl --script "$DIR/check-parens.lisp" "$f" 2>&1); then
  printf '%s CAUGHT %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$f" >> "$HOOK_LOG" 2>/dev/null || true
  echo "$err" >&2
  exit 2
fi
printf '%s ok %s\n' "$(date '+%Y-%m-%dT%H:%M:%S')" "$f" >> "$HOOK_LOG" 2>/dev/null || true
exit 0
