#!/usr/bin/env bash
# Rewrite explicit bitcoin-lisp.* package prefixes to their package-local
# nicknames. The rules are derived from bitcoin-lisp.nicknames:*package-nicknames*
# in src/util/package.lisp, the one table. Idempotent: run it on any branch after a
# rebase onto the nickname change instead of resolving the conflicts by hand.
#
#   scripts/refactor/apply-nicknames.sh [FILE|DIR ...]   # default: src tests
#
# Only a prefix followed by a colon is touched, so package NAMES in defpackage
# forms, strings and comments are left alone. tests/structural-tests.lisp is
# excluded: its baselines are real package names as data.
set -euo pipefail
cd "$(dirname "$0")/../.."
targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=(src tests)
files=$(find "${targets[@]}" -name '*.lisp' ! -name structural-tests.lisp)
args=()
while read -r nick full; do
  args+=(-e "s/${full//./\\.}:/$nick:/g")
done < <(sed -n 's/.*("\([A-Z.]*\)" \. "\(BITCOIN-LISP[A-Z.-]*\)").*/\1 \2/p' src/util/package.lisp | tr 'A-Z' 'a-z')
rules=$(( ${#args[@]} / 2 ))
[ "$rules" -ge 10 ] || { echo "ERROR: could not read the nickname table from src/util/package.lisp" >&2; exit 1; }
sed -i '' "${args[@]}" \
  $files
echo "nicknames applied to $(echo "$files" | wc -l | tr -d ' ') files ($rules rules)"
