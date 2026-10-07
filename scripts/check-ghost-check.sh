#!/usr/bin/env bash
# Positive control for `scripts/dev.sh ghost-check' (scripts/ghost-check.lisp),
# the warm image's deleted-definition guard, through the shipped entry point.
#
# A function the source does not have must make `dev.sh ghost-check' exit
# non-zero and name it, and a system load must warn about it; once it is gone
# the name must be gone from the report. The scanner's own reasons (no source,
# not in the build, deleted from its file) are controlled by
# tests/ghost-check-tests.lisp; this checks the wiring. It needs the warm
# image (scripts/dev.sh start). Exit 0 = the guard works.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEV="$ROOT/scripts/dev.sh"
probe='BITCOIN-LISP.TESTS::GHOST-CHECK-WIRING-PROBE'
cleanup() { "$DEV" eval "(fmakunbound '$probe)" >/dev/null 2>&1; }
trap cleanup EXIT

"$DEV" eval "(defun $probe () :ghost)" >/dev/null 2>&1
out=$("$DEV" ghost-check 2>&1); rc=$?
if [ "$rc" -eq 0 ] || ! printf '%s' "$out" | grep -q "$probe"; then
  printf '%s\n' "$out" | head -20
  echo "check-ghost-check: FAILED -- an eval'd defun left ghost-check at rc $rc"
  exit 1
fi
load_out=$("$DEV" eval '(asdf:load-system "bitcoin-lisp")' 2>&1)
if ! printf '%s' "$load_out" | grep -q "$probe"; then
  printf '%s\n' "$load_out" | tail -20
  echo "check-ghost-check: FAILED -- a system load did not warn about the probe"
  exit 1
fi
cleanup
out=$("$DEV" ghost-check 2>&1)
if printf '%s' "$out" | grep -q "$probe"; then
  printf '%s\n' "$out" | head -20
  echo "check-ghost-check: FAILED -- the probe is still reported after fmakunbound"
  exit 1
fi
echo "check-ghost-check: ok (probe -> rc $rc and a load warning; removed -> not reported)"
