#!/usr/bin/env bash
# Run the full test suite in the containerized SBCL (see docker-sbcl.sh).
# Exits non-zero on any test failure.
#
# Usage:
#   scripts/docker-test.sh                       # full suite
#   scripts/docker-test.sh :crypto-tests         # one suite
#   scripts/docker-test.sh --fresh-fasl [SUITE]  # compile everything from source
#
# --fresh-fasl (or BITCOIN_LISP_FRESH_FASL=1) runs against a brand-new FASL
# volume that is removed when the run ends. The ordinary cold lane mounts a
# persistent per-checkout volume, and ASDF does not track macro expansions:
# after a macro changes, every file that USED it keeps its stale expansion
# through a warm rebuild, an image restart AND a cold run (2026-08-19, cost
# three misdiagnoses including a false bisect). A fresh volume is the only
# run that compiles what the source says. It costs the Coalton build (a few
# minutes); use it for any PR that changes a macro or a defstruct.
set -euo pipefail

FRESH="${BITCOIN_LISP_FRESH_FASL:-0}"
if [ "${1:-}" = "--fresh-fasl" ]; then
  FRESH=1
  shift
fi
SUITE="${1:-:bitcoin-lisp-tests}"

if [ "$FRESH" = 1 ]; then
  # Unique per run so two fresh runs never share a cache; removed on exit,
  # whichever way the run ends.
  BITCOIN_LISP_FASL_VOLUME="bitcoin-lisp-fasl-fresh-$(date +%s)-$$"
  export BITCOIN_LISP_FASL_VOLUME
  echo "fresh FASL volume: $BITCOIN_LISP_FASL_VOLUME (removed on exit)" >&2
fi

# Not exec: the EXIT trap must run after the container returns, and the
# transcript is scanned afterwards.
TRANSCRIPT="$(mktemp -t bitcoin-lisp-cold)"
trap 'rm -f "$TRANSCRIPT"; [ "$FRESH" = 1 ] && docker volume rm -f "$BITCOIN_LISP_FASL_VOLUME" >/dev/null 2>&1; true' EXIT
"$(dirname "$0")/docker-sbcl.sh" --dynamic-space-size 4096 --non-interactive \
  --eval '(asdf:load-system "bitcoin-lisp/tests")' \
  --eval "(let ((r (fiveam:run $SUITE)))
            (fiveam:explain! r)
            (when (null r)
              (format t \"~&suite $SUITE selected no tests~%\")
              (sb-ext:exit :code 1))
            (unless (fiveam:results-status r) (sb-ext:exit :code 1)))" \
  2>&1 | tee "$TRANSCRIPT"
rc=${PIPESTATUS[0]}

# A definition that replaces one already loaded under the same name is a
# duplicate -- two files in one package defining the same function, the later
# silently winning. The 2026-08-27 cleanup found two: FSYNC-DIRECTORY (the
# active copy fsynced a file where the callers meant its parent directory)
# and TAGGED-HASH (a dead pure-Lisp copy). SBCL warned about both on every
# cold run and nobody read it; now the run fails.
if grep -q "WARNING: redefining BITCOIN-LISP" "$TRANSCRIPT"; then
  echo "ERROR: a bitcoin-lisp definition was redefined during the load:" >&2
  grep "WARNING: redefining BITCOIN-LISP" "$TRANSCRIPT" >&2
  exit 1
fi

# ASDF's compilation unit defers SBCL's "undefined variable" warnings past
# compile-file's failure-p, so a from-scratch build passes with them buried in
# the transcript: 2026-08-28 found 157 such lines in a green run, four of them
# docstrings cut short by an unescaped quote whose remaining prose had become
# code, plus a setf of a defvar that had been deleted. The checker tolerates
# only earmuffed names that are defined somewhere in the tree (forward
# references across load order); it self-tests first so it cannot pass
# vacuously.
"$(dirname "$0")/check-undefined-variables.sh" --self-test "$(dirname "$0")/.." >&2 || exit 1
if ! "$(dirname "$0")/check-undefined-variables.sh" "$TRANSCRIPT" "$(dirname "$0")/.." >&2; then
  echo "ERROR: the load referenced variables that do not exist (see above)" >&2
  exit 1
fi
exit "$rc"
