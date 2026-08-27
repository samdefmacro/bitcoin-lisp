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
  trap 'docker volume rm -f "$BITCOIN_LISP_FASL_VOLUME" >/dev/null 2>&1 || true' EXIT
  echo "fresh FASL volume: $BITCOIN_LISP_FASL_VOLUME (removed on exit)" >&2
fi

# Not exec: the EXIT trap must run after the container returns.
"$(dirname "$0")/docker-sbcl.sh" --dynamic-space-size 4096 --non-interactive \
  --eval '(asdf:load-system "bitcoin-lisp/tests")' \
  --eval "(let ((r (fiveam:run $SUITE)))
            (fiveam:explain! r)
            (when (null r)
              (format t \"~&suite $SUITE selected no tests~%\")
              (sb-ext:exit :code 1))
            (unless (fiveam:results-status r) (sb-ext:exit :code 1)))"
