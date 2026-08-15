#!/usr/bin/env bash
# Run the full test suite in the containerized SBCL (see docker-sbcl.sh).
# Exits non-zero on any test failure.
#
# Usage:
#   scripts/docker-test.sh                 # full suite
#   scripts/docker-test.sh :crypto-tests   # one suite
set -euo pipefail

SUITE="${1:-:bitcoin-lisp-tests}"

exec "$(dirname "$0")/docker-sbcl.sh" --dynamic-space-size 4096 --non-interactive \
  --eval '(asdf:load-system "bitcoin-lisp/tests")' \
  --eval "(let ((r (fiveam:run $SUITE)))
            (fiveam:explain! r)
            (when (null r)
              (format t \"~&suite $SUITE selected no tests~%\")
              (sb-ext:exit :code 1))
            (unless (fiveam:results-status r) (sb-ext:exit :code 1)))"
