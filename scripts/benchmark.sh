#!/usr/bin/env bash
# Run the validation hot-path microbenchmarks in the project container.
#
# Usage:
#   scripts/benchmark.sh
#
# See scripts/benchmark-reindex.sh for the IBD benchmark of record.
set -euo pipefail

exec "$(dirname "$0")/docker-sbcl.sh" --dynamic-space-size 4096 --non-interactive \
  --eval '(asdf:load-system "bitcoin-lisp")' \
  --load "$(dirname "$0")/benchmark.lisp" \
  --eval '(cl-user::run-benchmarks)'
