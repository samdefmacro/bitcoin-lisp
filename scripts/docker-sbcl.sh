#!/usr/bin/env bash
# Run the project's SBCL (2.6.5, containerized) with the repo mounted at
# /workspace — isolates this project's toolchain from any other SBCL on the
# host (Homebrew's, other apps'), and matches the production nodes' SBCL
# version exactly. See docker/Dockerfile.
#
# Usage:
#   scripts/docker-sbcl.sh                          # interactive REPL
#   scripts/docker-sbcl.sh --non-interactive --eval '(+ 1 2)'
#
# The FASL cache lives in the named volume 'bitcoin-lisp-fasl' (per-SBCL-
# version inside, VM-local so it is fast and never touches the host cache).
# Builds the image on first use (~20-30 min: SBCL bootstrap + secp256k1).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=bitcoin-lisp-sbcl:2.6.5

if [ ! -e "$REPO/refs/coalton" ]; then
  echo "ERROR: refs/coalton missing — run scripts/setup-coalton.sh first" >&2
  exit 1
fi

# `docker image inspect NAME` fails to resolve short names on some
# containerd-store daemons even when the image exists; `image ls -q` does.
if [ -z "$(docker image ls -q "$IMAGE")" ]; then
  echo "Image $IMAGE not found — building (one-time, ~20-30 min)..." >&2
  docker build -f "$REPO/docker/Dockerfile" -t "$IMAGE" "$REPO"
fi

TTY_FLAGS="-i"
[ -t 0 ] && [ -t 1 ] && TTY_FLAGS="-it"

exec docker run --rm $TTY_FLAGS \
  -v "$REPO:/workspace" \
  -v bitcoin-lisp-fasl:/fasl-cache \
  -w /workspace \
  "$IMAGE" sbcl "$@"
