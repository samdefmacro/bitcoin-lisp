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
# The FASL cache lives in a named volume scoped to THIS checkout's path
# (per-SBCL-version inside, VM-local so it is fast and never touches the host
# cache). Scoping matters: a single shared 'bitcoin-lisp-fasl' volume is
# written by every checkout on the machine, so a worktree whose refs/coalton
# differs from whoever wrote the cache last loads a half-stale image and dies
# with "attempt to redefine ... TYPE-ENTRY incompatibly" before running a
# single test -- and two concurrent runs corrupt each other's FASLs silently.
# scripts/dev.sh has always scoped its volume this way; this is the same
# identity. Override with BITCOIN_LISP_FASL_VOLUME if you really want to share
# one.
# Builds the image on first use (~20-30 min: SBCL bootstrap + secp256k1).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=bitcoin-lisp-sbcl:2.6.5-2

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  else
    echo "ERROR: sha256sum or shasum is required for runtime identity" >&2
    exit 1
  fi
}
CHECKOUT_SHORT="$(printf '%s' "$REPO" | sha256_stdin)"
CHECKOUT_SHORT="${CHECKOUT_SHORT:0:12}"
FASL_VOLUME="${BITCOIN_LISP_FASL_VOLUME:-bitcoin-lisp-fasl-cold-$CHECKOUT_SHORT}"

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
  -v "$FASL_VOLUME":/fasl-cache \
  --label "io.common-lisp-workbench.checkout=$CHECKOUT_SHORT" \
  -w /workspace \
  "$IMAGE" sbcl "$@"
