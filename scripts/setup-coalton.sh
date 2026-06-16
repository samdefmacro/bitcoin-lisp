#!/usr/bin/env bash
# Fetch + pin the Coalton checkout that bitcoin-lisp builds against. See BUILD.md.
#
# bitcoin-lisp.asd pushes refs/coalton/ onto asdf:*central-registry*, so that
# vendored clone IS the Coalton the node compiles with. refs/ is .gitignore'd
# (line 43), so the checkout is NOT tracked in this repo -- this script
# reproduces it deterministically.
#
# PINNED -- do NOT float to Coalton main: Coalton has no releases, and its
# bleeding edge has breaking changes this codebase's interop does not track:
#   - the `lisp` FFI form now requires `(-> type)` return-type syntax
#     (was a bare `type`), and
#   - `Unit -> X` functions now need an explicit parameter in the definition.
# The pin below is ~6 weeks newer than the latest Quicklisp-curated Coalton
# (2026-01-01 dist), compiles cleanly under SBCL 2.6.5, and passes the full suite.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${TARGET:-$REPO_ROOT/refs/coalton}"
REMOTE="${COALTON_REMOTE:-https://github.com/coalton-lang/coalton.git}"
PIN="${COALTON_PIN:-7ffbd50f3589f09719d995d6d973c30399407a98}"

command -v git >/dev/null 2>&1 || { echo "ERROR: git not found"; exit 1; }

if [ -d "$TARGET/.git" ]; then
  echo "Updating existing Coalton checkout at $TARGET"
  git -C "$TARGET" fetch -q origin
else
  echo "Cloning Coalton -> $TARGET"
  mkdir -p "$(dirname "$TARGET")"
  # Full clone (not shallow): the pin is a historical commit, not the tip.
  git clone -q "$REMOTE" "$TARGET"
fi

git -C "$TARGET" checkout -q "$PIN"
echo "Coalton pinned at: $(git -C "$TARGET" rev-parse --short HEAD)  $(git -C "$TARGET" log -1 --format=%s)"
