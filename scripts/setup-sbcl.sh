#!/usr/bin/env bash
# Build SBCL 2.6.5 from source via a local bootstrap chain, for running the
# bitcoin-lisp nodes. See BUILD.md for the full rationale.
#
# WHY a custom SBCL:
#   The mainnet node crashed at chain tip under the distro SBCL 2.1.11 (Nov 2021)
#   with "fatal error: GC invariant lost" -- a heap-corruption bug in its old
#   multithreaded gencgc, triggered by mainnet-scale allocation. SBCL 2.6.5 fixes
#   it (mainnet then ran 12h+ clean, 0 crashes).
#
# WHY build from source (not apt, not a prebuilt binary):
#   - apt only ships 2.1.11 on Ubuntu 22.04.
#   - the official 2.6.5 prebuilt Linux binary needs glibc 2.38; this host has
#     glibc 2.35 (Ubuntu 22.04), so it won't run.
#   - 2.1.11 is too old to cross-compile 2.6.5 directly (a host warning is fatal
#     in genesis), so we bootstrap through intermediate versions -- each stage
#     compiles the next, all linked against the host's own glibc.
#
# Result: $PREFIX/bin/sbcl (SBCL 2.6.5). The system SBCL is left untouched.
#
# Usage:  scripts/setup-sbcl.sh
# Env:    PREFIX     install dir          (default /data/bitcoin-lisp/sbcl-final)
#         HOPS       bootstrap chain      (default "2.3.5 2.4.11 2.6.5")
#         HOST_SBCL  initial build host   (default "sbcl" -- the system 2.1.11)
#         WORKDIR    scratch build dir    (default <PREFIX parent>/sbcl-bootstrap-build)
set -euo pipefail

PREFIX="${PREFIX:-/data/bitcoin-lisp/sbcl-final}"
HOPS="${HOPS:-2.3.5 2.4.11 2.6.5}"
HOST_SBCL="${HOST_SBCL:-sbcl}"
WORKDIR="${WORKDIR:-$(dirname "$PREFIX")/sbcl-bootstrap-build}"
REPO="https://github.com/sbcl/sbcl.git"

# Prerequisites: git, make, a C compiler (cc or gcc), zlib headers, and a host lisp.
command -v git  >/dev/null 2>&1 || { echo "ERROR: git not found"; exit 1; }
command -v make >/dev/null 2>&1 || { echo "ERROR: make not found (apt install build-essential)"; exit 1; }
command -v cc   >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || \
  { echo "ERROR: no C compiler (apt install build-essential zlib1g-dev)"; exit 1; }
command -v "$HOST_SBCL" >/dev/null 2>&1 || \
  { echo "ERROR: host lisp '$HOST_SBCL' not found (apt install sbcl)"; exit 1; }

echo "Building SBCL via chain: $HOPS   (host: $HOST_SBCL)   -> $PREFIX"
rm -rf "$WORKDIR"; mkdir -p "$WORKDIR"

# Each hop builds in-place; its run-sbcl.sh becomes the host for the next hop.
# Only the final hop is installed (to $PREFIX).
HOST="$HOST_SBCL --no-userinit --no-sysinit --disable-debugger"
LAST=""
for V in $HOPS; do
  echo "[$(date '+%H:%M:%S')] hop sbcl-$V ..."
  git clone -q --depth 1 --branch "sbcl-$V" "$REPO" "$WORKDIR/src-$V"
  (
    cd "$WORKDIR/src-$V"
    if ! sh make.sh --xc-host="$HOST" --prefix="$PREFIX" > "$WORKDIR/build-$V.log" 2>&1; then
      echo "ERROR: build of sbcl-$V failed. Tail of $WORKDIR/build-$V.log:"
      tail -25 "$WORKDIR/build-$V.log"
      exit 1
    fi
  )
  HOST="$WORKDIR/src-$V/run-sbcl.sh --no-userinit --no-sysinit --disable-debugger"
  LAST="$V"
  echo "[$(date '+%H:%M:%S')] hop sbcl-$V OK"
done

echo "Installing sbcl-$LAST -> $PREFIX"
( cd "$WORKDIR/src-$LAST" && sh install.sh > "$WORKDIR/install.log" 2>&1 )

echo "Cleaning build trees ($WORKDIR) ..."
rm -rf "$WORKDIR"

echo "Done. Installed:"
"$PREFIX/bin/sbcl" --version
echo
echo "Run it with:  SBCL_HOME=$PREFIX/lib/sbcl $PREFIX/bin/sbcl"
echo "(SBCL_HOME is normally auto-resolved from the baked --prefix; set it"
echo " explicitly in detached/supervisor contexts to be safe.)"
