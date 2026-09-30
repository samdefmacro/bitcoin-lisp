#!/usr/bin/env bash
#
# server-secp-upgrade.sh -- put libsecp256k1 v0.7.1 (with the musig module)
# into its OWN prefix on the live-node server, verify it, and print how to
# switch the nodes onto it. Run it ON THE SERVER, from the deploy checkout:
#
#   bash /data/bitcoin-lisp/code/scripts/server-secp-upgrade.sh
#
# It never touches a running node, never edits scripts/run-node.sh, and never
# overwrites a library a process may have mapped: the result is a new prefix,
# /data/bitcoin-lisp/secp256k1-0.7.1, next to the v0.5.1 one
# (/data/bitcoin-lisp/secp256k1-local) the nodes load today. Switching is the
# operator's step, printed at the end: run-node.sh's BL_SECP_LIB, then a clean
# stop and restart per network, then the node's own start-up line
# ("Using libsecp256k1 0.7.1 (...) with modules ... musig") as the acceptance
# check.
#
# Idempotent. When the prefix already holds a library that exports every
# module's probe symbol and says it is 0.7.1, it is REUSED and nothing is
# built. When the prefix is absent it is built from the tagged source and
# installed through a staging directory, so a failed build leaves no prefix
# behind. When the prefix exists but does NOT verify, the script refuses: it
# will not overwrite a directory a node may be running from -- move it aside
# by hand once nothing maps it.
#
# The module set is the container image's (docker/Dockerfile, which builds
# the same tag with autotools: --enable-module-recovery -extrakeys -schnorrsig
# -ellswift -ecdh -musig) and the node's (bl.crypto's *SECP256K1-MODULES*);
# tests/crypto/secp256k1-library-tests.lisp keeps the three lists equal.
# Core builds the same modules minus ECDH (cmake/secp256k1.cmake:17-19) and
# links them statically; nothing in the node binds secp256k1_ecdh, it is kept
# only so the server's library is the image's.
#
# Why v0.7.1: the newest TAGGED release at or below what Core d3056bc vendors
# (docker/Dockerfile's comment has the full argument), and the first line
# with musig is 0.6.0 -- v0.5.1 has no musig module at all, so MuSig2 signing
# and musig() descriptors answer "MuSig2 is not available" on it.
#
# Environment (all optional):
#   BL_ROOT              /data/bitcoin-lisp
#   BL_SERVER_HOSTNAME   the hostname this may run on (default below); the
#                        script refuses on any other host
#   BL_SECP_PREFIX       $BL_ROOT/secp256k1-0.7.1
#   BL_SECP_SRC          $BL_ROOT/secp256k1-src-0.7.1 (cloned when absent)
#   BL_SECP_JOBS         build parallelism (default: nproc)
#   BL_SECP_SKIP_TESTS   1 to skip upstream's tests + exhaustive tests
#
set -euo pipefail

SECP_VERSION=0.7.1
SECP_TAG="v$SECP_VERSION"
SECP_SOVERSION=6.0.1          # libtool/CMake version of the 0.7.1 release
SECP_REPO=https://github.com/bitcoin-core/secp256k1

BL_ROOT="${BL_ROOT:-/data/bitcoin-lisp}"
BL_SERVER_HOSTNAME="${BL_SERVER_HOSTNAME:-test-bitcoin-server}"
PREFIX="${BL_SECP_PREFIX:-$BL_ROOT/secp256k1-$SECP_VERSION}"
SRC="${BL_SECP_SRC:-$BL_ROOT/secp256k1-src-$SECP_VERSION}"
JOBS="${BL_SECP_JOBS:-$(nproc 2>/dev/null || echo 2)}"
OLD_LIB_DIR="$BL_ROOT/secp256k1-local/lib"   # v0.5.1, the fallback

# One probe symbol per module (bl.crypto *SECP256K1-MODULES*), plus the
# library's own entry point.
PROBE_SYMBOLS=(
  secp256k1_context_create
  secp256k1_ecdsa_recover        # recovery
  secp256k1_keypair_create       # extrakeys
  secp256k1_schnorrsig_sign32    # schnorrsig
  secp256k1_ellswift_create      # ellswift
  secp256k1_ecdh                 # ecdh
  secp256k1_musig_nonce_gen      # musig
)

say() { printf '[secp-upgrade] %s\n' "$*"; }
die() { printf '[secp-upgrade] REFUSED: %s\n' "$*" >&2; exit 1; }

# --- 1. Where are we? ---------------------------------------------------------
# Never on the development Mac (the project's rule: no toolchain on the host),
# never on any other machine.
[ "$(uname -s)" = Linux ] || die "this runs on the Linux node server only (uname: $(uname -s))"
HOST="$(hostname)"
[ "$HOST" = "$BL_SERVER_HOSTNAME" ] ||
  die "hostname is '$HOST', expected '$BL_SERVER_HOSTNAME' (set BL_SERVER_HOSTNAME only after checking this IS the node server)"
[ -d "$BL_ROOT" ] || die "$BL_ROOT is absent: not the node server"
# The symbol check runs in command substitutions, where a die would only end
# the subshell: the tools are checked here, once, in the script's own shell.
command -v nm >/dev/null 2>&1 || command -v objdump >/dev/null 2>&1 ||
  die "neither nm nor objdump is installed (apt-get install binutils)"

# --- 2. What makes a prefix good ------------------------------------------------
defined_symbols() {   # the dynamic symbols LIB defines, one per line
  local lib="$1"
  if command -v nm >/dev/null 2>&1; then
    nm -D --defined-only "$lib" | awk '{print $NF}'
  else
    objdump -T "$lib" | grep -v '\*UND\*' | awk '{print $NF}'
  fi
}

soname_of() {
  { objdump -p "$1" 2>/dev/null || readelf -d "$1" 2>/dev/null; } |
    grep -o 'libsecp256k1\.so\.[0-9]*' | head -1
}

pc_version() {        # Version: from the pkgconfig file an install writes
  local pc="$1/lib/pkgconfig/libsecp256k1.pc"
  [ -f "$pc" ] && awk -F': *' '$1 == "Version" {print $2}' "$pc"
}

# verify_prefix DIR: 0 when DIR/lib/libsecp256k1.so is v$SECP_VERSION and
# exports every probe symbol; prints what it found either way.
verify_prefix() {
  local dir="$1" lib="$1/lib/libsecp256k1.so" real version syms missing=()
  [ -e "$lib" ] || { say "no $lib"; return 1; }
  real="$(readlink -f "$lib")"
  version="$(pc_version "$dir" || true)"
  syms="$(defined_symbols "$real")"
  for s in "${PROBE_SYMBOLS[@]}"; do
    grep -qx "$s" <<<"$syms" || missing+=("$s")
  done
  say "library: $real (soname $(soname_of "$real" || true), pkgconfig version ${version:-absent})"
  if [ "${#missing[@]}" -gt 0 ]; then
    say "MISSING symbols: ${missing[*]}"
    return 1
  fi
  say "exports all ${#PROBE_SYMBOLS[@]} probe symbols: ${PROBE_SYMBOLS[*]}"
  # An install without its pkgconfig file still names its release in the
  # file the soname points at (0.7.1 is libsecp256k1.so.6.0.1).
  if [ -z "$version" ] && [ "$(basename "$real")" = "libsecp256k1.so.$SECP_SOVERSION" ]; then
    version="$SECP_VERSION"
  fi
  [ "$version" = "$SECP_VERSION" ] || { say "version is '${version:-absent}', want $SECP_VERSION"; return 1; }
  return 0
}

# --- 3. Reuse, or build ---------------------------------------------------------
if [ -e "$PREFIX" ]; then
  say "prefix $PREFIX exists; verifying it instead of building"
  verify_prefix "$PREFIX" ||
    die "$PREFIX exists but does not verify. It is not overwritten (a node may map it): move it aside once no process maps it, then re-run"
  say "REUSING $PREFIX (nothing built)"
else
  command -v cmake >/dev/null 2>&1 || die "cmake is not installed (apt-get install cmake)"
  command -v git >/dev/null 2>&1 || die "git is not installed"

  if [ ! -e "$SRC" ]; then
    say "cloning $SECP_REPO at $SECP_TAG into $SRC"
    git clone --quiet --depth 1 --branch "$SECP_TAG" "$SECP_REPO" "$SRC"
  fi
  # The source must BE the tag: an exact tag match when it is a git clone,
  # else the version its CMakeLists.txt declares.
  if [ -d "$SRC/.git" ]; then
    at="$(git -C "$SRC" describe --tags --exact-match 2>/dev/null || true)"
    [ "$at" = "$SECP_TAG" ] || die "$SRC is at '${at:-no tag}', not $SECP_TAG"
    [ -z "$(git -C "$SRC" status --porcelain --untracked-files=no)" ] ||
      die "$SRC has local modifications"
  else
    # project(libsecp256k1 ... VERSION x.y.z ...) spans lines there.
    grep -Eq "^[[:space:]]*VERSION $SECP_VERSION\$" "$SRC/CMakeLists.txt" ||
      die "$SRC/CMakeLists.txt does not declare VERSION $SECP_VERSION"
  fi

  BUILD="$(mktemp -d "$BL_ROOT/secp256k1-build-$SECP_VERSION.XXXXXX")"
  STAGE="$(mktemp -d "$BL_ROOT/secp256k1-stage-$SECP_VERSION.XXXXXX")"
  trap 'rm -rf "$BUILD" "$STAGE"' EXIT
  TESTS=ON; [ "${BL_SECP_SKIP_TESTS:-0}" = 1 ] && TESTS=OFF

  # RelWithDebInfo is what Core builds its copy with ("the most tested
  # configuration", cmake/secp256k1.cmake:39). Module flags: see the header.
  say "configuring $SRC (tests $TESTS)"
  cmake -S "$SRC" -B "$BUILD" \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DBUILD_SHARED_LIBS=ON \
    -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
    -DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON \
    -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON \
    -DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON \
    -DSECP256K1_ENABLE_MODULE_ECDH=ON \
    -DSECP256K1_ENABLE_MODULE_MUSIG=ON \
    -DSECP256K1_BUILD_BENCHMARK=OFF \
    -DSECP256K1_BUILD_EXAMPLES=OFF \
    -DSECP256K1_BUILD_TESTS="$TESTS" \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS="$TESTS"
  say "building with $JOBS jobs"
  cmake --build "$BUILD" -j "$JOBS"
  if [ "$TESTS" = ON ]; then
    say "running upstream's tests and exhaustive tests (a few minutes)"
    ctest --test-dir "$BUILD" -j "$JOBS" --output-on-failure
  fi
  DESTDIR="$STAGE" cmake --install "$BUILD"
  verify_prefix "$STAGE$PREFIX" || die "the freshly built library does not verify; nothing installed"
  # The staged tree lands under the prefix's own name in one rename.
  mkdir -p "$(dirname "$PREFIX")"
  mv "$STAGE$PREFIX" "$PREFIX"
  say "INSTALLED $PREFIX"
  verify_prefix "$PREFIX" || die "$PREFIX does not verify after the move"
fi

# --- 4. What the nodes load now (read-only) ---------------------------------------
say "libsecp256k1 each running sbcl has mapped:"
found=0
for proc in /proc/[0-9]*; do
  [ "$(cat "$proc/comm" 2>/dev/null)" = sbcl ] || continue
  pid="${proc#/proc/}"
  lib="$(grep -o '/[^ ]*libsecp256k1[^ ]*' "$proc/maps" 2>/dev/null | sort -u | tr '\n' ' ' || true)"
  say "  pid $pid: ${lib:-none mapped yet}  ($(tr '\0' ' ' < "/proc/$pid/cmdline" | grep -o 'network\* :[a-z0-9]*' || echo '?'))"
  found=1
done
[ "$found" = 1 ] || say "  (no sbcl running)"

# --- 5. The switch: printed, never performed ----------------------------------------
NEW_LINE="BL_SECP_LIB=\"\${BL_SECP_LIB:-\$BL_ROOT/secp256k1-$SECP_VERSION/lib}\""
RUN_NODE="$BL_ROOT/code/scripts/run-node.sh"
echo
say "NEXT STEPS (the operator's; this script changes nothing else):"
if [ -f "$RUN_NODE" ] && grep -qF "$NEW_LINE" "$RUN_NODE"; then
  say "1. $RUN_NODE already defaults to the new prefix:"
  say "     $NEW_LINE"
  say "   so a restart of each node picks it up."
else
  say "1. In $RUN_NODE the BL_SECP_LIB line must read"
  say "     $NEW_LINE"
  say "   (deploying a main that has this script has it). Do not edit the file a"
  say "   running supervisor is executing in place; deploy it (git reset writes a new file)."
fi
say "2. Per network, testnet4 first: stop the supervisor, then the sbcl, by PID"
say "   (never pkill -f), wait for 'Node stopped', relaunch run-node.sh."
say "3. Acceptance: the node's log shows"
say "     Using libsecp256k1 $SECP_VERSION ($(readlink -f "$PREFIX/lib/libsecp256k1.so")) with modules recovery extrakeys schnorrsig ellswift ecdh musig"
say "   and /proc/<sbcl pid>/maps names $PREFIX/lib."
say "Fallback: BL_SECP_LIB=$OLD_LIB_DIR (v0.5.1, no musig) in the supervisor's environment."
