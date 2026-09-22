#!/usr/bin/env bash
# Fetch the Bitcoin Core release archives that Core's functional tests call
# "previous releases", for the project container's architecture, and verify
# each one against the SHA256 table in Core's own
# test/get_previous_releases.py (at the project pin).
#
# This is the host-side, dependency-free half of
# `test/get_previous_releases.py --host aarch64-linux-gnu <tags>`: curl,
# shasum/sha256sum and nothing else, so no Python and no project code runs on
# the host. The archives land in refs/bitcoin/releases-archives/ (refs/ is
# git-ignored) and are NEVER extracted on the host:
#
#   ⚠️ host security software deletes some extracted release binaries on
#   sight (observed 2026-09-23: bin/bitcoind of v0.14.3 and v0.20.1 vanished
#   within ten seconds of extraction, in the checkout and in a temp dir alike,
#   while the verified .tar.gz stayed). So scripts/conformance.sh extracts
#   the archives INSIDE the project container, into a per-checkout Docker
#   volume mounted at /releases, laid out the way the framework's
#   add_nodes(versions=...) resolves them (test_framework.py:423-440):
#   /releases/v28.2/bin/bitcoind, /releases/v0.14.3/bin/bitcoind, ...
#
# Usage:
#   scripts/get-previous-releases.sh                # every tag the compat tests use
#   scripts/get-previous-releases.sh v28.2 v25.0    # just these
#   BL_RELEASES_HOST=x86_64-linux-gnu scripts/get-previous-releases.sh
#
# An archive already present and matching its hash is skipped. Exit status is
# non-zero if any archive is missing from Core's table or fails its checksum;
# a failing download is deleted, never kept.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
HOST="${BL_RELEASES_HOST:-aarch64-linux-gnu}"   # bitcoin-lisp-sbcl:2.6.5-4 is linux/arm64
DEST="$ROOT/refs/bitcoin/releases-archives"
TABLE="$ROOT/refs/bitcoin/test/get_previous_releases.py"

# The union of the versions=[...] lists of the Core tests this project runs
# with previous releases (docs/manual.lisp, the interop section):
#   v0.14.3  feature_unsupported_utxo_db      v0.20.1  mempool_compatibility,
#   v0.21.0 .. v25.0  wallet_backwards_compatibility,
#   v28.2    feature_coinstatsindex_compatibility, wallet_migration, and the
#            bitcoin-tx / bitcoin-util differential lane (scripts/dev.sh interop).
DEFAULT_TAGS="v0.14.3 v0.20.1 v0.21.0 v22.0 v23.0 v24.0.1 v25.0 v28.2"
TAGS="${*:-$DEFAULT_TAGS}"

[ -f "$TABLE" ] || { echo "No $TABLE -- clone refs/bitcoin at the project pin first." >&2; exit 1; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -p "$DEST"
rc=0
for tag in $TAGS; do
  ver="${tag#v}"
  archive="bitcoin-$ver-$HOST.tar.gz"
  # The expected hash is the key of the table entry naming this archive.
  want="$(grep -F "\"archive\": \"$archive\"" "$TABLE" | sed -E 's/^ *"([0-9a-f]{64})".*/\1/' || true)"
  if [ -z "$want" ]; then
    echo "ERROR: $archive is not in Core's SHA256 table ($TABLE)" >&2; rc=1; continue
  fi
  if [ -f "$DEST/$archive" ] && [ "$(sha256_file "$DEST/$archive")" = "$want" ]; then
    echo "cached $archive"; continue
  fi
  case "$ver" in *rc[0-9]*) dir="bitcoin-core-${ver%rc*}/test.rc${ver##*rc}";; *) dir="bitcoin-core-$ver";; esac
  tmp="$DEST/.$archive.$$"
  echo "fetching $archive"
  curl -fsSL --retry 2 -o "$tmp" "https://bitcoincore.org/bin/$dir/$archive"
  got="$(sha256_file "$tmp")"
  if [ "$got" != "$want" ]; then
    echo "ERROR: $archive checksum $got, Core's table says $want" >&2
    rm -f "$tmp"; rc=1; continue
  fi
  mv -f "$tmp" "$DEST/$archive"
  echo "ok $archive ($want)"
done
exit $rc
