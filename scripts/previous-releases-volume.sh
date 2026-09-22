#!/usr/bin/env bash
# Print the name of this checkout's Docker volume holding Core's previous
# releases, extracting any archive not yet in it; print nothing (exit 0) when
# refs/bitcoin/releases-archives/ has no archive.
#
# The archives are fetched and SHA256-verified on the host by
# scripts/get-previous-releases.sh and are extracted only here, inside the
# project image, because host security software deletes some extracted
# bitcoind binaries on sight (see that script). The layout is what the
# functional framework's add_nodes(versions=...) resolves
# (test_framework.py:423-440): /releases/v28.2/bin/bitcoind, ... Each tag is
# unpacked into a hidden directory and renamed into place with a .complete
# marker, so an interrupted extraction is redone rather than half-used.
# bitcoin-qt and test_bitcoin are left out; nothing here runs them.
#
# Users: scripts/conformance.sh (mounted at /releases for the framework),
# scripts/interop-test.sh (the bitcoin-tx / bitcoin-util differential lane)
# and scripts/dev.sh start (mounted read-only into the warm image).
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE=bitcoin-lisp-sbcl:2.6.5-4
ARCHIVES="$REPO/refs/bitcoin/releases-archives"

ls "$ARCHIVES"/bitcoin-*.tar.gz >/dev/null 2>&1 || exit 0

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  else shasum -a 256 | awk '{print $1}'; fi
}
CHECKOUT_SHORT="$(printf '%s' "$REPO" | sha256_stdin)"; CHECKOUT_SHORT="${CHECKOUT_SHORT:0:12}"
VOL="bitcoin-lisp-releases-$CHECKOUT_SHORT"

docker volume inspect "$VOL" >/dev/null 2>&1 \
  || docker volume create --label "agent=bitcoin-lisp-conformance-$CHECKOUT_SHORT" \
       --label "io.common-lisp-workbench.checkout=$CHECKOUT_SHORT" "$VOL" >/dev/null
docker run --rm -v "$ARCHIVES:/archives:ro" -v "$VOL:/releases" \
  --label "agent=bitcoin-lisp-releases-$CHECKOUT_SHORT" "$IMAGE" bash -c '
    set -e
    for a in /archives/bitcoin-*.tar.gz; do
      ver=$(basename "$a" | sed -E "s/^bitcoin-([^-]+)-.*/\1/"); tag=v$ver
      [ -f "/releases/$tag/.complete" ] && continue
      rm -rf "/releases/$tag" "/releases/.$tag"; mkdir -p "/releases/.$tag"
      tar -zxf "$a" -C "/releases/.$tag" --strip-components=1 \
        --exclude="*/bin/bitcoin-qt" --exclude="*/bin/test_bitcoin" "bitcoin-$ver/bin"
      touch "/releases/.$tag/.complete"; mv "/releases/.$tag" "/releases/$tag"
      echo "previous release $tag extracted" >&2
    done' >&2
echo "$VOL"
