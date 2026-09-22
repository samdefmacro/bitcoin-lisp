#!/usr/bin/env bash
# Run a previous release's bitcoind under the CURRENT functional test
# framework (scripts/conformance.sh BL_CONFORMANCE_REFERENCE=<tag>), inside the
# project container only.
#
# The framework passes every node options that postdate the release when it
# does not know the node's version -- a $BITCOIND override has none -- and an
# older bitcoind refuses to start on an unknown command-line option. Those few
# are dropped here; everything else reaches the release unchanged.
set -euo pipefail
: "${BL_REFERENCE_BITCOIND:?set by scripts/conformance.sh}"
args=()
for a in "$@"; do
  case "$a" in
    -nologratelimit) ;;   # -logratelimit arrived after 28.x
    *) args+=("$a") ;;
  esac
done
exec "$BL_REFERENCE_BITCOIND" ${args[@]+"${args[@]}"}
