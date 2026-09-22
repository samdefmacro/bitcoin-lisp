#!/usr/bin/env bash
# The differential lane against Bitcoin Core's own binaries (GA11 "Harness
# lanes", docs/gap-analysis-11.md): runs the fiveam suite
# :core-binary-differential-tests with a previous release's bitcoin-tx and
# bitcoin-util mounted at /releases, and REQUIRES them -- in the ordinary
# battery the same suite skips when the binaries are absent, which is right
# there and a silent pass here.
#
# Usage:
#   scripts/get-previous-releases.sh v28.2     # once: fetch + verify on the host
#   scripts/interop-test.sh                    # or: scripts/dev.sh interop,
#                                              #     cl-workbench validation run interop
#   BL_INTEROP_RELEASE=v25.0 scripts/interop-test.sh
#
# A cold container with its own FASL volume (never the cold battery's, which a
# concurrent battery would share) and a 2 GiB heap, so it is not mistaken for a
# battery by anyone polling for `dynamic-space-size 4096'. Exit status is the
# suite's; the adapter's counted gate reads its `Did N checks'.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE="${BL_INTEROP_RELEASE:-v28.2}"

VOL="$("$REPO/scripts/previous-releases-volume.sh")"
if [ -z "$VOL" ]; then
  echo "ERROR: no previous releases -- run scripts/get-previous-releases.sh $RELEASE first." >&2
  exit 1
fi

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  else shasum -a 256 | awk '{print $1}'; fi
}
CHECKOUT_SHORT="$(printf '%s' "$REPO" | sha256_stdin)"; CHECKOUT_SHORT="${CHECKOUT_SHORT:0:12}"

export BITCOIN_LISP_FASL_VOLUME="bitcoin-lisp-fasl-interop-$CHECKOUT_SHORT"
export BITCOIN_LISP_DOCKER_EXTRA="-v $VOL:/releases:ro -e BL_CORE_BIN_DIR=/releases/$RELEASE/bin/ -e BL_REQUIRE_CORE_BINARIES=1 --label agent=bitcoin-lisp-interop-$CHECKOUT_SHORT"

exec "$REPO/scripts/docker-sbcl.sh" --dynamic-space-size 2048 --non-interactive \
  --eval '(asdf:load-system "bitcoin-lisp/tests")' \
  --eval "(let ((r (fiveam:run :core-binary-differential-tests)))
            (fiveam:explain! r)
            (when (null r)
              (format t \"~&suite :core-binary-differential-tests selected no tests~%\")
              (sb-ext:exit :code 1))
            (unless (fiveam:results-status r) (sb-ext:exit :code 1)))"
