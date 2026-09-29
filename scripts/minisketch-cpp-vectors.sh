#!/usr/bin/env bash
# Regenerate tests/data/minisketch_cpp_vectors.json from Bitcoin Core's
# minisketch C++ LIBRARY (refs/bitcoin/src/minisketch/, pin d3056bc149), and
# tests/data/minisketch_core_vectors.json from Core's pyminisketch.py, then
# compare every section the two share.
#
# A REVIEWER tool. The cold battery never runs it: both JSON files are checked
# in, and tests/networking/minisketch-tests.lisp holds the Lisp port to them
# (and them to each other). Run it after touching either generator, or to
# re-derive the vectors from scratch:
#
#   scripts/minisketch-cpp-vectors.sh [--keep-image] [--selftest N]
#
# What it does, all inside containers, nothing on the host:
#  1. builds docker/minisketch-cpp.Dockerfile -- the pinned project image plus
#     g++ and make -- under a tag unique to this checkout,
#     bitcoin-lisp-sbcl:2.6.5-4-sketch-<checkout>, never the pinned tag;
#  2. compiles the library the way Core does (cmake/minisketch.cmake:
#     DISABLE_DEFAULT_FIELDS, ENABLE_FIELD_32, the generic fields) into
#     build/minisketch-cpp/, links tests/data/minisketch_cpp_vectors.cpp
#     against it and writes the C++ vectors;
#  3. regenerates the Python vectors with tests/data/minisketch_core_vectors.py;
#  4. compares the shared sections and exits 1 on any disagreement;
#  5. with --selftest N, also builds the library's own test suite
#     (src/minisketch/src/test.cpp, all fields, as upstream builds it) and runs
#     it at complexity N (1 takes a few minutes);
#  6. removes the image unless --keep-image.
# The run container has no network, publishes no port, mounts only this
# checkout, runs as the invoking user, and carries --label agent=<slug>.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BASE=bitcoin-lisp-sbcl:2.6.5-4
PIN=d3056bc149

KEEP=0; SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-image) KEEP=1 ;;
    --selftest) SELFTEST="${2:?--selftest needs a complexity}"; shift ;;
    *) echo "usage: $0 [--keep-image] [--selftest N]" >&2; exit 2 ;;
  esac
  shift
done

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | awk '{print $1}'
  else shasum -a 256 | awk '{print $1}'; fi
}
CHECKOUT_SHORT="$(printf '%s' "$REPO" | sha256_stdin)"; CHECKOUT_SHORT="${CHECKOUT_SHORT:0:12}"
SLUG="bitcoin-lisp-sketch-$CHECKOUT_SHORT"
TAG="$BASE-sketch-$CHECKOUT_SHORT"

head="$(git -C "$REPO/refs/bitcoin" rev-parse HEAD 2>/dev/null || true)"
case "$head" in
  "$PIN"*) ;;
  *) echo "ERROR: refs/bitcoin must be checked out at $PIN (it is at '${head:-nothing}')" >&2; exit 1 ;;
esac

docker image inspect "$BASE" >/dev/null 2>&1 \
  || { echo "ERROR: the project image $BASE is missing (docker/Dockerfile builds it)" >&2; exit 1; }

docker build --quiet --label "agent=$SLUG" --build-arg "BASE=$BASE" -t "$TAG" - \
  < "$REPO/docker/minisketch-cpp.Dockerfile" >/dev/null
[ "$KEEP" = 1 ] || trap 'docker rmi "$TAG" >/dev/null' EXIT

docker run --rm --network none --label "agent=$SLUG" --user "$(id -u):$(id -g)" \
  -e HOME=/tmp -e SELFTEST="$SELFTEST" -v "$REPO:/workspace" -w /workspace "$TAG" bash -c '
set -euo pipefail
MS=refs/bitcoin/src/minisketch
OUT=build/minisketch-cpp
mkdir -p "$OUT"
CXX="g++ -std=c++20 -O2 -Wall -Wno-unused-function -I$MS/include"

# The library as Core links it, less generic_4bytes.cpp: the generator
# includes that file itself, for its Field32.
objs=()
for src in $MS/src/minisketch.cpp $MS/src/fields/generic_{1byte,2bytes,3bytes,5bytes,6bytes,7bytes,8bytes}.cpp; do
  obj="$OUT/$(basename "$src" .cpp).o"
  $CXX -DDISABLE_DEFAULT_FIELDS -DENABLE_FIELD_32 -c "$src" -o "$obj"
  objs+=("$obj")
done
$CXX -I$MS/src tests/data/minisketch_cpp_vectors.cpp "${objs[@]}" -o "$OUT/vectors"
"$OUT/vectors" tests/data/minisketch_cpp_vectors.json
python3 tests/data/minisketch_core_vectors.py

python3 - <<"PY"
import json, sys
cpp = json.load(open("tests/data/minisketch_cpp_vectors.json"))
py = json.load(open("tests/data/minisketch_core_vectors.json"))
bad = 0
for section in sorted(set(cpp) & set(py) - {"source"}):
    same = cpp[section] == py[section]
    bad += not same
    print("%-16s %4d entries  %s" % (section, len(cpp[section]),
          "C++ == pyminisketch" if same else "DIFFERENT"))
    if not same:
        for i, (c, p) in enumerate(zip(cpp[section], py[section])):
            if c != p:
                print("   entry %d:\n     C++ %s\n     py  %s" % (i, c, p))
print("only in the C++ vectors:", sorted(set(cpp) - set(py)))
sys.exit(1 if bad else 0)
PY

if [ "$SELFTEST" != 0 ]; then
  # Upstream Makefile.am builds its test binary with every field enabled.
  $CXX -I$MS/src $MS/src/test.cpp $MS/src/minisketch.cpp $MS/src/fields/generic_*.cpp -o "$OUT/test-minisketch"
  "$OUT/test-minisketch" "$SELFTEST"
fi
'
