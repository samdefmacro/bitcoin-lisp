# A REVIEWER-ONLY derivative of the pinned project image: the same toolchain
# plus a C++ compiler, so Bitcoin Core's vendored minisketch C++ library
# (refs/bitcoin/src/minisketch/, pin d3056bc149) can be compiled and made to
# produce the test vectors our pure-Lisp port is held to
# (tests/data/minisketch_cpp_vectors.json).
#
# Nothing the node ships or the cold battery runs uses this image: the vectors
# are checked in, and the battery reads the JSON. It is built, used and removed
# by scripts/minisketch-cpp-vectors.sh under a session-unique tag
# (bitcoin-lisp-sbcl:2.6.5-4-sketch-<checkout>), never under the pinned tag.
#
# Build context: none (the script pipes this file on stdin); the sources come
# in through the repository bind mount at run time.
ARG BASE=bitcoin-lisp-sbcl:2.6.5-4
FROM ${BASE}

# g++ and make only: the runtime stage of docker/Dockerfile is slim and has
# no compiler at all. Nothing else in the image changes.
RUN apt-get update && apt-get install -y --no-install-recommends g++ make \
 && rm -rf /var/lib/apt/lists/*
