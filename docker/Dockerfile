# Containerized toolchain for bitcoin-lisp: SBCL 2.6.5 (the same version the
# production nodes run — see BUILD.md for why 2.6.5), libsecp256k1 v0.5.1
# (matching the servers' locally-built copy; distro packages are too old for
# BIP324's ellswift), LevelDB, OpenSSL, and a Quicklisp with all system
# dependencies pre-loaded.
#
# The image is TOOLCHAIN ONLY — the repository is bind-mounted at /workspace
# at run time (see scripts/docker-sbcl.sh / scripts/docker-test.sh), so image
# rebuilds are needed only when the toolchain changes, never for code changes.
#
# Build (from the repo root):
#   docker build -f docker/Dockerfile -t bitcoin-lisp-sbcl:2.6.5 .

FROM debian:trixie-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    sbcl git make gcc libc6-dev zlib1g-dev ca-certificates \
    autoconf automake libtool pkg-config \
 && rm -rf /var/lib/apt/lists/*

# SBCL 2.6.5 via the repo's bootstrap script. Trixie's apt SBCL (2.5.4) is
# recent enough to host the final version directly — a single hop, unlike the
# Ubuntu 22.04 chain documented in BUILD.md.
COPY scripts/setup-sbcl.sh /tmp/setup-sbcl.sh
RUN PREFIX=/opt/sbcl HOPS="2.6.5" WORKDIR=/tmp/sbcl-build \
    bash /tmp/setup-sbcl.sh

# libsecp256k1 v0.5.1 — the exact tag the production nodes run. Module set
# mirrors what the node's FFI uses: ECDSA (core), recovery, extrakeys +
# schnorrsig (taproot), ellswift (BIP324), ecdh.
RUN git clone --depth 1 --branch v0.5.1 \
      https://github.com/bitcoin-core/secp256k1 /tmp/secp256k1 \
 && cd /tmp/secp256k1 \
 && ./autogen.sh \
 && ./configure --enable-module-recovery --enable-module-extrakeys \
      --enable-module-schnorrsig --enable-module-ellswift \
      --enable-module-ecdh --disable-benchmark --disable-tests \
 && make -j"$(nproc)" \
 && make install DESTDIR=/tmp/secp-install

FROM debian:trixie-slim

# Runtime foreign libraries the node's cffi layer loads: libcrypto (hash.lisp),
# libleveldb (leveldb.lisp; -dev for the plain .so name the FFI probes),
# libsecp256k1 copied from the build stage. curl/git only for quicklisp below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 libleveldb-dev zlib1g ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /opt/sbcl /opt/sbcl
COPY --from=build /tmp/secp-install/usr/local/ /usr/local/
RUN ldconfig

ENV SBCL_HOME=/opt/sbcl/lib/sbcl \
    PATH=/opt/sbcl/bin:$PATH \
    CL_SOURCE_REGISTRY=/workspace// \
    XDG_CACHE_HOME=/fasl-cache

# Quicklisp at /opt/quicklisp with every dependency of bitcoin-lisp and its
# test system pre-loaded (bitcoin-lisp.asd :depends-on + fiveam + coalton's
# own dependency tree). The vendored refs/coalton (mounted with the repo)
# still wins at run time via the .asd's registry push; quickloading coalton
# here just bakes its transitive deps (fset etc.) into the image.
RUN curl -fsSL https://beta.quicklisp.org/quicklisp.lisp -o /tmp/quicklisp.lisp \
 && sbcl --non-interactive --load /tmp/quicklisp.lisp \
      --eval '(quicklisp-quickstart:install :path "/opt/quicklisp/")' \
 && printf '%s\n' '(load "/opt/quicklisp/setup.lisp")' > /root/.sbclrc \
 # 4 GB heap: compiling Coalton exhausts SBCL's default dynamic space
 && sbcl --dynamic-space-size 4096 --non-interactive \
      --eval '(ql:quickload (list "ironclad" "nibbles" "cffi" "usocket" "flexi-streams" "alexandria" "bordeaux-threads" "hunchentoot" "yason" "cl-base64" "fiveam" "coalton"))' \
 && rm /tmp/quicklisp.lisp

WORKDIR /workspace
CMD ["sbcl"]
