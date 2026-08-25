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
# TAG CONVENTION: <sbcl-version>-<toolchain-revision>. The SBCL version must
# keep naming the SBCL actually inside (it matches production and is
# load-bearing); the suffix is bumped whenever anything else in the image
# changes. Bumping rather than rebuilding the old tag in place matters because
# the Docker daemon is shared with other sessions: they keep working against
# the tag they started with until they choose to rebuild.
#   2.6.5    -> initial
#   2.6.5-2  -> + nodejs, so the web UI test harness runs in-container too
#   2.6.5-3  -> + libzmq (the node's ZMQ notification publishers) and
#               python3-zmq, so those publishers can be tested against an
#               INDEPENDENT ZeroMQ implementation rather than only themselves
#   2.6.5-4  -> libsecp256k1 v0.5.1 -> v0.7.1 + the musig module, which is
#               what MuSig2 (BIP327) key aggregation needs and which no
#               release before 0.6.0 has at all
#
# Build (from the repo root):
#   docker build -f docker/Dockerfile -t bitcoin-lisp-sbcl:2.6.5-4 .

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

# libsecp256k1 v0.7.1 — the newest TAGGED release at or below what Bitcoin Core
# d3056bc vendors. Core's subtree calls itself 0.7.2 (CMakeLists.txt:10) but
# with _PKG_VERSION_IS_RELEASE=false (configure.ac:9): it is master after
# v0.7.1, and no v0.7.2 tag exists to clone. v0.8.0 does exist, and is
# deliberately NOT used — for consensus-critical code, at-or-behind the
# reference implementation beats ahead of it.
#
# Module set mirrors what the node's FFI uses: ECDSA (core), recovery,
# extrakeys + schnorrsig (taproot), ellswift (BIP324), ecdh, and now musig.
#
# ⚠️ This is the library the node validates CONSENSUS with, so the bump is not
# a free "add a module". What bounds the risk, checked before making it:
#   - musig exists only from 0.6.0 (CHANGELOG "New module `musig`"), so there
#     is no smaller step that gets it;
#   - 0.7.0 REMOVED three deprecated aliases — ec_privkey_negate,
#     ec_privkey_tweak_add, ec_privkey_tweak_mul. Our FFI binds 32 symbols and
#     none of them is one of those, so nothing breaks at load;
#   - every other 0.6.0/0.7.x change is build, visibility, or secret-clearing.
#     No cryptographic behaviour of the functions we call changed. 0.7.1 in
#     particular is ABI backward compatible with 0.7.0 (CHANGELOG).
# The empirical answer is the cold battery plus Core's own script/sighash/
# BIP341/key_io vectors run against this image.
#
# Core itself forces this module on (cmake/secp256k1.cmake:19).
RUN git clone --depth 1 --branch v0.7.1 \
      https://github.com/bitcoin-core/secp256k1 /tmp/secp256k1 \
 && cd /tmp/secp256k1 \
 && ./autogen.sh \
 && ./configure --enable-module-recovery --enable-module-extrakeys \
      --enable-module-schnorrsig --enable-module-ellswift \
      --enable-module-ecdh --enable-module-musig \
      --disable-benchmark --disable-tests \
 && make -j"$(nproc)" \
 && make install DESTDIR=/tmp/secp-install

FROM debian:trixie-slim

# Runtime foreign libraries the node's cffi layer loads: libcrypto (hash.lisp),
# libleveldb (leveldb.lisp; -dev for the plain .so name the FFI probes),
# libzmq (the ZMQ notification publishers; -dev for the same reason, and the
# node loads it LAZILY so a host without it still runs fine with ZMQ off),
# libsecp256k1 copied from the build stage. curl/git only for quicklisp below.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3t64 libleveldb-dev libzmq3-dev zlib1g ca-certificates curl \
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

# nodejs is the web UI's TEST HARNESS ONLY (`scripts/dev.sh ui-test` runs
# `node --test tests/ui/`). Unlike SBCL and libsecp256k1 its exact version is
# NOT load-bearing: nothing the node ships runs on it, the harness has zero npm
# dependencies, and it needs only `node --test` plus ESM (node >= 18; trixie
# ships 20.x). It is here so the UI suite has the same container contract as
# every other suite, instead of being the one that had to run on the host.
#
# LAST layer deliberately. Everything above it is expensive — the quicklisp
# dist fetch and a Coalton compile under a 4 GB heap — and Docker invalidates
# every layer after a changed one. Putting a frontend-only dependency up in
# the first apt line would make every future bump of it re-run that.
RUN apt-get update && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# python3-zmq is a TEST DEPENDENCY, for the same reason and in the same place as
# nodejs. It exists so the ZMQ publishers can be verified against an independent
# ZeroMQ implementation: a Lisp publisher checked only by a Lisp subscriber would
# prove that our code agrees with itself, which is exactly the failure mode a
# wire protocol has. Nothing the node ships uses it.
RUN apt-get update && apt-get install -y --no-install-recommends python3-zmq \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
CMD ["sbcl"]
