# G7-23 — ZMQ notifications

**Status (2026-08-22): DONE** — libzmq was added to the toolchain image (2.6.5-3) and the publishers shipped in PRs 368-370; the text below records the decision as it stood. This records
what the work is, the two ways to do it, and what each costs, because both
require a change outside the source tree that is the maintainer's call.

## What Core has

Five publishers and one RPC:

| topic | payload |
|---|---|
| `hashblock` | 32-byte block hash |
| `hashtx` | 32-byte txid |
| `rawblock` | serialized block |
| `rawtx` | serialized transaction |
| `sequence` | hash + a one-byte event (A/D/C/R) + mempool sequence number |

Each publisher is a ZeroMQ **PUB** socket bound to a `-zmqpub<topic>=<address>`
address, with an optional `-zmqpub<topic>hwm`. Every message is multipart:
topic, body, then a little-endian uint32 counter per topic.
`getzmqnotifications` reports the active publishers.

The node-side plumbing is the easy half and maps onto hooks this tree already
has — `connect-block`, the mempool add/remove paths, and the reorg hooks all
already fire for the wallet and the indexes.

## Why it is blocked

The hard half is the wire. ZeroMQ is not a framing convention on a socket; it
is the ZMTP 3.1 protocol — a greeting exchange, a NULL-mechanism handshake, a
READY command, subscription frames from each subscriber, and multipart message
framing with per-frame MORE flags.

There are two ways to get it, and both need a decision:

### Option A — link libzmq (what Core does)

CFFI to `libzmq`, as this tree already does for `libsecp256k1`.

Cost:
- **The pinned image must be bumped.** `libzmq` is absent from
  `bitcoin-lisp-sbcl:2.6.5-2`. The Dockerfile documents the convention for
  exactly this — bump the suffix rather than rebuild a tag in place, because
  the Docker daemon is shared and other sessions keep working against the tag
  they started with. So: add `libzmq3-dev` (build) / `libzmq5` (runtime),
  build `2.6.5-3`, and update the tag in `scripts/docker-sbcl.sh`,
  `scripts/dev.sh` and `CLAUDE.md`.
- **The production server must gain the runtime library.** `libzmq` is not
  installed on test-bitcoin-server; `libzmq3-dev 4.3.4-2` is available from
  apt. Installing a package on the production host is a separate authorization.

### Option B — implement ZMTP 3.1 in Lisp

No native dependency, consistent with the rest of the networking layer, which
is pure Lisp down to the socket.

Cost: a wire protocol implementation of a few hundred lines — and, decisively,
**no way to verify it here**. There is no ZeroMQ client in the container to
test against, so a self-consistent publisher/subscriber pair would prove only
that our implementation agrees with itself. A handshake detail that a real
`pyzmq` or `libzmq` subscriber rejects would look complete and be useless.
Shipping an unverifiable wire protocol is the same defect as shipping code
nothing calls, which this tree has produced five times this month.

## Recommendation

**Option A.** It is what Core does, the image-bump procedure is already
documented in the Dockerfile for precisely this situation, and it makes the
result verifiable — with libzmq present, the publishers can be tested against a
real subscriber in the same container.

The two prerequisites are yours to approve:

1. bump the project image to `2.6.5-3` with `libzmq3-dev`/`libzmq5`;
2. install `libzmq5` on test-bitcoin-server.

With those done the remaining work is ordinary: a publisher struct per topic,
the `-zmqpub*` config options, the five hook call sites, `getzmqnotifications`,
and tests driving a real subscriber.
