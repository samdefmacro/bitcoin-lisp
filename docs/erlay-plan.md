# Erlay / BIP330 Transaction Reconciliation — Implementation Plan

Date: 2026-07-10. Status (2026-09-29): **P0-P4 DONE, verified against every oracle that exists** — P0 live-loop wiring (PRs 242/243), P1 handshake, P2-P4 (PRs 387-390) behind default-off `-txreconciliation`. Round 9 (2026-09-29) checked the sketches against Core's vendored minisketch (vectors from its pyminisketch.py; the decoder is now a port of sketch_impl.h), the short IDs and round messages against BIP-330, and ran two of our nodes through whole rounds over a real connection. The boundary with Core at the pin is in §6.
Reference: Bitcoin Core `refs/bitcoin/` @ d3056bc (v30-dev). Researched via 2 agents
(Core Erlay/BIP330 + minisketch; our networking layer).

## 1. The decisive research finding

**At d3056bc, Core itself ships only the `sendtxrcncl` handshake.** Verified: `protocol.h:266`
defines no reconciliation message beyond `sendtxrcncl` (no reqtxrcncl/sketch/reqsketchext/
reconcildiff anywhere); `node/txreconciliation.{h,cpp}` (≈260 lines total) stores per-peer
`{we_initiate, k0, k1}` that **nothing ever reads** ("make private once used in the following
commits" — commits that never landed); `-txreconciliation` is DEBUG_ONLY, default false
(net_processing.cpp:2020: "While Erlay support is incomplete…"). minisketch is fully vendored
(`src/minisketch/`) but used only by tests.

Consequence for us (project principle: match Core): **Core parity = handshake only** — a small,
well-specified deliverable. The sketch-exchange protocol is *beyond Core*, still evolving
upstream, and implementing it now risks incompatibility with whatever Core finally ships.
Recommendation: build P0+P1 now; treat P2-P4 as a parked track until Core merges the rest.

## 2. Precondition — the live-loop wiring gap (VERIFIED BUG, fix regardless of Erlay)

The only production message loop, `dispatch-ibd-message` (src/networking/ibd.lisp:1309-1370),
forwards non-block/header messages to the generic `handle-message` passing **only**
`:fee-estimator`/`:recent-rejects` (ibd.lisp:1367-1370). But `handle-message`
(src/networking/protocol.lisp:103-229) gates `tx` ingestion on `mempool` (:143-147), tx-inv
getdata on `mempool` (handle-inv :131→:344), compact-block paths on `mempool`, mempool-tx
serving in `handle-getdata` on `mempool`, and addr/addrv2/getaddr on `address-book`/`peers`
(:161-175). Net effect in production: **loose-tx ingestion, tx-inv requesting, tx serving,
compact-block relay, addr-gossip ingestion/relay, and `relay-transaction` are all inert** —
they run only from unit tests and RPC. (PR 236/239 paths included.)

Related dead wiring, also verified: `maintain-peers` (src/node.lisp:1993) has **zero callers** —
so block-relay slots + feelers (PR 216) and outgoing pings (`check-peers-health`) never run
live; `peer-send-queue` (peer.lisp:31) is declared but unused.

**P0 below fixes this first.** Any relay feature (Erlay included) is meaningless until then.

## 3. Core handshake spec (the P1 deliverable)

- Wire: `sendtxrcncl` = `uint32 version(=1)` + `uint64 salt` — 12-byte payload (protocol.h:262-266).
- **Send** (inside VERSION handling, before VERACK; ordering wtxidrelay → sendaddrv2 →
  sendtxrcncl → verack, net_processing.cpp:3715-3744): require negotiated proto ≥ 70016, feature
  enabled, peer is tx-relaying (their VERSION fRelay=1, not our block-relay/feeler conn, not
  blocksonly). On send, pre-register local salt = random u64 (txreconciliation.cpp:82-94).
- **Receive** (pre-verack only; net_processing.cpp:3963-4014): after verack ⇒ disconnect; from a
  peer we'd never take txs from ⇒ disconnect; peer's own fRelay=0 ⇒ disconnect; then
  RegisterPeer: NOT_FOUND (we never offered) ⇒ ignore; ALREADY_REGISTERED (duplicate) ⇒
  disconnect; version = min(theirs, ours), <1 ⇒ disconnect (higher version is fine, downgrades).
- **At VERACK**: if wtxid-relay wasn't negotiated or registration incomplete ⇒ forget peer
  (net_processing.cpp:3879-3886). Forget on disconnect too.
- **Salt combination** (txreconciliation.cpp:18-30): tagged hash, tag `"Tx Relay Salting"`
  (BIP340-style: SHA256(tag)‖SHA256(tag) preloaded), message = two u64 LE salts in **ascending
  order**; k0 = digest bytes 0-7 LE, k1 = bytes 8-15 LE. Short id (spec, unmerged):
  `1 + (SipHash-2-4(k0,k1, wtxid) mod 0xFFFFFFFF)` — 0 excluded (minisketch can't encode 0).
- Role: `we_initiate = we dialed them` (outbound).

## 4. Our integration surface

- **Feature-negotiation slot**: outbound `%send-version-and-capabilities`
  (src/networking/peer.lisp:272-310) currently sends caps *before* reading the peer's VERSION;
  Core requires gating on their fRelay ⇒ send sendtxrcncl after `%receive-and-store-version`
  (peer.lisp:383) instead. Inbound `perform-inbound-handshake` (:387-407) already has their
  VERSION first. Receive in `%await-verack` (:328-343) — note payload is currently
  `declare ignore`d and must be parsed for this message. Post-verack `sendtxrcncl` must
  **disconnect** (unlike the sendaddrv2/wtxidrelay no-op stubs at protocol.lisp:189-195).
- **Peer struct** (peer.lisp:19-97): add `recon-local-salt`, `recon-k0/k1`, `recon-we-initiate`,
  `recon-registered` (defstruct change ⇒ FASL clear on deploy). `wtxid-relay` flag exists (:76).
- **Announcement hook** (for the future P2+): `relay-transaction` (protocol.lisp:1016-1050) is
  the single per-peer announcement chokepoint — "if recon-registered → add wtxid short-id to
  peer's recon set, else inv as today". **No batching/timers exist anywhere** (every tx is a
  synchronous single-entry inv); Erlay's timer would be new machinery (nearest cadence anchor:
  the 30s sync loop, node.lisp:950). The deferred Poisson-batching item would land in the same
  place.
- **Adjacent wtxid bugs to clean up en route** (verified by the mapping agent): we announce to
  wtxid peers under inv type MSG_WITNESS_TX (0x40000001) instead of BIP339 MSG_WTX(5)
  (protocol.lisp:1028-1032, compensated in handle-getdata :696-714), and **incoming MSG_WTX(5)
  invs are ignored** (handle-inv matches only types 1/0x40000001, :341-342) — so BIP339-correct
  peers' announcements are dropped. Fix both when touching this path.
- v2 transport needs no changes: unknown commands auto-use long-form encoding
  (v2-transport.lisp:163-169); `sendtxrcncl` has no BIP324 short ID (matches Core).
- `-debug=txreconciliation` category already exists (logging.lisp:88).

## 5. minisketch (for the parked full protocol)

Vendored PinSketch lib; Core wrapper uses **32-bit field** (`node/minisketchwrapper.cpp:22`).
API: create(bits=32, impl, capacity) / add-uint64 (add twice = remove) / serialize (4 bytes per
capacity unit) / merge (XOR = symmetric difference) / decode. Field = GF(2^32) =
GF(2)[x]/(x^32+x^7+x^3+x^2+1), two 32-word precomputed tables (SQR/QRT,
fields/generic_4bytes.cpp:85-92); decode = Berlekamp-Massey + Berlekamp-trace root finding
(sketch_impl.h:129-323). **Pure-Lisp port verdict: very feasible, ~400-600 lines** of
(unsigned-byte 32) logxor/ash arithmetic (naive 32-step GFMul replaces the CLMUL/nibble-table
optimizations; capacities are tiny so O(c²) decode is fine); byte-exact oracles in
minisketch/src/test.cpp + src/test/minisketch_tests.cpp. FFI fallback exists (builds standalone
via autotools/CMake) but pure Lisp fits the project's MuHash precedent.

BIP330 full flow (spec, for when Core ships it): per-peer recon set instead of inv → initiator
sends `reqtxrcncl(set_size, q)` on a timer → responder `sketch(skdata)` → initiator merges with
its own sketch, decodes diff → success: `reconcildiff(1, ask_shortids)` + both sides announce
missing wtxids; failure: one extension round (`reqsketchext`) then full-flood fallback. Capacity
= |Δsizes| + q·min + c(=1). Low-fanout flooding retained for a small peer subset.

## 6. Staged milestones

| Phase | Deliverable | Size | Status vs Core |
|-------|-------------|------|----------------|
| **P0** | ✅ **DONE 2026-07-10** (PRs 242 + 243, deployed): live-loop wiring + `maintain-peers` + Core `IsInitialBlockDownload` latch; deploy verification exposed that `handle-inv` also dropped all MSG_WTX announcements — fixed (BIP339 announce/request both directions). testnet4 mempool fills from P2P; latch logged | S-M | **bug fix — done** |
| **P1** | Core-parity sendtxrcncl: config flag (default off, DEBUG-style), message codec + handshake send/receive rules + verack forget + salt storage; `compute-recon-salt` tagged-hash with a vector generated from Core | S-M | Core parity ✅ |
| P2 | ✅ (PRs 387-390, default off) per-peer recon sets + AddToSet in relay-transaction + fanout selection + timer | M | beyond Core |
| P3 | ✅ pure-Lisp minisketch (GF(2^32), BM, trace roots); Round 9: decoder ported from sketch_impl.h, vectors from Core's pyminisketch (§6.1) | M | Core's vendored library (tests only) |
| P4 | ✅ sketch exchange messages + extension + reconcildiff + flood fallback | M-L | beyond Core |

**Recommendation: do P0 now (it's a bug), P1 whenever convenient (small), park P2-P4 until Core
merges the remainder** — revisit at the next ref bump.


### 6.1 The Core-at-pin boundary (verified 2026-09-29, refs/bitcoin d3056bc149)

| Piece | Core d3056bc | Ours | Oracle it is held to |
|-------|--------------|------|----------------------|
| `sendtxrcncl` handshake, `PreRegisterPeer`/`RegisterPeer`/`ForgetPeer`, the salt combination (`ComputeSalt`, tag `"Tx Relay Salting"`, ascending order) | yes (node/txreconciliation.cpp, net_processing.cpp:3728-3742, :3879-3886, :3963-4014) | ported | Core source; `p2p_sendtxrcncl.py` (PASS); a truncated payload now takes Core's `ProcessMessages ... Exception caught` path and keeps the peer (:3994, :5283-5284) instead of our invented disconnect |
| minisketch GF(2^32) sketches: add, serialize, merge, decode | vendored (src/minisketch/), used only by tests | pure-Lisp; decoder ported from sketch_impl.h | vectors from Core's `src/minisketch/tests/pyminisketch.py` (tests/data/minisketch_core_vectors.py: field, 14 serializations, Core's minisketch_tests.cpp scenario, 116 decode verdicts incl. every failure shape) + the C library's SQR/QRT tables. The C++ library itself cannot be built in the container (no C++ compiler in the runtime image): pyminisketch-vs-C is the one residual |
| Short ID `1 + (SipHash-2-4(k0,k1,wtxid) mod 0xFFFFFFFF)` | **absent** (no `ComputeShortID`, no `AddToSet`, no `ShouldFanoutTo` at the pin) | BIP-330 | BIP-330 text + Core's functional-test SipHash (vectors) |
| Reconciliation sets and snapshots, fanout, round timer and timeout, q | **absent** | BIP-330 + named choices (`+recon-max-set-size+`, `+recon-round-interval-seconds+`, `+recon-default-q+` then BIP-330's q update, fanout shares, `+recon-max-sketch-capacity+` (ours, measured), `+recon-round-timeout-seconds+` (Core's GETDATA_TX_INTERVAL)) | properties + the two-node loopback test |
| `reqrecon` / `sketch` / `reqsketchext` / `reconcildiff` | **absent** (protocol.h:266 ends at `sendtxrcncl`) | BIP-330 tables: reqrecon = uint16 set_size + uint16 q (q x (2^15-1)); the extension is the double-capacity sketch minus the part already sent | BIP-330 text |

Reachability: every round message is ignored unless the peer completed the
handshake (impossible with `-txreconciliation` off, which is the default and
Core's DEBUG_ONLY flag) AND sends in its BIP-330 role (only the dialler sends
`reqrecon`/`reqsketchext`/`reconcildiff`, only the listener sends `sketch`).
The relay path holds transactions only for a registered peer, and the round
timer opens rounds only with one. With the flag off, nothing past the
handshake's "ignored" log line is reachable from the wire.

Fixed in Round 9 (each with a test that was red on the old code): the short
ID was `s mod 2^32` with 0 remapped (not the BIP's map, so a BIP peer would
agree on almost no ID); `reqrecon` sent a uint32 set_size and scaled q by
2^15; `reqsketchext` was answered with a whole sketch at twice the SNAPSHOT
size instead of the extension; the decoder indexed past its coefficient
vector on an LFSR longer than the capacity, answered the empty set and a
failure with the same NIL, and differed from Core on masking/zero elements
and mixed-capacity merges; round messages were accepted from either role;
a peer-sized sketch had no ceiling; the initiator skipped rounds when its own
set was empty, so the listener's held transactions had no way out; and a
reconciled difference was queued for announcement as `(wtxid wtxid 0)`, so a
segwit transaction read as gone from the mempool and every one fell under
the peer's feefilter.

Round 9, second phase (2026-09-29), each with a test red on the code before it:

- **Round timeout** (`+recon-round-timeout-seconds+` = 60). BIP-330 names no
  timeout and Core has no round, so the value is Core's nearest analogue: the
  expiry of an unanswered transaction request, `GETDATA_TX_INTERVAL` = 60 s
  (node/txdownloadman.h:38, armed at txdownloadman_impl.cpp:278). A reqrecon is
  a request whose answer we need before we can announce, as a getdata is. On
  timeout the initiator sends reconcildiff(success=0), floods its snapshot and
  opens the next round (`maybe-start-reconciliation` now takes the mempool the
  announcements need).
- **The set moves into the snapshot**, per BIP-330 ("Makes a snapshot of their
  current reconciliation set, and clears the set itself"), on both sides: a
  transaction arriving mid-round waits for the next round. A reqrecon arriving
  before the previous round's reconcildiff folds the stale snapshot into the
  new one rather than dropping it.
- **q is re-estimated** after every decoded round with BIP-330's rule,
  q = (d - |R - L|) / min(R, L) (R derived from the decoded split), held to
  what the uint16 carries; the next reqrecon sends it. The default is 1/4.
- **One writer of the announcement queue**: `%queue-tx-announcement` (txid,
  wtxid, integer fee rate per kvB); a test reads every src file and fails on
  any other definition that pushes onto `peer-tx-inv-queue`, with a positive
  control; reconciliation's announcements come from the mempool (a segwit
  transaction's txid, not its wtxid), and without a mempool nothing is queued.
- **`+recon-max-sketch-capacity+` = 128 is OUR number** (decided 2026-09-29):
  a measured denial-of-service bound with no Core reference behind it.

Left open: byte-exactness against the C++ minisketch itself, which needs a
C++ toolchain in the container.

## 7. Effort & risk

P0+P1 ≈ 2-3 PRs, low risk (P0 is behavior-*enabling*; soak testnet4 before mainnet — note
mainnet relay stays off by default per project config). Full P2-P4 ≈ 6-10 PRs and carries
spec-drift risk until Core freezes the protocol. FASL clear needed (peer defstruct).

## 8. Core source anchors

protocol.h:262-266,305; node/txreconciliation.{h,cpp} (all of it); net_processing.cpp:1713,
2020-2023, 3715-3744, 3879-3886, 3963-4014; net_processing.h:41; init.cpp:574;
node/minisketchwrapper.cpp:22-78; minisketch/: minisketch.h (API), sketch_impl.h (algorithms),
fields/generic_4bytes.cpp:85-92 (field 32 tables), src/test.cpp (vectors);
test/txreconciliation_tests.cpp. Our anchors: ibd.lisp:1309-1370 (wiring gap),
protocol.lisp:103-229 (gates), :1016-1050 (relay chokepoint), :341-352 (inv gap),
peer.lisp:272-343 (negotiation), node.lisp:1993-2000 (dead maintain-peers).
