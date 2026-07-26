# Outbound eclipse resistance (GA7 G7-08) — re-spec

Status: **P0 implemented; P1–P3 specified, not implemented.**

This is a re-specification. The original automated spec for G7-08 was judged
**unsound** by an adversarial review, with two *design-breaking* errors (§2).
It is rewritten here so those cannot be reintroduced, and so the remaining
phases are executable without re-deriving anything.

All Core citations are against the vendored `refs/bitcoin` revision and were
verified by reading the source, not taken from the gap analysis — whose
`approach` fields have been wrong at least twice in this project (G7-36's trim
direction was backwards; G7-19's "one persistent nonce" would have introduced a
tracking identifier).

## 1. The gap

An adversary — or simply a stuck set of peers — that fills our ~8 outbound
slots with live-but-silent peers can pin us on a stale or low-work tip
indefinitely. We have no work-based chain-sync eviction, no stale-tip trigger
to open an extra outbound peer, no rotation of the least-recently-announcing
outbound peer, and no protection for peers that have proven useful.

Our only substitute keys on the **unauthenticated static handshake
start-height** (`consider-peer-eviction`, peer.lisp) and only runs inside the
IBD download loop — so it is both spoofable and absent at the tip.

## 2. The two design-breaking errors (do not reintroduce)

**(a) `manual-peer-p` cannot live in `node.lisp`.** The original spec placed
`consider-chain-sync-eviction` in `src/networking/ibd.lisp` with a gate calling
a `node.lisp` predicate. `bitcoin-lisp.asd` loads the networking module
*before* `node.lisp`, so the call is not merely awkward — it is unavailable.
As written the subsystem would have evicted the operator's `-addnode` peers,
the exact regression its own risk notes forbid.

*Resolved*: `peer-manual` is a slot on the peer struct and
`peer-outbound-or-block-relay-p` is the shared predicate, both landed with
G7-18 (PR #311). Use them; do not add a node-scoped variant.

**(b) The sweep must not live in `run-ibd`'s download loop.** The original spec
anchored it at the `consider-peer-eviction` block inside `run-ibd`'s
`loop while` — whose head our own comment says never runs at tip. That places
the anti-eclipse core **exactly where eclipse does not matter** and omits it
where it does.

*Resolution*: drive it from `maintain-peers` in `node.lisp`, on its own
cadence. Related false claim in the original spec: that a `run-ibd`-local
timestamp gives a 45s cadence. `run-ibd` is re-entered on every outer sync
cycle, so a loop-local variable resets each pass.

## 3. Additional corrections carried forward

- **Clock epochs.** `node-last-tip-advance-time` is `get-universal-time`;
  `peer-connected-at` / `peer-last-block-time` are unix seconds; the feefilter
  timers (G7-15) are unix seconds; `%next-exp-interval-ticks` is
  internal-real-time. The original spec computed one `now` and fed it to two
  families — a ~2.2e9-second error. **Every timer added here is unix seconds.**
- **The announcement stamp belongs on the announcement, not the reconstruct.**
  It must be credited where a block is *announced*, not only where a compact
  block successfully reconstructs.
- **`m_protect` is assigned at the headers-processing site**, not in the
  eviction sweep, and is capped by a node-wide counter.
- Chain-sync eviction sends a **probing getheaders first** and only disconnects
  after a further `HEADERS_RESPONSE_TIME`; the full budget is 20min + 2min.

## 4. Verified Core constants

| Constant | Value | Source |
|---|---|---|
| `HEADERS_RESPONSE_TIME` | 2 min | net_processing.cpp:100 |
| `MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT` | 4 | :104 |
| `CHAIN_SYNC_TIMEOUT` | 20 min | :106 |
| `STALE_CHECK_INTERVAL` | 10 min | :108 |
| `EXTRA_PEER_CHECK_INTERVAL` | 45 s | :110 |
| `MINIMUM_CONNECT_TIME` | 30 s | :112 |
| `MAX_OUTBOUND_FULL_RELAY_CONNECTIONS` | 8 | net.h:69 |
| `MAX_BLOCK_RELAY_ONLY_CONNECTIONS` | 2 | net.h:73 |
| `nPowTargetSpacing` | 600 s on **every** network | kernel/chainparams.cpp |

The stale-tip threshold is `30 * 600 = 1800s` on all networks, including
regtest — worth knowing, because it makes the stale-tip path testable without
network-specific fixtures.

## 5. Phases

### P0 — prerequisites (DONE)

- `update-block-availability` fed Core's `pindexLast` (PR #308). **Everything
  below reads `peer-best-known-block-hash`; without this it is stale or NIL and
  the whole subsystem silently no-ops.**
- `peer-manual` + `peer-outbound-or-block-relay-p` (PR #311).

### P1 — ConsiderEviction (chain-sync timeout)

Port net_processing.cpp:5292-5350, driven from `maintain-peers`.

Per-peer state: `chain-sync-timeout` (unix seconds, 0 = unarmed),
`chain-sync-work-header` (the tip hash benchmarked against),
`chain-sync-sent-getheaders`, `chain-sync-protect`.

Gate: `(and (not protect) (peer-outbound-or-block-relay-p peer) sync-started)`.

- **A** — peer's best-known work ≥ our tip work → clear the timer.
- **B** — timer unarmed, *or* the peer has since reached the benchmark we armed
  against → re-arm: `timeout = now + 20min`, `work-header = current tip`,
  `sent-getheaders = nil`.
- **C** — armed and expired: if a probing getheaders was already sent →
  disconnect (silently — no misbehaviour score). Otherwise send getheaders on
  the locator of `work-header`'s parent, set the flag, and bump the timeout by
  `HEADERS_RESPONSE_TIME`.

### P2 — protection

At the headers-processing site (net_processing.cpp:2946-2956): when an outbound
full-relay peer delivers a chain at least as good as our tip and the node-wide
protected count is below 4, set its `chain-sync-protect` and increment. Decrement
on disconnect, asserting it never goes negative. **Block-relay peers are
deliberately *not* protected** — they are always subject to the bad/lagging
chain logic.

### P3 — stale tip and extra outbound

`CheckForStaleTipAndEvictPeers` on a 45s cadence in `maintain-peers`:

- If our tip has not advanced in `30 * 600 = 1800s` and nothing is in flight,
  open **one** extra outbound peer.
- Rotate the outbound peer with the oldest last-block-announcement stamp when
  over budget, respecting `MINIMUM_CONNECT_TIME` (30s) and the network-uniqueness
  guard (`MultipleManualOrFullOutboundConns`, net_processing.cpp:5422) so we
  never drop our only peer on some network.

Requires a `last-block-announcement` stamp credited at announcement time (§3).

## 6. Testing

Every phase mutation-tests as red-then-green. Specific traps found in review:

- A test that force-sets peer state without a handshake will not exercise the
  gate — check `sync-started` is genuinely reachable.
- The original spec proposed asserting on a `let*`-local `needed` binding
  inside `replace-disconnected-peers`; that is not observable. Assert on the
  peer set instead.
- Bind the IBD latch explicitly. It defaults to true, and several proposed
  tests would otherwise crash or pass vacuously.
- Never assert exact addrman counts (standing project rule).

## 7. Deliberately out of scope

`MSG_CMPCT_BLOCK` getdata (G7-16 step 9). Routing solicited blocks through
`handle-cmpctblock` bypasses `process-received-block` and therefore
`drain-block-queue` — the machinery that resolved the multi-day deep-reorg
wedge. It needs that path unified first.
