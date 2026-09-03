# Outbound eclipse resistance (GA7 G7-08) — re-spec

Status: **P0-P3 implemented. G7-08 is complete.**

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
G7-18 (PR 311). Use them; do not add a node-scoped variant.

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

The stale-tip threshold is `nPowTargetSpacing * 3 = 1800s` on all networks,
including regtest — worth knowing, because it makes the stale-tip path testable
without network-specific fixtures.

**The factor is 3, not 30.** Earlier revisions of this document wrote
`30 * 600 = 1800s` in both places it appears. The product is right and the
factor is wrong, which is the dangerous combination: an implementer copying
`30 *` lands on 18000s — five hours instead of thirty minutes — and a reviewer
checking the stated result against Core sees 1800 and agrees. Core:
`m_last_tip_update < GetTime() - nPowTargetSpacing * 3`
(net_processing.cpp:1339).

## 5. Phases

### P0 — prerequisites (DONE)

- `update-block-availability` fed Core's `pindexLast` (PR 308). **Everything
  below reads `peer-best-known-block-hash`; without this it is stale or NIL and
  the whole subsystem silently no-ops.**
- `peer-manual` + `peer-outbound-or-block-relay-p` (PR 311).

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

The decrement is the load-bearing half: Core does it in `FinalizeNode`
(net_processing.cpp:1717-1718), which runs for *every* node removal whatever the
reason. So the counter, the grant and the release all live in `peer.lisp`
alongside the retirement paths — `disconnect-peer`, `record-misbehavior` and
`ban-peer` each call `release-outbound-protection` — rather than in `ibd.lisp`
next to the eviction logic, which loads later and could not call back into
`disconnect-peer`. The per-peer flag is the source of truth so a peer retired by
two paths decrements only once. A counter that only increments does not merely
weaken this feature, it inverts it: during IBD any caught-up peer trivially
satisfies `best-known >= tip`, so all 4 slots are spent within minutes of
startup and, once those peers churn out, no peer can ever be protected again.

The grant carries Core's `!pfrom.fDisconnect` guard (net_processing.cpp:2951) as
`peer-live-p` — a peer already in `:disconnected` or `:banned` is refused. This
is the same leak from the other end: a retirement releases the slot, but it only
happens once (`replace-disconnected-peers` reaps `:disconnected` peers out of
`node-peers` with no release of its own, and never reaps `:banned` peers at
all), so a grant made *after* the retirement is never given back. Core needs the
guard because the sub-minchainwork drop (`:2926-2944`) sets `fDisconnect` a few
lines above the grant, on the same peer, in the same pass — and during IBD the
two conditions overlap in the common case of a peer whose best-known beats our
low tip but misses the work floor. G7-18's drop belongs in that same position
(`UpdatePeerStateForReceivedHeaders`), so the guard must be in place before it
moves there, independent of merge order.

With that guard, no slot can be stranded. A grant requires a live peer;
`:disconnected` / `:banned` are set at exactly three places (`disconnect-peer`,
`record-misbehavior`, `ban-peer`), each of which releases immediately and
unconditionally in the same function, ahead of any error-prone work; and every
`node-peers` removal (`node.lisp:427`, `:479`, `:2805`, `:3242`, `:3266`) either
calls `disconnect-peer` itself or reaps a peer already in `:disconnected`, i.e.
one that has already released. Membership in `node-peers` is not what the
accounting depends on.

### P3 — stale tip and extra outbound (DONE)

Implemented as specified below. Two things the spec did not say, found while
porting and worth keeping:

- **The dialing budget and the eviction budget differ by one, deliberately.**
  The extra slot raises only what ThreadOpenConnections may dial (net.cpp:2722);
  GetExtraFullOutboundCount keeps measuring against the unraised maximum
  (:2473), so the extra peer is immediately one too many and the rotation drops
  the stalest. The extra slot buys a REPLACEMENT. Raising both together makes
  the connection permanent and silences the rotation entirely.
- **Staleness is computed as a difference inside get-universal-time**, never by
  converting an epoch, which removes the §3 clock hazard rather than managing
  it.

`CheckForStaleTipAndEvictPeers` (net_processing.cpp:5460) on the 45s cadence
already established in `maintain-peers` by P1's `consider-outbound-evictions`.
It has three parts, and earlier revisions of this section described only the
second — the other two are restated here because each is load-bearing.

**Prerequisite: the `last-block-announcement` stamp.** Unix seconds, on the
peer. Core credits it at exactly two sites, both gated on
`received_new_header && <that chain>.nChainWork > our tip work`: headers
processing (net_processing.cpp:2922) and compact-block processing (:4624). It
is the *announcement* that counts, not a successful reconstruct (§3).

**(a) Extra block-relay-only eviction** (:5360). Runs whenever we hold more
block-relay peers than the target. Pick the *youngest* (highest peer id);
if that peer gave us a block more recently than the second-youngest, evict the
second-youngest instead. This half compares `m_last_block_time` — when a block
was *received* — **not** the announcement stamp; they are different clocks on
different peer sets and swapping them silently inverts the choice. The youngest
block-relay peer is by construction the extra one opened to unstick our tip, so
this is what closes the slot that (c) opens.

**(b) Extra full-relay rotation** (:5400). Pick the outbound full-relay peer
with the oldest `last-block-announcement`, subject to four filters, all
required:

- skip peers already marked for disconnection;
- **skip chain-sync-protected peers** (`m_chain_sync.m_protect`, :5419) — P2
  grants that flag precisely so rotation cannot take the peer back;
- skip a peer that is our only OUTBOUND_FULL_RELAY-or-MANUAL connection on its
  network (`MultipleManualOrFullOutboundConns`, :5422);
- **ties on the stamp break toward the higher peer id** (:5423), i.e. evict the
  *more recent* connection. Both halves of that comparison matter: a fresh peer
  starts at stamp 0 and so ties with every other peer that has never announced,
  and without the tie-break the choice among them is whatever order the peer
  list happens to be in.

Then, before actually disconnecting: `now - connected > MINIMUM_CONNECT_TIME`
(30s) **and** that peer has no blocks in flight. Note Core uses strict `>` here
and `>=` in the block-relay half (:5386); no behavioural difference at second
resolution, but do not "harmonise" them.

**(c) Stale-tip trigger** (:5471). Gated on its own **10-minute** timer
(`STALE_CHECK_INTERVAL`) *inside* the 45s sweep — the two cadences are
different and both real. If the tip may be stale — `last-tip-advance <
now - nPowTargetSpacing * 3` **and** nothing in flight globally
(`TipMayBeStale`, :1332) — allow one extra outbound connection.

**The reset is not optional**: when the tip is no longer stale, Core clears the
flag (`SetTryNewOutboundPeer(false)`, :5476). Without it the first stale
episode raises the outbound budget permanently, and (a) then spends every sweep
evicting a peer we just dialled.

We have no "extra outbound slot" concept today — the outbound budget is fixed
— so this is the one structurally new piece rather than a port of a loop.

**Clock epoch.** `node-last-tip-advance-time` (node.lisp:225) is
`get-universal-time`; everything else here is unix seconds. Convert at the
comparison or repeat §3's ~2.2e9-second error.

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
