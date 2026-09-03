# Core functional test triage (2026-08-25)

The coverage document's §8 lists "only 35 of 263 functional tests ever run" as P4, and judges it the
highest-leverage item right now. This round re-ran the triage. The conclusion supports that judgment.

## Method and confidence

`scripts/conformance.sh` drives Core's own `test/functional` against our node binary, with a 150-second limit per
test. Ran **p2p (55) + rpc (38) + mempool (20) + mining (5) + interface (12) = 130 tests**, 49% of the full set of
266.

⚠️ **The first round's numbers are not trustworthy, and the cause was self-inflicted**: `conformance-config.sh`
writes the shared `build/bin/bitcoind` with `ln -sf`, and `ln -sf` is "unlink then create". With four batches
running concurrently, any test that exec'd right in that window got `OSError: [Errno 22]`, which showed up as an
entire batch of apparently unrelated failures. And `conformance.sh`'s own comment claims "concurrent runs will not
conflict". Only after switching to an atomic replace via rename(2) and re-running did the numbers below become
valid.

## The biggest finding: one root cause blocking 45 tests

**`getblock` cannot find the genesis block.** 45 tests fail on the same `-5 Block not found`.

The cause is an explicit design decision, written at `chain.lisp:294`: *"The genesis block's BODY is never stored
in block storage (it is never received over the wire)"*. This holds for us but not for Core -- Core writes the
genesis block into the block files at initialization, so every one of Core's readers can retrieve it. And
`getblock(getbestblockhash())` on a brand-new node **is** the genesis block -- Core's test framework opens exactly
that way (`p2p_invalid_block.py:45`, `p2p_invalid_tx.py:54`).

The fix belongs in `get-block` rather than in the twelve RPC/REST call sites that want the block body -- one of
those would certainly get missed. `make-genesis-block` is self-verifying (it recomputes the merkle root and checks
it against the known genesis hash), so it cannot answer with the wrong block.

**Result: `Block not found` dropped from 45 to 2, and 3 tests went straight to green.**

⚠️ While fixing this I introduced a worse bug of my own: appending a form after `get-block`'s `let` **discards the
`let`'s return value**, so a block successfully read from the old-style single-block file got thrown away and the
function fell back to the genesis (NIL, for most blocks). The cost was 33 red tests and one misdiagnosis -- I
briefly believed "a just-mined block cannot be looked up" was a new storage defect. Chaining with `or` fixed it.

## Root-cause triage of the remaining failures

Of the 130 tests run, excluding the category above, the rest group by root cause:

| Category | Count | Nature |
|---|---|---|
| **Missing log lines** | 12 kinds | Core's tests grep `debug.log` for exact strings. Each one is a small fix |
| I2P not implemented | 3 | A genuine feature gap (`Creating persistent I2P SAM session`, etc.) |
| RPC error text | several | Same class as PR 493: `Missing or invalid method` vs. Core's `Missing method` |
| Timeouts | 9 | Need individual review, could be a hang or just slow |
| Other assertions | the rest | Each an independent finding |

The missing log lines, verbatim:

```
AcceptBlockHeader: not adding new block header <hash>, missing anti-dos proof-of-work validation
Added connection peer=0
bad-txns-duplicate
bad-txns-vout-empty
Creating persistent I2P SAM session
DNS seeding disabled
Empty addrman, adding seednode (25.0.0.1) to addrfetch
Error connecting to <...>.b32.i2p:8333, connection refused due to arbitrary port 8333
ignoring redundant verack message
Misbehaving
Recreating the banlist database
start sending v2 handshake to peer
Synchronizing blockheaders, height: N
ThreadRPCServer method=getblocktemplate
transaction sent in violation of protocol, disconnecting peer=0
```

`bad-txns-duplicate` and `bad-txns-vout-empty` deserve individual attention: those are **consensus rejection
reasons**, not log decoration. We either never emit this log line, or we use different wording.

## Judgment

The coverage document says "every remaining red test is a finding". The evidence from this round: running 49%
turned up one root cause blocking 45 tests, one concurrency defect in the harness itself, a 15-item list of missing
log vocabulary, plus several independent assertions. **Not one failure was noise.**

The next-step ordering should be: first fill in the log vocabulary (12 kinds, mechanical and cheap, turns a batch
green), then review the timeouts individually (a hang is the only kind of defect this suite can find), and finally
run the remaining 136 (feature 61 + wallet 63 + tool 8 + other).

## Continued: log vocabulary batch (2026-08-26)

The triage report's own next step was "fill in the log vocabulary first". This batch did five lines, each one
first located at its emission point in Core, then matched to our corresponding location -- **the location is
easier to get wrong than the wording**.

| Line | Core emission point | Our original problem |
|---|---|---|
| `ignoring redundant verack message from peer=N` | net_processing.cpp:3822 | The post-handshake verack fell into "unknown command", with no branch |
| `Added connection [to A ]peer=N` | net.cpp:4005/4009 | Never emitted; Core emits it for both outbound and inbound, the inbound one without an address |
| `DNS seeding disabled` | net.cpp:3525 | **wrong location** -- see below |
| `Loading addresses from DNS seed S` | net.cpp:2353 | We only emitted one summary line, Core emits one per seed |
| `Recreating the banlist database` | banman.cpp:41 | We only emitted it on a **read failure**, whereas Core emits it whenever `Read` returns false, **which also covers the file not existing** |

⚠️ **The lesson from "DNS seeding disabled" is about location, not wording.** My first version placed it inside
`connect-to-peers`, at the `-dnsseed=0` check -- looks right, but that function only reaches that section when it
"wants more addresses". Core emits it at **startup**, right where the DNS thread is either started or abandoned
(net.cpp:3524-3525). Every node the test framework starts carries `-connect`, so our line could never fire. Moving
it to the startup path made it pass immediately.

Likewise for `Recreating the banlist database`: my first version put it in error handling, but a brand-new
datadir **has no** banlist.json at all -- `probe-file` returns false and it silently returns. Core's `Read`
likewise returns false for a missing file.

### ⛔ A genuine behavior gap, clearly diagnosed but not fixed

`p2p_dns_seeds.py`'s second assertion requires that DNS seeds are still queried when `-connect` is combined
**with** an explicit `-dnsseed=1`. Core's `ThreadDNSAddressSeed` is an **independent thread**, started when connman
starts up, and
is unrelated to `-connect`; we folded discovery into `connect-to-peers`, and under `-connect` that code path only
dials the nodes named in the config.

The soft-set rule (`-connect` turns off `-dnsseed` by default) is already implemented on our side, so only nodes
that **explicitly request** `-dnsseed=1` are affected. The fix is to lift DNS seeding out into an independent
startup step, isomorphic to Core.

**Not done this round**: it touches the peer-discovery path of two live nodes and deserves its own round with its
own verification, rather than being slipped in incidentally alongside a batch of log-wording fixes.

## Continued: root cause of the timeouts (2026-08-26)

The triage report's second step was "review the timeouts individually -- a hang is the only kind of defect this
suite can find". Of 25 timeouts, the first one was investigated; the root cause is **shared**, and it is not a
hang.

`wallet_basic.py` stalls at `generate` + `sync_all`. But three-node sync itself is fine (converges in 14 seconds),
and mempool sync is also normal. The real problem was measured with `diag/propagation_probe.py`:

```
ROUND 0 mine=0.02s propagate=3.02s
ROUND 1 mine=0.00s propagate=4.03s
ROUND 2 mine=0.01s propagate=4.04s
ROUND 3 mine=0.01s propagate=4.04s
ROUND 4 mine=0.01s propagate=4.03s
```

**A block takes a constant 4 seconds to propagate on regtest**, while mining it takes only 0.01 seconds. That
round number points to waiting on a cycle, not network latency. The receiving side's log gives the whole answer:

```
00.436  Received: 1 headers, 1 new        <- header already received and ingested
00.436  IBD state: IDLE -> SYNCING-HEADERS   <- but the state machine got pushed back
02.471  Header sync kicked: 0 headers ingested  <- 2 seconds wasted waiting, not one more header
02.472  IBD state: SYNCING-HEADERS -> SYNCING-BLOCKS
03.456  IBD state: SYNCING-BLOCKS -> SYNCED
```

**An already-announced block drags the node through the entire IBD state machine.** `run-ibd` unconditionally
runs Phase 1 (header sync) before Phase 2, so every wakeup asks the peer for another round of headers we already
have, gets back 0, waits out the full timeout, and only then downloads the block.

Core does not do this: `ProcessHeadersMessage`, once already synced, attaches the header and then **requests that
block directly**.

This is the shared root cause of the 25 timeouts -- a test like `wallet_basic.py` calls generate+sync_all dozens
of times, and at 4 seconds each it runs into the test's own timeout. It also explains why the failures concentrate
in the wallet and feature categories, which mine blocks repeatedly.

✅ **Fixed** (in a separate round). The gate: when the header chain is already ahead of the block tip, Phase 1
has nothing to do while Phase 2 has work waiting -- exactly the state an **announcement** leaves behind. Core's
rule is isomorphic, just from the other end: it only asks for more headers when the headers message is **full**
(net_processing.cpp:3105); a single announced header never triggers another getheaders.

Measured: **4.0 seconds -> 2.0 seconds**, `wallet_basic.py` went from TIMEOUT to FAIL -- meaning it now runs to
completion and stalls on a real assertion, which is exactly what triage wants.

✅ **That remaining 2 seconds got fixed too**. In the wait between two rounds of the sync thread, `(sleep 1)` ran
**before the pump**, so a message that just arrived had to wait out an entire full tick before being read, and one
propagation spans two ticks. Splitting that tick into 1/5 second (the 30-second ceiling stays unchanged; the
trickle/ping/dump operations in the loop that want "once per second" are all gated on a **derived second**, so
finer slicing does not make them run more often).

**4.0s -> 2.0s (PR 507) -> 1.0s (PR 508)**, a 4x improvement.

⚠️ The remaining 1 second is not on the receiving side: the receiver now gets the header within a second, and
the time is spent in the 1.2 seconds of `SYNCING-BLOCKS`, i.e. the round trip from getdata going out to the block
coming back. The download loop's own idle step is only 0.05 seconds, so this is the **sender's** cadence for
noticing the getdata. Not yet investigated.

⚠️ And it does not resolve every timeout: `wallet_conflicts`, `p2p_addr_relay`, `feature_anchors` **still time
out** even at 1-second propagation, meaning they have a separate root cause. Separating the two categories requires
re-running the baseline.

## New baseline (2026-08-26, main 2de923c)

**34 PASS / 213 FAIL / 18 TIMEOUT**, 265 tests, one consistent measurement.

⚠️ Do not compare it to the "48 PASS / 188 FAIL / 30 TIMEOUT" in §14. That number was stitched together from
three sweeps at **different times, on different binaries** (the p2p and rest batches ran before the genesis fix),
and was never a single valid measurement. That is exactly why this re-run matters. The only comparison that holds
up is the timeout count: **30 -> 18**, meaning the PRs 507/508 propagation fixes resolved 12 of them.

A sample of 20 tests run individually showed **zero disagreement** with the concurrent sweep results, so
concurrency itself is stable; `wallet_avoidreuse` FAILs in the batch but PASSes when run alone -- an isolated
flake.

### Fixed this round from the new baseline

**The `+json-empty-array+` sentinel leaked into the PSBT creators.** An empty JSON array arrives at the handler as
a **sentinel** rather than NIL, so the handler can distinguish `[]` from "not passed" (server.lisp:349). Passing
the sentinel through unchanged into code expecting a LIST manifests as RPC **-32603 Internal error**.

Both `createpsbt([], {...})` and `walletcreatefundedpsbt([], {...})` were hit, and the latter is
`rpc_psbt.py`'s **first call** -- the sentinel took down the whole test before it could assert anything. After the
fix, both tests advance to real assertions.

Similar sites were checked: the other four spots in psbt.lisp and `createrawtransaction` already use
`%positional-array`; only these two were missed.

### Next batch candidates (by count)

| Root cause | Count |
|---|---|
| RPC errors (see below) | 47 |
| Uncategorized (need individual review) | 38 |
| Missing log lines | 19 |
| Timeouts | 18 |
| Assorted assertions | the rest |

RPC errors that can be acted on directly: `Method not found` (4, missing RPCs), `Unknown named parameter
feeRate/fee_rate` (2, the options members are not yet fully covered), `Invalid wallet name` (2, our name
validation is stricter than Core's), `transactions must be an array` (2), `Data must be hexadecimal string` (2).

## Continued: p2p_sendheaders (2026-09-03)

The second peer's handshake at `p2p_sendheaders.py:228` passes now, and the test stops at `:255`: after
test_node sends an unrequested block that becomes the tip (node0's log shows the height moving 1 -> 2, with no
`received: block` line, because the block message is not logged at that level), inv_node never receives the
inv announcement `check_last_inv_announcement` waits for. A node built from `0a7dd5f`, before the second-round
refactor, stops at the same line, so this is not a refactor regression. `relay-block` and its call in the
"block" handler are unchanged; the open question is why an unsolicited block that becomes the active tip is
not announced to the other connected peer -- `block-relay-targets` and the `relay-enabled-p` gate are the
places to look.

