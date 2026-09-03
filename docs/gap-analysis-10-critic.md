# GA10 completeness critic — what this round still misses

Verbatim output of the completeness-critic agent (GA10 round 2). This is GA11's starting point.

All paths below are under `/Users/sen/common-lisp/bitcoin-lisp/`. Report read: `/Users/sen/common-lisp/bitcoin-lisp/docs/gap-analysis-10.md` (447 lines).

# What GA10 still misses

**Bottom line.** GA10's 12 dimensions covered roughly the middle of the tree. Measured against `find src -name '*.lisp'` (148 files, 89,752 lines): **28 files / 6,099 lines were never named by any finder**, and a further **14 files / 7,218 lines were named only inside a "NOT covered" clause** — 42 files, 13,317 lines, ~15% of the tree, untouched, before counting the partial reads inside big files. On Core's side, ~30,000 non-vendored lines have no dimension pointed at them at all. And the round was 100% static: at least two finders recorded that the Docker socket was absent, and every one of the twelve wrote some form of "I ran no code." Docker is up now (`29.7.2`) — GA11 has no excuse.

---

## 1. Core subsystems with NO dimension at all

Ranked by (Core LOC × consequence). Each names our counterpart so GA11 can assign it directly.

| # | Core subsystem | Core LOC | Our counterpart | Why it matters |
|---|---|---|---|---|
| A | `script/descriptor.cpp` (3006) + `sign.cpp` (1075) + `signingprovider.cpp` (645) + `solver.cpp` (228) | ~5,000 | `src/rpc/descriptors.lisp` (2164) | Every address we derive, `importdescriptors`, `deriveaddresses`, `scantxoutset`, all wallet key material. Dim 3 listed it under "not audited in depth"; dim 11 read the wallet *engine*, not this. Memory already holds two descriptor traps (expansion cache keyed by descriptor string; xonly print-vs-script flag) — both found *outside* a gap analysis. |
| B | `script/miniscript.h` (2704) + `miniscript.cpp` (432) | ~3,100 | `src/validation/miniscript.lisp` (1983) | Consensus-adjacent satisfaction/sizing. Dim 5 and dim 12 *both* explicitly excluded it. Largest single unread file in the tree after descriptors. |
| C | `txgraph.cpp` (3581) + `cluster_linearize.h` (2041) | ~5,600 | `src/mempool/txgraph.lisp` (1132), `spanning-forest.lisp` (761), `cluster-linearize.lisp` (466), `feefrac.lisp` (168) | Dim 5 wrote "NOT covered … chunk/linearization correctness, txgraph-get-worst-main-chunk eviction ordering, txgraph-rbf-diagrams"; dim 7 wrote "I took the chunk ordering and topological guarantees on trust." Two dimensions both declined the same 2,527 lines. |
| D | `txrequest.cpp` (757) + `node/txdownloadman_impl.cpp` (583) | ~1,340 | `src/networking/protocol.lisp:344-600` | Our own comment says *"Simplified vs Core's full 3-state priority machinery (txrequest.cpp)."* Dim 8 excluded "the tx-relay/orphan/1p1c half of protocol.lisp (handle-tx, process-orphans, txrequest tracker)"; dim 5 took orphanage only. **Transaction relay scheduling has zero coverage in a round that had a p2p dimension.** |
| E | `wallet/walletdb.cpp` (1385) + `sqlite.cpp` (713) + `db.cpp` (159) | ~2,250 | `src/wallet/wallet-store.lisp` (443) | Wallet record persistence. Dim 11: "Not covered: wallet-store.lisp record key layout and %load-wallet-records." A misread record loses funds. |
| F | `wallet/rpc/*` (6 files) | ~3,000 | 62 `define-rpc` forms across `src/wallet/` (of 162 total) | Fell in the seam: dim 3 said wallet RPCs are "out of dimension," dim 11 said "the listtransactions/listsinceblock/gettransaction JSON field sets; getaddressinfo and InferDescriptor" not covered. **38% of our RPC surface was nobody's job.** |
| G | `rpc/util.cpp` (1405) + `core_io.cpp` (534) + `rawtransaction_util.cpp` (391) | ~2,300 | `src/rpc/output-script.lisp` (151, never opened), `src/rpc/accessors.lisp` (94, never opened), `src/rpc/json.lisp`, the `*-to-json` helpers | This is where every RPC argument parse and error *string* comes from — the exact text Core's functional tests assert on. Directly explains functional-suite failures. |
| H | `policy/fees/block_policy_estimator.cpp` internals (1119) + `rpc/fees.cpp` (227) | ~1,350 | `src/mempool/block-policy-estimator.lisp`, `src/mempool/fee-estimator.lisp` (370) | Dim 5: "not covered: the internal math … TxConfirmStats decay/estimate-median, fee_estimates.dat format." `estimatesmartfee`/`estimaterawfee` had no reader. |
| I | `wallet/coinselection.cpp` (994) | 994 | inside `src/wallet/wallet-spend.lisp` | Dim 11: "the BnB/Knapsack/SRD algorithm bodies line-by-line (I read their call sites and parameters only)." |
| J | `random.cpp` (716) + `randomenv.cpp` (473) | ~1,200 | `src/node/entropy.lisp` (61 lines, **never opened**) | It seeds `CL:*RANDOM-STATE*`, which is not a CSPRNG. Whatever is keyed off it — addrman bucket keys, P2P nonces, tie-breaks, ephemeral values — is a security question nobody has ever asked in ten rounds. |
| K | `scheduler.cpp` (200) + `validationinterface.cpp` (263) + `node/kernel_notifications.cpp` + `node/abort.cpp` | ~700 | `src/node/housekeeping.lisp` (157), `src/node/notify.lisp` (30), `src/node/wallet-hooks.lisp` (69), `src/node/indexes.lisp` (367) — **all four never opened** | The notification fan-out *drive sites*. Dim 4 read the index bodies and never the drivers. This is textbook `feedback_port_every_core_call_site`. |
| L | `node/chainstate.cpp` VerifyDB (280) | 280 | **absent** — `checkblocks`/`checklevel` are on the accept-and-drop list (`src/config-options.lisp:392`) | We never verify the chain DB at startup. Core does it every boot. |
| M | `versionbits.cpp` (345) + `deploymentinfo.cpp` + `deploymentstatus.h` | ~450 | `src/validation/versionbits.lisp` | Dim 10 explicitly excluded "versionbits state transitions"; dim 3 excluded "getdeploymentinfo field-by-field"; dim 7 found the symptom (gbt hardcodes `0x20000000`) without an owner for the cause. |
| N | `banman.cpp` (206) + `net_types.cpp` (74) | 280 | ban state across `src/networking/peer.lisp`, `addrman.lisp`, `node/init.lisp`, `node/shutdown.lisp` | `banlist.json` format parity and ban persistence across restart. Dim 1 read the misbehavior/discourage logic, not the persistence. |
| O | `merkleblock.cpp` (183) + `rpc/txoutproof.cpp` (186) | 369 | `src/rpc/merkleproof.lisp` | GA8 already found forged-merkle-proof acceptance here once. Dim 3 listed it as not audited. |
| P | `util/asmap.cpp` (355) + `netgroup.cpp` (127) | 482 | `src/networking/netaddress.lisp:766-940` | Dim 1: "the asmap trie decoder … was not verified against Core's asmap.cpp." A wrong trie decode silently destroys eclipse resistance. |
| Q | `zmq/*` (5 files) | ~700 | `src/zmq.lisp` | Only touched by dim 6, for one reorg notification. Sequence numbers, HWM, topic/payload parity: unowned. |
| R | `node/timeoffsets.cpp` (66) | 66 | **absent** (we store per-peer offset, no aggregator/warning) | |
| S | `node/caches.cpp` (84) + `kernel/caches.h` | ~150 | `src/kv/leveldb.lisp:228-262` | Dim 4 read leveldb.lisp for "options/error/lifecycle" only. `-dbcache` splitting is a live perf/OOM question. |
| T | `i2p.cpp` (495), `mapport.cpp`+`common/pcp.cpp`+`netif.cpp` (1098), `private_broadcast.cpp` (152), `common/bloom.cpp` (246) | ~2,000 | **absent** — all on the core-only accept-and-drop list | Dim 1 flagged I2P/private-broadcast as not compared and stopped there. |
| U | `signet.cpp` (153) | 153 | `src/validation/signet.lisp` | Dim 10 read lines 255-280; dim 7 excluded "signet block-solution production." |

**Cross-cutting seam nobody owned:** the reconciliation at startup between the persisted coins best-block pointer and the chain tip. Dim 4 said "NOT covered: `src/storage/chain.lisp` beyond the prune-cursor … the header-index serialization/CRC/delta-log format and load path, ~1400 lines, was only sampled." Dim 6 said "NOT covered: block-index status persistence and startup roll-forward reconciliation … the PHASE A critical-flush safety argument depends on that and I did not verify it." **Both this round's S1s live on exactly that path**, and both dimensions declined it.

---

## 2. Our source files nobody opened

**Never named by any finder (28 files, 6,099 lines)** — ranked by risk, not size:

| File | LOC | Why it should have been read |
|---|---|---|
| `src/validation/miniscript.lisp` | 1983 | see B above |
| `src/node/indexes.lisp` | 367 | The index hook *drive sites* + coinstatsindex crash-consistency. Dim 4 read every index body and none of its drivers. |
| `src/coalton/serialization.lisp` | 479 | The consensus script layer's data plumbing, under a `script.lisp` + `interop.lisp` that *were* read in full |
| `src/coalton/binary.lisp` | 284 | Same. GA10's first unverified S1 is a signed/unsigned bug *at this exact boundary* (`buf-set-u32-le` vs `(signed-byte 32)`) |
| `src/node/state.lisp` | 185 | Defines the `node` struct **and the locks** |
| `src/serialization/message-macro.lisp` | 178 | A **macro** generating every P2P struct/reader/writer. A bug here is systemic — and per CLAUDE.md a macro change survives warm rebuild, restart *and* an ordinary cold run, so it is also the file most able to produce a false green |
| `src/node/logging.lisp` | 187 | Dim 2 flagged the logging-option surface as uncovered; the cleartext-password S2 lives one file away |
| `src/coalton/types.lisp` | 153 | Coalton↔CL representation. Dim 12 could not confirm representation questions without a REPL |
| `src/rpc/output-script.lisp` | 151 | `createmultisig`/`validateaddress` (Core `rpc/output_script.cpp`) |
| `src/node/mempool-persist.lisp` | 133 | mempool.dat + broadcast tail; dim 5 excluded mempool.dat; history: an 83MB mempool.dat = 45-min silent outage |
| `src/node/sync.lisp` | 118 | Builds the `node-context` every pass and tick consumes; its own docstring records a past drift bug |
| `src/node/reindex.lisp` | 117 | `-reindex-chainstate` |
| `src/node/params.lisp` | 105 | Node file load order + `sb-sprof` |
| `src/storage/coins-view-migration.lisp` | 100 | utxoset.dat → LevelDB one-shot import |
| `src/rpc/accessors.lisp` | 94 | **Documents the entire node locking discipline.** Never read. |
| `src/node/listen.lisp` | 88 | Serial inbound accept loop with an inline handshake — a slow-loris shape we have been bitten by before |
| `src/util/context.lisp` | 86 | The `node-context` struct every handler takes |
| `src/node/wallet-hooks.lisp` | 69 | Wallet drive sites in connect-block / perform-reorg / mempool mutation |
| `src/util/conditions.lisp` | 67 | Condition hierarchy |
| `src/wallet/signmessage.lisp` | 66 | |
| `src/node/entropy.lisp` | 61 | see J above |
| `src/coalton/crypto.lisp` | 54 | |
| `src/networking/fd-wait.lisp` | 53 | The `poll(2)` shim written after the mainnet fd>1023 outage; never re-reviewed since |
| `src/util/ratelimit.lisp` | 44 | Asserts "no locking: every bucket belongs to one peer and is touched from one thread" — an invariant only a call-graph check can confirm |
| `src/node/notify.lisp` | 30 | `-blocknotify`/`-startupnotify`/`-shutdownnotify` |
| `src/node/housekeeping.lisp` | 157 | `-stopatheight`, disk-space abort, periodic peers.dat |
| `src/networking/minisketch.lisp` / `txreconciliation-set.lisp` | 400 / 290 | Erlay; parts have no Core reference at all |

**Named only as "not covered" (14 files, 7,218 lines):** `src/rpc/descriptors.lisp` (2164), `src/mempool/txgraph.lisp` (1132), `spanning-forest.lisp` (761), `cluster-linearize.lisp` (466), `feefrac.lisp` (168), `fee-estimator.lisp` (370), `src/wallet/wallet-store.lisp` (443), `src/crypto/chacha20.lisp` (410), `src/crypto/bip324.lisp` (141), `src/networking/socks5.lisp` (263), `src/storage/txospenderindex.lisp` (294), `blockfilter.lisp` (229), `migrate-blocks.lisp` (200), `reindex.lisp` (177).

**Also unowned and not a `.lisp` file:** `src/config-options.lisp:388-410` registers **55 accept-and-drop options**. GA10 found exactly one of them fails open (`-rpcwhitelist`) and stopped. Grep proves at least these have *zero* implementation anywhere in `src/`: `persistmempool`, `walletbroadcast`, `addresstype`, `changetype`, `avoidpartialspends`, `limitancestorcount/size`, `limitdescendantcount/size`, `checkblocks`, `checklevel`, `maxreceivebuffer`, `rpcworkqueue`, `timeout`, `blockversion`, `vbparams`, `discover`. An operator setting `-walletbroadcast=0` for offline signing gets broadcasts anyway; one setting `-limitancestorcount` gets our defaults. Same fail-open shape, twelve more instances, one grep away.

---

## 3. Dimensions that under-returned for their surface

| Dimension | Our LOC in scope | Findings | Verdict |
|---|---|---|---|
| **wallet** (11) | ~12,961 (`src/wallet/`) — **the single largest module, 14% of the tree** | 7, all unverified | **Worst ratio in the round.** Skipped wallet-store, coin-selection bodies, all 62 wallet RPCs' field sets, miniscript sizing, `%psbt-finalize` witness assembly. |
| **crypto-encoding** (9) | ~6,300 (`src/crypto/` + `src/serialization/` + bytes) | **2** (lax DER, base58 length) | Self-declared uncompared: chacha20, bip324, **the entire Schnorr/x-only/ellswift/MuSig2 half of secp256k1.lisp (~536 lines)**, **BIP143 *and* BIP341 sighash preimage construction**, addrv2/BIP155 codecs. It excluded the taproot signing surface and then reported two findings. |
| **p2p-protocol** (8) | ~15,439 (`src/networking/`) — largest after wallet | 6 | Excluded addrman, netaddress/BIP155, socks5, torcontrol, minisketch/txreconciliation, eviction *and* the whole tx-relay half. Dim 1 backfills some of it; **tx-relay/txrequest/1p1c is in the gap between them.** |
| **storage-indexes** (4) | ~8,412 (`src/storage/` + `src/kv/`) | ~4 | Produced the round's best S1, so yield-per-line is fine *where it looked*. 8 of 18 storage files plus all of `src/kv/datadir.lisp` and `fsync.lisp` unread; the 1400-line header-index format "only sampled." |
| **mining** (7) | ~1,342 | 7 | High yield, but **zero verdicts** — all seven sit in the unverified pile. |
| **script-interpreter** (12) | 7,234 (`src/coalton/`) | 8 | Read `script.lisp` + `interop.lisp` in full (5,967 lines, excellent) and none of the 970 lines underneath them; could not run anything, which it flagged as fatal for its own top finding. |

One structural observation worth carrying into GA11's design: `src/validation/block.lisp` was the **only** file with two independent readers (dims 6 and 10), and it produced 26 of 84 findings. Redundancy paid. Twelve disjoint dimensions guarantee twelve seams.

---

## 4. What this method structurally cannot see

Reading two trees side by side compares **definitions**. It cannot compare **executions**. Nine defect classes are therefore invisible by construction, not by budget:

**1. Concurrency: races, lock ordering, shared mutable state.** 97 lock sites across 15 files, 12 `make-thread` sites across 8 files. Core encodes this contract in the *type system* — `GUARDED_BY`, `EXCLUSIVE_LOCKS_REQUIRED`, `AssertLockHeld` — so a static reader of C++ sees the invariant on the line. A static reader of our Lisp sees nothing, and **both files that document our discipline (`src/node/state.lisp`, `src/rpc/accessors.lisp`) were never opened.** GA10 stumbled into exactly one instance (`*last-checksig-error*` / `*last-checkmultisig-error*` are process globals clobbered by parallel script workers) and it is unverified. *Most exposed:* the recursive `node-lock` under concurrent RPC handler threads + sync thread + inbound listener + parallel script-check pool + wallet hooks; `src/mempool/mempool.lisp`; addrman; per-peer send/receive queues; `src/util/ratelimit.lisp`'s unlocked-by-assumption buckets. *Tool:* a lock-order assertion pass plus a concurrency stress test (N RPC threads against a live sync), not another reader.

**2. Liveness: blocking I/O, deadlock, starvation, backpressure.** Our worst production bugs are all in this class and *none* was ever found by a gap analysis: `receive-bytes` blocking forever in `read-sequence` (a 24-byte header + silence froze the whole node — remote unauth DoS); `SEND-BYTES NEVER BLOCKS` (unbounded send-queue growth, root cause of a 1-in-3 cold-battery flake); the `select()` fd>1023 type-error that killed every mainnet peer. Each one reads perfectly on the page. GA10's unverified "a backed-up send buffer makes us DROP outbound messages" is the same family and needs a run to settle. *Tool:* an adversarial peer harness (slow-loris, half-open, dead-air, flood) and a long soak.

**3. Algorithmic complexity and resource growth.** Reading tells you what Core does, never how long ours takes. History: block *deserialization* was the IBD bottleneck (not signature verification, which is where everyone looked); an 83MB mempool.dat turned restart into a 45-minute silent outage; header-index write amplification; 25 functional-test "timeouts" that were one shared *slowness*, not a hang. *Most exposed:* `src/mempool/txgraph.lisp` + `cluster-linearize.lisp` (unread, and linearization is where superlinear blowups live), `src/storage/chain.lisp`, `src/networking/ibd.lisp`. *Tool:* profiling + a bounded-time assertion in the cold battery.

**4. Round-trip and boundary-value divergence.** Core ships **138 fuzz harnesses**; we have `tests/fuzz-property-tests.lisp` (283 lines, 12 properties, explicitly *not* libFuzzer — no coverage guidance, no sanitizer, no corpus minimization). Every finding of this shape GA10 produced by *reading* is unverified: the BIP144 all-empty-witness acceptance, the lax-DER divergence "in both directions," the unbounded `base58-decode`, the coinbase wtxid reported as 32 zero bytes. *Most exposed:* `src/serialization/*` (esp. the never-read `message-macro.lisp` that generates them all), `src/util/bytes.lisp`, `src/crypto/address.lisp`, `src/serialization/psbt.lisp`, `src/rpc/descriptors.lisp`, `src/storage/blockfilter.lisp` (GCS). *Tool:* a differential harness — same bytes into ours and into Core's `bitcoin-tx`/`bitcoin-util`/a fuzz target, compare verdicts. This is the highest-leverage thing GA11 could build.

**5. The "correct code, no caller / wrong caller" class.** Our history names it **at least fourteen times** ("14th no-caller bug", "12th 'correct code, wrong callers'"; `build-tx-index` had no caller; txindex maintained only by startup catch-up; 5 of 6 activation sites never passed `:tx-index`; reorg only triggered by an arriving block; ms-satisfy never wired into the signer). Two-tree reading compares definitions; it does not compare *who calls them, how often, and with what arguments*. GA10 caught one only by accident (`HANDLE-MESSAGE`'s `block`/`headers` arms are dead because `DISPATCH-IBD-MESSAGE` intercepts first). *Tool:* a mechanical call-graph/reachability diff, or coverage instrumentation over the cold battery — anything reached zero times by 34k checks is a candidate.

**6. State-machine divergence that needs N transitions.** Both of this round's S1s are of this shape: the FRESH/DIRTY flag needs a `gettxoutsetinfo` **then** a spend **then** a re-lookup; the flat-file scan needs a prune **then** a restart. Reading can only *hypothesize* these; ten minutes of a real pruned node would settle both. Same family: the `*cached-is-ibd*` one-way latch, the prune watermark that stops reclaiming space, addrman table saturation past `ADDRMAN_RETRIES`, deep-reorg candidate parking. *Most exposed:* pruning, restart/crash recovery, reorg, addrman.

**7. Timing, cadence, and scheduling.** Poisson addr/tx broadcast timers, feeler cadence, ping timeouts, headers-sync timeouts, fee-estimator decay, the eviction rotation. Reading gives the constant; only a run gives the emergent behaviour. GA10's addr-relay finding ("no queue, no poisson timer") is the visible half; whether the resulting cadence leaks topology is not knowable statically.

**8. SBCL-specific numeric and type behaviour.** Bignum promotion where Core wraps; `(signed-byte 32)` vs `(unsigned-byte 32)`; whether a declared type check *signals* or is *elided* at the current safety setting. GA10's first unverified S1 is precisely this — and its finder wrote that he could not confirm the runtime symptom because Docker was down. Also in this family: `%script-num` missing the CScriptNum sign byte; `CastToBool` on multi-byte negative zero; `(null #())` being false; SBCL eliding `coerce`+`reverse`. *Tool:* one `dev.sh eval` per claim. Cheapest verification available and this round did zero of it.

**9. Crash consistency and environment.** fsync ordering, partial writes, disk-full, file permissions, the flush/prune/index-write interleaving. `src/kv/fsync.lisp` and `src/kv/datadir.lisp` were not read; `src/node/indexes.lisp`'s own header describes an abandoned-chain window after a process kill and nobody checked it. *Tool:* a `kill -9`-at-each-phase restart matrix.

**And the oracle we already own and did not use.** `scripts/conformance.sh`'s own header says Core's functional suite is "the class of defect a 33k-check unit suite structurally cannot see." Baseline: **38 PASS / 185 FAIL / 23 SKIP / 17 TIMEOUT of 240**. GA10 ran **not one** of them. Several GA10 findings cite Core functional tests as *evidence by reading* (`rpc_users.py:178-181`, `feature_config_args.py:395`) without ever running them — those are one command from CONFIRMED or REFUTED.

---

## 5. Concrete first tasks for GA11

Ordered so the cheapest confirmations come first.

1. **Settle the two S1s empirically before anything else** (~1 hour, Docker is up). Pruned-node restart for `%scan-flat-block-files`; `gettxoutsetinfo` → spend → re-lookup for the FRESH/DIRTY flag. Both are reproducible in minutes and both are on the default configuration.
2. **Run the ~15 findings that cite a Core functional test.** `scripts/conformance.sh rpc_users.py feature_config_args.py …` converts reading into verdicts for free.
3. **Run the refactor-regression dimension** (GA10's own item 1) — still never executed.
4. **Assign the five orphaned Core subsystems** as first-class dimensions: descriptors+signing (A), miniscript (B), cluster-mempool/txgraph (C), tx-relay/txrequest (D), wallet persistence + the 62 wallet RPCs (E/F).
5. **One dimension for the 42 never-opened files**, ordered by the risk table in §2 — `indexes.lisp`, `state.lisp`+`accessors.lisp`, `message-macro.lisp`, the four `coalton/` support files, `entropy.lisp`.
6. **Audit all 55 accept-and-drop options with the `-rpcwhitelist` lens.** For each: what does the operator believe, and what do we do? At least fifteen have no implementation at all. Mechanical, high yield, one afternoon.
7. **Add two execution lanes the method has never had:** (a) a differential encode/decode harness against Core's binaries for serialization/descriptors/PSBT/filters; (b) a concurrency + adversarial-peer stress lane. Without these, classes 1-4 above stay invisible in GA11 exactly as they were in GA1-GA10.
8. **Design fix:** overlap dimensions deliberately. `validation/block.lisp` was the only double-read file and produced 31% of all findings. Assign each file two readers with different lenses, and require every "NOT covered" clause to name the dimension that inherits it — this round's two S1s both sat in a seam that *two* finders explicitly declined in writing.
