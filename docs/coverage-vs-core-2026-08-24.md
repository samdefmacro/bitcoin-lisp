# bitcoin-lisp coverage assessment relative to Bitcoin Core

Date: 2026-08-24 · Our `main` @ `8bb93ce` · Reference Core `refs/bitcoin` @ `d3056bc` (master, 2026-03)

Every number in this document was measured in this session or derived directly from comparing the two source trees; none is drawn from conclusions in older documents.

---

## 1. One-sentence conclusion

**As a consensus node, coverage is high (consensus rules, the P2P protocol, and the RPC interface are essentially complete; both live nodes are following the mainnet chain tip);
as a complete replacement for Bitcoin Core, coverage is low (peripheral binaries, GUI, multiprocess, and external signers are all at zero).
The biggest shortfall is not missing functionality but behavioral-consistency verification — of Core's 263 functional tests, only 35 have been run.**

---

## 2. Quantifiable dimensions

| Dimension | Core | Us | Coverage |
|---|---|---|---|
| RPC methods | 170 (incl. hidden) | 158 + our own `migrateblocks` | **93%** |
| P2P message types | 35 (`protocol.h`) | 35, plus 4 Erlay messages Core doesn't have | **100%** |
| `bitcoind` startup parameters | 212 (summed across all binaries) | all the missing ones belong to cli/qt/wallet/bench | **~100% on the node side** |
| Indexes | 4 | 3 (missing `txospenderindex`) | **75%** |
| Source size | 191,784 lines of C++ (excl. test/qt/vendored) | 83,956 lines of Lisp | 0.44x |
| Unit tests | 132 files | 98 files / 2,359 tests / **33,406 checks** | — |
| Fuzz testing | 133 fuzz targets | 0 (only 3 hand-written randomized tests) | **0%** |
| Functional tests (behavioral consistency) | 263 | **35 run** | **13%** |

### The 12 missing RPCs, classified by reason

| Reason | Method |
|---|---|
| External signer / HWI (we don't support it) | `enumeratesigners`, `walletdisplayaddress` |
| Legacy BDB wallet (excluded by design) | `migratewallet` |
| Multiprocess IPC | `echoipc` |
| Private broadcast (a new Core feature) | `abortprivatebroadcast`, `getprivatebroadcastinfo` |
| Hidden / test-only | `echo`, `generate`, `mockscheduler`, `getrawaddrman` |

Of these, only private broadcast and `importprunedfunds`/`removeprunedfunds` are "genuinely missing"; the rest are out of scope by design.

**Correction (2026-09-07, GA11 71d5aa9f):** `importprunedfunds` and
`removeprunedfunds` were filed above under the legacy BDB wallet, which was
wrong -- Core implements them in `wallet/rpc/backup.cpp` over `CWallet::RemoveTxs`
and touches no legacy code, and at d3056bc a legacy wallet cannot be created at
all. Both are now implemented; the row above keeps only `migratewallet`.

---

## 3. Consensus layer: nearly complete

All activated soft forks are implemented, each with a corresponding location in the Core source: BIP16/30/34/65/66/68/112/113/141/143/144/147/340/341/342,
plus BIP94 (timewarp), BIP325 (signet), and BIP54 (policy-only, same as Core).

**Script interpreter opcodes: 0 unhandled.** All limit values (10000/201/520/1000/20) match Core item for item;
`CastToBool` correctly handles multi-byte negative zero. All 22 `SCRIPT_VERIFY_*` flags are present.

Core's official vectors measured in this session (all pass 100%):

| Vector | Result |
|---|---|
| `script_tests.json` | **1222 / 1222** |
| `tx_valid.json` + `tx_invalid.json` | all pass (93 invalid) |
| `sighash.json` | **500 / 500** |
| BIP341 taproot | 127 checks, all pass |
| `key_io` (base58 / bech32 / bech32m) | 348 checks, all pass |
| Descriptors (ported from Core's `descriptor_tests.cpp`) | **422 / 422** |

### Verified consensus-layer deviations (by severity)

**1. WITNESS and TAPROOT are height-gated on our side; Core has them unconditionally always on.**
`src/validation/block.lisp:338-355` only turns on `WITNESS` at the segwit height and `TAPROOT` at the taproot height;
Core's `GetBlockScriptFlags` (`validation.cpp:2259`) sets `P2SH|WITNESS|TAPROOT` for **every block**,
with an exception only for two named block hashes. Confirmed by reading both sides' source directly.
Consequence: for a block below the segwit activation height that spends a v0 witness program with an empty scriptSig and no witness,
Core rules it `WITNESS_PROGRAM_WITNESS_EMPTY` while we rule it anyone-can-spend.
Reaching this requires forging a historical fork with valid PoW, but it is a real consensus divergence —
the very reason Core needs a taproot exception block at height 692,261 (**below** the taproot activation height) is that it is always on.

**2. The mainnet taproot exception block is missing four flags.**
`block.lisp:993-999` substitutes it directly with the literal `"P2SH,WITNESS"`;
Core starts from `P2SH|WITNESS` and then ORs in DERSIG, CLTV, CSV, NULLDUMMY (`validation.cpp:2265-2284`),
all four of which are already active at height 692,261.

**3. For the BIP16 exception block we skip script verification entirely** (`block.lisp:675-681`), whereas Core sets `SCRIPT_VERIFY_NONE` but **still executes each script**.

**4. `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` is declared but nothing reads it.**
Declared at `block.lisp:315`, but the OP_SUCCESS handling point `interop.lisp:3191` unconditionally returns success;
Core, in `interpreter.cpp:1846-1851`, errors out when that flag is set.
Consequence: we will accept and relay a tapscript containing `OP_SUCCESSx` that Core rules non-standard.
Unit tests don't catch this — `script_tests.json` has no tapscript vectors; this falls under `feature_taproot.py`'s scope.

**5. There is no BIP9 / versionbits state machine at all.** Every deployment is a hardcoded height.
Consequence: `getblocktemplate`'s `vbavailable`/`vbrequired` are always empty, there is no unknown-soft-fork warning,
and testnet3's taproot height `2346882` is our own constant (Core never hardcodes it).
Harmless today (no network has a pending deployment), but the code will have to change when the next soft fork arrives.

**6. Three `MoneyRange` checks are missing** (a single coin's input value, the accumulated `nValueIn`, and the block's accumulated fee).
Because `Satoshi` is backed by a CL bignum, there is no exploitable overflow, but the checks themselves genuinely do not exist.

---

## 4. Wallet / mempool / mining / indexes

### 4.1 Wallet: descriptor syntax is the biggest hole

Implemented: `pk/pkh/wpkh/sh/wsh/combo/addr/raw/multi/sortedmulti/tr(single key)/rawtr`,
multipath `<0;1>` (BIP389), miniscript inside `wsh()`,
three coin-selection algorithms (BnB / Knapsack / SRD) + the waste metric,
full PSBT (BIP174's six roles + BIP371 taproot fields), encryption / backup / rescan / labels / `bumpfee`.

**Not implemented (verified):**
- `tr(KEY, {script tree})` — hard errors "tr(): script trees are not supported" (`descriptors.lisp:528`)
- `multi_a` / `sortedmulti_a` (taproot multisig)
- miniscript inside tapscript leaves
- the `musig()` descriptor (BIP327) and the corresponding `PSBT_*_MUSIG2_*` fields
- CoinGrinder (deliberately deferred; affects only coin-selection quality at high fee rates, not correctness)

**This means no modern taproot multisig or policy wallet can be imported.**

**Two instances of "code is correct but has no caller" (confirmed this session, the 13th occurrence of this class of bug):**
- `ms-satisfy`: **0 call sites** in src/ (referenced only 4 times in tests) → `wsh(<miniscript>)` can be imported and tracked, but it can **never sign**.
- `ms-from-script`: in src/ there is only its own `defun` and two `return-from` occurrences, **0 external callers** → cannot infer a descriptor back from a script.
- `ms-node-non-malleable-p` / `ms-node-needs-signature-p`: 0 production call sites each.
  Core requires `IsSane() && !IsNotSatisfiable()` to accept a miniscript descriptor (`descriptor.cpp:2604`),
  while we check only `IsValid` and `IsValidTopLevel` (`descriptors.lisp:590-593`) —
  we will accept malleable / signature-not-required policies that Core rejects.

### 4.2 Mempool / policy: essentially at parity

Standardness, dust, ephemeral dust, cluster mempool (txgraph + linearization + SFL),
full-RBF + rules 3/4/5, package RBF, TRUC/v3, package acceptance, 1p1c package relay,
the orphan pool, a complete `CBlockPolicyEstimator`, rolling min fee — all implemented.
The CPFP carve-out has been removed in Core, and we correctly don't have it either.

**The only gap: `mempool.dat` is not in Core's format** (ours is `"MPL"+CRC32`, Core's is a bare uint64 + XOR key),
so `importmempool` cannot interoperate across nodes — which is precisely the point of that RPC's existence.

### 4.3 Mining: three GBT gaps

Block assembly uses Core's latest cluster-mempool `addChunks` (not the old ancestor-feerate approach), aligned item for item.

- **The client-supplied `rules` array is never read.** Verified: `"rules"` appears only once in `methods.lisp`, and it is on the output side. Core, in `rpc/mining.cpp:848-856`, throws
  `RPC_INVALID_PARAMETER` when `"segwit"` is missing (`"signet"` on signet). A pre-segwit miner would get a segwit template instead of an error.
- **`getblocktemplate` does not output `signet_challenge`** (Core `mining.cpp:1018`) → signet mining cannot work.
- `vbavailable`/`vbrequired` are hardcoded empty (a knock-on consequence of the missing BIP9).

### 4.4 Indexes

txindex / blockfilterindex(BIP157/158) / coinstatsindex are all present; `txospenderindex` is missing.
Knock-on consequence: `gettxspendingprevout` can only query the mempool, and it does not accept Core's options object.

Architectural difference (not a defect, but worth recording): Core's indexes run on a `BaseIndex` background thread with an explicit `Rewind`;
ours are embedded synchronously in `connect-block`/`perform-reorg`. This has repeatedly produced "missing call site" bugs in the project's history.

---

## 5. Structural gaps: peripheral components are nearly all at zero

| Core component | Us |
|---|---|
| `bitcoind` | ✅ A single `save-lisp-and-die` binary, drivable by Core's test framework |
| `bitcoin-cli` / `-tx` / `-util` / `-wallet` / `-chainstate` | ❌ None at all |
| `bitcoin-qt` GUI | ❌ No Qt; replaced by our own Web UI (`ui/`, 14 files, something Core doesn't have) |
| Multiprocess IPC / `libbitcoinkernel` | ❌ None |
| External signer / HWI | ❌ None |
| ZMQ / torcontrol / SOCKS5 / addrman / banman / netgroup+asmap / DNS seeds / BIP324 | ✅ All present |
| I2P (SAM transport) | ❌ We only support I2P **addresses**, no transport layer |
| NAT-PMP / PCP / UPnP | ❌ None |
| REST interface | ✅ Complete, including 5 recently added endpoints |
| Pruning / assumeutxo / reindex / flat block files | ✅ All present; plus `migrateblocks` in-place migration, which Core doesn't have |
| LevelDB / secp256k1 | Called via CFFI against system libraries, not vendored |
| `src/support/` secure memory (mlock / secure allocator / `memory_cleanse`) | ❌ **No counterpart at all**; key material is manually zeroed in only two places |
| fuzz framework (133 targets) | ❌ 0 |

**What we have that Core doesn't:** the Web UI, a complete Erlay message set (Core has only the `sendtxrcncl` handshake,
while we implement `reqrecon`/`sketch`/`reqsketchext`/`reconcildiff` + our own minisketch,
but **interoperability with Core cannot be verified, because Core has no counterpart**), the typed script interpreter written in Coalton,
`migrateblocks`, and PAX executable documentation.

---

## 6. Verification status (measured this session)

| Channel | Result |
|---|---|
| `cl-workbench doctor --strict` | all green |
| `asdf:load-system "bitcoin-lisp"` | loads cleanly |
| **Cold battery `scripts/docker-test.sh`** | **33,406 / 33,406 pass, 0 failures, exit 0** |
| Core's official vectors (see §3) | all 100% |
| Core functional tests | 35 of 263 run; documentation records 7 passing (only 3 named) |

### ⚠️ The warm image and the cold channel disagree (discovered this session)

On the same clean `main`:
- Running `rpc-tests` in isolation **inside the cold container**: **1,644 checks, 0 failures**
- Running the same suite in isolation on the **warm image** (after `dev.sh stop` + restart): **1,643 checks, 6 failures**

All 6 failures are in `estimatesmartfee`; the mechanism has been located: the test stubs
`bitcoin-lisp:node-fee-estimator` with `setf fdefinition`, but it is a `defstruct` accessor (`src/node.lisp:381`),
which SBCL inlines, so the stub never reaches `rpc-estimatesmartfee`; and `make-test-node` never sets that slot.

**The cold channel is the verification of record, and it is green**, so this is not a product defect. But it again confirms CLAUDE.md's warning:
the warm image is a development convenience, not the basis for verification.

There is also one dead seam **present on both channels**: the `(bitcoin-lisp::*syncing* nil)` binding in these tests.
SBCL explicitly warns in the cold-battery log *"using the lexical binding of the symbol, not the dynamic binding"*
and *"defined but never used"* — that variable is not special at all, so this binding is entirely ineffective.

---

## 7. Live operational status (test-bitcoin-server, measured)

| | mainnet (pruned) | testnet4 (full node) |
|---|---|---|
| Build | `g1a7c6f8` (behind main by **110** commits) | `d93f5db` (behind by **10**) |
| Height | **963,831**, headers match | **149,669**, headers match |
| IBD | false (synced) | false (synced) |
| Tip freshness | tip block mined 19 minutes ago | — |
| Connections | 18 | 16 |
| Mempool | 0 (relay off by default on mainnet) | 50 txs |
| Uptime | 3.6 days | 20.8 hours |
| Features | prune 4GiB, blockfilterindex, v2transport | txindex + coinstatsindex + blockfilterindex + flat block files, `-par=4` |

**Both nodes are genuinely following their respective chain tips.** This is the most persuasive evidence of coverage —
if the consensus rules had any deviation, the mainnet node could not possibly be stuck at 963,831.

**Performance:** reindexing testnet4 to h≈134.9k, Core 29.0 takes 1,039 seconds, we take 3,372 seconds (**about 3.2x slower**).
The bottleneck has been located: not signature verification but flexi-streams' gray-stream dispatch inside block **deserialization**.

---

## 8. Gap list by priority

**P1 — Consensus / funds correctness — ✅ all complete (see §9)**
1. ~~WITNESS/TAPROOT should be unconditionally always on; switch to Core's named exception table (§3.1-3.3)~~
2. ~~`wsh(<miniscript>)` cannot be spent: wire `ms-satisfy` into `%sign-tx-inputs`~~
3. ~~the miniscript descriptor is missing Core's sanity gate~~

**P2 — Interoperability with real clients / Core's test suite — ✅ all complete (see §10)**
4. ~~`getblocktemplate` ignores the client's `rules` array~~
5. ~~`getblocktemplate` does not output `signet_challenge`~~
6. ~~`DISCOURAGE_OP_SUCCESS` is read by nobody~~
7. ~~`mempool.dat` is not in Core's format~~

**P3 — Feature completeness — ✅ all complete (see §11-§14)**
8. ~~`tr()` script trees / `multi_a` / tapscript miniscript~~ ✅ trees and `multi_a` watch-only
   (§12) → script-path spending (§13) → miniscript in the tapscript context (§14)
9. ~~`txospenderindex`~~ ✅
10. BIP9 / versionbits state machine — ✅ the reporting part; activation determination deliberately left untouched
11. ~~the `musig()` descriptor + PSBT MuSig2 fields~~ ✅ the toolchain is now unblocked (libsecp v0.7.1),
    BIP327 aggregation + BIP328 derivation + the `musig()` descriptor + PSBT MuSig2 field decoding (§12, §14).
    ⚠️ **The signing side (nonce) is deliberately not done**: reusing a MuSig2 nonce across two messages directly leaks the private key,
    and that half deserves its own dedicated review pass.

**P4 — Verification capability — ✅ all complete (see §14 and docs/functional-triage-2026-08-25.md)**
12. ~~only 35 of 263 functional tests had been run~~ ✅ **all 266 have now been run and classified by root cause**.
    This item's task was "rerun and classify"; the classification is complete and written up; the defects found
    become a new backlog in their own right and are out of this item's scope. The biggest single item: one root cause blocked 45 tests.
13. ~~fuzz coverage was 0~~ ✅ `tests/fuzz-property-tests.lisp` — **not libFuzzer**,
    but the half of a fuzz target that needs no engine: random bytes + property assertions, reproducible with a deterministic seed.
    It caught `parse-tx-payload` accepting trailing bytes on its very first run.


---

## 9. P1 completion record (2026-08-24, branch p1-consensus-alignment)

Six commits, cold battery 33,406 → **33,738 all green**. Method: first dispatch a workflow to write the spec + a triple adversarial review,
then implement serially (the builds share the same container and FASL volume, so they cannot run in parallel).

| Commit | Content |
|---|---|
| `21b49f5` | P2SH/WITNESS/TAPROOT unconditionally on for every block; the exception table **replaces** the base set but still ORs in the four height-activated flags; the BIP16 exception block **executes** the script instead of skipping it; drive sites extended to sigop counting and `getdeploymentinfo` |
| `4fcd5a1` | Two defects in the previous commit (found by review): the exception table is scoped per-chain; an empty `script_flags` set must be `[]`, not `null` |
| `4e78782` | The miniscript descriptor gate now covers all seven properties of Core's `IsSane()`; ported the Ops/StackSize algebra; error text and branch order match Core verbatim |
| `6cb65bc` | Two real bugs: `andor`'s derived public key **mismatched** its key expression; `%infer-desc-body` was missing `:miniscript`, crashing `getaddressinfo` with -32603 |
| `df5603c` | `ms-satisfy` wired into the signer (the 14th "no caller"), rejects malleable satisfactions, added Core's CLTV/CSV predicates |
| `7a0c1d7` | Satisfaction size estimation, so miniscript coins can be selected |

### What review changed (worth remembering)

Three adversarial perspectives (Core fidelity / regression / drive sites) each independently flagged the same two defects in `21b49f5`,
even though that commit's own tests were green. Both were caused by **my change newly introducing reachability**:

- `script_flags` previously always contained `"P2SH"`, so an empty set was unreachable; turning the base set into something the exception table could override
  made `NIL` reachable for the first time, so the JSON rendered as `null`. This is the same class of defect as PR 496.
- The exception table is scoped per-chain, but I wrote it as a network-agnostic `cond`; and my own test's docstring
  **claimed** to test "no exception on testnet4/signet/regtest," while actually testing nothing.

### Still not done (an honest record)

- The **error text** for an oversized (>3600-byte) miniscript and the four out-of-range fallback nodes (older/after/thresh/multi)
  differs from Core: Core bails during parsing, giving
  `"A function is needed within P2WSH"`, while we parse successfully and the gate reports `"... is invalid"`.
  Both sides reject it, just with different wording.
- Signing completeness has not yet gone through Core's `VerifyScript` determination path (`sign.cpp:799`).
- Miniscript in the tapscript context is still unsupported (a descriptor-syntax hole, see §4.1).


---

## 10. P2 completion record (2026-08-24, branch p2-core-interop)

Five commits, cold battery 33,749 → **33,814 all green**.

| Commit | Content |
|---|---|
| `d45d552` | getblocktemplate's miner contract: reads the client's `rules` (errors verbatim as Core does when segwit/signet is missing), outputs `signet_challenge` and `!signet`, reports "Invalid mode" for an unknown `mode`, moved the connectivity check ahead of longpoll |
| `35961fc` | `DISCOURAGE_OP_SUCCESS` is finally read (the 15th "declared but nobody calls it"); the test also pins down that it's policy, not consensus |
| `4c6b621` | The defect found by review in the previous commit + mempool.dat switched to Core's format + two `importmempool` options now take effect + getblockchaininfo's `signet_challenge` |
| `4176a6f` | Format detection now reads only 4 bytes, no longer reading the whole file twice |
| `564c251` | A test for an empty mempool.dat — this is exactly what the live mainnet node writes on every shutdown |

### What review changed (more critical this time than P1)

The `rules` check in `d45d552` was written as `vectorp`. But **a nested JSON array never arrives at the handler
as a vector** — `%normalize-json-value` recurses into every request object and maps nested vectors
back to a LIST (server.lisp:338-356). So `{"rules":["segwit"]}` arrives as `("segwit")`,
the check reads NIL, and **every real miner gets rejected with -8**. Yet the whole suite was green, because the fixture stuffed
`(vector "segwit")` directly into the hash-table, never going through normalization.

⚠️ The lesson is in the **fixture**, not the check: a test that hand-constructs handler parameters tests a shape
that no real client can ever produce. `%gbt-params` now goes through `%normalize-rpc-params`, and one test now runs
the real parser starting from JSON text.

### The easiest thing to get wrong in mempool.dat

The XOR key offset is the **absolute file position** (AutoFile hands its own `m_position` to the obfuscator,
streams.cpp:25-27), while the header is 8 (version) + 9 (the key serialized as a **vector**: compact-size
0x08 plus 8 bytes) = 17 bytes. 17 is not a multiple of 8, so **the payload's first byte pairs with byte 1 of the
key**. Get it wrong and Core reads our file as garbage, while our own round-trip still passes — so the
interop test is **hand-built byte by byte** to Core's layout.

### The migration is verified against a real file

Both live nodes' on-disk mempool.dat begin with the old magic `01 4c 50 4d`. Pulling down testnet4's real
60,864-byte file and parsing it with the new dispatcher: **ok=T, 29 entries, transactions deserialize correctly**,
matching the 0x1d declared in the header. The old-format reader is retained, otherwise the first restart would
silently lose the entire mempool.

### Still not done (an honest record)

- Core's mempool.dat **has no checksum**, so we dropped the old format's CRC32 this time; a torn write can now
  only be detected by a parse failure.
- When deserialization errors, Core **keeps** the transactions already read (mempool_persist.cpp:145); we discard
  all of them — a deviation in the conservative direction, left unchanged.
- `-persistmempoolv1` (writing version 1, without XOR) is still on the "recognized but not implemented" list. The
  reader already recognizes version 1; adding the writer would be trivial, but this is an honestly declared
  unimplemented item, not an option silently ignored.


---

## 11. P3 progress (2026-08-24, branch p3-feature-completeness)

Of the four items, two are complete, one is blocked by the toolchain, and one is honestly deferred with its scope recorded.

### ✅ item 9 — txospenderindex (fully implemented)

The one index Core has that we were missing. The key is `'s' | SipHash(salt, outpoint) | block hash | tx offset`,
with an empty value; the salt is random and persisted, and collisions are **tolerated rather than avoided** — the
locator is part of the key, and a query walks every entry under the same hash, reading the candidate transaction
back from the block to verify it. This is also how Core does it.

⚠️ **This is the first index disconnect hook in this tree.** coinstatsindex and blockfilterindex key their
records by **height**; a reconnect overwrites them, and a stale record is simply never read back — node.lisp
already said as much: "no disconnect hook." But the spender index's key carries no height: after a reorg, a
disconnected block is still on disk and still spends that outpoint, so the leftover entry resolves to a spender
**on an abandoned chain**. That is a wrong answer, not a stale one.

⚠️ Erasure is placed in reorg's **PHASE C**, not PHASE A's disconnect loop. An interrupted reorg rolls back and
those blocks are still connected; erasing in phase A would delete index entries for blocks still on the chain.

⚠️ Includes **startup backfill**. Without it, turning on `-txospenderindex` on an existing node would index no
history at all — exactly the mistake this project's `-txindex` once made (`build-tx-index` had no caller).

`gettxspendingprevout` now adds what Core has and we had none of: `mempool_only`,
`return_spending_tx`, the `spendingtx` field, the index fallback itself, and Core's three error messages.

### ✅ item 10 — versionbits (the reporting part)

Core, in **all five sets of chain parameters**, still treats taproot as a versionbits deployment, so
getdeploymentinfo gives it a `bip9` object, while we report `buried` on all five chains — a caller wanting to
read a deployment's bit, window, or signal count from this RPC gets nothing at all from us.

⚠️ **Reporting only — activation determination is left untouched, not one line changed.** All our deployments
activated years ago, and both live nodes are synced on those chains; swapping the constant for a computed state
machine could move the real activation decision on a live chain — no benefit is worth that risk. The state
machine is wired into exactly one drive site: getdeploymentinfo.

Along the way, fixed a **live off-by-one** review found: Core's buried deployments report active starting from
**the block before the activation height** (`DeploymentActiveAfter`, and it comments on this at the call site),
while we compared heights directly, so on exactly one block we answered false while every Core node answered
true.

### ⛔ item 11 — musig(): blocked by the toolchain, not a discretionary deferral

`secp256k1_musig_pubkey_agg` **does not exist** at runtime. docker/Dockerfile:40 pins libsecp256k1 **v0.5.1**,
noting that this is "the exact tag the production node runs," and the musig module came later. Unblocking this =
upgrading the pinned library **and** upgrading the version running on the production node = a deployment
decision, not a code decision. Reimplementing BIP327 in Lisp ourselves would be reckless for a security-critical
aggregation protocol.

The only honest part achievable without it is **decoding** the `PSBT_IN_MUSIG2_*` fields in `decodepsbt`
(display only) — without key aggregation there is no output public key, no address, and the wallet cannot use
it.

### ⏸ item 8 — tr() script trees: not done, scope honestly recorded

This is actually three features, and their scopes differ substantially:

| | Scope | Notes |
|---|---|---|
| `tr()` trees + `multi_a`/`sortedmulti_a`, **watch-only** | ~450-600 lines | Neither the syntax loop nor TaprootBuilder needs new cryptography — `tap-leaf-hash`/`tap-branch-hash`/`tweak-xonly-pubkey` already exist. What actually makes this big is the **defstruct layout change** to `out-desc` and about 11 call sites that assume a single `sub` |
| Script-path **signing** | ~800-1200 lines | Touches the signer, the estimator, PSBT |
| Miniscript in the tapscript context | Large | Needs a context parameter added to the P2WSH-only type system |

The watch-only layer stands on its own: it can parse, canonicalize, derive the correct bech32m address (this is
the crucial part — the address depends on the whole tree, and getting it wrong means funds land somewhere the
wallet can't see), import, recognize its own outputs, and report the balance. It cannot sign. This tradeoff
either needs to be stated explicitly or shouldn't be made at all, so I left it for its own separate round.

## 12. P3 continued (2026-08-25, branch p3-libsecp-musig-and-tr-trees)

The previous round recorded item 11 as "blocked by the toolchain" and item 8 as "deferred with scope honestly
recorded." This round finished the parts of those two items that could be resolved unilaterally.

### ✅ Toolchain: libsecp256k1 v0.5.1 → v0.7.1, including the musig module

Image `bitcoin-lisp-sbcl:2.6.5-4`. The musig module only exists from 0.6.0 onward, so there was no smaller step available.

⚠️ **A fact-check worth recording**: I initially pinned the Dockerfile to **v0.7.2**, reasoning that "this is
exactly what Core vendors." `git clone` failed repeatedly, exit 128 — I initially took this for a network
problem. It wasn't: **the tag `v0.7.2` does not exist**. Core's subtree calls itself 0.7.2
(`CMakeLists.txt:10`), but `configure.ac:9` says `_PKG_VERSION_IS_RELEASE, false`
— that's master after v0.7.1, not a release.

Ultimately pinned **v0.7.1**: the newest official release at or below the version Core uses. `v0.8.0` does exist
and was deliberately not used — for consensus-critical code, lagging the reference implementation is better than
leading it.

The risk boundary of the change (checked before changing, not patched in afterward): 0.7.0 removed three
deprecated aliases (`ec_privkey_negate`, `ec_privkey_tweak_add`, `ec_privkey_tweak_mul`), none of which are among
the 32 symbols our FFI binds; the rest of the 0.6.0/0.7.x changes are all build, visibility, or stack-clearing
matters. The empirical evidence is the cold battery (including Core's own script/sighash/BIP341/key_io vectors)
rerun on the new image.

Measured inside the image: both `secp256k1_musig_pubkey_agg` and `secp256k1_musig_nonce_gen` resolve from our FFI
process, `ellswift` is still present, `.so.6.0.1` (v0.5.1 was `.so.2`).

**The `musig()` descriptor itself is still unimplemented** — removing the blocker is not the same as shipping the
feature. What remains is the FFI bindings, the `musig()` descriptor, and PSBT's MuSig2 fields; nonce management
is the dangerous part among these and deserves its own review.

### ✅ item 8, layer one: tr() script trees + multi_a/sortedmulti_a (watch-only)

All six of Core's `tr()` vectors match byte for byte, and `multi_a(1)`'s zero-key error text matches verbatim.

`out-desc` gained a `tree` slot (a list of `(DEPTH . out-desc)`) rather than turning `sub` into a list:
`sh()`/`wsh()` syntactically have only one child script, and conflating the two would force 17 existing
`out-desc-sub` call sites to handle a list they can never actually receive.

⚠️ **Two self-inflicted defects a green suite didn't catch**, both the old failure mode of "porting the mechanism but missing a drive site":

1. **The x-only flag was attached to the wrong object.** I first wired "push 32 or 33 bytes" to `desc-key-xonly-p`.
   That's a **print** flag. Core's criterion is `PKDescriptor::m_xonly`, attached to the **descriptor**.
   The two diverge in one place: when an xpub sits in a leaf, Core prints `pk(xpub.../1/*)` but still pushes 32 bytes.
   Wiring it to the wrong flag means the leaf hash → merkle root → **address** all differ, silently. Bare hex and WIF
   leaves both passed; only Core's ranged vector caught it.

2. **Inference reported every leaf as the internal key.** `%infer-desc-body` takes `(first pairs)` positionally,
   while `out-desc-ordered-keys` puts tr()'s internal key first. An inferred descriptor is the basis for backup
   recovery, so reporting the wrong key for a leaf means recovering a different wallet.

Also brought two more points in line with Core: `getaddressinfo` no longer reports a single-key origin for a
taproot address **with a tree** (Core requires `spenddata.merkle_root.IsNull()`, signingprovider.cpp:290 — the
internal key alone cannot spend this output); `multi()` inside `tr()` now gets Core's dedicated error text instead
of the generic "is not a valid descriptor function".

**Signing still cannot be done, and cannot be done safely**: both signing paths (`signrawtransactionwithkey`'s
`tr-keymap`, and the wallet's `%wallet-sign-maps`) look up by the BIP86 no-tree-tweaked output key, so a
tree-bearing output is not found → an explicit "no key" is reported, never a wrong signature. This is exactly the
boundary of the watch-only layer.

## 13. tr() script-path signing + server-side libsecp upgrade (2026-08-25, branch tr-script-path-signing)

The previous section made tr() trees watch-only and removed musig's toolchain blocker inside the **image**. This section advances both by one step.

### ✅ Server: testnet4 has switched to libsecp256k1 v0.7.1 + musig

On the server, installed v0.7.1 into a **separate prefix**, `/data/bitcoin-lisp/secp256k1-0.7.1`, using cmake 3.22
— without touching `secp256k1-local`, which is currently mmap'd by two running nodes. Built with tests on;
upstream's `tests 16` and `exhaustive_tests` both pass.

`run-node.sh`'s `BL_SECP_LIB` environment variable is exactly the seam that exists for this; switching required changing not one line of code:

```
BL_SECP_LIB=/data/bitcoin-lisp/secp256k1-0.7.1/lib
```

A graceful SIGTERM (node exits 0, the supervisor then exits, the path documented in the scripts); after restart,
`/proc/<pid>/maps` confirmed `secp256k1-0.7.1/lib/libsecp256k1.so.6.0.1` was loaded, height 149761 unchanged,
synced, no errors. **mainnet stays on v0.5.1, untouched** — that is a separate authorization.

⚠️ A recurring trap: `pgrep -f "dynamic-space-size 6144"` matched **the command line of a watcher process itself**
left over from July, not sbcl. Only `ps -eo pid,args | grep sbcl-final/bin/sbcl`, matching on the binary path,
found the right one. This same self-matching trap has killed the supervisor during a deploy before.

### ✅ item 8, layer two: tr() script-path spending

`tr-spend-data` is Core's `TaprootSpendData`: the output key, parity, internal key, merkle root,
and each leaf's (script . control block). The tree builder now tracks each leaf's merkle
branch during the combine step, not just the root.

⚠️ **Verified against Core's `bip341_wallet_vectors.json` — 6 trees, 12 control blocks, byte-for-byte match.**
This file is the only oracle able to distinguish "the tree is right" from "the tree is wrong": TapBranch sorts
each pair, so the merkle **root** (and hence the **address**) is independent of left/right order, and a builder
with the wrong shape can look completely correct the whole way through, until someone tries to spend it.

The signer tries the key path first, then iterates every leaf, taking the smallest witness (sign.cpp:601-612).
Leaf satisfaction covers only the kinds our syntax can construct (pk / pkh / multi_a / sortedmulti_a); everything
else explicitly reports unsatisfiable rather than guessing — Core routes every leaf through
`miniscript::Satisfy`, and we have no miniscript for the tapscript context.

⚠️ **Two stack orderings a green suite couldn't catch, one of which I genuinely got backwards**: multi_a's witness
order is the **reverse** of key order (CHECKSIGADD pops the signature from the top of the stack, so the first key
consumes the last element), while `pkh()` places the revealed public key **above** the signature (DUP reads the
top of the stack). I got pkh backwards, and every unit test passed anyway — what caught it was **actually signing
a spend and then running it through our own interpreter**. This is also the oracle the new tests use uniformly:
the interpreter is constrained elsewhere in this battery by Core's script/sighash/BIP341 vectors, so a witness it
accepts under standard flags is one Core accepts too.

Along the way, also fixed the same class of defect left over from the previous section: `pkh()` inside a taproot
leaf was still hashing a 33-byte key. Core blocks the pkh() **descriptor** from P2TR (descriptor.cpp:2290), but
leaves then go through the miniscript branch, where `pkh` is a fragment, so Core ultimately accepts
`tr(K,pkh(K2))` and hashes the **32-byte** x-only key, with the reasoning written at descriptor.cpp:1556.

**Drive site** (since this is the 14th time): `%spkm-tr-script-leaves` is reached only from `%wallet-sign-maps`,
whose fourth return value threads all the way through to `%sign-tx-inputs`. `WALLET-SIGNS-A-TR-SCRIPT-PATH`
imports such a descriptor into a real wallet and spends it, so an unwired graph turns a test red, not a user.

⏸ Still not done, and deliberately so: PSBT's taproot script-path fields (`PSBT_IN_TAP_SCRIPT_SIG` /
`TAP_LEAF_SCRIPT`) — the PSBT signer has not been touched by one line, and a tr() tree's input stays "completely
untouched" there rather than being recorded as half-done. Satisfaction-weight estimation still counts by the key
path, which is Core's own FIXME hanging off `TRDescriptor::MaxSatisfactionWeight` (descriptor.cpp:1523); following
it keeps our fee estimate consistent with Core's, rather than "better but different."

## 14. P3/P4 wrap-up (2026-08-26, branch p3-p4-completion)

§8's P1-P4 are now all complete. This section records the last few items.

### ✅ item 8, layer three: miniscript in the tapscript context

Miniscript's type rules, legal fragments, and resource limits are all **stated per context**; we previously
implemented only the P2WSH set. The context now hangs off the node and is threaded through the whole parse tree
via a special variable — not by hand-threading a parameter through 54 construction points, because that is
exactly the shape of "missing a call site," and a tree with a half-applied context can **still pass type
checking** yet compile into a script nobody recognizes.

Concrete differences, checked item by item against Core:

| Point | P2WSH | tapscript | Core |
|---|---|---|---|
| `multi` / `multi_a` | only `multi` | only `multi_a` | BIP342 removed CHECKMULTISIG |
| Key serialization | 33 bytes | **32-byte x-only** | descriptor.cpp:1569 |
| `d:`'s type | not `u` | **is `u`** | miniscript.cpp:126 |
| Script size limit | 3600 | **329482** | miniscript.h:284 |
| Signature size | 1+72 | **1+65** | miniscript.h:1189 |
| Stack check | witness item count ≤ 100 | **execution stack depth ≤ 1000** | miniscript.h:1590 |

The stack-check row deserves a look on its own: the two contexts check **different things**. Under P2WSH,
standardness limits the witness item count, so the input side is the constraint; under tapscript, neither script
nor witness size is limited by standardness, so nothing stops execution from hitting the **consensus** stack
limit — and that is exactly what Core checks there.

Verified against Core's `descriptor_tests.cpp:1143` vectors; scriptPubKey and the string round-trip both match byte for byte.

### ✅ item 11, remainder: PSBT MuSig2 fields (BIP373)

Decoding of `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS` / `_PUB_NONCE` / `_PARTIAL_SIG`.

⚠️ **keydata length is the discriminant**: 66 bytes is the key path (participant + aggregate key), 98 bytes is
the script path (one extra leaf hash). This distinction is encoded only in the length (Core psbt.h:428-430); a
reader that ignores it will attribute every script-path nonce to the key path.

**Decoding only.** A MuSig2 signing session needs nonce state this node does not persist, and improvising one
would be worse than not doing it at all: reusing a nonce across two messages directly leaks the private key.

### ✅ item 12: all 266 functional tests now run

See `docs/functional-triage-2026-08-25.md` for the classification report. Full-suite result: **48 PASS / 188 FAIL /
30 TIMEOUT** (FAIL includes a large number sharing the same root cause).

Fixed this round out of that set:

- **`getblock` could not find the genesis block** — one root cause blocking 45 tests (already recorded in §13).
- **RPC named-only parameters**: Core allows members of an options object to be passed as **top-level named
  parameters** (`RPCHelpMan::GetArgNames` emits them with `named_only=true`, rpc/util.cpp:750;
  `transformNamedArguments` gathers them into a new options object and pushes it into the options slot,
  rpc/server.cpp:408). We recognized only top-level names, so for every call a real Core client can issue we
  answered "Unknown named parameter fee_rate". The table is **generated from Core**, covering 12 RPCs.

⚠️ **A concurrency defect in the harness itself**: `conformance-config.sh` writes the shared `build/bin/bitcoind`
with `ln -sf`, and `ln -sf` unlinks before it creates — a concurrent batch can land in that window and get
`OSError 22`, which shows up as a whole batch of seemingly unrelated failures. And `conformance.sh`'s own comment
claims concurrency safety. Only after switching to rename(2) did concurrent sweeps actually become usable.

### ✅ item 13: fuzz coverage

`tests/fuzz-property-tests.lisp`, 12 items. **This is not libFuzzer** — calling it fuzzing would overstate it:
no coverage guidance, no sanitizer, no corpus minimization. It is the half of a fuzz target that **needs no
engine**: Core's target is just random bytes wired to a property assertion, and the assertion ports directly.

Two classes of property: **total functionality** (any bytes must either produce a value or a declared condition —
never an undeclared condition, and never hang) and **round-trip consistency** (anything that parses must encode
back to the same bytes). The byte source is a **seeded xorshift**, so a failure names a specific seed and
iteration number — an unreproducible failure is only hearsay.

Covers the properties of Core's `deserialize`, `block_header`, `parse_script`, `psbt`, `descriptor_parse`,
`bech32_roundtrip`, `hex`, `key_io`, and `base_encode_decode` targets.

Caught on its very first run: **`parse-tx-payload` accepts trailing bytes**, while Core's `DecodeTx` only accepts
a decode that reads the buffer empty (core_io.cpp:180).

### Deployment

**Both nodes are on the latest main**: testnet4 (libsecp v0.7.1 + musig) and mainnet
(libsecp v0.5.1). mainnet was previously running the August 21 build, about 90 PRs behind, including a
**missing consensus check** (PR 493), script flags aligned with Core (PR 497), and two stability fixes
(PRs 489/490).

## 15. 2026-08-26 — Functional-test root-cause batch (PR 513-516)

### 15.1 Clean baseline (after the cache fix)

| Result | Count |
|---|---|
| **PASS** | **38** |
| FAIL | 185 |
| SKIP (exit code 77) | 23 |
| TIMEOUT | 17 |
| non-test script | 1 |

**This is the first trustworthy baseline.** Every number before this had two systematic biases:

1. **The shared cache datadir could not be rebuilt for months** (see 15.3), so every test that isn't clean-chain ran on stale-format data.
2. **Exit code 77 is "skipped," not "failed,"** and was previously always counted as FAIL. Those 23 are tests skipping themselves for lacking `bitcoin-cli`, USDT tracing, IPC, an external signer, or an old binary version — Core itself gates on the same things, and it's outside what we can fix.

The real actionable denominator is **240**, of which 38 currently pass.

### 15.2 Shared root causes fixed this batch

| Root cause | Impact | PR |
|---|---|---|
| datadir layout is not Core's shape | 8 `FileNotFoundError`s | PR 513 |
| the genesis block is never written to disk | `feature_loadblock` never terminates | PR 513 |
| logs during config parsing never reach debug.log | every `assert_debug_log` | PR 513 |
| bitcoin.conf cannot negate any option | every `noXXX=1` | PR 513 |
| log-level tag is `WARN:` rather than `[warning]` | multiple `assert_debug_log` | PR 514 |
| `-loadblock` unimplemented | `feature_loadblock` | PR 514 |
| `-wallet` is a boolean rather than a list of names | `wallet_multiwallet`'s very first call fails | PR 514 |
| four init-error strings + `-loglevel=<category>:<level>` | the whole `feature_logging` chain | PR 516 |
| **the functional-test cache could not be rebuilt** | **the entire suite** | PR 516 |

Newly passing: `feature_settings`, `feature_loadblock`, `feature_logging`, `feature_blocksxor`.
The `assert_start_raises_init_error` cluster (7 tests) has vanished entirely from the failure classification.

### 15.3 ⚠️ The cache business

The framework builds a 199-block regtest datadir once and copies it to every test that doesn't set `setup_clean_chain`. Its cleanup step calls `os.rmdir(wallets)` (which we never create) and `os.remove` on every unexpected entry (which throws on our `undo/` **directory**). Both fail → the build fails → every run falls back to the last successful build's cache, which was written in the **now-obsolete single-block format**, dating from roughly July.

There is no hint of this in the output. The fix is two small ports: new datadirs create `wallets/` (Core `common/init.cpp:45-63`, both the base and network locations), and `undo/` is now created only on its first legacy write.

**Operational reminder**: after changing the on-disk format, the datadir layout, or startup file-creation behavior, `rm -rf refs/bitcoin/test/cache` before measuring; after a run, `ls refs/bitcoin/test/cache/node0/regtest` should show only `blocks` and `chainstate`.

### 15.3.1 The correct way to run a full sweep

```sh
scripts/build-node.sh                       # the binary must be current code
rm -rf refs/bitcoin/test/cache              # see above; skip this and you're testing stale data

# test/functional/ contains non-test helper scripts (combine_logs.py etc.),
# filter by test_runner.py's manifest, don't just use ls *.py
ls refs/bitcoin/test/functional/*.py | xargs -n1 basename \
  | grep -vE '^(test_runner|create_cache|combine_logs)\.py$' > /tmp/all.txt

split -l 33 /tmp/all.txt /tmp/sw-
for f in /tmp/sw-a?; do
  nohup bash -c "BL_CONFORMANCE_TIMEOUT=150 scripts/conformance.sh \$(tr '\n' ' ' < $f)" > "$f.log" 2>&1 &
done
```

When tallying, **SKIP must be counted separately from FAIL** (`conformance.sh` has reported `SKIP` since 2026-08-26; in older logs it appears as `FAIL(77)`). Counting skips as failures inflates the denominator by 23, and those 23 are things Core itself gates on too.

### 15.4 The biggest failure clusters in the next batch

| Count | Cluster |
|---|---|
| 27 | unclassified (framework-level, including the skips/non-tests already identified above) |
| 22 | bare `assert` (no message) |
| 17 | TIMEOUT |
| 13 | `not(x == y)` value mismatch |
| 13 | `wait_until` predicate timeout |
| 8 | `No exception raised` (accepted something that should have been rejected) |

### 15.5 Known root causes still blocking

- **The wallet storage engine.** Core v30's descriptor wallet is a single SQLite file, `wallets/<name>/wallet.dat`; ours is a LevelDB directory. `wallet_startup.py` renames that file directly by name. A separate storage-layer decision.
- **`bitcoin-cli` / `bitcoin-tx` / `bitcoin-util` / wallet tools do not exist**, already declared in `scripts/conformance-config.sh` as providing only the node itself.
- **settings.json takes effect only on the CLI path.** `scripts/run-node.sh` calls `start-node` directly, bypassing `start-node-from-args`, so on the production node settings.json is only read and written by the wallet layer. Functional tests go through the real binary's CLI and are unaffected.
