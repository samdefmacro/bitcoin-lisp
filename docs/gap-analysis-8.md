# 8th gap analysis — bitcoin-lisp vs Bitcoin Core (refs/bitcoin @ d3056bc)

Date: 2026-07-26. Baseline: `main` @ `0074bf1` plus the merged wave-4 work and the
six open PRs 309–314 (working tree on `net-g7-08-eclipse`).

**Method.** 8 parallel finder agents (one per dimension), each seeded with an
exclusion list of the 69 known GA7 items so it would only report *new* findings,
then 12 adversarial verifiers run refute-biased against every significant claim.
Five verifiers proved their verdict by *executing code* in isolated containers
rather than by reading alone.

**The verification pass is what makes this report trustworthy.** One claim was
fully refuted, three were downgraded, one was upgraded, and several were
sharpened in ways that changed the fix. Findings below are labelled with their
verdict; anything marked *unverified* rests on a single agent's code reading.

---

## Headline: 7 confirmed S1s, two of them proven by execution

Seven prior analyses concluded consensus was complete. It is not. The two
worst findings are in the oldest, most-exercised code in the project — the
block-validation loop — and both were invisible to every previous round because
they only misbehave on inputs an honest network never produces.

### S1-1. Same-block chained spends skip signature validation entirely

`validate-block` calls `validate-block-scripts` (`src/validation/block.lisp:1321-1325`)
without threading in the `pending-utxos` table it just built. `collect-spent-utxos`
(`src/validation/transaction.lisp:1088-1110`) returns NIL for the *whole
transaction* if any one input's coin is absent from the confirmed UTXO set, and
`validate-tx-scripts` (`block.lisp:604-636`) then loops `when utxo do <verify>`
and ends `finally (return t)` — a fail-**open** guard. Core checks every
transaction against a view `UpdateCoins` has already populated with the block's
earlier outputs (`refs/bitcoin/src/validation.cpp:2570-2597`), and asserts the
coin is present.

Proven in an isolated container with a non-vacuous control — the identical
garbage scriptSig is rejected when the parent is confirmed and accepted when the
parent is in the same block:

```
validate-block-scripts:  chained=NIL -> valid=NIL err=SCRIPT-FAILED   (control)
                         chained=T   -> valid=T   err=NIL
full validate-block:     chained=T   -> valid=T   err=NIL
mixed-input tx:                        valid=T   err=NIL
```

**The last line is an escalation the finder did not claim.** Because the helper
is all-or-nothing, a transaction mixing one same-block input with confirmed
inputs skips signature checks on *the confirmed ones too*. That converts this
from "a miner can steal coins created in his own block" into **unsigned spending
of arbitrary third-party UTXOs**, by attaching one throwaway same-block parent.

Two further consequences: `test-block-validity` (`block.lisp:1383`) shares the
path, so our own mining templates are not script-checked for chained
transactions; and non-adversarially, script validation has *already* been
silently skipped for every real chained spend (CPFP chains, batch payouts) on
every block we have ever validated — real script coverage is materially lower
than the suite implies.

The mempool path is genuinely unaffected: `mempool-extra-coins` hard-rejects
with `:missing-input` before any script work, so the same fail-open shape is
latent there rather than live.

**Fix (both halves must land together):** thread `:extra-coins pending-utxos`
through to `collect-spent-utxos`' existing third argument — which also fixes
BIP341 precomputed sighashes for chained taproot spends, currently NIL — *and*
make a NIL result a hard failure rather than a skip, mirroring Core's
`assert(!coin.IsSpent())`. Fixing only the second half would spuriously reject
honest chained blocks. The regression test must run through `validate-block`,
include the mixed-input case, and include a positive chained-valid-signature case.

### S1-2. A block spending the same output twice is accepted, and mints money

`pending-utxos` is add-only — nothing marks a prevout consumed — and input
existence is tested against an immutable snapshot, so both spends see the coin.
At apply time `coin-view-spend` returns NIL for the already-spent coin and the
second spend silently vanishes (`src/storage/coins-view-cache.lisp:354-370`).
Core rejects with `bad-txns-inputs-missingorspent`
(`refs/bitcoin/src/consensus/tx_verify.cpp:167-169`).

Proven end-to-end on regtest through the production entry point:

```
CONTROL-1  coinbase + 1 spend of C           -> valid=T   fees=10000000
CONTROL-2  coinbase + spend C + spend GHOST  -> valid=NIL err=MISSING-INPUT   (harness not vacuous)
CLAIM      coinbase + X + Y both spending C  -> valid=T   fees=30000000   ACCEPTED
           undo entries = 1 for 2 inputs (one spend vanished)
           utxo delta 5100000000 vs subsidy 5000000000  -> INFLATION 1 BTC
CLAIM-CTL  coinbase = subsidy + 30000001     -> valid=NIL COINBASE-TOO-LARGE  (fee half confirmed)
activate-block (production path)             -> activated=T, tip advanced
```

The fee is counted twice, inflating the permitted coinbase; a one-satoshi-higher
coinbase is correctly rejected, which independently confirms the inflated ceiling
was real. Only one undo entry is written for two inputs, so disconnecting such a
block would corrupt the UTXO set as well.

**Fix:** add a `spent-outpoints` table beside `pending-utxos`; treat a prevout
present in it as absent (falling into the existing `:missing-input`); after each
transaction validates, mark its inputs spent *then* add its outputs — Core's
`HaveInputs` + `UpdateCoins` pair, expressed without giving up our read-only-view
architecture. This also closes re-spending an intra-block output, defective today
for the same reason. As defence in depth, make `coin-view-apply-block` log rather
than silently ignore a failed spend.

### S1-3. Tapscript resource limits are not enforced

Three sub-claims, all confirmed. BIP342 removes the script-size and opcode-count
limits; it **keeps** the 520-byte element limit and the 1000-item stack cap. Core
proves this structurally: `MAX_SCRIPT_SIZE` (`interpreter.cpp:428`) and
`MAX_OPS_PER_SCRIPT` (`:451-455`) are sigversion-gated, while the push-size check
at `:447-448` sits between them ungated. Our interpreter gates all three push
sites on `(not (flag-enabled "TAPSCRIPT"))` (`src/coalton/script.lisp:2256-2308`)
with a comment asserting BIP342 removed the cap — that comment is simply wrong.
Separately, `validate-taproot-script-path` never size-checks or count-caps the
initial witness stack, where the v0 path correctly does
(`src/coalton/interop.lisp:2727-2730`).

**Fix placement is load-bearing:** Core's OP_SUCCESS scan overrides these limits,
so the new checks must go *after* the OP_SUCCESS return and *before* the weight
binding, count first then element size. Checking earlier would itself be a
divergence.

### S1-4. Tapscript validation-weight budget omits the annex

`validate-taproot` strips the annex with `(setf witness (butlast witness))`
*before* the budget is computed over the stripped list
(`src/coalton/interop.lisp:2997-3030`). Core computes it over the original
`witness.stack`; the pops at `interpreter.cpp:1951-1968` are `SpanPopBack` on a
*view* and never shrink the vector. Our `compute-witness-serialization-size` is
itself byte-exact — only its argument is wrong. Two independent finder agents
converged on this one.

Direction is strictly we-reject / Core-accepts: our budget is short by
`CompactSize(len) + len`, so an annex sized to push the total past a multiple of
50 costs us a sigop and we reject a block Core accepts. Annexes are non-standard
for relay, so this arrives only in a mined block — the pure split vector.
PR 304 rewrote the *decrement* side as an exact transliteration but never
touched the *initialisation* side. No test covers budget initialisation; the
BIP341 tests all bind the weight variable directly.

### S1-5. P2SH sigop counting diverges from `CScript::GetSigOpCount` (upgraded from S2)

Core's `GetScriptOp` clears its data buffer for every opcode and only refills it
for `opcode <= OP_PUSHDATA4`, so `OP_0`, `OP_1NEGATE`, `OP_RESERVED` and
`OP_1..OP_16` yield an *empty* subscript — zero sigops — while not tripping the
`opcode > OP_16` early-out. Our `extract-last-push` (`src/validation/block.lisp:966-1004`)
treats those as non-pushes and keeps an earlier blob, and has no push-only gate.

A P2SH output committing to the empty redeem script, spent with
`<520 bytes of OP_16 OP_CHECKMULTISIG> OP_0`, counts 0 sigops in Core and 4160
for us — 16,640 weighted per input, so five inputs cross the 80,000 cap and we
reject a block Core fully validates. The verifier confirmed our *own* script
engine accepts the spend (execution uses the real stack top, not this helper), so
we reject only the block: a pure split. The same over-count also makes us refuse
to relay transactions Core relays.

**Fix:** one sigop-specific helper for the two sigop call sites only — do not
repoint the three policy consumers, which have different semantics. Because
Core's function returns 0 exactly when the scriptSig is not push-only, that
single helper also supplies the `IsPushOnly` gate the P2SH-wrapped-witness branch
needs.

### S1-6. RPC authentication is never enforced — confirmed live

`check-auth` (`src/rpc/server.lisp:495-497`) is `(if (and *rpc-user* *rpc-password*)
<check> t)`. With no `-rpcuser`/`-rpcpassword` — our normal deployment — it
returns T without ever reading the `Authorization` header. A `.cookie` file *is*
generated, so the operator reasonably believes cookie auth is in force, but
nothing installs the cookie as a credential.

Proven against the live testnet4 node, read-only, `getblockcount` only:

```
no Authorization header  -> HTTP/1.1 200 OK  {"result":145782}
wrong Basic credential   -> HTTP/1.1 200 OK  {"result":145782}
```

The node is running with no RPC credentials and **its wallet is loaded**
(`smoke-deploy`), so `sendtoaddress` on real testnet coins is reachable with zero
credentials right now. Worse than reported: the cookie is written only when
user+password are *absent* while the cookie comparison runs only when they are
*present* — mutually exclusive, so cookie auth is unreachable in **every**
configuration.

Exposure is bounded by the loopback-only default bind: this is a local-privilege
boundary, not remote access. But the node runs as a normal user on a host with
SSH, so any local process or an `ssh -L` forward reaches it, and the 0600-cookie
boundary Core uses to separate local users does not exist here. Two amplifiers:
`-rpcbind` is passed straight through with no `-rpcallowip` gate and no warning
(Core ignores `-rpcbind` without it), so one flag makes this world-open; and the
generated cookie is **world-readable (0664)** on both the testnet4 and mainnet
datadirs, where Core creates it 0600.

**The test suite actively protects the hole.** `rpc-auth-check-no-credentials`
asserts `(is (check-auth nil))` — it will fail on the fix and must be rewritten —
and `rpc-basic-auth-and-cookie` binds user, password and cookie secret
simultaneously, a state startup can never produce, making it a vacuous test that
manufactures false assurance.

`-rpcauth`, `-rpcallowip`, `-rpccookiefile` and `-rpccookieperms` do not exist.

### S1-7. Header median-time-past is unenforced mid-batch, and the reorg path never re-checks

`compute-median-time-past` returns literal `0` for a hash not in the index
(`src/validation/block.lisp:100-118`), so the guard `(<= timestamp mtp)` in
`validate-header-chain` is vacuously false for any header whose in-batch
predecessor is not yet indexed. The batch *does* thread a staging chain and
**every other check uses it** — the MTP call uses a hash lookup instead. That is
the entire bug. There is no self-healing: a re-announcement hits the already-have
branch and is never re-validated.

Both halves proven empirically. Batch admission:

```
[A] batch (H12 H13)          -> accepted=2 err=NIL      (H13 nTime 100000s before its parent's MTP)
[B] batch (H12) then (H13)   -> accepted=1, then 0 err="Timestamp at or before median-time-past"
    probe mid-batch: compute-median-time-past(H12) = 0 ; after H12 indexed = 1500004200
```

And reorg connection — `:skip-header t` wraps the whole header check, including MTP:

```
[control] validate-block(B1) without skip-header -> err=:TIME-TOO-OLD
[reorg]   perform-reorg(A2 -> B3)                -> ok=T, tip=height 3, B1 status=:VALID
          time-too-old block on the ACTIVE chain: YES
```

The verifier also found extra scope the finder missed: `reconsiderblock` passes
the target directly to `perform-reorg`, so the violating block can be the reorg
tip itself, with no descendant needed. Conversely it *refuted* the same defect
for every other contextual rule — future-time, difficulty, version gates and PoW
all consume the threaded parent entry and correctly reject at batch position 2.
That narrows the fix considerably.

Severity is network-dependent: **S2 on mainnet** (needs a strictly heavier
three-block fork; mainnet relay is off by default here) but **S1-equivalent on
testnet4**, the network this project actually runs, where low difficulty and
documented multi-hundred-block reorgs let a modest ASIC hold us on a
Core-rejected chain indefinitely. Not reachable by accident — honest miners never
produce such blocks.

**Fix:** compute MTP from the entry we already hold rather than from a hash; the
correct walk already exists in `headers-sync.lisp:148-158`. Secondarily, make the
`0` fallback loud: returning 0 for an unknown hash is a silent fail-open in a
consensus comparison, and had it signalled, this bug could not have existed. Do
**not** drop `:skip-header t` from `perform-reorg` — that diverges from Core and
would spuriously fail PoW on deserialised fork bodies.

---

## Confirmed S2s

**Network, and eclipse-relevant.** Gossiped addresses older than 3 hours are
*discarded rather than stored* (`protocol.lisp:1031-1033`) — the window gates
storage, not relay, which has its own correct 10-minute gate. Core stores
regardless of age with a 2-hour penalty, and its own DNS-seed path deliberately
creates entries aged 3–7 days against a 30-day horizon. Since seeds never enter
our address book directly, this is the sole chokepoint for every solicited
`getaddr` response we ask for — the live node has 1,624 addrman entries after
~2.5 months. This silently undercuts the entire GA7 anti-eclipse investment,
since addrman diversity is the substrate those mechanisms select from.

**A bootstrap regression from PR 306.** `%reachable-seed-addresses` drops
anything `parse-network-address` cannot classify, but under `-proxy` the seed
list is deliberately *hostnames* so SOCKS5 can resolve them. With `-proxy` set
and no `-onlynet`, every DNS seed is filtered out. Testnet4 survives on its fixed
IPv4 seeds; **mainnet and signet have no fixed-seed list, so a proxied node with
a fresh datadir cannot bootstrap at all.** `git log -S` confirms this behaviour
arrived with commit 8aad566 and that the proxy path worked before it. The two
network findings compound: B kills the seed path, A then discards the `getaddr`
harvest that would otherwise recover, and because seeds are only consulted while
addrman holds fewer than 8 entries, the broken path stays load-bearing.

**Compact blocks punish honest peers.** Every failed `accept-downloaded-block`
calls `record-misbehavior`, which discourages the address permanently and
disconnects — with no reason filter, so `:orphan-block` and `:bad-merkle-root`
both punish. Core exempts compact-block failures entirely and answers an
unknown-parent compact block with `getheaders`. No attacker is needed: fall one
block behind, receive the next block from a high-bandwidth peer, and we exile our
fastest honest block-relay peer.

**Open-PR defects, catchable before merge.** In PR 314 the P2 protection counter
only ever increments — `release-outbound-protection` has no production caller —
so after one round of peer churn no peer can ever earn eclipse protection again,
inverting the feature's purpose. In PR 311 the low-work disconnect runs after
*every* branch of header ingestion, including shapes where Core returns early, so
an outbound peer sending a normal BIP130 announcement during early IBD can be
dropped; the in-code comment justifying the placement is factually wrong.
Also: PR 309 and PR 312 both insert a peer struct field at the same spot, so the
second merge needs a careful re-diff, and PRs 310/312 draw from SBCL's unseeded
`*random-state*`, making their anti-fingerprinting jitter deterministic across
restarts.

**Storage and operations.** The `coinstatsindex` stores no per-record block hash
and has no rewind hook, so a process kill inside the ≤10-minute post-reorg flush
window leaves height-keyed records holding the abandoned chain's state, and the
startup repair loop blesses them *and overwrites the one piece of evidence that
could have detected it*. Downgraded from S1 because the default
`gettxoutsetinfo` reads the live UTXO set, so only the opt-in index's historical
queries are wrong — but silently, permanently, and the live node runs with the
index enabled. Its most likely trigger is the next finding.

The shipped supervisor's watchdog exits the process within 10 seconds of
`node-running` going false, but `stop-node` flips that flag *first* and does the
chainstate flush, mempool.dat, peers.dat and wallet markers *after*. All three
internal stop paths run on non-main threads, so a plain RPC `stop` is a race
against the flush — roughly a coin flip at an idle tip, a guaranteed unclean kill
mid-block. The live supervisors on **both** nodes contain the identical logic, and
deterministic startup failures exit 1 into an unconditional 10-second respawn
loop. This manufactures, in normal operation, exactly the process-kill the
coinstatsindex bug needs.

Three further storage findings were reported from code reading alone and later
put through a dedicated confirmation pass (2026-07-26). **All three survived, but
two had their stated mechanism or severity corrected — one substantially — so the
original text is superseded by what follows.**

**Torn `txindex.dat` tail — confirmed, downgraded to S3, trigger refuted.** A
misaligned tail really does desync the offset map permanently: with a 40-byte
partial entry, reload counts it as a full entry and inserts a phantom txid, the
next appended entry's lookup dies with `END-OF-FILE`, and a restart makes it
permanent. A sub-32-byte tail is *worse* than reported — it returns the txid
bytes as the block hash and a garbage position, silently. But the claimed trigger
is wrong: a process kill *cannot* produce a torn tail, because the per-entry
`force-output` flushes all 68 bytes in one `write(2)` (measured: a 32-byte write
without `force-output` never reaches disk at all). It needs power loss, a kernel
panic, `ENOSPC`, or external truncation. Severity is capped because `-txindex` is
opt-in and off by default, it is mutually exclusive with pruning, and only
`getrawtransaction` and the merkle-proof RPC read it — no consensus path does.
One aggravating fact the original missed: `build-tx-index`, the only
repair-shaped routine, has **no production call site**, so nothing ever detects
or repairs the misalignment.

**Corrupt `chainstate.dat` — confirmed, but the mechanism was wrong and the
severity is network-dependent.** The silent half is exact: a one-bit flip and a
missing file are byte-for-byte indistinguishable (`load-state` returns NIL for
both, and the caller logs nothing), and a file truncated to 40 bytes is accepted
outright by the CRC-less legacy fallback. The cascade is real too — but it is
**not** `:missing-input`. That was refuted structurally: `perform-reorg` replays
forward from the fork point, so `apply-block-to-utxo-set` re-creates every coin
before any later block spends it, and a spend inside the replayed range can never
miss. The actual trigger is the **BIP30 duplicate-txid check**, which fires when a
replayed block re-creates a txid whose output is still unspent at the real height.
Measured on mainnet parameters: the node marks its own chain invalid and ends with
**no best-valid-tip at all** — a bricked index. But BIP30 enforcement is gated on
the BIP34 activation height, and testnet4, signet and regtest activate BIP34 at
height 1, so the whole live testnet4 range is exempt and the replay **self-heals**
(measured: 0 invalid, tip advanced). So this is **S1 on mainnet, S3 everywhere
this project actually runs**.

**600-second `destroy-thread` mid-reorg — confirmed.** SBCL's `destroy-thread`
does interrupt unprotected code mid-loop and unwind, while `without-interrupts`
defers it to completion, so the asymmetry the finding rests on is real:
`connect-block`'s tip-extension path and `%flush-chainstate` are wrapped,
`perform-reorg`'s disconnect phase is not. Downgraded to S3 for the stated
shutdown trigger (it needs a reorg overrunning 600s) but raised to **S2 for the
underlying defect**, which the confirmation pass found is reachable without any
shutdown at all.

**RPC contracts**, all five empirically settled. In descending order of real-client
breakage: JSON-RPC 1.x replies always carry `"jsonrpc":"2.0"` and never the
legacy `result`+`error` pair, so python-bitcoinrpc raises `KeyError: 'error'` on
every successful call (bitcoin-cli is coincidentally immune, which is why nobody
noticed); empty collections encode as `null` rather than `[]` on ~11 node-side
methods, verified live on `listbanned` and `getaddednodeinfo`; `getblockheader`
omits `nTx` and emits an all-zero `previousblockhash` for genesis instead of
omitting the key; `getblockstats` computes `total_size`, `total_out` and
`avgtxsize` from the wrong quantities (verified live: `avgtxsize`=121=13910/115,
the whole-block-over-ntx formula) and silently drops unknown stat names where
Core errors; and `/rest/headers` splices a fork header onto active-chain
successors, returning a non-contiguous chain — real, but REST is off by default
and off on the live node.

**Mempool.** We have no reconsiderable-rejects filter and no opportunistic
1-parent-1-child package relay, so a CPFP package whose parent is below the fee
floor is permanently black-holed: the parent is cached as rejected, the child
becomes an orphan, and the re-sent parent is dropped before validation. Modern
LN fee-bumping packages never enter our mempool at all. Package validation
exists but is reachable only from the `submitpackage` RPC.

**Wallet.** `bumpfee` with an explicit `fee_rate` skips Core's pre-build
`CheckFeeRate` gates and wrongly forces the fee-override flag, so it can commit
an unrelayable replacement, mark the original as bumped, and return success with
an empty `errors` array. Downgraded to S3 on verification: the original stays in
both mempools and can still confirm, and the resend timer re-broadcasts once the
rolling minimum decays, so funds self-heal rather than strand.

---

## What was refuted or downgraded

This section matters as much as the findings. Verification changed the answer
seven times:

- **Refuted outright:** trimmed disconnect-pool transactions do *not* leave
  orphaned mempool descendants. The premise was right — they are only logged —
  but the same reorg phase ends with a sweep that flags any entry with a missing
  input via two independent paths and removes it recursively. Different mechanism
  from Core's `removeRecursive`, identical fixed point. The associated
  "refuses to trim to empty" sub-claim is dead code that can never bind.
- **Upgraded:** the P2SH sigop divergence, S2 → S1 (it is a block-level rejection
  of a block Core validates).
- **Downgraded:** coinstatsindex corruption S1 → S2 (the default
  `gettxoutsetinfo` doesn't read the index); the `notfound` block spin S2 → S3
  (per-peer budgets pace it and other peers still make progress; the real defect
  is an unpenalised peer slot); `bumpfee` S2 → S3; the disconnect-pool accounting
  units to informational.
- **Sharpened:** the header MTP hole affects only headers whose in-batch
  predecessor is unindexed, not "all but the first", and provably no other
  contextual rule shares the defect — which shrinks the fix from a restructure to
  one call.

---

## GA7 backlog status

Of the 69 GA7 items: **10 merged, 6 in the open PRs 309–314, 53 remaining** —
12 S2 and 41 S3, with no S1s left from that round. The heaviest remaining are
G7-07 (wallet encryption and backup, still the bar to a mainnet wallet), G7-21
(fee estimator port), G7-23 (ZMQ), G7-24 (taproot script-path descriptors), and
G7-08 P3 (stale-tip trigger and outbound rotation), which is the tail of the
eclipse work — though the P1/P2 defects above mean the merged parts are not yet
Core-faithful either.

## Suggested sequencing

1. **RPC auth (S1-6)** first — it is the only finding that is live and exploitable
   today, and the fix is small. Fix the cookie mode, the file permissions, and the
   two tests that lock the hole in.
2. **The two block-validation S1s (S1-1, S1-2)** together — they share a file, a
   root cause (an incomplete intra-block overlay) and a test fixture, and they
   compose into a theft primitive. Consensus-critical: adversarial review and
   sign-off before merge, as with the GA7 taproot fixes.
3. **The three script/consensus S1s (S1-3, S1-4, S1-5)** — independent of each
   other, each small, each a clean chain-split cell.
4. **Header MTP (S1-7)** — one-line primary fix plus the fail-loud change.
5. **The open-PR defects** before merging 309–314, then the network S2 cluster
   (addr window, proxy seeds, compact-block punishment), which together restore
   the anti-eclipse posture GA7 wave 4 was meant to deliver.
6. Supervisor and coinstatsindex together, since the first triggers the second.
7. RPC contract fixes as one batch.

## Test-suite observations

Three distinct failure modes showed up, all worth generalising:

- A test that **asserts the bug** (`rpc-auth-check-no-credentials`).
- A test that is **vacuous by construction** — `rpc-basic-auth-and-cookie` binds a
  state the production code can never produce, so it validates nothing while
  reading as coverage. This is the same hazard recorded after wave 4, where a
  green mutation run masked a no-op patch.
- **Untested seams that look tested**: no test builds a chained same-block spend
  through `validate-block`; nothing covers validation-weight *initialisation*
  (the BIP341 tests bind the variable directly); nothing covers
  `extract-last-push` (the one test with a similar name covers a different
  function on the execution path).

The common thread: every one of these gaps sits where a test exists nearby and
appears to cover the area. Coverage counted by proximity is not coverage.
