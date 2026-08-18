# 9th gap analysis — bitcoin-lisp vs Bitcoin Core (refs/bitcoin @ d3056bc)

Date: 2026-08-18. Baseline: `main` @ `401e807`, clean tree.
Oracle: Bitcoin Core @ `d3056bc149f605225f22b1cc83b1a2d1cea64258` — the same revision GA7 and GA8
used, so severities and coverage are directly comparable across the three rounds.

## ⚠️ SCOPE: this round is INCOMPLETE — see the table for which dimensions finished

Twelve parallel finder agents were launched, each seeded with an exclusion list covering every
finding from GA1–GA8 so it could only report new ground. **Seven of them died mid-analysis on an
API session limit** and returned nothing. This report therefore covers a little under half the
intended surface, and its findings have NOT yet been through the adversarial verification pass
that made GA7 and GA8 trustworthy.

| Dimension | Status | Findings |
|---|---|---|
| block & tx validation | ✅ complete | 3 S1, 1 S2, 2 S3 |
| chain / headers / reorg | ✅ complete | 1 S1, 3 S2 |
| peer management & addrman | ✅ complete | 3 S2, 6 S3 |
| mining / config / lifecycle | ✅ complete | 1 S2, 11 S3 |
| GA7 backlog status refresh | ✅ complete | 2 status regressions |
| script interpreter | ❌ died on session limit | — |
| mempool & policy | ❌ died on session limit | — |
| P2P protocol & transport | ✅ complete (part 2) | 1 S1, 2 S2, 1 S3 |
| storage & indexes | ✅ complete (part 2) | 4 S2, 4 S3 |
| wallet | ❌ died on session limit | — |
| RPC / REST / UI | ❌ died on session limit | — |
| crypto & canonical encoding | ❌ died on session limit | — |

The seven missing dimensions include the three where the newest, least-reviewed code lives —
the resumable v1/v2 readers (#340–#342), the coins-DB alignment series (#333–#338), and Wallet
P6 encryption (#343). **Re-running those seven is the first task of GA9 part 2**, and the brief
that drives them is preserved (see "Reproducing this round" at the end).

Two findings below were independently confirmed by me directly against both source trees rather
than resting on an agent's reading; they are marked **[verified]**. Everything else rests on a
single agent's trace and should be treated as high-quality but unverified.

---

## Confirmed S1s

### S1-1. Block weight omits the header and tx-count varint, so we accept blocks up to 332 weight units over the limit **[verified]**

`calculate-block-weight` (`src/validation/block.lisp:992-995`) is literally
`(loop for tx in transactions sum (transaction-weight tx))`. Core's `GetBlockWeight`
(`src/consensus/validation.h:136-139`) serializes the **whole block** —
`GetSerializeSize(TX_NO_WITNESS(block)) * 3 + GetSerializeSize(TX_WITH_WITNESS(block))` — and the
block serializer emits `header(80) || CompactSize(vtx.size()) || txs`, so that 80+varint prefix is
counted four times. Core's total is therefore `4*(80 + cs(n)) + SUM(tx_weight)`; ours is
`SUM(tx_weight)` alone.

We under-count every block by exactly **324 wu** (n < 253) or **332 wu** (253 ≤ n < 65536).

Direction: **we accept what Core rejects.** A block whose true weight lands in
(4,000,000, 4,000,332] passes our check, connects, and advances our tip while every Core node
rejects it with `bad-blk-weight` — a permanent split ending only by manual intervention.

The tell that this is an oversight rather than a decision: the **base-size check nine lines below**
(`block.lisp:1269-1278`) gets it right, explicitly adding `80` and `compact-size-length`. The same
function understands the prefix and simply dropped it from the weight path.

Our own mining is unaffected — the assembler reserves 8000 wu for a coinbase costing ~600–1000 wu,
absorbing the shortfall. Secondary effect: `getblock`'s `weight` field is 324/332 low versus
bitcoind for the same block.

**Fix:** compute weight over the block, not the tx list: `4*(80 + compact-size-length(n)) + sum`.
Placement constraint: the RPC caller (`src/rpc/methods.lisp:287`) passes a tx list, not a block, so
give it the block or add a second arity — the consensus site and the RPC number must agree.

### S1-2. The finality check skips the coinbase, where Core checks it **[verified]**

Core's `ContextualCheckBlock` iterates **`block.vtx`** — which includes `vtx[0]` — with no
`IsCoinBase()` guard (`src/validation.cpp:4176-4181`). We iterate `(rest transactions)`
(`src/validation/block.lisp:1417`), skipping the coinbase, under a comment that states the
intent: "Check finality for all non-coinbase transactions".

The exclusion was applied to the wrong one of the two adjacent loops: the BIP68 sequence-lock loop
three lines below **correctly** uses `(rest transactions)`, because Core *does* guard that one with
`if (!tx.IsCoinBase())` (`validation.cpp:2528`).

Direction: **we accept what Core rejects.** A coinbase with `nLockTime` beyond the cutoff and its
input's `nSequence != 0xffffffff` is non-final; Core rejects the block `bad-txns-nonfinal`, we
connect it and build on it. No honest software produces this (Core's miner leaves the coinbase
input at `SEQUENCE_FINAL`, so `nLockTime` is ignored) and no historical block has it — so there is
no IBD exposure, only a deliberately crafted block. Cheap on testnet4/signet; needs hashpower on
mainnet.

**Fix:** one word — `(rest transactions)` → `transactions` at `block.lisp:1417`.
`check-transaction-final` already handles the coinbase shape. The BIP68 loop below must keep its
`(rest transactions)`.

### S1-3. BIP68's version gate reads a *signed* 32-bit version, so a high-bit version skips relative-locktime enforcement

Core stores the transaction version as `const uint32_t version`
(`src/primitives/transaction.h:293`) and gates BIP68 with `tx.version >= 2`
(`src/consensus/tx_verify.cpp:51`). Under unsigned comparison **every** version with bit 31 set is
`>= 2`, so Core **enforces** relative locktimes on it. We store `(signed-byte 32)`
(`src/serialization/types.lisp:139`, read via `read-int32-le` at `:251`), so the same bytes read
negative and `(when (< (transaction-version tx) 2) (return-from check-sequence-locks t))`
(`src/validation/block.lisp:159-161`) **skips BIP68 entirely**.

Direction: **we accept what Core rejects.** Version bytes `0x02000080` (version `0x80000002`)
spending an input with an unmatured relative locktime: Core rejects the containing block
`bad-txns-nonfinal`; we connect it. The same gate sits on the mempool path
(`src/validation/transaction.lisp:862-866`), so we would also admit and relay such a transaction,
and our assembler could mine it into a block the network rejects. Standardness does not save us —
nonstandard transactions are legal in blocks.

Confidence: medium (the finder's own rating). The reasoning is sound but this one deserves an
executable control before it is fixed.

**Fix:** compare the unsigned reinterpretation **at the gate only**:
`(>= (logand (transaction-version tx) #xFFFFFFFF) 2)`. Do **not** flip the struct slot to
unsigned — `write-int32-le` round-tripping and the TRUC/standardness version comparisons
(`transaction.lisp:179-188`) are all written against the signed value.

### S1-4. An invalidated block-index entry is silently resurrected

Core never rebuilds a `CBlockIndex`: `AddToBlockIndex` uses `try_emplace` and returns the existing
object (`src/node/blockstorage.cpp:228-231`); receiving the body mutates it in place
(`validation.cpp:3800-3821`). `AcceptBlockHeader` short-circuits a known-`BLOCK_FAILED_VALID`
header with `duplicate-invalid` (`validation.cpp:4231-4235`) and rejects any header whose parent
carries the flag with `bad-prevblk` (`:4252-4255`), and `FindMostWorkChain` independently refuses
any candidate whose path contains `BLOCK_FAILED_VALID` (`:3170-3196`).

Ours does the opposite. `connect-block` builds a **brand-new** `block-index-entry` with
`:status :valid` (`src/validation/block.lisp:1825-1834`) and `add-block-index-entry` is a plain
`(setf (gethash hash ...))` (`src/storage/chain.lisp:394-396`) — a replace, which erases an
existing `:invalid` mark. `accept-downloaded-block` (`src/networking/protocol.lisp:922-943`) has
neither Core gate: it only branches on whether prev-hash equals the tip. `perform-reorg`'s connect
loop (`block.lisp:2503-2562`) never reads entry status at all. The gate exists only on the compact-
block path (`protocol.lisp:3005/3019`).

Direction: **we accept what Core rejects.** Two consequences:

1. **`invalidateblock` is defeated by one unsolicited `block` message.** After the RPC reorgs down
   and marks the block `:invalid`, the tip is its parent — so a peer replaying the block hits the
   tip-extension arm, passes `validate-block` (it is consensus-valid; invalidateblock is a manual
   override), and `connect-block` re-creates the entry as `:valid` and re-applies it. The operator's
   node is back on the chain they explicitly refused, silently.
2. **The automatic poison is equally erasable.** `%mark-block-subtree-invalid`'s docstring claims the
   doomed subtree "is never re-requested or re-attempted"; any peer re-sending a poisoned fork block
   clears the mark, after which the full reorg is attempted again before being re-poisoned — an
   unmetered work-amplification loop driven by a ~1 MB message.

**Fix (three edits, all needed):** (a) in `connect-block`, mutate an existing entry rather than
constructing a new one, and *raise* status, never clear `:invalid`; (b) add Core's duplicate-invalid
/ bad-prevblk gate at the top of `accept-downloaded-block` — factor out the logic already in
`compact-block-header-verdict`; (c) in `perform-reorg`, refuse before mutating anything if any
to-connect entry is `:invalid` (Core's `fFailedChain` arm).

---

## Confirmed S2s

### S2-1. Signet cannot follow its own chain — found independently by two agents

**Two finders converged on this from different directions**, which is the strongest signal in this
round. Two independent defects:

- **No signet PoW limit.** Core's signet `powLimit` is `00000377ae...` (compact `0x1e0377ae`,
  `src/kernel/chainparams.cpp:490`). `*pow-limit-target*` is only ever raised for regtest
  (`src/node.lisp:418-421`), so on signet `derive-target` (`src/storage/chain.lisp:467-482`) runs
  against **mainnet's** limit and rejects every real signet nBits — including signet's own genesis
  `0x1e0377ae`, which our own `chain.lisp:359` records. `calculate-next-work-required` has the same
  hardcoded clamp (`chain.lisp:531`).
- **No non-boundary difficulty rule.** Signet has `fPowAllowMinDifficultyBlocks = false`, so Core
  simply inherits the previous block's nBits at a non-boundary height (`src/pow.cpp:38`).
  `get-expected-bits` has arms for genesis, regtest, retarget boundaries and `:mainnet`, then falls
  through to `(t nil)`; `validate-difficulty` turns a NIL expectation into the testnet
  min-difficulty case, tests `(member *network* '(:testnet3 :testnet4))`, and for `:signet` reaches
  the terminal `(t (values nil :bad-difficulty))` (`block.lisp:424, 447-448`).

So **2015 of every 2016 signet blocks are rejected `:bad-difficulty`**, and the PoW limit rejects
the rest. Direction: **we reject what Core accepts**, totally — the node cannot advance past
height 1 on signet.

This is not a stub network here: signet has its own genesis, magic, port 38333/RPC 38332, DNS
seeds, datadir, `nMinimumChainWork`, an assumeutxo table, and a byte-faithful BIP325 solution
validator in `src/validation/signet.lisp`. An operator has every reason to expect `-signet` to
work. It has clearly never been exercised — `tests/signet-tests.lisp` covers only the BIP325
solution port and never runs a signet header through `validate-block-header`.

**Fix:** add a `:signet` arm to the PoW-limit selection; make `calculate-next-work-required` clamp
on the dynamic `*pow-limit-target*` rather than the `+pow-limit-target+` constant; and give
`get-expected-bits` a non-boundary inherit-previous-bits arm for every network with
`fPowAllowMinDifficultyBlocks = false`. The predicate already exists at
`src/networking/headers-sync.lisp:101-103` and must become the single source of truth for both the
retarget path and `permitted-difficulty-transition`, or the two drift.

### S2-2. `connect-block` replacing the index entry breaks the `eq`-based ancestry walk

Same root cause as S1-4, distinct consequence. During headers-first sync, `process-headers` creates
entry E1 per header and links the next header's `prev-entry` to it
(`src/networking/ibd.lisp:946-953`). When the body arrives, `connect-block` builds a *new* entry E2
and replaces the table slot — so every header admitted before its body keeps pointing at the
orphaned E1. `block-descends-from-p` compares with `eq` against the `prev-entry` walk
(`block.lisp:2668-2670`), so it returns NIL for every header-only entry above the connected tip.

Consequences: `invalidateblock` leaves every already-known header above the tip at
`:header-valid`, so the download walk's `:invalid` abort never fires for them, their bodies are
fetched, and the first whose parent is the invalidated block drives straight into `perform-reorg`
onto the invalidated branch — compounding S1-4. `%mark-block-subtree-invalid`'s stated guarantee is
false for exactly the entries it was written to cover. `reconsiderblock`'s symmetric `eq` walk can
likewise fail, leaving the index in a state neither RPC can repair.

It only bites in a live session: `load-header-index` rebuilds a consistent object graph by hash on
restart (`chain.lisp:1006-1013`), which is why a restart-based test would never show it.

**Fix:** the same identity-preserving change as S1-4(a) fixes this. Defensively, convert
`block-descends-from-p`'s `eq` to a hash comparison so the invariant stops depending on object
identity.

### S2-3. Script checks are skipped on a bare height comparison

Core skips signature verification only when **all** of: assumevalid is set and in the index; the
block is an ancestor of the assumevalid block; it is on the best-header chain; best-header
chain-work ≥ `MinimumChainWork()`; and more than two weeks of equivalent work sits below the best
header (`src/validation.cpp:2342-2380`). **Checkpoints play no part** — Core's `fScriptChecks` is a
pure function of assumevalid.

Ours is `(max (last-checkpoint-height) (assumevalid-skip-height))` reduced to
`(<= height (script-skip-height))` (`src/networking/ibd.lisp:699-720, 3348, 3568, 3171`).

Because only height is compared, a block that is **not** an ancestor of the assumevalid block — any
competing-fork block at or below that height — is connected with signature verification disabled.
A fork must out-work the active chain to connect, which is expensive at mainnet tip but not during
IBD, and cheap by design on the min-difficulty test networks. In that window we accept a fork block
carrying forged scriptSigs that Core verifies and rejects.

Two further gaps in the same expression: no equivalent-time margin (Core's anti-extortion check);
and when the assumevalid header is not yet in our index — the whole first phase of a fresh IBD —
we fall back to the checkpoint height and skip **every** signature up to 840,000 on mainnet and
2,000,000 on testnet3, where Core verifies everything. We also never check
`best_header->nChainWork >= MinimumChainWork()`, the exact condition Core added to stop the skip
when a node is being denied the real chain.

**Fix:** replace the height test with Core's predicate evaluated **per block**, and drop the
checkpoint term. Placement constraint: it must run inside `perform-reorg`'s connect loop, not be
computed once by the caller and threaded in as one boolean (`block.lisp:2528-2533` applies a single
verdict to the whole fork) — otherwise the ancestor condition is unenforceable for exactly the
fork blocks it protects. Use hash comparison, not `eq`, given S2-2.

### S2-4. Any misbehaving inbound onion peer discourages `127.0.0.1`, disabling onion reachability

Core's `MaybeDiscourageAndDisconnect` has an explicit carve-out — `if (pnode.addr.IsLocal())` →
disconnect **but do not discourage** (`src/net_processing.cpp:5194-5201`) — whose comment names the
exact reason ("since that would discourage all peers on the same local address") and whose log line
names `m_inbound_onion` as the case it protects. Only after that guard does Core reach
`Discourage(pnode.addr)`.

Our `record-misbehavior` (`src/networking/peer.lisp:1500-1519`) calls
`(discourage-peer (peer-address peer))` unconditionally. Every inbound onion peer arrives through
the local Tor daemon on the loopback listener, so its address is the string `"127.0.0.1"`
(`src/node.lisp:665-667`).

One onion peer tripping any of the six `record-misbehavior` call sites inserts `"127.0.0.1"` into
the discourage filter. From then on, until restart: new inbound onion connections are dropped near
capacity; `evict-discouraged-inbound` finds an onion peer on **every** new inbound admission and
disconnects one, churning the whole onion population out; and `connect-peer` refuses to dial
`127.0.0.1` at all, breaking local addnode and regtest dials. An attacker who can reach our onion
service needs exactly one cheap violation (e.g. an addr message with count > 1000) to disable the
node's entire onion reachability.

**Fix:** gate the *discourage* (not the disconnect) on the peer not being loopback/local, inside
`record-misbehavior` — not at the six call sites, or the next one added will miss it.

### S2-5. addrman failure accounting never runs in steady state

Core calls `addrman.Attempt(...)` on **every** dial, immediately after the connect attempt and
before the socket is even checked (`src/net.cpp:492-497`); `Attempt_` stamps the try and increments
`nAttempts`, and `Good()` resets it to 0 on a successful VERSION.

We call `address-book-attempt` from exactly one place — the `handler-case` ERROR branch of
`connect-to-peers` (`src/node.lisp:3626, 3775`) — and `connect-to-peers` runs only at startup and
when the peer count reaches zero. Every steady-state dial path records nothing at all:
`replace-disconnected-peers`, `maintain-block-relay-peers`, `do-feeler-connection`,
`establish-outbound-peer`. The feeler is Core's dedicated address-quality prober; ours can only
promote, never demote. And a peer that accepts TCP then stalls returns NIL from
`perform-handshake` without signalling, so neither Good nor Attempt is recorded.

With `nAttempts` pinned at 0, `addr-info-terrible-p` can never fire on its two `nAttempts` clauses
and `addr-info-chance` never applies its 0.66^n decay. Dead addresses keep full selection weight
forever, are never overwritten as terrible incumbents, and are never filtered out of
`getaddr` — so we re-gossip an attacker's dead address set indefinitely.

**Fix:** call `address-book-attempt` once per dial at the point the dial is initiated, matching
Core's placement right after the connect syscall — it must fire before the handshake result is
known, or the stalling-peer case stays uncounted.

### S2-6. Inbound eviction omits four protection passes and preferentially evicts onion peers

Core's `SelectNodeToEvict` runs six protection passes (`src/node/eviction.cpp:186-205`): 4 by
**keyed** netgroup (unpredictable to an attacker), 8 by **lowest** ping, 4 by most-recent novel tx,
up to 8 block-relay peers that sent novel blocks, 4 by most-recent novel block, then
`ProtectEvictionCandidatesByRatio`, which protects half the survivors by uptime and reserves up to
a quarter of the protected set for CJDNS/I2P/localhost/**onion** peers — explicitly because those
"tend to be otherwise disadvantaged under our eviction criteria" (`eviction.cpp:105-120`).

`evict-least-valuable-inbound` (`src/node.lisp:494-544`) protects a fixed 4 by ping and 4 by
uptime, then picks the youngest member of the **most-populous netgroup**. Three defects:

- The four work-based protections are absent although the data is already tracked and exposed via
  `getpeerinfo` — `peer-last-block-time` and `peer-last-tx-time` are never read by the evictor.
- The ping protection uses the *most recent* RTT while `peer-min-ping-latency` is maintained right
  beside it and never used. Core chose the minimum deliberately: an attacker cannot manipulate it
  without physically moving nodes.
- **The worst:** all inbound onion peers present as `127.0.0.1`, so `ip-netgroup` returns `"127.0"`
  for every one. With two or more onion peers they form the largest group, so one is evicted on
  every new inbound admission at capacity. Core hits the same shared-group situation and
  compensates with the explicit disadvantaged-networks reservation. With `-listenonion` on by
  default, an operator loses their onion inbound peers to ordinary clearnet pressure.

**Fix, in value order:** exclude `peer-inbound-onion` peers from the most-populous-netgroup victim
rule (or give them Core's reserved quota); add protection passes on last-block/last-tx time; switch
to `peer-min-ping-latency`; scale uptime protection to half the candidate set. The onion carve-out
must key on `peer-inbound-onion`, not the address string — the string is the thing that collides.

### S2-7. `noX=1` — the only negation spelling a bitcoin.conf can carry — is silently discarded

Core splits key from value **first**, then runs `InterpretKey` on the bare key: any key starting
`no` is stripped and marked negated regardless of a following value
(`src/common/args.cpp:78-92`). Its config parser goes further — a line without `=` is a hard parse
error whose message tells the operator to write `noX=1` instead (`src/common/config.cpp:64-71`), so
**`noX=1` is the only negation spelling a config file can express**.

`parse-cli-args` (`src/config.lisp:614-624`) tests for `=` **before** testing the `no` prefix, so
the stripping branch is reachable only for a bare `-noX` token with no value. `nolisten=1` becomes
the alist cell `("nolisten" . "1")`, which no lookup ever consults. `parse-bitcoin-conf` drops any
line without `=`, so the bare form is unusable in a file either.

In bitcoin.conf, negation is therefore **entirely non-functional**: `nolisten=1` still opens the
inbound listener; `nolistenonion=1` still starts the onion listener and torcontrol; `nodnsseed=1`
still queries DNS seeds — the exact clearnet leak the code documents elsewhere as the reason
`-dnsseed` is soft-set off under `-onlynet`; `nowallet=1` on a test network still loads wallets, so
a node the operator declared key-free holds keys.

Completely silent: `known-config-option-p` deliberately accepts the raw `noKEY` spelling, so
neither `check-cli-args` nor the unknown-key warning fires.

**Fix:** apply the negation test to the key **after** splitting on `=`, in both parsers, before the
alist is built — doing it at lookup time would miss `apply-config-globals`, which scans by raw key.
Then drop the `noKEY` tolerance so a genuinely unknown `-nofoo` is rejected as Core does.

---

## S3 findings

**Validation.** Block script flags gate WITNESS and TAPROOT on activation height, where Core turns
them on unconditionally for every block except two hash-listed exceptions
(`validation.cpp:2247-2286`) — unreachable today (it needs re-mining pre-2017 history) but a hazard
the moment a new chainparams entry lands with non-trivial heights. Both transaction deserializers
accept a BIP144 witness marker with all-empty stacks where Core throws "Superfluous witness
record"; contained (txids and weights are unaffected) but a non-canonical encoding enters our block
store.

**Peers.** Tried-table collision resolution runs only inside `connect-to-peers`, i.e. at startup —
Core drains it every ~500ms and probes the incumbent via a feeler, so on a long-running node our
tried table becomes first-come-first-served on every contested slot, losing the self-healing that
makes a poisoned table recoverable. Manual `-addnode` peers are not exempt from discouragement
(Core returns early for them, `net_processing.cpp:5188-5192`), and once discouraged they can never
be redialled for the life of the process, silently. Ping budget is ~3 minutes (30s × 3 strikes)
against Core's single 20-minute `TIMEOUT_INTERVAL`, and a timed-out ping nils the nonce so a late
pong can never reset the counter — plus our own pump stalls are charged to every peer at once.
`address-routable-p` accepts IPv6 loopback, link-local, documentation and ORCHID space Core
rejects, so we store, dial and re-gossip them. `anchors.dat` is never removed after reading (Core
consumes it on read), so a crash-restart loop re-dials the same anchors forever. Outbound netgroup
diversity is enforced only once, over a candidate list frozen at startup; addresses learned during
the session are never used for outbound replacement.

**Config & lifecycle.** When the network is selected *inside* bitcoin.conf, that network's
`[section]` is parsed away before the network is known — the whole section is silently dropped.
`[network]` section values lose to global-area values of the same key (Core's precedence is the
reverse), and network-only options in the global area are applied instead of erroring. Inline `#`
comments are not stripped, so `datadir=/srv/btc  # mainnet` creates a directory with that literal
name and starts a fresh IBD. `conf-parse-bool` treats `true`/`yes`/`on` as true, where Core's
`InterpretBool` is `atoi(v) != 0` — so those spellings are **false** in Core, and `server=true`
opens a listener Core would leave closed. `-includeconf` is unimplemented, so a split config loads
with everything at defaults after one warning line. Conflicting chain selectors resolve by a silent
priority order instead of Core's "Can use at most one" error, so `-chain=regtest` plus a stale
`testnet=1` runs on public testnet3. A non-existent `-datadir` is created rather than refused
(Core: fatal), turning a typo or unmounted volume into a silent full re-sync. Mainnet lives in
`<datadir>/mainnet/` and testnet3 at the root — the **inverse** of Core's layout, so pointing at a
Core datadir with our default network writes testnet3 data into Core's mainnet directory. The
mined coinbase omits Core's timelock commitment (`nSequence` `0xFFFFFFFF`/`nLockTime` 0 instead of
`MAX_SEQUENCE_NONFINAL`/`nHeight-1`) — no validity consequence, but it drops a defence-in-depth
commitment and makes our blocks differ byte-for-byte from Core's for the same template.

**Signal safety and logging** (both medium-confidence, worth a second look). The SIGTERM/SIGINT
handler is not async-signal-safe: it takes the log-buffer mutex and writes to shared streams from
inside the handler, where Core reduces its handler to an atomic flag plus a one-byte self-pipe
write and states the rule explicitly (`init.cpp:417-421`). If the signal lands on a thread already
holding that non-recursive lock, SBCL signals a recursive-lock error inside the handler, which
reaches the debugger hook and exits 1 — so a routine `kill` skips the chainstate flush and
`run-node.sh` reads a deterministic failure. Separately, only the ring buffer is locked; the
console and file writes are unsynchronized across at least eight thread sources, so lines interleave
mid-line in the very file used for wedge forensics. Core holds one mutex across the whole emit.

---

## GA7 backlog status, re-derived from the code

**15 done · 5 partial · 49 open.** Two status regressions, both worth acting on:

### 🔴 The taproot spend-vector corpus is not in the repository at all **[verified]**

GA7 recorded our taproot script-path coverage as "5 success-only vectors" in
`tests/data/taproot_spend_vectors.json`. **That file is not tracked.** `.gitignore:34` carries a
bare `data/` rule which matches `tests/data/`; `git ls-files tests/data` returns nothing; the
directory does not exist in this worktree at all, while the developer's main checkout has the file
as an untracked artifact dated 2026-05-26.

`load-taproot-spend-vectors` (`tests/bitcoin-core-bip341-tests.lisp:147-150`) opens it with
`with-open-file` and **no `:if-does-not-exist` and no `probe-file` guard**, and the suite is
registered in `bitcoin-lisp.asd:206`. So in any fresh clone or CI checkout the registered test
`taproot-spend-vectors-baseline` signals a `FILE-ERROR` rather than running five vectors.
Version-controlled taproot spend-vector coverage is **zero**, and the generator
(`tests/gen_taproot_vectors.py`) is checked in while its output is not, so nobody reviewing the
repo can see or reproduce what those vectors assert.

Same failure family as the previously recorded `:script-tests`-never-existed and
docs-check-was-a-template incidents: green on the developer's machine, vacuous or broken anywhere
else. **Fix:** narrow the `.gitignore` rule (`/data/` or an explicit path) and commit the corpus.

### Four items recorded open are actually done

**G7-15** (BIP133 feefilter, PR #312), **G7-19** (self-connection detection, #309), **G7-20**
(GetAddr response cache, #310) and **G7-38** (fast rescan via BIP158) are all implemented **and
wired to production call sites** — the agent checked callers specifically, since inert-but-merged
is this project's documented failure mode. GA8 recorded "six items in #309–#314" but only credited
#311/#313/#314. Three of these are exactly the kind of item a future round would otherwise
re-implement from scratch.

### Notable partials

**G7-06** premise partly overtaken by #335–#337: the abort GA7 asked for now exists, but only via
the coins-DB pointer — a chainstate whose coins DB has no pointer yet still proceeds on an empty
index, and no blk-file reindex path exists. **G7-08**: P1/P2 are genuinely wired (the GA8
"counter only increments" defect is fixed and the grant is reached from production, not just
tests); **P3 remains entirely open** — no `CheckForStaleTipAndEvictPeers`, no last-block-announcement
stamp, no `EvictExtraOutboundPeers` rotation. **G7-16**: low-bandwidth-first and delivery-based
promotion landed; single announced blocks are still fetched as `MSG_WITNESS_BLOCK`, never
`MSG_CMPCT_BLOCK`. **G7-33**: the exposure half is closed (non-loopback `-rpcbind` is refused), the
feature is still absent, so an operator cannot legitimately serve RPC off-loopback at all.
**G7-49**: mitigated (timeout cap 15→5) but the adaptive 2–64s disconnect and window-staller
attribution are still missing.

---

## Verified negative results

Cheap to establish, and they close off standing suspicions.

**Test-suite wiring is sound.** All 71 `def-suite` forms declare `:in :bitcoin-lisp-tests`; no
suite is orphaned. The only three test files not registered in `bitcoin-lisp.asd` are the
deliberately-manual live-network scripts. This closes the zero-selection hazard that bit the
project during the Workbench migration. (Note the taproot regression above is a *different*
failure mode: the suite runs, but its data is missing.)

**The `*interrupt-check*` seam is genuinely connected.** Defined in `src/config.lisp:18`, installed
exactly once by `src/node.lisp:1223`, consumed at `node.lisp:778` and
`src/validation/block.lisp:2432,2507` — and `tests/reorg-tests.lisp:2683` asserts the installation
itself, so an edit that stopped wiring it would fail rather than pass vacuously. The project's own
lesson, correctly applied.

**The docs-check gate is non-vacuous.** `docs/manual.lisp` is filled and carries a deliberate red
self-test (`(+ 1 2) => 4`) whose job is to fail, so silently-disabled transcript checking fails the
run. At 38 lines with one substantive transcript it is very nearly empty of coverage — worth
expanding, not distrusting.

**The block-template assembler is a faithful port.** Traced `%select-chunks` against
`BlockAssembler::addChunks` line by line — budget semantics, `MAX_CONSECUTIVE_FAILURES`, the
8000-weight/400-sigop reserves, `-blockmintxfee`'s sat/kvB path all match. The documented
deliberate divergence is strictly tighter on sigops and no looser on weight, so it cannot produce
an over-limit block. Topological safety holds, and both `getblocktemplate` and `generate*` hold the
node lock across assembly *and* `TestBlockValidity`, so there is no stale-tip window.

**Addrman's bucketing maths is sound.** Hash preimages were checked byte for byte rather than
trusted. Ours drops Core's CompactSize length prefixes and concatenates raw, which is safe **here**
because our group encoding is prefix-free — the leading class byte fixes the length, and the one
6-byte case (he.net) cannot collide. Every splitting case was checked; no ambiguity exists. All
constants match Core, and `IsTerrible`/`GetChance` match clause for clause. Our address key adds a
BIP155 network byte Core's `CService::GetKey()` lacks — a strict improvement.

**Chain arithmetic is correct.** The retarget-window off-by-one, `target-to-bits` (including
`0x00800000` renormalisation), `target-to-work`, the testnet 20-minute rule and its walk-back, the
BIP94 basis-block selection, MTP including the partial-chain median index, and the equal-work
tie-break (our strict `>` never displaces the incumbent, consistent with Core's first-seen
ordering) all match. `HeadersSyncState` matches `headerssync.cpp` in all phases with bounded
buffers. `perform-reorg`'s rollback-vs-forward-convergence difference is **not** a lasting
divergence — `retry-best-reorg-candidate` re-selects the fork's valid prefix, so we converge on the
same tip.

**No secret reaches the log.** No path found by which an RPC password, cookie, passphrase, private
key or PSBT is logged; the RPC server file contains no log calls at all.

**Also cleared:** ban/discourage separation is correct (two stores, bounded unpersisted filter,
Core-shaped `banlist.json`); `torcontrol.lisp`'s security-relevant surface (SAFECOOKIE server-proof
verified before responding, cookie length checked); ports and magics match Core on every network;
undo data records the full coin including height and coinbase-ness, so a disconnect replays exactly;
we do not replicate Core's `fChecked` caching, so that hazard does not exist here.

---

## Suggested sequencing

1. **S1-1 and S1-2 together** — both are one-line arithmetic/iteration fixes in the same function,
   both are pure chain splits, and both are verified. Highest value per unit of effort in this
   round.
2. **S1-4 + S2-2 as one change** — identity-preserving `connect-block` fixes both, and S1-4 makes
   `invalidateblock` currently defeasible by a single message.
3. **S1-3** — small, but get an executable control first; it is the one S1 rated medium confidence.
4. **The taproot vector regression** — trivial (`.gitignore` + commit the corpus) and it currently
   means a fresh clone cannot run the suite.
5. **S2-1 signet** — self-contained, and the only finding two agents found independently.
6. **S2-7 config negation**, then the rest of the config cluster — all operator-facing, all silent.
7. **S2-4/5/6 as the peer-hygiene batch** — they share the loopback-address root cause and the
   addrman-accounting gap that undercuts the anti-eclipse work.
8. **S2-3 assumevalid** — needs care; the per-block predicate must go inside the reorg loop.

---

## Reproducing this round (GA9 part 2)

The finder brief, with its full GA1–GA8 exclusion list, is preserved at
`docs/gap-analysis-9-brief.md`. To complete the round, re-run the seven dimensions that died:
`script`, `mempool`, `p2p-wire`, `storage`, `wallet`, `rpc`, `crypto-ser`. Their per-dimension
prompts are in that file.

Then run the adversarial refute-biased verification pass over **all** findings, including the ones
in this report — GA7 and GA8 both had verification change the answer repeatedly (GA8: one refuted,
one upgraded, four downgraded, one sharpened), and this round has not had it.

**Method note for next time:** twelve concurrent deep-reading agents exhausted the session budget
about two-thirds of the way through. Run them in batches of four to five, persisting results after
each batch, rather than all at once.

---

# Part 2 findings

Part 1 lost seven dimensions to an API session limit. They are being re-run in batches of four.
This section records what those re-runs found; the scope table at the top is updated as each
lands.

## S1-5. `getblocktxn` is served from any block at any depth, with no rate limit **[verified]**

Core serves a `blocktxn` only from the most-recent-block cache or from a block at
`height >= ActiveChain().Height() - MAX_BLOCKTXN_DEPTH`, where `MAX_BLOCKTXN_DEPTH` is **10**
(`src/net_processing.cpp:140`, with a `static_assert` tying it to `MIN_BLOCKS_TO_KEEP`). For
anything deeper it deliberately refuses to build a blocktxn and queues a full `MSG_WITNESS_BLOCK`
getdata instead. Core's own comment names the reason (`net_processing.cpp:4380-4387`):

> Sending a full block response instead of a small blocktxn response is preferable in the case
> where a peer might maliciously send lots of getblocktxn requests to trigger expensive disk reads,
> because it will require the peer to actually receive all the data read from disk over the network.

`handle-getblocktxn` (`src/networking/protocol.lisp:1945-1966`) has **no depth test at all**. It
calls `get-block` on whatever hash the peer names and replies with only the indexes requested. Its
docstring shows the author considered availability ("Skipped if we don't have the block on disk")
but not depth.

`get-block` (`src/storage/blocks.lisp:91-122`) has **no cache**: every call does `probe-file`, opens
the block's file, allocates `(file-length stream)` bytes, `read-sequence`s the whole thing, and
fully deserializes it — verified by reading the function.

And `check-peer-rate-limit` (`src/networking/peer.lisp:1655-1673`) has buckets for
inv/tx/addr/addrv2/getdata/headers/getheaders/getblocks/getaddr; **`getblocktxn` falls through to
`(t nil)` — no limit at all** — verified by reading the cond.

Direction: **we do expensive work Core refuses to do.** All historical block hashes are public, so
any connected peer can do this. A getblocktxn naming a random old block and one index costs the
attacker ~40 wire bytes and costs us a random-file open, a full read and a full parse of up to a
4 MB block, for a ~250-byte reply. The pump grants each peer 32 messages per pass
(`+max-messages-per-peer-per-cycle+`), and the 64 KiB byte budget is irrelevant at 40 bytes per
request — so one peer sustains 32 whole-block reads and parses per pass, on the single sync thread
that also runs block validation, the pump and peer maintenance.

Contrast `handle-getdata` for blocks, which is self-limiting: the `connection-send-paused-p` break
and the 1 MB send cap force the attacker to actually receive the data. `getblocktxn` is the one
path where reply size is decoupled from work done.

**Fix:** look the hash up in the block index and serve a blocktxn only within 10 blocks of the tip;
for anything deeper, fall back to the full-block getdata path as Core does. **Placement constraint:
the depth test must run before `get-block`, or the disk read the fix exists to prevent has already
happened.** Adding a `getblocktxn` rate-limit bucket is worth doing but is not sufficient on its
own — Core's bound is structural, not rate-based.

## S2-8. Receive byte accounting is keyed on the peer's raw command string in an unbounded table

Core initialises `mapRecvBytesPerMsgType` once per `CNode` with every entry of
`ALL_NET_MESSAGE_TYPES` plus `NET_MESSAGE_TYPE_OTHER`, and folds anything unrecognised into the
OTHER bucket under an explicit comment: *"To prevent a memory DOS, only allow known message types"*
(`src/net.cpp:684-691`). The map is a fixed small size for the life of the connection.

`%account-message` (`src/networking/peer.lisp:493-496`) does
`(incf (gethash command table 0) ...)` with `command` taken straight from the wire, so **every
distinct command string a peer sends creates a permanent new entry**.

An unrecognised command is otherwise a complete no-op — no rate-limit bucket, and `handle-message`
falls through to `(t nil)` — so nothing disconnects the peer or even notices. A 24-byte message
with a fresh random type field costs the attacker 24 bytes and costs us a hash entry plus a string
key, never reclaimed until the peer disconnects. Bounded by the 32-messages-per-pass cap it is slow,
but it is unbounded and ends in OOM against a peer that simply stays connected.

The table is load-bearing for header-sync rotation (`%peer-headers-bytes`), so it cannot just be
dropped. **Fix:** give `%account-message` Core's shape — a constant list of known types, everything
else folded into one `"*other*"` key **before** the `gethash`, or the entry is already created.

## S2-9. The inbound handshake runs inline on the accept thread and its timeout is renewable

Core's `CreateNodeFromAcceptedSocket` (`src/net.cpp:1761-1869`) does the ban checks, constructs the
`CNode`, calls `InitializeNode`, pushes it onto `m_nodes` and returns — **not a single blocking read
in the accept path**; VERSION/VERACK are ordinary messages handled asynchronously.

`run-inbound-listener` (`src/node.lisp:637-682`) performs the whole handshake inline on the one
accept thread, and `%await-verack` calls `receive-message-blocking` in a `loop repeat 10` where each
call computes a **fresh** deadline of `now + timeout` (`peer.lisp:648-650`).

So the budget per connection is up to 15s in v2 detection, 15s for VERSION, then up to 10 × 15s in
`%await-verack` — and the loop only exits early when the peer goes *silent*. A peer sending any
complete non-verack message (a 32-byte ping suffices; no cond clause matches it, so it just loops)
once every ~14.9s holds the accept thread for **~165–180 seconds** for ~300 bytes of traffic.
`accept-connection` is not called during that window, so the listen backlog fills and the node
accepts effectively no inbound peers. The listener docstring's claim that "a silent peer stalls the
loop only briefly" is true for the silent case and false for this one.

Consequence is loss of inbound connectivity and peer diversity, not loss of the node.

**Fix (small):** give `perform-inbound-handshake` **one absolute deadline** for the whole handshake
— as `v2-handshake-outbound` already does via `%v2-deadline` — and pass the remaining time into each
step, capping a connection at ~15s. The deadline must also cover v2 detection, which today gets its
own independent 15s. **Fix (structural, matches Core):** hand the accepted socket to a handshake
worker or to the pump as a `:handshaking` peer so the accept loop never blocks — which is what the
file's own "a thread pool is a future refinement" note anticipates.

## S3. The v1 12-byte message type is never validated

Core checks `hdr.IsMessageTypeValid()` after the checksum (`src/net.cpp:826`), requiring every byte
up to the first NUL to be printable ASCII `[0x20,0x7E]` and all bytes after it to be zero
(`src/protocol.cpp:26-43`); failure drops the message without disconnecting. Our `bytes-to-command`
(`src/serialization/messages.lisp:68-71`) truncates at the first zero byte and `code-char`s the
rest — no printability check, no all-zeros-after-NUL check.

So `"inv\0" + 8 arbitrary non-zero bytes` dispatches here as an ordinary `inv` while Core discards
it. **The v2 path already implements both checks** (`v2-transport.lisp:255-262`) — only v1, the
default transport, is unguarded. No consensus or funds consequence, but it is a wire-format
acceptance divergence any conformance corpus will flag, and it widens the key space of S2-8 to
arbitrary byte values.

**Fix:** mirror `protocol.cpp:26-43` and call it where Core does — **after** the checksum, on the
drop-message-keep-peer path, not alongside the bad-magic disconnect. That requires keeping the raw
12 bytes to the checksum point rather than converting to a string at header-parse time.

### Cleared in this dimension

The resumable readers survived an adversarial read: framing invariants hold across pump passes,
`%abandon-receive` is reached on every path that consumed bytes, `recv-framing` cannot be crossed
between v1 and v2, and `MAX_PROTOCOL_MESSAGE_LENGTH` is enforced from the parsed header before
payload allocation. BIP324 matches `bip324.cpp` throughout — garbage bound, terminator, HKDF
salt/labels, session-id, key wiping, the FSChaCha20 rekey nonce and the FSChaCha20Poly1305
`{packet_counter, rekey_counter}` nonce including the `0xFFFFFFFF` rekey keystream and the
constant-time tag compare. Every per-message count cap is present and enforced before allocation
(`MAX_INV_SZ`, `MAX_HEADERS_RESULTS`, `MAX_ADDR_TO_SEND`, `MAX_LOCATOR_SZ`, `MAX_ADDRV2_SIZE`,
BIP152 and BIP157 limits), and `%read-n-vector` builds via a list so a hostile count fails on
truncation rather than pre-allocating. SOCKS5 is a faithful port of `netbase.cpp`'s `Socks5()`.

**One item left explicitly unresolved:** whether the pump's `data-available-p` readiness gate can
miss bytes already sitting in the SBCL fd-stream buffer and strand batched messages. It turns on
whether `usocket:wait-for-input` pre-checks `(listen (socket-stream x))`, which could not be
confirmed without reading usocket's source in the container. Worth a one-line check by whoever can.

## S2-10. A reorg never flushes the coins cache, so a deep disconnect grows it without bound

Core calls `FlushStateToDisk(state, FlushStateMode::IF_NEEDED)` at the end of **both**
`DisconnectTip` (`validation.cpp:2965-2968`) and `ConnectTip` (`:3093-3096`). `IF_NEEDED` trips on
`CRITICAL`, so the coins cache is size-checked once per connected *and* once per disconnected
block, **including inside a reorg**.

Our only flush trigger, `maybe-periodic-flush`, has exactly one call site in the whole tree: the
fast-forward branch of `connect-block` (`src/validation/block.lisp:1925`). `perform-reorg`'s
phase-A disconnect loop, phase-B connect loop and phase-C tail contain **no flush and no cache-size
check at all**. We also implement only Core's `LARGE` threshold and have no `CRITICAL` equivalent.

Every disconnected block restores all its spent prevouts into the cache as dirty entries and every
connected fork block adds its outputs, with nothing draining them. At the file's own ~200 bytes per
entry, a 2,000-block mainnet reorg is multiple GB on a heap this project has already been OOM-killed
on twice for this exact cache.

The sharpest path is not a natural reorg: `dumptxoutset` with a rollback target calls
`invalidate-block` → `perform-reorg`, and on mainnet a rollback to the published assumeutxo height
disconnects tens of thousands of blocks in one uninterrupted, unflushed loop. `invalidateblock` with
a deep hash does the same.

Not a consensus divergence — a self-inflicted node kill, sitting exactly where PRs #333–#338 made
mid-reorg flushing *safe for the first time*.

**Fix:** call the size check at the bottom of both reorg loop bodies — **after** the coins mutation
and **after** the `cvc-best-block` move, never between them. The pointer must already name the block
whose coins are in the cache, which is the same block-boundary invariant phase 3b established for
`*interrupt-check*`. Add a CRITICAL threshold so the mid-reorg check only fires when it must.

## S2-11. `gettxoutsetinfo` flushes and clears the live coins cache from an RPC thread without the node lock

Core takes `cs_main` inside `ForceFlushStateToDisk(wipe_cache=false)` — which maps to
`CCoinsViewCache::Sync`, writing dirty entries **without clearing** — and then, still under
`LOCK(::cs_main)`, snapshots the CoinsDB view and cursor (`rpc/blockchain.cpp:1075-1084`). The scan
then runs over a LevelDB cursor, an immutable snapshot.

We take the node lock only long enough to *read* the coins-view slot, then run the whole pass
unlocked. `%coin-view-iterate` begins with `coins-view-cache-flush`, which MAPHASHes the live
entries table into a writebatch and then **CLRHASHes it** and zeroes the counters
(`coins-view-cache.lisp:249-262`). The sync thread mutates that same table under the node lock.

Two silent failure modes. Entries the validation thread inserts while the RPC thread is inside
MAPHASH may not be visited, and the following CLRHASH drops them unwritten — a dropped tombstone
leaves a spent coin alive in LevelDB (we would accept a double-spend Core rejects); a dropped add
loses a real UTXO. And the batch also stages `cvc-best-block`, which `apply-block-to-utxo-set` only
moves *after* the whole block is applied — so a flush landing mid-apply commits half of block N
under the pointer for N-1, precisely the coins/pointer disagreement #333–#338 exist to make
impossible. Concurrent SBCL hash-table mutation during MAPHASH/CLRHASH is undefined behaviour on
its own terms.

**Fix:** follow Core — flush under the lock, create the iterator under the lock, then release and
scan the snapshot. **Load-bearing constraint: the flush and the iterator creation must be in the
same lock acquisition**, or coins connected in between are in neither. Add a Sync variant (write
dirty, keep entries) so an RPC does not also throw away the warm cache mid-IBD.

## S2-12. No `Uncache`: rejected transactions pull coins into the cache until the next block

Core records every prevout not already cached (`coins_to_uncache`, `validation.cpp:851`) and on any
non-VALID result calls `CoinsTip().Uncache()` on them, with the comment stating the purpose
verbatim: *"to prevent memory DoS in case we receive a large number of invalid transactions that
attempt to overrun the in-memory coins cache"* (`:1787-1790`). It then flushes PERIODIC, so the
cache is size-checked once per submitted transaction.

We have **no Uncache at all** — the cache exports no such operation — and our only size check is in
`maybe-periodic-flush`, reachable solely from `connect-block`. `fetch-coin` inserts every base-view
hit into the cache and bumps the accounting.

A peer streaming transactions whose inputs reference many distinct confirmed UTXOs — each rejected
*after* input fetch, e.g. for a bad signature — makes us retain one entry per distinct prevout with
no eviction until the next block connects. A ~1 MB transaction can name ~24,000 outpoints, so the
amplification is several times the bandwidth, held for a whole inter-block interval.

**Fix:** collect fetched-but-not-previously-cached outpoints and drop them on rejection. Core's
`Uncache` is `if (it != end && !it->second.IsDirty()) erase` — **the not-dirty guard is
load-bearing**; dropping a dirty entry loses a real write.

## S2-13. The txindex keeps every txid in an in-memory hash table, so `-txindex` cannot run on mainnet

Core's TxIndex is a pure LevelDB index with **no in-memory map**: `ReadTxPos` is a single DB read,
`WriteTxs` a batch write (`index/txindex.cpp:32-75`). Ours is an append-only 68-byte-record file
**plus a full in-memory hash table** mapping every txid to its offset, rebuilt by walking the entire
file on every startup, with each lookup re-opening the file.

At roughly 80 bytes per SBCL `equalp` entry, mainnet's ~1e9 transactions is on the order of 100 GB
of heap, and startup must stream tens of GB before serving anything. The node dies of heap
exhaustion during backfill — a hard OOM, not a diagnosable refusal. An advertised opt-in feature
that is unusable on the network the node claims to support.

**Fix:** move it to LevelDB as the block-filter and coinstats indexes already are. That deletes the
in-memory table, the startup replay and the per-lookup file open in one step, and gives the index
the persisted best-block marker it currently lacks entirely. (Related: G7-05, no startup catch-up.)

## S3 (storage)

`loadtxoutset` never writes the snapshot chainstate's coins-DB best-block pointer — the one thing
Core's comment calls out as *"Important that we set this"* (`validation.cpp:5884-5889`), and which
Core even stamps with a placeholder mid-load so its `assert(!hashBlock.IsNull())` can never fire.
Our populate path writes coins straight to LevelDB, bypassing the cache, and never sets it, so the
newly populated DB has a full UTXO set and no `DB_BEST_BLOCK`. Narrow window, but it silently opts
the assumeutxo chainstate out of the very invariant #333–#338 established.

`gettxoutsetinfo` makes **three** independent flush-and-rescan passes (distinct txids, total amount,
set hash) where Core computes all of it in one cursor pass, and reports the *chain* tip as
`bestblock` where Core reports the *coins DB's own* pointer. So its hash, counts and height can
describe different UTXO states — and `hash_serialized_3` is the assumeutxo commitment, so a
self-inconsistent `(height, hash)` pair can be produced that no Core node will reproduce. Each pass
also wipes the warm cache, which Core explicitly avoids via `wipe_cache=false`.

Three storage LevelDB scans never call `leveldb-iter-check-error` — the project's **own** helper,
whose docstring says any caller whose result is only meaningful if it saw every record must call it.
A grep finds one caller, in the wallet. Worst case is `erase-all-coins`: a truncated wipe reports a
count as if the set were emptied, and reindex then replays every block on top of the survivors,
leaving historically-spent outputs in the UTXO set. Needs a real I/O error, so S3 — but the silence
is the defect.

`coins-view-cache-add` marks a brand-new slot FRESH even when the caller passed `:allow-overwrite`.
Core computes `fresh` **only** inside `if (!possible_overwrite)` (`coins.cpp:94-113`), and its
`BatchWrite` throws `std::logic_error("FRESH flag misapplied to coin that exists in parent cache")`.
The reachable caller passes `:allow-overwrite` for *every* coinbase, so the trigger is a genuine
BIP30 duplicate coinbase whose overwriting output is spent before the next flush — latent today
(those outputs are unspent), but it is exactly the guard Core writes and we dropped.

### Cleared in this dimension

FRESH/DIRTY semantics of `coins-view-cache-spend` and of the flush's put/erase decision match
`CCoinsViewDB::BatchWrite`; the single-level cache plus flush-and-clear discipline makes the
disconnect-path FRESH derivation sound apart from the `:allow-overwrite` gap above. The
`cvc-best-block` movement and same-batch commit are correct, including phase-3b truncation — the
coins really are at the stop entry's state at the top of each disconnect iteration.
`coin-muhash-element` is byte-for-byte `TxOutSer`; MuHash3072 matches (modulus, SHA256-then-ChaCha20
expansion, LE load, fraction form, `Finalize` inverse). BIP158 matches throughout: element set with
OP_RETURN and empty excluded on outputs and empty only on prevouts, dedup, P=19/M=784931,
FastRange64, Golomb-Rice, and the header chain including the genesis anchor. The whole compressor
matches, including the six special script forms with the on-curve check and `VARINT`'s `-1`
non-final offset. Snapshot v2 layout, undo format (height and coinbase persisted, so restored coins
keep maturity), the coinstatsindex design and rewind, and the 3-phase flush marker discipline all
match.
