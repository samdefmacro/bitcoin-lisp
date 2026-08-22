# Real Assumeutxo — Implementation Plan

Date: 2026-07-10. Status (2026-08-22): **P0-P6 DONE** (commits "Assumeutxo P5: background-validation completion + promotion" and "Assumeutxo P6: pruned-node snapshots, dumptxoutset rollback, cache rebalancing"; §4 marks P6 only). Open: `loadtxoutset` does not write the snapshot coins-DB best-block pointer (docs/next-wave-2026-08-22.md §2.8).
Reference: Bitcoin Core `refs/bitcoin/` @ d3056bc (v30-dev). Researched via 2 deep-dive agents
(Core assumeutxo end-to-end; our chainstate/storage architecture).

## 1. Framing

Assumeutxo = bootstrap from a UTXO-set snapshot whose hash is committed in chainparams, then
**re-derive the same UTXO set from blocks in the background** and compare. Trust model is identical
to assumevalid: you trust a hash shipped in the source. Not consensus, but consensus-adjacent —
the `hash_serialized` computation and snapshot parsing must be byte-exact or a valid snapshot is
rejected (or worse, an invalid one accepted).

**Where we stand today**: we already ship `dumptxoutset`/`loadtxoutset` RPCs, but in our own
"UTXS" format, and `loadtxoutset` **blind-trusts** the file — it bulk-loads coins and
fast-forwards the single chainstate with no commitment check and no background validation
(src/rpc/methods.lisp:1380-1492). This plan upgrades that to the real thing: Core snapshot
format, hash verification against chainparams, dual chainstate, background IBD, promotion.

Payoff: a usable node at tip in minutes instead of days of IBD, with full-validation security
restored asymptotically. This is the deepest architectural item left in the backlog.

## 2. Core's architecture (v30 — note: NOT the old two-member design)

At d3056bc the old `m_ibd_chainstate`/`m_snapshot_chainstate` pair is gone. The current model
(port this one):

- `ChainstateManager` holds `vector<unique_ptr<Chainstate>> m_chainstates` (validation.h:1377).
- Per chainstate: `enum Assumeutxo {VALIDATED, UNVALIDATED, INVALID}` (validation.h:527-534),
  optional `m_from_snapshot_blockhash`, optional **target block** `m_target_blockhash` (+
  `m_target_utxohash` once done) (validation.h:643-647). Assumeutxo status is **never persisted**
  — re-derived and re-proven by re-hashing on every startup.
- Selection: `CurrentChainstate()` = first non-INVALID with **no target**; `HistoricalChainstate()`
  = non-INVALID with target and no `m_target_utxohash`; `ValidatedChainstate()` = whichever is
  VALIDATED (indexes bind to this) (validation.h:1119-1145).
- `AddChainstate` retargets the previously-current chainstate at the snapshot hash and **moves the
  mempool pointer** to the new one (validation.cpp:6189-6206).
- Shared across chainstates: block index, block/undo files, prune bookkeeping (`m_blockman`),
  `m_best_header`. Per-chainstate: coins DB + cache, `m_chain`, candidate set, target/assumeutxo
  state.

### Key flows

**ActivateSnapshot** (validation.cpp:5607-5747) — preconditions, each a clean error: no existing
snapshot chainstate; `AssumeutxoForBlockhash` entry exists; base **header** already in block index;
header not failed; `m_best_header->GetAncestor(height) == base`; **mempool empty**. Then build the
snapshot coins DB at `chainstate_snapshot/`, populate+verify (below), require snapshot tip has more
work than active tip, write the `base_blockhash` marker file (the only persistent "snapshot exists"
marker), AddChainstate, `PopulateBlockIndexCandidates`.

**PopulateAndValidateSnapshot** (validation.cpp:5773-5973): stream coins in with per-coin checks
(`coin.nHeight <= base_height`, `outpoint.n < UINT32_MAX`, `MoneyRange`); flush every 120k coins
when cache critical (fake random best-block to satisfy flush assert, overwrite with base hash at
end); exact-EOF check ("coins left over"); then `ComputeUTXOStats(HASH_SERIALIZED)` **over the new
DB** and compare to `au_data.hash_serialized` — mismatch deletes the dir. Then fake block-index
state for 1..base: set witness-stored flag where segwit active (so no redownload demand) and seed
`base->m_chain_tx_count = au_data.m_chain_tx_count` (0 is the "unknown" sentinel the design leans
on).

**Background validation**: `ProcessNewBlock` runs ActivateBestChain on the current chainstate AND
the historical one (validation.cpp:4430-4478). Candidate filtering keeps the historical chainstate
on track: `TryAddBlockIndexCandidate` only admits ancestors of the target (validation.cpp:3764-
3794). Net side: `TryDownloadingHistoricalBlocks` requests `[historical tip .. target]` from peers
whose known chain contains the target (net_processing.cpp:1445-1472); while the snapshot is
unvalidated, **refuse tip downloads from peers whose chain omits the base** (no undo below base ⇒
cannot reorg across it) (net_processing.cpp:1412-1421). ABC's connect loop breaks at
`ReachedTarget()`.

**MaybeValidateSnapshot** (validation.cpp:5986-6096) — fires at ConnectTip and at startup: when the
validated chainstate reaches the target, flush it, `ComputeUTXOStats(HASH_SERIALIZED)` over its DB
(held under the main lock — historical chainstate must not move during hashing), compare to
chainparams. Match ⇒ snapshot chainstate becomes VALIDATED, historical marked done. Mismatch ⇒
snapshot marked INVALID, dir renamed `chainstate_snapshot_INVALID` (forensics), **fatal shutdown**.

**ValidatedSnapshotCleanup** (validation.cpp:6299-6364) — startup-only (leveldb dirs are shuffled):
close handles, `chainstate` → `chainstate_todelete`, `chainstate_snapshot` → `chainstate`, delete
old; re-init as a single chainstate. So after a mid-run validation success the node keeps running
dual-state until the next restart, which re-proves the hash once more, then swaps.

**Interactions**: single mempool follows the current chainstate (historical has none). Indexes bind
`ValidatedChainstate()` and drop signals from non-validated roles; on background-sync completion
all indexes are restarted and resume onto the now-validated chain (init.cpp:1367-1383). Pruning:
unvalidated snapshot chainstate's prunable range starts at base+1; prune target halved while a
historical chainstate exists. Services drop to NODE_NETWORK_LIMITED while a historical chainstate
exists. `-reindex`/`-reindex-chainstate` delete the snapshot chainstate outright. `getchainstates`
reports both (historical first, active last); `getblockchaininfo` reports only the active one.

### The two hash/serialization traps (byte-exactness)

1. **Snapshot file format** (node/utxo_snapshot.h:37-106 + rpc/blockchain.cpp:3246-3323):
   magic `"utxo"+0xff` (5B) · version u16=2 · network magic 4B · base blockhash 32B · coins count
   u64. Then coins **grouped by txid**: txid 32B · CompactSize(n-coins) · per coin
   CompactSize(vout) + `Coin` = `VARINT(2*height+coinbase)` + **compressed** TxOut
   (compressed-amount varint + compressed script — compressor.h). Cursor order: txid-lex, vout
   ascending.
2. **hash_serialized_3** (kernel/coinstats.cpp:46-52,111-181): double-SHA256 over per-coin
   preimages in the SAME order, but **uncompressed**: outpoint (txid + vout u32 LE) ‖
   `u32 LE (height<<1 | coinbase)` ‖ CTxOut (value i64 LE + CompactSize script). Grouped per txid
   with vouts numerically sorted.

**Our `compute-utxo-set-hash` is NOT byte-exact** (src/storage/coins-view-cache.lisp:737-761):
it hashes `txid+vout+height(u32)+coinbase(u8)+value+script` — height and coinbase as separate
fields instead of Core's packed `(height<<1|coinbase)` u32. Additionally our LevelDB key stores
vout as **LE u32** (coins-view.lisp:23), whose lexicographic order diverges from numeric vout
order at vout ≥ 256, so raw-cursor-order hashing can mis-order within a txid group. Both must be
fixed (group by txid, sort vouts numerically, pack the code word) before any hash can match Core.
Also: we have **no TxOutCompression** anywhere (our coins/undo use plain encodings) — the
compressed-amount + compressed-script codec is a prerequisite module.

## 3. Integration surface (our code)

From the architecture map (all cites our tree):

- `chain-state` struct (src/storage/chain.lisp:23-30) — gains: `coins-view` slot (move ownership
  in), `from-snapshot-blockhash`, `assumeutxo-status`, `target-blockhash`, `target-utxohash`,
  `storage-suffix`. `node` (src/node.lisp:69-106) — `chain-state`/`utxo-set` slots become a
  **chainstates list** + accessors `current-chainstate`/`historical-chainstate`/
  `validated-chainstate`.
- **Single-chainstate collision points to parameterize** (the P2 refactor checklist):
  `do-flush`/`maybe-periodic-flush` read `*node*` slots (node.lisp:1094-1177) and fire from
  `connect-block` (validation/block.lisp:1552); index hooks `index-block-filter`/`-coinstats`
  read `*node*` (node.lisp:1183-1204,1297-1312) and must drop non-validated-chainstate signals;
  fixed on-disk names `chainstate.dat`, `chainstate/` LevelDB dir, `headerindex.dat`
  (chain.lisp:223, node.lisp:670) need a per-chainstate suffix scheme; crash recovery
  `recover-inconsistent-chainstate` (node.lisp:484-528) per-chainstate; IBD `*ibd-context*`
  anchored to one tip (ibd.lisp:167, 797-844); mempool call sites bind the single utxo-set
  (node.lisp:428-447, protocol.lisp:615, validation/block.lisp:1608-1623); RPC accessors
  (rpc/accessors.lisp:8-31); version-message start-height (peer.lisp:285-296);
  `rpc-getchainstates` already emits the plural shape but hardcodes one entry
  (methods.lisp:83-114).
- **What stays shared** (matches Core): block store (hash-addressed per-block files — height-
  agnostic, so Core's NORMAL/ASSUMED blockfile segmentation is **unnecessary for us**), undo
  storage, header/block index, headerindex.dat (its 185-byte record already persists tx-count —
  the faked `m_chain_tx_count` persists for free).
- **IBD driver**: `find-blocks-to-download-for-peer`/`queue-blocks-for-download` (ibd.lisp:775-844)
  need a second height cursor for the historical range `[historical-tip .. snapshot-base]`, plus
  the peer filter (skip peers whose chain omits the base for tip download).
- Existing `save-file-with-crc32` durability primitives, 3-phase `do-flush`, and
  `script-skip-height`/assumevalid machinery (ibd.lisp:520-560) all reuse cleanly — background
  validation below the base naturally reuses assumevalid script-skipping.

## 4. Staged milestones (node shippable at every stage)

| Phase | Deliverable | Test strategy | Size |
|-------|-------------|---------------|------|
| **P0** | **TxOutCompression module** (compress/decompress amount + the 6 script forms; Core compressor.{h,cpp}) — also a prerequisite for the block-file-format plan's rev files | port Core compress_tests vectors | S |
| **P1** | **hash_serialized_3 byte-exact**: pack `(height<<1|coinbase)` code word, group-by-txid + numeric-vout ordering in `compute-utxo-set-hash`; expose as `gettxoutsetinfo hash_serialized_3` | unit vectors on synthetic coins; end-to-end proof lands in P2 | S |
| **P2** | **Core snapshot format**: rewrite `dumptxoutset`/`loadtxoutset` to the `utxo\xff` v2 format (read+write); `loadtxoutset` gains full content checks (height/vout/MoneyRange/exact-EOF) **and the chainparams hash check**; ship `AssumeutxoData` tables (mainnet 840000/880000/910000/935000, testnet4 90000/120000, signet, regtest — kernel/chainparams.cpp values). Still single-chainstate fast-forward, but now **verified** | **load a publicly distributed mainnet-840000 or testnet4 snapshot and require the hash to match** — this is the real byte-exactness proof for P0+P1+P2 | M |
| **P3** | **Chainstate plumbing refactor** (shadow): chain-state owns its coins-view + storage suffix; node holds a chainstates list; flush/recovery/index hooks/RPC accessors parameterized by chainstate. Exactly one chainstate exists ⇒ behavior unchanged. The collision-point checklist in §3 is the work list | full suite + testnet4 soak, zero behavior change | M-L |
| **P4** | **Dual chainstate + background IBD**: ActivateSnapshot flow (preconditions, populate, candidate filtering by target-ancestor, mempool move, `chainstate_snapshot/` + `base_blockhash` marker, startup detection); IBD dual-cursor (historical range download + base-in-chain peer filter); ABC on both; services → NODE_NETWORK_LIMITED; real `getchainstates` | testnet4 end-to-end: load snapshot at 90000, watch background validation converge | L (the meat) |
| **P5** | **Validation completion**: MaybeValidateSnapshot at connect-tip + startup (hash historical DB at target, compare); INVALID path (rename `_INVALID`, fatal shutdown); startup ValidatedSnapshotCleanup (dir swap, re-init single) | testnet4 full cycle to promotion; corrupted-snapshot negative test | M |
| **P6** | **Interaction polish** — DONE: prune ranges (base+1 floor for unvalidated snapshot cs via `chain-state-prune-floor`; automatic target halved while historical exists via `effective-prune-target-bytes`, floored at 550 MiB) + loadtxoutset pruned refusal lifted; `dumptxoutset` rollback mode (invalidateblock/reconsiderblock with network suspended, Core TemporaryRollback+NetworkDisable); coins-cache rebalancing (`maybe-rebalance-caches`, 95/5 by IBD status, on activation/completion/IBD-exit). Index rebind on completion + `-reindex-chainstate` snapshot-cs deletion shipped earlier in P4/P5 | suite + targeted tests | M |

**MVP boundary = P0–P2**: Core-format, hash-verified snapshot load — interoperable with publicly
distributed snapshots and already a major security upgrade over today's blind trust (same trust
model as Core's load-time gate, minus background re-validation). P3–P5 deliver the real thing.

## 5. Effort & risk

- **~12–18 PRs, multi-session.** P3 (plumbing) and P4 (dual chainstate + IBD) dominate.
- Highest risk: startup ordering + per-chainstate flush correctness (our 3-phase chainstate.dat
  commit becomes per-chainstate; crash-recovery must not cross-contaminate). Mitigation: P3 lands
  as a pure refactor with one chainstate and soaks on both prod nodes before P4.
- Testing leverage: testnet4 ships AssumeutxoData at 90000/120000 — our testnet4 node is the
  perfect end-to-end rig (fresh datadir + snapshot + watch `getchainstates`). For unit-level
  work, add a hidden option to accept a caller-supplied hash (Core's regtest entries pattern) so
  we can dump/load our own snapshots in tests.
- FASL note: `chain-state`/`node` defstruct changes (P3) ⇒ deploy needs `rm -rf ~/.cache/common-lisp`.
- Deploy caution: P3+ touches flush/recovery — deploy one node first (testnet4), verify clean
  restart + crash-recovery paths before mainnet.

## 6. Open decisions

1. **Scope**: stop at MVP (verified Core-format snapshots, P0-P2) or commit to full dual-chainstate
   (P3-P6)? MVP alone is genuinely useful; full background validation is what makes it *assumeutxo*.
2. **dumptxoutset rollback mode** (network-disable + invalidate/reconsider): port or defer? (Defer
   recommended — needed only to *produce* historical snapshots, not to consume them.)
3. Keep our "UTXS" legacy format readable for one release or replace outright? (Replace — it was
   never advertised.)
4. Snapshot heights to ship: mirror Core's tables exactly (recommended, they're the audited values).

## 7. Core source anchors

- Architecture: validation.h:527-534,643-674,1119-1157,1377; validation.cpp:1860-1908 (ctor/paths),
  6098-6134 (selection/rebalance), 6170-6273 (load/add/delete chainstate)
- ActivateSnapshot/populate: validation.cpp:5607-5747, 5773-5973; node/utxo_snapshot.{h,cpp}
- Background: validation.cpp:3125-3135 (trigger), 3370-3508 (ABC target handling), 4430-4478
  (ProcessNewBlock both), 6394-6425; net_processing.cpp:1395-1544, 6164-6199
- Completion/cleanup: validation.cpp:5986-6096 (MaybeValidateSnapshot), 6220-6250 (invalidate dir),
  6299-6364 (ValidatedSnapshotCleanup); node/chainstate.cpp:151-238 (startup ordering incl. the
  candidate-set/sequence-id trap at 129-134)
- Hash + format: kernel/coinstats.cpp:46-52,87-187; rpc/blockchain.cpp:3052-3323 (dump), 3343-3422
  (load); kernel/chainparams.cpp:166-191,400-413,646-667 (shipped hashes); coins.h:63-69;
  compressor.{h,cpp}
- Interactions: blockstorage.cpp:321-400,423-508,771-845 (prune/loadindex/file segmentation —
  segmentation N/A for our per-block store); index/base.cpp:104-114,328-385; init.cpp:1367-1383,
  1946-1953
