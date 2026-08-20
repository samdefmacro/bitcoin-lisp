# Core Block-File Format (blk/rev + XOR) — Implementation Plan

Date: 2026-07-10. Status (2026-08-20): **P0-P5 BUILT.** P0 undo codec, P1 flat-file
engine, P2 index integration + dual read, P3 file-granular pruning, P4 migration
(`migrateblocks` RPC), P5 `reindex-block-index`. Live on testnet4 for NEW blocks
(`:flat-block-files t`); mainnet stays off until the testnet4 soak and the migration
have both been exercised there. P4 deliberately deviates from the plan's "one-shot
offline converter": see below.
Reference: Bitcoin Core `refs/bitcoin/` @ d3056bc (v30-dev). Researched via 2 agents
(Core block/undo storage byte-level; our storage architecture).

## 1. Framing

Purely an **internal storage format** change — zero protocol/consensus impact. What it buys:

- **Scale**: today = one file per block, hash-named (`blocks/<hex>.blk`,
  src/storage/blocks.lisp:34-38) + one undo file per block. Unpruned mainnet ⇒ ~900k+900k files
  in two directories; every `block-exists-p` is a `probe-file` stat; `init-block-store` is a
  full directory scan (blocks.lisp:105-124). Core's model = ~128 MiB append-only files (~250
  for pruned targets we run) with O(1) offset reads.
- **Interop**: external tools can parse blk files; a Core node's blocksdir could be imported.
- **Full `-reindex`**: rebuild the block index by scanning blk files (we currently only have
  `-reindex-chainstate`; a corrupted header index today means resync).
- **XOR obfuscation**: avoids AV/DPI false-positives on raw block patterns on disk.
- Fewer fsyncs: per-block `fsync` today (blocks.lisp:79-85) → per-file-rollover + periodic.

Costs: touches every block/undo IO path and **requires a migration story for the two live
production nodes**. Recommend doing this last of the four plans, or when file-count pain
actually materializes. Good synergy: the TxOutCompression module (P0) is shared with
assumeutxo-plan P0, and the plan removes the odd one-file-per-block undo format.

## 2. Core on-disk spec (byte-exact targets)

### blk/rev flat files (node/blockstorage.{h,cpp}, flatfile.{h,cpp})
- Names `blk%05u.dat` / `rev%05u.dat` in blocksdir; `MAX_BLOCKFILE_SIZE` 128 MiB; preallocation
  chunks 16 MiB (blk) / 1 MiB (rev); finalize = truncate to used size + fsync + dir-fsync.
- **Block record**: `[4B network magic][4B u32 LE length][serialized block with witness]`;
  length counts only the block; stored `nDataPos` points **after** the 8-byte header.
- **Undo record**: `[4B magic][4B u32 LE length][CBlockUndo][32B checksum]` where checksum =
  **double-SHA256( prev-block-hash ‖ serialized CBlockUndo )** (blockstorage.cpp:996-999);
  `nUndoPos` points at the CBlockUndo. Undo lives in the **same file number** as its block, in
  validation order (rev files lag blk files; two finalize triggers, blockstorage.cpp:866-871,
  1010-1026). Genesis never has undo.
- **CBlockUndo** (undo.h): vector<CTxUndo> (one per tx excluding coinbase); CTxUndo =
  vector<per-input Coin>: `VARINT(height*2 + coinbase)`, legacy dummy byte if height>0, then
  TxOutCompression (compressed amount varint + compressed script) — NOT our current
  per-entry `txid+index+value+height+coinbase+script` format (validation/block.lisp:1366-1383).
- Reads: `ReadRawBlock` verifies magic + length ≤ MAX_SIZE and can serve wire bytes directly
  (getdata serving without deserialize); `ReadBlockUndo` re-derives the checksum via a hash
  verifier seeded with prev-hash.

### XOR obfuscation
`xor.dat` in blocksdir = exactly 8 raw bytes; random only on a **fresh** blocksdir (else zero
key); pre-existing file always wins; `-blocksxor` default true; applied to blk+rev streams as
`plain[i] = disk[i] XOR key[(file_offset+i) mod 8]` (streams.cpp:21-31,115-127). Not applied to
the index DB. (Distinct from the LevelDB obfuscation record format — don't conflate.)

### Block index records (Core keeps them in a LevelDB at blocks/index)
`'b'+hash → CDiskBlockIndex`: `VARINT(dummy client version)`, `VARINT(nHeight)`,
`VARINT(nStatus)`, `VARINT(nTx)`, then **conditionally** `VARINT(nFile)` iff HAVE_DATA|HAVE_UNDO,
`VARINT(nDataPos)` iff HAVE_DATA, `VARINT(nUndoPos)` iff HAVE_UNDO, then the fixed 80-byte-header
fields minus prev-linkage recomputation (nVersion i32, hashPrev, merkle, nTime, nBits, nNonce);
hash not stored, PoW re-checked on load. `'f'+n → CBlockFileInfo` (all VARINT: nBlocks, nSize,
nUndoSize, nHeightFirst/Last, nTimeFirst/Last); `'l'` last file; `'R'` reindex-in-progress flag;
`'F'/"prunedblockfiles"` flag. BlockStatus: validity level 0-5 in low bits + HAVE_DATA(8)/
HAVE_UNDO(16)/FAILED_VALID(32)/OPT_WITNESS(128).

### Pruning (file-granular)
Target = Σ(nSize+nUndoSize) over files; `FindFilesToPrune` deletes whole blk+rev pairs whose
height range lies entirely below the prunable ceiling (tip−288), skipping until
`usage + buffer < target`; per-block: clear HAVE_DATA/HAVE_UNDO + zero positions;
**prune locks** protect index tails (blockfilterindex sets one; 10-block buffer;
blockstorage.h:147-149, validation.cpp:2719-2734). `-prune=1` = manual (pruneblockchain RPC).

### -reindex
Wipes block index (+ chainstate) but NOT blk files; `'R'` flag persists across interruption;
`ImportBlocks` probes `blk%05u.dat` from 0, `LoadExternalBlockFile` hunts the magic byte-wise,
tolerates garbage, parks out-of-order blocks in an unknown-parent multimap keyed by prev-hash
and drains recursively after each accept (validation.cpp:4988-5155).

## 3. Where we are (delta)

- No file/offset anywhere: `block-index-entry` (chain.lisp:10-21) and the headerindex.dat v2
  record carry no nFile/nDataPos/nUndoPos — but headerindex.dat has **format-version machinery**
  (chain.lisp:348-351,488-502), so a v3 record is a clean bump.
- IO is well-funneled (contained swap): block writes at exactly 4 sites
  (validation/block.lisp:1490, 2164; ibd.lisp:1888, 1918), reads via `get-block` (~17 sites) and
  undo via `get-undo-data` — all behind src/storage/blocks.lisp + the undo functions.
- `block-store` already keeps an O(1) `total-bytes` counter (blocks.lisp:18-26) ≈
  `CalculateCurrentUsage`.
- Pruning today is per-block deletion with a monotone `pruned-height` (blocks.lisp:146-211);
  the RPC + auto-prune semantics carry over, the granularity changes.
- txindex is hash-based (txid→block-hash+position) — storage-layout-agnostic, unaffected.
- We do NOT port Core's blocks/index LevelDB (decision below): our headerindex.dat +
  chainstate.dat 3-phase flush is the established, crash-tested persistence.

## 4. Staged milestones

| Phase | Deliverable | Size |
|-------|-------------|------|
| **P0** | TxOutCompression codec (**shared with assumeutxo-plan P0**) + Core CBlockUndo serializer/deserializer; byte-exact tests vs Core vectors | S |
| **P1** | Flat-file engine, standalone: FlatFileSeq (naming, chunked preallocate, truncate-finalize, fsync discipline incl. checked close), record framing (magic+len), undo checksum, XOR AutoFile layer + xor.dat lifecycle; unit tests incl. offset-mod-8 XOR and magic-hunting reader | M |
| **P2** | Index integration: `block-index-entry` gains file/data-pos/undo-pos + have-data/have-undo bits; headerindex.dat **v3**; per-file `CBlockFileInfo`-equivalent tracking persisted (into headerindex.dat trailer or a small side file); `store-block`/`get-block`/undo rewired behind the unchanged API; **dual-read**: legacy per-block files remain readable | M-L |
| **P3** | Pruning → file-granular (whole blk+rev pairs; keep monotone pruned-height semantics + `pruneblockchain` RPC; add a blockfilterindex prune-lock equivalent with the 10-block buffer) | M |
| **P4** | **Migration**: `migrateblocks` RPC — an incremental, resumable, budgeted converter that runs ON the live node instead of offline. See §4.1. | M |
| **P5** | *(optional)* Full `-reindex`: ImportBlocks scan + unknown-parent multimap + `'R'`-equivalent resume flag; `-loadblock=` | M |

### 4.1 P4 as built, and why it is not the offline converter

The plan called for a one-shot offline converter writing to a fresh directory. What
shipped is an RPC that converts a budget of blocks in place on the running node, and
the difference is deliberate:

- **Dual read (P2) removed the reason for a second directory.** The rejected
  "fresh-sync-only + permanent dual-read" alternative was rejected for leaving prod on
  the old format forever — but dual read plus an in-place converter gets the format
  change *without* the copy. An offline converter needs free space for a second copy of
  the block data; the mainnet node is the pruned one, on the smaller disk.
- **In-place is safe here because the conversion is per-block and verified.** Each
  block is written flat, read back through the flat path, and only then is the
  per-block file unlinked. A crash costs at most one duplicated block. If the read-back
  fails, the index is put *back* to the per-block file and the walk stops — otherwise
  dual read would serve the copy that just failed to read back.
- **It is budgeted and resumable** (`migrateblocks <nblocks> [start_height]` → `{migrated,
  next_height, remaining}`), so an operator converts a slice, watches the node, and
  continues. An offline converter is all-or-nothing and takes the node down for its
  duration.
- **It walks in height order**, which the offline converter would also have had to do:
  a flat file prunes whole, and only when its whole height range is below the horizon.
  Converting in arrival order would leave a pruned node silently unable to reclaim space.

Off-chain blocks keep their per-block files: they have no place in a height-ordered flat
file, there are few of them, and dual read keeps them served.

MVP boundary: P0-P2 (new format live for new blocks, dual-read for old). P3-P4 complete the
transition; P5 is the recovery-capability bonus that justifies the whole exercise.

## 5. Effort & risk

~8-12 PRs. The dominant risk is **P4 migration on live nodes** (both prod nodes carry years of
per-block files): mitigate with dual-read (P2) so migration is optional-per-node and reversible
(converter writes to a fresh dir, old dir kept until verified — same playbook as the LevelDB
UTXO migration). Second risk: fsync-discipline regressions (we move from per-block fsync to
file-rollover + periodic flush — crash-window analysis needed against our 3-phase
chainstate.dat commit; Core's ordering is blk/rev flush → index write → prune unlink → coins).
XOR + checksum layers are pure functions — low risk, high test coverage available.

## 6. Open decisions

1. Do it at all now? (Recommendation: **defer** until after cluster-mempool/assumeutxo unless
   file-count pain or `-reindex` need arrives first. Pruned nodes = bounded file count today.)
2. Adopt Core's blocks/index LevelDB too, or keep headerindex.dat v3? (Recommend **keep ours** —
   Core-parity of the *index* only matters for external tooling that reads the index itself.)
3. XOR default: on for fresh dirs (Core default) — trivial either way.
4. Undo payload: Core-exact CBlockUndo (recommended — free interop + smaller via compression)
   vs keeping our entry format inside the rev framing.

## 7. Core source anchors

node/blockstorage.{h,cpp}: constants h:118-129, cursors h:151-175/260-279, FindNextBlockPos
833-921, WriteBlock 1134-1165, undo write/read 967-1034/697-730, flush 732-791, XOR init
1167-1222, index load/write 423-589/92-103/510-527, prune 258-400/591-613/804-815, ImportBlocks
1261-1316; flatfile.cpp:29-115; validation.cpp: LoadExternalBlockFile 4988-5155, flush ordering
2699-2837, prune locks 2719-2734; chain.h:42-86 (BlockStatus), 316-376 (CDiskBlockIndex);
undo.h; compressor.{h,cpp}; util/obfuscation.h; streams.{h,cpp}:13-127. Ours:
storage/blocks.lisp (all), storage/chain.lisp:10-21,223-433 (index + persistence + versioning),
validation/block.lisp:1297-1461 (undo), node.lisp:1094-1177 (flush).
