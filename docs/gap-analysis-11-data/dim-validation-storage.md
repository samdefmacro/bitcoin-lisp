# GA11 dimension 9 — second reader of the validation and storage seam

Lens: crash consistency across the write pairs, ReplayBlocks, VerifyDB, the prune /
assumeutxo / background-chainstate interactions, reorg depth and undo availability, and the
delta log's truncated frame. Findings: `dim-validation-storage.json`.

Ours: `src/validation/block.lisp`, `src/storage/chain.lisp`, `src/storage/coins-view-cache.lisp`,
`src/storage/coins-view.lisp`, `src/storage/blocks.lisp`, `src/node/flush.lisp`,
`src/node/recovery.lisp`, `src/node/reindex.lisp`, `src/node/assumeutxo.lisp`,
`src/node/shutdown.lisp`, `src/node/init.lisp`.
Core: `validation.cpp` (FlushStateToDisk, ActivateBestChainStep, ConnectTip/DisconnectTip,
ReplayBlocks, VerifyDB), `node/chainstate.cpp`, `node/blockstorage.cpp`, `coins.cpp`, `txdb.cpp`.

## Result

5 findings: 1 S1, 3 S2, 1 S3. Three are executed on the project container.

| id | sev | what |
|---|---|---|
| `bbf6e679` | S1 | the coins-DB best-block pointer survives `-reindex-chainstate`'s wipe, so a crashed reindex restarts at the old tip over an EMPTY UTXO set and calls it a recovery |
| `dc27ca3a` | S2 | a snapshot chainstate's header-index delta is bound to a stale snapshot CRC; the whole delta is discarded at the next start |
| `b07c72f4` | S2 | delta replay leaves two entry objects per refreshed block; the active-chain walk hands out the orphan and reorg status writes land on it |
| `4452772a` | S2 | VerifyDB never runs at startup, and `verifychain` stops at Core's level 1 |
| `ce759c52` | S3 | every periodic flush empties the whole coins cache; Core `Sync`s on the time/count trigger and only `Flush`es on LARGE/CRITICAL |

`bbf6e679` and `4452772a` compound: Core's level-3 startup pass disconnects the last six blocks
against the coins cache and would refuse to start on the state `bbf6e679` produces.

## What was run

Warm image in this worktree (`scripts/dev.sh start`, `cl-workbench repl start`), four probes loaded
into `BITCOIN-LISP.TESTS` so the package-local nicknames resolve.

1. **Delta replay object graph.** Snapshot two linked entries, change the parent, append the delta,
   reload. `index[A]` came back `:INVALID`/data-pos 4242 while `B`'s `prev-entry` came back
   `:HEADER-VALID`/`NIL` and was not `EQ` to `index[A]`.
2. **Active-chain walk.** G-A-B-C all `:valid` with positions, snapshot, prune A (clear
   file/data-pos), delta, reload. `collect-chain-entries` from the tip returned the height-1 orphan;
   applying `%reorg-disconnect`'s own `(setf status :header-valid)` over the walked list left the
   live entry `:VALID`, and `%changed-header-index-entries` then saw 2 changed entries, not 3.
3. **Dual-chainstate delta CRC.** cs1 wrote the full snapshot (crc `b28c37cf`); a cs2 built exactly
   as `%make-snapshot-chainstate` builds it reported crc `NIL`, wrote its own full snapshot, deleted
   the delta and took crc `54642735` while cs1 kept `b28c37cf`. An `:invalid` mark persisted through
   cs1 afterwards read back `:HEADER-VALID` after a reload.
4. **Crashed `-reindex-chainstate`.** Regtest node, LevelDB coins view, 5 blocks mined and flushed
   (pointer = tip, height 5). Reproduced the crash state (`update-chain-tip` genesis +
   `save-state :in-transition t` + `coins-view-cache-wipe`): the pointer still named the old tip.
   `load-state` `:INCONSISTENT`; `recover-inconsistent-chainstate` -> T, height 0, amount 0;
   `reconcile-coins-db-best-block` -> `:RECONCILED`, height **5**, tip = old tip, UTXO count **0**.

## Verified correct, no finding filed

- `%replay-header-index-delta`'s truncated-frame stop: a short frame, a CRC failure, a zero count
  and an over-long frame all terminate replay and keep every complete frame before it.
- The delta-version gate replays a v1 log at its own 185-byte width rather than discarding it
  (discarding reverts statuses, which is the failure the format's docstring names).
- blk/rev records are fsynced per write, stricter than Core's `FlushBlockFile`.
- `%flush-chainstate` Phase 1 writes the header index BEFORE the coins batch, matching Core's
  `WriteBlockIndexDB` -> `CoinsTip().Sync()` order; `persist-block-index-for-coins-write` covers the
  RPC sync sites that never reach the flush.
- The coins best-block pointer is staged in the SAME writebatch as the coin puts/erases.
- `%save-undo-flat`'s write-once guard (Core `if (block.GetUndoPos().IsNull())`).
- `perform-reorg`'s five pre-mutation refusals: fork below the pruned height, an `:invalid` block on
  the target branch, the witness-stripped self-heal, missing bodies on either side (returned as a
  re-queue list), and `:corrupt-undo` for a spending block with no undo record.
- `+min-blocks-to-keep+` = 288 = `MIN_BLOCKS_TO_KEEP`; `+prune-lock-buffer+` = 10 =
  `PRUNE_LOCK_BUFFER`; the prune window's lower bound is `chain-state-prune-range-start`, not the
  walk cursor (GA10 `fdbe8a5e`).

## Examined and deliberately not filed

`%coinbase-committed-p`'s monotone-probe premise is false for a block whose coinbase output 0 is
provably unspendable — `script-unspendable-p` outputs are dropped from the UTXO set
(`coins-view-cache.lisp:635`) — so the recovery walk can rewind further than the truth. It does not
matter, because `reconcile-coins-db-best-block` runs afterwards and moves the record back to the
exact pointer; the cost is a longer walk and a misleading log line. The same probe returns NIL for
genesis, so any walk reaching height 0 ends in "no committed ancestor found on disk" and a refusal
to start, but I could not construct a reachable path to that.

## Not covered — who inherits it

- Per-index best-block markers and their startup catch-up/rewind (`index-base`, txindex,
  blockfilterindex, coinstatsindex, txospenderindex) — **storage-indexes**.
- assumeutxo snapshot LOADING and hash verification (`loadtxoutset`, the metadata format,
  promote/rename of `chainstate_snapshot/`) — **storage-indexes**, or a dedicated assumeutxo pass.
  Only the dual-chainstate *flush and prune* interactions were read here.
- The LevelDB wrapper itself (`bl.kv`: WAL, fsync, iterator lifetime, error surfaces) — treated as
  sound; **never-opened-files**.
- The flat block-file framing (magic, length prefix, `%scan-flat-block-files` enumeration) was read
  but not fuzzed — the **differential encode/decode harness** lane.
- mempool.dat, fee-estimate and banlist persistence — out of scope for this dimension.
- Nothing was run against a real testnet4 datadir, so no claim here rests on production-scale
  timing.
