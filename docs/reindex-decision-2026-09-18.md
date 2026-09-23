# `-reindex`: match Core, or keep the additive rebuild?

**Status (2026-09-18): DECIDED — option (B).** The additive rebuild stays, and is now a
*stated divergence* rather than an undocumented one: it is written at the option's own entry
(`src/config-options.lisp`), in `docs/manual.lisp`'s storage section, and in
`docs/functional-sweep-2026-09-13.md`, which marks the three wipe-dependent functional tests
as known divergences. The three §6 items that are Core's behaviour *and* cost no block file
were done at the same time: the persisted `'R'` resume marker (`BL.STORE:WRITE-REINDEX-FLAG`,
bracketing `%REBUILD-BLOCK-INDEX-FROM-BLOCK-FILES`, read back by `%REINDEX-REQUESTED-P`),
deletion of an assumeutxo snapshot chainstate under either reindex flag
(`%INIT-RECOVER-CHAIN`), and a wipe-and-resync of every enabled index (`OPEN-INDEX-DB`'s
`:wipe`, driven from `%START-INDEXES`). The deferred half is unchanged: wiping
`blocks/index`, wiping the chainstate, and deleting pruned block files, none of which should
be attempted before the three earlier functional failures in §3 are fixed and a local
block-connect rate has actually been measured.

**Re-checked 2026-09-23 (batch AM): the unpruned wipe stays deferred.** Round 6 ported the
pruned half (`4b0e3cf4`, WIPE-FOR-PRUNED-REINDEX: Core's `CleanupBlockRevFiles`, header
index, chainstate, coins db, indexes). All three §3 tests now get past their reindex
assertions: `feature_remove_pruned_files_on_startup` and `feature_index_prune` pass, and
`feature_assumeutxo` -- once batch AM let its background validation finish -- runs through
`:725-728` and `:791-794` and fails later, at `:799` (an IBD node downloading from a
NETWORK_LIMITED peer). So no functional test in the sweep needs the UNPRUNED wipe: the pieces
they exercise (the snapshot chainstate deleted, the indexes wiped, the pruned files cleaned
up) are all ported. What the unpruned wipe would add is Core's operator semantics -- a
`-reindex` that discards `headerindex.dat` and the chainstate and reconnects every block --
and §6's second condition for it still does not hold: no local block-connect rate has been
measured, and the node that would pay is the unpruned testnet4 node with three indexes. The
additive rebuild therefore remains the stated divergence for the unpruned case; measure a
from-disk connect rate first, then revisit.

Decision memo for the maintainer, 2026-09-18. Read-only analysis (functional sweep batch V):
nothing was built, run or changed; Core citations are `refs/bitcoin` at the project pin
`d3056bc1`. Question: our `-reindex` is *additive* — it extends the block index from the
block files and touches nothing else. Core's wipes three databases and rebuilds them. Should
ours become Core's?

## 1. What Core's `-reindex` does

`-reindex` = "wipe chain state and block index, and rebuild them from blk*.dat files on
disk. Also wipe and rebuild other optional indexes that are active" (`src/init.cpp:525`);
`-reindex-chainstate` wipes only the chainstate (`:526`). Both are read at `:1850-1851`.
Four wipes follow.

**1 — the block tree db.** `do_reindex` becomes `block_tree_db_params.wipe_data`
(`src/init.cpp:1344`), so `blocks/index` is recreated empty when `BlockManager` opens it.
The constructor writes the persistent resume flag `DB_REINDEX_FLAG 'R'` and clears
`m_blockfiles_indexed` (`src/node/blockstorage.cpp:1234-1236`; flag at `:61`, `:73-85`). A
later start *without* `-reindex` still resumes as a reindex, because `LoadBlockIndexDB`
reads the flag back (`:583-586`).

**2 — block and undo files, prune mode only.** Still in the constructor, `if (m_prune_mode)
CleanupBlockRevFiles()` (`:1238-1240`). That function (`:654-688`) deletes **every**
`rev?????.dat` unconditionally (`:668-670`) and every `blk?????.dat` outside a contiguous
run starting at `00000` (`:678-687`). On a pruned node the low-numbered blk files are
already gone, so the run is empty and *all* blk files are deleted.

**3 — the chainstate.** `options.wipe_chainstate_db = do_reindex || do_reindex_chainstate`
(`src/init.cpp:1386`) reaches `InitCoinsDB(..., should_wipe)`
(`src/node/chainstate.cpp:90-93`), erasing the UTXO set and its best-block pointer;
`NeedsUpgrade` and `ReplayBlocks` then become no-ops by construction (`:104-113`).

**4 — the optional indexes.** `do_reindex` is passed as `f_wipe` to `TxIndex`
(`src/init.cpp:1905`), every `BlockFilterIndex` (`:1915`) and `CoinStatsIndex` (`:1920`); it
becomes `DBParams::wipe_data` (`src/index/base.cpp:68-73`), so `BaseIndex::Init` reads a null
`DB_BEST_BLOCK` and starts from nothing (`:119-133`). Wipe-and-resync, not catch-up.

**Rebuild.** `LoadBlockIndex` runs against the empty db (`src/node/chainstate.cpp:42`);
`LoadGenesisBlock` is skipped while `m_blockfiles_indexed` is false (`:62-66`).
`ImportBlocks` walks `blk00000.dat` upward until a file is missing and calls
`LoadExternalBlockFile` on each (`src/node/blockstorage.cpp:1265-1284`), which deserialises
every block and accepts it, parking unknown-parent blocks in `mapBlocksUnknownParent`
(`src/validation.cpp:4988`; out-of-order log `:5050`, drain `:5123`). It clears `'R'`, sets
`m_blockfiles_indexed`, logs `Reindexing finished` and re-runs `LoadGenesisBlock`
(`:1288-1292`). The chainstate is rebuilt by ordinary block connection, so every block is
re-validated subject to assumevalid.

**What survives.** Nothing else is in the wipe set: `peers.dat`, `fee_estimates.dat`,
`mempool.dat`, `settings.json` and wallets are untouched by every path above. An assumeutxo
snapshot chainstate does *not* survive — one chainstate must remain after either flag
(`test/functional/feature_assumeutxo.py:725-728`). `-prune` + `-reindex-chainstate` is
refused (`src/init.cpp:1005-1008`, "Use full -reindex instead"), but `-prune` + `-reindex`
is *allowed* and is the documented route back to unpruned mode
(`src/node/chainstate.cpp:58`): it deletes the pruned block files and re-downloads the
chain.

## 2. What ours does

`-reindex` is registered at `src/config-options.lisp:157`, `-reindex-chainstate` at
`:111-112`. `-reindex` runs exactly one step, `%rebuild-block-index-from-block-files`
(`src/node/init.lisp:890-896`), which calls `reindex-block-index` and logs `Reindex: added
~D block index entries` (`src/node/init.lisp:720-747`, log at `:735`). Its docstring is the
policy: "Additive — an intact index is extended, never discarded" (`:722`).

`reindex-block-index` (`src/storage/reindex.lisp:121-196`) walks the store's records in file
order (`:100-119`), reads only the 80-byte header of each (`:24-42`), skips any hash already
in the index (`:152`), links the rest to a parent, and parks unknown-parent records under
the parent hash, draining them breadth-first as parents land (`:65-93`). Since 2026-09-15
(`b2ff7eb1`) it is a streaming walk emitting Core's two sentences — `Out of order block`
(`:161-164`) and `Processing out of order child` (`:84-87`). New entries carry `:status
:header-valid` only (`:56-60`), and genesis must already be in the index or every record
orphans (`src/node/init.lisp:75-85`).

**Re-read:** the blk flat files, headers only. **Kept, not re-derived:** `headerindex.dat`
(loaded first, `src/node/init.lisp:863-871`; re-saved with `:force-full t` only if entries
were added, `:737-739`); the coins db and `chainstate.dat`; every blk/rev file (no cleanup
exists, in prune mode or out of it); the txindex, blockfilterindex, coinstatsindex and
txospenderindex (`%start-indexes` takes only `reindex-chainstate`,
`src/node/indexes.lisp:502-503`, and only that flag forces a coinstats rebuild, `:590-595`);
and an assumeutxo snapshot chainstate, deleted for `-reindex-chainstate` only
(`src/node/init.lisp:923-928`).

**`-reindex-chainstate`** is a separate, complete implementation
(`src/node/reindex.lisp:3-32` and body): rewind `chainstate.dat` to genesis with the
in-transition marker, wipe the coins view, replay every stored active-chain block's UTXO
effects without re-running scripts, clear the coinstatsindex best marker. Refused under
`-prune` (`src/node/init.lisp:391-395`), as Core refuses it. There is **no persisted
reindex-in-progress flag**, so an interrupted `-reindex` resumes as an ordinary start
(`docs/next-wave-2026-08-22.md:466-471`), and a *corrupt* (as opposed to missing)
`headerindex.dat` is a startup refusal rather than something `-reindex` repairs
(`src/node/init.lisp:879-883`).

## 3. Which tests the divergence touches

Latest recorded sweep: `docs/functional-sweep-2026-09-13/after-3a337f7e.tsv` (117 PASS / 119
FAIL / 4 TIMEOUT / 23 SKIP). It predates `b2ff7eb1`, so its reindex rows are stale.

| Test | Line | Needs wipe? | Status in the tsv |
|---|---|---|---|
| `feature_reindex.py` | `:106` → `:71-74` | No — needs the two out-of-order log lines | FAIL (`:49`); `b2ff7eb1` added both sentences, unverified since |
| `feature_reindex.py` | `:107` → `:95` | No — asserts a *non*-reindex start does **not** wipe; additive passes trivially | — |
| `feature_remove_pruned_files_on_startup.py` | `:65-68` | **Yes** — prune-mode `-reindex` must leave exactly `blk00000.dat`+`rev00000.dat` and `getblockcount()==0` | FAIL, but at `:64` (`not(5 == 4)`, a pre-reindex file-count divergence); the wipe assertions are never reached |
| `feature_index_prune.py` | `:187-190` | **Yes** — an index whose best block is past the prune horizon must start after `-reindex`; only an index wipe delivers that | FAIL earlier, at `:103` |
| `feature_assumeutxo.py` | `:725-728`, `:791-794` | **Yes** — `-reindex` must delete the snapshot chainstate; ours keeps it | FAIL earlier, at `:187` |
| `feature_reindex_readonly.py` | `:78-80` | No — needs `Reindexing finished` | PASS |
| `feature_pruning.py` | `:132-133` | No — the `-prune`+`-reindex-chainstate` refusal, which we have | TIMEOUT |
| `wallet_reindex.py` | `:65-68` | No — needs `initload thread exit` | PASS |
| `feature_loadblock.py` | — | No | PASS |

The wipe semantics are a *latent* blocker for three tests; none of the three currently fails
**at** its reindex assertion, and no functional test passes *because* we are additive. What
pins the additive behaviour is ours: `REINDEXING-IS-ADDITIVE-AND-IDEMPOTENT` asserts a
second pass adds 0 (`tests/kv/flatfile-tests.lisp:1050-1073`); `:917` and `:952` pin order
independence and the out-of-order sentences; `tests/storage/storage-tests.lisp:96` pins the
genesis-root requirement, which exists only because the index is never rebuilt from nothing;
`tests/storage/reindex-tests.lisp:16-286` is the `-reindex-chainstate` suite; and
`src/node/init.lisp:890-896` + `:722` state the policy in prose, with
`docs/next-wave-2026-08-22.md:468` already recording it as a known divergence.

## 4. Operational risk for the two live nodes

Mainnet is pruned at 4096 MiB, legacy per-block files, blockfilterindex on
(`scripts/run-node.sh:88`); testnet4 is unpruned with txindex + coinstatsindex +
blockfilterindex and flat block files (`:76`). Heights at the last recorded query: testnet4
149,217, mainnet 963,244 with pruneheight 960,603 (`docs/next-tasks-2026-08-20.md:31-36`);
testnet4 is ~152k now.

- **Mainnet.** Core *allows* `-reindex` on a pruned node, and on one `CleanupBlockRevFiles`
  deletes every rev file plus every blk file (no contiguous run from 0). A Core-faithful
  `-reindex` would therefore destroy the ~4 GiB of retained blocks and force a full re-IBD —
  measured at **8 days** for this node (`docs/next-wave-2026-08-22.md:248-250`: 1.6-1.7
  blocks/s at h 680k-830k, 0.7-1.0 b/s by h≈888k). The counterpart is real too: today a
  pruned mainnet node has *no* supported way to rebuild its chainstate — `-reindex` only
  adds `:header-valid` entries and `-reindex-chainstate` is refused under `-prune`.
- **Testnet4.** A Core-style `-reindex` means re-reading ~152k blocks, re-connecting all of
  them, and re-syncing three indexes from zero. No local-replay rate has ever been measured
  here. Nearest data points: the profiled offline reindex of a real Core testnet4 datadir
  (`src/kv/flatfile.lisp:98-102`), the 134,923-record index rebuild
  (`src/node/init.lisp:83`), and the connect step once asked for 134,922 blocks in one call,
  which burned **16 minutes at 97% CPU** without completing
  (`src/validation/block.lisp:4329-4333`). Extrapolating mainnet's 1.7 b/s gives ~25 hours;
  testnet4 blocks are far smaller, so the real figure is lower, unknown, and unmeasured.

## 5. The two options

**(A) Match Core exactly.**

- Changes: `src/node/init.lisp:890-896` wipes the in-memory index and `headerindex.dat`
  first; `%init-load-chain` skips and redoes genesis in Core's order
  (`src/node/chainstate.cpp:62-66`); `-reindex` implies the chainstate rebuild
  (`src/node/init.lisp:996-997`) and deletes the snapshot chainstate (`:923-928`); a
  `CleanupBlockRevFiles` equivalent goes in `src/storage/blocks.lisp` for prune mode;
  `%start-indexes` (`src/node/indexes.lisp:502`) takes a wipe flag each index honours; a
  persisted `'R'`-equivalent is required or an interrupted reindex silently half-finishes;
  `:header-valid` (`src/storage/reindex.lisp:56-60`) stops being enough, because blocks must
  reconnect.
- Tests: delete or invert `REINDEXING-IS-ADDITIVE-AND-IDEMPOTENT`
  (`tests/kv/flatfile-tests.lisp:1050`); rewrite the genesis-root test
  (`tests/storage/storage-tests.lisp:96`); add prune-mode file-cleanup and index-wipe tests.
  Unblocks the three §3 rows — but only once their *earlier* failures (`:64`, `:103`,
  `:187`) are fixed too.
- Live cost: an 8-day operation on mainnet, multi-hour-to-day on testnet4; the one cheap
  recovery we have (rebuild a lost header index in minutes) is gone.
- Gain: operator semantics identical to Core; the flag repairs a *corrupt* index, not only a
  missing one; assumeutxo and index-prune recovery behave as Core documents.

**(B) Keep additive, document it as a stated divergence.**

- Changes: none to behaviour. Promote the divergence from a code comment to a documented
  contract: a note in `docs/manual.lisp` beside `reindex-block-index` (`:599`), a line in
  the option help (`src/config-options.lisp:157`), and the fact that a corrupt
  `headerindex.dat` must be deleted by hand first (`src/node/init.lisp:879-883`).
- Tests: mark `feature_remove_pruned_files_on_startup`, `feature_index_prune` and the
  `-reindex` arm of `feature_assumeutxo` expected-fail with a cited reason; keep the
  existing unit tests as the pins they already are.
- Live cost: none. Mainnet keeps its pruned blocks; testnet4 keeps its indexes.
- Gain: `-reindex` stays a minutes-long, non-destructive repair. Cost: three functional
  tests can never go green, a corrupt index still needs a manual `rm`, and `-reindex` on an
  assumeutxo node silently differs from Core.

## 6. Recommendation

Take **(B) now, with a scoped move toward (A) later**, and do not conflate the two. The wipe
semantics block nothing today: all three dependent tests fail earlier, for unrelated reasons
(`feature_remove_pruned_files_on_startup.py:64`, `feature_index_prune.py:103`,
`feature_assumeutxo.py:187`), so option A buys zero test movement until those are fixed,
while costing an 8-day re-IBD on the one production node that is pruned — and destroying the
only copy of the blocks below its prune horizon, a consequence Core's `CleanupBlockRevFiles`
accepts for its own reasons and ours has no cause to inherit unexamined. The parts of Core's
behaviour that are genuinely missing *and* genuinely cheap should be split out and done
regardless: the persisted `'R'` resume flag, snapshot-chainstate deletion on `-reindex`
(`src/node/init.lisp:923-928`, one branch), and an index wipe gated on `-reindex`
(`src/node/indexes.lisp:502`). Those three close the assumeutxo and index-prune divergences
without touching a single block file. The last piece — wiping `blocks/index` and the
chainstate and deleting pruned block files — is the one with a live-node blast radius; defer
it until those three earlier test failures are fixed and a local block-connect rate has
actually been measured, because every estimate in this repo that was not measured has been
wrong.
