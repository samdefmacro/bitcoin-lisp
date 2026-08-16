# Aligning chainstate consistency with Bitcoin Core

Date: 2026-08-16. Status: **P1 implemented; P2–P3 specified, not implemented.**

Written after reading Core rather than reasoning from our own structure. Two
GA8 findings and one live incident all turned out to be symptoms of a single
architectural divergence, so the aligned fix subsumes them.

## 1. What Core actually does

Verified in `refs/bitcoin/` (not from memory — this session already produced two
wrong claims about Core that were caught in review).

**The coins view owns its own best block.** Every block-level UTXO mutation ends
by moving the view's best-block pointer with it:

- `DisconnectBlock` → `view.SetBestBlock(pindex->pprev->GetBlockHash())`
  (`validation.cpp:2242`)
- `ConnectBlock` → `view.SetBestBlock(pindex->GetBlockHash())`
  (`validation.cpp:2651`)

`DisconnectTip` then advances the chain object in the same critical section:
`m_chain.SetTip(*pindexDelete->pprev)` and `UpdateTip(pindexDelete->pprev)`.
So the UTXO state and the block it corresponds to are **one object that moves
together, per block, under `cs_main`**. There is no window in which the coins
are being rewound while the recorded tip still names the old tip.

**Persistence is atomic by construction.** `CCoinsViewDB::BatchWrite`
(`txdb.cpp:100-159`) writes the best-block key *inside the same batch* as the
coin changes, and brackets a multi-batch flush with a transition marker:

```
first batch : Erase(DB_BEST_BLOCK); Write(DB_HEAD_BLOCKS, [new_tip, old_tip])
  … coin puts/erases, possibly several WriteBatch commits …
last batch  : Erase(DB_HEAD_BLOCKS); Write(DB_BEST_BLOCK, new_tip)
```

While `DB_HEAD_BLOCKS` exists, the database is self-describing as "somewhere
between old_tip and new_tip".

**Recovery rolls, it does not refuse.** On startup `ReplayBlocks`
(`validation.cpp:4812-4889`) reads the two head blocks; if present it
`DisconnectBlock`s back from the old tip to the fork, `RollforwardBlock`s up to
the intended tip, then `SetBestBlock` + flush. An interrupted flush is a
deterministic roll, not an abort.

**Shutdown is cooperative.** `m_chainman.m_interrupt` is checked *between*
`ActivateBestChainStep` calls (`validation.cpp:3514`), never inside a block.
Core never force-terminates the validation thread.

## 2. What we do instead, and what it costs

Our coins LevelDB defines exactly two key prefixes — `'C'` coins and `'M'`
migration marker (`storage/coins-view.lisp:23-26`). **There is no best-block
record.** The tip lives in a separate file, `chainstate.dat`, so two independent
artifacts can disagree. Consequences already observed:

- `perform-reorg` PHASE A (`validation/block.lisp:~2388`) rewinds the UTXO set
  block by block and **never touches the tip**; the tip only advances in PHASE B
  via `update-chain-tip` (`:2500`). The inconsistency spans the whole phase by
  design, which is why per-block `without-interrupts` — the pattern the connect
  path uses at `:1860` — cannot fix the `destroy-thread` hazard (GA8 S2).
- A corrupt or missing `chainstate.dat` made the node replay from genesis over
  a populated UTXO set, tripping BIP30 on mainnet and leaving no best-valid-tip
  (GA8 S1). PR #334 now refuses to start in that case — a guard, not a cure.
- `node.lisp:849` already carries a recovery hack for "UTXO set at h=X, recorded
  tip h=Y", i.e. the divergence is being papered over at runtime.

Aligning removes the second artifact instead of policing it.

## 3. Phases

| Phase | Change | Status |
|---|---|---|
| **P1** | Coins DB records its own best block, written **in the same batch** as the coin puts/erases; read back on open; startup compares it against `chainstate.dat` and reports a mismatch loudly | **DONE** |
| **P2** | `SetBestBlock` per block in both the connect and disconnect paths, so the pointer moves WITH the coins; the flush stamps the cache's own pointer rather than the chain's tip | **DONE** |
| **P3a** | Startup reconciliation when the pointer and `chainstate.dat` disagree | **DONE** |
| **P3b** | Cooperative shutdown: a stop check between blocks in `perform-reorg`, retiring the `destroy-thread` fallback | not started — see the design note below |

P3a needed no roll at all. Core's `ReplayBlocks` exists because `DB_HEAD_BLOCKS`
gives it a RANGE and it must move the coins to one end of it; our pointer is
exact, so the cheap record moves to the expensive one and normal sync
re-validates the gap. An unplaceable pointer (naming a block with no index
entry) is reported and refused rather than guessed at.

### P3b design note — the decision that must be made deliberately

The obvious implementation is to check `*ibd-stop-requested*` between blocks in
`perform-reorg`'s PHASE A and PHASE B and return without rolling back. With P2
and P3a that is safe **for shutdown**: the coins stop on a block boundary, the
pointer names it, and the next startup reconciles.

But `*ibd-stop-requested*` is **not shutdown-specific** — `call-with-sync-paused`
(`node.lisp:882`, assumeutxo snapshot activation) sets it too, and the node keeps
RUNNING afterwards. Aborting a reorg on that path would leave the in-memory
chainstate naming the old tip while the coins sit at an intermediate block: the
same inconsistency, moved from disk into memory, where startup reconciliation
never sees it.

So P3b must do one of:
- **(i)** check a shutdown-specific flag only, leaving pause-driven interruption
  as it is today; or
- **(ii)** on abort, also move the IN-MEMORY tip to the coins' block (the same
  rule P3a applies on disk), so memory and coins agree immediately and the
  following flush persists a consistent pair.

(ii) is the more complete answer and reuses the rule already established, but it
touches reorg control flow — including what the caller does with the
`(values nil reason)` it gets back, and whether `%rollback-partial-reorg` should
be skipped (it should: the coins are already at a clean boundary and rolling
back during a shutdown is work that can itself be interrupted). Decide this
deliberately rather than by reflex.

Phase order was corrected while implementing: per-block `SetBestBlock` had to
come FIRST. Without it the flush stamps whatever the caller believes the tip is,
which for the whole of a reorg's disconnect phase is the block being rewound
away from — so the pointer records a falsehood, and the P1 startup check
compares two copies of the same wrong answer and reports agreement. Only once
the pointer is honest does reconciling it with `chainstate.dat` mean anything.

**We do NOT need Core's `DB_HEAD_BLOCKS`.** That marker exists because
`CCoinsViewDB::BatchWrite` splits a large flush across several `WriteBatch`
commits (`batch_write_bytes`), leaving a window where neither the old nor the
new tip describes the database. Our `coins-view-cache-flush` commits exactly
one atomic `WriteBatch`, so that window does not exist. The one multi-batch
writer we do have is the assumeutxo snapshot loader, which writes into a
separate `chainstate_snapshot/` directory and validates the set hash before
promotion — an interrupted load is discarded rather than mistaken for state.

P1 is additive and safe on its own: a new key nothing yet depends on, plus a
diagnostic. P2 is what makes an interrupted flush recoverable. P3 is what closes
the `destroy-thread` hazard and lets the reorg drop `chainstate.dat` as the
source of truth.

## 4. Notes for the implementer

- Our flush is already a single atomic batch (`with-coins-view-batch`,
  `coins-view-cache-flush`), so P1 needs no new transactional machinery — that
  is the part Core's design depends on and we already have it.
- Do NOT make the reorg uninterruptible as a shortcut. It was considered and
  rejected: this node has lived through multi-hundred-block testnet4 reorgs, and
  deferring shutdown across one is a worse failure than the one being fixed.
- P3's cooperative shutdown must check the flag between blocks, matching Core's
  placement, and the existing 600s `destroy-thread` fallback should become
  unreachable rather than merely rarer.
- Keep PR #334's `:corrupt` refusal after P2 lands: it covers a chainstate file
  that is unreadable for reasons a replay cannot fix.
