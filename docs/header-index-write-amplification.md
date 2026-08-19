# G7-61 — header index write amplification

Design note. **No code change yet**; this records the measurement and the
options, because every variant trades something a maintainer should choose
deliberately.

## The measurement

`save-header-index` (`src/storage/chain.lisp`) `maphash`es the entire block
index into one byte buffer, CRC32s it, writes a temp file, fsyncs, and renames
— on **every** chainstate flush, inside `sb-sys:without-interrupts`, on the
sync thread (`%flush-chainstate` phase 1, `src/node.lisp`).

Flushes run every `+flush-every-n-seconds+` = 600s, or every 25,000 blocks.

Measured on the live nodes (2026-08-19):

| node | `headerindex.dat` | rewritten | per day |
|---|---|---|---|
| mainnet | **178 MB** | every 10 min | ~25 GB |
| testnet4 | 29 MB | every 10 min | ~4 GB |

On mainnet that rewrites 178 MB to persist, typically, **one new 185-byte
entry**. The irony is local: the comment immediately below in `%flush-chainstate`
notes that phase 2 is proportional to dirty entries "not the full ~17M-entry
set" — while phase 1 above it is proportional to the whole index.

Core does not have this problem: `CBlockTreeDB` is a LevelDB and
`WriteBatchSync` writes only `setDirtyBlockIndex`, which is a handful of
entries per flush.

## Why it is not a two-line fix

Any real fix needs to know **which entries changed**, and that is where the
risk is.

### Change detection

`block-index-entry` slots mutate at 15 `setf` sites (8 of them `status`, plus
`tx-count` ×3, `height`, `header`, `prev-entry`). Marking dirty at each is the
obvious approach and is **miss-prone in the worst way**: a missed mark means an
entry's status silently never reaches disk, so a block marked `:invalid`
reverts to `:valid` on restart. That is the exact failure GA9 S1 was about, and
"correct code that nothing calls" has already been this project's recurring bug
three times this month.

A miss-**proof** alternative is to compare against the state last written,
rather than trusting call sites to announce it. Entries are fixed-size (185
bytes, v2), and the mutable fields are small, so one extra `(unsigned-byte 64)`
slot per entry can pack `written-p | status(2) | height(32) | tx-count(29)`.
Per flush, walk the index comparing that packed value: ~963k cheap in-memory
comparisons (milliseconds) instead of 178 MB of serialization and I/O. Cost is
~8 MB of RAM at mainnet size. `header` and `prev-entry` are set once, early,
and are not covered by the packed value — they need either two more slots or a
forced full snapshot when they change.

### Crash safety

A snapshot + append-only delta must not replay a **stale** delta over a newer
snapshot — that would revert entries to older statuses, which is worse than
losing them. The delta therefore needs a generation number matching the
snapshot's, so a delta left behind by a crash between "write snapshot" and
"delete delta" is ignored rather than replayed. A torn trailing record (crash
mid-append) must be discarded, not treated as corruption — unlike
`headerindex.dat` itself, where a bad CRC now refuses startup (G7-06).

## Options

1. **Snapshot + generation-stamped delta log, miss-proof change detection.**
   The real fix; ~700× less I/O. Format change, ~300 lines with tests, touches
   live storage. Recommended, but deserves its own change window.
2. **Move the index to LevelDB**, as Core does. Also fixes the O(n) startup
   load. Larger migration; note the prefix-ordering trap that made the UTXO set
   iterate as empty in the coins DB (`'B'` sorting before `'C'`).
3. **Write the index every K-th flush** instead of every flush. Two lines, 6×
   less I/O at K=6. But it trades durability: an unclean crash loses up to K
   flushes of header entries (harmless — re-downloaded from peers) *and* of
   `:invalid` marks (not harmless — an operator's `invalidateblock` could be
   forgotten). Would need `invalidateblock` to force a flush.

Option 3 is the only one shippable in an afternoon, and it is the only one that
gives something up. That is why this is a note and not a patch.
