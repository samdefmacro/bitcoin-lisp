# GA11 dimension 5 — wallet persistence and wallet RPCs

Oracle: Bitcoin Core `d3056bc`, `src/wallet/walletdb.cpp`, `sqlite.cpp`, `db.cpp`, `wallet.cpp`,
`scriptpubkeyman.cpp` and all nine `src/wallet/rpc/*.cpp`. Ours: `src/wallet/*.lisp`, the 62
`define-rpc` forms under `src/wallet/`. Findings: `dim-wallet.json`.

## How it was run

Everything below was exercised in the project container against a regtest node built from
`tests/support/`'s fixtures, driving handlers through `bl.rpc:dispatch-rpc-method` with
`bl.rpc::%normalize-rpc-params` so the JSON coercions (top-level `false` sentinel, nested arrays as
lists) match a real request. Thirteen probe scripts: a record-schema dump, a full
write/unload/reload round trip, a six-case record-corruption battery, a ~30-call error-string
battery, an encryption/locked-wallet battery, a result-field-set sweep over a funded-and-spending
wallet, and four narrowing probes for the encryptwallet key-exposure finding.

## Covered

**Persistence.** The record key layout in `wallet-store.lisp` against `walletdb.cpp`'s `DBKeys`
table and its `Write*`/`Erase*` set; `%load-wallet-records` against `LoadWallet` and its six
sub-loaders; the `DBErrors` classes, by corrupting each of a `tx`, `walletdescriptor`,
`walletdescriptorkey`, `walletdescriptorcache` and `flags` record and reloading; a
create → mutate (label, purpose, persistent lock, spend) → `unloadwallet` → `loadwallet` round trip,
which came back byte-identical on every observable; `backupwallet`/`restorewallet`'s dump format,
checksum, network stamp and containment guards; `encryptwallet`'s on-disk key-material lifecycle.

**RPCs.** Result field sets and error strings for 40 of the 62, including every RPC in
`wallet/rpc/{addresses,coins,encrypt,transactions,wallet}.cpp` that a descriptor wallet can reach.
Argument *names* are already generated from Core into `src/rpc/core-tables.lisp`, so this pass
compared results and semantics rather than signatures.

## The headline

`encryptwallet` is supposed to end with Core's `GetDatabase().Rewrite()` equivalent so the deleted
plaintext keys leave the file. `encrypt-wallet` does call `bl.store:leveldb-compact` for exactly
that reason, and the call does not work: leveldb's `CompactRange(NULL, NULL)` flushes the memtable —
which is where the plaintext `CPrivKey` rows still are on a young wallet — into a fresh SST and then
compacts only the levels *below* it. Measured, the 32-byte master secret lands in `000005.ldb` and
survives repeated compactions, three unload/reload cycles and 300 new addresses.

## Two candidates dropped after reading Core

- `listunspent`'s hard-coded `"spendable": true` is what Core does too (`rpc/coins.cpp:675`, and the
  field is documented `(DEPRECATED) Always true`).
- Rejecting `createwallet ""` matches Core (`wallet.cpp:381`, same message); Core's own
  `wallet_startup.py` works around it by moving a named wallet's file.

## Not covered — and who inherits it

| area | inherits |
|---|---|
| coin selection, fees, change, the rest of `wallet-spend.lisp` (3,702 lines) | dimension 1 (descriptors + signing), dimension 3 (cluster mempool) |
| `psbt.lisp`'s 14 RPCs; `bumpfee` / `psbtbumpfee` / `walletcreatefundedpsbt` / `fundrawtransaction` / `walletprocesspsbt` result shapes | dimension 1 |
| descriptor parsing, expansion, the descriptor cache, inferred descriptors | dimension 1 |
| `wallet-hooks.lisp` and the manager fan-outs | dimension 6 (never-opened files) |
| the rescan / block-filter fast path in `scan-for-wallet-transactions` | dimension 9 (validation + storage second reader) |
| `-wallet`, `-walletdir`, `-keypool`, `-walletcrosschain`, `-fallbackfee` parsing | dimension 7 (accept-and-drop options) |

Two things were suspected and deliberately **not** filed for want of a reproduction: a
use-after-close window between `unload-wallet :force t` closing the LevelDB handle and the rescan
loop's next segment, and the durability of the three non-`:sync` writes (`orderposnext`, the
`destdata` "used" marker, `purpose`) under a real crash.
