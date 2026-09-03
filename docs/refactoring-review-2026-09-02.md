# Second-round refactoring review (2026-09-02, main 0a7dd5f)

The previous round (`docs/refactoring-plan-2026-08-27.md`, P0-P6, 521-562) essentially cleared out the **copy-paste layer**:
whole-function clone detection across 1,519 defuns of >=30 tokens in the tree left only the few small function pairs listed below;
0 cross-file name collisions, 0 bare `(error "...")` calls, 0 layering-violation baseline, and six definitional macros landed.
This review sweeps three lines once each (duplicate shapes, CL idiom, structure and tests); the conclusion: **the remaining
duplication is at the "idiom level" and the "a table hand-copied N times" level**, plus a few spots where the previous round's
own guards have blind spots. Below, ranked by value, each item carries evidence, counts, and a suggested abstraction.

## 0. One-sentence conclusion

Still missing: **4 definitional macros** (P2P dispatch table, scriptPubKey template table, wallet record schema, RPC parameter
table), **1 set of chain-params fields** (base58/BIP32 prefixes), **1 macro hygiene bug**, **zero declarations on the hot path**,
and **one blind spot in the layering ratchet** (the top-level package spans from the 5th file to the last module, so the 9
upward references from validation -> node get recorded as 0). On the test side, of the 7,174 `::` references, about 1,000 are
the same batch of inline shapes that can be absorbed into `tests/support/`.

## 1. Abstraction gaps ("a table hand-copied N times")

### 1.1 `handle-message` is still a 30-branch `string=` cond, and the message table is written out four times ★★★
- `src/networking/protocol.lisp:128-326`: 190 lines, 30 `(string= command "...")` branches, the vast majority the same
  three-line shape `((string= command "X") (handle-X peer payload ctx) t)`.
- `src/networking/peer.lisp:1826-1843` `check-peer-rate-limit`: the second 10-branch `string=` chain, the same batch of
  commands -> bucket accessors.
- `src/networking/peer.lisp:1128-1140`: the third, `verack/sendaddrv2/sendheaders/wtxidrelay/sendtxrcncl` within the
  handshake window.
- `src/networking/ibd.lisp:1634,1711`: the fourth, IBD's override of `block`/`headers` before falling through to
  `handle-message`.
- `src/validation/miniscript.lisp:1135-1169`: the parser fragment dispatch is likewise a 23-branch `string=` (a separate
  issue, same remedy).

**Abstraction**: `define-p2p-handler`, a table keyed by command string (handler symbol, rate-limit bucket accessor,
`:needs-mempool`, `:handshake-only`, `:post-verack-disconnect`), turning `handle-message` into a `gethash` + funcall; the
four irregular branches `mempool`/`verack`/`sendtxrcncl`/`feefilter` are each written as ordinary handler functions.
This is exactly the problem `define-rpc` already solved ("handler written but never wired into dispatch", a typical
instance of this repo's 15 "code correct, call site wrong" bugs). About -150 lines. **Note**: the
`received: ~A (~D bytes) peer=~A` log line in `handle-message` is text asserted by a functional test and must be kept
verbatim.

### 1.2 The scriptPubKey template table is copied five times, and it has already forked ★★★ (includes one real bug)
The same `(= len 25) (= (b 0) #x76) (= (b 1) #xa9) …` ladder appears in:
- `src/validation/script.lisp:635` `classify-script` (keyword + extracted data, ~100 lines) and `:735`
  `script-type-to-string`
- `src/rpc/blockchain.lisp:424` `%script-type` (string, 20 lines)
- `src/rpc/descriptors.lisp:2040` `%script->address` (28 lines)
- `src/wallet/psbt.lisp:1161`, `src/validation/transaction.lisp:470` `%match-p2pkh`,
  `src/serialization/compressor.lisp:142,200`

**Already forked**: `%script-type` recognizes `"anchor"` (P2A, blockchain.lisp:437) while `classify-script` does not;
`classify-script` recognizes `:multisig` while `%script-type` does not. 6 call sites use the former, 12 use the latter
(getblock/gettxout/rest/psbt vs. decodescript/wallet).
**Bug**: `src/rpc/rawtransaction.lisp:985` hardcodes `(if (eq network :testnet3) "tb" "bc")` instead of `segwit-hrp`, so
decodescript's segwit address HRP is wrong on testnet4/signet/regtest.

**Abstraction**: one template table in `validation/script.lisp` (pattern -> type keyword, Core name, extractor, address
encoder); `%script-type` = `script-type-to-string ∘ classify-script`, and `%script->address` becomes a dispatch on the
keyword. About -70 lines, eliminating one class of fork. Fix the HRP bug first (a separate PR, checkable against the
functional tests).

### 1.3 `wallet-store.lisp` hand-writes a record schema: 47 nearly-identical functions ★★
`src/wallet/wallet-store.lisp:197-412` (215 lines): 34 `wdb-*` writers + 13 `wdb-parse-*` readers, each a 2-6 line
`%wser`/`%wparse` body enumerating the same handful of field kinds (string, raw bytes, var-bytes, u32-le, u64-le).
The five write/read pairs for uint64/int64/int32/string/vector at `:317-344` differ only in the codec name.

**Abstraction**: `define-wdb-record (name key-string (key-field…) (value-field…))`, generating the key writer, key
parser, value writer, and value parser from one field table -- the same thing `define-message` already does for P2P.
About -150 lines. **In passing**: `%wser`/`%wparse` (flexi-streams) is a second buffering API alongside `bl.bytes`; the
tree still has 53 occurrences of `with-output-to-sequence`/`with-input-from-sequence` (`src/coalton/interop.lisp` 24,
wallet-store 5, `src/storage/chain.lisp` 4), matching the `:stream-io` ratchet's count of 42 to close out.

### 1.4 The four indexes each duplicate a set of LevelDB boilerplate ★★
- `%bfi-encode-meta` (`src/storage/blockfilterindex.lisp:84`) and `%csi-encode-meta`
  (`src/storage/coinstatsindex.lisp:75`) are **character-for-character identical**; `%*-decode-meta` likewise
  (`:90`/`:81`).
- `blockfilterindex-best :120` vs `coinstatsindex-best :169`: differ only in accessor and key name.
- `init-blockfilterindex :49`, `init-coinstatsindex :147`, `init-tx-index` (`src/storage/txindex.lisp:107`): three
  copies of the same 14-line shape -- **the only remaining three-way exact clone in the whole tree**.
- `%txindex-key :91`, `%bfi-filter-key :71`, `%csi-stat-key :64`, `%txospender-key` (`txospenderindex.lisp:99`): the
  same prefix-byte + payload concatenation.

**Abstraction**: `src/storage/index-base.lisp` already has 9 generics but **no default methods, no state**. Add
db/path/enabled/prefix slots to `base-index`, provide default `index-best-block`/`index-set-best`/`index-clear-best`/init,
and add `(index-key index prefix &rest parts)`. About -130 lines. defstruct change -> `cold-unit-fresh`.

### 1.5 RPC positional parameter parsing and type checking ★★
166 `define-rpc` forms, and today the macro only generates the defun + registration. Inside handler bodies, `src/rpc/` +
`src/wallet/` together have 278 `(error 'rpc-error …)` calls, of which ~63 are pure per-parameter type checks (36
`(unless (stringp x) … +rpc-type-error+)`, 27 integer versions); `(first params)`/`(nth 2 params)` appear 169 times.
Examples: `src/rpc/blockchain.lisp:180-185` (getblockhash), `src/rpc/rawtransaction.lisp:905-916` (estimaterawfee),
`src/rpc/mempool.lisp:243/253` (getmempoolancestors/descendants, 10-line bodies with 0.81 similarity). The parameter
**names** are already data (`src/rpc/core-tables.lisp`, Core-generated), but each handler re-derives the position
independently.

**Abstraction**: give `define-rpc` a parameter lambda-list `((hash :hex-hash) (verbosity :integer :default 1 :range (0 3)))`,
bind the variables, wrap `%positional-bool`/`%positional-array`, and raise `+rpc-type-error+` per Core. About -200 lines,
and it lets `core-tables.lisp` **check against the handler** instead of being maintained side by side. Do it in batches
(one PR per rpc file); error codes/message text are asserted by functional tests, so check each one against Core's
RPCHelpMan.

### 1.6 base58 / BIP32 version bytes never made it into `chain-params` ★★
`define-chain-params` has `bech32-hrp` but not Core's `base58Prefixes`, so three families of code still hand-write
`:mainnet` branches: WIF `src/crypto/address.lisp:101-127`, P2PKH/P2SH `:133-146`, `:365-376`, BIP32 xprv/xpub
`src/crypto/bip32.lisp:17-20,60-61,85`, plus `src/rpc/descriptors.lisp:216,226,328,1844`, `src/wallet/wallet.lisp:716,930`.
They also collapse the five chains down to a binary `:mainnet`/`:testnet` -- so `address-version-to-type` (`:142`) can
only ever answer `:testnet3`. Four new fields (pubkey-prefix, script-prefix, secret-prefix, ext-pub/prv) remove ~12
branches. The `+chain-dispatch-ceiling+` ratchet only counts `ecase network`, **it does not count
`(eq network :mainnet)`** -- add that.

### 1.7 Message constructors that differ only in the command string ★
`src/serialization/messages.lisp`: `make-getblocks-message:356`/`make-getheaders-message:370` share the same 12-line
body; `make-getdata:394`/`make-inv:402`/`make-notfound:410` are three copies of the same 6-line body;
`make-ping:344`/`make-pong:350`; 6 empty-payload constructors (`:340,:887,:891,:895,:899,:953`). Collapse into a
~12-line table using `define-message` or a `define-message-constructor`. About -60 lines.

### 1.8 `etypecase view` two-arm dispatch, 11 times ★
`src/storage/coins-view-cache.lisp:115,692,699,711,727,740,760,811,820,825,953` each dispatch on two arms, `utxo-set` vs.
`coins-view-cache`. The comment at `:680` defends this on speed grounds, but all of these already come after the
LevelDB/hash-table lookup. A generic function (or a `coins-view` protocol structure carrying function slots) removes
~60 lines and the "redefining functions from utxo.lisp"-style warning mentioned at `:686`. **A consensus-path**, so run
`scripts/benchmark.sh` for a baseline before changing it.

### 1.9 Small exact clones (while we're at it)
`write-u64-le-into`/`write-u32-le-into` (`src/storage/utxo.lisp:158,174`); `sfl-randrange`
(`spanning-forest.lisp:45`) vs. `wrng-randrange` (`wallet-spend.lisp:164`); `make-outpoint-key` (`mempool.lisp:601`) vs.
`%wtx-outpoint-key` (`wallet-tx.lisp:68`); `%timing-resistant-equal`/`-bytes` (`src/rpc/server.lisp:600,715`); the
wallet RPC preamble `wallet-for-request` at 45 sites, 14 of which are immediately followed by `with-wallet-lock` (->
`define-wallet-rpc`); the periodic-task idiom at 6 sites (`node/housekeeping.lisp:98,145`, `node/flush.lisp:338`,
`node/peers.lisp:949,987`, `wallet-spend.lisp:2477`, -> `define-periodic-task`); 20 literal all-zero 32-byte hashes (no
`+zero-hash+`); 16 `(or (gethash k h) (setf (gethash k h) …))` (-> `ensure-gethash`).

## 2. Language-level issues (idiom and robustness)

First, the clean parts: 0 `setq`, 0 `#'(lambda`, 0 `&aux`, 0 `(if x t nil)`, 0 non-eql `defconstant` in the whole tree,
all 45 `unwind-protect` occurrences pair with resource acquisition, and all 18 `with-*` macros take `&body`. Below are
the real problems.

### 2.1 `with-current-node-lock` variable capture ★★★ (bug)
`src/networking/protocol.lisp:7`: `` `(let ((node bl::*node*)) …) `` non-hygienically injects `node` into the body's
scope,
16 call sites (protocol 8, ibd 8). Any caller whose body itself has a `node` binding silently reads the
global instead. `src/rpc/accessors.lisp:31`'s `with-node-lock (node)` is already the correct form -- two names for
one thing; merge them, or change explicitly to an anaphoric form with an explicit parameter.

### 2.2 Zero declarations on the hot path ★★
`src/serialization/types.lisp` (593 lines, `read-transaction:266`, `read-block-header:491`, `read-compact-size`) has
**0 `declare` forms, 0 `optimize` forms**; `messages.lisp` has 1; `src/validation/script.lisp` has 0. Across the
whole tree's 3,240 definitions there are only 38 `(optimize …)` forms and 142 `(declare (type …))` forms. Meanwhile
the neighboring `src/util/bytes.lisp` (41 occurrences) and `src/storage/utxo.lisp:95-140` are fully declared +
inlined. `serialize-transaction`'s (`types.lisp:377`) own docstring says "Hot path… flexi-streams at ~50% of CPU".
The 2026-08-22 profile conclusion in memory is likewise that **block deserialization is the bottleneck**.
A file-level `(declaim (optimize (speed 3) (safety 1) (debug 1)))` plus `(simple-array (unsigned-byte 8) (*))`/`fixnum`
declarations on the read/write leaves. Keep `safety 1` (see 2.5). Run `scripts/benchmark.sh` before and after
(previous round's baseline: serialize-tx 535 ns/op, br-read-transaction 785 ns/op).

### 2.3 `equalp` hash-table keys on 32-byte txids ★★
139 occurrences of `equalp` (`validation/block.lisp` 25, `networking/ibd.lisp` 20, `mempool/mempool.lisp` 19). The
mempool's core indexes are all `equalp`: `mempool.lisp:114-115` (parents/children), `:346,348,350,376,382`. SBCL's
`equalp` walks the full 32 bytes on every lookup and is a generic recursive comparison.
**This repo has already invented the correct approach twice**: `src/storage/utxo.lisp:140`
`(sb-ext:define-hash-table-test utxo-key= utxo-key-hash)`, `src/coalton/interop.lisp:510` `sig-cache-hash` (taking
the first 8 bytes of the SHA256). Move it into `bl.bytes` as a `make-hash-hash-table`, a one-line change per mempool
site. Benchmark before and after.

### 2.4 `ignore-errors` swallows computation, not just cleanup ★★
78 occurrences, most of them legitimate best-effort cleanup. Four dangerous ones:
- `src/validation/block.lisp:744` `(or (ignore-errors …) …)`: the validation result falls back to a default on ANY
  error (including `storage-error`).
- `src/validation/block.lisp:2077` `(let* ((hash (ignore-errors …)))`: the block hash silently becomes NIL.
- `src/rpc/descriptors.lisp:648` `(ignore-errors (parse-integer …))` -> should be `:junk-allowed t`.
- `src/node/shutdown.lisp:104` `(loop until (eql 1 (ignore-errors …)))`: one error and it loops forever.
Separately, of the 214 `handler-case` forms, about 20 are `(error (e) (values nil …))` -- using the condition system
as a boolean return. Acceptable at a trust boundary (deserializing peer data), but it should be one documented
`with-untrusted-input` macro, not 20 sites each writing their own. The condition hierarchy already exists
(`bitcoin-lisp-error` + 12 subclasses) -- narrow these to the specific class.

### 2.5 `(safety 0)` at a trust boundary ★
9 occurrences; the 6 in `utxo.lisp` are fine. `src/coalton/interop.lisp:517` (`sig-cache-hash`) does 8 unchecked
`aref` calls on a key whose 32-byte length is guaranteed **only by a declaration**; `src/kv/flatfile.lisp:120` is a
`locally` wrapping file reads. A short vector under `(safety 0)` means an out-of-bounds read. Change to `(safety 1)`.

### 2.6 76 `defparameter`s named `+foo+` ★
637 `defconstant` + 121 `defparameter`, of which 76 use the `+name+` constant-naming convention
(`src/config.lisp:302`, `src/validation/transaction.lisp:208` `+dust-relay-fee-rate+`,
`src/validation/block.lisp:260-288`'s four script-flag sets). The name lies both ways. For values that are
lists/vectors, use `alexandria:define-constant :test #'equal` (this repo already uses it correctly in 5 places,
`src/rpc/descriptors.lisp:29,37`, `src/wallet/wallet-store.lisp:23-25`); for scalars use `defconstant` directly; for
ones that genuinely get reassigned, rename to `*foo*`. ⚠️ A `defconstant` change needs an image restart (the
CLAUDE.md item).

### 2.7 The Coalton boundary is a thick layer of hand-written near-identity wrappers ★
`src/coalton/interop.lisp`, 125 defuns:
- `:150-201`: 12 codecs, all `(cl-array-to-coalton-vector (with-output-to-sequence (s) (write-X s obj)))` and its
  inverse -- each crossing walks a byte stream **and then** does a full-copy `map 'vector #'identity`. One
  `define-coalton-codec (name writer reader)` would generate all 12.
- `:223-303`: 20 one-line arithmetic wrappers (`satoshi+`, `satoshi<`, `block-height>=`…), most of which unwrap and
  then apply a CL operator; `satoshi<` (`:239`) just discards the Coalton type and compares integers -- adding no
  type safety.
- `src/validation/transaction.lisp:75-180`: the fee-summation loop does `wrap-satoshi` once per output/input -- just
  to add integers allocated per UTXO. Either push the summation into Coalton once per transaction, or accept it's a
  fixnum sum and drop the wrapping.

### 2.8 Small items (a one-time sweep)
| Anti-pattern | Count | Example | Fix |
|---|---|---|---|
| `(cond … (t nil))` | 42 | `validation/transaction.lisp:630`, `block.lisp:531,1289` | Drop the t clause |
| `(not (null x))` as a predicate return | 13 | `mempool.lisp:615`, `txgraph.lisp:188`, `secp256k1.lisp:225` | Return a generalized boolean |
| `(if (null x) A B)` | 22 | `block.lisp:3813`, `rpc/blockchain.lisp:2262` | `(if x B A)` |
| Local hex helpers | 5 | `wallet-crypt.lisp:624` (downcases an already-lowercase result), `rpc/blockchain.lisp:18`, `descriptors.lisp:174` | Unify into `bl.crypto` |
| `octets-to-string` without `:external-format` | 8/15 | the rest mix `:utf-8`(5)/`:ascii`(2) | Make it explicit everywhere |
| 393 single-use `%` helpers (993 total) | -- | `node/housekeeping.lisp:117`, `blockfilterindex.lisp:81,90` | For the subset that closes over nothing and only reads a caller-local invariant, change to `flet`/`labels` (only 105 flet/labels occurrences in the whole tree); **do not** mechanically convert all of them -- extracting a named function was intentional in the previous round |
| `start-node`'s 62 `&key` parameters | 1 | `src/node/init.lisp:1268` | A `define-option` registry already exists: collapse into one `node-config`, `start-node` takes a single argument; `wallet-available-coins`'s 17 keys -> a `coin-filter` struct (Core's `CCoinControl`) |

## 3. Structure and tests

### 3.1 The layering ratchet's blind spot is now the entire remaining problem ★★★
`tests/structural-tests.lisp:901`'s `%package-prefix` pins the package `BITCOIN-LISP` to `src/package.lisp`
(position 3), and the docstring itself admits this is a blind spot. Result: references to `src/config.lisp`,
`src/zmq.lisp`, `src/config-options.lisp`, and all 22 files of `src/node/` all get counted as "downward". The actual
upward references (tested per-directory by `bl.*:` prefix):
- `src/validation/` -> `bl:maybe-stop-at-height` (`node/housekeeping.lisp`), `bl:maybe-periodic-flush`
  (`node/flush.lisp`), `bl:wallet-notify-block-{connected,disconnected}`:
  `src/validation/block.lisp:2693,2701,2710,3324,3370,3742,3762`, 9 occurrences total.
- `src/mempool/` -> `bl:wallet-notify-mempool-tx-{added,removed}` (`src/node/wallet-hooks.lisp`);
  `bl:zmq-notify-*` (`mempool.lisp:876`, zmq.lisp loads before mempool, so this one is fine).
- `src/wallet/` -> `bl:*wallet-max-tx-fee*`, `bl:*wallet-fallback-fee*` (`src/config.lisp`),
  `bl:run-notify-command` (`src/logging.lisp`).
- `src/rpc/` methods -> `bl:pruning-enabled-p` etc. are **spelling only** (they all resolve to a lower layer) -- just
  fix the prefix.
- `src/coalton/` -> 5 occurrences of `bl:log-warn` (-> `bl.log:`); `src/mining/` -> 1 occurrence of `bl:*network*`.

**Remedy**: Core's approach is `CValidationInterface` -- validation does not know about wallet/zmq/node, it calls a
set of hook variables. Add `src/util/hooks.lisp` (or validation's own `*block-connected-hooks*` list), registered by
node at startup; then have the layering scanner classify by **the symbol's defining file** (`sb-introspect`, already
used by P3.4) rather than by package -- the blind spot disappears, and the 9 + 2 + 3 sites above become real
failures. Once this is done, coalton / mining / mempool / validation / wallet / rpc-methods can each become an ASDF
subsystem (`src/node/` is the true top layer and stays in the main system).

### 3.2 Packages that "export everything" ★
| package.lisp | exports | top-level definitions |
|---|---|---|
| `src/storage/` | 370 | 363 |
| `src/serialization/` | 297 | 199 |
| `src/coalton/` | 234 | 159 (generated, already excluded from the orphan scan) |
| `src/rpc/` | 38 | — |
| `src/wallet/` | 10 | — |
The export tables for storage and serialization read like `(export (all-symbols))`; of the 68-item orphan-export
baseline (mempool 20, storage 12, networking 8), only 6 are genuine entry points, the rest are dead API. The
`*orphan-export-baseline*` ratchet (`:28`) **only forbids growth; a reduction is merely written to `*test-dribble*`**
(`:211`) -- make reduction mandatory too (the baseline can only go down), then clean it up package by package.
`src/package.lisp` has 157 exports + `:use`s 8 project packages, and `bl:` transitively re-exports ~1,500 symbols;
the previous round's "zero call-site changes" strategy was correct, but **every re-export should be intentional** --
list them in a table at the package definition and add a check that "each re-exported symbol has a caller in this
package".

### 3.3 Test inline shapes (the source of the 7,174 `::` references) ★★
`tests/` has 103 files, 69,014 lines; `tests/support/` has only 6 files, ~440 lines, 26 fixtures. Duplication of
named helpers is already gone (only `make-p2wsh-script`/`make-p2wpkh-script` remain as two spots); what's left is
**inline shapes**:

| Shape | Count | Example | Absorb into |
|---|---|---|---|
| Node setup `(let ((node …))` | 259 (`make-test-node` 168, bare `bl::make-node` 81) | `rpc-tests.lisp:731`, `dos-protection-tests.lisp` (14 bare occurrences) | `with-test-node` (node + unwind-protect + teardown) |
| Hand-written `uiop:delete-directory-tree` teardown | 62 (`unwind-protect` 254) | `storage-tests.lisp`, `pruning-tests.lisp` | `with-temp-directory` already exists (78 sites in use) |
| `(signals bl.rpc::rpc-error …)` | 122 (`bl.rpc::rpc-error` 248 total, `hash-to-hex` 88) | `rpc-tests.lisp` (135), `wallet-spend-tests.lisp` | `signals-rpc-error` (asserts code+message), `rpc-result-hash`; about −300 `::` |
| Wallet RPC preamble `*rpc-wallet-name*` + createwallet + getnewaddress + make-wrng | 99/66/60/38 | wallet-*-tests | Extend `with-wallet-chain-node` to bind the wallet name and mint one address |
| `bl.net::*ibd-context*` + `make-ibd` | 99/72 | `ibd-tests.lisp` (45), `reorg-tests.lisp` (16) | `with-ibd-context` (a sibling of `with-network`) |
| `bl::apply-config-globals` / `args->start-node-plist` | 82/53 | `config-tests.lisp` | `with-config-globals` |
| serialize -> deserialize -> compare | round-trip 141 + roundtrip 85 | `compressor-tests.lisp`, `util/roundtrip-tests.lisp` | One `check-roundtrip (encoder decoder value)` |
| `bl.val::*block-undo-data*` stub | 57 | reorg/persistence | `with-block-undo-data` |

The heaviest `::` targets: `bl.rpc::rpc-error` 173, `bl::node-chain-state` 132, `bl.wallet::*rpc-wallet-name*` 99,
`bl.net::*ibd-context*` 99, `bl.rpc::hash-to-hex` 88, `bl::apply-config-globals` 82, `bl::make-node` 81,
`bl::node-utxo-set` 73, `bl::node-mempool` 61, `bl::node-peers` 59, `bl::node-block-store` 49. **The `node-*`
accessors (≈374 occurrences) are the ones that should be exported as formal API**; the rest go through
test-support wrappers. Once the table above is done, `::` is projected to drop from 7,174 to ~5,500.

### 3.4 Documentation and scripts ★
- `docs/manual.lisp` has 17 sections, and **`src/zmq.lisp` (302 lines) is mentioned zero times**; `scripts/docs-check.lisp:39`
  only checks sections already listed, with no assertion that "every src module has a section" -- add one (and fill in
  zmq while at it).
- `scripts/profile-tapscript.sh`'s header comment says it's a single-region special case of `profile-regions.sh`
  (both mode 644, untouched since 2026-05-15) -- merge into one with a region parameter.
- `scripts/diag-*` (9 of them, one-shot reproductions of three specific blocks, untouched since 2026-05-15) + the
  root-level `diag/propagation_probe.py` -- delete or archive into `docs/`.
- 5 top-level test files are not in the `.asd` (`tests/manual-sync-test.lisp`, `quick-debug-test.lisp`,
  `testnet-1000-blocks.lisp`, `testnet-peer-reconnect-test.lisp`, `testnet-resume-test.lisp`, 726 lines): CLAUDE.md
  says they are "manual network scripts", so move them to `scripts/manual/` and document it -- don't let them look
  like tests that failed to get registered.
- The `src/` tree has only two genuine TODO/FIXME markers (`wallet-spend.lisp:478` parity,
  `txreconciliation-set.lisp:8` citing Core); the 68 "divergence" and 43 "⚠️" markers are all intentional
  annotations -- the comment layer is clean.

## 4. Suggested batching (lowest to highest risk, one thing per PR)

| Wave | Content | Verification |
|---|---|---|
| A — fix bugs (3 small PRs) | 2.1 macro capture; the HRP in 1.2; the four `ignore-errors` in 2.4 | touched suites + cold-unit |
| B — test support (3-4 PRs) | 3.3's fixtures: `with-test-node`, `signals-rpc-error`, `with-ibd-context`, `check-roundtrip`; `node-*` exports | `::` ratchet drops; cold-unit |
| C — definitional macros (4 PRs, one macro each) | 1.1 `define-p2p-handler`; 1.3 `define-wdb-record`; 1.7 message constructors; 1.5 `define-rpc` parameter table (batched per rpc file) | **macro -> cold-unit-fresh**; functional-test p2p_*/rpc_* spot-check list committed |
| D — tables and structure (3 PRs) | 1.2 script template table; 1.6 chain-params prefix fields; 1.4 base-index default methods | 1.4 is a defstruct -> fresh; Core vectors stay at 100% |
| E — performance/declarations (3 PRs) | 2.2 hot-path declarations; 2.3 hash-table test; 2.5 safety; 2.7 Coalton codec macro | `scripts/benchmark.sh` before/after comparison, written into the ledger |
| F — layering (2-3 PRs) | 3.1 hook variables + classify layer by defining file; then coalton/mining/wallet/mempool/validation/rpc-methods subsystems | fresh; layering baseline stays at 0 and the blind spot is closed (positive control: a temporarily added validation->node reference must go red) |
| G — sweep (1-2 PRs) | 2.6, 2.8, 1.9, the 3.2 orphan baseline switched one-way, 3.4 docs/scripts | cold-unit; docs-check |

Each table/macro replacement follows the P2f method: **use a real reader to pull the old table, compare key sets**
(lesson `registry-replacement-compare-key-sets`), no regexes; every new ratchet is first fed a synthetic input that
must be caught (lesson `positive-control-every-new-ratchet`, with the control committed into the tree).

## 5. Suggested new ratchets

The lesson from the previous round: a metric with no ratchet regresses. This round's quantifiable items:
- `string=` dispatch chains: the count of `(string= <var> "…")` with >=5 branches in the same cond (currently 4 sites
  + 1 in miniscript) -> 0.
- Number of `equalp` hash tables (currently >=8 in mempool) -> baseline only decreases.
- Hot-file declaration coverage: `serialization/types.lisp`, `messages.lisp`, `validation/script.lisp` -- every
  defun has at least one `declare`, or a file-level `declaim optimize`.
- `ignore-errors` count (78) only decreases; the `(error (e) (values nil` shape (~20) only decreases.
- `defparameter +x+` (76) -> 0.
- `(eq network :mainnet)` counted into `+chain-dispatch-ceiling+`.
- Orphan-export baseline (68) changed to only decrease.
- manual.lisp module coverage: every `src/` directory/top-level file referenced in some section.
- Bare `bl::make-node` in `tests/` (81) -> 0, `uiop:delete-directory-tree` (62) -> 0.

## 6. Method and confidence

The three scan lines are each independent (duplicate shapes: whole-function clone detection + shape grep; idiom:
pattern counting + reading 7 representative files; structure: ratchet files, asd, export tables, tests counts). For
every count in this document I rechecked the key items against the tree (meta codecs character-for-character
identical, 0 declarations in types.lisp, the hardcoded HRP, `etypecase view` at 11, 8 `equalp` tables, 5
unregistered tests, manual missing zmq, 76 `+x+` defparameters). Not rechecked: the agent-supplied per-symbol `::`
counts and the 393 count for single-use `%` helpers -- recount before acting on these.

## 7. Completion record (2026-09-02)

All seven waves from §4 were merged; each PR has a line in `docs/refactor-ledger.md` (A, B1, B2, C1, C2, C3, C4, D1,
D2, D3, E, F, F2, G) with the ratchet readings at the time that PR merged. Deviations from this document's
suggestions, by item:

- 1.5 `define-rpc` parameter table: implemented **positional binding + 6 kinds of coercion** (C4), but not the typed
  kinds with error codes (`:hex-hash`, mandatory `:string`/`:uint`) -- those ~45 type checks each have error text
  asserted by a functional test, and have to be converted one by one against Core's RPCHelpMan; it can't be done in
  bulk with a reader. Left for follow-up.
- The 76 `+foo+`s from 2.6: 9 of them are written by the `-option` table, so they were changed to `*foo*` defvars
  rather than constants (G).
- 3.1 layering: upward references 77 -> 22 (F + F2 moved `node/state` to right after config); the remaining 22 are
  pinned in `+top-package-upward-baseline+`, only allowed to decrease, never increase.
- 3.4's "5 unregistered test files": these are git-ignored local scripts that were never committed; left untouched.
- §5 new ratchets: `src-reaches-no-foreign-internals`, `no-pseudo-network-testnet`, the equalp table count, the
  upward-reference baseline, the orphan baseline switched one-way, docs-check module coverage,
  `rpc-specs-stay-within-core-arity` -- each with a positive control.

Final readings (at the time C4 merged): 0 duplicate definitions, 7 functions >200 lines (all documented Core-mirror
exceptions), 61 functions >100 lines (starting point 66), 4,417 `::` references within tests (starting point
7,174), cold-unit-fresh 34,595 / 0.
- 2.4 `ignore-errors`: wave A fixed two of the four (shutdown-token wait, descriptors parse-integer); the two in
  `src/validation/block.lisp` (`available-processor-count`, `prune-stale-undo-files`) were closed by the result
  review's follow-up (`docs/refactor-result-review-2026-09-02.md` §8): the first falls back only on an unreadable
  file, the second parses the name explicitly and logs the garbage it deletes.
- 2.7 `define-coalton-codec`: not built; `satoshi<` and the per-output `wrap-satoshi` loop are as they were.
  Lowest priority (single star), no ledger row claims it.

