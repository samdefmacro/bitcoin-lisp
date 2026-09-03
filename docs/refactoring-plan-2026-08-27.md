# Code Cleanup Plan: From "Chasing Features" to a "Readable, Reusable Base Library"

Date: 2026-08-27. Baseline: main `5f4f321`, cold tests 34,255 checks / 0 failures, functional tests 38 PASS.
Second draft (revised after same-day review, see §9). Decided: nicknames use the `bl.` prefix (`bl.ser`, `bl.store`...); P2 order follows the §3 table (chain-params first).
This is a dated research document (per the convention in CONTRIBUTING.md): where it conflicts with the code, the code wins, but please point it out.

## 0. One-Sentence Conclusion

The problem with this repository is not "poorly written" — it's that **there is only one means of abstraction**: across 89,000 lines of source there are 3,214 `defun`s,
130 `defstruct`s, 652 `defconstant`s, but only 31 `defmacro`s (all `with-*` resource macros,
not a single "definitional" macro), 2 `defgeneric`s, 7 conditions. Every concept — a P2P message,
an RPC, a config option, a chain's parameters, an index — is hand-written 3 to 5 times, scattered across 3 to 5 locations.
The core of the plan is to give each category of concept **one definition form** (`define-message`, `define-rpc`, `define-option`,
`define-chain-params`, `define-index`, `define-p2p-handler`), so that "defining is registering,"
then split the giant files apart following Core's directory layout, and finally extract the chain-independent layers into separate ASDF systems.

Every step must be a "no functional change" PR, using the cold tests, Core vectors, and the functional-test baseline as oracles,
and structural tests to turn new conventions into mechanical checks — this project has already proven, 14 times over, "written correctly but nothing calls it,"
and a documented convention cannot stop that, but `tests/structural-tests.lisp` can.

## 1. Current-State Survey (Data)

### 1.1 Scale and Shape

| Metric | Value |
|---|---|
| Source | 88 files / 88,739 lines; tests 100 files / 68,029 lines / 2,484 `test`s |
| Top-level forms | defun 3,214 · defstruct 130 · defconstant 652 · defvar+defparameter 438 · **defmacro 31 · defgeneric 2 · define-condition 7** |
| Docstring coverage | 87% (2,803 / 3,214) — good, must be preserved |
| Core `file.cpp:line` references | **1,660 occurrences** — this is the most important asset for an AI to understand the code; must be preserved and institutionalized |
| Functions over 100 lines | 62; >200 lines 13; >400 lines 3 (per the deep scan in `tests/structural-tests.lisp`; parens inside strings don't count) |
| Longest functions | `start-node` **1,338 lines**, `perform-reorg` 475, `%create-transaction-internal` 445, `apply-config-globals` 388, `validate-transaction-for-mempool` 361, `run-ibd` 349 |
| Largest files | `rpc/methods.lisp` 6,783 · `node.lisp` 6,582 · `validation/block.lisp` 4,108 · `networking/ibd.lisp` 4,104 · `networking/protocol.lisp` 3,835 · `rpc/wallet-spend.lisp` 3,737 · `coalton/interop.lisp` 3,536 |
| Change hotspots (last 200 commits) | `node.lisp` 74 times, **`package.lisp` 71 times**, `config.lisp` 37, `methods.lisp` 35 |

`package.lisp` was touched in 71/200 commits, meaning every added export symbol requires editing this 1,780-line file —
it is the main source of conflicts between parallel branches.

### 1.2 Package Structure

- 9 packages are crammed into a single `src/package.lisp`, each just `(:use #:cl)`, exporting 27-352 symbols
  (storage 352, serialization 289, networking 280, mempool 236).
- No package-local nicknames (except `bt`). As a result all cross-package references are written out in full:
  `bitcoin-lisp.serialization:` 2,348 occurrences, `bitcoin-lisp.storage:` 1,391 occurrences,
  `bitcoin-lisp.crypto:` 587 occurrences... roughly 5,300 occurrences total of a 30-character prefix.
- The top-level package `bitcoin-lisp` `:use`s 5 sub-packages — `node.lisp` is one big flat namespace.
- **The wallet (15,199 lines, 436 `defun`s) lives inside the `bitcoin-lisp.rpc` package.** Wallet logic and RPC handlers
  are mixed into the same batch of files (`wallet*.lisp`, `descriptors.lisp`, `psbt.lisp`). Core keeps `wallet/`
  and `wallet/rpc/` strictly separate.
- Tests: 100 files share a single `bitcoin-lisp.tests` package; `::` references into internal symbols number **7,136 occurrences
  (1,399 distinct symbols)**. This is the single biggest friction for refactoring: any rename ripples into the tests.

### 1.3 Duplication (Concrete Evidence)

1. **Four byte-serialization APIs coexist.**
   - Streaming `read-*-le`/`write-*-le stream` (88 call sites, built on a flexi-streams gray stream —
     already confirmed by profiling to be the block-deserialization bottleneck, see memory 2026-08-22);
   - `br-*` byte-reader (70 occurrences);
   - `bb-*` byte-buf (101 occurrences, `serialization/binary.lisp`);
   - **`coalton/interop.lisp` has yet another `bb-*`/`buf-set-*` set** (54 occurrences),
     the eight function names `bb-write-u8/u16-le/u32-le/u64-le/bytes/varint/finish/ensure` are **defined twice**
     — and the interop copy is the faster implementation (using `buf-set-u32-le` instead of four `aref`s).
   - CompactSize read/write has **12 definitions** scattered across 7 files (not counting the three `core-varint` ones): `read-compact-size`,
     `br-read-compact-size`, `bb-write-varint`×2, `write-varint`, `buf-set-varint`,
     `%compact-size-bytes`, `%vec-push-compact-size`, `%read-compact-size-at`,
     `%compact-size-size`, `decode-compact-size-from-first-byte`, `compact-size-length`...
     (the three `*-core-varint` ones are a different encoding, and that's legitimate.)
2. **Functions with the same name defined twice in different files** (17 of them): the 8 `bb-*` above, plus `wrap/unwrap-satoshi`,
   `wrap/unwrap-block-height`, `satoshi+`, `satoshi>`, `tagged-hash`, `fsync-directory`,
   `%script-push`. In addition the **macro name** `with-node-lock` has one definition each in `networking/protocol.lisp`
   (`(&body)`) and `rpc/accessors.lisp` (`((node))`), and even the lambda lists differ.
3. **P2P message encode/decode:** `messages.lisp` has 20-odd groups of `defstruct X` + `read-X` + `write-X`,
   the same field table copied three times (see `version-message`: the defstruct has 9 slots, the reader's `let*` has 9 lines,
   the writer has 9 lines, and `make-version-message` lists the same 9 keywords again).
4. **P2P dispatch:** `handle-message` is a 209-line `cond` with 33 `(string= command "...")` clauses;
   each handler carries 8 positional/keyword arguments
   (`peer payload chain-state utxo-set block-store &key mempool peers fee-estimator
   address-book recent-rejects`) — this is exactly Core's `NodeContext`, and we pass it by hand.
5. **RPC:** the definition of one RPC method is scattered across 5 places: the `defun` for `rpc-foo`, one line inside `register-all-methods`
   (a 197-line function with 164 `register-rpc-method` calls), `*rpc-arg-conversions*`,
   `*rpc-named-only-args*`, `*rpc-named-arg-names*` (the latter three tables are generated from Core by `scripts/gen-rpc-arg-names.py`),
   plus the help table. Argument access is positional: `(first params)`/`(second params)`/
   `(nth 3 params)` (293 occurrences), and 563 hand-written `(error 'rpc-error :code +rpc-...+ :message ...)`.
6. **Indexes:** the four files `txindex`, `txospenderindex`, `blockfilterindex`, `coinstatsindex`
   each implement the same skeleton: `*-db-path`, `init-*`, `close-*`, meta key, `*-best-block`/`set-best`,
   `*-height`, `*-add-block`, `*-remove-block`, `build-*`; `node.lisp` also has three parallel
   `%catch-up-blockfilterindex`/`%catch-up-coinstatsindex`/`%catch-up-txospenderindex`
   (57/49 lines). Core uses a single `BaseIndex` base class (`index/base.cpp`).
7. **Chain parameters (chainparams):** per-network dispatch via `(ecase network ...)` is scattered across nearly 30 sites in 8 files (29 `case`/`ecase` forms, plus 3 more sites in `address.lisp` written a different way):
   `node.lisp` (magic, port, dns-seeds, rpc-port, data-path), `config.lisp`
   (assumeutxo, assumevalid, minimum-chain-work), `validation/block.lisp`
   (BIP65/66/CSV/segwit/taproot activation heights, 10 sites), `storage/chain.lisp` (genesis),
   `crypto/address.lisp` (bech32 hrp, base58 prefixes). Core is a single `CChainParams` object.
   **This item directly determines "can it be reused for the next chain"** — right now adding a new chain means editing 8 files.
8. **Config options:** roughly 100 options, and the knowledge about each option is scattered across `known-config-options`,
   the `core-only` list, `conf-parse-*`, `apply-config-globals` (388 lines),
   `config-alist->start-node-plist`, and `start-node`'s keyword-argument list (the main reason `start-node` is 1,338 lines).
   Core has this as a single `ArgsManager::AddArg` declaration.
9. **Error handling:** 7 conditions against 199 bare `(error "string")` sites; 209 `handler-case` sites.
   A string error cannot be selectively handled, nor mapped to an RPC error code.

### 1.4 The 12 Responsibilities Inside `node.lisp`

Network constants, notify hooks, the pid file, logging toggles, process entropy, the startup sequence, inbound eviction, mempool loading,
chainstate crash recovery, the assumeutxo lifecycle, shutdown coordination (signal pipe + watchdog), index catch-up,
disk-space checks, the datadir lock. `*node*` is referenced 260 times inside this file; it is almost never used in the subsystems
(networking 7 times, storage/validation/mempool 0 times) — this is a good sign, meaning the subsystems already take
explicit parameters, and splitting up `node.lisp` won't disturb them.

## 2. Assets That Must Be Preserved

- **The Coalton script interpreter**: policy already settled ("the interpreter uses Coalton, everything else uses CL"); leave it alone.
- **1,660 Core `file:line` references** and the 87% docstring coverage: this is the most direct
  "spec pointer" for an AI agent reading the code. After cleanup, write this into convention: every definitional macro's expansion keeps a `:core "file.cpp:line"` slot.
- `%` internal prefix, `+constant+`, `*special-variable*`, `with-`/`do-` macro naming — already consistent, keep going.
- The 6 `with-*` macros in `storage/leveldb.lisp`, the `register-rpc-method` hash table: existing good shapes,
  the plan is to generalize them, not replace them.
- `tests/structural-tests.lisp`: whole-tree structural invariants (orphaned exports, unsynced globals). It is the enforcement point
  for the entire plan.
- The cold-test lane + `refs/bitcoin` vectors + the functional-test baseline (the 38-PASS set): three oracles.

## 3. Plan Overview

| Phase | Content | Risk | PR count |
|---|---|---|---|
| P0 | Measurement and guardrails: structural-test baseline, the cold lane's "fresh FASL" mode, the refactor ledger | None | 2 |
| P1 | Mechanical de-duplication: one byte API, three CompactSize functions, 17 duplicate names, package-local nicknames | Low (byte-level oracles are complete) | 5 |
| P2 | Definitional macros, one macro per PR: chain-params → message → p2p-handler+context → rpc → index → option | Medium (each has a precise oracle) | 6-8 |
| P3 | Split giant files and long functions: `node/`, `rpc/` follow Core's layout, the wallet becomes its own package, `block.lisp` split into steps | Medium (pure move + extract) | 8-10 |
| P4 | Layer into multiple ASDF systems, a condition hierarchy, a per-module package.lisp + PAX manual | Low | 4 |
| P5 | A test-support package, reducing `::` coupling | Low | 3 |

Principles:

1. **One PR, one mechanism, no functional change.** Commit messages use the `refactor:` prefix (Core's convention),
   the PR description must state what the oracle is, what the check count is, and whether the functional-test PASS set is unchanged.
2. **Renames are mechanical, not manual.** When moving a symbol, first forward it via `:import-from` + `:export` to keep the old name,
   the next PR then `sed`s references across the whole repo, and finally the forwarding is removed. The 7,136 `::` references in the tests can only be handled this way.
3. **A macro gets its oracle before it lands.** The first PR for each definitional macro rewrites only **one** existing definition into macro form,
   using existing tests to prove byte-identical output; only the second PR migrates in bulk.
4. **Structural tests follow the convention.** Every time a convention is introduced, the same PR adds a structural test that "only errors on new occurrences"
   (following the baseline + ratchet pattern of `no-new-orphaned-exports`).
5. **A macro must qualify.** A definitional macro must cover at least 5 instances, or Core must have the same abstraction
   (`BaseIndex`, `SERIALIZE_METHODS`, `RPCHelpMan`, `AddArg`, `CChainParams`);
   all six macros satisfy this, and any future macro follows the same rule.
6. **Moves use `git mv`; moving and modifying are separate commits.** The blame trail for the 1,660 Core references and historical comments
   is a clue an AI uses to read history, and a single "move + touch up while I'm at it" commit erases it.
7. **Deploy as usual.** The two live nodes deploy from main; after every P2 macro PR merges, deploy to testnet4 and observe for a day before
   merging the next one — memory has recorded "running the real binary found 3 bugs that 32,000 unit tests could not see,"
   the live nodes are the strongest behavioral oracle. The oracle for wallet-related moves is weaker (most wallet test cases in the functional tests are still
   in the FAIL set), so it can only rely on the unit suite — state this in the PR description.

## 4. Phase Details

### P0 Measurement and Guardrails (done first, 2 PRs)

**PR-0a Structural-test baseline**, added to `tests/structural-tests.lisp`:

- `no-new-duplicate-definitions`: whole-tree `defun`/`defmacro` definitions with the same name across different files, baseline = the current
  18 (including `with-node-lock`); any new one goes red.
- `no-new-long-functions`: baseline for functions >200 lines = 13 (named), any new one goes red;
  once a function is split up it is removed from the baseline (the ratchet only moves down). The count of >100-line functions (62) has a separate cap.
- `retiring-serialization-families-do-not-grow`: counts stream / `br-*` / `bb-*` / `buf-set-*`
  call sites, baseline 88/70/102/54; the streaming and interop families (and the 12 CompactSize definitions) **may only shrink, never grow**.
- `bare-error-strings-do-not-grow`: a per-directory baseline count of `(error "...")` (199 total).
- `no-new-layering-violations`: a file referencing a package that (by .asd component order) loads after it, with the order derived from ASDF rather than transcribed by hand.
  Today there are 15 sites: `config.lisp` 7 packages, `coalton/interop.lisp` 3, `coalton/crypto.lisp` 1, `zmq.lisp` 1,
  validation → mempool 3. This is the guardrail for the P4 layering, and also the "file → which packages it references" table.
- `every-p2p-command-has-handler` / `every-rpc-has-arg-spec`: enabled once P2 introduces the macros.

**PR-0b Cold lane "fresh FASL" mode.** Memory (2026-08-19) recorded that after a macro change, the stale expansion
"survives warm rebuild + image restart + cold battery — docker-test.sh mounts a persistent
FASL volume." This round changes a large number of macros, so the cold lane must be able to run against an empty FASL volume. **Without this, none of P2's green runs are trustworthy.**
Already implemented: `scripts/docker-test.sh --fresh-fasl` (or `BITCOIN_LISP_FRESH_FASL=1`) = each run gets a unique
volume that is deleted on exit; the Workbench entry point is `cl-workbench validation run cold-unit-fresh`. CLAUDE.md's claim that
"the cold lane compiles fresh" was wrong and has been corrected.

Also add `docs/refactor-ledger.md`: a table recording before/after metrics for every PR (§6).

### P1 Mechanical De-duplication (5 PRs)

1. **One byte API.** Done (PR P1.1): `byte-buf`/`byte-reader`/`buf-set-*`/CompactSize moved down into
   `src/util/bytes.lisp` (package `bitcoin-lisp.bytes`), loaded before `src/coalton/` — this is a hard constraint:
   interop's sighash code `declaim inline`s these writers, and if the implementation stayed in the later-loaded serialization package,
   interop would not see the definitions at compile time and the inlining would be lost — this is also why a copy existed in the first place. Both serialization and interop
   `:import-from` and re-export it, so the 200-plus `bitcoin-lisp.serialization:bb-*` call sites are unchanged.
   Plan correction: `buf-set-*` (positional writes into a pre-allocated array) is not a "second buffer set" but the primitive layer underneath `bb-write-*`,
   and is kept; the only things retired are the streaming `read-*-le stream` (88 occurrences) and the redundant CompactSize definitions.
   `scripts/benchmark.lisp` gained a new serialization benchmark (serialize / br-read / legacy sighash / raw byte-buf).
2. **CompactSize converges to three functions**: `read-compact-size` (byte-reader), `write-compact-size`
   (byte-buf), `compact-size-length`. The remaining 13 variants are replaced one at a time, each replacement backed
   by roundtrip-tests and the Core vectors.
3. **Each of the 17 duplicate-named functions keeps a single copy.** Done (PR P1.3). Two of the pairs were in **the same package**, where the later-loaded file silently overrode
   the earlier one — SBCL prints `WARNING: redefining ...` on every cold run, and no one ever read it: `fsync-directory`
   (utxo.lisp's "takes a file path, fsyncs the parent directory" version was overridden by flatfile.lisp's "takes a directory" version, so utxo's three
   rename-into-place sites only fsynced the file — the parent directory was never fsynced, silently dropping rename's crash-durability guarantee) and
   `tagged-hash` (hash.lisp's pure-Lisp version was dead code). Now `scripts/docker-test.sh` fails outright on
   `WARNING: redefining BITCOIN-LISP`, and a structural test guards the cross-package case. `with-node-lock`: the networking
   one (reads `*node*`) was renamed to `with-current-node-lock`, and rpc's `(with-node-lock (node) ...)` was kept.
   The two `%script-push` copies were merged into `bl.ser:script-push-data` (with OP_PUSHDATA4 added); the 6 one-line shims in validation forwarding
   to interop were deleted and the call sites qualified directly — ⚠️ the fresh cold run caught a missed change the warm image couldn't see
   (the old shim's fdefinition was still sitting in the warm image).
4. **Package-local nicknames.** Add to every `defpackage`:
   `(:local-nicknames (#:bl.ser #:bitcoin-lisp.serialization) (#:bl.crypto #:bitcoin-lisp.crypto)
   (#:bl.store #:bitcoin-lisp.storage) (#:bl.val #:bitcoin-lisp.validation)
   (#:bl.mp #:bitcoin-lisp.mempool) (#:bl.net #:bitcoin-lisp.networking))`,
   then change the 5,300 full-name references to short names. **Nicknames must carry the `bl.` prefix**: a bare `crypto` would collide with ironclad's
   global nickname `CRYPTO` (in SBCL a local nickname takes priority, so it would compile, but readers would mistake it for ironclad).
   The replacement script is committed as `scripts/refactor/apply-nicknames.sh`, so other parallel branches can rerun it themselves after rebasing,
   rather than manually resolving 5,300 conflicts. Done (PR P1.4, 159 files at once, roughly 24,000 lines).
   Implementation notes: the nickname table `bitcoin-lisp::*package-nicknames*` + `install-package-nicknames`, called at the end of each
   defining package's file via `eval-when (:compile-toplevel ...)` (SBCL refuses to give a nickname to a package that does not yet exist, and the packages are spread across 6 files;
   interop.lisp both defines a package and uses nicknames in the same file, so they must be installed by compile time). Three traps: nickname strings are
   **case-sensitive** — the reader upcases `bl.ser` before looking it up, so the table must spell it `"BL.SER"`; a package must also give **itself** a nickname
   (the top-level package's file writes `bl::*node*`); and the installer call itself, read inside `cl-user`, cannot use a nickname.
5. **Each module directory gets its own `package.lisp`** (`src/storage/package.lisp`, etc.),
   and `src/package.lisp` is split apart. This ends the 71/200 conflict hotspot.
   Constraint: `logging.lisp`/`config.lisp`/`zmq.lisp` load before crypto, yet belong to the `bitcoin-lisp` package that `:use`s all
   five sub-packages (`config.lisp` directly references networking 19 times, validation 9 times,
   mempool 8 times), so **every module's package file must be listed as one "packages" phase at the very front of the .asd**,
   rather than loading alongside its own module. This doesn't affect the de-conflicting payoff, but it does show that `config.lisp` is not actually a low layer — see P4.
   Done (PR P1.5): the eight files `src/{util,crypto,serialization,storage,validation,mempool,mining,networking}/package.lisp`
   are listed as the .asd's "packages" phase at the front, and `src/package.lisp` now holds only the top-level package + the nickname table/installer
   (1,780 lines → 246 lines).

### P2 Definitional Macros (one macro per PR, ordered from lowest to highest risk)

**(a) `define-chain-params`** — oracle: `refs/bitcoin/src/kernel/chainparams.cpp`.

```lisp
(defstruct chain-params
  name magic port rpc-port genesis-hash genesis-header
  bech32-hrp p2pkh-prefix p2sh-prefix
  bip34-height bip65-height bip66-height csv-height segwit-height taproot-height
  pow-limit pow-target-spacing pow-no-retargeting allow-min-difficulty-blocks
  dns-seeds assumevalid minimum-chain-work assumeutxo checkpoints
  default-relay-p wallet-default-p
  core "kernel/chainparams.cpp:LINE")

(define-chain-params :testnet4
  :magic #(#x1c #x16 #x3f #x28) :port 48333 :rpc-port 48332
  :bech32-hrp "tb" :p2pkh-prefix #x6f :p2sh-prefix #xc4
  :bip34-height 1 :bip65-height 1 :bip66-height 1 :csv-height 1
  :segwit-height 1 :taproot-height 1
  :dns-seeds ("seed.testnet4.bitcoin.sprovoost.nl" "seed.testnet4.wiz.biz")
  ...)

(defvar *chain-params*)            ; bound once at startup by start-node according to -chain
(chain-params-bip65-height *chain-params*)   ; replaces 10 ecase sites in block.lisp
```

The `*network*` keyword is kept as `(chain-params-name *chain-params*)`, and the nearly 30 `ecase` sites are swapped one by one for accessors.
**This is the key to reuse for "the next chain": a new chain = one `define-chain-params` form.**

Done (PR P2a): `src/util/chainparams.lisp`, package `bl.chain`, `defstruct chain-params` + `define-chain-params` +
5 chains; all per-chain data (magic, port, seeds, genesis parameters, activation heights, checkpoints, headers-sync parameters,
minimum-chain-work, assumevalid, assumeutxo, prune height, bech32 hrp, directory name) was **programmatically extracted** from the original 8 files by script
rather than transcribed by hand; once tabulated, the original 22 dispatch functions became one-line accessors, with unchanged signatures and 150 call sites untouched.
The structural test `no-chain-dispatch-outside-chainparams` pins the ceiling at 0. The `*chain-params*` global and passing it
explicitly (attached to `node-context`) are left for P2c to do together with ctx.

Two disciplines: (1) `*chain-params*` may only be `setf` once at startup, just like today's `*network*`,
**and must never be `let`-bound** — SBCL threads do not inherit dynamic bindings, so sync threads / RPC threads / peer threads would see
the global value; (2) places in existing code that explicitly pass a `network` parameter (`network-magic network`) are changed to explicitly pass a
`chain-params` struct (attached to `node-context`); the global variable is reserved for code with no context to reach.

**(b) `define-message`** — oracle: `tests/roundtrip-tests.lisp`, `robustness-tests`,
the Core vectors, and real P2P exchanges in the functional tests.

Survey correction (found during P2b-1): `messages.lisp` really only has about 8 groups that follow the "defstruct + read + write" triple;
another 30-plus are structless `make-X-message` (writes bytes)/`parse-X-payload` (reads bytes) functions, and all of them are
built on flexi-streams. So **P2b-1** was done first: migrating `messages.lisp` (all P2P encode/decode) as a whole to
byte-reader/byte-buf (116 primitive call sites + 36 stream constructions, mechanically renamed via a table, with the corresponding stream forms in the tests converted too),
leaving the streaming primitives only for **file formats** (peers.dat, wallet, fee estimates, mempool.dat — using streams there is legitimate;
"retiring the stream family" targets only the P2P hot path, and the structural test's stream count drops from 88 to 42). ⚠️ In the warm image, reloading any
module's `package.lisp` clears that package's local nicknames (`defpackage` re-executes), so the installer was moved to the first-loaded
`bitcoin-lisp.nicknames` package, and each package file's ending call self-heals it. `define-message` was finished in P2b-2: `src/serialization/message-macro.lisp`, a field-type table
(`:u8`...`:i64`/`:bool`/`:hash256`/`:var-bytes`/`:var-string`/`:block-header`/`:transaction`,
extensible via `define-message-field-type`) + compound forms `(:bytes N)`/`(:struct X)`/`(:list T :max M :name S)`
+ `:custom` (`:read`/`:write` clauses for encodings like differential indexes that can't be described by the table). The six groups message-header, version,
inv-vector, compact-block, and block-txn-request/response were converted to field tables; net-addr (the with/without-timestamp forms)
and net-addr-v2 (network-type dispatch) were left hand-written. ⚠️ In the warm image, after the macro changed, ASDF did **not** recompile messages.lisp
(the old expansion stayed in the image, and constructors still carried the old defaults), and it was only correct after a `touch` — this is exactly why the fresh cold lane exists.
`make-*`/`parse-*` are kept as thin wrappers.

```lisp
(define-message version-message
  (:core "protocol.h" :command "version")
  (version      :int32  :default +protocol-version+)
  (services     :uint64 :default +node-network+)
  (timestamp    :int64)
  (addr-recv    net-addr)
  (addr-from    net-addr)
  (nonce        :uint64)
  (user-agent   :var-string)
  (start-height :int32)
  (relay        :bool :default t
                :read  (if (> version 70001) (= (read-byte stream nil 1) 1) t)))
```

Expands to `defstruct` + `read-version-message` + `write-version-message` +
`version-message-serialized-length`. The field-type table is `:int32 :uint64 :var-string :hash256
:compact-size (:vector T) (:struct T)`; `:read`/`:write` clauses are the escape hatch, covering conditional fields.
The first PR migrates only `version-message`, using existing tests to prove `write`'s output bytes are unchanged;
the second PR migrates the remaining 20 groups in `messages.lisp` in bulk, with the read side always generating a byte-reader version (incidentally migrating away the 39
streaming `read-*-le stream` sites — that is the deserialization bottleneck found by profiling). The tx/block in `types.lisp`
**are not migrated by default**: the ambiguity of the witness marker byte, hash caching, and `parse-tx-payload`'s strictness about trailing bytes
(memory ⚠️) are all things the macro cannot naturally express; once the macro has proven itself on 20 messages, decide whether to touch these,
and if so it must run Core's `tx_valid`/`block` vectors + the cold lane's fresh FASL.

**(c) `define-p2p-handler` + `node-context`** — oracle: `serve-requests-tests`,
`inbound-listening-tests`, `compact-block-tests`, and the functional tests' p2p_* set.

`node.lisp`'s `defstruct node` **already has all of these slots** (chainstates, block-store, mempool,
tx-index, the three indexes, fee-estimator, address-book, recent-rejects, peers...). The only reason handlers
pass 8 parameters by hand is that `node` is defined in the last-loaded top-level package, so networking/validation cannot reference it.
So this isn't building a new struct — it's sinking the data slots down:

```lisp
;; Low-level package (util or a new bitcoin-lisp.context) that networking/validation can both see
(defstruct node-context                     ; Core node/context.h
  chain-params chain-state utxo-set block-store mempool peers fee-estimator
  address-book recent-rejects tx-index blockfilterindex coinstatsindex
  txospenderindex historical-chainstate)

;; node.lisp: runtime slots stay in node, data slots are inherited via :include, accessors like node-mempool are unchanged
(defstruct (node (:include node-context))
  running lock sync-thread listener-socket ...)

(define-p2p-handler "ping" (peer payload ctx)
  (:core "net_processing.cpp:LINE")
  ...)
```

`handle-message` shrinks to "logging + rate-limit gating (these two pieces must stay before dispatch — the functional tests assert on that log line) +
one hash-table lookup"; the structural test `every-p2p-command-has-handler` cross-checks against Core's full `NetMsgType` table.
All handler signatures with 8 positional parameters become `(peer payload ctx)`. `run-ibd` and `connect-block` are likewise changed to take `ctx`.

Honestly, this item's main value is the `ctx` signature, not the table lookup: functions like `handle-inv`/`handle-block` already
existed, and the `cond` was just 209 lines of pure dispatch; and Core's own `ProcessMessage` is itself an if-chain, so a table lookup would actually deviate from
Core's shape. So the table lookup is a byproduct of the `ctx` rework, not a separate line item.

Done (PR P2c): `src/util/context.lisp`, package `bl.ctx`, the **data structure** `node-context` (chain-state, utxo-set,
block-store, mempool, peers, fee-estimator, address-book, recent-rejects, tx-index, historical-chainstate)
+ the `with-node-context` unpacking macro. It did not go through `node (:include node-context)`: node's `chain-state`/`utxo-set` are derived from
the `chainstates` list, and what handlers need is a **resolved** snapshot of references; node constructs ctx at the start of each sync loop
(`sync-blockchain` → `start-ibd`), which is cleaner than inheritance. The 17 handlers were unified to `(peer payload ctx)` (function bodies
kept verbatim under `with-node-context`), and `handle-message`/`dispatch-ibd-message`/`safely-dispatch-peer-message`/
`drain-and-reap-peer`/`pump-peer-messages`/`start-ibd`/`run-ibd` were changed to `(... node-ctx ctx)` — the class of 2026-07-10
"only two keywords passed" wiring bug can no longer be written under this signature. The ~120 call sites in the tests were mechanically mapped
via the old lambda-list table to `make-node-context`. Table-lookup dispatch is left for later (Core itself is also an if-chain).

**(d) `define-rpc`** — oracle: `rpc-tests`, `wave10-tests` (error codes/boolean parity),
and the three parameter tables generated from Core (**the generation script is kept; the tables become a verification source, not a data source**).

```lisp
(define-rpc "getblockhash" (node &args (height :integer))
  (:core "rpc/blockchain.cpp:LINE" :category :blockchain)
  "Returns hash of block in best-block-chain at height provided."
  (let ((chain-state (rpc-get-chain-state node)))
    ...))
```

Expands to: `defun rpc-getblockhash (node params)`, type checking with Core semantics per the `&args` spec
(reusing the existing `%json-type-error`/`%parse-verbosity`, error text unchanged), `register-rpc-method`,
and named-argument mapping. The structural test `every-rpc-has-arg-spec`: the parameter-name sequence declared by the macro must equal
the sequence in `*rpc-named-arg-names*` (generated from Core); a mismatch goes red — this way Core's table becomes a machine-checked
oracle rather than a fourth hand-copy. The 197 lines of `register-all-methods` disappear.
Expectations should stay honest: of the 563 `rpc-error` sites, only about 173 are argument-shape checks (`+rpc-type-error+`/
`+rpc-invalid-parameter+` with text like Invalid/expected/must be); the `&args` spec can absorb that one-third,
the rest are semantic errors that rightly belong in the function body.

Done as a first step (PR P2d-1): `src/rpc/define-rpc.lisp` — `define-rpc "name" (node params) ...` = `defun rpc-name`
+ load-time registration + a registry; 161 handlers were mechanically converted, and `register-all-methods` shrank from 197 lines to a 6-line
"reload from the registry" (8 test call sites needed no change). ⚠️ The conversion script's regex for pulling the old registry missed one registration
that spanned **two lines** (`syncwithvalidationinterfacequeue`); I briefly wrote it into a comment as "dead code that was never registered" —
it was caught back by the `...-EXISTS-AND-ANSWERS-NULL` test on a cold run: when replacing a registry you must diff **the sets** of the old and new tables, not just their counts.
`&args` argument destructuring + a name-by-name comparison against the Core-generated table is left for P2d-2 (must preserve "no functional change": the existing handlers already
do their own type checking, with error text matching Core, and the macro must not change their error codes for them).

**P2d-2 canceled (decided 2026-08-28)**: the three tables in server.lisp — the positional-argument names `*rpc-named-arg-names*`,
the options-object members, the JSON conversion table — are all **generated** from Core's source (`scripts/gen-rpc-arg-names.py` walking
`src/rpc/*.cpp`), and rpc-tests cross-checks them line-by-line against Core's client.cpp. Splitting them into 161 hand-written
`define-rpc` forms would wreck the "change refs/bitcoin, rerun the script" workflow, trading a bit of readability for manual maintenance — not worth it.
Core itself also puts RPCHelpMan's parameter declarations next to the handler rather than making the handler parse them.
Changed to: keep the tables generated, and when P3 splits up rpc/, move the three tables into a separate generated data file (`src/rpc/core-tables.lisp`),
leaving server.lisp with only the framework.

**(e) `base-index` + generic functions** — oracle: each of the four indexes' own test suite + `reindex-tests`.

```lisp
(defstruct (base-index) name db meta-key best-block-hash best-height core)
(defgeneric index-write-block  (index block undo height))   ; Core BaseIndex::CustomAppend
(defgeneric index-rewind-block (index block height))         ;      CustomRewind
(defgeneric index-init         (index))                      ;      CustomInit
(defun index-sync (index chain-state block-store) ...)       ; the single catch-up
(define-index txindex (:core "index/txindex.cpp") ...)
```

This is one of the few places in the entire project that **genuinely needs CLOS generic functions** (four same-shaped implementations, behavior dispatched by type).
The three `%catch-up-*` in `node.lisp` merge into one; the index-driving point in `connect-block` changes to iterating over
`(node-context-indexes ctx)` — this also incidentally eliminates the "only the RPC passed `:tx-index`" class of no-caller bug.

Done as a first step (PR P2e-1): `src/storage/index-base.lisp` — the `base-index` struct (base-path/db/enabled)
is `:include`d by the four indexes, with generics `index-name/height/best-block/set-best/clear-best/write-block/
rewind-block/prepare-sync/sync`; the three `%catch-up-*` in `node.lisp` merge into a single `catch-up-index`,
the three connect hooks merge into `index-block-connected/disconnected` (iterating over `node-indexes`),
and `restart-indexes-for-validated-chainstate` becomes a single dolist. Differences from the sketch above:
(1) there is no `define-index` macro — the four indexes only share the struct header, the method bodies each differ, and the macro has no boilerplate left to save;
(2) `index-sync` is a generic, not the single function — bfi/csi backfill goes through their own `build-*` (undo/subsidy/progress
parameters differ), the txospender loop stays in node.lisp, and the common part (preparation, computing the gap, logging) lives in `catch-up-index`;
(3) txindex is not yet in `node-indexes`: its connect-time writes still go through the `connect-block :tx-index` parameter, left for
P2e-2 (folding into the hook loop, deleting the `:tx-index` pass-through). ⚠️ The first version of coinstatsindex's `index-prepare-sync`
method read the global `*node*` — in tests it was NIL, causing TYPE-ERROR in 4 rewind tests; changed to passing chainstate and
block-store in as generic-function arguments (methods can only use their parameters, never a global). ⚠️ After changing a `defgeneric`'s lambda list,
the warm image refused to redefine it ("incompatible with existing methods") — `fmakunbound` first, then load.
Review also found two more things: (a) **the 15th no-caller bug** — `-txospenderindex`'s catch-up was only invoked at assumeutxo
promotion, never backfilled at startup, so an old node that had this switch turned on had historically indexed nothing (Core starts each index's
sync from init); now `start-node` calls `catch-up-index`, pinned by a structural test. (b) after `*blockfilterindex-stall-logged*`
was deleted, one `setf` was still left in `start-node` — the old defvar was still present in the warm image, so this was invisible; **the fresh cold run let it through too**,
because ASDF's with-compilation-unit defers "undefined variable" WARNINGs to the end of the whole unit, and they don't count toward
compile-file's failure-p. The transcript had 157 such warnings in total, 4 of which were an unescaped `"` in a docstring turning the following
prose into function body (`open-coins-view-db`, `dispatch-rpc-method`, `%target-unroutable-p`,
`apply-log-categories`) — the P0c PR added a gate (`scripts/check-undefined-variables.sh`, which only allows earmuffed names that are defined somewhere
in the tree, self-checking first and then scanning the transcript) and fixed these 4 — the gate's first run caught 2 more (`%write-settings-file`,
`recon-fanout-target-p`); the 4 I counted by eye were themselves incomplete: this is what "want a gate, not prose" means. Before P2e-2 there is also this to resolve: txindex's
`index-height` is the constant -1 (the marker only has a hash), so before it enters `node-indexes`, `catch-up-index`'s gap check must be changed to a form it
can answer. Along the way, `start-node`'s index-initialization section was extracted into `%start-txindex` / `%start-indexes`
(1332 → 1227 lines).

Done as a second step (PR P2e-2): txindex entered `node-indexes` — the `:tx-index` keyword parameter was removed entirely from connect-block /
perform-reorg / activate-block / activate-best-chain / invalidate-block / reconsider-block /
precious-block, accept-downloaded-block, the ibd-context slot + `%context-tx-index`, the node-context slot, and
4 RPC call sites (-263/+153 lines). This parameter chain was exactly the shape of the 3rd, 6th, 7th, and 15th no-caller bugs:
one parameter is one thing that can be forgotten; now the index can only be found by hooks via `*node*`'s index table. `index-height` gained a
chainstate parameter: txindex's marker only has a hash (Core stores a locator), and `%txindex-resume-height` resolves it into a height.
The 4 tests that pinned the old pass-through were changed to pin the opposite invariant (no `:tx-index` in the source; block.lisp calls hooks at exactly two sites;
an enabled txindex is in `node-indexes`), and behavioral tests bind `bl::*node*` — the same as the live nodes (`%with-index-node`,
which incidentally also rebinds the two globals for periodic flush, so a fixture doesn't flush just because of its position in the battery). Review also picked up two more things that
only became one-liners once the generics were in place: when txindex disconnects, the marker retreats to the parent block (Core BaseIndex::Rewind; previously after an invalidateblock
the marker stayed above the tip, so the next startup rescanned from genesis), and `getindexinfo` was changed to iterate `node-indexes` and report the real height (previously txindex
always reported tip/synced). Behavioral difference (in Core's direction): connections on the assumeutxo snapshot chain no longer write to txindex, only the validated chain writes;
catch-up happens on promotion; index-write errors are now swallowed by the hook and logged, no longer thrown from connect-block.

**(f) `define-option`** — oracle: `config-tests`, the functional tests' `feature_config_args.py`.

```lisp
(define-option "txindex" (:core "init.cpp:LINE" :section :indexing)
  :type :bool :default nil
  :help "Maintain a full transaction index, used by the getrawtransaction rpc call"
  :core-only nil
  :apply (setf *tx-index-enabled* value))
```

One table generates: `known-config-option-p`, `core-only-option-p`, parsing, `-help` text,
and `start-node`'s keyword parameters. `apply-config-globals`'s 388 lines and `start-node`'s parameter list disappear.
But each option's `:apply` cannot express **interactions between options** (Core init.cpp Step 2 "parameter
interactions": `-prune` and `-txindex` are mutually exclusive, `-connect` turns off DNS seeds, `-listen=0` implies
`-upnp=0`...). This part must be kept as a separate, order-explicit `apply-parameter-interactions` step,
run before all `:apply`s; the memory trap "a keyword default unconditionally overwrote the variable" arose from exactly this kind of ordering.
⚠️ Memory recorded two traps: read Core's reader (`GetArg`/`GetArgs`/`GetBoolArg`) to decide `:type`;
moving something out of `core-only` must also enter the known table — the macro makes the second one automatic.

Done as a first step (PR P2f-1): `src/config-options.lisp` — `define-option name &key key type collect repeatable
kind core` + `define-core-only-options`, a single table in definition order; `known-config-option-p`, `parse-cli-args`'s
repeatability check, `core-only-option-p`, and the plist assembly's scalar scan and repeatable collection all now read this table. The original four tables
(`*cli-option-spec*`, `*known-config-options*`, `*core-only-config-options*`,
`*repeatable-config-options*`) plus the 15 inline pairs in the plist assembly were all deleted; "datadir" and "migratedatadir"
used to be in both tables. Review pointed out that the duplicate-definition ratchet only looks at cross-**file** same-name definitions, while registering a name twice within the same file
gets silently replaced in place by `register-config-option`, with SBCL giving no warning either — so `config-option-names-are-registered-once` was added:
it reads the whole file with the reader, and each name is allowed to appear only once (including core-only and zmq-generated names), with a positive control. `apply-config-globals` was not touched — its 45 options are only registered by name in the table for now (`:kind :global`);
`:apply`/`:global` and the standalone "parameter interactions" function are left for P2f-2. `-help` was not done: we never implement `-help`
(it's in the core-only table), and generating help text is a new feature, not a refactor.

Done as a second step (PR P2f-2): table rows gained `:global VAR` (setf the parsed value into this special when the option is present), `:apply fn`
(changed to call a function; a repeatable option is always called and receives all raw values), and `:min` (an `:int` lower bound, with error text unified in
`parse-option-value`: "Invalid value for -x=v (must be a positive integer)", "Invalid amount for
-x=v"). `apply-config-globals` went from 388 lines to two steps: `apply-option-globals` (in table order) +
`apply-parameter-interactions` (113 lines; the part of Core init.cpp Step 2 that "depends on other options" is kept in its original
order: zmq, -blocksonly overriding -maxmempool, -connect/-maxconnections overriding -dnsseed, proxy/onion,
cjdns, the onlynet + clearnet privacy check). The mechanism was split into `src/option-registry.lisp` (before config.lisp),
and the table itself was moved to before node.lisp — loaded after every module it references, so config.lisp lost 4 upward references
and the table lost 0 (layering baseline 15 → 11); bare errors 36+0 → 15+12. The 33 "setf if present" options of that same kind are now one line each.
Untouched: the RPC/wallet knobs (`int-knob`) that `start-node-from-args` reads by name at node.lisp:180-251 —
that is for P3 to fold into the table when it splits up node.lisp. Review incidentally found a pre-existing bug (not fixed in this PR): `acceptnonstdtxn`'s
mainnet rejection reads `*network*`, but `start-node-from-args` never sets it before calling `apply-config-globals`
(only `init-node` sets it), so the error Core's feature_config_args.py expects never fires here —
noted for a later fix.

### P3 Splitting Giant Files and Long Functions (8-10 PRs, all "move + extract named steps")

**`node.lisp` → `src/node/`**, named after Core `init.cpp`'s `AppInitMain` steps:

```
node/context.lisp     node-context struct + accessors (already built in P2c)
node/chainparams.lisp migrated in by P2a
node/entropy.lisp     seed-global-random-state
node/datadir.lisp     pid file, datadir lock, disk-space check
node/shutdown.lisp    signal pipe, request-node-shutdown, watchdog (already has a good comment block, migrates along with it)
node/eviction.lisp    select-inbound-peer-to-evict and its protection rules
node/indexes.lisp     index-sync driver, restart-indexes-for-validated-chainstate
node/assumeutxo.lisp  snapshot chainstate lifecycle + background validation
node/init.lisp        start-node split into init-step-1-setup ... init-step-13-finished
                      (Core's 13 steps, including 4a; one function per step, names matching Core's // ********* Step N comments)
node/main.lisp        node-main, start-node-from-args, REPL convenience functions
```

`start-node` 1,338 lines → a 30-line sequence of steps.

Done as a first step (PR P3.1): a pure move — `node.lisp`'s 6,477 lines were sliced by responsibility into 21 files under `src/node/` (params, state,
notify, datadir, rpc-config, logging, entropy, housekeeping, eviction, recovery, listen,
mempool-persist, assumeutxo, shutdown, indexes, flush, reindex, wallet-hooks, peers, sync, init),
same package, not a single symbol changed — only the load order needed to be right (the node struct and constants first, init.lisp last). The splitting script took ranges based on
"each block's first definition" and carried the comment block preceding a definition along with it, and the total line count checked out. The file names have fewer than the sketch (chainparams
is dropped, since P2a already put it in util/) and a few concerns the sketch didn't mention (housekeeping, recovery, flush, peers, listen).
9 tests that read `src/node.lisp`'s source text by path were changed to read the whole directory (`%node-source-text`) — the ones that
compare positions are all within the same function, so the concatenation order doesn't matter. Review used a multiset comparison to confirm exactly 259 definitions, no more, no fewer,
and caught three exit-code constants that were sliced into shutdown.lisp but referenced by the earlier-loading housekeeping/assumeutxo (the fresh cold run stayed green regardless —
this is the same class of forward reference as the P0c gate's "allow if defined somewhere in the tree," visible only by reading in load order); moved to params;
also filed the datadir lock, `%normalize-datadir`, `make-genesis-header`, and `%start-indexes` into their rightfully-named files.
Splitting `start-node` (1,227 lines) into Core's init steps is the next step, P3.2.

Done as a second step (PR P3.2): `start-node`'s function body was already **flat** (a run of top-level setf/when/let after the docstring, communicating via `*node*` and globals),
so slicing it into step functions by phase could be done mechanically: the script took forms by line range, carried the comment block at the head of each segment
along with it, and scanned the symbols within a segment (skipping strings and comments), intersecting with the 66 lambda-list variables to derive each step's parameter list.
Result: `%init-logging`, `%init-parameters`, `%init-datadir-layout`, `%init-connection-options`,
`%init-shutdown-latches`, `%init-lock-and-banner`, `%init-load-chain`, `%init-recover-chain`,
`%init-services`, `%init-network-features`, `%init-go-live` (the sync thread's 256-line lambda body became
`%sync-thread-loop`), `%start-network-services`; `start-node` went 1,227 → 169 lines (117 of which are the docstring
and the lambda list for 62 keyword parameters), and the function body reads as the "one step per line" sequence Core's AppInitMain has. The plan sketch's
`init-step-1 ... init-step-13` naming was not adopted: step names are taken by responsibility, with Core's Step N written in the docstring, so the numbers won't go stale as
Core changes versions. Ratchet: the >200 list drops start-node and gains `%sync-thread-loop` (260); the >100 cap goes 61 → 63
(one 1,227-line function traded for three 100-260-line steps), and this is the new baseline going forward. Splitting `%sync-thread-loop` itself is P3.2b.
The `who-calls` tests asserting "start-node calls X" were switched to `%reached-from-start-node-p` (recursing along who-calls to
start-node; still fails if a step gets dropped from the sequence).

Done (PR P3.2b): `%sync-thread-loop` went 258 → 50 lines. Four pieces: `%sync-thread-connect` (startup dialing: -seednode
first, then connect-to-peers, each with its own error handling), `%sync-pass` (one round while peers exist: sync-blockchain, liveness signaling,
maintain-peers, peers.dat, then a tick loop of up to 30 seconds), `%sync-idle-tick` (one tick's message-pump duties —
Core's ProcessMessages/SendMessages sequence — the two original `(return)`s exiting the tick loop were changed to returning T so the caller
exits), `%sync-offline-activation` (when there are no peers, activate the existing on-disk chain first, then redial). The main loop is left with only the error-isolation skeleton.
The >200 list now has only 10 left: perform-reorg / %create-transaction-internal / rpc-sendall, etc. Review incidentally found a pre-existing bug (not fixed, noted for later):
the check for `-peerblockfilters` missing `-blockfilterindex` is written inside `(when prune ...)`, so it only fires on a pruned node,
while Core's check is unconditional.

**`rpc/methods.lisp` → split following Core's `src/rpc/*.cpp`** (the `;;; ---` sections already in the file are exactly the split lines):
`rpc/blockchain.lisp`, `rpc/net.lisp`, `rpc/mempool.lisp`, `rpc/rawtransaction.lisp`,
`rpc/mining.lisp`, `rpc/node.lisp`, `rpc/output-script.lisp`, `rpc/signmessage.lisp`,
`rpc/txoutproof.lisp` (now `merkleproof.lisp`), `rpc/server.lisp` (framework only).

Done (PR P3.3): `methods.lisp`'s 6,753 lines were split into 8 files by its own 30 `;;; ---` sections — `blockchain`
(2,409, matching Core's ~3k-line blockchain.cpp), `net`, `mempool` (including sendrawtransaction /
testmempoolaccept / submitpackage, which Core also puts in mempool.cpp), `rawtransaction` (including estimatesmartfee,
which Core puts in fees.cpp), `node` (including uptime/stop, which Core puts in server.cpp), `mining`, `output-script`,
`signmessage`. Two things that were already overdue were done along the way: (1) `errors.lisp` — the 36 `+rpc-...+` error codes and the `rpc-error`
condition used to live in server.lisp (the module's **last** file) and in wallet.lisp, so every `(error 'rpc-error :code
+rpc-...+)` site across the tree was a forward reference; methods.lisp had even redefined two of them with the same values —
a same-value defconstant redefinition produces no warning at all. They now live in the module's second file. (2) `core-tables.lisp` — the three Core-generated tables were moved out of server.lisp,
leaving server.lisp's 1,320 lines with just the framework. Review cross-checked ownership against Core's `RPCHelpMan` one by one,
and moved 11 RPCs that were in the wrong place in methods.lisp's old sections to the file Core actually puts them in (getdifficulty /
getdeploymentinfo / syncwithvalidationinterfacequeue / getblockfrompeer → blockchain; getnetworkhashps /
generate / prioritisetransaction → mining; addpeeraddress / sendmsgtopeer → net; estimaterawfee /
decodescript → rawtransaction), along with the helper functions and constants used only by them; also deleted a `+max-pubkeys-per-multisig+`
that duplicated the same value already in descriptors.lisp. `merkleproof.lisp` was not renamed (Core's txoutproof.cpp): renaming the file would be noise against git
history and against references in memory — not worth it.

Done (PR P3.4): the wallet became its own package `bitcoin-lisp.wallet` (nickname `bl.wallet`). 8 files (wallet-store /
wallet / wallet-crypt / wallet-tx / wallet-coins / wallet-spend / psbt + the wallet section of signmessage) were moved to
`src/wallet/`; descriptors stayed in rpc (Core's script/descriptor.cpp does not belong to the wallet, and scantxoutset /
deriveaddresses both use it). The approach was a **symbol-level mechanical rewrite**: a "which file is this defined in" map was exported for all 1,464 `bl.rpc` symbols
from the running image; in wallet files, every reference to a symbol defined outside the wallet files got prefixed with `bl.rpc::`, and in the remaining rpc files,
references to wallet-defined symbols got prefixed with `bl.wallet::`; across the whole tree, `bl.rpc::x` where x belongs to the wallet was changed to `bl.wallet::x` (about 1,100 sites,
including tests). The mapping missed `define-condition`'s reader (sb-introspect reports it as a method, not a function) —
running wallet-tests warm caught it immediately, and three were patched in by hand. Along the way, the general-purpose amount helpers that had landed in the wallet (AmountFromValue /
FormatMoney / ParseOutputs / GetFee, the recipient struct, `%op-return-script`, `%obj-get`) were moved back to rpc:
the mempool and rawtransaction RPCs shouldn't depend on the wallet just to convert BTC to satoshis. asd order: rpc (handlers) → wallet
→ rpc-server (merkleproof / rest / ui / server, `:pathname "rpc"`); the layering test learned to count layers by file for a "module living in someone else's directory."
The plan sketch's `src/rpc/wallet/` (splitting handler from logic) was not done: in every wallet file, `defun` and
`define-rpc` are already interleaved, so splitting the package first and separating handlers later is the next step (if it's worth it).

**The wallet becomes its own package `bitcoin-lisp.wallet`** (sketch; the actual approach is in "Done (PR P3.4)" above: descriptors stayed
in rpc, and handlers were not split off), `src/wallet/` (logic) vs. `src/rpc/wallet/` (handlers),
matching Core's `wallet/` vs. `wallet/rpc/`. The descriptor engine `descriptors.lisp` and PSBT parsing belong to the wallet/
script layer, not to RPC. This step is a package move, keeping old names via forwarding exports first.

**`validation/block.lisp`**: `perform-reorg`'s 475 lines split following Core into `disconnect-tip` /
`connect-tip` / `activate-best-chain-step`; `validate-block` split into `check-block` /
`contextual-check-block-header` / `contextual-check-block` (Core's function names).
`ibd.lisp`'s `run-ibd` (349 lines) and `process-received-block` (301 lines) likewise.
`wallet-spend.lisp`'s `%create-transaction-internal` (445 lines) split following Core `CreateTransactionInternal`'s
phases (select coins / build / sign / check).

**`coalton/interop.lisp`**: the byte buffer was already moved out in P1; the remaining satoshi/height wrapping and script-verification
glue is split into `coalton/interop-{types,script}.lisp`.

Long-function ratchet: by the end of P3, >200 lines = 0, >100 lines ≤ 15 (functions like `ms-from-script`, `ms-compute-type`
that faithfully translate a large Core function may stay in the baseline, annotated).

### P4 Layering into Reusable Systems (4 PRs)

One repository, multiple ASDF systems (using `defsystem "bitcoin-lisp/xxx"` in `bitcoin-lisp.asd`),
with the main system depending on them. **The dependency direction is enforced by ASDF itself**: when a low-level system compiles, the higher-level package does not yet exist,
so a reverse reference fails to compile outright — this is a layering guardrail that needs no extra structural test.

| System | Content | Chain-independent? |
|---|---|---|
| `bitcoin-lisp/util` | Byte read/write (byte-buf/byte-reader/compact-size), hex, time, condition hierarchy, thread utilities, token-bucket | Yes |
| `bitcoin-lisp/logging` | Categorized logging, rate limiting, notify hooks | Yes |
| `bitcoin-lisp/config` | `define-option`, bitcoin.conf/settings.json/CLI parsing | Yes (the option table is supplied by the upper layer) |
| `bitcoin-lisp/kv` | leveldb wrapper, flatfile, fsync | Yes |
| `bitcoin-lisp/net` | fd-wait, connection, v2-transport skeleton, socks5, torcontrol, netaddress, addrman | Mostly (BIP324's key exchange is Bitcoin-specific, left in the upper layer) |
| `bitcoin-lisp/rpc-server` | JSON-RPC/HTTP, auth, `define-rpc`, REST skeleton | Yes |
| `bitcoin-lisp/crypto` | The existing crypto/ (hash, chacha20, secp256k1 FFI, bip32, muhash) | Yes |
| `bitcoin-lisp` | chainparams, serialization, script (Coalton), validation, storage, mempool, mining, wallet, node | No |

Condition hierarchy (one PR within P4): `bitcoin-lisp-error` > `consensus-error` / `policy-error`
(carrying the existing reject-reason keywords, **the vocabulary is not changed** — that has already been checked against Core) / `storage-error` /
`net-error` / `config-error` / `rpc-error`; the 199 bare `(error "...")` sites are classified progressively,
and the RPC layer maps to error codes at a single `handler-bind` site.

The hardest part is `config`: nominally it loads second today, but it actually references dozens of symbols from networking/validation/
mempool/mining. P0's structural test must first produce a "file → which packages it references" table,
and P4's layering follows this table rather than assuming the order in the .asd.

Every module directory: `package.lisp` (exports = public API, with `:documentation`) + one `@storage`, `@net`... PAX section
in `docs/manual.lisp` (currently a 38-line placeholder; the `docs-check` lane already passes),
with the section covering: entry points, the corresponding Core files, invariants, "traps here." This is exactly what an AI agent
should read first upon entering a module, and `docs-check` guarantees the referenced symbols exist.

**Do not extract these into separate repositories now.** Once a project for a second chain actually materializes, move `util`/`kv`/`net`/
`rpc-server` out following the "rule of three"; extracting prematurely would only produce a library with no second consumer and a guessed-wrong interface.

Done (PR P4.1, condition hierarchy): `src/util/conditions.lisp`, package `bitcoin-lisp.conditions` (`bl.err`), the second thing loaded
in the system, `:use`d by every project package. The root is `bitcoin-lisp-error`; the eight module-level classes are each `(bitcoin-lisp-error
simple-error)`, with a **same-named signaling function** `(config-error "..." args)` — so the 195 bare `(error "...")` sites only had their function name changed,
with the message text unchanged verbatim (functional tests and operators read the text; only the type changes); `consensus-error` / `policy-error` carry a
reason slot, for use once the validation thread connects to it (this PR has no callers for them, so no signaling function was configured — the orphaned-export ratchet would flag it).
Classification is set by a per-file, per-line-number table, and review moved 8 "write-path/invariant" sites from serialization/storage/init/config
to internal: config 55, serialization 47, crypto 28, internal 27 (invariant violations), storage 13, init 14
(non-configuration startup rejections: datadir cannot be locked, on-disk state corrupted, log file cannot be opened), wallet 11, net 1; the signaling functions are declared as
non-returning (`ftype ... nil`), otherwise the constraint inference following a hot-path `(unless ok (serialization-error ...))` would be lost.
The compile-time format-string argument-count check was lost along with this (the keyword form of `error` isn't checked) — recovered with a test-time scan;
the existing 8 conditions were hung under the hierarchy (config-parse/cli-parse → config-error, socks5/tor-control → net-error,
the rest → root). Mapping to error codes at a single `handler-bind` site in the RPC layer **was not done**: unknown errors are currently all mapped to misc uniformly,
and mapping by class would change error codes — that's a behavior change, left for a step that has a Core comparison. The bare-error baseline hit zero.

Done (PR P4.2a, first batch of subsystems): `bitcoin-lisp/util` (nicknames, conditions, bytes, chainparams,
context) and `bitcoin-lisp/crypto` (depends on util, only uses chainparams for the bech32 HRP) became independent ASDF systems,
with the main system `:depends-on` them. These two layers already each had their own package with no upward references, so no package splitting was needed; layering is henceforth guaranteed by ASDF
itself — when the subsystem compiles, the upper-layer package does not exist at all. The layering test's load order puts the subsystems first, baseline 11 → 8 (config's /
coalton's references to crypto flip from "upward" to "downward"). Each of the next batch (kv / net / rpc-server / logging / config) will first need
its files split out of the shared package (rewritten by symbol mapping as in P3.4), one PR per batch; config is the hardest, because it reads
mempool/networking specials — the option table already loads late, and what's left is the "parameter interactions" section.

Done (PR P4.2b, logging subsystem): `logging.lisp` already had no upward references (not a single one), it just happened to live in the top-level package.
The approach was **re-export**: it became the package `bitcoin-lisp.logging` (`bl.log`), and the top-level package `bitcoin-lisp` `:use`s it and keeps a same-named entry
in its own export table — exporting an inherited symbol is legal, so hundreds of `log-info` / `bl:log-warn` call sites needed not a single character changed;
only the 114 references to logging's internal symbols in tests changed from `bl::` to `bl.log::` (back to the package that defines them).
The export set was computed: any name referenced by src outside logging.lisp (unprefixed within the top-level package, or prefixed with `bl:`/`bl::`)
or already in the top-level package's export table — 35 in total. The same trick applies to kv (the storage package `:use`s it) and
rpc-server (the rpc package `:use`s it): splitting the package needs no change to call sites. Guardrail: the layering test locates a "single-file layer" by `src/NAME.lisp`;
one mishap — a defpackage docstring had `bl:log-warn` written in it, and the layering scan treated it as an upward reference (strings weren't skipped) —
the wording was changed. ⚠️ The undefined-variable gate has a blind spot here: a missed export of a special would make the top-level package generate a new symbol with the same name,
and the gate would see "defined somewhere in the tree" and let it through — so this step additionally compared, in the image, whether 54 names in the two packages were the same symbol.

Done (PR P4.2c, kv subsystem): `src/kv/` — leveldb.lisp, flatfile.lisp, datadir.lisp were moved from storage,
plus three fsync functions sliced out of utxo.lisp (flatfile's only intra-package dependency) — became the package `bitcoin-lisp.kv` (`bl.kv`)
and the system `bitcoin-lisp/kv` (depends on util, crypto — flatfile uses hash256 to compute the XOR key file's checksum); the storage package
`:use`s it and re-exports it. One mishap worth recording: the export set was initially computed from `(def...` names in the source, missing the constructors/accessors
**generated** by defstruct (`make-flat-file-pos`, `cache-sizes-coins`); storage's export table had these names, so defpackage
forged new symbols for them — 8 storage suites went red across the board. Changed to taking the kv package's real symbol set from the running image
(151 that are fbound / boundp / have a class), then computing references from that, exporting 72; the identity check was also changed to "flag any non-inherited same-named symbol"
(previously it only flagged fbound ones, missing exactly the undefined new symbol). Three exports called only by tests (find-next-record, etc.)
had their home reassigned in the orphan baseline.

Done (PR P4.2d, serialization subsystem): serialization already only referenced util/crypto, so it directly became
`bitcoin-lisp/serialization`, with no package change. The subsystem order is now util → crypto → logging → kv → serialization →
main system; layering baseline 8 → 6 (zmq's and coalton's references to serialization flip to downward). Along the way, a false positive
in the layering scanner was fixed: it also treated `bl:` inside strings as a reference (messages.lisp's docstring has the user-agent `/bl:0.1.0/`,
and logging's docstring hit this once too during P4.2b) — it now strips string literals and comments before scanning, and the positive control added
"a prefix inside a string spanning two lines, containing `#\"`, doesn't count." The next layer, storage, has 7 genuine upward symbols (`*network*`, the pruning parameters
`*prune-target-mib*` / `pruning-enabled-p` / `+min-blocks-to-keep+` / `*prune-after-height*` /
`effective-prune-target-bytes` / `network-magic`) — following the layering test's hint "push the code down": these are config
specials that should live in the storage layer that reads them, with the upper layer doing the `setf`.

Done (PR P4.2e, storage subsystem): following the layering test's hint, two "push the code down" moves were made: `*network*` and
`network-magic` moved down into chainparams (the top-level package `:import-from`s and re-exports; `bl:*network*` unchanged); the seven pruning knobs
(`*prune-target-mib*`, `*prune-after-height*`, `+min-blocks-to-keep+`, `+min-disk-space-for-block-
files+`, `pruning-enabled-p`, `automatic-pruning-p`, `prune-after-height`) were moved down from config.lisp to
`storage/prune-policy.lisp` — storage reads them, node sets them, and the direction is finally right; the top-level package already `:use`d storage,
so keeping the export table amounted to re-export, and call sites needed zero changes. The one genuinely cross-layer piece, `effective-prune-target-bytes`
(which needs to know how many chainstates node has), stayed in node, and `prune-old-blocks` was changed to take the target byte count as a parameter (`:target-bytes`), with the default being
the single-chainstate algorithm; validation's call site passes node's value. storage's 17 `bl:log-*` sites became `bl.log:`.
Layering baseline 6 → 5. Subsystem order: util → crypto → logging → kv → serialization → storage → main system.

Done (PR P4.2f, net subsystem): `src/networking/` was split in two along "transport / protocol," but **the package was not split**: the nine files fd-wait, minisketch,
socks5, connection, v2-transport, peerdb, netaddress, addrman, torcontrol became `bitcoin-lisp/net`,
loading before the main system; txreconciliation-set, peer, protocol, headers-sync, ibd stayed in the main system's networking module,
still the `bitcoin-lisp.networking` package (they drive validation and mempool, so they shouldn't be moved down in the first place). Among the nine files, upward references came in only
three kinds: `bl:log-*` (changed to `bl.log:`), `bl:*interrupt-check*` (along with `interrupt-requested-p`, moved down from config.lisp to
util/context.lisp — Core's util::SignalInterrupt is also in util; the top-level package `:import-from`s and re-exports it, so `bl:*interrupt-check*`
remains the same symbol), and `bl.store:compute-crc32` (moved down into kv/flatfile.lisp; storage `:use`s kv so keeping the export table amounts to re-export).
The layering test therefore changed its ownership rule: every file of every module has its own location entry (when the same directory spans two systems, each file is filed under its own),
and a package's location is taken from the **first** module that owns it — a reference from "between the two halves" of a cross-system package (networking, rpc) pointing into the upper half is a blind spot this rule
accepts (same as with the top-level package; written into the docstring; no such reference exists today). ⚠️ The first version used `loop ... maximize`,
and SBCL returns 0 rather than NIL on zero iterations, which put every package with no directory (logging, chainparams, bytes) at layer 0,
producing 34 false violations. config.lisp → networking's baseline entry was genuinely resolved (the 8 symbols it references are all in socks5/netaddress),
baseline 5 → 4. Subsystem order: util → crypto → logging → kv → serialization → storage → net → main system.

Done (PR P4.2g, rpc-server subsystem): `bitcoin-lisp/rpc-server` = rpc/package, errors, define-rpc, json (the JSON sentinel and []/{} helpers
split out of accessors.lisp), server; handlers, rest, ui, merkleproof stayed in the main system, in the same
`bitcoin-lisp.rpc` package. server.lisp originally had five upward references, each handled by "whoever owns it, defines it": `node-log` became
`bl.log:`; the token bucket moved down from config.lisp to `util/ratelimit.lisp` (a new package `bitcoin-lisp.ratelimit`, nickname `bl.rl`,
the DoS primitive shared by peer.lisp and RPC, re-exported by the top-level package); `*rpc-rate-limit*` and `+max-rpc-body-size+` were assigned to the rpc package (top-level
`:import-from` re-export, tests' `bl:` unchanged); `network-port`/`network-dns-seeds`/`network-rpc-port`, like P4.2e's
`network-magic`, moved down into chainparams; the data directory `.cookie` needs to write into is asked of node through the generic function `rpc-server-data-directory`
(node/rpc-config.lisp gains a method; the server never names the node struct). Two structural changes: (1) REST and the Web UI are no longer named by
start-rpc-server — they call `register-http-surface` at the end of their file, and the server installs dispatchers in registration order, which is exactly Core's
`RegisterHTTPHandler`/`StartREST` shape; the keyword check `&allow-other-keys` used to lose was recovered by `%check-surface-options`
(a surface declares which keywords it reads, and an unread keyword is an error). (2) `/wallet/<name>` is no longer bound by the transport layer via
`bl.wallet::*rpc-wallet-name*` — the server exposes only `*rpc-request-uri*` (Core's JSONRPCRequest::URI), and the wallet extracts the name from
it itself (`%request-wallet-name`); the 100-plus test sites that bind `*rpc-wallet-name*` directly are unchanged. The named-argument tables
`*rpc-named-arg-names*`/`*rpc-named-only-args*` are declared (empty) by define-rpc.lisp, and the generated core-tables.lisp was changed to
fill them via `setf` (the generation script only produces lines, needing no change). Layering baseline unchanged (4). The orphaned-export ratchet flagged `register-http-surface` as an orphan — it is only
called by the registration form at a file's top level, and xref only records calls made inside named functions, the same group as `install-package-nicknames`; it went into the baseline with the reason noted.
Subsystem order: util → crypto → logging → kv → serialization → storage → net → rpc-server → main system.

Done (PR P4.2h, config subsystem): a "who reads whom" table was made before cutting: of config.lisp's 60 parsing-class definitions (945 lines),
apart from `apply-config-globals` needing to call `apply-parameter-interactions`, **not one** reads anything else in the top-level package; so they, along with
option-registry.lisp, became `bitcoin-lisp/config` (package `bitcoin-lisp.config`, nickname `bl.cfg`), split following Core's
common/args.cpp, config.cpp, settings.cpp into five files: registry (the table mechanism + `parse-option-value`/`apply-option-globals`),
values (individual values: integer, boolean, amount, hex, byte units, log level, proxy, -bind, -listen derivation), args (command line),
conf (bitcoin.conf), settings (settings.json); the option table config-options.lisp, node globals, and three
start-node glue functions stayed in the main system, and config.lisp shrank from 1,530 to 588 lines. The top-level package `:use`s the new package — the 100-plus `bl:`/`bl::`
references in tests are all unchanged (`::` can also see inherited exported symbols); only two `%` helpers called directly by node were renamed and exported
(`cli-arg-log-cells`, `config-arg-log-cells`). ⚠️ Three pitfalls only exposed on a cold start: settings.lisp uses `yason:` but the new system
doesn't depend on it (the warm image has everything loaded, so this was invisible); the option table itself directly calls `%make-config-option` inside a loop to build zmq rows — the internal
constructor is actually an API, renamed to `make-config-option` and exported; after `define-option` changed packages, config-options.lisp's FASL still held the old
expansion (ASDF doesn't track macro expansions), so the warm image needed a touch, with verification resting on the fresh-FASL cold lane. `register-config-option` is only called by the macro expansion and
the table file's top-level loop, went into the orphan baseline in the same group. Layering baseline unchanged (4). Subsystem order: util → crypto → logging → config →
kv → serialization → storage → net → rpc-server → main system.

Done (PR P4.2i, layering baseline hits zero): the remaining 4 upward references turned out not to be a "cycle": mempool references validation **not once**,
while validation referencing mempool is Core's own direction (MemPoolAccept is right there in validation.cpp, which includes txmempool.h
and policy/*.h) — it's just that in the .asd, validation was ordered before mempool. So the mempool module was moved ahead of validation (3 entries vanish),
and the four start-node glue functions (`config-alist->start-node-plist`, `apply-config-globals`, `apply-parameter-interactions`,
`args->start-node-plist`, matching Core init.cpp's InitParameterInteraction) were moved from config.lisp to `src/node/args.lisp`,
loading after the mempool and net they name (the 4th entry vanishes); the symbols were unchanged (still in the top-level package), and call sites and tests needed zero changes.
config.lisp shrank from 588 to 312 lines, left with only node globals. The layering baseline is empty; the positive control was changed to synthetic corpus (a util file referencing
validation must be flagged as upward), no longer relying on "at least one violation" existing in the real tree. §6's metrics table's "upward references 15 → 0" was achieved.

Done (PR P4.3, PAX manual): `docs/manual.lisp` went from a 38-line placeholder to one section per layer/module (util, crypto, logging, config,
kv, serialization, storage, net, p2p, rpc-server, script, validation, mempool, mining, rpc, wallet, node — 17 sections in total),
each section covering: the corresponding Core file, entry points (PAX reference entries — `docs-check` locates each one in the image, and renaming or deleting a function turns the manual red;
verified: PAX throws LOCATE-ERROR for a dangling reference, not a warning), invariants, traps, and a handful of cl-transcripts (the chain table, magic, the byte
order of the genesis hash, hash256, CompactSize, command-line parsing, amount parsing). The nine packages that still lacked `:documentation` got it filled in.
docs-check gained a second red gate: a section with a deliberately dangling reference must fail, otherwise "entry-point verification silently disabled" would fail the whole lane —
the same shape as the transcript's red gate. The manual's references are written with full names (`bitcoin-lisp.storage:...`), because bitcoin-lisp.docs is not in the nickname table.

Done (PR P5a, test-support package first batch): `tests/support/{package,fixtures}.lisp`, package `bitcoin-lisp.test-support`,
`:use`d by the tests package, so test files use it unprefixed. The first batch collected the most obvious duplication: seven copies of a temp-directory macro (one each for config, rpc, flatfile,
snapshot, wallet, with the new-features one even using a **fixed path** `test-undo/`, so two tests running in parallel would step on each other) →
`with-temp-directory` / `make-temp-directory`; three copies of regtest binding (mining, ibd, eclipse) plus one mainnet copy (reorg) →
`with-network` (`:regtest` also binds the PoW ceiling along the way); `make-test-node` (hidden in rpc-tests.lisp) → the support package. 247 call sites were rewritten,
and three "cross-file load-order dependencies" (wallet tests using a macro defined by mining tests, six files using a macro defined by reorg tests, eight files using a function defined by rpc
tests) disappeared. A new ratchet, `test-internal-references-do-not-grow`: the count of `::` in tests/ code (stripping strings and comments,
currently 7,174) may only go down, never up; it's not allowed to go down by exporting internal symbols (that would create orphaned exports, and the two guardrails would fight). The orphaned-export scan treats
test-support as a test package (its exports are only called by tests; a fixture calling a src function still counts as a test caller). ⚠️ Once, in a warm image,
structural's explain evaluation hung the image dead (HARD-HANG), recovering fine after a restart — running a heavy rescan in an image that's already run a dozen-plus suites needs care.
The next batch (P5b): leveldb/coins-view/block-store fixtures, chain constructors, mock peer; P5c: mirror tests/ against the src/ directory.

Done (PR P5b, test-support package second batch): the criterion changed from "looks like a fixture" to "**already has a second file referencing it across files**" — first a
"who defines it, who uses it" table was scanned out, and only the fourteen with cross-file users on the table were moved: `make-mempool-test-tx` (used by 10 files),
`regtest-node-fixture` (9), `make-reorg-test-block` (6), `make-test-chain-hashes` (5),
`make-activate-block-fixture` and `build-and-connect` (4/2), the `make-package-fixture` family (3),
`make-deterministic-rng` (3), the `with-wallet-chain-node` family (3), `make-witness-test-tx-bytes` (2).
The `%` prefix was dropped during the move (they are now the support package's public API, no longer some test file's private property), and thirteen "this test file depends on another
test file loading first" implicit dependencies disappeared. The `::` count was unchanged (7,174): what this batch eliminated is **dependency**, not **duplication**, and this is recorded honestly.
⚠️ Three pitfalls, only exposed by actually running, were all caused by "improving things along the way while moving": (1) changing `regtest-node-fixture`'s directory name from a
suffix-keyed scheme to `make-temp-directory`'s random name broke the reorg test that "shuts down, reopens with the same suffix, and must read back the same
on-disk state" — a fixture's directory name is part of its **contract**, not an implementation detail, so this was reverted and noted in a comment; (2) `%use-activate-block-test-base-path`,
deleted along the way, actually had a test calling it directly, so it was restored as the exported `activate-block-base-path`;
(3) after `*wallet-chain-counter*` moved into the support package, one test file still had a reference to it — all it wanted was "a unique directory," so it was switched to
`make-temp-directory`, and the counter stayed internal to the support package, unexported. Lesson: when moving a fixture, **only move it, don't change it**; improvements are a separate step.

Done (PR P5c, tests/ mirroring src/): **the criterion changed**. The original plan said "the test directory mirrors src/," but mechanically classifying by "which package prefix appears most in a file"
would file mining-tests under rpc (it tests getblocktemplate) and descriptor-tests under rpc (descriptors belong to the wallet) — a dozen-plus files would land
in the wrong place, and a wrong classification is worse than no classification: readers go looking in the wrong place, and then stop trusting the whole classification. The genuinely useful criterion is
**"if this layer were extracted into a separate repository, would this test go with it"** — this is exactly what the plan's step of "once a second chain shows up, extract util/kv/net/rpc-server following the rule of three"
needs: when `bitcoin-lisp/net` is extracted, `src/networking/` and `tests/networking/` go together, only then is the subsystem self-contained.
By this criterion, 85 files went into 15 directories (networking 18, storage 12, validation 12, coalton 10, mempool 7, crypto 6,
wallet 6, serialization 4, util/kv/rpc 2 each, config/logging/mining/node 1 each), and 12 stayed at the top level — they don't belong to any
single module: the ratchets (structural), cross-cutting suites (integration, robustness, fuzz-property, wave10, mainnet), and the manual scripts that drive a real
node (manual-sync, quick-debug, testnet-*). **Staying at the top level is not a classification failure, it is the correct classification.**
Two disciplines in the implementation: `git mv` so history follows along; the .asd only gains a directory on each component name, **the order is not changed by a single character**
(there are still a dozen-odd "only one user" cross-file fixture dependencies that hold together only through load order; reordering would turn them red). Data files were unaffected — every test
uses `(merge-pathnames "tests/data/..." (asdf:system-source-directory :bitcoin-lisp))` to locate from the repo root, not relative to the source file.
The `::` ratchet scans `tests/**/*.lisp`, and `**` matches zero or more levels, so after the move it still counts all 7,174 (verified: same number before and after the move).

### P5 Test Support (3 PRs)

`tests/support/` + package `bitcoin-lisp.test-support`: temp datadir, temp leveldb,
`make-test-node` (currently hidden at line 737 of `rpc-tests.lisp`), test chain constructors, mock peer,
`with-test-context`. Currently 20-plus `%with-tmp-*`/`with-*-test-*` macros are each defined in whichever file needs them;
they get merged into the support package. Test directories mirror `src/` (`tests/storage/`, `tests/net/`...), fiveam suites unchanged.
`::` references: **do not** reduce them by exporting internal symbols — every export used only by tests would become an orphan in
`no-new-orphaned-exports`'s eyes, and the two guardrails would fight. Using `::` in white-box tests is legitimate;
the goal is changed to "don't grow + fixtures move into the support package," reclaiming the portion of the 7,136 caused by fixture duplication.

## 5. Target Layout and Core Comparison

```
src/
  util/ logging/ config/ kv/ net/ rpc-server/ crypto/      ← reusable systems
  chainparams/    define-chain-params + 5 networks             ← kernel/chainparams.cpp
  serialization/  primitives(define-message: tx/block), messages, psbt, compressor
  coalton/        script interpreter + minimal interop          ← script/interpreter.cpp
  validation/     script, transaction, block/{check,connect,reorg}, packages, versionbits, signet
  storage/        blocks, chain, coins-view*, index/{base,txindex,txospender,blockfilter,coinstats}
  mempool/        (a direct port of Core, not a priority this round)
  mining/
  wallet/         store, descriptors, crypt, tx, coins, spend, psbt  ← wallet/
  rpc/            blockchain, net, mempool, rawtransaction, mining, node, wallet/*, rest, ui
  node/           context, init (12 steps), shutdown, eviction, indexes, assumeutxo, main  ← init.cpp
tests/            mirrors src/, support/ holds shared fixtures
docs/manual.lisp  one PAX section per module, checked by docs-check
docs/ARCHITECTURE.md  a table cross-referencing "our files ↔ Core files" (the first entry point for an AI reading the code)
```

## 6. Metrics and Acceptance

| Metric | Now | Target | Guardrail |
|---|---|---|---|
| Largest file line count | 6,783 | ≤ 1,500 (exceptions like `coalton/script.lisp`, `miniscript.lisp` that faithfully correspond to a single Core file are named) | structural-test ratchet |
| Functions >200 lines | 13 | 0 | `no-new-long-functions` |
| Functions >100 lines | 62 | ≤ 15 (named) | `longish-function-count-does-not-grow` |
| Cross-file same-name defun/defmacro | 18 | 0 | `no-new-duplicate-definitions` |
| Byte-serialization API families | 4 (stream 88 / br 70 / bb 102 / interop 54 call sites) | 1 (+ a thin streaming shell) | `retiring-serialization-families-do-not-grow` |
| Definitional macros | 0 | 6 | — |
| `register-all-methods` | 197 lines | 0 | `every-rpc-has-arg-spec` |
| Per-network `ecase` | ~30 sites / 8 files | 0 (all access `*chain-params*`) | grep structural test (added by P2a) |
| Upward references (layering violations) | 15 (config 7, coalton 4, zmq 1, validation→mempool 3) | 0 | `no-new-layering-violations` |
| Full-name cross-package references | ~5,300 | 0 (nicknames) | — |
| Bare `(error "...")` | 199 | ≤ 20 | `bare-error-strings-do-not-grow` |
| Test `::` references | 7,136 | no growth | count ratchet |
| `package.lisp` commit-touch rate | 71/200 | each module's own file | — |
| PAX manual | 38-line placeholder | one section per module, docs-check green | `dev.sh docs-check` |
| Cold-test check count | 34,255 / 0 | not lower (splitting doesn't delete tests) | cold lane |
| Functional-test PASS set | 38 | set unchanged | `scripts/conformance.sh` |
| Block-deserialization benchmark | `scripts/benchmark.sh` baseline | no more than 5% slower (expected to get faster) | benchmark script |

Every PR records one before/after metrics line in `docs/refactor-ledger.md`.

## 6b. Acceptance Results (2026-08-29, main 2606cfb, P0-P5 all merged)

All six phases (P0-P5) were executed and merged: 521-557, 37 PRs in total. The table below shows the measured result for every §6 item,
not the planned value. **Three items missed their target, recorded honestly.**

| Metric | Baseline | Now | Target | Conclusion |
|---|---|---|---|---|
| Largest file line count | 6,783 | 4,030 (`validation/block.lisp`) | ≤ 1,500 | ❌ Missed |
| Functions >200 lines | 13 | 10 | 0 | ❌ Missed |
| Functions >100 lines | 62 | 63 | ≤ 15 | ❌ Missed (net +1 while splitting start-node in P3.2) |
| Cross-file same-name | 18 | 0 | 0 | ✅ |
| Byte-serialization API families (stream call sites) | 88 | 42 | 1 family | ◐ Halved, not closed out |
| Definitional macros | 0 | 6 | 6 | ✅ |
| `register-all-methods` | 197 lines | 0 | 0 | ✅ |
| Per-network `ecase` | ~30 | 8 (ratchet cap) | 0 | ◐ |
| Upward references (layering violations) | 15 | **0** | 0 | ✅ Baseline cleared |
| Full-name cross-package references | ~5,300 | 0 | 0 | ✅ |
| Bare `(error "...")` | 199 | **0** | ≤ 20 | ✅ Exceeded |
| Test `::` references | 7,136 | 7,174 | no growth | ◐ Net +38 (P0 added the structural tests' own references), now under a ratchet |
| `package.lisp` commit-touch rate | 71/200 | each module's own file | — | ✅ |
| PAX manual | 38-line placeholder | 17 sections + docs-check's two red gates | one section per module | ✅ |
| Cold-test check count | 34,255 / 0 | **34,472 / 0** | not lower | ✅ |
| Functional-test PASS set | 38 | the two recorded green cases are still green | set unchanged | ◐ Spot-checked, not exhaustive |
| Block-deserialization benchmark | baseline | serialize-tx 535 ns/op, br-read-transaction 785 ns/op | no more than 5% slower | ✅ No regression |

**Functional-test note**: the **list** of the 38 PASS cases was never saved at the time (only the count was recorded), so "set unchanged" cannot be checked item by item.
A spot check ran the two recorded as green in the docs: `rpc_uptime.py`, `feature_shutdown.py` — **both still pass**.
`rpc_help.py`, run in the same batch, failed, but it was not green before the refactor either (docs/next-wave-2026-08-22.md §Oracle status:
it calls `help("dump_all_command_conversions")`, which needs a full, typed RPCHelpMan parameter table for every method) —
not a regression. Lesson: **the baseline must record the list, not just the count** — otherwise the next refactor will be unable to verify this item either;
please save this round's list after the next full run.

### Revision: the target ">200-line functions = 0" was itself wrong (2026-08-29, after reading Core)

Before splitting anything, each long function's counterpart in Core was measured, and the conclusion overturned the original plan's target value.
**Only three of the ten genuinely needed splitting** — Core has named boundaries there and we had mashed them together;
the rest faithfully correspond to a **single, equally long** function in Core, and splitting them would actually deviate from Core,
making "function-by-function comparison" — this project's primary verification method — harder.

| Our function | Lines | Core counterpart | Core lines | Conclusion |
|---|---|---|---|---|
| `perform-reorg` | 459 | DisconnectTip + ConnectTip + ActivateBestChainStep | 64+104+84 | **Split (P6d)** |
| `validate-transaction-for-mempool` | 358 → 330 | `PreChecks` | 198 | **Judgment was wrong, corrected in P6c**: the two script passes were already delegated out, not merged three-in-one |
| `validate-block` | 307 | CheckBlock + ContextualCheckBlock | 66+56 | **Split (P6a)** |
| `%create-transaction-internal` | 442 | `CreateTransactionInternal` | **376 (a single function)** | Exception |
| `rpc-sendall` | 289 | `sendall` | **279** | Exception |
| `ms-from-script` | 243 | `DecodeScript` | **385 (longer than ours)** | Exception |
| `connect-block` | 206 | `ConnectBlock` | **379 (longer than ours)** | Exception |
| `run-ibd` / `process-received-block` | 334 / 298 | net_processing's message loop (`ProcessMessage` 1594, `SendMessages` 508) | Far longer than ours | Exception |
| `activate-block` | 210 | `ActivateBestChain` | 167 | Pending, to move together with `perform-reorg` |

**A further revision (P6b): the two remaining "should split" functions need a state object first.** Core can split `MemPoolAccept` into three sections
because it has a 13-field `Workspace` struct passed between `PreChecks` → `PolicyScriptChecks` →
`ConsensusScriptChecks` (validation.cpp:626, 668-686); our `perform-reorg`'s three phases
share eight accumulators plus one rollback path. So these two are not the kind of work rated "Medium (pure move + extract)" in the plan —
**they are a design change**: introduce the state struct first, then split the phases, two PRs, each reviewed separately.
The `P6a` kind (`validate-block`: the boundary already exists in the form of keyword arguments, the two halves independent of each other) is the only kind that's pure extraction.

**A correction to P6c (also a lesson)**: P6b said `validate-transaction-for-mempool` "mashes Core's three stages together" —
**that was wrong**. That judgment was inferred from Core's function list, without reading our own code: the two script-checking passes had long since been delegated to
`validate-transaction-scripts`, with the comment even reading "Script pass 1 — PolicyScriptChecks." P6c extracted these two passes into
`%policy-script-checks` (20 lines) and `%consensus-script-checks` (29 lines), matching Core's names; the function went from 358 to 330 lines —
**not a single metric moved** (still >200), because the remaining 330 lines were already entirely the one PreChecks stage, 1.7x the length of Core's.
Shortening it further requires deleting our own additions (the package-coins path, sibling eviction, several explicitly-noted divergences), not "extracting a stage."
The lesson is the other half of the same one as P6a: **comparing against a reference implementation must be read in both directions** — read how it splits things,
and also read how far we've already split them.

**P6d: `perform-reorg` is fully split; the judgment to do the state object first was correct.** 469 lines were split into a `reorg` struct plus three functions
— `%reorg-disconnect` (92, Core DisconnectTip's loop), `%reorg-connect` (118, ConnectTip's loop, including rollback),
`%reorg-commit` (114, side-effect commit) — exactly Core `ActivateBestChainStep`'s shape carrying a `DisconnectedBlockTransactions`
pool. The struct is not decoration: eight accumulators are written in PHASE A and read in PHASE C, and as long as they remained `let` bindings, the three phases could not be extracted.
The approach was done in two steps, each verified separately: first the `let` bindings were mechanically replaced with struct slots (warm-image compile + 7 suites all green), then the three phases
were extracted whole into functions (context passed as explicit parameters, function bodies untouched). ⚠️ The mechanical replacement hit two pitfalls, both cases of "identifier replacement ignoring syntax":
the **keyword** `:interrupted` got replaced into `:(reorg-interrupted r)`, and "connected" inside a log **string** also got replaced —
the replacement script must skip strings, comments, and keyword prefixes. Both times it blew up at compile time, but if a string replacement happens to still read fine, it would quietly
change the log text.
`>200` is now 8 (-1), `>100` is 66 (+2, one 469-line function becoming three >100-line ones, the same arithmetic as P6a), block.lisp is 4,114 lines.

The final tally for the ten long functions: **2 split** (P6a `validate-block`, P6d `perform-reorg`), **1 stage renamed to align with Core** (P6c),
**6 filed as exceptions with their Core counterpart written into the ratchet** (P6b),
**1 pending** (`activate-block` 210 vs. Core `ActivateBestChain` 167 — now that reorg has been moved, it can be evaluated separately). The ratchet `+long-function-baseline+` now carries, for every entry,
its Core counterpart and the reasoning behind the judgment — the "exceptions named" clause is now genuinely enforced.

So §6's "**functions >200 lines → 0**" is changed to: **where Core splits it, we split it too; where Core itself is one long function,
it is filed as an exception with its counterpart and line count written down** — this is the same principle already written for the "largest file line count" row's
"exceptions faithfully corresponding to a single Core file are named," just not written for functions at the time as well.

"Functions >100 lines ≤ 15" needs revising the same way, and the reasoning is arithmetic: P6a split the 307-line `validate-block` into 107 + 191,
`>200` lost one, `>100` **gained one**. Core's own half is at this same order of magnitude (PreChecks 198, ActivateBestChain 167,
ConnectTip 104), so pushing 64 down to 15 would require slicing finer than Core itself. The target is changed to: **no growth, with every entry over 100 lines
carrying its Core counterpart in the ratchet**.

### The Remaining Wave (recommended as a separate project, not part of P0-P5)

The three items that missed their target are actually the same thing: `validation/block.lisp`'s 4,030 lines house `perform-reorg` (459),
`validate-block` (307), `activate-block` (210), `connect-block` (206). Splitting these four along Core's
`DisconnectTip` / `ConnectTip` / `ActivateBestChainStep` / `CheckBlock` / `ContextualCheckBlock`
boundaries moves all three metrics at once. Among the ten >200-line functions:

- **Non-consensus, can go first**: `%create-transaction-internal` (442, wallet, matching Core `CreateTransactionInternal`,
  covered by 822+407 checks), `rpc-sendall` (289), `ms-from-script` (243, miniscript).
- **Consensus-critical, needs care**: `perform-reorg`, `validate-block`, `connect-block`, `activate-block`,
  `validate-transaction-for-mempool` (358) — this repo's 15-times history of "code correct, call site wrong" all lives in this neighborhood.
- **Protocol**: `run-ibd` (334), `process-received-block` (298).

Estimated at 10-15 PRs. **Why this wasn't finished in this round**: splitting just one function at a time cannot make any metric hit its target (splitting 1 of 10
still leaves 9 at >200), so it's either done as a whole wave or not at all; and this wave's risk level (consensus paths) is not the same order of magnitude as the first six phases
(pure move, pure rename, pure layering) — it deserves being its own project with its own acceptance criteria.

## 7. Known Pitfalls (from this project's memory, must be avoided during the refactor)

- **After a macro change, the stale expansion survives** — a warm rebuild, an image restart, even the cold lane (persistent FASL volume) don't clear it.
  P0b's fresh-FASL cold run is a necessary condition for every P2 PR.
- **Adding a defstruct slot** makes even new instances use the old layout (the FASL volume persists); when the three new defstructs `node-context`, `chain-params`,
  `base-index` are introduced, clear the volume + restart.
- **Changing a defconstant's value needs an image restart**. When P2a folded 30-plus network constants into `chain-params`,
  the old constants were deleted rather than value-changed, avoiding this trap.
- **`setf fdefinition` cannot override a defstruct accessor** (SBCL inlines it) — test stubs must be switched to
  `base-index` generic methods or explicit hook variables.
- **"Written correctly but nothing calls it" has already happened 14 times**. One of the values of definitional macros is "defining is registering,"
  but during migration `no-new-orphaned-exports` must stay in effect, updating its baseline with every symbol move.
- **Coalton's internal symbols are bound to the release** — when splitting interop, do not add new references to `coalton-library/...::`.
- **The warm container is shared with the Workbench session** — confirm before `dev.sh stop`; do P2/P3 restarts via the cold lane.
- **The functional tests' cached datadir went unrebuilt for months** (2026-08-26) — before a PR that changes storage layout (like the index base class
  changing meta-key encoding), `rm -rf refs/bitcoin/test/cache`.

## 8. Suggested First Batch of PRs (in order)

1. `refactor: structural baselines for the cleanup (duplicate names, long functions, API census)`
2. `dev: fresh-FASL mode for the cold battery`
3. `refactor: package-local nicknames for every package` (one package per commit)
4. `refactor: one byte-buf/byte-reader implementation; interop imports it` (with benchmark data attached)
5. `refactor: compact-size down to three functions`
6. `refactor: per-module package.lisp`
7. `refactor: define-chain-params; network dispatch via *chain-params*`
8. `refactor: define-message for version-message (one message, byte-identical)`

By the 8th PR, look back at the ledger and decide whether the order of P2's remaining macros needs adjusting.

## 9. Review-Correction Record (Second Draft)

An adversarial review was done on the first draft, and the following judgments were corrected after checking the code item by item:

1. **`node-context` was originally reinventing the wheel** — `defstruct node` already had all the context slots; the problem was that it was defined in
   the last-loaded top-level package. Changed to "sink the data slots down + `node (:include node-context)`" (§4 P2c).
2. **`*chain-params*` must not be `let`-bound** (SBCL threads do not inherit dynamic bindings), and passing the struct explicitly should be preferred (P2a).
3. **The nickname `crypto` collides with ironclad's global nickname**, changed to the `bl.` prefix; the replacement script was committed to the repo for parallel branches to rerun (P1.4).
4. **Each module's `package.lisp` is constrained by load order**: `config.lisp` loads second yet references higher-level packages,
   so all package files must be placed as one phase at the very front of the .asd; this also exposed `config` as the hardest piece of P4's layering.
5. **`define-rpc`'s payoff was overstated**: of the 563 `rpc-error` sites, only about 173 are argument-shape checks.
6. **`define-p2p-handler`'s table-lookup value was overstated**: handler functions already existed, and Core itself is also an if-chain;
   the value is in the `ctx` signature, with the table lookup demoted to a byproduct.
7. **`define-message` does not touch tx/block by default**: witness markers, hash caching, and trailing-byte strictness don't suit a macro.
8. **`define-option` was missing Core Step 2's parameter-interactions step**, filled in with a separate `apply-parameter-interactions`.
9. **Reducing test `::` by exporting internal symbols would fight with `no-new-orphaned-exports`**, so the target was changed to no growth.
10. Added principles: macro qualification (≥5 instances or Core has the same abstraction), separating `git mv` from modification into different commits, deploying as usual.
11. The largest-file-line-count metric leaves a named exception list for ports that faithfully correspond to a single Core file; "mempool is cleanest" was an unverified claim and has been removed.
