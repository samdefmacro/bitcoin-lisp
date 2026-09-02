# Refactoring results review (2026-09-02)

Object: the 14 PRs executed against `docs/refactoring-review-2026-09-02.md` (#567-#581, main `3be72c2`), ledger
`docs/refactor-ledger.md` rows A, B1, B2, C1, C2, C3, C4, D1, D2, D3, E, F, F2, G. Starting commit `0a7dd5f`.

## 1. Conclusion

All seven waves landed, and each ledger row's claim, checked item by item, is **essentially accurate**; no
regressions in consensus, wire protocol, or RPC behavior were found. What needs follow-up is four categories of
"half-done" work and a set of behavior changes the ledger did not record:

| Severity | Count | Content |
|---|---|---|
| S1 | 0 | — |
| S2 | 4 | Three unrecorded behavior changes in wave F; only two of the four `ignore-errors` in 2.4 were fixed; C2 generated three parsers nobody calls; B2's fixture migration was left unfinished |
| S3 | 6 | Wave G's `(t nil)` removal carried away three comments; 10 `(t nil)` clauses remain in `case` forms; one `(and x (and x t))`; one stale comment; a site-count error in the review document; one hand-copied P2PKH pattern in psbt |

Plus two items **deliberately left undone per plan** (1.5's typed parameter kinds, 2.7's Coalton codec macro);
§7's completion record only mentions the former.

## 2. Evidence

| Method | Result |
|---|---|
| `cold-unit-fresh` (at C4 merge) | 34,595 / 0 |
| Structural ratchets (warm) | 95 / 0, including `rpc-specs-stay-within-core-arity` and its positive control |
| Core functional test spot check (binary rebuilt from main, 18 tests) | 4 PASS (rpc_uptime, feature_shutdown, rpc_deriveaddresses, rpc_getblockfilter); the 13 FAILs' **failure points (file:line + assertion text) match the August baseline one for one**; p2p_sendheaders's failure point moved later (228 -> 255, the second peer's handshake now passes) |
| Three read-only audits (grouped by wave, checked against `0a7dd5f` and `refs/bitcoin`) | see §3-§5 below |
| My own review | every S2 item in §3 was reproduced with `git show 0a7dd5f` / grep |

**Comparison against the pre-refactor binary (completed after Docker returned):** a node built from
`0a7dd5f` in the worktree `/Users/sen/common-lisp/bl-base` fails p2p_sendheaders at exactly the same point
(run_test:230 -> test_null_locators:255 -> check_last_inv_announcement:181, "Predicate not true after 60
seconds"): inv_node never receives the inv announcement for a block that test_node sent unrequested. The
stall predates the refactor. `relay-block` and its call site in the "block" handler are character-for-character
identical before and after C1; the open question is why an unsolicited block that becomes the tip (the log
shows height 1 -> 2) is not announced to the other peer, and that belongs in `docs/functional-triage`, not
in this review. The August run failed earlier (the second peer's handshake at line 228), which is why the
baseline had no data for this point.

## 3. S2 findings

### 3.1 Wave F (validation-interface hooks): three behavior changes did not make it into the ledger
1. **Subscriber ordering was unified.** Previously the connect path was index -> zmq, and the disconnect path was
   wallet -> zmq -> index (`0a7dd5f:src/validation/block.lisp:2643-2665`, ~3320-3345); now both paths follow hook
   registration order: zmq (`src/zmq.lisp:308`, earlier than the node module in the .asd) -> indexes
   (`src/node/indexes.lisp:227`) -> wallet-hooks (`src/node/wallet-hooks.lisp:19`). Checked against Core's
   `init.cpp` registration order (ZMQ before txindex, wallet later), the new order is correct and the old one was
   not; but it is a behavior change.
2. **Reorg's forward-reconnected blocks now emit ZMQ.** The old `%reorg-commit` only called index and wallet, not
   `zmq-notify-block-connected` (the only call site in the whole tree was at `:2662`); now the single
   `notify-block-connected` at `src/validation/block.lisp:3328` fires all subscribers. This is a correction, but
   it was not declared.
3. **Hooks moved out of `without-interrupts`.** The old code put `index-block-connected`,
   `zmq-notify-block-connected`, and `notify-block-tip` inside the same `sb-sys:without-interrupts` as the UTXO
   application, undo writes, and tip update (`0a7dd5f:2631-2666`); now the critical section ends at
   `mempool-remove-for-block` (`src/validation/block.lisp:2623-2645`), and `notify-block-connected` /
   `notify-updated-block-tip` execute after `:2675-2676`. A SIGTERM landing in this window would leave the indexes
   one block behind the tip, recovered by catch-up against the best-block marker at startup -- recoverable by
   design, and Core's indexes are likewise asynchronous, but ledger row F's "Behaviour:" note does not mention it.

Two other changes are **declared** and were verified: the zmq and blocknotify subscribers gained a background
chainstate guard; `maybe-stop-at-height`'s guard moved from the call site into the function body.

### 3.2 Only two of the four `ignore-errors` from 2.4 were fixed

- Fixed: `src/node/shutdown.lisp:96-107` (retries only on EINTR), `src/rpc/descriptors.lisp` (removed the
  redundant `ignore-errors` under the digit guard).
- Untouched, character-for-character identical to `0a7dd5f`: `src/validation/block.lisp:740`
  (`available-processor-count`, falls back to 4 on any error) and `:2063` (`prune-stale-undo-files`, a filename
  parse failure -> hash NIL -> entry NIL -> the file gets deleted as "unrecognized by the index").
- Ledger row A's wording is honest (it lists only the two that were done); **the review document's §7 completion
  record omits this half**.

### 3.3 C2: three generated field parsers have no caller

`define-wdb-key` (`src/wallet/wallet-store.lisp:113-135`) generates `wdb-parse-<name>-fields` for a key that
carries fields; three of them -- `lockedutxo`, `descriptor-parent-cache`, `descriptor-derived-cache` -- are
generated but have no caller in src/ or tests/ (grep comes back empty). `src/wallet/wallet.lisp:1101-1104` reads
lockedutxo's 32 bytes + u32 by hand with a bare `%wparse` -- byte-equivalent to the generated parser, the same
class of problem as "the table exists, but the hand-written copy is still alive". The two descriptor-cache ones
have a reason (the same type string distinguishes two record kinds by length), but they could still call the
generated parser within the length dispatch; lockedutxo has no such reason. The field parsers are currently
internal symbols, so the orphan-export scan does not reach them -- "generated but never called" is missing a
ratchet.

### 3.4 B2: fixture migration left unfinished

- 26 hand-written `(handler-case … (bl.rpc:rpc-error (e) …))` forms remain, 18 of them in
  `tests/rpc/rpc-tests.lisp`, of which `:191-201`, `:2560-2576`, `:4183-4189` do exactly what
  `signals-rpc-error` does, and the same file's `:181,185` are already using the fixture.
- 3 bare `(let ((bl.net:*ibd-context* (bl.net::make-ibd))) …)` forms never moved into `with-ibd-context`:
  `tests/storage/persistence-tests.lisp:1369`, `tests/validation/reorg-tests.lisp:1882`, `:1952`.
- The `::` ratchet (4,417) blocks growth, but does not drive migration of the remaining sites.

## 4. S3 findings

1. Wave G's removal of `(cond … (t nil))` carried away three explanatory comments (in
   `src/validation/block.lisp`: "Non-boundary on testnet…", "Other encodings not valid for BIP 34.", "New block is
   on a weaker chain — just store it.", each present once at `0a7dd5f`, 0 at main). The recorded lesson
   `form-swap-must-carry-comments` covers only if-branch swaps, not cond-clause removal -- the same class of defect
   recurred in a sibling transformation.
2. 10 `(t nil)` clauses remain in `case`/`typecase` forms (e.g. `src/storage/chain.lisp:1126`,
   `src/wallet/wallet.lisp:100`, `src/rpc/descriptors.lisp:2046`); the tool only matched `cond`.
3. `src/serialization/types.lisp:186`: `(and stack (not (null stack)))` became
   `(and stack (and stack t))`.
4. `src/wallet/wallet-spend.lisp:34`'s comment still says `%btc` (renamed to `satoshi->btc`).
5. The review document's 2.1 says `with-current-node-lock` has 18 sites (protocol 9 / ibd 8 / peer 1); in fact
   both `0a7dd5f` and main have protocol 8 / ibd 8 / peer 0 = 16; ledger row A carried forward the 18. The fix
   itself is correct.
6. `src/wallet/psbt.lisp:1160` still hand-copies the 25-byte P2PKH pattern instead of going through
   `%match-p2pkh`; this is a ledger-recorded exception (it satisfies a leaf template, not a classification), so
   there is no risk of divergence.

The `equalp` table ratchet: currently 103 = the ceiling, zero headroom; the 9 local txid-keyed tables in
`src/mempool/mempool.lisp` and `src/networking/ibd.lisp:471`'s `*block-failure-counts*` are still `equalp`. Ledger
row E's wording only claims the 7 struct-slot tables + sig-cache, which is not an overstatement.

## 5. Items verified as "done and correct"

- **1.1 define-p2p-handler**: 31 handlers fully replace the old 30-branch `string=`; `:needs-mempool` is
  exactly tx/cmpctblock/blocktxn, and the `:rate-bucket` mapping matches the old `check-peer-rate-limit` line for
  line; `dispatch-ibd-message` still covers only block/headers. The remaining 6 `string=` occurrences in peer.lisp
  are handshake-state flags (version/verack/sendaddrv2/sendheaders/wtxidrelay/sendtxrcncl), which were never meant
  to be in the table, and `tests/networking/dos-protection-tests.lisp:75-115` pins this down.
- **1.2 classify-script + HRP**: `src/validation/solver.lisp:153-197`'s ordering matches
  `refs/bitcoin/src/script/solver.cpp:141-210` (including P2A, unknown witness versions, `CPubKey::ValidSize`);
  `%script-type` and `%script-p2pk-p` have been deleted, `parse-multisig` is now a thin wrapper; the HRP is read
  from `chain-params-bech32-hrp`; the positive control is in `tests/mempool/mempool-tests.lisp:2737-2757`.
- **1.4 index-base**: all four indexes now `:include base-index`; bfi/csi use the default best/set/clear;
  txindex/txospender each override (documented exceptions); no remaining `%bfi-encode-meta`-style copies.
- **1.6 chain-params prefixes**: the values match `kernel/chainparams.cpp:153-157, 274-278`; the four test
  chains share one set; `wif-to-private-key` returns the version byte, and 5 call sites compare against the
  current chain's prefix; the `no-pseudo-network-testnet` ratchet has a positive control, currently at count 0.
- **1.7 message constructors**: the three payload builders are byte-identical to the old inline bodies.
- **1.5 / C4**: after `destructuring-bind (&optional … &rest more)`, a pure coercion `let*` in spec order, with
  no evaluation-order or side-effect risk; getblockhash/gettxout's positions match `rpc/blockchain.cpp`;
  scantxoutset/scanblocks/testmempoolaccept's `[]`-vs-null check still looks directly at `params`.
- **2.1**, **2.2** (per-function `(speed 3) (safety 1)`, no file-level declaim), **2.5** (flatfile -> safety 1,
  `sig-cache-hash` was entirely replaced by `octets-hash`; the six in utxo.lisp and `siphash-rotl64` were kept for
  documented reasons), **2.6** (0 `defparameter +x+`; all 77 `define-constant`s carry `:test`; the 9 `:global`
  option defvars are wired in; no constant references cross load order).
- **3.1 layering ratchet**: `tests/structural-tests.lisp:1479-1484` uses a synthetic validation->node reference
  as the positive control, and excludes `bl.store:`, comments, and strings; all 22 baseline entries are genuine
  rpc/networking/validation->node references. **3.2**: `src-reaches-no-foreign-internals` has a positive control; a
  spot check of 5 new exports all have cross-package callers; the orphan baseline is bidirectional (a new one goes
  red, and one resolved-but-not-removed also goes red), and it recognizes define-p2p-handler /
  define-validation-hook. **§5 ratchets**: the ones spot-checked all have non-vacuous positive controls;
  `%definitions-longer-than`'s control is weaker (it only asserts the real corpus is non-empty).

## 6. Left undone per plan

- 1.5's typed kinds (`:hex-hash`, mandatory `:string`/`:uint` raising `+rpc-type-error+`) -- already recorded in §7.
- 2.7 `define-coalton-codec`: never built; `satoshi<` (`interop.lisp:182`) and the per-output `wrap-satoshi`
  (`transaction.lisp:87`) remain as-is. No ledger row claims this was done, but §7 doesn't mention it either.

## 7. Suggested follow-ups (all small PRs)

1. Add a "Behaviour:" note to ledger row F (the three items in §3.1), and decide whether the hooks should go
   back inside `without-interrupts`, or document in `docs/manual.lisp`'s util section that "the index can lag one
   block behind, caught up at startup".
2. Handle the two `ignore-errors` at `src/validation/block.lisp:740` and `:2063` per review item 2.4; note it
   in §7.
3. Change `wallet.lisp:1101` to call `wdb-parse-lockedutxo-fields`; call the other two within
   descriptor-cache's length dispatch; add a check for "generated/defined but never-called internal functions"
   (at least for `define-wdb-*` products).
4. The 26 hand-written rpc-error catches in rpc-tests -> `signals-rpc-error`; the 3 `*ibd-context*` sites ->
   `with-ibd-context`.
5. Restore the three comments; clean up the 10 `(t nil)` clauses in `case` forms; `types.lisp:186`;
   `wallet-spend.lisp:34`'s comment; the review document's 2.1, 18 -> 16.
6. Add `→ guard` to `form-swap-must-carry-comments`: a check that "the set of comment lines is unchanged before
   and after the transformation", applicable to any reader-driven bulk rewrite.
7. Write the p2p_sendheaders attribution (§2: pre-existing, not a refactor regression -- an unsolicited
   block that becomes the tip is not announced to other peers) into `docs/functional-triage`.
