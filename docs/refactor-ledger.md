# Refactor ledger

Companion to `docs/refactoring-plan-2026-08-27.md`. One row per merged
`refactor:` PR; the numbers are what `tests/structural-tests.lisp` measures
(the "Refactoring ratchets" section), so a row can be regenerated:

```
scripts/dev.sh eval '(list (bitcoin-lisp.tests::%duplicate-definition-names)
  (length (bitcoin-lisp.tests::%definitions-longer-than 200))
  (length (bitcoin-lisp.tests::%definitions-longer-than 100))
  (let ((text (bitcoin-lisp.tests::%source-text))) (mapcar (lambda (f) (cons f (bitcoin-lisp.tests::%serialization-family-count f text))) (list :stream-io :compact-size-definitions)))
  (reduce (function +) (bitcoin-lisp.tests::%bare-error-census) :key (function cdr))
  (bitcoin-lisp.tests::%layering-violations))'
```

Columns: dup = DEFUN/DEFMACRO names defined in two files; >200 / >100 = top-level
definitions over that many lines; stream / cs-defs = call sites of
the stream integer codecs and distinct CompactSize/varint definitions (the
retiring families; the `interop` column was dropped in P1.1 when buf-set-*
became the primitive layer under byte-buf rather than a second buffer); bare = `(error
"...")` forms; layer = upward package references; max file = longest file in
src/; cold = cold-battery check count / failures.

| date | PR | step | dup | >200 | >100 | stream | cs-defs | bare | layer | max file | cold |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-08-27 | baseline (main 5f4f321) | — | 18 | 13 | 62 | 88 | 12 | 199 | 15 | 6,783 | 34,255 / 0 |
| 2026-08-27 | P0a | structural baselines | 18 | 13 | 62 | 88 | 12 | 199 | 15 | 6,783 | — |
| 2026-08-27 | P0b | fresh-FASL cold lane | 18 | 13 | 62 | 88 | 12 | 199 | 15 | 6,783 | 34,302 / 0 (fresh, 3m13s) |
| 2026-08-27 | P1.1 | one byte-buf/byte-reader (src/util/bytes.lisp) | 10 | 13 | 62 | 88 | 12 | 199 | 15 | 6,783 | 34,302 / 0 (fresh) |
| 2026-08-28 | P1.2 | CompactSize down to the bytes package (4 private variants gone) | 10 | 13 | 62 | 88 | 8 | 199 | 15 | 6,783 | 34,305 / 0 (fresh) |
| 2026-08-28 | P1.3 | last 10 duplicate names gone; redefinition warnings now fail the cold lane | 0 | 13 | 62 | 88 | 8 | 198 | 15 | 6,783 | 34,317 / 0 (fresh) |
| 2026-08-28 | P1.4 | package-local nicknames (bl.ser, bl.store, …) across src/ and tests/ | 0 | 13 | 62 | 88 | 8 | 198 | 15 | 6,783 | 34,319 / 0 (fresh) |
| 2026-08-28 | P1.5 | each module's package in src/<module>/package.lisp; src/package.lisp 1,780 → 246 lines | 0 | 13 | 62 | 88 | 8 | 198 | 15 | 6,783 | 34,319 / 0 (fresh) |
| 2026-08-28 | P2a | define-chain-params: 29 network dispatches in 8 files → one table (src/util/chainparams.lisp) | 0 | 13 | 62 | 88 | 8 | 200 | 15 | 6,783 | 34,420 / 0 (fresh) |
| 2026-08-28 | P2b-1 | messages.lisp (P2P) on byte-reader/byte-buf; nickname installer self-heals warm reloads | 0 | 13 | 62 | 42 | 8 | 199 | 15 | 6,783 | 34,420 / 0 (fresh) |
| 2026-08-28 | P2b-2 | define-message: 6 struct+reader+writer triples → 6 field lists (src/serialization/message-macro.lisp) | 0 | 13 | 62 | 42 | 8 | 202 | 15 | 6,783 | 34,420 / 0 (fresh) |
| 2026-08-28 | P2c | node-context: every P2P handler and the IBD pump take (peer payload ctx) instead of up to 8 params | 0 | 12 | 62 | 42 | 8 | 202 | 15 | 6,783 | 34,420 / 0 (fresh) |
| 2026-08-28 | P2d-1 | define-rpc: 161 handlers register themselves; register-all-methods 197 → 6 lines | 0 | 12 | 61 | 42 | 8 | 202 | 15 | 6,783 | 34,424 / 0 (fresh) |
| 2026-08-28 | P2e-1 | base-index + 9 generics: 3 per-index catch-ups → catch-up-index, 3 connect hooks → index-block-connected/disconnected (txindex still via :tx-index, P2e-2); start-node 1332 → 1227 (%start-txindex, %start-indexes) | 0 | 12 | 61 | 42 | 8 | 205† | 15 | 6,767 | 34,425 / 0 (fresh) |
| 2026-08-28 | P0c | cold lane gates on `undefined variable` warnings (scripts/check-undefined-variables.sh, self-tested); 6 docstrings cut short by an inner `"` fixed (open-coins-view-db, dispatch-rpc-method, %target-unroutable-p, apply-log-categories, %write-settings-file, recon-fanout-target-p) | 0 | 12 | 61 | 42 | 8 | 205 | 15 | 6,767 | 34,425 / 0 (fresh) |
| 2026-08-28 | P2e-2 | txindex joins node-indexes: the `:tx-index` argument threaded through 7 validation entry points, accept-downloaded-block, ibd-context, node-context and 4 RPC sites is gone (-263/+153 lines); index-height takes the chainstate; txindex rewinds its marker on disconnect; getindexinfo via the generics | 0 | 12 | 61 | 42 | 8 | 205 | 15 | 6,764 | 34,425 / 0 (fresh) |

## Notes

- The 15 layering violations (a file naming a package whose module loads
  later in `bitcoin-lisp.asd`): `config.lisp` → 7 packages (it loads second),
  `coalton/interop.lisp` → crypto/serialization/storage, `coalton/crypto.lisp`
  → crypto, `zmq.lisp` → serialization, and validation → mempool ×3
  (`validate-transaction-for-mempool` and friends). This is the "file →
  packages" table P4 works from; the config ones are the hard part.
- `ms-from-script` (243 lines) is a faithful port of Core's
  `miniscript.h` FromScript; it is on the >200 list so the decision to leave
  it is made in P3, not by default.

† 205 is the census on main as well — the earlier rows carried a stale 202; the P2e-1 diff adds and removes no `(error "...")` form.
