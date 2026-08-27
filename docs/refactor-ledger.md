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
