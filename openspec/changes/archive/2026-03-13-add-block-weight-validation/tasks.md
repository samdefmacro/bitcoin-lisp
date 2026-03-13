## 1. Weight calculation
- [x] 1.1 Add `transaction-weight` in `src/serialization/types.lisp` that returns weight units (base_size * 3 + total_size)
- [x] 1.2 Add `+max-block-weight+` constant (4,000,000) in `src/validation/block.lisp`

## 2. Block weight validation
- [x] 2.1 Add `calculate-block-weight` in `src/validation/block.lisp` that sums all transaction weights
- [x] 2.2 Add block weight check to `validate-block` that rejects blocks exceeding `+max-block-weight+`

## 3. Exports and integration
- [x] 3.1 Export `transaction-weight` from serialization package
- [x] 3.2 Export `+max-block-weight+` from validation package

## 4. Tests
- [x] 4.1 Unit tests for `transaction-weight` (legacy tx, witness tx, relationship with vsize)
- [x] 4.2 Unit test for `calculate-block-weight`
- [x] 4.3 Integration test: block at/below weight limit accepted, block exceeding limit rejected
