# Change: Add block weight validation

## Why
The node has no block weight validation. BIP 141 (SegWit) replaced the 1 MB block size limit with a 4,000,000 weight unit limit, where weight = `(base_size * 3) + total_size`. Without this check, the node would accept oversized blocks that Bitcoin Core rejects. Transaction `vsize` calculation already exists (`transaction-vsize`) but there's no corresponding block-level weight calculation or enforcement.

## What Changes
- Add `transaction-weight` function (weight = vsize * 4, or equivalently `3 * base_size + total_size`)
- Add `block-weight` function that sums transaction weights
- Add `+max-block-weight+` constant (4,000,000)
- Validate block weight in `validate-block` and reject blocks exceeding the limit
- Keep the existing `+max-block-size+` (1 MB) check as a pre-witness sanity check on base size

## Impact
- Affected specs: `validation`
- Affected code: `src/serialization/types.lisp`, `src/validation/block.lisp`
