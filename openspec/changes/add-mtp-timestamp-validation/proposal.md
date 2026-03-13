# Change: Add MTP timestamp validation for block headers

## Why
The validation spec requires that block timestamps are greater than the median-time-past of the previous 11 blocks, but this check is not implemented. This is a consensus rule — Bitcoin Core rejects blocks with timestamps at or before MTP. Missing this check could cause the node to accept blocks that the rest of the network rejects.

## What Changes
- Add MTP timestamp check to `validate-block-header` (used during block connection)
- Add MTP timestamp check to `validate-header-chain` (used during IBD header sync)
- Add tests for MTP timestamp rejection

## Impact
- Affected specs: validation (MODIFIED — Block Header Validation, Header Chain Validation)
- Affected code: `src/validation/block.lisp`, `src/networking/ibd.lisp`, `tests/`
