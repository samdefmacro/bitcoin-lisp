# Change: Add difficulty adjustment validation

## Why
The node validates that a block's hash meets the target encoded in its `bits` field, but never verifies that `bits` itself is correctly calculated. This means an attacker could broadcast blocks with artificially low difficulty and the node would accept them. Difficulty retargeting every 2016 blocks is a core consensus rule — without it, the node cannot safely validate the chain on mainnet or testnet.

## What Changes
- Add `calculate-next-work-required` to compute the expected `bits` for a block based on the prior retarget period (timespan from block H-2016 to block H-1, i.e. 2015 inter-block intervals — matching Bitcoin Core's known off-by-one)
- Add `target-to-bits` (inverse of existing `bits-to-target`) for compact encoding
- Validate that each block header's `bits` matches the expected difficulty during header chain validation and full block validation
- Handle testnet special rules: min-difficulty blocks allowed when >20 minutes since last block; when within 20 minutes, walk back to find the last non-min-difficulty block's `bits`
- Clamp retarget adjustment to the Bitcoin Core range (no more than 4x increase or decrease per period)

## Impact
- Affected specs: `validation`
- Affected code: `src/validation/block.lisp`, `src/storage/chain.lisp`, `src/networking/ibd.lisp`
