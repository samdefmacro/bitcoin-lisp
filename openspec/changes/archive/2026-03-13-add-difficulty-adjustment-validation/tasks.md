## 1. Core difficulty calculation
- [x] 1.1 Add `target-to-bits` function in `src/storage/chain.lisp` (inverse of `bits-to-target`)
- [x] 1.2 Add `calculate-next-work-required` in `src/storage/chain.lisp` (retarget algorithm: timespan from block H-2016 to H-1, with 4x clamp, matching Bitcoin Core's off-by-one)
- [x] 1.3 Add difficulty-related constants: `+difficulty-adjustment-interval+` (2016), `+pow-target-timespan+` (1,209,600 seconds), `+pow-limit-bits+` (0x1d00ffff)

## 2. Expected bits resolution
- [x] 2.1 Add `get-expected-bits` in `src/validation/block.lisp` that resolves the correct `bits` for a given height: genesis/first-period handling, retarget boundary calculation, and non-boundary inheritance
- [x] 2.2 Add `testnet-min-difficulty-allowed-p` predicate for testnet's 20-minute exception rule
- [x] 2.3 Add `testnet-walk-back-bits` to find the last non-min-difficulty block's `bits` by walking back through prev-entry pointers (stops at retarget boundary or non-min-difficulty block)
- [x] 2.4 Integrate testnet logic into `get-expected-bits` (min-difficulty when >20 min gap, walk-back otherwise)

## 3. Integration into validation
- [x] 3.1 Add `bits` validation to `validate-block-header` in `src/validation/block.lisp`
- [x] 3.2 Add `bits` validation to `validate-header-chain` in `src/networking/ibd.lisp`
- [x] 3.3 Export new functions from package.lisp

## 4. Tests
- [x] 4.1 Unit tests for `target-to-bits` (roundtrip with `bits-to-target`, edge cases)
- [x] 4.2 Unit tests for `calculate-next-work-required` (known retarget vectors, 4x clamp boundaries)
- [x] 4.3 Unit tests for testnet min-difficulty logic and walk-back across consecutive min-difficulty blocks
- [x] 4.4 Unit test for first retarget period (heights 0–2015 use genesis bits)
- [x] 4.5 Integration test: validate a sequence of headers across a retarget boundary
