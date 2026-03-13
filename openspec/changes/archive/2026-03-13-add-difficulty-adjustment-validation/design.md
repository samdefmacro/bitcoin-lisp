## Context
Bitcoin adjusts its proof-of-work difficulty every 2016 blocks (~2 weeks) to maintain a ~10-minute block interval. The node currently trusts the `bits` field in each header without verifying it matches the expected retarget calculation. This is consensus-critical.

**Known off-by-one (consensus quirk):** Bitcoin Core measures the retarget timespan from block `height - 2016` to block `height - 1`, which is 2015 inter-block intervals, not 2016. This is baked into consensus and MUST be replicated exactly.

Testnet has a special difficulty rule: if no block is found within 20 minutes, the next block may use the minimum difficulty (0x1d00ffff). When a block IS found within 20 minutes, the expected `bits` is determined by walking back through the chain to find the last block that either sits at a retarget boundary or does not have min-difficulty bits.

## Goals / Non-Goals
- Goals:
  - Validate `bits` field for every block header on both mainnet and testnet
  - Handle the 2016-block retarget boundary calculation (with correct off-by-one)
  - Handle testnet min-difficulty exception and walk-back logic
  - Handle the first retarget period (heights 0–2015 use genesis bits)
  - Integrate into both header chain validation (IBD) and full block validation
- Non-Goals:
  - Regtest/signet support
  - Custom difficulty algorithms

## Decisions
- **Place `calculate-next-work-required` and `target-to-bits` in `src/storage/chain.lisp`**: These are chain-state utility functions alongside existing `bits-to-target` and `calculate-chain-work`.
- **Single `+pow-limit-bits+` constant (0x1d00ffff)**: Mainnet and testnet share the same PoW limit. No need for per-network constants (regtest is a non-goal).
- **Place `get-expected-bits` in `src/validation/block.lisp`**: This orchestrates the lookup of the retarget-period ancestor and calls the calculation. It needs chain-state access.
- **Add validation call in `validate-header-chain` (ibd.lisp)**: During IBD, check `bits` matches expected after PoW check but before committing the header.
- **Add validation call in `validate-block-header` (block.lisp)**: For post-IBD blocks, validate `bits` during header validation. Requires passing height and chain-state.
- **Testnet special case**: Two functions: `testnet-min-difficulty-allowed-p` checks if 20+ minutes elapsed since the previous block, and `testnet-walk-back-bits` walks back to find the last non-min-difficulty block's `bits`.

## Risks / Trade-offs
- Walking back through prev-entry pointers to find the retarget ancestor adds overhead during IBD header validation. Mitigated by the fact that this only happens at retarget boundaries (every 2016 blocks); intermediate blocks just inherit the previous `bits`. On testnet, the walk-back for non-min-difficulty blocks adds minor overhead but chains of min-difficulty blocks are typically short.
- Testnet's min-difficulty rule adds complexity but is necessary for correct testnet validation.
- The off-by-one quirk must be preserved exactly — implementers should not "fix" the 2015-vs-2016 interval difference.

## Open Questions
- None; the algorithm is well-specified in Bitcoin Core.
