## ADDED Requirements

### Requirement: Difficulty Adjustment Validation
The system SHALL validate that each block header's `bits` field matches the expected difficulty target according to Bitcoin's retarget algorithm.

Difficulty retarget rules:
- Every 2016 blocks (the "retarget interval"), the difficulty target is recalculated
- The retarget timespan is measured from block `height - 2016` to block `height - 1` (2015 inter-block intervals, matching Bitcoin Core's known off-by-one)
- The new target = previous target * (actual timespan / target timespan), where target timespan is 1,209,600 seconds (2 weeks)
- The adjustment is clamped: no more than 4x increase or 4x decrease per retarget period
- The target SHALL NOT exceed the network's proof-of-work limit (minimum difficulty, bits = 0x1d00ffff)
- For blocks in the first retarget period (height 0–2015), `bits` MUST equal the genesis block's bits (0x1d00ffff)
- On mainnet, between retarget boundaries, all blocks MUST use the same `bits` value as the previous block

Network-specific testnet rules:
- When more than 20 minutes (1200 seconds) have elapsed since the previous block's timestamp, a min-difficulty `bits` value of 0x1d00ffff is accepted
- When within 20 minutes, the expected `bits` is found by walking back through the chain to the last block that either (a) is at a retarget boundary (height % 2016 == 0) or (b) does not have min-difficulty bits, and using that block's `bits`

#### Scenario: Validate bits at retarget boundary
- **GIVEN** a block at height 2016 (a retarget boundary) where the timespan from block 0 to block 2015 was 1,209,600 seconds (exactly 2 weeks)
- **WHEN** validating the block header
- **THEN** the `bits` field equals the previous period's `bits` (no change needed)

#### Scenario: Reject incorrect bits at retarget boundary
- **GIVEN** a block at height 2016 with `bits` that does not match the calculated retarget value
- **WHEN** validating the block header
- **THEN** validation fails with :bad-difficulty error

#### Scenario: Validate bits in first retarget period
- **GIVEN** a block at height 500 (within the first retarget period)
- **WHEN** validating the block header
- **THEN** the `bits` field MUST equal 0x1d00ffff (genesis/PoW-limit difficulty)

#### Scenario: Validate bits between retarget boundaries on mainnet
- **GIVEN** mainnet network and a block at height 3000 (not a retarget boundary)
- **WHEN** validating the block header
- **THEN** the `bits` field MUST equal the previous block's `bits` field

#### Scenario: Clamp retarget to 4x maximum adjustment
- **GIVEN** a retarget period where the timespan was only 302,400 seconds (1/4 of target timespan)
- **WHEN** calculating the new difficulty
- **THEN** the adjustment is clamped to 4x increase (timespan treated as 302,400 seconds minimum)

#### Scenario: Clamp retarget to 4x minimum adjustment
- **GIVEN** a retarget period where the timespan was 4,838,400 seconds (4x target timespan)
- **WHEN** calculating the new difficulty
- **THEN** the adjustment is clamped to 4x decrease (timespan treated as 4,838,400 seconds maximum)

#### Scenario: Testnet min-difficulty exception
- **GIVEN** testnet network and a block whose timestamp is more than 20 minutes after the previous block's timestamp
- **WHEN** validating the block header's `bits` field
- **THEN** a `bits` value of 0x1d00ffff (minimum difficulty) is accepted

#### Scenario: Testnet walk-back after min-difficulty blocks
- **GIVEN** testnet network, a block whose timestamp is within 20 minutes of the previous block, and the previous 3 blocks all used min-difficulty bits
- **WHEN** validating the block header's `bits` field
- **THEN** the expected `bits` is the `bits` from the last block that either sits at a retarget boundary or does not have min-difficulty bits
