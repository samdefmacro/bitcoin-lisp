## ADDED Requirements

### Requirement: Header Chain Validation
The system SHALL validate block headers form a valid chain.

Header validation checks:
- Previous block hash references the prior header
- Proof of work meets the target difficulty
- Timestamp is greater than median of previous 11 blocks
- Timestamp is not more than 2 hours in the future
- Version is acceptable for the height

#### Scenario: Validate header links
- **GIVEN** a sequence of block headers
- **WHEN** validating the chain
- **THEN** each header's prev_hash matches the prior header's hash

#### Scenario: Validate header proof of work
- **GIVEN** a block header
- **WHEN** validating proof of work
- **THEN** the block hash is below the target derived from the bits field

#### Scenario: Reject header with bad timestamp
- **GIVEN** a header with timestamp before median-time-past
- **WHEN** validating the header
- **THEN** validation fails with "timestamp too old" error

### Requirement: Block Connection
The system SHALL connect validated blocks to the chain state.

Connection involves:
- Verifying block matches its header
- Validating all transactions in context
- Updating UTXO set (add new outputs, remove spent outputs)
- Updating chain state (height, tip, chainwork)

#### Scenario: Connect block to chain
- **GIVEN** a fully validated block
- **WHEN** connecting to the chain
- **THEN** the UTXO set and chain state are updated atomically

#### Scenario: Handle out-of-order blocks
- **GIVEN** blocks arriving out of height order
- **WHEN** a block's parent is not yet connected
- **THEN** the block is queued until its parent is connected

#### Scenario: Reject block with invalid transactions
- **GIVEN** a block containing an invalid transaction
- **WHEN** validating the block
- **THEN** the block is rejected and the peer may be penalized

### Requirement: IBD Validation Mode
The system SHALL use optimized validation during Initial Block Download.

During IBD (when significantly behind chain tip):
- Script validation may be skipped for blocks covered by checkpoints
- Signature validation may use parallel verification
- UTXO set updates are batched for efficiency

After IBD completes, full validation resumes for all new blocks.

#### Scenario: Skip scripts before checkpoint
- **GIVEN** a block at height below the last checkpoint
- **WHEN** in IBD mode with checkpoint-guarded optimization enabled
- **THEN** script validation may be skipped (signatures still checked)

#### Scenario: Full validation after IBD
- **GIVEN** a block received after IBD completes
- **WHEN** validating the block
- **THEN** full script and signature validation is performed
