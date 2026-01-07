# Validation

Transaction and block validation against Bitcoin consensus rules.

## ADDED Requirements

### Requirement: Transaction Structure Validation
The system SHALL validate basic transaction structure before script execution.

Checks include:
- Transaction has at least one input and one output
- No input references null outpoint (except coinbase)
- Output values are non-negative and don't exceed 21M BTC
- Total output value doesn't exceed total input value (for non-coinbase)
- Transaction size within limits

#### Scenario: Reject empty inputs
- **GIVEN** a transaction with zero inputs
- **WHEN** validating structure
- **THEN** validation fails with "no inputs" error

#### Scenario: Reject negative output value
- **GIVEN** a transaction with a negative output value
- **WHEN** validating structure
- **THEN** validation fails with "negative output" error

### Requirement: Script Validation
The system SHALL execute Bitcoin scripts to validate transaction authorization.

The script interpreter SHALL support:
- Stack operations (OP_DUP, OP_DROP, OP_SWAP, etc.)
- Crypto operations (OP_HASH160, OP_HASH256, OP_CHECKSIG, etc.)
- Flow control (OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY)
- Arithmetic operations (OP_ADD, OP_SUB, OP_EQUAL, etc.)

#### Scenario: Validate P2PKH transaction
- **GIVEN** a transaction spending a P2PKH output with valid signature
- **WHEN** executing scriptSig + scriptPubKey
- **THEN** the script succeeds and validation passes

#### Scenario: Reject invalid signature
- **GIVEN** a transaction with an invalid ECDSA signature
- **WHEN** executing OP_CHECKSIG
- **THEN** the script fails and validation rejects the transaction

### Requirement: Block Header Validation
The system SHALL validate block headers against consensus rules.

Checks include:
- Proof of work meets target difficulty
- Timestamp within acceptable range
- Previous block hash references a known block
- Block version is acceptable

#### Scenario: Validate proof of work
- **GIVEN** a block header
- **WHEN** checking proof of work
- **THEN** the block hash is verified to be below the target derived from bits field

#### Scenario: Reject future timestamp
- **GIVEN** a block header with timestamp >2 hours in the future
- **WHEN** validating the header
- **THEN** validation fails with "timestamp too far in future" error

### Requirement: Block Validation
The system SHALL validate complete blocks against consensus rules.

Checks include:
- First transaction is coinbase, no others are
- Coinbase value doesn't exceed block reward + fees
- All transactions are valid
- Merkle root matches transaction hashes
- Block size within limits

#### Scenario: Validate merkle root
- **GIVEN** a block with transactions
- **WHEN** computing the merkle root
- **THEN** it matches the merkle root in the header

#### Scenario: Reject excess coinbase value
- **GIVEN** a block where coinbase output exceeds (subsidy + fees)
- **WHEN** validating the block
- **THEN** validation fails with "coinbase value too high" error

### Requirement: Contextual Validation
The system SHALL validate transactions and blocks in the context of the current chain state.

Checks include:
- All inputs reference existing UTXOs
- No double-spends
- Coinbase maturity (100 blocks before spendable)
- Sequence locks and timelocks

#### Scenario: Reject double spend
- **GIVEN** a transaction spending an already-spent UTXO
- **WHEN** validating against UTXO set
- **THEN** validation fails with "input already spent" error

#### Scenario: Enforce coinbase maturity
- **GIVEN** a transaction spending a coinbase output
- **WHEN** the coinbase is less than 100 blocks deep
- **THEN** validation fails with "coinbase not mature" error

### Requirement: Chain Selection
The system SHALL select the best chain based on accumulated proof of work.

#### Scenario: Accept longer chain
- **GIVEN** two competing chains
- **WHEN** one has more accumulated chainwork
- **THEN** that chain is selected as the best chain

#### Scenario: Handle chain reorganization
- **GIVEN** a new block that creates a longer competing chain
- **WHEN** the new chain has more work than the current best
- **THEN** the node reorganizes to the new chain, disconnecting old blocks and connecting new ones
