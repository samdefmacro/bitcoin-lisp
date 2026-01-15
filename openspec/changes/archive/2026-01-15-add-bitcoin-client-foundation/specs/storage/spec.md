# Storage

Persistent storage for blocks, UTXO set, and chain state.

## ADDED Requirements

### Requirement: Block Storage
The system SHALL persistently store downloaded blocks.

#### Scenario: Store new block
- **GIVEN** a validated block
- **WHEN** adding the block to storage
- **THEN** the block is persisted and retrievable by hash

#### Scenario: Retrieve block by hash
- **GIVEN** a block hash
- **WHEN** querying storage
- **THEN** the corresponding block data is returned if present

#### Scenario: Check block existence
- **GIVEN** a block hash
- **WHEN** checking if the block exists
- **THEN** true is returned if stored, false otherwise

### Requirement: UTXO Set Management
The system SHALL maintain an accurate set of unspent transaction outputs (UTXOs).

A UTXO is identified by:
- Transaction hash (32 bytes)
- Output index (uint32)

A UTXO contains:
- Value in satoshis (int64)
- ScriptPubKey (variable bytes)
- Block height where created (for coinbase maturity)

#### Scenario: Add UTXO from new transaction
- **GIVEN** a confirmed transaction output
- **WHEN** the transaction is included in a block
- **THEN** the output is added to the UTXO set

#### Scenario: Remove UTXO when spent
- **GIVEN** a transaction input referencing a UTXO
- **WHEN** the spending transaction is confirmed
- **THEN** the UTXO is removed from the set

#### Scenario: Query UTXO
- **GIVEN** a transaction hash and output index
- **WHEN** querying the UTXO set
- **THEN** the UTXO data is returned if unspent, or nil if spent/nonexistent

### Requirement: Chain State
The system SHALL track the current best chain state.

State includes:
- Best block hash
- Current block height
- Total accumulated chainwork
- Chain tip headers

#### Scenario: Update chain tip
- **GIVEN** a new valid block extending the best chain
- **WHEN** the block is connected
- **THEN** the chain state is updated with the new tip

#### Scenario: Retrieve current height
- **GIVEN** the chain state
- **WHEN** querying current height
- **THEN** the height of the best chain tip is returned

### Requirement: Block Index
The system SHALL maintain an index mapping block hashes to storage locations and metadata.

Metadata includes:
- Block height
- Block header
- Chainwork
- Validation status

#### Scenario: Index new block
- **GIVEN** a new block header
- **WHEN** adding to the index
- **THEN** the block is indexed by hash with its metadata

#### Scenario: Get block header by height
- **GIVEN** a block height
- **WHEN** querying the main chain
- **THEN** the block header at that height is returned

### Requirement: Persistence and Recovery
The system SHALL persist state to disk and recover on restart.

#### Scenario: Graceful shutdown
- **WHEN** the node is shutting down
- **THEN** all pending state is flushed to disk

#### Scenario: Startup recovery
- **WHEN** the node starts
- **THEN** state is loaded from disk and the node resumes from the last persisted state
