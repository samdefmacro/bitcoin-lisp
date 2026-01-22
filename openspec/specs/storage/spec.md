# storage Specification

## Purpose
TBD - created by archiving change add-bitcoin-client-foundation. Update Purpose after archive.
## Requirements
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

### Requirement: Header Chain Storage
The system SHALL store block headers separately from full blocks during IBD.

Headers are stored with:
- Block hash (primary key)
- Header data (80 bytes)
- Height in chain
- Chainwork at this block
- Validation status (header-valid, fully-valid)

#### Scenario: Store header before block
- **GIVEN** a validated block header
- **WHEN** the full block is not yet downloaded
- **THEN** the header is stored with status `header-valid`

#### Scenario: Query headers by height range
- **GIVEN** a start and end height
- **WHEN** querying the header chain
- **THEN** all headers in the range are returned in order

#### Scenario: Find common ancestor
- **GIVEN** two block hashes
- **WHEN** finding the common ancestor
- **THEN** the highest block that is an ancestor of both is returned

### Requirement: Checkpoint Storage
The system SHALL store and validate against hardcoded checkpoints.

Checkpoints are (height, hash) pairs representing known-good blocks that the chain must pass through. During IBD, the header chain is validated against checkpoints to prevent long-range attacks.

#### Scenario: Load testnet checkpoints
- **WHEN** the node initializes
- **THEN** testnet checkpoint data is available for validation

#### Scenario: Validate chain against checkpoint
- **GIVEN** a header at a checkpoint height
- **WHEN** validating the header chain
- **THEN** the header hash must match the checkpoint hash

#### Scenario: Reject chain diverging before checkpoint
- **GIVEN** a header chain that diverges before the last checkpoint
- **WHEN** validating the chain
- **THEN** the chain is rejected as invalid

### Requirement: Download Queue Management
The system SHALL maintain a queue of blocks pending download.

The queue tracks:
- Blocks to download (by hash and height)
- In-flight requests (peer, timestamp)
- Completed downloads pending validation

#### Scenario: Add blocks to download queue
- **GIVEN** a range of validated headers
- **WHEN** blocks are needed
- **THEN** block hashes are added to the download queue in height order

#### Scenario: Track in-flight request
- **GIVEN** a block request sent to a peer
- **WHEN** the request is initiated
- **THEN** the request is recorded with peer ID and timestamp

#### Scenario: Mark block downloaded
- **GIVEN** a block received from a peer
- **WHEN** the block matches a pending request
- **THEN** the request is removed from in-flight and block is queued for validation

