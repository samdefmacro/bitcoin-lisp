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

### Requirement: UTXO Set Persistence
The system SHALL persist the UTXO set to disk and reload it on startup.

The persistence format SHALL include integrity protection:
- 4-byte magic identifier ("UTXO")
- 4-byte format version
- 4-byte entry count
- Entry data (key + value per entry)
- 4-byte CRC32 checksum of all preceding bytes

UTXO set writes SHALL be atomic: data is written to a temporary file (`<path>.tmp`), then renamed to the final path. This prevents corruption from interrupted writes.

On load, the system SHALL verify magic bytes, format version, and CRC32 checksum before accepting the data. If verification fails, the file is rejected and the node starts with an empty UTXO set.

If a `.tmp` file exists but the main file does not, the system SHALL log a warning (indicates an interrupted write) and start with an empty UTXO set.

Old-format files (no magic bytes) SHALL be detected and loaded using the legacy parser for backward compatibility. The new format is written on the next save.

#### Scenario: Save and reload UTXO set
- **GIVEN** a UTXO set with entries
- **WHEN** saving to disk and reloading
- **THEN** all entries are preserved with identical values

#### Scenario: Detect truncated UTXO file
- **GIVEN** a UTXO file that was truncated mid-write
- **WHEN** loading the file
- **THEN** the CRC32 check fails and the file is rejected

#### Scenario: Detect corrupted UTXO file
- **GIVEN** a UTXO file with flipped bits in an entry
- **WHEN** loading the file
- **THEN** the CRC32 check fails and the file is rejected

#### Scenario: Atomic write prevents corruption
- **GIVEN** a valid UTXO file on disk
- **WHEN** a save operation is interrupted (simulated by leaving `.tmp` file)
- **THEN** the original file remains intact and loadable

#### Scenario: Reject unknown format version
- **GIVEN** a UTXO file with format version 99
- **WHEN** loading the file
- **THEN** the file is rejected with a version mismatch warning

#### Scenario: Backward compatibility with old format
- **GIVEN** a UTXO file in the old format (no magic bytes, no checksum)
- **WHEN** loading the file
- **THEN** the old format is detected and loaded successfully

### Requirement: Header Index Persistence
The system SHALL persist the header chain index to disk with checksum integrity protection.

The format SHALL include:
- 4-byte magic identifier ("HIDX")
- 4-byte format version
- 4-byte entry count
- Entry data
- 4-byte CRC32 checksum

The header index already uses a two-phase write pattern (placeholder count, then entries, then count update). This existing pattern is retained; CRC32 and magic bytes are added.

#### Scenario: Save and reload header index
- **GIVEN** a header index with block entries
- **WHEN** saving to disk and reloading
- **THEN** all entries are preserved and the chain can resume sync

#### Scenario: Detect corrupted header index
- **GIVEN** a header index file with corrupted data
- **WHEN** loading the file
- **THEN** the CRC32 check fails and the file is rejected

### Requirement: Persistence Consistency After Reorg
The system SHALL maintain UTXO set consistency through chain reorganizations and persistence cycles.

After a reorg followed by a save/load cycle, the UTXO set SHALL reflect the current chain tip accurately.

#### Scenario: UTXO consistency after reorg and reload
- **GIVEN** a reorg has occurred and the UTXO set has been updated
- **WHEN** the UTXO set is saved and reloaded
- **THEN** the reloaded set matches the post-reorg state exactly

### Requirement: Transaction Index Storage
The system SHALL optionally maintain an index mapping transaction IDs to their block location.

The transaction index:
- Maps 32-byte txid to (block_hash, tx_position)
- Persists to disk for durability across restarts
- Rebuilds in-memory index from disk on startup
- Supports efficient O(1) lookups by txid

Configuration:
- `txindex`: Boolean to enable/disable (default: false)
- Index is not required for basic node operation

#### Scenario: txindex lookup existing transaction
- **GIVEN** txindex is enabled AND transaction T was indexed in block B at position 3
- **WHEN** txindex-lookup(T.txid) is called
- **THEN** returns (B.hash, 3)

#### Scenario: txindex lookup missing transaction
- **GIVEN** txindex is enabled AND transaction T was never indexed
- **WHEN** txindex-lookup(T.txid) is called
- **THEN** returns nil

#### Scenario: txindex add transaction
- **GIVEN** txindex is enabled
- **WHEN** txindex-add(txid, block_hash, position) is called
- **THEN** entry is written to index AND subsequent lookup succeeds

#### Scenario: txindex persistence
- **GIVEN** txindex has entries AND node restarts
- **WHEN** txindex is loaded
- **THEN** all previously indexed transactions are findable

#### Scenario: txindex disabled
- **GIVEN** txindex is disabled
- **WHEN** block is validated
- **THEN** no txindex entries are written

### Requirement: Transaction Index Chain Reorganization
The system SHALL update the transaction index during chain reorganizations.

During reorg:
- Transactions in orphaned blocks are removed from index
- Transactions in new chain are added to index
- Index remains consistent with current best chain

#### Scenario: txindex reorg removal
- **GIVEN** txindex has transaction T from block B AND block B is orphaned
- **WHEN** chain reorganizes to exclude B
- **THEN** txindex-lookup(T.txid) returns nil (or new location if T in new chain)

#### Scenario: txindex reorg addition
- **GIVEN** chain reorganizes to include block B with transaction T
- **WHEN** reorganization completes
- **THEN** txindex-lookup(T.txid) returns T's location in B

### Requirement: Transaction Index Background Building
The system SHALL support building the transaction index from existing blocks.

Background index building:
- Scans all blocks from genesis to current tip
- Indexes all transactions in each block
- Reports progress during long operations
- Does not block normal node operation

#### Scenario: build txindex from scratch
- **GIVEN** txindex is empty AND chain has blocks 0-1000
- **WHEN** build-tx-index is called
- **THEN** all transactions in blocks 0-1000 are indexed

#### Scenario: build txindex progress
- **GIVEN** chain has 10000 blocks
- **WHEN** build-tx-index is called with progress callback
- **THEN** callback receives periodic progress updates (height, percentage)

### Requirement: UTXO Set Iteration
The system SHALL support ordered iteration over the UTXO set.

UTXO iteration:
- Traverses all unspent outputs in deterministic order
- Order is (txid, vout) ascending (lexicographic on txid, then numeric on vout)
- Enables computation of UTXO set hash

#### Scenario: iterate UTXO set
- **GIVEN** UTXO set has entries for txids A, B, C with various vouts
- **WHEN** utxo-iterate is called
- **THEN** entries are visited in (txid, vout) ascending order

#### Scenario: iterate empty UTXO set
- **GIVEN** UTXO set is empty
- **WHEN** utxo-iterate is called
- **THEN** callback is never invoked

#### Scenario: UTXO iteration consistency
- **GIVEN** UTXO set state S
- **WHEN** utxo-iterate is called twice without modifications
- **THEN** same entries are visited in same order

