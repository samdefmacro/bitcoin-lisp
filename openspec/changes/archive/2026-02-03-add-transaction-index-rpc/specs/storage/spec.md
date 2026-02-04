# Storage Spec Delta: Transaction Index

## ADDED Requirements

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

#### Scenario: build txindex incremental
- **GIVEN** txindex covers blocks 0-500 AND chain has blocks 0-1000
- **WHEN** build-tx-index is called
- **THEN** only blocks 501-1000 are scanned

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
