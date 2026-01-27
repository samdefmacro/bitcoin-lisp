## ADDED Requirements

### Requirement: Mempool Storage
The system SHALL maintain an in-memory pool of validated unconfirmed transactions.

Each mempool entry contains:
- Transaction data
- Fee in satoshis
- Serialized size in bytes
- Entry timestamp

The mempool is indexed by transaction ID (txid) for O(1) lookup.

#### Scenario: Add transaction to mempool
- **GIVEN** a valid unconfirmed transaction
- **WHEN** adding it to the mempool
- **THEN** the transaction is stored and retrievable by txid

#### Scenario: Remove transaction from mempool
- **GIVEN** a transaction in the mempool
- **WHEN** removing it by txid
- **THEN** the transaction is no longer present and its spent outpoints are freed

#### Scenario: Reject duplicate transaction
- **GIVEN** a transaction already in the mempool
- **WHEN** attempting to add it again
- **THEN** the addition is rejected

### Requirement: Conflict Detection
The system SHALL reject transactions that spend outputs already spent by another mempool transaction.

The mempool tracks which outpoints are spent by which mempool transactions. A new transaction is rejected if any of its inputs reference an outpoint already spent by an existing mempool entry.

#### Scenario: Reject double-spend against mempool
- **GIVEN** a mempool containing transaction A that spends output X
- **WHEN** transaction B also spending output X is submitted
- **THEN** transaction B is rejected as a conflict

#### Scenario: Allow spending different outputs
- **GIVEN** a mempool containing transaction A that spends output X
- **WHEN** transaction B spending output Y is submitted
- **THEN** transaction B is accepted (no conflict)

### Requirement: Mempool Size Limit
The system SHALL enforce a maximum mempool size based on total serialized transaction data.

Default maximum: 300 MB of serialized transaction data. When the limit is exceeded, the lowest fee-rate transactions are evicted until the total size is under the limit.

#### Scenario: Evict lowest fee-rate transaction
- **GIVEN** a mempool at its size limit
- **WHEN** a new higher fee-rate transaction is added
- **THEN** the lowest fee-rate transaction is evicted to make room

#### Scenario: Reject transaction below eviction threshold
- **GIVEN** a mempool at its size limit
- **WHEN** a new transaction has fee-rate lower than the minimum in the pool
- **THEN** the new transaction is rejected

### Requirement: Mempool Acceptance Validation
The system SHALL validate transactions against consensus rules and mempool policy before acceptance.

Validation includes:
- Consensus checks: valid structure, valid scripts, inputs reference existing UTXOs, no double-spends against confirmed chain
- Policy checks: minimum fee-rate (1 sat/vbyte default), maximum transaction size, standard script types
- Mempool checks: no conflicts with existing mempool entries, no duplicate

#### Scenario: Accept valid standard transaction
- **GIVEN** a transaction with valid scripts, sufficient fee, and standard outputs
- **WHEN** submitted to the mempool
- **THEN** the transaction is accepted

#### Scenario: Reject transaction with insufficient fee
- **GIVEN** a transaction with fee-rate below the minimum relay fee
- **WHEN** submitted to the mempool
- **THEN** the transaction is rejected with insufficient fee error

#### Scenario: Reject transaction with missing inputs
- **GIVEN** a transaction referencing a UTXO that does not exist
- **WHEN** submitted to the mempool
- **THEN** the transaction is rejected with missing inputs error

### Requirement: Block-Mempool Synchronization
The system SHALL update the mempool when blocks are connected or disconnected.

When a block is connected:
- Transactions included in the block are removed from the mempool
- Transactions conflicting with block transactions are removed

When a block is disconnected (reorg):
- Non-coinbase transactions from the disconnected block are re-validated and re-added to the mempool if still valid

#### Scenario: Remove confirmed transactions
- **GIVEN** a mempool containing transactions A and B
- **WHEN** a block containing transaction A is connected
- **THEN** transaction A is removed from the mempool and transaction B remains

#### Scenario: Remove conflicting transactions on block connect
- **GIVEN** mempool transaction M spending output X
- **WHEN** a block is connected containing transaction N that also spends output X
- **THEN** transaction M is removed from the mempool as conflicting

#### Scenario: Re-admit transactions on block disconnect
- **GIVEN** a block containing transaction A is disconnected during reorg
- **WHEN** transaction A is still valid against the new chain state
- **THEN** transaction A is re-added to the mempool
