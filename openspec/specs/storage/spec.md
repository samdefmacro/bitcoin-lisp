# storage Specification

## Purpose
TBD - created by archiving change add-bitcoin-client-foundation. Update Purpose after archive.
## Requirements
### Requirement: Block Storage
The system SHALL persistently store downloaded blocks.

Blocks MAY be pruned (deleted from disk) after full validation when pruning is enabled. A pruned block returns NIL from `get-block` but its header remains available through the block index.

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

#### Scenario: Retrieve pruned block returns nil
- **GIVEN** a block that has been pruned
- **WHEN** querying storage with `get-block`
- **THEN** nil is returned

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
- Pruned height (height of the last pruned block, 0 if none)

#### Scenario: Update chain tip
- **GIVEN** a new valid block extending the best chain
- **WHEN** the block is connected
- **THEN** the chain state is updated with the new tip

#### Scenario: Retrieve current height
- **GIVEN** the chain state
- **WHEN** querying current height
- **THEN** the height of the best chain tip is returned

#### Scenario: Query pruned height
- **GIVEN** pruning has been performed up to height N
- **WHEN** querying pruned-height
- **THEN** N is returned

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
The system SHALL store and validate against hardcoded checkpoints for the active network.

Checkpoints are (height, hash) pairs representing known-good blocks that the chain must pass through. During IBD, the header chain is validated against checkpoints to prevent long-range attacks.

Each network has its own set of checkpoints:
- Testnet: `*testnet-checkpoints*` - testnet-specific checkpoint blocks
- Mainnet: `*mainnet-checkpoints*` - mainnet checkpoint blocks including halving blocks

Accessor functions `get-checkpoint-hash` and `last-checkpoint-height` dispatch on the active network.

#### Scenario: Load testnet checkpoints
- **GIVEN** network is set to testnet
- **WHEN** calling `get-checkpoint-hash` or `last-checkpoint-height`
- **THEN** testnet checkpoint data is used

#### Scenario: Load mainnet checkpoints
- **GIVEN** network is set to mainnet
- **WHEN** calling `get-checkpoint-hash` or `last-checkpoint-height`
- **THEN** mainnet checkpoint data is used

#### Scenario: Validate chain against checkpoint
- **GIVEN** a header at a checkpoint height
- **WHEN** validating the header chain
- **THEN** the header hash must match the checkpoint hash for the active network

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

### Requirement: Network Genesis Block
The system SHALL use the correct genesis block hash for the active network.

Genesis block hashes (display format, big-endian):
- Testnet: `000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943`
- Mainnet: `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`

The `network-genesis-hash` function returns the appropriate genesis hash based on the active network.

#### Scenario: Initialize testnet chain state
- **GIVEN** network is set to testnet
- **WHEN** creating initial chain state
- **THEN** genesis hash is set to testnet genesis block

#### Scenario: Initialize mainnet chain state
- **GIVEN** network is set to mainnet
- **WHEN** creating initial chain state
- **THEN** genesis hash is set to mainnet genesis block

### Requirement: Network Data Directory
The system SHALL store blockchain data in network-appropriate directories.

Directory structure:
- Testnet: `<base-directory>/` (backward compatible, no subdirectory)
- Mainnet: `<base-directory>/mainnet/`

This ensures:
- Existing testnet data is not affected
- Mainnet and testnet data cannot be accidentally mixed
- Running both networks simultaneously is possible

#### Scenario: Store testnet data at base directory
- **GIVEN** network is set to testnet
- **WHEN** persisting blockchain data
- **THEN** files are written to `<base>/` (e.g., `~/.bitcoin-lisp/utxo.dat`)

#### Scenario: Store mainnet data in mainnet subdirectory
- **GIVEN** network is set to mainnet
- **WHEN** persisting blockchain data
- **THEN** files are written to `<base>/mainnet/` subdirectory

#### Scenario: Existing testnet data unaffected
- **GIVEN** existing testnet data at `<base>/`
- **WHEN** node starts with testnet
- **THEN** existing data is loaded normally without migration

### Requirement: Block Pruning
The system SHALL support optional pruning of old block data to reduce disk usage while maintaining full validation capability.

Pruning configuration:
- `*prune-target-mib*`: Target disk usage in MiB for block storage. nil = pruning disabled (default). 1 = manual-only mode (no automatic pruning, but `pruneblockchain` RPC works). >= 550 = automatic pruning with byte target. Any other value SHALL signal an error at startup.
- `*prune-after-height*`: Minimum chain height before pruning can begin. 100000 on mainnet, 1000 on testnet. Prevents premature deletion during early IBD.
- Minimum block retention: 288 blocks (`MIN_BLOCKS_TO_KEEP`, ~2 days of mainnet blocks) are always kept regardless of byte target, matching Bitcoin Core.

Pruning is **off by default**. The user MUST explicitly set `*prune-target-mib*` to enable pruning.

Automatic pruning behavior (when `*prune-target-mib*` >= 550):
- After a block is fully validated and connected to the best chain, the system checks total block storage size on disk
- If storage exceeds `*prune-target-mib*`, the oldest block files are deleted until storage is under the target
- Blocks within the 288-block retention window SHALL NOT be pruned regardless of storage pressure
- Pruning SHALL NOT begin until the chain height exceeds `*prune-after-height*`
- Only the raw block data file (`.blk`) is deleted; block headers, UTXO set, and chain state are retained
- Pruning is idempotent: pruning an already-pruned block is a no-op

Manual-only mode (when `*prune-target-mib*` = 1):
- No automatic pruning occurs after block connection
- Pruning is only performed via the `pruneblockchain` RPC method
- The 288-block retention window and `*prune-after-height*` still apply

Pruning constraints:
- Pruning and txindex SHALL NOT be enabled simultaneously. The node SHALL signal an error at startup if both are configured.
- A pruned node still fully validates all blocks during IBD before deleting them.

Reorg safety:
- If a chain reorganization would require disconnecting blocks that have been pruned, the system SHALL signal an error. The node cannot reorg past the pruned height and must re-sync from scratch. This matches Bitcoin Core behavior. The 288-block retention window makes this scenario essentially impossible in practice.

#### Scenario: Automatic pruning when storage exceeds target
- **GIVEN** pruning is enabled with prune-target-mib=550
- **AND** total block storage on disk exceeds 550 MiB after connecting a new block
- **AND** chain height exceeds prune-after-height
- **WHEN** the pruning check runs
- **THEN** the oldest block files are deleted until total storage is at or below 550 MiB
- **AND** blocks within the most recent 288 are never deleted
- **AND** block headers for deleted blocks remain available

#### Scenario: Pruning disabled by default
- **GIVEN** `*prune-target-mib*` is nil (default)
- **WHEN** blocks are connected to the chain
- **THEN** no block files are deleted

#### Scenario: Manual-only mode
- **GIVEN** `*prune-target-mib*` is 1
- **WHEN** blocks are connected to the chain
- **THEN** no automatic pruning occurs
- **AND** the `pruneblockchain` RPC method is available

#### Scenario: Pruning incompatible with txindex
- **GIVEN** both pruning and txindex are enabled
- **WHEN** the node starts
- **THEN** an error is signaled indicating the incompatibility

#### Scenario: Prune target below minimum rejected
- **GIVEN** `*prune-target-mib*` is set to 100
- **WHEN** the node starts
- **THEN** an error is signaled indicating minimum is 550 MiB (or 1 for manual-only mode)

#### Scenario: Pruning deferred before prune-after-height
- **GIVEN** pruning is enabled with automatic mode
- **AND** chain height is 50000 (below mainnet prune-after-height of 100000)
- **WHEN** the pruning check runs
- **THEN** no blocks are pruned regardless of storage usage

#### Scenario: Manual pruning via prune-blocks-to-height
- **GIVEN** pruning is enabled (any mode) and chain is at height 200000
- **WHEN** `prune-blocks-to-height` is called with target height 199000
- **THEN** all block files at heights below 199000 are deleted (respecting 288-block minimum)
- **AND** pruned-height is updated accordingly

#### Scenario: 288-block minimum retention enforced
- **GIVEN** pruning is enabled and chain is at height 500
- **AND** storage exceeds the prune target and chain exceeds prune-after-height
- **WHEN** the pruning check runs
- **THEN** blocks at heights 213 through 500 (288 blocks) are retained
- **AND** only blocks below height 213 are eligible for deletion

#### Scenario: Reorg past pruned height fails
- **GIVEN** blocks below height 5000 have been pruned
- **WHEN** a chain reorganization requires disconnecting block 4999
- **THEN** an error is signaled indicating the block data is unavailable
- **AND** the node must re-sync from scratch to recover

### Requirement: Pruning State Persistence
The system SHALL persist the pruning state across node restarts.

The chain state SHALL additionally track:
- `pruned-height`: The height of the last pruned block (0 if no pruning has occurred)

This field SHALL be saved and loaded as part of the chain state file (`chainstate.dat`).

#### Scenario: Pruned height persists across restart
- **GIVEN** blocks have been pruned up to height 5000
- **WHEN** the node restarts and loads chain state
- **THEN** `pruned-height` is restored to 5000
- **AND** the node does not attempt to re-download pruned blocks

#### Scenario: Fresh node has pruned-height zero
- **GIVEN** a new node with no prior state
- **WHEN** chain state is initialized
- **THEN** `pruned-height` is 0

