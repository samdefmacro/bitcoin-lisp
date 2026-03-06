## ADDED Requirements

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

## MODIFIED Requirements

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
