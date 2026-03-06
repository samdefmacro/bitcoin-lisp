## ADDED Requirements

### Requirement: Prune Blockchain RPC
The system SHALL provide a `pruneblockchain` RPC method to manually trigger block pruning.

Method: `pruneblockchain`
Parameters:
- `height` (integer): Target height to prune up to

Behavior:
- Deletes block data files for all blocks below the specified height
- Respects the 288-block minimum retention window (clamps to `chain-height - 288`)
- Returns the height of the first unpruned block (pruned-height + 1), matching Bitcoin Core
- Works in both automatic pruning mode and manual-only mode (`*prune-target-mib*` = 1)
- Requires pruning to be enabled (any mode); returns error if pruning is disabled

#### Scenario: Manual prune to height
- **GIVEN** pruning is enabled and chain is at height 10000
- **WHEN** `pruneblockchain` is called with height 9000
- **THEN** blocks below height 9000 are pruned
- **AND** response is 9000 (first unpruned block height)

#### Scenario: Prune rejected when disabled
- **GIVEN** pruning is not enabled (`*prune-target-mib*` is nil)
- **WHEN** `pruneblockchain` is called
- **THEN** an error response is returned indicating node is not in prune mode

#### Scenario: Prune clamped to 288-block retention
- **GIVEN** pruning is enabled and chain is at height 10000
- **WHEN** `pruneblockchain` is called with height 9900
- **THEN** blocks are pruned only up to height 9712 (10000 - 288)
- **AND** response is 9713 (first unpruned block)

#### Scenario: Prune in manual-only mode
- **GIVEN** `*prune-target-mib*` is 1 (manual-only) and chain is at height 10000
- **WHEN** `pruneblockchain` is called with height 9000
- **THEN** blocks below height 9000 are pruned
- **AND** response is 9000

## MODIFIED Requirements

### Requirement: Blockchain Query Methods
The system SHALL provide methods to query blockchain state.

Methods:
- `getblockchaininfo`: Returns network, chain, height, sync progress, and pruning status
- `getbestblockhash`: Returns the hash of the current tip
- `getblockcount`: Returns the current block height
- `getblockhash <height>`: Returns block hash at given height
- `getblock <hash> [verbosity]`: Returns block data (0=hex, 1=json, 2=json+tx)
- `getblockheader <hash> [verbose]`: Returns header data

The `getblockchaininfo` response SHALL include pruning fields when pruning is enabled:
- `pruned`: Boolean indicating if pruning is enabled (always present)
- `pruneheight`: Height of the first unpruned block (pruned-height + 1), or 0 if nothing pruned yet (only present when pruned is true)
- `automatic_pruning`: Boolean indicating whether automatic pruning is active vs manual-only (only present when pruned is true)
- `prune_target_size`: Configured prune target in **bytes** (i.e., `*prune-target-mib*` * 1024 * 1024), only present when automatic_pruning is true

#### Scenario: getblockchaininfo
- **GIVEN** the node is synced to height 1000
- **WHEN** getblockchaininfo is called
- **THEN** response includes chain "test", blocks 1000, and headers count

#### Scenario: getblockchaininfo on auto-pruned node
- **GIVEN** automatic pruning is enabled with prune-target-mib=550 and pruned-height=5000
- **WHEN** getblockchaininfo is called
- **THEN** response includes `"pruned": true`, `"pruneheight": 5001`, `"automatic_pruning": true`, and `"prune_target_size": 576716800`

#### Scenario: getblockchaininfo on manual-only pruned node
- **GIVEN** manual-only pruning is enabled (prune-target-mib=1) and pruned-height=3000
- **WHEN** getblockchaininfo is called
- **THEN** response includes `"pruned": true`, `"pruneheight": 3001`, `"automatic_pruning": false`
- **AND** `prune_target_size` is NOT present

#### Scenario: getblockchaininfo on non-pruned node
- **GIVEN** pruning is disabled
- **WHEN** getblockchaininfo is called
- **THEN** response includes `"pruned": false`
- **AND** `pruneheight`, `automatic_pruning`, and `prune_target_size` are not present

#### Scenario: getblock with verbosity 0
- **GIVEN** block exists at hash H
- **WHEN** getblock(H, 0) is called
- **THEN** response is hex-encoded raw block

#### Scenario: getblock with verbosity 1
- **GIVEN** block exists at hash H
- **WHEN** getblock(H, 1) is called
- **THEN** response is JSON with block fields and txid list

#### Scenario: getblock with verbosity 2
- **GIVEN** block exists at hash H
- **WHEN** getblock(H, 2) is called
- **THEN** response is JSON with block fields and full transaction details

#### Scenario: getblock with invalid hash format
- **GIVEN** the RPC server is running
- **WHEN** getblock("not-a-hash", 1) is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: getblock for unknown hash
- **GIVEN** hash H does not exist in chain
- **WHEN** getblock(H, 1) is called
- **THEN** error is returned indicating block not found

#### Scenario: getblockhash for invalid height
- **GIVEN** chain height is 100
- **WHEN** getblockhash(200) is called
- **THEN** error is returned indicating block not found
