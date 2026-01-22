# Change: Initial Block Download (IBD)

## Why

The node cannot participate in the Bitcoin network without first synchronizing with the blockchain. Initial Block Download is the process of downloading and validating the complete blockchain from genesis to the current tip. Without IBD, the node has no UTXO set and cannot validate new transactions or blocks.

## What Changes

- **Headers-first synchronization**: Download all block headers before requesting full blocks, enabling parallel block downloads and early detection of invalid chains
- **Block download management**: Coordinate block requests across multiple peers with request tracking, timeouts, and retry logic
- **Checkpoint validation**: Validate headers against hardcoded checkpoints to prevent long-range attacks during sync
- **Progress tracking**: Track and report synchronization progress (headers synced, blocks downloaded, validation state)
- **Sync state machine**: Manage IBD lifecycle states (downloading headers, downloading blocks, synced, reorg)

## Impact

- Affected specs: networking, storage, validation
- Affected code: `src/networking/`, `src/storage/`, `src/node.lisp`
- New capability: Node can sync from genesis to chain tip on testnet
