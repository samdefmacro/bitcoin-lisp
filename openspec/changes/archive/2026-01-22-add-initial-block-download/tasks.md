## 1. Headers-First Sync

- [x] 1.1 Implement `getheaders` message serialization and sending
- [x] 1.2 Implement `headers` message parsing (up to 2000 headers per message)
- [x] 1.3 Build header chain validation (prev_hash links, proof-of-work)
- [x] 1.4 Store headers in block index with validation status
- [x] 1.5 Implement locator construction for `getheaders` requests

## 2. Checkpoint Validation

- [x] 2.1 Define testnet checkpoint data (hash, height pairs)
- [x] 2.2 Validate header chain passes through checkpoints
- [x] 2.3 Reject chains that diverge before last checkpoint

## 3. Block Download Management

- [x] 3.1 Implement `getdata` message for block requests
- [x] 3.2 Track in-flight block requests per peer
- [x] 3.3 Implement download window (max blocks in flight)
- [x] 3.4 Handle `block` message responses
- [x] 3.5 Implement request timeout and retry logic
- [x] 3.6 Distribute requests across multiple peers

## 4. Block Processing Pipeline

- [x] 4.1 Validate received blocks against headers
- [x] 4.2 Process blocks in height order (handle out-of-order arrival)
- [x] 4.3 Connect blocks to chain (update UTXO set)
- [x] 4.4 Persist validated blocks to storage

## 5. Sync State Machine

- [x] 5.1 Define IBD states: `idle`, `syncing-headers`, `syncing-blocks`, `synced`
- [x] 5.2 Implement state transitions and event handling
- [x] 5.3 Track sync progress (current height, target height, peers)
- [x] 5.4 Detect sync completion (caught up with peers)
- [x] 5.5 Handle peer disconnection during sync

## 6. Testing

- [x] 6.1 Unit tests for header chain validation
- [x] 6.2 Unit tests for block download tracking
- [x] 6.3 Integration test: sync first 1000 blocks from testnet
- [x] 6.4 Test checkpoint enforcement
- [x] 6.5 Test peer timeout and recovery
