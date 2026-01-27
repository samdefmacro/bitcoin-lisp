## 1. UTXO Set Persistence
- [x] 1.1 Implement `save-utxo-set` to serialize the UTXO set to a binary file (36-byte key + value/script-len/script/height/coinbase per entry)
- [x] 1.2 Implement `load-utxo-set` to deserialize the UTXO set from disk on startup
- [x] 1.3 Add periodic UTXO flush during sync (every 1000 blocks) and on shutdown
- [x] 1.4 Write tests for UTXO save/load round-trip

## 2. Header Chain Persistence
- [x] 2.1 Implement `save-header-index` to write block-index-entry records to disk
- [x] 2.2 Implement `load-header-index` to rebuild block-index from disk on startup
- [x] 2.3 Wire header persistence into `connect-block` (append on new block) and startup (load existing)
- [x] 2.4 Write tests for header index save/load round-trip

## 3. Sync Resume
- [x] 3.1 Modify `start-node` to load persisted UTXO set and header index before syncing
- [x] 3.2 Modify IBD to skip already-downloaded headers and blocks based on persisted state
- [x] 3.3 Write test: simulate restart by saving state, creating fresh node, loading state, verifying resume point

## 4. Peer Reconnection
- [x] 4.1 Add peer health monitoring: periodic ping (every 60s), disconnect peers that miss 3 pings
- [x] 4.2 Implement automatic peer replacement: when a peer disconnects, connect a new one from known addresses
- [x] 4.3 Maintain target peer count throughout sync (not just at startup)
- [x] 4.4 Write tests for peer health monitoring and replacement logic

## 5. Block Timeout Peer Rotation
- [x] 5.1 On block request timeout, retry from a different peer instead of the same one
- [x] 5.2 Track per-peer timeout count; disconnect after 3 timeouts
- [x] 5.3 Write tests for timeout rotation and peer disconnection

## 6. Out-of-Order Block Processing
- [x] 6.1 After connecting a block, check the queue for children whose parent is now connected
- [x] 6.2 Process queued children recursively until no more can be connected
- [x] 6.3 Write tests for out-of-order block arrival and queue draining

## 7. Chain Reorganization
- [x] 7.1 Detect reorg condition in `connect-block` when new chain has more work than current tip
- [x] 7.2 Find fork point between current and new chain
- [x] 7.3 Disconnect blocks from current tip back to fork point using `disconnect-block-from-utxo-set`
- [x] 7.4 Connect new chain blocks forward from fork point
- [x] 7.5 Write tests for shallow reorg (1-3 blocks deep)

## 8. Integration Validation
- [ ] 8.1 Manual testnet sync test: connect to real testnet, sync at least 1000 blocks, verify UTXO set consistency
- [ ] 8.2 Verify sync resume: stop node mid-sync, restart, confirm it resumes from persisted state
- [ ] 8.3 Verify peer reconnection: disconnect a peer during sync, confirm replacement connects
