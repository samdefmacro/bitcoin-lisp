## Context
The node implements IBD (Initial Block Download) with headers-first sync, but real-world testnet sync exposes multiple failure modes: peer disconnects, node restarts losing all progress, out-of-order blocks never processed, and chain reorgs corrupting the UTXO set. These must be fixed before the node can reliably sync even a modest stretch of testnet.

## Goals / Non-Goals
- Goals:
  - Persist UTXO set to disk so sync resumes after restart
  - Persist header chain index so headers are not re-downloaded
  - Automatically reconnect to new peers when connections drop
  - Rotate to a different peer when a block request times out
  - Drain the out-of-order block queue when parent blocks arrive
  - Invoke UTXO rollback during chain reorganization
  - Monitor connection health and disconnect stale peers
- Non-Goals:
  - Mainnet support — testnet only
  - Full chain reorg testing (deep reorgs) — only shallow reorgs handled
  - Parallel block validation — sequential is sufficient
  - Pruning old blocks — store everything

## Decisions

### UTXO persistence format
- Decision: Serialize UTXO set as a flat binary file (key-value pairs: 36-byte key + entry fields)
- Rationale: Simple, fast sequential write; the UTXO set fits in memory so we flush periodically and on shutdown
- Alternative considered: SQLite — adds external dependency, over-engineered for current scale

### Header chain persistence
- Decision: Append-only binary file of block-index-entry records (hash, height, header bytes, chainwork, status)
- Rationale: Headers are small (80 bytes each + metadata); sequential append is efficient
- Alternative: Store only the best-chain headers — but then forks require re-download

### Peer reconnection strategy
- Decision: When a peer disconnects, attempt to connect a replacement from the known address pool. Maintain the target peer count. Check peer health every 60 seconds via ping.
- Rationale: Simple replacement model; no exponential backoff needed for testnet

### Block timeout peer rotation
- Decision: When a block request times out, mark the peer as slow and retry from a different peer. After 3 timeouts from the same peer, disconnect it.
- Rationale: Avoids getting stuck on a single unresponsive peer

### Out-of-order block processing
- Decision: When a block arrives and its parent is already connected, process it immediately. After connecting any block, check the queue for children that can now be processed.
- Rationale: The queue already exists; just needs a drain loop

### Chain reorganization
- Decision: When a competing chain tip has more work, disconnect blocks back to the fork point using `disconnect-block-from-utxo-set`, then connect the new chain's blocks forward.
- Rationale: The `disconnect-block-from-utxo-set` function already exists but is never called; wire it into `connect-block` when detecting a reorg

## Risks / Trade-offs
- UTXO persistence adds disk I/O during sync — mitigated by batching writes (every N blocks or on shutdown)
- Peer rotation may connect to worse peers — acceptable for testnet
- Reorg handling only covers shallow reorgs (common on testnet) — deep reorgs are rare and can be deferred

## Open Questions
- None; all decisions are straightforward for testnet scope
