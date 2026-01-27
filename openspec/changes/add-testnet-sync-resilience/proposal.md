# Change: Add Testnet Sync Resilience

## Why
The node can connect to peers and download blocks, but real-world testnet sync fails because of gaps in error recovery, state persistence, and peer management. Specifically: sync progress is lost on restart (UTXO set and headers not persisted), peers that disconnect or misbehave are never replaced, out-of-order blocks get stuck in a queue that is never drained, and chain reorganizations corrupt the UTXO set because rollback is never invoked.

## What Changes
- Modified `storage` capability: persist UTXO set and header chain to disk; load on restart for sync resume
- Modified `networking` capability: automatic peer reconnection, peer rotation on failure, drain out-of-order block queue, connection health monitoring
- Modified `validation` capability: invoke UTXO rollback on chain reorganization

## Impact
- Affected specs: `storage` (modified), `networking` (modified), `validation` (modified)
- Affected code: `src/storage/chain.lisp`, `src/storage/utxo.lisp`, `src/networking/ibd.lisp`, `src/networking/peer.lisp`, `src/networking/protocol.lisp`, `src/node.lisp`, `src/validation/block.lisp`
- No breaking changes to existing APIs; existing tests remain valid
