# Change: Add Mempool & Transaction Relay

## Why
The node can validate and store blocks but cannot participate in transaction propagation. Without a mempool, the node ignores unconfirmed transactions from peers and cannot relay them, making it a passive observer rather than a full participant in the Bitcoin P2P network.

## What Changes
- New `mempool` capability: in-memory pool of validated unconfirmed transactions with fee tracking, size limits, and eviction
- Modified `networking` capability: handle `tx` messages, respond to `getdata` for transactions, relay transaction inventory to peers
- Modified `validation` capability: mempool-specific acceptance rules (policy checks beyond consensus)

## Impact
- Affected specs: `mempool` (new), `networking` (modified), `validation` (modified)
- Affected code: new `src/mempool/` module, modifications to `src/networking/protocol.lisp`, `src/validation/transaction.lisp`, `src/node.lisp`
- No breaking changes to existing functionality
