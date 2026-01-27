## 1. Mempool Core
- [x] 1.1 Create `src/mempool/mempool.lisp` with `mempool-entry` struct (transaction, fee, size, entry-time) and `mempool` struct (txid hash-table, spent-outpoints hash-table, total-size counter)
- [x] 1.2 Implement `mempool-add`, `mempool-remove`, `mempool-get`, `mempool-has` operations
- [x] 1.3 Implement spent-outpoint conflict detection (reject transactions that double-spend mempool entries)
- [x] 1.4 Implement size-based eviction: when total serialized size exceeds limit, evict lowest fee-rate entries
- [x] 1.5 Write unit tests for mempool add/remove/eviction/conflict detection

## 2. Mempool Validation
- [x] 2.1 Implement `validate-transaction-for-mempool` in `src/validation/transaction.lisp` — consensus checks plus policy checks (minimum fee-rate, max transaction size, standard script types)
- [x] 2.2 Integrate UTXO lookups: verify all inputs reference existing UTXOs not already spent by other mempool entries
- [x] 2.3 Write tests for mempool acceptance and rejection cases

## 3. Transaction Message Handling
- [x] 3.1 Add `make-tx-message` to `src/serialization/messages.lisp` for serializing a transaction into a P2P `tx` message
- [x] 3.2 Add `tx` command handler to `handle-message` in `src/networking/protocol.lisp` — parse transaction, validate for mempool, add if valid
- [x] 3.3 Add `getdata` handler for transaction inventory types — look up txid in mempool and respond with `tx` message
- [x] 3.4 Modify `inv` handler to request transactions (not just blocks) when they are unknown
- [x] 3.5 Write tests for tx message round-trip and inv/getdata handling

## 4. Transaction Relay
- [x] 4.1 Implement `relay-transaction` — after accepting a tx into mempool, send `inv` to all connected peers except the source
- [x] 4.2 Track per-peer announced transaction set to avoid re-announcing known txs
- [x] 4.3 Write tests for relay logic (announces to others, skips source peer)

## 5. Block-Mempool Integration
- [x] 5.1 On block connect: remove confirmed transactions from mempool, remove conflicting transactions
- [x] 5.2 On block disconnect (reorg): re-validate and re-add disconnected block's non-coinbase transactions to mempool
- [x] 5.3 Write tests for block connect/disconnect mempool updates

## 6. Node Integration
- [x] 6.1 Initialize mempool in `src/node.lisp` and wire it into message handling
- [x] 6.2 Add mempool status logging (size, tx count, memory usage)
- [x] 6.3 Integration test: accept tx from peer, verify relay to other peer
