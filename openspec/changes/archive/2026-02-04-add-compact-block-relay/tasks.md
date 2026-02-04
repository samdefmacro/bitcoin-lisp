# Tasks: Add Compact Block Relay (BIP 152)

## 1. Crypto: SipHash-2-4

- [x] 1.1 Implement `siphash-2-4` function in `src/crypto/hash.lisp`
- [x] 1.2 Add `compute-siphash-key` to derive k0/k1 from header + nonce
- [x] 1.3 Add `compute-short-txid` to compute 6-byte short transaction ID
- [x] 1.4 Add unit tests with BIP 152 test vectors

## 2. Serialization: Compact Block Messages

- [x] 2.1 Define `compact-block` struct (HeaderAndShortIDs)
- [x] 2.2 Define `prefilled-tx` struct with differential index encoding
- [x] 2.3 Define `block-txn-request` struct (getblocktxn payload)
- [x] 2.4 Define `block-txn-response` struct (blocktxn payload)
- [x] 2.5 Implement `read-compact-block` / `write-compact-block`
- [x] 2.6 Implement `read-block-txn-request` / `write-block-txn-request`
- [x] 2.7 Implement `read-block-txn-response` / `write-block-txn-response`
- [x] 2.8 Implement `parse-sendcmpct-payload` (1 byte + 8 bytes)
- [x] 2.9 Add `make-sendcmpct-message` for protocol negotiation
- [x] 2.10 Add `make-getblocktxn-message` for requesting missing txs
- [x] 2.11 Add `+inv-type-cmpct-block+` constant (value 4)
- [x] 2.12 Add unit tests for all message parsing/serialization

## 3. Networking: Peer State

- [x] 3.1 Add `compact-block-version` slot to peer struct (0, 1, or 2)
- [x] 3.2 Add `compact-block-high-bandwidth` slot to peer struct
- [x] 3.3 Add `pending-compact-block` slot for in-progress reconstruction
- [x] 3.4 Export new peer accessors from package

## 4. Networking: Protocol Negotiation

- [x] 4.1 Send `sendcmpct` messages after handshake (versions 2 and 1)
- [x] 4.2 Handle incoming `sendcmpct` messages, update peer state
- [x] 4.3 Track highest mutually supported version per peer
- [x] 4.4 Add unit tests for negotiation logic

## 5. Networking: Compact Block Handling

- [x] 5.1 Add `handle-cmpctblock` function for incoming compact blocks
- [x] 5.2 Implement `build-shortid-map` to index mempool by short ID (with collision detection)
- [x] 5.3 Implement `reconstruct-block` to match short IDs to mempool txs
- [x] 5.4 Implement `handle-blocktxn` to complete pending reconstruction
- [x] 5.5 Add `make-getblocktxn-request` to request missing transactions
- [x] 5.6 Add fallback to full block request on reconstruction failure or collision
- [x] 5.7 Register handlers in `handle-message` dispatch
- [x] 5.8 Add `pending-compact-block` struct for tracking in-progress reconstructions
- [x] 5.9 Implement timeout handling for pending reconstructions (default 10s)
- [x] 5.10 Add pending state cleanup on: completion, timeout, new block, peer disconnect

## 6. Networking: Block Download Integration

- [x] 6.1 Add `should-use-compact-blocks-p` predicate (checks peer support + not in IBD)
- [x] 6.2 Update `handle-inv` to request `MSG_CMPCT_BLOCK` when `should-use-compact-blocks-p`
- [ ] 6.3 Add support for high-bandwidth mode (unsolicited cmpctblock sending)
- [x] 6.4 Log reconstruction success/failure/collision metrics

## 7. Mempool Integration

- [x] 7.1 Add `mempool-for-each` for efficient iteration when building short ID map
- [x] 7.2 Ensure efficient iteration for building short ID map

## 8. Testing

- [x] 8.1 Add SipHash test vectors from BIP 152
- [x] 8.2 Add compact block message round-trip tests
- [x] 8.3 Add block reconstruction tests with mock mempool
- [x] 8.4 Add negotiation protocol tests
- [ ] 8.5 Integration test: receive compact block from testnet peer

## 9. Documentation

- [x] 9.1 Update USAGE.md with compact block support notes
- [x] 9.2 Document any new configuration options (none needed - compact blocks work automatically)
