## 1. Implementation

- [ ] 1.1 Create `src/networking/peerdb.lisp` — `peer-address` struct, IP helper functions (IPv4-to-mapped-IPv6, address-book key), `address-book` struct, add/lookup/evict operations, scoring function (`compute-peer-score`), `save-address-book` / `load-address-book` persistence (reuse `compute-crc32` from `src/storage/utxo.lisp`, atomic write via `.tmp` + `rename-file`)
- [ ] 1.2 Update `src/package.lisp` — export new symbols from `bitcoin-lisp.networking` package
- [ ] 1.3 Update `bitcoin-lisp.asd` — add `src/networking/peerdb` component before `protocol`
- [ ] 1.4 Modify `handle-addr` in `src/networking/protocol.lisp` — feed parsed addresses into the address book instead of discarding them; filter by plausible timestamps (within 3 hours)
- [ ] 1.5 Modify `src/node.lisp` — load address book in `start-node`, save in `stop-node`, add warm-start logic to `connect-to-peers` (prefer address book, fall back to DNS), call success/failure tracking on handshake completion and connection failure

## 2. Tests

- [ ] 2.1 Create `tests/peerdb-tests.lisp` with the following test cases:
  - Create and populate address book
  - Add duplicate peer (update existing)
  - Score computation (reliable vs unreliable peers)
  - Score computation for untried peers (default 0.5 reliability)
  - Eviction when address book is full
  - Save and load round-trip (write then read back)
  - Reject corrupted file (bad CRC32)
  - Handle missing file gracefully
  - IPv4-to-mapped-IPv6 conversion
