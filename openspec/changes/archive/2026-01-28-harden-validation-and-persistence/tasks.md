## 1. Add block script validation via Coalton interop
- [x] 1.1 Implement `validate-block-scripts` in `src/validation/block.lisp` that iterates non-coinbase transactions, looks up each input's UTXO, and calls Coalton interop for script execution
- [x] 1.2 Dispatch to `run-scripts-with-p2sh` for legacy/P2SH, `validate-witness-program` for SegWit v0, and `validate-taproot` for P2TR based on the UTXO's scriptPubKey pattern
- [x] 1.3 Call `validate-block-scripts` from `validate-block` after contextual validation passes
- [x] 1.4 Add tests verifying that blocks with invalid signatures are rejected

## 2. Add witness commitment validation
- [x] 2.1 Implement `compute-witness-merkle-root` to compute the merkle root of witness txids
- [x] 2.2 Implement `find-witness-commitment` to locate the commitment in the coinbase OP_RETURN outputs (scan for 0xaa21a9ed header)
- [x] 2.3 Add commitment validation to `validate-block` for blocks with witness data
- [x] 2.4 Add tests for blocks with valid/invalid/missing witness commitments

## 3. Add persistence integrity checks
- [x] 3.1 Add CRC32 computation utility (using ironclad or manual implementation)
- [x] 3.2 Update `save-utxo-set` to write magic bytes, version, and CRC32 checksum; use atomic write-rename
- [x] 3.3 Update `load-utxo-set` to verify magic, version, and CRC32; reject corrupted files
- [x] 3.4 Update header index save/load to write and verify magic bytes, version, and CRC32 checksum (keep existing two-phase write pattern)
- [x] 3.5 Add backward compatibility: detect old format files (no magic bytes) and load using existing parser
- [x] 3.6 Add tests for corrupted files (truncated, bad checksum, bad magic, bad version)
- [x] 3.7 Add tests for UTXO atomic write recovery (`.tmp` file exists but main file doesn't)

## 4. Add peer misbehavior scoring
- [x] 4.1 Add `misbehavior-score` field to peer struct and `*banned-peers*` hash table (address -> expiry time)
- [x] 4.2 Add `record-misbehavior` function that increments score and sets peer state to `:banned` at threshold
- [x] 4.3 Add `peer-banned-p` check in peer connection establishment, rejecting banned addresses
- [x] 4.4 Call `record-misbehavior` from protocol handlers when receiving invalid blocks, headers, or transactions
- [x] 4.5 Add tests for ban scoring, threshold triggering, and expiry

## 5. Add BIP 34 coinbase height validation
- [x] 5.1 Implement `decode-coinbase-height` to extract height from coinbase scriptSig
- [x] 5.2 Add height validation to `validate-block` for blocks at/above activation height (21,111 testnet, 227,931 mainnet)
- [x] 5.3 Add tests with valid and invalid coinbase height encodings

## 6. Add reorg and persistence edge-case tests
- [x] 6.1 Test multi-block reorg (3+ blocks deep)
- [x] 6.2 Test reorg when undo data is missing (should fail gracefully, not corrupt state)
- [x] 6.3 Test persistence round-trip after reorg (save, load, verify chain state consistent)
- [x] 6.4 Test UTXO set consistency after save/load cycle during sync
