## 1. Add witness data to transaction struct and serialization
- [x] 1.1 Add `witness` slot to `transaction` struct (list of witness stacks, one per input; each stack is a list of byte vectors)
- [x] 1.2 Implement `read-witness-transaction` that detects BIP 144 marker/flag (0x00 0x01) after version, reads inputs, outputs, per-input witness stacks, and lock-time
- [x] 1.3 Update `read-transaction` to auto-detect witness format and dispatch accordingly
- [x] 1.4 Implement `write-witness-transaction` that writes BIP 144 format (version + marker + flag + inputs + outputs + witness + lock-time)
- [x] 1.5 Implement `serialize-witness-transaction` returning the witness-format byte vector
- [x] 1.6 Implement `transaction-wtxid` computing double-SHA256 of witness serialization (returns all-zeros for coinbase)
- [x] 1.7 Ensure `transaction-hash` (txid) still uses legacy serialization (no witness data)
- [x] 1.8 Add `transaction-has-witness-p` predicate
- [x] 1.9 Export new symbols from package: `transaction-witness`, `transaction-wtxid`, `transaction-has-witness-p`, `serialize-witness-transaction`, `read-transaction`
- [x] 1.10 Clear FASL cache after struct change to avoid redefinition errors

## 2. Add witness serialization tests
- [x] 2.1 Test round-trip: deserialize a known BIP 144 witness transaction from hex, verify fields, serialize back, compare bytes
- [x] 2.2 Test txid vs wtxid: verify txid excludes witness, wtxid includes witness, both computed correctly for a known transaction
- [x] 2.3 Test legacy transaction: verify old format still deserializes correctly (no marker/flag)
- [x] 2.4 Test coinbase wtxid: verify coinbase wtxid is all zeros
- [x] 2.5 Test witness stack parsing: verify correct number of stack items per input with correct byte content

## 3. Update block parsing to preserve witness data
- [x] 3.1 Update `read-bitcoin-block` / `parse-block-payload` to use witness-aware transaction reading
- [x] 3.2 Update `parse-tx-payload` to use witness-aware transaction reading
- [x] 3.3 Verify existing block deserialization still works for non-witness blocks

## 4. Request witness blocks from peers
- [x] 4.1 Change `request-blocks` in protocol.lisp to use `+inv-type-witness-block+` instead of `+inv-type-block+`
- [x] 4.2 Change transaction relay to use `+inv-type-witness-tx+` for getdata requests when fetching announced transactions

## 5. Wire witness data into block validation
- [x] 5.1 Update `block-has-witness-data-p` to check `transaction-has-witness-p` on block transactions
- [x] 5.2 Update `validate-block-scripts` to pass witness stack to `validate-witness-program` for witness program inputs instead of skipping them
- [x] 5.3 Implement `compute-witness-merkle-root` using wtxids (coinbase wtxid = all zeros)
- [x] 5.4 Update `validate-witness-commitment` to compute and verify the witness merkle root against the coinbase commitment
- [x] 5.5 Export new symbols: `compute-witness-merkle-root`

## 6. Add witness validation tests
- [x] 6.1 Test that a block with witness transactions has `block-has-witness-data-p` return T
- [x] 6.2 Test witness merkle root computation against known block data
- [x] 6.3 Test that `validate-block-scripts` now calls witness validation for P2WPKH/P2WSH inputs (not just skips them)
- [x] 6.4 Test witness commitment validation with matching/mismatching commitment
