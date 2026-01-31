# Change: Add SegWit witness data serialization

## Why
The serialization layer does not deserialize or serialize witness data (BIP 144). This means ~80% of modern Bitcoin transactions cannot be fully validated despite the Coalton script engine already supporting P2WPKH, P2WSH, Taproot, and BIP 143/341 sighash computation. The node also requests blocks using `MSG_BLOCK` instead of `MSG_WITNESS_BLOCK`, so peers may strip witness data before sending.

## What Changes
- Add `witness` field to the `transaction` struct (list of witness stacks, one per input)
- Implement BIP 144 serialized witness format: detect marker/flag bytes (`0x00 0x01`) after version, deserialize per-input witness stacks, serialize back with exact binary compatibility
- Compute `wtxid` (hash of witness-serialized transaction) separately from `txid` (hash of legacy serialization)
- Compute witness merkle root from wtxids for witness commitment validation
- Update `validate-block-scripts` to pass witness data to the existing Coalton `validate-witness-program` function instead of skipping witness programs
- Update `block-has-witness-data-p` to detect witness data on transactions
- Request blocks using `MSG_WITNESS_BLOCK` so peers send witness data
- Maintain backward compatibility: `transaction-hash` (txid) still uses legacy serialization; the new `transaction-wtxid` uses witness serialization

## Impact
- Affected specs: `serialization`, `validation`, `networking`
- Affected code:
  - `src/serialization/types.lisp` - transaction struct, read/write functions
  - `src/serialization/messages.lisp` - block/tx parsing from network
  - `src/validation/block.lisp` - witness validation, witness commitment
  - `src/networking/protocol.lisp` - block request type
  - `src/package.lisp` - new exports
