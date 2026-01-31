## Context

The Coalton script engine already validates witness programs (P2WPKH, P2WSH, Taproot) and computes BIP 143/341 sighash. The missing piece is the serialization layer: the `transaction` struct has no witness fields, and the wire format reader ignores the BIP 144 marker/flag bytes. This means witness data is silently discarded during deserialization, and `validate-block-scripts` skips all witness program inputs.

### Current state
- `transaction` struct: version, inputs, outputs, lock-time, cached-hash
- `read-transaction`: reads version, inputs, outputs, lock-time (no witness)
- `transaction-hash` (txid): double-SHA256 of legacy serialization
- `validate-block-scripts`: skips inputs where scriptPubKey is a witness program
- `request-blocks`: uses `+inv-type-block+` (peers may strip witness data)
- `validate-witness-commitment`: infrastructure exists but `block-has-witness-data-p` always returns NIL

## Goals / Non-Goals

### Goals
- Deserialize and serialize BIP 144 witness transactions with binary compatibility
- Compute wtxid (witness txid) for witness commitment validation
- Wire witness stacks through to the existing Coalton `validate-witness-program` function
- Request witness blocks from peers
- Validate witness commitments in coinbase

### Non-Goals
- Adding new Coalton validation code (already exists)
- Implementing compact blocks (BIP 152)
- Weight/vsize calculation (future work)
- Fee-rate computation based on weight (future work)

## Decisions

### Decision: Add witness as a slot on `transaction`, not on `tx-in`
Bitcoin Core stores witness per-input, but in the serialization format the witness section is a separate block after all outputs. Storing it as a list-of-lists on `transaction` (parallel to inputs) is simpler and matches the wire format structure. Each element is a list of byte vectors (the witness stack items for that input).

**Alternatives considered:**
- Adding `witness-stack` slot to `tx-in`: More natural semantically but complicates struct redefinition (tx-in is used everywhere) and doesn't match wire format grouping.

### Decision: Preserve `transaction-hash` as legacy txid
The existing `transaction-hash` function computes txid (legacy serialization, no witness). This is correct per BIP 141: txid excludes witness data. A new function `transaction-wtxid` will compute the witness-inclusive hash. For coinbase transactions, wtxid is defined as all zeros.

### Decision: Auto-detect witness format on deserialization
BIP 144 uses a marker byte (0x00) after version where the input count would normally be. If the first byte after version is 0x00 and the next byte is 0x01 (flag), it's a witness transaction. Otherwise fall back to legacy parsing. This is the same detection approach used by Bitcoin Core.

### Decision: Use `MSG_WITNESS_BLOCK` for block requests
Change `request-blocks` to use `+inv-type-witness-block+` instead of `+inv-type-block+`. This signals to peers that we want witness data included. Peers that don't support witness will ignore the flag bit.

## Risks / Trade-offs

- **Struct redefinition**: Adding a `witness` slot to `transaction` will require clearing FASL cache (same issue resolved during the hardening proposal). Mitigation: document in tasks.
- **Memory increase**: Witness data adds memory per transaction. For a typical SegWit transaction, witness is ~100-200 bytes. This is acceptable for the in-memory UTXO/block processing model.
- **Backward compatibility**: Old persisted blocks (stored without witness) will load with nil witness. The code must handle nil witness gracefully.

## Open Questions
None - the wire format is well-specified by BIP 144 and the validation code already exists in Coalton.
