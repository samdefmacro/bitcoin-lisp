## Context
The bitcoin-lisp node has two script execution paths:
1. **Coalton engine** (`src/coalton/script.lisp` + `src/coalton/interop.lisp`): Type-safe, full-featured, handles all 1,213 Bitcoin Core test vectors. Has proper sighash implementations for legacy, BIP 143 (SegWit), and BIP 341 (Taproot).
2. **CL validation layer** (`src/validation/script.lisp`): Simplified interpreter with a placeholder `compute-sighash`. Used by `validate-transaction-scripts` during mempool validation.

The critical finding: `validate-block` in `src/validation/block.lisp` calls `validate-transaction-structure` and `validate-transaction-contextual` but **never calls `validate-transaction-scripts`**. This means block connection skips script validation entirely -- invalid signatures are accepted.

The peer struct already has a `:banned` state and health-check infrastructure (`check-peer-health`, `record-block-timeout`), but no misbehavior scoring for protocol violations like invalid blocks or transactions.

The header index in `src/storage/chain.lisp` already uses a two-phase write pattern. The UTXO set in `src/storage/utxo.lisp` does not -- it writes directly with `:if-exists :supersede`. Neither file has checksums.

The mempool already enforces a 300MB size limit with fee-rate eviction (no changes needed there).

## Goals
- Make block validation execute transaction scripts via the Coalton engine
- Detect persistence corruption before it causes chain state divergence
- Ban peers that send invalid data using the existing peer state infrastructure
- Validate BIP 34 coinbase height and BIP 141 witness commitment

## Non-Goals
- Implementing RBF (BIP 125) -- policy, not consensus
- Full difficulty retarget validation -- separate proposal
- Mempool ancestor/descendant limits -- separate proposal
- Compact block relay (BIP 152) -- separate proposal

## Decisions

### 1. Block script validation approach
**Decision**: Add a call to the Coalton interop script execution from `validate-block`, using the `run-scripts-with-p2sh` or `validate-witness-program` functions already available in `src/coalton/interop.lisp`.

**Why not fix the CL script.lisp sighash?** The CL interpreter is incomplete in many ways beyond sighash. The Coalton engine already passes all 1,213 Bitcoin Core test vectors. Routing block validation through the Coalton engine is the correct fix.

**Approach**: Add a `validate-block-scripts` function that iterates non-coinbase transactions, looks up each input's UTXO, and dispatches to the Coalton interop for script execution. Call this from `validate-block` after contextual validation passes.

### 2. Persistence integrity
**Decision**: Use CRC32 checksums. Add atomic write-rename for UTXO set only (header index already has two-phase writes).

**Format change**:
```
[4 bytes: magic "UTXO" or "HIDX"]
[4 bytes: format version (1)]
[4 bytes: entry count]
[... entries ...]
[4 bytes: CRC32 of all preceding bytes]
```

**UTXO atomic write**: Write to `<path>.tmp`, then rename to `<path>`. On load, if the main file is missing but `.tmp` exists, warn and refuse to load (indicates interrupted write).

**Backward compatibility**: Detect old format (first 4 bytes won't match magic) and load using the existing parser, then save in new format on next flush.

**Alternatives considered**:
- SHA256 checksum: Overkill for integrity detection (not adversarial), CRC32 is fast and sufficient.
- WAL (write-ahead log): Too complex for current needs.

### 3. Peer misbehavior scoring
**Decision**: Extend the existing peer infrastructure with a misbehavior score.

Add `misbehavior-score` to the peer struct (alongside existing `consecutive-ping-failures` and `block-timeout-count`). Protocol violations increment the score:
- Invalid block header: +100 (immediate ban)
- Invalid block: +100 (immediate ban)
- Invalid transaction: +10

When score reaches 100, set peer state to `:banned` (already in the state enum) and add address to a `*banned-peers*` hash table with 24h expiry. The existing `is-banned-p` or similar check rejects connections from banned addresses.

### 4. Witness commitment validation
**Decision**: Check the last OP_RETURN output of the coinbase transaction for the witness commitment hash (BIP 141 commitment structure).

The commitment is: `OP_RETURN OP_PUSHBYTES_36 [4-byte header 0xaa21a9ed] [32-byte hash]`

The commitment hash is: `SHA256d(witness_root_hash || witness_reserved_value)`

Only required for blocks containing witness data.

### 5. BIP 34 coinbase height
**Decision**: For blocks at height >= 21,111 (testnet) / 227,931 (mainnet), validate that the coinbase scriptSig starts with a push of the block height encoded as little-endian bytes.

## Risks / Trade-offs
- **Persistence format change**: Existing files won't have magic/checksum. Mitigation: detect old format and convert on first save.
- **Block validation performance**: Adding script validation to block connection will slow IBD significantly. This is expected and correct -- skipping script validation was a bug, not an optimization.
