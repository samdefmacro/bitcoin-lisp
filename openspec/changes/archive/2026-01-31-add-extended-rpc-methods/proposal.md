# Proposal: Add Extended RPC Methods

## Summary
Add additional Bitcoin Core-compatible RPC methods for working with raw transactions, fee estimation, and address/script utilities.

## Motivation
The current RPC implementation provides blockchain query, UTXO lookup, network info, and mempool methods. To be more useful for external tools and wallets, the node should also support:

1. **Raw Transaction Methods** - Allow clients to fetch, decode, and construct raw transactions without needing a wallet
2. **Fee Estimation** - Provide fee rate estimates for transaction construction
3. **Address/Script Utilities** - Validate addresses and decode scripts for debugging and verification

## Scope
This proposal adds 6 new RPC methods to the existing `rpc` capability:

| Method | Description |
|--------|-------------|
| `getrawtransaction` | Fetch raw transaction by txid from mempool (Phase 1) or blockchain (Phase 2) |
| `decoderawtransaction` | Parse hex transaction and return JSON structure |
| `createrawtransaction` | Build unsigned transaction from inputs/outputs |
| `estimatesmartfee` | Estimate fee rate for confirmation target (simplified heuristic) |
| `validateaddress` | Check if address is valid and return metadata |
| `decodescript` | Parse hex script and return opcodes/type |

## Out of Scope
- Wallet functionality (signing, key management)
- `signrawtransaction` (requires wallet)
- Advanced fee estimation using mempool analysis

## Implementation Notes

### New Infrastructure Required

**Address Encoding** (new module `src/crypto/address.lisp`):
- Base58Check encoding/decoding for P2PKH and P2SH addresses
- Bech32 encoding/decoding for P2WPKH and P2WSH (BIP 173)
- Bech32m encoding/decoding for P2TR (BIP 350)

**Script Disassembly** (extend `src/validation/script.lisp`):
- Opcode-to-name reverse mapping
- `disassemble-script` function returning ASM string
- Script type classification (P2PKH, P2SH, P2WPKH, etc.)

**Transaction Index** (Phase 2, extend `src/storage/`):
- Index mapping txid → block hash for confirmed transactions
- Required for `getrawtransaction` to find blockchain transactions

### Phased Delivery

**Phase 1** (this proposal):
- All 6 RPC methods implemented
- `getrawtransaction` searches mempool only; returns error for confirmed txs
- `estimatesmartfee` returns conservative fixed estimate

**Phase 2** (future work):
- Transaction index for blockchain lookups
- Fee tracking per block for better estimation

## Dependencies
- Existing serialization infrastructure for transaction parsing
- Existing script module for opcode constants
- Chain state for network detection
