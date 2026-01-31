# Tasks: Add Extended RPC Methods

## Prerequisites

### 1. Implement Base58Check encoding/decoding
- [x] Create `src/crypto/address.lisp`
- [x] Implement Base58 alphabet encoding/decoding
- [x] Add checksum validation (double SHA256, first 4 bytes)
- [x] Support testnet prefixes: 0x6f (P2PKH), 0xc4 (P2SH)
- [x] Support mainnet prefixes: 0x00 (P2PKH), 0x05 (P2SH)
- [x] **Validation**: Unit tests for encode/decode round-trip, checksum validation

### 2. Implement Bech32/Bech32m encoding/decoding
- [x] Extend `src/crypto/address.lisp`
- [x] Implement Bech32 (BIP 173) for witness v0 (P2WPKH, P2WSH)
- [x] Implement Bech32m (BIP 350) for witness v1+ (P2TR)
- [x] Support HRPs: "tb" (testnet), "bc" (mainnet)
- [x] Parse witness version and program from address
- [x] **Validation**: Unit tests with BIP 173/350 test vectors

### 3. Implement script disassembly
- [x] Add opcode-to-name mapping in `src/validation/script.lisp`
- [x] Create `disassemble-script` function returning ASM string
- [x] Handle data pushes (show as hex), opcodes (show as names)
- [x] **Validation**: Unit tests for P2PKH, P2WPKH, multisig scripts

### 4. Implement script type classification
- [x] Add `classify-script` function in `src/validation/script.lisp`
- [x] Detect types: pubkeyhash, scripthash, witness_v0_keyhash, witness_v0_scripthash, witness_v1_taproot, multisig, nulldata, nonstandard
- [x] Extract pubkey hashes and witness programs where applicable
- [x] **Validation**: Unit tests for each script type

## RPC Method Implementation

### 5. Implement `decoderawtransaction`
- [x] Add `rpc-decoderawtransaction` function
- [x] Parse hex input to transaction struct (reuse existing deserializer)
- [x] Return full JSON representation (reuse existing `tx-to-json`)
- [x] Handle malformed hex input with error code -22
- [x] **Validation**: Unit test with valid/invalid hex inputs
- **Depends on**: None (uses existing infrastructure)

### 6. Implement `getrawtransaction` (Phase 1: mempool only)
- [x] Add `rpc-getrawtransaction` function
- [x] Look up transaction by txid in mempool
- [x] Support verbosity parameter (0=hex, 1=json)
- [x] Return error -5 for transactions not in mempool
- Note: Blockchain lookup deferred to Phase 2 (requires tx index)
- [x] **Validation**: Test fetching mempool tx, test not-found error
- **Depends on**: None

### 7. Implement `validateaddress`
- [x] Add `rpc-validateaddress` function
- [x] Parse address using Base58Check or Bech32/Bech32m decoders
- [x] Return isvalid, address, scriptPubKey, iswitness, witness_version, witness_program
- [x] Handle network mismatch (mainnet addr on testnet node → invalid)
- [x] **Validation**: Test valid/invalid addresses of each type
- **Depends on**: Tasks 1, 2

### 8. Implement `decodescript`
- [x] Add `rpc-decodescript` function
- [x] Parse hex script bytes
- [x] Return asm (disassembly), type, p2sh address, segwit address
- [x] **Validation**: Test with various script types
- **Depends on**: Tasks 1, 2, 3, 4

### 9. Implement `createrawtransaction`
- [x] Add `rpc-createrawtransaction` function
- [x] Accept inputs as `[{"txid": "...", "vout": N, "sequence": N}, ...]`
- [x] Accept outputs as `{"address": amount, ...}`
- [x] Decode addresses to scriptPubKey using address decoders
- [x] Build unsigned transaction with empty scriptSigs
- [x] Return hex-encoded transaction
- [x] **Validation**: Test creating transaction, verify it decodes correctly
- **Depends on**: Tasks 1, 2

### 10. Implement `estimatesmartfee` (simplified)
- [x] Add `rpc-estimatesmartfee` function
- [x] Accept conf_target parameter (validate 1-1008)
- [x] Return fixed conservative fee rate (e.g., 0.00001 BTC/kvB for testnet)
- [x] Return error if node is still in IBD
- Note: Proper fee estimation deferred to Phase 2
- [x] **Validation**: Test returns estimate, test IBD error
- **Depends on**: None

### 11. Register new methods in RPC server
- [x] Add all 6 methods to method dispatch table in `src/rpc/server.lisp`
- [x] **Validation**: Verify methods are callable via curl
- **Depends on**: Tasks 5-10

### 12. Add RPC integration tests
- [x] Add test cases in `tests/rpc-tests.lisp` for all new methods
- [x] Cover success paths and error handling
- [x] **Validation**: All tests pass
- **Depends on**: Task 11

## Dependency Graph

```
[1: Base58] ──┬──→ [7: validateaddress] ──┐
              │                            │
[2: Bech32] ──┼──→ [8: decodescript] ─────┼──→ [11: Register] ──→ [12: Tests]
              │                            │
[3: Disasm] ──┤                            │
              │                            │
[4: Classify]─┘    [9: createrawtx] ──────┤
                                           │
               [5: decoderawtx] ──────────┤
                                           │
               [6: getrawtx] ─────────────┤
                                           │
               [10: estimatefee] ─────────┘
```

All tasks completed.
