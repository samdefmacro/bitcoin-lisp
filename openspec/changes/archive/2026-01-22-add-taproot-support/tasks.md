# Tasks: Add Taproot Support (BIP 340-342)

## 1. Schnorr Signatures (BIP 340)
- [x] 1.1 Implement x-only public key type (32 bytes, implicit even Y)
- [x] 1.2 Implement `lift-x` to recover full public key from x-coordinate
- [x] 1.3 Implement tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || data)`
- [x] 1.4 Implement `hash-aux` for auxiliary randomness
- [x] 1.5 Implement `hash-challenge` for Schnorr challenge computation
- [x] 1.6 Implement Schnorr signature verification (64-byte signatures)
- [x] 1.7 Add unit tests for Schnorr verification with BIP 340 test vectors

## 2. Taproot Key Path (BIP 341)
- [x] 2.1 Implement SegWit v1 witness program detection (version byte 0x51)
- [x] 2.2 Implement `taproot-tweak-pubkey` for key tweaking with Merkle root
- [x] 2.3 Implement BIP 341 signature hash algorithm (`SigMsg` serialization)
- [x] 2.4 Implement key path spending validation (witness = [signature])
- [x] 2.5 Handle SIGHASH_DEFAULT (0x00) for Taproot
- [x] 2.6 Add epoch byte (0x00) to signature hash message

## 3. Taproot Script Path (BIP 341)
- [x] 3.1 Implement control block parsing (version, internal pubkey, Merkle path)
- [x] 3.2 Implement `taproot-tweak-verify` to verify Merkle inclusion
- [x] 3.3 Implement Merkle branch verification (`TapBranch` hashing)
- [x] 3.4 Implement script path spending validation
- [x] 3.5 Extract leaf version from control block
- [x] 3.6 Compute `TapLeaf` hash for script execution

## 4. Tapscript Validation (BIP 342)
- [x] 4.1 Implement OP_CHECKSIGADD (pops n, pubkey, sig; pushes n or n+1)
- [x] 4.2 Add signature hash extension for Tapscript (`ext` field)
- [x] 4.3 Implement `tapleaf-hash` in signature message
- [x] 4.4 Handle OP_SUCCESS opcodes (0x50, 0x62, 0x89-0xfe make script succeed)
- [x] 4.5 Implement upgraded CHECKSIG semantics (empty sig = 0, invalid sig = failure)
- [x] 4.6 Disable OP_CHECKMULTISIG/OP_CHECKMULTISIGVERIFY in Tapscript
- [x] 4.7 Remove MINIMALIF exception in Tapscript (strict 0/1 requirement)

## 5. Signature Hash (BIP 341 Annex G)
- [x] 5.1 Implement `hash-amounts` (SHA256 of all input amounts)
- [x] 5.2 Implement `hash-script-pubkeys` (SHA256 of all input scriptPubKeys)
- [x] 5.3 Implement `SigMsg` construction with all components
- [x] 5.4 Handle `annex` field in witness (0x50 prefix, for future extensions)
- [x] 5.5 Handle SIGHASH_SINGLE, SIGHASH_NONE, SIGHASH_ANYONECANPAY for Taproot

## 6. Error Handling
- [x] 6.1 Add `SE-TaprootInvalidSignature` error
- [x] 6.2 Add `SE-TaprootInvalidControlBlock` error
- [x] 6.3 Add `SE-TaprootMerkleMismatch` error
- [x] 6.4 Add `SE-TapscriptInvalidOpcode` error (for disabled ops)
- [x] 6.5 Add `SE-SchnorrSignatureSize` error (must be 64 or 65 bytes)

## 7. Integration
- [x] 7.1 Update `execute-scripts` to route v1 witness programs to Taproot validation
- [x] 7.2 Update test runner to handle TAPROOT flag
- [x] 7.3 Pass script execution flags to distinguish Tapscript context

## 8. Testing
- [x] 8.1 Add unit tests for tagged hash functions
- [x] 8.2 Add unit tests for control block parsing
- [x] 8.3 Add unit tests for Taproot key path spending
- [x] 8.4 Add unit tests for Taproot script path spending
- [x] 8.5 Add unit tests for OP_CHECKSIGADD
- [x] 8.6 Enable Bitcoin Core Taproot test vectors
- [x] 8.7 Verify all tests pass
