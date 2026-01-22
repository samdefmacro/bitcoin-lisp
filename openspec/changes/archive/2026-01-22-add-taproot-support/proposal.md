# Change: Add Taproot Support (BIP 340-342)

## Why
Taproot is Bitcoin's most significant upgrade since SegWit, enabling more efficient and private smart contracts. BIP 340 introduces Schnorr signatures (smaller, faster, batch-verifiable), BIP 341 defines SegWit version 1 spending rules with key path and script path spending, and BIP 342 introduces Tapscript with improved script semantics. Supporting Taproot is essential for a complete Bitcoin Script implementation.

## What Changes
- Add Schnorr signature verification on secp256k1 (BIP 340)
- Add x-only public key (32-byte) support
- Add tagged hash functions (BIP 340)
- Implement SegWit v1 witness program detection
- Implement Taproot key path spending (single Schnorr signature)
- Implement Taproot script path spending with control blocks and Merkle proofs
- Add BIP 341 signature hash algorithm (different from BIP 143)
- Add OP_CHECKSIGADD for Tapscript (replaces CHECKMULTISIG)
- Add Tapscript-specific validation rules (BIP 342)
- Add success opcodes handling (OP_SUCCESSx)

## Impact
- Affected specs: `script`, `crypto`
- Affected code: `src/coalton/script.lisp`, `src/coalton/interop.lisp`, `src/crypto/secp256k1.lisp`
- Tests: Enable additional Bitcoin Core tests with TAPROOT flag
