# Tasks: Add Segregated Witness (SegWit) Support

## 1. Witness Program Detection
- [x] 1.1 Implement `is-witness-program` to detect witness scriptPubKey pattern
- [x] 1.2 Implement `get-witness-version` to extract version byte (0 for v0)
- [x] 1.3 Implement `get-witness-program` to extract program bytes
- [x] 1.4 Add witness program length validation (20 or 32 bytes for v0)

## 2. BIP 143 Signature Hash
- [x] 2.1 Implement `hash-prevouts` - double SHA256 of all input outpoints
- [x] 2.2 Implement `hash-sequence` - double SHA256 of all input sequences
- [x] 2.3 Implement `hash-outputs` - double SHA256 of all outputs
- [x] 2.4 Implement `bip143-sighash` main function with proper serialization order
- [x] 2.5 Handle SIGHASH_SINGLE and SIGHASH_NONE variants
- [x] 2.6 Handle SIGHASH_ANYONECANPAY modifier

## 3. P2WPKH Validation
- [x] 3.1 Implement `is-p2wpkh-program` (20-byte witness program detector)
- [x] 3.2 Implement `validate-p2wpkh-witness` - verify witness stack has 2 elements
- [x] 3.3 Generate implicit P2PKH script from witness program
- [x] 3.4 Execute implicit script with BIP 143 sighash
- [x] 3.5 Add WITNESS_PUBKEYTYPE validation for compressed pubkeys only

## 4. P2WSH Validation
- [x] 4.1 Implement `is-p2wsh-program` (32-byte witness program detector)
- [x] 4.2 Implement `validate-p2wsh-witness` - verify witness stack has witness script
- [x] 4.3 Verify SHA256(witness-script) matches program
- [x] 4.4 Execute witness script with remaining witness stack items
- [x] 4.5 Use BIP 143 sighash for CHECKSIG operations

## 5. Nested SegWit (P2SH-wrapped)
- [x] 5.1 Detect P2SH-P2WPKH pattern (redeemScript is witness program)
- [x] 5.2 Detect P2SH-P2WSH pattern
- [x] 5.3 Implement nested validation flow: P2SH unwrap -> witness validation
- [x] 5.4 Ensure proper script context for nested execution

## 6. Witness Stack Processing
- [x] 6.1 Add witness field to transaction input structure (if not present)
- [x] 6.2 Implement witness stack to script stack conversion
- [x] 6.3 Handle empty witness for non-witness inputs
- [x] 6.4 Add witness element size limits (max 520 bytes per element)

## 7. Script Execution Integration
- [x] 7.1 Modify `execute-scripts` to detect witness programs
- [x] 7.2 Route witness programs to appropriate validator (P2WPKH/P2WSH)
- [x] 7.3 Pass witness data through execution context
- [x] 7.4 Use correct sighash algorithm based on witness vs legacy

## 8. Error Handling
- [x] 8.1 Add `SE-WitnessProgramWrongLength` error
- [x] 8.2 Add `SE-WitnessProgramWitnessEmpty` error
- [x] 8.3 Add `SE-WitnessProgramMismatch` error (hash mismatch)
- [x] 8.4 Add `SE-WitnessUnexpected` error (witness for non-witness input)
- [x] 8.5 Add `SE-WitnessMalleated` error (non-empty scriptSig for native witness)

## 9. Test Runner Updates
- [x] 9.1 Enable WITNESS flag handling in test runner
- [x] 9.2 Parse witness data from test JSON format
- [x] 9.3 Pass witness stack to script validation
- [x] 9.4 Pass input amounts for BIP 143 sighash

## 10. Testing
- [x] 10.1 Enable the 23 skipped WITNESS tests
- [x] 10.2 Add unit tests for witness program detection
- [x] 10.3 Add unit tests for BIP 143 sighash computation
- [x] 10.4 Add integration tests for P2WPKH
- [x] 10.5 Add integration tests for P2WSH
- [x] 10.6 Add integration tests for nested P2SH-P2WPKH
- [x] 10.7 Verify all 1213 tests pass (1190 current + 23 WITNESS)
