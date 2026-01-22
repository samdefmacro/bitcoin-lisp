## ADDED Requirements

### Requirement: SegWit v1 (Taproot) Detection
The system SHALL detect and validate SegWit version 1 witness programs.

SegWit v1 programs:
- scriptPubKey format: `OP_1 <32-byte-program>`
- Version byte: 0x51 (OP_1)
- Program length: exactly 32 bytes

#### Scenario: Detect native Taproot output
- **GIVEN** a scriptPubKey of `0x51 0x20 <32-bytes>`
- **WHEN** checking for witness program
- **THEN** identifies as SegWit v1 with 32-byte program

#### Scenario: Reject wrong program length
- **GIVEN** a SegWit v1 scriptPubKey with program length not 32
- **WHEN** validating
- **THEN** returns `SE-WitnessProgramWrongLength` error

### Requirement: Taproot Key Path Spending
The system SHALL validate Taproot key path spends.

Key path spending:
- Witness: `[signature]` (single 64 or 65 byte Schnorr signature)
- The 32-byte witness program is the tweaked public key
- Signature validates against the tweaked key using BIP 341 sighash

#### Scenario: Valid key path spend
- **GIVEN** a Taproot output and witness with single valid Schnorr signature
- **WHEN** validating the spend
- **THEN** validation succeeds

#### Scenario: Key path with sighash type
- **GIVEN** a Taproot key path with 65-byte signature (64 + sighash byte)
- **WHEN** validating
- **THEN** uses the specified sighash type (not SIGHASH_DEFAULT)

#### Scenario: Invalid key path signature
- **GIVEN** a Taproot output with invalid signature in witness
- **WHEN** validating
- **THEN** returns `SE-TaprootInvalidSignature` error

### Requirement: Taproot Script Path Spending
The system SHALL validate Taproot script path spends with Merkle proofs.

Script path spending:
- Witness: `[script inputs...] <script> <control-block>`
- Control block: `<version-byte> <32-byte-internal-pubkey> <merkle-path...>`
- Version byte: leaf version (0xc0 for Tapscript) OR'd with parity bit
- Merkle path: concatenated 32-byte hashes

#### Scenario: Valid script path spend
- **GIVEN** a Taproot output, witness script, and valid control block
- **WHEN** the Merkle proof verifies and script execution succeeds
- **THEN** validation succeeds

#### Scenario: Invalid Merkle proof
- **GIVEN** a control block with incorrect Merkle path
- **WHEN** validating script path
- **THEN** returns `SE-TaprootMerkleMismatch` error

#### Scenario: Invalid control block structure
- **GIVEN** a control block with wrong length (not 33 + 32n bytes)
- **WHEN** parsing control block
- **THEN** returns `SE-TaprootInvalidControlBlock` error

### Requirement: BIP 341 Signature Hash
The system SHALL compute signature hashes according to BIP 341.

Signature hash components:
- Epoch (0x00)
- Hash type
- Transaction version
- Lock time
- `hash_prevouts`, `hash_amounts`, `hash_script_pubkeys`, `hash_sequences`, `hash_outputs`
- Spend type (key path or script path flags)
- Input-specific data
- For script path: `tapleaf_hash` and `key_version`

#### Scenario: Key path sighash
- **GIVEN** a Taproot key path spend with SIGHASH_DEFAULT
- **WHEN** computing signature hash
- **THEN** returns 32-byte hash per BIP 341 Annex G

#### Scenario: Script path sighash
- **GIVEN** a Tapscript spend
- **WHEN** computing signature hash
- **THEN** includes `tapleaf_hash` and `key_version` in the preimage

#### Scenario: SIGHASH_ANYONECANPAY
- **GIVEN** SIGHASH_ANYONECANPAY flag set
- **WHEN** computing Taproot sighash
- **THEN** omits `hash_prevouts`, `hash_amounts`, `hash_script_pubkeys`, `hash_sequences`

### Requirement: Tapscript Execution (BIP 342)
The system SHALL execute scripts in Tapscript context with modified rules.

Tapscript modifications:
- OP_CHECKSIGADD replaces OP_CHECKMULTISIG semantics
- OP_SUCCESSx opcodes (0x50, 0x62, 0x89-0xfe) make script succeed immediately
- Empty signature pushes 0, invalid signature causes failure
- MINIMALIF strictly requires 0x00 or 0x01

#### Scenario: Execute OP_CHECKSIGADD
- **GIVEN** stack `[n, pubkey, signature]` in Tapscript context
- **WHEN** executing OP_CHECKSIGADD
- **THEN** pushes `n+1` if signature valid, `n` if signature empty

#### Scenario: OP_SUCCESS makes script succeed
- **GIVEN** a Tapscript containing OP_SUCCESS80 (0x50)
- **WHEN** executing the script
- **THEN** script succeeds immediately regardless of other opcodes

#### Scenario: Disabled CHECKMULTISIG
- **GIVEN** a Tapscript containing OP_CHECKMULTISIG
- **WHEN** executing
- **THEN** returns `SE-TapscriptInvalidOpcode` error

#### Scenario: Invalid signature causes failure
- **GIVEN** a non-empty but invalid signature in Tapscript CHECKSIG
- **WHEN** executing
- **THEN** script fails (not just push false)

### Requirement: Taproot Error Types
The system SHALL define specific error types for Taproot validation failures.

Error types:
- `SE-TaprootInvalidSignature` - Schnorr signature verification failed
- `SE-TaprootInvalidControlBlock` - Malformed control block
- `SE-TaprootMerkleMismatch` - Merkle proof doesn't match output key
- `SE-TapscriptInvalidOpcode` - Disabled opcode in Tapscript context
- `SE-SchnorrSignatureSize` - Signature not 64 or 65 bytes

#### Scenario: Report Schnorr failure
- **WHEN** Schnorr verification fails
- **THEN** returns `SE-TaprootInvalidSignature` with context

#### Scenario: Report control block error
- **WHEN** control block parsing fails
- **THEN** returns `SE-TaprootInvalidControlBlock`
