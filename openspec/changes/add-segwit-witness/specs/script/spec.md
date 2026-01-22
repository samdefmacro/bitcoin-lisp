## ADDED Requirements

### Requirement: Witness Program Detection
The system SHALL detect witness programs in scriptPubKey by checking:
- Length is between 4 and 42 bytes
- First byte is a valid version (0x00 for v0, 0x51-0x60 for v1-v16)
- Second byte is a direct push opcode matching remaining length

#### Scenario: Valid P2WPKH witness program
- **WHEN** scriptPubKey is `0x0014<20-byte-hash>`
- **THEN** system identifies it as witness v0 program with 20-byte program

#### Scenario: Valid P2WSH witness program
- **WHEN** scriptPubKey is `0x0020<32-byte-hash>`
- **THEN** system identifies it as witness v0 program with 32-byte program

#### Scenario: Invalid witness program length
- **WHEN** scriptPubKey is `0x0010<16-byte-data>`
- **THEN** system does not identify it as witness program (length not 20 or 32 for v0)

### Requirement: P2WPKH Validation
The system SHALL validate Pay-to-Witness-Public-Key-Hash scripts by:
1. Verifying witness has exactly 2 elements (signature, pubkey)
2. Constructing implicit script: `DUP HASH160 <program> EQUALVERIFY CHECKSIG`
3. Executing implicit script with witness stack as input
4. Using BIP 143 signature hash algorithm

#### Scenario: Valid P2WPKH spend
- **WHEN** scriptPubKey is `OP_0 <20-byte-keyhash>`
- **AND** witness contains `[<valid-signature> <compressed-pubkey>]`
- **AND** HASH160(pubkey) equals the 20-byte program
- **THEN** validation succeeds

#### Scenario: P2WPKH with wrong witness count
- **WHEN** scriptPubKey is `OP_0 <20-byte-keyhash>`
- **AND** witness contains only 1 element
- **THEN** validation fails with witness program witness empty error

### Requirement: P2WSH Validation
The system SHALL validate Pay-to-Witness-Script-Hash scripts by:
1. Taking the last witness element as witness script
2. Verifying SHA256(witness-script) equals the 32-byte program
3. Executing witness script with remaining witness elements as stack

#### Scenario: Valid P2WSH spend
- **WHEN** scriptPubKey is `OP_0 <32-byte-scripthash>`
- **AND** witness contains `[<args...> <witness-script>]`
- **AND** SHA256(witness-script) equals the 32-byte program
- **THEN** system executes witness-script with args on stack

#### Scenario: P2WSH hash mismatch
- **WHEN** scriptPubKey is `OP_0 <32-byte-scripthash>`
- **AND** SHA256(witness-script) does not equal the program
- **THEN** validation fails with witness program mismatch error

### Requirement: BIP 143 Signature Hash
The system SHALL implement BIP 143 signature hash algorithm for witness inputs:
1. Compute hashPrevouts = SHA256(SHA256(all input outpoints))
2. Compute hashSequence = SHA256(SHA256(all input sequences))
3. Compute hashOutputs = SHA256(SHA256(all outputs))
4. Serialize: version + hashPrevouts + hashSequence + outpoint + scriptCode + value + sequence + hashOutputs + locktime + sighash_type
5. Return SHA256(SHA256(serialized))

#### Scenario: BIP 143 sighash for P2WPKH
- **WHEN** computing sighash for witness v0 P2WPKH input
- **THEN** scriptCode is `0x1976a914<20-byte-keyhash>88ac` (implicit P2PKH)
- **AND** input value is included in hash preimage

#### Scenario: BIP 143 sighash for P2WSH
- **WHEN** computing sighash for witness v0 P2WSH input
- **THEN** scriptCode is the witness script with OP_CODESEPARATOR handling
- **AND** input value is included in hash preimage

### Requirement: Nested SegWit Support
The system SHALL support P2SH-wrapped witness programs:
1. Execute P2SH validation to unwrap redeemScript
2. If redeemScript is a witness program, validate as witness
3. Use witness stack for witness validation

#### Scenario: P2SH-P2WPKH validation
- **WHEN** scriptPubKey is P2SH pattern
- **AND** redeemScript is `OP_0 <20-byte-keyhash>`
- **THEN** system validates inner P2WPKH with witness stack

#### Scenario: P2SH-P2WSH validation
- **WHEN** scriptPubKey is P2SH pattern
- **AND** redeemScript is `OP_0 <32-byte-scripthash>`
- **THEN** system validates inner P2WSH with witness stack

### Requirement: Witness Malleability Checks
The system SHALL enforce witness malleability rules:
1. Native witness inputs MUST have empty scriptSig
2. Witness pubkeys MUST be compressed (33 bytes, starting with 0x02 or 0x03)
3. Witness signatures MUST be strict DER with low-S

#### Scenario: Native witness with non-empty scriptSig
- **WHEN** input spends native witness output (P2WPKH or P2WSH)
- **AND** scriptSig is not empty
- **THEN** validation fails with witness malleated error

#### Scenario: Uncompressed pubkey in witness
- **WHEN** P2WPKH witness contains uncompressed pubkey
- **THEN** validation fails with witness pubkey type error

### Requirement: Witness Version Handling
The system SHALL handle witness versions appropriately:
- Version 0: Validate as P2WPKH (20 bytes) or P2WSH (32 bytes)
- Versions 1-16: Reserved for future upgrades, treated as anyone-can-spend if not recognized

#### Scenario: Unknown witness version
- **WHEN** scriptPubKey has witness version > 0
- **AND** DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM flag is set
- **THEN** validation fails with discourage upgradable witness program error

#### Scenario: Unknown witness version without flag
- **WHEN** scriptPubKey has witness version > 0
- **AND** DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM flag is not set
- **THEN** validation succeeds (anyone-can-spend)

## MODIFIED Requirements

### Requirement: Script Execution with Witness
The system SHALL extend script execution to handle witness data:
1. Accept optional witness stack for input validation
2. Detect witness programs in scriptPubKey
3. Route to appropriate validator (legacy, P2WPKH, P2WSH)
4. Select correct sighash algorithm (legacy vs BIP 143)

#### Scenario: Legacy script execution unchanged
- **WHEN** scriptPubKey is not a witness program
- **AND** no witness data is present
- **THEN** execute using legacy flow (scriptSig + scriptPubKey)

#### Scenario: Native witness script execution
- **WHEN** scriptPubKey is a witness program
- **THEN** validate using witness stack and BIP 143 sighash
