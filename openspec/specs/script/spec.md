# script Specification

## Purpose
TBD - created by archiving change add-script-operations. Update Purpose after archive.
## Requirements
### Requirement: Typed Opcode Definitions
The system SHALL define Bitcoin script opcodes as a Coalton algebraic data type with compile-time type safety.

The opcode type SHALL include:
- Push operations (OP_0, OP_1-16, OP_PUSHBYTES, OP_PUSHDATA)
- Stack operations (OP_DUP, OP_DROP, OP_SWAP, OP_ROT, etc.)
- Arithmetic operations (OP_ADD, OP_SUB, OP_NEGATE, etc.)
- Comparison operations (OP_EQUAL, OP_LESSTHAN, etc.)
- Crypto operations (OP_HASH160, OP_HASH256, OP_CHECKSIG)
- Flow control (OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY, OP_RETURN)
- Unknown opcode variant for forward compatibility

#### Scenario: Parse known opcode
- **GIVEN** the byte value 0x76 (OP_DUP)
- **WHEN** parsing to Opcode type
- **THEN** returns `OP-DUP` variant

#### Scenario: Parse unknown opcode
- **GIVEN** an unassigned opcode byte value
- **WHEN** parsing to Opcode type
- **THEN** returns `OP-UNKNOWN` variant with the byte value

### Requirement: Type-Safe Script Stack
The system SHALL provide typed stack operations for script execution.

Stack operations SHALL include:
- `stack-push`: Add value to top of stack
- `stack-pop`: Remove and return top value (returns Option)
- `stack-top`: Peek at top value without removing
- `stack-depth`: Return number of items on stack
- Multi-element operations (2dup, 2drop, 2swap, etc.)

#### Scenario: Stack underflow handling
- **GIVEN** an empty script stack
- **WHEN** attempting to pop a value
- **THEN** returns None (not a runtime error)

#### Scenario: Type-safe push and pop
- **GIVEN** a byte vector pushed onto the stack
- **WHEN** popping from the stack
- **THEN** returns the same byte vector with correct type

### Requirement: Script Value Conversions
The system SHALL provide typed conversions between bytes and script numbers.

Conversions SHALL handle:
- Little-endian encoding
- Sign bit in most significant byte
- Minimal encoding (no unnecessary leading zeros)
- 4-byte maximum for arithmetic operations

#### Scenario: Convert positive number to bytes
- **GIVEN** the script number 127
- **WHEN** converting to bytes
- **THEN** returns `#(127)` (single byte, no sign bit needed)

#### Scenario: Convert negative number to bytes
- **GIVEN** the script number -1
- **WHEN** converting to bytes
- **THEN** returns `#(129)` (0x81 = 1 with sign bit set)

#### Scenario: Convert bytes to number with sign
- **GIVEN** the bytes `#(129)` (0x81)
- **WHEN** converting to script number
- **THEN** returns -1

### Requirement: Script Execution Context
The system SHALL maintain typed execution context during script evaluation.

Context SHALL include:
- Main stack (List of byte vectors)
- Alt stack for OP_TOALTSTACK/OP_FROMALTSTACK
- Current script and position
- Condition stack for IF/ELSE nesting
- Transaction reference for CHECKSIG
- Input index being validated
- Script verification flags
- Transaction locktime (nLockTime) for CHECKLOCKTIMEVERIFY
- Transaction version for CHECKSEQUENCEVERIFY
- Input sequence number (nSequence) for CHECKSEQUENCEVERIFY

#### Scenario: Track execution position
- **GIVEN** a script context at position 0
- **WHEN** reading a 1-byte opcode
- **THEN** position advances to 1

#### Scenario: Nested conditional execution
- **GIVEN** a script with `OP_IF OP_IF ... OP_ENDIF OP_ENDIF`
- **WHEN** executing the script
- **THEN** the condition stack correctly tracks nesting depth

#### Scenario: Transaction context available for locktime opcodes
- **GIVEN** a script context created with transaction nLockTime=600000, version=2, and input nSequence=10
- **WHEN** executing OP_CHECKLOCKTIMEVERIFY or OP_CHECKSEQUENCEVERIFY
- **THEN** the opcodes can access the transaction locktime, version, and sequence values from the context

### Requirement: Crypto Opcode Integration
The system SHALL execute crypto opcodes using the typed Coalton crypto module.

Integration SHALL ensure:
- OP_HASH160 uses `compute-hash160` returning `Hash160`
- OP_HASH256 uses `compute-hash256` returning `Hash256`
- OP_SHA256 uses `compute-sha256`
- OP_CHECKSIG uses typed signature verification

#### Scenario: Execute OP_HASH160
- **GIVEN** a stack with a public key (33 or 65 bytes)
- **WHEN** executing OP_HASH160
- **THEN** the public key is replaced with its 20-byte hash

#### Scenario: Execute OP_CHECKSIG with valid signature
- **GIVEN** a stack with [signature, pubkey] and valid transaction context
- **WHEN** executing OP_CHECKSIG
- **THEN** pushes true (0x01) if signature is valid

### Requirement: Script Execution Result
The system SHALL return typed results from script execution.

Results SHALL be either:
- Success with final stack state
- Failure with typed error (StackUnderflow, VerifyFailed, etc.)

#### Scenario: Successful script execution
- **GIVEN** a valid P2PKH script with correct signature
- **WHEN** executing scriptSig + scriptPubKey
- **THEN** returns Success with non-empty true value on stack

#### Scenario: Failed verification
- **GIVEN** a script where OP_VERIFY encounters false
- **WHEN** executing the script
- **THEN** returns Failure with VerifyFailed error

### Requirement: P2PKH Validation
The system SHALL validate Pay-to-Public-Key-Hash scripts.

P2PKH scriptPubKey format: `OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG`
P2PKH scriptSig format: `<signature> <pubkey>`

#### Scenario: Valid P2PKH spend
- **GIVEN** a P2PKH output and matching signature/pubkey
- **WHEN** validating the transaction input
- **THEN** validation succeeds

#### Scenario: Wrong pubkey hash
- **GIVEN** a P2PKH output and pubkey that hashes to different value
- **WHEN** validating the transaction input
- **THEN** validation fails at OP_EQUALVERIFY

### Requirement: P2SH Validation
The system SHALL validate Pay-to-Script-Hash scripts.

P2SH scriptPubKey format: `OP_HASH160 <20-byte-hash> OP_EQUAL`
P2SH scriptSig format: `<data...> <serialized-script>`

The system SHALL:
- Verify the serialized script hashes to the expected value
- Execute the serialized script with remaining stack items

#### Scenario: Valid P2SH spend
- **GIVEN** a P2SH output and correct redeem script
- **WHEN** validating the transaction input
- **THEN** the redeem script is executed and validation succeeds

#### Scenario: Wrong redeem script hash
- **GIVEN** a P2SH output and redeem script with wrong hash
- **WHEN** validating the transaction input
- **THEN** validation fails before executing the redeem script

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

### Requirement: OP_CHECKLOCKTIMEVERIFY (BIP 65)
The system SHALL validate OP_CHECKLOCKTIMEVERIFY by comparing the stack top against the spending transaction's nLockTime.

When the CHECKLOCKTIMEVERIFY flag is enabled:
1. The stack MUST NOT be empty
2. The stack top value MUST be interpreted as a 5-byte script number (not the default 4-byte arithmetic limit) and MUST be non-negative
3. The stack top and nLockTime MUST be the same type:
   - Height-based: value < 500,000,000
   - Time-based: value >= 500,000,000
4. The stack top value MUST be <= nLockTime
5. The input's nSequence MUST NOT be 0xFFFFFFFF (which disables locktime)

The opcode SHALL NOT pop the stack value.

When the CHECKLOCKTIMEVERIFY flag is not enabled, the opcode SHALL be treated as OP_NOP2 (no operation).

#### Scenario: Valid height-based CLTV
- **GIVEN** a script with `<400000> OP_CHECKLOCKTIMEVERIFY` and transaction nLockTime=500000
- **WHEN** executing the script with CHECKLOCKTIMEVERIFY flag enabled
- **THEN** validation succeeds and 400000 remains on the stack

#### Scenario: Valid time-based CLTV
- **GIVEN** a script with `<1600000000> OP_CHECKLOCKTIMEVERIFY` and transaction nLockTime=1700000000
- **WHEN** executing the script with CHECKLOCKTIMEVERIFY flag enabled
- **THEN** validation succeeds

#### Scenario: CLTV type mismatch fails
- **GIVEN** a script with `<400000> OP_CHECKLOCKTIMEVERIFY` (height-based) and transaction nLockTime=1600000000 (time-based)
- **WHEN** executing the script with CHECKLOCKTIMEVERIFY flag enabled
- **THEN** validation fails with unsatisfied locktime error

#### Scenario: CLTV with future locktime fails
- **GIVEN** a script with `<600000> OP_CHECKLOCKTIMEVERIFY` and transaction nLockTime=500000
- **WHEN** executing the script with CHECKLOCKTIMEVERIFY flag enabled
- **THEN** validation fails because stack top > nLockTime

#### Scenario: CLTV with sequence 0xFFFFFFFF fails
- **GIVEN** a script with `<400000> OP_CHECKLOCKTIMEVERIFY` and input nSequence=0xFFFFFFFF
- **WHEN** executing the script with CHECKLOCKTIMEVERIFY flag enabled
- **THEN** validation fails because locktime is disabled for this input

#### Scenario: CLTV with negative value fails
- **GIVEN** a script with `<-1> OP_CHECKLOCKTIMEVERIFY`
- **WHEN** executing the script with CHECKLOCKTIMEVERIFY flag enabled
- **THEN** validation fails with negative locktime error

#### Scenario: CLTV treated as NOP when flag disabled
- **GIVEN** a script with `<400000> OP_CHECKLOCKTIMEVERIFY` and CHECKLOCKTIMEVERIFY flag NOT enabled
- **WHEN** executing the script
- **THEN** the opcode is treated as NOP and execution continues

### Requirement: OP_CHECKSEQUENCEVERIFY (BIP 112)
The system SHALL validate OP_CHECKSEQUENCEVERIFY by comparing the stack top against the spending input's nSequence.

When the CHECKSEQUENCEVERIFY flag is enabled:
1. The stack MUST NOT be empty
2. The stack top value MUST be interpreted as a 5-byte script number (not the default 4-byte arithmetic limit) and MUST be non-negative
3. If the stack top bit 31 (0x80000000) is set, treat as NOP (disabled)
4. The transaction version MUST be >= 2 (otherwise fail)
5. The input's nSequence bit 31 (disable flag) MUST NOT be set
6. Both values MUST be masked with 0x0040FFFF (SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK). The type flags (bit 22) MUST match:
   - Bit 22 = 0: height-based (lower 16 bits = number of blocks)
   - Bit 22 = 1: time-based (lower 16 bits = multiples of 512 seconds)
7. The stack top masked value (& 0x0040FFFF) MUST be <= nSequence masked value (& 0x0040FFFF)

The opcode SHALL NOT pop the stack value.

When the CHECKSEQUENCEVERIFY flag is not enabled, the opcode SHALL be treated as OP_NOP3 (no operation).

#### Scenario: Valid height-based CSV
- **GIVEN** a script with `<10> OP_CHECKSEQUENCEVERIFY`, tx version=2, and input nSequence=15
- **WHEN** executing the script with CHECKSEQUENCEVERIFY flag enabled
- **THEN** validation succeeds (10 <= 15 blocks of relative height)

#### Scenario: Valid time-based CSV
- **GIVEN** a script with `<0x400005> OP_CHECKSEQUENCEVERIFY` (bit 22 set, 5 units), tx version=2, and input nSequence=0x40000A (bit 22 set, 10 units)
- **WHEN** executing the script with CHECKSEQUENCEVERIFY flag enabled
- **THEN** validation succeeds (5 <= 10 time units)

#### Scenario: CSV with tx version 1 fails
- **GIVEN** a script with `<10> OP_CHECKSEQUENCEVERIFY` and tx version=1
- **WHEN** executing the script with CHECKSEQUENCEVERIFY flag enabled
- **THEN** validation fails because tx version < 2

#### Scenario: CSV with disabled stack value passes
- **GIVEN** a script with `<0x80000001> OP_CHECKSEQUENCEVERIFY` (bit 31 set)
- **WHEN** executing the script with CHECKSEQUENCEVERIFY flag enabled
- **THEN** validation succeeds (disable flag means treat as NOP)

#### Scenario: CSV with disabled input sequence fails
- **GIVEN** a script with `<10> OP_CHECKSEQUENCEVERIFY`, tx version=2, and input nSequence=0xFFFFFFFF (bit 31 set)
- **WHEN** executing the script with CHECKSEQUENCEVERIFY flag enabled
- **THEN** validation fails because input sequence has disable flag set

#### Scenario: CSV type mismatch fails
- **GIVEN** a script with `<10> OP_CHECKSEQUENCEVERIFY` (height-based, bit 22=0) and input nSequence=0x400010 (time-based, bit 22=1)
- **WHEN** executing the script with CHECKSEQUENCEVERIFY flag enabled
- **THEN** validation fails because type flags do not match

#### Scenario: CSV with negative value fails
- **GIVEN** a script with `<-1> OP_CHECKSEQUENCEVERIFY`
- **WHEN** executing the script with CHECKSEQUENCEVERIFY flag enabled
- **THEN** validation fails with negative locktime error

#### Scenario: CSV treated as NOP when flag disabled
- **GIVEN** a script with `<10> OP_CHECKSEQUENCEVERIFY` and CHECKSEQUENCEVERIFY flag NOT enabled
- **WHEN** executing the script
- **THEN** the opcode is treated as NOP and execution continues

