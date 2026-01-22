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

#### Scenario: Track execution position
- **GIVEN** a script context at position 0
- **WHEN** reading a 1-byte opcode
- **THEN** position advances to 1

#### Scenario: Nested conditional execution
- **GIVEN** a script with `OP_IF OP_IF ... OP_ENDIF OP_ENDIF`
- **WHEN** executing the script
- **THEN** the condition stack correctly tracks nesting depth

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

