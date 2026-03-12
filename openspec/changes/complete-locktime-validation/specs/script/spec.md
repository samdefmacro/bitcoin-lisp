## MODIFIED Requirements

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

## ADDED Requirements

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
