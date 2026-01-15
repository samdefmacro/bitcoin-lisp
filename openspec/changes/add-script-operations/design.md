# Design: Typed Script Operations

## Context

Bitcoin script is a stack-based language used to define spending conditions for transaction outputs. The script interpreter is consensus-critical—bugs can lead to fund loss or chain splits. The existing CL implementation uses untyped operations with runtime checks.

### Constraints
- Must match Bitcoin Core behavior exactly for consensus
- Stack values have complex semantics (bytes interpreted as numbers, bools)
- Script integers use variable-length encoding with sign bit
- Must integrate with existing Coalton types (Hash256, Hash160, Satoshi)
- Performance matters for block validation

### Stakeholders
- Node operators relying on correct validation
- Contributors extending script functionality

## Goals / Non-Goals

### Goals
- Catch type errors at compile time (wrong opcode arguments, stack misuse)
- Provide clear semantics for script values via types
- Enable safe refactoring of script interpreter
- Maintain exact consensus compatibility

### Non-Goals
- Optimizing script execution performance (future work)
- Supporting deprecated/disabled opcodes
- Implementing witness script extensions (separate proposal)

## Decisions

### Decision 1: Opcode ADT vs Constants

**What**: Define opcodes as an algebraic data type rather than numeric constants.

```coalton
(define-type Opcode
  OP-0
  OP-PUSHDATA1
  OP-PUSHDATA2
  OP-PUSHDATA4
  (OP-PUSHBYTES U8)  ; 1-75 bytes
  OP-1NEGATE
  OP-1 OP-2 ... OP-16
  OP-NOP
  OP-IF OP-NOTIF OP-ELSE OP-ENDIF
  OP-VERIFY OP-RETURN
  OP-DUP OP-DROP OP-SWAP ...
  OP-EQUAL OP-EQUALVERIFY
  OP-HASH160 OP-HASH256 OP-SHA256
  OP-CHECKSIG OP-CHECKSIGVERIFY
  OP-UNKNOWN U8)  ; For forward compatibility
```

**Why**: Pattern matching ensures exhaustive handling. Unknown opcodes are explicitly typed.

**Alternatives considered**:
- Numeric constants: Rejected—no compile-time exhaustiveness checking

### Decision 2: Script Value Types

**What**: Define explicit types for script stack values.

```coalton
(define-type ScriptNum
  "A script number (signed, variable-length, max 4 bytes)."
  (ScriptNum Integer))

(define-type ScriptValue
  "A value on the script stack."
  (SV-Bytes (Vector U8))
  (SV-Num ScriptNum))
```

**Why**: Distinguishes between raw bytes and numeric interpretations. Prevents mixing.

**Alternatives considered**:
- Single bytes type: Rejected—loses semantic information about intended use
- Separate stacks for numbers/bytes: Rejected—doesn't match Bitcoin semantics

### Decision 3: Execution Result Type

**What**: Use Result type for script execution.

```coalton
(define-type ScriptError
  SE-StackUnderflow
  SE-InvalidNumber
  SE-VerifyFailed
  SE-OpReturn
  SE-DisabledOpcode
  SE-UnknownOpcode
  SE-BadScript)

(define-type (ScriptResult :a)
  (ScriptOk :a)
  (ScriptErr ScriptError))
```

**Why**: Makes error handling explicit. Caller must handle both success and failure.

### Decision 4: Execution Context as Record

**What**: Use a Coalton record for execution context.

```coalton
(define-type ScriptContext
  (ScriptContext
    (stack (List (Vector U8)))
    (alt-stack (List (Vector U8)))
    (script (Vector U8))
    (position UFix)
    (condition-stack (List Boolean))  ; For IF/ELSE nesting
    (tx-hash (Optional Hash256))
    (input-index U32)
    (flags U32)))
```

**Why**: Groups related state. Immutable updates via functional style.

### Decision 5: Crypto Integration

**What**: Reuse existing Coalton crypto module for hash operations.

```coalton
(declare execute-op-hash160 (ScriptContext -> (ScriptResult ScriptContext)))
(define (execute-op-hash160 ctx)
  (match (stack-pop ctx)
    ((Some (Tuple data new-ctx))
     (let ((hash (bitcoin-lisp.coalton.crypto:compute-hash160 data)))
       (ScriptOk (stack-push new-ctx (hash160-bytes hash)))))
    ((None) (ScriptErr SE-StackUnderflow))))
```

**Why**: Avoids duplication. Ensures type consistency across modules.

### Decision 6: Flow Control Implementation

**What**: Track conditional execution with a condition stack.

```
IF pushes True/False based on top of stack
ELSE inverts top of condition stack
ENDIF pops condition stack
Operations only execute when all conditions are True
```

**Why**: Handles nested IF/ELSE/ENDIF correctly. Standard Bitcoin approach.

## Risks / Trade-offs

| Risk | Impact | Mitigation |
|------|--------|------------|
| Consensus divergence | Critical | Extensive testing against Bitcoin Core vectors |
| Performance regression | Medium | Profile after correctness, optimize later |
| Complex type conversions | Low | Clear conversion functions with tests |

## Migration Plan

### Phase 1: Core Types
1. Add script package definition
2. Implement Opcode ADT and conversions
3. Implement ScriptNum conversions

### Phase 2: Stack & Execution
1. Implement typed stack operations
2. Implement execution context
3. Add simple opcodes (push, stack manipulation)

### Phase 3: Full Interpreter
1. Add arithmetic opcodes
2. Add crypto opcodes (using Coalton crypto)
3. Add flow control
4. Implement CHECKSIG

### Phase 4: Integration
1. Create CL interop layer
2. Wire into validation module
3. Run test vectors

### Rollback
Each phase can be reverted by removing Coalton code. The CL implementation remains as fallback.

## Open Questions

1. **CHECKSIG performance**: Should signature verification stay in CL for libsecp256k1 FFI efficiency?
2. **Test vectors**: Where to source comprehensive script test vectors?
3. **P2SH-P2WPKH**: Should basic SegWit support be included or deferred?
