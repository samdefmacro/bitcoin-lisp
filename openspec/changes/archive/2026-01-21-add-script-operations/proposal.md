# Change: Add Typed Script Operations

## Why

Bitcoin script validation is consensus-critical code where type errors can lead to fund loss or chain splits. The current CL implementation uses untyped stack operations and runtime checks. Adding Coalton static typing will catch type mismatches at compile time, ensuring stack values, opcodes, and execution contexts are handled correctly.

## What Changes

- **NEW** `script` capability: Typed Bitcoin script interpreter with Coalton
- **MODIFIED** `validation` capability: Integration with typed script execution

Key additions:
- Typed opcode definitions using algebraic data types
- Type-safe stack with compile-time guarantees
- Typed script values (ScriptNum, ScriptBytes)
- Integration with existing Hash256, Hash160 types for crypto opcodes
- Typed execution context and result types

## Impact

- Affected specs: `script` (new), `validation` (modified)
- Affected code: `src/coalton/script.lisp` (new), `src/validation/script.lisp` (wrapper)
- Dependencies: Requires `coalton-integration` spec (Coalton types already available)

## Scope

This proposal covers:
- Typed opcodes for standard Bitcoin script operations
- Stack operations (OP_DUP, OP_DROP, OP_SWAP, etc.)
- Crypto operations (OP_HASH160, OP_HASH256, OP_CHECKSIG)
- Arithmetic operations (OP_ADD, OP_SUB, OP_EQUAL)
- Flow control (OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY)
- P2PKH and P2SH script validation

Out of scope:
- SegWit script extensions (witness programs)
- Taproot/Tapscript (BIP 340-342)
- OP_CHECKMULTISIG optimization
