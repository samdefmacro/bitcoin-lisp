# Tasks: Add Typed Script Operations

## 1. Project Setup
- [x] 1.1 Add `bitcoin-lisp.coalton.script` package to `src/coalton/package.lisp`
- [x] 1.2 Update `bitcoin-lisp.asd` to include `script.lisp` in coalton module
- [x] 1.3 Create `src/coalton/script.lisp` with Coalton module structure

## 2. Core Types
- [x] 2.1 Define `ScriptNum` type for script numeric values (wrapping Integer)
- [x] 2.2 Define `ScriptError` ADT (StackUnderflow, StackOverflow, InvalidNumber, VerifyFailed, OpReturn, DisabledOpcode, UnknownOpcode, ScriptTooLarge, TooManyOps, InvalidStackOperation)
- [x] 2.3 Define `ScriptResult` type using Result pattern

## 3. Opcode Definitions
- [x] 3.1 Define `Opcode` ADT - Constants (OP-0, OP-1NEGATE, OP-1 through OP-16)
- [x] 3.2 Define `Opcode` ADT - Push data (OP-PUSHBYTES with size, OP-PUSHDATA1/2/4)
- [x] 3.3 Define `Opcode` ADT - Flow control (OP-NOP, OP-IF, OP-NOTIF, OP-ELSE, OP-ENDIF, OP-VERIFY, OP-RETURN)
- [x] 3.4 Define `Opcode` ADT - Stack ops (OP-TOALTSTACK, OP-FROMALTSTACK, OP-DUP, OP-DROP, OP-SWAP, OP-ROT, OP-OVER, OP-PICK, OP-ROLL, OP-NIP, OP-TUCK, OP-IFDUP, OP-DEPTH, OP-2DROP, OP-2DUP, OP-3DUP, OP-2OVER, OP-2ROT, OP-2SWAP)
- [x] 3.5 Define `Opcode` ADT - Arithmetic (OP-1ADD, OP-1SUB, OP-NEGATE, OP-ABS, OP-NOT, OP-0NOTEQUAL, OP-ADD, OP-SUB, OP-BOOLAND, OP-BOOLOR, OP-NUMEQUAL, OP-NUMEQUALVERIFY, OP-NUMNOTEQUAL, OP-LESSTHAN, OP-GREATERTHAN, OP-LESSTHANOREQUAL, OP-GREATERTHANOREQUAL, OP-MIN, OP-MAX, OP-WITHIN)
- [x] 3.6 Define `Opcode` ADT - Crypto (OP-RIPEMD160, OP-SHA1, OP-SHA256, OP-HASH160, OP-HASH256, OP-CODESEPARATOR, OP-CHECKSIG, OP-CHECKSIGVERIFY, OP-CHECKMULTISIG, OP-CHECKMULTISIGVERIFY)
- [x] 3.7 Define `Opcode` ADT - Comparison (OP-EQUAL, OP-EQUALVERIFY)
- [x] 3.8 Define `Opcode` ADT - Disabled/Unknown (OP-DISABLED for OP_CAT etc., OP-UNKNOWN with byte value)
- [x] 3.9 Implement `opcode-to-byte` function (Opcode -> U8)
- [x] 3.10 Implement `byte-to-opcode` function (U8 -> Opcode)
- [x] 3.11 Add opcode predicates (is-push-op, is-disabled, is-conditional)

## 4. Value Conversions
- [x] 4.1 Implement `bytes-to-script-num` with little-endian sign handling
- [x] 4.2 Implement `script-num-to-bytes` with minimal encoding
- [x] 4.3 Implement `cast-to-bool` for conditional operations
- [x] 4.4 Add `script-num-in-range` for 4-byte bounds checking
- [x] 4.5 Implement `require-minimal-encoding` validation

## 5. Stack Operations
- [x] 5.1 Define `ScriptStack` as `(List (Vector U8))`
- [x] 5.2 Implement `stack-push` (value -> stack -> stack)
- [x] 5.3 Implement `stack-pop` (stack -> Optional (Tuple value stack))
- [x] 5.4 Implement `stack-top` (stack -> Optional value)
- [x] 5.5 Implement `stack-depth` (stack -> UFix)
- [x] 5.6 Implement `stack-pick` (index -> stack -> Optional value)
- [x] 5.7 Implement `stack-roll` (index -> stack -> Optional stack)
- [x] 5.8 Implement 2-element ops: `stack-2dup`, `stack-2drop`, `stack-2swap`, `stack-2over`, `stack-2rot`
- [x] 5.9 Implement `stack-3dup`
- [x] 5.10 Implement `stack-rot`, `stack-over`, `stack-nip`, `stack-tuck`, `stack-ifdup`

## 6. Execution Context
- [x] 6.1 Define `ScriptContext` record type with fields:
  - main-stack: ScriptStack
  - alt-stack: ScriptStack
  - script: (Vector U8)
  - position: UFix
  - condition-stack: (List Boolean) for IF/ELSE nesting
  - executing: Boolean (false when in unexecuted IF branch)
  - op-count: UFix (for 201 limit)
  - codesep-pos: UFix (for CHECKSIG)
- [x] 6.2 Add transaction context fields (tx-hash, input-index, flags)
- [x] 6.3 Implement context update helpers (advance-position, increment-op-count)

## 7. Opcode Execution - Push Operations
- [x] 7.1 Implement OP_0 (push empty vector)
- [x] 7.2 Implement OP_1NEGATE (push -1)
- [x] 7.3 Implement OP_1 through OP_16 (push small integers)
- [x] 7.4 Implement OP_PUSHBYTES (1-75 bytes direct push)
- [x] 7.5 Implement OP_PUSHDATA1/2/4 (length-prefixed push)

## 8. Opcode Execution - Stack Manipulation
- [x] 8.1 Implement OP_DUP, OP_DROP, OP_NIP, OP_OVER
- [x] 8.2 Implement OP_SWAP, OP_ROT, OP_TUCK
- [x] 8.3 Implement OP_PICK, OP_ROLL
- [x] 8.4 Implement OP_2DROP, OP_2DUP, OP_3DUP
- [x] 8.5 Implement OP_2OVER, OP_2ROT, OP_2SWAP
- [x] 8.6 Implement OP_IFDUP, OP_DEPTH
- [x] 8.7 Implement OP_TOALTSTACK, OP_FROMALTSTACK

## 9. Opcode Execution - Arithmetic
- [x] 9.1 Implement OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS
- [x] 9.2 Implement OP_NOT, OP_0NOTEQUAL
- [x] 9.3 Implement OP_ADD, OP_SUB
- [x] 9.4 Implement OP_BOOLAND, OP_BOOLOR
- [x] 9.5 Implement OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL
- [x] 9.6 Implement OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL
- [x] 9.7 Implement OP_MIN, OP_MAX, OP_WITHIN

## 10. Opcode Execution - Comparison & Crypto
- [x] 10.1 Implement OP_EQUAL, OP_EQUALVERIFY
- [x] 10.2 Implement OP_RIPEMD160, OP_SHA1, OP_SHA256
- [x] 10.3 Implement OP_HASH160 using Coalton crypto module
- [x] 10.4 Implement OP_HASH256 using Coalton crypto module
- [x] 10.5 Implement OP_CODESEPARATOR (update codesep-pos)
- [x] 10.6 Implement OP_CHECKSIG with sighash computation
- [x] 10.7 Implement OP_CHECKSIGVERIFY
- [x] 10.8 Implement OP_CHECKMULTISIG (basic support)
- [x] 10.9 Implement OP_CHECKMULTISIGVERIFY

## 11. Opcode Execution - Flow Control
- [x] 11.1 Implement OP_NOP (no operation)
- [x] 11.2 Implement OP_VERIFY (fail if top is false)
- [x] 11.3 Implement OP_RETURN (immediate failure)
- [x] 11.4 Implement OP_IF (push condition, update executing flag)
- [x] 11.5 Implement OP_NOTIF (inverse of IF)
- [x] 11.6 Implement OP_ELSE (invert top of condition stack)
- [x] 11.7 Implement OP_ENDIF (pop condition stack)
- [x] 11.8 Add condition stack validation (balanced IF/ENDIF)

## 12. Script Execution Engine
- [x] 12.1 Implement `read-next-opcode` (parse opcode from script bytes)
- [x] 12.2 Implement `execute-opcode` dispatcher
- [x] 12.3 Implement `execute-script` main loop
- [x] 12.4 Add script size limit check (10,000 bytes max)
- [x] 12.5 Add opcode count limit check (201 non-push ops max)
- [x] 12.6 Add stack size limit check (1,000 elements max)
- [x] 12.7 Add disabled opcode rejection
- [x] 12.8 Implement `validate-scripts` (scriptSig + scriptPubKey execution)

## 13. Standard Script Validation
- [x] 13.1 Implement `is-p2pkh-script` pattern detector
- [x] 13.2 Implement `validate-p2pkh` helper
- [x] 13.3 Implement `is-p2sh-script` pattern detector
- [x] 13.4 Implement `validate-p2sh` with redeem script execution
- [x] 13.5 Implement `is-p2pk-script` pattern detector

## 14. CL Interop Layer
- [x] 14.1 Update `src/validation/script.lisp` to call Coalton functions
- [x] 14.2 Add CL wrapper for `execute-script`
- [x] 14.3 Add CL wrapper for `validate-scripts`
- [x] 14.4 Ensure backward compatibility with existing `validate-script` function
- [x] 14.5 Add conversion helpers (CL arrays <-> Coalton vectors)

## 15. Testing
- [x] 15.1 Create `tests/coalton-script-tests.lisp`
- [x] 15.2 Add unit tests for value conversions (bytes<->num, cast-to-bool)
- [x] 15.3 Add unit tests for stack operations
- [x] 15.4 Add unit tests for push opcodes
- [x] 15.5 Add unit tests for arithmetic opcodes
- [x] 15.6 Add unit tests for comparison opcodes
- [x] 15.7 Add unit tests for crypto opcodes
- [x] 15.8 Add unit tests for flow control (IF/ELSE/ENDIF nesting)
- [x] 15.9 Add tests for disabled opcode rejection
- [x] 15.10 Add tests for script/stack size limits
- [x] 15.11 Add integration tests for P2PKH scripts
- [x] 15.12 Add integration tests for P2SH scripts
- [x] 15.13 Add tests from Bitcoin Core script_tests.json (from bitcoin/src/test/data/)
- [x] 15.14 Verify all existing validation tests pass

## 16. Documentation
- [x] 16.1 Add inline documentation to all public functions
- [x] 16.2 Document script execution model in USAGE.md
- [x] 16.3 Add examples of P2PKH and P2SH validation
