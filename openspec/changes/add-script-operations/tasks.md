# Tasks: Add Typed Script Operations

## 1. Project Setup
- [ ] 1.1 Add `bitcoin-lisp.coalton.script` package to `src/coalton/package.lisp`
- [ ] 1.2 Update `bitcoin-lisp.asd` to include `script.lisp` in coalton module
- [ ] 1.3 Create `src/coalton/script.lisp` with Coalton module structure

## 2. Core Types
- [ ] 2.1 Define `ScriptNum` type for script numeric values (wrapping Integer)
- [ ] 2.2 Define `ScriptError` ADT (StackUnderflow, StackOverflow, InvalidNumber, VerifyFailed, OpReturn, DisabledOpcode, UnknownOpcode, ScriptTooLarge, TooManyOps, InvalidStackOperation)
- [ ] 2.3 Define `ScriptResult` type using Result pattern

## 3. Opcode Definitions
- [ ] 3.1 Define `Opcode` ADT - Constants (OP-0, OP-1NEGATE, OP-1 through OP-16)
- [ ] 3.2 Define `Opcode` ADT - Push data (OP-PUSHBYTES with size, OP-PUSHDATA1/2/4)
- [ ] 3.3 Define `Opcode` ADT - Flow control (OP-NOP, OP-IF, OP-NOTIF, OP-ELSE, OP-ENDIF, OP-VERIFY, OP-RETURN)
- [ ] 3.4 Define `Opcode` ADT - Stack ops (OP-TOALTSTACK, OP-FROMALTSTACK, OP-DUP, OP-DROP, OP-SWAP, OP-ROT, OP-OVER, OP-PICK, OP-ROLL, OP-NIP, OP-TUCK, OP-IFDUP, OP-DEPTH, OP-2DROP, OP-2DUP, OP-3DUP, OP-2OVER, OP-2ROT, OP-2SWAP)
- [ ] 3.5 Define `Opcode` ADT - Arithmetic (OP-1ADD, OP-1SUB, OP-NEGATE, OP-ABS, OP-NOT, OP-0NOTEQUAL, OP-ADD, OP-SUB, OP-BOOLAND, OP-BOOLOR, OP-NUMEQUAL, OP-NUMEQUALVERIFY, OP-NUMNOTEQUAL, OP-LESSTHAN, OP-GREATERTHAN, OP-LESSTHANOREQUAL, OP-GREATERTHANOREQUAL, OP-MIN, OP-MAX, OP-WITHIN)
- [ ] 3.6 Define `Opcode` ADT - Crypto (OP-RIPEMD160, OP-SHA1, OP-SHA256, OP-HASH160, OP-HASH256, OP-CODESEPARATOR, OP-CHECKSIG, OP-CHECKSIGVERIFY, OP-CHECKMULTISIG, OP-CHECKMULTISIGVERIFY)
- [ ] 3.7 Define `Opcode` ADT - Comparison (OP-EQUAL, OP-EQUALVERIFY)
- [ ] 3.8 Define `Opcode` ADT - Disabled/Unknown (OP-DISABLED for OP_CAT etc., OP-UNKNOWN with byte value)
- [ ] 3.9 Implement `opcode-to-byte` function (Opcode -> U8)
- [ ] 3.10 Implement `byte-to-opcode` function (U8 -> Opcode)
- [ ] 3.11 Add opcode predicates (is-push-op, is-disabled, is-conditional)

## 4. Value Conversions
- [ ] 4.1 Implement `bytes-to-script-num` with little-endian sign handling
- [ ] 4.2 Implement `script-num-to-bytes` with minimal encoding
- [ ] 4.3 Implement `cast-to-bool` for conditional operations
- [ ] 4.4 Add `script-num-in-range` for 4-byte bounds checking
- [ ] 4.5 Implement `require-minimal-encoding` validation

## 5. Stack Operations
- [ ] 5.1 Define `ScriptStack` as `(List (Vector U8))`
- [ ] 5.2 Implement `stack-push` (value -> stack -> stack)
- [ ] 5.3 Implement `stack-pop` (stack -> Optional (Tuple value stack))
- [ ] 5.4 Implement `stack-top` (stack -> Optional value)
- [ ] 5.5 Implement `stack-depth` (stack -> UFix)
- [ ] 5.6 Implement `stack-pick` (index -> stack -> Optional value)
- [ ] 5.7 Implement `stack-roll` (index -> stack -> Optional stack)
- [ ] 5.8 Implement 2-element ops: `stack-2dup`, `stack-2drop`, `stack-2swap`, `stack-2over`, `stack-2rot`
- [ ] 5.9 Implement `stack-3dup`
- [ ] 5.10 Implement `stack-rot`, `stack-over`, `stack-nip`, `stack-tuck`, `stack-ifdup`

## 6. Execution Context
- [ ] 6.1 Define `ScriptContext` record type with fields:
  - main-stack: ScriptStack
  - alt-stack: ScriptStack
  - script: (Vector U8)
  - position: UFix
  - condition-stack: (List Boolean) for IF/ELSE nesting
  - executing: Boolean (false when in unexecuted IF branch)
  - op-count: UFix (for 201 limit)
  - codesep-pos: UFix (for CHECKSIG)
- [ ] 6.2 Add transaction context fields (tx-hash, input-index, flags)
- [ ] 6.3 Implement context update helpers (advance-position, increment-op-count)

## 7. Opcode Execution - Push Operations
- [ ] 7.1 Implement OP_0 (push empty vector)
- [ ] 7.2 Implement OP_1NEGATE (push -1)
- [ ] 7.3 Implement OP_1 through OP_16 (push small integers)
- [ ] 7.4 Implement OP_PUSHBYTES (1-75 bytes direct push)
- [ ] 7.5 Implement OP_PUSHDATA1/2/4 (length-prefixed push)

## 8. Opcode Execution - Stack Manipulation
- [ ] 8.1 Implement OP_DUP, OP_DROP, OP_NIP, OP_OVER
- [ ] 8.2 Implement OP_SWAP, OP_ROT, OP_TUCK
- [ ] 8.3 Implement OP_PICK, OP_ROLL
- [ ] 8.4 Implement OP_2DROP, OP_2DUP, OP_3DUP
- [ ] 8.5 Implement OP_2OVER, OP_2ROT, OP_2SWAP
- [ ] 8.6 Implement OP_IFDUP, OP_DEPTH
- [ ] 8.7 Implement OP_TOALTSTACK, OP_FROMALTSTACK

## 9. Opcode Execution - Arithmetic
- [ ] 9.1 Implement OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS
- [ ] 9.2 Implement OP_NOT, OP_0NOTEQUAL
- [ ] 9.3 Implement OP_ADD, OP_SUB
- [ ] 9.4 Implement OP_BOOLAND, OP_BOOLOR
- [ ] 9.5 Implement OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL
- [ ] 9.6 Implement OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL
- [ ] 9.7 Implement OP_MIN, OP_MAX, OP_WITHIN

## 10. Opcode Execution - Comparison & Crypto
- [ ] 10.1 Implement OP_EQUAL, OP_EQUALVERIFY
- [ ] 10.2 Implement OP_RIPEMD160, OP_SHA1, OP_SHA256
- [ ] 10.3 Implement OP_HASH160 using Coalton crypto module
- [ ] 10.4 Implement OP_HASH256 using Coalton crypto module
- [ ] 10.5 Implement OP_CODESEPARATOR (update codesep-pos)
- [ ] 10.6 Implement OP_CHECKSIG with sighash computation
- [ ] 10.7 Implement OP_CHECKSIGVERIFY
- [ ] 10.8 Implement OP_CHECKMULTISIG (basic support)
- [ ] 10.9 Implement OP_CHECKMULTISIGVERIFY

## 11. Opcode Execution - Flow Control
- [ ] 11.1 Implement OP_NOP (no operation)
- [ ] 11.2 Implement OP_VERIFY (fail if top is false)
- [ ] 11.3 Implement OP_RETURN (immediate failure)
- [ ] 11.4 Implement OP_IF (push condition, update executing flag)
- [ ] 11.5 Implement OP_NOTIF (inverse of IF)
- [ ] 11.6 Implement OP_ELSE (invert top of condition stack)
- [ ] 11.7 Implement OP_ENDIF (pop condition stack)
- [ ] 11.8 Add condition stack validation (balanced IF/ENDIF)

## 12. Script Execution Engine
- [ ] 12.1 Implement `read-next-opcode` (parse opcode from script bytes)
- [ ] 12.2 Implement `execute-opcode` dispatcher
- [ ] 12.3 Implement `execute-script` main loop
- [ ] 12.4 Add script size limit check (10,000 bytes max)
- [ ] 12.5 Add opcode count limit check (201 non-push ops max)
- [ ] 12.6 Add stack size limit check (1,000 elements max)
- [ ] 12.7 Add disabled opcode rejection
- [ ] 12.8 Implement `validate-scripts` (scriptSig + scriptPubKey execution)

## 13. Standard Script Validation
- [ ] 13.1 Implement `is-p2pkh-script` pattern detector
- [ ] 13.2 Implement `validate-p2pkh` helper
- [ ] 13.3 Implement `is-p2sh-script` pattern detector
- [ ] 13.4 Implement `validate-p2sh` with redeem script execution
- [ ] 13.5 Implement `is-p2pk-script` pattern detector

## 14. CL Interop Layer
- [ ] 14.1 Update `src/validation/script.lisp` to call Coalton functions
- [ ] 14.2 Add CL wrapper for `execute-script`
- [ ] 14.3 Add CL wrapper for `validate-scripts`
- [ ] 14.4 Ensure backward compatibility with existing `validate-script` function
- [ ] 14.5 Add conversion helpers (CL arrays <-> Coalton vectors)

## 15. Testing
- [ ] 15.1 Create `tests/coalton-script-tests.lisp`
- [ ] 15.2 Add unit tests for value conversions (bytes<->num, cast-to-bool)
- [ ] 15.3 Add unit tests for stack operations
- [ ] 15.4 Add unit tests for push opcodes
- [ ] 15.5 Add unit tests for arithmetic opcodes
- [ ] 15.6 Add unit tests for comparison opcodes
- [ ] 15.7 Add unit tests for crypto opcodes
- [ ] 15.8 Add unit tests for flow control (IF/ELSE/ENDIF nesting)
- [ ] 15.9 Add tests for disabled opcode rejection
- [ ] 15.10 Add tests for script/stack size limits
- [ ] 15.11 Add integration tests for P2PKH scripts
- [ ] 15.12 Add integration tests for P2SH scripts
- [ ] 15.13 Add tests from Bitcoin Core script_tests.json (from bitcoin/src/test/data/)
- [ ] 15.14 Verify all existing validation tests pass

## 16. Documentation
- [ ] 16.1 Add inline documentation to all public functions
- [ ] 16.2 Document script execution model in USAGE.md
- [ ] 16.3 Add examples of P2PKH and P2SH validation
