# Bitcoin-Lisp Script Interpreter Progress

*Last updated: 2026-01-27*

## Current Status

**Test Results:** 1213 passed / 1213 total run (100% pass rate)

| Category | Count |
|----------|-------|
| Passed | 1213 |
| Failed | 0 |

## Completed Features

- [x] Fix script.lisp compilation issue
- [x] Implement CHECKSIG with transaction context
- [x] Implement STRICTENC validation for signatures
- [x] Implement CHECKMULTISIG
- [x] Implement MINIMALDATA validation
- [x] Fix EVAL_FALSE detection (stack top truthiness check)
- [x] Implement lax DER signature parsing (for non-DERSIG mode)
- [x] Implement strict DER validation (for DERSIG flag)
- [x] Implement NULLFAIL validation
- [x] Fix CHECKMULTISIG edge cases
- [x] Implement SIGPUSHONLY validation
- [x] Implement SegWit (BIP 141/143)
- [x] Implement Taproot (BIP 340-342)
- [x] Implement Initial Block Download (IBD)

## Completed Work

### CHECKSIG Implementation
- Location: `src/coalton/script.lisp` lines 1601-1626
- Uses test transaction format for sighash computation
- Calls `verify-checksig-for-script` from interop layer

### STRICTENC Validation
- Location: `src/coalton/interop.lisp` lines 180-373
- Added `*script-flags*` dynamic variable for test harness
- Added `valid-sighash-type-p` - validates sighash types (1, 2, 3 with optional 0x80)
- Added `valid-pubkey-format-p` - rejects hybrid pubkeys (0x06, 0x07 prefix)
- `verify-checksig-for-script` wrapper tracks STRICTENC errors
- `last-checksig-had-strictenc-error-p` lets Coalton detect errors

### CHECKMULTISIG Implementation
- Location: `src/coalton/interop.lisp` functions `verify-checkmultisig`, `do-checkmultisig-stack-op`
- Location: `src/coalton/script.lisp` lines 1655-1716
- Implements m-of-n multisig verification with proper signature ordering
- Handles Bitcoin's off-by-one bug (dummy element pop)
- NULLDUMMY flag validation for the dummy element
- Uses `coalton-vec-to-array` for Coalton/CL type conversion

### MINIMALDATA Validation
- Location: `src/coalton/interop.lisp` functions `minimal-push-encoding-p`, `minimal-number-encoding-p`
- Location: `src/coalton/script.lisp` function `check-minimal-push`, modified `bytes-to-script-num`
- **Push encoding validation**: Checks that push opcodes use minimal encoding
  - Direct push (1-75 bytes) checked for OP_N equivalents
  - PUSHDATA1/2/4 checked for minimal size usage
- **Number encoding validation**: Checks that stack numbers are minimally encoded
  - Zero must be empty (not 0x00 or 0x80)
  - No unnecessary leading zero bytes
- Added validation to CHECKMULTISIG for n/m values
- Added validation to CHECKSEQUENCEVERIFY for stack top

### EVAL_FALSE Detection (Stack Top Truthiness)
- Location: `src/coalton/interop.lisp` function `stack-top-truthy-p`
- Location: `tests/bitcoin-core-script-tests.lisp` updated `run-script-test`
- **Problem**: Script result was not checking if stack top is TRUE, only if execution succeeded
- **Fix**: Added `stack-top-truthy-p` to check if stack is non-empty AND top is truthy
- Fixes tests where CHECKSIG pushes FALSE but script should fail with EVAL_FALSE

### Lax and Strict DER Signature Parsing
- Location: `src/crypto/secp256k1.lisp` functions `normalize-signature-lax`, `check-der-signature-format`
- Location: `src/coalton/interop.lisp` function `check-der-integer-encoding`
- **Lax parsing** (default): Tolerates padding issues in DER signatures
  - Extracts R and S values tolerantly
  - Normalizes to compact 64-byte format for secp256k1
- **Strict parsing** (with DERSIG flag): Full BIP66 validation
  - Rejects signatures > 73 bytes
  - Validates INTEGER encoding (no unnecessary padding)
  - Rejects negative R/S values (high bit without 0x00 prefix)
  - Returns `:sig-der` error on invalid format
- `verify-signature` now accepts `:strict` keyword

### Tapscript (BIP 342) Implementation
- Location: `src/coalton/script.lisp`, `src/coalton/interop.lisp`
- **Error types added**: `SE-TapscriptMinimalIf`, `SE-TapscriptCheckmultisig`, `SE-TapscriptInvalidSig`
- **OP_SUCCESS pre-scan**: Scripts with OP_SUCCESS opcodes succeed immediately
- **MINIMALIF rule**: In Tapscript, IF/NOTIF arguments must be empty or `[0x01]`
- **CHECKMULTISIG disabled**: Returns `SE-TapscriptCheckmultisig` in Tapscript context
- **CHECKSIG/CHECKSIGVERIFY**: Uses Schnorr verification in Tapscript, ECDSA in legacy
- **OP_CHECKSIGADD**: New opcode for Tapscript multi-sig (sig n pubkey -> n+valid)
- **Signature verification**: Invalid non-empty signatures fail immediately in Tapscript

### Key Technical Details

**Coalton-CL Interop Pattern:**
```lisp
;; Defer symbol lookup to runtime to avoid package errors
(let ((fn (cl:fdefinition (cl:intern "FUNCTION-NAME" "PACKAGE-NAME"))))
  (cl:funcall fn args...))
```

**Compilation Note:**
Project requires this flag due to Coalton warnings:
```lisp
(let ((asdf:*compile-file-failure-behaviour* :warn))
  (asdf:load-system :bitcoin-lisp))
```

## All Tests Passing

All Bitcoin Core script_tests.json tests now pass (1213/1213 = 100%).

## Files Modified

- `src/coalton/interop.lisp` - CL interop layer, STRICTENC functions, DER validation
- `src/coalton/script.lisp` - Main script interpreter, CHECKSIG/CHECKSIGVERIFY
- `src/crypto/secp256k1.lisp` - Signature verification with lax/strict modes
- `tests/bitcoin-core-script-tests.lisp` - Test harness, stack truthiness check

## Running Tests

```bash
sbcl --eval '(require :asdf)' \
     --eval '(let ((asdf:*compile-file-failure-behaviour* :warn))
               (asdf:load-system :bitcoin-lisp)
               (asdf:test-system :bitcoin-lisp))'
```
