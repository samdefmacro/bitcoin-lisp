# Bitcoin-Lisp Script Interpreter Progress

*Last updated: 2026-01-15*

## Current Status

**Test Results:** 847 passed / 1079 total run

| Category | Count |
|----------|-------|
| Passed | 847 |
| Failed (P2SH) | 129 |
| Failed (MINIMALDATA) | 71 |
| Failed (Other) | 32 |
| Skipped (CHECKMULTISIG) | 111 |
| Skipped (WITNESS) | 23 |

## Todo List

- [x] Fix script.lisp compilation issue
- [x] Implement CHECKSIG with transaction context
- [x] Implement STRICTENC validation for signatures
- [ ] **Implement CHECKMULTISIG** (111 tests skipped - HIGH PRIORITY)
- [ ] **Implement MINIMALDATA validation** (71 failures)
- [ ] Implement SIGPUSHONLY validation
- [ ] Investigate 32 "other" failures
- [ ] Run final verification tests

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

## Next Steps

### 1. CHECKMULTISIG (High Priority)
- Unlocks 111 currently skipped tests
- Requires implementing multi-signature verification loop
- Pattern: pop n pubkeys, pop m signatures, verify m-of-n
- Watch for off-by-one bug (Bitcoin's original bug)

### 2. MINIMALDATA (Medium Priority)
- Would fix 71 failing tests
- Validate that push operations use minimal encoding
- e.g., pushing 1 should use OP_1, not OP_PUSHDATA1 0x01 0x01

### 3. Investigate "Other" Failures
- 32 tests failing for unknown reasons
- May reveal edge cases or bugs

## Files Modified

- `src/coalton/interop.lisp` - CL interop layer, STRICTENC functions
- `src/coalton/script.lisp` - Main script interpreter, CHECKSIG/CHECKSIGVERIFY
- `tests/bitcoin-core-script-tests.lisp` - Test harness (exports added)

## Running Tests

```bash
sbcl --eval '(require :asdf)' \
     --eval '(let ((asdf:*compile-file-failure-behaviour* :warn))
               (asdf:load-system :bitcoin-lisp)
               (asdf:test-system :bitcoin-lisp))'
```
