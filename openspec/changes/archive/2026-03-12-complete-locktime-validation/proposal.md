# Change: Complete CLTV/CSV Locktime Validation (BIP 65/68/112/113)

## Why
The script engine has placeholder implementations for OP_CHECKLOCKTIMEVERIFY (BIP 65) and OP_CHECKSEQUENCEVERIFY (BIP 112) that never actually verify against transaction context. CLTV always passes without checking nLockTime, and CSV always fails because it hardcodes a tx version of 1. The node also lacks BIP 68 consensus enforcement of sequence locks during block connection and BIP 113 median-time-past for locktime evaluation. These are consensus-critical rules active since 2016 -- without them the node cannot correctly validate the blockchain.

## What Changes
- Thread transaction context (nLockTime, nSequence, tx version) into the Coalton ScriptContext
- Implement OP_CHECKLOCKTIMEVERIFY per BIP 65 (compare stack top against tx nLockTime)
- Implement OP_CHECKSEQUENCEVERIFY per BIP 112 (compare stack top against input nSequence)
- Add transaction finality check (`IsFinalTx`) during block connection
- Add median-time-past calculation for BIP 113 locktime evaluation
- Add BIP 68 sequence lock validation during block connection
- Set `*script-flags*` during block validation based on activation heights
- Add tests with Bitcoin Core test vectors covering CLTV/CSV scenarios

## Impact
- Affected specs: `script`, `validation`
- Affected code: `src/coalton/script.lisp`, `src/coalton/interop.lisp`, `src/validation/block.lisp`, `src/validation/transaction.lisp`
- Tests: Enable Bitcoin Core CLTV/CSV test vectors, add block-level locktime tests
