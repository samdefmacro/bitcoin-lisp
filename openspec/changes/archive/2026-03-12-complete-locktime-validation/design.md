## Context
The Coalton script engine (`src/coalton/script.lisp`) has stub implementations for OP_CHECKLOCKTIMEVERIFY (BIP 65, line 2052) and OP_CHECKSEQUENCEVERIFY (BIP 112, line 2076). Both check verification flags but never validate against actual transaction data:

- CLTV: Comments say "In production, would verify against nLockTime" and always passes
- CSV: Comments say "In production would check actual tx version and nSequence" and always fails with SE-UnsatisfiedLocktime (hardcoded tx version 1)

The `ScriptContext` in Coalton has no fields for transaction locktime, sequence, or block context. Transaction context is available on the CL side via `*current-tx*` and `*current-input-index*` dynamic variables in `src/coalton/interop.lisp`, but is not threaded into the Coalton execution environment.

Block validation in `src/validation/block.lisp` does not calculate median-time-past, enforce BIP 68 sequence locks, or check transaction finality (`IsFinalTx`) during block connection. Additionally, `*script-flags*` is never set before script validation in block connection -- only in the test harness. The `p2sh-enabled` boolean is passed separately to `run-scripts-with-p2sh` as a hardcoded `t`, so P2SH works despite the missing flags.

## Goals
- Complete CLTV verification against transaction nLockTime (BIP 65)
- Complete CSV verification against input nSequence with BIP 68 rules (BIP 112)
- Add median-time-past calculation for BIP 113 locktime evaluation
- Enforce BIP 68 sequence locks at block connection time
- Add transaction finality check (`IsFinalTx`) during block connection
- Set `*script-flags*` during block validation based on activation heights
- Pass all Bitcoin Core test vectors for CLTV and CSV flags

## Non-Goals
- OP_CHECKLOCKTIMEVERIFY and OP_CHECKSEQUENCEVERIFY with non-consensus flag combinations
- Mempool sequence lock evaluation (policy, not consensus -- can be added later)
- Relative locktime in fee estimation or transaction construction

## Decisions

### 1. Threading transaction context into ScriptContext
**Decision**: Add `tx-locktime`, `tx-version`, and `input-sequence` fields to the Coalton `ScriptContext`. These are set when the context is created and read by CLTV/CSV opcodes.

**Why not use CL dynamic variables from Coalton?** The current approach of calling back into CL via `lisp` forms works but is fragile and makes the Coalton code harder to test in isolation. Adding fields to ScriptContext keeps the execution self-contained and testable.

**Approach**: Extend `make-script-context` to accept transaction context parameters. The full call chain that needs updating is:

```
CL: run-scripts-with-p2sh → Coalton: execute-scripts → execute-script → make-script-context
```

`execute-scripts` (line 2396) currently takes `(script-sig, script-pubkey, p2sh-enabled)` and `execute-script` (line 2109) takes only `(Vector U8)`. Both need updated signatures to accept and forward transaction context. The CL interop layer (`run-scripts-with-p2sh`, `validate-witness-program`) already has access to `*current-tx*` and `*current-input-index*` -- extract nLockTime, version, and nSequence from these and pass them through the call chain.

### 2. CHECKLOCKTIMEVERIFY implementation (BIP 65)
**Decision**: Follow the Bitcoin Core reference implementation exactly.

**5-byte script numbers**: Both CLTV and CSV interpret the stack top as a 5-byte script number (not the default 4-byte limit used by arithmetic opcodes). This is needed because locktime values can be up to `0xFFFFFFFF`, requiring 5 bytes in script number encoding. Bitcoin Core explicitly passes `nMaxNumSize=5` to `CScriptNum`. The existing `bytes-to-script-num-limited` function (line 608 of script.lisp) accepts a `max-len` parameter and should be called with 5 for both opcodes.

Algorithm:
1. Stack must not be empty
2. Stack top must be non-negative (as 5-byte script number)
3. Stack top and nLockTime must be the same type (both height or both time):
   - Height: value < 500,000,000
   - Time: value >= 500,000,000
4. Stack top must be <= nLockTime
5. Input nSequence must not be 0xFFFFFFFF (which disables locktime)

Note: CLTV does NOT pop the stack (it leaves the value for subsequent opcodes).

### 3. CHECKSEQUENCEVERIFY implementation (BIP 112)
**Decision**: Follow the Bitcoin Core reference implementation exactly. Uses 5-byte script numbers (same as CLTV, see above).

Algorithm:
1. Stack must not be empty
2. Stack top must be non-negative (as 5-byte script number)
3. If stack top bit 31 (disable flag 0x80000000) is set, pass as NOP
4. Transaction version must be >= 2 (otherwise fail)
5. If input nSequence bit 31 (disable flag) is set, fail
6. Both stack top and nSequence are masked with `SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK` (`0x0040FFFF`). The type flags (bit 22) must match -- both height-based or both time-based.
7. Stack top (masked with `0x0040FFFF`) must be <= nSequence (masked with `0x0040FFFF`)

Note: CSV does NOT pop the stack.

### 4. Median-time-past calculation (BIP 113)
**Decision**: Calculate MTP as the median of the timestamps of the previous 11 blocks. Store it alongside block height when connecting blocks.

**Where computed**: In `validate-block` / block connection code in `src/validation/block.lisp`. The MTP is calculated from the header index (which already stores timestamps for all headers).

**Usage**: MTP is used for three things:
1. BIP 113: Transaction finality (`IsFinalTx`) -- compare nLockTime against MTP instead of block timestamp
2. BIP 68: Evaluating relative time-based sequence locks -- use MTP delta
3. Header validation: Timestamp must be > MTP (already checked as "median of previous 11 blocks" in header chain validation)

### 4a. Transaction finality check (IsFinalTx)
**Decision**: Add a `check-transaction-final` function called during block connection.

The node currently has **no nLockTime enforcement** during block validation. In Bitcoin Core, `IsFinalTx` verifies that every non-coinbase transaction in a block has a satisfied locktime:
- If nLockTime == 0: final (always valid)
- If nLockTime < 500,000,000: final when block height > nLockTime
- If nLockTime >= 500,000,000: final when block time > nLockTime (using MTP after BIP 113 activation)
- A transaction is also final if ALL input sequences are 0xFFFFFFFF (SEQUENCE_FINAL)

This is a pre-existing consensus rule (not BIP 65), but BIP 113 modifies the time comparison to use MTP. Without this check, the node accepts blocks containing transactions whose locktimes haven't been reached.

### 5. BIP 68 sequence lock enforcement
**Decision**: Add a `check-sequence-locks` function called during block connection (after transaction structure and contextual validation, before script validation).

For each non-coinbase transaction with version >= 2:
- For each input where nSequence bit 31 is NOT set:
  - If bit 22 is 0 (height-based): the input's UTXO must be at least N blocks deep, where N = nSequence & 0xFFFF
  - If bit 22 is 1 (time-based): the MTP must be at least N*512 seconds after the MTP at the height when the input's UTXO was confirmed

**Activation**: BIP 68 activated at block 419,328 (mainnet) and 770,112 (testnet). These heights should be checked before enforcing.

### 6. Activation heights
**Decision**: Add activation height constants alongside the existing BIP 34 heights.

| BIP | Mainnet | Testnet | Description |
|-----|---------|---------|-------------|
| BIP 65 (CLTV) | 388,381 | 581,885 | OP_CHECKLOCKTIMEVERIFY |
| BIP 68 (Seq locks) | 419,328 | 770,112 | Consensus sequence locks |
| BIP 112 (CSV) | 419,328 | 770,112 | OP_CHECKSEQUENCEVERIFY |
| BIP 113 (MTP) | 419,328 | 770,112 | Median-time-past for locktime |

BIPs 68/112/113 were deployed together as part of the CSV soft fork (BIP 9 deployment "csv").

For script validation: CLTV and CSV flags in `*script-flags*` should be set based on block height >= activation height.

### 7. Script flags during block validation
**Decision**: Set `*script-flags*` in `validate-block-scripts` based on block height. Currently `*script-flags*` is never set during block validation (only in the test harness), so no script flags are enforced.

For this change, set CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY flags based on activation heights. Other flags (DERSIG, WITNESS, TAPROOT, etc.) are either handled through separate code paths (P2SH via the `p2sh-enabled` parameter, witness via `validate-witness-program`) or are not yet height-gated. Setting additional flags is out of scope but would be a natural follow-up.

## Risks / Trade-offs
- **ScriptContext size increase**: Adding 3 integer fields is negligible overhead.
- **Activation height hardcoding**: BIP 9 (versionbits) is not implemented, so activation heights are hardcoded like BIP 34. This is correct for historical blocks and acceptable until BIP 9 is needed for future soft forks.
- **MTP calculation performance**: Computing median of 11 timestamps per block is cheap. The header index already stores all timestamps.

## Open Questions
- None. The BIP specifications are well-defined and the Bitcoin Core implementation is the reference.
