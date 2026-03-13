## 1. Script-level sigops counting
- [x] 1.1 Add `+max-pubkeys-per-multisig+` constant (20) in `src/validation/script.lisp`
- [x] 1.2 Add `count-script-sigops` in `src/validation/script.lisp` that scans a raw script byte vector and counts OP_CHECKSIG(VERIFY) as 1, OP_CHECKMULTISIG(VERIFY) as n-pubkeys (accurate) or 20 (inaccurate). Takes `(script &key accurate)`.

## 2. Transaction-level sigops cost
- [x] 2.1 Add `count-legacy-sigops` in `src/validation/block.lisp` that sums inaccurate sigops across all scriptSigs (inputs) and scriptPubKeys (outputs) of a transaction
- [x] 2.2 Add `count-p2sh-sigops` in `src/validation/block.lisp` that takes a transaction and a lookup function for spent scriptPubKeys, counts accurate sigops from the redeemScript (last push in scriptSig) for each P2SH input
- [x] 2.3 Add `count-witness-sigops` in `src/validation/block.lisp` that takes a transaction and a lookup function for spent scriptPubKeys, returns 1 per P2WPKH input, counts from witness script for P2WSH inputs. Handles both native and P2SH-wrapped witness programs.
- [x] 2.4 Add `count-transaction-sigops-cost` in `src/validation/block.lisp` that combines: (legacy + p2sh) * 4 + witness. Takes a transaction and a scriptPubKey lookup function.

## 3. Block-level validation
- [x] 3.1 Replace `+max-block-sigops+` with `+max-block-sigops-cost+` (80,000) and add `+witness-scale-factor+` (4)
- [x] 3.2 Add sigops cost check in `validate-block` during the existing transaction loop, using UTXO lookups already available. Reject block if total exceeds 80,000 with :too-many-sigops.

## 4. Exports
- [x] 4.1 Export `count-script-sigops`, `count-transaction-sigops-cost`, `+max-block-sigops-cost+`, `+witness-scale-factor+` from validation package

## 5. Tests
- [x] 5.1 Unit tests for `count-script-sigops` (checksig, checkmultisig accurate/inaccurate, empty script, push-data skipping)
- [x] 5.2 Unit tests for `count-transaction-sigops-cost` (P2PKH, P2WPKH, P2SH-P2WPKH, P2WSH, P2SH multisig, witness scale factor)
- [x] 5.3 Integration test: block at/exceeding sigops cost limit
