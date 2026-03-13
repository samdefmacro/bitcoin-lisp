# Change: Add sigops validation

## Why
The node defines `+max-block-sigops+` (20,000) but never enforces it. Bitcoin Core limits blocks to 80,000 sigops cost (BIP 141 weighted), where legacy sigops count as 4 and witness sigops count as 1. Without this check, the node accepts blocks that Bitcoin Core rejects — a consensus-critical gap that could cause chain splits.

## What Changes
- Add `count-script-sigops` to scan raw script bytes for OP_CHECKSIG(VERIFY) and OP_CHECKMULTISIG(VERIFY)
- Add `count-transaction-sigops-cost` to compute weighted sigops for a transaction (legacy * 4 + witness * 1)
- Replace `+max-block-sigops+` with `+max-block-sigops-cost+` (80,000) per BIP 141
- Validate total block sigops cost in `validate-block`

### Sigops counting rules
- **Legacy**: Scan all scriptSigs and scriptPubKeys. OP_CHECKSIG(VERIFY) = 1. OP_CHECKMULTISIG(VERIFY) = 20 (inaccurate count, always uses max).
- **P2SH**: Additionally count sigops in the redeemScript (last push in scriptSig) using accurate counting (use preceding OP_n for multisig key count).
- **Witness P2WPKH** (native or P2SH-wrapped): 1 sigop.
- **Witness P2WSH** (native or P2SH-wrapped): Count sigops from the witness script (last item in witness stack) using accurate counting.
- **Weighting**: Legacy and P2SH sigops are multiplied by 4 (witness scale factor). Witness sigops count at face value. Total must be <= 80,000.

## Impact
- Affected specs: `validation`
- Affected code: `src/validation/script.lisp` (count-script-sigops), `src/validation/block.lisp` (transaction/block-level counting and validation), `src/package.lisp`
