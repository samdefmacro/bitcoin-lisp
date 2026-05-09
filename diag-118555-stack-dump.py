#!/usr/bin/env python3
"""
Patch python-bitcoinlib's EvalScript to dump the stack state just before
each opcode. We're particularly interested in the stack at byte 3953
(OP_CHECKMULTISIGVERIFY). Compare to our Lisp engine's state to find
the divergent opcode.
"""

import sys
from bitcoin.core import CTransaction, x
from bitcoin.core.script import CScript, OP_CHECKMULTISIGVERIFY, OP_CHECKMULTISIG
from bitcoin.core.scripteval import (
    VerifyScript, SCRIPT_VERIFY_FLAGS_BY_NAME,
    EvalScript, _CheckMultiSig, _CheckSig)
import bitcoin.core.scripteval as scripteval

TX_HEX = open("/tmp/118555-tx.hex").read().strip()
SPK_HEX = open("/tmp/118555-spk.hex").read().strip()
INPUT_IDX = 1

# Patch _CheckMultiSig to dump pubkeys + sigs.
orig_cms = scripteval._CheckMultiSig
def patched_cms(opcode, script, stack, txTo, inIdx, flags, err_raiser, nOpCount):
    # Stack at this moment: [..., dummy, sig1, ..., sigN, N, pk1, ..., pkM, M]
    print(f"\n[python-bitcoinlib] _CheckMultiSig opcode={opcode} stack-depth={len(stack)}")
    if len(stack) >= 1:
        m_bytes = stack[-1]
        print(f"  M (pubkey count) bytes: {m_bytes.hex() if m_bytes else '(empty)'}")
        try:
            # python-bitcoinlib uses internal helper for script-num decoding.
            from bitcoin.core._bignum import vch2bn
            m = vch2bn(stack[-1])
            print(f"  M = {m}")
            if m > 0 and len(stack) >= 1 + m:
                print(f"  pubkeys (stack[-2..-{1+m}]):")
                for i in range(m):
                    pk = stack[-2 - i]
                    print(f"    pk[{i}] = {pk.hex()}")
                if len(stack) >= 2 + m:
                    n_bytes = stack[-2 - m]
                    print(f"  N (sig count) bytes: {n_bytes.hex() if n_bytes else '(empty)'}")
                    n = vch2bn(n_bytes)
                    print(f"  N = {n}")
                    if n > 0 and len(stack) >= 2 + m + n:
                        print(f"  sigs:")
                        for i in range(n):
                            s = stack[-3 - m - i]
                            print(f"    sig[{i}] = {s.hex()}")
        except Exception as e:
            print(f"  (parse error: {e})")
    return orig_cms(opcode, script, stack, txTo, inIdx, flags, err_raiser, nOpCount)

scripteval._CheckMultiSig = patched_cms

def main():
    tx = CTransaction.deserialize(x(TX_HEX))
    inp = tx.vin[INPUT_IDX]
    scriptsig = CScript(inp.scriptSig)
    scriptpubkey = CScript(x(SPK_HEX))
    flag_names = ("P2SH", "DERSIG", "CHECKLOCKTIMEVERIFY", "NULLDUMMY")
    flags = {SCRIPT_VERIFY_FLAGS_BY_NAME[k] for k in flag_names if k in SCRIPT_VERIFY_FLAGS_BY_NAME}
    try:
        VerifyScript(scriptsig, scriptpubkey, tx, INPUT_IDX, flags=flags)
        print("\n=== VerifyScript: PASS ===")
    except Exception as e:
        print(f"\n=== VerifyScript: FAIL — {type(e).__name__}: {e} ===")

if __name__ == "__main__":
    main()
