#!/usr/bin/env python3
"""
Run scriptSig + scriptPubKey through python-bitcoinlib's reference interpreter
for tx 3 input 1 of testnet4 block 118555. If python-bitcoinlib accepts, our
Coalton interpreter has a bug — likely in stack manipulation. If python-bitcoinlib
also rejects, the issue is upstream (different sighash, different inputs).
"""

from bitcoin.core import CTransaction, CMutableTransaction, x
from bitcoin.core.script import CScript, SIGHASH_ALL, SignatureHash
from bitcoin.core.scripteval import VerifyScript, SCRIPT_VERIFY_FLAGS_BY_NAME, EvalScript
import sys

# Tx 3 of block 118555 (witness-stripped serialization).
TX_HEX = open("/tmp/118555-tx.hex").read().strip()
SPK_HEX = open("/tmp/118555-spk.hex").read().strip()

INPUT_IDX = 1

def main():
    tx = CTransaction.deserialize(x(TX_HEX))
    print(f"tx version={tx.nVersion} locktime={tx.nLockTime} ins={len(tx.vin)} outs={len(tx.vout)}")
    inp = tx.vin[INPUT_IDX]
    print(f"input[{INPUT_IDX}] outpoint={inp.prevout.hash[::-1].hex()}:{inp.prevout.n}")
    print(f"  scriptsig len={len(inp.scriptSig)}")

    scriptsig = CScript(inp.scriptSig)
    scriptpubkey = CScript(x(SPK_HEX))

    flags_set = ("P2SH", "DERSIG", "CHECKLOCKTIMEVERIFY", "CHECKSEQUENCEVERIFY",
                 "WITNESS", "NULLDUMMY", "TAPROOT")
    # python-bitcoinlib uses different flag names — map what's available.
    avail = SCRIPT_VERIFY_FLAGS_BY_NAME.keys()
    flags = set()
    for name in flags_set:
        if name in avail:
            flags.add(SCRIPT_VERIFY_FLAGS_BY_NAME[name])
    # If P2SH is not in dict, try "p2sh" lowercase variants:
    print(f"flags applied: {[k for k in flags_set if k in avail]}")
    print(f"available flags: {sorted(avail)}")

    try:
        VerifyScript(scriptsig, scriptpubkey, tx, INPUT_IDX, flags=flags)
        print("VerifyScript: PASS — python-bitcoinlib accepts. Our interpreter has the bug.")
    except Exception as e:
        print(f"VerifyScript: FAIL — {type(e).__name__}: {e}")

if __name__ == "__main__":
    main()
