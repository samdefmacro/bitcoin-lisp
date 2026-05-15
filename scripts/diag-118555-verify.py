#!/usr/bin/env python3
"""
Independent ECDSA verification of (sighash, sig, pubkey) from h=118555.
If our libsecp256k1-bound verify-signature says NIL but the standalone
ecdsa lib says True, we have a Lisp-side bug. If both say invalid, the
issue is upstream (wrong sighash, wrong pubkey, or wrong sig).

Run with the diag-118555-venv that has `ecdsa` installed.
"""

import hashlib
from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_der

# Captured from the Lisp diagnostic.
SIGHASH_HEX = "b3a29cef574d19524a11845ae92d5a45bc5ecbcfe43fe8fba8577bdd840586cb"
SIG_DER_HEX = ("303902153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63"
               "0220337727dcdad75c1acb0ca731edaf9940a6ae0de52f137f94d94369f44522b81f")

# 9 pubkeys passed to verify-checkmultisig.
PUBKEYS_HEX = [
    "033f4d9cffa30d2468cbba00ff53b3204660828708c98161a1417e6d1bf225750d",
    "02789c9853c2b45887ea265834fefdfd8434392c42504919a8864748b200e27995",
    "028366885d78a0b7393095e5e1a71d2dda30db124f88e26fe409c17ac4c5ffb687",
    "03c19a148747f4e270d27107cc696c45e3d286244bf85a87a3c30fe1402ee50135",
    "021d2cb68faebff30b3bb7eaabff9e92451df102d6de7a72c4773f046d4d2196b3",
    "039d57ae6f18806bd456c17e33c8ece64c1fb16ff7041de4121029b9d7e1bec123",
    "021b5584dc88386015d083bfd429db7933b7e4debb97b763b0ca685e60ee419e4e",
    "02b2d36bf1b0a0971a165269e520aa3efcf574484a58684c3a405db5461c11b626",
    "025d053203b5d92e8379a63d51b236d9b806b82e72640623b14abe337b29e56fdd",
]

def verify_one(pubkey_hex: str, sighash: bytes, sig_der: bytes) -> str:
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=SECP256k1)
    except Exception as e:
        return f"pubkey-parse-fail: {e}"
    try:
        ok = vk.verify_digest(sig_der, sighash, sigdecode=sigdecode_der)
        return f"OK (verify={ok})" if ok else "verify=False"
    except Exception as e:
        return f"verify-exception: {e}"

if __name__ == "__main__":
    sighash = bytes.fromhex(SIGHASH_HEX)
    sig = bytes.fromhex(SIG_DER_HEX)
    print(f"sighash: {SIGHASH_HEX}")
    print(f"sig DER: {SIG_DER_HEX} ({len(sig)} bytes)")
    print()
    for i, pk_hex in enumerate(PUBKEYS_HEX):
        result = verify_one(pk_hex, sighash, sig)
        print(f"pubkey[{i}] = {pk_hex[:16]}...  {result}")
