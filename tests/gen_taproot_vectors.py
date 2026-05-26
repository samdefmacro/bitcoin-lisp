#!/usr/bin/env python3
"""Generate taproot spend test vectors (script_assets-style) using Bitcoin
Core's pure-Python test_framework — no bitcoind build required.

Each record: {tx (full witness hex), prevouts:[{scriptPubKey, amountSats}],
index, flags, comment}. The CL runner (tests/coalton-script-tests.lisp)
parses the tx, builds the spent-utxo set, and runs verify-script on the
given input, asserting success.

Run from the repo root:
  python3 tests/gen_taproot_vectors.py > tests/data/taproot_spend_vectors.json

Covers (so far): key-path (DEFAULT, ALL|ANYONECANPAY), key-path with annex,
script-path CHECKSIG, script-path with OP_CODESEPARATOR. The annex and
codesep records exercise the BIP341 sighash extensions.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "refs", "bitcoin", "test", "functional"))

from test_framework.script import (
    CScript, taproot_construct, TaprootSignatureHash,
    OP_CHECKSIG, OP_CODESEPARATOR, OP_DROP, OP_1,
    LEAF_VERSION_TAPSCRIPT, SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_ANYONECANPAY,
)
from test_framework.key import (
    generate_privkey, compute_xonly_pubkey, sign_schnorr, tweak_add_privkey,
)
from test_framework.messages import (
    CTransaction, CTxIn, CTxOut, COutPoint, CTxInWitness,
)

FLAGS = "P2SH,WITNESS,TAPROOT,NULLDUMMY,CHECKLOCKTIMEVERIFY,CHECKSEQUENCEVERIFY,DERSIG"
AMOUNT = 100_000_000


def spend_tx(spk):
    tx = CTransaction()
    tx.version = 2
    tx.vin = [CTxIn(COutPoint(0x0101010101010101010101010101010101010101010101010101010101010101, 0),
                    b"", 0xFFFFFFFF)]
    tx.vout = [CTxOut(AMOUNT - 1000, CScript([OP_1]))]
    tx.wit.vtxinwit = [CTxInWitness()]
    tx.nLockTime = 0
    return tx


def record(tx, spk, comment):
    prevout = CTxOut(AMOUNT, spk)
    return {
        "tx": tx.serialize_with_witness().hex(),
        "prevouts": [{"scriptPubKey": spk.hex(), "amountSats": AMOUNT}],
        "index": 0,
        "flags": FLAGS,
        "comment": comment,
    }


def keypath(hash_type, with_annex=False):
    priv = generate_privkey()
    pub, _ = compute_xonly_pubkey(priv)
    tap = taproot_construct(pub)
    tx = spend_tx(tap.scriptPubKey)
    prevout = CTxOut(AMOUNT, tap.scriptPubKey)
    annex = bytes([0x50]) + b"\x00\x01\x02\x03" if with_annex else None
    sighash = TaprootSignatureHash(tx, [prevout], hash_type, input_index=0, annex=annex)
    key_t = tweak_add_privkey(priv, tap.tweak)
    sig = sign_schnorr(key_t, sighash)
    if hash_type != SIGHASH_DEFAULT:
        sig += bytes([hash_type])
    stack = [sig]
    if annex is not None:
        stack.append(annex)
    tx.wit.vtxinwit[0].scriptWitness.stack = stack
    return record(tx, tap.scriptPubKey,
                  f"keypath hashtype=0x{hash_type:02x} annex={with_annex}")


def scriptpath(codesep=False):
    priv = generate_privkey()
    pub, _ = compute_xonly_pubkey(priv)
    if codesep:
        # OP_CODESEPARATOR after a 10-byte push + OP_DROP: opcode index 2,
        # but byte offset 12 — so this vector only verifies if the sighash
        # commits the OPCODE INDEX (not the byte offset).
        leaf = CScript([bytes(10), OP_DROP, OP_CODESEPARATOR, pub, OP_CHECKSIG])
        codeseparator_pos = 2
    else:
        leaf = CScript([pub, OP_CHECKSIG])
        codeseparator_pos = 0xFFFFFFFF
    tap = taproot_construct(pub, [("leaf", leaf)])
    tx = spend_tx(tap.scriptPubKey)
    prevout = CTxOut(AMOUNT, tap.scriptPubKey)
    leaf_info = tap.leaves["leaf"]
    sighash = TaprootSignatureHash(
        tx, [prevout], SIGHASH_DEFAULT, input_index=0,
        scriptpath=True, leaf_script=leaf, codeseparator_pos=codeseparator_pos)
    sig = sign_schnorr(priv, sighash)
    controlblock = (bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey
                    + leaf_info.merklebranch)
    tx.wit.vtxinwit[0].scriptWitness.stack = [sig, bytes(leaf), controlblock]
    return record(tx, tap.scriptPubKey,
                  f"scriptpath checksig codesep={codesep}")


def main():
    recs = [
        keypath(SIGHASH_DEFAULT),
        keypath(SIGHASH_ALL | SIGHASH_ANYONECANPAY),
        scriptpath(codesep=False),
        keypath(SIGHASH_DEFAULT, with_annex=True),
        scriptpath(codesep=True),
    ]
    json.dump(recs, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
