#!/usr/bin/env python3
"""
Bitcoin legacy sighash oracle for testnet4 h=118555 tx 3 input 1.
Computes what the sighash should be per Bitcoin Core's algorithm,
to compare against our computed b3a29cef... and find the divergence.

Algorithm (SIGHASH_ALL, no ANYONECANPAY):
  1. Copy tx.
  2. For each input != target: clear scriptSig.
  3. For target input: set scriptSig = subscript (with FindAndDelete of sig push).
  4. Sequence rules: keep all (SIGHASH_ALL).
  5. Outputs: keep all (SIGHASH_ALL).
  6. Append 4-byte hashtype LE.
  7. Double SHA256.
"""

import hashlib
import struct

# Inputs from the diagnostic capture.
TX_HEX = (
    "02000000027533852feb4791de81a435e9a211396b894b51586bf0994af96fa8bd867006c60100000000ffffffff"
    "7533852feb4791de81a435e9a211396b894b51586bf0994af96fa8bd867006c600000000fd72035152535455565758"
    "017101720173017401750176017701780a72315f736563726574370a72315f736563726574360a72315f7365637265"
    "74350a72315f736563726574340a72315f736563726574330a72315f736563726574320a72315f736563726574310a"
    "72315f736563726574300c72325f7365637265743131390c72325f7365637265743131380c72325f73656372657431"
    "31370c72325f7365637265743131360c72325f7365637265743131350c72325f7365637265743131340c72325f7365"
    "63726574313133...REPLACE..."
)

import sys

def dsha256(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def varint(n: int) -> bytes:
    if n < 0xfd: return bytes([n])
    if n < 0x10000: return b"\xfd" + struct.pack("<H", n)
    if n < 0x100000000: return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)

def parse_tx(b: bytes):
    p = 0
    version = struct.unpack_from("<I", b, p)[0]; p += 4
    n_in = b[p]; p += 1
    if n_in >= 0xfd:
        if n_in == 0xfd:
            n_in = struct.unpack_from("<H", b, p)[0]; p += 2
        else:
            raise NotImplementedError("large varint")
    inputs = []
    for _ in range(n_in):
        prev = b[p:p+32]; p += 32
        idx = struct.unpack_from("<I", b, p)[0]; p += 4
        sl = b[p]; p += 1
        if sl >= 0xfd:
            if sl == 0xfd:
                sl = struct.unpack_from("<H", b, p)[0]; p += 2
            elif sl == 0xfe:
                sl = struct.unpack_from("<I", b, p)[0]; p += 4
            else:
                raise NotImplementedError
        scriptsig = b[p:p+sl]; p += sl
        seq = struct.unpack_from("<I", b, p)[0]; p += 4
        inputs.append([prev, idx, scriptsig, seq])
    n_out = b[p]; p += 1
    if n_out >= 0xfd:
        raise NotImplementedError
    outputs = []
    for _ in range(n_out):
        value = struct.unpack_from("<Q", b, p)[0]; p += 8
        sl = b[p]; p += 1
        if sl >= 0xfd:
            raise NotImplementedError
        spk = b[p:p+sl]; p += sl
        outputs.append([value, spk])
    locktime = struct.unpack_from("<I", b, p)[0]; p += 4
    return version, inputs, outputs, locktime

def serialize_tx(version, inputs, outputs, locktime) -> bytes:
    out = struct.pack("<I", version)
    out += varint(len(inputs))
    for prev, idx, sig, seq in inputs:
        out += prev + struct.pack("<I", idx) + varint(len(sig)) + sig + struct.pack("<I", seq)
    out += varint(len(outputs))
    for value, spk in outputs:
        out += struct.pack("<Q", value) + varint(len(spk)) + spk
    out += struct.pack("<I", locktime)
    return out

def find_and_delete(script: bytes, pattern: bytes) -> bytes:
    """Bitcoin Core's FindAndDelete on scriptCode."""
    if not pattern or len(pattern) > len(script):
        return script
    out = bytearray()
    i = 0
    while i < len(script):
        if script[i:i+len(pattern)] == pattern:
            i += len(pattern)
        else:
            out.append(script[i])
            i += 1
    return bytes(out)

def legacy_sighash(tx_hex: str, input_idx: int, subscript_hex: str, sig_with_hashtype_hex: str, hashtype: int = 1) -> bytes:
    tx_bytes = bytes.fromhex(tx_hex)
    subscript = bytes.fromhex(subscript_hex)
    sig_full = bytes.fromhex(sig_with_hashtype_hex)
    # FindAndDelete: pattern is the *push* of the signature, i.e. length-prefixed
    # by the direct-push opcode if siglen <= 75, else PUSHDATA1/2.
    siglen = len(sig_full)
    if siglen <= 75:
        pattern = bytes([siglen]) + sig_full
    elif siglen <= 255:
        pattern = bytes([0x4c, siglen]) + sig_full
    elif siglen <= 65535:
        pattern = bytes([0x4d]) + struct.pack("<H", siglen) + sig_full
    else:
        pattern = bytes([0x4e]) + struct.pack("<I", siglen) + sig_full
    subscript_fad = find_and_delete(subscript, pattern)
    print(f"  FindAndDelete: in={len(subscript)} out={len(subscript_fad)} pattern-len={len(pattern)}")

    version, inputs, outputs, locktime = parse_tx(tx_bytes)
    # Mutate inputs per SIGHASH_ALL legacy:
    new_inputs = []
    for i, (prev, idx, _sig, seq) in enumerate(inputs):
        if i == input_idx:
            new_inputs.append([prev, idx, subscript_fad, seq])
        else:
            new_inputs.append([prev, idx, b"", seq])
    preimage = serialize_tx(version, new_inputs, outputs, locktime) + struct.pack("<I", hashtype)
    print(f"  preimage len: {len(preimage)} bytes")
    print(f"  preimage hash (single SHA256): {hashlib.sha256(preimage).hexdigest()}")
    print(f"  preimage hash (double SHA256): {dsha256(preimage).hex()}")
    return dsha256(preimage)

if __name__ == "__main__":
    # Inputs captured from the Lisp diagnostic.
    tx_hex = sys.argv[1] if len(sys.argv) > 1 else open("/tmp/118555-tx.hex").read().strip()
    subscript_hex = open("/tmp/118555-spk.hex").read().strip()
    # The sig as pushed: 60 bytes = 59 DER + 1 sighash byte. We need the FULL
    # 60-byte sig (with hashtype) for FindAndDelete.
    sig_full_hex = "303902153b78ce563f89a0ed9414f5aa28ad0d96d6795f9c630220337727dcdad75c1acb0ca731edaf9940a6ae0de52f137f94d94369f44522b81f01"
    print(f"tx hex len: {len(tx_hex)} chars = {len(tx_hex)//2} bytes")
    print(f"subscript hex len: {len(subscript_hex)} chars")
    print(f"sig (with hashtype) len: {len(sig_full_hex)//2} bytes")
    sighash = legacy_sighash(tx_hex, input_idx=1, subscript_hex=subscript_hex,
                             sig_with_hashtype_hex=sig_full_hex, hashtype=1)
    print(f"\nEXPECTED sighash: {sighash.hex()}")
    print(f"OUR sighash    : b3a29cef574d19524a11845ae92d5a45bc5ecbcfe43fe8fba8577bdd840586cb")
