#!/usr/bin/env python3
"""Generate tests/data/minisketch_core_vectors.json from BITCOIN CORE's code.

The oracle is refs/bitcoin/src/minisketch/tests/pyminisketch.py, the Python
reimplementation of libminisketch's algorithms that Core vendors with the C++
library (same moduli, same odd-syndrome layout, same little-endian bit-packed
serialization, same Berlekamp-Massey + Berlekamp-trace decode and the same
failure verdicts), and Core's functional-test SipHash
(test/functional/test_framework/crypto/siphash.py) for the BIP-330 short IDs.
The C++ library itself cannot be compiled in the project container (the
runtime image carries no C++ compiler), so this is the strongest executable
Core oracle available there; the C library's own field tables
(fields/generic_4bytes.cpp:88-90) are checked directly by the Lisp tests.

Run inside the project container from the repository root:

  scripts/dev.sh eval '(uiop:run-program (list "python3" "tests/data/minisketch_core_vectors.py") :output :string)'

Deterministic: every random draw comes from random.Random(330), and a decode's
answer is a sorted SET, independent of the random root-finding basis.
"""

import hashlib
import json
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "refs/bitcoin/src/minisketch/tests"))
sys.path.insert(0, os.path.join(ROOT, "refs/bitcoin/test/functional"))

from pyminisketch import GF2Ops, Minisketch                    # noqa: E402
from test_framework.crypto.siphash import siphash256            # noqa: E402

BITS = 32
rng = random.Random(330)
gf = GF2Ops(BITS)


def sketch_of(elements, capacity):
    s = Minisketch(BITS, capacity)
    for e in elements:
        s.add(e)
    return s


def decode_hex(hexstr, capacity, max_count=None):
    s = Minisketch(BITS, capacity)
    s.deserialize(bytes.fromhex(hexstr))
    r = s.decode(max_count)
    return None if r is None else sorted(r)


out = {"source": "refs/bitcoin/src/minisketch/tests/pyminisketch.py @ d3056bc149"}

# --- Field: GF(2^32) mod x^32+x^7+x^3+x^2+1 ------------------------------------
pairs = [(1, 1), (2, 3), (0x80000000, 2), (0xFFFFFFFF, 0xFFFFFFFF),
         (0x12345678, 0x9ABCDEF0), (0xDEADBEEF, 0xCAFEBABE), (0x8D, 0x8D)]
pairs += [(rng.randrange(1, 1 << BITS), rng.randrange(1, 1 << BITS)) for _ in range(24)]
out["mul"] = [{"a": a, "b": b, "r": gf.mul(a, b)} for a, b in pairs]
invs = [1, 2, 3, 0x8D, 0x12345678, 0xFFFFFFFF] + [rng.randrange(1, 1 << BITS) for _ in range(12)]
out["inv"] = [{"a": a, "r": gf.inv(a)} for a in invs]

# --- Sketch serialization -----------------------------------------------------
sk = []
fixed = [([1], 1), ([1, 2, 3], 3), ([0x11111111, 0x22222222], 2),
         (list(range(1, 11)), 10), ([0xDEADBEEF, 0xCAFEBABE, 0x12345678, 1, 0xFFFFFFFF], 5),
         ([], 4), ([7, 7], 3), ([5], 0)]
for elements, cap in fixed:
    sk.append((elements, cap))
for cap in (1, 2, 3, 8, 16, 33):
    n = rng.randrange(0, 2 * cap + 2)
    sk.append(([rng.randrange(1, 1 << BITS) for _ in range(n)], cap))
out["sketch"] = [{"elements": e, "capacity": c, "hex": sketch_of(e, c).serialize().hex()}
                 for e, c in sk]

# --- Merge + decode: Core's own minisketch_tests.cpp scenario ----------------
# (src/test/minisketch_tests.cpp:21-47: capacity 10, up to 10 differences
# between two overlapping integer ranges), with its random draws taken here.
recon = []
for _ in range(12):
    errors = rng.randrange(11)
    start_a = 1 + rng.randrange(1000000000)
    a_not_b = rng.randrange(errors + 1)
    b_not_a = errors - a_not_b
    both = rng.randrange(60)
    end_a = start_a + a_not_b + both
    start_b = start_a + a_not_b
    end_b = start_b + both + b_not_a
    a = sketch_of(range(start_a, end_a), 10)
    b = sketch_of(range(start_b, end_b), 10)
    ha, hb = a.serialize().hex(), b.serialize().hex()
    a.merge(b)
    recon.append({"start_a": start_a, "end_a": end_a, "start_b": start_b, "end_b": end_b,
                  "capacity": 10, "max_count": errors,
                  "hex_a": ha, "hex_b": hb, "hex_merged": a.serialize().hex(),
                  "decoded": decode_hex(a.serialize().hex(), 10, errors)})
out["reconcile"] = recon

# --- Decode verdicts, including every failure shape --------------------------
dec = []
def add_decode(hexstr, cap, max_count, why):
    dec.append({"capacity": cap, "max_count": max_count, "hex": hexstr,
                "decoded": decode_hex(hexstr, cap, max_count), "why": why})

add_decode("", 0, None, "capacity 0 decodes to the empty set")
add_decode("00" * 16, 4, None, "an all-zero sketch is the empty set, a success")
add_decode(sketch_of([1, 2, 3, 4, 5], 2).serialize().hex(), 2, None,
           "an over-full sketch that still decodes -- to a different set")
for n, cap in ((3, 2), (5, 4), (9, 8), (4, 3)):
    add_decode(sketch_of([rng.randrange(1, 1 << BITS) for _ in range(n)], cap).serialize().hex(),
               cap, None, "one more element than the capacity")
for n, cap, mc in ((4, 6, 3), (6, 6, 5), (2, 2, 1), (3, 5, 0)):
    add_decode(sketch_of([rng.randrange(1, 1 << BITS) for _ in range(n)], cap).serialize().hex(),
               cap, mc, "max_count below the true size")
for cap in (2, 3, 4, 5, 6, 8):
    # BM LFSR longer than the capacity: odd syndromes zero except the last.
    add_decode("00" * (4 * (cap - 1)) + "05000000", cap, None,
               "only the highest odd syndrome set: the LFSR outgrows the capacity")
for cap in (1, 2, 3, 4, 5, 6, 7, 12):
    for _ in range(12):
        add_decode(bytes(rng.randrange(256) for _ in range(4 * cap)).hex(), cap, None,
                   "random bytes")
for cap in (6, 20, 40):
    n = cap
    add_decode(sketch_of([rng.randrange(1, 1 << BITS) for _ in range(n)], cap).serialize().hex(),
               cap, None, "full to capacity")
out["decode"] = dec

# --- BIP-330 salts and short IDs ----------------------------------------------
TAG = hashlib.sha256(b"Tx Relay Salting").digest()
def salt(s1, s2):
    lo, hi = min(s1, s2), max(s1, s2)
    h = hashlib.sha256(TAG + TAG + lo.to_bytes(8, "little") + hi.to_bytes(8, "little")).digest()
    return int.from_bytes(h[0:8], "little"), int.from_bytes(h[8:16], "little")

ids = []
for s1, s2 in ((1, 2), (0, 0xFFFFFFFFFFFFFFFF), (rng.getrandbits(64), rng.getrandbits(64))):
    k0, k1 = salt(s1, s2)
    for _ in range(6):
        wtxid = bytes(rng.randrange(256) for _ in range(32))
        s = siphash256(k0, k1, int.from_bytes(wtxid, "little"))
        ids.append({"salt1": s1, "salt2": s2, "k0": k0, "k1": k1,
                    "wtxid_internal_hex": wtxid.hex(), "siphash": s,
                    "short_id": 1 + (s % 0xFFFFFFFF)})
out["short_id"] = ids

path = os.path.join(ROOT, "tests/data/minisketch_core_vectors.json")
with open(path, "w") as f:
    json.dump(out, f, indent=1)
    f.write("\n")
print("wrote", path, {k: len(v) for k, v in out.items() if isinstance(v, list)})
