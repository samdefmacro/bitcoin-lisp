# An independent reference for minisketch over GF(2^32), written from
# refs/bitcoin/src/minisketch/doc/math.md. Deliberately naive: schoolbook
# carry-less multiply with a reduction loop, inverse by Fermat exponentiation.
MOD = 0x8D          # x^32 + x^7 + x^3 + x^2 + 1, minus the x^32 term
BITS = 32
MASK = (1 << BITS) - 1

def mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        carry = a >> (BITS - 1)
        a = (a << 1) & MASK
        if carry:
            a ^= MOD
    return r

def sqr(a):
    return mul(a, a)

def powr(a, e):
    r = 1
    while e:
        if e & 1:
            r = mul(r, a)
        a = sqr(a)
        e >>= 1
    return r

def inv(a):
    assert a != 0
    return powr(a, (1 << BITS) - 2)

def sketch(elements, capacity):
    """[s1, s3, ..., s_{2c-1}] as a list of field elements."""
    s = [0] * capacity
    for m in elements:
        assert 1 <= m <= MASK
        p = m
        m2 = sqr(m)
        for i in range(capacity):
            s[i] ^= p
            p = mul(p, m2)     # m^(2i+1) -> m^(2i+3)
    return s

def serialize(s):
    out = bytearray()
    for e in s:
        out += e.to_bytes(4, 'little')
    return bytes(out)

if __name__ == "__main__":
    import json, sys
    vectors = {}
    # Field multiplication vectors.
    pairs = [(1, 1), (2, 3), (0x80000000, 2), (0xFFFFFFFF, 0xFFFFFFFF),
             (0x12345678, 0x9ABCDEF0), (0xDEADBEEF, 0xCAFEBABE), (0x8D, 0x8D)]
    vectors["mul"] = [{"a": a, "b": b, "r": mul(a, b)} for a, b in pairs]
    vectors["inv"] = [{"a": a, "r": inv(a)} for a in
                      [1, 2, 3, 0x8D, 0x12345678, 0xFFFFFFFF]]
    # Sanity: a * inv(a) == 1
    for v in vectors["inv"]:
        assert mul(v["a"], v["r"]) == 1
    # Sketch vectors.
    sets = [([1], 1), ([1, 2, 3], 3), ([0x11111111, 0x22222222], 2),
            (list(range(1, 11)), 10),
            ([0xDEADBEEF, 0xCAFEBABE, 0x12345678, 1, 0xFFFFFFFF], 5)]
    vectors["sketch"] = [{"elements": els, "capacity": cap,
                          "terms": sketch(els, cap),
                          "hex": serialize(sketch(els, cap)).hex()}
                         for els, cap in sets]
    json.dump(vectors, sys.stdout, indent=0)
