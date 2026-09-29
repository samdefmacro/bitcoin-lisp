// Generate tests/data/minisketch_cpp_vectors.json from BITCOIN CORE's minisketch
// C++ LIBRARY itself (refs/bitcoin/src/minisketch/, pin d3056bc149), the code a
// Core node links -- not the Python reimplementation that
// tests/data/minisketch_core_vectors.py drives.
//
// Built and run by scripts/minisketch-cpp-vectors.sh, inside a derivative of
// the project image that adds g++ (docker/minisketch-cpp.Dockerfile). The
// library is compiled the way Core compiles it (cmake/minisketch.cmake:54-57:
// DISABLE_DEFAULT_FIELDS + ENABLE_FIELD_32, the generic field implementations;
// the CLMUL ones exist only on x86_64 and compute the same field).
//
// Sketches, merges, serializations and decodes go through the public C API
// (include/minisketch.h: minisketch_create(32, 0, capacity), add_uint64,
// serialize, deserialize, merge, set_seed, decode). The field products and
// inverses have no API, so this translation unit INCLUDES the library's own
// fields/generic_4bytes.cpp -- which also provides ConstructGeneric4Bytes to the
// library, so that file is not compiled separately -- and calls its Field32
// (Mul = GFMul, Inv = InvExtGCD) directly.
//
// The inputs are the Python generator's, draw for draw: PyRandom below is
// CPython's Mersenne Twister (Modules/_randommodule.c init_by_array,
// genrand_uint32, getrandbits) and Lib/random.py's randrange, so
// random.Random(330) yields the same elements, capacities and byte strings
// here as there, and every section the two files share can be compared field
// for field. Sections only this file had first are drawn from
// random.Random(3301), which the Python generator uses for the same sections.
//
// Every decode is run under six splitting bases (minisketch_set_seed with -1,
// 0, 1, 330, 2^32+7 and the library's own random default) and the generator
// aborts if the verdicts differ: the port draws its basis at random, so a
// basis-dependent verdict would be a flaky oracle.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#define DISABLE_DEFAULT_FIELDS
#define ENABLE_FIELD_32
#include "fields/generic_4bytes.cpp"   // Field32 + ConstructGeneric4Bytes
#include <minisketch.h>

namespace {

// --- CPython's random.Random ----------------------------------------------------

class PyRandom {
    static constexpr int N = 624, M = 397;
    uint32_t mt[N];
    int mti = N + 1;

    void init_genrand(uint32_t s) {
        mt[0] = s;
        for (mti = 1; mti < N; mti++) {
            mt[mti] = 1812433253U * (mt[mti - 1] ^ (mt[mti - 1] >> 30)) + mti;
        }
    }

public:
    // random.seed(n) for a non-negative n below 2^32: init_by_array({n}).
    explicit PyRandom(uint32_t seed) {
        const uint32_t key[1] = {seed};
        const int key_length = 1;
        init_genrand(19650218U);
        int i = 1, j = 0;
        for (int k = std::max(N, key_length); k; k--) {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525U)) + key[j] + j;
            i++; j++;
            if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
            if (j >= key_length) j = 0;
        }
        for (int k = N - 1; k; k--) {
            mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941U)) - i;
            i++;
            if (i >= N) { mt[0] = mt[N - 1]; i = 1; }
        }
        mt[0] = 0x80000000U;
    }

    uint32_t genrand_uint32() {
        static const uint32_t mag01[2] = {0x0U, 0x9908b0dfU};
        uint32_t y;
        if (mti >= N) {
            int kk;
            for (kk = 0; kk < N - M; kk++) {
                y = (mt[kk] & 0x80000000U) | (mt[kk + 1] & 0x7fffffffU);
                mt[kk] = mt[kk + M] ^ (y >> 1) ^ mag01[y & 0x1U];
            }
            for (; kk < N - 1; kk++) {
                y = (mt[kk] & 0x80000000U) | (mt[kk + 1] & 0x7fffffffU);
                mt[kk] = mt[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1U];
            }
            y = (mt[N - 1] & 0x80000000U) | (mt[0] & 0x7fffffffU);
            mt[N - 1] = mt[M - 1] ^ (y >> 1) ^ mag01[y & 0x1U];
            mti = 0;
        }
        y = mt[mti++];
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680U;
        y ^= (y << 15) & 0xefc60000U;
        y ^= (y >> 18);
        return y;
    }

    // getrandbits(k), 1 <= k <= 64: 32-bit words, least significant first,
    // the last one shifted down to its remaining width.
    uint64_t getrandbits(int k) {
        if (k <= 32) return genrand_uint32() >> (32 - k);
        uint64_t lo = genrand_uint32();
        uint64_t hi = genrand_uint32() >> (64 - k);
        return lo | (hi << 32);
    }

    // _randbelow_with_getrandbits: k = n.bit_length(), redraw while r >= n.
    uint64_t randbelow(uint64_t n) {
        int k = 64 - __builtin_clzll(n);
        uint64_t r = getrandbits(k);
        while (r >= n) r = getrandbits(k);
        return r;
    }

    uint64_t randrange(uint64_t stop) { return randbelow(stop); }
    uint64_t randrange(uint64_t start, uint64_t stop) { return start + randbelow(stop - start); }
};

// --- JSON, printed the way Python's json.dump(indent=1) prints it ----------------

struct Json {
    enum Kind { NUL, NUM, STR, ARR, OBJ } kind = NUL;
    uint64_t num = 0;
    std::string str;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;

    static Json null() { return Json(); }
    static Json number(uint64_t n) { Json j; j.kind = NUM; j.num = n; return j; }
    static Json string(const std::string& s) { Json j; j.kind = STR; j.str = s; return j; }
    static Json array() { Json j; j.kind = ARR; return j; }
    static Json object() { Json j; j.kind = OBJ; return j; }
    static Json numbers(const std::vector<uint64_t>& v) {
        Json j = array();
        for (uint64_t n : v) j.arr.push_back(number(n));
        return j;
    }

    Json& set(const std::string& k, Json v) { obj.emplace_back(k, std::move(v)); return *this; }
    Json& set(const std::string& k, uint64_t v) { return set(k, number(v)); }
    Json& set(const std::string& k, const char* v) { return set(k, string(v)); }
    Json& set(const std::string& k, const std::string& v) { return set(k, string(v)); }
    void push(Json v) { arr.push_back(std::move(v)); }

    void dump(std::string& out, int depth) const {
        auto nl = [&](int d) { out += '\n'; out.append(d, ' '); };
        switch (kind) {
        case NUL: out += "null"; break;
        case NUM: out += std::to_string(num); break;
        case STR:
            out += '"';
            for (char c : str) {
                if (c == '"' || c == '\\') out += '\\';
                out += c;
            }
            out += '"';
            break;
        case ARR:
            if (arr.empty()) { out += "[]"; break; }
            out += '[';
            for (size_t i = 0; i < arr.size(); ++i) {
                if (i) out += ',';
                nl(depth + 1);
                arr[i].dump(out, depth + 1);
            }
            nl(depth); out += ']';
            break;
        case OBJ:
            if (obj.empty()) { out += "{}"; break; }
            out += '{';
            for (size_t i = 0; i < obj.size(); ++i) {
                if (i) out += ',';
                nl(depth + 1);
                out += '"'; out += obj[i].first; out += "\": ";
                obj[i].second.dump(out, depth + 1);
            }
            nl(depth); out += '}';
            break;
        }
    }
};

// --- The library, through its C API ---------------------------------------------

constexpr uint32_t BITS = 32;
const Field32 FIELD;

struct Sketch {
    minisketch* s;
    explicit Sketch(size_t capacity) : s(minisketch_create(BITS, 0, capacity)) {
        if (!s) { fprintf(stderr, "minisketch_create(32, 0, %zu) failed\n", capacity); exit(1); }
    }
    ~Sketch() { minisketch_destroy(s); }
    Sketch(const Sketch&) = delete;
    Sketch& operator=(const Sketch&) = delete;

    void add(uint64_t e) { minisketch_add_uint64(s, e); }
    std::vector<unsigned char> serialize() const {
        std::vector<unsigned char> out(minisketch_serialized_size(s));
        minisketch_serialize(s, out.data());
        return out;
    }
    void deserialize(const std::vector<unsigned char>& in) {
        if (in.size() != minisketch_serialized_size(s)) {
            fprintf(stderr, "deserialize: %zu bytes for capacity %zu\n", in.size(), minisketch_capacity(s));
            exit(1);
        }
        minisketch_deserialize(s, in.data());
    }
};

std::string hex_of(const std::vector<unsigned char>& b) {
    static const char* d = "0123456789abcdef";
    std::string h;
    for (unsigned char c : b) { h += d[c >> 4]; h += d[c & 15]; }
    return h;
}

std::vector<unsigned char> bytes_of(const std::string& h) {
    std::vector<unsigned char> b;
    for (size_t i = 0; i + 1 < h.size(); i += 2) b.push_back(std::stoi(h.substr(i, 2), nullptr, 16));
    return b;
}

std::string sketch_hex(const std::vector<uint64_t>& elements, size_t capacity) {
    Sketch sk(capacity);
    for (uint64_t e : elements) sk.add(e);
    return hex_of(sk.serialize());
}

// minisketch_decode's verdict as the vectors state it: the sorted elements, or
// null for -1. One sketch, decoded under every basis in SEEDS.
Json decode_hex(const std::string& hex, size_t capacity, size_t max_count, const std::string& what) {
    static const uint64_t SEEDS[] = {(uint64_t)-1, 0, 1, 330, (1ULL << 32) + 7};
    const auto bytes = bytes_of(hex);
    std::vector<std::vector<uint64_t>> verdicts;   // {1} + elements, or {0}
    for (int round = 0; round <= 5; ++round) {
        Sketch sk(capacity);
        sk.deserialize(bytes);
        if (round < 5) minisketch_set_seed(sk.s, SEEDS[round]);   // round 5: the random default
        std::vector<uint64_t> out(max_count + 1);
        ssize_t n = minisketch_decode(sk.s, max_count, out.data());
        std::vector<uint64_t> v;
        if (n < 0) {
            v.push_back(0);
        } else {
            v.push_back(1);
            std::vector<uint64_t> got(out.begin(), out.begin() + n);
            std::sort(got.begin(), got.end());
            v.insert(v.end(), got.begin(), got.end());
        }
        verdicts.push_back(v);
    }
    for (const auto& v : verdicts) {
        if (v != verdicts[0]) {
            fprintf(stderr, "FINDING: the decode verdict depends on the splitting basis (%s, capacity %zu, %s)\n",
                    what.c_str(), capacity, hex.c_str());
            exit(2);
        }
    }
    if (verdicts[0][0] == 0) return Json::null();
    return Json::numbers(std::vector<uint64_t>(verdicts[0].begin() + 1, verdicts[0].end()));
}

std::vector<uint64_t> random_elements(PyRandom& rng, size_t n) {
    std::vector<uint64_t> v;
    for (size_t i = 0; i < n; ++i) v.push_back(rng.randrange(1, 1ULL << BITS));
    return v;
}

std::string random_bytes_hex(PyRandom& rng, size_t n) {
    std::vector<unsigned char> b;
    for (size_t i = 0; i < n; ++i) b.push_back(rng.randrange(256));
    return hex_of(b);
}

// The Core minisketch_tests.cpp:21-47 draw, with `both` below BOTH_LIMIT.
Json reconcile_case(PyRandom& rng, uint64_t both_limit) {
    uint64_t errors = rng.randrange(11);
    uint64_t start_a = 1 + rng.randrange(1000000000);
    uint64_t a_not_b = rng.randrange(errors + 1);
    uint64_t b_not_a = errors - a_not_b;
    uint64_t both = rng.randrange(both_limit);
    uint64_t end_a = start_a + a_not_b + both;
    uint64_t start_b = start_a + a_not_b;
    uint64_t end_b = start_b + both + b_not_a;
    Sketch a(10), b(10);
    for (uint64_t x = start_a; x < end_a; ++x) a.add(x);
    for (uint64_t x = start_b; x < end_b; ++x) b.add(x);
    std::string ha = hex_of(a.serialize()), hb = hex_of(b.serialize());
    // Through the wire form, as the protocol and Core's test both do.
    Sketch ar(10), br(10);
    ar.deserialize(a.serialize());
    br.deserialize(b.serialize());
    if (minisketch_merge(ar.s, br.s) != 10) { fprintf(stderr, "merge failed\n"); exit(1); }
    std::string hm = hex_of(ar.serialize());
    return Json::object()
        .set("start_a", start_a).set("end_a", end_a).set("start_b", start_b).set("end_b", end_b)
        .set("capacity", 10).set("max_count", errors)
        .set("hex_a", ha).set("hex_b", hb).set("hex_merged", hm)
        .set("decoded", decode_hex(hm, 10, errors, "reconcile"));
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s OUTPUT.json\n", argv[0]); return 1; }
    if (!minisketch_implementation_supported(BITS, 0)) { fprintf(stderr, "no 32-bit field\n"); return 1; }

    PyRandom rng(330);
    Json out = Json::object();
    out.set("source", "refs/bitcoin/src/minisketch (the C++ library, implementation 0) @ d3056bc149"
                      ", via tests/data/minisketch_cpp_vectors.cpp");

    // --- Field: GF(2^32) mod x^32+x^7+x^3+x^2+1 --------------------------------
    std::vector<std::pair<uint64_t, uint64_t>> pairs = {
        {1, 1}, {2, 3}, {0x80000000, 2}, {0xFFFFFFFF, 0xFFFFFFFF},
        {0x12345678, 0x9ABCDEF0}, {0xDEADBEEF, 0xCAFEBABE}, {0x8D, 0x8D}};
    for (int i = 0; i < 24; ++i) {
        uint64_t a = rng.randrange(1, 1ULL << BITS);
        uint64_t b = rng.randrange(1, 1ULL << BITS);
        pairs.emplace_back(a, b);
    }
    Json mul = Json::array();
    for (auto [a, b] : pairs) {
        mul.push(Json::object().set("a", a).set("b", b).set("r", (uint64_t)FIELD.Mul(a, b)));
    }
    out.set("mul", mul);
    std::vector<uint64_t> invs = {1, 2, 3, 0x8D, 0x12345678, 0xFFFFFFFF};
    for (int i = 0; i < 12; ++i) invs.push_back(rng.randrange(1, 1ULL << BITS));
    Json inv = Json::array();
    for (uint64_t a : invs) inv.push(Json::object().set("a", a).set("r", (uint64_t)FIELD.Inv(a)));
    out.set("inv", inv);

    // --- Sketch serialization ----------------------------------------------------
    std::vector<std::pair<std::vector<uint64_t>, size_t>> sk = {
        {{1}, 1}, {{1, 2, 3}, 3}, {{0x11111111, 0x22222222}, 2},
        {{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10},
        {{0xDEADBEEF, 0xCAFEBABE, 0x12345678, 1, 0xFFFFFFFF}, 5},
        {{}, 4}, {{7, 7}, 3}, {{5}, 0}};
    for (size_t cap : {1, 2, 3, 8, 16, 33}) {
        size_t n = rng.randrange(0, 2 * cap + 2);
        sk.emplace_back(random_elements(rng, n), cap);
    }
    Json sketches = Json::array();
    for (const auto& [elements, cap] : sk) {
        sketches.push(Json::object().set("elements", Json::numbers(elements)).set("capacity", cap)
                          .set("hex", sketch_hex(elements, cap)));
    }
    out.set("sketch", sketches);

    // --- Merge + decode: Core's own minisketch_tests.cpp scenario --------------
    Json recon = Json::array();
    for (int i = 0; i < 12; ++i) recon.push(reconcile_case(rng, 60));
    out.set("reconcile", recon);

    // --- Decode verdicts, including every failure shape --------------------------
    Json dec = Json::array();
    auto add_decode = [&](const std::string& hex, size_t cap, Json max_count, const char* why) {
        size_t mc = max_count.kind == Json::NUL ? cap : max_count.num;
        Json verdict = decode_hex(hex, cap, mc, why);
        dec.push(Json::object().set("capacity", cap).set("max_count", std::move(max_count))
                     .set("hex", hex).set("decoded", std::move(verdict)).set("why", why));
    };
    add_decode("", 0, Json::null(), "capacity 0 decodes to the empty set");
    add_decode(std::string(32, '0'), 4, Json::null(), "an all-zero sketch is the empty set, a success");
    add_decode(sketch_hex({1, 2, 3, 4, 5}, 2), 2, Json::null(),
               "an over-full sketch that still decodes -- to a different set");
    for (auto [n, cap] : std::vector<std::pair<size_t, size_t>>{{3, 2}, {5, 4}, {9, 8}, {4, 3}}) {
        add_decode(sketch_hex(random_elements(rng, n), cap), cap, Json::null(),
                   "one more element than the capacity");
    }
    for (auto [n, cap, mc] : std::vector<std::tuple<size_t, size_t, size_t>>{
             {4, 6, 3}, {6, 6, 5}, {2, 2, 1}, {3, 5, 0}}) {
        add_decode(sketch_hex(random_elements(rng, n), cap), cap, Json::number(mc),
                   "max_count below the true size");
    }
    for (size_t cap : {2, 3, 4, 5, 6, 8}) {
        add_decode(std::string(8 * (cap - 1), '0') + "05000000", cap, Json::null(),
                   "only the highest odd syndrome set: the LFSR outgrows the capacity");
    }
    for (size_t cap : {1, 2, 3, 4, 5, 6, 7, 12}) {
        for (int i = 0; i < 12; ++i) {
            add_decode(random_bytes_hex(rng, 4 * cap), cap, Json::null(), "random bytes");
        }
    }
    for (size_t cap : {6, 20, 40}) {
        add_decode(sketch_hex(random_elements(rng, cap), cap), cap, Json::null(), "full to capacity");
    }
    out.set("decode", dec);

    // --- Sections drawn from random.Random(3301) ---------------------------------
    PyRandom rng2(3301);

    // Capacity edges: 0, 1, 2; 128, the largest first sketch the node's
    // reconciliation accepts (+RECON-MAX-SKETCH-CAPACITY+); 129, one it
    // refuses at that layer although the library takes it; 256, the doubled
    // capacity an extension decodes at. Each full, then one past full.
    Json caps = Json::array();
    for (size_t cap : {0, 1, 2, 128, 129, 256}) {
        for (size_t extra : {0, 1}) {
            auto elements = random_elements(rng2, cap + extra);
            std::string hex = sketch_hex(elements, cap);
            caps.push(Json::object().set("capacity", cap).set("elements", Json::numbers(elements))
                          .set("hex", hex).set("decoded", decode_hex(hex, cap, cap, "capacity edge")));
        }
    }
    out.set("capacity", caps);

    // Elements the field cannot hold as given: 0 (a no-op), and values at or
    // above 2^32, which lose their high bits (Field::FromUint64 masks) -- so
    // 2^32 is 0 again, and x + 2^32 cancels x.
    const std::vector<std::vector<uint64_t>> edge_sets = {
        {0}, {0, 0, 0}, {1ULL << 32}, {(1ULL << 32) + 1}, {(1ULL << 32) + 1, 1},
        {0xFFFFFFFFULL}, {0xFFFFFFFF00000000ULL}, {0xFFFFFFFFFFFFFFFFULL},
        {0, 5, (1ULL << 33) + 9, 0x123456789ABCDEF0ULL}, {0x8000000000000000ULL, 3, 0}};
    Json edges = Json::array();
    for (const auto& elements : edge_sets) {
        std::string hex = sketch_hex(elements, 4);
        edges.push(Json::object().set("capacity", 4).set("elements", Json::numbers(elements))
                       .set("hex", hex).set("decoded", decode_hex(hex, 4, 4, "element edge")));
    }
    out.set("element_edges", edges);

    // Random sets: a capacity, a set of up to two past it, the sketch, and the
    // verdict at max_count = capacity and at a random max_count.
    Json rnd = Json::array();
    for (int i = 0; i < 48; ++i) {
        size_t cap = rng2.randrange(1, 41);
        size_t n = rng2.randrange(0, cap + 3);
        size_t mc = rng2.randrange(0, cap + 1);
        auto elements = random_elements(rng2, n);
        std::string hex = sketch_hex(elements, cap);
        rnd.push(Json::object().set("capacity", cap).set("elements", Json::numbers(elements))
                     .set("hex", hex).set("decoded", decode_hex(hex, cap, cap, "random set"))
                     .set("max_count", mc).set("decoded_max", decode_hex(hex, cap, mc, "random set")));
    }
    out.set("random", rnd);

    // Core's minisketch_tests.cpp scenario at its own range (both < 10000).
    Json wide = Json::array();
    for (int i = 0; i < 8; ++i) wide.push(reconcile_case(rng2, 10000));
    out.set("reconcile_wide", wide);

    std::string text;
    out.dump(text, 0);
    text += '\n';
    FILE* f = fopen(argv[1], "w");
    if (!f || fwrite(text.data(), 1, text.size(), f) != text.size() || fclose(f) != 0) {
        fprintf(stderr, "cannot write %s\n", argv[1]);
        return 1;
    }
    printf("wrote %s: mul %zu, inv %zu, sketch %zu, reconcile %zu, decode %zu, capacity %zu, "
           "element_edges %zu, random %zu, reconcile_wide %zu\n", argv[1], mul.arr.size(),
           inv.arr.size(), sketches.arr.size(), recon.arr.size(), dec.arr.size(), caps.arr.size(),
           edges.arr.size(), rnd.arr.size(), wide.arr.size());
    return 0;
}
