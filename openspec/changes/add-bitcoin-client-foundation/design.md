# Design: Bitcoin Client Foundation

## Context

Building a Bitcoin full node in Common Lisp requires careful architectural decisions to balance:
- Correctness (consensus-critical code must be exact)
- Performance (blockchain sync, validation throughput)
- Lisp idioms (leverage CL strengths while interfacing with Bitcoin's binary protocols)

**Target**: SBCL on Linux/macOS, testnet initially.

## Goals / Non-Goals

### Goals
- Implement all Bitcoin protocol data structures with exact binary compatibility
- Connect to testnet peers and perform initial block download (IBD)
- Validate blocks and transactions according to consensus rules
- Maintain accurate UTXO set
- Clean, idiomatic Common Lisp code

### Non-Goals
- Wallet functionality (separate future proposal)
- Mining support
- Performance parity with Bitcoin Core (correctness first)
- GUI or web interface

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Bitcoin Node                          │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │ Networking  │  │ Validation  │  │    Mempool      │ │
│  │   (P2P)     │◄─┤  (Blocks/   │◄─┤  (Unconfirmed   │ │
│  │             │  │    Txs)     │  │      Txs)       │ │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────┘ │
│         │                │                              │
│  ┌──────▼──────────────▼──────┐                       │
│  │       Serialization         │                       │
│  │  (Protocol Data Structures) │                       │
│  └──────────────┬──────────────┘                       │
│                 │                                       │
│  ┌──────────────▼──────────────┐                       │
│  │          Crypto             │                       │
│  │  (SHA256, RIPEMD, secp256k1)│                       │
│  └──────────────┬──────────────┘                       │
│                 │                                       │
│  ┌──────────────▼──────────────┐                       │
│  │          Storage            │                       │
│  │  (Blocks, UTXO, Chain State)│                       │
│  └─────────────────────────────┘                       │
└─────────────────────────────────────────────────────────┘
```

## Decisions

### 1. Binary Serialization Strategy
**Decision**: Use a custom binary serialization layer with explicit byte-level control.

**Rationale**: Bitcoin's wire protocol requires exact binary compatibility. Using a dedicated serialization system ensures:
- Correct endianness handling (little-endian for most fields)
- Variable-length integer encoding (CompactSize)
- Exact byte-for-byte reproducibility for hashing

**Alternatives considered**:
- Generic serialization libraries: Rejected - too much overhead, not byte-exact
- CFFI to C structures: Rejected - loses Lisp idioms, harder to debug

### 2. Cryptographic Primitives
**Decision**: Use SBCL's native capabilities where possible, FFI to libsecp256k1 for ECDSA.

**Rationale**:
- SHA256/RIPEMD160: Can implement in pure Lisp or use ironclad library
- secp256k1: FFI to libsecp256k1 required for performance and correctness (consensus-critical)

**Dependencies**:
- `ironclad` - Hash functions
- `cffi` - Foreign function interface
- `libsecp256k1` - System library for ECDSA

### 3. Network I/O Model
**Decision**: Use SBCL's sb-bsd-sockets with a single-threaded event loop initially.

**Rationale**:
- Simpler to implement and debug
- Sufficient for testnet with limited peers
- Can migrate to multi-threaded or async later if needed

**Alternatives considered**:
- usocket: More portable but less control
- iolib: Async but more complex
- bordeaux-threads from start: Premature complexity

### 4. Storage Backend
**Decision**: Use a simple file-based storage with in-memory indices initially.

**Rationale**:
- Blocks stored as flat files (one per block or batched)
- UTXO set in memory with periodic snapshots
- Simple and debuggable for testnet scale

**Future**: May migrate to LevelDB via FFI or cl-store for larger scale.

### 5. Project Structure
**Decision**: ASDF system with clear package separation.

```
bitcoin-lisp/
├── bitcoin-lisp.asd          # System definition
├── src/
│   ├── package.lisp          # Package definitions
│   ├── crypto/
│   │   ├── hash.lisp         # SHA256, RIPEMD160, Hash256, Hash160
│   │   └── secp256k1.lisp    # ECDSA via FFI
│   ├── serialization/
│   │   ├── binary.lisp       # Binary read/write primitives
│   │   ├── types.lisp        # Core types (TxIn, TxOut, Tx, Block, etc.)
│   │   └── messages.lisp     # P2P protocol messages
│   ├── networking/
│   │   ├── connection.lisp   # TCP connections
│   │   ├── peer.lisp         # Peer state management
│   │   └── protocol.lisp     # Message handling
│   ├── validation/
│   │   ├── script.lisp       # Script interpreter
│   │   ├── transaction.lisp  # Tx validation
│   │   └── block.lisp        # Block validation
│   └── storage/
│       ├── blocks.lisp       # Block storage
│       ├── utxo.lisp         # UTXO set
│       └── chain.lisp        # Chain state
└── tests/
    └── ...
```

## Risks / Trade-offs

| Risk | Impact | Mitigation |
|------|--------|------------|
| Consensus bugs | Critical - chain splits | Extensive testing against Bitcoin Core, use test vectors |
| FFI complexity | Medium - crashes, memory issues | Careful error handling, defensive programming |
| Performance | Low - slow sync | Acceptable for testnet; optimize later |
| Library compatibility | Medium - SBCL-specific code | Document dependencies, consider portability layer later |

## Open Questions

1. **Script interpreter completeness**: Should we implement all opcodes or just common ones initially?
   - Recommendation: Start with P2PKH/P2SH, add SegWit later

2. **Test framework**: Which CL testing library?
   - Recommendation: `fiveam` - widely used, good assertions

3. **Logging strategy**: Custom or library?
   - Recommendation: `log4cl` for structured logging
