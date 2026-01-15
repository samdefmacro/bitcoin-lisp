# Design: Coalton Static Typing Integration

## Context

Bitcoin-lisp is a full node implementation where correctness is paramount. The codebase currently uses Common Lisp's `defstruct` with type declarations that are only checked at runtime (and often ignored). Coalton provides a way to add compile-time type safety while maintaining interoperability with existing CL libraries (ironclad, cffi, usocket).

### Constraints
- Must maintain compatibility with existing CL libraries (ironclad, cffi, usocket)
- Gradual migration required - cannot break working code
- Consensus-critical code must remain verifiable
- SBCL is the primary target (Coalton has limited cross-implementation support)

### Stakeholders
- Bitcoin developers relying on correct validation
- Contributors who need to understand the type system

## Goals / Non-Goals

### Goals
- Catch type errors at compile time, especially around byte arrays and numeric types
- Provide clear, domain-specific types (Hash256 vs generic byte array)
- Enable gradual migration without breaking existing functionality
- Maintain full interoperability with CL ecosystem

### Non-Goals
- Complete rewrite of all modules immediately
- Support for all CL implementations (focus on SBCL)
- Formal verification (out of scope, but types improve verifiability)

## Decisions

### Decision 1: Phased Module Migration

**What**: Migrate modules in order: (1) Core types, (2) Crypto, (3) Serialization, (4) Validation, (5) Networking

**Why**:
- Core types have no dependencies, lowest risk starting point
- Crypto/Serialization are highest-value targets (most type-sensitive)
- Validation depends on both, natural next step
- Networking is most coupled to external libraries, highest risk

**Alternatives considered**:
- Full rewrite: Rejected - too risky, breaks working code
- New code only: Rejected - doesn't address existing type risks

### Decision 2: Wrapper Pattern for CL Interop

**What**: Create thin wrapper functions that convert between Coalton types and CL types at module boundaries.

```
CL World                    Coalton World
---------                   -------------
(unsigned-byte 8) array <-> (ByteArray 32)
integer                 <-> Satoshi
defstruct              <-> define-type
```

**Why**: Allows existing CL code (tests, libraries) to continue working while new typed code is added.

**Alternatives considered**:
- Direct replacement: Rejected - would break all callers immediately
- Parallel implementations: Rejected - maintenance burden, divergence risk

### Decision 3: Domain-Specific Newtypes

**What**: Use Coalton newtypes to distinguish semantically different byte arrays:

```coalton
(define-type Hash256 (Hash256 (Vector UFix8)))
(define-type Hash160 (Hash160 (Vector UFix8)))
(define-type Satoshi (Satoshi Integer))
(define-type BlockHeight (BlockHeight UFix32))
```

**Why**: Prevents mixing up hashes of different lengths, or confusing satoshi amounts with block heights. The compiler rejects `(verify-signature (Hash160 ...) ...)` when `Hash256` is expected.

**Alternatives considered**:
- Type aliases: Rejected - no compile-time distinction
- Raw vectors everywhere: Rejected - current state, loses semantic information

### Decision 4: Algebraic Data Types for Protocol Structures

**What**: Model Bitcoin structures as Coalton ADTs:

```coalton
(define-type Outpoint
  (Outpoint Hash256 UFix32))

(define-type TxIn
  (TxIn Outpoint ByteArray UFix32))

(define-type TxOut
  (TxOut Satoshi ByteArray))

(define-type Transaction
  (Transaction IFix32 (List TxIn) (List TxOut) UFix32))
```

**Why**:
- Pattern matching for exhaustive handling
- Immutable by default (safer for consensus code)
- Clear field types enforced at compile time

### Decision 5: Git Submodule for Coalton Dependency

**What**: Use a git submodule at `coalton/` in the project root for the Coalton dependency.

**Why**:
- Ensures reproducible builds with exact Coalton version pinned
- No dependency on Quicklisp availability or version
- Allows local patches if needed during Coalton's pre-1.0 phase
- Simplifies CI setup (no network fetch required)

**Location**: `coalton/` (already present in project root)

### Decision 6: Unified Test Infrastructure

**What**: Integrate Coalton tests with the existing fiveam test suite, adding compile-time type rejection tests and property-based tests.

**Why**:
- Single `asdf:test-system` command runs all tests
- Compile-time tests verify type safety actually prevents errors
- Property-based tests catch edge cases in serialization
- Maintains existing test workflow

**Test categories**:
- Unit tests: Verify typed functions produce correct results
- Type rejection tests: Verify wrong types fail at compile time
- Property tests: Random input round-trip validation
- Integration tests: CL/Coalton interop verification

## Risks / Trade-offs

| Risk | Impact | Mitigation |
|------|--------|------------|
| Coalton API instability | Medium - May need code updates | Pin version, isolate behind stable interfaces |
| Compile-time overhead | Low - Adds seconds to build | Acceptable for safety benefits |
| SBCL-only limitation | Medium - Reduces portability | Document requirement, acceptable for primary dev environment |
| Learning curve | Low - Team needs training | Start simple, provide examples, document patterns |

## Migration Plan

### Phase 1: Foundation
1. Add Coalton dependency to `bitcoin-lisp.asd`
2. Create `src/coalton/package.coalton` with core types
3. Define `Hash256`, `Hash160`, `Satoshi`, `BlockHeight` newtypes
4. Add conversion functions to/from CL types

### Phase 2: Crypto Module
1. Define typed hash function signatures
2. Implement `sha256`, `hash256`, `ripemd160`, `hash160` in Coalton
3. Create CL wrapper functions maintaining existing API
4. Verify against existing test vectors

### Phase 3: Serialization Types
1. Port `Outpoint`, `TxIn`, `TxOut`, `Transaction`, `BlockHeader` to Coalton ADTs
2. Implement typed serialization/deserialization
3. Add property tests for round-trip serialization
4. Maintain CL struct compatibility layer

### Phase 4: Validation (Future)
1. Type script execution context
2. Add typed opcode handlers
3. Implement typed signature verification

### Rollback
Each phase can be rolled back independently by removing Coalton code and reverting to CL implementations. The wrapper pattern ensures no external API changes.

## Open Questions

1. **CI integration**: How to handle Coalton compilation in GitHub Actions given SBCL requirements?
2. **FFI typing**: How to safely type the libsecp256k1 CFFI bindings through Coalton?
