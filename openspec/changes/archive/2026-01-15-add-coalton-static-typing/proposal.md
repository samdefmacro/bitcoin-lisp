# Change: Add Coalton Static Type Support

## Why

The bitcoin-lisp implementation handles consensus-critical operations where type errors can lead to:
- Incorrect transaction validation (loss of funds)
- Malformed block parsing (chain splits)
- Hash/signature mishandling (security vulnerabilities)

Common Lisp's dynamic typing catches these errors at runtime. Coalton provides compile-time type checking while maintaining full interoperability with existing CL code, allowing gradual migration without breaking the working implementation.

## What Changes

- **New dependency**: Add `coalton` via git submodule (already present at `coalton/`)
- **Core type definitions**: Define `Hash256`, `Hash160`, `Satoshi`, `Outpoint`, `TxIn`, `TxOut`, `Transaction`, `BlockHeader` as Coalton types with compile-time safety
- **Crypto module**: Migrate hash functions to Coalton with proper byte array typing
- **Serialization module**: Type-safe binary read/write operations with explicit width constraints
- **Interop layer**: Provide seamless conversion between Coalton and existing CL code during transition
- **Test infrastructure**:
  - Add Coalton test package integrated with fiveam
  - Add compile-time type rejection tests (verify type errors occur)
  - Add property-based tests for serialization round-trips
  - Extend CI to validate both CL and Coalton tests

## Impact

- Affected specs: None currently (this creates new capability)
- Affected code:
  - `bitcoin-lisp.asd` - Add coalton dependency, update test system
  - `src/package.lisp` - Add Coalton package integration
  - `src/crypto/hash.lisp` - Migrate to typed functions
  - `src/serialization/types.lisp` - Core protocol types
  - `src/serialization/binary.lisp` - Typed serialization primitives
  - `tests/coalton-package.lisp` - New Coalton test package
  - `tests/coalton-types-tests.lisp` - Core type tests
  - `tests/coalton-crypto-tests.lisp` - Typed crypto tests
  - `tests/coalton-serialization-tests.lisp` - ADT and serialization tests

## Risks

- **Coalton maturity**: Coalton has not reached 1.0; API may change
  - *Mitigation*: Pin to specific commit/version, isolate Coalton types behind stable interfaces
- **Build complexity**: Additional compilation step and SBCL-specific features
  - *Mitigation*: Document build requirements, add CI validation
- **Learning curve**: Team needs to understand Coalton's type system
  - *Mitigation*: Start with simple types, provide examples
