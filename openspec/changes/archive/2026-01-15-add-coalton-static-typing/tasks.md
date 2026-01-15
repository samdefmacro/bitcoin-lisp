# Tasks: Add Coalton Static Type Support

## 1. Project Setup
- [x] 1.1 Add coalton dependency to `bitcoin-lisp.asd`
- [x] 1.2 Create `src/coalton/` directory structure
- [x] 1.3 Update USAGE.md with Coalton installation instructions
- [x] 1.4 Add Coalton compilation to CI workflow

## 2. Core Type Definitions
- [x] 2.1 Create `src/coalton/types.coalton` with package definition
- [x] 2.2 Define `Hash256` newtype with 32-byte constraint
- [x] 2.3 Define `Hash160` newtype with 20-byte constraint
- [x] 2.4 Define `Satoshi` newtype wrapping Integer
- [x] 2.5 Define `BlockHeight` newtype wrapping UFix32
- [x] 2.6 Implement conversion functions: `hash256->bytes`, `bytes->hash256`, etc.
- [x] 2.7 Add unit tests for type conversions

## 3. Crypto Module Migration
- [x] 3.1 Create `src/coalton/crypto.coalton`
- [x] 3.2 Implement typed `sha256 :: ByteArray -> Hash256`
- [x] 3.3 Implement typed `hash256 :: ByteArray -> Hash256`
- [x] 3.4 Implement typed `ripemd160 :: ByteArray -> Hash160`
- [x] 3.5 Implement typed `hash160 :: ByteArray -> Hash160`
- [x] 3.6 Create CL wrapper functions in `src/crypto/hash.lisp`
- [x] 3.7 Verify all existing crypto tests pass
- [x] 3.8 Add type-level tests (ensure wrong types rejected at compile)

## 4. Serialization Types Migration
- [x] 4.1 Create `src/coalton/serialization.coalton`
- [x] 4.2 Define `Outpoint` ADT
- [x] 4.3 Define `TxIn` ADT
- [x] 4.4 Define `TxOut` ADT
- [x] 4.5 Define `Transaction` ADT
- [x] 4.6 Define `BlockHeader` ADT
- [x] 4.7 Define `BitcoinBlock` ADT
- [x] 4.8 Implement typed serialization functions
- [x] 4.9 Implement typed deserialization functions
- [x] 4.10 Create CL compatibility layer (defstruct <-> ADT)
- [x] 4.11 Verify all existing serialization tests pass
- [x] 4.12 Add property-based round-trip tests

## 5. Binary Primitives (Optional Enhancement)
- [x] 5.1 Define typed read/write functions for fixed-width integers
- [x] 5.2 Implement `read-uint32-le :: Stream -> UFix32` pattern
- [x] 5.3 Add stream position tracking types

Note: Section 5 implemented in `src/coalton/binary.lisp` with:
- `ReadResult` type for position tracking
- `read-u8`, `read-u16-le`, `read-u32-le`, `read-u64-le`, `read-i32-le`, `read-i64-le`
- `read-compact-size`, `read-bytes`
- `write-u8`, `write-u16-le`, `write-u32-le`, `write-u64-le`, `write-i32-le`, `write-i64-le`
- `write-compact-size`, `concat-bytes`
- Tests in `tests/coalton-binary-tests.lisp`

## 6. Test Infrastructure
- [x] 6.1 Add `coalton/testing` dependency to `bitcoin-lisp/tests` system
- [x] 6.2 Create `tests/coalton-package.lisp` with Coalton test package
- [x] 6.3 Create `tests/coalton-types-tests.lisp` for core type tests
- [x] 6.4 Create `tests/coalton-crypto-tests.lisp` for typed crypto tests
- [x] 6.5 Create `tests/coalton-serialization-tests.lisp` for ADT tests
- [x] 6.6 Add compile-time type rejection tests (verify type errors occur)
- [x] 6.7 Add property-based tests using Coalton's testing facilities
- [x] 6.8 Integrate Coalton tests into existing fiveam test suite
- [x] 6.9 Update CI to run both CL and Coalton test suites

## 7. Documentation
- [x] 7.1 Document Coalton type patterns in USAGE.md
- [x] 7.2 Add inline documentation to Coalton source files
- [x] 7.3 Create migration guide for future module conversions
- [x] 7.4 Document test patterns for Coalton code
