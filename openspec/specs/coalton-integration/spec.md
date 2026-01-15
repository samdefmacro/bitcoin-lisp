# coalton-integration Specification

## Purpose
TBD - created by archiving change add-coalton-static-typing. Update Purpose after archive.
## Requirements
### Requirement: Coalton Type System Integration

The system SHALL provide Coalton-based static type definitions for Bitcoin protocol primitives that are checked at compile time.

#### Scenario: Hash type safety prevents mixing hash sizes
- **WHEN** a function expects a `Hash256` argument
- **AND** a `Hash160` value is passed
- **THEN** compilation SHALL fail with a type error

#### Scenario: Satoshi type prevents arithmetic with raw integers
- **WHEN** a function expects a `Satoshi` value
- **AND** a raw `Integer` is passed without explicit conversion
- **THEN** compilation SHALL fail with a type error

### Requirement: Domain-Specific Newtypes

The system SHALL define the following Coalton newtypes to distinguish Bitcoin protocol values:

| Type | Description | Underlying |
|------|-------------|------------|
| `Hash256` | Double-SHA256 hash (32 bytes) | `(Vector UFix8)` |
| `Hash160` | RIPEMD160(SHA256) hash (20 bytes) | `(Vector UFix8)` |
| `Satoshi` | Bitcoin amount in satoshis | `Integer` |
| `BlockHeight` | Block height in chain | `UFix32` |

#### Scenario: Hash256 construction validates length
- **WHEN** constructing a `Hash256` from bytes
- **AND** the byte array length is not exactly 32
- **THEN** the construction SHALL signal an error

#### Scenario: Hash160 construction validates length
- **WHEN** constructing a `Hash160` from bytes
- **AND** the byte array length is not exactly 20
- **THEN** the construction SHALL signal an error

### Requirement: Typed Cryptographic Operations

The system SHALL provide typed hash functions with the following signatures:

```coalton
sha256    :: (Vector UFix8) -> Hash256
hash256   :: (Vector UFix8) -> Hash256
ripemd160 :: (Vector UFix8) -> Hash160
hash160   :: (Vector UFix8) -> Hash160
```

#### Scenario: sha256 returns Hash256
- **WHEN** calling `sha256` with a byte array
- **THEN** the return type SHALL be `Hash256`
- **AND** the underlying bytes SHALL be the SHA-256 digest

#### Scenario: hash256 performs double hashing
- **WHEN** calling `hash256` with a byte array
- **THEN** the result SHALL be `SHA256(SHA256(input))`
- **AND** the return type SHALL be `Hash256`

### Requirement: Protocol Structure ADTs

The system SHALL define algebraic data types for Bitcoin protocol structures:

```coalton
(define-type Outpoint
  (Outpoint Hash256 UFix32))

(define-type TxIn
  (TxIn Outpoint (Vector UFix8) UFix32))

(define-type TxOut
  (TxOut Satoshi (Vector UFix8)))

(define-type Transaction
  (Transaction IFix32 (List TxIn) (List TxOut) UFix32))

(define-type BlockHeader
  (BlockHeader IFix32 Hash256 Hash256 UFix32 UFix32 UFix32))
```

#### Scenario: Transaction construction enforces field types
- **WHEN** constructing a `Transaction`
- **AND** the version is not `IFix32`
- **THEN** compilation SHALL fail with a type error

#### Scenario: Outpoint hash is type-checked
- **WHEN** constructing an `Outpoint`
- **AND** the first argument is not a `Hash256`
- **THEN** compilation SHALL fail with a type error

### Requirement: CL Interoperability Layer

The system SHALL provide bidirectional conversion between Coalton types and existing Common Lisp structures.

#### Scenario: Convert CL defstruct to Coalton ADT
- **WHEN** calling `transaction-from-cl` with a CL `transaction` struct
- **THEN** a Coalton `Transaction` value SHALL be returned
- **AND** all fields SHALL be correctly converted

#### Scenario: Convert Coalton ADT to CL defstruct
- **WHEN** calling `transaction-to-cl` with a Coalton `Transaction`
- **THEN** a CL `transaction` struct SHALL be returned
- **AND** all fields SHALL be correctly converted

#### Scenario: Round-trip conversion preserves data
- **WHEN** converting a CL struct to Coalton and back
- **THEN** the result SHALL be `equalp` to the original

### Requirement: Typed Serialization

The system SHALL provide type-safe serialization and deserialization functions.

```coalton
serialize-transaction   :: Transaction -> (Vector UFix8)
deserialize-transaction :: (Vector UFix8) -> (Result String Transaction)
```

#### Scenario: Serialization produces valid bytes
- **WHEN** serializing a `Transaction`
- **THEN** the output bytes SHALL match Bitcoin protocol encoding

#### Scenario: Deserialization returns Result type
- **WHEN** deserializing bytes to `Transaction`
- **AND** the bytes are malformed
- **THEN** the result SHALL be `(Err error-message)`

#### Scenario: Round-trip serialization preserves transaction
- **WHEN** serializing and then deserializing a `Transaction`
- **THEN** the result SHALL equal the original transaction

### Requirement: Coalton Test Infrastructure

The system SHALL provide a test infrastructure for validating Coalton-typed code alongside existing Common Lisp tests.

#### Scenario: Coalton tests run with fiveam suite
- **WHEN** running `(asdf:test-system "bitcoin-lisp")`
- **THEN** both CL tests and Coalton tests SHALL execute
- **AND** test results SHALL be reported in unified format

#### Scenario: Type error tests verify compile-time safety
- **WHEN** compiling test code with intentional type mismatches
- **THEN** the test framework SHALL verify compilation fails
- **AND** the error message SHALL indicate the type mismatch

#### Scenario: Property-based tests for serialization
- **WHEN** running property-based tests
- **THEN** random valid `Transaction` values SHALL be generated
- **AND** round-trip serialization SHALL be verified for each

#### Scenario: Crypto test vectors validate typed functions
- **WHEN** running crypto tests
- **THEN** Bitcoin Core test vectors SHALL pass
- **AND** results SHALL match existing CL implementation exactly

### Requirement: Coalton Dependency Management

The system SHALL use a git submodule for Coalton to ensure reproducible builds.

#### Scenario: Coalton loads from local submodule
- **WHEN** loading the `bitcoin-lisp` system
- **THEN** Coalton SHALL be loaded from the `coalton/` submodule
- **AND** no external Quicklisp fetch SHALL be required

#### Scenario: Submodule version is pinned
- **WHEN** cloning the repository with `--recurse-submodules`
- **THEN** the exact Coalton version used SHALL be reproducible

