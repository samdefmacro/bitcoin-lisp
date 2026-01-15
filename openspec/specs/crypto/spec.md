# crypto Specification

## Purpose
TBD - created by archiving change add-bitcoin-client-foundation. Update Purpose after archive.
## Requirements
### Requirement: SHA256 Hashing
The system SHALL compute SHA-256 hashes of arbitrary byte sequences.

#### Scenario: Hash empty input
- **GIVEN** an empty byte sequence
- **WHEN** computing SHA-256
- **THEN** the hash `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` is returned

#### Scenario: Hash known input
- **GIVEN** the ASCII string "hello"
- **WHEN** computing SHA-256
- **THEN** the hash `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` is returned

### Requirement: Double SHA256 (Hash256)
The system SHALL compute double-SHA256 (SHA256(SHA256(x))) for Bitcoin block and transaction hashing.

#### Scenario: Compute Hash256
- **GIVEN** a byte sequence
- **WHEN** computing Hash256
- **THEN** the SHA-256 of the SHA-256 of the input is returned

### Requirement: RIPEMD160 Hashing
The system SHALL compute RIPEMD-160 hashes for Bitcoin address generation.

#### Scenario: Hash known input
- **GIVEN** the ASCII string "hello"
- **WHEN** computing RIPEMD-160
- **THEN** the hash `108f07b8382412612c048d07d13f814118445acd` is returned

### Requirement: Hash160
The system SHALL compute Hash160 (RIPEMD160(SHA256(x))) for Bitcoin public key hashing.

#### Scenario: Compute Hash160 of public key
- **GIVEN** a 33-byte compressed public key
- **WHEN** computing Hash160
- **THEN** the 20-byte public key hash is returned

### Requirement: ECDSA Signature Verification
The system SHALL verify ECDSA signatures on the secp256k1 curve.

#### Scenario: Verify valid signature
- **GIVEN** a message hash, signature, and public key
- **WHEN** the signature is valid for the message and key
- **THEN** verification returns true

#### Scenario: Reject invalid signature
- **GIVEN** a message hash, signature, and public key
- **WHEN** the signature is invalid
- **THEN** verification returns false

### Requirement: Public Key Operations
The system SHALL parse and validate secp256k1 public keys.

Supported formats:
- Compressed (33 bytes, prefix 0x02 or 0x03)
- Uncompressed (65 bytes, prefix 0x04)

#### Scenario: Parse compressed public key
- **GIVEN** a 33-byte compressed public key
- **WHEN** parsing the key
- **THEN** the key is validated as a point on secp256k1

#### Scenario: Reject invalid public key
- **GIVEN** bytes that do not represent a valid secp256k1 point
- **WHEN** parsing the key
- **THEN** an error is signaled

