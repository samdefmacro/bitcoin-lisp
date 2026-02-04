# crypto Specification Delta

## ADDED Requirements

### Requirement: SipHash-2-4

The system SHALL implement SipHash-2-4 for computing short transaction IDs as specified in BIP 152.

SipHash-2-4 is a fast, secure pseudorandom function used to generate 6-byte short transaction identifiers from 32-byte transaction IDs. The algorithm:
1. Takes two 64-bit keys (k0, k1) and arbitrary-length input
2. Performs 2 compression rounds and 4 finalization rounds
3. Returns a 64-bit hash value

#### Scenario: Compute SipHash with test vector

- **GIVEN** k0 = 0x0706050403020100, k1 = 0x0f0e0d0c0b0a0908
- **AND** input = empty bytes
- **WHEN** computing SipHash-2-4
- **THEN** the result is 0x726fdb47dd0e0e31

#### Scenario: Compute SipHash with 8-byte input

- **GIVEN** k0 = 0x0706050403020100, k1 = 0x0f0e0d0c0b0a0908
- **AND** input = bytes [0, 1, 2, 3, 4, 5, 6, 7]
- **WHEN** computing SipHash-2-4
- **THEN** the result is 0x93f5f5799a932462

### Requirement: Compact Block Short ID Computation

The system SHALL compute short transaction IDs for compact blocks as specified in BIP 152.

Short ID computation:
1. Derive SipHash key: SHA256(block_header || nonce), take first 16 bytes as k0 (bytes 0-7) and k1 (bytes 8-15) in little-endian
2. Compute SipHash-2-4(k0, k1, txid_or_wtxid)
3. Truncate to 6 bytes (drop 2 most significant bytes)

#### Scenario: Compute SipHash key from header and nonce

- **GIVEN** a serialized block header (80 bytes) and a uint64 nonce
- **WHEN** computing the SipHash key
- **THEN** k0 is bytes 0-7 of SHA256(header || nonce) as little-endian uint64
- **AND** k1 is bytes 8-15 of SHA256(header || nonce) as little-endian uint64

#### Scenario: Compute short transaction ID

- **GIVEN** SipHash keys k0 and k1
- **AND** a 32-byte transaction ID
- **WHEN** computing the short transaction ID
- **THEN** the result is SipHash-2-4(k0, k1, txid) masked to 48 bits (6 bytes)

#### Scenario: Short ID collision is possible

- **GIVEN** two different transaction IDs
- **AND** the same SipHash keys k0 and k1
- **WHEN** computing short transaction IDs for both
- **THEN** there is a small probability (~1/2^48) they produce the same short ID
- **AND** callers must handle this case by falling back to full block download
