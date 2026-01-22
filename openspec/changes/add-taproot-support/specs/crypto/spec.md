## ADDED Requirements

### Requirement: Schnorr Signature Verification (BIP 340)
The system SHALL verify Schnorr signatures on the secp256k1 curve as defined in BIP 340.

Schnorr signatures:
- Are 64 bytes (r, s components, each 32 bytes)
- Use x-only public keys (32 bytes, implicit even Y coordinate)
- Include a tagged hash challenge: `e = H("BIP0340/challenge" || R || P || m)`

#### Scenario: Verify valid Schnorr signature
- **GIVEN** a 32-byte message hash, 64-byte signature, and 32-byte x-only public key
- **WHEN** the signature is valid per BIP 340
- **THEN** verification returns true

#### Scenario: Reject invalid Schnorr signature
- **GIVEN** a message hash, signature, and public key
- **WHEN** the signature is invalid (wrong r, wrong s, or wrong key)
- **THEN** verification returns false

#### Scenario: Reject oversized signature
- **GIVEN** a signature that is not exactly 64 bytes
- **WHEN** attempting verification
- **THEN** verification fails

### Requirement: X-Only Public Keys
The system SHALL support x-only (32-byte) public key format for Taproot.

X-only keys:
- Contain only the x-coordinate (32 bytes)
- Implicitly assume even Y coordinate
- Can be lifted to full public key using `lift-x` operation

#### Scenario: Parse x-only public key
- **GIVEN** a 32-byte x-coordinate on secp256k1
- **WHEN** parsing as x-only key
- **THEN** the key is validated as having a corresponding point on secp256k1

#### Scenario: Lift x-only to full key
- **GIVEN** a valid 32-byte x-coordinate
- **WHEN** lifting to full public key
- **THEN** returns the point (x, y) where y is even

#### Scenario: Reject invalid x-coordinate
- **GIVEN** 32 bytes that do not correspond to any secp256k1 point
- **WHEN** attempting to lift
- **THEN** an error is returned

### Requirement: Tagged Hash Functions (BIP 340)
The system SHALL compute tagged hashes as defined in BIP 340.

Tagged hash formula: `SHA256(SHA256(tag) || SHA256(tag) || message)`

Required tags:
- `"BIP0340/challenge"` - Schnorr signature challenge
- `"BIP0340/aux"` - Auxiliary randomness
- `"TapLeaf"` - Taproot leaf hash
- `"TapBranch"` - Merkle branch hash
- `"TapTweak"` - Key tweaking
- `"TapSighash"` - Signature hash

#### Scenario: Compute tagged hash
- **GIVEN** a tag string and message bytes
- **WHEN** computing the tagged hash
- **THEN** returns SHA256(SHA256(tag) || SHA256(tag) || message)

#### Scenario: Challenge hash for Schnorr
- **GIVEN** R point (32 bytes), P point (32 bytes), and message (32 bytes)
- **WHEN** computing `hash-challenge`
- **THEN** returns tagged hash with tag "BIP0340/challenge"
