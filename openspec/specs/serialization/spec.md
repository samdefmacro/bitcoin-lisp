# serialization Specification

## Purpose
TBD - created by archiving change add-bitcoin-client-foundation. Update Purpose after archive.
## Requirements
### Requirement: Binary Primitives
The system SHALL provide functions to read and write binary primitives in little-endian format.

Supported types:
- Unsigned integers: uint8, uint16, uint32, uint64
- Signed integers: int32, int64
- CompactSize (variable-length integer)
- Variable-length byte vectors
- Fixed-length byte arrays

#### Scenario: Read little-endian uint32
- **GIVEN** a byte stream containing `[0x01, 0x02, 0x03, 0x04]`
- **WHEN** reading a uint32
- **THEN** the value `67305985` (0x04030201) is returned

#### Scenario: Write CompactSize for small value
- **GIVEN** the value `100`
- **WHEN** encoding as CompactSize
- **THEN** a single byte `[0x64]` is produced

#### Scenario: Write CompactSize for large value
- **GIVEN** the value `1000`
- **WHEN** encoding as CompactSize
- **THEN** bytes `[0xFD, 0xE8, 0x03]` are produced

### Requirement: Transaction Serialization
The system SHALL serialize and deserialize Bitcoin transactions with exact binary compatibility.

A transaction consists of:
- Version (int32)
- Input count (CompactSize)
- Inputs (list of TxIn)
- Output count (CompactSize)
- Outputs (list of TxOut)
- Lock time (uint32)

#### Scenario: Deserialize simple transaction
- **GIVEN** raw transaction bytes from the Bitcoin protocol
- **WHEN** deserializing the transaction
- **THEN** all fields are correctly parsed and accessible

#### Scenario: Serialize transaction round-trip
- **GIVEN** a deserialized transaction object
- **WHEN** serializing back to bytes
- **THEN** the output matches the original input bytes exactly

### Requirement: Block Serialization
The system SHALL serialize and deserialize Bitcoin blocks with exact binary compatibility.

A block consists of:
- Block header (80 bytes)
- Transaction count (CompactSize)
- Transactions (list of Transaction)

A block header consists of:
- Version (int32)
- Previous block hash (32 bytes)
- Merkle root (32 bytes)
- Timestamp (uint32)
- Bits (uint32) - difficulty target
- Nonce (uint32)

#### Scenario: Deserialize block header
- **GIVEN** 80 bytes of block header data
- **WHEN** deserializing the header
- **THEN** all six fields are correctly extracted

#### Scenario: Compute block hash
- **GIVEN** a block header
- **WHEN** computing the block hash
- **THEN** the double-SHA256 of the 80-byte header is returned in internal byte order

### Requirement: Script Serialization
The system SHALL serialize and deserialize Bitcoin scripts.

A script is a variable-length byte vector containing opcodes and data pushes.

#### Scenario: Deserialize P2PKH script
- **GIVEN** a standard P2PKH scriptPubKey
- **WHEN** deserializing the script
- **THEN** the opcodes and pubkey hash are correctly identified

### Requirement: Network Message Serialization
The system SHALL serialize and deserialize Bitcoin P2P protocol messages.

All messages have:
- Magic bytes (4 bytes, network-specific)
- Command name (12 bytes, null-padded ASCII)
- Payload length (uint32)
- Checksum (4 bytes, first 4 bytes of double-SHA256 of payload)
- Payload (variable)

#### Scenario: Deserialize version message
- **GIVEN** raw bytes of a version message from the network
- **WHEN** deserializing the message
- **THEN** the version, services, timestamp, and other fields are correctly extracted

#### Scenario: Serialize verack message
- **GIVEN** a verack message (empty payload)
- **WHEN** serializing for testnet
- **THEN** the output contains testnet magic bytes, "verack" command, zero length, and correct checksum

