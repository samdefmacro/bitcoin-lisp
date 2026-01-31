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
The system SHALL serialize and deserialize Bitcoin transactions with exact binary compatibility, supporting both legacy and BIP 144 witness formats.

A transaction consists of:
- Version (int32)
- Input count (CompactSize)
- Inputs (list of TxIn)
- Output count (CompactSize)
- Outputs (list of TxOut)
- Lock time (uint32)

BIP 144 witness transactions additionally contain:
- Marker byte (0x00) and flag byte (0x01) after version
- Per-input witness stacks between outputs and lock-time
- Each witness stack is a list of byte vectors (CompactSize count + items)

The system SHALL auto-detect witness format during deserialization by checking for the marker/flag bytes where the input count would normally be.

The system SHALL compute two distinct hashes:
- `txid`: double-SHA256 of legacy serialization (excluding witness data)
- `wtxid`: double-SHA256 of witness serialization (including witness data); for coinbase transactions, wtxid is defined as 32 zero bytes

#### Scenario: Deserialize simple transaction
- **GIVEN** raw transaction bytes from the Bitcoin protocol in legacy format
- **WHEN** deserializing the transaction
- **THEN** all fields are correctly parsed and witness is nil

#### Scenario: Deserialize witness transaction
- **GIVEN** raw transaction bytes in BIP 144 witness format (marker 0x00, flag 0x01)
- **WHEN** deserializing the transaction
- **THEN** version, inputs, outputs, lock-time, and per-input witness stacks are all correctly parsed

#### Scenario: Serialize transaction round-trip
- **GIVEN** a deserialized transaction object (legacy or witness)
- **WHEN** serializing back to bytes in the same format
- **THEN** the output matches the original input bytes exactly

#### Scenario: Compute txid excludes witness
- **GIVEN** a witness transaction
- **WHEN** computing the txid
- **THEN** the hash uses legacy serialization (no marker, flag, or witness data)

#### Scenario: Compute wtxid includes witness
- **GIVEN** a witness transaction
- **WHEN** computing the wtxid
- **THEN** the hash uses witness serialization (includes marker, flag, and witness stacks)

#### Scenario: Coinbase wtxid is zero
- **GIVEN** a coinbase transaction
- **WHEN** computing the wtxid
- **THEN** the result is 32 zero bytes regardless of transaction content

### Requirement: Block Serialization
The system SHALL serialize and deserialize Bitcoin blocks with exact binary compatibility, including BIP 144 witness data on transactions.

A block consists of:
- Block header (80 bytes)
- Transaction count (CompactSize)
- Transactions (list of Transaction, which may include witness data)

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

#### Scenario: Deserialize block with witness transactions
- **GIVEN** a block containing BIP 144 witness transactions
- **WHEN** deserializing the block
- **THEN** each transaction's witness stacks are preserved and accessible

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

