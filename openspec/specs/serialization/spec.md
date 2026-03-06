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

### Requirement: Compact Block Message Serialization

The system SHALL serialize and deserialize BIP 152 compact block messages with exact binary compatibility.

#### HeaderAndShortIDs (cmpctblock payload)

| Field | Type | Description |
|-------|------|-------------|
| header | block_header | Standard 80-byte block header |
| nonce | uint64 | Random nonce for short ID key derivation |
| shortids_length | CompactSize | Number of short transaction IDs |
| shortids | uint48[] | 6-byte short transaction IDs (little-endian) |
| prefilledtxn_length | CompactSize | Number of prefilled transactions |
| prefilledtxn | PrefilledTransaction[] | Full transactions (usually coinbase) |

#### PrefilledTransaction

| Field | Type | Description |
|-------|------|-------------|
| index | CompactSize | Differentially encoded position |
| tx | Transaction | Full transaction data (witness format) |

Note: Indexes are differentially encoded. The first index is the absolute position. Each subsequent index is relative to (previous_index + 1).

Note: Transactions are serialized in witness format (BIP 144) to include witness data for SegWit transactions.

#### Scenario: Parse cmpctblock message

- **GIVEN** raw bytes of a cmpctblock message
- **WHEN** parsing the message
- **THEN** the header, nonce, short IDs, and prefilled transactions are extracted
- **AND** prefilled transaction indexes are decoded from differential to absolute

#### Scenario: Serialize cmpctblock round-trip

- **GIVEN** a compact-block structure
- **WHEN** serializing and then parsing the bytes
- **THEN** all fields match the original structure

### Requirement: Block Transactions Request Serialization

The system SHALL serialize and deserialize BIP 152 getblocktxn messages.

#### BlockTransactionsRequest (getblocktxn payload)

| Field | Type | Description |
|-------|------|-------------|
| blockhash | hash256 | Block hash being requested |
| indexes_length | CompactSize | Number of transaction indexes |
| indexes | CompactSize[] | Differentially encoded indexes |

#### Scenario: Create getblocktxn message

- **GIVEN** a block hash and list of missing transaction indexes [0, 5, 6, 10]
- **WHEN** creating a getblocktxn message
- **THEN** indexes are differentially encoded as [0, 4, 0, 3]

#### Scenario: Parse getblocktxn message

- **GIVEN** raw bytes of a getblocktxn message
- **WHEN** parsing the message
- **THEN** the block hash and absolute transaction indexes are extracted

### Requirement: Block Transactions Response Serialization

The system SHALL serialize and deserialize BIP 152 blocktxn messages.

#### BlockTransactions (blocktxn payload)

| Field | Type | Description |
|-------|------|-------------|
| blockhash | hash256 | Block hash for these transactions |
| transactions_length | CompactSize | Number of transactions |
| transactions | Transaction[] | Full transaction data |

#### Scenario: Parse blocktxn message

- **GIVEN** raw bytes of a blocktxn message containing full transactions
- **WHEN** parsing the message
- **THEN** the block hash and list of full transactions are extracted

### Requirement: Send Compact Block Negotiation Message

The system SHALL serialize and deserialize BIP 152 sendcmpct messages.

#### sendcmpct payload

| Field | Type | Description |
|-------|------|-------------|
| announce | bool (1 byte) | High-bandwidth mode: 0=low, 1=high |
| version | uint64 | Compact block protocol version (1 or 2) |

#### Scenario: Parse sendcmpct message

- **GIVEN** a sendcmpct message payload (9 bytes)
- **WHEN** parsing the message
- **THEN** the announce flag (0 or 1) and version number are extracted

#### Scenario: Create sendcmpct message

- **GIVEN** announce=false and version=2
- **WHEN** creating a sendcmpct message
- **THEN** the payload is 9 bytes: [0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

### Requirement: Compact Block Inventory Type

The system SHALL support the MSG_CMPCT_BLOCK inventory type for requesting compact blocks via getdata.

| Constant | Value | Description |
|----------|-------|-------------|
| MSG_CMPCT_BLOCK | 4 | Request compact block instead of full block |

#### Scenario: Request compact block via getdata

- **GIVEN** a block hash and peer supports compact blocks
- **WHEN** creating a getdata message for the block
- **THEN** the inventory type MSG_CMPCT_BLOCK (4) can be used

### Requirement: ADDRv2 Serialization
The system SHALL serialize and deserialize addrv2 message entries as specified in BIP 155.

Each addrv2 entry SHALL contain:
- Timestamp (4 bytes, uint32 LE)
- Services (compact-size encoded, 1-9 bytes)
- Network ID (1 byte): 1=IPv4, 2=IPv6, 4=TorV3, 5=I2P, 6=CJDNS
- Address length (compact-size encoded)
- Address bytes (variable, up to 512 bytes)
- Port (2 bytes, uint16 big-endian)

The system SHALL validate that address length matches the expected size for known network IDs (IPv4=4, IPv6=16, TorV2=10, TorV3=32, I2P=32, CJDNS=16). Entries with mismatched lengths for known network IDs SHALL be skipped.

Entries with unknown network IDs SHALL be skipped by reading past their bytes without error.

The system SHALL serialize `sendaddrv2` as a message with empty payload.

#### Scenario: Deserialize IPv4 addrv2 entry
- **GIVEN** an addrv2 entry with network ID 1 and 4-byte address
- **WHEN** deserializing the entry
- **THEN** the IPv4 address, port, services, and timestamp are extracted

#### Scenario: Deserialize IPv6 addrv2 entry
- **GIVEN** an addrv2 entry with network ID 2 and 16-byte address
- **WHEN** deserializing the entry
- **THEN** the IPv6 address, port, services, and timestamp are extracted

#### Scenario: Skip unknown network ID
- **GIVEN** an addrv2 entry with an unrecognized network ID
- **WHEN** deserializing the entry
- **THEN** the entry is skipped by reading past its bytes without error

#### Scenario: Skip entry with mismatched address length
- **GIVEN** an addrv2 entry with a known network ID but incorrect address length
- **WHEN** deserializing the entry
- **THEN** the entry is skipped by reading past its bytes without error

#### Scenario: Serialize sendaddrv2 message
- **GIVEN** a request to build a sendaddrv2 message
- **WHEN** serializing
- **THEN** the message has the correct header and zero-length payload

