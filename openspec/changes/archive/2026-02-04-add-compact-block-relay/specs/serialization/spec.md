# serialization Specification Delta

## ADDED Requirements

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
