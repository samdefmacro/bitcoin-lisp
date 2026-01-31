## MODIFIED Requirements

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
