# networking Specification Delta

## ADDED Requirements

### Requirement: Compact Block Protocol Negotiation

The system SHALL negotiate compact block support with peers using sendcmpct messages as specified in BIP 152.

After completing the version handshake:
1. Send sendcmpct messages advertising supported versions (version 2 first, then version 1)
2. Track received sendcmpct messages from peers
3. Use the highest mutually supported version for compact block communication

Version semantics:
- Version 1: Uses txid for short ID computation
- Version 2: Uses wtxid for short ID computation (required for SegWit)

#### Scenario: Advertise compact block support

- **GIVEN** a successful version handshake with a peer
- **WHEN** post-handshake setup completes
- **THEN** sendcmpct messages are sent for versions 2 and 1 (in that order)
- **AND** the announce flag is set to 0 (low-bandwidth mode)

#### Scenario: Track peer compact block version

- **GIVEN** a peer sends a sendcmpct message with version 2
- **WHEN** the message is processed
- **THEN** the peer's compact block version is recorded as 2

#### Scenario: Use highest mutual version

- **GIVEN** we support versions 1 and 2
- **AND** a peer only sent sendcmpct for version 1
- **WHEN** requesting a compact block from this peer
- **THEN** version 1 (txid-based) short IDs are used for reconstruction

### Requirement: Compact Block Reception

The system SHALL receive and process cmpctblock messages, reconstructing full blocks from mempool transactions.

When receiving a cmpctblock:
1. Validate the block header (proof-of-work, chain linkage)
2. Compute SipHash key from header and nonce
3. Build a map of short IDs to mempool transactions
4. Match each short ID to a mempool transaction
5. Place prefilled transactions at their specified indexes
6. If all transactions found, validate and connect the full block
7. If transactions missing, request them via getblocktxn

#### Scenario: Reconstruct block from mempool

- **GIVEN** a cmpctblock message for a new block
- **AND** all referenced transactions exist in the mempool
- **WHEN** processing the compact block
- **THEN** the full block is reconstructed from mempool transactions
- **AND** the block is validated and connected to the chain

#### Scenario: Request missing transactions

- **GIVEN** a cmpctblock message for a new block
- **AND** some short IDs do not match any mempool transaction
- **WHEN** processing the compact block
- **THEN** a getblocktxn message is sent requesting the missing transactions by index

#### Scenario: Handle short ID collision

- **GIVEN** a cmpctblock message for a new block
- **AND** two mempool transactions hash to the same short ID
- **WHEN** processing the compact block
- **THEN** reconstruction is aborted
- **AND** a full block is requested via standard getdata

#### Scenario: Handle high-bandwidth mode

- **GIVEN** a peer is in high-bandwidth mode for compact blocks
- **WHEN** the peer sends an unsolicited cmpctblock message
- **THEN** the compact block is processed normally (same as low-bandwidth)

### Requirement: Block Transactions Request/Response

The system SHALL request missing transactions via getblocktxn and complete block reconstruction upon receiving blocktxn.

#### Scenario: Complete reconstruction with blocktxn

- **GIVEN** a pending compact block reconstruction with missing transactions
- **AND** the peer responds with a blocktxn message containing those transactions
- **WHEN** the blocktxn is received
- **THEN** the missing transactions are inserted at their expected positions
- **AND** the full block is validated and connected

#### Scenario: Timeout waiting for blocktxn

- **GIVEN** a pending compact block reconstruction
- **AND** getblocktxn was sent but no blocktxn received within timeout
- **WHEN** the timeout expires
- **THEN** the reconstruction is abandoned
- **AND** a full block is requested via standard getdata

### Requirement: Compact Block Request via Getdata

The system SHALL request compact blocks using MSG_CMPCT_BLOCK inventory type when the peer supports compact blocks.

#### Scenario: Request compact block for announced block

- **GIVEN** a peer announces a new block via inv
- **AND** the peer supports compact blocks
- **AND** the node is not in Initial Block Download
- **WHEN** requesting the block
- **THEN** a getdata message with MSG_CMPCT_BLOCK type is sent

#### Scenario: Skip compact blocks during IBD

- **GIVEN** a peer announces a new block via inv
- **AND** the peer supports compact blocks
- **AND** the node is in Initial Block Download (syncing headers or blocks)
- **WHEN** requesting the block
- **THEN** a getdata message with MSG_WITNESS_BLOCK type is sent (full block)

#### Scenario: Fallback to full block

- **GIVEN** a compact block reconstruction failed
- **WHEN** retrying the block download
- **THEN** a getdata message with MSG_WITNESS_BLOCK type is sent (full block)

## MODIFIED Requirements

### Requirement: Message Sending

The system SHALL send properly formatted P2P messages to connected peers.

**Addition**: The system SHALL support sending the following compact block messages:
- `sendcmpct`: Compact block version negotiation
- `getblocktxn`: Request missing transactions for block reconstruction

#### Scenario: Send sendcmpct message

- **GIVEN** a peer connection after version handshake
- **WHEN** sending a sendcmpct message with announce=0 and version=2
- **THEN** the message is serialized with correct header and 9-byte payload

#### Scenario: Send getblocktxn message

- **GIVEN** a compact block with missing transactions at indexes [1, 5, 6]
- **WHEN** sending a getblocktxn message
- **THEN** the message contains the block hash and differentially encoded indexes

### Requirement: Message Receiving

The system SHALL receive and parse P2P messages from connected peers.

**Addition**: The system SHALL handle the following compact block messages:
- `sendcmpct`: Update peer's compact block capabilities
- `cmpctblock`: Attempt block reconstruction from mempool
- `blocktxn`: Complete pending block reconstruction

#### Scenario: Receive sendcmpct message

- **GIVEN** an incoming sendcmpct message from a peer
- **WHEN** the message is processed
- **THEN** the peer's compact block version and mode are recorded

#### Scenario: Receive cmpctblock message

- **GIVEN** an incoming cmpctblock message from a peer
- **WHEN** the message is processed
- **THEN** block reconstruction is attempted using mempool transactions
