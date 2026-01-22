## ADDED Requirements

### Requirement: Header Chain Storage
The system SHALL store block headers separately from full blocks during IBD.

Headers are stored with:
- Block hash (primary key)
- Header data (80 bytes)
- Height in chain
- Chainwork at this block
- Validation status (header-valid, fully-valid)

#### Scenario: Store header before block
- **GIVEN** a validated block header
- **WHEN** the full block is not yet downloaded
- **THEN** the header is stored with status `header-valid`

#### Scenario: Query headers by height range
- **GIVEN** a start and end height
- **WHEN** querying the header chain
- **THEN** all headers in the range are returned in order

#### Scenario: Find common ancestor
- **GIVEN** two block hashes
- **WHEN** finding the common ancestor
- **THEN** the highest block that is an ancestor of both is returned

### Requirement: Checkpoint Storage
The system SHALL store and validate against hardcoded checkpoints.

Checkpoints are (height, hash) pairs representing known-good blocks that the chain must pass through. During IBD, the header chain is validated against checkpoints to prevent long-range attacks.

#### Scenario: Load testnet checkpoints
- **WHEN** the node initializes
- **THEN** testnet checkpoint data is available for validation

#### Scenario: Validate chain against checkpoint
- **GIVEN** a header at a checkpoint height
- **WHEN** validating the header chain
- **THEN** the header hash must match the checkpoint hash

#### Scenario: Reject chain diverging before checkpoint
- **GIVEN** a header chain that diverges before the last checkpoint
- **WHEN** validating the chain
- **THEN** the chain is rejected as invalid

### Requirement: Download Queue Management
The system SHALL maintain a queue of blocks pending download.

The queue tracks:
- Blocks to download (by hash and height)
- In-flight requests (peer, timestamp)
- Completed downloads pending validation

#### Scenario: Add blocks to download queue
- **GIVEN** a range of validated headers
- **WHEN** blocks are needed
- **THEN** block hashes are added to the download queue in height order

#### Scenario: Track in-flight request
- **GIVEN** a block request sent to a peer
- **WHEN** the request is initiated
- **THEN** the request is recorded with peer ID and timestamp

#### Scenario: Mark block downloaded
- **GIVEN** a block received from a peer
- **WHEN** the block matches a pending request
- **THEN** the request is removed from in-flight and block is queued for validation
