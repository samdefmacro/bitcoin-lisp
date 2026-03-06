## MODIFIED Requirements

### Requirement: Peer Discovery
The system SHALL discover new peers through DNS seeds, peer exchange, and a persistent address book.

On startup, the system SHALL prefer peers from the address book over DNS seeds. DNS seed queries SHALL only occur when the address book contains fewer than 8 candidates.

#### Scenario: Query DNS seeds
- **GIVEN** testnet DNS seed hostnames
- **WHEN** querying for peer addresses
- **THEN** a list of potential peer IP addresses is returned

#### Scenario: Receive addr message
- **GIVEN** an `addr` message from a connected peer
- **WHEN** processing the message
- **THEN** the advertised addresses are added to the address book with their timestamp and services

#### Scenario: Warm start from address book
- **GIVEN** a peers.dat file exists with previously learned addresses
- **WHEN** the node starts
- **THEN** peers are selected from the address book sorted by score
- **AND** DNS seeds are not queried

#### Scenario: Fall back to DNS seeds
- **GIVEN** the address book has fewer than 8 entries
- **WHEN** the node starts
- **THEN** DNS seeds are queried to supplement the address book

## ADDED Requirements

### Requirement: Peer Address Persistence
The system SHALL persist learned peer addresses to a `peers.dat` binary file in the data directory, enabling warm starts across restarts.

The file format SHALL use a magic header ("PEER"), version number, entry count, fixed-size entries (38 bytes each), and a CRC32 checksum for integrity verification.

Each entry stores: IP address (16 bytes), port (2 bytes), services (8 bytes), last-seen timestamp (4 bytes), last-attempt timestamp (4 bytes), success count (2 bytes), failure count (2 bytes).

The system SHALL write atomically (write to temporary file, then rename) to prevent corruption on crash.

The maximum address book capacity SHALL be 2000 entries.

#### Scenario: Save address book on shutdown
- **GIVEN** the node has learned peer addresses during operation
- **WHEN** the node shuts down
- **THEN** the address book is written to peers.dat atomically

#### Scenario: Load address book on startup
- **GIVEN** a valid peers.dat file exists in the data directory
- **WHEN** the node starts
- **THEN** the address book is populated from the file

#### Scenario: Reject corrupted peers.dat
- **GIVEN** a peers.dat file with a CRC32 mismatch
- **WHEN** the node attempts to load it
- **THEN** the file is ignored with a warning
- **AND** the node starts with an empty address book

#### Scenario: Handle missing peers.dat
- **GIVEN** no peers.dat file exists
- **WHEN** the node starts
- **THEN** the node starts with an empty address book
- **AND** falls back to DNS seed discovery

#### Scenario: Evict lowest-scored entry when full
- **GIVEN** the address book has reached 2000 entries
- **WHEN** a new peer address is learned
- **THEN** the entry with the lowest score is evicted to make room

### Requirement: Peer Reputation Tracking
The system SHALL track connection success and failure counts for each peer address and use this data to score peers for selection priority.

The scoring formula SHALL be: `reliability / sqrt(age)` where:
- `reliability` = successes / (successes + failures), defaulting to 0.5 for untried peers
- `age` = max(1, hours since last seen)

On successful handshake, the success count SHALL be incremented and last-seen updated. On connection failure, the failure count SHALL be incremented and last-attempt updated.

#### Scenario: Track successful connection
- **GIVEN** a peer address in the address book
- **WHEN** a connection to that peer completes the version handshake
- **THEN** the success count is incremented and last-seen is updated

#### Scenario: Track failed connection
- **GIVEN** a peer address in the address book
- **WHEN** a connection attempt to that peer fails or times out
- **THEN** the failure count is incremented and last-attempt is updated

#### Scenario: Prefer reliable peers
- **GIVEN** an address book with peers of varying success rates
- **WHEN** selecting peers for connection
- **THEN** peers with higher scores (more reliable, more recently seen) are tried first

#### Scenario: Score untried peer
- **GIVEN** a newly learned peer address with zero successes and zero failures
- **WHEN** computing the peer's score
- **THEN** the reliability defaults to 0.5
