## ADDED Requirements

### Requirement: Peer Misbehavior Tracking
The system SHALL track misbehavior scores for connected peers and ban peers that exceed the ban threshold.

Each peer has an integer misbehavior score starting at 0. Protocol violations increase the score:
- Invalid block header received: +100 (immediate ban)
- Invalid block received: +100 (immediate ban)
- Invalid transaction received: +10

When a peer's score reaches or exceeds 100, the peer is disconnected and banned.

#### Scenario: Ban peer sending invalid block
- **GIVEN** a connected peer
- **WHEN** the peer sends a block that fails consensus validation
- **THEN** the peer's misbehavior score increases by 100 and the peer is banned

#### Scenario: Ban peer after repeated invalid transactions
- **GIVEN** a connected peer with misbehavior score 90
- **WHEN** the peer sends an invalid transaction (+10)
- **THEN** the peer's score reaches 100 and the peer is banned

#### Scenario: Do not ban peer for timeout
- **GIVEN** a connected peer that times out on a block request
- **WHEN** the timeout is recorded
- **THEN** the existing timeout/disconnect logic handles it (no misbehavior score increase)

### Requirement: Ban List Management
The system SHALL maintain a list of banned peer addresses with expiry times.

Default ban duration: 24 hours. Banned addresses are stored in memory (not persisted across restarts).

Connection attempts to or from banned addresses SHALL be rejected.

#### Scenario: Reject connection from banned peer
- **GIVEN** a peer address that is currently banned
- **WHEN** a connection attempt from that address is received
- **THEN** the connection is rejected

#### Scenario: Allow connection after ban expires
- **GIVEN** a peer address whose ban expired
- **WHEN** a connection attempt from that address is received
- **THEN** the connection is allowed

#### Scenario: Clean start after restart
- **GIVEN** the node is restarted
- **WHEN** loading peer state
- **THEN** the ban list is empty (bans are not persisted)
