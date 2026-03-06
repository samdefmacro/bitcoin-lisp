## MODIFIED Requirements

### Requirement: Version Handshake
The system SHALL perform the Bitcoin version handshake when connecting to peers.

The handshake sequence:
1. Send `version` message
2. Send `sendaddrv2` message (BIP 155 feature negotiation)
3. Receive `version` message from peer
4. Send `verack` message
5. Receive `verack` message from peer (other feature negotiation messages like `sendaddrv2`, `wtxidrelay` may arrive before `verack`)

When a `sendaddrv2` message is received from a peer during handshake, the system SHALL record that the peer supports addrv2 format.

#### Scenario: Complete successful handshake
- **GIVEN** a connected peer
- **WHEN** performing the version handshake
- **THEN** both sides exchange version and verack messages

#### Scenario: Reject incompatible protocol version
- **GIVEN** a peer advertising an unsupported protocol version
- **WHEN** receiving their version message
- **THEN** the connection is terminated

#### Scenario: Negotiate addrv2 support
- **GIVEN** a connected peer
- **WHEN** performing the version handshake
- **THEN** a sendaddrv2 message is sent after the version message
- **AND** if the peer also sends sendaddrv2, the peer is marked as addrv2-capable

### Requirement: Peer Discovery
The system SHALL discover new peers through DNS seeds, peer exchange, and a persistent address book.

On startup, the system SHALL prefer peers from the address book over DNS seeds. DNS seed queries SHALL only occur when the address book contains fewer than 8 candidates.

The system SHALL accept peer addresses from both `addr` (v1) and `addrv2` (BIP 155) messages.

When processing `addrv2` messages, only IPv4 and IPv6 addresses SHALL be added to the address book. Addresses for other networks (Tor v3, I2P, CJDNS) SHALL be parsed but silently discarded.

#### Scenario: Query DNS seeds
- **GIVEN** testnet DNS seed hostnames
- **WHEN** querying for peer addresses
- **THEN** a list of potential peer IP addresses is returned

#### Scenario: Receive addr message
- **GIVEN** an `addr` message from a connected peer
- **WHEN** processing the message
- **THEN** the advertised addresses are added to the address book with their timestamp and services

#### Scenario: Receive addrv2 message
- **GIVEN** an `addrv2` message from a connected peer
- **WHEN** processing the message
- **THEN** IPv4 and IPv6 addresses with plausible timestamps are added to the address book
- **AND** addresses for other network types are silently skipped
- **AND** at most 1000 entries are processed per message

#### Scenario: Warm start from address book
- **GIVEN** a peers.dat file exists with previously learned addresses
- **WHEN** the node starts
- **THEN** peers are selected from the address book sorted by score
- **AND** DNS seeds are not queried

#### Scenario: Fall back to DNS seeds
- **GIVEN** the address book has fewer than 8 entries
- **WHEN** the node starts
- **THEN** DNS seeds are queried to supplement the address book

### Requirement: Message Receiving

The system SHALL receive and parse P2P messages from connected peers.

**Addition**: The system SHALL handle the following compact block messages:
- `sendcmpct`: Update peer's compact block capabilities
- `cmpctblock`: Attempt block reconstruction from mempool
- `blocktxn`: Complete pending block reconstruction

**Addition**: The system SHALL handle the following address messages:
- `addrv2`: Process BIP 155 variable-length peer addresses
- `sendaddrv2`: Record peer's addrv2 capability (during handshake)

#### Scenario: Receive sendcmpct message

- **GIVEN** an incoming sendcmpct message from a peer
- **WHEN** the message is processed
- **THEN** the peer's compact block version and mode are recorded

#### Scenario: Receive cmpctblock message

- **GIVEN** an incoming cmpctblock message from a peer
- **WHEN** the message is processed
- **THEN** block reconstruction is attempted using mempool transactions

#### Scenario: Receive addrv2 message

- **GIVEN** an incoming addrv2 message from a peer
- **WHEN** the message is processed
- **THEN** IPv4/IPv6 addresses are added to the address book
- **AND** non-IPv4/IPv6 addresses are silently skipped

## ADDED Requirements

### Requirement: ADDRv2 Message Support
The system SHALL support BIP 155 addrv2 messages for modern peer address exchange.

The system SHALL send `sendaddrv2` during handshake to signal addrv2 capability to peers.

The system SHALL track which peers have sent `sendaddrv2` and use the appropriate message format when relaying addresses:
- Peers that sent `sendaddrv2`: receive `addrv2` messages
- Peers that did not: receive `addr` (v1) messages

#### Scenario: Send sendaddrv2 during handshake
- **GIVEN** a new peer connection
- **WHEN** performing the version handshake
- **THEN** a sendaddrv2 message (empty payload) is sent after the version message

#### Scenario: Track peer addrv2 capability
- **GIVEN** a peer sends sendaddrv2 during handshake
- **WHEN** the message is received
- **THEN** the peer is marked as addrv2-capable

#### Scenario: Convert IPv4 from addrv2 to address book format
- **GIVEN** an addrv2 entry with network ID 1 (IPv4) and a 4-byte address
- **WHEN** adding to the address book
- **THEN** the address is converted to IPv4-mapped IPv6 (16 bytes) for storage
