## ADDED Requirements

### Requirement: Per-Peer Message Rate Limiting
The system SHALL enforce per-peer rate limits on incoming P2P messages using a token bucket algorithm.

Each peer SHALL have independent rate limiters for the following message types:
- INV: 50 messages/sec sustained, burst 200
- TX: 10 messages/sec sustained, burst 50
- ADDR/ADDRV2: 1 message/sec sustained, burst 10
- GETDATA: 20 messages/sec sustained, burst 100
- HEADERS: 10 messages/sec sustained, burst 50

When a peer exceeds its rate limit for any message type, the system SHALL disconnect the peer and log the violation.

Rate limit parameters SHALL be configurable via global variables.

#### Scenario: Allow normal message flow
- **GIVEN** a connected peer sending INV messages at 20/sec
- **WHEN** messages are received within the sustained rate
- **THEN** all messages are processed normally

#### Scenario: Allow burst within limit
- **GIVEN** a connected peer that has been idle for 4 seconds
- **WHEN** the peer sends 200 INV messages in a burst
- **THEN** all messages are processed (burst capacity accumulated during idle time)

#### Scenario: Disconnect peer exceeding rate limit
- **GIVEN** a connected peer continuously sending INV messages at 100/sec
- **WHEN** the token bucket for INV is depleted
- **THEN** the peer is disconnected
- **AND** a log message records the rate limit violation with peer address and message type

#### Scenario: Independent rate limiters per message type
- **GIVEN** a connected peer at its INV rate limit
- **WHEN** the peer sends a TX message
- **THEN** the TX message is processed normally (TX has its own independent rate limiter)

#### Scenario: Headers rate limit accommodates IBD
- **GIVEN** the node is performing Initial Block Download
- **WHEN** the sync peer responds rapidly to getheaders requests
- **THEN** up to 50 headers responses in burst are processed without disconnecting the peer

### Requirement: Handshake Timeout
The system SHALL disconnect peers that do not complete the version handshake within 30 seconds of connecting.

The handshake timeout SHALL be checked during the periodic peer maintenance cycle.

#### Scenario: Disconnect slow handshake peer
- **GIVEN** a peer that connected 31 seconds ago
- **WHEN** the peer has not completed the version handshake (state is not :ready)
- **THEN** the peer is disconnected
- **AND** a log message records the handshake timeout

#### Scenario: Allow normal handshake completion
- **GIVEN** a peer that connected 5 seconds ago
- **WHEN** the peer completes the version handshake within 30 seconds
- **THEN** the peer transitions to :ready state normally

### Requirement: Maximum Message Payload Size
The system SHALL validate the payload length declared in P2P message headers before reading the payload, rejecting messages that exceed 4 MB.

This check SHALL occur after reading the 24-byte message header and before allocating a buffer or reading payload bytes.

#### Scenario: Accept normal-sized message
- **GIVEN** a peer sends a message with payload length 1,000,000 bytes
- **WHEN** the message header is read
- **THEN** the payload is read and processed normally

#### Scenario: Reject oversized message
- **GIVEN** a peer sends a message with payload length 5,000,000 bytes (> 4 MB)
- **WHEN** the message header is read
- **THEN** the peer is disconnected without reading the payload
- **AND** a log message records the oversized message with declared size

#### Scenario: Reject zero-filling attack
- **GIVEN** a peer sends a forged header with payload length 2,147,483,647 bytes
- **WHEN** the message header is read
- **THEN** the peer is disconnected immediately without allocating memory

### Requirement: Recent Transaction Rejects Filter
The system SHALL maintain a bounded set of recently rejected transaction hashes to avoid redundant validation of known-bad transactions.

The filter SHALL hold a maximum of 50,000 entries with LRU (Least Recently Used) eviction when full. The maximum size SHALL be configurable.

When a transaction hash is found in the rejects filter, the system SHALL skip mempool validation and silently drop the transaction.

The filter SHALL be cleared when a block is disconnected (during chain reorganization), because reorgs may change transaction validity. The filter SHALL NOT be cleared on normal forward block connects, since permanently invalid transactions (e.g. bad signatures) remain invalid regardless of new blocks.

#### Scenario: Skip validation for recently rejected transaction
- **GIVEN** transaction T was previously rejected and its hash is in the rejects filter
- **WHEN** a peer sends transaction T again
- **THEN** mempool validation is skipped
- **AND** the transaction is silently dropped

#### Scenario: Add rejected transaction to filter
- **GIVEN** a transaction fails mempool validation
- **WHEN** the rejection is processed
- **THEN** the transaction hash is added to the rejects filter

#### Scenario: Clear filter on block disconnect
- **GIVEN** the rejects filter contains entries
- **WHEN** a block is disconnected during chain reorganization
- **THEN** the rejects filter is cleared

#### Scenario: Preserve filter on forward block connect
- **GIVEN** the rejects filter contains entries
- **WHEN** a new block is connected during normal chain progress
- **THEN** the rejects filter is NOT cleared

#### Scenario: Evict oldest entry when full
- **GIVEN** the rejects filter is at capacity (50,000 entries)
- **WHEN** a new rejected transaction hash is added
- **THEN** the least recently used entry is evicted to make room

#### Scenario: Policy rejections added to filter
- **GIVEN** a transaction rejected for insufficient fee (policy violation)
- **WHEN** the rejection is processed
- **THEN** the transaction hash is added to the rejects filter (avoids re-validation cost)
