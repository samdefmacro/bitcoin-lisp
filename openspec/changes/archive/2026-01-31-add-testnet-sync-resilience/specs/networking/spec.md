## ADDED Requirements

### Requirement: Peer Health Monitoring
The system SHALL monitor peer connection health and disconnect unresponsive peers.

Health monitoring includes:
- Sending periodic ping messages (every 60 seconds)
- Tracking ping response times
- Disconnecting peers that fail to respond to 3 consecutive pings

#### Scenario: Ping responsive peer
- **GIVEN** a connected peer
- **WHEN** a ping is sent and a matching pong is received within 30 seconds
- **THEN** the peer remains connected and latency is updated

#### Scenario: Disconnect unresponsive peer
- **GIVEN** a connected peer that has not responded to 3 consecutive pings
- **WHEN** the health check runs
- **THEN** the peer is disconnected

### Requirement: Automatic Peer Reconnection
The system SHALL maintain the target peer count by automatically connecting replacement peers when connections are lost.

#### Scenario: Replace disconnected peer
- **GIVEN** a peer disconnects during operation
- **WHEN** the peer count falls below the target
- **THEN** a new peer is connected from the known address pool

#### Scenario: Maintain peer count during sync
- **GIVEN** the node is syncing blocks
- **WHEN** peer connections are lost
- **THEN** replacement peers are connected without interrupting sync

### Requirement: Block Request Peer Rotation
The system SHALL rotate to a different peer when a block request times out, and disconnect peers with repeated timeouts.

#### Scenario: Retry with different peer
- **GIVEN** a block request to peer A has timed out
- **WHEN** retrying the request
- **THEN** the request is sent to a different peer B

#### Scenario: Disconnect slow peer
- **GIVEN** a peer has timed out on 3 block requests
- **WHEN** the third timeout occurs
- **THEN** the peer is disconnected and replaced

## MODIFIED Requirements

### Requirement: Block Download Coordination
The system SHALL coordinate block downloads across multiple peers.

Download management includes:
- Tracking which blocks are requested from which peer
- Maintaining a download window (max blocks in flight per peer)
- Distributing requests across available peers
- Handling request timeouts with peer rotation
- Processing out-of-order blocks when their parents become available

#### Scenario: Request block from peer
- **GIVEN** a block hash to download and an available peer
- **WHEN** the block is not already in-flight
- **THEN** a `getdata` message is sent and the request is tracked

#### Scenario: Handle block timeout
- **GIVEN** a block request that has not been fulfilled
- **WHEN** the timeout period expires
- **THEN** the request is retried with a different peer

#### Scenario: Distribute requests across peers
- **GIVEN** multiple connected peers and blocks to download
- **WHEN** requesting blocks
- **THEN** requests are distributed to balance load across peers

#### Scenario: Process out-of-order block
- **GIVEN** a block arrives whose parent was not yet connected
- **WHEN** the parent block is subsequently connected
- **THEN** the queued block is processed immediately
