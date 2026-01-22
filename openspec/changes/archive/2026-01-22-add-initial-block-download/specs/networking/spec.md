## ADDED Requirements

### Requirement: Headers Synchronization
The system SHALL synchronize block headers using the headers-first approach.

The node sends `getheaders` messages with a block locator (list of known block hashes at exponentially decreasing heights) and receives `headers` messages containing up to 2000 headers per response.

#### Scenario: Request headers from peer
- **GIVEN** a connected peer and a block locator
- **WHEN** sending a `getheaders` message
- **THEN** the message contains the locator hashes and stop hash

#### Scenario: Receive headers response
- **GIVEN** a `headers` message from a peer
- **WHEN** parsing the message
- **THEN** up to 2000 block headers are extracted and validated

#### Scenario: Continue header sync
- **GIVEN** a `headers` response with 2000 headers
- **WHEN** processing is complete
- **THEN** another `getheaders` request is sent starting from the last received header

### Requirement: Block Download Coordination
The system SHALL coordinate block downloads across multiple peers.

Download management includes:
- Tracking which blocks are requested from which peer
- Maintaining a download window (max blocks in flight per peer)
- Distributing requests across available peers
- Handling request timeouts and retries

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

### Requirement: Sync Progress Reporting
The system SHALL track and report synchronization progress.

Progress information includes:
- Current sync state (headers/blocks/synced)
- Headers synced count and target
- Blocks downloaded count and target
- Estimated completion percentage

#### Scenario: Report header sync progress
- **GIVEN** headers are being downloaded
- **WHEN** querying sync progress
- **THEN** the current header height and estimated target are returned

#### Scenario: Report block sync progress
- **GIVEN** blocks are being downloaded
- **WHEN** querying sync progress
- **THEN** the current block height, target, and percentage complete are returned
