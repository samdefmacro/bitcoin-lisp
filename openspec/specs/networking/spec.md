# networking Specification

## Purpose
TBD - created by archiving change add-bitcoin-client-foundation. Update Purpose after archive.
## Requirements
### Requirement: Peer Connection
The system SHALL establish TCP connections to Bitcoin peers.

#### Scenario: Connect to testnet peer
- **GIVEN** a testnet peer IP address and port (default 18333)
- **WHEN** initiating a connection
- **THEN** a TCP socket connection is established

#### Scenario: Handle connection failure
- **GIVEN** an unreachable peer address
- **WHEN** attempting to connect
- **THEN** the connection attempt fails gracefully with an appropriate error

### Requirement: Version Handshake
The system SHALL perform the Bitcoin version handshake when connecting to peers.

The handshake sequence:
1. Send `version` message
2. Receive `version` message from peer
3. Send `verack` message
4. Receive `verack` message from peer

#### Scenario: Complete successful handshake
- **GIVEN** a connected peer
- **WHEN** performing the version handshake
- **THEN** both sides exchange version and verack messages

#### Scenario: Reject incompatible protocol version
- **GIVEN** a peer advertising an unsupported protocol version
- **WHEN** receiving their version message
- **THEN** the connection is terminated

### Requirement: Message Sending
The system SHALL send properly formatted P2P messages to connected peers.

#### Scenario: Send inventory message
- **GIVEN** a list of inventory items (transaction or block hashes)
- **WHEN** sending an `inv` message
- **THEN** the message is serialized with correct header and checksum

#### Scenario: Send transaction message
- **GIVEN** a transaction to send to a peer
- **WHEN** sending a `tx` message
- **THEN** the transaction is serialized into a properly formatted P2P message

### Requirement: Message Receiving
The system SHALL receive and parse P2P messages from connected peers.

#### Scenario: Receive block message
- **GIVEN** an incoming `block` message from a peer
- **WHEN** the message is received
- **THEN** the block data is deserialized and made available for processing

#### Scenario: Handle malformed message
- **GIVEN** a message with invalid checksum
- **WHEN** receiving the message
- **THEN** the message is rejected and optionally the peer is penalized

### Requirement: Peer Discovery
The system SHALL discover new peers through DNS seeds and peer exchange.

#### Scenario: Query DNS seeds
- **GIVEN** testnet DNS seed hostnames
- **WHEN** querying for peer addresses
- **THEN** a list of potential peer IP addresses is returned

#### Scenario: Receive addr message
- **GIVEN** an `addr` message from a connected peer
- **WHEN** processing the message
- **THEN** the advertised addresses are added to the known peers list

### Requirement: Network Parameters
The system SHALL use correct network parameters for testnet.

Parameters include:
- Magic bytes: `0x0B110907`
- Default port: `18333`
- DNS seeds: testnet-specific seeds

#### Scenario: Use testnet magic bytes
- **GIVEN** a message being sent to a testnet peer
- **WHEN** serializing the message header
- **THEN** the magic bytes `0x0B110907` are used

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

### Requirement: Transaction Message Handling
The system SHALL send and receive `tx` P2P messages containing individual transactions.

When receiving a `tx` message:
1. Deserialize the transaction
2. Validate for mempool acceptance
3. If valid, add to mempool and relay to other peers
4. If invalid, optionally penalize the sending peer

#### Scenario: Receive valid transaction
- **GIVEN** a connected peer sends a `tx` message
- **WHEN** the transaction passes mempool validation
- **THEN** the transaction is added to the mempool

#### Scenario: Receive invalid transaction
- **GIVEN** a connected peer sends a `tx` message
- **WHEN** the transaction fails validation
- **THEN** the transaction is rejected and the peer may be penalized

### Requirement: Transaction Inventory Handling
The system SHALL handle `inv` messages containing transaction inventory and request unknown transactions via `getdata`.

#### Scenario: Request unknown transaction from inv
- **GIVEN** a peer sends an `inv` message containing a transaction hash
- **WHEN** the transaction is not in the mempool or recent rejects
- **THEN** a `getdata` message is sent requesting the transaction

#### Scenario: Ignore known transaction from inv
- **GIVEN** a peer sends an `inv` message containing a transaction hash
- **WHEN** the transaction is already in the mempool
- **THEN** no `getdata` request is sent

### Requirement: Transaction Getdata Response
The system SHALL respond to `getdata` requests for transactions by sending the requested transaction data.

#### Scenario: Respond to getdata for mempool transaction
- **GIVEN** a peer sends a `getdata` message requesting a transaction by hash
- **WHEN** the transaction exists in the mempool
- **THEN** a `tx` message containing the transaction is sent to the peer

#### Scenario: Ignore getdata for unknown transaction
- **GIVEN** a peer sends a `getdata` message requesting a transaction by hash
- **WHEN** the transaction is not in the mempool
- **THEN** no response is sent (standard Bitcoin protocol behavior)

### Requirement: Transaction Relay
The system SHALL relay newly accepted transactions to connected peers.

When a transaction is accepted into the mempool:
- An `inv` message containing the transaction hash is sent to all connected peers except the peer that sent the transaction
- The system tracks which transactions have been announced to which peers to avoid redundant announcements

#### Scenario: Relay to other peers
- **GIVEN** a transaction received from peer A is accepted into the mempool
- **WHEN** peers B and C are connected
- **THEN** an `inv` message for the transaction is sent to peers B and C but not peer A

#### Scenario: Avoid duplicate announcements
- **GIVEN** a transaction has already been announced to peer B
- **WHEN** another event would trigger re-announcement
- **THEN** the transaction is not announced again to peer B

