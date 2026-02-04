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
The system SHALL use correct network parameters for the selected network.

Parameters are selected based on the active network (`:testnet` or `:mainnet`):

| Parameter | Testnet | Mainnet |
|-----------|---------|---------|
| Magic bytes | `0x0B110907` | `0xF9BEB4D9` |
| Default port | 18333 | 8333 |
| DNS seeds | testnet-specific | mainnet-specific |
| Default RPC port | 18332 | 8332 |

The system SHALL reject peer connections using incorrect magic bytes for the active network.

#### Scenario: Use testnet magic bytes
- **GIVEN** network is set to testnet
- **WHEN** serializing a message header
- **THEN** the magic bytes `0x0B110907` are used

#### Scenario: Use mainnet magic bytes
- **GIVEN** network is set to mainnet
- **WHEN** serializing a message header
- **THEN** the magic bytes `0xF9BEB4D9` are used

#### Scenario: Use mainnet default RPC port
- **GIVEN** network is set to mainnet and no explicit RPC port specified
- **WHEN** starting the RPC server
- **THEN** port 8332 is used

#### Scenario: Reject cross-network connection
- **GIVEN** network is set to testnet
- **WHEN** receiving a message with mainnet magic bytes
- **THEN** the message is rejected

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

### Requirement: Witness Data Request
The system SHALL request blocks using `MSG_WITNESS_BLOCK` (inventory type with witness flag bit set) so that peers include witness data in block responses.

The system SHALL request transactions using `MSG_WITNESS_TX` when fetching announced transactions via getdata.

#### Scenario: Request block with witness flag
- **WHEN** requesting a block from a peer
- **THEN** the getdata message uses inventory type `MSG_WITNESS_BLOCK` (0x40000002)

#### Scenario: Request transaction with witness flag
- **WHEN** fetching an announced transaction from a peer
- **THEN** the getdata message uses inventory type `MSG_WITNESS_TX` (0x40000001)

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

### Requirement: Mainnet Transaction Relay Control
The system SHALL allow disabling transaction relay on mainnet for safety.

When mainnet relay is disabled:
- The node validates and stores blocks normally
- The node does NOT send `inv` messages for transactions to peers
- The node does NOT respond to `getdata` requests for mempool transactions
- A log message indicates relay status at startup

Default: Relay disabled on mainnet.

#### Scenario: Disable relay on mainnet
- **GIVEN** network is set to mainnet and relay is disabled
- **WHEN** a transaction is accepted to mempool
- **THEN** no `inv` message is sent to peers

#### Scenario: Log relay status at startup
- **GIVEN** network is set to mainnet
- **WHEN** node starts
- **THEN** a log message indicates whether transaction relay is enabled or disabled

