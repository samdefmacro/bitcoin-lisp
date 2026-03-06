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

### Requirement: Pruned Node Service Advertisement
The system SHALL advertise limited block serving capability when pruning is enabled, per BIP 159.

When pruning is enabled (any mode):
- The version message SHALL include the `NODE_NETWORK_LIMITED` service bit (bit 10, value 1024)
- The version message SHALL NOT include the `NODE_NETWORK` service bit (bit 0, value 1). `NODE_NETWORK` signals full chain availability, which a pruned node cannot provide.
- The node SHALL NOT serve block data for heights at or below the pruned height
- The node SHALL respond to `getdata` for blocks within the 288-block retention window normally

#### Scenario: Advertise NODE_NETWORK_LIMITED when pruned
- **GIVEN** pruning is enabled
- **WHEN** sending a version message to a peer
- **THEN** the services field includes the NODE_NETWORK_LIMITED bit (1024)
- **AND** the services field does NOT include the NODE_NETWORK bit (1)

#### Scenario: Non-pruned node advertises NODE_NETWORK
- **GIVEN** pruning is disabled
- **WHEN** sending a version message to a peer
- **THEN** the services field includes the NODE_NETWORK bit (1)
- **AND** the services field does NOT include the NODE_NETWORK_LIMITED bit (1024)

#### Scenario: Reject getdata for pruned block
- **GIVEN** pruning is enabled and blocks up to height 5000 have been pruned
- **WHEN** a peer requests block data at height 3000
- **THEN** the request is not fulfilled
- **AND** a log message indicates the block is pruned

#### Scenario: Serve blocks within retention window
- **GIVEN** pruning is enabled and chain is at height 6000 with 288-block minimum retention
- **WHEN** a peer requests block data at height 5800
- **THEN** the block data is served normally

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

