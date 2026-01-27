## ADDED Requirements

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

## MODIFIED Requirements

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
