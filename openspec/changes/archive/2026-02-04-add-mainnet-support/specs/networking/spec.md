## MODIFIED Requirements

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

## ADDED Requirements

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
