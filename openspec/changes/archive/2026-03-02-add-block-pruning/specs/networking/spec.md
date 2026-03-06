## ADDED Requirements

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
