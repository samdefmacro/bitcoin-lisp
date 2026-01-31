## ADDED Requirements

### Requirement: Witness Data Request
The system SHALL request blocks using `MSG_WITNESS_BLOCK` (inventory type with witness flag bit set) so that peers include witness data in block responses.

The system SHALL request transactions using `MSG_WITNESS_TX` when fetching announced transactions via getdata.

#### Scenario: Request block with witness flag
- **WHEN** requesting a block from a peer
- **THEN** the getdata message uses inventory type `MSG_WITNESS_BLOCK` (0x40000002)

#### Scenario: Request transaction with witness flag
- **WHEN** fetching an announced transaction from a peer
- **THEN** the getdata message uses inventory type `MSG_WITNESS_TX` (0x40000001)
