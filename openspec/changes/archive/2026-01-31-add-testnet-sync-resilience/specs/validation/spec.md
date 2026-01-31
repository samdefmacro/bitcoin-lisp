## MODIFIED Requirements

### Requirement: Chain Selection
The system SHALL select the best chain based on accumulated proof of work.

When a competing chain has more accumulated work, the node reorganizes by:
1. Finding the fork point (common ancestor)
2. Disconnecting blocks from the current tip back to the fork point (rolling back UTXO changes)
3. Connecting blocks from the new chain forward from the fork point

#### Scenario: Accept longer chain
- **GIVEN** two competing chains
- **WHEN** one has more accumulated chainwork
- **THEN** that chain is selected as the best chain

#### Scenario: Handle chain reorganization
- **GIVEN** a new block that creates a longer competing chain
- **WHEN** the new chain has more work than the current best
- **THEN** the node reorganizes to the new chain, disconnecting old blocks and connecting new ones

#### Scenario: Rollback UTXO set on reorg
- **GIVEN** a chain reorganization occurs
- **WHEN** disconnecting blocks from the old chain
- **THEN** the UTXO set is rolled back by restoring spent outputs and removing created outputs

#### Scenario: Shallow reorg on testnet
- **GIVEN** a 1-3 block deep reorganization on testnet
- **WHEN** the new chain tip has more work
- **THEN** the node correctly switches chains and the UTXO set is consistent with the new tip
