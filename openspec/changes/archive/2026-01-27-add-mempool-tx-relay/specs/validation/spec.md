## ADDED Requirements

### Requirement: Mempool Policy Validation
The system SHALL enforce mempool acceptance policies beyond consensus rules.

Policy checks include:
- Minimum relay fee-rate (default: 1 satoshi per virtual byte)
- Maximum transaction size for relay
- Standard script types only (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- Maximum signature operations

These policies are stricter than consensus rules and may reject transactions that would be valid in a block.

#### Scenario: Reject below minimum relay fee
- **GIVEN** a transaction with fee-rate below 1 sat/vbyte
- **WHEN** validating for mempool acceptance
- **THEN** the transaction is rejected with policy violation error

#### Scenario: Reject non-standard script
- **GIVEN** a transaction with a non-standard output script type
- **WHEN** validating for mempool acceptance
- **THEN** the transaction is rejected as non-standard

#### Scenario: Accept standard transaction meeting policy
- **GIVEN** a transaction with standard scripts and sufficient fee-rate
- **WHEN** validating for mempool acceptance
- **THEN** policy validation passes
