## MODIFIED Requirements

### Requirement: Block Header Validation
The system SHALL validate block headers against consensus rules.

Checks include:
- Proof of work meets target difficulty
- Timestamp within acceptable range
- Timestamp is greater than median-time-past of the previous 11 blocks
- Previous block hash references a known block
- Block version is acceptable

#### Scenario: Validate proof of work
- **GIVEN** a block header
- **WHEN** checking proof of work
- **THEN** the block hash is verified to be below the target derived from bits field

#### Scenario: Reject future timestamp
- **GIVEN** a block header with timestamp >2 hours in the future
- **WHEN** validating the header
- **THEN** validation fails with "timestamp too far in future" error

#### Scenario: Reject timestamp at or before MTP
- **GIVEN** a block header with timestamp <= median-time-past of the previous 11 blocks
- **WHEN** validating the header
- **THEN** validation fails with :time-too-old error
