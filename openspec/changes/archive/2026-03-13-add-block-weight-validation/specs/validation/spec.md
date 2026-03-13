## ADDED Requirements

### Requirement: Block Weight Validation
The system SHALL validate that the total weight of a block does not exceed the maximum block weight limit of 4,000,000 weight units (BIP 141).

Block weight is calculated as the sum of all transaction weights in the block.

Transaction weight is defined as: `(base_size * 3) + total_size`, where:
- `base_size` is the serialized size without witness data (legacy serialization)
- `total_size` is the serialized size with witness data (BIP 144 serialization)
- For legacy (non-witness) transactions, `base_size == total_size`, so weight = `total_size * 4`

The weight formula applies the witness discount: witness data counts as 1 weight unit per byte, while non-witness data counts as 4 weight units per byte.

#### Scenario: Accept block within weight limit
- **GIVEN** a block whose total transaction weight is 3,999,999 weight units
- **WHEN** validating the block
- **THEN** weight validation passes

#### Scenario: Reject block exceeding weight limit
- **GIVEN** a block whose total transaction weight is 4,000,001 weight units
- **WHEN** validating the block
- **THEN** validation fails with :block-too-heavy error

#### Scenario: Legacy transaction weight
- **GIVEN** a legacy (non-witness) transaction with serialized size of 250 bytes
- **WHEN** calculating its weight
- **THEN** the weight is 1000 (250 * 4)

#### Scenario: Witness transaction weight
- **GIVEN** a SegWit transaction with base_size of 200 bytes and total_size of 250 bytes
- **WHEN** calculating its weight
- **THEN** the weight is 850 (200 * 3 + 250)
