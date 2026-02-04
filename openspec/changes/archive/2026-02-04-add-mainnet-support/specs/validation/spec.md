## MODIFIED Requirements

### Requirement: Block Validation
The system SHALL validate complete blocks against consensus rules with network-appropriate activation heights.

BIP 34 (coinbase height encoding) activation heights:
- Testnet: 21111
- Mainnet: 227931

The `get-bip34-activation-height` function returns the appropriate height based on the active network.

For blocks at or above the activation height, the coinbase scriptSig must start with a push of the block height.

#### Scenario: Validate BIP 34 coinbase height on testnet
- **GIVEN** network is testnet and block height >= 21111
- **WHEN** validating the coinbase transaction
- **THEN** the coinbase scriptSig must start with a push of the block height

#### Scenario: Validate BIP 34 coinbase height on mainnet
- **GIVEN** network is mainnet and block height >= 227931
- **WHEN** validating the coinbase transaction
- **THEN** the coinbase scriptSig must start with a push of the block height

#### Scenario: Skip BIP 34 check below activation
- **GIVEN** block height is below the network's BIP 34 activation height
- **WHEN** validating the coinbase transaction
- **THEN** coinbase height encoding is not required

#### Scenario: Reject wrong coinbase height
- **GIVEN** block height >= activation height
- **WHEN** coinbase encodes a different height than the actual block height
- **THEN** validation fails with "bad coinbase height" error

## ADDED Requirements

### Requirement: Network Selection Validation
The system SHALL validate network selection at startup.

Validation checks:
- Network parameter is valid (`:testnet` or `:mainnet`)
- Invalid network values cause initialization failure with clear error

#### Scenario: Accept valid testnet selection
- **GIVEN** network is set to `:testnet`
- **WHEN** node initializes
- **THEN** initialization proceeds with testnet parameters

#### Scenario: Accept valid mainnet selection
- **GIVEN** network is set to `:mainnet`
- **WHEN** node initializes
- **THEN** initialization proceeds with mainnet parameters

#### Scenario: Reject invalid network parameter
- **GIVEN** network is set to an unrecognized value (e.g., `:invalid`)
- **WHEN** attempting to initialize
- **THEN** initialization fails with a clear error message

### Requirement: Mainnet Startup Warning
The system SHALL log a warning when starting on mainnet.

This ensures users are aware they are operating on the production Bitcoin network where real value is at stake.

#### Scenario: Warn on mainnet startup
- **GIVEN** network is set to mainnet
- **WHEN** node starts
- **THEN** a warning is logged indicating mainnet operation

#### Scenario: No warning on testnet
- **GIVEN** network is set to testnet
- **WHEN** node starts
- **THEN** no mainnet warning is logged
