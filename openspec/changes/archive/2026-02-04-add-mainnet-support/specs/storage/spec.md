## MODIFIED Requirements

### Requirement: Checkpoint Storage
The system SHALL store and validate against hardcoded checkpoints for the active network.

Checkpoints are (height, hash) pairs representing known-good blocks that the chain must pass through. During IBD, the header chain is validated against checkpoints to prevent long-range attacks.

Each network has its own set of checkpoints:
- Testnet: `*testnet-checkpoints*` - testnet-specific checkpoint blocks
- Mainnet: `*mainnet-checkpoints*` - mainnet checkpoint blocks including halving blocks

Accessor functions `get-checkpoint-hash` and `last-checkpoint-height` dispatch on the active network.

#### Scenario: Load testnet checkpoints
- **GIVEN** network is set to testnet
- **WHEN** calling `get-checkpoint-hash` or `last-checkpoint-height`
- **THEN** testnet checkpoint data is used

#### Scenario: Load mainnet checkpoints
- **GIVEN** network is set to mainnet
- **WHEN** calling `get-checkpoint-hash` or `last-checkpoint-height`
- **THEN** mainnet checkpoint data is used

#### Scenario: Validate chain against checkpoint
- **GIVEN** a header at a checkpoint height
- **WHEN** validating the header chain
- **THEN** the header hash must match the checkpoint hash for the active network

#### Scenario: Reject chain diverging before checkpoint
- **GIVEN** a header chain that diverges before the last checkpoint
- **WHEN** validating the chain
- **THEN** the chain is rejected as invalid

## ADDED Requirements

### Requirement: Network Genesis Block
The system SHALL use the correct genesis block hash for the active network.

Genesis block hashes (display format, big-endian):
- Testnet: `000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943`
- Mainnet: `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`

The `network-genesis-hash` function returns the appropriate genesis hash based on the active network.

#### Scenario: Initialize testnet chain state
- **GIVEN** network is set to testnet
- **WHEN** creating initial chain state
- **THEN** genesis hash is set to testnet genesis block

#### Scenario: Initialize mainnet chain state
- **GIVEN** network is set to mainnet
- **WHEN** creating initial chain state
- **THEN** genesis hash is set to mainnet genesis block

### Requirement: Network Data Directory
The system SHALL store blockchain data in network-appropriate directories.

Directory structure:
- Testnet: `<base-directory>/` (backward compatible, no subdirectory)
- Mainnet: `<base-directory>/mainnet/`

This ensures:
- Existing testnet data is not affected
- Mainnet and testnet data cannot be accidentally mixed
- Running both networks simultaneously is possible

#### Scenario: Store testnet data at base directory
- **GIVEN** network is set to testnet
- **WHEN** persisting blockchain data
- **THEN** files are written to `<base>/` (e.g., `~/.bitcoin-lisp/utxo.dat`)

#### Scenario: Store mainnet data in mainnet subdirectory
- **GIVEN** network is set to mainnet
- **WHEN** persisting blockchain data
- **THEN** files are written to `<base>/mainnet/` subdirectory

#### Scenario: Existing testnet data unaffected
- **GIVEN** existing testnet data at `<base>/`
- **WHEN** node starts with testnet
- **THEN** existing data is loaded normally without migration
