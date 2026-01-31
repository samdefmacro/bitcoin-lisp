## MODIFIED Requirements

### Requirement: Block Validation
The system SHALL validate complete blocks against consensus rules.

Checks include:
- First transaction is coinbase, no others are
- Coinbase value doesn't exceed block reward + fees
- All transactions have valid structure and contextual rules (UTXO existence, fees)
- All non-coinbase transaction scripts are executed and validated via the Coalton interop engine
- Merkle root matches transaction hashes
- Block size within limits
- Witness commitment matches witness merkle root (for blocks with witness data)
- Coinbase scriptSig encodes the block height (BIP 34, for blocks at/above activation height)

#### Scenario: Validate transaction scripts during block connection
- **GIVEN** a block containing transactions with signatures
- **WHEN** validating the block
- **THEN** all non-coinbase transaction scripts are executed via the Coalton interop engine and must pass

#### Scenario: Reject block with invalid signature
- **GIVEN** a block containing a transaction with an invalid ECDSA or Schnorr signature
- **WHEN** validating the block
- **THEN** validation fails and the block is rejected

#### Scenario: Validate SegWit scripts during block connection
- **GIVEN** a block containing P2WPKH or P2WSH transactions
- **WHEN** validating the block
- **THEN** witness programs are validated via `validate-witness-program` with BIP 143 sighash

#### Scenario: Validate Taproot scripts during block connection
- **GIVEN** a block containing P2TR transactions
- **WHEN** validating the block
- **THEN** Taproot key-path or script-path spending is validated via `validate-taproot`

#### Scenario: Validate merkle root
- **GIVEN** a block with transactions
- **WHEN** computing the merkle root
- **THEN** it matches the merkle root in the header

#### Scenario: Reject excess coinbase value
- **GIVEN** a block where coinbase output exceeds (subsidy + fees)
- **WHEN** validating the block
- **THEN** validation fails with "coinbase value too high" error

#### Scenario: Validate witness commitment
- **GIVEN** a block containing SegWit transactions with witness data
- **WHEN** validating the block
- **THEN** the witness merkle root commitment in the coinbase OP_RETURN output is verified

#### Scenario: Reject invalid witness commitment
- **GIVEN** a block with witness data but incorrect witness commitment hash
- **WHEN** validating the block
- **THEN** validation fails with "bad witness commitment" error

#### Scenario: Validate BIP 34 coinbase height
- **GIVEN** a block at height >= 21111 (testnet) or 227931 (mainnet)
- **WHEN** validating the coinbase transaction
- **THEN** the coinbase scriptSig starts with a push of the block height

#### Scenario: Reject wrong coinbase height
- **GIVEN** a block at height >= activation with coinbase encoding a different height
- **WHEN** validating the block
- **THEN** validation fails with "bad coinbase height" error

## ADDED Requirements

### Requirement: Reorg Resilience
The system SHALL handle chain reorganization edge cases gracefully.

When undo data is unavailable for a block being disconnected, the reorg SHALL fail with an explicit error rather than silently corrupting the UTXO set.

#### Scenario: Fail reorg when undo data missing
- **GIVEN** a chain reorganization requiring disconnection of a block
- **WHEN** the undo data for that block is not available
- **THEN** the reorg fails with an explicit error and the chain state is unchanged

#### Scenario: Multi-block reorg
- **GIVEN** a competing chain that is 3+ blocks longer than the current chain
- **WHEN** the competing chain has more accumulated work
- **THEN** the node reorganizes by disconnecting old blocks and connecting new blocks in order
