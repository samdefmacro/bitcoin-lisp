# validation Specification

## Purpose
TBD - created by archiving change add-bitcoin-client-foundation. Update Purpose after archive.
## Requirements
### Requirement: Transaction Structure Validation
The system SHALL validate basic transaction structure before script execution.

Checks include:
- Transaction has at least one input and one output
- No input references null outpoint (except coinbase)
- Output values are non-negative and don't exceed 21M BTC
- Total output value doesn't exceed total input value (for non-coinbase)
- Transaction size within limits

#### Scenario: Reject empty inputs
- **GIVEN** a transaction with zero inputs
- **WHEN** validating structure
- **THEN** validation fails with "no inputs" error

#### Scenario: Reject negative output value
- **GIVEN** a transaction with a negative output value
- **WHEN** validating structure
- **THEN** validation fails with "negative output" error

### Requirement: Script Validation
The system SHALL execute Bitcoin scripts to validate transaction authorization, including witness programs.

The script interpreter SHALL support:
- Stack operations (OP_DUP, OP_DROP, OP_SWAP, etc.)
- Crypto operations (OP_HASH160, OP_HASH256, OP_CHECKSIG, etc.)
- Flow control (OP_IF, OP_ELSE, OP_ENDIF, OP_VERIFY)
- Arithmetic operations (OP_ADD, OP_SUB, OP_EQUAL, etc.)
- Witness program validation (P2WPKH, P2WSH, P2TR) using deserialized witness stacks

For witness program inputs, the system SHALL pass the witness stack from the transaction's serialized witness data to the Coalton `validate-witness-program` function.

#### Scenario: Validate P2PKH transaction
- **GIVEN** a transaction spending a P2PKH output with valid signature
- **WHEN** executing scriptSig + scriptPubKey
- **THEN** the script succeeds and validation passes

#### Scenario: Reject invalid signature
- **GIVEN** a transaction with an invalid ECDSA signature
- **WHEN** executing OP_CHECKSIG
- **THEN** the script fails and validation rejects the transaction

#### Scenario: Validate P2WPKH witness input
- **GIVEN** a transaction spending a P2WPKH output with witness data containing a valid signature and public key
- **WHEN** validating the witness program
- **THEN** the witness stack is passed to the Coalton validator and validation succeeds

#### Scenario: Reject witness input with invalid signature
- **GIVEN** a transaction spending a witness program output with an invalid witness stack
- **WHEN** validating the witness program
- **THEN** validation fails with a script error

### Requirement: Block Header Validation
The system SHALL validate block headers against consensus rules.

Checks include:
- Proof of work meets target difficulty
- Timestamp within acceptable range
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

### Requirement: Contextual Validation
The system SHALL validate transactions and blocks in the context of the current chain state.

Checks include:
- All inputs reference existing UTXOs
- No double-spends
- Coinbase maturity (100 blocks before spendable)
- Sequence locks and timelocks

#### Scenario: Reject double spend
- **GIVEN** a transaction spending an already-spent UTXO
- **WHEN** validating against UTXO set
- **THEN** validation fails with "input already spent" error

#### Scenario: Enforce coinbase maturity
- **GIVEN** a transaction spending a coinbase output
- **WHEN** the coinbase is less than 100 blocks deep
- **THEN** validation fails with "coinbase not mature" error

### Requirement: Chain Selection
The system SHALL select the best chain based on accumulated proof of work.

#### Scenario: Accept longer chain
- **GIVEN** two competing chains
- **WHEN** one has more accumulated chainwork
- **THEN** that chain is selected as the best chain

#### Scenario: Handle chain reorganization
- **GIVEN** a new block that creates a longer competing chain
- **WHEN** the new chain has more work than the current best
- **THEN** the node reorganizes to the new chain, disconnecting old blocks and connecting new ones

### Requirement: Header Chain Validation
The system SHALL validate block headers form a valid chain.

Header validation checks:
- Previous block hash references the prior header
- Proof of work meets the target difficulty
- Timestamp is greater than median of previous 11 blocks
- Timestamp is not more than 2 hours in the future
- Version is acceptable for the height

#### Scenario: Validate header links
- **GIVEN** a sequence of block headers
- **WHEN** validating the chain
- **THEN** each header's prev_hash matches the prior header's hash

#### Scenario: Validate header proof of work
- **GIVEN** a block header
- **WHEN** validating proof of work
- **THEN** the block hash is below the target derived from the bits field

#### Scenario: Reject header with bad timestamp
- **GIVEN** a header with timestamp before median-time-past
- **WHEN** validating the header
- **THEN** validation fails with "timestamp too old" error

### Requirement: Block Connection
The system SHALL connect validated blocks to the chain state.

Connection involves:
- Verifying block matches its header
- Validating all transactions in context
- Updating UTXO set (add new outputs, remove spent outputs)
- Updating chain state (height, tip, chainwork)

#### Scenario: Connect block to chain
- **GIVEN** a fully validated block
- **WHEN** connecting to the chain
- **THEN** the UTXO set and chain state are updated atomically

#### Scenario: Handle out-of-order blocks
- **GIVEN** blocks arriving out of height order
- **WHEN** a block's parent is not yet connected
- **THEN** the block is queued until its parent is connected

#### Scenario: Reject block with invalid transactions
- **GIVEN** a block containing an invalid transaction
- **WHEN** validating the block
- **THEN** the block is rejected and the peer may be penalized

### Requirement: IBD Validation Mode
The system SHALL use optimized validation during Initial Block Download.

During IBD (when significantly behind chain tip):
- Script validation may be skipped for blocks covered by checkpoints
- Signature validation may use parallel verification
- UTXO set updates are batched for efficiency

After IBD completes, full validation resumes for all new blocks.

#### Scenario: Skip scripts before checkpoint
- **GIVEN** a block at height below the last checkpoint
- **WHEN** in IBD mode with checkpoint-guarded optimization enabled
- **THEN** script validation may be skipped (signatures still checked)

#### Scenario: Full validation after IBD
- **GIVEN** a block received after IBD completes
- **WHEN** validating the block
- **THEN** full script and signature validation is performed

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

