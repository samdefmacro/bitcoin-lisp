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

### Requirement: Median-Time-Past Calculation (BIP 113)
The system SHALL calculate the median-time-past (MTP) for locktime evaluation as the median timestamp of the previous 11 blocks.

For blocks at or above the BIP 113 activation height (419,328 mainnet / 770,112 testnet), nLockTime comparisons SHALL use MTP instead of the block's own timestamp.

For blocks with fewer than 11 ancestors, the median is calculated from all available ancestor timestamps.

#### Scenario: Calculate MTP from 11 blocks
- **GIVEN** 11 previous block timestamps [1, 3, 5, 7, 9, 11, 2, 4, 6, 8, 10]
- **WHEN** computing median-time-past
- **THEN** the result is 6 (median of sorted values)

#### Scenario: Calculate MTP with fewer than 11 blocks
- **GIVEN** only 5 previous block timestamps [100, 200, 300, 400, 500]
- **WHEN** computing median-time-past
- **THEN** the result is 300 (median of available timestamps)

#### Scenario: MTP used for locktime after activation
- **GIVEN** a block at height >= 419,328 (mainnet) with MTP of 1600000000
- **WHEN** evaluating a transaction with nLockTime=1599999999 (time-based)
- **THEN** the transaction's locktime is satisfied (nLockTime < MTP)

### Requirement: Transaction Finality Check (IsFinalTx)
The system SHALL verify that every non-coinbase transaction in a block has a satisfied locktime during block connection.

A transaction is final if any of the following conditions are met:
- nLockTime is 0
- All input sequences are 0xFFFFFFFF (SEQUENCE_FINAL)
- nLockTime < 500,000,000 (height-based) and nLockTime < block height
- nLockTime >= 500,000,000 (time-based) and nLockTime < block time

For blocks at or above the BIP 113 activation height, time-based nLockTime comparisons SHALL use median-time-past instead of the block's own timestamp.

#### Scenario: Transaction with nLockTime=0 is final
- **GIVEN** a transaction with nLockTime=0
- **WHEN** checking finality during block connection
- **THEN** the transaction is final regardless of block height or time

#### Scenario: Transaction with all SEQUENCE_FINAL inputs is final
- **GIVEN** a transaction with nLockTime=500000 and all inputs have nSequence=0xFFFFFFFF
- **WHEN** checking finality during block connection
- **THEN** the transaction is final because all sequences are final

#### Scenario: Height-based locktime satisfied
- **GIVEN** a transaction with nLockTime=400000 (height-based) in a block at height 400001
- **WHEN** checking finality
- **THEN** the transaction is final (block height > nLockTime)

#### Scenario: Height-based locktime not satisfied
- **GIVEN** a transaction with nLockTime=400000 in a block at height 399999
- **WHEN** checking finality
- **THEN** the block is rejected because the transaction is not final

#### Scenario: Time-based locktime uses MTP after BIP 113
- **GIVEN** a transaction with nLockTime=1600000000 (time-based) in a block at height >= 419,328 (mainnet) with MTP=1600000001
- **WHEN** checking finality with BIP 113 active
- **THEN** the transaction is final (MTP > nLockTime)

### Requirement: BIP 68 Sequence Lock Enforcement
The system SHALL enforce relative locktime (BIP 68 sequence locks) during block connection for blocks at or above activation height (419,328 mainnet / 770,112 testnet).

For each non-coinbase transaction with version >= 2, each input's nSequence is examined:
- If nSequence bit 31 (0x80000000) is set, the input is exempt from relative locktime
- If bit 22 (0x00400000) is clear (height-based): the input's referenced UTXO must be at least (nSequence & 0xFFFF) blocks deep
- If bit 22 is set (time-based): the median-time-past of the current block must be at least (nSequence & 0xFFFF) * 512 seconds after the MTP at the height when the referenced UTXO was confirmed

Transactions with version < 2 are exempt from BIP 68 enforcement.

#### Scenario: Height-based sequence lock satisfied
- **GIVEN** a transaction (version 2) spending a UTXO confirmed 20 blocks ago, with input nSequence=10 (height-based)
- **WHEN** validating the transaction during block connection
- **THEN** the sequence lock is satisfied (20 >= 10)

#### Scenario: Height-based sequence lock not satisfied
- **GIVEN** a transaction (version 2) spending a UTXO confirmed 5 blocks ago, with input nSequence=10 (height-based)
- **WHEN** validating the transaction during block connection
- **THEN** validation fails because the UTXO is not deep enough (5 < 10)

#### Scenario: Time-based sequence lock satisfied
- **GIVEN** a transaction (version 2) with input nSequence=0x400003 (time-based, 3 units = 1536 seconds) and MTP delta of 2000 seconds since UTXO confirmation
- **WHEN** validating during block connection
- **THEN** the sequence lock is satisfied (2000 >= 1536)

#### Scenario: Sequence lock disabled by bit 31
- **GIVEN** a transaction with input nSequence=0xFFFFFFFE (bit 31 set)
- **WHEN** checking sequence locks
- **THEN** the input is exempt from relative locktime checks

#### Scenario: Tx version 1 exempt from BIP 68
- **GIVEN** a transaction with version=1 and nSequence values that would fail BIP 68
- **WHEN** checking sequence locks
- **THEN** the transaction is exempt (BIP 68 only applies to version >= 2)

#### Scenario: Skip enforcement below activation height
- **GIVEN** a block below the BIP 68 activation height
- **WHEN** connecting the block
- **THEN** sequence lock checks are not enforced

### Requirement: Locktime Activation Heights
The system SHALL enforce locktime-related BIPs based on network-specific activation heights.

Activation heights:
- BIP 65 (CLTV): 388,381 (mainnet) / 581,885 (testnet)
- BIP 68 (sequence locks): 419,328 (mainnet) / 770,112 (testnet)
- BIP 112 (CSV): 419,328 (mainnet) / 770,112 (testnet)
- BIP 113 (MTP): 419,328 (mainnet) / 770,112 (testnet)

Script verification flags (CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY) SHALL be set based on block height relative to activation heights.

#### Scenario: CLTV flag enabled at activation height
- **GIVEN** a block at height 388,381 on mainnet
- **WHEN** setting script verification flags
- **THEN** the CHECKLOCKTIMEVERIFY flag is enabled

#### Scenario: CSV flag not enabled below activation
- **GIVEN** a block at height 419,327 on mainnet
- **WHEN** setting script verification flags
- **THEN** the CHECKSEQUENCEVERIFY flag is not enabled

#### Scenario: All locktime flags enabled above activation
- **GIVEN** a block at height 500,000 on mainnet
- **WHEN** setting script verification flags
- **THEN** both CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY flags are enabled

### Requirement: Difficulty Adjustment Validation
The system SHALL validate that each block header's `bits` field matches the expected difficulty target according to Bitcoin's retarget algorithm.

Difficulty retarget rules:
- Every 2016 blocks (the "retarget interval"), the difficulty target is recalculated
- The retarget timespan is measured from block `height - 2016` to block `height - 1` (2015 inter-block intervals, matching Bitcoin Core's known off-by-one)
- The new target = previous target * (actual timespan / target timespan), where target timespan is 1,209,600 seconds (2 weeks)
- The adjustment is clamped: no more than 4x increase or 4x decrease per retarget period
- The target SHALL NOT exceed the network's proof-of-work limit (minimum difficulty, bits = 0x1d00ffff)
- For blocks in the first retarget period (height 0–2015), `bits` MUST equal the genesis block's bits (0x1d00ffff)
- On mainnet, between retarget boundaries, all blocks MUST use the same `bits` value as the previous block

Network-specific testnet rules:
- When more than 20 minutes (1200 seconds) have elapsed since the previous block's timestamp, a min-difficulty `bits` value of 0x1d00ffff is accepted
- When within 20 minutes, the expected `bits` is found by walking back through the chain to the last block that either (a) is at a retarget boundary (height % 2016 == 0) or (b) does not have min-difficulty bits, and using that block's `bits`

#### Scenario: Validate bits at retarget boundary
- **GIVEN** a block at height 2016 (a retarget boundary) where the timespan from block 0 to block 2015 was 1,209,600 seconds (exactly 2 weeks)
- **WHEN** validating the block header
- **THEN** the `bits` field equals the previous period's `bits` (no change needed)

#### Scenario: Reject incorrect bits at retarget boundary
- **GIVEN** a block at height 2016 with `bits` that does not match the calculated retarget value
- **WHEN** validating the block header
- **THEN** validation fails with :bad-difficulty error

#### Scenario: Validate bits in first retarget period
- **GIVEN** a block at height 500 (within the first retarget period)
- **WHEN** validating the block header
- **THEN** the `bits` field MUST equal 0x1d00ffff (genesis/PoW-limit difficulty)

#### Scenario: Validate bits between retarget boundaries on mainnet
- **GIVEN** mainnet network and a block at height 3000 (not a retarget boundary)
- **WHEN** validating the block header
- **THEN** the `bits` field MUST equal the previous block's `bits` field

#### Scenario: Clamp retarget to 4x maximum adjustment
- **GIVEN** a retarget period where the timespan was only 302,400 seconds (1/4 of target timespan)
- **WHEN** calculating the new difficulty
- **THEN** the adjustment is clamped to 4x increase (timespan treated as 302,400 seconds minimum)

#### Scenario: Clamp retarget to 4x minimum adjustment
- **GIVEN** a retarget period where the timespan was 4,838,400 seconds (4x target timespan)
- **WHEN** calculating the new difficulty
- **THEN** the adjustment is clamped to 4x decrease (timespan treated as 4,838,400 seconds maximum)

#### Scenario: Testnet min-difficulty exception
- **GIVEN** testnet network and a block whose timestamp is more than 20 minutes after the previous block's timestamp
- **WHEN** validating the block header's `bits` field
- **THEN** a `bits` value of 0x1d00ffff (minimum difficulty) is accepted

#### Scenario: Testnet walk-back after min-difficulty blocks
- **GIVEN** testnet network, a block whose timestamp is within 20 minutes of the previous block, and the previous 3 blocks all used min-difficulty bits
- **WHEN** validating the block header's `bits` field
- **THEN** the expected `bits` is the `bits` from the last block that either sits at a retarget boundary or does not have min-difficulty bits

