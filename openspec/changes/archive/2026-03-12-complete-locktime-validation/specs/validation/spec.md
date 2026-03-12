## ADDED Requirements

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
