## ADDED Requirements

### Requirement: Fee Estimation Data Collection
The system SHALL collect fee rate statistics from confirmed blocks for fee estimation.

For each connected block, the system records:
- Block height
- Median fee rate of transactions (sat/vB)
- 10th percentile fee rate (low priority baseline)
- 90th percentile fee rate (high priority baseline)
- Transaction count (excluding coinbase)

Fee history is maintained for the most recent 1008 blocks (~1 week).

#### Scenario: Record fee stats on block connect
- **GIVEN** a block with transactions is connected
- **WHEN** the block contains non-coinbase transactions with computable fees
- **THEN** fee statistics are computed and stored in the estimator history

#### Scenario: Handle empty block
- **GIVEN** a block containing only the coinbase transaction
- **WHEN** the block is connected
- **THEN** no fee statistics are recorded for that block (skipped)

#### Scenario: Maintain history limit
- **GIVEN** fee history contains 1008 block entries
- **WHEN** a new block is connected
- **THEN** the oldest entry is removed and the new entry is added

### Requirement: Fee Rate Estimation
The system SHALL estimate transaction fee rates based on historical block data.

The estimation algorithm:
- Analyzes fee rates from recent blocks proportional to confirmation target
- Returns a percentile-based estimate (higher percentile for faster confirmation)
- Falls back to minimum relay fee when insufficient data is available

Confirmation target ranges:
- 1-2 blocks: Use 90th percentile from recent blocks
- 3-6 blocks: Use 85th percentile
- 7-144 blocks: Use progressively lower percentiles
- 145-1008 blocks: Use 25th percentile (economy)

#### Scenario: Estimate fee for fast confirmation
- **GIVEN** fee estimator has sufficient history (6+ blocks)
- **WHEN** estimate is requested for conf_target=2
- **THEN** returns 90th percentile fee rate from recent blocks

#### Scenario: Estimate fee for economy confirmation
- **GIVEN** fee estimator has sufficient history
- **WHEN** estimate is requested for conf_target=144
- **THEN** returns lower percentile fee rate suitable for next-day confirmation

#### Scenario: Insufficient history fallback
- **GIVEN** fee estimator has fewer than 6 blocks of history
- **WHEN** estimate is requested
- **THEN** returns minimum relay fee (1 sat/vB) with warning

#### Scenario: Conservative vs economical mode
- **GIVEN** sufficient fee history exists
- **WHEN** estimate is requested with mode="economical"
- **THEN** returns lower percentile (15 points lower) than mode="conservative" for same conf_target

### Requirement: Fee Stats Persistence
The system SHALL persist fee statistics to disk for recovery across restarts.

Fee statistics cannot be recalculated after block connection (input values are only available during connection). Therefore, the system persists fee stats to a file.

File format includes:
- Magic bytes and version for format detection
- Entry count
- Fee stats entries (height, median-rate, low-rate, high-rate, tx-count)
- CRC32 checksum for integrity

#### Scenario: Save fee stats on shutdown
- **GIVEN** fee estimator has recorded statistics
- **WHEN** node shuts down gracefully
- **THEN** fee stats are written to disk

#### Scenario: Load fee stats on startup
- **GIVEN** a valid fee stats file exists
- **WHEN** node starts
- **THEN** fee history is restored from the file

#### Scenario: Handle missing fee stats file
- **GIVEN** no fee stats file exists (fresh install)
- **WHEN** node starts
- **THEN** fee estimator starts with empty history (cold start)

#### Scenario: Handle corrupt fee stats file
- **GIVEN** fee stats file has invalid CRC32
- **WHEN** node starts
- **THEN** file is rejected and estimator starts with empty history

### Requirement: Fee Estimator Readiness
The system SHALL indicate when fee estimation data is sufficient.

The estimator requires a minimum number of blocks (default: 6) before providing computed estimates. Until this threshold is reached, the estimator returns fallback values with warnings.

#### Scenario: Ready after minimum blocks
- **GIVEN** fee history has 6 or more block entries
- **WHEN** fee estimate is requested
- **THEN** estimator returns computed estimate (not fallback)

#### Scenario: Not ready with insufficient history
- **GIVEN** fee history has fewer than 6 block entries
- **WHEN** fee estimate is requested
- **THEN** estimator returns minimum relay fee with warning
