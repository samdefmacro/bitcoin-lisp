## MODIFIED Requirements

### Requirement: Fee Estimation
The system SHALL provide a method to estimate transaction fees based on historical block data.

Method:
- `estimatesmartfee <conf_target> [estimate_mode]`

Parameters:
- `conf_target`: Number of blocks for confirmation target (1-1008)
- `estimate_mode`: "conservative" (default) or "economical"

Returns:
- `feerate`: Estimated fee rate in BTC/kvB (1000 virtual bytes)
- `blocks`: The conf_target value (may be adjusted if insufficient data)
- `errors`: Array of warning messages (optional, present when data is limited)

The estimate is computed from historical fee rates in confirmed blocks:
- Conservative mode uses higher percentiles for more reliable confirmation
- Economical mode uses lower percentiles for cost savings with longer wait

When insufficient historical data exists (fewer than 6 blocks), returns the minimum relay fee with a warning.

#### Scenario: estimatesmartfee with sufficient data
- **GIVEN** node has processed at least 6 blocks with fee data
- **WHEN** estimatesmartfee(6) is called
- **THEN** response includes computed feerate based on historical data

#### Scenario: estimatesmartfee conservative mode
- **GIVEN** node has sufficient fee history
- **WHEN** estimatesmartfee(6, "conservative") is called
- **THEN** response feerate uses higher percentile for reliable confirmation

#### Scenario: estimatesmartfee economical mode
- **GIVEN** node has sufficient fee history
- **WHEN** estimatesmartfee(6, "economical") is called
- **THEN** response feerate is lower than conservative mode for same target

#### Scenario: estimatesmartfee insufficient data
- **GIVEN** node has fewer than 6 blocks of fee history
- **WHEN** estimatesmartfee is called
- **THEN** response includes minimum fee with errors array containing warning

#### Scenario: estimatesmartfee during IBD
- **GIVEN** node is still performing initial block download
- **WHEN** estimatesmartfee is called
- **THEN** error is returned indicating insufficient data

#### Scenario: estimatesmartfee invalid target zero
- **GIVEN** conf_target is 0
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: estimatesmartfee invalid target negative
- **GIVEN** conf_target is negative
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: estimatesmartfee invalid target too high
- **GIVEN** conf_target is greater than 1008
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

### Requirement: Mempool Information
The system SHALL provide a method to query mempool statistics.

Method:
- `getmempoolinfo`

Returns:
- `loaded`: Boolean indicating mempool is fully loaded
- `size`: Number of transactions in mempool
- `bytes`: Total size of mempool in bytes
- `mempoolminfee`: Minimum fee rate (BTC/kvB) to enter mempool
- `minrelaytxfee`: Configured minimum relay fee rate (BTC/kvB)

#### Scenario: getmempoolinfo returns fee fields
- **GIVEN** a running node with mempool
- **WHEN** getmempoolinfo is called
- **THEN** response includes mempoolminfee and minrelaytxfee fields

#### Scenario: mempoolminfee reflects eviction threshold
- **GIVEN** mempool is at capacity with transactions
- **WHEN** getmempoolinfo is called
- **THEN** mempoolminfee reflects the minimum fee rate that would be accepted
