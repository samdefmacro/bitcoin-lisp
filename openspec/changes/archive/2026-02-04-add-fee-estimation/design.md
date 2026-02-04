# Design: Fee Estimation

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                       RPC Layer                              │
│            estimatesmartfee    getmempoolinfo               │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│                    Fee Estimator                             │
│  ┌──────────────────┐  ┌──────────────────────────────────┐ │
│  │ Block Fee Stats  │  │  Estimation Algorithm            │ │
│  │ (historical)     │──│  (percentile-based)              │ │
│  └──────────────────┘  └──────────────────────────────────┘ │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Block Validation / Mempool                      │
│  (provides fee data when blocks are connected)               │
└─────────────────────────────────────────────────────────────┘
```

## Fee Data Collection

### What We Track
For each confirmed block, record fee statistics:
- Block height
- Median fee rate (sat/vB)
- 10th percentile fee rate (for low priority)
- 90th percentile fee rate (for high priority)
- Number of transactions

### Data Structure
```lisp
(defstruct block-fee-stats
  height        ; Block height
  median-rate   ; Median fee rate in sat/vB
  low-rate      ; 10th percentile
  high-rate     ; 90th percentile
  tx-count)     ; Number of transactions

(defstruct fee-estimator
  history       ; Circular buffer of block-fee-stats (last 1008 blocks)
  history-size  ; Current number of entries
  min-blocks)   ; Minimum blocks needed for estimation (default: 6)
```

### Collection Point
When `connect-block` succeeds, compute fee statistics for all non-coinbase transactions in the block and record them.

Fee rate calculation requires input values. The `apply-block-to-utxo-set` function returns spent UTXOs with their values - we capture this at block connection time:

```lisp
;; In connect-block, after apply-block-to-utxo-set:
(let ((spent-utxos (apply-block-to-utxo-set utxo-set block height)))
  ;; spent-utxos contains (txid index utxo-entry) with utxo-entry.value
  (record-block-fee-stats fee-estimator block spent-utxos height))
```

This approach works because we have full access to input values at block connection time.

## Estimation Algorithm

### Approach: Percentile-Based
Simple but effective algorithm used by many implementations:

1. Collect fee rates from recent blocks (up to conf_target blocks back)
2. Calculate the Nth percentile of those fee rates
3. Return as the estimate

For a conf_target of N blocks:
- Look at the last `min(N * 2, 1008)` blocks
- Apply percentile based on conf_target and estimate_mode (see table below)

### Confirmation Target Mapping

The table below shows percentiles for **conservative** mode (default). For **economical** mode, subtract 15 from each percentile (minimum 10th percentile).

| conf_target | Blocks Analyzed | Conservative | Economical |
|-------------|-----------------|--------------|------------|
| 1-2         | 12              | 90th         | 75th       |
| 3-6         | 36              | 85th         | 70th       |
| 7-12        | 72              | 75th         | 60th       |
| 13-25       | 144             | 65th         | 50th       |
| 26-144      | 288             | 50th         | 35th       |
| 145-1008    | 1008            | 25th         | 10th       |

Conservative mode prioritizes reliable confirmation over cost savings. Economical mode accepts longer potential wait times for lower fees.

### Fallback Behavior
- If insufficient history: return minimum relay fee (1 sat/vB) with warning
- If mempool is empty and recent blocks are empty: use minimum
- Never return 0 or negative values

## RPC Changes

### estimatesmartfee (Modified)
Current: Returns hardcoded 0.00001 BTC/kvB
New: Returns dynamic estimate based on historical data

```
estimatesmartfee <conf_target> [estimate_mode]

Arguments:
1. conf_target  (numeric) Confirmation target in blocks (1-1008)
2. estimate_mode (string, optional) "economical" or "conservative" (default)

Returns:
{
  "feerate": n.nnnnnnnn,  // BTC per kvB
  "blocks": n,            // conf_target (or adjusted if insufficient data)
  "errors": ["..."]       // Optional warnings
}
```

### getmempoolinfo (Enhanced)
Add fee statistics to existing response:

```
{
  ... existing fields ...
  "mempoolminfee": n.nnnnnnnn,  // Minimum fee rate for relay (BTC/kvB)
  "minrelaytxfee": n.nnnnnnnn   // Configured minimum relay fee (BTC/kvB)
}
```

## Storage Considerations

### Memory
- 1008 blocks × ~20 bytes/entry = ~20 KB
- Negligible impact

### Persistence
Fee history is persisted to disk to survive restarts. Without persistence, we cannot recalculate historical fees (input values are not available after block connection).

**File format**: `fee-stats.dat`
```
[4-byte magic "FEES"]
[4-byte version]
[4-byte entry count]
[entries...]
[4-byte CRC32]

Each entry (20 bytes):
[4-byte height]
[4-byte median-rate]  (sat/vB)
[4-byte low-rate]     (10th percentile)
[4-byte high-rate]    (90th percentile)
[4-byte tx-count]
```

Total file size: ~20 KB for 1008 blocks.

### Startup Behavior
On node start:
1. Load fee stats from `fee-stats.dat` if it exists
2. If file is missing/corrupt, start with empty history (cold start)
3. New blocks will populate history as they are connected
4. Mark estimator as ready when min_blocks (6) are available

### Write Strategy
- Append new entry when block is connected
- Truncate oldest entries when exceeding 1008 limit
- Flush to disk periodically (every 10 blocks) or on shutdown

## Error Handling

| Condition | Behavior |
|-----------|----------|
| Node syncing | Return error "Insufficient data (syncing)" |
| < min_blocks history | Return minimum fee with warning |
| No transactions in window | Return minimum fee with warning |
| Invalid conf_target | Return error -8 |

## Testing Strategy

1. **Unit tests**: Fee calculation, percentile computation
2. **Integration tests**:
   - Connect blocks and verify fee stats collected
   - Query estimatesmartfee and verify response format
3. **Edge cases**:
   - Empty blocks (no fee data)
   - Very high/low fee spikes
   - Fresh node startup
