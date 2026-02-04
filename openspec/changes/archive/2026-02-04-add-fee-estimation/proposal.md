# Add Fee Estimation

## Why
The current `estimatesmartfee` RPC returns a hardcoded value (1 sat/vB), providing no actual fee estimation. Users and wallet integrations need accurate fee estimates to:
- Set appropriate transaction fees for timely confirmation
- Avoid overpaying during low-congestion periods
- Avoid underpaying during high-congestion periods

## What Changes
1. Track historical fee data from confirmed blocks
2. Implement fee rate estimation based on confirmation target
3. Update `estimatesmartfee` RPC to return dynamic estimates
4. Add `getmempoolinfo` fee statistics

## Scope
- Fee rate tracking from confirmed blocks (last N blocks)
- Simple percentile-based estimation algorithm
- Mempool fee statistics for current state

## Out of Scope
- Complex fee prediction models (machine learning, etc.)
- Replace-by-fee (RBF) bump fee calculation
- Fee rate histogram in getmempoolinfo (future enhancement)
- Package relay fee considerations

## Dependencies
- Existing mempool with fee-rate tracking
- Block validation pipeline (provides spent UTXO values during block connection)
- Existing persistence patterns (CRC32, atomic writes)

## Risks
- **Accuracy**: Simple algorithm may be less accurate than Bitcoin Core's sophisticated estimator
- **Storage**: Fee history adds memory/disk usage
- **Cold start**: No estimates available until sufficient blocks are processed

Mitigations:
- Start with conservative estimates when data is insufficient
- Limit history to reasonable window (e.g., 1008 blocks = ~1 week)
- Document limitations clearly
