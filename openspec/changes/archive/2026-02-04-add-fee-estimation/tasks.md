# Tasks: Add Fee Estimation

## Phase 1: Fee Data Collection

### 1.1 Create fee estimator module
- [x] Create `src/mempool/fee-estimator.lisp`
- [x] Define `block-fee-stats` struct (height, median-rate, low-rate, high-rate, tx-count)
- [x] Define `fee-estimator` struct (history buffer, min-blocks threshold)
- [x] Implement `make-fee-estimator` with configurable history size
- **Validation**: Unit tests for struct creation

### 1.2 Implement fee rate calculation
- [x] Add `calculate-tx-fee-rate` function (uses spent UTXO values from block connection)
- [x] Add `compute-block-fee-stats` function (analyzes block transactions and spent UTXOs)
- [x] Handle edge cases: empty blocks, coinbase-only blocks
- **Validation**: Test with known block data, verify fee calculations

### 1.3 Integrate with block validation
- [x] Hook into `connect-block` to record fee stats after successful connection
- [x] Add `fee-estimator` slot to node struct
- [x] Initialize fee estimator in `start-node`
- **Validation**: Test that fee stats are recorded when blocks connect

### 1.4 Add fee stats persistence
- [x] Define file format (magic, version, entries, CRC32)
- [x] Implement `save-fee-stats` to write history to disk
- [x] Implement `load-fee-stats` to restore history on startup
- [x] Add periodic flush (every 10 blocks) and flush on shutdown
- **Validation**: Restart node and verify history is preserved

### 1.5 Integrate persistence with node lifecycle
- [x] Load fee stats in `start-node` after chain state is loaded
- [x] Save fee stats in `stop-node` before shutdown
- [x] Handle missing/corrupt file gracefully (start with empty history)
- **Validation**: Test restart scenarios, corrupt file handling

## Phase 2: Estimation Algorithm

### 2.1 Implement percentile calculation
- [x] Add `fee-rate-percentile` function
- [x] Implement efficient percentile over circular buffer
- **Validation**: Unit tests with known data sets

### 2.2 Implement estimation logic
- [x] Add `estimate-fee-rate` function with conf_target and mode parameters
- [x] Implement confirmation target to percentile mapping
- [x] Handle insufficient data case (return minimum with warning)
- **Validation**: Test various conf_target values

## Phase 3: RPC Integration

### 3.1 Update estimatesmartfee RPC
- [x] Modify `rpc-estimatesmartfee` to use fee estimator
- [x] Add `estimate_mode` parameter support ("economical" vs "conservative")
- [x] Return errors array when data is insufficient
- **Validation**: Compare output format with Bitcoin Core

### 3.2 Enhance getmempoolinfo RPC
- [x] Add `mempoolminfee` field (current minimum fee to enter mempool)
- [x] Add `minrelaytxfee` field (configured relay fee threshold)
- **Validation**: Verify new fields appear in response

## Phase 4: Testing & Documentation

### 4.1 Integration tests
- [x] Test fee estimation across different confirmation targets
- [x] Test behavior during node sync
- [x] Test with empty/sparse blocks
- **Validation**: All fee estimation tests pass

### 4.2 Update specs
- [x] Modify `estimatesmartfee` requirement in rpc/spec.md
- [x] Add fee estimator requirements to mempool/spec.md
- **Validation**: `openspec validate` passes

## Dependencies
- Phase 2 depends on Phase 1 (need data before estimation)
- Phase 3 depends on Phase 2 (need algorithm before RPC)
- Phase 4 depends on all prior phases
- Task 1.4 depends on 1.1 (need struct definitions for persistence)
- Task 1.5 depends on 1.4 (need persistence functions before integration)

## Parallelization
- 1.1 and 1.2 can run in parallel (no overlap)
- 1.3 and 1.4 can run in parallel (block integration vs persistence)
- 3.1 and 3.2 can run in parallel (independent RPC changes)
