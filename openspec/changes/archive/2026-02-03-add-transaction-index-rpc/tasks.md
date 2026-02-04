# Tasks: Add Transaction Index RPC Methods

## Phase 1: Transaction Index Storage

### 1.1 Create txindex storage module
- [x] Create `src/storage/txindex.lisp`
- [x] Define `tx-location` struct (block-hash, tx-position)
- [x] Implement file-based storage with append-only writes
- [x] Implement in-memory hash table index (txid → file offset)
- [x] Add index rebuild from file on startup
- **Validation**: Unit tests for add/lookup/rebuild operations

### 1.2 Integrate txindex with block processing
- [x] Add `txindex-enabled` configuration option
- [x] Hook into block validation to index transactions
- [x] Handle chain reorganizations (remove orphaned block txs)
- **Validation**: Test indexing during simulated IBD

### 1.3 Add background reindex capability
- [x] Implement `build-tx-index` function to scan existing blocks
- [x] Add progress reporting for long reindex operations
- **Validation**: Reindex small testnet chain segment

## Phase 2: Extended getrawtransaction

### 2.1 Extend getrawtransaction for confirmed transactions
- [x] Modify `rpc-getrawtransaction` to check txindex first
- [x] Add `blockhash` parameter for direct block lookup
- [x] Return proper error when txindex disabled but needed
- **Validation**: Test retrieving confirmed transaction by txid

### 2.2 Add verbose response fields for confirmed transactions
- [x] Add `blockhash` to verbose response
- [x] Add `confirmations` (current_height - block_height + 1)
- [x] Add `time` and `blocktime` from block header
- **Validation**: Compare output format with Bitcoin Core

## Phase 3: UTXO Set Statistics

### 3.1 Implement gettxoutsetinfo
- [x] Add `rpc-gettxoutsetinfo` method
- [x] Calculate transaction count (distinct txids with UTXOs)
- [x] Calculate total amount from UTXO set
- [x] Implement `hash_serialized_3` UTXO set hash
- **Validation**: Test against known UTXO set state

### 3.2 Add UTXO iteration support to storage
- [x] Add `utxo-set-iterate` function for ordered traversal
- [x] Ensure consistent ordering (by txid, then vout)
- **Validation**: Unit test iteration order

## Phase 4: Block Statistics

### 4.1 Implement getblockstats
- [x] Add `rpc-getblockstats` method
- [x] Calculate size statistics (avg tx size, total block size)
- [x] Calculate input/output counts
- [x] Calculate subsidy based on height
- [x] Support stat filtering (only return requested stats)
- **Validation**: Compare output with Bitcoin Core for same block (excluding fee stats)

Note: Fee statistics (avgfee, totalfee, avgfeerate) deferred - requires historical UTXO state.

## Phase 5: Testing & Documentation

### 5.1 Integration tests
- [x] Test getrawtransaction across mempool and confirmed
- [x] Test gettxoutsetinfo accuracy
- [x] Test getblockstats calculations
- **Validation**: All RPC tests pass

### 5.2 Update RPC spec
- [x] Add new requirements to `openspec/specs/rpc/spec.md`
- [x] Document new configuration options
- **Validation**: `openspec validate` passes

## Dependencies
- Phase 2 depends on Phase 1 (txindex storage)
- Phases 3 and 4 can run in parallel
- Phase 5 depends on all prior phases

## Parallelization
- 1.1 and 3.2 can be developed in parallel (no overlap)
- 4.1 has no dependencies on txindex, can start early
