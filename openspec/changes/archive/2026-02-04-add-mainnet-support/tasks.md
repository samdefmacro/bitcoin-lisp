# Tasks: Add Mainnet Support

## 1. Core Network Parameters

- [x] 1.1 Add `*mainnet-genesis-hash*` constant in `src/storage/chain.lisp`
- [x] 1.2 Add `network-genesis-hash` function that dispatches on `*network*`
- [x] 1.3 Update `make-chain-state` to use `network-genesis-hash`
- [x] 1.4 Add `*mainnet-checkpoints*` list in `src/networking/ibd.lisp`
- [x] 1.5 Update `get-checkpoint-hash` to dispatch on `*network*`
- [x] 1.6 Update `last-checkpoint-height` to dispatch on `*network*`

## 2. Validation Updates

- [x] 2.1 Create `get-bip34-activation-height` function in `src/validation/block.lisp`
- [x] 2.2 Update `validate-bip34-coinbase-height` to call `get-bip34-activation-height`
- [x] 2.3 Verify BIP 16 exception handling works for both networks (already has both hashes)

## 3. Data Directory Separation

- [x] 3.1 Update `init-node` to append network subdirectory for mainnet only
  - Testnet: `~/.bitcoin-lisp/` (backward compatible)
  - Mainnet: `~/.bitcoin-lisp/mainnet/`
- [x] 3.2 Verify all storage paths go through `node-data-directory`:
  - `utxo-set-file-path`
  - `init-block-store`
  - `init-chain-state`
  - `init-tx-index`
  - Fee estimator data path

## 4. RPC Configuration

- [x] 4.1 Add `network-rpc-port` function in `src/node.lisp` (testnet: 18332, mainnet: 8332)
- [x] 4.2 Update `start-rpc-server` default port to use `network-rpc-port`
- [x] 4.3 Update `start-node` docstring to reflect network-aware RPC port

## 5. Transaction Relay Control

- [x] 5.1 Add `*mainnet-relay-enabled*` flag (default: nil)
- [x] 5.2 Update transaction relay logic to check flag when on mainnet
- [x] 5.3 Add startup log message indicating relay status

## 6. Startup and Configuration

- [x] 6.1 Add network validation in `init-node` (reject invalid network values)
- [x] 6.2 Add startup warning when running on mainnet
- [x] 6.3 Update RPC `getblockchaininfo` to correctly report network name

## 7. Testing

- [x] 7.1 Add unit tests for `network-genesis-hash`
- [x] 7.2 Add unit tests for `get-checkpoint-hash` with both networks
- [x] 7.3 Add unit tests for `get-bip34-activation-height`
- [x] 7.4 Add unit tests for `network-rpc-port`
- [x] 7.5 Add test validating mainnet genesis block header

## 8. Documentation

- [x] 8.1 Update USAGE.md with mainnet operation instructions
- [x] 8.2 Document storage requirements (~600GB for mainnet)
- [x] 8.3 Document relay disabled status on mainnet
- [x] 8.4 Update project.md constraint to indicate mainnet is now supported
