## 1. Core Pruning Logic
- [ ] 1.1 Add `*prune-target-mib*` configuration variable to node.lisp (nil = disabled, 1 = manual-only, >= 550 = automatic)
- [ ] 1.2 Add `*prune-after-height*` per-network constant (100000 mainnet, 1000 testnet)
- [ ] 1.3 Add `pruned-height` field to `chain-state` struct and persistence (save/load)
- [ ] 1.4 Implement `block-storage-size-mib` to calculate total size of block files on disk
- [ ] 1.5 Implement `prune-block` function in blocks.lisp to delete a block file by hash
- [ ] 1.6 Implement `prune-old-blocks` that deletes oldest blocks until storage is under target, respecting 288-block minimum retention and prune-after-height
- [ ] 1.7 Implement `prune-blocks-to-height` for manual pruning to a specific height (respecting 288-block retention)
- [ ] 1.8 Validate txindex/prune incompatibility at startup (error if both enabled)
- [ ] 1.9 Validate `*prune-target-mib*` is 1 or >= 550 at startup (error if invalid)
- [ ] 1.10 Handle reorg-past-pruned-height: signal error if disconnect requires pruned blocks

## 2. Automatic Pruning Integration
- [ ] 2.1 Call `prune-old-blocks` after each block is connected to the chain during IBD (automatic mode only)
- [ ] 2.2 Call `prune-old-blocks` after each block is connected during steady-state operation (automatic mode only)
- [ ] 2.3 Skip pruning if chain height is below `*prune-after-height*`
- [ ] 2.4 Update `pruned-height` in chain state after pruning
- [ ] 2.5 Persist pruned-height across restarts

## 3. Peer Interaction (BIP 159)
- [ ] 3.1 Add `NODE_NETWORK_LIMITED` service bit (bit 10, value 1024) to version message when pruning is enabled
- [ ] 3.2 Remove `NODE_NETWORK` service bit (bit 0) from version message when pruning is enabled
- [ ] 3.3 Reject `getdata` block requests for heights below pruned-height
- [ ] 3.4 Log when rejecting pruned block requests

## 4. RPC Integration
- [ ] 4.1 Add `pruneblockchain` RPC method (accepts target height, prunes up to that height respecting 288-block retention; works in both automatic and manual-only modes)
- [ ] 4.2 Add pruning fields to `getblockchaininfo` response: `pruned`, `pruneheight` (first unpruned block = pruned-height + 1), `automatic_pruning`, `prune_target_size` (in bytes)

## 5. Tests
- [ ] 5.1 Test pruning deletes block files correctly and respects 288-block minimum retention
- [ ] 5.2 Test pruning triggers when storage exceeds byte target (automatic mode)
- [ ] 5.3 Test manual-only mode: no automatic pruning, but `pruneblockchain` RPC works
- [ ] 5.4 Test pruning does not begin before prune-after-height
- [ ] 5.5 Test pruned-height persists across save/load
- [ ] 5.6 Test txindex/prune incompatibility check
- [ ] 5.7 Test prune-target-mib validation (reject values other than nil, 1, or >= 550)
- [ ] 5.8 Test `pruneblockchain` RPC method returns first unpruned block height
- [ ] 5.9 Test `getblockchaininfo` reports pruning status with correct fields and units
- [ ] 5.10 Test pruned node sets NODE_NETWORK_LIMITED and unsets NODE_NETWORK
- [ ] 5.11 Test pruned node rejects getdata for pruned blocks
- [ ] 5.12 Test reorg past pruned height signals error
