# Change: Add Block Pruning

## Why
Mainnet requires 600GB+ of block storage, making it impractical for most users. Block pruning deletes old block data after validation while retaining the UTXO set, headers, and recent blocks -- reducing storage to a configurable target while maintaining full validation capability.

## What Changes
- Add optional, opt-in block pruning with a byte-based target (MiB), matching Bitcoin Core's `-prune=N` behavior
- Pruning is **off by default** -- user must explicitly set `*prune-target-mib*` to enable
- Two pruning modes: automatic (`*prune-target-mib*` >= 550) and manual-only (`*prune-target-mib*` = 1)
- Minimum retention of 288 blocks (`MIN_BLOCKS_TO_KEEP`) regardless of byte target, matching Bitcoin Core
- Pruning does not begin until chain reaches `*prune-after-height*` (100000 mainnet, 1000 testnet)
- Track pruning state in chain state (pruned height)
- Set `NODE_NETWORK_LIMITED` and unset `NODE_NETWORK` service bits per BIP 159
- Reject `getdata` requests for pruned blocks from peers
- Make txindex incompatible with pruning
- Add `pruneblockchain` RPC method for manual pruning (works in both automatic and manual-only modes)
- Report pruning status in `getblockchaininfo` RPC with `pruned`, `pruneheight`, `automatic_pruning`, and `prune_target_size` fields
- Node cannot reorg past pruned height -- must re-sync from scratch if needed (same as Bitcoin Core)

## Impact
- Affected specs: `storage`, `rpc`, `networking`
- Affected code: `src/storage/blocks.lisp`, `src/storage/chain.lisp`, `src/node.lisp`, `src/rpc/methods.lisp`, `src/networking/ibd.lisp`, `src/networking/peer.lisp`
- Storage reduction: from 600GB+ to user-configured target (minimum 550 MiB) for mainnet
- No consensus changes -- pruned nodes still fully validate all blocks during IBD
