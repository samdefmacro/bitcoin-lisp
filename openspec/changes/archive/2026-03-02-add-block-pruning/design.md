## Context
The node currently stores every block as an individual `.blk` file under `blocks/`. On mainnet this grows to 600GB+. Bitcoin Core solves this with `-prune=N` which keeps only the most recent N MiB of block data. We follow the same approach to maintain compatibility and user expectations.

## Goals / Non-Goals
- Goals:
  - Reduce mainnet disk usage from 600GB+ to a user-configured byte target (minimum 550 MiB)
  - Match Bitcoin Core's pruning semantics: byte-based target, minimum 288-block retention, manual-only mode, prune-after-height guard
  - Pruning is optional and off by default -- user must explicitly opt in
  - Two modes: automatic (>= 550 MiB target) and manual-only (RPC-only pruning)
  - Prune automatically after block validation during IBD and steady-state (automatic mode only)
  - Allow manual pruning via `pruneblockchain` RPC (both modes)
  - Maintain full validation (all blocks are validated before pruning)
  - Advertise pruned status to peers per BIP 159

- Non-Goals:
  - Wallet rescanning support (no wallet in scope)
  - Partial block storage (we either have the full block or not)
  - UNIX timestamp argument for `pruneblockchain` RPC (defer)
  - Anti-fingerprinting block serving cap (BIP 159 SHOULD, defer)

## Decisions
- **Byte-based target**: `*prune-target-mib*` sets the target in MiB. nil = pruning disabled (default). 1 = manual-only mode. >= 550 = automatic pruning. Matches Bitcoin Core's `-prune=0/1/N`.
- **Minimum block retention**: Always keep at least 288 blocks (`MIN_BLOCKS_TO_KEEP`, ~2 days), regardless of byte target. This provides reorg safety -- reorgs deeper than 288 blocks are essentially impossible on mainnet.
- **Prune-after-height guard**: `*prune-after-height*` prevents pruning until the chain reaches a minimum height. Defaults to 100000 on mainnet, 1000 on testnet. Ensures early chain history is fully processed during IBD before any deletion begins.
- **Pruning trigger**: After each block is fully validated and connected to the chain, check total block storage size (automatic mode only). If it exceeds `*prune-target-mib*`, delete the oldest block files until under target, but never delete blocks within the 288-block retention window or below `*prune-after-height*`.
- **Size tracking**: Sum file sizes of `.blk` files in the blocks directory. Our one-file-per-block model makes this straightforward.
- **Pruning granularity**: Delete individual `.blk` files, oldest first by height.
- **State tracking**: Add `pruned-height` to chain-state persistence. This is the height of the last pruned block. `pruneheight` in RPC returns `pruned-height + 1` (first unpruned block), matching Bitcoin Core semantics.
- **txindex incompatibility**: Refuse to enable both `txindex` and `prune` simultaneously. Check at startup.
- **Service bits (BIP 159)**: Pruned nodes set `NODE_NETWORK_LIMITED` (bit 10) and MUST NOT set `NODE_NETWORK` (bit 0). This tells peers not to request historical blocks.
- **Reorg past pruned height**: If a reorg would require blocks that have been pruned, the node cannot disconnect those blocks. The node must re-sync from scratch. This matches Bitcoin Core behavior. The 288-block retention window makes this scenario essentially impossible in practice.
- Alternatives considered:
  - Block-count-only pruning: Simpler but doesn't match Bitcoin Core behavior. Byte-based is more predictable for users managing disk space.
  - Batch pruning (every N blocks): Simpler but creates bursty I/O. Per-block pruning is smoother.

## Risks / Trade-offs
- Pruned nodes cannot serve historical blocks to peers -> Mitigated by `NODE_NETWORK_LIMITED` flag and unsetting `NODE_NETWORK`
- Cannot enable txindex after pruning (data is gone) -> Warn clearly at startup
- Re-syncing from scratch required if reorg exceeds 288 blocks or UTXO set is corrupted -> Same as Bitcoin Core; 288-block reorgs are essentially impossible on mainnet
- Byte-based requires scanning block file sizes -> Acceptable overhead given one-file-per-block model

## Open Questions
- None
