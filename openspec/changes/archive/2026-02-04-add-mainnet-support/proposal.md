# Change: Add Mainnet Support

## Why

The node currently operates on testnet only, as stated in project constraints. Mainnet support enables the node to validate the real Bitcoin network, which is the primary use case for a full node implementation. The codebase already has most mainnet parameters defined (magic bytes, ports, DNS seeds, address versions) but lacks mainnet-specific checkpoints, genesis hash, and proper network-aware validation logic.

## What Changes

- **ADDED**: Mainnet checkpoints for chain validation during IBD
- **ADDED**: Mainnet genesis block hash constant
- **MODIFIED**: Checkpoint accessor functions to select checkpoints based on active network
- **MODIFIED**: Chain state initialization to use correct genesis hash per network
- **MODIFIED**: BIP 34 validation to use network-appropriate activation height
- **MODIFIED**: RPC server to use network-appropriate default port
- **MODIFIED**: Data directory structure to include network subdirectory
- **ADDED**: Network selection validation at startup
- **ADDED**: Mainnet startup warning
- **DECISION**: Transaction relay disabled on mainnet initially (safety)

## Impact

- Affected specs: `networking`, `storage`, `validation`
- Affected code:
  - `src/node.lisp` - Network initialization, data paths
  - `src/networking/ibd.lisp` - Checkpoints
  - `src/storage/chain.lisp` - Genesis hash
  - `src/validation/block.lisp` - BIP 34 activation height
  - `src/rpc/server.lisp` - Default RPC port
- No breaking changes to existing testnet functionality
- Existing testnet data remains at `~/.bitcoin-lisp/` (backward compatible)
- Mainnet data stored at `~/.bitcoin-lisp/mainnet/`

## Risk Assessment

- **Consensus risk**: Mainnet validation errors could cause chain rejection. Mitigated by:
  - Using verified checkpoint hashes from Bitcoin Core source
  - Testing against known mainnet blocks before full IBD
  - Disabling transaction relay on mainnet initially
- **Data safety**: Mainnet operations involve real value. Mitigated by clear warnings and validation-only mode.
- **Resource usage**: Mainnet blockchain is ~600GB+. Documented in usage instructions.

## Verification

Checkpoint hashes verified against [Bitcoin Core chainparams.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp).
