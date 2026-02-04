# Add Transaction Index RPC Methods

## Summary
Extend the RPC interface with transaction index support, enabling lookup of confirmed transactions by txid and UTXO set statistics.

## Motivation
Currently `getrawtransaction` only works for mempool transactions. Users need to query confirmed transactions for:
- Block explorers and analytics
- Transaction verification and auditing
- Wallet integration (checking payment confirmations)

The UTXO set statistics (`gettxoutsetinfo`) provide chain verification data.

## Scope
- Build a transaction index mapping txid → (block_hash, tx_position)
- Enable `getrawtransaction` for confirmed transactions
- Add `gettxoutsetinfo` for UTXO set statistics
- Add `getblockstats` for per-block statistics

## Out of Scope
- Address index (listunspent by address)
- Full wallet functionality
- Coinstats index (separate optimization)

## Dependencies
- Existing storage layer (`src/storage/`)
- Existing RPC infrastructure (`src/rpc/`)
- Block storage with transaction data

## Risks
- **Storage growth**: Transaction index adds ~50 bytes per transaction
- **IBD slowdown**: Index building during sync adds overhead
- **Migration**: Existing nodes need reindex or background index build

Mitigations:
- Make txindex optional (default off for low-resource nodes)
- Support background index building without restarting
