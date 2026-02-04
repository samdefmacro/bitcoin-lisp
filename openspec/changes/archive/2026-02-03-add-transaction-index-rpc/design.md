# Design: Transaction Index RPC Methods

## Architecture Overview

```
┌──────────────────────────────────────────────────────────┐
│                      RPC Layer                            │
│  getrawtransaction  gettxoutsetinfo  getblockstats       │
└────────────────────────┬─────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────┐
│                   Storage Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐  │
│  │  TX Index   │  │  UTXO Set   │  │  Block Storage   │  │
│  │ txid→block  │  │  (existing) │  │    (existing)    │  │
│  └─────────────┘  └─────────────┘  └──────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

## Transaction Index Design

### Data Structure
The txindex maps transaction IDs to their location in the blockchain:

```lisp
(defstruct tx-location
  block-hash    ; 32-byte block hash
  tx-position)  ; integer position in block (0 = coinbase)
```

### Storage Strategy
Options considered:

1. **Hash table in memory** - Fast, but O(n) memory with chain size
2. **Append-only file with hash index** - Moderate speed, persistent
3. **LMDB/SQLite** - Standard approach, adds dependency

**Decision**: Use append-only file with in-memory hash table index.
- File format: `[32-byte txid][32-byte block-hash][4-byte position]` = 68 bytes/tx
- Memory index: hash table mapping txid → file offset
- Rebuild index on startup by scanning file

Rationale: Simple, no new dependencies, adequate performance for testnet/small mainnet usage.

### Index Building
Two modes:
1. **During IBD**: Index transactions as blocks are validated (if enabled)
2. **Background reindex**: Scan existing blocks to build index without restart

## RPC Method Specifications

### getrawtransaction (extended)
Current: mempool-only
Extended: check txindex first, then mempool

```
getrawtransaction "txid" ( verbose "blockhash" )

Arguments:
1. txid        (string, required) Transaction ID
2. verbose     (boolean, optional, default=false) Return JSON vs hex
3. blockhash   (string, optional) Block hash hint for faster lookup

Returns:
- If verbose=false: hex-encoded transaction
- If verbose=true: JSON with txid, version, vin, vout, blockhash, confirmations, time, blocktime
```

### gettxoutsetinfo
Returns statistics about the UTXO set.

```
gettxoutsetinfo ( "hash_type" )

Arguments:
1. hash_type   (string, optional) "hash_serialized_3" (default) or "none"

Returns:
{
  "height": n,           Block height
  "bestblock": "hex",    Block hash
  "transactions": n,     Number of transactions with unspent outputs
  "txouts": n,           Number of unspent outputs
  "total_amount": n.nnn, Total amount in BTC
  "hash_serialized_3": "hex"  (if hash_type != "none")
}
```

Note: `hash_serialized_3` matches Bitcoin Core's UTXO set hash format for verification.

### getblockstats
Returns per-block statistics.

```
getblockstats hash_or_height ( stats )

Arguments:
1. hash_or_height  (string/numeric) Block hash or height
2. stats           (array, optional) Subset of stats to return

Returns:
{
  "avgtxsize": n,     Average transaction size
  "blockhash": "hex",
  "height": n,
  "ins": n,           Number of inputs (excluding coinbase)
  "outs": n,          Number of outputs
  "subsidy": n,       Block subsidy in satoshis
  "time": n,          Block timestamp
  "total_out": n,     Total output value
  "total_size": n,    Total block size
  "txs": n,           Number of transactions
}
```

**Note**: Fee statistics (`avgfee`, `totalfee`, `avgfeerate`) are omitted in Phase 1.
Computing fees requires input values, which requires UTXO state at block height.
This can be added in a future phase with undo data or input value caching.

## UTXO Set Hash Calculation

Bitcoin Core's `hash_serialized_3` is computed as:
1. For each UTXO ordered by (txid, vout):
   - Serialize: txid || vout || height || coinbase_flag || value || scriptPubKey
2. SHA256 of concatenated serializations

This enables cross-node UTXO set verification.

## Configuration

New node configuration options:
- `txindex` (boolean, default: false) - Enable transaction index
- `txindex-path` (string) - Custom path for txindex file

## Error Handling

| Condition | Error Code | Message |
|-----------|------------|---------|
| TX not found (no index) | -5 | "No such mempool transaction. Use -txindex..." |
| TX not found (with index) | -5 | "No such transaction" |
| Invalid txid format | -8 | "Invalid txid" |
| Index not enabled | -1 | "Transaction index not enabled" |

## Performance Considerations

- Index lookup: O(1) hash table lookup + 1 disk read
- Index building: ~68 bytes written per transaction
- Memory usage: ~40 bytes per transaction for index (txid hash → offset)
- Testnet (3M+ txs): ~120MB memory, ~200MB disk for index
- Mainnet (~1B txs): Would need different strategy (not in scope)
