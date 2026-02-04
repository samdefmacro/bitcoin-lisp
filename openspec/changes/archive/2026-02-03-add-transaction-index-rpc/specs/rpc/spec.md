# RPC Spec Delta: Transaction Index Methods

## MODIFIED Requirements

### Requirement: Raw Transaction Query Methods
The system SHALL provide methods to fetch and decode raw transactions.

Methods:
- `getrawtransaction <txid> [verbose] [blockhash]`: Returns raw transaction data
- `decoderawtransaction <hex>`: Decodes hex transaction to JSON

For `getrawtransaction`:
- If `verbose=false` (default), returns hex-encoded transaction
- If `verbose=true`, returns JSON with transaction details
- Searches mempool for unconfirmed transactions
- **ADDED**: When txindex is enabled, searches confirmed transactions by txid
- **ADDED**: Optional `blockhash` parameter provides direct block lookup hint
- **ADDED**: Returns `blockhash`, `confirmations`, `time`, `blocktime` for confirmed transactions

#### Scenario: getrawtransaction from mempool
- **GIVEN** transaction T is in the mempool
- **WHEN** getrawtransaction(T.txid, false) is called
- **THEN** response is hex-encoded transaction bytes

#### Scenario: getrawtransaction verbose from mempool
- **GIVEN** transaction T is in the mempool
- **WHEN** getrawtransaction(T.txid, true) is called
- **THEN** response is JSON with txid, version, vin, vout, locktime (no blockhash)

#### Scenario: getrawtransaction confirmed with txindex
- **GIVEN** txindex is enabled AND transaction T is confirmed in block B
- **WHEN** getrawtransaction(T.txid, true) is called
- **THEN** response includes txid, version, vin, vout, locktime, blockhash, confirmations, time, blocktime

#### Scenario: getrawtransaction with blockhash hint
- **GIVEN** transaction T is in block B
- **WHEN** getrawtransaction(T.txid, true, B.hash) is called
- **THEN** transaction is found directly in block B without txindex lookup

#### Scenario: getrawtransaction not found without txindex
- **GIVEN** txindex is disabled AND txid T is not in mempool
- **WHEN** getrawtransaction(T) is called
- **THEN** error code -5 with message indicating txindex needed

#### Scenario: getrawtransaction not found with txindex
- **GIVEN** txindex is enabled AND txid T does not exist
- **WHEN** getrawtransaction(T) is called
- **THEN** error code -5 "No such transaction"

## ADDED Requirements

### Requirement: UTXO Set Statistics
The system SHALL provide a method to query UTXO set statistics.

Method:
- `gettxoutsetinfo [hash_type]`

Parameters:
- `hash_type`: Optional, one of "hash_serialized_3" (default), "none"

Returns:
- `height`: Current block height
- `bestblock`: Hash of the current tip
- `transactions`: Number of transactions with unspent outputs
- `txouts`: Total number of unspent transaction outputs
- `total_amount`: Total BTC value in UTXO set
- `hash_serialized_3`: UTXO set hash (if hash_type != "none")

The UTXO set hash uses Bitcoin Core's `hash_serialized_3` format:
- UTXOs ordered by (txid, vout) ascending
- Each UTXO serialized as: txid || vout || height || coinbase || value || scriptPubKey
- Final hash is SHA256 of concatenated serializations

#### Scenario: gettxoutsetinfo basic
- **GIVEN** UTXO set has 1000 outputs from 500 transactions totaling 50000 BTC
- **WHEN** gettxoutsetinfo() is called
- **THEN** response has txouts=1000, transactions=500, total_amount=50000

#### Scenario: gettxoutsetinfo with hash
- **GIVEN** UTXO set state is deterministic
- **WHEN** gettxoutsetinfo("hash_serialized_3") is called
- **THEN** response includes hash_serialized_3 matching expected value

#### Scenario: gettxoutsetinfo without hash
- **GIVEN** node is running
- **WHEN** gettxoutsetinfo("none") is called
- **THEN** response omits hash_serialized_3 field (faster)

#### Scenario: gettxoutsetinfo during IBD
- **GIVEN** node is still performing initial block download
- **WHEN** gettxoutsetinfo() is called
- **THEN** response reflects current (incomplete) UTXO set state

### Requirement: Block Statistics
The system SHALL provide a method to query per-block statistics.

Method:
- `getblockstats <hash_or_height> [stats]`

Parameters:
- `hash_or_height`: Block hash (string) or height (integer)
- `stats`: Optional array of stat names to return (returns all if omitted)

Returns object with:
- `avgtxsize`: Average transaction size in bytes
- `blockhash`: Block hash
- `height`: Block height
- `ins`: Total inputs (excluding coinbase)
- `outs`: Total outputs
- `subsidy`: Block subsidy in satoshis
- `time`: Block timestamp
- `total_out`: Total output value in satoshis
- `total_size`: Total block size in bytes
- `txs`: Number of transactions

Note: Fee statistics (`avgfee`, `totalfee`, `avgfeerate`) require input values from historical UTXO state and are deferred to a future phase.

#### Scenario: getblockstats by height
- **GIVEN** block at height 100 exists
- **WHEN** getblockstats(100) is called
- **THEN** response contains statistics for block at height 100

#### Scenario: getblockstats by hash
- **GIVEN** block with hash H exists
- **WHEN** getblockstats(H) is called
- **THEN** response contains statistics for block H

#### Scenario: getblockstats filtered
- **GIVEN** block at height 100 exists
- **WHEN** getblockstats(100, ["txs", "total_size"]) is called
- **THEN** response contains only txs and total_size fields

#### Scenario: getblockstats invalid height
- **GIVEN** chain height is 100
- **WHEN** getblockstats(200) is called
- **THEN** error code -8 "Block not found"

#### Scenario: getblockstats invalid hash
- **GIVEN** hash H does not exist
- **WHEN** getblockstats(H) is called
- **THEN** error code -5 "Block not found"

#### Scenario: getblockstats genesis block
- **GIVEN** genesis block (height 0)
- **WHEN** getblockstats(0) is called
- **THEN** response shows txs=1, ins=0 (coinbase only)
