# rpc Specification

## Purpose
TBD - created by archiving change add-rpc-interface. Update Purpose after archive.
## Requirements
### Requirement: JSON-RPC Server
The system SHALL provide a JSON-RPC 2.0 server over HTTP.

The server:
- Listens on a configurable port (default 18332 for testnet, 8332 for mainnet)
- Binds to localhost (127.0.0.1) by default
- Accepts POST requests to the root path (/)
- Parses JSON-RPC 2.0 request format
- Returns JSON-RPC 2.0 response format

#### Scenario: Valid RPC request
- **GIVEN** the RPC server is running
- **WHEN** a POST request with valid JSON-RPC body is received
- **THEN** the corresponding method is invoked and result returned

#### Scenario: Invalid JSON
- **GIVEN** the RPC server is running
- **WHEN** a POST request with malformed JSON is received
- **THEN** error code -32700 (Parse error) is returned

#### Scenario: Unknown method
- **GIVEN** the RPC server is running
- **WHEN** a request for unknown method is received
- **THEN** error code -32601 (Method not found) is returned

#### Scenario: Batch request
- **GIVEN** the RPC server is running
- **WHEN** a JSON array of requests is received
- **THEN** a JSON array of responses is returned in corresponding order

#### Scenario: Request id preserved
- **GIVEN** the RPC server is running
- **WHEN** a request with id "test-123" is received
- **THEN** the response includes id "test-123"

#### Scenario: Invalid Content-Type
- **GIVEN** the RPC server is running
- **WHEN** a POST request with Content-Type text/plain is received
- **THEN** HTTP 415 Unsupported Media Type is returned

### Requirement: Blockchain Query Methods
The system SHALL provide methods to query blockchain state.

Methods:
- `getblockchaininfo`: Returns network, chain, height, sync progress, and pruning status
- `getbestblockhash`: Returns the hash of the current tip
- `getblockcount`: Returns the current block height
- `getblockhash <height>`: Returns block hash at given height
- `getblock <hash> [verbosity]`: Returns block data (0=hex, 1=json, 2=json+tx)
- `getblockheader <hash> [verbose]`: Returns header data

The `getblockchaininfo` response SHALL include pruning fields when pruning is enabled:
- `pruned`: Boolean indicating if pruning is enabled (always present)
- `pruneheight`: Height of the first unpruned block (pruned-height + 1), or 0 if nothing pruned yet (only present when pruned is true)
- `automatic_pruning`: Boolean indicating whether automatic pruning is active vs manual-only (only present when pruned is true)
- `prune_target_size`: Configured prune target in **bytes** (i.e., `*prune-target-mib*` * 1024 * 1024), only present when automatic_pruning is true

#### Scenario: getblockchaininfo
- **GIVEN** the node is synced to height 1000
- **WHEN** getblockchaininfo is called
- **THEN** response includes chain "test", blocks 1000, and headers count

#### Scenario: getblockchaininfo on auto-pruned node
- **GIVEN** automatic pruning is enabled with prune-target-mib=550 and pruned-height=5000
- **WHEN** getblockchaininfo is called
- **THEN** response includes `"pruned": true`, `"pruneheight": 5001`, `"automatic_pruning": true`, and `"prune_target_size": 576716800`

#### Scenario: getblockchaininfo on manual-only pruned node
- **GIVEN** manual-only pruning is enabled (prune-target-mib=1) and pruned-height=3000
- **WHEN** getblockchaininfo is called
- **THEN** response includes `"pruned": true`, `"pruneheight": 3001`, `"automatic_pruning": false`
- **AND** `prune_target_size` is NOT present

#### Scenario: getblockchaininfo on non-pruned node
- **GIVEN** pruning is disabled
- **WHEN** getblockchaininfo is called
- **THEN** response includes `"pruned": false`
- **AND** `pruneheight`, `automatic_pruning`, and `prune_target_size` are not present

#### Scenario: getblock with verbosity 0
- **GIVEN** block exists at hash H
- **WHEN** getblock(H, 0) is called
- **THEN** response is hex-encoded raw block

#### Scenario: getblock with verbosity 1
- **GIVEN** block exists at hash H
- **WHEN** getblock(H, 1) is called
- **THEN** response is JSON with block fields and txid list

#### Scenario: getblock with verbosity 2
- **GIVEN** block exists at hash H
- **WHEN** getblock(H, 2) is called
- **THEN** response is JSON with block fields and full transaction details

#### Scenario: getblock with invalid hash format
- **GIVEN** the RPC server is running
- **WHEN** getblock("not-a-hash", 1) is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: getblock for unknown hash
- **GIVEN** hash H does not exist in chain
- **WHEN** getblock(H, 1) is called
- **THEN** error is returned indicating block not found

#### Scenario: getblockhash for invalid height
- **GIVEN** chain height is 100
- **WHEN** getblockhash(200) is called
- **THEN** error is returned indicating block not found

### Requirement: UTXO Query Methods
The system SHALL provide methods to query the UTXO set.

Methods:
- `gettxout <txid> <vout> [include_mempool]`: Returns UTXO if unspent

#### Scenario: gettxout for existing UTXO
- **GIVEN** UTXO exists for txid T, vout 0
- **WHEN** gettxout(T, 0) is called
- **THEN** response includes value, scriptPubKey, confirmations

#### Scenario: gettxout for spent output
- **GIVEN** output at txid T, vout 0 has been spent
- **WHEN** gettxout(T, 0) is called
- **THEN** null is returned

#### Scenario: gettxout with invalid txid format
- **GIVEN** the RPC server is running
- **WHEN** gettxout("invalid", 0) is called
- **THEN** error code -8 (Invalid parameter) is returned

### Requirement: Network Query Methods
The system SHALL provide methods to query network state.

Methods:
- `getpeerinfo`: Returns array of connected peer details
- `getnetworkinfo`: Returns network status and version info
- `getconnectioncount`: Returns number of connected peers

#### Scenario: getpeerinfo
- **GIVEN** connected to 3 peers
- **WHEN** getpeerinfo is called
- **THEN** response is array of 3 peer objects with addr, version, subver

#### Scenario: getconnectioncount
- **GIVEN** connected to 3 peers
- **WHEN** getconnectioncount is called
- **THEN** response is 3

#### Scenario: getnetworkinfo
- **GIVEN** the node is running on testnet
- **WHEN** getnetworkinfo is called
- **THEN** response includes version, subversion, protocolversion, and networkactive

### Requirement: Mempool Methods
The system SHALL provide methods to query and interact with the mempool.

Methods:
- `getmempoolinfo`: Returns mempool statistics (size, bytes, usage, fee thresholds)
- `getrawmempool [verbose]`: Returns txids or detailed tx info
- `sendrawtransaction <hex>`: Submits raw transaction to mempool

For `getmempoolinfo`, returns:
- `loaded`: Boolean indicating mempool is fully loaded
- `size`: Number of transactions in mempool
- `bytes`: Total size of mempool in bytes
- `mempoolminfee`: Minimum fee rate (BTC/kvB) to enter mempool
- `minrelaytxfee`: Configured minimum relay fee rate (BTC/kvB)

#### Scenario: getmempoolinfo
- **GIVEN** mempool has 5 transactions totaling 2000 bytes
- **WHEN** getmempoolinfo is called
- **THEN** response includes size 5 and bytes 2000

#### Scenario: getmempoolinfo returns fee fields
- **GIVEN** a running node with mempool
- **WHEN** getmempoolinfo is called
- **THEN** response includes mempoolminfee and minrelaytxfee fields

#### Scenario: mempoolminfee reflects eviction threshold
- **GIVEN** mempool is at capacity with transactions
- **WHEN** getmempoolinfo is called
- **THEN** mempoolminfee reflects the minimum fee rate that would be accepted

#### Scenario: getrawmempool non-verbose
- **GIVEN** mempool has transactions with txids T1, T2, T3
- **WHEN** getrawmempool(false) is called
- **THEN** response is array of txid strings

#### Scenario: getrawmempool verbose
- **GIVEN** mempool has transactions with txids T1, T2, T3
- **WHEN** getrawmempool(true) is called
- **THEN** response is object mapping txids to fee, size, time details

#### Scenario: sendrawtransaction success
- **GIVEN** a valid transaction hex
- **WHEN** sendrawtransaction is called
- **THEN** response is the transaction hash

#### Scenario: sendrawtransaction invalid
- **GIVEN** an invalid transaction hex
- **WHEN** sendrawtransaction is called
- **THEN** error is returned with rejection reason

### Requirement: RPC Authentication
The system SHALL optionally require HTTP Basic authentication.

When authentication is enabled:
- Requests without credentials return HTTP 401
- Requests with invalid credentials return HTTP 401
- Requests with valid credentials are processed normally

#### Scenario: Authentication disabled
- **GIVEN** RPC auth is disabled
- **WHEN** request without credentials is received
- **THEN** request is processed normally

#### Scenario: Authentication required
- **GIVEN** RPC auth is enabled with user "test", password "pass"
- **WHEN** request with matching Basic auth is received
- **THEN** request is processed normally

#### Scenario: Invalid credentials
- **GIVEN** RPC auth is enabled
- **WHEN** request with wrong credentials is received
- **THEN** HTTP 401 Unauthorized is returned

### Requirement: RPC Server Lifecycle
The system SHALL integrate RPC server with node lifecycle.

#### Scenario: Start RPC with node
- **GIVEN** node is configured with RPC enabled
- **WHEN** node starts
- **THEN** RPC server starts listening on configured port

#### Scenario: Stop RPC with node
- **GIVEN** RPC server is running
- **WHEN** node stops
- **THEN** RPC server stops accepting connections gracefully

#### Scenario: Port already in use
- **GIVEN** port 18332 is already bound by another process
- **WHEN** node starts with RPC enabled
- **THEN** node logs error and continues without RPC (does not crash)

### Requirement: Raw Transaction Query Methods
The system SHALL provide methods to fetch and decode raw transactions.

Methods:
- `getrawtransaction <txid> [verbose] [blockhash]`: Returns raw transaction data
- `decoderawtransaction <hex>`: Decodes hex transaction to JSON

For `getrawtransaction`:
- If `verbose=false` (default), returns hex-encoded transaction
- If `verbose=true`, returns JSON with transaction details
- Searches mempool for unconfirmed transactions
- When txindex is enabled, searches confirmed transactions by txid
- Optional `blockhash` parameter provides direct block lookup hint
- Returns `blockhash`, `confirmations`, `time`, `blocktime` for confirmed transactions

For `decoderawtransaction`:
- Parses hex string as serialized transaction
- Returns JSON with version, inputs, outputs, locktime
- Does not require transaction to exist in chain

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

#### Scenario: decoderawtransaction valid
- **GIVEN** valid hex-encoded transaction H
- **WHEN** decoderawtransaction(H) is called
- **THEN** response is JSON with parsed transaction fields

#### Scenario: decoderawtransaction invalid hex
- **GIVEN** invalid hex string H (odd length or non-hex chars)
- **WHEN** decoderawtransaction(H) is called
- **THEN** error code -22 (Invalid hex) is returned

#### Scenario: decoderawtransaction malformed tx
- **GIVEN** valid hex that doesn't parse as transaction
- **WHEN** decoderawtransaction(H) is called
- **THEN** error code -22 is returned indicating decode failure

### Requirement: Raw Transaction Construction
The system SHALL provide a method to construct unsigned transactions.

Method:
- `createrawtransaction <inputs> <outputs> [locktime]`

Parameters:
- `inputs`: Array of `{"txid": "hex", "vout": n, "sequence": n}` (sequence optional, defaults to 0xffffffff)
- `outputs`: Object `{"address": amount, ...}` where amount is in BTC
- `locktime`: Optional transaction locktime (default 0)

Returns hex-encoded unsigned transaction with empty scriptSigs.

Supported address formats for outputs:
- Base58Check: P2PKH (m.../n... testnet), P2SH (2... testnet)
- Bech32: P2WPKH, P2WSH (tb1q... testnet)
- Bech32m: P2TR (tb1p... testnet)

#### Scenario: createrawtransaction basic
- **GIVEN** valid input references and output addresses
- **WHEN** createrawtransaction is called
- **THEN** response is hex transaction with specified inputs/outputs

#### Scenario: createrawtransaction with locktime
- **GIVEN** inputs, outputs, and locktime 500000
- **WHEN** createrawtransaction is called with locktime
- **THEN** response transaction has locktime 500000

#### Scenario: createrawtransaction invalid input txid
- **GIVEN** input with invalid txid format
- **WHEN** createrawtransaction is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: createrawtransaction invalid address
- **GIVEN** output with invalid or unrecognized address
- **WHEN** createrawtransaction is called
- **THEN** error code -5 (Invalid address) is returned

#### Scenario: createrawtransaction wrong network address
- **GIVEN** output with mainnet address on testnet node
- **WHEN** createrawtransaction is called
- **THEN** error code -5 (Invalid address) is returned

#### Scenario: createrawtransaction negative amount
- **GIVEN** output with negative amount
- **WHEN** createrawtransaction is called
- **THEN** error code -3 (Invalid amount) is returned

#### Scenario: createrawtransaction amount too large
- **GIVEN** output with amount > 21 million BTC
- **WHEN** createrawtransaction is called
- **THEN** error code -3 (Invalid amount) is returned

### Requirement: Fee Estimation
The system SHALL provide a method to estimate transaction fees based on historical block data.

Method:
- `estimatesmartfee <conf_target> [estimate_mode]`

Parameters:
- `conf_target`: Number of blocks for confirmation target (1-1008)
- `estimate_mode`: "conservative" (default) or "economical"

Returns:
- `feerate`: Estimated fee rate in BTC/kvB (1000 virtual bytes)
- `blocks`: The conf_target value (may be adjusted if insufficient data)
- `errors`: Array of warning messages (optional, present when data is limited)

The estimate is computed from historical fee rates in confirmed blocks:
- Conservative mode uses higher percentiles for more reliable confirmation
- Economical mode uses lower percentiles for cost savings with longer wait

When insufficient historical data exists (fewer than 6 blocks), returns the minimum relay fee with a warning.

#### Scenario: estimatesmartfee with sufficient data
- **GIVEN** node has processed at least 6 blocks with fee data
- **WHEN** estimatesmartfee(6) is called
- **THEN** response includes computed feerate based on historical data

#### Scenario: estimatesmartfee conservative mode
- **GIVEN** node has sufficient fee history
- **WHEN** estimatesmartfee(6, "conservative") is called
- **THEN** response feerate uses higher percentile for reliable confirmation

#### Scenario: estimatesmartfee economical mode
- **GIVEN** node has sufficient fee history
- **WHEN** estimatesmartfee(6, "economical") is called
- **THEN** response feerate is lower than conservative mode for same target

#### Scenario: estimatesmartfee insufficient data
- **GIVEN** node has fewer than 6 blocks of fee history
- **WHEN** estimatesmartfee is called
- **THEN** response includes minimum fee with errors array containing warning

#### Scenario: estimatesmartfee during IBD
- **GIVEN** node is still performing initial block download
- **WHEN** estimatesmartfee is called
- **THEN** error is returned indicating insufficient data

#### Scenario: estimatesmartfee invalid target zero
- **GIVEN** conf_target is 0
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: estimatesmartfee invalid target negative
- **GIVEN** conf_target is negative
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

#### Scenario: estimatesmartfee invalid target too high
- **GIVEN** conf_target is greater than 1008
- **WHEN** estimatesmartfee is called
- **THEN** error code -8 (Invalid parameter) is returned

### Requirement: Address Validation
The system SHALL provide a method to validate Bitcoin addresses.

Method:
- `validateaddress <address>`

Returns object with:
- `isvalid`: Boolean indicating validity
- `address`: The address (if valid)
- `scriptPubKey`: Hex scriptPubKey (if valid)
- `isscript`: True for P2SH/P2WSH
- `iswitness`: True for SegWit addresses
- `witness_version`: 0 or 1 for SegWit (if applicable)
- `witness_program`: Hex witness program (if applicable)

Supported formats:
- Base58Check: P2PKH (testnet prefix 0x6f → m.../n...), P2SH (testnet prefix 0xc4 → 2...)
- Bech32: P2WPKH (20-byte program), P2WSH (32-byte program) - tb1q...
- Bech32m: P2TR (32-byte program) - tb1p...

#### Scenario: validateaddress P2PKH
- **GIVEN** valid testnet P2PKH address (m... or n...)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=false, isscript=false, scriptPubKey is OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG

#### Scenario: validateaddress P2SH
- **GIVEN** valid testnet P2SH address (2...)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=false, isscript=true, scriptPubKey is OP_HASH160 <hash> OP_EQUAL

#### Scenario: validateaddress P2WPKH
- **GIVEN** valid testnet P2WPKH address (tb1q... with 20-byte program)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=true, witness_version=0, witness_program is 20 bytes

#### Scenario: validateaddress P2WSH
- **GIVEN** valid testnet P2WSH address (tb1q... with 32-byte program)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=true, witness_version=0, witness_program is 32 bytes

#### Scenario: validateaddress P2TR
- **GIVEN** valid testnet P2TR address (tb1p...)
- **WHEN** validateaddress is called
- **THEN** isvalid=true, iswitness=true, witness_version=1, witness_program is 32 bytes

#### Scenario: validateaddress invalid checksum
- **GIVEN** Base58 address with invalid checksum
- **WHEN** validateaddress is called
- **THEN** isvalid=false

#### Scenario: validateaddress invalid bech32
- **GIVEN** malformed bech32 address
- **WHEN** validateaddress is called
- **THEN** isvalid=false

#### Scenario: validateaddress wrong network
- **GIVEN** mainnet address (1... or bc1...) on testnet node
- **WHEN** validateaddress is called
- **THEN** isvalid=false

#### Scenario: validateaddress empty string
- **GIVEN** empty string as address
- **WHEN** validateaddress is called
- **THEN** isvalid=false

### Requirement: Script Decoding
The system SHALL provide a method to decode Bitcoin scripts.

Method:
- `decodescript <hex>`

Returns:
- `asm`: Script disassembly (opcode names and hex data pushes)
- `type`: Detected script type (pubkeyhash, scripthash, witness_v0_keyhash, witness_v0_scripthash, witness_v1_taproot, multisig, nulldata, nonstandard)
- `reqSigs`: Required signatures (for multisig)
- `addresses`: Array of addresses (if applicable)
- `p2sh`: P2SH address wrapping this script
- `segwit`: Nested SegWit address (if script is witness program)

#### Scenario: decodescript P2PKH
- **GIVEN** hex P2PKH script (OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG)
- **WHEN** decodescript is called
- **THEN** type="pubkeyhash", asm shows opcodes, addresses contains P2PKH address

#### Scenario: decodescript P2SH
- **GIVEN** hex P2SH script (OP_HASH160 <20-byte-hash> OP_EQUAL)
- **WHEN** decodescript is called
- **THEN** type="scripthash", addresses contains P2SH address

#### Scenario: decodescript P2WPKH
- **GIVEN** hex witness v0 keyhash script (OP_0 <20-byte-hash>)
- **WHEN** decodescript is called
- **THEN** type="witness_v0_keyhash", segwit contains tb1q address

#### Scenario: decodescript P2WSH
- **GIVEN** hex witness v0 scripthash script (OP_0 <32-byte-hash>)
- **WHEN** decodescript is called
- **THEN** type="witness_v0_scripthash", segwit contains tb1q address

#### Scenario: decodescript P2TR
- **GIVEN** hex witness v1 script (OP_1 <32-byte-key>)
- **WHEN** decodescript is called
- **THEN** type="witness_v1_taproot", segwit contains tb1p address

#### Scenario: decodescript multisig
- **GIVEN** hex bare multisig script (OP_2 <pubkey1> <pubkey2> <pubkey3> OP_3 OP_CHECKMULTISIG)
- **WHEN** decodescript is called
- **THEN** type="multisig", reqSigs=2, asm shows M-of-N structure

#### Scenario: decodescript nulldata
- **GIVEN** hex OP_RETURN script (OP_RETURN <data>)
- **WHEN** decodescript is called
- **THEN** type="nulldata", asm shows OP_RETURN and data

#### Scenario: decodescript invalid hex
- **GIVEN** invalid hex string (odd length or non-hex)
- **WHEN** decodescript is called
- **THEN** error code -22 (Invalid hex) is returned

#### Scenario: decodescript empty
- **GIVEN** empty script (zero bytes, hex "")
- **WHEN** decodescript is called
- **THEN** type="nonstandard", asm=""

#### Scenario: decodescript nonstandard
- **GIVEN** script that doesn't match any standard pattern
- **WHEN** decodescript is called
- **THEN** type="nonstandard", asm shows opcodes/data

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

### Requirement: Prune Blockchain RPC
The system SHALL provide a `pruneblockchain` RPC method to manually trigger block pruning.

Method: `pruneblockchain`
Parameters:
- `height` (integer): Target height to prune up to

Behavior:
- Deletes block data files for all blocks below the specified height
- Respects the 288-block minimum retention window (clamps to `chain-height - 288`)
- Returns the height of the first unpruned block (pruned-height + 1), matching Bitcoin Core
- Works in both automatic pruning mode and manual-only mode (`*prune-target-mib*` = 1)
- Requires pruning to be enabled (any mode); returns error if pruning is disabled

#### Scenario: Manual prune to height
- **GIVEN** pruning is enabled and chain is at height 10000
- **WHEN** `pruneblockchain` is called with height 9000
- **THEN** blocks below height 9000 are pruned
- **AND** response is 9000 (first unpruned block height)

#### Scenario: Prune rejected when disabled
- **GIVEN** pruning is not enabled (`*prune-target-mib*` is nil)
- **WHEN** `pruneblockchain` is called
- **THEN** an error response is returned indicating node is not in prune mode

#### Scenario: Prune clamped to 288-block retention
- **GIVEN** pruning is enabled and chain is at height 10000
- **WHEN** `pruneblockchain` is called with height 9900
- **THEN** blocks are pruned only up to height 9712 (10000 - 288)
- **AND** response is 9713 (first unpruned block)

#### Scenario: Prune in manual-only mode
- **GIVEN** `*prune-target-mib*` is 1 (manual-only) and chain is at height 10000
- **WHEN** `pruneblockchain` is called with height 9000
- **THEN** blocks below height 9000 are pruned
- **AND** response is 9000

### Requirement: RPC Request Rate Limiting
The system SHALL enforce a global rate limit on incoming RPC requests using a token bucket algorithm.

The default rate limit SHALL be 100 requests per second with a burst capacity of 200.

When the rate limit is exceeded, the system SHALL return HTTP 429 (Too Many Requests) without processing the request.

Rate limit parameters SHALL be configurable via global variables.

#### Scenario: Allow requests within rate limit
- **GIVEN** the RPC server is receiving requests at 50/sec
- **WHEN** a new request arrives
- **THEN** the request is processed normally

#### Scenario: Reject requests exceeding rate limit
- **GIVEN** the RPC server has exhausted its rate limit tokens
- **WHEN** a new request arrives
- **THEN** HTTP 429 Too Many Requests is returned
- **AND** the response body contains a JSON-RPC error with message "Rate limit exceeded"

#### Scenario: Allow burst of requests
- **GIVEN** the RPC server has been idle for 2 seconds
- **WHEN** 200 requests arrive simultaneously
- **THEN** all 200 requests are processed (burst capacity)

### Requirement: RPC Request Body Size Limit
The system SHALL reject RPC requests with a body exceeding 1 MB.

The size check SHALL occur before reading and parsing the request body, using the Content-Length header when available.

#### Scenario: Accept normal-sized request
- **GIVEN** an RPC request with a 500-byte JSON body
- **WHEN** the request is received
- **THEN** the request is processed normally

#### Scenario: Reject oversized request
- **GIVEN** an RPC request with Content-Length of 2,000,000 bytes
- **WHEN** the request is received
- **THEN** HTTP 413 Payload Too Large is returned
- **AND** the request body is not read or parsed

#### Scenario: Reject oversized request without Content-Length
- **GIVEN** an RPC request without Content-Length header that exceeds 1 MB during reading
- **WHEN** the body read exceeds 1 MB
- **THEN** reading is aborted and HTTP 413 Payload Too Large is returned

