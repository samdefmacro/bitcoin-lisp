# Capability: RPC

The RPC capability provides a JSON-RPC 2.0 interface for external tools to query node state and submit transactions.

## ADDED Requirements

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
- `getblockchaininfo`: Returns network, chain, height, sync progress
- `getbestblockhash`: Returns the hash of the current tip
- `getblockcount`: Returns the current block height
- `getblockhash <height>`: Returns block hash at given height
- `getblock <hash> [verbosity]`: Returns block data (0=hex, 1=json, 2=json+tx)
- `getblockheader <hash> [verbose]`: Returns header data

#### Scenario: getblockchaininfo
- **GIVEN** the node is synced to height 1000
- **WHEN** getblockchaininfo is called
- **THEN** response includes chain "test", blocks 1000, and headers count

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
- `getmempoolinfo`: Returns mempool statistics (size, bytes, usage)
- `getrawmempool [verbose]`: Returns txids or detailed tx info
- `sendrawtransaction <hex>`: Submits raw transaction to mempool

#### Scenario: getmempoolinfo
- **GIVEN** mempool has 5 transactions totaling 2000 bytes
- **WHEN** getmempoolinfo is called
- **THEN** response includes size 5 and bytes 2000

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
