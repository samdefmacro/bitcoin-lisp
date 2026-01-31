# Design: RPC Interface

## Overview
Implement a JSON-RPC 2.0 server that exposes Bitcoin Core-compatible methods for querying node state. The interface prioritizes read-only operations initially, with write operations (sendrawtransaction) added for mempool interaction.

## Architecture

### Components
1. **HTTP Server** - Listens on configurable port (default 18332 for testnet)
2. **JSON-RPC Handler** - Parses requests, dispatches to methods, formats responses
3. **Method Registry** - Maps method names to handler functions
4. **Authentication** - Optional HTTP Basic Auth (rpcuser/rpcpassword)
5. **Thread-Safe Accessors** - Safe access to node state from RPC threads

### Request Flow
```
HTTP POST /
  -> Validate Content-Type: application/json
  -> Parse JSON-RPC request
  -> Validate method exists
  -> Acquire node lock (read)
  -> Execute handler with params
  -> Release lock
  -> Format JSON-RPC response (preserve request "id")
  -> Return HTTP 200 with JSON body
```

### JSON-RPC 2.0 Response Format
All responses include:
- `"jsonrpc": "2.0"` - Protocol version
- `"id"` - Copied from request (null for notifications)
- `"result"` - On success, the method return value
- `"error"` - On failure, object with `code`, `message`, optional `data`

## Method Categories

### Blockchain Query (Phase 1)
- `getblockchaininfo` - Network, chain height, sync status
- `getbestblockhash` - Current tip hash
- `getblockcount` - Current height
- `getblockhash <height>` - Hash at height
- `getblock <hash> [verbosity]` - Block data (hex or decoded)
- `getblockheader <hash> [verbose]` - Header data

### UTXO Query (Phase 1)
- `gettxout <txid> <vout>` - UTXO entry if unspent

### Network Info (Phase 1)
- `getpeerinfo` - Connected peer details
- `getnetworkinfo` - Network status
- `getconnectioncount` - Peer count

### Mempool (Phase 2)
- `getmempoolinfo` - Mempool statistics
- `getrawmempool [verbose]` - Transaction list
- `sendrawtransaction <hex>` - Submit transaction

## Design Decisions

### Why JSON-RPC 2.0?
- Bitcoin Core compatibility
- Simple protocol (single POST endpoint)
- Batch request support
- Established tooling (bitcoin-cli, curl)

### Why Hunchentoot?
- Mature, stable HTTP server for Common Lisp
- Easy to embed in existing process
- Supports threading for concurrent requests

### Authentication Model
- Optional for development (disabled by default)
- HTTP Basic Auth when enabled
- Single rpcuser/rpcpassword pair (no ACLs initially)

### Error Handling
Standard JSON-RPC error codes:
- -32700: Parse error
- -32600: Invalid request
- -32601: Method not found
- -32602: Invalid params
- -32603: Internal error

Bitcoin-specific errors:
- -1: General error
- -5: Invalid address/key
- -8: Invalid parameter

## Thread Safety

The node has multiple concurrent threads:
- Main thread (REPL)
- IBD sync thread (downloading/validating blocks)
- RPC handler threads (one per request via hunchentoot)

### Strategy: Reader Lock
RPC methods are primarily read-only queries. Use the existing `node-lock` for synchronization:
- RPC methods acquire lock before accessing node state
- IBD thread already uses lock for state updates
- Read operations are fast, minimal contention expected

### Thread-Safe Accessors
Create accessor functions that acquire lock internally:
- `(rpc-get-chain-state node)` - Returns chain-state snapshot
- `(rpc-get-utxo-set node)` - Returns utxo-set reference
- `(rpc-get-peers node)` - Returns copy of peer list
- `(rpc-get-mempool node)` - Returns mempool reference

## Error Handling

### Startup Errors
- Port already in use: Log error, node continues without RPC
- Invalid configuration: Log warning, use defaults

### Request Errors
- Malformed JSON: Return -32700 with parse error details
- Invalid method: Return -32601 with method name
- Invalid params: Return -32602 with param validation message
- Internal error: Return -32603, log full stack trace

### Input Validation
- Block hash: Must be 64 hex characters
- Txid: Must be 64 hex characters
- Height: Must be non-negative integer within chain range
- Verbosity: Must be 0, 1, or 2

## Explicitly Deferred Features
- `getrawtransaction` - Requires transaction index (not implemented)
- `gettransaction` - Requires wallet (out of scope)
- TLS/HTTPS - Use reverse proxy if needed
- Rate limiting - Localhost-only mitigates risk
- RPC whitelist/blacklist - Single user auth sufficient initially

## Security Considerations
- Bind to localhost by default (127.0.0.1)
- Require Content-Type: application/json
- No CORS headers (browser access blocked)
- Rate limiting deferred to future work
- TLS/HTTPS deferred to future work

## Dependencies
- `hunchentoot` - HTTP server
- `yason` - JSON parsing/generation (preferred over cl-json for speed)
