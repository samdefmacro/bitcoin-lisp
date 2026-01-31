## 1. RPC Infrastructure
- [x] 1.1 Add hunchentoot and yason dependencies to bitcoin-lisp.asd
- [x] 1.2 Create src/rpc/package.lisp with RPC package definition
- [x] 1.3 Create src/rpc/server.lisp with start-rpc-server and stop-rpc-server
- [x] 1.4 Implement JSON-RPC 2.0 request parsing (single and batch, preserve id)
- [x] 1.5 Implement JSON-RPC 2.0 response formatting with error codes
- [x] 1.6 Implement Content-Type validation (require application/json)
- [x] 1.7 Create method registry with dispatch-rpc-method
- [x] 1.8 Handle port-in-use error gracefully (log and continue without RPC)
- [x] 1.9 Write tests for JSON-RPC parsing, id preservation, and error handling

## 2. Thread-Safe Accessors
- [x] 2.1 Create src/rpc/accessors.lisp with thread-safe node state accessors
- [x] 2.2 Implement rpc-get-chain-state (acquires node lock)
- [x] 2.3 Implement rpc-get-utxo-set (acquires node lock)
- [x] 2.4 Implement rpc-get-peers (returns copy of peer list)
- [x] 2.5 Implement rpc-get-mempool (acquires node lock)
- [x] 2.6 Implement rpc-get-block-store (acquires node lock)
- [x] 2.7 Write tests for concurrent access safety

## 3. Blockchain Query Methods
- [x] 3.1 Create src/rpc/methods.lisp for method implementations
- [x] 3.2 Implement getblockchaininfo (chain, height, headers, sync progress)
- [x] 3.3 Implement getbestblockhash
- [x] 3.4 Implement getblockcount
- [x] 3.5 Implement getblockhash with height validation
- [x] 3.6 Implement getblock with verbosity 0 (hex)
- [x] 3.7 Implement getblock with verbosity 1 (json with txids)
- [x] 3.8 Implement getblock with verbosity 2 (json with full tx details)
- [x] 3.9 Implement getblockheader (verbose and non-verbose)
- [x] 3.10 Add input validation for block hash format (64 hex chars)
- [x] 3.11 Write tests for blockchain query methods

## 4. UTXO Query Methods
- [x] 4.1 Implement gettxout (lookup UTXO, format response)
- [x] 4.2 Add input validation for txid format (64 hex chars)
- [x] 4.3 Write tests for gettxout with existing, spent, and invalid inputs

## 5. Network Query Methods
- [x] 5.1 Implement getpeerinfo (connected peers with addr, version, subver)
- [x] 5.2 Implement getnetworkinfo (version, subversion, protocolversion, networkactive)
- [x] 5.3 Implement getconnectioncount
- [x] 5.4 Write tests for network query methods

## 6. Mempool Methods
- [x] 6.1 Implement getmempoolinfo (size, bytes, usage)
- [x] 6.2 Implement getrawmempool non-verbose (array of txids)
- [x] 6.3 Implement getrawmempool verbose (object with tx details)
- [x] 6.4 Implement sendrawtransaction with validation and error messages
- [x] 6.5 Write tests for mempool methods

## 7. Authentication
- [x] 7.1 Implement HTTP Basic auth header parsing
- [x] 7.2 Add rpcuser/rpcpassword configuration to node
- [x] 7.3 Return HTTP 401 for missing/invalid credentials when auth enabled
- [x] 7.4 Write tests for authentication flow (enabled and disabled)

## 8. Node Integration
- [x] 8.1 Update src/package.lisp with RPC exports
- [x] 8.2 Add RPC configuration options to start-node (:rpc-port, :rpc-bind, :rpc-user, :rpc-password)
- [x] 8.3 Start RPC server in node startup sequence (after chain-state initialized)
- [x] 8.4 Stop RPC server in node shutdown sequence (before chain-state cleanup)
- [x] 8.5 Write integration test: start node, call RPC, verify response

## 9. Validation and Documentation
- [x] 9.1 Manual test with curl: getblockchaininfo, getblock, gettxout
- [x] 9.2 Manual test batch request handling
- [x] 9.3 Verify error responses match Bitcoin Core format
- [x] 9.4 Test concurrent RPC requests during active sync
