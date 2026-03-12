## 1. Token Bucket Rate Limiter
- [x] 1.1 Implement `make-token-bucket` struct (rate, burst, tokens, last-refill timestamp)
- [x] 1.2 Implement `token-bucket-allow-p` function (refill tokens based on elapsed time, consume or reject)
- [x] 1.3 Add unit tests for token bucket (refill, burst, depletion, edge cases)

## 2. Per-Peer Message Rate Limiting
- [x] 2.1 Add rate limiter slots to peer struct (one token bucket per tracked message type)
- [x] 2.2 Initialize rate limiters on peer creation with default parameters
- [x] 2.3 Add rate limit check in message dispatch (before processing INV, TX, ADDR, ADDRV2, GETDATA, HEADERS)
- [x] 2.4 Disconnect peer when rate limit exceeded, log the violation
- [x] 2.5 Add configurable rate limit parameters to config.lisp
- [x] 2.6 Add tests for per-peer rate limiting

## 3. Handshake Timeout
- [x] 3.1 Record handshake start time when peer connects
- [x] 3.2 Add handshake timeout check in peer maintenance loop (30-second limit)
- [x] 3.3 Disconnect peers that exceed handshake timeout
- [x] 3.4 Add tests for handshake timeout enforcement

## 4. Maximum Message Payload Validation
- [x] 4.1 Add `+max-message-payload+` constant (4 MB)
- [x] 4.2 Validate payload length from message header before reading payload bytes
- [x] 4.3 Disconnect peer and log if oversized message received
- [x] 4.4 Add tests for oversized message rejection

## 5. Recent Transaction Rejects Filter
- [x] 5.1 Implement bounded hash set with LRU eviction (`make-recent-rejects`, `recent-reject-p`, `add-recent-reject`)
- [x] 5.2 Add reject filter check before mempool validation in transaction processing
- [x] 5.3 Add rejected transaction hashes to filter after validation failure
- [x] 5.4 Clear filter on block disconnect (reorg only, not on every block connect)
- [x] 5.5 Add configurable max size (default 50,000)
- [x] 5.6 Add tests for recent rejects filter

## 6. RPC Rate Limiting
- [x] 6.1 Add global RPC token bucket (100 req/sec, burst 200) with thread-safe access (lock around token bucket operations)
- [x] 6.2 Check rate limit before dispatching RPC method
- [x] 6.3 Return HTTP 429 Too Many Requests when rate exceeded
- [x] 6.4 Add configurable rate limit parameters
- [x] 6.5 Add tests for RPC rate limiting

## 7. RPC Request Body Size Limit
- [x] 7.1 Add `+max-rpc-body-size+` constant (1 MB)
- [x] 7.2 Implement size check via custom Hunchentoot acceptor subclass or before-handler hook (body must be rejected before Hunchentoot reads it fully)
- [x] 7.3 Return HTTP 413 Payload Too Large when exceeded
- [x] 7.4 Add tests for body size limit
