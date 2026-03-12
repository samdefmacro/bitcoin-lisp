# Change: Add DoS protection and rate limiting

## Why
The node has no defense against resource exhaustion attacks. A malicious peer can flood the node with messages (INV, TX, ADDR, GETDATA), and the RPC interface has no request throttling. This makes the node unsuitable for production use on mainnet where adversarial conditions are expected.

## What Changes
- Per-peer message rate limiting using token bucket algorithm (INV, TX, ADDR, GETDATA, HEADERS)
- Handshake timeout enforcement (disconnect peers that don't complete handshake promptly)
- Maximum P2P message payload size validation before reading payload bytes
- Recent transaction rejects filter to avoid redundant validation work
- RPC request rate limiting with configurable per-second threshold
- RPC request body size limit to prevent memory exhaustion

## Impact
- Affected specs: networking, rpc
- Affected code: `src/networking/peer.lisp`, `src/networking/protocol.lisp`, `src/rpc/server.lisp`, `src/config.lisp`, `src/node.lisp`
