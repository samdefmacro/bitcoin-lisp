## Context
The node currently relies only on misbehavior scoring (ban after 100 points) and connection timeouts for protection. This is insufficient against volumetric attacks where individually valid-looking messages arrive at high rates. Bitcoin Core implements multiple rate limiting layers; we need similar protections.

## Goals / Non-Goals
- Goals:
  - Prevent resource exhaustion from high-rate message floods
  - Limit RPC abuse from unauthorized or runaway clients
  - Avoid revalidating recently rejected transactions
- Non-Goals:
  - Inbound connection rate limiting — the node only makes outbound connections currently; add when inbound listener is implemented
  - Eclipse attack resistance (address bucketing) — separate change
  - Per-peer bandwidth throttling (bytes/sec caps) — future enhancement
  - Advanced peer scoring (latency-based selection) — separate change
  - RPC authentication improvements — already has HTTP Basic auth
  - Per-item rate limiting within messages (e.g. item count in INV) — noted as future enhancement below

## Decisions

### Token bucket rate limiting for P2P messages
- Decision: Use a per-peer token bucket with configurable rate and burst for each message type
- Why: Token bucket is simple, allows bursts (legitimate during block announcements), and is well-understood. Bitcoin Core uses similar approach.
- Alternatives: Fixed window counters (too bursty at boundaries), sliding window (more complex, marginal benefit)
- Parameters per message type:
  - INV: 50/sec sustained, burst 200 (block announcements can be large)
  - TX: 10/sec sustained, burst 50
  - ADDR/ADDRV2: 1/sec sustained, burst 10
  - GETDATA: 20/sec sustained, burst 100
  - HEADERS: 10/sec sustained, burst 50 (must be generous — during IBD the node sends rapid getheaders requests and receives rapid responses)
- IBD consideration: During Initial Block Download, the node is the requestor for HEADERS and blocks. The HEADERS rate limit is set high enough to accommodate rapid header sync without disconnecting the sync peer.
- Scope note: This limits the number of *messages* per second, not the number of *items* within a message. A single INV message can contain up to 50,000 inventory items. Per-item limiting is a separate concern for future work; the existing 1000-entry cap on ADDR messages (already in the networking spec) is an example of per-item limiting.

### Handshake timeout
- Decision: Peers MUST complete version handshake within 30 seconds or be disconnected
- Why: Prevents "ghost" connections that hold slots without contributing. 30 seconds is generous for legitimate peers.

### Maximum message payload size
- Decision: Enforce a 4 MB max payload size, validated before allocating/reading the payload buffer
- Why: Bitcoin protocol max block size is ~4 MB (with witness discount). No legitimate message exceeds this. Prevents memory exhaustion from forged length headers.

### Recent rejects filter
- Decision: Maintain a bounded set of recently rejected transaction hashes (max 50,000 entries, LRU eviction)
- Why: Avoids expensive re-validation of transactions that were already rejected. Bitcoin Core uses a rolling bloom filter; a bounded hash set is simpler and sufficient for our peer count.
- Clear on block disconnect (reorg), not on every block connect. A transaction rejected for a bad signature will never become valid after a new block; only missing-input or timelock rejections could change validity after a reorg. Clearing on every block connect would discard useful cached rejections unnecessarily.

### RPC rate limiting
- Decision: Global request rate limit using token bucket, default 100 req/sec with burst of 200
- Why: Prevents accidental or malicious query floods. Per-client limiting would require tracking client IPs; global limiting is simpler and sufficient for a localhost-bound service.
- Thread safety: The RPC token bucket is shared across Hunchentoot's thread pool and MUST use a lock for thread-safe access. P2P rate limiters are accessed from the single sync thread and do not need locking.

### RPC request body size limit
- Decision: Reject requests with body > 1 MB
- Why: Prevents memory exhaustion from oversized JSON payloads. Largest legitimate request (sendrawtransaction) is ~400 KB for a max-size transaction.
- Hunchentoot constraint: Hunchentoot reads the request body before invoking the handler. The size check will need to use a custom acceptor subclass or `before-handler` hook to reject oversized requests before the body is fully read, rather than checking inside the RPC handler after the fact.

## Risks / Trade-offs
- Overly aggressive rate limits could affect legitimate sync during IBD → Mitigate: HEADERS limit is generous (10/sec, burst 50); INV and GETDATA limits are also generous; during IBD the node is the requestor, not the receiver for most message types
- Token bucket state adds per-peer memory overhead → Minimal: ~100 bytes per bucket, ~5 buckets per peer
- Recent rejects filter is not cleared on forward block progress, only on reorg → Acceptable: entries are evicted via LRU when capacity is reached, and transactions rejected for permanent reasons (bad signature) should stay rejected

## Open Questions
- Should rate limit violations increment misbehavior score? Starting with disconnect-only (no ban) to be conservative.
