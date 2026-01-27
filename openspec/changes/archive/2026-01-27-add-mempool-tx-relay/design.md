## Context
The node currently handles blocks-only synchronization. To be a full network participant, it must accept, validate, store, and relay unconfirmed transactions. This touches networking (new message handlers), validation (policy rules), and a new mempool subsystem.

## Goals / Non-Goals
- Goals:
  - Accept and validate unconfirmed transactions from peers
  - Maintain an in-memory transaction pool indexed by txid
  - Relay valid transactions to connected peers via inv/getdata
  - Enforce basic mempool policy (size limits, minimum fee, eviction)
  - Remove confirmed transactions when blocks are connected
  - Re-admit transactions when blocks are disconnected (reorg)
- Non-Goals:
  - Replace-By-Fee (BIP 125) — future enhancement
  - CPFP (Child Pays For Parent) fee calculation — future enhancement
  - Compact block relay (BIP 152) — future enhancement
  - Fee estimation — future enhancement
  - Mempool persistence across restarts — future enhancement

## Decisions

### Mempool data structure
- Decision: Hash table keyed by txid, with a secondary index on spent outpoints for conflict detection
- Alternatives considered:
  - Sorted tree by fee-rate: adds complexity; a simple hash table with linear-scan eviction is sufficient for initial implementation
  - Multi-index container: over-engineered for current needs

### Fee-rate tracking
- Decision: Store fee and serialized size per entry; compute fee-rate on demand
- Rationale: Avoids stale cached values; fee-rate = fee / size is cheap to compute

### Eviction policy
- Decision: When mempool exceeds max size, evict lowest fee-rate transactions until under limit
- Max size: 300 MB of serialized transaction data (matches Bitcoin Core default)
- Rationale: Simple and effective; Bitcoin Core uses a more sophisticated descendant-score eviction, but that requires ancestor/descendant tracking we're deferring

### Transaction relay
- Decision: Announce new mempool transactions to all connected peers (except the sender) via `inv` messages; respond to `getdata` with `tx` messages
- Rationale: Straightforward relay model; batching/trickling can be added later

### Mempool and block interaction
- Decision: When a block is connected, remove its transactions from the mempool. When a block is disconnected during reorg, re-validate and re-admit its non-coinbase transactions to the mempool.
- Rationale: Ensures mempool stays consistent with chain tip

## Risks / Trade-offs
- Memory usage: unbounded mempool could use excessive memory → Mitigation: enforce max size with eviction
- DoS via invalid transactions: peers could flood invalid txs → Mitigation: disconnect/ban peers that send many invalid transactions
- No RBF means conflicting transactions are rejected outright → acceptable for initial implementation

## Open Questions
- None currently; deferred features (RBF, CPFP, persistence) are explicitly out of scope
