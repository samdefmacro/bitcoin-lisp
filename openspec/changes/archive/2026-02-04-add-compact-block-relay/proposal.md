# Proposal: Add Compact Block Relay (BIP 152)

## Summary

Implement BIP 152 Compact Block Relay to significantly reduce bandwidth during block propagation. Instead of transmitting full blocks (~1-2MB), compact blocks transmit short transaction IDs (~6 bytes each) that receivers can match against their mempool to reconstruct the block locally.

## Motivation

Currently, when a new block is announced:
1. Node receives `inv` for the block
2. Node requests full block via `getdata`
3. Peer sends complete block (~1-2MB)

With compact blocks:
1. Peer sends `cmpctblock` with header + short txids (~10-30KB typical)
2. Node reconstructs block from mempool (most transactions already known)
3. If missing transactions, request only those via `getblocktxn` (~few KB)

**Benefits:**
- ~90-99% bandwidth reduction for block relay (depending on mempool synchronization)
- Faster block propagation (critical for network health)
- Reduces orphan rates during high traffic periods
- Required for proper interaction with modern Bitcoin Core nodes

## Scope

### In Scope
- **Low-bandwidth mode** (version 1 and 2): Receive compact blocks after `inv`/`headers` announcement
- **High-bandwidth mode**: Receive unsolicited `cmpctblock` messages for faster relay
- New P2P messages: `sendcmpct`, `cmpctblock`, `getblocktxn`, `blocktxn`
- SipHash-2-4 implementation for short transaction ID calculation
- Compact block reconstruction from mempool
- Version 2 support (uses wtxid instead of txid for SegWit compatibility)

### Out of Scope
- Sending compact blocks to peers (relay mode) - we only receive
- Compact block filter support (BIP 157/158) - separate feature
- Block relay optimization during IBD (compact blocks not used during IBD)

## Technical Approach

### 1. SipHash-2-4 Implementation
Add SipHash-2-4 to the crypto module. This is a fast, secure hash used to compute 6-byte short transaction IDs from full 32-byte txids.

### 2. New Message Types (Serialization)
Add parsing/serialization for:
- `sendcmpct`: Negotiation message (1-byte announce flag + 8-byte version)
- `cmpctblock`: HeaderAndShortIDs structure
- `getblocktxn`: Request missing transactions by index
- `blocktxn`: Response with requested full transactions

### 3. Protocol Negotiation
During handshake:
- Send `sendcmpct` messages to advertise support (versions 2 then 1)
- Track per-peer compact block version negotiation
- Store high-bandwidth vs low-bandwidth mode preference per peer

### 4. Compact Block Handling
When receiving `cmpctblock`:
1. Parse header and validate proof-of-work
2. Compute SipHash key from header + nonce
3. For each short ID, search mempool for matching transaction
4. If all transactions found, reconstruct and validate block
5. If transactions missing, send `getblocktxn` request
6. Upon receiving `blocktxn`, complete reconstruction

### 5. Integration with Block Download
- Request compact blocks via `MSG_CMPCT_BLOCK` getdata type
- Fall back to full block if reconstruction fails
- Track reconstruction success rate for optimization

## Alternatives Considered

1. **Skip compact blocks entirely**: Simpler but wastes significant bandwidth
2. **Version 1 only**: Would work but version 2 is needed for proper SegWit support
3. **High-bandwidth only**: Simpler but less flexible; low-bandwidth mode is useful for bandwidth-constrained nodes

## Dependencies

- Mempool must be functional (already implemented)
- Transaction wtxid calculation (already implemented)
- Block header validation (already implemented)

## Risks

- **Complexity**: Compact block reconstruction adds code paths
- **Mempool desync**: If mempool differs significantly from miner's, falls back to full block
- **Hash collisions**: Extremely rare (~1 per 281,474 blocks) but must be handled

## Success Criteria

- Successfully negotiate compact block support with Bitcoin Core peers
- Reconstruct blocks from compact announcements when mempool is synchronized
- Graceful fallback to full block requests when reconstruction fails
- Unit tests for SipHash, message parsing, and block reconstruction
