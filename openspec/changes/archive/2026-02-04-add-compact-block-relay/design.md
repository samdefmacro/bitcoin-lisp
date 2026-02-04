# Design: Compact Block Relay (BIP 152)

## Overview

This document describes the technical design for implementing BIP 152 Compact Block Relay in bitcoin-lisp. The implementation focuses on receiving compact blocks from peers (not sending), which provides the bandwidth benefits while keeping complexity manageable.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Compact Block Flow                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Peer sends:     ┌──────────────┐                          │
│  sendcmpct  ───► │   Peer       │ ◄─── Track CB version    │
│                  │   State      │      per peer            │
│                  └──────────────┘                          │
│                         │                                   │
│                         ▼                                   │
│  Peer sends:     ┌──────────────┐     ┌───────────────┐   │
│  cmpctblock ───► │   Parse &    │ ──► │   Mempool     │   │
│                  │   Validate   │     │   Lookup      │   │
│                  └──────────────┘     └───────────────┘   │
│                         │                    │             │
│                         ▼                    ▼             │
│                  ┌──────────────────────────────────┐      │
│                  │     Reconstruct Block            │      │
│                  │     (match short IDs to txs)     │      │
│                  └──────────────────────────────────┘      │
│                         │                                   │
│         ┌───────────────┴───────────────┐                  │
│         ▼                               ▼                  │
│  ┌─────────────┐                 ┌─────────────────┐       │
│  │ All txs     │                 │ Missing txs     │       │
│  │ found       │                 │ detected        │       │
│  └─────────────┘                 └─────────────────┘       │
│         │                               │                   │
│         ▼                               ▼                   │
│  ┌─────────────┐                 ┌─────────────────┐       │
│  │ Validate &  │                 │ Send getblocktxn│       │
│  │ Connect     │                 │ Wait for        │       │
│  │ Block       │                 │ blocktxn        │       │
│  └─────────────┘                 └─────────────────┘       │
│                                         │                   │
│                                         ▼                   │
│                                  ┌─────────────────┐       │
│                                  │ Complete block  │       │
│                                  │ & validate      │       │
│                                  └─────────────────┘       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Data Structures

### Peer State Extensions

```lisp
;; Added to peer struct
(defstruct peer
  ;; ... existing fields ...
  ;; Compact block negotiation
  (compact-block-version 0 :type (unsigned-byte 64))  ; 0=not supported, 1 or 2
  (compact-block-high-bandwidth nil :type boolean)    ; High-bandwidth mode enabled
  ;; Pending compact block reconstruction
  (pending-compact-block nil))  ; Partially reconstructed block awaiting txs
```

### Compact Block Message Structures

```lisp
;; HeaderAndShortIDs - the cmpctblock payload
(defstruct compact-block
  (header nil :type block-header)     ; 80-byte block header
  (nonce 0 :type (unsigned-byte 64))  ; Random nonce for short ID generation
  (short-ids '() :type list)          ; List of 6-byte short transaction IDs
  (prefilled-txs '() :type list))     ; List of (index . transaction) pairs

;; PrefilledTransaction
(defstruct prefilled-tx
  (index 0 :type (unsigned-byte 32))  ; Differentially encoded index
  (transaction nil :type bitcoin-transaction))

;; BlockTransactionsRequest (getblocktxn)
(defstruct block-txn-request
  (block-hash nil :type (simple-array (unsigned-byte 8) (32)))
  (indexes '() :type list))  ; Differentially encoded indexes

;; BlockTransactions (blocktxn)
(defstruct block-txn-response
  (block-hash nil :type (simple-array (unsigned-byte 8) (32)))
  (transactions '() :type list))  ; Full transactions
```

## SipHash-2-4 Implementation

BIP 152 uses SipHash-2-4 to generate short transaction IDs. The algorithm:

1. **Key derivation**: `SHA256(header || nonce)` → first 16 bytes as k0, k1
2. **Hash computation**: `SipHash-2-4(k0, k1, txid)` → 8 bytes
3. **Truncation**: Drop 2 MSB bytes → 6-byte short ID

```lisp
(defun compute-siphash-key (header nonce)
  "Compute SipHash key from block header and nonce.
   Returns (k0 . k1) as two 64-bit integers."
  (let* ((data (concatenate '(vector (unsigned-byte 8))
                            (serialize-block-header header)
                            (uint64-to-bytes-le nonce)))
         (hash (sha256 data)))
    ;; First 8 bytes = k0, next 8 bytes = k1 (little-endian)
    (values (bytes-to-uint64-le hash 0)
            (bytes-to-uint64-le hash 8))))

(defun compute-short-txid (k0 k1 txid)
  "Compute 6-byte short transaction ID using SipHash-2-4."
  (let ((hash (siphash-2-4 k0 k1 txid)))
    ;; Take lower 6 bytes (drop 2 MSB)
    (logand hash #xFFFFFFFFFFFF)))
```

## Short ID Matching Algorithm

Efficiently matching short IDs to mempool transactions:

```lisp
(defun build-shortid-map (mempool k0 k1 use-wtxid)
  "Build hash table mapping short IDs to transactions.
   USE-WTXID is true for compact block version 2.
   Returns (VALUES map collision-detected) where collision-detected is T if
   two transactions hash to the same short ID."
  (let ((map (make-hash-table))
        (collision nil))
    (mempool-for-each mempool
      (lambda (txid entry)
        (let* ((tx (mempool-entry-transaction entry))
               (id (if use-wtxid
                       (transaction-wtxid tx)
                       txid))
               (short-id (compute-short-txid k0 k1 id)))
          ;; Detect collisions - if short ID already in map, mark collision
          (when (gethash short-id map)
            (setf collision t))
          (setf (gethash short-id map) tx))))
    (values map collision)))

(defun reconstruct-block (compact-block mempool use-wtxid)
  "Attempt to reconstruct full block from compact block and mempool.
   Returns (VALUES block missing-indexes) where missing-indexes is NIL on success.
   Returns (VALUES nil :collision) if short ID collision detected."
  (let* ((header (compact-block-header compact-block))
         (nonce (compact-block-nonce compact-block))
         (short-ids (compact-block-short-ids compact-block))
         (prefilled (compact-block-prefilled-txs compact-block))
         (tx-count (+ (length short-ids) (length prefilled))))
    (multiple-value-bind (k0 k1) (compute-siphash-key header nonce)
      (multiple-value-bind (shortid-map collision)
          (build-shortid-map mempool k0 k1 use-wtxid)
        ;; If collision detected, fall back to full block
        (when collision
          (return-from reconstruct-block (values nil :collision)))

        (let ((transactions (make-array tx-count :initial-element nil))
              (missing-indexes '())
              (short-id-idx 0))
          ;; Place prefilled transactions at their absolute indexes
          ;; (indexes were decoded from differential during parsing)
          (dolist (ptx prefilled)
            (setf (aref transactions (prefilled-tx-index ptx))
                  (prefilled-tx-transaction ptx)))

          ;; Fill remaining slots with mempool transactions matched by short ID
          ;; Short IDs fill positions NOT occupied by prefilled transactions
          (dotimes (i tx-count)
            (when (null (aref transactions i))
              ;; This slot needs a transaction from short IDs
              (let* ((short-id (nth short-id-idx short-ids))
                     (tx (gethash short-id shortid-map)))
                (if tx
                    (setf (aref transactions i) tx)
                    (push i missing-indexes))
                (incf short-id-idx))))

          (if missing-indexes
              (values nil (nreverse missing-indexes))
              (values (make-bitcoin-block :header header
                                          :transactions (coerce transactions 'list))
                      nil)))))))
```

## Protocol Flow

### Handshake Phase

```
Node                                    Peer
  |                                      |
  |  ─────── version ──────────────────► |
  |  ◄────── version ────────────────── |
  |  ─────── verack ───────────────────► |
  |  ◄────── verack ─────────────────── |
  |                                      |
  |  ◄────── sendcmpct(hb=0, v=2) ───── |  (peer supports version 2)
  |  ◄────── sendcmpct(hb=0, v=1) ───── |  (peer also supports version 1)
  |                                      |
  |  ─────── sendcmpct(hb=0, v=2) ─────►|  (we support version 2)
  |  ─────── sendcmpct(hb=0, v=1) ─────►|  (we also support version 1)
  |                                      |
```

### Low-Bandwidth Mode Block Receipt

```
Node                                    Peer
  |                                      |
  |  ◄────── inv(block_hash) ────────── |  New block announced
  |                                      |
  |  ─── getdata(MSG_CMPCT_BLOCK) ─────►|  Request compact block
  |                                      |
  |  ◄────── cmpctblock ─────────────── |  Receive compact block
  |                                      |
  |  [Reconstruct from mempool]          |
  |                                      |
  |  (If missing txs):                   |
  |  ─────── getblocktxn ──────────────►|  Request missing txs
  |  ◄────── blocktxn ─────────────────  |  Receive missing txs
  |                                      |
  |  [Complete reconstruction]           |
  |  [Validate and connect block]        |
```

### High-Bandwidth Mode Block Receipt

```
Node                                    Peer
  |                                      |
  |  ◄────── cmpctblock ─────────────── |  Unsolicited compact block
  |                                      |
  |  [Reconstruct from mempool]          |
  |                                      |
  |  (Same flow as low-bandwidth for     |
  |   missing transactions)              |
```

## Inventory Type

Add new inventory type for requesting compact blocks:

```lisp
(defconstant +inv-type-cmpct-block+ 4)
;; MSG_CMPCT_BLOCK = 4, used in getdata to request cmpctblock instead of full block
```

## Error Handling

### Reconstruction Failures

If block reconstruction fails (too many missing transactions, collision detected):
1. Fall back to requesting full block via standard `getdata`
2. Log the failure for debugging
3. Do not penalize peer (not their fault)

### Hash Collisions

Short ID collisions are detected during `build-shortid-map`:
- If two mempool transactions hash to the same short ID, the map builder sets a collision flag
- When collision detected, immediately fall back to full block request
- Log collision events for monitoring (expected ~1 per 281,474 blocks)

### Pending State Management

The `pending-compact-block` slot in peer state requires careful lifecycle management:

**Creation**: When receiving a `cmpctblock` with missing transactions:
- Store the partial reconstruction state
- Record the block hash, missing indexes, and timestamp
- Send `getblocktxn` request

**Completion**: When receiving `blocktxn`:
- Verify block hash matches pending reconstruction
- Insert missing transactions and complete block
- Clear pending state

**Cleanup triggers**:
1. **Successful completion**: Clear after block validated and connected
2. **Timeout**: Clear after N seconds (default: 10s) if no `blocktxn` received
3. **New block received**: If we receive a different block (full or compact) while waiting, clear pending state for the old block
4. **Peer disconnect**: Clear all pending state for that peer

**State structure**:
```lisp
(defstruct pending-compact-block
  (block-hash nil)           ; Hash of block being reconstructed
  (header nil)               ; Block header
  (transactions nil)         ; Partial transaction array (with nils for missing)
  (missing-indexes nil)      ; List of indexes still needed
  (request-time 0)           ; When getblocktxn was sent
  (use-wtxid nil))           ; Version 2 uses wtxid
```

## Version Selection

- **Version 2**: Use wtxid (witness txid) - required for SegWit transactions
- **Version 1**: Use txid - legacy support

We prefer version 2 but fall back to version 1 if peer doesn't support it.

## Integration Points

### Message Handler Updates

Add handlers in `handle-message`:
- `sendcmpct`: Update peer's compact block capabilities
- `cmpctblock`: Attempt reconstruction, request missing txs if needed
- `blocktxn`: Complete pending reconstruction

### Block Download Coordination

When requesting blocks:
- If peer supports compact blocks and we're not in IBD, use `MSG_CMPCT_BLOCK`
- If compact block fails, retry with full block request

### IBD (Initial Block Download) Guard

Compact blocks are NOT used during IBD:
- During IBD, mempool is empty or has very few transactions
- Block reconstruction would fail for almost every block
- Full blocks are more efficient during bulk sync

Implementation:
```lisp
(defun should-use-compact-blocks-p (peer)
  "Return T if we should request compact blocks from PEER."
  (and (> (peer-compact-block-version peer) 0)  ; Peer supports CB
       (not (eq (ibd-state) :syncing-blocks))   ; Not in IBD
       (not (eq (ibd-state) :syncing-headers)))) ; Not syncing headers
```

### Mempool Integration

- Need efficient lookup by short ID (hash table with O(1) lookup)
- Version 2 requires wtxid lookup capability
- Prefilled transactions in `cmpctblock` use witness serialization format

## Performance Considerations

1. **Memory**: Short ID map is temporary, built per compact block
2. **CPU**: SipHash is fast (~3 cycles/byte), SHA256 for key derivation is one-time
3. **Bandwidth**: Primary benefit - reduces block relay by ~95% typical case

## Testing Strategy

1. **Unit tests**: SipHash implementation against test vectors
2. **Unit tests**: Message parsing/serialization
3. **Unit tests**: Block reconstruction with mock mempool
4. **Integration tests**: Negotiate compact blocks with testnet peer
5. **Integration tests**: Receive and reconstruct testnet blocks
