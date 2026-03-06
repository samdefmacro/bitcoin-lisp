## Context
The node has no memory of peers between restarts. Every startup hits DNS seeds, which is slow and wasteful. Connected peer quality is unknown — no tracking of which peers respond reliably. This design adds a persistent peer database to enable warm starts and reputation-informed selection.

## Goals / Non-Goals
- Goals: persist learned peer addresses across restarts, score peers by reliability, select good peers first, integrate with addr message flow
- Non-Goals: geographic diversity, Tor/I2P support, encrypted peer database, peer address relay (addrv2)

## Decisions

### Persistence Format
Binary file `peers.dat` in the node's data directory:

```
Offset  Size   Field
0       4      Magic bytes: "PEER" (0x50454552)
4       4      Version: 1 (uint32 LE)
8       4      Entry count (uint32 LE)
12      N*38   Entries (38 bytes each)
12+N*38 4      CRC32 of all preceding bytes
```

Each entry (38 bytes):
```
Offset  Size   Field
0       16     IP address (IPv4-mapped-IPv6, big-endian)
16      2      Port (uint16 big-endian, network byte order)
18      8      Services bitfield (uint64 LE)
26      4      Last-seen timestamp (uint32 LE, Unix epoch)
30      4      Last-attempt timestamp (uint32 LE, Unix epoch)
34      2      Success count (uint16 LE, capped at 65535)
36      2      Failure count (uint16 LE, capped at 65535)
```

- Rationale: Fixed-size entries enable simple sequential read/write. 38 bytes × 2000 entries = 76KB max — trivial.
- CRC32 reuses `compute-crc32` from `src/storage/utxo.lisp:160`.
- Atomic write uses the `.tmp` + `rename-file` pattern from `save-utxo-set` (`src/storage/utxo.lisp:206-211`).

### Address Book Structure
```lisp
(defstruct peer-address
  (ip #(0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0) :type (simple-array (unsigned-byte 8) (16)))
  (port 0 :type (unsigned-byte 16))
  (services 0 :type (unsigned-byte 64))
  (last-seen 0 :type (unsigned-byte 32))
  (last-attempt 0 :type (unsigned-byte 32))
  (successes 0 :type (unsigned-byte 16))
  (failures 0 :type (unsigned-byte 16)))

(defstruct address-book
  (entries (make-hash-table :test 'equalp) :type hash-table)  ; key = ip+port bytes
  (max-entries 2000 :type (unsigned-byte 16))
  (dirty nil :type boolean))
```

Key is a 18-byte vector (16 IP + 2 port) for uniqueness.

### Peer Scoring
Selection priority uses `reliability / sqrt(age)`:
- `reliability` = successes / (successes + failures), defaulting to 0.5 for new entries (0 successes, 0 failures)
- `age` = max(1, hours since last-seen)
- Peers with recent successful connections and high success rates score highest

### Capacity and Eviction
- Maximum 2000 entries. When full, evict the entry with the lowest score before inserting a new one.
- On addr message receipt, only insert addresses with plausible timestamps (within last 3 hours, per Bitcoin Core behavior).

### Warm Start Logic
On `start-node`:
1. Attempt to load `peers.dat` from data directory
2. If loaded, sort entries by score descending
3. Try top-scored peers first in `connect-to-peers`
4. Fall back to DNS seeds only if address book has fewer than 8 candidates

On `stop-node`:
1. Save address book to `peers.dat` (atomic write)

### Connection Tracking
- On successful handshake: increment success count, update last-seen
- On connection failure or timeout: increment failure count, update last-attempt
- On receiving addr message: add/update entries in address book

## Risks / Trade-offs
- Fixed entry size wastes bytes for IPv4 (padded to 16) — acceptable for simplicity
- No encryption of peers.dat — peer addresses are public network data, not sensitive
- Single flat file won't scale past tens of thousands of peers — 2000 cap keeps it simple
- CRC32 detects corruption but not tampering — acceptable for peer addresses

## Open Questions
- None — design is straightforward and follows established patterns in the codebase
