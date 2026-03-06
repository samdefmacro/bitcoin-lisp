# Change: Add Persistent Peer Database

## Why
The node currently discovers peers only through DNS seeds at startup and discards all learned peer information on shutdown. This means every restart incurs slow DNS lookups, wastes seed bandwidth, and loses knowledge about which peers are reliable. A persistent peer database enables warm starts and informed peer selection.

## What Changes
- **Peer address book**: In-memory address book (`defstruct address-book`) holding up to 2000 peer entries with IP, port, services, timestamps, and success/failure counters
- **Persistence**: `peers.dat` binary file using the same atomic-write pattern as `utxo.dat` (write to `.tmp`, rename), with CRC32 integrity check reusing `compute-crc32` from `src/storage/utxo.lisp`
- **Reputation scoring**: Peer selection weighted by `reliability / sqrt(age)` where reliability = successes / (successes + failures) and age = hours since last seen
- **Warm starts**: On startup, load `peers.dat` and attempt known-good peers before falling back to DNS seeds
- **Addr message integration**: `handle-addr` in `src/networking/protocol.lisp` now feeds parsed addresses into the address book instead of discarding them
- **Lifecycle hooks**: `start-node` loads the peer database; `stop-node` saves it; connection success/failure updates the address book

## Impact
- Affected specs: networking (MODIFIED Peer Discovery, ADDED Peer Address Persistence, ADDED Peer Reputation Tracking)
- Affected code: `src/networking/protocol.lisp` (handle-addr), `src/node.lisp` (lifecycle, peer selection), new `src/networking/peerdb.lisp`, `src/package.lisp`, `bitcoin-lisp.asd`
