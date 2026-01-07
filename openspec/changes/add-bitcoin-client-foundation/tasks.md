# Tasks: Bitcoin Client Foundation

Implementation checklist for the foundational Bitcoin client architecture.

## 0. Project Setup
- [x] 0.1 Create ASDF system definition (`bitcoin-lisp.asd`)
- [x] 0.2 Set up package structure (`src/package.lisp`)
- [x] 0.3 Configure dependencies (quicklisp: ironclad, cffi, usocket)
- [x] 0.4 Set up test framework (fiveam)
- [x] 0.5 Create basic project structure (directories per design.md)

## 1. Crypto Capability
*Dependency: Project setup*

- [x] 1.1 Implement SHA-256 wrapper using ironclad
- [x] 1.2 Implement double-SHA256 (Hash256)
- [x] 1.3 Implement RIPEMD-160 wrapper
- [x] 1.4 Implement Hash160 (RIPEMD160(SHA256(x)))
- [x] 1.5 Set up CFFI bindings for libsecp256k1
- [x] 1.6 Implement public key parsing and validation
- [x] 1.7 Implement ECDSA signature verification
- [x] 1.8 Write tests for all crypto functions with known test vectors

## 2. Serialization Capability
*Dependency: Crypto (for hashing)*

- [x] 2.1 Implement binary read/write primitives (uint8, uint16, uint32, uint64)
- [x] 2.2 Implement CompactSize encoding/decoding
- [x] 2.3 Implement variable-length byte vector serialization
- [x] 2.4 Define transaction structures (TxIn, TxOut, Transaction)
- [x] 2.5 Implement transaction serialization/deserialization
- [x] 2.6 Define block structures (BlockHeader, Block)
- [x] 2.7 Implement block serialization/deserialization
- [x] 2.8 Implement script serialization
- [x] 2.9 Define P2P message structures
- [x] 2.10 Implement P2P message header serialization (magic, command, length, checksum)
- [x] 2.11 Implement version message serialization
- [x] 2.12 Implement common message types (verack, inv, getdata, block, tx, addr, getblocks, getheaders)
- [x] 2.13 Write tests using real Bitcoin transaction/block test vectors

## 3. Storage Capability
*Dependency: Serialization*

- [x] 3.1 Design storage directory structure
- [x] 3.2 Implement block file storage (write/read blocks to disk)
- [x] 3.3 Implement block index (hash -> location mapping)
- [x] 3.4 Implement UTXO set data structure
- [x] 3.5 Implement UTXO add/remove/query operations
- [x] 3.6 Implement chain state tracking (best block, height, chainwork)
- [x] 3.7 Implement state persistence (save/load on shutdown/startup)
- [ ] 3.8 Write tests for storage operations

## 4. Validation Capability
*Dependency: Crypto, Serialization, Storage*

- [x] 4.1 Implement transaction structure validation
- [x] 4.2 Implement basic script interpreter framework
- [x] 4.3 Implement stack operations (DUP, DROP, SWAP, ROT, etc.)
- [x] 4.4 Implement crypto opcodes (HASH160, HASH256, CHECKSIG)
- [x] 4.5 Implement comparison/arithmetic opcodes
- [x] 4.6 Implement flow control (IF, ELSE, ENDIF, VERIFY)
- [x] 4.7 Implement P2PKH script validation
- [x] 4.8 Implement block header validation (PoW, timestamp, version)
- [x] 4.9 Implement merkle root calculation and validation
- [x] 4.10 Implement full block validation
- [x] 4.11 Implement contextual validation (UTXO checks, double-spend prevention)
- [x] 4.12 Implement coinbase maturity checks
- [x] 4.13 Implement chain selection (most work)
- [x] 4.14 Implement chain reorganization logic
- [ ] 4.15 Write comprehensive validation tests with known valid/invalid blocks

## 5. Networking Capability
*Dependency: Serialization, Validation, Storage*

- [x] 5.1 Implement TCP connection management using sb-bsd-sockets
- [x] 5.2 Implement peer state machine (connecting, handshaking, connected, disconnected)
- [x] 5.3 Implement version handshake protocol
- [x] 5.4 Implement message send queue
- [x] 5.5 Implement message receive and dispatch
- [x] 5.6 Implement DNS seed query for peer discovery
- [x] 5.7 Implement peer address management
- [x] 5.8 Implement ping/pong for connection health
- [x] 5.9 Implement inv/getdata request/response flow
- [x] 5.10 Implement block download (getblocks, getheaders, getdata)
- [x] 5.11 Implement initial block download (IBD) coordination
- [ ] 5.12 Write integration tests with testnet

## 6. Integration
*Dependency: All above*

- [ ] 6.1 Create main node entry point
- [ ] 6.2 Implement startup sequence (load state, connect to peers)
- [ ] 6.3 Implement shutdown sequence (save state, disconnect peers)
- [ ] 6.4 Implement basic logging
- [ ] 6.5 Test full IBD on testnet (sync at least 1000 blocks)
- [ ] 6.6 Document usage and configuration

## Notes

- Tasks within each section can often be parallelized
- Each task should have corresponding tests before moving to the next
- Use Bitcoin Core's test vectors where available
- Focus on correctness over performance in this foundation phase
