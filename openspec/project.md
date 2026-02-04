# Project Context

## Purpose
A Bitcoin full node implementation in Common Lisp. The goal is to create a fully validating node capable of connecting to the Bitcoin network, downloading and validating the blockchain, and maintaining an accurate UTXO set.

## Tech Stack
- Common Lisp (SBCL)
- ironclad - cryptographic hash functions
- cffi - foreign function interface for libsecp256k1
- usocket / sb-bsd-sockets - network I/O
- fiveam - testing framework

## Project Conventions

### Code Style
- Use lowercase with hyphens for naming (lisp-style)
- Prefer `defstruct` for data types, `defclass` only when polymorphism needed
- Document exported functions with docstrings
- Keep functions focused and small

### Architecture Patterns
- Layered architecture: crypto -> serialization -> storage/validation -> networking
- Pure functions where possible, explicit state management
- Conditions and restarts for error handling

### Testing Strategy
- Unit tests for all crypto and serialization functions
- Use Bitcoin Core test vectors for validation
- Integration tests with testnet

### Git Workflow
- Feature branches for new capabilities
- Commits should be atomic and well-described

## Domain Context
- Bitcoin protocol: P2P network protocol, consensus rules, script language
- Testnet: Bitcoin test network with worthless coins for development
- UTXO model: Unspent Transaction Output - Bitcoin's accounting model
- Proof of Work: SHA256d-based mining, difficulty adjustment

## Important Constraints
- Consensus-critical code must match Bitcoin Core behavior exactly
- No wallet functionality in initial scope
- Transaction relay disabled by default on mainnet for safety

## Supported Networks
- **Testnet** (default): Test network for development, default port 18333, RPC 18332
- **Mainnet**: Production Bitcoin network, default port 8333, RPC 8332
  - Requires ~600GB+ storage for full blockchain
  - Transaction relay disabled by default (set `*mainnet-relay-enabled*` to enable)

## External Dependencies
- libsecp256k1: System library required for ECDSA operations
- Bitcoin network: Testnet or mainnet for synchronization
