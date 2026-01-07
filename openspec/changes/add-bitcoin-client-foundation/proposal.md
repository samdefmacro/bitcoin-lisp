# Change: Add Bitcoin Client Foundation

## Why

This project aims to implement a Bitcoin full node in Common Lisp (SBCL). A foundational architecture is needed to establish the core capabilities that all other features will build upon. Starting with testnet allows safe development and testing without risking real funds.

## What Changes

- **NEW** `serialization` capability: Bitcoin protocol data structure encoding/decoding
- **NEW** `crypto` capability: Cryptographic primitives (SHA256, RIPEMD160, secp256k1)
- **NEW** `networking` capability: P2P protocol message handling and peer connections
- **NEW** `storage` capability: Persistent storage for blocks, UTXO set, and chain state
- **NEW** `validation` capability: Transaction and block validation against consensus rules

## Impact

- Affected specs: All new capabilities (no existing specs)
- Affected code: Greenfield implementation
- Target: SBCL on testnet
- Dependencies: Requires external libraries for cryptographic primitives (secp256k1)

## Scope

This proposal establishes the **minimal viable foundation** for a Bitcoin full node:

1. Parse and serialize all Bitcoin protocol data types
2. Connect to testnet peers and exchange messages
3. Download and validate the blockchain
4. Maintain UTXO set for transaction validation

Out of scope for this proposal:
- Wallet functionality (key management, transaction creation)
- Mining
- RPC interface
- Mainnet support (testnet only initially)
