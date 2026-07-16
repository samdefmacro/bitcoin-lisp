A Bitcoin full node implementation in Common Lisp (SBCL).

Tech stack: ironclad (crypto), cffi + libsecp256k1 (ECDSA), usocket (networking), fiveam (tests).

Architecture: layered (crypto -> serialization -> storage/validation -> networking).
Use defstruct for data types, pure functions where possible, conditions/restarts for errors.
Consensus-critical code must match Bitcoin Core behavior exactly.

Reference implementation: refs/bitcoin/ (cloned Bitcoin Core repo) is the canonical spec.
When implementing consensus rules, read the corresponding Bitcoin Core source code directly.

Supported networks:
- Testnet (default): port 18333, RPC 18332
- Mainnet: port 8333, RPC 8332, relay disabled by default

Wallet: descriptor-only wallet in progress per docs/wallet-plan.md (no BDB/legacy
wallets, no BIP39). Wallet support is enabled by default on test networks,
default-OFF on mainnet (config flag `-wallet`); testnet4 first.
