# Design: Add Mainnet Support

## Context

The bitcoin-lisp node currently operates exclusively on testnet. The project constraint "Testnet only initially (no mainnet)" indicates mainnet was always a planned future capability. Most network-specific parameters are already defined (magic bytes, ports, DNS seeds, address versions), but several components hardcode testnet assumptions.

### Current State

| Component | Testnet | Mainnet |
|-----------|---------|---------|
| Magic bytes | Defined | Defined |
| Port | Defined (18333) | Defined (8333) |
| DNS seeds | Defined | Defined |
| Address versions | Defined | Defined |
| Checkpoints | Defined | **Missing** |
| Genesis hash | Defined | **Missing** |
| BIP 34 height | Used (hardcoded) | Defined but unused |
| RPC port | Hardcoded 18332 | **Missing** (should be 8332) |

## Goals / Non-Goals

### Goals

- Enable full validation of the mainnet blockchain
- Maintain complete backward compatibility with testnet operation
- Ensure network-specific data is properly isolated
- Provide clear user feedback about which network is active
- Safe defaults for mainnet operation

### Non-Goals

- Wallet functionality (explicitly out of scope per project.md)
- Mining or block creation
- Performance optimization for mainnet scale (separate concern)
- Regtest/signet support (future work)

## Decisions

### Decision 1: Separate checkpoint variables (not consolidated)

Keep `*testnet-checkpoints*` and add `*mainnet-checkpoints*` as separate variables. Update accessor functions to dispatch on `*network*`.

```lisp
(defun get-checkpoint-hash (height)
  (let ((checkpoints (ecase bitcoin-lisp:*network*
                       (:testnet *testnet-checkpoints*)
                       (:mainnet *mainnet-checkpoints*))))
    ...))
```

**Rationale**: Minimal change to existing code. Follows established pattern in `network-magic`, `network-port`, etc.

**Alternative rejected**: Consolidated `*checkpoints*` alist - requires more refactoring for marginal benefit.

### Decision 2: Backward-compatible data directories

- Testnet: `~/.bitcoin-lisp/` (unchanged, backward compatible)
- Mainnet: `~/.bitcoin-lisp/mainnet/`

**Rationale**: Existing testnet users don't need to migrate data. Mainnet is new, so subdirectory is acceptable.

### Decision 3: Transaction relay disabled on mainnet

Add `*mainnet-relay-enabled*` flag, default `nil`. When mainnet and relay disabled:
- Node validates and stores blocks
- Node does NOT relay transactions to peers
- Logged at startup

**Rationale**: Safety. A validation bug could cause relay of invalid transactions to production network. Can be enabled later after confidence is established.

### Decision 4: Default RPC port by network

- Testnet: 18332 (current default)
- Mainnet: 8332 (Bitcoin Core standard)

**Rationale**: Matches Bitcoin Core conventions, allows running both networks simultaneously.

### Decision 5: No automatic mainnet activation

Users must explicitly specify `:network :mainnet`. Default remains `:testnet`.

**Rationale**: Safety. Mainnet operations should be intentional.

## Mainnet Parameters

### Genesis Block

**Hash (little-endian, wire format):**
```
6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000
```

**Hash (big-endian, display format):**
```
000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
```

Source: [Bitcoin Core chainparams.cpp](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp)

### Checkpoints

Verified against Bitcoin Core source. Note: Bitcoin Core stopped adding traditional checkpoints after height 295000 (2014), using assumevalid instead. We include historical checkpoints plus halving blocks.

| Height | Hash (display format) | Notes |
|--------|----------------------|-------|
| 11111 | `0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d` | Early checkpoint |
| 33333 | `000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6` | |
| 74000 | `0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20` | |
| 105000 | `00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97` | |
| 134444 | `00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe` | |
| 168000 | `000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763` | |
| 193000 | `000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317` | |
| 210000 | `000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e` | First halving |
| 250000 | `000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214` | |
| 295000 | `00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983` | Last Core checkpoint |
| 420000 | `000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74f112` | Second halving |
| 630000 | `000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d` | Third halving |
| 840000 | `0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5` | Fourth halving |

### BIP Activation Heights

| BIP | Testnet | Mainnet | Notes |
|-----|---------|---------|-------|
| BIP 34 (coinbase height) | 21111 | 227931 | Height-gated in validation |
| BIP 66 (strict DER) | 330776 | 363725 | Always enforced in script |
| BIP 65 (CLTV) | 581885 | 388381 | Always enforced in script |
| BIP 112 (CSV) | 770112 | 419328 | Always enforced in script |
| BIP 141 (SegWit) | 834624 | 481824 | Always enforced in script |

Note: BIP 66/65/112/141 are always enforced in our script interpreter regardless of height. Only BIP 34 requires height-gated logic.

## Risks / Trade-offs

### Risk: Consensus divergence on mainnet

A validation bug that passed on testnet could cause mainnet chain rejection.

**Mitigation**:
- Verified checkpoints from Bitcoin Core source
- Transaction relay disabled by default
- Test against known mainnet blocks before full IBD

### Risk: Resource exhaustion

Mainnet blockchain is ~600GB+ and growing.

**Mitigation**:
- Document storage requirements clearly
- Progress reporting during IBD

### Trade-off: Backward compatibility vs. clean structure

Keeping testnet at root (`~/.bitcoin-lisp/`) is slightly inconsistent but avoids migration complexity.

**Decision**: Backward compatibility wins. Testnet stays at root.

## Migration Plan

1. Implement mainnet parameters (genesis, checkpoints)
2. Update network-aware accessor functions
3. Add mainnet data directory path
4. Add RPC port selection
5. Add relay control flag
6. Add tests
7. Update documentation
8. Update project.md constraint

### Rollback

Remove `*mainnet-checkpoints*` and `*mainnet-genesis-hash*`. Revert accessor functions. No data migration needed.

## Resolved Questions

1. **Transaction relay on mainnet?** → Disabled by default for safety
2. **Regtest/signet support?** → Out of scope, future work
3. **Checkpoint list?** → Historical Core checkpoints + halving blocks
4. **Data directory structure?** → Testnet at root (backward compatible), mainnet in subdirectory
