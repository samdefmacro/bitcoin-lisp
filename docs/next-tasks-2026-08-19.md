# Task list — 2026-08-19

Built from three sources: the GA8 Wave 8 backlog (= the 53 remaining GA7 items in
`memory/ga7_synthesis.json`), the deliberate deferrals recorded during the GA9 S2
wave, and the standing small-items list.

## 0. GA8 Wave 8 triage — is it already fixed?

The `bl-ga8w8` worktree is untouched (zero diff vs `main`), so nothing was done
there. But a large share of Wave 8 was fixed *incidentally* by later waves —
GA8 waves 4-7, the wallet P6 phase, the eclipse P3 thread, and the GA9 S1/S2
waves. Verified against the tree at `0b39885`:

### Already fixed — do not redo (19)

| Item | Evidence in tree |
|---|---|
| G7-04 wallet auto-load / `load_on_startup` | `src/rpc/wallet.lisp:1145-1250` (settings.json) |
| G7-05 txindex startup catch-up | PR #356, `src/node.lisp` catch-up call |
| G7-07 wallet encryption + backup | wallet P6 (2026-08-17) |
| G7-08 outbound eclipse resistance | PR #348 |
| G7-12 `AreInputsStandard` prevout gate | `src/validation/transaction.lisp:888` |
| G7-13 bare P2PK standard | `classify-output-script` → `:pubkey` |
| G7-14 P2A classification | `pay-to-anchor-p` in the same solver |
| G7-15 BIP133 feefilter | `peer.lisp:55-59` `next-send-feefilter` |
| G7-16 BIP152 high-bandwidth mode | `peer.lisp:194-195`, `ibd.lisp:1717` |
| G7-17 named RPC arguments | `rpc/server.lisp:260` |
| G7-18 sub-minchainwork disconnect | `ibd.lisp:2558-2589` |
| G7-19 self-connection nonce | `peer.lisp:978-991` |
| G7-20 getaddr response cache | `protocol.lisp:2182` (21h, Core's) |
| G7-24 taproot script-path descriptors | `rpc/descriptors.lisp:487` multi_a |
| G7-35 subversion cap + sanitize | `config.lisp:533-1000` |
| G7-36 disconnectpool cap | `validation/block.lisp:21` `trim-disconnect-pool` |
| G7-45 long-polling RPCs | `rpc/server.lisp:140-142` |
| G7-49 stalling-peer response | `ibd.lisp:15-87` near-tip margin |
| G7-33 `-rpcallowip` | **mitigated, not implemented**: non-loopback `-rpcbind` is refused outright (`rpc/server.lisp:781-789`), so there is no exposure — it is a missing *feature*, not a hole |

### Still open (34)

S2: G7-06, G7-09, G7-10 (partial), G7-11, G7-21, G7-22, G7-23, G7-25, G7-26.
S3: G7-27, G7-28 (partial), G7-29, G7-30, G7-31, G7-32 (partial), G7-34, G7-37,
G7-38, G7-39, G7-40, G7-41, G7-42, G7-43, G7-44 (partial), G7-46, G7-47, G7-48,
G7-50, G7-51, G7-52, G7-53, G7-55, G7-56, G7-57, G7-58, G7-59, G7-60 (partial),
G7-61, G7-62..69 (8 test-vector corpora).

## 1. The executable list (this session, in order)

1. **G7-09 — enforce `maxfeerate` / `maxburnamount`.** `rpc-sendrawtransaction`
   reads only `(first params)`; `rpc-submitpackage`'s own docstring says the
   rails "are accepted for API compatibility but not enforced". A fat-finger fee
   is broadcast with no guard. Core rejects above `DEFAULT_MAX_RAW_TX_FEE_RATE`.
2. **G7-61 — header index dirty-entry writes.** `save-header-index` maphashes the
   whole `block-index` every flush; that is ~963k entries on the live mainnet
   node, per flush.
3. **G7-30 — debug log management.** No rotation, no `ShrinkDebugFile`, no SIGHUP
   reopen: the live nodes' logs grow without bound.
4. **G7-06 — corrupt header index must not start silently empty.**
5. **G7-29 — datadir `.lock`.** Two nodes on one datadir is silent corruption.
6. **G7-31 — `-maxmempool`.**
7. **G7-57 — `-blockmaxweight` / `-blockreservedweight`.**
8. **G7-62..69 — adopt the 8 missing test-vector corpora** (`tests/data/` holds
   only `taproot_spend_vectors.json` today).

## 2. Tracked, deliberately not in this list

Large features, each its own thread: G7-21 fee estimator port
(`CBlockPolicyEstimator`), G7-23 ZMQ, G7-41 miniscript, G7-11 ephemeral dust.

From the GA9 S2 wave (documented in code at the deferral sites):
- maintain `m_best_header` incrementally → unlocks S2-3's three omitted Core
  conditions *and* removes an O(index) scan;
- `%rollback-partial-reorg` → real disconnect, unblocking S2-10 phase B;
- move the inbound handshake off the accept thread (S2-9).

Plus: GA9's ~43 S3s (never verification-passed), Sparrow acceptance (wallet P7),
the mainnet wallet enablement decision.
