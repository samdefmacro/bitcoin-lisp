# GA12 backlog audit — the GA11 "left out" items, re-verified

Date: 2026-09-23. Base: `main` @ `2a7074c4`. Oracle: Bitcoin Core @ `d3056bc`
(`refs/bitcoin`), except where noted (Erlay: BIP-330; the wallet dump: our own
format, since Core has no dump reader).

`docs/gap-analysis-11.md`, section "Left out, deliberately, for GA12 — closed
2026-09-09", says every item on its list was closed by a named commit. This audit
checked each claim against the code instead of the list: it found the closing
commit with `git log --grep`, read the change and the current source, compared it
with Core, and ran the test that pins it in the warm image. It then took the smaller
leftovers that were never claimed closed. The method is the one earlier rounds
learned the hard way: verify before fixing, because the list has been wrong in both
directions before.

**Result:** every claimed closure holds in the code, and every pinning test passes
warm. Four claims or leftovers were not quite true. Each got a fix, or for the
removeprunedfunds item a pin test, with a pre-fix-red test:

- `%input-sig-witness-p` (now `bl.rpc:input-sig-witness-p`) still left out a kind.
  GA11 added `:p2tr-script` and the two miniscript kinds, but not `:anchor`, so any
  process-PSBT call over a pay-to-anchor input failed with a case error.
- The wallet-dump streaming closure capped the number of lines, not the length of a
  line. A source with no newline was still read into memory whole.
- `-rpcworkqueue` was accepted and ignored, and `-rpcthreads` did not follow Core's
  `max(atoi, 1)` rule.
- `removeprunedfunds` had been unified onto `parse-hash-v` in the GA11 round, but no
  test pinned it.

## The claimed closures

| # | Item | Closing commit | Pinning test(s), warm result | Holds? |
|---|------|----------------|------------------------------|--------|
| 1 | RPC arity check (`IsValidNumArgs`, -1 with the help text) | `d96d87b1` RPC: a call with the wrong number of arguments is refused with the usage line | `rpc-call-with-the-wrong-number-of-arguments-is-the-help-text` 11/0; `every-rpc-method-has-a-core-argument-row` 6/0 | Yes. `check-rpc-arg-count` (src/rpc/server.lisp) runs Core's rule (rpc/util.cpp:733-743) before the type gate. It answers -1 with the whole help document (util.cpp:644, server.cpp:514-515). |
| 2 | `IsCurrentForFeeEstimation`'s third arm + cached best header | `fe6e9544` Storage: the best header is kept, and fee estimation asks it | `fee-estimation-is-not-current-while-headers-run-two-ahead` 5/0; `best-header-follows-the-most-work-valid-entry` 9/0; `best-header-is-shared-by-every-chainstate-on-one-index` 2/0 | Yes. `current-for-fee-estimation-p` implements all three arms of validation.cpp:280-292 on the mockable clock. `best-header-entry` is O(1) and recalculates when the cached entry has become `:invalid`. InvalidChainFound marks the whole subtree `:invalid`, so the recalculation also covers Core's validation.cpp:1968-1969. One stale comment in reconsiderblock said Core does not recalculate. At the pin it does (rpc/blockchain.cpp:1749-1750). The comment is fixed in `6a90451b`. The code already matched Core. |
| 3 | `UNKNOWN_NEW_RULES_ACTIVATED` warning | `62108c72` Validation: an unknown soft fork activating on our chain is a warning | `unknown-new-rules-warning-reaches-the-rpc-array` 3/0; `unknown-version-bits-walk-their-own-bip9-window` 7/0; `unknown-version-bits-below-the-warning-height-say-nothing` 2/0 | Yes. The `warn-unknown-new-rules` hook (src/node/notify.lisp) matches validation.cpp:2899-2911: it runs outside IBD, warns on ACTIVE bits, only logs LOCKED_IN bits, and never unsets the warning. |
| 4a | Erlay: a full set falls back to flooding (`recon-set-add` cap) | `f511c4f6` Erlay: a full reconciliation set falls back to flooding | `a-full-reconciliation-set-falls-back-to-flooding` 6/0 | Yes. `recon-set-add` returns NIL at `+recon-max-set-size+`, and the relay path then uses the ordinary inventory queue. |
| 4b | Erlay: `recon-set-remove` has a caller | `533a4930` Erlay: a transaction the peer is known to hold leaves its reconciliation set | `a-transaction-we-announce-leaves-the-peers-reconciliation-set` 3/0; `a-transaction-the-peer-announces-to-us-leaves-its-set` 2/0 | Yes. `%mark-tx-known-to-peer` is its only caller in src/. |
| 4c | Erlay: responder failure path | `6333759b` Erlay: a failed round floods the snapshot on both sides, and a zero sketch is a success | `a-failed-round-makes-the-responder-flood-its-snapshot` 5/0; `a-failed-extension-makes-the-initiator-report-and-flood` 15/0; `a-malformed-sketch-ends-the-round-for-both-sides` 4/0; `identical-sets-reconcile-to-nothing-and-succeed` 6/0 | Yes. On a failed reconcildiff, `%handle-reconcildiff` floods `recon-flood-snapshot`. On a success it retires the whole snapshot. The oracle is BIP-330, because Core d3056bc has only the handshake. |
| 5 | `ms-produce-input` simple-vectors | `37593cbd` Miniscript: the satisfier's SATS tables are simple-vectors | `satisfier-dynamic-programs-keep-their-bytes-on-vectors` 7/0 | Yes. The multi, multi_a and thresh programs share `%ms-dp-step` over simple-vectors, and no `nth` is left in `%ms-produce-input-up`. `ms-node-to-string` is still quadratic, as Core's `ToString` is. That was deliberate. |
| 6a | `%parse-wallet-dump` streaming | `995f35c7` Wallet: restorewallet reads its dump as a stream of lines | `wenc-restore-rejects-each-malformed-dump` 34/0; `wenc-restore-refuses-a-dump-over-the-line-cap` 2/0; `wenc-restore-does-not-buffer-the-whole-dump` 4/0 | **Partly.** The dump is streamed and the line COUNT is capped. But the cap counts newlines, so a source with none (`/dev/zero`, the character device the cap's own docstring names, or any big file without a line break) was one line, and its buffer grew until the image died. Fixed in `d9c91a88` (below). |
| 6b | `%wser-string` UTF-8 | `da3c7b27` Wallet: CWalletTx mapValue strings are Core's UTF-8 bytes on disk | `wallet-tx-map-value-holds-cores-utf-8-bytes` 7/0 | Yes. `%wser-string` and `%wser-string-into` write `utf8-string-to-bytes`. `%wread-string` decodes UTF-8 and replaces invalid sequences, and no ASCII codec is left in wallet-store.lisp. |
| 7a | `ban-peer` has no production caller | `b1198c03` Net: a ban is an address fact set by setban, and no peer is ever "banned" | covered by the edited eclipse/compact-block/package-relay suites (no new test; the function was deleted) | Yes. `ban-peer` no longer exists anywhere in src/, and bans are address facts set by `setban`. |
| 7b | addnode peers typed `:manual` | `a854e89b` Net: an operator-named peer is a :manual connection, not a flagged outbound one | `a-named-destination-is-dialed-as-a-manual-connection` 5/0; `manual-peers-count-as-a-path-to-their-network` 4/0; `a-manual-peer-occupies-a-netgroup-in-the-diversity-set` 3/0; `manual-peers-leave-the-full-relay-slots-to-fill` 1/0; `whitelist-ranges-reach-an-outbound-peer-only-when-it-is-manual` 4/0 | Yes. Every addnode and connect dial passes `:conn-type :manual` (src/node/peers.lisp), and the chain-sync eviction set excludes `:manual` (src/networking/peer.lisp). |
| 8a | `-signetchallenge` given twice | `e77bae0b` Config: a second -signetchallenge is an init error, in Core's words | `a-second-signetchallenge-is-an-init-error-in-cores-words` 11/0 | Yes. The error text is Core's own (chainparams.cpp:34, :38). |
| 8b | `-conf` naming a directory | `5cbce712` Config: a directory at the config path is refused in Core's words | `a-config-file-that-is-a-directory-is-fatal-in-cores-words` 6/0 | Yes. The text is Core's `Config file "..." is a directory.` (common/config.cpp:135). The includeconf variant (:187) is also present. |
| 9 | `signrawtransactionwithkey` malformed `prevtxs` | `77f07ec2` RPC: a malformed prevtxs entry is refused in Core's words | `signrawtransactionwithkey-refuses-a-malformed-prevtxs-entry-in-cores-words` 19/0; `signrawtransactionwithwallet-refuses-a-malformed-prevtxs-entry-in-cores-words` 5/0 | Yes. |
| 10 | Taproot script path from `witness_utxo` alone | `ebd33438` Wallet: a taproot script path signs from the witness_utxo alone, as any witness kind does | `walletprocesspsbt-signs-a-tr-script-path-from-the-witness-utxo-alone` 3/0; `descriptorprocesspsbt-refuses-a-legacy-signature-over-the-witness-utxo-alone` 3/0; `input-sig-witness-p-answers-for-every-kind` 15/0 | **Partly.** The claimed kinds are fixed, but the "every kind" test listed the kinds by hand and missed `:anchor`. The ECASE therefore signalled on any P2A input. Fixed in `040e1553` (below). |
| 11 | `decodescript` `rawtr()` | `6f60c6c5` Descriptors: InferScript answers pk(), multi() and rawtr() before addr() (GA11 finding `8f138c13`) | `infer-descriptor-answers-cores-typed-descriptors-before-addr` 7/0 | Yes. |
| 12 | `wallet-set-address-book` | none (the claim is "no change needed") | none | Yes. Core's `SetAddressBookWithDB` (wallet/wallet.cpp:2480-2507) updates the in-memory book, then writes the purpose record (only when a purpose is given) and then the name. `wallet-set-address-book` (src/wallet/wallet.lisp) does the same. No test pins the order. |

## The smaller leftovers (never claimed closed)

| Item | Finding | Commit / test |
|------|---------|---------------|
| `removeprunedfunds` parses its txid with a wallet-local helper | Already closed. `e2229cd9` (RPC: the rpc-args and wallet-rpc batches agree on the hash parser and the amount token) moved it onto `bl.rpc:parse-hash-v`, Core's `ParseHashV(request.params[0], "txid")` (wallet/rpc/backup.cpp:115, rpc/util.cpp:117-125). Nothing pinned it. | `e10152f8` tests: removeprunedfunds names a malformed txid in ParseHashV's words. `pruned-funds-import-and-remove` asserts both -8 sentences, 24/0. This is a pin: the test passes on the current code and is not a fix. |
| `%input-sig-witness-p` omits `:p2tr-script` / `:p2wsh-miniscript` / `:p2sh-p2wsh-miniscript` | Those three were closed by `ebd33438`. **`:anchor` was still missing**, and the ECASE signalled `:ANCHOR fell through ECASE expression` for any descriptorprocesspsbt or walletprocesspsbt call over a P2A input. Core's SignStep answers ANCHOR with an empty solution (script/sign.cpp:706-707). No witness branch (:757-789) names ANCHOR, so `sigdata.witness` stays false and SignPSBTInput answers INCOMPLETE (psbt.cpp:488). | `040e1553` PSBT: a pay-to-anchor input is a non-witness signature, not a case failure. `input-sig-witness-p-covers-every-kind-the-signer-builds` reads every `:kind` out of the signer's source, so a new kind cannot be missed again, and it drives a P2A input end to end. Pre-fix 17/3, fixed 21/0. |
| blockfilterindex startup rewind (CustomRemove keeps abandoned filters) | Confirmed. `81a7fc5d` (Index: the filter index rewinds an off-chain marker at start-up). `%rewind-blockfilterindex` (src/node/indexes.lisp) moves an off-chain marker back to the fork point. It erases nothing, because our records are keyed only by hash. That matches CustomRemove, which copies the height index to the hash index (index/blockfilterindex.cpp:277-297). The online disconnect hook is the default no-op, which also keeps the filters. | `blockfilterindex-rewinds-a-marker-left-on-an-abandoned-branch` 17/0. It asserts that the abandoned branch's filters survive and that the active branch chains off the fork header. |
| `-rpcthreads` / `-rpcworkqueue` semantics vs Core | **Open, now fixed.** Core reads both as `std::max(GetArg(name, DEFAULT), 1)` with defaults 16 and 64 (httpserver.cpp:419, :440; httpserver.h:20, :26). When `WorkQueueSize() >= depth` it answers 503 `Work queue depth exceeded` (httpserver.cpp:255-258). interface_rpc.py:229-240 tests this. Ours accepted and ignored `-rpcworkqueue`, so no request was ever refused and that test's loop could never end. Ours also made `-rpcthreads=0` an init error (Core starts with 1) and left `-rpcthreads` unbounded by default. | `5358693a` RPC: -rpcworkqueue refuses the request past its depth, and both HTTP pool knobs are Core's max(atoi, 1). `rpcworkqueue-refuses-a-request-once-that-many-are-waiting`: pre-fix 3/3, fixed 6/0. `rpcthreads-and-rpcworkqueue-are-at-least-one-never-an-error`: pre-fix 4/8, fixed 12/0. |
| Wallet dump: the line-count cap does not bound a line | New, found while verifying item 6a. | `d9c91a88` Wallet: a restore source with no newline is refused, not buffered whole. It adds `*wallet-dump-max-line-bytes*`, 64 MiB. `wenc-restore-refuses-a-line-over-the-byte-cap`: pre-fix 2/1 (128 MiB consed for a 16 MiB file), fixed 3/0. |
| "What the round cost, and what it taught" follow-ups | That section names no open follow-up. Its guards (the `::` corpus from ASDF, `dev.sh test` quoting, `check-wrong-arity-calls.sh`, the self-delegating-fixture check) are in the tree. | none |

## Decisions for the coordinator

- `-rpcthreads` now defaults to Core's 16 instead of unbounded. Before this, the
  default was a deliberate choice of ours, documented in `*rpc-threads*`. Core's
  value is the spec, and the functional framework writes `rpcthreads=2` anyway. On a
  live node, though, more than 16 slow RPCs at once, such as long-polls, now queue
  (64 deep) and then get 503, where before they all ran. Setting `rpcthreads` in the
  node's bitcoin.conf restores any other bound.

## Still open from GA11

- **The differential encode/decode harness against `bitcoin-tx` / `bitcoin-util`**
  (GA11 "Harness lanes"). It is still blocked here because no Core binary can be built
  in this environment. It is **owned by batch AI**, which is fetching Core's release
  binaries to run it. Nothing in this audit depends on it.
