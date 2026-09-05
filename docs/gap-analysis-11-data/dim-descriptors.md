# GA11 dimension 1 — descriptors + signing: coverage note

Oracle: Bitcoin Core @ `d3056bc` (`refs/bitcoin/`). Method: `docs/gap-analysis-method.md`.
Findings: `dim-descriptors.json` (7: four S2, three S3). Survey only — no `src/` or `tests/` change.

## What was read, side by side

| Core | ours |
|---|---|
| `script/descriptor.cpp` — `Parse`, `ParsePubkey`, `ParsePubkeyInner`, `ParseKeyPath`, `ParseKeyPathNum`, `ParseDeriveType`, `ParseScript`, `BIP32PubkeyProvider::GetPubKey`, `MuSigPubkeyProvider`, `InferScript`, `InferPubkey`, `InferXOnlyPubkey`, `CheckChecksum`, `DescriptorChecksum` | `src/rpc/descriptors.lisp` (all 2136 lines) |
| `script/solver.cpp` (whole file) | `src/validation/solver.lisp` (whole file) |
| `script/sign.cpp` — `SignStep`, `CreateSig`, the taproot key/script arms | `src/rpc/rawtransaction.lisp:280-600` (`compute-input-signatures` + helpers) |
| `script/signingprovider.cpp` `TaprootBuilder::Combine` | `%tap-combine` / `%taproot-tree` / `%taproot-control-block` |
| `key_io.cpp` `DecodeDestination` / `DecodeSecret` / `DecodeExtKey` | `src/crypto/address.lisp`, `src/crypto/bip32.lisp` |
| `rpc/util.cpp` `ParseRange` / `ParseDescriptorRange` / `EvalDescriptorStringOrObject`, `rpc/output_script.cpp`, `core_io.cpp:415` | `parse-descriptor-range`, `descriptor-scanobject-scripts`, `getdescriptorinfo`, `deriveaddresses`, `scriptpubkey-desc` |
| — | `src/wallet/wallet-spend.lisp:395-620,1719-1900`, `src/wallet/psbt.lisp` signer half, `src/wallet/wallet-coins.lisp:128-190`, `src/validation/transaction.lisp:620-730` |

## What was run

Everything below ran in the project container (`scripts/dev.sh eval`, warm image, `bitcoin-lisp`
and `bitcoin-lisp/tests` loaded) in the `fix/ga11-descriptors` worktree.

1. **Negative corpus.** All 94 `CheckUnparsable` descriptor strings from
   `refs/bitcoin/src/test/descriptor_tests.cpp` through `parse-descriptor` — **94/94 rejected,
   zero wrongly accepted.** This is the strongest clean result of the survey: we do not accept a
   single descriptor Core refuses.
2. **Positive corpus.** 234 descriptor-shaped string literals from the same file. The only
   rejections were the 30 multipath vectors plus two extraction artifacts (a `rawtr()` two-key
   string that is itself a Core `CheckUnparsable` case, rejected with Core's exact message, and a
   `strprintf` template containing `%u`).
3. **Round-trip.** 51 public-form descriptors, `parse-descriptor` → `out-desc-string`. Every
   mismatch was an uncompressed-WIF input printing as its pubkey, which is what Core does.
4. **Multipath expander.** The 30 multipath vectors through `expand-multipath-descriptor`:
   18 accepted, 12 rejected with `Multiple multipath key path specifiers found`.
5. **RPC surface.** `getdescriptorinfo` and `deriveaddresses` through `bl.rpc:dispatch-rpc-method`
   on a `make-test-node :mainnet`.
6. **Wallet.** `importdescriptors` of a `musig()` and of a `combo(tprv…)` descriptor into a
   regtest wallet (`with-wallet-chain-node`), plus `%wallet-owning-spkm` on each expanded script.
7. **Signing.** `signrawtransactionwithkey` on a bare-P2PK input with a P2PKH control on the same
   key; `%collect-multisig-sig-pairs` with three held keys at m=1 and m=2.
8. **Classifier.** `classify-script` on a 1-of-17 bare multisig (582 bytes).
9. **Inference.** `scriptpubkey-desc` on P2PK / P2TR / bare-multisig / P2PKH.

## The three that matter

- **`95cd2402` (S2)** — `compute-input-signatures` has no `TxoutType::PUBKEY` case. A `combo()`
  import (Core's legacy-migration shape) makes the bare-P2PK script the wallet's own,
  `%script-sat-weight` sizes it, coin selection picks it, and signing then answers
  `unsupported scriptPubKey type pubkey`. Coins the wallet counts, it cannot spend.
- **`232c293f` + `c9da9f50` (S2)** — BIP389 multipath. `parse-descriptor` rejects all of it, so
  `getdescriptorinfo` calls a valid descriptor invalid and never emits `multipath_expansion`;
  and the one path that does expand refuses a specifier in more than one key expression, i.e. the
  ordinary multi-cosigner wallet export.
- **`f29c6fe6` (S2)** — `%desc-key-pubkey-at-cached` has no `musig()` branch, so the wallet's
  `Expand`/`ExpandFromCache` path type-errors on every musig descriptor and `importdescriptors`
  blames "hardened derivations without private keys" for a descriptor that has neither.

## Not covered — who inherits it

- Miniscript parsing / satisfaction / `FromScript` → **dimension 2 (miniscript)**. I only verified
  that `wsh()` and `tr()` leaves fall through to it and that `%check-miniscript-sane` exists.
- Wallet descriptor records, SPKM persistence, the 62 wallet RPCs beyond `importdescriptors`,
  and the PSBT combiner/finalizer/analyzer roles and taproot PSBT fields →
  **dimension 5 (wallet persistence + wallet RPCs)** and the serialization dimension.
- `core_io.cpp`'s other fields and the rest of `rpc/util.cpp` → **dimension 8 (rpc/util + core_io)**.
- Core's `Check()` expected-scriptPubKey hex vectors were **not** re-run as a differential:
  `tests/wallet/descriptor-tests.lisp` already pins many of them (`desc-core-*`,
  `tr-script-trees-match-core-vectors`, `musig-descriptors-match-core-vectors`) and I relied on
  that rather than duplicating it. A verifier who wants that oracle should extract the multi-line
  `Check(prv, pub, norm, flags, {scripts})` tuples.
- `key_io.cpp` is already covered by `tests/crypto/bitcoin-core-key-io-tests.lisp` against
  `key_io_valid.json` / `key_io_invalid.json`; I read the code but did not re-run the suite.
- `TaprootBuilder` / `GetTaprootSpendData` and the taproot script-path signing order were read but
  not differentially executed. No BIP32 test-vector run (the parser was read and matches, including
  the depth-0 rejections BIP32 vector 5 exercises).

## ⚠️ Harness trap (not a code defect)

A descriptor containing a **non-ASCII byte passed literally on the `scripts/dev.sh eval` command
line HARD-HANGS the eval client** (rc 4, "interrupt was not honored"). Core's
`raw(Ü)#00000000` vector cost an image restart and a 15-minute batch bisect before the cause was
clear. The same string built inside the form with `(code-char 220)` is handled correctly and is
rejected with Core's `Invalid characters in payload`. Build non-ASCII test data with `code-char`,
never inline.
