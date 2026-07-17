# Wallet Functionality — Implementation Plan

Date: 2026-07-15. Status: **PLAN — not started.**
Reference: Bitcoin Core `refs/bitcoin/` @ d3056bc (v30-dev, descriptor-only wallets).
Researched via 2 agents (Core `src/wallet/` architecture; our building-block inventory).
Companion plan: `docs/gui-plan.md` (wallet screens there gate on phases here).

## 1. Framing and scope decisions

This reverses the long-standing "no wallet functionality in scope" line in CLAUDE.md —
**update CLAUDE.md in the first wallet PR.** Ground rules derived from Core at d3056bc:

- **Descriptor wallets only.** Core can no longer *create* legacy (BDB) wallets
  (`rpc/wallet.cpp:403-404` hard-rejects `descriptors=false`); legacy code exists solely to
  load-and-migrate. We skip BDB entirely — no `migratewallet`, no BerkeleyDB parser.
- **No BIP39 mnemonics.** Core has none; seeds are random keys wrapped in descriptors
  (`GenerateWalletDescriptor`, walletutil.cpp:35-86). Backup = wallet file + `listdescriptors true`.
- **Not consensus-critical, but funds-critical.** Divergence from Core here can't split the
  chain, but a wrong fee/change computation or keypool-persistence bug loses real money.
  Same porting discipline as consensus code: read Core, port faithfully.
- **Deployment posture:** wallet available on testnet4 first; on mainnet default-disabled
  (config flag, like relay). The server nodes hold keys only if the user explicitly opts in.
- Out of scope for this plan: external signers / hardware wallets (headless server),
  MuSig2, miniscript, ZMQ notifications, Core wallet.dat (SQLite) file-format
  interop (see Open decisions §7).

## 2. Head start — what already exists (inventory verified 2026-07-15)

Far more than expected; the wallet is mostly *assembly* of existing parts plus four new
engines (descriptors v2, DB/keystore, tx tracking, coin selection):

- **Signing complete**: ECDSA (RFC6979 low-S), Schnorr/BIP340, recoverable-compact, pubkey
  derivation, taproot tweaks (src/crypto/secp256k1.lisp, bip32.lisp). `signrawtransactionwithkey`
  (src/rpc/methods.lisp:3522) already signs P2PKH/P2WPKH/P2TR-keypath/multisig/P2SH-wrapped —
  the wallet reuses its sighash + witness-construction machinery via `bitcoin-lisp.coalton.interop`.
- **BIP32 full** (src/crypto/bip32.lisp): CKDpriv/CKDpub, xprv/xpub ser/parse, path parsing,
  fingerprints, HMAC-SHA512. All address types + WIF (src/crypto/address.lisp).
- **PSBT** (src/serialization/psbt.lisp, src/rpc/psbt.lisp): parse/serialize/combine/
  finalize/extract with byte-preserving maps and all keytype constants — only the *signer role*
  (inserting `partial_sig`/`tap_key_sig`) is missing.
- **Fee estimation** (`estimatesmartfee`, src/mempool/fee-estimator.lisp), **broadcast** (Wave 8B
  BroadcastTransaction + unbroadcast set — exactly what wallet rebroadcast needs), **LevelDB**
  bindings (src/storage/leveldb.lisp), RPC registry + cookie auth (src/rpc/server.lisp).
- **Descriptor parser is the weak spot** (src/rpc/descriptors.lisp): addr/raw/pk/pkh/wpkh/
  sh(wpkh)/combo/tr(key-only) with checksums, but **no xpubs, no key origins, no ranged `/*`,
  no multi/sortedmulti, no wsh(), no tapscript** — P0 fixes this.
- **No validation-interface pub/sub**: indexes are hardcoded calls inside `connect-block`
  (src/validation/block.lisp:1583 txindex, :1570 filters, :1573 coinstats) and `perform-reorg`.
  The wallet wires in the same way (§4).

## 3. Core architecture — the shape we're porting

- **CWallet** (wallet.h:309) owns `mapWallet` (txid→wtx), `m_txos` (outpoint→owned TXO,
  spent *and* unspent), `mapTxSpends` (outpoint→spending txids, powers conflict detection),
  address book, locked coins, and an SPKM registry. Everything under one `cs_wallet` lock.
- **TxState** (transaction.h:31-82) is a variant: Confirmed{hash,height,pos} / InMempool /
  BlockConflicted{hash,height} / Inactive{abandoned}. Depth <0 conflicted, 0 mempool, ≥1 confirms;
  coinbase maturity = 100 (+1 rule via `GetTxBlocksToMaturity`).
- **DescriptorScriptPubKeyMan** (scriptpubkeyman.h:275): one descriptor + expansion caches;
  keypool = precomputed `range_end` window (`DEFAULT_KEYPOOL_SIZE=1000`); `TopUp`
  (scriptpubkeyman.cpp:1001) extends `range_end = max(next_index + keypool, range_end)` and
  persists cache; `IsMine` = hash-lookup in `m_map_script_pub_keys` (:863). `GetNewDestination`
  (:824) = TopUp → expand at `next_index` → increment → **persist before handing out**.
- **Default wallet = 8 SPKMs** (wallet.cpp:3594): {external,internal} × {legacy 44h,
  p2sh-segwit 49h, bech32 84h, bech32m 86h}, coin `0h` mainnet / `1h` testnet, `/0/*` external
  `/1/*` change.
- **Chain tracking**: wallet subscribes to blockConnected (wallet.cpp:1526), blockDisconnected
  (:1555), transactionAddedToMempool (:1414), transactionRemovedFromMempool (:1457),
  updatedBlockTip (:1602). It does NOT use chainStateFlushed — it writes its own best-block
  locator when a wallet tx changed or every 144 blocks (:1550, WriteBestBlock :4534). Rescan =
  `ScanForWalletTransactions` (:1857), birth-time gated, abortable, locator checkpointed.
  Note: Core delivers these callbacks **asynchronously on the scheduler thread**; our indexes
  run synchronously inside connect-block — see risk §6.
- **Accounting** (receive.cpp): credit = Σ IsMine outputs; debit needs prevout's parent in
  mapWallet; fee = debit − valueOut only when debit>0; change heuristic = IsMine ∧ not in
  address book; trusted = confirmed, or (from-me ∧ in-mempool ∧ all inputs trusted-ours ∧
  spend-zero-conf-change); immature coinbase credit counts as 0.
- **Coin selection** (coinselection.cpp): run BnB (positive-effective-value group, skipped under
  subtract-fee-from-outputs), Knapsack (mixed group), CoinGrinder (only when feerate > 3× long-term),
  SRD — keep least **waste** = (change_cost|excess) + Σin·(eff_rate − longterm_rate) − bump_discount.
  Eligibility cascade loosens (6conf-theirs,1conf-ours) → zero-conf-change → ancestor limits
  (spend.cpp:900-927). Change target random in [50k, 1M] sat.
- **CreateTransactionInternal** (spend.cpp:1063): discard rate (default 10000 sat/kvB) →
  cost-of-change → select → change at random position → anti-fee-sniping nLockTime
  (= tip height, 10% chance −rand(100)) → sequence 0xFFFFFFFD (**RBF default ON**,
  `DEFAULT_WALLET_RBF=true`) else 0xFFFFFFFE → size via CalculateMaximumSignedTxSize → fee loop
  must land exactly (`fee_needed == current_fee` asserts) → caps: MAX_STANDARD_TX_WEIGHT,
  maxtxfee, chain limits. `fundrawtransaction` = same path with caller inputs preset, sign=false.
- **Storage**: abstract kv batch (db.h) over SQLite; record schema = DBKeys strings
  (walletdb.cpp:32-63): `walletdescriptor`, `walletdescriptorkey`/`ckey`, `walletdescriptorcache`,
  `activeexternalspk`/`activeinternalspk`, `tx`, `bestblock[_nomerkle]`, `name`/`purpose`,
  `flags`, `mkey`, `orderposnext`, `lockedutxo`, `minversion`/`version`.
- **Encryption** (crypter.h): AES-256-CBC; master key encrypted by SHA512-KDF(passphrase,
  salt, 25000 rounds); each privkey encrypted with master key, IV = sha256d(pubkey); **only key
  material encrypted** — descriptors/txs/metadata stay plaintext. walletpassphrase timeout relock.
- **Multiwallet**: RPC routing by URL path `/wallet/<name>` (httprpc.cpp:340, rpc/util.cpp:19-85);
  createwallet flags: disable_private_keys(1<<32), blank(1<<33), descriptors(1<<34, always),
  avoid_reuse(1<<0). Flags >2^31 are mandatory-understand.
- **Rebroadcast** (wallet.cpp:2105): unconfirmed own txs resubmitted on a random 12-24h timer,
  skipping txs newer than best-block-time − 5min; force-resubmit (no relay) at startup.

## 4. Our integration surface

- **Event hooks**: add a `wallet-manager` (fans out to loaded wallets) called from the same
  tip-update critical sections as the indexes: `connect-block` (src/validation/block.lisp:1508,
  index calls at :1570-1583), `perform-reorg` (~:1900) for disconnects, mempool accept/remove
  (src/mempool/mempool.lisp) for the two mempool callbacks. Keep per-hook work O(tx-in-block ×
  hash lookups) + one LevelDB batch — synchronous is fine at that cost (risk §6).
- **RPC**: new `rpc-*` handlers registered in `register-all-methods` (src/rpc/server.lisp);
  add `/wallet/<name>` path routing in the hunchentoot dispatch (currently POST `/` only) and a
  wallet-name→wallet resolution helper mirroring rpc/util.cpp:54-85.
- **Signer reuse**: factor the sighash/witness-construction core out of
  `rpc-signrawtransactionwithkey` (src/rpc/methods.lisp:3522) into a signing-provider-style
  function the wallet can call with keys from its keystore; extend to write PSBT
  `partial_sig`/`tap_key_sig` records (P5) instead of only final scriptSig/witness.
- **Storage**: one LevelDB per wallet under `<datadir>/wallets/<name>/` using Core's exact
  record key strings and value serializations (CWalletTx, WalletDescriptor). Byte-level record
  compat makes any future SQLite-container work (or a wallet-file importer) mechanical.
- **Crypto for encryption**: ironclad AES-256-CBC + SHA512 already available; KDF is a
  straight port of `BytesToKeySHA512AES`.
- **defstruct additions** (wallet structs, node slot for wallet-manager) ⇒ **FASL clear on
  deploy** (rm -rf ~/.cache/common-lisp), as with every wave that touched defstructs.
- **Threading**: one lock per wallet (cs_wallet equivalent); lock order = validation lock →
  wallet lock, never the reverse (RPC threads must not call into validation while holding it).

## 5. Staged milestones (node shippable at every stage)

| Phase | Deliverable | Test strategy | Size |
|-------|-------------|---------------|------|
| **P0** | **DONE (PR #283)** **Descriptor engine v2** (no wallet yet): xpub/xprv keys with origins `[fp/path]`, ranged `/*` + hardened paths, `multi()`/`sortedmulti()`, `wsh()`, private-key descriptors, expansion cache. Immediately upgrades existing `deriveaddresses` (ranges), `scantxoutset`, `getdescriptorinfo` | port Core descriptor_tests.cpp vectors; cross-check `deriveaddresses` against Core on the same descriptors | M-L |
| **P1** | **Wallet container + keystore**: wallet struct + per-wallet LevelDB (Core DBKeys record schema), descriptor-SPKM (spk maps, TopUp/keypool=1000, persist-before-issue next_index), 8 default SPKMs (44h/49h/84h/86h × ext/int), wallet-manager + `/wallet/<name>` routing; RPCs: createwallet/loadwallet/unloadwallet/listwallets/listwalletdir/getwalletinfo, getnewaddress/getrawchangeaddress, listdescriptors, importdescriptors (rescan lands P2) | unit: keypool persistence across reload (issue → crash-sim → reload → no address reuse); descriptor-key derivation vs Core | L |
| **P2** | **DONE (PR #288)** **Chain tracking**: hooks in connect-block/reorg/mempool, AddToWalletIfInvolvingMe, TxState variant + mapWallet/m_txos/mapTxSpends, mempool + block conflict tracking, birth time, best-block locator (144-block cadence), ScanForWalletTransactions + rescanblockchain/abortrescan + importdescriptors timestamp rescan; RPCs: gettransaction, listtransactions, listsinceblock | regtest: fund wallet, mine, reorg across funding tx, double-spend conflict, coinbase maturity; rescan-from-genesis equals live-tracked state | L (the meat) |
| **P3** | **DONE (PR #TBD)** **Balances & coins**: receive.cpp accounting port (credit/debit/fee, trusted rules, immature, change heuristic), address book + labels; RPCs: getbalance(s), listunspent, lockunspent/listlockunspent, getaddressinfo, setlabel/getaddressesbylabel/listlabels, abandontransaction | port Core functional expectations (wallet_balance.py, wallet_abandonconflict.py scenarios) on regtest | M |
| **P4** | **Spending** (funds-critical): coin selection (BnB/Knapsack/SRD + waste + eligibility cascade; CoinGrinder deferred), CreateTransactionInternal port (change target/dust/discard, anti-fee-sniping, RBF-default sequences, exact fee loop, weight/maxtxfee caps), wallet signing via P0 providers; RPCs: sendtoaddress, sendmany, send, sendall, fundrawtransaction, signrawtransactionwithwallet; rebroadcast timer (12-24h) via Wave 8B unbroadcast machinery | port coinselector_tests waste/BnB vectors; regtest end-to-end spends incl. SFFO, dust-change, locktime/sequence field checks vs Core-built txs; testnet4 live spend | L (the meat, pt. 2) |
| **P5** | **PSBT bridge + fee bump**: sign→PSBT (partial_sig/tap_key_sig insertion), FillPSBT port; RPCs: walletprocesspsbt, walletcreatefundedpsbt, descriptorprocesspsbt (node-level — feasible now with P0, was on the "infeasible" list), bumpfee/psbtbumpfee (feebumper port) | Core rpc_psbt.json signer vectors (we already pass the no-wallet ones); regtest RBF bump chains | M |
| **P6** | **Encryption + backup + message signing**: crypter port (AES-256-CBC, 25k-round SHA512 KDF, IV=sha256d(pubkey)), encryptwallet/walletpassphrase(+timeout relock)/walletpassphrasechange/walletlock, backupwallet/restorewallet, signmessage | unit: encrypt→lock→unlock→sign roundtrip; restore backup into fresh node, balances identical; keys never logged | M |
| **P7** | **Polish/parity**: avoid_reuse flag, getreceivedbyaddress/label, listreceivedby*, listaddressgroupings, keypoolrefill, simulaterawtransaction, getwalletinfo field completeness; **Sparrow Wallet connected as external client** as an RPC-fidelity acceptance test | Sparrow connects, sees balances/history, composes+signs+broadcasts via our node | S-M |

**Watch-only MVP = P0-P3** (import Core descriptors, track funds, full history/balances — already
useful on the server nodes with zero key-loss risk). **Spending MVP = P0-P4.** P5-P7 reach
Core parity minus the explicit out-of-scopes.

## 6. Effort & risk

- **~15-20 PRs, multi-wave** (comparable to the cluster-mempool track). P2 and P4 dominate.
- **Funds-loss risks (top of list)**: (a) keypool `next_index` must persist *before* an address
  is handed out — reuse after crash otherwise; (b) the P4 fee/change loop — port Core's asserts
  as hard errors, cap with maxtxfee from day one; (c) conflict/abandon state driving
  `listunspent` — spending a conflicted-away output burns fees. Mitigate: regtest reorg suite in
  P2 before any spend path exists; testnet4 soak between P2/P3 and P4; mainnet stays default-off.
- **Sync-hook cost**: wallet callbacks run inside the connect-block critical section
  (Core runs them async). Budget: hash-lookups per tx + one batched DB write per block. If IBD
  profiling shows drag, gate hooks on `ibd-completed` + rescan-on-attach, or add a queue later.
- **Security**: server nodes are internet-facing; keys on the node are opt-in (testnet4 first,
  mainnet default-off), encrypted wallets recommended, RPC stays localhost+cookie. Never log key
  material; zeroize decrypted keys on lock where the GC allows.
- **FASL**: multiple new defstructs ⇒ every deploy in this track needs the FASL clear.
- Worktree rule stands: implement in worktrees, PR+merge, deploys from main checkout only.

## 7. Open decisions

1. **Storage container**: LevelDB with Core's record schema (recommended — zero new deps,
   record-level compat) vs adding SQLite for literal wallet.dat interop. Migration from Core
   works either way via `importdescriptors` (export from Core with `listdescriptors true`).
   Revisit SQLite only if wallet.dat portability becomes a real need.
2. **Mainnet policy**: keep wallet compiled-in but default-disabled on mainnet (recommended),
   or testnet-only build flag until P6 encryption lands?
3. **CoinGrinder**: defer (recommended — it only activates above ~3× long-term feerate; BnB/
   Knapsack/SRD are what run in practice) or port in P4 for full waste-comparison parity?
4. **Multipath descriptors** `<0;1>` and `createwalletdescriptor`/`gethdkeys`: defer both
   (Core's default wallets don't emit multipath; niche RPCs).
5. **Notification delivery**: keep synchronous hardcoded hooks (recommended, matches our index
   pattern) or build a Core-style async validation-interface queue first? (Queue becomes
   attractive if the GUI's SSE push channel wants the same events — see gui-plan P5.)

## 8. Core source anchors

- CWallet/state: wallet.h:309,340,417-438,473-498,526; transaction.h:31-121,278-366
- Notifications/rescan: wallet.cpp:1414,1457,1526,1555,1602,1799,1813,1857,3171-3313,4534
- Descriptor SPKM: scriptpubkeyman.h:63,174,275; scriptpubkeyman.cpp:824,863,1001,1277,1309;
  walletutil.h:15-95; walletutil.cpp:35-86 (default paths); wallet.cpp:3594-3685 (setup/active)
- Spend/selection: spend.cpp:702-927 (selection cascade),1006-1043 (fee-sniping),1063-1421
  (CreateTransactionInternal),1494-1534 (fund); coinselection.h:296-476; fees.cpp; wallet.h:108-132
  (defaults); receive.cpp:52-263 (accounting)
- Signing/PSBT: wallet.cpp:2152-2186; script/sign.cpp:25,64,88,729,1009; rpc/spend.cpp:960
  (bumpfee_helper),1573,1657
- Storage/encryption: walletdb.{h:192-306,cpp:32-63,182,560+}; db.h:167,206; sqlite.cpp;
  crypter.h:14-48; wallet.cpp:808 (EncryptWallet),2061-2142 (resend)
- Multiwallet/RPC: httprpc.cpp:340; rpc/util.cpp:19-85; rpc/wallet.cpp:346-408,844-902
