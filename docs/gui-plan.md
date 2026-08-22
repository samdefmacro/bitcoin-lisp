# GUI — Implementation Plan (web UI served by the node)

Date: 2026-07-15. Status (2026-08-22): **P0-P4 and P6a-d DONE** (PRs #282-#301; see §5); P5 (SSE push) not built.
Reference: Bitcoin Core `refs/bitcoin/` @ d3056bc (`src/qt/` feature inventory).
Researched via 2 agents (bitcoin-qt screens/architecture; CL GUI toolkit landscape with
web-verified maintenance status). Companion plan: `docs/wallet-plan.md` (P6 here gates on it).

## 1. The decisive research finding

**The nodes are headless Linux servers reached over SSH; any GUI is therefore a remote client
of the node.** That single constraint settles the toolkit question:

- **Chosen: a static, no-build-step web SPA served by the node's existing hunchentoot server**,
  talking to the existing JSON-RPC (which already supports batch requests) — zero new Lisp
  dependencies, works through `ssh -L` unchanged, same cookie auth. This is the standard
  architecture in the ecosystem: btc-rpc-explorer ("database-free, via RPC to Core"),
  mempool.space (frontend/backend over Core RPC), Sparrow (desktop RPC client). GUI stays a
  replaceable RPC client; the consensus image stays GUI-free.
- **Runner-up: CLOG** (healthy: v2.4 Nov 2025, SBCL first-class) — but it drags clack/
  websocket-driver/cl-dbi/sqlite into the image, holds per-tab server state on a websocket that
  dies over flaky SSH, and pays tunnel RTT per DOM event. If "GUI in Lisp" ever becomes a goal,
  run CLOG as a *separate* process speaking JSON-RPC — which is the SPA architecture anyway.
- **Ruled out as the primary architecture**: CommonQt/qtools (archived, Qt4-era), cl-gtk4
  (slow-moving, weak on macOS), McCLIM (X11-only on Mac, no Windows backend), Electron/Tauri
  shells (a toolchain to ship what a browser tab already does — but see §4: Tauri returns as
  optional *packaging* for local wallet users). LTk/nodgui noted as the native fallback if a
  local desktop client is ever wanted.
- bitcoin-qt itself talks to the node **in-process** via `interfaces::Node`/`interfaces::Wallet`
  (query/command calls + push subscriptions), not RPC. Our web transport maps 1:1: HTTP JSON-RPC
  for query/command, polling (later SSE) standing in for the push signals — Qt's WalletModel
  polls balances on a timer anyway.

## 2. Architecture

- **Serving**: `hunchentoot:create-folder-dispatcher-and-handler` for `/ui/` → repo `ui/`
  directory (configurable path), registered next to the existing `/` RPC and `/rest/` dispatchers
  in src/rpc/server.lisp. ~20 lines of Lisp. UI enabled by config flag (default on for testnet4,
  operator's choice on mainnet).
- **Frontend**: one page shell + vanilla ES-module JS, no npm/build/CDN — every asset checked
  into `ui/` and served same-origin (works air-gapped; nothing to supply-chain). A ~100-line
  helper lib wraps batched JSON-RPC `fetch` + a poll scheduler (2-5s cadence, one batch per tick:
  getblockchaininfo, getnetworkinfo, getmempoolinfo, getnettotals, getbestblockhash…).
- **Auth**: small login screen takes rpcuser/rpcpassword or the `.cookie` value, keeps it in
  sessionStorage, sends it as an explicit `Authorization` header on every fetch. Deliberately
  NOT browser-native Basic-auth/cookies: no ambient credential ⇒ CSRF-inert by construction
  (belt-and-braces: RPC handler can also reject cross-`Origin` POSTs).
- **Transport security**: RPC stays localhost-bound; remote use is `ssh -L 18332:localhost:18332`
  then `http://localhost:18332/ui/` — the RaspiBolt/btc-rpc-explorer pattern. The GUI adds zero
  new write capability: it can only do what the RPC surface already allows.
- **Explorer data**: block/tx pages need only getblock verbosity 2 / getrawtransaction —
  btc-rpc-explorer proves RPC suffices, no database. Address pages are the one thing RPC can't
  do without an address index (mempool.space uses electrs for this) — deferred, see §7.

## 3. Feature set (transposed from bitcoin-qt)

**Node-only** (works with no wallet — everything through P5 ships before/without wallet-plan):
dashboard (height/headers, IBD progress + ETA à la modaloverlay, connections in/out, mempool
count+vbytes+fees, traffic graph from getnettotals, version/network/uptime/warnings), recent
blocks, block/tx explorer with search (height|blockhash|txid), peers table + per-peer detail
(direction, transport v1/v2, services, ping, synced height — getpeerinfo has it all), ban
management (setban/listbanned/disconnectnode), network-active toggle, RPC console (method list +
history), log tail. Qt's options dialog mostly becomes read-only config display for us
(config file is the source of truth on the servers).

**Wallet-gated** (mirrors Qt's `-disablewallet` split; needs wallet-plan phases): overview
balances (available/pending/immature + mask-values privacy toggle), receive (new address, QR,
request history), transaction history (filters/search/CSV, abandon, bumpfee), send
(multi-recipient, estimatesmartfee target slider, RBF toggle, subtract-fee, later coin control),
wallet lifecycle (create/load/unload/encrypt/unlock-with-timeout/backup), PSBT panel
(load/decode/sign/broadcast — pairs with existing PSBT RPCs even pre-wallet for decode/analyze),
sign/verify message, per-wallet RPC-console scoping via `/wallet/<name>`.

## 4. Deployment modes & wallet threat model

One SPA, three delivery modes — one codebase, no per-platform GUI work:

| Audience | Mode | Notes |
|---|---|---|
| Operator (our headless servers) | `ssh -L` tunnel → any browser | the §2 auth model; nothing new listens on the server |
| Local node user (Mac/Windows/Linux) | browser at `http://localhost:<rpcport>/ui/`, **auto-opened on startup** (config flag, ships in P0) | the Syncthing/Transmission local-daemon pattern; zero installs on every OS (contrast: McCLIM needs XQuartz on macOS and has no Windows backend at all) |
| Local GUI-**wallet** user | **Tauri shell** wrapping the identical SPA (optional, post-P6) | dedicated OS webview: no browser extensions, own profile, real .app/.exe, ~10MB; pure packaging — zero GUI rework |

Wallet threat model (applies once P6 + wallet-plan land):

- **Keys never enter the GUI.** The wallet lives in the node (Core's bitcoind + bitcoin-qt
  model, wallet-plan §1); the SPA is a thin RPC client — key storage, encryption, signing, and
  coin selection are all node-side. A compromised GUI is bounded by the RPC surface × the
  unlock window (`walletpassphrase` timeout).
- **Remote websites**: blocked by design — auth is an explicit `Authorization` header (no
  ambient cookie/Basic credentials for a hostile page to ride) plus Origin checks (§2).
- **Browser extensions are the residual risk** for wallet screens: an extension can read/modify
  page content — the classic attack swaps a displayed or copied destination address. Mitigation
  is the Tauri mode above (extension-free webview) for wallet-heavy users; plain-browser mode
  remains fine for dashboard/explorer/console use.
- The passphrase transits loopback HTTP exactly as `bitcoin-cli walletpassphrase` does today;
  remote use rides inside the SSH tunnel.
- Users preferring a mature external wallet GUI point Sparrow at the same node instead
  (wallet-plan P7's validation target); in-node wallet + SPA stays the first-party path.

## 5. Staged milestones (each phase independently useful)

| Phase | Deliverable | Test strategy | Size |
|-------|-------------|---------------|------|
| **P0** | **DONE (PR #282)** **Serving + auth plumbing**: `/ui/` folder dispatcher + config flag (`-webui`/`-webuipath`); page shell/nav; JS rpc helper (batch, error surfaces) + login screen (Authorization-header auth, no ambient creds); Origin check on RPC POSTs (403 before auth); auto-open-browser-on-startup config flag (`-webuiopen`) for local runs (§4) | unit: dispatcher auth/404 paths; manual: tunnel from Mac to testnet4 node | S |
| **P1** | **DONE (PR #282)** **Node dashboard**: sync/IBD card (progress, ETA, headers-vs-blocks via getchainstates), peers/mempool/traffic cards, recent-blocks list, warnings banner; 3s batched poll (visibility-paused) | eyeball vs `getblockchaininfo` etc. on both nodes; IBD view exercised on a fresh regtest/testnet sync | S-M |
| **P2** | **DONE (PR #284)** **Explorer**: block page (header fields, paginated tx list), tx page (inputs w/ client-side prevout resolution — our getblock/getrawtransaction emit no prevout data at any verbosity — outputs, witness, fee/feerate, RBF signal), universal search box; permalinks | spot-check rendering vs the node's own getblock/getrawtransaction JSON (genesis, BIP143 segwit, coinbase edge cases) via a jsdom+stub-RPC harness | M |
| **P3** | **DONE (PR #286)** **Peers & network ops**: sortable peer table + detail drawer, ban list w/ setban/unban/disconnect, network-active toggle — the write actions of Qt's Peers tab | zero-dep node harness (tests/ui/peers.test.mjs: DOM shim + stubbed fetch drive the real modules — rendering, sorting, action→RPC params) + Lisp serving/wiring tests; manual against testnet4 node post-merge | S-M |
| **P4** | **DONE (PR #289)** **RPC console**: method autocomplete from `help`, JSON or space-separated params, history, result pretty-print; (wallet selector dropdown arrives with P6) | zero-dep node harness (tests/ui/console.test.mjs: arg parsing, autocomplete, history, result/error rendering, exact RPC POSTs) + Lisp serving/wiring tests; manual against testnet4 node post-merge | S |
| **P5** | *(optional)* **Push channel**: SSE endpoint streaming tip/mempool/peer-count events (hunchentoot chunked stream fed by a small node-side event ring), UI falls back to polling | soak: leave dashboard open through several blocks; kill/restore tunnel | S-M |
| **P6** | **Wallet screens**, sub-phased to track wallet-plan: **6a DONE (PR #292)** overview+receive+history+address book (needs wallet P1-P3; wallet selector over /wallet/<name>, client-side QR encoder vector-tested byte-exact, mask-values toggle, disabled/empty states); **6b DONE (PR #301)** send + fee UI (wallet P4); **6c DONE** PSBT panel + bumpfee (wallet P5; Core psbtoperationsdialog port); **6d DONE** lifecycle/encryption dialogs (wallet P1/P6; Security tab + UnlockContext port, see §5.1) | 6a: zero-dep node harness (tests/ui/wallet.test.mjs + qr.test.mjs vs machine-generated reference vectors) + Lisp serving/wiring tests; regtest wallet driven end-to-end from the browser; testnet4 send round-trip at 6b | M-L total |

P1-P5 have **zero dependency on the wallet plan** — ship them now in any order after P0
(P2 is the most useful day-to-day; P5 can be dropped if polling feels fine).

### 5.1 6d — the Bitcoin Core cross-reference

Wallet P6 shipped (PR #343), so 6d is unblocked. Core's Qt GUI already contains this
exact dialog set; port its *logic*, not its widgets. Anchors at `refs/bitcoin` d3056bc:

| Core (`src/qt/`) | 6d piece |
|---|---|
| `askpassphrasedialog.{h,cpp}` | one dialog, four modes: `Encrypt` / `Unlock` / `ChangePass` / `UnlockMigration` |
| `walletmodel.{h,cpp}` | `EncryptionStatus` + `UnlockContext` + `setWalletLocked` / `changePassphrase` |
| `createwalletdialog.{h,cpp}` | new-wallet dialog incl. the passphrase field |
| `walletcontroller.{h,cpp}` | Create / Open / Unload lifecycle activities |
| `walletframe.cpp`, `bitcoingui.cpp` | menu actions, status-bar lock icon |

**1. `EncryptionStatus` is derivable from `getwalletinfo` alone — but it takes TWO fields.**
Core's four states (`walletmodel.h:67-73`) are annotated with the very predicates wallet P6
implements:

```
NoKeys,       // wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)
Unencrypted,  // !wallet->HasEncryptionKeys()
Locked,       // wallet->HasEncryptionKeys() && wallet->IsLocked()
Unlocked      // wallet->HasEncryptionKeys() && !wallet->IsLocked()
```

Mapping onto our RPC:

| Core state | derive from `getwalletinfo` |
|---|---|
| `NoKeys` | `private_keys_enabled == false` — **check this FIRST** |
| `Unencrypted` | `unlocked_until` key **absent** |
| `Locked` | `unlocked_until == 0` |
| `Unlocked` | `unlocked_until > 0` |

No new RPC needed. Two things to get right: `NoKeys` dominates (a watch-only wallet must
show no encrypt/unlock controls at all, whatever the other fields say), and the
`Unencrypted` case is the *absence* of the key, not `0` — which is why P6 omits the field
entirely rather than reporting `0`, since `0` already means "encrypted but locked".

**2. Port `UnlockContext`, not a retry-on-`-13` loop.** The obvious browser design —
catch `-13`, prompt, retry — is *reactive* and leaves the wallet unlocked afterwards.
Core is proactive and self-restoring (`walletmodel.cpp:428-446`):

```cpp
bool was_locked = getEncryptionStatus() == Locked;
if (was_locked) Q_EMIT requireUnlock();          // UI raises the dialog
bool valid = getEncryptionStatus() != Locked;    // still locked ⇒ cancelled/wrong
return UnlockContext(this, valid, /*relock=*/was_locked);
```

Every signing path opens with `ctx(requestUnlock()); if (!ctx.isValid()) return false;`,
and the destructor **relocks iff the wallet was locked when the operation began** — borrow
the unlock, hand it back. Our equivalent is a `withUnlocked(fn)` wrapper: prompt if
locked → run → `walletlock` in a `finally` when it started locked. Prevents the "unlocked
for 10 minutes to send one payment, then forgot" failure that a retry loop invites.

Edge case worth copying: `privateKeysDisabled()` returns a valid, non-relocking context
(`walletmodel.cpp:434-436`) because old Core bugs produced watch-only wallets that carry
encryption keys which do nothing. Our `encryptwallet` refuses watch-only with `-16` so we
never mint one, but a wallet imported from Core can be in that state.

**3. Reusable strings** (`askpassphrasedialog.cpp:42-195`), several of which our RPC layer
already matches:

- `Warning: If you encrypt your wallet and lose your passphrase, you will <b>LOSE ALL OF YOUR BITCOINS</b>!`
- `IMPORTANT: Any previous backups you have made of your wallet file should be replaced with the newly generated, encrypted wallet file…` — the GUI twin of our `encryptwallet` return string.
- passphrase-strength hint: `ten or more random characters, or eight or more words`
- `The supplied passphrases do not match.` — **frontend-only** (the two-field confirm); there is no RPC for it and there should not be.
- the null-character passphrase explanation, matching our `-14` long form.

Also worth copying: caps-lock detection (`fCapsLock`), `secureClearPassFields`, and the
show-password toggle.

**⚠️ The one thing that does NOT transfer.** Qt is an in-process GUI: the passphrase lives
in a `SecureString` and never leaves the process. Ours crosses HTTP to the RPC, and
JavaScript cannot truly scrub a string — `secureClearPassFields` has no faithful analogue.
Copying the dialogs must not imply copying the security posture: the loopback/SSH-tunnel
constraint in §4 is what actually bounds the risk, and 6d should say so in the UI rather
than let a Core-shaped dialog imply Core-grade handling.

## 6. Effort & risk

- **P0-P4 ≈ 4-6 small PRs**; P6 lands incrementally behind wallet-plan phases. Much lighter
  than the wallet track — the node-side Lisp is ~a page; the rest is frontend files.
- **Security posture is the main design load**: no CDN/external assets ever (self-contained
  `ui/`), no ambient credentials, Origin checks, UI flag off ⇒ dispatcher not even registered.
  The wallet screens inherit wallet-plan's posture (encrypted wallet, unlock timeout) — the GUI
  never sees or stores keys, only RPC.
- **Perf**: explorer pages on mainnet can hit big blocks (4MB weight, thousands of prevout
  lookups via verbosity 3) — paginate tx lists, lazy-render.
- Hunchentoot is already a prod dependency (RPC server since day one) — no new attack surface
  beyond the new handlers themselves; the folder dispatcher must canonicalize paths (no `..`).
- No deploy from worktrees; UI files ride normal PR flow and need no FASL clear (static files),
  but P0's server.lisp change does.

## 7. Open decisions

1. **Address pages in the explorer**: defer (recommended) vs build an optional address index
   (scriptPubKey→txids, LevelDB, à la electrs) as a later index alongside txindex. On-demand
   `scantxoutset` per lookup is possible but seconds-slow on mainnet — fine as a stopgap
   "address balance" widget, wrong for history.
2. **Framework**: vanilla JS modules (recommended: zero deps, matches self-contained rule) vs
   vendored Preact+htm single-file (~13KB, nicer components, still no build step). Decide in P1
   when the dashboard's complexity is visible.
3. **SSE (P5)**: only if 2-5s polling annoys in practice. If wallet-plan open-decision 5 builds
   an async notification queue, SSE should consume the same queue.
4. **Mainnet UI default**: on (read-mostly, localhost-only anyway) or off (symmetry with relay
   policy)? Recommend on until wallet screens exist, revisit at P6.
5. QR rendering: ~200-line vendored JS QR encoder vs skip QR initially (recommend vendored at
   6a; receive screens without QR are half-useful on mobile).

## 8. Source anchors

- Qt screens: qt/bitcoingui.*, overviewpage.*, sendcoinsdialog.* (+sendcoinsentry),
  receivecoinsdialog.* (+receiverequestdialog, qrimagewidget), transactionview.*
  (+transactionrecord.h states), addressbookpage.*, coincontroldialog.*, rpcconsole.* (console
  syntax + wallet combo), optionsdialog.*/optionsmodel.*, modaloverlay.* (IBD UX), intro.*
- Node/wallet boundary: interfaces/node.h (executeRpc, getNodesStats, notifications),
  interfaces/wallet.h (WalletBalances/WalletTx shapes worth mirroring in our JSON),
  qt/clientmodel.*, qt/walletmodel.* (timer-poll precedent)
- Ours: src/rpc/server.lisp (dispatchers, batch handler, cookie auth), src/rpc/rest.lisp
- Prior art: github.com/janoside/btc-rpc-explorer (RPC-only explorer), github.com/mempool/mempool,
  sparrowwallet.com/docs/connect-node.html (external-wallet validation target, wallet-plan P7)
