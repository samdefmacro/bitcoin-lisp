# Project state and next tasks — 2026-08-20

Compiled from: the tree at `e232927`, the two live nodes (queried today), the GA9
report (`docs/gap-analysis-9.md`), the GA8 Wave 8 triage
(`docs/next-tasks-2026-08-19.md`), and the wallet/GUI/feature plans.

---

## 1. Where the project is

### Code

`main` = `e232927`, clean tree, 372 PRs merged. Last cold battery on this commit:
**30,830 checks, 0 failures**.

| Track | State |
|---|---|
| Consensus | GA9's 9 S1s all fixed and deployed (#352). No known consensus divergence. |
| GA9 S2 | All 14 fixed and deployed (#354). Three follow-ups deliberately deferred (below). |
| GA9 S3 | **~43 open, and no adversarial-verification pass has ever run on this round.** |
| GA8 Wave 8 (= GA7 backlog) | 19 were already fixed incidentally; 13 fixed since (#357-#360, #365-#370); **~30 open**. |
| Wallet | P0-P4 + P6 done; P5 RPCs all present; P7 partial (4 RPCs missing = G7-42); Sparrow acceptance never run. |
| Web UI | P0-P4 + P6a-d done. P5 (SSE push) optional, not built. |
| Big features | assumeutxo P0-P6 done; cluster mempool P0-P9 (P10 optional); Tor P0-P3 done (**the plan doc is stale and says P2+ not started**); Erlay = handshake only; block-file-format deferred. |

### Live nodes (queried 2026-08-20)

Both on `e232927`, both fully synced, no errors in the current epoch.

| | testnet4 | mainnet |
|---|---|---|
| blocks / headers | 149217 / 149217 | 963244 / 963244 |
| peers | 11 (1 in, 10 out) | connected, `-listen` off |
| mode | full, txindex + coinstatsindex + blockfilterindex | pruned 4096 MiB (pruneheight 960603) |
| disk | `/data` 77G used of 196G (41%) | shared |

G7-61 is confirmed working in production: both datadirs now carry a
`headerindex.delta` beside `headerindex.dat`.

### Blocked right now

**The Docker daemon on this Mac is not running** (`cl-workbench doctor --strict`
fails with "Docker daemon is unavailable"). No build, eval, test or cold battery
can run until Docker Desktop is started. Everything below is research done from
files, git and read-only queries against the live nodes.

---

## 2. New findings from today's inspection

These are not in any existing list. Four of the five are observability defects
that make every future diagnosis harder — which is why they lead.

**N1. 24% of the testnet4 log is one benign warning.**
`WARN: Header validation error: Timestamp too far in the future` appears
**33,567 times** in a 141,693-line log covering 2026-08-07 to 2026-08-20 — the
single most common line by 2x, about 2,600 a day. It is
not a bug in the check (`ibd.lisp:786` matches Core's `MAX_FUTURE_BLOCK_TIME`
rule exactly): testnet4's tip is legitimately ~1.9 h ahead of wall clock, so the
next header routinely lands past `now + 2h` and is correctly refused until time
passes. Core logs the same event at debug level and does not punish for it.
Two fixes: downgrade/rate-limit it, and make it say *which* header and by how
much — today it prints neither, so the condition cannot be confirmed from the log
alone.

**N2. Header sync runs ~1,390 times a day to ingest nothing.**
17,628 `IDLE -> SYNCING-HEADERS` transitions over those 12.7 days — one every
~62 s on a chain that produces ~144 blocks a day. **11,904 of the 12,170**
completed rounds report `0 headers`, and **7,553 of the 7,844** peer kicks report
`0 headers ingested`: 96% either way. Core is announcement-driven (headers on
`inv`/`cmpctblock`, plus a stale-tip timer) rather than polled. Costs bandwidth
on both ends and is what makes N1 fire so often.

**N3. A multi-line condition report is pretty-printed across ~10 log lines.**
`connection.lisp:727` formats the condition with `~A` while `*print-pretty*` is
on, so an SBCL type-error is emitted like this:

```
[...] WARN: Receive failed on 34.254.97.244:8333 with a non-I/O error: The
                                                                       value

                                                                         3119

                                                                       is
                                                                       not
                                                                       of
                                                                       type

                                                                         (UNSIGNED-BYTE
                                                                          10)
```

That is the *fd > 1023 select() bug* (PR #351) reported by the very mechanism
written to catch it — and it took a session to diagnose partly because grep on
the log returns only `... non-I/O error: The`. Bind `*print-pretty*` to nil (or
squash newlines) when a condition goes into a log line. Pairs with GA9's S3
finding that log writes are unsynchronized and interleave mid-line.

**N4. Unfetchable fork bodies are retried forever.**
`REORG REFUSED: N blocks missing from store` appears 205 times across ~40
distinct heights (11x at height 149208 alone), but `Re-queued ... missing fork
blocks` only 25 times — the re-queue is guarded on "not already pending", so a
fork body no peer will serve stays pending and every activation pass re-walks and
re-refuses it. testnet4 currently reports **2,714 chain tips**. Harmless today
(the node holds tip), but it is unbounded retry against a permanently absent
body, and the tip count makes every `getchaintips` and every best-tip scan
costlier over time. Wants a give-up/backoff rule.

**N5. The RPC server rejects a Content-Type Core accepts.**
`rpc/server.lisp:689-694` returns **415** unless the header contains
`application/json` or `text/plain`. Core's `httprpc.cpp` never inspects the
request Content-Type at all. So plain `curl -d ...` (which defaults to
`application/x-www-form-urlencoded`) and any client that omits the header get 415
from us and work against Core. Found by having it happen during today's survey.

---

## 2a. Found while deploying the fix for the above

**N6. Five of the six block-activation call sites on the IBD path never passed
the transaction index.** PR #372 fixed the *arrival* path
(`accept-downloaded-block`); the deploy of the observability PR immediately
rescanned the whole txindex from genesis again, and the diagnostic added in
#371 said why: `marker-off-chain`. `activate-best-chain` and the four
`activate-block` calls in `src/networking/ibd.lisp` all take `:tx-index` and all
omitted it, so every block reaching the chain through the drain, retry, reorg
and periodic-activation paths was connected with the index switched off — its
transactions never indexed, and the best-block marker left naming a block the
reorg had just disconnected. Fixed by reading the index from the IBD context
through one helper rather than accepting it per-caller, plus a structural test
that fails when a new call site omits it.

**N7. Erlay P2 has no Bitcoin Core reference to port from.** Core's
`TxReconciliationTracker` (`src/node/txreconciliation.{h,cpp}`) is **170 lines**
with exactly four public methods — `PreRegisterPeer`, `RegisterPeer`,
`ForgetPeer`, `IsPeerRegistered`. There is no `AddToSet`, no fanout selection,
no timer and no sketch; the file's own comments still read *"TODO: ... Make
private once used in the following commits."* Core ships the `sendtxrcncl`
handshake and nothing else.

Our P1 is already a complete, faithful port of exactly that surface, verified
line by line: `NOT_FOUND` / `ALREADY_REGISTERED` / `PROTOCOL_VIOLATION`, the
`min(theirs, ours)` version downgrade, `we_initiate = !is_peer_inbound`, the
BIP-330 salt ordering, and the verack-time forget when wtxid relay was never
negotiated.

So P2 would be new protocol design, not a port — and it is **not shippable on
its own**: P2 diverts transactions into per-peer reconciliation sets, and
without P3 (minisketch) and P4 (sketch exchange) there is no mechanism that
ever delivers them. Deploying P2 alone would degrade relay on the live nodes.
The Erlay track is therefore P2+P3+P4 or nothing, ~6-10 PRs against a protocol
Core has not merged, with no reference implementation to check against — which
is the single most reliable error-catcher this project has.

---

## 3. Carried-over backlog

> **SUPERSEDED 2026-08-23 — do not work from this list without checking first.**
> A verification pass against the tree found most of it already fixed by the
> waves that followed. The whole "Config & lifecycle" cluster below, called out
> here as the largest and most operator-facing one, is **done**: `[network]`
> precedence, inline `#` comments, `conf-parse-bool`, `-includeconf`,
> conflicting chain selectors, a non-existent `-datadir`, and the datadir
> layout. So are signal safety and logging, four of the six Peers items, and
> all four GA8 Wave 8 S2s.
>
> The verified table — what is fixed, what is still open, and what a grep could
> not settle — is in `docs/next-wave-2026-08-22.md`, section
> "Verifying the carried-over backlog". Read that instead.

### 3a. Deferred from the GA9 S2 wave (documented at the deferral sites in code)

- maintain `m_best_header` incrementally — unlocks S2-3's three omitted Core
  conditions *and* removes an O(index) scan;
- `%rollback-partial-reorg` → a real disconnect, which unblocks S2-10 phase B;
- move the inbound handshake off the accept thread (S2-9).

### 3b. GA9 S3, clustered (~43 items, never verification-passed)

- **Config & lifecycle** (the largest and most operator-facing cluster): a
  `[section]` for the network selected *inside* bitcoin.conf is dropped before
  the network is known; `[network]` values lose to global values (Core's
  precedence is the reverse); inline `#` comments are not stripped;
  `conf-parse-bool` accepts `true`/`yes`/`on` where Core's `InterpretBool` is
  `atoi(v) != 0`; `-includeconf` unimplemented; conflicting chain selectors
  resolve silently instead of erroring; a non-existent `-datadir` is created
  rather than refused; and **our datadir layout is the inverse of Core's**
  (mainnet in `<datadir>/mainnet/`, testnet3 at the root) — confirmed on the live
  host, where mainnet lives in `.../mainnet-prune/mainnet/`.
- **Signal safety & logging**: the SIGTERM/SIGINT handler is not
  async-signal-safe (it writes to shared streams and takes the log mutex —
  `node.lisp:3418-3462`), so a routine `kill` can hit a recursive-lock error in
  the handler and skip the chainstate flush; log writes are unsynchronized across
  ~8 thread sources. Both land on the live nodes. **Group with N3.**
- **Peers**: tried-table collision resolution runs only at startup; `-addnode`
  peers are not exempt from discouragement and can never be redialled;
  ping budget 3 min vs Core's 20; `address-routable-p` accepts space Core
  rejects; `anchors.dat` is never consumed on read; outbound netgroup diversity
  frozen at startup.
- **Storage**: `loadtxoutset` never writes the snapshot coins-DB best-block
  pointer (opts assumeutxo out of the invariant #333-#338 established);
  `gettxoutsetinfo` makes three flush-and-rescan passes and mixes chain tip with
  coins-DB pointer, so its `(height, hash_serialized_3)` pair can be
  self-inconsistent — and that hash is the assumeutxo commitment; three LevelDB
  scans never call the project's own `leveldb-iter-check-error`;
  `coins-view-cache-add` marks a slot FRESH under `:allow-overwrite` where Core
  guards with a `logic_error`.
- **Script** (all policy-only, no consensus effect): empty-signature
  `OP_CHECKSIG` short-circuits before `CheckPubKeyEncoding`;
  `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` is declared but **never consulted**; the
  single-CHECKSIG FindAndDelete pattern disagrees with
  `strip-sigs-from-script-code`; P2SH-wrapped-witness detection uses
  `extract-last-push-data` instead of the stack top; the script-flag parse cache
  is an unsynchronized hash table mutated by parallel workers.
- **RPC / wallet / mempool**: Basic-auth credentials decoded latin-1 where Core
  compares raw bytes (a non-ASCII `-rpcpassword` can never authenticate);
  `walletprocesspsbt` omits the wallet's `non_witness_utxo`; a rescan freezes the
  passphrase relock deadline while `getwalletinfo` reports it already expired;
  BIP54's per-transaction legacy sigop relay cap is absent.

### 3c. GA8 Wave 8 remaining (~30)

S2 (4): **G7-10** getdata serving has no fingerprinting/prune-depth/bandwidth
guards · **G7-11** ephemeral dust policy entirely absent · **G7-22**
`estimatesmartfee` contract divergences (feerate on failure, no mempool-min
clamp, wrong default mode) · **G7-26** taproot accept/reject corpus.

S3 (~26): G7-27 VerifyDB · G7-28 flush failures swallowed · G7-32 `-debug=<cat>`
· G7-34 `-connect` · G7-37 `-maxuploadtarget` · G7-38/39/40/41 wallet (fast
rescan, CPFP bump fees, multipath, miniscript) · G7-42 four descriptor RPCs ·
G7-43 verbosity 3 · G7-44 REST endpoints · G7-46/47 signer & private broadcast ·
G7-48/50/51/52 peer/download policy · G7-53/55 privacy-net · G7-58 versionbits
template version · G7-59 coins-DB obfuscation key · G7-60 txospenderindex ·
**G7-62, G7-65-69** six test-vector corpora.

### 3d. Standing decisions

Mainnet wallet enablement; Sparrow acceptance (wallet P7); whether to run a 10th
gap analysis or spend the same budget verifying GA9's S3s.

---

## 4. Recommended order

The principle: **fix what makes diagnosis expensive first**, then the silent
operator-facing divergences, then the policy tail, then features.

1. **Observability pass — N1 and N3 in one PR, N2 measured first.** The smallest
   change in this document, and it improves every later investigation on the
   live nodes.
   Include the offending hash/timestamp/delta in the N1 message rather than only
   silencing it. Ship-the-log-line has now paid off twice this month.
2. **Shutdown & logging safety** — GA9's signal-safety and log-interleaving S3s,
   which belong with N3 and land directly on the two production nodes. A `kill`
   that skips the chainstate flush is an outage-shaped bug.
3. **Config & lifecycle cluster** — the whole GA9 config group as one wave. Every
   item is silent, operator-facing, and several are data-loss adjacent (the
   inverted datadir layout can write testnet3 data into a Core mainnet
   directory; a mistyped `-datadir` silently starts a fresh IBD).
4. **N5 + the latin-1 auth decode** — two small RPC-compatibility fixes that both
   present as "client X cannot talk to our node".
5. **GA8 W8's four S2s** — G7-11 ephemeral dust, G7-22 `estimatesmartfee`
   (natural follow-on from the estimator work just merged), G7-10 getdata guards,
   G7-26 taproot corpus.
6. **N4 fork-body backoff**, together with the deferred `m_best_header`
   incremental maintenance — same area, and the O(index) scan is the reason a
   2,714-tip index is a cost at all.
7. **The six remaining vector corpora (G7-62, 65-69).** Cheap, mechanical, and
   the last corpus adoption (G7-63) found a real bech32 bug on contact.
8. **Then choose**: wallet P7 + Sparrow acceptance (closes the wallet track), or
   the GA9 S3 verification pass, or GA10. GA7 and GA8 both had adversarial
   verification change the answer repeatedly, so verifying GA9's S3s before
   fixing them is the higher-confidence spend.

### Not recommended yet

Erlay P2+, cluster mempool P10, block-file-format, and miniscript (G7-41) are all
large and none of them is on a live failure path. They should wait until the S3
backlog stops producing operator-visible defects.
