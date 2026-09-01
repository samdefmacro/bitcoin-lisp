# 10th gap analysis — bitcoin-lisp vs Bitcoin Core (refs/bitcoin @ d3056bc)

Date: 2026-09-01. Baseline: `main` @ `3470694`, clean tree — immediately after the 43-PR
cleanup refactor (#521–#562), so this round doubles as a post-refactor check.
Oracle: Bitcoin Core @ `d3056bc` — the same revision GA7–GA9 used, so severities and
coverage are directly comparable across four rounds.

## ⚠️ Read this before trusting any number below

**This round did not finish.** 167 agents were launched; 102 died on an API session limit
mid-run. What that cost, precisely:

- **12 of 13 finder dimensions completed** and produced **84 candidate findings**.
- **The 13th dimension — refactor-induced regression — never ran at all.** That was the
  dimension written specifically for this moment: 43 PRs had just moved symbols between
  layers, split `validate-block` and `perform-reorg`, and carved up `src/node/` and
  `src/rpc/`. It is the single most important gap in this round and the first task of the next.
- **Verification ran to roughly a third of its design.** The plan was 3 refute-biased
  verifiers per S1/S2 and 1 per S3 — about 152 verdicts. **53 returned.**

So the 26 findings below are those that survived *whatever verification reached them* —
some by the intended 3-lens panel, some on a single vote. Treat each as high-quality but
**not** as settled: confirm against both trees before acting.

**The 58 findings in the second list are NOT refuted.** The orchestrator's tally called
them that, and the tally was wrong: a finding whose verifiers all died scored zero votes
and fell into the same bucket as one three skeptics genuinely killed. Absence of
confirmation is not refutation. They are listed unverified, and re-verifying them is the
second task of the next round.

**One S1 is orchestrator-confirmed.** I traced `%scan-flat-block-files` myself, end to end,
rather than resting on the agent's reading — GA9's practice for S1s:

1. `prune-old-blocks` prunes via `%prunable-flat-files` (blocks.lisp:889), which selects files
   whose entire height range is below the keep window — the OLDEST heights, which live in the
   LOWEST-numbered files. `blk00000.dat` goes first.
2. `init-block-store` calls `%scan-flat-block-files` **unconditionally** (blocks.lisp:616). It is
   the normal restart path, not a reindex-only fallback.
3. That scan is `loop for file from 0 ... while (probe-file path)` (blocks.lisp:538-540) — it
   stops at the first absent file.
4. So after the first automatic prune, the next restart indexes **zero** flat-file blocks.

The second S1 (the FRESH/DIRTY coins-cache flag) is NOT orchestrator-confirmed and rests on its
finder plus whatever verifiers reached it. Confirm it before acting.

What did work: where the panel ran it changed answers. `%scan-flat-block-files` was filed
S2 by its finder and **upgraded to S1** by a verifier who traced the consequence further
than the finder had. That is the pass GA9 explicitly lacked, doing its job.

## Round 2 (2026-09-01, 10 agents): the four S1s are verified, and three of them stand

The first run left four S1s with no verdict at all. A second, deliberately small run (10 agents:
8 verifiers = 4 findings x 2 adversarial lenses, 1 refactor-regression finder, 1 critic) settled
them. **All four verifiers-pairs returned; none of the four was refuted on mechanism, and every
verdict was reached by RUNNING code in the container, not only by reading.**

| # | finding | verdict | severity |
|---|---|---|---|
| 1 | cmpctblock has no anti-DoS work threshold; the replay gate only fires for headers already indexed | **confirmed** | **S1** |
| 2 | deserializer accepts BIP144 with all-empty witness stacks ("Superfluous witness record") | mechanism confirmed, **impact refuted** | **S3** (was S1) |
| 3 | block bodies persisted with no CheckBlock on both IBD paths | **confirmed** | **S1** |
| 4 | BIP143/BIP341 sighash writes nVersion through a `(unsigned-byte 32)`-declared writer | **confirmed by execution** | **S1** |

**#4 was decided by running it.** Its finder wrote "I could not execute the image to determine
which" -- whether SBCL elides the declaration or signals. A verifier ran it:
`(buf-set-u32-le b 0 -2147483648)` -> `SIMPLE-TYPE-ERROR`, and both
`compute-bip143-sighash-real` and `compute-bip341-sighash-real` abort the same way on a real
transaction struct with `:version -2147483648`. There is no benign branch. A miner can mine a
segwit/taproot spend inside a transaction with bit 31 set -- valid to Core, which has no consensus
rule on version -- and our validation aborts. The verifier also corrected the finder: at `d3056bc`
Core's `CTransaction::version` is `uint32_t`, not `int32_t`, which *strengthens* the finding.

**#2 is why the verification pass exists.** Both lenses confirmed the parse divergence exactly as
filed -- and both downgraded it, because the *consequence* does not follow. Every outbound path
re-serializes from the struct rather than echoing received bytes (`store-block` writes
`serialize-witness-block`, blocks.lisp:387; `make-block-message` re-serializes, messages.lisp:431).
Executed: the hostile block parses, and re-serializing it is byte-identical to the canonical one --
same header hash, same merkle root. So we *launder* the block into the encoding Core accepts rather
than following a chain the network rejects. The attacker gains nothing over publishing the
canonical form. It is a strictness gap, not a chain split.

**#1 was measured, and the finder's magnitude was wrong in both directions.** Executed against a
50,000-entry mempool: a replay costs ~13-15 ms and 6.4-16 MB, not the claimed 0.2-0.3 s and 50 MB
(`transaction-wtxid` is cached). The DoS is real and unrate-limited -- `check-peer-rate-limit`
returned T for 10,000 consecutive `cmpctblock` calls -- but it is a smaller constant than filed.
A verifier also found the finding *understated* elsewhere: a replay matching an outstanding
`getblocktxn` re-runs the whole map build and emits another `getblocktxn`, where Core returns early.

### The refactor-regression dimension (it had never run)

Three findings, one of them a regression introduced by the refactor itself and now fixed in this
same branch:

1. **`bl:token-bucket` and `bl:make-token-bucket` were exported but named nothing.** P6d (#551)
   moved the struct to `bitcoin-lisp.ratelimit`; `src/package.lisp`'s `:import-from` list was
   retyped with six names while the `:export` list beside it was carried over verbatim with eight.
   Executed: `eq` NIL, no class, not `fbound`. A caller writing `bl:token-bucket` got a reader
   error. **Fixed here**, plus a new structural ratchet `every-export-names-something` so the shape
   cannot recur -- the orphan-export sweep could never have caught it, because that test asks who
   *calls* an exported **function** and these were not functions.
2. **`fsync-parent-directory` was wired into 3 of its 7 drive sites.** #525 split a file-path and a
   directory-path fsync that had previously collided, but scoped the fix to the file the losing
   definition lived in rather than to the callers' argument shape. Four `rename-file` paths still
   pass a *file* to the *directory* function -- `settings.json` (twice), `mempool.dat`, and the
   wallet backup -- each directly under a comment saying the rename is not durable until the
   directory is synced. `fsync-directory` swallows all errors, so it never complains. Pre-existing,
   but the tree now *looks* fixed, which is worse than the uniform bug it replaced. NOT yet fixed.
3. A third finding plus a set of load-bearing negative results, recorded in the workflow journal.

## Round 3 (10 agents): all 16 S2s verified

Eight agents took two S2s each (grouped by file so each carried related context), plus two on what
I mis-counted as a remaining S1. Every verdict was again settled by RUNNING code, and each carried
a `title_prefix` so index-to-finding alignment could be checked: **16/16 aligned**.

**All 16 S2s were confirmed on mechanism; none was refuted.** Three had their consequence cut to
S3. That is a much lower kill rate than the S1 round, and the likely reason is that an S2 claim is
modest enough to be right more often -- the S1s were where the overreach lived.

| # | finding | verdict |
|---|---|---|
| 0 | *last-checksig-error* / *last-checkmultisig-error* are process-global specials, never rebound, so parallel script-check workers clobber each other's e | **S2** |
| 1 | Lax (pre-BIP66) DER signature parser diverges from Core's ecdsa_signature_parse_der_lax in both directions | **S3** (was S2) |
| 2 | Fee estimator has no `validForFeeEstimation` gate: it tracks reorg re-adds, package submissions, chained children, and transactions accepted while the | **S2** |
| 3 | We never push an unsolicited cmpctblock to peers that selected us as their BIP152 high-bandwidth peer | **S2** |
| 4 | ContextualCheckBlock's UTXO-free half (finality, BIP34 height, witness malleation, block weight) is deferred to reorg time for every non-tip block | **S3** (was S2) |
| 5 | testmempoolaccept validates each transaction in isolation; Core runs multi-tx batches as a package, so a CPFP child is falsely reported "missing-input | **S2** |
| 6 | invalidateblock reorgs only to the invalidated block's parent and never re-activates the best remaining valid chain | **S2** |
| 7 | getblocktemplate returns a cached template verbatim — curtime, bits and target are never refreshed, so on min-difficulty chains the served nBits goes  | **S3** (was S2) |
| 8 | Pruning is not a flush trigger, so block files below tip-288 are unlinked while the on-disk chainstate can be thousands of blocks behind | **S2** |
| 9 | Re-mined transactions are never removed from the reorg disconnect pool, so their still-valid in-mempool children are removed recursively | **S2** |
| 10 | REORG-DISCONNECTED-BLOCKS retains every disconnected block in full, defeating the 20 MB disconnect-pool cap | **S2** |
| 11 | A fork block failing with a non-allowlisted error is neither poisoned nor excluded from candidate selection, so activate-best-chain repeats the same r | **S2** |
| 12 | No ZMQ block-connected, -blocknotify or fee-estimator block notification for blocks connected through a reorg | **S2** |
| 13 | BIP30 is skipped for essentially the whole chain on testnet4/signet/regtest, where Core enforces it at every height | **S2** |
| 14 | bumpfee's MarkReplaced writes `replaced_by_txid` only in memory — the marker is lost on restart | **S2** |
| 15 | bumpfee forces fOverrideFeeRate, skipping the mempool-min-fee and required-fee halves of Core's CheckFeeRate | **S2** |

### ⚠️ A second accounting error of mine, and it wasted two agents

I reported "1 S1 still unverified" and spent two agents on it. There was none. All four S1s had
been settled in round 2; my de-duplication matched findings **by title string**, and the titles I
retyped into the workflow args had different quote characters from the ones in the journal, so the
BIP144 finding failed to match itself and was queued again.

The silver lining is real but accidental: two fresh agents, with no knowledge of round 2, reached
the **same** verdict independently -- mechanism confirmed, consequence refuted, S1 -> S3, each
proving it by executing the round-trip and showing the re-serialized block is byte-identical to the
canonical one. An unintended replication is still evidence. One of them also corrected an older
record: `docs/gap-analysis-9.md:367` claimed the non-canonical encoding reaches the block store; it
does not, because `store-block` writes `serialize-witness-block`.

The lesson is the same one this round already produced once: **match findings by a stable id, not
by prose**. Both of my errors in GA10 were bookkeeping, not analysis -- first collapsing
"never judged" into "refuted", now failing to de-duplicate across rounds.

### Where GA10 stands

| state | count |
|---|---|
| verified this round or in round 2 (executed) | 20 (4 S1-round + 16 S2) |
| round-1 "confirmed", some on a single vote | 26 |
| **still no verdict at all** | **41** (38 S3 + 3 refactor-regression findings) |

## Round 4 (22 agents): GA10 is complete

Every remaining finding now has a verdict. 22 agents, 0 errors, **67 verdicts, 63 of them settled
by running code**. Coverage check: 0 findings missed, 0 index misalignments (three alignment
warnings were the agents echoing a `[S2] ` prefix I had stripped from the stored titles).

| bucket | result |
|---|---|
| the 3 refactor-regression claims | all 3 mechanisms confirmed, **all 3 cut to S3** |
| the 26 round-1 "confirmed" (single vote) | re-checked independently; 12 hold at S2, 1 cut to S3, the rest S3 |
| the 38 never-judged S3s | 2 **upgraded to S2**, 2 refuted, 34 hold |

### The sweep found two S3s that were worse than filed

- **`getnetworkhashps` ignores its `height` argument entirely** and never implements `nblocks = -1`;
  it always anchors at the tip. Confirmed by execution -- `(second params)` never appears in the body.
- **PSBT `complete` trusts the final/partial fields without verifying them.** Core ANDs
  `PSBTInputSignedAndVerified` over every input, which resolves the UTXO and runs `VerifyScript`
  under standard flags; we do not.

### Two refutations, one of which exposed a different bug

- `address-book-add`'s missing update-interval: mechanism true, consequence unreachable, and the
  finding misread what Core's gate blocks.
- Block-relay-only eviction ignoring `fRelevantServices`: **mechanism textually true, consequence
  unreachable because our filter is broken in a *different* way** -- `(not (peer-relays-txs-p p))`
  makes the pass select nobody at all. The refutation is worth more than the finding was.

### ⚠️ Three errors of MINE that the verifiers caught

1. **The fsync finding is not what I published.** I recorded it as a refactor-introduced problem.
   It is not: `git grep fsync-directory 5f4f321` shows the same four call sites, byte-identical,
   before the refactor -- two same-named definitions collided in one package and the
   directory-taking one won, so those sites already fsynced the wrong inode. Nor is it a Core
   divergence: Core calls `DirectoryCommit` in exactly one place (`flatfile.cpp:108`, the block
   allocator -- the one site we get right), and its own settings writer does `RenameOver` with no
   directory sync at all. Our settings path is *more* durable than Core's. **S3, pre-existing,
   not a regression.**
2. **My commit message for #564 said a caller "got a reader error".** Wrong -- the symbol exists
   and reads fine; you get an undefined-function or unknown-type at compile or run time. The
   original finder said "signals", which was right; I introduced the error while writing it up.
   That message also labels #551 as "P6d"; P6d is #562.
3. **The positive control for `every-export-names-something` existed only in that commit message.**
   `refactoring-ratchets-can-actually-fail` carries a control for every other scanner and had none
   for this one -- so the sweep could have silently gone vacuous again and nothing in the tree would
   have said so. Fixed in this change: `%dead-exports` is factored out and the control feeds it a
   probe package whose only export names nothing.

The verifier also confirmed the #564 fix is complete: sweeping all 28 `BITCOIN-LISP*` packages
(2,360 external symbols, wider than the ratchet's own scope) finds no other dead export, and no
exported name anywhere resolves to two different symbol objects -- so no other "export list carried
over, import list retyped" residue exists.

### Final tally

| state | count |
|---|---|
| findings with a verdict | **84 of 84** |
| verified by execution | 83 |
| confirmed | 78 |
| refuted | 6 |

## Summary

| | S1 | S2 | S3 | total |
|---|---|---|---|---|
| survived verification | 2 | 12 | 12 | **26** |
| unverified (not refuted) | 4 | 16 | 38 | 58 |
| candidates found | 6 | 28 | 50 | 84 |

## Findings that survived verification


### S1

#### %scan-flat-block-files stops at the first missing blk file, so a pruned node loses its entire flat block index on restart

- **ours:** `src/storage/blocks.lisp:538-540 (`loop for file from 0 ... while (probe-file path)`), consumed by init-block-store:606-615 and rebuild-block-file-info:706-740`
- **core:** `refs/bitcoin/src/node/blockstorage.cpp:120-145 (BlockTreeDB::LoadBlockIndexGuts reads nFile/nDataPos/nUndoPos out of the block-index DB) and :529-610 (LoadBlockIndexDB); Core never locates blocks by scanning blk files except under -reindex`
- **Core does:** Core persists each CBlockIndex's nFile and nDataPos in the block-index LevelDB and restores them at startup, so a hole in the blk numbering left by pruning is irrelevant -- every surviving file is still addressable.
- **we do:** We rebuild the hash -> flat-file-pos map by probing blk00000.dat, blk00001.dat, ... and stopping at the first name that does not exist. The block index entries DO carry file/data-pos (src/storage/chain.lisp:30-31, persisted in the v2 header index), but nothing ever reads them back to populate block-store-index -- get-block goes through the scanned table only (src/storage/blocks.lisp:443, :518). The sibling undo scanner was fixed for exactly this hazard and says so in its own comment (src/storage/blocks.lisp:334-338: "Enumerated, not counted from 0 until one is missing: rev numbering has holes. Pruning deletes the lowest-numbered files first..."); the blk scanner was not.
- **impact:** prune-flat-block-file deletes blk/rev pairs lowest-number-first. After the first automatic prune, the next restart's scan stops at the first deleted file, so every block in the surviving higher-numbered files -- including the whole 288-block retention window -- is absent from block-store-index. get-block/block-exists-p return NIL for them, so the node cannot serve blocks, cannot read undo data, cannot reorg, and the coinbase-probe crash recovery (src/node/recovery.lisp:96-108) cannot find any committed ancestor. rebuild-block-file-info then produces an empty file-info table, so block-store-total-bytes under-reports and automatic pruning stops working. Worse, cursor-file/cursor-pos reset to the first surviving-or-recreated file, so once the write cursor rolls over (blocks.lisp:117-129) %store-block-flat opens an existing higher-numbered blk file with :if-exists :overwrite at offset 0 and writes over live block data. *flat-block-files* has been the default since 2026-08-26 (blocks.lisp:25-27), so this is the default configuration for a pruned node.
- finder confidence: read-both-trees — **severity raised from S2 by verification**

#### coins-view-cache-sync clears DIRTY but leaves FRESH set, so coins already written to LevelDB are later dropped on spend without an erase

- **ours:** `src/storage/coins-view-cache.lisp:369-372 (and the FRESH branch it feeds at :307-312, entered from :896)`
- **core:** `refs/bitcoin/src/coins.cpp:291-300 (CCoinsViewCache::Sync) -> refs/bitcoin/src/coins.h:279-295 (CoinsViewCacheCursor::NextAndMaybeErase) and refs/bitcoin/src/coins.h:175-182 (SetClean); FRESH contract documented at refs/bitcoin/src/coins.h:150-159`
- **Core does:** Sync builds a cursor with will_erase=false. For every flagged entry NextAndMaybeErase either erases it (spent) or calls SetClean(), which zeroes m_flags entirely -- BOTH DIRTY and FRESH. coins.h states the invariant verbatim: "Marking a coin as FRESH when it exists unspent in the parent cache will cause a consensus failure, since it might not be deleted from the parent when this cache is flushed."
- **we do:** coins-view-cache-sync writes every dirty entry into the base LevelDB batch, then walks the table a second time doing only `(setf (ce-dirty ce) nil)`. ce-fresh is never cleared, and spent tombstones are left in the table rather than erased. The entry is now present-and-unspent in the base while still flagged FRESH in the cache.
- **impact:** %coin-view-iterate calls coins-view-cache-sync (coins-view-cache.lisp:896), and that is the path taken by gettxoutsetinfo, dumptxoutset, scantxoutset and the assumeutxo hash check (src/rpc/blockchain.lisp:1170, :1535, :1786; src/node/assumeutxo.lisp:290). After any one of those RPCs, every non-coinbase output created since the last full flush is on disk AND still FRESH. When such a coin is later spent, coins-view-cache-spend takes the ce-fresh branch, REMHASHes the entry and stages no erase, so the coin survives in the coins DB as unspent. The very next lookup of that outpoint re-fetches it from the base and reports it unspent, so a second spend of it -- in a later transaction of the same block, a later block, or after a restart -- is ACCEPTED. That is a consensus split (we accept a double-spend Core rejects) plus silent UTXO-set inflation; gettxoutsetinfo/hash_serialized_3 and any assumeutxo snapshot taken afterwards are also wrong. The existing regression test (tests/storage/storage-tests.lisp:1611) asserts dirty-count is zero after the sync but never inspects fresh, so it passes.
- finder confidence: read-both-trees


### S2

#### -rpcpassword / -rpcauth / -rpcuser / -torpassword are written to debug.log in cleartext; Core masks them as ****

- **ours:** `src/node/init.lisp:1486-1497 (%log-args)`
- **core:** `refs/bitcoin/src/common/args.cpp:874-886 (logArgsPrefix), registrations at refs/bitcoin/src/init.cpp:602, 707, 712, 716`
- **Core does:** AddArg tags -torpassword, -rpcauth, -rpcpassword and -rpcuser with ArgsManager::SENSITIVE (init.cpp:602/707/712/716). logArgsPrefix, which emits every `Config file arg:` and `Command-line arg:` line, does `std::string value_str = (*flags & SENSITIVE) ? "****" : value.write();` (args.cpp:883), so the secret never reaches the log.
- **we do:** %log-args emits the raw JSON rendering for every KNOWN option, with no notion of a sensitive row: `(defer-log :info "Config file arg: ~:[~;[~:*~A] ~]~A=~A" ... name json)` (init.lisp:1490-1491) and `(defer-log :info "Command-line arg: ~A=~A" (car cell) (cdr cell))` (init.lisp:1497). Nothing in src/logging.lisp, src/config/ or src/node/init.lisp masks anything (grep for **** / sensitive / redact finds no masking code). -rpcpassword, -rpcuser, -rpcauth and -torpassword are all registered options (src/config-options.lisp:53,54,63,126), so known-config-option-p is true and they are logged.
- **impact:** A node started with `-rpcpassword=<secret>` (or with `rpcpassword=` / `rpcauth=` / `torpassword=` in bitcoin.conf) writes the plaintext RPC password, the rpcauth salt$HMAC and the Tor control password into debug.log at every start. debug.log is the file operators tail, ship to log aggregators and paste into bug reports; on Core the same command line leaks nothing. Anyone with read access to the log gets full RPC control of the node (and, via the Tor control password, of the local Tor daemon).
- finder confidence: read-both-trees

#### -rpcwhitelist / -rpcwhitelistdefault are accepted at startup but never enforced, so a user the operator restricted gets full RPC

- **ours:** `src/config-options.lisp:404 (inside define-core-only-options, src/config-options.lisp:388); enforcement site missing in src/rpc/server.lisp:871 (rpc-handler) and src/rpc/server.lisp:411 (handle-batch-request)`
- **core:** `refs/bitcoin/src/httprpc.cpp:144-158, 176-189, 306-316`
- **Core does:** InitRPCAuthentication builds g_rpc_whitelist from every -rpcauth-authenticated user named in a -rpcwhitelist spec, and sets g_rpc_whitelist_default = GetBoolArg("-rpcwhitelistdefault", !GetArgs("-rpcwhitelist").empty()) (httprpc.cpp:306-316). HTTPReq_JSONRPC then gates EVERY request on it: a user with no whitelist entry while g_rpc_whitelist_default is set gets HTTP 403 for all methods (httprpc.cpp:144-148); a user WITH a whitelist gets 403 for any method not in it, checked both for the singleton request (:154-158) and for every member of a batch before any of them runs (:176-189).
- **we do:** check-auth (server.lisp:800) returns the authenticated username exactly as Core does, and its docstring even says the name is returned "because Core threads it out of RPCAuthorized (httprpc.cpp:84) for -rpcwhitelist to key on" — but nothing ever consults it. -rpcwhitelist and -rpcwhitelistdefault are registered by define-core-only-options, i.e. parsed, accepted, and dropped. dispatch-rpc-method (server.lisp:68) looks up the method in *rpc-methods* with no per-user filter. Startup does emit one warning listing accepted-but-unimplemented options (src/node/init.lisp:1573-1577), so it is not literally silent, but the node still starts and serves.
- **impact:** An operator who follows Core's documented least-privilege recipe — an -rpcauth user for a monitoring/watchtower process plus -rpcwhitelist=monitor:getblockcount,getblockchaininfo — gets, on this node, a credential with the FULL RPC surface: stop, sendrawtransaction, generatetoaddress, setban, and every wallet method. The same command line on Core answers 403 for all of them. This is an authorization control that fails OPEN. The define-core-only-options docstring's reasoning ("accepting is not implementing" so Core-style command lines start) is sound for logging/cosmetic flags but is wrong for an access-control flag: for -rpcwhitelist, rejecting the option (or refusing to start) is the safe reading, and accepting -rpcwhitelistdefault=1 while granting everything to everyone is the exact inverse of what it asks for.
- finder confidence: read-both-trees

#### /rest/spenttxouts serializes the on-disk compressed CBlockUndo codec instead of Core's REST format, and its JSON omits Core's leading coinbase array

- **ours:** `src/rpc/rest.lisp:483-511 (%rest-spenttxouts), src/rpc/rest.lisp:506 calling bl.store:serialize-block-undo; src/storage/block-undo.lisp:34-70; src/rpc/rest.lisp:513-537 (%block-undo-json)`
- **core:** `refs/bitcoin/src/rest.cpp:277-289 (SerializeBlockUndo), refs/bitcoin/src/rest.cpp:293-296 (BlockUndoToJSON), refs/bitcoin/src/primitives/transaction.h:152 (CTxOut::SERIALIZE_METHODS)`
- **Core does:** rest_spent_txouts uses a REST-SPECIFIC serializer, not the rev-file codec: WriteCompactSize(vtxundo.size() + 1), then WriteCompactSize(0) as an empty list standing in for the coinbase, then per transaction WriteCompactSize(vprevout.size()) followed by `coin.out.Serialize(stream)` — a bare CTxOut, i.e. int64 LE nValue plus CompactSize-prefixed scriptPubKey, with NO height, NO coinbase flag and NO amount/script compression (rest.cpp:277-289). The JSON form likewise pushes an empty array first for the coinbase before the per-transaction arrays (rest.cpp:295).
- **we do:** %rest-spenttxouts hands tx-undos straight to bl.store:serialize-block-undo, which is the DISK codec (its own file header documents it as Core's undo.h format): outer CompactSize is (length tx-undos) with no +1 and no leading zero, and each coin is written by bb-write-undo-coin as Core VARINT(height*2+coinbase), an 0x00 dummy byte when height>0, then bb-write-compressed-tx-out (TxOutCompression of value and script). The docstring at rest.lisp:484-489 asserts this is "Core's CBlockUndo serialization, which is the same codec the rev files use" — that is the mistake: Core deliberately does NOT use the rev-file codec here. %block-undo-json emits one array per non-coinbase transaction with no leading empty array.
- **impact:** Every /rest/spenttxouts/<hash>.bin and .hex response is undecodable by any client written against Core: the outer count is short by one, the coinbase placeholder is missing, and each coin carries extra leading VARINT bytes and a compressed (not raw) amount and script. A client that decodes it anyway reads garbage amounts and scripts. On the .json side the arrays are shifted by one, so a client indexing result[i] for block transaction i reads the coins of transaction i+1 — silently wrong prevout values attributed to the wrong transaction. Neither form errors; both look plausible.
- finder confidence: read-both-trees

#### A negated repeatable option (-noX) is appended to the list as the literal string "0" instead of clearing it; -norpcauth kills the RPC server, -noonlynet/-nodebugexclude refuse to start

- **ours:** `src/config/args.lisp:40-56 (interpret-arg), src/config/args.lisp:78-85 (parse-cli-args), src/node/args.lisp:35-39 (collected-key-options scan)`
- **core:** `refs/bitcoin/src/common/settings.cpp:203-246 (GetSettingsList), :240, :264, :268-274; refs/bitcoin/src/common/args.cpp:367-374 (GetArgs)`
- **Core does:** For list options (GetArgs -> GetSettingsList) a negation ERASES the span up to and including itself and blocks every lower-precedence source: `SettingsSpan::begin() { return data + negated(); }` (settings.cpp:264) where negated() is the position after the last `false` (settings.cpp:268-274), plus `done |= span.negated() > 0` (settings.cpp:240) and the prev_negated_empty gate at :243 that also suppresses the config-file "zombie" values. So `-rpcauth=a -rpcauth=b -norpcauth` yields an EMPTY list, and `-noconnect` with `connect=...` in bitcoin.conf yields an empty list too.
- **we do:** interpret-arg turns any -noKEY into (KEY . "0") (args.lisp:52-53) and parse-cli-args keeps EVERY occurrence of a repeatable key (args.lisp:81-82). config-alist->start-node-plist then collects every value verbatim, including the "0" (node/args.lisp:35-39). There is no negation-clears-the-span rule anywhere in src/config/.
- **impact:** Concretely reachable from Core's own test suite. (a) rpc_users.py:178-181 restarts with `[-rpcauth=user1..., -rpcauth=user2..., -norpcauth]`; we build :rpc-auth = (user1spec user2spec "0"), parse-rpcauth-entry rejects "0" (src/rpc/server.lisp:750-764), %parse-rpcauth-credentials returns :invalid (src/rpc/server.lisp:1106-1113) and start-rpc-server returns NIL (src/rpc/server.lisp:1196-1198) — the node comes up with NO RPC at all, where Core comes up with RPC live and the two credentials revoked. (b) `-noonlynet` gives onlynets = ("0"), and conf-parse-network-name signals "Unknown network specified in -onlynet" (src/config/values.lisp:229) — startup failure on a command line Core accepts. (c) `-nodebugexclude` gives exclude = ("0"), and apply-log-categories signals "Unsupported logging category -debugexclude=0." (src/logging.lisp:445-447) — same. (d) feature_config_args.py:395 restarts with `-noconnect` against a bitcoin.conf that already carries `connect=0` (test_framework/util.py:580-581): we get :connect-nodes = ("0" "0"), which is not `equal` to '("0") (src/node/init.lisp:406), so instead of disabling outbound we log "Connecting only to -connect peers: 0, 0" and repeatedly try to dial a host named "0". The same shape means `-noconnect` on the command line does NOT clear a real `connect=<peer>` in bitcoin.conf — we keep dialing the peer the operator just disabled.
- finder confidence: read-both-trees

#### Every dial counts an addrman failure — Core suppresses failure counting when the node looks offline, and never counts it for manual/addr-fetch dials

- **ours:** `src/node/peers.lisp:206-231 (`:count-failure t` at :231) and :297`
- **core:** `refs/bitcoin/src/net.cpp:2886-2891, 494-497; 2422, 2541, 2986, 1905`
- **Core does:** ConnectNode calls `addrman.Attempt(target_addr, fCountFailure)` only `if (!proxyConnectionFailed)`. fCountFailure comes from OpenNetworkConnection, and ThreadOpenConnections computes it as `count_failures{((int)outbound_ipv46_peer_netgroups.size() + outbound_privacy_network_peers) >= std::min(m_max_automatic_connections - 1, 2)}` with the comment "Don't record addrman failure attempts when node is offline. This can be identified since all local network connections (if any) belong in the same netgroup." Every other OpenNetworkConnection call site — ADDR_FETCH/-seednode (:2422), -connect (:2541), addnode (:2986), addconnection (:1905) — passes `false`.
- **we do:** %record-dial-attempt hard-codes `:count-failure t` and is called from establish-outbound-peer (which serves -addnode, -connect, -seednode and the addconnection test RPC), from replace-disconnected-peers and from do-feeler-connection. %record-outbound-result (:297) does the same on the failure branch. There is no online/offline test and no proxy-failure carve-out.
- **impact:** An offline episode (link down, laptop resumed, node started before the network is up, or a dead Tor proxy for the whole onion set) charges a real failure against every address we cycle through, on top of Core's own m_last_good epoch guard which limits it to one per address per epoch. A few offline/online cycles push nAttempts past ADDRMAN_RETRIES=3 with last_success still 0, at which point addr-info-terrible-p is true for the whole table: those addresses stop being returned by getaddr, become preferred overwrite targets in new buckets, and their GetChance collapses. Manual addnode/-connect targets that are simply down accrue the same damage, which Core never does. This is distinct from the GA-known "addrman failure accounting" item (attempts not being recorded at all from steady-state dials); the recording now exists but is unconditional in the direction Core deliberately gates.
- finder confidence: read-both-trees

#### Eviction's disadvantaged-network reserve protects the NEWEST connections instead of the longest-connected (comparator inverted)

- **ours:** `src/node/eviction.lisp:151-157`
- **core:** `refs/bitcoin/src/node/eviction.cpp:64-72, 104-175`
- **Core does:** ProtectEvictionCandidatesByRatio protects, per disadvantaged network, using CompareNodeNetworkTime whose final term is `return a.m_connected > b.m_connected;` — descending connect time — and EraseLastKElements then protects the LAST k, i.e. the SMALLEST m_connected = the longest-connected peers of that network. This is the same direction as ReverseCompareNodeTimeConnected used for the remaining uptime half (eviction.cpp:21-24, 175), and the file's comment says the point is to "protect the half of the remaining nodes which have been connected the longest … and precludes attacks that start later."
- **we do:** %evict-protect-by-ratio calls %evict-erase-last-k with `(lambda (a b) (< (peer-connect-time a) (peer-connect-time b)))` for the per-network pass. %evict-erase-last-k (eviction.lisp:69-81) sorts and protects `(subseq sorted (- (length sorted) n))` — the last n. Ascending connect-time puts the oldest first and the most recent last, so the protected set is the most RECENTLY connected peers of that network. The final uptime pass two lines later (:167-171) correctly uses `>`, so the two passes disagree with each other.
- **impact:** The quarter of inbound slots reserved for onion / I2P / CJDNS / localhost peers is handed to whoever connected most recently. An attacker who repeatedly opens fresh inbound connections over Tor (or from localhost, or CJDNS) is guaranteed the reserved protected slots on every admission, while our long-established peers on those same networks fall back into the eviction pool — inverting the anti-"attacks that start later" property this pass exists to provide. The existing tests (tests/networking/dos-protection-tests.lisp:596, eclipse-dos-tests.lisp:1989) only assert that SOME onion peer survives, so they pass either way. This is distinct from the GA-known "inbound eviction protections" item, which was about the missing passes/k-values; the passes are present, one comparator inside them points the wrong way.
- finder confidence: read-both-trees

#### Gossiped addresses are relayed immediately, one addr message per address — no m_addrs_to_send queue and no poisson broadcast timer

- **ours:** `src/networking/protocol.lisp:1150-1158`
- **core:** `refs/bitcoin/src/net_processing.cpp:160, 1130-1140 (PushAddress), 5570-5600 (MaybeSendAddr)`
- **Core does:** RelayAddress calls PushAddress, which only appends the address to the destination peer's `m_addrs_to_send` vector (capped at MAX_ADDR_TO_SEND=1000, with random replacement when full). Nothing is sent there. MaybeSendAddr later flushes the whole accumulated vector as ONE addr/addrv2 message and re-arms `m_next_addr_send = current_time + rand_exp_duration(AVG_ADDRESS_BROADCAST_INTERVAL)` (30 s mean, exponentially distributed, net_processing.cpp:160,5573), filtering m_addr_known on the same pass.
- **we do:** relay-address ranks eligible peers and, inside the same loop, calls `(build-addr-response p (list peer-addr))` and `(send-message p msg)` — an immediate, single-address addr/addrv2 message per relayed address per destination. Grep confirms there is no addrs-to-send queue, no next-addr-send timer and no MaybeSendAddr equivalent anywhere in src/ (only the separate 24 h local-address self-announcement at protocol.lisp:2545+ has a timer).
- **impact:** Timing correlation: a peer watching our addr output sees a message the instant we accept a gossiped address from someone else, which is exactly the linkage Core's exponential broadcast timer exists to destroy — it lets an observer infer when and from where we learned each address and helps map our peer topology. Also multiplies bandwidth/message count (24-byte header + varint per address instead of up to 1000 batched) and gives a small per-message amplification: one 10-address addr from an attacker becomes up to 20 outbound addr messages.
- finder confidence: read-both-trees

#### IsBadPort is absent: automatic outbound dials will connect to any gossiped port (SMTP, SSH, MySQL, IRC, …)

- **ours:** `src/networking/addrman.lisp:535-550`
- **core:** `refs/bitcoin/src/net.cpp:2854 + refs/bitcoin/src/netbase.cpp:847-935`
- **Core does:** ThreadOpenConnections rejects a selected addrman candidate with `if (nTries < 50 && (addr.IsIPv4() || addr.IsIPv6()) && IsBadPort(addr.GetPort())) continue;`. IsBadPort is an explicit deny-list of ~90 ports (1, 7, 9, 20-25, 53, 110, 119, 123, 143, 179, 389, 465, 512-515, 587, 636, 993, 995, 3306, 3389, 5432, 5900, 6000, 6667, 27017, …) documented in doc/p2p-bad-ports.md. Core also warns about them for -bind/-port (init.cpp:2135, 2169).
- **we do:** There is no IsBadPort equivalent anywhere in src/ (grep for bad-port/IsBadPort returns nothing). select-dialable-address — the single filter every automatic selection path is required to go through (outbound slots, block-relay slots, feelers) — filters only on dialable-network-p and reachable-network-p; the port is passed straight to connect-peer. address-book-add likewise accepts any port, and relay-address gossips such records onward.
- **impact:** Any peer can gossip `victim-ip:25` / `:22` / `:3306` / `:6667`; we store them, select them, open a TCP connection and speak the Bitcoin protocol at an arbitrary third-party service, and re-gossip the address to two more nodes. That turns the node into an unwitting cross-protocol attack / port-scanning amplifier against arbitrary hosts (the exact scenario doc/p2p-bad-ports.md exists for), and wastes automatic outbound slots on addresses that can never complete a handshake.
- finder confidence: read-both-trees

#### Network-only options (-port, -rpcport, -bind, -connect, -addnode, -wallet, -walletdir) are honored from bitcoin.conf's default section on non-mainnet chains; Core ignores them AND refuses to start

- **ours:** `src/node/args.lisp:281-287 (conf = sections then globals; merged = cli + settings + conf, first ASSOC wins)`
- **core:** `refs/bitcoin/src/common/args.cpp:875-878 (UseDefaultSection), :134-146 (GetUnsuitableSectionOnlyArgs); refs/bitcoin/src/common/settings.cpp:181-184; refs/bitcoin/src/init.cpp:944-951; NETWORK_ONLY registrations at refs/bitcoin/src/init.cpp:539,548,550,575,708,713 and src/wallet/init.cpp:71,73`
- **Core does:** `UseDefaultSection` returns false for a NETWORK_ONLY arg whenever m_network != "main" (args.cpp:875-878), which passes ignore_default_section_config=true into GetSetting/GetSettingsList, and settings.cpp:181-184 then drops the default-section value entirely. On top of that, GetUnsuitableSectionOnlyArgs (args.cpp:134-146) collects any network-only arg that is set ONLY in the default section, and init.cpp:944-951 turns that into a hard `InitError("Config setting for %s only applied on %s network when in [%s] section.")` — the node refuses to start.
- **we do:** args->start-node-plist appends the [network] section entries in front of the global-area entries and lets first-ASSOC win, with no notion of a network-only option and no unsuitable-section check. A key present only in the global area is therefore applied on every chain. Nothing in src/config/ or src/node/ implements either half (grep for "only applied on" finds nothing).
- **impact:** A shared bitcoin.conf whose global area carries `rpcport=8332`, `port=8333`, `connect=<mainnet peer>`, `addnode=<mainnet peer>` or `wallet=<name>` silently applies those to a testnet4/signet/regtest node here. Core stops with a message naming the option; we bind the mainnet RPC port on a testnet node, or dial mainnet peers from a testnet node. This is exactly the accident the NETWORK_ONLY flag and the init error were added to prevent.
- finder confidence: read-both-trees

#### Outbound netgroup-diversity set is built from ALL peers including inbound, so free inbound connections can veto our outbound replacement dials

- **ours:** `src/node/peers.lisp:647-667`
- **core:** `refs/bitcoin/src/net.cpp:2651-2687, 2826`
- **Core does:** ThreadOpenConnections builds `outbound_ipv46_peer_netgroups` by switching on `pnode->m_conn_type` and explicitly BREAKS (contributes nothing) for INBOUND, ADDR_FETCH, FEELER and PRIVATE_BROADCAST, with the comment "We currently don't take inbound connections into account. Since they are free to make, an attacker could make them to prevent us from connecting to certain peers." Only MANUAL / OUTBOUND_FULL_RELAY / BLOCK_RELAY insert a group, and Tor/I2P/CJDNS peers are counted separately (outbound_privacy_network_peers) instead of contributing a group. The set is then used at net.cpp:2826 to reject a candidate in an already-occupied netgroup.
- **we do:** replace-disconnected-peers computes `used-addrs` as `(mapcar #'peer-address (node-peers node))` — the whole peer list, inbound peers included — and `used-groups` from that, then at :665-667 skips any candidate whose /16 ip-netgroup is already in `used-groups`. Feeler, addr-fetch and block-relay peers are also folded in, and onion/i2p/cjdns peers are not carved out.
- **impact:** An attacker occupying inbound slots (114 by default, *max-inbound-connections*, and inbound connections cost the attacker nothing) from addresses spread across the /16 groups of our candidate list suppresses every outbound replacement dial to those groups. Because node-known-addresses is a static candidate list built once by connect-to-peers, covering its groups can drive replacement to zero while our outbound peers die off — the precise eclipse primitive Core's comment names. Even without an attacker, a busy node with many inbound peers silently blocks legitimate replacements that share a /16 with any inbound peer, so the outbound full-relay target is chronically under-filled.
- finder confidence: read-both-trees

#### The "-peerblockfilters without -blockfilterindex" refusal is nested inside (when prune ...), so an unpruned node advertises NODE_COMPACT_FILTERS it cannot serve

- **ours:** `src/node/init.lisp:239-256 (the check at :253-254 sits inside the `(when prune` opened at :239)`
- **core:** `refs/bitcoin/src/init.cpp:992-999`
- **Core does:** The check is unconditional in AppInitParameterInteraction and gates the service bit: `if (args.GetBoolArg("-peerblockfilters", ...)) { if (!g_enabled_filter_types.contains(BlockFilterType::BASIC)) return InitError(_("Cannot set -peerblockfilters without -blockfilterindex.")); g_local_services = ServiceFlags(g_local_services | NODE_COMPACT_FILTERS); }` (init.cpp:992-999). It is nowhere near the -prune block (init.cpp:1001-1008).
- **we do:** %init-parameters puts `(when (and peer-block-filters (not blockfilterindex)) (config-error "Cannot set -peerblockfilters without -blockfilterindex."))` between the -txospenderindex and -reindex-chainstate prune checks, all inside `(when prune ...)`. With -prune absent the form is never evaluated. %init-peer-features-and-wallet then unconditionally does `(setf bl:*peer-block-filters* (and peer-block-filters t))` (src/node/init.lisp:837) — its docstring at :835 claims the gate happened in %INIT-PARAMETERS, which is only true under -prune.
- **impact:** `bitcoin-lisd -peerblockfilters=1` with no -blockfilterindex starts happily where Core refuses. We then set NODE_COMPACT_FILTERS in our advertised service flags (src/networking/peer.lisp:909-911), so BIP157 light clients pick us as a filter server, while %cf-serving-index returns NIL (src/networking/protocol.lisp:2147-2153) and handle-getcfilters/getcfheaders/getcfcheckpt silently return nothing. Every light client that selects us stalls on a request that is never answered and never rejected. Also a plain misconfiguration Core would have named at startup.
- finder confidence: read-both-trees

#### The RPC coins sync advances the persisted coins best-block pointer without persisting the block index, so a later crash makes the node refuse to start

- **ours:** `src/storage/coins-view-cache.lisp:365-366 (coins-view-cache-sync stages set-best-block) called from :896; compare src/node/flush.lisp:240-283 where the pointer is only ever meant to move as Phase 2 of the 3-phase commit`
- **core:** `refs/bitcoin/src/rpc/blockchain.cpp:1075 (gettxoutsetinfo calls ForceFlushStateToDisk(wipe_cache=false)) -> refs/bitcoin/src/validation.cpp:2780-2812 (FlushChainstateBlockFile, then WriteBlockIndexDB, then CoinsTip().Sync())`
- **Core does:** Every path that syncs the coins to disk from an RPC goes through the full FlushStateToDisk, which flushes the block/undo files and writes the block index DB BEFORE syncing the coins, precisely so the coins DB can never name a block the block index does not contain.
- **we do:** coins-view-cache-sync writes the coin deltas AND coins-view-batch-set-best-block for the cache's current block, but nothing on that path saves chainstate.dat or the header index. save-header-index has only three callers (src/node/flush.lisp:250 and two startup/reindex sites in src/node/init.lisp), so block index entries accepted since the last periodic flush are memory-only.
- **impact:** Run gettxoutsetinfo / dumptxoutset / scantxoutset, then crash or get OOM-killed before the next periodic flush (up to 600 s or 25 000 blocks later). On restart the coins DB's best-block names a block whose entry was never written to the header index, so reconcile-coins-db-best-block cannot place it and returns :unresolvable (src/node/recovery.lisp:38-46); src/node/init.lisp:812-815 then aborts start-up with "Refusing to start: the UTXO set names a block this node cannot place. Recover by reindexing from the block files, or restore a backup." A routine read-only RPC thus converts an ordinary unclean shutdown into a mandatory reindex.
- finder confidence: read-both-trees


### S3

#### -bind / -whitebind together with an explicit -listen=0 is accepted; Core makes it a hard init error

- **ours:** `src/config/values.lisp:313-336 (conf-effective-listen-flags checks only the -listenonion contradiction)`
- **core:** `refs/bitcoin/src/init.cpp:1016-1020`
- **Core does:** `size_t nUserBind = args.GetArgs("-bind").size() + args.GetArgs("-whitebind").size(); if (nUserBind != 0 && !args.GetBoolArg("-listen", DEFAULT_LISTEN)) return InitError(Untranslated("Cannot set -bind or -whitebind together with -listen=0"));` — an explicit -listen=0 beats the -bind soft-set, and Core refuses rather than starting deaf.
- **we do:** conf-effective-listen-flags replays Core's soft-set chain correctly (an explicit -listen wins over the -bind soft-set, values.lisp:319-321) and then only signals for the -listen=0/-listenonion=1 pair (values.lisp:333-334). The -bind/-whitebind case falls through: config-alist->start-node-plist still sets :listen-bind from the -bind value (src/node/args.lisp:84-89) and :listen NIL (src/node/args.lisp:118).
- **impact:** `-bind=127.0.0.1 -listen=0` starts a node that records a bind address and never listens on it. The operator's explicit binding is silently discarded where Core names the contradiction and stops. Same for -whitebind, where the discarded value also carried net permissions.
- finder confidence: read-both-trees

#### -forcednsseed=1 with -dnsseed=0 (or with -connect) is silently ignored instead of being an init error

- **ours:** `src/config-options.lisp:336-338; src/node/peers.lisp:348-352`
- **core:** `refs/bitcoin/src/init.cpp:1010-1013`
- **Core does:** `if (args.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED) && !args.GetBoolArg("-dnsseed", DEFAULT_DNSSEED)) return InitError(_("Cannot set -forcednsseed to true when setting -dnsseed to false."));` Because InitParameterInteraction already soft-set -dnsseed=0 for -connect / -maxconnections<=0 / a clearnet-free -onlynet (init.cpp:777-784, 833-842), this also fires for `-forcednsseed -connect=x`.
- **we do:** The option row just sets *force-dns-seed* (config-options.lisp:338), and the only consumer guards on `(and *force-dns-seed* *dns-seed-enabled*)` (src/node/peers.lisp:352). No consistency check exists anywhere (grep for "forcednsseed" finds only these two sites plus the defvar).
- **impact:** `-forcednsseed -connect=<peer>` or `-forcednsseed -nodnsseed` starts a node on which -forcednsseed does nothing, where Core stops and tells the operator the two options contradict. The operator believes DNS seeding is being forced and never finds out it is not.
- finder confidence: read-both-trees

#### /rest/block/<hash>.json renders getblock verbosity 2; Core renders verbosity 3 (SHOW_DETAILS_AND_PREVOUT)

- **ours:** `src/rpc/rest.lisp:101-108, specifically src/rpc/rest.lisp:106`
- **core:** `refs/bitcoin/src/rest.cpp:470-473 (rest_block_extended) and refs/bitcoin/src/rest.cpp:1146; mapping at refs/bitcoin/src/rpc/blockchain.cpp:867-874`
- **Core does:** /rest/block/ is served by rest_block_extended, which passes TxVerbosity::SHOW_DETAILS_AND_PREVOUT (rest.cpp:472). In getblock that verbosity level is reached only at verbosity 3 (blockchain.cpp:867-874), and it adds a "prevout" object (generated, height, value, scriptPubKey) to every non-coinbase vin. /rest/block/notxdetails/ uses SHOW_TXID, i.e. verbosity 1.
- **we do:** %rest-block calls (rpc-getblock node (list body (if notxdetails 1 2))) — verbosity 1 for notxdetails (correct) and verbosity 2 for the plain endpoint. Our getblock does implement verbosity 3 (blockchain.lisp:266-274, :prevouts (>= verbosity 3)), so the capability exists and is simply not requested from REST.
- **impact:** A REST client reading /rest/block/<hash>.json gets vins with no "prevout" member at all, so it cannot see the spent output's value, height, coinbase flag or scriptPubKey — the data that makes the endpoint usable for block explorers and fee analysis without a second round trip per input. The same request against Core returns them.
- finder confidence: read-both-trees

#### /rest/mempool/contents.json ignores the ?verbose= and ?mempool_sequence= query parameters and always serves the verbose dump

- **ours:** `src/rpc/rest.lisp:171-179, specifically src/rpc/rest.lisp:176`
- **core:** `refs/bitcoin/src/rest.cpp:796-821`
- **Core does:** rest_mempool reads ?verbose= (default "true") and ?mempool_sequence= (default "false"), rejects anything other than the literal strings "true"/"false" with HTTP 400 naming the parameter, rejects verbose+mempool_sequence together with HTTP 400 and a hint, then calls MempoolToJSON(pool, verbose, mempool_sequence) — so ?verbose=false yields a plain array of txids and ?verbose=false&mempool_sequence=true yields {"txids":[...],"mempool_sequence":N}. It also answers HTTP 400 (not 404) for a path other than info/contents (rest.cpp:787-789).
- **we do:** %rest-mempool hardcodes (rpc-getrawmempool node (list t)) for "contents" — always verbose, no query-parameter parsing at all, no validation, no conflict check. (A malformed path does get a 400, which matches.)
- **impact:** A REST client asking for the cheap form gets the expensive one: on a full mempool the response is roughly an order of magnitude larger than the txid array it requested, and it is a different JSON TYPE (object keyed by txid rather than array), so the client's parse fails outright rather than degrading. Since /rest/ is unauthenticated whenever -rest is enabled, this is also an amplification the caller cannot opt out of. And, as with getrawmempool above, the mempool_sequence snapshot Core documents for ZMQ consumers is unreachable through REST too.
- finder confidence: read-both-trees

#### A negative -maxconnections is accepted and clamped instead of being an init error

- **ours:** `src/config-options.lisp:50 (:type :int, no :min); src/node/peers.lisp:861-871 (automatic-inbound-capacity clamps with (max 0 ...))`
- **core:** `refs/bitcoin/src/init.cpp:1032-1036`
- **Core does:** `int user_max_connection = args.GetIntArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS); if (user_max_connection < 0) { return InitError(Untranslated("-maxconnections must be greater or equal than zero")); }`
- **we do:** The option row parses the integer with no lower bound. automatic-inbound-capacity clamps the result with (max 0 ...) so inbound capacity becomes 0, and conf-effective-listen-flags separately reads `-maxconnections <= 0` as the -connect-style soft-set of -listen=0 (src/config/values.lisp:324-327). The node starts, listens for nobody and seeds no DNS.
- **impact:** A typo such as `-maxconnections=-1` (or a shell-mangled value) starts a node with no inbound capacity, listening disabled and DNS seeding disabled, instead of the immediate refusal Core gives. The node looks up but never gains peers, and nothing in the log names the cause.
- finder confidence: read-both-trees

#### Dotted section keys in bitcoin.conf (main.rpcport=..., test.connect=...) are treated as unknown options and dropped

- **ours:** `src/config/conf.lisp:78-111 (parse-bitcoin-conf-sections), src/config/args.lisp:40-56 (interpret-arg never splits on #\.)`
- **core:** `refs/bitcoin/src/common/config.cpp:55-65; refs/bitcoin/src/common/args.cpp:76-90 (InterpretKey)`
- **Core does:** GetConfigOptions builds `name = prefix + key` (config.cpp:56) and ReadConfigStream passes it through InterpretKey, which splits the key at the first '.' into result.section + result.name (args.cpp:80-84) before the ro_config[section][name] store (config.cpp:109). So `main.rpcport=8888` written anywhere in the file — with or without a `[main]` header — is a main-section setting. Core's own argsman_tests exercises the dotted spelling directly (src/test/argsman_tests.cpp:788 builds `prefix = section + "."`).
- **we do:** parse-bitcoin-conf-sections only recognises `[section]` header lines (conf.lisp:65-71); a key is taken whole and handed to interpret-arg, which strips a `no` prefix but never a `section.` prefix. `main.rpcport` therefore fails known-config-option-p and is reported by unknown-config-file-keys as "Ignoring unknown configuration value main.rpcport" (src/node/init.lisp:1567-1570).
- **impact:** An operator who scopes settings with the dotted spelling instead of section headers gets a node running entirely on defaults for those options. It is visible (one warning line per key) rather than silent, but a config Core reads and applies is one we discard.
- finder confidence: read-both-trees

#### Inbound admission ban/discourage checks have no NoBan permission exemption

- **ours:** `src/node/eviction.lisp:284-312`
- **core:** `refs/bitcoin/src/net.cpp:1799-1813`
- **Core does:** CreateNodeFromAcceptedSocket guards both checks with the permission flag: `if (!NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan) && banned) return;` and `if (!NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan) && nInbound + 1 >= m_max_inbound && discouraged) return;`. The flags are computed from vWhitelistedRangeIncoming just above (net.cpp:1772).
- **we do:** inbound-connection-allowed-p drops on `(peer-banned-p host)` and on `(and (peer-discouraged-p host) (>= (1+ inbound-count) *max-inbound-connections*))` with no consultation of peer-permission-flags, even though that function exists (netaddress.lisp:735) and record-misbehavior already uses +perm-noban+.
- **impact:** A peer the operator explicitly whitelisted with `-whitelist=noban@…` is still refused at accept time if its address happens to be banned or discouraged — the whole point of the option is that such a peer survives our opinion of it. Operationally this makes -whitelist=noban unreliable on shared/NAT addresses and on regtest/functional-test setups where 127.0.0.1 can get discouraged.
- finder confidence: read-both-trees

#### JSON-RPC batch members never get the named-argument transform, so any batch call using named params fails with -32603

- **ours:** `src/rpc/server.lisp:411-431 (handle-batch-request), specifically the params binding at src/rpc/server.lisp:420-421`
- **core:** `refs/bitcoin/src/httprpc.cpp:196-200; refs/bitcoin/src/rpc/server.cpp:503-512 (ExecuteCommand)`
- **Core does:** Each batch member is re-parsed into the same JSONRPCRequest and executed through JSONRPCExec -> CRPCTable::execute -> ExecuteCommands -> ExecuteCommand, and ExecuteCommand applies transformNamedArguments whenever request.params.isObject() (rpc/server.cpp:508-510). Named parameters therefore work identically in a batch and in a singleton request.
- **we do:** The singleton path (parse-json-rpc-request, server.lisp:303-305) calls (%normalize-rpc-params (%named-params-to-positional method ...)). The batch path binds params as (%normalize-rpc-params (or (gethash "params" req) '())) with no %named-params-to-positional call, so a member whose "params" is a JSON object reaches the handler as a raw hash-table. Handlers read positionally — (first params), (second params) — so (first <hash-table>) signals a type error, which handle-single-request's generic error clause converts to -32603 "Internal error: ...". Core's "args" positional-prefix convenience and the OBJ_NAMED_PARAMS options-object collection are likewise unavailable in a batch.
- **impact:** A client that batches named-argument calls (the shape doc/JSON-RPC-interface.md documents and that Core's own authproxy supports) gets an internal-error reply per member instead of a result. The failure mode is misleading: the error text names a Lisp type error, not a bad request, so the client cannot tell that the transport shape is at fault.
- finder confidence: read-both-trees

#### No REST endpoint checks RPC warmup, so /rest/* serves a half-initialized node during startup instead of 503

- **ours:** `src/rpc/rest.lisp:538-604 (rest-handle) and every %rest-* handler; contrast src/rpc/server.lisp:68-84 (dispatch-rpc-method), which does check`
- **core:** `refs/bitcoin/src/rest.cpp:170-176 (CheckWarmup) and its call at the head of every handler: rest.cpp:182, 314, 394, 501, 623, 717, 744, 783, 839, 898, 1093`
- **Core does:** Every REST handler begins with `if (!CheckWarmup(req)) return false;`, which answers HTTP 503 with "Service temporarily unavailable: <rpcWarmupStatus>" for as long as RPCIsInWarmup is true — the same gate CRPCTable::execute applies to JSON-RPC.
- **we do:** *rpc-warmup-status* is consulted only in dispatch-rpc-method, which the REST layer bypasses entirely: rest-handle routes directly to %rest-chaininfo, %rest-block, %rest-getutxos etc., and those call the rpc-* handler FUNCTIONS (e.g. (rpc-getblockchaininfo node nil) at rest.lisp:88) rather than dispatching. start-rpc-server binds the socket and installs the surfaces while warmup is still set (server.lisp:1186-1188), and warmup is only cleared at src/node/init.lisp:1237, after index catch-up.
- **impact:** During startup ("Loading block index...", "Replaying mempool...", "Catching up transaction index...") a REST client gets 200-with-content computed against a chainstate/mempool/index that is not yet consistent, or an opaque 500 from rest-dispatch-handler's catch-all, instead of Core's retryable 503 naming the phase. Monitoring and indexer clients that poll /rest/chaininfo on restart cannot distinguish "still starting" from "answered".
- finder confidence: read-both-trees

#### address-book-add is missing Core's "do not update if no new information is present" gate and its nTime refresh interval

- **ours:** `src/networking/addrman.lisp:413-428`
- **core:** `refs/bitcoin/src/addrman.cpp:566-590`
- **Core does:** For an address already in the table AddSingle first throttles the timestamp refresh — `const bool currently_online{NodeClock::now() - addr.nTime < 24h}; const auto update_interval{currently_online ? 1h : 24h}; if (pinfo->nTime < addr.nTime - update_interval - time_penalty) { pinfo->nTime = …; }` — and then bails out entirely with `if (addr.nTime <= pinfo->nTime) return false;` ("do not update if no new information is present"), BEFORE the fInTried / nRefCount / stochastic-multiplication checks.
- **we do:** We bump last-seen on any strictly newer timestamp with no interval throttle (`(when (> time (peer-address-last-seen existing)) (setf …))`) and then fall straight through to the in-tried / ref-count-8 / `(ash 1 ref-count)` stochastic test and, if it passes, place the address into another new bucket. There is no equivalent of the `addr.nTime <= pinfo->nTime` early return.
- **impact:** A peer replaying an identical addr record (same, even stale, timestamp) keeps getting fresh rolls of the 1-in-2^refcount multiplication test, so it can push an address it controls up to the 8-bucket maximum in the new table without ever supplying new information — Core refuses the roll outright. The missing refresh interval also means our stored nTime tracks attacker-supplied gossip continuously rather than at most hourly, keeping otherwise-stale entries inside the 30-day ADDRMAN_HORIZON and out of addr-info-terrible-p. Bounded in practice by the per-address token bucket, hence S3.
- finder confidence: read-both-trees

#### getrawmempool ignores its second argument mempool_sequence, which our own argument table advertises

- **ours:** `src/rpc/mempool.lisp:113-142; argument declared at src/rpc/core-tables.lisp:63 and src/rpc/core-tables.lisp:279`
- **core:** `refs/bitcoin/src/rpc/mempool.cpp:571-605 (MempoolToJSON), refs/bitcoin/src/rpc/mempool.cpp:660, 693-698`
- **Core does:** getrawmempool takes (verbose, mempool_sequence). With verbose=false and mempool_sequence=true, MempoolToJSON returns an OBJECT {"txids": [...], "mempool_sequence": N} where N is pool.GetSequence() read under the same pool.cs as the txid list (mempool.cpp:588-605). With verbose=true and mempool_sequence=true it raises RPC_INVALID_PARAMETER "Verbose results cannot contain mempool sequence values." (mempool.cpp:574-576).
- **we do:** rpc-getrawmempool binds only (first params) as verbose and never reads (second params). It returns a bare array for verbose=false regardless, and never raises the verbose+sequence conflict. The counter itself exists and works — bl.mp:mempool-sequence (src/mempool/mempool.lisp:430) is already read by the ZMQ sequence publisher (src/zmq.lisp:261-274) and by src/networking/protocol.lisp:2880,2930 — and core-tables.lisp:63/279 registers "mempool_sequence" as getrawmempool's argument 1, so a named call getrawmempool(verbose=false, mempool_sequence=true) is accepted, mapped to a positional slot, and then dropped on the floor.
- **impact:** This is the argument Core's doc/zmq.md tells a mempool-tracking client to use to take an atomic snapshot of the mempool together with the sequence number, so it can then apply ZMQ sequence events without a gap or a duplicate. On this node that client silently receives a plain array: result["mempool_sequence"] raises on the client side, or — worse — a client that tolerates the missing key falls back to "whatever sequence I saw last" and drifts out of sync with the mempool it is mirroring. The RPC advertises the parameter, so nothing signals that it was ignored.
- finder confidence: read-both-trees

#### getrawtransaction consults the mempool even when an explicit blockhash is given, and never rejects an unknown blockhash

- **ours:** `src/rpc/rawtransaction.lisp:37-78 — mempool probe at src/rpc/rawtransaction.lisp:50, blockhash branch at src/rpc/rawtransaction.lisp:58`
- **core:** `refs/bitcoin/src/node/transaction.cpp:143-147; refs/bitcoin/src/rpc/rawtransaction.cpp:298-305`
- **Core does:** Two things. (a) GetTransaction consults the mempool only when no block index was supplied: `if (mempool && !block_index) { ... }` (node/transaction.cpp:145). With a blockhash, Core looks in the txindex (rejecting a hit whose block_hash differs) and then reads that block, and nowhere else. (b) getrawtransaction resolves the blockhash first and throws RPC_INVALID_ADDRESS_OR_KEY "Block hash not found" when LookupBlockIndex returns nullptr (rawtransaction.cpp:301-303), before any transaction lookup.
- **we do:** rpc-getrawtransaction probes the mempool unconditionally and returns the mempool transaction before it ever looks at blockhash-hint (rawtransaction.lisp:50-56). Only if the mempool misses does it try the hint. And when the hinted block is not in the block store it does not error — it falls through to the txindex branch and can return a transaction found in a completely different block, or ends at the generic not-found message.
- **impact:** getrawtransaction(txid, verbose, blockhash) is the query that asks "is this transaction in THAT block". For a txid still in the mempool we answer yes-here-it-is with no blockhash and no in_active_chain field, where Core answers -5 "No such transaction found in the provided block". For an unknown/typo'd blockhash we can answer with the transaction from whatever block the txindex points at, where Core answers -5 "Block hash not found" — so a caller using the blockhash argument as a containment check gets a false positive from both paths.
- finder confidence: read-both-trees


## Unverified candidates (NOT refuted — verification never reached them)


### S1

- **BIP143/BIP341 sighash writes nVersion through buf-set-u32-le, which is declared (unsigned-byte 32) while transaction-version is (signed-byte 32)** — `src/coalton/interop.lisp:1859` vs `refs/bitcoin/src/script/interpreter.cpp:1646` (read-both-trees)
- **Block bodies are written to disk with no CheckBlock at all on the two IBD persist paths, and a present-but-invalid body is never re-requested** — `src/networking/ibd.lisp:3858-3862 (out-of-order persist), src/networking/ibd.lisp:3644-3649 (competing-fork persist), src/validation/block.lisp:4102-4110 (activate-block case 3)` vs `refs/bitcoin/src/validation.cpp:4382-4389 (CheckBlock + ContextualCheckBlock) immediately before refs/bitcoin/src/validation.cpp:4405 (WriteBlock)` (read-both-trees)
- **Transaction deserializer accepts the BIP144 extended encoding with all-empty witness stacks; Core throws "Superfluous witness record"** — `src/serialization/types.lisp:209-232 (br-read-transaction); same gap in read-transaction at src/serialization/types.lisp:266-289` vs `refs/bitcoin/src/primitives/transaction.h:222-231` (read-both-trees)
- **cmpctblock has no anti-DoS work threshold, and the anti-replay gate only fires for headers already in the index — every replay rebuilds the whole-mempool short-ID map** — `src/networking/protocol.lisp:3515` vs `refs/bitcoin/src/net_processing.cpp:4578` (read-both-trees)

### S2

- ***last-checksig-error* / *last-checkmultisig-error* are process-global specials, never rebound, so parallel script-check workers clobber each other's encoding verdict** — `src/coalton/interop.lisp:2207` vs `refs/bitcoin/src/script/interpreter.cpp:335` (read-both-trees)
- **A fork block failing with a non-allowlisted error is neither poisoned nor excluded from candidate selection, so activate-best-chain repeats the same reorg-and-rollback forever and never tries the next-best chain** — `src/validation/block.lisp:3262 (%deterministic-consensus-failure-p gate), :3766-3769 (activate-best-chain failure arm), :3613-3639 (best-valid-tip)` vs `refs/bitcoin/src/validation.cpp:1985-1994 (InvalidBlockFound), :3267-3276 (ActivateBestChainStep), :3423-3425 (fInvalidFound wipes pindexMostWork), :3145-3202 (FindMostWorkChain)` (read-both-trees)
- **BIP30 is skipped for essentially the whole chain on testnet4/signet/regtest, where Core enforces it at every height** — `src/validation/block.lisp:1222-1232 (bip30-enforced-p), used at src/validation/block.lisp:1708` vs `refs/bitcoin/src/validation.cpp:2457-2464` (read-both-trees)
- **ContextualCheckBlock's UTXO-free half (finality, BIP34 height, witness malleation, block weight) is deferred to reorg time for every non-tip block** — `src/validation/block.lisp:1690-1695 (%contextual-check-block docstring), src/validation/block.lisp:1879+ (validate-block :context-free-only), src/networking/protocol.lisp:1026-1029` vs `refs/bitcoin/src/validation.cpp:4161-4216 (ContextualCheckBlock) called from refs/bitcoin/src/validation.cpp:4383` (read-both-trees)
- **Fee estimator has no `validForFeeEstimation` gate: it tracks reorg re-adds, package submissions, chained children, and transactions accepted while the node is behind** — `src/mempool/mempool.lisp:871 (accept-validated-tx) and src/mempool/block-policy-estimator.lisp:352-362` vs `refs/bitcoin/src/policy/fees/block_policy_estimator.cpp:596-636; refs/bitcoin/src/validation.cpp:1303-1309; refs/bitcoin/src/kernel/mempool_entry.h:173-199` (read-both-trees)
- **Lax (pre-BIP66) DER signature parser diverges from Core's ecdsa_signature_parse_der_lax in both directions** — `src/crypto/secp256k1.lisp:422-495 (parse-der-integer-lax, integer-to-bytes-be, normalize-signature-lax)` vs `refs/bitcoin/src/pubkey.cpp:45-185` (read-both-trees)
- **No ZMQ block-connected, -blocknotify or fee-estimator block notification for blocks connected through a reorg** — `src/validation/block.lisp:3342-3369 (%reorg-commit connected loop) vs :2656-2665 (connect-block tip-extension arm)` vs `refs/bitcoin/src/validation.cpp:3429-3435 (BlockConnected per connected block), :3452-3470 (UpdatedBlockTip + blockTip after each step); refs/bitcoin/src/zmq/zmqnotificationinterface.cpp:150-158, 180-195` (read-both-trees)
- **Pruning is not a flush trigger, so block files below tip-288 are unlinked while the on-disk chainstate can be thousands of blocks behind** — `src/validation/block.lisp:2710-2720 (maybe-periodic-flush, which is conditional, then prune-old-blocks unconditionally) and src/node/flush.lisp:329-361` vs `refs/bitcoin/src/validation.cpp:2714-2757 (FindFilesToPrune sets fFlushForPrune) and :2766-2812 (fFlushForPrune forces should_write; the UnlinkPrunedFiles at :2795-2800 sits inside the same FlushStateToDisk that has just written the block index and immediately goes on to sync the coins)` (read-both-trees)
- **REORG-DISCONNECTED-BLOCKS retains every disconnected block in full, defeating the 20 MB disconnect-pool cap** — `src/validation/block.lisp:3162-3163 (%reorg-disconnect), consumed at 3323-3341` vs `refs/bitcoin/src/validation.cpp:2925-2988 (DisconnectTip), :3601-3602 (LimitValidationInterfaceQueue in InvalidateBlock's loop), refs/bitcoin/src/kernel/disconnected_transactions.cpp:31-42` (read-both-trees)
- **Re-mined transactions are never removed from the reorg disconnect pool, so their still-valid in-mempool children are removed recursively** — `src/validation/block.lisp:3394 (and the connected loop at 3342-3369)` vs `refs/bitcoin/src/validation.cpp:3105-3106 (ConnectTip), :313-322 (MaybeUpdateMempoolForReorg)` (read-both-trees)
- **We never push an unsolicited cmpctblock to peers that selected us as their BIP152 high-bandwidth peer** — `src/networking/protocol.lisp:3053` vs `refs/bitcoin/src/net_processing.cpp:5893` (read-both-trees)
- **bumpfee forces fOverrideFeeRate, skipping the mempool-min-fee and required-fee halves of Core's CheckFeeRate** — `src/wallet/psbt.lisp:1780-1783 (with src/wallet/wallet-spend.lisp:339-342)` vs `refs/bitcoin/src/wallet/feebumper.cpp:60-115 (CheckFeeRate) and :278-292; refs/bitcoin/src/wallet/fees.cpp:38-41` (read-both-trees)
- **bumpfee's MarkReplaced writes `replaced_by_txid` only in memory — the marker is lost on restart** — `src/wallet/psbt.lisp:1870-1874` vs `refs/bitcoin/src/wallet/wallet.cpp:961-991 (batch.WriteTx at :983)` (read-both-trees)
- **getblocktemplate returns a cached template verbatim — curtime, bits and target are never refreshed, so on min-difficulty chains the served nBits goes stale** — `/Users/sen/common-lisp/bitcoin-lisp/src/rpc/mining.lisp:332-334 (cache hit returns the stored alist) and :336-354 (%gbt-cached-result), with curtime/bits/target frozen at build time in %gbt-assemble :389-397` vs `refs/bitcoin/src/rpc/mining.cpp:885-888, 939, 996-997, 1013-1014; refs/bitcoin/src/node/miner.cpp:49-65 (UpdateTime)` (read-both-trees)
- **invalidateblock reorgs only to the invalidated block's parent and never re-activates the best remaining valid chain** — `src/validation/block.lisp:3772-3807 (invalidate-block), src/rpc/blockchain.lisp:761-791 (%chain-control-block)` vs `refs/bitcoin/src/rpc/blockchain.cpp:1695-1714 (InvalidateBlock helper), refs/bitcoin/src/validation.cpp:3553-3700 (Chainstate::InvalidateBlock)` (read-both-trees)
- **testmempoolaccept validates each transaction in isolation; Core runs multi-tx batches as a package, so a CPFP child is falsely reported "missing-inputs"** — `src/rpc/mempool.lisp:504-615` vs `refs/bitcoin/src/rpc/mempool.cpp:343-346, refs/bitcoin/src/validation.cpp:1444-1474` (read-both-trees)

### S3

- **%reorg-commit fires tx-relay and wallet side effects without connect-block's background-chainstate role guard** — `src/validation/block.lisp:3342-3369 (no target-blockhash guard) vs :2676-2699 (connect-block's explicit `(unless (bl.store:chain-state-target-blockhash chain-state) ...)` guard)` vs `refs/bitcoin/src/zmq/zmqnotificationinterface.cpp:180-183 (`if (role.historical) return;`), refs/bitcoin/src/validation.cpp:3416, 3429-3435 (ChainstateRole passed to every BlockConnected), :3452 (`this == &m_chainman.ActiveChainstate()` gate on UpdatedBlockTip/blockTip)` (read-both-trees)
- **A backed-up send buffer makes us DROP outbound messages; Core instead stops processing inbound messages until it drains** — `src/networking/connection.lisp:495` vs `refs/bitcoin/src/net_processing.cpp:5245` (read-both-trees)
- **Block script validation never consults the script-execution cache, so every mempool-verified transaction is re-interpreted at connect** — `src/validation/block.lisp:793-849 (validate-tx-scripts) vs src/validation/transaction.lisp:1364-1401 (validate-transaction-scripts, which does use it)` vs `refs/bitcoin/src/validation.cpp:2075-2081 and refs/bitcoin/src/validation.cpp:2580-2583` (read-both-trees)
- **Block templates never signal any BIP9 deployment: nVersion is the hardcoded constant 0x20000000 and vbavailable is hardcoded empty** — `/Users/sen/common-lisp/bitcoin-lisp/src/mining/assembler.lisp:54-56 and :72 (`(version +versionbits-top-bits+)`); /Users/sen/common-lisp/bitcoin-lisp/src/rpc/mining.lisp:384, :413-419` vs `refs/bitcoin/src/node/miner.cpp:140-145; refs/bitcoin/src/rpc/mining.cpp:958-987` (read-both-trees)
- **Block-conflict removal does not clear the conflicted transaction's prioritisation delta** — `src/mempool/mempool.lisp:1781-1793 (the conflict branch of mempool-remove-for-block)` vs `refs/bitcoin/src/txmempool.cpp:388-403 (removeConflicts)` (read-both-trees)
- **Block-relay-only eviction protection ignores fRelevantServices, so a non-tx-relay peer without the services we want can take one of the 8 reserved slots** — `src/node/eviction.lisp:217-224` vs `refs/bitcoin/src/node/eviction.cpp:189-190` (read-both-trees)
- **CONST_SCRIPTCODE's OP_CODESEPARATOR rule is applied only to the scriptPubKey and to a scriptCode reached by a CHECKSIG, not to the scriptSig or the P2SH redeem script** — `src/coalton/interop.lisp:804` vs `refs/bitcoin/src/script/interpreter.cpp:474` (read-both-trees)
- **CheckTxInputs (coinbase maturity, fee/value consensus) runs after the standardness-of-inputs, sigop and witness checks instead of before** — `src/validation/transaction.lisp:1160-1200` vs `refs/bitcoin/src/validation.cpp:892-905` (read-both-trees)
- **CheckTxInputs' input-value MoneyRange guards and ConnectBlock's accumulated-fee guard have no analogue** — `src/validation/transaction.lisp:119-190 (validate-transaction-contextual), src/validation/block.lisp:1786-1791 (fee accumulation)` vs `refs/bitcoin/src/consensus/tx_verify.cpp:184-210 and refs/bitcoin/src/validation.cpp:2537-2541` (read-both-trees)
- **Coinbase "hash" (wtxid) reported as 32 zero bytes by the RPC transaction serializer; Core reports the real witness hash** — `src/serialization/types.lisp:443-446 and src/rpc/blockchain.lisp:466` vs `refs/bitcoin/src/primitives/transaction.cpp:86-93; refs/bitcoin/src/consensus/merkle.cpp:80` (read-both-trees)
- **Duplicate-in-mempool check is txid-only: Core's "txn-same-nonwitness-data-in-mempool" case is never reported** — `src/validation/transaction.lisp:1086-1089` vs `refs/bitcoin/src/validation.cpp:823-830` (read-both-trees)
- **ECDSA satisfaction sized at 72 bytes on a stated justification that is factually false — our signer does grind low-R** — `src/wallet/wallet-spend.lisp:392-399 and :48-52 (divergence 1); +ecdsa-max-sig-size+ used at :436, :463-531` vs `refs/bitcoin/src/wallet/spend.cpp:54-58 (UseMaxSig), :70-72 (MaxInputWeight), :117-124 (CalculateMaximumSignedInputSize); refs/bitcoin/src/script/descriptor.cpp:1163,1196,1229,1299; refs/bitcoin/src/wallet/wallet.cpp:4119-4122 (CanGrindR)` (read-both-trees)
- **FindAndDelete is skipped for an EMPTY signature; Core's pattern for an empty sig is the single byte 0x00 (OP_0), not the empty script** — `src/coalton/interop.lisp:2405` vs `refs/bitcoin/src/script/interpreter.cpp:330` (read-both-trees)
- **Gossiped addresses are stored in addrman and relayed onward without the banned/discouraged filter Core applies at ingest** — `src/networking/protocol.lisp:1250` vs `refs/bitcoin/src/net_processing.cpp:4094` (read-both-trees)
- **No -walletcrosschain guard: a wallet whose locator belongs to another chain is loaded and rewritten** — `src/wallet/wallet-tx.lisp:1650-1673 (wallet-attach-chain) and src/wallet/wallet.lisp:1198 (loaded-locator)` vs `refs/bitcoin/src/wallet/wallet.cpp:3178-3190` (read-both-trees)
- **OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY consult DISCOURAGE_UPGRADABLE_NOPS when their own flag is off; Core treats them as a plain NOP** — `src/coalton/script.lisp:2108` vs `refs/bitcoin/src/script/interpreter.cpp:521` (read-both-trees)
- **OP_CHECKMULTISIG charges nKeysCount against the 201-op budget only after running the signature verifications; Core charges and enforces it before** — `src/coalton/script.lisp:1983` vs `refs/bitcoin/src/script/interpreter.cpp:1119` (read-both-trees)
- **PSBT "complete" and the already-signed test trust final/partial fields without verifying the scripts** — `src/wallet/psbt.lisp:996-1002 (%psbt-input-signed-p) and :1418-1430 (%psbt-signer-result)` vs `refs/bitcoin/src/psbt.cpp:325-355 (PSBTInputSignedAndVerified), :407-409; refs/bitcoin/src/wallet/wallet.cpp:2231-2235` (read-both-trees)
- **PSBT parser omits two of Core's global-map validity checks (out-of-range prevout index, unsupported PSBT version)** — `src/serialization/psbt.lisp:203-232 (parse-psbt) and src/serialization/psbt.lisp:178-201 (%psbt-validate-input)` vs `refs/bitcoin/src/psbt.h:1373-1377 and refs/bitcoin/src/psbt.h:1319-1324` (read-both-trees)
- **PSBT signing never checks that existing signatures use the requested sighash type** — `src/wallet/psbt.lisp:1249-1264 (%psbt-record-signatures) and :1073-1086 (%psbt-effective-sighash)` vs `refs/bitcoin/src/psbt.cpp:459-475` (read-both-trees)
- **Package consistency check adds inputs one at a time, misreporting a transaction with duplicate inputs as a package conflict; empty-vin members are not caught** — `src/validation/packages.lisp:128-138 (the `spent` loop in package-well-formed)` vs `refs/bitcoin/src/policy/packages.cpp:52-74 (IsConsistentPackage)` (read-both-trees)
- **Relayed addresses go out immediately, one addr message per address, instead of Core's per-peer Poisson-batched queue** — `src/networking/protocol.lisp:1158` vs `refs/bitcoin/src/net_processing.cpp:5571` (read-both-trees)
- **Rolling minimum fee decays with no block since the bump, and block connection never resets the decay clock** — `src/mempool/mempool.lisp:461-489 (mempool-decayed-rolling-min-fee-rate), 1718-1724 (bump in mempool-trim-to-size), 1756-1793 (mempool-remove-for-block)` vs `refs/bitcoin/src/txmempool.cpp:829-851 (GetMinFee), 853-858 (trackPackageRemoved), 426-427 (end of removeForBlock)` (read-both-trees)
- **The BIP94 timewarp floor and check use the fixed 2016-block interval and a hardcoded testnet4 gate; the comment justifying this misreads Core** — `/Users/sen/common-lisp/bitcoin-lisp/src/mining/assembler.lisp:83-95 and the justifying comment at :245-256; /Users/sen/common-lisp/bitcoin-lisp/src/validation/block.lisp:629-644` vs `refs/bitcoin/src/node/miner.cpp:36-47; refs/bitcoin/src/consensus/params.h:126; refs/bitcoin/src/kernel/chainparams.cpp:576-580; refs/bitcoin/src/validation.cpp:4127-4137; refs/bitcoin/src/chainparams.cpp:47` (read-both-trees)
- **The intra-block coin overlay keeps provably-unspendable outputs that Core's AddCoin drops** — `src/validation/block.lisp:1755-1765 and src/validation/block.lisp:1806-1816 (pending-utxos population)` vs `refs/bitcoin/src/coins.cpp AddCoin (`if (coin.out.scriptPubKey.IsUnspendable()) return;`), reached from UpdateCoins in refs/bitcoin/src/validation.cpp:2589` (read-both-trees)
- **The prune window's lower bound is our walk cursor rather than Core's 0, so the first blk file is never prunable** — `src/storage/blocks.lisp:889 (`(%prunable-flat-files store (1+ start) min-keep-height)`) with start from src/storage/chain.lisp:201-207 and pruned-height defaulting to 0 at chain.lisp:57` vs `refs/bitcoin/src/validation.cpp:6366-6391 (Chainstate::GetPruneRange returns prune_start = 0 unless this is an unvalidated snapshot chainstate) and refs/bitcoin/src/node/blockstorage.cpp:386-389 (`if (fileinfo.nHeightLast > last_block_can_prune || fileinfo.nHeightFirst < min_block_to_prune) continue;`)` (read-both-trees)
- **The relay-finality check runs after the duplicate and missing-input checks, so a non-final transaction with unknown parents is stored in the orphanage instead of rejected** — `src/validation/transaction.lisp:1086-1097 (duplicate + mempool-extra-coins), 1130-1139 (:non-final)` vs `refs/bitcoin/src/validation.cpp:819-822 (CheckFinalTxAtTip), 823-829 (exists), 866 (bad-txns-inputs-missingorspent)` (read-both-trees)
- **base58-decode has no length bound; Core's DecodeBase58 bails as soon as the decoded length exceeds max_ret_len** — `src/crypto/address.lisp:43-68 (base58-decode), reached from base58check-decode:85, decode-address:337, bip32-parse:179, wif-to-private-key:120` vs `refs/bitcoin/src/base58.cpp:40-71; refs/bitcoin/src/key_io.cpp:93` (read-both-trees)
- **enforce_BIP94 is hardcoded to testnet4; Core lets regtest turn it on with -test=bip94** — `src/validation/block.lisp:629-643 (bip94-timewarp-violation-p)` vs `refs/bitcoin/src/kernel/chainparams.cpp:579 and refs/bitcoin/src/chainparams.cpp:47` (read-both-trees)
- **generateblock builds its own coinbase and re-introduces the unconditional segwit witness that builder.lisp already fixed** — `/Users/sen/common-lisp/bitcoin-lisp/src/rpc/mining.lisp:754-758` vs `refs/bitcoin/src/rpc/mining.cpp:379-389; refs/bitcoin/src/node/miner.cpp:67-77 (RegenerateCommitments); refs/bitcoin/src/validation.cpp:4017-4027, 4029-4051` (read-both-trees)
- **generatetoaddress / generatetodescriptor raise an error when maxtries is exhausted instead of returning the blocks mined so far** — `/Users/sen/common-lisp/bitcoin-lisp/src/rpc/mining.lisp:624-625 (and /Users/sen/common-lisp/bitcoin-lisp/src/mining/builder.lisp:124-132, mine-block)` vs `refs/bitcoin/src/rpc/mining.cpp:137-182` (read-both-trees)
- **getmininginfo reports currentblockweight/currentblocktx as 0 before any template has been assembled; Core omits the fields** — `/Users/sen/common-lisp/bitcoin-lisp/src/rpc/mining.lisp:456-457` vs `refs/bitcoin/src/rpc/mining.cpp:466-467; refs/bitcoin/src/node/miner.h:95-99` (read-both-trees)
- **getnetworkhashps computes the wrong number: integer rounding drops sub-1 H/s results to 0, and the timespan uses the window's endpoints instead of its min/max block time** — `/Users/sen/common-lisp/bitcoin-lisp/src/rpc/mining.lisp:809-819` vs `refs/bitcoin/src/rpc/mining.cpp:91-108` (read-both-trees)
- **getnetworkhashps ignores its `height` argument entirely, does not implement nblocks = -1, and never validates its inputs** — `/Users/sen/common-lisp/bitcoin-lisp/src/rpc/mining.lisp:799-808` vs `refs/bitcoin/src/rpc/mining.cpp:65-89, 118-121` (read-both-trees)
- **script-is-push-only-p rejects OP_RESERVED (0x50); Core's IsPushOnly deliberately counts it as push-type** — `src/coalton/interop.lisp:1353` vs `refs/bitcoin/src/script/script.cpp:266` (read-both-trees)
- **sendcmpct(0) never clears the recorded high-bandwidth-from flag** — `src/networking/protocol.lisp:3259` vs `refs/bitcoin/src/net_processing.cpp:3918` (read-both-trees)
- **verify-checksig's inline FindAndDelete pattern omits the PUSHDATA prefix for signatures longer than 75 bytes** — `src/coalton/interop.lisp:2149` vs `refs/bitcoin/src/script/interpreter.cpp:330` (read-both-trees)
- **wtxidrelay / sendaddrv2 received after VERACK are silently ignored where Core disconnects** — `src/networking/protocol.lisp:257` vs `refs/bitcoin/src/net_processing.cpp:3949` (read-both-trees)

## Coverage, in the finders' own words

1. Read in full on our side: src/networking/addrman.lisp (all 834 lines), src/networking/peerdb.lisp, src/node/eviction.lisp, src/node/peers.lisp, the misbehavior/ban/discourage section of src/networking/peer.lisp (~1540-1830), the addr/addrv2/getaddr/relay sections of src/networking/protocol.lisp (~1100-1420, 2426-2600), the local-address + reachability + permissions sections of src/networking/netaddress.lisp (~460-760), and the auth/onion-proxy half of src/networking/torcontrol.lisp. Read on Core's side: addrman.cpp (constants, GetTriedBucket/GetNewBucket/GetBucketPosition, IsTerrible, GetChance, Unserialize, Delete/ClearNew/MakeTried, AddSingle, Good_, Attempt_, Select_, GetAddr_, Connected_, ResolveCollisions_, SelectTriedCollision_), node/eviction.cpp in full, net.cpp (ConnectNode, AttemptToEvictConnection, CreateNodeFromAcceptedSocket, ThreadOpenConnections 2640-2900, AddLocal), netaddress.cpp GetReachabilityFrom, netbase.cpp IsBadPort, net_processing.cpp RelayAddress/PushAddress/MaybeSendAddr.

Not covered / only skimmed: socks5.lisp and the I/O half of torcontrol.lisp (reply parsing, ADD_ONION, reconnect backoff) were only skimmed — no findings claimed there; addrman peers.dat serialization was read but not compared byte-for-byte against Core's Serialize/Unserialize (our format is deliberately our own, CRC32 + "ADRM", so byte parity is not the standard); the asmap trie decoder (netaddress.lisp:766-940) was not verified against Core's asmap.cpp; net.cpp's I2P/PRIVATE_BROADCAST paths and MaybePickPreferredNetwork / EXTRA_NETWORK_PEER (per-network extra outbound) were not compared — the latter appears to have no counterpart in our tree but I did not read our side closely enough to file it.

Two further divergences I verified but judged below the bar and did not file: (a) network-reachability-from's unroutable-partner arm returns +reach-ipv6-strong+ for an IPv6 local address where Core returns REACH_IPV6_WEAK (netaddress.cpp:770-775), inverting the IPv4-vs-IPv6 preference for peers we cannot type — unreachable today because torcontrol is the map's only writer; (b) relay-address always uses max-targets 1 for unreachable-net addresses, where Core relays them to 1 or 2 by a coin flip (net_processing.cpp:2303), rotates destinations on a per-address-offset 24 h boundary rather than a global UTC day, keys the ranking with a node-secret SipHash randomizer rather than a bare SHA-256, and drops (rather than substitutes) a destination that already knows the address — all folded conceptually into finding 3.

2. Read in full on our side: src/config/args.lisp, src/config/values.lisp, src/config/conf.lisp, src/config/settings.lisp, src/config/registry.lisp, src/config-options.lisp, src/config.lisp, src/node/args.lisp, src/node/datadir.lisp, src/node/rpc-config.lisp, and the relevant parts of src/node/init.lisp (%log-args, start-node-from-args, node-main, %init-logging, %init-parameters, %init-connection-options, %init-peer-features-and-wallet) plus the consuming call sites I needed to verify impact (src/rpc/server.lisp parse-rpcauth-entry/%parse-rpcauth-credentials/start-rpc-server, src/logging.lisp apply-log-categories, src/networking/protocol.lisp %cf-serving-index, src/networking/peer.lisp service flags, src/node/peers.lisp automatic-inbound-capacity). Read on Core's side: common/args.cpp in full, common/config.cpp in full, common/settings.cpp in full, common/init.cpp in full, init.cpp SetupServerArgs flag registrations, InitParameterInteraction (764-846) and AppInitParameterInteraction (919-1110) plus the -connect/-seednode block at 2205-2230, and test/functional/test_framework/util.py write_config, rpc_users.py and feature_config_args.py for the reachable-by-Core's-own-tests claims.

NOT covered, and where a second pass would pay: (1) the shutdown teardown ORDER against Core's Interrupt()/Shutdown() in init.cpp:255-450 — I read src/node/shutdown.lisp's coordination design and the first half of %stop-node and found it careful and well-documented, but I did not walk the remaining ~100 lines against Core's exact stop sequence (connman->Stop, DumpMempool, fee estimates, scheduler, index shutdown ordering); (2) the -logratelimit / init/common.cpp logging-option surface beyond -debug/-debugexclude/-loglevel; (3) Core's AppInitMain steps 5-13 ordering against our %init-* decomposition; (4) the datadir/blocksdir path-cache semantics (Core re-resolves paths after ReadConfigFiles via ClearPathCache, and only checks -blocksdir existence at init.cpp:968 — we have no -blocksdir at all, it is on the core-only list).

Two smaller divergences I verified but did not spend a finding slot on: Core does NOT lowercase a [SECTION] header (config.cpp:49) while parse-bitcoin-conf-sections does (conf.lisp:67), so `[TEST]` applies for us and is an unrecognized section for Core; and `noincludeconf=1` written inside bitcoin.conf clears the include span in Core (config.cpp:170) whereas %read-config-includes would try to include a file literally named "0" and abort startup (src/node/datadir.lisp:116,125-127) — that one is a sub-case of finding 2's root cause.

3. Read in full on our side: src/rpc/server.lisp (JSON-RPC parsing, named-arg transform, batch handling, reply shaping, cookie generation, HTTP Basic auth, ACL, acceptor, start-rpc-server), src/rpc/rest.lisp (all endpoints + router + surface registration), src/rpc/ui.lisp, src/rpc/define-rpc.lisp, src/rpc/errors.lisp, src/rpc/json.lisp, src/rpc/amounts.lisp, src/rpc/node.lisp; plus the relevant regions of src/rpc/mempool.lisp (getrawmempool, testmempoolaccept, sendrawtransaction, submitpackage), src/rpc/mining.lisp (submitblock, submitheader, generate*), src/rpc/rawtransaction.lisp (getrawtransaction, tx-to-json-confirmed), src/rpc/blockchain.lisp (getblock/getblockheader verbosity, getblockfilter, block-header-entry-to-json, mempool-coin-height), src/storage/block-undo.lisp, src/config-options.lisp and src/config/registry.lisp. On Core's side: refs/bitcoin/src/httprpc.cpp and httpserver.cpp in full, rest.cpp in full, rpc/request.h, rpc/server.cpp (execute/ExecuteCommand/transformNamedArguments call site), node/transaction.cpp GetTransaction, rpc/mempool.cpp MempoolToJSON + getrawmempool, rpc/blockchain.cpp getblock verbosity mapping, primitives/transaction.h CTxOut. NOT covered: I did not run anything (no container session opened), so all findings are from reading both trees, not from execution. Not audited in depth: src/rpc/descriptors.lisp (2164 lines, descriptor/scantxoutset surface), the bulk of src/rpc/blockchain.lisp (getblockstats, gettxoutsetinfo, scanblocks/scantxoutset internals, getchaintxstats, getdeploymentinfo field-by-field), src/rpc/net.lisp (setban/addnode/getpeerinfo field sets), src/rpc/mining.lisp getblocktemplate body, src/rpc/merkleproof.lisp, src/rpc/signmessage.lisp, and the wallet RPCs (out of dimension). I also deliberately did not re-report the GA1-GA9 items listed as excluded; the -rpcwhitelist finding is adjacent to a line in docs/next-wave-2026-08-22.md that recorded the option as merely "absent", but the defect now is different in kind — it is registered by define-core-only-options, so it is parsed and accepted rather than rejected, which turns a missing feature into a silently unenforced authorization control.

4. Read in full on our side: src/storage/coins-view-cache.lisp, coins-view.lisp, utxo.lisp (head), blocks.lisp (flat store/undo/scan/prune sections and store-block/init-block-store), prune-policy.lisp, index-base.lisp, blockfilterindex.lisp, coinstatsindex.lisp (apply/add), txindex.lisp (head), src/kv/leveldb.lisp (options/error/lifecycle), src/kv/flatfile.lisp (seq/allocate/flush/framing), src/node/flush.lisp, src/node/recovery.lisp, plus the prune/flush call sites in src/validation/block.lisp and the iterate call sites in src/rpc/blockchain.lisp. Read on Core's side: coins.cpp (whole), coins.h (CCoinsCacheEntry, CoinsViewCacheCursor), txdb.cpp (CCoinsViewDB), node/blockstorage.cpp (FindFilesToPrune, FindFilesToPruneManual, LoadBlockIndexGuts locations), validation.cpp (FlushStateToDisk, GetPruneRange), rpc/blockchain.cpp (gettxoutsetinfo prologue), index/base.cpp and index/coinstatsindex.cpp (grep-level only, for CustomAppend/CustomRemove/Rewind shape). NOT covered: src/storage/chain.lisp beyond the prune-cursor and block-position helpers (the header-index serialization/CRC/delta-log format and load path, ~1400 lines, was only sampled), assumeutxo snapshot load/validate, migrate-blocks.lisp and storage/reindex.lisp, txospenderindex.lisp, src/kv/datadir.lisp and fsync.lisp, blockfilter.lisp (GCS encoding), and the whole tests/ tree apart from the one sync regression test cited. I also did not run anything -- all findings are static reads, no container work.

5. Read in full on our side: src/validation/transaction.lisp (the whole mempool-acceptance path — validate-transaction-for-mempool, %is-standard-tx, are-inputs-standard-p, check-sigops-bip54-p, is-witness-standard-p, dust/ephemeral helpers, mempool-extra-coins, %policy-script-checks/%consensus-script-checks, the reject-reason table); src/validation/packages.lisp (package-well-formed, package-child-with-parents-tree-p, package-truc-checks, %package-rbf-checks, %accept-package-subset); src/mempool/mempool.lisp (constants, mempool-entry, sigop-adjusted-vsize, dynamic-usage model, rolling min fee, single-truc-checks, mempool-add/remove/remove-recursive, the full RBF block, trim-to-size, expire, remove-for-block, prioritise); src/mempool/orphan.lisp (structure, scoring, LimitOrphans); src/mempool/block-policy-estimator.lisp (constants, buckets, bpe-process-transaction/remove-tx/process-block and the note-* entry points); src/rpc/mempool.lisp testmempoolaccept and the maxfeerate/maxburnamount rails; the reject-cache classification in src/networking/protocol.lisp; the reorg mempool paths in src/validation/block.lisp (remove-reorged-nonfinal-mempool-entries, readd-disconnected-txs-to-mempool).

Read on Core's side for comparison: validation.cpp PreChecks/ReplacementChecks/PackageRBFChecks/AcceptSingleTransactionInternal/AcceptMultipleTransactionsInternal/CheckFeeRate/LimitMempoolSize/IsCurrentForFeeEstimation; txmempool.cpp GetMinFee/trackPackageRemoved/TrimToSize/removeForBlock/removeConflicts/removeForReorg/PrioritiseTransaction; policy/policy.{h,cpp}; policy/rbf.cpp; policy/truc_policy.cpp; policy/packages.{h,cpp}; policy/ephemeral_policy.{h,cpp}; policy/feerate.cpp; policy/fees/block_policy_estimator.{h,cpp} processTransaction; kernel/mempool_entry.h; node/txorphanage.cpp scoring/limits; node/txdownloadman_impl.cpp MempoolRejectedTx; rpc/mempool.cpp testmempoolaccept.

NOT covered (no findings claimed there): the cluster-mempool machinery itself — src/mempool/txgraph.lisp, cluster-linearize.lisp, spanning-forest.lisp, feefrac.lisp — i.e. chunk/linearization correctness, txgraph-get-worst-main-chunk eviction ordering, txgraph-rbf-diagrams, and mempool-package-fits-cluster-limits-p; I read their call sites but not the algorithms against Core's txgraph.cpp/cluster_linearize.h. Also not covered: the internal math of block-policy-estimator (TxConfirmStats decay/estimate-median, fee_estimates.dat format), the mempool.dat serialization details, src/mempool/fee-estimator.lisp, and the script-standardness predicates in detail (classify-output-script, input-witness-standard-p, +standard-script-verify-flags+) — those overlap the script dimension. Verified-equivalent and deliberately NOT reported: the RBF rules 3/4/5 and ImprovesFeerateDiagram port, EntriesAndTxidsDisjoint semantics, SingleTRUCChecks including sibling eviction, PackageTRUCChecks, PreCheckEphemeralTx/CheckEphemeralSpends, GetDustThreshold, IsStandardTx incl. the shared datacarrier budget, GetVirtualTransactionSize, the orphanage DoS-score/limit model, and every policy constant in policy.h.

6. Read in full on our side: src/validation/block.lisp lines 1-70 and 2500-4114 (trim-disconnect-pool, connect-block, find-fork-point, collect-chain-entries, the mempool reorg filter/re-add, %rollback-partial-reorg, the deterministic-invalid allowlist, the REORG struct and %reorg-disconnect/%reorg-connect/%reorg-commit, perform-reorg, best-valid-tip, %activation-step-target, activate-best-chain, invalidate-block/reconsider-block/precious-block, activate-block); src/networking/headers-sync.lisp in full; the reorg-relevant parts of src/networking/ibd.lisp (activate-best-chain call site, process-received-block, retry-best-reorg-candidate, note/reject-reorg-candidate); src/mempool/mempool.lisp mempool-remove-for-block / mempool-remove-spenders / mempool-update-for-reorg; src/rpc/blockchain.lisp chain-control RPCs; src/zmq.lisp notify functions. Read on Core's side: validation.cpp 285-400 (MaybeUpdateMempoolForReorg), 1985-1994 (InvalidBlockFound), 2925-3145 (DisconnectTip/ConnectTip/ConnectTrace), 3145-3360 (FindMostWorkChain, PruneBlockIndexCandidates, ActivateBestChainStep), 3400-3500 (ActivateBestChain), 3553-3700 (InvalidateBlock); headerssync.cpp in full; kernel/disconnected_transactions.cpp in full; rpc/blockchain.cpp 1695-1786; zmq/zmqnotificationinterface.cpp 148-205. I also reviewed the PR #562 diff to confirm the refactor was mechanical — the phase boundaries, rollback list ordering and interrupt/truncation logic check out against Core's ActivateBestChainStep and I found no regression introduced by the split itself. NOT covered: block-index status persistence and startup roll-forward reconciliation between the coins-view best-block pointer and the chain tip (src/storage/chain.lisp, node/flush.lisp) — the PHASE A critical-flush safety argument depends on that and I did not verify it; the full deep-reorg candidate machinery in ibd.lisp (%best-completable-reorg-target, parking/re-arming) beyond what finding 3 needed; headerssync driver integration in sync-headers/net_processing TryLowWorkHeadersSync; and the assumeutxo snapshot-promotion interaction with perform-reorg. One deliberate divergence I checked and accepted: Core stays on the partially-connected chain after a ConnectTip failure while we roll back in memory — documented in %reorg-connect's note and internally consistent. Also checked and NOT reported (ours is equivalent or better): the disconnect-pool trim direction (matches Core's LimitMemoryUsage front-pop), reconsider-block's ancestor+descendant clearing, header bad-prevblk admission (protocol.lisp:997-1007), and headerssync's redownload previous_nBits (ours tracks the true last header rather than reverting to chain_start.nBits on an emptied buffer).

7. Read in full, ours: src/mining/assembler.lisp (270 lines), src/mining/builder.lisp (132), src/mining/package.lisp, src/rpc/mining.lisp (893 — getblocktemplate incl. proposal/longpoll/cache, getmininginfo, submitblock, submitheader, generatetoaddress/todescriptor/generateblock, getnetworkhashps, prioritisetransaction, getprioritisedtransactions), plus the difficulty and template-validation helpers they call: src/validation/block.lisp:420-590 (testnet-min-difficulty-allowed-p, testnet-walk-back-bits, get-retarget-ancestor, get-expected-bits, validate-difficulty, check-proof-of-work), :629-644 (bip94-timewarp-violation-p), :1152-1173 (update-uncommitted-block-structures), :1922-1969 (test-block-validity, calculate-block-subsidy), src/storage/chain.lisp:500-548 (target-to-bits, calculate-next-work-required), src/mempool/mempool.lisp:77-120 (entry fee/sigops/vsize semantics), src/validation/versionbits.lisp:1-110, src/config-options.lisp:225-252 (-blockmaxweight/-blockreservedweight/-blockmintxfee).

Read in full, Core: node/miner.cpp (527), node/miner.h, node/types.h:40-78, rpc/mining.cpp (1160), pow.cpp (171), validation.cpp:4017-4051 and :4124-4141, policy/policy.h and consensus/consensus.h limits, kernel/chainparams.cpp pow/BIP94 params for all five chains, init.cpp:1079-1093, plus the covering functional tests (mining_basic.py, rpc_blockchain.py:_test_getnetworkhashps) to pin down observable consequences.

Verified as MATCHING Core (no finding): the chunk-walk structure and its >= budget tests, MAX_CONSECUTIVE_FAILURES / BLOCK_FULL_ENOUGH_WEIGHT_DELTA give-up heuristic, blockMinFeeRate early-out and its per-vsize comparison, base-fee (not modified-fee) accounting into coinbasevalue, weighted sigop cost, the 8000/2000/400 reserves and the -blockmaxweight/-blockreservedweight init errors, GetNextWorkRequired incl. the testnet3 walk-back and testnet4 BIP94 retarget basis, CalculateNextWorkRequired clamping and per-network powLimit cap, GetCompact/DeriveTarget, CheckProofOfWork, GenerateCoinbaseCommitment / UpdateUncommittedBlockStructures (submitblock path), the coinbase's MAX_SEQUENCE_NONFINAL + nLockTime = height-1, the gbt cache VALIDITY condition, the longpoll id format and wait ordering, the client-rules gate and its message order, the proposal branch's duplicate/duplicate-invalid/inconclusive-not-best-prevblk answers, and the gbt transactions/depends/fee/sigops/weight fields.

One further small divergence I verified but did not spend a finding slot on: our prioritisetransaction dust refusal (src/rpc/mining.lisp:861-868) omits Core's `mempool.m_opts.require_standard &&` guard (refs/bitcoin/src/rpc/mining.cpp:535-538), so with -acceptnonstdtxn=1 we refuse to prioritise a dust transaction Core accepts — even though we do have bl.val::*require-standard* wired to that option (src/config-options.lisp:344-349). Also noted, not reported: our coinbase uses tx version 1 where Core's CMutableTransaction default is CURRENT_VERSION = 2 (no consensus effect), and `depends` deduplicates indices where Core repeats them for a tx spending two outputs of the same in-template parent.

NOT covered: the cluster-mempool txgraph internals behind block-builder-current-chunk/include/skip (src/mempool/txgraph.lisp, cluster-linearize.lisp) — I took the chunk ordering and topological guarantees on trust; the mining IPC/interfaces layer (interfaces/mining.h waitNext/cooldown, which we do not implement at all); signet block-solution production; and I ran no code — everything here is source comparison only, per the read-both-trees discipline.

8. Read in full on our side: src/networking/v2-transport.lisp (all 409 lines), src/networking/peer.lisp message I/O + handshake + ping/health + misbehaviour + rate limiting (lines 285-320, 465-760, 995-1250, 1358-1545, 1823-1843), src/networking/protocol.lisp handle-message dispatcher, handle-inv/notfound/headers/block, addr/addrv2 ingest + relay, handle-getdata + its BlockRequestAllowed/network-limited/upload-target guards, BIP157 handlers, handle-getblocktxn, getheaders/getblocks/getaddr responders, relay-block, the whole BIP152 block (sendcmpct, HB list, build-shortid-map, reconstruct-compact-block, compact-block-header-verdict, handle-cmpctblock, handle-blocktxn), src/networking/ibd.lisp dispatch-ibd-message/safely-dispatch/drain-and-reap/pump + ingest-headers-from-peer + process-received-block, src/networking/connection.lisp send path, src/serialization/messages.lisp message parsers and their count bounds, plus src/validation/block.lisp:655 validate-block-header. Core side read at the corresponding places: net_processing.cpp ProcessMessage arms 3585-5155 (every arm), MaybePunishNodeForBlock/BlockRequestAllowed 1908-1960, NewPoWValidBlock 2130-2155, SendMessages block announcement 5820-5935, MaybeSendAddr 5530-5605, ProcessMessages 5238-5250; net.cpp V2Transport (914-1565) and MAX_CONTENTS_LEN/MAX_GARBAGE_LEN/V1_PREFIX_LEN; bip324.cpp + crypto/chacha20poly1305.cpp for the rekey interval.

Verified-and-clean (checked both trees, no divergence worth reporting): BIP324 FSChaCha20/FSChaCha20Poly1305 REKEY_INTERVAL=224 and the packet size cap; the v2 message-ID table and long-form type validation; MAX_INV_SZ, MAX_LOCATOR_SZ, MAX_HEADERS_RESULTS and the addr 1000 cap, all enforced in the parsers; getaddr inbound-only + once-per-connection + the 21-27h per-network response cache with the ban filter at fill; the addr token bucket and shuffle; MAX_BLOCKTXN_DEPTH and the full-block fallback; MAX_CMPCTBLOCK_DEPTH/CanDirectFetch on the serve side; the HB-list inbound-protection swap; the mempool-message permission and upload-target arms; feefilter MoneyRange; self-connection nonce detection; MIN_PEER_PROTO_VERSION and the desirable-services disconnect.

Not covered: addrman.lisp, netaddress.lisp/BIP155 codec details, socks5.lisp, torcontrol.lisp, minisketch/txreconciliation internals, node/eviction.lisp, and the tx-relay/orphan/1p1c half of protocol.lisp (handle-tx, process-orphans, txrequest tracker) — I read their surroundings but did not do a line-by-line Core comparison, so a divergence could remain there. I also did not exercise anything: every claim is from reading, not from running the node. One observation that is not a Core divergence but is worth someone's attention: HANDLE-MESSAGE's "block" and "headers" arms (protocol.lisp:177, 173) are unreachable in production, because DISPATCH-IBD-MESSAGE (ibd.lisp:1631-1727) intercepts both commands before its `(t (handle-message ...))` fall-through, and that is the only production caller of HANDLE-MESSAGE. HANDLE-BLOCK's blanket `(record-misbehavior peer "invalid block")` on every rejection reason — which would diverge from Core's per-reason MaybePunishNodeForBlock (no punishment for BLOCK_TIME_FUTURE or BLOCK_HEADER_LOW_WORK) — therefore never fires today, so I did not report it as a finding.

9. Read in full on our side: src/serialization/{binary,types,compressor,psbt}.lisp, the compact-block/BIP152 half of messages.lisp, src/util/bytes.lisp (byte-buf/byte-reader, CompactSize), src/crypto/{hash,address,bip32,muhash,crypter}.lisp, and the DER/encoding/verification half of src/crypto/secp256k1.lisp (lines ~410-880), plus the signature-encoding and legacy-sighash call sites in src/coalton/interop.lisp (check-der-signature-format, verify-checksig, verify-checksig-witness, cached-verify-ecdsa, valid-sighash-type-p, valid-pubkey-format-p) and the script-flag activation table in src/validation/block.lisp.

Read on the Core side for comparison: compressor.{h,cpp}, primitives/transaction.{h,cpp}, consensus/merkle.cpp, serialize.h (ReadCompactSize/WriteVarInt/ReadVarInt/MAX_SIZE), pubkey.cpp (ecdsa_signature_parse_der_lax, CPubKey::Verify, CheckLowS), script/interpreter.cpp (IsValidSignatureEncoding, IsLowDERSignature, IsDefinedHashtypeSignature, CheckSignatureEncoding, CheckPubKeyEncoding, EvalChecksig), crypto/siphash.{h,cpp}, crypto/muhash.cpp, psbt.h, base58.cpp, key_io.cpp, bech32 decode semantics via key_io.

Verified-equivalent (checked, no finding): CompactSize canonical-encoding and MAX_SIZE handling; Core VARINT read/write incl. the overflow guards; CompressAmount/DecompressAmount and the six compressed-script forms; SipHash-2-4 including the uint8 length byte (Core's m_count is uint8_t, we mask with 0xff); MuHash element mapping (SHA256 key, 384 ChaCha20 bytes, little-endian, fraction form) and Finalize; bech32/bech32m decode (33..126 charset, mixed case, 90-char cap, separator position, v0-bech32 / v1+-bech32m, 2..40 and 20/32 program lengths); CCrypter SHA512 KDF and the constant-time PKCS#7 unpad; BIP32 parse/serialize incl. the depth-0 rules; valid-sighash-type-p vs IsDefinedHashtypeSignature and valid-pubkey-format-p vs IsCompressedOrUncompressedPubKey; the tx-version signedness masking in bb-write-*-le; compact-block prefilled-index and tx-count bounds. I also chased the theory that libsecp's strict parse_der would reject overflowing R/S where Core's syntactic IsValidSignatureEncoding accepts — it does not (libsecp clamps the scalar to zero and returns 1), and the code comment at src/coalton/interop.lisp:2008-2019 already documents that, so it is not a finding.

NOT covered: src/crypto/chacha20.lisp and bip324.lisp were not byte-compared against Core crypto/chacha20*.cpp / chacha20poly1305.cpp / bip324.cpp — I only established what the MuHash call site requires of them. The Schnorr / x-only / ellswift / MuSig2 sections of secp256k1.lisp (lines ~514-1050), the BIP143 and BIP341 sighash preimage construction, and the addrv2/BIP155 and addr encodings in messages.lisp were not compared. ripemd160/sha512/sha3 are delegated to ironclad and were not audited.

No runtime verification was possible: the Docker daemon is not running on this host (`scripts/dev.sh start` fails to reach unix:///Users/sen/.docker/run/docker.sock), and project code must not run natively, so I could not execute the one-line probe I had prepared to confirm finding 1 in the image. Every finding is from reading both trees; none is from executing code.

10. Read in full, ours: src/validation/block.lisp (all 4114 lines except the undo-storage block ~1971-2390 and %reorg-disconnect/%reorg-commit/perform-reorg internals, which I skimmed for entry points only), src/validation/transaction.lisp:1-200 and 1326-1401, src/validation/script.lisp sigop + witness-program helpers, src/validation/signet.lisp:255-280, src/storage/chain.lisp:395-547, src/storage/blocks.lisp:366-440, src/storage/coins-view-cache.lisp:757-805, src/storage/utxo.lisp:20-27, src/serialization/types.lisp (tx/header structs, serializers, wtxid, weight), src/util/chainparams.lisp activation tables, plus the call sites that reach validation: src/networking/protocol.lisp accept-downloaded-block/handle-block/compact-header gate and src/networking/ibd.lisp validate-header-chain, process-received-block, drain-block-queue, %out-of-order-block-acceptable-p, handle-validation-failure, the download walk. Read in Core: validation.cpp CheckBlockHeader/CheckMerkleRoot/CheckWitnessMalleation/CheckBlock/ContextualCheckBlockHeader/ContextualCheckBlock/AcceptBlock/ConnectBlock/CheckInputScripts/GetBlockSubsidy, consensus/tx_check.cpp in full, consensus/tx_verify.cpp in full, pow.cpp GetNextWorkRequired/CalculateNextWorkRequired, kernel/chainparams.cpp per-chain BIP34/BIP94 params. Verified as MATCHING and therefore not reported: merkle root + CVE-2012-2459 mutation flag, block weight formula (header + tx-count varint prefix), legacy 1MB base-size limit, legacy/P2SH/witness sigop counting incl. CScript::GetSigOpCount's push-only bail-out and WitnessSigOps v0-only rule, IsWitnessProgram bounds, BIP141 commitment search and nonce/merkle-match checks, BIP34 encode-bip34-height against CScript()<<nHeight, IsFinalTx (lock-time is unsigned, version is signed -- both correct), BIP68 CalculateSequenceLocks/EvaluateSequenceLocks arithmetic incl. the -1 nLockTime semantics and the ancestor-at-nCoinHeight-1 MTP, coinbase maturity, coinbase value cap, subsidy incl. regtest's 150-block interval, retarget math and the BIP94 first-block basis, testnet min-difficulty and walk-back, GetCompact/SetCompact, script-flag exception table, script-checks-skippable-p, and the header battery run at admission (which is what makes :skip-header safe on the reorg path). NOT covered: the script interpreter itself, taproot/tapscript, miniscript, mempool acceptance policy, the reorg disconnect half and %rollback-partial-reorg, versionbits state transitions, undo-file storage, and assumeutxo. I ran no code -- this project is container-only and I did not start the workbench, so every claim is from reading both trees, not from a test.

11. Read in full on our side: src/wallet/wallet-crypt.lisp (all), src/crypto/crypter.lisp (all), src/wallet/wallet-tx.lisp (struct/state, depth+maturity, record (de)serialization, AddToSpends/RefreshTXOs/IsSpent, trusted-p, AddToWallet, MarkUnusedAddresses, AddToWalletIfInvolvingMe/SyncTransaction, MarkConflicted/RecursiveUpdateTxState/Abandon, all four notification handlers, LoadTxRecords, ScanForWalletTransactions, RescanFromTime, AttachChain), src/wallet/wallet-spend.lisp (policy constants, dust/feerate helpers, CCoinControl, wallet fees, size estimation entry points, ChooseSelectionResult/AttemptSelection/filters, FetchSelectedInputs, sign/verify helpers, all of %create-transaction-internal, FinishTransaction, SendMoney, sendall, submit/commit/resubmit, signrawtransactionwithwallet head), src/wallet/wallet-coins.lisp (IsSpent, locked coins, GetBalance, AvailableCoins, output-type), src/wallet/wallet.lisp (flags, SPKM TopUp/SetCache/IsMine/GetNewDestination, ReserveDestination, name validation, EnsureWalletIsUnlocked, ProcessDescriptorImport), src/wallet/psbt.lisp (prevout resolution, coins map, UTXO filling, sighash resolution, record-signatures, completeness/extract, walletprocesspsbt, feebumper), plus src/rpc/json.lisp and src/rpc/server.lisp for the JSON-false sentinel semantics and src/crypto/secp256k1.lisp for the signer.

Read on Core's side at d3056bc: wallet/crypter.cpp (all), wallet/fees.cpp (all), wallet/feebumper.cpp:1-330, wallet/spend.cpp:40-140, 265-470, 702-830, 1063-1440, wallet/receive.cpp:190-340, wallet/wallet.cpp (blockDisconnected, MarkReplaced, EncryptWallet/Lock/Unlock, AttachChain, FillPSBT tail), wallet/scriptpubkeyman.cpp Encrypt/MarkUnusedAddresses/GetNewDestination/TopUp via the call sites, wallet/rpc/backup.cpp:141-300, wallet/rpc/spend.cpp:205-236 + the EnsureWalletIsUnlocked sites, psbt.cpp:325-520, script/descriptor.cpp MaxSatSize sites.

Checked and found CORRECT (no finding): the AES-256-CBC/PKCS#7 and SHA-512 KDF primitives byte-for-byte incl. Core's constant-time unpad shape; EncryptWallet's atomicity and seed rotation; ChangeWalletPassphrase; CachedTxIsTrusted and GetBalance; GetTxDepthInMainChain/BlocksToMaturity; blockConnected/blockDisconnected incl. the coinbase-abandoned flag and the disconnect-height conflict rewind; AvailableCoins tx-level and per-output filters incl. the TRUC bucketing; ChooseSelectionResult/AttemptSelection ordering and error propagation; the whole CreateTransactionInternal body incl. SFFO truncate/rem and the change-adjust invariants; TransactionChangeType; ReserveDestination return/rewind; FetchSelectedInputs; GetMinimumFeeRate/GetDiscardRate (settxfee/-paytxfee are gone at d3056bc, so their absence is correct); ProcessDescriptorImport; backupwallet/restorewallet (hardened beyond Core); wallet name containment. I specifically checked whether nested JSON `false` in importdescriptors leaks the truthy +json-false+ sentinel — it does not (src/rpc/server.lisp:109 folds nested false to NIL).

Not covered: wallet-store.lisp record key layout and %load-wallet-records in detail; the listtransactions/listsinceblock/gettransaction JSON field sets; getaddressinfo and InferDescriptor; the BnB/Knapsack/SRD algorithm bodies line-by-line (I read their call sites and parameters only); %psbt-finalize's per-type witness assembly; miniscript satisfaction sizing; migrate.cpp/dump.cpp equivalents; external-signer paths (unimplemented here and out of scope).

12. Read in full, ours: src/coalton/script.lisp (all 2607 lines -- opcode table, ScriptNum encode/decode, CastToBool, the stack ops, execute-opcode, the eval loop with its op-count/push-size/stack-size/conditional handling, P2SH and witness-program helpers), src/coalton/interop.lisp (all 3360 lines -- verify-script, run-scripts-with-p2sh, flags, OP_SUCCESS scan, tapscript signature/weight logic, run-tapscript, IsPushOnly, DER/pubkey/hashtype encoding checks, verify-checksig, CHECKMULTISIG, MINIMALDATA, P2WPKH/P2WSH/witness dispatch, taproot key- and script-path, legacy/BIP143/BIP341 sighash, FindAndDelete, the sig and script-execution caches), src/validation/script.lisp (sigops counting, validate-input-script), plus src/crypto/secp256k1.lisp check-signature-encoding/verify-signature, src/util/bytes.lisp writers, src/validation/block.lisp flag sets and the parallel worker pool, and src/validation/transaction.lisp's mempool flag path. Read in Core: script/interpreter.cpp EvalScript in full (the pre-switch checks, every opcode case, CLTV/CSV/CheckLockTime/CheckSequence, EvalChecksig{,PreTapscript,Tapscript}, CheckSignatureEncoding/IsValidSignatureEncoding/CheckPubKeyEncoding, FindAndDelete, SignatureHash, SignatureHashSchnorr, ExecuteWitnessScript, VerifyTaprootCommitment, VerifyWitnessProgram, VerifyScript), script/script.cpp GetSigOpCount/IsPushOnly/IsWitnessProgram/IsPayToScriptHash, script/script.h AppendDataSize and the push operators, policy/policy.cpp IsStandardTx, and test/data/script_tests.json for the NOP/CLTV flag vectors. NOT covered: I could not execute anything -- the Docker daemon socket at ~/.docker/run/docker.sock is absent, so scripts/dev.sh start fails and no eval, suite, or empirical check was possible. That matters most for finding 1, where the exact SBCL runtime symptom (TYPE-ERROR versus an elided check) is unverified; the source-level type mismatch itself is verified by reading. Also not covered: the tagged-hash primitives themselves (tap-leaf-hash / tap-branch-hash / tap-tweak-hash / verify-xonly-tweak in src/crypto/), Coalton-to-CL representation questions I could not confirm without a REPL, the miniscript satisfier, and src/validation/script.lisp's second (apparently vestigial) CL interpreter at lines 145-405, whose callers I did not trace.


## Next round

1. **Run the refactor-regression dimension.** It never executed and it is the one aimed at
   the newest, least-reviewed state of the tree.
2. **Re-verify the 58.** They carry no verdict at all; some will be real, some will die.
3. **Re-verify the 26 that stand on a single vote**, since the panel demonstrably changes
   answers when it runs in full.
4. Then triage: the two S1s touch the coins cache and the flat-file block index, both on
   the restart/prune path, and both deserve a reproduction before a fix.
