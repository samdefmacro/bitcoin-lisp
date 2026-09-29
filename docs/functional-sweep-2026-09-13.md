# Functional-test sweep — 2026-09-13

Core's `test/functional` suite (pin `d3056bc`, 263 test scripts after the
three helpers are excluded) run against the node binary built from `main`,
eight batches of 33 in parallel, 150 s per test, cache datadir rebuilt first
(`scripts/conformance.sh create_cache.py`, left `blocks` and `chainstate`
only). Recipe: docs/coverage-vs-core-2026-08-24.md §15.3.1. The per-test
classification (status, failure point, exception line) is in
`docs/functional-sweep-2026-09-13/*.tsv`; the classifier reads the batch
logs and records the last frame inside `test/functional/` plus the exception
line, so a test is compared by WHERE it died, not only by whether it did
(docs/functional-triage-2026-08-25.md, "measure the failure point").

## Baseline at `6011851b` (GA11 closed)

| PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|
| 48 | 171 | 21 | 23 |

The 23 skips are Core's own gates (USDT, `bitcoin-cli`, wallet tool, external
signer). Previous trusted baseline, 2026-08-25: 34 / 213 / 18 with skips
counted as failures.

Signature clusters over the 192 red tests (three or more):

| count | signature |
|---|---|
| 21 | TIMEOUT (150 s) |
| 21 | bare `AssertionError` |
| 15 | `wait_until` predicate timeout (`Predicate ''''`) |
| 14 | `Expected substring not found in error message` (our RPC error text differs from Core's) |
| 7 | `No exception raised` (we accepted what Core rejects) |
| 6 | `not(False == True)` |
| 5 | `FailedToStartError` (node exited at init) |
| 4 | `bitcoind should have exited within 60s with expected error` |
| 3 | `not(1 == 0)` |

## Root cause 1: every new peer waited for the next 30-second cycle

Reading `example_test.py`'s node logs: node0 accepted the framework's python
peer at 10:28:57 and read its first message at 10:29:27. The listener thread
hands a handshaked inbound peer to the sync thread through
`pending-inbound-peers`, and only the top of `%sync-thread-loop`'s iteration
(`merge-inbound-peers`) moved it into `node-peers`; the idle tick's receive
pump (`pump-peer-messages`, five times a second) iterated `node-peers` alone.
The same cycle-boundary drain served `addnode onetry` and `addconnection`,
so `p2p_add_connections.py` gained one connection per 30 s. Core has no
hand-off: an accepted socket joins `m_nodes` at once (net.cpp:1854-1858),
`ThreadMessageHandler` runs `ProcessMessages` on it continuously, and
`CConnman::AddConnection` dials on the RPC thread (net.cpp:1871-1907).

Fixed on `main` by "Net: the idle tick admits new peers and dials queued
requests, as Core does at once": `%sync-idle-tick` runs `merge-inbound-peers`
and the new `dial-queued-nodes` before the pump. Test:
`tests/node/sync-thread-tests.lisp` (a pending inbound peer's ping is
answered by one tick; one tick consumes the addconnection queue), 4 failures
against the pre-fix `init.lisp` loaded into the image, green after. Cold
battery on the branch 38,483 green with one who-sets assertion renamed.

## Root causes 2 and 3, fixed in the same round

- **Unsolicited blocks dropped during a sync pass.** The ten blocks
  `example_test.py`'s peer pushed were read by the IBD drain
  (`dispatch-ibd-message`), whose block arm handed them to
  `process-received-block`, which drops a block whose header is not in the
  index (`Received unknown block`). Core's `ProcessNewBlock` runs
  `AcceptBlockHeader` first (validation.cpp:4340). Fixed by "Net: the
  block-download drain indexes an unseen header before judging the body":
  the arm runs an unknown header through `ingest-headers-from-peer` and then
  proceeds; test in `tests/networking/ibd-tests.lisp`, 2 failures pre-fix.
- **`-asmap=<relative>`** (`feature_asmap.py:66`) was anchored at the datadir
  root where Core anchors it at the chain directory (init.cpp:1591-1593).
  Fixed by "Net: a relative -asmap path hangs off the network data directory,
  as Core's does" (`asmap-file-path`; the bare and boolean spellings are
  refused as Core refuses them without an embedded map).

## Re-sweeps

| binary | fixes in it | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|---|
| `6011851b` | none (baseline) | 48 | 171 | 21 | 23 |
| `55bb7ba8` | idle tick admits new peers | 48 | 180 | 12 | 23 |
| `cf2e9596` | + asmap path, drain indexes headers | 47 | 179 | 14 | 23 |
| `f662c475` | + wait-ending tick, getnetworkinfo live count | **49** | **181** | **10** | 23 |

Read by failure point, not by the PASS column (docs/functional-triage-2026-08-25.md):
after the idle-tick fix nine timeouts became ordinary failures deeper in
their test (feature_anchors, feature_fee_estimation, p2p_add_connections,
p2p_addr_relay, p2p_eviction, p2p_segwit, wallet_basic, wallet_conflicts,
wallet_listtransactions), `p2p_1p1c_network` passed outright, and
`wallet_balance` went from PASS to a `sync_blocks` timeout -- root cause 4
below. After the drain fix five more failure points advanced (feature_asmap
66 -> 89, feature_cltv 95 -> 138, feature_dersig 93 -> 103,
p2p_compactblocks 162 -> 210, p2p_compactblocks_blocksonly 75 -> 96) and
`wallet_balance` passed again. `wallet_avoidreuse` and `wallet_conflicts`
timed out in the third sweep only (the August triage already recorded
`wallet_avoidreuse` as batch-sensitive); `p2p_invalid_locator` failed once in
the third sweep at its second peer's handshake; all three passed in the fourth.

The fourth sweep against the baseline: no test lost status; eleven timeouts
ended (ten now fail on a later assertion, `p2p_1p1c_network` passes); six
failure points advanced. `p2p_add_connections` got past its connection count
and now times out while adding inbound peers one every 10 to 20 s -- the
listener's serial inline handshake is the next thing to read there. The
sixth commit (root cause 6) landed after the fourth sweep; `rpc_users.py`
run alone against it passes its five init-error checks and stops at :127
(`-norpccookiefile` start-up never logs `Done loading`).

## Root cause 4: a peer dialed mid-wait waited for the sync pass

Moving the merge and the dials into the idle tick left OUR side of a new
connection -- the sync pass's getheaders -- for the end of the 30-second
wait, where the cycle-start merge had been followed by the pass at once.
`wallet_balance.py` restarts node1, connects it and calls `sync_blocks`
(60 s); the re-sweep timed it out. Fixed by "Net: a tick that admits or
dials a peer ends the wait, so the sync pass asks it for headers now"
(`%sync-idle-tick` returns T when node-peers grew; test red 1 of 11 on the
previous tick).

## Root cause 5: getnetworkinfo counted peers getpeerinfo had dropped

`p2p_add_connections.py:73`, reachable only after root cause 1: the
framework's `disconnect_p2ps` waits until getpeerinfo shows no test peer,
then `check_node_connections` reads getnetworkinfo's `connections_out` and
found 10. Core counts m_nodes for both (rpc/net.cpp:711-713, net.cpp:3769)
and DisconnectNodes erases a closed connection from it on the next socket
round (net.cpp:1909-1939); ours keeps a `:disconnected` peer in node-peers
until the sync cycle reaps it, and only getpeerinfo hid it. Fixed by "RPC:
getnetworkinfo counts the peers getpeerinfo lists" (test red 2 of 3 on the
previous handler).

## Root cause 6: a failed RPC server start was not an init error

`rpc_users.py:160` waits sixty seconds for `Error: Unable to start HTTP
server. See debug log for details.` on stderr after `-rpcauth=foo`. Core's
AppInitMain turns AppInitServers' false into that InitError
(init.cpp:1559-1561); ours logged the malformed option and ran on without an
RPC server. Fixed by "Init: a failed RPC server start is Core's InitError,
not a node without RPC" (`start-rpc-early` signals `init-error` when
`start-rpc-server` returns NIL; test red on the previous step).

## Seen alongside, not yet fixed

- **Mainnet was not our default chain.** `mining_mainnet.py` and
  `rpc_validateaddress.py` write a config with no chain selector and expect
  mainnet; our CLI defaulted to testnet3, so the default-section options were
  refused as testnet-unsuitable. Decided 2026-09-13: mainnet is the default,
  as in Core ("Config: the default chain is mainnet, as Core's is"). Run alone
  against that commit, `mining_mainnet.py` passes and `rpc_validateaddress.py`
  reaches its first real assertion: for one malformed address Core answers
  `Invalid Bech32 checksum` where we answer the generic `Invalid or
  unsupported Segwit (Bech32) or Base58 encoding.`
- **`tool_bitcoin.py`** wants a `bitcoin` multiplexer binary; declared absent
  in `scripts/conformance-config.sh` like `bitcoin-cli`.
- **Three init-error texts** the framework waits 60 s for and never sees:
  `Witness data for blocks after height N requires validation. Please restart
  with -reindex` (feature_presegwit_node_upgrade.py:39), `Error initializing
  block database` (feature_reindex_init.py:23, a removed `blocks/index`) and
  `The block database contains a block which appears to be from the future`
  (rpc_blockchain.py). Each is a chainstate-load failure Core reports before
  offering `-reindex`.
- **Wallet files by name** (wallet_startup.py:38, wallet_reorgsrestore.py:203,
  wallet_listtransactions.py:229): the tests open `wallets/<name>/wallet.dat`;
  ours is a LevelDB directory (docs/coverage-vs-core-2026-08-24.md 15.5).

### Known divergence: `-reindex` does not wipe (decided 2026-09-18)

Our `-reindex` rebuilds the block index from the block files *additively* and wipes no block
file, no chainstate and no block-tree database. That is a decision, not an omission
(`docs/reindex-decision-2026-09-18.md`, option B), and it is now stated at the option's own
entry and in `docs/manual.lisp`'s storage section. Three functional tests assert the wipe
semantics and therefore cannot pass while the divergence stands. None of them currently
fails *at* those lines — each fails earlier, for an unrelated reason — so nothing is blocked
on the decision today:

- `feature_remove_pruned_files_on_startup.py:65-68` — a prune-mode `-reindex` must leave
  exactly `blk00000.dat` + `rev00000.dat` and `getblockcount() == 0`. Core deletes them in
  `CleanupBlockRevFiles` (`node/blockstorage.cpp:654-688`). Fails earlier at `:64`.
- `feature_index_prune.py:187-190` — an index whose best block is past the prune horizon
  must start after `-reindex`. The index wipe is now ported (Core's `f_wipe`,
  `index/base.cpp:68-73`), so this row needs only its earlier failure at `:103` fixed.
- `feature_assumeutxo.py:725-728`, `:791-794` — one chainstate after either reindex flag.
  The snapshot-chainstate deletion is now ported; fails earlier at `:187`.

The three Core behaviours that cost no block file were taken on 2026-09-18: the persisted
`'R'` resume marker, snapshot-chainstate deletion under either flag, and the index
wipe-and-resync. `feature_reindex.py`, `feature_reindex_readonly.py`, `wallet_reindex.py`
and `feature_loadblock.py` do not depend on the wipe.

## Ready-made batches from the baseline

**RPC error text differs from Core's** (14 tests, each one message):

| test : line | Core expects | we say |
|---|---|---|
| feature_assumeutxo.py:220 | `Population failed: Work does not exceed active chainstate.` | `assumeutxo block hash in snapshot metadata not recognized` |
| feature_block.py:157 | `bad-txns-inputs-missingorspent, CheckTxInputs: inputs missing/spent in transaction <txid>` | `MISSING-INPUT` |
| mempool_limit.py:212 | `mempool min fee not met` | `min relay fee not met` |
| mempool_truc.py:69 | `TRUC-violation, version=3 tx <txid> (wtxid=…)` | `truc-tx-too-big` |
| rpc_createmultisig.py:150 | `Missing transactions` | `txs must be a non-empty array of hex transactions` |
| rpc_getblockfrompeer.py:61, rpc_getblockstats.py:188 | `Block not available (not fully downloaded)` | `Block not found` |
| rpc_getdescriptorinfo.py:41 | `' is not a valid descriptor function` | `Internal error: The value …` (a type error escapes) |
| rpc_rawtransaction.py:267 | `JSON value of type string is not of expected type object` | `JSON value of type null is not of expected type string` |
| rpc_txoutproof.py:37 | `Transaction not yet in block` | `Need a blockhash (no txindex on this node)` |
| wallet_keypool.py:165 | `Transaction needs a change address, but we can't generate it.` | `Unknown named parameter feeRate` |
| wallet_sendall.py:254 | `Must provide at least one address without a specified amount` | `recipients must be a non-empty array` |
| wallet_sendmany.py:33 | `… invalid value type: bool` | `… invalid value type` |

**We accept what Core rejects** (`No exception raised`, 7): feature_bip68_sequence.py:114,
mempool_expiry.py:87, mempool_persist.py:194, rpc_gettxspendingprevout.py:111,
rpc_packages.py:526, rpc_signmessagewithprivkey.py:44, wallet_simulaterawtx.py:93.

**A boolean the other way** (`not(False == True)`, 6): feature_maxtipage.py:39,
p2p_feefilter.py:24, wallet_gethdkeys.py:62, wallet_importdescriptors.py:583,
wallet_multiwallet.py:78, wallet_musig.py:89.

## Round 2

Same oracle, same recipe, run the same day after the round-1 fixes. Each item
below is one commit on `main` with a pre-fix-red test and the Core lines in
its message; the cold battery ran on every branch and on the merged `main`
before each push (38,510 → 38,563 checks).

| root cause | Core | fix |
|---|---|---|
| 7. At the tip, header sync waited ~10 s per silent peer on the sync thread, so every peer the idle tick admitted cost a 20-second pass (`p2p_add_connections`: one connection per pass) | SendMessages sends the initial getheaders and moves on, net_processing.cpp:5797-5810 | "Net: at the tip, header sync sends its getheaders and does not wait" |
| 8. `init message:` lines never logged; `-norpccookiefile` read as a cookie file named `0` | noui.cpp:56; rpc/request.cpp:115, httprpc.cpp:261 | "Init: Core's `init message:` log lines, and -norpccookiefile means no cookie file" |
| 9. Blocks connected by the block-download drain (every block fetched after an announcement) were never announced onward; `example_test` node1 heard about 1 of 10 | UpdatedBlockTip queues every new tip for every peer, net_processing.cpp:2160-2189 | "Net: every new tip is announced from the tip hook" (the `:updated-block-tip` hook replaces the two ad-hoc call sites) |
| 10. A header-only block was `Block not found` (-5); `gettxoutproof` demanded a blockhash or txindex | CheckBlockDataAvailability, rpc/blockchain.cpp:671-700; txoutproof.cpp:71-91 | "RPC: a known header without its body is `Block not available`, and gettxoutproof finds the block through an unspent output" |
| 11. One fee-floor reason where Core has two | CheckFeeRate, validation.cpp:699-712 | "Mempool: the two fee-floor reasons, in Core's order" |
| 12. A closed connection still counted toward the addconnection cap for a whole cycle | AddConnection counts m_nodes, net.cpp:1894; DisconnectNodes erases, :1909-1939 | "Net: a closed connection no longer counts toward addconnection's outbound cap" |
| 13. A commitment without witness was "stripped" at any height; with `-testactivationheight=segwit@120` node1 refused every block node0 mined below 120 and re-requested them forever (4,500 getdata in a minute) | ContextualCheckBlock judges the commitment only where segwit is active, validation.cpp:4021 | "Validation: a witness commitment is judged only where BIP141 is active" |
| 14. One getheaders per unconnecting announcement (thirty in a millisecond after a 99-block mine), and node0 disconnected node1 for it; the same per inv | MaybeSendGetHeaders throttles both, net_processing.cpp:2659, :4198 | "Net: unconnecting headers ask once per response window…", "Net: an inv naming an unknown block asks for headers once per response window" |
| 15. Block rejections logged as upper-case keywords; the framework greps for Core's lower-case reasons (`unexpected-witness`) | BlockValidationState::ToString, consensus/validation.h:110-121 | "Validation: a rejected block is logged in Core's words" |

Three log lines Core writes and ours did not were added along the way, and
they were what it took to see 13 and 14: the condition text of a send
failure, `received: block|headers` for the drain's own two arms, and the
ingest decisions (`missing prev block`, `Ignoring low-work chain`); plus
`sending <command> (<bytes>) peer=<id>` for every send (net.cpp:4075).

### Round-2 sweep

Binary `580627ba` (every round-2 fix but the inv throttle, which landed
during the run), classification in `docs/functional-sweep-2026-09-13/after-580627ba.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `6011851b` baseline | 48 | 171 | 21 | 23 |
| `f662c475` round 1 | 49 | 181 | 10 | 23 |
| `580627ba` round 2 | **58** | **176** | **6** | 23 |

Against round 1: nine tests now pass (`example_test`, `mining_mainnet`,
`p2p_add_connections`, `p2p_compactblocks_hb`, `rpc_users`,
`wallet_importprunedfunds`, `wallet_listsinceblock`, `wallet_orphanedreward`,
`wallet_transactiontime_rescan`); thirteen failure points advanced
(`p2p_segwit` 309 → 145, `p2p_sendheaders` 181 → 340, `rpc_txoutproof` 37 → 84,
`wallet_groups` 42 → 137, `mining_basic`, `mempool_limit`, `rpc_getblockfrompeer`,
`rpc_getblockstats`, ...); three timeouts became ordinary failures; no test
lost status. `feature_pruning` and `wallet_address_types` timed out this run
(both have alternated before). The "Block sync timed out" cluster is gone.

Next round, from this sweep: the 13 RPC error texts still open (table above),
8 "accepted what Core rejects", the 5 wallet-file (`wallet.dat`) failures,
`p2p_node_network_limited.py:110` (a `getblockfrompeer` on a header-only
block should be allowed), and the two remaining init-error texts.

## Round 3

Three, then three more, parallel batches on worktree branches, each with a
pre-fix-red test and Core file:line per commit and a green cold battery on the
branch; the coordinator rebased, ran the merged battery (fresh FASL volume
wherever a defstruct changed) and pushed. Sixty-two code commits landed
between `4c0db43b` and `7e124486`; the ones below are the root causes, grouped
by what the functional suite was measuring.

| area | root causes (commit subjects abridged) |
|---|---|
| Net, peer bookkeeping | the first peer is id 0 as Core's is; a closed connection no longer counts; the initial getheaders goes to each peer once (`fSyncStarted`); an addr-fetch peer is never asked for headers; an empty headers answer re-arms the throttle; a block batch is requested oldest first; a BIP37 `filter*` is refused without NODE_BLOOM; a peer is not disconnected for asking for what this node announced; an equal-work sibling is worth downloading (`<`, not `<=`); a compact block awaiting `getblocktxn` is in flight; a bare `-whitelist` grants Core's implicit permissions |
| Init | Core's reindex-offer text; a relative `-pid` under the network datadir; owner-only files (Core's umask) |
| Validation / mempool | a block's transaction verdict carries Core's reason and debug message (`*block-reject-reasons*`, incl. `high-hash`, `bad-txnmrklroot`, `bad-txns-nonfinal`); BIP68 is policy before CSV activates; an accepted transaction expires the stale ones; the replacement fee rejection is `insufficient fee`; a TRUC violation is one reason; savemempool through `.new` |
| RPC arguments and texts | one `RPCTypeCheckObj` with `fStrict` (gettxspendingprevout's closed sets, the named-only options); `ParseHashV` words; combinerawtransaction, createrawtransaction, verifymessage (-3 base64, key hash), gettxoutproof as a set, loadtxoutset halves, a body the index placed but cannot read is `Block not found on disk`, `initialblockdownload` is the tip's age, `verificationprogress` is `GuessVerificationProgress`, getblocktemplate's pre-BIP141 units, submitblock indexes an unseen header and judges the block before its parent, testmempoolaccept reports only what Core finished, submitpackage's -25, getblockfrompeer's pre-segwit refusal, generate's deprecation text, `help <method>` answers the document and hides Core's hidden category, echo, getpeerinfo help, getblockchaininfo's prune target, a snapshot path under the datadir, decodescript's `wsh()` inference |
| Signing / wallet | a partially signed multisig input is written and read back; a musig() participant key is the descriptor's; gethdkeys reports held keys; simulaterawtransaction refuses a foreign input; a PSBT process RPC reports the psbt it returns; pay-to-anchor signs with nothing; sendmany/sendall diagnostics |

Two live-node hazards came out of the batches rather than the suite:
`*ibd-context*` is rebound per pump tick, so anything an RPC reads from it
sees a fresh context (the compact-block in-flight mark now goes through the
peer); and block announcements are not coalesced -- one inv per connected
block from the mining thread, where Core queues per peer and flushes up to
eight headers (net_processing.cpp:2160-2189, :5830-5900). The second is open.

### Round-3 sweep

Binary `67b724d2` (batches A, B, C merged; D and E landed during the run),
classification in `docs/functional-sweep-2026-09-13/after-67b724d2.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | **69** | **166** | **5** | 23 |

Fourteen tests went to PASS (`feature_maxtipage`, `feature_reindex_init`,
`mempool_expiry`, `p2p_eviction`, `p2p_node_network_limited`,
`p2p_nobloomfilter_messages`, `rpc_getblockstats`, `rpc_getdescriptorinfo`,
`rpc_signmessagewithprivkey`, `rpc_txoutproof`, `wallet_address_types`,
`wallet_keypool`, `wallet_sendmany`, `wallet_simulaterawtx`) and three left it
(`p2p_compactblocks_hb`, `p2p_net_deadlock`, `wallet_change_address`, each
explained below); about thirty failure points advanced. Batch D's oracle runs add `rpc_decodescript`,
`rpc_named_arguments`, `rpc_orphans`, `rpc_preciousblock`; batch E's add
`feature_posix_fs_permissions` and `feature_versionbits_warning`.

Three things about the measurement itself, learned this round:

- The eight-way parallel driver rewrote `build/bin/bitcoind` (a symlink
  `conformance-config.sh` replaces at startup) from all eight runs at once;
  sixteen tests failed inside their first second with `OSError: [Errno 22]`
  before any node ran. They were rerun in staggered batches and folded in.
  The harness must be started serially.
- The classifier's failure point is the deepest frame in the test file. A
  failure inside a helper (`rpc_packages.py:51`, `p2p_blocksonly.py:36`)
  reads as a line-number retreat when the test in fact advanced; the last
  `TestFramework (INFO)` step is the comparison that holds.
- Under the eight-way load, `wallet_change_address`, `wallet_groups` and
  `wallet_send` time out on mempool sync and pass alone: the 2-second
  non-preferred-peer request delay plus a once-a-second scheduler is slow when
  twenty-four nodes share the CPU. Not a defect, but it is what the numbers
  above contain.

Two failures were bisected with the oracle on a scratch worktree:

- `p2p_net_deadlock` passed through round 2 only because the test sends its
  two 4,000,000-byte messages to peer id 0, which did not exist while ids
  started at 1. With ids as Core's, the messages go out, each node's send
  buffer passes the 1 MB pause threshold, and each side stops READING the
  paused peer, which is the deadlock the test is about: Core keeps receiving
  under `fPauseSend` (only `ProcessMessages` returns early,
  net_processing.cpp:5244) and pauses receiving only at `m_recv_flood_size`.
  Open, and listed first for the next net batch.
- `p2p_compactblocks_hb` has been intermittent since the baseline (three
  timeouts, a fail, a pass, then three fails). Two modes were captured with a
  temporary per-second drain log: a block an inbound peer says it sent that
  never reaches our socket, and a fresh outbound dial that reads `Bad message
  magic` a millisecond after sending `version`, before the remote replied.
  Open.

Deployed: testnet4 relaunched on `911848f9` (batches A-D), synced and out of
IBD within a minute, 21 peers an hour later. Mainnet stays on `6011851b`
until its restart is approved.

## Round 4

Batches F (P2P bookkeeping), G (wallet), H (mempool and mining RPCs) and J
(init, config, interfaces) merged onto `main` through `bc65804a`, each with
the branch battery green and the merged battery green before the push
(38,956 → 39,242 checks). Their root causes are in the commit log between
`7e124486` and `bc65804a`; the ones that changed the node's behaviour most:
the accept loop handed each handshake to its own thread (one silent peer had
blocked every other connection for 15 s), the tx-request tracker moved to the
mockable clock, `-rpcthreads` stopped being a connection cap that blocked the
HTTP accept loop, ZMQ bound once per address, a reject reason and its debug
message became two fields as in Core, a disconnected block kept its validity,
and the wallet's transaction map is walked in txid order (SBCL's `maphash` is
arrival order; Core's `unordered_map` is not).

### Round-4 sweep

Binary `bc65804a`, classification in
`docs/functional-sweep-2026-09-13/after-bc65804a.tsv`; the harness was started
with staggered batches and the few race-hit tests were rerun serially:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | 69 | 166 | 5 | 23 |
| `bc65804a` round 4 | **100** | **137** | **3** | 23 |

Thirty-one tests went to PASS and none left it. Every line-number retreat
was checked against the test's own step log and turned out to be a helper
frame or a load flake that passes alone (`feature_segwit` passes now;
`p2p_segwit` reaches its block-relay subtest; `feature_fee_estimation` fails
in the RBF section, one step past where batch J left it).

Deployed: both live nodes to `bc65804a` (testnet4 first, then mainnet).

## Round 5

Batches I, N and S (net), K (mempool and package RPCs), M, P and R (RPC, REST,
coinstats), L, O, Q, T and Z (wallet, PSBT, descriptors), W (reindex), X and Y
(storage, datadir) and U (init, config, interfaces) merged onto `main` from
`bc65804a` through `2a7074c4`: 148 commits, 22 of them `tests:` commits
(ratchets, fixtures, merge seams). Each fix carries a pre-fix-red unit test and
the Core file:line in its message; the merged battery ran on a fresh FASL volume
before every push (39,242 → 40,290 checks) and the `::` ceiling fell from 3,865
to 3,813. The behaviour changes that mattered most, by area:

**Net.** Round 3's two bisected failures and one of its two live-node hazards
are closed. Block announcements are queued per peer and flushed once a pass as
one headers message of up to eight or one inv (`3f9f2ae8`,
net_processing.cpp:2160-2189, :5825-5956); the other hazard, a fresh
`*ibd-context*` per pump tick, is still open, and `74155cca` keeps its block
request in a process-global table for that reason. The "Bad message magic
80110100" seen on fresh connections was the resumable reader's second drain
after its EOF probe: its byte count was discarded and the next pass overwrote
the peer's first 24 bytes (`5040752a`). A send-paused peer is still read, its
messages parked, as Core pauses dispatch and never the socket (`1ffdd838`,
`p2p_net_deadlock`). A destructive `(sort (remove-if-not …))` had truncated the
live peer list, dropping the peer a getdata had just gone to (`b64fa28c`, the
"Block sync timed out" family). Header sync now drives one peer with Core's
15-minute timeout doing the rotation, plus one new peer per inv'd block, in
place of a failover that asked every peer on every pass (`1caceddd`,
`749d15d4`). A mutated block is refused at the wire and its sender punished;
one mangled copy had cancelled an honest peer's delivery (`5e380b1c`). A block
that fails to connect is marked failed once, Core's InvalidBlockFound, instead
of a retry budget (`6121e4a8`). Also: genesis carries its own proof, so every
chain-work had been one block short and `-minimumchainwork` measured against
it (`1ed67b03`); block validity is monotone, so a reorged-off block stays
servable (`5f186ca3`); the ban list is keyed by subnet (`23b83f8b`); an
accepted peer is published before its handshake (`18937510`); the tx-inv
trickle and the unbroadcast re-announcement run on the mockable clock
(`d1e73338`, `e3d34be8`); the stalling timeout decays as blocks connect
(`ff43ea04`); a pruned block fetched by `getblockfrompeer` is written
(`74155cca`).

**Validation and storage.** Mined blocks are now Core's bytes: coinbase
version 2 and a single `OP_0` extranonce where ours wrote 1 and four zero bytes,
so the same RPCs built a different chain from Core's (`9507d894`), pinned on
the `base_hash` Core's own `rpc_dumptxoutset.py` carries (`5a83b0ef`). A failed
tip-extending block is marked invalid, so `submitblock` answers
`duplicate-invalid` and a child header `bad-prevblk` (`af9df67a`, `8c9ef37b`);
`invalidateblock` lands on the best chain still valid and re-adds at most ten
blocks' transactions (`3a19182f`, `a6bda7b3`). A disconnect reads the rev
record, not an undo cache that could serve a record whose file was gone
(`2848a380`). A pruned restart no longer writes genesis into a new blk file
(`8aa00e8c`). The reindex walk streams in file order and logs Core's
out-of-order lines (`b2ff7eb1`, `c63e2fc9`). The filter and coinstats index
databases open at Core's `…/db` and an existing one is moved there in place
(`3f22c293`; the live nodes migrate on their next start), and every LevelDB
open and wipe is logged in Core's words (`127f40b6`). An index whose best block
is past the pruned data, and an assumeutxo base the chain parameters do not
know, now stop start-up (`8c7ccc14`, `9a457df8`). A transaction's cached txid,
wtxid and weight are dropped when it is mutated in place; a fee bump signed in
place had kept its unsigned weight and reported 66.6 sat/vB against a 60 target
(`2f0c63d8`).

**Mempool and mining.** `testmempoolaccept` validates a package as a package
(`3ebc9037`); a package TRUC violation carries Core's sentence (`e205d6a8`); a
member accepted alone reports its prioritised feerate (`333bd7b5`);
prioritisation invalidates the cached template (`d7ad0e5a`); a reorg re-add is
stamped sequence 0 so a peer may fetch it (`bbe09369`); `-maxmempool` must hold
one cluster (`316a7a99`); a combo() coinbase pays the script Core picks
(`9db375bf`).

**RPC and REST.** A repeated JSON key reaches the handler (`2d515492`); an
undecodable address says why and where, Core's bech32 LocateErrors
(`c6b12be2`); `submitheader` answers the reject token (`4c1f9b45`); a
wrong-arity call answers the whole help document and an explicit null in a
required argument is `-3` (`14914b1d`, `3ee4418b`); `help` lists usage lines
under Core's category headings, from a table generated from Core's sources
(`532efa3e`, `fa3e069a`); `migratewallet` exists, so no Core method with a
typed argument is left unserved (`205903fa`); `combinerawtransaction` merges
signatures instead of keeping the longest scriptSig (`2e8342b7`); `getchaintips`
always reports the active tip (`01a573e5`); `/rest/getutxos` reads BIP64's POST
body and `/rest/headers` answers an unknown hash with an empty result
(`ef1a1c2d`, `a1b0fe40`); `gettxoutsetinfo` serves a reorged-out block's
coinstats by hash (`747a3353`).

**Wallet, PSBT and descriptors.** `node::MiniMiner` is ported, so an
unconfirmed input is priced with its ancestors' bump fee and a shared ancestor
is paid once (`aed46dc1`, `70def246`); `-limitancestorcount` and
`-limitdescendantcount` reach coin selection (`888f892b`). A cosigner signs
for a key an input lists when it does not own the script, which is what
multi-party signing needs (`cf65f5b2`). `bumpfee`'s `outputs` replaces the
outputs, and every refusal had left with code NIL because the helper bound five
values of a three-value function (`7939a174`). A taproot PSBT drops the
previous transactions it cannot need and records the `witness_utxo` it signed
over (`8d0d6298`, `9e82bae3`). A `musig()` participant is a key expression with
its own cache slot and normalizes as Core's does (`ca924814`, `a02ca2ed`).
`walletprocesspsbt` runs on a private-keys-disabled wallet and is idempotent
(`5eb7e09f`, `821e2c7f`); an extended key is read on the running chain only
(`d4a9583d`); a zero-value output's spend is still from the wallet
(`acacc9a9`); a load during a background sync is refused by height
(`d8778aa5`); the BIP371 field lengths reject all 41 of Core's invalid PSBT
vectors (`81707abe`).

**Init, config and interfaces.** Long-lived threads log Core's `thread
start`/`thread exit` lines (`99a04890`); config-read errors carry Core's
prefix, and a block that fails ConnectBlock is logged (`1c6e33b5`);
`-bind=…=onion` binds the address it names, the RPC server binds both
loopbacks, and a duplicated binding is an init error (`14914b1d`,
`bd1693bb`); ZMQ `rawtx` is the with-witness serialization, which is why
`interface_zmq` timed out in its sync-up, and `unix:` addresses bind
(`d724da1e`, `6fdb7885`); notify commands ShellEscape a value instead of refusing it and
`-blocknotify` passes the hash in display order (`bdf40a7f`, `09c5db90`,
`3ccdda96`); a log line's timestamp is one clock reading, so `debug.log` no
longer runs backwards within a second (`fafcb414`).

Three guards came out of the merges: the structural memos drop on a src edit
(`20c4a811`), an in-place transaction mutation must invalidate the caches
(`1a216f60`), and a red suite no longer skips the battery's three transcript
gates (`9314beb7`). The cold lane's undefined-variable gate caught two
docstrings ended early by an unescaped quote (`a2a645de`, `76dfbe48`).

### Decisions recorded in Round 5

- **`-reindex` stays additive** — [reindex-decision-2026-09-18.md](reindex-decision-2026-09-18.md),
  option B, and "Known divergence" above. The three pieces that cost no block
  file were ported: the `'R'` resume marker (`bdebf6ce`), snapshot-chainstate
  deletion under either flag (`a59a188e`), and the index wipe-and-resync
  (`2b1ab7c2`).
- **Absolute wallet paths stay refused.** The containment rule is stated in
  `%VALID-WALLET-NAME-P`'s docstring ([src/wallet/wallet.lisp](../src/wallet/wallet.lisp)):
  an absolute path is the one form that writes wallet files outside the
  datadir. `wallet_crosschain.py:32` fails on it (`-8 Invalid wallet name`) and
  will while this stands.
- **The RPC server binds `::1` and `127.0.0.1`, and one bound is enough** —
  `+RPC-DEFAULT-LOOPBACK-BINDS+` and `%BIND-RPC-ACCEPTORS` in
  [src/rpc/server.lisp](../src/rpc/server.lisp) (`14914b1d`, Core
  httpserver.cpp:320-321, :341-357). Batch U reported that the socket library
  in the image cannot listen on `::1`, so the node serves on `127.0.0.1` alone
  there and `rpc_bind.py:46` stays red; not re-measured here.
- **A `musig()` cache written under the old key numbering is repaired on the
  miss**, not from a version marker — [wallet-plan.md](wallet-plan.md),
  "The descriptor xpub cache and musig() key-expression numbering" (`ca924814`).

### Round-5 sweep

Binary `3a337f7e` (batches I, K, L, M; the flips rerun serially), classification
in `docs/functional-sweep-2026-09-13/after-3a337f7e.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | 69 | 166 | 5 | 23 |
| `bc65804a` round 4 | 100 | 137 | 3 | 23 |
| `3a337f7e` round 5, first half | **117** | **119** | **4** | 23 |
| `2a7074c4` round 5 | **136** | **102** | **2** | 23 |

Nineteen tests went to PASS (`feature_minchainwork`, `feature_utxo_set_hash`,
`mempool_package_limits`, `mempool_sigoplimit`, `mining_prioritisetransaction`,
`p2p_blocksonly`, `p2p_disconnect_ban`, `p2p_fingerprint`, `p2p_net_deadlock`,
`p2p_permissions`, `rpc_getchaintips`, `rpc_gettxspendingprevout`, `rpc_setban`,
`rpc_validateaddress`, `wallet_anchor`, `wallet_createwalletdescriptor`,
`wallet_listdescriptors`, `wallet_reindex`, `wallet_sendall`) and two left it,
each checked against its failure line:

- `feature_csv_activation` (`:181`, `Predicate ''''`) is a real regression.
  The node kept asking the announcing peer for a block whose script had
  failed, a getdata/reject loop for the whole 60-second wait; before
  `b64fa28c` the loop had ended only because that peer fell out of the
  truncated list. `65422f45` made the walk honour the retry pause, which left
  the node asking for nothing, and `6121e4a8` ported InvalidBlockFound in place
  of the retry budget: FAIL → PASS on the oracle.
- `wallet_address_types` (`:91`, `Predicate ''''`) is the 24-byte loss on a
  fresh connection in its six-node mesh, a fault present before this round and
  fixed by `5040752a`.

`feature_proxy` went from a failure to a timeout. Twenty-three failure points
moved later (`p2p_segwit` 200 → 309, `wallet_fundrawtransaction` 337 → 591,
`rpc_getdescriptoractivity` 65 → 204, `feature_coinstatsindex` 91 → 280,
`mempool_truc` 284 → 520, `wallet_hd` from an init failure to `:84`, ...).
Twelve moved earlier. Three are helper frames reached after a line that now
passes: `feature_assumeutxo` `:187` is the `expected_error` helper called at
`:191`, after `:220`; `rpc_dumptxoutset` `:26` is reached from `:75`, after the
`:50` `base_hash`; `mempool_limit` `:93` is in a sub-test `run_test` calls
after `:238`. Two are the mempool-sync timeouts under the eight-way load
(`wallet_basic`, `wallet_groups`), and `wallet_send` `:131` is inside its own
`test_send` helper. `p2p_sendheaders` `:169`, `p2p_addrv2_relay` `:58` and
`p2p_compactblocks_hb` `:32` are helper frames too, so only the step log can
compare them (`p2p_sendheaders` failed at `:309` on `749d15d4`'s oracle runs;
`p2p_compactblocks_hb` has been intermittent since the baseline).
`p2p_ibd_stalling` stopped at `:106`, which passed on `ff43ea04`'s oracle run.
Two are real retreats inside one sub-test, not bisected: `mempool_reorg`
106 → 87 (three invs where, with no mocked time elapsed, the test expects none)
and `p2p_opportunistic_1p1c` 557 → 514 (`test_orphanage_dos_many`).

Binary `2a7074c4` (the whole round; four staggered batches of the harness,
the flips and time-outs rerun serially), classification in
`docs/functional-sweep-2026-09-13/after-2a7074c4.tsv`. Twenty-two tests went
to PASS (`feature_bind_extra`, `feature_coinstatsindex`,
`feature_csv_activation`, `feature_includeconf`, `feature_notifications`,
`feature_reindex`, `mining_basic`, `p2p_compactblocks_hb`,
`p2p_initial_headers_sync`, `p2p_mutated_blocks`, `rpc_createmultisig`,
`rpc_dumptxoutset`, `rpc_getblockfrompeer`, `rpc_help`,
`rpc_invalid_address_message`, `rpc_invalidateblock`, `rpc_scantxoutset`,
`rpc_signrawtransactionwithkey`, `wallet_abandonconflict`,
`wallet_address_types`, `wallet_conflicts`, `wallet_spend_unconfirmed`).
Three left it, and each fails serially too, so they are regressions of the
round's second half, handed to the batches that own the area:
`feature_port` `:48` (an onion `-bind` with no port must take `-port` + 1),
`p2p_leak_tx` `:51` (the queued inv does not go out when mock time advances)
and `p2p_permissions` `:149` (the peer is not in `getpeerinfo` after a
restart and reconnect). `feature_maxuploadtarget` and `interface_zmq` went
from a time-out to a failure (`:177`, `:254`). `feature_proxy` and
`feature_pruning` still time out at 600 seconds alone.

Deployed: both live nodes to `2a7074c4` (testnet4 first with a 15-minute
soak, then mainnet; neither needed the index migration, the pre-Core layout
notice is logged and `-migratedatadir` stays optional).

After the sweep, commit messages record six more oracle runs going FAIL → PASS:
`feature_csv_activation` (`6121e4a8`), `p2p_initial_headers_sync`
(`749d15d4`), `p2p_mutated_blocks` (`5e380b1c`), `p2p_ibd_stalling`
(`ff43ea04`), `rpc_getblockfrompeer` (`74155cca`) and `feature_notifications`
(`bdf40a7f`). The sweep of `2a7074c4`, which carries all of round 5, is
the last row of the table above.

## Round 6

Nine worktree batches merged onto `main` on 2026-09-23, from `2a7074c4`
through `bdfd8434`: 188 commits, 14 of them `tests:` commits; seven are
seams where one batch met another on `main` (`a4024ada`, `40003bad`,
`c8b0147f`, `9335fe3a`, `e4c68bdc`, `0dab093c`, `bdfd8434`). Each batch ran
its own green battery on a fresh FASL volume, and the merged battery ran
before every push (40,290 → 41,577 passing checks, plus four skips: the
Core-binary lane below, which skips where `/releases` is not mounted); the
`::` ceiling fell from 3,813 to 3,780. The batches, in merge order: the GA12
backlog audit
([gap-analysis-12-backlog.md](gap-analysis-12-backlog.md), 7 commits),
bitcoin-cli (6), previous-releases compatibility and the Core-binary
differential lane (8), mempool3 (28), net4 (27), tools and the external signer
(5), init3 (30), p2p5 (23) and wallet7 (54). The behaviour changes that
mattered most, by area:

**GA12 audit.** Every item `gap-analysis-11.md` had closed for GA12 was
re-verified against its commit and test; all fourteen hold, two only partly,
and both were finished here: a restore source with no newline is refused at a
64 MiB line instead of buffered until the image dies (`f020f81e`), and a
pay-to-anchor input is a non-witness signature instead of an ECASE failure
(`932d8735`). `-rpcworkqueue` stopped being accepted and ignored: a request
past its depth is Core's 503 `Work queue depth exceeded`, and both HTTP pool
knobs are `max(atoi, 1)` with Core's 16 and 64 as defaults (`7b468384`,
httpserver.cpp:255-258, :419, :440).

**bitcoin-cli.** `src/cli/` is Core's `bitcoin-cli.cpp` as its own layer on
the config layer: SetupCliArgs and ParseParameters' refusals, all 331 rows of
`vRPCConvertParams`, UniValue's number-preserving printer, CallRPC's port,
cookie and `-rpcwallet` rules and texts, `-rpcwait`, `-stdin*`, `-getinfo`,
`-netinfo`, `-generate` and `-addrinfo` (`9ee1a70d`). One saved image serves
both programs, dispatching on `argv[0]`. Getting the functional tests through
it took three server changes: a named-params object that repeats a key is
Core's -8 (`08d01e96`, which is how `-named` with `args=` is refused);
getnetworkinfo's `networks` lists Core's five networks and the proxy that
reaches each, where ours had one entry named after the chain (`6ef33f1f`); and
the RPC server binds `::1` itself, because glibc's `AI_ADDRCONFIG` refuses the
literal in any container whose only IPv6 address is the loopback -- the Round-5
note that "the socket library cannot listen on `::1`" is this (`74ce1d07`).

**Previous releases and the differential lane.** Core's own old binaries now
run inside the container: `scripts/get-previous-releases.sh` fetches and
SHA256-checks the archives on the host, and `scripts/previous-releases-volume.sh`
extracts them into a per-checkout volume mounted read-only at `/releases`
(`f789ecf1`, `5b831e92`; host security software deleted two extracted
`bitcoind`s within seconds, so they never exist outside the volume). With them,
a v0.20.1 `mempool.dat` without its unbroadcast set keeps what Core would
already have loaded (`cf3c8182`), and a pre-0.15 coins database is refused in
Core's words (`6757d280`). The GA11 harness lane that stayed open is closed:
`:core-binary-differential-tests` (`tests/rpc/core-binary-differential-tests.lisp`,
run by `scripts/interop-test.sh`) drives v28.2's `bitcoin-tx` and
`bitcoin-util` over Core's own vectors -- all 672 decodes agree, 13 creates and
4 signs are byte-identical, and a ground header passes our proof-of-work check
(`5b831e92`). Its first catch: a transaction's version is unsigned and
"coinbase" is decided per transaction; 278 of the 672 decodes disagreed
before `5ba2aca7`. The `-discover` port (below) and the two `-bind` tests'
container addresses (`f2ace578`) came from this batch too.

**Mempool and validation.** `mockscheduler` forwards a scheduler clock and no
longer freezes the node clock, which since the trickle moved onto the
mockable clock had left every Poisson deadline in a future that never came
(`0a74a3ff`); the unbroadcast re-announcement is armed at start as Core's is
(`d9c7161d`). A peer's first trickle pass sends (`a405ecf6`, the round-5
`p2p_leak_tx` regression), and a noban peer trickles on every pass
(`fe10ca3c`). The reorg re-filter judges BIP68 and finality below the CSV
height, finality against median-time-past (`4bc57e9d`). CheckBlock reads the
mutation flag before the coinbase rules (`b06a8fc6`), a tip block that fails
AcceptBlock is marked and its sender punished (`4bfe6271`), and the header
locator never starts at an invalid header (`ba32578d`). Package RBF, Rule 5,
TRUC sibling eviction and the conflicting-spend refusal carry Core's reasons
and sentences (`26bd3324`, `76e87987`, `a0aa2835`, `f321bda5`); maxfeerate is
a per-member PreChecks verdict (`f959ade7`); getrawmempool lists the pool in
mining order (`4e15f94f`); `OP_CHECKSIGADD` refuses a short stack before it
reads an operand (`75275cde`).

**Net.** The header tip is Core's `m_best_header`, the most-work header not
marked invalid (`9fdd65d8`). Headers ending at a block with at least our tip's
work fetch it directly from the announcer, which is what lets an equal-work
sibling be downloaded at all (`89324647`, net_processing.cpp:2844-2902). A
block that fails validation for good punishes the peer that sent it, through
Core's `mapBlockSource` (`7f9d39fa`), and a reorg announces every new block,
oldest first (`038232ba`). A getheaders answer records the peer's best header
sent (`e7fdcb2b`). The addr flush, the self-announcement and the addr token
bucket run on the mockable clock (`455942dd`, `733b43a3`); a getaddr reply is
queued for the addr flush (`128206ea`); an addr-fetch connection is dropped
after 300 s (`e11e1417`). A refused dial fails at once instead of waiting out
the 10 s timeout on the sync thread (`a3b51ce9`). Core's fixed-seed fallback
is ported (`dc6893d6`), `-capturemessages` writes Core's capture files
(`c11a8d8d`), and getnetworkinfo lists `localaddresses` (`4fbc5713`,
`e171a8b0`). `-discover` is on by default as in Core, adding routable bind and
interface addresses, and under it a peer's view of our address is advertised
(`fb1e04d4`, `f253e179`, from the compatibility batch).

**Tools and the external signer.** `src/tools/` carries `bitcoin-util` and
`bitcoin-tx`, run from the node executable by name and checked in-process
against Core's 107-vector `bitcoin-util-test.json` (`65deefba`), and
`bitcoin-wallet` with info, create, dump and createfromdump over our LevelDB
wallets (`f89ed2f7`; the database format is the documented divergence).
External signers are ported: `-signer`, `enumeratesigners`,
`walletdisplayaddress`, a keyless wallet whose descriptors come from the
device, and send, sendall and bumpfee signing through it (`a7c09ba4`); the
child runs through temporary files and its stderr is logged (`4bd7fe4b`).
getblocktemplate's `transactions` is `[]` for an empty mempool, which the
signet miner iterates (`a54a663b`).

**Init, storage, REST and ZMQ.** A disconnect that cannot run aborts the node
through `bl.log:fatal-error`, Core's AbortNode (`390765a6`); VerifyDB level 2
fails a block whose rev file is gone or does not read (`7016c308`,
`287d4917`); a full flush creates the current block file's rev file
(`ccb27a2c`); a disconnect moves the prune locks back (`24c67b2a`). `-reindex`
on a pruned node wipes and rebuilds from nothing, as Core's does
(`4b0e3cf4`). A startup wallet another process holds stops startup in Core's
words (`8320ff61`). Every `-rpcbind` is bound at its own port (`fc49e582`), a
bracketed IPv6 `-rpcallowip` is a subnet (`212bdf47`), a refused address gets
Core's bare 403 (`739e2b45`), and a `=onion` bind with no port takes `-port`
+ 1 (`801a7de7`, the round-5 `feature_port` regression). REST answers each
failure with Core's status and bytes (`c60737d6`, `e2be8281`, `2e872421`,
`acf39ab0`, `b03e990f`, `85db8503`, `7b74d735`, `2cf84441`). ZMQ: a removal
takes the next mempool sequence (`d418ee3d`), a block's conflicts leave in
block order (`42fe6610`), hashblock and rawblock announce the new tip once per
step (`bfa14981`), and a reorg signals its new blocks after the disconnected
transactions return (`1015f7be`). A snapshot base has a chain transaction
count and no nTx (`f147d9e2`); the anchors load logs Core's lines, 0 included
(`38023205`).

**P2P.** The node keeps one IBD context and the receive pump works in it
(`6921eb25`), which closes the second Round-3 live-node hazard; the net4
batch's side table for direct fetches then went, and the direct fetch files its
requests in the one in-flight table (`e4c68bdc`). Per connection, addconnection
and addnode onetry dial the transport the caller asked for (`3d6841e2`). An
unfinished handshake times out on the mockable clock, on every tick, with
Core's V2 and version lines (`19b2737e`); BIP324 errors and messages before
VERSION or VERACK are logged in Core's words (`e6462ee0`, `7da2b55a`).
ConsiderEviction runs after each message and on every tick, and only once
header sync has started (`02b11e8b`, `b6932306`). A `-whitebind` address is
listened on beside an `=onion` bind (`7cc8f3ba`, the round-5
`p2p_permissions` regression), every `=onion` bind is listened on and the
getaddr cache is per socket (`77e0cfdd`). An outbound peer is published when
its socket opens and addconnection returns then (`37407c11`); a feeler is
dropped once its handshake is done (`e1e700e0`). A requested transaction is
never charged to the tx rate limit (`dddbe06d`), a noban peer is spared the
bucket (`685dc0f4`, `0dab093c`), and a relay-permission peer lifts the
announcement cap (`252e5382`).

**Wallet and PSBT.** A PSBT is written in Core's field order
(`5fc266c7`) with a legacy-serialized `non_witness_utxo` (`a5b1c888`), and the
taproot-derivation, taproot-tree and MuSig2 records are validated as Core
reads them, so all twenty of `rpc_psbt.py`'s `invalid_with_msg` vectors carry
Core's sentence (`04ffaf49`). `analyzepsbt` is Core's AnalyzePSBT
(`5b77c3ec`); `utxoupdatepsbt` and `descriptorprocesspsbt` are ProcessPSBT,
mempool and descriptors included (`e22cac70`, `2019db8b`); `joinpsbts` clears
signatures and shuffles (`1511d6e1`); an input whose signatures do not use its
sighash type does not finalize (`e3984d38`). Non-multisig witness scripts and
tapscript leaves are signed and finalized through miniscript (`17684e87`,
`d4b9a78e`), every tapscript signature made reaches the PSBT (`c072db06`,
`8396a0b1`), and taproot key paths are signed tweaked by the merkle root or,
for `rawtr()`, untweaked (`67520106`, `90c0793a`, `902fde34`). A `musig()`
PSBT names its participants and their derivations (`c79de2b1`, `a00db955`).
send and sendall build their PSBT as FinishTransaction does, so an unsigned
input is no longer "final" (`443f332c`). bumpfee replaces a non-signaling
transaction, prices a given rate against the replacement's outputs, carries
the original's comment, and is not blocked by an abandoned descendant
(`f03abeb6`, `b31adbab`, `308cb422`, `dd875a75`).

### Round-6 sweep

Binary `bdfd8434` (the whole round; four staggered batches of the harness, the
flips and time-outs rerun serially with a 900-second cap), classification in
`docs/functional-sweep-2026-09-13/after-bdfd8434.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | 69 | 166 | 5 | 23 |
| `bc65804a` round 4 | 100 | 137 | 3 | 23 |
| `2a7074c4` round 5 | 136 | 102 | 2 | 23 |
| `bdfd8434` round 6 | **193** | **59** | **2** | **9** |

Fifty-one tests went from FAIL to PASS (`feature_abortnode`,
`feature_bip68_sequence`, `feature_cltv`, `feature_dersig`,
`feature_fee_estimation`, `feature_filelock`, `feature_index_prune`,
`feature_port`, `feature_remove_pruned_files_on_startup`, `feature_taproot`,
`interface_rest`, `mempool_limit`, `mempool_packages`, `mempool_persist`,
`mempool_reorg`, `mempool_truc`, `mempool_unbroadcast`,
`mining_template_verification`, `p2p_addr_relay`, `p2p_addr_selfannouncement`,
`p2p_addrfetch`, `p2p_addrv2_relay`, `p2p_getaddr_caching`, `p2p_handshake`,
`p2p_ibd_stalling`, `p2p_ibd_txrelay`, `p2p_invalid_block`, `p2p_leak_tx`,
`p2p_message_capture`, `p2p_outbound_eviction`, `p2p_permissions`,
`p2p_timeouts`, `p2p_v2_encrypted`, `p2p_v2_misbehaving`, `p2p_v2_transport`,
`rpc_bind`, `rpc_getdescriptoractivity`, `rpc_packages`, `rpc_psbt`,
`wallet_basic`, `wallet_bumpfee`, `wallet_fundrawtransaction`,
`wallet_groups`, `wallet_importdescriptors`, `wallet_labels`,
`wallet_miniscript`, `wallet_miniscript_decaying_multisig_descriptor_psbt`,
`wallet_multisig_descriptor_psbt`, `wallet_send`,
`wallet_signrawtransactionwithwallet`, `wallet_taproot`), all three round-5
regressions among them, and seven from SKIP to PASS (`interface_bitcoin_cli`,
`mempool_compatibility`, `rpc_signer`, `tool_signet_miner`, `tool_utils`,
`wallet_listreceivedby`, `wallet_signer`).

Seven former SKIPs now run and fail, each for a stated reason:

- `feature_bind_port_discover` (`:66`) and `feature_bind_port_externalip`
  fail on Core v28.2's own `bitcoind` at the pin too
  (`BL_CONFORMANCE_REFERENCE=v28.2`): `test_node.py` adds `-bind` to every node
  without one, so Core never calls Discover, and nodes bound to 1.1.1.1 are
  unreachable for `setup_network` (`fb1e04d4`). Broken upstream.
- `feature_coinstatsindex_compatibility` (`:34`) and
  `feature_unsupported_utxo_db` (`:56`) need Core's `blocks/index` LevelDB
  block index, which this node does not read.
- `tool_wallet` (`:46`), `wallet_backwards_compatibility` (`:278`) and
  `wallet_migration` (`:139`) assert on SQLite or BDB wallet files, out of
  scope per [wallet-plan.md](wallet-plan.md).

Nine SKIPs remain: the five `interface_usdt_*` tests need USDT tracepoints,
bcc and root BPF, which the container policy forbids; `interface_ipc` and
`interface_ipc_mining` need Cap'n Proto multiprocess; `tool_bench_sanity_check`
and `tool_bitcoin_chainstate` need binaries only Core builds.

One test left PASS: `rpc_dumptxoutset` `:84`, where the node exits 1 on the
stop after the test's last step. `feature_pruning` went from a time-out to a
failure at `:223` (disk usage above the 550 MiB target after 220 large
blocks), and `feature_block` from a failure at its `send_blocks` helper
(`:1450`) to a time-out at 900 seconds; `feature_proxy` still times out. The
first two went to a follow-up batch the same day. `rpc_dumptxoutset` was
`390765a6`'s doing: the FatalError port sat inside the reorg helper every
caller shares, so a failed `invalidateblock` disconnect (the test removes a
rev file) asked the node to shut down with exit code 1, where Core's
InvalidateBlock only returns false (validation.cpp:3614-3622); `94ce5c97`
makes the abort the caller's choice. `feature_pruning` was older: since the
flat block files, a block stored a second time (a fork or out-of-order block
connect-block stores again) was written to the blk file again and never
counted, 173 MiB of duplicates on the test's node 2; `d26627e8` returns early
for a block already on disk, as AcceptBlock does (validation.cpp:4350), and
`5698a802` makes invalidateblock's reactivation skip a candidate chain with
missing data (FindMostWorkChain). The test now reaches `:263`, where a pruned
node must re-download the blocks of the chain it switches to; ours refuses
the reorg below its pruned height, which Core never does. That is the next
item. Eleven failure points moved later
(`p2p_segwit` 200 → 826, `feature_rbf` 288 → 507, `rpc_rawtransaction` 81 →
304, `rpc_net` 255 → 343, `feature_config_args` 320 → 388,
`feature_assumeutxo` 585 → 676, ...), five earlier; those five were not
checked against their step logs here, and `interface_zmq`'s new `:57` is the
subscriber's receive helper, so only the step log can compare it.

Deployed: both live nodes to `bdfd8434` -- testnet4 at 04:59 UTC with a
15-minute soak, then mainnet at 05:17 UTC; both clean. Under `-discover`,
testnet4's getnetworkinfo `localaddresses` now lists its onion service.

### Decisions recorded in Round 6

- **`-rpcthreads` and `-rpcworkqueue` default to Core's 16 and 64** --
  `7b468384`, [src/rpc/server.lisp](../src/rpc/server.lisp) (the two
  default constants). The unbounded pool is gone.
- **`-discover` is on by default, as in Core**, soft-set off by a real
  `-proxy`, `-listen=0` or `-externalip`; only fully routable addresses are
  advertised, so a container or LAN address never is. The live nodes now
  advertise their routable addresses. `fb1e04d4`, the manual's net section.
- **NET_ADMIN is granted by `scripts/conformance.sh` only to a run that
  includes one of the two `-bind` tests**, for `/32` aliases in the
  container's own network namespace; never `--privileged`, host networking or
  a published port (`f2ace578`, `scripts/conformance.sh`).
- **The per-peer tx rate-limit bucket stays**, though Core has no
  per-message-type disconnect: a noban peer and a transaction we requested are
  exempt (`685dc0f4`, `dddbe06d`, `0dab093c`). Whether it should exist at 10/s
  is left open; a mainnet peer can exceed it in a fee spike.
- **The per-pass getheaders to the sync peer (ours, not Core's) is skipped
  when that peer is caught up** (`89820698`); a peer we know nothing about is
  still asked.
- **Mempool finality below the CSV height uses median-time-past**, as Core's
  CheckFinalTxAtTip always does; the pre-BIP113 wall-clock rule is gone from
  both acceptance and the reorg re-filter (`4bc57e9d`).
- **The `addcon`, `scheduler`, `msghand` and index `thread start` lines are
  not logged**, because those threads do not exist here; only threads that
  exist are traced (`TRACE-THREAD`, [src/logging.lisp](../src/logging.lisp)).
  `feature_init` `:93` and `feature_config_args` `:388` wait for them and stay
  red.
- **`peers.dat` stays our bucket format** (`feature_addrman` `:65`,
  `feature_asmap` `:89` stay red), and **`anchors.dat` stays the
  network-typed format** of `SAVE-ANCHORS`
  ([src/node/peers.lisp](../src/node/peers.lisp)).
- **The equal-work first-seen tie-break needs the per-block receive order**,
  which the index does not keep; `feature_chain_tiebreaks` now fetches the
  sibling (`89324647`) and stops at `:94`.
- **`-reindex` without `-prune` stays additive**; a pruned `-reindex` now wipes
  as Core's does (`4b0e3cf4`). See "Known divergence" above.
- **The external signer is always compiled in** (`a7c09ba4`, the manual's
  wallet section): Core's `ENABLE_EXTERNAL_SIGNER` is advertised
  unconditionally. [wallet-plan.md](wallet-plan.md) §1 still lists external
  signers as out of scope and needs updating.
- **MuSig2 signing is out of scope**: a `musig()` aggregate has no private key
  of its own here, so it yields none; participants and derivations are
  written, nonces and partial signatures are not (`f6bedebb`).
- **`wallet.dat` as a file, and absolute wallet paths, stay documented
  divergences** ("Wallet files by name" above; Round 5's decision on absolute
  paths).
- **`tool_wallet`'s SQLite-file assertions stay red**: our wallet database is
  a LevelDB directory, so `Format:` reads `leveldb` and the lock sentence
  names it; a copy of the test with only those assertions adapted passes end
  to end (`f89ed2f7`, the manual's tools section).

## Round 7

Six worktree batches merged onto `main` on 2026-09-23, from `6e76cfb8`
through `632abe24`: 73 commits, two of them `tests:` commits, in merge order
p2p6 (6), init4 (12), wallet8 (15), blockdl (8), net7 (17) and prune (15).
One is a seam where two batches met on `main`: wallet8's UTXO-set refusal and
net7's `-privatebroadcast` gate took sendrawtransaction's handler to 104
lines, one helper over the ratchet (`7d59179e`); and the prune batch's last
commit closes a window its rebase onto p2p6's pump opened (`632abe24`, below).
Each batch ran its own green battery on a fresh FASL volume -- three of the
round's commits change a defstruct or a macro (`0cb79f36`, `021f8822`, `0eb2b5e5`) --
and the merged battery ran before every push: 41,598 → 41,938 passing
checks, plus the four skips of the Core-binary lane (the prune worktree's
log at `632abe24`). The `::` ceiling fell from 3,780 to 3,761, paid by init4's
anchors.dat tests and the thread entry points it exported. The behaviour
changes that mattered most, by batch:

**p2p6.** The sync thread's idle wait is Core's message handler's: one
poll(2) over every peer the pump reads, ended at once by buffered input, with
the 200 ms tick as its timeout instead of a fixed sleep before every pump; a
request/reply round trip no longer costs a tick, and `p2p_tx_download`'s
twenty-ping announce loop fell from 3.86 s to 1.09 s (`4484d829`,
net.cpp:3157, :2246-2253). The per-peer tx token bucket that disconnected the
sender of the 51st unsolicited transaction is gone -- Core's TX handler has
no count limit, and an orphan flood is bounded by the orphanage's DoS scores
(`dc7d8170`, the reversal of a Round-6 decision, below). `-test=addrman` keys
the address book with Core's `uint256{1}`, and the bucket and position
hashes are Core's bytes (the address key without a network byte,
CompactSize-prefixed groups), so a collision ground by Core reproduces here;
a missing `peers.dat` is created and logged in Core's words, and
addpeeraddress answers with Core's codes (`a25ab0ce`, `2bc17ef0`).
getpeerinfo reports `addrlocal` for every peer with a valid address, and an
inbound peer's routable view of us raises that local address's score, Core's
SeenLocal (`b3083257`). The Tor control dial goes through `%socket-connect`,
so a refused control port fails at once instead of holding the thread for
usocket's 10 s (`71e783ce`). `p2p_opportunistic_1p1c` and `p2p_tx_download`
PASS in the batch's oracle runs.

**init4.** `peers.dat` and `anchors.dat` are Bitcoin Core's files: SerializeDB
around AddrManImpl's format 4 with each entry's source address, and
Unserialize's range checks, re-bucketing and closing CheckAddrman; a file
from a future format is backed up and replaced, a corrupt one refuses
startup with Core's sentence (`8af8137d`). The former ADRM/CRC32 format is
read once, rewritten in Core's format and the migration logged, and the
writer never produces a file its own reader would refuse (`2d9184f4`) --
the path the live nodes take on their first start with this round. The
old ANC1/ANC2 anchors are not read; anchors are block-relay-only
connections, dialed first and last-first. `-checkaddrman=<n>` runs the port
of CheckAddrman with Core's timer lines. The scheduler, `addcon` and index
catch-ups are real threads, and the sync thread is logged as `msghand` (and
`opencon` only when Core would start ThreadOpenConnections) (`9b2180db`); a
stop during start-up is torn down after start-up returns, where it had freed
the filter index's LevelDB under the index thread (`d18f2ff9`). A negated
`-wallet` on the command line hides settings.json's list, as GetSettingsList
does (`a38ae63d`). A SOCKS5 reply already in the stream's buffer is read
instead of waited for, which had failed every dial through a proxy that
keeps the connection open (`383b3c90`). `-asmap` looks an IPv4 address up as
`::ffff:a.b.c.d` and groups by AS as Core does -- before, every IPv4 address
came back unmapped (`ecfe7591`) -- its errors quote the path and start-up
logs Core's ASMap health check (`d7cdc6e8`). `feature_addrman` and
`feature_anchors` PASS in the batch's oracle runs.

**wallet8.** generateblock reports a ranged or keyless descriptor's own
error, falling back to an address only when the descriptor does not parse
(`2c9c7224`). The reject-keyword check now reads every transaction-verdict
file across line breaks, with positive controls; it found six package-wide
reasons without a row and two keywords no Core rejection spells, both
removed (`6d03fa87`). The wallet's PSBT updaters store a `non_witness_utxo`
without its witness (`e703605a`), and [wallet-plan.md](wallet-plan.md) §1
now says external signers are ported (`81647cb4`, the Round-6 note).
sendrawtransaction refuses a transaction whose outputs are already in the
UTXO set, Core's -27 (`69da8e9f`, `44366a1d`); waitfornewblock waits against
the `current_tip` it is given (`c7455f7b`); a snapshot chainstate's prune
height is Core's GetPruneHeight walk (`8e83cfb6`); getblock with details
fails when the undo the index names cannot be read (`f5450d73`); an outputs
array member must be a one-key object (`69f67f6d`). A refused wallet load
leaves the stored best block where it was, so the next load is refused
again instead of skipping the blocks (`5384f8e2`); the refusal and the
rescan errors name pruning only when blocks have been pruned, the
assumeutxo background sync when that is the cause, and the timestamps Core
names (`ae6c1418`, `2d58506f`, `e2948b81`). A winning block whose fork
ancestors lack bodies is stored, as AcceptBlock stores it (`8b08d3ad`).
`rpc_generate` PASSES in the batch's oracle run.

**blockdl.** An equal-work tie goes to the chain whose data was complete
first: Core's nSequenceId, kept in memory only, with preciousblock's
negative ids and ActivateBestChain after a refusal for missing bodies
(`0cb79f36`) -- the per-block receive order the Round-6 decision said the
index lacked. The witness commitment is checked before the block weight,
and ContextualCheckBlock before ConnectBlock, so a stuffed coinbase witness
is `bad-witness-nonce-size` and the size and weight limits carry Core's
`bad-blk-length` and `bad-blk-weight` (`6d780f9f`). A CheckBlock failure
marks no block invalid, as ProcessNewBlock skips AcceptBlock for it
(`b9a26904`); a fork verdict that carries a debug message is no longer
mistaken for a list of blocks to download, the cause of Round 6's
`feature_block` time-out (`b74633da`). A block message whose header fails its
own proof of work, or a contextual header rule, costs the sender the
connection, `time-too-new` excepted (`f7429eaf`, `b33adcc9`). BIP 30 is
enforced at every height where the network's `BIP34Hash` is null -- testnet4,
signet and regtest -- and at the BIP 34 block itself on mainnet
(`021f8822`). That is a CONSENSUS change on testnet4: the live node would
connect a block Core rejects as `bad-txns-BIP30`; the fix reaches it on its
next deploy. `feature_chain_tiebreaks` PASSES in the batch's oracle
run.

**net7.** getrawaddrman is Core's bucket/position table, and every IPv6
address prints compressed as IPv6ToString does (`2696a076`, `445994c6`).
`-privatebroadcast` is validated in Core's three cases and words, and since
the mechanism is not ported, sendrawtransaction refuses under it
(`37b29646`). The inv, addr/addrv2, headers and serve token buckets that
disconnected the sender of the first message past them are removed: Core
bounds each message, never the count of a kind; the addr bucket that DROPS
addresses and the send-buffer pause stay (`0eb2b5e5`). An over-limit vector
is Core's `Misbehaving` line, and an over-long locator only disconnects
(`2e903e27`). Received bytes are counted per chunk as they arrive
(`db115194`); a version after the handshake is logged as redundant
(`9e50379f`); a malformed v1 header is reported in V1Transport's words and
its type field judged whole (`30b3e58a`). A noban peer's headers skip the
low-work gate, a low-work chain is ignored once in Core's words, and header
progress is reported while in IBD by Core's definition (`f2bff6bd`,
`9af280ba`). Config: `conf=` in a configuration file is refused and
`reindex=` warned about, as IsConfSupported does (`d10903f0`, `f607463f`);
an ignored bitcoin.conf names its directory without a trailing separator
(`737f0566`); the `-acceptnonstdtxn` refusal names the chain `main`
(`a25e2027`). Start-up says `Loading wallet…` before each wallet
(`4576225a`), after init4's `Verifying wallet(s)…` (`8cd020c4`). `rpc_net`
and `feature_asmap` PASS in the batch's oracle runs.

**prune.** A reorg below the pruned height waits for the bodies and
re-downloads them instead of refusing ("Node must re-sync."): the pruned
height is a height, not a chain, and FindMostWorkChain asks each block only
for its data (`e675b547`). Automatic pruning keeps Core's buffer -- one blk
and one rev chunk, 17 MiB, plus 1 MB per block still to come in IBD -- under
the target, and no longer stops at the pruned-height cursor, which after a
reorg onto a lower tip had stopped pruning for good (`9a63175b`); a pruned
node prunes at startup after the wallets' rescans (`1178f6a9`). The
assumeutxo background chainstate connects target-path bodies already on
disk and, from a divergent chain, fetches from the last common ancestor
and reorgs onto its target path (`33bd67a4`, `9d330f68`). pruneblockchain,
`-prune`, scanblocks' false-positive check and a pruned genesis answer in
Core's words and order (`dfc019f8`, `c4a3ff36`, `684aacbe`, `e6e626cf`), and
`-fastprune` lowers regtest's prune-after height to 100 (`d9a1310d`), without
which the new "too short" check had turned `feature_index_prune` and
`rpc_getblockfrompeer` red inside the batch. A serviced shutdown request
interrupts the sync loops at once, Core's Interrupt: with the pump waking
on input, the 700 ms until the watchdog's poll let `feature_assumeutxo`'s
`-stopatheight` restart connect 40 blocks past the stop and promote the
background chainstate, moving its failure point from `:799` back to `:695`
(`632abe24`). `scripts/dev.sh docs-check` is green again: the manual's own
package, made after the system loads, never received the `bl.*` nicknames
(`61f48c4d`). `feature_pruning` PASSES in the batch's oracle run.

### Round-7 sweep

Binary `632abe24` (the whole round), classification in
`docs/functional-sweep-2026-09-13/after-632abe24.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | 69 | 166 | 5 | 23 |
| `bc65804a` round 4 | 100 | 137 | 3 | 23 |
| `2a7074c4` round 5 | 136 | 102 | 2 | 23 |
| `bdfd8434` round 6 | 193 | 59 | 2 | 9 |
| `632abe24` round 7 | **204** | **48** | **2** | 9 |

Binary `632abe24` (four staggered batches, the flips and time-outs rerun
serially with a 900 s cap), classification in
`docs/functional-sweep-2026-09-13/after-632abe24.tsv`. Twelve tests went to
PASS (`feature_addrman`, `feature_asmap`, `feature_chain_tiebreaks`,
`feature_pruning`, `mempool_package_rbf`, `p2p_headers_sync_with_minchainwork`,
`p2p_opportunistic_1p1c`, `p2p_sendheaders`, `p2p_tx_download`,
`rpc_dumptxoutset`, `rpc_generate`, `rpc_net`; `feature_anchors` had passed
in a batch's oracle run and passed here too, so it is not a flip). One left
it: `p2p_feefilter` `:72`, a forcerelay peer receiving a feefilter. The gate
had never existed (Core's MaybeSendFeefilter returns for ForceRelay,
net_processing.cpp:5632); the faster pump of `4484d829` sent the message
before the test's poll instead of after, which is how an absence assertion
had passed for a year. `57c75404` adds the gate, on the binary after this
sweep. `interface_zmq` went from a failure at `:57` to a time-out at 900 s,
and `feature_block` from a time-out to a failure at its `send_blocks` helper
(`:1450`), the shape it had in Round 6; `feature_proxy` still times out.

Deployed: both live nodes to `632abe24` (testnet4, a 15-minute soak, then
mainnet). Each migrated its peers.dat to Core's format on the first start
(testnet4 kept 35,153 of 49,219 entries, mainnet 42,466 of 66,513: entries
Core's CheckAddrman would refuse are dropped), and testnet4 now enforces
BIP 30 at every height.

### Decisions recorded in Round 7

- **No message kind disconnects its sender for how many it sends**, as in
  Core: the per-peer tx bucket (`dc7d8170`) and the inv, addr/addrv2,
  headers and serve buckets (`0eb2b5e5`) are removed, reversing Round 6's
  "the per-peer tx rate-limit bucket stays". The per-message limits, the
  addr token bucket that drops addresses and the send-buffer pause remain.
  The rationale lives in the two commit bodies, and the manual's p2p
  invariants say the same since `88d96f06`.
- ~~**`-privatebroadcast` refuses sendrawtransaction rather than queueing**~~
  -- reversed in Round 8: Core's private broadcast is ported
  (networking/private-broadcast.lisp, node/private-broadcast.lisp) and
  sendrawtransaction queues as Core does; p2p_private_broadcast.py passes.
- **`Checking all blk files are present` is not logged**: the block index
  keeps no per-entry data flag or file number to check against, so the line
  would describe a check that did not run; `feature_init` `:93` stays red
  (`9b2180db`'s body).
- **Start-up joins each index thread before it goes on**: the connect-time
  index hooks assume an index at the tip, where Core's BaseIndex ignores
  notifications until caught up; the thread is real, the concurrency is not
  (`START-INDEX-BACKGROUND-SYNC`, [src/node/indexes.lisp](../src/node/indexes.lisp)).
- **The scheduler thread runs only two tasks**, the disk-space check and
  the log rate limiter's window; the peers.dat dump, fee-estimate flush,
  stale-tip check and wallet resend stay on the sync thread, which owns
  their state without a lock, and the 24-hour ASMap health-check repeat is
  not ported (the header of [src/node/threads.lisp](../src/node/threads.lisp),
  `d7cdc6e8`).
- **A corrupt Core-format `peers.dat` refuses startup**, with Core's
  sentence; only the former bitcoin-lisp format is still backed up and
  replaced (`%LOAD-CORE-PEERS-DAT` and `%LOAD-LEGACY-PEERS-DAT`,
  [src/networking/addrdb.lisp](../src/networking/addrdb.lisp)). This closes
  Round 6's "`peers.dat` stays our bucket format".
- **`-reindex` without `-prune` stays additive**: all three wipe-dependent
  functional tests now pass their reindex assertions without the wipe, and
  the memo's measured-connect-rate condition still does not hold
  ([reindex-decision-2026-09-18.md](reindex-decision-2026-09-18.md),
  "Re-checked 2026-09-23"; `ce2a6424`).
- **getrawaddrman's source for a self-added entry is the entry itself**, as
  Core's addpeeraddress records `Add({address}, address)`; a gossiped entry
  names its sender (`%ADDRMAN-ENTRY-JSON`, [src/rpc/net.lisp](../src/rpc/net.lisp);
  `2696a076`, `445994c6`).

### Left open after Round 7

From the batch reports and commit bodies; the round-7 sweep will confirm
each failure point:

- `feature_assumeutxo` `:799` (test_sync_from_assumeutxo_node, `:335`): the
  IBD node downloads from a NETWORK_LIMITED snapshot node during its own IBD,
  which Core's SendMessages never does (net_processing.cpp:6165; `9d330f68`,
  `632abe24`).
- `rpc_blockchain` `:106`: `verifychain(4, 0)` -- our level 4 runs
  ContextualCheckBlock where Core's VerifyDB runs only ConnectBlock.
- `wallet_assumeutxo` `:98`: after background sync, pruneblockchain must
  return GetPruneHeight's walk (298), which needs the snapshot chain's blocks
  in Core's separate block files.
- `rpc_rawtransaction` `:246`: a pruned peer is asked for blocks below the
  NODE_NETWORK_LIMITED window.
- `p2p_invalid_messages` `:194`: the end-of-data condition text of
  `bl.bytes` is not Core's `DataStream::read(): end of data`.
- `p2p_segwit` `:1201`: the same text, expected in the debug log for
  test_witness_input_length's block (`6d780f9f`).
- `feature_block` `:947`: b64a, a block with a non-canonical CompactSize,
  must be refused as `non-canonical ReadCompactSize()`.
- `feature_config_args` `:176`: an unrecognised config-file section is a
  warning on stderr in Core; ours writes it to the log only.
- `p2p_headers_sync_with_minchainwork` `:148`: the 2000+-block reorg times
  out.
- `interface_zmq` `:563`: with several `-zmqpubhashblock` addresses only the
  last one publishes.
- `feature_init` `:93` (the blk-files line, decided above) and `:202`, where
  the corruption rounds glob `blocks/index/*.ldb`, Core's LevelDB block
  index.
- The three large items still awaiting a decision: Core's `blocks/index`
  LevelDB format, SQLite wallet files, and BerkeleyRO with migratewallet.

## Round 8

Eight worktree batches merged onto `main` on 2026-09-24, from `053f81fd`
through `cf46af32`: 99 commits including the merges, in merge order texts
(18), wallet (7), blockindex (4), netops (11), blockdl (19, with its own merge
of `main`), cmpct (9), tail (13, with its merge of `main`) and regress (5, with
two merges of `main`). The round was the user's answer to a ranking of what
was left after Round 7: the three format decisions, the block-download
divergences that touch the live mainnet node, VerifyDB and the error texts,
the wallet's P7 remainder, and the two operator-visible network defects --
with one rule for every batch, "Core's way unless a documented reason says
otherwise". Every batch ran its own green battery on a fresh FASL volume, as
five of the round's commits change a macro or a defstruct (`0a5b8f14`,
`923773a4`, `39cdabb4`, `00ca4420`, `d95be76e`), and the merged battery ran
before every push: 41,942 → 42,425 passing checks, plus the four skips of the
Core-binary lane (`build/cold-main-55..58` and the branches' own logs). The
`::` ceiling fell from 3,761 to 3,682, paid by the retired headerindex.dat
suites and by the cmpct and tail batches' exports of names that have src
callers; one seam (`f6cece2a`) reset it to 3,701 where three parallel
batches met on `main`, before it fell again. The behaviour changes that
mattered most, by batch:

**texts.** VerifyDB's level 4 is Core's ConnectBlock alone, without
ContextualCheckBlock, and every level logs Core's `Verifying last N blocks at
level L` and `Verification progress` lines (`9be290a1`, validation.cpp:4760)
-- `rpc_blockchain` had failed because a chain mined with segwit active from
genesis was re-checked under `-testactivationheight=segwit@6`. Every
byte-reader primitive signals `DataStream::read(): end of data`, the
CompactSize readers `non-canonical ReadCompactSize()` and `ReadCompactSize():
size too large`, and a caught handler error is logged as Core's
`ProcessMessages(...): Exception '...' caught` (`0a5b8f14`, the macro change).
An unrecognised config-file section is Core's InitWarning on stderr and in the
log, found per file and line with exact-case headers (`93864fc2`,
`eb69f6fc`), and the InitWarnings Core gives for a trimmed `-maxconnections`,
a bad listen port and an oversized `-dbcache` now exist (`bf9e4a36`). Headers
that fail CheckHeadersPoW are Misbehaving (`d0f630ec`); the orphan-resolution
log lines and `bad-cb-height` are Core's (`b4f5bb24`, `afdf4984`,
`6614ed77`). The default datadir is `$HOME/.bitcoin-lisp`, expanded as
GetDefaultDataDir expands its own -- before, nothing expanded the `~`, so a
node started without `-datadir` could not take its lock (`6f2e5e00`). The
warm-image ASDF load now fails on a deferred undefined-variable warning, the
cold lane's check on the warm path, with `scripts/check-warm-load-guard.sh`
as its positive control (`f00dd91a`) -- the guard the repeated
scripted-edit lesson asked for. `rpc_blockchain`, `p2p_invalid_messages` and
`p2p_invalid_tx` PASS in the batch's oracle runs.

**wallet.** G7-42's four RPCs (gethdkeys, setwalletflag,
createwalletdescriptor, migratewallet) turned out to have landed in earlier
rounds: every one of Core's 56 wallet RPCs is registered, and
[wallet-plan.md](wallet-plan.md) P7 now says so (`317ceb8a`). A wallet whose
stored best block is gone is still this chain's, as AttachChain decides by
the genesis alone (`47647c85`) -- before, deleting `blocks/` and `chainstate/`
made the node refuse its own wallet. The wallet directory is Core's
GetWalletDir (`-walletdir`, else `wallets/` if it exists, else the network
datadir), names are relative paths that may nest, and every wallet directory
carries a `BITCOIN_LISP_WALLET` id file with the network's magic, checked at
the format probe so another network's wallet is Core's -18 "Data is not in
recognized format" and is not listed (`776c8f96`); existing wallets are
stamped on the first start. `-walletdir` is verified as VerifyWallets does
and a duplicate `-wallet` is warned about (`35ebbca9`). validateaddress and
getaddressinfo share one DescribeAddress, so a taproot output is a script and
an anchor carries no witness fields (`bac34008`); a load-time rescan says
`Rescanning…` first and logs how far back it goes (`484eadac`, `42949259`).
No unmodified wallet test moved to PASS: the batch ran copies of seven of
them with only the wallet.dat step replaced (backupwallet/restorewallet, or
`format == 'leveldb'`), and all seven pass end to end, so the file format
is the only thing behind them (the classification table under "Decisions").

**blockindex.** The block index persists in Core's `blocks/index` LevelDB,
byte for byte: `b`+hash records in CDiskBlockIndex's layout, `f`+nFile
CBlockFileInfo, `l`, `R`, `F`+flag and the obfuscation-key record
(`923773a4`, txdb.cpp, chain.h). A regtest `blocks/index` written by Core
v28.2 loads here and re-encodes to the same bytes, and Core v28.2 started on
our datadir reads its chain from our index. `headerindex.dat` and its delta
log are converted in place on the first start, in 50k batches, and renamed
`*.migrated` once the count reads back (900,001 entries in 7.8 s). Start-up
reports Core's `Error opening block database`, `Error loading block
database` and the witness-data `-reindex` sentence. Under `-reindex`,
active-chain blocks past segwit activation that lack BLOCK_OPT_WITNESS are
reset to header-only and their bodies re-accepted, so the tip falls back as
Core's reindex makes it fall, without the wipe the reindex memo rules out; an
unpruned start over pruned files is refused in Core's words and `-reindex`
clears the `prunedblockfiles` flag; `-dbcrashratio` and `-dbbatchsize` exist,
coins flushes over the batch size are partial batches with Core's
in-progress marker, and start-up replays an interrupted flush (`a90a16ae`,
ReplayBlocks). A stored body is judged once, at accept, and a winning block
is stored before the reorg toward it, so a crash mid-reorg no longer loses it
(`7db93c5a`). `feature_presegwit_node_upgrade`, `feature_unsupported_utxo_db`
and `feature_dbcrash` PASS in the batch's oracle runs.

**netops.** One ZMQ publisher per `-zmqpub<topic>` address with its own
sequence counter, and IPv6 addresses bind (`9c40430e`) -- `interface_zmq`
had timed out because only the last address published and the test's
sync-up loop is unbounded. Proxies are Core's per-network table with
`=ipv4|ipv6|onion|cjdns` suffixes, CheckHostPortOptions and the exact error
sentences; a `unix:` proxy dials its socket file; and an IPv6-literal proxy
is reached at all (`891ea152`): `%socket-connect` handed every host to
usocket's resolver, which refuses `::1` when loopback is the only IPv6
address, so `-proxy=[::1]:9050` never left the machine -- the dial path the
live nodes' Tor outbound uses. The DNS seed thread and the `-seednode` queue
follow ThreadDNSAddressSeed's timing and lines (`52d65373`); the ping timer
runs on the mockable clock and a pong names Core's problems (`dbe2542a`,
`e209ddf3`); a handshake cut short by a shutdown request keeps its peer for
the anchor dump (`8221caea`). BIP 37 is served as Core serves it: CBloomFilter
with the BLOOM_UPDATE_* flags, filterload/filteradd/filterclear with their
limits and Misbehaving, `-peerbloomfilters` and NODE_BLOOM, the filtered
`mempool` answer and MSG_FILTERED_BLOCK merkleblocks, checked against
bloom_tests.cpp's vectors (`39cdabb4`). I2P goes through a SAM 3.1 bridge as
i2p.cpp does it -- persistent and transient sessions, `i2p_private_key`, the
`i2paccept` thread, `-i2psam` making i2p reachable (`00ca4420`;
[tor-i2p-cjdns-plan.md](tor-i2p-cjdns-plan.md) P4). Every call that resolves
a host now sits in a literal-aware function, checked by a structural test
with a positive control (`ffce1d89`), the mechanical guard for a trap that
had hit twice. Ten tests PASS in the batch's oracle runs: `interface_zmq`,
`feature_proxy`, `feature_anchors`, `p2p_dns_seeds`, `p2p_seednode`,
`p2p_ping`, `p2p_filter`, `feature_maxuploadtarget`, `p2p_i2p_sessions`,
`p2p_i2p_ports`.

**blockdl.** An IBD node asks no NODE_NETWORK_LIMITED peer for blocks, and
its initial getheaders is gated the same way (`a37cfecf`,
net_processing.cpp:6165, :5779); a noban peer is served blocks below the
limited window (`25e15a8c`). A low-work headers sync that ends on a full
message asks for the rest (`51e90541`) -- `p2p_headers_sync_with_minchainwork`
had stopped at height 6000 of 6159, not slowness. The download loop fetches
an equal-work fork (`b90ffe03`), an unsolicited block meets AcceptBlock's
gates -- min_pow_checked, "requested" meaning in flight, fHasMoreOrSameWork
(`445344b6`) -- and bodies stored above the tip and the reorg candidates
outlive the sync cycle (`00ee80b9`). A block that fails only ConnectBlock
keeps its body, as AcceptBlock writes it first (`f5271ea6`); a header on an
invalid parent is `bad-prevblk` and its sender punished (`670693f0`). The
deep-reorg retry chooses its target and activates it under one node lock
(`f67c9a9c`), and generate steps aside between blocks so the sync thread
announces as it goes (`8a76e713`) -- `rpc_rawtransaction`'s stall
reproduced on Core v28.2 with a replica and came from the RPC thread
starving the announcer. Compact blocks: NewPoWValidBlock's push to
high-bandwidth peers, the direct fetch of one block as a cmpctblock, a
compact header no better than the tip indexed but not reconstructed, and no
segwit-era getdata to a peer without NODE_WITNESS (`54de6990`, `bcf8ba4e`,
`59fab7b1`, `977ac639`). `feature_assumeutxo`, `rpc_rawtransaction`,
`p2p_unrequested_blocks`, `feature_block` (once the texts batch's log line
landed), `p2p_compactblocks_blocksonly` and
`p2p_headers_sync_with_minchainwork` PASS in the batch's oracle runs.

**cmpct.** The block in-flight table is Core's mapBlocksInFlight: up to
three peers per block, the last slot for an outbound peer, and every reader
-- timeouts, stalling, the download walk, getpeerinfo's `inflight`, the
compact-block path -- moved to the multimap (`e662c95f`). A relayed block's
consensus verdict is cached on the block index (`8321b797`); a compact-block
reconstruction is filled once and a second blocktxn is punished
(`0eac01e7`); an undecodable tx message reaches ProcessMessages' exception
line, `Unknown transaction optional data` included (`f2a0ee5b`). Chain
activation is serialized behind Core's m_chainstate_mutex (`d95be76e`,
validation.cpp:3354-3368): in one of five `p2p_compactblocks` runs
generatetoaddress was inside connect-block, the block indexed and its coins
applied but the tip not yet moved, when the sync thread picked the same
block as a heavier tip and connected it again -- `bad-txns-BIP30`, a
deterministic verdict, so a valid block was marked invalid and the tip
rolled back. `bl.val:*chainstate-mutex*` is held by every activation entry
point, `install-cs-main-check` refuses an activation without the node lock
once the threads start, and a deterministic test parks one thread at that
exact window. `p2p_compactblocks` (5 of 5 serial runs) and `p2p_segwit` PASS.

**tail.** Assumevalid skips scripts only for a buried ancestor on the best
header chain, Core's three clauses that read the best header (`3817f064`,
validation.cpp:2357-2362), and the ancestry walk is no longer quadratic in
chain height; `-reindex-chainstate` reconnects each block through
ConnectBlock's checks (`9ecd06c7`). `-incrementalrelayfee` raises an unset
`-minrelaytxfee` (`d7ad89f0`); preciousblock of an invalidated block succeeds
without reconnecting it (`61f48cf2`); an orphan's parents are Core's unique
parents (`79855f0e`); no sendtxrcncl on an addr-fetch connection and Core's
outcome lines (`6bb28f15`, `eee6b5d9`); BIP 157 requests are prepared and
answered as Core does, stale branches included (`c0c090f9`). Core's private
broadcast is ported -- the queue, the connection count, the opening thread,
the per-connection exchange, received-back detection, the 2-3 minute
rebroadcast, `getprivatebroadcastinfo` and `abortprivatebroadcast` -- and
sendrawtransaction under `-privatebroadcast` queues instead of refusing
(`a2e43e11`, the reversal of Round 7's decision; v2 when the address
advertises it, `8e19920e`). reconsiderblock keeps the validity level a block
had, as ResetBlockFailureFlags clears only the failure bits (`db9f0e7a`); a
feeler is done once our verack is out (`8cd5c78e`, 30 s → 0.2 s in
`p2p_sendtxrcncl`). `feature_assumevalid`, `feature_rbf`,
`p2p_orphan_handling`, `p2p_sendtxrcncl`, `p2p_blockfilters` and
`p2p_private_broadcast` PASS in the batch's oracle runs.

**regress.** The interim sweep on `53d98310` found three tests red that
Round 7 had green. `feature_loadblock` was a race the round only made lose:
getmempoolinfo's `loaded` was a constant, and mempool.dat was replayed before
the `-loadblock` import; it is now Core's initload order -- import, then
replay, then the latch the framework waits for (`6d959558`). `feature_pruning`
was the blockdl batch's compact-block push meeting a slow acceptor: profiled,
47% of a 950 KB block's acceptance was an untyped sigop scan and 23% a
one-byte-at-a-time block writer; acceptance went from 45 ms to 7 ms with
identical bytes (`c0e53f90`). `feature_init` was not a regression but the
same failure two frames apart; on the way the coins database reads its
obfuscation key at open as CDBWrapper does (`bb88da61`), a new chainstate
names genesis as its best block as ConnectBlock does (`b193a632`), and
start-up opens `chainstate/` once (`7594955d`). Its last two phases, merged
after the sweep, take `feature_init` to the end: every index reads its
best-block record checksummed at open, as BaseIndex::Init does (`29633e4f`),
the record is Core's serialized block locator, committed from the chainstate
flush rather than per block, with the old 32- and 36-byte records decoded
once and rewritten, and a record naming a block the block index does not
hold is refused with Core's "Please rebuild the index" (`b75d5da4`; the
base-index struct gained a slot). The obfuscation-key read of `bb88da61` had
refused a v0.14.3 chainstate's own key before NeedsUpgrade could speak; the
seam commit on `main` puts the two refusals in InitCoinsDB's order.

### Round-8 sweep

Binary `cf46af32` (the round through the regress batch's second phase; four
staggered batches of the harness with a 150 s cap, the time-outs and the two
new failures rerun serially with a 900 s cap), classification in
`docs/functional-sweep-2026-09-13/after-cf46af32.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | 69 | 166 | 5 | 23 |
| `bc65804a` round 4 | 100 | 137 | 3 | 23 |
| `2a7074c4` round 5 | 136 | 102 | 2 | 23 |
| `bdfd8434` round 6 | 193 | 59 | 2 | 9 |
| `632abe24` round 7 | 204 | 48 | 2 | 9 |
| `cf46af32` round 8 | **233** | **21** | **0** | 9 |

Twenty-nine tests went to PASS and none left it: `feature_anchors`,
`feature_assumeutxo`, `feature_assumevalid`, `feature_block`,
`feature_dbcrash`, `feature_maxuploadtarget`, `feature_presegwit_node_upgrade`,
`feature_proxy`, `feature_rbf`, `interface_zmq`, `p2p_blockfilters`,
`p2p_compactblocks`, `p2p_compactblocks_blocksonly`, `p2p_dns_seeds`,
`p2p_feefilter`, `p2p_filter`, `p2p_i2p_ports`, `p2p_i2p_sessions`,
`p2p_invalid_messages`, `p2p_invalid_tx`, `p2p_orphan_handling`, `p2p_ping`,
`p2p_private_broadcast`, `p2p_seednode`, `p2p_segwit`, `p2p_sendtxrcncl`,
`p2p_unrequested_blocks`, `rpc_blockchain`, `rpc_rawtransaction`. An interim
sweep on `53d98310` (after the first five batches) had found three tests red
that Round 7 had green -- `feature_pruning`, `feature_loadblock`,
`feature_init` -- which the regress batch took (above); all three pass here
except `feature_init`, which had never passed and moved from `:93` to the
index damage rounds. Of the 21 failures, thirteen are the wallet.dat, MuSig2
and absolute-path decisions, two need NET_ADMIN, and the rest are the coins
format (`feature_init`, `feature_coinstatsindex_compatibility`), the default
datadir (`feature_config_args` `:212`), `tool_bitcoin`'s multiplexer binary,
`wallet_assumeutxo` `:98`, and `feature_unsupported_utxo_db` `:48` -- a
regression of the regress batch's own obfuscation-key read, which refused
a v0.14.3 chainstate's key before NeedsUpgrade could give Core's sentence;
fixed on the binary after this sweep, in Core's order, together with the
regress batch's last phase (`feature_init` PASS in its oracle run: every
index reads its best-block record checksummed at open and commits Core's
block locator from the chainstate flush). `feature_block` passes in 7.5
minutes and `feature_dbcrash`, `feature_pruning` and `p2p_ping` within the
serial cap; all four time out under the parallel 150 s cap, as before. On
`7bf698a4`, the binary of the seam and the regress batch's last phase,
`feature_unsupported_utxo_db`, `feature_init`, `feature_coinstatsindex` and
`feature_index_prune` PASS in a serial confirming run.

Deployed: both live nodes to `93da36a9` -- testnet4 on 2026-09-24 (the block
index migrated in place, 170,958 entries in 3.0 s; three wallets stamped with
their network id; a four-day soak with no restart, no error line, 51 peers)
and mainnet on 2026-09-29 after a clean stop (969,102 entries in 16.0 s; the
pruned node came back at its tip with 18 peers). Neither node needed
`-reindex`; each left its `headerindex.dat.migrated` behind for a downgrade.

### Decisions recorded in Round 8

- **Core's `blocks/index` LevelDB is ported** (reversing
  [block-file-format-plan.md](block-file-format-plan.md) §6's "keep ours"):
  the index is a public format now, migrated in place from headerindex.dat on
  the first start, and `-reindex` stays additive
  ([reindex-decision-2026-09-18.md](reindex-decision-2026-09-18.md), with the
  witness-less-entry rule added to its re-checked list).
- **No SQLite `wallet.dat`, no BerkeleyRO, no migratewallet** -- wallet-plan's
  policy stands. The wallet tests that fail only there are fail-by-design and
  keep their rows in the sweep: `wallet_descriptor` `:93` (format is
  `leveldb`), `wallet_multiwallet` `:78`, `wallet_backup` `:118`,
  `wallet_startup` `:38`, `wallet_listtransactions` `:229`,
  `wallet_keypool_topup` `:40`, `wallet_reorgsrestore` `:205`, `wallet_hd`
  `:86` (each opens, copies or moves a `wallet.dat` file), `tool_wallet` `:46`
  (the SQLite lock sentence), `wallet_backwards_compatibility` `:278` (an old
  Core cannot open a LevelDB wallet), `wallet_migration` `:139` (BDB). Adapted
  copies of seven of them with only that step changed pass end to end
  (the wallet batch's `build/adapted/`). `wallet_musig` `:262` is MuSig2
  signing, out of scope; `wallet_crosschain` `:32` is the Round-5 refusal of
  absolute wallet paths, which stands (nested relative names are accepted
  now, as Core accepts them).
- **The default datadir stays `~/.bitcoin-lisp`**: our chainstate is not
  Core's format, so sharing `~/.bitcoin` with a Core install would corrupt
  one of the two nodes; the reason is in `BL.CFG:DEFAULT-DATA-DIRECTORY`'s
  docstring and README.md. `feature_config_args` `:212` expects Core's name
  and stays red.
- **Private broadcast is ported** (reversing Round 7's "refuses rather than
  queueing"). Two divergences are recorded in the manual's p2p section: the
  short-lived connections run on their own threads and never join the peer
  list (nothing but the one exchange can be sent on them, where Core relies
  on a send filter), and a v1 re-dial after a failed v2 attempt keeps the
  first dial's proxy.
- **Core's start-up port and address checks are enforced**:
  CheckHostPortOptions for `-i2psam`, `-onion`, `-proxy`, `-bind`, `-rpcbind`,
  `-torcontrol`, `-whitebind` and `-zmqpub*` (a `-zmqpub*=ipc://` spelling is
  refused; Core takes `unix:`), and a proxy host name is resolved at start-up.
  A relative `-walletdir` refuses start-up. `addnode onetry` blocks for up to
  10 s until the dial is made, as Core dials it on the RPC thread.
- **The chainstate lock order differs from Core's**: `*chainstate-mutex*` is
  taken inside the node lock, because every activation caller already holds
  the node lock across the whole activation and the connect hooks take it
  too; Core takes m_chainstate_mutex before cs_main. `install-cs-main-check`
  makes the order mechanical.
- **`-reindex-chainstate` re-validates every block**, as Core does; scripts
  stay skipped under assumevalid.

### Left open after Round 8

- **Core's chainstate (coins) LevelDB format** -- the one decision the round
  did not take. With `blocks/index` ported and the index records Core's,
  `feature_coinstatsindex_compatibility` `:34` and full datadir interchange
  with Core wait on the coins encoding and its obfuscation; a mainnet
  migration of ~180 M coins is hours of downtime, so it is the user's call.
- `wallet_assumeutxo` `:98`: pruneblockchain after the background sync must
  answer GetPruneHeight's walk over the snapshot chain's blocks, which needs
  them in separate block files (unchanged since Round 7).
- The Sparrow acceptance run of [wallet-plan.md](wallet-plan.md) P7 needs a
  desktop client; nothing in this harness can run it.
- `feature_bind_port_discover` and `feature_bind_port_externalip` need
  NET_ADMIN in the container; `interface_usdt_*`, `interface_ipc*`,
  `tool_bench_sanity_check` and `tool_bitcoin_chainstate` stay SKIP as in
  Round 6.
- Found and not fixed: Core's "Invalid -wallet path" refusal is reachable only
  through wallet.dat files; the duplicate `-wallet` check compares names, where
  Core compares joined paths; the unnamed `""` wallet is `wallets/wallet.dat`
  in Core; about twenty tolerated undefined-variable forward references
  remain outside the networking layer (`*blocks-since-flush*`,
  `+seed-outbound-connection-threshold+`, `+wallet-timestamp-window+`,
  `*request-id*`, `+standard-script-verify-flags+`); Core's disk-space, exFAT
  and onion-bind InitWarnings are not emitted.

## Round 9

Five worktree batches merged onto `main` on 2026-09-29, from `93da36a9`
(the Round-8 report, both live nodes on it that morning) through the musig
batch's last phase: cleanup (8), coinsdb (3 + 2), erlay (4 + 2), musig
(2 + 2), tools (5 + 6 + 1), with three coordinator seams. The round was the
user's answer to "what can run in parallel next": the one format decision
Round 8 left open, the two subsystems whose Core parity had never been
verified against Core's bytes (Erlay's minisketch, MuSig2's signing side),
the `bitcoin` wrapper and a datadir differential, and compile hygiene.
Every batch ran its own green battery on a fresh FASL volume -- the round
changes nine defstructs and one defconstant -- and the merged battery ran
before every push (42,456 → 43,150 passing checks, `build/cold-main-65.log`
on `4443cfe7`). The `::` ceiling fell from 3,682 to 3,608; the
cold lane now refuses every forward reference and every unused variable in
src/ (`0f382442`, [CLAUDE.md](../CLAUDE.md)). The behaviour changes that
mattered most, by batch:

**cleanup.** Every special and constant is defined before its first use
(`4f6ff991`: node globals into config.lisp and node/state.lisp, the IBD
latch into a new networking/specials.lisp, policy flags into
transaction.lisp), and one of the 24 forward references was a real bug: a
`let` of `*mempool-removal-reason*` before its `defvar` bound it lexically,
so every BIP125 replacement's evictions were announced with the caller's
reason instead of `:replaced` (`6b1d78a7`). No unused variable or
contradicted IGNORE remains in src/ (`42266f07`), and the two gates now
enforce it with self-tests (`0f382442`). A `-wallet` named twice is one
joined path, and a bad path is Core's "Invalid -wallet path" refusal
(`f366553c`); a signed input is complete when VerifyScript says so and its
error is Core's sentence (`6324a084`); a P2TR input is sized as Core infers
it and an off-curve output key is unsolvable (`efa19047`); Core's miniscript
parse error is pinned (`3ddd6c11`).

**coinsdb.** The coins database is Core's chainstate LevelDB, byte for byte
(`e90ba053`): `C`+txid+VARINT(vout) → Core's Coin encoding through the
assumeutxo codec, `B` and `H`, a random obfuscation key XORed over every
value, `-dbbatchsize` partial batches kept from Round 8. Core v28.2 reads
what we write and we read what it writes, with identical `hash_serialized_3`
and `muhash` both ways, and Core's VerifyDB finds no inconsistency in ours.
The first start converts `chainstate/` in place, resumable, in 16 MiB
batches with the converted range compacted as it goes, keying the old and
new records apart by length (37 vs ≤36 bytes); 20 M synthetic coins took
112 s in the container, so the pruned mainnet node's ~180 M coins are
budgeted at 30-60 minutes of blocking start-up, logged every 10 %. Core's
VARINT sorts numerically only within one encoded length, so the UTXO
iterator regroups each txid's outputs (a recorded lesson). A `-reindex`
start keeps the coins, so the head-blocks replay and the pre-0.15 refusal
run under it (`4ec4de57`); genesis's block-index entry records its body's
position and old unpruned datadirs are repaired once (`9184d835`,
`27ced157`); an old `indexes/coinstats` is warned about and kept
(`a9bb7525`). `feature_coinstatsindex_compatibility`, `feature_init` and
`feature_unsupported_utxo_db` PASS in the batch's oracle runs.

**erlay.** The minisketch decoder is a port of Core's vendored library, held
to vectors generated by Core's own pyminisketch reference inside the
container -- field tables, 14 serialized sketches, Core's minisketch_tests
scenario, 116 decode verdicts, 18 BIP-330 short ids and salts, all
byte-exact (`50757528`); the old decoder read past its capacity and
conflated an empty difference with a failure. Eleven BIP-330 divergences
went with it (`ba388f93`): the short id is `1 + (s mod 0xFFFFFFFF)`,
reqrecon carries uint16 fields with q scaled by 2^15 − 1, the sketch
extension is only the extension, round messages are accepted only from a
registered peer in its role, a 128-term capacity ceiling bounds a peer's
demand (our measured number, recorded as ours), an initiator with an empty
set still runs its round, and reconciled transactions are announced by txid
with their real fee rate. Rounds time out after 60 s (Core's
GETDATA_TX_INTERVAL, the nearest thing to a timing text), the set moves into
the snapshot as the BIP says, q is re-estimated per peer, and one writer
feeds the announcement queue (`8ddc7259`). Core at the pin has only the
handshake ([erlay-plan.md](erlay-plan.md) §6.1); with `-txreconciliation`
off nothing past it is reachable on the wire. `p2p_sendtxrcncl` keeps
passing, and a loopback test runs two of our nodes through a full round
with a no-rounds control.

**musig.** The MuSig2 signing side that Round 8 and the coverage audit left
out on purpose: nonces, partial signatures and aggregation through
libsecp256k1's musig module, BIP 327's vectors byte-exact (key_agg,
nonce_gen, nonce_agg, sign/verify, tweak, sig_agg; `fe0b2e2c`). The secret
nonce lives in foreign memory, never in the Lisp heap; the signing call,
invalidation and the GC finalizer take it with one compare-and-swap, so a
second use signals `musig-secnonce-reused` where Core's move-only
MuSig2SecNonce would not compile -- eight threads racing on one nonce give
one signature. The wallet flow is Core's SignMuSig2 (`b4909766`):
walletprocesspsbt contributes pubnonces, then partial signatures once every
nonce is in, then aggregates; descriptorprocesspsbt contributes a nonce as
Core's release does; finalizepsbt aggregates only; the three BIP 373 PSBT
fields use Core's layout. Along the way a derived musig() key's origin
became Core's (the aggregate's fingerprint plus the musig path), rawtr()
inputs stopped getting a TAP_INTERNAL_KEY Core never writes, and
participants' keys reach the signing maps. `wallet_musig` PASSES all 20
success and 3 failure cases; `rpc_psbt`, `wallet_taproot`,
`wallet_miniscript` and `wallet_multisig_descriptor_psbt` keep passing. The
live mainnet node's libsecp256k1 is v0.5.1 without the musig module; its
wallet is off, and the next image upgrade takes v0.7.1.

**tools.** `bitcoin`, Core's command wrapper, dispatches to the node and
the tools with Core's usage, exit codes and `execvp` error (`36df4026`;
`tool_bitcoin` PASSES). A datadir differential now runs both ways against
Core v28.2 (`d9f46618`, `scripts/interop/datadir_interop.py` in
`scripts/interop-test.sh`): our node mines 129 blocks of every output kind
plus a stale branch, Core starts on the copy, and 1,019 answers per
direction -- getblockhash, getblockheader, getblock, getblockfilter,
gettxoutsetinfo, getrawtransaction, gettxoutproof, getchaintips,
getindexinfo -- compare with 0 mismatches. The lane found two defects the
sweep never had: genesis's block-index record lacked HAVE_DATA, on which
Core v28.2 hung forever at "Verifying blocks…" (`3e265ccc`), and every
double in an RPC reply was printed with 17 digits where UniValue prints 16
(`1c80b876`, 261 mismatches; difficulty is now GetDifficulty's). It also
corrected the coordinator's premise: only the index best-block locators
were Core's, not the records. Now they are (`db10b0c3`, `2b81070c`,
`21837073`): the txindex and spender index keep CDiskTxPos (and read the
transaction back to check its txid, as FindTx does), the block filter index
keeps Core's height/hash records with the filters in `fltr?????.dat` files,
the coinstats index keeps Core's per-height records and running MuHash
under `M`, each migrated in place on first start (729 regtest blocks with
all four indexes: 0.5 s; testnet4 projected 15-17 minutes before the
indexes catch up; mainnet's filter index 5-20 minutes, disk-bound, with a
transient doubling of the index's disk use). Core v28.2 logs "txindex is
enabled at height 129" on our indexes, and the lanes copy `chainstate/` and
`indexes/` by default (`fe3db982`). A coinstats state the index cannot read
refuses the start with Core's sentence, the backfills walk the chain once,
and a datadir without chainstate.dat takes its tip from the coins quietly
(`58f2ab6e`); bitcoind reads its config before `-help`/`-version`, and every
program prints one license text (`dcfbf3a9`).

### Round-9 sweep

Binary `ddb02f15` (every batch merged; four staggered batches of the
harness with a 150 s cap, the time-outs and the three new failures rerun
serially with a 900 s cap), classification in
`docs/functional-sweep-2026-09-13/after-ddb02f15.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | 69 | 166 | 5 | 23 |
| `bc65804a` round 4 | 100 | 137 | 3 | 23 |
| `2a7074c4` round 5 | 136 | 102 | 2 | 23 |
| `bdfd8434` round 6 | 193 | 59 | 2 | 9 |
| `632abe24` round 7 | 204 | 48 | 2 | 9 |
| `cf46af32` round 8 | 233 | 21 | 0 | 9 |
| `ddb02f15` round 9 | **236** | **18** | **0** | 9 |

Five tests went to PASS -- `feature_coinstatsindex_compatibility`,
`feature_init`, `feature_unsupported_utxo_db`, `tool_bitcoin`,
`wallet_musig` -- and two left it. `feature_includeconf` `:59` was a
regression of the tools batch's config-before-`-version` read: the files
were read twice, so the stderr warning for an `-includeconf` inside an
included file was written twice, and the test compares the whole of stderr
at stop; `e5f07bcd`, on the binary after this sweep, reads the config once
and hands it to the start (`feature_includeconf` PASS in its confirming
run). `p2p_v2_misbehaving` `:156` gives the node one second between
`bumpmocktime(4)` and the socket close; under the parallel batches the sync
thread's next pass came late, and it PASSES serially on the same binary and
on `e5f07bcd`, as it had in Round 8's serial rerun -- a load-sensitive
margin, not a behaviour change. `wallet_listsinceblock` failed once under
the same load and passed serially. Of the 18 failures, thirteen are the
wallet.dat, MuSig2-free and absolute-path decisions (`wallet_musig` itself
now passes), two need NET_ADMIN, one is the documented datadir name
(`feature_config_args` `:212`), one is `wallet_assumeutxo` `:98`, and the
two above. `feature_block`, `feature_dbcrash`, `feature_pruning` and
`p2p_ping` time out under the parallel 150 s cap and pass serially, as
before.

Deployed: both live nodes to `ceaf9994` on 2026-09-29. testnet4 first: its
14.25 M coins converted to Core's chainstate format in two minutes (about
100 k coins/s on the server's disk), the block filter index in 10 s, the
coinstats index in 221 s, the txindex in place; all three indexes synced at
the tip, no error line. Then mainnet, after a clean stop: 400,530,565 coins
-- more than twice the 180 M the batch had budgeted for -- converted in 31
minutes, the chainstate shrank from 32 GB to 11 GB under Core's compressed
records, the filter index migrated in 5.5 s, and the pruned node came back
at its tip with no error line. Neither node needed `-reindex`.

### Decisions recorded in Round 9

- **Core's chainstate (coins) LevelDB format is ported** -- the decision Round
  8 left to the user, taken by approving the batch. The conversion runs in
  place at the first start of the new binary (resumable; a downgrade needs
  `-reindex-chainstate`), and the mainnet node's projected 30-60 minutes of
  blocking start-up are reported before its deploy, not discovered during
  it. Every index record is Core's too (txindex, spender, block filter,
  coinstats), so a datadir now interchanges with Core v28.2 whole:
  `blocks/`, `blocks/index`, `chainstate/`, `indexes/`.
- **Erlay beyond the handshake is ours by construction**: Core at the pin has
  only `sendtxrcncl`, so the rounds are held to BIP 330 and to Core's
  vendored minisketch reference; the 128-term sketch capacity ceiling and the
  60 s round timeout (Core's GETDATA_TX_INTERVAL) are our numbers, recorded
  at the constants and in [erlay-plan.md](erlay-plan.md) §6.1. Nothing past
  the handshake is reachable with `-txreconciliation` off, the default.
- **MuSig2 signing diverges from Core in five recorded ways, all safer**: a
  second nonce for a live session is an error, not Core's Assert; one nonce
  table per wallet rather than per SPKM; a participant carries only its own
  leaf hashes; an aggregate signature is verified against its key before it
  is recorded; a PSBT origin that does not reach the key is skipped rather
  than asserted. descriptorprocesspsbt publishes a nonce and drops its
  secret, as Core's release does. `%wallet-sign-transaction` has no MuSig2
  step (Core's would orphan nonces; no observable difference), noted at the
  function.
- **A duplicate `-wallet` warns and loads once**: Core compares the joined
  paths lexically, so `w1` and `./w1` pass its check and then fail on the
  database lock; ours joins and normalizes, then warns. Recorded at the
  check.
- **The cold lane tolerates no forward reference and no unused variable in
  src/** ([CLAUDE.md](../CLAUDE.md)); a special is defined before its first
  use, never declaimed into existence.
- **A coinstats index whose running state disagrees with its best-block
  record refuses the start** in Core's words, reversing the batch's first
  choice to rebuild; a rewind that cannot reverse a block (body or undo
  gone) still rebuilds where Core aborts -- left as is, noted.
- **Legacy per-block files keep their own index records** (`L` in the
  txindex, `S` in the spender index, prefixes Core never reads), since a
  block outside the blk files has no CDiskTxPos; mainnet's 2,706 such files
  run under no txindex.

### Left open after Round 9

- Byte-exactness of the minisketch port against the C++ library itself:
  the container has no C++ compiler, so the oracle is Core's Python
  reference, and whether the two agree is Core's claim, not ours.
- The mainnet node's libsecp256k1 is v0.5.1 without the musig module; the
  next image upgrade takes v0.7.1 (the container already has it).
- `wallet_assumeutxo` `:98` (snapshot blocks in their own block files),
  `feature_config_args` `:212` (the documented datadir name), the
  NET_ADMIN bind tests, the wallet.dat-bound tests and `wallet_crosschain`
  are unchanged from Round 8's tables.
- CJDNS transport ([tor-i2p-cjdns-plan.md](tor-i2p-cjdns-plan.md) P5), the
  Sparrow acceptance run (a desktop client), and Core's fuzz targets beyond
  the property tests.
- Found and not fixed: five structs are defined after code that uses them was
  compiled (`storage/chain.lisp`, `mempool.lisp`, `versionbits.lisp`,
  `networking/peer.lisp`), so their accessors are not inlined on hot paths;
  createwallet over a path reached through a file can still surface a raw
  file-system error; a rewind the coinstats index cannot reverse rebuilds
  where Core aborts; Core v28.2 cannot share a coinstats index with the
  pinned Core at all (the path and record changed after v29); the tests/
  tree still carries 29 style warnings the gates do not cover.

## Round 10

Five worktree batches merged onto `main` on 2026-09-30, from `12202352`
(the Round-9 deploy note) onward: sketch (2), structs (9), storage (6),
fuzz (19 with its merges) and net (11 with its merges), plus the batches'
second phases. The round took the list that followed Round 9 -- the
verification gaps, the compile-order debt, the last storage-layout items
and the two sweep failures that were not decisions -- with the same rule,
Core's way unless a documented reason. Every batch ran its own green
battery on a fresh FASL volume (three commits change a defstruct's slots or
file), and the merged battery ran before every push; the `::` ceiling fell
from 3,608 to 3,557, the EQUALP hash-table ceiling from 102 to 86, and the
cold lane gained two gates: no defstruct compiled after a reader
(`scripts/check-struct-order.sh`) and no unused variable in tests/ either.
The behaviour changes that mattered most, by batch:

**sketch.** The minisketch port is held to Core's C++ library itself, not
only to pyminisketch (`bf68b748`): `scripts/minisketch-cpp-vectors.sh`
builds a session-tagged derived image that adds g++ and make to the pinned
one, compiles `refs/bitcoin/src/minisketch/` with Core's own defines,
generates `tests/data/minisketch_cpp_vectors.json` through the C API (field
tables, 14 sketches, Core's merge scenario, 116 decode verdicts, capacity
and element edges, seeded random sets, 259 entries shared with the Python
file), compares the two files and removes its image. The library,
pyminisketch and our port agree on every vector; the port needed no change.
The battery reads the checked-in JSON and never needs the C++ image.

**structs.** Four structs were compiled after code that read their accessors
-- BLOCK-INDEX-ENTRY and CHAIN-STATE (now in a new `src/storage/types.lisp`
at the head of the storage module), MEMPOOL and VB-WARNING-CHECKER (moved up
in their files) -- and PEER's early reader, `txreconciliation-set`, now loads
after it (`8320bc2a`, `20d83cfc`, `5853deb6`, `cb81f49c`): the hot accessors
inline again (`recon-should-start-round-p` 13.2 → 7.8 ns per call), and
`scripts/check-struct-order.sh` refuses a recurrence (`45367e96`). The
tests/ tree compiled with 30 style warnings and one WARNING; four were real
test bugs -- an ibd test bound a constant that no longer existed and so
always waited its full 10 s -- and the unused-variable gate now covers
tests/ (`b9af97b2`, `a1b0d58f`). createwallet and restorewallet over a path
through a plain file answer Core's `-4` filesystem sentence instead of a raw
SBCL error (`fbfd3e63`); sixteen txid- and wtxid-keyed sets use the octet
test (`8920d0d2`).

**storage.** Every index directory now lives at Core's path --
`indexes/txindex`, `indexes/blockfilter/basic` with the `fltr?????.dat` files
beside the database, `indexes/coinstats`, `indexes/txospenderindex` -- and a
datadir with the old flat directories moves each one into place at start-up
with a single rename, both parents fsynced, refusing before it moves anything
if an index exists at both paths (`aced0dd7`, `09c4236b`, `bf268e3c`); the
`-migratedatadir` option, which Core does not have, is gone. A loaded
assumeutxo snapshot's blocks go to block files of their own, as Core's second
block-file cursor keeps them (`32003780`, blockstorage.cpp:771-905): before,
one file mixed the snapshot's heights with the background chain's, and
pruneblockchain after the background sync answered -1 where Core's
GetPruneHeight answers 298. A coinstats or spender-index rewind that cannot
reverse a block aborts the node with Core's "Failed to rewind" instead of
rebuilding (`31d65d69`, `bc436f00`). `wallet_assumeutxo` PASSES in the
batch's oracle run.

**fuzz.** 69 of Core's 216 fuzz targets, from 37 of its 133 files, are
seeded property tests under `tests/fuzz/` -- a port of FuzzedDataProvider
(`tests/fuzz/fuzz.lisp`), the Consume* helpers, one fiveam test per target
citing Core's file and invariant, a positive control and a minimum-reached
floor each -- covering deserialization, transactions, scripts and flags,
net messages, addrman, crypto, encodings, wallet keys and PSBT, miniscript,
RPC parsing and storage codecs, about 70 s in all. They found eight real
defects, each fixed in its own commit with the input pinned:
TxOutCompression's amount now wraps as Core's uint64 and the code and script
size are uint32 (`348c1c6f`); compact-block indexes are uint16 with Core's
three refusals (`729b7055`); a subnet mask must be contiguous and a full
IPv6 mask works (`29971918`); 0.0.0.0 and 255.255.255.255 are not routable
(`132e0528`); a WIF over an invalid scalar is refused (`1303ec27`); PSBT
pubkeys, origins and witness stacks are type-checked at decode
(`abe86d0e`); LocaleIndependentAtoi saturates and ParseMoney follows Core's
grammar (`9e3a1472`); storage VARINTs are read into Core's field types
(`8282a5e7`).

**net.** An unfinished handshake is judged by the thread that owns its
socket, between its 50 ms reads, and closed in that pass, as Core's
SocketHandler closes what InactivityCheck marked (`dee1ef27`) -- the sweep's
`p2p_v2_misbehaving` failure was the sync thread's tick arriving 0.7 s after
`bumpmocktime`; a ready peer's ping and inactivity are judged every tick
(`753f27fd`); Discover runs whenever the node binds on any address, listening
or not (`1a078558`, init.cpp:2193-2197); an accepted peer is published
already marked detecting when we offer v2 (`a3cd76dd`). The two `bind_port`
tests fail on Core v28.2's own bitcoind at the same lines, because the
pinned framework adds `-bind` to nodes given none and dials ports their
1.1.1.1 binds do not listen on; copies with only those two steps replaced
pass on Core and, after the Discover fix, on ours. An IBD profile over
2,100 full regtest blocks (sb-sprof on the syncing node) found three hot
spots and fixed each with identical bytes: `cl-array-to-coalton-vector`'s
generic VECTOR-MAP-INTO (12.9 % → 1.4 %, `bbb7dc5c`), `flag-enabled-p`'s
synchronized string-keyed cache (10.2 % → 1.4 %, `49044f9c`) and the
one-byte-at-a-time receive drain (11.3 % → 0.3 %, `9db478e6`, 51-78 MB/s →
2.7-4 GB/s); the P2P sync fell from 339-373 s to 295-301 s, a `-loadblock`
import from 138 s to 107 s, sampled CPU by 30 %. The no-peer, reorg and
index-rewind lines log at Core's levels (`330c5ccb`, `3c0732e1`).

The batches' second phases, merged after the first: fuzz's five findings
went Core's way -- `conf-parse-int` reads as GetIntArg's atoi (`abc` is 0,
`125peers` is 125, past int64 saturates; `59488307`), a PSBT partial
signature must pass DERSIG|STRICTENC at decode (`d46ee324`), nine struct
slot defaults now satisfy their declared array types (`4a7dc674`), the
invented `+max-block-tx-count+` is gone and an oversized BIP152 count is
dropped through MAX_SIZE without punishment (`a9d787e6`, a `define-message`
macro change), and AreInputsStandard treats a coinbase and a missing coin as
Core does while the three P2SH policy readers take the stack top an
evaluation leaves, so `<16×CHECKSIG> OP_0` over an empty redeem script is
relayed as Core relays it (`c8582723`; the consensus sigop counter keeps
Core's last-push read). net's second phase gave the project one outpoint
key, COutPoint's own bytes in `bl.ser:make-outpoint-table`, and moved the
validation layer's cons-keyed overlays onto it: EQUALP hashing fell from
15.2 % of the IBD profile to none, the sync from 339-373 s before the batch
to 246-253 s (`7adb3665`, `0d53645e`); the fee estimator now learns only what
Core's processBlock learns and does nothing for an empty mempool
(`8278da9a`); `scripts/conformance.sh` gained `--runner` and `--adapted`
lanes and the two adapted bind tests are tracked under
`tests/functional-adapted/` (`e8369f4c`); the SIGUSR1 profile lands beside
debug.log (`4430ff79`).

### Round-10 sweep

Binary `1df60a1c` (every batch and second phase merged; four staggered
batches of the harness with a 150 s cap, the three time-outs rerun serially
with a 900 s cap), classification in
`docs/functional-sweep-2026-09-13/after-1df60a1c.tsv`:

| binary | PASS | FAIL | TIMEOUT | SKIP |
|---|---|---|---|---|
| `580627ba` round 2 | 58 | 176 | 6 | 23 |
| `67b724d2` round 3 | 69 | 166 | 5 | 23 |
| `bc65804a` round 4 | 100 | 137 | 3 | 23 |
| `2a7074c4` round 5 | 136 | 102 | 2 | 23 |
| `bdfd8434` round 6 | 193 | 59 | 2 | 9 |
| `632abe24` round 7 | 204 | 48 | 2 | 9 |
| `cf46af32` round 8 | 233 | 21 | 0 | 9 |
| `ddb02f15` round 9 | 236 | 18 | 0 | 9 |
| `1df60a1c` round 10 | **239** | **15** | **0** | 9 |

Three tests went to PASS and none left it: `feature_includeconf` (the
single config read), `p2p_v2_misbehaving` (the handshake thread's own
close) and `wallet_assumeutxo` (the snapshot's own block files). Every one
of the 15 failures is a recorded decision or a framework limit: eleven are
the wallet.dat file format (`tool_wallet`, `wallet_backup`,
`wallet_backwards_compatibility`, `wallet_descriptor`, `wallet_hd`,
`wallet_keypool_topup`, `wallet_listtransactions`, `wallet_migration`,
`wallet_multiwallet`, `wallet_reorgsrestore`, `wallet_startup`), one the
Round-5 refusal of absolute wallet paths (`wallet_crosschain`), one the
documented datadir name (`feature_config_args` `:212`), and two the pinned
framework's `-bind` handling that fails on Core v28.2 too
(`feature_bind_port_discover`, `feature_bind_port_externalip`; their
adapted copies pass). `feature_block`, `feature_dbcrash` and
`feature_pruning` time out under the parallel 150 s cap and pass serially,
as before. The 9 SKIPs are unchanged since Round 6.

### Decisions recorded in Round 10

- **`-migratedatadir` is removed**: Core has no such option; the index
  directories move to Core's paths by themselves at start-up, and nothing
  else it moved still needs moving.
- **`feature_bind_port_discover` and `feature_bind_port_externalip` are
  SKIP-by-framework**: both fail on Core v28.2's own bitcoind at the same
  lines, because the pinned framework adds `-bind` to nodes given none and
  dials 127.0.0.1 ports that a 1.1.1.1 bind does not listen on. Copies with
  only those two steps replaced live in `tests/functional-adapted/` (README
  names the steps and Core's lines) and pass on Core and on ours; they run
  through `scripts/conformance.sh --adapted`.
- **The minisketch capacity ceiling (128) stays ours** even though the C++
  library decodes larger capacities; the library vectors cover 129 and 256,
  and only our reconciliation layer refuses them.
- **A coinstats or spender-index rewind that cannot reverse a block aborts
  the node**, reversing Round 9's rebuild; the case where the stale branch
  is not in the header index still rebuilds (start-up refuses it earlier).
- **The three P2SH policy readers take the evaluated stack top**, as
  AreInputsStandard, IsWitnessStandard and the MAX_P2SH_SIGOPS gate do in
  policy.cpp:213-250, superseding gap-analysis-8-plan's "do not repoint";
  the consensus sigop count (script.cpp:183-205) keeps its own last-push
  read.
- **The fee estimator keeps no per-block statistics**: the block fee-rate
  percentile nothing read, and its ten-block rewrite of fee_estimates.dat,
  are gone; `connect-block` and `perform-reorg` still accept
  `:fee-estimator` for their callers and collect nothing.

### Left open after Round 10

- The IBD profile's top frame is now the Coalton interpreter's type checks
  (10.5 %), then the syscall and socket floor; the coins cache's
  `utxo-key-hash` reads only the first eight bytes of the txid and does not
  mix the output index, so one transaction's outputs share a bucket chain.
- The `:fee-estimator` keyword is still threaded through the IBD and RPC
  call paths and is now unused; `src/networking/ibd.lisp` writes forensic
  blocks to a fixed `/data/bitcoin-lisp/forensic-blocks/` path.
- Fuzz: 69 of Core's 216 targets are ported; the cluster/txgraph/mempool/
  orphanage/txrequest simulations, the P2P processing and transport
  simulations, the coins-view and chainstate targets, and miniscript_stable/
  smart need harnesses of their own. Found by the targets and not fixed:
  `scriptsig-push-only-p` accepts a direct push that runs off the end where
  IsPushOnly says false (reject reason only); `-maxmempool=-1`'s message;
  the bitcoin-wallet tool's createfromdump still surfaces a raw file error
  for a name through a plain file.
- Five src/ style warnings no gate covers: `&OPTIONAL and &KEY` in one
  lambda list each in src/node/init.lisp, src/node/mempool-persist.lisp and
  three in src/rpc/blockchain.lisp; the musig BIP327 signing-vector test
  never reads the vectors' signer column.
- The minisketch CLMUL field implementations exist only on x86_64; the
  Docker VM is arm64, so only the generic fields were exercised (they
  compute the same field).
- Unchanged: the live mainnet node's libsecp256k1 v0.5.1 (musig module at the
  next image bump), `wallet_assumeutxo` now passes but the wallet.dat-bound
  tests, `wallet_crosschain`, `feature_config_args` `:212` and the Sparrow
  and CJDNS items stand as in Rounds 8-9.
