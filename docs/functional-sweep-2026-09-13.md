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

Eleven more tests pass (`feature_maxtipage`, `feature_reindex_init`,
`mempool_expiry`, `p2p_eviction`, `p2p_node_network_limited`,
`p2p_nobloomfilter_messages`, `rpc_getblockstats`, `rpc_getdescriptorinfo`,
`rpc_signmessagewithprivkey`, `rpc_txoutproof`, `wallet_address_types`,
`wallet_keypool`, `wallet_sendmany`, `wallet_simulaterawtx`); about thirty
failure points advanced. Batch D's oracle runs add `rpc_decodescript`,
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
