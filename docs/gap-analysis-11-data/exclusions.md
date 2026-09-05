# GA11 finder exclusions

Everything below was found in GA1-GA10 and is FIXED on main (or refuted). Do NOT report these again;
report only a NEW, DISTINCT defect in the same area and say explicitly how it differs. The four GA10
S1s (sighash nVersion type error, coins-cache FRESH after sync, cmpctblock work floor / header indexing,
block bodies persisted without CheckBlock) are fixed too, as are the follow-ups named at the end of
docs/gap-analysis-10-verdicts.md.

## GA1-GA9 (from the GA10 survey seed)

Already found in GA1-GA9 -- do NOT report these again (report only if you find a NEW,
DISTINCT defect in the same area, and say explicitly how it differs):
- Block weight omitted header+tx-count varint; finality check skipped the coinbase
- BIP68 signed-version gate; invalidated block-index entry resurrected
- getblocktxn served at any depth unrated; same-block chained spends skipped sig validation
- Block spending an output twice accepted; tapscript resource limits / annex weight budget
- P2SH sigop counting vs GetSigOpCount; CastToBool multi-byte negative zero
- FindAndDelete offset matching; strict-DER off-by-one; verifytxoutproof tx count
- RPC auth never enforced; header MTP unenforced mid-batch
- Signet cannot follow its own chain; connect-block eq-based ancestry walk
- Script checks skipped on a bare height comparison
- Onion peer discourages 127.0.0.1; addrman failure accounting; inbound eviction protections
- Receive byte accounting keyed on raw command; inbound handshake inline on accept thread
- Reorg never flushes coins cache; gettxoutsetinfo clears live cache without the node lock
- No Uncache for rejected txs; txindex in-memory txid table; PSBT witness_utxo precedence
- getblocktemplate discards template_request; web UI console stores raw command lines
- Package-RBF feerate truncation; v1 12-byte message type unvalidated
- noX=1 config negation discarded; taproot spend-vector corpus absent

## GA10 (all judged; final severity, then the finding)

- S1 `2279d91b`: coins-view-cache-sync clears DIRTY but leaves FRESH set, so coins already written to LevelDB are later dropped on spend without an eras
- S2 `2f0cf648`: Outbound netgroup-diversity set is built from ALL peers including inbound, so free inbound connections can veto our outbound replacemen
- S2 `42dacfaf`: Every dial counts an addrman failure — Core suppresses failure counting when the node looks offline, and never counts it for manual/add
- S2 `56b53a04`: getnetworkhashps ignores its `height` argument entirely, does not implement nblocks = -1, and never validates its inputs
- S2 `7f01522e`: %scan-flat-block-files stops at the first missing blk file, so a pruned node loses its entire flat block index on restart
- S2 `801f2ad3`: -rpcpassword / -rpcauth / -rpcuser / -torpassword are written to debug.log in cleartext; Core masks them as ****
- S2 `87801e86`: Network-only options (-port, -rpcport, -bind, -connect, -addnode, -wallet, -walletdir) are honored from bitcoin.conf's default section 
- S2 `97855c61`: PSBT "complete" and the already-signed test trust final/partial fields without verifying the scripts
- S2 `abae237b`: Eviction's disadvantaged-network reserve protects the NEWEST connections instead of the longest-connected (comparator inverted)
- S2 `c831e584`: The RPC coins sync advances the persisted coins best-block pointer without persisting the block index, so a later crash makes the node 
- S2 `d2099b36`: The "-peerblockfilters without -blockfilterindex" refusal is nested inside (when prune ...), so an unpruned node advertises NODE_COMPAC
- S2 `d4f123e8`: A negated repeatable option (-noX) is appended to the list as the literal string "0" instead of clearing it; -norpcauth kills the RPC s
- S2 `d9aadbc5`: IsBadPort is absent: automatic outbound dials will connect to any gossiped port (SMTP, SSH, MySQL, IRC, …)
- S2 `e2db2089`: -rpcwhitelist / -rpcwhitelistdefault are accepted at startup but never enforced, so a user the operator restricted gets full RPC
- S2 `feac3eb3`: /rest/spenttxouts serializes the on-disk compressed CBlockUndo codec instead of Core's REST format, and its JSON omits Core's leading c
- S3 `0a061de4`: getrawmempool ignores its second argument mempool_sequence, which our own argument table advertises
- S3 `0c05f5d0`: Relayed addresses go out immediately, one addr message per address, instead of Core's per-peer Poisson-batched queue
- S3 `0c63c99c`: CheckTxInputs (coinbase maturity, fee/value consensus) runs after the standardness-of-inputs, sigop and witness checks instead of befor
- S3 `0e7ec2f3`: /rest/mempool/contents.json ignores the ?verbose= and ?mempool_sequence= query parameters and always serves the verbose dump
- S3 `105290bf`: Dotted section keys in bitcoin.conf (main.rpcport=..., test.connect=...) are treated as unknown options and dropped
- S3 `24e0c216`: /rest/block/<hash>.json renders getblock verbosity 2; Core renders verbosity 3 (SHOW_DETAILS_AND_PREVOUT)
- S3 `272e30f0`: CONST_SCRIPTCODE's OP_CODESEPARATOR rule is applied only to the scriptPubKey and to a scriptCode reached by a CHECKSIG, not to the scri
- S3 `2834e5b3`: JSON-RPC batch members never get the named-argument transform, so any batch call using named params fails with -32603
- S3 `32758a48`: A negative -maxconnections is accepted and clamped instead of being an init error
- S3 `34a807d1`: ECDSA satisfaction sized at 72 bytes on a stated justification that is factually false — our signer does grind low-R
- S3 `38bb5cc7`: CheckTxInputs' input-value MoneyRange guards and ConnectBlock's accumulated-fee guard have no analogue
- S3 `3911beba`: -bind / -whitebind together with an explicit -listen=0 is accepted; Core makes it a hard init error
- S3 `3f90b8bc`: getmininginfo reports currentblockweight/currentblocktx as 0 before any template has been assembled; Core omits the fields
- S3 `5054e381`: wtxidrelay / sendaddrv2 received after VERACK are silently ignored where Core disconnects
- S3 `508fedab`: PSBT parser omits two of Core's global-map validity checks (out-of-range prevout index, unsupported PSBT version)
- S3 `54fdda5c`: Duplicate-in-mempool check is txid-only: Core's "txn-same-nonwitness-data-in-mempool" case is never reported
- S3 `57e206a8`: The BIP94 timewarp floor and check use the fixed 2016-block interval and a hardcoded testnet4 gate; the comment justifying this misread
- S3 `631b90f9`: -forcednsseed=1 with -dnsseed=0 (or with -connect) is silently ignored instead of being an init error
- S3 `6635e4c9`: Package consistency check adds inputs one at a time, misreporting a transaction with duplicate inputs as a package conflict; empty-vin 
- S3 `70502bf3`: A backed-up send buffer makes us DROP outbound messages; Core instead stops processing inbound messages until it drains
- S3 `7b813f60`: generatetoaddress / generatetodescriptor raise an error when maxtries is exhausted instead of returning the blocks mined so far
- S3 `7db4b27f`: verify-checksig's inline FindAndDelete pattern omits the PUSHDATA prefix for signatures longer than 75 bytes
- S3 `81c98c4b`: enforce_BIP94 is hardcoded to testnet4; Core lets regtest turn it on with -test=bip94
- S3 `83599047`: Block templates never signal any BIP9 deployment: nVersion is the hardcoded constant 0x20000000 and vbavailable is hardcoded empty
- S3 `88f3a071`: Block-conflict removal does not clear the conflicted transaction's prioritisation delta
- S3 `8d88f6ac`: base58-decode has no length bound; Core's DecodeBase58 bails as soon as the decoded length exceeds max_ret_len
- S3 `98069fe2`: sendcmpct(0) never clears the recorded high-bandwidth-from flag
- S3 `994f223b`: The relay-finality check runs after the duplicate and missing-input checks, so a non-final transaction with unknown parents is stored i
- S3 `9f54cae8`: %reorg-commit fires tx-relay and wallet side effects without connect-block's background-chainstate role guard
- S3 `a4680ae1`: Gossiped addresses are relayed immediately, one addr message per address — no m_addrs_to_send queue and no poisson broadcast timer
- S3 `a6afe2d6`: generateblock builds its own coinbase and re-introduces the unconditional segwit witness that builder.lisp already fixed
- S3 `a7b67ad1`: OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY consult DISCOURAGE_UPGRADABLE_NOPS when their own flag is off; Core treats them as a pl
- S3 `a9ddbd92`: getnetworkhashps computes the wrong number: integer rounding drops sub-1 H/s results to 0, and the timespan uses the window's endpoints
- S3 `b219c779`: getrawtransaction consults the mempool even when an explicit blockhash is given, and never rejects an unknown blockhash
- S3 `b48227fc`: FindAndDelete is skipped for an EMPTY signature; Core's pattern for an empty sig is the single byte 0x00 (OP_0), not the empty script
- S3 `ba446c02`: Block script validation never consults the script-execution cache, so every mempool-verified transaction is re-interpreted at connect
- S3 `cc698623`: No REST endpoint checks RPC warmup, so /rest/* serves a half-initialized node during startup instead of 503
- S3 `ccac3137`: The intra-block coin overlay keeps provably-unspendable outputs that Core's AddCoin drops
- S3 `d410b7bf`: script-is-push-only-p rejects OP_RESERVED (0x50); Core's IsPushOnly deliberately counts it as push-type
- S3 `d73be57b`: Rolling minimum fee decays with no block since the bump, and block connection never resets the decay clock
- S3 `d8cffd5c`: PSBT signing never checks that existing signatures use the requested sighash type
- S3 `df63423d`: Gossiped addresses are stored in addrman and relayed onward without the banned/discouraged filter Core applies at ingest
- S3 `f506ca73`: No -walletcrosschain guard: a wallet whose locator belongs to another chain is loaded and rewritten
- S3 `f5b31fb7`: OP_CHECKMULTISIG charges nKeysCount against the 201-op budget only after running the signature verifications; Core charges and enforces
- S3 `fac08286`: Coinbase "hash" (wtxid) reported as 32 zero bytes by the RPC transaction serializer; Core reports the real witness hash
- S3 `fdbe8a5e`: The prune window's lower bound is our walk cursor rather than Core's 0, so the first blk file is never prunable
- S3 `ff51e9d5`: Inbound admission ban/discourage checks have no NoBan permission exemption
- S3 `refactor-1`: fsync-parent-directory was written to fix a durability bug and wired into only 3 of its 7 drive sites — 4 atomic-rename paths still nev
- S3 `refactor-2`: bl:token-bucket and bl:make-token-bucket are now undefined symbols — a real regression from the util-layer split
- S3 `refactor-3`: known-config-option-p silently lost its case-insensitive fallback for core-only options
- refuted `606ac3e5`: address-book-add is missing Core's "do not update if no new information is present" gate and its nTime refresh interval
- refuted `6dcf6d71`: Block-relay-only eviction protection ignores fRelevantServices, so a non-tx-relay peer without the services we want can take one of the

## Fixed after GA10 without a finding id
- empty signature skipped CheckPubKeyEncoding; getrawtransaction genesis-coinbase exception; generate*(0) returns [];
  gettxoutsetinfo/scantxoutset hold the node lock; -vbparams; getdata deferral for a send-paused peer; RelayAddress
  rotation key and two-pick fanout; addr ingest num_proc/AddAddressKnown order; sendtxrcncl ignore log; self-announce
  via the addr queue; proxy-failure carve-out for addrman Attempt; inbound-onion whitelist skip; getpeerinfo
  permissions; sigop cap after PreCheckEphemeralTx; one CHECKSIG encoding check in Core order; ms-check-older
  unsigned version; fsync-file logs failures; base58 decode bound; fsync sites pass the directory; wrong-arity build gate.
