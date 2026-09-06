# GA11 survey — the accept-and-drop options

Dimension 7 of `docs/gap-analysis-11-plan.md`. Oracle: Bitcoin Core @ `d3056bc` under `refs/bitcoin/`.
Subject: every name in `define-core-only-options` (`src/config-options.lisp:434-454`, 49 names after
`-rpcwhitelist`, `-walletcrosschain`, `-vbparams`, `-test` and `-blockversion` were promoted to real
options), read with the `-rpcwhitelist` lens — what does an operator who sets it believe the node now
does, and what do we actually do. The real option table was audited for the reverse defect at the end.

Findings: `docs/gap-analysis-11-data/dim-options.json` (13; 7 S2, 6 S3).

## The mitigation that applies to the whole list

`start-node-from-args` logs a WARN naming every core-only option actually supplied
(`src/node/init.lisp:1664-1668`, via `bl.cfg:supplied-core-only-options`):

    Accepted but NOT implemented by this node, so these options have no effect: -X -Y

Executed check — `start-node-plist` on
`-regtest -persistmempool=0 -blocksdir=/mnt/big -walletbroadcast=0 -checkblocks=1000 -checklevel=4
-timeout=30000 -alertnotify=... -shrinkdebugfile=0 -logips=1 -maxreceivebuffer=1` returns the plist
`(:LISTEN T :WALLET-NAMES NIL :NETWORK :REGTEST)` — none of the ten reaches a keyword — and
`supplied-core-only-options` returns all ten, so all ten are named in that warning.

That is a real correction to the operator's belief, and it is why most rows below are class (a)
rather than (b). It has one blind spot, and it is where the (c) findings live: **an option Core
derives from a DIFFERENT option is never supplied, so it is never named**. Two cases:

- `-blocksonly=1` soft-sets `-walletbroadcast=0` (Core `wallet/init.cpp:95`) — our wallet keeps
  broadcasting and nothing warns. **Fixed** (finding `8c442ee3`): the soft set is applied in
  `config-alist->start-node-plist` and logged with Core's own line.
- any `-debug` category defaults `-shrinkdebugfile` to 0 (Core `logging.cpp:167-170`) — we scroll
  the log anyway and nothing warns.

## Classes

- **(a) harmless to ignore** — 33 options. No behaviour Core would have that matters here, or the
  behaviour we have is at least as safe. Each row says which.
- **(b) misleading** — 6 options. The operator believes a protection or a feature is on and it is
  not, with a security, privacy or funds consequence.
- **(c) implemented elsewhere under a different name** — 10 options / 7 mechanisms. The behaviour
  exists; the option is not wired to it. These should be wired, not dropped.

## The table

Core reader is what `init.cpp` (or the option's own module) calls. "we do" is what actually happens
on a node given that option.

| option | Core reader + default | what we do | class | one line |
|---|---|---|---|---|
| `-addresstype` | `GetArg("-addresstype","")` → `m_default_address_type`, `DEFAULT_ADDRESS_TYPE` = bech32 (`wallet/wallet.cpp:2956`) | `getnewaddress` hardcodes `:bech32` as the fallback (`src/wallet/wallet.lisp:1822`); the per-call `address_type` argument works | c | `addresstype=bech32m` still yields P2WPKH from a bare `getnewaddress` — finding `4d28b231` |
| `-alertnotify` | `GetArg("-alertnotify","")` inside `AlertNotify`, fired from `warningSet` (`node/kernel_notifications.cpp:30-47,79-83`) | no AlertNotify, no warning registry, no `LARGE_WORK_INVALID_CHAIN` / `UNKNOWN_NEW_RULES_ACTIVATED` detection; `"warnings"` is the constant `#()` in three RPCs | b | the operator's chain-split pager never fires and polling cannot substitute — finding `c053f780` |
| `-allowignoredconf` | `GetBoolArg("-allowignoredconf", false)` downgrades a FATAL shadowed-conf error to a warning (`common/init.cpp:65-95`) | no shadowed-conf check exists in either direction | b | a datadir `bitcoin.conf` hidden by `-conf` or by a conf-set `datadir=` is silently lost — finding `9e7729b8` |
| `-avoidpartialspends` | `GetBoolArg(..., DEFAULT_AVOIDPARTIALSPENDS=false)` in EVERY `CCoinControl` ctor (`wallet/coincontrol.cpp:12`) | grouping machinery fully implemented; the coin-control default is only ever raised by `avoid_reuse` or the per-call flag (`wallet-spend.lisp:3129`) | c | address grouping stays off for an operator who configured it on — finding `feecc533` |
| `-blockreconstructionextratxn` | `GetIntArg` → `max_extra_txs`, default 100 (`node/peerman_args.cpp:19`) | no extra-txn pool for compact-block reconstruction at all | a | absent feature; costs a `getblocktxn` round trip, no security or funds consequence |
| `-blocksdir` | `GetPathArg("-blocksdir")` → `GetBlocksDirPath()`, default datadir; a missing dir is a fatal InitError (`common/args.cpp:295`, `init.cpp:967`) | blocks always `<datadir>/blocks/` (`src/storage/blocks.lisp:77`); `*blocks-directory*` is declared and never assigned | b | the separate block volume is ignored and the datadir disk fills — finding `ebb73768` |
| `-capturemessages` | `GetBoolArg(...,false)` → dump every P2P message to `message_capture/` (`init.cpp:2112`) | no message capture | a | a developer tool; its absence is immediately visible (no files appear) |
| `-changetype` | `GetArg("-changetype","")` → `m_default_change_type`, else follows the address type (`wallet/wallet.cpp:2965`) | `getrawchangeaddress` hardcodes `:bech32` (`src/wallet/wallet.lisp:1846`) | c | change can land on a different script type than the payment — folded into finding `4d28b231` |
| `-checkaddrman` | `GetIntArg(..., DEFAULT_ADDRMAN_CONSISTENCY_CHECKS=0)`, clamped 0..1e6 (`addrdb.cpp:198`) | no addrman consistency checks | a | default is 0 (off) in Core too; a test-only self-check |
| `-checkblockindex` | `GetIntArg`, default `DefaultConsistencyChecks()` — 0, **1 on regtest** (`node/chainstatemanager_args.cpp:27`) | no block-tree consistency self-check | a | a self-check, not a rule; it would only ever have caught OUR bugs, and it is on by default only under regtest — dimension 9 inherits whether it would have caught a live break |
| `-checkblocks` | `GetIntArg(..., DEFAULT_CHECKBLOCKS=6)` → `VerifyDB` at `LoadChainstate` (`init.cpp:1388`, `node/chainstate.cpp:257`) | no startup verification runs; the `verifychain` RPC exists but nothing calls it at startup | c | the operator's post-crash verification never happens — finding `21cf40de` |
| `-checklevel` | `GetIntArg(..., DEFAULT_CHECKLEVEL=3)`; either option set ⇒ `require_full_verification`, a downgrade becomes a startup FAILURE (`init.cpp:1389-1390`) | as above; our `verifychain` implements levels 0/1 only (no undo, no disconnect/reconnect) | c | folded into finding `21cf40de` |
| `-checkmempool` | `GetIntArg`, default `DefaultConsistencyChecks()` (`node/mempool_args.cpp:47`) | `txgraph-sanity-check` exists (`src/mempool/txgraph.lisp:1045`) and runs on its own schedule, not on this ratio | a | a self-check with no consensus effect; ours is not absent, only not tunable |
| `-checkpoints` | `IsArgSet` ⇒ `InitWarning` "checkpoints were removed. This option has no effect." (`init.cpp:927`) | accepted; our own core-only line warns it has no effect | a | Core warns and ignores, we warn and ignore — identical outcome |
| `-daemon` | `GetBoolArg(..., DEFAULT_DAEMON=false)` ⇒ fork; also defaults `-printtoconsole` to 0 (`bitcoind.cpp:207`, `init/common.cpp:50`) | we never daemonize; `-printtoconsole` defaults ON | a | loud, immediate and non-security: a `Type=forking` unit simply fails to start rather than silently misbehaving |
| `-daemonwait` | `GetBoolArg(..., DEFAULT_DAEMONWAIT=false)`, implies `-daemon` (`bitcoind.cpp:215`) | same | a | as `-daemon` |
| `-dbbatchsize` | `GetIntArg` → `batch_write_bytes`, `DEFAULT_DB_CACHE_BATCH` = 32 MiB (`node/coins_view_args.cpp:13`) | LevelDB write batch size not tunable | a | a throughput knob; no correctness or safety property rides on it |
| `-deprecatedrpc` | `GetArgs("-deprecatedrpc")` — a LIST of method/field names to re-enable (`rpc/server.cpp:341`) | nothing is gated; fields Core hides behind it are always present (`src/rpc/net.lisp:126,248`) | a | we are strictly more permissive than Core's default — an over-permissive RPC surface, not a missing protection |
| `-discover` | `GetBoolArg("-discover", true)`; soft-set 0 by `-proxy`, `-listen=0`, `-externalip` (`init.cpp:797,806,817,1578`) | no interface discovery at all; `*local-addresses*` is written only by the torcontrol client (`src/networking/netaddress.lisp:498-526`) | a | `-discover=0` asks for behaviour we already do not have; `=1` asks for a feature we lack, and lacking it is the privacy-safe direction |
| `-dns` | `GetBoolArg("-dns", DEFAULT_NAME_LOOKUP=true)` → `fNameLookup`, gating `Lookup(pszDest, ..., fNameLookup && !HaveNameProxy())` (`net.cpp:406`) | named dial targets go straight to `usocket:socket-connect` when no proxy applies (`connection.lisp:274`); with a proxy the name IS sent as SOCKS5 DOMAINNAME | b | `-dns=0` still leaks one DNS query per named `-addnode`/`-connect`/`-seednode` — finding `1f1f28b7` |
| `-help` | `IsArgSet` → print help, exit 0 (`common/args.cpp:719`) | handled at the entry point before anything starts (`src/node/init.lisp:1749-1757`) | a | actually implemented; it is on this list only so the option parser accepts it |
| `-i2pacceptincoming` | `GetBoolArg(..., DEFAULT_I2P_ACCEPT_INCOMING=true)`, ignored without `-i2psam`, soft-set 0 by `-listen=0` (`init.cpp:2248`) | no I2P support | a | inert without `-i2psam`, which we also do not support |
| `-i2psam` | `GetArg("-i2psam","")` → SAM proxy (`init.cpp:2232`) | no I2P; `-onlynet=i2p` is a hard init error (`src/node/args.lisp:236`) | a | the dangerous combination (believing traffic is I2P-only) cannot start silently — the node refuses |
| `-ipcbind` | `GetArgs("-ipcbind")` → Unix-socket IPC listeners (`init.cpp:1503`) | no IPC surface | a | absent feature; a client connecting to the socket gets ECONNREFUSED immediately |
| `-limitancestorcount` | `GetIntArg(..., DEFAULT_ANCESTOR_LIMIT=25)`; **deprecated at `d3056bc`** — replaced by cluster limits, kept only for wallet coin selection (`node/mempool_args.cpp:39`) | we implement `-limitclustercount` / `-limitclustersize` (the replacements) and `-walletrejectlongchains` | a | the mechanism it fed was replaced by the cluster limits we do implement |
| `-limitancestorsize` | `IsArgSet` ⇒ `InitWarning` "replaced with cluster size limits" (`init.cpp:930`) | accepted; our core-only line warns | a | Core warns and ignores, we warn and ignore |
| `-limitdescendantcount` | `GetIntArg(..., DEFAULT_DESCENDANT_LIMIT=25)`; deprecated, wallet coin selection only (`node/mempool_args.cpp:41`) | as `-limitancestorcount` | a | same |
| `-limitdescendantsize` | `IsArgSet` ⇒ `InitWarning` (`init.cpp:933`) | accepted; our core-only line warns | a | same |
| `-logips` | `GetBoolArg(..., DEFAULT_LOGIPS=false)` → `fLogIPs`; `CNode::LogIP` appends ` peeraddr=` only when on (`net.cpp:704-707`) | 13 log calls in `peer.lisp` alone print `(peer-address peer)` at :info/:warn, ungated; 82 uses across `src/` | b | the default debug.log records every peer's address, which Core's default never does — finding `559c86ad` |
| `-loglevelalways` | `GetBoolArg(..., DEFAULT_LOGLEVELALWAYS=false)` → always prefix category+level (`init/common.cpp:55`) | our line format is fixed | a | cosmetic; a log-format preference with no behavioural effect |
| `-logsourcelocations` | `GetBoolArg(..., false)` → prefix file:line:function (`init/common.cpp:54`) | not supported | a | cosmetic developer aid |
| `-logtimestamps` | `GetBoolArg(..., DEFAULT_LOGTIMESTAMPS=true)` (`init/common.cpp:51`) | timestamps always on, which is Core's default | a | only `-logtimestamps=0` diverges, and that is a formatting preference |
| `-maxreceivebuffer` | `GetIntArg(..., DEFAULT_MAXRECEIVEBUFFER=5000) * 1000` → `nReceiveFloodSize`; a peer whose PROCESS QUEUE exceeds it is `fPauseRecv` (`net.cpp:4025`) | we have no message process queue — one message is read and handled inline, and its size is capped at `+max-message-payload+` (`src/networking/peer.lisp:624`) | a | the memory this option bounds does not accumulate here; our per-peer in-flight bound is tighter than Core's default. Aggregate-across-peers is dimension 10's |
| `-natpmp` | `GetBoolArg(..., DEFAULT_NATPMP=true)` → `StartMapPort` (PCP/NAT-PMP) (`init.cpp:2097`) | no port mapping | a | connectivity only: the node behind NAT gets fewer inbound peers. Not mapping a port is the security-safe direction |
| `-peerbloomfilters` | `GetBoolArg(..., DEFAULT_PEERBLOOMFILTERS=false)` → advertise `NODE_BLOOM`, serve BIP37 (`init.cpp:1104`) | never advertised, never served; `peer.lisp:781` says so explicitly | a | Core's default is off and BIP37 is a known DoS surface — the missing feature is the safe direction |
| `-persistmempool` | `GetBoolArg(..., DEFAULT_PERSIST_MEMPOOL=true)` gates BOTH `LoadMempool` and `DumpMempool` (`node/mempool_persist_args.cpp:13`, `init.cpp:338,2047`) | **fixed**: one `should-persist-mempool-p` gates `mempool-load-path` and `save-mempool-at-shutdown` (`src/node/mempool-persist.lisp`), with Core's `GetLoadTried` guard | fixed | finding `212b060f` |
| `-persistmempoolv1` | `GetBoolArg` → write the older on-disk format (`node/mempool_args.cpp:106`) | **fixed**: `*persist-mempool-v1*` selects the version-1 layout in `core-mempool-file-bytes` (no key record, unobfuscated) | fixed | folded into finding `212b060f` |
| `-printpriority` | `GetBoolArg(..., DEFAULT_PRINT_MODIFIED_FEE=false)` → log fee rates while assembling (`node/miner.cpp:105`) | not supported | a | a mining log line |
| `-privatebroadcast` | `GetBoolArg(..., DEFAULT_PRIVATE_BROADCAST=false)` → a reserved pool of private connections for our own txs (`net.cpp:3554`, `init.cpp:1037,2257`) | no private-broadcast connection type; own txs go to every peer | b | the operator believes their own transactions do not originate from this node's ordinary peer set — finding `3be511c4` |
| `-rpcdoccheck` | `GetBoolArg(..., DEFAULT_RPC_DOC_CHECK)` → non-fatal error on bad RPC docs (`rpc/util.cpp:662`) | not supported | a | a developer self-check on Core's own documentation strings |
| `-rpcworkqueue` | `GetArg(..., DEFAULT_HTTP_WORKQUEUE=64)` → `g_max_queue_depth` (`httpserver.cpp:419`) | no queue-depth knob; `-rpcthreads` caps concurrency (`src/rpc/server.lisp:1420-1424`) | a | a related bound IS configurable; the depth knob's absence changes queueing latency, not any protection |
| `-shrinkdebugfile` | `GetBoolArg(..., DefaultShrinkDebugFile())`, and that default is **false whenever any `-debug` category is set** (`init/common.cpp:110`, `logging.cpp:167-170`) | `start-file-logging` calls `shrink-log-file` unconditionally (`src/node/logging.lisp:146`) | c | a `-debug` restart discards all but the last 10 MB of the evidence — finding `e9d39df8` |
| `-signer` | `GetArg("-signer","")` → external signing command (`wallet/external_signer_scriptpubkeyman.cpp:49`) | no external-signer support | a | absent feature; `enumeratesigners`/`displayaddress` are simply not there, so it fails loudly at first use |
| `-signetseednode` | `GetArgs` (a LIST) → `options.seeds`, which REPLACES `vSeeds` (`chainparams.cpp:28`, `kernel/chainparams.cpp:471`) | dropped; the `:signet` params hardcode the two public signet DNS seeds | c | a custom signet dials the PUBLIC signet instead of the seed node it was given — finding `7f6337e2` |
| `-stopafterblockimport` | `GetBoolArg(..., DEFAULT_STOPAFTERBLOCKIMPORT=false)` → shut down after `ImportBlocks` (`init.cpp:2031`) | `%import-external-block-files` runs and the node carries on (`src/node/init.lisp:1502`) | a | a scripted bootstrap ends with a node still running rather than exited — visible, no security or funds consequence |
| `-timeout` | `GetIntArg(..., DEFAULT_CONNECT_TIMEOUT=5000)` ms → `nConnectTimeout`, clamped up if ≤ 0 (`init.cpp:1062`) | `make-tcp-connection` has a hardcoded `:timeout 10` seconds and no caller overrides it (`src/networking/connection.lisp:238`) | a | our fixed 10 s is twice Core's default — more patient, not less; the loss is only that a Tor/high-latency operator cannot raise it |
| `-unsafesqlitesync` | `GetBoolArg` → SQLite `synchronous=OFF` (`wallet/db.cpp:156`) | we have no SQLite | a | names a database engine this tree does not use |
| `-version` | `GetBoolArg("-version", false)` → print version, exit 0 (`bitcoind.cpp:138`) | handled at the entry point before anything starts (`src/node/init.lisp:1744-1748`) | a | actually implemented; listed only so the parser accepts it |
| `-walletbroadcast` | `GetBoolArg(..., DEFAULT_WALLETBROADCAST=true)` → `fBroadcastTransactions`; false stops `CommitTransaction` before the mempool (`wallet/wallet.cpp:2341`) and the resend timer (`:2109`). Soft-set 0 by `-blocksonly` (`wallet/init.cpp:95`) | **fixed**: `bl:*wallet-broadcast*` gates Core's three sites (commit, resubmit, the resend pass) and `-blocksonly=1` soft-sets it 0 | fixed | finding `8c442ee3` |

## The reverse defect: real options whose semantics differ from Core's reader

Checked; **already correct**, and re-verified here rather than assumed:

- `-maxuploadtarget` — `:byte-units`, so a bare number is MEBIbytes like Core's `ParseByteUnits`
  default. Executed: `apply-option-globals` with `maxuploadtarget=500` set
  `bl.net:*max-upload-target*` to 524288000 = 500 × 1024².
- `-par` — 0 means one worker per core and a NEGATIVE value leaves that many cores free
  (`src/config-options.lisp:399-408`), not an absolute value.
- `-listen` / `-listenonion` / `-bind` / `-whitebind` / `-connect` / `-proxy` — the whole soft-set
  chain is centralised in `conf-effective-listen-flags` (`src/config/values.lisp:283-345`) in Core's
  first-wins order, so `-bind` beats `-connect` beats `-proxy`, and both of Core's surviving
  contradictions are init errors.
- `-dnsseed` — soft-set 0 by `-connect`, by `-maxconnections<=0` and by a clearnet-free `-onlynet`;
  `-forcednsseed` against the EFFECTIVE `-dnsseed` is an init error (`src/node/args.lisp:171-270`).
- `-prune` — all four Core conflicts present: `-txindex`, `-txospenderindex`, `-reindex-chainstate`
  and the 550 MiB floor (`src/node/init.lisp:291-306`).
- `NETWORK_ONLY` (8 options) and `SENSITIVE` (exactly 4) tagging matches Core's registrations.
- Every row documented as "read by name in `START-NODE-FROM-ARGS`" (`-rpccookiefile`,
  `-rpcthreads`, `-mintxfee`, `-maxapsfee`, `-keypool`, `-walletnotify`, …) does have a reader in
  `src/node/rpc-config.lisp` — none is registered-but-never-read.

**One defect found**, and it is finding `7f6337e2` (**fixed**): `-signetchallenge` is a real option
whose Core reader rewrites four DERIVED chain parameters and ours rewrote none. Executed —
`apply-option-globals` with a custom challenge under `*network* = :signet` leaves the magic
`#(10 3 207 64)`, the DNS seeds the two public signet ones, `minimum-chain-work` 12396326331576 and
the genesis hash all at the public signet's values, where Core derives `pchMessageStart` from
sha256d of the challenge, clears `vSeeds`, and zeroes `nMinimumChainWork` and `defaultAssumeValid`.

## Not covered here

- Whether `-checkaddrman` / `-checkblockindex` / `-checkmempool` would have caught a live invariant
  break → **dimension 9** (validation/chain second reader).
- `getnetworkinfo`'s `"localaddresses"` being the constant `#()` while
  `src/networking/netaddress.lisp:510-526` maintains a real `*local-addresses*` map written by the
  torcontrol client → **dimension 8** (rpc/util).
- The aggregate inbound memory bound across all peers (the thing `-maxreceivebuffer` bounds per-peer
  in Core) → **dimension 10** (protocol/peer second reader).

The six rows marked `fixed` above were closed by the GA11 options-wiring S2 batch
(findings `7f6337e2`, `212b060f`, `8c442ee3`, `9e7729b8`, `ebb73768`); every other row here is
unchanged.
