# 11th gap analysis — bitcoin-lisp vs Bitcoin Core (refs/bitcoin @ d3056bc)

Dates: survey 2026-09-05, verification 2026-09-05 to 2026-09-06, fixes 2026-09-05 to
2026-09-07. Baseline: `main` @ `f5fc0da`, immediately after the GA10 fixes and the four
follow-up batches that closed them. Oracle: Bitcoin Core @ `d3056bc`, the same revision
GA7 to GA10 used. Plan and method: `docs/gap-analysis-11-plan.md`. Data:
`docs/gap-analysis-11-data/` (one survey file per dimension, one verdict file per
finding, `fixed-by.json` for the one finding fixed under a sibling's id).

## What this round did that GA10 could not

GA10 stopped at 84 candidates with 58 unverified and its refactor-regression dimension
never run. This round finished every stage:

- **Survey**: 10 dimensions, five agents at a time, 95 candidate findings with mechanical
  ids (`scripts/gap-analysis/check-ids.py`; 33 ids that did not reproduce were recomputed
  and the verdict files renamed before verification began). The refactor-regression
  dimension GA10 owed ran as the `never-opened` dimension.
- **Verification**: every finding judged by execution, refute-biased, two lenses for S1/S2
  and one for S3. 95 of 95 confirmed; severities moved in both directions (two S3s raised
  to S2, two S2s lowered to S3, several narrowed, one mechanism corrected).
- **Fixes**: 94 of 95 landed on `main` (the 95th, `-logips`, is in flight), in 24 worktree
  batches of one to eight findings grouped by file, each with a reproduction, a test that
  fails on the pre-fix source, the Core lines in the commit, and a green cold battery on the
  merged `main` before every push. The battery grew from 35,999 checks at the first push
  to 37,850 at the latest.

## The six S1s

| finding | what was wrong | fix |
|---|---|---|
| `2a636776` cluster mempool | every removal invalidated the whole mining chunk index, so at the default `-maxmempool` a full pool re-sorted 300k+ entries once per evicted chunk and the node could not keep up | the chunk index is maintained incrementally, as Core's `m_main_chunkindex` |
| `dd92141d` wallet | `encryptwallet` compacted LevelDB after deleting the plaintext keys, but a compaction is not a vacuum: the master private key survived on disk next to a live `walletdescriptor` naming its xpub | the database is rebuilt into a fresh file instead of compacted |
| `bbf6e679` storage | a crashed `-reindex-chainstate` left an empty coins database whose best-block pointer still named the old tip, so the node restarted "clean" at the old height with zero UTXOs | an emptied coins database names no block; plus Core's `LoadBlockIndex` reconcile and `VerifyDB` at startup and behind `verifychain` |
| `95cd2402` signing | `compute-input-signatures` had no `TxoutType::PUBKEY` case, so a wallet whose only coin was a bare P2PK output reported it spendable and could not spend it by any path | Core's first `SignStep` case |
| `1141db2b` miniscript | a `tr()` descriptor with a miniscript leaf handed out addresses and booked the coins, but the leaf satisfier could not spend them even with every private key | a `tr()` leaf is satisfied from its script, the way Core signs one |
| `c7fe77bf` miniscript | an inferred `pk_h` node carried no key, so a `wsh()` policy with a `pkh()` branch was never signed while the wallet still issued its addresses | a `pkh()` branch resolves its key through the provider |

## Defects the fixes surfaced that no finding named

Each was found while fixing a listed finding, fixed in its own commit, and is recorded
here because it has no id in the survey:

- **Funds: `v:` dropped its VERIFY flag under `and_v` and `s:`.** `ToScript` propagated
  the flag at one of Core's three sites, so `wsh(and_v(v:and_v(v:pk(A),pk(B)),older(10)))`
  was sane, importable, and issued an address whose script ends in `CHECKSIG` where Core's
  ends in `CHECKSIGVERIFY`. Same length, so every size check agreed with the wrong bytes.
  Surfaced by the miniscript tree-walker port; fixed the same day.
- **113 of 1,222 Core script vectors had never executed.** The corpus runner tested
  `(listp (first (first test)))` on witness vectors whose items are strings, read every
  witness vector one field left, and reported PASS. Turning them on found the BIP143 test
  sighash wrong twice and one Core evaluation-order rule (`CLEANSTACK` before
  `EVAL_FALSE`) unported.
- **A witnessless prefilled compact-block transaction went out with the `0x0001`
  marker**, which Core refuses as a superfluous witness record. Found when the stricter
  `DecodeTx` reader was ported.
- **`fee_estimates.dat` was loaded before the estimator existed**, so the persisted policy
  section was discarded on every start; the seam test was green because it bound the
  special first.
- **The 201-op limit was applied to tapscript miniscript**, refusing policies Core accepts
  and our own interpreter would run.
- **A `storage-condition` escaped every RPC boundary** (`CONTROL-STACK-EXHAUSTED` is not an
  `error`), killing the worker; reachable once the miniscript parser became linear.
- **The blockfilterindex shares the txospenderindex's off-chain-marker shape** and had no
  startup rewind; **P2SH(P2PK) was unsignable** (the scripthash arm had no P2PK redeem
  case). Both are in the follow-ups batch.
- Smaller ones, each fixed in place: an `undefined variable` pair the cold gate only saw
  on a real recompile; submitpackage's effective fee rate rendered as a rational; the
  `:: ` ratchet counting two git-ignored scratch files; two flaky tests whose deadlines
  went negative inside the first minute of an image.

## Harness lanes

- **Core error names in the script corpus** (done): `SE-VerifyFailed` stood in for
  thirteen `SCRIPT_ERR_*` values. Every variant now names exactly one Core error, the
  corpus compares the expected name as Core's own runner does (453 mismatches before, 0
  after, empty allowlist), and a mempool rejection carries Core's `ScriptErrorString`.
- **Differential encode/decode harness against `bitcoin-tx` / `bitcoin-util`** (blocked):
  no Core binary can be built in this environment (`scripts/conformance-config.sh` records
  the same limit for the functional suite). Carried to GA12.
- **Core functional tests as verdicts**: run by the verifiers where a finding cited one;
  not a separate lane.

## Left out, deliberately, for GA12

Named in the commit that scoped each one out:

- Core's RPC arity check (`IsValidNumArgs`, -1 with the help text); extra arguments are
  still ignored.
- `IsCurrentForFeeEstimation`'s third arm (best header height) — our best-header lookup is
  a linear scan and the check runs per accepted transaction.
- `UNKNOWN_NEW_RULES_ACTIVATED` needs a `WarningBitsConditionChecker` inside the BIP9 state
  machine.
- Erlay: `recon-set-remove` has no caller in `src/`, `recon-set-add` has no cap, and the
  responder's failure path abandons a round it never has.
- `ms-produce-input` indexes its satisfaction lists with `nth`; `ms-node-to-string` is
  quadratic at the tapscript ceiling, as Core's is.
- The wallet dump restore (`%parse-wallet-dump`) still buffers the file; the older wallet
  stream codec (`%wser-string`) is still ASCII.
- `ban-peer` has no production caller; `addnode` peers are typed outbound-full-relay, not
  manual, so they remain in the chain-sync eviction set.
- `-signetchallenge` given twice is accepted; `-conf` naming a directory is not Core's
  distinct error; `signrawtransactionwithkey` skips a malformed `prevtxs` entry silently.
- The differential harness above.

## What the round cost, and what it taught

Nine session-limit interruptions (five concurrent Opus agents exhaust a window in roughly
five hours); every killed agent was resumed in place and none lost work. Sixty-nine
lesson lines were recorded in the skills' lessons logs during the round; the ones that
repeated got mechanical guards instead of a second line: the `::` ratchet's corpus is the
ASDF-declared file list, `scripts/dev.sh test` quotes a bare suite designator and keeps a
large suite's summary line, `check-wrong-arity-calls.sh` fails the cold lane on a
wrong-arity call, and the structural suite refuses a fixture that delegates to itself.

The two lessons worth repeating in prose: a green test can be pinning a divergence from
Core (three tests were, and the faithful port turned them red), and a positive control
must be red for the right reason — several first controls died on a symbol the fix added
before reaching the behaviour they were meant to test.

## Tables

Generated by `scripts/gap-analysis/render-ga11.py --doc docs/gap-analysis-11.md`; do not
edit by hand. `survey` is the severity the finder assigned, `final` the verifier's; `fix`
names the commit(s) whose message carries the id.

<!-- render-ga11:begin -->
| dimension | S1 fixed/open | S2 fixed/open | S3 fixed/open |
|---|---|---|---|
| cluster-mempool | 1/0 | 2/0 | 2/0 |
| descriptors | 1/0 | 3/0 | 3/0 |
| miniscript | 2/0 | 3/0 | 5/0 |
| never-opened | 0/0 | 5/0 | 2/0 |
| options | 0/0 | 5/1 | 7/0 |
| p2p-liveness | 0/0 | 6/0 | 3/0 |
| rpc-util | 0/0 | 5/0 | 12/0 |
| tx-relay | 0/0 | 5/0 | 6/0 |
| validation-storage | 1/0 | 3/0 | 1/0 |
| wallet | 1/0 | 1/0 | 9/0 |

95 findings, 94 fixed, 1 open.

| dimension | finding | survey | final | verdict | fix |
|---|---|---|---|---|---|
| cluster-mempool | `2a636776` Every removal invalidates the whole mining chunk index, so eviction re-sorts ... | S1 | S1 | confirmed | `3055e3b0` Mempool: the mining chunk index is maintained incrementally |
| cluster-mempool | `7585dbb3` prioritisetransaction with an out-of-int64 fee_delta leaves the mempool entry... | S2 | S2 | confirmed | `0f5f52ac` Mempool: a prioritisation delta saturates instead of splitting the two fee views |
| cluster-mempool | `af013c51` RBF staging rebuilds every affected cluster edge by edge, relinearizing once ... | S2 | S2 | confirmed | `6266e7b1` Mempool: RBF staging copies the affected clusters instead of rebuilding them |
| cluster-mempool | `afcc1221` RBF descendant expansion runs before the rule-5 cluster cap meant to bound it | S3 | S3 | confirmed | `75204cef` Mempool: rule 5's cluster cap gates the RBF descendant expansion |
| cluster-mempool | `ed2f2295` txgraph sizes are sigop-adjusted vbytes where Core uses sigop-adjusted weight | S3 | S3 | confirmed | `07f8d429` tests: the chunk RPCs report Core's weight, so their fixture does; `952cbdf3` Mempool: the txgraph measures sigop-adjusted weight, as Core's does |
| descriptors | `95cd2402` compute-input-signatures has no TxoutType::PUBKEY case: bare P2PK coins are i... | S2 | S1 | confirmed | `8f5826f9` Wallet: a bare P2PK coin is signed, the way Core's SignStep does |
| descriptors | `232c293f` parse-descriptor rejects every BIP389 multipath descriptor, so getdescriptori... | S2 | S2 | confirmed | `4ea11df8` Descriptors: BIP389 multipath belongs to the parser, as it does in Core |
| descriptors | `c9da9f50` expand-multipath-descriptor refuses a multipath specifier in more than one ke... | S2 | S2 | confirmed | `4ea11df8` Descriptors: BIP389 multipath belongs to the parser, as it does in Core |
| descriptors | `f29c6fe6` %desc-key-pubkey-at-cached has no musig() branch: the wallet Expand path type... | S2 | S2 | confirmed | `1c46aea0` Descriptors: the wallet expansion path knows musig(), and cannot TYPE-ERROR |
| descriptors | `42a8a239` %collect-multisig-sig-pairs stops at the threshold, so a PSBT records at most... | S3 | S3 | confirmed | `e8d67d77` Signing: a multisig input is signed for every key held, and m are pushed (42a8a239) |
| descriptors | `8f138c13` scriptpubkey-desc never infers pk()/multi()/rawtr(); the RPC desc field says ... | S3 | S3 | confirmed | `6f60c6c5` Descriptors: InferScript answers pk(), multi() and rawtr() before addr() |
| descriptors | `bfcaa33f` %match-multisig accepts only OP_1..OP_16 for m and n; Core's GetScriptNumber ... | S3 | S3 | confirmed | `8126ace3` Solver: the bare-multisig counts read through Core's GetScriptNumber |
| miniscript | `1141db2b` tr() miniscript leaves are accepted and given an address but tr-leaf-satisfac... | S2 | S1 | confirmed | `c672ca36` Wallet: a tr() leaf is satisfied from its script, the way Core signs one |
| miniscript | `c7fe77bf` An inferred pk_h node carries no key, so a P2WSH miniscript with a pkh() bran... | S2 | S1 | confirmed | `9fe8b8b9` Wallet: a pkh() branch resolves its key, so a wsh() policy holding it spends |
| miniscript | `05af23cd` A miniscript descriptor's node reports script size 0, so IsValid's MaxScriptS... | S2 | S2 | confirmed | `fb994c79` Miniscript: a node's script size comes from its shape, not from generating it |
| miniscript | `780c1251` ms-parse never checks fragment arity: extra arguments are silently dropped an... | S2 | S2 | confirmed | `6f06883c` Miniscript: the parser follows Core's ParseContext schedule, so arity is checked |
| miniscript | `d722b087` Miniscript parsing and inference are cubic in input size and have no incremen... | S2 | S2 | confirmed | `6f06883c` Miniscript: the parser follows Core's ParseContext schedule, so arity is checked; `fb994c79` Miniscript: a node's script size comes from its shape, not from generating it |
| miniscript | `3ded15f3` No unsafe-older() descriptor warning: an older(k) above 65535 blocks is impor... | S3 | S3 | confirmed | `c5d3010f` Descriptors: an unsafe older() is reported, the way Core reports it (3ded15f3) |
| miniscript | `4b671f54` Script decomposition accepts non-minimal pushes and non-minimal script number... | S3 | S3 | confirmed | `d240c5e2` Script: CheckMinimalPush is one helper, and miniscript decomposition runs it |
| miniscript | `8c3b8174` ms-from-script has no tapscript arms: no x-only key push and no multi_a decoding | S3 | S3 | confirmed | `cc6c6eff` Miniscript: the decoder reads a tapscript leaf, keys and multi_a included |
| miniscript | `c9076fba` ms-produce-input has no multi_a case, so satisfying any multi_a node is an EC... | S3 | S3 | confirmed | `595499cd` Miniscript: multi_a satisfaction, transcribed rather than copied from multi |
| miniscript | `e8dfc12f` Numeric arguments accept a leading plus sign and surrounding whitespace that ... | S3 | S3 | confirmed | `431192a4` Miniscript: a numeric argument is ToIntegral's text, not PARSE-INTEGER's |
| never-opened | `1052063f` VERSION user agent has neither Core's 256-byte cap nor SanitizeString, so a p... | S2 | S2 | confirmed | `bff324e1` Net: the peer subversion is capped at 256 bytes and sanitized at the boundary |
| never-opened | `4a05974e` P2P nonces, addrman selection and relay jitter all draw from one MT19937 stre... | S2 | S2 | confirmed | `4a883ec0` Net: every nonce we publish is drawn from the OS CSPRNG, not the MT stream |
| never-opened | `6c83742d` Eviction netgroup secret is drawn at load time and frozen into the saved exec... | S1 | S2 | confirmed | `7962962b` Node: the eviction netgroup key is drawn per process from the OS CSPRNG |
| never-opened | `be1b5ed4` txospenderindex has no startup rewind, so a marker off the active chain leave... | S3 | S2 | confirmed | `8a41705b` Index: the spender marker's height says what it is for; `0ea4aa25` Index: the spender index rewinds an off-chain marker at start-up |
| never-opened | `c537a699` -blocknotify fires on every connected block including IBD and reindex | S2 | S2 | confirmed | `c509751e` Node: -blocknotify runs only once the node is past initial block download |
| never-opened | `2cae91f5` define-message :var-string is Latin-1, not bytes: a wallet label above U+00FF... | S3 | S3 | confirmed | `736e0e17` Serialization: a serialized string is UTF-8 bytes, not one byte per code point (GA11 2cae91f5) |
| never-opened | `d9ca7c2f` A boolean wire field is true only for the byte 1; Core treats every nonzero b... | S3 | S3 | confirmed | `4ae9377e` Serialization: a wire boolean is true for every nonzero byte (GA11 d9ca7c2f) |
| options | `212b060f` -persistmempool / -persistmempoolv1 are dropped: mempool.dat is always loaded... | S2 | S2 | confirmed | `4c9e528a` Node: -persistmempool gates both mempool.dat drive sites (212b060f) |
| options | `559c86ad` -logips is dropped and peer addresses are logged unconditionally at info/warn... | S3 | S2 | confirmed | open |
| options | `7f6337e2` -signetseednode is dropped and -signetchallenge rewrites none of Core's deriv... | S2 | S2 | confirmed | `39b58ad8` Config: a custom signet is its own network, derived from its challenge (7f6337e2) |
| options | `8c442ee3` -walletbroadcast is dropped and -blocksonly does not soft-set it: the wallet ... | S2 | S2 | confirmed | `7f4f8fd6` Wallet: -walletbroadcast keeps a signed transaction off the wire (8c442ee3) |
| options | `9e7729b8` A bitcoin.conf in the datadir shadowed by -conf or by a conf-set datadir= is ... | S2 | S2 | confirmed | `8969900b` Config: the bitcoin.conf we do not read is an error, not a silence (9e7729b8) |
| options | `ebb73768` -blocksdir is dropped: blocks always go to <datadir>/blocks, filling the data... | S2 | S2 | confirmed | `8d09ece5` Storage: -blocksdir puts the block bulk on the volume it names (ebb73768) |
| options | `1f1f28b7` -dns is dropped: a named -addnode/-connect/-seednode target is still resolved... | S3 | S3 | confirmed | `49e0ab73` Net: -dns=0 keeps a named dial off the local resolver (1f1f28b7) |
| options | `21cf40de` -checkblocks / -checklevel are dropped: no startup VerifyDB runs at all, and ... | S2 | S3 | confirmed | `05111c8b` Validation: Core's VerifyDB, at startup and behind verifychain (GA11 4452772a) |
| options | `3be511c4` -privatebroadcast is dropped: own-transaction broadcast over dedicated privat... | S3 | S3 | confirmed | `c12ab862` Config: -privatebroadcast is refused, the way Core refuses it (3be511c4) |
| options | `4d28b231` -addresstype / -changetype are dropped: getnewaddress and getrawchangeaddress... | S3 | S3 | confirmed | `176ba8f9` Wallet: -addresstype and -changetype are the wallet's defaults (4d28b231) |
| options | `c053f780` -alertnotify is accepted and dropped, and the whole kernel warning system beh... | S2 | S3 | confirmed | `a578388a` Node: the warnings an operator is paged about exist, and -alertnotify fires (c053f780) |
| options | `e9d39df8` -shrinkdebugfile is dropped and the log is scrolled unconditionally, includin... | S3 | S3 | confirmed | `3069ca2f` Node: -shrinkdebugfile keeps the log a -debug restart was started to fill (e9d39df8) |
| options | `feecc533` -avoidpartialspends is dropped: the coin-control default never reads it, so a... | S3 | S3 | confirmed | `4f7a1ec9` Wallet: -avoidpartialspends is where a coin control starts (feecc533) |
| p2p-liveness | `33c6687d` The outbound full-relay refill dials a start-up snapshot of addrman in fixed ... | S2 | S2 | confirmed | `710d63dd` Net: the outbound refill draws from addrman on every try (33c6687d) |
| p2p-liveness | `4e23abcd` record-misbehavior has no manual-connection exemption, so an -addnode peer is... | S3 | S2 | confirmed | `e65e3b1f` Net: a manually connected peer is never punished (4e23abcd) |
| p2p-liveness | `50dc142d` Any error raised by a message handler disconnects the peer; Core catches ever... | S2 | S2 | confirmed | `15c7b6dc` Net: a handler's error is forgiven, the way ProcessMessages forgives it (50dc142d) |
| p2p-liveness | `853e20f5` record-misbehavior and ban-peer retire a peer without the disconnect hook, or... | S3 | S2 | confirmed | `ffd7e2f1` Net: every retirement path ends in the one finalize step (853e20f5) |
| p2p-liveness | `d2396ac9` One stall round disconnects a peer: the per-peer block-timeout budget is spen... | S2 | S2 | confirmed | `f8967ad5` Net: block-download eviction is Core's two rules, not the per-hash retry (d2396ac9) |
| p2p-liveness | `d49c3f1b` Height-based eviction has no Core counterpart and applies to inbound and manu... | S2 | S2 | confirmed | `16df4a3d` Net: the height-based peer eviction that Core does not have is gone (d49c3f1b) |
| p2p-liveness | `1b4b73fe` Core's InactivityCheck is absent and -peertimeout is bound to the handshake t... | S3 | S3 | confirmed | `198b4af5` Net: -peertimeout gates every liveness verdict, as Core's does (1b4b73fe) |
| p2p-liveness | `3cad28cc` A partially-received message is reaped after 300s; Core has no per-message st... | S3 | S3 | confirmed | `8d821e14` Net: the half-read-message reaper waits Core's twenty minutes (3cad28cc) |
| p2p-liveness | `4db38801` The 'connection dead' warning is a reap of an already-dead socket, not a live... | S3 | S3 | confirmed | `382e9ca4` Net: the reap says why the connection died, at Core's level (4db38801) |
| rpc-util | `2453fab8` decoderawtransaction accepts trailing bytes and has no legacy/witness disambi... | S2 | S2 | confirmed | `825d28f8` Serialization: one transaction hex is read both ways, as Core's DecodeTx is |
| rpc-util | `95edd4e7` decodescript returns the pre-v22 shape and offers p2sh/segwit wrappers Core r... | S2 | S2 | confirmed | `69fec15e` RPC: decodescript is Core's object, and wraps only what Core wraps |
| rpc-util | `c9835924` estimatesmartfee falls back to a block-percentile estimate where Core reports... | S2 | S2 | confirmed | `9bccf17a` Mempool: the fee estimator learns from what Core lets it, and answers only that |
| rpc-util | `dd5787ca` Fee estimator tracks every mempool entry: none of Core's validForFeeEstimatio... | S2 | S2 | confirmed | `9bccf17a` Mempool: the fee estimator learns from what Core lets it, and answers only that |
| rpc-util | `fa699133` createrawtransaction ignores replaceable and version and defaults sequence to... | S2 | S2 | confirmed | `f71bd636` RPC: createrawtransaction is Core's ConstructTransaction, all five arguments |
| rpc-util | `54578659` Amounts render as JSON doubles instead of Core's ValueFromAmount fixed 8-deci... | S3 | S3 | confirmed | `338a0bd4` RPC: an amount is Core's number token, not a float printer's guess |
| rpc-util | `63b42740` estimaterawfee omits decay and scale and reports feerate 0 where Core omits f... | S3 | S3 | confirmed | `ab3ae8ee` RPC: estimaterawfee reports Core's two horizon objects, decay and scale first |
| rpc-util | `67602eb4` createrawtransaction rejects an empty inputs array that Core accepts | S2 | S3 | confirmed | `f71bd636` RPC: createrawtransaction is Core's ConstructTransaction, all five arguments |
| rpc-util | `ac99774f` amount-from-value's string path is not ParseFixedPoint: leading zeros accepte... | S3 | S3 | confirmed | `e6d3ca4a` RPC: amounts parse through Core's ParseFixedPoint, text and all |
| rpc-util | `adfc52aa` No ParseHashV/ParseHexV: every hash-argument error is ad hoc, and getchaintxs... | S3 | S3 | confirmed | `87379458` RPC: one ParseHashV answers every hash argument, in Core's words |
| rpc-util | `b276a1e0` Verbosity-3 prevout scriptPubKey omits the desc field Core's ScriptToUniv alw... | S3 | S3 | confirmed | `8388f73b` tests: the prevout scriptPubKey is the same object as the vout's |
| rpc-util | `bc10de29` getdeploymentinfo never emits the bip9 signalling string | S3 | S3 | confirmed | `ef93e9f3` RPC: getdeploymentinfo says which blocks of the period signalled (GA11 bc10de29) |
| rpc-util | `be96017b` No RPCHelpMan type gate: wrong-typed arguments never produce -3 Wrong type pa... | S3 | S3 | confirmed | `4ab5331a` RPC: every call runs Core's declared-argument type gate first |
| rpc-util | `c1649d3d` Script ASM renders small pushes as hex and OP_0/OP_1..16/OP_1NEGATE as opcode... | S2 | S3 | confirmed | `464e7b2c` Script: the asm field is Core's ScriptToAsmStr, not our own rendering |
| rpc-util | `ce1283b3` createrawtransaction sequence out of range escapes as a Lisp TYPE-ERROR repor... | S3 | S3 | confirmed | `14e21d27` tests: createrawtransaction's sequence range is Core's, and stays pinned |
| rpc-util | `d426a155` Data must be hexadecimal string omits Core's (not '<value>') suffix | S3 | S3 | confirmed | `87379458` RPC: one ParseHashV answers every hash argument, in Core's words |
| rpc-util | `ef28c178` getdeploymentinfo reports threshold and possible in LOCKED_IN where Core omit... | S3 | S3 | confirmed | `cc171719` Validation: a locked-in deployment reports no threshold and no possible (GA11 ef28c178) |
| tx-relay | `27695ef5` Every notfound message re-runs a full scan of the global tx-request tracker u... | S2 | S2 | confirmed | `1bd9b208` Net: a notfound costs its own item count, and drains a bucket (27695ef5) |
| tx-relay | `87e5fccf` tx messages are fully validated, admitted to the mempool and relayed during i... | S2 | S2 | confirmed | `0977ee3b` Net: a tx message is dropped while the node is in IBD (87e5fccf) |
| tx-relay | `931a5184` A failed announcement is deleted rather than kept COMPLETED, so one peer can ... | S2 | S2 | confirmed | `bd94e192` Net: a failed tx announcement is completed, not deleted (931a5184) |
| tx-relay | `c65becf1` Request candidate selection is deterministic (preferred, then earliest ready)... | S2 | S2 | confirmed | `02b3e7bc` Net: the request candidate is a salted hash, not the announcement order (c65becf1) |
| tx-relay | `dd85e71f` Receiving any transaction forgets EVERY peer's announcement of its hash, not ... | S2 | S2 | confirmed | `52be5670` Net: orphan intake enrols every announcer, and filters the parents (1dc189a8); `abf4c4b6` Net: a delivered transaction completes one announcement, not the txhash (dd85e71f) |
| tx-relay | `1dc189a8` Orphan intake registers only the delivering peer for parent resolution, and i... | S3 | S3 | confirmed | `52be5670` Net: orphan intake enrols every announcer, and filters the parents (1dc189a8) |
| tx-relay | `2686f00d` Reconciliation sets never shed the entries both sides already had, so a recon... | S3 | S3 | confirmed | `b6bc9d99` Erlay: a successful round retires the whole snapshot, not just the difference (2686f00d) |
| tx-relay | `2be715a4` An inv never enters the announcing peer's known-tx filter, so we announce the... | S3 | S3 | confirmed | `8b94b21a` Net: an inv marks the transaction known to the peer that sent it (2be715a4) |
| tx-relay | `490e6e59` Trickled announcements are flushed in FIFO order; Core sends them fee-rate first | S3 | S3 | confirmed | `83ccd9e6` Net: the announcement queue is Core's -- no truncation, an accelerating drain, mempool order (98f80da8, 490e6e59) |
| tx-relay | `98f80da8` The per-peer tx announcement queue silently drops its OLDEST entries at 5000,... | S3 | S3 | confirmed | `83ccd9e6` Net: the announcement queue is Core's -- no truncation, an accelerating drain, mempool order (98f80da8, 490e6e59) |
| tx-relay | `9e4e0a16` Connecting a block leaves the confirmed transactions in the tx-request tracke... | S3 | S3 | confirmed | `44994f01` Net: a connected block forgets the tracked announcements it confirms (9e4e0a16) |
| validation-storage | `bbf6e679` coins-view-cache-wipe keeps the coins DB best-block pointer, so a crashed -re... | S1 | S1 | confirmed | `fa179567` Tests: the suites that start a real node run before the battery's build-up; `3f72f556` Tests: a node started in a test must give back the fail-fast debugger hook; `e634c1ae` Storage: the header-index delta binds to its FILES, not to a chainstate (GA11 dc27ca3a); `05111c8b` Validation: Core's VerifyDB, at startup and behind verifychain (GA11 4452772a); `27d9aa70` Storage: an emptied coins database names no block (GA11 bbf6e679) |
| validation-storage | `4452772a` VerifyDB never runs at startup and verifychain implements only Core's levels 0-1 | S2 | S2 | confirmed | `2254f4e8` docs: the option survey and the manual follow the S3 wiring batch; `fa179567` Tests: the suites that start a real node run before the battery's build-up; `3f72f556` Tests: a node started in a test must give back the fail-fast debugger hook; `e3ddb12b` Docs: close the VerifyDB manual entry's quoted Core message (GA11 4452772a); `05111c8b` Validation: Core's VerifyDB, at startup and behind verifychain (GA11 4452772a) |
| validation-storage | `b07c72f4` Header-index delta replay leaves two objects per refreshed block, and the act... | S2 | S2 | confirmed | `595a8859` Storage: delta replay keeps one object per block hash (GA11 b07c72f4) |
| validation-storage | `dc27ca3a` A snapshot chainstate's header-index delta is bound to a stale snapshot CRC, ... | S2 | S2 | confirmed | `e634c1ae` Storage: the header-index delta binds to its FILES, not to a chainstate (GA11 dc27ca3a) |
| validation-storage | `ce759c52` Every periodic flush empties the whole coins cache; Core only Syncs on the ti... | S3 | S3 | confirmed | `3697c262` Validation: only a size-tier or forced flush empties the coins cache |
| wallet | `dd92141d` encryptwallet's post-encryption leveldb-compact does not remove the deleted p... | S1 | S1 | confirmed | `c02e6763` Wallet: encryptwallet rebuilds the database instead of compacting it |
| wallet | `4e92ca22` A tx record that fails to parse is skipped with a warning instead of Core's N... | S2 | S2 | confirmed | `5b43b817` Wallet: a tx record that will not load is Core's NEED_RESCAN |
| wallet | `2ea896f4` Extraneous mkey records are not removed from a disable_private_keys wallet on... | S3 | S3 | confirmed | `e3632168` Wallet: extraneous encryption keys leave a watch-only wallet on load |
| wallet | `5b7d945a` A wallet database that cannot be opened or read answers -32603 Internal error | S3 | S3 | confirmed | `e301fcb9` Wallet: a database that cannot be read answers Core's DatabaseStatus |
| wallet | `652d565b` blockDisconnected updates the best block in memory only; Core persists the ro... | S3 | S3 | confirmed | `d1c35b7c` Wallet: a disconnect writes the rolled-back best block, as Core's does (652d565b) |
| wallet | `69862ba9` A corrupt walletdescriptor record surfaces the descriptor parser's message, n... | S3 | S3 | confirmed | `a1cef7e7` Wallet: a walletdescriptor record that will not read is one class, as in Core; `fd85ad18` Wallet: the version record is read, logged and restamped, as Core does |
| wallet | `71d5aa9f` importprunedfunds and removeprunedfunds are not implemented | S3 | S3 | confirmed | `8f96ae26` Wallet: a pruned node can import and remove a transaction record (71d5aa9f) |
| wallet | `7aea0d09` signmessage validates the address before requiring the passphrase; Core unloc... | S3 | S3 | confirmed | `743feb32` Wallet: signmessage asks for the passphrase before it reads the address (7aea0d09) |
| wallet | `b314f13a` The version record is written once at creation and never read or refreshed; m... | S3 | S3 | confirmed | `a1cef7e7` Wallet: a walletdescriptor record that will not read is one class, as in Core; `fd85ad18` Wallet: the version record is read, logged and restamped, as Core does |
| wallet | `c7a9a092` listsinceblock parses its blockhash with the txid helper, so a bad hash repor... | S3 | S3 | confirmed | `87379458` RPC: one ParseHashV answers every hash argument, in Core's words |
| wallet | `e05d644b` The whole wallet database is materialized in memory on every load and backup | S3 | S3 | confirmed | `316fdc57` Wallet: the record scan is a driver, so a load or a backup holds one record |
<!-- render-ga11:end -->
