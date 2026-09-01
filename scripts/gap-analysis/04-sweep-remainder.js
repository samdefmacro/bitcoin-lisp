export const meta = {
  name: 'ga10-finish',
  description: 'Finish GA10: 3 refactor claims, re-check 26 single-vote, sweep 38 S3',
  phases: [
    { title: 'Refactor', detail: '3 refactor-regression claims' },
    { title: 'Recheck 26', detail: 'round-1 confirmed that rested on a single vote' },
    { title: 'S3 sweep', detail: '38 findings with no verdict at all' },
  ],
}

const REPO = '/Users/sen/common-lisp/bitcoin-lisp'
const F = '/private/tmp/claude-501/-Users-sen-common-lisp-bitcoin-lisp/be9485ca-5f21-407c-89c0-198cdf66317b/scratchpad/r4.json'
const RF = '/private/tmp/claude-501/-Users-sen-common-lisp-bitcoin-lisp/be9485ca-5f21-407c-89c0-198cdf66317b/scratchpad/refactor.txt'

const CONF=[["2f0cf648", "S2", "Outbound netgroup-diversity set is built from ALL peers including inbound, so free inbou"], ["d9aadbc5", "S2", "IsBadPort is absent: automatic outbound dials will connect to any gossiped port (SMTP, S"], ["a4680ae1", "S2", "Gossiped addresses are relayed immediately, one addr message per address \u2014 no m_addrs_to"], ["abae237b", "S2", "Eviction's disadvantaged-network reserve protects the NEWEST connections instead of the "], ["42dacfaf", "S2", "Every dial counts an addrman failure \u2014 Core suppresses failure counting when the node lo"], ["606ac3e5", "S3", "address-book-add is missing Core's \"do not update if no new information is present\" gate"], ["ff51e9d5", "S3", "Inbound admission ban/discourage checks have no NoBan permission exemption"], ["801f2ad3", "S2", "-rpcpassword / -rpcauth / -rpcuser / -torpassword are written to debug.log in cleartext;"], ["d4f123e8", "S2", "A negated repeatable option (-noX) is appended to the list as the literal string \"0\" ins"], ["d2099b36", "S2", "The \"-peerblockfilters without -blockfilterindex\" refusal is nested inside (when prune ."], ["87801e86", "S2", "Network-only options (-port, -rpcport, -bind, -connect, -addnode, -wallet, -walletdir) a"], ["3911beba", "S3", "-bind / -whitebind together with an explicit -listen=0 is accepted; Core makes it a hard"], ["105290bf", "S3", "Dotted section keys in bitcoin.conf (main.rpcport=..., test.connect=...) are treated as "], ["631b90f9", "S3", "-forcednsseed=1 with -dnsseed=0 (or with -connect) is silently ignored instead of being "], ["32758a48", "S3", "A negative -maxconnections is accepted and clamped instead of being an init error"], ["e2db2089", "S2", "-rpcwhitelist / -rpcwhitelistdefault are accepted at startup but never enforced, so a us"], ["feac3eb3", "S2", "/rest/spenttxouts serializes the on-disk compressed CBlockUndo codec instead of Core's R"], ["2834e5b3", "S3", "JSON-RPC batch members never get the named-argument transform, so any batch call using n"], ["cc698623", "S3", "No REST endpoint checks RPC warmup, so /rest/* serves a half-initialized node during sta"], ["24e0c216", "S3", "/rest/block/<hash>.json renders getblock verbosity 2; Core renders verbosity 3 (SHOW_DET"], ["0a061de4", "S3", "getrawmempool ignores its second argument mempool_sequence, which our own argument table"], ["0e7ec2f3", "S3", "/rest/mempool/contents.json ignores the ?verbose= and ?mempool_sequence= query parameter"], ["b219c779", "S3", "getrawtransaction consults the mempool even when an explicit blockhash is given, and nev"], ["2279d91b", "S1", "coins-view-cache-sync clears DIRTY but leaves FRESH set, so coins already written to Lev"], ["7f01522e", "S2", "%scan-flat-block-files stops at the first missing blk file, so a pruned node loses its e"], ["c831e584", "S2", "The RPC coins sync advances the persisted coins best-block pointer without persisting th"]];
const S3=[["6dcf6d71", "Block-relay-only eviction protection ignores fRelevantServices, so a non-tx-relay peer w"], ["fdbe8a5e", "The prune window's lower bound is our walk cursor rather than Core's 0, so the first blk"], ["d73be57b", "Rolling minimum fee decays with no block since the bump, and block connection never rese"], ["994f223b", "The relay-finality check runs after the duplicate and missing-input checks, so a non-fin"], ["0c63c99c", "CheckTxInputs (coinbase maturity, fee/value consensus) runs after the standardness-of-in"], ["54fdda5c", "Duplicate-in-mempool check is txid-only: Core's \"txn-same-nonwitness-data-in-mempool\" ca"], ["6635e4c9", "Package consistency check adds inputs one at a time, misreporting a transaction with dup"], ["88f3a071", "Block-conflict removal does not clear the conflicted transaction's prioritisation delta"], ["9f54cae8", "%reorg-commit fires tx-relay and wallet side effects without connect-block's background-"], ["83599047", "Block templates never signal any BIP9 deployment: nVersion is the hardcoded constant 0x2"], ["a6afe2d6", "generateblock builds its own coinbase and re-introduces the unconditional segwit witness"], ["a9ddbd92", "getnetworkhashps computes the wrong number: integer rounding drops sub-1 H/s results to "], ["56b53a04", "getnetworkhashps ignores its `height` argument entirely, does not implement nblocks = -1"], ["3f90b8bc", "getmininginfo reports currentblockweight/currentblocktx as 0 before any template has bee"], ["7b813f60", "generatetoaddress / generatetodescriptor raise an error when maxtries is exhausted inste"], ["57e206a8", "The BIP94 timewarp floor and check use the fixed 2016-block interval and a hardcoded tes"], ["98069fe2", "sendcmpct(0) never clears the recorded high-bandwidth-from flag"], ["df63423d", "Gossiped addresses are stored in addrman and relayed onward without the banned/discourag"], ["0c05f5d0", "Relayed addresses go out immediately, one addr message per address, instead of Core's pe"], ["5054e381", "wtxidrelay / sendaddrv2 received after VERACK are silently ignored where Core disconnect"], ["70502bf3", "A backed-up send buffer makes us DROP outbound messages; Core instead stops processing i"], ["fac08286", "Coinbase \"hash\" (wtxid) reported as 32 zero bytes by the RPC transaction serializer; Cor"], ["508fedab", "PSBT parser omits two of Core's global-map validity checks (out-of-range prevout index, "], ["8d88f6ac", "base58-decode has no length bound; Core's DecodeBase58 bails as soon as the decoded leng"], ["ba446c02", "Block script validation never consults the script-execution cache, so every mempool-veri"], ["ccac3137", "The intra-block coin overlay keeps provably-unspendable outputs that Core's AddCoin drop"], ["38bb5cc7", "CheckTxInputs' input-value MoneyRange guards and ConnectBlock's accumulated-fee guard ha"], ["81c98c4b", "enforce_BIP94 is hardcoded to testnet4; Core lets regtest turn it on with -test=bip94"], ["34a807d1", "ECDSA satisfaction sized at 72 bytes on a stated justification that is factually false \u2014"], ["d8cffd5c", "PSBT signing never checks that existing signatures use the requested sighash type"], ["97855c61", "PSBT \"complete\" and the already-signed test trust final/partial fields without verifying"], ["f506ca73", "No -walletcrosschain guard: a wallet whose locator belongs to another chain is loaded an"], ["b48227fc", "FindAndDelete is skipped for an EMPTY signature; Core's pattern for an empty sig is the "], ["272e30f0", "CONST_SCRIPTCODE's OP_CODESEPARATOR rule is applied only to the scriptPubKey and to a sc"], ["7db4b27f", "verify-checksig's inline FindAndDelete pattern omits the PUSHDATA prefix for signatures "], ["a7b67ad1", "OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY consult DISCOURAGE_UPGRADABLE_NOPS when "], ["d410b7bf", "script-is-push-only-p rejects OP_RESERVED (0x50); Core's IsPushOnly deliberately counts "], ["f5b31fb7", "OP_CHECKMULTISIG charges nKeysCount against the 201-op budget only after running the sig"]];

const COMMON = `Working directory: ${REPO}. Ours is src/, Bitcoin Core @ d3056bc is refs/bitcoin/src/.
The full text of each finding (title, our_ref, core_ref, core_does, we_do, impact) is in ${F},
a JSON file with a "confirmed" array and an "s3" array, each entry carrying an "id". READ THAT FILE
YOURSELF and look up only your assigned ids.

YOU CAN RUN CODE, and an executed answer outranks a read one:
  scripts/dev.sh eval '<lisp form>'    # ~0.3s, warm image, system already loaded
  scripts/dev.sh test :some-tests      # one fiveam suite
Do not modify any file. Never run a git command that writes.

YOUR JOB IS TO REFUTE each claim. Set refuted=true if it misreads either tree, if the behaviour is
handled elsewhere (this tree was heavily refactored recently -- a check may have MOVED, so grep
before concluding it is absent), if a comment documents it as a deliberate and correctly reasoned
divergence, or if the stated impact is not reachable. Default to refuted=true when you cannot
confirm it. Judge MECHANISM and CONSEQUENCE separately: a real divergence whose consequence does
not follow is a severity correction, not a confirmation. Do not use the Agent tool.

Return one verdict per assigned id, echoing the id exactly, with title_prefix so alignment can be
checked. If the entry at an id is not what you judged, say so in evidence instead of guessing.`

const VERDICTS = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title_prefix: { type: 'string' },
          refuted: { type: 'boolean' },
          corrected_severity: { type: 'string', enum: ['S1', 'S2', 'S3', 'unchanged'] },
          evidence: { type: 'string' },
          executed: { type: 'boolean' },
        },
        required: ['id', 'title_prefix', 'refuted', 'corrected_severity', 'evidence', 'executed'],
      },
    },
  },
  required: ['verdicts'],
}

const chunk = (xs, n) => xs.reduce((a, x, i) => (i % n ? a[a.length - 1].push(x) : a.push([x]), a), [])

phase('Refactor')
const REF = [
  'Finding 1: fsync-parent-directory is wired into only 3 of its 7 drive sites -- four rename-file paths (settings.json in src/node/datadir.lisp and src/wallet/wallet.lisp, mempool.dat in src/mempool/mempool.lisp, the wallet backup in src/wallet/wallet-crypt.lisp) still pass a FILE path to the DIRECTORY-taking fsync-directory, so the rename is never made durable. Check whether fsync-directory given a file path really fails to sync the directory, and whether those four sites really pass a file.',
  'Finding 2: bl:token-bucket and bl:make-token-bucket were exported from the top package but named nothing after the struct moved to bitcoin-lisp.ratelimit. This was FIXED in commit fb5cbb4. Confirm the claim was correct AND that the fix is complete: are there other exported-but-undefined symbols anywhere, and does the new every-export-names-something ratchet actually catch them? TRY TO MAKE THAT RATCHET FAIL.',
  'Finding 3: read the third finding in that report and judge it on its own terms.',
]
const refactor = await parallel(REF.map((what, i) => () => agent(
`${COMMON}

The refactor-regression finder's report is in ${RF} -- read it. Its oracle is our OWN pre-refactor
behaviour, not Core: use \`git log --oneline ee312af -80\` and \`git show <commit>:<path>\`.

ASSIGNMENT: ${what}

Return exactly one verdict with id "refactor-${i + 1}".`,
  { label: `refactor-${i + 1}`, phase: 'Refactor', schema: VERDICTS })))

phase('Recheck 26')
const recheck = await pipeline(
  chunk(CONF, 3),
  (grp) => agent(
`${COMMON}

These were marked "confirmed" in an earlier round, but that verdict rested on as little as a SINGLE
verifier -- the panel meant to judge them died mid-run. You are the independent re-check. Being
previously marked confirmed is NOT evidence; judge each from the code.

ASSIGNMENT -- the "confirmed" array in ${F}, ONLY these ids:
${grp.map((f) => `  ${f[0]}  [${f[1]}] ${f[2]}`).join('\n')}`,
    { label: `recheck:${grp.length}`, phase: 'Recheck 26', schema: VERDICTS }),
)

phase('S3 sweep')
const s3 = await pipeline(
  chunk(S3, 4),
  (grp) => agent(
`${COMMON}

These were filed S3 -- correctness nits, missing hardening, divergences with no practical
consequence -- and NO verifier has ever judged them. Confirm or refute each. An S3 whose
consequence turns out to be real should be UPGRADED; say so in corrected_severity.

ASSIGNMENT -- the "s3" array in ${F}, ONLY these ids:
${grp.map((f) => `  ${f[0]}  ${f[1]}`).join('\n')}`,
    { label: `s3:${grp.length}`, phase: 'S3 sweep', schema: VERDICTS }),
)

const all = [...refactor, ...recheck, ...s3].filter(Boolean).flatMap((r) => r.verdicts || [])
const conf = all.filter((v) => !v.refuted)
log(`Finished: ${all.length} verdicts -- ${conf.length} confirmed, ${all.length - conf.length} refuted, ${all.filter((v) => v.executed).length} settled by execution.`)
return { total_verdicts: all.length, confirmed: conf.length, refuted: all.length - conf.length, executed: all.filter((v) => v.executed).length, verdicts: all }
