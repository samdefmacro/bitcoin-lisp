export const meta = {
  name: 'gap-analysis-10',
  description: 'Gap analysis 10: bitcoin-lisp vs Bitcoin Core, 13 dimensions, adversarially verified',
  phases: [
    { title: 'Survey', detail: '13 dimension finders, each seeded with GA1-GA9 exclusions' },
    { title: 'Verify', detail: 'refute-biased panel per finding (3 lenses for S1/S2, 1 for S3)' },
    { title: 'Synthesize', detail: 'report + completeness critic' },
  ],
}

const REPO = '/Users/sen/common-lisp/bitcoin-lisp'
const CORE = 'refs/bitcoin (Bitcoin Core @ d3056bc, the same revision GA7-GA9 used)'

const EXCLUSIONS = `
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
`

const FINDING_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string', description: 'One line: what diverges from Core' },
          severity: { type: 'string', enum: ['S1', 'S2', 'S3'] },
          our_ref: { type: 'string', description: 'our file:line' },
          core_ref: { type: 'string', description: 'refs/bitcoin file:line' },
          core_does: { type: 'string' },
          we_do: { type: 'string' },
          impact: { type: 'string', description: 'Concrete consequence: what an attacker or operator gets' },
          confidence: { type: 'string', enum: ['read-both-trees', 'read-ours-only', 'inferred'] },
        },
        required: ['title', 'severity', 'our_ref', 'core_ref', 'core_does', 'we_do', 'impact', 'confidence'],
      },
    },
    coverage_note: { type: 'string', description: 'What you read, and what you could NOT cover' },
  },
  required: ['findings', 'coverage_note'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    reason: { type: 'string' },
    corrected_severity: { type: 'string', enum: ['S1', 'S2', 'S3', 'unchanged'] },
  },
  required: ['refuted', 'reason', 'corrected_severity'],
}

const DIMENSIONS = [
  { key: 'consensus-block-tx', scope: 'Block and transaction consensus validation. Ours: src/validation/block.lisp (note it was JUST refactored: %check-block / %contextual-check-block / %reorg-* / connect-block / activate-block), src/validation/transaction.lisp. Core: validation.cpp CheckBlock/ContextualCheckBlock/ConnectBlock/CheckTxInputs, consensus/tx_check.cpp, consensus/tx_verify.cpp.' },
  { key: 'script-interpreter', scope: 'Script interpreter, tapscript, sighash, signature encoding. Ours: src/coalton/script.lisp, src/coalton/interop.lisp, src/validation/script.lisp. Core: script/interpreter.cpp, script/script.cpp, script/sigcache.cpp.' },
  { key: 'chain-reorg', scope: 'Chain selection, headers, reorg. Ours: src/validation/block.lisp perform-reorg + %reorg-disconnect/%reorg-connect/%reorg-commit (JUST REFACTORED in PR PR 562 -- scrutinise the phase boundaries, the rollback path and the interrupt handling especially), activate-block, src/networking/headers-sync.lisp. Core: validation.cpp ActivateBestChain/ActivateBestChainStep/DisconnectTip/ConnectTip/FindMostWorkChain, headerssync.cpp.' },
  { key: 'mempool-policy', scope: 'Mempool and policy. Ours: src/mempool/*.lisp, src/validation/transaction.lisp validate-transaction-for-mempool, src/validation/packages.lisp. Core: txmempool.cpp, validation.cpp MemPoolAccept (PreChecks/PolicyScriptChecks/ConsensusScriptChecks), policy/rbf.cpp, policy/truc_policy.cpp, policy/packages.cpp, policy/fees.cpp.' },
  { key: 'p2p-protocol', scope: 'P2P message handling and transport. Ours: src/networking/protocol.lisp, peer.lisp, ibd.lisp, v2-transport.lisp, connection.lisp. Core: net_processing.cpp, net.cpp, bip324.cpp, protocol.cpp.' },
  { key: 'peer-addrman', scope: 'Peer management, addrman, eviction, ban/discourage. Ours: src/networking/addrman.lisp, netaddress.lisp, peerdb.lisp, torcontrol.lisp, socks5.lisp, src/node/peers.lisp. Core: addrman.cpp, net.cpp eviction, netaddress.cpp, torcontrol.cpp, netbase.cpp.' },
  { key: 'storage-indexes', scope: 'Block store, coins view, chain state, indexes, pruning, flush/crash safety. Ours: src/storage/*.lisp, src/kv/*.lisp, src/node/flush.lisp. Core: node/blockstorage.cpp, coins.cpp, txdb.cpp, chain.cpp, index/*.cpp, dbwrapper.cpp, flatfile.cpp.' },
  { key: 'wallet', scope: 'Descriptor wallet, spending, PSBT, encryption, rescan. Ours: src/wallet/*.lisp. Core: wallet/wallet.cpp, spend.cpp, scriptpubkeyman.cpp, descriptor.cpp, psbt.cpp, crypter.cpp.' },
  { key: 'rpc-rest-ui', scope: 'RPC methods, REST, web UI, the HTTP server. Ours: src/rpc/*.lisp (note server.lisp was refactored: register-http-surface, rpc-server-data-directory, *rpc-request-uri*). Core: rpc/*.cpp, httprpc.cpp, httpserver.cpp, rest.cpp.' },
  { key: 'crypto-encoding', scope: 'Crypto primitives and canonical encodings. Ours: src/crypto/*.lisp, src/serialization/*.lisp. Core: crypto/*, key.cpp, pubkey.cpp, serialize.h, primitives/*, compressor.cpp, psbt.cpp.' },
  { key: 'mining', scope: 'Block template assembly, coinbase, witness commitment, difficulty. Ours: src/mining/*.lisp, src/rpc/mining.lisp. Core: node/miner.cpp, rpc/mining.cpp, pow.cpp.' },
  { key: 'config-lifecycle', scope: 'Option parsing, parameter interactions, init order, shutdown. Ours: src/config/*.lisp, src/config-options.lisp, src/config.lisp, src/node/args.lisp, init.lisp, shutdown.lisp. Core: common/args.cpp, common/config.cpp, common/settings.cpp, init.cpp.' },
  { key: 'refactor-regression', scope: 'REFACTOR-INDUCED REGRESSION. In the last week 43 PRs (the cleanup refactor) restructured this tree: src/ split into nine ASDF sub-systems, symbols moved down layers (*network*, network-magic, the pruning knobs, the token bucket, *interrupt-check*, compute-crc32, the config parsers), src/node/ and src/rpc/ were carved up, validate-block and perform-reorg were split, and tests/ moved into per-module directories. Read `git log --oneline 3470694 -60` and `git diff` on the riskiest of those commits. Hunt for BEHAVIOUR that changed as a side effect of a move: a re-exported symbol that is now a different object, a special read before it is set, an :apply/:global option row that no longer fires, a hook that lost its caller, a phase boundary that changed evaluation order. This dimension has no Core counterpart -- compare against our own pre-refactor behaviour (git show <old>:<path>).' },
]

const finderPrompt = (d) => `You are one of thirteen finders in the 10th gap analysis of bitcoin-lisp,
a Bitcoin full node in Common Lisp, against ${CORE}.

Working directory: ${REPO}. Both trees are on disk: ours under src/, Core under refs/bitcoin/src/.

YOUR DIMENSION: ${d.key}
${d.scope}

METHOD -- this is what separates a useful finding from a plausible one:
1. Read OUR code first and understand what it actually does. Do not skim.
2. Then read the CORRESPONDING Core code. Cite exact file:line on BOTH sides.
3. Report a divergence only when you have read both. If you only read ours, or you are
   reasoning from the name of a function, mark confidence honestly -- an honest
   'read-ours-only' is far more useful than a fabricated 'read-both-trees'.
4. Deliberate divergences are documented in our code's own comments (search for
   "DIVERGENCE", "deliberate", "Core"). If a comment explains why we differ, that is NOT a
   finding unless the comment's reasoning is actually wrong -- in which case say so.

SEVERITY:
  S1 = consensus split, fund loss, or remote crash/DoS reachable by any peer
  S2 = wrong behaviour with real operational consequence (relay, sync, wallet, resource)
  S3 = correctness nit, missing hardening, divergence with no practical consequence

${EXCLUSIONS}

Do NOT use the Agent tool; do the reading yourself.
Report at most 8 findings, strongest first. Quality over quantity: three findings you
verified in both trees beat eight you guessed at. If you find nothing new in your
dimension, return an empty list and say so in coverage_note -- that is a legitimate and
valuable result, not a failure.`

const verifyPrompt = (f, lens) => `You are an adversarial verifier in a gap analysis of bitcoin-lisp
(a Bitcoin node in Common Lisp) against ${CORE}. Working directory: ${REPO}.

A finder claims this divergence:

  TITLE:     ${f.title}
  SEVERITY:  ${f.severity}
  OURS:      ${f.our_ref}
  CORE:      ${f.core_ref}
  CORE DOES: ${f.core_does}
  WE DO:     ${f.we_do}
  IMPACT:    ${f.impact}
  (finder's own confidence: ${f.confidence})

YOUR LENS: ${lens}

Your job is to REFUTE it. Open both files at the cited lines and check the claim yourself.
Refute if ANY of these hold:
  - the cited line does not say what the finder claims
  - our code handles the case elsewhere (a caller, a guard, a different layer)
  - Core does not actually do what the finder says
  - a code comment documents this as a deliberate, correctly-reasoned divergence
  - the impact is not reachable in practice
Default to refuted=true when you cannot confirm the claim by reading the code. A finding
that survives must be one you personally traced. If it survives but the severity is wrong,
say so in corrected_severity.

Do NOT use the Agent tool; read the files yourself.`

// ---- Survey + Verify, pipelined so each dimension verifies as soon as it lands ----
phase('Survey')
const results = await pipeline(
  DIMENSIONS,
  (d) => agent(finderPrompt(d), { label: `find:${d.key}`, phase: 'Survey', schema: FINDING_SCHEMA }),
  (found, d) => {
    if (!found || !found.findings || found.findings.length === 0) {
      log(`${d.key}: no new findings`)
      return { dimension: d.key, coverage: found ? found.coverage_note : 'agent died', verified: [] }
    }
    log(`${d.key}: ${found.findings.length} candidate(s) -> verifying`)
    const LENSES = {
      S1: ['Does Core REALLY do what is claimed? Read refs/bitcoin at the cited line.',
           'Does OUR code really fail to do it? Look for the check in a caller, a guard, or another layer.',
           'Is the impact reachable in practice, at the claimed severity?'],
      S2: ['Does Core REALLY do what is claimed? Read refs/bitcoin at the cited line.',
           'Does OUR code really fail to do it? Look for the check elsewhere.',
           'Is the operational consequence real, or theoretical?'],
      S3: ['Is this claim accurate on both sides, and is it genuinely a divergence rather than a documented deliberate one?'],
    }
    return parallel(
      found.findings.map((f) => () =>
        parallel((LENSES[f.severity] || LENSES.S3).map((lens) => () =>
          agent(verifyPrompt(f, lens), { label: `verify:${d.key}`, phase: 'Verify', schema: VERDICT_SCHEMA })))
          .then((votes) => {
            const v = votes.filter(Boolean)
            const refutes = v.filter((x) => x.refuted).length
            // THREE outcomes, not two. A finding whose verifiers all DIED has
            // no verdict at all -- it is not the same as one skeptics killed,
            // and collapsing the two buries real bugs under a number that
            // looks like diligence. (The first run of this workflow did
            // exactly that: 102 agents died and 58 findings were reported
            // 'refuted' when most had simply never been judged.)
            const status = v.length === 0 ? 'unjudged'
                         : refutes >= Math.ceil(v.length / 2) ? 'refuted'
                         : 'confirmed'
            const sev = v.map((x) => x.corrected_severity).filter((s) => s && s !== 'unchanged')
            return {
              ...f,
              status,
              survives: status === 'confirmed',
              votes: v.length,
              refutes,
              severity: sev.length ? sev[0] : f.severity,
              refute_reasons: v.filter((x) => x.refuted).map((x) => x.reason),
              confirm_reasons: v.filter((x) => !x.refuted).map((x) => x.reason),
            }
          })))
      .then((judged) => ({
        dimension: d.key,
        coverage: found.coverage_note,
        verified: judged.filter(Boolean),
      }))
  }
)

const dims = results.filter(Boolean)
const all = dims.flatMap((r) => r.verified)
const confirmed = all.filter((f) => f.status === 'confirmed')
const killed = all.filter((f) => f.status === 'refuted')
const unjudged = all.filter((f) => f.status === 'unjudged')
log(`Survey complete: ${all.length} candidates -- ${confirmed.length} confirmed, ${killed.length} refuted, ${unjudged.length} NEVER JUDGED (no verifier returned)`)

// ---- Synthesis + completeness critic ----
phase('Synthesize')
const brief = confirmed.map((f, i) =>
  `${i + 1}. [${f.severity}] ${f.title}\n   ours: ${f.our_ref}\n   core: ${f.core_ref}\n   core does: ${f.core_does}\n   we do: ${f.we_do}\n   impact: ${f.impact}\n   verification: ${f.votes - f.refutes}/${f.votes} confirmed. ${(f.confirm_reasons[0] || '').slice(0, 300)}`
).join('\n\n')

const coverage = dims.map((r) => `- ${r.dimension}: ${r.coverage}`).join('\n')
const killedBrief = killed.map((f) => `- [${f.severity}] ${f.title} -- refuted ${f.refutes}/${f.votes}: ${(f.refute_reasons[0] || '').slice(0, 200)}`).join('\n')
const unjudgedBrief = unjudged.map((f) => `- [${f.severity}] ${f.title} (${f.our_ref} vs ${f.core_ref}) -- NO verdict returned`).join('\n')

const [report, critic] = await parallel([
  () => agent(`Write the 10th gap analysis report for bitcoin-lisp vs ${CORE}, to be saved as
docs/gap-analysis-10.md in ${REPO}. WRITE THE FILE with the Write tool.

Baseline: main @ 3470694 (immediately after a 43-PR refactor, the cleanup refactor).
Prior rounds: docs/gap-analysis-8.md, docs/gap-analysis-9.md. Unlike GA9, this round DID run an
adversarial refute-biased verification pass -- say so, and give the numbers.

CONFIRMED FINDINGS (survived a refute-biased panel):
${brief || '(none)'}

REFUTED CANDIDATES (a skeptic actually killed these -- what verification kills is evidence
about method, so record them):
${killedBrief || '(none)'}

NEVER JUDGED -- no verifier returned a verdict for these. They are NOT refuted and must NOT
be presented as such; absence of confirmation is not refutation. List them as unverified
candidates carrying their finder's severity, and say plainly that they still need a panel:
${unjudgedBrief || '(none)'}

PER-DIMENSION COVERAGE, in the finders' own words:
${coverage}

Structure: title and baseline; a scope table (dimension / candidates / confirmed); the
confirmed findings grouped S1 then S2 then S3, each with both file:line refs, what Core does,
what we do, the impact, and how it was verified; then the refuted list with why; then coverage
gaps and suggested sequencing. Be precise and honest -- where coverage was thin, say so.
Do not inflate severity. Return a 15-line summary of what you wrote.`,
    { label: 'write-report', phase: 'Synthesize' }),

  () => agent(`You are the completeness critic for a gap analysis of bitcoin-lisp against ${CORE}.
Working directory: ${REPO}.

Thirteen dimensions were surveyed: ${DIMENSIONS.map((d) => d.key).join(', ')}.

Coverage notes the finders gave:
${coverage}

Confirmed findings: ${confirmed.length}. Refuted: ${killed.length}.

Your job: say what this round MISSED. Consider specifically --
- Which Core subsystems have no corresponding dimension above at all?
- Which of our source files were likely never opened by any finder? (ls src/**/*.lisp and reason
  about which the dimension scopes cover.)
- Which dimensions returned suspiciously little given their surface area?
- What kind of defect is structurally invisible to this method (reading two trees side by side)?
Be concrete: name files and subsystems. This becomes the first task of the next round.
Do NOT use the Agent tool.`,
    { label: 'completeness-critic', phase: 'Synthesize' }),
])

return {
  candidates: all.length,
  confirmed: confirmed.length,
  refuted: killed.length,
  never_judged: unjudged.length,
  unjudged_titles: unjudged.map((f) => `[${f.severity}] ${f.title} (${f.our_ref})`),
  by_severity: {
    S1: confirmed.filter((f) => f.severity === 'S1').length,
    S2: confirmed.filter((f) => f.severity === 'S2').length,
    S3: confirmed.filter((f) => f.severity === 'S3').length,
  },
  confirmed_titles: confirmed.map((f) => `[${f.severity}] ${f.title} (${f.our_ref})`),
  report_summary: report,
  completeness_critic: critic,
}
