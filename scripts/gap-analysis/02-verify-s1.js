export const meta = {
  name: 'ga10-verify-s1',
  description: 'GA10 continuation: verify the 4 unjudged S1s, run the missing refactor dimension, critic',
  phases: [
    { title: 'Verify S1', detail: '4 findings x 2 adversarial lenses, with container eval available' },
    { title: 'Refactor sweep', detail: 'the dimension that never ran' },
    { title: 'Critic', detail: 'what this method still cannot see' },
  ],
}

const REPO = '/Users/sen/common-lisp/bitcoin-lisp'
const FINDINGS = args

const VERDICT = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    corrected_severity: { type: 'string', enum: ['S1', 'S2', 'S3', 'unchanged'] },
    evidence: { type: 'string', description: 'What you read or RAN, with file:line or the eval output. Be specific.' },
    executed: { type: 'boolean', description: 'true if you settled any part of this by running code, not just reading' },
  },
  required: ['refuted', 'corrected_severity', 'evidence', 'executed'],
}

const EVAL_NOTE = `
YOU CAN RUN CODE. This project builds in a container; from ${REPO}:
  scripts/dev.sh eval '<lisp form>'     # ~0.3s, the warm image, exit 0 ok / 1 lisp error
  scripts/dev.sh test :some-tests       # one fiveam suite
The image is already running. If any part of this claim is decidable by EXECUTION rather than
reading -- does this call actually signal a type error, does this deserializer actually accept
these bytes, does this function actually return what the finder says -- then RUN IT and report
the output as evidence. An executed answer outranks a read one. Do not modify any file.
Never run a git command that writes (no commit, checkout, reset).`

const lens = (f, which) => which === 'A'
  ? `LENS A -- CLAIM ACCURACY. Open BOTH cited locations yourself.
Is the Core behaviour really what the finder says at ${f.core_ref}? Is our code really doing what
they say at ${f.our_ref}? Check whether the thing they say is missing is actually done somewhere
else -- a caller, a guard, another layer, a later phase. Our tree was heavily refactored last week,
so a check may have MOVED rather than vanished; grep for it before concluding it is absent.`
  : `LENS B -- REACHABILITY AND SEVERITY. Grant the code reading for argument's sake and attack the
CONSEQUENCE. Is the bad path actually reachable by a peer or a miner in practice? Is there a rate
limit, a permission gate, a height/work gate, or a caller-side condition that stops it? Does the
claimed impact follow, and does it deserve S1 (consensus split, fund loss, or remote crash/DoS any
peer can trigger) rather than S2?`

phase('Verify S1')
const verdicts = await pipeline(
  FINDINGS.flatMap((f, i) => [{ f, i, which: 'A' }, { f, i, which: 'B' }]),
  ({ f, i, which }) => agent(
`You are an adversarial verifier for the 10th gap analysis of bitcoin-lisp (a Bitcoin full node in
Common Lisp) against Bitcoin Core @ d3056bc. Working directory: ${REPO}. Ours is src/, Core is
refs/bitcoin/src/.

A finder filed this as S1. It has NOT yet been verified by anyone -- the first verification round
died on an API limit before reaching it. You are one of two independent skeptics on it.

  TITLE:     ${f.title}
  OURS:      ${f.our_ref}
  CORE:      ${f.core_ref}
  CORE DOES: ${f.core_does}
  WE DO:     ${f.we_do}
  IMPACT:    ${f.impact}

${lens(f, which)}

${EVAL_NOTE}

YOUR JOB IS TO REFUTE IT. Set refuted=true if the claim misreads either tree, if the behaviour is
handled elsewhere, if a comment documents it as a deliberate and correctly-reasoned divergence, or
if the impact is not reachable. Default to refuted=true when you cannot confirm it by reading or
running. A finding that survives you must be one you personally traced. Do not use the Agent tool.`,
    { label: `verify-s1-${i + 1}${which}`, phase: 'Verify S1', schema: VERDICT }),
)

phase('Refactor sweep')
const refactor = await agent(
`You are the finder for the one gap-analysis dimension that never ran: REFACTOR-INDUCED REGRESSION.
Working directory: ${REPO}. This is a Bitcoin full node in Common Lisp.

In the last week 43 PRs (#521-#562) restructured this tree:
- src/ was split into nine ASDF sub-systems (util, crypto, logging, config, kv, serialization,
  storage, net, rpc-server), each compiled before the next.
- Symbols MOVED DOWN layers and are re-exported from the top package: *network*, network-magic,
  network-port/-dns-seeds/-rpc-port, the pruning knobs (*prune-target-mib* etc.), the token bucket,
  *interrupt-check* / interrupt-requested-p, compute-crc32, and the whole config parser set.
- src/node/ and src/rpc/ were carved into per-topic files; the RPC server gained
  register-http-surface, rpc-server-data-directory and *rpc-request-uri*.
- validate-block was split into %check-block + %contextual-check-block; perform-reorg into a REORG
  struct + %reorg-disconnect / %reorg-connect / %reorg-commit.
- tests/ moved into per-module directories.

There is NO Core counterpart for this dimension. Your oracle is our OWN pre-refactor behaviour:
  git log --oneline 3470694 -60
  git show <commit>:<path>          # the file as it was before a move
  git diff <old>..<new> -- <path>

Hunt for BEHAVIOUR that changed as a side effect of a move, not for style. The shapes to look for:
- a re-exported symbol that is now a DIFFERENT object than a caller expects (import-from vs use),
- a special read before the code that sets it now runs (load-order changed),
- a config option whose :apply/:global row no longer fires, or an option table row orphaned,
- a hook, notification or index update that lost its only caller in the move,
- an evaluation-order or early-return change at a new function boundary (the validate-block and
  perform-reorg splits are the two riskiest: check the phase boundaries, the rollback path, the
  interrupt/stop handling, and what each half returns),
- something that was inside a lock/unwind-protect and is now outside it.

${EVAL_NOTE}

This project's recurring failure is "correct code, wrong or missing caller" -- it has shipped 15
times. Weight your search that way. Report at most 8 findings, strongest first, each with the
pre-refactor and post-refactor evidence (commit + file:line on both). If you find nothing, say so
plainly -- that is a real result. Do not use the Agent tool.`,
  { label: 'find:refactor-regression', phase: 'Refactor sweep' })

phase('Critic')
const critic = await agent(
`You are the completeness critic for the 10th gap analysis of bitcoin-lisp vs Bitcoin Core @
d3056bc. Working directory: ${REPO}. Read docs/gap-analysis-10.md first -- it records what the
round covered and, importantly, how it failed (102 of 167 agents died on an API limit).

Twelve dimensions were surveyed: consensus-block-tx, script-interpreter, chain-reorg,
mempool-policy, p2p-protocol, peer-addrman, storage-indexes, wallet, rpc-rest-ui, crypto-encoding,
mining, config-lifecycle. A thirteenth (refactor regression) ran only now.

Say what this round STILL misses. Be concrete and name things:
1. Which Core subsystems have no dimension at all? (ls refs/bitcoin/src/ and its subdirs.)
2. Which of OUR source files were likely never opened? (find src -name '*.lisp' -- 148 files. The
   report's coverage notes say what each finder read; name the files nobody covered.)
3. Which dimensions returned suspiciously little for their surface area?
4. What class of defect is STRUCTURALLY invisible to this method -- reading two trees side by side
   with no execution? Name the specific kinds of bug that only a differential test, a fuzzer, or a
   live network run would surface, and say which of our subsystems are most exposed to them.
This becomes the first task of GA11, so be specific enough to act on. Do not use the Agent tool.`,
  { label: 'completeness-critic', phase: 'Critic' })

const v = verdicts.filter(Boolean)
const per = FINDINGS.map((f, i) => {
  const mine = [v[i * 2], v[i * 2 + 1]].filter(Boolean)
  const refutes = mine.filter((x) => x.refuted).length
  return {
    title: f.title,
    our_ref: f.our_ref,
    votes: mine.length,
    refutes,
    status: mine.length === 0 ? 'still-unjudged' : refutes === 0 ? 'CONFIRMED' : refutes === mine.length ? 'refuted' : 'split',
    severity: mine.map((x) => x.corrected_severity).filter((s) => s && s !== 'unchanged'),
    executed: mine.some((x) => x.executed),
    evidence: mine.map((x) => `${x.refuted ? 'REFUTE' : 'CONFIRM'}: ${x.evidence}`),
  }
})
log(`S1 verification: ${per.filter((p) => p.status === 'CONFIRMED').length} confirmed, ${per.filter((p) => p.status === 'refuted').length} refuted, ${per.filter((p) => p.status === 'split').length} split`)
return { s1: per, refactor_regression: refactor, completeness_critic: critic }
