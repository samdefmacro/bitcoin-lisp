export const meta = {
  name: 'ga10-round3',
  description: 'GA10 round 3: verify the last S1 and all 16 S2s with 10 agents',
  phases: [
    { title: 'S1', detail: 'the remaining S1, two adversarial lenses' },
    { title: 'S2 sweep', detail: '16 S2s, two per agent, refute-biased with execution' },
  ],
}

const REPO = '/Users/sen/common-lisp/bitcoin-lisp'
const FILE = '/private/tmp/claude-501/-Users-sen-common-lisp-bitcoin-lisp/be9485ca-5f21-407c-89c0-198cdf66317b/scratchpad/round3args.json'

const COMMON = `Working directory: ${REPO}. Ours is src/, Bitcoin Core @ d3056bc is refs/bitcoin/src/.

The findings you must judge are in ${FILE} (JSON). Read that file and take ONLY your assigned
entries; each has title / our_ref / core_ref / core_does / we_do / impact.

YOU CAN RUN CODE, and an executed answer outranks a read one:
  scripts/dev.sh eval '<lisp form>'    # ~0.3s against the warm image, exit 0 ok / 1 lisp error
  scripts/dev.sh test :some-tests      # one fiveam suite
The image is up and the system is loaded. If a claim is decidable by execution -- does this
function actually return that, does this deserializer actually accept those bytes, does this
path actually signal -- RUN IT and quote the output. Do not modify any file. Never run a git
command that writes.

YOUR JOB IS TO REFUTE. Set refuted=true if the claim misreads either tree, if the behaviour is
handled elsewhere (our tree was heavily refactored recently -- a check may have MOVED, so grep
before concluding it is absent), if a code comment documents it as a deliberate and correctly
reasoned divergence, or if the stated impact is not reachable. Default to refuted=true when you
cannot confirm it. A finding that survives you must be one you personally traced or ran.
Judge the MECHANISM and the CONSEQUENCE separately: a real divergence with an unreachable or
overstated consequence is a severity correction, not a confirmation. Do not use the Agent tool.`

const VERDICT_ONE = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    corrected_severity: { type: 'string', enum: ['S1', 'S2', 'S3', 'unchanged'] },
    evidence: { type: 'string' },
    executed: { type: 'boolean' },
  },
  required: ['refuted', 'corrected_severity', 'evidence', 'executed'],
}

const VERDICT_MANY = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          index: { type: 'integer', description: 'the s2 index you were assigned' },
          title_prefix: { type: 'string', description: 'first ~60 chars of the title, to confirm alignment' },
          refuted: { type: 'boolean' },
          corrected_severity: { type: 'string', enum: ['S1', 'S2', 'S3', 'unchanged'] },
          evidence: { type: 'string', description: 'What you read or RAN, with file:line or eval output' },
          executed: { type: 'boolean' },
        },
        required: ['index', 'title_prefix', 'refuted', 'corrected_severity', 'evidence', 'executed'],
      },
    },
  },
  required: ['verdicts'],
}

phase('S1')
const s1 = await parallel([
  () => agent(`${COMMON}

ASSIGNMENT: the single entry in the "s1" array of that file.

LENS A -- CLAIM ACCURACY. Open both cited locations. Is Core's behaviour really what is claimed?
Is ours really what is claimed? Is the thing said to be missing done somewhere else -- a caller,
a guard, another layer, a later phase?`,
    { label: 's1-lensA', phase: 'S1', schema: VERDICT_ONE }),
  () => agent(`${COMMON}

ASSIGNMENT: the single entry in the "s1" array of that file.

LENS B -- REACHABILITY AND SEVERITY. Grant the code reading and attack the CONSEQUENCE. Can a peer
or miner actually reach it? Does anything downstream neutralise it (normalisation, re-serialization,
a later validation, a rate limit, a permission gate)? Does the impact deserve S1 -- consensus split,
fund loss, or remote crash/DoS any peer can trigger -- rather than S2 or S3?`,
    { label: 's1-lensB', phase: 'S1', schema: VERDICT_ONE }),
])

phase('S2 sweep')
const PAIRS = [[0, 1], [2, 3], [4, 5], [6, 7], [8, 9], [10, 11], [12, 13], [14, 15]]
const s2 = await pipeline(
  PAIRS,
  (pair) => agent(`${COMMON}

ASSIGNMENT: entries at index ${pair[0]} and ${pair[1]} of the "s2" array in that file (0-based).
Judge BOTH, independently, and return one verdict object per index. Include title_prefix so the
alignment can be checked -- if the entry at an index does not look like what you judged, say so in
evidence rather than guessing.

These were filed S2: wrong behaviour with a real operational consequence (relay, sync, wallet,
resource), short of a consensus split. Confirm or refute each on its own merits, and correct the
severity where the evidence warrants -- upgrades to S1 included if you find the consequence is
worse than filed.`,
    { label: `s2:${pair[0]},${pair[1]}`, phase: 'S2 sweep', schema: VERDICT_MANY }),
)

const flat = s2.filter(Boolean).flatMap((r) => r.verdicts || [])
const v1 = s1.filter(Boolean)
log(`S1: ${v1.filter((x) => !x.refuted).length}/${v1.length} confirmed. S2: ${flat.filter((x) => !x.refuted).length}/${flat.length} confirmed, ${flat.filter((x) => x.executed).length} settled by execution.`)
return {
  s1: { votes: v1.length, refutes: v1.filter((x) => x.refuted).length, detail: v1 },
  s2: flat,
  s2_missing: 16 - flat.length,
}
