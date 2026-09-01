# The gap-analysis harness — what GA10 learned about running one

GA10 (2026-09-01) was the first round run as a multi-agent workflow rather than by hand, and the
first with an adversarial verification pass. This file records the harness so GA11 starts from a
working design instead of re-deriving it, and records the failures so it does not repeat them.

Artifacts: `scripts/gap-analysis/*.js` (the four workflow scripts, in run order),
`docs/gap-analysis-10-data/*.json` (every finding and every verdict),
`docs/gap-analysis-10.md` (the report), `docs/gap-analysis-10-verdicts.md` (the verdict table),
`docs/gap-analysis-10-critic.md` (what the round missed — GA11's backlog).

## The shape that worked

    survey (one agent per dimension, seeded with prior findings as exclusions)
      -> verify   (refute-biased panel per finding, execution available)
        -> synthesize (report + completeness critic)

Pipelined, not barriered: a dimension's findings start verifying the moment that dimension lands.

**Numbers from GA10.** 84 candidates from 13 dimensions; 78 confirmed, 6 refuted; 83 of the 84
verdicts were reached by *running code*, not only reading it.

### The five rules that produced the good verdicts

1. **Verifiers are told to refute, and to default to refuted when they cannot confirm.** A finding
   that survives must be one the verifier personally traced. This is what killed the six.
2. **Execution outranks reading, and verifiers are given the container.** `scripts/dev.sh eval` in
   the prompt changed outcomes: the sighash S1's own finder wrote "I could not execute the image to
   determine which"; a verifier ran it and turned a maybe into a proven `SIMPLE-TYPE-ERROR`. The
   cmpctblock DoS was *measured* (13-15 ms and 6.4-16 MB per replay) rather than estimated, which
   corrected the finder's claim by an order of magnitude in one direction and found it understated
   in another.
3. **Mechanism and consequence are judged separately.** Two of GA10's most instructive results were
   "the code reading is exactly right and the impact does not follow": the BIP144 deserializer gap
   (we re-serialize from the struct, so a hostile block is laundered into canonical form — no chain
   split) and the block-relay-only eviction filter (unreachable, because the filter is broken a
   *different* way that selects nobody). Without this split, both would have been recorded at the
   wrong severity.
4. **Finders are told an honest "I only read our side" beats a fabricated citation, and that
   returning nothing is a legitimate result.** The pressure to produce findings is what manufactures
   plausible-but-wrong ones.
5. **Verifiers are warned the tree was recently refactored** — a check they cannot find may have
   *moved*, not vanished. Grep before concluding absence.

### Dimensions

GA9's twelve (consensus-block-tx, script-interpreter, chain-reorg, mempool-policy, p2p-protocol,
peer-addrman, storage-indexes, wallet, rpc-rest-ui, crypto-encoding, mining, config-lifecycle) plus
**refactor-regression**, which has no Core counterpart: its oracle is our own pre-refactor behaviour
via `git show <commit>:<path>`. That dimension found a real regression (`bl:token-bucket` exported
but naming nothing) that no Core comparison could have surfaced. Run it after any large refactor.

## The failures, and the fixes they earned

Each of these cost real time in GA10. They are harness bugs, not model failures — every one was
mine.

| failure | what happened | fix |
|---|---|---|
| **"refuted" vs "never judged" collapsed** | 102 agents died on a session limit; my tally scored a finding with *zero* surviving verifiers the same as one three skeptics killed, and reported "58 refuted". Filing them that way would have buried real bugs. | Three-way status: `confirmed` / `refuted` / `unjudged`. Absence of confirmation is not refutation. |
| **De-duplication by title string** | I retyped finding titles into workflow args with different quote characters, so a finding failed to match itself across rounds and was verified twice while I reported an S1 still outstanding. | Give every finding a **stable id** (`sha1(our_ref + title[:60])[:8]`) at extraction time and match on that. Never match on prose. |
| **An agent used for bulk file I/O** | A `load-findings` agent was asked to echo a 114 KB JSON verbatim so the script could use it. It ground for 9+ minutes and blocked all 21 downstream agents (the script `await`s it). | Agents have filesystem access. Inline only the **index** (id + truncated title, ~7 KB) in the script and let each agent read the full record from the file itself. |
| **Batch agents mis-attributing verdicts** | One agent judging several findings can silently attach a verdict to the wrong one. | Require `id` + `title_prefix` in every verdict and check alignment after the run. GA10 round 3-4: 0 real misalignments out of 83. |
| **A positive control that lived only in prose** | A new ratchet's first draft was vacuous; a throwaway probe caught it; the commit message described the probe but the probe was never committed. | Factor the scanner into a function and have `refactoring-ratchets-can-actually-fail` feed it a synthetic input it MUST flag. See `%dead-exports`. |

## Sizing

- The first run launched 167 agents and **102 died on a session limit**. Verification is the
  expensive half (3 lenses per S1/S2), so it is what gets truncated.
- Batching works: one agent judging 2-4 related findings (grouped by file, so it carries shared
  context) costs far less than one agent per finding and showed no loss of quality.
- GA10's whole verification, done in three batched rounds, was 10 + 10 + 22 = 42 agents for 84
  findings. Budget that, not 250.
- Resume is cheap and correct: unchanged `(prompt, opts)` replay from cache, so a killed run can be
  restarted after editing post-processing without re-spending the agents that finished.

## What this method structurally cannot see

Reading two trees side by side finds divergences that are visible in source. It does not find
behaviour that only appears when the code runs against real inputs — races, resource exhaustion
under load, state-machine paths reachable only after a specific message sequence, or anything whose
divergence is in *timing*. `docs/gap-analysis-10-critic.md` names the specific subsystems most
exposed to that, and lists the 21 Core subsystems no GA10 dimension covered at all — including
`txgraph`/`cluster_linearize` (~5,600 lines), `descriptor`/`sign` (~5,000), `miniscript` (~3,100),
and `wallet/rpc/*` (~3,000, which fell in the seam between the wallet and RPC dimensions). Two of
our own files are named there as never opened by any finder.

**GA11 starts there**, not with a fresh sweep of ground GA10 already covered.
