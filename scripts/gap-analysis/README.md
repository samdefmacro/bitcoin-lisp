# Gap-analysis workflow scripts

The four Workflow scripts GA10 ran, in order. They are kept because the harness is worth
more than any one round's findings; `docs/gap-analysis-method.md` explains the design,
what worked, and the five harness bugs these versions still contain or have fixed.

| script | what it does | agents |
|---|---|---|
| `01-survey.js` | one finder per dimension, seeded with prior rounds' findings as exclusions, then a refute-biased panel per finding | 167 (102 died on a session limit — see the method doc on sizing) |
| `02-verify-s1.js` | the four S1s, two adversarial lenses each, with `dev.sh eval` offered to the verifiers | 10 |
| `03-verify-batch.js` | 16 S2s, two per agent, grouped by file | 10 |
| `04-sweep-remainder.js` | the 38 never-judged S3s, the 26 single-vote re-checks, the 3 refactor claims | 22 |

Before reusing these, read the method doc's failure table. In particular `01-survey.js` still
has the two-way `survives` tally that conflates "refuted" with "never judged", and
`04-sweep-remainder.js` is the version WITHOUT the loader agent that deadlocked its first draft.

Findings and verdicts from the round these produced: `docs/gap-analysis-10-data/`.
