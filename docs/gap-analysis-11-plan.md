# Gap analysis 11 — plan

Baseline: `main` after the GA10 S1-S3 fixes (2026-09-05). Oracle: Bitcoin Core @ `d3056bc`, the
revision GA7-GA10 used. Method: `docs/gap-analysis-method.md`. Backlog: `docs/gap-analysis-10-critic.md`.
Run as orchestrated Opus agents, at most five concurrently, one worktree each; findings and verdicts
are committed as JSON under `docs/gap-analysis-11-data/` so the round survives a session limit.

## What GA10 taught this round to do differently

- Every dimension EXECUTES. Docker is up; a finder that cannot run a probe says so, and a verifier
  that only read is not a verdict. Each agent has its own container (`scripts/dev.sh` in its worktree).
- Findings carry a stable id (`sha1(our_ref + title[:60])[:8]`) from the moment they are written.
- Three-way status: confirmed / refuted / unjudged. A dead agent is not a vote.
- Two readers per high-value file, with different lenses; every "NOT covered" clause names the
  dimension that inherits it.
- Mechanism and consequence are judged separately, and severity follows the consequence.

## Round 1 — survey (10 dimensions, run five at a time)

The critic's five orphaned Core subsystems come first; each names its Core files and ours.

| # | dimension | Core | ours |
|---|---|---|---|
| 1 | descriptors + signing | script/descriptor.cpp, sign.cpp, signingprovider.cpp, solver.cpp | src/rpc/descriptors.lisp, src/validation/solver.lisp, the wallet signer |
| 2 | miniscript | script/miniscript.h/.cpp | src/validation/miniscript.lisp |
| 3 | cluster mempool | txgraph.cpp, cluster_linearize.h, txmempool.cpp chunk/eviction | src/mempool/txgraph.lisp, spanning-forest.lisp, cluster-linearize.lisp, feefrac.lisp |
| 4 | transaction relay scheduling | txrequest.cpp, node/txdownloadman_impl.cpp, txorphanage | src/networking/protocol.lisp (tx-relay half), orphanage |
| 5 | wallet persistence + wallet RPCs | wallet/walletdb.cpp, sqlite.cpp, wallet/rpc/* | src/wallet/wallet-store.lisp, the 62 wallet define-rpc forms |
| 6 | never-opened files | (each file's Core counterpart) | indexes.lisp, state.lisp, accessors.lisp, message-macro.lisp, coalton/{serialization,binary,types,crypto}.lisp, entropy.lisp, sync.lisp, listen.lisp, fd-wait.lisp, ratelimit.lisp, notify.lisp, housekeeping.lisp, wallet-hooks.lisp |
| 7 | accept-and-drop options | init.cpp / each option's reader | src/config-options.lisp define-core-only-options: for each, what the operator believes vs what we do |
| 8 | rpc/util + core_io + fees + versionbits reporting | rpc/util.cpp, core_io.cpp, rpc/fees.cpp, block_policy_estimator internals, versionbits.cpp | src/rpc/{json,accessors,output-script}.lisp, fee estimator, getdeploymentinfo |
| 9 | second reader: validation/block.lisp + chain.lisp + coins-view-cache.lisp | validation.cpp, coins.cpp, blockstorage.cpp | the restart / prune / reorg / flush seam GA10's two S1s sat in |
| 10 | second reader: protocol.lisp + peer.lisp + connection.lisp | net_processing.cpp, net.cpp | the liveness / backpressure / handshake seam |

Every finder is seeded with the GA1-GA10 exclusion list (GA10's `scripts/gap-analysis/01-survey.js`
plus the GA10 verdict table) and told that returning nothing is a legitimate result.

## Round 2 — verify

Refute-biased panel: two lenses for S1/S2, one for S3, batched two to four related findings per
agent grouped by file, with the container. Verdicts are written next to the findings with the
finding id and a title prefix; alignment is checked after the run.

## Round 3 — fix

The GA10 recipe: one worktree and one agent per batch of two to five findings grouped by file,
a reproduction and a pre-fix-red test per finding, the Core lines in each commit, merge from the
main checkout, the cold battery on merged main before every push.

## Harness lanes (their own batches, before round 3 starts)

- Differential encode/decode harness against Core's binaries (`bitcoin-tx`, `bitcoin-util`) for
  serialization, descriptors, PSBT and block filters — the critic's highest-leverage item.
- The script corpus runner compares Core's expected error name, not only accept/reject, which needs
  `SE-VerifyFailed` split into the thirteen Core errors it stands in for.
- Run the Core functional tests the findings cite (`scripts/conformance.sh <test>.py`) as verdicts.
