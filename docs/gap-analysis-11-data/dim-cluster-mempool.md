# GA11 survey - cluster mempool

Dimension 3 of `docs/gap-analysis-11-plan.md`. Oracle: Bitcoin Core `refs/bitcoin/` @ d3056bc.
Findings: `dim-cluster-mempool.json` (1 S1, 2 S2, 2 S3). Survey only - nothing under `src/` or
`tests/` was changed.

## What was read, against what

| ours | Core |
|---|---|
| `src/mempool/feefrac.lisp` | `util/feefrac.h`, `util/feefrac.cpp` (CompareChunks) |
| `src/mempool/cluster-linearize.lisp` | `cluster_linearize.h` DepGraph :29-357, chunking :427-463, PostLinearize :1854-2037 |
| `src/mempool/spanning-forest.lisp` | `cluster_linearize.h` SFLDefaultCostModel :496-544, SpanningForestState :546-1600, Linearize :1799-1836 |
| `src/mempool/txgraph.lisp` | `txgraph.h`, `txgraph.cpp` (Updated :1072, CompareMainTransactions :492, BlockBuilder :3159, GetWorstMainChunk :3258, Trim :3285, staging :1693 / :2809) |
| `src/mempool/mempool.lisp` consumers | `txmempool.cpp` (TrimToSize :861, GetMinFee :829, ChangeSet :994-1080), `validation.cpp` (ReplacementChecks :981, PackageRBFChecks :1034, LimitMempoolSize), `policy/rbf.cpp` |
| `src/mining/assembler.lisp` | `node/miner.cpp` addChunks :278-334 |

## Method

Everything was executed in the project container (`scripts/dev.sh eval`, warm image on
`fix/ga11-cluster-mempool`). Probes built random and adversarially shaped DepGraphs, timed
64-transaction relinearization, timed the global chunk index under eviction, timed the RBF staging
scratch copy at the rule-5 maximum shape, and drove a real mempool for the prioritisation,
weight-vs-vsize and trim cases. Each finding's `executed` field carries the form's actual output.

Trap worth repeating: `tests/package.lisp` sets `bl.mp:*txgraph-shadow-checks*` to T at load time,
and the warm dev image loads the test system, so every eval in it runs the O(n) per-operation
sanity assert. A 20,000-transaction mempool fill that should take seconds ran past 30 minutes.
Bind the flag to NIL in any timing probe.

## The pure algorithm layer is a faithful port

Line-for-line comparison found no divergence in: `CompareChunks` (including the `done_0`/`done_1`
side selection and the equal-size advance of the other diagram), `EvaluateFee` rounding in both
directions, `DepGraph::RemoveTransactions` / `AddDependencies` / `GetReducedParents` (including the
iterate-the-snapshot semantics of Core's BitSet iterator), `PostLinearize`'s merge/swap cycle and
both output directions, the whole SFL state machine and its cost-model coefficients, `Trim`'s
heap-plus-union-find shape, and `GetMinFee`'s decay. Existing suites already assert the fuzz-target
properties (topological validity, chunk monotonicity, optimality against exhaustive search for small
clusters, seeded determinism, randomized txgraph-vs-model equivalence), so those were not
re-derived.

Three extra properties were measured rather than read:

- **Linearization is seed independent.** 200 random 12-transaction clusters times 8 RNG seeds
  produced identical linearizations *and* identical chunk feerate multisets every time. The fresh
  per-call seed therefore cannot make mining order or an RBF verdict nondeterministic.
- **A rejected over-limit add rolls back exactly.** Our reject path mutates the MAIN graph and
  undoes it, where Core stages in a separate level. Two chains (40 and 30) plus a joining
  transaction that trips IS-OVERSIZED, then removal: cluster membership, linearization order and
  every chunk feerate came back identical and `TXGRAPH-SANITY-CHECK` passed.
- **No cost budget is not a DoS.** `LINEARIZE` passes `most-positive-fixnum` where Core caps a
  synchronous relinearization at `ACCEPTABLE_COST` 75,000. A 400-shape search over 64-transaction
  clusters found a worst SFL cost of 102,741 - over Core's budget - but wall time never exceeded
  0.35 ms per call. Documented in the `LINEARIZE` docstring; not filed as a finding.

## Where the divergences are

All five findings are in the *integration* layer, not the algorithms:

1. `2a636776` (S1) - the global mining chunk index is rebuilt and re-sorted from scratch after every
   mutation, so eviction pays n log n work per evicted chunk where Core pays log n. Measured
   0.187 s per evicted chunk at 200,000 transactions in the txgraph, and 0.206 s to evict ten
   transactions from a real 30,000-transaction mempool, all under the node lock.
2. `af013c51` (S2) - RBF staging reconstructs affected clusters one dependency at a time, each one a
   merge plus a full relinearization, where Core copies the cluster wholesale. 0.389 s for one
   check at the rule-5 maximum shape, before script validation, under the node lock.
3. `7585dbb3` (S2) - an out-of-int64 `prioritisetransaction` delta type-errors *after* mutating the
   entry, permanently desynchronising the mempool entry from the txgraph.
4. `ed2f2295` (S3) - the graph is sized in sigop-adjusted vbytes where Core uses sigop-adjusted
   weight; the per-transaction ceiling lands before the feerate comparisons instead of after.
5. `afcc1221` (S3) - the RBF descendant expansion runs before the rule-5 cluster cap that exists to
   bound it.

## Not covered, and who inherits it

- Fee estimator and block-policy estimator (`fee-estimator.lisp`, `block-policy-estimator.lisp`) -
  same directory, no cluster machinery. **GA11 dimension 8** (rpc/util + fees + versionbits).
- Orphan pool (`orphan.lisp`) and all request/announce scheduling - **GA11 dimension 4**
  (transaction relay scheduling).
- TRUC/BIP431 topology rules and 1p1c package assembly beyond their txgraph calls - mempool-policy.
- `getmempoolentry` / `getmempoolcluster` / `getmempoolfeeratediagram` JSON shapes and field names
  (their unit divergence is documented in the handlers) - **GA11 dimension 8**.
- `mempool.dat` persistence - untouched by cluster mempool by design.
- Concurrency: no soak or multi-thread probe was run, so nothing here proves that no path reaches
  `MAKE-BLOCK-BUILDER` without the node lock; the assembler takes it, the rest was read only.
