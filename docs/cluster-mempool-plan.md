# Cluster Mempool + Feerate-Diagram RBF — Implementation Plan

Date: 2026-07-10. Status (2026-08-22): **P0-P10 DONE** — through "Cluster mempool P8+P9: reorg bulk re-add + package/diagram RBF reconciliation + cluster RPCs", then P10 (the SFL linearizer) in PR 376. The §6 table was never updated.
Reference: Bitcoin Core `refs/bitcoin/` @ d3056bc (v30-dev, cluster mempool fully merged).
Researched via 4 parallel deep-dives: Core txgraph/linearization internals, Core mempool integration,
Core diagram-RBF policy, and our own mempool architecture.

## 1. Framing

Cluster mempool is **policy, not consensus**. It changes mempool acceptance, relay announcement
order, mining-template composition, eviction, and the RBF economic test — never block validity.
Divergence from Core costs relay efficiency / template quality, not a chain split. Unlike consensus
work, this can land incrementally and imperfectly, phase by phase, with the node shippable at every
stage.

## 2. The paradigm shift

|                | Today (ours)                                              | Cluster mempool (Core v30)                                                        |
|----------------|-----------------------------------------------------------|-----------------------------------------------------------------------------------|
| Graph          | on-demand BFS over parent/child hash-sets, no cached state | persistent **clusters** (connected components), each with a maintained **linearization** chopped into **chunks** |
| Limits         | 25/25 ancestors/descendants + 101 kvB each                | **64 tx / 101 kvB per cluster**; ancestor/descendant counts kept for RPC reporting only |
| Mining         | ancestor-feerate greedy (single static sort)              | walk chunks in descending chunk-feerate order across all clusters                  |
| Eviction       | worst descendant-package feerate, recursive remove        | drop the single worst chunk (reverse-topological), rolling-min-fee kept            |
| RBF economics  | BIP125 rules 1–5                                          | rules 3/4/5 survive as anti-DoS pre-filters; economic test = **feerate-diagram improvement** |
| CPFP carve-out | n/a (we never had it)                                     | deleted in Core                                                                    |

Definitions:
- **Cluster** — connected component under the spends-from relation, capped at 64 tx / 101,000 vB.
- **Linearization** — topological order of a cluster approximating fee-optimal mining order.
- **Chunk** — maximal prefix grouping of the linearization with monotonically non-increasing
  feerates: walk the linearization; each tx starts a singleton chunk; while it has strictly higher
  feerate than the previous chunk, absorb that chunk (`cluster_linearize.h:427-463`).
- **Feerate diagram** — chunk (fee,size) pairs of a set of clusters sorted by descending feerate,
  read as the concave cumulative fee-vs-size curve from (0,0) (what a miner collects filling x
  vbytes greedily).

## 3. Key research findings that shape the plan

1. **The RBF change is smaller than advertised.** In Core d3056bc the diagram check is layered
   **on top of** BIP125 anti-DoS rules, not a wholesale replacement (`policy/rbf.cpp`):
   - Rule 1 (signaling): **gone** — full-RBF unconditional in the accept path
     (`validation.cpp:490`); `IsRBFOptIn` survives only for RPC display.
   - Rule 2 (no new unconfirmed inputs): **gone** from node policy (wallet-only now).
   - Rule 3 (pay ≥ Σ replaced fees): **survives** (`PaysForRBF`, `rbf.cpp:106-112`).
   - Rule 4 (pay own bandwidth at incremental-relay 100 sat/kvB): **survives** (`rbf.cpp:114-123`).
   - Rule 5: **survives redefined** — ≤ 100 distinct **clusters** conflicted (`rbf.cpp:58-83`)
     plus a 500-tx gather cap (`txmempool.cpp:988-990`).
   - Old feerate-superiority rule (`PaysMoreThanConflicts`): **replaced** by
     `ImprovesFeerateDiagram` = `is_gt(CompareChunks(new_diagram, old_diagram))`
     (`rbf.cpp:127-140`).
   Our `find-rbf-conflicts` and the "replaced set = direct conflicts ∪ descendants" expansion
   (src/mempool/mempool.lisp:555-582) stay; only the economic test inside `check-rbf-rules`
   (mempool.lisp:569-636) changes.

2. **The scary algorithm is deferrable.** Core's linearizer is SFL (spanning-forest local search,
   `cluster_linearize.h:546-716`), budgeted and resumable behind a stable interface. A first-cut
   linearizer — ancestor-feerate seeding + `PostLinearize` (2-pass sweep, provably optimal for
   tree-shaped clusters, the overwhelmingly common case; `cluster_linearize.h:1854-2037`) — is
   *correct*, just suboptimal on complex DAGs. SFL is a quality upgrade swappable later with zero
   integration churn.

3. **Entry-is-a-ref has no Lisp analogue.** In Core, `CTxMemPoolEntry : public TxGraph::Ref` and
   the Ref *destructor* removes the tx from the graph. Lisp has no destructors — every mempool
   entry removal must explicitly call `txgraph-remove`. This is the most important mechanical
   discipline of the port; shadow-mode asserts (P3) exist to catch any missed path.

4. **No persistence changes.** Core's mempool.dat is unchanged; graph state is derived, never
   serialized — reload replays acceptance. Our save/read (mempool.lisp:675-737) is untouched.

## 4. The txgraph contract to implement

A new `src/mempool/txgraph.lisp` (+ `feefrac.lisp`, `linearize.lisp`) module, Bitcoin-agnostic like
Core's:

1. **feefrac** `{fee: int64, size: int32}` — division-free cross-multiplied comparisons (CL bignums
   make this trivial). Full order = feerate then *descending* size, empty sorts last; feerate-only
   compare for chunk absorption; `evaluate-fee` with directed rounding. (`util/feefrac.h`)
2. **compare-chunks(A, B)** → `{:less :greater :equal :unordered}` — sweep both concave diagrams
   left-to-right by size, comparing slopes; each-better-somewhere ⇒ `:unordered`. **This is the RBF
   predicate.** (`feefrac.cpp:10-73`)
3. **depgraph** per cluster — per-tx feerate + **ancestor and descendant bitsets (transitive
   closure, not raw edges)**; 64-cap ⇒ one 64-bit integer per set; connected-component,
   reduced-parents, topo helpers. (`cluster_linearize.h:29-357`)
4. **chunking** — the greedy absorb pass (§2 above).
5. **linearize** — P1: ancestor-feerate seed + `post-linearize`. P10 (optional): SFL with cost
   budget + optimal flag. Interface: `(linearize depgraph &key max-cost existing)` →
   `(values linearization optimal-p cost-spent)`.
6. **cluster registry + mining-ordered chunk index** — global ordered index on (chunk-feerate desc,
   tie-breaks: equal-feerate-prefix, fallback txid-ascending, linearization position). Front =
   mining, back = eviction (`get-worst-main-chunk`, reverse-topological within the chunk).
7. **mutation pipeline** — Core is lazy (ApplyRemovals → SplitAll → GroupClusters(union-find) →
   Merge → ApplyDependencies → MakeAcceptable, `DoWork(max-cost)` drainer). **We start eager** —
   at our mempool sizes (remote node, default 300 MB cap but low tx volume) eager re-linearization
   per mutation is fine; the lazy pipeline is a later optimization if profiling demands it.
8. **limits** — `is-oversized(level)`: any component > 64 tx or > 101,000 vB; `trim` (greedy
   heap + union-find) to restore limits after reorg re-adds.
9. **staging overlay** — Core: copy-on-write second level (Present/Missing/Removed locators,
   `PullIn`). **We start with scratch-copy of only the affected clusters** (bounded: ≤ 100 clusters
   × ≤ 64 tx), upgrade to COW only if needed. API: `start-staging` / `abort-staging` /
   `commit-staging` + `get-main-staging-diagrams`.
10. **queries** — `get-ancestors/descendants[-union]`, `get-cluster`, `get-main-chunk-feerate`,
    `get-individual-feerate`, `compare-main-order`, `count-distinct-clusters`, block-builder
    (`current-chunk` / `include` / `skip` — skip suppresses the rest of that cluster).

Constants (Core-exact, for relay compatibility): cluster limit **64** tx, cluster size
**101 kvB**, `ACCEPTABLE_COST` 75,000, `POST_CHANGE_COST` 375,000, incremental relay fee
100 sat/kvB, RBF caps 100 clusters / 500 tx.

## 5. Integration surface (our code)

**Replaced** (src/mempool/mempool.lisp unless noted):
- `%walk-mempool-graph`, `mempool-ancestors/descendants` (:216-250) → graph queries
- `mempool-*-stats`, `mempool-ancestor/descendant-fee-rate` (:252-294) → chunk feerates
- `check-ancestor-descendant-limits` (:361-386) → `is-oversized` cluster check
- `check-rbf-rules` economic test (:569-636) → rules 3/4/5 pre-filters + diagram check
- `mempool-evict-for-size` ranking (:741-782) → worst-chunk loop
- `assemble-block-template` selection (src/mining/assembler.lisp:132-170) → chunk walk

**Modified** (gain graph-maintenance hooks): `mempool-entry`/`mempool` structs, `mempool-add`
(:420-480), `mempool-remove(-recursive)` (:482-517), `accept-validated-tx` (:406-418),
`mempool-remove-for-block` (:808-835), `single-truc-checks` interplay.

**Unchanged**: conflict/outpoint index, prioritise/modified-fee (feeds `set-transaction-fee`),
wtxid index, orphan pool, rolling-min-fee decay machinery (trigger becomes evicted-chunk feerate),
mempool.dat format, and all consensus/standardness checks in `validate-transaction-for-mempool`
except its fee-floor/TRUC/RBF sub-steps.

**Riskiest couplings**:
1. Reorg re-add (`readd-disconnected-txs-to-mempool`, src/validation/block.lisp:1608-1623) — Core
   re-adds then wires deps then `Trim()`s; per-tx re-clustering is the churn hot spot.
2. Package 1p1c acceptance (src/validation/packages.lisp) — Core restricts package-RBF to
   1-parent-1-child with **no in-mempool ancestors** (resulting cluster ≤ 2), plus a
   package-feerate > parent-feerate chunk check.
3. Mining consumers: builder.lisp:53, getblocktemplate/getmininginfo, `*last-block-template*`.
4. Every block confirmation splits clusters (`mempool-remove-for-block`).
5. RPC graph exposure: getmempoolentry/ancestors/descendants keep working as shims.

## 6. Staged milestones (node shippable at every stage)

| Phase | Deliverable | Test strategy | Size |
|-------|-------------|---------------|------|
| **P0** | `feefrac.lisp`: FeeFrac + compare-chunks | port Core `feefrac_tests.cpp` vectors | S |
| **P1** | `linearize.lisp`: DepGraph + chunking + ancestor-seed + post-linearize | port `cluster_linearize` test shapes; property tests (topological, chunk monotonicity) | M (the meat) |
| **P2** | `txgraph.lisp`: cluster registry, chunk index, queries, is-oversized, worst-chunk; single graph, eager | unit tests + randomized graph ops vs brute-force reference | M |
| **P3** | **Shadow mode**: entries carry graph handle; graph maintained on every add/remove/block/reorg; equivalence-assert vs existing BFS (ancestor/descendant sets, limits). Behavior unchanged. | full suite + soak on testnet4 | S-M |
| **P4** | Mining flips to chunk-walk block builder (weight/sigops/locktime tests, blockMinFeeRate early-out, skip-suppresses-cluster) | A/B template comparison vs old greedy | S |
| **P5** | Eviction flips to worst-chunk; rolling-min-fee fed by evicted chunk feerate + incremental | existing eviction tests adapted | S |
| **P6** | Limits flip to cluster 64/101 kvB; 25/25 becomes RPC-reporting-only; `-limitclustercount/-limitclustersize` config | Core policy tests adapted; TRUC interplay | S |
| **P7** | **Diagram RBF**: staging (scratch-copy) + `improves-feerate-diagram`; keep rules 3/4/5, drop rules 1/2 (full-RBF), rule 5 → 100-cluster cap | port `rbf_tests.cpp` scenarios | M-L |
| **P8** | Reorg bulk re-add + trim; package 1p1c reconciled with diagram path (Core-style package RBF + sibling eviction acceptance fall out here) | reorg + package suites; testnet4 soak | M |
| **P9** | RPCs: getmempoolentry chunk fee/feerate, getmempoolfeeratediagram, getmempoolcluster | RPC tests | S |
| **P10** | *(optional)* full SFL linearizer swap-in | Core linearize optimality vectors | M |

**MVP boundary = P0–P6**: cluster mining + chunk eviction + cluster limits, RBF unchanged. Real
value at low risk; P7+ separable.

**Synergy**: P7/P8 subsume three other Tier-4 backlog items — package RBF, sibling-eviction
acceptance, and the package-TRUC interaction — because Core implements all of them *via* the
diagram machinery.

## 7. Effort & risk

- ~15–22 PRs, multi-session; the largest Tier-4 item alongside real-assumeutxo.
- Risk is implementation churn, not safety (policy, not consensus). Hot spots: staging correctness
  (mitigated by scratch-copy-first) and reorg re-add (mitigated by P3 shadow asserts).
- Test leverage is excellent: Core ships portable vectors for every pure layer (feefrac_tests,
  cluster_linearize_tests, rbf_tests, txgraph fuzz corpora).
- FASL note: `mempool-entry`/`mempool` defstruct changes (P3) ⇒ deploy needs
  `rm -rf ~/.cache/common-lisp`.

## 8. Open decisions

1. **Scope**: run through P7-P9, or stop at the P0-P6 MVP and reassess?
2. **Linearizer**: is post-linearize-only acceptable indefinitely (suboptimal only on complex
   non-tree DAGs), or is SFL (P10) a committed goal?
3. **Staging**: scratch-copy simplification vs full COW overlay (recommend scratch-copy first).
4. **Constants**: Core-exact 64 / 101 kvB / 100-cluster RBF cap — recommend non-negotiable for
   relay compatibility.

## 9. Core source anchors

- Interface: `src/txgraph.h` (Ref :62/:232-253, API :78-216, MAX_CLUSTER_COUNT_LIMIT :18)
- Engine: `src/txgraph.cpp` (TxGraphImpl :390, lazy pipeline :782-796, Relinearize :2157,
  staging :2626-2719, diagrams :2810-2834, BlockBuilder :3159-3225, worst chunk :3258, Trim :3285,
  DoWork :3113)
- Algorithms: `src/cluster_linearize.h` (DepGraph :29-357, chunking :427-463, SFL :546-716,
  Linearize :1798-1836, PostLinearize :1854-2037)
- FeeFrac: `src/util/feefrac.h`, `src/util/feefrac.cpp` (CompareChunks :10-73)
- Mempool glue: `src/txmempool.h:261-737`, `src/txmempool.cpp:91-1102` (ChangeSet :994-1080,
  TrimToSize :861-911), `src/kernel/mempool_entry.h:65`
- Acceptance: `src/validation.cpp` (PreChecks :782-979, ReplacementChecks :981-1032,
  PackageRBFChecks :1034-1130, AcceptPackage :1619-1768, LimitMempoolSize :264-278)
- RBF policy: `src/policy/rbf.{h,cpp}`; limits `src/policy/policy.h:71-73`
- Mining: `src/node/miner.cpp:122-334`
- Docs: `doc/policy/mempool-design.md`, `doc/release-notes-33629.md`
