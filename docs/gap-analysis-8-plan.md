# GA8 remediation plan

Implementation plan for the findings in `docs/gap-analysis-8.md`. Written to be
executed by a separate implementing agent (Opus 5) without re-deriving the
analysis. Every task below cites the exact edit sites, the Core reference that
defines correct behaviour, the pitfalls that adversarial verification surfaced,
and the tests that must exist before the task counts as done.

Baseline: `main` @ `0074bf1`. Branch every task off `main`, not off the current
`net-g7-08-eclipse` working branch (except W3, which edits the open PR branches).

---

## 0. Ground rules for every task

**Toolchain.** All Lisp runs in Docker; never on the host. `scripts/docker-sbcl.sh`
and `scripts/docker-test.sh` hardcode the **shared** FASL volume
`bitcoin-lisp-fasl` — concurrent agents must NOT share it (it corrupts silently).
Each agent picks a slug `ga8-<task-letter>` and runs Docker directly instead:

```bash
docker run --rm -i --label agent=ga8-X \
  -v "$PWD:/workspace" -v ga8-X-fasl:/fasl-cache -w /workspace \
  bitcoin-lisp-sbcl:2.6.5-2 sbcl --dynamic-space-size 4096 --non-interactive \
  --eval '(asdf:load-system "bitcoin-lisp/tests")' \
  --eval '(let ((r (fiveam:run :bitcoin-lisp-tests)))
            (fiveam:explain! r)
            (unless (fiveam:results-status r) (sb-ext:exit :code 1)))'
```

Tear down only your own slug at the end (`docker volume rm ga8-X-fasl`). Never
prune, never touch another agent's containers/volumes/images. Load
`~/.claude/skills/common-lisp/SKILL.md` before writing Lisp.

**Worktrees.** Tasks that run in parallel use an isolated git worktree. `refs/`
is gitignored, so a fresh worktree has no Bitcoin Core reference and
`docker-sbcl.sh` refuses to start. After creating the worktree:

```bash
cp -R /Users/sen/common-lisp/bitcoin-lisp/refs .      # ~89M: refs/bitcoin + refs/coalton
cp -R /Users/sen/common-lisp/bitcoin-lisp/tests/data tests/   # 4K, if absent
```

Symlinks are invisible inside the container — real copies only.

**A `defstruct` change requires clearing your FASL volume** (`docker volume rm
ga8-X-fasl`). ASDF's timestamp check does not notice; the symptom is "attempt to
redefine the STRUCTURE-OBJECT class ... incompatibly".

**Mutation testing is mandatory** (skill §7) for every behavioural fix: revert
the source change, confirm the new tests go RED, restore, confirm GREEN. **Before
running a mutation, assert that the patch text was actually found** — a green
mutation run is otherwise indistinguishable from a no-op patch, which has bitten
this project twice.

**Definition of done per task:** full suite green (28,383 baseline, expect growth),
every new test mutation-verified, `/simplify` run over the diff, PR opened.
**Do not merge.** Consensus-critical PRs (W1-A, W1-B, W2-D, W2-E) need adversarial
review and user sign-off first, as the GA7 taproot fixes did. **Do not deploy or
restart any node.**

**Sequencing.** W1-A, W1-B, W1-C are file-disjoint and run in parallel. W2-D and
W2-E both edit `src/validation/block.lisp` and must wait for W1-A to land (or
branch off W1-A's branch and rebase). W3 edits the open PR branches and is
independent of everything else.

---

## Wave 1 — parallel

### W1-A. Intra-block coin overlay: script-skip + double-spend (S1-1, S1-2)

Two findings, one root cause: the intra-block overlay tracks created coins but
not consumed ones, and is not threaded into script validation. They compose into
a theft primitive, share a file and a test fixture, so they are one task.
**Both halves of each fix must land together** — half of S1-1 alone turns silent
acceptance into spurious rejection of honest chained blocks.

Files: `src/validation/block.lisp`, `src/validation/transaction.lisp`,
`src/storage/coins-view-cache.lisp`.

**Part 1 — thread the overlay into script validation.**
- `validate-block-scripts` (`block.lisp:682`) currently takes `(block utxo-set &key (height 0))`.
  Add `&key extra-coins`; do the same for `validate-block-scripts-parallel`.
- `validate-tx-scripts` (`block.lisp:604-636`) passes `extra-coins` to
  `collect-spent-utxos` as its existing third positional argument.
- Call site `block.lisp:1321-1325`: pass `:extra-coins pending-utxos`.
- Parallel path caveat: `pending-utxos` is fully populated by the loop at
  `block.lisp:1272-1297`, which completes before line 1321, and is read-only
  afterwards — so it is safe to share with workers. Verify this still holds after
  your edit.
- Side benefit to preserve: a complete `spent-utxos` vector is what
  `init-precomputed-sighash` needs for a chained **taproot** spend; today it is
  NIL. Add a test for a chained taproot spend.

**Part 2 — fail closed.**
- `validate-tx-scripts` (`block.lisp:610-613`): a NIL `spent-utxos`, or a NIL
  element within it, must return invalid (mirroring Core's
  `assert(!coin.IsSpent())` in `CheckInputScripts`), never skip.
- `validate-transaction-scripts` (`transaction.lisp:1129-1136`) carries the
  identical fail-open shape. It is latent today (the mempool path pre-rejects
  with `:missing-input` at `transaction.lisp:832-834`) — harden it anyway; it is
  one refactor away from becoming live.

**Part 3 — per-block spent-outpoint tracking.**
- `block.lisp:1235-1237`: add `(spent-outpoints (make-hash-table :test 'equalp))`
  beside `pending-utxos`.
- `validate-transaction-contextual` (`transaction.lisp:101-136`): add a
  `spent-outpoints` key; a prevout present in that table is treated as **absent**,
  falling into the existing `:missing-input` return (our name for Core's
  `bad-txns-inputs-missingorspent`).
- `block.lisp:1272-1297`: after each transaction validates, mark every one of its
  input outpoints in `spent-outpoints`, **then** add its outputs to
  `pending-utxos`. Order matters — this is Core's `UpdateCoins` (spend inputs,
  then add outputs, `validation.cpp:2597`). Skip the coinbase's null prevout.
- This also closes re-spending an intra-block *output*, defective today for the
  same reason.

**Part 4 — defence in depth.**
- `coins-view-cache.lisp:368-370` and the legacy `utxo-set` branch at `:528-537`:
  log an error when `coin-view-spend` returns NIL for a non-coinbase input,
  instead of silently continuing. Core asserts here.

**Pitfalls.** The fix must sit *after* the `context-free-only` early return
(`block.lisp:1215`) so fork blocks get it exactly when their contextual checks
run. All other entry points (`activate-block` 2627/2703, `perform-reorg` 2306,
`accept-downloaded-block` protocol.lisp:911/925, `test-block-validity` 1383)
funnel through the same `validate-block` and need no separate change.
`%verify-tx-scripts` (`rpc/wallet-spend.lisp:1840-1862`) is already fail-closed —
leave it alone.

**Tests** (all through `validate-block`, not just the inner helpers):
1. Chained same-block spend with an **invalid** signature ⇒ block rejected.
   Control: identical scriptSig against a **confirmed** parent ⇒ also rejected
   (proves the test is not vacuous).
2. Chained same-block spend with a **valid** signature ⇒ block still accepted.
3. **Mixed-input**: one same-block input + one confirmed input carrying a bad
   script ⇒ rejected. This is the theft-escalation case and must not be omitted.
4. Two transactions in one block spending the same prevout ⇒ rejected with
   `:missing-input`. Control: the same block with only one of them ⇒ accepted.
5. A transaction spending an output created earlier in the same block, then a
   third spending that same output again ⇒ rejected.
6. Fee accounting: the double-spend block must no longer produce an inflated
   coinbase ceiling. Assert on the rejection, and keep a test that the legitimate
   single-spend fee total is unchanged.
7. Chained taproot spend validates (precomputed sighash present).

Working reproductions from the analysis are in the session scratchpad
(`repro.lisp`, `dsp.lisp`, `dsp2.lisp`) and are a good starting point for
fixtures.

### W1-B. Tapscript resource limits and annex weight (S1-3, S1-4)

Files: `src/coalton/script.lisp`, `src/coalton/interop.lisp`. Two findings, same
files, so one task; keep them as two commits.

**Part 1 — the 520-byte push limit applies in tapscript.**
- `script.lisp:2256-2258`, `:2280-2282`, `:2306-2308`: drop the
  `(not (flag-enabled "TAPSCRIPT"))` conjunct so the check is unconditional.
- Correct the three comments claiming "BIP 342 removes this 520-byte cap" — it
  does not. Core proves it structurally: `MAX_SCRIPT_SIZE`
  (`interpreter.cpp:428`) and `MAX_OPS_PER_SCRIPT` (`:451-455`) are
  sigversion-gated, while the push check at `:447-448` between them is not.
- **Do not touch** the correctly-gated script-size check (`script.lisp:2176-2178`)
  or op-count gate (`:2223-2231`) — tapscript genuinely disables those.
- Only PUSHDATA2/PUSHDATA4 can exceed 520 in practice; fix all three sites anyway.

**Part 2 — initial witness stack limits.**
In `validate-taproot-script-path` (`interop.lisp:2947-3005`), insert **after** the
OP_SUCCESS scan's `(values t nil)` return (`:2987-2988`) and **before** the
weight-binding `let` (`:2997`), in this order:
1. `(> (length script-inputs) 1000)` ⇒ `:stack-size`. Strictly `>` — 1000 passes,
   1001 fails.
2. per item, `(> (length item) 520)` ⇒ `:push-size`, mirroring the correct v0
   check at `interop.lisp:2727-2730`.

**Placement is load-bearing.** Core's OP_SUCCESS scan overrides both limits
(`interpreter.cpp:1837`), so checking before the scan would itself be a new
divergence. Core's own order in `ExecuteWitnessScript` is: OP_SUCCESS scan →
stack-count → element-size → eval (`interpreter.cpp:1854-1861`).

**Part 3 — annex in the validation-weight budget.**
`validate-taproot` (`interop.lisp:3019-3030`) strips the annex with
`(setf witness (butlast witness))` before dispatching, and the budget at
`:2997-2999` is computed over the stripped list. Core computes it over the
original `witness.stack`; the pops at `interpreter.cpp:1951-1968` are
`SpanPopBack` on a *view* and never shrink the vector (`span.h:73-81`).
- Add an optional `full-witness` parameter to `validate-taproot-script-path`,
  pass the original list from `validate-taproot` **before** the `butlast`, and use
  it at `:2998`.
- Prefer this over the arithmetic shortcut (`+ CompactSize(len) + len`): threading
  the untouched stack mirrors Core's structure and survives future stack-shape
  changes.
- `compute-witness-serialization-size` (`interop.lisp:944-951`) is already
  byte-exact — do not modify it.

**Tests.**
1. Tapscript with `OP_PUSHDATA2 <600 bytes> OP_DROP OP_1` ⇒ rejected `:push-size`.
   Control: the same script under witness v0 ⇒ already rejected (unchanged).
2. Witness argument of 600 bytes with script `OP_DROP OP_1` ⇒ rejected.
   (The obvious `OP_SIZE <0x5802> OP_EQUAL` variant fails cleanstack first and
   would be a vacuous test — do not use it.)
3. 1001 initial witness items + a leading `OP_DROP` ⇒ rejected `:stack-size`;
   1000 items ⇒ accepted (boundary both sides).
4. All three above with a leaf script containing an **OP_SUCCESS** opcode ⇒
   **accepted**, proving the checks sit after the scan.
5. Annex budget: a script-path spend with an n-byte annex and k CHECKSIGs sized
   so `50k` falls between the stripped and full budgets ⇒ must now be accepted.
   Assert on the computed budget directly as well, since no existing test covers
   initialisation (the BIP341 tests bind `*tapscript-validation-weight-left*`
   directly and would not catch a regression).

### W1-C. RPC authentication (S1-6)

Files: `src/rpc/server.lisp`, `tests/rpc-tests.lisp`, and the `-rpcbind` handling
in `src/config.lisp` / `src/node.lisp`.

This is the only finding that is live and exploitable today. Highest priority,
smallest fix — but read the compatibility note first.

**⚠️ This reverses a deliberate design decision, not an oversight.** `check-auth`'s
own docstring says so: *"With nothing configured, allow open local RPC (our nodes
bind 127.0.0.1) — a .cookie is still written so stock bitcoin-cli, which always
sends credentials, authenticates; existing unauthenticated local clients keep
working."* The reasoning was defensible when written; it is wrong now that the
node runs a loaded wallet on a multi-user host, and it silently diverges from
Core, whose cookie file *is* the local access boundary. Proceed with the fix —
but treat it as a behaviour change with a blast radius, not a typo:

- **Audit every in-repo client before landing.** Anything that talks to our RPC
  without credentials will start receiving 401s: the `/ui/` SPA dashboard
  (`src/rpc/ui.lisp` and its front-end fetches), any `scripts/` helper, the GUI
  console, and monitoring/health checks. Each must be taught to read the cookie
  file. Grep for RPC callers that construct requests without an `Authorization`
  header.
- **Same-origin browser clients need explicit thought**: the UI SPA cannot read a
  0600 file from JavaScript. Decide deliberately — either the server injects the
  credential into the served page, or the UI routes through an authenticated
  server-side path, or `/ui/` is documented as requiring `-rpcuser`. Do not
  quietly exempt `/ui/` from auth; that recreates the hole behind a different door.
- **Flag operator impact in the PR**: the live node is driven by scripts on the
  server that may pass no credentials. Landing this without updating them turns a
  security fix into an outage. List what needs updating server-side; do not deploy.
- If the audit turns up something that genuinely cannot carry a credential,
  raise it rather than widening the exemption — an opt-in `-rpcallowlocalanon`
  style escape hatch is a last resort, off by default, and must be argued for.

1. **Make the cookie a real credential.** In `start-rpc-server`
   (`server.lisp:627-703`), after `generate-rpc-cookie` succeeds and when no
   `-rpcuser`/`-rpcpassword` was configured, set `*rpc-user*` to the cookie user
   (`__cookie__`) and `*rpc-password*` to the generated secret. Core's shape: the
   cookie pair is pushed into `g_rpcauth` (`httprpc.cpp:275-288`). This single
   change closes the hole and keeps `check-auth`'s existing structure.
   Today the cookie is written only when user+password are *absent* while the
   cookie comparison at `server.lisp:438-440` runs only when they are *present* —
   mutually exclusive, so that branch is currently unreachable in every
   configuration. Verify it is reachable after your change.
2. **Make `check-auth` unconditional** (`server.lisp:495-497`): an absent or
   malformed `Authorization` header ⇒ NIL. `rpc-handler:535-537` already emits
   `401` + `WWW-Authenticate` when `check-auth` returns NIL
   (`httprpc.cpp:112-117`), so no handler change is needed.
3. **Cookie file permissions — the file must be 0600 *from creation*, not
   chmod-ed afterwards.** (Corrected 2026-07-26: an earlier revision of this plan
   said "chmod to 0600 after writing", which review showed is defeatable and is
   the wrong instruction.) `with-open-file` creates the temp file `#o666 & ~umask`,
   and the live host runs umask 002 — which is exactly why its cookies are 0664 —
   so the file exists world-readable *while the secret is written into it*. POSIX
   checks permissions only at `open(2)`, so any local user who opens it at
   creation keeps a valid fd across both the chmod and the rename. Watching the
   datadir makes that deterministic across a restart. Create it atomically
   instead: `sb-posix:open` with `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` and mode
   `#o600`, or set `sb-posix:umask #o077` around the write and restore it in an
   `unwind-protect`. `O_EXCL|O_NOFOLLOW` also closes a second hole:
   `:if-exists :supersede` plus `(truename tmp)` would follow an attacker-planted
   `.cookie.tmp` symlink and then rename the *resolved target* over `.cookie`.
   Core needs none of this because it sets a process-wide umask 0077
   (`common/system.cpp`), so `request.cpp:109-123` is 0600 from creation and
   `fs::permissions` is only called for an explicit `-rpccookieperms`.
3b. **Generate the cookie only after the acceptor binds.** Core's order is
   `InitHTTPServer` (binds the sockets) → `StartHTTPRPC` →
   `InitRPCAuthentication` → `GenerateAuthCookie`, so a port conflict aborts
   before any cookie is touched. Writing it first means a second process started
   on a live datadir — which has happened here, when `restart-node.sh`'s pkill
   marker failed to match the running supervisor — overwrites `.cookie` with a
   secret matching nothing, fails to bind, and exits, while the healthy node
   keeps serving the old secret in memory. Every client that re-reads the cookie
   then gets 401 from a node that is perfectly fine, and the surviving process
   logs nothing. Harmless before this task (nothing checked the credential);
   after it, one accidental double-start locks every client out of a live,
   wallet-loaded node. Install the credential after `hunchentoot:start` succeeds
   — safe, because the dispatcher is fail-closed while `*rpc-user*` is still NIL.
4. **Constant-time comparison** in `%basic-auth-matches-p` (`server.lisp:437,440`
   use `string=`; Core uses `TimingResistantEqual`, `httprpc.cpp:67,76`), and
   `(sleep 0.25)` before returning 401 on a *wrong* credential — not on a missing
   one (`httprpc.cpp:124-133`).
5. **Delete the cookie on shutdown** (`stop-rpc-server`), matching Core's
   `DeleteAuthCookie`.
6. **`-rpcbind` guard**: refuse, or at minimum loudly warn, on a non-loopback
   bind, mirroring Core's rule that `-rpcbind` is ignored without `-rpcallowip`
   (`init.cpp:708`). We have no `-rpcallowip` at all, so today one flag makes the
   node world-open. A real `-rpcallowip` implementation is GA7 G7-33 and stays out
   of scope here.

**Test debt — this is part of the task, not optional.** Two existing tests
currently protect the hole:
- `rpc-auth-check-no-credentials` (`tests/rpc-tests.lisp:1083-1088`) asserts
  `(is (check-auth nil))`. It will fail on the fix. Rewrite it to assert the
  opposite.
- `rpc-basic-auth-and-cookie` (`:1913-1923`) binds `*rpc-user*`, `*rpc-password*`
  **and** `*rpc-cookie-secret*` simultaneously — a state `start-rpc-server` can
  never produce, making it vacuous. Rewrite it to exercise a state startup can
  actually produce.
- Add an end-to-end test through `rpc-handler`: no header ⇒ 401 with
  `WWW-Authenticate`; wrong credential ⇒ 401; correct cookie credential ⇒ 200.
- Add a test asserting the cookie file mode is 0600.

---

## Wave 2 — after W1-A lands (same file)

### W2-D. P2SH sigop counting (S1-5)

File: `src/validation/block.lisp`.

Core's `GetScriptOp` clears its data buffer for every opcode and refills it only
for `opcode <= OP_PUSHDATA4` (`script.cpp:313-359`), so `OP_0`, `OP_1NEGATE`,
`OP_RESERVED` and `OP_1..OP_16` yield an **empty** subscript — zero sigops — while
not tripping the `opcode > OP_16` early-out. `GetSigOpCount(scriptSig)`
(`script.cpp:183-205`) also returns 0 on any `GetOp` failure or any opcode above
`OP_16`.

Add a **sigop-specific** helper and use it at `block.lisp:1056` and `:1062`:
- walk with strict bounds; on any truncated push ⇒ return NIL (⇒ 0 sigops)
- `opcode > OP_16` ⇒ return NIL
- `opcode <= OP_PUSHDATA4` ⇒ set the remembered range to that push's data,
  including the empty range for `OP_0`
- `OP_1NEGATE` / `OP_RESERVED` / `OP_1..OP_16` ⇒ **reset the remembered range to
  empty** (this is the actual bug) and advance
- return the final remembered range

Because Core's function returns 0 exactly when the scriptSig is not push-only,
this one helper simultaneously supplies the `IsPushOnly` gate that the
P2SH-wrapped-witness branch requires (`interpreter.cpp:2152-2163`).

**Do not repoint** `extract-last-push`'s other three consumers
(`transaction.lisp:270,612,896`) — those are policy/standardness redeem-script
extraction with different semantics.

**Tests.** P2SH committing to the empty redeem script, spent with
`<520 bytes of OP_16 OP_CHECKMULTISIG> OP_0` ⇒ counts 0 sigops (today: 4160).
Five such inputs in one block ⇒ block accepted (today: rejected `:too-many-sigops`).
Add cases for a trailing `OP_1NEGATE`, a trailing opcode above `OP_16`, and a
truncated push. Also assert the standardness side: such a transaction is no
longer rejected for exceeding `+max-standard-tx-sigops-cost+`. There is currently
**no** test for `extract-last-push` (the similarly-named test at
`tests/bitcoin-core-script-tests.lisp:629` covers a different function).

### W2-E. Header median-time-past (S1-7)

Files: `src/validation/block.lisp`, `src/networking/ibd.lisp`.

`compute-median-time-past` (`block.lisp:100-118`) walks by index lookup and
returns literal `0` for an unknown hash, so the guard at `ibd.lisp:780-785`
(`(<= timestamp mtp)`) is vacuously false for any header whose in-batch
predecessor is not yet indexed. The batch already threads a staging chain
(synthetic entries with correct `prev-entry`, `ibd.lisp:842-849`) and **every
other contextual check uses it** — only MTP does a hash lookup.

**Primary fix.** Add `compute-median-time-past-from-entry` in the validation
package; make the existing hash-keyed function a lookup-then-delegate wrapper;
call the entry version from `validate-header-chain` using the `parent` entry it
already holds. The correct walk already exists as `hss-median-time-past`
(`src/networking/headers-sync.lisp:148-158`), which is exactly
`GetMedianTimePast(pindexPrev)` — reuse its shape. Median index arithmetic
already matches Core for partial windows.

**Secondary fix — make the fallback loud.** Returning `0` for an unknown hash is
a silent fail-open in a consensus comparison; had it signalled, this bug could
not have existed. Return NIL for "not in index" and treat NIL as reject/error at
the two consensus sites (`block.lisp:541-544`, `ibd.lisp:780`), keeping a
`0`/NIL-tolerant default at the informational callers, all of which pass a known
hash today: `block.lisp:1301`, `transaction.lisp:844`, `mining/assembler.lisp:215`,
`rpc/methods.lisp:60/253/2691-2694`, `rpc/wallet.lisp:1133`.

**Do not** fix this by dropping `:skip-header t` from `perform-reorg`. That
diverges from Core (`ConnectBlock` deliberately does not re-run
`ContextualCheckBlockHeader`) and, per the comment at `block.lisp:1106-1108`,
would spuriously fail PoW on deserialised fork bodies that carry no cached hash.
If belt-and-braces is wanted, re-run only the timestamp checks in PHASE B.

**Scope note (verified):** no other contextual rule shares this defect —
future-time, difficulty/`GetNextWorkRequired`, BIP94, version gates and PoW all
consume the threaded parent entry and correctly reject at batch position 2. Do
not "fix" them.

**Tests.**
1. Two-header batch where header 2's `nTime <= MTP(header 1)` ⇒ batch rejected.
   Control: the same two headers delivered as two separate batches ⇒ the second
   is already rejected today (proves the fixture is real).
2. A valid two-header batch still accepted (no false positive).
3. Reorg path: a fork whose non-final block violates MTP ⇒ `perform-reorg`
   refuses. Control: `validate-block` without `:skip-header` already rejects it.
4. `reconsiderblock` with such a block as the reorg target ⇒ refused.
5. Regression guards that the other contextual rules still reject at batch
   position 2 (cheap, and documents the verified scope).

**Residual to note in the PR:** headers already admitted to a persisted index
before this fix are never re-validated (the already-have branch skips them).

---

## Wave 3 — open PR defects (do before merging 309–314)

Edit the existing PR branches; these are corrections to unmerged work.

- **PR 314 — protection slots leak (S2).** `release-outbound-protection`
  (`ibd.lisp:2352-2357`) has no production caller, so `*protected-outbound-count*`
  only ever increments; after one churn cycle no peer can earn eclipse protection
  again, inverting the feature. Call it from `disconnect-peer`
  (`peer.lisp:339-359`) and the node.lisp replace/health paths, asserting it never
  goes negative (Core `FinalizeNode`, `net_processing.cpp:1717-1718`). Test:
  protect 4 peers, disconnect them, verify a fifth can then be protected.
- **PR 311 — disconnect fires on shapes Core never evaluates (S2).**
  `maybe-disconnect-low-work-outbound` runs after *every* branch of
  `ingest-headers-from-peer` (`ibd.lisp:2576`, `:2640-2641`). Core early-returns
  for empty batches (`net_processing.cpp:2969-2981`), unconnecting headers
  (`:3029-3040`) and presync (`:3065-3074`); the check lives only in
  `UpdatePeerStateForReceivedHeaders`, reached solely on the stored path
  (`:3113`). Move it there and delete the incorrect justification comment at
  `ibd.lisp:2634-2639`. Test: a BIP130 announcement with an unknown parent during
  IBD must not disconnect.
- **PR 313 — HB selection (S3).** `forget-hb-announcing-peer` has no call site;
  promotion happens before block validation (Core promotes only on
  `state.IsValid()`, `net_processing.cpp:2219-2223`); full-block deliveries never
  promote. Wire the first, move promotion after validation, and add the
  full-block path.
- **Unseeded `*random-state*` (S3).** PR 310's cache-expiry jitter and PR 312's
  feefilter draws are identical on every start. Seed from the CSPRNG at startup,
  as PR 309 correctly did. This is a **generic SBCL lesson** — add it to
  `~/.claude/skills/common-lisp/SKILL.md` per that file's §0.
- **Merge order.** PR 309 and PR 312 both insert a peer `defstruct` field immediately
  after `(version nil)`; PR 312's node.lisp hunk was cut against a pre-`06384db`
  base. Textual conflicts are guaranteed — re-diff the second merge, because a
  silently dropped hunk disables a feature without failing a test.

---

## Wave 4 — network S2 cluster (restores the anti-eclipse posture)

- **Address ingestion window.** `%ingest-gossiped-address`
  (`protocol.lisp:1031-1033`) *discards* addresses outside ±3h; the window gates
  storage, not relay. Delete it. Instead: if `timestamp <= 100000000` or
  `> now+600`, rewrite to `now - 5 days` (`net_processing.cpp:4090-4092`), then
  store with Core's 2-hour penalty (`:4114`). Leave the relay gate at `:1046`
  untouched — it is already Core-correct. Aged entries are handled where Core
  handles them, at selection time (`addr-info-terrible-p`). Also add Core's
  service-bit filter (`:4087`). Test: an address with a 20-day-old timestamp is
  stored but not relayed.
- **Proxied DNS seeding (regression from PR 306).** `%reachable-seed-addresses`
  (`node.lisp:3011-3030`) drops hostnames, but under `-proxy` the seed list is
  deliberately hostnames for SOCKS5 to resolve. Change the predicate to
  `(if net (reachable-network-p net) proxy-configured-p)`, mirroring
  `net.cpp:2356-2357`. This cannot reopen the G7-03 leak: with `-onlynet`
  excluding clearnet the DNS query is already soft-disabled upstream
  (`config.lisp:1050-1054`), and without a proxy `discover-peers` never emits
  hostnames. Test: `-proxy` + no `-onlynet` ⇒ seed hostnames survive the filter;
  `-onlynet=onion` ⇒ no clearnet dial.
- **Compact-block punishment.** In `handle-cmpctblock`, look up the parent in the
  index *before* reconstruction; if absent, send `getheaders` and return
  (`net_processing.cpp:4571-4577`). On validation failure at
  `protocol.lisp:2449-2451` and `:2524-2526`, fall back to `request-full-block`
  instead of `record-misbehavior` — **per failure reason, not for every failure.**
  (Corrected 2026-07-26: an earlier revision said "keeping punishment only for
  structurally malformed messages". That is too coarse; it was implemented
  literally and produced a *demonstrated* DoS regression where a peer replays
  invalid-PoW compact blocks indefinitely on one connection, each costing a full
  `build-shortid-map` SipHash pass over every mempool entry. Measured: `origin/main`
  discourages and disconnects on the first message; the over-broad fix left the peer
  `:READY` and merely sent a getdata.) Core's `via_compact_block` exemption covers
  only `BLOCK_CONSENSUS`, `BLOCK_MUTATED` and conditionally `BLOCK_CACHED_INVALID`
  (`net_processing.cpp:1920-1926`) — two of seven switch arms.
  `BLOCK_INVALID_HEADER`, `BLOCK_INVALID_PREV` and `BLOCK_MISSING_PREV` call
  `Misbehaving` **unconditionally** (`:1936-1945`), and Core reaches them on this
  exact path: `ProcessNewBlockHeaders({{cmpctblock.header}}, ...)` at `:4589` calls
  `MaybePunishNodeForBlock(..., via_compact_block=true, "invalid header via
  cmpctblock")` at `:4591`. Map our failure reasons onto Core's arms individually.
  While here, delete the dead dedup guard at `:2424-2427` — it
  tests `:connected`, which is not in the status enum (`storage/chain.lisp:17`).

---

## Wave 5 — operations and storage

- **Supervisor shutdown race (live on both nodes).** `stop-node` flips
  `node-running` nil *first* (`node.lisp:2745`) and flushes *after*
  (`:2809-2838`), while the watchdog exits 10s later (`scripts/run-node.sh:84-95`).
  Change the internal stop paths (RPC `stop`, `-stopatheight`, disk-abort) to only
  *request* shutdown, and let the main thread run `stop-node` itself, with an
  idempotence guard (`stop-node` is not currently concurrent-safe). In the
  wrapper: exit 0 ⇒ stop for good, exit 1 ⇒ stop or bounded backoff, 7/crash ⇒
  respawn. Drop the `|| true` at `:91` that makes the logged exit code always 0.
  **The same change must be applied to the two live supervisor scripts on the
  server** (`/data/bitcoin-lisp/testnet4-supervisor.sh` and the mainnet inline
  one) — coordinate that separately with the user; it is a deploy action.
- **coinstatsindex rewind.** In `%catch-up-coinstatsindex`
  (`node.lisp:1215-1248`) stop blessing records by existence. Read the meta best
  `(height, hash)`, and if that hash is not the active chain's hash at that
  height, walk the header index back to the last common ancestor and set best
  there before backfilling — the `Rewind` equivalent (`index/base.cpp:290`),
  requiring no record-format change. Optionally write record+meta in one
  `WriteBatch` and error on stale-hash queries in `%gettxoutsetinfo-from-index`.
  Fixing the supervisor removes this bug's most likely trigger but not the bug.
- Remaining storage S2s from the report, unverified by execution and needing a
  confirmation pass first: torn `txindex.dat` trailing entry; corrupt
  `chainstate.dat` starting silently at height 0 (which then poisons the real
  chain via the deterministic-invalid allowlist); the 600s `destroy-thread`
  landing mid-reorg.

---

## Wave 6 — RPC contracts (one batch, ordered by client breakage)

1. **JSON-RPC 1.x reply shape.** Thread `version` and id-presence into
   `make-rpc-response` / `make-rpc-error-response` (`server.lisp:330-349`): for
   `:v1` omit `jsonrpc`, always emit both `result` and `error` with one null, and
   omit `id` when the request had none (`request.cpp:51-68`). Keep the V2 shape
   otherwise. This breaks python-bitcoinrpc on every call today.
2. **Empty collections encode as `null`.** Fix per-site — NIL is ambiguous at the
   encoder, so a global normalizer is wrong. `(or … #())` for arrays and
   `(or … (make-hash-table :test 'equal))` for objects at the ~11 node-side sites
   listed in the report. Note `getrawmempool`'s empty verbose case must be `{}`,
   not `[]`.
3. **`getblockheader`**: add `nTx` (helper `%entry-tx-count` exists at
   `methods.lisp:2614`); emit `previousblockhash` only when a parent exists.
   Add `coinbase_tx` to `getblock` (lower priority).
4. **`getblockstats`**: accumulate witness-inclusive per-transaction size and
   `total_out` skipping the coinbase, with no header; divide `avgtxsize` by
   `ntx-1`; raise `-8` for unknown stat names. Implement the fee statistics from
   undo data (already stored). Note `outs` is currently correct — Core counts
   outputs before the coinbase `continue`.
5. **`/rest/headers`**: return empty unless the start entry is on the active
   chain; the helper `entry-on-active-chain-p` already exists and is used by
   `merkleproof.lisp:234`.

---

## Wave 7 — mempool package relay

Add Core's reconsiderable-rejects filter and opportunistic 1-parent-1-child
package relay (`node/txdownloadman_impl.cpp:454-466`, `:297-321`, `:544-551`,
`:371-396`, `:125-148`). Today a CPFP package whose parent is below the fee floor
is permanently black-holed: the parent is cached as rejected, the child orphaned,
and the re-sent parent dropped before validation — so modern LN fee-bumping
packages never enter our mempool. `validate-package-for-mempool` already exists
but is reachable only from the `submitpackage` RPC. Also: orphan intake must
tolerate exactly one reconsiderable parent, and post-validation add failures
(`:mempool-full`, `:too-large-cluster`) should be cached
(`validation.cpp:1399-1402`).

---

## Wave 8 — remaining GA7 backlog (53 items: 12 S2 + 41 S3)

Unchanged from `memory/ga7_synthesis.json`; no S1s remain in it. Highest value
first: G7-07 wallet encryption + backup (still the bar to a mainnet wallet),
G7-21 fee estimator port, G7-24 taproot script-path descriptors, G7-23 ZMQ, and
G7-08 P3 (stale-tip trigger + outbound rotation) once W3 has made P1/P2
Core-faithful. The test-vector wave (G7-25/26, G7-62–69) is pure `tests/` and can
run in parallel with any source wave.

---

## Standing lessons to apply while implementing

- **A silent fail-open default is the shared root cause** of S1-1, S1-7 and the
  RPC auth hole: returning `0`, NIL or T when data is missing. When you touch a
  helper that returns a neutral value on absence, ask whether a consensus or
  security comparison consumes it.
- **Coverage counted by proximity is not coverage.** Every S1 here sits where a
  test exists nearby and appears to cover the area. When adding tests, add the
  control that must fail.
- Two tests in the suite currently assert buggy behaviour or are vacuous by
  construction (both in `tests/rpc-tests.lisp`, W1-C). Expect more of this
  pattern; a test that cannot fail is worse than no test.
