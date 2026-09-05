# GA11 dimension 6 - the files no gap analysis ever opened

Findings: `dim-never-opened.json`. Baseline `main` after the GA10 S1-S3 fixes; oracle Bitcoin Core
`d3056bc` under `refs/bitcoin/`. Method `docs/gap-analysis-method.md`; exclusions
`docs/gap-analysis-11-data/exclusions.md`.

## What was covered, and how

Container up for the whole pass (`bitcoin-lisp-sbcl:2.6.5-4`, `scripts/dev.sh` in this worktree).
Five of seven findings were reached by running code; the two read-only ones say so.

| file | read | executed probe |
|---|---|---|
| `src/node/entropy.lisp` | full | build-time `*random-state*` is a process constant (3 fresh SBCL children); `*random-state-seed*` is NIL after a system load; `save-lisp-and-die` freezes a load-time `(random ...)` defvar (positive control) |
| `src/node/eviction.lisp:92` (consumer) | full | live value read across an image restart |
| `src/serialization/message-macro.lisp` | full | verack bytes vs Core's canonical frame; 200 KB unsanitised user agent round trip; log-line forgery through `format-log-entry`; `:bool` byte 2; `:var-string` Latin-1 in both directions |
| `src/node/indexes.lisp` | full | none (crash matrix not run) - read against Core `index/base.cpp` |
| `src/node/notify.lisp` | full | none - read against Core `init.cpp:2009-2018` |
| `src/node/state.lisp`, `src/rpc/accessors.lisp` | full | lock sites enumerated by grep; the four documented rules checked against the `waitfor*` RPCs, the ban / scan / gbt / txoutset leaf locks, and the listener |
| `src/networking/fd-wait.lisp` | full | `sb-unix:unix-simple-poll` probed on a live pipe (POLLHUP, POLLNVAL, bogus fd) |
| `src/util/ratelimit.lisp` | full | call-graph check of the "one bucket, one thread" claim |
| `src/node/{sync,listen,housekeeping,wallet-hooks,mempool-persist,reindex,params}.lisp` | full | - |
| `src/storage/coins-view-migration.lisp` | full | - |
| `src/coalton/{serialization,binary,types,crypto}.lisp` | full | reachability grep: only `crypto` is on the consensus path |

## Cleared without a finding

`fd-wait.lisp` (poll semantics correct; the `:timeout nil` divergence has no caller);
`ratelimit.lisp` (invariant holds; the RPC bucket is lock-guarded, so the file comment understates
the safety); the `define-message` header codec (byte-identical to Core's verack frame); the
`-prune` incompatibilities with `-txindex` / `-txospenderindex` / `-reindex-chainstate` (all
present, matching `init.cpp:1002-1009`); `housekeeping.lisp`'s 50 MiB disk floor and `df` parsing;
`%account-message` (the GA1-9 raw-command accounting finding is fixed); `listen.lisp`'s accept loop
(the residual slow-loris shape is the already-excluded "inbound handshake inline on accept thread").

## Not covered - and who inherits it

- **Crash consistency.** No kill-then-restart matrix was run, so the coinstatsindex rewind and the
  txospenderindex gap (`be1b5ed4`) are both unreproduced. GA11 dimension 9 (validation/block.lisp +
  chain.lisp + coins-view-cache.lisp) inherits it.
- **The full lock audit.** 140 `node-lock` sites across 23 files were enumerated but not all read.
  `accessors.lisp` documents five leaf locks; the tree has at least twelve. Dimensions 10 (peer /
  protocol) and 8 (rpc) inherit the rest.
- **`src/coalton/{serialization,binary,types}.lisp` are dead outside tests** - nothing under `src/`
  but `src/coalton/package.lisp` names `bl.cser` or `bl.cbin`, and `bitcoin-lisp.coalton.script`
  imports only from `coalton.crypto`. Their missing BIP144 support, missing non-canonical
  CompactSize check and unbounded `read-bytes` are therefore unreachable from the network and are
  filed as no finding. The script-interpreter dimension should decide whether to delete them.
- **Deliberate, documented divergences not filed:** `load-mempool-from-disk` has no expiry filter
  where Core's `mempool_persist.cpp:100` skips and counts entries older than `m_opts.expiry` (and
  has no "already there" bucket); `do-reindex-chainstate` re-applies stored blocks without script
  re-validation. Both are stated in their own docstrings and bounded.
- **Out of assignment, still never opened:** `src/node/logging.lisp`, `src/rpc/output-script.lisp`
  (dimension 8), `src/util/context.lisp`, `src/util/conditions.lisp`,
  `src/wallet/signmessage.lisp`, `src/networking/minisketch.lisp`,
  `src/networking/txreconciliation-set.lisp`.
