A Bitcoin full node implementation in Common Lisp (SBCL).

Tech stack: ironclad (crypto), cffi + libsecp256k1 (ECDSA), usocket (networking), fiveam (tests).

Architecture: layered (crypto -> serialization -> storage/validation -> networking).
Use defstruct for data types, pure functions where possible, conditions/restarts for errors.
Consensus-critical code must match Bitcoin Core behavior exactly.

Reference implementation: refs/bitcoin/ (cloned Bitcoin Core repo) is the canonical spec.
When implementing consensus rules, read the corresponding Bitcoin Core source code directly.

Supported networks:
- Testnet (default): port 18333, RPC 18332
- Mainnet: port 8333, RPC 8332, relay disabled by default

Wallet: descriptor-only wallet in progress per docs/wallet-plan.md (no BDB/legacy
wallets, no BIP39). Wallet support is enabled by default on test networks,
default-OFF on mainnet (config flag `-wallet`); testnet4 first.

## Package prefixes

Cross-package references use the package-local nicknames installed by
`src/util/package.lisp` (`bitcoin-lisp.nicknames:*package-nicknames*`): `bl:` for the top
package, `bl.err`, `bl.bytes`, `bl.crypto`, `bl.ser`, `bl.store`, `bl.val`, `bl.mp`,
`bl.mining`, `bl.net`, `bl.rpc`, `bl.wallet`, `bl.interop`, `bl.script`, `bl.ctypes`,
`bl.cser`, `bl.cbin`, `bl.ccrypto`, `bl.tests`. Write `bl.ser:transaction-inputs`,
never the full name. A branch that predates the nicknames rebases and runs
`scripts/refactor/apply-nicknames.sh`. A file that DEFINES packages follows
its DEFPACKAGE forms with `(eval-when (:compile-toplevel :load-toplevel
:execute) (bitcoin-lisp.nicknames:install-package-nicknames))` — a warm-image
reload of a package file re-executes its DEFPACKAGE, which DROPS that
package's nicknames, and this call restores them.

## The development loop (cl-workbench managed, containerized warm image)

This is a Common Lisp Workbench managed project (`.cl-workbench/project.toml`,
execution profile container-required). Run `cl-workbench doctor --strict` from
the project root once per substantive session before the first build, eval, or
test. SBCL never runs on the host: every entry point below runs inside the
pinned project container (bitcoin-lisp-sbcl:2.6.5-4), and the warm image's Swank
port stays private to the container (evals are a docker exec of the Workbench
client; no host port is published). Container, session, and FASL-volume
identities are checkout-specific, so parallel checkouts never collide.

```
scripts/dev.sh start            # warm image in the project container
scripts/dev.sh eval '(+ 1 2)'   # ~0.3 s per eval
scripts/dev.sh test :bitcoin-core-script-tests   # one fiveam suite (raw designator)
scripts/dev.sh test-all         # full :bitcoin-lisp-tests (29k+ checks; long)
scripts/dev.sh docs-check       # PAX transcripts (docs/manual.lisp), cold container
scripts/dev.sh ui-test          # web UI node harness (tests/ui/), cold container
scripts/dev.sh stop
```

`cl-workbench repl eval FORM`, `test [SUITE]`, `docs verify`, and
`validation run warm-unit|cold-unit|cold-docs` route to these same entry
points through `.cl-workbench/adapter`.

Discipline: ground before writing (`dev.sh eval '(describe ...)'`, apropos);
develop in small evals; after editing, reload (`dev.sh eval '(asdf:load-system
"bitcoin-lisp")'`) and re-run the touched suite; defstruct/Coalton layout
changes require an image restart. **Changing a `defconstant`'s VALUE needs an
image RESTART** — `:force t` is not enough. Re-evaluating the definition
signals `SB-EXT:DEFCONSTANT-UNEQL`, a *continuable* error, and the warm image
ends up stale whichever way that goes:

- continued (interactive, or a handler that invokes CONTINUE) — the symbol
  takes the new value while callers compiled earlier keep the OLD value folded
  in. Observed 2026-08-16 retuning a rate limit: the symbol read 16384 while
  the caller still behaved as 32768.
- not continued (our batch `dev.sh eval` path) — the restart is never taken,
  so the symbol AND its callers both keep the OLD value, while the FASL on
  disk holds the new one. Observed 2026-08-18: after
  `(asdf:load-system "bitcoin-lisp" :force t)` the source read `(* 3 600)` but
  the image still reported 1800 for a constant edited to `(* 30 600)`; the
  suite passed green against a value no longer in the source. `dev.sh stop` +
  restart reported 18000 and the test went red.

Either way a test can pass against a value that is not in the source, so
`dev.sh stop` + `cl-workbench repl start` before trusting any result that
depends on a changed constant. The cold battery recompiles a changed file,
so it is unaffected by a constant edit, and it stays the verification of
record. Consensus-critical work still finishes with
`cl-workbench validation run cold-unit` (= scripts/docker-test.sh, check count
recorded) — the warm image is a dev convenience, not the verification of
record. A suite designator that selects zero tests fails (rc 1); it can never
pass silently. The cold lane also fails on `WARNING: redefining
BITCOIN-LISP` (a same-package duplicate silently winning) and on any
`undefined variable` warning that is not an earmuffed special defined
somewhere in the tree (`scripts/check-undefined-variables.sh`): ASDF's
compilation unit defers those warnings past compile-file's failure-p, so a
from-scratch build otherwise passes with them buried in the transcript —
2026-08-28 it hid a `setf` of a deleted defvar and six docstrings cut short
by an unescaped `"` whose remaining prose had become code.

**Changing a MACRO (or a defstruct's layout) needs a FRESH FASL volume** —
the cold lane is not "compiles fresh": it mounts a persistent per-checkout
volume, and ASDF does not track macro expansions, so every file that USED the
macro keeps its stale expansion through a warm rebuild, an image restart AND
an ordinary cold run (observed 2026-08-19: three misdiagnoses including a
false bisect). `cl-workbench validation run cold-unit-fresh`
(= `scripts/docker-test.sh --fresh-fasl`) runs the battery on a brand-new
volume that is removed afterwards; it costs the Coalton build, a few minutes.
Any PR that changes a macro or a defstruct verifies with it.

Eval exit codes: 0 ok / 1 lisp error (+backtrace) / 2 connection (image down,
NOT your code — dev.sh start) / 3 timed out+interrupted (image survives;
raise DEV_EVAL_TIMEOUT for long forms) / 4 hard hang. NOTE: heavy FFI calls
(libsecp256k1, LevelDB) cannot be interrupted mid-call — a long foreign call
may show up as rc=4 even though the image recovers when the call returns.
Workbench appends payload-free outcome events under `.cl-workbench/state/`
(git-ignored); the Claude Code paren hook logs to
`.cl-workbench/state/paren-hook.log`. The hook stanza in
`.claude/settings.json` is tracked (see `.gitignore`), so it fires in every
clone and worktree. Legacy `.dev-runtime/` state is retired — do not read,
import, or delete it.

## Recording lessons

When you write a `⚠️` in a commit message or a doc because something here was
a trap, record it in the same turn:

    ~/.claude/skills/develop-common-lisp/scripts/lesson add SLUG "what happened and what to do" "bitcoin-lisp#<PR> or docs/<file>"

(blockchain-specific traps: add `--skill develop-blockchain-with-common-lisp`
before SLUG). No branch, review, or approval is needed for the log line. Exit 3
(REPEAT) means the slug already exists and prose did not stop the trap: do not
add a second line — add a check that fires mechanically here (dev.sh, the
adapter, or a test with a positive control) and append `→ guard <where>` to
the existing line. The full rule is the `develop-common-lisp` skill's
"Recording lessons" section.
