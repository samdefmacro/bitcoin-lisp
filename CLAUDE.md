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

## The development loop (cl-workbench managed, containerized warm image)

This is a Common Lisp Workbench managed project (`.cl-workbench/project.toml`,
execution profile container-required). Run `cl-workbench doctor --strict` from
the project root once per substantive session before the first build, eval, or
test. SBCL never runs on the host: every entry point below runs inside the
pinned project container (bitcoin-lisp-sbcl:2.6.5), and the warm image's Swank
port stays private to the container (evals are a docker exec of the Workbench
client; no host port is published). Container, session, and FASL-volume
identities are checkout-specific, so parallel checkouts never collide.

```
scripts/dev.sh start            # warm image in the project container
scripts/dev.sh eval '(+ 1 2)'   # ~0.1s per eval
scripts/dev.sh test :bitcoin-core-script-tests   # one fiveam suite (raw designator)
scripts/dev.sh test-all         # full :bitcoin-lisp-tests (29k+ checks; long)
scripts/dev.sh docs-check       # PAX transcripts (docs/manual.lisp), cold container
scripts/dev.sh stop
```

`cl-workbench repl eval FORM`, `test [SUITE]`, `docs verify`, and
`validation run warm-unit|cold-unit|cold-docs` route to these same entry
points through `.cl-workbench/adapter`.

Discipline: ground before writing (`dev.sh eval '(describe ...)'`, apropos);
develop in small evals; after editing, reload (`dev.sh eval '(asdf:load-system
"bitcoin-lisp")'`) and re-run the touched suite; defstruct/Coalton layout
changes require an image restart. Consensus-critical work still finishes with
scripts/docker-test.sh (= `cl-workbench validation run cold-unit`) — the warm
image is a dev convenience, not the verification of record. A suite designator
that selects zero tests fails (rc 1); it can never pass silently.

Eval exit codes: 0 ok / 1 lisp error (+backtrace) / 2 connection (image down,
NOT your code — dev.sh start) / 3 timed out+interrupted (image survives;
raise DEV_EVAL_TIMEOUT for long forms) / 4 hard hang. NOTE: heavy FFI calls
(libsecp256k1, LevelDB) cannot be interrupted mid-call — a long foreign call
may show up as rc=4 even though the image recovers when the call returns.
Workbench appends payload-free outcome events under `.cl-workbench/state/`
(git-ignored); the Claude Code paren hook logs to
`.cl-workbench/state/paren-hook.log`. Legacy `.dev-runtime/` state is retired
— do not read, import, or delete it.
