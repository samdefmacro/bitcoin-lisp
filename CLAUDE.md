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

## The development loop (containerized warm image) — cl-agent-repl

```
scripts/dev.sh start            # warm image IN the project container, Swank on 127.0.0.1:4007
scripts/dev.sh eval '(+ 1 2)'   # ~0.1s per eval (client on host, image in container)
scripts/dev.sh test :script-tests   # one fiveam suite (raw designator)
scripts/dev.sh test-all         # full :bitcoin-lisp-tests (26k+ checks; long)
scripts/dev.sh stop
```

Discipline: ground before writing (`dev.sh eval '(describe ...)'`, apropos);
develop in small evals; after editing, reload (`dev.sh eval '(asdf:load-system
"bitcoin-lisp")'`) and re-run the touched suite; defstruct/Coalton layout
changes require an image restart. Consensus-critical work still finishes with
scripts/docker-test.sh — the warm image is a dev convenience, not the
verification of record.

Eval exit codes: 0 ok / 1 lisp error (+backtrace) / 2 connection (image down,
NOT your code — dev.sh start) / 3 timed out+interrupted (image survives;
raise DEV_EVAL_TIMEOUT for long forms) / 4 hard hang. NOTE: heavy FFI calls
(libsecp256k1, LevelDB) cannot be interrupted mid-call — a long foreign call
may show up as rc=4 even though the image recovers when the call returns;
report such cases in cl-agent-repl's FEEDBACK.md. Every eval is logged to
.dev-runtime/swank-dev/eval-metrics.log; the paren hook logs to
.dev-runtime/paren-hook.log — do not delete either.
