# Contributing

## Build and run

`BUILD.md` is the source of truth for building and running a node — a pinned
SBCL, a pinned Coalton (`scripts/setup-coalton.sh`), and the node's own
supervisor. Read it before the install section of `README.md`, which describes
a plain distro toolchain suitable for testnet and regtest only.

Development happens **inside the project container**, never against a host
SBCL:

```
scripts/dev.sh start                       # warm image
scripts/dev.sh eval '(+ 1 2)'              # ~0.1s per eval
scripts/dev.sh test :bitcoin-core-script-tests
scripts/docker-test.sh                     # the cold battery: verification of record
scripts/dev.sh stop
```

`CLAUDE.md` documents the full development loop, including the traps that have
cost real time (a changed `defconstant` needs an image restart; a struct change
needs the FASL volumes dropped).

## What a change needs

- **Cite Bitcoin Core.** Consensus, policy, P2P and RPC behaviour are specified
  by `refs/bitcoin/`, not by intuition. Reference `file:line` in the commit
  message or a comment wherever the behaviour is not obvious — and read Core
  first: this project's own history is full of cases where reasoning from our
  own structure produced a divergence.
- **A test that can fail.** Consensus and policy changes need a case that fails
  without the fix. Where the change is about something *not* happening, include
  a positive control so the assertion cannot pass vacuously.
- **The cold battery, green.** `scripts/docker-test.sh` is the verification of
  record. Confirm the check count is in the expected range (~32,000) as well as
  the exit code — a battery that aborts early can otherwise look like a pass.
- **One logical change per pull request**, with a commit message that explains
  *why*, not just what.

## Things worth knowing

- The script interpreter is Coalton; everything else is Common Lisp. That split
  is settled — see `docs/`.
- `refs/` is git-ignored: `scripts/setup-coalton.sh` fetches the pinned Coalton,
  and the Bitcoin Core clone supplies both the specification and the test
  vectors several suites read.
- Plan and gap-analysis documents under `docs/` are dated research. Where one
  disagrees with the code, the code is what runs — but say so, because a stale
  plan header has sent work down the wrong path before.
