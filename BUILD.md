# Building & running bitcoin-lisp nodes

This documents the **custom toolchain** the live nodes run on and how to
reproduce it. Two pieces are not captured by `git clone` alone — the SBCL build
and the vendored Coalton checkout (`refs/` is `.gitignore`d) — so a fresh
machine needs the two setup scripts below before the node will build.

## Why a custom SBCL (2.6.5)

The mainnet node crashed at chain tip under the distro **SBCL 2.1.11** (Nov 2021)
with `fatal error: GC invariant lost` — a heap-corruption bug in its old
multithreaded `gencgc`, triggered by mainnet-scale allocation/threading.
**SBCL 2.6.5 is the fix** (mainnet then ran 12 h+ clean past the former ~4.5 h
worst case, 0 crashes).

We build it from source because:

- apt only ships 2.1.11 on Ubuntu 22.04;
- the official 2.6.5 prebuilt Linux binary needs **glibc 2.38**, but this host
  has **glibc 2.35** (Ubuntu 22.04), so it won't run; and
- 2.1.11 is too old to cross-compile 2.6.5 directly, so we **bootstrap through
  intermediate versions** (2.1.11 → 2.3.5 → 2.4.11 → 2.6.5), each stage
  compiling the next, all linked against the host's own glibc.

## Prerequisites (Ubuntu 22.04)

```sh
sudo apt-get install -y sbcl git build-essential zlib1g-dev
```

`sbcl` here is the 2.1.11 host used only to bootstrap; it is left untouched.

## 1. Build SBCL 2.6.5

```sh
scripts/setup-sbcl.sh
```

Installs to `/data/bitcoin-lisp/sbcl-final` (override with `PREFIX=...`). Takes
~20 min. Verify:

```sh
/data/bitcoin-lisp/sbcl-final/bin/sbcl --version   # => SBCL 2.6.5...
```

## 2. Fetch + pin Coalton

```sh
scripts/setup-coalton.sh
```

`bitcoin-lisp.asd` adds `refs/coalton/` to the ASDF registry, so that vendored
clone is the Coalton the node compiles with. It is **pinned** at `7ffbd50`.

> Do **not** float to Coalton `main`. Coalton has no releases, and its bleeding
> edge has breaking changes this codebase's interop does not track (the `lisp`
> FFI form now needs `(-> type)` return syntax; `Unit -> X` defines need an
> explicit parameter). The pin is ~6 weeks newer than the latest
> Quicklisp-curated Coalton (the 2026-01-01 dist), compiles under 2.6.5, and
> passes the full suite.

## 3. Build + test the node

```sh
/data/bitcoin-lisp/sbcl-final/bin/sbcl --non-interactive \
  --eval '(asdf:load-system "bitcoin-lisp/tests")' \
  --eval '(fiveam:run! :bitcoin-lisp-tests)'
```

Quicklisp provides the remaining deps (ironclad, cffi, usocket, fiveam,
bordeaux-threads) via `~/.sbclrc`.

> The BIP341 vector test reads `tests/data/taproot_spend_vectors.json`, and
> `tests/data/` is `.gitignore`d — if that file is absent the test errors with
> `FILE-DOES-NOT-EXIST` (not a code failure).

## Running the nodes

Both nodes run under a **crash-recovery supervisor** (a `bash` respawn loop) on
the 2.6.5 SBCL, resuming from chainstate in ~60 s on any exit. The launchers
live on the server:

| Script | Network | `dynamic-space-size` | RPC | P2P | Supervisor marker |
|--------|---------|----------------------|-----|-----|-------------------|
| `run-mainnet.sh`  | mainnet (pruned, outbound-only) | 5120 | 8332 | 8333 | `MAINNET_SUPERVISOR_5120` |
| `restart-node.sh` | testnet4 (listening)            | 6144 | 18332 | 18333 | `TESTNET4_SUPERVISOR_6144` |

The `dynamic-space-size` (5120 vs 6144) doubles as the `pgrep` discriminator
between the two nodes. Both launchers point at `/data/bitcoin-lisp/sbcl-final`
and export `SBCL_HOME=/data/bitcoin-lisp/sbcl-final/lib/sbcl`.

### Stopping a node (e.g. for redeploy)

Kill the **supervisor first** so it doesn't respawn, then the sbcl child:

```sh
pkill -f MAINNET_SUPERVISOR_5120        # or TESTNET4_SUPERVISOR_6144
# then TERM the sbcl child (matched by 'dynamic-space-size 5120' / '6144')
```

The launcher scripts do this automatically. Graceful shutdown takes ~6 s
(durable UTXO / header-index / mempool flush); a `TERM` no longer hangs.

## Operational notes

- **Crash fix**: the SBCL 2.6.5 upgrade is the root fix. A contributing factor —
  `bitcoin-lisp:*parallel-block-validation*` — now defaults `NIL` (serial
  block-script validation); the per-block worker threads added the
  allocation/threading pressure that surfaced the 2.1.11 GC bug.
- **Logs** (`/data/bitcoin-lisp/logs/`): `mainnet.log` / `leveldb-test.log` are
  the node logs; `mainnet-stdout.log` / `stdout.log` capture supervisor output
  and any SBCL `ldb` crash dumps.
- **FASL cache** is per-SBCL-version (`~/.cache/common-lisp/sbcl-2.6.5...`), so
  the 2.6.5 build does not collide with any leftover 2.1.11 cache.
