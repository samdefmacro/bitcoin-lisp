# GA9 S3 verification pass — 2026-08-21

Why this document exists: **GA7 and GA8 both had adversarial verification change
the answer repeatedly**, and GA9's ~43 S3 findings had never had a verification
pass. This session produced two more data points for that, both from item 5 of
the recommended order:

- **G7-11 ephemeral dust**, listed as "policy entirely absent", is implemented
  and wired — all three parts, with tests.
- **G7-26 taproot corpus**, listed as open, is adopted — `bitcoin-core-bip341-tests.lisp`
  runs Core's `bip341_wallet_vectors.json` across 15 tests.

Two of four "open S2s" were already closed. Fixing before verifying would have
spent the effort on nothing twice.

Method: each claim checked against the current tree and against `refs/bitcoin/`.
A claim is CONFIRMED only when both sides were read. Claims not reached are
listed as such rather than assumed either way.

---

## Already closed by this wave (not re-listed below)

| Cluster | Status |
|---|---|
| Config & lifecycle (8 findings) | Fixed, PR #395 |
| Signal safety + log interleaving | Fixed, PRs #373 and #394 |
| Basic-auth latin-1 decode | Fixed, PR #396 |
| N4 fork-body retry | Fixed, this wave |

---

## CONFIRMED

### C1. The ping timeout is 30 seconds where Core's is 20 minutes

`peer.lisp:1426-1427` — `+ping-interval-seconds+` 60, `+ping-timeout-seconds+`
**30**. Core: `PING_INTERVAL{2min}` (net_processing.cpp:122) and the disconnect
is on `TIMEOUT_INTERVAL` = **20 minutes** (net.h:59).

Forty times stricter than Core. Any peer that takes longer than 30 s to answer a
ping — a busy node, a congested link, a Tor circuit — is disconnected here and
kept by Core. This is a plausible contributor to peer churn on the live nodes
and costs nothing to check against, since the counter already exists.

### C2. `address-routable-p` accepts four kinds of address Core rejects

`addrman.lisp:158-171` checks: correct length, non-zero, CJDNS carries 0xFC,
IPv6 not in `fc00::/7`. Core's `IsRoutable` (netaddress.cpp:462-465) additionally
excludes RFC2544, RFC3927, RFC4862 (**IPv6 link-local**), RFC6598, RFC5737,
RFC4843/RFC7343 (**ORCHID**), `IsLocal` (**::1**) and `IsInternal`.

So we store, dial and **re-gossip** IPv6 loopback, link-local, documentation and
ORCHID space. Re-gossip is the part that matters: we hand other nodes addresses
they will refuse, which wastes their addrman slots and marks us as a peculiar
source.

Note for whoever fixes it: accepting **IPv4** private ranges is a documented
deliberate divergence for private/regtest setups (the docstring says so). A fix
must keep that and add only the IPv6 categories.

### C3. `anchors.dat` is never consumed on read

`load-anchors` (node.lisp:4114-4135) reads the file and leaves it in place.
Core's `ReadAnchors` (addrdb.cpp:234-246) ends with `fs::remove(anchors_db_path)`
**unconditionally**, including on a parse failure.

Core consumes them so a crash-restart loop cannot re-dial the same two
block-relay anchors forever. Ours re-reads the same file every start, so a pair
of dead or hostile anchors is dialled first on every boot, indefinitely.

### C4. `SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS` is declared and never consulted — and its helper has no caller

The flag name appears once, in a list of flag-name strings
(`block.lisp:258`). Nothing reads it. Meanwhile `scan-for-op-success`
(`interop.lisp:871`) is written, exported (`interop.lisp:120`) and **called from
nowhere**.

Core (interpreter.cpp:1847-1848): hitting an `OP_SUCCESSx` in tapscript succeeds
the script immediately, unless the discourage flag is set, in which case it is an
error. That flag is part of the standardness set, so Core does not relay such
transactions.

This is the **eighth** "correct code that nothing calls" in this codebase. The
seven before it were found by shipping a diagnostic or by a live log line, never
by a test — worth remembering when deciding how to fix this one.

### C5. The script-flag cache is an unsynchronized hash table mutated by parallel workers

`*flag-set-cache*` (`interop.lisp:836`) is a plain `make-hash-table`, and
`flag-enabled-p` does a read-then-write into it. It is reached from the per-block
`script-check-N` worker threads. Concurrent `setf gethash` during a rehash is
genuine corruption, not a benign race.

The finding is real, but the root cause is worth naming because fixing the
symptom leaves it: **the cache exists only because we represent script flags as a
comma-separated STRING.** Core's flags are an integer bitfield tested with
`flags & SCRIPT_VERIFY_X` — no parsing, no cache, no lock, no race.

That representation has already cost this project once: an end-to-end spend test
passed a LIST to `set-script-flags`, which enabled nothing, so the test took the
non-witness path and "verified" an empty witness. A bitfield would have been a
type error.

### C6. `leveldb-iter-check-error` has one caller against eighteen iterator scans

Defined at `leveldb.lisp:354`, exported, and called from exactly one place
(`wallet-store.lisp:442`). There are 18 iterator-advance sites in the tree.

An iterator that stops because of an I/O error is indistinguishable from one that
stops because it reached the end. Every unchecked scan silently reports a partial
result as a complete one — and two of those scans back `gettxoutsetinfo`, whose
output is an assumeutxo commitment.

### C7. `gettxoutsetinfo` mixes the chain tip with the UTXO set's own statistics

`rpc-gettxoutsetinfo` (`methods.lisp:4666-4669`) takes `height` and `bestblock`
from the **chain state** and the coin statistics from the **UTXO set**, with no
single point of consistency between them.

Core reports the height and hash the coins view itself is at. The pair matters
more here than it looks: `hash_serialized_3` **is** the assumeutxo commitment, so
a `(height, hash)` pair that does not correspond to one another describes a
snapshot no one can validate.

Confirmed structurally — the two reads come from different sources. Not
demonstrated with an observed inconsistency.

### C8. There is no per-transaction legacy-sigop relay cap (BIP54)

Core: `MAX_TX_LEGACY_SIGOPS{2'500}` (policy.h:45), a policy/relay cap. No
equivalent constant exists in this tree; `count-legacy-sigops` is used for the
per-block budget only (`block.lisp:1261,1390,1449`).

So we relay transactions Core refuses, and once BIP54 is consensus such a
transaction is invalid in a block — meaning we would relay something that cannot
be mined.

---

## NOT REACHED

Listed so the next pass starts here rather than re-deriving the list. **None of
these has been verified in either direction** — they are as GA9 wrote them.

- Peers: tried-table collision resolution runs only at startup; `-addnode` peers
  are not exempt from discouragement and can never be redialled; outbound
  netgroup diversity frozen at startup over a candidate list fixed at boot.
- Storage: `loadtxoutset` never writes the snapshot coins-DB best-block pointer
  (opts assumeutxo out of the invariant PRs #335-#338 established);
  `coins-view-cache-add` marks a slot FRESH under `:allow-overwrite` where Core
  guards with a `logic_error`.
- Script: the single-CHECKSIG `FindAndDelete` pattern disagrees with
  `strip-sigs-from-script-code`; P2SH-wrapped-witness detection uses
  `extract-last-push-data` (`interop.lisp:725`) instead of the stack top.
- Wallet: `walletprocesspsbt` omits the wallet's `non_witness_utxo`; a rescan
  freezes the passphrase relock deadline while `getwalletinfo` reports it already
  expired.

## Suggested order for the fixes

1. **C1 ping timeout** — one constant, lands on both live nodes, and peer churn
   is the kind of thing that hides other problems.
2. **C8 BIP54 relay cap** and **C4 OP_SUCCESS discourage** — both are "we relay
   what Core will not", and C4 also closes a no-caller.
3. **C6 iterator error checks** — mechanical, and it is the one that currently
   turns an I/O error into a wrong answer.
4. **C2 routability** and **C3 anchors** — small, and both are addr-hygiene.
5. **C5 flag cache** — do the bitfield, not the lock. The lock fixes the race and
   leaves the representation that caused the empty-witness bug.
6. **C7 gettxoutsetinfo** — needs the coins view to report its own best block,
   which is adjacent to the NOT-REACHED `loadtxoutset` pointer item; do them
   together.
