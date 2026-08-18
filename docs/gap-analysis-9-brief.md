# GA9 finder brief — bitcoin-lisp vs Bitcoin Core

This is the brief that drove the 9th gap analysis. It is preserved so GA9 part 2 (the seven
dimensions that died on a session limit) can be run under identical conditions, and so a 10th
round can extend the exclusion list rather than rebuild it.

You are one of the parallel finder agents. Read this file completely before doing anything.

## Paths

- **Our code (the subject):** the repository root (a git worktree may be in use; work from it).
- **Bitcoin Core (the oracle):** `/Users/sen/common-lisp/bitcoin-lisp/refs/bitcoin` @
  `d3056bc149f605225f22b1cc83b1a2d1cea64258`. It is gitignored and therefore **not present inside a
  worktree** — use the absolute path. Read with `rg`/`cat`. **Never run a git command against it.**
- Prior reports for style and exclusions: `docs/gap-analysis-8.md`, `docs/gap-analysis-9.md`.

## Ground rules

1. **READ CORE. Never argue from memory or from a plan document.** Every claim cites an exact Core
   file:line and an exact our-code file:line. This project's history contains repeated cases where a
   plan's paraphrase of Core was backwards. If you cannot find the Core code, say so and mark the
   finding unverified rather than inventing behaviour.
2. **Report only NEW findings.** Anything on the exclusion list below, or any restatement or
   sub-case of it, is out of scope. Your value is entirely in ground nobody has covered.
3. **No code execution.** Read-only pass: `rg`, `cat`, `sed -n`, `ls`, and `git log`/`git show`
   inside the worktree only. No docker, no sbcl, no dev.sh.
4. **Severity, applied strictly.** **S1** — consensus divergence (we accept what Core rejects, or
   reject what Core accepts), loss or theft of funds, remote unauthenticated node-kill, or a broken
   security invariant the operator is entitled to rely on. **S2** — significant divergence with real
   operational impact: relay policy that strands real transactions, bounded but real DoS, silent
   corruption in an opt-in subsystem, wallet behaviour that misleads about funds. **S3** — missing
   feature, contract/format divergence, test gap, robustness nit. Do not inflate; a missing feature
   is S3 even when it is a big feature.
5. **Depth over breadth.** Five findings traced through both codebases beat twenty pattern-matched
   guesses. An unverifiable hunch is worth less than nothing, because verification has to pay to
   kill it.
6. **State the direction of every consensus divergence** (we-accept/Core-rejects vs
   we-reject/Core-accepts) and what an attacker or honest peer must do to reach it.
7. **Look hardest at code written since 2026-07-27** — see "New since GA8".

## Output format

Return a JSON array and nothing else, most severe first:

```json
[{
  "id": "G9-<dim>-1",
  "title": "one line, states the divergence not the topic",
  "severity": "S1|S2|S3",
  "dimension": "<your dimension>",
  "our_refs": ["src/foo/bar.lisp:123-140"],
  "core_refs": ["src/validation.cpp:2570-2597"],
  "divergence": "what Core does vs what we do, in Core's own terms",
  "impact": "who is hurt, how, what they must do to reach it. State the direction.",
  "reachability": "honest-network | attacker-constructible | operator-config | unreachable-today",
  "approach": "smallest fix, and any load-bearing placement constraint",
  "effort": "S|M|L",
  "confidence": "high|medium|low",
  "evidence": "the reasoning chain: what you read in both trees that forces this conclusion"
}]
```

`[]` plus a note on what you cleared is a legitimate and useful result. Do not pad.

---

# EXCLUSION LIST — everything known through GA9 part 1

## GA9 part 1 (2026-08-18) — this round's own findings
S1: block weight omitting the 80-byte header + tx-count varint; the finality loop skipping the
coinbase; BIP68's signed-vs-unsigned version gate; invalidated block-index entries resurrected by
connect-block. S2: signet unable to follow its own chain (no signet powLimit, no non-boundary
difficulty rule); connect-block replacing the index entry breaking the eq-based ancestry walk;
assumevalid script-skip on a bare height comparison; misbehaving inbound onion peers discouraging
127.0.0.1; addrman Attempt never called in steady state; inbound eviction missing four protection
passes and preferring onion peers; `noX=1` config negation silently discarded. S3: height-gated
WITNESS/TAPROOT script flags; superfluous witness record accepted; tried-collision resolution only
at startup; manual peers not exempt from discouragement; 3-minute ping budget; address-routable-p
accepting IPv6 loopback/link-local/doc/ORCHID; anchors.dat never consumed on read; outbound netgroup
diversity enforced once over a frozen list; config `[section]` dropped when the network is selected
in the file; section values losing to global values; inline `#` comments not stripped; conf-parse-bool
treating true/yes/on as true; -includeconf unimplemented; conflicting chain selectors resolved
silently; non-existent -datadir created; mainnet/testnet3 datadir layout inverted; mined coinbase
omitting Core's timelock commitment; non-async-signal-safe SIGTERM handler; unsynchronized log
stream writes. Plus: tests/data untracked via a bare `data/` gitignore rule, so the taproot
spend-vector test hard-errors in a fresh clone; and G7-15/19/20/38 recorded open but actually done.

## GA8 (2026-07-26) — all 7 S1s fixed (PRs #316–#320), S2s addressed (#321–#329)
Same-block chained spends skipping script validation; intra-block double-spend + inflation;
tapscript 520B/1000-item limits; tapscript weight budget omitting the annex; P2SH sigop counting;
RPC auth never enforced; header MTP unenforced mid-batch. S2s: 3-hour gossip window discarding
addresses; proxied seed hostnames dropped; compact blocks punishing honest peers; #314 protection
counter; #311 low-work disconnect placement; supervisor/flush race; coinstatsindex rewind;
JSON-RPC 1.x reply shape; empty collections as null; getblockheader nTx; getblockstats fields;
/rest/headers non-contiguity; 1p1c package relay + reconsiderable-rejects; bumpfee CheckFeeRate;
unseeded *random-state*; txindex torn tail; corrupt chainstate.dat / BIP30 replay brick;
600s destroy-thread mid-reorg.

## GA7 (2026-07-23) — roadmap G7-01..G7-69, ALL KNOWN
G7-01 tapscript CHECKSIG ordering (FIXED) · G7-02 BIP341 SIGHASH_SINGLE out-of-range (FIXED) ·
G7-03 -onlynet DNS leak (FIXED) · G7-04 wallet auto-load (FIXED) · G7-05 txindex no startup
catch-up · G7-06 corrupt headerindex.dat · G7-07 wallet encryption+backup (DONE, PR #343) ·
G7-08 outbound eclipse resistance (P1/P2 done, **P3 open**) · G7-09 maxfeerate/maxburnamount ·
G7-10 handle-getdata guards · G7-11..14 relay policy (FIXED) · G7-15 BIP133 feefilter (DONE #312) ·
G7-16 BIP152 HB mode (partial) · G7-17 named RPC args · G7-18 sub-minchainwork drop (DONE) ·
G7-19 self-connection detection (DONE #309) · G7-20 GetAddr cache (DONE #310) · G7-21 fee estimator ·
G7-22 estimatesmartfee contract · G7-23 ZMQ · G7-24 taproot script-path descriptors ·
G7-25 key_io vectors · G7-26 taproot script-assets corpus · G7-27 VerifyDB · G7-28 flush failures
swallowed · G7-29 datadir .lock · G7-30 debug-log management · G7-31 -maxmempool ·
G7-32 -debug=<category> · G7-33 -rpcallowip (partial) · G7-34 -connect · G7-35 subversion cap and
sanitize · G7-36 disconnectpool bound (FIXED) · G7-37 -maxuploadtarget · G7-38 fast rescan (DONE) ·
G7-39 CPFP bump fees in coin selection · G7-40 multipath descriptors · G7-41 miniscript ·
G7-42 descriptor-wallet straggler RPCs · G7-43 getblock verbosity 3 · G7-44 REST endpoints ·
G7-45 hidden test RPCs · G7-46 external signer · G7-47 private broadcast · G7-48 preferred download ·
G7-49 stalling-peer response (partial) · G7-50 noban/whitelist · G7-51 invalid-PoW headers not
discouraged · G7-52 desirable-services disconnect · G7-53 un-salted addr relay · G7-54 v2 transport
default OFF · G7-55 optimistic v2 handshake · G7-56 stale fee_estimates.dat · G7-57 -blockmaxweight ·
G7-58 hardcoded template version · G7-59 no coins-DB obfuscation key · G7-60 txospenderindex ·
G7-61 full header-index rewrite per flush · G7-62..69 test-vector adoption (BIP32 vectors 2-5,
bech32/bech32m, base58, rpc_getblockstats, rpc_decodescript, rpc_bip67, mainnet_alt, SipHash table).

## GA1–GA6 — known themes
Consensus: BIP30/34/65/66/68/112/113, CVE-2012-2459, segwit+sigop gating, FindAndDelete, BIP143
quirks, tapscript OP_SUCCESS, CScriptNum bounds, CHECKMULTISIG scriptCode, witnessless witness-program
spends, low-R grinding. Networking: cmpctblock witness wedge, CLOSE_WAIT/FIN, per-peer block
tracking, disconnect order, fork/reorg bugs, deep-reorg wedge. Storage: LevelDB migration,
coinstatsindex, BIP158 GCS, sigcache, skip-list ancestor. RPC: the ~140-method sweep and the
2026-06-27 gapfill. Mempool: the policy sweep, cluster mempool P0-P10. Tier-4: assumeutxo P4-P6,
tor onion, txgraph, BIP155, Erlay handshake, SOCKS5.

## New since GA8 (2026-08-16/17) — the fixes are IN SCOPE for new defects
PR #332 live-node wedges (receive-bytes blocking forever, %socks5-recv, sync-blockchain NIL peer,
inbound admission queue). PRs #333–#338 coins-DB alignment (streamed UTXO hash, corrupt chainstate
detection, coins-DB best block, same-batch write, startup reconciliation, reorg block-boundary
interrupt via `*interrupt-check*`). PR #339 mempool import progress + signal trapping.
PRs #340–#342 resumable v1 reader, resumable v2/BIP324 reader with MAX_RESERVE_AHEAD, header sync
on the shared pump with per-pass byte bounds and %maybe-send-getheaders throttling. PR #343 Wallet
P6 (crypter, encryption lifecycle, relock timer, logical-dump backup). PRs #344–#347 GUI 6c/6d.
Already-found defects in that work — do NOT re-report: locked wallet still signing via the embedded
xprv; backupwallet RENAME-FILE writing nothing; walletpassphrasechange making a timed unlock
permanent; wallet-db-records not checking leveldb_iter_get_error; %path-under-p defeated by `..`;
wallet-is-locked-p being a mutator called outside the lock; the getheaders locator-source
termination bug; the v2 decoy flood; reserve-ahead over-allocation.

---

# Per-dimension prompts for the seven dimensions still to run (GA9 part 2)

Give each agent: "Read `docs/gap-analysis-9-brief.md` completely first and follow every rule in it,
including the exclusion list and the JSON output format. Your dimension: <name>." Then the scope
block below. **Run in batches of four to five — twelve at once exhausted the session budget.**

## script — script interpreter
Scope: `src/coalton/{script,interop,types}.lisp`, `src/validation/script.lisp`, script-flag plumbing.
Oracle: `src/script/{interpreter.cpp,interpreter.h,script.h,script.cpp,sigcache.cpp,script_error.cpp}`.
Hunt: opcode-by-opcode `EvalScript` semantics, `fRequireMinimal`, CScriptNum ranges at EVERY
consumer (not just arithmetic), OP_IF/NOTIF under each sigversion, `vfExec` empty checks,
OP_CODESEPARATOR position accounting, disabled opcodes checked inside unexecuted branches; every
`SCRIPT_VERIFY_*` flag and whether consensus and standardness are conflated; `VerifyScript`'s P2SH
`stack.empty()`/push-only checks, cleanstack under P2SH+witness, `WITNESS_UNEXPECTED`, and the exact
order in `VerifyWitnessProgram`; segwit v0 32/20-byte discrimination, `WRONG_LENGTH` vs `MISMATCH`;
taproot control-block parsing, merkle path bound, leaf-version masking, parity bit,
`MAX_TAPROOT_CONTROL_SIZE`/`TAPROOT_CONTROL_BASE_SIZE` arithmetic; `IsValidSignatureEncoding`,
`IsDefinedHashtypeSignature`, `CheckPubKeyEncoding`, low-S, and where each is gated.

## mempool — mempool & policy
Scope: `src/mempool/*.lisp`, `src/validation/packages.lisp`.
Oracle: `src/validation.cpp` (MemPoolAccept: PreChecks/PolicyScriptChecks/ConsensusScriptChecks/
Finalize/AcceptMultipleTransactions/PackageMempoolChecks), `src/policy/{policy,rbf,packages,
truc_policy,ephemeral_policy}.cpp`, `src/txmempool.cpp`, `src/node/txdownloadman_impl.cpp`,
`src/txorphanage.cpp`.
Hunt: **TRUC/v3 policy — check whether ANY of it exists** (ancestor/descendant limits of 1,
`TRUC_MAX_VSIZE`/`TRUC_CHILD_MAX_VSIZE`, sibling eviction, the rule that a TRUC tx cannot spend a
non-TRUC unconfirmed parent and vice versa); if absent, what happens when a v3 transaction arrives —
do we relay it under normal policy? RBF: all five checks, BIP125 signalling, the `-mempoolfullrbf`
default in this revision, the 100-conflict cap, incremental relay fee arithmetic. Ancestor/descendant
counting (does the tx itself count?) and the carve-out. `TrimToSize` descendant-score ordering and
the rolling-minimum-fee half-life and floor. Orphan eviction, per-peer accounting, the weight-based
bound in this revision, recent-rejects/recent-confirmed reset-on-new-block. `IsStandardTx` arm by
arm (version range, size, scriptSig push-only+size, dust per output type, bare multisig, datacarrier,
`IsWitnessStandard`). `GetModifiedFee`, prioritisetransaction accounting, and any fee or vsize
computed with integer division Core rounds differently.

## p2p-wire — P2P protocol & transport  ← HIGHEST PRIORITY, newest code
Scope: `src/networking/{protocol,connection,v2-transport,socks5}.lisp`,
`src/serialization/messages.lisp`, `src/crypto/{bip324,chacha20}.lisp`.
Oracle: `src/net.cpp` (V1Transport/V2Transport/CNode/SocketHandler), `src/net_processing.cpp`
(ProcessMessage — every handler), `src/protocol.cpp`, `src/bip324.cpp`,
`src/crypto/chacha20poly1305.cpp`.
PRs #332/#340/#341/#342 rewrote the whole read path days before this analysis. Read them
adversarially (`git log -p`, worktree only).
Hunt: resumable v1/v2 state-machine holes — a message of declared length 0, exactly at the boundary,
a valid header followed by a different message's bytes; can the accumulated buffer, `recv-framing`,
or reserve-ahead be driven into an inconsistent state that survives ACROSS pump passes? Compare
against Core's `V1Transport::ReceivedBytes`/`V2Transport::ReceivedBytes`, which are explicit state
enums with assertions. `MAX_PROTOCOL_MESSAGE_LENGTH` enforced BEFORE allocation, and every
per-message count cap (`MAX_INV_SZ`, `MAX_ADDR_TO_SEND`, `MAX_HEADERS_RESULTS`, `MAX_LOCATOR_SZ`,
`MAX_BLOCKS_TO_ANNOUNCE`, getdata limits) — check EVERY handler for a missing cap and for
allocation-before-validation. v2 handshake: garbage length bound (4095), garbage-terminator scanning
cost, the v1 fallback and whether an attacker can force expensive work in the ambiguous window, key
derivation ordering, session-id/short-command-id table, AEAD nonce/sequence on both directions.
Core's rejection of messages before VERSION/VERACK, duplicate VERSION, the `fSuccessfullyConnected`
gate. Checksum and unknown-command handling, and whether a malformed message desynchronises the
stream rather than being skipped cleanly. SOCKS5 reply bounds, auth negotiation, domain-name length.

## storage — storage & indexes  ← newest code (#333–#338)
Scope: `src/storage/*.lisp`, `src/serialization/compressor.lisp`.
Oracle: `src/txdb.cpp`, `src/coins.{cpp,h}`, `src/dbwrapper.cpp`, `src/node/blockstorage.cpp`,
`src/index/{base,blockfilterindex,coinstatsindex,txindex}.cpp`, `src/compressor.cpp`,
`src/blockfilter.cpp`, `src/crypto/muhash.cpp`.
Hunt: `CCoinsViewCache` FRESH/DIRTY semantics in `BatchWrite` — getting them wrong causes a lost
write or a resurrected spent coin. Especially spent-and-fresh (must be **erased** from the parent,
not written as spent) and the DIRTY-but-not-FRESH path; also `Uncache`, `SetBestBlock` ordering, and
`Sync` vs `Flush`. Whether any cache memory bound exists at all (Core flushes on `-dbcache` pressure
with a CRITICAL threshold). Coin serialization byte-exactness (`TxOutCompression`, the varint amount
compression — a lossy-looking but lossless transform easy to get subtly wrong — and the six special
script types) on boundary values. BIP158: the exact element set (Core includes previous output
scripts from the undo data and excludes OP_RETURN and empty scripts), the dedup, P=19/M=784931, the
Golomb-Rice boundary, and the filter **header** chain. Index catch-up/rewind on reorg
(`BaseIndex::BlockConnected`/`Rewind`, `best_block` persistence) and whether an index can silently
lag the chain and be treated as current. MuHash 3072-bit arithmetic, the ChaCha20 expansion, and the
removal inverse. Block file magic/size prefix, `-prune` interaction with indexes, truncated-file
detection. LevelDB CFFI: iterator lifetime, `leveldb_free` ownership, error-string handling,
use-after-close.

## wallet — wallet  ← newest code (#343)
Scope: `src/rpc/{wallet,wallet-store,wallet-coins,wallet-spend,wallet-tx,wallet-crypt,descriptors,
psbt}.lisp`, `src/crypto/{crypter,bip32,address}.lisp`, `src/serialization/psbt.lisp`.
Oracle: `src/wallet/{wallet,scriptpubkeyman,spend,coinselection,feebumper,crypter,walletdb,receive,
transaction}.cpp`, `src/script/descriptor.cpp`, `src/script/signingprovider.cpp`, `src/psbt.cpp`,
`src/key.cpp`, `src/pubkey.cpp`.
Hunt: the crypter vs `wallet/crypter.cpp` — `BytesToKeySHA512AES` exactly (passphrase-then-salt,
iteration semantics, the key/IV split), AES-256-CBC parameters, `CKeyingMaterial` handling, and
whether Core's `DecryptKey` check (re-derive the pubkey and compare) is present. Is key material
zeroized; is it in a `LockedPool` equivalent; can a passphrase or key reach a log or a condition
report string? `ckey` record byte compatibility — Core commits to the pubkey and uses it as the IV
source; **a wallet that cannot be read back is a funds-loss event**. Coin selection: BnB/SRD/
knapsack, the waste metric, `-changetype`, change-position randomisation, and **anti-fee-sniping —
Core sets nLockTime to the current height with a 10% chance of a random back-off, and a divergence
here fingerprints our transactions on-chain**. `GetMinimumFee`, discard-fee/change-dust interaction,
`max_tx_weight`, and whether change can be created below dust or dropped without adding its value to
the fee. `IsMine` vs `IsFromMe`, immature coinbase, `GetAvailableBalance` conflict handling,
abandoned transactions, reorg-conflicted state. Descriptor checksum **required** on import,
hardened derivation from a pubkey-only descriptor, range handling, key-origin fingerprints. PSBT:
BIP174 field-key uniqueness and ordering, the unknown-fields-must-be-preserved rule, combine/
finalize/extract, sighash-type consistency, and **whether `non_witness_utxo` is validated against
the input's prevout txid** — missing that is how wallets get tricked into signing a wrong fee.

## rpc — RPC / REST / UI
Scope: `src/rpc/{server,methods,accessors,rest,merkleproof,ui}.lisp`, `ui/`, `tests/ui/`.
Oracle: `src/rpc/{server,request,blockchain,mempool,net,rawtransaction,mining,util}.cpp`,
`src/httpserver.cpp`, `src/httprpc.cpp`, `src/rest.cpp`, `src/univalue/`.
Hunt: the HTTP server as an attack surface now that auth is enforced (#318) and the UI is served
from the same place — header parsing bounds, request-body size limits, chunked encoding, keep-alive
state, concurrent connections and worker queue depth (`-rpcthreads`, `-rpcworkqueue`), slow-loris on
the RPC port, and whether an unauthenticated request can make us allocate or work **before** the
auth check. **Is the Basic-auth comparison constant-time? Core uses `TimingResistantEqual`.** The
UI: is any route auth-exempt; is there path traversal in static serving; is any user-controlled
value (wallet labels, addresses, PSBT text) interpolated into HTML/JS without escaping; is there a
CSRF vector given browser-cached Basic auth. Error-code fidelity against Core's `RPC_*` codes for
the specific failure each method produces. Per-method argument **validation** (type coercion,
out-of-range, optional defaults) for methods not already excluded. `getblocktemplate`'s full
contract: capabilities/rules negotiation, longpoll, `mutable`, `template_request`, the segwit rule.
REST: content-type handling, `.bin`/`.hex`/`.json` suffix dispatch, and that it bypasses auth by
design in Core — confirm we match and that it is off by default.

## crypto-ser — crypto & canonical encoding
Scope: `src/crypto/*.lisp`, `src/serialization/{binary,types}.lisp`,
`src/coalton/{binary,serialization,crypto}.lisp`.
Oracle: `src/key.cpp`, `src/pubkey.cpp`, `src/hash.{cpp,h}`, `src/crypto/{sha256,ripemd160,
hmac_sha512,siphash}.cpp`, `src/serialize.h`, `src/streams.h`, `src/util/strencodings.cpp`,
`src/bech32.cpp`, `src/base58.cpp`, `src/secp256k1/include/`.
Hunt: the libsecp256k1 CFFI boundary as a correctness **and memory-safety** surface. For every
foreign call: are input lengths validated before the call; are return codes checked (secp256k1
returns 0/1 and Core treats 0 as a hard failure everywhere); is the context created with the right
flags and is it ever used across threads without the randomization Core applies
(`secp256k1_context_randomize`, re-applied periodically); are output buffers the exact required
size; is any Lisp array passed without pinning; can GC move a buffer mid-call; is foreign memory
leaked on a non-local exit out of a `with-foreign-object` body? Does the ECDSA verify path use a
normalized-low-S signature as Core does, and does the Schnorr path match BIP340 exactly? Key
handling: the RFC6979 nonce function and the low-R grinding loop's exact counter encoding (an
off-by-one produces valid-but-different signatures), key validity checks, `RecoverCompact`.
**BIP32: Core's `CExtKey::Derive` INCREMENTS the index and retries on an invalid child — a
divergence gives different addresses for the same seed, a funds-loss-on-restore event**; also the
leading-zero padding in the derivation preimage and the fingerprint computation. Serialization:
`CompactSize` canonicality (`ReadCompactSize` rejects non-canonical encodings and enforces
`MAX_SIZE`), `VarInt` (the **other** format, used in the coins DB, also canonical-checked), signed/
unsigned widths, and `CTransaction`'s witness marker/flag disambiguation including the "zero inputs
means segwit-serialized" rule and the rule that a segwit serialization with an empty witness must be
rejected. Hash preimages: `SerializeHash`, the BIP340/341 `TaggedHash` (tag hashed twice), SipHash
key and finalization. Addresses: bech32/bech32m checksum constant selected by witness version,
charset and mixed-case rules, length bounds, base58check. For every hash or encoding claim, write
out the exact byte sequence each side produces.
