# GA11 dimension 4 — transaction relay scheduling

Survey only: nothing under `src/` or `tests/` was changed. Findings are in
`dim-tx-relay.json`; this note records what was read, what was run, and what was
left for another dimension.

Oracle: Bitcoin Core `d3056bc` in `refs/bitcoin/`. Container: the project's warm
image (`bitcoin-lisp-sbcl:2.6.5-4`) in this worktree; every probe below was run
through `scripts/dev.sh eval`.

## What was compared

| ours | Core |
|---|---|
| `src/networking/protocol.lisp:321-637` (tx-request tracker) | `src/txrequest.{h,cpp}`, `src/node/txdownloadman_impl.cpp:170-300` |
| `handle-inv` (`protocol.lisp:754`), `handle-notfound` (`:855`) | `net_processing.cpp:4150-4200`, `:5150-5164` |
| `handle-tx` (`protocol.lisp:1816`) | `net_processing.cpp:4473-4560`, `ProcessValidTx` / `ProcessInvalidTx` |
| `%cache-tx-rejection`, the reject / reconsiderable / recently-confirmed filters | `txdownloadman_impl.cpp:340-500`, `:91-123` |
| 1p1c package relay (`%find-1p1c-package`, `%try-1p1c-package`) | `Find1P1CPackage`, `ProcessPackageResult` |
| `src/mempool/orphan.lisp` | `src/node/txorphanage.cpp` |
| `relay-transaction`, `%flush-peer-tx-invs`, `flush-tx-announcements`, the unbroadcast reattempt, `handle-mempool-request` | `net_processing.cpp` SendMessages inventory block, `:5960-6090` |
| the tx arm of `process-peer-getdata` (`protocol.lisp:2085`) | `ProcessGetData` / `FindTxForGetData` |
| `src/networking/txreconciliation-set.lisp`, `minisketch.lisp` | `src/node/txreconciliation.cpp` (handshake only) + BIP-330 |

## Probes that were run

1. **Repeat grants to one peer.** 1000 announce/notfound rounds from a single
   peer produced 1000 getdata grants for the same txhash; with an honest peer
   permanently in the candidate pool, the attacker still won 3 of 6 expiry
   cycles.
2. **`tx-request-received` scope.** Three announcers of one txid, then one
   `tx-request-received`: all three announcements and the in-flight record are
   gone and the next scheduler pass sends nothing.
3. **`tx` during IBD.** With `*cached-is-ibd*` bound to T on a package fixture,
   `handle-tx` admitted the transaction to the mempool and queued it for relay
   to a second peer.
4. **Scheduler scan cost.** `process-tx-requests` at 5,000 / 25,000 / 50,000
   tracked hashes: 0.9 / 4.9 / 9.6 ms per scan (linear). One 61-byte `notfound`
   triggers one such scan, and `notfound` declares no rate bucket.
5. **Block connect vs the tracker.** A confirmed transaction's announcement
   survives `note-block-connected` and still produces a getdata.
6. **Known-tx filter.** After `handle-inv` from a peer, `relay-transaction` for
   the same txid queues an announcement straight back to that peer.
7. **Inv queue.** 8 peers driven to `+max-tx-inv-queue+`: the queue stays pinned
   at 5,000 (oldest entries silently discarded) at ~0.06 ms per peer per relayed
   transaction.

## Not covered — and who inherits it

- **`minisketch.lisp` field arithmetic and decoding.** No Core counterpart; it is
  a from-scratch implementation and needs a differential harness, not a
  side-by-side read. → the GA11 harness lane.
- **The BIP133 feefilter sender** (`src/networking/peer.lisp:1289-1400`) and its
  fee rounder. → dimension 8 (rpc/util + fees + versionbits reporting).
- **Which failures are reconsiderable** (RBF, TRUC, cluster limits, fee floor):
  this dimension only checks how the reasons are *routed*. → dimension 3
  (cluster mempool).
- **The block-relay half of `protocol.lisp`** (cmpctblock, blocktxn, getblocktxn,
  the high-bandwidth peer set) and the liveness/backpressure seam. → dimension 10
  (second reader: protocol.lisp + peer.lisp + connection.lisp).
- **Persistence of the unbroadcast set through mempool.dat.** → dimension 5 / 9.
- **Concurrency.** Every probe drove the handlers on one thread. Races and lock
  ordering between the sync pump, the RPC broadcast path and `*tx-request-lock*`
  are untested here.
