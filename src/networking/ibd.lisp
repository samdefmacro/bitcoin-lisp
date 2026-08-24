(in-package #:bitcoin-lisp.networking)

;;; Initial Block Download (IBD)
;;;
;;; Coordinates headers-first synchronization with the Bitcoin network.
;;; Implements download queue management, checkpoint validation, and
;;; sync state machine.

;;;; IBD State Machine

(deftype ibd-state ()
  "States for Initial Block Download."
  '(member :idle :syncing-headers :syncing-blocks :synced))

(defparameter +block-stalling-timeout+ 30
  "Shorter per-block request timeout applied only NEAR THE TIP (within
   +stalling-near-tip-margin+ of the header tip). There, blocks are recent
   and small, so a block in-flight this long means a silent/unresponsive
   peer — retry it elsewhere fast instead of waiting out the full
   compute-block-download-timeout (~125s). This is what cuts silent-peer
   fork-recovery latency from ~max-block-request-timeouts x 125s (~10 min)
   to ~max x 30s (~2.5 min), with the same retry+eviction path.")

(defparameter +stalling-near-tip-margin+ 144
  "How close (in blocks) the validated tip must be to the header tip for
   the shorter +block-stalling-timeout+ to apply. Far below this (bulk
   IBD — notably the testnet4 multi-MB stress region at h=51k-67k, ~70k
   below tip) the full per-block timeout stands, so a slow legitimate
   transfer is never mistaken for a stall (the 2026-05 eviction
   death-spiral). 144 blocks is firmly in the at-tip zone for any chain
   whose heavy region isn't within a day of the tip.")

(defparameter +max-messages-per-peer-per-cycle+ 32
  "How many messages to drain from each peer in one IBD loop iteration.
   Reading just one used to let kernel TCP buffers fill (multi-MB) whenever
   validation took a few seconds, then the stalling-peer check would evict
   peers for OUR slowness. Drain in batches to keep buffers shallow.")

(defparameter +max-recv-bytes-per-peer-per-cycle+ 65536
  "Bytes one peer may hand us in a single drain before we move to the next.

A message count alone is not a fairness bound: 32 messages can be 32 blocks,
and a peer that keeps its socket full holds the drain for as long as it can
feed it. Core's bound is on BYTES, not messages — at most 0x10000 per node per
socket-handler pass (net.cpp:2171-2183) — so a peer with a lot to say costs one
turn, not the pass.

Checked BETWEEN messages, so it never truncates one: a single 4 MB block still
arrives whole (the reader is resumable, and stopping mid-message would only
defer the same bytes), it just ends that peer's turn afterwards.")

(defparameter +max-block-queue-bytes+ (* 256 1024 1024)
  "Byte cap (wire size) for the out-of-order block-queue. The 1024-COUNT
cap alone was sized for testnet4's small blocks: with the tip stuck at
mainnet h=544,085 (the bad-version consensus bug), peers filled the
count window with 2018-era 1-1.5MB blocks — ~5GB once parsed — and the
heap died before the stuck-tip halt could fire. 256MB wire ≈ ~1-1.5GB
parsed, comfortably inside the 5GB dynamic space.")

(defparameter +max-block-queue-size+ 1024
  "Maximum number of out-of-order blocks held in the IBD block-queue,
   matching Bitcoin Core's BLOCK_DOWNLOAD_WINDOW (net_processing.cpp:146).
   Each entry holds a fully-deserialized block (multi-MB on testnet4
   stress blocks); 1024 × ~80KB worst-case ≈ 80MB fits comfortably below
   the 8GB heap budget. The earlier 4000-cap commentary about
   re-download thrashing assumed an unbounded receive path: with the
   receive-side cap in process-received-block + the gap-only request
   clamp, peers no longer redeliver dropped blocks because we stop
   asking once at cap.")

(defparameter +no-progress-yield-seconds+ 5
  "The block-download loop RETURNS (yielding to the 30s maintenance cadence)
when it has neither requested nor received a single block for this many
seconds while its gate is still open. Distinct from +stuck-tip-halt-seconds+
(a hard halt when the tip is stuck AND the queue is full): here the queue is
empty and the loop is simply idle because the servable chain is exhausted but
`pending` still holds fork headers no peer serves — OR the gate stays open on a
heavier chain that is unobtainable. Returning is safe: run-ibd is re-entered
every maintenance pass, so control resumes; without this the work-based gate
below could spin the loop forever and starve peer maintenance.")

(defparameter +stuck-tip-halt-seconds+ 300
  "If the connect-tip fails to advance for this many seconds AND the
   block-queue is at cap, IBD halts. Mirrors the spirit of Bitcoin Core's
   TipMayBeStale check (net_processing.cpp:1332-1340) which uses
   nPowTargetSpacing*3 (≈30 min) before connecting an extra peer — we are
   stricter because for our node a long stall almost always means a
   consensus bug in the validator, not a network issue. Halting + logging
   beats spinning until the heap exhausts.")

(declaim (inline block-hash-key-hash))
(defun block-hash-key-hash (k)
  "Custom :hash-function for the IBD block-hash-keyed tables (pending,
in-flight, request-timeouts). Keys are 32-byte SHA256d
block hashes (already uniformly random), so read the first 8 bytes as a
fixnum-masked uint64 instead of equalp's full 32-byte data-vector-hash.
:test stays 'equalp for exact collision resolution. Mirrors utxo-key-hash;
profile (fresh testnet4 IBD) showed this hashing dominating IBD CPU."
  (declare (optimize (speed 3)))
  (if (and (vectorp k) (>= (length k) 8))
      (logand (+ (aref k 0) (ash (aref k 1) 8) (ash (aref k 2) 16) (ash (aref k 3) 24)
                 (ash (aref k 4) 32) (ash (aref k 5) 40) (ash (aref k 6) 48) (ash (aref k 7) 56))
              most-positive-fixnum)
      (sxhash k)))

(defun make-block-hash-table (&key synchronized)
  "An equalp hash-table for 32-byte block-hash keys, using the fast
block-hash-key-hash. Falls back to plain equalp off SBCL. SYNCHRONIZED makes
the table thread-safe (SBCL): the in-flight table needs it because
getpeerinfo's \"inflight\" snapshot reads it from RPC threads while the sync
thread mutates it."
  (declare (ignorable synchronized))
  (make-hash-table :test 'equalp
                   #+sbcl :hash-function #+sbcl #'block-hash-key-hash
                   #+sbcl :synchronized #+sbcl synchronized))

(defstruct ibd-context
  "Context for managing Initial Block Download."
  (state :idle :type keyword)
  (header-sync-peer nil)
  (target-height 0 :type (unsigned-byte 32))
  (headers-received 0 :type (unsigned-byte 32))
  (blocks-received 0 :type (unsigned-byte 32))
  ;; Header tip (separate from validated block tip in chain-state)
  (header-tip-height 0 :type (unsigned-byte 32))
  ;; Best-header chain-WORK (monotonic max over the header index). The block-
  ;; download loop gate keys on this in addition to header-tip-HEIGHT so a
  ;; heavier-but-SHORTER fork (fewer full-difficulty blocks, tip height <= ours
  ;; but more cumulative work — the classic testnet4 min-difficulty case) is
  ;; still downloaded; a height-only gate leaves such a most-work chain
  ;; unrequested (a most-work-chain liveness violation). O(index) to seed at
  ;; startup, then maintained incrementally as headers are admitted.
  (best-header-work 0 :type integer)
  ;; Download queue
  (pending-blocks (make-block-hash-table) :type hash-table)  ; hash -> height
  (in-flight (make-block-hash-table :synchronized t) :type hash-table) ; hash -> (peer . timestamp)
  (block-queue (make-hash-table :test 'eql) :type hash-table)  ; height -> (block . wire-bytes), out-of-order
  (block-queue-bytes 0 :type integer)  ; sum of queued wire-bytes (see +max-block-queue-bytes+)
  ;; Blocks persisted to DISK above the active tip: height -> list of hashes
  ;; (Core BLOCK_HAVE_DATA semantics — AcceptBlock stores every accepted
  ;; block immediately; ActivateBestChain connects from disk). The
  ;; out-of-order receive path persists each witness-complete block and
  ;; records it here; drain-block-queue falls back to this map when the RAM
  ;; block-queue misses at the next height, so a queue cap-drop, a
  ;; same-height fork collision, or a restart can never strand a persisted
  ;; block above the tip. Re-seeded from disk by queue-blocks-for-download
  ;; after restart. Without this durable path, a deep reorg livelocks: the
  ;; winning fork's blocks above tip+1 sat only in RAM, perform-reorg
  ;; (all-or-nothing, disk-only) never saw them, and the per-peer download
  ;; walk could not distinguish them from missing blocks.
  (disk-blocks-above-tip (make-hash-table :test 'eql) :type hash-table)
  ;; Deep-reorg candidate SET: hashes of PERSISTED blocks whose chain
  ;; outweighs the active tip (Core setBlockIndexCandidates, restricted to
  ;; what we hold on disk). Core re-evaluates the best chain after every
  ;; accepted block; our receive path is height-dispatched, so a block that
  ;; wins the reorg only above tip+1 (or below the tip on a heavier-shorter
  ;; fork) otherwise never gets a reorg attempted. retry-best-reorg-candidate
  ;; walks this set for the highest-work COMPLETABLE target — a work-ordered
  ;; SET, not a single slot, so a higher-work but unobtainable fork can never
  ;; starve a lower-work obtainable one. Recorded by the receive path and the
  ;; download walk (re-arms after restart). hash -> t.
  (reorg-candidates (make-block-hash-table) :type hash-table)
  ;; Hashes of candidates whose reorg deterministically FAILED validation, or
  ;; that stayed refused past the retry throttle — so the retry stops
  ;; re-attempting a doomed/never-completable fork every cycle. hash -> t.
  (rejected-reorg-candidates (make-block-hash-table) :type hash-table)
  ;; Core m_blocks_unlinked: fork candidates that cannot be tried because a body
  ;; on their branch is missing. Keyed by the hash of THAT body, so the drain on
  ;; arrival is O(1). PARKED-REORG-CANDIDATES is the same information keyed the
  ;; other way, so the candidate scan can skip a parked branch in O(1) instead
  ;; of re-walking it. See %PARK-UNLINKED-REORG-CANDIDATE.
  (unlinked-reorg-candidates (make-block-hash-table) :type hash-table)
  (parked-reorg-candidates (make-block-hash-table) :type hash-table)
  ;; Exponential moving average of received block wire sizes. Seeds at 1MB
  ;; (safe both ways: modern blocks ~1-2MB; early-chain blocks correct it
  ;; downward within seconds). Telemetry only since the per-peer walk
  ;; replaced the byte-aware height window: the walk's window is bounded
  ;; in block COUNT (Core BLOCK_DOWNLOAD_WINDOW) and backpressure is
  ;; enforced by the byte-capped receive queue instead.
  (avg-block-wire-bytes (* 1024 1024) :type integer)
  ;; Per-pending-hash timeout count. retry-timed-out-requests bumps the
  ;; counter each time a request for this hash times out; after
  ;; +max-block-request-timeouts+, the block is dropped from pending
  ;; (it's likely a competing-fork block that peers won't serve).
  ;; hash -> integer.
  (request-timeouts (make-block-hash-table) :type hash-table)
  ;; Configuration
  (max-in-flight 16 :type (unsigned-byte 8))
  (request-timeout 60 :type (unsigned-byte 16))  ; seconds
  ;; Progress tracking
  (start-time 0 :type integer)
  (last-progress-time 0 :type integer)
  ;; Sliding-window rate samples: list of (internal-real-time . height)
  ;; pairs, most recent first. Trimmed in report-ibd-progress to drop
  ;; entries older than +recent-rate-window-seconds+. The cumulative
  ;; rate (received/elapsed since session start) hides recent stalls in
  ;; long sessions; this gives a real-time view alongside.
  (recent-samples nil :type list)
  ;; Wall-clock seconds (get-universal-time) at the last connect-tip advance.
  ;; Used by the stuck-tip detector to halt IBD when validation can't drain
  ;; the queue (vs Core's TipMayBeStale, net_processing.cpp:1332-1340).
  (last-tip-advance-time 0 :type integer)
  (last-tip-height 0 :type (unsigned-byte 32))
  ;; Per-block delivery samples: (timestamp peer-address latency-ms) most
  ;; recent first. Trimmed in report-ibd-progress to +recent-rate-window-seconds+.
  ;; Lets us see whether slow IBD is peer-side (some peers deliver in 30s+)
  ;; or pipeline-side (peers fast but we don't request enough).
  (delivery-samples nil :type list)
  ;; Node mempool, so the block-activation path can remove confirmed txs and
  ;; re-add reorg-disconnected ones. Threaded in once at run-ibd entry rather
  ;; than through every networking function.
  (mempool nil)
  ;; Node transaction index, threaded the same way and for the same reason.
  ;; Without it the connect path runs with TX-INDEX nil, so -txindex is updated
  ;; ONLY by the startup catch-up: every block arriving from the network goes
  ;; unindexed until the next restart, and a reorg leaves the index's
  ;; best-block marker pointing at a block that is no longer on the chain.
  (tx-index nil)
  ;; Live peer list and address book for the generic message path
  ;; (handle-message :peers / :address-book). Without these, tx
  ;; ingestion/serving, tx-inv getdata, compact-block relay, and addr
  ;; gossip were all inert outside unit tests — the live loop passed
  ;; only :fee-estimator/:recent-rejects (wiring bug, fixed 2026-07-10).
  ;; Threaded in at run-ibd entry like mempool; peers is refreshed
  ;; whenever run-ibd prunes disconnected entries.
  (peers nil :type list)
  (address-book nil)
  ;; --- Assumeutxo dual-cursor state (set at run-ibd entry) ---
  ;; The historical chainstate re-deriving history toward the snapshot base
  ;; (Core HistoricalChainstate), or NIL. When set, run-ibd also queues the
  ;; [historical-tip .. base] range and routes received blocks at heights
  ;; <= base to this chainstate (Core ProcessNewBlock runs ABC on both,
  ;; validation.cpp:4463-4470).
  (historical-chain-state nil)
  ;; Block-index entry of the snapshot base (the historical chainstate's
  ;; target). Height boundary for routing and the historical window.
  (snapshot-base-entry nil)
  ;; T while the CURRENT chainstate is an unvalidated snapshot chainstate:
  ;; all block downloads are then restricted to peers whose best-known chain
  ;; contains the base — no undo data exists below the base, so we cannot
  ;; reorg across it (Core net_processing.cpp:1412-1421 for the tip range,
  ;; TryDownloadingHistoricalBlocks:1458-1471 for the historical range).
  (snapshot-unvalidated-p nil)
  ;; Memo for the base-in-chain peer test, keyed by the peer's best-known
  ;; block hash (the walk from a peer tip down to the base is O(tip-base);
  ;; best-known hashes change rarely within a session). Recreated with the
  ;; context, so it can never go stale across snapshot changes.
  (base-in-chain-cache (make-block-hash-table) :type hash-table))

(defparameter +recent-rate-window-seconds+ 60
  "Window for the recent-rate metric in IBD Progress logs. 60s gives a
useful real-time view of throughput swings (peer disconnects, stress
regions) that the cumulative session-average smooths over.")

(defparameter +max-block-request-timeouts+ 5
  "Drop a block from the pending queue after this many request timeouts.
Competing-fork-block headers get auto-queued by process-headers; most
peers don't serve blocks on chains they don't follow, so requests time
out indefinitely. After N timeouts we give up — if the fork later
catches up, the activate-block path will request the block again on
demand. Mirrors Bitcoin Core's MAX_HEADERS_RESULTS retry caps in
net_processing.cpp.")

(declaim (inline trim-samples-older-than))
(defun trim-samples-older-than (samples cutoff-ticks)
  "Drop entries whose head (timestamp in internal-time units) is older
than CUTOFF-TICKS. Works on both `recent-samples` (time . height) cons
cells and `delivery-samples` (time peer-address latency-ms) lists."
  (delete-if (lambda (s) (< (first s) cutoff-ticks)) samples))

(defvar *ibd-context* nil
  "Current IBD context.")

;;; *ibd-stop-requested* is defined in connection.lisp (the first-loaded
;;; networking file) so the low-level socket read can poll it; the IBD inner
;;; loops below poll it so a TERM exits the sync thread within seconds instead
;;; of running until the pending queue drains.
(defun request-ibd-stop ()
  "Ask the IBD loops to exit at the next check point."
  (setf *ibd-stop-requested* t))

(defun reset-ibd-stop ()
  "Clear a previous stop request (called at node start). Also re-latches
the IBD-status cache to \"in IBD\" so a restarted node re-proves tip
freshness before requesting loose txs (Core resets m_cached_is_ibd per
process; reset here covers in-image restarts and tests)."
  (setf *ibd-stop-requested* nil)
  (setf *cached-is-ibd* t))

(defvar *ibd-gap-only-mode* nil
  "Set by request-blocks-from-peers when the queue is at cap and the
   next-needed block is missing. In this mode the block-request budget
   is clamped to 1 (the gap block only) so the request flood that
   previously filled the heap cannot reoccur.")

(defun note-tip-advanced (chain-state)
  "Record that the connect-tip just advanced. Resets the stuck-tip timer."
  (when *ibd-context*
    (setf (ibd-context-last-tip-advance-time *ibd-context*) (get-universal-time)
          (ibd-context-last-tip-height *ibd-context*)
          (bitcoin-lisp.storage:current-height chain-state))))

;;;; Per-peer block-availability tracking
;;;;
;;;; Mirrors Bitcoin Core's ProcessBlockAvailability / UpdateBlockAvailability
;;;; (net_processing.cpp:1361-1392). The key invariant: a peer's
;;;; best-known-block-hash points to a block-index-entry whose chain
;;;; ancestor relation determines which blocks we can ask THIS peer for.
;;;;
;;;; Hook points:
;;;;   - inv "block": update with the announced hash.
;;;;   - headers: update with the last header in the batch (peer's tip).
;;;;   - block: update with the block's hash (proof peer had it).
;;;;
;;;; The hash-last-unknown-block slot stages a hash we received in inv
;;;; before we had a chain-state entry for it. Once the corresponding
;;;; header arrives, the next process-block-availability call resolves
;;;; it to a proper best-known-block.

(defun better-or-equal-work-p (a b)
  "T if entry A is at least as good as entry B (in chain-work terms).
B may be NIL, in which case A is trivially better — A is a known
entry, B is the absence of one. A NIL → NIL (caller shouldn't update
to nothing). Matches Bitcoin Core's `state->pindexBestKnownBlock ==
nullptr || pindex->nChainWork >= state->pindexBestKnownBlock->nChainWork`
shape in net_processing.cpp:1368."
  (when a
    (or (null b)
        (>= (bitcoin-lisp.storage:block-index-entry-chain-work a)
            (bitcoin-lisp.storage:block-index-entry-chain-work b)))))

(defvar *highest-header-seen* 0
  "Highest block height we have ever held a header for, across sync passes.

The IBD context is created per pass, so its header-tip-height is gone by the
time the sync loop settles into its between-pass wait — which is exactly when
knowing whether we are BEHIND is worth something. A hint only: it shortens the
wait, and decides nothing about the chain.")

(defun process-block-availability (peer chain-state)
  "Resolve PEER's hash-last-unknown-block to a chain-state entry if we
now have one for it. Promotes to best-known-block-hash when the staged
hash has at least as much chain-work as the current best-known."
  (let ((staged (peer-hash-last-unknown-block peer)))
    (when staged
      (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state staged)))
        (when (and entry
                   (plusp (bitcoin-lisp.storage:block-index-entry-chain-work entry)))
          (let ((current (and (peer-best-known-block-hash peer)
                              (bitcoin-lisp.storage:get-block-index-entry
                               chain-state (peer-best-known-block-hash peer)))))
            (when (better-or-equal-work-p entry current)
              (setf (peer-best-known-block-hash peer) staged)))
          (setf (peer-hash-last-unknown-block peer) nil))))))

(defun update-block-availability (peer chain-state hash)
  "PEER announced (via inv / headers / block) that it has HASH. Update
its best-known-block-hash if HASH is in our index AND has at least as
much work as the current best-known; otherwise stage HASH for later
resolution (the header may arrive in a subsequent message)."
  (process-block-availability peer chain-state)
  (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))
    (cond
      ((and entry
            (plusp (bitcoin-lisp.storage:block-index-entry-chain-work entry)))
       (let ((current (and (peer-best-known-block-hash peer)
                           (bitcoin-lisp.storage:get-block-index-entry
                            chain-state (peer-best-known-block-hash peer)))))
         (when (better-or-equal-work-p entry current)
           (setf (peer-best-known-block-hash peer) hash))))
      (t
       ;; Unknown block — assume the latest one is best until we learn
       ;; otherwise. Mirrors Core's hashLastUnknownBlock fallback
       ;; (net_processing.cpp:1390).
       (setf (peer-hash-last-unknown-block peer) hash)))))

(defun peer-best-known-height (peer chain-state)
  "PEER's best-advertised block height, or NIL if we have no availability
info for it yet. Used as a cheap routing proxy for Bitcoin Core's
FindNextBlocksToDownload ancestor test (net_processing.cpp:1437): a peer
whose best-known tip is below a block's height cannot have that block.
Deliberately height-only — no chain ancestor walk — because the
skip-list ancestor index was reverted for a live regression (PR #71)."
  (let ((bk (peer-best-known-block-hash peer)))
    (when bk
      (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state bk)))
        (when entry
          (bitcoin-lisp.storage:block-index-entry-height entry))))))

(defun peer-chain-contains-base-p (peer chain-state)
  "T iff PEER's best-known chain contains the snapshot base block — i.e. the
base entry is an ancestor of the peer's best-known block (Core
`state->pindexBestKnownBlock->GetAncestor(base->nHeight) == base`,
net_processing.cpp:1412-1421). NIL when we have no availability info for
the peer yet (Core also refuses to download from such peers while the
snapshot is unvalidated). Memoized per best-known hash on the IBD context."
  (let ((ctx *ibd-context*))
    (when ctx
      (let ((base (ibd-context-snapshot-base-entry ctx))
            (bk (peer-best-known-block-hash peer)))
        (when (and base bk)
          (let ((cache (ibd-context-base-in-chain-cache ctx)))
            (multiple-value-bind (cached present) (gethash bk cache)
              (if present
                  cached
                  (let* ((bk-entry (bitcoin-lisp.storage:get-block-index-entry
                                    chain-state bk))
                         (result
                           (and bk-entry
                                (eq base
                                    (bitcoin-lisp.storage:entry-ancestor-at-height
                                     bk-entry
                                     (bitcoin-lisp.storage:block-index-entry-height base)))
                                t)))
                    ;; Bound the memo (best-known hashes churn slowly; 4096
                    ;; is far beyond any realistic peer set).
                    (when (> (hash-table-count cache) 4096)
                      (clrhash cache))
                    (setf (gethash bk cache) result))))))))))

(defun drop-pending-block (hash)
  "Remove HASH from the pending queue and its timeout counter, once a
request for it has timed out too many times."
  (when *ibd-context*
    (remhash hash (ibd-context-pending-blocks *ibd-context*))
    (remhash hash (ibd-context-request-timeouts *ibd-context*))))

(defun peer-inflight-block-hashes (peer)
  "Block hashes currently requested from PEER and not yet received — the
source of getpeerinfo's \"inflight\" heights (Core CNodeStateStats::
vHeightInFlight). Snapshots the synchronized in-flight table under its lock
so RPC threads can read while the sync thread mutates."
  (let ((result '()))
    (when *ibd-context*
      (let ((in-flight (ibd-context-in-flight *ibd-context*)))
        (flet ((scan ()
                 (maphash (lambda (hash entry)
                            (when (eq (car entry) peer)
                              (push hash result)))
                          in-flight)))
          #+sbcl (sb-ext:with-locked-hash-table (in-flight) (scan))
          #-sbcl (scan))))
    result))

(defun %context-tx-index ()
  "The live transaction index, from the IBD context.

Every activate-block / activate-best-chain call on this path takes the index as
an argument, and each one that omitted it silently disabled the index for the
blocks it connected: their transactions never entered it, and a reorg left the
best-block marker naming a block that had just been disconnected, so the next
startup rescanned from genesis. That omission has now been found three separate
times (PR #372 on the arrival path, and five more sites here), always the same
way — from a live log line, never from a test. Read it from the context rather
than accepting it per-caller, so a new call site cannot reintroduce it by
forgetting an argument."
  (and *ibd-context* (ibd-context-tx-index *ibd-context*)))

(defun queue-missing-fork-blocks (missing-blocks)
  "MISSING-BLOCKS is a list of (hash . height) cons cells, returned by
perform-reorg when it refused due to blocks missing from the store.
Add each to the pending queue, reset its timeout counter, and REWIND each
ready peer's per-peer download cursor to below the lowest missing height so
the next chain walk re-derives from the fork point and re-requests the hole.
The rewind is essential under the layer-5 scheduler: the walk requests from
each peer's chain (not from pending-blocks), and once a peer's cursor has
advanced past the hole it would never re-request it — the re-queue alone is
a dead letter. Without recovery, perform-reorg refuses on the same missing
block forever (the deferred-reorg loop bug, project_per_peer_block_tracking.md)."
  (unless (and *ibd-context* missing-blocks)
    (return-from queue-missing-fork-blocks 0))
  (let ((pending (ibd-context-pending-blocks *ibd-context*))
        (in-flight (ibd-context-in-flight *ibd-context*))
        (timeouts (ibd-context-request-timeouts *ibd-context*))
        (queued 0))
    (dolist (cell missing-blocks)
      (let ((hash (car cell)) (height (cdr cell)))
        ;; Only queue if not already pending or in-flight.
        (unless (or (gethash hash pending) (gethash hash in-flight))
          (setf (gethash hash pending) height)
          ;; Reset the timeout counter so this is a fresh download attempt.
          (remhash hash timeouts)
          (incf queued))))
    ;; Rewind cursors at/above the lowest missing block so the per-peer walk
    ;; revisits the hole. Setting to NIL is safe and self-limiting: the next
    ;; walk recomputes last-common = fork point and re-requests only what we
    ;; still lack (a one-time O(window) rewalk per peer).
    (dolist (peer (ibd-context-peers *ibd-context*))
      (setf (peer-last-common-block-hash peer) nil))
    (when (plusp queued)
      (bitcoin-lisp:log-warn "Re-queued ~D missing fork blocks for download (cursors rewound)"
                             queued))
    queued))

(defparameter +max-block-revalidation-attempts+ 3
  "Consecutive validation failures for the same block hash after which we stop
re-requesting it in the tight receive->validate->re-request loop. The stuck-tip
detector and normal header/tip sync remain the recovery path, so this is a PAUSE,
not a permanent reject — a later witness-complete copy (same hash) can still be
processed and connect. A single bad/witness-stripped block spun this loop
indefinitely and spammed 6.5M log lines / 1.1GB on testnet4
(project_cmpctblock_witness_wedge).")

(defparameter +block-failure-counts-cap+ 4096
  "Hard cap on the failure-count map; cleared wholesale on overflow (losing a few
counts only grants a few extra retries — harmless).")

(defvar *block-failure-counts* (make-hash-table :test 'equalp)
  "block-hash -> consecutive validation-failure count (bounded anti-spam throttle).")

(defun note-block-failure (hash)
  "Increment and return the consecutive validation-failure count for HASH."
  (when (>= (hash-table-count *block-failure-counts*) +block-failure-counts-cap+)
    (clrhash *block-failure-counts*))
  (setf (gethash hash *block-failure-counts*)
        (1+ (gethash hash *block-failure-counts* 0))))

(defun clear-block-failure (hash)
  "Forget HASH's failure count — call when a block connects successfully so a
later reorg/re-org through the same hash starts with a fresh retry budget."
  (remhash hash *block-failure-counts*))

(defun handle-validation-failure (block height error chain-state)
  "Handle a block-validation failure during IBD, with a bounded retry budget.

For the first +max-block-revalidation-attempts+ failures of a given block hash we
re-add it to pending-blocks so it can be re-requested from another peer (the
failure may be peer-side corruption rather than a real consensus violation) and
log the error. Past the budget we STOP re-queuing it (and go silent) so one
persistently-failing block cannot spin the tight receive->validate->re-request
loop or spam the log — the stuck-tip detector + normal sync remain the recovery
path. This is a pause keyed on the count, never a permanent reject of the hash, so
a witness-complete copy with the same hash can still connect later.

Bitcoin Core punishes the source peer in MaybePunishNodeForBlock
(net_processing.cpp) on BLOCK_CONSENSUS / BLOCK_MUTATED but does not re-request —
Core trusts its own validator. Ours is less battle-tested, so we re-request a few
times before pausing."
  (declare (ignore chain-state))
  (when *ibd-context*
    (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
           (hash (bitcoin-lisp.serialization:block-header-hash header))
           (pending (ibd-context-pending-blocks *ibd-context*))
           (in-flight (ibd-context-in-flight *ibd-context*))
           (count (note-block-failure hash)))
      ;; Always free the in-flight slot so a retry / another peer's copy can come.
      (remhash hash in-flight)
      (cond
        ((<= count +max-block-revalidation-attempts+)
         (bitcoin-lisp:log-error "Block ~D validation failed: ~A (attempt ~D/~D)"
                                 height error count +max-block-revalidation-attempts+)
         (unless (gethash hash pending)
           (setf (gethash hash pending) height)))
        ((= count (1+ +max-block-revalidation-attempts+))
         ;; Cross the budget exactly once, then go quiet.
         (bitcoin-lisp:log-warn
          "Block ~D (~A) failed validation ~D times; pausing tight re-request (stuck-tip detector + normal sync remain the recovery path)"
          height (bitcoin-lisp.crypto:bytes-to-hex hash) count))))))

(defun check-stuck-tip ()
  "Halt IBD if the connect-tip has not advanced for longer than
+stuck-tip-halt-seconds+ AND the block-queue is near its cap. Returns
T if we should halt.

This is the backstop that prevents the failure mode observed at testnet4
height 70700 (May 2 16:32 crash): a permanently-failing connect-tip
block, no advance for 1h 40m, queue grew unbounded until heap exhaustion.
With this check, we halt cleanly instead of OOM-ing.

The queue-near-cap guard avoids false positives during fork-recovery,
where we have a handful of fork blocks in the queue waiting for missing
intermediates to arrive. In that scenario the queue stays small (1-15
blocks) and is no OOM risk — but the old `(plusp queue-size)` check
fired the 5-minute timeout repeatedly, causing peer-rotation churn that
made the recovery slower (test-bitcoin-server 2026-05-21 06:46–07:07
saw 3 STUCK TIP cycles before a 13-block reorg finally completed)."
  (when *ibd-context*
    (let* ((last-time (ibd-context-last-tip-advance-time *ibd-context*))
           (queue-size (hash-table-count
                        (ibd-context-block-queue *ibd-context*)))
           (queue-bytes (ibd-context-block-queue-bytes *ibd-context*))
           ;; Near-cap on EITHER axis: the 256MB byte cap pins the count
           ;; at ~170 modern 1.5MB blocks — far below 90% of the 1024
           ;; count cap — so a count-only check never fired during the
           ;; June 2026 two-day stall at h=851,912; the node retried
           ;; forever instead of halting as designed.
           (near-cap (or (>= queue-size
                             (floor (* +max-block-queue-size+ 9/10)))
                         (>= queue-bytes
                             (floor (* +max-block-queue-bytes+ 9/10))))))
      (when (and (plusp last-time)
                 near-cap
                 (> (- (get-universal-time) last-time)
                    +stuck-tip-halt-seconds+))
        (bitcoin-lisp:log-error
         "STUCK TIP: connect-tip has not advanced in ~D seconds; ~D blocks / ~DMB queued. Halting IBD to avoid OOM. Investigate validator."
         (- (get-universal-time) last-time) queue-size
         (floor queue-bytes 1048576))
        t))))

(defun make-ibd ()
  "Create a new IBD context."
  (make-ibd-context :start-time (get-internal-real-time)))

(defun ibd-state ()
  "Get the current IBD state."
  (if *ibd-context*
      (ibd-context-state *ibd-context*)
      :idle))

(defun set-ibd-state (new-state)
  "Transition to a new IBD state."
  (when *ibd-context*
    (let ((old-state (ibd-context-state *ibd-context*)))
      (unless (eq old-state new-state)
        (setf (ibd-context-state *ibd-context*) new-state)
        (bitcoin-lisp:log-info "IBD state: ~A -> ~A" old-state new-state)))))

;;;; Network Checkpoints

(defvar *testnet3-checkpoints*
  '((546 . "000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")
    (100000 . "00000000009e2958c15ff9290d571bf9459e93b19765c6801ddeccadbb160a1e")
    (500000 . "000000000001a7c0aaa2630fbb2c0e476aafffc60f82177375b2aaa22209f606")
    (1000000 . "0000000000478e259a3eda2fafbeeb0106626f946347955e99278fe6cc848414")
    (1500000 . "00000000000000a33e21d6d82fe7cef5b35dfe75af01baafa5df7c11e69cf099")
    (2000000 . "0000000000000795a6501e606e3fd3b3f51c6d9e47d3a1ba83c3fb1e84d50b7a"))
  "Testnet checkpoints as (height . hex-hash) pairs.")

(defvar *mainnet-checkpoints*
  '((11111 . "0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")
    (33333 . "000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")
    (74000 . "0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")
    (105000 . "00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")
    (134444 . "00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")
    (168000 . "000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")
    (193000 . "000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")
    (210000 . "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")
    (250000 . "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")
    (295000 . "00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")
    (420000 . "000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74f112")
    (630000 . "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d")
    (840000 . "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"))
  "Mainnet checkpoints as (height . hex-hash) pairs.
Verified against Bitcoin Core chainparams.cpp.")

;; Testnet4 and signet: no checkpoints yet (new networks)
(defvar *testnet4-checkpoints* '()
  "Testnet4 checkpoints.")

(defvar *signet-checkpoints* '()
  "Signet checkpoints.")

(defun network-checkpoints (network)
  "Return the checkpoint list for NETWORK."
  (ecase network
    (:testnet3 \*testnet3-checkpoints*)
    (:testnet4 *testnet4-checkpoints*)
    (:signet *signet-checkpoints*)
    (:regtest nil)                       ; regtest has no checkpoints
    (:mainnet *mainnet-checkpoints*)))

(defun get-checkpoint-hash (height)
  "Get the checkpoint hash for HEIGHT, or NIL if no checkpoint exists.
Returns the hash in wire format (little-endian).
Uses the current network from bitcoin-lisp:*network*."
  (let* ((checkpoints (network-checkpoints bitcoin-lisp:*network*))
         (entry (assoc height checkpoints)))
    (when entry
      ;; Checkpoints are stored in display format (big-endian), reverse for wire format
      (reverse (bitcoin-lisp.crypto:hex-to-bytes (cdr entry))))))

(defun last-checkpoint-height ()
  "Get the height of the last checkpoint for the current network."
  (let ((checkpoints (network-checkpoints bitcoin-lisp:*network*)))
    (if checkpoints
        (caar (last checkpoints))
        0)))

(defun default-assumevalid ()
  "The current network's defaultAssumeValid hash in wire order, or NIL.
The table itself now lives in config.lisp as NETWORK-ASSUMEVALID, because the
validation layer must consult it per block and loads before this file."
  (bitcoin-lisp:network-assumevalid bitcoin-lisp:*network*))

(defun assumevalid-skip-height (chain-state)
  "Height of the hardcoded assumevalid block when its header is already in our
index (i.e. we are syncing the chain that contains it), else -1. Blocks at or
below this height may skip SIGNATURE checks: the assumevalid hash is unforgeable,
so a block carrying it pins a known-good ancestor chain. Mirrors Bitcoin Core's
-assumevalid (sigs skipped for ancestors of the assumed-valid block)."
  (let ((av (default-assumevalid)))
    (if (null av)
        -1
        (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state av)))
          (if entry
              (bitcoin-lisp.storage:block-index-entry-height entry)
              -1)))))

(defun script-skip-height (chain-state)
  "Highest height at which a signature skip is even CONSIDERED: the assumevalid
block's height, or -1 when its header is not in our index.

This is a cheap pre-filter only. The decision itself is
BITCOIN-LISP.VALIDATION:SCRIPT-CHECKS-SKIPPABLE-P, which additionally requires
the block to be an ANCESTOR of the assumevalid block — Core's fScriptChecks
(validation.cpp:2342-2380) is a per-block predicate, not a height comparison.

The checkpoint term is GONE. Checkpoints play no part in Core's fScriptChecks,
and including them meant that whenever the assumevalid header was not yet in
our index — the entire first phase of a fresh IBD — we skipped every signature
up to 840,000 on mainnet and 2,000,000 on testnet3, where Core verifies all of
them."
  (assumevalid-skip-height chain-state))

(defun validate-checkpoint (hash height)
  "Validate that HASH at HEIGHT matches any applicable checkpoint.
Returns T if valid or no checkpoint at that height, NIL if checkpoint mismatch."
  (let ((checkpoint-hash (get-checkpoint-hash height)))
    (or (null checkpoint-hash)
        (equalp hash checkpoint-hash))))

;;;; Header Chain Validation

(defun validate-header-pow (header)
  "Validate proof-of-work for a header. Delegates to the consensus
check-proof-of-work, which derives the target with derive-target -- so a header
whose nBits is negative / zero / overflowing / above the PoW limit is rejected
(Core CheckBlockHeader), not silently decoded as an in-range target."
  (bitcoin-lisp.validation:check-proof-of-work header))

(defun validate-header-chain (headers chain-state)
  "Validate a list of headers against the current chain state.
Returns (VALUES valid-headers error-message).
VALID-HEADERS is a list of headers that passed validation (may be fewer than input)."
  (let ((valid-headers '())
        (prev-hash nil)
        (prev-entry nil)
        (prev-height -1))  ; Track height of previous header in this batch
    (dolist (header headers)
      (block continue
        (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
               (header-prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))

          ;; Check if we already have this header
          (when (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
            (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))
              (setf prev-hash hash)
              (setf prev-entry entry)
              (setf prev-height (bitcoin-lisp.storage:block-index-entry-height entry)))
            (return-from continue))

          ;; Check chain linkage - use previous header from this batch if it matches
          (let ((parent (cond
                          ;; Previous header in this batch is the parent
                          ((and prev-hash (equalp header-prev-hash prev-hash))
                           prev-entry)
                          ;; Look up in chain-state
                          (t
                           (bitcoin-lisp.storage:get-block-index-entry
                            chain-state header-prev-hash)))))
            (unless parent
              ;; No parent found, stop here
              (return-from validate-header-chain
                (values (nreverse valid-headers)
                        (format nil "Missing parent ~A"
                                (bitcoin-lisp.crypto:bytes-to-hex header-prev-hash)))))

            ;; Validate proof-of-work
            (unless (validate-header-pow header)
              (return-from validate-header-chain
                (values (nreverse valid-headers)
                        (format nil "Invalid proof-of-work for header ~A"
                                (bitcoin-lisp.crypto:bytes-to-hex hash)))))

            ;; Reject headers timestamped too far in the future (Core
            ;; ContextualCheckBlockHeader: block time > now + 2h). Admitting one
            ;; would pollute the index / inflate best-header chain-work with a
            ;; header Core refuses at admission.
            ;;
            ;; Name the header and the overshoot. This fires constantly and
            ;; benignly on testnet4, whose tip legitimately runs close to the
            ;; +2h bound, so the interesting question is always "by how much,
            ;; and is it the same header every time" — which the bare message
            ;; could not answer (33,567 of 141,693 lines on the live node,
            ;; 2026-08-20, none of them actionable).
            (let ((overshoot (- (bitcoin-lisp.serialization:block-header-timestamp header)
                                (+ (bitcoin-lisp.serialization:get-unix-time)
                                   bitcoin-lisp.validation:+max-future-block-time+))))
              (when (plusp overshoot)
                (return-from validate-header-chain
                  (values (nreverse valid-headers)
                          (format nil "Timestamp too far in the future for header ~A (~Ds past the ~Ds bound)"
                                  (bitcoin-lisp.crypto:bytes-to-hex hash)
                                  overshoot
                                  bitcoin-lisp.validation:+max-future-block-time+)))))

            ;; Validate timestamp > median-time-past. PARENT, not
            ;; HEADER-PREV-HASH: a mid-batch parent is a staging entry that is
            ;; not in the index yet, so a hash lookup would find nothing and the
            ;; comparison would pass for every header after the first.
            (when (bitcoin-lisp.validation:header-time-too-old-p header parent)
              (return-from validate-header-chain
                (values (nreverse valid-headers)
                        (format nil "Timestamp at or before median-time-past for header ~A"
                                (bitcoin-lisp.crypto:bytes-to-hex hash)))))

            ;; Calculate new height and validate checkpoint
            (let* ((parent-height (if (eq parent prev-entry)
                                      prev-height
                                      (bitcoin-lisp.storage:block-index-entry-height parent)))
                   (new-height (1+ parent-height)))

              ;; Validate difficulty adjustment
              (multiple-value-bind (valid error)
                  (bitcoin-lisp.validation:validate-difficulty
                   header new-height parent)
                (declare (ignore error))
                (unless valid
                  (return-from validate-header-chain
                    (values (nreverse valid-headers)
                            (format nil "Bad difficulty at height ~D" new-height)))))
              ;; BIP94 timewarp mitigation at header ADMISSION (Core
              ;; ContextualCheckBlockHeader, validation.cpp:4129). This was
              ;; only enforced at connect time (validate-block-header); but
              ;; perform-reorg validates fork intermediates with :skip-header t,
              ;; so a violating testnet4 retarget-boundary block admitted here
              ;; would be counted toward chain-work and connectable on a reorg —
              ;; a consensus chain-split from the testnet4 network (the exact
              ;; cheap-fork threat BIP94 stops). No-op off testnet4 retarget
              ;; boundaries and for honest blocks, so no false-reject risk.
              (when (bitcoin-lisp.validation:bip94-timewarp-violation-p
                     header new-height parent)
                (return-from validate-header-chain
                  (values (nreverse valid-headers)
                          (format nil "BIP94 timewarp violation at height ~D" new-height))))
              ;; Softfork version minimums, gated by activation height (Core
              ;; ContextualCheckBlockHeader BIP34/66/65). No upper bound --
              ;; miners roll high version bits (overt AsicBoost).
              (let ((version (bitcoin-lisp.serialization:block-header-version header)))
                (when (or (and (< version 2)
                               (>= new-height (bitcoin-lisp.validation:get-bip34-activation-height
                                               bitcoin-lisp:*network*)))
                          (and (< version 3)
                               (>= new-height (bitcoin-lisp.validation:get-bip66-activation-height
                                               bitcoin-lisp:*network*)))
                          (and (< version 4)
                               (>= new-height (bitcoin-lisp.validation:get-bip65-activation-height
                                               bitcoin-lisp:*network*))))
                  (return-from validate-header-chain
                    (values (nreverse valid-headers)
                            (format nil "Bad version at height ~D" new-height)))))

              (unless (validate-checkpoint hash new-height)
                (return-from validate-header-chain
                  (values (nreverse valid-headers)
                          (format nil "Checkpoint mismatch at height ~D" new-height))))

              ;; Header is valid - create temp entry for chain linkage of next header
              (push header valid-headers)
              (setf prev-hash hash)
              (setf prev-height new-height)
              (setf prev-entry
                    (bitcoin-lisp.storage:make-block-index-entry
                     :hash hash
                     :height new-height
                     :header header
                     :prev-entry parent
                     :chain-work 0  ; Don't need accurate chain work for validation
                     :status :header-valid)))))))

    (values (nreverse valid-headers) nil)))

;;;; Enhanced Header Handling

(defun process-headers (headers chain-state)
  "Process validated headers and add to block index.
Adds headers to the index but does NOT update the chain tip (best-height),
since headers are not yet validated as full blocks.
The header tip is tracked in the IBD context for download coordination.

Side-effect: queues each newly-added HEADER-VALID entry for block
download in the IBD context. Without this, headers arriving during
tip-tracking (e.g. for a competing fork) never had their blocks fetched
— queue-blocks-for-download only ran once at IBD entry. The result was
that near-tip reorgs got stuck: we had the canonical fork's headers
but never the blocks, so perform-reorg couldn't apply them.

Returns the number of new headers added."
  (let ((added 0)
        (best-header-height (if *ibd-context*
                                (ibd-context-header-tip-height *ibd-context*)
                                0))
        (newly-added '())
        ;; nMinimumChainWork anti-DoS gate (Core AcceptBlockHeader min_pow_checked).
        ;; Once our active chain is past the work floor, refuse any header whose
        ;; chain would fall below it — a peer cannot bloat the index with a long
        ;; low-work fork. During a fresh genesis sync (tip below the floor) the
        ;; gate is off, so honest sync proceeds until it crosses the floor.
        (min-work (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*))
        (past-min-work
          (let ((tip (bitcoin-lisp.storage:get-block-index-entry
                      chain-state (bitcoin-lisp.storage:best-block-hash chain-state))))
            (and tip (>= (bitcoin-lisp.storage:block-index-entry-chain-work tip)
                         (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*))))))
    (dolist (header headers)
      (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
             (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))
        ;; Skip if already have it
        (unless (bitcoin-lisp.storage:get-block-index-entry chain-state hash)
          (let ((prev-entry (bitcoin-lisp.storage:get-block-index-entry
                             chain-state prev-hash)))
            (when prev-entry
              (let* ((new-height (1+ (bitcoin-lisp.storage:block-index-entry-height
                                      prev-entry)))
                     (prev-work (bitcoin-lisp.storage:block-index-entry-chain-work
                                 prev-entry))
                     (bits (bitcoin-lisp.serialization:block-header-bits header))
                     (new-work (bitcoin-lisp.storage:calculate-chain-work
                                bits prev-work)))
                (cond
                  ;; BLOCK_FAILED_CHILD at header admission (Core
                  ;; AcceptBlockHeader: pindexPrev->nStatus & BLOCK_FAILED_MASK
                  ;; -> this header is BLOCK_FAILED_CHILD and never becomes a
                  ;; download candidate). A header extending a block already
                  ;; marked :invalid is itself permanently invalid, so an
                  ;; attacker cannot make us fetch a doomed subtree by extending
                  ;; a known-invalid block with fresh headers. Keep it in the
                  ;; index marked :invalid — so its OWN descendants are
                  ;; recognized and FAILED_CHILD'd in turn — but do NOT push it to
                  ;; newly-added, so it is never queued for download. Safe because
                  ;; :invalid is ONLY ever set on a deterministic consensus
                  ;; verdict (see block.lisp %deterministic-consensus-failure-p);
                  ;; the transient reorg-refusal paths never mark :invalid.
                  ((eq (bitcoin-lisp.storage:block-index-entry-status prev-entry)
                       :invalid)
                   (bitcoin-lisp.storage:add-block-index-entry
                    chain-state
                    (bitcoin-lisp.storage:make-block-index-entry
                     :hash hash
                     :height new-height
                     :header header
                     :prev-entry prev-entry
                     :chain-work new-work
                     :status :invalid)))
                  ;; Anti-DoS: when already synced past the floor, drop headers
                  ;; whose chain is still below it (a fresh low-work fork an
                  ;; attacker is trying to plant). Legitimate near-tip forks have
                  ;; chain-work far above the floor and are unaffected. Matched
                  ;; with an empty body = dropped (not added, not queued).
                  ((and past-min-work (< new-work min-work)))
                  (t
                   (let ((entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash hash
                                 :height new-height
                                 :header header
                                 :prev-entry prev-entry
                                 :chain-work new-work
                                 :status :header-valid)))
                     (bitcoin-lisp.storage:add-block-index-entry chain-state entry)
                     (push (cons hash new-height) newly-added)
                     (incf added)
                     ;; Track header tip height in IBD context
                     (when (> new-height best-header-height)
                       (setf best-header-height new-height))
                     ;; Maintain best-header-WORK incrementally (monotonic max)
                     ;; so the download-loop gate can key on work, not just
                     ;; height — a heavier-but-shorter fork must still be fetched.
                     (when (and *ibd-context*
                                (> new-work (ibd-context-best-header-work *ibd-context*)))
                       (setf (ibd-context-best-header-work *ibd-context*) new-work)))))))))))
    ;; Highest header seen, kept OUTSIDE the IBD context too. The context is
    ;; per-sync-pass; this survives it, so the sync loop's between-pass wait can
    ;; tell "at the tip, nothing to do" from "behind, waiting for no reason".
    ;; Monotone, and only ever a hint: the wait uses it to shorten itself, never
    ;; to decide anything about the chain.
    (when (> best-header-height *highest-header-seen*)
      (setf *highest-header-seen* best-header-height))
    ;; Update header tip in IBD context (not the chain-state best-height)
    (when *ibd-context*
      (setf (ibd-context-header-tip-height *ibd-context*) best-header-height)
      ;; Queue each newly-added header's block for download (unless it's
      ;; already pending or in-flight). This is what makes near-tip-reorg
      ;; fork chains downloadable — headers for the competing fork at
      ;; heights ≤ current-height would otherwise sit in the index
      ;; forever without a corresponding block ever being requested.
      (let ((pending (ibd-context-pending-blocks *ibd-context*))
            (in-flight (ibd-context-in-flight *ibd-context*)))
        (dolist (cell newly-added)
          (let ((hash (car cell)) (height (cdr cell)))
            (unless (or (gethash hash pending) (gethash hash in-flight))
              (setf (gethash hash pending) height))))))
    added))

;;;; Download Queue Management

(defun queue-blocks-for-download (chain-state start-height end-height)
  "Queue blocks for download from START-HEIGHT to END-HEIGHT.
Walks the header chain and adds block hashes to the pending queue."
  (unless *ibd-context*
    (return-from queue-blocks-for-download 0))

  (let ((queued 0)
        (pending (ibd-context-pending-blocks *ibd-context*)))
    ;; Find headers at each height and queue them
    ;; This is O(n) in the chain length, but we only do it once per batch
    (maphash (lambda (hash entry)
               (let ((height (bitcoin-lisp.storage:block-index-entry-height entry)))
                 (when (and (>= height start-height)
                            (<= height end-height)
                            (eq (bitcoin-lisp.storage:block-index-entry-status entry)
                                :header-valid)
                            (not (gethash hash pending)))
                   (setf (gethash hash pending) height)
                   (incf queued))))
             (bitcoin-lisp.storage::chain-state-block-index chain-state))
    queued))

(defun queue-historical-blocks (historical-chainstate)
  "Queue the historical (background-validation) range for download:
[historical tip + 1 .. snapshot base], following the target-ancestors path
EXACTLY — no maphash over the index, so sibling forks below the base are
never queued for the historical cursor (Core TryDownloadingHistoricalBlocks
walks GetAncestor the same way, net_processing.cpp:1445-1472). Returns the
number queued."
  (unless *ibd-context*
    (return-from queue-historical-blocks 0))
  (let ((target-height (bitcoin-lisp.storage:chain-state-target-height
                        historical-chainstate)))
    (unless target-height
      (return-from queue-historical-blocks 0))
    (let ((pending (ibd-context-pending-blocks *ibd-context*))
          (in-flight (ibd-context-in-flight *ibd-context*))
          (queued 0))
      (loop for h from (1+ (bitcoin-lisp.storage:current-height historical-chainstate))
              to target-height
            for entry = (bitcoin-lisp.storage:target-ancestor-entry
                         historical-chainstate h)
            while entry
            do (let ((hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
                 (unless (or (gethash hash pending) (gethash hash in-flight))
                   (setf (gethash hash pending) h)
                   (incf queued))))
      queued)))

;; NOTE: the height-based scheduler pair `get-next-blocks-to-request` /
;; `select-peer-for-block` was removed with the layer-5 rewrite. It chose
;; blocks from the global pending set by HEIGHT and peers by best-known
;; HEIGHT — chain-membership-blind, which is what let the node fixate on a
;; fork no connected peer served. The per-peer walk below
;; (find-blocks-to-download-for-peer / find-historical-blocks-to-download)
;; is the replacement for both the tip range and the assumeutxo historical
;; range.

(defun %entry-ancestor-of-p (ancestor descendant)
  "T if ANCESTOR lies on DESCENDANT's chain (i.e. is an ancestor, or equal).
Walks DESCENDANT back to ANCESTOR's height and compares hashes. O(height diff),
no skip list."
  (when (and ancestor descendant
             (<= (bitcoin-lisp.storage:block-index-entry-height ancestor)
                 (bitcoin-lisp.storage:block-index-entry-height descendant)))
    (let ((e descendant)
          (h (bitcoin-lisp.storage:block-index-entry-height ancestor)))
      (loop while (and e (> (bitcoin-lisp.storage:block-index-entry-height e) h))
            do (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
      (and e (equalp (bitcoin-lisp.storage:block-index-entry-hash e)
                     (bitcoin-lisp.storage:block-index-entry-hash ancestor))))))

(defun find-blocks-to-download-for-peer (peer chain-state block-store count)
  "Bitcoin Core FindNextBlocksToDownload (net_processing.cpp): up to COUNT block
hashes ON THIS PEER'S CHAIN that we lack and are not in-flight, from the peer's
last-common block forward, within the download window. Because it only returns
ancestors of the peer's best-known block, the node downloads the chains its
peers actually serve rather than fixating on a fork whose blocks no connected
peer has (the testnet4 min-difficulty fork-storm wedge). Advances the peer's
LAST-COMMON-BLOCK-HASH cursor over blocks already on disk / on our active chain."
  (when (or (null *ibd-context*) (zerop count))
    (return-from find-blocks-to-download-for-peer nil))
  (process-block-availability peer chain-state)
  (let* ((best-known (and (peer-best-known-block-hash peer)
                          (bitcoin-lisp.storage:get-block-index-entry
                           chain-state (peer-best-known-block-hash peer))))
         (tip-entry (bitcoin-lisp.storage:get-block-index-entry
                     chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
         (tip-work (if tip-entry
                       (bitcoin-lisp.storage:block-index-entry-chain-work tip-entry) 0)))
    ;; Peer has nothing more-work than our tip, or is below minimum chain work.
    (when (or (null best-known)
              (<= (bitcoin-lisp.storage:block-index-entry-chain-work best-known) tip-work)
              (< (bitcoin-lisp.storage:block-index-entry-chain-work best-known)
                 (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*)))
      ;; Under -debug=net, say WHICH gate closed. "gate open, nothing servable"
      ;; is the download loop's only symptom when this walk declines for every
      ;; peer, and it names none of the reasons — so diagnosing a node that can
      ;; see a heavier chain and does not fetch it starts from nothing.
      (bitcoin-lisp:log-debug
       "no-download ~A: ~A (best-known ~:[none~;h=~:*~D~], tip h=~D)"
       (peer-address peer)
       (cond ((null best-known) "peer availability unknown")
             ((<= (bitcoin-lisp.storage:block-index-entry-chain-work best-known) tip-work)
              "peer chain not heavier than our tip")
             (t "peer chain below minimum chain work"))
       (and best-known (bitcoin-lisp.storage:block-index-entry-height best-known))
       (if tip-entry (bitcoin-lisp.storage:block-index-entry-height tip-entry) -1))
      (return-from find-blocks-to-download-for-peer nil))
    ;; last-common = fork point between the peer's chain and ours, unless the
    ;; cached cursor is still a >=work ancestor of the peer's best block.
    (let* ((cached (and (peer-last-common-block-hash peer)
                        (bitcoin-lisp.storage:get-block-index-entry
                         chain-state (peer-last-common-block-hash peer))))
           (fork (bitcoin-lisp.validation:find-fork-point best-known tip-entry))
           (last-common (if (and cached
                                 (%entry-ancestor-of-p cached best-known)
                                 (>= (bitcoin-lisp.storage:block-index-entry-chain-work cached)
                                     (bitcoin-lisp.storage:block-index-entry-chain-work fork)))
                            cached fork)))
      (when (null last-common)
        (return-from find-blocks-to-download-for-peer nil))
      (setf (peer-last-common-block-hash peer)
            (bitcoin-lisp.storage:block-index-entry-hash last-common))
      (when (equalp (bitcoin-lisp.storage:block-index-entry-hash last-common)
                    (bitcoin-lisp.storage:block-index-entry-hash best-known))
        (bitcoin-lisp:log-debug
         "no-download ~A: cursor is already at the peer's best block (h=~D)"
         (peer-address peer)
         (bitcoin-lisp.storage:block-index-entry-height best-known))
        (return-from find-blocks-to-download-for-peer nil))
      (let* ((lc-hash (bitcoin-lisp.storage:block-index-entry-hash last-common))
             (window-end (+ (bitcoin-lisp.storage:block-index-entry-height last-common)
                            +max-block-queue-size+))
             (max-height (min (bitcoin-lisp.storage:block-index-entry-height best-known)
                              (1+ window-end)))
             (in-flight (ibd-context-in-flight *ibd-context*))
             ;; Per-peer service-flag guards (Core FindNextBlocks): a peer that
             ;; cannot serve witnesses is useless once segwit is active, and a
             ;; limited (pruned) peer can only serve recent blocks. :ready peers
             ;; always have services populated — %receive-and-store-version sets
             ;; peer-services before %await-verack flips the peer to :ready.
             (services (peer-services peer))
             (peer-witness-p (logtest services
                                      bitcoin-lisp.serialization:+node-witness+))
             (is-limited (and (logtest services
                                       bitcoin-lisp.serialization:+node-network-limited+)
                              (not (logtest services
                                            bitcoin-lisp.serialization:+node-network+))))
             (best-known-height (bitcoin-lisp.storage:block-index-entry-height best-known))
             (segwit-height (bitcoin-lisp.validation:get-segwit-activation-height
                             bitcoin-lisp:*network*))
             (chain '())       ; peer's chain above last-common, oldest-first
             (result '())
             (advancing t))
        ;; Walk from best-known down (skipping above the window) to last-common.
        (let ((e best-known))
          (loop while (and e (> (bitcoin-lisp.storage:block-index-entry-height e) max-height))
                do (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
          (loop while (and e (not (equalp (bitcoin-lisp.storage:block-index-entry-hash e) lc-hash)))
                do (push e chain)
                   (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e))))
        ;; Forward pass: advance the cursor over contiguous have-data blocks;
        ;; collect the first COUNT we lack and aren't in-flight.
        (block collect
          (dolist (entry chain)
            ;; Core FindNextBlocks (net_processing.cpp:1497-1500): a block
            ;; marked invalid (invalidateblock) poisons the whole chain above
            ;; it — abort the walk, keeping what we collected below it.
            (when (eq (bitcoin-lisp.storage:block-index-entry-status entry) :invalid)
              (return-from collect))
            ;; Core FindNextBlocks (net_processing.cpp:1502-1505): if this peer
            ;; cannot serve witnesses and segwit is active at this block, we would
            ;; never download it or its descendants from this peer — abort the walk
            ;; (keeping what we collected below). On our networks segwit is active
            ;; for the whole IBD range, so a non-witness peer yields nothing.
            (when (and (not peer-witness-p)
                       (>= (bitcoin-lisp.storage:block-index-entry-height entry)
                           segwit-height))
              (return-from collect))
            (let ((hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                  (h (bitcoin-lisp.storage:block-index-entry-height entry)))
              (cond
                ;; block-exists-p, not get-block: presence probe only — the
                ;; same path get-block checks, without reading + deserializing
                ;; a multi-MB block file per have-data block per tick. On-disk
                ;; blocks above the tip are (re-)recorded in
                ;; disk-blocks-above-tip as a side effect: that keeps drain's
                ;; disk fallback working across restarts (the RAM queue and
                ;; this map are both process-local, the block files are not)
                ;; without any startup-time full-index disk scan.
                ((let ((on-disk (bitcoin-lisp.storage:block-exists-p block-store hash)))
                   (when (and on-disk
                              (or (null tip-entry)
                                  (> h (bitcoin-lisp.storage:block-index-entry-height
                                        tip-entry))))
                     ;; Capped record (same ceiling as the receive path) so a
                     ;; pathological header topology can't grow the map without
                     ;; bound; and note the reorg candidate — (re-)arms the
                     ;; retry after a restart, when the arrival-time note is
                     ;; long gone but the bodies are still on disk.
                     (%record-disk-block-above-tip h hash)
                     (note-reorg-candidate entry chain-state))
                   (or on-disk
                       (let ((a (bitcoin-lisp.storage:get-block-at-height chain-state h)))
                         (and a (equalp (bitcoin-lisp.storage:block-index-entry-hash a)
                                        hash)))))
                 (when advancing
                   (setf (peer-last-common-block-hash peer) hash)))
                (t
                 (setf advancing nil)
                 (when (> h window-end) (return-from collect))
                 ;; Core FindNextBlocks (net_processing.cpp:1533-1536): never ask a
                 ;; limited (pruned) peer for a block deeper than it retains —
                 ;; NODE_NETWORK_LIMITED_MIN_BLOCKS-2 = 286 below the peer's best
                 ;; known. Skip it but keep walking toward the peer's tip, where
                 ;; shallower blocks become fetchable.
                 (unless (or (gethash hash in-flight)
                             (and is-limited
                                  (>= (- best-known-height h) 286)))
                   (push hash result)
                   (when (>= (length result) count)
                     (return-from collect))))))))
        (nreverse result)))))

(defun find-historical-blocks-to-download (peer chain-state block-store count)
  "Bitcoin Core TryDownloadingHistoricalBlocks (net_processing.cpp:1445-1472):
up to COUNT hashes on the assumeutxo background-validation range
[historical-tip+1 .. snapshot base], following the target-ancestors path —
the unique chain below the base, so no per-peer fork walk is needed. Only
peers whose best chain contains the base can serve the range (Core
GetAncestor(target.height) == target check). NIL when no historical
chainstate is active or this peer can't serve it. Replaces the historical
partition the retired height-based scheduler used to provide."
  (when (or (null *ibd-context*) (zerop count))
    (return-from find-historical-blocks-to-download nil))
  (let ((hist (ibd-context-historical-chain-state *ibd-context*))
        (base (ibd-context-snapshot-base-entry *ibd-context*)))
    (unless (and hist base (peer-chain-contains-base-p peer chain-state))
      (return-from find-historical-blocks-to-download nil))
    (let* ((from-height (bitcoin-lisp.storage:current-height hist))
           (target-height (or (bitcoin-lisp.storage:chain-state-target-height hist)
                              0))
           ;; Core: min(from_tip->nHeight + BLOCK_DOWNLOAD_WINDOW, target->nHeight)
           (window-end (min (+ from-height +max-block-queue-size+) target-height))
           (in-flight (ibd-context-in-flight *ibd-context*))
           (result '()))
      (when (>= from-height target-height)
        (return-from find-historical-blocks-to-download nil))
      (loop for h from (1+ from-height) to window-end
            for entry = (bitcoin-lisp.storage:target-ancestor-entry hist h)
            while entry
            do (let ((hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
                 (unless (or (bitcoin-lisp.storage:block-exists-p block-store hash)
                             (gethash hash in-flight))
                   (push hash result)
                   (when (>= (length result) count)
                     (loop-finish)))))
      (nreverse result))))

(defun note-block-wire-size (ctx wire-size)
  "Fold WIRE-SIZE into the context's moving average of block sizes
(0.9 old + 0.1 new, integer EMA). Ignores zero (unknown) sizes."
  (when (plusp wire-size)
    (setf (ibd-context-avg-block-wire-bytes ctx)
          (floor (+ (* 9 (ibd-context-avg-block-wire-bytes ctx)) wire-size) 10))))

(defun mark-block-in-flight (hash peer)
  "Mark a block as being requested from PEER."
  (when *ibd-context*
    (setf (gethash hash (ibd-context-in-flight *ibd-context*))
          (cons peer (get-internal-real-time)))))

(defun mark-block-received (hash)
  "Mark a block as received, removing it from pending and in-flight.
Records delivery latency (now - request-time) for the corresponding
in-flight entry so report-ibd-progress can surface p50/p95."
  (when *ibd-context*
    (when (gethash hash (ibd-context-pending-blocks *ibd-context*))
      (remhash hash (ibd-context-pending-blocks *ibd-context*))
      (incf (ibd-context-blocks-received *ibd-context*)))
    (let ((entry (gethash hash (ibd-context-in-flight *ibd-context*))))
      (when entry
        (let* ((peer (car entry))
               (sent-at (cdr entry))
               (now (get-internal-real-time))
               (latency-ms (round (* 1000 (- now sent-at))
                                  internal-time-units-per-second)))
          (push (list now (peer-address peer) latency-ms)
                (ibd-context-delivery-samples *ibd-context*)))))
    (remhash hash (ibd-context-in-flight *ibd-context*))
    ;; Clear the per-hash timeout counter so a future re-request of this
    ;; hash (e.g. on a reorg) starts fresh.
    (remhash hash (ibd-context-request-timeouts *ibd-context*))))

(defun compute-block-download-timeout (num-downloading-peers)
  "Compute block download timeout in seconds based on number of peers.
Mirrors Bitcoin Core's net_processing.cpp shape but with a longer base
(90s vs Core's 30s) because testnet4 stress-region blocks (h=51k-67k)
are multi-MB and routinely take 60-90s wire transit even on healthy
links. With 30s, every in-flight request to a slow-but-functional peer
times out before delivery, fires the per-peer record-block-timeout
counter, and combined with the old +max-block-timeouts+=3 produced a
mass-eviction death spiral on the stress region. 90s + per-peer 5s
gives ≈125s with 8 peers — wide enough that a peer mid-transfer
isn't punished for slow-but-progressing delivery, narrow enough that
a genuinely dead peer is still cleared in 2 minutes.

  BLOCK_DOWNLOAD_TIMEOUT_BASE = 90 s
  BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 5 s
  timeout = base + per_peer * other_peers"
  (let* ((base 90)
         (per-peer 5)
         (other-peers (max 0 (1- num-downloading-peers))))
    (+ base (* per-peer other-peers))))

(defun get-timed-out-requests (&optional timeout-seconds)
  "Get list of block hashes whose in-flight request has exceeded
TIMEOUT-SECONDS (default: the adaptive per-peer request timeout). Callers
pass a shorter timeout near the tip — see request-blocks-from-peers."
  (unless *ibd-context*
    (return-from get-timed-out-requests nil))

  (let ((in-flight (ibd-context-in-flight *ibd-context*))
        (timeout-ticks (* (or timeout-seconds
                              (ibd-context-request-timeout *ibd-context*))
                          internal-time-units-per-second))
        (now (get-internal-real-time))
        (timed-out '()))
    (maphash (lambda (hash peer-time)
               (when (> (- now (cdr peer-time)) timeout-ticks)
                 (push hash timed-out)))
             in-flight)
    timed-out))

(defun release-orphaned-in-flight ()
  "Release in-flight block requests held by peers that are no longer
:ready (disconnected). Once released, the next per-peer download walk
(find-blocks-to-download-for-peer) re-requests the block from a live
peer whose chain covers it this same cycle rather than waiting out the
~125s per-hash request timeout. Returns the number released.

Mirrors Bitcoin Core's PeerManagerImpl::FinalizeNode, which drops a
disconnected node's mapBlocksInFlight entries so FindNextBlocksToDownload
reassigns them immediately. Without this, a peer that FIN'd while holding
a critical-path block stalls the tip for up to the full request timeout
(per the 2026-05-24 close-wait follow-up). The per-hash timeout counter
is deliberately left untouched — the peer dying is not the block's fault,
so it keeps its full retry budget on reassignment."
  (if (null *ibd-context*)
      0
      (let ((in-flight (ibd-context-in-flight *ibd-context*))
            (orphaned '()))
        (maphash (lambda (hash peer-time)
                   (unless (eq (peer-state (car peer-time)) :ready)
                     (push hash orphaned)))
                 in-flight)
        (dolist (hash orphaned)
          (remhash hash in-flight))
        (length orphaned))))

(defun retry-timed-out-requests (&optional peers timeout-seconds)
  "Remove timed out requests from in-flight so they can be retried.
When PEERS is provided, tracks per-peer timeouts and disconnects slow
peers. After a block has timed out +MAX-BLOCK-REQUEST-TIMEOUTS+ times
it's also dropped from PENDING — competing-fork blocks that peers
won't serve would otherwise loop forever, blocking IBD termination.
TIMEOUT-SECONDS overrides the per-block timeout (shorter near the tip)."
  (let ((timed-out (get-timed-out-requests timeout-seconds))
        (peers-to-disconnect '())
        (dropped 0))
    (dolist (hash timed-out)
      (let* ((peer-time (gethash hash (ibd-context-in-flight *ibd-context*)))
             (peer (car peer-time))
             (timeouts (gethash hash (ibd-context-request-timeouts *ibd-context*) 0)))
        ;; Track timeout for this peer
        (when (and peer peers)
          (when (record-block-timeout peer)
            (pushnew peer peers-to-disconnect)))
        ;; Bump the per-hash timeout count.
        (setf (gethash hash (ibd-context-request-timeouts *ibd-context*))
              (1+ timeouts))
        ;; Remove from in-flight so it can be retried from a different peer.
        (remhash hash (ibd-context-in-flight *ibd-context*))
        ;; After repeated timeouts, drop from pending entirely. Peers
        ;; aren't serving this block — likely a side-chain header that
        ;; got auto-queued by process-headers. activate-block will
        ;; re-request on demand if a future block makes this fork win.
        (when (>= (1+ timeouts) +max-block-request-timeouts+)
          (drop-pending-block hash)
          (incf dropped))))
    (when (plusp dropped)
      (bitcoin-lisp:log-debug "Dropped ~D pending blocks after ~D timeouts each"
                              dropped +max-block-request-timeouts+))
    ;; Disconnect peers that hit the timeout limit (only if still connected)
    (dolist (peer peers-to-disconnect)
      (when (eq (peer-state peer) :ready)
        (bitcoin-lisp:log-warn "Disconnecting stalling peer ~A"
                               (peer-address peer))
        (handler-case
            (disconnect-peer peer)
          (error () nil))))
    (length timed-out)))

;;;; Multi-Peer Request Distribution

(defun count-peer-in-flight (peer)
  "Count in-flight block requests assigned to PEER."
  (let ((count 0))
    (when *ibd-context*
      (maphash (lambda (hash peer-time)
                 (declare (ignore hash))
                 (when (eq (car peer-time) peer)
                   (incf count)))
               (ibd-context-in-flight *ibd-context*)))
    count))

(defun request-blocks-from-peers (peers chain-state block-store)
  "Request blocks from multiple peers, distributing the load.
Enforces per-peer in-flight limits (like Bitcoin Core's
MAX_BLOCKS_IN_TRANSIT_PER_PEER) rather than a single global limit.

Applies backpressure: when the out-of-order block-queue is at capacity,
new requests are paused so peers do not deliver blocks we'd just drop +
re-request, which causes duplicate-delivery thrash and wasted bandwidth."
  (unless (and *ibd-context* peers)
    (return-from request-blocks-from-peers 0))

  ;; Reassign blocks held by peers that have since disconnected — they'd
  ;; otherwise sit in-flight until the per-hash timeout before any live
  ;; peer could be asked. Then retry timed-out requests — even under
  ;; backpressure — so in-flight requests that were lost (peer dropped,
  ;; request lost) don't stay stuck once the queue fills, including the
  ;; very block we need to advance.
  (let ((orphaned (release-orphaned-in-flight)))
    (when (> orphaned 0)
      (bitcoin-lisp:log-warn "Released ~D in-flight blocks from disconnected peers" orphaned)))
  ;; Near the tip (fork-recovery zone), use the shorter +block-stalling-timeout+
  ;; so a silent peer's block is retried elsewhere in ~30s instead of ~125s.
  ;; Far from tip (bulk IBD), the full adaptive timeout stands — EXCEPT when
  ;; the block queue is saturated: there progress is serialized on the few
  ;; blocks just above the tip, so a slow peer holding one of them stalls
  ;; everything (Core disconnects such a peer after BLOCK_STALLING_TIMEOUT,
  ;; net_processing.cpp:5436). Use the short timeout to re-route fast.
  (let* ((near-tip (<= (- (ibd-context-header-tip-height *ibd-context*)
                          (bitcoin-lisp.storage:current-height chain-state))
                       +stalling-near-tip-margin+))
         (queue-saturated (>= (ibd-context-block-queue-bytes *ibd-context*)
                              +max-block-queue-bytes+))
         (timeout (and (or near-tip queue-saturated) +block-stalling-timeout+))
         (retried (retry-timed-out-requests peers timeout)))
    (when (> retried 0)
      (bitcoin-lisp:log-warn "Retrying ~D timed out block requests~:[~; (short timeout)~]"
                             retried timeout)))

  ;; Backpressure: cap NEW requests so block-queue + in-flight stays bounded.
  ;; When at cap and the next-needed block is missing, only allow ONE request
  ;; (the gap-block) — not the full per-peer budget. The previous override
  ;; lifted backpressure entirely; if connect-tip stalled (e.g. validation
  ;; bug), peers kept delivering blocks above the gap, the queue grew past
  ;; cap on the receive side (no cap there pre-fix), and the heap exhausted.
  ;; Bitcoin Core never has this issue because FindNextBlocksToDownload
  ;; (net_processing.cpp:1437-1440) only walks within BLOCK_DOWNLOAD_WINDOW
  ;; from the LastCommonBlock, which advances only when blocks connect.
  (let* ((queue (ibd-context-block-queue *ibd-context*))
         (queue-load (+ (hash-table-count queue)
                        (hash-table-count (ibd-context-in-flight *ibd-context*))))
         (next-needed (1+ (bitcoin-lisp.storage:current-height chain-state)))
         (gap-block-missing (not (gethash next-needed queue)))
         (over-cap (>= queue-load +max-block-queue-size+)))
    (when (and over-cap (not gap-block-missing))
      (return-from request-blocks-from-peers 0))
    ;; over-cap AND gap missing: fall through, but the request budget is
    ;; clamped to 1 below to avoid the unbounded-flood failure mode.
    (when over-cap
      (setf *ibd-gap-only-mode* t)))

  (let* ((max-per-peer (ibd-context-max-in-flight *ibd-context*))
         (ready-peers (sort (remove-if-not (lambda (p) (eq (peer-state p) :ready)) peers)
                            #'< :key (lambda (p)
                                       (let ((lat (peer-ping-latency p)))
                                         (if (plusp lat) lat most-positive-fixnum)))))
         ;; While the snapshot chainstate is UNVALIDATED, request blocks only
         ;; from peers whose best-known chain contains the snapshot base: no
         ;; undo data exists below the base, so a chain that omits it can
         ;; never be reorged to (Core net_processing.cpp:1412-1421), and only
         ;; such peers can serve the historical range (1458-1471). Peers with
         ;; no availability info yet are excluded too, as in Core.
         (ready-peers (if (and (ibd-context-snapshot-unvalidated-p *ibd-context*)
                               (ibd-context-snapshot-base-entry *ibd-context*))
                          (remove-if-not
                           (lambda (p) (peer-chain-contains-base-p p chain-state))
                           ready-peers)
                          ready-peers))
         ;; Calculate total budget across all peers. When the queue is at cap
         ;; and we're only allowed to request the gap block, clamp to 1.
         (raw-budget (loop for peer in ready-peers
                           sum (max 0 (- max-per-peer (count-peer-in-flight peer)))))
         (total-budget (if *ibd-gap-only-mode* (min 1 raw-budget) raw-budget)))

    ;; Reset for next caller; the gate already gave us the budget we need.
    (setf *ibd-gap-only-mode* nil)

    (when (or (null ready-peers) (zerop total-budget))
      (return-from request-blocks-from-peers 0))

    ;; Per-peer chain-aware download (Bitcoin Core FindNextBlocksToDownload):
    ;; ask each peer ONLY for blocks on that peer's own best chain, walking
    ;; from our last-common block with it. This is the layer-5 fix: the node
    ;; downloads whatever chains its peers actually serve and can never fixate
    ;; on a fork whose blocks no connected peer has (there is no notfound for
    ;; blocks, so the old height-based scheduler retried such blocks forever).
    ;; Mark each peer's chosen blocks in-flight BEFORE walking the next peer so
    ;; two peers on the same chain don't both get the same block.
    ;; TOTAL-BUDGET is the cross-peer request cap: the aggregate per-peer
    ;; capacity normally, clamped to 1 in gap-only mode. It was computed
    ;; BEFORE *ibd-gap-only-mode* was reset above — do not re-read the
    ;; special here (re-reading it after the reset silently disabled the
    ;; gap-only clamp, re-opening the request flood the backpressure gate
    ;; exists to prevent).
    (let ((requests-made 0)
          (peer-requests (make-hash-table :test 'eq))
          (in-flight (ibd-context-in-flight *ibd-context*))
          (remaining total-budget))
      (dolist (peer ready-peers)
        (when (plusp remaining)
          (let ((budget (min remaining
                             (max 0 (- max-per-peer (count-peer-in-flight peer)))))
                (taken 0))
            (when (plusp budget)
              (dolist (hash (find-blocks-to-download-for-peer
                             peer chain-state block-store budget))
                (unless (gethash hash in-flight)
                  (mark-block-in-flight hash peer)
                  (push hash (gethash peer peer-requests))
                  (incf taken)
                  (incf requests-made)
                  (decf remaining)))
              ;; Assumeutxo background range: top up whatever per-peer budget
              ;; the tip walk left unused with historical blocks (Core
              ;; SendMessages runs TryDownloadingHistoricalBlocks right after
              ;; FindNextBlocksToDownload the same way).
              (let ((hist-budget (min (- budget taken) remaining)))
                (when (plusp hist-budget)
                  (dolist (hash (find-historical-blocks-to-download
                                 peer chain-state block-store hist-budget))
                    (unless (gethash hash in-flight)
                      (mark-block-in-flight hash peer)
                      (push hash (gethash peer peer-requests))
                      (incf requests-made)
                      (decf remaining)))))))))
      (when (zerop requests-made)
        (return-from request-blocks-from-peers 0))

      ;; Send batch request to each peer
      (maphash (lambda (peer hashes)
                   (when hashes
                     (handler-case
                         (let ((inv-vectors (mapcar (lambda (h)
                                                      (bitcoin-lisp.serialization:make-inv-vector
                                                       :type bitcoin-lisp.serialization:+inv-type-witness-block+
                                                       :hash h))
                                                    hashes)))
                           (send-message peer
                                         (bitcoin-lisp.serialization:make-getdata-message
                                          inv-vectors)))
                       (error () nil))))
                 peer-requests)

      requests-made)))

;;;; Progress Reporting

(defun ibd-progress (&optional chain-state)
  "Return a plist with current IBD progress.
   When CHAIN-STATE is given, the headline progress is reported as
   current-validated-height / target, which is what users care about and
   stays meaningful across process restarts. Without it, falls back to the
   per-session blocks-received counter, which resets to 0 each restart."
  (unless *ibd-context*
    (return-from ibd-progress nil))

  (let* ((ctx *ibd-context*)
         (now (get-internal-real-time))
         (elapsed-secs (/ (- now (ibd-context-start-time ctx))
                          internal-time-units-per-second))
         (received (ibd-context-blocks-received ctx))
         (target (ibd-context-target-height ctx))
         (current-height (if chain-state
                             (bitcoin-lisp.storage:current-height chain-state)
                             received))
         (pending (hash-table-count (ibd-context-pending-blocks ctx)))
         (in-flight (hash-table-count (ibd-context-in-flight ctx)))
         (cutoff (- now (* +recent-rate-window-seconds+
                           internal-time-units-per-second)))
         (samples (cons (cons now current-height)
                        (trim-samples-older-than
                         (ibd-context-recent-samples ctx) cutoff)))
         ;; Recent rate: oldest sample still in window vs current.
         (oldest (car (last samples)))
         (recent-secs (/ (- now (car oldest))
                         internal-time-units-per-second))
         (recent-blocks (- current-height (cdr oldest)))
         (recent-rate (if (> recent-secs 0)
                          (/ recent-blocks recent-secs)
                          0)))
    (setf (ibd-context-recent-samples ctx) samples)
    (list :state (ibd-context-state ctx)
          :headers-received (ibd-context-headers-received ctx)
          :blocks-received received
          :current-height current-height
          :target-height target
          :pending-blocks pending
          :in-flight-blocks in-flight
          :elapsed-seconds (round elapsed-secs)
          :blocks-per-second (if (> elapsed-secs 0)
                                 (/ received elapsed-secs)
                                 0)
          :recent-blocks-per-second recent-rate
          :progress-percent (if (> target 0)
                                (* 100.0 (/ current-height target))
                                0))))

(defun report-ibd-progress (&optional chain-state)
  "Log current IBD progress."
  (let ((progress (ibd-progress chain-state)))
    (when progress
      (bitcoin-lisp:log-info
       "IBD Progress: ~D/~D blocks (~,1F%), ~,1F b/s avg / ~,1F b/s recent, ~D pending, ~D in-flight"
       (getf progress :current-height)
       (getf progress :target-height)
       (getf progress :progress-percent)
       (getf progress :blocks-per-second)
       (getf progress :recent-blocks-per-second)
       (getf progress :pending-blocks)
       (getf progress :in-flight-blocks))
      (report-delivery-latency))))

(defun report-delivery-latency ()
  "Log p50/p95 block-delivery latency and per-peer counts over the recent
window. Trims delivery-samples to drop entries older than the window."
  (when *ibd-context*
    (let* ((ctx *ibd-context*)
           (cutoff (- (get-internal-real-time)
                      (* +recent-rate-window-seconds+
                         internal-time-units-per-second)))
           (samples (trim-samples-older-than
                     (ibd-context-delivery-samples ctx) cutoff)))
      (setf (ibd-context-delivery-samples ctx) samples)
      (when samples
        (let* ((latencies (sort (mapcar #'third samples) #'<))
               (n (length latencies))
               ;; nearest-rank-below semantics, clamped so percentile
               ;; index is always in [0, n-1].
               (p50 (nth (min (1- n) (floor (* n 0.50))) latencies))
               (p95 (nth (min (1- n) (floor (* n 0.95))) latencies))
               (per-peer (make-hash-table :test 'equal)))
          (dolist (s samples)
            (incf (gethash (second s) per-peer 0)))
          (bitcoin-lisp:log-info
           "Block-latency p50/p95: ~Dms / ~Dms over ~D samples; per-peer: ~{~A~^, ~}"
           p50 p95 n
           (sort (loop for k being each hash-key of per-peer
                       using (hash-value v)
                       collect (format nil "~A=~D" k v))
                 #'string<)))))))

;;;; Main IBD Loop

(defun handle-peer-fin (peer)
  "Reap a peer whose connection has been flagged dead. receive-bytes
flips connection-connected to NIL on a zero-progress read (Linux
POLLHUP after peer FIN) and on any send-bytes/receive-bytes error.
Without this propagation peer-state stays :ready, the outer drain
prune keeps the zombie, and replace-disconnected-peers (which only
counts non-:ready slots as needing replacement) never reconnects.
Result: sockets pile up in CLOSE-WAIT, IBD spins on an empty header
poll forever (incident 2026-05-22: all 7 testnet4 peers stuck in
CLOSE-WAIT after 48h, sync gap from h=135,913 vs network tip).
Mirrors Bitcoin Core's SocketHandlerConnected: recv()==0 or send
error sets pnode->fDisconnect (net.cpp:2204). Returns T iff the peer
was disconnected (handler-case yielded successfully)."
  (when (and (peer-connection peer)
             (not (connection-connected (peer-connection peer))))
    (bitcoin-lisp:log-warn "Peer ~A connection dead — disconnecting"
                           (peer-address peer))
    (handler-case (progn (disconnect-peer peer) t)
      (error () nil))))

(defun dispatch-ibd-message (peer command payload chain-state utxo-set block-store ctx
                             &key fee-estimator recent-rejects)
  "Process one wire message from PEER during IBD: connect a received
block, ingest announced headers, or hand anything else to the generic
handler. Shared by the block-download drain and the at-tip reap pass."
  (cond
    ((string= command "block")
     (let* ((block (bitcoin-lisp.serialization:parse-block-payload payload))
            (header (bitcoin-lisp.serialization:bitcoin-block-header block))
            (hash (bitcoin-lisp.serialization:block-header-hash header)))
       ;; Forensic raw-payload capture: dump the wire-format
       ;; (witness-included) bytes to a side dir before parse loses
       ;; witness data. Triggered only when *forensic-store-from-height*
       ;; is set.
       (when *forensic-store-from-height*
         (let ((entry (bitcoin-lisp.storage:get-block-index-entry
                       chain-state hash)))
           (when (and entry
                      (>= (bitcoin-lisp.storage:block-index-entry-height entry)
                          *forensic-store-from-height*))
             (let* ((dir "/data/bitcoin-lisp/forensic-blocks/")
                    (path (format nil "~A~A.raw" dir
                                  (bitcoin-lisp.crypto:bytes-to-hex hash))))
               (ignore-errors (ensure-directories-exist dir))
               (with-open-file (s path :direction :output
                                       :if-exists :supersede
                                       :element-type '(unsigned-byte 8))
                 (write-sequence payload s))))))
       ;; Per-peer availability: receiving a block proves peer had it.
       (update-block-availability peer chain-state hash)
       ;; Assumeutxo routing (Core ProcessNewBlock runs ABC on the current
       ;; AND the historical chainstate, validation.cpp:4430-4478): blocks
       ;; at heights at or below the snapshot base belong to the historical
       ;; chainstate's background validation; everything else extends the
       ;; current chainstate. The two height ranges are disjoint, so one
       ;; download pipeline serves both cursors. The height is read from
       ;; the pending table (which stores it) BEFORE mark-block-received
       ;; removes the entry — the index lookup is only the fallback for
       ;; blocks that were never pending (tip relay).
       (multiple-value-bind (route-cs route-view)
           (let* ((hist (and ctx (ibd-context-historical-chain-state ctx)))
                  (base (and hist (ibd-context-snapshot-base-entry ctx)))
                  (height (and base
                               (or (gethash hash (ibd-context-pending-blocks ctx))
                                   (let ((entry (bitcoin-lisp.storage:get-block-index-entry
                                                 chain-state hash)))
                                     (and entry
                                          (bitcoin-lisp.storage:block-index-entry-height
                                           entry)))))))
             (if (and height
                      (<= height
                          (bitcoin-lisp.storage:block-index-entry-height base)))
                 (values hist (bitcoin-lisp.storage:chain-state-coins-view hist))
                 (values chain-state utxo-set)))
         ;; Capture "did we request this?" BEFORE mark-block-received clears
         ;; the in-flight/pending entry — the out-of-order persist gate needs
         ;; it to tell a solicited download from an unsolicited disk-fill push.
         (let ((requested (and ctx (or (gethash hash (ibd-context-in-flight ctx))
                                       (gethash hash (ibd-context-pending-blocks ctx))))))
           (mark-block-received hash)
           (record-block-received-from-peer peer)
           (let ((connected
                   (process-received-block block route-cs route-view block-store
                                           :fee-estimator fee-estimator
                                           :recent-rejects recent-rejects
                                           :wire-size (length payload)
                                           :requested (and requested t))))
             ;; Earned BIP152 high-bandwidth promotion. Core's BlockChecked
             ;; drives this off mapBlockSource (net_processing.cpp:2202,
             ;; 2218-2223), which is filled for FULL blocks as well as
             ;; reconstructed compact ones — a node whose peers all fail
             ;; compact reconstruction still keeps 3 HB peers. It fires only
             ;; on the state.IsValid() arm, so we gate on the block having
             ;; actually validated and connected (process-received-block
             ;; returns T only from the tip+1 activate-block success path,
             ;; which is also the closest analogue of Core's "no other blocks
             ;; in flight" best-block proxy). maybe-promote-block-deliverer
             ;; applies the not-IBD gate itself, against the ACTIVE chainstate
             ;; (route-cs may be the assumeutxo background one, whose tip says
             ;; nothing about whether the node is still in IBD).
             (when connected
               (maybe-promote-block-deliverer peer chain-state)))))))

    ((string= command "headers")
     (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
       ;; The at-tip / BIP130 sendheaders steady-state flow. Contextual
       ;; validation (PoW / MTP / difficulty / checkpoint) happens inside via
       ;; validate-header-chain, PLUS the low-work anti-DoS gate: during a
       ;; from-genesis IBD the validated tip sits below the work floor, so
       ;; process-headers' own gate is off — without the presync diversion a
       ;; peer could grow the index without bound through this path
       ;; (ingest-headers-from-peer, Core ProcessHeadersMessage).
       ;; Node lock: process-headers inside mutates the block index the RPC
       ;; threads read/write under the same lock (see handle-headers).
       (with-node-lock
         (ingest-headers-from-peer
          peer headers chain-state
          :count-fn (lambda (n) (incf (ibd-context-headers-received ctx) n))))))

    ;; Everything else: the generic handler, with the full node context
    ;; threaded off the IBD ctx. handle-message silently disables tx
    ;; ingestion/serving, tx-inv getdata, compact blocks, and addr gossip
    ;; when :mempool/:peers/:address-book are nil — which is exactly what
    ;; happened here until 2026-07-10 (only the two keywords below were
    ;; passed, so those paths never ran outside unit tests and RPC).
    (t (handle-message peer command payload
                       chain-state utxo-set block-store
                       :mempool (and ctx (ibd-context-mempool ctx))
                       :peers (and ctx (ibd-context-peers ctx))
                       :address-book (and ctx (ibd-context-address-book ctx))
                       :fee-estimator fee-estimator
                       :recent-rejects recent-rejects))))

(defun safely-dispatch-peer-message (peer command payload chain-state utxo-set
                                     block-store ctx &key fee-estimator recent-rejects)
  "Dispatch one already-read message from PEER, isolating failures: a
malformed/oversized/unprocessable message raises an error that is caught here
and disconnects only this peer (Bitcoin Core's misbehaving-peer posture), so one
bad message can neither tear down the drain loop nor escape to the sync thread.
Returns T if the peer is still connected afterward, NIL if it was disconnected."
  (handler-case
      (progn
        (dispatch-ibd-message peer command payload chain-state utxo-set block-store ctx
                              :fee-estimator fee-estimator
                              :recent-rejects recent-rejects)
        t)
    (error (c)
      (bitcoin-lisp:log-warn
       "Peer ~A sent a malformed/unprocessable ~A message — disconnecting: ~A"
       (peer-address peer) command c)
      (handler-case (disconnect-peer peer) (error () nil))
      nil)))

(defun drain-and-reap-peer (peer chain-state utxo-set block-store ctx
                            &key fee-estimator recent-rejects)
  "Pump every currently-readable message from PEER, then reap it if its
connection has gone dead. Mirrors the per-peer branch of Bitcoin Core's
CConnman::SocketHandlerConnected (net.cpp:2204): drain readable data,
and on recv()==0 / send error mark the peer for disconnect.

A dead socket can make usocket:wait-for-input or read-sequence (inside
receive-message) raise SIMPLE-STREAM-ERROR; the handler-case keeps that
per-peer so the outer loop keeps iterating other peers (without it the
error escaped run-ibd and killed the sync thread — incident 2026-05-09).

Draining a peer whose remote has FIN'd eventually hits a zero-progress
read, which flips connection-connected to NIL; handle-peer-fin then
disconnects it so replace-disconnected-peers can refill the slot."
  ;; Read the connection ONCE. An RPC-thread disconnect (disconnectnode, setban)
  ;; between two reads of the slot would hand (connection-connected NIL) a NIL —
  ;; a TYPE-ERROR outside the handler-case below, which aborts the whole sync
  ;; cycle. Latent before; header sync now runs this several times a second.
  (let ((conn (peer-connection peer)))
   (when (and (eq (peer-state peer) :ready)
              conn
              ;; Only drain a connection still believed live. If a previous
              ;; read already flipped connection-connected to NIL (and may
              ;; have NILed the socket), skip straight to handle-peer-fin —
              ;; no point waiting for input on a dead/closed socket.
              (connection-connected conn))
    (handler-case
        ;; Drain only as long as the socket actually has data ready
        ;; (usocket:wait-for-input :timeout 0 is non-blocking). This lets us
        ;; pull all queued messages in the batch without ever timing out
        ;; mid-payload, then exit immediately when nothing is left to read.
        (let ((byte-budget-start (connection-bytes-received conn)))
         (loop repeat +max-messages-per-peer-per-cycle+
              ;; Stop check per message, not just per outer-loop pass: a
              ;; full drain is up to 32 messages x block validation each
              ;; (~0.1-2s), so without this a TERM waits out the whole
              ;; batch for every peer before run-ibd's check fires.
              while (not *ibd-stop-requested*)
              ;; Re-check liveness every iteration: a mid-drain dispatch can
              ;; disconnect the peer (rate-limit, oversized payload), NILing
              ;; the connection or flipping connection-connected — both of
              ;; which data-available-p folds in (non-blocking, :timeout 0).
              ;; INPUT-PENDING, not DATA-AVAILABLE: the readers drain through
              ;; the Lisp stream, which buffers, so a second message sharing a
              ;; TCP segment with the first is invisible to poll(2) on the fd.
              ;; Asking the socket left it parked until unrelated traffic woke
              ;; the connection — eleven seconds, measured.
              while (and (peer-connection peer)
                         (connection-input-pending-p (peer-connection peer))
                         ;; Byte fairness, checked between messages: a peer
                         ;; with plenty to say costs one turn, not the pass
                         ;; (see +max-recv-bytes-per-peer-per-cycle+).
                         (< (- (connection-bytes-received (peer-connection peer))
                               byte-budget-start)
                            +max-recv-bytes-per-peer-per-cycle+))
              for (command payload) = (multiple-value-list
                                       (receive-message peer :timeout 5))
              while command
              ;; Per-message isolation: a malformed message disconnects only
              ;; this peer (see safely-dispatch-peer-message); the next
              ;; liveness check then ends the drain. The outer handler-case
              ;; below remains the backstop for I/O errors from receive-message.
              do (safely-dispatch-peer-message peer command payload chain-state
                                               utxo-set block-store ctx
                                               :fee-estimator fee-estimator
                                               :recent-rejects recent-rejects)))
      ((or stream-error usocket:socket-condition end-of-file) (c)
        (bitcoin-lisp:log-warn
         "Peer ~A I/O error during message drain — disconnecting: ~A"
         (peer-address peer) c)
        (handler-case (disconnect-peer peer) (error () nil)))
      ;; A malformed/oversized message (bad count, truncated payload, decode
      ;; failure) raises a non-I/O error. Treat the peer as misbehaving and
      ;; disconnect only it — Bitcoin Core's posture — rather than letting the
      ;; error escape and tear down the whole sync thread.
      (error (c)
        (bitcoin-lisp:log-warn
         "Peer ~A sent a malformed message during drain — disconnecting: ~A"
         (peer-address peer) c)
        (handler-case (disconnect-peer peer) (error () nil))))
    ;; Reap a message the peer began and then abandoned. The reader no longer
    ;; waits for the rest of one, so a peer that sends a header and goes silent
    ;; produces nothing readable: the drain above skips it every cycle and the
    ;; half-read message would otherwise sit there for the life of the
    ;; connection.
    ;;
    ;; AFTER the drain, never before. The budget is measured from the last byte
    ;; that ARRIVED, so checking first would judge a peer stalled on the
    ;; strength of how long WE took to come back to it — and during IBD a cycle
    ;; is minutes of block validation, with the peer's remaining bytes already
    ;; sitting unread in our own receive buffer. Core likewise drains before it
    ;; consults inactivity (SocketHandlerConnected).
    (when (and (peer-connection peer)
               (connection-receive-expired-p (peer-connection peer)))
      (bitcoin-lisp:log-warn
       "Peer ~A began a message and delivered nothing for ~Ds — disconnecting"
       (peer-address peer) +receive-stall-timeout-seconds+)
      (handler-case (disconnect-peer peer) (error () nil))))
  (handle-peer-fin peer)))

(defun pump-peer-messages (peers chain-state utxo-set block-store
                           &key mempool address-book fee-estimator
                                recent-rejects ctx tx-index)
  "Drain every peer's currently-readable messages once, with the FULL node
context — the steady-state receive pump. Called ~1x/second from the sync
thread's between-cycles wait: without it the node had a ~30s window per
cycle where no thread read peer sockets, so pings, invs, headers
announcements and — worst — getdata for txs we had just announced sat
unanswered until the next sync cycle (Core has no such window: each peer's
ProcessMessages/SendMessages runs continuously). Returns the pump's
ibd-context so the caller can inspect counters (e.g. headers-received > 0
means a new block was announced and a sync cycle should start now)."
  (let ((ctx (or ctx (make-ibd))))
    (setf (ibd-context-mempool ctx) mempool
          (ibd-context-tx-index ctx) tx-index
          (ibd-context-peers ctx) peers
          (ibd-context-address-book ctx) address-book)
    ;; process-received-block and the block-activation path read the ambient
    ;; *ibd-context*; bind it to the pump's context for the drain (thread-
    ;; local, so concurrent RPC readers are unaffected).
    (let ((*ibd-context* ctx))
      (dolist (peer peers)
        (drain-and-reap-peer peer chain-state utxo-set block-store ctx
                             :fee-estimator fee-estimator
                             :recent-rejects recent-rejects)))
    ctx))

(defun start-ibd (peers chain-state utxo-set block-store target-height
                   &key fee-estimator recent-rejects mempool address-book
                     historical-chainstate tx-index)
  "Start Initial Block Download.
Returns the number of blocks downloaded. HISTORICAL-CHAINSTATE, when
non-NIL, is the assumeutxo background-validation chainstate — run-ibd adds
a second download cursor for its [tip .. snapshot-base] range."
  (setf *ibd-context* (make-ibd))
  ;; TARGET-HEIGHT arrives as a peer's advertised start height, which is a
  ;; SIGNED int32 on the wire and whose "unknown" value is -1 (Core's
  ;; CNode::nStartingHeight initialises to -1, and its own P2PInterface test
  ;; client sends -1 in every version message it constructs). The slot is
  ;; (UNSIGNED-BYTE 32), so storing that raw is a type error — and it is raised
  ;; on the SYNC THREAD, which unwinds the whole iteration before
  ;; MAINTAIN-PEERS runs, so nothing is pumped, nothing is reaped, and the next
  ;; iteration fails identically. One peer sending a legal value takes the
  ;; node's sync loop down for as long as it stays connected.
  ;;
  ;; This is the same failure SHAPE the docstring of SYNC-BLOCKCHAIN records
  ;; from a live incident — a type error on the sync thread that feeds itself,
  ;; logged every five seconds for nineteen days. Clamped here rather than at
  ;; the source because -1 is MEANINGFUL as a peer attribute: getpeerinfo
  ;; reports it, and Core's is signed for exactly that reason. What must be
  ;; non-negative is a download TARGET.
  (setf (ibd-context-target-height *ibd-context*) (max 0 target-height))
  ;; Set adaptive timeout based on number of peers
  (setf (ibd-context-request-timeout *ibd-context*)
        (compute-block-download-timeout (length peers)))

  (unwind-protect
       (run-ibd peers chain-state utxo-set block-store
                :fee-estimator fee-estimator
                :recent-rejects recent-rejects
                :mempool mempool
                :address-book address-book
                :tx-index tx-index
                :historical-chainstate historical-chainstate)
    (setf *ibd-context* nil)))

(defun run-ibd (peers chain-state utxo-set block-store
                &key fee-estimator recent-rejects mempool address-book
                  historical-chainstate tx-index)
  "Main IBD loop."
  (let ((ctx *ibd-context*)
        (start-height (bitcoin-lisp.storage:current-height chain-state)))
    ;; Make the mempool reachable from the block-activation path (which reads
    ;; it off *ibd-context*) so confirmed txs are removed during IBD/tip
    ;; advance — and, with peers + address-book, from dispatch-ibd-message's
    ;; generic fallthrough so tx relay and addr gossip actually run live.
    (when ctx
      (setf (ibd-context-mempool ctx) mempool
            (ibd-context-tx-index ctx) tx-index
            (ibd-context-peers ctx) peers
            (ibd-context-address-book ctx) address-book))

    ;; Assumeutxo dual-cursor setup: resolve the historical chainstate's
    ;; target (the snapshot base) and whether the CURRENT chainstate is an
    ;; unvalidated snapshot chainstate (which gates block downloads to
    ;; base-in-chain peers). The base entry lives in the shared block index.
    (when (and ctx historical-chainstate)
      (let* ((target-hash (bitcoin-lisp.storage:chain-state-target-blockhash
                           historical-chainstate))
             (base-entry (and target-hash
                              (bitcoin-lisp.storage:get-block-index-entry
                               chain-state target-hash))))
        (when base-entry
          (setf (ibd-context-historical-chain-state ctx) historical-chainstate
                (ibd-context-snapshot-base-entry ctx) base-entry
                (ibd-context-snapshot-unvalidated-p ctx)
                (and (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash
                      chain-state)
                     (eq (bitcoin-lisp.storage:chain-state-assumeutxo-status
                          chain-state)
                         :unvalidated)
                     t)))))

    ;; Initialize header-tip-height from existing chain state
    ;; This ensures we know about existing headers even if header sync fails
    (let ((best-header-height 0)
          (best-header-work 0))
      (maphash (lambda (hash entry)
                 (declare (ignore hash))
                 (when (> (bitcoin-lisp.storage:block-index-entry-height entry) best-header-height)
                   (setf best-header-height (bitcoin-lisp.storage:block-index-entry-height entry)))
                 ;; Best-WORK header (Core m_best_header): skip invalid branches.
                 (when (and (not (eq (bitcoin-lisp.storage:block-index-entry-status entry) :invalid))
                            (> (bitcoin-lisp.storage:block-index-entry-chain-work entry)
                               best-header-work))
                   (setf best-header-work (bitcoin-lisp.storage:block-index-entry-chain-work entry))))
               (bitcoin-lisp.storage::chain-state-block-index chain-state))
      (setf (ibd-context-header-tip-height ctx) best-header-height
            (ibd-context-best-header-work ctx) best-header-work))

    ;; Phase 1: Download headers
    (set-ibd-state :syncing-headers)
    (sync-headers-with-failover peers chain-state ctx
                                :recent-rejects recent-rejects
                                :utxo-set utxo-set
                                :block-store block-store
                                :fee-estimator fee-estimator)

    ;; Phase 2: Download and validate blocks
    (set-ibd-state :syncing-blocks)

    ;; Prime per-peer block availability across the whole ready set before the
    ;; per-peer download walk runs. Phase 1 only learned the bulk header-sync
    ;; peer's tip; the others' best-known-block stays empty until they happen to
    ;; announce, so find-blocks-to-download-for-peer cannot tell which peers
    ;; serve the tip. One getheaders per ready peer, on a locator one block back
    ;; from our header tip (Core's pprev trick), makes a caught-up peer reply
    ;; with the single header we already have — the already-known fast path
    ;; records its best-known cheaply, no block transfer.
    (broadcast-initial-getheaders peers chain-state)

    ;; Queue all blocks from current height to header tip
    (let ((header-tip (ibd-context-header-tip-height ctx)))
      ;; Reflect the real chain tip in the progress reporter — `target-height`
      ;; was previously set to the small `max-blocks` cap from sync-blockchain.
      (setf (ibd-context-target-height ctx) header-tip)
      (queue-blocks-for-download chain-state (1+ start-height) header-tip))

    ;; Assumeutxo: queue the historical range [historical tip .. base] along
    ;; the exact target-ancestor path (second download cursor).
    (let ((hist (ibd-context-historical-chain-state ctx)))
      (when hist
        (let ((queued (queue-historical-blocks hist)))
          (when (plusp queued)
            (bitcoin-lisp:log-info
             "[snapshot] queued ~D historical block~:P for background validation (h=~D..~D)"
             queued
             (1+ (bitcoin-lisp.storage:current-height hist))
             (bitcoin-lisp.storage:chain-state-target-height hist))))))

    ;; Initialize stuck-tip tracking — start the timer at IBD entry so the
    ;; first stall is detected even if no block ever connects.
    (setf (ibd-context-last-tip-advance-time ctx) (get-universal-time)
          (ibd-context-last-tip-height ctx) start-height)

    ;; Download blocks
    (let ((last-report-time (get-internal-real-time))
          (report-interval (* 10 internal-time-units-per-second))  ; Every 10 seconds
          (no-peer-cycles 0)
          ;; Wall-clock of the last cycle that made download progress (requested
          ;; or received a block). Drives the +no-progress-yield-seconds+
          ;; bounded exit below.
          (last-progress-time (get-universal-time)))

      ;; Loop until either (a) the pending queue is empty, or (b) we've caught
      ;; up to the best chain — current height >= header tip AND no heavier
      ;; header chain outweighs our tip. The WORK term matters: a heavier-but-
      ;; SHORTER fork (tip height <= ours but more cumulative work) must still
      ;; be downloaded, and a height-only gate would leave it unrequested (a
      ;; most-work-chain liveness violation). Any remaining pending entries once
      ;; the gate closes are competing-fork blocks no peer serves; without the
      ;; gate they'd pin the loop forever. A historical (assumeutxo) chainstate
      ;; keeps the loop alive for its background cursor. The +no-progress-yield-
      ;; seconds+ exit inside the body is the required backstop: the work gate
      ;; can stay open on an UNOBTAINABLE heavier chain, and without a bounded
      ;; exit the loop would spin forever (its pending blocks never go in-flight
      ;; so never time out) and starve the 30s maintenance cadence.
      (loop while (and (> (hash-table-count (ibd-context-pending-blocks ctx)) 0)
                       (or (< (bitcoin-lisp.storage:current-height chain-state)
                              (ibd-context-header-tip-height ctx))
                           (let ((tip (bitcoin-lisp.storage:get-block-index-entry
                                       chain-state
                                       (bitcoin-lisp.storage:best-block-hash chain-state))))
                             (> (ibd-context-best-header-work ctx)
                                (if tip
                                    (bitcoin-lisp.storage:block-index-entry-chain-work tip)
                                    0)))
                           (let ((hist (ibd-context-historical-chain-state ctx)))
                             (and hist
                                  (< (bitcoin-lisp.storage:current-height hist)
                                     (or (bitcoin-lisp.storage:chain-state-target-height hist)
                                         0))))))
            do (let ((cycle-received (ibd-context-blocks-received ctx))
                     (cycle-requested 0))
                 (when *ibd-stop-requested*
                   (return))

                 ;; Stuck-tip backstop: if connect-tip hasn't advanced for
                 ;; +stuck-tip-halt-seconds+ AND blocks are queued, halt
                 ;; cleanly instead of growing the queue until OOM.
                 (when (check-stuck-tip)
                   (return))

                 ;; Prune disconnected peers from the list (and keep the
                 ;; ctx copy current — relay fanout reads it).
                 (setf peers (remove-if-not
                              (lambda (p) (eq (peer-state p) :ready))
                              peers))
                 (setf (ibd-context-peers ctx) peers)

                 ;; Handle no-peer condition: exit after a few seconds
                 ;; (caller is responsible for reconnecting and retrying)
                 (when (null peers)
                   (incf no-peer-cycles)
                   (when (> no-peer-cycles 5)
                     (bitcoin-lisp:log-warn "No peers available, pausing block download")
                     (return))
                   (sleep 1))

                 ;; Retry buffered unsent bytes on every peer (non-blocking;
                 ;; the periodic half of Core's SocketSendData) so a peer
                 ;; whose socket backed up drains even when nothing new is
                 ;; being sent to it this cycle.
                 (flush-peer-send-buffers peers)

                 ;; Request more blocks if needed
                 (when peers
                   (setf no-peer-cycles 0)
                   (incf cycle-requested
                         (request-blocks-from-peers peers chain-state block-store)))

                 ;; Receive and process messages from all peers. Drain up to
                 ;; +max-messages-per-peer-per-cycle+ messages per peer per
                 ;; outer-loop iteration so kernel TCP buffers don't fill up
                 ;; while we're busy validating an earlier (heavy) block.
                 (dolist (peer peers)
                   (drain-and-reap-peer peer chain-state utxo-set block-store ctx
                                        :fee-estimator fee-estimator
                                        :recent-rejects recent-rejects)
                   ;; Core-style pipeline top-up (SendMessages tops every
                   ;; peer up to MAX_BLOCKS_IN_TRANSIT_PER_PEER on each
                   ;; event-loop pass, net_processing.cpp:6164): re-feed
                   ;; the fleet as soon as in-flight drops below half the
                   ;; budget instead of once per outer iteration. One
                   ;; peer's 32-block drain validates for seconds; without
                   ;; this every OTHER peer sat idle for the whole pass —
                   ;; observed live on mainnet IBD as in-flight sawtoothing
                   ;; 48->0 and ~3 b/s at h~190k where ~80 b/s of peer
                   ;; capacity existed.
                   (when (< (hash-table-count (ibd-context-in-flight ctx))
                            (ash (* (length peers)
                                    (ibd-context-max-in-flight ctx))
                                 -1))
                     (incf cycle-requested
                           (request-blocks-from-peers peers chain-state block-store))))

                 ;; Per-block request timeout retries (retry-timed-out-requests
                 ;; in request-blocks-from-peers) is our peer-disconnect path:
                 ;; if a specific peer fails to deliver multiple requested
                 ;; blocks within the request-timeout, record-block-timeout
                 ;; eventually drops them. The previous secondary "no blocks
                 ;; in 30s" check duplicated this and fired wrongly when our
                 ;; backpressure was the actual reason peers looked idle.
                 ;; Bad-chain peers only:
                 (let ((our-height (bitcoin-lisp.storage:current-height chain-state)))
                   (dolist (peer (copy-list peers))
                     (when (consider-peer-eviction peer our-height)
                       (bitcoin-lisp:log-warn "Evicting peer ~A (height ~D behind our ~D)"
                                              (peer-address peer)
                                              (peer-start-height peer) our-height)
                       (handler-case (disconnect-peer peer) (error () nil)))))

                 ;; Periodic progress report
                 (let ((now (get-internal-real-time)))
                   (when (> (- now last-report-time) report-interval)
                     (report-ibd-progress chain-state)
                     (setf last-report-time now)))

                 ;; Deep-reorg candidate retry, once per cycle: covers the
                 ;; arrival orders the receive-path retries miss and re-arms
                 ;; after restart (the walk above re-records persisted
                 ;; candidates). No-op unless a candidate is armed, and the
                 ;; bodies-complete gate keeps a still-downloading fork
                 ;; cheap (early-exit probe at its first gap).
                 (retry-best-reorg-candidate chain-state block-store utxo-set
                                             :fee-estimator fee-estimator
                                             :recent-rejects recent-rejects)

                 ;; Progress accounting for the two idle backstops below.
                 (if (or (plusp cycle-requested)
                         (/= (ibd-context-blocks-received ctx) cycle-received))
                     (setf last-progress-time (get-universal-time))
                     (progn
                       ;; Idle pacing: a cycle that neither requested nor
                       ;; received a block yields the CPU briefly. The gate
                       ;; keeps us here while pending holds fork headers no peer
                       ;; serves (the per-peer walk correctly never requests
                       ;; them) and drain-and-reap polls non-blockingly — without
                       ;; this the loop busy-spins at 100% CPU during a fork
                       ;; storm.
                       (when peers (sleep 0.05))
                       ;; Bounded no-progress exit: if we've made NO download
                       ;; progress for +no-progress-yield-seconds+ while the gate
                       ;; is still open, RETURN so control yields to the 30s
                       ;; maintenance loop (run-ibd re-enters next pass). Without
                       ;; this the work-based gate could spin forever on a
                       ;; heavier chain no peer can serve — its pending blocks
                       ;; never go in-flight so never time out — starving peer
                       ;; maintenance. Safe because returning only pauses the
                       ;; download loop, not the node.
                       (when (>= (- (get-universal-time) last-progress-time)
                                 +no-progress-yield-seconds+)
                         (bitcoin-lisp:log-debug
                          "IBD download idle ~Ds (gate open, nothing servable) — yielding to maintenance"
                          +no-progress-yield-seconds+)
                         (return)))))))

    ;; At-tip FIN reap: the block-download loop above is gated on
    ;; (< current-height header-tip-height), so once we reach the tip it
    ;; never runs — and neither does its per-peer drain+handle-peer-fin.
    ;; But peers that FIN during a fork-recovery window do so precisely at
    ;; tip, leaving sockets in CLOSE-WAIT with peer-state stuck :ready and
    ;; the node spinning the empty header poll forever (incident 2026-05-22;
    ;; recurred 2026-05-24 because PR #73 wired the reap only into the
    ;; block-download loop). Pump every peer's readable socket once per
    ;; run-ibd invocation — i.e. once per outer 30s sync poll
    ;; (node.lisp:454-462) — so a dead connection surfaces (zero-progress
    ;; read flips connection-connected) and gets reaped; the subsequent
    ;; replace-disconnected-peers (node.lisp) then refills the slot. Mirrors
    ;; Bitcoin Core's SocketHandlerConnected running on every event-loop
    ;; pass, not only during block download (net.cpp:2204).
    (dolist (peer peers)
      (drain-and-reap-peer peer chain-state utxo-set block-store ctx
                           :fee-estimator fee-estimator
                           :recent-rejects recent-rejects))

    ;; Activate the best chain we can actually reach, whether or not a block
    ;; arrived this pass (Core ActivateBestChain runs from ProcessNewBlock AND
    ;; from startup, not only on arrival). Without this the ONLY reorg trigger
    ;; is connect-block, so a heavier chain whose bodies are already on disk —
    ;; the normal outcome after a refused reorg re-downloads its missing
    ;; blocks, or after a restart — sits unactivated until some unrelated block
    ;; happens to arrive. Live on 2026-08-19: testnet4 held tip 149110 for 40+
    ;; minutes with a fully-downloaded, strictly-heavier 149120 branch on disk.
    ;; Skipped when a stop is pending — shutdown must return promptly rather
    ;; than start a reorg — and when there is no block store, since then no
    ;; candidate can have a body on disk to switch to.
    (when (and block-store utxo-set (not (bitcoin-lisp:interrupt-requested-p)))
      (multiple-value-bind (switched missing)
          (bitcoin-lisp.validation:activate-best-chain
           chain-state block-store utxo-set
           :fee-estimator fee-estimator
           :recent-rejects recent-rejects
           :mempool mempool
           ;; From the CONTEXT, never from a caller who might forget: this
           ;; argument was missing here from the day the function landed, so
           ;; every reorg driven by the periodic activation — which on testnet4
           ;; is most of them — reconnected blocks with the txindex switched
           ;; off. Their transactions never entered the index, and the
           ;; best-block marker stayed on a block the reorg had just
           ;; disconnected, so the next startup read `marker-off-chain' and
           ;; rescanned from genesis. Observed live 2026-08-20, one restart
           ;; after the arrival path was fixed for the same omission (#372).
           :tx-index (%context-tx-index))
        (when switched
          (bitcoin-lisp:log-info "Activated best chain: tip now height ~D"
                                 (bitcoin-lisp.storage:current-height chain-state)))
        ;; Refused for want of block bodies — re-request them, exactly as the
        ;; arrival path does.
        (when (consp missing)
          (queue-missing-fork-blocks missing))))

    ;; Done — distinguish "actually finished" from "paused due to no peers".
    ;; Either: pending+in-flight both zero (we drained), OR
    ;; current-height ≥ header-tip-height (we caught up; any leftover
    ;; pending is fork-blocks waiting for a real reorg trigger).
    (let* ((pending (hash-table-count (ibd-context-pending-blocks ctx)))
           (in-flight (hash-table-count (ibd-context-in-flight ctx)))
           (at-tip (>= (bitcoin-lisp.storage:current-height chain-state)
                       (ibd-context-header-tip-height ctx))))
      (if (or (and (zerop pending) (zerop in-flight))
              at-tip)
          (set-ibd-state :synced)
          (set-ibd-state :idle)))
    (ibd-context-blocks-received ctx)))

(defun %best-header-entry (chain-state)
  "The highest-height entry in the block index (the header tip)."
  (let ((best-entry nil)
        (best-height 0))
    (maphash (lambda (hash entry)
               (declare (ignore hash))
               (when (> (bitcoin-lisp.storage:block-index-entry-height entry) best-height)
                 (setf best-height (bitcoin-lisp.storage:block-index-entry-height entry))
                 (setf best-entry entry)))
             (bitcoin-lisp.storage::chain-state-block-index chain-state))
    best-entry))

(defun %locator-from-entry (entry chain-state)
  "Exponential block locator walking back from ENTRY through prev-entry links;
the genesis locator when ENTRY is NIL."
  (if entry
      ;; Walk back through prev-entry links
      (let ((locator '())
            (e entry)
            (step 1)
            (count 0))
        (loop while e
              do (push (bitcoin-lisp.storage:block-index-entry-hash e) locator)
                 (incf count)
                 (when (> count 10)
                   (setf step (* step 2)))
                 (let ((moved nil))
                   (loop repeat step
                         while (bitcoin-lisp.storage:block-index-entry-prev-entry e)
                         do (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e))
                            (setf moved t))
                   (unless moved
                     (return))))
        (nreverse locator))
      ;; No entries - use genesis
      (bitcoin-lisp.storage:build-block-locator chain-state)))

(defun build-header-locator (chain-state)
  "Build a block locator starting from the highest header in the index.
Used during IBD when the validated block tip lags behind the header tip."
  (%locator-from-entry (%best-header-entry chain-state) chain-state))

(defun build-header-locator-pprev (chain-state)
  "Block locator starting ONE BLOCK BACK from the header tip (Core's
GetLocator(pindexBestHeader->pprev)). A caught-up peer answers a getheaders on
this locator with the single header it thinks comes next — our own best header,
which we already have — so the already-known fast path in ingest-headers-from-
peer runs update-block-availability and records the peer's best-known cheaply,
transferring nothing. Falls back to the header-tip locator at genesis."
  (let* ((best (%best-header-entry chain-state))
         (pprev (and best (bitcoin-lisp.storage:block-index-entry-prev-entry best))))
    (%locator-from-entry (or pprev best) chain-state)))

(defun request-headers-for-ibd (peer chain-state)
  "Request headers using a locator built from the header tip, not the validated block tip."
  (let ((locator (build-header-locator chain-state)))
    (bitcoin-lisp.networking:send-message
     peer
     (bitcoin-lisp.serialization:make-getheaders-message locator))))

(defun broadcast-initial-getheaders (peers chain-state)
  "At the start of block download, send one getheaders — locator one block back
from our header tip — to every ready peer. Phase 1 learned only the bulk
header-sync peer's tip; every other peer has an empty best-known-block, so the
per-peer download walk (find-blocks-to-download-for-peer) cannot yet tell which
of them serve the tip. A caught-up peer replies with our own best header
(already-known fast path -> update-block-availability), setting its best-known
without any block transfer; a peer slightly ahead sends the few new headers it
has. Core sends this pprev-locator getheaders on peer/sync events; here it
primes availability for the whole ready set as Phase 2 begins. Errors are
isolated per peer so one dead socket cannot abort the sweep."
  (let ((locator (build-header-locator-pprev chain-state)))
    (when locator
      (dolist (peer peers)
        (when (eq (peer-state peer) :ready)
          (ignore-errors
           (send-message
            peer
            (bitcoin-lisp.serialization:make-getheaders-message locator))))))))

;;; --- Outbound chain-sync eviction (Core ConsiderEviction) ---
;;;
;;; An adversary, or simply a stuck set of peers, that fills our outbound slots
;;; with live-but-SILENT peers can pin us on a stale tip indefinitely: they
;;; answer pings, so nothing else evicts them. Core gives each such peer a
;;; 20-minute budget to produce a chain at least as good as our tip, probes
;;; once with a getheaders, and then drops it.

(defconstant +chain-sync-timeout-seconds+ 1200
  "Core CHAIN_SYNC_TIMEOUT (20min): how long an outbound peer may sit below
our tip's work before we probe it.")

(defconstant +headers-response-time-seconds+ 120
  "Core HEADERS_RESPONSE_TIME (2min): the grace period after the probing
getheaders. Total budget before a disconnect is 20min + 2min.")

;;; The protection half (maybe-protect-outbound-peer / release-outbound-protection
;;; and their counter) lives in peer.lisp: the slot must be released from
;;; disconnect-peer, record-misbehavior and ban-peer (Core FinalizeNode), and
;;; peer.lisp loads before this file.

(defun consider-chain-sync-eviction (peer chain-state now)
  "Port of Core ConsiderEviction (net_processing.cpp:5292-5350). Returns
:cleared, :armed, :probed, :disconnected, or NIL when the peer is not a
candidate.

Runs from maintain-peers, NOT from run-ibd's download loop: that loop does not
run at tip, which is precisely where eclipse resistance matters.

Silent throughout — no misbehaviour score, no discouragement. A peer on a worse
chain is useless to us, not malicious."
  (when (and (not (peer-chain-sync-protect peer))
             (peer-outbound-or-block-relay-p peer)
             (eq (peer-state peer) :ready))
    (let* ((tip-hash (bitcoin-lisp.storage:best-block-hash chain-state))
           (tip (and tip-hash (bitcoin-lisp.storage:get-block-index-entry
                               chain-state tip-hash)))
           (tip-work (and tip (bitcoin-lisp.storage:block-index-entry-chain-work tip)))
           (best (and (peer-best-known-block-hash peer)
                      (bitcoin-lisp.storage:get-block-index-entry
                       chain-state (peer-best-known-block-hash peer))))
           (best-work (and best (bitcoin-lisp.storage:block-index-entry-chain-work best))))
      (cond
        ;; A: the peer is at least as good as our tip — nothing to answer for.
        ((and best-work tip-work (>= best-work tip-work))
         (setf (peer-chain-sync-timeout peer) 0
               (peer-chain-sync-work-header peer) nil
               (peer-chain-sync-sent-getheaders peer) nil)
         :cleared)
        ;; B: arm, or RE-arm because the peer caught the benchmark we set last
        ;; time while our tip has since advanced past it.
        ((or (zerop (peer-chain-sync-timeout peer))
             (let ((bench (and (peer-chain-sync-work-header peer)
                               (bitcoin-lisp.storage:get-block-index-entry
                                chain-state (peer-chain-sync-work-header peer)))))
               (and bench best-work
                    (>= best-work
                        (bitcoin-lisp.storage:block-index-entry-chain-work bench)))))
         (setf (peer-chain-sync-timeout peer) (+ now +chain-sync-timeout-seconds+)
               (peer-chain-sync-work-header peer) tip-hash
               (peer-chain-sync-sent-getheaders peer) nil)
         :armed)
        ;; C: armed and expired.
        ((and (plusp (peer-chain-sync-timeout peer))
              (> now (peer-chain-sync-timeout peer)))
         (cond
           ((peer-chain-sync-sent-getheaders peer)
            (bitcoin-lisp:log-info "Peer ~A: outbound peer has old chain, disconnecting"
                                   (peer-address peer))
            (disconnect-peer peer)
            :disconnected)
           (t
            ;; Probe once before dropping: ask from the parent of the benchmark
            ;; so a peer that simply missed an announcement can answer.
            (let* ((bench (and (peer-chain-sync-work-header peer)
                               (bitcoin-lisp.storage:get-block-index-entry
                                chain-state (peer-chain-sync-work-header peer))))
                   (parent (and bench (bitcoin-lisp.storage:block-index-entry-prev-entry bench))))
              (ignore-errors
               (send-message peer (bitcoin-lisp.serialization:make-getheaders-message
                                   (%locator-from-entry (or parent bench) chain-state)))))
            (setf (peer-chain-sync-sent-getheaders peer) t
                  (peer-chain-sync-timeout peer) (+ now +headers-response-time-seconds+))
            :probed)))))))

;;;; ------------------------------------------------------------------
;;;; Extra-outbound eviction (Core EvictExtraOutboundPeers,
;;;; net_processing.cpp:5352-5457)
;;;;
;;;; Two independent halves over two disjoint peer sets, each running only
;;;; when that set is over its own target. They are NOT variations on one
;;;; rule: the block-relay half ranks by when a block was RECEIVED, the
;;;; full-relay half by when one was ANNOUNCED, and the two clocks disagree
;;;; precisely for the peer that announces promptly but loses every download
;;;; race — the peer worth keeping.
;;;;
;;;; Lives here rather than in peer.lisp because the release condition needs
;;;; the in-flight table, and not in node.lisp because that loads later still
;;;; and is where the sweep is driven from.

(defconstant +minimum-connect-time-seconds+ 30
  "Core MINIMUM_CONNECT_TIME: how long a peer must have been connected before
it can be evicted as extra. Without it the stale-tip path is a treadmill —
open an extra peer, evict it on the next 45s sweep before it has had time to
announce anything, open another.")

(defun %extra-eviction-releasable-p (peer now test)
  "Core's final guard on both halves: long enough connected, and no block in
flight from this peer. The in-flight half matters as much as the clock —
dropping a peer mid-download throws the bytes away and re-requests them from
someone else, which under a stale tip is the opposite of progress.

TEST is #'>= for the block-relay half (net_processing.cpp:5386) and #'> for the
full-relay half (:5438). Core really does write them differently. At one-second
resolution they diverge only for a peer connected exactly
MINIMUM_CONNECT_TIME ago, but unifying them would be an unforced divergence and
the next reader would have no way to tell it was deliberate."
  (and (funcall test (- now (peer-connected-at peer)) +minimum-connect-time-seconds+)
       (zerop (count-peer-in-flight peer))))

(defun %peer-network (peer)
  "PEER's network as a BIP155 keyword (:ipv4 :ipv6 :torv3 :i2p :cjdns), or NIL
for an address we cannot classify (a hostname). NIL is its own bucket, which is
the conservative reading: unclassifiable peers only ever protect each other."
  (nth-value 0 (parse-network-address (peer-address peer))))

(defun %multiple-full-outbound-on-network-p (peers peer)
  "Core CConnman::MultipleManualOrFullOutboundConns (net.cpp): do we hold more
than one OUTBOUND_FULL_RELAY-or-MANUAL connection on PEER's network? Manual
peers count toward the total even though they are never themselves evicted —
an operator-pinned peer is still a path to that network, which is exactly what
this guard protects.

Returns NIL — i.e. protects the peer — when it is our only one there. That is
what stops the rotation severing our last Tor or I2P route while the IPv4 set
looks healthy."
  (let ((net (%peer-network peer)))
    (> (count-if (lambda (p)
                   (and (peer-live-p p)
                        (eq (peer-conn-type p) :outbound-full-relay)
                        (eq (%peer-network p) net)))
                 peers)
       1)))

(defun select-extra-block-relay-eviction (peers)
  "Core EvictExtraOutboundPeers' block-relay half (net_processing.cpp:5360-5397):
of the block-relay-only peers take the YOUNGEST (highest id, since ids are
handed out in connection order); if it has given us a block more recently than
the second-youngest, take the second-youngest instead. Returns a peer or NIL.

The youngest block-relay peer is by construction the extra one opened to
unstick a stale tip, so this is what closes the slot the stale-tip trigger
opens. Ranking by PEER-LAST-BLOCK-TIME — block RECEIVED — rather than by the
announcement stamp is Core's choice and matters: block-relay peers exist to
deliver blocks, which is also why they are excluded from chain-sync
protection."
  (let ((live (remove-if-not (lambda (p)
                               (and (eq (peer-conn-type p) :block-relay)
                                    (peer-live-p p)))
                             peers)))
    (when live
      (let* ((sorted (sort (copy-list live) #'> :key #'peer-id))
             (youngest (first sorted))
             (next (second sorted)))
        (if (and next (> (peer-last-block-time youngest)
                         (peer-last-block-time next)))
            next
            youngest)))))

(defun select-extra-full-relay-eviction (peers)
  "Core EvictExtraOutboundPeers' full-relay half (net_processing.cpp:5400-5432):
the outbound full-relay peer with the OLDEST last-block-announcement, ties
broken toward the HIGHER id. Returns a peer or NIL.

Four filters, each of which changes the answer:

  - live peers only (Core's `!pfrom.fDisconnect');
  - never a chain-sync-protected peer (:5419) — P2 hands out that flag
    precisely so this rotation cannot take the peer back;
  - never a MANUAL peer. Core gets this free because MANUAL is a separate
    connection type from OUTBOUND_FULL_RELAY; we type -addnode peers as
    :outbound-full-relay (see replace-disconnected-peers), so without this
    clause the rotation would evict the operator's pinned peers — the exact
    regression the plan's §2 forbids;
  - never our only full-relay-or-manual connection on a network
    (MultipleManualOrFullOutboundConns, :5422), so rotation cannot cost us our
    last Tor or I2P path.

The tie-break is not cosmetic. Every peer that has never announced sits at
stamp 0, so during IBD and after any restart the whole outbound set ties and
this comparison IS the policy: highest id = most recently connected = least
invested, which is also what stops the sweep evicting a long-lived peer that
simply has not seen a new block yet."
  (let ((candidates
          (remove-if-not
           (lambda (p)
             (and (eq (peer-conn-type p) :outbound-full-relay)
                  (peer-live-p p)
                  (not (peer-chain-sync-protect p))
                  (not (peer-manual p))
                  (%multiple-full-outbound-on-network-p peers p)))
           peers)))
    (when candidates
      (reduce (lambda (worst p)
                (let ((wa (peer-last-block-announcement worst))
                      (pa (peer-last-block-announcement p)))
                  (cond ((< pa wa) p)
                        ((and (= pa wa) (> (peer-id p) (peer-id worst))) p)
                        (t worst))))
              candidates))))

(defun any-blocks-in-flight-p ()
  "Core's `mapBlocksInFlight.empty()' test, inverted (net_processing.cpp:1339).
GLOBAL, not per-peer: the question the stale-tip check asks is whether the node
as a whole is making progress, and a download in flight from anyone means our
tip is about to move on its own. Answering it per-peer would call the tip stale
while a block was actively arriving and open an extra connection for nothing."
  (and *ibd-context*
       (plusp (hash-table-count (ibd-context-in-flight *ibd-context*)))
       t))

(defun evict-extra-outbound-peers (peers now full-relay-target block-relay-target)
  "Core PeerManagerImpl::EvictExtraOutboundPeers (net_processing.cpp:5352).
Drops at most one peer per half per call. Returns the peers actually
disconnected, for the caller's log and for the tests.

Each half is gated on ITS OWN set against ITS OWN target, exactly as Core gates
on GetExtraBlockRelayCount / GetExtraFullOutboundCount. Comparing a combined
outbound count against a combined target instead would let two idle block-relay
slots mask a full-relay set that is one over, and vice versa — the same
conflation replace-disconnected-peers already documents on the dialing side of
the same two pools.

The targets are arguments rather than reads: the full-relay one is node-scoped
(node-max-peers, raised by one while the tip looks stale) and node.lisp loads
after this file."
  (let ((evicted '()))
    (flet ((live-count (type)
             (count-if (lambda (p) (and (peer-live-p p) (eq (peer-conn-type p) type)))
                       peers))
           (try (victim test label)
             (when (and victim (%extra-eviction-releasable-p victim now test))
               (bitcoin-lisp:log-info
                "Disconnecting extra ~A peer ~A (last announcement ~D, connected ~Ds)"
                label (peer-address victim)
                (peer-last-block-announcement victim)
                (- now (peer-connected-at victim)))
               (disconnect-peer victim)
               (push victim evicted))))
      (when (> (live-count :block-relay) block-relay-target)
        (try (select-extra-block-relay-eviction peers) #'>= "block-relay-only"))
      (when (> (live-count :outbound-full-relay) full-relay-target)
        (try (select-extra-full-relay-eviction peers) #'> "outbound")))
    (nreverse evicted)))

(defun maybe-disconnect-low-work-outbound (peer chain-state full-batch)
  "Core's IBD chain-quality drop (net_processing.cpp:2926-2944): during IBD, a
peer that has no more headers to give us and whose best-known chain has less
than minimum-chain-work cannot help us sync, so an automatic outbound slot it
occupies is wasted — a step toward IBD eclipse. We refused to DOWNLOAD from
such a peer but never disconnected it, so the slot stayed pinned.

Every clause here is load-bearing:
  - IBD only. Past IBD the rule does not apply.
  - FULL-BATCH is Core's may_have_more_headers, computed from the RECEIVED
    message length (a full 2000-header batch means more may follow). Only a
    NON-full batch proves we have seen the peer's tip.
  - The peer must actually have announced something: a NIL best-known block is
    never judged (Core :2930).
  - The work compared is the peer's best-known over the WHOLE connection
    (monotone via update-block-availability), not this batch's work.
  - STRICTLY less than minimum-chain-work; equal work is kept.
  - Compared against MINIMUM-CHAIN-WORK, not our tip: we do not start block
    download until the header chain clears that floor anyway, so a peer past
    our tip but under the floor is still useless (Core's own note).
  - Automatic outbound slots only (peer-outbound-or-block-relay-p), which
    excludes manual peers and inbound.
  - SILENT: no misbehaviour score, no discouragement. The peer is not
    malicious, just useless to us right now.
Call site is load-bearing too: %store-validated-headers, i.e. only the shapes
on which Core reaches UpdatePeerStateForReceivedHeaders. Returns T when the
peer was dropped."
  (when (and (initial-block-download-p chain-state)
             (not full-batch)
             (peer-outbound-or-block-relay-p peer)
             (peer-best-known-block-hash peer))
    (let* ((entry (bitcoin-lisp.storage:get-block-index-entry
                   chain-state (peer-best-known-block-hash peer)))
           (work (and entry (bitcoin-lisp.storage:block-index-entry-chain-work entry)))
           (floor-work (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*)))
      (when (and work (< work floor-work))
        (bitcoin-lisp:log-info "Peer ~A: headers chain has insufficient work (~A < ~A), disconnecting outbound peer"
                               (peer-address peer) work floor-work)
        (disconnect-peer peer)
        t))))

(defun %store-validated-headers (peer chain-state headers full-batch count-fn label)
  "Contextually validate HEADERS (validate-header-chain) and add the valid
prefix to the block index, bumping the running count via COUNT-FN, then run
Core's UpdatePeerStateForReceivedHeaders (net_processing.cpp:2909-2944) over
PEER: refresh per-peer availability from pindexLast and apply the IBD
sub-minchainwork outbound drop. Shared by the normal and redownload store
paths — i.e. exactly the shapes on which Core reaches
UpdatePeerStateForReceivedHeaders (:3113).

FULL-BATCH is Core's may_have_more_headers: the length of the RECEIVED
message, NOT of the batch stored here. They differ on the REDOWNLOAD path,
where a full 2000-header message releases a shorter run of buffered headers
for storage; Core passes `nCount == m_opts.max_headers_result` from the
received message there too.

Holds the node lock: process-headers mutates the block index the RPC
threads read/write under the same lock."
  (with-node-lock
   (multiple-value-bind (valid error) (validate-header-chain headers chain-state)
    (when error
      ;; Core logs every ContextualCheckBlockHeader failure at
      ;; LogDebug(BCLog::VALIDATION) with the header hash and the state string
      ;; (validation.cpp:4257), and punishment is a separate decision made by
      ;; MaybePunishNodeForBlock — which explicitly does NOT punish
      ;; BLOCK_TIME_FUTURE (net_processing.cpp:1945-1946). A WARN here inverted
      ;; that: the one result Core singles out as nobody's fault was the single
      ;; most common line in the node's log.
      (bitcoin-lisp:log-cat "validation" "Header validation error: ~A" error))
    (let* (;; Core's received_new_header (net_processing.cpp:3079) is
           ;; `last_received_header == nullptr', where last_received_header is
           ;; the index lookup of headers.BACK() (:3052) — i.e. the LAST header
           ;; of the RECEIVED batch was unknown to us. It has to be read before
           ;; process-headers stores anything, which is what forces LET* here.
           ;; The LET this replaced would have evaluated its init forms in the
           ;; same order, but that ordering would have been load-bearing and
           ;; invisible: swapping two bindings would make every batch look
           ;; already-known and the stamp would silently never advance.
           (received-new-header
             (and headers
                  (null (bitcoin-lisp.storage:get-block-index-entry
                         chain-state
                         (bitcoin-lisp.serialization:block-header-hash
                          (car (last headers)))))))
           (added (process-headers valid chain-state))
           ;; Core's pindexLast as an index ENTRY, set below — the follow-up
           ;; getheaders is built from it, never from our own header tip.
           (last-entry nil))
      (funcall count-fn added)
      ;; Core's pindexLast (net_processing.cpp ProcessHeadersMessage): the last
      ;; header of the RECEIVED batch that is in the block index afterwards —
      ;; INCLUDING headers we already had, because AcceptBlockHeader returns
      ;; the existing index entry for a known header.
      ;;
      ;; We cannot use (car (last VALID)): validate-header-chain drops
      ;; already-known headers from VALID entirely, so a batch we already hold
      ;; left VALID empty and updated NO availability. A peer that only ever
      ;; announces headers we already have — the normal case for a peer at the
      ;; same tip, and for every BIP130 announcement of a block we just got
      ;; from someone else — stayed pinned at its handshake-time best block
      ;; forever. Everything keyed off peer-best-known-block-hash (block
      ;; download selection, and the work comparisons the eclipse-resistance
      ;; work depends on) was reading that stale value.
      (let ((pindex-last nil))
        (map nil (lambda (h)
                   (when (bitcoin-lisp.storage:get-block-index-entry
                          chain-state (bitcoin-lisp.serialization:block-header-hash h))
                     (setf pindex-last h)))
             headers)
        ;; PEER may be NIL on degenerate/test callers (handle-headers with no
        ;; peer) — availability is per-peer, so skip it then.
        (setf last-entry
              (and pindex-last
                   (bitcoin-lisp.storage:get-block-index-entry
                    chain-state
                    (bitcoin-lisp.serialization:block-header-hash pindex-last))))
        (when (and peer pindex-last)
          (update-block-availability
           peer chain-state
           (bitcoin-lisp.serialization:block-header-hash pindex-last))
          ;; Core does the IBD chain-quality drop HERE, immediately after
          ;; UpdateBlockAvailability and nowhere else: ProcessHeadersMessage
          ;; returns early for an empty message (:2969-2981), for an
          ;; unconnecting BIP130 announcement (:3029-3040) and for a batch
          ;; diverted into a low-work presync (:3065-3074), so none of those
          ;; shapes is ever judged. Judging them dropped honest outbound peers
          ;; during early IBD — a 1-header announcement whose parent we lack
          ;; only stages hash-last-unknown, leaving best-known at its stale
          ;; sub-minchainwork value, and the check then fired on it.
          (maybe-disconnect-low-work-outbound peer chain-state full-batch)
          ;; Core net_processing.cpp:2946-2956: an outbound full-relay peer
          ;; that delivers a chain at least as good as our tip earns
          ;; protection from the chain-sync eviction logic.
          (let* ((tip-hash (bitcoin-lisp.storage:best-block-hash chain-state))
                 (tip (and tip-hash (bitcoin-lisp.storage:get-block-index-entry
                                     chain-state tip-hash)))
                 (best (and (peer-best-known-block-hash peer)
                            (bitcoin-lisp.storage:get-block-index-entry
                             chain-state (peer-best-known-block-hash peer)))))
            (when (and tip best
                       (>= (bitcoin-lisp.storage:block-index-entry-chain-work best)
                           (bitcoin-lisp.storage:block-index-entry-chain-work tip)))
              (maybe-protect-outbound-peer peer))
            ;; Core net_processing.cpp:2921-2923, the statement immediately
            ;; before the protection grant. Adjacent, but NOT the same test:
            ;; protection takes pindexBestKnownBlock >= tip, this takes
            ;; pindexLast STRICTLY > tip and additionally requires the batch to
            ;; have been new. Collapsing the two — the obvious simplification,
            ;; since here BEST and LAST-ENTRY are the same entry — would stamp
            ;; every peer sitting at our own tip on every duplicate
            ;; announcement, and the rotation that reads this stamp would then
            ;; see a uniformly fresh outbound set and rotate on the tie-break
            ;; alone, i.e. by peer id.
            (when (and received-new-header tip last-entry
                       (> (bitcoin-lisp.storage:block-index-entry-chain-work last-entry)
                          (bitcoin-lisp.storage:block-index-entry-chain-work tip)))
              (credit-block-announcement peer)))))
      (when (> added 0)
        (bitcoin-lisp:log-info "~A: ~D headers, ~D new" label (length headers) added))
      ;; Second value: Core's pindexLast as an index ENTRY. The follow-up
      ;; getheaders must be built from it, not from our own header tip — see
      ;; %maybe-request-more-headers.
      (values added last-entry)))))

(defun %entry-ancestor-at-height (entry height)
  "ENTRY's ancestor at HEIGHT, walking prev-entry links (Core
CBlockIndex::GetAncestor without its skip list — this project reverted the
skip-list walk, #71). NIL when HEIGHT is above ENTRY or the links run out."
  (let ((e entry))
    (loop while (and e (> (bitcoin-lisp.storage:block-index-entry-height e) height))
          do (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
    (when (and e (= (bitcoin-lisp.storage:block-index-entry-height e) height))
      e)))

(defun %ancestor-of-best-header-or-tip-p (chain-state entry)
  "Core PeerManagerImpl::IsAncestorOfBestHeaderOrTip (net_processing.cpp:2813-
2823): ENTRY is m_best_header or one of its ancestors, or lies on the active
chain. NIL for a NIL entry — and, the part that carries the weight, NIL for a
header we hold only on a FORK.

The two disjuncts are Core's; the order here is an optimisation. The
active-chain test walks down from the block tip and costs nothing when ENTRY is
at that tip (the at-tip announcement case), while best-header-entry rescans the
whole index — Core maintains m_best_header incrementally, we do not."
  (and entry
       (or (bitcoin-lisp.storage:entry-on-active-chain-p chain-state entry)
           (let ((best (bitcoin-lisp.storage:best-header-entry chain-state)))
             (and best
                  (let ((ancestor (%entry-ancestor-at-height
                                   best
                                   (bitcoin-lisp.storage:block-index-entry-height entry))))
                    (and ancestor
                         (equalp (bitcoin-lisp.storage:block-index-entry-hash ancestor)
                                 (bitcoin-lisp.storage:block-index-entry-hash entry)))))))
       t))

(defun %batch-already-validated-work-p (chain-state headers)
  "Core's already_validated_work (net_processing.cpp:3046-3054): the batch's
LAST header is already in our block index AND is an ancestor of our best header
or of the active tip. Testing the last header alone is enough for the
membership half, since headers are admitted parent-first — last-known implies
all-known.

Such a batch costs no new index memory and leaks nothing that could fingerprint
us, so both header paths skip the anti-DoS work gate for it and take the store
path instead: a near-no-op that still refreshes per-peer availability and
applies the IBD sub-minchainwork outbound drop (Core
UpdatePeerStateForReceivedHeaders). Core's comment at :2786-2790 relies on
exactly this interaction.

Core's ancestor condition is load-bearing and NOT an optional refinement.
Testing plain index membership — as this did before the GA8 W3 review —
also captures headers we hold on a FORK, which Core deliberately leaves to
TryLowWorkHeadersSync (:2769-2800). Swallowing those here ends header sync
with a fork peer while our own locator, built from our header tip rather than
from the batch, reproduces the same request for ever: a fork we already hold
>= 2000 headers of (aborted presync, peer rotation, restart mid-fork) could
never be synced, and the BIP130 announcement path cannot rescue it either.
Excluded here, such a batch falls through to %maybe-divert-to-presync exactly
as in Core, and the presync's own locator advances into the peer's chain.

Membership is tested first because it is O(1) and false for every ordinary new
batch; the ancestor test behind it is O(index size), same as the header locator
this path builds anyway."
  (and headers
       (%ancestor-of-best-header-or-tip-p
        chain-state
        (bitcoin-lisp.storage:get-block-index-entry
         chain-state
         (bitcoin-lisp.serialization:block-header-hash (car (last headers)))))))

(defun %clear-peer-headers-sync (peer &key finalize)
  "Drop PEER's low-work sync state (Core peer.m_headers_sync.reset()),
finalizing it first when FINALIZE (frees the commitment/redownload buffers of
a sync abandoned mid-flight; a sync that ended by itself is already :final).
NIL PEER (degenerate/test caller) is a no-op."
  (let ((hss (and peer (peer-headers-sync peer))))
    (when hss
      (when finalize (hss-finalize hss))
      (setf (peer-headers-sync peer) nil))))

(defun %drive-headers-sync (peer chain-state headers full-batch count-fn)
  "Feed a batch to PEER's in-progress low-work sync (Core
IsContinuationOfLowWorkHeadersSync): validate batch PoW, advance the state
machine, store whatever REDOWNLOAD releases. Returns REQUEST-MORE — T when
the caller should send the next getheaders from the sync's own locator; on
NIL the sync is over (complete or aborted) and the slot is cleared."
  (let ((hss (peer-headers-sync peer)))
    (if (headers-pow-valid-p headers)
        (multiple-value-bind (ok request-more ready)
            (hss-process-next-headers hss headers full-batch)
          (when ready
            (%store-validated-headers peer chain-state ready full-batch
                                      count-fn "Redownload"))
          (cond ((and ok request-more) t)
                (t
                 (bitcoin-lisp:log-info "Low-work headers sync ~A with ~A (presync height ~D)"
                                        (if ok "complete" "aborted")
                                        (peer-address peer) (hss-current-height hss))
                 (%clear-peer-headers-sync peer)
                 nil)))
        ;; PoW-invalid batch from a peer we're presyncing — abort the sync.
        (progn (%clear-peer-headers-sync peer :finalize t) nil))))

(defun %maybe-divert-to-presync (peer chain-state headers full-batch)
  "No sync running: decide the batch's fate under the anti-DoS work gate
(Core TryLowWorkHeadersSync). Returns one of
  :presync — a low-work sync was started on PEER and fed this batch; the
             caller should request more via the sync's locator;
  :ignore  — low-work batch that cannot start a sync (sub-batch chain, a
             PoW-invalid batch, or a first batch the machine rejected):
             store NOTHING (Core \"Ignoring low-work chain\");
  :store   — work threshold met; store normally."
  (multiple-value-bind (start low-work)
      (maybe-start-presync headers chain-state full-batch)
    (cond
      ;; Presync needs a peer to persist its state across batches and to
      ;; receive the follow-up getheaders; a NIL peer (degenerate/test caller)
      ;; falls through — a low-work batch is still ignored below.
      ((and start peer)
       (bitcoin-lisp:log-info
        "Low-work chain from ~A: presyncing before storing (anti-DoS work gate)"
        (peer-address peer))
       ;; Feed this first batch immediately (already PoW-checked in
       ;; maybe-start-presync); presync never releases headers to store.
       (multiple-value-bind (ok request-more ready)
           (hss-process-next-headers start headers full-batch)
         (declare (ignore ready))
         (cond ((and ok request-more)
                (setf (peer-headers-sync peer) start)
                :presync)
               (t :ignore))))
      (low-work
       ;; Connects, but claims sub-threshold work and no sync can start.
       ;; Core ignores such batches entirely — storing them would let an
       ;; attacker grow the index with arbitrarily many cheap sub-2000-header
       ;; forks (net_processing.cpp:2802-2804).
       (bitcoin-lisp:log-cat "net" "Ignoring low-work chain (~D headers) from peer ~A"
                             (length headers) (and peer (peer-address peer)))
       :ignore)
      (t :store))))

(defun handle-header-batch (peer chain-state headers full-batch count-fn)
  "Process one received header batch during Phase-1 sync, driving PEER's
low-work sync state (peer-headers-sync — Core Peer::m_headers_sync; shared
with the generic path, ingest-headers-from-peer). Returns DONE: whether
header sync from this peer is finished.

Four cases:
  - a low-work sync is already running: drive it, storing any headers it
    releases during REDOWNLOAD, and end when it finalizes;
  - the batch already sits on our own best-header/active chain: skip the
    anti-DoS gate, take the store path (Core already_validated_work) and end
    sync — the peer has taught us nothing, so our locator cannot advance;
    a batch we hold only on a FORK is NOT this case (see
    %batch-already-validated-work-p) and falls through to the gate below;
  - no sync, but this batch connects and claims sub-threshold work: start a
    presync when it is a full batch (store nothing yet), or ignore it
    entirely when not (anti-DoS — Core TryLowWorkHeadersSync);
  - otherwise: store the batch normally, ending on a short (non-full) batch."
  (cond
    ((null headers)
     ;; Core nCount==0: the peer suddenly has nothing to give (perhaps it
     ;; reorged onto our chain) — clear any sync state and stop asking.
     (%clear-peer-headers-sync peer :finalize t)
     t)

    ;; A low-work presync/redownload is in progress with this peer.
    ((peer-headers-sync peer)
     (not (%drive-headers-sync peer chain-state headers full-batch count-fn)))

    ;; Batch already on OUR OWN best-header/active chain
    ;; (%batch-already-validated-work-p = Core already_validated_work): store
    ;; path, no work gate. Without this branch the classic case never fired —
    ;; an outbound peer pinned on a low-work chain, answering our getheaders
    ;; with a short batch we already have, was swallowed by :ignore and never
    ;; judged.
    ;;
    ;; DONE is T even for a full batch, where Core asks again from
    ;; GetLocator(pindexLast). Nothing entered the index, and this loop re-asks
    ;; from our own header tip, so that locator is byte-identical next time
    ;; round and the peer would resend the same batch until the 100-request cap
    ;; — free round-trips for a peer replaying our own chain at us. Ending here
    ;; cannot strand anything precisely because the batch is on our chain: a
    ;; batch we hold only on a FORK is excluded from this branch and goes to
    ;; the presync gate below, whose locator does advance into the peer's
    ;; chain.
    ((%batch-already-validated-work-p chain-state headers)
     (%store-validated-headers peer chain-state headers full-batch
                               count-fn "Received")
     t)

    ;; No sync yet: divert into presync, ignore, or store.
    (t
     (ecase (%maybe-divert-to-presync peer chain-state headers full-batch)
       (:presync nil)
       (:ignore t)
       (:store
        (%store-validated-headers peer chain-state headers full-batch
                                  count-fn "Received")
        (< (length headers)
           bitcoin-lisp.serialization:+max-headers-count+))))))

(defconstant +headers-response-time-seconds+ 120
  "Minimum gap between getheaders messages to one peer (Core
HEADERS_RESPONSE_TIME, net_processing.cpp:100). Every getheaders goes through
%MAYBE-SEND-GETHEADERS so no peer behaviour can turn our own requests into a
flood — most sharply for 1-header unconnecting announcements, where each one
would otherwise buy an index-wide locator walk and a ~1 KB request from us.")

(defun %maybe-send-getheaders (peer locator)
  "Send a getheaders built from LOCATOR unless one went to PEER recently (Core
MaybeSendGetHeaders, net_processing.cpp:2825-2837). Returns T if sent."
  (let ((now (bitcoin-lisp.serialization:get-node-time)))
    (when (> (- now (peer-last-getheaders-time peer))
             +headers-response-time-seconds+)
      (setf (peer-last-getheaders-time peer) now)
      (send-message peer (bitcoin-lisp.serialization:make-getheaders-message locator))
      t)))

(defun %maybe-request-more-headers (peer chain-state last-entry full-batch)
  "Core ProcessHeadersMessage's tail (net_processing.cpp:3105-3111): a
maximum-size headers message means the peer may have more, so ask again — from
GetLocator(pindexLast), the last header of the batch we just received.

THE LOCATOR SOURCE IS THE TERMINATION ARGUMENT, and getting it wrong is a
non-terminating loop with an ordinary lagging peer. Our exponential locator has
gaps wider than a batch, so a peer a few thousand blocks behind answers a
getheaders built from OUR header tip with 2000 headers we already hold. Nothing
enters the index, our header tip does not move, the next locator is
byte-identical, and the peer replays the same batch forever — hundreds of KB and
an index-wide walk per round, and with header sync waiting on that peer, the
sync thread never returns. Built from pindexLast the locator advances into the
peer's chain every round whether or not anything was stored.

Skipped while a low-work sync owns the conversation (Core's !have_headers_sync):
that path sends its own follow-up from the sync's locator."
  (when (and peer full-batch last-entry (null (peer-headers-sync peer)))
    (%maybe-send-getheaders peer (%locator-from-entry last-entry chain-state))))

(defun ingest-headers-from-peer (peer headers chain-state &key count-fn)
  "Generic-path headers ingestion — BIP130 sendheaders announcements,
unsolicited batches, and the at-tip/block-download message drains
(handle-message / dispatch-ibd-message) — with the same low-work anti-DoS
gating as the solicited Phase-1 sync. Port of Core ProcessHeadersMessage
(net_processing.cpp:2960-3117), which is Core's ONE path for every headers
message. Previously this path validated and committed any connecting batch
directly: during a from-genesis IBD the validated tip sits below the work
floor, so process-headers' past-minimum-work gate was off and an attacker
could grow the index without bound with cheap headers — the presync
machinery only protected the solicited path. The sync state lives on the
peer (Core Peer::m_headers_sync), shared with sync-headers, so the two
drivers can never run concurrent syncs against one peer; unlike the Phase-1
loop, this path must send its own follow-up getheaders. Returns the number
of headers added to the index."
  (let ((full-batch (and headers
                         (= (length headers)
                            bitcoin-lisp.serialization:+max-headers-count+)))
        (count-fn (or count-fn (lambda (n) (declare (ignore n))))))
    ;; A CONNECTING headers message is the answer to any getheaders we had
    ;; outstanding, so re-arm the throttle (Core net_processing.cpp:3040-3043 —
    ;; deliberately NOT for unconnecting batches, which are announcements and
    ;; must not buy an unthrottled request from us).
    (when (and peer headers
               (bitcoin-lisp.storage:get-block-index-entry
                chain-state
                (bitcoin-lisp.serialization:block-header-prev-block (first headers))))
      (setf (peer-last-getheaders-time peer) 0))
    (cond
      ;; Empty message: cannot be an announcement; a peer mid-low-work-sync
      ;; suddenly has nothing for us — drop the sync (Core nCount==0 branch).
      ((null headers)
       (%clear-peer-headers-sync peer :finalize t)
       0)

      ;; A low-work presync/redownload is in progress with this peer: drive
      ;; it and request the next batch via the sync's own locator (Core
      ;; IsContinuationOfLowWorkHeadersSync sends the follow-up getheaders
      ;; itself). (PEER is non-nil here — a NIL peer holds no sync state.)
      ((and peer (peer-headers-sync peer))
       (let ((added 0))
         (when (%drive-headers-sync peer chain-state headers full-batch
                                    (lambda (n) (incf added n) (funcall count-fn n)))
           (send-message peer (bitcoin-lisp.serialization:make-getheaders-message
                               (hss-locator-hashes (peer-headers-sync peer)))))
         added))

      ;; Unconnecting batch: possibly a benign announcement whose connecting
      ;; headers we lack — request them from our header tip and stage the
      ;; announced tip for per-peer availability, storing nothing (Core
      ;; HandleUnconnectingHeaders, net_processing.cpp:2654-2672). With no
      ;; peer there is nobody to ask or to stage availability for.
      ((null (bitcoin-lisp.storage:get-block-index-entry
              chain-state
              (bitcoin-lisp.serialization:block-header-prev-block (first headers))))
       (when peer
         (request-headers-for-ibd peer chain-state)
         (update-block-availability
          peer chain-state
          (bitcoin-lisp.serialization:block-header-hash (car (last headers)))))
       0)

      ;; Batch already on our own best-header/active chain: store path, no
      ;; work gate — see %batch-already-validated-work-p (Core's
      ;; last_received_header / IsAncestorOfBestHeaderOrTip skip,
      ;; net_processing.cpp:3046-3054). A batch we hold only on a fork is not
      ;; this case and falls through to the gate below, as in Core.
      ((%batch-already-validated-work-p chain-state headers)
       (multiple-value-bind (added last-entry)
           (%store-validated-headers peer chain-state headers full-batch
                                     count-fn "Received")
         (%maybe-request-more-headers peer chain-state last-entry full-batch)
         added))

      ;; Connecting batch with new headers: anti-DoS work gate, then store.
      (t
       (ecase (%maybe-divert-to-presync peer chain-state headers full-batch)
         (:presync
          (send-message peer (bitcoin-lisp.serialization:make-getheaders-message
                              (hss-locator-hashes (peer-headers-sync peer))))
          0)
         (:ignore 0)
         (:store
          (multiple-value-bind (added last-entry)
              (%store-validated-headers peer chain-state headers full-batch
                                        count-fn "Received")
            (%maybe-request-more-headers peer chain-state last-entry full-batch)
            added)))))))

(defparameter +header-sync-silent-passes+ 50
  "Pump passes with NO headers message from the chosen peer before header sync
calls it silent and the caller rotates (~10s at the pass sleep below).")

(defparameter +header-sync-quiet-passes+ 5
  "Pump passes after the peer's LAST answer before header sync returns. Short on
purpose: once a peer has answered, the conversation continues through the pump
whether or not this function is still watching (ingest sends the follow-up
getheaders itself), so there is nothing to wait for — and at the tip, where the
first answer is also the last, waiting out the silent budget would burn ~10s of
every sync cycle for nothing.")

(defparameter +header-sync-deadline-seconds+ 60
  "Absolute cap on one sync-headers call, whatever the peer does. The idle
counters alone are not a bound: a peer that emits one headers message every few
seconds — even 1-header announcements — resets them forever, and this runs on
the sync thread, so it would pin block download, peer maintenance and the pump
behind one peer indefinitely. That is the frozen-tip failure class this
subsystem has produced twice.")

(defun %peer-headers-bytes (peer)
  "Wire bytes of headers messages received from PEER — the existing per-command
counter (Core mapRecvBytesPerMsgType). Strictly increasing per headers message,
including empty ones, so a CHANGE is exactly 'this peer answered'. That is the
signal header-sync rotation needs, and it is NOT 'this peer had something new':
a peer at our own tip answers with a batch we already hold, and scoring that as
silence would rotate away from every healthy peer the moment we caught up."
  (gethash "headers" (peer-recv-per-msg peer) 0))

(defun sync-headers (peer chain-state &key recent-rejects ctx utxo-set
                                           block-store fee-estimator)
  "Kick header sync with PEER, WITHOUT owning the message pump. Returns
(values received-count stalled-p); STALLED-P is true when the peer never
answered, the signal sync-headers-with-failover uses to rotate.

This used to be a blocking request/response loop: send getheaders, then sit in
receive-message-blocking on this one peer for up to 30 x 5s per batch. It runs
on the sync thread — the same thread as the pump — so for that whole time NO
other peer was drained, no block was processed, and no expired read was reaped.
One peer's latency was the whole node's.

Now the wait IS a pump pass, and the sync itself continues through the ordinary
message path (ingest-headers-from-peer sends its own follow-up getheaders), so
this function only has to kick it off and report whether the peer is worth
keeping. Core has no header-sync loop at all for the same reason."
  (let* ((start-received (if ctx (ibd-context-headers-received ctx) 0))
         (answered-before (%peer-headers-bytes peer))
         (last-answer answered-before)
         (idle 0)
         (deadline (+ (get-universal-time) +header-sync-deadline-seconds+)))
    ;; Kick: one getheaders, throttled like every other. Use the low-work sync's
    ;; own locator when one is in progress (its headers are not in the index).
    (let ((hss (peer-headers-sync peer)))
      (unless (if hss
                  (send-message peer (bitcoin-lisp.serialization:make-getheaders-message
                                      (hss-locator-hashes hss)))
                  (%maybe-send-getheaders peer (build-header-locator chain-state)))
        ;; Nothing was SENT — %MAYBE-SEND-GETHEADERS throttles a repeat within
        ;; +HEADERS-RESPONSE-TIME-SECONDS+ of the last one, as Core's
        ;; MaybeSendGetHeaders does. Waiting for a reply to a request we did not
        ;; make burns the whole silent budget (~10s) every cycle, which is
        ;; exactly what a node AT ITS TIP does on every pass: the previous
        ;; cycle's getheaders is still inside the throttle window, so nothing
        ;; goes out and nothing comes back. It logged "(no answer)" and looked
        ;; like a quiet peer.
        ;;
        ;; Return NOT-STALLED: the peer did nothing wrong, we simply did not
        ;; ask. Reporting a stall here would rotate header sync away from a
        ;; perfectly healthy peer on a timer.
        (return-from sync-headers (values 0 nil))))
    (loop
      (when (or *ibd-stop-requested*
                (not (eq (peer-state peer) :ready))
                (null (peer-connection peer))
                (> (get-universal-time) deadline))
        (return))
      ;; The wait: one pass over EVERY peer, with the live context — nobody is
      ;; starved while we wait. Sends queued by the dispatch (getheaders,
      ;; getdata, pong) are flushed in the same pass, or a partially-written
      ;; request would sit until the next send to that peer and read as a stall.
      (pump-peer-messages (or (and ctx (ibd-context-peers ctx)) (list peer))
                          chain-state utxo-set block-store
                          :ctx ctx
                          :mempool (and ctx (ibd-context-mempool ctx))
                          :address-book (and ctx (ibd-context-address-book ctx))
                          :fee-estimator fee-estimator
                          :recent-rejects recent-rejects)
      (let ((answer (%peer-headers-bytes peer)))
        (if (/= answer last-answer)
            (setf last-answer answer
                  idle 0)
            (incf idle)))
      (when (>= idle (if (= last-answer answered-before)
                         +header-sync-silent-passes+
                         +header-sync-quiet-passes+))
        (return))
      (sleep 0.2))
    (let ((received (- (if ctx (ibd-context-headers-received ctx) 0) start-received))
          (never-answered (= last-answer answered-before)))
      ;; RECEIVED is the ctx-wide count, so it includes headers other peers
      ;; delivered during the pass — informational only; the caller reads the
      ;; stall flag.
      (bitcoin-lisp:log-info "Header sync kicked ~A: ~D headers ingested~:[~; (no answer)~]"
                             (peer-address peer) received never-answered)
      (values received never-answered))))

(defun sync-headers-with-failover (peers chain-state ctx
                                   &key recent-rejects (sync-fn #'sync-headers)
                                        utxo-set block-store fee-estimator)
  "Run header sync against ready PEERS in descending start-height order,
rotating to the next peer whenever one STALLS (sync-fn's 2nd value true),
and stopping at the first that answers. Returns the peer that responded, or
NIL if every ready peer stalled / none were ready. SYNC-FN is injectable so
the rotation logic is testable without network I/O. The full node context
(CTX + UTXO-SET/BLOCK-STORE/FEE-ESTIMATOR) is threaded to SYNC-FN so its
interleaved-message drains can serve tx getdata and process blocks.

Fixes the single-peer header-sync freeze: run-ibd previously synced from one
peer chosen by start-height (frozen at handshake), with no failover — a quiet
or dead-fork peer was re-picked every cycle and pinned the tip for hours."
  (dolist (peer (sort (copy-list peers) #'> :key #'peer-start-height) nil)
    (when *ibd-stop-requested*
      (return nil))
    (when (eq (peer-state peer) :ready)
      (setf (ibd-context-header-sync-peer ctx) peer)
      (multiple-value-bind (count stalled)
          (funcall sync-fn peer chain-state
                   :recent-rejects recent-rejects
                   :ctx ctx
                   :utxo-set utxo-set
                   :block-store block-store
                   :fee-estimator fee-estimator)
        (declare (ignore count))
        (unless stalled (return peer))))))

(defvar *forensic-store-from-height* nil
  "Debug: when set to an integer N, store every received block at
   height >= N to disk BEFORE validation, so failed-validation blocks
   are still available for analysis. Use to capture blocks our
   validator rejects so we can compare against Bitcoin Core.")

(defun %fork-bodies-complete-p (entry tip-entry chain-state block-store)
  "T when every block on ENTRY's branch strictly above its fork point with
TIP-ENTRY is present in the block-store. Returns (values ok-p missing-hash):
on failure MISSING-HASH is the first absent body, which is what the branch has
to WAIT for (Core's pindexTest — the key it parks the branch under).

Cheap gate for the deep-reorg trigger: probe-file only (block-exists-p),
walking UP from the fork point with early exit at the first gap — so while the
fork is still downloading this costs a handful of probes, and the expensive
perform-reorg machinery runs only once, when the last body lands. ENTRY itself
is excluded: the trigger holds the incoming block in hand."
  (let ((fork (bitcoin-lisp.validation:find-fork-point entry tip-entry)))
    (when fork
      ;; Collect entry's parent chain down to the fork point (exclusive),
      ;; then probe upward (oldest first) so the common early-missing case
      ;; exits after one probe.
      (let ((chain '())
            (e (bitcoin-lisp.storage:block-index-entry-prev-entry entry))
            (fork-hash (bitcoin-lisp.storage:block-index-entry-hash fork)))
        (loop while (and e (not (equalp (bitcoin-lisp.storage:block-index-entry-hash e)
                                        fork-hash)))
              do (push e chain)
                 (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
        (when e   ; reached the fork point — the branch is well-formed
          (dolist (be chain t)
            (let ((bh (bitcoin-lisp.storage:block-index-entry-hash be))
                  (h (bitcoin-lisp.storage:block-index-entry-height be)))
              ;; On-active-chain blocks below our tip count as present even
              ;; if pruned from the store (perform-reorg's disconnect side
              ;; re-checks; this is only the cheap gate).
              (unless (or (bitcoin-lisp.storage:block-exists-p block-store bh)
                          (let ((a (bitcoin-lisp.storage:get-block-at-height
                                    chain-state h)))
                            (and a (equalp (bitcoin-lisp.storage:block-index-entry-hash a)
                                           bh))))
                ;; The SECOND value names the block we are waiting for — Core's
                ;; pindexTest, the block it keys m_blocks_unlinked on.
                (return (values nil bh))))))))))

(defparameter +reorg-candidates-cap+ 4096
  "Hard cap on the reorg-candidate SET (and disk-blocks-above-tip). The
AcceptBlock gate already bounds what enters, but this is a belt-and-suspenders
ceiling so a pathological header topology can't grow the set without bound.")

(defun %record-disk-block-above-tip (height hash)
  "Record a persisted above-tip block in disk-blocks-above-tip (drain's disk
fallback). Bounded by +reorg-candidates-cap+ heights; over cap the entry is
dropped (the block stays on disk and the download walk re-records it when the
window reaches it)."
  (when *ibd-context*
    (let ((map (ibd-context-disk-blocks-above-tip *ibd-context*)))
      (when (or (gethash height map)
                (< (hash-table-count map) +reorg-candidates-cap+))
        (pushnew hash (gethash height map) :test #'equalp)))))

(defun %out-of-order-block-acceptable-p (entry current-height requested chain-state)
  "Core AcceptBlock anti-DoS gate (validation.cpp:4367-4378) for an
out-of-order block: keep it if we REQUESTED it, or (unsolicited) it has more
work than our tip, sits within +min-blocks-to-keep+ of the tip, and meets
minimum chain work. Header admission already validated its PoW before the
entry got chain-work, so this bounds only unsolicited far-ahead / low-work
disk fill."
  (or requested
      (let* ((tip-entry (bitcoin-lisp.storage:get-block-index-entry
                         chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
             (work (bitcoin-lisp.storage:block-index-entry-chain-work entry))
             (height (bitcoin-lisp.storage:block-index-entry-height entry)))
        (and tip-entry
             (> work (bitcoin-lisp.storage:block-index-entry-chain-work tip-entry))
             (<= height (+ current-height bitcoin-lisp:+min-blocks-to-keep+))
             (>= work (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*))))))

(defun note-reorg-candidate (entry chain-state)
  "Add ENTRY to the deep-reorg candidate SET if its chain outweighs the active
tip and it isn't already rejected. Only PERSISTED blocks should be noted (the
retry loads the body from disk); callers note from the persist paths and the
download walk. O(1); safe to call once per walked block per tick. Bounded by
+reorg-candidates-cap+."
  (when *ibd-context*
    (let ((tip-entry (bitcoin-lisp.storage:get-block-index-entry
                      chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
          (hash (bitcoin-lisp.storage:block-index-entry-hash entry))
          (set (ibd-context-reorg-candidates *ibd-context*)))
      (when (and tip-entry
                 (> (bitcoin-lisp.storage:block-index-entry-chain-work entry)
                    (bitcoin-lisp.storage:block-index-entry-chain-work tip-entry))
                 (not (gethash hash (ibd-context-rejected-reorg-candidates *ibd-context*)))
                 (or (gethash hash set)
                     (< (hash-table-count set) +reorg-candidates-cap+)))
        (setf (gethash hash set) t)))))

(defun %reject-reorg-candidate (hash)
  "Move HASH out of the candidate set into the rejected set (bounded)."
  (when *ibd-context*
    (remhash hash (ibd-context-reorg-candidates *ibd-context*))
    (let ((rej (ibd-context-rejected-reorg-candidates *ibd-context*)))
      (when (>= (hash-table-count rej) +reorg-candidates-cap+)
        (clrhash rej))
      (setf (gethash hash rej) t))))

(defun %park-unlinked-reorg-candidate (candidate-hash missing-hash)
  "Mark CANDIDATE-HASH as waiting for MISSING-HASH, the body its branch needs.
A parked candidate is skipped by the scan until that body arrives.

This is Core's response to the same situation. FindMostWorkChain, on reaching a
branch block with no data, takes the branch out of setBlockIndexCandidates and
inserts it into m_blocks_unlinked keyed by the parent — and says why: \"so that
if the block arrives in the future we can try adding to setBlockIndexCandidates
again\" (validation.cpp:3184-3190).

Ours SUPPRESSES THE PROBE rather than dropping the candidacy, which is the same
idea adapted to a different structure. Core's candidate set IS its work queue,
so erasing from it is how Core stops working on the branch; ours is a set plus a
separate probe loop, and several paths legitimately observe the set to mean
\"recoverable, not rejected\" — dropping the entry there broke the deep-reorg
livelock regression test, correctly. Skipping the probe removes the same cost.

The cost being removed is real. Measured on testnet4 over 12.7 days: 205 \"REORG
REFUSED: N blocks missing from store\" lines across ~40 heights, 11 of them at a
single height, each one a fresh walk of a branch whose answer could not have
changed. The retry is not the problem — the retry with no event to wait for is."
  (when *ibd-context*
    (let ((map (ibd-context-unlinked-reorg-candidates *ibd-context*))
          (parked (ibd-context-parked-reorg-candidates *ibd-context*)))
      ;; Bounded like every other candidate map: a pathological header topology
      ;; must not be able to grow this without limit.
      (when (or (gethash missing-hash map)
                (< (hash-table-count map) +reorg-candidates-cap+))
        (pushnew candidate-hash (gethash missing-hash map) :test #'equalp)
        (setf (gethash candidate-hash parked) missing-hash)))))

(defun %reorg-candidate-parked-p (candidate-hash block-store)
  "T when CANDIDATE-HASH is waiting for a body that is still not here, so
walking its branch again cannot produce a different answer.

The awaited body is re-checked rather than trusted: a body can appear through a
path that does not drain the map (a reindex, an operator dropping a file in),
and a candidate parked against a block that has since arrived would otherwise
never be probed again — trading an unbounded retry for a reorg that never
happens, which is strictly worse than the bug."
  (when *ibd-context*
    (let ((missing (gethash candidate-hash
                            (ibd-context-parked-reorg-candidates *ibd-context*))))
      (and missing
           (not (bitcoin-lisp.storage:block-exists-p block-store missing))))))

(defun %rearm-unlinked-reorg-candidates (hash chain-state)
  "A body with HASH just landed: un-park everything that was waiting for it.
Core drains m_blocks_unlinked on the same event (after a block is written).
Returns how many were re-armed.

NOTE-REORG-CANDIDATE re-applies the work and rejected-set tests, so a branch
that went stale or was rejected while it waited does not come back."
  (when *ibd-context*
    (let* ((map (ibd-context-unlinked-reorg-candidates *ibd-context*))
           (parked (ibd-context-parked-reorg-candidates *ibd-context*))
           (waiting (gethash hash map))
           (n 0))
      (when waiting
        (remhash hash map)
        (dolist (candidate-hash waiting)
          (remhash candidate-hash parked)
          (let ((e (bitcoin-lisp.storage:get-block-index-entry chain-state
                                                              candidate-hash)))
            (when e
              (note-reorg-candidate e chain-state)
              (incf n))))
        (when (plusp n)
          (bitcoin-lisp:log-cat
           "validation" "Reorg: ~D parked fork candidate~:P re-armed by the ~
                         arrival of ~A"
           n (bitcoin-lisp.crypto:bytes-to-hex hash))))
      n)))

(defun %best-completable-reorg-target (chain-state block-store tip-entry tip-work)
  "Highest-work candidate in the set whose fork bodies are all on disk (both
the connect side via %fork-bodies-complete-p and — because perform-reorg is
all-or-nothing on BOTH sides — the disconnect side, the active chain down to
the fork point). Prunes stale (<=tip work), rejected, :invalid, and
body-missing entries as it scans. Returns (values entry block) or NIL. Bounds
the per-cycle gate work: probes only the top few by work, since higher-work
completable targets are what we want and gated forks early-exit cheaply."
  (let ((set (ibd-context-reorg-candidates *ibd-context*))
        (rej (ibd-context-rejected-reorg-candidates *ibd-context*))
        (cands '()))
    (maphash
     (lambda (hash v)
       (declare (ignore v))
       (let ((e (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))
         (cond
           ((or (null e)
                (gethash hash rej)
                (eq (bitcoin-lisp.storage:block-index-entry-status e) :invalid)
                (<= (bitcoin-lisp.storage:block-index-entry-chain-work e) tip-work))
            (remhash hash set))          ; prune: stale / rejected / invalid
           (t (push e cands)))))
     set)
    ;; Highest work first; try the top few through the (two-sided) gate.
    (setf cands (sort cands #'>
                      :key #'bitcoin-lisp.storage:block-index-entry-chain-work))
    ;; A branch still waiting on a body it has already been shown to lack is
    ;; skipped without walking it again — see %REORG-CANDIDATE-PARKED-P.
    (setf cands (remove-if (lambda (e)
                             (%reorg-candidate-parked-p
                              (bitcoin-lisp.storage:block-index-entry-hash e)
                              block-store))
                           cands))
    (loop for e in cands
          for i from 0 below 16
          do (multiple-value-bind (complete missing)
                 (%fork-bodies-complete-p e tip-entry chain-state block-store)
               (cond
                 ((and complete
                       (%active-chain-present-to-fork-p e tip-entry chain-state
                                                        block-store))
                  (let ((blk (bitcoin-lisp.storage:get-block
                              block-store
                              (bitcoin-lisp.storage:block-index-entry-hash e))))
                    (if blk
                        (return-from %best-completable-reorg-target (values e blk))
                        ;; Body vanished since it was noted — prune and keep scanning.
                        (remhash (bitcoin-lisp.storage:block-index-entry-hash e) set))))
                 (missing
                  ;; A connect-side body is not here. Stop re-probing this branch
                  ;; every pass and wait for the event that could change the
                  ;; answer — the body arriving.
                  (%park-unlinked-reorg-candidate
                   (bitcoin-lisp.storage:block-index-entry-hash e) missing))
                 ;; No MISSING means the DISCONNECT side is incomplete: local
                 ;; corruption, not something a peer will deliver, so parking it
                 ;; under a hash would park it under nothing. Left to the
                 ;; existing skip.
                 (t nil))))
    nil))

(defun %active-chain-present-to-fork-p (entry tip-entry chain-state block-store)
  "T when every ACTIVE-chain (disconnect-side) body from TIP-ENTRY down to the
fork point with ENTRY is present — perform-reorg needs both sides, and a
missing active-chain body (undo/block corruption) otherwise makes it refuse
every cycle after the connect-side gate passed. Active-chain blocks below the
tip are treated as present when on-chain (get-block-at-height), even if pruned;
perform-reorg's own precondition is the authority — this only avoids the
wasteful attempt."
  (let ((fork (bitcoin-lisp.validation:find-fork-point entry tip-entry)))
    (when fork
      (let ((fork-height (bitcoin-lisp.storage:block-index-entry-height fork))
            (e tip-entry))
        (loop while (and e (> (bitcoin-lisp.storage:block-index-entry-height e)
                              fork-height))
              do (let ((bh (bitcoin-lisp.storage:block-index-entry-hash e))
                       (h (bitcoin-lisp.storage:block-index-entry-height e)))
                   (unless (or (bitcoin-lisp.storage:block-exists-p block-store bh)
                               (let ((a (bitcoin-lisp.storage:get-block-at-height
                                         chain-state h)))
                                 (and a (equalp (bitcoin-lisp.storage:block-index-entry-hash a)
                                                bh))))
                     (return-from %active-chain-present-to-fork-p nil))
                   (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e))))
        t))))

(defun retry-best-reorg-candidate (chain-state block-store utxo-set
                                   &key fee-estimator recent-rejects)
  "Deep-reorg activation — the case the height-dispatched receive path cannot
reach. A block that wins the reorg only above tip+1 (or below the tip on a
heavier-shorter fork) never triggers activate-block, so nothing attempts the
reorg and the tip sits still forever (there is no periodic best-chain
re-evaluation; Core's ActivateBestChain runs after every accepted block).

Finds the highest-work COMPLETABLE candidate (both fork sides on disk) and
runs activate-block's pre-reorg case for it — the all-or-nothing perform-reorg
is attempted only when it can succeed. The ONLY permanent-reject path is a
deterministic validate-block failure (a consensus-invalid fork); a transient
:reorg-refused (raced/corrupt body) re-queues and retries, and a raced
:weaker-chain just drops from the set — so a completable best chain can never
be permanently rejected. Called on out-of-order/weaker arrivals and once per
fetch cycle (which also re-arms after restart via the download walk). Returns T if a
candidate activated."
  (when (null *ibd-context*)
    (return-from retry-best-reorg-candidate nil))
  (let ((tip-entry (bitcoin-lisp.storage:get-block-index-entry
                    chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
        (mempool (ibd-context-mempool *ibd-context*)))
    (when (null tip-entry)
      (return-from retry-best-reorg-candidate nil))
    (multiple-value-bind (entry blk)
        (%best-completable-reorg-target
         chain-state block-store tip-entry
         (bitcoin-lisp.storage:block-index-entry-chain-work tip-entry))
      (when (null entry)
        (return-from retry-best-reorg-candidate nil))
      (let ((cand-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
            (height (bitcoin-lisp.storage:block-index-entry-height entry)))
        (bitcoin-lisp:log-debug
         "Deep-reorg candidate at height ~D outweighs tip ~D with complete bodies; attempting reorg"
         height (bitcoin-lisp.storage:block-index-entry-height tip-entry))
        (multiple-value-bind (activated error missing-blocks)
            (with-node-lock
              (bitcoin-lisp.validation:activate-block
               blk chain-state block-store utxo-set
               :current-time (bitcoin-lisp.serialization:get-unix-time)
               :skip-scripts (bitcoin-lisp.validation:script-checks-skippable-p
                              chain-state
                              (bitcoin-lisp.serialization:block-header-hash
                               (bitcoin-lisp.serialization:bitcoin-block-header blk))
                              height)
               :fee-estimator fee-estimator
               :recent-rejects recent-rejects
               :mempool mempool
               :tx-index (%context-tx-index)))
          (cond
            (activated
             (remhash cand-hash (ibd-context-reorg-candidates *ibd-context*))
             (clear-block-failure cand-hash)
             (note-tip-advanced chain-state)
             (bitcoin-lisp:log-warn "Deep-reorg activated: new tip height ~D" height)
             ;; Children above the new tip may already be buffered.
             (drain-block-queue chain-state utxo-set block-store
                                :fee-estimator fee-estimator
                                :recent-rejects recent-rejects)
             t)
            ((and (eq error :reorg-refused) missing-blocks)
             ;; TRANSIENT: gate passed but perform-reorg found a body absent at
             ;; reorg time — raced out (pruned), or an active-chain body whose
             ;; file exists (so %active-chain-present-to-fork-p passed) but is
             ;; corrupt/unreadable. Re-queue it (re-fetch + cursor rewind) and
             ;; return. Do NOT reject: this is not a validation verdict, and
             ;; permanently rejecting a completable best chain here (corrupt
             ;; file / pruned disconnect body) is worse than a bounded per-cycle
             ;; cheap re-probe — perform-reorg's missing-precondition refuses
             ;; early (no full validation), and the two-sided completeness gate
             ;; stops re-selecting the candidate while the body is genuinely
             ;; absent, so there is no expensive loop.
             (queue-missing-fork-blocks missing-blocks)
             nil)
            ((eq error :interrupted)
             ;; Stopping/pausing — says nothing about the candidate. Keep it in
             ;; the set, don't reject it, don't retry now.
             nil)
            ((member error '(:weaker-chain :reorg-refused :unknown-parent :corrupt-undo))
             ;; NOT a validation verdict on the CANDIDATE: the tip advanced under
             ;; us (raced :weaker-chain), the reorg is structurally impossible
             ;; right now (no common ancestor / fork below pruned height, bare
             ;; :reorg-refused), or our own disconnect-side undo is corrupt
             ;; (:corrupt-undo — the candidate is fine, our local state isn't).
             ;; Drop from the candidate set but do NOT permanently reject — it
             ;; may become the best completable target again once the transient
             ;; condition clears (e.g. the undo is repaired / re-derived).
             (remhash cand-hash (ibd-context-reorg-candidates *ibd-context*))
             nil)
            (t
             ;; Deterministic validate-block failure (this fork or the incoming
             ;; block is consensus-invalid): reject so we never re-attempt a
             ;; doomed reorg. This is the ONLY permanent-reject path.
             (bitcoin-lisp:log-warn
              "Deep-reorg candidate at height ~D did not activate (~A); rejecting"
              height error)
             (%reject-reorg-candidate cand-hash)
             nil)))))))

(defun process-received-block (block chain-state utxo-set block-store
                                &key fee-estimator recent-rejects
                                  (wire-size 0) requested)
  "Process a received block - validate and connect to chain.
After connecting, drains the queue of any children that can now be connected.
REQUESTED is T when this block was in-flight/pending (we asked for it); it
lifts the AcceptBlock anti-DoS gate on the out-of-order persist path."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (hash (bitcoin-lisp.serialization:block-header-hash header))
         (entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash))
         (mempool (and *ibd-context* (ibd-context-mempool *ibd-context*))))
    (when *ibd-context*
      (note-block-wire-size *ibd-context* wire-size))

    (unless entry
      (bitcoin-lisp:log-warn "Received unknown block ~A"
                             (bitcoin-lisp.crypto:bytes-to-hex hash))
      (return-from process-received-block nil))

    (let ((height (bitcoin-lisp.storage:block-index-entry-height entry))
          (current-height (bitcoin-lisp.storage:current-height chain-state)))

      ;; Skip blocks we already applied (duplicates from multiple peers).
      ;; Distinct from competing-fork blocks at h ≤ current-height: those
      ;; still have status :header-valid and we need to STORE them so a
      ;; future reorg can use them. Only :valid means "already on our
      ;; active chain."
      (when (and (<= height current-height)
                 (eq (bitcoin-lisp.storage:block-index-entry-status entry) :valid))
        (return-from process-received-block nil))

      ;; A competing-fork block (h ≤ current, status :header-valid):
      ;; store it and dispatch to activate-block. activate-block will
      ;; recognize the weaker-chain case and return :weaker-chain
      ;; without changing our active tip. A later block that pushes the
      ;; fork past our tip will then trigger the reorg.
      (when (<= height current-height)
        ;; Never PERSIST a witness-stripped competing-fork block: the
        ;; :weaker-chain path stores before full validation (deferred until a
        ;; reorg needs it), so a stripped block would land on disk and then fail
        ;; every reorg attempt — exactly what wedged testnet4. Drop this copy; a
        ;; witness-complete copy arrives via v2 compact blocks / full witness
        ;; downloads if the fork ever becomes relevant.
        (if (bitcoin-lisp.validation:block-witness-stripped-p block)
            (bitcoin-lisp:log-debug
             "Competing-fork block ~D arrived witness-stripped; not storing" height)
            ;; Node lock: activation mutates chainstate/UTXO/mempool state
            ;; the RPC threads access under the same lock.
            (progn
              (with-node-lock
                (bitcoin-lisp.storage:note-block-position
                 chain-state hash
                 (nth-value 1 (bitcoin-lisp.storage:store-block
                               block-store block :height height))))
              ;; Same event as the out-of-order path: a body landed, so any fork
              ;; candidate parked waiting for it can be tried again. BOTH persist
              ;; sites must drain, or a fork whose last missing body arrives
              ;; through this one stays parked forever — which is precisely the
              ;; deep-reorg livelock this file already has a regression test for.
              (when *ibd-context*
                (%rearm-unlinked-reorg-candidates hash chain-state))
              (multiple-value-bind (activated error missing-blocks)
                  (with-node-lock
                    (bitcoin-lisp.validation:activate-block
                     block chain-state block-store utxo-set
                     :skip-scripts (bitcoin-lisp.validation:script-checks-skippable-p
                                 chain-state
                                 (bitcoin-lisp.serialization:block-header-hash
                                  (bitcoin-lisp.serialization:bitcoin-block-header block))
                                 height)
                     :fee-estimator fee-estimator
                     :recent-rejects recent-rejects
                     :mempool mempool
                     :tx-index (%context-tx-index)))
                (cond
                  ;; A heavier-shorter fork can win the reorg with its tip at or
                  ;; below our height (real-difficulty fork vs min-difficulty
                  ;; spam) — activate-block case 2 then fires here.
                  (activated
                   (clear-block-failure hash)
                   (note-tip-advanced chain-state)
                   (drain-block-queue chain-state utxo-set block-store
                                      :fee-estimator fee-estimator
                                      :recent-rejects recent-rejects))
                  ;; Stored, doesn't yet outweigh the tip: note it so the
                  ;; per-cycle retry re-evaluates once its fork completes
                  ;; (the crossover-at-or-below-tip case — F3).
                  ;; :corrupt-undo is our own disconnect-side undo fault, not
                  ;; the incoming block's — note it as a candidate (the retry
                  ;; below re-attempts once the undo is re-derived) rather than
                  ;; blaming the innocent block.
                  ;; :interrupted is a stop request truncating the reorg, not a
                  ;; verdict on this block either — note the candidate so the
                  ;; reorg is re-attempted once the node resumes.
                  ((member error '(:weaker-chain :corrupt-undo :interrupted))
                   (note-reorg-candidate entry chain-state))
                  ;; Outweighs but intermediate bodies missing: re-queue the
                  ;; hole (cursors rewound) and note for retry.
                  ((eq error :reorg-refused)
                   (queue-missing-fork-blocks missing-blocks)
                   (note-reorg-candidate entry chain-state))
                  (t
                   (bitcoin-lisp:log-debug "Competing-fork block ~D activate result: ~A"
                                           height error)))
                ;; Try the best completable candidate now that this block is on
                ;; disk (may complete a fork whose bodies just filled in).
                (retry-best-reorg-candidate chain-state block-store utxo-set
                                            :fee-estimator fee-estimator
                                            :recent-rejects recent-rejects))))
        (return-from process-received-block nil))

      ;; Check if this is the next block we need
      (if (= height (1+ current-height))
          ;; activate-block handles three cases uniformly:
          ;;   (a) prev == current best tip → validate then connect.
          ;;   (b) prev is on a competing fork with strictly more
          ;;       chain-work than our tip → pre-reorg first, then
          ;;       validate + connect. This is the path the old
          ;;       validate-then-connect order couldn't reach because
          ;;       validation against the wrong-fork UTXO state
          ;;       short-circuited with MISSING-INPUT.
          ;;   (c) prev is on a weaker chain → store, don't activate.
          ;; Skip signature validation for blocks at or below the last
          ;; checkpoint or the assumevalid block (matches Bitcoin Core IBD;
          ;; everything except sig checks is still validated).
          ;; A witness-stripped block at tip+1 must NOT reach activate-block:
          ;; the case-3 (weaker-fork) path would persist it, and a stripped
          ;; block on disk fails every later reorg — the original testnet4
          ;; wedge. Drop it; a witness-complete copy arrives via the normal
          ;; download / compact-block path. (Mirrors the competing-fork guard
          ;; below and the out-of-order guard further down.)
          (if (bitcoin-lisp.validation:block-witness-stripped-p block)
              (progn
                (bitcoin-lisp:log-debug
                 "Tip+1 block ~D arrived witness-stripped; dropping (await complete copy)"
                 height)
                nil)
          (let ((current-time (bitcoin-lisp.serialization:get-unix-time))
                ;; Core's fScriptChecks is a PER-BLOCK predicate, not a height
                ;; comparison: the block must be an ancestor of the assumevalid
                ;; block (validation.cpp:2342-2380).
                (skip-scripts (bitcoin-lisp.validation:script-checks-skippable-p
                               chain-state
                               (bitcoin-lisp.serialization:block-header-hash
                                (bitcoin-lisp.serialization:bitcoin-block-header block))
                               height)))
            (multiple-value-bind (activated error missing-blocks)
                ;; Node lock per block connect (drain-block-queue then
                ;; re-takes it per drained block, so RPC threads interleave
                ;; between connects instead of stalling for a whole cascade).
                (with-node-lock
                  (bitcoin-lisp.validation:activate-block
                   block chain-state block-store utxo-set
                   :current-time current-time
                   :skip-scripts skip-scripts
                   :fee-estimator fee-estimator
                   :recent-rejects recent-rejects
                   :mempool mempool
                   :tx-index (%context-tx-index)))
              (cond
                (activated
                 (clear-block-failure hash)
                 (note-tip-advanced chain-state)
                 ;; Drain queued blocks whose parent is now connected
                 (drain-block-queue chain-state utxo-set block-store
                                    :fee-estimator fee-estimator
                                    :recent-rejects recent-rejects)
                 t)
                ;; :weaker-chain isn't an error — block stored, no
                ;; activation needed. But its chain may cross the tip's work
                ;; only ABOVE here later; record it as a reorg candidate so
                ;; the per-cycle retry can trigger the reorg once complete
                ;; (fixes the crossover-at-or-below-tip stall).
                ;; :corrupt-undo is our own disconnect-side undo fault, not the
                ;; incoming block's — route it like a refused reorg (note the
                ;; candidate + retry once the undo is re-derived) instead of
                ;; handle-validation-failure, which would blame the innocent
                ;; block and burn it through +max-block-revalidation-attempts+
                ;; pointless re-downloads.
                ((member error '(:weaker-chain :corrupt-undo))
                 (note-reorg-candidate entry chain-state)
                 (retry-best-reorg-candidate chain-state block-store utxo-set
                                             :fee-estimator fee-estimator
                                             :recent-rejects recent-rejects)
                 nil)
                ;; :reorg-refused — the new block sits on a stronger
                ;; fork but we don't have the intermediate fork blocks.
                ;; Re-queue the missing ones for download (with timeout
                ;; counters reset) and DON'T re-queue the incoming
                ;; block — otherwise we'd retry the same unprocessable
                ;; tip forever. Record the candidate + retry so the reorg
                ;; fires once the fork bodies are all in store, rather than
                ;; waiting for the next fresh tip announcement or fetch cycle.
                ((eq error :reorg-refused)
                 (queue-missing-fork-blocks missing-blocks)
                 (note-reorg-candidate entry chain-state)
                 (retry-best-reorg-candidate chain-state block-store utxo-set
                                             :fee-estimator fee-estimator
                                             :recent-rejects recent-rejects)
                 nil)
                ;; Stop request, not a verdict on this block: handle-validation-
                ;; failure would burn its re-download budget for a shutdown it had
                ;; nothing to do with. No immediate retry — the flag is still set.
                ((eq error :interrupted)
                 (note-reorg-candidate entry chain-state)
                 nil)
                (t
                 ;; handle-validation-failure logs (throttled by retry count) and
                 ;; manages re-request budget.
                 (handle-validation-failure block height error chain-state)
                 nil)))))

          ;; Out of order (h > tip+1). Bitcoin Core persists every ACCEPTED
          ;; block to disk immediately (AcceptBlock -> SaveBlockToDisk,
          ;; BLOCK_HAVE_DATA) and connects from disk; we do the same — the RAM
          ;; block-queue below is only the in-order fast path for
          ;; drain-block-queue. But we persist ONLY if the block passes Core's
          ;; AcceptBlock anti-DoS gate: it must be REQUESTED, or (unsolicited)
          ;; carry more work than our tip, sit within +min-blocks-to-keep+ of
          ;; it, and meet minimum chain work (validation.cpp:4367-4378).
          ;; Without this an attacker fills our disk with unsolicited
          ;; far-ahead min-difficulty fork bodies. Witness-stripped copies are
          ;; never persisted (a stripped block on disk fails every later reorg
          ;; — the original testnet4 wedge). Persisted blocks that miss the RAM
          ;; queue (cap, same-height fork collision) stay reachable through
          ;; disk-blocks-above-tip (drain's disk fallback), so they are never
          ;; re-requested and never stranded.
          (progn
            (bitcoin-lisp:log-debug "Block ~D received out of order (current: ~D)"
                                    height current-height)
            (let* ((stripped (bitcoin-lisp.validation:block-witness-stripped-p block))
                   (accept (and (not stripped)
                                (%out-of-order-block-acceptable-p
                                 entry current-height requested chain-state))))
              (cond
                ((not accept)
                 (bitcoin-lisp:log-debug
                  "Out-of-order block ~D not persisted (~:[unsolicited/low-work/too-far~;stripped~], tip ~D)"
                  height stripped current-height)
                 ;; Re-enter pending for a re-fetch when it is a block we still
                 ;; genuinely want but didn't persist this copy of:
                 ;;   - a stripped copy of a requested block (await complete), or
                 ;;   - a legit heavy-fork block (outweighs tip, meets minimum
                 ;;     chain work) that failed the gate only for being >288
                 ;;     above the tip while unsolicited (its `pending` backstop
                 ;;     was dropped after 5 timeouts under the persistent wedge
                 ;;     context; without this re-add it could bounce
                 ;;     request->timeout->late-deliver->drop indefinitely).
                 ;; The DoS gate on DISK persistence is preserved — this only
                 ;; re-arms a request intent, not a store.
                 (when *ibd-context*
                   (let ((tip-entry (bitcoin-lisp.storage:get-block-index-entry
                                     chain-state
                                     (bitcoin-lisp.storage:best-block-hash chain-state))))
                     (when (or (and stripped requested)
                               (and (not stripped)
                                    tip-entry
                                    (> (bitcoin-lisp.storage:block-index-entry-chain-work entry)
                                       (bitcoin-lisp.storage:block-index-entry-chain-work tip-entry))
                                    (>= (bitcoin-lisp.storage:block-index-entry-chain-work entry)
                                        (bitcoin-lisp:minimum-chain-work bitcoin-lisp:*network*))))
                       (setf (gethash hash (ibd-context-pending-blocks *ibd-context*))
                             height)))))
                (t
                 (with-node-lock
                   (bitcoin-lisp.storage:note-block-position
                    chain-state hash
                    (nth-value 1 (bitcoin-lisp.storage:store-block
                                  block-store block :height height))))
                 (when *ibd-context*
                   ;; A body just landed: any fork candidate that was parked
                   ;; waiting for THIS block can be tried again (Core drains
                   ;; m_blocks_unlinked on the same event).
                   (%rearm-unlinked-reorg-candidates hash chain-state)
                   (%record-disk-block-above-tip height hash)
                   (let ((queue (ibd-context-block-queue *ibd-context*)))
                     (cond
                       ((gethash height queue)
                        nil)  ; RAM slot taken (dup/fork sibling); disk copy recorded
                       ((or (>= (hash-table-count queue) +max-block-queue-size+)
                            (>= (ibd-context-block-queue-bytes *ibd-context*)
                                +max-block-queue-bytes+)
                            (> (- height current-height) +max-block-queue-size+))
                        nil)  ; skips RAM queue; disk copy + map entry carry it
                       (t
                        (setf (gethash height queue) (cons block wire-size))
                        (incf (ibd-context-block-queue-bytes *ibd-context*)
                              wire-size))))
                   ;; Deep-reorg trigger: a block above tip+1 never reaches
                   ;; activate-block via the height dispatch, so a fork whose
                   ;; work overtakes the tip only up here would otherwise never
                   ;; get its reorg attempted. Record it as a candidate and
                   ;; retry immediately (gated on fork bodies complete on disk;
                   ;; the fetch loop retries once per cycle as arrivals fill
                   ;; the fork in whatever order the network delivers).
                   (note-reorg-candidate entry chain-state)
                   (retry-best-reorg-candidate chain-state block-store utxo-set
                                               :fee-estimator fee-estimator
                                               :recent-rejects recent-rejects)))))
            nil)))))

(defun %next-disk-block-for-drain (next-height chain-state block-store)
  "Drain's disk fallback: a persisted block at NEXT-HEIGHT whose parent is
the current tip, located via disk-blocks-above-tip (blocks that missed the
RAM queue through a cap-drop, a same-height fork collision, or a restart).
Consumes the map entry it returns; sweeps map keys below NEXT-HEIGHT (the
tip has passed them — their blocks remain on disk for any later reorg).
NIL when no persisted child of the tip exists at that height."
  (when *ibd-context*
    (let ((map (ibd-context-disk-blocks-above-tip *ibd-context*))
          (tip-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
      ;; Sweep stale heights. The map spans at most a download window of
      ;; heights, so the full maphash stays cheap.
      (let ((stale '()))
        (maphash (lambda (h hashes)
                   (declare (ignore hashes))
                   (when (< h next-height) (push h stale)))
                 map)
        (dolist (h stale) (remhash h map)))
      (dolist (bh (gethash next-height map))
        (let* ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state bh))
               (prev (and entry
                          (bitcoin-lisp.storage:block-index-entry-prev-entry entry))))
          (when (and prev
                     (equalp (bitcoin-lisp.storage:block-index-entry-hash prev)
                             tip-hash))
            (let ((blk (bitcoin-lisp.storage:get-block block-store bh)))
              (when blk
                (setf (gethash next-height map)
                      (remove bh (gethash next-height map) :test #'equalp))
                (unless (gethash next-height map)
                  (remhash next-height map))
                (return-from %next-disk-block-for-drain blk)))))))))

(defun drain-block-queue (chain-state utxo-set block-store &key fee-estimator recent-rejects)
  "Process queued blocks whose parents are now connected.
Repeats until no more queued blocks can be connected. Pulls from the RAM
block-queue first, then falls back to persisted out-of-order blocks
(disk-blocks-above-tip) so a RAM drop or restart never strands a block
the tip is ready to connect."
  (unless *ibd-context*
    (return-from drain-block-queue 0))
  (let ((drained 0)
        (skip-height (script-skip-height chain-state))
        (mempool (ibd-context-mempool *ibd-context*)))
    (loop
      ;; A full cascade can connect the whole queued window (~170 blocks
      ;; x ~0.1-2s validation) from one received block; poll the stop
      ;; flag per connect so shutdown isn't held for the entire run.
      ;; Stopping between connects is safe: activate-block updates UTXO
      ;; set + tip atomically and the shutdown flush persists the tip.
      (when *ibd-stop-requested*
        (return drained))
      (let* ((current-height (bitcoin-lisp.storage:current-height chain-state))
             (next-height (1+ current-height))
             (queue (ibd-context-block-queue *ibd-context*))
             (cell (gethash next-height queue))
             (block (car cell)))
        (if cell
            (progn
              (remhash next-height queue)
              (decf (ibd-context-block-queue-bytes *ibd-context*) (cdr cell)))
            ;; RAM miss — a persisted out-of-order block may still be ready
            ;; to connect (cap-dropped, fork collision at this height, or a
            ;; restart emptied the RAM queue while the bodies stayed on disk).
            (setf block (%next-disk-block-for-drain next-height chain-state
                                                    block-store)))
        (unless block
          (return drained))
        ;; Try to activate. activate-block dispatches to either direct
        ;; tip-extend, pre-reorg+activate, or store-only based on the
        ;; incoming block's parent vs. our current tip.
        (let* ((current-time (bitcoin-lisp.serialization:get-unix-time))
               (skip-scripts (bitcoin-lisp.validation:script-checks-skippable-p
                              chain-state
                              (bitcoin-lisp.serialization:block-header-hash
                               (bitcoin-lisp.serialization:bitcoin-block-header block))
                              next-height)))
          (multiple-value-bind (activated error missing-blocks)
              ;; Node lock per connect, released between loop iterations so
              ;; RPC threads aren't starved across a long drain cascade.
              (with-node-lock
                (bitcoin-lisp.validation:activate-block
                 block chain-state block-store utxo-set
                 :current-time current-time
                 :skip-scripts skip-scripts
                 :fee-estimator fee-estimator
                 :recent-rejects recent-rejects
                 :mempool mempool
                 :tx-index (%context-tx-index)))
            (cond
              (activated
               (note-tip-advanced chain-state)
               (incf drained)
               (bitcoin-lisp:log-debug "Drained queued block at height ~D" next-height))
              ((eq error :weaker-chain)
               ;; Stored but not active — nothing to drain further on
               ;; this height. Continue trying queued blocks.
               nil)
              ((eq error :reorg-refused)
               ;; Re-queue missing fork blocks; don't tight-loop on
               ;; this queued block.
               (queue-missing-fork-blocks missing-blocks)
               (return drained))
              ((eq error :interrupted)
               ;; Stop requested mid-reorg: stop draining, blame nothing. This
               ;; block was popped from the RAM queue but persisted, so
               ;; %next-disk-block-for-drain picks it up again after restart.
               (return drained))
              (t
               ;; handle-validation-failure logs (throttled) + manages the bounded
               ;; re-request budget. Stop draining after a failure.
               (handle-validation-failure block next-height error chain-state)
               (return drained)))))))))
