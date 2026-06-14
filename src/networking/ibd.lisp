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
in-flight, request-timeouts, block-disclaims). Keys are 32-byte SHA256d
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

(defun make-block-hash-table ()
  "An equalp hash-table for 32-byte block-hash keys, using the fast
block-hash-key-hash. Falls back to plain equalp off SBCL."
  (make-hash-table :test 'equalp #+sbcl :hash-function #+sbcl #'block-hash-key-hash))

(defstruct ibd-context
  "Context for managing Initial Block Download."
  (state :idle :type keyword)
  (header-sync-peer nil)
  (target-height 0 :type (unsigned-byte 32))
  (headers-received 0 :type (unsigned-byte 32))
  (blocks-received 0 :type (unsigned-byte 32))
  ;; Header tip (separate from validated block tip in chain-state)
  (header-tip-height 0 :type (unsigned-byte 32))
  ;; Download queue
  (pending-blocks (make-block-hash-table) :type hash-table)  ; hash -> height
  (in-flight (make-block-hash-table) :type hash-table)       ; hash -> (peer . timestamp)
  (block-queue (make-hash-table :test 'eql) :type hash-table)  ; height -> (block . wire-bytes), out-of-order
  (block-queue-bytes 0 :type integer)  ; sum of queued wire-bytes (see +max-block-queue-bytes+)
  ;; Exponential moving average of received block wire sizes. Seeds at 1MB
  ;; (safe both ways: modern blocks ~1-2MB; early-chain blocks correct it
  ;; downward within seconds). Drives the byte-aware request window in
  ;; get-next-blocks-to-request.
  (avg-block-wire-bytes (* 1024 1024) :type integer)
  ;; Per-pending-hash timeout count. retry-timed-out-requests bumps the
  ;; counter each time a request for this hash times out; after
  ;; +max-block-request-timeouts+, the block is dropped from pending
  ;; (it's likely a competing-fork block that peers won't serve).
  ;; hash -> integer.
  (request-timeouts (make-block-hash-table) :type hash-table)
  ;; Peers that answered `notfound` for a pending block. hash -> list of
  ;; peers. The scheduler won't re-request a block from a peer that has
  ;; disclaimed it, and drops the block once every ready peer has. Scoped
  ;; to the block's pending lifecycle: cleared when the block is received,
  ;; re-queued (a fresh download attempt), or dropped — so a peer is never
  ;; permanently excluded from a block it may later receive.
  (block-disclaims (make-block-hash-table) :type hash-table)
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
  (mempool nil))

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

(defvar *ibd-stop-requested* nil
  "Set by stop-node (via request-ibd-stop) when the process is shutting
down. The IBD inner loops poll it so a TERM exits the sync thread within
seconds instead of running until the pending queue drains — both June
2026 mainnet deploys hung in run-ibd after \"Stopping node...\" and
needed a verified-safe SIGKILL.")

(defun request-ibd-stop ()
  "Ask the IBD loops to exit at the next check point."
  (setf *ibd-stop-requested* t))

(defun reset-ibd-stop ()
  "Clear a previous stop request (called at node start)."
  (setf *ibd-stop-requested* nil))

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

(defun peer-disclaimed-block-p (peer hash)
  "T if PEER has answered `notfound` for block HASH in the current
download attempt (see ibd-context-block-disclaims)."
  (and *ibd-context*
       (member peer (gethash hash (ibd-context-block-disclaims *ibd-context*))
               :test #'eq)
       t))

(defun drop-pending-block (hash)
  "Remove HASH from the pending queue and all per-hash bookkeeping
(timeout counters, notfound disclaims). Used both when a block has
timed out too many times and when every peer has disclaimed it."
  (when *ibd-context*
    (remhash hash (ibd-context-pending-blocks *ibd-context*))
    (remhash hash (ibd-context-request-timeouts *ibd-context*))
    (remhash hash (ibd-context-block-disclaims *ibd-context*))))

(defun note-block-not-available (peer hash)
  "Record that PEER answered `notfound` for block HASH and release the
block from in-flight (if this peer held it) so it can be re-requested
from a different peer immediately, rather than waiting out the full
request timeout. The scheduler skips disclaiming peers and drops the
block entirely once all peers have disclaimed it. Mirrors Bitcoin
Core's MSG NOTFOUND handling, which clears the peer's block request."
  (when *ibd-context*
    (pushnew peer (gethash hash (ibd-context-block-disclaims *ibd-context*))
             :test #'eq)
    (let* ((in-flight (ibd-context-in-flight *ibd-context*))
           (entry (gethash hash in-flight)))
      (when (and entry (eq (car entry) peer))
        (remhash hash in-flight)))))

(defun queue-missing-fork-blocks (missing-blocks)
  "MISSING-BLOCKS is a list of (hash . height) cons cells, returned by
perform-reorg when it refused due to blocks missing from the store.
Add each to the pending queue and reset its timeout counter so the
existing download scheduler asks peers for them again. Without this,
perform-reorg refuses on the same missing block forever — the
deferred-reorg loop bug (project_per_peer_block_tracking.md)."
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
          ;; Reset timeout counter and notfound disclaims so this is a
          ;; fresh download attempt — peers that disclaimed it on a prior
          ;; attempt may have received it since.
          (remhash hash timeouts)
          (remhash hash (ibd-context-block-disclaims *ibd-context*))
          (incf queued))))
    (when (plusp queued)
      (bitcoin-lisp:log-warn "Re-queued ~D missing fork blocks for download"
                             queued))
    queued))

(defun handle-validation-failure (block height error chain-state)
  "Handle a block-validation failure during IBD.

Re-adds the block hash to pending-blocks so it can be re-requested from
a different peer (the failure may be peer-side data corruption rather
than a real consensus violation). The stuck-tip detector in the main IBD
loop is the backstop if the same block keeps failing.

Bitcoin Core punishes the source peer in MaybePunishNodeForBlock
(net_processing.cpp:1908-1951) on BLOCK_CONSENSUS / BLOCK_MUTATED but
does not re-request — Core trusts its own validator. Our validator is
less battle-tested, so we re-request once-or-twice before halting."
  (declare (ignore error))
  (when *ibd-context*
    (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
           (hash (bitcoin-lisp.serialization:block-header-hash header))
           (pending (ibd-context-pending-blocks *ibd-context*))
           (in-flight (ibd-context-in-flight *ibd-context*)))
      ;; Drop any stale in-flight entry for this hash so it can be retried.
      (remhash hash in-flight)
      ;; Re-add to pending if not already there.
      (unless (gethash hash pending)
        (setf (gethash hash pending) height)))))

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

(defun validate-checkpoint (hash height)
  "Validate that HASH at HEIGHT matches any applicable checkpoint.
Returns T if valid or no checkpoint at that height, NIL if checkpoint mismatch."
  (let ((checkpoint-hash (get-checkpoint-hash height)))
    (or (null checkpoint-hash)
        (equalp hash checkpoint-hash))))

;;;; Header Chain Validation

(defun validate-header-pow (header)
  "Validate proof-of-work for a header.
Returns T if hash is below target, NIL otherwise."
  (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
         (bits (bitcoin-lisp.serialization:block-header-bits header))
         (target (bitcoin-lisp.storage:bits-to-target bits)))
    ;; Convert hash to integer (little-endian)
    (let ((hash-value 0))
      (loop for i from 31 downto 0
            do (setf hash-value (logior (ash hash-value 8) (aref hash i))))
      (<= hash-value target))))

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
                        "Invalid proof-of-work")))

            ;; Validate timestamp > median-time-past
            (let ((mtp (bitcoin-lisp.validation:compute-median-time-past
                        chain-state header-prev-hash)))
              (when (<= (bitcoin-lisp.serialization:block-header-timestamp header) mtp)
                (return-from validate-header-chain
                  (values (nreverse valid-headers)
                          "Timestamp at or before median-time-past"))))

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
                ;; Anti-DoS: when already synced past the floor, drop headers
                ;; whose chain is still below it (a fresh low-work fork an
                ;; attacker is trying to plant). Legitimate near-tip forks have
                ;; chain-work far above the floor and are unaffected.
                (unless (and past-min-work (< new-work min-work))
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
                      (setf best-header-height new-height))))))))))
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

(defun get-next-blocks-to-request (n &optional tip-height)
  "Get up to N block hashes to request, sorted by height.

When TIP-HEIGHT is supplied, filters out blocks more than
+max-block-queue-size+ ahead of it — Bitcoin Core's BLOCK_DOWNLOAD_WINDOW
(net_processing.cpp:146). Without this filter, peers serve blocks far
ahead of tip that we then drop in the receive path AND lose from pending
(mark-block-received already removed them), producing the failure mode
observed at h=1027 on May 7 where 53k blocks were dropped and the gap
above the tip became permanent.

If TIP-HEIGHT is NIL, the height filter is skipped (used by unit tests
that don't construct a chain-state)."
  (unless *ibd-context*
    (return-from get-next-blocks-to-request nil))

  (let* (;; Byte-aware window: never request further ahead than the
         ;; byte-capped queue can hold. With 2024-era ~1.5MB blocks the
         ;; 256MB cap fits ~170 blocks, far below the 1024 count window —
         ;; requesting the full count window stuffed peers' send queues
         ;; with far-ahead blocks that were dropped at the cap on arrival,
         ;; serializing the tip on multi-minute deliveries (observed live
         ;; at h~851.7k post-restart: p50 latency 178s, ~1 block/min).
         ;; Floor of 32 keeps the pipeline parallel even for huge blocks.
         (window (min +max-block-queue-size+
                      (max 32 (floor +max-block-queue-bytes+
                                     (max 1 (ibd-context-avg-block-wire-bytes
                                             *ibd-context*))))))
         (max-request-height (when tip-height (+ tip-height window)))
         (pending (ibd-context-pending-blocks *ibd-context*))
         (in-flight (ibd-context-in-flight *ibd-context*))
         (available '()))
    ;; Collect blocks that are within the window AND not in-flight. Check
    ;; the cheap height filter FIRST: during early IBD pending holds the
    ;; whole chain (130k+ entries), almost all far ABOVE the window, so
    ;; testing the window before the (equalp) in-flight gethash skips the
    ;; hash for the vast majority. Profile (fresh testnet4 IBD h~5k-22k)
    ;; showed the old order — gethash on every pending block per cycle — at
    ;; ~35% of CPU (data-vector-hash on the 32-byte key).
    (maphash (lambda (hash height)
               (when (and (or (null max-request-height)
                              (<= height max-request-height))
                          (not (gethash hash in-flight)))
                 (push (cons hash height) available)))
             pending)
    ;; Sort by height and take first N
    (let ((sorted (sort available #'< :key #'cdr)))
      (mapcar #'car (subseq sorted 0 (min n (length sorted)))))))

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
    ;; Clear the per-hash timeout counter and any notfound disclaims so a
    ;; future re-request of this hash (e.g. on a reorg) starts fresh.
    (remhash hash (ibd-context-request-timeouts *ibd-context*))
    (remhash hash (ibd-context-block-disclaims *ibd-context*))))

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
:ready (disconnected). The block stays in PENDING, so the next
get-next-blocks-to-request reassigns it to a live peer this same cycle
rather than waiting out the ~125s per-hash request timeout. Returns the
number released.

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

(defun find-peer-blocking-progress (next-height chain-state)
  "Return the peer that holds the in-flight request for NEXT-HEIGHT, if any.
   This is the one peer whose delivery would unblock chain progress; Bitcoin
   Core's stalling-peer detection focuses solely on this peer."
  (declare (ignore chain-state))
  (when *ibd-context*
    (let ((found nil))
      (maphash (lambda (hash peer-time)
                 (declare (ignore hash))
                 (let* ((entry-height (gethash hash
                                               (ibd-context-pending-blocks *ibd-context*))))
                   (when (and entry-height (= entry-height next-height))
                     (setf found (car peer-time)))))
               (ibd-context-in-flight *ibd-context*))
      found)))

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

(defun select-peer-for-block (hash height ready-peers peer-counts bk-heights max-per-peer)
  "Pick the best ready peer to request block HASH (at HEIGHT) from, and
count how many ready peers have disclaimed it. Returns (values peer
disclaimed-count). Candidate preference mirrors Bitcoin Core's
FindNextBlocksToDownload, which only asks peers whose best-known chain
reaches the block:
  tier 1 — peer's best-known height >= HEIGHT,
  tier 2 — peer with no availability info yet (worth trying),
  tier 3 — peer whose info says too-short (our info may be stale, so a
           fallback rather than a hard exclusion).
Within a tier, the peer with the fewest in-flight requests wins (load
balancing; READY-PEERS is latency-sorted so ties favor the faster peer).
Peers that answered `notfound` are always skipped and counted instead.
PEER-COUNTS and BK-HEIGHTS are precomputed once per call by the caller."
  (let ((disclaimed 0)
        (best nil)
        (best-tier most-positive-fixnum)
        (best-count 0))
    (dolist (peer ready-peers)
      (let ((count (gethash peer peer-counts 0)))
        (cond
          ((peer-disclaimed-block-p peer hash)
           (incf disclaimed))
          ((>= count max-per-peer)
           nil)  ; at per-peer limit this cycle
          (t
           (let* ((bk-height (gethash peer bk-heights))
                  (tier (cond ((null bk-height) 2)
                              ((and height (>= bk-height height)) 1)
                              (t 3))))
             (when (or (null best)
                       (< tier best-tier)
                       (and (= tier best-tier) (< count best-count)))
               (setf best-tier tier best-count count best peer)))))))
    (values best disclaimed)))

(defun request-blocks-from-peers (peers chain-state)
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
         ;; Calculate total budget across all peers. When the queue is at cap
         ;; and we're only allowed to request the gap block, clamp to 1.
         (raw-budget (loop for peer in ready-peers
                           sum (max 0 (- max-per-peer (count-peer-in-flight peer)))))
         (total-budget (if *ibd-gap-only-mode* (min 1 raw-budget) raw-budget)))

    ;; Reset for next caller; the gate already gave us the budget we need.
    (setf *ibd-gap-only-mode* nil)

    (when (or (null ready-peers) (zerop total-budget))
      (return-from request-blocks-from-peers 0))

    ;; Get blocks to request (up to total budget, filtered to within the
    ;; download window of current tip).
    (let ((to-request (get-next-blocks-to-request
                       total-budget
                       (bitcoin-lisp.storage:current-height chain-state))))
      (when (null to-request)
        (return-from request-blocks-from-peers 0))

      ;; Distribute requests across peers, respecting per-peer limits.
      ;; peer-counts (in-flight per peer) and bk-heights (each peer's
      ;; best-known block height) are computed once per call here and read
      ;; by select-peer-for-block, rather than re-derived per (block,peer).
      (let ((requests-made 0)
            (peer-requests (make-hash-table :test 'eq))
            (peer-counts (make-hash-table :test 'eq))
            (bk-heights (make-hash-table :test 'eq))
            (pending (ibd-context-pending-blocks *ibd-context*))
            (num-ready (length ready-peers)))
        (dolist (peer ready-peers)
          (setf (gethash peer peer-counts) (count-peer-in-flight peer))
          (setf (gethash peer bk-heights) (peer-best-known-height peer chain-state)))

        (dolist (hash to-request)
          (multiple-value-bind (best disclaimed)
              (select-peer-for-block hash (gethash hash pending)
                                     ready-peers peer-counts bk-heights max-per-peer)
            (cond
              (best
               (mark-block-in-flight hash best)
               (push hash (gethash best peer-requests))
               (setf (gethash best peer-counts) (1+ (gethash best peer-counts 0)))
               (incf requests-made))
              ;; No peer can serve it and every ready peer has disclaimed
              ;; it (a stale fork) — drop it so IBD stops retrying forever
              ;; instead of completing the reorg.
              ((and (plusp num-ready) (>= disclaimed num-ready))
               (drop-pending-block hash)
               (bitcoin-lisp:log-warn
                "Dropping block ~A — all ~D peers report notfound (stale fork)"
                (bitcoin-lisp.crypto:bytes-to-hex hash) num-ready)))))

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

        requests-made))))

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
       (mark-block-received hash)
       (record-block-received-from-peer peer)
       (process-received-block block chain-state utxo-set block-store
                               :fee-estimator fee-estimator
                               :recent-rejects recent-rejects
                               :wire-size (length payload))))

    ((string= command "headers")
     (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
       (process-headers headers chain-state)
       (incf (ibd-context-headers-received ctx) (length headers))
       ;; Per-peer availability: peer's tip is the last header in the batch.
       (let ((last (car (last headers))))
         (when last
           (update-block-availability
            peer chain-state
            (bitcoin-lisp.serialization:block-header-hash last))))))

    (t (handle-message peer command payload
                       chain-state utxo-set block-store
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
  (when (and (eq (peer-state peer) :ready)
             ;; A prior in-loop disconnect (rate-limit, oversized payload)
             ;; NILs peer-connection; guard so connection-socket below
             ;; doesn't raise TYPE-ERROR (which the handler-case below does
             ;; not catch) and kill the sync thread.
             (peer-connection peer)
             ;; Only drain a connection still believed live. If a previous
             ;; read already flipped connection-connected to NIL (and may
             ;; have NILed the socket), skip straight to handle-peer-fin —
             ;; no point waiting for input on a dead/closed socket.
             (connection-connected (peer-connection peer)))
    (handler-case
        ;; Drain only as long as the socket actually has data ready
        ;; (usocket:wait-for-input :timeout 0 is non-blocking). This lets us
        ;; pull all queued messages in the batch without ever timing out
        ;; mid-payload, then exit immediately when nothing is left to read.
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
              while (and (peer-connection peer)
                         (data-available-p (peer-connection peer)))
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
                                               :recent-rejects recent-rejects))
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
        (handler-case (disconnect-peer peer) (error () nil)))))
  (handle-peer-fin peer))

(defun start-ibd (peers chain-state utxo-set block-store target-height
                   &key fee-estimator recent-rejects mempool)
  "Start Initial Block Download.
Returns the number of blocks downloaded."
  (setf *ibd-context* (make-ibd))
  (setf (ibd-context-target-height *ibd-context*) target-height)
  ;; Set adaptive timeout based on number of peers
  (setf (ibd-context-request-timeout *ibd-context*)
        (compute-block-download-timeout (length peers)))

  (unwind-protect
       (run-ibd peers chain-state utxo-set block-store
                :fee-estimator fee-estimator
                :recent-rejects recent-rejects
                :mempool mempool)
    (setf *ibd-context* nil)))

(defun run-ibd (peers chain-state utxo-set block-store
                &key fee-estimator recent-rejects mempool)
  "Main IBD loop."
  (let ((ctx *ibd-context*)
        (start-height (bitcoin-lisp.storage:current-height chain-state)))
    ;; Make the mempool reachable from the block-activation path (which reads
    ;; it off *ibd-context*) so confirmed txs are removed during IBD/tip advance.
    (when ctx
      (setf (ibd-context-mempool ctx) mempool))

    ;; Initialize header-tip-height from existing chain state
    ;; This ensures we know about existing headers even if header sync fails
    (let ((best-header-height 0))
      (maphash (lambda (hash entry)
                 (declare (ignore hash))
                 (when (> (bitcoin-lisp.storage:block-index-entry-height entry) best-header-height)
                   (setf best-header-height (bitcoin-lisp.storage:block-index-entry-height entry))))
               (bitcoin-lisp.storage::chain-state-block-index chain-state))
      (setf (ibd-context-header-tip-height ctx) best-header-height))

    ;; Phase 1: Download headers
    (set-ibd-state :syncing-headers)
    (sync-headers-with-failover peers chain-state ctx :recent-rejects recent-rejects)

    ;; Phase 2: Download and validate blocks
    (set-ibd-state :syncing-blocks)

    ;; Queue all blocks from current height to header tip
    (let ((header-tip (ibd-context-header-tip-height ctx)))
      ;; Reflect the real chain tip in the progress reporter — `target-height`
      ;; was previously set to the small `max-blocks` cap from sync-blockchain.
      (setf (ibd-context-target-height ctx) header-tip)
      (queue-blocks-for-download chain-state (1+ start-height) header-tip))

    ;; Initialize stuck-tip tracking — start the timer at IBD entry so the
    ;; first stall is detected even if no block ever connects.
    (setf (ibd-context-last-tip-advance-time ctx) (get-universal-time)
          (ibd-context-last-tip-height ctx) start-height)

    ;; Download blocks
    (let ((last-report-time (get-internal-real-time))
          (report-interval (* 10 internal-time-units-per-second))  ; Every 10 seconds
          (no-peer-cycles 0))

      ;; Loop until either (a) the pending queue is empty, or (b) we've
      ;; reached the header tip — in which case any remaining pending
      ;; entries are competing-fork blocks that don't move the active
      ;; chain forward. Without the header-tip exit, fork-block headers
      ;; auto-queued by process-headers can pin the loop forever (peers
      ;; don't typically serve side-chain blocks).
      (loop while (and (> (hash-table-count (ibd-context-pending-blocks ctx)) 0)
                       (< (bitcoin-lisp.storage:current-height chain-state)
                          (ibd-context-header-tip-height ctx)))
            do (progn
                 (when *ibd-stop-requested*
                   (return))

                 ;; Stuck-tip backstop: if connect-tip hasn't advanced for
                 ;; +stuck-tip-halt-seconds+ AND blocks are queued, halt
                 ;; cleanly instead of growing the queue until OOM.
                 (when (check-stuck-tip)
                   (return))

                 ;; Prune disconnected peers from the list
                 (setf peers (remove-if-not
                              (lambda (p) (eq (peer-state p) :ready))
                              peers))

                 ;; Handle no-peer condition: exit after a few seconds
                 ;; (caller is responsible for reconnecting and retrying)
                 (when (null peers)
                   (incf no-peer-cycles)
                   (when (> no-peer-cycles 5)
                     (bitcoin-lisp:log-warn "No peers available, pausing block download")
                     (return))
                   (sleep 1))

                 ;; Request more blocks if needed
                 (when peers
                   (setf no-peer-cycles 0)
                   (request-blocks-from-peers peers chain-state))

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
                     (request-blocks-from-peers peers chain-state)))

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
                     (setf last-report-time now))))))

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

(defun build-header-locator (chain-state)
  "Build a block locator starting from the highest header in the index.
Used during IBD when the validated block tip lags behind the header tip."
  (let ((best-entry nil)
        (best-height 0))
    ;; Find the highest header-valid entry
    (maphash (lambda (hash entry)
               (declare (ignore hash))
               (when (> (bitcoin-lisp.storage:block-index-entry-height entry) best-height)
                 (setf best-height (bitcoin-lisp.storage:block-index-entry-height entry))
                 (setf best-entry entry)))
             (bitcoin-lisp.storage::chain-state-block-index chain-state))
    (if best-entry
        ;; Walk back through prev-entry links
        (let ((locator '())
              (entry best-entry)
              (step 1)
              (count 0))
          (loop while entry
                do (push (bitcoin-lisp.storage:block-index-entry-hash entry) locator)
                   (incf count)
                   (when (> count 10)
                     (setf step (* step 2)))
                   (let ((moved nil))
                     (loop repeat step
                           while (bitcoin-lisp.storage:block-index-entry-prev-entry entry)
                           do (setf entry (bitcoin-lisp.storage:block-index-entry-prev-entry entry))
                              (setf moved t))
                     (unless moved
                       (return))))
          (nreverse locator))
        ;; No entries - use genesis
        (bitcoin-lisp.storage:build-block-locator chain-state))))

(defun request-headers-for-ibd (peer chain-state)
  "Request headers using a locator built from the header tip, not the validated block tip."
  (let ((locator (build-header-locator chain-state)))
    (bitcoin-lisp.networking:send-message
     peer
     (bitcoin-lisp.serialization:make-getheaders-message locator))))

(defun sync-headers (peer chain-state &key recent-rejects)
  "Download all headers from PEER. Returns (values received-count stalled-p);
STALLED-P is true when the peer went silent (a getheaders went unanswered),
the signal run-ibd uses to rotate to another header-sync peer."
  (let ((received-count 0)
        (done nil)
        (timed-out nil)
        (requests-sent 0)
        (max-requests 100))
    ;; First, drain any pending messages from peer (sendcmpct, sendheaders, etc.)
    (loop repeat 10
          do (multiple-value-bind (command payload)
                 (receive-message peer :timeout 1)
               (when command
                 (bitcoin-lisp:log-debug "Pre-sync: received ~A" command)
                 (handler-case
                     (handle-message peer command payload chain-state nil nil
                                     :recent-rejects recent-rejects)
                   (error () nil)))
               (unless command (return))))

    (loop until (or done *ibd-stop-requested*)
          do (progn
               ;; Request headers using header-tip-aware locator
               (request-headers-for-ibd peer chain-state)
               (incf requests-sent)
               (when (> requests-sent max-requests)
                 (bitcoin-lisp:log-warn "Header sync: hit max requests (~D)" max-requests)
                 (return))

               ;; Wait for headers response, handling other messages
               (let ((got-headers nil)
                     (attempts 0))
                 (loop while (and (not got-headers) (< attempts 30)
                                  (not *ibd-stop-requested*))
                       do (multiple-value-bind (command payload)
                              (receive-message peer :timeout 5)
                            (incf attempts)
                            (cond
                              ((null command)
                               (when (> attempts 10)
                                 (bitcoin-lisp:log-warn "Timeout waiting for headers")
                                 (setf done t)
                                 (setf got-headers t)
                                 (setf timed-out t)))

                              ((string= command "headers")
                               (setf got-headers t)
                               (handler-case
                                   (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
                                     (when (null headers)
                                       (setf done t))
                                     ;; Validate and add headers
                                     (multiple-value-bind (valid-headers error)
                                         (validate-header-chain headers chain-state)
                                       (when error
                                         (bitcoin-lisp:log-warn "Header validation error: ~A" error))

                                       (let ((added (process-headers valid-headers chain-state)))
                                         (incf received-count added)

                                         ;; A short batch (< the protocol max)
                                         ;; means the peer has no more headers.
                                         (when (< (length headers)
                                                  bitcoin-lisp.serialization:+max-headers-count+)
                                           (setf done t))

                                         ;; Per-peer availability: peer's tip is
                                         ;; the last header in this batch.
                                         (let ((last (car (last valid-headers))))
                                           (when last
                                             (update-block-availability
                                              peer chain-state
                                              (bitcoin-lisp.serialization:block-header-hash last))))

                                         (when (> added 0)
                                           (bitcoin-lisp:log-info "Received ~D headers, ~D new, total ~D"
                                                                  (length headers) added received-count)))))
                                 (error (e)
                                   (bitcoin-lisp:log-error "Error parsing headers: ~A" e)
                                   (setf done t))))

                              (t
                               ;; Handle other messages (ping, sendcmpct, etc.)
                               (bitcoin-lisp:log-debug "Header sync: received ~A" command)
                               (handler-case
                                   (handle-message peer command payload chain-state nil nil
                                                   :recent-rejects recent-rejects)
                                 (error () nil)))))))))

    (bitcoin-lisp:log-info "Header sync complete: ~D headers received" received-count)
    (values received-count timed-out)))

(defun sync-headers-with-failover (peers chain-state ctx
                                   &key recent-rejects (sync-fn #'sync-headers))
  "Run header sync against ready PEERS in descending start-height order,
rotating to the next peer whenever one STALLS (sync-fn's 2nd value true),
and stopping at the first that answers. Returns the peer that responded, or
NIL if every ready peer stalled / none were ready. SYNC-FN is injectable so
the rotation logic is testable without network I/O.

Fixes the single-peer header-sync freeze: run-ibd previously synced from one
peer chosen by start-height (frozen at handshake), with no failover — a quiet
or dead-fork peer was re-picked every cycle and pinned the tip for hours."
  (dolist (peer (sort (copy-list peers) #'> :key #'peer-start-height) nil)
    (when *ibd-stop-requested*
      (return nil))
    (when (eq (peer-state peer) :ready)
      (setf (ibd-context-header-sync-peer ctx) peer)
      (multiple-value-bind (count stalled)
          (funcall sync-fn peer chain-state :recent-rejects recent-rejects)
        (declare (ignore count))
        (unless stalled (return peer))))))

(defvar *forensic-store-from-height* nil
  "Debug: when set to an integer N, store every received block at
   height >= N to disk BEFORE validation, so failed-validation blocks
   are still available for analysis. Use to capture blocks our
   validator rejects so we can compare against Bitcoin Core.")

(defun process-received-block (block chain-state utxo-set block-store
                                &key fee-estimator recent-rejects
                                  (wire-size 0))
  "Process a received block - validate and connect to chain.
After connecting, drains the queue of any children that can now be connected."
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

      ;; Forensic capture: store the block to disk BEFORE validation if
      ;; *forensic-store-from-height* is set and we're at-or-above that
      ;; height. Lets us analyze blocks our validator rejects.
      (when (and *forensic-store-from-height*
                 (>= height *forensic-store-from-height*))
        (handler-case
            (bitcoin-lisp.storage:store-block block-store block)
          (error (e)
            (bitcoin-lisp:log-warn "Forensic store failed for block ~D: ~A"
                                   height e))))

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
        (bitcoin-lisp.storage:store-block block-store block)
        (multiple-value-bind (activated error)
            (bitcoin-lisp.validation:activate-block
             block chain-state block-store utxo-set
             :skip-scripts (<= height (last-checkpoint-height))
             :fee-estimator fee-estimator
             :recent-rejects recent-rejects
             :mempool mempool)
          (declare (ignore activated))
          ;; :weaker-chain is the expected outcome here; any other
          ;; error is worth logging at debug level for now.
          (unless (eq error :weaker-chain)
            (bitcoin-lisp:log-debug "Competing-fork block ~D activate result: ~A"
                                    height error))
          (return-from process-received-block nil)))

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
          ;; Skip script validation for blocks at or below the last
          ;; checkpoint (matches Bitcoin Core IBD behavior).
          (let ((current-time (bitcoin-lisp.serialization:get-unix-time))
                (skip-scripts (<= height (last-checkpoint-height))))
            (multiple-value-bind (activated error missing-blocks)
                (bitcoin-lisp.validation:activate-block
                 block chain-state block-store utxo-set
                 :current-time current-time
                 :skip-scripts skip-scripts
                 :fee-estimator fee-estimator
                 :recent-rejects recent-rejects
                 :mempool mempool)
              (cond
                (activated
                 (note-tip-advanced chain-state)
                 ;; Drain queued blocks whose parent is now connected
                 (drain-block-queue chain-state utxo-set block-store
                                    :fee-estimator fee-estimator
                                    :recent-rejects recent-rejects)
                 t)
                ;; :weaker-chain isn't an error — block stored, no
                ;; activation needed.
                ((eq error :weaker-chain)
                 nil)
                ;; :reorg-refused — the new block sits on a stronger
                ;; fork but we don't have the intermediate fork blocks.
                ;; Re-queue the missing ones for download (with timeout
                ;; counters reset) and DON'T re-queue the incoming
                ;; block — otherwise we'd retry the same unprocessable
                ;; tip forever. When the fork blocks finally arrive
                ;; through normal download, the next tip announcement
                ;; will trigger another reorg attempt, this time with
                ;; everything in store.
                ((eq error :reorg-refused)
                 (queue-missing-fork-blocks missing-blocks)
                 nil)
                (t
                 (bitcoin-lisp:log-error "Block ~D validation failed: ~A"
                                         height error)
                 (handle-validation-failure block height error chain-state)
                 nil))))

          ;; Out of order - queue for later, with a HARD receive-side cap.
          ;; Bitcoin Core only ever requests blocks within BLOCK_DOWNLOAD_WINDOW
          ;; of tip (net_processing.cpp:1437-1440); the request-side filter in
          ;; get-next-blocks-to-request enforces the same window for us.
          ;; Drops here are belt-and-suspenders for in-flight retries that
          ;; landed late; we re-add to pending so the block isn't lost from
          ;; our system (mark-block-received already removed it). Without
          ;; this re-add, dropped blocks become permanent gaps — observed
          ;; May 7 at h=1027 with 53k drops and a stuck tip.
          (progn
            (bitcoin-lisp:log-debug "Block ~D received out of order (current: ~D)"
                                    height current-height)
            (when *ibd-context*
              (let ((queue (ibd-context-block-queue *ibd-context*))
                    (pending (ibd-context-pending-blocks *ibd-context*)))
                (cond
                  ((gethash height queue)
                   nil)  ; duplicate
                  ((or (>= (hash-table-count queue) +max-block-queue-size+)
                       (>= (ibd-context-block-queue-bytes *ibd-context*)
                           +max-block-queue-bytes+))
                   (bitcoin-lisp:log-warn
                    "Dropping out-of-order block at height ~D: queue at cap (~D blocks, ~DMB, tip ~D); re-queuing for later"
                    height (hash-table-count queue)
                    (floor (ibd-context-block-queue-bytes *ibd-context*) 1048576)
                    current-height)
                   (setf (gethash hash pending) height))
                  ((> (- height current-height) +max-block-queue-size+)
                   (bitcoin-lisp:log-warn
                    "Dropping out-of-order block at height ~D: too far ahead of tip ~D; re-queuing for later"
                    height current-height)
                   (setf (gethash hash pending) height))
                  (t
                   (setf (gethash height queue) (cons block wire-size))
                   (incf (ibd-context-block-queue-bytes *ibd-context*)
                         wire-size)))))
            nil)))))

(defun drain-block-queue (chain-state utxo-set block-store &key fee-estimator recent-rejects)
  "Process queued blocks whose parents are now connected.
Repeats until no more queued blocks can be connected."
  (unless *ibd-context*
    (return-from drain-block-queue 0))
  (let ((drained 0)
        (checkpoint-height (last-checkpoint-height))
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
        (unless block
          (return drained))
        (remhash next-height queue)
        (decf (ibd-context-block-queue-bytes *ibd-context*) (cdr cell))
        ;; Try to activate. activate-block dispatches to either direct
        ;; tip-extend, pre-reorg+activate, or store-only based on the
        ;; incoming block's parent vs. our current tip.
        (let* ((current-time (bitcoin-lisp.serialization:get-unix-time))
               (skip-scripts (<= next-height checkpoint-height)))
          (multiple-value-bind (activated error missing-blocks)
              (bitcoin-lisp.validation:activate-block
               block chain-state block-store utxo-set
               :current-time current-time
               :skip-scripts skip-scripts
               :fee-estimator fee-estimator
               :recent-rejects recent-rejects
               :mempool mempool)
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
              (t
               (bitcoin-lisp:log-error "Queued block ~D validation failed: ~A"
                                       next-height error)
               (handle-validation-failure block next-height error chain-state)
               ;; Stop draining after a failure — the block is now back in
               ;; pending and will be re-requested. Returning here also
               ;; prevents tight-looping on a permanently-failing block.
               (return drained)))))))))
