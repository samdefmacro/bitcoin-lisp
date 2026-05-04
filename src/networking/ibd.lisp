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
  "Seconds the next-needed block can be in-flight at one peer before we
   conclude THAT peer is the bottleneck and disconnect it. Bitcoin Core
   uses 2s here; we use 30s because testnet4 stress blocks can be
   multi-MB and take seconds just to transit the wire.")

(defparameter +max-messages-per-peer-per-cycle+ 32
  "How many messages to drain from each peer in one IBD loop iteration.
   Reading just one used to let kernel TCP buffers fill (multi-MB) whenever
   validation took a few seconds, then the stalling-peer check would evict
   peers for OUR slowness. Drain in batches to keep buffers shallow.")

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
  (pending-blocks (make-hash-table :test 'equalp) :type hash-table)  ; hash -> height
  (in-flight (make-hash-table :test 'equalp) :type hash-table)       ; hash -> (peer . timestamp)
  (block-queue (make-hash-table :test 'eql) :type hash-table)  ; height -> block, out-of-order
  ;; Configuration
  (max-in-flight 16 :type (unsigned-byte 8))
  (request-timeout 60 :type (unsigned-byte 16))  ; seconds
  ;; Progress tracking
  (start-time 0 :type integer)
  (last-progress-time 0 :type integer)
  ;; Wall-clock seconds (get-universal-time) at the last connect-tip advance.
  ;; Used by the stuck-tip detector to halt IBD when validation can't drain
  ;; the queue (vs Core's TipMayBeStale, net_processing.cpp:1332-1340).
  (last-tip-advance-time 0 :type integer)
  (last-tip-height 0 :type (unsigned-byte 32)))

(defvar *ibd-context* nil
  "Current IBD context.")

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
+stuck-tip-halt-seconds+. Returns T if we should halt.

This is the backstop that prevents the failure mode observed at testnet4
height 70700 (May 2 16:32 crash): a permanently-failing connect-tip
block, no advance for 1h 40m, queue grew unbounded until heap exhaustion.
With this check, we halt cleanly instead of OOM-ing."
  (when *ibd-context*
    (let* ((last-time (ibd-context-last-tip-advance-time *ibd-context*))
           (queue-size (hash-table-count
                        (ibd-context-block-queue *ibd-context*))))
      (when (and (plusp last-time)
                 (plusp queue-size)
                 (> (- (get-universal-time) last-time)
                    +stuck-tip-halt-seconds+))
        (bitcoin-lisp:log-error
         "STUCK TIP: connect-tip has not advanced in ~D seconds; ~D blocks queued. Halting IBD to avoid OOM. Investigate validator."
         (- (get-universal-time) last-time) queue-size)
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
Returns the number of new headers added."
  (let ((added 0)
        (best-header-height (if *ibd-context*
                                (ibd-context-header-tip-height *ibd-context*)
                                0)))
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
                     (entry (bitcoin-lisp.storage:make-block-index-entry
                             :hash hash
                             :height new-height
                             :header header
                             :prev-entry prev-entry
                             :chain-work (bitcoin-lisp.storage:calculate-chain-work
                                          bits prev-work)
                             :status :header-valid)))
                (bitcoin-lisp.storage:add-block-index-entry chain-state entry)
                (incf added)
                ;; Track header tip height in IBD context
                (when (> new-height best-header-height)
                  (setf best-header-height new-height))))))))
    ;; Update header tip in IBD context (not the chain-state best-height)
    (when *ibd-context*
      (setf (ibd-context-header-tip-height *ibd-context*) best-header-height))
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

(defun get-next-blocks-to-request (n)
  "Get up to N block hashes to request, sorted by height."
  (unless *ibd-context*
    (return-from get-next-blocks-to-request nil))

  (let ((pending (ibd-context-pending-blocks *ibd-context*))
        (in-flight (ibd-context-in-flight *ibd-context*))
        (available '()))
    ;; Collect blocks that are pending but not in-flight
    (maphash (lambda (hash height)
               (unless (gethash hash in-flight)
                 (push (cons hash height) available)))
             pending)
    ;; Sort by height and take first N
    (let ((sorted (sort available #'< :key #'cdr)))
      (mapcar #'car (subseq sorted 0 (min n (length sorted)))))))

(defun mark-block-in-flight (hash peer)
  "Mark a block as being requested from PEER."
  (when *ibd-context*
    (setf (gethash hash (ibd-context-in-flight *ibd-context*))
          (cons peer (get-internal-real-time)))))

(defun mark-block-received (hash)
  "Mark a block as received, removing it from pending and in-flight."
  (when *ibd-context*
    (when (gethash hash (ibd-context-pending-blocks *ibd-context*))
      (remhash hash (ibd-context-pending-blocks *ibd-context*))
      (incf (ibd-context-blocks-received *ibd-context*)))
    (remhash hash (ibd-context-in-flight *ibd-context*))))

(defun compute-block-download-timeout (num-downloading-peers)
  "Compute block download timeout in seconds based on number of peers.
Matches Bitcoin Core's actual constants from net_processing.cpp:
  BLOCK_DOWNLOAD_TIMEOUT_BASE = 30 s
  BLOCK_DOWNLOAD_TIMEOUT_PER_PEER = 5 s
  timeout = base + per_peer * other_peers
With 8 peers ≈ 65s. The previous formula used a 600s block_interval scale,
giving 2700s — far too long, so timed-out in-flight blocks would never retry
and IBD would stall whenever a peer dropped a request."
  (let* ((base 30)
         (per-peer 5)
         (other-peers (max 0 (1- num-downloading-peers))))
    (+ base (* per-peer other-peers))))

(defun get-timed-out-requests ()
  "Get list of block hashes that have timed out."
  (unless *ibd-context*
    (return-from get-timed-out-requests nil))

  (let ((in-flight (ibd-context-in-flight *ibd-context*))
        (timeout-ticks (* (ibd-context-request-timeout *ibd-context*)
                          internal-time-units-per-second))
        (now (get-internal-real-time))
        (timed-out '()))
    (maphash (lambda (hash peer-time)
               (when (> (- now (cdr peer-time)) timeout-ticks)
                 (push hash timed-out)))
             in-flight)
    timed-out))

(defun retry-timed-out-requests (&optional peers)
  "Remove timed out requests from in-flight so they can be retried.
When PEERS is provided, tracks per-peer timeouts and disconnects slow peers."
  (let ((timed-out (get-timed-out-requests))
        (peers-to-disconnect '()))
    (dolist (hash timed-out)
      (let* ((peer-time (gethash hash (ibd-context-in-flight *ibd-context*)))
             (peer (car peer-time)))
        ;; Track timeout for this peer
        (when (and peer peers)
          (when (record-block-timeout peer)
            (pushnew peer peers-to-disconnect)))
        ;; Remove from in-flight so it can be retried from a different peer
        (remhash hash (ibd-context-in-flight *ibd-context*))))
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

(defun request-blocks-from-peers (peers chain-state)
  "Request blocks from multiple peers, distributing the load.
Enforces per-peer in-flight limits (like Bitcoin Core's
MAX_BLOCKS_IN_TRANSIT_PER_PEER) rather than a single global limit.

Applies backpressure: when the out-of-order block-queue is at capacity,
new requests are paused so peers do not deliver blocks we'd just drop +
re-request, which causes duplicate-delivery thrash and wasted bandwidth."
  (unless (and *ibd-context* peers)
    (return-from request-blocks-from-peers 0))

  ;; Always retry timed-out requests first — even under backpressure. Otherwise
  ;; in-flight requests that timed out (peer dropped, request lost) stay stuck
  ;; forever once the queue fills, including the very block we need to advance.
  (let ((retried (retry-timed-out-requests peers)))
    (when (> retried 0)
      (bitcoin-lisp:log-warn "Retrying ~D timed out block requests" retried)))

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

    ;; Get blocks to request (up to total budget)
    (let ((to-request (get-next-blocks-to-request total-budget)))
      (when (null to-request)
        (return-from request-blocks-from-peers 0))

      ;; Distribute requests across peers, respecting per-peer limits
      (let ((requests-made 0)
            (peer-requests (make-hash-table :test 'eq))
            (peer-counts (make-hash-table :test 'eq)))
        ;; Initialize per-peer counts
        (dolist (peer ready-peers)
          (setf (gethash peer peer-counts) (count-peer-in-flight peer)))

        ;; Assign blocks round-robin, skipping peers at their limit
        (let ((peer-index 0)
              (num-peers (length ready-peers)))
          (dolist (hash to-request)
            ;; Find next peer with budget
            (let ((found nil))
              (dotimes (attempts num-peers)
                (let* ((peer (nth (mod (+ peer-index attempts) num-peers) ready-peers))
                       (current (gethash peer peer-counts 0)))
                  (when (< current max-per-peer)
                    (mark-block-in-flight hash peer)
                    (push hash (gethash peer peer-requests))
                    (setf (gethash peer peer-counts) (1+ current))
                    (setf peer-index (1+ (mod (+ peer-index attempts) num-peers)))
                    (incf requests-made)
                    (setf found t)
                    (return))))
              (unless found (return)))))

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
         (elapsed-secs (/ (- (get-internal-real-time) (ibd-context-start-time ctx))
                          internal-time-units-per-second))
         (received (ibd-context-blocks-received ctx))
         (target (ibd-context-target-height ctx))
         (current-height (if chain-state
                             (bitcoin-lisp.storage:current-height chain-state)
                             received))
         (pending (hash-table-count (ibd-context-pending-blocks ctx)))
         (in-flight (hash-table-count (ibd-context-in-flight ctx))))
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
          :progress-percent (if (> target 0)
                                (* 100.0 (/ current-height target))
                                0))))

(defun report-ibd-progress (&optional chain-state)
  "Log current IBD progress."
  (let ((progress (ibd-progress chain-state)))
    (when progress
      (bitcoin-lisp:log-info "IBD Progress: ~D/~D blocks (~,1F%), ~,1F blocks/sec, ~D pending, ~D in-flight"
                             (getf progress :current-height)
                             (getf progress :target-height)
                             (getf progress :progress-percent)
                             (getf progress :blocks-per-second)
                             (getf progress :pending-blocks)
                             (getf progress :in-flight-blocks)))))

;;;; Main IBD Loop

(defun start-ibd (peers chain-state utxo-set block-store target-height
                   &key fee-estimator recent-rejects)
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
                :recent-rejects recent-rejects)
    (setf *ibd-context* nil)))

(defun run-ibd (peers chain-state utxo-set block-store &key fee-estimator recent-rejects)
  "Main IBD loop."
  (let ((ctx *ibd-context*)
        (start-height (bitcoin-lisp.storage:current-height chain-state)))

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
    (let ((best-peer (first (sort (copy-list peers) #'>
                                  :key #'peer-start-height))))
      (when best-peer
        (setf (ibd-context-header-sync-peer ctx) best-peer)
        (sync-headers best-peer chain-state :recent-rejects recent-rejects)))

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

      (loop while (> (hash-table-count (ibd-context-pending-blocks ctx)) 0)
            do (progn
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
                   (when (eq (peer-state peer) :ready)
                     ;; Drain only as long as the socket actually has data ready
                     ;; (usocket:wait-for-input :timeout 0 is non-blocking). This
                     ;; lets us pull all queued messages in the batch without
                     ;; ever timing out mid-payload, then exit immediately when
                     ;; nothing is left to read.
                     (loop repeat +max-messages-per-peer-per-cycle+
                           while (usocket:wait-for-input
                                  (bitcoin-lisp.networking::connection-socket
                                   (peer-connection peer))
                                  :timeout 0 :ready-only t)
                           for (command payload) = (multiple-value-list
                                                     (receive-message peer :timeout 5))
                           while command
                           do (cond
                                ((string= command "block")
                                 (let* ((block (bitcoin-lisp.serialization:parse-block-payload payload))
                                        (header (bitcoin-lisp.serialization:bitcoin-block-header block))
                                        (hash (bitcoin-lisp.serialization:block-header-hash header)))
                                   (mark-block-received hash)
                                   (record-block-received-from-peer peer)
                                   (process-received-block block chain-state utxo-set block-store
                                                           :fee-estimator fee-estimator
                                                           :recent-rejects recent-rejects)))

                                ((string= command "headers")
                                 (let ((headers (bitcoin-lisp.serialization:parse-headers-payload payload)))
                                   (process-headers headers chain-state)
                                   (incf (ibd-context-headers-received ctx) (length headers))))

                                (t (handle-message peer command payload
                                                   chain-state utxo-set block-store
                                                   :fee-estimator fee-estimator
                                                   :recent-rejects recent-rejects))))))

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

    ;; Done — but distinguish "actually finished" from "paused due to no peers".
    ;; If pending is empty AND nothing in-flight, we drained the queue. Otherwise
    ;; we paused; the caller (sync-blockchain) will reconnect and resume.
    (let ((pending (hash-table-count (ibd-context-pending-blocks ctx)))
          (in-flight (hash-table-count (ibd-context-in-flight ctx))))
      (if (and (zerop pending) (zerop in-flight))
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
  "Download all headers from a peer."
  (let ((received-count 0)
        (done nil)
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

    (loop until done
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
                 (loop while (and (not got-headers) (< attempts 30))
                       do (multiple-value-bind (command payload)
                              (receive-message peer :timeout 5)
                            (incf attempts)
                            (cond
                              ((null command)
                               (when (> attempts 10)
                                 (bitcoin-lisp:log-warn "Timeout waiting for headers")
                                 (setf done t)
                                 (setf got-headers t)))

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

                                         ;; If we got less than 2000, we're done
                                         (when (< (length headers) 2000)
                                           (setf done t))

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
    received-count))

(defun process-received-block (block chain-state utxo-set block-store
                                &key fee-estimator recent-rejects)
  "Process a received block - validate and connect to chain.
After connecting, drains the queue of any children that can now be connected."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (hash (bitcoin-lisp.serialization:block-header-hash header))
         (entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))

    (unless entry
      (bitcoin-lisp:log-warn "Received unknown block ~A"
                             (bitcoin-lisp.crypto:bytes-to-hex hash))
      (return-from process-received-block nil))

    (let ((height (bitcoin-lisp.storage:block-index-entry-height entry))
          (current-height (bitcoin-lisp.storage:current-height chain-state)))

      ;; Skip blocks already connected (duplicates from multiple peers)
      (when (<= height current-height)
        (return-from process-received-block nil))

      ;; Check if this is the next block we need
      (if (= height (1+ current-height))
          ;; Validate and connect
          ;; Skip script validation for blocks at or below the last checkpoint
          ;; (matches Bitcoin Core behavior during IBD)
          (let ((current-time (bitcoin-lisp.serialization:get-unix-time))
                (skip-scripts (<= height (last-checkpoint-height))))
            (multiple-value-bind (valid error)
                (bitcoin-lisp.validation:validate-block
                 block chain-state utxo-set height current-time
                 :skip-scripts skip-scripts)
              (if valid
                  (progn
                    (bitcoin-lisp.validation:connect-block
                     block chain-state block-store utxo-set
                     :fee-estimator fee-estimator
                     :recent-rejects recent-rejects)
                    (note-tip-advanced chain-state)
                    ;; Drain queued blocks whose parent is now connected
                    (drain-block-queue chain-state utxo-set block-store
                                       :fee-estimator fee-estimator
                                       :recent-rejects recent-rejects)
                    t)
                  (progn
                    (bitcoin-lisp:log-error "Block ~D validation failed: ~A" height error)
                    (handle-validation-failure block height error chain-state)
                    nil))))

          ;; Out of order - queue for later, with a HARD receive-side cap.
          ;; Bitcoin Core only ever requests blocks within BLOCK_DOWNLOAD_WINDOW
          ;; of tip (net_processing.cpp:1437-1440) so peers shouldn't deliver
          ;; beyond that window. If they do (due to in-flight retries or our
          ;; gap-block override), drop to bound memory. Without this cap, a
          ;; permanently-failing connect-tip block lets the queue grow until
          ;; the heap exhausts (observed: testnet4 height 70700 stall, 16:32
          ;; node.log crash inside READ-WITNESS-STACK).
          (progn
            (bitcoin-lisp:log-debug "Block ~D received out of order (current: ~D)"
                                    height current-height)
            (when *ibd-context*
              (let ((queue (ibd-context-block-queue *ibd-context*)))
                (cond
                  ((gethash height queue)
                   nil)  ; duplicate
                  ((>= (hash-table-count queue) +max-block-queue-size+)
                   (bitcoin-lisp:log-warn
                    "Dropping out-of-order block at height ~D: queue at cap (~D, tip ~D)"
                    height (hash-table-count queue) current-height))
                  ((> (- height current-height) +max-block-queue-size+)
                   (bitcoin-lisp:log-warn
                    "Dropping out-of-order block at height ~D: too far ahead of tip ~D"
                    height current-height))
                  (t
                   (setf (gethash height queue) block)))))
            nil)))))

(defun drain-block-queue (chain-state utxo-set block-store &key fee-estimator recent-rejects)
  "Process queued blocks whose parents are now connected.
Repeats until no more queued blocks can be connected."
  (unless *ibd-context*
    (return-from drain-block-queue 0))
  (let ((drained 0)
        (checkpoint-height (last-checkpoint-height)))
    (loop
      (let* ((current-height (bitcoin-lisp.storage:current-height chain-state))
             (next-height (1+ current-height))
             (queue (ibd-context-block-queue *ibd-context*))
             (block (gethash next-height queue)))
        (unless block
          (return drained))
        (remhash next-height queue)
        ;; Try to connect
        (let* ((current-time (bitcoin-lisp.serialization:get-unix-time))
               (skip-scripts (<= next-height checkpoint-height)))
          (multiple-value-bind (valid error)
              (bitcoin-lisp.validation:validate-block
               block chain-state utxo-set next-height current-time
               :skip-scripts skip-scripts)
            (if valid
                (progn
                  (bitcoin-lisp.validation:connect-block
                   block chain-state block-store utxo-set
                   :fee-estimator fee-estimator
                   :recent-rejects recent-rejects)
                  (note-tip-advanced chain-state)
                  (incf drained)
                  (bitcoin-lisp:log-debug "Drained queued block at height ~D" next-height))
                (progn
                  (bitcoin-lisp:log-error "Queued block ~D validation failed: ~A"
                                          next-height error)
                  (handle-validation-failure block next-height error chain-state)
                  ;; Stop draining after a failure — the block is now back in
                  ;; pending and will be re-requested. Returning here also
                  ;; prevents tight-looping on a permanently-failing block.
                  (return drained)))))))))
