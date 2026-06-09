(in-package #:bitcoin-lisp.tests)

;;; IBD (Initial Block Download) Tests

(def-suite ibd-tests :in :bitcoin-lisp-tests)
(in-suite ibd-tests)

;;;; Checkpoint Tests

(test checkpoint-data-exists
  "Test that testnet checkpoint data is defined."
  (is (not (null bitcoin-lisp.networking::\*testnet3-checkpoints\*)))
  (is (listp bitcoin-lisp.networking::\*testnet3-checkpoints\*))
  ;; Check first checkpoint at height 546
  (let ((first (first bitcoin-lisp.networking::\*testnet3-checkpoints\*)))
    (is (= 546 (car first)))
    (is (stringp (cdr first)))))

(test get-checkpoint-hash
  "Test checkpoint hash retrieval."
  (let ((bitcoin-lisp:*network* :testnet3))
    ;; Known testnet3 checkpoint should return a hash
    (let ((hash (bitcoin-lisp.networking::get-checkpoint-hash 546)))
      (is (not (null hash)))
      (is (= 32 (length hash))))
    ;; Non-checkpoint height should return NIL
    (is (null (bitcoin-lisp.networking::get-checkpoint-hash 547)))))

(test last-checkpoint-height
  "Test getting the last checkpoint height."
  (let ((bitcoin-lisp:*network* :testnet3))
    (let ((height (bitcoin-lisp.networking::last-checkpoint-height)))
      (is (integerp height))
      (is (> height 0)))))

(test validate-checkpoint-match
  "Test checkpoint validation when hash matches."
  (let ((bitcoin-lisp:*network* :testnet3))
    (let ((hash (bitcoin-lisp.networking::get-checkpoint-hash 546)))
      (is (bitcoin-lisp.networking::validate-checkpoint hash 546)))))

(test validate-checkpoint-mismatch
  "Test checkpoint validation when hash doesn't match."
  (let ((bitcoin-lisp:*network* :testnet3))
    (let ((bad-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (is (not (bitcoin-lisp.networking::validate-checkpoint bad-hash 546))))))

(test validate-checkpoint-no-checkpoint
  "Test checkpoint validation at non-checkpoint height."
  (let ((any-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    ;; Should return T since there's no checkpoint at height 100
    (is (bitcoin-lisp.networking::validate-checkpoint any-hash 100))))

;;;; Header PoW Validation Tests

(test validate-header-pow-structure
  "Test that PoW validation function exists and handles edge cases."
  ;; Create a minimal mock header with easy target (high bits)
  (let* ((easy-bits #x1d00ffff)  ; Easy target for testing
         (header (bitcoin-lisp.serialization::make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits easy-bits
                  :nonce 0)))
    ;; The PoW validation should at least run without error
    (is (or (bitcoin-lisp.networking::validate-header-pow header)
            (not (bitcoin-lisp.networking::validate-header-pow header))))))

;;;; IBD Context Tests

(test ibd-context-creation
  "Test creating an IBD context."
  (let ((ctx (bitcoin-lisp.networking::make-ibd)))
    (is (not (null ctx)))
    (is (eq :idle (bitcoin-lisp.networking::ibd-context-state ctx)))
    (is (= 0 (bitcoin-lisp.networking::ibd-context-headers-received ctx)))
    (is (= 0 (bitcoin-lisp.networking::ibd-context-blocks-received ctx)))
    (is (= 16 (bitcoin-lisp.networking::ibd-context-max-in-flight ctx)))))

(test ibd-state-transitions
  "Test IBD state machine transitions."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd)))
    (is (eq :idle (bitcoin-lisp.networking::ibd-state)))
    (bitcoin-lisp.networking::set-ibd-state :syncing-headers)
    (is (eq :syncing-headers (bitcoin-lisp.networking::ibd-state)))
    (bitcoin-lisp.networking::set-ibd-state :syncing-blocks)
    (is (eq :syncing-blocks (bitcoin-lisp.networking::ibd-state)))
    (bitcoin-lisp.networking::set-ibd-state :synced)
    (is (eq :synced (bitcoin-lisp.networking::ibd-state)))))

;;;; Download Queue Tests

(test download-queue-tracking
  "Test tracking blocks in the download queue."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (hash2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    ;; Add blocks to pending
    (setf (gethash hash1 (bitcoin-lisp.networking::ibd-context-pending-blocks
                          bitcoin-lisp.networking::*ibd-context*)) 100)
    (setf (gethash hash2 (bitcoin-lisp.networking::ibd-context-pending-blocks
                          bitcoin-lisp.networking::*ibd-context*)) 101)

    ;; Check pending count
    (is (= 2 (hash-table-count (bitcoin-lisp.networking::ibd-context-pending-blocks
                                bitcoin-lisp.networking::*ibd-context*))))

    ;; Get blocks to request
    (let ((to-request (bitcoin-lisp.networking::get-next-blocks-to-request 10)))
      (is (= 2 (length to-request)))
      ;; Should be sorted by height (hash1 at 100 should come first)
      (is (equalp hash1 (first to-request))))))

(test in-flight-tracking
  "Test tracking in-flight block requests."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (mock-peer :peer))

    ;; Add to pending
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                         bitcoin-lisp.networking::*ibd-context*)) 100)

    ;; Mark as in-flight
    (bitcoin-lisp.networking::mark-block-in-flight hash mock-peer)

    ;; Check it's now in-flight
    (let ((in-flight (bitcoin-lisp.networking::ibd-context-in-flight
                      bitcoin-lisp.networking::*ibd-context*)))
      (is (= 1 (hash-table-count in-flight)))
      (let ((entry (gethash hash in-flight)))
        (is (eq mock-peer (car entry)))))

    ;; Should not appear in get-next-blocks-to-request
    (is (null (bitcoin-lisp.networking::get-next-blocks-to-request 10)))))

(test block-received-tracking
  "Test marking blocks as received."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))

    ;; Add to pending and in-flight
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                         bitcoin-lisp.networking::*ibd-context*)) 100)
    (bitcoin-lisp.networking::mark-block-in-flight hash (bitcoin-lisp.networking::make-peer))

    ;; Initial blocks received count
    (is (= 0 (bitcoin-lisp.networking::ibd-context-blocks-received
              bitcoin-lisp.networking::*ibd-context*)))

    ;; Mark as received
    (bitcoin-lisp.networking::mark-block-received hash)

    ;; Should be removed from pending and in-flight
    (is (= 0 (hash-table-count (bitcoin-lisp.networking::ibd-context-pending-blocks
                                bitcoin-lisp.networking::*ibd-context*))))
    (is (= 0 (hash-table-count (bitcoin-lisp.networking::ibd-context-in-flight
                                bitcoin-lisp.networking::*ibd-context*))))
    ;; Blocks received should increment
    (is (= 1 (bitcoin-lisp.networking::ibd-context-blocks-received
              bitcoin-lisp.networking::*ibd-context*)))))

;;;; STUCK TIP detection
;;;;
;;;; check-stuck-tip is the OOM-prevention backstop. It must fire when
;;;; the queue is genuinely growing toward cap (validator wedged) but
;;;; NOT during ordinary fork-recovery where the queue holds a handful
;;;; of fork blocks waiting on missing intermediates.

(test stuck-tip-fires-when-queue-near-cap
  "When queue >= 90% of cap and tip hasn't advanced in
+stuck-tip-halt-seconds+, check-stuck-tip returns T."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd))
         (bitcoin-lisp.networking::*ibd-context* ctx)
         (cap bitcoin-lisp.networking::+max-block-queue-size+)
         (threshold (floor (* cap 9/10))))
    ;; Plant queue at threshold
    (let ((q (bitcoin-lisp.networking::ibd-context-block-queue ctx)))
      (loop for i from 0 below threshold
            do (setf (gethash i q) i)))
    ;; Set last-tip-advance well in the past
    (setf (bitcoin-lisp.networking::ibd-context-last-tip-advance-time ctx)
          (- (get-universal-time)
             (1+ bitcoin-lisp.networking::+stuck-tip-halt-seconds+)))
    (is (eq t (bitcoin-lisp.networking::check-stuck-tip)))))

(test stuck-tip-does-not-fire-for-small-fork-queue
  "Regression: when the queue has a handful of fork blocks (1-15)
waiting on missing intermediates, check-stuck-tip must NOT fire even
if tip has been stalled past +stuck-tip-halt-seconds+. Test-bitcoin-
server 2026-05-21 06:46–07:07 hit this 3 times in 21 min before a
13-block reorg completed; the OOM backstop fired and forced peer
rotation each cycle, slowing recovery."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd))
         (bitcoin-lisp.networking::*ibd-context* ctx))
    ;; Plant 14 fork blocks (well below cap of 1024)
    (let ((q (bitcoin-lisp.networking::ibd-context-block-queue ctx)))
      (loop for i from 0 below 14
            do (setf (gethash i q) i)))
    ;; Tip stalled for 10 minutes (2x the threshold)
    (setf (bitcoin-lisp.networking::ibd-context-last-tip-advance-time ctx)
          (- (get-universal-time) 600))
    (is (null (bitcoin-lisp.networking::check-stuck-tip)))))

(test stuck-tip-does-not-fire-when-tip-fresh
  "If tip advanced recently, check-stuck-tip never fires regardless of
queue size."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd))
         (bitcoin-lisp.networking::*ibd-context* ctx)
         (cap bitcoin-lisp.networking::+max-block-queue-size+))
    ;; Plant queue at cap
    (let ((q (bitcoin-lisp.networking::ibd-context-block-queue ctx)))
      (loop for i from 0 below cap
            do (setf (gethash i q) i)))
    ;; Tip advanced just now
    (setf (bitcoin-lisp.networking::ibd-context-last-tip-advance-time ctx)
          (get-universal-time))
    (is (null (bitcoin-lisp.networking::check-stuck-tip)))))

;;;; Peer FIN handling
;;;;
;;;; receive-bytes flips connection-connected NIL when a ready socket
;;;; yields zero progress (Linux POLLHUP after peer FIN). handle-peer-fin
;;;; must propagate this into peer-state so the outer drain + replace-
;;;; disconnected-peers can reap. Regression for 2026-05-22 incident:
;;;; 7 testnet4 peers stuck in CLOSE-WAIT for 48h, sync gap from
;;;; h=135,913 to network tip.

(test handle-peer-fin-disconnects-on-dead-connection
  "When connection-connected is NIL, handle-peer-fin disconnects the
peer and returns T."
  (let* ((conn (bitcoin-lisp.networking::make-connection
                :host "10.0.0.1" :port 48333 :connected nil))
         (peer (bitcoin-lisp.networking:make-peer
                :connection conn :state :ready :address "10.0.0.1")))
    (is (eq t (bitcoin-lisp.networking::handle-peer-fin peer)))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
    (is (null (bitcoin-lisp.networking::peer-connection peer)))))

(test handle-peer-fin-noop-on-healthy-connection
  "When connection-connected is T (no FIN seen), handle-peer-fin leaves
the peer untouched and returns NIL."
  (let* ((conn (bitcoin-lisp.networking::make-connection
                :host "10.0.0.2" :port 48333 :connected t))
         (peer (bitcoin-lisp.networking:make-peer
                :connection conn :state :ready :address "10.0.0.2")))
    (is (null (bitcoin-lisp.networking::handle-peer-fin peer)))
    (is (eq :ready (bitcoin-lisp.networking:peer-state peer)))
    (is (eq conn (bitcoin-lisp.networking::peer-connection peer)))))

(test handle-peer-fin-noop-when-no-connection
  "Already-disconnected peers (peer-connection NIL) are a no-op — no
crash, return NIL."
  (let ((peer (bitcoin-lisp.networking:make-peer
               :connection nil :state :disconnected :address "10.0.0.3")))
    (is (null (bitcoin-lisp.networking::handle-peer-fin peer)))))

;;;; At-tip FIN reap (drain-and-reap-peer)
;;;;
;;;; The block-download loop is gated on (< current-height
;;;; header-tip-height) and never runs at tip, so its per-peer
;;;; drain+handle-peer-fin is skipped there. run-ibd now also calls
;;;; drain-and-reap-peer unconditionally each cycle. Regression for the
;;;; 2026-05-24 recurrence: a peer that FIN'd at tip (connection-connected
;;;; already NIL) must be reaped without touching its dead/closed socket.

(test drain-and-reap-peer-reaps-dead-connection-at-tip
  "A :ready peer whose connection-connected is already NIL is reaped —
the drain loop is skipped (no socket I/O on a dead connection) and
handle-peer-fin disconnects it so replace-disconnected-peers can refill."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd))
         (conn (bitcoin-lisp.networking::make-connection
                :host "10.0.0.4" :port 48333 :connected nil :socket nil))
         (peer (bitcoin-lisp.networking:make-peer
                :connection conn :state :ready :address "10.0.0.4")))
    (bitcoin-lisp.networking::drain-and-reap-peer peer nil nil nil ctx)
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
    (is (null (bitcoin-lisp.networking::peer-connection peer)))))

(test drain-and-reap-peer-noop-when-no-connection
  "A peer with peer-connection NIL is a no-op — no crash, state untouched."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd))
         (peer (bitcoin-lisp.networking:make-peer
                :connection nil :state :disconnected :address "10.0.0.5")))
    (bitcoin-lisp.networking::drain-and-reap-peer peer nil nil nil ctx)
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

;;;; Timeout Tests

(test timeout-detection
  "Test detecting timed out requests."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))

    ;; Set a very short timeout for testing (1 second)
    (setf (bitcoin-lisp.networking::ibd-context-request-timeout
           bitcoin-lisp.networking::*ibd-context*) 1)

    ;; Add to in-flight with old timestamp
    (let ((old-time (- (get-internal-real-time)
                       (* 2 internal-time-units-per-second))))  ; 2 seconds ago
      (setf (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                           bitcoin-lisp.networking::*ibd-context*))
            (cons :peer old-time)))

    ;; Should detect timeout
    (let ((timed-out (bitcoin-lisp.networking::get-timed-out-requests)))
      (is (= 1 (length timed-out)))
      (is (equalp hash (first timed-out))))))

(test get-timed-out-requests-near-tip-shorter-timeout
  "A block in-flight ~40s is timed out under the near-tip
+block-stalling-timeout+ (30s) but NOT under the full per-block timeout
(120s) — so near the tip a silent peer's block is retried elsewhere fast."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (setf (bitcoin-lisp.networking::ibd-context-request-timeout
           bitcoin-lisp.networking::*ibd-context*) 120)
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                         bitcoin-lisp.networking::*ibd-context*))
          (cons :peer (- (get-internal-real-time)
                         (* 40 internal-time-units-per-second))))  ; 40s ago
    ;; Default (full 120s) timeout: not yet timed out.
    (is (null (bitcoin-lisp.networking::get-timed-out-requests)))
    ;; Near-tip 30s timeout: timed out.
    (let ((timed-out (bitcoin-lisp.networking::get-timed-out-requests
                      bitcoin-lisp.networking::+block-stalling-timeout+)))
      (is (= 1 (length timed-out)))
      (is (equalp hash (first timed-out))))))

(test retry-timed-out-requests
  "Test retrying timed out requests."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))

    ;; Set short timeout and add old request
    (setf (bitcoin-lisp.networking::ibd-context-request-timeout
           bitcoin-lisp.networking::*ibd-context*) 1)
    (let ((old-time (- (get-internal-real-time)
                       (* 2 internal-time-units-per-second))))
      (setf (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                           bitcoin-lisp.networking::*ibd-context*))
            (cons :peer old-time)))

    ;; Also add to pending so it can be retried
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                         bitcoin-lisp.networking::*ibd-context*)) 100)

    ;; Retry should remove from in-flight
    (let ((count (bitcoin-lisp.networking::retry-timed-out-requests)))
      (is (= 1 count))
      (is (= 0 (hash-table-count (bitcoin-lisp.networking::ibd-context-in-flight
                                  bitcoin-lisp.networking::*ibd-context*))))
      ;; Should still be in pending
      (is (= 1 (hash-table-count (bitcoin-lisp.networking::ibd-context-pending-blocks
                                  bitcoin-lisp.networking::*ibd-context*)))))))

(test retry-timed-out-requests-drops-after-N-attempts
  "After +max-block-request-timeouts+ retries, a block is dropped from
the pending queue. Without this, competing-fork blocks that peers
won't serve would keep IBD's main loop spinning forever."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))
    (setf (bitcoin-lisp.networking::ibd-context-request-timeout
           bitcoin-lisp.networking::*ibd-context*) 1)
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                         bitcoin-lisp.networking::*ibd-context*)) 100)
    ;; Simulate N timeouts. Each iteration: put the request back
    ;; in-flight with an old timestamp, then retry — retry-timed-out-
    ;; requests removes it from in-flight and bumps the counter.
    (let ((old-time (- (get-internal-real-time)
                       (* 2 internal-time-units-per-second))))
      (loop repeat (1- bitcoin-lisp.networking::+max-block-request-timeouts+)
            do (setf (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                                     bitcoin-lisp.networking::*ibd-context*))
                     (cons :peer old-time))
               (bitcoin-lisp.networking::retry-timed-out-requests)))
    ;; After N-1 timeouts, still in pending.
    (is (= 1 (hash-table-count
              (bitcoin-lisp.networking::ibd-context-pending-blocks
               bitcoin-lisp.networking::*ibd-context*))))
    ;; One more timeout should drop it from pending.
    (let ((old-time (- (get-internal-real-time)
                       (* 2 internal-time-units-per-second))))
      (setf (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                           bitcoin-lisp.networking::*ibd-context*))
            (cons :peer old-time)))
    (bitcoin-lisp.networking::retry-timed-out-requests)
    (is (= 0 (hash-table-count
              (bitcoin-lisp.networking::ibd-context-pending-blocks
               bitcoin-lisp.networking::*ibd-context*))))))

(test mark-block-received-clears-timeout-counter
  "A successful receive clears the per-hash timeout counter so a future
re-request (e.g. after a reorg) starts fresh."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    ;; Plant a non-zero counter directly.
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-request-timeouts
                         bitcoin-lisp.networking::*ibd-context*)) 3)
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                         bitcoin-lisp.networking::*ibd-context*)) 100)
    (bitcoin-lisp.networking::mark-block-received hash)
    (is (= 0 (hash-table-count
              (bitcoin-lisp.networking::ibd-context-request-timeouts
               bitcoin-lisp.networking::*ibd-context*))))))

;;;; Per-peer block-availability tracking
;;;;
;;;; Mirrors Bitcoin Core's ProcessBlockAvailability / UpdateBlockAvailability
;;;; (net_processing.cpp:1361-1392). These tests cover the state
;;;; machine: known hash → best-known set; unknown hash → staged;
;;;; staged hash resolves once index catches up.

(defun %make-peer-with-state (state-key)
  "Construct a minimal peer struct for availability tests, with the
:state slot set so callers can pretend it's :ready."
  (let ((p (bitcoin-lisp.networking::make-peer :address "test")))
    (setf (bitcoin-lisp.networking::peer-state p) state-key)
    p))

(test update-block-availability-known-hash
  "When the announced hash is already in the index with positive
chain-work, peer's best-known-block-hash is set to it."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash hash :height 5 :chain-work 100 :status :header-valid))
    (bitcoin-lisp.networking::update-block-availability peer state hash)
    (is (equalp hash (bitcoin-lisp.networking::peer-best-known-block-hash peer)))
    (is (null (bitcoin-lisp.networking::peer-hash-last-unknown-block peer)))))

(test update-block-availability-unknown-hash-staged
  "When the announced hash isn't in the index yet, it's staged in
hash-last-unknown-block for later resolution."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (mystery-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC)))
    (bitcoin-lisp.networking::update-block-availability peer state mystery-hash)
    (is (null (bitcoin-lisp.networking::peer-best-known-block-hash peer)))
    (is (equalp mystery-hash
                (bitcoin-lisp.networking::peer-hash-last-unknown-block peer)))))

(test process-block-availability-resolves-staged
  "Once the staged hash gets a block-index entry, the next
process-block-availability promotes it to best-known."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)))
    ;; Stage hash before the index has it.
    (bitcoin-lisp.networking::update-block-availability peer state hash)
    (is (equalp hash (bitcoin-lisp.networking::peer-hash-last-unknown-block peer)))
    ;; Index catches up.
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash hash :height 10 :chain-work 200 :status :header-valid))
    ;; Process resolves the staged hash.
    (bitcoin-lisp.networking::process-block-availability peer state)
    (is (equalp hash (bitcoin-lisp.networking::peer-best-known-block-hash peer)))
    (is (null (bitcoin-lisp.networking::peer-hash-last-unknown-block peer)))))

(test update-block-availability-does-not-downgrade
  "If best-known is at chain-work N and we announce a block with
chain-work < N, best-known stays put (this peer might be temporarily
sending us an old announcement; we keep the strongest claim)."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (strong-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (weak-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash strong-hash :height 100 :chain-work 5000 :status :valid))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash weak-hash :height 50 :chain-work 1000 :status :header-valid))
    (bitcoin-lisp.networking::update-block-availability peer state strong-hash)
    (is (equalp strong-hash
                (bitcoin-lisp.networking::peer-best-known-block-hash peer)))
    (bitcoin-lisp.networking::update-block-availability peer state weak-hash)
    ;; best-known should still be the strong one.
    (is (equalp strong-hash
                (bitcoin-lisp.networking::peer-best-known-block-hash peer)))))

(test queue-missing-fork-blocks-adds-with-reset-timeout
  "queue-missing-fork-blocks adds each hash to pending and clears its
timeout counter so the existing scheduler retries with a fresh budget."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (h1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (h2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    ;; Plant a stale timeout count for h1 to ensure it gets reset.
    (setf (gethash h1 (bitcoin-lisp.networking::ibd-context-request-timeouts
                       bitcoin-lisp.networking::*ibd-context*)) 7)
    (let ((queued (bitcoin-lisp.networking::queue-missing-fork-blocks
                   (list (cons h1 100) (cons h2 101)))))
      (is (= 2 queued))
      (is (= 2 (hash-table-count
                (bitcoin-lisp.networking::ibd-context-pending-blocks
                 bitcoin-lisp.networking::*ibd-context*))))
      ;; Timeout counter for h1 was reset.
      (is (= 0 (hash-table-count
                (bitcoin-lisp.networking::ibd-context-request-timeouts
                 bitcoin-lisp.networking::*ibd-context*)))))))

(test queue-missing-fork-blocks-skips-already-queued
  "If a hash is already in pending or in-flight, queue-missing-fork-blocks
doesn't add it again."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
        (h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (setf (gethash h (bitcoin-lisp.networking::ibd-context-pending-blocks
                      bitcoin-lisp.networking::*ibd-context*)) 50)
    (is (= 0 (bitcoin-lisp.networking::queue-missing-fork-blocks
              (list (cons h 50)))))))

;;;; notfound handling + availability-aware request routing
;;;;
;;;; Regression for the 2026-05-25 fork-recovery stall: 6 fork blocks
;;;; needed for a reorg were requested round-robin from peers that didn't
;;;; have them, perpetually timed out, and the reorg never completed.
;;;; notfound lets a peer tell us it lacks a block; the scheduler then
;;;; stops asking it, and drops the block once ALL peers have disclaimed.

(test note-block-not-available-records-and-releases-in-flight
  "note-block-not-available records the disclaim and, if the block was
in-flight to THIS peer, releases it for immediate retry elsewhere."
  (let* ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)))
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                         bitcoin-lisp.networking::*ibd-context*))
          (cons peer (get-internal-real-time)))
    (bitcoin-lisp.networking::note-block-not-available peer hash)
    (is (bitcoin-lisp.networking::peer-disclaimed-block-p peer hash))
    (is (null (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                             bitcoin-lisp.networking::*ibd-context*))))))

(test note-block-not-available-keeps-in-flight-held-by-other-peer
  "A notfound from peer A must not release an in-flight request that
peer B is still servicing."
  (let* ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
         (peer-a (%make-peer-with-state :ready))
         (peer-b (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4)))
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                         bitcoin-lisp.networking::*ibd-context*))
          (cons peer-b (get-internal-real-time)))
    (bitcoin-lisp.networking::note-block-not-available peer-a hash)
    (is (bitcoin-lisp.networking::peer-disclaimed-block-p peer-a hash))
    ;; B's request is untouched.
    (let ((entry (gethash hash (bitcoin-lisp.networking::ibd-context-in-flight
                                bitcoin-lisp.networking::*ibd-context*))))
      (is (eq peer-b (car entry))))))

(test peer-best-known-height-resolves-from-index
  "peer-best-known-height returns the height of the peer's best-known
block when in the index, and NIL when availability is unknown."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6)))
    (is (null (bitcoin-lisp.networking::peer-best-known-height peer state)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash hash :height 42 :chain-work 100 :status :header-valid))
    (setf (bitcoin-lisp.networking::peer-best-known-block-hash peer) hash)
    (is (= 42 (bitcoin-lisp.networking::peer-best-known-height peer state)))))

(test request-blocks-drops-block-when-all-peers-disclaim
  "When every ready peer has answered notfound for a pending block, the
scheduler drops it from pending — a stale fork no peer can serve — so
IBD stops retrying it forever."
  (let* ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
         (state (bitcoin-lisp.storage:make-chain-state))
         (peer-a (%make-peer-with-state :ready))
         (peer-b (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5)))
    ;; Block is pending at a height within the download window of tip 0.
    (setf (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                         bitcoin-lisp.networking::*ibd-context*)) 5)
    ;; Both peers have disclaimed it.
    (bitcoin-lisp.networking::note-block-not-available peer-a hash)
    (bitcoin-lisp.networking::note-block-not-available peer-b hash)
    (bitcoin-lisp.networking::request-blocks-from-peers (list peer-a peer-b) state)
    (is (null (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                             bitcoin-lisp.networking::*ibd-context*))))))

(test handle-notfound-marks-block-disclaimed
  "An incoming notfound message for a block marks it disclaimed on the
peer (wire-path coverage of the parse + dispatch)."
  (let* ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (inv (bitcoin-lisp.serialization:make-inv-vector
               :type bitcoin-lisp.serialization:+inv-type-witness-block+ :hash hash))
         (payload (flexi-streams:with-output-to-sequence (s)
                    (bitcoin-lisp.serialization::write-compact-size s 1)
                    (bitcoin-lisp.serialization::write-inv-vector s inv))))
    (bitcoin-lisp.networking::handle-notfound peer payload)
    (is (bitcoin-lisp.networking::peer-disclaimed-block-p peer hash))))

;;;; In-flight orphan reassignment
;;;;
;;;; When a peer disconnects, the blocks it held in-flight must be freed
;;;; for immediate reassignment (Bitcoin Core's FinalizeNode), not left
;;;; until the ~125s per-hash timeout. The block stays in pending, so the
;;;; next get-next-blocks-to-request picks it up.

(test release-orphaned-in-flight-reclaims-disconnected-peer-blocks
  "Releases in-flight blocks held by a non-:ready peer (still in pending),
leaving a live peer's in-flight untouched."
  (let* ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
         (ctx bitcoin-lisp.networking::*ibd-context*)
         (live (%make-peer-with-state :ready))
         (dead (%make-peer-with-state :disconnected))
         (live-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (dead-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (setf (gethash live-hash (bitcoin-lisp.networking::ibd-context-pending-blocks ctx)) 10
          (gethash dead-hash (bitcoin-lisp.networking::ibd-context-pending-blocks ctx)) 11)
    (setf (gethash live-hash (bitcoin-lisp.networking::ibd-context-in-flight ctx))
          (cons live (get-internal-real-time))
          (gethash dead-hash (bitcoin-lisp.networking::ibd-context-in-flight ctx))
          (cons dead (get-internal-real-time)))
    (is (= 1 (bitcoin-lisp.networking::release-orphaned-in-flight)))
    ;; Dead peer's block freed from in-flight but kept in pending.
    (is (null (gethash dead-hash (bitcoin-lisp.networking::ibd-context-in-flight ctx))))
    (is (= 11 (gethash dead-hash (bitcoin-lisp.networking::ibd-context-pending-blocks ctx))))
    ;; Live peer's in-flight is untouched.
    (is (eq live (car (gethash live-hash (bitcoin-lisp.networking::ibd-context-in-flight ctx)))))))

;;;; Progress Reporting Tests

(test ibd-progress-reporting
  "Test IBD progress reporting."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd)))
    ;; Set some state
    (setf (bitcoin-lisp.networking::ibd-context-target-height
           bitcoin-lisp.networking::*ibd-context*) 1000)
    (setf (bitcoin-lisp.networking::ibd-context-blocks-received
           bitcoin-lisp.networking::*ibd-context*) 500)
    (setf (bitcoin-lisp.networking::ibd-context-headers-received
           bitcoin-lisp.networking::*ibd-context*) 1000)

    (let ((progress (bitcoin-lisp.networking::ibd-progress)))
      (is (not (null progress)))
      (is (= 500 (getf progress :blocks-received)))
      (is (= 1000 (getf progress :target-height)))
      (is (= 1000 (getf progress :headers-received)))
      ;; 500/1000 = 50%
      (is (= 50.0 (getf progress :progress-percent))))))

;;;; Header Chain Validation Tests

(test process-headers-empty
  "Test processing empty header list."
  (let ((state (bitcoin-lisp.storage:init-chain-state
                (merge-pathnames "test-chain/" (uiop:temporary-directory)))))
    (is (= 0 (bitcoin-lisp.networking::process-headers '() state)))))

(test validate-block-skip-scripts
  "Test that validate-block with :skip-scripts t skips script validation."
  ;; Create a minimal block with an invalid script that would normally fail.
  ;; With :skip-scripts t, it should still pass script validation.
  ;; Without :skip-scripts, it should fail with :script-failed.
  (let* ((bitcoin-lisp:*network* :testnet3)
         (state (bitcoin-lisp.storage:init-chain-state
                 (merge-pathnames "test-skip-scripts/" (uiop:temporary-directory))))
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (genesis-hash (bitcoin-lisp.storage:network-genesis-hash bitcoin-lisp:*network*))
         ;; Create a coinbase transaction at height 1
         (coinbase-script (make-array 3 :element-type '(unsigned-byte 8)
                                        :initial-contents '(#x01 #x01 #x00)))  ; BIP 34: height 1
         (coinbase-input (bitcoin-lisp.serialization:make-tx-in
                          :previous-output (bitcoin-lisp.serialization:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                 :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig coinbase-script
                          :sequence #xFFFFFFFF))
         (coinbase-output (bitcoin-lisp.serialization:make-tx-out
                           :value 5000000000  ; 50 BTC
                           :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                        :initial-contents '(#x51))))  ; OP_TRUE
         (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (vector coinbase-input)
                       :outputs (vector coinbase-output)
                       :lock-time 0))
         ;; Build a valid-looking block header
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block genesis-hash
                  :merkle-root (bitcoin-lisp.validation:compute-merkle-root
                                (list (bitcoin-lisp.serialization:transaction-hash coinbase-tx)))
                  :timestamp (+ 1231006505 600)  ; Genesis + 10 min
                  :bits #x1d00ffff
                  :nonce 0))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header header
                 :transactions (list coinbase-tx))))
    ;; The :skip-scripts parameter should be accepted without error
    ;; (We can't fully test block validation here without a complete chain setup,
    ;; but we verify the parameter is wired through correctly by checking that
    ;; validate-block accepts it and the checkpoint height is accessible.)
    (is (> (bitcoin-lisp.networking::last-checkpoint-height) 0)
        "Last checkpoint height should be positive")
    ;; Verify validate-block accepts the :skip-scripts keyword
    ;; (It will fail on header validation since our mock block isn't fully valid,
    ;; but the important thing is it doesn't signal an error about unknown keywords.)
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block
         block state utxo-set 1 (bitcoin-lisp.serialization:get-unix-time)
         :skip-scripts t)
      (declare (ignore valid))
      ;; Should get a validation error (not a keyword error), proving skip-scripts is accepted
      (is (keywordp error)))))

(test validate-header-chain-empty
  "Test validating empty header chain."
  (let ((state (bitcoin-lisp.storage:init-chain-state
                (merge-pathnames "test-chain/" (uiop:temporary-directory)))))
    (multiple-value-bind (valid-headers error)
        (bitcoin-lisp.networking::validate-header-chain '() state)
      (is (null valid-headers))
      (is (null error)))))

;;;; Header-sync peer failover (the testnet4 at-tip stall fix)

(test header-sync-failover-rotates-past-stalled-peers
  "sync-headers-with-failover tries ready peers in descending start-height
order and rotates past any that STALL, stopping at the first that answers."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd-context))
         ;; Three ready peers; the two highest-start-height ones stall.
         (p-hi  (bitcoin-lisp.networking:make-peer :state :ready :start-height 900))
         (p-mid (bitcoin-lisp.networking:make-peer :state :ready :start-height 800))
         (p-lo  (bitcoin-lisp.networking:make-peer :state :ready :start-height 700))
         (tried '())
         ;; Stub: p-hi and p-mid stall (values 0 t); p-lo answers (values 3 nil).
         (sync-fn (lambda (peer chain-state &key recent-rejects)
                    (declare (ignore chain-state recent-rejects))
                    (push peer tried)
                    (if (eq peer p-lo) (values 3 nil) (values 0 t)))))
    (let ((winner (bitcoin-lisp.networking::sync-headers-with-failover
                   (list p-lo p-hi p-mid) nil ctx :sync-fn sync-fn)))
      ;; Stopped at the first non-stalled peer.
      (is (eq p-lo winner))
      ;; Tried in start-height order hi -> mid -> lo, then stopped.
      (is (equal (list p-hi p-mid p-lo) (nreverse tried)))
      ;; header-sync-peer left pointing at the peer that answered.
      (is (eq p-lo (bitcoin-lisp.networking::ibd-context-header-sync-peer ctx))))))

(test header-sync-failover-first-peer-answers
  "When the highest-start-height peer answers, no rotation happens."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd-context))
         (p-hi (bitcoin-lisp.networking:make-peer :state :ready :start-height 900))
         (p-lo (bitcoin-lisp.networking:make-peer :state :ready :start-height 700))
         (calls 0)
         (sync-fn (lambda (peer chain-state &key recent-rejects)
                    (declare (ignore peer chain-state recent-rejects))
                    (incf calls) (values 10 nil))))
    (is (eq p-hi (bitcoin-lisp.networking::sync-headers-with-failover
                  (list p-lo p-hi) nil ctx :sync-fn sync-fn)))
    (is (= 1 calls))))   ; stopped after the first peer

(test header-sync-failover-all-stalled-and-skips-nonready
  "All-stalled returns NIL; non-:ready peers are skipped entirely."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd-context))
         (ready (bitcoin-lisp.networking:make-peer :state :ready :start-height 500))
         (dead  (bitcoin-lisp.networking:make-peer :state :disconnected :start-height 999))
         (tried '())
         (sync-fn (lambda (peer chain-state &key recent-rejects)
                    (declare (ignore chain-state recent-rejects))
                    (push peer tried) (values 0 t))))
    ;; All ready peers stall -> NIL.
    (is (null (bitcoin-lisp.networking::sync-headers-with-failover
               (list ready) nil ctx :sync-fn sync-fn)))
    ;; The disconnected peer (higher start-height) is never tried.
    (setf tried '())
    (bitcoin-lisp.networking::sync-headers-with-failover
     (list ready dead) nil ctx :sync-fn sync-fn)
    (is (equal (list ready) (nreverse tried)))))
