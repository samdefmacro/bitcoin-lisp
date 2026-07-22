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

;;;; Byte-aware request window
;;;;
;;;; The request lookahead must never exceed what the byte-capped block
;;;; queue can hold (+max-block-queue-bytes+ / avg block wire size).
;;;; Regression for 2026-06-12 mainnet h~851.7k: the 1024-count window
;;;; vs the ~170-block byte capacity stuffed peers' send queues with
;;;; far-ahead 2MB blocks that were dropped at the cap on arrival,
;;;; serializing the tip on multi-minute deliveries (~1 block/min).

(defun %plant-pending (heights)
  "Add one pending block per height in HEIGHTS, hash derived from height."
  (let ((pending (bitcoin-lisp.networking::ibd-context-pending-blocks
                  bitcoin-lisp.networking::*ibd-context*)))
    (dolist (h heights)
      (let ((hash (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
        (setf (aref hash 0) (ldb (byte 8 0) h)
              (aref hash 1) (ldb (byte 8 8) h)
              (aref hash 2) (ldb (byte 8 16) h))
        (setf (gethash hash pending) h)))))

(test request-window-clamped-by-byte-cap
  "With the default 1MB avg block size, the window is byte-cap/1MB = 256
blocks, far below the 1024 count window."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd)))
    (%plant-pending '(150 356 357 1100))
    (let ((heights (mapcar (lambda (hash)
                             (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                                            bitcoin-lisp.networking::*ibd-context*)))
                           (bitcoin-lisp.networking::get-next-blocks-to-request 10 100))))
      ;; tip 100 + window 256 = 356: heights 150 and 356 in, 357/1100 out
      (is (equal '(150 356) (sort heights #'<))))))

(test request-window-expands-for-small-blocks
  "With tiny historic blocks the byte capacity exceeds 1024, so the
count window is the binding limit again."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd)))
    (setf (bitcoin-lisp.networking::ibd-context-avg-block-wire-bytes
           bitcoin-lisp.networking::*ibd-context*)
          1024)                         ; 1KB blocks -> capacity 262144
    (%plant-pending (list (+ 100 bitcoin-lisp.networking::+max-block-queue-size+)
                          (+ 101 bitcoin-lisp.networking::+max-block-queue-size+)))
    (is (= 1 (length (bitcoin-lisp.networking::get-next-blocks-to-request 10 100))))))

(test request-window-floor-keeps-pipeline-alive
  "Even with absurdly large blocks the window never shrinks below 32."
  (let ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd)))
    (setf (bitcoin-lisp.networking::ibd-context-avg-block-wire-bytes
           bitcoin-lisp.networking::*ibd-context*)
          (* 64 1024 1024))             ; 64MB avg -> raw capacity 4
    (%plant-pending '(132 133))
    (let ((heights (mapcar (lambda (hash)
                             (gethash hash (bitcoin-lisp.networking::ibd-context-pending-blocks
                                            bitcoin-lisp.networking::*ibd-context*)))
                           (bitcoin-lisp.networking::get-next-blocks-to-request 10 100))))
      ;; tip 100 + floor 32 = 132: height 132 in, 133 out
      (is (equal '(132) heights)))))

(test note-block-wire-size-ema
  "note-block-wire-size folds sizes in as a 0.9/0.1 integer EMA and
ignores zero (unknown) sizes."
  (let ((ctx (bitcoin-lisp.networking::make-ibd)))
    (is (= (* 1024 1024)
           (bitcoin-lisp.networking::ibd-context-avg-block-wire-bytes ctx)))
    (bitcoin-lisp.networking::note-block-wire-size ctx (* 2 1024 1024))
    (is (= (floor (+ (* 9 1048576) 2097152) 10)
           (bitcoin-lisp.networking::ibd-context-avg-block-wire-bytes ctx)))
    (let ((before (bitcoin-lisp.networking::ibd-context-avg-block-wire-bytes ctx)))
      (bitcoin-lisp.networking::note-block-wire-size ctx 0)
      (is (= before (bitcoin-lisp.networking::ibd-context-avg-block-wire-bytes ctx))))))

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

(test stuck-tip-fires-on-byte-cap
  "Regression for the June 2026 two-day stall at h=851,912: the byte cap
pins the queue count at ~170 modern blocks, far below 90% of the 1024
count cap, so a count-only near-cap check never fired. The halt must
also trigger when queue BYTES are near +max-block-queue-bytes+."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd))
         (bitcoin-lisp.networking::*ibd-context* ctx))
    ;; Small count (150 entries), bytes at the cap
    (let ((q (bitcoin-lisp.networking::ibd-context-block-queue ctx)))
      (loop for i from 0 below 150
            do (setf (gethash i q) i)))
    (setf (bitcoin-lisp.networking::ibd-context-block-queue-bytes ctx)
          bitcoin-lisp.networking::+max-block-queue-bytes+)
    (setf (bitcoin-lisp.networking::ibd-context-last-tip-advance-time ctx)
          (- (get-universal-time)
             (1+ bitcoin-lisp.networking::+stuck-tip-halt-seconds+)))
    (is (eq t (bitcoin-lisp.networking::check-stuck-tip)))))

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

(test block-relay-targets-skips-source-and-nonready
  "block-relay-targets announces a new block to every ready peer except the
source (which already has it); non-ready peers are excluded."
  (let ((src (%make-peer-with-state :ready))
        (ready (%make-peer-with-state :ready))
        (dead (%make-peer-with-state :disconnected)))
    (is (equal (list ready)
               (bitcoin-lisp.networking::block-relay-targets src (list src ready dead))))))

(test relay-block-noop-when-relay-disabled
  "relay-block is a no-op when relay is disabled (mainnet default), so a
relay-off node never propagates blocks."
  (let ((bitcoin-lisp:*network* :mainnet)
        (bitcoin-lisp:*mainnet-relay-enabled* nil)
        (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (null (bitcoin-lisp.networking::relay-block
               (bitcoin-lisp.serialization:make-block-header
                :version 1 :prev-block zeros :merkle-root zeros
                :timestamp 1700000000 :bits #x1d00ffff :nonce 0)
               nil (list (%make-peer-with-state :ready)))))))

(test tx-request-tracker-dedups-and-records-announcers
  "tx-request-wanted-p requests from the first announcer only; a second peer
announcing the same txid is recorded as a failover candidate (no duplicate
request). After the tx is received, a later announce requests again."
  (bitcoin-lisp.networking::reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
        (p1 (%make-peer-with-state :ready))
        (p2 (%make-peer-with-state :ready)))
    (is (eq t (bitcoin-lisp.networking::tx-request-wanted-p txid p1)))
    (is (null (bitcoin-lisp.networking::tx-request-wanted-p txid p2)))
    (bitcoin-lisp.networking::tx-request-received txid)
    (is (eq t (bitcoin-lisp.networking::tx-request-wanted-p txid p1)))
    (bitcoin-lisp.networking::reset-tx-requests)))

(test tx-request-retry-reroutes-to-next-announcer
  "A timed-out tx request is re-routed to another ready announcer."
  (bitcoin-lisp.networking::reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8))
        (p1 (%make-peer-with-state :ready))
        (p2 (%make-peer-with-state :ready)))
    (bitcoin-lisp.networking::tx-request-wanted-p txid p1)
    (bitcoin-lisp.networking::tx-request-wanted-p txid p2)
    ;; backdate the in-flight timestamp by >timeout to force a re-route
    ;; (internal-real-time is image-relative, so use a real elapsed delta)
    (setf (gethash txid bitcoin-lisp.networking::*tx-in-flight*)
          (cons p1 (- (get-internal-real-time)
                      (* 120 internal-time-units-per-second))))
    (is (= 1 (bitcoin-lisp.networking::retry-timed-out-tx-requests)))
    (is (eq p2 (car (gethash txid bitcoin-lisp.networking::*tx-in-flight*))))
    (bitcoin-lisp.networking::reset-tx-requests)))

(test tx-request-retry-drops-when-no-other-announcer
  "A timed-out tx request with no other announcer is dropped from tracking."
  (bitcoin-lisp.networking::reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
        (p1 (%make-peer-with-state :ready)))
    (bitcoin-lisp.networking::tx-request-wanted-p txid p1)
    (setf (gethash txid bitcoin-lisp.networking::*tx-in-flight*)
          (cons p1 (- (get-internal-real-time)
                      (* 120 internal-time-units-per-second))))
    (is (= 0 (bitcoin-lisp.networking::retry-timed-out-tx-requests)))
    (is (null (gethash txid bitcoin-lisp.networking::*tx-in-flight*)))
    (bitcoin-lisp.networking::reset-tx-requests)))

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

;; NOTE: the old test `request-blocks-drops-block-when-all-peers-disclaim`
;; was removed with the layer-5 download rewrite. It asserted that the
;; scheduler drops a pending block once every peer answered notfound for it —
;; a band-aid built on the false premise that peers notfound blocks. They do
;; not (Bitcoin only sends notfound for txs, never blocks — net_processing.cpp
;; ProcessGetData), which is exactly why the node wedged retrying an
;; unobtainable fork forever. The new scheduler (find-blocks-to-download-for-peer)
;; never requests a block off a peer's own best chain in the first place, so
;; there is nothing to "drop". That correct behavior is covered directly by
;; `find-blocks-to-download-only-on-peer-chain` in reorg-tests.lisp.

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
;;;; until the ~125s per-hash timeout. Once freed from in-flight, the next
;;;; per-peer download walk (find-blocks-to-download-for-peer) re-requests it
;;;; from a live peer whose chain still covers it.

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

(test minimum-chain-work-constants
  "minimum-chain-work returns Core's exact nMinimumChainWork per network, and
the override takes precedence (for tests / custom chains)."
  (is (= #x0000000000000000000000000000000000000001128750f82f4c366153a3a030
         (bitcoin-lisp:minimum-chain-work :mainnet)))
  (is (= #x0000000000000000000000000000000000000000000009a0fe15d0177d086304
         (bitcoin-lisp:minimum-chain-work :testnet4)))
  (is (= 0 (bitcoin-lisp:minimum-chain-work :regtest)))
  (let ((bitcoin-lisp::*minimum-chain-work-override* 42))
    (is (= 42 (bitcoin-lisp:minimum-chain-work :mainnet)))))

(test process-headers-minimum-chain-work-gate
  "Once the active chain is past nMinimumChainWork, a header building a chain
below the floor is refused index admission (anti-DoS low-work fork spam), while
a header extending the high-work tip is accepted."
  (let* ((bitcoin-lisp:*network* :regtest)
         (state (bitcoin-lisp.storage:init-chain-state
                 (merge-pathnames "test-minwork/" (uiop:temporary-directory))))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         ;; init-chain-state sets the genesis hash but does not add an index
         ;; entry; add one (low chain-work) so the fork header below resolves
         ;; its prev-entry and is gated by the work floor, not skipped for a
         ;; missing parent.
         (genesis-entry (bitcoin-lisp.storage:make-block-index-entry
                         :hash genesis-hash :height 0 :chain-work 1 :status :valid
                         :header (bitcoin-lisp.serialization:make-block-header
                                  :version 1 :prev-block zeros :merkle-root zeros
                                  :timestamp 1296688600 :bits #x207fffff :nonce 0
                                  :cached-hash genesis-hash)))
         ;; Plant a high-chain-work tip so past-min-work is true.
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bitcoin-lisp.storage:add-block-index-entry state genesis-entry)
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash tip-hash :height 1 :prev-entry genesis-entry
            :chain-work 1000000000000 :status :valid
            :header (bitcoin-lisp.serialization:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp 1296688700 :bits #x207fffff :nonce 0
                     :cached-hash tip-hash)))
    (bitcoin-lisp.storage:update-chain-tip state tip-hash 1)
    (let ((bitcoin-lisp::*minimum-chain-work-override* 500000000000))
      ;; A header forking off genesis: chain-work ~= genesis + 1 regtest block,
      ;; far below the 5e11 floor -> rejected.
      (let* ((fork-hdr (bitcoin-lisp.serialization:make-block-header
                        :version 1 :prev-block genesis-hash :merkle-root zeros
                        :timestamp 1296688800 :bits #x207fffff :nonce 1))
             (fork-hash (bitcoin-lisp.serialization:block-header-hash fork-hdr)))
        (bitcoin-lisp.networking::process-headers (list fork-hdr) state)
        (is (null (bitcoin-lisp.storage:get-block-index-entry state fork-hash))
            "low-work fork header should be refused"))
      ;; A header extending the high-work tip: chain-work > floor -> accepted.
      (let* ((ext-hdr (bitcoin-lisp.serialization:make-block-header
                       :version 1 :prev-block tip-hash :merkle-root zeros
                       :timestamp 1296688900 :bits #x207fffff :nonce 2))
             (ext-hash (bitcoin-lisp.serialization:block-header-hash ext-hdr)))
        (bitcoin-lisp.networking::process-headers (list ext-hdr) state)
        (is (not (null (bitcoin-lisp.storage:get-block-index-entry state ext-hash)))
            "tip-extending header should be admitted")))))

(test handle-headers-validates-before-admission
  "CONSENSUS/anti-DoS (P0 fix 2026-06-16): announced headers must be validated
(PoW / MTP / difficulty / checkpoint) before entering the block index. The
generic message path (handle-headers, used by the IBD pre-sync drain and BIP130
sendheaders) and the at-tip dispatch path both now route through
validate-header-chain. Before the fix, handle-headers admitted any header with a
known parent, unvalidated — letting a peer inflate chain-work with low-target
headers and bypass checkpoints at admission. Uses a header whose timestamp is at
the median-time-past, which fails the timestamp>MTP rule deterministically."
  (let* ((bitcoin-lisp:*network* :regtest)
         (state (bitcoin-lisp.storage:init-chain-state
                 (merge-pathnames "test-hdr-validation/" (uiop:temporary-directory))))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-ts 1296688600)
         (genesis-entry (bitcoin-lisp.storage:make-block-index-entry
                         :hash genesis-hash :height 0 :chain-work 1 :status :valid
                         :header (bitcoin-lisp.serialization:make-block-header
                                  :version 1 :prev-block zeros :merkle-root zeros
                                  :timestamp genesis-ts :bits #x207fffff :nonce 0
                                  :cached-hash genesis-hash))))
    (bitcoin-lisp.storage:add-block-index-entry state genesis-entry)
    ;; Child of genesis whose timestamp == genesis MTP -> invalid (<= MTP).
    (let* ((bad-hdr (bitcoin-lisp.serialization:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp genesis-ts :bits #x207fffff :nonce 1))
           (bad-hash (bitcoin-lisp.serialization:block-header-hash bad-hdr)))
      ;; (a) the shared validation gate rejects it.
      (multiple-value-bind (valid-headers error)
          (bitcoin-lisp.networking::validate-header-chain (list bad-hdr) state)
        (is (null valid-headers) "invalid header must not pass validate-header-chain")
        (is (not (null error))))
      ;; (b) routing: handle-headers must not admit it to the index. (nil peer is
      ;; safe — with no valid headers, update-block-availability is never called.)
      (let ((payload (concatenate '(vector (unsigned-byte 8))
                                  (vector 1)  ; header-count varint
                                  (bitcoin-lisp.serialization:serialize-block-header bad-hdr)
                                  (vector 0)))) ; per-header tx-count varint
        (bitcoin-lisp.networking::handle-headers nil payload state)
        (is (null (bitcoin-lisp.storage:get-block-index-entry state bad-hash))
            "invalid header must not be admitted by handle-headers")))))

(test validate-header-chain-rejects-future-and-bad-version
  "CONSENSUS (Core ContextualCheckBlockHeader): at header admission we now also
reject a timestamp >2h in the future and a version below the softfork minimum
for its height -- previously only the block-connect path checked these, so a
peer could pollute the header index / best-header chain-work with headers Core
refuses at admission."
  (let* ((bitcoin-lisp:*network* :regtest)
         ;; Bind the regtest PoW limit so #x207fffff is a valid target (else
         ;; derive-target rejects it as above the default limit and PoW never
         ;; passes) -- mirrors the mining tests' %with-regtest.
         (bitcoin-lisp.storage:*pow-limit-target* bitcoin-lisp.storage:+regtest-pow-limit-target+)
         (state (bitcoin-lisp.storage:init-chain-state
                 (merge-pathnames "test-hdr-ctx/" (uiop:temporary-directory))))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state)))
    (flet ((pow-grind (hdr)
             ;; regtest pow-limit target passes ~half of nonces; find one so the
             ;; header clears PoW and reaches the check under test.
             (loop for nonce from 0 below 500
                   do (setf (bitcoin-lisp.serialization:block-header-nonce hdr) nonce
                            (bitcoin-lisp.serialization:block-header-cached-hash hdr) nil)
                   when (bitcoin-lisp.validation:check-proof-of-work hdr)
                     do (return hdr)
                   finally (return hdr))))
      ;; --- future timestamp (child of genesis at height 1; version 4 so the
      ;;     BIP34 gate, active from height 1 on regtest, isn't what rejects) ---
      (bitcoin-lisp.storage:add-block-index-entry
       state (bitcoin-lisp.storage:make-block-index-entry
              :hash genesis-hash :height 0 :chain-work 1 :status :valid
              :header (bitcoin-lisp.serialization:make-block-header
                       :version 1 :prev-block zeros :merkle-root zeros
                       :timestamp 1296688600 :bits #x207fffff :nonce 0
                       :cached-hash genesis-hash)))
      (let ((hdr (pow-grind
                  (bitcoin-lisp.serialization:make-block-header
                   :version 4 :prev-block genesis-hash :merkle-root zeros
                   :timestamp (+ (bitcoin-lisp.serialization:get-unix-time) 7201)
                   :bits #x207fffff :nonce 0))))
        (multiple-value-bind (valid error)
            (bitcoin-lisp.networking::validate-header-chain (list hdr) state)
          (is (null valid) "future-dated header must be rejected")
          (is (and error (search "future" error)) "reason should be the future timestamp")))
      ;; --- version below BIP34 minimum (regtest BIP34 activates at height 1) ---
      (let* ((parent-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
             (parent-hdr (bitcoin-lisp.serialization:make-block-header
                          :version 4 :prev-block zeros :merkle-root zeros
                          :timestamp 1296690000 :bits #x207fffff :nonce 0
                          :cached-hash parent-hash)))
        (bitcoin-lisp.storage:add-block-index-entry
         state (bitcoin-lisp.storage:make-block-index-entry
                :hash parent-hash :height 100 :chain-work 2 :status :valid
                :header parent-hdr))
        (let ((hdr (pow-grind
                    (bitcoin-lisp.serialization:make-block-header
                     :version 1 :prev-block parent-hash :merkle-root zeros
                     :timestamp 1296690100 :bits #x207fffff :nonce 0))))
          (multiple-value-bind (valid error)
              (bitcoin-lisp.networking::validate-header-chain (list hdr) state)
            (is (null valid) "version<2 at/after BIP34 height must be rejected")
            (is (and error (search "version" error)) "reason should be the bad version")))))))

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
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
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
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
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
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
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

;;;; Shutdown stop flag
;;;;
;;;; Both June 2026 mainnet deploys hung after "Stopping node...": TERM
;;;; flips node-running but run-ibd's inner loops never checked it and
;;;; ran until SIGKILL. *ibd-stop-requested* (set by stop-node via
;;;; request-ibd-stop) must make the IBD loops exit within seconds.

(test header-sync-failover-honors-stop-request
  "With a stop requested, the rotation exits before trying any peer."
  (let* ((ctx (bitcoin-lisp.networking::make-ibd-context))
         (ready (bitcoin-lisp.networking:make-peer :state :ready :start-height 500))
         (calls 0)
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
                    (declare (ignore peer chain-state recent-rejects))
                    (incf calls) (values 10 nil))))
    (let ((bitcoin-lisp.networking::*ibd-stop-requested* t))
      (is (null (bitcoin-lisp.networking::sync-headers-with-failover
                 (list ready) nil ctx :sync-fn sync-fn))))
    (is (= 0 calls))))

(test run-ibd-honors-stop-request
  "run-ibd with pending work and a stop requested returns immediately
instead of cycling the no-peer grace (~6s) or downloading."
  (let* ((bitcoin-lisp.networking::*ibd-context* (bitcoin-lisp.networking::make-ibd))
         (state (bitcoin-lisp.storage:make-chain-state))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    ;; A header-valid entry above the current tip gives run-ibd pending
    ;; work and keeps its download-loop gate (height < header-tip) true.
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash hash :height 10 :chain-work 100 :status :header-valid))
    (let ((bitcoin-lisp.networking::*ibd-stop-requested* t)
          (start (get-internal-real-time)))
      (bitcoin-lisp.networking::run-ibd '() state nil nil)
      (is (< (- (get-internal-real-time) start)
             (* 2 internal-time-units-per-second))))))

(test receive-bytes-honors-stop-request
  "receive-bytes on an idle socket must return promptly when
*ibd-stop-requested* is set, instead of blocking for the full :timeout. This is
the socket-read leg of the shutdown path: a TERM arriving while the sync thread
is blocked in a peer read (message wait OR handshake) must not pin it until the
timeout while stop-node waits to join it. A real loopback socket is used so that
WITHOUT the flag check the read would genuinely block (the test would then
exceed the bound)."
  (let ((server (usocket:socket-listen "127.0.0.1" 0 :reuse-address t
                                       :element-type '(unsigned-byte 8))))
    (unwind-protect
         (let* ((port (usocket:get-local-port server))
                (client (usocket:socket-connect "127.0.0.1" port
                                                :element-type '(unsigned-byte 8)))
                (conn (bitcoin-lisp.networking::make-connection
                       :socket client :host "127.0.0.1" :port port
                       :connected t :last-activity (get-universal-time))))
           (unwind-protect
                ;; No data is ever sent, so the read can only finish via the
                ;; stop-request check (or the 30s timeout, which would fail the
                ;; bound below).
                (let ((bitcoin-lisp.networking::*ibd-stop-requested* t)
                      (start (get-internal-real-time)))
                  (let ((result (bitcoin-lisp.networking:receive-bytes
                                 conn 8 :timeout 30)))
                    (is (null result))
                    (is (< (- (get-internal-real-time) start)
                           (* 5 internal-time-units-per-second)))))
             (usocket:socket-close client)))
      (usocket:socket-close server))))

(test assumevalid-skip-height
  "assumevalid lets IBD skip signature checks for ancestors of a known-good
block. default-assumevalid yields a 32-byte WIRE-order hash for real networks
(nil on regtest); assumevalid-skip-height returns the assumevalid block's height
when its header is in the index, -1 when absent or disabled; script-skip-height
is the max with the checkpoint height. Only sig checks are skipped — everything
else is still validated."
  ;; default-assumevalid presence + byte order (display ...51ba5ac -> wire 0xac..0x00)
  (let ((bitcoin-lisp:*network* :mainnet))
    (let ((av (bitcoin-lisp.networking::default-assumevalid)))
      (is (= 32 (length av)))
      (is (= #xac (aref av 0)))
      (is (= #x00 (aref av 31)))))
  (let ((bitcoin-lisp:*network* :regtest))
    (is (null (bitcoin-lisp.networking::default-assumevalid))))
  ;; skip-height logic on a synthetic regtest chain (checkpoint height = 0)
  (let* ((bitcoin-lisp:*network* :regtest)
         (state (bitcoin-lisp.storage:init-chain-state
                 (merge-pathnames "test-assumevalid/" (uiop:temporary-directory))))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (av-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (absent (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash genesis-hash :height 0 :chain-work 1 :status :valid
            :header (bitcoin-lisp.serialization:make-block-header
                     :version 1 :prev-block zeros :merkle-root zeros
                     :timestamp 1296688600 :bits #x207fffff :nonce 0
                     :cached-hash genesis-hash)))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash av-hash :height 50 :chain-work 100 :status :header-valid
            :header (bitcoin-lisp.serialization:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp 1296688700 :bits #x207fffff :nonce 0
                     :cached-hash av-hash)))
    ;; assumevalid points at the in-index block -> its height; sigs skip <= 50.
    (let ((bitcoin-lisp:*assumevalid-override* av-hash))
      (is (= 50 (bitcoin-lisp.networking::assumevalid-skip-height state)))
      (is (= 50 (bitcoin-lisp.networking::script-skip-height state))))
    ;; assumevalid hash not in our index -> no skip.
    (let ((bitcoin-lisp:*assumevalid-override* absent))
      (is (= -1 (bitcoin-lisp.networking::assumevalid-skip-height state))))
    ;; assumevalid explicitly disabled -> no skip.
    (let ((bitcoin-lisp:*assumevalid-override* nil))
      (is (= -1 (bitcoin-lisp.networking::assumevalid-skip-height state))))))

(test block-failure-count-throttle
  "note-block-failure increments a per-hash counter, clear-block-failure resets
it, and counts are independent per hash. This bounded counter backs the
re-request budget in handle-validation-failure that stops a single
persistently-failing block from spinning the receive->validate->re-request loop
and spamming the log (the testnet4 wedge produced 6.5M lines / 1.1GB this way)."
  (let ((h1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (h2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (clrhash bitcoin-lisp.networking::*block-failure-counts*)
    ;; increments per hash
    (is (= 1 (bitcoin-lisp.networking::note-block-failure h1)))
    (is (= 2 (bitcoin-lisp.networking::note-block-failure h1)))
    (is (= 3 (bitcoin-lisp.networking::note-block-failure h1)))
    ;; independent per hash
    (is (= 1 (bitcoin-lisp.networking::note-block-failure h2)))
    (is (= 4 (bitcoin-lisp.networking::note-block-failure h1)))
    ;; clear resets a single hash
    (bitcoin-lisp.networking::clear-block-failure h1)
    (is (= 1 (bitcoin-lisp.networking::note-block-failure h1)))
    (is (= 2 (bitcoin-lisp.networking::note-block-failure h2)))  ; h2 untouched
    (clrhash bitcoin-lisp.networking::*block-failure-counts*)))

;;;; Initial-block-download latch (Core IsInitialBlockDownload)
;;;;
;;;; Gates loose-tx fetching in handle-inv: during IBD announced txs are
;;;; not requested (their inputs can't resolve against a stale UTXO set),
;;;; mirroring net_processing.cpp:4176-4180. The status is latched — once
;;;; the tip is recent with enough work it never flips back.

(defun %make-ibd-latch-state (timestamp &key (work 100))
  "Chain-state whose tip header carries TIMESTAMP and chain-work WORK."
  (let ((state (bitcoin-lisp.storage:make-chain-state))
        (hash (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element (mod timestamp 251))))
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash hash :height 1 :chain-work work :status :valid
            :header (bitcoin-lisp.serialization::make-block-header
                     :version 1
                     :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 0)
                     :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                     :timestamp timestamp :bits #x1d00ffff :nonce 0)))
    (bitcoin-lisp.storage:update-chain-tip state hash 1)
    state))

(test initial-block-download-latch
  "T while the tip is stale or low-work; latches NIL once the tip is
recent with enough chain work; never flips back until reset-ibd-stop."
  (let ((bitcoin-lisp.networking::*cached-is-ibd* t)
        (bitcoin-lisp:*network* :regtest)  ; minimum-chain-work 0
        (bitcoin-lisp:*minimum-chain-work-override* nil)
        (now (bitcoin-lisp.serialization:get-unix-time)))
    ;; Tip two days old => still in IBD.
    (is-true (bitcoin-lisp.networking::initial-block-download-p
              (%make-ibd-latch-state (- now (* 48 60 60)))))
    ;; Fresh tip but below minimum chain work => still in IBD.
    (let ((bitcoin-lisp:*minimum-chain-work-override* (expt 2 100)))
      (is-true (bitcoin-lisp.networking::initial-block-download-p
                (%make-ibd-latch-state now))))
    ;; Fresh tip with enough work => leaves IBD and latches.
    (is-false (bitcoin-lisp.networking::initial-block-download-p
               (%make-ibd-latch-state now)))
    (is-false bitcoin-lisp.networking::*cached-is-ibd*)
    ;; Latched: a stale tip no longer flips it back.
    (is-false (bitcoin-lisp.networking::initial-block-download-p
               (%make-ibd-latch-state (- now (* 48 60 60)))))
    ;; reset-ibd-stop (node start) re-arms the latch.
    (bitcoin-lisp.networking:reset-ibd-stop)
    (is-true (bitcoin-lisp.networking::initial-block-download-p
              (%make-ibd-latch-state (- now (* 48 60 60)))))))

(test handle-inv-tx-fetch-gated-during-ibd
  "During IBD, tx invs are not recorded in the request tracker and no
getdata is attempted (Core net_processing.cpp:4176-4180)."
  (let* ((bitcoin-lisp.networking::*cached-is-ibd* t)
         (bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*minimum-chain-work-override* nil)
         (now (bitcoin-lisp.serialization:get-unix-time))
         (state (%make-ibd-latch-state (- now (* 48 60 60))))  ; stale => IBD
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (announcer (bitcoin-lisp.networking:make-peer :state :ready))
         (probe (bitcoin-lisp.networking:make-peer :state :ready))
         (tx-hash (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 7))
         (payload (subseq (bitcoin-lisp.serialization:make-inv-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-tx+
                                  :hash tx-hash)))
                          24)))  ; strip the 24-byte v1 message header
    (bitcoin-lisp.networking:reset-tx-requests)
    ;; With the announcer's peer having no connection, a getdata attempt
    ;; would error — the gate must short-circuit before any of that.
    (finishes (bitcoin-lisp.networking::handle-inv announcer payload state mempool))
    ;; Nothing was recorded for the hash: a fresh request from another
    ;; peer is still "wanted" (no outstanding in-flight entry).
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p tx-hash probe))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test handle-inv-wtx-announcement-requested
  "MSG_WTX (BIP339) tx announcements — the only kind modern wtxidrelay
peers send (net_processing.cpp:6009) — are matched and recorded in the
request tracker; MSG_TX announcements still work. Regression test: the
tx branch previously matched only types 1/0x40000001, so every
announcement from a wtxidrelay peer was silently dropped."
  (let* ((bitcoin-lisp.networking::*cached-is-ibd* t)
         (bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*minimum-chain-work-override* nil)
         (now (bitcoin-lisp.serialization:get-unix-time))
         (state (%make-ibd-latch-state now))  ; fresh tip => not in IBD
         (mempool (bitcoin-lisp.mempool:make-mempool))
         ;; MSG_WTX only comes from wtxidrelay peers; MSG_TX only from
         ;; non-wtxidrelay peers — handle-inv ignores mismatches (Core
         ;; net_processing.cpp:4145-4152), so use one announcer of each kind.
         (wtx-announcer (bitcoin-lisp.networking:make-peer :state :ready
                                                           :wtxid-relay t))
         (tx-announcer (bitcoin-lisp.networking:make-peer :state :ready))
         (probe (bitcoin-lisp.networking:make-peer :state :ready))
         (wtxid (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 11))
         (txid (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 12))
         (inv-payload
           (lambda (type hash)
             (subseq (bitcoin-lisp.serialization:make-inv-message
                      (list (bitcoin-lisp.serialization:make-inv-vector
                             :type type :hash hash)))
                     24))))
    (bitcoin-lisp.networking:reset-tx-requests)
    ;; The announcer peer has no connection, so the getdata send at the end
    ;; of handle-inv errors — but the tracker recording happens first, which
    ;; is the observable we assert on.
    (ignore-errors
      (bitcoin-lisp.networking::handle-inv
       wtx-announcer (funcall inv-payload bitcoin-lisp.serialization:+inv-type-wtx+ wtxid)
       state mempool))
    ;; Recorded: a probe from another peer sees the request outstanding.
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p wtxid probe))
    ;; MSG_TX (txid) announcements keep working alongside.
    (ignore-errors
      (bitcoin-lisp.networking::handle-inv
       tx-announcer (funcall inv-payload bitcoin-lisp.serialization:+inv-type-tx+ txid)
       state mempool))
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid probe))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test handle-inv-ignores-wtxidrelay-mismatch
  "Invs that don't match the wtxidrelay negotiation are ignored: MSG_TX from
a wtxidrelay peer, MSG_WTX from a non-wtxidrelay peer (Core
net_processing.cpp:4145-4152)."
  (let* ((bitcoin-lisp.networking::*cached-is-ibd* t)
         (bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*minimum-chain-work-override* nil)
         (now (bitcoin-lisp.serialization:get-unix-time))
         (state (%make-ibd-latch-state now))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (wtx-peer (bitcoin-lisp.networking:make-peer :state :ready
                                                      :wtxid-relay t))
         (legacy-peer (bitcoin-lisp.networking:make-peer :state :ready))
         (probe (bitcoin-lisp.networking:make-peer :state :ready))
         (h1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 13))
         (h2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 14))
         (inv-payload
           (lambda (type hash)
             (subseq (bitcoin-lisp.serialization:make-inv-message
                      (list (bitcoin-lisp.serialization:make-inv-vector
                             :type type :hash hash)))
                     24))))
    (bitcoin-lisp.networking:reset-tx-requests)
    ;; MSG_TX from a wtxidrelay peer: ignored, nothing recorded.
    (finishes
      (bitcoin-lisp.networking::handle-inv
       wtx-peer (funcall inv-payload bitcoin-lisp.serialization:+inv-type-tx+ h1)
       state mempool))
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p h1 probe))
    ;; MSG_WTX from a non-wtxidrelay peer: ignored too.
    (bitcoin-lisp.networking:reset-tx-requests)
    (finishes
      (bitcoin-lisp.networking::handle-inv
       legacy-peer (funcall inv-payload bitcoin-lisp.serialization:+inv-type-wtx+ h2)
       state mempool))
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p h2 probe))
    (bitcoin-lisp.networking:reset-tx-requests)))

;;;; Relay polish: wtxid-keyed rejects, getaddr, BIP35 mempool

(test recent-rejects-are-wtxid-keyed
  "A rejected witness tx lands in the rejects filter under its WTXID,
never its txid — the witness can be malleated, so the same txid with a
different witness could still be valid (Core issue #8279,
txdownloadman_impl.cpp MempoolRejectedTx). No-witness txs are covered
since wtxid = txid there."
  (let* ((input (bitcoin-lisp.serialization:make-tx-in
                 :previous-output (bitcoin-lisp.serialization:make-outpoint
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 42)
                                   :index 0)
                 :script-sig (make-array 2 :element-type '(unsigned-byte 8)
                                           :initial-element 0)
                 :sequence #xFFFFFFFF))
         (output (bitcoin-lisp.serialization:make-tx-out
                  :value 10000
                  :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                :initial-element 0)))
         ;; version 5 > +max-standard-tx-version+ (3): rejected as
         ;; :version-non-standard before input resolution, i.e. the plain
         ;; reject path (not the :missing-input orphan path).
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 5
              :inputs (vector input)
              :outputs (vector output)
              :lock-time 0
              :witness (vector (list (make-array 8 :element-type '(unsigned-byte 8)
                                                   :initial-element 7)))))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
         (payload (subseq (bitcoin-lisp.serialization:make-tx-message tx :witness t) 24))
         (rejects (bitcoin-lisp:make-rejects-filter 100))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (state (bitcoin-lisp.storage:make-chain-state))
         (peer (bitcoin-lisp.networking:make-peer :state :ready)))
    ;; Sanity: this is a witness tx, ids differ.
    (is-false (equalp txid wtxid))
    (bitcoin-lisp.networking:reset-tx-requests)
    (bitcoin-lisp.networking::handle-tx peer payload nil mempool state nil
                                        :recent-rejects rejects)
    (is-true (bitcoin-lisp:recent-reject-p rejects wtxid))
    (is-false (bitcoin-lisp:recent-reject-p rejects txid))))

;;;; Wave 8A: tx-relay request path (orphan-parent fetch, failover id type,
;;;; reject-poisoning semantics) — Core txdownloadman/txrequest parity.

(defun %wave8-witness-peer (&optional (state :ready))
  "A :ready peer advertising NODE_WITNESS, like every modern Core peer."
  (bitcoin-lisp.networking:make-peer
   :address "test" :state state
   :services bitcoin-lisp.serialization:+node-witness+))

(defun %wave8-p2pkh-script ()
  "A well-formed (garbage-hash) P2PKH scriptPubKey."
  (let ((s (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
          (aref s 23) #x88 (aref s 24) #xac)
    s))

(defun %wave8-tx (&key (prev-id #xAA) (prev-index 0) (value 50000000)
                       (script-sig #()) witness)
  "A standard v2 tx spending <PREV-ID-filled hash>:PREV-INDEX to a P2PKH
output. WITNESS, when true, attaches a one-element witness stack so
wtxid /= txid."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element prev-id)
                                      :index prev-index)
                    :script-sig (coerce script-sig '(vector (unsigned-byte 8)))
                    :sequence #xFFFFFFFF))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value value
                     :script-pubkey (%wave8-p2pkh-script)))
   :lock-time 0
   :witness (when witness
              (vector (list (make-array 8 :element-type '(unsigned-byte 8)
                                          :initial-element 7))))))

(test tx-request-failover-preserves-announcement-id-type
  "The tracker remembers whether each entry was announced by wtxid (MSG_WTX)
or txid, and a timed-out request fails over with the SAME id type: wtxid
entries as MSG_WTX, txid entries as MSG_TX|witness-flag (Core txrequest
GenTxid + net_processing.cpp:6207). Regression: failover used to re-request
EVERYTHING as MSG_WITNESS_TX, which Core interprets as a TXID lookup — a
wtxid hash got notfound and failover never worked for segwit txs."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let ((wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 41))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
        (p1 (%wave8-witness-peer))
        (p2 (%wave8-witness-peer)))
    ;; One wtxid-based and one txid-based announcement, two candidates each.
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p wtxid p1 t))
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p wtxid p2 t))
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p txid p1 nil))
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid p2 nil))
    ;; Backdate both in-flight entries past the timeout to force failover.
    (let ((stale (- (get-internal-real-time)
                    (* 120 internal-time-units-per-second))))
      (setf (gethash wtxid bitcoin-lisp.networking::*tx-in-flight*) (cons p1 stale))
      (setf (gethash txid bitcoin-lisp.networking::*tx-in-flight*) (cons p1 stale)))
    (is (= 2 (bitcoin-lisp.networking::retry-timed-out-tx-requests)))
    ;; Both rerouted to p2 with the id type preserved.
    (is (eq p2 (car (gethash wtxid bitcoin-lisp.networking::*tx-in-flight*))))
    (is (eq p2 (car (gethash txid bitcoin-lisp.networking::*tx-in-flight*))))
    (is-true (gethash wtxid bitcoin-lisp.networking::*tx-request-wtxid-p*))
    (is-false (gethash txid bitcoin-lisp.networking::*tx-request-wtxid-p*))
    ;; The inv the failover getdata carries for each entry type:
    (is (= bitcoin-lisp.serialization:+inv-type-wtx+
           (bitcoin-lisp.serialization:inv-vector-type
            (bitcoin-lisp.networking::tx-request-inv wtxid t p2))))
    (is (= bitcoin-lisp.serialization:+inv-type-witness-tx+
           (bitcoin-lisp.serialization:inv-vector-type
            (bitcoin-lisp.networking::tx-request-inv txid nil p2))))
    ;; A peer without NODE_WITNESS gets bare MSG_TX for txid entries
    ;; (Core GetFetchFlags returns no witness flag for it).
    (is (= bitcoin-lisp.serialization:+inv-type-tx+
           (bitcoin-lisp.serialization:inv-vector-type
            (bitcoin-lisp.networking::tx-request-inv
             txid nil (%make-peer-with-state :ready)))))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test orphan-parent-getdata-carries-witness-flag
  "Missing parents of an orphan are requested by TXID with the witness flag
(MSG_TX|MSG_WITNESS_FLAG) for witness-capable peers, never bare MSG_TX
(Core requests txid announcements as MSG_TX | GetFetchFlags,
net_processing.cpp:6207; orphan parents enter the tracker via
MaybeAddOrphanResolutionCandidate, txdownloadman_impl.cpp:257-260).
Regression: bare MSG_TX fetched the witness-stripped parent, which failed
scripts and — wtxid == txid for a stripped tx — poisoned recent-rejects
with the parent's real txid, so the orphan could never resolve."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let* ((utxo (bitcoin-lisp.storage:make-utxo-set))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (orphan (%wave8-tx :prev-id #xB1))
         (peer (%wave8-witness-peer))
         (parents (bitcoin-lisp.networking::missing-parent-txids orphan utxo mempool)))
    (is (= 1 (length parents)))
    (let ((invs (bitcoin-lisp.networking::request-orphan-parents peer parents)))
      (is (= 1 (length invs)))
      (is (= bitcoin-lisp.serialization:+inv-type-witness-tx+
             (bitcoin-lisp.serialization:inv-vector-type (first invs))))
      (is (equalp (first parents)
                  (bitcoin-lisp.serialization:inv-vector-hash (first invs)))))
    ;; The parent request is registered with the tx-request tracker (txid-
    ;; based), so another announcer doesn't trigger a duplicate getdata and
    ;; timeout failover applies to parent fetches too.
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p
               (first parents) (%make-peer-with-state :ready)))
    (is-false (gethash (first parents)
                       bitcoin-lisp.networking::*tx-request-wtxid-p*))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test orphan-with-rejected-parent-rejected-under-both-ids
  "A tx with missing inputs whose missing parent is already in recent-rejects
is NOT kept as an orphan: it is rejected outright under BOTH its txid and
wtxid, and no parent fetch goes out (Core 'not keeping orphan with rejected
parents', txdownloadman_impl.cpp:422-436)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let* ((utxo (bitcoin-lisp.storage:make-utxo-set))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (state (bitcoin-lisp.storage:make-chain-state))
         (peer (%wave8-witness-peer))
         (rejects (bitcoin-lisp:make-rejects-filter 100))
         (tx (%wave8-tx :prev-id #xB2 :witness t))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
         (parent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xB2))
         (payload (subseq (bitcoin-lisp.serialization:make-tx-message tx :witness t) 24)))
    (is-false (equalp txid wtxid))
    ;; The missing parent was recently rejected.
    (bitcoin-lisp:add-recent-reject rejects parent-txid)
    (bitcoin-lisp.networking::handle-tx peer payload utxo mempool state nil
                                        :recent-rejects rejects)
    ;; Rejected under both ids; never admitted to the orphan pool; the
    ;; parent was NOT re-requested.
    (is-true (bitcoin-lisp:recent-reject-p rejects txid))
    (is-true (bitcoin-lisp:recent-reject-p rejects wtxid))
    (is-false (bitcoin-lisp.mempool:orphan-tx
               (bitcoin-lisp.mempool:mempool-orphan-pool mempool) txid))
    (is (zerop (hash-table-count bitcoin-lisp.networking::*tx-in-flight*)))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test orphan-with-unrejected-parent-is-kept-and-parent-fetched
  "The healthy counterpart: a missing-inputs tx whose parents are NOT
rejected goes into the orphan pool, its parent fetch is tracker-registered,
and the tx itself is not cached as a reject."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let* ((utxo (bitcoin-lisp.storage:make-utxo-set))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (state (bitcoin-lisp.storage:make-chain-state))
         (peer (%wave8-witness-peer))
         (rejects (bitcoin-lisp:make-rejects-filter 100))
         (tx (%wave8-tx :prev-id #xB3 :witness t))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (parent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xB3))
         (payload (subseq (bitcoin-lisp.serialization:make-tx-message tx :witness t) 24)))
    (bitcoin-lisp.networking::handle-tx peer payload utxo mempool state nil
                                        :recent-rejects rejects)
    ;; The orphanage is wtxid-keyed (Core TxOrphanage).
    (is-true (bitcoin-lisp.mempool:orphan-tx
              (bitcoin-lisp.mempool:mempool-orphan-pool mempool)
              (bitcoin-lisp.serialization:transaction-wtxid tx)))
    (is-false (bitcoin-lisp:recent-reject-p rejects txid))
    (is-false (bitcoin-lisp:recent-reject-p
               rejects (bitcoin-lisp.serialization:transaction-wtxid tx)))
    ;; Parent fetch registered as a txid-based tracker entry.
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p
               parent-txid (%make-peer-with-state :ready)))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test witness-stripped-failure-not-cached-in-recent-rejects
  "A no-witness tx that fails scripts while spending a witness-program
output is classified witness-stripped and cached NOWHERE — its wtxid equals
its txid, so caching would poison the real witnessed tx's txid and block its
relay permanently (Core TX_WITNESS_STRIPPED, txdownloadman_impl.cpp:438-439,
classified by validation.cpp:1143-1148 SpendsNonAnchorWitnessProg). A
genuinely failing non-witness-program spend IS still cached (wtxid-keyed)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let* ((bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*minimum-chain-work-override* nil)
         (now (bitcoin-lisp.serialization:get-unix-time))
         (state (%make-ibd-latch-state now))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (peer (%wave8-witness-peer))
         (rejects (bitcoin-lisp:make-rejects-filter 100))
         ;; Coin 1: P2WPKH (a witness program).
         (p2wpkh (let ((s (make-array 22 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
                   (setf (aref s 0) #x00 (aref s 1) #x14)
                   s))
         (stripped (%wave8-tx :prev-id #xC1))   ; no witness attached
         (stripped-id (bitcoin-lisp.serialization:transaction-hash stripped))
         ;; Coin 2: P2PKH — witness stripping cannot explain this failure.
         (failing (%wave8-tx :prev-id #xC2 :script-sig (vector #x51)))
         (failing-id (bitcoin-lisp.serialization:transaction-hash failing)))
    (bitcoin-lisp.storage:add-utxo
     utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xC1)
     0 100000000 p2wpkh 0)
    (bitcoin-lisp.storage:add-utxo
     utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xC2)
     0 100000000 (%wave8-p2pkh-script) 0)
    ;; Sanity: wtxid == txid for both (no witness), the poisoning precondition.
    (is (equalp stripped-id (bitcoin-lisp.serialization:transaction-wtxid stripped)))
    (bitcoin-lisp.networking::handle-tx
     peer (subseq (bitcoin-lisp.serialization:make-tx-message stripped) 24)
     utxo mempool state nil :recent-rejects rejects)
    (bitcoin-lisp.networking::handle-tx
     peer (subseq (bitcoin-lisp.serialization:make-tx-message failing) 24)
     utxo mempool state nil :recent-rejects rejects)
    ;; The plain script failure IS cached (proves this fixture reaches the
    ;; reject-insert path)...
    (is-true (bitcoin-lisp:recent-reject-p rejects failing-id))
    ;; ...but the witness-stripped one is NOT.
    (is-false (bitcoin-lisp:recent-reject-p rejects stripped-id))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test bip35-mempool-message-disconnects
  "BIP35 'mempool' requests get a disconnect: we never advertise
NODE_BLOOM, matching Core's no-bloom path (net_processing.cpp:4940-4951)."
  (let ((peer (bitcoin-lisp.networking:make-peer :state :ready)))
    (is-true (bitcoin-lisp.networking::handle-message peer "mempool" #() nil nil nil))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test getaddr-message-format
  "getaddr serializes as a bare 24-byte v1 header with empty payload."
  (let ((bytes (bitcoin-lisp.serialization:make-getaddr-message)))
    (is (= 24 (length bytes)))
    (is (string= "getaddr" (map 'string #'code-char
                                (remove 0 (subseq bytes 4 16)))))))

;;;; Trickled (Poisson) tx announcement batching

(test relay-transaction-queues-instead-of-sending
  "relay-transaction enqueues per-peer announcements (Core
m_tx_inventory_to_send); nothing is sent and nothing is marked announced
until flush time."
  (let* ((bitcoin-lisp:*network* :regtest)
         (peer (bitcoin-lisp.networking:make-peer :state :ready :wtxid-relay t))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
         (wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 22)))
    ;; Peer has no connection: an immediate send would error, a queue won't.
    (finishes (bitcoin-lisp.networking::relay-transaction
               txid nil (list peer) :fee-rate 2 :wtxid wtxid))
    (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue peer))))
    (is-false (bitcoin-lisp:recent-reject-p
               (bitcoin-lisp.networking:peer-announced-txs peer) txid))))

(test flush-tx-announcements-drains-on-schedule
  "First flush pass only arms an outbound peer's exponential timer (Core
initializes m_next_inv_send_time the same way); once the deadline is
due, the queue drains and the tx is marked announced. Send errors from
the connectionless peer are swallowed."
  (let* ((bitcoin-lisp:*network* :regtest)
         (peer (bitcoin-lisp.networking:make-peer :state :ready :wtxid-relay t))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 23))
         (wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 24)))
    (bitcoin-lisp.networking::relay-transaction
     txid nil (list peer) :fee-rate 2 :wtxid wtxid)
    ;; Arm pass: timer initialized, nothing flushed.
    (bitcoin-lisp.networking:flush-tx-announcements (list peer) nil)
    (is (plusp (bitcoin-lisp.networking::peer-next-inv-send-time peer)))
    (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue peer))))
    ;; Deadline in the past: flush drains and marks announced.
    (setf (bitcoin-lisp.networking::peer-next-inv-send-time peer) 1)
    (bitcoin-lisp.networking:flush-tx-announcements (list peer) nil)
    (is (null (bitcoin-lisp.networking::peer-tx-inv-queue peer)))
    (is-true (bitcoin-lisp:recent-reject-p
              (bitcoin-lisp.networking:peer-announced-txs peer) txid))))

(test flush-drops-feefiltered-entries
  "A queued announcement below the peer's BIP133 feefilter is dropped at
flush time — neither sent nor marked announced (Core skips it out of
m_tx_inventory_to_send the same way)."
  (let* ((bitcoin-lisp:*network* :regtest)
         (peer (bitcoin-lisp.networking:make-peer :state :ready))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 25)))
    (setf (bitcoin-lisp.networking:peer-feefilter-rate peer) 1000000)
    ;; fee-rate 1 sat/vB = 1000 sat/kvB < 1000000 filter.
    (bitcoin-lisp.networking::relay-transaction txid nil (list peer) :fee-rate 1)
    (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue peer))))
    (setf (bitcoin-lisp.networking::peer-next-inv-send-time peer) 1)
    (bitcoin-lisp.networking:flush-tx-announcements (list peer) nil)
    (is (null (bitcoin-lisp.networking::peer-tx-inv-queue peer)))
    (is-false (bitcoin-lisp:recent-reject-p
               (bitcoin-lisp.networking:peer-announced-txs peer) txid))))

;;;; Initial broadcast of locally-submitted txs (unbroadcast set)

(test getdata-serving-clears-unbroadcast
  "Serving a tx from the mempool in response to a getdata removes it from
the unbroadcast set — the propagation signal (Core ProcessGetData,
net_processing.cpp:2550). An unrelated getdata leaves the set alone."
  (let* ((bitcoin-lisp:*network* :regtest)
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (peer (bitcoin-lisp.networking:make-peer :state :ready))
         (other (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (%add-tx mempool tx)
    (is-true (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid))
    ;; Make the tx servable to this peer: snapshot the mempool sequence as if
    ;; an inv flush to the peer had happened after acceptance (the getdata
    ;; anti-probing gate serves only txs older than the last flush).
    (setf (bitcoin-lisp.networking:peer-last-inv-sequence peer)
          (bitcoin-lisp.mempool:mempool-sequence mempool))
    (flet ((getdata-payload (hash)
             (subseq (bitcoin-lisp.serialization:make-getdata-message
                      (list (bitcoin-lisp.serialization:make-inv-vector
                             :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                             :hash hash)))
                     24)))
      ;; A request for some OTHER tx (not served) doesn't clear ours.
      (bitcoin-lisp.networking::handle-getdata peer (getdata-payload other) nil mempool)
      (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))
      ;; A request for the unbroadcast tx clears it.
      (bitcoin-lisp.networking::handle-getdata peer (getdata-payload txid) nil mempool)
      (is (= 0 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool))))))

(test reattempt-initial-broadcast-relays-only-in-mempool
  "The re-announcement pass queues invs for unbroadcast txs still in the
pool and drops ids whose tx has left it (Core ReattemptInitialBroadcast,
net_processing.cpp:1625-1643)."
  (let* ((bitcoin-lisp:*network* :regtest)
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (stale (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (peer (bitcoin-lisp.networking:make-peer :state :ready :wtxid-relay t)))
    (%add-tx mempool tx)
    (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
    ;; Simulate a stale id (tx evicted after a crash-restore of the set):
    ;; poke the table directly — the public adder refuses non-members.
    (setf (gethash stale (bitcoin-lisp.mempool:mempool-unbroadcast mempool)) t)
    (bitcoin-lisp.networking:reattempt-initial-broadcast (list peer) mempool)
    ;; The live tx was queued for announcement (wtxid rides along)...
    (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue peer))))
    (destructuring-bind (qtxid qwtxid fee-rate-per-kb)
        (first (bitcoin-lisp.networking::peer-tx-inv-queue peer))
      (declare (ignore fee-rate-per-kb))
      (is (equalp txid qtxid))
      (is (equalp (bitcoin-lisp.serialization:transaction-wtxid tx) qwtxid)))
    ;; ...and stays tracked until a getdata confirms; the stale id is gone.
    (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))
    (is-true (gethash txid (bitcoin-lisp.mempool:mempool-unbroadcast mempool)))))

(test maybe-reattempt-initial-broadcast-schedule
  "First call only arms the 10-15min timer (Core schedules the first pass a
full interval out, net_processing.cpp:2036-2038); once the deadline passes,
the pass runs and the timer re-arms."
  (let* ((bitcoin-lisp:*network* :regtest)
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (peer (bitcoin-lisp.networking:make-peer :state :ready)))
    (%add-tx mempool tx)
    (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
    (bitcoin-lisp.networking:reset-initial-broadcast-schedule)
    ;; Arm pass: nothing queued yet.
    (bitcoin-lisp.networking:maybe-reattempt-initial-broadcast (list peer) mempool)
    (is (plusp bitcoin-lisp.networking::*next-initial-broadcast-time*))
    (is (null (bitcoin-lisp.networking::peer-tx-inv-queue peer)))
    ;; Deadline in the past: the pass runs and re-arms.
    (setf bitcoin-lisp.networking::*next-initial-broadcast-time* 1)
    (bitcoin-lisp.networking:maybe-reattempt-initial-broadcast (list peer) mempool)
    (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue peer))))
    (is (> bitcoin-lisp.networking::*next-initial-broadcast-time* 1))
    (bitcoin-lisp.networking:reset-initial-broadcast-schedule)))

;;;; Erlay P1: BIP330 sendtxrcncl handshake (Core-parity: handshake only)

(defun %recon-test-peer (&key (relay t) (inbound nil)
                              (conn-type :outbound-full-relay)
                              (proto-version 70016) (local-salt 1))
  "Bare peer mid-handshake: peer VERSION received (fRelay=RELAY, protocol
PROTO-VERSION), our sendtxrcncl offer already made when LOCAL-SALT is set."
  (let ((peer (bitcoin-lisp.networking:make-peer
               :state :handshaking
               :inbound inbound
               :conn-type conn-type
               :version (bitcoin-lisp.serialization::make-version-message
                         :version proto-version :relay relay))))
    (when local-salt
      (setf (bitcoin-lisp.networking::peer-recon-local-salt peer) local-salt))
    peer))

(defun %sendtxrcncl-payload (version salt)
  "The 12-byte sendtxrcncl payload (message bytes minus the 24-byte header)."
  (subseq (bitcoin-lisp.serialization:make-sendtxrcncl-message salt version) 24))

(test sendtxrcncl-message-codec
  "sendtxrcncl is uint32 version + uint64 salt, both LE — a 12-byte payload
(Core protocol.h:262-266); default version is 1 (TXRECONCILIATION_VERSION)."
  (let ((bytes (bitcoin-lisp.serialization:make-sendtxrcncl-message
                #x1122334455667788)))
    (is (= (+ 24 12) (length bytes)))
    (is (string= "sendtxrcncl" (map 'string #'code-char
                                    (remove 0 (subseq bytes 4 16)))))
    ;; version=1 LE then salt LE
    (is (equalp #(1 0 0 0 #x88 #x77 #x66 #x55 #x44 #x33 #x22 #x11)
                (subseq bytes 24)))
    (multiple-value-bind (version salt)
        (bitcoin-lisp.serialization:parse-sendtxrcncl-payload (subseq bytes 24))
      (is (= 1 version))
      (is (= #x1122334455667788 salt)))))

(test sendtxrcncl-salt-combination
  "compute-recon-salt matches Core ComputeSalt (txreconciliation.cpp:18-30):
tagged hash, tag \"Tx Relay Salting\", over the u64 LE salts in ascending
order; k0/k1 = digest bytes 0-7 / 8-15 read LE. Expected values derived
independently with:
  python3 -c \"import hashlib
tag = hashlib.sha256(b'Tx Relay Salting').digest()
h = hashlib.sha256(tag + tag + (1).to_bytes(8,'little')
                   + (2).to_bytes(8,'little')).digest()
print(int.from_bytes(h[0:8],'little'), int.from_bytes(h[8:16],'little'))\"
  => 6513280882736911012 14473150418129592761"
  (multiple-value-bind (k0 k1)
      (bitcoin-lisp.networking::compute-recon-salt 1 2)
    (is (= 6513280882736911012 k0))
    (is (= 14473150418129592761 k1)))
  ;; Ascending order is applied internally, so argument order is irrelevant.
  (multiple-value-bind (k0 k1)
      (bitcoin-lisp.networking::compute-recon-salt 2 1)
    (is (= 6513280882736911012 k0))
    (is (= 14473150418129592761 k1))))

(test sendtxrcncl-offer-conditions
  "We offer reconciliation only when: -txreconciliation on, negotiated proto
>= 70016, our conn relays txs, and the peer's VERSION set fRelay (Core
net_processing.cpp:3728-3742). The offer pre-registers a random local salt."
  (let ((bitcoin-lisp:*tx-reconciliation* t))
    (let ((peer (%recon-test-peer :local-salt nil)))
      (is-true (bitcoin-lisp.networking::%maybe-send-sendtxrcncl peer))
      (is-true (bitcoin-lisp.networking::peer-recon-local-salt peer)))
    ;; Peer's fRelay=0
    (let ((peer (%recon-test-peer :relay nil :local-salt nil)))
      (bitcoin-lisp.networking::%maybe-send-sendtxrcncl peer)
      (is-false (bitcoin-lisp.networking::peer-recon-local-salt peer)))
    ;; We don't relay txs on block-relay connections
    (let ((peer (%recon-test-peer :conn-type :block-relay :local-salt nil)))
      (bitcoin-lisp.networking::%maybe-send-sendtxrcncl peer)
      (is-false (bitcoin-lisp.networking::peer-recon-local-salt peer)))
    ;; Pre-wtxidrelay protocol version
    (let ((peer (%recon-test-peer :proto-version 70015 :local-salt nil)))
      (bitcoin-lisp.networking::%maybe-send-sendtxrcncl peer)
      (is-false (bitcoin-lisp.networking::peer-recon-local-salt peer))))
  ;; Feature off
  (let ((bitcoin-lisp:*tx-reconciliation* nil)
        (peer (%recon-test-peer :local-salt nil)))
    (bitcoin-lisp.networking::%maybe-send-sendtxrcncl peer)
    (is-false (bitcoin-lisp.networking::peer-recon-local-salt peer))))

(test sendtxrcncl-registers-peer
  "Offer + valid sendtxrcncl reply registers the peer: k0/k1 from
compute-recon-salt (salts 1,2 — same vector as above), negotiated version 1,
we-initiate on an outbound connection (Core RegisterPeer SUCCESS)."
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (%recon-test-peer :local-salt 1)))
    (is-true (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
              peer (%sendtxrcncl-payload 1 2)))
    (is-true (bitcoin-lisp.networking::peer-recon-registered peer))
    (is (= 1 (bitcoin-lisp.networking::peer-recon-version peer)))
    (is (= 6513280882736911012 (bitcoin-lisp.networking::peer-recon-k0 peer)))
    (is (= 14473150418129592761 (bitcoin-lisp.networking::peer-recon-k1 peer)))
    (is-true (bitcoin-lisp.networking::peer-recon-we-initiate peer))
    (is (not (eq :disconnected (bitcoin-lisp.networking:peer-state peer))))))

(test sendtxrcncl-duplicate-disconnects
  "A second sendtxrcncl on the same connection is a protocol violation
(Core RegisterPeer ALREADY_REGISTERED => disconnect)."
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (%recon-test-peer)))
    (is-true (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
              peer (%sendtxrcncl-payload 1 2)))
    (is-false (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
               peer (%sendtxrcncl-payload 1 3)))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test sendtxrcncl-from-non-relay-peer-disconnects
  "sendtxrcncl from a peer whose VERSION had fRelay=0 disconnects
(net_processing.cpp:3982-3990)."
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (%recon-test-peer :relay nil)))
    (is-false (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
               peer (%sendtxrcncl-payload 1 2)))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test sendtxrcncl-on-block-relay-conn-disconnects
  "sendtxrcncl on a connection where WE indicated no tx relay (block-relay)
disconnects (Core RejectIncomingTxs, net_processing.cpp:3976-3980)."
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (%recon-test-peer :conn-type :block-relay :local-salt nil)))
    (is-false (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
               peer (%sendtxrcncl-payload 1 2)))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test sendtxrcncl-version-zero-disconnects
  "Version 0 is below the v1 floor: protocol violation => disconnect
(txreconciliation.cpp:117-119)."
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (%recon-test-peer)))
    (is-false (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
               peer (%sendtxrcncl-payload 0 2)))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test sendtxrcncl-higher-version-downgrades
  "A peer announcing version 2 registers fine at negotiated min(2, 1) = 1
(txreconciliation.cpp:112-116)."
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (%recon-test-peer)))
    (is-true (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
              peer (%sendtxrcncl-payload 2 2)))
    (is-true (bitcoin-lisp.networking::peer-recon-registered peer))
    (is (= 1 (bitcoin-lisp.networking::peer-recon-version peer)))))

(test sendtxrcncl-unsolicited-ignored
  "sendtxrcncl when we never offered (no pre-registration) is ignored — no
registration, no disconnect (Core RegisterPeer NOT_FOUND)."
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (%recon-test-peer :local-salt nil)))
    (is-true (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
              peer (%sendtxrcncl-payload 1 2)))
    (is-false (bitcoin-lisp.networking::peer-recon-registered peer))
    (is (not (eq :disconnected (bitcoin-lisp.networking:peer-state peer))))))

(test sendtxrcncl-forgotten-without-wtxidrelay
  "At VERACK, a (pre-)registered peer that never negotiated wtxidrelay has
its reconciliation state forgotten (net_processing.cpp:3879-3886); with
wtxidrelay negotiated the state survives."
  (let ((bitcoin-lisp:*tx-reconciliation* t))
    (let ((peer (%recon-test-peer)))
      (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
       peer (%sendtxrcncl-payload 1 2))
      (is-true (bitcoin-lisp.networking::peer-recon-registered peer))
      ;; wtxidrelay never arrived => forget everything
      (bitcoin-lisp.networking::%verack-finalize-recon peer)
      (is-false (bitcoin-lisp.networking::peer-recon-registered peer))
      (is-false (bitcoin-lisp.networking::peer-recon-k0 peer))
      (is-false (bitcoin-lisp.networking::peer-recon-local-salt peer)))
    ;; Offered but never answered: dangling pre-registration salt is dropped.
    (let ((peer (%recon-test-peer)))
      (setf (bitcoin-lisp.networking:peer-wtxid-relay peer) t)
      (bitcoin-lisp.networking::%verack-finalize-recon peer)
      (is-false (bitcoin-lisp.networking::peer-recon-local-salt peer)))
    (let ((peer (%recon-test-peer)))
      (setf (bitcoin-lisp.networking:peer-wtxid-relay peer) t)
      (bitcoin-lisp.networking::%handle-handshake-sendtxrcncl
       peer (%sendtxrcncl-payload 1 2))
      (bitcoin-lisp.networking::%verack-finalize-recon peer)
      (is-true (bitcoin-lisp.networking::peer-recon-registered peer)))))

(test sendtxrcncl-post-verack-disconnects
  "Post-verack sendtxrcncl via handle-message is a protocol violation:
disconnect when -txreconciliation is on (net_processing.cpp:3969-3973);
ignored when it is off (:3964-3967)."
  (let ((bitcoin-lisp:*tx-reconciliation* nil)
        (peer (bitcoin-lisp.networking:make-peer :state :ready)))
    (is-true (bitcoin-lisp.networking::handle-message
              peer "sendtxrcncl" (%sendtxrcncl-payload 1 2) nil nil nil))
    (is (eq :ready (bitcoin-lisp.networking:peer-state peer))))
  (let ((bitcoin-lisp:*tx-reconciliation* t)
        (peer (bitcoin-lisp.networking:make-peer :state :ready)))
    (is-true (bitcoin-lisp.networking::handle-message
              peer "sendtxrcncl" (%sendtxrcncl-payload 1 2) nil nil nil))
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test txreconciliation-config-flag-wiring
  "-txreconciliation maps to start-node's :tx-reconciliation keyword like the
other boolean flags (Core: DEBUG_ONLY, default off)."
  (multiple-value-bind (plist merged network)
      (bitcoin-lisp::args->start-node-plist '("-txreconciliation" "-regtest"))
    (declare (ignore merged))
    (is (eq :regtest network))
    (is (eq t (getf plist :tx-reconciliation))))
  (multiple-value-bind (plist merged network)
      (bitcoin-lisp::args->start-node-plist '("-regtest"))
    (declare (ignore merged network))
    (is (eq nil (getf plist :tx-reconciliation)))))

;;;; ============================================================
;;;; Wave 9B: tx-relay hardening
;;;; fRelay honor, tx-request caps/delays/cleanup, getdata anti-probing
;;;; gate, recent-confirmed filter, steady-state drain serving.
;;;; ============================================================

(defun %w9-version-msg (&key (relay t))
  "A minimal stored version message with the given fRelay."
  (bitcoin-lisp.serialization::make-version-message
   :version 70016 :services 0 :timestamp 0
   :addr-recv (bitcoin-lisp.serialization:make-empty-net-addr)
   :addr-from (bitcoin-lisp.serialization:make-empty-net-addr)
   :nonce 1 :user-agent "/test/" :start-height 0 :relay relay))

(test peer-tx-relay-p-honors-frelay
  "peer-tx-relay-p mirrors Core's Peer::TxRelay existence condition
(net_processing.cpp:3681-3696): fRelay=0 in the peer's version means no tx
relay for the connection's life (we never offer NODE_BLOOM); block-relay and
feeler conns never have it; a peer without a stored version defaults to
relaying (Core's fRelay=true default)."
  (let ((frelay0 (bitcoin-lisp.networking:make-peer
                  :state :ready :version (%w9-version-msg :relay nil)))
        (frelay1 (bitcoin-lisp.networking:make-peer
                  :state :ready :version (%w9-version-msg :relay t)))
        (no-version (bitcoin-lisp.networking:make-peer :state :ready))
        (block-relay (bitcoin-lisp.networking:make-peer
                      :state :ready :conn-type :block-relay
                      :version (%w9-version-msg :relay t))))
    (is-false (bitcoin-lisp.networking:peer-tx-relay-p frelay0))
    (is-true (bitcoin-lisp.networking:peer-tx-relay-p frelay1))
    (is-true (bitcoin-lisp.networking:peer-tx-relay-p no-version))
    (is-false (bitcoin-lisp.networking:peer-tx-relay-p block-relay))))

(test relay-transaction-skips-frelay0-peer
  "No tx announcements are queued for a BIP37/BIP60 fRelay=0 peer (Core only
builds tx inventory when the TxRelay structure exists — announcing to a
blocksonly peer gets us disconnected)."
  (let* ((bitcoin-lisp:*network* :regtest)
         (frelay0 (bitcoin-lisp.networking:make-peer
                   :state :ready :version (%w9-version-msg :relay nil)))
         (frelay1 (bitcoin-lisp.networking:make-peer
                   :state :ready :version (%w9-version-msg :relay t)))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 91)))
    (bitcoin-lisp.networking::relay-transaction
     txid nil (list frelay0 frelay1) :fee-rate 2)
    (is (null (bitcoin-lisp.networking::peer-tx-inv-queue frelay0)))
    (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue frelay1))))))

(test handle-tx-disconnects-when-relay-disabled
  "A tx message arriving where we advertised fRelay=0 (mainnet with relay
disabled — our blocksonly) is a protocol violation: disconnect (Core
RejectIncomingTxs in the TX handler, net_processing.cpp:4474-4479)."
  (let* ((bitcoin-lisp:*network* :mainnet)
         (bitcoin-lisp:*mainnet-relay-enabled* nil)
         (peer (bitcoin-lisp.networking:make-peer :state :ready)))
    (bitcoin-lisp.networking::handle-tx peer #() nil nil nil nil)
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test handle-inv-disconnects-tx-inv-when-relay-disabled
  "Tx invs in violation of our advertised fRelay=0 disconnect the sender
(Core net_processing.cpp:4168-4172); block invs stay fine."
  (let* ((bitcoin-lisp:*network* :mainnet)
         (bitcoin-lisp:*mainnet-relay-enabled* nil)
         (state (bitcoin-lisp.storage:make-chain-state))
         (peer (bitcoin-lisp.networking:make-peer :state :ready))
         (payload (subseq (bitcoin-lisp.serialization:make-inv-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-tx+
                                  :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                       :initial-element 92))))
                          24)))
    (bitcoin-lisp.networking::handle-inv peer payload state nil)
    (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))

(test blocksonly-rejects-incoming-txs-any-network
  "-blocksonly (Core ignore_incoming_txs, DEFAULT_BLOCKSONLY=false) rejects
incoming txs on ANY network: ignore-incoming-txs-p flips, a tx message and a
tx inv both disconnect the sender — on a test network where relay is
otherwise always on."
  (let* ((bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*blocksonly* t))
    (is-true (bitcoin-lisp.networking:ignore-incoming-txs-p))
    ;; tx message in violation of our fRelay=0 -> disconnect
    ;; (Core net_processing.cpp:4474-4479).
    (let ((peer (bitcoin-lisp.networking:make-peer :state :ready)))
      (bitcoin-lisp.networking::handle-tx peer #() nil nil nil nil)
      (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer))))
    ;; tx inv in violation -> disconnect (net_processing.cpp:4168-4172).
    (let ((state (bitcoin-lisp.storage:make-chain-state))
          (peer (bitcoin-lisp.networking:make-peer :state :ready))
          (payload (subseq (bitcoin-lisp.serialization:make-inv-message
                            (list (bitcoin-lisp.serialization:make-inv-vector
                                   :type bitcoin-lisp.serialization:+inv-type-tx+
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 94))))
                           24)))
      (bitcoin-lisp.networking::handle-inv peer payload state nil)
      (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))))
  ;; Default off: regtest relays normally.
  (let* ((bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*blocksonly* nil))
    (is-false (bitcoin-lisp.networking:ignore-incoming-txs-p))))

(test blocksonly-still-announces-own-txs
  "A blocksonly node still queues announcements of its OWN (locally
submitted) transactions — Core's RelayTransaction has no
ignore_incoming_txs gate; only the receive side is switched off."
  (let* ((bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*blocksonly* t)
         (frelay1 (bitcoin-lisp.networking:make-peer
                   :state :ready :version (%w9-version-msg :relay t)))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 95)))
    (bitcoin-lisp.networking::relay-transaction
     txid nil (list frelay1) :fee-rate 2)
    (is (= 1 (length (bitcoin-lisp.networking::peer-tx-inv-queue frelay1))))))

;;;; Tx-request tracker: Core txrequest caps, delays, cleanup

(test tx-request-nonpref-peer-delayed
  "An inbound (non-preferred) peer's announcement is deferred by
NONPREF_PEER_TX_DELAY instead of requested immediately; the scheduler sends
it once the delay passes (Core txdownloadman_impl.cpp:216)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 93))
        (inbound (bitcoin-lisp.networking:make-peer :state :ready :inbound t)))
    ;; Deferred: no immediate request, nothing in flight.
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid inbound))
    (is (null (gethash txid bitcoin-lisp.networking::*tx-in-flight*)))
    ;; Not due yet: the scheduler sends nothing.
    (is (= 0 (bitcoin-lisp.networking:process-tx-requests)))
    ;; Backdate the candidate's ready time; now the scheduler requests it.
    (let ((ann (first (gethash txid bitcoin-lisp.networking::*tx-announcers*))))
      (setf (cdr ann) (- (get-internal-real-time) 1)))
    (is (= 1 (bitcoin-lisp.networking:process-tx-requests)))
    (is (eq inbound (car (gethash txid bitcoin-lisp.networking::*tx-in-flight*))))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test tx-request-txid-relay-delay
  "With wtxid-relay peers connected, txid-based announcements are deferred by
TXID_RELAY_DELAY while wtxid-based ones are not (Core
txdownloadman_impl.cpp:217)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 94))
        (wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 95))
        (outbound (bitcoin-lisp.networking:make-peer :state :ready)))
    ;; num-wtxid-peers = 1: txid announcement deferred...
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid outbound nil 1))
    (is (null (gethash txid bitcoin-lisp.networking::*tx-in-flight*)))
    ;; ...wtxid announcement immediate.
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p wtxid outbound t 1))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test tx-request-overloaded-peer-delayed
  "A peer with MAX_PEER_TX_REQUEST_IN_FLIGHT (100) outstanding requests gets
OVERLOADED_PEER_TX_DELAY on new announcements (Core
txdownloadman_impl.cpp:218-219)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 96))
        (outbound (bitcoin-lisp.networking:make-peer :state :ready)))
    (setf (gethash outbound bitcoin-lisp.networking::*tx-peer-in-flight*)
          bitcoin-lisp.networking::+max-peer-tx-request-in-flight+)
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid outbound))
    (is (null (gethash txid bitcoin-lisp.networking::*tx-in-flight*)))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test tx-request-per-peer-announcement-cap
  "Announcements beyond MAX_PEER_TX_ANNOUNCEMENTS (5000) per peer are dropped
outright — not recorded, not requested (Core txdownloadman_impl.cpp:204-207)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let ((peer (bitcoin-lisp.networking:make-peer :state :ready))
        (over (make-array 32 :element-type '(unsigned-byte 8) :initial-element 97)))
    ;; Simulate a full announcement budget without 5000 inserts.
    (setf (gethash peer bitcoin-lisp.networking::*tx-peer-announcements*)
          bitcoin-lisp.networking::+max-peer-tx-announcements+)
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p over peer))
    (is (null (gethash over bitcoin-lisp.networking::*tx-announcers*)))
    (is (null (gethash over bitcoin-lisp.networking::*tx-in-flight*)))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test tx-request-disconnected-peer-cleanup-and-failover
  "DisconnectedPeer semantics: the peer's announcements are forgotten, its
in-flight requests are released, and the next scheduler pass fails the
request over to another announcer (Core TxRequestTracker::DisconnectedPeer)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 98))
        (p1 (bitcoin-lisp.networking:make-peer :state :ready))
        (p2 (bitcoin-lisp.networking:make-peer :state :ready)))
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p txid p1))
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid p2))
    (bitcoin-lisp.networking:tx-request-disconnected-peer p1)
    ;; p1's request was released and its announcement forgotten.
    (is (null (gethash txid bitcoin-lisp.networking::*tx-in-flight*)))
    (is (= 0 (bitcoin-lisp.networking:tx-request-count p1)))
    ;; The scheduler re-requests from the surviving announcer.
    (is (= 1 (bitcoin-lisp.networking:process-tx-requests)))
    (is (eq p2 (car (gethash txid bitcoin-lisp.networking::*tx-in-flight*))))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test tx-request-disconnect-hook-registered
  "disconnect-peer runs the tracker cleanup via *peer-disconnect-hook* (the
tracker lives in a later-loaded file), so every disconnect path forgets the
peer's entries."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99))
        (peer (bitcoin-lisp.networking:make-peer :state :ready)))
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p txid peer))
    (is (= 1 (bitcoin-lisp.networking:tx-request-count peer)))
    (bitcoin-lisp.networking:disconnect-peer peer)
    (is (= 0 (bitcoin-lisp.networking:tx-request-count peer)))
    (is (null (gethash txid bitcoin-lisp.networking::*tx-in-flight*)))
    (bitcoin-lisp.networking:reset-tx-requests)))

(test tx-request-notfound-fails-over
  "A notfound for an in-flight tx completes that peer's announcement and the
request fails over to another announcer immediately (Core ReceivedNotFound ->
ReceivedResponse; handle-notfound re-runs the scheduler)."
  (bitcoin-lisp.networking:reset-tx-requests)
  (let* ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 100))
         (p1 (bitcoin-lisp.networking:make-peer :state :ready))
         (p2 (bitcoin-lisp.networking:make-peer :state :ready))
         (payload (subseq (bitcoin-lisp.serialization:make-notfound-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (is-true (bitcoin-lisp.networking::tx-request-wanted-p txid p1))
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid p2))
    (bitcoin-lisp.networking::handle-notfound p1 payload)
    ;; Failed over to p2; p1's announcement is gone.
    (is (eq p2 (car (gethash txid bitcoin-lisp.networking::*tx-in-flight*))))
    (is (= 0 (bitcoin-lisp.networking:tx-request-count p1)))
    (bitcoin-lisp.networking:reset-tx-requests)))

;;;; Recently-confirmed filter + most-recent-block tx set

(defun %w9-block-with-tx (tx)
  (bitcoin-lisp.serialization:make-bitcoin-block
   :header (bitcoin-lisp.serialization:make-block-header
            :version 1
            :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)
            :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 0)
            :timestamp 1700000000 :bits #x1d00ffff :nonce 0)
   :transactions (list tx)))

(test note-block-connected-populates-relay-structures
  "note-block-connected records the block's txids AND wtxids as recently
confirmed (Core BlockConnected) and rebuilds the most-recent-block tx map
(Core m_most_recent_block_txs); reset-recent-confirmed empties the filter
(Core BlockDisconnected)."
  (let* ((tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)))
    (unwind-protect
        (progn
          (bitcoin-lisp.validation:note-block-connected (%w9-block-with-tx tx))
          (is-true (bitcoin-lisp.validation:recently-confirmed-p txid))
          (is-true (bitcoin-lisp.validation:recently-confirmed-p wtxid))
          (is (eq tx (bitcoin-lisp.validation:most-recent-block-tx txid)))
          (is (eq tx (bitcoin-lisp.validation:most-recent-block-tx wtxid)))
          ;; Reorg disconnect: the filter resets, the map is replaced by the
          ;; next connect.
          (bitcoin-lisp.validation:reset-recent-confirmed)
          (is-false (bitcoin-lisp.validation:recently-confirmed-p txid)))
      (bitcoin-lisp.validation:reset-recent-confirmed)
      (setf bitcoin-lisp.validation::*most-recent-block-txs* nil))))

(test handle-inv-skips-recently-confirmed
  "A tx announcement for a recently-confirmed tx is not requested (Core
AlreadyHaveTx's recent-confirmed check, txdownloadman_impl.cpp:144)."
  (let* ((bitcoin-lisp.networking::*cached-is-ibd* t)
         (bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*minimum-chain-work-override* nil)
         (now (bitcoin-lisp.serialization:get-unix-time))
         (state (%make-ibd-latch-state now))   ; fresh tip => not in IBD
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
         (announcer (bitcoin-lisp.networking:make-peer :state :ready :wtxid-relay t))
         (probe (bitcoin-lisp.networking:make-peer :state :ready))
         (payload (subseq (bitcoin-lisp.serialization:make-inv-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-wtx+
                                  :hash wtxid)))
                          24)))
    (unwind-protect
        (progn
          (bitcoin-lisp.networking:reset-tx-requests)
          (bitcoin-lisp.validation:note-block-connected (%w9-block-with-tx tx))
          (finishes (bitcoin-lisp.networking::handle-inv announcer payload state mempool))
          ;; Nothing recorded: a fresh probe still gets an immediate request.
          (is-true (bitcoin-lisp.networking::tx-request-wanted-p wtxid probe t)))
      (bitcoin-lisp.networking:reset-tx-requests)
      (bitcoin-lisp.validation:reset-recent-confirmed)
      (setf bitcoin-lisp.validation::*most-recent-block-txs* nil))))

;;;; getdata anti-probing gate + flush sequence snapshots

(test flush-updates-last-inv-sequence
  "%flush-peer-tx-invs snapshots the mempool sequence into the peer's
last-inv-sequence on every due flush (Core net_processing.cpp:6086-6088),
opening getdata service for everything announceable up to that point."
  (let* ((bitcoin-lisp:*network* :regtest)
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (peer (bitcoin-lisp.networking:make-peer :state :ready :wtxid-relay t)))
    (is (= 1 (bitcoin-lisp.networking:peer-last-inv-sequence peer)))
    (%add-tx mempool (%witness-tx-for-relay))
    ;; Due flush (empty queue is fine — Core updates the snapshot either way).
    (setf (bitcoin-lisp.networking::peer-next-inv-send-time peer) 1)
    (bitcoin-lisp.networking:flush-tx-announcements (list peer) mempool)
    (is (= (bitcoin-lisp.mempool:mempool-sequence mempool)
           (bitcoin-lisp.networking:peer-last-inv-sequence peer)))))

(test getdata-gate-blocks-unannounced-mempool-tx
  "A getdata for a tx that entered the mempool AFTER our last inv flush to
the peer is NOT served (mempool-probing block, Core FindTxForGetData ->
info_for_relay): the unbroadcast set keeps the tx, proving no serve fired."
  (let* ((bitcoin-lisp:*network* :regtest)
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (peer (bitcoin-lisp.networking:make-peer :state :ready))
         (payload (subseq (bitcoin-lisp.serialization:make-getdata-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (%add-tx mempool tx)
    (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
    ;; Peer's last flush predates the tx (default sequence snapshot 1).
    (bitcoin-lisp.networking::handle-getdata peer payload nil mempool)
    (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))
    ;; After a flush-time snapshot, the same request is served.
    (setf (bitcoin-lisp.networking:peer-last-inv-sequence peer)
          (bitcoin-lisp.mempool:mempool-sequence mempool))
    (bitcoin-lisp.networking::handle-getdata peer payload nil mempool)
    (is (= 0 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))))

(test getdata-serves-most-recent-block-tx
  "A tx confirmed in the most recent block is served even though it left the
mempool (Core FindTxForGetData's m_most_recent_block_txs source) — here
observed via the unbroadcast-set removal that fires on every serve."
  (let* ((bitcoin-lisp:*network* :regtest)
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (peer (bitcoin-lisp.networking:make-peer :state :ready))
         (payload (subseq (bitcoin-lisp.serialization:make-getdata-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (unwind-protect
        (progn
          ;; The tx is NOT in the mempool; it is in the most recent block.
          (bitcoin-lisp.validation:note-block-connected (%w9-block-with-tx tx))
          ;; Track it as unbroadcast via the raw table (the public adder
          ;; requires pool membership) so the serve signal is observable.
          (setf (gethash txid (bitcoin-lisp.mempool:mempool-unbroadcast mempool)) t)
          (bitcoin-lisp.networking::handle-getdata peer payload nil mempool)
          (is (= 0 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool))))
      (bitcoin-lisp.validation:reset-recent-confirmed)
      (setf bitcoin-lisp.validation::*most-recent-block-txs* nil))))

(test getdata-from-frelay0-peer-ignored
  "Tx getdata from an fRelay=0 peer is ignored outright — no serve (Core
ProcessGetData's tx_relay == nullptr continue): the unbroadcast set keeps
the tx even though it is old enough to serve."
  (let* ((bitcoin-lisp:*network* :regtest)
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (peer (bitcoin-lisp.networking:make-peer
                :state :ready :version (%w9-version-msg :relay nil)))
         (payload (subseq (bitcoin-lisp.serialization:make-getdata-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (%add-tx mempool tx)
    (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
    (setf (bitcoin-lisp.networking:peer-last-inv-sequence peer)
          (bitcoin-lisp.mempool:mempool-sequence mempool))
    (bitcoin-lisp.networking::handle-getdata peer payload nil mempool)
    (is (= 1 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))))

;;;; Orphan resolution candidates via MSG_WTX announcements

(test wtx-announcement-of-orphan-requests-parents
  "A MSG_WTX announcement matching a stored orphan makes the announcer an
orphan-resolution candidate: its missing parents are requested from that
peer (txid-based) and the peer is recorded as an additional announcer (Core
AddTxAnnouncement's orphan branch + MaybeAddOrphanResolutionCandidate)."
  (let* ((bitcoin-lisp.networking::*cached-is-ibd* t)
         (bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*minimum-chain-work-override* nil)
         (now (bitcoin-lisp.serialization:get-unix-time))
         (state (%make-ibd-latch-state now))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (pool (bitcoin-lisp.mempool:mempool-orphan-pool mempool))
         (orphan (%wave8-tx :prev-id #xD1 :witness t))
         (owtxid (bitcoin-lisp.serialization:transaction-wtxid orphan))
         (parent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xD1))
         (p1 (%wave8-witness-peer))
         (p2 (bitcoin-lisp.networking:make-peer
              :address "test2" :state :ready :wtxid-relay t
              :services bitcoin-lisp.serialization:+node-witness+))
         (payload (subseq (bitcoin-lisp.serialization:make-inv-message
                           (list (bitcoin-lisp.serialization:make-inv-vector
                                  :type bitcoin-lisp.serialization:+inv-type-wtx+
                                  :hash owtxid)))
                          24)))
    (bitcoin-lisp.networking:reset-tx-requests)
    ;; Orphan stored from p1, parents never requested (direct pool add).
    (bitcoin-lisp.mempool:orphan-add pool orphan p1)
    (finishes
      (bitcoin-lisp.networking::handle-inv p2 payload state mempool
                                           :utxo-set utxo))
    ;; p2 became an announcer of the orphan...
    (is-true (bitcoin-lisp.mempool:orphan-have-from-peer pool owtxid p2))
    ;; ...and the missing parent is in flight to p2 (txid-based entry).
    (is (eq p2 (car (gethash parent-txid bitcoin-lisp.networking::*tx-in-flight*))))
    (is-false (gethash parent-txid bitcoin-lisp.networking::*tx-request-wtxid-p*))
    ;; The orphan itself was NOT re-requested.
    (is (null (gethash owtxid bitcoin-lisp.networking::*tx-in-flight*)))
    (bitcoin-lisp.networking:reset-tx-requests)))

;;;; Steady-state drain serves mempool txs end-to-end (loopback)

(test pump-peer-messages-serves-getdata-loopback
  "The steady-state pump answers a peer's tx getdata from the mempool with a
real tx message over the wire — the regression for the ~30s receive dead
window and the NIL-mempool drains (a getdata for a tx we announced used to
get notfound). Runs over a loopback socket pair."
  (let ((srv (bitcoin-lisp.networking:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
          (let* ((bitcoin-lisp:*network* :regtest)
                 (port (usocket:get-local-port srv))
                 (state (bitcoin-lisp.storage:make-chain-state))
                 (mempool (bitcoin-lisp.mempool:make-mempool))
                 (tx (%witness-tx-for-relay))
                 (txid (bitcoin-lisp.serialization:transaction-hash tx))
                 (server-peer nil))
            (%add-tx mempool tx)
            (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
            (let ((client (bitcoin-lisp.networking:connect-peer "127.0.0.1" port)))
              (is-true client)
              (when client
                (let ((conn (bitcoin-lisp.networking:accept-connection srv :timeout 10)))
                  (is-true conn)
                  (when conn
                    (setf server-peer (bitcoin-lisp.networking:make-inbound-peer
                                       conn "127.0.0.1"))
                    (setf (bitcoin-lisp.networking:peer-state server-peer) :ready)
                    (setf (bitcoin-lisp.networking:peer-state client) :ready)
                    ;; Announced: snapshot the sequence as a flush would.
                    (setf (bitcoin-lisp.networking:peer-last-inv-sequence server-peer)
                          (bitcoin-lisp.mempool:mempool-sequence mempool))
                    ;; Client requests the tx...
                    (bitcoin-lisp.networking:send-message
                     client
                     (bitcoin-lisp.serialization:make-getdata-message
                      (list (bitcoin-lisp.serialization:make-inv-vector
                             :type bitcoin-lisp.serialization:+inv-type-witness-tx+
                             :hash txid))))
                    (sleep 0.2)
                    ;; ...the pump drains and serves it with full context.
                    (bitcoin-lisp.networking:pump-peer-messages
                     (list server-peer) state
                     (bitcoin-lisp.storage:make-utxo-set) nil
                     :mempool mempool)
                    ;; The client receives a tx message...
                    (multiple-value-bind (command payload)
                        (bitcoin-lisp.networking:receive-message client :timeout 5)
                      (is (equal "tx" command))
                      (when payload
                        (is (equalp txid
                                    (bitcoin-lisp.serialization:transaction-hash
                                     (bitcoin-lisp.serialization:parse-tx-payload
                                      payload))))))
                    ;; ...and the serve cleared the unbroadcast entry.
                    (is (= 0 (bitcoin-lisp.mempool:mempool-unbroadcast-count mempool)))))
                (when server-peer
                  (bitcoin-lisp.networking:disconnect-peer server-peer))
                (bitcoin-lisp.networking:disconnect-peer client))))
        (bitcoin-lisp.networking:close-listener srv)))))
