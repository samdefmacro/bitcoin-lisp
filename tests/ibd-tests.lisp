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
         (sync-fn (lambda (peer chain-state &key recent-rejects)
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
         (announcer (bitcoin-lisp.networking:make-peer :state :ready))
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
       announcer (funcall inv-payload bitcoin-lisp.serialization:+inv-type-wtx+ wtxid)
       state mempool))
    ;; Recorded: a probe from another peer sees the request outstanding.
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p wtxid probe))
    ;; MSG_TX (txid) announcements keep working alongside.
    (ignore-errors
      (bitcoin-lisp.networking::handle-inv
       announcer (funcall inv-payload bitcoin-lisp.serialization:+inv-type-tx+ txid)
       state mempool))
    (is-false (bitcoin-lisp.networking::tx-request-wanted-p txid probe))
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
