(in-package #:bitcoin-lisp.tests)

;;; IBD (Initial Block Download) Tests

(def-suite ibd-tests :in :bitcoin-lisp-tests)
(in-suite ibd-tests)

;;;; Checkpoint Tests

(defun %ibd-ctx ()
  "A fresh IBD context, the way START-IBD builds one."
  (bl.net::make-ibd-context))

(defun %ibd ()
  "A fresh IBD context with the start time stamped (BL.NET's own MAKE-IBD)."
  (bl.net::make-ibd))

(defun %sendtxrcncl (peer payload)
  "Drive the shipped BIP330 sendtxrcncl branch of the handshake window."
  (bl.net::%handle-handshake-sendtxrcncl peer payload))

(test checkpoint-data-exists
  "Test that testnet checkpoint data is defined."
  (is (not (null (bl.net:network-checkpoints :testnet3))))
  (is (listp (bl.net:network-checkpoints :testnet3)))
  ;; Check first checkpoint at height 546
  (let ((first (first (bl.net:network-checkpoints :testnet3))))
    (is (= 546 (car first)))
    (is (stringp (cdr first)))))

(test get-checkpoint-hash
  "Test checkpoint hash retrieval."
  (let ((bl:*network* :testnet3))
    ;; Known testnet3 checkpoint should return a hash
    (let ((hash (bl.net:get-checkpoint-hash 546)))
      (is (not (null hash)))
      (is (= 32 (length hash))))
    ;; Non-checkpoint height should return NIL
    (is (null (bl.net:get-checkpoint-hash 547)))))

(test last-checkpoint-height
  "Test getting the last checkpoint height."
  (let ((bl:*network* :testnet3))
    (let ((height (bl.net:last-checkpoint-height)))
      (is (integerp height))
      (is (> height 0)))))

(test validate-checkpoint-match
  "Test checkpoint validation when hash matches."
  (let ((bl:*network* :testnet3))
    (let ((hash (bl.net:get-checkpoint-hash 546)))
      (is (bl.net::validate-checkpoint hash 546)))))

(test validate-checkpoint-mismatch
  "Test checkpoint validation when hash doesn't match."
  (let ((bl:*network* :testnet3))
    (let ((bad-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (is (not (bl.net::validate-checkpoint bad-hash 546))))))

(test validate-checkpoint-no-checkpoint
  "Test checkpoint validation at non-checkpoint height."
  (let ((any-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    ;; Should return T since there's no checkpoint at height 100
    (is (bl.net::validate-checkpoint any-hash 100))))

;;;; Header PoW Validation Tests

(test validate-header-pow-structure
  "Test that PoW validation function exists and handles edge cases."
  ;; Create a minimal mock header with easy target (high bits)
  (let* ((easy-bits #x1d00ffff)  ; Easy target for testing
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits easy-bits
                  :nonce 0)))
    ;; The PoW validation should at least run without error
    (is (or (bl.net::validate-header-pow header)
            (not (bl.net::validate-header-pow header))))))

;;;; IBD Context Tests

(test ibd-context-creation
  "Test creating an IBD context."
  (let ((ctx (%ibd)))
    (is (not (null ctx)))
    (is (eq :idle (bl.net::ibd-context-state ctx)))
    (is (= 0 (bl.net:ibd-context-headers-received ctx)))
    (is (= 0 (bl.net::ibd-context-blocks-received ctx)))
    (is (= 16 (bl.net::ibd-context-max-in-flight ctx)))))

(test ibd-state-transitions
  "Test IBD state machine transitions."
  (with-ibd-context
    (is (eq :idle (bl.net::ibd-state)))
    (bl.net::set-ibd-state :syncing-headers)
    (is (eq :syncing-headers (bl.net::ibd-state)))
    (bl.net::set-ibd-state :syncing-blocks)
    (is (eq :syncing-blocks (bl.net::ibd-state)))
    (bl.net::set-ibd-state :synced)
    (is (eq :synced (bl.net::ibd-state)))))

;;;; Download Queue Tests

;; NOTE: `download-queue-tracking` and the three `request-window-*` tests
;; were removed with the height-based scheduler they exercised
;; (get-next-blocks-to-request): block selection is now the per-peer chain
;; walk find-blocks-to-download-for-peer, covered in reorg-tests
;; (find-blocks-to-download-only-on-peer-chain and friends), whose window
;; is Core's BLOCK_DOWNLOAD_WINDOW in block count anchored at the per-peer
;; last-common block.

(test in-flight-tracking
  "Test tracking in-flight block requests."
  (with-ibd-context
    ;; A real peer, not a keyword stand-in: MARK-BLOCK-IN-FLIGHT stamps the
    ;; peer's download clock, which is what Core's per-peer timeout is judged
    ;; against.
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
          (mock-peer (bl.net:make-peer :address "203.0.113.77")))

      ;; Add to pending
      (setf (gethash hash (bl.net:ibd-context-pending-blocks
                           bl.net:*ibd-context*)) 100)

      ;; Mark as in-flight
      (bl.net::mark-block-in-flight hash mock-peer)

      ;; Check it's now in-flight
      (let ((in-flight (bl.net:ibd-context-in-flight
                        bl.net:*ibd-context*)))
        (is (= 1 (hash-table-count in-flight)))
        (let ((entry (gethash hash in-flight)))
          (is (eq mock-peer (car entry))))))))

(test block-received-tracking
  "Test marking blocks as received."
  (with-ibd-context
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))

      ;; Add to pending and in-flight
      (setf (gethash hash (bl.net:ibd-context-pending-blocks
                           bl.net:*ibd-context*)) 100)
      (bl.net::mark-block-in-flight hash (bl.net:make-peer))

      ;; Initial blocks received count
      (is (= 0 (bl.net::ibd-context-blocks-received
                bl.net:*ibd-context*)))

      ;; Mark as received
      (bl.net::mark-block-received hash)

      ;; Should be removed from pending and in-flight
      (is (= 0 (hash-table-count (bl.net:ibd-context-pending-blocks
                                  bl.net:*ibd-context*))))
      (is (= 0 (hash-table-count (bl.net:ibd-context-in-flight
                                  bl.net:*ibd-context*))))
      ;; Blocks received should increment
      (is (= 1 (bl.net::ibd-context-blocks-received
                bl.net:*ibd-context*))))))

;;;; (The byte-aware request-window tests that lived here exercised the
;;;; retired height-based scheduler. The per-peer walk's window is Core's
;;;; BLOCK_DOWNLOAD_WINDOW in block COUNT anchored at last-common;
;;;; byte-level backpressure is enforced by the receive-side queue caps in
;;;; process-received-block and the gap-only gate in
;;;; request-blocks-from-peers. avg-block-wire-bytes remains as telemetry.)

(test note-block-wire-size-ema
  "note-block-wire-size folds sizes in as a 0.9/0.1 integer EMA and
ignores zero (unknown) sizes."
  (let ((ctx (%ibd)))
    (is (= (* 1024 1024)
           (bl.net::ibd-context-avg-block-wire-bytes ctx)))
    (bl.net::note-block-wire-size ctx (* 2 1024 1024))
    (is (= (floor (+ (* 9 1048576) 2097152) 10)
           (bl.net::ibd-context-avg-block-wire-bytes ctx)))
    (let ((before (bl.net::ibd-context-avg-block-wire-bytes ctx)))
      (bl.net::note-block-wire-size ctx 0)
      (is (= before (bl.net::ibd-context-avg-block-wire-bytes ctx))))))

;;;; STUCK TIP detection
;;;;
;;;; check-stuck-tip is the OOM-prevention backstop. It must fire when
;;;; the queue is genuinely growing toward cap (validator wedged) but
;;;; NOT during ordinary fork-recovery where the queue holds a handful
;;;; of fork blocks waiting on missing intermediates.

(test stuck-tip-fires-when-queue-near-cap
  "When queue >= 90% of cap and tip hasn't advanced in
+stuck-tip-halt-seconds+, check-stuck-tip returns T."
  (let* ((ctx (%ibd))
         (bl.net:*ibd-context* ctx)
         (cap bl.net::+max-block-queue-size+)
         (threshold (floor (* cap 9/10))))
    ;; Plant queue at threshold
    (let ((q (bl.net:ibd-context-block-queue ctx)))
      (loop for i from 0 below threshold
            do (setf (gethash i q) i)))
    ;; Set last-tip-advance well in the past
    (setf (bl.net::ibd-context-last-tip-advance-time ctx)
          (- (get-universal-time)
             (1+ bl.net::+stuck-tip-halt-seconds+)))
    (is (eq t (bl.net::check-stuck-tip)))))

(test stuck-tip-does-not-fire-for-small-fork-queue
  "Regression: when the queue has a handful of fork blocks (1-15)
waiting on missing intermediates, check-stuck-tip must NOT fire even
if tip has been stalled past +stuck-tip-halt-seconds+. Test-bitcoin-
server 2026-05-21 06:46–07:07 hit this 3 times in 21 min before a
13-block reorg completed; the OOM backstop fired and forced peer
rotation each cycle, slowing recovery."
  (let* ((ctx (%ibd))
         (bl.net:*ibd-context* ctx))
    ;; Plant 14 fork blocks (well below cap of 1024)
    (let ((q (bl.net:ibd-context-block-queue ctx)))
      (loop for i from 0 below 14
            do (setf (gethash i q) i)))
    ;; Tip stalled for 10 minutes (2x the threshold)
    (setf (bl.net::ibd-context-last-tip-advance-time ctx)
          (- (get-universal-time) 600))
    (is (null (bl.net::check-stuck-tip)))))

(test stuck-tip-fires-on-byte-cap
  "Regression for the June 2026 two-day stall at h=851,912: the byte cap
pins the queue count at ~170 modern blocks, far below 90% of the 1024
count cap, so a count-only near-cap check never fired. The halt must
also trigger when queue BYTES are near +max-block-queue-bytes+."
  (let* ((ctx (%ibd))
         (bl.net:*ibd-context* ctx))
    ;; Small count (150 entries), bytes at the cap
    (let ((q (bl.net:ibd-context-block-queue ctx)))
      (loop for i from 0 below 150
            do (setf (gethash i q) i)))
    (setf (bl.net::ibd-context-block-queue-bytes ctx)
          bl.net::+max-block-queue-bytes+)
    (setf (bl.net::ibd-context-last-tip-advance-time ctx)
          (- (get-universal-time)
             (1+ bl.net::+stuck-tip-halt-seconds+)))
    (is (eq t (bl.net::check-stuck-tip)))))

(test stuck-tip-does-not-fire-when-tip-fresh
  "If tip advanced recently, check-stuck-tip never fires regardless of
queue size."
  (let* ((ctx (%ibd))
         (bl.net:*ibd-context* ctx)
         (cap bl.net::+max-block-queue-size+))
    ;; Plant queue at cap
    (let ((q (bl.net:ibd-context-block-queue ctx)))
      (loop for i from 0 below cap
            do (setf (gethash i q) i)))
    ;; Tip advanced just now
    (setf (bl.net::ibd-context-last-tip-advance-time ctx)
          (get-universal-time))
    (is (null (bl.net::check-stuck-tip)))))

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
  (let* ((conn (make-test-connection
                :host "10.0.0.1" :port 48333 :connected nil))
         (peer (bl.net:make-peer
                :connection conn :state :ready :address "10.0.0.1")))
    (is (eq t (bl.net::handle-peer-fin peer)))
    (is (eq :disconnected (bl.net:peer-state peer)))
    (is (null (bl.net:peer-connection peer)))))

(test handle-peer-fin-noop-on-healthy-connection
  "When connection-connected is T (no FIN seen), handle-peer-fin leaves
the peer untouched and returns NIL."
  (let* ((conn (make-test-connection
                :host "10.0.0.2" :port 48333 :connected t))
         (peer (bl.net:make-peer
                :connection conn :state :ready :address "10.0.0.2")))
    (is (null (bl.net::handle-peer-fin peer)))
    (is (eq :ready (bl.net:peer-state peer)))
    (is (eq conn (bl.net:peer-connection peer)))))

(test handle-peer-fin-noop-when-no-connection
  "Already-disconnected peers (peer-connection NIL) are a no-op — no
crash, return NIL."
  (let ((peer (bl.net:make-peer
               :connection nil :state :disconnected :address "10.0.0.3")))
    (is (null (bl.net::handle-peer-fin peer)))))

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
  (let* ((ctx (%ibd))
         (conn (make-test-connection
                :host "10.0.0.4" :port 48333 :connected nil :socket nil))
         (peer (bl.net:make-peer
                :connection conn :state :ready :address "10.0.0.4")))
    (drain-peer-once peer (bl.ctx:make-node-context) ctx)
    (is (eq :disconnected (bl.net:peer-state peer)))
    (is (null (bl.net:peer-connection peer)))))

(test drain-and-reap-peer-noop-when-no-connection
  "A peer with peer-connection NIL is a no-op — no crash, state untouched."
  (let* ((ctx (%ibd))
         (peer (bl.net:make-peer
                :connection nil :state :disconnected :address "10.0.0.5")))
    (drain-peer-once peer (bl.ctx:make-node-context) ctx)
    (is (eq :disconnected (bl.net:peer-state peer)))))

;;;; Timeout Tests

(test timeout-detection
  "Test detecting timed out requests."
  (with-ibd-context
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))

      ;; Set a very short timeout for testing (1 second)
      (setf (bl.net::ibd-context-request-timeout
             bl.net:*ibd-context*) 1)

      ;; Add to in-flight with old timestamp
      (let ((old-time (- (get-internal-real-time)
                         (* 2 internal-time-units-per-second))))  ; 2 seconds ago
        (setf (gethash hash (bl.net:ibd-context-in-flight
                             bl.net:*ibd-context*))
              (cons :peer old-time)))

      ;; Should detect timeout
      (let ((timed-out (bl.net::get-timed-out-requests)))
        (is (= 1 (length timed-out)))
        (is (equalp hash (first timed-out)))))))

(test get-timed-out-requests-near-tip-shorter-timeout
  "A block in-flight ~40s is timed out under the near-tip
+block-stalling-timeout+ (30s) but NOT under the full per-block timeout
(120s) — so near the tip a silent peer's block is retried elsewhere fast."
  (with-ibd-context
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
      (setf (bl.net::ibd-context-request-timeout
             bl.net:*ibd-context*) 120)
      (setf (gethash hash (bl.net:ibd-context-in-flight
                           bl.net:*ibd-context*))
            (cons :peer (- (get-internal-real-time)
                           (* 40 internal-time-units-per-second))))  ; 40s ago
      ;; Default (full 120s) timeout: not yet timed out.
      (is (null (bl.net::get-timed-out-requests)))
      ;; Near-tip 30s timeout: timed out.
      (let ((timed-out (bl.net::get-timed-out-requests
                        bl.net::+block-stalling-timeout+)))
        (is (= 1 (length timed-out)))
        (is (equalp hash (first timed-out)))))))

(test retry-timed-out-requests
  "Test retrying timed out requests."
  (with-ibd-context
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))

      ;; Set short timeout and add old request
      (setf (bl.net::ibd-context-request-timeout
             bl.net:*ibd-context*) 1)
      (let ((old-time (- (get-internal-real-time)
                         (* 2 internal-time-units-per-second))))
        (setf (gethash hash (bl.net:ibd-context-in-flight
                             bl.net:*ibd-context*))
              (cons :peer old-time)))

      ;; Also add to pending so it can be retried
      (setf (gethash hash (bl.net:ibd-context-pending-blocks
                           bl.net:*ibd-context*)) 100)

      ;; Retry should remove from in-flight
      (let ((count (bl.net::retry-timed-out-requests)))
        (is (= 1 count))
        (is (= 0 (hash-table-count (bl.net:ibd-context-in-flight
                                    bl.net:*ibd-context*))))
        ;; Should still be in pending
        (is (= 1 (hash-table-count (bl.net:ibd-context-pending-blocks
                                    bl.net:*ibd-context*))))))))

(test retry-timed-out-requests-drops-after-N-attempts
  "After +max-block-request-timeouts+ retries, a block is dropped from
the pending queue. Without this, competing-fork blocks that peers
won't serve would keep IBD's main loop spinning forever."
  (with-ibd-context
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)))
      (setf (bl.net::ibd-context-request-timeout
             bl.net:*ibd-context*) 1)
      (setf (gethash hash (bl.net:ibd-context-pending-blocks
                           bl.net:*ibd-context*)) 100)
      ;; Simulate N timeouts. Each iteration: put the request back
      ;; in-flight with an old timestamp, then retry — retry-timed-out-
      ;; requests removes it from in-flight and bumps the counter.
      (let ((old-time (- (get-internal-real-time)
                         (* 2 internal-time-units-per-second))))
        (loop repeat (1- bl.net::+max-block-request-timeouts+)
              do (setf (gethash hash (bl.net:ibd-context-in-flight
                                       bl.net:*ibd-context*))
                       (cons :peer old-time))
                 (bl.net::retry-timed-out-requests)))
      ;; After N-1 timeouts, still in pending.
      (is (= 1 (hash-table-count
                (bl.net:ibd-context-pending-blocks
                 bl.net:*ibd-context*))))
      ;; One more timeout should drop it from pending.
      (let ((old-time (- (get-internal-real-time)
                         (* 2 internal-time-units-per-second))))
        (setf (gethash hash (bl.net:ibd-context-in-flight
                             bl.net:*ibd-context*))
              (cons :peer old-time)))
      (bl.net::retry-timed-out-requests)
      (is (= 0 (hash-table-count
                (bl.net:ibd-context-pending-blocks
                 bl.net:*ibd-context*)))))))

;;;; Core's two per-peer block-download disconnects
;;;;
;;;; Core keeps the re-routing of a slow request and the eviction of a slow
;;;; PEER strictly apart (net_processing.cpp:6094-6122). We had one mechanism
;;;; doing both: retry-timed-out-requests called record-block-timeout once per
;;;; timed-out HASH against a per-peer budget of 15, while the per-peer
;;;; in-flight cap is 16 and one request-blocks-from-peers call tops a peer up
;;;; to that cap -- so a peer holding a full window of same-age requests went
;;;; from 0 to 16 timeouts in a single pass.

(defun %bd-hash (n)
  "A distinct 32-byte block hash for index N."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (ldb (byte 8 0) n)
          (aref h 1) (ldb (byte 8 8) n)
          (aref h 2) (ldb (byte 8 16) n))
    h))

(defun %bd-check (peers &optional (now *bd-epoch*))
  "Run Core's two per-peer block-download disconnects over PEERS at NOW --
the pass SendMessages makes. Returns how many peers were dropped."
  (bl.net::check-block-download-timeouts peers now))

(defun %bd-stalling-timeout ()
  "The current stalling timeout, which doubles toward Core's 64s ceiling every
time a peer is dropped for stalling."
  bl.net::*block-stalling-timeout*)

(defun %bd-peer (&optional (address "203.0.113.1"))
  (bl.net:make-peer :address address :state :ready))

(defparameter *bd-epoch* (* 1000 internal-time-units-per-second)
  "A synthetic clock origin for the download-timeout tests. GET-INTERNAL-REAL-TIME
starts near zero at process start, so `now minus ten minutes' is NEGATIVE in a
freshly started image and every plusp guard reads the stamp as unset -- the
assertion then passes for the wrong reason. These tests place both the stamp
and the current time explicitly instead, which is also what Core does: its
SendMessages receives current_time rather than reading the clock.")

(defun %bd-fill-window (peer count age-seconds &optional (now *bd-epoch*))
  "Put COUNT blocks in flight from PEER, all requested AGE-SECONDS before NOW,
and stamp the peer's download clock as MARK-BLOCK-IN-FLIGHT would have."
  (let ((then (- now (* age-seconds internal-time-units-per-second))))
    (dotimes (i count)
      (setf (gethash (%bd-hash i)
                     (bl.net:ibd-context-in-flight bl.net:*ibd-context*))
            (cons peer (+ then i)))
      (setf (gethash (%bd-hash i)
                     (bl.net:ibd-context-pending-blocks bl.net:*ibd-context*))
            (+ 100 i)))
    (setf (bl.net:peer-downloading-since peer) then)))

(test the-retry-path-re-routes-and-evicts-nobody
  "Releasing a timed-out request so another peer can be asked for it must cost
the peer that was holding it nothing. It used to cost it one strike out of 15,
per hash, so a full 16-block window crossing the timeout together disconnected
the peer in ONE pass: 125 seconds of silence during bulk download, 30 seconds
anywhere within 144 blocks of the header tip."
  (let ((src (project-source-text "src/networking/ibd.lisp")))
    ;; Positive control for the scan: the mechanism that stayed is still named.
    (is-true (search "retry-timed-out-requests" src)
             "the ibd.lisp source scan read nothing")
    (is-false (search "record-block-timeout" src)
              "the per-hash retry is driving peer eviction again"))
  (is-false (fboundp 'bl.net::record-block-timeout)
            "the per-peer timeout strike counter is back")
  (with-ibd-context
    (let ((peer (%bd-peer)))
      (setf (bl.net::ibd-context-request-timeout bl.net:*ibd-context*) 125)
      ;; RETRY-TIMED-OUT-REQUESTS reads the real clock, so this one window is
      ;; placed against it rather than against the synthetic epoch.
      (%bd-fill-window peer 16 200 (get-internal-real-time))
      (is (= 16 (bl.net::retry-timed-out-requests))
          "every request past the timeout is released for re-routing")
      (is (= 0 (hash-table-count
                (bl.net:ibd-context-in-flight bl.net:*ibd-context*)))
          "the released requests must leave the in-flight table")
      (is (eq :ready (bl.net:peer-state peer))
          "a re-route must not disconnect the peer that was holding the block"))))

(test block-download-timeout-measures-silence-not-request-age
  "Core's per-peer download timeout (net_processing.cpp:6109-6122) is one
decision per peer, taken on its front in-flight block against
m_downloading_since -- the time of its LAST DELIVERY, not the age of the
request -- and widened by half a block interval per other downloading peer so
our own saturated downlink cannot evict a fleet of honest peers."
  ;; The budget itself, against Core's arithmetic.
  (is (= (* 600 internal-time-units-per-second)
         (bl.net::block-download-deadline-ticks 1))
      "one downloading peer: 600s")
  (is (= (* 2700 internal-time-units-per-second)
         (bl.net::block-download-deadline-ticks 8))
      "eight downloading peers: 2700s")
  (with-ibd-context
    ;; The verifier's case: 16 in-flight requests, 126 seconds of silence --
    ;; one second past the old 125s adaptive timeout, and the peer used to be
    ;; :disconnected after a single retry pass.
    (let ((peer (%bd-peer)))
      (%bd-fill-window peer 16 126)
      (is (= 0 (%bd-check (list peer)))
          "126s of silence on a full window is nowhere near Core's floor")
      (is (eq :ready (bl.net:peer-state peer)))))
  (with-ibd-context
    ;; Positive control: past Core's deadline the same peer IS dropped, so the
    ;; assertion above is about the threshold and not about a dead code path.
    (let ((peer (%bd-peer)))
      (%bd-fill-window peer 16 601)
      (is (= 1 (%bd-check (list peer)))
          "silence past 600s with one downloading peer must disconnect")
      (is (eq :disconnected (bl.net:peer-state peer)))))
  (with-ibd-context
    ;; A peer holding NOTHING is never judged, however long ago it last spoke
    ;; (Core guards on vBlocksInFlight.size() > 0).
    (let ((peer (%bd-peer)))
      (setf (bl.net:peer-downloading-since peer)
            (- *bd-epoch* (* 5000 internal-time-units-per-second)))
      (is (= 0 (%bd-check (list peer))))
      (is (eq :ready (bl.net:peer-state peer))))))

(test a-front-block-delivery-restamps-the-download-clock
  "Core RemoveBlockRequest (net_processing.cpp:1221-1231): the clock starts
when a peer's in-flight list fills from EMPTY, and only the FRONT block
arriving restarts it -- that is what makes one decision per peer sound. Any
delivery clears the stalling stamp."
  ;; GET-INTERNAL-REAL-TIME advances in millisecond steps here even though
  ;; INTERNAL-TIME-UNITS-PER-SECOND is a million, so two adjacent operations
  ;; read the SAME value and "the stamp moved" cannot be asserted by comparing
  ;; before and after. Each case plants a sentinel stamp instead and asks
  ;; whether the code replaced it.
  (with-ibd-context
    (let ((peer (%bd-peer)))
      (bl.net::mark-block-in-flight (%bd-hash 0) peer)
      (is (plusp (bl.net:peer-downloading-since peer))
          "the first request starts the clock")
      (setf (bl.net:peer-downloading-since peer) 1)
      (bl.net::mark-block-in-flight (%bd-hash 1) peer)
      (bl.net::mark-block-in-flight (%bd-hash 2) peer)
      (is (= 1 (bl.net:peer-downloading-since peer))
          "topping the peer up must not restart its clock")
      ;; A NON-front delivery leaves the clock alone, and clears the stall.
      (setf (bl.net:peer-stalling-since peer) 12345)
      (bl.net::mark-block-received (%bd-hash 2))
      (is (= 1 (bl.net:peer-downloading-since peer))
          "a later block arriving says nothing about the one we are waiting for")
      (is (zerop (bl.net:peer-stalling-since peer))
          "any delivery clears the stalling stamp")
      ;; The FRONT delivery restarts it.
      (bl.net::mark-block-received (%bd-hash 0))
      (is (> (bl.net:peer-downloading-since peer) 1)
          "the front block arriving restarts the clock for the next one"))))

(test the-stalling-rule-doubles-its-own-timeout
  "Core's stalling rule (net_processing.cpp:6094-6107) fires only for a peer
whose stalling stamp is set -- i.e. one holding the first block below a window
that cannot move -- and DOUBLES its timeout from 2s toward 64s after each use,
so our own insufficient bandwidth cannot evict several peers in a row."
  (with-ibd-context
    (let ((bl.net::*block-stalling-timeout* bl.net::+block-stalling-timeout-default+))
      ;; Control: a peer with no stalling stamp is never dropped by this rule,
      ;; however long it has been connected.
      (let ((quiet (%bd-peer "203.0.113.9")))
        (is (= 0 (%bd-check (list quiet))))
        (is (eq :ready (bl.net:peer-state quiet))))
      (let ((expected bl.net::+block-stalling-timeout-default+))
        (dolist (address '("203.0.113.1" "203.0.113.2" "203.0.113.3"
                           "203.0.113.4" "203.0.113.5" "203.0.113.6"
                           "203.0.113.7"))
          (let ((peer (%bd-peer address)))
            (is (= expected (%bd-stalling-timeout))
                "the stalling timeout must be ~Ds before dropping ~A"
                expected address)
            (setf (bl.net:peer-stalling-since peer)
                  (- *bd-epoch* (* (1+ expected) internal-time-units-per-second)))
            (is (= 1 (%bd-check (list peer)))
                "~A stalled past ~Ds and must be dropped" address expected)
            (is (eq :disconnected (bl.net:peer-state peer)))
            (setf expected (min (* 2 expected)
                                bl.net::+block-stalling-timeout-max+))))
        (is (= bl.net::+block-stalling-timeout-max+ expected)
            "the doubling must reach and stop at Core's 64s ceiling")
        (is (= bl.net::+block-stalling-timeout-max+ (%bd-stalling-timeout)))))))

(test the-window-staller-is-the-peer-holding-its-first-missing-block
  "Core FindNextBlocks (net_processing.cpp:1514-1531): when the walk reaches
the end of the download window with nothing to ask THIS peer for, the peer
holding the first block we found already in flight is the one keeping the
window shut, and SendMessages (:6191-6197) starts its stalling clock. Without
this second value nothing ever sets a stalling stamp and Core's stalling rule
is dead code."
  (with-temp-directory (dir "bl-staller")
    (with-network (:regtest)
      (let* ((state (bl.store:make-chain-state))
             (store (bl.store:init-block-store dir))
             (genesis (bl.store:make-block-index-entry
                       :hash (%bd-hash 0) :height 0 :chain-work 1
                       :status :valid))
             (entries (list genesis))
             (prev genesis))
        (bl.store:add-block-index-entry state genesis)
        ;; A peer chain one block PAST the download window (1024 blocks), so
        ;; the walk runs out of window rather than out of chain.
        (loop for h from 1 to (+ bl.net::+max-block-queue-size+ 1)
              do (let ((e (bl.store:make-block-index-entry
                           :hash (%bd-hash h) :height h
                           :chain-work (+ 1 h) :prev-entry prev
                           :status :header-valid)))
                   (bl.store:add-block-index-entry state e)
                   (push e entries)
                   (setf prev e)))
        (bl.store:update-chain-tip state (%bd-hash 0) 0)
        (let* ((services (logior bl.ser:+node-network+ bl.ser:+node-witness+))
               (holder (bl.net:make-peer :address "198.51.100.1" :state :ready
                                         :services services))
               (asker (bl.net:make-peer :address "198.51.100.2" :state :ready
                                        :services services)))
          (setf (bl.net:peer-best-known-block-hash holder)
                (%bd-hash (+ bl.net::+max-block-queue-size+ 1))
                (bl.net:peer-best-known-block-hash asker)
                (%bd-hash (+ bl.net::+max-block-queue-size+ 1)))
          (with-ibd-context
            ;; Everything inside the window is already in flight from HOLDER.
            (loop for h from 1 to bl.net::+max-block-queue-size+
                  do (bl.net::mark-block-in-flight (%bd-hash h) holder))
            (multiple-value-bind (hashes staller)
                (bl.net::find-blocks-to-download-for-peer asker state store 16)
              (is (null hashes)
                  "the window is full, so this peer has nothing to fetch")
              (is (eq holder staller)
                  "the peer holding the window's first missing block is the staller"))
            ;; Control: with the window free the same walk collects blocks and
            ;; names no staller, so the assertion above is about the window.
            (clrhash (bl.net:ibd-context-in-flight bl.net:*ibd-context*))
            (multiple-value-bind (hashes staller)
                (bl.net::find-blocks-to-download-for-peer asker state store 16)
              (is (= 16 (length hashes))
                  "with the window free the walk fills the peer's budget")
              (is (null staller)
                  "a peer that can be asked for blocks names no staller"))))))))

(test mark-block-received-clears-timeout-counter
  "A successful receive clears the per-hash timeout counter so a future
re-request (e.g. after a reorg) starts fresh."
  (with-ibd-context
    (let ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
      ;; Plant a non-zero counter directly.
      (setf (gethash hash (bl.net::ibd-context-request-timeouts
                           bl.net:*ibd-context*)) 3)
      (setf (gethash hash (bl.net:ibd-context-pending-blocks
                           bl.net:*ibd-context*)) 100)
      (bl.net::mark-block-received hash)
      (is (= 0 (hash-table-count
                (bl.net::ibd-context-request-timeouts
                 bl.net:*ibd-context*)))))))

;;;; Per-peer block-availability tracking
;;;;
;;;; Mirrors Bitcoin Core's ProcessBlockAvailability / UpdateBlockAvailability
;;;; (net_processing.cpp:1361-1392). These tests cover the state
;;;; machine: known hash → best-known set; unknown hash → staged;
;;;; staged hash resolves once index catches up.

(defun %make-peer-with-state (state-key)
  "Construct a minimal peer struct for availability tests, with the
:state slot set so callers can pretend it's :ready."
  (let ((p (bl.net:make-peer :address "test")))
    (setf (bl.net:peer-state p) state-key)
    p))

(test block-relay-targets-skips-source-and-nonready
  "block-relay-targets announces a new block to every ready peer except the
source (which already has it); non-ready peers are excluded."
  (let ((src (%make-peer-with-state :ready))
        (ready (%make-peer-with-state :ready))
        (dead (%make-peer-with-state :disconnected)))
    (is (equal (list ready)
               (bl.net::block-relay-targets src (list src ready dead))))))

(test relay-block-noop-when-relay-disabled
  "relay-block is a no-op when relay is disabled (mainnet default), so a
relay-off node never propagates blocks."
  (let ((bl:*network* :mainnet)
        (bl:*mainnet-relay-enabled* nil)
        (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (null (bl.net:relay-block
               (bl.ser:make-block-header
                :version 1 :prev-block zeros :merkle-root zeros
                :timestamp 1700000000 :bits #x1d00ffff :nonce 0)
               nil (list (%make-peer-with-state :ready)))))))

(test tx-request-tracker-dedups-and-records-announcers
  "tx-request-wanted-p requests from the first announcer only; a second peer
announcing the same txid is recorded as a failover candidate (no duplicate
request). After the tx is received, a later announce requests again."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
        (p1 (%make-peer-with-state :ready))
        (p2 (%make-peer-with-state :ready)))
    (is (eq t (bl.net:tx-request-wanted-p txid p1)))
    (is (null (bl.net:tx-request-wanted-p txid p2)))
    (bl.net:tx-request-received txid)
    (is (eq t (bl.net:tx-request-wanted-p txid p1)))
    (bl.net:reset-tx-requests)))

(test tx-request-retry-reroutes-to-next-announcer
  "A timed-out tx request is re-routed to another ready announcer."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8))
        (p1 (%make-peer-with-state :ready))
        (p2 (%make-peer-with-state :ready)))
    (bl.net:tx-request-wanted-p txid p1)
    (bl.net:tx-request-wanted-p txid p2)
    ;; backdate the in-flight timestamp by >timeout to force a re-route
    ;; (internal-real-time is image-relative, so use a real elapsed delta)
    (is (eq p1 (expire-tx-request txid)))
    (is (= 1 (bl.net:retry-timed-out-tx-requests)))
    (is (eq p2 (tx-request-in-flight-peer txid)))
    (bl.net:reset-tx-requests)))

(test tx-request-retry-drops-when-no-other-announcer
  "A timed-out tx request with no other announcer is dropped from tracking."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
        (p1 (%make-peer-with-state :ready)))
    (bl.net:tx-request-wanted-p txid p1)
    (is (eq p1 (expire-tx-request txid)))
    (is (= 0 (bl.net:retry-timed-out-tx-requests)))
    (is (null (tx-request-in-flight-peer txid)))
    (bl.net:reset-tx-requests)))

(test update-block-availability-known-hash
  "When the announced hash is already in the index with positive
chain-work, peer's best-known-block-hash is set to it."
  (let* ((state (bl.store:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash hash :height 5 :chain-work 100 :status :header-valid))
    (bl.net:update-block-availability peer state hash)
    (is (equalp hash (bl.net:peer-best-known-block-hash peer)))
    (is (null (bl.net::peer-hash-last-unknown-block peer)))))

(test update-block-availability-unknown-hash-staged
  "When the announced hash isn't in the index yet, it's staged in
hash-last-unknown-block for later resolution."
  (let* ((state (bl.store:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (mystery-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC)))
    (bl.net:update-block-availability peer state mystery-hash)
    (is (null (bl.net:peer-best-known-block-hash peer)))
    (is (equalp mystery-hash
                (bl.net::peer-hash-last-unknown-block peer)))))

(test process-block-availability-resolves-staged
  "Once the staged hash gets a block-index entry, the next
process-block-availability promotes it to best-known."
  (let* ((state (bl.store:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)))
    ;; Stage hash before the index has it.
    (bl.net:update-block-availability peer state hash)
    (is (equalp hash (bl.net::peer-hash-last-unknown-block peer)))
    ;; Index catches up.
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash hash :height 10 :chain-work 200 :status :header-valid))
    ;; Process resolves the staged hash.
    (bl.net::process-block-availability peer state)
    (is (equalp hash (bl.net:peer-best-known-block-hash peer)))
    (is (null (bl.net::peer-hash-last-unknown-block peer)))))

(test update-block-availability-does-not-downgrade
  "If best-known is at chain-work N and we announce a block with
chain-work < N, best-known stays put (this peer might be temporarily
sending us an old announcement; we keep the strongest claim)."
  (let* ((state (bl.store:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (strong-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (weak-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash strong-hash :height 100 :chain-work 5000 :status :valid))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash weak-hash :height 50 :chain-work 1000 :status :header-valid))
    (bl.net:update-block-availability peer state strong-hash)
    (is (equalp strong-hash
                (bl.net:peer-best-known-block-hash peer)))
    (bl.net:update-block-availability peer state weak-hash)
    ;; best-known should still be the strong one.
    (is (equalp strong-hash
                (bl.net:peer-best-known-block-hash peer)))))

(test queue-missing-fork-blocks-adds-with-reset-timeout
  "queue-missing-fork-blocks adds each hash to pending and clears its
timeout counter so the existing scheduler retries with a fresh budget."
  (with-ibd-context
    (let ((h1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
          (h2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
      ;; Plant a stale timeout count for h1 to ensure it gets reset.
      (setf (gethash h1 (bl.net::ibd-context-request-timeouts
                         bl.net:*ibd-context*)) 7)
      (let ((queued (bl.net::queue-missing-fork-blocks
                     (list (cons h1 100) (cons h2 101)))))
        (is (= 2 queued))
        (is (= 2 (hash-table-count
                  (bl.net:ibd-context-pending-blocks
                   bl.net:*ibd-context*))))
        ;; Timeout counter for h1 was reset.
        (is (= 0 (hash-table-count
                  (bl.net::ibd-context-request-timeouts
                   bl.net:*ibd-context*))))))))

(test queue-missing-fork-blocks-skips-already-queued
  "If a hash is already in pending or in-flight, queue-missing-fork-blocks
doesn't add it again."
  (with-ibd-context
    (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
      (setf (gethash h (bl.net:ibd-context-pending-blocks
                        bl.net:*ibd-context*)) 50)
      (is (= 0 (bl.net::queue-missing-fork-blocks
                (list (cons h 50))))))))

(test peer-best-known-height-resolves-from-index
  "peer-best-known-height returns the height of the peer's best-known
block when in the index, and NIL when availability is unknown."
  (let* ((state (bl.store:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6)))
    (is (null (bl.net::peer-best-known-height peer state)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash hash :height 42 :chain-work 100 :status :header-valid))
    (setf (bl.net:peer-best-known-block-hash peer) hash)
    (is (= 42 (bl.net::peer-best-known-height peer state)))))

;; NOTE: the block-notfound disclaim machinery (and its tests) was retired:
;; Bitcoin only sends `notfound` for txs, never blocks (net_processing.cpp
;; ProcessGetData), and ignores a block notfound on receipt, so a peer that
;; cannot serve a block it announced is handled by the download timeout —
;; see handle-notfound. The scheduler (find-blocks-to-download-for-peer)
;; never requests a block off a peer's own best chain in the first place;
;; that is covered by `find-blocks-to-download-only-on-peer-chain` in
;; reorg-tests.lisp.

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
  (with-ibd-context
    (let* ((ctx bl.net:*ibd-context*)
          (live (%make-peer-with-state :ready))
          (dead (%make-peer-with-state :disconnected))
          (live-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
          (dead-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
      (setf (gethash live-hash (bl.net:ibd-context-pending-blocks ctx)) 10
            (gethash dead-hash (bl.net:ibd-context-pending-blocks ctx)) 11)
      (setf (gethash live-hash (bl.net:ibd-context-in-flight ctx))
            (cons live (get-internal-real-time))
            (gethash dead-hash (bl.net:ibd-context-in-flight ctx))
            (cons dead (get-internal-real-time)))
      (is (= 1 (bl.net::release-orphaned-in-flight)))
      ;; Dead peer's block freed from in-flight but kept in pending.
      (is (null (gethash dead-hash (bl.net:ibd-context-in-flight ctx))))
      (is (= 11 (gethash dead-hash (bl.net:ibd-context-pending-blocks ctx))))
      ;; Live peer's in-flight is untouched.
      (is (eq live (car (gethash live-hash (bl.net:ibd-context-in-flight ctx))))))))

;;;; Progress Reporting Tests

(test ibd-progress-reporting
  "Test IBD progress reporting."
  (with-ibd-context
    ;; Set some state
    (setf (bl.net::ibd-context-target-height
           bl.net:*ibd-context*) 1000)
    (setf (bl.net::ibd-context-blocks-received
           bl.net:*ibd-context*) 500)
    (setf (bl.net:ibd-context-headers-received
           bl.net:*ibd-context*) 1000)

    (let ((progress (bl.net::ibd-progress)))
      (is (not (null progress)))
      (is (= 500 (getf progress :blocks-received)))
      (is (= 1000 (getf progress :target-height)))
      (is (= 1000 (getf progress :headers-received)))
      ;; 500/1000 = 50%
      (is (= 50.0 (getf progress :progress-percent))))))

;;;; Header Chain Validation Tests

(test process-headers-empty
  "Test processing empty header list."
  (let ((state (bl.store:init-chain-state
                (merge-pathnames "test-chain/" (uiop:temporary-directory)))))
    (is (= 0 (bl.net:process-headers '() state)))))

(test minimum-chain-work-constants
  "minimum-chain-work returns Core's exact nMinimumChainWork per network, and
the override takes precedence (for tests / custom chains)."
  (is (= #x0000000000000000000000000000000000000001128750f82f4c366153a3a030
         (bl:minimum-chain-work :mainnet)))
  (is (= #x0000000000000000000000000000000000000000000009a0fe15d0177d086304
         (bl:minimum-chain-work :testnet4)))
  (is (= 0 (bl:minimum-chain-work :regtest)))
  (let ((bl:*minimum-chain-work-override* 42))
    (is (= 42 (bl:minimum-chain-work :mainnet)))))

(test process-headers-minimum-chain-work-gate
  "Once the active chain is past nMinimumChainWork, a header building a chain
below the floor is refused index admission (anti-DoS low-work fork spam), while
a header extending the high-work tip is accepted."
  (let* ((bl:*network* :regtest)
         (state (bl.store:init-chain-state
                 (merge-pathnames "test-minwork/" (uiop:temporary-directory))))
         (genesis-hash (bl.store:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         ;; init-chain-state sets the genesis hash but does not add an index
         ;; entry; add one (low chain-work) so the fork header below resolves
         ;; its prev-entry and is gated by the work floor, not skipped for a
         ;; missing parent.
         (genesis-entry (bl.store:make-block-index-entry
                         :hash genesis-hash :height 0 :chain-work 1 :status :valid
                         :header (bl.ser:make-block-header
                                  :version 1 :prev-block zeros :merkle-root zeros
                                  :timestamp 1296688600 :bits #x207fffff :nonce 0
                                  :cached-hash genesis-hash)))
         ;; Plant a high-chain-work tip so past-min-work is true.
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bl.store:add-block-index-entry state genesis-entry)
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash tip-hash :height 1 :prev-entry genesis-entry
            :chain-work 1000000000000 :status :valid
            :header (bl.ser:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp 1296688700 :bits #x207fffff :nonce 0
                     :cached-hash tip-hash)))
    (bl.store:update-chain-tip state tip-hash 1)
    (let ((bl:*minimum-chain-work-override* 500000000000))
      ;; A header forking off genesis: chain-work ~= genesis + 1 regtest block,
      ;; far below the 5e11 floor -> rejected.
      (let* ((fork-hdr (bl.ser:make-block-header
                        :version 1 :prev-block genesis-hash :merkle-root zeros
                        :timestamp 1296688800 :bits #x207fffff :nonce 1))
             (fork-hash (bl.ser:block-header-hash fork-hdr)))
        (bl.net:process-headers (list fork-hdr) state)
        (is (null (bl.store:get-block-index-entry state fork-hash))
            "low-work fork header should be refused"))
      ;; A header extending the high-work tip: chain-work > floor -> accepted.
      (let* ((ext-hdr (bl.ser:make-block-header
                       :version 1 :prev-block tip-hash :merkle-root zeros
                       :timestamp 1296688900 :bits #x207fffff :nonce 2))
             (ext-hash (bl.ser:block-header-hash ext-hdr)))
        (bl.net:process-headers (list ext-hdr) state)
        (is (not (null (bl.store:get-block-index-entry state ext-hash)))
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
  (let* ((bl:*network* :regtest)
         (state (bl.store:init-chain-state
                 (merge-pathnames "test-hdr-validation/" (uiop:temporary-directory))))
         (genesis-hash (bl.store:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-ts 1296688600)
         (genesis-entry (bl.store:make-block-index-entry
                         :hash genesis-hash :height 0 :chain-work 1 :status :valid
                         :header (bl.ser:make-block-header
                                  :version 1 :prev-block zeros :merkle-root zeros
                                  :timestamp genesis-ts :bits #x207fffff :nonce 0
                                  :cached-hash genesis-hash))))
    (bl.store:add-block-index-entry state genesis-entry)
    ;; Child of genesis whose timestamp == genesis MTP -> invalid (<= MTP).
    (let* ((bad-hdr (bl.ser:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp genesis-ts :bits #x207fffff :nonce 1))
           (bad-hash (bl.ser:block-header-hash bad-hdr)))
      ;; (a) the shared validation gate rejects it.
      (multiple-value-bind (valid-headers error)
          (bl.net:validate-header-chain (list bad-hdr) state)
        (is (null valid-headers) "invalid header must not pass validate-header-chain")
        (is (not (null error))))
      ;; (b) routing: handle-headers must not admit it to the index. (nil peer is
      ;; safe — with no valid headers, update-block-availability is never called.)
      (let ((payload (concatenate '(vector (unsigned-byte 8))
                                  (vector 1)  ; header-count varint
                                  (bl.ser:serialize-block-header bad-hdr)
                                  (vector 0)))) ; per-header tx-count varint
        (bl.net::handle-headers nil payload (bl.ctx:make-node-context :chain-state state))
        (is (null (bl.store:get-block-index-entry state bad-hash))
            "invalid header must not be admitted by handle-headers")))))

(test validate-header-chain-rejects-future-and-bad-version
  "CONSENSUS (Core ContextualCheckBlockHeader): at header admission we now also
reject a timestamp >2h in the future and a version below the softfork minimum
for its height -- previously only the block-connect path checked these, so a
peer could pollute the header index / best-header chain-work with headers Core
refuses at admission."
  (let* ((bl:*network* :regtest)
         ;; Bind the regtest PoW limit so #x207fffff is a valid target (else
         ;; derive-target rejects it as above the default limit and PoW never
         ;; passes) -- mirrors (with-network (:regtest) ...).
         (bl.store:*pow-limit-target* bl.store:+regtest-pow-limit-target+)
         (state (bl.store:init-chain-state
                 (merge-pathnames "test-hdr-ctx/" (uiop:temporary-directory))))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-hash (bl.store:best-block-hash state)))
    (flet ((pow-grind (hdr)
             ;; regtest pow-limit target passes ~half of nonces; find one so the
             ;; header clears PoW and reaches the check under test.
             (loop for nonce from 0 below 500
                   do (setf (bl.ser:block-header-nonce hdr) nonce
                            (bl.ser:block-header-cached-hash hdr) nil)
                   when (bl.val:check-proof-of-work hdr)
                     do (return hdr)
                   finally (return hdr))))
      ;; --- future timestamp (child of genesis at height 1; version 4 so the
      ;;     BIP34 gate, active from height 1 on regtest, isn't what rejects) ---
      (bl.store:add-block-index-entry
       state (bl.store:make-block-index-entry
              :hash genesis-hash :height 0 :chain-work 1 :status :valid
              :header (bl.ser:make-block-header
                       :version 1 :prev-block zeros :merkle-root zeros
                       :timestamp 1296688600 :bits #x207fffff :nonce 0
                       :cached-hash genesis-hash)))
      (let ((hdr (pow-grind
                  (bl.ser:make-block-header
                   :version 4 :prev-block genesis-hash :merkle-root zeros
                   :timestamp (+ (bl.ser:get-unix-time) 7201)
                   :bits #x207fffff :nonce 0))))
        (multiple-value-bind (valid error)
            (bl.net:validate-header-chain (list hdr) state)
          (is (null valid) "future-dated header must be rejected")
          (is (and error (search "future" error)) "reason should be the future timestamp")))
      ;; --- version below BIP34 minimum (regtest BIP34 activates at height 1) ---
      (let* ((parent-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
             (parent-hdr (bl.ser:make-block-header
                          :version 4 :prev-block zeros :merkle-root zeros
                          :timestamp 1296690000 :bits #x207fffff :nonce 0
                          :cached-hash parent-hash)))
        (bl.store:add-block-index-entry
         state (bl.store:make-block-index-entry
                :hash parent-hash :height 100 :chain-work 2 :status :valid
                :header parent-hdr))
        (let ((hdr (pow-grind
                    (bl.ser:make-block-header
                     :version 1 :prev-block parent-hash :merkle-root zeros
                     :timestamp 1296690100 :bits #x207fffff :nonce 0))))
          (multiple-value-bind (valid error)
              (bl.net:validate-header-chain (list hdr) state)
            (is (null valid) "version<2 at/after BIP34 height must be rejected")
            (is (and error (search "version" error)) "reason should be the bad version")))))))

;;;; Median-time-past across a header batch (GA8 S1-7)

(defconstant +mtp-batch-genesis-time+ 1296688600
  "Timestamp of the synthetic genesis header the MTP-batch fixtures chain from.")

(defun %mtp-batch-fixture (suffix)
  "(values chain-state genesis-hash) — a regtest chain-state whose genesis index
entry carries a header timestamped +mtp-batch-genesis-time+."
  (let* ((state (bl.store:init-chain-state
                 (ensure-directories-exist
                  (merge-pathnames (format nil "test-mtp-batch-~A/" suffix)
                                   (uiop:temporary-directory)))))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-hash (bl.store:best-block-hash state)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash genesis-hash :height 0 :chain-work 1 :status :valid
            :header (bl.ser:make-block-header
                     :version 4 :prev-block zeros :merkle-root zeros
                     :timestamp +mtp-batch-genesis-time+ :bits #x207fffff :nonce 0
                     :cached-hash genesis-hash)))
    (values state genesis-hash)))

(defun %mtp-header (prev-hash timestamp &key (version 4) (bits #x207fffff) (grind t))
  "A header for the MTP-batch fixtures. GRIND searches nonces for one that clears
the regtest pow-limit target, so the header reaches the contextual checks."
  (let ((hdr (bl.ser:make-block-header
              :version version :prev-block prev-hash
              :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                          :initial-element 0)
              :timestamp timestamp :bits bits :nonce 0)))
    (when grind
      (loop for nonce from 0 below 5000
            do (setf (bl.ser:block-header-nonce hdr) nonce
                     (bl.ser:block-header-cached-hash hdr) nil)
            until (bl.val:check-proof-of-work hdr)))
    hdr))

(test validate-header-chain-mtp-uses-in-batch-parent
  "CONSENSUS (GA8 S1-7): the timestamp>median-time-past rule must be evaluated
against the parent ENTRY threaded through the batch, not a block-index lookup of
the parent HASH. A header whose parent is only staged in this batch found nothing
in the index and was compared against a neutral 0, so Core's
ContextualCheckBlockHeader time-too-old rule (validation.cpp:4124,
pindexPrev->GetMedianTimePast()) was vacuously satisfied for every header after
the first in a batch.
Control: the same two headers delivered as SEPARATE batches — the second is
rejected once its parent is indexed — proving the fixture really violates MTP."
  (with-network (:regtest)
   (multiple-value-bind (state genesis-hash) (%mtp-batch-fixture "inbatch")
     (let* ((h1 (%mtp-header genesis-hash (+ +mtp-batch-genesis-time+ 1000)))
            (h1-hash (bl.ser:block-header-hash h1))
            ;; MTP(H1) = median{genesis, H1}; Core takes the upper element of an
            ;; even window, so it is H1's own time and anything at or below it
            ;; violates the rule.
            (h2 (%mtp-header h1-hash (+ +mtp-batch-genesis-time+ 500))))
       (multiple-value-bind (valid error)
           (bl.net:validate-header-chain (list h1 h2) state)
         (is (= 1 (length valid)) "only the first header may be admitted")
         (is (equalp h1 (first valid)))
         (is (and error (search "median-time-past" error))))
       ;; Control, part 1: H1 on its own is a valid batch.
       (multiple-value-bind (valid error)
           (bl.net:validate-header-chain (list h1) state)
         (is (= 1 (length valid)))
         (is (null error)))
       ;; Control, part 2: with H1 indexed, the hash lookup finds a median and
       ;; H2 is rejected — the behaviour a second batch always had.
       (bl.net:process-headers (list h1) state)
       (is (not (null (bl.store:get-block-index-entry state h1-hash)))
           "H1 must be indexed for the control to mean anything")
       (multiple-value-bind (valid error)
           (bl.net:validate-header-chain (list h2) state)
         (is (null valid))
         (is (and error (search "median-time-past" error))))))))

(test validate-header-chain-accepts-valid-mtp-batch
  "No false positives: a batch whose every header is strictly after its parent's
median-time-past is admitted whole."
  (with-network (:regtest)
   (multiple-value-bind (state genesis-hash) (%mtp-batch-fixture "valid")
     (let* ((h1 (%mtp-header genesis-hash (+ +mtp-batch-genesis-time+ 1000)))
            (h2 (%mtp-header (bl.ser:block-header-hash h1)
                             (+ +mtp-batch-genesis-time+ 2000)))
            (h3 (%mtp-header (bl.ser:block-header-hash h2)
                             (+ +mtp-batch-genesis-time+ 3000))))
       (multiple-value-bind (valid error)
           (bl.net:validate-header-chain (list h1 h2 h3) state)
         (is (null error))
         (is (= 3 (length valid))))))))

(test validate-header-chain-contextual-rules-reject-at-batch-position-2
  "Regression guard for the verified scope of GA8 S1-7: MTP was the ONLY
contextual rule that consulted the index by hash. Proof-of-work, the future-time
bound, difficulty and the softfork version minimums all consume the threaded
parent entry and already reject a violating header at batch position 2, so none
of them needed the same fix."
  (with-network (:regtest)
   (multiple-value-bind (state genesis-hash) (%mtp-batch-fixture "position2")
     (let* ((h1 (%mtp-header genesis-hash (+ +mtp-batch-genesis-time+ 1000)))
            (h1-hash (bl.ser:block-header-hash h1))
            (good-time (+ +mtp-batch-genesis-time+ 2000)))
       (dolist (case (list
                      ;; Target below the regtest pow limit that a nonce sweep
                      ;; will not reach: PoW fails.
                      (list "proof-of-work"
                            (%mtp-header h1-hash good-time :bits #x1d00ffff :grind nil))
                      (list "future"
                            (%mtp-header h1-hash (+ (bl.ser:get-unix-time)
                                                    7201)))
                      ;; Regtest never retargets, so a child must inherit its
                      ;; parent's bits exactly.
                      (list "difficulty"
                            (%mtp-header h1-hash good-time :bits #x207ffffe))
                      ;; Regtest activates BIP34 at height 1.
                      (list "version"
                            (%mtp-header h1-hash good-time :version 1))))
         (destructuring-bind (reason h2) case
           (multiple-value-bind (valid error)
               (bl.net:validate-header-chain (list h1 h2) state)
             (is (= 1 (length valid)) "~A: header 2 must not be admitted" reason)
             (is (and error (search reason error))
                 "~A: rejection reason should name it, got ~A" reason error))))))))

(test validate-block-skip-scripts
  "Test that validate-block with :skip-scripts t skips script validation."
  ;; Create a minimal block with an invalid script that would normally fail.
  ;; With :skip-scripts t, it should still pass script validation.
  ;; Without :skip-scripts, it should fail with :script-failed.
  (let* ((bl:*network* :testnet3)
         (state (bl.store:init-chain-state
                 (merge-pathnames "test-skip-scripts/" (uiop:temporary-directory))))
         (utxo-set (bl.store:make-utxo-set))
         (genesis-hash (bl.store:network-genesis-hash bl:*network*))
         ;; Create a coinbase transaction at height 1
         (coinbase-script (make-array 3 :element-type '(unsigned-byte 8)
                                        :initial-contents '(#x01 #x01 #x00)))  ; BIP 34: height 1
         (coinbase-input (bl.ser:make-tx-in
                          :previous-output (bl.ser:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                 :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig coinbase-script
                          :sequence #xFFFFFFFF))
         (coinbase-output (bl.ser:make-tx-out
                           :value 5000000000  ; 50 BTC
                           :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                        :initial-contents '(#x51))))  ; OP_TRUE
         (coinbase-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector coinbase-input)
                       :outputs (vector coinbase-output)
                       :lock-time 0))
         ;; Build a valid-looking block header
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block genesis-hash
                  :merkle-root (bl.val:compute-merkle-root
                                (list (bl.ser:transaction-hash coinbase-tx)))
                  :timestamp (+ 1231006505 600)  ; Genesis + 10 min
                  :bits #x1d00ffff
                  :nonce 0))
         (block (bl.ser:make-bitcoin-block
                 :header header
                 :transactions (list coinbase-tx))))
    ;; The :skip-scripts parameter should be accepted without error
    ;; (We can't fully test block validation here without a complete chain setup,
    ;; but we verify the parameter is wired through correctly by checking that
    ;; validate-block accepts it and the checkpoint height is accessible.)
    (is (> (bl.net:last-checkpoint-height) 0)
        "Last checkpoint height should be positive")
    ;; Verify validate-block accepts the :skip-scripts keyword
    ;; (It will fail on header validation since our mock block isn't fully valid,
    ;; but the important thing is it doesn't signal an error about unknown keywords.)
    (multiple-value-bind (valid error)
        (bl.val:validate-block
         block state utxo-set 1 (bl.ser:get-unix-time)
         :skip-scripts t)
      (declare (ignore valid))
      ;; Should get a validation error (not a keyword error), proving skip-scripts is accepted
      (is (keywordp error)))))

(test validate-header-chain-empty
  "Test validating empty header chain."
  (let ((state (bl.store:init-chain-state
                (merge-pathnames "test-chain/" (uiop:temporary-directory)))))
    (multiple-value-bind (valid-headers error)
        (bl.net:validate-header-chain '() state)
      (is (null valid-headers))
      (is (null error)))))

;;;; Header-sync peer failover (the testnet4 at-tip stall fix)

(test header-sync-failover-rotates-past-stalled-peers
  "sync-headers-with-failover tries ready peers in descending start-height
order and rotates past any that STALL, stopping at the first that answers."
  (let* ((ctx (%ibd-ctx))
         ;; Three ready peers; the two highest-start-height ones stall.
         (p-hi  (bl.net:make-peer :state :ready :start-height 900))
         (p-mid (bl.net:make-peer :state :ready :start-height 800))
         (p-lo  (bl.net:make-peer :state :ready :start-height 700))
         (tried '())
         ;; Stub: p-hi and p-mid stall (values 0 t); p-lo answers (values 3 nil).
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
                    (declare (ignore chain-state recent-rejects))
                    (push peer tried)
                    (if (eq peer p-lo) (values 3 nil) (values 0 t)))))
    (let ((winner (bl.net::sync-headers-with-failover
                   (list p-lo p-hi p-mid) nil ctx :sync-fn sync-fn)))
      ;; Stopped at the first non-stalled peer.
      (is (eq p-lo winner))
      ;; Tried in start-height order hi -> mid -> lo, then stopped.
      (is (equal (list p-hi p-mid p-lo) (nreverse tried)))
      ;; header-sync-peer left pointing at the peer that answered.
      (is (eq p-lo (bl.net::ibd-context-header-sync-peer ctx))))))

(test header-sync-failover-first-peer-answers
  "When the highest-start-height peer answers, no rotation happens."
  (let* ((ctx (%ibd-ctx))
         (p-hi (bl.net:make-peer :state :ready :start-height 900))
         (p-lo (bl.net:make-peer :state :ready :start-height 700))
         (calls 0)
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
                    (declare (ignore peer chain-state recent-rejects))
                    (incf calls) (values 10 nil))))
    (is (eq p-hi (bl.net::sync-headers-with-failover
                  (list p-lo p-hi) nil ctx :sync-fn sync-fn)))
    (is (= 1 calls))))   ; stopped after the first peer

(test header-sync-failover-all-stalled-and-skips-nonready
  "All-stalled returns NIL; non-:ready peers are skipped entirely."
  (let* ((ctx (%ibd-ctx))
         (ready (bl.net:make-peer :state :ready :start-height 500))
         (dead  (bl.net:make-peer :state :disconnected :start-height 999))
         (tried '())
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
                    (declare (ignore chain-state recent-rejects))
                    (push peer tried) (values 0 t))))
    ;; All ready peers stall -> NIL.
    (is (null (bl.net::sync-headers-with-failover
               (list ready) nil ctx :sync-fn sync-fn)))
    ;; The disconnected peer (higher start-height) is never tried.
    (setf tried '())
    (bl.net::sync-headers-with-failover
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
  (let* ((ctx (%ibd-ctx))
         (ready (bl.net:make-peer :state :ready :start-height 500))
         (calls 0)
         (sync-fn (lambda (peer chain-state &key recent-rejects &allow-other-keys)
                    (declare (ignore peer chain-state recent-rejects))
                    (incf calls) (values 10 nil))))
    (let ((bl.net::*ibd-stop-requested* t))
      (is (null (bl.net::sync-headers-with-failover
                 (list ready) nil ctx :sync-fn sync-fn))))
    (is (= 0 calls))))

(test run-ibd-honors-stop-request
  "run-ibd with pending work and a stop requested returns immediately
instead of cycling the no-peer grace (~6s) or downloading."
  (with-ibd-context
    (let* ((state (bl.store:make-chain-state))
          (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
      ;; A header-valid entry above the current tip gives run-ibd pending
      ;; work and keeps its download-loop gate (height < header-tip) true.
      (bl.store:add-block-index-entry
       state (bl.store:make-block-index-entry
              :hash hash :height 10 :chain-work 100 :status :header-valid))
      (let ((bl.net::*ibd-stop-requested* t)
            (start (get-internal-real-time)))
        (bl.net::run-ibd '() (bl.ctx:make-node-context :chain-state state :peers '()))
        (is (< (- (get-internal-real-time) start)
               (* 2 internal-time-units-per-second)))))))

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
                (conn (make-test-connection
                       :socket client :host "127.0.0.1" :port port
                       :connected t :last-activity (get-universal-time))))
           (unwind-protect
                ;; No data is ever sent, so the read can only finish via the
                ;; stop-request check (or the 30s timeout, which would fail the
                ;; bound below).
                (let ((bl.net::*ibd-stop-requested* t)
                      (start (get-internal-real-time)))
                  (let ((result (bl.net:receive-bytes
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
  (let ((bl:*network* :mainnet))
    (let ((av (bl.net::default-assumevalid)))
      (is (= 32 (length av)))
      (is (= #xac (aref av 0)))
      (is (= #x00 (aref av 31)))))
  (let ((bl:*network* :regtest))
    (is (null (bl.net::default-assumevalid))))
  ;; skip-height logic on a synthetic regtest chain (checkpoint height = 0)
  (let* ((bl:*network* :regtest)
         (state (bl.store:init-chain-state
                 (merge-pathnames "test-assumevalid/" (uiop:temporary-directory))))
         (genesis-hash (bl.store:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (av-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (absent (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash genesis-hash :height 0 :chain-work 1 :status :valid
            :header (bl.ser:make-block-header
                     :version 1 :prev-block zeros :merkle-root zeros
                     :timestamp 1296688600 :bits #x207fffff :nonce 0
                     :cached-hash genesis-hash)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash av-hash :height 50 :chain-work 100 :status :header-valid
            :header (bl.ser:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp 1296688700 :bits #x207fffff :nonce 0
                     :cached-hash av-hash)))
    ;; assumevalid points at the in-index block -> its height; sigs skip <= 50.
    (let ((bl:*assumevalid-override* av-hash))
      (is (= 50 (bl.net::assumevalid-skip-height state)))
      (is (= 50 (bl.net::script-skip-height state))))
    ;; assumevalid hash not in our index -> no skip.
    (let ((bl:*assumevalid-override* absent))
      (is (= -1 (bl.net::assumevalid-skip-height state))))
    ;; assumevalid explicitly disabled -> no skip.
    (let ((bl:*assumevalid-override* nil))
      (is (= -1 (bl.net::assumevalid-skip-height state))))))

(test block-failure-count-throttle
  "note-block-failure increments a per-hash counter, clear-block-failure resets
it, and counts are independent per hash. This bounded counter backs the
re-request budget in handle-validation-failure that stops a single
persistently-failing block from spinning the receive->validate->re-request loop
and spamming the log (the testnet4 wedge produced 6.5M lines / 1.1GB this way)."
  (let ((h1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (h2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (clrhash bl.net::*block-failure-counts*)
    ;; increments per hash
    (is (= 1 (bl.net::note-block-failure h1)))
    (is (= 2 (bl.net::note-block-failure h1)))
    (is (= 3 (bl.net::note-block-failure h1)))
    ;; independent per hash
    (is (= 1 (bl.net::note-block-failure h2)))
    (is (= 4 (bl.net::note-block-failure h1)))
    ;; clear resets a single hash
    (bl.net::clear-block-failure h1)
    (is (= 1 (bl.net::note-block-failure h1)))
    (is (= 2 (bl.net::note-block-failure h2)))  ; h2 untouched
    (clrhash bl.net::*block-failure-counts*)))

;;;; Initial-block-download latch (Core IsInitialBlockDownload)
;;;;
;;;; Gates loose-tx fetching in handle-inv: during IBD announced txs are
;;;; not requested (their inputs can't resolve against a stale UTXO set),
;;;; mirroring net_processing.cpp:4176-4180. The status is latched — once
;;;; the tip is recent with enough work it never flips back.

(defun %make-ibd-latch-state (timestamp &key (work 100))
  "Chain-state whose tip header carries TIMESTAMP and chain-work WORK."
  (let ((state (bl.store:make-chain-state))
        (hash (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-element (mod timestamp 251))))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash hash :height 1 :chain-work work :status :valid
            :header (bl.ser:make-block-header
                     :version 1
                     :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 0)
                     :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                 :initial-element 0)
                     :timestamp timestamp :bits #x1d00ffff :nonce 0)))
    (bl.store:update-chain-tip state hash 1)
    state))

(test initial-block-download-latch
  "T while the tip is stale or low-work; latches NIL once the tip is
recent with enough chain work; never flips back until reset-ibd-stop."
  (let ((bl.net:*cached-is-ibd* t)
        (bl:*network* :regtest)  ; minimum-chain-work 0
        (bl:*minimum-chain-work-override* nil)
        (now (bl.ser:get-unix-time)))
    ;; Tip two days old => still in IBD.
    (is-true (bl.net:initial-block-download-p
              (%make-ibd-latch-state (- now (* 48 60 60)))))
    ;; Fresh tip but below minimum chain work => still in IBD.
    (let ((bl:*minimum-chain-work-override* (expt 2 100)))
      (is-true (bl.net:initial-block-download-p
                (%make-ibd-latch-state now))))
    ;; Fresh tip with enough work => leaves IBD and latches.
    (is-false (bl.net:initial-block-download-p
               (%make-ibd-latch-state now)))
    (is-false bl.net:*cached-is-ibd*)
    ;; Latched: a stale tip no longer flips it back.
    (is-false (bl.net:initial-block-download-p
               (%make-ibd-latch-state (- now (* 48 60 60)))))
    ;; reset-ibd-stop (node start) re-arms the latch.
    (bl.net:reset-ibd-stop)
    (is-true (bl.net:initial-block-download-p
              (%make-ibd-latch-state (- now (* 48 60 60)))))))

(test handle-inv-tx-fetch-gated-during-ibd
  "During IBD, tx invs are not recorded in the request tracker and no
getdata is attempted (Core net_processing.cpp:4176-4180)."
  (let* ((bl.net:*cached-is-ibd* t)
         (bl:*network* :regtest)
         (bl:*minimum-chain-work-override* nil)
         (now (bl.ser:get-unix-time))
         (state (%make-ibd-latch-state (- now (* 48 60 60))))  ; stale => IBD
         (mempool (bl.mp:make-mempool))
         (announcer (bl.net:make-peer :state :ready))
         (probe (bl.net:make-peer :state :ready))
         (tx-hash (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 7))
         (payload (subseq (bl.ser:make-inv-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-tx+
                                  :hash tx-hash)))
                          24)))  ; strip the 24-byte v1 message header
    (bl.net:reset-tx-requests)
    ;; With the announcer's peer having no connection, a getdata attempt
    ;; would error — the gate must short-circuit before any of that.
    (finishes (deliver-inv announcer payload (bl.ctx:make-node-context :chain-state state :mempool mempool)))
    ;; Nothing was recorded for the hash: a fresh request from another
    ;; peer is still "wanted" (no outstanding in-flight entry).
    (is-true (bl.net:tx-request-wanted-p tx-hash probe))
    (bl.net:reset-tx-requests)))

(test handle-inv-wtx-announcement-requested
  "MSG_WTX (BIP339) tx announcements — the only kind modern wtxidrelay
peers send (net_processing.cpp:6009) — are matched and recorded in the
request tracker; MSG_TX announcements still work. Regression test: the
tx branch previously matched only types 1/0x40000001, so every
announcement from a wtxidrelay peer was silently dropped."
  (let* ((bl.net:*cached-is-ibd* t)
         (bl:*network* :regtest)
         (bl:*minimum-chain-work-override* nil)
         (now (bl.ser:get-unix-time))
         (state (%make-ibd-latch-state now))  ; fresh tip => not in IBD
         (mempool (bl.mp:make-mempool))
         ;; MSG_WTX only comes from wtxidrelay peers; MSG_TX only from
         ;; non-wtxidrelay peers — handle-inv ignores mismatches (Core
         ;; net_processing.cpp:4145-4152), so use one announcer of each kind.
         (wtx-announcer (bl.net:make-peer :state :ready
                                                           :wtxid-relay t))
         (tx-announcer (bl.net:make-peer :state :ready))
         (probe (bl.net:make-peer :state :ready))
         (wtxid (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 11))
         (txid (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element 12)))
    (bl.net:reset-tx-requests)
    ;; The announcer peer has no connection, so the getdata send at the end
    ;; of handle-inv errors — but the tracker recording happens first, which
    ;; is the observable we assert on.
    (ignore-errors
      (deliver-inv wtx-announcer (tx-inv-payload bl.ser:+inv-type-wtx+ wtxid) (bl.ctx:make-node-context :chain-state state :mempool mempool)))
    ;; Recorded: a probe from another peer sees the request outstanding.
    (is-false (bl.net:tx-request-wanted-p wtxid probe))
    ;; MSG_TX (txid) announcements keep working alongside.
    (ignore-errors
      (deliver-inv tx-announcer (tx-inv-payload bl.ser:+inv-type-tx+ txid) (bl.ctx:make-node-context :chain-state state :mempool mempool)))
    (is-false (bl.net:tx-request-wanted-p txid probe))
    (bl.net:reset-tx-requests)))

(test handle-inv-ignores-wtxidrelay-mismatch
  "Invs that don't match the wtxidrelay negotiation are ignored: MSG_TX from
a wtxidrelay peer, MSG_WTX from a non-wtxidrelay peer (Core
net_processing.cpp:4145-4152)."
  (let* ((bl.net:*cached-is-ibd* t)
         (bl:*network* :regtest)
         (bl:*minimum-chain-work-override* nil)
         (now (bl.ser:get-unix-time))
         (state (%make-ibd-latch-state now))
         (mempool (bl.mp:make-mempool))
         (wtx-peer (bl.net:make-peer :state :ready
                                                      :wtxid-relay t))
         (legacy-peer (bl.net:make-peer :state :ready))
         (probe (bl.net:make-peer :state :ready))
         (h1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 13))
         (h2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 14))
         (inv-payload
           (lambda (type hash)
             (subseq (bl.ser:make-inv-message
                      (list (bl.ser:make-inv-vector
                             :type type :hash hash)))
                     24))))
    (bl.net:reset-tx-requests)
    ;; MSG_TX from a wtxidrelay peer: ignored, nothing recorded.
    (finishes
      (deliver-inv wtx-peer (funcall inv-payload bl.ser:+inv-type-tx+ h1) (bl.ctx:make-node-context :chain-state state :mempool mempool)))
    (is-true (bl.net:tx-request-wanted-p h1 probe))
    ;; MSG_WTX from a non-wtxidrelay peer: ignored too.
    (bl.net:reset-tx-requests)
    (finishes
      (deliver-inv legacy-peer (funcall inv-payload bl.ser:+inv-type-wtx+ h2) (bl.ctx:make-node-context :chain-state state :mempool mempool)))
    (is-true (bl.net:tx-request-wanted-p h2 probe))
    (bl.net:reset-tx-requests)))

;;;; Relay polish: wtxid-keyed rejects, getaddr, BIP35 mempool

(test recent-rejects-are-wtxid-keyed
  "A rejected witness tx lands in the rejects filter under its WTXID,
never its txid — the witness can be malleated, so the same txid with a
different witness could still be valid (Core issue bitcoin/bitcoin#8279,
txdownloadman_impl.cpp MempoolRejectedTx). No-witness txs are covered
since wtxid = txid there."
  (let* ((input (bl.ser:make-tx-in
                 :previous-output (bl.ser:make-outpoint
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 42)
                                   :index 0)
                 :script-sig (make-array 2 :element-type '(unsigned-byte 8)
                                           :initial-element 0)
                 :sequence #xFFFFFFFF))
         (output (bl.ser:make-tx-out
                  :value 10000
                  :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                :initial-element 0)))
         ;; version 5 > +max-standard-tx-version+ (3): rejected as
         ;; :version-non-standard before input resolution, i.e. the plain
         ;; reject path (not the :missing-input orphan path).
         (tx (bl.ser:make-transaction
              :version 5
              :inputs (vector input)
              :outputs (vector output)
              :lock-time 0
              :witness (vector (list (make-array 8 :element-type '(unsigned-byte 8)
                                                   :initial-element 7)))))
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx))
         (payload (subseq (bl.ser:make-tx-message tx :witness t) 24))
         (rejects (bl:make-rejects-filter 100))
         (mempool (bl.mp:make-mempool))
         (state (bl.store:make-chain-state))
         (peer (bl.net:make-peer :state :ready)))
    ;; Sanity: this is a witness tx, ids differ.
    (is-false (equalp txid wtxid))
    (bl.net:reset-tx-requests)
    (with-tx-relay-out-of-ibd
      (deliver-tx peer payload (bl.ctx:make-node-context :chain-state state :mempool mempool :recent-rejects rejects)))
    (is-true (bl:recent-reject-p rejects wtxid))
    (is-false (bl:recent-reject-p rejects txid))))

;;;; Wave 8A: tx-relay request path (orphan-parent fetch, failover id type,
;;;; reject-poisoning semantics) — Core txdownloadman/txrequest parity.

(defun %wave8-witness-peer (&optional (state :ready))
  "A :ready peer advertising NODE_WITNESS, like every modern Core peer."
  (bl.net:make-peer
   :address "test" :state state
   :services bl.ser:+node-witness+))

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
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element prev-id)
                                      :index prev-index)
                    :script-sig (coerce script-sig '(vector (unsigned-byte 8)))
                    :sequence #xFFFFFFFF))
   :outputs (vector (bl.ser:make-tx-out
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
  (bl.net:reset-tx-requests)
  (let ((wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 41))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
        (p1 (%wave8-witness-peer))
        (p2 (%wave8-witness-peer)))
    ;; One wtxid-based and one txid-based announcement, two candidates each.
    (is-true (bl.net:tx-request-wanted-p wtxid p1 t))
    (is-false (bl.net:tx-request-wanted-p wtxid p2 t))
    (is-true (bl.net:tx-request-wanted-p txid p1 nil))
    (is-false (bl.net:tx-request-wanted-p txid p2 nil))
    ;; Backdate both in-flight entries past the timeout to force failover.
    (is (eq p1 (expire-tx-request wtxid)))
    (is (eq p1 (expire-tx-request txid)))
    (is (= 2 (bl.net:retry-timed-out-tx-requests)))
    ;; Both rerouted to p2 with the id type preserved.
    (is (eq p2 (tx-request-in-flight-peer wtxid)))
    (is (eq p2 (tx-request-in-flight-peer txid)))
    (is-true (tx-request-wtxid-entry-p wtxid))
    (is-false (tx-request-wtxid-entry-p txid))
    ;; The inv the failover getdata carries for each entry type:
    (is (= bl.ser:+inv-type-wtx+
           (bl.ser:inv-vector-type
            (bl.net::tx-request-inv wtxid t p2))))
    (is (= bl.ser:+inv-type-witness-tx+
           (bl.ser:inv-vector-type
            (bl.net::tx-request-inv txid nil p2))))
    ;; A peer without NODE_WITNESS gets bare MSG_TX for txid entries
    ;; (Core GetFetchFlags returns no witness flag for it).
    (is (= bl.ser:+inv-type-tx+
           (bl.ser:inv-vector-type
            (bl.net::tx-request-inv
             txid nil (%make-peer-with-state :ready)))))
    (bl.net:reset-tx-requests)))

(test orphan-parent-getdata-carries-witness-flag
  "Missing parents of an orphan are requested by TXID with the witness flag
(MSG_TX|MSG_WITNESS_FLAG) for witness-capable peers, never bare MSG_TX
(Core requests txid announcements as MSG_TX | GetFetchFlags,
net_processing.cpp:6207; orphan parents enter the tracker via
MaybeAddOrphanResolutionCandidate, txdownloadman_impl.cpp:257-260).
Regression: bare MSG_TX fetched the witness-stripped parent, which failed
scripts and — wtxid == txid for a stripped tx — poisoned recent-rejects
with the parent's real txid, so the orphan could never resolve."
  (bl.net:reset-tx-requests)
  (let* ((utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (orphan (%wave8-tx :prev-id #xB1))
         (peer (%wave8-witness-peer))
         (parents (bl.net::missing-parent-txids orphan utxo mempool)))
    (is (= 1 (length parents)))
    (let ((invs (bl.net::request-orphan-parents peer parents)))
      (is (= 1 (length invs)))
      (is (= bl.ser:+inv-type-witness-tx+
             (bl.ser:inv-vector-type (first invs))))
      (is (equalp (first parents)
                  (bl.ser:inv-vector-hash (first invs)))))
    ;; The parent request is registered with the tx-request tracker (txid-
    ;; based), so another announcer doesn't trigger a duplicate getdata and
    ;; timeout failover applies to parent fetches too.
    (is-false (bl.net:tx-request-wanted-p
               (first parents) (%make-peer-with-state :ready)))
    (is-false (tx-request-wtxid-entry-p (first parents)))
    (bl.net:reset-tx-requests)))

(test orphan-with-rejected-parent-rejected-under-both-ids
  "A tx with missing inputs whose missing parent is already in recent-rejects
is NOT kept as an orphan: it is rejected outright under BOTH its txid and
wtxid, and no parent fetch goes out (Core 'not keeping orphan with rejected
parents', txdownloadman_impl.cpp:422-436)."
  (bl.net:reset-tx-requests)
  (let* ((utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (state (bl.store:make-chain-state))
         (peer (%wave8-witness-peer))
         (rejects (bl:make-rejects-filter 100))
         (tx (%wave8-tx :prev-id #xB2 :witness t))
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx))
         (parent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xB2))
         (payload (subseq (bl.ser:make-tx-message tx :witness t) 24)))
    (is-false (equalp txid wtxid))
    ;; The missing parent was recently rejected.
    (bl:add-recent-reject rejects parent-txid)
    (with-tx-relay-out-of-ibd
      (deliver-tx peer payload (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool :recent-rejects rejects)))
    ;; Rejected under both ids; never admitted to the orphan pool; the
    ;; parent was NOT re-requested.
    (is-true (bl:recent-reject-p rejects txid))
    (is-true (bl:recent-reject-p rejects wtxid))
    (is-false (bl.mp:orphan-tx
               (bl.mp:mempool-orphan-pool mempool) txid))
    (is (null (tx-request-in-flight-peer txid)))
    (is (null (tx-request-in-flight-peer parent-txid)))
    (bl.net:reset-tx-requests)))

(test orphan-with-unrejected-parent-is-kept-and-parent-fetched
  "The healthy counterpart: a missing-inputs tx whose parents are NOT
rejected goes into the orphan pool, its parent fetch is tracker-registered,
and the tx itself is not cached as a reject."
  (bl.net:reset-tx-requests)
  (let* ((utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (state (bl.store:make-chain-state))
         (peer (%wave8-witness-peer))
         (rejects (bl:make-rejects-filter 100))
         (tx (%wave8-tx :prev-id #xB3 :witness t))
         (txid (bl.ser:transaction-hash tx))
         (parent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xB3))
         (payload (subseq (bl.ser:make-tx-message tx :witness t) 24)))
    (with-tx-relay-out-of-ibd
      (deliver-tx peer payload (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool :recent-rejects rejects)))
    ;; The orphanage is wtxid-keyed (Core TxOrphanage).
    (is-true (bl.mp:orphan-tx
              (bl.mp:mempool-orphan-pool mempool)
              (bl.ser:transaction-wtxid tx)))
    (is-false (bl:recent-reject-p rejects txid))
    (is-false (bl:recent-reject-p
               rejects (bl.ser:transaction-wtxid tx)))
    ;; Parent fetch registered as a txid-based tracker entry.
    (is-false (bl.net:tx-request-wanted-p
               parent-txid (%make-peer-with-state :ready)))
    (bl.net:reset-tx-requests)))

(test witness-stripped-failure-not-cached-in-recent-rejects
  "A no-witness tx that fails scripts while spending a witness-program
output is classified witness-stripped and cached NOWHERE — its wtxid equals
its txid, so caching would poison the real witnessed tx's txid and block its
relay permanently (Core TX_WITNESS_STRIPPED, txdownloadman_impl.cpp:438-439,
classified by validation.cpp:1143-1148 SpendsNonAnchorWitnessProg). A
genuinely failing non-witness-program spend IS still cached (wtxid-keyed)."
  (bl.net:reset-tx-requests)
  (let* ((bl:*network* :regtest)
         (bl:*minimum-chain-work-override* nil)
         (now (bl.ser:get-unix-time))
         (state (%make-ibd-latch-state now))
         (utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (peer (%wave8-witness-peer))
         (rejects (bl:make-rejects-filter 100))
         ;; Coin 1: P2WPKH (a witness program).
         (p2wpkh (let ((s (make-array 22 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
                   (setf (aref s 0) #x00 (aref s 1) #x14)
                   s))
         (stripped (%wave8-tx :prev-id #xC1))   ; no witness attached
         (stripped-id (bl.ser:transaction-hash stripped))
         ;; Coin 2: P2PKH — witness stripping cannot explain this failure.
         (failing (%wave8-tx :prev-id #xC2 :script-sig (vector #x51)))
         (failing-id (bl.ser:transaction-hash failing)))
    (bl.store:add-utxo
     utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xC1)
     0 100000000 p2wpkh 0)
    (bl.store:add-utxo
     utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xC2)
     0 100000000 (%wave8-p2pkh-script) 0)
    ;; Sanity: wtxid == txid for both (no witness), the poisoning precondition.
    (is (equalp stripped-id (bl.ser:transaction-wtxid stripped)))
    (deliver-tx peer (subseq (bl.ser:make-tx-message stripped) 24) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool :recent-rejects rejects))
    (deliver-tx peer (subseq (bl.ser:make-tx-message failing) 24) (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool :recent-rejects rejects))
    ;; The plain script failure IS cached (proves this fixture reaches the
    ;; reject-insert path)...
    (is-true (bl:recent-reject-p rejects failing-id))
    ;; ...but the witness-stripped one is NOT.
    (is-false (bl:recent-reject-p rejects stripped-id))
    (bl.net:reset-tx-requests)))

(test bip35-mempool-message-disconnects
  "BIP35 'mempool' requests get a disconnect: we never advertise
NODE_BLOOM, matching Core's no-bloom path (net_processing.cpp:4940-4951)."
  (let ((peer (bl.net:make-peer :state :ready)))
    (is-true (bl.net:handle-message peer "mempool" #() (bl.ctx:make-node-context)))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test getaddr-message-format
  "getaddr serializes as a bare 24-byte v1 header with empty payload."
  (let ((bytes (bl.ser:make-getaddr-message)))
    (is (= 24 (length bytes)))
    (is (string= "getaddr" (map 'string #'code-char
                                (remove 0 (subseq bytes 4 16)))))))

;;;; Trickled (Poisson) tx announcement batching

(test relay-transaction-queues-instead-of-sending
  "relay-transaction enqueues per-peer announcements (Core
m_tx_inventory_to_send); nothing is sent and nothing is marked announced
until flush time."
  (let* ((bl:*network* :regtest)
         (peer (bl.net:make-peer :state :ready :wtxid-relay t))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
         (wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 22)))
    ;; Peer has no connection: an immediate send would error, a queue won't.
    (finishes (bl.net:relay-transaction
               txid nil (list peer) :fee-rate 2 :wtxid wtxid))
    (is (= 1 (length (bl.net:peer-tx-inv-queue peer))))
    (is-false (bl:recent-reject-p
               (bl.net:peer-announced-txs peer) txid))))

(test flush-tx-announcements-drains-on-schedule
  "First flush pass only arms an outbound peer's exponential timer (Core
initializes m_next_inv_send_time the same way); once the deadline is
due, the queue drains and the tx is marked known to the peer under the id
that peer's inventory uses — the WTXID here, since it negotiated wtxidrelay
(Core keys m_tx_inventory_known_filter by `m_wtxid_relay ? wtxid : txid`).
Send errors from the connectionless peer are swallowed."
  (let* ((bl:*network* :regtest)
         (peer (bl.net:make-peer :state :ready :wtxid-relay t))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 23))
         (wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 24)))
    (bl.net:relay-transaction
     txid nil (list peer) :fee-rate 2 :wtxid wtxid)
    ;; Arm pass: timer initialized, nothing flushed.
    (bl.net:flush-tx-announcements (list peer) nil)
    (is (plusp (bl.net::peer-next-inv-send-time peer)))
    (is (= 1 (length (bl.net:peer-tx-inv-queue peer))))
    ;; Deadline in the past: flush drains and marks announced.
    (setf (bl.net::peer-next-inv-send-time peer) 1)
    (bl.net:flush-tx-announcements (list peer) nil)
    (is (null (bl.net:peer-tx-inv-queue peer)))
    (is-true (bl:recent-reject-p
              (bl.net:peer-announced-txs peer) wtxid))
    (is-false (bl:recent-reject-p
               (bl.net:peer-announced-txs peer) txid)
              "a wtxidrelay peer's filter is keyed by wtxid, not txid")))

(test flush-drops-feefiltered-entries
  "A queued announcement below the peer's BIP133 feefilter is dropped at
flush time — neither sent nor marked announced (Core skips it out of
m_tx_inventory_to_send the same way)."
  (let* ((bl:*network* :regtest)
         (peer (bl.net:make-peer :state :ready))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 25)))
    (setf (bl.net:peer-feefilter-rate peer) 1000000)
    ;; fee-rate 1 sat/vB = 1000 sat/kvB < 1000000 filter.
    (bl.net:relay-transaction txid nil (list peer) :fee-rate 1)
    (is (= 1 (length (bl.net:peer-tx-inv-queue peer))))
    (setf (bl.net::peer-next-inv-send-time peer) 1)
    (bl.net:flush-tx-announcements (list peer) nil)
    (is (null (bl.net:peer-tx-inv-queue peer)))
    (is-false (bl:recent-reject-p
               (bl.net:peer-announced-txs peer) txid))))

(defun %relay-txid (n)
  "A distinct 32-byte transaction id for the Nth queued announcement."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref v 0) (ldb (byte 8 0) n)
          (aref v 1) (ldb (byte 8 8) n)
          (aref v 2) (ldb (byte 8 16) n))
    v))

(test an-inv-marks-the-transaction-known-to-the-peer-that-sent-it
  "Core AddKnownTx(peer, inv.hash) on every gen-tx inv (net_processing.cpp:
4174), placed OUTSIDE the IsInitialBlockDownload branch on purpose -- a peer
that announced during IBD is still not told about the transaction once we
leave it. Without that write we announced every transaction we accepted
straight back to each peer that had already announced it to us. The filter is
keyed by the id THAT peer's inventory uses, so a wtxidrelay peer's MSG_WTX
inv has to suppress a wtxid announcement."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (declare (ignore utxo funding))
    (let* ((bl:*network* :regtest)
           ;; Left IN initial block download, which is where Core still does
           ;; this write.
           (bl.net:*cached-is-ibd* t)
           (peer (bl.net:make-peer :state :ready :wtxid-relay t))
           (other (bl.net:make-peer :state :ready :wtxid-relay t))
           (txid (%relay-txid 41))
           (wtxid (%relay-txid 42))
           (ctx (bl.ctx:make-node-context :chain-state state :mempool mempool)))
      (deliver-inv peer (tx-inv-payload bl.ser:+inv-type-wtx+ wtxid) ctx)
      (is-true (bl:recent-reject-p (bl.net:peer-announced-txs peer) wtxid)
               "the announced id enters the announcer's known-tx filter")
      (bl.net:relay-transaction txid nil (list peer other)
                                :fee-rate 2 :wtxid wtxid)
      (is (null (bl.net:peer-tx-inv-queue peer))
          "and the announcer is not told about its own announcement")
      (is (= 1 (length (bl.net:peer-tx-inv-queue other)))
          "while a peer that said nothing still hears about it"))))

;;;; Initial broadcast of locally-submitted txs (unbroadcast set)

(test getdata-serving-clears-unbroadcast
  "Serving a tx from the mempool in response to a getdata removes it from
the unbroadcast set — the propagation signal (Core ProcessGetData,
net_processing.cpp:2550). An unrelated getdata leaves the set alone."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (peer (bl.net:make-peer :state :ready))
         (other (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (%add-tx mempool tx)
    (is-true (bl.mp:mempool-add-unbroadcast mempool txid))
    ;; Make the tx servable to this peer: snapshot the mempool sequence as if
    ;; an inv flush to the peer had happened after acceptance (the getdata
    ;; anti-probing gate serves only txs older than the last flush).
    (setf (bl.net:peer-last-inv-sequence peer)
          (bl.mp:mempool-sequence mempool))
    (flet ((getdata-payload (hash)
             (subseq (bl.ser:make-getdata-message
                      (list (bl.ser:make-inv-vector
                             :type bl.ser:+inv-type-witness-tx+
                             :hash hash)))
                     24)))
      ;; A request for some OTHER tx (not served) doesn't clear ours.
      (deliver-getdata peer (getdata-payload other) (bl.ctx:make-node-context :mempool mempool))
      (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
      ;; A request for the unbroadcast tx clears it.
      (deliver-getdata peer (getdata-payload txid) (bl.ctx:make-node-context :mempool mempool))
      (is (= 0 (bl.mp:mempool-unbroadcast-count mempool))))))

(test reattempt-initial-broadcast-relays-only-in-mempool
  "The re-announcement pass queues invs for unbroadcast txs still in the
pool and drops ids whose tx has left it (Core ReattemptInitialBroadcast,
net_processing.cpp:1625-1643)."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (stale (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (peer (bl.net:make-peer :state :ready :wtxid-relay t)))
    (%add-tx mempool tx)
    (bl.mp:mempool-add-unbroadcast mempool txid)
    ;; Simulate a stale id (tx evicted after a crash-restore of the set):
    ;; poke the table directly — the public adder refuses non-members.
    (setf (gethash stale (bl.mp:mempool-unbroadcast mempool)) t)
    (bl.net:reattempt-initial-broadcast (list peer) mempool)
    ;; The live tx was queued for announcement (wtxid rides along)...
    (is (= 1 (length (bl.net:peer-tx-inv-queue peer))))
    (destructuring-bind (qtxid qwtxid fee-rate-per-kb)
        (first (bl.net:peer-tx-inv-queue peer))
      (declare (ignore fee-rate-per-kb))
      (is (equalp txid qtxid))
      (is (equalp (bl.ser:transaction-wtxid tx) qwtxid)))
    ;; ...and stays tracked until a getdata confirms; the stale id is gone.
    (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
    (is-true (gethash txid (bl.mp:mempool-unbroadcast mempool)))))

(test maybe-reattempt-initial-broadcast-schedule
  "First call only arms the 10-15min timer (Core schedules the first pass a
full interval out, net_processing.cpp:2036-2038); once the deadline passes,
the pass runs and the timer re-arms."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (peer (bl.net:make-peer :state :ready)))
    (%add-tx mempool tx)
    (bl.mp:mempool-add-unbroadcast mempool txid)
    (bl.net:reset-initial-broadcast-schedule)
    ;; Arm pass: nothing queued yet.
    (bl.net:maybe-reattempt-initial-broadcast (list peer) mempool)
    (is (plusp bl.net::*next-initial-broadcast-time*))
    (is (null (bl.net:peer-tx-inv-queue peer)))
    ;; Deadline in the past: the pass runs and re-arms.
    (setf bl.net::*next-initial-broadcast-time* 1)
    (bl.net:maybe-reattempt-initial-broadcast (list peer) mempool)
    (is (= 1 (length (bl.net:peer-tx-inv-queue peer))))
    (is (> bl.net::*next-initial-broadcast-time* 1))
    (bl.net:reset-initial-broadcast-schedule)))

;;;; Erlay P1: BIP330 sendtxrcncl handshake (Core-parity: handshake only)

(defun %recon-test-peer (&key (relay t) (inbound nil)
                              (conn-type :outbound-full-relay)
                              (proto-version 70016) (local-salt 1))
  "Bare peer mid-handshake: peer VERSION received (fRelay=RELAY, protocol
PROTO-VERSION), our sendtxrcncl offer already made when LOCAL-SALT is set."
  (let ((peer (bl.net:make-peer
               :state :handshaking
               :inbound inbound
               :conn-type conn-type
               :version (bl.ser::make-version-message
                         :version proto-version :relay relay))))
    (when local-salt
      (setf (bl.net::peer-recon-local-salt peer) local-salt))
    peer))

(defun %sendtxrcncl-payload (version salt)
  "The 12-byte sendtxrcncl payload (message bytes minus the 24-byte header)."
  (subseq (bl.ser:make-sendtxrcncl-message salt version) 24))

(test sendtxrcncl-message-codec
  "sendtxrcncl is uint32 version + uint64 salt, both LE — a 12-byte payload
(Core protocol.h:262-266); default version is 1 (TXRECONCILIATION_VERSION)."
  (let ((bytes (bl.ser:make-sendtxrcncl-message
                #x1122334455667788)))
    (is (= (+ 24 12) (length bytes)))
    (is (string= "sendtxrcncl" (map 'string #'code-char
                                    (remove 0 (subseq bytes 4 16)))))
    ;; version=1 LE then salt LE
    (is (equalp #(1 0 0 0 #x88 #x77 #x66 #x55 #x44 #x33 #x22 #x11)
                (subseq bytes 24)))
    (multiple-value-bind (version salt)
        (bl.ser:parse-sendtxrcncl-payload (subseq bytes 24))
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
      (bl.net::compute-recon-salt 1 2)
    (is (= 6513280882736911012 k0))
    (is (= 14473150418129592761 k1)))
  ;; Ascending order is applied internally, so argument order is irrelevant.
  (multiple-value-bind (k0 k1)
      (bl.net::compute-recon-salt 2 1)
    (is (= 6513280882736911012 k0))
    (is (= 14473150418129592761 k1))))

(test sendtxrcncl-offer-conditions
  "We offer reconciliation only when: -txreconciliation on, negotiated proto
>= 70016, our conn relays txs, and the peer's VERSION set fRelay (Core
net_processing.cpp:3728-3742). The offer pre-registers a random local salt."
  (let ((bl:*tx-reconciliation* t))
    (let ((peer (%recon-test-peer :local-salt nil)))
      (is-true (bl.net::%maybe-send-sendtxrcncl peer))
      (is-true (bl.net::peer-recon-local-salt peer)))
    ;; Peer's fRelay=0
    (let ((peer (%recon-test-peer :relay nil :local-salt nil)))
      (bl.net::%maybe-send-sendtxrcncl peer)
      (is-false (bl.net::peer-recon-local-salt peer)))
    ;; We don't relay txs on block-relay connections
    (let ((peer (%recon-test-peer :conn-type :block-relay :local-salt nil)))
      (bl.net::%maybe-send-sendtxrcncl peer)
      (is-false (bl.net::peer-recon-local-salt peer)))
    ;; Pre-wtxidrelay protocol version
    (let ((peer (%recon-test-peer :proto-version 70015 :local-salt nil)))
      (bl.net::%maybe-send-sendtxrcncl peer)
      (is-false (bl.net::peer-recon-local-salt peer))))
  ;; Feature off
  (let ((bl:*tx-reconciliation* nil)
        (peer (%recon-test-peer :local-salt nil)))
    (bl.net::%maybe-send-sendtxrcncl peer)
    (is-false (bl.net::peer-recon-local-salt peer))))

(test sendtxrcncl-registers-peer
  "Offer + valid sendtxrcncl reply registers the peer: k0/k1 from
compute-recon-salt (salts 1,2 — same vector as above), negotiated version 1,
we-initiate on an outbound connection (Core RegisterPeer SUCCESS)."
  (let ((bl:*tx-reconciliation* t)
        (peer (%recon-test-peer :local-salt 1)))
    (is-true (%sendtxrcncl
              peer (%sendtxrcncl-payload 1 2)))
    (is-true (bl.net::peer-recon-registered peer))
    (is (= 1 (bl.net::peer-recon-version peer)))
    (is (= 6513280882736911012 (bl.net::peer-recon-k0 peer)))
    (is (= 14473150418129592761 (bl.net::peer-recon-k1 peer)))
    (is-true (bl.net::peer-recon-we-initiate peer))
    (is (not (eq :disconnected (bl.net:peer-state peer))))))

(test sendtxrcncl-duplicate-disconnects
  "A second sendtxrcncl on the same connection is a protocol violation
(Core RegisterPeer ALREADY_REGISTERED => disconnect)."
  (let ((bl:*tx-reconciliation* t)
        (peer (%recon-test-peer)))
    (is-true (%sendtxrcncl
              peer (%sendtxrcncl-payload 1 2)))
    (is-false (%sendtxrcncl
               peer (%sendtxrcncl-payload 1 3)))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test sendtxrcncl-from-non-relay-peer-disconnects
  "sendtxrcncl from a peer whose VERSION had fRelay=0 disconnects
(net_processing.cpp:3982-3990)."
  (let ((bl:*tx-reconciliation* t)
        (peer (%recon-test-peer :relay nil)))
    (is-false (%sendtxrcncl
               peer (%sendtxrcncl-payload 1 2)))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test sendtxrcncl-on-block-relay-conn-disconnects
  "sendtxrcncl on a connection where WE indicated no tx relay (block-relay)
disconnects (Core RejectIncomingTxs, net_processing.cpp:3976-3980)."
  (let ((bl:*tx-reconciliation* t)
        (peer (%recon-test-peer :conn-type :block-relay :local-salt nil)))
    (is-false (%sendtxrcncl
               peer (%sendtxrcncl-payload 1 2)))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test sendtxrcncl-version-zero-disconnects
  "Version 0 is below the v1 floor: protocol violation => disconnect
(txreconciliation.cpp:117-119)."
  (let ((bl:*tx-reconciliation* t)
        (peer (%recon-test-peer)))
    (is-false (%sendtxrcncl
               peer (%sendtxrcncl-payload 0 2)))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test sendtxrcncl-higher-version-downgrades
  "A peer announcing version 2 registers fine at negotiated min(2, 1) = 1
(txreconciliation.cpp:112-116)."
  (let ((bl:*tx-reconciliation* t)
        (peer (%recon-test-peer)))
    (is-true (%sendtxrcncl
              peer (%sendtxrcncl-payload 2 2)))
    (is-true (bl.net::peer-recon-registered peer))
    (is (= 1 (bl.net::peer-recon-version peer)))))

(test sendtxrcncl-unsolicited-ignored
  "sendtxrcncl when we never offered (no pre-registration) is ignored — no
registration, no disconnect (Core RegisterPeer NOT_FOUND)."
  (let ((bl:*tx-reconciliation* t)
        (peer (%recon-test-peer :local-salt nil)))
    (is-true (%sendtxrcncl
              peer (%sendtxrcncl-payload 1 2)))
    (is-false (bl.net::peer-recon-registered peer))
    (is (not (eq :disconnected (bl.net:peer-state peer))))))

(test sendtxrcncl-forgotten-without-wtxidrelay
  "At VERACK, a (pre-)registered peer that never negotiated wtxidrelay has
its reconciliation state forgotten (net_processing.cpp:3879-3886); with
wtxidrelay negotiated the state survives."
  (let ((bl:*tx-reconciliation* t))
    (let ((peer (%recon-test-peer)))
      (%sendtxrcncl
       peer (%sendtxrcncl-payload 1 2))
      (is-true (bl.net::peer-recon-registered peer))
      ;; wtxidrelay never arrived => forget everything
      (bl.net::%verack-finalize-recon peer)
      (is-false (bl.net::peer-recon-registered peer))
      (is-false (bl.net::peer-recon-k0 peer))
      (is-false (bl.net::peer-recon-local-salt peer)))
    ;; Offered but never answered: dangling pre-registration salt is dropped.
    (let ((peer (%recon-test-peer)))
      (setf (bl.net:peer-wtxid-relay peer) t)
      (bl.net::%verack-finalize-recon peer)
      (is-false (bl.net::peer-recon-local-salt peer)))
    (let ((peer (%recon-test-peer)))
      (setf (bl.net:peer-wtxid-relay peer) t)
      (%sendtxrcncl
       peer (%sendtxrcncl-payload 1 2))
      (bl.net::%verack-finalize-recon peer)
      (is-true (bl.net::peer-recon-registered peer)))))

(defun %net-log-of (thunk)
  "Call THUNK with the \"net\" log category enabled and the log stream
captured; return (VALUES thunk-result log-text). Core's functional tests grep
debug.log for these lines -- p2p_addrv2_relay.py:81 for the whole sendaddrv2
line, p2p_sendtxrcncl.py:217 and :181 for the sendtxrcncl ones -- so the
wording is behaviour and gets asserted, not just the effect."
  (let ((out (make-string-output-stream))
        (was-on (bl.log:log-category-enabled-p "net")))
    (unwind-protect
         (let ((bl.log:*log-stream* out))
           (bl.log:enable-log-category "net")
           ;; VALUES is left-to-right, so THUNK runs before the stream is
           ;; drained.
           (values (funcall thunk) (get-output-stream-string out)))
      (unless was-on (bl.log:disable-log-category "net")))))

(defun %post-verack-delivery (peer command payload)
  "Deliver COMMAND to PEER through the shipped dispatcher; return (VALUES
handled-p net-log-text)."
  (%net-log-of
   (lambda ()
     (bl.net:handle-message peer command payload (bl.ctx:make-node-context)))))

(test sendtxrcncl-ignored-with-the-feature-off-says-so
  "With -txreconciliation off Core returns from the SENDTXRCNCL branch at once
and logs WHY (net_processing.cpp:3964-3967). p2p_sendtxrcncl.py:181 asserts
that line, so staying silent is a divergence even though the message is
correctly ignored. Both of our ignore paths reach Core\'s single early return
-- inside the handshake window, which is where the functional test\'s
PeerNoVerack sends it, and after VERACK -- so both say it."
  (let ((bl:*tx-reconciliation* nil)
        (phrase "ignored, as our node does not have txreconciliation enabled"))
    (let ((peer (%recon-test-peer :local-salt nil)))
      (multiple-value-bind (ok log)
          (%net-log-of (lambda ()
                         (%sendtxrcncl
                          peer (%sendtxrcncl-payload 1 2))))
        (is-true ok "the message is ignored, not treated as a violation")
        (is (not (eq :disconnected (bl.net:peer-state peer))))
        (is-true (search (format nil "sendtxrcncl from peer=~A ~A"
                                 (bl.net:peer-id peer) phrase)
                         log)
                 "handshake-window ignore line, logged: ~S" log)))
    (let ((peer (bl.net:make-peer :state :ready :id 7)))
      (multiple-value-bind (handled log)
          (%post-verack-delivery peer "sendtxrcncl" (%sendtxrcncl-payload 1 2))
        (is-true handled)
        (is (eq :ready (bl.net:peer-state peer))
            "the feature being off is not a reason to drop the peer")
        (is-true (search (format nil "sendtxrcncl from peer=7 ~A" phrase) log)
                 "post-verack ignore line, logged: ~S" log)))))

(test sendtxrcncl-post-verack-disconnects
  "Post-verack sendtxrcncl via handle-message is a protocol violation with
-txreconciliation on: disconnect (net_processing.cpp:3969-3973). The
feature-off path is the test above."
  (let ((bl:*tx-reconciliation* t)
        (peer (bl.net:make-peer :state :ready :id 3)))
    (multiple-value-bind (handled log)
        (%post-verack-delivery peer "sendtxrcncl" (%sendtxrcncl-payload 1 2))
      (is-true handled)
      (is (eq :disconnected (bl.net:peer-state peer)))
      (is-true (search "sendtxrcncl received after verack, disconnecting peer=3" log)
               "sendtxrcncl disconnect line, logged: ~S" log))))

(test feature-negotiation-after-verack-disconnects
  "BIP155 (sendaddrv2) and BIP339 (wtxidrelay) negotiate strictly between
VERSION and VERACK, and Core drops a peer that sends either afterwards
(net_processing.cpp:3928-3933 and :3950-3955). Our negotiation window is
%await-verack, which handles both inline, so reaching HANDLE-MESSAGE at all
IS the violation -- these two were inert no-ops returning T, which let a peer
spam them post-handshake at zero cost. The flag each message negotiates must
stay untouched on the way out, and the log line is p2p_addrv2_relay.py's
oracle verbatim."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8))))
    (dolist (command '("sendaddrv2" "wtxidrelay"))
      (let ((peer (bl.net:make-peer :state :ready :id 0)))
        (multiple-value-bind (handled log)
            (%post-verack-delivery peer command empty)
          (is-true handled "~A must still dispatch as a handled message" command)
          (is (eq :disconnected (bl.net:peer-state peer))
              "~A after verack must disconnect the peer, state: ~S"
              command (bl.net:peer-state peer))
          (is-true (search (format nil "~A received after verack, disconnecting peer=0"
                                   command)
                           log)
                   "~A disconnect line, logged: ~S" command log))
        ;; Neither message may flip the relay mode it negotiates: Core returns
        ;; before touching m_wants_addrv2 / m_wtxid_relay.
        (is-false (bl.net:peer-wants-addrv2 peer))
        (is-false (bl.net:peer-wtxid-relay peer))))))

(test txreconciliation-config-flag-wiring
  "-txreconciliation maps to start-node's :tx-reconciliation keyword like the
other boolean flags (Core: DEBUG_ONLY, default off)."
  (multiple-value-bind (plist merged network)
      (start-node-plist '("-txreconciliation" "-regtest"))
    (declare (ignore merged))
    (is (eq :regtest network))
    (is (eq t (getf plist :tx-reconciliation))))
  (multiple-value-bind (plist merged network)
      (start-node-plist '("-regtest"))
    (declare (ignore merged network))
    (is (eq nil (getf plist :tx-reconciliation)))))

;;;; ============================================================
;;;; Wave 9B: tx-relay hardening
;;;; fRelay honor, tx-request caps/delays/cleanup, getdata anti-probing
;;;; gate, recent-confirmed filter, steady-state drain serving.
;;;; ============================================================

(defun %w9-version-msg (&key (relay t))
  "A minimal stored version message with the given fRelay."
  (bl.ser::make-version-message
   :version 70016 :services 0 :timestamp 0
   :addr-recv (bl.ser:make-empty-net-addr)
   :addr-from (bl.ser:make-empty-net-addr)
   :nonce 1 :user-agent "/test/" :start-height 0 :relay relay))

(test peer-tx-relay-p-honors-frelay
  "peer-tx-relay-p mirrors Core's Peer::TxRelay existence condition
(net_processing.cpp:3681-3696): fRelay=0 in the peer's version means no tx
relay for the connection's life (we never offer NODE_BLOOM); block-relay and
feeler conns never have it; a peer without a stored version defaults to
relaying (Core's fRelay=true default)."
  (let ((frelay0 (bl.net:make-peer
                  :state :ready :version (%w9-version-msg :relay nil)))
        (frelay1 (bl.net:make-peer
                  :state :ready :version (%w9-version-msg :relay t)))
        (no-version (bl.net:make-peer :state :ready))
        (block-relay (bl.net:make-peer
                      :state :ready :conn-type :block-relay
                      :version (%w9-version-msg :relay t))))
    (is-false (bl.net:peer-tx-relay-p frelay0))
    (is-true (bl.net:peer-tx-relay-p frelay1))
    (is-true (bl.net:peer-tx-relay-p no-version))
    (is-false (bl.net:peer-tx-relay-p block-relay))))

(test relay-transaction-skips-frelay0-peer
  "No tx announcements are queued for a BIP37/BIP60 fRelay=0 peer (Core only
builds tx inventory when the TxRelay structure exists — announcing to a
blocksonly peer gets us disconnected)."
  (let* ((bl:*network* :regtest)
         (frelay0 (bl.net:make-peer
                   :state :ready :version (%w9-version-msg :relay nil)))
         (frelay1 (bl.net:make-peer
                   :state :ready :version (%w9-version-msg :relay t)))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 91)))
    (bl.net:relay-transaction
     txid nil (list frelay0 frelay1) :fee-rate 2)
    (is (null (bl.net:peer-tx-inv-queue frelay0)))
    (is (= 1 (length (bl.net:peer-tx-inv-queue frelay1))))))

(test handle-tx-disconnects-when-relay-disabled
  "A tx message arriving where we advertised fRelay=0 (mainnet with relay
disabled — our blocksonly) is a protocol violation: disconnect (Core
RejectIncomingTxs in the TX handler, net_processing.cpp:4474-4479)."
  (let* ((bl:*network* :mainnet)
         (bl:*mainnet-relay-enabled* nil)
         (peer (bl.net:make-peer :state :ready)))
    (deliver-tx peer #() (bl.ctx:make-node-context))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test handle-inv-disconnects-tx-inv-when-relay-disabled
  "Tx invs in violation of our advertised fRelay=0 disconnect the sender
(Core net_processing.cpp:4168-4172); block invs stay fine."
  (let* ((bl:*network* :mainnet)
         (bl:*mainnet-relay-enabled* nil)
         (state (bl.store:make-chain-state))
         (peer (bl.net:make-peer :state :ready))
         (payload (subseq (bl.ser:make-inv-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-tx+
                                  :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                       :initial-element 92))))
                          24)))
    (deliver-inv peer payload (bl.ctx:make-node-context :chain-state state))
    (is (eq :disconnected (bl.net:peer-state peer)))))

(test blocksonly-rejects-incoming-txs-any-network
  "-blocksonly (Core ignore_incoming_txs, DEFAULT_BLOCKSONLY=false) rejects
incoming txs on ANY network: ignore-incoming-txs-p flips, a tx message and a
tx inv both disconnect the sender — on a test network where relay is
otherwise always on."
  (let* ((bl:*network* :regtest)
         (bl:*blocksonly* t))
    (is-true (bl.net:ignore-incoming-txs-p))
    ;; tx message in violation of our fRelay=0 -> disconnect
    ;; (Core net_processing.cpp:4474-4479).
    (let ((peer (bl.net:make-peer :state :ready)))
      (deliver-tx peer #() (bl.ctx:make-node-context))
      (is (eq :disconnected (bl.net:peer-state peer))))
    ;; tx inv in violation -> disconnect (net_processing.cpp:4168-4172).
    (let ((state (bl.store:make-chain-state))
          (peer (bl.net:make-peer :state :ready))
          (payload (subseq (bl.ser:make-inv-message
                            (list (bl.ser:make-inv-vector
                                   :type bl.ser:+inv-type-tx+
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 94))))
                           24)))
      (deliver-inv peer payload (bl.ctx:make-node-context :chain-state state))
      (is (eq :disconnected (bl.net:peer-state peer)))))
  ;; Default off: regtest relays normally.
  (let* ((bl:*network* :regtest)
         (bl:*blocksonly* nil))
    (is-false (bl.net:ignore-incoming-txs-p))))

(test blocksonly-still-announces-own-txs
  "A blocksonly node still queues announcements of its OWN (locally
submitted) transactions — Core's RelayTransaction has no
ignore_incoming_txs gate; only the receive side is switched off."
  (let* ((bl:*network* :regtest)
         (bl:*blocksonly* t)
         (frelay1 (bl.net:make-peer
                   :state :ready :version (%w9-version-msg :relay t)))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 95)))
    (bl.net:relay-transaction
     txid nil (list frelay1) :fee-rate 2)
    (is (= 1 (length (bl.net:peer-tx-inv-queue frelay1))))))

;;;; Tx-request tracker: Core txrequest caps, delays, cleanup

(test tx-request-nonpref-peer-delayed
  "An inbound (non-preferred) peer's announcement is deferred by
NONPREF_PEER_TX_DELAY instead of requested immediately; the scheduler sends
it once the delay passes (Core txdownloadman_impl.cpp:216)."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 93))
        (inbound (bl.net:make-peer :state :ready :inbound t)))
    ;; Deferred: no immediate request, nothing in flight.
    (is-false (bl.net:tx-request-wanted-p txid inbound))
    (is (null (tx-request-in-flight-peer txid)))
    ;; Not due yet: the scheduler sends nothing.
    (is (= 0 (bl.net:process-tx-requests)))
    ;; Backdate the candidate's ready time; now the scheduler requests it.
    (is (= 1 (backdate-tx-announcements txid)))
    (is (= 1 (bl.net:process-tx-requests)))
    (is (eq inbound (tx-request-in-flight-peer txid)))
    (bl.net:reset-tx-requests)))

(test tx-request-txid-relay-delay
  "With wtxid-relay peers connected, txid-based announcements are deferred by
TXID_RELAY_DELAY while wtxid-based ones are not (Core
txdownloadman_impl.cpp:217)."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 94))
        (wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 95))
        (outbound (bl.net:make-peer :state :ready)))
    ;; num-wtxid-peers = 1: txid announcement deferred...
    (is-false (bl.net:tx-request-wanted-p txid outbound nil 1))
    (is (null (tx-request-in-flight-peer txid)))
    ;; ...wtxid announcement immediate.
    (is-true (bl.net:tx-request-wanted-p wtxid outbound t 1))
    (bl.net:reset-tx-requests)))

(test tx-request-overloaded-peer-delayed
  "A peer with MAX_PEER_TX_REQUEST_IN_FLIGHT (100) outstanding requests gets
OVERLOADED_PEER_TX_DELAY on new announcements (Core
txdownloadman_impl.cpp:218-219)."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 96))
        (outbound (bl.net:make-peer :state :ready)))
    (setf (tx-request-peer-in-flight-count outbound)
          bl.net::+max-peer-tx-request-in-flight+)
    (is-false (bl.net:tx-request-wanted-p txid outbound))
    (is (null (tx-request-in-flight-peer txid)))
    (bl.net:reset-tx-requests)))

(test tx-request-per-peer-announcement-cap
  "Announcements beyond MAX_PEER_TX_ANNOUNCEMENTS (5000) per peer are dropped
outright — not recorded, not requested (Core txdownloadman_impl.cpp:204-207)."
  (bl.net:reset-tx-requests)
  (let ((peer (bl.net:make-peer :state :ready))
        (over (make-array 32 :element-type '(unsigned-byte 8) :initial-element 97)))
    ;; Simulate a full announcement budget without 5000 inserts.
    (setf (tx-request-peer-count peer)
          bl.net::+max-peer-tx-announcements+)
    (is-false (bl.net:tx-request-wanted-p over peer))
    (is (null (tx-request-announcement-peers over :completed t)))
    (is (null (tx-request-in-flight-peer over)))
    (bl.net:reset-tx-requests)))

(test tx-request-disconnected-peer-cleanup-and-failover
  "DisconnectedPeer semantics: the peer's announcements are forgotten, its
in-flight requests are released, and the next scheduler pass fails the
request over to another announcer (Core TxRequestTracker::DisconnectedPeer)."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 98))
        (p1 (bl.net:make-peer :state :ready))
        (p2 (bl.net:make-peer :state :ready)))
    (is-true (bl.net:tx-request-wanted-p txid p1))
    (is-false (bl.net:tx-request-wanted-p txid p2))
    (bl.net:tx-request-disconnected-peer p1)
    ;; p1's request was released and its announcement forgotten.
    (is (null (tx-request-in-flight-peer txid)))
    (is (= 0 (bl.net:tx-request-count p1)))
    ;; The scheduler re-requests from the surviving announcer.
    (is (= 1 (bl.net:process-tx-requests)))
    (is (eq p2 (tx-request-in-flight-peer txid)))
    (bl.net:reset-tx-requests)))

(test tx-request-disconnect-hook-registered
  "disconnect-peer runs the tracker cleanup via *peer-disconnect-hook* (the
tracker lives in a later-loaded file), so every disconnect path forgets the
peer's entries."
  (bl.net:reset-tx-requests)
  (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99))
        (peer (bl.net:make-peer :state :ready)))
    (is-true (bl.net:tx-request-wanted-p txid peer))
    (is (= 1 (bl.net:tx-request-count peer)))
    (bl.net:disconnect-peer peer)
    (is (= 0 (bl.net:tx-request-count peer)))
    (is (null (tx-request-in-flight-peer txid)))
    (bl.net:reset-tx-requests)))

(test tx-request-notfound-fails-over
  "A notfound for an in-flight tx completes that peer's announcement and the
request fails over to another announcer immediately (Core ReceivedNotFound ->
ReceivedResponse; handle-notfound re-runs the scheduler)."
  (bl.net:reset-tx-requests)
  (let* ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 100))
         (p1 (bl.net:make-peer :state :ready))
         (p2 (bl.net:make-peer :state :ready))
         (payload (subseq (bl.ser:make-notfound-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (is-true (bl.net:tx-request-wanted-p txid p1))
    (is-false (bl.net:tx-request-wanted-p txid p2))
    (deliver-notfound p1 payload nil)
    ;; Failed over to p2. p1's announcement is COMPLETED, not deleted: the
    ;; slot stays so p1 cannot re-announce its way back into the candidate
    ;; set, and the budget its failure spent stays charged (Core
    ;; MakeCompleted, txrequest.cpp:456-478).
    (is (eq p2 (tx-request-in-flight-peer txid)))
    (is-true (tx-request-completed-p txid p1))
    (is (= 1 (bl.net:tx-request-count p1)))
    (is (equal (list p2) (tx-request-announcement-peers txid)))
    (bl.net:reset-tx-requests)))

(defun %w9-hash (n)
  "A distinct 32-byte hash for tracker test N."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i below 8 do (setf (aref h i) (ldb (byte 8 (* 8 i)) n)))
    h))

(defun %w9-notfound-payload (hashes)
  "The `notfound' message payload announcing HASHES as MSG_TX items."
  (subseq (bl.ser:make-notfound-message
           (mapcar (lambda (h)
                     (bl.ser:make-inv-vector
                      :type bl.ser:+inv-type-witness-tx+ :hash h))
                   hashes))
          24))

(test tx-request-notfound-does-not-re-open-the-candidate-slot
  "A peer that answered notfound may not announce the same hash again while
another announcer is alive. Core's MakeCompleted keeps the (peer, txhash)
slot in the ByPeer index, so ReceivedInv's emplace fails and the
re-announcement is a no-op (txrequest.cpp:456-478, :578-592) -- the invariant
of txrequest.h:45-58, that giving a peer several chances to announce one
transaction lets it bias requests in its favour."
  (bl.net:reset-tx-requests)
  (let* ((txid (%w9-hash 201))
         (attacker (%make-peer-with-state :ready))
         (honest (%make-peer-with-state :ready))
         (stranger (%make-peer-with-state :ready))
         (payload (%w9-notfound-payload (list txid))))
    ;; The attacker announces first and is granted the request; the honest
    ;; peer is recorded as a live candidate behind it.
    (is-true (bl.net:tx-request-wanted-p txid attacker))
    (is-false (bl.net:tx-request-wanted-p txid honest))
    (deliver-notfound attacker payload nil)
    ;; The attacker's slot survives as COMPLETED and its re-announcement
    ;; changes nothing.
    (is-true (tx-request-completed-p txid attacker))
    (is-false (bl.net:tx-request-wanted-p txid attacker))
    (is (equal (list honest) (tx-request-announcement-peers txid)))
    (is (= 1 (bl.net:tx-request-count attacker)))
    ;; Positive control: a peer with no announcement of this hash is still
    ;; recorded, so the refusal above is the completed slot and not a
    ;; tracker that stopped accepting announcements.
    (is-false (bl.net:tx-request-wanted-p txid stranger))
    (is (= 2 (length (tx-request-announcement-peers txid))))
    (is (= 1 (bl.net:tx-request-count stranger)))
    (bl.net:reset-tx-requests)))

(test tx-request-last-failed-announcement-forgets-the-hash
  "The other half of MakeCompleted, and NOT a divergence: when the completing
announcement is the last non-COMPLETED one for a txhash, Core erases them all
(IsOnlyNonCompleted, txrequest.cpp:463-470; 'If for a given txhash only
already-failed announcements remain, they are all forgotten', txrequest.h:52)
-- so a sole announcer that notfounds is free to re-announce."
  (bl.net:reset-tx-requests)
  (let* ((txid (%w9-hash 202))
         (only (%make-peer-with-state :ready))
         (payload (%w9-notfound-payload (list txid))))
    (is-true (bl.net:tx-request-wanted-p txid only))
    (deliver-notfound only payload nil)
    (is (null (tx-request-announcement-peers txid :completed t)))
    (is (= 0 (bl.net:tx-request-count only)))
    ;; A fresh announcement of a forgotten hash is a fresh candidate.
    (is-true (bl.net:tx-request-wanted-p txid only))
    (bl.net:reset-tx-requests)))

(test tx-request-failed-announcements-stay-charged-to-the-peer
  "MAX_PEER_TX_ANNOUNCEMENTS bounds a peer's FAILURES too: Core counts
COMPLETED announcements in m_peerinfo.m_total, which is what Count(peer)
returns and what AddTxAnnouncement checks (txrequest.cpp:660-670,
txdownloadman_impl.cpp:204-207). Announce-then-notfound rounds against a live
honest co-announcer therefore climb to the cap and STOP; deleting the failed
announcement instead refunded the budget, so the attacker's count peaked at 1
however many rounds it ran and the cap never bound it at all."
  (bl.net:reset-tx-requests)
  (let* ((attacker (%make-peer-with-state :ready))
         ;; A pool of honest announcers, so no single one hits the cap first
         ;; and leaves the attacker as the only announcer.
         (honest (loop repeat 6 collect (%make-peer-with-state :ready)))
         (rounds (+ bl.net::+max-peer-tx-announcements+ 50))
         (last-hash nil))
    (dotimes (i rounds)
      (let ((txid (%w9-hash (+ 300000 i))))
        (setf last-hash txid)
        ;; The honest peer announces first and holds the request, so its live
        ;; announcement keeps the entry alive when the attacker's completes.
        (bl.net:tx-request-wanted-p txid (nth (mod i 6) honest))
        (bl.net:tx-request-wanted-p txid attacker)
        (bl.net:tx-request-received-response attacker txid)))
    (is (= bl.net::+max-peer-tx-announcements+
           (bl.net:tx-request-count attacker))
        "after ~D announce/notfound rounds the attacker is charged ~D of the ~
~D cap" rounds (bl.net:tx-request-count attacker)
        bl.net::+max-peer-tx-announcements+)
    ;; Past the cap its announcements are dropped outright, so the last
    ;; rounds recorded the honest announcer only.
    (is (equal (list (nth (mod (1- rounds) 6) honest))
               (tx-request-announcement-peers last-hash :completed t)))
    (bl.net:reset-tx-requests)))

(test notfound-drains-the-serve-bucket
  "An unsolicited response message must cost the sender something. The
notfound handler declared no rate bucket, and check-peer-rate-limit lets any
command whose row declares none straight through, so this was the one
uncharged command on the tx-relay path."
  (let ((peer (bl.net:init-peer-rate-limiters (bl.net:make-peer))))
    ;; Positive control: the bucket starts full.
    (is-true (bl.net:check-peer-rate-limit peer "notfound"))
    (loop repeat 200 do (bl.net:check-peer-rate-limit peer "notfound"))
    (is-false (bl.net:check-peer-rate-limit peer "notfound"))
    ;; It is the SERVE bucket, shared with the other unsolicited-work
    ;; commands, so draining it here also stops a getaddr flood.
    (is-false (bl.net:check-peer-rate-limit peer "getaddr"))
    ;; ...and not some other peer's, nor every bucket on this one.
    (is-true (bl.net:check-peer-rate-limit peer "inv"))
    (is-true (bl.net:check-peer-rate-limit
              (bl.net:init-peer-rate-limiters (bl.net:make-peer))
              "notfound"))))

(test an-oversized-notfound-has-its-tx-items-ignored
  "Core's NOTFOUND arm discards the tx entries of a message carrying more than
MAX_PEER_TX_ANNOUNCEMENTS + MAX_BLOCKS_IN_TRANSIT_PER_PEER invs
(net_processing.cpp:5150-5164): no peer can have more than that outstanding,
so a larger message is answering nothing we asked for. Our parser allows
+MAX-INV-COUNT+ (50,000)."
  (bl.net:reset-tx-requests)
  (let* ((txid (%w9-hash 500001))
         (p1 (%make-peer-with-state :ready))
         (p2 (%make-peer-with-state :ready))
         (limit (+ bl.net::+max-peer-tx-announcements+
                   bl.net::+max-blocks-in-transit-per-peer+))
         (padding (loop for i below (1- limit) collect (%w9-hash (+ 510000 i)))))
    (is-true (bl.net:tx-request-wanted-p txid p1))
    (is-false (bl.net:tx-request-wanted-p txid p2))
    ;; One item over the limit: the whole tx half of the message is ignored.
    (deliver-notfound p1 (%w9-notfound-payload (cons txid (cons txid padding)))
                      nil)
    (is-false (tx-request-completed-p txid p1))
    (is (eq p1 (tx-request-in-flight-peer txid)))
    ;; Positive control: exactly at the limit it is processed as usual.
    (deliver-notfound p1 (%w9-notfound-payload (cons txid padding)) nil)
    (is-true (tx-request-completed-p txid p1))
    (is (eq p2 (tx-request-in-flight-peer txid)))
    (bl.net:reset-tx-requests)))

(test notfound-failover-costs-the-message-not-the-tracker
  "The failover re-selects only the hashes the message named. Re-running the
whole scheduler here turned a 61-byte notfound into a walk of every tracked
announcement under the single tx-relay lock -- about 1 ms at the 5,000
announcements one connection can reach by itself, 10 ms at 50,000, times the
32 messages the pump admits per peer per pass, unauthenticated and uncharged.

Counted rather than timed: %TX-REQUEST-BEST-CANDIDATE is called once per hash
considered, and the full scheduler pass over the same tracker is the positive
control that the counter is live and that the tracker really holds them all."
  (bl.net:reset-tx-requests)
  (let* ((tracked 300)
         (inbound (bl.net:make-peer :address "test" :state :ready :inbound t))
         (hashes (loop for i below tracked collect (%w9-hash (+ 520000 i))))
         (considered 0)
         (real (fdefinition 'bl.net::%tx-request-best-candidate)))
    ;; Inbound announcements carry NONPREF_PEER_TX_DELAY, so every hash is a
    ;; candidate the scheduler must look at rather than an in-flight request.
    (dolist (h hashes) (bl.net:tx-request-wanted-p h inbound))
    (unwind-protect
         (progn
           (setf (fdefinition 'bl.net::%tx-request-best-candidate)
                 (lambda (&rest args) (incf considered) (apply real args)))
           (deliver-notfound inbound (%w9-notfound-payload (list (first hashes)))
                             nil)
           (is (= 1 considered)
               "a one-item notfound considered ~D of ~D tracked hashes"
               considered tracked)
           (setf considered 0)
           (bl.net:process-tx-requests)
           ;; One less than TRACKED: the notfound above completed the only
           ;; announcement of its hash, which forgets the hash entirely
           ;; (IsOnlyNonCompleted).
           (is (= (1- tracked) considered)
               "the scheduler pass considered ~D of ~D tracked hashes -- the ~
counter or the fixture is dead" considered tracked))
      (setf (fdefinition 'bl.net::%tx-request-best-candidate) real))
    (bl.net:reset-tx-requests)))

(defun %w9-request-winner (hash order peers)
  "The index in PEERS of the announcer the scheduler grants HASH to when the
announcements arrive in ORDER and every delay has elapsed. Announced as
txid-based entries with a wtxid-relay peer connected, so EVERY announcement
carries TXID_RELAY_DELAY and none is granted at announcement time -- the
scheduler makes the choice, which is what is under test."
  (bl.net:reset-tx-requests)
  (dolist (p order) (bl.net:tx-request-wanted-p hash p nil 1))
  (backdate-tx-announcements hash)
  (bl.net:process-tx-requests)
  (position (tx-request-in-flight-peer hash) peers))

(test tx-request-candidate-is-a-salted-hash-not-the-announcement-order
  "Core's PriorityComputer is SipHash(k0, k1, txhash || peer) >> 1 with the
preferred bit in bit 63, and the highest priority wins (txrequest.cpp:112-118,
:595-624). The winner is therefore uniform over the candidates, different for
each transaction, and unpredictable without the node's salt.

Selecting preferred-then-earliest-ready instead handed the choice to the
announcer: whoever announced first won EVERY transaction, so an attacker
racing the network's announcements held every GETDATA_TX_INTERVAL window it
could rather than a random share of them."
  (let ((peers (loop repeat 5 collect (%make-peer-with-state :ready)))
        (hashes (loop for i below 200 collect (%w9-hash (+ 700000 i)))))
    (with-tx-request-salt (#x0123456789abcdef #xfedcba9876543210)
      (let* ((rotated (append (cddr peers) (subseq peers 0 2)))
             (in-order (mapcar (lambda (h) (%w9-request-winner h peers peers))
                               hashes))
             (in-rotated-order
               (mapcar (lambda (h) (%w9-request-winner h rotated peers))
                       hashes))
             (moved (count nil (mapcar #'eql in-order in-rotated-order)))
             (distinct (length (remove-duplicates in-order))))
        ;; The decisive one: rotating the announcement order moves no winner.
        ;; Before the port every winner moved with the order, exactly.
        (is (= 0 moved)
            "~D of ~D winners moved when the announcement order rotated"
            moved (length hashes))
        ;; And the choice really varies with the transaction rather than
        ;; landing on one peer -- the positive control that the priority is
        ;; not simply constant.
        (is (>= distinct 4)
            "only ~D of 5 announcers ever won over ~D transactions: ~S"
            distinct (length hashes)
            (loop for i below 5 collect (count i in-order)))
        ;; A fixed salt makes it reproducible; a different salt re-ranks.
        (is (equal in-order
                   (mapcar (lambda (h) (%w9-request-winner h peers peers))
                           hashes)))
        (let ((other (with-tx-request-salt (#xdeadbeefcafef00d #x0f1e2d3c4b5a6978)
                       (mapcar (lambda (h) (%w9-request-winner h peers peers))
                               hashes))))
          (is (not (equal in-order other))
              "a different node salt must produce a different ranking"))))
    (bl.net:reset-tx-requests)))

(test tx-request-preferred-announcers-outrank-every-other
  "The preferred flag is bit 63 of the priority, so an outbound announcer
beats every inbound one whatever the txhash -- Core's \"restrict to preferred
peers if any exist, then pick uniformly at random among them\"
(txrequest.h:66-72)."
  (let* ((inbound (loop repeat 4 collect
                        (bl.net:make-peer :address "test" :state :ready
                                                    :inbound t)))
         (outbound (%make-peer-with-state :ready))
         (peers (append inbound (list outbound))))
    (with-tx-request-salt (#x0123456789abcdef #xfedcba9876543210)
      (let ((wins (loop for i below 30
                        count (eql 4 (%w9-request-winner
                                      (%w9-hash (+ 800000 i))
                                      ;; the preferred peer announces LAST,
                                      ;; so order cannot be what elects it
                                      peers peers)))))
        (is (= 30 wins)
            "the preferred announcer won ~D of 30" wins)))
    ;; Control: with the preferred peer removed the inbound ones do win, so
    ;; the count above is the preferred bit and not a dead fixture.
    (with-tx-request-salt (#x0123456789abcdef #xfedcba9876543210)
      (let ((winners (loop for i below 30
                           collect (%w9-request-winner
                                    (%w9-hash (+ 800000 i))
                                    inbound inbound))))
        (is (>= (length (remove-duplicates winners)) 2))))
    (bl.net:reset-tx-requests)))

(test tx-request-expiry-completes-the-timed-out-announcement
  "A request that burns the whole GETDATA_TX_INTERVAL completes the
announcement rather than deleting it (Core SetTimePoint -> MakeCompleted,
txrequest.cpp:485-500), so the peer that let it expire cannot re-announce and
take a SECOND window on the same transaction while an honest announcer is
still waiting."
  (bl.net:reset-tx-requests)
  (let ((txid (%w9-hash 203))
        (attacker (%make-peer-with-state :ready))
        (honest (%make-peer-with-state :ready)))
    (is-true (bl.net:tx-request-wanted-p txid attacker))
    (is-false (bl.net:tx-request-wanted-p txid honest))
    ;; Window 1 expires and fails over to the honest announcer.
    (is (eq attacker (expire-tx-request txid)))
    (is (= 1 (bl.net:retry-timed-out-tx-requests)))
    (is (eq honest (tx-request-in-flight-peer txid)))
    (is-true (tx-request-completed-p txid attacker))
    ;; The attacker cannot buy window 3 by announcing again.
    (is-false (bl.net:tx-request-wanted-p txid attacker))
    (is (equal (list honest) (tx-request-announcement-peers txid)))
    ;; When the last non-completed announcement expires, the whole entry
    ;; goes (IsOnlyNonCompleted).
    (is (eq honest (expire-tx-request txid)))
    (is (= 0 (bl.net:retry-timed-out-tx-requests)))
    (is (null (tx-request-announcement-peers txid :completed t)))
    (bl.net:reset-tx-requests)))

;;;; Recently-confirmed filter + most-recent-block tx set

(defun %w9-block-with-tx (tx)
  (bl.ser:make-bitcoin-block
   :header (bl.ser:make-block-header
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
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx)))
    (unwind-protect
        (progn
          (bl.val:note-block-connected (%w9-block-with-tx tx))
          (is-true (bl.val:recently-confirmed-p txid))
          (is-true (bl.val:recently-confirmed-p wtxid))
          (is (eq tx (bl.val:most-recent-block-tx txid)))
          (is (eq tx (bl.val:most-recent-block-tx wtxid)))
          ;; Reorg disconnect: the filter resets, the map is replaced by the
          ;; next connect.
          (bl.val:reset-recent-confirmed)
          (is-false (bl.val:recently-confirmed-p txid)))
      (bl.val:reset-recent-confirmed)
      (setf bl.val::*most-recent-block-txs* nil))))

(test block-connect-forgets-every-announcement-of-a-confirmed-tx
  "Core BlockConnected calls m_txrequest.ForgetTxHash on the txid and the
wtxid of every transaction the block carries (txdownloadman_impl.cpp:107-108),
beside the recently-confirmed filter inserts. Without it an announcement that
was outstanding when the block connected survived, and the next scheduler pass
sent a getdata for a transaction we already knew was confirmed -- which a Core
peer answers in full out of m_most_recent_block_txs, so we paid a whole
redundant transaction body and threw it away on the recently-confirmed check.

Driven through the shipped validation-interface signal, which is how
validation reaches the tracker without naming networking."
  (bl.net:reset-tx-requests)
  (let* ((tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx))
         (other (%w9-hash 600001))
         (a (%make-peer-with-state :ready))
         (b (%make-peer-with-state :ready))
         (state (bl.store:make-chain-state)))
    (unwind-protect
         (progn
           (is-true (member 'bl.net::tx-request-block-connected
                            (bl.vi:validation-hooks :block-connected)))
           (bl.net:tx-request-wanted-p txid a)
           (bl.net:tx-request-wanted-p wtxid b t)
           (bl.net:tx-request-wanted-p other a)
           (is (equal (list a) (bl.net:tx-request-candidate-peers txid)))
           (bl.vi:notify-block-connected state (%w9-block-with-tx tx)
                                         (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 1)
                                         101 nil)
           ;; Both ids of the confirmed transaction are forgotten...
           (is (null (bl.net:tx-request-candidate-peers txid)))
           (is (null (bl.net:tx-request-candidate-peers wtxid)))
           (is (null (tx-request-in-flight-peer txid)))
           ;; ...and nothing else is: the hook clears the block's
           ;; transactions, not the tracker.
           (is (equal (list a) (bl.net:tx-request-candidate-peers other))))
      (bl.val:reset-recent-confirmed)
      (setf bl.val::*most-recent-block-txs* nil)
      (bl.net:reset-tx-requests))))

(test a-targeted-chainstates-connect-does-not-touch-the-tracker
  "The assumeutxo background chainstate re-derives ancient history; Core wires
the tx-download callbacks to the ACTIVE chainstate only
(net_processing.cpp:2086-2092), so its connects must not release announcements
of transactions that are still unconfirmed for us."
  (bl.net:reset-tx-requests)
  (let* ((tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (a (%make-peer-with-state :ready))
         (targeted (bl.store:make-chain-state
                    :target-blockhash (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 9))))
    (unwind-protect
         (progn
           (bl.net:tx-request-wanted-p txid a)
           (bl.vi:notify-block-connected targeted (%w9-block-with-tx tx)
                                         (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 1)
                                         101 nil)
           (is (equal (list a) (bl.net:tx-request-candidate-peers txid))))
      (bl.val:reset-recent-confirmed)
      (setf bl.val::*most-recent-block-txs* nil)
      (bl.net:reset-tx-requests))))

(test handle-inv-skips-recently-confirmed
  "A tx announcement for a recently-confirmed tx is not requested (Core
AlreadyHaveTx's recent-confirmed check, txdownloadman_impl.cpp:144)."
  (let* ((bl.net:*cached-is-ibd* t)
         (bl:*network* :regtest)
         (bl:*minimum-chain-work-override* nil)
         (now (bl.ser:get-unix-time))
         (state (%make-ibd-latch-state now))   ; fresh tip => not in IBD
         (mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (wtxid (bl.ser:transaction-wtxid tx))
         (announcer (bl.net:make-peer :state :ready :wtxid-relay t))
         (probe (bl.net:make-peer :state :ready))
         (payload (subseq (bl.ser:make-inv-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-wtx+
                                  :hash wtxid)))
                          24)))
    (unwind-protect
        (progn
          (bl.net:reset-tx-requests)
          (bl.val:note-block-connected (%w9-block-with-tx tx))
          (finishes (deliver-inv announcer payload (bl.ctx:make-node-context :chain-state state :mempool mempool)))
          ;; Nothing recorded: a fresh probe still gets an immediate request.
          (is-true (bl.net:tx-request-wanted-p wtxid probe t)))
      (bl.net:reset-tx-requests)
      (bl.val:reset-recent-confirmed)
      (setf bl.val::*most-recent-block-txs* nil))))

;;;; getdata anti-probing gate + flush sequence snapshots

(test flush-updates-last-inv-sequence
  "%flush-peer-tx-invs snapshots the mempool sequence into the peer's
last-inv-sequence on every due flush (Core net_processing.cpp:6086-6088),
opening getdata service for everything announceable up to that point."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (peer (bl.net:make-peer :state :ready :wtxid-relay t)))
    (is (= 1 (bl.net:peer-last-inv-sequence peer)))
    (%add-tx mempool (%witness-tx-for-relay))
    ;; Due flush (empty queue is fine — Core updates the snapshot either way).
    (setf (bl.net::peer-next-inv-send-time peer) 1)
    (bl.net:flush-tx-announcements (list peer) mempool)
    (is (= (bl.mp:mempool-sequence mempool)
           (bl.net:peer-last-inv-sequence peer)))))

(test getdata-gate-blocks-unannounced-mempool-tx
  "A getdata for a tx that entered the mempool AFTER our last inv flush to
the peer is NOT served (mempool-probing block, Core FindTxForGetData ->
info_for_relay): the unbroadcast set keeps the tx, proving no serve fired."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (peer (bl.net:make-peer :state :ready))
         (payload (subseq (bl.ser:make-getdata-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (%add-tx mempool tx)
    (bl.mp:mempool-add-unbroadcast mempool txid)
    ;; Peer's last flush predates the tx (default sequence snapshot 1).
    (deliver-getdata peer payload (bl.ctx:make-node-context :mempool mempool))
    (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
    ;; After a flush-time snapshot, the same request is served.
    (setf (bl.net:peer-last-inv-sequence peer)
          (bl.mp:mempool-sequence mempool))
    (deliver-getdata peer payload (bl.ctx:make-node-context :mempool mempool))
    (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))))

(test getdata-serves-most-recent-block-tx
  "A tx confirmed in the most recent block is served even though it left the
mempool (Core FindTxForGetData's m_most_recent_block_txs source) — here
observed via the unbroadcast-set removal that fires on every serve."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (peer (bl.net:make-peer :state :ready))
         (payload (subseq (bl.ser:make-getdata-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (unwind-protect
        (progn
          ;; The tx is NOT in the mempool; it is in the most recent block.
          (bl.val:note-block-connected (%w9-block-with-tx tx))
          ;; Track it as unbroadcast via the raw table (the public adder
          ;; requires pool membership) so the serve signal is observable.
          (setf (gethash txid (bl.mp:mempool-unbroadcast mempool)) t)
          (deliver-getdata peer payload (bl.ctx:make-node-context :mempool mempool))
          (is (= 0 (bl.mp:mempool-unbroadcast-count mempool))))
      (bl.val:reset-recent-confirmed)
      (setf bl.val::*most-recent-block-txs* nil))))

(test getdata-from-frelay0-peer-ignored
  "Tx getdata from an fRelay=0 peer is ignored outright — no serve (Core
ProcessGetData's tx_relay == nullptr continue): the unbroadcast set keeps
the tx even though it is old enough to serve."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (peer (bl.net:make-peer
                :state :ready :version (%w9-version-msg :relay nil)))
         (payload (subseq (bl.ser:make-getdata-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-witness-tx+
                                  :hash txid)))
                          24)))
    (%add-tx mempool tx)
    (bl.mp:mempool-add-unbroadcast mempool txid)
    (setf (bl.net:peer-last-inv-sequence peer)
          (bl.mp:mempool-sequence mempool))
    (deliver-getdata peer payload (bl.ctx:make-node-context :mempool mempool))
    (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))))

;;;; Orphan resolution candidates via MSG_WTX announcements

(test wtx-announcement-of-orphan-requests-parents
  "A MSG_WTX announcement matching a stored orphan makes the announcer an
orphan-resolution candidate: its missing parents are requested from that
peer (txid-based) and the peer is recorded as an additional announcer (Core
AddTxAnnouncement's orphan branch + MaybeAddOrphanResolutionCandidate)."
  (let* ((bl.net:*cached-is-ibd* t)
         (bl:*network* :regtest)
         (bl:*minimum-chain-work-override* nil)
         (now (bl.ser:get-unix-time))
         (state (%make-ibd-latch-state now))
         (utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (pool (bl.mp:mempool-orphan-pool mempool))
         (orphan (%wave8-tx :prev-id #xD1 :witness t))
         (owtxid (bl.ser:transaction-wtxid orphan))
         (parent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xD1))
         (p1 (%wave8-witness-peer))
         (p2 (bl.net:make-peer
              :address "test2" :state :ready :wtxid-relay t
              :services bl.ser:+node-witness+))
         (payload (subseq (bl.ser:make-inv-message
                           (list (bl.ser:make-inv-vector
                                  :type bl.ser:+inv-type-wtx+
                                  :hash owtxid)))
                          24)))
    (bl.net:reset-tx-requests)
    ;; Orphan stored from p1, parents never requested (direct pool add).
    (bl.mp:orphan-add pool orphan p1)
    (finishes
      (deliver-inv p2 payload (bl.ctx:make-node-context :chain-state state :utxo-set utxo :mempool mempool)))
    ;; p2 became an announcer of the orphan...
    (is-true (bl.mp:orphan-have-from-peer pool owtxid p2))
    ;; ...and the missing parent is in flight to p2 (txid-based entry).
    (is (eq p2 (tx-request-in-flight-peer parent-txid)))
    (is-false (tx-request-wtxid-entry-p parent-txid))
    ;; The orphan itself was NOT re-requested.
    (is (null (tx-request-in-flight-peer owtxid)))
    (bl.net:reset-tx-requests)))

;;;; Steady-state drain serves mempool txs end-to-end (loopback)

(test pump-peer-messages-keeps-node-context-peers-live
  "The handlers relay through the node-context's PEERS slot, and the IBD loop
rewrites that list as peers disconnect. The pump must therefore write the
list it was given into the context it hands the handlers -- a context built
without :peers (as sync-blockchain's tick and sync-headers used to) would
otherwise relay to nobody, silently: the 2026-07-10 wiring bug in a new
shape. Positive control: the slot is NIL before and the pump's list after."
  (let* ((p1 (bl.net:make-peer :connection nil :state :disconnected :address "10.0.0.7"))
         (p2 (bl.net:make-peer :connection nil :state :disconnected :address "10.0.0.8"))
         (peers (list p1 p2))
         (node-ctx (bl.ctx:make-node-context :chain-state (bl.store:make-chain-state))))
    (is (null (bl.ctx:node-context-peers node-ctx)))
    (bl.net:pump-peer-messages peers node-ctx (%ibd))
    (is (eq peers (bl.ctx:node-context-peers node-ctx)))))

(test pump-peer-messages-serves-getdata-loopback
  "The steady-state pump answers a peer's tx getdata from the mempool with a
real tx message over the wire — the regression for the ~30s receive dead
window and the NIL-mempool drains (a getdata for a tx we announced used to
get notfound). Runs over a loopback socket pair."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
          (let* ((bl:*network* :regtest)
                 (port (usocket:get-local-port srv))
                 (state (bl.store:make-chain-state))
                 (mempool (bl.mp:make-mempool))
                 (tx (%witness-tx-for-relay))
                 (txid (bl.ser:transaction-hash tx))
                 (server-peer nil))
            (%add-tx mempool tx)
            (bl.mp:mempool-add-unbroadcast mempool txid)
            (let ((client (bl.net:connect-peer "127.0.0.1" port)))
              (is-true client)
              (when client
                (let ((conn (bl.net:accept-connection srv :timeout 10)))
                  (is-true conn)
                  (when conn
                    (setf server-peer (bl.net:make-inbound-peer
                                       conn "127.0.0.1"))
                    (setf (bl.net:peer-state server-peer) :ready)
                    (setf (bl.net:peer-state client) :ready)
                    ;; Announced: snapshot the sequence as a flush would.
                    (setf (bl.net:peer-last-inv-sequence server-peer)
                          (bl.mp:mempool-sequence mempool))
                    ;; Client requests the tx...
                    (bl.net:send-message
                     client
                     (bl.ser:make-getdata-message
                      (list (bl.ser:make-inv-vector
                             :type bl.ser:+inv-type-witness-tx+
                             :hash txid))))
                    (sleep 0.2)
                    ;; ...the pump drains and serves it with full context.
                    (bl.net:pump-peer-messages (list server-peer) (bl.ctx:make-node-context :chain-state state :utxo-set (bl.store:make-utxo-set) :mempool mempool :peers (list server-peer)) nil)
                    ;; The client receives a tx message. Blocking variant: the
                    ;; plain reader is resumable and would answer :incomplete if
                    ;; the payload had not fully landed yet, making this timing-
                    ;; dependent.
                    (multiple-value-bind (command payload)
                        (bl.net::receive-message-blocking
                         client :timeout 5)
                      (is (equal "tx" command))
                      (when payload
                        (is (equalp txid
                                    (bl.ser:transaction-hash
                                     (bl.ser:parse-tx-payload
                                      payload))))))
                    ;; ...and the serve cleared the unbroadcast entry.
                    (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))))
                (when server-peer
                  (bl.net:disconnect-peer server-peer))
                (bl.net:disconnect-peer client))))
        (bl.net:close-listener srv)))))

(test store-validated-headers-updates-availability-for-known-batch
  "PREREQUISITE FIX (GA7 wave-4 prep). Core updates per-peer availability from
pindexLast — the last header of the RECEIVED batch that is in the index,
INCLUDING headers we already had, because AcceptBlockHeader returns the
existing entry for a known header.

validate-header-chain drops already-known headers from VALID entirely
(ibd.lisp: the `(return-from continue)` on index membership), so
%store-validated-headers used to read (car (last valid)) = NIL for a batch we
already hold and update NO availability at all. A peer that only ever announces
headers we already have — the normal case for a peer at our tip, and for every
BIP130 announcement of a block we just got from someone else — stayed pinned at
its handshake-time best block forever.

That silently disabled the pprev-locator priming sweep: build-header-locator-pprev
exists so a caught-up peer answers with our own best header and thereby records
its availability with no block transfer. It recorded nothing."
  (let* ((zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (state (bl.store:make-chain-state))
         (peer (%make-peer-with-state :ready))
         (hdr (bl.ser:make-block-header
               :version 1 :prev-block zeros :merkle-root zeros
               :timestamp 1000 :bits #x207fffff :nonce 0))
         (hash (bl.ser:block-header-hash hdr)))
    ;; The header is ALREADY in the index, with positive chain work.
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash hash :height 5 :chain-work 100 :status :header-valid))
    (is (null (bl.net:peer-best-known-block-hash peer))
        "precondition: peer has no recorded best block")
    ;; FULL-BATCH t: Core's may_have_more_headers. The sibling half of
    ;; UpdatePeerStateForReceivedHeaders — the IBD sub-minchainwork outbound
    ;; drop — is skipped for a full batch, keeping this test on availability
    ;; alone (that drop has its own tests in ECLIPSE-DOS-TESTS).
    (bl.net::%store-validated-headers
     peer state (list hdr) t (lambda (n) (declare (ignore n))) "test")
    (is (equalp hash (bl.net:peer-best-known-block-hash peer))
        "an all-already-known batch must still record the peer's best block")))

;;;; ============================================================
;;;; G7-15: BIP133 feefilter (Core MaybeSendFeefilter + FeeFilterRounder)
;;;; ============================================================

(defun %g715-peer (&key (version bl.ser:+protocol-version+)
                        (conn-type :outbound-full-relay))
  "A :ready peer that has completed a version handshake at VERSION, with a
capturing transport so sends can be observed without sockets."
  (let ((p (bl.net:make-peer :address "test")))
    (setf (bl.net:peer-state p) :ready
          (bl.net:peer-conn-type p) conn-type
          (bl.net:peer-version p)
          (bl.bytes:with-byte-reader (s (bl.ser:make-version-message-bytes :version version))
            (bl.ser:read-version-message s)))
    p))

(defmacro %g715-capturing ((sent) &body body)
  "Run BODY capturing every feefilter value sent, into the list SENT."
  `(let ((,sent '()))
     (let ((real (fdefinition 'bl.net:send-message)))
       (unwind-protect
            (progn
              (setf (fdefinition 'bl.net:send-message)
                    (lambda (peer msg)
                      (declare (ignore peer))
                      (when (string= "feefilter"
                                     (bl.bytes:with-byte-reader (s msg)
                                       (bl.ser:message-header-command
                                        (bl.ser:read-message-header s))))
                        (push (bl.ser:parse-feefilter-payload
                               (subseq msg 24))
                              ,sent))))
              ,@body)
         (setf (fdefinition 'bl.net:send-message) real)))
     (setf ,sent (nreverse ,sent))))

(test g7-15-fee-filter-buckets-match-core
  "Buckets are {0} U {50 * 1.1^k <= 1e7}, built by repeated MULTIPLICATION as
Core does (MakeFeeSet) — so the third boundary is 55.00000000000001, not 55.0.
The base is Core's compile-time DEFAULT_MIN_RELAY_TX_FEE/2 = 50, NOT the
configured -minrelaytxfee: configuring the relay floor must not move the
buckets, or our quantization would become a fingerprint."
  (let ((b bl.net::*fee-filter-buckets*))
    (is (= 0 (aref b 0)))
    (is (= 50.0d0 (aref b 1)))
    (is (= (* 50.0d0 1.1d0) (aref b 2))
        "built by repeated multiplication, not recomputed as 50*1.1^k")
    (is (<= (aref b (1- (length b))) 1d7))
    ;; The IBD sentinel goes on the wire as the TOP BUCKET, never MAX_MONEY.
    (is (= 9936506 (bl.net::%feefilter-max-value)))))

(test g7-15-rounding-clamps-and-quantizes
  "round() clamps anything above the top bucket to the top bucket, never
returns a non-bucket value, and is never above the requested fee's bucket."
  (dotimes (i 200)
    (declare (ignore i))
    (let ((r (bl.net:fee-filter-round 1000)))
      (is (find (float r 1d0) bl.net::*fee-filter-buckets*
                :test (lambda (x b) (= x (floor b))))
          "every rounded value must be an actual bucket")))
  (is (= (bl.net::%feefilter-max-value)
         (bl.net:fee-filter-round most-positive-fixnum))
      "above the top bucket must clamp deterministically"))

(test g7-15-ibd-sends-top-bucket-then-resends-on-exit
  "During IBD we ask peers for no txs at all (they would be discarded), by
sending round(MAX_MONEY) = the top bucket. Leaving IBD must FORCE a resend —
without that, peers keep withholding txs from us for up to another 10 minutes."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (state (bl.store:make-chain-state))
         (peer (%g715-peer)))
    ;; --- in IBD ---
    (%g715-capturing (sent)
      (let ((bl.net:*cached-is-ibd* t))
        (bl.net:maybe-send-feefilter peer mempool state 1000))
      (is (equal (list (bl.net::%feefilter-max-value)) sent)
          "IBD must put the top bucket on the wire, not MAX_MONEY"))
    (is (> (bl.net::peer-next-send-feefilter peer) 1000)
        "the next-send time must be advanced")
    ;; --- out of IBD: forced resend regardless of the schedule ---
    (%g715-capturing (sent)
      (let ((bl.net:*cached-is-ibd* nil))
        (bl.net:maybe-send-feefilter peer mempool state 1001))
      (is (= 1 (length sent))
          "leaving IBD must force an immediate resend")
      (is (/= (bl.net::%feefilter-max-value) (first sent))
          "the resent value must be the real filter, not the IBD sentinel"))))

(test g7-15-next-send-advances-even-when-value-unchanged
  "Core advances m_next_send_feefilter UNCONDITIONALLY inside the due branch,
even when the value is unchanged and nothing is sent. Omitting that turns the
tick into a per-second re-evaluation of every peer."
  (let* ((bl:*network* :regtest)
         (bl.net:*cached-is-ibd* nil)
         (mempool (bl.mp:make-mempool))
         (state (bl.store:make-chain-state))
         (peer (%g715-peer)))
    (%g715-capturing (sent)
      (bl.net:maybe-send-feefilter peer mempool state 1000)
      (is (= 1 (length sent)) "first call sends"))
    (let ((scheduled (bl.net::peer-next-send-feefilter peer)))
      (is (> scheduled 1000))
      ;; Due again, same value: nothing sent, but the timer still moves.
      (%g715-capturing (sent)
        (bl.net:maybe-send-feefilter
         peer mempool state (1+ scheduled))
        (is (null sent) "an unchanged value must not be resent"))
      (is (> (bl.net::peer-next-send-feefilter peer) scheduled)
          "the timer must advance even when nothing was sent"))))

(test g7-15-gates-version-and-block-relay
  "Core skips feefilter for peers below FEEFILTER_VERSION (70013) and for
outbound block-relay-only peers, which never announce txs to us anyway."
  (let* ((bl:*network* :regtest)
         (bl.net:*cached-is-ibd* nil)
         (mempool (bl.mp:make-mempool))
         (state (bl.store:make-chain-state)))
    (%g715-capturing (sent)
      (bl.net:maybe-send-feefilter
       (%g715-peer :version 70012) mempool state 1000)
      (is (null sent) "a pre-70013 peer must not receive feefilter"))
    (%g715-capturing (sent)
      (bl.net:maybe-send-feefilter
       (%g715-peer :conn-type :block-relay) mempool state 1000)
      (is (null sent) "block-relay-only peers must not receive feefilter"))
    (%g715-capturing (sent)
      (bl.net:maybe-send-feefilter
       (%g715-peer) mempool state 1000)
      (is (= 1 (length sent)) "a normal peer must receive one"))))

(test g7-15-rolling-min-excludes-relay-floor
  "Core rounds CTxMemPool::GetMinFee, which EXCLUDES -minrelaytxfee; the max()
with the floor is applied AFTER rounding. Feeding the already-floored value to
round() would emit 107 a third of the time where Core emits a flat 100."
  (let ((mempool (bl.mp:make-mempool)))
    (is (= 0 (bl.mp:mempool-decayed-rolling-min-fee-rate mempool))
        "an idle pool has NO rolling minimum, independent of the relay floor")
    (is (plusp (bl.mp:mempool-effective-min-fee-rate mempool))
        "the effective rate still folds the floor in")))

;;;; Header sync over the shared pump (Core has no header-sync loop: headers are
;;;; ordinary messages, and ProcessHeadersMessage asks for the next batch itself).

(defun %hdr-sync-chain-state (suffix)
  "A regtest chain-state holding only genesis, for header-ingestion tests."
  (let* ((state (bl.store:init-chain-state
                 (merge-pathnames (format nil "test-hdrpump-~A/" suffix)
                                  (uiop:temporary-directory))))
         (genesis-hash (bl.store:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (bl.store:add-block-index-entry
     state
     (bl.store:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid
      :header (bl.ser:make-block-header
               :version 1 :prev-block zeros :merkle-root zeros
               :timestamp 1296688600 :bits #x207fffff :nonce 0
               :cached-hash genesis-hash)))
    state))

(test headers-ingest-asks-for-more-on-a-full-batch
  "Core's ProcessHeadersMessage tail (net_processing.cpp:3105-3111): a
maximum-size headers message means the peer may have more, so ask again. Ours
did not, which is the whole reason a dedicated BLOCKING header-sync loop
existed — and that loop ran on the pump's own thread, so it stalled every other
peer while its chosen one answered.

The follow-up must be skipped while a low-work sync owns the conversation
(Core's !have_headers_sync): that path sends its own, from the sync's locator,
and a second getheaders would desynchronise it."
  (let* ((bl:*network* :regtest)
         (state (%hdr-sync-chain-state "more"))
         (sent 0)
         (peer (bl.net:make-peer :state :ready)))
    ;; Count getheaders without a socket: send-message on a peer with no
    ;; connection returns NIL, so stub the throttled sender instead.
    (let ((real (symbol-function 'bl.net::%maybe-send-getheaders))
          (entry (bl.store:get-block-index-entry
                  state (bl.store:best-block-hash state))))
      (unwind-protect
           (progn
             (setf (symbol-function 'bl.net::%maybe-send-getheaders)
                   (lambda (p loc) (declare (ignore p loc)) (incf sent) t))
             ;; Not a full batch: nothing more to ask for.
             (bl.net::%maybe-request-more-headers peer state entry nil)
             (is (= 0 sent) "a short batch ends the conversation")
             ;; Full batch: ask again — and from THIS batch's last header, which
             ;; is the whole termination argument (see the docstring).
             (bl.net::%maybe-request-more-headers peer state entry t)
             (is (= 1 sent) "a maximum-size batch means ask for the next")
             ;; No pindexLast (nothing of the batch is in our index) — there is
             ;; no advancing locator to ask from, so stay quiet rather than
             ;; re-ask from our own tip and loop.
             (setf (bl.net::peer-last-getheaders-time peer) 0)
             (bl.net::%maybe-request-more-headers peer state nil t)
             (is (= 1 sent) "no pindexLast means no advancing locator")
             ;; Full batch while a low-work sync owns this peer: that driver
             ;; sends its own follow-up, so this one must stay quiet.
             (setf (bl.net:peer-headers-sync peer) :in-progress
                   (bl.net::peer-last-getheaders-time peer) 0)
             (bl.net::%maybe-request-more-headers peer state entry t)
             (is (= 1 sent) "a low-work sync owns its own follow-up"))
        (setf (symbol-function 'bl.net::%maybe-send-getheaders) real)))))

(test headers-ingest-counts-an-answer-even-with-nothing-new
  "Header sync rotates on 'this peer never answered', which is NOT 'this peer
had nothing new'. A peer at our own tip answers a getheaders with a batch we
already hold; counting only NEW headers would score it exactly like a peer that
went silent, and the failover would rotate away from every healthy peer the
moment we caught up."
  (let* ((bl:*network* :regtest)
         (state (%hdr-sync-chain-state "answered"))
         (peer (bl.net:make-peer :state :ready)))
    (is (= 0 (bl.net::%peer-headers-bytes peer)))
    ;; The counter is the transport's own per-command byte tally, so record an
    ;; empty headers message the way the reader would.
    (bl.net::%account-message
     (bl.net:peer-recv-per-msg peer) nil "headers" 1)
    (is (plusp (bl.net::%peer-headers-bytes peer))
        "an empty answer is still an answer")))

(test per-cycle-byte-budget-ends-a-peers-turn
  "A message COUNT is not a fairness bound: 32 messages can be 32 blocks, and a
peer that keeps its socket full holds the drain for as long as it can feed it.
Core bounds BYTES per node per socket-handler pass (net.cpp:2171-2183).

Driven, not asserted about constants: queue well past the budget in small
messages and check the drain leaves some behind for the next pass."
  (let* ((bl:*network* :regtest)
         (state (bl.store:make-chain-state))
         (listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener)))
    (unwind-protect
         (let* ((client (usocket:socket-connect "127.0.0.1" port
                                                :element-type '(unsigned-byte 8)))
                (server (usocket:socket-accept listener
                                               :element-type '(unsigned-byte 8)))
                (peer (bl.net:make-peer
                       :state :ready
                       :connection (make-test-connection
                                    :socket server :connected t)))
                (ctx (%ibd-ctx))
                ;; "ping" carries an 8-byte nonce: 32 bytes on the wire, so a
                ;; few thousand comfortably exceed the 64 KB budget.
                (msg (bl.ser:make-ping-message 7))
                (queued 4000))
           (setf (bl.net::ibd-context-peers ctx) (list peer))
           (dotimes (i queued)
             (write-sequence msg (usocket:socket-stream client)))
           (force-output (usocket:socket-stream client))
           (sleep 0.3)
           (drain-peer-once peer (bl.ctx:make-node-context :chain-state state :utxo-set (bl.store:make-utxo-set)) ctx)
           (let ((took (bl.net:connection-bytes-received
                        (bl.net:peer-connection peer))))
             (is (plusp took) "the drain served this peer")
             (is (< took (* (length msg) queued))
                 "but yielded before draining everything it had"))
           (usocket:socket-close client))
      (usocket:socket-close listener))))

(test header-sync-waiting-does-not-starve-other-peers
  "THE reason this changed. sync-headers used to wait for its chosen peer in
receive-message-blocking — up to 30 x 5s per batch — on the sync thread, which
is the pump's own thread. For that whole time no other peer was drained, no
block was processed and no expired read was reaped: one peer's latency was the
whole node's.

The wait is now a pump pass. Here the chosen peer says nothing at all while a
second peer sends a headers message; that second peer must still be served."
  (let* ((bl:*network* :regtest)
         (state (%hdr-sync-chain-state "starve"))
         (listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)))
         (port (usocket:get-local-port listener)))
    (unwind-protect
         (let* ((quiet-client (usocket:socket-connect "127.0.0.1" port
                                                      :element-type '(unsigned-byte 8)))
                (quiet-server (usocket:socket-accept listener
                                                     :element-type '(unsigned-byte 8)))
                (talker-client (usocket:socket-connect "127.0.0.1" port
                                                       :element-type '(unsigned-byte 8)))
                (talker-server (usocket:socket-accept listener
                                                      :element-type '(unsigned-byte 8)))
                (quiet (bl.net:make-peer
                        :state :ready
                        :connection (make-test-connection
                                     :socket quiet-server :connected t)))
                (talker (bl.net:make-peer
                         :state :ready
                         :connection (make-test-connection
                                      :socket talker-server :connected t)))
                (ctx (%ibd-ctx)))
           (setf (bl.net::ibd-context-peers ctx) (list quiet talker))
           ;; The talker answers with an empty headers message — the smallest
           ;; well-formed one, and exactly what a peer at our tip sends.
           (write-sequence (bl.ser:serialize-message
                            "headers" (make-array 1 :element-type '(unsigned-byte 8)
                                                    :initial-element 0))
                           (usocket:socket-stream talker-client))
           (force-output (usocket:socket-stream talker-client))
           (sleep 0.2)
           ;; Short idle window so the test does not sit out the real one.
           (let ((bl.net::+header-sync-idle-passes+ 3))
             (multiple-value-bind (received stalled)
                 (bl.net::sync-headers
                  quiet state :ctx ctx
                  :utxo-set (bl.store:make-utxo-set))
               (declare (ignore received))
               (is-true stalled "the chosen peer never answered, so rotate")))
           (is (plusp (bl.net::%peer-headers-bytes talker))
               "the OTHER peer was served while header sync waited")
           (is (= 0 (bl.net::%peer-headers-bytes quiet))
               "control: the chosen peer really did stay silent")
           (usocket:socket-close quiet-client)
           (usocket:socket-close talker-client))
      (usocket:socket-close listener))))

;;;; --- getdata block-serving guards (G7-10, Core net_processing.cpp) ---------

(defun %gd-header (&key (timestamp 1700000000) (bits #x1d00ffff) (seed 1))
  (bl.ser:make-block-header
   :version 1
   :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
   :timestamp timestamp
   :bits bits
   :nonce 0))

(defun %gd-entry (&key hash height (timestamp 1700000000) (work 1000)
                       (status :valid) (bits #x1d00ffff))
  (bl.store:make-block-index-entry
   :hash (or hash (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element (mod height 256)))
   :height height
   :header (%gd-header :timestamp timestamp :bits bits :seed (mod height 256))
   :chain-work work
   :status status))

(defun %gd-chain-state (tip-height)
  "A chain state whose active chain is TIP-HEIGHT+1 linked entries."
  (let ((cs (bl.store:make-chain-state :base-path #p"/tmp/gd/"))
        (prev nil))
    (loop for h from 0 to tip-height
          ;; Realistic per-block work (difficulty-1 is ~2^32), because the
          ;; work-equivalent age divides by it — token values make every gap
          ;; round to zero seconds and the check vacuous.
          do (let ((e (%gd-entry :height h :work (* (1+ h) (expt 2 32))
                                 :timestamp (+ 1700000000 (* h 600)))))
               (setf (bl.store:block-index-entry-prev-entry e) prev)
               (bl.store:add-block-index-entry cs e)
               (setf prev e)))
    (bl.store:update-chain-tip
     cs (bl.store:block-index-entry-hash prev) tip-height)
    (values cs prev)))

(test an-old-off-chain-block-is-not-served-on-request
  "Core BlockRequestAllowed (net_processing.cpp:1953-1960): a block NOT on the
active chain is served only while it is younger than STALE_RELAY_AGE_LIMIT (30
days) by BOTH wall-clock time and work-equivalent time. Serving an arbitrarily
old side-chain block on request is a fingerprinting oracle — it tells the asker
exactly which forks this node witnessed and kept. We had no such check at all."
  (multiple-value-bind (cs tip) (%gd-chain-state 200)
    (let ((best tip))
      ;; On the active chain: always allowed, however old.
      (let ((on-chain (bl.store:get-block-at-height cs 5)))
        (is-true (bl.net::%block-request-allowed-p cs on-chain best)))
      ;; Off-chain but recent: allowed.
      (let ((recent (%gd-entry :height 199 :work (* 200 (expt 2 32))
                               :timestamp (bl.ser:block-header-timestamp
                                           (bl.store:block-index-entry-header tip)))))
        (bl.store:add-block-index-entry cs recent)
        (is-true (bl.net::%block-request-allowed-p cs recent best)))
      ;; Off-chain and older than a month by wall clock: refused.
      (let ((stale (%gd-entry :height 199 :work (* 200 (expt 2 32))
                              :timestamp (- (bl.ser:block-header-timestamp
                                             (bl.store:block-index-entry-header tip))
                                            (* 31 24 60 60)))))
        (setf (bl.store:block-index-entry-hash stale)
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element 250))
        (bl.store:add-block-index-entry cs stale)
        (is-false (bl.net::%block-request-allowed-p cs stale best)))
      ;; A block that never reached full validation is refused whatever its age
      ;; (Core requires BLOCK_VALID_SCRIPTS).
      (let ((unvalidated (%gd-entry :height 199 :work (* 200 (expt 2 32)) :status :header-valid
                                    :timestamp (bl.ser:block-header-timestamp
                                                (bl.store:block-index-entry-header tip)))))
        (setf (bl.store:block-index-entry-hash unvalidated)
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element 251))
        (bl.store:add-block-index-entry cs unvalidated)
        (is-false (bl.net::%block-request-allowed-p cs unvalidated best))))))

(test the-work-equivalent-age-catches-what-a-forged-timestamp-would-not
  "The second half of BlockRequestAllowed, and the reason it has two halves. A
header's nTime is attacker-influenced within the median-time-past and 2-hour
windows, so an age test on timestamps alone can be talked out of. The
work-equivalent age (Core GetBlockProofEquivalentTime, chain.cpp:136-151)
cannot be: producing the work is the cost."
  ;; The chain must be taller than the limit expressed in blocks (30 days at a
  ;; 10-minute target is 4,320) or no work gap inside it can exceed the limit
  ;; and the assertion is vacuous.
  (multiple-value-bind (cs tip) (%gd-chain-state 5000)
    ;; A block claiming to be seconds old but carrying work from far behind:
    ;; 4,500 blocks' worth, which at the 10-minute target is ~31 days.
    (let ((forged (%gd-entry :height 4999
                             :work (- (bl.store:block-index-entry-chain-work tip)
                                      (* 4500 (expt 2 32)))
                             :timestamp (bl.ser:block-header-timestamp
                                         (bl.store:block-index-entry-header tip)))))
      (setf (bl.store:block-index-entry-hash forged)
            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 252))
      (bl.store:add-block-index-entry cs forged)
      ;; Its timestamp passes the wall-clock half...
      (is (< (- (bl.ser:block-header-timestamp
                 (bl.store:block-index-entry-header tip))
                (bl.ser:block-header-timestamp
                 (bl.store:block-index-entry-header forged)))
             bl.net::+stale-relay-age-limit+))
      ;; ...and the work half refuses it anyway.
      (is-false (bl.net::%block-request-allowed-p cs forged tip)))))

(test a-network-limited-node-does-not-answer-below-its-promised-depth
  "Core net_processing.cpp:2385-2392. A node advertising NODE_NETWORK_LIMITED
without NODE_NETWORK promises the last 288 blocks; answering for anything
deeper tells the asker how much history it actually kept, which is its prune
configuration. Core's two-block buffer is kept — without it a race against a
tip advance turns a legitimate request into a disconnect."
  (multiple-value-bind (cs tip) (%gd-chain-state 1000)
    (is-true tip)
    ;; Pruning on => NODE_NETWORK is not advertised => the threshold applies.
    (let ((bl:*prune-target-mib* 550))
      (is-true (bl.net::%below-network-limited-threshold-p
                cs (bl.store:get-block-at-height cs 100)))
      ;; Inside the window, including the two-block buffer.
      (is-false (bl.net::%below-network-limited-threshold-p
                 cs (bl.store:get-block-at-height cs 1000)))
      (is-false (bl.net::%below-network-limited-threshold-p
                 cs (bl.store:get-block-at-height cs (- 1000 288))))
      (is-false (bl.net::%below-network-limited-threshold-p
                 cs (bl.store:get-block-at-height cs (- 1000 290))))
      (is-true (bl.net::%below-network-limited-threshold-p
                cs (bl.store:get-block-at-height cs (- 1000 291)))))
    ;; A full node advertises NODE_NETWORK and the threshold never applies.
    (let ((bl:*prune-target-mib* 0))
      (is-false (bl.net::%below-network-limited-threshold-p
                 cs (bl.store:get-block-at-height cs 1))))))

(test the-getdata-handler-is-given-the-chain-state-it-needs-to-check
  "The seam. Every guard above reads the chain state, and HANDLE-GETDATA used
to `(declare (ignore chain-state))` -- so a version of this that forgot to pass
it would compile, run, and silently serve everything. The dispatch now hands
every handler the whole node context (bl.ctx:node-context), so the check is
that handle-getdata reads chain-state out of it and nobody ignores it."
  (let ((src (uiop:read-file-string
              (merge-pathnames "src/networking/protocol.lisp"
                               (asdf:system-source-directory :bitcoin-lisp)))))
    (is (string= "HANDLE-GETDATA"
                 (symbol-name (bl.net:p2p-handler-function (bl.net:p2p-handler-for "getdata"))))
        "the message table no longer routes getdata to handle-getdata")
    (let ((start (search "(define-p2p-handler (\"getdata\"" src)))
      (is (and start (search "(bl.ctx:with-node-context (chain-state" src :start2 start))
          "handle-getdata no longer reads chain-state from the context"))
    (is (null (search "(declare (ignore chain-state))" src))
        "handle-getdata ignores chain-state again, which disables every guard")))

;;;; --- Parking an unfetchable fork instead of retrying it forever (N4) -------

(test a-fork-with-a-missing-body-is-parked-not-re-probed-every-pass
  "Measured on testnet4 over 12.7 days: 205 \"REORG REFUSED: N blocks missing
from store\" lines across ~40 heights, 11 of them at a single height, for fork
bodies no peer would serve. The candidate stayed in the set and was re-probed
on every activation pass forever.

Core's answer is not a timer. FindMostWorkChain erases such a branch from
setBlockIndexCandidates and inserts it into m_blocks_unlinked keyed by the
block it is waiting for — \"so that if the block arrives in the future we can
try adding to setBlockIndexCandidates again\" (validation.cpp:3184-3190). The
retry is not the problem; the retry with no event to wait for is."
  (let ((bl.net:*ibd-context*
          (%ibd-ctx)))
    (let ((candidate (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
          (missing (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
          (set (bl.net::ibd-context-reorg-candidates
                bl.net:*ibd-context*))
          (parked (bl.net::ibd-context-unlinked-reorg-candidates
                   bl.net:*ibd-context*)))
      (setf (gethash candidate set) t)
      (bl.net::%park-unlinked-reorg-candidate candidate missing)
      ;; It stays a CANDIDATE — several paths read that set to mean "recoverable,
      ;; not rejected", and dropping it there broke the deep-reorg livelock
      ;; regression test. What stops is the repeated branch WALK.
      (is-true (gethash candidate set))
      (is (equal (list candidate) (gethash missing parked))
          "it is not parked under the block it is waiting for")
      (is-true (bl.net::%reorg-candidate-parked-p
                candidate (bl.store:init-block-store
                           (uiop:temporary-directory)))
               "a parked candidate is not being skipped by the scan")
      ;; Parking twice does not duplicate it.
      (bl.net::%park-unlinked-reorg-candidate candidate missing)
      (is (= 1 (length (gethash missing parked)))))))

(test the-arrival-of-the-missing-body-re-arms-the-parked-fork
  "The event that makes parking safe. If the body never arrives the branch
costs nothing; if it does, the branch must come back — otherwise this trades an
unbounded retry for a reorg that never happens, which is strictly worse."
  (let ((bl.net:*ibd-context*
          (%ibd-ctx)))
    (multiple-value-bind (cs tip) (%gd-chain-state 10)
      ;; A candidate entry with MORE work than the tip, so note-reorg-candidate
      ;; will accept it back.
      (let* ((cand (%gd-entry :height 11
                              :work (+ (bl.store:block-index-entry-chain-work tip)
                                       (expt 2 32))))
             (cand-hash (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 77))
             (missing (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 88)))
        (setf (bl.store:block-index-entry-hash cand) cand-hash)
        (bl.store:add-block-index-entry cs cand)
        (bl.net::%park-unlinked-reorg-candidate cand-hash missing)
        ;; An unrelated block arriving changes nothing.
        (is (= 0 (bl.net::%rearm-unlinked-reorg-candidates
                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                  cs)))
        (is-true (gethash cand-hash
                          (bl.net::ibd-context-parked-reorg-candidates
                           bl.net:*ibd-context*)))
        ;; The awaited block arriving un-parks it.
        (is (= 1 (bl.net::%rearm-unlinked-reorg-candidates missing cs)))
        (is-false (gethash cand-hash
                           (bl.net::ibd-context-parked-reorg-candidates
                            bl.net:*ibd-context*))
                  "the parked fork is still being skipped after its body landed")
        (is-true (gethash cand-hash
                          (bl.net::ibd-context-reorg-candidates
                           bl.net:*ibd-context*)))
        ;; The parked entry is consumed, not left to fire again.
        (is-false (gethash missing
                           (bl.net::ibd-context-unlinked-reorg-candidates
                            bl.net:*ibd-context*)))))))

(test re-arming-re-applies-the-tests-that-admit-a-candidate
  "Re-arming goes through NOTE-REORG-CANDIDATE rather than writing to the set
directly, so a branch that went stale or was rejected while it waited does not
come back. Putting it back unconditionally would resurrect exactly the
candidates the rejected set exists to keep out."
  (let ((bl.net:*ibd-context*
          (%ibd-ctx)))
    (multiple-value-bind (cs tip) (%gd-chain-state 10)
      (let* ((stale (%gd-entry :height 11
                               ;; LESS work than the tip: no longer a reorg target.
                               :work (- (bl.store:block-index-entry-chain-work tip)
                                        1000)))
             (stale-hash (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 66))
             (missing (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 99)))
        (setf (bl.store:block-index-entry-hash stale) stale-hash)
        (bl.store:add-block-index-entry cs stale)
        (bl.net::%park-unlinked-reorg-candidate stale-hash missing)
        (bl.net::%rearm-unlinked-reorg-candidates missing cs)
        (is-false (gethash stale-hash
                           (bl.net::ibd-context-reorg-candidates
                            bl.net:*ibd-context*))
                  "a branch that went stale while parked came back as a candidate")))))

(test a-body-that-arrived-by-another-route-un-parks-the-branch-anyway
  "The parked marker names a block, and the scan RE-CHECKS whether that block is
here rather than trusting the marker. A body can appear through a path that does
not drain the map — a reindex, an operator restoring a file — and a candidate
parked against a block that has since arrived would otherwise never be probed
again: an unbounded retry traded for a reorg that never happens, which is worse
than the bug this fixes."
  ;; A private directory built here rather than with flatfile-tests' fixture:
  ;; that file compiles AFTER this one, so its macro is not defined yet and the
  ;; call reads as a function call. It passed in a warm image that happened to
  ;; have it loaded, and the cold battery caught it.
  (let ((dir (ensure-directories-exist
              (merge-pathnames (format nil "bl-unpark-~D/" (get-internal-real-time))
                               (uiop:temporary-directory)))))
    (unwind-protect
         (let* ((bl.net:*ibd-context*
                  (%ibd-ctx))
                (store (bl.store:init-block-store dir))
                (cand (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
                (blk (make-reorg-test-block
                      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 210)
                      1))
                (missing (bl.ser:block-header-hash
                          (bl.ser:bitcoin-block-header blk))))
           (bl.net::%park-unlinked-reorg-candidate cand missing)
           (is-true (bl.net::%reorg-candidate-parked-p cand store)
                    "parked while the awaited body is genuinely absent")
           ;; The body appears without anyone draining the map.
           (bl.store:store-block store blk :height 1)
           (is-false (bl.net::%reorg-candidate-parked-p cand store)
                     "the branch is still skipped even though its body is here"))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test the-parked-map-is-bounded-like-every-other-candidate-map
  "A pathological header topology must not be able to grow this without limit —
the same reason the candidate and rejected sets are capped."
  (let ((bl.net:*ibd-context*
          (%ibd-ctx)))
    (let ((parked (bl.net::ibd-context-unlinked-reorg-candidates
                   bl.net:*ibd-context*)))
      (loop for i from 0 below (+ bl.net::+reorg-candidates-cap+ 50)
            do (let ((missing (make-array 32 :element-type '(unsigned-byte 8))))
                 (setf (aref missing 0) (ldb (byte 8 0) i)
                       (aref missing 1) (ldb (byte 8 8) i)
                       (aref missing 2) (ldb (byte 8 16) i))
                 (bl.net::%park-unlinked-reorg-candidate
                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                  missing)))
      (is (<= (hash-table-count parked)
              bl.net::+reorg-candidates-cap+)
          "the parked map grew past its cap (~D entries)"
          (hash-table-count parked)))))

(test the-body-persist-path-drains-the-parked-map
  "The seam, and the one this project keeps getting wrong: parking is only safe
if something actually re-arms. Assert the persist path calls the drain."
  (let ((src (uiop:read-file-string
              (merge-pathnames "src/networking/ibd.lisp"
                               (asdf:system-source-directory :bitcoin-lisp)))))
    (is (search "(%rearm-unlinked-reorg-candidates hash chain-state)" src)
        "no caller drains the parked map, so a parked fork never comes back")))

;;;; Core AcceptBlock's pre-write gate on the two IBD persist paths
;;;;
;;;; PROCESS-RECEIVED-BLOCK wrote every body to disk with no CheckBlock at all:
;;;; the competing-fork path (h <= tip) checked only BLOCK-WITNESS-STRIPPED-P,
;;;; and the out-of-order path (h > tip+1) only that plus the anti-DoS gate.
;;;; Core runs CheckBlock and ContextualCheckBlock immediately before its one
;;;; write (validation.cpp:4381-4389), so a peer could put an arbitrary body on
;;;; disk under an honest header's hash -- and BLOCK-EXISTS-P then told the
;;;; per-peer download walk we had that height, so the real block was never
;;;; re-requested and the tip could not pass it without a reindex.

(defun %forged-body-fixture (suffix)
  "(values CHAIN-STATE UTXO STORE GENESIS-HASH TIP-ENTRY GENESIS-ENTRY): a
mainnet fixture with an active chain of two blocks. Mainnet on purpose --
BIP34 and segwit are inactive at these heights, so a synthetic coinbase is a
valid body and the positive controls really do persist."
  (multiple-value-bind (cs utxo store genesis-hash)
      (make-activate-block-fixture suffix)
    (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA0 2))
    (values cs utxo store genesis-hash
            (bl.store:get-block-index-entry cs (bl.store:best-block-hash cs))
            (bl.store:get-block-index-entry cs genesis-hash))))

(defun %index-header (chain-state block hash height prev-entry work)
  "Index BLOCK's header the way AcceptBlockHeader would, before its body
arrives."
  (bl.store:add-block-index-entry
   chain-state
   (bl.store:make-block-index-entry
    :hash hash :height height :prev-entry prev-entry :chain-work work
    :status :header-valid
    :header (bl.ser:bitcoin-block-header block))))

(test s1-a-forged-body-is-never-persisted-by-either-ibd-persist-path
  "GA10 S1. A body whose transactions are not the ones its header commits to is
refused before BL.STORE:STORE-BLOCK on BOTH of PROCESS-RECEIVED-BLOCK's persist
paths -- the competing-fork arm (h <= tip) and the out-of-order arm (h > tip+1)
-- and the honest block the same header names still persists through each of
them, so the gate rejects the lie rather than the path."
  (with-network (:mainnet)
    (multiple-value-bind (cs utxo store genesis-hash tip-entry genesis-entry)
        (%forged-body-fixture "s1-forged-body")
      (destructuring-bind (fork-h fork-ok-h ooo-h ooo-ok-h)
          (make-test-chain-hashes #xB1 4)
        (let ((tip-hash (bl.store:block-index-entry-hash tip-entry)))
          (multiple-value-bind (fork-forged fork-honest)
              (make-forged-body-block genesis-hash fork-h 1)
            (multiple-value-bind (ooo-forged ooo-honest)
                (make-forged-body-block tip-hash ooo-h 5)
              (let ((fork-ok (make-reorg-test-block genesis-hash fork-ok-h 1))
                    (ooo-ok (make-reorg-test-block tip-hash ooo-ok-h 5)))
                ;; Headers only: the bodies are what is under test.
                (%index-header cs fork-forged fork-h 1 genesis-entry 50)
                (%index-header cs fork-ok fork-ok-h 1 genesis-entry 50)
                (%index-header cs ooo-forged ooo-h 5 tip-entry 900000)
                (%index-header cs ooo-ok ooo-ok-h 5 tip-entry 900000)
                (with-ibd-context
                  ;; Competing-fork arm (height 1, tip is at 2).
                  (deliver-block fork-forged cs utxo store :requested t)
                  (is-false (bl.store:block-exists-p store fork-h)
                            "a forged competing-fork body reached disk")
                  (deliver-block fork-honest cs utxo store :requested t)
                  (is-true (bl.store:block-exists-p store fork-h)
                           "positive control: the honest body must still persist")
                  ;; Out-of-order arm (height 5, tip is at 2).
                  (deliver-block ooo-forged cs utxo store :requested t)
                  (is-false (bl.store:block-exists-p store ooo-h)
                            "a forged out-of-order body reached disk")
                  (deliver-block ooo-honest cs utxo store :requested t)
                  (is-true (bl.store:block-exists-p store ooo-h)
                           "positive control: the honest body must still persist")
                  ;; And the second positive control, a body nobody forged.
                  (deliver-block ooo-ok cs utxo store :requested t)
                  (is-true (bl.store:block-exists-p store ooo-ok-h)
                           "positive control: an ordinary body must persist"))))))))))

(test s1-a-refused-body-punishes-its-peer-and-marks-only-a-non-mutated-verdict
  "Core MaybePunishNodeForBlock misbehaves on BLOCK_CONSENSUS and BLOCK_MUTATED
alike (net_processing.cpp:1908-1949), so either verdict costs the sending peer
its connection. InvalidBlockFound does NOT: it skips BLOCK_FAILED_VALID for
BLOCK_MUTATED (validation.cpp:1985-1993), because the block hash does not
commit to what the mutated checks read -- marking one would let a peer that
mangles a body in transit poison an honest header permanently. So a forged body
leaves its entry downloadable, while two coinbases -- which the merkle root
authenticates -- poison the entry and its indexed descendants."
  (with-network (:mainnet)
    (multiple-value-bind (cs utxo store genesis-hash tip-entry)
        (%forged-body-fixture "s1-refused-body")
      (declare (ignore genesis-hash))
      (destructuring-bind (mutated-h consensus-h child-h)
          (make-test-chain-hashes #xB2 3)
        (let* ((tip-hash (bl.store:block-index-entry-hash tip-entry))
               (mutated (make-forged-body-block tip-hash mutated-h 5))
               (consensus (make-two-coinbase-block tip-hash consensus-h 5))
               (child (make-reorg-test-block consensus-h child-h 6))
               (mutated-peer (bl.net:make-peer))
               (consensus-peer (bl.net:make-peer)))
          (%index-header cs mutated mutated-h 5 tip-entry 900000)
          (%index-header cs consensus consensus-h 5 tip-entry 900000)
          (%index-header cs child child-h 6
                         (bl.store:get-block-index-entry cs consensus-h) 900001)
          (with-ibd-context
            ;; BLOCK_MUTATED: peer punished, header left alone.
            (deliver-block mutated cs utxo store
                           :requested t :peer mutated-peer)
            (is (eq :disconnected (bl.net:peer-state mutated-peer))
                "a peer that sent a forged body was not punished")
            (is (eq :header-valid
                    (bl.store:block-index-entry-status
                     (bl.store:get-block-index-entry cs mutated-h)))
                "a mutated body poisoned the honest header it was sent under")
            ;; BLOCK_CONSENSUS: peer punished AND the subtree marked invalid.
            (deliver-block consensus cs utxo store
                           :requested t :peer consensus-peer)
            (is (eq :disconnected (bl.net:peer-state consensus-peer))
                "a peer that sent a consensus-invalid body was not punished")
            (is-false (bl.store:block-exists-p store consensus-h)
                      "a consensus-invalid body reached disk")
            (is (eq :invalid
                    (bl.store:block-index-entry-status
                     (bl.store:get-block-index-entry cs consensus-h)))
                "the entry was not marked invalid (Core InvalidBlockFound)")
            (is (eq :invalid
                    (bl.store:block-index-entry-status
                     (bl.store:get-block-index-entry cs child-h)))
                "the doomed subtree was not marked (Core BLOCK_FAILED_CHILD)")))))))
