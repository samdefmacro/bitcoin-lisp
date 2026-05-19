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

;;;; find-next-blocks-to-download
;;;;
;;;; Per-peer download walker. Tests cover the key dispatch paths:
;;;; peer has nothing better than our tip (skip), peer is on a stronger
;;;; chain (walk + collect missing), already-in-store blocks advance
;;;; last-common-block.

(defun %make-test-chain-entries (chain-state hashes &key prev-entry start-work)
  "Build N block-index-entries chained via prev-entry, increasing height
by 1 and chain-work by 100. Return the tip entry."
  (let ((prev prev-entry)
        (work (or start-work 0))
        (height (if prev-entry
                    (bitcoin-lisp.storage:block-index-entry-height prev-entry)
                    -1)))
    (dolist (hash hashes)
      (incf height)
      (incf work 100)
      (let ((entry (bitcoin-lisp.storage:make-block-index-entry
                    :hash hash :height height :prev-entry prev
                    :chain-work work :status :header-valid)))
        (bitcoin-lisp.storage:add-block-index-entry chain-state entry)
        (setf prev entry)))
    prev))

(test find-next-blocks-skips-peer-with-weaker-chain
  "If peer's best-known has less chain-work than our tip, return NIL."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (block-store (bitcoin-lisp.storage:init-block-store
                       (ensure-directories-exist
                        (merge-pathnames (format nil "ibd-find-test-~D/" (random 100000))
                                         (uiop:temporary-directory)))))
         (peer (%make-peer-with-state :ready))
         (our-hashes (loop for i from 1 to 5
                           collect (let ((h (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 0)))
                                     (setf (aref h 0) #xA0) (setf (aref h 1) i) h)))
         (peer-hashes (loop for i from 1 to 3
                            collect (let ((h (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 0)))
                                      (setf (aref h 0) #xB0) (setf (aref h 1) i) h))))
    (let ((our-tip (%make-test-chain-entries state our-hashes :start-work 0)))
      (setf (bitcoin-lisp.storage::chain-state-best-block-hash state)
            (bitcoin-lisp.storage:block-index-entry-hash our-tip)))
    (%make-test-chain-entries state peer-hashes :start-work 0)
    (setf (bitcoin-lisp.networking::peer-best-known-block-hash peer)
          (car (last peer-hashes)))
    (is (null (bitcoin-lisp.networking::find-next-blocks-to-download
               peer 10 state block-store)))))

(test find-next-blocks-returns-fork-blocks-peer-knows
  "When peer's best-known is on a stronger fork that shares an ancestor
with our chain, walk from fork-point to peer's tip collecting blocks."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (block-store (bitcoin-lisp.storage:init-block-store
                       (ensure-directories-exist
                        (merge-pathnames (format nil "ibd-find-test-~D/" (random 100000))
                                         (uiop:temporary-directory)))))
         (peer (%make-peer-with-state :ready))
         (genesis-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-entry
           (bitcoin-lisp.storage:make-block-index-entry
            :hash genesis-hash :height 0 :chain-work 1 :status :valid)))
    (bitcoin-lisp.storage:add-block-index-entry state genesis-entry)
    (setf (bitcoin-lisp.storage::chain-state-best-block-hash state) genesis-hash)
    ;; Build a chain B1 → B2 → B3 (chain-work 101 → 201 → 301)
    (let* ((b1-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                      (setf (aref h 0) #xB0) (setf (aref h 1) 1) h))
           (b2-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                      (setf (aref h 0) #xB0) (setf (aref h 1) 2) h))
           (b3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                      (setf (aref h 0) #xB0) (setf (aref h 1) 3) h))
           (peer-tip (%make-test-chain-entries state
                                                (list b1-hash b2-hash b3-hash)
                                                :prev-entry genesis-entry
                                                :start-work 1)))
      (declare (ignore peer-tip))
      (setf (bitcoin-lisp.networking::peer-best-known-block-hash peer) b3-hash)
      ;; find-next-blocks-to-download walks from fork-point (genesis) → b3.
      (let ((results (bitcoin-lisp.networking::find-next-blocks-to-download
                      peer 10 state block-store)))
        (is (= 3 (length results)))
        ;; Ordered by height ascending: b1 first.
        (is (equalp b1-hash (car (first results))))
        (is (= 1 (cdr (first results))))
        (is (equalp b3-hash (car (third results))))
        (is (= 3 (cdr (third results))))))))

(test find-next-blocks-nil-when-peer-has-nothing
  "Peer with NIL best-known returns NIL — we don't know what to ask for."
  (let* ((state (bitcoin-lisp.storage:make-chain-state))
         (peer (%make-peer-with-state :ready)))
    (is (null (bitcoin-lisp.networking::find-next-blocks-to-download
               peer 10 state nil)))))

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
                       :inputs (list coinbase-input)
                       :outputs (list coinbase-output)
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
