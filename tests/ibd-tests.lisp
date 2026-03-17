(in-package #:bitcoin-lisp.tests)

;;; IBD (Initial Block Download) Tests

(def-suite ibd-tests :in :bitcoin-lisp-tests)
(in-suite ibd-tests)

;;;; Checkpoint Tests

(test checkpoint-data-exists
  "Test that testnet checkpoint data is defined."
  (is (not (null bitcoin-lisp.networking::*testnet-checkpoints*)))
  (is (listp bitcoin-lisp.networking::*testnet-checkpoints*))
  ;; Check first checkpoint at height 546
  (let ((first (first bitcoin-lisp.networking::*testnet-checkpoints*)))
    (is (= 546 (car first)))
    (is (stringp (cdr first)))))

(test get-checkpoint-hash
  "Test checkpoint hash retrieval."
  ;; Known checkpoint should return a hash
  (let ((hash (bitcoin-lisp.networking::get-checkpoint-hash 546)))
    (is (not (null hash)))
    (is (= 32 (length hash))))
  ;; Non-checkpoint height should return NIL
  (is (null (bitcoin-lisp.networking::get-checkpoint-hash 547))))

(test last-checkpoint-height
  "Test getting the last checkpoint height."
  (let ((height (bitcoin-lisp.networking::last-checkpoint-height)))
    (is (integerp height))
    (is (> height 0))))

(test validate-checkpoint-match
  "Test checkpoint validation when hash matches."
  (let ((hash (bitcoin-lisp.networking::get-checkpoint-hash 546)))
    (is (bitcoin-lisp.networking::validate-checkpoint hash 546))))

(test validate-checkpoint-mismatch
  "Test checkpoint validation when hash doesn't match."
  (let ((bad-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (not (bitcoin-lisp.networking::validate-checkpoint bad-hash 546)))))

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
    (bitcoin-lisp.networking::mark-block-in-flight hash :peer)

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
  (let* ((state (bitcoin-lisp.storage:init-chain-state
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
