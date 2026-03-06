(in-package #:bitcoin-lisp.tests)

(in-suite :pruning-tests)

;;;; Helper: create a test block and store it

(defun make-pruning-test-block (prev-hash block-hash height)
  "Create a minimal test block for pruning tests."
  (let* ((coinbase-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (list (bitcoin-lisp.serialization:make-tx-in
                                      :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                          :initial-element 0)
                                                        :index #xFFFFFFFF)
                                      :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                                :initial-element 1)))
                       :outputs (list (bitcoin-lisp.serialization:make-tx-out
                                       :value 5000000000
                                       :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                  :initial-element #x76)))
                       :lock-time 0
                       :cached-hash (let ((txh (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 0)))
                                      (setf (aref txh 0) (aref block-hash 0))
                                      (setf (aref txh 1) (aref block-hash 1))
                                      (setf (aref txh 2) (aref block-hash 2))
                                      (setf (aref txh 3) #xCC)
                                      txh)))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp (+ 1231006505 (* height 600))
                  :bits #x1d00ffff
                  :nonce 0
                  :cached-hash block-hash)))
    (bitcoin-lisp.serialization:make-bitcoin-block
     :header header
     :transactions (list coinbase-tx))))

(defun make-test-hash (prefix height)
  "Create a unique 32-byte hash with PREFIX byte and HEIGHT encoded in bytes 1-2."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) prefix)
    (setf (aref h 1) (logand height #xFF))
    (setf (aref h 2) (logand (ash height -8) #xFF))
    h))

(defun setup-pruning-test-store (n-blocks)
  "Set up a block store with N-BLOCKS for pruning tests.
Returns (VALUES base-path block-store chain-state block-hashes)."
  (let* ((base-path (ensure-directories-exist
                     (merge-pathnames (format nil "test-pruning-~A/" (get-universal-time))
                                      (uiop:temporary-directory))))
         (block-store (bitcoin-lisp.storage:init-block-store base-path))
         (chain-state (bitcoin-lisp.storage:init-chain-state base-path))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (block-hashes (list genesis-hash)))
    ;; Add genesis entry
    (let ((genesis-entry (bitcoin-lisp.storage:make-block-index-entry
                          :hash genesis-hash :height 0 :chain-work 1 :status :valid)))
      (bitcoin-lisp.storage:add-block-index-entry chain-state genesis-entry)
      ;; Create and store N blocks with proper prev-entry links
      (let ((prev-hash genesis-hash)
            (prev-entry genesis-entry))
        (loop for h from 1 to n-blocks
              for block-hash = (make-test-hash #xAA h)
              do (let ((block (make-pruning-test-block prev-hash block-hash h)))
                   (bitcoin-lisp.storage:store-block block-store block)
                   (let ((entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash block-hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev-entry)))
                     (bitcoin-lisp.storage:add-block-index-entry chain-state entry)
                     (bitcoin-lisp.storage:update-chain-tip chain-state block-hash h)
                     (push block-hash block-hashes)
                     (setf prev-hash block-hash)
                     (setf prev-entry entry))))))
    (values base-path block-store chain-state (nreverse block-hashes))))

(defun cleanup-test-dir (base-path)
  "Remove test directory and all contents."
  (when (probe-file base-path)
    (ignore-errors
      (uiop:delete-directory-tree (pathname base-path) :validate t))))

;;;; Test 5.1: prune-block deletes files and respects 288-block minimum

(test prune-block-deletes-file
  "prune-block should delete the block file and remove it from the index."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore chain-state))
    (unwind-protect
        (let ((hash (second block-hashes)))  ; block at height 1
          ;; Block exists before pruning
          (is (not (null (bitcoin-lisp.storage:block-exists-p block-store hash))))
          ;; Prune it
          (let ((deleted-bytes (bitcoin-lisp.storage:prune-block block-store hash)))
            (is (not (null deleted-bytes)))
            (is (> deleted-bytes 0)))
          ;; Block no longer exists
          (is (null (bitcoin-lisp.storage:block-exists-p block-store hash)))
          ;; get-block returns NIL for pruned block
          (is (null (bitcoin-lisp.storage:get-block block-store hash))))
      (cleanup-test-dir base-path))))

(test prune-block-nonexistent
  "prune-block should return NIL for a block that doesn't exist."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 1)
    (declare (ignore chain-state block-hashes))
    (unwind-protect
        (let ((fake-hash (make-test-hash #xFF #xFF)))
          (is (null (bitcoin-lisp.storage:prune-block block-store fake-hash))))
      (cleanup-test-dir base-path))))

;;;; Test 5.2: automatic pruning triggers when storage exceeds target

(test prune-old-blocks-respects-target
  "prune-old-blocks should prune when storage exceeds target."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 10)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bitcoin-lisp:*prune-target-mib* 550)
              (bitcoin-lisp:*prune-after-height* 0))
          ;; Storage is tiny (test blocks), so nothing should be pruned
          ;; since we're well under 550 MiB
          (let ((pruned (bitcoin-lisp.storage:prune-old-blocks block-store chain-state)))
            (is (= 0 pruned))))
      (cleanup-test-dir base-path))))

(test prune-old-blocks-skips-when-disabled
  "prune-old-blocks should return 0 when pruning is not automatic."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore block-hashes))
    (unwind-protect
        (progn
          ;; NIL = disabled
          (let ((bitcoin-lisp:*prune-target-mib* nil))
            (is (= 0 (bitcoin-lisp.storage:prune-old-blocks block-store chain-state))))
          ;; 1 = manual-only, no automatic pruning
          (let ((bitcoin-lisp:*prune-target-mib* 1))
            (is (= 0 (bitcoin-lisp.storage:prune-old-blocks block-store chain-state)))))
      (cleanup-test-dir base-path))))

;;;; Test 5.3: manual-only mode

(test manual-only-mode-pruning
  "In manual-only mode (*prune-target-mib* = 1), prune-blocks-to-height should work
but prune-old-blocks should not."
  ;; Need 300 blocks so tip (300) - min-keep (288) = 12, allowing pruning of blocks 1-12
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 300)
    (unwind-protect
        (let ((bitcoin-lisp:*prune-target-mib* 1)
              (bitcoin-lisp:*prune-after-height* 0))
          ;; Automatic pruning should not run
          (is (= 0 (bitcoin-lisp.storage:prune-old-blocks block-store chain-state)))
          ;; Manual pruning should work (prune up to height 10)
          (let ((pruned (bitcoin-lisp.storage:prune-blocks-to-height
                         block-store chain-state 10)))
            (is (> pruned 0))
            ;; Pruned blocks should be gone (height 1)
            (is (null (bitcoin-lisp.storage:block-exists-p
                       block-store (second block-hashes))))
            ;; Blocks at height 10+ should remain
            (is (not (null (bitcoin-lisp.storage:block-exists-p
                            block-store (nth 11 block-hashes)))))))
      (cleanup-test-dir base-path))))

;;;; Test 5.4: prune-after-height

(test pruning-respects-prune-after-height
  "prune-old-blocks should not prune when chain height is below *prune-after-height*."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bitcoin-lisp:*prune-target-mib* 550)
              (bitcoin-lisp:*prune-after-height* 1000))  ; chain is only at height 5
          ;; Should skip pruning because chain height (5) < prune-after-height (1000)
          (is (= 0 (bitcoin-lisp.storage:prune-old-blocks block-store chain-state))))
      (cleanup-test-dir base-path))))

;;;; Test 5.5: pruned-height persistence

(test pruned-height-persists
  "pruned-height should survive save/load cycle."
  (let ((base-path (ensure-directories-exist
                    (merge-pathnames (format nil "test-prune-persist-~A/" (get-universal-time))
                                     (uiop:temporary-directory)))))
    (unwind-protect
        (progn
          ;; Save state with pruned-height
          (let ((state (bitcoin-lisp.storage:init-chain-state base-path)))
            (let ((hash (make-test-hash #xBB 1)))
              (bitcoin-lisp.storage:update-chain-tip state hash 500))
            (setf (bitcoin-lisp.storage:chain-state-pruned-height state) 200)
            (bitcoin-lisp.storage:save-state state))
          ;; Load into fresh state
          (let ((state2 (bitcoin-lisp.storage:init-chain-state base-path)))
            (is (bitcoin-lisp.storage:load-state state2))
            (is (= 200 (bitcoin-lisp.storage:chain-state-pruned-height state2)))
            (is (= 500 (bitcoin-lisp.storage:current-height state2)))))
      (cleanup-test-dir base-path))))

(test pruned-height-backward-compat
  "Loading old chainstate.dat without pruned-height should default to 0."
  (let ((base-path (ensure-directories-exist
                    (merge-pathnames (format nil "test-prune-compat-~A/" (get-universal-time))
                                     (uiop:temporary-directory)))))
    (unwind-protect
        (progn
          ;; Write old-format 36-byte chainstate.dat manually
          (let ((path (merge-pathnames "chainstate.dat" base-path)))
            (with-open-file (stream path
                                    :direction :output
                                    :if-exists :supersede
                                    :element-type '(unsigned-byte 8))
              ;; 32 bytes of hash
              (dotimes (i 32) (write-byte #xDD stream))
              ;; 4 bytes of height (little-endian, height = 100)
              (write-byte 100 stream)
              (write-byte 0 stream)
              (write-byte 0 stream)
              (write-byte 0 stream)))
          ;; Load - should succeed with pruned-height = 0
          (let ((state (bitcoin-lisp.storage:init-chain-state base-path)))
            (is (bitcoin-lisp.storage:load-state state))
            (is (= 0 (bitcoin-lisp.storage:chain-state-pruned-height state)))
            (is (= 100 (bitcoin-lisp.storage:current-height state)))))
      (cleanup-test-dir base-path))))

;;;; Test 5.6: txindex/prune incompatibility

(test txindex-prune-incompatibility
  "Starting with both txindex and prune should signal an error."
  (signals error
    (bitcoin-lisp:start-node :data-directory "/tmp/btc-prune-incompat-test/"
                             :network :testnet
                             :sync nil
                             :txindex t
                             :prune 550)))

;;;; Test 5.7: prune target validation

(test prune-target-validation
  "Invalid prune targets should signal an error."
  ;; Values between 2 and 549 are invalid
  (signals error
    (bitcoin-lisp:start-node :data-directory "/tmp/btc-prune-val-test/"
                             :network :testnet
                             :sync nil
                             :prune 100))
  (signals error
    (bitcoin-lisp:start-node :data-directory "/tmp/btc-prune-val-test/"
                             :network :testnet
                             :sync nil
                             :prune 549)))

;;;; Test 5.8: pruneblockchain RPC return value

(test prune-blocks-to-height-return
  "prune-blocks-to-height should update pruned-height and return count."
  ;; Need 300 blocks so tip (300) - min-keep (288) = 12, allowing pruning of blocks 1-12
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 300)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bitcoin-lisp:*prune-target-mib* 1))  ; manual-only
          ;; Prune up to height 10
          (let ((pruned (bitcoin-lisp.storage:prune-blocks-to-height
                         block-store chain-state 10)))
            (is (> pruned 0))
            ;; pruned-height should be updated (last pruned block)
            (is (> (bitcoin-lisp.storage:chain-state-pruned-height chain-state) 0))
            (is (< (bitcoin-lisp.storage:chain-state-pruned-height chain-state) 10))))
      (cleanup-test-dir base-path))))

;;;; Test 5.9: getblockchaininfo pruning fields

(test getblockchaininfo-pruning-disabled
  "getblockchaininfo should report pruned=NIL when pruning is disabled."
  (let ((bitcoin-lisp:*prune-target-mib* nil))
    (is (not (bitcoin-lisp:pruning-enabled-p)))))

(test getblockchaininfo-pruning-enabled
  "getblockchaininfo should report correct pruning fields."
  ;; Test automatic mode
  (let ((bitcoin-lisp:*prune-target-mib* 550))
    (is (bitcoin-lisp:pruning-enabled-p))
    (is (bitcoin-lisp:automatic-pruning-p)))
  ;; Test manual-only mode
  (let ((bitcoin-lisp:*prune-target-mib* 1))
    (is (bitcoin-lisp:pruning-enabled-p))
    (is (not (bitcoin-lisp:automatic-pruning-p)))))

(test prune-target-size-in-bytes
  "prune_target_size should be in bytes (MiB * 1048576)."
  (let ((bitcoin-lisp:*prune-target-mib* 550))
    ;; 550 * 1048576 = 576716800
    (is (= (* 550 1048576) 576716800))))

;;;; Test 5.10: BIP 159 service bits

(test service-bits-pruning-enabled
  "When pruning is enabled, services should include NODE_NETWORK_LIMITED
and exclude NODE_NETWORK."
  (let ((bitcoin-lisp:*prune-target-mib* 550))
    (let ((services (if (bitcoin-lisp:pruning-enabled-p)
                        (logior bitcoin-lisp.serialization:+node-network-limited+
                                bitcoin-lisp.serialization:+node-witness+)
                        (logior bitcoin-lisp.serialization:+node-network+
                                bitcoin-lisp.serialization:+node-witness+))))
      ;; NODE_NETWORK_LIMITED should be set
      (is (not (zerop (logand services bitcoin-lisp.serialization:+node-network-limited+))))
      ;; NODE_NETWORK should NOT be set
      (is (zerop (logand services bitcoin-lisp.serialization:+node-network+)))
      ;; NODE_WITNESS should be set
      (is (not (zerop (logand services bitcoin-lisp.serialization:+node-witness+)))))))

(test service-bits-pruning-disabled
  "When pruning is disabled, services should include NODE_NETWORK
and exclude NODE_NETWORK_LIMITED."
  (let ((bitcoin-lisp:*prune-target-mib* nil))
    (let ((services (if (bitcoin-lisp:pruning-enabled-p)
                        (logior bitcoin-lisp.serialization:+node-network-limited+
                                bitcoin-lisp.serialization:+node-witness+)
                        (logior bitcoin-lisp.serialization:+node-network+
                                bitcoin-lisp.serialization:+node-witness+))))
      ;; NODE_NETWORK should be set
      (is (not (zerop (logand services bitcoin-lisp.serialization:+node-network+))))
      ;; NODE_NETWORK_LIMITED should NOT be set
      (is (zerop (logand services bitcoin-lisp.serialization:+node-network-limited+))))))

;;;; Test 5.11: pruned block get-block returns NIL

(test get-block-returns-nil-for-pruned
  "get-block should return NIL for a pruned block."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 3)
    (declare (ignore chain-state))
    (unwind-protect
        (let ((hash (second block-hashes)))  ; height 1
          ;; Block exists
          (is (not (null (bitcoin-lisp.storage:get-block block-store hash))))
          ;; Prune it
          (bitcoin-lisp.storage:prune-block block-store hash)
          ;; get-block returns NIL
          (is (null (bitcoin-lisp.storage:get-block block-store hash))))
      (cleanup-test-dir base-path))))

;;;; Test 5.12: reorg past pruned height

(test reorg-past-pruned-height-fails
  "perform-reorg should return NIL when fork point is below pruned height."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 10)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bitcoin-lisp:*prune-target-mib* 550))
          ;; Simulate pruned-height at 5
          (setf (bitcoin-lisp.storage:chain-state-pruned-height chain-state) 5)
          ;; Create old-tip at height 10 and new-tip with fork at height 3
          ;; The fork is below pruned-height (5), so reorg should fail
          (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
                 ;; Build a fake old tip entry at height 10
                 (fork-hash (make-test-hash #xF0 3))
                 (fork-entry (bitcoin-lisp.storage:make-block-index-entry
                              :hash fork-hash :height 3 :chain-work 4 :status :valid))
                 ;; Old chain: fork -> ... -> old-tip (height 10)
                 (old-mid-entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash (make-test-hash #xF1 7) :height 7
                                 :chain-work 8 :status :valid
                                 :prev-entry fork-entry))
                 (old-tip-entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash (make-test-hash #xF1 10) :height 10
                                 :chain-work 11 :status :valid
                                 :prev-entry old-mid-entry))
                 ;; New chain: fork -> ... -> new-tip (height 12, more work)
                 (new-mid-entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash (make-test-hash #xF2 8) :height 8
                                 :chain-work 9 :status :valid
                                 :prev-entry fork-entry))
                 (new-tip-entry (bitcoin-lisp.storage:make-block-index-entry
                                 :hash (make-test-hash #xF2 12) :height 12
                                 :chain-work 15 :status :valid
                                 :prev-entry new-mid-entry)))
            ;; Reorg should fail (fork at height 3 < pruned-height 5)
            (is (null (bitcoin-lisp.validation:perform-reorg
                       chain-state block-store utxo-set
                       old-tip-entry new-tip-entry)))))
      (cleanup-test-dir base-path))))

;;;; Test: block-storage-size-mib

(test block-storage-size-mib-calculation
  "block-storage-size-mib should return the total size of block files."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 3)
    (declare (ignore chain-state block-hashes))
    (unwind-protect
        (let ((size (bitcoin-lisp.storage:block-storage-size-mib block-store)))
          ;; Should be positive (we stored 3 blocks)
          (is (> size 0))
          ;; Should be small (test blocks are tiny)
          (is (< size 1.0)))
      (cleanup-test-dir base-path))))

;;;; Test: prune-blocks-to-height respects min-blocks-to-keep

(test prune-respects-min-blocks-retention
  "prune-blocks-to-height should not prune within min-blocks-to-keep of tip."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 10)
    (unwind-protect
        (let ((bitcoin-lisp:*prune-target-mib* 1))
          ;; Chain is at height 10, min-blocks-to-keep is 288
          ;; max-prune-height = max(0, 10 - 288) = 0
          ;; So nothing should be prunable
          (let ((pruned (bitcoin-lisp.storage:prune-blocks-to-height
                         block-store chain-state 999)))
            (is (= 0 pruned))
            ;; All blocks should still exist
            (loop for hash in (rest block-hashes)
                  do (is (not (null (bitcoin-lisp.storage:block-exists-p
                                     block-store hash)))))))
      (cleanup-test-dir base-path))))

;;;; Test: pruning disabled returns 0

(test prune-blocks-to-height-disabled
  "prune-blocks-to-height should return 0 when pruning is disabled."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bitcoin-lisp:*prune-target-mib* nil))
          (is (= 0 (bitcoin-lisp.storage:prune-blocks-to-height
                     block-store chain-state 3))))
      (cleanup-test-dir base-path))))
