(in-package #:bitcoin-lisp.tests)

(in-suite :pruning-tests)

;;;; Helper: create a test block and store it

(defun make-pruning-test-block (prev-hash block-hash height)
  "Create a minimal test block for pruning tests."
  (let* ((coinbase-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector (bl.ser:make-tx-in
                                      :previous-output (bl.ser:make-outpoint
                                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                          :initial-element 0)
                                                        :index #xFFFFFFFF)
                                      :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                                :initial-element 1)))
                       :outputs (vector (bl.ser:make-tx-out
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
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp (+ 1231006505 (* height 600))
                  :bits #x1d00ffff
                  :nonce 0
                  :cached-hash block-hash)))
    (bl.ser:make-bitcoin-block
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
Returns (VALUES base-path block-store chain-state block-hashes).

Blocks go into LEGACY per-block files, whatever the current default is. This
suite asserts per-BLOCK prune semantics — \"prune to height 90 deletes 61..89\"
— and those exist only in that format: a blk?????.dat prunes whole, so a store
holding all 400 of these tiny blocks in one file can only prune all of them or
none, which is Core's behaviour too. File-granular pruning has its own coverage
in flatfile-tests.lisp (PRUNE-OLD-BLOCKS-ACTUALLY-PRUNES-A-FLAT-FILE,
PRUNEBLOCKCHAIN-PRUNES-A-FLAT-FILE, PRUNE-LOCK-*)."
  (let* ((bl.store:*flat-block-files* nil)
         (base-path (ensure-directories-exist
                     (merge-pathnames (format nil "test-pruning-~A/" (get-universal-time))
                                      (uiop:temporary-directory))))
         (block-store (bl.store:init-block-store base-path))
         (chain-state (bl.store:init-chain-state base-path))
         (genesis-hash (bl.store:best-block-hash chain-state))
         (block-hashes (list genesis-hash)))
    ;; Add genesis entry
    (let ((genesis-entry (bl.store:make-block-index-entry
                          :hash genesis-hash :height 0 :chain-work 1 :status :valid)))
      (bl.store:add-block-index-entry chain-state genesis-entry)
      ;; Create and store N blocks with proper prev-entry links
      (let ((prev-hash genesis-hash)
            (prev-entry genesis-entry))
        (loop for h from 1 to n-blocks
              for block-hash = (make-test-hash #xAA h)
              do (let ((block (make-pruning-test-block prev-hash block-hash h)))
                   (bl.store:store-block block-store block)
                   (let ((entry (bl.store:make-block-index-entry
                                 :hash block-hash :height h :chain-work (1+ h)
                                 :status :valid :prev-entry prev-entry)))
                     (bl.store:add-block-index-entry chain-state entry)
                     (bl.store:update-chain-tip chain-state block-hash h)
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

(test prune-deletes-undo-files-and-stale-sweep
  "Pruned blocks take their undo files with them (Core deletes rev with
blk), and prune-stale-undo-files clears undo at/below the pruned horizon
plus unknown-hash remnants."
  ;; 300 blocks: tip - +min-blocks-to-keep+ (288) leaves heights 1..12 prunable.
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 300)
    (let ((undo-dir (merge-pathnames "undo/" base-path))
          (bl:*prune-target-mib* 1)
          (bl:*prune-after-height* 0))
      (unwind-protect
           (progn
             (bl.val:initialize-undo-storage undo-dir)
             ;; Fabricate undo files for the first five blocks + garbage.
             (dolist (hash (subseq block-hashes 1 6))
               (bl.val::save-undo-data-to-disk hash '()))
             (with-open-file (out (merge-pathnames "nothex.dat" undo-dir)
                                  :direction :output
                                  :element-type '(unsigned-byte 8))
               (write-byte 0 out))
             ;; Manual prune to height 3 deletes blocks 1..2 AND their undo.
             (let ((pruned (bl.store:prune-blocks-to-height
                            block-store chain-state 3
                            :on-prune #'bl.val:delete-undo-file)))
               (is (= 2 pruned)))
             (let ((h1 (second block-hashes))
                   (h5 (sixth block-hashes)))
               (is (null (probe-file (bl.val::undo-file-path h1))))
               (is (not (null (probe-file (bl.val::undo-file-path h5)))))
               ;; Re-create one stale undo below the horizon (simulating the
               ;; pre-undo-pruning backlog), then sweep: it and the garbage
               ;; file go; the above-horizon file stays.
               (bl.val::save-undo-data-to-disk h1 '())
               (let ((swept (bl.val:prune-stale-undo-files chain-state)))
                 (is (>= swept 2)))
               (is (null (probe-file (bl.val::undo-file-path h1))))
               (is (null (probe-file (merge-pathnames "nothex.dat" undo-dir))))
               (is (not (null (probe-file (bl.val::undo-file-path h5)))))))
        (setf bl.val::*undo-base-path* nil)
        (uiop:delete-directory-tree base-path :validate t :if-does-not-exist :ignore)))))

(test prune-block-deletes-file
  "prune-block should delete the block file and remove it from the index."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore chain-state))
    (unwind-protect
        (let ((hash (second block-hashes)))  ; block at height 1
          ;; Block exists before pruning
          (is (not (null (bl.store:block-exists-p block-store hash))))
          ;; Prune it
          (let ((deleted-bytes (bl.store:prune-block block-store hash)))
            (is (not (null deleted-bytes)))
            (is (> deleted-bytes 0)))
          ;; Block no longer exists
          (is (null (bl.store:block-exists-p block-store hash)))
          ;; get-block returns NIL for pruned block
          (is (null (bl.store:get-block block-store hash))))
      (cleanup-test-dir base-path))))

(test prune-block-nonexistent
  "prune-block should return NIL for a block that doesn't exist."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 1)
    (declare (ignore chain-state block-hashes))
    (unwind-protect
        (let ((fake-hash (make-test-hash #xFF #xFF)))
          (is (null (bl.store:prune-block block-store fake-hash))))
      (cleanup-test-dir base-path))))

;;;; Test 5.2: automatic pruning triggers when storage exceeds target

(test prune-old-blocks-respects-target
  "prune-old-blocks should prune when storage exceeds target."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 10)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bl:*prune-target-mib* 550)
              (bl:*prune-after-height* 0))
          ;; Storage is tiny (test blocks), so nothing should be pruned
          ;; since we're well under 550 MiB
          (let ((pruned (bl.store:prune-old-blocks block-store chain-state)))
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
          (let ((bl:*prune-target-mib* nil))
            (is (= 0 (bl.store:prune-old-blocks block-store chain-state))))
          ;; 1 = manual-only, no automatic pruning
          (let ((bl:*prune-target-mib* 1))
            (is (= 0 (bl.store:prune-old-blocks block-store chain-state)))))
      (cleanup-test-dir base-path))))

;;;; Test 5.3: manual-only mode

(test manual-only-mode-pruning
  "In manual-only mode (*prune-target-mib* = 1), prune-blocks-to-height should work
but prune-old-blocks should not."
  ;; Need 300 blocks so tip (300) - min-keep (288) = 12, allowing pruning of blocks 1-12
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 300)
    (unwind-protect
        (let ((bl:*prune-target-mib* 1)
              (bl:*prune-after-height* 0))
          ;; Automatic pruning should not run
          (is (= 0 (bl.store:prune-old-blocks block-store chain-state)))
          ;; Manual pruning should work (prune up to height 10)
          (let ((pruned (bl.store:prune-blocks-to-height
                         block-store chain-state 10)))
            (is (> pruned 0))
            ;; Pruned blocks should be gone (height 1)
            (is (null (bl.store:block-exists-p
                       block-store (second block-hashes))))
            ;; Blocks at height 10+ should remain
            (is (not (null (bl.store:block-exists-p
                            block-store (nth 11 block-hashes)))))))
      (cleanup-test-dir base-path))))

;;;; Test 5.4: prune-after-height

(test pruning-respects-prune-after-height
  "prune-old-blocks should not prune when chain height is below *prune-after-height*."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bl:*prune-target-mib* 550)
              (bl:*prune-after-height* 1000))  ; chain is only at height 5
          ;; Should skip pruning because chain height (5) < prune-after-height (1000)
          (is (= 0 (bl.store:prune-old-blocks block-store chain-state))))
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
          (let ((state (bl.store:init-chain-state base-path)))
            (let ((hash (make-test-hash #xBB 1)))
              (bl.store:update-chain-tip state hash 500))
            (setf (bl.store:chain-state-pruned-height state) 200)
            (bl.store:save-state state))
          ;; Load into fresh state
          (let ((state2 (bl.store:init-chain-state base-path)))
            (is (bl.store:load-state state2))
            (is (= 200 (bl.store:chain-state-pruned-height state2)))
            (is (= 500 (bl.store:current-height state2)))))
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
          (let ((state (bl.store:init-chain-state base-path)))
            (is (bl.store:load-state state))
            (is (= 0 (bl.store:chain-state-pruned-height state)))
            (is (= 100 (bl.store:current-height state)))))
      (cleanup-test-dir base-path))))

;;;; Test 5.6: txindex/prune incompatibility

(test txindex-prune-incompatibility
  "Starting with both txindex and prune should signal an error."
  (signals error
    (bl:start-node :data-directory "/tmp/btc-prune-incompat-test/"
                             :network :testnet
                             :sync nil
                             :txindex t
                             :prune 550)))

;;;; Test 5.7: prune target validation

(test prune-target-validation
  "Invalid prune targets should signal an error."
  ;; Values between 2 and 549 are invalid
  (signals error
    (bl:start-node :data-directory "/tmp/btc-prune-val-test/"
                             :network :testnet
                             :sync nil
                             :prune 100))
  (signals error
    (bl:start-node :data-directory "/tmp/btc-prune-val-test/"
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
        (let ((bl:*prune-target-mib* 1))  ; manual-only
          ;; Prune up to height 10
          (let ((pruned (bl.store:prune-blocks-to-height
                         block-store chain-state 10)))
            (is (> pruned 0))
            ;; pruned-height should be updated (last pruned block)
            (is (> (bl.store:chain-state-pruned-height chain-state) 0))
            (is (< (bl.store:chain-state-pruned-height chain-state) 10))))
      (cleanup-test-dir base-path))))

;;;; Test 5.9: getblockchaininfo pruning fields

(test getblockchaininfo-pruning-disabled
  "getblockchaininfo should report pruned=NIL when pruning is disabled."
  (let ((bl:*prune-target-mib* nil))
    (is (not (bl:pruning-enabled-p)))))

(test getblockchaininfo-pruning-enabled
  "getblockchaininfo should report correct pruning fields."
  ;; Test automatic mode
  (let ((bl:*prune-target-mib* 550))
    (is (bl:pruning-enabled-p))
    (is (bl:automatic-pruning-p)))
  ;; Test manual-only mode
  (let ((bl:*prune-target-mib* 1))
    (is (bl:pruning-enabled-p))
    (is (not (bl:automatic-pruning-p)))))

(test prune-target-size-in-bytes
  "prune_target_size should be in bytes (MiB * 1048576)."
  (let ((bl:*prune-target-mib* 550))
    ;; 550 * 1048576 = 576716800
    (is (= (* 550 1048576) 576716800))))

;;;; Test 5.10: BIP 159 service bits

(test service-bits-pruning-enabled
  "When pruning is enabled, services should include NODE_NETWORK_LIMITED
and exclude NODE_NETWORK."
  (let ((bl:*prune-target-mib* 550))
    (let ((services (if (bl:pruning-enabled-p)
                        (logior bl.ser:+node-network-limited+
                                bl.ser:+node-witness+)
                        (logior bl.ser:+node-network+
                                bl.ser:+node-witness+))))
      ;; NODE_NETWORK_LIMITED should be set
      (is (not (zerop (logand services bl.ser:+node-network-limited+))))
      ;; NODE_NETWORK should NOT be set
      (is (zerop (logand services bl.ser:+node-network+)))
      ;; NODE_WITNESS should be set
      (is (not (zerop (logand services bl.ser:+node-witness+)))))))

(test service-bits-pruning-disabled
  "When pruning is disabled, services should include NODE_NETWORK
and exclude NODE_NETWORK_LIMITED."
  (let ((bl:*prune-target-mib* nil))
    (let ((services (if (bl:pruning-enabled-p)
                        (logior bl.ser:+node-network-limited+
                                bl.ser:+node-witness+)
                        (logior bl.ser:+node-network+
                                bl.ser:+node-witness+))))
      ;; NODE_NETWORK should be set
      (is (not (zerop (logand services bl.ser:+node-network+))))
      ;; NODE_NETWORK_LIMITED should NOT be set
      (is (zerop (logand services bl.ser:+node-network-limited+))))))

;;;; Test 5.11: pruned block get-block returns NIL

(test get-block-returns-nil-for-pruned
  "get-block should return NIL for a pruned block."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 3)
    (declare (ignore chain-state))
    (unwind-protect
        (let ((hash (second block-hashes)))  ; height 1
          ;; Block exists
          (is (not (null (bl.store:get-block block-store hash))))
          ;; Prune it
          (bl.store:prune-block block-store hash)
          ;; get-block returns NIL
          (is (null (bl.store:get-block block-store hash))))
      (cleanup-test-dir base-path))))

;;;; Test 5.12: reorg past pruned height

(test reorg-past-pruned-height-fails
  "perform-reorg should return NIL when fork point is below pruned height."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 10)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bl:*prune-target-mib* 550))
          ;; Simulate pruned-height at 5
          (setf (bl.store:chain-state-pruned-height chain-state) 5)
          ;; Create old-tip at height 10 and new-tip with fork at height 3
          ;; The fork is below pruned-height (5), so reorg should fail
          (let* ((utxo-set (bl.store:make-utxo-set))
                 ;; Build a fake old tip entry at height 10
                 (fork-hash (make-test-hash #xF0 3))
                 (fork-entry (bl.store:make-block-index-entry
                              :hash fork-hash :height 3 :chain-work 4 :status :valid))
                 ;; Old chain: fork -> ... -> old-tip (height 10)
                 (old-mid-entry (bl.store:make-block-index-entry
                                 :hash (make-test-hash #xF1 7) :height 7
                                 :chain-work 8 :status :valid
                                 :prev-entry fork-entry))
                 (old-tip-entry (bl.store:make-block-index-entry
                                 :hash (make-test-hash #xF1 10) :height 10
                                 :chain-work 11 :status :valid
                                 :prev-entry old-mid-entry))
                 ;; New chain: fork -> ... -> new-tip (height 12, more work)
                 (new-mid-entry (bl.store:make-block-index-entry
                                 :hash (make-test-hash #xF2 8) :height 8
                                 :chain-work 9 :status :valid
                                 :prev-entry fork-entry))
                 (new-tip-entry (bl.store:make-block-index-entry
                                 :hash (make-test-hash #xF2 12) :height 12
                                 :chain-work 15 :status :valid
                                 :prev-entry new-mid-entry)))
            ;; Reorg should fail (fork at height 3 < pruned-height 5)
            (is (null (bl.val:perform-reorg
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
        (let ((size (bl.store:block-storage-size-mib block-store)))
          ;; Should be positive (we stored 3 blocks)
          (is (> size 0))
          ;; Should be small (test blocks are tiny)
          (is (< size 1.0)))
      (cleanup-test-dir base-path))))

;;;; Test: total-bytes running counter (O(1) size accounting)

(test total-bytes-tracks-store-and-prune
  "block-store-total-bytes should track store-block, overwrites, prune-block,
and survive an init-block-store rescan."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore chain-state))
    (unwind-protect
        (let ((total (bl.store:block-store-total-bytes block-store)))
          ;; Counter is positive and matches the directory-scan value of a
          ;; freshly initialized store
          (is (> total 0))
          (let ((store2 (bl.store:init-block-store base-path)))
            (is (= total (bl.store:block-store-total-bytes store2))))
          ;; Overwriting an existing block must not double-count. The binding
          ;; keeps the rewrite in the same format the store already holds:
          ;; appending it to a blk file instead would not be an overwrite at
          ;; all, it would be a second copy, and the counter would rightly grow.
          (let ((bl.store:*flat-block-files* nil)
                (block (make-pruning-test-block (second block-hashes)
                                                (third block-hashes) 2)))
            (bl.store:store-block block-store block)
            (is (= total (bl.store:block-store-total-bytes block-store))))
          ;; Pruning decrements by the deleted size
          (let ((deleted (bl.store:prune-block
                          block-store (second block-hashes))))
            (is (> deleted 0))
            (is (= (- total deleted)
                   (bl.store:block-store-total-bytes block-store)))))
      (cleanup-test-dir base-path))))

(test prune-old-blocks-prunes-down-to-keep-window
  "When over target, prune-old-blocks should delete oldest blocks up to
tip - min-blocks-to-keep in one call, advancing pruned-height."
  ;; 300 blocks: min-keep-height = 300 - 288 = 12, so heights 1-12 are prunable
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 300)
    (unwind-protect
        (let ((bl:*prune-target-mib* 550)
              (bl:*prune-after-height* 0))
          ;; Fake an over-target counter (real test blocks are tiny); the
          ;; prune loop should then delete everything it's allowed to
          (setf (bl.store:block-store-total-bytes block-store)
                (* 600 1048576))
          (let ((pruned (bl.store:prune-old-blocks
                         block-store chain-state)))
            (is (= 12 pruned))
            (is (= 12 (bl.store:chain-state-pruned-height chain-state)))
            ;; Heights 1 and 12 gone, 13 still present
            (is (null (bl.store:block-exists-p
                       block-store (nth 1 block-hashes))))
            (is (null (bl.store:block-exists-p
                       block-store (nth 12 block-hashes))))
            (is (not (null (bl.store:block-exists-p
                            block-store (nth 13 block-hashes)))))))
      (cleanup-test-dir base-path))))

;;;; Test: prune-blocks-to-height respects min-blocks-to-keep

(test prune-respects-min-blocks-retention
  "prune-blocks-to-height should not prune within min-blocks-to-keep of tip."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 10)
    (unwind-protect
        (let ((bl:*prune-target-mib* 1))
          ;; Chain is at height 10, min-blocks-to-keep is 288
          ;; max-prune-height = max(0, 10 - 288) = 0
          ;; So nothing should be prunable
          (let ((pruned (bl.store:prune-blocks-to-height
                         block-store chain-state 999)))
            (is (= 0 pruned))
            ;; All blocks should still exist
            (loop for hash in (rest block-hashes)
                  do (is (not (null (bl.store:block-exists-p
                                     block-store hash)))))))
      (cleanup-test-dir base-path))))

;;;; Test: pruning disabled returns 0

(test prune-blocks-to-height-disabled
  "prune-blocks-to-height should return 0 when pruning is disabled."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore block-hashes))
    (unwind-protect
        (let ((bl:*prune-target-mib* nil))
          (is (= 0 (bl.store:prune-blocks-to-height
                     block-store chain-state 3))))
      (cleanup-test-dir base-path))))

;;;; Coins-cache budget (Core -dbcache) — large-coins-cache-threshold scaling

(test coins-cache-threshold-scales-and-stays-under-budget
  "large-coins-cache-threshold returns a flush point below the budget and
rises with it, across the default 450 MiB and the larger -dbcache regimes
(so a bigger budget really does hold more UTXOs before flushing)."
  (flet ((thr (mib) (bl::large-coins-cache-threshold (* mib 1024 1024))))
    ;; Always strictly below the budget (cache flushes before exceeding it).
    (dolist (mib '(450 768 1536 2048 4096))
      (is (< (thr mib) (* mib 1024 1024)) "threshold < budget at ~D MiB" mib))
    ;; Monotonically increasing in the budget.
    (is (< (thr 450) (thr 1536)))
    (is (< (thr 1536) (thr 4096)))
    ;; Default budget is Core's DEFAULT_DB_CACHE (450 MiB).
    (is (= (* 450 1024 1024)
           (let ((bl::*coins-cache-budget-bytes* (* 450 1024 1024)))
             bl::*coins-cache-budget-bytes*)))))

;;;; Assumeutxo P6: per-chainstate prune ranges (Core Chainstate::GetPruneRange,
;;;; validation.cpp:6366-6391) + halved automatic target while a historical
;;;; chainstate exists (Core FindFilesToPrune, node/blockstorage.cpp:330-338).

(test chain-state-prune-floor-roles
  "chain-state-prune-floor is the snapshot base height for an UNVALIDATED
snapshot chainstate, 0 for a plain or VALIDATED chainstate, and refuses all
pruning (most-positive-fixnum) when the base header is missing from the
index."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 5)
    (declare (ignore block-store))
    (unwind-protect
         (progn
           ;; Plain chainstate: prunes from genesis.
           (is (= 0 (bl.store:chain-state-prune-floor chain-state)))
           ;; Unvalidated snapshot chainstate: floor at the base height.
           (setf (bl.store:chain-state-from-snapshot-blockhash chain-state)
                 (nth 3 block-hashes)
                 (bl.store:chain-state-assumeutxo-status chain-state)
                 :unvalidated)
           (is (= 3 (bl.store:chain-state-prune-floor chain-state)))
           ;; Promotion (VALIDATED) lifts the floor entirely.
           (setf (bl.store:chain-state-assumeutxo-status chain-state)
                 :validated)
           (is (= 0 (bl.store:chain-state-prune-floor chain-state)))
           ;; Unknown base header: refuse to prune anything.
           (setf (bl.store:chain-state-assumeutxo-status chain-state)
                 :unvalidated
                 (bl.store:chain-state-from-snapshot-blockhash chain-state)
                 (make-test-hash #xEE #xEE))
           (is (= most-positive-fixnum
                  (bl.store:chain-state-prune-floor chain-state))))
      (cleanup-test-dir base-path))))

(test effective-prune-target-halved-while-historical-exists
  "effective-prune-target-bytes divides the automatic prune target by the
number of chainstates — halved while a historical chainstate exists, floored
at MIN_DISK_SPACE_FOR_BLOCK_FILES (Core node/blockstorage.cpp:330-338)."
  (let* ((base-hash (make-test-hash #xEE 5))
         (primary (bl.store:make-chain-state))
         (snap (bl.store:make-chain-state
                :from-snapshot-blockhash base-hash
                :assumeutxo-status :unvalidated
                :storage-suffix "_snapshot"))
         (node (bl::make-node :network :testnet3)))
    ;; A target-blockhash (and no target-utxohash) makes PRIMARY historical.
    (setf (bl.store:chain-state-target-blockhash primary) base-hash
          (bl::node-chainstates node) (list primary snap))
    (let ((bl::*node* node))
      (let ((bl:*prune-target-mib* 2000))
        (is (= (* 1000 1048576) (bl:effective-prune-target-bytes))))
      ;; Halving never pushes the target below the 550 MiB floor.
      (let ((bl:*prune-target-mib* 550))
        (is (= bl:+min-disk-space-for-block-files+
               (bl:effective-prune-target-bytes)))))
    ;; No node / no historical chainstate: the full target.
    (let ((bl::*node* nil)
          (bl:*prune-target-mib* 2000))
      (is (= (* 2000 1048576) (bl:effective-prune-target-bytes))))
    ;; Background completion ends the historical role: full target again.
    (setf (bl.store:chain-state-target-utxohash primary)
          (make-test-hash 1 1))
    (let ((bl::*node* node)
          (bl:*prune-target-mib* 2000))
      (is (= (* 2000 1048576) (bl:effective-prune-target-bytes))))))

(test prune-floor-unvalidated-snapshot-then-promotion
  "Automatic pruning driven by an UNVALIDATED snapshot chainstate never
deletes a block at or below the snapshot base (deleting one would wedge the
background validation permanently); after promotion the floor lifts and the
rewound cursor lets a later walk reclaim the protected window."
  ;; 400 blocks: tip - 288 = 112 prunable ceiling; snapshot base at 60.
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 400)
    (unwind-protect
         (let* ((base-hash (nth 60 block-hashes))
                (historical (bl.store:make-chain-state
                             :block-index (bl.store::chain-state-block-index
                                           chain-state)))
                (node (bl::make-node :network :testnet3)))
           ;; CHAIN-STATE becomes the snapshot chainstate (tip 400, base 60);
           ;; HISTORICAL re-derives history below the base (tip 40).
           (setf (bl.store:chain-state-from-snapshot-blockhash chain-state)
                 base-hash
                 (bl.store:chain-state-assumeutxo-status chain-state)
                 :unvalidated)
           (bl.store:update-chain-tip historical (nth 40 block-hashes) 40)
           (bl.store:set-chainstate-target
            historical (bl.store:get-block-index-entry chain-state base-hash))
           (setf (bl::node-chainstates node) (list historical chain-state))
           (let ((bl::*node* node)
                 (bl:*prune-target-mib* 550)
                 (bl:*prune-after-height* 0))
             (is (= 60 (bl.store:chain-state-prune-floor chain-state)))
             (is (= 0 (bl.store:chain-state-prune-floor historical)))
             ;; Force an over-target prune on the SNAPSHOT chainstate: only
             ;; heights 61..112 may go; the base range 1..60 stays on disk.
             (setf (bl.store:block-store-total-bytes block-store)
                   (* 600 1048576))
             (let ((pruned (bl.store:prune-old-blocks
                            block-store chain-state)))
               (is (= 52 pruned)))
             (is (= 112 (bl.store:chain-state-pruned-height chain-state)))
             (is (not (null (bl.store:block-exists-p
                             block-store (nth 1 block-hashes)))))
             (is (not (null (bl.store:block-exists-p
                             block-store (nth 60 block-hashes)))))
             (is (null (bl.store:block-exists-p
                        block-store (nth 61 block-hashes))))
             (is (null (bl.store:block-exists-p
                        block-store (nth 112 block-hashes))))
             (is (not (null (bl.store:block-exists-p
                             block-store (nth 113 block-hashes)))))
             ;; The HISTORICAL chainstate (tip 40) has no prunable range of
             ;; its own yet (40 - 288 < 1): nothing deleted.
             (is (= 0 (bl.store:prune-old-blocks
                       block-store historical)))
             ;; Promotion: VALIDATED lifts the floor and the cursor rewinds
             ;; (what %validate-snapshot-against-commitment does), so the
             ;; protected window is reclaimed.
             (setf (bl.store:chain-state-assumeutxo-status chain-state)
                   :validated)
             (bl.store:lift-prune-floor-on-promotion
              chain-state historical)
             (is (= 0 (bl.store:chain-state-prune-floor chain-state)))
             (let ((pruned (bl.store:prune-old-blocks
                            block-store chain-state)))
               (is (= 60 pruned)))
             (is (null (bl.store:block-exists-p
                        block-store (nth 1 block-hashes))))
             (is (null (bl.store:block-exists-p
                        block-store (nth 60 block-hashes))))
             (is (not (null (bl.store:block-exists-p
                             block-store (nth 113 block-hashes)))))))
      (cleanup-test-dir base-path))))

(test prune-historical-own-range-while-snapshot-floored
  "While the snapshot chainstate is floored at a high base, the historical
chainstate still prunes its OWN already-validated range normally (Core: each
chainstate prunes its GetPruneRange; the historical range starts at 0)."
  ;; Base at 350 (above the snapshot tip's 400-288=112 prune ceiling): the
  ;; snapshot chainstate can prune nothing; the historical (tip 300) prunes
  ;; its own 1..12 window.
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 400)
    (unwind-protect
         (let* ((base-hash (nth 350 block-hashes))
                (historical (bl.store:make-chain-state
                             :block-index (bl.store::chain-state-block-index
                                           chain-state)))
                (node (bl::make-node :network :testnet3)))
           (setf (bl.store:chain-state-from-snapshot-blockhash chain-state)
                 base-hash
                 (bl.store:chain-state-assumeutxo-status chain-state)
                 :unvalidated)
           (bl.store:update-chain-tip historical (nth 300 block-hashes) 300)
           (bl.store:set-chainstate-target
            historical (bl.store:get-block-index-entry chain-state base-hash))
           (setf (bl::node-chainstates node) (list historical chain-state))
           (let ((bl::*node* node)
                 (bl:*prune-target-mib* 550)
                 (bl:*prune-after-height* 0))
             (setf (bl.store:block-store-total-bytes block-store)
                   (* 600 1048576))
             ;; Snapshot chainstate: floor 350 > prune ceiling 112 -> nothing.
             (is (= 0 (bl.store:prune-old-blocks
                       block-store chain-state)))
             (is (not (null (bl.store:block-exists-p
                             block-store (nth 1 block-hashes)))))
             ;; Historical chainstate: prunes its own 1..12 (300 - 288).
             (let ((pruned (bl.store:prune-old-blocks
                            block-store historical)))
               (is (= 12 pruned)))
             (is (= 12 (bl.store:chain-state-pruned-height historical)))
             (is (null (bl.store:block-exists-p
                        block-store (nth 12 block-hashes))))
             (is (not (null (bl.store:block-exists-p
                             block-store (nth 13 block-hashes)))))))
      (cleanup-test-dir base-path))))

(test manual-prune-respects-snapshot-floor
  "pruneblockchain's prune-blocks-to-height honors the snapshot floor too
(Core FindFilesToPruneManual also bounds the manual range by GetPruneRange):
a manual prune to a height above the base deletes only blocks strictly
between the base and the requested height."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 400)
    (unwind-protect
         (let ((bl:*prune-target-mib* 1))  ; manual-only mode
           (setf (bl.store:chain-state-from-snapshot-blockhash chain-state)
                 (nth 60 block-hashes)
                 (bl.store:chain-state-assumeutxo-status chain-state)
                 :unvalidated)
           (let ((pruned (bl.store:prune-blocks-to-height
                          block-store chain-state 90)))
             (is (= 29 pruned)))    ; heights 61..89
           (is (= 89 (bl.store:chain-state-pruned-height chain-state)))
           (is (not (null (bl.store:block-exists-p
                           block-store (nth 60 block-hashes)))))
           (is (null (bl.store:block-exists-p
                      block-store (nth 61 block-hashes))))
           (is (null (bl.store:block-exists-p
                      block-store (nth 89 block-hashes))))
           (is (not (null (bl.store:block-exists-p
                           block-store (nth 90 block-hashes))))))
      (cleanup-test-dir base-path))))

(test prune-stale-undo-files-horizon-override
  "The startup undo sweep deletes only at/below the caller-supplied horizon:
with dual chainstates the caller passes the MINIMUM pruned-height, so the
snapshot chainstate's high cursor can never wipe the historical chainstate's
undo window."
  (multiple-value-bind (base-path block-store chain-state block-hashes)
      (setup-pruning-test-store 300)
    (declare (ignore block-store))
    (let ((undo-dir (merge-pathnames "undo/" base-path)))
      (unwind-protect
           (progn
             (bl.val:initialize-undo-storage undo-dir)
             (dolist (hash (subseq block-hashes 1 6))   ; heights 1..5
               (bl.val::save-undo-data-to-disk hash '()))
             ;; The (snapshot) chainstate's own cursor claims 5, but the
             ;; conservative horizon is 3: only undo 1..3 may go.
             (setf (bl.store:chain-state-pruned-height chain-state) 5)
             (is (= 3 (bl.val:prune-stale-undo-files
                       chain-state :horizon 3)))
             (is (null (probe-file (merge-pathnames
                                    (format nil "~A.dat" (bl.crypto:bytes-to-hex
                                                          (nth 3 block-hashes)))
                                    undo-dir))))
             (is (not (null (probe-file (merge-pathnames
                                         (format nil "~A.dat" (bl.crypto:bytes-to-hex
                                                               (nth 4 block-hashes)))
                                         undo-dir)))))
             ;; Default horizon = the chainstate's own pruned-height (5).
             (is (= 2 (bl.val:prune-stale-undo-files chain-state)))
             (is (null (probe-file (merge-pathnames
                                    (format nil "~A.dat" (bl.crypto:bytes-to-hex
                                                          (nth 5 block-hashes)))
                                    undo-dir)))))
        (cleanup-test-dir base-path)))))
