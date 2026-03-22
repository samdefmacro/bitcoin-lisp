(in-package #:bitcoin-lisp.tests)

(def-suite :reorg-tests
  :description "Tests for chain reorganization logic"
  :in :bitcoin-lisp-tests)

(in-suite :reorg-tests)

;;;; Helpers for building test chains

(defun make-reorg-hash (id)
  "Create a unique 32-byte hash from an integer ID."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (logand id #xFF))
    (setf (aref h 1) (logand (ash id -8) #xFF))
    h))

(defun build-chain-entries (heights &key (base-work 0) (prev nil) (chain-state nil))
  "Build a list of block-index-entries for the given heights.
Returns the tip entry. If CHAIN-STATE provided, entries are added to it."
  (let ((entry prev))
    (dolist (h heights)
      (let ((new-entry (bitcoin-lisp.storage:make-block-index-entry
                        :hash (make-reorg-hash (+ h (* 1000 (if prev (bitcoin-lisp.storage:block-index-entry-height prev) 0))))
                        :height h
                        :header nil
                        :prev-entry entry
                        :chain-work (+ base-work h)
                        :status :valid)))
        (when chain-state
          (bitcoin-lisp.storage:add-block-index-entry chain-state new-entry))
        (setf entry new-entry)))
    entry))

;;; Fork point detection tests

(test find-fork-point-same-chain
  "Fork point of two entries on the same chain is the earlier one."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         (block2 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 2) :height 2 :prev-entry block1 :chain-work 2 :status :valid)))
    (let ((fork (bitcoin-lisp.validation:find-fork-point block2 block1)))
      (is (not (null fork)))
      (is (= 1 (bitcoin-lisp.storage:block-index-entry-height fork))))))

(test find-fork-point-diverging-chains
  "Fork point of two diverging chains is the common ancestor."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         ;; Chain A: genesis -> 1 -> 2a -> 3a
         (block2a (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 20) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3a (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 30) :height 3 :prev-entry block2a :chain-work 3 :status :valid))
         ;; Chain B: genesis -> 1 -> 2b -> 3b
         (block2b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 21) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 31) :height 3 :prev-entry block2b :chain-work 3 :status :valid)))
    (let ((fork (bitcoin-lisp.validation:find-fork-point block3a block3b)))
      (is (not (null fork)))
      ;; Fork point is block1 (height 1)
      (is (= 1 (bitcoin-lisp.storage:block-index-entry-height fork)))
      (is (equalp (make-reorg-hash 1) (bitcoin-lisp.storage:block-index-entry-hash fork))))))

(test find-fork-point-different-lengths
  "Fork point works when chains have different lengths."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         ;; Short chain: genesis -> 1 -> 2a
         (block2a (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 20) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         ;; Long chain: genesis -> 1 -> 2b -> 3b -> 4b
         (block2b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 21) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 31) :height 3 :prev-entry block2b :chain-work 3 :status :valid))
         (block4b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 41) :height 4 :prev-entry block3b :chain-work 4 :status :valid)))
    (let ((fork (bitcoin-lisp.validation:find-fork-point block2a block4b)))
      (is (= 1 (bitcoin-lisp.storage:block-index-entry-height fork))))))

;;; Collect chain entries tests

(test collect-chain-entries-basic
  "Collect entries from tip back to (not including) fork point."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         (block2 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 2) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 3) :height 3 :prev-entry block2 :chain-work 3 :status :valid)))
    (let ((entries (bitcoin-lisp.validation::collect-chain-entries block3 genesis)))
      ;; collect-chain-entries walks tip→fork, pushes, then nreverses
      ;; Result order: fork-adjacent first, tip last
      (is (= 3 (length entries)))
      ;; Verify all heights are present (order may vary)
      (let ((heights (mapcar #'bitcoin-lisp.storage:block-index-entry-height entries)))
        (is (member 1 heights))
        (is (member 2 heights))
        (is (member 3 heights))))))

;;; UTXO reorg consistency

(test utxo-apply-disconnect-roundtrip
  "Apply then disconnect a block should restore original UTXO state."
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Initial state: one UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 100000 script 50)
    (let ((initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
      ;; Apply block that spends it
      (let* ((coinbase (make-e2e-coinbase-tx))
             (spending (make-e2e-regular-tx :prev-txid prev-txid :prev-index 0 :value 90000))
             (block (make-e2e-block (list coinbase spending))))
        (let ((spent-utxos (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block 51)))
          ;; State changed
          (is (not (= initial-count (bitcoin-lisp.storage:utxo-count utxo-set))))
          ;; Disconnect
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block spent-utxos)
          ;; State restored
          (is (= initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
          ;; Original UTXO is back
          (is (bitcoin-lisp.storage:utxo-exists-p utxo-set prev-txid 0))
          (let ((entry (bitcoin-lisp.storage:get-utxo utxo-set prev-txid 0)))
            (is (= 100000 (bitcoin-lisp.storage:utxo-entry-value entry)))))))))

(test utxo-multi-block-disconnect
  "Disconnecting multiple blocks in reverse restores the original state."
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xE1))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Initial UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 200000 script 10)
    (let ((initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
      ;; Block 1: spends txid1
      (let* ((cb1 (make-e2e-coinbase-tx :height 11))
             (tx1 (make-e2e-regular-tx :prev-txid txid1 :prev-index 0 :value 190000))
             (block1 (make-e2e-block (list cb1 tx1)))
             (spent1 (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block1 11)))
        ;; Block 2: spends block1's coinbase
        (let* ((cb1-txid (bitcoin-lisp.serialization:transaction-hash cb1))
               (cb2 (make-e2e-coinbase-tx :height 12))
               (tx2 (make-e2e-regular-tx :prev-txid cb1-txid :prev-index 0 :value 4999000000))
               (block2 (make-e2e-block (list cb2 tx2)))
               (spent2 (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block2 12)))
          ;; Disconnect block2 then block1
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block2 spent2)
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block1 spent1)
          ;; Original state restored
          (is (= initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
          (is (bitcoin-lisp.storage:utxo-exists-p utxo-set txid1 0)))))))
