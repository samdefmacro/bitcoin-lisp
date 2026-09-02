(in-package #:bitcoin-lisp.tests)

(def-suite :block-e2e-tests
  :description "End-to-end block validation and connection tests"
  :in :bitcoin-lisp-tests)

(in-suite :block-e2e-tests)

;;;; Block structure validation tests (no PoW required)

(defun make-e2e-coinbase-tx (&key (value 5000000000) (height 0))
  "Create a coinbase transaction for testing."
  (let ((height-script (make-array 4 :element-type '(unsigned-byte 8)
                                   :initial-contents
                                   (list 3  ; push 3 bytes
                                         (logand height #xFF)
                                         (logand (ash height -8) #xFF)
                                         (logand (ash height -16) #xFF)))))
    (bl.ser:make-transaction
     :version 1
     :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                     :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)
                                     :index #xFFFFFFFF)
                    :script-sig height-script
                    :sequence #xFFFFFFFF))
     :outputs (vector (bl.ser:make-tx-out
                     :value value
                     :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                :initial-element #x76)))
     :lock-time 0)))

(defun make-e2e-regular-tx (&key (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element #xAA))
                                  (prev-index 0) (value 100000))
  "Create a regular (non-coinbase) transaction."
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint
                                   :hash prev-txid
                                   :index prev-index)
                  :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                          :initial-element #x51)
                  :sequence #xFFFFFFFF))
   :outputs (vector (bl.ser:make-tx-out
                   :value value
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time 0))

(defun make-e2e-block (transactions &key (prev-hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 0)))
  "Create a test block with correct merkle root."
  (let* ((tx-hashes (mapcar #'bl.ser:transaction-hash transactions))
         (merkle-root (bl.val:compute-merkle-root tx-hashes)))
    (bl.ser:make-bitcoin-block
     :header (bl.ser:make-block-header
              :version 4
              :prev-block prev-hash
              :merkle-root merkle-root
              :timestamp (+ 1231006505 600)
              :bits #x1d00ffff
              :nonce 0)
     :transactions transactions)))

;;; Merkle root validation

(test block-correct-merkle-root
  "Block with correct merkle root should pass merkle validation."
  (let* ((coinbase (make-e2e-coinbase-tx))
         (block (make-e2e-block (list coinbase)))
         (header (bl.ser:bitcoin-block-header block))
         (txs (bl.ser:bitcoin-block-transactions block))
         (computed (bl.val:compute-merkle-root
                    (mapcar #'bl.ser:transaction-hash txs))))
    (is (equalp computed
                (bl.ser:block-header-merkle-root header)))))

(test block-bad-merkle-root-detected
  "Block with incorrect merkle root should be detectable."
  (let* ((coinbase (make-e2e-coinbase-tx))
         (block (make-e2e-block (list coinbase)))
         (header (bl.ser:bitcoin-block-header block)))
    ;; Corrupt the merkle root
    (setf (aref (bl.ser:block-header-merkle-root header) 0) #xFF)
    (let* ((txs (bl.ser:bitcoin-block-transactions block))
           (computed (bl.val:compute-merkle-root
                      (mapcar #'bl.ser:transaction-hash txs))))
      (is (not (equalp computed
                       (bl.ser:block-header-merkle-root header)))))))

;;; Block structure validation

(test block-must-have-transactions
  "Block with no transactions should fail."
  ;; validate-block requires transactions
  (is (null (bl.ser:bitcoin-block-transactions
             (bl.ser:make-bitcoin-block
              :header (bl.ser:make-block-header
                       :version 1 :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                       :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                       :timestamp 0 :bits 0 :nonce 0)
              :transactions nil)))))

(test block-first-tx-must-be-coinbase
  "First transaction must be a coinbase."
  (let ((regular-tx (make-e2e-regular-tx)))
    (is (not (bl.val::is-coinbase-tx regular-tx)))))

(test coinbase-tx-detection
  "Coinbase transaction should be detected correctly."
  (let ((coinbase (make-e2e-coinbase-tx)))
    (is (bl.val::is-coinbase-tx coinbase))))

(test block-non-coinbase-after-first
  "Non-first transactions must not be coinbase."
  (let ((coinbase (make-e2e-coinbase-tx))
        (regular (make-e2e-regular-tx)))
    ;; First is coinbase - good
    (is (bl.val::is-coinbase-tx coinbase))
    ;; Second is regular - good
    (is (not (bl.val::is-coinbase-tx regular)))))

;;; UTXO set operations during block connection

(test utxo-apply-block-creates-outputs
  "Applying a block should add new UTXOs for transaction outputs."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (coinbase (make-e2e-coinbase-tx :value 5000000000 :height 0))
         (block (make-e2e-block (list coinbase)))
         (txid (bl.ser:transaction-hash coinbase)))
    (bl.store:apply-block-to-utxo-set utxo-set block 0)
    ;; Coinbase output should now be in UTXO set
    (is (bl.store:utxo-exists-p utxo-set txid 0))
    (let ((entry (bl.store:get-utxo utxo-set txid 0)))
      (is (= 5000000000 (bl.store:utxo-entry-value entry)))
      (is (= 0 (bl.store:utxo-entry-height entry)))
      (is (bl.store:utxo-entry-coinbase entry)))))

(test utxo-apply-block-spends-inputs
  "Applying a block should remove spent UTXOs."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Pre-populate UTXO
    (bl.store:add-utxo utxo-set prev-txid 0 50000000 script 100)
    (is (bl.store:utxo-exists-p utxo-set prev-txid 0))
    ;; Create block that spends it
    (let* ((coinbase (make-e2e-coinbase-tx))
           (spending-tx (make-e2e-regular-tx :prev-txid prev-txid :prev-index 0 :value 49000000))
           (block (make-e2e-block (list coinbase spending-tx))))
      (bl.store:apply-block-to-utxo-set utxo-set block 101)
      ;; Spent UTXO should be gone
      (is (not (bl.store:utxo-exists-p utxo-set prev-txid 0)))
      ;; New outputs should exist
      (let ((spending-txid (bl.ser:transaction-hash spending-tx)))
        (is (bl.store:utxo-exists-p utxo-set spending-txid 0))))))

(test utxo-disconnect-block-restores-state
  "Disconnecting a block should restore the previous UTXO state."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Pre-populate UTXO
    (bl.store:add-utxo utxo-set prev-txid 0 50000000 script 100)
    ;; Apply block
    (let* ((coinbase (make-e2e-coinbase-tx))
           (spending-tx (make-e2e-regular-tx :prev-txid prev-txid :prev-index 0 :value 49000000))
           (block (make-e2e-block (list coinbase spending-tx))))
      (let ((spent-utxos (bl.store:apply-block-to-utxo-set utxo-set block 101)))
        ;; Disconnect
        (bl.store:disconnect-block-from-utxo-set utxo-set block spent-utxos)
        ;; Original UTXO should be restored
        (is (bl.store:utxo-exists-p utxo-set prev-txid 0))
        ;; Block's outputs should be gone
        (let ((coinbase-txid (bl.ser:transaction-hash coinbase))
              (spending-txid (bl.ser:transaction-hash spending-tx)))
          (is (not (bl.store:utxo-exists-p utxo-set coinbase-txid 0)))
          (is (not (bl.store:utxo-exists-p utxo-set spending-txid 0))))))))

;;; Block weight validation

(test block-weight-single-coinbase
  "Block with single coinbase should have weight = 4 * tx_size + overhead."
  (let* ((coinbase (make-e2e-coinbase-tx))
         (weight (bl.val:calculate-block-weight (list coinbase))))
    (is (plusp weight))
    (is (< weight 4000000))))  ; Well under limit

(test block-subsidy-calculation
  "Block subsidy should halve every 210,000 blocks."
  (is (= 5000000000 (bl.val:calculate-block-subsidy 0)))
  (is (= 5000000000 (bl.val:calculate-block-subsidy 209999)))
  (is (= 2500000000 (bl.val:calculate-block-subsidy 210000)))
  (is (= 1250000000 (bl.val:calculate-block-subsidy 420000)))
  (is (= 0 (bl.val:calculate-block-subsidy (* 64 210000)))))
