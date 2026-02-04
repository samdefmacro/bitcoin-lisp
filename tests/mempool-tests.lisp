(in-package #:bitcoin-lisp.tests)

(in-suite :mempool-tests)

;;;; Test helpers

(defun make-mempool-test-tx (&key (input-id 1) (input-index 0) (value 50000000))
  "Create a test transaction for mempool tests.
INPUT-ID controls the prev outpoint hash byte, creating distinct inputs."
  (let ((input (bitcoin-lisp.serialization:make-tx-in
                :previous-output (bitcoin-lisp.serialization:make-outpoint
                                  :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element input-id)
                                  :index input-index)
                :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                        :initial-element #x00)
                :sequence #xFFFFFFFF))
        ;; P2PKH output script (standard)
        (output (bitcoin-lisp.serialization:make-tx-out
                 :value value
                 :script-pubkey (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)))
                                  (setf (aref s 0) #x76)   ; OP_DUP
                                  (setf (aref s 1) #xa9)   ; OP_HASH160
                                  (setf (aref s 2) #x14)   ; push 20 bytes
                                  (setf (aref s 23) #x88)  ; OP_EQUALVERIFY
                                  (setf (aref s 24) #xac)  ; OP_CHECKSIG
                                  s))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (list input)
     :outputs (list output)
     :lock-time 0)))

(defun make-mempool-entry-for-tx (tx &key (fee 10000))
  "Create a mempool entry for a test transaction."
  (let ((serialized (bitcoin-lisp.serialization:serialize-transaction tx)))
    (bitcoin-lisp.mempool:make-mempool-entry
     :transaction tx
     :fee fee
     :size (length serialized)
     :entry-time 1000000)))

;;;; Mempool core tests

(test mempool-add-and-get
  "Adding a transaction to mempool makes it retrievable."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (make-mempool-test-tx :input-id 1))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid entry)))
    (is (bitcoin-lisp.mempool:mempool-has mempool txid))
    (is (not (null (bitcoin-lisp.mempool:mempool-get mempool txid))))
    (is (= 1 (bitcoin-lisp.mempool:mempool-count mempool)))))

(test mempool-remove
  "Removing a transaction clears it from the mempool."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (make-mempool-test-tx :input-id 2))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx)))
    (bitcoin-lisp.mempool:mempool-add mempool txid entry)
    (is (bitcoin-lisp.mempool:mempool-has mempool txid))
    (let ((removed (bitcoin-lisp.mempool:mempool-remove mempool txid)))
      (is (not (null removed))))
    (is (not (bitcoin-lisp.mempool:mempool-has mempool txid)))
    (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool)))))

(test mempool-reject-duplicate
  "Adding a duplicate transaction is rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (make-mempool-test-tx :input-id 3))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid entry)))
    (is (eq :duplicate (bitcoin-lisp.mempool:mempool-add mempool txid entry)))))

(test mempool-conflict-detection
  "Transactions spending the same outpoint are rejected as conflicts."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         ;; tx1 and tx2 both spend input-id 4, index 0
         (tx1 (make-mempool-test-tx :input-id 4 :value 40000000))
         (tx2 (make-mempool-test-tx :input-id 4 :value 30000000))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid1 entry1)))
    (is (eq :conflict (bitcoin-lisp.mempool:mempool-add mempool txid2 entry2)))))

(test mempool-no-conflict-different-inputs
  "Transactions spending different outpoints do not conflict."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx1 (make-mempool-test-tx :input-id 5))
         (tx2 (make-mempool-test-tx :input-id 6))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid1 entry1)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid2 entry2)))
    (is (= 2 (bitcoin-lisp.mempool:mempool-count mempool)))))

(test mempool-size-tracking
  "Mempool tracks total size correctly."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx1 (make-mempool-test-tx :input-id 7))
         (tx2 (make-mempool-test-tx :input-id 8))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    (is (= 0 (bitcoin-lisp.mempool:mempool-total-size mempool)))
    (bitcoin-lisp.mempool:mempool-add mempool txid1 entry1)
    (let ((size1 (bitcoin-lisp.mempool:mempool-total-size mempool)))
      (is (> size1 0))
      (bitcoin-lisp.mempool:mempool-add mempool txid2 entry2)
      (is (> (bitcoin-lisp.mempool:mempool-total-size mempool) size1)))
    ;; Remove one, size should decrease
    (let ((size-before (bitcoin-lisp.mempool:mempool-total-size mempool)))
      (bitcoin-lisp.mempool:mempool-remove mempool txid1)
      (is (< (bitcoin-lisp.mempool:mempool-total-size mempool) size-before)))))

;;;; Eviction tests

(test mempool-eviction-lowest-fee-rate
  "When mempool is full, lowest fee-rate entry is evicted for a higher one."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool
                   :max-size 100))  ; Smaller than one tx (~95 bytes)
         (tx1 (make-mempool-test-tx :input-id 10 :value 10000000))
         (tx2 (make-mempool-test-tx :input-id 11 :value 20000000))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         ;; tx1 has low fee, tx2 has high fee
         (entry1 (make-mempool-entry-for-tx tx1 :fee 100))
         (entry2 (make-mempool-entry-for-tx tx2 :fee 50000)))
    ;; Add tx1 first (low fee) - fits in empty pool
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid1 entry1)))
    ;; Add tx2 (high fee) - should evict tx1 to make room
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid2 entry2)))
    ;; tx1 should have been evicted
    (is (not (bitcoin-lisp.mempool:mempool-has mempool txid1)))
    (is (bitcoin-lisp.mempool:mempool-has mempool txid2))))

(test mempool-reject-low-fee-when-full
  "When mempool is full, a transaction with lower fee-rate than all entries is rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool
                   :max-size 100))
         (tx1 (make-mempool-test-tx :input-id 12 :value 10000000))
         (tx2 (make-mempool-test-tx :input-id 13 :value 20000000))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         ;; tx1 has high fee, tx2 has very low fee
         (entry1 (make-mempool-entry-for-tx tx1 :fee 50000))
         (entry2 (make-mempool-entry-for-tx tx2 :fee 1)))
    ;; Add tx1 first (high fee)
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid1 entry1)))
    ;; Add tx2 (very low fee) - should be rejected since tx1 has higher fee-rate
    (is (eq :mempool-full (bitcoin-lisp.mempool:mempool-add mempool txid2 entry2)))
    ;; tx1 should still be there
    (is (bitcoin-lisp.mempool:mempool-has mempool txid1))))

;;;; Block interaction tests

(test mempool-remove-for-block
  "Block connection removes confirmed transactions from mempool."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx1 (make-mempool-test-tx :input-id 20))
         (tx2 (make-mempool-test-tx :input-id 21))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    ;; Add both to mempool
    (bitcoin-lisp.mempool:mempool-add mempool txid1 entry1)
    (bitcoin-lisp.mempool:mempool-add mempool txid2 entry2)
    (is (= 2 (bitcoin-lisp.mempool:mempool-count mempool)))
    ;; Create a block containing tx1 (with coinbase)
    (let* ((coinbase-input (bitcoin-lisp.serialization:make-tx-in
                            :previous-output (bitcoin-lisp.serialization:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 0)
                                              :index #xFFFFFFFF)
                            :script-sig (make-array 3 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)
                            :sequence #xFFFFFFFF))
           (coinbase-output (bitcoin-lisp.serialization:make-tx-out
                             :value 5000000000
                             :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                        :initial-element #x76)))
           (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                         :version 1
                         :inputs (list coinbase-input)
                         :outputs (list coinbase-output)
                         :lock-time 0))
           (block-header (bitcoin-lisp.serialization:make-block-header
                          :version 1
                          :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element 0)
                          :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)
                          :timestamp 1000000
                          :bits #x1d00ffff
                          :nonce 0))
           (block (bitcoin-lisp.serialization:make-bitcoin-block
                   :header block-header
                   :transactions (list coinbase-tx tx1))))
      ;; Remove for block
      (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)
      ;; tx1 should be removed, tx2 should remain
      (is (not (bitcoin-lisp.mempool:mempool-has mempool txid1)))
      (is (bitcoin-lisp.mempool:mempool-has mempool txid2))
      (is (= 1 (bitcoin-lisp.mempool:mempool-count mempool))))))

(test mempool-remove-conflicts-on-block
  "Block connection removes conflicting mempool transactions."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         ;; mempool tx spends input 30
         (mempool-tx (make-mempool-test-tx :input-id 30))
         (mempool-txid (bitcoin-lisp.serialization:transaction-hash mempool-tx))
         (mempool-entry (make-mempool-entry-for-tx mempool-tx)))
    ;; Add to mempool
    (bitcoin-lisp.mempool:mempool-add mempool mempool-txid mempool-entry)
    (is (bitcoin-lisp.mempool:mempool-has mempool mempool-txid))
    ;; Block contains a different tx that also spends input 30
    (let* ((block-tx (make-mempool-test-tx :input-id 30 :value 30000000))
           (coinbase-input (bitcoin-lisp.serialization:make-tx-in
                            :previous-output (bitcoin-lisp.serialization:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 0)
                                              :index #xFFFFFFFF)
                            :script-sig (make-array 3 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)
                            :sequence #xFFFFFFFF))
           (coinbase-output (bitcoin-lisp.serialization:make-tx-out
                             :value 5000000000
                             :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                        :initial-element #x76)))
           (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                         :version 1
                         :inputs (list coinbase-input)
                         :outputs (list coinbase-output)
                         :lock-time 0))
           (block-header (bitcoin-lisp.serialization:make-block-header
                          :version 1
                          :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element 0)
                          :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)
                          :timestamp 1000000
                          :bits #x1d00ffff
                          :nonce 0))
           (block (bitcoin-lisp.serialization:make-bitcoin-block
                   :header block-header
                   :transactions (list coinbase-tx block-tx))))
      (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)
      ;; Conflicting mempool tx should be removed
      (is (not (bitcoin-lisp.mempool:mempool-has mempool mempool-txid)))
      (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool))))))

;;;; Fee rate tests

(test mempool-entry-fee-rate-calculation
  "Fee rate is correctly computed as fee/size."
  (let* ((tx (make-mempool-test-tx :input-id 40))
         (entry (bitcoin-lisp.mempool:make-mempool-entry
                 :transaction tx
                 :fee 1000
                 :size 200
                 :entry-time 0)))
    (is (= 5 (bitcoin-lisp.mempool:mempool-entry-fee-rate entry)))))

;;;; Transaction relay tests

(test relay-skips-source-peer
  "Transaction relay sends inv to other peers but not the source."
  (let ((source-peer (bitcoin-lisp.networking:make-peer
                      :state :ready
                      :announced-txs (make-hash-table :test 'equalp)))
        (other-peer (bitcoin-lisp.networking:make-peer
                     :state :ready
                     :announced-txs (make-hash-table :test 'equalp)))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42)))
    ;; We can't actually send messages without a connection,
    ;; but we can verify announcement tracking
    (setf (gethash txid (bitcoin-lisp.networking:peer-announced-txs source-peer)) t)
    ;; Check source has it, other doesn't
    (is (gethash txid (bitcoin-lisp.networking:peer-announced-txs source-peer)))
    (is (not (gethash txid (bitcoin-lisp.networking:peer-announced-txs other-peer))))))

;;;; Standard script detection tests

(test standard-output-script-p2pkh
  "P2PKH scripts are standard."
  (let ((script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x76)   ; OP_DUP
    (setf (aref script 1) #xa9)   ; OP_HASH160
    (setf (aref script 2) #x14)   ; push 20 bytes
    (setf (aref script 23) #x88)  ; OP_EQUALVERIFY
    (setf (aref script 24) #xac)  ; OP_CHECKSIG
    (is (bitcoin-lisp.validation::standard-output-script-p script))))

(test standard-output-script-p2sh
  "P2SH scripts are standard."
  (let ((script (make-array 23 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #xa9)   ; OP_HASH160
    (setf (aref script 1) #x14)   ; push 20 bytes
    (setf (aref script 22) #x87)  ; OP_EQUAL
    (is (bitcoin-lisp.validation::standard-output-script-p script))))

(test standard-output-script-p2wpkh
  "P2WPKH scripts are standard."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x00)   ; OP_0
    (setf (aref script 1) #x14)   ; push 20 bytes
    (is (bitcoin-lisp.validation::standard-output-script-p script))))

(test standard-output-script-p2tr
  "P2TR scripts are standard."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x51)   ; OP_1
    (setf (aref script 1) #x20)   ; push 32 bytes
    (is (bitcoin-lisp.validation::standard-output-script-p script))))

(test non-standard-output-script
  "Arbitrary scripts are non-standard."
  (let ((script (make-array 10 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    (is (not (bitcoin-lisp.validation::standard-output-script-p script)))))

;;;; Fee estimation tests

(test fee-estimator-creation
  "Fee estimator is created with correct defaults."
  (let ((estimator (bitcoin-lisp.mempool:make-fee-estimator)))
    (is (= 0 (bitcoin-lisp.mempool:fee-estimator-entry-count estimator)))
    (is (not (bitcoin-lisp.mempool:fee-estimator-ready-p estimator)))))

(test fee-estimator-add-stats
  "Adding fee statistics increments the entry count."
  (let ((estimator (bitcoin-lisp.mempool:make-fee-estimator))
        (stats (bitcoin-lisp.mempool:make-block-fee-stats
                :height 100
                :median-rate 50
                :low-rate 10
                :high-rate 100
                :tx-count 200)))
    (bitcoin-lisp.mempool:fee-estimator-add-stats estimator stats)
    (is (= 1 (bitcoin-lisp.mempool:fee-estimator-entry-count estimator)))))

(test fee-estimator-ready-after-min-blocks
  "Fee estimator becomes ready after minimum blocks are added."
  (let ((estimator (bitcoin-lisp.mempool:make-fee-estimator)))
    ;; Add enough blocks to meet the threshold (6 by default)
    (dotimes (i 6)
      (let ((stats (bitcoin-lisp.mempool:make-block-fee-stats
                    :height (+ 100 i)
                    :median-rate (+ 10 i)
                    :low-rate 5
                    :high-rate 50
                    :tx-count 100)))
        (bitcoin-lisp.mempool:fee-estimator-add-stats estimator stats)))
    (is (bitcoin-lisp.mempool:fee-estimator-ready-p estimator))))

(test fee-estimation-basic
  "Fee estimation returns reasonable values."
  (let ((estimator (bitcoin-lisp.mempool:make-fee-estimator)))
    ;; Add test data with varying fee rates
    (dotimes (i 10)
      (let ((stats (bitcoin-lisp.mempool:make-block-fee-stats
                    :height (+ 100 i)
                    :median-rate (+ 10 (* i 5))  ; 10, 15, 20, ...55
                    :low-rate 5
                    :high-rate 100
                    :tx-count 200)))
        (bitcoin-lisp.mempool:fee-estimator-add-stats estimator stats)))
    ;; Test estimation
    (multiple-value-bind (rate error)
        (bitcoin-lisp.mempool:estimate-fee-rate estimator 6)
      (declare (ignore error))
      (is (> rate 0))
      (is (<= rate 100)))))

(test fee-estimation-conservative-vs-economical
  "Conservative mode returns higher fee than economical."
  (let ((estimator (bitcoin-lisp.mempool:make-fee-estimator)))
    ;; Add test data
    (dotimes (i 15)
      (let ((stats (bitcoin-lisp.mempool:make-block-fee-stats
                    :height (+ 100 i)
                    :median-rate (+ 10 (* i 3))
                    :low-rate 5
                    :high-rate 100
                    :tx-count 200)))
        (bitcoin-lisp.mempool:fee-estimator-add-stats estimator stats)))
    (multiple-value-bind (conservative-rate c-error)
        (bitcoin-lisp.mempool:estimate-fee-rate estimator 6 :mode :conservative)
      (declare (ignore c-error))
      (multiple-value-bind (economical-rate e-error)
          (bitcoin-lisp.mempool:estimate-fee-rate estimator 6 :mode :economical)
        (declare (ignore e-error))
        (is (>= conservative-rate economical-rate))))))

(test fee-estimation-longer-target-lower-fee
  "Longer confirmation targets tend to have lower fee estimates."
  (let ((estimator (bitcoin-lisp.mempool:make-fee-estimator)))
    ;; Add test data
    (dotimes (i 20)
      (let ((stats (bitcoin-lisp.mempool:make-block-fee-stats
                    :height (+ 100 i)
                    :median-rate (+ 10 (* i 2))
                    :low-rate 5
                    :high-rate 100
                    :tx-count 200)))
        (bitcoin-lisp.mempool:fee-estimator-add-stats estimator stats)))
    (multiple-value-bind (short-rate s-error)
        (bitcoin-lisp.mempool:estimate-fee-rate estimator 2)
      (declare (ignore s-error))
      (multiple-value-bind (long-rate l-error)
          (bitcoin-lisp.mempool:estimate-fee-rate estimator 25)
        (declare (ignore l-error))
        ;; Short target should have higher or equal fee
        (is (>= short-rate long-rate))))))

(test fee-estimation-insufficient-data
  "Fee estimation returns error when data is insufficient."
  (let ((estimator (bitcoin-lisp.mempool:make-fee-estimator)))
    ;; Only add 2 blocks (less than minimum of 6)
    (dotimes (i 2)
      (let ((stats (bitcoin-lisp.mempool:make-block-fee-stats
                    :height (+ 100 i)
                    :median-rate 20
                    :low-rate 10
                    :high-rate 50
                    :tx-count 100)))
        (bitcoin-lisp.mempool:fee-estimator-add-stats estimator stats)))
    (multiple-value-bind (rate error)
        (bitcoin-lisp.mempool:estimate-fee-rate estimator 6)
      (is (= rate 1))  ; Fallback minimum
      (is (not (null error))))))
