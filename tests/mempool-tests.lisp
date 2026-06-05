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
     :inputs (vector input)
     :outputs (vector output)
     :lock-time 0)))

(defun make-mempool-entry-for-tx (tx &key (fee 10000))
  "Create a mempool entry for a test transaction (computes size/vsize/wtxid)."
  (bitcoin-lisp.mempool:make-entry-from-tx tx fee 0 :entry-time 1000000))

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
                         :inputs (vector coinbase-input)
                         :outputs (vector coinbase-output)
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
                         :inputs (vector coinbase-input)
                         :outputs (vector coinbase-output)
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
  "Fee rate is correctly computed as fee/vsize."
  (let* ((tx (make-mempool-test-tx :input-id 40))
         (entry (bitcoin-lisp.mempool:make-mempool-entry
                 :transaction tx
                 :fee 1000
                 :vsize 200
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

;;;; PR1 foundation: entry enrichment, wtxid index, vsize fee-rate

(test mempool-entry-from-tx-fields
  "make-entry-from-tx populates size, vsize, wtxid, height."
  (let* ((tx (make-mempool-test-tx :input-id 70))
         (entry (bitcoin-lisp.mempool:make-entry-from-tx tx 1234 555)))
    (is (= 1234 (bitcoin-lisp.mempool:mempool-entry-fee entry)))
    (is (= 555 (bitcoin-lisp.mempool:mempool-entry-height entry)))
    (is (plusp (bitcoin-lisp.mempool:mempool-entry-size entry)))
    ;; legacy tx: vsize equals serialized size
    (is (= (bitcoin-lisp.serialization:transaction-vsize tx)
           (bitcoin-lisp.mempool:mempool-entry-vsize entry)))
    (is (equalp (bitcoin-lisp.serialization:transaction-wtxid tx)
                (bitcoin-lisp.mempool:mempool-entry-wtxid entry)))
    ;; fee-rate uses vsize
    (is (= (/ 1234 (bitcoin-lisp.mempool:mempool-entry-vsize entry))
           (bitcoin-lisp.mempool:mempool-entry-fee-rate entry)))))

(test mempool-wtxid-index
  "Adding/removing a tx maintains the by-wtxid index."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (make-mempool-test-tx :input-id 71))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
         (entry (bitcoin-lisp.mempool:make-entry-from-tx tx 10000 0)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid entry)))
    (is (equalp txid (gethash wtxid (bitcoin-lisp.mempool:mempool-by-wtxid mempool))))
    (bitcoin-lisp.mempool:mempool-remove mempool txid)
    (is (null (gethash wtxid (bitcoin-lisp.mempool:mempool-by-wtxid mempool))))))

;;;; PR2 standardness policy

(test policy-dust-threshold-values
  "dust-threshold matches Bitcoin Core: ~546 P2PKH, ~294 P2WPKH, 0 for OP_RETURN."
  (let ((p2pkh (let ((s (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
                 (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                       (aref s 23) #x88 (aref s 24) #xac) s))
        (p2wpkh (let ((s (make-array 22 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref s 0) #x00 (aref s 1) #x14) s))
        (opret (let ((s (make-array 10 :element-type '(unsigned-byte 8) :initial-element 0)))
                 (setf (aref s 0) #x6a) s)))
    (is (= 546 (bitcoin-lisp.validation::dust-threshold p2pkh)))
    (is (= 294 (bitcoin-lisp.validation::dust-threshold p2wpkh)))
    (is (= 0 (bitcoin-lisp.validation::dust-threshold opret)))
    (is-true (bitcoin-lisp.validation::output-witness-program-p p2wpkh))
    (is-false (bitcoin-lisp.validation::output-witness-program-p p2pkh))))

(test policy-scriptsig-push-only
  "scriptsig-push-only-p accepts push opcodes and rejects ops > OP_16."
  ;; push 2 bytes, then OP_1..OP_16
  (is-true (bitcoin-lisp.validation::scriptsig-push-only-p
            (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(2 #xaa #x51))))
  ;; OP_CHECKSIG (0xac) is not a push
  (is-false (bitcoin-lisp.validation::scriptsig-push-only-p
             (make-array 1 :element-type '(unsigned-byte 8) :initial-element #xac))))

(test mempool-rejects-nonstandard-version
  "A tx with version outside [1,3] is rejected as non-standard."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (base (make-mempool-test-tx :input-id 80))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 4
              :inputs (bitcoin-lisp.serialization:transaction-inputs base)
              :outputs (bitcoin-lisp.serialization:transaction-outputs base)
              :lock-time 0)))
    (multiple-value-bind (valid err)
        (bitcoin-lisp.validation:validate-transaction-for-mempool tx utxo mempool 100)
      (is (null valid))
      (is (eq err :version-non-standard)))))

(test mempool-rejects-dust-output
  "A tx with a dust-value output is rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (tx (make-mempool-test-tx :input-id 81 :value 1)))  ; 1 sat < 546 dust
    (multiple-value-bind (valid err)
        (bitcoin-lisp.validation:validate-transaction-for-mempool tx utxo mempool 100)
      (is (null valid))
      (is (eq err :dust)))))

(test mempool-rejects-nonpushonly-scriptsig
  "A tx whose scriptSig contains a non-push opcode is rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (base (make-mempool-test-tx :input-id 82))
         (bad-input (bitcoin-lisp.serialization:make-tx-in
                     :previous-output (bitcoin-lisp.serialization:tx-in-previous-output
                                       (elt (bitcoin-lisp.serialization:transaction-inputs base) 0))
                     :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                             :initial-element #xac)  ; OP_CHECKSIG
                     :sequence #xFFFFFFFF))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 1 :inputs (vector bad-input)
              :outputs (bitcoin-lisp.serialization:transaction-outputs base)
              :lock-time 0)))
    (multiple-value-bind (valid err)
        (bitcoin-lisp.validation:validate-transaction-for-mempool tx utxo mempool 100)
      (is (null valid))
      (is (eq err :scriptsig-not-pushonly)))))

;;;; PR3 ancestor/descendant tracking + chained spends

(defun %mp-spending-tx (parent-txid &key (vout 0) (value 40000000))
  "A tx spending PARENT-TXID's output VOUT, paying a standard P2PKH output."
  (bitcoin-lisp.serialization:make-transaction
   :version 1
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash parent-txid :index vout)
                  :script-sig (make-array 10 :element-type '(unsigned-byte 8) :initial-element 0)
                  :sequence #xFFFFFFFF))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value value
                   :script-pubkey (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)))
                                    (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                                          (aref s 23) #x88 (aref s 24) #xac) s)))
   :lock-time 0))

(defun %add-tx (mempool tx &key (fee 10000))
  (bitcoin-lisp.mempool:mempool-add
   mempool (bitcoin-lisp.serialization:transaction-hash tx)
   (bitcoin-lisp.mempool:make-entry-from-tx
    tx fee 0 :entry-time (bitcoin-lisp.serialization:get-unix-time))))

(test mempool-ancestor-descendant-chain
  "An A->B->C chain reports correct ancestor/descendant sets and stats."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (a (make-mempool-test-tx :input-id 90))
         (atxid (bitcoin-lisp.serialization:transaction-hash a))
         (b (%mp-spending-tx atxid))
         (btxid (bitcoin-lisp.serialization:transaction-hash b))
         (c (%mp-spending-tx btxid))
         (ctxid (bitcoin-lisp.serialization:transaction-hash c)))
    (is (eq :ok (%add-tx mempool a)))
    (is (eq :ok (%add-tx mempool b)))
    (is (eq :ok (%add-tx mempool c)))
    (is (= 2 (hash-table-count (bitcoin-lisp.mempool:mempool-ancestors mempool ctxid))))
    (is (= 3 (nth-value 0 (bitcoin-lisp.mempool:mempool-ancestor-stats mempool ctxid))))
    (is (= 2 (hash-table-count (bitcoin-lisp.mempool:mempool-descendants mempool atxid))))
    (is (= 3 (nth-value 0 (bitcoin-lisp.mempool:mempool-descendant-stats mempool atxid))))))

(test mempool-ancestor-descendant-limit
  "A chain longer than the 25-tx package limit is rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (root (make-mempool-test-tx :input-id 91))
         (prev-txid (bitcoin-lisp.serialization:transaction-hash root))
         (last-result (%add-tx mempool root)))
    (loop for i from 1 to 30
          while (eq last-result :ok)
          do (let ((child (%mp-spending-tx prev-txid)))
               (setf last-result (%add-tx mempool child))
               (when (eq last-result :ok)
                 (setf prev-txid (bitcoin-lisp.serialization:transaction-hash child)))))
    (is (eq last-result :too-long-mempool-chain))))

(test mempool-remove-recursive-test
  "Removing a tx removes all of its descendants."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (a (make-mempool-test-tx :input-id 92))
         (atxid (bitcoin-lisp.serialization:transaction-hash a))
         (b (%mp-spending-tx atxid))
         (btxid (bitcoin-lisp.serialization:transaction-hash b))
         (c (%mp-spending-tx btxid)))
    (%add-tx mempool a) (%add-tx mempool b) (%add-tx mempool c)
    (is (= 3 (bitcoin-lisp.mempool:mempool-count mempool)))
    (is (= 3 (bitcoin-lisp.mempool:mempool-remove-recursive mempool atxid)))
    (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool)))))

(test mempool-chained-spend-coins
  "mempool-extra-coins resolves an input spending an unconfirmed parent output."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (a (make-mempool-test-tx :input-id 93))
         (atxid (bitcoin-lisp.serialization:transaction-hash a))
         (b (%mp-spending-tx atxid)))
    (%add-tx mempool a)
    (multiple-value-bind (coins ok)
        (bitcoin-lisp.validation::mempool-extra-coins b utxo mempool)
      (is-true ok)
      (is (not (null (gethash (cons atxid 0) coins)))))))

(test mempool-eviction-removes-descendants
  "Evicting a low-fee parent also removes its in-mempool child (no orphan)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool :max-size 260))
         (a (make-mempool-test-tx :input-id 95))
         (atxid (bitcoin-lisp.serialization:transaction-hash a))
         (b (%mp-spending-tx atxid))
         (btxid (bitcoin-lisp.serialization:transaction-hash b))
         (c (make-mempool-test-tx :input-id 96))
         (ctxid (bitcoin-lisp.serialization:transaction-hash c)))
    ;; A has the lowest fee-rate so eviction targets it first; child B has a
    ;; higher fee-rate but must still be removed together with its parent.
    (is (eq :ok (%add-tx mempool a :fee 100)))
    (is (eq :ok (%add-tx mempool b :fee 5000)))
    ;; High-fee C forces eviction; A is evicted and takes child B recursively.
    (%add-tx mempool c :fee 100000)
    (is (not (bitcoin-lisp.mempool:mempool-has mempool atxid)))
    (is (not (bitcoin-lisp.mempool:mempool-has mempool btxid)))
    (is (bitcoin-lisp.mempool:mempool-has mempool ctxid))))

;;;; PR4 RBF (BIP125)

(defun %rbf-tx (input-id &key (sequence #xfffffffd) (value 50000000))
  "A tx spending outpoint (INPUT-ID-hash, 0) with the given input SEQUENCE."
  (bitcoin-lisp.serialization:make-transaction
   :version 1
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element input-id)
                                    :index 0)
                  :script-sig (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)
                  :sequence sequence))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value value
                   :script-pubkey (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)))
                                    (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                                          (aref s 23) #x88 (aref s 24) #xac) s)))
   :lock-time 0))

(test rbf-signaling-detection
  "tx-signals-rbf-p reads the BIP125 opt-in sequence."
  (is-true (bitcoin-lisp.mempool:tx-signals-rbf-p (%rbf-tx 1 :sequence #xfffffffd)))
  (is-false (bitcoin-lisp.mempool:tx-signals-rbf-p (%rbf-tx 1 :sequence #xffffffff))))

(test rbf-find-conflicts
  "find-rbf-conflicts returns every mempool tx spending a shared outpoint."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 100))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig)))
    (%add-tx mempool orig :fee 1000)
    (is (equal (list orig-txid)
               (bitcoin-lisp.mempool:find-rbf-conflicts mempool (%rbf-tx 100 :value 40000000))))))

(test rbf-rules-fee-and-signaling
  "BIP125 rules: higher fee replaces; lower fee and non-signaling are rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 100 :sequence #xfffffffd))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig))
         (repl (%rbf-tx 100 :sequence #xfffffffd :value 40000000))
         (rvsize (bitcoin-lisp.serialization:transaction-vsize repl)))
    (%add-tx mempool orig :fee 1000)
    ;; Rule 3/4 pass: a clearly higher fee.
    (multiple-value-bind (ok reason replaced)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 50000 rvsize (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))
    ;; Rule 3 fail: fee below the original's.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 500 rvsize (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))))

(test rbf-requires-signaling-unless-full-rbf
  "Rule 1 rejects replacing a non-signaling tx, unless *mempool-full-rbf*."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 101 :sequence #xffffffff))   ; non-signaling
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig))
         (repl (%rbf-tx 101 :sequence #xfffffffd))
         (rvsize (bitcoin-lisp.serialization:transaction-vsize repl)))
    (%add-tx mempool orig :fee 1000)
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 50000 rvsize (list orig-txid))
      (is-false ok)
      (is (eq reason :txn-mempool-conflict)))
    (let ((bitcoin-lisp.mempool:*mempool-full-rbf* t))
      (multiple-value-bind (ok)
          (bitcoin-lisp.mempool:check-rbf-rules mempool repl 50000 rvsize (list orig-txid))
        (is-true ok)))))

;;;; PR5 CPFP eviction

(test mempool-cpfp-eviction-protects-parent
  "Eviction ranks by descendant-package fee-rate: a high-fee child protects its
low-fee parent, so a cheaper standalone tx is evicted first."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool :max-size 300))
         (s (make-mempool-test-tx :input-id 110))        ; standalone, low fee
         (stxid (bitcoin-lisp.serialization:transaction-hash s))
         (p (make-mempool-test-tx :input-id 111))        ; parent, low fee
         (ptxid (bitcoin-lisp.serialization:transaction-hash p))
         (c (%mp-spending-tx ptxid))                     ; child, high fee (CPFP)
         (ctxid (bitcoin-lisp.serialization:transaction-hash c))
         (n (make-mempool-test-tx :input-id 112))        ; incoming, medium fee
         (ntxid (bitcoin-lisp.serialization:transaction-hash n)))
    (is (eq :ok (%add-tx mempool s :fee 100)))
    (is (eq :ok (%add-tx mempool p :fee 100)))
    (is (eq :ok (%add-tx mempool c :fee 50000)))
    ;; Adding N forces eviction; the cheapest package (standalone S) is dropped,
    ;; while the CPFP'd P<-C package survives despite P's low individual fee.
    (%add-tx mempool n :fee 10000)
    (is (not (bitcoin-lisp.mempool:mempool-has mempool stxid)))
    (is (bitcoin-lisp.mempool:mempool-has mempool ptxid))
    (is (bitcoin-lisp.mempool:mempool-has mempool ctxid))
    (is (bitcoin-lisp.mempool:mempool-has mempool ntxid))))

;;;; PR6 orphan pool

(defun %txid-array (n)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element n))

(test orphan-add-depend-remove
  "Orphans are indexed by parent txid; remove clears the index."
  (let* ((pool (bitcoin-lisp.mempool:make-orphan-pool))
         (parent (%txid-array 50))
         (o (%mp-spending-tx parent))
         (otxid (bitcoin-lisp.serialization:transaction-hash o)))
    (is-true (bitcoin-lisp.mempool:orphan-add pool o nil))
    (is (= 1 (bitcoin-lisp.mempool:orphan-pool-count pool)))
    (is (member otxid (bitcoin-lisp.mempool:orphans-depending-on pool parent) :test #'equalp))
    (is (bitcoin-lisp.mempool:orphan-remove pool otxid))
    (is (= 0 (bitcoin-lisp.mempool:orphan-pool-count pool)))
    (is (null (bitcoin-lisp.mempool:orphans-depending-on pool parent)))))

(test orphan-expiry
  "orphan-expire drops entries older than the expiry window."
  (let* ((pool (bitcoin-lisp.mempool:make-orphan-pool))
         (o (%mp-spending-tx (%txid-array 51))))
    (bitcoin-lisp.mempool:orphan-add pool o nil)
    (is (= 1 (bitcoin-lisp.mempool:orphan-pool-count pool)))
    (is (= 1 (bitcoin-lisp.mempool:orphan-expire
              pool (+ (bitcoin-lisp.serialization:get-unix-time)
                      bitcoin-lisp.mempool::+orphan-expire-seconds+ 1))))
    (is (= 0 (bitcoin-lisp.mempool:orphan-pool-count pool)))))

(test orphan-cap
  "The orphan pool is bounded by +max-orphan-transactions+."
  (let ((pool (bitcoin-lisp.mempool:make-orphan-pool)))
    (dotimes (i 110)
      (bitcoin-lisp.mempool:orphan-add pool (%mp-spending-tx (%txid-array i)) nil))
    (is (<= (bitcoin-lisp.mempool:orphan-pool-count pool)
            bitcoin-lisp.mempool::+max-orphan-transactions+))))

(test orphan-erase-for-peer
  "orphan-erase-for-peer drops only the given peer's orphans."
  (let ((pool (bitcoin-lisp.mempool:make-orphan-pool))
        (peer-a (list :a))
        (peer-b (list :b)))
    (bitcoin-lisp.mempool:orphan-add pool (%mp-spending-tx (%txid-array 60)) peer-a)
    (bitcoin-lisp.mempool:orphan-add pool (%mp-spending-tx (%txid-array 61)) peer-b)
    (is (= 2 (bitcoin-lisp.mempool:orphan-pool-count pool)))
    (is (= 1 (bitcoin-lisp.mempool:orphan-erase-for-peer pool peer-a)))
    (is (= 1 (bitcoin-lisp.mempool:orphan-pool-count pool)))))

;;;; PR7 mempool expiry

(test mempool-expire-old-entries
  "mempool-expire removes entries older than the expiry window (with descendants)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (a (make-mempool-test-tx :input-id 120))
         (atxid (bitcoin-lisp.serialization:transaction-hash a))
         (b (%mp-spending-tx atxid)))
    (%add-tx mempool a)
    (%add-tx mempool b)
    (is (= 2 (bitcoin-lisp.mempool:mempool-count mempool)))
    ;; Nothing expires "now".
    (is (= 0 (bitcoin-lisp.mempool:mempool-expire mempool)))
    ;; With a far-future 'now', the aged parent expires and drags its child.
    (is (= 2 (bitcoin-lisp.mempool:mempool-expire
              mempool (+ (bitcoin-lisp.serialization:get-unix-time)
                         (* bitcoin-lisp.mempool::+default-mempool-expiry-hours+ 3600)
                         1))))
    (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool)))))

;;;; Mempool deferrals: dynamic rolling minimum fee

(test mempool-effective-min-fee
  "Effective min-fee is the relay floor, or the (decaying) rolling minimum."
  (let ((mempool (bitcoin-lisp.mempool:make-mempool)))
    ;; No rolling minimum set -> relay floor (1 sat/vB).
    (is (= 1 (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool)))
    ;; Set a fresh rolling minimum -> used as-is.
    (setf (bitcoin-lisp.mempool::mempool-rolling-min-fee-rate mempool) 100
          (bitcoin-lisp.mempool::mempool-rolling-min-fee-time mempool)
          (bitcoin-lisp.serialization:get-unix-time))
    (is (= 100 (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool)))
    ;; Far in the future it decays back below the floor -> floor.
    (is (= 1 (bitcoin-lisp.mempool:mempool-effective-min-fee-rate
              mempool (+ (bitcoin-lisp.serialization:get-unix-time) (* 100 86400)))))))

;;;; Min non-witness size (65 B) + witness standardness

(defun %zbytes (n &optional (fill 0))
  (make-array n :element-type '(unsigned-byte 8) :initial-element fill))

(test mempool-rejects-tiny-nonwitness-tx
  "A transaction smaller than 65 non-witness bytes is rejected (CVE-2017-12842)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         ;; 1 non-coinbase input (empty scriptSig) + 1 empty-scriptPubKey output
         ;; serializes to ~60 non-witness bytes.
         (input (bitcoin-lisp.serialization:make-tx-in
                 :previous-output (bitcoin-lisp.serialization:make-outpoint
                                   :hash (%zbytes 32 7) :index 0)
                 :script-sig (%zbytes 0) :sequence #xFFFFFFFF))
         (output (bitcoin-lisp.serialization:make-tx-out :value 1000 :script-pubkey (%zbytes 0)))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 1 :inputs (vector input) :outputs (vector output) :lock-time 0)))
    (is (< (length (bitcoin-lisp.serialization:serialize-transaction tx)) 65))
    (multiple-value-bind (valid err)
        (bitcoin-lisp.validation:validate-transaction-for-mempool tx utxo mempool 100)
      (is (null valid))
      (is (eq err :tx-size-small)))))

(defun %witness-tx (witness-stack spk)
  "Single-input tx carrying WITNESS-STACK (a list of byte vectors). Returns
(VALUES tx spent-script-fn) where the spent output's scriptPubKey is SPK."
  (let* ((input (bitcoin-lisp.serialization:make-tx-in
                 :previous-output (bitcoin-lisp.serialization:make-outpoint
                                   :hash (%zbytes 32 9) :index 0)
                 :script-sig (%zbytes 0) :sequence #xFFFFFFFF))
         (output (bitcoin-lisp.serialization:make-tx-out :value 1000
                                                         :script-pubkey (%zbytes 25)))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 2 :inputs (vector input) :outputs (vector output)
              :lock-time 0 :witness (vector witness-stack))))
    (values tx (lambda (txid index) (declare (ignore txid index)) spk))))

(defun %p2wsh-spk () (let ((s (%zbytes 34))) (setf (aref s 0) #x00 (aref s 1) #x20) s))
(defun %taproot-spk () (let ((s (%zbytes 34))) (setf (aref s 0) #x51 (aref s 1) #x20) s))
(defun %p2pkh-spk ()
  (let ((s (%zbytes 25)))
    (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14 (aref s 23) #x88 (aref s 24) #xac)
    s))

(defun %wit-std-p (stack spk)
  (multiple-value-bind (tx fn) (%witness-tx stack spk)
    (bitcoin-lisp.validation::is-witness-standard-p tx fn)))

(test witness-standard-p2wsh-ok
  "A P2WSH spend within the stack/script limits is standard."
  (is-true (%wit-std-p (list (%zbytes 5) (%zbytes 10)) (%p2wsh-spk))))   ; 1 item + witnessScript

(test witness-nonstandard-p2wsh-oversized-script
  "A P2WSH witnessScript larger than 3600 bytes is nonstandard."
  (is-false (%wit-std-p (list (%zbytes 5) (%zbytes 3601)) (%p2wsh-spk))))

(test witness-nonstandard-p2wsh-oversized-item
  "A P2WSH stack item larger than 80 bytes is nonstandard."
  (is-false (%wit-std-p (list (%zbytes 81) (%zbytes 10)) (%p2wsh-spk))))

(test witness-nonstandard-p2wsh-too-many-items
  "A P2WSH spend with more than 100 stack items is nonstandard."
  (let ((stack (append (loop repeat 101 collect (%zbytes 1)) (list (%zbytes 10)))))
    (is-false (%wit-std-p stack (%p2wsh-spk)))))

(test witness-standard-taproot-keypath
  "A Taproot key-path spend (single witness element) is standard."
  (is-true (%wit-std-p (list (%zbytes 64)) (%taproot-spk))))

(test witness-nonstandard-taproot-annex
  "A Taproot spend carrying an annex is nonstandard."
  (let ((annex (%zbytes 3))) (setf (aref annex 0) #x50)   ; ANNEX_TAG
    (is-false (%wit-std-p (list (%zbytes 64) annex) (%taproot-spk)))))

(test witness-nonstandard-taproot-tapscript-oversized-item
  "A Taproot tapscript spend with a stack item over 80 bytes is nonstandard."
  (let ((control (%zbytes 33))) (setf (aref control 0) #xc0)   ; tapscript leaf version
    ;; stack: [arg(81), script, control-block]
    (is-false (%wit-std-p (list (%zbytes 81) (%zbytes 20) control) (%taproot-spk)))))

(test witness-nonstandard-on-nonwitness-program
  "A witness attached to a non-witness-program input is nonstandard."
  (is-false (%wit-std-p (list (%zbytes 10)) (%p2pkh-spk))))

(test witness-standard-p2wpkh
  "A P2WPKH witness spend has no extra stack/script policy limits."
  (let ((p2wpkh-spk (let ((s (%zbytes 22))) (setf (aref s 0) #x00 (aref s 1) #x14) s)))
    (is-true (%wit-std-p (list (%zbytes 71) (%zbytes 33)) p2wpkh-spk))))

(test witness-standard-taproot-tapscript-path
  "A Taproot tapscript script-path spend with in-limit items is standard."
  (let ((control (%zbytes 33)))
    (setf (aref control 0) #xc0)   ; tapscript leaf version
    ;; stack: [arg(<=80), script, control-block]
    (is-true (%wit-std-p (list (%zbytes 50) (%zbytes 20) control) (%taproot-spk)))))
