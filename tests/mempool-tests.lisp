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

;;;; Shared acceptance tail (accept-validated-tx)
;;;;
;;;; The evict-replaced + build-entry + mempool-add sequence used to be
;;;; inlined at six call sites (peer tx handler, orphan cascade,
;;;; sendrawtransaction, mempool.dat reload, reorg re-add, submitpackage)
;;;; and had started to drift. accept-validated-tx is the single tail.

(test accept-validated-tx-evicts-replaced-and-adds
  "Accepting with :replaced evicts the RBF'd tx and adds the new one,
returning (values :ok entry)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (old-tx (make-mempool-test-tx :input-id 1))
         (old-txid (bitcoin-lisp.serialization:transaction-hash old-tx))
         (new-tx (make-mempool-test-tx :input-id 2))
         (new-txid (bitcoin-lisp.serialization:transaction-hash new-tx)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                 mempool old-txid (make-mempool-entry-for-tx old-tx))))
    (multiple-value-bind (result entry)
        (bitcoin-lisp.mempool:accept-validated-tx
         mempool new-txid new-tx 15000 0
         :entry-time 1000001 :replaced (list old-txid))
      (is (eq :ok result))
      (is (= 15000 (bitcoin-lisp.mempool:mempool-entry-fee entry)))
      (is (= 1000001 (bitcoin-lisp.mempool:mempool-entry-entry-time entry))))
    (is (null (bitcoin-lisp.mempool:mempool-get mempool old-txid)))
    (is (bitcoin-lisp.mempool:mempool-get mempool new-txid))))

(test accept-validated-tx-nil-fee-defaults-to-zero
  "A NIL fee is folded to 0 rather than poisoning entry arithmetic."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (make-mempool-test-tx :input-id 3))
         (txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (multiple-value-bind (result entry)
        (bitcoin-lisp.mempool:accept-validated-tx mempool txid tx nil 0)
      (is (eq :ok result))
      (is (= 0 (bitcoin-lisp.mempool:mempool-entry-fee entry))))))

;;;; Prioritisation tests (Core PrioritiseTransaction / mapDeltas)

(test mempool-prioritise-in-mempool
  "Prioritising an in-mempool tx adjusts its modified fee and feerate scoring,
deltas stack, and a net-zero delta is dropped from the map."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (make-mempool-test-tx :input-id 1))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx :fee 10000)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid entry)))
    (is (= 10000 (bitcoin-lisp.mempool:mempool-entry-modified-fee entry)))
    (bitcoin-lisp.mempool:mempool-prioritise mempool txid 5000)
    (is (= 15000 (bitcoin-lisp.mempool:mempool-entry-modified-fee entry)))
    (is (= 10000 (bitcoin-lisp.mempool:mempool-entry-fee entry)))   ; real fee untouched
    (is (= (/ 15000 (bitcoin-lisp.mempool:mempool-entry-vsize entry))
           (bitcoin-lisp.mempool:mempool-entry-fee-rate entry)))
    ;; Stacking: -5000 brings the accumulated delta to zero -> map entry dropped.
    (bitcoin-lisp.mempool:mempool-prioritise mempool txid -5000)
    (is (= 10000 (bitcoin-lisp.mempool:mempool-entry-modified-fee entry)))
    (is (zerop (hash-table-count (bitcoin-lisp.mempool:mempool-deltas mempool))))))

(test mempool-prioritise-before-acceptance
  "A delta set before the tx exists applies when the tx is later accepted
(Core: ATMP ApplyDelta), and mining for a confirmed tx clears its delta."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (make-mempool-test-tx :input-id 2))
         (txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (bitcoin-lisp.mempool:mempool-prioritise mempool txid 7000)
    (let ((entry (make-mempool-entry-for-tx tx :fee 1000)))
      (is (eq :ok (bitcoin-lisp.mempool:mempool-add mempool txid entry)))
      (is (= 8000 (bitcoin-lisp.mempool:mempool-entry-modified-fee entry))))
    ;; Mined in a block -> delta cleared (Core ClearPrioritisation).
    (let ((block (bitcoin-lisp.serialization:make-bitcoin-block
                  :header (bitcoin-lisp.serialization:make-block-header
                           :version 1
                           :prev-block (make-array 32 :element-type '(unsigned-byte 8))
                           :merkle-root (make-array 32 :element-type '(unsigned-byte 8))
                           :timestamp 0 :bits 0 :nonce 0)
                  :transactions (list tx))))
      (bitcoin-lisp.mempool:mempool-remove-for-block mempool block))
    (is (null (bitcoin-lisp.mempool:mempool-get mempool txid)))
    (is (zerop (hash-table-count (bitcoin-lisp.mempool:mempool-deltas mempool))))))

;;;; Persistence tests (mempool.dat)

(test mempool-dat-round-trip
  "save-mempool-file/read-mempool-file round-trips entries (parents first),
per-entry deltas, and residual deltas; corrupt files read as not-ok."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (parent (make-mempool-test-tx :input-id 60))
         (parent-txid (bitcoin-lisp.serialization:transaction-hash parent))
         (child (%mp-spending-tx parent-txid))
         (child-txid (bitcoin-lisp.serialization:transaction-hash child))
         (absent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 99))
         (path (merge-pathnames (format nil "mempool-test-~D.dat" (get-universal-time))
                                (uiop:temporary-directory))))
    ;; Child added after parent; insertion order child-last but save must be
    ;; parents-first regardless of table order.
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                 mempool parent-txid (make-mempool-entry-for-tx parent :fee 5000))))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                 mempool child-txid (make-mempool-entry-for-tx child :fee 7000))))
    (bitcoin-lisp.mempool:mempool-prioritise mempool child-txid 1234)
    (bitcoin-lisp.mempool:mempool-prioritise mempool absent-txid -555)
    (unwind-protect
         (progn
           (is (= 2 (bitcoin-lisp.mempool:save-mempool-file mempool path)))
           (multiple-value-bind (entries residual ok)
               (bitcoin-lisp.mempool:read-mempool-file path)
             (is-true ok)
             (is (= 2 (length entries)))
             ;; Parents-first: parent tx is the first record.
             (destructuring-bind (tx1 time1 delta1) (first entries)
               (is (equalp parent-txid (bitcoin-lisp.serialization:transaction-hash tx1)))
               (is (= 1000000 time1))
               (is (zerop delta1)))
             (destructuring-bind (tx2 time2 delta2) (second entries)
               (declare (ignore time2))
               (is (equalp child-txid (bitcoin-lisp.serialization:transaction-hash tx2)))
               (is (= 1234 delta2)))
             ;; Residual: only the absent txid's delta.
             (is (= 1 (length residual)))
             (is (equalp absent-txid (car (first residual))))
             (is (= -555 (cdr (first residual)))))
           ;; Corrupt the file -> not ok.
           (with-open-file (out path :direction :output :if-exists :overwrite
                                     :element-type '(unsigned-byte 8))
             (file-position out 20)
             (write-byte 0 out)
             (write-byte 255 out))
           (is-false (nth-value 2 (bitcoin-lisp.mempool:read-mempool-file path))))
      (ignore-errors (delete-file path)))))

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
                 :modified-fee 1000
                 :vsize 200
                 :entry-time 0)))
    (is (= 5 (bitcoin-lisp.mempool:mempool-entry-fee-rate entry)))))

;;;; Transaction relay tests

(test relay-skips-source-peer
  "Transaction relay sends inv to other peers but not the source."
  (let ((source-peer (bitcoin-lisp.networking:make-peer :state :ready))
        (other-peer (bitcoin-lisp.networking:make-peer :state :ready))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42)))
    ;; We can't actually send messages without a connection,
    ;; but we can verify announcement tracking (now a bounded set)
    (bitcoin-lisp:add-recent-reject
     (bitcoin-lisp.networking:peer-announced-txs source-peer) txid)
    ;; Check source has it, other doesn't
    (is (bitcoin-lisp:recent-reject-p
         (bitcoin-lisp.networking:peer-announced-txs source-peer) txid))
    (is (not (bitcoin-lisp:recent-reject-p
              (bitcoin-lisp.networking:peer-announced-txs other-peer) txid)))))

(test peer-announced-txs-bounded
  "peer-announced-txs is a bounded FIFO set (Core CRollingBloomFilter{50000}
analogue): filling past capacity evicts the oldest entries instead of growing
without bound (the old hash-table leaked per-peer memory forever)."
  (let* ((peer (bitcoin-lisp.networking:make-peer
                :state :ready :announced-txs (bitcoin-lisp:make-rejects-filter 10)))
         (set (bitcoin-lisp.networking:peer-announced-txs peer))
         (ids (loop for i below 15
                    collect (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element i))))
    (dolist (id ids) (bitcoin-lisp:add-recent-reject set id))
    ;; the 5 oldest were evicted; the 10 newest remain
    (is (not (bitcoin-lisp:recent-reject-p set (nth 0 ids))))
    (is (not (bitcoin-lisp:recent-reject-p set (nth 4 ids))))
    (is (bitcoin-lisp:recent-reject-p set (nth 5 ids)))
    (is (bitcoin-lisp:recent-reject-p set (nth 14 ids)))
    (is (= 10 (hash-table-count (bitcoin-lisp::recent-rejects-table set))))))

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

(defun %op-return-script (data-len)
  "An OP_RETURN scriptPubKey carrying DATA-LEN data bytes (OP_RETURN +
1-byte pushdata prefix + data)."
  (let ((s (make-array (+ 2 data-len) :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref s 0) #x6a (aref s 1) data-len)
    s))

(test datacarrier-policy-knobs
  "*accept-datacarrier* gates OP_RETURN standardness; *max-datacarrier-bytes*
sizes it (-datacarrier / -datacarriersize)."
  (let ((ok (%op-return-script 75))      ; 77 bytes total
        (big (%op-return-script 82)))     ; 84 bytes total, over the 83 default
    ;; default: accepted up to the size cap, rejected beyond it
    (is (bitcoin-lisp.validation::standard-output-script-p ok))
    (is (not (bitcoin-lisp.validation::standard-output-script-p big)))
    ;; datacarrier disabled: even a small OP_RETURN is non-standard
    (let ((bitcoin-lisp:*accept-datacarrier* nil))
      (is (not (bitcoin-lisp.validation::standard-output-script-p ok))))
    ;; raised size cap admits the larger script
    (let ((bitcoin-lisp:*max-datacarrier-bytes* 100))
      (is (bitcoin-lisp.validation::standard-output-script-p big)))))

(test bare-multisig-policy-knob
  "Bare multisig is standard by default (DEFAULT_PERMIT_BAREMULTISIG=true) and
non-standard under *permit-bare-multisig* nil (1<=m<=n<=3, 33/65-byte keys)."
  (let* ((k (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2))
         ;; OP_1 <33-key> <33-key> OP_2 OP_CHECKMULTISIG  (1-of-2)
         (ms (concatenate '(vector (unsigned-byte 8))
                          (vector #x51 33) k (vector 33) k (vector #x52 #xae)))
         ;; 1-of-4 exceeds the bare-multisig key cap (n>3) -> never standard
         (ms4 (concatenate '(vector (unsigned-byte 8))
                           (vector #x51 33) k (vector 33) k (vector 33) k (vector 33) k
                           (vector #x54 #xae))))
    ;; standard by default; non-standard only when the knob is disabled
    (is (bitcoin-lisp.validation::standard-output-script-p ms))
    (let ((bitcoin-lisp:*permit-bare-multisig* nil))
      (is (not (bitcoin-lisp.validation::standard-output-script-p ms))))
    (let ((bitcoin-lisp:*permit-bare-multisig* t))
      (is (bitcoin-lisp.validation::standard-output-script-p ms))
      (is (not (bitcoin-lisp.validation::standard-output-script-p ms4)))
      ;; a truncated/garbage multisig is rejected even when permitted
      (is (not (bitcoin-lisp.validation::standard-output-script-p
                (coerce #(#x51 #xae) '(vector (unsigned-byte 8)))))))))

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
  "A tx with version outside [1,3] is rejected as non-standard. Version 3 is now
standard (TRUC/BIP431 enforced) -- see +max-standard-tx-version+."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (base (make-mempool-test-tx :input-id 80)))
    (flet ((rejected-p (ver)
             (let ((tx (bitcoin-lisp.serialization:make-transaction
                        :version ver
                        :inputs (bitcoin-lisp.serialization:transaction-inputs base)
                        :outputs (bitcoin-lisp.serialization:transaction-outputs base)
                        :lock-time 0)))
               (multiple-value-bind (valid err)
                   (bitcoin-lisp.validation:validate-transaction-for-mempool tx utxo mempool 100)
                 (and (null valid) (eq err :version-non-standard))))))
      (is-true (rejected-p 4))
      (is-true (rejected-p 0))
      ;; v3 is no longer rejected on the version check (TRUC governs its topology)
      (is-false (rejected-p 3)))))

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

(defun %mempool-final-fixture (suffix)
  "Chain-state with a genesis + tip entry (both carrying headers so the MTP
walk works) and a UTXO-set. Returns (values state utxo tip-height)."
  (let* ((state (bitcoin-lisp.storage:init-chain-state
                 (merge-pathnames suffix (uiop:temporary-directory))))
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-entry (bitcoin-lisp.storage:make-block-index-entry
                         :hash genesis-hash :height 0 :chain-work 1 :status :valid
                         :header (bitcoin-lisp.serialization:make-block-header
                                  :version 1 :prev-block zeros :merkle-root zeros
                                  :timestamp 1700000000 :bits #x207fffff :nonce 0
                                  :cached-hash genesis-hash)))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (bitcoin-lisp.storage:add-block-index-entry state genesis-entry)
    (bitcoin-lisp.storage:add-block-index-entry
     state (bitcoin-lisp.storage:make-block-index-entry
            :hash tip-hash :height 1 :prev-entry genesis-entry
            :chain-work 3 :status :valid
            :header (bitcoin-lisp.serialization:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp 1700000600 :bits #x207fffff :nonce 0
                     :cached-hash tip-hash)))
    (bitcoin-lisp.storage:update-chain-tip state tip-hash 1)
    (values state utxo 1)))

(test mempool-rejects-non-final-tx
  "With chain-state supplied, a tx whose height-based locktime is beyond the
next block and whose sequences are non-final is rejected :non-final (Core
PreChecks). Without chain-state the finality check is skipped."
  (let ((bitcoin-lisp:*network* :regtest))
    (multiple-value-bind (state utxo tip-height)
        (%mempool-final-fixture "test-mp-final/")
      (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
             (base (make-mempool-test-tx :input-id 90))
             (prevout (bitcoin-lisp.serialization:tx-in-previous-output
                       (elt (bitcoin-lisp.serialization:transaction-inputs base) 0)))
             ;; non-final sequence + far-future height-based locktime
             (tx (bitcoin-lisp.serialization:make-transaction
                  :version 1
                  :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                   :previous-output prevout
                                   :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                                           :initial-element 0)
                                   :sequence 0))
                  :outputs (bitcoin-lisp.serialization:transaction-outputs base)
                  :lock-time 9999999)))
        ;; Resolve the input so validation reaches the finality check.
        (bitcoin-lisp.storage:add-utxo
         utxo (bitcoin-lisp.serialization:outpoint-hash prevout)
         (bitcoin-lisp.serialization:outpoint-index prevout)
         100000000
         (bitcoin-lisp.serialization:tx-out-script-pubkey
          (elt (bitcoin-lisp.serialization:transaction-outputs base) 0))
         0)
        ;; With chain-state: rejected as non-final.
        (multiple-value-bind (valid err)
            (bitcoin-lisp.validation:validate-transaction-for-mempool
             tx utxo mempool tip-height :chain-state state)
          (is (null valid))
          (is (eq err :non-final)))
        ;; Without chain-state: the finality check is skipped (so it is not the
        ;; reason for any rejection).
        (multiple-value-bind (valid err)
            (bitcoin-lisp.validation:validate-transaction-for-mempool
             tx utxo mempool tip-height)
          (declare (ignore valid))
          (is (not (eq err :non-final))))))))

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

(defun %add-tx (mempool tx &key (fee 10000) (height 0))
  "Insert TX directly into MEMPOOL as an already-accepted entry (bypassing
validation). The shared direct-add helper of the whole test package."
  (bitcoin-lisp.mempool:mempool-add
   mempool (bitcoin-lisp.serialization:transaction-hash tx)
   (bitcoin-lisp.mempool:make-entry-from-tx
    tx fee height :entry-time (bitcoin-lisp.serialization:get-unix-time))))

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

(test mempool-cluster-count-limit
  "Acceptance is bounded by the 64-tx cluster limit (cluster mempool P6): a
64-long chain — far past the old 25-ancestor limit, which is RPC-reporting-
only now — is accepted in full, and the 65th link is rejected with
:too-large-cluster, leaving the graph non-oversized (the staged addition is
rolled back)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (root (make-mempool-test-tx :input-id 91))
         (prev-txid (bitcoin-lisp.serialization:transaction-hash root))
         (last-result (%add-tx mempool root))
         (accepted 1))
    (loop for i from 2 to 65
          while (eq last-result :ok)
          do (let ((child (%mp-spending-tx prev-txid)))
               (setf last-result (%add-tx mempool child))
               (when (eq last-result :ok)
                 (incf accepted)
                 (setf prev-txid (bitcoin-lisp.serialization:transaction-hash child)))))
    (is (= 64 accepted))
    (is (eq last-result :too-large-cluster))
    (is (= 64 (bitcoin-lisp.mempool:mempool-count mempool)))
    (is-false (bitcoin-lisp.mempool:txgraph-oversized-p
               (bitcoin-lisp.mempool:mempool-graph mempool)))))

(test mempool-cluster-size-limit
  "Acceptance is bounded by the cluster vsize limit: a chain whose total
vsize would exceed *cluster-size-limit* is rejected at the tx that crosses
it, and a single tx alone over the limit is rejected outright. (The limit is
bound low here; the graph's limits are fixed at make-mempool time.)"
  (let* ((mempool (let ((bitcoin-lisp.mempool:*cluster-size-limit* 200))
                    (bitcoin-lisp.mempool:make-mempool)))
         (a (make-mempool-test-tx :input-id 97))
         (atxid (bitcoin-lisp.serialization:transaction-hash a))
         (b (%mp-spending-tx atxid))
         (btxid (bitcoin-lisp.serialization:transaction-hash b))
         (c (%mp-spending-tx btxid)))
    ;; Each test tx is 95 vB: A (95) and B (190 total) fit under 200,
    ;; C (285 total) does not.
    (is (eq :ok (%add-tx mempool a)))
    (is (eq :ok (%add-tx mempool b)))
    (is (eq :too-large-cluster (%add-tx mempool c)))
    (is (= 2 (bitcoin-lisp.mempool:mempool-count mempool)))
    (is-false (bitcoin-lisp.mempool:txgraph-oversized-p
               (bitcoin-lisp.mempool:mempool-graph mempool))))
  ;; A single transaction larger than the cluster size limit.
  (let ((mempool (let ((bitcoin-lisp.mempool:*cluster-size-limit* 50))
                   (bitcoin-lisp.mempool:make-mempool))))
    (is (eq :too-large-cluster
            (%add-tx mempool (make-mempool-test-tx :input-id 98))))
    (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool)))))

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
  "Evicting a low-fee parent also removes its in-mempool child (no orphan):
the CPFP pair shares one chunk, evicted as a unit."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool :max-size 260))
         (a (make-mempool-test-tx :input-id 95))
         (atxid (bitcoin-lisp.serialization:transaction-hash a))
         (b (%mp-spending-tx atxid))
         (btxid (bitcoin-lisp.serialization:transaction-hash b))
         (c (make-mempool-test-tx :input-id 96))
         (ctxid (bitcoin-lisp.serialization:transaction-hash c)))
    ;; B fee-bumps A, so [A B] forms one chunk whose feerate is still below
    ;; C's — it is the worst chunk, evicted whole.
    (is (eq :ok (%add-tx mempool a :fee 100)))
    (is (eq :ok (%add-tx mempool b :fee 5000)))
    ;; High-fee C forces eviction; the [A B] chunk goes together.
    (%add-tx mempool c :fee 100000)
    (is (not (bitcoin-lisp.mempool:mempool-has mempool atxid)))
    (is (not (bitcoin-lisp.mempool:mempool-has mempool btxid)))
    (is (bitcoin-lisp.mempool:mempool-has mempool ctxid))))

(test mempool-eviction-worst-chunk-cpfp-protection
  "TrimToSize evicts the globally WORST CHUNK: a standalone middling tx goes
before a CPFP pair whose merged chunk feerate beats it (the high-fee child
protects its low-fee parent), and the rolling minimum fee rises to exactly
the evicted chunk's feerate plus the incremental relay fee (Core TrimToSize
+ trackPackageRemoved)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool :max-size 260))
         (p (make-mempool-test-tx :input-id 101))
         (ptxid (bitcoin-lisp.serialization:transaction-hash p))
         (c (%mp-spending-tx ptxid))
         (ctxid (bitcoin-lisp.serialization:transaction-hash c))
         (m (make-mempool-test-tx :input-id 102))
         (mtxid (bitcoin-lisp.serialization:transaction-hash m))
         (m-vsize (bitcoin-lisp.serialization:transaction-vsize m)))
    ;; P alone (100 sat / 95 vB) is far worse than M (2000 sat / 95 vB), but
    ;; child C (20000 sat) absorbs P into one chunk at ~105 sat/vB - so the
    ;; worst chunk is [M], not [P ...].
    (is (eq :ok (%add-tx mempool p :fee 100)))
    (is (eq :ok (%add-tx mempool m :fee 2000)))
    (is (eq :ok (%add-tx mempool c :fee 20000)))     ; triggers the trim
    (is (not (bitcoin-lisp.mempool:mempool-has mempool mtxid)))
    (is (bitcoin-lisp.mempool:mempool-has mempool ptxid))
    (is (bitcoin-lisp.mempool:mempool-has mempool ctxid))
    ;; Rolling minimum fee: evicted chunk feerate (sat/kvB, truncated) +
    ;; incremental relay fee (100 sat/kvB).
    (is (= (+ (truncate (* 2000 1000) m-vsize) 100)
           (bitcoin-lisp.mempool::mempool-rolling-min-fee-rate mempool)))))

(test mempool-full-self-eviction-bumps-rolling-fee
  "A newcomer whose own chunk is the worst evicts itself (Core: add, trim,
then \"mempool full\" when the tx is gone) - and still bumps the rolling
minimum fee past its feerate, so an equal-feerate retry cannot loop."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool :max-size 100))
         (rich (make-mempool-test-tx :input-id 103))
         (poor (make-mempool-test-tx :input-id 104))
         (poor-vsize (bitcoin-lisp.serialization:transaction-vsize poor)))
    (is (eq :ok (%add-tx mempool rich :fee 50000)))
    (is (eq :mempool-full (%add-tx mempool poor :fee 30)))
    (is (bitcoin-lisp.mempool:mempool-has
         mempool (bitcoin-lisp.serialization:transaction-hash rich)))
    (is (not (bitcoin-lisp.mempool:mempool-has
              mempool (bitcoin-lisp.serialization:transaction-hash poor))))
    (is (= (+ (truncate (* 30 1000) poor-vsize) 100)
           (bitcoin-lisp.mempool::mempool-rolling-min-fee-rate mempool)))))

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

(test rbf-full-rbf-unconditional
  "Cluster mempool drops BIP125 rule 1: a NON-signaling mempool tx is
replaceable regardless of *mempool-full-rbf* (Core validation.cpp:490 — the
accept path never consults SignalsOptInRBF; IsRBFOptIn survives for RPC only)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 101 :sequence #xffffffff))   ; non-signaling (final)
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig))
         (repl (%rbf-tx 101 :sequence #xffffffff :value 40000000))
         (rvsize (bitcoin-lisp.serialization:transaction-vsize repl)))
    (%add-tx mempool orig :fee 1000)
    ;; Replacing the non-signaling original succeeds on a strictly better fee,
    ;; with *mempool-full-rbf* NIL (the default).
    (is (null bitcoin-lisp.mempool:*mempool-full-rbf*))
    (multiple-value-bind (ok reason replaced)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 50000 rvsize (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))))

;;;; Diagram RBF (cluster mempool P7 — Core policy/rbf.cpp ImprovesFeerateDiagram
;;;; + ReplacementChecks, ported from src/test/rbf_tests.cpp). check-rbf-rules
;;;; now: drops rules 1/2 (full-RBF unconditional), keeps rules 3/4, redefines
;;;; rule 5 (100-cluster + 500-tx gather caps), and requires the replacement to
;;;; strictly improve the mempool feerate diagram.

(defun %rbf-chain (mempool root-id length &key (fee 10000))
  "Add a chain of LENGTH txs rooted at a fresh %rbf-tx(ROOT-ID) into MEMPOOL
(each tx spends its predecessor's output 0). Returns the root txid."
  (let* ((root (%rbf-tx root-id))
         (root-txid (bitcoin-lisp.serialization:transaction-hash root))
         (prev-txid root-txid))
    (%add-tx mempool root :fee fee)
    (loop repeat (1- length)
          for child = (%mp-spending-tx prev-txid)
          for child-txid = (bitcoin-lisp.serialization:transaction-hash child)
          do (%add-tx mempool child :fee fee)
             (setf prev-txid child-txid))
    root-txid))

(test rbf-diagram-accepts-strict-improvement
  "A replacement paying a strictly higher feerate improves the diagram and is
accepted; the replaced set is the conflict."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 130))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig))
         (repl (%rbf-tx 130 :value 40000000))
         (rvsize (bitcoin-lisp.serialization:transaction-vsize repl)))
    (%add-tx mempool orig :fee 1000)
    (multiple-value-bind (ok reason replaced)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 50000 rvsize (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))))

(test rbf-diagram-rejects-non-improvement
  "Rules 3 and 4 can pass while the diagram does NOT strictly improve: a
replacement paying slightly more total fee but at a far lower feerate (much
larger vsize) is rejected :replacement-failed (Core ImprovesFeerateDiagram
failure, rbf.cpp:136-138)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 131))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig))
         (repl (%rbf-tx 131 :value 40000000)))
    (%add-tx mempool orig :fee 1000)
    ;; new-fee 1100 >= 1000 (rule 3 ok) and additional 100 == bandwidth for a
    ;; 1000-vbyte replacement (rule 4 ok), but the huge vsize makes the new
    ;; chunk's feerate far worse than the original's — the diagram is not
    ;; strictly better.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 1100 1000 (list orig-txid))
      (is-false ok)
      (is (eq reason :replacement-failed)))))

(test rbf-rule3-and-rule4-survive
  "Rule 3 (pay >= replaced fees) and rule 4 (pay own bandwidth at the
incremental relay fee) still reject before the diagram is consulted."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 132))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig))
         (repl (%rbf-tx 132 :value 40000000))
         (rvsize (bitcoin-lisp.serialization:transaction-vsize repl)))
    (%add-tx mempool orig :fee 10000)
    ;; Rule 3: fee below the replaced fee.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 9000 rvsize (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))
    ;; Rule 4: fee above the replaced fee but not by enough to cover the
    ;; replacement's own bandwidth (needs at least ceil(rvsize*100/1000) extra).
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl (1+ 10000) rvsize (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))))

(test rbf-rule5-cluster-cap
  "Rule 5: conflicting directly with more than 100 distinct clusters is
rejected :too-many-clusters (Core GetUniqueClusterCount > MAX_REPLACEMENT_
CANDIDATES, rbf.cpp:69-74). 100 distinct clusters is allowed."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (conflicts '()))
    ;; 101 independent singleton-cluster txs, each on its own outpoint
    ;; (%rbf-tx's input-id fills a (unsigned-byte 8) array, so ids stay <= 255).
    (loop for i from 1 to 101
          for tx = (%rbf-tx i)
          do (%add-tx mempool tx :fee 1000)
             (push (bitcoin-lisp.serialization:transaction-hash tx) conflicts))
    (let ((cand (%rbf-tx 200)))
      ;; 101 distinct conflicting clusters => rejected.
      (multiple-value-bind (ok reason)
          (bitcoin-lisp.mempool:check-rbf-rules
           mempool cand 100000000 (bitcoin-lisp.serialization:transaction-vsize cand)
           conflicts)
        (is-false ok)
        (is (eq reason :too-many-clusters)))
      ;; Dropping one leaves exactly 100 => the cluster cap is satisfied (and,
      ;; paying a huge fee over singletons, the replacement is accepted).
      (multiple-value-bind (ok reason)
          (bitcoin-lisp.mempool:check-rbf-rules
           mempool cand 100000000 (bitcoin-lisp.serialization:transaction-vsize cand)
           (rest conflicts))
        (declare (ignore reason))
        (is-true ok)))))

(test rbf-rule5-gather-cap
  "Rule 5 second bound: the conflicting clusters may hold at most 500 txs in
total (Core GatherClusters cap). A single conflicting cluster larger than the
cap is rejected :too-many-replacements."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         ;; A 3-tx conflicting cluster with the cap lowered to 2.
         (root-txid (%rbf-chain mempool 150 3 :fee 10000))
         (cand (%rbf-tx 150 :value 40000000))   ; conflicts with the root
         (bitcoin-lisp.mempool::+max-rbf-gather-transactions+ 2))
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-rbf-rules
         mempool cand 100000000 (bitcoin-lisp.serialization:transaction-vsize cand)
         (list root-txid))
      (is-false ok)
      (is (eq reason :too-many-replacements)))))

(test rbf-diagram-uncalculable-is-too-large-cluster
  "When the staged replacement would form an over-limit cluster the diagram is
uncalculable and the replacement is rejected :too-large-cluster (Core
CheckMemPoolPolicyLimits failing before ImprovesFeerateDiagram)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 160))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig))
         (repl (%rbf-tx 160 :value 40000000)))
    (%add-tx mempool orig :fee 1000)
    ;; Rules 3/4 pass (huge fee), but a 200000-vbyte candidate exceeds the
    ;; 101000-vB cluster size limit, so the diagram is uncalculable.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-rbf-rules mempool repl 200000 200000 (list orig-txid))
      (is-false ok)
      (is (eq reason :too-large-cluster)))))

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

;;;; BIP339 wtxid getdata serving

(defun %witness-tx-for-relay ()
  "A segwit tx (has a witness stack) so its wtxid differs from its txid."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 77)
                                      :index 0)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence #xffffffff))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value 1000
                     :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                  :initial-element #x51)))
   :witness (vector (list (make-array 4 :element-type '(unsigned-byte 8)
                                        :initial-contents '(1 2 3 4))))
   :lock-time 0))

(test mempool-get-by-wtxid-serves-getdata
  "A segwit tx (wtxid != txid) is retrievable by wtxid via mempool-get-by-wtxid
(the MSG_WTX / wtxidrelay getdata serving path). A txid lookup by that wtxid
returns nil -- the pre-fix bug where handle-getdata used mempool-get and served
nothing for our own wtxid announcements."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)))
    (is (not (equalp txid wtxid)))                 ; witness tx: distinct ids
    (%add-tx mempool tx)
    (is-true (bitcoin-lisp.mempool:mempool-get-by-wtxid mempool wtxid))
    (is (null (bitcoin-lisp.mempool:mempool-get-by-wtxid mempool txid)))
    (is (null (bitcoin-lisp.mempool:mempool-get mempool wtxid)))))

(test make-tx-message-witness-flag
  "make-tx-message :witness serializes a segwit tx in BIP144 form (00 01 marker
after the version); the default (MSG_TX) path strips witness. A non-witness tx
uses the legacy form regardless."
  (let* ((tx (%witness-tx-for-relay))
         (wit (bitcoin-lisp.serialization:make-tx-message tx :witness t))
         (leg (bitcoin-lisp.serialization:make-tx-message tx)))
    (is (> (length wit) (length leg)))
    ;; payload starts after the 24-byte header; version is 4 bytes, then 00 01.
    (is (= 0 (aref wit (+ 24 4))))
    (is (= 1 (aref wit (+ 24 5))))
    ;; legacy path: byte after version is the input count (1), not the marker 0.
    (is (= 1 (aref leg (+ 24 4))))))

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
  "Effective min-fee (sat/kvB) is the relay floor, or the (decaying) rolling
minimum."
  (let ((mempool (bitcoin-lisp.mempool:make-mempool)))
    ;; No rolling minimum set -> relay floor (100 sat/kvB = 0.1 sat/vB, Core
    ;; DEFAULT_MIN_RELAY_TX_FEE).
    (is (= 100 (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool)))
    ;; Set a fresh rolling minimum -> used as-is.
    (setf (bitcoin-lisp.mempool::mempool-rolling-min-fee-rate mempool) 5000
          (bitcoin-lisp.mempool::mempool-rolling-min-fee-time mempool)
          (bitcoin-lisp.serialization:get-unix-time))
    (is (= 5000 (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool)))
    ;; Far in the future it decays back below the floor -> floor.
    (is (= 100 (bitcoin-lisp.mempool:mempool-effective-min-fee-rate
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

;;;; OP_RETURN push-only standardness + bare-multisig default

(defun %policy-bytes (&rest bs)
  (make-array (length bs) :element-type '(unsigned-byte 8) :initial-contents bs))

(test op-return-push-only-standardness
  "OP_RETURN is a standard data-carrier only when its payload is push-only
(Core Solver NULL_DATA / IsPushOnly); a non-push opcode makes it nonstandard."
  (let ((bitcoin-lisp::*accept-datacarrier* t)
        (bitcoin-lisp::*max-datacarrier-bytes* 83))
    ;; OP_RETURN <push 3 bytes> -> standard
    (is-true (bitcoin-lisp.validation::standard-output-script-p
              (%policy-bytes #x6a #x03 #xaa #xbb #xcc)))
    ;; OP_RETURN OP_ADD (0x93, a non-push opcode) -> nonstandard
    (is-false (bitcoin-lisp.validation::standard-output-script-p
               (%policy-bytes #x6a #x93)))
    ;; the helper directly
    (is-true (bitcoin-lisp.validation::%op-return-push-only-p
              (%policy-bytes #x6a #x03 #x01 #x02 #x03)))
    (is-true (bitcoin-lisp.validation::%op-return-push-only-p
              (%policy-bytes #x6a #x51 #x60)))            ; OP_1 .. OP_16 are pushes
    (is-false (bitcoin-lisp.validation::%op-return-push-only-p
               (%policy-bytes #x6a #x93)))
    ;; a push that overruns the script end is not push-only
    (is-false (bitcoin-lisp.validation::%op-return-push-only-p
               (%policy-bytes #x6a #x05 #x01)))))

(test bare-multisig-standard-by-default
  "Bare multisig is standard by default (Core DEFAULT_PERMIT_BAREMULTISIG=true)."
  (is-true bitcoin-lisp::*permit-bare-multisig*)          ; default flipped to t
  (let* ((pk (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2))
         (script (concatenate '(vector (unsigned-byte 8))
                              (%policy-bytes #x51 #x21) pk (%policy-bytes #x51 #xae))))
    (is-true (bitcoin-lisp.validation::standard-output-script-p script))))

(test mempool-entry-fields-spentby-rbf
  "%mempool-entry-fields reports spentby (in-mempool children), bip125-replaceable,
and unbroadcast. A parent's spentby lists a child that spends it."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (parent (make-mempool-test-tx :input-id 200))
         (ptxid (bitcoin-lisp.serialization:transaction-hash parent)))
    (%add-tx mempool parent)
    (let* ((child (%mp-spending-tx ptxid))
           (ctxid (bitcoin-lisp.serialization:transaction-hash child)))
      (%add-tx mempool child)
      (let ((f (bitcoin-lisp.rpc::%mempool-entry-fields
                mempool ptxid (bitcoin-lisp.mempool:mempool-get mempool ptxid))))
        (is (assoc "spentby" f :test #'string=))
        (is (assoc "bip125-replaceable" f :test #'string=))
        (is (assoc "unbroadcast" f :test #'string=))
        (is (member (bitcoin-lisp.rpc::hash-to-hex ctxid)
                    (cdr (assoc "spentby" f :test #'string=)) :test #'string=))))))

(test witness-unknown-and-p2a-outputs-standard
  "Future witness-version outputs (v2..v16, 2..40-byte program) and P2A
(OP_1 <0x4e73>) are standard to create (Core WITNESS_UNKNOWN / ANCHOR);
irregular version-0 programs stay nonstandard."
  (flet ((wp (ver-op &rest prog)
           (concatenate '(vector (unsigned-byte 8))
                        (vector ver-op (length prog))
                        (coerce prog '(vector (unsigned-byte 8))))))
    ;; P2A: OP_1 push2 0x4e73
    (is-true (bitcoin-lisp.validation::standard-output-script-p (wp #x51 #x4e #x73)))
    ;; v2 (OP_2) 32-byte program
    (is-true (bitcoin-lisp.validation::standard-output-script-p
              (concatenate '(vector (unsigned-byte 8)) (vector #x52 #x20)
                           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))))
    ;; v16 (OP_16) 40-byte program (max)
    (is-true (bitcoin-lisp.validation::standard-output-script-p
              (concatenate '(vector (unsigned-byte 8)) (vector #x60 #x28)
                           (make-array 40 :element-type '(unsigned-byte 8) :initial-element 1))))
    ;; 41-byte program: not a witness program -> nonstandard
    (is-false (bitcoin-lisp.validation::standard-output-script-p
               (concatenate '(vector (unsigned-byte 8)) (vector #x52 #x29)
                            (make-array 41 :element-type '(unsigned-byte 8) :initial-element 1))))
    ;; irregular v0 (OP_0 push2): stays nonstandard
    (is-false (bitcoin-lisp.validation::standard-output-script-p (wp #x00 #xaa #xbb)))
    ;; RPC type names
    (is (string= "anchor" (bitcoin-lisp.rpc::%script-type (wp #x51 #x4e #x73))))
    (is (string= "witness_unknown" (bitcoin-lisp.rpc::%script-type (wp #x52 #xaa #xbb))))))

;;;; BIP431 TRUC (v3) topology

(defun %truc-tx (parent-txid &key (version 3) (vout 0) (value 40000000))
  "A v-VERSION tx spending PARENT-TXID:VOUT (make-outpoint hash is 32 bytes)."
  (let ((tx (%mp-spending-tx parent-txid :vout vout :value value)))
    (setf (bitcoin-lisp.serialization:transaction-version tx) version)
    tx))

(test single-truc-checks-topology
  "single-truc-checks (Core SingleTRUCChecks): inheritance both ways, v3 ancestor
and descendant limits of 1, and the 1000-vsize child cap."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 60))
         ;; a v3 parent in the mempool
         (v3-parent (%truc-tx root :version 3))
         (v3-pid (bitcoin-lisp.serialization:transaction-hash v3-parent))
         ;; a v2 parent in the mempool
         (v2-parent (%truc-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 61)
                              :version 2))
         (v2-pid (bitcoin-lisp.serialization:transaction-hash v2-parent)))
    (%add-tx mempool v3-parent)
    (%add-tx mempool v2-parent)
    (flet ((ok (tx &optional (vsize 200) conflicts)
             (bitcoin-lisp.mempool:single-truc-checks mempool tx vsize conflicts)))
      ;; a lone v3 tx (no mempool parent) is fine
      (is-true (ok (%truc-tx root :version 3 :vout 5)))
      ;; a lone non-v3 tx is unaffected
      (is-true (ok (%truc-tx root :version 2 :vout 6)))
      ;; inheritance: non-v3 spending the v3 parent -> rejected
      (multiple-value-bind (o r) (ok (%truc-tx v3-pid :version 2))
        (is-false o) (is (eq :truc-nonv3-spends-v3 r)))
      ;; inheritance: v3 spending the v2 parent -> rejected
      (multiple-value-bind (o r) (ok (%truc-tx v2-pid :version 3))
        (is-false o) (is (eq :truc-v3-spends-nonv3 r)))
      ;; a v3 child of the v3 parent is fine (1 ancestor, 1 descendant)
      (is-true (ok (%truc-tx v3-pid :version 3)))
      ;; v3 child too big (> 1000 vsize) -> rejected
      (multiple-value-bind (o r) (ok (%truc-tx v3-pid :version 3) 1001)
        (is-false o) (is (eq :truc-child-too-big r)))
      ;; v3 tx too big (> 10000 vsize) -> rejected even without a parent
      (multiple-value-bind (o r) (ok (%truc-tx root :version 3 :vout 7) 10001)
        (is-false o) (is (eq :truc-tx-too-big r))))))

(test truc-descendant-limit-one-child
  "A v3 parent may have at most one unconfirmed child; a second fails the
descendant limit, naming the existing child as the evictable sibling (the
caller may then run it through the RBF economics — sibling eviction, Core
truc_policy.cpp:233-262)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 70))
         (parent (%truc-tx root :version 3))
         (pid (bitcoin-lisp.serialization:transaction-hash parent)))
    (%add-tx mempool parent)
    ;; first child ok, then add it
    (let* ((child1 (%truc-tx pid :version 3 :vout 0))
           (cid1 (bitcoin-lisp.serialization:transaction-hash child1)))
      (is-true (bitcoin-lisp.mempool:single-truc-checks mempool child1 200 nil))
      (%add-tx mempool child1)
      ;; a second child of the same parent -> descendant limit, with CHILD1
      ;; identified as the considerable sibling (parent has exactly one
      ;; descendant whose only ancestor is the parent).
      (multiple-value-bind (o r sibling)
          (bitcoin-lisp.mempool:single-truc-checks mempool (%truc-tx pid :version 3 :vout 1) 200 nil)
        (is-false o) (is (eq :truc-descendant-limit r))
        (is (equalp cid1 sibling)))
      ;; ... unless the existing child is being replaced anyway.
      (is-true (bitcoin-lisp.mempool:single-truc-checks
                mempool (%truc-tx pid :version 3 :vout 1) 200 (list cid1))))))

(test truc-sibling-eviction-not-considerable-with-grandchild
  "Sibling eviction is only offered in the clean 1p1c shape: a sibling that
itself has a descendant (a reorg-created shape) is NOT returned (Core
consider_sibling_eviction: GetDescendantCount(parent)==2 &&
GetAncestorCount(sibling)==2, truc_policy.cpp:250-252)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 71))
         (parent (%truc-tx root :version 3))
         (pid (bitcoin-lisp.serialization:transaction-hash parent))
         (child1 (%truc-tx pid :version 3 :vout 0))
         (cid1 (bitcoin-lisp.serialization:transaction-hash child1))
         ;; Direct adds bypass validation, building the reorg-only shape.
         (grandchild (%truc-tx cid1 :version 3 :vout 0)))
    (%add-tx mempool parent)
    (%add-tx mempool child1)
    (%add-tx mempool grandchild)
    (multiple-value-bind (o r sibling)
        (bitcoin-lisp.mempool:single-truc-checks mempool (%truc-tx pid :version 3 :vout 1) 200 nil)
      (is-false o) (is (eq :truc-descendant-limit r))
      (is (null sibling)))))

(test v3-now-standard
  "v3 is a standard tx version (TRUC enabled): +max-standard-tx-version+ = 3."
  (is (= 3 bitcoin-lisp.validation::+max-standard-tx-version+)))

;;;; Package RBF rules (cluster mempool P8 — Core PackageRBFChecks,
;;;; validation.cpp:1034-1130). check-package-rbf-rules applies the anti-DoS
;;;; rules to the PACKAGE totals, requires the package feerate to strictly
;;;; exceed the parent's, and stages BOTH transactions for the diagram test.
;;;; The 1p1c / no-mempool-ancestor shape preconditions live in the caller
;;;; (validation/packages.lisp) and are tested in package-tests.

(test package-rbf-rules-accepts-cpfp-replacement
  "A low-fee parent + high-fee child replacing a conflicting tx passes when
the pair out-earns it: rules 3/4 on package totals, feerate above parent,
and a strict diagram improvement."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 170))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig)))
    (%add-tx mempool orig :fee 1000)
    (multiple-value-bind (ok reason replaced)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 10 100 5000 100 (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))))

(test package-rbf-rules-rule3-rule4-on-totals
  "Rules 3/4 evaluate the package totals: a pair whose combined fee does not
cover the replaced fees (plus its own bandwidth) is rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 171))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig)))
    (%add-tx mempool orig :fee 10000)
    ;; Rule 3: 10 + 5000 < 10000.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 10 100 5000 100 (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))
    ;; Rule 4: totals exceed the replaced fee but not by the pair's own
    ;; bandwidth at 100 sat/kvB (needs ceil(200*100/1000) = 20 extra).
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 10 100 10009 100 (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))))

(test package-rbf-rules-feerate-must-exceed-parent
  "The package feerate must STRICTLY exceed the parent's own feerate — the
pair must be a chunk on its own, not a child merely paying anti-DoS fees
(Core validation.cpp:1104-1111). Equality is also rejected."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 172))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig)))
    (%add-tx mempool orig :fee 100)
    ;; Parent 50 sat/vB, child 0 -> package 25 sat/vB < parent.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 5000 100 0 100 (list orig-txid))
      (is-false ok)
      (is (eq reason :package-feerate-not-above-parent)))
    ;; Equal feerates (parent 10, child 10 sat/vB) -> still rejected.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 1000 100 1000 100 (list orig-txid))
      (is-false ok)
      (is (eq reason :package-feerate-not-above-parent)))))

(test package-rbf-rules-diagram-must-improve
  "Rules 3/4 and the parent-feerate check can pass while the two-transaction
diagram does NOT strictly improve — rejected :replacement-failed."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 173))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig)))
    ;; Original: 10 sat/vB over 100 vB.
    (%add-tx mempool orig :fee 1000)
    ;; Pair: parent 5 sat/vB + child 7 sat/vB -> one 6 sat/vB chunk over
    ;; 200 vB. Rule 3/4: 1200 >= 1000 + 20. Package feerate 6 > parent 5.
    ;; Diagram: worse than the original at size 100 (600 < 1000), better at
    ;; 200 (1200 > 1000) -> :unordered, not a strict improvement.
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 500 100 700 100 (list orig-txid))
      (is-false ok)
      (is (eq reason :replacement-failed)))))

(test package-rbf-rules-cluster-caps
  "Rule 5's caps apply unchanged to the aggregate package conflicts."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (conflicts '()))
    (loop for i from 1 to 101
          for tx = (%rbf-tx i)
          do (%add-tx mempool tx :fee 1000)
             (push (bitcoin-lisp.serialization:transaction-hash tx) conflicts))
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 1000 100 100000000 100 conflicts)
      (is-false ok)
      (is (eq reason :too-many-clusters)))))

(test package-rbf-rules-too-large-cluster
  "A package member breaching the cluster size limit in staging is rejected
:too-large-cluster (uncalculable diagram)."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))
         (orig (%rbf-tx 174))
         (orig-txid (bitcoin-lisp.serialization:transaction-hash orig)))
    (%add-tx mempool orig :fee 1000)
    (multiple-value-bind (ok reason)
        (bitcoin-lisp.mempool:check-package-rbf-rules
         mempool 1000 100 100000000 200000 (list orig-txid))
      (is-false ok)
      (is (eq reason :too-large-cluster)))))
