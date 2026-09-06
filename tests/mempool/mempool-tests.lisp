(in-package #:bitcoin-lisp.tests)

(in-suite :mempool-tests)

;;;; Test helpers

(defun make-mempool-entry-for-tx (tx &key (fee 10000))
  "Create a mempool entry for a test transaction (computes size/vsize/wtxid)."
  (bl.mp:make-entry-from-tx tx fee 0 :entry-time 1000000))

(defun %rolling-min-fee (mempool)
  "The mempool's stored rolling minimum fee rate (Core rollingMinimumFeeRate)."
  (bl.mp::mempool-rolling-min-fee-rate mempool))

(defun %set-rolling-min-fee (mempool rate time)
  "Plant a rolling minimum of RATE sat/kvB last decayed at TIME, with a block
since the bump — the state a trim followed by a connected block leaves (Core
trackPackageRemoved then removeForBlock)."
  (setf (bl.mp::mempool-rolling-min-fee-rate mempool) (coerce rate 'double-float)
        (bl.mp::mempool-rolling-min-fee-time mempool) time
        (bl.mp::mempool-block-since-rolling-fee-bump mempool) t)
  rate)

(defun %mp-block (txs)
  "A block carrying TXS. MEMPOOL-REMOVE-FOR-BLOCK reads the transaction list
and nothing else, so the header is a placeholder."
  (bl.ser:make-bitcoin-block
   :header (bl.ser:make-block-header
            :version 1
            :prev-block (make-array 32 :element-type '(unsigned-byte 8))
            :merkle-root (make-array 32 :element-type '(unsigned-byte 8))
            :timestamp 0 :bits 0 :nonce 0)
   :transactions txs))

;;;; Shared acceptance tail (accept-validated-tx)
;;;;
;;;; The evict-replaced + build-entry + mempool-add sequence used to be
;;;; inlined at six call sites (peer tx handler, orphan cascade,
;;;; sendrawtransaction, mempool.dat reload, reorg re-add, submitpackage)
;;;; and had started to drift. accept-validated-tx is the single tail.

(test accept-validated-tx-evicts-replaced-and-adds
  "Accepting with :replaced evicts the RBF'd tx and adds the new one,
returning (values :ok entry)."
  (let* ((mempool (bl.mp:make-mempool))
         (old-tx (make-mempool-test-tx :input-id 1))
         (old-txid (bl.ser:transaction-hash old-tx))
         (new-tx (make-mempool-test-tx :input-id 2))
         (new-txid (bl.ser:transaction-hash new-tx)))
    (is (eq :ok (bl.mp:mempool-add
                 mempool old-txid (make-mempool-entry-for-tx old-tx))))
    (multiple-value-bind (result entry)
        (bl.mp:accept-validated-tx
         mempool new-txid new-tx 15000 0
         :entry-time 1000001 :replaced (list old-txid))
      (is (eq :ok result))
      (is (= 15000 (bl.mp:mempool-entry-fee entry)))
      (is (= 1000001 (bl.mp:mempool-entry-entry-time entry))))
    (is (null (bl.mp:mempool-get mempool old-txid)))
    (is (bl.mp:mempool-get mempool new-txid))))

(test accept-validated-tx-nil-fee-defaults-to-zero
  "A NIL fee is folded to 0 rather than poisoning entry arithmetic."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 3))
         (txid (bl.ser:transaction-hash tx)))
    (multiple-value-bind (result entry)
        (bl.mp:accept-validated-tx mempool txid tx nil 0)
      (is (eq :ok result))
      (is (= 0 (bl.mp:mempool-entry-fee entry))))))

;;;; Prioritisation tests (Core PrioritiseTransaction / mapDeltas)

(test mempool-prioritise-in-mempool
  "Prioritising an in-mempool tx adjusts its modified fee and feerate scoring,
deltas stack, and a net-zero delta is dropped from the map."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 1))
         (txid (bl.ser:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx :fee 10000)))
    (is (eq :ok (bl.mp:mempool-add mempool txid entry)))
    (is (= 10000 (bl.mp:mempool-entry-modified-fee entry)))
    (bl.mp:mempool-prioritise mempool txid 5000)
    (is (= 15000 (bl.mp:mempool-entry-modified-fee entry)))
    (is (= 10000 (bl.mp:mempool-entry-fee entry)))   ; real fee untouched
    (is (= (/ 15000 (bl.mp:mempool-entry-vsize entry))
           (bl.mp:mempool-entry-fee-rate entry)))
    ;; Stacking: -5000 brings the accumulated delta to zero -> map entry dropped.
    (bl.mp:mempool-prioritise mempool txid -5000)
    (is (= 10000 (bl.mp:mempool-entry-modified-fee entry)))
    (is (zerop (hash-table-count (bl.mp:mempool-deltas mempool))))))

(test mempool-prioritise-before-acceptance
  "A delta set before the tx exists applies when the tx is later accepted
(Core: ATMP ApplyDelta), and mining for a confirmed tx clears its delta."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 2))
         (txid (bl.ser:transaction-hash tx)))
    (bl.mp:mempool-prioritise mempool txid 7000)
    (let ((entry (make-mempool-entry-for-tx tx :fee 1000)))
      (is (eq :ok (bl.mp:mempool-add mempool txid entry)))
      (is (= 8000 (bl.mp:mempool-entry-modified-fee entry))))
    ;; Mined in a block -> delta cleared (Core ClearPrioritisation).
    (bl.mp:mempool-remove-for-block mempool (%mp-block (list tx)))
    (is (null (bl.mp:mempool-get mempool txid)))
    (is (zerop (hash-table-count (bl.mp:mempool-deltas mempool))))))

;;;; Persistence tests (mempool.dat)

(test mempool-dat-round-trip
  "save-mempool-file/read-mempool-file round-trips entries (parents first),
per-entry deltas, and residual deltas; corrupt files read as not-ok."
  (let* ((mempool (bl.mp:make-mempool))
         (parent (make-mempool-test-tx :input-id 60))
         (parent-txid (bl.ser:transaction-hash parent))
         (child (make-spending-test-tx parent-txid))
         (child-txid (bl.ser:transaction-hash child))
         (absent-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 99))
         (path (merge-pathnames (format nil "mempool-test-~D.dat" (get-universal-time))
                                (uiop:temporary-directory))))
    ;; Child added after parent; insertion order child-last but save must be
    ;; parents-first regardless of table order.
    (is (eq :ok (bl.mp:mempool-add
                 mempool parent-txid (make-mempool-entry-for-tx parent :fee 5000))))
    (is (eq :ok (bl.mp:mempool-add
                 mempool child-txid (make-mempool-entry-for-tx child :fee 7000))))
    (bl.mp:mempool-prioritise mempool child-txid 1234)
    (bl.mp:mempool-prioritise mempool absent-txid -555)
    (unwind-protect
         (progn
           (is (= 2 (bl.mp:save-mempool-file mempool path)))
           (multiple-value-bind (entries residual ok)
               (bl.mp:read-mempool-file path)
             (is-true ok)
             (is (= 2 (length entries)))
             ;; Parents-first: parent tx is the first record.
             (destructuring-bind (tx1 time1 delta1) (first entries)
               (is (equalp parent-txid (bl.ser:transaction-hash tx1)))
               (is (= 1000000 time1))
               (is (zerop delta1)))
             (destructuring-bind (tx2 time2 delta2) (second entries)
               (declare (ignore time2))
               (is (equalp child-txid (bl.ser:transaction-hash tx2)))
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
           (is-false (nth-value 2 (bl.mp:read-mempool-file path))))
      (ignore-errors (delete-file path)))))

(test mempool-dat-unbroadcast-round-trip
  "The v2 mempool.dat trailer round-trips the unbroadcast set (Core
node/mempool_persist.cpp:134-141/205-206), and a version-1 file (no
trailer) still loads cleanly with an empty set."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 61))
         (txid (bl.ser:transaction-hash tx))
         (path (merge-pathnames (format nil "mempool-unbr-test-~D.dat" (get-universal-time))
                                (uiop:temporary-directory))))
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (make-mempool-entry-for-tx tx :fee 5000))))
    (is-true (bl.mp:mempool-add-unbroadcast mempool txid))
    (unwind-protect
         (progn
           ;; v2 round trip: the set comes back as the 4th value.
           (is (= 1 (bl.mp:save-mempool-file mempool path)))
           (multiple-value-bind (entries residual ok unbroadcast)
               (bl.mp:read-mempool-file path)
             (declare (ignore residual))
             (is-true ok)
             (is (= 1 (length entries)))
             (is (= 1 (length unbroadcast)))
             (is (equalp txid (first unbroadcast))))
           ;; Old-format (version 1) file: ends after the residual deltas.
           ;; A restart with a pre-v2 mempool.dat must not crash.
           (let ((tx-bytes (bl.ser:transaction-wire-bytes tx)))
             (bl.store:save-file-with-crc32
              path
              (lambda (s)
                (bl.ser:write-uint32-le
                 s bl.mp::+mempool-dat-magic+)
                (bl.ser:write-uint8 s 1)   ; version 1
                (bl.ser:write-uint32-le s 1)
                (bl.ser:write-uint32-le s (length tx-bytes))
                (write-sequence tx-bytes s)
                (bl.ser:write-uint64-le s 1000000)
                (bl.ser:write-int64-le s 0)
                (bl.ser:write-uint32-le s 0))))   ; no residuals
           (multiple-value-bind (entries residual ok unbroadcast)
               (bl.mp:read-mempool-file path)
             (declare (ignore residual))
             (is-true ok)
             (is (= 1 (length entries)))
             (is (equalp txid (bl.ser:transaction-hash
                               (first (first entries)))))
             (is (null unbroadcast))))
      (ignore-errors (delete-file path)))))

;;;; Unbroadcast set (Core m_unbroadcast_txids)

(test mempool-unbroadcast-add-requires-membership
  "mempool-add-unbroadcast records only in-pool txids (Core AddUnbroadcastTx's
exists() guard, txmempool.h:542-548); removal reports presence."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 70))
         (txid (bl.ser:transaction-hash tx))
         (absent (make-array 32 :element-type '(unsigned-byte 8) :initial-element 71)))
    ;; Not in the pool -> not recorded.
    (is-false (bl.mp:mempool-add-unbroadcast mempool absent))
    (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (make-mempool-entry-for-tx tx))))
    (is-true (bl.mp:mempool-add-unbroadcast mempool txid))
    (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
    (is (equalp (list txid) (bl.mp:mempool-unbroadcast-txids mempool)))
    (is-true (bl.mp:mempool-remove-unbroadcast mempool txid))
    (is-false (bl.mp:mempool-remove-unbroadcast mempool txid))
    (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))))

(test mempool-unbroadcast-cleared-when-tx-leaves-pool
  "A tx leaving the mempool leaves the unbroadcast set with it — direct
removal (eviction/expiry funnel through mempool-remove, Core removeUnchecked
-> RemoveUnbroadcastTx, txmempool.cpp:287) and block confirmation
(removeForBlock) both clear it."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 72))
         (txid (bl.ser:transaction-hash tx)))
    ;; Direct removal.
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (make-mempool-entry-for-tx tx))))
    (bl.mp:mempool-add-unbroadcast mempool txid)
    (bl.mp:mempool-remove mempool txid)
    (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))
    ;; Confirmation in a block.
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (make-mempool-entry-for-tx tx))))
    (bl.mp:mempool-add-unbroadcast mempool txid)
    (bl.mp:mempool-remove-for-block mempool (%mp-block (list tx)))
    (is (null (bl.mp:mempool-get mempool txid)))
    (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))))

;;;; Mempool core tests

(test mempool-add-and-get
  "Adding a transaction to mempool makes it retrievable."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 1))
         (txid (bl.ser:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx)))
    (is (eq :ok (bl.mp:mempool-add mempool txid entry)))
    (is (bl.mp:mempool-has mempool txid))
    (is (not (null (bl.mp:mempool-get mempool txid))))
    (is (= 1 (bl.mp:mempool-count mempool)))))

(test mempool-remove
  "Removing a transaction clears it from the mempool."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 2))
         (txid (bl.ser:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx)))
    (bl.mp:mempool-add mempool txid entry)
    (is (bl.mp:mempool-has mempool txid))
    (let ((removed (bl.mp:mempool-remove mempool txid)))
      (is (not (null removed))))
    (is (not (bl.mp:mempool-has mempool txid)))
    (is (= 0 (bl.mp:mempool-count mempool)))))

(test mempool-reject-duplicate
  "Adding a duplicate transaction is rejected."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 3))
         (txid (bl.ser:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx)))
    (is (eq :ok (bl.mp:mempool-add mempool txid entry)))
    (is (eq :duplicate (bl.mp:mempool-add mempool txid entry)))))

(test mempool-conflict-detection
  "Transactions spending the same outpoint are rejected as conflicts."
  (let* ((mempool (bl.mp:make-mempool))
         ;; tx1 and tx2 both spend input-id 4, index 0
         (tx1 (make-mempool-test-tx :input-id 4 :value 40000000))
         (tx2 (make-mempool-test-tx :input-id 4 :value 30000000))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    (is (eq :ok (bl.mp:mempool-add mempool txid1 entry1)))
    (is (eq :conflict (bl.mp:mempool-add mempool txid2 entry2)))))

(test mempool-no-conflict-different-inputs
  "Transactions spending different outpoints do not conflict."
  (let* ((mempool (bl.mp:make-mempool))
         (tx1 (make-mempool-test-tx :input-id 5))
         (tx2 (make-mempool-test-tx :input-id 6))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    (is (eq :ok (bl.mp:mempool-add mempool txid1 entry1)))
    (is (eq :ok (bl.mp:mempool-add mempool txid2 entry2)))
    (is (= 2 (bl.mp:mempool-count mempool)))))

(test mempool-size-tracking
  "Mempool tracks total size correctly."
  (let* ((mempool (bl.mp:make-mempool))
         (tx1 (make-mempool-test-tx :input-id 7))
         (tx2 (make-mempool-test-tx :input-id 8))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    (is (= 0 (bl.mp:mempool-total-size mempool)))
    (bl.mp:mempool-add mempool txid1 entry1)
    (let ((size1 (bl.mp:mempool-total-size mempool)))
      (is (> size1 0))
      (bl.mp:mempool-add mempool txid2 entry2)
      (is (> (bl.mp:mempool-total-size mempool) size1)))
    ;; Remove one, size should decrease
    (let ((size-before (bl.mp:mempool-total-size mempool)))
      (bl.mp:mempool-remove mempool txid1)
      (is (< (bl.mp:mempool-total-size mempool) size-before)))))

;;;; Eviction tests

(test mempool-eviction-lowest-fee-rate
  "When mempool is full, lowest fee-rate entry is evicted for a higher one."
  (let* ((mempool (bl.mp:make-mempool
                   :max-size 800))  ; one tx models to 704 usage bytes; two to 1392
         (tx1 (make-mempool-test-tx :input-id 10 :value 10000000))
         (tx2 (make-mempool-test-tx :input-id 11 :value 20000000))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         ;; tx1 has low fee, tx2 has high fee
         (entry1 (make-mempool-entry-for-tx tx1 :fee 100))
         (entry2 (make-mempool-entry-for-tx tx2 :fee 50000)))
    ;; Add tx1 first (low fee) - fits in empty pool
    (is (eq :ok (bl.mp:mempool-add mempool txid1 entry1)))
    ;; Add tx2 (high fee) - should evict tx1 to make room
    (is (eq :ok (bl.mp:mempool-add mempool txid2 entry2)))
    ;; tx1 should have been evicted
    (is (not (bl.mp:mempool-has mempool txid1)))
    (is (bl.mp:mempool-has mempool txid2))))

(test mempool-reject-low-fee-when-full
  "When mempool is full, a transaction with lower fee-rate than all entries is rejected."
  (let* ((mempool (bl.mp:make-mempool
                   :max-size 800))  ; one tx = 704 usage bytes, two = 1392
         (tx1 (make-mempool-test-tx :input-id 12 :value 10000000))
         (tx2 (make-mempool-test-tx :input-id 13 :value 20000000))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         ;; tx1 has high fee, tx2 has very low fee
         (entry1 (make-mempool-entry-for-tx tx1 :fee 50000))
         (entry2 (make-mempool-entry-for-tx tx2 :fee 1)))
    ;; Add tx1 first (high fee)
    (is (eq :ok (bl.mp:mempool-add mempool txid1 entry1)))
    ;; Add tx2 (very low fee) - should be rejected since tx1 has higher fee-rate
    (is (eq :mempool-full (bl.mp:mempool-add mempool txid2 entry2)))
    ;; tx1 should still be there
    (is (bl.mp:mempool-has mempool txid1))))

;;;; Block interaction tests

(test mempool-remove-for-block
  "Block connection removes confirmed transactions from mempool."
  (let* ((mempool (bl.mp:make-mempool))
         (tx1 (make-mempool-test-tx :input-id 20))
         (tx2 (make-mempool-test-tx :input-id 21))
         (txid1 (bl.ser:transaction-hash tx1))
         (txid2 (bl.ser:transaction-hash tx2))
         (entry1 (make-mempool-entry-for-tx tx1))
         (entry2 (make-mempool-entry-for-tx tx2)))
    ;; Add both to mempool
    (bl.mp:mempool-add mempool txid1 entry1)
    (bl.mp:mempool-add mempool txid2 entry2)
    (is (= 2 (bl.mp:mempool-count mempool)))
    ;; Create a block containing tx1 (with coinbase)
    (let* ((coinbase-input (bl.ser:make-tx-in
                            :previous-output (bl.ser:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 0)
                                              :index #xFFFFFFFF)
                            :script-sig (make-array 3 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)
                            :sequence #xFFFFFFFF))
           (coinbase-output (bl.ser:make-tx-out
                             :value 5000000000
                             :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                        :initial-element #x76)))
           (coinbase-tx (bl.ser:make-transaction
                         :version 1
                         :inputs (vector coinbase-input)
                         :outputs (vector coinbase-output)
                         :lock-time 0))
           (block (%mp-block (list coinbase-tx tx1))))
      ;; Remove for block
      (bl.mp:mempool-remove-for-block mempool block)
      ;; tx1 should be removed, tx2 should remain
      (is (not (bl.mp:mempool-has mempool txid1)))
      (is (bl.mp:mempool-has mempool txid2))
      (is (= 1 (bl.mp:mempool-count mempool))))))

(test mempool-remove-conflicts-on-block
  "Block connection removes conflicting mempool transactions."
  (let* ((mempool (bl.mp:make-mempool))
         ;; mempool tx spends input 30
         (mempool-tx (make-mempool-test-tx :input-id 30))
         (mempool-txid (bl.ser:transaction-hash mempool-tx))
         (mempool-entry (make-mempool-entry-for-tx mempool-tx)))
    ;; Add to mempool
    (bl.mp:mempool-add mempool mempool-txid mempool-entry)
    (is (bl.mp:mempool-has mempool mempool-txid))
    ;; Block contains a different tx that also spends input 30
    (let* ((block-tx (make-mempool-test-tx :input-id 30 :value 30000000))
           (coinbase-input (bl.ser:make-tx-in
                            :previous-output (bl.ser:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 0)
                                              :index #xFFFFFFFF)
                            :script-sig (make-array 3 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)
                            :sequence #xFFFFFFFF))
           (coinbase-output (bl.ser:make-tx-out
                             :value 5000000000
                             :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                        :initial-element #x76)))
           (coinbase-tx (bl.ser:make-transaction
                         :version 1
                         :inputs (vector coinbase-input)
                         :outputs (vector coinbase-output)
                         :lock-time 0))
           (block (%mp-block (list coinbase-tx block-tx))))
      (bl.mp:mempool-remove-for-block mempool block)
      ;; Conflicting mempool tx should be removed
      (is (not (bl.mp:mempool-has mempool mempool-txid)))
      (is (= 0 (bl.mp:mempool-count mempool))))))

;;;; Fee rate tests

(test mempool-entry-fee-rate-calculation
  "Fee rate is correctly computed as fee/vsize."
  (let* ((tx (make-mempool-test-tx :input-id 40))
         (entry (bl.mp:make-mempool-entry
                 :transaction tx
                 :fee 1000
                 :modified-fee 1000
                 :vsize 200
                 :entry-time 0)))
    (is (= 5 (bl.mp:mempool-entry-fee-rate entry)))))

;;;; Transaction relay tests

(test relay-skips-source-peer
  "Transaction relay sends inv to other peers but not the source."
  (let ((source-peer (bl.net:make-peer :state :ready))
        (other-peer (bl.net:make-peer :state :ready))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42)))
    ;; We can't actually send messages without a connection,
    ;; but we can verify announcement tracking (now a bounded set)
    (bl:add-recent-reject
     (bl.net:peer-announced-txs source-peer) txid)
    ;; Check source has it, other doesn't
    (is (bl:recent-reject-p
         (bl.net:peer-announced-txs source-peer) txid))
    (is (not (bl:recent-reject-p
              (bl.net:peer-announced-txs other-peer) txid)))))

(test peer-announced-txs-bounded
  "peer-announced-txs is a bounded FIFO set (Core CRollingBloomFilter{50000}
analogue): filling past capacity evicts the oldest entries instead of growing
without bound (the old hash-table leaked per-peer memory forever)."
  (let* ((peer (bl.net:make-peer
                :state :ready :announced-txs (bl:make-rejects-filter 10)))
         (set (bl.net:peer-announced-txs peer))
         (ids (loop for i below 15
                    collect (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element i))))
    (dolist (id ids) (bl:add-recent-reject set id))
    ;; the 5 oldest were evicted; the 10 newest remain
    (is (not (bl:recent-reject-p set (nth 0 ids))))
    (is (not (bl:recent-reject-p set (nth 4 ids))))
    (is (bl:recent-reject-p set (nth 5 ids)))
    (is (bl:recent-reject-p set (nth 14 ids)))
    (is (= 10 (hash-table-count (bl::recent-rejects-table set))))))

;;;; Standard script detection tests

(test standard-output-script-p2pkh
  "P2PKH scripts are standard."
  (let ((script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x76)   ; OP_DUP
    (setf (aref script 1) #xa9)   ; OP_HASH160
    (setf (aref script 2) #x14)   ; push 20 bytes
    (setf (aref script 23) #x88)  ; OP_EQUALVERIFY
    (setf (aref script 24) #xac)  ; OP_CHECKSIG
    (is (bl.val::standard-output-script-p script))))

(test standard-output-script-p2sh
  "P2SH scripts are standard."
  (let ((script (make-array 23 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #xa9)   ; OP_HASH160
    (setf (aref script 1) #x14)   ; push 20 bytes
    (setf (aref script 22) #x87)  ; OP_EQUAL
    (is (bl.val::standard-output-script-p script))))

(test standard-output-script-p2wpkh
  "P2WPKH scripts are standard."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x00)   ; OP_0
    (setf (aref script 1) #x14)   ; push 20 bytes
    (is (bl.val::standard-output-script-p script))))

(test standard-output-script-p2tr
  "P2TR scripts are standard."
  (let ((script (make-array 34 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x51)   ; OP_1
    (setf (aref script 1) #x20)   ; push 32 bytes
    (is (bl.val::standard-output-script-p script))))

(test acceptnonstdtxn-is-one-gate-over-corecs-set
  "-acceptnonstdtxn (Core mempool_args.cpp:101 -> require_standard). Core gates
a SPECIFIC set behind one flag; ours were inline checks interleaved with
non-policy ones, which is why this option sat on the accepted-but-unimplemented
list until the set could be separated.

Two halves matter equally. With the flag off, a non-standard transaction is
accepted as far as its non-standardness goes. And the checks Core keeps OUTSIDE
require_standard must STILL fire — a flag that turned off more than Core's is
worse than one that does nothing, because it silently relaxes consensus-adjacent
rules the operator never asked about."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (base (make-mempool-test-tx :input-id 81)))
    (flet ((reason (tx)
             (nth-value 1 (bl.val:validate-transaction-for-mempool
                           tx utxo mempool 100)))
           (retyped (ver)
             (bl.ser:make-transaction
              :version ver
              :inputs (bl.ser:transaction-inputs base)
              :outputs (bl.ser:transaction-outputs base)
              :lock-time 0)))
      ;; Control: with the flag ON (the default) a bad version is refused.
      (let ((bl.val:*require-standard* t))
        (is (eq :version-non-standard (reason (retyped 4)))))
      ;; With the flag OFF it gets past standardness entirely and fails on the
      ;; empty UTXO set instead — i.e. on a CONSENSUS ground, not a policy one.
      (let ((bl.val:*require-standard* nil))
        (is (eq :missing-input (reason (retyped 4))))
        ;; A non-standard OUTPUT script likewise stops being a reason.
        (let* ((weird (make-array 10 :element-type '(unsigned-byte 8)
                                     :initial-element #xFF))
               (tx (bl.ser:make-transaction
                    :version 2
                    :inputs (bl.ser:transaction-inputs base)
                    :outputs (vector (bl.ser:make-tx-out
                                      :value 100000 :script-pubkey weird))
                    :lock-time 0)))
          (is (eq :missing-input (reason tx))))
        ;; But the 64-byte minimum still fires: Core keeps
        ;; MIN_STANDARD_TX_NONWITNESS_SIZE outside require_standard
        ;; (validation.cpp:813-815) because it mitigates CVE-2017-12842, and a
        ;; flag that switched it off would be strictly more permissive than
        ;; Core's.
        (let* ((in (aref (bl.ser:transaction-inputs base) 0))
               (tiny (bl.ser:make-transaction
                      :version 2
                      :inputs (vector (bl.ser:make-tx-in
                                       :previous-output
                                       (bl.ser:tx-in-previous-output in)
                                       :script-sig (make-array 0 :element-type
                                                                 '(unsigned-byte 8))
                                       :sequence #xffffffff))
                      :outputs (vector (bl.ser:make-tx-out
                                        :value 100000
                                        :script-pubkey
                                        (make-array 0 :element-type
                                                      '(unsigned-byte 8))))
                      :lock-time 0)))
          ;; Assert the premise, or this test silently stops testing anything.
          (is (< (length (bl.ser:serialize-transaction tiny))
                 bl.val::+min-standard-tx-nonwitness-size+))
          (is (eq :tx-size-small (reason tiny))))
        ;; And a coinbase is still refused — consensus, never policy.
        (is (eq :coinbase-not-allowed
                (reason (bl.ser:make-transaction
                         :version 2
                         :inputs (vector (bl.ser:make-tx-in
                                          :previous-output
                                          (bl.ser:make-outpoint
                                           :hash (make-array 32 :element-type
                                                                '(unsigned-byte 8)
                                                             :initial-element 0)
                                           :index #xffffffff)
                                          :script-sig (make-array 2 :element-type
                                                                    '(unsigned-byte 8)
                                                                 :initial-element 0)
                                          :sequence #xffffffff))
                         :outputs (bl.ser:transaction-outputs base)
                         :lock-time 0)))))))
  ;; Core REFUSES TO START with -acceptnonstdtxn on a non-test chain
  ;; (mempool_args.cpp:102-104). An error, not a warning: a mainnet node quietly
  ;; relaying non-standard transactions has them dropped by every peer and never
  ;; finds out.
  (let ((saved bl.val:*require-standard*))
    (unwind-protect
         (progn
           (let ((bl:*network* :mainnet))
             (signals error
               (apply-config-globals '(("acceptnonstdtxn" . "1"))))
             ;; =0 on mainnet is fine — it asks for the default.
             (apply-config-globals '(("acceptnonstdtxn" . "0")))
             (is-true bl.val:*require-standard*))
           (let ((bl:*network* :regtest))
             (apply-config-globals '(("acceptnonstdtxn" . "1")))
             (is-false bl.val:*require-standard*)))
      (setf bl.val:*require-standard* saved)))
  (is-true (bl:known-config-option-p "acceptnonstdtxn"))
  (is-false (bl.cfg:core-only-option-p "acceptnonstdtxn")))

(test non-standard-output-script
  "Arbitrary scripts are non-standard."
  (let ((script (make-array 10 :element-type '(unsigned-byte 8) :initial-element #xFF)))
    (is (not (bl.val::standard-output-script-p script)))))

(defun %op-return-script (data-len)
  "An OP_RETURN scriptPubKey carrying DATA-LEN data bytes: OP_RETURN + a
direct push (<=75) or OP_PUSHDATA1 prefix + data."
  (if (<= data-len 75)
      (let ((s (make-array (+ 2 data-len) :element-type '(unsigned-byte 8)
                           :initial-element 0)))
        (setf (aref s 0) #x6a (aref s 1) data-len)
        s)
      (let ((s (make-array (+ 3 data-len) :element-type '(unsigned-byte 8)
                           :initial-element 0)))
        (setf (aref s 0) #x6a (aref s 1) #x4c (aref s 2) data-len)
        s)))

(defun %datacarrier-validate (data-lens &key value)
  "Validate (against an empty UTXO set) a tx whose outputs are OP_RETURN
scripts carrying DATA-LENS data bytes each, plus one standard P2PKH output.
Returns the rejection keyword. A tx passing the output-standardness stage
fails later with :missing-input (empty UTXO set), so :missing-input here
means the datacarrier budget was satisfied."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (base (make-mempool-test-tx :input-id 90 :value (or value 50000000)))
         (outputs (concatenate
                   'vector
                   (bl.ser:transaction-outputs base)
                   (map 'vector (lambda (len)
                                  (bl.ser:make-tx-out
                                   :value 0
                                   :script-pubkey (%op-return-script len)))
                        data-lens)))
         (tx (bl.ser:make-transaction
              :version 1
              :inputs (bl.ser:transaction-inputs base)
              :outputs outputs
              :lock-time 0)))
    (nth-value 1 (bl.val:validate-transaction-for-mempool
                  tx utxo mempool 100))))

(test datacarrier-shared-budget
  "OP_RETURN outputs draw on ONE shared -datacarriersize byte budget (Core
IsStandardTx datacarrier_bytes_left, policy.cpp:136-150): each output's whole
scriptPubKey size counts, multiple outputs are fine within the budget, and
the default budget is MAX_OP_RETURN_RELAY = 100,000."
  ;; Default budget is Core's MAX_OP_RETURN_RELAY.
  (is (= 100000 bl:*max-datacarrier-bytes*))
  ;; Per-output classification no longer size-caps OP_RETURN.
  (is-true (bl.val::standard-output-script-p
            (%op-return-script 200)))
  (let ((bl:*max-datacarrier-bytes* 168))
    ;; Two 84-byte scripts (OP_RETURN + PUSHDATA1 + len + 81 data) total
    ;; exactly 168 <= 168: both fit the shared budget.
    (is (eq :missing-input (%datacarrier-validate '(81 81))))
    ;; Three of them (252 bytes) overdraw the shared budget -> "datacarrier".
    (is (eq :datacarrier (%datacarrier-validate '(81 81 81))))
    ;; A single output bigger than the whole budget is rejected outright.
    (is (eq :datacarrier (%datacarrier-validate '(180))))
    ;; The budget counts each WHOLE script (84 bytes), not the data (81):
    ;; 165 covers the 162 data bytes but not two whole scripts.
    (let ((bl:*max-datacarrier-bytes* 165))
      (is (eq :datacarrier (%datacarrier-validate '(81 81)))))))

(test datacarrier-disabled-zeroes-budget
  "-datacarrier=0 zeroes the shared budget: any OP_RETURN output — of any
size — fails with the \"datacarrier\" reason (Core mempool_args.cpp:95-98:
max_datacarrier_bytes = nullopt -> value_or(0)); classification itself stays
NULL_DATA (standard)."
  (let ((bl:*accept-datacarrier* nil))
    ;; Still classified a standard script type...
    (is-true (bl.val::standard-output-script-p
              (%op-return-script 3)))
    ;; ...but any NULL_DATA output overdraws the zero budget.
    (is (eq :datacarrier (%datacarrier-validate '(3))))))

(test mempool-says-already-known-for-a-confirmed-tx
  "\"Are inputs missing because we already have the tx?\" (Core
validation.cpp:857-866). A transaction that is already CONFIRMED presents
exactly as one with missing inputs — it spent its own inputs — so before
reporting that, Core looks for any of the transaction's own outputs among the
coins and reports txn-already-known when it finds one. Without this, resubmitting
a mined transaction answers missing-inputs, which sends a client looking for a
reorg that did not happen."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (tx (make-mempool-test-tx :input-id 91))
         (txid (bl.ser:transaction-hash tx))
         (out0 (elt (bl.ser:transaction-outputs tx) 0)))
    ;; Inputs absent and no output of ours among the coins: genuinely missing.
    (is (eq :missing-input
            (nth-value 1 (bl.val:validate-transaction-for-mempool
                          tx utxo mempool 100))))
    ;; Now the coins hold OUR output, which is what a block containing this
    ;; transaction leaves behind. The inputs are still absent — that is the
    ;; whole point — so the only thing that can change the answer is the check.
    (bl.store:add-utxo
     utxo txid 0
     (bl.ser:tx-out-value out0)
     (bl.ser:tx-out-script-pubkey out0)
     99 :coinbase nil)
    (is (eq :already-known
            (nth-value 1 (bl.val:validate-transaction-for-mempool
                          tx utxo mempool 100))))))

(defun %tx-with-output-script (script &key (value 100000))
  "A minimal one-in one-out transaction paying SCRIPT, for standardness checks.
The scriptSig is empty, which is push-only, so the only standardness question
the transaction raises is the output's."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 3)
                                      :index 0)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence #xFFFFFFFF))
   :outputs (vector (bl.ser:make-tx-out
                     :value value :script-pubkey script))
   :lock-time 0))

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
    ;; STANDARD-OUTPUT-SCRIPT-P is Core's IsStandard, which does NOT consult
    ;; -permitbaremultisig: that gate lives in IsStandardTx (policy.cpp:151-153)
    ;; so the two can report different reasons. The knob is asserted through
    ;; the battery below; here the shape cap is what IsStandard owns.
    (is (bl.val::standard-output-script-p ms))
    (let ((bl:*permit-bare-multisig* nil))
      (is (bl.val::standard-output-script-p ms)))
    (let ((bl:*permit-bare-multisig* t))
      (is (bl.val::standard-output-script-p ms))
      (is (not (bl.val::standard-output-script-p ms4)))
      ;; a truncated/garbage multisig is rejected even when permitted
      (is (not (bl.val::standard-output-script-p
                (coerce #(#x51 #xae) '(vector (unsigned-byte 8)))))))
    ;; The knob, through the battery, with Core's two distinct reasons:
    ;; :bare-multisig for a permitted SHAPE refused by the knob, and
    ;; :non-standard-output ("scriptpubkey") for a shape IsStandard refuses on
    ;; its own. mempool_accept.py:304,311 asserts both, one after the other.
    (let ((tx-ms (%tx-with-output-script ms))
          (tx-ms4 (%tx-with-output-script ms4)))
      (let ((bl:*permit-bare-multisig* nil))
        (is (eq :bare-multisig
                (nth-value 1 (bl.val::%is-standard-tx tx-ms)))))
      (let ((bl:*permit-bare-multisig* t))
        (is (eq t (nth-value 0 (bl.val::%is-standard-tx tx-ms))))
        ;; n>3 is IsStandard's own cap, so the knob cannot excuse it
        (is (eq :non-standard-output
                (nth-value 1 (bl.val::%is-standard-tx tx-ms4))))))))

;;;; Fee estimation tests

(test fee-estimator-creation
  "Fee estimator is created with correct defaults."
  (let ((estimator (bl.mp:make-fee-estimator)))
    (is (= 0 (bl.mp:fee-estimator-entry-count estimator)))))

(test fee-estimator-add-stats
  "Adding fee statistics increments the entry count."
  (let ((estimator (bl.mp:make-fee-estimator))
        (stats (bl.mp:make-block-fee-stats
                :height 100
                :median-rate 50
                :low-rate 10
                :high-rate 100
                :tx-count 200)))
    (bl.mp:fee-estimator-add-stats estimator stats)
    (is (= 1 (bl.mp:fee-estimator-entry-count estimator)))))

(test fee-estimation-answers-only-from-the-policy-estimator
  "ESTIMATE-FEE-RATE is Core's estimateSmartFee and nothing else. It used to
fall through to a percentile of the median feerates of the last N blocks when
the policy estimator had no answer, and returned it with NO error message --
so the RPC reported it as a real feerate and a wallet reading it never fell
back to its own -fallbackfee. A percentile of what miners TOOK cannot express
that a feerate FAILED to confirm, which is the whole content of an estimate.

The block statistics below are exactly the history that fallback read: twenty
blocks at a median of 10 to 48 sat/vB, plenty for the old path, and the answer
must still be the absence of an estimate."
  (let ((estimator (bl.mp:make-fee-estimator))
        (bl.mp:*block-policy-estimator* (bl.mp:make-block-policy-estimator)))
    (dotimes (i 20)
      (bl.mp:fee-estimator-add-stats
       estimator (bl.mp:make-block-fee-stats
                  :height (+ 100 i) :median-rate (+ 10 (* i 2))
                  :low-rate 5 :high-rate 100 :tx-count 200)))
    (is (= 20 (bl.mp:fee-estimator-entry-count estimator))
        "positive control: the percentile history is populated")
    (dolist (target '(2 6 25 1008))
      (multiple-value-bind (rate error returned) (bl.mp:estimate-fee-rate target)
        (is (null rate) "target ~D answered ~S from the block history" target rate)
        (is (string= "Insufficient data or no feerate found" error))
        (is (= target returned))))
    ;; Positive control the other way: with a POLICY estimator that has an
    ;; answer, the same call returns it.
    (let ((bl.mp:*block-policy-estimator* (bpe-populated-estimator)))
      (multiple-value-bind (rate error) (bl.mp:estimate-fee-rate 6)
        (is (null error))
        (is (plusp rate))))))

;;;; PR1 foundation: entry enrichment, wtxid index, vsize fee-rate

(test mempool-entry-from-tx-fields
  "make-entry-from-tx populates size, vsize, wtxid, height."
  (let* ((tx (make-mempool-test-tx :input-id 70))
         (entry (bl.mp:make-entry-from-tx tx 1234 555)))
    (is (= 1234 (bl.mp:mempool-entry-fee entry)))
    (is (= 555 (bl.mp:mempool-entry-height entry)))
    (is (plusp (bl.mp:mempool-entry-size entry)))
    ;; legacy tx: vsize equals serialized size
    (is (= (bl.ser:transaction-vsize tx)
           (bl.mp:mempool-entry-vsize entry)))
    (is (equalp (bl.ser:transaction-wtxid tx)
                (bl.mp:mempool-entry-wtxid entry)))
    ;; fee-rate uses vsize
    (is (= (/ 1234 (bl.mp:mempool-entry-vsize entry))
           (bl.mp:mempool-entry-fee-rate entry)))))

(test mempool-wtxid-index
  "Adding/removing a tx maintains the by-wtxid index."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 71))
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx))
         (entry (bl.mp:make-entry-from-tx tx 10000 0)))
    (is (eq :ok (bl.mp:mempool-add mempool txid entry)))
    (is (equalp txid (gethash wtxid (bl.mp:mempool-by-wtxid mempool))))
    (bl.mp:mempool-remove mempool txid)
    (is (null (gethash wtxid (bl.mp:mempool-by-wtxid mempool))))))

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
    (is (= 546 (bl.val:dust-threshold p2pkh)))
    (is (= 294 (bl.val:dust-threshold p2wpkh)))
    (is (= 0 (bl.val:dust-threshold opret)))
    (is-true (bl.val:output-witness-program-p p2wpkh))
    (is-false (bl.val:output-witness-program-p p2pkh))))

(test policy-scriptsig-push-only
  "scriptsig-push-only-p accepts push opcodes and rejects ops > OP_16."
  ;; push 2 bytes, then OP_1..OP_16
  (is-true (bl.val::scriptsig-push-only-p
            (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(2 #xaa #x51))))
  ;; OP_CHECKSIG (0xac) is not a push
  (is-false (bl.val::scriptsig-push-only-p
             (make-array 1 :element-type '(unsigned-byte 8) :initial-element #xac))))

(test mempool-rejects-nonstandard-version
  "A tx with version outside [1,3] is rejected as non-standard. Version 3 is now
standard (TRUC/BIP431 enforced) -- see +max-standard-tx-version+."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (base (make-mempool-test-tx :input-id 80)))
    (flet ((rejected-p (ver)
             (let ((tx (bl.ser:make-transaction
                        :version ver
                        :inputs (bl.ser:transaction-inputs base)
                        :outputs (bl.ser:transaction-outputs base)
                        :lock-time 0)))
               (multiple-value-bind (valid err)
                   (bl.val:validate-transaction-for-mempool tx utxo mempool 100)
                 (and (null valid) (eq err :version-non-standard))))))
      (is-true (rejected-p 4))
      (is-true (rejected-p 0))
      ;; v3 is no longer rejected on the version check (TRUC governs its topology)
      (is-false (rejected-p 3)))))

(defun %eph-tx (&key (input-id 1) (input-index 0) outputs)
  "A transaction spending (INPUT-ID, INPUT-INDEX) and paying OUTPUTS."
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element input-id)
                                      :index input-index)
                    :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                               :initial-element 0)
                    :sequence #xFFFFFFFF))
   :outputs (coerce outputs 'vector)
   :lock-time 0))

(defun %eph-spend (parent-tx indices)
  "A transaction spending PARENT-TX's outputs at INDICES."
  (let ((txid (bl.ser:transaction-hash parent-tx)))
    (bl.ser:make-transaction
     :version 1
     :inputs (map 'vector
                  (lambda (i)
                    (bl.ser:make-tx-in
                     :previous-output (bl.ser:make-outpoint
                                       :hash txid :index i)
                     :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                                :initial-element 0)
                     :sequence #xFFFFFFFF))
                  indices)
     :outputs (vector (bl.ser:make-tx-out
                       :value 10000
                       :script-pubkey (bl.ser:tx-out-script-pubkey
                                       (elt (bl.ser:transaction-outputs
                                             parent-tx) 0))))
     :lock-time 0)))

(test mempool-ephemeral-dust-requires-zero-fee
  "Core PreCheckEphemeralTx (ephemeral_policy.cpp:23, called from
validation.cpp once fees are known): a transaction carrying dust must pay
NOTHING, so there is never an incentive to mine it alone. Dust is only safe
while it can travel and be swept as a package.

mempool-rejects-dust-output's docstring has pointed at this test by name since
the rule was written; the test did not exist."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (base (make-mempool-test-tx :input-id 95))
         (in (elt (bl.ser:transaction-inputs base) 0))
         (prevout (bl.ser:tx-in-previous-output in))
         (spk (bl.ser:tx-out-script-pubkey
               (elt (bl.ser:transaction-outputs base) 0)))
         (funding 100000))
    (bl.store:add-utxo
     utxo (bl.ser:outpoint-hash prevout)
     (bl.ser:outpoint-index prevout)
     funding spk 1 :coinbase nil)
    (flet ((tx-paying (total)
             ;; One dust output (1 sat) plus a normal one, summing to TOTAL.
             (bl.ser:make-transaction
              :version 1
              :inputs (vector in)
              :outputs (vector (bl.ser:make-tx-out
                                :value (- total 1) :script-pubkey spk)
                               (bl.ser:make-tx-out
                                :value 1 :script-pubkey spk))
              :lock-time 0)))
      ;; Paying a fee (outputs < input) WITH dust: refused.
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           (tx-paying (- funding 5000)) utxo mempool 100)
        (is (null valid))
        (is (eq :dust err) "a dust-carrying tx that pays a fee must be refused"))
      ;; Zero fee (outputs == input) WITH dust: the dust gate does NOT fire.
      ;; It may still fail a later policy check, which is fine — the property
      ;; under test is that :dust is no longer the reason.
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           (tx-paying funding) utxo mempool 100)
        (declare (ignore valid))
        (is (not (eq :dust err))
            "a 0-fee tx may carry ephemeral dust")))))

(test check-ephemeral-spends-requires-the-child-to-sweep-all-dust
  "Core CheckEphemeralSpends (ephemeral_policy.cpp:33). Dust is tolerated ONLY
because it is ephemeral — created and destroyed inside one package, never left
in the UTXO set. A child that spends a dust-carrying parent without also
spending the dust would strand it, so the whole exemption rests on this check.

The function existed and was wired into both the single-tx and package paths;
nothing tested it."
  (let* ((spk (bl.ser:tx-out-script-pubkey
               (elt (bl.ser:transaction-outputs
                     (make-mempool-test-tx :input-id 90)) 0)))
         (parent (%eph-tx :input-id 90
                          :outputs (list (bl.ser:make-tx-out
                                          :value 50000 :script-pubkey spk)
                                         ;; 1 sat, far below the 546-ish threshold
                                         (bl.ser:make-tx-out
                                          :value 1 :script-pubkey spk)))))
    ;; Sanity: output 1 really is dust, output 0 is not.
    (is (equal '(1) (bl.val::transaction-dust-indices parent)))
    ;; A child that sweeps BOTH outputs is fine.
    (multiple-value-bind (ok offender)
        (bl.val::check-ephemeral-spends
         (list parent (%eph-spend parent '(0 1))) nil)
      (is-true ok)
      (is (null offender)))
    ;; A child that takes only the non-dust output STRANDS the dust.
    (multiple-value-bind (ok offender)
        (bl.val::check-ephemeral-spends
         (list parent (%eph-spend parent '(0))) nil)
      (is (null ok))
      (is (equalp (bl.ser:transaction-hash
                   (%eph-spend parent '(0)))
                  offender)))
    ;; A child that spends ONLY the dust is also fine — the dust is gone.
    (multiple-value-bind (ok)
        (bl.val::check-ephemeral-spends
         (list parent (%eph-spend parent '(1))) nil)
      (is-true ok))
    ;; A parent with no dust imposes nothing on its child.
    (let ((clean (%eph-tx :input-id 91
                          :outputs (list (bl.ser:make-tx-out
                                          :value 50000 :script-pubkey spk)
                                         (bl.ser:make-tx-out
                                          :value 60000 :script-pubkey spk)))))
      (is-true (bl.val::check-ephemeral-spends
                (list clean (%eph-spend clean '(0))) nil)))))

(test check-ephemeral-spends-sees-mempool-parents-too
  "A parent already IN the mempool imposes the same sweep requirement as one
inside the package — that is the single-tx path, where the child arrives alone
and its dust-carrying parent is already accepted."
  (let* ((mempool (bl.mp:make-mempool))
         (spk (bl.ser:tx-out-script-pubkey
               (elt (bl.ser:transaction-outputs
                     (make-mempool-test-tx :input-id 92)) 0)))
         (parent (%eph-tx :input-id 92
                          :outputs (list (bl.ser:make-tx-out
                                          :value 50000 :script-pubkey spk)
                                         (bl.ser:make-tx-out
                                          :value 1 :script-pubkey spk))))
         (ptxid (bl.ser:transaction-hash parent)))
    (bl.mp:accept-validated-tx mempool ptxid parent 0 100)
    ;; The child alone: the parent is found in the MEMPOOL, and its dust must
    ;; still be swept.
    (multiple-value-bind (ok offender)
        (bl.val::check-ephemeral-spends
         (list (%eph-spend parent '(0))) mempool)
      (is (null ok))
      (is-true offender))
    (is-true (bl.val::check-ephemeral-spends
              (list (%eph-spend parent '(0 1))) mempool))))

(test mempool-rejects-dust-output
  "EPHEMERAL DUST (Core policy.cpp:157-161): MAX_DUST_OUTPUTS_PER_TX is 1, so a
SECOND dust output is rejected outright. A single dust output is no longer
rejected on sight — that is what made us refuse the 0-fee TRUC parent carrying
a P2A anchor that every Core peer relays — it is gated by the 0-fee rule
instead (see mempool-ephemeral-dust-requires-zero-fee)."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (base (make-mempool-test-tx :input-id 81 :value 1))   ; 1 sat < 546 dust
         (dust-out (elt (bl.ser:transaction-outputs base) 0)))
    ;; Two dust outputs: over the cap, rejected before inputs are even resolved.
    (let ((tx (bl.ser:make-transaction
               :version 1
               :inputs (bl.ser:transaction-inputs base)
               :outputs (vector dust-out dust-out)
               :lock-time 0)))
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool tx utxo mempool 100)
        (is (null valid))
        (is (eq err :dust))))
    ;; Exactly one dust output passes the count rule and proceeds (here it
    ;; falls through to the unresolved input, proving it was NOT rejected
    ;; :dust).
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool base utxo mempool 100)
      (is (null valid))
      (is (not (eq err :dust))))))

(test mempool-rejects-nonpushonly-scriptsig
  "A tx whose scriptSig contains a non-push opcode is rejected."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (base (make-mempool-test-tx :input-id 82))
         (bad-input (bl.ser:make-tx-in
                     :previous-output (bl.ser:tx-in-previous-output
                                       (elt (bl.ser:transaction-inputs base) 0))
                     :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                             :initial-element #xac)  ; OP_CHECKSIG
                     :sequence #xFFFFFFFF))
         (tx (bl.ser:make-transaction
              :version 1 :inputs (vector bad-input)
              :outputs (bl.ser:transaction-outputs base)
              :lock-time 0)))
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool tx utxo mempool 100)
      (is (null valid))
      (is (eq err :scriptsig-not-pushonly)))))

(defun %mempool-final-fixture (suffix)
  "Chain-state with a genesis + tip entry (both carrying headers so the MTP
walk works) and a UTXO-set. Returns (values state utxo tip-height)."
  (let* ((state (bl.store:init-chain-state
                 (merge-pathnames suffix (uiop:temporary-directory))))
         (utxo (bl.store:make-utxo-set))
         (genesis-hash (bl.store:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (genesis-entry (bl.store:make-block-index-entry
                         :hash genesis-hash :height 0 :chain-work 1 :status :valid
                         :header (bl.ser:make-block-header
                                  :version 1 :prev-block zeros :merkle-root zeros
                                  :timestamp 1700000000 :bits #x207fffff :nonce 0
                                  :cached-hash genesis-hash)))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (bl.store:add-block-index-entry state genesis-entry)
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash tip-hash :height 1 :prev-entry genesis-entry
            :chain-work 3 :status :valid
            :header (bl.ser:make-block-header
                     :version 1 :prev-block genesis-hash :merkle-root zeros
                     :timestamp 1700000600 :bits #x207fffff :nonce 0
                     :cached-hash tip-hash)))
    (bl.store:update-chain-tip state tip-hash 1)
    (values state utxo 1)))

(test mempool-rejects-non-final-tx
  "With chain-state supplied, a tx whose height-based locktime is beyond the
next block and whose sequences are non-final is rejected :non-final (Core
PreChecks). Without chain-state the finality check is skipped."
  (let ((bl:*network* :regtest))
    (multiple-value-bind (state utxo tip-height)
        (%mempool-final-fixture "test-mp-final/")
      (let* ((mempool (bl.mp:make-mempool))
             (base (make-mempool-test-tx :input-id 90))
             (prevout (bl.ser:tx-in-previous-output
                       (elt (bl.ser:transaction-inputs base) 0)))
             ;; non-final sequence + far-future height-based locktime
             (tx (bl.ser:make-transaction
                  :version 1
                  :inputs (vector (bl.ser:make-tx-in
                                   :previous-output prevout
                                   :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                                           :initial-element 0)
                                   :sequence 0))
                  :outputs (bl.ser:transaction-outputs base)
                  :lock-time 9999999)))
        ;; Resolve the input so validation reaches the finality check.
        (bl.store:add-utxo
         utxo (bl.ser:outpoint-hash prevout)
         (bl.ser:outpoint-index prevout)
         100000000
         (bl.ser:tx-out-script-pubkey
          (elt (bl.ser:transaction-outputs base) 0))
         0)
        ;; With chain-state: rejected as non-final.
        (multiple-value-bind (valid err)
            (bl.val:validate-transaction-for-mempool
             tx utxo mempool tip-height :chain-state state)
          (is (null valid))
          (is (eq err :non-final)))
        ;; Without chain-state: the finality check is skipped (so it is not the
        ;; reason for any rejection).
        (multiple-value-bind (valid err)
            (bl.val:validate-transaction-for-mempool
             tx utxo mempool tip-height)
          (declare (ignore valid))
          (is (not (eq err :non-final))))))))

;;;; PreChecks ORDER: which rule a transaction that breaks several is told about
;;;;
;;;; Every check in Core's MemPoolAccept::PreChecks returns on first failure, so
;;;; the accepted set does not depend on their order -- but the reason a caller
;;;; is given does, and so does what our own P2P layer then DOES with the
;;;; transaction. The three tests below pin the three orderings that were wrong.

(test mempool-non-final-is-decided-before-the-inputs-are-looked-up
  "Core runs CheckFinalTxAtTip at validation.cpp:817-821 -- before the mempool
duplicate probe (:823) and before the coin-availability loop that yields
TX_MISSING_INPUTS (:866). So a transaction that is BOTH non-final and naming
parents we do not have is \"non-final\", never \"missing-inputs\".

The vocabulary is the smaller half of it: :missing-input is the one keyword
src/networking/protocol.lisp routes to the orphanage, so reporting it here puts
a transaction Core drops outright into our orphan pool and spends parent-getdata
slots fetching parents that may not exist. Core instead remembers the wtxid in
RecentRejectsFilter (txdownloadman_impl.cpp:468)."
  (let ((bl:*network* :regtest))
    (multiple-value-bind (state utxo tip-height)
        (%mempool-final-fixture "test-mp-nonfinal-order/")
      (let* ((mempool (bl.mp:make-mempool))
             (final (make-mempool-test-tx :input-id 91))
             (prevout (bl.ser:tx-in-previous-output
                       (elt (bl.ser:transaction-inputs final) 0)))
             ;; Same unknown prevout, but a far-future locktime and a non-final
             ;; sequence: two rules broken at once.
             (non-final (bl.ser:make-transaction
                         :version 1
                         :inputs (vector (bl.ser:make-tx-in
                                          :previous-output prevout
                                          :script-sig (make-array
                                                       10 :element-type '(unsigned-byte 8)
                                                          :initial-element 0)
                                          :sequence 0))
                         :outputs (bl.ser:transaction-outputs final)
                         :lock-time 9999999)))
        ;; The prevout is deliberately absent from the UTXO set.
        (is (eq :non-final
                (nth-value 1 (bl.val:validate-transaction-for-mempool
                              non-final utxo mempool tip-height
                              :chain-state state))))
        ;; Control: a FINAL transaction naming the same unknown prevout still
        ;; reports :missing-input, so the orphan route is intact and the
        ;; assertion above is about the ORDER, not about finality swallowing
        ;; every missing-input verdict.
        (is (eq :missing-input
                (nth-value 1 (bl.val:validate-transaction-for-mempool
                              final utxo mempool tip-height
                              :chain-state state))))))))

(test mempool-duplicate-probe-tells-a-malleated-witness-apart
  "Core probes the pool twice, in this order (validation.cpp:823-830):
exists(wtxid) -> \"txn-already-in-mempool\" for the byte-identical transaction,
and only then exists(txid) -> \"txn-same-nonwitness-data-in-mempool\" for a
same-txid-different-witness variant of something we already hold.

A txid hit is a strict superset of a wtxid hit, so one txid probe rejects the
same set -- it just cannot tell the two apart, and that distinction is the only
signal a submitter gets that its witness was replaced in transit.
refs/bitcoin/test/functional/mempool_accept_wtxid.py:66-72 asserts on the exact
string."
  (multiple-value-bind (utxo mempool chain-state funding-txid)
      (make-package-fixture :current-height 200)
    (flet ((spend (&key witness)
             (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash funding-txid :index 0)
                               ;; push the OP_TRUE redeem script
                               :script-sig (%spk #x01 #x51)
                               :sequence #xFFFFFFFF))
              :outputs (vector (bl.ser:make-tx-out
                                :value 99000000
                                :script-pubkey (%p2pkh-spk)))
              :witness witness
              :lock-time 0)))
      (let* ((pooled (spend))
             (malleated (spend :witness (vector (list (%spk #x01))))))
        (bl.mp:accept-validated-tx mempool (bl.ser:transaction-hash pooled)
                                   pooled 1000 200)
        ;; The premise: same txid, different wtxid, and the variant's wtxid is
        ;; genuinely absent from the pool -- otherwise the first probe would hit
        ;; and this test would pass for the wrong reason.
        (is (equalp (bl.ser:transaction-hash pooled)
                    (bl.ser:transaction-hash malleated)))
        (is (not (equalp (bl.ser:transaction-wtxid pooled)
                         (bl.ser:transaction-wtxid malleated))))
        (is-false (bl.mp:mempool-get-by-wtxid
                   mempool (bl.ser:transaction-wtxid malleated)))
        (is (eq :same-nonwitness-data-in-mempool
                (nth-value 1 (bl.val:validate-transaction-for-mempool
                              malleated utxo mempool 200
                              :chain-state chain-state))))
        ;; Control: resubmitting the byte-identical transaction still takes the
        ;; wtxid branch.
        (is (eq :already-in-mempool
                (nth-value 1 (bl.val:validate-transaction-for-mempool
                              pooled utxo mempool 200
                              :chain-state chain-state))))))))

(test mempool-checktxinputs-runs-before-the-input-policy-checks
  "Core's order for the checks that read the spent coins (validation.cpp:892-905)
is Consensus::CheckTxInputs, then AreInputsStandard, then IsWitnessStandard,
then the sigop cost. A transaction that breaks a consensus rule and a policy
rule at once must report the CONSENSUS one: TX_CONSENSUS is a permanent
property of the transaction, TX_INPUTS_NOT_STANDARD only this node's relay
policy, and src/networking/protocol.lisp caches the txid IN ADDITION to the
wtxid for :nonstandard-inputs alone -- so the swap changed which identifiers
were remembered as well as what the client was told."
  (let* ((utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (chain-state (bl.store:make-chain-state :best-height 100))
         (cb-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (bare-true (%spk #x51)))
    ;; Spend height is tip+1 = 101, so a coin mined at 100 is one block old.
    (bl.store:add-utxo utxo cb-txid 0 50000000 bare-true 100 :coinbase t)
    (bl.store:add-utxo utxo cb-txid 1 50000000 (%p2pkh-spk) 100 :coinbase t)
    ;; ...while a coin mined at 0 is 101 blocks old, i.e. mature.
    (bl.store:add-utxo utxo cb-txid 2 50000000 bare-true 0 :coinbase t)
    (flet ((err-of (index)
             (nth-value 1
                        (bl.val:validate-transaction-for-mempool
                         (bl.ser:make-transaction
                          :version 2
                          :inputs (vector (bl.ser:make-tx-in
                                           :previous-output (bl.ser:make-outpoint
                                                             :hash cb-txid :index index)
                                           :script-sig (%spk #x01 #x51)
                                           :sequence #xFFFFFFFF))
                          :outputs (vector (bl.ser:make-tx-out
                                            :value 49000000
                                            :script-pubkey (%p2pkh-spk)))
                          :lock-time 0)
                         utxo mempool 100 :chain-state chain-state))))
      ;; Immature AND nonstandard to spend: the consensus reason wins.
      (is (eq :coinbase-not-mature (err-of 0)))
      ;; Immature alone: unchanged.
      (is (eq :coinbase-not-mature (err-of 1)))
      ;; Control: with maturity satisfied, the standardness gate still fires --
      ;; CheckTxInputs running first did not disable it.
      (is (eq :nonstandard-inputs (err-of 2))))))

(defun %add-sigop-dense-p2wsh-coin (utxo txid)
  "Add a 1-BTC P2WSH coin to UTXO at (TXID, 0) whose witness script is 3,600
bare OP_CHECKMULTISIG: 72,000 witness sigops against the 16,000 of
MAX_STANDARD_TX_SIGOPS_COST, so every spend of it is over the cap. Returns
the witness script."
  (let* ((witness-script (make-array 3600 :element-type '(unsigned-byte 8)
                                          :initial-element #xae))
         (p2wsh (%w8d-script #x00 #x20 (bl.crypto:sha256 witness-script))))
    (bl.store:add-utxo utxo txid 0 100000000 p2wsh 0)
    witness-script))

(defun %sigop-dense-spend (txid witness-script stack-items outputs)
  "A spend of that coin: one input, OUTPUTS, and a witness of STACK-ITEMS
one-byte items below WITNESS-SCRIPT, which Core does not count against
MAX_STANDARD_P2WSH_STACK_ITEMS."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint :hash txid :index 0)
                    :script-sig (%spk)
                    :sequence #xFFFFFFFF))
   :outputs outputs
   :witness (vector (append (make-list stack-items :initial-element (%spk #x01))
                            (list witness-script)))
   :lock-time 0))

(test mempool-witness-standardness-is-checked-before-the-sigop-cap
  "Core computes the sigop cost only AFTER IsWitnessStandard
(validation.cpp:901-905), so a witness-nonstandard spend that is also
sigop-dense is \"bad-witness-nonstandard\", not \"bad-txns-too-many-sigops\".
The fixture is one sigop-dense P2WSH input whose stack carries 101 items, one
past MAX_STANDARD_P2WSH_STACK_ITEMS."
  (let* ((utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (chain-state (bl.store:make-chain-state :best-height 100))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
         (witness-script (%add-sigop-dense-p2wsh-coin utxo txid)))
    (flet ((err-of (stack-items)
             (nth-value 1
                        (bl.val:validate-transaction-for-mempool
                         (%sigop-dense-spend
                          txid witness-script stack-items
                          (vector (bl.ser:make-tx-out
                                   :value 90000000
                                   :script-pubkey (%p2pkh-spk))))
                         utxo mempool 100 :chain-state chain-state))))
      ;; 101 stack items: nonstandard witness, and sigop-dense.
      (is (eq :bad-witness-nonstandard (err-of 101)))
      ;; Control: at 100 items the witness is standard, so the same 72,000
      ;; sigops now reach the cap -- proving both checks are live and that the
      ;; assertion above is about which one runs first.
      (is (eq :too-many-sigops (err-of 100))))))

(test mempool-ephemeral-dust-is-checked-before-the-sigop-cap
  "Core's PreChecks calls PreCheckEphemeralTx at validation.cpp:933 and tests
nSigOpsCost against MAX_STANDARD_TX_SIGOPS_COST only afterwards, at :937-939.
So a fee-paying transaction that carries dust AND is sigop-dense is refused
\"dust\", not \"bad-txns-too-many-sigops\". Both verdicts are TX_NOT_STANDARD,
so the order decides nothing but the reason the submitter is told -- which is
what mempool_accept.py and every client matching on the string read.

The fixture is the witness-standardness test's, with a second output of one
satoshi to a P2PKH script -- below the 546-sat dust threshold -- and a fee
that varies with the first."
  (let* ((utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (chain-state (bl.store:make-chain-state :best-height 100))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 22))
         (witness-script (%add-sigop-dense-p2wsh-coin utxo txid)))
    (flet ((err-of (change)
             ;; CHANGE plus the 1-sat dust output is what the 100,000,000-sat
             ;; input pays out, so it is what sets the fee.
             (nth-value 1
                        (bl.val:validate-transaction-for-mempool
                         (%sigop-dense-spend
                          txid witness-script 100
                          (vector (bl.ser:make-tx-out
                                   :value change
                                   :script-pubkey (%p2pkh-spk))
                                  (bl.ser:make-tx-out
                                   :value 1
                                   :script-pubkey (%p2pkh-spk))))
                         utxo mempool 100 :chain-state chain-state))))
      ;; A 10,000,000-sat fee: the dust may not be paid for, and Core says so
      ;; before it looks at the sigop cost.
      (is (eq :dust (err-of 90000000)))
      ;; Control: the same transaction paying NO fee is legal ephemeral dust,
      ;; so it passes PreCheckEphemeralTx and the same 72,000 sigops then reach
      ;; the cap -- both checks are live, and the assertion above is only about
      ;; which one runs first.
      (is (eq :too-many-sigops (err-of 99999999))))))

;;;; Wave 8A: witness-stripped classification + coinbase maturity at tip+1

(test spends-non-anchor-witness-program-p-cases
  "Port of Core SpendsNonAnchorWitnessProg (policy.cpp:340-373): true for a
direct witness-program spend (any version) and for P2SH whose redeem script
(scriptSig's last push) is a witness program; false for pay-to-anchor and
for plain non-witness spends."
  (let* ((utxo (bl.store:make-utxo-set))
         (p2wpkh (let ((s (make-array 22 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
                   (setf (aref s 0) #x00 (aref s 1) #x14) s))
         (p2a (make-array 4 :element-type '(unsigned-byte 8)
                            :initial-contents '(#x51 #x02 #x4e #x73)))
         (p2sh (let ((s (make-array 23 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #xa9 (aref s 1) #x14 (aref s 22) #x87) s))
         (p2pkh (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
                  (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                        (aref s 23) #x88 (aref s 24) #xac) s))
         ;; scriptSig whose last push is a v0-witness-program redeem script.
         (witness-redeem-sig (let ((s (make-array 23 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)))
                               (setf (aref s 0) 22    ; push 22 bytes
                                     (aref s 1) #x00 (aref s 2) #x14)
                               s))
         (spend (lambda (id sig)
                  (bl.ser:make-transaction
                   :version 2
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output (bl.ser:make-outpoint
                                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                           :initial-element id)
                                                      :index 0)
                                    :script-sig sig
                                    :sequence #xFFFFFFFF))
                   :outputs (vector (bl.ser:make-tx-out
                                     :value 10000 :script-pubkey p2pkh))
                   :lock-time 0))))
    (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1) 0 100000 p2wpkh 0)
    (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2) 0 100000 p2a 0)
    (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3) 0 100000 p2sh 0)
    (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4) 0 100000 p2pkh 0)
    (let ((empty-sig (make-array 0 :element-type '(unsigned-byte 8)))
          (op1-sig (make-array 1 :element-type '(unsigned-byte 8)
                                 :initial-element #x51)))
      (is-true (bl.val::spends-non-anchor-witness-program-p
                (funcall spend 1 empty-sig) utxo nil))
      (is-false (bl.val::spends-non-anchor-witness-program-p
                 (funcall spend 2 empty-sig) utxo nil))
      (is-true (bl.val::spends-non-anchor-witness-program-p
                (funcall spend 3 witness-redeem-sig) utxo nil))
      (is-false (bl.val::spends-non-anchor-witness-program-p
                 (funcall spend 4 op1-sig) utxo nil)))))

(test mempool-script-failure-classified-witness-stripped
  "A script failure of a NO-witness tx spending a witness program is
classified :witness-stripped (Core TX_WITNESS_STRIPPED, validation.cpp:
1143-1148) so the P2P layer never caches it; the same failure on a
non-witness-program spend is the policy-pass script rejection
:mempool-script-verify-flag-failed (Core TX_NOT_STANDARD from
PolicyScriptChecks)."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (p2wpkh (let ((s (make-array 22 :element-type '(unsigned-byte 8)
                                         :initial-element 0)))
                   (setf (aref s 0) #x00 (aref s 1) #x14) s))
         (base (make-mempool-test-tx :input-id 120 :value 50000000)))
    ;; Coin for the stripped spend: P2WPKH, generous value so fee checks pass.
    (bl.store:add-utxo
     utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element 120)
     0 100000000 p2wpkh 0)
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool
         base utxo mempool 100)
      (is (null valid))
      (is (eq err :witness-stripped)))
    ;; Same tx shape spending a P2PKH coin: witness stripping cannot explain
    ;; the failure, so it is the generic policy-pass script rejection.
    (let ((base2 (make-mempool-test-tx :input-id 121 :value 50000000)))
      (bl.store:add-utxo
       utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element 121)
       0 100000000
       (bl.ser:tx-out-script-pubkey
        (elt (bl.ser:transaction-outputs base2) 0))
       0)
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           base2 utxo mempool 100)
        (is (null valid))
        ;; The reason carries the script error Core would name in its
        ;; parenthetical: the fixture's scriptSig does not satisfy the P2PKH
        ;; output it spends, so the failure is the OP_EQUALVERIFY.
        (is (equal '(:mempool-script-verify-flag-failed :equalverify) err))))))

(test mempool-coinbase-maturity-at-next-block-height
  "Core's mempool acceptance checks maturity at nSpendHeight = tip + 1
(MemPoolAccept::PreChecks -> CheckTxInputs, 'nSpendHeight - coin.nHeight <
COINBASE_MATURITY'): a coinbase created at height 0 is spendable in block
100, so it must be ACCEPTED when the tip is 99 — and still rejected
:coinbase-not-mature when the tip is 98. Regression: the mempool path used
to evaluate maturity at the tip height itself, off by one."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (tx (make-mempool-test-tx :input-id 122 :value 50000000)))
    ;; The spent coin is a COINBASE output created at height 0.
    (bl.store:add-utxo
     utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element 122)
     0 100000000
     (bl.ser:tx-out-script-pubkey
      (elt (bl.ser:transaction-outputs tx) 0))
     0 :coinbase t)
    ;; Tip 98: spend height 99, age 99 < 100 -> immature.
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool
         tx utxo mempool 98)
      (is (null valid))
      (is (eq err :coinbase-not-mature)))
    ;; Tip 99: spend height 100, age 100 -> mature; validation proceeds past
    ;; maturity (this unsigned fixture then fails at script validation,
    ;; which is the point: the maturity gate no longer fires).
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool
         tx utxo mempool 99)
      (declare (ignore valid))
      (is (not (equal err :coinbase-not-mature)))
      (is (equal '(:mempool-script-verify-flag-failed :equalverify) err)))))

;;;; Wave 9D: two-pass mempool script validation — PolicyScriptChecks
;;;; (STANDARD flags) then ConsensusScriptChecks (tip consensus flags),
;;;; Core validation.cpp:1132-1185.

(test standard-script-verify-flags-composition
  "+standard-script-verify-flags+ is Core's STANDARD_SCRIPT_VERIFY_FLAGS
(policy/policy.h:118-133): the height-independent MANDATORY set
(P2SH|DERSIG|NULLDUMMY|CLTV|CSV|WITNESS|TAPROOT, policy.h:104-110) plus
every policy flag — 20 flags total, as a comma-separated string."
  (let ((flags (uiop:split-string
                bl.val:+standard-script-verify-flags+
                :separator ",")))
    (is (= 20 (length flags)))
    (dolist (f '("P2SH" "DERSIG" "NULLDUMMY" "CHECKLOCKTIMEVERIFY"
                 "CHECKSEQUENCEVERIFY" "WITNESS" "TAPROOT"
                 "STRICTENC" "MINIMALDATA" "DISCOURAGE_UPGRADABLE_NOPS"
                 "CLEANSTACK" "MINIMALIF" "NULLFAIL" "LOW_S"
                 "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" "WITNESS_PUBKEYTYPE"
                 "CONST_SCRIPTCODE" "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"
                 "DISCOURAGE_OP_SUCCESS" "DISCOURAGE_UPGRADABLE_PUBKEYTYPE"))
      (is (member f flags :test #'string=) "missing flag ~A" f))))

(defun %p2sh-of (redeem)
  "P2SH scriptPubKey paying to REDEEM (a byte vector)."
  (let ((spk (make-array 23 :element-type '(unsigned-byte 8))))
    (setf (aref spk 0) #xa9 (aref spk 1) #x14 (aref spk 22) #x87)
    (replace spk (bl.crypto:hash160 redeem) :start1 2)
    spk))

(defun %cleanstack-violation-fixture (script-sig &key (input-id 130))
  "(values tx utxo-set mempool): TX spends a P2SH(OP_TRUE) coin with
SCRIPT-SIG, paying a standard non-dust P2PKH output with an ample fee."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (redeem (make-array 1 :element-type '(unsigned-byte 8)
                               :initial-element #x51))   ; OP_TRUE
         (prev (make-array 32 :element-type '(unsigned-byte 8)
                              :initial-element input-id))
         (base (make-mempool-test-tx))     ; borrow its P2PKH output shape
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash prev :index 0)
                               :script-sig script-sig
                               :sequence #xFFFFFFFF))
              :outputs (vector (bl.ser:make-tx-out
                                :value 99000000
                                :script-pubkey (bl.ser:tx-out-script-pubkey
                                                (elt (bl.ser:transaction-outputs base) 0))))
              :lock-time 0)))
    (bl.store:add-utxo utxo prev 0 100000000 (%p2sh-of redeem) 1)
    (values tx utxo mempool)))

(test mempool-policy-scripts-reject-consensus-valid-nonstandard
  "PolicyScriptChecks: a P2SH(OP_TRUE) spend whose scriptSig carries an EXTRA
leading push is CONSENSUS-valid (no consensus flag rejects the leftover
stack item) but fails STANDARD flags on CLEANSTACK — mempool acceptance
must reject it :mempool-script-verify-flag-failed (Core TX_NOT_STANDARD,
reject reason \"mempool-script-verify-flag-failed\", CheckInputScripts
validation.cpp:2117). Regression: the pre-Wave-9 mempool path ran
MANDATORY-only flags and ACCEPTED it."
  ;; scriptSig: push OP_TRUE's byte (extra), then push the redeemScript.
  (let ((extra-push-sig (make-array 4 :element-type '(unsigned-byte 8)
                                      :initial-contents '(#x01 #x51 #x01 #x51)))
        (canonical-sig (make-array 2 :element-type '(unsigned-byte 8)
                                     :initial-contents '(#x01 #x51))))
    (multiple-value-bind (tx utxo mempool) (%cleanstack-violation-fixture extra-push-sig)
      ;; Consensus scripts (block flags at this height) PASS — the failure
      ;; is purely a policy-flag one...
      (is (eq t (bl.val:validate-transaction-scripts
                 tx utxo :height 100)))
      ;; ...and the full STANDARD set rejects it...
      (is (null (bl.val:validate-transaction-scripts
                 tx utxo
                 :flags bl.val:+standard-script-verify-flags+)))
      ;; ...so mempool acceptance classifies TX_NOT_STANDARD. This keyword
      ;; hits the generic P2P reject branch (wtxid cached, txid never) —
      ;; exactly Core's handling of TX_NOT_STANDARD (txdownloadman_impl.cpp).
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           tx utxo mempool 100)
        (is (null valid))
        ;; And it names WHICH standard flag rejected: Core's SCRIPT_ERR_CLEANSTACK.
        (is (equal '(:mempool-script-verify-flag-failed :cleanstack) err))))
    ;; Control: the canonical single-push scriptSig sails through BOTH
    ;; passes and is accepted.
    (multiple-value-bind (tx utxo mempool)
        (%cleanstack-violation-fixture canonical-sig :input-id 131)
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           tx utxo mempool 100)
        (is (eq t valid))
        (is (null err))))))

(test mempool-policy-scripts-minimaldata-rejected
  "A non-minimal redeemScript push (OP_PUSHDATA1 for a 1-byte push) is
consensus-valid but violates MINIMALDATA: rejected by the policy pass."
  (let ((pushdata1-sig (make-array 3 :element-type '(unsigned-byte 8)
                                     :initial-contents '(#x4c #x01 #x51))))
    (multiple-value-bind (tx utxo mempool)
        (%cleanstack-violation-fixture pushdata1-sig :input-id 132)
      (is (eq t (bl.val:validate-transaction-scripts
                 tx utxo :height 100)))
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           tx utxo mempool 100)
        (is (null valid))
        (is (equal '(:mempool-script-verify-flag-failed :minimaldata) err))))))

;;;; PR3 ancestor/descendant tracking + chained spends

(defun %add-tx (mempool tx &key (fee 10000) (height 0))
  "Insert TX directly into MEMPOOL as an already-accepted entry (bypassing
validation). The shared direct-add helper of the whole test package."
  (bl.mp:mempool-add
   mempool (bl.ser:transaction-hash tx)
   (bl.mp:make-entry-from-tx
    tx fee height :entry-time (bl.ser:get-unix-time))))

(test mempool-ancestor-descendant-chain
  "An A->B->C chain reports correct ancestor/descendant sets and stats."
  (let* ((mempool (bl.mp:make-mempool))
         (a (make-mempool-test-tx :input-id 90))
         (atxid (bl.ser:transaction-hash a))
         (b (make-spending-test-tx atxid))
         (btxid (bl.ser:transaction-hash b))
         (c (make-spending-test-tx btxid))
         (ctxid (bl.ser:transaction-hash c)))
    (is (eq :ok (%add-tx mempool a)))
    (is (eq :ok (%add-tx mempool b)))
    (is (eq :ok (%add-tx mempool c)))
    (is (= 2 (hash-table-count (bl.mp:mempool-ancestors mempool ctxid))))
    (is (= 3 (nth-value 0 (bl.mp:mempool-ancestor-stats mempool ctxid))))
    (is (= 2 (hash-table-count (bl.mp:mempool-descendants mempool atxid))))
    (is (= 3 (nth-value 0 (bl.mp:mempool-descendant-stats mempool atxid))))))

(test mempool-cluster-count-limit
  "Acceptance is bounded by the 64-tx cluster limit (cluster mempool P6): a
64-long chain — far past the old 25-ancestor limit, which is RPC-reporting-
only now — is accepted in full, and the 65th link is rejected with
:too-large-cluster, leaving the graph non-oversized (the staged addition is
rolled back)."
  (let* ((mempool (bl.mp:make-mempool))
         (root (make-mempool-test-tx :input-id 91))
         (prev-txid (bl.ser:transaction-hash root))
         (last-result (%add-tx mempool root))
         (accepted 1))
    (loop for i from 2 to 65
          while (eq last-result :ok)
          do (let ((child (make-spending-test-tx prev-txid)))
               (setf last-result (%add-tx mempool child))
               (when (eq last-result :ok)
                 (incf accepted)
                 (setf prev-txid (bl.ser:transaction-hash child)))))
    (is (= 64 accepted))
    (is (eq last-result :too-large-cluster))
    (is (= 64 (bl.mp:mempool-count mempool)))
    (is-false (bl.mp:txgraph-oversized-p
               (bl.mp:mempool-graph mempool)))))

(test mempool-cluster-size-limit
  "Acceptance is bounded by the cluster vsize limit: a chain whose total
vsize would exceed *cluster-size-limit* is rejected at the tx that crosses
it, and a single tx alone over the limit is rejected outright. (The limit is
bound low here; the graph's limits are fixed at make-mempool time.)"
  (let* ((mempool (let ((bl.mp:*cluster-size-limit* 200))
                    (bl.mp:make-mempool)))
         (a (make-mempool-test-tx :input-id 97))
         (atxid (bl.ser:transaction-hash a))
         (b (make-spending-test-tx atxid))
         (btxid (bl.ser:transaction-hash b))
         (c (make-spending-test-tx btxid)))
    ;; Each test tx is 95 vB: A (95) and B (190 total) fit under 200,
    ;; C (285 total) does not.
    (is (eq :ok (%add-tx mempool a)))
    (is (eq :ok (%add-tx mempool b)))
    (is (eq :too-large-cluster (%add-tx mempool c)))
    (is (= 2 (bl.mp:mempool-count mempool)))
    (is-false (bl.mp:txgraph-oversized-p
               (bl.mp:mempool-graph mempool))))
  ;; A single transaction larger than the cluster size limit.
  (let ((mempool (let ((bl.mp:*cluster-size-limit* 50))
                   (bl.mp:make-mempool))))
    (is (eq :too-large-cluster
            (%add-tx mempool (make-mempool-test-tx :input-id 98))))
    (is (= 0 (bl.mp:mempool-count mempool)))))

(test mempool-remove-recursive-test
  "Removing a tx removes all of its descendants."
  (let* ((mempool (bl.mp:make-mempool))
         (a (make-mempool-test-tx :input-id 92))
         (atxid (bl.ser:transaction-hash a))
         (b (make-spending-test-tx atxid))
         (btxid (bl.ser:transaction-hash b))
         (c (make-spending-test-tx btxid)))
    (%add-tx mempool a) (%add-tx mempool b) (%add-tx mempool c)
    (is (= 3 (bl.mp:mempool-count mempool)))
    (is (= 3 (bl.mp:mempool-remove-recursive mempool atxid)))
    (is (= 0 (bl.mp:mempool-count mempool)))))

(test mempool-chained-spend-coins
  "mempool-extra-coins resolves an input spending an unconfirmed parent output,
recording it at the spend height (tip+1) — Core treats every mempool prevout
as confirming in the next block for BIP68 (validation.cpp:185-192)."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (a (make-mempool-test-tx :input-id 93))
         (atxid (bl.ser:transaction-hash a))
         (b (make-spending-test-tx atxid)))
    (%add-tx mempool a)
    (multiple-value-bind (coins ok)
        (bl.val::mempool-extra-coins b utxo mempool 201)
      (is-true ok)
      (let ((coin (gethash (cons atxid 0) coins)))
        (is (not (null coin)))
        (is (= 201 (bl.store:utxo-entry-height coin)))))))

(test mempool-eviction-removes-descendants
  "Evicting a low-fee parent also removes its in-mempool child (no orphan):
the CPFP pair shares one chunk, evicted as a unit."
  (let* ((mempool (bl.mp:make-mempool :max-size 1500)) ; 2 txs = 1392 usage, 3 = 2080
         (a (make-mempool-test-tx :input-id 95))
         (atxid (bl.ser:transaction-hash a))
         (b (make-spending-test-tx atxid))
         (btxid (bl.ser:transaction-hash b))
         (c (make-mempool-test-tx :input-id 96))
         (ctxid (bl.ser:transaction-hash c)))
    ;; B fee-bumps A, so [A B] forms one chunk whose feerate is still below
    ;; C's — it is the worst chunk, evicted whole.
    (is (eq :ok (%add-tx mempool a :fee 100)))
    (is (eq :ok (%add-tx mempool b :fee 5000)))
    ;; High-fee C forces eviction; the [A B] chunk goes together.
    (%add-tx mempool c :fee 100000)
    (is (not (bl.mp:mempool-has mempool atxid)))
    (is (not (bl.mp:mempool-has mempool btxid)))
    (is (bl.mp:mempool-has mempool ctxid))))

(test mempool-eviction-worst-chunk-cpfp-protection
  "TrimToSize evicts the globally WORST CHUNK: a standalone middling tx goes
before a CPFP pair whose merged chunk feerate beats it (the high-fee child
protects its low-fee parent), and the rolling minimum fee rises to exactly
the evicted chunk's feerate plus the incremental relay fee (Core TrimToSize
+ trackPackageRemoved)."
  (let* ((mempool (bl.mp:make-mempool :max-size 1500)) ; 2 txs = 1392 usage, 3 = 2080
         (p (make-mempool-test-tx :input-id 101))
         (ptxid (bl.ser:transaction-hash p))
         (c (make-spending-test-tx ptxid))
         (ctxid (bl.ser:transaction-hash c))
         (m (make-mempool-test-tx :input-id 102))
         (mtxid (bl.ser:transaction-hash m))
         (m-vsize (bl.ser:transaction-vsize m)))
    ;; P alone (100 sat / 95 vB) is far worse than M (2000 sat / 95 vB), but
    ;; child C (20000 sat) absorbs P into one chunk at ~105 sat/vB - so the
    ;; worst chunk is [M], not [P ...].
    (is (eq :ok (%add-tx mempool p :fee 100)))
    (is (eq :ok (%add-tx mempool m :fee 2000)))
    (is (eq :ok (%add-tx mempool c :fee 20000)))     ; triggers the trim
    (is (not (bl.mp:mempool-has mempool mtxid)))
    (is (bl.mp:mempool-has mempool ptxid))
    (is (bl.mp:mempool-has mempool ctxid))
    ;; Rolling minimum fee: evicted chunk feerate (sat/kvB, truncated) +
    ;; incremental relay fee (100 sat/kvB).
    (is (= (+ (truncate (* 2000 1000) m-vsize) 100)
           (%rolling-min-fee mempool)))))

(test mempool-full-self-eviction-bumps-rolling-fee
  "A newcomer whose own chunk is the worst evicts itself (Core: add, trim,
then \"mempool full\" when the tx is gone) - and still bumps the rolling
minimum fee past its feerate, so an equal-feerate retry cannot loop."
  (let* ((mempool (bl.mp:make-mempool :max-size 800)) ; one tx = 704 usage bytes
         (rich (make-mempool-test-tx :input-id 103))
         (poor (make-mempool-test-tx :input-id 104))
         (poor-vsize (bl.ser:transaction-vsize poor)))
    (is (eq :ok (%add-tx mempool rich :fee 50000)))
    (is (eq :mempool-full (%add-tx mempool poor :fee 30)))
    (is (bl.mp:mempool-has
         mempool (bl.ser:transaction-hash rich)))
    (is (not (bl.mp:mempool-has
              mempool (bl.ser:transaction-hash poor))))
    (is (= (+ (truncate (* 30 1000) poor-vsize) 100)
           (%rolling-min-fee mempool)))))

;;;; PR4 RBF (BIP125)

(defun %rbf-tx (input-id &key (sequence #xfffffffd) (value 50000000))
  "A tx spending outpoint (INPUT-ID-hash, 0) with the given input SEQUENCE."
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element input-id)
                                    :index 0)
                  :script-sig (make-array 4 :element-type '(unsigned-byte 8) :initial-element 0)
                  :sequence sequence))
   :outputs (vector (bl.ser:make-tx-out
                   :value value
                   :script-pubkey (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)))
                                    (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                                          (aref s 23) #x88 (aref s 24) #xac) s)))
   :lock-time 0))

(test rbf-signaling-detection
  "tx-signals-rbf-p reads the BIP125 opt-in sequence."
  (is-true (bl.mp:tx-signals-rbf-p (%rbf-tx 1 :sequence #xfffffffd)))
  (is-false (bl.mp:tx-signals-rbf-p (%rbf-tx 1 :sequence #xffffffff))))

(test rbf-find-conflicts
  "find-rbf-conflicts returns every mempool tx spending a shared outpoint."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 100))
         (orig-txid (bl.ser:transaction-hash orig)))
    (%add-tx mempool orig :fee 1000)
    (is (equal (list orig-txid)
               (bl.mp:find-rbf-conflicts mempool (%rbf-tx 100 :value 40000000))))))

(test rbf-rules-fee-and-signaling
  "BIP125 rules: higher fee replaces; lower fee and non-signaling are rejected."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 100 :sequence #xfffffffd))
         (orig-txid (bl.ser:transaction-hash orig))
         (repl (%rbf-tx 100 :sequence #xfffffffd :value 40000000))
         (rvsize (bl.ser:transaction-vsize repl))
         (rweight (bl.ser:transaction-weight repl)))
    (%add-tx mempool orig :fee 1000)
    ;; Rule 3/4 pass: a clearly higher fee.
    (multiple-value-bind (ok reason replaced)
        (bl.mp:check-rbf-rules mempool repl 50000 rvsize rweight
                               (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))
    ;; Rule 3 fail: fee below the original's.
    (multiple-value-bind (ok reason)
        (bl.mp:check-rbf-rules mempool repl 500 rvsize rweight
                               (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))))

(test rbf-full-rbf-unconditional
  "Cluster mempool drops BIP125 rule 1: a NON-signaling mempool tx is
replaceable regardless of *mempool-full-rbf* (Core validation.cpp:490 — the
accept path never consults SignalsOptInRBF; IsRBFOptIn survives for RPC only)."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 101 :sequence #xffffffff))   ; non-signaling (final)
         (orig-txid (bl.ser:transaction-hash orig))
         (repl (%rbf-tx 101 :sequence #xffffffff :value 40000000))
         (rvsize (bl.ser:transaction-vsize repl))
         (rweight (bl.ser:transaction-weight repl)))
    (%add-tx mempool orig :fee 1000)
    ;; Replacing the non-signaling original succeeds on a strictly better fee,
    ;; with *mempool-full-rbf* NIL (the default).
    (is (null bl.mp:*mempool-full-rbf*))
    (multiple-value-bind (ok reason replaced)
        (bl.mp:check-rbf-rules mempool repl 50000 rvsize rweight
                               (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))))

;;;; Diagram RBF (cluster mempool P7 — Core policy/rbf.cpp ImprovesFeerateDiagram
;;;; + ReplacementChecks, ported from src/test/rbf_tests.cpp). check-rbf-rules
;;;; now: drops rules 1/2 (full-RBF unconditional), keeps rules 3/4, redefines
;;;; rule 5 (100-distinct-cluster cap only), and requires the replacement to
;;;; strictly improve the mempool feerate diagram.

(defun %rbf-chain (mempool root-id length &key (fee 10000))
  "Add a chain of LENGTH txs rooted at a fresh %rbf-tx(ROOT-ID) into MEMPOOL
(each tx spends its predecessor's output 0). Returns the root txid."
  (let* ((root (%rbf-tx root-id))
         (root-txid (bl.ser:transaction-hash root))
         (prev-txid root-txid))
    (%add-tx mempool root :fee fee)
    (loop repeat (1- length)
          for child = (make-spending-test-tx prev-txid)
          for child-txid = (bl.ser:transaction-hash child)
          do (%add-tx mempool child :fee fee)
             (setf prev-txid child-txid))
    root-txid))

(test rbf-diagram-accepts-strict-improvement
  "A replacement paying a strictly higher feerate improves the diagram and is
accepted; the replaced set is the conflict."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 130))
         (orig-txid (bl.ser:transaction-hash orig))
         (repl (%rbf-tx 130 :value 40000000))
         (rvsize (bl.ser:transaction-vsize repl))
         (rweight (bl.ser:transaction-weight repl)))
    (%add-tx mempool orig :fee 1000)
    (multiple-value-bind (ok reason replaced)
        (bl.mp:check-rbf-rules mempool repl 50000 rvsize rweight
                               (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))))

(test rbf-diagram-rejects-non-improvement
  "Rules 3 and 4 can pass while the diagram does NOT strictly improve: a
replacement paying slightly more total fee but at a far lower feerate (much
larger vsize) is rejected :replacement-failed (Core ImprovesFeerateDiagram
failure, rbf.cpp:136-138)."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 131))
         (orig-txid (bl.ser:transaction-hash orig))
         (repl (%rbf-tx 131 :value 40000000)))
    (%add-tx mempool orig :fee 1000)
    ;; new-fee 1100 >= 1000 (rule 3 ok) and additional 100 == bandwidth for a
    ;; 1000-vbyte replacement (rule 4 ok), but the huge vsize makes the new
    ;; chunk's feerate far worse than the original's — the diagram is not
    ;; strictly better.
    (multiple-value-bind (ok reason)
        (bl.mp:check-rbf-rules mempool repl 1100 1000 4000 (list orig-txid))
      (is-false ok)
      (is (eq reason :replacement-failed)))))

(test rbf-rule3-and-rule4-survive
  "Rule 3 (pay >= replaced fees) and rule 4 (pay own bandwidth at the
incremental relay fee) still reject before the diagram is consulted."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 132))
         (orig-txid (bl.ser:transaction-hash orig))
         (repl (%rbf-tx 132 :value 40000000))
         (rvsize (bl.ser:transaction-vsize repl))
         (rweight (bl.ser:transaction-weight repl)))
    (%add-tx mempool orig :fee 10000)
    ;; Rule 3: fee below the replaced fee.
    (multiple-value-bind (ok reason)
        (bl.mp:check-rbf-rules mempool repl 9000 rvsize rweight
                               (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))
    ;; Rule 4: fee above the replaced fee but not by enough to cover the
    ;; replacement's own bandwidth (needs at least ceil(rvsize*100/1000) extra).
    (multiple-value-bind (ok reason)
        (bl.mp:check-rbf-rules mempool repl (1+ 10000) rvsize rweight
                               (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))))

(test rbf-rule5-cluster-cap
  "Rule 5: conflicting directly with more than 100 distinct clusters is
rejected :too-many-clusters (Core GetUniqueClusterCount > MAX_REPLACEMENT_
CANDIDATES, rbf.cpp:69-74). 100 distinct clusters is allowed."
  (let* ((mempool (bl.mp:make-mempool))
         (conflicts '()))
    ;; 101 independent singleton-cluster txs, each on its own outpoint
    ;; (%rbf-tx's input-id fills a (unsigned-byte 8) array, so ids stay <= 255).
    (loop for i from 1 to 101
          for tx = (%rbf-tx i)
          do (%add-tx mempool tx :fee 1000)
             (push (bl.ser:transaction-hash tx) conflicts))
    (let ((cand (%rbf-tx 200)))
      ;; 101 distinct conflicting clusters => rejected.
      (multiple-value-bind (ok reason)
          (bl.mp:check-rbf-rules
           mempool cand 100000000 (bl.ser:transaction-vsize cand)
           (bl.ser:transaction-weight cand) conflicts)
        (is-false ok)
        (is (eq reason :too-many-clusters)))
      ;; Dropping one leaves exactly 100 => the cluster cap is satisfied (and,
      ;; paying a huge fee over singletons, the replacement is accepted).
      (multiple-value-bind (ok reason)
          (bl.mp:check-rbf-rules
           mempool cand 100000000 (bl.ser:transaction-vsize cand)
           (bl.ser:transaction-weight cand) (rest conflicts))
        (declare (ignore reason))
        (is-true ok)))))

(test rbf-rule5-gates-the-descendant-expansion
  "Rule 5 is consulted BEFORE the conflict set is expanded to its descendants,
which is the whole point of Core's arrangement: GetEntriesForConflicts
(rbf.cpp:58-83) tests GetUniqueClusterCount and returns its error string
first, and only then runs the CalculateDescendants loop, under the comment
naming the cluster cap as the bound on that loop.

The two orders produce the SAME verdict, so this observes the ORDER and not
the result: MEMPOOL-DESCENDANTS -- the per-conflict walk %RBF-REPLACED-SET
performs, and the only caller of it on this path -- is instrumented, and a
candidate rejected by rule 5 must leave it uncalled. The accepted candidate
one cluster below the cap is the positive control: it MUST reach the walk, so
an instrumentation that never fires cannot pass this vacuously. Both the
single-transaction and the package entry point are checked."
  (let* ((mempool (bl.mp:make-mempool))
         (conflicts '())
         (walks 0)
         (real (fdefinition 'bl.mp:mempool-descendants)))
    ;; 101 independent singleton-cluster txs, one per outpoint.
    (loop for i from 1 to 101
          for tx = (%rbf-tx i)
          do (%add-tx mempool tx :fee 1000)
             (push (bl.ser:transaction-hash tx) conflicts))
    (unwind-protect
         (let ((cand (%rbf-tx 200)))
           (setf (fdefinition 'bl.mp:mempool-descendants)
                 (lambda (&rest args) (incf walks) (apply real args)))
           ;; 101 clusters: rule 5 rejects, and nothing was expanded.
           (multiple-value-bind (ok reason)
               (bl.mp:check-rbf-rules mempool cand 100000000
                                      (bl.ser:transaction-vsize cand)
                                      (bl.ser:transaction-weight cand)
                                      conflicts)
             (is-false ok)
             (is (eq reason :too-many-clusters)))
           (is (zerop walks)
               "rule 5 rejected the replacement after ~D descendant walks had already run"
               walks)
           ;; Positive control: 100 clusters clears the cap, and the same
           ;; instrumentation does fire.
           (multiple-value-bind (ok reason)
               (bl.mp:check-rbf-rules mempool cand 100000000
                                      (bl.ser:transaction-vsize cand)
                                      (bl.ser:transaction-weight cand)
                                      (rest conflicts))
             (declare (ignore reason))
             (is-true ok))
           (is (= 100 walks)
               "the accepted replacement expanded ~D of its 100 conflicts" walks)
           ;; The package path has the same arrangement.
           (setf walks 0)
           (multiple-value-bind (ok reason)
               (bl.mp:check-package-rbf-rules mempool 1000 100 400
                                              100000000 100 400 conflicts)
             (is-false ok)
             (is (eq reason :too-many-clusters)))
           (is (zerop walks)
               "package rule 5 rejected after ~D descendant walks had already run"
               walks)
           (bl.mp:check-package-rbf-rules mempool 1000 100 400
                                          100000000 100 400 (rest conflicts))
           (is (= 100 walks)
               "the package that cleared the cap expanded ~D of its 100 conflicts"
               walks))
      (setf (fdefinition 'bl.mp:mempool-descendants) real))))

(test rbf-rule5-no-transaction-count-cap
  "Rule 5 bounds only the DISTINCT CLUSTER count; there is no cap on how many
transactions those clusters hold (the old 500-tx gather cap was ours alone —
Core's GatherClusters cap serves the mini-miner fee estimator,
node/mini_miner.cpp:66, and GetEntriesForConflicts, rbf.cpp:58-83, checks
only GetUniqueClusterCount). Replacing the root of a multi-tx cluster is
decided by the economics, not a transaction-count bound."
  (let* ((mempool (bl.mp:make-mempool))
         ;; One conflicting cluster of 5 chained txs.
         (root-txid (%rbf-chain mempool 150 5 :fee 10000))
         (cand (%rbf-tx 150 :value 40000000)))   ; conflicts with the root
    (multiple-value-bind (ok reason replaced)
        (bl.mp:check-rbf-rules
         mempool cand 100000000 (bl.ser:transaction-vsize cand)
         (bl.ser:transaction-weight cand) (list root-txid))
      (declare (ignore reason))
      (is-true ok)
      ;; The whole 5-tx chain (root + descendants) is the replaced set.
      (is (= 5 (hash-table-count replaced))))))

(test rbf-diagram-uncalculable-is-too-large-cluster
  "When the staged replacement would form an over-limit cluster the diagram is
uncalculable and the replacement is rejected :too-large-cluster (Core
CheckMemPoolPolicyLimits failing before ImprovesFeerateDiagram)."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 160))
         (orig-txid (bl.ser:transaction-hash orig))
         (repl (%rbf-tx 160 :value 40000000)))
    (%add-tx mempool orig :fee 1000)
    ;; Rules 3/4 pass (huge fee), but a 200000-vbyte candidate is 800000 WU
    ;; against the 404000-WU cluster size limit, so the diagram is
    ;; uncalculable.
    (multiple-value-bind (ok reason)
        (bl.mp:check-rbf-rules mempool repl 200000 200000 800000
                               (list orig-txid))
      (is-false ok)
      (is (eq reason :too-large-cluster)))))

;;;; PR5 CPFP eviction

(test mempool-cpfp-eviction-protects-parent
  "Eviction ranks by descendant-package fee-rate: a high-fee child protects its
low-fee parent, so a cheaper standalone tx is evicted first."
  (let* ((mempool (bl.mp:make-mempool :max-size 2200)) ; 3 txs = 2080 usage, 4 = 2768
         (s (make-mempool-test-tx :input-id 110))        ; standalone, low fee
         (stxid (bl.ser:transaction-hash s))
         (p (make-mempool-test-tx :input-id 111))        ; parent, low fee
         (ptxid (bl.ser:transaction-hash p))
         (c (make-spending-test-tx ptxid))                     ; child, high fee (CPFP)
         (ctxid (bl.ser:transaction-hash c))
         (n (make-mempool-test-tx :input-id 112))        ; incoming, medium fee
         (ntxid (bl.ser:transaction-hash n)))
    (is (eq :ok (%add-tx mempool s :fee 100)))
    (is (eq :ok (%add-tx mempool p :fee 100)))
    (is (eq :ok (%add-tx mempool c :fee 50000)))
    ;; Adding N forces eviction; the cheapest package (standalone S) is dropped,
    ;; while the CPFP'd P<-C package survives despite P's low individual fee.
    (%add-tx mempool n :fee 10000)
    (is (not (bl.mp:mempool-has mempool stxid)))
    (is (bl.mp:mempool-has mempool ptxid))
    (is (bl.mp:mempool-has mempool ctxid))
    (is (bl.mp:mempool-has mempool ntxid))))

;;;; BIP339 wtxid getdata serving

(defun %witness-tx-for-relay ()
  "A segwit tx (has a witness stack) so its wtxid differs from its txid."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 77)
                                      :index 0)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
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
  (let* ((mempool (bl.mp:make-mempool))
         (tx (%witness-tx-for-relay))
         (txid (bl.ser:transaction-hash tx))
         (wtxid (bl.ser:transaction-wtxid tx)))
    (is (not (equalp txid wtxid)))                 ; witness tx: distinct ids
    (%add-tx mempool tx)
    (is-true (bl.mp:mempool-get-by-wtxid mempool wtxid))
    (is (null (bl.mp:mempool-get-by-wtxid mempool txid)))
    (is (null (bl.mp:mempool-get mempool wtxid)))))

(test make-tx-message-witness-flag
  "make-tx-message :witness serializes a segwit tx in BIP144 form (00 01 marker
after the version); the default (MSG_TX) path strips witness. A non-witness tx
uses the legacy form regardless."
  (let* ((tx (%witness-tx-for-relay))
         (wit (bl.ser:make-tx-message tx :witness t))
         (leg (bl.ser:make-tx-message tx)))
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
  "Orphans are indexed under each input's parent txid; remove clears the
index. The pool is wtxid-keyed (Core TxOrphanage) — for this witnessless tx
wtxid == txid."
  (let* ((pool (bl.mp:make-orphan-pool))
         (parent (%txid-array 50))
         (o (make-spending-test-tx parent))
         (owtxid (bl.ser:transaction-wtxid o)))
    (is-true (bl.mp:orphan-add pool o nil))
    (is (= 1 (bl.mp:orphan-pool-count pool)))
    (is (member owtxid (bl.mp:orphans-depending-on pool parent) :test #'equalp))
    (is-true (bl.mp:orphan-have pool owtxid))
    (is (bl.mp:orphan-remove pool owtxid))
    (is (= 0 (bl.mp:orphan-pool-count pool)))
    (is (null (bl.mp:orphans-depending-on pool parent)))))

(test orphan-multiple-announcers
  "One orphan can carry several announcers (Core AddTx/AddAnnouncer): a
second peer's announcement doesn't duplicate the orphan, erase-for-peer
removes only that peer's announcement, and the orphan disappears with its
LAST announcer (Core EraseForPeer)."
  (let* ((pool (bl.mp:make-orphan-pool))
         (peer-a (list :a))
         (peer-b (list :b))
         (o (make-spending-test-tx (%txid-array 52)))
         (owtxid (bl.ser:transaction-wtxid o)))
    ;; First announcement stores the orphan; the second only adds an announcer.
    (is-true (bl.mp:orphan-add pool o peer-a))
    (is-false (bl.mp:orphan-add pool o peer-b))
    ;; Duplicate (wtxid, peer) announcement is a no-op.
    (is-false (bl.mp:orphan-add pool o peer-a))
    (is (= 1 (bl.mp:orphan-pool-count pool)))
    (is (= 2 (bl.mp::orphan-pool-announcement-count pool)))
    (is-true (bl.mp:orphan-have-from-peer pool owtxid peer-a))
    (is-true (bl.mp:orphan-have-from-peer pool owtxid peer-b))
    ;; peer-a disconnects: the orphan survives via peer-b.
    (is (= 1 (bl.mp:orphan-erase-for-peer pool peer-a)))
    (is (= 1 (bl.mp:orphan-pool-count pool)))
    (is-false (bl.mp:orphan-have-from-peer pool owtxid peer-a))
    ;; Last announcer goes: so does the orphan.
    (is (= 1 (bl.mp:orphan-erase-for-peer pool peer-b)))
    (is (= 0 (bl.mp:orphan-pool-count pool)))))

(test orphan-oversized-rejected
  "Orphans above max standard tx weight are never stored (Core AddTx's
MAX_STANDARD_TX_WEIGHT check — the send-big-orphans memory-exhaustion
attack)."
  (let* ((pool (bl.mp:make-orphan-pool))
         (big (bl.ser:make-transaction
               :version 1
               :inputs (vector (bl.ser:make-tx-in
                                :previous-output (bl.ser:make-outpoint
                                                  :hash (%txid-array 53) :index 0)
                                :script-sig (make-array 110000
                                                        :element-type '(unsigned-byte 8)
                                                        :initial-element 0)
                                :sequence #xFFFFFFFF))
               :outputs (vector (bl.ser:make-tx-out
                                 :value 1000
                                 :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                              :initial-element #x51)))
               :lock-time 0)))
    (is (> (bl.ser:transaction-weight big)
           bl.mp::+orphan-max-tx-weight+))
    (is-false (bl.mp:orphan-add pool big nil))
    (is (= 0 (bl.mp:orphan-pool-count pool)))))

(test orphan-eviction-is-per-peer-fair
  "A single peer flooding the orphanage cannot evict another peer's orphans
(Core LimitOrphans: eviction targets the peer with the highest DoS score,
so a peer within its own reservation is never trimmed while a flooder
exceeds its allowance). The pool ends within its global limits and only
the flooder lost announcements."
  (let ((pool (bl.mp:make-orphan-pool))
        (victim (list :victim))
        (attacker (list :attacker)))
    ;; The victim announces one modest orphan.
    (let ((vic-tx (make-spending-test-tx (%txid-array 200))))
      (is-true (bl.mp:orphan-add pool vic-tx victim))
      ;; The attacker floods well past every per-peer allowance. Announcement
      ;; latency score is 1 each (single-input txs), so the global latency
      ;; budget (3000) is the binding limit with two peers.
      (dotimes (i 3500)
        (bl.mp:orphan-add
         pool
         (make-spending-test-tx (%txid-array (mod i 250)) :vout i)
         attacker))
      ;; Global limits are enforced...
      (is (<= (bl.mp:orphan-total-latency-score pool)
              bl.mp:+max-orphanage-latency-score+))
      (is (<= (bl.mp:orphan-total-usage pool)
              (* 2 bl.mp:+reserved-orphan-weight-per-peer+)))
      ;; ...the attacker lost announcements to the trim...
      (is (< (bl.mp:orphan-announcements-from-peer pool attacker)
             3500))
      ;; ...and the victim's orphan is untouched.
      (is-true (bl.mp:orphan-have-from-peer
                pool
                (bl.ser:transaction-wtxid vic-tx)
                victim)))))

(test orphan-erase-for-block
  "Orphans included in or conflicting with a connected block are erased by
EXACT spent outpoint (Core EraseForBlock): an orphan spending a different
output of the same parent tx survives."
  (let* ((pool (bl.mp:make-orphan-pool))
         (parent (%txid-array 70))
         (conflicted (make-spending-test-tx parent :vout 0))
         (unrelated (make-spending-test-tx parent :vout 1))
         (block-tx (make-spending-test-tx parent :vout 0 :value 123456))
         (block (%mp-block (list block-tx))))
    (bl.mp:orphan-add pool conflicted (list :p))
    (bl.mp:orphan-add pool unrelated (list :p))
    (is (= 2 (bl.mp:orphan-pool-count pool)))
    ;; block-tx spends parent:0 — conflicts with CONFLICTED only.
    (is (= 1 (bl.mp:orphan-erase-for-block pool block)))
    (is-false (bl.mp:orphan-have
               pool (bl.ser:transaction-wtxid conflicted)))
    (is-true (bl.mp:orphan-have
              pool (bl.ser:transaction-wtxid unrelated)))))

(test orphan-erase-for-peer
  "orphan-erase-for-peer drops only the given peer's orphans."
  (let ((pool (bl.mp:make-orphan-pool))
        (peer-a (list :a))
        (peer-b (list :b)))
    (bl.mp:orphan-add pool (make-spending-test-tx (%txid-array 60)) peer-a)
    (bl.mp:orphan-add pool (make-spending-test-tx (%txid-array 61)) peer-b)
    (is (= 2 (bl.mp:orphan-pool-count pool)))
    (is (= 1 (bl.mp:orphan-erase-for-peer pool peer-a)))
    (is (= 1 (bl.mp:orphan-pool-count pool)))))

;;;; PR7 mempool expiry

(test mempool-expire-old-entries
  "mempool-expire removes entries older than the expiry window (with descendants)."
  (let* ((mempool (bl.mp:make-mempool))
         (a (make-mempool-test-tx :input-id 120))
         (atxid (bl.ser:transaction-hash a))
         (b (make-spending-test-tx atxid)))
    (%add-tx mempool a)
    (%add-tx mempool b)
    (is (= 2 (bl.mp:mempool-count mempool)))
    ;; Nothing expires "now".
    (is (= 0 (bl.mp:mempool-expire mempool)))
    ;; With a far-future 'now', the aged parent expires and drags its child.
    (is (= 2 (bl.mp:mempool-expire
              mempool (+ (bl.ser:get-unix-time)
                         (* bl.mp::+default-mempool-expiry-hours+ 3600)
                         1))))
    (is (= 0 (bl.mp:mempool-count mempool)))))

;;;; Mempool deferrals: dynamic rolling minimum fee

(test mempool-effective-min-fee
  "Effective min-fee (sat/kvB) is the relay floor, or the (decaying) rolling
minimum."
  (let ((mempool (bl.mp:make-mempool)))
    ;; No rolling minimum set -> relay floor (100 sat/kvB = 0.1 sat/vB, Core
    ;; DEFAULT_MIN_RELAY_TX_FEE).
    (is (= 100 (bl.mp:mempool-effective-min-fee-rate mempool)))
    ;; Set a fresh rolling minimum -> used as-is.
    (%set-rolling-min-fee mempool 5000 (bl.ser:get-unix-time))
    (is (= 5000 (bl.mp:mempool-effective-min-fee-rate mempool)))
    ;; Far in the future it decays back below the floor -> floor.
    (is (= 100 (bl.mp:mempool-effective-min-fee-rate
                mempool (+ (bl.ser:get-unix-time) (* 100 86400)))))))

;;;; Min non-witness size (65 B) + witness standardness

(defun %zbytes (n &optional (fill 0))
  (make-array n :element-type '(unsigned-byte 8) :initial-element fill))

(test mempool-rejects-tiny-nonwitness-tx
  "A transaction smaller than 65 non-witness bytes is rejected (CVE-2017-12842)."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         ;; 1 non-coinbase input (empty scriptSig) + 1 output whose
         ;; scriptPubKey is a bare OP_RETURN serializes to 61 non-witness
         ;; bytes. The output script has to be STANDARD, or the standardness
         ;; battery answers first and this test stops being about the size:
         ;; Core checks IsStandardTx at validation.cpp:808 and the size only at
         ;; :813. A single OP_RETURN is NULL_DATA, which is standard, fits the
         ;; -datacarriersize budget, and is never dust (an unspendable output's
         ;; dust threshold is 0).
         (input (bl.ser:make-tx-in
                 :previous-output (bl.ser:make-outpoint
                                   :hash (%zbytes 32 7) :index 0)
                 :script-sig (%zbytes 0) :sequence #xFFFFFFFF))
         (op-return (coerce #(#x6a) '(vector (unsigned-byte 8))))
         (output (bl.ser:make-tx-out :value 1000
                                                        :script-pubkey op-return))
         (tx (bl.ser:make-transaction
              :version 1 :inputs (vector input) :outputs (vector output) :lock-time 0)))
    (is (< (length (bl.ser:serialize-transaction tx)) 65))
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool tx utxo mempool 100)
      (is (null valid))
      (is (eq err :tx-size-small)))
    ;; The order itself, pinned: the SAME tiny transaction with a non-standard
    ;; output reports the standardness reason, because Core's IsStandardTx runs
    ;; first. This test used to use an empty scriptPubKey and so asserted the
    ;; inverted order without saying so — mempool_accept.py:302 reads the
    ;; difference.
    (let ((tiny-nonstandard
            (bl.ser:make-transaction
             :version 1 :inputs (vector input)
             :outputs (vector (bl.ser:make-tx-out
                               :value 1000 :script-pubkey (%zbytes 0)))
             :lock-time 0)))
      (is (< (length (bl.ser:serialize-transaction tiny-nonstandard)) 65))
      (is (eq :non-standard-output
              (nth-value 1 (bl.val:validate-transaction-for-mempool
                            tiny-nonstandard utxo mempool 100)))))))

(defun %witness-tx (witness-stack spk)
  "Single-input tx carrying WITNESS-STACK (a list of byte vectors). Returns
(VALUES tx spent-script-fn) where the spent output's scriptPubKey is SPK."
  (let* ((input (bl.ser:make-tx-in
                 :previous-output (bl.ser:make-outpoint
                                   :hash (%zbytes 32 9) :index 0)
                 :script-sig (%zbytes 0) :sequence #xFFFFFFFF))
         (output (bl.ser:make-tx-out :value 1000
                                                         :script-pubkey (%zbytes 25)))
         (tx (bl.ser:make-transaction
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
    (bl.val::is-witness-standard-p tx fn)))

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
  (let ((bl:*accept-datacarrier* t)
        (bl:*max-datacarrier-bytes* 83))
    ;; OP_RETURN <push 3 bytes> -> standard
    (is-true (bl.val::standard-output-script-p
              (%policy-bytes #x6a #x03 #xaa #xbb #xcc)))
    ;; OP_RETURN OP_ADD (0x93, a non-push opcode) -> nonstandard
    (is-false (bl.val::standard-output-script-p
               (%policy-bytes #x6a #x93)))
    ;; the helper directly
    (is-true (bl.val::%op-return-push-only-p
              (%policy-bytes #x6a #x03 #x01 #x02 #x03)))
    (is-true (bl.val::%op-return-push-only-p
              (%policy-bytes #x6a #x51 #x60)))            ; OP_1 .. OP_16 are pushes
    (is-false (bl.val::%op-return-push-only-p
               (%policy-bytes #x6a #x93)))
    ;; a push that overruns the script end is not push-only
    (is-false (bl.val::%op-return-push-only-p
               (%policy-bytes #x6a #x05 #x01)))))

(test bare-multisig-standard-by-default
  "Bare multisig is standard by default (Core DEFAULT_PERMIT_BAREMULTISIG=true)."
  (is-true bl:*permit-bare-multisig*)          ; default flipped to t
  (let* ((pk (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2))
         (script (concatenate '(vector (unsigned-byte 8))
                              (%policy-bytes #x51 #x21) pk (%policy-bytes #x51 #xae))))
    (is-true (bl.val::standard-output-script-p script))))

(test mempool-entry-fields-spentby-rbf
  "%mempool-entry-fields reports spentby (in-mempool children), bip125-replaceable,
and unbroadcast. A parent's spentby lists a child that spends it."
  (let* ((mempool (bl.mp:make-mempool))
         (parent (make-mempool-test-tx :input-id 200))
         (ptxid (bl.ser:transaction-hash parent)))
    (%add-tx mempool parent)
    (let* ((child (make-spending-test-tx ptxid))
           (ctxid (bl.ser:transaction-hash child)))
      (%add-tx mempool child)
      (let ((f (bl.rpc::%mempool-entry-fields
                mempool ptxid (bl.mp:mempool-get mempool ptxid))))
        (is (assoc "spentby" f :test #'string=))
        (is (assoc "bip125-replaceable" f :test #'string=))
        (is (assoc "unbroadcast" f :test #'string=))
        (is (member (bl.rpc:hash-to-hex ctxid)
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
    (is-true (bl.val::standard-output-script-p (wp #x51 #x4e #x73)))
    ;; v2 (OP_2) 32-byte program
    (is-true (bl.val::standard-output-script-p
              (concatenate '(vector (unsigned-byte 8)) (vector #x52 #x20)
                           (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))))
    ;; v16 (OP_16) 40-byte program (max)
    (is-true (bl.val::standard-output-script-p
              (concatenate '(vector (unsigned-byte 8)) (vector #x60 #x28)
                           (make-array 40 :element-type '(unsigned-byte 8) :initial-element 1))))
    ;; 41-byte program: not a witness program -> nonstandard
    (is-false (bl.val::standard-output-script-p
               (concatenate '(vector (unsigned-byte 8)) (vector #x52 #x29)
                            (make-array 41 :element-type '(unsigned-byte 8) :initial-element 1))))
    ;; irregular v0 (OP_0 push2): stays nonstandard
    (is-false (bl.val::standard-output-script-p (wp #x00 #xaa #xbb)))
    ;; RPC type names
    (is (string= "anchor" (bl.val:script-type-name (wp #x51 #x4e #x73))))
    (is (string= "witness_unknown" (bl.val:script-type-name (wp #x52 #xaa #xbb))))))

;;;; BIP431 TRUC (v3) topology

(defun %truc-tx (parent-txid &key (version 3) (vout 0) (value 40000000))
  "A v-VERSION tx spending PARENT-TXID:VOUT (make-outpoint hash is 32 bytes)."
  (let ((tx (make-spending-test-tx parent-txid :vout vout :value value)))
    (setf (bl.ser:transaction-version tx) version)
    tx))

(test single-truc-checks-topology
  "single-truc-checks (Core SingleTRUCChecks): inheritance both ways, v3 ancestor
and descendant limits of 1, and the 1000-vsize child cap."
  (let* ((mempool (bl.mp:make-mempool))
         (root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 60))
         ;; a v3 parent in the mempool
         (v3-parent (%truc-tx root :version 3))
         (v3-pid (bl.ser:transaction-hash v3-parent))
         ;; a v2 parent in the mempool
         (v2-parent (%truc-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 61)
                              :version 2))
         (v2-pid (bl.ser:transaction-hash v2-parent)))
    (%add-tx mempool v3-parent)
    (%add-tx mempool v2-parent)
    (flet ((ok (tx &optional (vsize 200) conflicts)
             (bl.mp:single-truc-checks mempool tx vsize conflicts)))
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
  (let* ((mempool (bl.mp:make-mempool))
         (root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 70))
         (parent (%truc-tx root :version 3))
         (pid (bl.ser:transaction-hash parent)))
    (%add-tx mempool parent)
    ;; first child ok, then add it
    (let* ((child1 (%truc-tx pid :version 3 :vout 0))
           (cid1 (bl.ser:transaction-hash child1)))
      (is-true (bl.mp:single-truc-checks mempool child1 200 nil))
      (%add-tx mempool child1)
      ;; a second child of the same parent -> descendant limit, with CHILD1
      ;; identified as the considerable sibling (parent has exactly one
      ;; descendant whose only ancestor is the parent).
      (multiple-value-bind (o r sibling)
          (bl.mp:single-truc-checks mempool (%truc-tx pid :version 3 :vout 1) 200 nil)
        (is-false o) (is (eq :truc-descendant-limit r))
        (is (equalp cid1 sibling)))
      ;; ... unless the existing child is being replaced anyway.
      (is-true (bl.mp:single-truc-checks
                mempool (%truc-tx pid :version 3 :vout 1) 200 (list cid1))))))

(test truc-sibling-eviction-not-considerable-with-grandchild
  "Sibling eviction is only offered in the clean 1p1c shape: a sibling that
itself has a descendant (a reorg-created shape) is NOT returned (Core
consider_sibling_eviction: GetDescendantCount(parent)==2 &&
GetAncestorCount(sibling)==2, truc_policy.cpp:250-252)."
  (let* ((mempool (bl.mp:make-mempool))
         (root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 71))
         (parent (%truc-tx root :version 3))
         (pid (bl.ser:transaction-hash parent))
         (child1 (%truc-tx pid :version 3 :vout 0))
         (cid1 (bl.ser:transaction-hash child1))
         ;; Direct adds bypass validation, building the reorg-only shape.
         (grandchild (%truc-tx cid1 :version 3 :vout 0)))
    (%add-tx mempool parent)
    (%add-tx mempool child1)
    (%add-tx mempool grandchild)
    (multiple-value-bind (o r sibling)
        (bl.mp:single-truc-checks mempool (%truc-tx pid :version 3 :vout 1) 200 nil)
      (is-false o) (is (eq :truc-descendant-limit r))
      (is (null sibling)))))

(test v3-now-standard
  "v3 is a standard tx version (TRUC enabled): +max-standard-tx-version+ = 3."
  (is (= 3 bl.val::+max-standard-tx-version+)))

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
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 170))
         (orig-txid (bl.ser:transaction-hash orig)))
    (%add-tx mempool orig :fee 1000)
    (multiple-value-bind (ok reason replaced)
        (bl.mp:check-package-rbf-rules
         mempool 10 100 400 5000 100 400 (list orig-txid))
      (declare (ignore reason))
      (is-true ok)
      (is (not (null (gethash orig-txid replaced)))))))

(test package-rbf-rules-rule3-rule4-on-totals
  "Rules 3/4 evaluate the package totals: a pair whose combined fee does not
cover the replaced fees (plus its own bandwidth) is rejected."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 171))
         (orig-txid (bl.ser:transaction-hash orig)))
    (%add-tx mempool orig :fee 10000)
    ;; Rule 3: 10 + 5000 < 10000.
    (multiple-value-bind (ok reason)
        (bl.mp:check-package-rbf-rules
         mempool 10 100 400 5000 100 400 (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))
    ;; Rule 4: totals exceed the replaced fee but not by the pair's own
    ;; bandwidth at 100 sat/kvB (needs ceil(200*100/1000) = 20 extra).
    (multiple-value-bind (ok reason)
        (bl.mp:check-package-rbf-rules
         mempool 10 100 400 10009 100 400 (list orig-txid))
      (is-false ok)
      (is (eq reason :insufficient-fee)))))

(test package-rbf-rules-feerate-must-exceed-parent
  "The package feerate must STRICTLY exceed the parent's own feerate — the
pair must be a chunk on its own, not a child merely paying anti-DoS fees
(Core validation.cpp:1104-1111). Equality is also rejected."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 172))
         (orig-txid (bl.ser:transaction-hash orig)))
    (%add-tx mempool orig :fee 100)
    ;; Parent 50 sat/vB, child 0 -> package 25 sat/vB < parent.
    (multiple-value-bind (ok reason)
        (bl.mp:check-package-rbf-rules
         mempool 5000 100 400 0 100 400 (list orig-txid))
      (is-false ok)
      (is (eq reason :package-feerate-not-above-parent)))
    ;; Equal feerates (parent 10, child 10 sat/vB) -> still rejected.
    (multiple-value-bind (ok reason)
        (bl.mp:check-package-rbf-rules
         mempool 1000 100 400 1000 100 400 (list orig-txid))
      (is-false ok)
      (is (eq reason :package-feerate-not-above-parent)))))

(test package-rbf-rules-diagram-must-improve
  "Rules 3/4 and the parent-feerate check can pass while the two-transaction
diagram does NOT strictly improve — rejected :replacement-failed."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 173))
         (orig-txid (bl.ser:transaction-hash orig)))
    ;; Original: 10 sat/vB over 100 vB.
    (%add-tx mempool orig :fee 1000)
    ;; Pair: parent 5 sat/vB + child 7 sat/vB -> one 6 sat/vB chunk over
    ;; 200 vB. Rule 3/4: 1200 >= 1000 + 20. Package feerate 6 > parent 5.
    ;; Diagram: worse than the original at size 100 (600 < 1000), better at
    ;; 200 (1200 > 1000) -> :unordered, not a strict improvement.
    (multiple-value-bind (ok reason)
        (bl.mp:check-package-rbf-rules
         mempool 500 100 400 700 100 400 (list orig-txid))
      (is-false ok)
      (is (eq reason :replacement-failed)))))

(test package-rbf-rules-cluster-caps
  "Rule 5's caps apply unchanged to the aggregate package conflicts."
  (let* ((mempool (bl.mp:make-mempool))
         (conflicts '()))
    (loop for i from 1 to 101
          for tx = (%rbf-tx i)
          do (%add-tx mempool tx :fee 1000)
             (push (bl.ser:transaction-hash tx) conflicts))
    (multiple-value-bind (ok reason)
        (bl.mp:check-package-rbf-rules
         mempool 1000 100 400 100000000 100 400 conflicts)
      (is-false ok)
      (is (eq reason :too-many-clusters)))))

(test package-rbf-rules-too-large-cluster
  "A package member breaching the cluster size limit in staging is rejected
:too-large-cluster (uncalculable diagram)."
  (let* ((mempool (bl.mp:make-mempool))
         (orig (%rbf-tx 174))
         (orig-txid (bl.ser:transaction-hash orig)))
    (%add-tx mempool orig :fee 1000)
    (multiple-value-bind (ok reason)
        (bl.mp:check-package-rbf-rules
         mempool 1000 100 400 100000000 200000 800000 (list orig-txid))
      (is-false ok)
      (is (eq reason :too-large-cluster)))))

;;;; Wave 7: sigop-adjusted virtual size (Core GetVirtualTransactionSize,
;;;; policy.cpp:376-384; CTxMemPoolEntry::GetTxSize)

(defun %unit-tx (prev-hash witness-len)
  "A one-input, one-output segwit transaction spending PREV-HASH:0 whose
WITNESS-LEN witness bytes move its weight by ONE unit each. Weight is
3*base + total (BIP141), so a witness byte is the only way a transaction's
weight stops being a multiple of four -- which is the whole window in which
sigop-adjusted vbytes and sigop-adjusted weight can disagree."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint :hash prev-hash :index 0)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence #xFFFFFFFD))
   :outputs (vector (bl.ser:make-tx-out
                     :value 1000
                     :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                   :initial-element #x51)))
   :witness (vector (list (make-array witness-len :element-type '(unsigned-byte 8)
                                                  :initial-element 1)))
   :lock-time 0))

(defun %graph-size-of (mempool txid)
  "The size the txgraph holds for the mempool entry TXID, in the graph's own
unit."
  (bl.mp:feefrac-size
   (bl.mp:txgraph-get-individual-feerate
    (bl.mp:mempool-graph mempool)
    (bl.mp:mempool-entry-graph-handle (bl.mp:mempool-get mempool txid)))))

(test sigop-adjusted-weight-matches-core
  "max(weight, sigops * DEFAULT_BYTES_PER_SIGOP) with NO division -- Core
GetSigOpsAdjustedWeight (policy.cpp:376-379) and CTxMemPoolEntry's
GetAdjustedWeight (kernel/mempool_entry.h:114). The vsize beside it is this
value divided by four, rounding up, which is why the division must not happen
first."
  (is (= 400 (bl.mp:sigop-adjusted-weight 400 0)))
  (is (= 401 (bl.mp:sigop-adjusted-weight 401 0)))
  (is (= 403 (bl.mp:sigop-adjusted-weight 403 0)))
  ;; The sigop branch: 30 sigops * 20 = 600 dominates a weight of 400.
  (is (= 600 (bl.mp:sigop-adjusted-weight 400 30)))
  (is (= 400 (bl.mp:sigop-adjusted-weight 400 20)))
  ;; And the vsize is exactly this rounded up, never the other way round.
  (dolist (pair '((400 0) (401 0) (403 0) (400 30) (400 20)))
    (destructuring-bind (w sigops) pair
      (is (= (bl.mp:sigop-adjusted-vsize w sigops)
             (ceiling (bl.mp:sigop-adjusted-weight w sigops) 4))))))

(test mempool-stages-sigop-adjusted-weight-into-the-txgraph
  "GA11 ed2f2295. Core's TxGraph works in WEIGHT throughout: StageAddition
builds FeePerWeight(fee, GetSigOpsAdjustedWeight(...)) (txmempool.cpp:1017)
and MakeTxGraph is handed cluster_size_vbytes * WITNESS_SCALE_FACTOR
(:179-181), with the division to virtual bytes happening only at the consumer
boundary (ToFeePerVSize, policy/policy.h:196). Feeding the graph vbytes
instead applies the per-transaction ceiling BEFORE the cross-multiplied
feerate comparisons.

Both the weight-dominated and the sigop-dominated entry are checked, and each
asserts the staged size is NOT the vsize as well as that it IS the weight, so
a unit that happened to coincide cannot pass this."
  (let* ((mempool (bl.mp:make-mempool))
         (plain (%unit-tx (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 11)
                          1))
         (plain-txid (bl.ser:transaction-hash plain)))
    (bl.mp:mempool-add mempool plain-txid
                       (bl.mp:make-entry-from-tx plain 1000 0))
    (let ((entry (bl.mp:mempool-get mempool plain-txid)))
      (is (= (bl.ser:transaction-weight plain)
             (bl.mp:mempool-entry-graph-weight entry)))
      (is (= (bl.mp:mempool-entry-graph-weight entry)
             (%graph-size-of mempool plain-txid)))
      (is (/= (bl.mp:mempool-entry-vsize entry)
              (%graph-size-of mempool plain-txid))
          "the txgraph was fed the entry's virtual size, not its weight"))
    ;; A sigop-dominated entry takes the max() branch: 40 sigops * 20 = 800
    ;; weight units, well past this transaction's own weight.
    (let* ((dense (%unit-tx (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 12)
                            1))
           (dense-txid (bl.ser:transaction-hash dense)))
      (bl.mp:mempool-add mempool dense-txid
                         (bl.mp:make-entry-from-tx dense 1000 0 :sigops 40))
      (let ((entry (bl.mp:mempool-get mempool dense-txid)))
        (is (= 800 (bl.mp:mempool-entry-graph-weight entry)))
        (is (= 800 (%graph-size-of mempool dense-txid)))
        (is (= 200 (bl.mp:mempool-entry-vsize entry)))))))

(test mempool-chunks-a-cpfp-pair-core-does-not-split
  "GA11 ed2f2295, executed case 1: a chunk BOUNDARY, not merely a tie order.

Parent and child pay the same fee and round to the same sigop-adjusted VSIZE,
but the child's weight is strictly smaller, so in Core's unit its feerate is
strictly higher and the pair chunks together; in virtual bytes the two
feerates are equal, the merge is not a strict improvement, and the cluster
stays two chunks. The eviction set follows: TXGRAPH-GET-WORST-MAIN-CHUNK
hands the trimmer the child ALONE where Core evicts the parent-and-child
pair, and the rolling minimum fee is computed from whichever it returns.

The premise is asserted first, so a change to the fixture that lost the
equal-vsize/different-weight shape would fail here rather than silently make
the rest vacuous."
  (let* ((mempool (bl.mp:make-mempool))
         (parent (%unit-tx (make-array 32 :element-type '(unsigned-byte 8)
                                          :initial-element 21)
                           3))
         (parent-txid (bl.ser:transaction-hash parent))
         (child (%unit-tx parent-txid 1))
         (child-txid (bl.ser:transaction-hash child)))
    ;; Premise: same vsize, child strictly lighter.
    (is (= (bl.mp:sigop-adjusted-vsize (bl.ser:transaction-weight parent) 0)
           (bl.mp:sigop-adjusted-vsize (bl.ser:transaction-weight child) 0))
        "the fixture pair no longer shares a virtual size")
    (is (< (bl.ser:transaction-weight child) (bl.ser:transaction-weight parent))
        "the fixture child is no longer the lighter of the two")
    (bl.mp:mempool-add mempool parent-txid
                       (bl.mp:make-entry-from-tx parent 100 0))
    (bl.mp:mempool-add mempool child-txid
                       (bl.mp:make-entry-from-tx child 100 0))
    (let ((chunks (bl.mp:txgraph-get-cluster-chunks
                   (bl.mp:mempool-graph mempool)
                   (bl.mp:mempool-entry-graph-handle
                    (bl.mp:mempool-get mempool parent-txid)))))
      (is (= 1 (length chunks))
          "the CPFP pair was split into ~D chunks; Core forms one"
          (length chunks)))
    (multiple-value-bind (handles feerate)
        (bl.mp:txgraph-get-worst-main-chunk (bl.mp:mempool-graph mempool))
      (is (= 2 (length handles))
          "eviction would drop ~D of the pair; Core evicts both together"
          (length handles))
      (is (= 200 (bl.mp:feefrac-fee feerate)))
      (is (= (+ (bl.ser:transaction-weight parent)
                (bl.ser:transaction-weight child))
             (bl.mp:feefrac-size feerate))))))

(test mempool-mining-order-follows-fee-per-weight
  "GA11 ed2f2295, executed case 2: a strict mining-order FLIP, not a tie
broken by the fallback.

X pays 1005 over 345 weight units and Y 1000 over 344. In Core's unit X's
feerate is the higher and X mines first; rounded to virtual bytes (87 and 86)
Y's is, and the two orders are both strict, so this is not the txid fallback
deciding a tie."
  (let* ((mempool (bl.mp:make-mempool))
         (x (%unit-tx (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 31)
                      1))
         (y (%unit-tx (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 32)
                      0))
         (x-txid (bl.ser:transaction-hash x))
         (y-txid (bl.ser:transaction-hash y)))
    (is (= 1 (- (bl.ser:transaction-weight x) (bl.ser:transaction-weight y)))
        "the fixture pair no longer differs by exactly one weight unit")
    (bl.mp:mempool-add mempool x-txid (bl.mp:make-entry-from-tx x 1005 0))
    (bl.mp:mempool-add mempool y-txid (bl.mp:make-entry-from-tx y 1000 0))
    (let ((graph (bl.mp:mempool-graph mempool)))
      ;; Negative means X sorts EARLIER in mining order.
      (is (= -1 (bl.mp:txgraph-compare-main-order
                 graph
                 (bl.mp:mempool-entry-graph-handle
                  (bl.mp:mempool-get mempool x-txid))
                 (bl.mp:mempool-entry-graph-handle
                  (bl.mp:mempool-get mempool y-txid))))
          "Y mines before X, which is the fee-per-vbyte order, not Core's")
      ;; The worst chunk is the other one, which is the same statement from
      ;; the eviction end.
      (multiple-value-bind (handles) (bl.mp:txgraph-get-worst-main-chunk graph)
        (is (equalp y-txid (bl.mp:tx-handle-data (first handles))))))))

(test txgraph-cluster-cap-is-core-weight-units
  "GA11 ed2f2295, executed case 3: the cluster size limit was strictly
STRICTER than Core's, because each transaction's vsize was rounded up
individually before the sum. A 64-transaction cluster of total weight 403812
WU is well inside Core's 404000 (cluster_size_vbytes * WITNESS_SCALE_FACTOR,
txmempool.cpp:179-181), and its per-transaction vbytes summed to 101001
against a 101000 cap -- an admission Core accepts, rejected as
:too-large-cluster. The window is up to 3 WU per transaction, so at 64
transactions the old cap was up to 192 WU tight.

The chain at exactly the cap, and the one unit past it, are the two controls:
without them a graph that is never oversized would pass the first assertion."
  (flet ((chain (total-weight)
           ;; 64 transactions in one cluster, total weight TOTAL-WEIGHT, each
           ;; weight congruent to 1 mod 4 as the survey's fixture was.
           (let* ((mempool (bl.mp:make-mempool))
                  (graph (bl.mp:mempool-graph mempool))
                  (each (- (floor total-weight 64) (mod (floor total-weight 64) 4) -1))
                  (last (- total-weight (* 63 each)))
                  (prev nil))
             (dotimes (i 64)
               (let ((h (bl.mp:txgraph-add-transaction
                         graph 1000 (if (= i 63) last each)
                         ;; The graph's fallback order reads this payload as a
                         ;; txid, so it must be one.
                         (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element i))))
                 (when prev (bl.mp:txgraph-add-dependency graph prev h))
                 (setf prev h)))
             (bl.mp:txgraph-oversized-p graph))))
    (is-false (chain 403812)
              "a 403812-WU cluster is inside Core's 404000 cap and must be accepted")
    (is-false (chain 404000) "the cap itself must be accepted")
    (is-true (chain 404004) "one transaction past the cap must be oversized")))

(test sigop-adjusted-vsize-matches-core
  "ceil(max(weight, sigops * DEFAULT_BYTES_PER_SIGOP) / 4), hand-checked
against Core's arithmetic."
  ;; weight dominates: plain BIP141 vsize, with Core's ceiling division.
  (is (= 100 (bl.mp:sigop-adjusted-vsize 400 0)))
  (is (= 101 (bl.mp:sigop-adjusted-vsize 401 0)))
  (is (= 101 (bl.mp:sigop-adjusted-vsize 404 0)))
  ;; tie: 20 sigops * 20 = 400 = weight.
  (is (= 100 (bl.mp:sigop-adjusted-vsize 400 20)))
  ;; sigops dominate: 100 * 20 / 4 = 500; 1 * 20 / 4 = 5.
  (is (= 500 (bl.mp:sigop-adjusted-vsize 400 100)))
  (is (= 5 (bl.mp:sigop-adjusted-vsize 0 1))))

(test entry-vsize-is-sigop-adjusted
  "make-entry-from-tx records the sigop-adjusted virtual size: unchanged for
plain txs, max(weight, sigops*20)/4 when the sigop cost dominates — the size
Core's entry reports and mines by (CTxMemPoolEntry::GetTxSize)."
  (let* ((tx (make-mempool-test-tx :input-id 97))
         (weight (bl.ser:transaction-weight tx))
         (plain (bl.mp:make-entry-from-tx tx 1000 0))
         (dense (bl.mp:make-entry-from-tx tx 1000 0 :sigops 400)))
    (is (= (bl.ser:transaction-vsize tx)
           (bl.mp:mempool-entry-vsize plain)))
    (is (< weight (* 400 20)))          ; sigops dominate for this tiny tx
    (is (= 2000 (bl.mp:mempool-entry-vsize dense)))))

;;;; Wave 9C: modeled dynamic memory usage (Core DynamicMemoryUsage)

(test dynamic-usage-models-core-formula
  "The mempool cap is keyed on Core's malloc-modeled DYNAMIC MEMORY USAGE,
computed as a formula over transaction structure (core_memusage.h /
memusage.h / txmempool.cpp:778-782, 64-bit): for the 1-in/1-out test tx
(both scripts within the 36-byte prevector direct storage) the entry usage
is MallocUsage(sizeof CTransaction=128) + MallocUsage(shared counter=24) +
MallocUsage(1*sizeof CTxIn=112) + MallocUsage(1*sizeof CTxOut=48) =
144+48+128+64 = 384; the pool adds per-entry mapTx (224), per-input
mapNextTx (64) and the txns_randomized vector on top."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 230))
         (entry (make-mempool-entry-for-tx tx)))
    ;; MallocUsage: 16 bytes overhead rounded up to a 16-byte boundary; 0 -> 0.
    (is (= 0 (bl.mp::malloc-usage 0)))
    (is (= 32 (bl.mp::malloc-usage 1)))
    (is (= 48 (bl.mp::malloc-usage 24)))
    (is (= 144 (bl.mp::malloc-usage 128)))
    ;; Entry usage (Core CTxMemPoolEntry::nUsageSize).
    (is (= 384 (bl.mp:transaction-dynamic-usage tx)))
    (is (= 384 (bl.mp:mempool-entry-usage entry)))
    ;; Empty pool models zero.
    (is (= 0 (bl.mp:mempool-dynamic-usage mempool)))
    ;; One entry: 224 (mapTx node) + 64 (mapNextTx per input) +
    ;; MallocUsage(16) = 32 (txns_randomized) + 384 (inner) = 704.
    (bl.mp:mempool-add
     mempool (bl.ser:transaction-hash tx) entry)
    (is (= 704 (bl.mp:mempool-dynamic-usage mempool)))
    ;; Second identical-shape entry: 2*224 + 2*64 + MallocUsage(32)=48 + 768.
    (let ((tx2 (make-mempool-test-tx :input-id 231)))
      (bl.mp:mempool-add
       mempool (bl.ser:transaction-hash tx2)
       (make-mempool-entry-for-tx tx2))
      (is (= 1392 (bl.mp:mempool-dynamic-usage mempool))))
    ;; A prioritisation delta for an absent txid adds one mapDeltas node (96).
    (bl.mp:mempool-prioritise
     mempool (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99)
     500)
    (is (= (+ 1392 96) (bl.mp:mempool-dynamic-usage mempool)))
    ;; Removal restores the previous number exactly.
    (bl.mp:mempool-remove
     mempool (bl.ser:transaction-hash tx))
    (is (= (+ 704 96) (bl.mp:mempool-dynamic-usage mempool)))))

(test dynamic-usage-counts-witness-and-large-scripts
  "Witness stacks and over-36-byte scripts allocate in Core's model: each
witness stack costs MallocUsage(items * 24) plus MallocUsage(len) per
non-empty item (core_memusage.h:20-26); scripts within the prevector's
36-byte direct storage cost nothing, longer ones MallocUsage(len)."
  ;; %witness-tx-for-relay: 1-in/1-out (384) + stack of one 4-byte item:
  ;; MallocUsage(24) = 48 outer + MallocUsage(4) = 32 item -> 464.
  (is (= 464 (bl.mp:transaction-dynamic-usage
              (%witness-tx-for-relay))))
  ;; A 37-byte scriptPubKey exceeds direct storage: + MallocUsage(37) = 64.
  (let ((base (make-mempool-test-tx :input-id 232)))
    (flet ((tx-with-spk (n)
             (bl.ser:make-transaction
              :version 1
              :inputs (bl.ser:transaction-inputs base)
              :outputs (vector (bl.ser:make-tx-out
                                :value 50000000
                                :script-pubkey (make-array
                                                n :element-type '(unsigned-byte 8)
                                                :initial-element 0)))
              :lock-time 0)))
      (is (= 384 (bl.mp:transaction-dynamic-usage (tx-with-spk 36))))
      (is (= (+ 384 64)
             (bl.mp:transaction-dynamic-usage (tx-with-spk 37)))))))

(test maxmempool-default-is-core-decimal-mb
  "-maxmempool is a MEMORY cap: DEFAULT_MAX_MEMPOOL_SIZE_MB{300} * 1'000'000
decimal bytes (Core kernel/mempool_options.h:19,40), not 300 MiB, and not
wire bytes."
  (is (= 300000000 bl.mp:+default-max-mempool-bytes+)))

(test rolling-fee-halflife-shortens-when-pool-underfull
  "The rolling minimum fee's 12h half-life divides by 4 while the pool's
dynamic usage sits below 1/4 of the cap (Core GetMinFee,
txmempool.cpp:836-840), and a rolling rate decayed below half the
incremental relay fee resets to zero (txmempool.cpp:845-848)."
  (let ((mempool (bl.mp:make-mempool))
        (now (bl.ser:get-unix-time)))
    ;; Empty pool -> usage 0 < cap/4 -> halflife 43200/4 = 10800. One full
    ;; 43200 s window is then FOUR half-lives: 16000 -> 1000.
    (%set-rolling-min-fee mempool 16000 now)
    (is (= 1000 (bl.mp:mempool-effective-min-fee-rate
                 mempool (+ now 43200))))
    ;; Decayed below incremental/2 (= 50): resets the slot to 0 and the
    ;; relay floor applies.
    (is (= 100 (bl.mp:mempool-effective-min-fee-rate
                mempool (+ now (* 20 43200)))))
    (is (= 0 (%rolling-min-fee mempool)))))

(test getmempoolinfo-reports-usage-and-vsize-bytes
  "getmempoolinfo: \"bytes\" is the summed sigop-adjusted VIRTUAL size (Core
GetTotalTxSize, txmempool.h:191) and \"usage\" the modeled DynamicMemoryUsage
(rpc/mempool.cpp:1040-1041)."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 233))
         (entry (make-mempool-entry-for-tx tx)))
    (bl.mp:mempool-add
     mempool (bl.ser:transaction-hash tx) entry)
    (is (= (bl.mp:mempool-entry-vsize entry)
           (bl.mp:mempool-total-size mempool)))
    (is (= 704 (bl.mp:mempool-dynamic-usage mempool)))))

;;;; ============================================================
;;;; GA7 wave 2: mempool relay-policy parity with Bitcoin Core
;;;; ============================================================

(defun %spk (&rest bytes)
  (make-array (length bytes) :element-type '(unsigned-byte 8)
                             :initial-contents bytes))

(defun %push-script (push-len first-byte trailer)
  "A script: <push-len> <first-byte> <padding..> <trailer>."
  (let ((s (make-array (+ 2 push-len) :element-type '(unsigned-byte 8)
                                      :initial-element 0)))
    (setf (aref s 0) push-len
          (aref s 1) first-byte
          (aref s (+ 1 push-len)) trailer)
    s))

(test classify-script-returns-solver-data
  "The second value of CLASSIFY-SCRIPT is Solver's vSolutionsRet as a plist:
the hash forms carry :hash, every witness program carries its version and
program (P2A included), nulldata its payload, pubkey its key, and bare
multisig m, n and the keys in script order. The one classifier now feeds
decodescript, the descriptor address printer and the wallet, so the plist
shape is a contract."
  (flet ((spk (&rest bytes) (coerce bytes '(simple-array (unsigned-byte 8) (*))))
         (cat (&rest parts) (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) parts))
         (fill-bytes (n v) (make-array n :element-type '(unsigned-byte 8) :initial-element v)))
    (let ((h20 (fill-bytes 20 7)) (h32 (fill-bytes 32 9)))
      (multiple-value-bind (type data) (bl.val:classify-script (cat (spk #x76 #xa9 #x14) h20 (spk #x88 #xac)))
        (is (eq :pubkeyhash type)) (is (equalp h20 (getf data :hash))))
      (multiple-value-bind (type data) (bl.val:classify-script (cat (spk #xa9 #x14) h20 (spk #x87)))
        (is (eq :scripthash type)) (is (equalp h20 (getf data :hash))))
      (multiple-value-bind (type data) (bl.val:classify-script (cat (spk #x51 #x20) h32))
        (is (eq :witness-v1-taproot type))
        (is (= 1 (getf data :witness-version)))
        (is (equalp h32 (getf data :witness-program))))
      (multiple-value-bind (type data) (bl.val:classify-script (spk #x51 #x02 #x4e #x73))
        (is (eq :anchor type))
        (is (equalp (spk #x4e #x73) (getf data :witness-program))))
      (multiple-value-bind (type data) (bl.val:classify-script (spk #x6a #x02 #xaa #xbb))
        (is (eq :nulldata type)) (is (equalp (spk #x02 #xaa #xbb) (getf data :data))))
      ;; An OP_RETURN whose tail is not push-only is NONSTANDARD, not nulldata:
      ;; the retired classifier said nulldata for any leading OP_RETURN.
      (is (eq :nonstandard (bl.val:classify-script (spk #x6a #xac))))
      ;; A 33-byte push whose header byte is not 02/03 is not a pubkey (Core
      ;; CPubKey::ValidSize); the retired classifier took any 33/65-byte push.
      (is (eq :nonstandard (bl.val:classify-script (cat (spk 33 #x04) (fill-bytes 32 1) (spk #xac)))))
      (multiple-value-bind (type data) (bl.val:classify-script (cat (spk 33 #x02) (fill-bytes 32 1) (spk #xac)))
        (is (eq :pubkey type)) (is (= 33 (length (getf data :pubkey)))))
      ;; 1-of-2 bare multisig: keys come back in script order.
      (let* ((k1 (cat (spk #x02) (fill-bytes 32 1)))
             (k2 (cat (spk #x03) (fill-bytes 32 2))))
        (multiple-value-bind (type data) (bl.val:classify-script (cat (spk #x51 33) k1 (spk 33) k2 (spk #x52 #xae)))
          (is (eq :multisig type))
          (is (= 1 (getf data :m))) (is (= 2 (getf data :n)))
          (is (equalp (list k1 k2) (getf data :pubkeys)))))
      ;; A key push whose header byte is not a pubkey header fails MatchMultisig
      ;; (Core checks CPubKey::ValidSize on every key).
      (let ((bad (cat (spk #x00) (fill-bytes 32 1))))
        (is (eq :nonstandard (bl.val:classify-script (cat (spk #x51 33) bad (spk #x51 #xae))))))
      ;; The type name is the classification's name: one table, not two.
      (is (string= "anchor" (bl.val:script-type-name (spk #x51 #x02 #x4e #x73))))
      (is (string= "witness_unknown" (bl.val:script-type-name (cat (spk #x52 #x20) h32))))
      (is (string= "nonstandard" (bl.val:script-type-name (cat (spk #x00 #x10) (fill-bytes 16 3))))))))

(test classify-script-solver-parity
  "G7-12/13: classify-script mirrors Core's Solver (solver.cpp:141),
including the order in which the forms are matched."
  (flet ((c (s) (bl.val:classify-script s)))
    ;; P2SH is matched first, before anything else.
    (is (eq :scripthash
            (c (let ((s (make-array 23 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #xa9 (aref s 1) #x14 (aref s 22) #x87) s))))
    ;; Witness programs.
    (is (eq :witness-v0-keyhash
            (c (let ((s (make-array 22 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #x00 (aref s 1) #x14) s))))
    (is (eq :witness-v0-scripthash
            (c (let ((s (make-array 34 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #x00 (aref s 1) #x20) s))))
    (is (eq :witness-v1-taproot
            (c (let ((s (make-array 34 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #x51 (aref s 1) #x20) s))))
    (is (eq :anchor (c (%spk #x51 #x02 #x4e #x73))))
    ;; v2..v16 and odd-sized v1 are the forward-compatible class.
    (is (eq :witness-unknown
            (c (let ((s (make-array 34 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #x52 (aref s 1) #x20) s))))
    (is (eq :witness-unknown
            (c (let ((s (make-array 22 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #x51 (aref s 1) #x14) s))))
    ;; An IRREGULAR v0 program is NONSTANDARD, never witness-unknown — the
    ;; asymmetry that makes this classifier necessary.
    (is (eq :nonstandard
            (c (let ((s (make-array 24 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #x00 (aref s 1) #x16) s))))
    ;; OP_RETURN, matched before the bare key forms.
    (is (eq :nulldata (c (%spk #x6a #x02 #xaa #xbb))))
    ;; Bare pay-to-pubkey, both encodings.
    (is (eq :pubkey (c (%push-script 33 #x02 #xac))))
    (is (eq :pubkey (c (%push-script 33 #x03 #xac))))
    (is (eq :pubkey (c (%push-script 65 #x04 #xac))))
    (is (eq :pubkey (c (%push-script 65 #x06 #xac))))
    (is (eq :pubkey (c (%push-script 65 #x07 #xac))))
    ;; Header byte must AGREE with the length (CPubKey::ValidSize).
    (is (eq :nonstandard (c (%push-script 33 #x04 #xac))))
    (is (eq :nonstandard (c (%push-script 65 #x02 #xac))))
    ;; ...and the script must end in OP_CHECKSIG.
    (is (eq :nonstandard (c (%push-script 33 #x02 #xad))))
    (is (eq :pubkeyhash
            (c (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                       :initial-element 0)))
                 (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                       (aref s 23) #x88 (aref s 24) #xac)
                 s))))
    (is (eq :nonstandard (c (%spk #x51))))          ; bare OP_TRUE
    (is (eq :nonstandard (c (%spk))))))             ; empty

(test g7-13-bare-p2pk-output-is-standard
  "G7-13: Core's IsStandard accepts TxoutType::PUBKEY unconditionally
(solver.cpp:190-192, policy.cpp:79-97). We classified bare P2PK NONSTANDARD
and so refused to relay transactions the whole network relays."
  (is-true (bl.val::standard-output-script-p
            (%push-script 33 #x02 #xac)))
  (is-true (bl.val::standard-output-script-p
            (%push-script 65 #x04 #xac)))
  ;; A malformed pubkey script stays nonstandard.
  (is-false (bl.val::standard-output-script-p
             (%push-script 33 #x04 #xac))))

(test g7-12-multisig-shape-vs-output-standardness
  "Core's Solver classifies MULTISIG by SHAPE (up to 16 keys); the n<=3 cap is
an IsStandard rule for OUTPUTS only. An input SPENDING a bigger bare multisig
is still standard, so the two must not share one predicate."
  (flet ((ms (m n)   ; OP_m <n 33-byte pushes> OP_n OP_CHECKMULTISIG
           (let ((s (make-array (+ 1 (* n 34) 2) :element-type '(unsigned-byte 8)
                                                 :initial-element 0)))
             (setf (aref s 0) (+ #x50 m))
             ;; each key: a 33-byte push whose header byte is a compressed
             ;; pubkey's (Core MatchMultisig checks CPubKey::ValidSize)
             (dotimes (i n)
               (setf (aref s (+ 1 (* i 34))) 33
                     (aref s (+ 2 (* i 34))) #x02))
             (setf (aref s (- (length s) 2)) (+ #x50 n)
                   (aref s (- (length s) 1)) #xae)
             s)))
    ;; Shape matches well past the standardness cap.
    (is (eq :multisig (bl.val:classify-script (ms 1 1))))
    (is (eq :multisig (bl.val:classify-script (ms 2 3))))
    (is (eq :multisig (bl.val:classify-script (ms 5 5))))
    (is (eq :multisig (bl.val:classify-script (ms 15 15))))
    ;; But only n<=3 is a standard OUTPUT.
    (let ((bl:*permit-bare-multisig* t))
      (is-true (bl.val::standard-output-script-p (ms 2 3)))
      (is-false (bl.val::standard-output-script-p (ms 4 4))))
    ;; -permitbaremultisig=0 rejects even the small ones — but through
    ;; IsStandardTx, not IsStandard: Core applies that gate in the output loop
    ;; (policy.cpp:151-153) so it can report "bare-multisig" rather than
    ;; "scriptpubkey". STANDARD-OUTPUT-SCRIPT-P is IsStandard alone and so
    ;; keeps answering for the SHAPE regardless of the knob.
    (let ((bl:*permit-bare-multisig* nil))
      (is-true (bl.val::standard-output-script-p (ms 2 3)))
      (is (eq :bare-multisig
              (nth-value 1 (bl.val::%is-standard-tx
                            (%tx-with-output-script (ms 2 3)))))))))

(test g7-12-nonstandard-and-unknown-witness-inputs-rejected
  "G7-12 (Core AreInputsStandard, policy.cpp:224-232): spending a NONSTANDARD
or WITNESS_UNKNOWN prevout is rejected. Both are standard as OUTPUTS and only
nonstandard to SPEND — we relayed txs every Core peer rejects."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (p2pkh (let ((s (make-array 25 :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
                  (setf (aref s 0) #x76 (aref s 1) #xa9 (aref s 2) #x14
                        (aref s 23) #x88 (aref s 24) #xac)
                  s))
         (bare-true (%spk #x51))                       ; NONSTANDARD prevout
         (v2-program (let ((s (make-array 34 :element-type '(unsigned-byte 8)
                                            :initial-element 0)))
                       (setf (aref s 0) #x52 (aref s 1) #x20) s))  ; WITNESS_UNKNOWN
         (p2pk (%push-script 33 #x02 #xac)))
    (flet ((spend (id)
             (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output
                               (bl.ser:make-outpoint
                                :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element id)
                                :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xFFFFFFFF))
              :outputs (vector (bl.ser:make-tx-out
                                :value 10000 :script-pubkey p2pkh))
              :lock-time 0))
           (err-of (tx)
             (nth-value 1 (bl.val:validate-transaction-for-mempool
                           tx utxo mempool 100))))
      (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 1)
                                     0 100000 bare-true 0)
      (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 2)
                                     0 100000 v2-program 0)
      (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 3)
                                     0 100000 p2pk 0)
      (is (eq :nonstandard-inputs (err-of (spend 1))) "bare OP_TRUE prevout")
      (is (eq :nonstandard-inputs (err-of (spend 2))) "unknown witness version prevout")
      ;; A bare-P2PK prevout is perfectly standard to spend — it must NOT be
      ;; caught by the same gate.
      (is (not (eq :nonstandard-inputs (err-of (spend 3)))) "bare P2PK prevout"))))

(test bip54-legacy-sigop-relay-cap
  "BIP54 (Core CheckSigopsBIP54, policy.cpp:169-190; MAX_TX_LEGACY_SIGOPS
2,500): legacy sigops counted where they execute — each scriptSig plus the
spent scriptPubKey's count for it, the redeem script's for P2SH — may not
exceed 2,500 per transaction. 167 P2SH inputs whose redeem script carries 15
CHECKSIGs (the per-input P2SH maximum) total 2,505 and are refused as
nonstandard inputs; 166 total 2,490 and pass this gate (they then fail
script verification, which is a different error)."
  (let* ((mempool (bl.mp:make-mempool))
         (utxo (bl.store:make-utxo-set))
         (redeem (%w8d-script (make-list 15 :initial-element #xac)))   ; 15 x OP_CHECKSIG
         (spk (%w8d-script #xa9 #x14 (bl.crypto:hash160 redeem) #x87))
         (script-sig (%w8d-script (length redeem) redeem))            ; one canonical push
         (p2pkh (%p2pkh-spk))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (dotimes (i 167)
      (bl.store:add-utxo utxo txid i 100000 spk 0))
    (flet ((spend (n)
             (bl.ser:make-transaction
              :version 2
              :inputs (coerce (loop for i below n
                                    collect (bl.ser:make-tx-in
                                             :previous-output
                                             (bl.ser:make-outpoint
                                              :hash txid :index i)
                                             :script-sig script-sig
                                             :sequence #xFFFFFFFF))
                              'simple-vector)
              :outputs (vector (bl.ser:make-tx-out
                                :value 10000 :script-pubkey p2pkh))
              :lock-time 0))
           (err-of (tx)
             (nth-value 1 (bl.val:validate-transaction-for-mempool
                           tx utxo mempool 100))))
      (is (eq :nonstandard-inputs (err-of (spend 167))) "2,505 legacy sigops")
      (is (not (eq :nonstandard-inputs (err-of (spend 166)))) "2,490 legacy sigops"))))

(test g7-14-p2a-witness-stuffing-nonstandard
  "G7-14 (Core IsWitnessStandard, policy.cpp:268-271): spending a pay-to-anchor
output never needs witness data, so ANY witness on a P2A spend is stuffing.
It matters beyond bloat — a stuffed variant shares the clean spend's TXID, so
admitting it makes the clean spend bounce as :already-in-mempool, which is the
anchor-pinning this rule prevents."
  (let ((p2a (%spk #x51 #x02 #x4e #x73))
        (p2wpkh (let ((s (make-array 22 :element-type '(unsigned-byte 8)
                                        :initial-element 0)))
                  (setf (aref s 0) #x00 (aref s 1) #x14) s))
        (empty (make-array 0 :element-type '(unsigned-byte 8)))
        (stuffing (list (make-array 1 :element-type '(unsigned-byte 8)
                                      :initial-element #x51))))
    ;; Any witness at all on a P2A spend is nonstandard.
    (is-false (bl.val::input-witness-standard-p stuffing p2a empty))
    ;; The same witness on a normal P2WPKH spend is fine.
    (is-true (bl.val::input-witness-standard-p stuffing p2wpkh empty))))

(test g7-36-disconnect-pool-is-bounded
  "G7-36 (Core LimitMemoryUsage): the reorg disconnect pool is capped, and it
trims the blocks NEAREST THE OLD TIP. Direction is the point — the re-add
walks oldest-first, so the survivors must be parents; dropping the oldest
would strand children with missing inputs."
  (let ((cap bl.val::+max-disconnected-tx-pool-bytes+))
    ;; Under the cap: nothing is touched.
    (multiple-value-bind (kept bytes dropped)
        (bl.val::trim-disconnect-pool
         (list (cons '(:a) 10) (cons '(:b) 20)) 30)
      (is (equal '(((:a) . 10) ((:b) . 20)) kept))
      (is (= 30 bytes))
      (is (= 0 dropped)))
    ;; Over the cap: the TAIL (newest) goes first, the head (oldest) survives.
    (let* ((oldest (cons '(:old1 :old2) (floor cap 2)))
           (newer (cons '(:new1) cap))
           (newest (cons '(:tip1 :tip2 :tip3) cap)))
      (multiple-value-bind (kept bytes dropped)
          (bl.val::trim-disconnect-pool
           (list oldest newer newest) (+ (cdr oldest) (cdr newer) (cdr newest)))
        (is (equal (list oldest) kept) "only the oldest block survives")
        (is (= (cdr oldest) bytes))
        (is (= 4 dropped) "3 tip txs + 1 from the middle block")))
    ;; Never trims to empty, even when one block alone exceeds the cap.
    (multiple-value-bind (kept bytes dropped)
        (bl.val::trim-disconnect-pool
         (list (cons '(:only) (* 2 cap))) (* 2 cap))
      (is (= 1 (length kept)))
      (is (= (* 2 cap) bytes))
      (is (= 0 dropped)))))

;;;; --- mempool.dat interoperability with Bitcoin Core ----------------------

(defun %mp-key8 (&rest bytes)
  "An 8-byte obfuscation key as the typed vector OBFUSCATE! requires — a bare
#(...) literal is a SIMPLE-VECTOR and fails its declared key type."
  (make-array (length bytes) :element-type '(unsigned-byte 8)
                             :initial-contents bytes))

(defun %core-mempool-fixture-bytes (tx-bytes &key (key (%mp-key8 1 2 3 4 5 6 7 8))
                                                  (entry-time 1700000000)
                                                  (fee-delta 0))
  "A one-transaction Core mempool.dat, assembled BYTE BY BYTE from the layout
in node/mempool_persist.cpp rather than by calling our own writer.

A round-trip against our own writer proves nothing about interoperability — it
would pass just as happily if both halves were wrong together. This is the
oracle: if Core's layout is what this function builds, and our reader parses
it, then a Core dump loads here."
  (let* ((payload
           (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
             ;; u64 transaction count
             (bl.ser:write-uint64-le s 1)
             (write-sequence tx-bytes s)
             (bl.ser:write-int64-le s entry-time)
             (bl.ser:write-int64-le s fee-delta)
             ;; compact-size mapDeltas count, then the unbroadcast set
             (bl.ser:write-compact-size s 0)
             (bl.ser:write-compact-size s 0)))
         (obfuscated (copy-seq payload)))
    ;; ⚠️ The key offset is the ABSOLUTE file position (streams.cpp:25-27), and
    ;; the header is 8 bytes of version plus 9 bytes for the key's VECTOR
    ;; serialization — a compact-size 0x08 then the 8 bytes. 17 is not a
    ;; multiple of 8, so the first payload byte pairs with key byte 1.
    (bl.store:obfuscate! obfuscated key :key-offset 17)
    (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
      (bl.ser:write-uint64-le s 2)   ; MEMPOOL_DUMP_VERSION
      (bl.ser:write-compact-size s 8)
      (write-sequence key s)
      (write-sequence obfuscated s))))

(test mempool-dat-reads-a-file-laid-out-the-way-core-lays-one-out
  "importmempool exists to move a mempool between nodes, and could not: we wrote
a format of our own, so a Core dump was unreadable here and ours unreadable
there.

The fixture is assembled from Core's source layout, not from our writer."
  (let* ((tx (make-mempool-test-tx))
         (tx-bytes (bl.ser:transaction-wire-bytes tx))
         (data (%core-mempool-fixture-bytes tx-bytes :entry-time 1700000000
                                                     :fee-delta 1234)))
    (multiple-value-bind (entries residual ok unbroadcast)
        (bl.mp::read-core-mempool-file-bytes data)
      (is-true ok "a Core-format mempool.dat did not parse")
      (is (= 1 (length entries)))
      (is (null residual))
      (is (null unbroadcast))
      (destructuring-bind (parsed time delta) (first entries)
        (is (equalp (bl.ser:transaction-hash tx)
                    (bl.ser:transaction-hash parsed)))
        (is (= 1700000000 time))
        (is (= 1234 delta))))))

(test mempool-dat-header-is-exactly-cores-header
  "The three header facts that decide interoperability, asserted on the bytes:
a u64 version of 2, then the key as a VECTOR — a compact-size 0x08 and 8 bytes,
nine on disk, not eight — and payload starting at absolute offset 17."
  (let* ((tx-bytes (bl.ser:transaction-wire-bytes
                    (make-mempool-test-tx)))
         (data (%core-mempool-fixture-bytes tx-bytes)))
    ;; u64 LE version 2
    (is (equalp #(2 0 0 0 0 0 0 0) (subseq data 0 8)))
    ;; compact-size 8, then the key itself, unobfuscated
    (is (= 8 (aref data 8)))
    (is (equalp (%mp-key8 1 2 3 4 5 6 7 8) (subseq data 9 17)))
    ;; And the first payload byte is XORed with key byte 1, not key byte 0:
    ;; the transaction count's low byte is 1, and 1 XOR key[1] = 1 XOR 2 = 3.
    (is (= 3 (aref data 17))
        "the payload is obfuscated from the wrong key offset")))

(test mempool-dat-round-trips-through-our-own-writer
  "And what we write is what we read — with the same key, byte-identical to the
hand-built fixture, so the writer is pinned to the same layout as the reader."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx))
         (txid (bl.ser:transaction-hash tx))
         (entry (make-mempool-entry-for-tx tx)))
    (bl.mp:mempool-add mempool txid entry)
    (let* ((key (%mp-key8 1 2 3 4 5 6 7 8))
           (written (bl.mp::core-mempool-file-bytes mempool :key key)))
      (is (equalp #(2 0 0 0 0 0 0 0) (subseq written 0 8)))
      (is (= 8 (aref written 8)))
      (is (equalp key (subseq written 9 17)))
      (multiple-value-bind (entries residual ok) 
          (bl.mp::read-core-mempool-file-bytes written)
        (declare (ignore residual))
        (is-true ok)
        (is (= 1 (length entries)))
        (is (equalp (bl.ser:transaction-hash tx)
                    (bl.ser:transaction-hash
                     (first (first entries)))))))))

(test legacy-mempool-dat-still-loads-after-the-format-change
  "The migration guarantee, and the reason the legacy reader is kept.

Two live nodes have a mempool.dat on disk in the format this node used to
write. If the reader only understood Core's, the first restart after this
change would drop the entire mempool — and mempool reload logs nothing until it
finishes, so on a large file that is a long outage indistinguishable from a
wedge (the 2026-08-16 deploy: an 83 MB testnet4 dump, ~45 minutes of silence).

The fixture writes the OLD layout by hand, because nothing writes it any more:
  magic u32 | version u8 | count u32 |
  [tx-len u32 | tx bytes | time u64 | delta i64]* |
  residual u32 | [txid | delta]* | unbroadcast u32 | [txid]* | CRC32"
  (let* ((tx (make-mempool-test-tx))
         (tx-bytes (bl.ser:transaction-wire-bytes tx))
         (path (merge-pathnames "legacy-mempool-test.dat" (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (bl.store:save-file-with-crc32
            path
            (lambda (s)
              (bl.ser:write-uint32-le
               s bl.mp::+mempool-dat-magic+)
              (bl.ser:write-uint8 s 2)
              (bl.ser:write-uint32-le s 1)
              (bl.ser:write-uint32-le s (length tx-bytes))
              (write-sequence tx-bytes s)
              (bl.ser:write-uint64-le s 1700000001)
              (bl.ser:write-int64-le s 4321)
              (bl.ser:write-uint32-le s 0)
              (bl.ser:write-uint32-le s 0)))
           (multiple-value-bind (entries residual ok)
               (bl.mp:read-mempool-file path)
             (declare (ignore residual))
             (is-true ok "an existing legacy mempool.dat no longer loads")
             (is (= 1 (length entries)))
             (destructuring-bind (parsed time delta) (first entries)
               (is (equalp (bl.ser:transaction-hash tx)
                           (bl.ser:transaction-hash parsed)))
               (is (= 1700000001 time))
               (is (= 4321 delta)))))
      (ignore-errors (delete-file path)))))

(test mempool-dat-format-is-chosen-by-the-file-not-by-configuration
  "The two formats are told apart by their first four bytes: the legacy magic is
0x4d504c01, and a Core file opens with a u64 version of 1 or 2, so its first
four bytes are 01 00 00 00 or 02 00 00 00 and can never collide."
  (let* ((tx-bytes (bl.ser:transaction-wire-bytes
                    (make-mempool-test-tx)))
         (core-file (%core-mempool-fixture-bytes tx-bytes)))
    ;; Core's first four bytes read as the version, never as our magic.
    (is (/= bl.mp::+mempool-dat-magic+
            (logior (aref core-file 0) (ash (aref core-file 1) 8)
                    (ash (aref core-file 2) 16) (ash (aref core-file 3) 24))))
    ;; An unknown version is refused rather than guessed at, as Core refuses it
    ;; (node/mempool_persist.cpp:69).
    (let ((bogus (copy-seq core-file)))
      (setf (aref bogus 0) 99)
      (is-false (nth-value 2 (bl.mp::read-core-mempool-file-bytes bogus))))))

(test empty-mempool-dat-round-trips
  "The case the live mainnet node actually hits: it relays nothing, so its
mempool is empty and every shutdown writes an empty mempool.dat. An empty file
must still be a WELL-FORMED one — 8 bytes of version, 9 for the key record, an
8-byte zero count and two zero compact-sizes — or the next start reads a
truncated file, decides it is corrupt, and logs a scary line about it forever."
  (let* ((mempool (bl.mp:make-mempool))
         (path (merge-pathnames "empty-mempool-test.dat" (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (is (= 0 (bl.mp:save-mempool-file mempool path)))
           (multiple-value-bind (entries residual ok unbroadcast)
               (bl.mp:read-mempool-file path)
             (is-true ok "an empty mempool.dat did not read back")
             (is (null entries))
             (is (null residual))
             (is (null unbroadcast)))
           ;; 8 + 9 + 8 + 1 + 1: nothing optional is omitted.
           (with-open-file (in path :element-type '(unsigned-byte 8))
             (is (= 27 (file-length in)))))
      (ignore-errors (delete-file path)))))

;;;; ============================================================
;;;; GA10 S3: block conflicts and the rolling minimum fee
;;;; ============================================================

(test block-conflict-clears-the-conflicted-tx-prioritisation
  "A block that double-spends a prioritised mempool transaction drops its
delta with it (Core removeConflicts calls ClearPrioritisation before
removeRecursive, txmempool.cpp:395-401). A conflicted txid can never be
resubmitted, so a surviving delta is ballast forever: counted in
mempool-dynamic-usage, reported by getprioritisedtransactions, and written
to — and reloaded from — mempool.dat's residual-delta section."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 205))
         (txid (bl.ser:transaction-hash tx))
         ;; A different transaction spending the same outpoint.
         (block-tx (make-mempool-test-tx :input-id 205 :value 30000000)))
    (is (eq :ok (%add-tx mempool tx)))
    (is (= 100000 (bl.mp:mempool-prioritise mempool txid 100000)))
    (bl.mp:mempool-remove-for-block mempool (%mp-block (list block-tx)))
    (is-false (bl.mp:mempool-has mempool txid))
    (is (zerop (hash-table-count (bl.mp:mempool-deltas mempool)))
        "the conflicted tx's delta outlived it")
    (is (zerop (bl.mp:mempool-dynamic-usage mempool))
        "a residual delta keeps charging the pool's usage accounting")))

(test block-conflict-keeps-the-descendants-prioritisation
  "Only the DIRECTLY conflicting transaction loses its delta: Core clears
the one txid it hands to removeRecursive (txmempool.cpp:395-401) and
removeUnchecked never touches mapDeltas, so a descendant evicted with it
keeps its prioritisation — it spends an output that still exists, and can
be resubmitted once its parent is."
  (let* ((mempool (bl.mp:make-mempool))
         (parent (make-mempool-test-tx :input-id 206))
         (parent-txid (bl.ser:transaction-hash parent))
         (child (make-spending-test-tx parent-txid))
         (child-txid (bl.ser:transaction-hash child))
         (block-tx (make-mempool-test-tx :input-id 206 :value 30000000)))
    (is (eq :ok (%add-tx mempool parent)))
    (is (eq :ok (%add-tx mempool child)))
    (bl.mp:mempool-prioritise mempool parent-txid 100000)
    (bl.mp:mempool-prioritise mempool child-txid 7000)
    (bl.mp:mempool-remove-for-block mempool (%mp-block (list block-tx)))
    (is (zerop (bl.mp:mempool-count mempool)))
    (is-false (gethash parent-txid (bl.mp:mempool-deltas mempool)))
    (is (eql 7000 (gethash child-txid (bl.mp:mempool-deltas mempool))))))

(defun %trimmed-mempool (now)
  "A mempool whose rolling minimum has just been bumped by a real trim at
NOW: an 800-byte pool holding one 704-byte transaction, after a newcomer
that evicted itself. Returns the pool and the surviving transaction's txid."
  (let* ((mempool (bl.mp:make-mempool :max-size 800))
         (rich (make-mempool-test-tx :input-id 211))
         (poor (make-mempool-test-tx :input-id 212))
         (bl.ser:*mock-time* now))
    (is (eq :ok (%add-tx mempool rich :fee 50000)))
    (is (eq :mempool-full (%add-tx mempool poor :fee 300)))
    (values mempool (bl.ser:transaction-hash rich))))

(test rolling-min-fee-does-not-decay-before-a-block
  "The bump freezes the rolling minimum until a block connects: Core's
trackPackageRemoved clears blockSinceLastRollingFeeBump (txmempool.cpp:
853-858) and GetMinFee returns the UNDECAYED rate while it is clear
(:831-832), which is what makes TrimToSize's promise hold — \"we don't allow
txn to enter mempool with feerate equal to txn which were removed with no
block in between\". removeForBlock then restarts the clock (:426-427)."
  (let* ((t0 1700000000)
         (mempool (%trimmed-mempool t0))
         (bumped (%rolling-min-fee mempool)))
    (is (plusp bumped))
    ;; Twelve hours pass with no block: the floor has not moved.
    (is (= bumped (bl.mp:mempool-decayed-rolling-min-fee-rate
                   mempool (+ t0 43200)))
        "the floor decayed with no block since the bump")
    ;; A block — carrying a transaction the pool never held — starts it.
    (let ((bl.ser:*mock-time* t0))
      (bl.mp:mempool-remove-for-block
       mempool (%mp-block (list (make-mempool-test-tx :input-id 213)))))
    ;; 704 of 800 bytes in use, so this interval runs at the full 12 h
    ;; half-life.
    (is (= (floor (+ (/ bumped 2) 1/2))
           (bl.mp:mempool-decayed-rolling-min-fee-rate
            mempool (+ t0 43200)))
        "a connected block did not restart the decay")))

(test rolling-min-fee-decays-at-the-half-life-that-was-in-force
  "Core's GetMinFee decays the STORED rate over the interval since its last
step and writes both back (txmempool.cpp:842-843), so the shortened
half-life of a drained pool applies only to the interval it is drained for.
Recomputing from the original bump instead would apply the current
half-life retroactively to hours the pool spent full."
  (let ((t0 1700000000))
    (multiple-value-bind (mempool rich-txid) (%trimmed-mempool t0)
      (let ((bumped (%rolling-min-fee mempool)))
        (let ((bl.ser:*mock-time* t0))
          (bl.mp:mempool-remove-for-block
           mempool (%mp-block (list (make-mempool-test-tx :input-id 214)))))
        ;; Twelve hours at 704/800 bytes: one full half-life, one halving.
        (is (= (floor (+ (/ bumped 2) 1/2))
               (bl.mp:mempool-decayed-rolling-min-fee-rate
                mempool (+ t0 43200))))
        ;; Now the pool empties, which shortens the half-life to 3 h for the
        ;; NEXT interval only — the twelve hours already elapsed keep the
        ;; half-life they ran under.
        (bl.mp:mempool-remove mempool rich-txid)
        (is (zerop (bl.mp:mempool-dynamic-usage mempool)))
        (is (= (floor (+ (/ bumped 4) 1/2))
               (bl.mp:mempool-decayed-rolling-min-fee-rate
                mempool (+ t0 43200 10800)))
            "the shortened half-life was applied to the hours the pool was full")))))

(test rolling-min-fee-answers-zero-after-an-enormous-gap
  "A gap wide enough to take the decay factor out of the double range answers
0 rather than signalling, the way Core's `rate / pow(2.0, dt/halflife)` does:
the divisor is an infinity, the rate goes to zero, and the reset below half
the incremental relay fee clears the slot (txmempool.cpp:842-848). Worth
pinning because SBCL traps floating-point overflow by default in arithmetic
it compiles inline — EXPT hands back the infinity instead, so the ported
expression can keep Core's shape."
  (let ((t0 1700000000)
        (mempool (bl.mp:make-mempool)))
    (%set-rolling-min-fee mempool 16000 t0)
    ;; An empty pool decays at a 3 h half-life, so 400 days is ~3200 of them
    ;; and 2^3200 is not a double.
    (is (zerop (bl.mp:mempool-decayed-rolling-min-fee-rate
                mempool (+ t0 (* 400 86400)))))
    (is (zerop (%rolling-min-fee mempool)))))

;;;; -persistmempool / -persistmempoolv1 (finding 212b060f)
;;;;
;;;; Core reads the flag once (ShouldPersistMempool,
;;;; node/mempool_persist_args.cpp:13-16) and gates BOTH drive sites with it:
;;;; the startup LoadMempool (init.cpp:2047, an EMPTY path rather than a
;;;; skipped call) and the shutdown DumpMempool (init.cpp:338-340, which also
;;;; requires GetLoadTried).

(test persistmempoolv1-writes-cores-version-1-layout
  "-persistmempoolv1 selects MEMPOOL_DUMP_VERSION_NO_XOR_KEY: the version word
alone, then an UNOBFUSCATED payload -- Core DumpMempool writes no key record and
calls SetObfuscation({}) on that branch (node/mempool_persist.cpp:181-191). The
version-2 write is the positive control: without it a writer that emitted
nothing at all would satisfy every assertion below."
  (let* ((mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx))
         (txid (bl.ser:transaction-hash tx))
         (key (%mp-key8 1 2 3 4 5 6 7 8)))
    (bl.mp:mempool-add mempool txid (make-mempool-entry-for-tx tx))
    (let ((v2 (bl.mp::core-mempool-file-bytes mempool :key key :v1 nil))
          (v1 (bl.mp::core-mempool-file-bytes mempool :key key :v1 t)))
      ;; positive control: the default is still Core's version 2, key and all
      (is (equalp #(2 0 0 0 0 0 0 0) (subseq v2 0 8)))
      (is (= 8 (aref v2 8)))
      (is (equalp key (subseq v2 9 17)))
      ;; version 1: no key record at all, and the payload starts at 8
      (is (equalp #(1 0 0 0 0 0 0 0) (subseq v1 0 8)))
      (is (= (- (length v2) 9) (length v1))
          "version 1 must be exactly the nine bytes of the key record shorter")
      (is (= 1 (aref v1 8)) "the transaction count must be written in the clear")
      ;; and both round-trip through the reader, which knows both versions
      (dolist (bytes (list v1 v2))
        (multiple-value-bind (entries residual ok)
            (bl.mp::read-core-mempool-file-bytes bytes)
          (declare (ignore residual))
          (is-true ok)
          (is (equalp txid (bl.ser:transaction-hash (first (first entries))))))))))

(defun %mempool-dat-version (path)
  "The u64 version word a mempool.dat opens with: Core writes 1 under
-persistmempoolv1 and 2 otherwise."
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((head (make-array 8 :element-type '(unsigned-byte 8))))
      (read-sequence head in)
      (loop with acc = 0
            for i from 7 downto 0
            do (setf acc (+ (ash acc 8) (aref head i)))
            finally (return acc)))))

(test persist-mempool-gates-both-drive-sites
  "-persistmempool=0 must stop the startup replay AND the shutdown dump, and a
node whose replay never finished must not overwrite the dump it was reading
(Core GetLoadTried). Every branch is asserted against a real file on disk, so a
gate that returned the right NIL while still writing would fail."
  (with-temp-directory (dir)
    (let* ((node (make-test-node :network :regtest))
           (tx (make-mempool-test-tx))
           (txid (bl.ser:transaction-hash tx))
           (path (bl.mp:mempool-dat-path dir))
           (bl::*persist-mempool* t)
           (bl::*mempool-load-tried* t))
      (setf (bl:node-data-directory node) dir)
      (bl.mp:mempool-add (bl:node-mempool node) txid (make-mempool-entry-for-tx tx))
      ;; (1) positive control: on, and the replay finished => the file is written
      (is (= 1 (bl::save-mempool-at-shutdown node)))
      (is-true (probe-file path))
      (is (equal (namestring path) (namestring (bl::mempool-load-path node))))
      (is (= 2 (%mempool-dat-version path)))
      ;; (2) -persistmempoolv1 reaches the writer through the same call
      (let ((bl.mp:*persist-mempool-v1* t))
        (is (= 1 (bl::save-mempool-at-shutdown node)))
        (is (= 1 (%mempool-dat-version path))))
      ;; (3) -persistmempool=0: nothing is read and nothing is written
      (delete-file path)
      (let ((bl::*persist-mempool* nil))
        (is (null (bl::mempool-load-path node))
            "-persistmempool=0 must hand LoadMempool an empty path")
        (is (null (bl::save-mempool-at-shutdown node)))
        (is (null (probe-file path))))
      ;; (4) the replay never finished: the existing dump is left alone
      (is (= 1 (bl::save-mempool-at-shutdown node)))
      (let ((before (with-open-file (in path :element-type '(unsigned-byte 8))
                      (file-length in)))
            (bl::*mempool-load-tried* nil))
        (is (null (bl::save-mempool-at-shutdown node)))
        (is (= before (with-open-file (in path :element-type '(unsigned-byte 8))
                        (file-length in))))))))

(test persist-mempool-options-reach-start-node
  "Both names are real options now, so they feed START-NODE keywords instead of
being reported as accepted-and-ignored."
  (multiple-value-bind (plist merged)
      (start-node-plist '("-regtest" "-persistmempool=0" "-persistmempoolv1=1"))
    (is (eq nil (getf plist :persist-mempool)))
    (is (member :persist-mempool plist) "the keyword must be present, not defaulted")
    (is (eq t (getf plist :persist-mempool-v1)))
    (is (null (bl.cfg:supplied-core-only-options merged))))
  (multiple-value-bind (plist merged) (start-node-plist '("-regtest"))
    (declare (ignore merged))
    (is (not (member :persist-mempool plist))
        "an absent option must leave START-NODE's own default in force")))
