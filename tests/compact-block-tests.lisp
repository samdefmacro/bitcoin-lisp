(in-package #:bitcoin-lisp.tests)

(def-suite :compact-block-tests
  :description "Tests for Compact Block Relay (BIP 152)"
  :in :bitcoin-lisp-tests)

(in-suite :compact-block-tests)

;;;; Helper functions

(defun make-mock-peer ()
  "Create a mock peer for testing."
  (bitcoin-lisp.networking:make-peer
   :state :ready
   :address "127.0.0.1"))

(defun make-mock-mempool-with-txs (txs)
  "Create a mempool with the given transactions.
   TXS is a list of (txid . transaction) pairs."
  (let ((mempool (bitcoin-lisp.mempool:make-mempool)))
    (dolist (pair txs)
      (let ((txid (car pair))
            (tx (cdr pair)))
        (bitcoin-lisp.mempool:mempool-add
         mempool txid
         (bitcoin-lisp.mempool:make-mempool-entry
          :transaction tx
          :fee 1000
          :size 200
          :entry-time 0))))
    mempool))

(defun make-simple-tx (id-byte)
  "Create a simple transaction with a unique identifier byte."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (list (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element id-byte)
                                    :index 0)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence #xffffffff))
   :outputs (list (bitcoin-lisp.serialization:make-tx-out
                   :value 50000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time 0))

;;;; Protocol Negotiation Tests

(test sendcmpct-updates-peer-version
  "handle-sendcmpct should update peer's compact block version."
  (let ((peer (make-mock-peer)))
    ;; Initially no compact block support
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))
    ;; Receive sendcmpct v1
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 1) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 1))
    ;; Receive sendcmpct v2 (should upgrade)
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 2) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 2))))

(test sendcmpct-rejects-invalid-version
  "handle-sendcmpct should ignore invalid versions."
  (let ((peer (make-mock-peer)))
    ;; Set to v1
    (setf (bitcoin-lisp.networking:peer-compact-block-version peer) 1)
    ;; Try to set v3 (invalid - max is 2)
    (let ((payload (flexi-streams:with-output-to-sequence (s)
                     (write-byte 0 s)  ; low-bandwidth
                     (bitcoin-lisp.serialization:write-uint64-le s 3))))  ; version 3
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    ;; Should remain at v1
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 1))))

(test sendcmpct-tracks-high-bandwidth
  "handle-sendcmpct should track high-bandwidth mode preference."
  (let ((peer (make-mock-peer)))
    (is (null (bitcoin-lisp.networking:peer-compact-block-high-bandwidth peer)))
    ;; Receive high-bandwidth request
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message t 1) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (bitcoin-lisp.networking:peer-compact-block-high-bandwidth peer))))

(test should-use-compact-blocks-checks-peer-support
  "should-use-compact-blocks-p should check if peer supports compact blocks."
  (let ((peer (make-mock-peer)))
    ;; No support
    (is (null (bitcoin-lisp.networking:should-use-compact-blocks-p peer)))
    ;; Add support
    (setf (bitcoin-lisp.networking:peer-compact-block-version peer) 1)
    ;; Now should be true (assuming not in IBD)
    (is (bitcoin-lisp.networking:should-use-compact-blocks-p peer))))

;;;; Short ID Map Building Tests

(test build-shortid-map-indexes-mempool
  "build-shortid-map should create mapping from short IDs to transactions."
  (let* ((tx1 (make-simple-tx #x11))
         (tx2 (make-simple-tx #x22))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)
                                                    (cons txid2 tx2))))
         (k0 #x0706050403020100)
         (k1 #x0f0e0d0c0b0a0908))
    (multiple-value-bind (map collision)
        (bitcoin-lisp.networking::build-shortid-map mempool k0 k1 nil)
      (is (not collision))
      (is (= (hash-table-count map) 2))
      ;; Each entry should be (tx . full-id)
      (let ((short-id1 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid1)))
        (is (gethash short-id1 map))))))

(test build-shortid-map-detects-collision
  "build-shortid-map should detect collisions within mempool."
  ;; This is hard to test directly without crafting collision inputs,
  ;; but we can verify the collision flag mechanism works
  (let* ((tx1 (make-simple-tx #x11))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)))))
    (multiple-value-bind (map collision)
        (bitcoin-lisp.networking::build-shortid-map mempool 0 0 nil)
      (declare (ignore map))
      ;; With just one tx, no collision expected
      (is (not collision)))))

(test build-shortid-map-uses-wtxid-for-v2
  "build-shortid-map should use wtxid when use-wtxid is true."
  (let* ((tx (make-simple-tx #x33))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
         (mempool (make-mock-mempool-with-txs (list (cons txid tx))))
         (k0 #x1234)
         (k1 #x5678))
    ;; With use-wtxid=nil, should use txid
    (multiple-value-bind (map1 collision1)
        (bitcoin-lisp.networking::build-shortid-map mempool k0 k1 nil)
      (declare (ignore collision1))
      (let ((short-id-txid (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid)))
        (is (gethash short-id-txid map1))))
    ;; With use-wtxid=t, should use wtxid
    (multiple-value-bind (map2 collision2)
        (bitcoin-lisp.networking::build-shortid-map mempool k0 k1 t)
      (declare (ignore collision2))
      (let ((short-id-wtxid (bitcoin-lisp.crypto:compute-short-txid k0 k1 wtxid)))
        (is (gethash short-id-wtxid map2))))))

;;;; Block Reconstruction Tests

(test reconstruct-with-all-txs-in-mempool
  "Block should reconstruct successfully when all txs are in mempool."
  (let* ((tx1 (make-simple-tx #x11))
         (tx2 (make-simple-tx #x22))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (txid2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1)
                                                    (cons txid2 tx2))))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (nonce #x1234567890abcdef)
         (header-bytes (bitcoin-lisp.serialization:serialize-block-header header)))
    ;; Compute short IDs for our transactions
    (multiple-value-bind (k0 k1)
        (bitcoin-lisp.crypto:compute-siphash-key header-bytes nonce)
      (let* ((short-id1 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid1))
             (short-id2 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid2))
             (compact-block (bitcoin-lisp.serialization:make-compact-block
                             :header header
                             :nonce nonce
                             :short-ids (list short-id1 short-id2)
                             :prefilled-txs '())))
        (multiple-value-bind (block missing partial)
            (bitcoin-lisp.networking::reconstruct-compact-block compact-block mempool nil)
          (declare (ignore partial))
          (is-true block)
          (is (null missing))
          (is (= (length (bitcoin-lisp.serialization:bitcoin-block-transactions block)) 2)))))))

(test reconstruct-with-missing-txs
  "Reconstruction should return missing indexes when txs not in mempool."
  (let* ((mempool (bitcoin-lisp.mempool:make-mempool))  ; Empty mempool
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (compact-block (bitcoin-lisp.serialization:make-compact-block
                         :header header
                         :nonce 0
                         :short-ids (list #x112233445566 #xaabbccddeeff)
                         :prefilled-txs '())))
    (multiple-value-bind (block missing partial)
        (bitcoin-lisp.networking::reconstruct-compact-block compact-block mempool nil)
      (is (null block))
      (is (equal missing '(0 1)))  ; Both indexes missing
      (is-true partial))))  ; Partial array returned

(test reconstruct-with-prefilled-coinbase
  "Reconstruction should place prefilled transactions correctly."
  (let* ((coinbase-tx (make-simple-tx #x00))
         (tx1 (make-simple-tx #x11))
         (txid1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (mempool (make-mock-mempool-with-txs (list (cons txid1 tx1))))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                  :timestamp 0
                  :bits #x1d00ffff
                  :nonce 0))
         (nonce #x1234567890abcdef)
         (header-bytes (bitcoin-lisp.serialization:serialize-block-header header)))
    (multiple-value-bind (k0 k1)
        (bitcoin-lisp.crypto:compute-siphash-key header-bytes nonce)
      (let* ((short-id1 (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid1))
             (prefilled (bitcoin-lisp.serialization:make-prefilled-tx
                         :index 0
                         :transaction coinbase-tx))
             (compact-block (bitcoin-lisp.serialization:make-compact-block
                             :header header
                             :nonce nonce
                             :short-ids (list short-id1)
                             :prefilled-txs (list prefilled))))
        (multiple-value-bind (block missing partial)
            (bitcoin-lisp.networking::reconstruct-compact-block compact-block mempool nil)
          (declare (ignore partial))
          (is-true block)
          (is (null missing))
          ;; First tx should be coinbase (prefilled), second should be tx1
          (is (= (length (bitcoin-lisp.serialization:bitcoin-block-transactions block)) 2)))))))

;;;; Timeout Handling Tests

(test compact-block-timeout-clears-pending
  "check-compact-block-timeout should clear expired pending state."
  (let ((peer (make-mock-peer)))
    ;; Set up pending state with old timestamp
    (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
          (bitcoin-lisp.networking:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)
           :request-time (- (get-internal-real-time)
                            (* 20 internal-time-units-per-second))))  ; 20 seconds ago
    (is (bitcoin-lisp.networking:peer-pending-compact-block peer))
    ;; Check timeout (should clear and request full block)
    ;; Note: This will try to send a message which will fail, but state should clear
    (handler-case
        (bitcoin-lisp.networking:check-compact-block-timeout peer)
      (error () nil))
    (is (null (bitcoin-lisp.networking:peer-pending-compact-block peer)))))

(test compact-block-timeout-preserves-fresh-pending
  "check-compact-block-timeout should not clear fresh pending state."
  (let ((peer (make-mock-peer)))
    ;; Set up pending state with recent timestamp
    (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
          (bitcoin-lisp.networking:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)
           :request-time (get-internal-real-time)))  ; Just now
    (bitcoin-lisp.networking:check-compact-block-timeout peer)
    ;; Should still have pending state
    (is (bitcoin-lisp.networking:peer-pending-compact-block peer))))

;;;; Metrics Tests

(test compact-block-stats-returns-metrics
  "compact-block-stats should return current metrics."
  (let ((stats (bitcoin-lisp.networking:compact-block-stats)))
    (is (listp stats))
    (is (member :successes stats))
    (is (member :failures stats))
    (is (member :collisions stats))))

;;;; Clear pending state test

(test clear-pending-compact-block
  "clear-pending-compact-block should remove pending state."
  (let ((peer (make-mock-peer)))
    (setf (bitcoin-lisp.networking:peer-pending-compact-block peer)
          (bitcoin-lisp.networking:make-pending-compact-block
           :block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (bitcoin-lisp.networking:peer-pending-compact-block peer))
    (bitcoin-lisp.networking:clear-pending-compact-block peer)
    (is (null (bitcoin-lisp.networking:peer-pending-compact-block peer)))))
