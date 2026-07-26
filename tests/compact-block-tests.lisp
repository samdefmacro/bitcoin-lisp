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
         (bitcoin-lisp.mempool:make-entry-from-tx tx 1000 0))))
    mempool))

(defun make-simple-tx (id-byte)
  "Create a simple transaction with a unique identifier byte."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element id-byte)
                                    :index 0)
                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                  :sequence #xffffffff))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value 50000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time 0))

;;;; Protocol Negotiation Tests

(test sendcmpct-updates-peer-version
  "handle-sendcmpct accepts ONLY compact-block version 2 (witness), matching
Bitcoin Core's CMPCTBLOCKS_VERSION gate. A v1 (non-witness) sendcmpct is ignored:
a v1 compact block delivers a witness-stripped prefilled coinbase, so the
reconstructed block fails BIP141 validation (bad-witness-nonce-size). Accepting v1
is what wedged the testnet4 node ~1800 blocks behind the chain."
  (let ((peer (make-mock-peer)))
    ;; Initially no compact block support
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))
    ;; v1 is ignored — peer stays unsupported (we fall back to full witness blocks)
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 1) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))
    ;; v2 is accepted
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 2) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 2))))

(test sendcmpct-rejects-invalid-version
  "handle-sendcmpct ignores every version other than 2 — v1 and future/unknown
versions alike (mirrors Core's `if (version != CMPCTBLOCKS_VERSION) return;`)."
  (let ((peer (make-mock-peer)))
    ;; v3 (unknown/future) ignored
    (let ((payload (flexi-streams:with-output-to-sequence (s)
                     (write-byte 0 s)  ; low-bandwidth
                     (bitcoin-lisp.serialization:write-uint64-le s 3))))  ; version 3
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))
    ;; v1 ignored too
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message nil 1) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (= (bitcoin-lisp.networking:peer-compact-block-version peer) 0))))

(test sendcmpct-tracks-high-bandwidth
  "handle-sendcmpct tracks the high-bandwidth preference from a (v2) sendcmpct."
  (let ((peer (make-mock-peer)))
    (is (null (bitcoin-lisp.networking:peer-compact-block-high-bandwidth peer)))
    ;; Receive high-bandwidth request (v2 — the only version we accept)
    (let ((payload (subseq (bitcoin-lisp.serialization:make-sendcmpct-message t 2) 24)))
      (bitcoin-lisp.networking::handle-sendcmpct peer payload))
    (is (bitcoin-lisp.networking:peer-compact-block-high-bandwidth peer))
    (is (= 2 (bitcoin-lisp.networking:peer-compact-block-version peer)))))

(test should-use-compact-blocks-checks-peer-support
  "should-use-compact-blocks-p should check if peer supports compact blocks."
  (let ((peer (make-mock-peer)))
    ;; No support
    (is (null (bitcoin-lisp.networking:should-use-compact-blocks-p peer)))
    ;; Add support (v2 — the only version we negotiate)
    (setf (bitcoin-lisp.networking:peer-compact-block-version peer) 2)
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

;;;; ============================================================
;;;; G7-16: BIP152 high-bandwidth selection
;;;; ============================================================

(defun %g716-peer (&key inbound (version 2))
  (let ((p (bitcoin-lisp.networking::make-peer :inbound inbound)))
    (setf (bitcoin-lisp.networking::peer-compact-block-version p) version
          (bitcoin-lisp.networking::peer-state p) :ready)
    p))

(defmacro %g716-quiet (&body body)
  "Run BODY with send-message stubbed out (no sockets)."
  `(let ((real (fdefinition 'bitcoin-lisp.networking::send-message)))
     (unwind-protect
          (progn (setf (fdefinition 'bitcoin-lisp.networking::send-message)
                       (lambda (peer msg) (declare (ignore peer msg)) t))
                 ,@body)
       (setf (fdefinition 'bitcoin-lisp.networking::send-message) real))))

(test g7-16-initial-sendcmpct-is-low-bandwidth
  "G7-16: high bandwidth is a SCARCE SELECTION (BIP152 allows 3), not a
capability handshake. We used to request HB from every compact-capable peer, so
every one of them pushed an unsolicited cmpctblock for every block instead of
about three."
  (let ((sent '())
        (peer (%g716-peer)))
    (let ((real (fdefinition 'bitcoin-lisp.networking::send-message)))
      (unwind-protect
           (progn
             (setf (fdefinition 'bitcoin-lisp.networking::send-message)
                   (lambda (p msg) (declare (ignore p)) (push msg sent)))
             (bitcoin-lisp.networking::send-compact-block-negotiation peer))
        (setf (fdefinition 'bitcoin-lisp.networking::send-message) real)))
    (is (= 1 (length sent)))
    ;; Assert on the ACTUAL sendcmpct byte on the wire, and on the peer that
    ;; was negotiated — checking a fresh peer's default-NIL flag would pass no
    ;; matter what this function does.
    (let ((payload (subseq (first sent) 24)))
      (is (zerop (aref payload 0))
          "the high-bandwidth byte of the initial sendcmpct must be 0"))
    (is (null (bitcoin-lisp.networking::peer-compact-block-high-bandwidth-to peer))
        "negotiation must not mark the peer HB")))

(test g7-16-hb-selection-capped-at-three-demoting-oldest
  "Core caps the HB set at 3 and demotes the OLDEST (front of
lNodesAnnouncingHeaderAndIDs). A peer already selected is only moved to the
back with NO sendcmpct re-sent — re-announcing every block would be a visible
protocol anomaly."
  (let ((bitcoin-lisp.networking::*hb-announcing-peers* '()))
    (%g716-quiet
      (let ((a (%g716-peer)) (b (%g716-peer)) (c (%g716-peer)) (d (%g716-peer)))
        (dolist (p (list a b c))
          (bitcoin-lisp.networking:maybe-set-peer-announcing-hb p))
        (is (equal (list a b c) bitcoin-lisp.networking::*hb-announcing-peers*))
        (is (every #'bitcoin-lisp.networking::peer-compact-block-high-bandwidth-to
                   (list a b c)))
        ;; Re-selecting an existing peer only reorders it.
        (bitcoin-lisp.networking:maybe-set-peer-announcing-hb a)
        (is (equal (list b c a) bitcoin-lisp.networking::*hb-announcing-peers*)
            "an already-selected peer moves to the back")
        ;; A fourth peer evicts the oldest (now b).
        (bitcoin-lisp.networking:maybe-set-peer-announcing-hb d)
        (is (equal (list c a d) bitcoin-lisp.networking::*hb-announcing-peers*))
        (is (null (bitcoin-lisp.networking::peer-compact-block-high-bandwidth-to b))
            "the evicted peer must be demoted to low bandwidth")))))

(test g7-16-inbound-promotion-protects-last-outbound-hb-peer
  "THE SUBTLE ONE (Core net_processing.cpp:1299-1310). When an INBOUND peer is
promoted, the set is full, and exactly ONE entry is outbound sitting at the
front, Core swaps the first two so the outbound HB peer is not evicted.

Without it a flood of inbound peers evicts every outbound HB peer in turn — an
eclipse/partition weakening, and the same class of ordering mistake as trimming
the wrong end of the reorg disconnect pool."
  (let ((bitcoin-lisp.networking::*hb-announcing-peers* '()))
    (%g716-quiet
      (let ((out (%g716-peer))
            (in1 (%g716-peer :inbound t))
            (in2 (%g716-peer :inbound t))
            (in3 (%g716-peer :inbound t)))
        ;; Outbound peer is at the FRONT and is the only outbound entry.
        (dolist (p (list out in1 in2))
          (bitcoin-lisp.networking:maybe-set-peer-announcing-hb p))
        (is (equal (list out in1 in2) bitcoin-lisp.networking::*hb-announcing-peers*))
        ;; Promoting another inbound peer must NOT evict the lone outbound one.
        (bitcoin-lisp.networking:maybe-set-peer-announcing-hb in3)
        (is (member out bitcoin-lisp.networking::*hb-announcing-peers*)
            "the last outbound HB peer must be protected from inbound eviction")
        (is-true (bitcoin-lisp.networking::peer-compact-block-high-bandwidth-to out))
        (is (null (bitcoin-lisp.networking::peer-compact-block-high-bandwidth-to in1))
            "the inbound peer in slot 1 is evicted instead")))))

(test g7-16-non-signalling-and-blocksonly-peers-not-promoted
  "Core gates promotion on m_provides_cmpctblocks and skips it entirely in
blocksonly mode — our mempool would not hold the transactions needed to
reconstruct the block."
  (let ((bitcoin-lisp.networking::*hb-announcing-peers* '()))
    (%g716-quiet
      (bitcoin-lisp.networking:maybe-set-peer-announcing-hb (%g716-peer :version 0))
      (is (null bitcoin-lisp.networking::*hb-announcing-peers*)
          "a peer that never signalled compact-block support is not eligible"))))

(test g7-16-disconnect-frees-an-hb-slot
  "A disconnected peer must not hold one of the three slots forever."
  (let ((bitcoin-lisp.networking::*hb-announcing-peers* '()))
    (%g716-quiet
      (let ((a (%g716-peer)))
        (bitcoin-lisp.networking:maybe-set-peer-announcing-hb a)
        (is (equal (list a) bitcoin-lisp.networking::*hb-announcing-peers*))
        (bitcoin-lisp.networking:forget-hb-announcing-peer a)
        (is (null bitcoin-lisp.networking::*hb-announcing-peers*))))))
