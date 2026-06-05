(in-package #:bitcoin-lisp.tests)

;;; Package relay / submitpackage tests (Bitcoin Core ProcessNewPackage).
;;;
;;; Spendable test transactions use P2SH-wrapped OP_TRUE: a standard P2SH output
;;; whose redeemScript is OP_TRUE, spendable with scriptSig = push(OP_TRUE) and
;;; no signature. That clears standardness (P2SH output), push-only scriptSig,
;;; and full script validation (P2SH is a mandatory flag at every height) without
;;; needing a signing key (the node has no wallet).

(in-suite :package-tests)

(defparameter +optrue-redeem+
  (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x51))
  "The redeemScript: OP_TRUE.")

(defun %p2sh-optrue-spk ()
  "scriptPubKey for P2SH(OP_TRUE): OP_HASH160 <hash160(OP_TRUE)> OP_EQUAL."
  (let ((h (bitcoin-lisp.crypto:hash160 +optrue-redeem+))
        (spk (make-array 23 :element-type '(unsigned-byte 8))))
    (setf (aref spk 0) #xa9)        ; OP_HASH160
    (setf (aref spk 1) #x14)        ; push 20 bytes
    (replace spk h :start1 2)
    (setf (aref spk 22) #x87)       ; OP_EQUAL
    spk))

(defun %p2sh-optrue-scriptsig ()
  "scriptSig spending P2SH(OP_TRUE): a single push of the 1-byte redeemScript."
  (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(#x01 #x51)))

(defun %pkg-tx (prev-txid prev-index out-value &key (sequence #xffffffff) (version 2))
  "A non-witness tx spending (PREV-TXID, PREV-INDEX) via P2SH(OP_TRUE), paying
OUT-VALUE to one P2SH(OP_TRUE) output."
  (bitcoin-lisp.serialization:make-transaction
   :version version
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash prev-txid :index prev-index)
                  :script-sig (%p2sh-optrue-scriptsig)
                  :sequence sequence))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value out-value
                   :script-pubkey (%p2sh-optrue-spk)))
   :lock-time 0))

(defun %pkg-fixture (&key (fund-value 100000000) (fund-height 1) (current-height 200))
  "Return (values utxo-set mempool chain-state funding-txid). The funding UTXO is
a confirmed P2SH(OP_TRUE) output of FUND-VALUE that test parents spend."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (mempool (bitcoin-lisp.mempool:make-mempool))
        (chain-state (bitcoin-lisp.storage:make-chain-state :best-height current-height))
        (funding-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bitcoin-lisp.storage:add-utxo utxo-set funding-txid 0 fund-value
                                   (%p2sh-optrue-spk) fund-height :coinbase nil)
    (values utxo-set mempool chain-state funding-txid)))

(defun %result-for (results tx)
  "The package-tx-result in RESULTS whose wtxid matches TX."
  (let ((w (bitcoin-lisp.serialization:transaction-wtxid tx)))
    (find w results :key #'bitcoin-lisp.validation:package-tx-result-wtxid :test #'equalp)))

;;;; Well-formedness / topology (pure)

(test package-well-formed-accepts-valid-chain
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (declare (ignore utxo-set mempool chain-state))
    (let* ((parent (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (bitcoin-lisp.serialization:transaction-hash parent) 0 99980000)))
      (is (eq t (bitcoin-lisp.validation:package-well-formed (list parent child)))))))

(test package-well-formed-rejects-empty
  (is (eq nil (bitcoin-lisp.validation:package-well-formed '()))))

(test package-well-formed-rejects-too-many
  ;; 26 standalone txs spending distinct funding outpoints.
  (let ((pkg (loop for i from 0 below 26
                   collect (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element i)
                                    0 1000))))
    (multiple-value-bind (ok reason) (bitcoin-lisp.validation:package-well-formed pkg)
      (is (eq nil ok))
      (is (eq :package-too-many-transactions reason)))))

(test package-well-formed-rejects-duplicate
  (let ((tx (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9) 0 1000)))
    (multiple-value-bind (ok reason) (bitcoin-lisp.validation:package-well-formed (list tx tx))
      (is (eq nil ok))
      (is (eq :package-contains-duplicates reason)))))

(test package-well-formed-rejects-unsorted
  ;; child before parent.
  (multiple-value-bind (u m c funding-txid) (%pkg-fixture)
    (declare (ignore u m c))
    (let* ((parent (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (bitcoin-lisp.serialization:transaction-hash parent) 0 99980000)))
      (multiple-value-bind (ok reason)
          (bitcoin-lisp.validation:package-well-formed (list child parent))
        (is (eq nil ok))
        (is (eq :package-not-sorted reason))))))

(test package-well-formed-rejects-internal-conflict
  ;; two txs spend the same funding outpoint.
  (multiple-value-bind (u m c funding-txid) (%pkg-fixture)
    (declare (ignore u m c))
    (let ((a (%pkg-tx funding-txid 0 99990000))
          (b (%pkg-tx funding-txid 0 99980000)))
      (multiple-value-bind (ok reason)
          (bitcoin-lisp.validation:package-well-formed (list a b))
        (is (eq nil ok))
        (is (eq :conflict-in-package reason))))))

(test package-child-with-parents-tree-accepts-valid
  (multiple-value-bind (u m c funding-txid) (%pkg-fixture)
    (declare (ignore u m c))
    (let* ((parent (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (bitcoin-lisp.serialization:transaction-hash parent) 0 99980000)))
      (is (eq t (bitcoin-lisp.validation:package-child-with-parents-tree-p
                 (list parent child)))))))

(test package-child-with-parents-tree-rejects-non-parent
  ;; "parent" is not actually spent by the child.
  (multiple-value-bind (u m c funding-txid) (%pkg-fixture)
    (declare (ignore u m c))
    (let* ((stray (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                           0 50000)))
      (multiple-value-bind (ok reason)
          (bitcoin-lisp.validation:package-child-with-parents-tree-p (list stray child))
        (is (eq nil ok))
        (is (eq :package-not-child-with-parents reason))))))

(test package-child-with-parents-tree-rejects-parent-chain
  ;; parent2 spends parent1's output → parents depend on each other (a chain, not
  ;; a tree). The child spends both, so child-with-parents holds but the tree
  ;; check must reject.
  (multiple-value-bind (u m c funding-txid) (%pkg-fixture)
    (declare (ignore u m c))
    (let* ((p1 (%pkg-tx funding-txid 0 99990000))
           (p1id (bitcoin-lisp.serialization:transaction-hash p1))
           (p2 (%pkg-tx p1id 0 99980000))
           (p2id (bitcoin-lisp.serialization:transaction-hash p2))
           ;; child spends both p1 (its 2nd output? no — single output) — build a
           ;; 2-input child spending p1:0- already spent by p2... use p2:0 and a
           ;; separate funding output for p1 reference. Simpler: child spends p2
           ;; and p1 directly is impossible (p1:0 consumed by p2). So give the
           ;; child two inputs: p2:0 and p1 is a parent only transitively. We only
           ;; need the parents list {p1,p2} both spent by child.
           (child (bitcoin-lisp.serialization:make-transaction
                   :version 2
                   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                    :hash p2id :index 0)
                                  :script-sig (%p2sh-optrue-scriptsig))
                                 (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                    :hash p1id :index 0)
                                  :script-sig (%p2sh-optrue-scriptsig)))
                   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                   :value 50000 :script-pubkey (%p2sh-optrue-spk)))
                   :lock-time 0)))
      (multiple-value-bind (ok reason)
          (bitcoin-lisp.validation:package-child-with-parents-tree-p (list p1 p2 child))
        (is (eq nil ok))
        (is (eq :package-parent-depends-on-parent reason))))))

;;;; End-to-end acceptance

(test package-cpfp-low-fee-parent-rides-in-on-child
  ;; The headline case: a parent paying 50 sat (0.x sat/vB, below the 1 sat/vB
  ;; floor) is accepted because the child pays 50000 sat; the package feerate
  ;; clears the floor.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 50)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 50) 50000))))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :success msg))
        (is (null replaced))
        (is (eq :valid (bitcoin-lisp.validation:package-tx-result-status
                        (%result-for results parent))))
        (is (eq :valid (bitcoin-lisp.validation:package-tx-result-status
                        (%result-for results child))))
        ;; both ended up in the mempool
        (is-true (bitcoin-lisp.mempool:mempool-has mempool pid))
        (is-true (bitcoin-lisp.mempool:mempool-has
                  mempool (bitcoin-lisp.serialization:transaction-hash child)))
        ;; the parent's effective feerate is the package feerate (it includes
        ;; both wtxids), not its meagre own.
        (is (= 2 (length (bitcoin-lisp.validation:package-tx-result-effective-includes
                          (%result-for results parent)))))))))

(test package-single-sufficient-tx-accepted
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let ((tx (%pkg-tx funding-txid 0 (- 100000000 10000))))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list tx) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :success msg))
        (is (eq :valid (bitcoin-lisp.validation:package-tx-result-status
                        (%result-for results tx))))
        (is-true (bitcoin-lisp.mempool:mempool-has
                  mempool (bitcoin-lisp.serialization:transaction-hash tx)))))))

(test package-single-low-fee-tx-rejected
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let ((tx (%pkg-tx funding-txid 0 (- 100000000 50))))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list tx) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :insufficient-fee msg))
        (is (eq :invalid (bitcoin-lisp.validation:package-tx-result-status
                          (%result-for results tx))))
        (is (eq nil (bitcoin-lisp.mempool:mempool-has
                     mempool (bitcoin-lisp.serialization:transaction-hash tx))))))))

(test package-below-floor-rejected
  ;; parent + child both tiny: even the package feerate is below 1 sat/vB.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 10)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 10) 10))))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :insufficient-fee msg))
        (is (eq nil (bitcoin-lisp.mempool:mempool-has mempool pid)))
        (is (eq :invalid (bitcoin-lisp.validation:package-tx-result-status
                          (%result-for results child))))))))

(test package-dedup-already-in-mempool
  ;; A package whose parent is already in the mempool reports the parent as
  ;; :mempool-entry and still accepts the child.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 10000)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 10000) 10000))))
      ;; first submit the parent on its own (sufficient fee → enters mempool)
      (bitcoin-lisp.validation:validate-package-for-mempool
       (list parent) utxo-set mempool chain-state)
      (is-true (bitcoin-lisp.mempool:mempool-has mempool pid))
      ;; now submit the full package
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :success msg))
        (is (eq :mempool-entry (bitcoin-lisp.validation:package-tx-result-status
                                (%result-for results parent))))
        (is (eq :valid (bitcoin-lisp.validation:package-tx-result-status
                        (%result-for results child))))
        (is-true (bitcoin-lisp.mempool:mempool-has
                  mempool (bitcoin-lisp.serialization:transaction-hash child)))))))

(test package-bad-topology-rejected
  ;; unsorted package → context-free reject, nothing validated, nothing added.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 50)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 50) 50000))))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list child parent) utxo-set mempool chain-state)   ; child first
        (declare (ignore replaced))
        (is (eq :package-not-sorted msg))
        (is (eq :not-validated (bitcoin-lisp.validation:package-tx-result-status
                                (first results))))
        (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool)))))))

(test package-not-child-with-parents-rejected
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((stray (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4)
                           0 50000)))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list stray child) utxo-set mempool chain-state)
        (declare (ignore results replaced))
        (is (eq :package-not-child-with-parents msg))
        (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool)))))))

;;;; RPC shape

(test rpc-submitpackage-cpfp-shape
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((node (bitcoin-lisp::make-node :network :testnet3))
           (parent (%pkg-tx funding-txid 0 (- 100000000 50)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 50) 50000)))
           (phex (bitcoin-lisp.crypto:bytes-to-hex
                  (bitcoin-lisp.serialization:serialize-transaction parent)))
           (chex (bitcoin-lisp.crypto:bytes-to-hex
                  (bitcoin-lisp.serialization:serialize-transaction child))))
      (setf (bitcoin-lisp::node-chain-state node) chain-state
            (bitcoin-lisp::node-utxo-set node) utxo-set
            (bitcoin-lisp::node-mempool node) mempool)
      (let* ((result (bitcoin-lisp.rpc::rpc-submitpackage node (list (list phex chex))))
             (msg (cdr (assoc "package_msg" result :test #'string=)))
             (tx-results (cdr (assoc "tx-results" result :test #'string=))))
        (is (string= "success" msg))
        (is (= 2 (length tx-results)))
        ;; each entry is (wtxid-hex . field-alist) carrying at least a txid
        (is-true (every (lambda (e) (assoc "txid" (cdr e) :test #'string=)) tx-results))))))
