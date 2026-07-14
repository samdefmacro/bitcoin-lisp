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
  ;; The headline case: a parent paying 5 sat (~0.05 sat/vB, below the
  ;; 0.1 sat/vB / 100 sat/kvB floor) is accepted because the child pays
  ;; 50000 sat; the package feerate clears the floor.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 5)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 5) 50000))))
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
    (let ((tx (%pkg-tx funding-txid 0 (- 100000000 5))))
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
  ;; parent + child both tiny: even the package feerate is below the 0.1 sat/vB
  ;; (100 sat/kvB) relay floor.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 1)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 1) 1))))
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

(test single-tx-in-sub-1-satvb-band-accepted
  "A lone tx paying ~0.5 sat/vB -- inside the 0.1..1.0 sat/vB band Core relays --
is accepted under the 100 sat/kvB floor (the old 1 sat/vB integer floor rejected
the entire band)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (%pkg-fixture)
    (let ((tx (%pkg-tx funding-txid 0 (- 100000000 50))))   ; 50 sat fee
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list tx) utxo-set mempool chain-state)
        (declare (ignore results replaced))
        (is (eq :success msg))
        (is-true (bitcoin-lisp.mempool:mempool-has
                  mempool (bitcoin-lisp.serialization:transaction-hash tx)))))))

;;;; Package RBF (cluster mempool P8 — Core PackageRBFChecks,
;;;; validation.cpp:1034-1130, wired through %accept-package-subset)

(defun %pkg-tx-2in (prev1 idx1 prev2 idx2 out-value)
  "A two-input P2SH(OP_TRUE) tx spending (PREV1,IDX1) and (PREV2,IDX2)."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash prev1 :index idx1)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff)
                   (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash prev2 :index idx2)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value out-value
                     :script-pubkey (%p2sh-optrue-spk)))
   :lock-time 0))

(test package-rbf-replaces-mempool-conflict
  "A 1p1c package whose parent conflicts with a pool tx replaces it when the
package out-earns it through the diagram check: the conflict is evicted and
both members enter the pool."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (let* ((a (%pkg-tx funding 0 99999000))          ; pool tx, fee 1000
           (aid (bitcoin-lisp.serialization:transaction-hash a))
           ;; Parent double-spends FUNDING:0 at a sub-floor fee (5 sat) so its
           ;; individual attempt defers; the child carries the package.
           (parent (%pkg-tx funding 0 99999995))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 99949995))          ; fee 50000
           (cid (bitcoin-lisp.serialization:transaction-hash child)))
      (is (eq :ok (%add-tx mempool a :fee 1000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :success msg))
        (is (every (lambda (r) (eq :valid (bitcoin-lisp.validation:package-tx-result-status r)))
                   results))
        (is (member aid replaced :test #'equalp)))
      (is (not (bitcoin-lisp.mempool:mempool-has mempool aid)))
      (is (bitcoin-lisp.mempool:mempool-has mempool pid))
      (is (bitcoin-lisp.mempool:mempool-has mempool cid)))))

(test package-rbf-insufficient-total-fees-rejected
  "Package RBF rule 3 on the totals: a pair whose combined fees do not cover
the replaced tx's is rejected and the pool is untouched."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (let* ((a (%pkg-tx funding 0 99950000))          ; pool tx, fee 50000
           (aid (bitcoin-lisp.serialization:transaction-hash a))
           (parent (%pkg-tx funding 0 99999995))     ; fee 5, conflicts with A
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 99989995)))         ; fee 10000
      (is (eq :ok (%add-tx mempool a :fee 50000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore results))
        (is (eq :insufficient-fee msg))
        (is (null replaced)))
      (is (bitcoin-lisp.mempool:mempool-has mempool aid))
      (is (not (bitcoin-lisp.mempool:mempool-has mempool pid))))))

(test package-rbf-mempool-ancestors-rejected
  "Package RBF requires NO in-mempool ancestors (the resulting cluster must
be exactly the pair, Core validation.cpp:1052-1064): a conflicting package
whose parent also spends a pool tx's output is rejected."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (let* ((funding2 (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 8))
           (m (%pkg-tx funding 0 99999000))          ; pool tx: parent's ancestor
           (mid (bitcoin-lisp.serialization:transaction-hash m))
           (a2 (%pkg-tx funding2 0 99999000))        ; pool tx: the conflict
           (a2id (bitcoin-lisp.serialization:transaction-hash a2))
           ;; Parent spends M:0 (in-mempool ancestor) AND double-spends
           ;; FUNDING2:0 (the conflict), at a sub-floor fee.
           (parent (%pkg-tx-2in mid 0 funding2 0 199998990))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 199948990)))        ; fee 50000
      (bitcoin-lisp.storage:add-utxo utxo-set funding2 0 100000000
                                     (%p2sh-optrue-spk) 1 :coinbase nil)
      (is (eq :ok (%add-tx mempool m :fee 1000 :height 200)))
      (is (eq :ok (%add-tx mempool a2 :fee 1000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore results))
        (is (eq :package-rbf-mempool-ancestors msg))
        (is (null replaced)))
      (is (bitcoin-lisp.mempool:mempool-has mempool mid))
      (is (bitcoin-lisp.mempool:mempool-has mempool a2id))
      (is (not (bitcoin-lisp.mempool:mempool-has mempool pid))))))

(test package-rbf-not-1p1c-rejected
  "A conflicting multi-tx subset larger than 1-parent-1-child cannot use
package RBF (Core validation.cpp:1047-1050)."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (let* ((funding4 (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 9))
           (a (%pkg-tx funding 0 99999000))          ; pool tx, fee 1000
           (aid (bitcoin-lisp.serialization:transaction-hash a))
           (p1 (%pkg-tx funding 0 99999995))         ; conflicts with A, fee 5
           (p2 (%pkg-tx funding4 0 99999995))        ; fee 5
           (child (%pkg-tx-2in (bitcoin-lisp.serialization:transaction-hash p1) 0
                               (bitcoin-lisp.serialization:transaction-hash p2) 0
                               199899990)))          ; fee 100000
      (bitcoin-lisp.storage:add-utxo utxo-set funding4 0 100000000
                                     (%p2sh-optrue-spk) 1 :coinbase nil)
      (is (eq :ok (%add-tx mempool a :fee 1000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bitcoin-lisp.validation:validate-package-for-mempool
           (list p1 p2 child) utxo-set mempool chain-state)
        (declare (ignore results))
        (is (eq :package-rbf-not-1p1c msg))
        (is (null replaced)))
      (is (bitcoin-lisp.mempool:mempool-has mempool aid)))))

;;;; TRUC sibling eviction through the single-tx acceptance path (Core
;;;; PreChecks, validation.cpp:950-970: the sibling joins the conflict set
;;;; and the replacement economics decide)

(defun %truc-2out-parent (funding)
  "A v3 parent spending FUNDING:0 with TWO outputs, so a second child does
not input-conflict with the first."
  (bitcoin-lisp.serialization:make-transaction
   :version 3
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash funding :index 0)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value 49990000 :script-pubkey (%p2sh-optrue-spk))
                    (bitcoin-lisp.serialization:make-tx-out
                     :value 49990000 :script-pubkey (%p2sh-optrue-spk)))
   :lock-time 0))

(test truc-sibling-eviction-accepted-when-paying
  "A second TRUC child that pays enough EVICTS its sibling through the RBF
economics instead of being rejected on the descendant limit (Core PreChecks
sibling eviction, validation.cpp:950-970); one that does not pay is rejected
on the economics (:insufficient-fee), and with sibling eviction disabled the
TRUC error surfaces unchanged."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (declare (ignore chain-state))
    (let* ((parent (%truc-2out-parent funding))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (sib (%pkg-tx pid 0 49985000 :version 3))          ; fee 5000
           (sibid (bitcoin-lisp.serialization:transaction-hash sib))
           (rich (%pkg-tx pid 1 49930000 :version 3))         ; fee 60000
           (richid (bitcoin-lisp.serialization:transaction-hash rich))
           (poor (%pkg-tx pid 1 49984996 :version 3)))        ; fee 5004
      (is (eq :ok (%add-tx mempool parent :fee 20000 :height 200)))
      (is (eq :ok (%add-tx mempool sib :fee 5000 :height 200)))
      ;; Not paying its own bandwidth over the sibling's 5000 (rule 4 needs
      ;; ~+9 sat): rejected on the ECONOMICS, not the descendant limit.
      (multiple-value-bind (valid err)
          (bitcoin-lisp.validation:validate-transaction-for-mempool
           poor utxo-set mempool 200)
        (is-false valid)
        (is (eq :insufficient-fee err)))
      ;; With sibling eviction disabled (the multi-tx package context), the
      ;; TRUC descendant-limit error surfaces instead.
      (multiple-value-bind (valid err)
          (bitcoin-lisp.validation:validate-transaction-for-mempool
           rich utxo-set mempool 200 :allow-sibling-eviction nil)
        (is-false valid)
        (is (eq :truc-descendant-limit err)))
      ;; :skip-rbf-check alone also disables the fallthrough — with the
      ;; economics skipped there is nothing to evaluate the eviction.
      (multiple-value-bind (valid err)
          (bitcoin-lisp.validation:validate-transaction-for-mempool
           rich utxo-set mempool 200 :skip-rbf-check t)
        (is-false valid)
        (is (eq :truc-descendant-limit err)))
      ;; Paying enough: the sibling is the replaced set; accepting evicts it.
      (multiple-value-bind (valid err fee replaced)
          (bitcoin-lisp.validation:validate-transaction-for-mempool
           rich utxo-set mempool 200)
        (declare (ignore err))
        (is-true valid)
        (is (= 60000 fee))
        (is (member sibid replaced :test #'equalp))
        (is (eq :ok (bitcoin-lisp.mempool:accept-validated-tx
                     mempool richid rich fee 200 :replaced replaced))))
      (is (not (bitcoin-lisp.mempool:mempool-has mempool sibid)))
      (is (bitcoin-lisp.mempool:mempool-has mempool richid))
      (is (bitcoin-lisp.mempool:mempool-has mempool pid)))))
