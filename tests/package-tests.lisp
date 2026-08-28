(in-package #:bitcoin-lisp.tests)

;;; Package relay / submitpackage tests (Bitcoin Core ProcessNewPackage).
;;;
;;; Spendable test transactions use P2SH-wrapped OP_TRUE: a standard P2SH output
;;; whose redeemScript is OP_TRUE, spendable with scriptSig = push(OP_TRUE) and
;;; no signature. That clears standardness (P2SH output), push-only scriptSig,
;;; and full script validation (P2SH is a mandatory flag at every height) without
;;; needing a signing key (the node has no wallet).

(in-suite :package-tests)

(defun %p2sh-optrue-scriptsig ()
  "scriptSig spending P2SH(OP_TRUE): a single push of the 1-byte redeemScript."
  (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(#x01 #x51)))

(defun %pkg-tx (prev-txid prev-index out-value &key (sequence #xffffffff) (version 2))
  "A non-witness tx spending (PREV-TXID, PREV-INDEX) via P2SH(OP_TRUE), paying
OUT-VALUE to one P2SH(OP_TRUE) output."
  (bl.ser:make-transaction
   :version version
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint
                                    :hash prev-txid :index prev-index)
                  :script-sig (%p2sh-optrue-scriptsig)
                  :sequence sequence))
   :outputs (vector (bl.ser:make-tx-out
                   :value out-value
                   :script-pubkey (p2sh-optrue-script-pubkey)))
   :lock-time 0))

(defun %result-for (results tx)
  "The package-tx-result in RESULTS whose wtxid matches TX."
  (let ((w (bl.ser:transaction-wtxid tx)))
    (find w results :key #'bl.val:package-tx-result-wtxid :test #'equalp)))

;;;; Well-formedness / topology (pure)

(test package-well-formed-accepts-valid-chain
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (declare (ignore utxo-set mempool chain-state))
    (let* ((parent (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (bl.ser:transaction-hash parent) 0 99980000)))
      (is (eq t (bl.val:package-well-formed (list parent child)))))))

(test package-well-formed-rejects-empty
  (is (eq nil (bl.val:package-well-formed '()))))

(test package-well-formed-rejects-too-many
  ;; 26 standalone txs spending distinct funding outpoints.
  (let ((pkg (loop for i from 0 below 26
                   collect (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element i)
                                    0 1000))))
    (multiple-value-bind (ok reason) (bl.val:package-well-formed pkg)
      (is (eq nil ok))
      (is (eq :package-too-many-transactions reason)))))

(test package-well-formed-rejects-duplicate
  (let ((tx (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9) 0 1000)))
    (multiple-value-bind (ok reason) (bl.val:package-well-formed (list tx tx))
      (is (eq nil ok))
      (is (eq :package-contains-duplicates reason)))))

(test package-well-formed-rejects-unsorted
  ;; child before parent.
  (multiple-value-bind (u m c funding-txid) (make-package-fixture)
    (declare (ignore u m c))
    (let* ((parent (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (bl.ser:transaction-hash parent) 0 99980000)))
      (multiple-value-bind (ok reason)
          (bl.val:package-well-formed (list child parent))
        (is (eq nil ok))
        (is (eq :package-not-sorted reason))))))

(test package-well-formed-rejects-internal-conflict
  ;; two txs spend the same funding outpoint.
  (multiple-value-bind (u m c funding-txid) (make-package-fixture)
    (declare (ignore u m c))
    (let ((a (%pkg-tx funding-txid 0 99990000))
          (b (%pkg-tx funding-txid 0 99980000)))
      (multiple-value-bind (ok reason)
          (bl.val:package-well-formed (list a b))
        (is (eq nil ok))
        (is (eq :conflict-in-package reason))))))

(test package-child-with-parents-tree-accepts-valid
  (multiple-value-bind (u m c funding-txid) (make-package-fixture)
    (declare (ignore u m c))
    (let* ((parent (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (bl.ser:transaction-hash parent) 0 99980000)))
      (is (eq t (bl.val:package-child-with-parents-tree-p
                 (list parent child)))))))

(test package-child-with-parents-tree-rejects-non-parent
  ;; "parent" is not actually spent by the child.
  (multiple-value-bind (u m c funding-txid) (make-package-fixture)
    (declare (ignore u m c))
    (let* ((stray (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                           0 50000)))
      (multiple-value-bind (ok reason)
          (bl.val:package-child-with-parents-tree-p (list stray child))
        (is (eq nil ok))
        (is (eq :package-not-child-with-parents reason))))))

(test package-child-with-parents-tree-rejects-parent-chain
  ;; parent2 spends parent1's output → parents depend on each other (a chain, not
  ;; a tree). The child spends both, so child-with-parents holds but the tree
  ;; check must reject.
  (multiple-value-bind (u m c funding-txid) (make-package-fixture)
    (declare (ignore u m c))
    (let* ((p1 (%pkg-tx funding-txid 0 99990000))
           (p1id (bl.ser:transaction-hash p1))
           (p2 (%pkg-tx p1id 0 99980000))
           (p2id (bl.ser:transaction-hash p2))
           ;; child spends both p1 (its 2nd output? no — single output) — build a
           ;; 2-input child spending p1:0- already spent by p2... use p2:0 and a
           ;; separate funding output for p1 reference. Simpler: child spends p2
           ;; and p1 directly is impossible (p1:0 consumed by p2). So give the
           ;; child two inputs: p2:0 and p1 is a parent only transitively. We only
           ;; need the parents list {p1,p2} both spent by child.
           (child (bl.ser:make-transaction
                   :version 2
                   :inputs (vector (bl.ser:make-tx-in
                                  :previous-output (bl.ser:make-outpoint
                                                    :hash p2id :index 0)
                                  :script-sig (%p2sh-optrue-scriptsig))
                                 (bl.ser:make-tx-in
                                  :previous-output (bl.ser:make-outpoint
                                                    :hash p1id :index 0)
                                  :script-sig (%p2sh-optrue-scriptsig)))
                   :outputs (vector (bl.ser:make-tx-out
                                   :value 50000 :script-pubkey (p2sh-optrue-script-pubkey)))
                   :lock-time 0)))
      (multiple-value-bind (ok reason)
          (bl.val:package-child-with-parents-tree-p (list p1 p2 child))
        (is (eq nil ok))
        (is (eq :package-parent-depends-on-parent reason))))))

;;;; End-to-end acceptance

(test package-cpfp-low-fee-parent-rides-in-on-child
  ;; The headline case: a parent paying 5 sat (~0.05 sat/vB, below the
  ;; 0.1 sat/vB / 100 sat/kvB floor) is accepted because the child pays
  ;; 50000 sat; the package feerate clears the floor.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 5)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 5) 50000))))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :success msg))
        (is (null replaced))
        (is (eq :valid (bl.val:package-tx-result-status
                        (%result-for results parent))))
        (is (eq :valid (bl.val:package-tx-result-status
                        (%result-for results child))))
        ;; both ended up in the mempool
        (is-true (bl.mp:mempool-has mempool pid))
        (is-true (bl.mp:mempool-has
                  mempool (bl.ser:transaction-hash child)))
        ;; the parent's effective feerate is the package feerate (it includes
        ;; both wtxids), not its meagre own.
        (is (= 2 (length (bl.val:package-tx-result-effective-includes
                          (%result-for results parent)))))))))

(test package-single-sufficient-tx-accepted
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let ((tx (%pkg-tx funding-txid 0 (- 100000000 10000))))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list tx) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :success msg))
        (is (eq :valid (bl.val:package-tx-result-status
                        (%result-for results tx))))
        (is-true (bl.mp:mempool-has
                  mempool (bl.ser:transaction-hash tx)))))))

(test package-single-low-fee-tx-rejected
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let ((tx (%pkg-tx funding-txid 0 (- 100000000 5))))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list tx) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :insufficient-fee msg))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results tx))))
        (is (eq nil (bl.mp:mempool-has
                     mempool (bl.ser:transaction-hash tx))))))))

(test package-below-floor-rejected
  ;; parent + child both tiny: even the package feerate is below the 0.1 sat/vB
  ;; (100 sat/kvB) relay floor.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 1)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 1) 1))))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :insufficient-fee msg))
        (is (eq nil (bl.mp:mempool-has mempool pid)))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results child))))))))

(test package-dedup-already-in-mempool
  ;; A package whose parent is already in the mempool reports the parent as
  ;; :mempool-entry and still accepts the child.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 10000)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 10000) 10000))))
      ;; first submit the parent on its own (sufficient fee → enters mempool)
      (bl.val:validate-package-for-mempool
       (list parent) utxo-set mempool chain-state)
      (is-true (bl.mp:mempool-has mempool pid))
      ;; now submit the full package
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore replaced))
        (is (eq :success msg))
        (is (eq :mempool-entry (bl.val:package-tx-result-status
                                (%result-for results parent))))
        (is (eq :valid (bl.val:package-tx-result-status
                        (%result-for results child))))
        (is-true (bl.mp:mempool-has
                  mempool (bl.ser:transaction-hash child)))))))

(test package-bad-topology-rejected
  ;; unsorted package → context-free reject, nothing validated, nothing added.
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 (- 100000000 50)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 50) 50000))))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list child parent) utxo-set mempool chain-state)   ; child first
        (declare (ignore replaced))
        (is (eq :package-not-sorted msg))
        (is (eq :not-validated (bl.val:package-tx-result-status
                                (first results))))
        (is (= 0 (bl.mp:mempool-count mempool)))))))

(test package-not-child-with-parents-rejected
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((stray (%pkg-tx funding-txid 0 99990000))
           (child (%pkg-tx (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4)
                           0 50000)))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list stray child) utxo-set mempool chain-state)
        (declare (ignore results replaced))
        (is (eq :package-not-child-with-parents msg))
        (is (= 0 (bl.mp:mempool-count mempool)))))))

;;;; RPC shape

(test rpc-submitpackage-cpfp-shape
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((node (bl::make-node :network :testnet3))
           (parent (%pkg-tx funding-txid 0 (- 100000000 50)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 50) 50000)))
           (phex (bl.crypto:bytes-to-hex
                  (bl.ser:serialize-transaction parent)))
           (chex (bl.crypto:bytes-to-hex
                  (bl.ser:serialize-transaction child))))
      (setf (bl::node-chain-state node) chain-state
            (bl::node-utxo-set node) utxo-set
            (bl::node-mempool node) mempool)
      (let* ((result (bl.rpc::rpc-submitpackage node (list (list phex chex))))
             (msg (cdr (assoc "package_msg" result :test #'string=)))
             (tx-results (cdr (assoc "tx-results" result :test #'string=))))
        (is (string= "success" msg))
        (is (= 2 (length tx-results)))
        ;; each entry is (wtxid-hex . field-alist) carrying at least a txid
        (is-true (every (lambda (e) (assoc "txid" (cdr e) :test #'string=)) tx-results))))))

(test rpc-submitpackage-broadcasts-accepted-members
  "submitpackage queues an announcement for every package member that made
it into the mempool (Core rpc/mempool.cpp:1423-1444 runs
BroadcastTransaction per accepted tx). The members are NOT added to the
unbroadcast set: they are already in the pool when broadcast runs, so
Core's already-in-mempool branch (node/transaction.cpp:63-72) relays
without AddUnbroadcastTx — matched exactly."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((node (bl::make-node :network :testnet3))
           (peer (bl.net:make-peer :state :ready))
           (parent (%pkg-tx funding-txid 0 (- 100000000 50)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 50) 50000)))
           (phex (bl.crypto:bytes-to-hex
                  (bl.ser:serialize-transaction parent)))
           (chex (bl.crypto:bytes-to-hex
                  (bl.ser:serialize-transaction child))))
      (setf (bl::node-chain-state node) chain-state
            (bl::node-utxo-set node) utxo-set
            (bl::node-mempool node) mempool
            (bl::node-peers node) (list peer))
      (let ((result (bl.rpc::rpc-submitpackage node (list (list phex chex)))))
        (is (string= "success" (cdr (assoc "package_msg" result :test #'string=)))))
      ;; Both members queued for announcement to the relay peer.
      (let ((queued (bl.net::peer-tx-inv-queue peer)))
        (is (= 2 (length queued)))
        (is-true (find pid queued :key #'first :test #'equalp))
        (is-true (find (bl.ser:transaction-hash child)
                       queued :key #'first :test #'equalp)))
      (is (= 0 (bl.mp:mempool-unbroadcast-count mempool))))))

(test single-tx-in-sub-1-satvb-band-accepted
  "A lone tx paying ~0.5 sat/vB -- inside the 0.1..1.0 sat/vB band Core relays --
is accepted under the 100 sat/kvB floor (the old 1 sat/vB integer floor rejected
the entire band)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let ((tx (%pkg-tx funding-txid 0 (- 100000000 50))))   ; 50 sat fee
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list tx) utxo-set mempool chain-state)
        (declare (ignore results replaced))
        (is (eq :success msg))
        (is-true (bl.mp:mempool-has
                  mempool (bl.ser:transaction-hash tx)))))))

;;;; Package RBF (cluster mempool P8 — Core PackageRBFChecks,
;;;; validation.cpp:1034-1130, wired through %accept-package-subset)

(defun %pkg-tx-2in (prev1 idx1 prev2 idx2 out-value)
  "A two-input P2SH(OP_TRUE) tx spending (PREV1,IDX1) and (PREV2,IDX2)."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash prev1 :index idx1)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff)
                   (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash prev2 :index idx2)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                     :value out-value
                     :script-pubkey (p2sh-optrue-script-pubkey)))
   :lock-time 0))

(test package-rbf-replaces-mempool-conflict
  "A 1p1c package whose parent conflicts with a pool tx replaces it when the
package out-earns it through the diagram check: the conflict is evicted and
both members enter the pool."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((a (%pkg-tx funding 0 99999000))          ; pool tx, fee 1000
           (aid (bl.ser:transaction-hash a))
           ;; Parent double-spends FUNDING:0 at a sub-floor fee (5 sat) so its
           ;; individual attempt defers; the child carries the package.
           (parent (%pkg-tx funding 0 99999995))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 99949995))          ; fee 50000
           (cid (bl.ser:transaction-hash child)))
      (is (eq :ok (%add-tx mempool a :fee 1000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :success msg))
        (is (every (lambda (r) (eq :valid (bl.val:package-tx-result-status r)))
                   results))
        (is (member aid replaced :test #'equalp)))
      (is (not (bl.mp:mempool-has mempool aid)))
      (is (bl.mp:mempool-has mempool pid))
      (is (bl.mp:mempool-has mempool cid)))))

(test package-rbf-insufficient-total-fees-rejected
  "Package RBF rule 3 on the totals: a pair whose combined fees do not cover
the replaced tx's is rejected and the pool is untouched."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((a (%pkg-tx funding 0 99950000))          ; pool tx, fee 50000
           (aid (bl.ser:transaction-hash a))
           (parent (%pkg-tx funding 0 99999995))     ; fee 5, conflicts with A
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 99989995)))         ; fee 10000
      (is (eq :ok (%add-tx mempool a :fee 50000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore results))
        (is (eq :insufficient-fee msg))
        (is (null replaced)))
      (is (bl.mp:mempool-has mempool aid))
      (is (not (bl.mp:mempool-has mempool pid))))))

(test package-rbf-mempool-ancestors-rejected
  "Package RBF requires NO in-mempool ancestors (the resulting cluster must
be exactly the pair, Core validation.cpp:1052-1064): a conflicting package
whose parent also spends a pool tx's output is rejected."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((funding2 (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 8))
           (m (%pkg-tx funding 0 99999000))          ; pool tx: parent's ancestor
           (mid (bl.ser:transaction-hash m))
           (a2 (%pkg-tx funding2 0 99999000))        ; pool tx: the conflict
           (a2id (bl.ser:transaction-hash a2))
           ;; Parent spends M:0 (in-mempool ancestor) AND double-spends
           ;; FUNDING2:0 (the conflict), at a sub-floor fee.
           (parent (%pkg-tx-2in mid 0 funding2 0 199998990))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 199948990)))        ; fee 50000
      (bl.store:add-utxo utxo-set funding2 0 100000000
                                     (p2sh-optrue-script-pubkey) 1 :coinbase nil)
      (is (eq :ok (%add-tx mempool m :fee 1000 :height 200)))
      (is (eq :ok (%add-tx mempool a2 :fee 1000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore results))
        (is (eq :package-rbf-mempool-ancestors msg))
        (is (null replaced)))
      (is (bl.mp:mempool-has mempool mid))
      (is (bl.mp:mempool-has mempool a2id))
      (is (not (bl.mp:mempool-has mempool pid))))))

(test package-rbf-not-1p1c-rejected
  "A conflicting multi-tx subset larger than 1-parent-1-child cannot use
package RBF (Core validation.cpp:1047-1050)."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((funding4 (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 9))
           (a (%pkg-tx funding 0 99999000))          ; pool tx, fee 1000
           (aid (bl.ser:transaction-hash a))
           (p1 (%pkg-tx funding 0 99999995))         ; conflicts with A, fee 5
           (p2 (%pkg-tx funding4 0 99999995))        ; fee 5
           (child (%pkg-tx-2in (bl.ser:transaction-hash p1) 0
                               (bl.ser:transaction-hash p2) 0
                               199899990)))          ; fee 100000
      (bl.store:add-utxo utxo-set funding4 0 100000000
                                     (p2sh-optrue-script-pubkey) 1 :coinbase nil)
      (is (eq :ok (%add-tx mempool a :fee 1000 :height 200)))
      (multiple-value-bind (msg results replaced)
          (bl.val:validate-package-for-mempool
           (list p1 p2 child) utxo-set mempool chain-state)
        (declare (ignore results))
        (is (eq :package-rbf-not-1p1c msg))
        (is (null replaced)))
      (is (bl.mp:mempool-has mempool aid)))))

;;;; TRUC sibling eviction through the single-tx acceptance path (Core
;;;; PreChecks, validation.cpp:950-970: the sibling joins the conflict set
;;;; and the replacement economics decide)

(defun %truc-2out-parent (funding)
  "A v3 parent spending FUNDING:0 with TWO outputs, so a second child does
not input-conflict with the first."
  (bl.ser:make-transaction
   :version 3
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash funding :index 0)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                     :value 49990000 :script-pubkey (p2sh-optrue-script-pubkey))
                    (bl.ser:make-tx-out
                     :value 49990000 :script-pubkey (p2sh-optrue-script-pubkey)))
   :lock-time 0))

(test truc-sibling-eviction-accepted-when-paying
  "A second TRUC child that pays enough EVICTS its sibling through the RBF
economics instead of being rejected on the descendant limit (Core PreChecks
sibling eviction, validation.cpp:950-970); one that does not pay is rejected
on the economics (:insufficient-fee), and with sibling eviction disabled the
TRUC error surfaces unchanged."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (declare (ignore chain-state))
    (let* ((parent (%truc-2out-parent funding))
           (pid (bl.ser:transaction-hash parent))
           (sib (%pkg-tx pid 0 49985000 :version 3))          ; fee 5000
           (sibid (bl.ser:transaction-hash sib))
           (rich (%pkg-tx pid 1 49930000 :version 3))         ; fee 60000
           (richid (bl.ser:transaction-hash rich))
           (poor (%pkg-tx pid 1 49984996 :version 3)))        ; fee 5004
      (is (eq :ok (%add-tx mempool parent :fee 20000 :height 200)))
      (is (eq :ok (%add-tx mempool sib :fee 5000 :height 200)))
      ;; Not paying its own bandwidth over the sibling's 5000 (rule 4 needs
      ;; ~+9 sat): rejected on the ECONOMICS, not the descendant limit.
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           poor utxo-set mempool 200)
        (is-false valid)
        (is (eq :insufficient-fee err)))
      ;; With sibling eviction disabled (the multi-tx package context), the
      ;; TRUC descendant-limit error surfaces instead.
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           rich utxo-set mempool 200 :allow-sibling-eviction nil)
        (is-false valid)
        (is (eq :truc-descendant-limit err)))
      ;; :skip-rbf-check alone also disables the fallthrough — with the
      ;; economics skipped there is nothing to evaluate the eviction.
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           rich utxo-set mempool 200 :skip-rbf-check t)
        (is-false valid)
        (is (eq :truc-descendant-limit err)))
      ;; Paying enough: the sibling is the replaced set; accepting evicts it.
      (multiple-value-bind (valid err fee replaced)
          (bl.val:validate-transaction-for-mempool
           rich utxo-set mempool 200)
        (declare (ignore err))
        (is-true valid)
        (is (= 60000 fee))
        (is (member sibid replaced :test #'equalp))
        (is (eq :ok (bl.mp:accept-validated-tx
                     mempool richid rich fee 200 :replaced replaced))))
      (is (not (bl.mp:mempool-has mempool sibid)))
      (is (bl.mp:mempool-has mempool richid))
      (is (bl.mp:mempool-has mempool pid)))))

;;;; Wave 7: sigop-cost recording + 16k standardness cap + package finality

(defun %bare-multisig-spk ()
  "A standard bare 1-of-3 multisig scriptPubKey. CHECKMULTISIG counts 20
legacy (inaccurate) sigops, so each such OUTPUT adds 20*4 = 80 weighted
sigop cost to the transaction that CREATES it (Core GetLegacySigOpCount
covers the tx's own outputs)."
  (let ((spk (make-array 105 :element-type '(unsigned-byte 8))))
    (setf (aref spk 0) #x51)            ; OP_1
    (loop for k below 3
          for base = (+ 1 (* k 34))
          do (setf (aref spk base) 33)  ; push 33 bytes
             (fill spk #x02 :start (1+ base) :end (+ base 34)))
    (setf (aref spk 103) #x53)          ; OP_3
    (setf (aref spk 104) #xae)          ; OP_CHECKMULTISIG
    spk))

(defun %multisig-outputs-tx (funding n-multisig change)
  "A tx spending the FUNDING P2SH(OP_TRUE) coin into N-MULTISIG bare 1-of-3
multisig outputs of 1000 sat each, plus a CHANGE P2SH(OP_TRUE) output."
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash funding :index 0)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff))
   :outputs (coerce
             (append (loop repeat n-multisig
                           collect (bl.ser:make-tx-out
                                    :value 1000
                                    :script-pubkey (%bare-multisig-spk)))
                     (list (bl.ser:make-tx-out
                            :value change :script-pubkey (p2sh-optrue-script-pubkey))))
             'simple-vector)
   :lock-time 0))

(test mempool-acceptance-records-sigop-cost
  "The weighted sigop cost computed during validation is returned (5th value)
and recorded on the mempool entry — the value the block assembler's sigop
budget consumes (Core PreChecks -> StageAddition sigops_cost,
validation.cpp:905,924). 5 bare 1-of-3 multisig outputs = 5 * 20 * 4 = 400."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((tx (%multisig-outputs-tx funding 5 99900000))
           (txid (bl.ser:transaction-hash tx)))
      (multiple-value-bind (valid err fee replaced sigops)
          (bl.val:validate-transaction-for-mempool
           tx utxo-set mempool 200 :chain-state chain-state)
        (declare (ignore err))
        (is-true valid)
        (is (= 400 sigops))
        (is (eq :ok (bl.mp:accept-validated-tx
                     mempool txid tx fee 200
                     :sigops sigops :replaced replaced))))
      (is (= 400 (bl.mp:mempool-entry-sigops
                  (bl.mp:mempool-get mempool txid)))))))

(test standardness-sigop-cap-is-16000
  "MAX_STANDARD_TX_SIGOPS_COST is MAX_BLOCK_SIGOPS_COST/5 = 16,000 (Core
policy.h:43), not the 80,000 block budget: 201 bare multisig outputs
(16,080 cost) are rejected, 200 (exactly 16,000 — Core rejects on >) pass."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (multiple-value-bind (valid err)
        (bl.val:validate-transaction-for-mempool
         (%multisig-outputs-tx funding 201 99000000)
         utxo-set mempool 200 :chain-state chain-state)
      (is-false valid)
      (is (eq :too-many-sigops err)))
    (multiple-value-bind (valid err fee replaced sigops)
        (bl.val:validate-transaction-for-mempool
         (%multisig-outputs-tx funding 200 99000000)
         utxo-set mempool 200 :chain-state chain-state)
      (declare (ignore err fee replaced))
      (is-true valid)
      (is (= 16000 sigops)))))

(test package-member-nonfinal-rejected
  "A submitpackage member with an unmet nLockTime is rejected — Core's
PreChecks runs CheckFinalTxAtTip for package members like any other tx
(validation.cpp:819); previously the package path skipped finality entirely
and a timelocked tx could sit in the mempool and get mined. The zero-fee
parent forces the CPFP package-feerate path."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 100000000))     ; zero fee -> deferred
           (pid (bl.ser:transaction-hash parent))
           (child (bl.ser:make-transaction
                   :version 2
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output (bl.ser:make-outpoint
                                                      :hash pid :index 0)
                                    :script-sig (%p2sh-optrue-scriptsig)
                                    :sequence 0))   ; non-final sequence: locktime enforced
                   :outputs (vector (bl.ser:make-tx-out
                                     :value 99900000
                                     :script-pubkey (p2sh-optrue-script-pubkey)))
                   :lock-time 500)))                  ; height 500 > next block 201
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :non-final msg))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results child)))))
      (is (not (bl.mp:mempool-has mempool pid))))))

(test package-member-bip68-nonfinal-rejected
  "A submitpackage member whose BIP68 relative lock cannot be satisfied is
rejected. The child's 5-block height lock is on an UNCONFIRMED parent, which
Core assumes confirms in the next block (prevheight = tip+1,
validation.cpp:185-192) — so any nonzero relative lock on it is non-final."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 100000000))     ; zero fee -> deferred
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 99900000 :sequence 5)))   ; 5-block relative lock
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :non-bip68-final msg))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results child)))))
      (is (not (bl.mp:mempool-has mempool pid))))))

(test fee-floor-uses-sigop-adjusted-vsize
  "The relay fee floor prices sigop-dense txs on the ADJUSTED virtual size
(Core CheckFeeRate runs on ws.m_vsize = the entry's GetTxSize,
validation.cpp:929,945): 200 bare multisig outputs adjust ~23 kvB of actual
bytes up to 80,000 vB (16,000 sigops * 20 / 4), so a fee ample for the raw
size fails the floor."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let ((tx (%multisig-outputs-tx funding 200 99795000)))   ; fee 5,000 sat
      ;; Ample for the raw ~23 kvB at 100 sat/kvB (needs ~2,300)...
      (is (> 5000 (ceiling (* 100 (bl.ser:transaction-vsize tx))
                           1000)))
      ;; ...but the adjusted 80,000 vB needs 8,000 sat.
      (multiple-value-bind (valid err)
          (bl.val:validate-transaction-for-mempool
           tx utxo-set mempool 200 :chain-state chain-state)
        (is-false valid)
        (is (eq :insufficient-fee err))))))

;;;; Wave 9C: PackageTRUCChecks (Core policy/truc_policy.cpp:58-170)

(defun %pkg-truc (mempool tx vsize txns)
  (bl.val:package-truc-checks mempool tx vsize txns))

(test package-truc-checks-inheritance
  "In-package v3<->v2 inheritance: a v3 member cannot spend an in-package v2
parent, a v2 member cannot spend an in-package v3 parent; a clean v3
parent/child pair passes."
  (let* ((mempool (bl.mp:make-mempool))
         (funding (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 21))
         (p3 (%pkg-tx funding 0 99990000 :version 3))
         (p3id (bl.ser:transaction-hash p3))
         (c3 (%pkg-tx p3id 0 99980000 :version 3))
         (p2 (%pkg-tx funding 0 99990000 :version 2))
         (p2id (bl.ser:transaction-hash p2))
         (c3-of-v2 (%pkg-tx p2id 0 99980000 :version 3))
         (c2-of-v3 (%pkg-tx p3id 0 99980000 :version 2)))
    ;; clean v3 pair: both members pass
    (is (null (%pkg-truc mempool p3 100 (list p3 c3))))
    (is (null (%pkg-truc mempool c3 100 (list p3 c3))))
    ;; v3 spending in-package v2 parent
    (is (eq :truc-v3-spends-nonv3
            (%pkg-truc mempool c3-of-v2 100 (list p2 c3-of-v2))))
    ;; v2 spending in-package v3 parent
    (is (eq :truc-nonv3-spends-v3
            (%pkg-truc mempool c2-of-v3 100 (list p3 c2-of-v3))))))

(test package-truc-checks-child-size-and-ancestors
  "A v3 child of an in-package parent is capped at TRUC_CHILD_MAX_VSIZE =
1000 vB; ancestor counting spans mempool AND in-package parents (limit 2
including self); a member with both a parent and an in-package child fails."
  (let* ((mempool (bl.mp:make-mempool))
         (funding (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 22))
         (a (%pkg-tx funding 0 99990000 :version 3))
         (aid (bl.ser:transaction-hash a))
         (b (%pkg-tx aid 0 99980000 :version 3))
         (bid (bl.ser:transaction-hash b))
         (c (%pkg-tx bid 0 99970000 :version 3)))
    ;; child size cap (vsize passed directly)
    (is (eq :truc-child-too-big (%pkg-truc mempool b 1001 (list a b))))
    (is (null (%pkg-truc mempool b 1000 (list a b))))
    ;; grandparent chain [A B C]: B has a parent (A) and an in-package
    ;; child (C) -> too many ancestors (Core truc_policy.cpp:138-142).
    (is (eq :truc-too-many-ancestors (%pkg-truc mempool b 100 (list a b c))))
    ;; C itself: one in-package parent (B) + self = 2, fine in isolation...
    ;; but B's violation already kills the package; C alone passes.
    (is (null (%pkg-truc mempool c 100 (list b c))))))

(test package-truc-checks-in-package-sibling
  "Two package members spending the same TRUC parent exceed the descendant
limit, with NO sibling-eviction escape (the sibling is in the same package,
Core truc_policy.cpp:127-136); a mempool parent that already has a
descendant is likewise at its limit."
  (let* ((mempool (bl.mp:make-mempool))
         (funding (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 23))
         (parent (%truc-2out-parent funding))
         (pid (bl.ser:transaction-hash parent))
         (c1 (%pkg-tx pid 0 49980000 :version 3))
         (c2 (%pkg-tx pid 1 49980000 :version 3)))
    ;; in-package sibling: checking either child sees the other spend PID
    (is (eq :truc-descendant-limit (%pkg-truc mempool c1 100 (list parent c1 c2))))
    ;; mempool parent with an existing pool child: a package child of it is
    ;; one descendant too many
    (is (eq :ok (%add-tx mempool parent :fee 20000 :height 200)))
    (is (eq :ok (%add-tx mempool c1 :fee 20000 :height 200)))
    (is (eq :truc-descendant-limit (%pkg-truc mempool c2 100 (list c2))))))

(test package-truc-enforced-end-to-end
  "The in-package TRUC topology is enforced on the CPFP path: a v2 child
CPFPing a 0-fee v3 parent — invisible to the per-tx single checks because
the parent is not in the mempool — is rejected by PACKAGE-TRUC-CHECKS and
the mempool is untouched (pre-Wave-9 this package was ACCEPTED: the
PackageTRUCChecks port was a stub)."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 100000000 :version 3))   ; 0 fee -> deferred
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 99950000 :version 2)))        ; v2 spends v3!
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :truc-nonv3-spends-v3 msg))
        ;; package-level failure: members keep their phase-1 nonfinal results
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results parent)))))
      (is (= 0 (bl.mp:mempool-count mempool))))))

(test package-truc-child-size-end-to-end
  "TRUC_CHILD_MAX_VSIZE applies to a child of an IN-PACKAGE v3 parent on the
CPFP path (single checks only see in-mempool parents): a >1000-vB v3 child
fails the package."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 100000000 :version 3))   ; 0 fee -> deferred
           (pid (bl.ser:transaction-hash parent))
           ;; Bulk the child past 1000 vB with a large OP_RETURN output
           ;; (standard now that the datacarrier budget is 100k).
           (child (bl.ser:make-transaction
                   :version 3
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output (bl.ser:make-outpoint
                                                      :hash pid :index 0)
                                    :script-sig (%p2sh-optrue-scriptsig)
                                    :sequence #xffffffff))
                   :outputs (vector
                             (bl.ser:make-tx-out
                              :value 99000000
                              :script-pubkey (p2sh-optrue-script-pubkey))
                             (bl.ser:make-tx-out
                              :value 0
                              :script-pubkey
                              ;; OP_RETURN + OP_PUSHDATA2 + 2 len bytes + 1000
                              ;; data bytes = 1004-byte script.
                              (let ((s (make-array 1004 :element-type '(unsigned-byte 8)
                                                        :initial-element 0)))
                                (setf (aref s 0) #x6a      ; OP_RETURN
                                      (aref s 1) #x4d      ; OP_PUSHDATA2
                                      (aref s 2) (ldb (byte 8 0) 1000)
                                      (aref s 3) (ldb (byte 8 8) 1000))
                                s)))
                   :lock-time 0)))
      (is (> (bl.ser:transaction-vsize child) 1000))
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (declare (ignore results))
        (is (eq :truc-child-too-big msg)))
      (is (= 0 (bl.mp:mempool-count mempool))))))

;;;; Wave 9C: atomic package acceptance + Core result semantics

(test package-cluster-limit-failure-is-atomic
  "A package that fails the cluster limits leaves the mempool UNTOUCHED: the
staged cluster-limit check runs before any mutation (Core changeset
CheckMemPoolPolicyLimits, validation.cpp:1516-1520). Pre-Wave-9 the members
were added one by one and a mid-package :too-large-cluster stranded the
earlier members in the pool."
  (let ((bl.mp:*cluster-count-limit* 2))
    (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
      (let* ((m (%pkg-tx funding 0 99990000))          ; pool tx, fee 10000
             (mid (bl.ser:transaction-hash m))
             ;; P spends M's output at 0 fee -> deferred to the CPFP phase.
             (parent (%pkg-tx mid 0 99990000))
             (pid (bl.ser:transaction-hash parent))
             (child (%pkg-tx pid 0 99940000))          ; fee 50000
             (cid (bl.ser:transaction-hash child)))
        (is (eq :ok (%add-tx mempool m :fee 10000 :height 200)))
        ;; [M P C] would form a 3-tx cluster; the limit is 2. P alone would
        ;; fit (M-P = 2), so the pre-fix flow admitted P and then stranded it
        ;; when C tripped the limit.
        (multiple-value-bind (msg results replaced)
            (bl.val:validate-package-for-mempool
             (list parent child) utxo-set mempool chain-state)
          (declare (ignore results))
          (is (eq :too-large-cluster msg))
          (is (null replaced)))
        ;; ATOMIC: neither member entered; the pool is exactly as before.
        (is (bl.mp:mempool-has mempool mid))
        (is (not (bl.mp:mempool-has mempool pid)))
        (is (not (bl.mp:mempool-has mempool cid)))
        (is (= 1 (bl.mp:mempool-count mempool)))
        (bl.mp::%mempool-graph-verify mempool)))))

(test package-hard-failure-does-not-drop-later-members
  "A member failing individually for a non-fee reason no longer voids the
rest: Core keeps validating the remaining members individually and the
valid ones land in the mempool (AcceptPackage quit_early only skips the
package-feerate retry, validation.cpp:1694-1712)."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((funding2 (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 31))
           ;; P1: pays a 100-sat P2SH output -> :dust, a hard failure.
           (p1 (%pkg-tx funding 0 100))
           (p1id (bl.ser:transaction-hash p1))
           ;; P2: individually valid with an ample fee.
           (p2 (%pkg-tx funding2 0 99990000))
           (p2id (bl.ser:transaction-hash p2))
           (child (%pkg-tx-2in p1id 0 p2id 0 99000000)))
      (bl.store:add-utxo utxo-set funding2 0 100000000
                                     (p2sh-optrue-script-pubkey) 1 :coinbase nil)
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list p1 p2 child) utxo-set mempool chain-state)
        (is (eq :dust msg))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results p1))))
        (is (eq :dust (bl.val:package-tx-result-error
                       (%result-for results p1))))
        ;; P2 was validated on its own and ENTERED the mempool.
        (is (eq :valid (bl.val:package-tx-result-status
                        (%result-for results p2))))
        ;; The child keeps its individual :missing-input (nonfinal) result —
        ;; the package-feerate retry was skipped.
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results child))))
        (is (eq :missing-input (bl.val:package-tx-result-error
                                (%result-for results child)))))
      (is (bl.mp:mempool-has mempool p2id))
      (is (not (bl.mp:mempool-has mempool p1id))))))

(test package-feerate-failure-lands-on-child
  "A package-feerate failure is reported on the CHILD alone, carrying the
package feerate and the wtxids it was computed over (Core FeeFailure on
workspaces.back(), validation.cpp:1504-1509); the parent keeps its phase-1
individual fee failure without those fields."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 1)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- (- 100000000 1) 1))))
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state)
        (is (eq :insufficient-fee msg))
        (let ((pres (%result-for results parent))
              (cres (%result-for results child)))
          (is (eq :invalid (bl.val:package-tx-result-status pres)))
          (is (eq :invalid (bl.val:package-tx-result-status cres)))
          ;; the child carries the package-feerate diagnostics
          (is (not (null (bl.val:package-tx-result-effective-feerate cres))))
          (is (= 2 (length (bl.val:package-tx-result-effective-includes cres))))
          ;; the parent does not
          (is (null (bl.val:package-tx-result-effective-feerate pres))))))))
