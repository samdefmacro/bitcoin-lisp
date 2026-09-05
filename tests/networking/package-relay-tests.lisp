(in-package #:bitcoin-lisp.tests)

;;; Opportunistic 1-parent-1-child package relay over the P2P tx path, plus
;;; the reconsiderable rejects filter that makes it possible (Core
;;; node/txdownloadman_impl.cpp:125-148, :297-321, :371-396, :454-466,
;;; :544-551).
;;;
;;; The shape under test is the modern Lightning unilateral close: a
;;; commitment transaction that pays (nearly) no fee of its own plus a CPFP
;;; child that fee-bumps it. The two arrive as separate `tx` messages, and
;;; NEITHER is acceptable alone — the parent is under the fee floor, the child
;;; has a missing input. Before this wave the parent's fee failure was cached
;;; in the single rejects filter, which is permanent until the next block, so
;;; the parent was dropped before validation on every re-arrival and the pair
;;; could never be accepted, mined or relayed.
;;;
;;; Spendable fixtures are the P2SH(OP_TRUE) transactions from
;;; package-tests.lisp (%pkg-tx / make-package-fixture / %p2sh-optrue-*): standard,
;;; non-witness, and valid without a signing key. Non-witness means
;;; txid == wtxid, which is also the exact shape of the second divergence
;;; tested here.

(in-suite :package-relay-tests)

(defun %pr-peer ()
  "A :ready peer advertising NODE_WITNESS, like every modern Core peer."
  (bl.net:make-peer
   :address "pkgrelay" :state :ready
   :services bl.ser:+node-witness+))

(defun %pr-payload (tx &key witness)
  "The `tx` message payload for TX (header stripped), as handle-tx sees it.
With WITNESS, the BIP144 witness serialization -- what a getdata for MSG_WTX
or MSG_WITNESS_TX is answered with."
  (subseq (bl.ser:make-tx-message tx :witness witness) 24))

(defun %pr-witness-twin (tx witness-length)
  "TX with its witness replaced by a single WITNESS-LENGTH-byte element: the
SAME txid, a different wtxid -- a witness-malleated twin. At 450,000 bytes
the twin is over the weight limit, so it is rejected without the real
transaction's own validity being at stake."
  (bl.ser:make-transaction
   :version (bl.ser:transaction-version tx)
   :inputs (bl.ser:transaction-inputs tx)
   :outputs (bl.ser:transaction-outputs tx)
   :lock-time (bl.ser:transaction-lock-time tx)
   :witness (vector (list (make-array witness-length
                                      :element-type '(unsigned-byte 8)
                                      :initial-element 3)))))

(defun %pr-tx (inputs out-value)
  "A non-witness P2SH(OP_TRUE) transaction spending INPUTS — a list of
(txid . index) — and paying OUT-VALUE to a single P2SH(OP_TRUE) output."
  (bl.ser:make-transaction
   :version 2
   :inputs (coerce (mapcar
                    (lambda (in)
                      (bl.ser:make-tx-in
                       :previous-output (bl.ser:make-outpoint
                                         :hash (car in) :index (cdr in))
                       :script-sig (%p2sh-optrue-scriptsig)
                       :sequence #xffffffff))
                    inputs)
                   'vector)
   :outputs (vector (bl.ser:make-tx-out
                     :value out-value
                     :script-pubkey (p2sh-optrue-script-pubkey)))
   :lock-time 0))

(defun %pr-ctx (state utxo mempool rejects &optional peers)
  "The node-context handle-tx and handle-inv act on in this file: the
chainstate, its coins view, the mempool, the main rejects filter and (for the
relay half) the peer list."
  (bl.ctx:make-node-context :chain-state state :utxo-set utxo
                            :mempool mempool :recent-rejects rejects
                            :peers peers))

(defmacro %with-fresh-rejects ((rejects) &body body)
  "Run BODY with a fresh main rejects filter bound to REJECTS and the
node-global reconsiderable filter rebound to a fresh one, so reject state
never leaks between tests. Also brackets BODY with reset-tx-requests, since
handle-tx and the orphan-parent fetch both touch the shared tracker."
  `(let ((,rejects (bl:make-rejects-filter 100))
         (bl.val:*recent-rejects-reconsiderable*
           (bl:make-rejects-filter 100)))
     (bl.net:reset-tx-requests)
     (unwind-protect (progn ,@body)
       (bl.net:reset-tx-requests))))

(defmacro %counting-tx-validations ((counter) &body body)
  "Run BODY with VALIDATE-TRANSACTION-FOR-MEMPOOL wrapped in a call counter
bound to COUNTER. The real function still runs, so behaviour is unchanged;
the count says whether an arriving transaction reached validation at all,
which is the whole point of a rejects filter (Core's AlreadyHaveTx gate)."
  (let ((real (gensym "REAL")))
    `(let ((,counter 0)
           (,real (fdefinition
                   'bl.val:validate-transaction-for-mempool)))
       (unwind-protect
            (progn
              (setf (fdefinition
                     'bl.val:validate-transaction-for-mempool)
                    (lambda (&rest args)
                      (incf ,counter)
                      (apply ,real args)))
              ,@body)
         (setf (fdefinition
                'bl.val:validate-transaction-for-mempool)
               ,real)))))

(defun %pr-orphan-p (mempool tx)
  "T if TX is in MEMPOOL's orphan pool (wtxid-keyed)."
  (and (bl.mp:orphan-tx
        (bl.mp:mempool-orphan-pool mempool)
        (bl.ser:transaction-wtxid tx))
       t))

;;;; (a) The headline case: an LN-shaped CPFP pair arriving as two messages

(test ln-cpfp-pair-enters-mempool-as-a-package
  "Parent below the fee floor, then its CPFP child, then the parent again —
the pair enters the mempool as a 1p1c package. Every step of the sequence is
asserted, because each one used to fail:

  1. the parent's fee failure is RECONSIDERABLE: it goes to the second
     filter, NOT the main rejects filter (which is what black-holed it);
  2. the child is kept as an orphan even though its only missing parent is a
     rejected transaction — Core tolerates one reconsiderable parent;
  3. the re-sent parent is no longer dropped before validation: it is paired
     with the orphan and both are submitted as a package (Core ReceivedTx ->
     Find1P1CPackage -> ProcessNewPackage, txdownloadman_impl.cpp:544-551).

Against main this fails at step 1 already, and there is no path at all from
step 3 to the mempool."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bl.ser:transaction-hash child))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        ;; 1. The parent on its own: below the floor, reconsiderable.
        (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (is-false (bl.mp:mempool-has mempool pid))
        (is-true (bl.val:reconsiderable-reject-p
                  (bl.ser:transaction-wtxid parent)))
        (is-false (bl:recent-reject-p
                   rejects (bl.ser:transaction-wtxid parent)))
        ;; 2. The child: an orphan, not a reject.
        (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
        (is-true (%pr-orphan-p mempool child))
        (is-false (bl:recent-reject-p rejects cid))
        ;; 3. The parent again: accepted as a package with the orphan child.
        (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (is-true (bl.mp:mempool-has mempool pid))
        (is-true (bl.mp:mempool-has mempool cid))
        ;; The child left the orphanage when it entered the mempool
        ;; (Core MempoolAcceptedTx -> EraseTx).
        (is-false (%pr-orphan-p mempool child))))))

(test ln-cpfp-pair-accepted-when-the-child-arrives-first
  "The other arrival order, and the one Core optimises for: the child is
already an orphan when the parent arrives for the FIRST time, so the
parent's very first fee failure forms the package (Core's
ProcessInvalidTx -> Find1P1CPackage on first_time_failure,
txdownloadman_impl.cpp:460-465). No re-announcement is needed."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bl.ser:transaction-hash child))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
        (is-true (%pr-orphan-p mempool child))
        (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (is-true (bl.mp:mempool-has mempool pid))
        (is-true (bl.mp:mempool-has mempool cid))
        (is-false (%pr-orphan-p mempool child))))))

(test reconsiderable-parent-alone-is-still-rejected
  "The control for the test above: with NO child in the orphanage, a
re-arriving low-fee parent is still not accepted. The fee floor is intact —
1p1c relay makes the parent reconsiderable, not acceptable."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bl.ser:transaction-hash parent))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (is-false (bl.mp:mempool-has mempool pid))
        (is (zerop (bl.mp:mempool-count mempool)))))))

(test one-p-one-c-only-pairs-children-from-the-same-peer
  "Core's censorship guard: Find1P1CPackage only considers children the SAME
peer announced (txdownloadman_impl.cpp:303-307), so a flood of fake children
from an attacker cannot displace the honest peer's real one. Here the child
comes from peer B, the parent from peer A: no package is formed."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bl.ser:transaction-hash child))
           (peer-a (%pr-peer))
           (peer-b (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (deliver-tx peer-a (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (deliver-tx peer-b (%pr-payload child) (%pr-ctx state utxo mempool rejects))
        (is-true (%pr-orphan-p mempool child))
        (deliver-tx peer-a (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (is-false (bl.mp:mempool-has mempool pid))
        (is-false (bl.mp:mempool-has mempool cid))))))

;;;; (b) A non-segwit low-fee parent must not blacklist its child

(test nonsegwit-low-fee-parent-does-not-blacklist-child
  "A low-feerate NON-SEGWIT parent has txid == wtxid, so its cached failure
is visible under the id the child's orphan-intake scan looks up. Core
distinguishes the two filters there and tolerates exactly one reconsiderable
parent (txdownloadman_impl.cpp:371-396): the child stays in the orphanage.
Previously the parent's fee failure sat in the MAIN filter and the child was
blacklisted under both of its own ids — permanently, until the next block."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bl.ser:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bl.ser:transaction-hash child))
           (peer (%pr-peer)))
      ;; The precondition that makes this case distinct.
      (is (equalp pid (bl.ser:transaction-wtxid parent)))
      (%with-fresh-rejects (rejects)
        (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
        (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
        (is-true (%pr-orphan-p mempool child))
        (is-false (bl:recent-reject-p rejects cid))
        (is-false (bl:recent-reject-p
                   rejects (bl.ser:transaction-wtxid child)))))))

(test two-reconsiderable-parents-do-blacklist-the-child
  "The boundary on the other side: 1p1c submits ONE parent with one child, so
a child whose TWO missing parents both failed reconsiderably can never be
rescued. Core gives up at the second one (txdownloadman_impl.cpp:379-386) and
rejects the child under both ids rather than holding it in the orphanage."
  (let* ((utxo (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (state (bl.store:make-chain-state :best-height 200))
         (fund-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
         (fund-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 22))
         (peer (%pr-peer)))
    (bl.store:add-utxo utxo fund-a 0 100000000 (p2sh-optrue-script-pubkey) 1)
    (bl.store:add-utxo utxo fund-b 0 100000000 (p2sh-optrue-script-pubkey) 1)
    (let* ((pa (%pr-tx (list (cons fund-a 0)) (- 100000000 5)))
           (pb (%pr-tx (list (cons fund-b 0)) (- 100000000 5)))
           (paid (bl.ser:transaction-hash pa))
           (pbid (bl.ser:transaction-hash pb))
           (child (%pr-tx (list (cons paid 0) (cons pbid 0))
                          (- (* 2 (- 100000000 5)) 50000)))
           (cid (bl.ser:transaction-hash child)))
      (%with-fresh-rejects (rejects)
        (deliver-tx peer (%pr-payload pa) (%pr-ctx state utxo mempool rejects))
        (deliver-tx peer (%pr-payload pb) (%pr-ctx state utxo mempool rejects))
        ;; Both parents are reconsiderable — the precondition.
        (is-true (bl.val:reconsiderable-reject-p paid))
        (is-true (bl.val:reconsiderable-reject-p pbid))
        (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
        (is-false (%pr-orphan-p mempool child))
        (is-true (bl:recent-reject-p rejects cid))
        (is-true (bl:recent-reject-p
                  rejects (bl.ser:transaction-wtxid child)))))))

;;;; (c) The DoS control: genuinely invalid transactions are still cached

(test invalid-tx-still-cached-and-dropped-before-revalidation
  "The control that this wave did not simply weaken the rejects filter. A
transaction that fails for a NON-reconsiderable reason still lands in the
MAIN filter and is dropped on re-arrival WITHOUT being re-validated — the
whole DoS property of the filter. The call counter carries its own positive
control: the first arrival must reach validation exactly once, or a count of
zero on the second would prove nothing."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((peer (%pr-peer))
           ;; version 5 > +max-standard-tx-version+: rejected as
           ;; :version-non-standard, a plain (non-reconsiderable) failure.
           (bad (%pkg-tx funding 0 (- 100000000 10000) :version 5))
           (bad-id (bl.ser:transaction-hash bad)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          (deliver-tx peer (%pr-payload bad) (%pr-ctx state utxo mempool rejects))
          (is (= 1 calls) "first arrival must reach validation" calls)
          (is-true (bl:recent-reject-p rejects bad-id))
          (is-false (bl.val:reconsiderable-reject-p bad-id))
          ;; Re-announced: dropped at the precheck, never re-validated.
          (deliver-tx peer (%pr-payload bad) (%pr-ctx state utxo mempool rejects))
          (is (= 1 calls) "re-arrival must not be re-validated" calls)
          (is-false (bl.mp:mempool-has mempool bad-id)))))))

;;;; (d) Post-validation mempool-add failures are cached too

(test mempool-full-is-cached-reconsiderably-and-not-revalidated
  "A transaction that passes validation but self-evicts on the post-add trim
fails with \"mempool full\", which Core marks TX_RECONSIDERABLE
(validation.cpp:1399-1402). It was previously cached NOWHERE, so every
re-announcement was re-downloaded and fully re-validated. It must now land in
the reconsiderable filter — not the main one, since a package could still
carry it — and be dropped before validation on re-arrival."
  (let* ((utxo (bl.store:make-utxo-set))
         ;; A zero-byte cap: the trim after the add evicts the new entry.
         (mempool (bl.mp:make-mempool :max-size 0))
         (state (bl.store:make-chain-state :best-height 200))
         (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 31))
         (peer (%pr-peer)))
    (bl.store:add-utxo utxo funding 0 100000000 (p2sh-optrue-script-pubkey) 1)
    (let* ((tx (%pr-tx (list (cons funding 0)) (- 100000000 10000)))
           (txid (bl.ser:transaction-hash tx)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          (deliver-tx peer (%pr-payload tx) (%pr-ctx state utxo mempool rejects))
          (is (= 1 calls) "first arrival must reach validation" calls)
          (is-false (bl.mp:mempool-has mempool txid))
          (is-true (bl.val:reconsiderable-reject-p txid))
          (is-false (bl:recent-reject-p rejects txid))
          (deliver-tx peer (%pr-payload tx) (%pr-ctx state utxo mempool rejects))
          (is (= 1 calls) "re-arrival must not be re-validated" calls))))))

;;;; (e) A FAILED 1p1c package must not black-hole its members
;;;
;;; The mirror of section (a). When a 1p1c package fails a PACKAGE-LEVEL check
;;; — TRUC topology, package RBF, cluster limits, ephemeral dust, or the
;;; quit-early path — validate-package-for-mempool leaves the CHILD's phase-1
;;; individual result untouched, and that result is :invalid / :missing-input.
;;; Core carries exactly that nonfinal TX_MISSING_INPUTS into results_final
;;; (validation.cpp:1759-1763) so that ProcessPackageResult can see it and do
;;; NOTHING with it: MempoolRejectedTx's TX_MISSING_INPUTS branch is gated on
;;; first_time_failure, which ProcessPackageResult always passes as false
;;; (net_processing.cpp:3209), so nothing is cached and the child is not even
;;; erased from the orphanage (txdownloadman_impl.cpp:360-362, 490-492).
;;;
;;; Caching it in the MAIN rejects filter instead would black-hole the child
;;; until the next block — dropped at the handle-tx precheck, dropped from
;;; every peer's inv by AlreadyHaveTx, and (for a non-segwit child, where
;;; txid == wtxid) excluded from every future pairing by Find1P1CPackage's own
;;; child-txid guard. That is the failure mode the reconsiderable-filter split
;;; exists to remove, in the mirror direction.

(defun %pr-rbf-loser-fixture ()
  "The package-RBF loss: a well-paying RIVAL already holds the funding
outpoint, PARENT double-spends it at a sub-floor fee, CHILD fee-bumps PARENT.
The pair is a legitimate CPFP package, it just cannot out-earn RIVAL, so
validate-package-for-mempool fails at the package-RBF step — a PACKAGE-level
failure that overwrites no member result. Returns
(values utxo mempool state rival parent child)."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((rival (%pkg-tx funding 0 (- 100000000 50000)))     ; fee 50000
           (parent (%pkg-tx funding 0 (- 100000000 5)))        ; fee 5
           (child (%pkg-tx (bl.ser:transaction-hash parent)
                           0 (- 100000000 5 10000))))          ; fee 10000
      (values utxo mempool state rival parent child))))

(test package-level-failure-keeps-the-childs-missing-input-result
  "The precondition the P2P test below rests on, asserted directly so that
test cannot go vacuous: a package-RBF loss is a PACKAGE-level failure, so the
CHILD still carries the nonfinal :missing-input from phase 1 (Core
individual_results_nonfinal -> results_final, validation.cpp:1759-1763). If
the failure had come from the package-FEERATE step instead, the child's
result would read :insufficient-fee and no :missing-input would ever reach
the caller."
  (multiple-value-bind (utxo mempool state rival parent child)
      (%pr-rbf-loser-fixture)
    (is (eq :ok (%add-tx mempool rival :fee 50000 :height 200)))
    (multiple-value-bind (msg results)
        (bl.val:validate-package-for-mempool
         (list parent child) utxo mempool state)
      (is (eq :insufficient-fee msg))
      (let ((pres (%result-for results parent))
            (cres (%result-for results child)))
        (is (not (null pres)))
        (is (not (null cres)))
        (when (and pres cres)
          (is (eq :invalid (bl.val:package-tx-result-status pres)))
          (is (eq :insufficient-fee
                  (bl.val:package-tx-result-error pres)))
          (is (eq :invalid (bl.val:package-tx-result-status cres)))
          (is (eq :missing-input
                  (bl.val:package-tx-result-error cres))
              "the child must still carry its nonfinal missing-input result"))))
    ;; Nothing was admitted and RIVAL is untouched.
    (is (= 1 (bl.mp:mempool-count mempool)))))

(test failed-1p1c-package-does-not-blacklist-the-child
  "THE regression this section exists for. A 1p1c package that loses a
package-RBF race must not put the CHILD into the MAIN rejects filter: its
carried failure is :missing-input, which Core caches nowhere. Driven end to
end through handle-tx.

Also asserts the two halves the walk must keep doing: the failed COMBINATION
is remembered by package hash (Core MempoolRejectedPackage, so the same pair
is not re-validated on every re-announcement), and the PARENT's own
:insufficient-fee still lands in the RECONSIDERABLE filter, never the main
one."
  (multiple-value-bind (utxo mempool state rival parent child)
      (%pr-rbf-loser-fixture)
    (let* ((rid (bl.ser:transaction-hash rival))
           (pid (bl.ser:transaction-hash parent))
           (pwtxid (bl.ser:transaction-wtxid parent))
           (cid (bl.ser:transaction-hash child))
           (cwtxid (bl.ser:transaction-wtxid child))
           (pool (bl.mp:mempool-orphan-pool mempool))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          ;; RIVAL wins the outpoint honestly.
          (deliver-tx peer (%pr-payload rival) (%pr-ctx state utxo mempool rejects))
          (is-true (bl.mp:mempool-has mempool rid))
          ;; The sub-floor double-spending PARENT: reconsiderable, not main.
          (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
          (is-true (bl.val:reconsiderable-reject-p pwtxid))
          ;; The CHILD: held as an orphan (one reconsiderable parent is fine).
          (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
          (is-true (%pr-orphan-p mempool child))
          ;; The parent again — this forms the package, and it FAILS.
          (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
          ;; The package path really ran and really failed as a package.
          (is-true (bl.val:reconsiderable-reject-p
                    (bl.val:package-hash (list parent child)))
                   "the failed combination must be remembered by package hash")
          (is-false (bl.mp:mempool-has mempool pid))
          (is-false (bl.mp:mempool-has mempool cid))
          (is-true (bl.mp:mempool-has mempool rid))
          ;; THE BLOCKER: the child is cached NOWHERE, under either id.
          (is-false (bl:recent-reject-p rejects cwtxid)
                    "child wtxid must not enter the MAIN rejects filter")
          (is-false (bl:recent-reject-p rejects cid)
                    "child txid must not enter the MAIN rejects filter")
          (is-false (bl.val:reconsiderable-reject-p cwtxid))
          ;; ...and it is not erased from the orphanage either
          ;; (txdownloadman_impl.cpp:490-492 excludes TX_MISSING_INPUTS).
          (is-true (%pr-orphan-p mempool child))
          ;; CONTROL (b): the parent's own fee failure is still reconsiderable.
          (is-true (bl.val:reconsiderable-reject-p pwtxid))
          (is-false (bl:recent-reject-p rejects pwtxid))
          ;; The child is still RETRYABLE. Simulate the orphanage eviction
          ;; LimitOrphans performs under load: the announcement must still be
          ;; worth requesting (Core AlreadyHaveTx, the gate handle-inv uses)...
          (bl.mp:orphan-remove pool cwtxid)
          (is-false (bl.net::%already-have-tx-p
                     cwtxid t mempool rejects t)
                    "an inv for the child must still be requestable")
          ;; ...and the re-sent child must reach validation instead of being
          ;; dropped at handle-tx's precheck, and be held as an orphan again.
          (let ((before calls))
            (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
            (is (= (1+ before) calls)
                "re-sent child must reach validation, not the reject precheck"
                before calls))
          (is-true (%pr-orphan-p mempool child))
          ;; And once the blocking condition clears — the next block confirms
          ;; RIVAL and wipes both reject filters (Core ActiveTipChange) — the
          ;; honest CPFP pair is accepted after all.
          (bl.mp:mempool-remove mempool rid)
          (bl:clear-recent-rejects rejects)
          (bl.val:clear-reconsiderable-rejects)
          (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
          (is-true (bl.mp:mempool-has mempool pid))
          (is-true (bl.mp:mempool-has mempool cid)))))))

(defun %pr-badscript-child (parent-txid out-value)
  "A child of PARENT-TXID whose scriptSig pushes the WRONG redeemScript, so
the P2SH OP_EQUAL fails. Push-only and standard, so it is rejected only once
the parent's output is actually available — i.e. individually it is a plain
:missing-input orphan, and the hard failure surfaces inside the package."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash parent-txid :index 0)
                    :script-sig (make-array 2 :element-type '(unsigned-byte 8)
                                              :initial-contents '(#x01 #x00))
                    :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                     :value out-value
                     :script-pubkey (p2sh-optrue-script-pubkey)))
   :lock-time 0))

(test hard-failure-inside-a-1p1c-package-is-still-cached
  "CONTROL (a) for the test above: the fix must not simply stop caching
package members, which would be a DoS regression. A child that fails the
package for a HARD reason — its scripts do not verify once the parent's
output is available — still lands in the MAIN filter, still leaves the
orphanage (Core MempoolRejectedTx's tail erases everything except
TX_MISSING_INPUTS, txdownloadman_impl.cpp:490-492), and is dropped on
re-arrival WITHOUT being re-validated. The parent's :insufficient-fee still
goes to the reconsiderable filter — CONTROL (b) again, on this path."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))        ; fee 5
           (pid (bl.ser:transaction-hash parent))
           (pwtxid (bl.ser:transaction-wtxid parent))
           (child (%pr-badscript-child pid (- 100000000 5 10000)))
           (cid (bl.ser:transaction-hash child))
           (cwtxid (bl.ser:transaction-wtxid child))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
          (is-true (bl.val:reconsiderable-reject-p pwtxid))
          (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
          (is-true (%pr-orphan-p mempool child)
                   "the bad child must be an orphan first, or the package
never forms and this control asserts nothing")
          ;; Form the package; the child fails hard inside it.
          (deliver-tx peer (%pr-payload parent) (%pr-ctx state utxo mempool rejects))
          (is (zerop (bl.mp:mempool-count mempool)))
          (is-true (bl:recent-reject-p rejects cwtxid)
                   "a hard package failure must still be cached")
          (is-false (bl.val:reconsiderable-reject-p cwtxid))
          (is-false (%pr-orphan-p mempool child)
                    "a hard failure must leave the orphanage")
          ;; CONTROL (b): the parent is still only reconsiderable.
          (is-true (bl.val:reconsiderable-reject-p pwtxid))
          (is-false (bl:recent-reject-p rejects pwtxid))
          ;; Re-announced: dropped at the precheck, never re-validated.
          (let ((before calls))
            (deliver-tx peer (%pr-payload child) (%pr-ctx state utxo mempool rejects))
            (is (= before calls)
                "a cached hard failure must not be re-validated" before calls))
          (is-false (%pr-orphan-p mempool child))
          (is-false (bl.mp:mempool-has mempool cid)))))))

;;;; Filter plumbing

(test package-hash-is-order-independent
  "Core GetPackageHash sorts the wtxids before hashing (policy/packages.cpp:
151-170), so the identity of a package is the COMBINATION, not the order —
which is what lets a failed 1p1c pairing be remembered once."
  (multiple-value-bind (u m c funding) (make-package-fixture)
    (declare (ignore u m c))
    (let* ((a (%pkg-tx funding 0 99990000))
           (b (%pkg-tx (bl.ser:transaction-hash a) 0 99980000))
           (h1 (bl.val:package-hash (list a b)))
           (h2 (bl.val:package-hash (list b a))))
      (is (= 32 (length h1)))
      (is (equalp h1 h2))
      (is-false (equalp h1 (bl.val:package-hash (list a)))))))

(test reconsiderable-filter-cleared-on-tip-change
  "Core resets BOTH reject filters on every active tip change
(ActiveTipChange, txdownloadman_impl.cpp:91-95): a new block moves the fee
floor and changes which parents exist, so every cached fee failure is stale."
  (let ((bl.val:*recent-rejects-reconsiderable*
          (bl:make-rejects-filter 100))
        (h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 77)))
    (bl.val:add-reconsiderable-reject h)
    (is-true (bl.val:reconsiderable-reject-p h))
    (bl.val:clear-reconsiderable-rejects)
    (is-false (bl.val:reconsiderable-reject-p h))))

(test inv-for-reconsiderable-tx-is-not-requested
  "AlreadyHaveTx(include_reconsiderable=true) at announcement time: there is
no point downloading a transaction we would only submit alone again (Core
AddTxAnnouncement, txdownloadman_impl.cpp:199). The control is the same inv
with the filter empty, which IS requested."
  (let* ((bl.net:*cached-is-ibd* t)
         (bl:*network* :regtest)
         (bl:*minimum-chain-work-override* nil)
         (now (bl.ser:get-unix-time))
         (state (%make-ibd-latch-state now))
         (mempool (bl.mp:make-mempool))
         (announcer (bl.net:make-peer :state :ready
                                                       :wtxid-relay t))
         (probe (bl.net:make-peer :state :ready))
         (blocked (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 51))
         (fresh (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 52))
         (inv-payload
           (lambda (hash)
             (subseq (bl.ser:make-inv-message
                      (list (bl.ser:make-inv-vector
                             :type bl.ser:+inv-type-wtx+
                             :hash hash)))
                     24))))
    (%with-fresh-rejects (rejects)
      (bl.val:add-reconsiderable-reject blocked)
      (ignore-errors
       (deliver-inv announcer (funcall inv-payload blocked) (bl.ctx:make-node-context :chain-state state :mempool mempool :recent-rejects rejects)))
      ;; Nothing recorded: a probe from another peer still wants it.
      (is-true (bl.net:tx-request-wanted-p blocked probe t))
      (bl.net:reset-tx-requests)
      ;; Control: an unknown wtxid from the same announcer IS requested.
      (ignore-errors
       (deliver-inv announcer (funcall inv-payload fresh) (bl.ctx:make-node-context :chain-state state :mempool mempool :recent-rejects rejects)))
      (is-false (bl.net:tx-request-wanted-p fresh probe t)))))

;;;; Tx-request tracking across a delivery: ReceivedResponse vs ForgetTxHash
;;;
;;; Core's ReceivedTx completes the DELIVERING peer's announcement only
;;; (txdownloadman_impl.cpp:505-513 -> txrequest.cpp:667-676) and reserves
;;; ForgetTxHash for the points where the transaction is genuinely resolved:
;;; mempool acceptance (:325-328), orphan intake and rejected parents
;;; (:418-419, :434-435), a non-reconsiderable rejection (:470, :483-484) and
;;; block connection (:107-108).

(test tx-delivery-completes-only-the-delivering-peers-announcement
  "An unsolicited, witness-malleated copy of a transaction must not release
the peers that announced its TXID. The twin has the same txid and a different
wtxid, so it is rejected and cached under its OWN wtxid while the real
transaction is neither in the mempool nor blacklisted -- and before this fix
every honest announcer had been forgotten, so no further request went out and
the transaction (or the orphan whose parent it is) waited for an entirely new
announcer."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((real (%pr-tx (list (cons funding 0)) (- 100000000 50000)))
           (txid (bl.ser:transaction-hash real))
           (twin (%pr-witness-twin real 450000))
           (a (%pr-peer)) (b (%pr-peer)) (c (%pr-peer))
           (attacker (%pr-peer)))
      (is (equalp txid (bl.ser:transaction-hash twin)))
      (is-false (equalp (bl.ser:transaction-wtxid real)
                        (bl.ser:transaction-wtxid twin)))
      (%with-fresh-rejects (rejects)
        ;; Three peers announce the txid; the first holds the request.
        (is-true (bl.net:tx-request-wanted-p txid a))
        (is-false (bl.net:tx-request-wanted-p txid b))
        (is-false (bl.net:tx-request-wanted-p txid c))
        (is (eq a (tx-request-in-flight-peer txid)))
        (is (= 3 (length (tx-request-announcement-peers txid))))
        ;; A fourth peer, which announced nothing, sends the twin.
        (deliver-tx attacker (%pr-payload twin :witness t)
                    (%pr-ctx state utxo mempool rejects))
        ;; Witness that the delivery really reached the handler and really
        ;; was rejected for the malleation: the sender is marked as knowing
        ;; the txid, and the TWIN's wtxid -- not the txid -- is cached.
        (is-true (bl:recent-reject-p (bl.net:peer-announced-txs attacker) txid))
        (is-true (bl:recent-reject-p rejects (bl.ser:transaction-wtxid twin)))
        (is-false (bl:recent-reject-p rejects txid))
        (is-false (bl.mp:mempool-has mempool txid))
        ;; Every honest announcement survives; the attacker completed nothing
        ;; because it had nothing to complete.
        (is (= 3 (length (tx-request-announcement-peers txid))))
        (is (eq a (tx-request-in-flight-peer txid)))
        ;; And the transaction is still fetchable: a's window expiring hands
        ;; it to one of the other two.
        (is (eq a (expire-tx-request txid)))
        (is (= 1 (bl.net:retry-timed-out-tx-requests)))
        (is-true (member (tx-request-in-flight-peer txid) (list b c)))))))

(test tx-delivery-from-an-announcer-completes-its-own-slot
  "The other half of ReceivedResponse: when the DELIVERER is an announcer,
its own announcement completes -- the in-flight request is released and the
next scheduler pass re-routes to a co-announcer, which is what makes a peer
that answers with a useless transaction lose its window."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((real (%pr-tx (list (cons funding 0)) (- 100000000 50000)))
           (txid (bl.ser:transaction-hash real))
           (twin (%pr-witness-twin real 450000))
           (a (%pr-peer)) (b (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (is-true (bl.net:tx-request-wanted-p txid a))
        (is-false (bl.net:tx-request-wanted-p txid b))
        (deliver-tx a (%pr-payload twin :witness t)
                    (%pr-ctx state utxo mempool rejects))
        (is-true (tx-request-completed-p txid a))
        (is (equal (list b) (tx-request-announcement-peers txid)))
        (is (null (tx-request-in-flight-peer txid)))
        ;; Two announcements are moved: b's live one and a's completed one,
        ;; which the scheduler must skip.
        (is (= 2 (backdate-tx-announcements txid)))
        (is (= 1 (bl.net:process-tx-requests)))
        (is (eq b (tx-request-in-flight-peer txid)))))))

(test mempool-acceptance-forgets-every-announcer
  "ForgetTxHash belongs where the transaction is RESOLVED. Mempool acceptance
is Core's first such point (MempoolAcceptedTx, txdownloadman_impl.cpp:325-328,
\"as this version of the transaction was acceptable, we can forget about any
requests for it\"), so every peer's announcement goes, not only the
deliverer's."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((tx (%pr-tx (list (cons funding 0)) (- 100000000 50000)))
           (txid (bl.ser:transaction-hash tx))
           (a (%pr-peer)) (b (%pr-peer)) (c (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (is-true (bl.net:tx-request-wanted-p txid a))
        (is-false (bl.net:tx-request-wanted-p txid b))
        (is (= 2 (length (tx-request-announcement-peers txid))))
        (deliver-tx c (%pr-payload tx) (%pr-ctx state utxo mempool rejects))
        (is-true (bl.mp:mempool-has mempool txid))
        (is (null (tx-request-announcement-peers txid :completed t)))
        (is (null (tx-request-in-flight-peer txid)))
        (is (= 0 (bl.net:tx-request-count a)))
        (is (= 0 (bl.net:tx-request-count b)))))))

(test a-non-reconsiderable-rejection-forgets-the-wtxid-only
  "Core ForgetTxHash's the WTXID of a non-reconsiderable failure (:470) and
adds the TXID only for TX_INPUTS_NOT_STANDARD, whose verdict the txid alone
decides (:483-484). Anything else may be a verdict on this witness, so the
txid keeps its announcers -- the same rule the rejects filter follows, and
the reason the malleated twin above cannot blacklist the real transaction."
  (multiple-value-bind (utxo mempool state funding) (make-package-fixture)
    (let* ((real (%pr-tx (list (cons funding 0)) (- 100000000 50000)))
           (txid (bl.ser:transaction-hash real))
           (twin (%pr-witness-twin real 450000))
           (twin-wtxid (bl.ser:transaction-wtxid twin))
           (announcer (%pr-peer))
           (deliverer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        ;; The twin's own wtxid was announced too, by the peer that sends it.
        (is-true (bl.net:tx-request-wanted-p twin-wtxid deliverer t))
        (is-true (bl.net:tx-request-wanted-p txid announcer))
        (deliver-tx deliverer (%pr-payload twin :witness t)
                    (%pr-ctx state utxo mempool rejects))
        ;; The wtxid entry is forgotten outright: no witness can make this
        ;; one acceptable.
        (is (null (tx-request-announcement-peers twin-wtxid :completed t)))
        ;; The txid entry keeps its announcer.
        (is (equal (list announcer) (tx-request-announcement-peers txid)))))))
