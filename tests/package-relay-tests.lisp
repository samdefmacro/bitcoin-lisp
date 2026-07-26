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
;;; package-tests.lisp (%pkg-tx / %pkg-fixture / %p2sh-optrue-*): standard,
;;; non-witness, and valid without a signing key. Non-witness means
;;; txid == wtxid, which is also the exact shape of the second divergence
;;; tested here.

(in-suite :package-relay-tests)

(defun %pr-peer ()
  "A :ready peer advertising NODE_WITNESS, like every modern Core peer."
  (bitcoin-lisp.networking:make-peer
   :address "pkgrelay" :state :ready
   :services bitcoin-lisp.serialization:+node-witness+))

(defun %pr-payload (tx)
  "The `tx` message payload for TX (header stripped), as handle-tx sees it."
  (subseq (bitcoin-lisp.serialization:make-tx-message tx) 24))

(defun %pr-tx (inputs out-value)
  "A non-witness P2SH(OP_TRUE) transaction spending INPUTS — a list of
(txid . index) — and paying OUT-VALUE to a single P2SH(OP_TRUE) output."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (coerce (mapcar
                    (lambda (in)
                      (bitcoin-lisp.serialization:make-tx-in
                       :previous-output (bitcoin-lisp.serialization:make-outpoint
                                         :hash (car in) :index (cdr in))
                       :script-sig (%p2sh-optrue-scriptsig)
                       :sequence #xffffffff))
                    inputs)
                   'vector)
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value out-value
                     :script-pubkey (%p2sh-optrue-spk)))
   :lock-time 0))

(defmacro %with-fresh-rejects ((rejects) &body body)
  "Run BODY with a fresh main rejects filter bound to REJECTS and the
node-global reconsiderable filter rebound to a fresh one, so reject state
never leaks between tests. Also brackets BODY with reset-tx-requests, since
handle-tx and the orphan-parent fetch both touch the shared tracker."
  `(let ((,rejects (bitcoin-lisp:make-rejects-filter 100))
         (bitcoin-lisp.validation:*recent-rejects-reconsiderable*
           (bitcoin-lisp:make-rejects-filter 100)))
     (bitcoin-lisp.networking:reset-tx-requests)
     (unwind-protect (progn ,@body)
       (bitcoin-lisp.networking:reset-tx-requests))))

(defmacro %counting-tx-validations ((counter) &body body)
  "Run BODY with VALIDATE-TRANSACTION-FOR-MEMPOOL wrapped in a call counter
bound to COUNTER. The real function still runs, so behaviour is unchanged;
the count says whether an arriving transaction reached validation at all,
which is the whole point of a rejects filter (Core's AlreadyHaveTx gate)."
  (let ((real (gensym "REAL")))
    `(let ((,counter 0)
           (,real (fdefinition
                   'bitcoin-lisp.validation:validate-transaction-for-mempool)))
       (unwind-protect
            (progn
              (setf (fdefinition
                     'bitcoin-lisp.validation:validate-transaction-for-mempool)
                    (lambda (&rest args)
                      (incf ,counter)
                      (apply ,real args)))
              ,@body)
         (setf (fdefinition
                'bitcoin-lisp.validation:validate-transaction-for-mempool)
               ,real)))))

(defun %pr-orphan-p (mempool tx)
  "T if TX is in MEMPOOL's orphan pool (wtxid-keyed)."
  (and (bitcoin-lisp.mempool:orphan-tx
        (bitcoin-lisp.mempool:mempool-orphan-pool mempool)
        (bitcoin-lisp.serialization:transaction-wtxid tx))
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
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        ;; 1. The parent on its own: below the floor, reconsiderable.
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (is-false (bitcoin-lisp.mempool:mempool-has mempool pid))
        (is-true (bitcoin-lisp.validation:reconsiderable-reject-p
                  (bitcoin-lisp.serialization:transaction-wtxid parent)))
        (is-false (bitcoin-lisp:recent-reject-p
                   rejects (bitcoin-lisp.serialization:transaction-wtxid parent)))
        ;; 2. The child: an orphan, not a reject.
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload child) utxo mempool state nil :recent-rejects rejects)
        (is-true (%pr-orphan-p mempool child))
        (is-false (bitcoin-lisp:recent-reject-p rejects cid))
        ;; 3. The parent again: accepted as a package with the orphan child.
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (is-true (bitcoin-lisp.mempool:mempool-has mempool pid))
        (is-true (bitcoin-lisp.mempool:mempool-has mempool cid))
        ;; The child left the orphanage when it entered the mempool
        ;; (Core MempoolAcceptedTx -> EraseTx).
        (is-false (%pr-orphan-p mempool child))))))

(test ln-cpfp-pair-accepted-when-the-child-arrives-first
  "The other arrival order, and the one Core optimises for: the child is
already an orphan when the parent arrives for the FIRST time, so the
parent's very first fee failure forms the package (Core's
ProcessInvalidTx -> Find1P1CPackage on first_time_failure,
txdownloadman_impl.cpp:460-465). No re-announcement is needed."
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload child) utxo mempool state nil :recent-rejects rejects)
        (is-true (%pr-orphan-p mempool child))
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (is-true (bitcoin-lisp.mempool:mempool-has mempool pid))
        (is-true (bitcoin-lisp.mempool:mempool-has mempool cid))
        (is-false (%pr-orphan-p mempool child))))))

(test reconsiderable-parent-alone-is-still-rejected
  "The control for the test above: with NO child in the orphanage, a
re-arriving low-fee parent is still not accepted. The fee floor is intact —
1p1c relay makes the parent reconsiderable, not acceptable."
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (is-false (bitcoin-lisp.mempool:mempool-has mempool pid))
        (is (zerop (bitcoin-lisp.mempool:mempool-count mempool)))))))

(test one-p-one-c-only-pairs-children-from-the-same-peer
  "Core's censorship guard: Find1P1CPackage only considers children the SAME
peer announced (txdownloadman_impl.cpp:303-307), so a flood of fake children
from an attacker cannot displace the honest peer's real one. Here the child
comes from peer B, the parent from peer A: no package is formed."
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           (peer-a (%pr-peer))
           (peer-b (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (bitcoin-lisp.networking::handle-tx
         peer-a (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (bitcoin-lisp.networking::handle-tx
         peer-b (%pr-payload child) utxo mempool state nil :recent-rejects rejects)
        (is-true (%pr-orphan-p mempool child))
        (bitcoin-lisp.networking::handle-tx
         peer-a (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (is-false (bitcoin-lisp.mempool:mempool-has mempool pid))
        (is-false (bitcoin-lisp.mempool:mempool-has mempool cid))))))

;;;; (b) A non-segwit low-fee parent must not blacklist its child

(test nonsegwit-low-fee-parent-does-not-blacklist-child
  "A low-feerate NON-SEGWIT parent has txid == wtxid, so its cached failure
is visible under the id the child's orphan-intake scan looks up. Core
distinguishes the two filters there and tolerates exactly one reconsiderable
parent (txdownloadman_impl.cpp:371-396): the child stays in the orphanage.
Previously the parent's fee failure sat in the MAIN filter and the child was
blacklisted under both of its own ids — permanently, until the next block."
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (child (%pkg-tx pid 0 (- 100000000 5 50000)))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           (peer (%pr-peer)))
      ;; The precondition that makes this case distinct.
      (is (equalp pid (bitcoin-lisp.serialization:transaction-wtxid parent)))
      (%with-fresh-rejects (rejects)
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload child) utxo mempool state nil :recent-rejects rejects)
        (is-true (%pr-orphan-p mempool child))
        (is-false (bitcoin-lisp:recent-reject-p rejects cid))
        (is-false (bitcoin-lisp:recent-reject-p
                   rejects (bitcoin-lisp.serialization:transaction-wtxid child)))))))

(test two-reconsiderable-parents-do-blacklist-the-child
  "The boundary on the other side: 1p1c submits ONE parent with one child, so
a child whose TWO missing parents both failed reconsiderably can never be
rescued. Core gives up at the second one (txdownloadman_impl.cpp:379-386) and
rejects the child under both ids rather than holding it in the orphanage."
  (let* ((utxo (bitcoin-lisp.storage:make-utxo-set))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (state (bitcoin-lisp.storage:make-chain-state :best-height 200))
         (fund-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
         (fund-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 22))
         (peer (%pr-peer)))
    (bitcoin-lisp.storage:add-utxo utxo fund-a 0 100000000 (%p2sh-optrue-spk) 1)
    (bitcoin-lisp.storage:add-utxo utxo fund-b 0 100000000 (%p2sh-optrue-spk) 1)
    (let* ((pa (%pr-tx (list (cons fund-a 0)) (- 100000000 5)))
           (pb (%pr-tx (list (cons fund-b 0)) (- 100000000 5)))
           (paid (bitcoin-lisp.serialization:transaction-hash pa))
           (pbid (bitcoin-lisp.serialization:transaction-hash pb))
           (child (%pr-tx (list (cons paid 0) (cons pbid 0))
                          (- (* 2 (- 100000000 5)) 50000)))
           (cid (bitcoin-lisp.serialization:transaction-hash child)))
      (%with-fresh-rejects (rejects)
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload pa) utxo mempool state nil :recent-rejects rejects)
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload pb) utxo mempool state nil :recent-rejects rejects)
        ;; Both parents are reconsiderable — the precondition.
        (is-true (bitcoin-lisp.validation:reconsiderable-reject-p paid))
        (is-true (bitcoin-lisp.validation:reconsiderable-reject-p pbid))
        (bitcoin-lisp.networking::handle-tx
         peer (%pr-payload child) utxo mempool state nil :recent-rejects rejects)
        (is-false (%pr-orphan-p mempool child))
        (is-true (bitcoin-lisp:recent-reject-p rejects cid))
        (is-true (bitcoin-lisp:recent-reject-p
                  rejects (bitcoin-lisp.serialization:transaction-wtxid child)))))))

;;;; (c) The DoS control: genuinely invalid transactions are still cached

(test invalid-tx-still-cached-and-dropped-before-revalidation
  "The control that this wave did not simply weaken the rejects filter. A
transaction that fails for a NON-reconsiderable reason still lands in the
MAIN filter and is dropped on re-arrival WITHOUT being re-validated — the
whole DoS property of the filter. The call counter carries its own positive
control: the first arrival must reach validation exactly once, or a count of
zero on the second would prove nothing."
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((peer (%pr-peer))
           ;; version 5 > +max-standard-tx-version+: rejected as
           ;; :version-non-standard, a plain (non-reconsiderable) failure.
           (bad (%pkg-tx funding 0 (- 100000000 10000) :version 5))
           (bad-id (bitcoin-lisp.serialization:transaction-hash bad)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload bad) utxo mempool state nil :recent-rejects rejects)
          (is (= 1 calls) "first arrival must reach validation" calls)
          (is-true (bitcoin-lisp:recent-reject-p rejects bad-id))
          (is-false (bitcoin-lisp.validation:reconsiderable-reject-p bad-id))
          ;; Re-announced: dropped at the precheck, never re-validated.
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload bad) utxo mempool state nil :recent-rejects rejects)
          (is (= 1 calls) "re-arrival must not be re-validated" calls)
          (is-false (bitcoin-lisp.mempool:mempool-has mempool bad-id)))))))

;;;; (d) Post-validation mempool-add failures are cached too

(test mempool-full-is-cached-reconsiderably-and-not-revalidated
  "A transaction that passes validation but self-evicts on the post-add trim
fails with \"mempool full\", which Core marks TX_RECONSIDERABLE
(validation.cpp:1399-1402). It was previously cached NOWHERE, so every
re-announcement was re-downloaded and fully re-validated. It must now land in
the reconsiderable filter — not the main one, since a package could still
carry it — and be dropped before validation on re-arrival."
  (let* ((utxo (bitcoin-lisp.storage:make-utxo-set))
         ;; A zero-byte cap: the trim after the add evicts the new entry.
         (mempool (bitcoin-lisp.mempool:make-mempool :max-size 0))
         (state (bitcoin-lisp.storage:make-chain-state :best-height 200))
         (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 31))
         (peer (%pr-peer)))
    (bitcoin-lisp.storage:add-utxo utxo funding 0 100000000 (%p2sh-optrue-spk) 1)
    (let* ((tx (%pr-tx (list (cons funding 0)) (- 100000000 10000)))
           (txid (bitcoin-lisp.serialization:transaction-hash tx)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload tx) utxo mempool state nil :recent-rejects rejects)
          (is (= 1 calls) "first arrival must reach validation" calls)
          (is-false (bitcoin-lisp.mempool:mempool-has mempool txid))
          (is-true (bitcoin-lisp.validation:reconsiderable-reject-p txid))
          (is-false (bitcoin-lisp:recent-reject-p rejects txid))
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload tx) utxo mempool state nil :recent-rejects rejects)
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
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((rival (%pkg-tx funding 0 (- 100000000 50000)))     ; fee 50000
           (parent (%pkg-tx funding 0 (- 100000000 5)))        ; fee 5
           (child (%pkg-tx (bitcoin-lisp.serialization:transaction-hash parent)
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
        (bitcoin-lisp.validation:validate-package-for-mempool
         (list parent child) utxo mempool state)
      (is (eq :insufficient-fee msg))
      (let ((pres (%result-for results parent))
            (cres (%result-for results child)))
        (is (not (null pres)))
        (is (not (null cres)))
        (when (and pres cres)
          (is (eq :invalid (bitcoin-lisp.validation:package-tx-result-status pres)))
          (is (eq :insufficient-fee
                  (bitcoin-lisp.validation:package-tx-result-error pres)))
          (is (eq :invalid (bitcoin-lisp.validation:package-tx-result-status cres)))
          (is (eq :missing-input
                  (bitcoin-lisp.validation:package-tx-result-error cres))
              "the child must still carry its nonfinal missing-input result"))))
    ;; Nothing was admitted and RIVAL is untouched.
    (is (= 1 (bitcoin-lisp.mempool:mempool-count mempool)))))

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
    (let* ((rid (bitcoin-lisp.serialization:transaction-hash rival))
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (pwtxid (bitcoin-lisp.serialization:transaction-wtxid parent))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           (cwtxid (bitcoin-lisp.serialization:transaction-wtxid child))
           (pool (bitcoin-lisp.mempool:mempool-orphan-pool mempool))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          ;; RIVAL wins the outpoint honestly.
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload rival) utxo mempool state nil :recent-rejects rejects)
          (is-true (bitcoin-lisp.mempool:mempool-has mempool rid))
          ;; The sub-floor double-spending PARENT: reconsiderable, not main.
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
          (is-true (bitcoin-lisp.validation:reconsiderable-reject-p pwtxid))
          ;; The CHILD: held as an orphan (one reconsiderable parent is fine).
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload child) utxo mempool state nil :recent-rejects rejects)
          (is-true (%pr-orphan-p mempool child))
          ;; The parent again — this forms the package, and it FAILS.
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
          ;; The package path really ran and really failed as a package.
          (is-true (bitcoin-lisp.validation:reconsiderable-reject-p
                    (bitcoin-lisp.validation:package-hash (list parent child)))
                   "the failed combination must be remembered by package hash")
          (is-false (bitcoin-lisp.mempool:mempool-has mempool pid))
          (is-false (bitcoin-lisp.mempool:mempool-has mempool cid))
          (is-true (bitcoin-lisp.mempool:mempool-has mempool rid))
          ;; THE BLOCKER: the child is cached NOWHERE, under either id.
          (is-false (bitcoin-lisp:recent-reject-p rejects cwtxid)
                    "child wtxid must not enter the MAIN rejects filter")
          (is-false (bitcoin-lisp:recent-reject-p rejects cid)
                    "child txid must not enter the MAIN rejects filter")
          (is-false (bitcoin-lisp.validation:reconsiderable-reject-p cwtxid))
          ;; ...and it is not erased from the orphanage either
          ;; (txdownloadman_impl.cpp:490-492 excludes TX_MISSING_INPUTS).
          (is-true (%pr-orphan-p mempool child))
          ;; CONTROL (b): the parent's own fee failure is still reconsiderable.
          (is-true (bitcoin-lisp.validation:reconsiderable-reject-p pwtxid))
          (is-false (bitcoin-lisp:recent-reject-p rejects pwtxid))
          ;; The child is still RETRYABLE. Simulate the orphanage eviction
          ;; LimitOrphans performs under load: the announcement must still be
          ;; worth requesting (Core AlreadyHaveTx, the gate handle-inv uses)...
          (bitcoin-lisp.mempool:orphan-remove pool cwtxid)
          (is-false (bitcoin-lisp.networking::%already-have-tx-p
                     cwtxid t mempool rejects t)
                    "an inv for the child must still be requestable")
          ;; ...and the re-sent child must reach validation instead of being
          ;; dropped at handle-tx's precheck, and be held as an orphan again.
          (let ((before calls))
            (bitcoin-lisp.networking::handle-tx
             peer (%pr-payload child) utxo mempool state nil
             :recent-rejects rejects)
            (is (= (1+ before) calls)
                "re-sent child must reach validation, not the reject precheck"
                before calls))
          (is-true (%pr-orphan-p mempool child))
          ;; And once the blocking condition clears — the next block confirms
          ;; RIVAL and wipes both reject filters (Core ActiveTipChange) — the
          ;; honest CPFP pair is accepted after all.
          (bitcoin-lisp.mempool:mempool-remove mempool rid)
          (bitcoin-lisp:clear-recent-rejects rejects)
          (bitcoin-lisp.validation:clear-reconsiderable-rejects)
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
          (is-true (bitcoin-lisp.mempool:mempool-has mempool pid))
          (is-true (bitcoin-lisp.mempool:mempool-has mempool cid)))))))

(defun %pr-badscript-child (parent-txid out-value)
  "A child of PARENT-TXID whose scriptSig pushes the WRONG redeemScript, so
the P2SH OP_EQUAL fails. Push-only and standard, so it is rejected only once
the parent's output is actually available — i.e. individually it is a plain
:missing-input orphan, and the hard failure surfaces inside the package."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash parent-txid :index 0)
                    :script-sig (make-array 2 :element-type '(unsigned-byte 8)
                                              :initial-contents '(#x01 #x00))
                    :sequence #xffffffff))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value out-value
                     :script-pubkey (%p2sh-optrue-spk)))
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
  (multiple-value-bind (utxo mempool state funding) (%pkg-fixture)
    (let* ((parent (%pkg-tx funding 0 (- 100000000 5)))        ; fee 5
           (pid (bitcoin-lisp.serialization:transaction-hash parent))
           (pwtxid (bitcoin-lisp.serialization:transaction-wtxid parent))
           (child (%pr-badscript-child pid (- 100000000 5 10000)))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           (cwtxid (bitcoin-lisp.serialization:transaction-wtxid child))
           (peer (%pr-peer)))
      (%with-fresh-rejects (rejects)
        (%counting-tx-validations (calls)
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
          (is-true (bitcoin-lisp.validation:reconsiderable-reject-p pwtxid))
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload child) utxo mempool state nil :recent-rejects rejects)
          (is-true (%pr-orphan-p mempool child)
                   "the bad child must be an orphan first, or the package
never forms and this control asserts nothing")
          ;; Form the package; the child fails hard inside it.
          (bitcoin-lisp.networking::handle-tx
           peer (%pr-payload parent) utxo mempool state nil :recent-rejects rejects)
          (is (zerop (bitcoin-lisp.mempool:mempool-count mempool)))
          (is-true (bitcoin-lisp:recent-reject-p rejects cwtxid)
                   "a hard package failure must still be cached")
          (is-false (bitcoin-lisp.validation:reconsiderable-reject-p cwtxid))
          (is-false (%pr-orphan-p mempool child)
                    "a hard failure must leave the orphanage")
          ;; CONTROL (b): the parent is still only reconsiderable.
          (is-true (bitcoin-lisp.validation:reconsiderable-reject-p pwtxid))
          (is-false (bitcoin-lisp:recent-reject-p rejects pwtxid))
          ;; Re-announced: dropped at the precheck, never re-validated.
          (let ((before calls))
            (bitcoin-lisp.networking::handle-tx
             peer (%pr-payload child) utxo mempool state nil
             :recent-rejects rejects)
            (is (= before calls)
                "a cached hard failure must not be re-validated" before calls))
          (is-false (%pr-orphan-p mempool child))
          (is-false (bitcoin-lisp.mempool:mempool-has mempool cid)))))))

;;;; Filter plumbing

(test package-hash-is-order-independent
  "Core GetPackageHash sorts the wtxids before hashing (policy/packages.cpp:
151-170), so the identity of a package is the COMBINATION, not the order —
which is what lets a failed 1p1c pairing be remembered once."
  (multiple-value-bind (u m c funding) (%pkg-fixture)
    (declare (ignore u m c))
    (let* ((a (%pkg-tx funding 0 99990000))
           (b (%pkg-tx (bitcoin-lisp.serialization:transaction-hash a) 0 99980000))
           (h1 (bitcoin-lisp.validation:package-hash (list a b)))
           (h2 (bitcoin-lisp.validation:package-hash (list b a))))
      (is (= 32 (length h1)))
      (is (equalp h1 h2))
      (is-false (equalp h1 (bitcoin-lisp.validation:package-hash (list a)))))))

(test reconsiderable-filter-cleared-on-tip-change
  "Core resets BOTH reject filters on every active tip change
(ActiveTipChange, txdownloadman_impl.cpp:91-95): a new block moves the fee
floor and changes which parents exist, so every cached fee failure is stale."
  (let ((bitcoin-lisp.validation:*recent-rejects-reconsiderable*
          (bitcoin-lisp:make-rejects-filter 100))
        (h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 77)))
    (bitcoin-lisp.validation:add-reconsiderable-reject h)
    (is-true (bitcoin-lisp.validation:reconsiderable-reject-p h))
    (bitcoin-lisp.validation:clear-reconsiderable-rejects)
    (is-false (bitcoin-lisp.validation:reconsiderable-reject-p h))))

(test inv-for-reconsiderable-tx-is-not-requested
  "AlreadyHaveTx(include_reconsiderable=true) at announcement time: there is
no point downloading a transaction we would only submit alone again (Core
AddTxAnnouncement, txdownloadman_impl.cpp:199). The control is the same inv
with the filter empty, which IS requested."
  (let* ((bitcoin-lisp.networking::*cached-is-ibd* t)
         (bitcoin-lisp:*network* :regtest)
         (bitcoin-lisp:*minimum-chain-work-override* nil)
         (now (bitcoin-lisp.serialization:get-unix-time))
         (state (%make-ibd-latch-state now))
         (mempool (bitcoin-lisp.mempool:make-mempool))
         (announcer (bitcoin-lisp.networking:make-peer :state :ready
                                                       :wtxid-relay t))
         (probe (bitcoin-lisp.networking:make-peer :state :ready))
         (blocked (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 51))
         (fresh (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 52))
         (inv-payload
           (lambda (hash)
             (subseq (bitcoin-lisp.serialization:make-inv-message
                      (list (bitcoin-lisp.serialization:make-inv-vector
                             :type bitcoin-lisp.serialization:+inv-type-wtx+
                             :hash hash)))
                     24))))
    (%with-fresh-rejects (rejects)
      (bitcoin-lisp.validation:add-reconsiderable-reject blocked)
      (ignore-errors
       (bitcoin-lisp.networking::handle-inv
        announcer (funcall inv-payload blocked) state mempool
        :recent-rejects rejects))
      ;; Nothing recorded: a probe from another peer still wants it.
      (is-true (bitcoin-lisp.networking::tx-request-wanted-p blocked probe t))
      (bitcoin-lisp.networking:reset-tx-requests)
      ;; Control: an unknown wtxid from the same announcer IS requested.
      (ignore-errors
       (bitcoin-lisp.networking::handle-inv
        announcer (funcall inv-payload fresh) state mempool
        :recent-rejects rejects))
      (is-false (bitcoin-lisp.networking::tx-request-wanted-p fresh probe t)))))
