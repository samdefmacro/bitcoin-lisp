(in-package #:bitcoin-lisp.validation)

;;; Package relay / submitpackage
;;;
;;; Validates and submits a *package* of transactions — a topologically-sorted
;;; child-with-parents group — to the mempool as a unit, so a low-fee parent can
;;; ride in on a high-fee child (CPFP) before either is in the mempool. Mirrors
;;; Bitcoin Core's ProcessNewPackage -> AcceptPackage (validation.cpp) and the
;;; well-formedness/topology checks in policy/packages.cpp.
;;;
;;; Scope vs Bitcoin Core: individual-tx RBF inside a package flows through
;;; validate-transaction-for-mempool's replacement path (single-tx subsets,
;;; like Core's SingleInPackageAccept), and multi-tx subsets whose members
;;; conflict with mempool transactions go through Core's package RBF
;;; (PackageRBFChecks, validation.cpp:1034-1130): the subset must be exactly
;;; 1-parent-1-child with NO in-mempool ancestors (resulting cluster <= 2),
;;; pay the aggregate anti-DoS fees, strictly exceed the parent's feerate,
;;; and strictly improve the feerate diagram with BOTH transactions staged
;;; (check-package-rbf-rules, src/mempool/mempool.lisp). In-package TRUC
;;; topology is enforced by PACKAGE-TRUC-CHECKS (Core PackageTRUCChecks) on
;;; the multi-tx subset, on top of the per-tx single-truc-checks — which run
;;; with sibling eviction disabled in the multi-tx path exactly as Core
;;; disables it there (PackageChildWithParents args, validation.cpp:516-527).
;;;
;;; The multi-tx subset is ATOMIC, like Core's changeset staging: every check
;;; — per-member validation, TRUC topology, package feerate, package RBF, and
;;; the staged cluster-limit test (mempool-package-fits-cluster-limits-p) —
;;; is read-only, and the mempool is first mutated (evictions, then adds) only
;;; after all of them have passed, at which point the adds cannot fail. A
;;; failing package leaves the mempool untouched.

;;;; Constants (Bitcoin Core policy/packages.h)

(defconstant +max-package-count+ 25
  "Maximum number of transactions in a package (Core MAX_PACKAGE_COUNT).")

(defconstant +max-package-weight+ 404000
  "Maximum total weight of a package (Core MAX_PACKAGE_WEIGHT).")

;;;; Package identity

(defun %wtxid-lessp (a b)
  "Ascending uint256 order over two 32-byte hashes — Core compares them with
reverse iterators (policy/packages.cpp:158-161), i.e. from the LAST byte
backwards, since a uint256 is stored little-endian."
  (loop for i from 31 downto 0
        do (let ((x (aref a i)) (y (aref b i)))
             (cond ((< x y) (return t))
                   ((> x y) (return nil))))
        finally (return nil)))

(defun package-hash (package)
  "Core GetPackageHash (policy/packages.cpp:151-170): SHA256 over PACKAGE's
wtxids concatenated in ascending uint256 order. The identity of a package as
a COMBINATION — order-independent — so a combination already known to fail
can be remembered in the reconsiderable-rejects filter and skipped instead of
re-validated on every re-announcement (MempoolRejectedPackage /
Find1P1CPackage, txdownloadman_impl.cpp:302-320, 500-502)."
  (let* ((wtxids (sort (mapcar #'bl.ser:transaction-wtxid
                               package)
                       #'%wtxid-lessp))
         (buf (make-array (* 32 (length wtxids))
                          :element-type '(unsigned-byte 8))))
    (loop for w in wtxids
          for off from 0 by 32
          do (replace buf w :start1 off))
    (bl.crypto:sha256 buf)))

;;;; Per-transaction result of package validation

(defstruct package-tx-result
  "The outcome of one transaction within a submitted package, mirroring the
fields Bitcoin Core's submitpackage reports per wtxid."
  (txid nil)
  (wtxid nil)
  ;; :valid :mempool-entry :different-witness :invalid :not-validated
  (status :not-validated)
  (vsize nil)
  (fee nil)
  ;; sat/vB (rational): the package feerate at which a CPFP member was accepted.
  (effective-feerate nil)
  ;; wtxids (byte vectors) that shared the effective-feerate calculation.
  (effective-includes nil)
  ;; for :different-witness — the wtxid of the in-mempool version.
  (other-wtxid nil)
  ;; rejection reason keyword, for :invalid / :not-validated.
  (error nil))

;;;; Well-formedness and topology (Bitcoin Core policy/packages.cpp)

(defun package-well-formed (package)
  "Mirror Bitcoin Core IsWellFormedPackage. PACKAGE is a list of transactions.
Returns (values ok-p reason): count within bounds, total weight within bounds,
no duplicate txids, topologically sorted (no tx spends an output of a tx that
appears later), no member with an empty vin, and no two txs spend the same
prevout."
  (let ((n (length package)))
    (cond
      ((zerop n) (values nil :package-empty))
      ((> n +max-package-count+) (values nil :package-too-many-transactions))
      (t
       ;; Total weight — only meaningful for a multi-tx package (a single tx is
       ;; already bounded by the standard tx-weight limit).
       (when (> n 1)
         (let ((total-weight 0))
           (dolist (tx package)
             (incf total-weight (bl.ser:transaction-weight tx)))
           (when (> total-weight +max-package-weight+)
             (return-from package-well-formed (values nil :package-too-large)))))
       ;; No duplicate txids.
       (let ((seen (make-hash-table :test 'equalp)))
         (dolist (tx package)
           (let ((txid (bl.ser:transaction-hash tx)))
             (when (gethash txid seen)
               (return-from package-well-formed (values nil :package-contains-duplicates)))
             (setf (gethash txid seen) t))))
       ;; Topologically sorted: walking front-to-back, a tx may not spend an
       ;; output of a tx whose txid has not yet been seen (i.e. appears later).
       (let ((later (make-hash-table :test 'equalp)))
         (dolist (tx package)
           (setf (gethash (bl.ser:transaction-hash tx) later) t))
         (dolist (tx package)
           (bl.ser:dovector (in (bl.ser:transaction-inputs tx))
             (when (gethash (bl.ser:outpoint-hash
                             (bl.ser:tx-in-previous-output in))
                            later)
               (return-from package-well-formed (values nil :package-not-sorted))))
           (remhash (bl.ser:transaction-hash tx) later)))
       ;; No two txs spend the same prevout — Core IsConsistentPackage
       ;; (policy/packages.cpp:52-74). Two rules, both of them exact:
       ;;
       ;;  * An empty vin makes the package inconsistent (:56-62). The question
       ;;    this check asks is about inputs and there are none to ask it of,
       ;;    and two such transactions are not consistent with each other.
       ;;  * The prevouts of a transaction are added a TRANSACTION AT A TIME,
       ;;    once the whole transaction has been checked against what came
       ;;    before (:69-73). Adding them one input at a time would make a
       ;;    transaction that spends a single outpoint twice collide with
       ;;    ITSELF, and Core says why that is wrong: duplicate inputs are "a
       ;;    more severe, consensus error", to be reported per-transaction by
       ;;    CheckTransaction as bad-txns-inputs-duplicate rather than as a
       ;;    package-wide verdict with no per-member attribution.
       (let ((spent (make-hash-table :test 'equalp)))
         (dolist (tx package)
           (let ((keys (map 'list (lambda (in)
                                    (let ((p (bl.ser:tx-in-previous-output in)))
                                      (cons (bl.ser:outpoint-hash p)
                                            (bl.ser:outpoint-index p))))
                            (bl.ser:transaction-inputs tx))))
             (when (or (null keys)
                       (some (lambda (key) (gethash key spent)) keys))
               (return-from package-well-formed (values nil :conflict-in-package)))
             (dolist (key keys)
               (setf (gethash key spent) t)))))
       (values t nil)))))

(defun package-child-with-parents-tree-p (package)
  "Mirror Bitcoin Core IsChildWithParentsTree. The last tx is the child; every
other tx must be a parent of the child (the child spends one of its outputs),
and no parent may spend another parent's output (the parents form a tree, not a
DAG). Returns (values ok-p reason)."
  (let ((child (car (last package)))
        (parents (butlast package))
        (parent-txids (make-hash-table :test 'equalp))
        (child-spends (make-hash-table :test 'equalp)))
    ;; The txids the child spends from.
    (bl.ser:dovector (in (bl.ser:transaction-inputs child))
      (setf (gethash (bl.ser:outpoint-hash
                      (bl.ser:tx-in-previous-output in))
                     child-spends)
            t))
    ;; Every parent must be spent by the child.
    (dolist (tx parents)
      (let ((txid (bl.ser:transaction-hash tx)))
        (setf (gethash txid parent-txids) t)
        (unless (gethash txid child-spends)
          (return-from package-child-with-parents-tree-p
            (values nil :package-not-child-with-parents)))))
    ;; No parent may depend on another parent.
    (dolist (tx parents)
      (bl.ser:dovector (in (bl.ser:transaction-inputs tx))
        (when (gethash (bl.ser:outpoint-hash
                        (bl.ser:tx-in-previous-output in))
                       parent-txids)
          (return-from package-child-with-parents-tree-p
            (values nil :package-parent-depends-on-parent)))))
    (values t nil)))

;;;; Package acceptance

(defun %build-package-coins (package height)
  "A (txid . index) -> utxo-entry table covering every output of every tx in
PACKAGE, so a later package tx's input that spends an earlier sibling's output
resolves during the package-feerate phase (Core's CCoinsViewMemPool layered over
the package). Consulted only as a fallback, after the confirmed UTXO set and the
real mempool. HEIGHT is the height these unconfirmed outputs are assumed to
confirm at — the next block (tip+1) — which is what BIP68 evaluates against."
  (let ((coins (%make-package-coins)))
    (dolist (tx package coins)
      (%add-package-coins coins tx height))))

(defun %make-package-coins ()
  "An empty package coin table. EQUALP and not the octet-vector test because
the key is a (txid . index) CONS, not a hash."
  (make-hash-table :test 'equalp))

(defun %add-package-coins (coins tx height)
  "Add TX's outputs to the package coin table COINS at HEIGHT — Core
m_viewmempool.PackageAddTransaction, run after each member clears PreChecks so
that the members AFTER it can spend its outputs (validation.cpp:1473)."
  (let ((txid (bl.ser:transaction-hash tx)))
    (loop for out across (bl.ser:transaction-outputs tx)
          for idx from 0
          do (setf (gethash (cons txid idx) coins)
                   (bl.store:make-utxo-entry
                    :value (bl.ser:tx-out-value out)
                    :script-pubkey (bl.ser:tx-out-script-pubkey out)
                    :height height
                    :coinbase nil)))
    coins))

(defun %mark-result-valid (res vsize fee feerate includes)
  "Record a successful acceptance on RES at the given effective FEERATE
(sat/vB), clearing any nonfinal individual error a deferred member carried
before the package-feerate phase reconsidered it."
  (setf (package-tx-result-status res) :valid
        (package-tx-result-vsize res) vsize
        (package-tx-result-fee res) fee
        (package-tx-result-effective-feerate res) feerate
        (package-tx-result-effective-includes res) includes
        (package-tx-result-error res) nil))

(defun %mark-result-invalid (res reason)
  "Record a rejection on RES."
  (setf (package-tx-result-status res) :invalid
        (package-tx-result-error res) reason))

(defun %accept-into-mempool (tx txid fee sigops height now mempool rset replaced)
  "Record the RBF-replaced txs in RSET into the REPLACED hash-set, then run
the shared evict+add tail (recording the weighted SIGOPS cost on the entry).
Returns the mempool-add result keyword. The per-add byte-cap trim is
deferred (Core package_submission, validation.cpp:1393):
validate-package-for-mempool re-limits once at the end, like Core's
AcceptPackage (validation.cpp:1728)."
  (dolist (rt rset)
    (setf (gethash rt replaced) t))
  (values (bl.mp:accept-validated-tx
           mempool txid tx fee height :entry-time now :sigops sigops
           :replaced rset :defer-trim t
           ;; Core's m_package_submission: a package member is priced as part
           ;; of its package, not on its own, so it teaches the fee estimator
           ;; nothing (validation.cpp:1304-1307).
           :package-submission t)))

(defun %finalize-package-results (package results reason)
  "The per-tx result list for an aborted package: whatever RESULTS already
holds for the members processed so far, and a :not-validated placeholder
carrying REASON for the members Core never got to (its early return leaves
them absent from m_tx_results)."
  (mapcar (lambda (tx)
            (let ((wtxid (bl.ser:transaction-wtxid tx)))
              (or (gethash wtxid results)
                  (make-package-tx-result
                   :txid (bl.ser:transaction-hash tx)
                   :wtxid wtxid
                   :status :not-validated
                   :error reason))))
          package))

(defun %results-not-validated (package reason)
  "A not-validated result for every tx in PACKAGE — used when a context-free
package check fails before any tx is processed."
  (mapcar (lambda (tx)
            (make-package-tx-result
             :txid (bl.ser:transaction-hash tx)
             :wtxid (bl.ser:transaction-wtxid tx)
             :status :not-validated
             :error reason))
          package))

(defstruct (%pkg-val (:constructor %make-pkg-val
                         (tx txid wtxid fee vsize sigops rset modified-fee)))
  "Validation record for one member of a package subset — the Lisp analogue
of the per-tx Workspace fields Core's package layer reads back (m_ptx,
m_base_fees, m_vsize, m_sigops_cost, m_modified_fees, the replaced set)."
  tx txid wtxid fee vsize sigops rset modified-fee)

(defun %pkg-val-graph-weight (v)
  "V's size in the TXGRAPH's unit — its sigop-adjusted WEIGHT, Core's
GetSigOpsAdjustedWeight at StageAddition (txmempool.cpp:1017). Derived from
the transaction and the sigop count the record already holds rather than
stored beside the VSIZE, so the two units cannot disagree."
  (bl.mp:transaction-graph-weight (%pkg-val-tx v) (%pkg-val-sigops v)))

(defun %in-package-parents (txns tx)
  "The members of TXNS, in order, that are direct parents of TX — Core
FindInPackageParents (truc_policy.cpp:18-37). TXNS is topologically sorted,
so scanning stops at TX itself."
  (let ((possible (make-hash-table :test 'equalp)))
    (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
      (setf (gethash (bl.ser:outpoint-hash
                      (bl.ser:tx-in-previous-output input))
                     possible)
            t))
    (loop for ptx in txns
          until (eq ptx tx)
          when (gethash (bl.ser:transaction-hash ptx) possible)
            collect ptx)))

(defun package-truc-checks (mempool tx vsize txns)
  "BIP431 TRUC (v3) topology checks for TX evaluated as part of the package
TXNS — an exact port of Core PackageTRUCChecks (policy/truc_policy.cpp:
58-170), which Core runs for every member of a multi-tx subset after all
PreChecks (validation.cpp:1478-1483). VSIZE is TX's sigop-adjusted virtual
size. Returns NIL when acceptable, else the rejection keyword.

The per-tx SINGLE-TRUC-CHECKS only see in-mempool relatives; this adds the
IN-PACKAGE dimension: ancestor counting includes in-package parents, the
1000-vB child cap applies to a child of an in-package TRUC parent, v3<->v2
inheritance covers in-package parents, and the one-descendant rule rejects
a package sibling spending the same parent (with no sibling-eviction escape
— the sibling is in the same package, truc_policy.cpp:127-136)."
  (let* ((v3 (= (bl.ser:transaction-version tx)
                bl.mp:+truc-version+))
         (mempool-parents (bl.mp:mempool-find-parents mempool tx))
         (in-package-parents (%in-package-parents txns tx)))
    (if v3
        (progn
          ;; Single checks enforced this already; Core keeps it as an Assume
          ;; (truc_policy.cpp:71-75) — keep it as a real check.
          (when (> vsize bl.mp:+truc-max-vsize+)
            (return-from package-truc-checks :truc-tx-too-big))
          ;; Ancestor limit over BOTH parent sets (+ self).
          (when (> (+ (length mempool-parents) (length in-package-parents) 1)
                   bl.mp:+truc-ancestor-limit+)
            (return-from package-truc-checks :truc-too-many-ancestors))
          ;; A mempool parent must not have ancestors of its own
          ;; (GetAncestorCount includes self, truc_policy.cpp:82-86).
          (when mempool-parents
            (when (> (+ (bl.mp:mempool-ancestor-stats
                         mempool (first mempool-parents))
                        (length in-package-parents) 1)
                     bl.mp:+truc-ancestor-limit+)
              (return-from package-truc-checks :truc-too-many-ancestors)))
          (when (or mempool-parents in-package-parents)
            ;; A TRUC child cannot be too large.
            (when (> vsize bl.mp:+truc-child-max-vsize+)
              (return-from package-truc-checks :truc-child-too-big))
            ;; Exactly 1 parent exists at this point, in mempool or package.
            (multiple-value-bind (parent-txid parent-version parent-has-descendant)
                (if mempool-parents
                    (let* ((ptxid (first mempool-parents))
                           (pe (bl.mp:mempool-get mempool ptxid)))
                      (values ptxid
                              (bl.ser:transaction-version
                               (bl.mp:mempool-entry-transaction pe))
                              ;; GetDescendantCount(parent) > 1 (incl. self).
                              (> (bl.mp:mempool-descendant-stats
                                  mempool ptxid)
                                 1)))
                    (let ((ptx (first in-package-parents)))
                      (values (bl.ser:transaction-hash ptx)
                              (bl.ser:transaction-version ptx)
                              nil)))
              ;; The parent must be TRUC too.
              (unless (= parent-version bl.mp:+truc-version+)
                (return-from package-truc-checks :truc-v3-spends-nonv3))
              ;; No other package tx may spend the same parent (an in-package
              ;; sibling — never evictable), and TX cannot have both a parent
              ;; and an in-package child (truc_policy.cpp:122-143).
              (let ((txid (bl.ser:transaction-hash tx)))
                (dolist (ptx txns)
                  (unless (eq ptx tx)
                    (bl.ser:dovector
                        (input (bl.ser:transaction-inputs ptx))
                      (let ((prev (bl.ser:outpoint-hash
                                   (bl.ser:tx-in-previous-output input))))
                        (when (equalp prev parent-txid)
                          (return-from package-truc-checks :truc-descendant-limit))
                        (when (equalp prev txid)
                          (return-from package-truc-checks :truc-too-many-ancestors)))))))
              ;; A mempool parent that already has a descendant is at its
              ;; limit (truc_policy.cpp:145-148).
              (when parent-has-descendant
                (return-from package-truc-checks :truc-descendant-limit))))
          nil)
        ;; Non-TRUC transactions cannot have TRUC parents, in mempool or in
        ;; the package (truc_policy.cpp:150-168).
        (progn
          (dolist (ptxid mempool-parents)
            (let ((pe (bl.mp:mempool-get mempool ptxid)))
              (when (and pe
                         (= (bl.ser:transaction-version
                             (bl.mp:mempool-entry-transaction pe))
                            bl.mp:+truc-version+))
                (return-from package-truc-checks :truc-nonv3-spends-v3))))
          (dolist (ptx in-package-parents)
            (when (= (bl.ser:transaction-version ptx)
                     bl.mp:+truc-version+)
              (return-from package-truc-checks :truc-nonv3-spends-v3)))
          nil))))

(defun %package-rbf-checks (txns validated mempool conflicts)
  "Core PackageRBFChecks (validation.cpp:1034-1130) for a multi-tx subset
whose members CONFLICT with mempool transactions. TXNS/VALIDATED are the
subset and its %PKG-VAL records; CONFLICTS the aggregated direct-conflict
txids. Returns (values reason-or-NIL replaced-set): NIL reason = checks
passed and REPLACED-SET (a txid hash-set) is what the package evicts."
  (cond
    ;; The replacement proposal must be exactly 1-parent-1-child
    ;; (validation.cpp:1047-1050).
    ((not (and (= 2 (length txns))
               (package-child-with-parents-tree-p txns)))
     (values :package-rbf-not-1p1c nil))
    ;; Neither transaction may have in-mempool ancestors, keeping the
    ;; resulting cluster <= 2 (validation.cpp:1052-1064).
    ((some (lambda (tx) (bl.mp:mempool-find-parents mempool tx))
           txns)
     (values :package-rbf-mempool-ancestors nil))
    (t
     (destructuring-bind (parent child) validated
       (multiple-value-bind (ok reason rset)
           (bl.mp:check-package-rbf-rules
            mempool
            (%pkg-val-modified-fee parent) (%pkg-val-vsize parent)
            (%pkg-val-graph-weight parent)
            (%pkg-val-modified-fee child) (%pkg-val-vsize child)
            (%pkg-val-graph-weight child)
            conflicts)
         (if ok
             (values nil rset)
             (values reason nil)))))))

(defun %accept-package-subset (txns utxo-set mempool chain-state height
                               pkg-coins now results replaced)
  "Validate the deferred TXNS (topologically ordered) as a unit at the package
feerate and, once EVERY check has passed, submit them all parents-first.
Updates the RESULTS table (wtxid -> package-tx-result) and the REPLACED
hash-set. Returns :success or a failure reason keyword.

ATOMIC, like Core's changeset staging (FinalizeSubpackage applies removals
and additions together only after all checks, validation.cpp:1188-1237,
1555): per-member validation, in-package TRUC topology, the package-feerate
check, package RBF, and the staged cluster-limit test are all READ-ONLY; the
mempool is first mutated — evictions, then adds — after the last of them,
at which point the adds cannot fail. A failing package leaves the mempool
untouched.

Result reporting mirrors Core AcceptMultipleTransactions: a per-member
validation failure overwrites only THAT member's result (the rest keep
their phase-1 individual results — Core returns them \"unfinished\",
validation.cpp:1445-1451); the package-feerate failure overwrites only the
CHILD's, carrying the package feerate (Core FeeFailure on
workspaces.back(), validation.cpp:1504-1509); package-LEVEL failures (TRUC
topology, package RBF, cluster limits) overwrite none
(validation.cpp:1479-1520 return empty/unchanged results); success
overwrites all with the package feerate.

A single-tx subset keeps single-transaction semantics (fee floor on its own
feerate via the aggregate check below, per-tx RBF economics + TRUC sibling
eviction, Core SingleInPackageAccept args, validation.cpp:530-543; no
package TRUC pass, no staged-limits precheck — its lone MEMPOOL-ADD is
atomic by itself and may legitimately return :too-large-cluster). A
multi-tx subset defers all conflict handling to package RBF
(%PACKAGE-RBF-CHECKS), with sibling eviction disabled, exactly as Core's
AcceptMultipleTransactions does (validation.cpp:1511-1516)."
  (let* ((package-eval (> (length txns) 1))
         (total-fee 0)                  ; prioritisation-modified fees
         (total-vsize 0)
         (conflict-set (make-hash-table :test 'equalp))
         (validated '()))               ; %PKG-VAL records, package order
    ;; 1. Validate each member (read-only) with the per-tx fee floor skipped
    ;; and the package's own outputs available, so a child can spend a
    ;; still-unconfirmed parent. Fee-based policy below runs on the returned
    ;; MODIFIED fee, like Core's m_total_modified_fees
    ;; (validation.cpp:1496-1499). CHAIN-STATE keeps the finality/BIP68
    ;; checks on: Core's PreChecks runs them for package members like any
    ;; other tx (validation.cpp:819,886-889), so a non-final member fails
    ;; the whole package instead of riding in on CPFP.
    (dolist (tx txns)
      (let ((wtxid (bl.ser:transaction-wtxid tx)))
        (multiple-value-bind (valid err fee rset sigops modified-fee conflicts)
            (validate-transaction-for-mempool tx utxo-set mempool height
                                              :package-coins pkg-coins
                                              :chain-state chain-state
                                              :skip-fee-check t
                                              :skip-rbf-check package-eval)
          (unless valid
            (%mark-result-invalid (gethash wtxid results) err)
            (return-from %accept-package-subset err))
          (when package-eval
            (dolist (c conflicts) (setf (gethash c conflict-set) t)))
          ;; Package feerate and per-tx records use the sigop-adjusted vsize,
          ;; like Core's ws.m_vsize totals (validation.cpp:1494-1496).
          (let ((vsize (bl.mp:sigop-adjusted-vsize
                        (bl.ser:transaction-weight tx) sigops)))
            (incf total-fee modified-fee)
            (incf total-vsize vsize)
            (push (%make-pkg-val tx (bl.ser:transaction-hash tx)
                                 wtxid (or fee 0) vsize sigops rset modified-fee)
                  validated)))))
    (setf validated (nreverse validated))
    ;; 2. In-package TRUC topology, for every member, now that all vsizes and
    ;; parents are known (Core PackageTRUCChecks after all PreChecks,
    ;; validation.cpp:1476-1483). Package-level failure: no member results.
    (when package-eval
      (dolist (v validated)
        (let ((reason (package-truc-checks mempool (%pkg-val-tx v)
                                           (%pkg-val-vsize v) txns)))
          (when reason
            (return-from %accept-package-subset reason)))))
    ;; 3. Package feerate must clear the mempool's effective minimum
    ;; (sat/kvB): fee*1000 vs rate*vsize, exact integer math (Core
    ;; CheckFeeRate on the package feerate, validation.cpp:1500-1510, BEFORE
    ;; package RBF). Failure lands on the CHILD alone, carrying the package
    ;; feerate (Core FeeFailure on workspaces.back()).
    (let ((pkg-feerate (if (zerop total-vsize) 0 (/ total-fee total-vsize)))
          (includes (mapcar #'%pkg-val-wtxid validated))
          (pkg-replaced nil))
      ;; Core CheckFeeRate over the package (validation.cpp:1610): the same
      ;; two reasons, dynamic floor first.
      (let ((reason (fee-floor-reason mempool total-fee (max total-vsize 1))))
        (when reason
          (let ((child-res (gethash (%pkg-val-wtxid (car (last validated))) results)))
            (%mark-result-invalid child-res reason)
            (setf (package-tx-result-effective-feerate child-res) pkg-feerate
                  (package-tx-result-effective-includes child-res) includes))
          (return-from %accept-package-subset reason)))
      ;; 4. Package RBF: a multi-tx subset that conflicts with the mempool is
      ;; only acceptable as a Core package replacement
      ;; (validation.cpp:1511-1516). Package-level failure: no member results.
      (when (and package-eval (plusp (hash-table-count conflict-set)))
        (multiple-value-bind (reason rset)
            (%package-rbf-checks txns validated mempool
                                 (loop for k being the hash-keys of conflict-set
                                       collect k))
          (when reason (return-from %accept-package-subset reason))
          (setf pkg-replaced rset)))
      ;; 5. Staged cluster-limit check (Core's changeset
      ;; CheckMemPoolPolicyLimits, validation.cpp:1516-1520): stage every
      ;; member + its dependencies in the txgraph, test, unstage. Passing
      ;; here guarantees the adds below cannot fail — the keystone of
      ;; atomicity. Exact even with PKG-REPLACED pending, because package-RBF
      ;; members have no in-mempool ancestors, so the evictions cannot touch
      ;; the members' would-be cluster.
      (when (and package-eval
                 (not (bl.mp:mempool-package-fits-cluster-limits-p
                       mempool
                       (mapcar (lambda (v) (list (%pkg-val-tx v)
                                                 (%pkg-val-modified-fee v)
                                                 (%pkg-val-graph-weight v)))
                               validated))))
        (return-from %accept-package-subset :too-large-cluster))
      ;; 6. Ephemeral-dust spend check over the whole subset (Core
      ;; CheckEphemeralSpends at validation.cpp:1526 — same position, after the
      ;; cluster-limit test and before the commit). The per-tx call in
      ;; validate-transaction-for-mempool only sees MEMPOOL parents; a dust
      ;; parent that is still in this package is only visible here. Read-only,
      ;; so it keeps the atomicity above.
      (when *require-standard*
        (multiple-value-bind (dust-ok dust-txid offender)
            (check-ephemeral-spends (mapcar #'%pkg-val-tx validated) mempool)
          (declare (ignore dust-txid))
          (unless dust-ok
            ;; The PACKAGE state is "unspent-dust" (validation.cpp:1527) and
            ;; the CHILD's own state carries Core's missing-ephemeral-spends
            ;; sentence (ephemeral_policy.cpp:88-89).
            (let ((child (gethash (bl.ser:transaction-wtxid
                                   (or offender (%pkg-val-tx (car (last validated)))))
                                  results)))
              (when child
                (%mark-result-invalid child (ephemeral-spends-verdict offender))))
            (return-from %accept-package-subset :unspent-dust))))
      ;; ---- Commit point: every check passed; mutate the mempool. ----
      ;; Evict the package-RBF replaced set once, up front — the analogue of
      ;; Core applying the changeset's removals with its additions.
      (when pkg-replaced
        (let ((bl.mp:*mempool-removal-reason* :replaced))
          (loop for k being the hash-keys of pkg-replaced
                do (setf (gethash k replaced) t)
                   (bl.mp:mempool-remove-recursive mempool k))))
      ;; Submit all, parents first. For a multi-tx subset a failure here is
      ;; unreachable (step 5); mirror Core's belt-and-suspenders (SubmitPackage,
      ;; validation.cpp:1255-1277): mark the member, keep submitting the rest.
      (let ((failure nil))
        (dolist (v validated)
          (let ((add-result (%accept-into-mempool
                             (%pkg-val-tx v) (%pkg-val-txid v) (%pkg-val-fee v)
                             (%pkg-val-sigops v)
                             height now mempool (%pkg-val-rset v) replaced))
                (res (gethash (%pkg-val-wtxid v) results)))
            (if (eq add-result :ok)
                (%mark-result-valid res (%pkg-val-vsize v) (%pkg-val-fee v)
                                    pkg-feerate includes)
                (progn
                  (when package-eval
                    (bl:log-warn
                     "package submit: staged cluster check passed but ~
                      mempool-add failed (~A) — should be unreachable"
                     add-result))
                  (%mark-result-invalid res add-result)
                  (setf failure (or failure add-result))))))
        (or failure :success)))))

(defparameter *package-level-reject-reasons*
  '(;; policy/packages.cpp IsWellFormedPackage
    :package-empty
    :package-too-many-transactions                ; packages.cpp:84
    :package-too-large                            ; :91
    :package-contains-duplicates                  ; :101
    :package-not-sorted                           ; :109
    :conflict-in-package                          ; :114
    ;; The topology gate (validation.cpp:1640) and our second half of it.
    :package-not-child-with-parents
    :package-parent-depends-on-parent
    ;; PackageTRUCChecks (validation.cpp:1480), one reason for all six.
    :truc-tx-too-big :truc-child-too-big :truc-too-many-ancestors
    :truc-descendant-limit :truc-nonv3-spends-v3 :truc-v3-spends-nonv3
    ;; PackageRBFChecks (validation.cpp:1049-1119).
    :package-rbf-not-1p1c :package-rbf-mempool-ancestors
    :package-rbf-insufficient-fee
    ;; The changeset's cluster limits (:1518) and the package dust sweep
    ;; (:1527), both judged over the whole subset.
    :too-large-cluster :unspent-dust)
  "The verdicts Core states about the PACKAGE rather than about one member.

Core keeps two states side by side: a TxValidationState per transaction and
one PackageValidationState for the package. A per-transaction failure sets
the package state to PCKG_TX \"transaction failed\" and nothing else -- the
member's own reason stays in its own result -- while the checks in this list
are the package's own verdict and keep their word (PCKG_POLICY, plus
unspent-dust at PCKG_TX). testmempoolaccept reports the PCKG_POLICY ones as
`package-error' and submitpackage reports every one of them as package_msg
(rpc/mempool.cpp:368-370, :1395-1400).")

(defun %package-level-reject-p (reason)
  "T when REASON is one of *PACKAGE-LEVEL-REJECT-REASONS*."
  (and (member (tx-reject-keyword reason) *package-level-reject-reasons*) t))

(defun %package-msg (reason)
  "Core's package_msg for REASON: the package state's own ToString().
A verdict about one member is `transaction failed' at package level, however
the member itself was rejected -- mempool_ephemeral_dust.py:160 submits a
dusty parent and reads package_msg \"transaction failed\" while the parent's
own result carries \"dust, tx with dust output must be 0-fee\"."
  (if (%package-level-reject-p reason)
      (tx-reject-reason-string reason)
      "transaction failed"))

(defun test-package-acceptance (package utxo-set mempool chain-state)
  "Core MemPoolAccept::AcceptMultipleTransactionsInternal under
ATMPArgs::PackageTestAccept (validation.cpp:1429-1553, args at :499-513) — the
READ-ONLY package path, and the one testmempoolaccept takes whenever it is
handed more than one transaction (rpc/mempool.cpp:343-346). The mempool is
never touched.

It is NOT the submitpackage path with the submission removed, and the
differences are the whole point of the RPC:

  * the package is validated as a package. One coin view covers the confirmed
    UTXO set, the mempool and the members already checked, so a child spending
    an in-package parent is answered on its merits instead of `missing-inputs';
  * the context-free package rules apply, and their verdict is about the
    PACKAGE — `package-not-sorted', `conflict-in-package',
    `package-contains-duplicates' — which the caller prints on every row;
  * m_allow_replacement is FALSE (:505), so a member conflicting with a
    mempool transaction is rejected as `bip125-replacement-disallowed' however
    good a replacement it would make on its own. testmempoolaccept answers for
    the package it was given, and that package is not a replacement
    (rpc_packages.py:320-326, mempool_package_rbf.py:110);
  * m_package_feerates is FALSE (:509), so every member pays its own fee floor
    and reports its OWN effective feerate — a package testres therefore equals
    the individual testres of its members (rpc_packages.py:100), which is
    exactly what submitpackage's CPFP evaluation would not give;
  * there is no child-with-parents gate: that one belongs to AcceptPackage
    (:1639), so a 25-long chain is a legal thing to ask about
    (rpc_packages.py:145-150).

Returns (values package-error results):

  PACKAGE-ERROR is a PCKG_POLICY verdict keyword, or NIL. Core prints that
  class — and only that class — as `package-error' on EVERY row
  (rpc/mempool.cpp:360-362); the PCKG_TX verdicts are statements about one
  member, so they travel in that member's own result instead.

  RESULTS is one PACKAGE-TX-RESULT per member in package order. A member Core
  never finished carries :not-validated and is rendered as txid and wtxid
  alone. WHICH pass failed decides how many of those there are: a PreChecks
  failure leaves every other member blank, while a script failure leaves the
  members before it complete (%PACKAGE-TEST-ROWS in src/rpc/mempool.lisp)."
  (let ((height (bl.store:current-height chain-state)))
    ;; 0. Context-free package checks (:1436). PCKG_POLICY, no member results.
    (multiple-value-bind (ok reason) (package-well-formed package)
      (unless ok
        (return-from test-package-acceptance
          (values reason (%results-not-validated package reason)))))
    (let ((results (bl.bytes:make-octets-hash-table))   ; wtxid -> result
          (pkg-coins (%make-package-coins))
          (validated '()))
      (dolist (tx package)
        (let ((wtxid (bl.ser:transaction-wtxid tx)))
          (setf (gethash wtxid results)
                (make-package-tx-result :txid (bl.ser:transaction-hash tx)
                                        :wtxid wtxid))))
      (flet ((result-for (tx) (gethash (bl.ser:transaction-wtxid tx) results))
             (ordered ()
               (loop for tx in package
                     collect (gethash (bl.ser:transaction-wtxid tx) results))))
        ;; 1. PreChecks for EVERY member first, so a package holding one member
        ;; we will reject never pays for the others' signature verification
        ;; (:1445-1450). The first failure ends the pass: that member gets its
        ;; verdict, the rest stay blank.
        (dolist (tx package)
          (multiple-value-bind (valid err fee rset sigops modified-fee)
              (validate-transaction-for-mempool tx utxo-set mempool height
                                                :package-coins pkg-coins
                                                :chain-state chain-state
                                                :allow-replacement nil
                                                :allow-sibling-eviction nil
                                                :defer-script-checks t)
            (declare (ignore rset))
            (unless valid
              (%mark-result-invalid (result-for tx) err)
              (return-from test-package-acceptance (values nil (ordered))))
            (push (%make-pkg-val tx (bl.ser:transaction-hash tx)
                                 (bl.ser:transaction-wtxid tx) (or fee 0)
                                 (bl.mp:sigop-adjusted-vsize
                                  (bl.ser:transaction-weight tx) sigops)
                                 sigops nil modified-fee)
                  validated)
            ;; This member's outputs are now spendable by the ones after it
            ;; (:1473). Unconfirmed, so they carry the next block's height for
            ;; BIP68, like MEMPOOL-EXTRA-COINS.
            (%add-package-coins pkg-coins tx (1+ height))))
        (setf validated (nreverse validated))
        ;; 2. In-package TRUC topology, now that every vsize and parent is
        ;; known (:1477-1483). PCKG_POLICY: no member results at all.
        (dolist (v validated)
          (let ((reason (package-truc-checks mempool (%pkg-val-tx v)
                                             (%pkg-val-vsize v) package)))
            (when reason
              (return-from test-package-acceptance (values reason (ordered))))))
        ;; 3. No package-feerate check and no package RBF here: m_package_feerates
        ;; is false, and with replacement disallowed above there can be no
        ;; conflicts left for PackageRBFChecks to judge (:1506, :1511).
        ;;
        ;; 4. Would the package fit the cluster limits (:1516-1520)? Staged and
        ;; unstaged, so the mempool is unchanged. PCKG_POLICY
        ;; (mempool_package_limits.py:28, mempool_sigoplimit.py:175).
        (unless (bl.mp:mempool-package-fits-cluster-limits-p
                 mempool
                 (mapcar (lambda (v) (list (%pkg-val-tx v)
                                           (%pkg-val-modified-fee v)
                                           (%pkg-val-graph-weight v)))
                         validated))
          (return-from test-package-acceptance
            (values :too-large-cluster (ordered))))
        ;; 5. Ephemeral dust over the whole package (:1524-1531). PCKG_TX, so
        ;; no package-error — only the child that stranded the dust answers.
        (when *require-standard*
          (multiple-value-bind (dust-ok dust-txid offender)
              (check-ephemeral-spends package mempool)
            (declare (ignore dust-txid))
            (unless dust-ok
              (let ((child (result-for (or offender (car (last package))))))
                (when child
                  (%mark-result-invalid child (ephemeral-spends-verdict offender))))
              (return-from test-package-acceptance (values nil (ordered))))))
        ;; 6. The script passes, member by member (:1533-1551). A member is
        ;; recorded as accepted only once it has passed them, which is why the
        ;; members before a script failure keep their full result and the ones
        ;; after it do not have one yet. The effective feerate is the member's
        ;; OWN modified feerate (m_package_feerates false, :1542-1545).
        (dolist (v validated)
          (multiple-value-bind (ok err)
              (mempool-script-checks (%pkg-val-tx v) utxo-set mempool height
                                     :package-coins pkg-coins)
            (unless ok
              (%mark-result-invalid (gethash (%pkg-val-wtxid v) results) err)
              (return-from test-package-acceptance (values nil (ordered)))))
          (let ((vsize (%pkg-val-vsize v)))
            (%mark-result-valid (gethash (%pkg-val-wtxid v) results)
                                vsize (%pkg-val-fee v)
                                (if (zerop vsize)
                                    0
                                    (/ (%pkg-val-modified-fee v) vsize))
                                (list (%pkg-val-wtxid v)))))
        (values nil (ordered))))))

(defun validate-package-for-mempool (package utxo-set mempool chain-state
                                    &key client-maxfeerate)
  "Validate and submit a transaction PACKAGE (a topologically-sorted list of
transactions, the last being the child) to the mempool. Mirrors Bitcoin Core's
ProcessNewPackage -> AcceptPackage: context-free well-formedness + child-with-
parents-tree checks, then per-tx individual acceptance, then a package-feerate
evaluation of the txs that could not pay their own way (CPFP). Mutates MEMPOOL.

A member failing individually for a NON-fee reason does not stop the others:
the remaining members are still validated individually and the valid ones
land in the mempool (Core AcceptPackage's quit_early only skips the
package-feerate retry, validation.cpp:1694-1712). Deferred members keep
their individual failure as the nonfinal result unless the package-feerate
phase decides otherwise. The package-feerate phase itself is ATOMIC: it
mutates the mempool only after every check has passed
(%ACCEPT-PACKAGE-SUBSET).

Returns (values msg results replaced):
CLIENT-MAXFEERATE is submitpackage's caller-supplied cap in satoshis per kvB
(Core AcceptPackage's m_client_maxfeerate). NIL disables it, which is what a
maxfeerate of 0 means. A member whose modified feerate exceeds it aborts the
WHOLE package immediately, leaving later members unvalidated
(validation.cpp:1365-1368,1453-1462) — members already accepted stay in the
mempool, exactly as in Core's early return.

  MSG       — :success, or a package-/tx-level failure reason keyword
  RESULTS   — a list of PACKAGE-TX-RESULT, one per package tx, in package order
  REPLACED  — list of txids (byte vectors) evicted by RBF during acceptance
  PACKAGE-MSG — Core's package_msg for MSG (see %PACKAGE-MSG), which
              submitpackage reports verbatim."
  (let ((height (bl.store:current-height chain-state)))
    ;; 0. Context-free package checks.
    (multiple-value-bind (ok reason) (package-well-formed package)
      (unless ok
        (return-from validate-package-for-mempool
          (values reason (%results-not-validated package reason) nil
                  (%package-msg reason)))))
    (when (> (length package) 1)
      (multiple-value-bind (ok reason) (package-child-with-parents-tree-p package)
        (unless ok
          (return-from validate-package-for-mempool
            (values reason (%results-not-validated package reason) nil
                    (%package-msg reason))))))
    ;; 1. Per-tx individual acceptance. No package coins — each tx must stand on
    ;;    its own against confirmed UTXOs + the current mempool. Txs that fail
    ;;    only for low feerate or a missing (in-package) input are deferred to
    ;;    the package-feerate phase; any other failure sets QUIT-EARLY — which
    ;;    skips only that phase, NOT the rest of this loop: Core keeps
    ;;    validating the remaining members individually, and individually-valid
    ;;    ones still enter the mempool (\"some of them may still be valid\",
    ;;    AcceptPackage, validation.cpp:1694-1712).
    (let ((now (bl.ser:get-unix-time))
          (results (make-hash-table :test 'equalp))   ; wtxid -> package-tx-result
          (replaced (make-hash-table :test 'equalp))   ; txid -> t
          (deferred '())
          (quit-early nil)
          (fail-reason nil)
          ;; Whether FAIL-REASON is a verdict on the PACKAGE (Core's
          ;; PCKG_POLICY word, or unspent-dust) rather than on one member.
          ;; Decided by the SITE that set it -- too-large-cluster is both a
          ;; per-transaction insertion verdict (validation.cpp:1021) and a
          ;; package one (:1518), so the keyword alone cannot say.
          (package-level-failure nil))
      (dolist (tx package)
        (let* ((txid (bl.ser:transaction-hash tx))
               (wtxid (bl.ser:transaction-wtxid tx))
               (res (make-package-tx-result :txid txid :wtxid wtxid)))
          (setf (gethash wtxid results) res)
          (cond
            ;; Already in the mempool by wtxid → MEMPOOL_ENTRY (no re-validation).
            ((gethash wtxid (bl.mp:mempool-by-wtxid mempool))
             (let ((e (bl.mp:mempool-get mempool txid)))
               (setf (package-tx-result-status res) :mempool-entry)
               (when e
                 (setf (package-tx-result-vsize res) (bl.mp:mempool-entry-vsize e)
                       (package-tx-result-fee res) (bl.mp:mempool-entry-fee e)))))
            ;; Same txid, different witness already present → DIFFERENT_WITNESS.
            ((bl.mp:mempool-has mempool txid)
             (let ((e (bl.mp:mempool-get mempool txid)))
               (setf (package-tx-result-status res) :different-witness
                     (package-tx-result-other-wtxid res)
                     (and e (bl.mp:mempool-entry-wtxid e)))))
            (t
             ;; CHAIN-STATE keeps the finality/BIP68 checks on (Core PreChecks
             ;; runs them for every package member, validation.cpp:819,886-889).
             (multiple-value-bind (valid err fee rset sigops modified-fee)
                 (validate-transaction-for-mempool tx utxo-set mempool height
                                                   :chain-state chain-state)
               ;; The caller's feerate cap is checked in PreChecks, i.e. BEFORE
               ;; submission, and aborts the whole package on the first breach
               ;; (validation.cpp:1365-1368). Compare exactly, by
               ;; cross-multiplication: modified-fee/vsize > rate/1000. Core
               ;; compares CFeeRate(m_modified_fees, m_vsize), so the
               ;; prioritised fee against the sigop-adjusted size.
               (when (and valid client-maxfeerate)
                 (let ((vsize (bl.mp:sigop-adjusted-vsize
                               (bl.ser:transaction-weight tx)
                               sigops)))
                   (when (> (* (or modified-fee fee) 1000)
                            (* client-maxfeerate vsize))
                     (%mark-result-invalid res :max-feerate-exceeded)
                     (return-from validate-package-for-mempool
                       (values :transaction-failed
                               (%finalize-package-results package results
                                                          :max-feerate-exceeded)
                               (loop for k being the hash-keys of replaced
                                     collect k)
                               "transaction failed")))))
               (cond
                 (valid
                  (let ((add-result (%accept-into-mempool tx txid fee sigops
                                                          height now
                                                          mempool rset replaced)))
                    (if (eq add-result :ok)
                        ;; Reported vsize/feerate use the sigop-adjusted size
                        ;; (Core MempoolAcceptResult carries ws.m_vsize).
                        (let ((vsize (bl.mp:sigop-adjusted-vsize
                                      (bl.ser:transaction-weight tx)
                                      sigops)))
                          (%mark-result-valid res vsize fee
                                              (if (zerop vsize) 0 (/ fee vsize))
                                              (list wtxid)))
                        (progn
                          (setf quit-early t
                                fail-reason (or fail-reason add-result))
                          (%mark-result-invalid res add-result)))))
                 ;; Fee-related failures are TX_RECONSIDERABLE in Core —
                 ;; including a failed single-tx RBF diagram (rbf.cpp:136-138)
                 ;; — and missing inputs may be in-package parents; both defer
                 ;; to the package-feerate phase (a single-tx package has no
                 ;; such phase to defer to, validation.cpp:1694). The
                 ;; individual failure is recorded now as the NONFINAL result
                 ;; (Core individual_results_nonfinal): it stands unless the
                 ;; package-feerate phase overwrites it.
                 ((and (> (length package) 1)
                       ;; A verdict carrying Core's debug message is the list
                       ;; (KEYWORD DETAIL); the class is the keyword's.
                       (member (if (consp err) (first err) err)
                               '(:insufficient-fee :mempool-min-fee-not-met
                                 :rbf-insufficient-fee
                                 :replacement-failed :missing-input)))
                  (%mark-result-invalid res err)
                  (push tx deferred))
                 (t
                  (setf quit-early t fail-reason (or fail-reason err))
                  (%mark-result-invalid res err))))))))
      ;; 2. Package-feerate evaluation of the deferred txs (CPFP). The package
      ;;    coin view is only needed here, so build it lazily.
      (setf deferred (nreverse deferred))
      (when (and (not quit-early) deferred)
        ;; Package-sibling coins are unconfirmed, so they carry the
        ;; next-block height for BIP68, like mempool-extra-coins (Core
        ;; MEMPOOL_HEIGHT -> tip+1, validation.cpp:185-192).
        (let ((msg (%accept-package-subset deferred utxo-set mempool chain-state
                                           height
                                           (%build-package-coins package (1+ height))
                                           now results replaced)))
          (unless (eq msg :success)
            (when (null fail-reason)
              (setf package-level-failure (%package-level-reject-p msg)))
            (setf fail-reason (or fail-reason msg)))))
      ;; Re-limit ONCE (Core AcceptPackage -> LimitMempoolSize,
      ;; validation.cpp:1728): every package submission above deferred its
      ;; per-add byte-cap trim. A member admitted here — or one already in
      ;; the pool — may be evicted by the trim; flip its result to
      ;; :mempool-full, as Core does by re-checking existence
      ;; (validation.cpp:1736-1760).
      (bl.mp:mempool-limit-size mempool)
      (loop for res being the hash-values of results
            when (and (member (package-tx-result-status res)
                              '(:valid :mempool-entry :different-witness))
                      (not (bl.mp:mempool-has
                            mempool (package-tx-result-txid res))))
              do (%mark-result-invalid res :mempool-full)
                 (setf fail-reason (or fail-reason :mempool-full)))
      (values (or fail-reason :success)
              (loop for tx in package
                    collect (gethash (bl.ser:transaction-wtxid tx) results))
              (loop for k being the hash-keys of replaced collect k)
              (if fail-reason
                  ;; The PACKAGE phase's own verdicts keep their word; every
                  ;; other failure here is a per-transaction one, which Core
                  ;; states at package level as "transaction failed".
                  (if package-level-failure (%package-msg fail-reason) "transaction failed")
                  "success")))))
