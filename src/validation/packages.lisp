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
;;; (check-package-rbf-rules, src/mempool/mempool.lisp). Core's
;;; PackageTRUCChecks (in-package TRUC topology) remains out of scope; the
;;; per-tx single-truc-checks still run, with sibling eviction disabled in
;;; the multi-tx path exactly as Core disables it there (PackageChildWith-
;;; Parents args, validation.cpp:516-527).

;;;; Constants (Bitcoin Core policy/packages.h)

(defconstant +max-package-count+ 25
  "Maximum number of transactions in a package (Core MAX_PACKAGE_COUNT).")

(defconstant +max-package-weight+ 404000
  "Maximum total weight of a package (Core MAX_PACKAGE_WEIGHT).")

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
appears later), and no two txs spend the same prevout."
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
             (incf total-weight (bitcoin-lisp.serialization:transaction-weight tx)))
           (when (> total-weight +max-package-weight+)
             (return-from package-well-formed (values nil :package-too-large)))))
       ;; No duplicate txids.
       (let ((seen (make-hash-table :test 'equalp)))
         (dolist (tx package)
           (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
             (when (gethash txid seen)
               (return-from package-well-formed (values nil :package-contains-duplicates)))
             (setf (gethash txid seen) t))))
       ;; Topologically sorted: walking front-to-back, a tx may not spend an
       ;; output of a tx whose txid has not yet been seen (i.e. appears later).
       (let ((later (make-hash-table :test 'equalp)))
         (dolist (tx package)
           (setf (gethash (bitcoin-lisp.serialization:transaction-hash tx) later) t))
         (dolist (tx package)
           (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
             (when (gethash (bitcoin-lisp.serialization:outpoint-hash
                             (bitcoin-lisp.serialization:tx-in-previous-output in))
                            later)
               (return-from package-well-formed (values nil :package-not-sorted))))
           (remhash (bitcoin-lisp.serialization:transaction-hash tx) later)))
       ;; No two txs spend the same prevout.
       (let ((spent (make-hash-table :test 'equalp)))
         (dolist (tx package)
           (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
             (let* ((p (bitcoin-lisp.serialization:tx-in-previous-output in))
                    (key (cons (bitcoin-lisp.serialization:outpoint-hash p)
                               (bitcoin-lisp.serialization:outpoint-index p))))
               (when (gethash key spent)
                 (return-from package-well-formed (values nil :conflict-in-package)))
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
    (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs child))
      (setf (gethash (bitcoin-lisp.serialization:outpoint-hash
                      (bitcoin-lisp.serialization:tx-in-previous-output in))
                     child-spends)
            t))
    ;; Every parent must be spent by the child.
    (dolist (tx parents)
      (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
        (setf (gethash txid parent-txids) t)
        (unless (gethash txid child-spends)
          (return-from package-child-with-parents-tree-p
            (values nil :package-not-child-with-parents)))))
    ;; No parent may depend on another parent.
    (dolist (tx parents)
      (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
        (when (gethash (bitcoin-lisp.serialization:outpoint-hash
                        (bitcoin-lisp.serialization:tx-in-previous-output in))
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
  (let ((coins (make-hash-table :test 'equalp)))
    (dolist (tx package coins)
      (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
        (loop for out across (bitcoin-lisp.serialization:transaction-outputs tx)
              for idx from 0
              do (setf (gethash (cons txid idx) coins)
                       (bitcoin-lisp.storage:make-utxo-entry
                        :value (bitcoin-lisp.serialization:tx-out-value out)
                        :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey out)
                        :height height
                        :coinbase nil)))))))

(defun %mark-result-valid (res vsize fee feerate includes)
  "Record a successful acceptance on RES at the given effective FEERATE (sat/vB)."
  (setf (package-tx-result-status res) :valid
        (package-tx-result-vsize res) vsize
        (package-tx-result-fee res) fee
        (package-tx-result-effective-feerate res) feerate
        (package-tx-result-effective-includes res) includes))

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
  (values (bitcoin-lisp.mempool:accept-validated-tx
           mempool txid tx fee height :entry-time now :sigops sigops
           :replaced rset :defer-trim t)))

(defun %results-not-validated (package reason)
  "A not-validated result for every tx in PACKAGE — used when a context-free
package check fails before any tx is processed."
  (mapcar (lambda (tx)
            (make-package-tx-result
             :txid (bitcoin-lisp.serialization:transaction-hash tx)
             :wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)
             :status :not-validated
             :error reason))
          package))

(defstruct (%pkg-val (:constructor %make-pkg-val
                         (tx txid wtxid fee vsize sigops rset modified-fee)))
  "Validation record for one member of a package subset — the Lisp analogue
of the per-tx Workspace fields Core's package layer reads back (m_ptx,
m_base_fees, m_vsize, m_sigops_cost, m_modified_fees, the replaced set)."
  tx txid wtxid fee vsize sigops rset modified-fee)

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
    ((some (lambda (tx) (bitcoin-lisp.mempool:mempool-find-parents mempool tx))
           txns)
     (values :package-rbf-mempool-ancestors nil))
    (t
     (destructuring-bind (parent child) validated
       (multiple-value-bind (ok reason rset)
           (bitcoin-lisp.mempool:check-package-rbf-rules
            mempool (%pkg-val-modified-fee parent) (%pkg-val-vsize parent)
            (%pkg-val-modified-fee child) (%pkg-val-vsize child) conflicts)
         (if ok
             (values nil rset)
             (values reason nil)))))))

(defun %accept-package-subset (txns utxo-set mempool chain-state height
                               pkg-coins now results replaced)
  "Validate the deferred TXNS (topologically ordered) as a unit at the package
feerate and, if they clear the mempool's effective minimum, submit them all
parents-first. Updates the RESULTS table (wtxid -> package-tx-result) and the
REPLACED hash-set. Returns :success or a failure reason keyword.

A single-tx subset keeps single-transaction replacement semantics (per-tx
RBF economics + TRUC sibling eviction, Core SingleInPackageAccept args,
validation.cpp:530-541). A multi-tx subset defers all conflict handling to
package RBF (%PACKAGE-RBF-CHECKS), with sibling eviction disabled, exactly
as Core's AcceptMultipleTransactions does (validation.cpp:1513-1516)."
  (let* ((package-eval (> (length txns) 1))
         (total-fee 0)                  ; prioritisation-modified fees
         (total-vsize 0)
         (conflict-set (make-hash-table :test 'equalp))
         (validated '()))               ; %PKG-VAL records, package order
    ;; Validate each with the per-tx fee floor skipped and the package's own
    ;; outputs available, so a child can spend a still-unconfirmed parent.
    ;; Fee-based policy below runs on the returned MODIFIED fee, like Core's
    ;; m_total_modified_fees (validation.cpp:1496-1499). CHAIN-STATE keeps
    ;; the finality/BIP68 checks on: Core's PreChecks runs them for package
    ;; members like any other tx (validation.cpp:819,886-889), so a non-final
    ;; member fails the whole package instead of riding in on CPFP.
    (dolist (tx txns)
      (let ((wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)))
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
          (incf total-fee modified-fee)
          (incf total-vsize (bitcoin-lisp.serialization:transaction-vsize tx))
          (push (%make-pkg-val tx (bitcoin-lisp.serialization:transaction-hash tx)
                               wtxid (or fee 0)
                               (bitcoin-lisp.serialization:transaction-vsize tx)
                               sigops rset modified-fee)
                validated))))
    (setf validated (nreverse validated))
    (flet ((fail-all (reason)
             (dolist (v validated)
               (%mark-result-invalid (gethash (%pkg-val-wtxid v) results) reason))
             reason))
      ;; Package feerate must clear the mempool's effective minimum (sat/kvB):
      ;; fee*1000 vs rate*vsize, exact integer math (Core CheckFeeRate on the
      ;; package feerate, validation.cpp:1500-1510, BEFORE package RBF).
      (let ((pkg-feerate (if (zerop total-vsize) 0 (/ total-fee total-vsize)))
            (min-fee (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool))
            (includes (mapcar #'%pkg-val-wtxid validated))
            (pkg-replaced nil))
        (when (< (* total-fee 1000) (* min-fee (max total-vsize 1)))
          (return-from %accept-package-subset (fail-all :insufficient-fee)))
        ;; Package RBF: a multi-tx subset that conflicts with the mempool is
        ;; only acceptable as a Core package replacement
        ;; (validation.cpp:1513-1516).
        (when (and package-eval (plusp (hash-table-count conflict-set)))
          (multiple-value-bind (reason rset)
              (%package-rbf-checks txns validated mempool
                                   (loop for k being the hash-keys of conflict-set
                                         collect k))
            (when reason (return-from %accept-package-subset (fail-all reason)))
            (setf pkg-replaced rset)))
        ;; Evict the package-RBF replaced set once, up front — the analogue of
        ;; Core applying the changeset's removals with its additions.
        (when pkg-replaced
          (loop for k being the hash-keys of pkg-replaced
                do (setf (gethash k replaced) t)
                   (bitcoin-lisp.mempool:mempool-remove-recursive mempool k)))
        ;; Submit all, parents first.
        (dolist (v validated :success)
          (let ((add-result (%accept-into-mempool
                             (%pkg-val-tx v) (%pkg-val-txid v) (%pkg-val-fee v)
                             (%pkg-val-sigops v)
                             height now mempool (%pkg-val-rset v) replaced))
                (res (gethash (%pkg-val-wtxid v) results)))
            (if (eq add-result :ok)
                (%mark-result-valid res (%pkg-val-vsize v) (%pkg-val-fee v)
                                    pkg-feerate includes)
                (progn
                  (%mark-result-invalid res add-result)
                  (return-from %accept-package-subset add-result)))))))))

(defun validate-package-for-mempool (package utxo-set mempool chain-state)
  "Validate and submit a transaction PACKAGE (a topologically-sorted list of
transactions, the last being the child) to the mempool. Mirrors Bitcoin Core's
ProcessNewPackage -> AcceptPackage: context-free well-formedness + child-with-
parents-tree checks, then per-tx individual acceptance, then a package-feerate
evaluation of the txs that could not pay their own way (CPFP). Mutates MEMPOOL.

Returns (values msg results replaced):
  MSG       — :success, or a package-/tx-level failure reason keyword
  RESULTS   — a list of PACKAGE-TX-RESULT, one per package tx, in package order
  REPLACED  — list of txids (byte vectors) evicted by RBF during acceptance."
  (let ((height (bitcoin-lisp.storage:current-height chain-state)))
    ;; 0. Context-free package checks.
    (multiple-value-bind (ok reason) (package-well-formed package)
      (unless ok
        (return-from validate-package-for-mempool
          (values reason (%results-not-validated package reason) nil))))
    (when (> (length package) 1)
      (multiple-value-bind (ok reason) (package-child-with-parents-tree-p package)
        (unless ok
          (return-from validate-package-for-mempool
            (values reason (%results-not-validated package reason) nil)))))
    ;; 1. Per-tx individual acceptance. No package coins — each tx must stand on
    ;;    its own against confirmed UTXOs + the current mempool. Txs that fail
    ;;    only for low feerate or a missing (in-package) input are deferred to
    ;;    the package-feerate phase; any other failure aborts the rest.
    (let ((now (bitcoin-lisp.serialization:get-unix-time))
          (results (make-hash-table :test 'equalp))   ; wtxid -> package-tx-result
          (replaced (make-hash-table :test 'equalp))   ; txid -> t
          (deferred '())
          (quit-early nil)
          (fail-reason nil))
      (dolist (tx package)
        (let* ((txid (bitcoin-lisp.serialization:transaction-hash tx))
               (wtxid (bitcoin-lisp.serialization:transaction-wtxid tx))
               (res (make-package-tx-result :txid txid :wtxid wtxid)))
          (setf (gethash wtxid results) res)
          (cond
            (quit-early
             (setf (package-tx-result-status res) :not-validated
                   (package-tx-result-error res) :package-not-validated))
            ;; Already in the mempool by wtxid → MEMPOOL_ENTRY (no re-validation).
            ((gethash wtxid (bitcoin-lisp.mempool:mempool-by-wtxid mempool))
             (let ((e (bitcoin-lisp.mempool:mempool-get mempool txid)))
               (setf (package-tx-result-status res) :mempool-entry)
               (when e
                 (setf (package-tx-result-vsize res) (bitcoin-lisp.mempool:mempool-entry-vsize e)
                       (package-tx-result-fee res) (bitcoin-lisp.mempool:mempool-entry-fee e)))))
            ;; Same txid, different witness already present → DIFFERENT_WITNESS.
            ((bitcoin-lisp.mempool:mempool-has mempool txid)
             (let ((e (bitcoin-lisp.mempool:mempool-get mempool txid)))
               (setf (package-tx-result-status res) :different-witness
                     (package-tx-result-other-wtxid res)
                     (and e (bitcoin-lisp.mempool:mempool-entry-wtxid e)))))
            (t
             ;; CHAIN-STATE keeps the finality/BIP68 checks on (Core PreChecks
             ;; runs them for every package member, validation.cpp:819,886-889).
             (multiple-value-bind (valid err fee rset sigops)
                 (validate-transaction-for-mempool tx utxo-set mempool height
                                                   :chain-state chain-state)
               (cond
                 (valid
                  (let ((add-result (%accept-into-mempool tx txid fee sigops
                                                          height now
                                                          mempool rset replaced)))
                    (if (eq add-result :ok)
                        (let ((vsize (bitcoin-lisp.serialization:transaction-vsize tx)))
                          (%mark-result-valid res vsize fee
                                              (if (zerop vsize) 0 (/ fee vsize))
                                              (list wtxid)))
                        (progn
                          (setf quit-early t fail-reason add-result)
                          (%mark-result-invalid res add-result)))))
                 ;; Fee-related failures are TX_RECONSIDERABLE in Core —
                 ;; including a failed single-tx RBF diagram (rbf.cpp:136-138)
                 ;; — and missing inputs may be in-package parents; both defer
                 ;; to the package-feerate phase (AcceptPackage,
                 ;; validation.cpp:1695-1712).
                 ((member err '(:insufficient-fee :replacement-failed :missing-input))
                  (push tx deferred))
                 (t
                  (setf quit-early t fail-reason err)
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
            (setf fail-reason (or fail-reason msg)))))
      ;; Re-limit ONCE (Core AcceptPackage -> LimitMempoolSize,
      ;; validation.cpp:1728): every package submission above deferred its
      ;; per-add byte-cap trim. A member admitted here — or one already in
      ;; the pool — may be evicted by the trim; flip its result to
      ;; :mempool-full, as Core does by re-checking existence
      ;; (validation.cpp:1736-1760).
      (bitcoin-lisp.mempool:mempool-trim-to-size mempool)
      (loop for res being the hash-values of results
            when (and (member (package-tx-result-status res)
                              '(:valid :mempool-entry :different-witness))
                      (not (bitcoin-lisp.mempool:mempool-has
                            mempool (package-tx-result-txid res))))
              do (%mark-result-invalid res :mempool-full)
                 (setf fail-reason (or fail-reason :mempool-full)))
      (values (or fail-reason :success)
              (loop for tx in package
                    collect (gethash (bitcoin-lisp.serialization:transaction-wtxid tx) results))
              (loop for k being the hash-keys of replaced collect k)))))
