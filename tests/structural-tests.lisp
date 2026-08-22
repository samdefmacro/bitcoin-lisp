(in-package #:bitcoin-lisp.tests)

(def-suite :structural-tests :in :bitcoin-lisp-tests
  :description "Whole-tree structural invariants no single unit test can see.")
(in-suite :structural-tests)

;;;; ====================================================================
;;;; Exported functions with no production caller
;;;;
;;;; This project has shipped ten pieces of correct code that nothing called
;;;; -- the notfound disclaims, the CBlockUndo codec, the compact-block
;;;; emitter, build-tx-index, scan-for-op-success, connect-block's :tx-index
;;;; argument, and more. Every one was found by a live log line, a shipped
;;;; diagnostic or a manual sweep; NONE was found by the 30,000-check unit
;;;; suite, because a unit test calls the function itself and so proves only
;;;; that it works, never that anything uses it.
;;;;
;;;; This test closes that gap. It cannot tell a deliberate API entry point
;;;; from an accident, so it does not try: it pins the known set and fails on
;;;; ADDITIONS. It deliberately does not fail when an entry gains a caller --
;;;; that is the change we want, and a test that goes red on good news is one
;;;; whose baseline gets re-pasted wholesale rather than read, which is
;;;; exactly how an instrument like this stops detecting anything while still
;;;; reporting green. Resolved entries are printed instead; deleting their
;;;; lines is a one-commit chore.
;;;; ====================================================================

(defparameter *orphan-export-baseline*
  '(
    ;; Entry points reached from outside the image: the launcher
    ;; (scripts/run-node.sh) and an operator at the REPL.
    "bitcoin-lisp:clear-logs"
    "bitcoin-lisp:disable-console-logging"
    "bitcoin-lisp:node-status"
    "bitcoin-lisp:run-node-watchdog"
    "bitcoin-lisp:show-logs"
    "bitcoin-lisp:start-node-from-args"
    "bitcoin-lisp:stop-file-logging"

    ;; block-file-format P6: the Core CBlockUndo codec is written and tested
    ;; but still unwired -- see docs/next-wave-2026-08-22.md track A item 2.
    "bitcoin-lisp.storage:block-undo-from-spent-utxos"
    "bitcoin-lisp.storage:deserialize-block-undo"
    "bitcoin-lisp.storage:serialize-block-undo"
    "bitcoin-lisp.storage:spent-utxos-from-block-undo"
    "bitcoin-lisp.storage:undo-record-bytes"

    ;; Superseded, or written and never wired. Includes the legacy utxo-set
    ;; API that coins-view-cache replaced, REQUEST-HEADERS beside the live
    ;; REQUEST-HEADERS-FOR-IBD, and BAN-PEER, which nothing calls because
    ;; misbehaviour discourages and setban bans by address.
    "bitcoin-lisp.crypto:bip324-cipher-initialized-p"
    "bitcoin-lisp.crypto:ellswift-decode"
    "bitcoin-lisp.crypto:muhash-combine"
    "bitcoin-lisp.crypto:muhash-divide"
    "bitcoin-lisp.crypto:xonly-pubkey-valid-p"
    "bitcoin-lisp.mempool:ancestor-sort-linearization"
    "bitcoin-lisp.mempool:chunk-linearization"
    "bitcoin-lisp.mempool:depgraph-reduced-children"
    "bitcoin-lisp.mempool:feefrac-empty-p"
    "bitcoin-lisp.mempool:feefrac-evaluate-fee-down"
    "bitcoin-lisp.mempool:feefrac-evaluate-fee-up"
    "bitcoin-lisp.mempool:feefrac<"
    "bitcoin-lisp.mempool:feefrac<="
    "bitcoin-lisp.mempool:feefrac>="
    "bitcoin-lisp.mempool:mempool-ancestor-fee-rate"
    "bitcoin-lisp.mempool:mempool-descendant-fee-rate"
    "bitcoin-lisp.mempool:mempool-entry-fee-rate"
    "bitcoin-lisp.mempool:mempool-get-transactions"
    "bitcoin-lisp.mempool:orphan-announcements-from-peer"
    "bitcoin-lisp.mempool:orphan-announcers"
    "bitcoin-lisp.mempool:orphan-usage-by-peer"
    "bitcoin-lisp.mempool:topological-subset-p"
    "bitcoin-lisp.mempool:txgraph-compare-main-order"
    "bitcoin-lisp.mempool:txgraph-get-ancestors-union"
    "bitcoin-lisp.mempool:txgraph-get-descendants-union"
    "bitcoin-lisp.mempool:txgraph-get-individual-feerate"
    "bitcoin-lisp.networking:ban-peer"
    "bitcoin-lisp.networking:clear-discouraged"
    "bitcoin-lisp.networking:clear-pending-compact-block"
    "bitcoin-lisp.networking:compact-block-stats"
    "bitcoin-lisp.networking:last-checkpoint-height"
    "bitcoin-lisp.networking:local-addresses"
    "bitcoin-lisp.networking:request-headers"
    "bitcoin-lisp.networking:tor-controller-service-id"
    "bitcoin-lisp.serialization:bip155-network-keyword"
    "bitcoin-lisp.serialization:br-read-compressed-coin"
    "bitcoin-lisp.serialization:make-getblocks-message"
    "bitcoin-lisp.storage:add-utxo"
    "bitcoin-lisp.storage:any-utxo-for-txid-p"
    "bitcoin-lisp.storage:coins-view-db-erase"
    "bitcoin-lisp.storage:coins-view-db-has-p"
    "bitcoin-lisp.storage:coins-view-db-put"
    "bitcoin-lisp.storage:coins-view-db-write-batch"
    "bitcoin-lisp.storage:find-next-record"
    "bitcoin-lisp.storage:flat-file-pos-null-p"
    "bitcoin-lisp.storage:gcs-filter-match"
    "bitcoin-lisp.storage:leveldb-writebatch-clear"
    "bitcoin-lisp.storage:load-tx-index"
    "bitcoin-lisp.storage:remove-utxo"
    "bitcoin-lisp.storage:save-utxo-set"
    "bitcoin-lisp.storage:txindex-contains-p"
    "bitcoin-lisp.storage:txindex-remove-block"
    "bitcoin-lisp.storage:utxo-exists-p"
    "bitcoin-lisp.storage:write-utxo-entry-fields"
    "bitcoin-lisp.validation:decode-coinbase-height"
    "bitcoin-lisp.validation:execute-script")
  "Exported functions with no caller in src/ as of 2026-08-22, as
\"package:name\" strings -- strings rather than symbols so that unexporting one
is an ordinary test failure and not a READ error that kills compilation.")

(defun %bitcoin-lisp-packages ()
  "The project's own CL packages: everything named BITCOIN-LISP*, minus the
tests package and the Coalton ones. Derived rather than listed so a new package
cannot be silently excluded from the sweep -- but the Coalton packages are held
out on purpose: their exports are generated, and the several hundred that no CL
code calls would bury the finding this test exists to surface."
  (remove-if-not
   (lambda (p)
     (let ((n (package-name p)))
       (and (>= (length n) 12)
            (string= "BITCOIN-LISP" n :end2 12)
            (not (search ".COALTON" n))
            (not (string= "BITCOIN-LISP.TESTS" n)))))
   (list-all-packages)))

(defun %function-object-references (src)
  "The set of names SRC references as a function OBJECT, i.e. #'name.

Needed because xref records CALLS only: a function installed as a hook --
Core-style, e.g. (setf *peer-disconnect-hook* #'tx-request-disconnected-peer)
-- has no call site and would otherwise read as dead. Tokenised rather than
searched per symbol, so that #'request-headers-for-ibd cannot be mistaken for
a reference to REQUEST-HEADERS: a substring test would drop every name that is
a prefix of another, silently, which is the same failure mode as the dead code
it hunts."
  (let ((refs (make-hash-table :test #'equal))
        (i 0))
    (flet ((name-char-p (c)
             (or (alphanumericp c) (find c "-+*/<>=!?%_&.:"))))
      (loop while (setf i (search "#'" src :start2 i))
            do (let* ((start (+ i 2))
                      (end (or (position-if-not #'name-char-p src :start start)
                               (length src))))
                 (when (> end start)
                   (setf (gethash (subseq src start end) refs) t))
                 (setf i start))))
    refs))

(defvar *orphan-sweep-cache* nil
  "Memo for %ORPHAN-EXPORTED-FUNCTIONS: the sweep reads every file under src/
and nothing between the tests in this file can change its answer.")

(defun %orphan-exported-functions ()
  "Every exported function in the project's packages with no caller in src/.

A caller counts when SB-INTROSPECT:WHO-CALLS reports one whose own name is not
in the tests package, or when src/ references the function as an object (see
%FUNCTION-OBJECT-REFERENCES).

DEFSTRUCT-generated predicates and accessors are excluded: SBCL gives them a
source-transform and hand-written functions have none, so the two separate
cleanly and the many unused accessors do not bury the real finding."
  (or *orphan-sweep-cache*
      (setf *orphan-sweep-cache*
            (let* ((root (asdf:system-source-directory :bitcoin-lisp))
                   (src (string-downcase
                         (with-output-to-string (o)
                           (dolist (f (directory (merge-pathnames "src/**/*.lisp" root)))
                             (with-open-file (in f :external-format :utf-8)
                               (loop for line = (read-line in nil) while line
                                     do (write-line line o)))))))
                   (refs (%function-object-references src))
                   (tests-package (find-package "BITCOIN-LISP.TESTS"))
                   (found '()))
              (labels ((root-symbol (name)
                         (cond ((symbolp name) name)
                               ((consp name) (root-symbol (find-if #'symbolp (cdr name))))
                               (t nil)))
                       (test-caller-p (caller)
                         (let ((r (root-symbol (car caller))))
                           (and r (eq (symbol-package r) tests-package))))
                       (orphan-p (sym)
                         (and (fboundp sym)
                              (not (macro-function sym))
                              (not (typep (fdefinition sym) 'generic-function))
                              (not (sb-int:info :function :source-transform sym))
                              (every #'test-caller-p (sb-introspect:who-calls sym))
                              (not (gethash (string-downcase (symbol-name sym)) refs)))))
                (dolist (pkg (%bitcoin-lisp-packages))
                  (do-external-symbols (sym pkg)
                    (when (orphan-p sym)
                      (pushnew (format nil "~(~A:~A~)"
                                       (package-name (symbol-package sym))
                                       (symbol-name sym))
                               found :test #'string=))))
                (sort found #'string<))))))

(test no-new-orphaned-exports
  "An exported function that nothing in src/ calls is either an entry point or
a bug, and this project's history says it is usually a bug -- ten times so far,
never once caught by a unit test."
  (let* ((current (%orphan-exported-functions))
         (new (set-difference current *orphan-export-baseline* :test #'string=))
         (resolved (set-difference *orphan-export-baseline* current :test #'string=)))
    (is (null new)
        "no caller in src/ for:~%~{  ~A~%~}Wire it up, or add it to ~
*ORPHAN-EXPORT-BASELINE* under the group that says why."
        new)
    ;; Progress, not a failure: report it so the list can be pruned.
    (when resolved
      (format *test-dribble*
              "~&; ~D *ORPHAN-EXPORT-BASELINE* entr~:@P now called from src/; ~
delete from the list:~%~{;   ~A~%~}" (length resolved) resolved))))

(test orphan-sweep-can-actually-fail
  "Positive control for NO-NEW-ORPHANED-EXPORTS, whose assertion is of the form
\"this set is empty\" -- exactly the shape that keeps passing once the machinery
underneath quietly stops working. Hide one known orphan from the comparison and
confirm the sweep still reports it. Independent of the baseline, so baseline
drift cannot turn this control into a false alarm."
  (let ((current (%orphan-exported-functions)))
    (is (plusp (length current)) "the orphan sweep found nothing at all")
    (is (= 1 (length (set-difference current (rest current) :test #'string=)))
        "a known orphan withheld from the comparison must surface as new")
    ;; And the object-reference scan must actually exclude something, or every
    ;; hook-installed function would read as dead.
    (let ((refs (%function-object-references "(setf *hook* #'tx-request-disconnected-peer)")))
      (is-true (gethash "tx-request-disconnected-peer" refs))
      (is-false (gethash "tx-request-disconnected" refs)
                "a prefix of a referenced name must not count as referenced"))))
