(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/package_eval.cpp at the pin (d3056bc149):
;;;; tx_package_eval and ephemeral_package_eval. The chain of the tx_pool
;;;; targets, its coinbases paying P2WSH of the EMPTY script; packages of one
;;;; to 26 transactions (at most four, and dust, in the ephemeral target)
;;;; submitted through ProcessNewPackage -- VALIDATE-PACKAGE-FOR-MEMPOOL, or
;;;; TEST-PACKAGE-ACCEPTANCE when Core test-accepts -- and their last
;;;; transaction through AcceptToMemoryPool; the per-transaction results must
;;;; agree with the package verdict and the pool (Core
;;;; CheckPackageMempoolAcceptResult), the TRUC topology and the ephemeral
;;;; dust rules hold, and the pool passes CTxMemPool::check at the end.
;;;;
;;;; Ours differs from Core's in three ways the port states rather than
;;;; asserts. A reconsiderable failure (a fee failure) carries no effective
;;;; feerate here -- no caller reads one -- so only a VALID result's is
;;;; checked. The package result lists its replacements once, not per
;;;; transaction, so Core's "a two-transaction package RBF is a cluster of
;;;; two" check has no per-transaction set to read. And the test-accept path
;;;; takes no client maxfeerate (testmempoolaccept applies its own cap after
;;;; the fact); Core's single-transaction test accept is handed one.
;;;; Core's ancestor/descendant count options are read and ignored, as the
;;;; cluster mempool ignores them.

(def-suite :fuzz-package-eval-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/package_eval.cpp targets")

(in-suite :fuzz-package-eval-tests)

(defparameter +p2wsh-empty+
  (p2wsh-script (bl.crypto:sha256 (make-array 0 :element-type '(unsigned-byte 8))))
  "Core P2WSH_EMPTY (test/util/script.h:23-29).")

(defun package-eval-stack (op)
  "P2WSH_EMPTY_TRUE_STACK (OP = #x51) or P2WSH_EMPTY_TWO_STACK (#x52): OP,
then the empty witness script."
  (list (make-array 1 :element-type '(unsigned-byte 8) :initial-element op)
        (make-array 0 :element-type '(unsigned-byte 8))))

(defparameter +package-eval-null-txid+
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun package-eval-apply-events (delta mempool-outpoints)
  "Core OutpointsUpdater (package_eval.cpp:60-86) over DELTA's signals in
sequence order: an added transaction's outputs become spendable; a removed
one's inputs are spendable again (a replacement's could already be) and its
outputs gone. Returns the txids added and not removed since, Core's
TransactionsDelta."
  (let ((added '()))
    (dolist (event (sort (append (mapcar (lambda (e) (cons :added e)) (car delta))
                                 (mapcar (lambda (e) (cons :removed e)) (cdr delta)))
                         #'< :key #'third))
      (destructuring-bind (kind txid sequence tx) event
        (declare (ignore sequence))
        (ecase kind
          (:added
           (pushnew txid added :test #'equalp)
           (dotimes (n (length (bl.ser:transaction-outputs tx)))
             (outpoint-set-insert mempool-outpoints (cons txid n))))
          (:removed
           (setf added (remove txid added :test #'equalp))
           (loop for in across (bl.ser:transaction-inputs tx)
                 for op = (bl.ser:tx-in-previous-output in)
                 do (outpoint-set-insert mempool-outpoints
                                         (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op))))
           (dotimes (n (length (bl.ser:transaction-outputs tx)))
             (outpoint-set-erase mempool-outpoints (cons txid n)))))))
    (setf (car delta) '() (cdr delta) '())
    added))

(defun package-eval-policy-failure-p (package-msg)
  "Did the package fail as a package (Core PCKG_POLICY), not on a member?"
  (not (member package-msg '("success" "transaction failed") :test #'string=)))

(defun check-package-mempool-accept-result (txs msg results replaced mempool)
  "Core CheckPackageMempoolAcceptResult (test/util/txmempool.cpp:44-143) for
a submitted package whose verdict MSG is not a package-level one: every
member has a result, none invalid in a valid package; the base fee and
vsize are there exactly for a VALID or MEMPOOL_ENTRY result, the other wtxid
exactly for DIFFERENT_WITNESS, and a VALID result has its effective feerate;
a member is in the pool (by txid) exactly when its result is not INVALID,
and not by wtxid when it was a different witness; nothing replaced is left
in the pool, and no more than 100 were replaced."
  (dolist (tx txs)
    (let* ((wtxid (bl.ser:transaction-wtxid tx))
           (r (find wtxid results :key #'bl.val:package-tx-result-wtxid :test #'equalp))
           (status (and r (bl.val:package-tx-result-status r))))
      (fuzz-assert (and r (not (eq status :not-validated))) "no result for a package member")
      (when (and r (not (eq status :not-validated)))
        (let ((has-fees (member status '(:valid :mempool-entry))))
          (when (eq msg :success)
            (fuzz-assert (not (eq status :invalid)) "a member of a valid package failed: ~S"
                         (bl.val:package-tx-result-error r)))
          (fuzz-assert (eq (not (bl.val:package-tx-result-fee r)) (not has-fees))
                       "a ~S result ~:[without~;with~] a base fee" status (bl.val:package-tx-result-fee r))
          (fuzz-assert (eq (not (bl.val:package-tx-result-vsize r)) (not has-fees))
                       "a ~S result ~:[without~;with~] a vsize" status (bl.val:package-tx-result-vsize r))
          (fuzz-assert (eq (not (bl.val:package-tx-result-other-wtxid r)) (not (eq status :different-witness)))
                       "a ~S result ~:[without~;with~] another wtxid" status (bl.val:package-tx-result-other-wtxid r))
          (when (eq status :valid)
            (fuzz-assert (and (bl.val:package-tx-result-effective-feerate r)
                              (bl.val:package-tx-result-effective-includes r))
                         "a valid result without its effective feerate"))
          (fuzz-assert (eq (not (fuzz-sabotage (bl.mp:mempool-has mempool (bl.ser:transaction-hash tx))))
                           (eq status :invalid))
                       "a ~S member is ~:[not ~;~]in the pool" status
                       (bl.mp:mempool-has mempool (bl.ser:transaction-hash tx)))
          (when (eq status :different-witness)
            (fuzz-assert (not (gethash wtxid (bl.mp:mempool-by-wtxid mempool)))
                         "a different-witness member is in the pool by its own wtxid"))))))
  (fuzz-assert (<= (length replaced) 100) "~D replaced" (length replaced))
  (dolist (txid replaced)
    (fuzz-assert (not (bl.mp:mempool-has mempool txid)) "a replaced transaction is still in the pool")))

(defun package-eval-submit (txs single-submit utxo-set mempool chain-state client-maxfeerate)
  "ProcessNewPackage(txs, test_accept = SINGLE-SUBMIT, client_maxfeerate).
Returns (values msg results replaced package-msg)."
  (if single-submit
      (multiple-value-bind (package-error results)
          (bl.val:test-package-acceptance txs utxo-set mempool chain-state)
        (values (or package-error
                    (if (every (lambda (r) (eq (bl.val:package-tx-result-status r) :valid)) results)
                        :success :failed))
                results '()
                (if package-error "package-error" "transaction failed")))
      (bl.val:validate-package-for-mempool txs utxo-set mempool chain-state
                                           :client-maxfeerate client-maxfeerate)))

(defun package-eval-check-results (txs single-submit msg results replaced package-msg mempool)
  (cond (single-submit)
        ((not (package-eval-policy-failure-p package-msg))
         (check-package-mempool-accept-result txs msg results replaced mempool))
        (t
         ;; Core: empty when the package failed early, else one per member.
         (fuzz-assert (or (every (lambda (r) (eq (bl.val:package-tx-result-status r) :not-validated)) results)
                          (notany (lambda (r) (eq (bl.val:package-tx-result-status r) :not-validated)) results))
                      "a package-level failure with some members judged and some not"))))

(defun tx-package-eval-tx (fdp txs num-txs mempool-outpoints package-outpoints values)
  "One transaction of tx_package_eval's package (package_eval.cpp:340-420)."
  (let* ((version (if (consume-bool fdp) bl.mp:+truc-version+ 2))
         (lock-time (if (consume-bool fdp) 0 (consume-integral fdp :u32)))
         (last-tx (and (> num-txs 1) (= (length txs) (1- num-txs))))
         (num-in (if last-tx
                     (hash-table-count package-outpoints)
                     (consume-integral-in-range fdp 1 (hash-table-count mempool-outpoints) 32)))
         (num-out (consume-integral-in-range fdp 1 (* 2 (hash-table-count mempool-outpoints)) 32))
         (outpoints (if last-tx package-outpoints mempool-outpoints))
         (amount-in 0) (inputs '()) (stacks '()) (outputs '()))
    (fuzz-assert (plusp (hash-table-count outpoints)))
    (dotimes (i num-in)
      (declare (ignorable i))
      (let ((op (outpoint-set-pop fdp outpoints)))
        (incf amount-in (gethash op values))
        (push (cons op (consume-sequence fdp)) inputs)
        (push (package-eval-stack (if (consume-bool fdp) #x51 #x52)) stacks)))
    (let ((dup-input (consume-bool fdp)))
      (when dup-input
        (push (first inputs) inputs)
        (push (first stacks) stacks))
      (when (consume-bool fdp)
        ;; A CTxIn(): the null prevout, no script, SEQUENCE_FINAL.
        (push (cons (cons +package-eval-null-txid+ #xffffffff) #xffffffff) inputs)
        (push '() stacks))
      (when (and last-tx (> amount-in 1000) (consume-bool fdp))
        (push (cons 1000 +tx-pool-fuzz-p2pk-sigops+) outputs)
        (setf num-out 1)
        (decf amount-in 1000))
      (let* ((fee (consume-integral-in-range fdp 0 amount-in))
             (amount-out (truncate (- amount-in fee) num-out)))
        (dotimes (i num-out) (push (cons amount-out +p2wsh-empty+) outputs)))
      (let ((tx (fuzz-tx-with-witness version lock-time (reverse inputs) (reverse stacks) (reverse outputs))))
        (unless last-tx
          (dolist (in inputs)
            (fuzz-assert (or (equalp (car in) (cons +package-eval-null-txid+ #xffffffff))
                             (outpoint-set-insert outpoints (car in))
                             dup-input)))
          (dotimes (n (length (bl.ser:transaction-outputs tx)))
            (outpoint-set-insert package-outpoints (cons (bl.ser:transaction-hash tx) n))))
        (loop for o across (bl.ser:transaction-outputs tx)
              for n from 0
              do (setf (gethash (cons (bl.ser:transaction-hash tx) n) values) (bl.ser:tx-out-value o)))
        tx))))

(defun package-eval-make-mempool (fdp)
  "Core MakeMempool (package_eval.cpp:115-140). Returns (values mempool
expiry-hours bytes-per-sigop require-standard)."
  (consume-integral-in-range fdp 0 50 32)     ; limits.ancestor_count
  (consume-integral-in-range fdp 0 50 32)     ; limits.descendant_count
  (let* ((max-size (* (consume-integral-in-range fdp 0 200 32) 1000000))
         (expiry (consume-integral-in-range fdp 0 999 32))
         (bytes-per-sigop (* (consume-integral-in-range fdp 0 1 32) 10000))
         (require-standard (consume-bool fdp)))
    (values (bl.mp:make-mempool :max-size max-size) expiry bytes-per-sigop require-standard)))

(defun package-eval-coin-values (mature)
  (let ((values (make-hash-table :test 'equalp)))
    (dolist (op mature values)
      (setf (gethash op values) (* 50 +fuzz-coin+)))))

(defun tx-package-eval-record-tx (tail fdp last-tx package-size)
  "Record one tx_package_eval transaction's reads: one input (or, for the
child, the package's outputs, which it reads no count for), one output, the
OP_TRUE witness, no duplicate or null input, a fee small beside the 50 BTC
the input carries -- or none, for a parent a child has to pay for."
  (if (plusp (consume-integral-in-range fdp 0 4))
      (fdp-tail-bool tail nil)                         ; version 2
      (fdp-tail-bool tail t))                          ; TRUC
  (fdp-tail-bool tail t)                               ; nLockTime 0
  (unless last-tx
    (fdp-tail-integral tail 1 1 128 32))               ; one input
  (fdp-tail-integral tail 1 1 256 32)                  ; one output
  (dotimes (i (if last-tx (1- package-size) 1))
    ;; Which outpoint: of about a hundred, or of the child's parents'
    ;; outputs, which it pops one by one (a range of 0 reads nothing).
    (let ((top (if last-tx (- package-size 2 i) 127)))
      (fdp-tail-integral tail (consume-integral-in-range fdp 0 (min top 99)) 0 top))
    (fdp-tail-bool tail t)
    (fdp-tail-integral tail (pick-value-in-array fdp '(0 2)) 0 2)       ; final, or signalling
    (fdp-tail-bool tail t))                            ; P2WSH_EMPTY_TRUE_STACK
  (fdp-tail-bool tail nil)                             ; no duplicate input
  (fdp-tail-bool tail nil)                             ; no null input
  (when last-tx (fdp-tail-bool tail nil))              ; no P2PK output
  (fdp-tail-integral tail (cond ((and (not last-tx) (> package-size 1) (zerop (consume-integral-in-range fdp 0 2))) 0)
                                (last-tx (consume-integral-in-range fdp 1000 60000))
                                (t (consume-integral-in-range fdp 150 6000)))
                     0 (* 50 +fuzz-coin+)))

(defun tx-package-eval-corpus (fdp)
  "A buffer whose END records up to twelve packages Core's target can accept:
a lone transaction, or one or two parents and the child spending them, each
spending one outpoint the target picks (a coinbase, a pool output, or one
already spent: a replacement). The front is random, and the target reads on
into it."
  (let ((tail (make-fdp-tail)))
    (tx-pool-fuzz-record-mock-time tail fdp)
    (fdp-tail-integral tail 0 0 50 32)                 ; ancestor_count
    (fdp-tail-integral tail 0 0 50 32)                 ; descendant_count
    (fdp-tail-integral tail (consume-integral-in-range fdp 1 200) 0 200 32)
    (fdp-tail-integral tail (consume-integral-in-range fdp 1 999) 0 999 32)
    (fdp-tail-integral tail (consume-integral-in-range fdp 0 1) 0 1 32)
    (fdp-tail-bool tail (consume-bool fdp))            ; require_standard
    (dotimes (r (consume-integral-in-range fdp 1 12))
      (declare (ignorable r))
      (let ((size (pick-value-in-array fdp '(1 2 2 3))))
        (fdp-tail-integral tail size 1 26)
        (dotimes (k size)
          (tx-package-eval-record-tx tail fdp (and (> size 1) (= k (1- size))) size))
        (fdp-tail-bool tail nil)                       ; no new mock time
        (fdp-tail-bool tail (zerop (consume-integral-in-range fdp 0 5)))
        (fdp-tail-bool tail nil)                       ; no prioritisation
        (when (= size 1) (fdp-tail-bool tail (consume-bool fdp))) ; single_submit
        (fdp-tail-bool tail nil)))                     ; no client maxfeerate
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (insecure-rand-bytes (make-insecure-random-context (consume-integral fdp :u64)) 64)
                 (fdp-tail-bytes tail))))

(define-fuzz-target tx-package-eval
    (buffer :core "package_eval.cpp:318-539" :iterations 750 :max-len 3000
            :corpus (lambda (fdp) (tx-package-eval-corpus fdp)))
  "Packages of one to 26 transactions spending the pool's outputs: a
submitted package's per-member results agree with its verdict and with the
pool, a lone transaction is accepted exactly when the pool announces it, the
TRUC topology and (under standardness) the ephemeral dust rules hold, and the
pool passes CTxMemPool::check at the end."
  (with-network (:regtest)
    (let ((fdp (make-fuzzed-data-provider buffer))
          (bl.ser:*mock-time* nil)
          (bl.mp:*block-policy-estimator* nil)
          (delta (cons '() '())))
      (multiple-value-bind (chain-state utxo-set mature) (tx-pool-fuzz-setup +p2wsh-empty+)
        (fuzz-mock-time fdp chain-state)
        (let ((mempool-outpoints (make-outpoint-set mature))
              (values (package-eval-coin-values mature)))
          (multiple-value-bind (mempool expiry bytes-per-sigop require-standard)
              (package-eval-make-mempool fdp)
            (let ((bl.val:*require-standard* require-standard)
                  (bl.mp:*mempool-expiry-hours* expiry)
                  (bl.mp:*bytes-per-sigop* bytes-per-sigop)
                  (*fuzz-mempool-delta* delta))
              (limited-while ((plusp (remaining-bytes fdp)) 300)
                (fuzz-assert (plusp (hash-table-count mempool-outpoints)))
                (let* ((num-txs (consume-integral-in-range fdp 1 26))
                       (package-outpoints (make-outpoint-set))
                       (txs '()))
                  (loop while (< (length txs) num-txs)
                        do (setf txs (append txs (list (tx-package-eval-tx fdp txs num-txs mempool-outpoints
                                                                           package-outpoints values)))))
                  (when (consume-bool fdp) (fuzz-mock-time fdp chain-state))
                  (when (consume-bool fdp) (fuzz-restart-rolling-fee mempool))
                  (when (consume-bool fdp)
                    (tx-pool-fuzz-prioritise
                     fdp mempool (if (consume-bool fdp)
                                     (bl.ser:transaction-hash (car (last txs)))
                                     (car (outpoint-set-nth mempool-outpoints
                                                            (consume-integral-in-range
                                                             fdp 0 (1- (hash-table-count mempool-outpoints))))))))
                  (package-eval-apply-events delta mempool-outpoints)
                  (let* ((tx (car (last txs)))
                         (single-submit (and (= 1 (length txs)) (consume-bool fdp)))
                         (client-maxfeerate (when (consume-bool fdp)
                                              ;; CFeeRate(fee, 100 vB), in sat/kvB.
                                              (* 10 (consume-integral-in-range fdp -1 (* 50 +fuzz-coin+))))))
                    (multiple-value-bind (msg results replaced package-msg)
                        (package-eval-submit txs single-submit utxo-set mempool chain-state client-maxfeerate)
                      (let* ((passed (fuzz-atmp tx utxo-set mempool chain-state :test-accept (not single-submit)))
                             (added (package-eval-apply-events delta mempool-outpoints)))
                        (if single-submit
                            (progn
                              (fuzz-assert (eq (not (fuzz-sabotage passed)) (null added))
                                           "passed ~S, but the pool announced ~D additions" passed (length added))
                              (when passed
                                (fuzz-assert (and (= 1 (length added))
                                                  (equalp (first added) (bl.ser:transaction-hash tx))))))
                            (package-eval-check-results txs nil msg results replaced package-msg mempool)))))
                  (check-mempool-truc-invariants mempool)
                  (when require-standard
                    (check-mempool-ephemeral-invariants mempool))))
              (check-mempool mempool :coin-value (tx-pool-fuzz-coin-value utxo-set)))))))))

(defun package-eval-child-evicting-prevout (mempool)
  "Core GetChildEvictingPrevout (package_eval.cpp:163-190): the first dusty
pool transaction with a child, and an input of that child not spending the
dusty parent -- double-spending it evicts the child and strands the dust."
  (dolist (item (mempool-entries-in-mining-order mempool))
    (destructuring-bind (txid . e) item
      (when (fuzz-dust-indexes (bl.mp:mempool-entry-transaction e))
        (let ((children (loop for c being the hash-keys of (bl.mp:mempool-entry-children e) collect c)))
          (when children
            (fuzz-assert (= 1 (length children)))
            (loop for in across (bl.ser:transaction-inputs
                                 (bl.mp:mempool-entry-transaction (bl.mp:mempool-get mempool (first children))))
                  for op = (bl.ser:tx-in-previous-output in)
                  unless (equalp (bl.ser:outpoint-hash op) txid)
                    do (return-from package-eval-child-evicting-prevout
                         (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op))))))))))

(defun ephemeral-package-eval-tx (fdp txs num-txs rbf-outpoint mempool-outpoints package-outpoints values)
  "One transaction of ephemeral_package_eval's package (package_eval.cpp:219-290)."
  (let* ((last-tx (and (> num-txs 1) (= (length txs) (1- num-txs))))
         (num-in (cond (rbf-outpoint 2)
                       (last-tx (consume-integral-in-range fdp (1+ (floor (hash-table-count package-outpoints) 2))
                                                           (hash-table-count package-outpoints) 32))
                       (t (consume-integral-in-range fdp 1 4 32))))
         (num-out (if rbf-outpoint 1 (consume-integral-in-range fdp 1 4 32)))
         (outpoints (if last-tx package-outpoints mempool-outpoints))
         (amount-in 0) (inputs '()) (outputs '()))
    (fuzz-assert (and (>= (hash-table-count outpoints) num-in) (plusp num-in)))
    (dotimes (i num-in)
      (let* ((k (consume-integral-in-range fdp 0 (1- (hash-table-count outpoints))))
             (op (if (and (zerop i) rbf-outpoint)
                     (progn (outpoint-set-erase outpoints rbf-outpoint) rbf-outpoint)
                     (let ((o (outpoint-set-nth outpoints k))) (outpoint-set-erase outpoints o) o))))
        (incf amount-in (gethash op values))
        (push op inputs)))
    (setf inputs (nreverse inputs))
    (let* ((fee (consume-integral-in-range fdp 0 amount-in))
           (amount-out (truncate (- amount-in fee) num-out)))
      (dotimes (i num-out) (push (cons amount-out +p2wsh-empty+) outputs))
      (setf outputs (nreverse outputs))
      (when (and (not rbf-outpoint) (consume-bool fdp))
        (let ((at (consume-integral-in-range fdp 0 num-out 32)))
          (setf outputs (append (subseq outputs 0 at) (list (cons 0 +p2wsh-empty+)) (nthcdr at outputs))))))
    (let ((tx (fuzz-tx-with-witness 2 0 (mapcar (lambda (op) (cons op #xffffffff)) inputs)
                                    (mapcar (lambda (op) (declare (ignore op)) (package-eval-stack #x51)) inputs)
                                    outputs)))
      (unless last-tx
        (dolist (op inputs) (fuzz-assert (outpoint-set-insert outpoints op)))
        (dotimes (n (length (bl.ser:transaction-outputs tx)))
          (outpoint-set-insert package-outpoints (cons (bl.ser:transaction-hash tx) n))))
      (loop for o across (bl.ser:transaction-outputs tx)
            for n from 0
            do (setf (gethash (cons (bl.ser:transaction-hash tx) n) values) (bl.ser:tx-out-value o)))
      tx)))

(define-fuzz-target ephemeral-package-eval
    (buffer :core "package_eval.cpp:192-316" :iterations 500 :max-len 3000
            :corpus (lambda (fdp) (tx-pool-fuzz-corpus fdp)))
  "Small packages that leave dust outputs, and single transactions that
double-spend a dust sweeper's other input, under standardness and a zero
relay floor: a pool transaction has at most one dust output, pays nothing
if it has one, and has at most one child, which spends it; a submitted
package's results agree with its verdict; the pool passes CTxMemPool::check."
  (with-network (:regtest)
    (let ((fdp (make-fuzzed-data-provider buffer))
          (bl.ser:*mock-time* nil)
          (bl.mp:*block-policy-estimator* nil)
          (bl.val:*require-standard* t)
          (delta (cons '() '())))
      (multiple-value-bind (chain-state utxo-set mature) (tx-pool-fuzz-setup +p2wsh-empty+)
        (fuzz-mock-time fdp chain-state)
        (let ((mempool-outpoints (make-outpoint-set mature))
              (values (package-eval-coin-values mature))
              (mempool (bl.mp:make-mempool :min-fee-rate 0))
              (*fuzz-mempool-delta* delta))
          (limited-while ((plusp (remaining-bytes fdp)) 300)
            (fuzz-assert (plusp (hash-table-count mempool-outpoints)))
            (let* ((rbf-outpoint (and (consume-bool fdp) (package-eval-child-evicting-prevout mempool)))
                   (num-txs (if rbf-outpoint 1 (consume-integral-in-range fdp 1 4)))
                   (package-outpoints (make-outpoint-set))
                   (txs '()))
              (loop while (< (length txs) num-txs)
                    do (setf txs (append txs (list (ephemeral-package-eval-tx
                                                    fdp txs num-txs rbf-outpoint mempool-outpoints
                                                    package-outpoints values)))))
              (when (consume-bool fdp)
                (let ((txid (if (consume-bool fdp)
                                (bl.ser:transaction-hash (car (last txs)))
                                (car (outpoint-set-nth mempool-outpoints
                                                       (consume-integral-in-range
                                                        fdp 0 (1- (hash-table-count mempool-outpoints)))))))
                      (delta-fee (consume-integral-in-range fdp (* -50 +fuzz-coin+) (* 50 +fuzz-coin+))))
                  ;; Only a pool transaction without dust: prioritisation
                  ;; does not filter for ephemeral dust.
                  (let ((e (bl.mp:mempool-get mempool txid)))
                    (when (and e (null (fuzz-dust-indexes (bl.mp:mempool-entry-transaction e))))
                      (bl.mp:mempool-prioritise mempool txid delta-fee)))))
              (let ((single-submit (= 1 (length txs))))
                (multiple-value-bind (msg results replaced package-msg)
                    (package-eval-submit txs single-submit utxo-set mempool chain-state nil)
                  (fuzz-atmp (car (last txs)) utxo-set mempool chain-state :test-accept (not single-submit))
                  (unless single-submit
                    (package-eval-check-results txs nil msg results replaced package-msg mempool))))
              (package-eval-apply-events delta mempool-outpoints)
              (check-mempool-ephemeral-invariants mempool)))
          (check-mempool mempool :coin-value (tx-pool-fuzz-coin-value utxo-set)))))))
