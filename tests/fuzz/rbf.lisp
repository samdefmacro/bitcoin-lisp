(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/rbf.cpp at the pin (d3056bc149): rbf (IsRBFOptIn over
;;;; a pool of arbitrary transactions) and package_rbf (the before/after
;;;; feerate diagrams of a replacement staged over parent-child pairs --
;;;; Core's ChangeSet::CalculateChunksForRBF, TXGRAPH-RBF-DIAGRAMS here -- and
;;;; ImprovesFeerateDiagram's verdict on them).
;;;;
;;;; Core's rbf target asserts nothing but survival; the port checks the answer
;;;; against IsRBFOptIn computed directly (policy/rbf.cpp:24-49: the
;;;; transaction's own signal, else, for a pool transaction, any in-pool
;;;; ancestor's -- ancestors being the parents it had when it entered). Its
;;;; pool holds unvalidated transactions (an input may name an output its
;;;; parent does not have), so CTxMemPool::check, which Core does not call
;;;; there either, runs only over package_rbf's pool. The pool is filled through MEMPOOL-ADD,
;;;; which, unlike Core's TryAddToMempool test helper, refuses a second spend
;;;; of an outpoint.

(def-suite :fuzz-rbf-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/rbf.cpp targets")

(in-suite :fuzz-rbf-tests)

(defun rbf-fuzz-consume-tx (fdp)
  "ConsumeDeserializable<CMutableTransaction>(TX_WITH_WITNESS)."
  (consume-deserializable
   fdp (lambda (bytes) (bl.ser:br-read-transaction (bl.ser:make-byte-reader-from bytes)))))

(defun rbf-fuzz-serialized-tx (fdp)
  "A small random transaction with at least one input -- a transaction with
none reads back, under TX_WITH_WITNESS, as a witness marker -- as
ConsumeDeserializable reads one from the front of the buffer."
  (let ((tx (loop repeat 8
                  for tx = (consume-transaction fdp :max-num-in 3 :max-num-out 3)
                  when (plusp (length (bl.ser:transaction-inputs tx))) return tx
                  finally (return tx))))
    (fdp-random-length-bytes (bl.ser:serialize-transaction tx))))

(defun rbf-fuzz-corpus (fdp)
  "For the rbf target: the transaction and N more at the front, and at the end
the choices that put them all in the pool (each loop round's ConsumeBool, the
prevout rewrite, an entry per transaction) -- steered, where libFuzzer's
coverage guidance would find them, so a draw reaches a pool of several."
  (let ((n (consume-integral-in-range fdp 0 10))
        (front (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
        (tail (make-fdp-tail)))
    (flet ((add-front (bytes) (loop for b across bytes do (vector-push-extend b front))))
      (add-front (rbf-fuzz-serialized-tx fdp))
      (fdp-tail-integral tail (consume-integral fdp :i64) (- (ash 1 63)) (1- (ash 1 63)))
      (dotimes (k n)
        (fdp-tail-bool tail t)
        (add-front (rbf-fuzz-serialized-tx fdp))
        (fdp-tail-bool tail (consume-bool fdp))
        (fdp-tail-mempool-entry tail fdp :max-height #xffffffff))
      (fdp-tail-bool tail nil)
      ;; The transaction itself joins the pool, where IsRBFOptIn looks at
      ;; its ancestors.
      (fdp-tail-bool tail t)
      (fdp-tail-mempool-entry tail fdp :max-height #xffffffff)
      (concatenate '(vector (unsigned-byte 8)) front (fdp-tail-bytes tail)))))

(defun package-rbf-fuzz-corpus (fdp)
  "For the package_rbf target: the replacement at the front, and at the end
its entry, N parent-child rounds (each a ConsumeBool, two entries and the
prioritisation choice), the conflicts chosen and the replacement fee."
  (let ((n (consume-integral-in-range fdp 0 12))
        (tail (make-fdp-tail)))
    (fdp-tail-integral tail (consume-integral fdp :i64) (- (ash 1 63)) (1- (ash 1 63)))
    (fdp-tail-mempool-entry tail fdp)
    (dotimes (k n)
      (fdp-tail-bool tail t)
      (fdp-tail-mempool-entry tail fdp)
      (fdp-tail-mempool-entry tail fdp)
      (let ((prioritise (consume-bool fdp)))
        (fdp-tail-bool tail prioritise)
        (when prioritise
          (fdp-tail-integral tail (consume-integral-in-range fdp -100000 100000) -100000 100000))))
    (fdp-tail-bool tail nil)
    (dotimes (k (* 2 n)) (fdp-tail-bool tail (consume-bool fdp)))
    (fdp-tail-integral tail (consume-integral-in-range fdp 0 2000000)
                       0 bl.val:+max-money+)
    (concatenate '(vector (unsigned-byte 8)) (rbf-fuzz-serialized-tx fdp) (fdp-tail-bytes tail))))

(defun rbf-fuzz-with-prevout (tx prevout-hash prevout-index)
  "TX with its first input's prevout replaced (Core's `mtx->vin[0].prevout =
...'), as a fresh transaction."
  (let ((inputs (copy-seq (bl.ser:transaction-inputs tx))))
    (setf (svref inputs 0)
          (bl.ser:make-tx-in :previous-output (bl.ser:make-outpoint :hash prevout-hash :index prevout-index)
                             :script-sig (bl.ser:tx-in-script-sig (svref inputs 0))
                             :sequence (bl.ser:tx-in-sequence (svref inputs 0))))
    (bl.ser:make-transaction :version (bl.ser:transaction-version tx)
                             :inputs inputs
                             :outputs (bl.ser:transaction-outputs tx)
                             :lock-time (bl.ser:transaction-lock-time tx)
                             :witness (bl.ser:transaction-witness tx))))

(define-fuzz-target rbf
    (buffer :core "rbf.cpp:52-92" :iterations 1500 :max-len 3000
            :corpus (lambda (fdp) (rbf-fuzz-corpus fdp)))
  "IsRBFOptIn answers as policy/rbf.cpp:24-49 does over a pool of arbitrary
transactions: the transaction's own opt-in signal, else any in-pool
ancestor's."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (mtx (progn (consume-integral fdp :i64) (rbf-fuzz-consume-tx fdp)))
         (pool (bl.mp:make-mempool))
         (parents-at-entry (make-hash-table :test 'equalp)))
    (unless mtx (fuzz-reject))
    (flet ((add (tx)
             (let ((txid (bl.ser:transaction-hash tx)))
               (unless (bl.mp:mempool-has pool txid)
                 (let ((parents (bl.mp:mempool-find-parents pool tx)))
                   (when (eq :ok (try-add-to-mempool
                                  pool (fuzz-mempool-entry (consume-tx-mempool-entry fdp tx #xffffffff))))
                     (setf (gethash txid parents-at-entry) parents)))))))
      (limited-while ((consume-bool fdp) 10000)
        (let ((another (rbf-fuzz-consume-tx fdp)))
          (unless another (return))
          (when (and (consume-bool fdp) (plusp (length (bl.ser:transaction-inputs mtx))))
            (setf mtx (rbf-fuzz-with-prevout mtx (bl.ser:transaction-hash another) 0)))
          (add another)))
      (when (consume-bool fdp) (add mtx))
      (let* ((txid (bl.ser:transaction-hash mtx))
             (expect (or (bl.mp:tx-signals-rbf-p mtx)
                         (and (bl.mp:mempool-has pool txid)
                              (let ((seen (make-hash-table :test 'equalp)) (todo (list txid)))
                                ;; The ancestors as Core's graph holds them:
                                ;; each transaction's parents when it entered.
                                (loop while todo
                                      do (let ((x (pop todo)))
                                           (dolist (p (gethash x parents-at-entry))
                                             (unless (gethash p seen)
                                               (setf (gethash p seen) t)
                                               (push p todo)))))
                                (loop for a being the hash-keys of seen
                                        thereis (bl.mp:tx-signals-rbf-p
                                                 (bl.mp:mempool-entry-transaction (bl.mp:mempool-get pool a)))))))))
        (when (bl.mp:mempool-has pool txid)
          (fuzz-assert (eq (fuzz-sabotage (and (bl.mp:mempool-tx-or-ancestor-signals-rbf-p pool txid) t))
                           (and expect t))
                       "IsRBFOptIn ~A, policy/rbf.cpp says ~A"
                       (bl.mp:mempool-tx-or-ancestor-signals-rbf-p pool txid) expect))))))

(define-fuzz-target package-rbf
    (buffer :core "rbf.cpp:94-247" :iterations 1500 :max-len 3000
            :corpus (lambda (fdp) (package-rbf-fuzz-corpus fdp)))
  "Staging a replacement of random conflicts (with their descendants) over
parent-child pairs gives diagrams whose feerates never rise, whose sums differ
by exactly what is replaced and what replaces it, and whose comparison is
`uncalculable' only when the staged cluster is over the limits -- and a
diagram the replacement improves never has a lower total fee."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (pool (bl.mp:make-mempool))
         (iter 0)
         (replacement (progn (consume-integral fdp :i64) (rbf-fuzz-consume-tx fdp))))
    (unless replacement (fuzz-reject))
    (flet ((unique-prevout ()
             ;; g_outpoints: a zero hash and a distinct index each.
             (prog1 (bl.ser:make-outpoint :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                 :initial-element 0)
                                          :index iter)
               (incf iter)))
           (one-input-tx (prevout outputs)
             (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in :previous-output prevout
                                                 :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                                 :sequence #xffffffff))
              :outputs outputs :lock-time 0)))
      (let* ((rtx (let ((op (unique-prevout)))
                    (bl.ser:make-transaction
                     :version (bl.ser:transaction-version replacement)
                     :inputs (vector (bl.ser:make-tx-in :previous-output op
                                                        :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                                        :sequence #xffffffff))
                     :outputs (bl.ser:transaction-outputs replacement)
                     :lock-time (bl.ser:transaction-lock-time replacement))))
             (rentry (consume-tx-mempool-entry fdp rtx 0))
             (replacement-weight (bl.mp:transaction-graph-weight rtx (getf rentry :sigops)))
             (running-vsize (getf rentry :vsize))
             (mempool-txs '()))
        (loop while (and (consume-bool fdp) (< iter 10000))
              do (let* ((parent (one-input-tx (unique-prevout)
                                              (vector (bl.ser:make-tx-out
                                                       :value 0
                                                       :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))))
                        (pentry (consume-tx-mempool-entry fdp parent 0)))
                   (incf running-vsize (getf pentry :vsize))
                   (when (> (* 4 running-vsize) (1- (ash 1 31))) (return))
                   ;; A parent the cluster limits refuse is skipped, child and all.
                   (when (eq :ok (try-add-to-mempool pool (fuzz-mempool-entry pentry)))
                     (push parent mempool-txs)
                     (let* ((child (one-input-tx (bl.ser:make-outpoint :hash (bl.ser:transaction-hash parent)
                                                                       :index 0)
                                                 #()))
                            (centry (consume-tx-mempool-entry fdp child 0)))
                       (incf running-vsize (getf centry :vsize))
                       (when (> (* 4 running-vsize) (1- (ash 1 31))) (return))
                       (when (eq :ok (try-add-to-mempool pool (fuzz-mempool-entry centry)))
                         (push child mempool-txs)
                         (when (consume-bool fdp)
                           (bl.mp:mempool-prioritise pool (bl.ser:transaction-hash child)
                                                     (consume-integral-in-range fdp -100000 100000))))))))
        (check-mempool pool)
        ;; Direct conflicts and everything descending from them.
        (let ((all (make-hash-table :test 'equalp)))
          (dolist (tx (reverse mempool-txs))
            (let ((txid (bl.ser:transaction-hash tx)))
              (when (and (consume-bool fdp) (bl.mp:mempool-has pool txid))
                (setf (gethash txid all) t)
                (maphash (lambda (d v) (declare (ignore v)) (setf (gethash d all) t))
                         (bl.mp:mempool-descendants pool txid)))))
          (let* ((fees (consume-money fdp))
                 (handles (loop for txid being the hash-keys of all
                                collect (bl.mp:mempool-entry-graph-handle (bl.mp:mempool-get pool txid))))
                 (replaced (bl.mp:make-feefrac)))
            (maphash (lambda (txid v) (declare (ignore v))
                       (let ((e (bl.mp:mempool-get pool txid)))
                         (setf replaced (bl.mp:feefrac+ replaced
                                                        (bl.mp:make-feefrac (bl.mp:mempool-entry-modified-fee e)
                                                                            (bl.mp:mempool-entry-graph-weight e))))))
                     all)
            (multiple-value-bind (old new)
                (bl.mp:txgraph-rbf-diagrams (bl.mp:mempool-graph pool) handles '() fees replacement-weight)
              (if (eq old :uncalculable)
                  ;; Uncalculable only for a staged cluster over the limits:
                  ;; the replacement has no in-pool parent, so only itself.
                  (fuzz-assert (> replacement-weight (* 4 bl.mp:*cluster-size-limit*))
                               "a replacement with no in-pool parent was called uncalculable")
                  (let ((old-sum (feefrac-sum old)) (new-sum (feefrac-sum new)))
                    (loop for (a b) on old while b do (fuzz-assert (not (bl.mp:feefrac<< a b))))
                    (loop for (a b) on new while b do (fuzz-assert (not (bl.mp:feefrac<< a b))))
                    (fuzz-assert (bl.mp:feefrac= (bl.mp:feefrac- old-sum replaced)
                                                 (bl.mp:feefrac- new-sum
                                                                 (bl.mp:make-feefrac (fuzz-sabotage fees)
                                                                                     replacement-weight)))
                                 "old diagram minus replaced ~A, new minus replacement ~A"
                                 (bl.mp:feefrac- old-sum replaced)
                                 (bl.mp:feefrac- new-sum (bl.mp:make-feefrac fees replacement-weight)))
                    ;; ImprovesFeerateDiagram (policy/rbf.cpp:127-140).
                    (when (eq (bl.mp:compare-chunks new old) :greater)
                      (fuzz-assert (<= (bl.mp:feefrac-fee old-sum) (bl.mp:feefrac-fee new-sum)))))))))))))
