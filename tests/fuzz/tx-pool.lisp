(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/tx_pool.cpp at the pin (d3056bc149): tx_pool_standard
;;;; and tx_pool. A regtest chain of 200 blocks whose first 100 coinbases are
;;;; mature (TX-POOL-FUZZ-SETUP), a mempool under random cluster, size and
;;;; expiry limits, and transactions submitted through the path every
;;;; acceptance takes (validate-transaction-for-mempool, accept-validated-tx),
;;;; with the pool checked the way Core's -checkmempool checks it
;;;; (CHECK-MEMPOOL) before and after a block is mined from it, re-added as
;;;; though reorged out, trimmed and expired.
;;;;
;;;; tx_pool_standard builds standard spends of the pool's own outputs and
;;;; keeps Core's books: the fees in the pool plus every spendable output's
;;;; value is always the 100 coinbases' 5000 BTC, and a transaction is
;;;; accepted exactly when the pool announces it, alone. tx_pool throws
;;;; arbitrary transactions (ConsumeTransaction) at the pool. Both check the
;;;; TRUC topology after every acceptance.
;;;;
;;;; Core's bypass of the signals queue (SyncWithValidationInterfaceQueue)
;;;; has no counterpart: our signals are synchronous. The coinbase of Core's
;;;; template is not offered back to the pool (it is refused there anyway).

(def-suite :fuzz-tx-pool-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/tx_pool.cpp targets")

(in-suite :fuzz-tx-pool-tests)

(defparameter +tx-pool-fuzz-p2pk-sigops+
  (let ((s (make-array 35 :element-type '(unsigned-byte 8) :initial-element 2)))
    (setf (aref s 0) 33 (aref s 34) #xac)
    s)
  "CScript() << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG.")

(defun tx-pool-fuzz-make-mempool (fdp)
  "Core SetMempoolConstraints + MakeMempool (tx_pool.cpp:82-94, :147-165):
cluster count 1..64, cluster size 1..250 kvB, -maxmempool 0..200 MB,
-mempoolexpiry 0..999 hours, and whether standardness is required. Returns
(values mempool expiry-hours require-standard)."
  (let* ((count (consume-integral-in-range fdp 1 64 32))
         (size-kvb (consume-integral-in-range fdp 1 250 32))
         (max-mb (consume-integral-in-range fdp 0 200 32))
         (expiry (consume-integral-in-range fdp 0 999 32))
         (require-standard (consume-bool fdp)))
    (let ((bl.mp:*cluster-count-limit* count)
          (bl.mp:*cluster-size-limit* (* size-kvb 1000)))
      (values (bl.mp:make-mempool :max-size (* max-mb 1000000)) expiry require-standard))))

(defun tx-pool-fuzz-prioritise (fdp mempool txid)
  "Core PrioritiseTransaction(txid, ConsumeIntegralInRange(-50 BTC, +50 BTC))."
  (bl.mp:mempool-prioritise mempool txid
                            (consume-integral-in-range fdp (* -50 +fuzz-coin+) (* 50 +fuzz-coin+))))

(defun tx-pool-fuzz-check-block-order (mempool txs)
  "Every template transaction's in-pool parents come before it."
  (let ((seen (make-hash-table :test 'equalp)))
    (dolist (tx txs)
      (let ((txid (bl.ser:transaction-hash tx)))
        (loop for in across (bl.ser:transaction-inputs tx)
              for ptxid = (bl.ser:outpoint-hash (bl.ser:tx-in-previous-output in))
              do (when (bl.mp:mempool-get mempool ptxid)
                   (fuzz-assert (gethash ptxid seen) "a template transaction precedes its in-pool parent")))
        (setf (gethash txid seen) t)))))

(defun tx-pool-fuzz-finish (fdp mempool utxo-set chain-state)
  "Core Finish (tx_pool.cpp:96-137): check the pool; mine a template from it
under a random weight limit and minimum feerate, remove the block's
transactions and offer them back as a reorg would (bypassing the limits,
removing with their spenders the ones refused, wiring the rest back in);
remove one pool transaction with its descendants; maybe trim to a random
size and expire at a random age; check the pool again."
  (let ((spend-height (1+ (bl.store:current-height chain-state))))
    (check-mempool mempool :coins utxo-set :spend-height spend-height)
    (let* ((template (let ((bl.mining:*block-max-weight* (consume-integral-in-range fdp 0 4000000 32))
                           (bl.mining:*block-min-tx-fee-rate* (consume-money fdp +fuzz-coin+)))
                       (bl.mining:assemble-block-template chain-state mempool)))
           (txs (mapcar #'bl.mp:mempool-entry-transaction
                        (bl.mining:block-template-transactions template))))
      (fuzz-assert template "no block template")
      (tx-pool-fuzz-check-block-order mempool txs)
      (bl.mp:mempool-remove-for-block mempool (bl.ser:make-bitcoin-block :transactions txs))
      (let ((readded '()))
        (dolist (tx txs)
          (let ((txid (bl.ser:transaction-hash tx)))
            (if (fuzz-atmp tx utxo-set mempool chain-state :bypass-limits t)
                (push txid readded)
                ;; removeRecursive(*tx, REORG): the transaction if it is in
                ;; the pool, else whatever spends its outputs.
                (let ((bl.mp:*mempool-removal-reason* :reorg))
                  (if (bl.mp:mempool-has mempool txid)
                      (bl.mp:mempool-remove-recursive mempool txid)
                      (bl.mp:mempool-remove-spenders mempool txid
                                                     (length (bl.ser:transaction-outputs tx))))))))
        (bl.mp:mempool-update-for-reorg mempool readded)))
    (let ((all (mempool-entries-in-mining-order mempool)))
      (when all
        (bl.mp:mempool-remove-recursive mempool (car (pick-value-in-array fdp all)))
        (fuzz-assert (< (fuzz-sabotage (bl.mp:mempool-count mempool)) (length all))
                     "removing a pool transaction left ~D of ~D" (bl.mp:mempool-count mempool) (length all))))
    (when (consume-bool fdp)
      (bl.mp:mempool-trim-to-size mempool (consume-integral-in-range
                                           fdp 0 (* 2 (bl.mp:mempool-dynamic-usage mempool)))))
    (when (consume-bool fdp)
      ;; Expire(GetMockTime() - seconds): ours takes the time the window
      ;; ends at, not its start.
      (bl.mp:mempool-expire mempool (+ (- bl.ser:*mock-time* (consume-integral fdp :u32))
                                       (* bl.mp:*mempool-expiry-hours* 3600))))
    (check-mempool mempool :coins utxo-set :spend-height spend-height)))

(defun tx-pool-fuzz-corpus (fdp)
  "Random bytes, most of them odd at a density drawn per buffer: a
FuzzedDataProvider reads a byte's low bit as a bool, so the loop runs, and a
new transaction takes a small number of inputs and outputs, far more often
than from uniform bytes."
  (let* ((n (consume-integral-in-range fdp 200 3000))
         (odd-per-8 (consume-integral-in-range fdp 4 7))
         (ctx (make-insecure-random-context (consume-integral fdp :u64)))
         (raw (insecure-rand-bytes ctx (* 2 n)))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n out)
      (let ((b (aref raw (* 2 i))) (r (aref raw (1+ (* 2 i)))))
        (setf (aref out i)
              (if (< (mod r 8) odd-per-8)
                  (logior 1 (mod b 4))
                  b))))))

(defun tx-pool-standard-tx (fdp rbf amount)
  "The transaction tx_pool_standard builds (tx_pool.cpp:246-295): TRUC or
version 2, final or a random locktime, 1..|RBF| inputs popped from RBF (and
put back) spending with the OP_TRUE witness, and 1..2|RBF| equal P2WSH outputs
paying the inputs less a fee in -1000..inputs, the first maybe a P2PK for its
sigops."
  (let* ((version (if (consume-bool fdp) bl.mp:+truc-version+ 2))
         (lock-time (if (consume-bool fdp) 0 (consume-integral fdp :u32)))
         (num-in (consume-integral-in-range fdp 1 (hash-table-count rbf) 32))
         (num-out (consume-integral-in-range fdp 1 (* 2 (hash-table-count rbf)) 32))
         (amount-in 0) (inputs '()) (stacks '()) (outputs '()))
    (dotimes (i num-in)
      (declare (ignorable i))
      (let ((op (outpoint-set-pop fdp rbf)))
        (incf amount-in (funcall amount op))
        (push (cons op (consume-sequence fdp)) inputs)
        (push (list (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51)) stacks)))
    (let* ((add-sigops (consume-bool fdp))
           (fee (consume-integral-in-range fdp -1000 amount-in))
           (amount-out (truncate (- amount-in fee) num-out)))
      (dotimes (i num-out)
        (push (cons amount-out (if (and (zerop i) add-sigops) +tx-pool-fuzz-p2pk-sigops+ +p2wsh-op-true+))
              outputs)))
    (dolist (in inputs) (fuzz-assert (outpoint-set-insert rbf (car in))))
    (fuzz-tx-with-witness version lock-time (nreverse inputs) (nreverse stacks) (nreverse outputs))))

(defun tx-pool-standard-books (removed added supply rbf)
  "Core's outpoint bookkeeping after a submission (tx_pool.cpp:352-394):
the outputs of what left the pool no longer exist and its inputs count again;
the outputs of what entered are spendable and its inputs no longer count."
  (let ((consumed-erased '()) (consumed-supply '()))
    (dolist (tx removed)
      (loop for n below (length (bl.ser:transaction-outputs tx))
            do (push (cons (bl.ser:transaction-hash tx) n) consumed-erased))
      (loop for in across (bl.ser:transaction-inputs tx)
            for op = (bl.ser:tx-in-previous-output in)
            do (fuzz-assert (outpoint-set-insert supply (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op)))
                            "a removed transaction's input was still counted")))
    (dolist (tx added)
      (loop for n below (length (bl.ser:transaction-outputs tx))
            for op = (cons (bl.ser:transaction-hash tx) n)
            do (fuzz-assert (outpoint-set-insert supply op) "an added output already counted")
               (fuzz-assert (outpoint-set-insert rbf op) "an added output already spendable"))
      (loop for in across (bl.ser:transaction-inputs tx)
            for op = (bl.ser:tx-in-previous-output in)
            do (push (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op)) consumed-supply)))
    (dolist (op consumed-erased)
      (fuzz-assert (outpoint-set-erase supply op) "a removed output was not counted")
      (fuzz-assert (outpoint-set-erase rbf op) "a removed output was not spendable"))
    (dolist (op consumed-supply)
      (fuzz-assert (outpoint-set-erase supply op) "an added transaction spent an uncounted output"))))

(define-fuzz-target tx-pool-standard
    (buffer :core "tx_pool.cpp:214-397" :iterations 750 :max-len 3000
            :corpus (lambda (fdp) (tx-pool-fuzz-corpus fdp)))
  "Standard spends of the pool's own outputs keep the books: pool fees plus
spendable value are always the 5000 BTC of the mature coinbases, a
transaction is accepted exactly when the pool announces it (alone, and
present by txid and wtxid), a single-transaction package test gives a
per-transaction verdict, the TRUC topology holds, and the pool passes
CTxMemPool::check before and after a block is mined from it."
  (with-network (:regtest)
    (let ((fdp (make-fuzzed-data-provider buffer))
          (bl.ser:*mock-time* nil)
          (bl.mp:*block-policy-estimator* nil))
      (multiple-value-bind (chain-state utxo-set mature) (tx-pool-fuzz-setup +p2wsh-op-true+)
        (fuzz-mock-time fdp chain-state)
        (let ((supply (make-outpoint-set mature))
              (rbf (make-outpoint-set mature)))
          (multiple-value-bind (mempool expiry require-standard) (tx-pool-fuzz-make-mempool fdp)
            (let ((bl.val:*require-standard* require-standard)
                  (bl.mp:*mempool-expiry-hours* expiry))
              (flet ((amount (op)
                       ;; CCoinsViewMemPool::GetCoin: a pool transaction's
                       ;; output, else the chain's coin.
                       (let ((e (bl.mp:mempool-get mempool (car op))))
                         (if e
                             (bl.ser:tx-out-value (aref (bl.ser:transaction-outputs
                                                         (bl.mp:mempool-entry-transaction e))
                                                        (cdr op)))
                             (bl.store:utxo-entry-value (bl.store:get-utxo utxo-set (car op) (cdr op)))))))
                (limited-while ((consume-bool fdp) 100)
                  (let ((supply-now 0))
                    (bl.mp:mempool-for-each mempool (lambda (txid e) (declare (ignore txid))
                                                      (incf supply-now (bl.mp:mempool-entry-fee e))))
                    (maphash (lambda (op v) (declare (ignore v)) (incf supply-now (amount op))) supply)
                    (fuzz-assert (= (fuzz-sabotage supply-now) (* 100 50 +fuzz-coin+))
                                 "pool fees plus spendable outputs are ~D" supply-now))
                  (fuzz-assert (plusp (hash-table-count supply)))
                  (let* ((tx (tx-pool-standard-tx fdp rbf #'amount))
                         (txid (bl.ser:transaction-hash tx)))
                    (when (consume-bool fdp) (fuzz-mock-time fdp chain-state))
                    (when (consume-bool fdp) (fuzz-restart-rolling-fee mempool))
                    (when (consume-bool fdp)
                      (tx-pool-fuzz-prioritise fdp mempool (if (consume-bool fdp)
                                                               txid
                                                               (car (outpoint-set-nth
                                                                     rbf (consume-integral-in-range
                                                                          fdp 0 (1- (hash-table-count rbf))))))))
                    (let ((*fuzz-mempool-delta* (cons '() '()))
                          (removed-txs (make-hash-table :test 'equalp)))
                      ;; ProcessNewPackage({tx}, test_accept): a verdict for
                      ;; the transaction unless the package itself was refused.
                      (multiple-value-bind (package-error results)
                          (bl.val:test-package-acceptance (list tx) utxo-set mempool chain-state)
                        (unless package-error
                          (let ((r (find (bl.ser:transaction-wtxid tx) results
                                         :key #'bl.val:package-tx-result-wtxid :test #'equalp)))
                            (fuzz-assert (and r (member (bl.val:package-tx-result-status r) '(:valid :invalid)))
                                         "a one-transaction package test answered ~S"
                                         (and r (bl.val:package-tx-result-status r))))))
                      ;; What the pool held before, to find what the removal
                      ;; signals are about.
                      (bl.mp:mempool-for-each mempool (lambda (id e)
                                                        (setf (gethash id removed-txs)
                                                              (bl.mp:mempool-entry-transaction e))))
                      (let* ((accepted (fuzz-atmp tx utxo-set mempool chain-state))
                             (added (mapcar #'car (car *fuzz-mempool-delta*)))
                             (removed (remove txid (mapcar #'car (cdr *fuzz-mempool-delta*))
                                              :test #'equalp)))
                        (when accepted
                          (fuzz-assert (and (bl.mp:mempool-has mempool txid)
                                            (gethash (bl.ser:transaction-wtxid tx) (bl.mp:mempool-by-wtxid mempool)))
                                       "an accepted transaction is not in the pool by txid and wtxid"))
                        (fuzz-assert (eq (not (fuzz-sabotage accepted)) (null added))
                                     "accepted ~S, but the pool announced ~D additions" accepted (length added))
                        (when accepted
                          (fuzz-assert (and (= 1 (length added)) (equalp (first added) txid))
                                       "the pool announced ~D additions for one transaction" (length added))
                          (check-mempool-truc-invariants mempool))
                        (tx-pool-standard-books
                         (mapcar (lambda (id) (gethash id removed-txs)) removed)
                         (and accepted (list tx))
                         supply rbf))))))
              (tx-pool-fuzz-finish fdp mempool utxo-set chain-state))))))))

(defun tx-pool-fuzz-record-mempool (tail fdp)
  "Record TX-POOL-FUZZ-MAKE-MEMPOOL's reads: roomy limits most of the time."
  (fdp-tail-integral tail (consume-integral-in-range fdp 2 64) 1 64 32)
  (fdp-tail-integral tail (consume-integral-in-range fdp 10 250) 1 250 32)
  (fdp-tail-integral tail (consume-integral-in-range fdp 1 200) 0 200 32)
  (fdp-tail-integral tail (consume-integral-in-range fdp 0 999) 0 999 32)
  (fdp-tail-bool tail (consume-bool fdp)))

(defun tx-pool-fuzz-record-mock-time (tail fdp)
  (let ((mtp (bl.val:compute-median-time-past (tx-pool-fuzz-chain)
                                              (bl.store:best-block-hash (tx-pool-fuzz-chain)))))
    (fdp-tail-integral tail (+ mtp 1 (consume-integral-in-range fdp 0 100000))
                       (1+ mtp) (1- (ash 1 32)) 32)))

(defun tx-pool-fuzz-structured-corpus (fdp)
  "A buffer whose END is a sequence of ConsumeTransaction draws that make
spends: P2WSH OP_TRUE transactions of version 2 (now and then TRUC),
final, each spending one or two outputs of a mature coinbase or of an
earlier draw -- sometimes one already spent -- at a small fee. The front is
random, for the four made-up txids and whatever Finish reads."
  (let ((tail (make-fdp-tail))
        (outputs (loop for i below 100 collect (list i 0 (* 50 +fuzz-coin+))))
        (len 108)
        (rounds (consume-integral-in-range fdp 1 60)))
    (tx-pool-fuzz-record-mock-time tail fdp)
    (tx-pool-fuzz-record-mempool tail fdp)
    (dotimes (r rounds)
      (declare (ignorable r))
      (fdp-tail-bool tail t)                         ; the loop goes on
      (fdp-tail-bool tail t)                         ; P2WSH OP_TRUE
      (if (plusp (consume-integral-in-range fdp 0 5))
          (fdp-tail-bool tail t)                     ; version 2
          (progn (fdp-tail-bool tail nil)
                 (fdp-tail-integral tail bl.mp:+truc-version+ 0 #xffffffff 32)))
      (fdp-tail-integral tail 0 0 #xffffffff 32)     ; nLockTime
      (let* ((num-in (min (length outputs) (consume-integral-in-range fdp 1 2)))
             (num-out (consume-integral-in-range fdp 1 3))
             (spent (loop repeat num-in
                          collect (let ((o (nth (consume-integral-in-range fdp 0 (1- (length outputs))) outputs)))
                                    ;; Mostly a fresh output; now and then a
                                    ;; double spend, which is a replacement.
                                    (when (plusp (consume-integral-in-range fdp 0 4))
                                      (setf outputs (remove o outputs)))
                                    o)))
             (in-value (reduce #'+ (mapcar #'third spent)))
             (fee (consume-integral-in-range fdp 150 100000))
             (each (min (* 50 +fuzz-coin+) (max 0 (floor (- in-value fee) num-out)))))
        (fdp-tail-integral tail num-in 0 10 32)
        (fdp-tail-integral tail num-out 0 10 32)
        (dolist (o spent)
          (fdp-tail-integral tail (first o) 0 (1- len) 32)
          (fdp-tail-integral tail (second o) 0 10 32)
          (fdp-tail-bool tail t)
          (fdp-tail-integral tail (consume-integral-in-range fdp 0 2) 0 2 32))
        (dotimes (i num-out)
          (fdp-tail-integral tail each -10 (+ (* 50 +fuzz-coin+) 10)))
        (fdp-tail-bool tail nil)                     ; no new mock time
        (fdp-tail-bool tail (zerop (consume-integral-in-range fdp 0 7)))
        (fdp-tail-bool tail nil)                     ; no prioritisation
        (fdp-tail-bool tail (zerop (consume-integral-in-range fdp 0 9))) ; bypass_limits
        ;; Assume it was accepted: its outputs are the next draws' coins.
        (dotimes (i num-out) (push (list len i each) outputs))
        (incf len)))
    (fdp-tail-bool tail nil)                         ; the loop ends
    (concatenate '(simple-array (unsigned-byte 8) (*))
                 (insecure-rand-bytes (make-insecure-random-context (consume-integral fdp :u64)) 200)
                 (fdp-tail-bytes tail))))

(define-fuzz-target tx-pool
    (buffer :core "tx_pool.cpp:399-464" :iterations 750 :max-len 3000
            :corpus (lambda (fdp) (tx-pool-fuzz-structured-corpus fdp)))
  "Arbitrary transactions over the mature coinbases, four immature ones and
four that do not exist: the pool never crashes, keeps the TRUC topology while
no acceptance bypassed the limits, and passes CTxMemPool::check before and
after a block is mined from it."
  (with-network (:regtest)
    (let ((fdp (make-fuzzed-data-provider buffer))
          (bl.ser:*mock-time* nil)
          (bl.mp:*block-policy-estimator* nil))
      (multiple-value-bind (chain-state utxo-set mature immature) (tx-pool-fuzz-setup +p2wsh-op-true+)
        (fuzz-mock-time fdp chain-state)
        (let ((txids (make-array 0 :adjustable t :fill-pointer 0))
              (ever-bypassed nil))
          (dolist (op mature) (vector-push-extend (car op) txids))
          (dotimes (i 4)
            (vector-push-extend (car (nth i immature)) txids)
            (vector-push-extend (consume-uint256 fdp) txids))
          (multiple-value-bind (mempool expiry require-standard) (tx-pool-fuzz-make-mempool fdp)
            (let ((bl.val:*require-standard* require-standard)
                  (bl.mp:*mempool-expiry-hours* expiry))
              (limited-while ((consume-bool fdp) 300)
                (let* ((tx (consume-transaction fdp :prevout-txids txids))
                       (txid (bl.ser:transaction-hash tx)))
                  (when (consume-bool fdp) (fuzz-mock-time fdp chain-state))
                  (when (consume-bool fdp) (fuzz-restart-rolling-fee mempool))
                  (when (consume-bool fdp)
                    (tx-pool-fuzz-prioritise fdp mempool (if (consume-bool fdp)
                                                             txid
                                                             (pick-value-in-array fdp txids))))
                  (let ((bypass (consume-bool fdp)))
                    (setf ever-bypassed (or ever-bypassed bypass))
                    (when (fuzz-atmp tx utxo-set mempool chain-state :bypass-limits bypass)
                      (vector-push-extend txid txids)
                      (unless ever-bypassed
                        (check-mempool-truc-invariants mempool))))))
              (tx-pool-fuzz-finish fdp mempool utxo-set chain-state))))))))

;;;; What the fuzz target found, pinned: Core's LimitMempoolSize (Expire, then
;;;; TrimToSize) runs BEFORE a single transaction is announced, and the
;;;; announcement takes the NEXT sequence (validation.cpp:1392-1415).

(defun %tx-pool-test-entry-tx (input-id)
  (make-mempool-test-tx :input-id input-id :value 1000))

(defmacro %with-tx-pool-test-delta ((delta) &body body)
  `(let* ((,delta (cons '() '()))
          (*fuzz-mempool-delta* ,delta)
          (bl.mp:*block-policy-estimator* nil))
     ,@body))

(test an-admission-its-own-limit-evicts-is-never-announced
  "Core announces a single transaction (TransactionAddedToMempool) only after
LimitMempoolSize, and only if it is still there (validation.cpp:1392-1415): a
child whose parent the expiry sweep removes -- and with it the child -- was
never in the pool as far as a subscriber can tell. Ours announced it first and
expired it after, a ZMQ `A' for a transaction that is not in the pool."
  (let* ((mempool (bl.mp:make-mempool))
         (parent (%tx-pool-test-entry-tx 71))
         (parent-txid (bl.ser:transaction-hash parent))
         (child (bl.ser:make-transaction
                 :version 1 :lock-time 0
                 :inputs (vector (bl.ser:make-tx-in
                                  :previous-output (bl.ser:make-outpoint :hash parent-txid :index 0)
                                  :script-sig (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51)
                                  :sequence #xffffffff))
                 :outputs (vector (bl.ser:make-tx-out :value 500 :script-pubkey
                                                      (bl.ser:tx-out-script-pubkey
                                                       (aref (bl.ser:transaction-outputs parent) 0))))))
         (child-txid (bl.ser:transaction-hash child))
         (t0 1700000000))
    (%with-tx-pool-test-delta (delta)
      (let ((bl.mp:*mempool-expiry-hours* 1))
        (let ((bl.ser:*mock-time* t0))
          (is (eq :ok (bl.mp:accept-validated-tx mempool parent-txid parent 1000 100))))
        (let ((bl.ser:*mock-time* (+ t0 7200)))
          (is (eq :mempool-full (bl.mp:accept-validated-tx mempool child-txid child 500 100))
              "the expiry took the parent, and the child with it")))
      (is (not (bl.mp:mempool-has mempool child-txid)))
      (is (null (find child-txid (car delta) :key #'car :test #'equalp))
          "the child was announced although it never stayed in the pool"))))

(test the-size-limit-expires-before-it-trims
  "Core LimitMempoolSize expires first and trims what is left
(validation.cpp:264-275). An old transaction the expiry removes anyway frees
the room a newcomer needs, so nothing is trimmed: a fresh low-feerate
transaction stays, and the rolling minimum is not bumped. Ours trimmed first,
evicting the fresh transaction as the worst chunk, and expired after."
  (let* ((old (%tx-pool-test-entry-tx 72))
         (low (%tx-pool-test-entry-tx 73))
         (new (%tx-pool-test-entry-tx 74))
         (t0 1700000000)
         (two-usage (let ((m (bl.mp:make-mempool)))
                      (bl.mp:accept-validated-tx m (bl.ser:transaction-hash low) low 100 100 :defer-trim t)
                      (bl.mp:accept-validated-tx m (bl.ser:transaction-hash new) new 90000 100 :defer-trim t)
                      (bl.mp:mempool-dynamic-usage m)))
         (mempool (bl.mp:make-mempool :max-size two-usage)))
    (%with-tx-pool-test-delta (delta)
      (let ((bl.mp:*mempool-expiry-hours* 2))
        (let ((bl.ser:*mock-time* t0))
          (is (eq :ok (bl.mp:accept-validated-tx mempool (bl.ser:transaction-hash old) old 90000 100))))
        (let ((bl.ser:*mock-time* (+ t0 3600)))
          (is (eq :ok (bl.mp:accept-validated-tx mempool (bl.ser:transaction-hash low) low 100 100))))
        (let ((bl.ser:*mock-time* (+ t0 7201)))
          (is (eq :ok (bl.mp:accept-validated-tx mempool (bl.ser:transaction-hash new) new 90000 100)))))
      (is (not (bl.mp:mempool-has mempool (bl.ser:transaction-hash old))) "the old transaction expired")
      (is-true (bl.mp:mempool-has mempool (bl.ser:transaction-hash low))
               "the expiry made the room: nothing had to be trimmed")
      (is (zerop (bl.mp:mempool-decayed-rolling-min-fee-rate mempool (+ t0 7201)))))))

(test an-announcement-takes-the-sequence-after-the-evictions-it-caused
  "Core's added signal draws GetAndIncrementSequence AFTER LimitMempoolSize
(validation.cpp:1415), so the transactions a newcomer's admission trimmed
out are numbered before it in the ZMQ `sequence' stream, each number once.
Ours stamped the newcomer's number first and handed the announcement the
last eviction's number again."
  (let* ((low (%tx-pool-test-entry-tx 75))
         (new (%tx-pool-test-entry-tx 76))
         (one-usage (let ((m (bl.mp:make-mempool)))
                      (bl.mp:accept-validated-tx m (bl.ser:transaction-hash new) new 90000 100 :defer-trim t)
                      (bl.mp:mempool-dynamic-usage m)))
         (mempool (bl.mp:make-mempool :max-size one-usage)))
    (%with-tx-pool-test-delta (delta)
      (is (eq :ok (bl.mp:accept-validated-tx mempool (bl.ser:transaction-hash low) low 100 100)))
      (is (eq :ok (bl.mp:accept-validated-tx mempool (bl.ser:transaction-hash new) new 90000 100)))
      (is (not (bl.mp:mempool-has mempool (bl.ser:transaction-hash low))) "the newcomer trimmed the low one")
      (let ((evicted (find (bl.ser:transaction-hash low) (cdr delta) :key #'car :test #'equalp))
            (announced (find (bl.ser:transaction-hash new) (car delta) :key #'car :test #'equalp)))
        (is-true (and evicted announced))
        (is (< (second evicted) (second announced))
            "eviction numbered ~A, the announcement ~A" (second evicted) (second announced))))))
