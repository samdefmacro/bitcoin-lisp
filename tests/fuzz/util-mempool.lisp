(in-package #:bitcoin-lisp.tests)

;;;; Core's mempool-side fuzz helpers at the pin (d3056bc149):
;;;; src/test/fuzz/util/mempool.cpp (ConsumeTxMemPoolEntry),
;;;; src/test/util/txmempool.cpp (TryAddToMempool) and CTxMemPool::check
;;;; (src/txmempool.cpp:433-553, BL.MP:MEMPOOL-CHECK-NOW), the consistency
;;;; check Core's -checkmempool runs and its mempool fuzz targets call after
;;;; every change. Used by the
;;;; rbf, tx_pool and package_eval ports.

(defun consume-tx-mempool-entry (fdp tx max-height)
  "Core ConsumeTxMemPoolEntry (test/fuzz/util/mempool.cpp:17-31), as a plist:
a fee in the money range below int64 max / 100,000, an entry time, a
sequence, a height in 0..MAX-HEIGHT, a spends-coinbase flag, a sigop cost up
to MAX_BLOCK_SIGOPS_COST -- and the sigop-adjusted vsize they make (Core
GetTxSize)."
  (let* ((fee (consume-money fdp (floor (1- (ash 1 63)) 100000)))
         (time (consume-integral fdp :i64))
         (sequence (consume-integral fdp :u64))
         (height (consume-integral-in-range fdp 0 max-height 32))
         (spends-coinbase (consume-bool fdp))
         (sigops (consume-integral-in-range fdp 0 bl.val:+max-block-sigops-cost+ 32)))
    (list :tx tx :fee fee :time time :sequence sequence :height height
          :spends-coinbase spends-coinbase :sigops sigops
          :vsize (bl.mp:sigop-adjusted-vsize (bl.ser:transaction-weight tx) sigops))))

(defun fdp-tail-mempool-entry (tail fdp &key (max-height 0) (max-sigops 300) (max-fee 1000000))
  "Record, for a corpus, the values CONSUME-TX-MEMPOOL-ENTRY reads, drawn from
FDP: a fee up to MAX-FEE and a sigop cost up to MAX-SIGOPS -- small, so the
entry fits the cluster limits -- and any time, sequence, height and flag."
  (fdp-tail-integral tail (consume-integral-in-range fdp 0 max-fee)
                     0 (floor (1- (ash 1 63)) 100000))
  (fdp-tail-integral tail (consume-integral fdp :i64) (- (ash 1 63)) (1- (ash 1 63)))
  (fdp-tail-integral tail (consume-integral fdp :u64) 0 (1- (ash 1 64)))
  (fdp-tail-integral tail (consume-integral-in-range fdp 0 max-height 32) 0 max-height 32)
  (fdp-tail-bool tail (consume-bool fdp))
  (fdp-tail-integral tail (consume-integral-in-range fdp 0 max-sigops 32)
                     0 bl.val:+max-block-sigops-cost+ 32))

(defun fuzz-mempool-entry (entry-plist)
  "A BL.MP mempool entry for CONSUME-TX-MEMPOOL-ENTRY's plist. The entry time
is kept non-negative (our slot is unsigned; Core's is an int64 of seconds)."
  (bl.mp:make-entry-from-tx (getf entry-plist :tx) (getf entry-plist :fee)
                            (getf entry-plist :height)
                            :sigops (getf entry-plist :sigops)
                            :entry-time (ldb (byte 63 0) (getf entry-plist :time))))

(defun try-add-to-mempool (mempool entry)
  "Core TryAddToMempool (test/util/txmempool.cpp): stage the entry and apply
it only if the cluster limits hold -- MEMPOOL-ADD, which refuses the same
over-limit cluster (and, unlike Core's test helper, a conflicting spend).
Returns MEMPOOL-ADD's keyword."
  (bl.mp:mempool-add mempool (bl.ser:transaction-hash (bl.mp:mempool-entry-transaction entry)) entry))

(defun mempool-entries-in-mining-order (mempool)
  "The pool's entries sorted by the mining order (Core
GetSortedScoreWithTopology), as (txid . entry)."
  (let ((all '()))
    (bl.mp:mempool-for-each mempool (lambda (txid e) (push (cons txid e) all)))
    (sort all (lambda (a b) (minusp (bl.mp:mempool-compare-mining-order mempool (car a) (car b)))))))

(defun check-mempool (mempool &key coins (spend-height 0))
  "Core CTxMemPool::check -- BL.MP:MEMPOOL-CHECK-NOW, which the node runs on
-checkmempool -- as a fuzz assertion. COINS is the chain's coin view (NIL:
the pool's own outputs only, for a pool planted without validation), spent
at SPEND-HEIGHT with Core's coinbase maturity."
  (let ((failure (handler-case
                     (progn (bl.mp:mempool-check-now mempool coins spend-height
                                                     :coinbase-maturity (and coins bl.val:+coinbase-maturity+))
                            nil)
                   (bl.mp:mempool-check-failed (c) (princ-to-string c)))))
    (fuzz-assert (fuzz-sabotage (null failure)) "~A" failure)))

;;;; The node Core's tx_pool and package_eval targets run against
;;;; (initialize_tx_pool, tx_pool.cpp:43-60 / package_eval.cpp:42-58): a
;;;; regtest chain of 200 blocks over genesis whose coinbases each pay 50 BTC
;;;; to one script, the first 100 of them mature at the next height.

(defconstant +fuzz-coin+ 100000000)

(defvar *tx-pool-fuzz-chain* nil
  "The 201-entry chain every run shares: nothing in a target writes to it.")

(defun tx-pool-fuzz-chain ()
  (or *tx-pool-fuzz-chain*
      ;; Core's chain starts at regtest genesis time, so a locktime below it
      ;; is final by time as well as by height.
      (setf *tx-pool-fuzz-chain*
            (values (make-versionbits-chain-with-tip 201 :base-time 1296688602)))))

(defun tx-pool-fuzz-coinbase-txid (height)
  (let ((b (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref b i) (ldb (byte 8 (* 8 i)) height)))
    (bl.crypto:sha256 b)))

(defun tx-pool-fuzz-setup (script-pubkey)
  "(values chain-state utxo-set mature immature): a fresh coin set over the
shared chain, one 50 BTC coinbase coin paying SCRIPT-PUBKEY per block 1..200;
MATURE and IMMATURE are their outpoints as (txid . index), heights 1..100 and
101..200 as Core splits them."
  (let ((utxo-set (bl.store:make-utxo-set))
        (mature '()) (immature '()))
    (loop for height from 1 to 200
          for txid = (tx-pool-fuzz-coinbase-txid height)
          do (bl.store:add-utxo utxo-set txid 0 (* 50 +fuzz-coin+) script-pubkey height :coinbase t)
             (if (<= height 100)
                 (push (cons txid 0) mature)
                 (push (cons txid 0) immature)))
    (values (tx-pool-fuzz-chain) utxo-set (nreverse mature) (nreverse immature))))

(defun fuzz-mock-time (fdp chain-state)
  "Core MockTime (tx_pool.cpp:139-145): a mock time from the tip's
median-time-past + 1 to the largest nTime."
  (let ((mtp (bl.val:compute-median-time-past chain-state (bl.store:best-block-hash chain-state))))
    (setf bl.ser:*mock-time* (consume-integral-in-range fdp (1+ mtp) (1- (ash 1 32))))))

(defun fuzz-atmp (tx utxo-set mempool chain-state &key bypass-limits test-accept)
  "Core AcceptToMemoryPool for one transaction: PreChecks through the script
checks, then -- unless TEST-ACCEPT -- the submission, the size limit and the
added signal. Returns (values accepted-p reason fee vsize), REASON a
rejection keyword (or ACCEPT-VALIDATED-TX's when the submission itself
failed)."
  (let ((height (bl.store:current-height chain-state))
        (txid (bl.ser:transaction-hash tx)))
    (multiple-value-bind (valid err fee replaced sigops)
        (bl.val:validate-transaction-for-mempool tx utxo-set mempool height
                                                 :chain-state chain-state
                                                 :bypass-limits bypass-limits)
      (cond ((not valid) (values nil err))
            (test-accept (values t nil fee))
            (t (multiple-value-bind (result entry)
                   (bl.mp:accept-validated-tx mempool txid tx fee height
                                              :sigops sigops :replaced replaced
                                              :bypass-limits bypass-limits)
                 (if (eq result :ok)
                     (values t nil fee (bl.mp:mempool-entry-vsize entry))
                     (values nil result))))))))

(defvar *fuzz-mempool-delta* nil
  "While a cons (ADDED . REMOVED), the mempool's added and removed signals
push (txid sequence tx) onto its side -- Core's TransactionsDelta
(tx_pool.cpp:62-80). NIL (the default) records nothing.")

(bl.vi:define-validation-hook :transaction-added fuzz-mempool-note-added (tx txid sequence)
  (when *fuzz-mempool-delta*
    (push (list txid sequence tx) (car *fuzz-mempool-delta*))))

(bl.vi:define-validation-hook :transaction-removed fuzz-mempool-note-removed (tx txid sequence reason)
  (declare (ignore reason))
  (when *fuzz-mempool-delta*
    (push (list txid sequence tx) (cdr *fuzz-mempool-delta*))))

(defun %mempool-set-vsize (mempool txids)
  (let ((sum 0))
    (maphash (lambda (txid v) (declare (ignore v))
               (incf sum (bl.mp:mempool-entry-vsize (bl.mp:mempool-get mempool txid))))
             txids)
    sum))

(defun check-mempool-truc-invariants (mempool)
  "Core CheckMempoolTRUCInvariants (test/util/txmempool.cpp:182-213): a TRUC
transaction keeps TRUC's size cap and its one-parent-one-child topology, a
TRUC child is small and spends only TRUC parents, and a non-TRUC transaction
spends no unconfirmed TRUC parent."
  (bl.mp:mempool-for-each
   mempool
   (lambda (txid e)
     (let* ((tx (bl.mp:mempool-entry-transaction e))
            (ancestors (bl.mp:mempool-ancestors mempool txid))
            (descendants (bl.mp:mempool-descendants mempool txid))
            (vsize (bl.mp:mempool-entry-vsize e))
            (anc-count (1+ (hash-table-count ancestors)))
            (desc-count (1+ (hash-table-count descendants)))
            (parents (loop for p being the hash-keys of (bl.mp:mempool-entry-parents e)
                           collect (bl.mp:mempool-entry-transaction (bl.mp:mempool-get mempool p)))))
       (if (= (bl.ser:transaction-version tx) bl.mp:+truc-version+)
           (progn
             (fuzz-assert (<= vsize bl.mp:+truc-max-vsize+) "a TRUC transaction of ~D vB" vsize)
             (fuzz-assert (<= (fuzz-sabotage desc-count) 2) ; TRUC_DESCENDANT_LIMIT
                          "a TRUC transaction with ~D descendants" desc-count)
             (fuzz-assert (<= anc-count bl.mp:+truc-ancestor-limit+))
             (fuzz-assert (<= (+ vsize (%mempool-set-vsize mempool descendants))
                              (+ bl.mp:+truc-max-vsize+ bl.mp:+truc-child-max-vsize+)))
             (fuzz-assert (<= (+ vsize (%mempool-set-vsize mempool ancestors))
                              (+ bl.mp:+truc-max-vsize+ bl.mp:+truc-child-max-vsize+)))
             (when (> anc-count 1)
               (fuzz-assert (<= vsize bl.mp:+truc-child-max-vsize+) "a TRUC child of ~D vB" vsize)
               (fuzz-assert (= (bl.ser:transaction-version (first parents)) bl.mp:+truc-version+)
                            "a TRUC child of a non-TRUC parent")))
           (when (> anc-count 1)
             (dolist (p parents)
               (fuzz-assert (/= (bl.ser:transaction-version p) bl.mp:+truc-version+)
                            "a non-TRUC child of a TRUC parent"))))))))

(defun fuzz-dust-indexes (tx)
  "Core GetDust: the indexes of TX's outputs that are dust at the dust relay feerate."
  (loop for o across (bl.ser:transaction-outputs tx)
        for i from 0
        when (bl.val:output-is-dust-p o) collect i))

(defun check-mempool-ephemeral-invariants (mempool)
  "Core CheckMempoolEphemeralInvariants (test/util/txmempool.cpp:145-180): a
pool transaction has at most one dust output, and one that has it pays no
fee, base or modified, and has at most one child -- which spends the dust."
  (bl.mp:mempool-for-each
   mempool
   (lambda (txid e)
     (let* ((tx (bl.mp:mempool-entry-transaction e))
            (dust (fuzz-dust-indexes tx)))
       (fuzz-assert (< (length dust) 2) "a pool transaction with ~D dust outputs" (length dust))
       (when dust
         (fuzz-assert (and (zerop (bl.mp:mempool-entry-fee e))
                           (zerop (fuzz-sabotage (bl.mp:mempool-entry-modified-fee e))))
                      "a dusty transaction pays ~D (modified ~D)"
                      (bl.mp:mempool-entry-fee e) (bl.mp:mempool-entry-modified-fee e))
         (let ((children (loop for c being the hash-keys of (bl.mp:mempool-entry-children e) collect c)))
           (fuzz-assert (< (length children) 2) "a dusty transaction with ~D children" (length children))
           (when children
             (fuzz-assert
              (some (lambda (in)
                      (let ((op (bl.ser:tx-in-previous-output in)))
                        (and (equalp (bl.ser:outpoint-hash op) txid)
                             (= (bl.ser:outpoint-index op) (first dust)))))
                    (bl.ser:transaction-inputs
                     (bl.mp:mempool-entry-transaction (bl.mp:mempool-get mempool (first children)))))
              "the only child of a dusty transaction leaves the dust unspent"))))))))

;;;; Core's std::set<COutPoint>, as an EQUALP table of (txid . index) -> T:
;;;; insertion-ordered, so every draw is deterministic.

(defun make-outpoint-set (&optional outpoints)
  (let ((set (make-hash-table :test 'equalp)))
    (dolist (op outpoints set) (setf (gethash op set) t))))

(defun outpoint-set-insert (set op)
  "Insert OP; true when it was not there (std::set::insert(...).second)."
  (unless (gethash op set)
    (setf (gethash op set) t)))

(defun outpoint-set-erase (set op)
  "Erase OP; true when it was there."
  (remhash op set))

(defun outpoint-set-nth (set k)
  (loop for op being the hash-keys of set
        for i from 0
        when (= i k) return op))

(defun outpoint-set-pop (fdp set)
  "Erase and return a member of SET picked by FDP (std::advance(begin(),
ConsumeIntegralInRange(0, size-1)))."
  (let ((op (outpoint-set-nth set (consume-integral-in-range fdp 0 (1- (hash-table-count set))))))
    (remhash op set)
    op))

(defun fuzz-restart-rolling-fee (mempool)
  "Core MockedTxPool::RollingFeeUpdate (tx_pool.cpp:35-40): the rolling
minimum's decay clock restarts now, as though a block had just connected."
  (setf (bl.mp:mempool-rolling-min-fee-time mempool) (bl.ser:get-unix-time)
        (bl.mp:mempool-block-since-rolling-fee-bump mempool) t))

(defun fuzz-tx-with-witness (version lock-time inputs stacks outputs)
  "A transaction from (txid . index) INPUTS as (outpoint . sequence) pairs,
their witness STACKS and (value . script) OUTPUTS."
  (bl.ser:make-transaction
   :version version :lock-time lock-time
   :inputs (map 'simple-vector
                (lambda (in)
                  (bl.ser:make-tx-in :previous-output (bl.ser:make-outpoint :hash (car (car in))
                                                                            :index (cdr (car in)))
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                     :sequence (cdr in)))
                inputs)
   :outputs (map 'simple-vector
                 (lambda (o) (bl.ser:make-tx-out :value (car o) :script-pubkey (cdr o)))
                 outputs)
   :witness (when (some #'identity stacks) (coerce stacks 'simple-vector))))
