(in-package #:bitcoin-lisp.tests)

(def-suite :block-policy-estimator-tests
  :description "Bitcoin Core CBlockPolicyEstimator port"
  :in :bitcoin-lisp-tests)

(in-suite :block-policy-estimator-tests)

(defun %bpe-stats (&key (periods 24) (decay 0.9952d0) (scale 2))
  (bl.mp::make-tx-confirm-stats
   (bl.mp::make-fee-buckets) periods decay scale))

(test fee-buckets-match-core-spacing
  "Core's bucket set: geometric from MIN_BUCKET_FEERATE (100) to
MAX_BUCKET_FEERATE (1e7) at FEE_SPACING (1.05), then an INF catch-all. Bucket
lookup is lower_bound — the first bucket whose upper bound is >= the feerate."
  (let ((b (bl.mp::make-fee-buckets)))
    (is (= 100d0 (aref b 0)))
    (is (= 105d0 (aref b 1)))
    (is (= bl.mp::+inf-feerate+ (aref b (1- (length b)))))
    (is (<= (aref b (- (length b) 2)) bl.mp::+fee-max-bucket-feerate+))
    ;; lower_bound: a feerate AT a boundary belongs to that bucket, not the next.
    (is (= 0 (bl.mp::fee-bucket-index b 99d0)))
    (is (= 0 (bl.mp::fee-bucket-index b 100d0)))
    (is (= 1 (bl.mp::fee-bucket-index b 101d0)))
    ;; Anything above the top finite bucket lands in INF.
    (is (= (1- (length b)) (bl.mp::fee-bucket-index b 1d8)))))

(test estimator-reports-the-feerate-that-confirmed
  "A population that confirms within the target is reported back at its own
feerate."
  (let ((s (%bpe-stats)))
    (dotimes (i 100) (bl.mp::tx-confirm-stats-record s 1 10000d0))
    (is (= 10000d0 (bl.mp::tx-confirm-stats-estimate-median
                    s 1 0.1d0 0.85d0 100)))
    ;; A longer target is satisfied by the same data.
    (is (= 10000d0 (bl.mp::tx-confirm-stats-estimate-median
                    s 2 0.1d0 0.85d0 100)))))

(test estimator-will-not-recommend-a-feerate-that-fails
  "THE property a block-percentile heuristic cannot express. Two populations:
expensive transactions that confirm, and cheap ones that do not. The estimate
must stay at the expensive feerate when the cheap ones FAILED, and drop to the
cheap one when they confirmed — same volumes, same buckets, opposite outcomes."
  (let ((failed (%bpe-stats))
        (confirmed (%bpe-stats)))
    ;; Both: 100 expensive transactions confirm in one block.
    (dotimes (i 100)
      (bl.mp::tx-confirm-stats-record failed 1 10000d0)
      (bl.mp::tx-confirm-stats-record confirmed 1 10000d0))
    ;; FAILED: 100 cheap ones enter and are evicted unconfirmed 30 blocks later.
    (dotimes (i 100)
      (let ((b (bl.mp::tx-confirm-stats-new-tx failed 100 500d0)))
        (bl.mp::tx-confirm-stats-remove-tx failed 100 130 b nil)))
    ;; CONFIRMED: the same 100 cheap ones confirm in one block.
    (dotimes (i 100)
      (bl.mp::tx-confirm-stats-record confirmed 1 500d0))
    (is (= 10000d0 (bl.mp::tx-confirm-stats-estimate-median
                    failed 1 0.1d0 0.85d0 130))
        "a feerate that did not confirm must not be recommended")
    (is (= 500d0 (bl.mp::tx-confirm-stats-estimate-median
                  confirmed 1 0.1d0 0.85d0 130))
        "the cheapest feerate that DID confirm is the answer")))

(test estimator-returns-minus-one-without-enough-data
  "Below SUFFICIENT_FEETXS/(1-decay) transactions, no bucket range may answer:
-1, not a confident guess off two samples."
  (let ((s (%bpe-stats)))
    (is (= -1d0 (bl.mp::tx-confirm-stats-estimate-median
                 s 1 0.1d0 0.85d0 100)))
    (dotimes (i 3) (bl.mp::tx-confirm-stats-record s 1 10000d0))
    (is (= -1d0 (bl.mp::tx-confirm-stats-estimate-median
                 s 1 0.1d0 0.85d0 100)))))

(test estimator-decay-fades-old-history
  "UpdateMovingAverages decays every counter, so history fades continuously
instead of falling off a hard window edge."
  (let ((s (%bpe-stats :decay 0.5d0)))
    (dotimes (i 100) (bl.mp::tx-confirm-stats-record s 1 10000d0))
    (let ((bucket (bl.mp::fee-bucket-index
                   (bl.mp::make-fee-buckets) 10000d0)))
      (let ((before (aref (bl.mp::tx-confirm-stats-txct-avg s) bucket)))
        (bl.mp::tx-confirm-stats-update-moving-averages s)
        (is (= (/ before 2)
               (aref (bl.mp::tx-confirm-stats-txct-avg s) bucket)))))))

(test estimator-confirmation-is-not-a-failure
  "removeTx's IN-BLOCK flag is the difference between 'confirmed' and 'gave up'.
Only the latter records a failure — counting confirmations as failures would
push every estimate upward without bound."
  (let ((s (%bpe-stats))
        (bucket (bl.mp::fee-bucket-index
                 (bl.mp::make-fee-buckets) 500d0)))
    ;; Confirmed after 30 blocks: no failure recorded.
    (let ((b (bl.mp::tx-confirm-stats-new-tx s 100 500d0)))
      (bl.mp::tx-confirm-stats-remove-tx s 100 130 b t))
    (is (= 0d0 (aref (aref (bl.mp::tx-confirm-stats-fail-avg s) 0) bucket)))
    ;; Evicted after 30 blocks: failure recorded.
    (let ((b (bl.mp::tx-confirm-stats-new-tx s 100 500d0)))
      (bl.mp::tx-confirm-stats-remove-tx s 100 130 b nil))
    (is (plusp (aref (aref (bl.mp::tx-confirm-stats-fail-avg s) 0) bucket)))))

(test estimator-clear-current-ages-unconfirmed-into-the-old-bucket
  "ClearCurrent rolls the circular buffer: whatever still sits in a slot when it
comes round again has aged out of the window and moves to OLD-UNCONF-TXS, where
it still counts against success rates. Dropping it instead would make a bucket
nobody can confirm look perfect for lack of evidence."
  (let* ((s (%bpe-stats))
         (bucket (bl.mp::tx-confirm-stats-new-tx s 7 500d0)))
    (is (= 1 (aref (aref (bl.mp::tx-confirm-stats-unconf-txs s)
                         (mod 7 (length (bl.mp::tx-confirm-stats-unconf-txs s))))
                   bucket)))
    (is (= 0 (aref (bl.mp::tx-confirm-stats-old-unconf-txs s) bucket)))
    (bl.mp::tx-confirm-stats-clear-current s 7)
    (is (= 0 (aref (aref (bl.mp::tx-confirm-stats-unconf-txs s)
                         (mod 7 (length (bl.mp::tx-confirm-stats-unconf-txs s))))
                   bucket)))
    (is (= 1 (aref (bl.mp::tx-confirm-stats-old-unconf-txs s) bucket)))))

;;;; --- The three-horizon estimator ---

(defun %bpe-id (a b c)
  "A distinct 32-byte txid from three small integers."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref v 0) a
          (aref v 1) (ldb (byte 8 0) b)
          (aref v 2) (ldb (byte 8 8) b)
          (aref v 3) (ldb (byte 8 0) c))
    v))

(defun %bpe-simulate (&key (blocks 60) (per-block 40)
                        (fast-feerate 20000d0) (slow-feerate 800d0)
                        confirm-slow)
  "Run BLOCKS blocks. Each block, PER-BLOCK transactions at FAST-FEERATE enter
and confirm in the next block, and PER-BLOCK at SLOW-FEERATE enter. CONFIRM-SLOW
decides whether the cheap ones also confirm or sit unconfirmed forever."
  (let ((e (bl.mp::make-block-policy-estimator)))
    (loop for h from 1 to blocks
          do (let ((confirmed '()))
               (dotimes (i per-block)
                 (let ((txid (%bpe-id 1 h i)))
                   (bl.mp::bpe-process-transaction e txid h fast-feerate)
                   (push txid confirmed)))
               (dotimes (i per-block)
                 (let ((txid (%bpe-id 2 h i)))
                   (bl.mp::bpe-process-transaction e txid h slow-feerate)
                   (when confirm-slow
                     (push txid confirmed))))
               (bl.mp::bpe-process-block e (1+ h) confirmed)))
    e))

(test estimator-smart-fee-reports-the-confirming-feerate
  "End to end: sixty blocks in which 20000 sat/kvB confirms next-block and 800
never does. estimateSmartFee must report 20000 — the cheap population is
plentiful but useless, which is exactly the case a block-percentile heuristic
gets wrong."
  (let ((e (%bpe-simulate)))
    (is (= 61 (bl.mp::block-policy-estimator-best-height e)))
    (is (= 20000 (bl.mp::bpe-estimate-smart-fee e 2)))
    (is (= 20000 (bl.mp::bpe-estimate-smart-fee e 6)))
    (is (= 20000 (bl.mp::bpe-estimate-smart-fee e 6 :conservative t)))
    ;; The unconfirmed cheap transactions are still tracked, still counting
    ;; against their bucket's success rate.
    (is (plusp (hash-table-count
                (bl.mp::block-policy-estimator-tracked e))))))

(test estimator-smart-fee-drops-when-cheap-transactions-confirm
  "The control for the test above: identical volumes and buckets, the only
difference being that the cheap population CONFIRMS. The estimate must fall to
it — otherwise the previous test would pass on an estimator that simply always
returns the most expensive bucket."
  (let ((e (%bpe-simulate :confirm-slow t)))
    (is (= 800 (bl.mp::bpe-estimate-smart-fee e 6)))))

(test estimator-refuses-targets-it-cannot-support
  "Targets outside the tracked range, and a history too short to justify one,
both return 0 rather than a fabricated number."
  (let ((fresh (bl.mp::make-block-policy-estimator)))
    (is (= 0 (bl.mp::bpe-estimate-smart-fee fresh 0)))
    (is (= 0 (bl.mp::bpe-estimate-smart-fee fresh 6)))
    ;; Beyond the longest horizon.
    (is (= 0 (bl.mp::bpe-estimate-smart-fee fresh 100000))))
  ;; A short run cannot justify a distant target: MaxUsableEstimate halves the
  ;; observed block span. Ten simulated blocks record from height 2 (the first
  ;; block that confirmed anything) to height 11, a span of 9, so targets are
  ;; capped at 4.
  (let ((short-run (%bpe-simulate :blocks 10)))
    (is (= 2 (bl.mp::block-policy-estimator-first-recorded-height short-run)))
    (is (= 11 (bl.mp::block-policy-estimator-best-height short-run)))
    (is (= 4 (bl.mp::bpe-max-usable-estimate short-run))))
  ;; An estimator that has seen blocks but never counted a transaction has no
  ;; span at all — the clock starts on DATA, not on blocks.
  (let ((empty (bl.mp::make-block-policy-estimator)))
    (bl.mp::bpe-process-block empty 100 (list))
    (bl.mp::bpe-process-block empty 200 (list))
    (is (= 0 (bl.mp::block-policy-estimator-first-recorded-height empty)))
    (is (= 0 (bl.mp::bpe-max-usable-estimate empty)))))

(test estimator-a-confirmed-transaction-stops-being-tracked
  "processBlock must untrack what it confirms; otherwise every confirmed
transaction would go on counting as 'still in the mempool' against its own
bucket forever."
  (let ((e (bl.mp::make-block-policy-estimator))
        (txid (%bpe-id 9 9 9)))
    (bl.mp::bpe-process-transaction e txid 1 5000d0)
    (is (= 1 (hash-table-count
              (bl.mp::block-policy-estimator-tracked e))))
    (bl.mp::bpe-process-block e 2 (list txid))
    (is (= 0 (hash-table-count
              (bl.mp::block-policy-estimator-tracked e))))))

(test estimator-ignores-a-block-it-has-already-seen
  "A block at or below the best seen height must not be processed twice — the
decay step would run again and silently age all history by an extra block."
  (let ((e (%bpe-simulate :blocks 5)))
    (let ((height (bl.mp::block-policy-estimator-best-height e)))
      (is (= 0 (bl.mp::bpe-process-block e height '())))
      (is (= 0 (bl.mp::bpe-process-block e (1- height) '())))
      (is (= height (bl.mp::block-policy-estimator-best-height e))))))

;;;; --- The reporting seam must be CONNECTED ---
;;;;
;;;; The estimator being correct is worth nothing if the mempool and
;;;; connect-block never tell it anything. These drive the REAL code paths with
;;;; a live estimator bound, and require the data to arrive.

(test mempool-acceptance-reports-to-the-fee-estimator
  "accept-validated-tx must report the entry. Without this the estimator sees
no transactions at all and every estimate is 0 forever."
  (let* ((bl.mp:*block-policy-estimator*
           (bl.mp:make-block-policy-estimator))
         (est bl.mp:*block-policy-estimator*)
         (mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 120))
         (txid (bl.ser:transaction-hash tx)))
    (is (= 0 (hash-table-count
              (bl.mp::block-policy-estimator-tracked est))))
    (bl.mp:accept-validated-tx mempool txid tx 5000 200)
    (is (= 1 (hash-table-count
              (bl.mp::block-policy-estimator-tracked est)))
        "the mempool must report acceptances to the estimator")
    ;; It recorded the ENTRY HEIGHT, which is what a confirmation is measured
    ;; against.
    (is (= 200 (first (gethash txid (bl.mp::block-policy-estimator-tracked est)))))))

(test mempool-eviction-reports-a-failure-but-confirmation-does-not
  "A removal that is not a confirmation is a FAILURE at that feerate. A
confirmation must NOT be reported from the removal path: the block hook records
it and untracks in one step, so reporting here first would untrack it before
the confirmation was recorded — silently discarding the data point."
  (let* ((bl.mp:*block-policy-estimator*
           (bl.mp:make-block-policy-estimator))
         (est bl.mp:*block-policy-estimator*)
         (mempool (bl.mp:make-mempool))
         (tx (make-mempool-test-tx :input-id 121))
         (txid (bl.ser:transaction-hash tx))
         (tracked (bl.mp::block-policy-estimator-tracked est)))
    ;; Evicted for size: untracked, and a failure is recorded.
    (bl.mp:accept-validated-tx mempool txid tx 5000 200)
    (setf (bl.mp::block-policy-estimator-best-height est) 260)
    (let ((bl.mp::*mempool-removal-reason* :size-limit))
      (bl.mp::mempool-remove mempool txid))
    (is (= 0 (hash-table-count tracked)))
    ;; Removed BY A BLOCK: the removal path leaves it alone.
    (let ((tx2 (make-mempool-test-tx :input-id 122)))
      (let ((txid2 (bl.ser:transaction-hash tx2)))
        (bl.mp:accept-validated-tx mempool txid2 tx2 5000 200)
        (is (= 1 (hash-table-count tracked)))
        (let ((bl.mp::*mempool-removal-reason* :block))
          (bl.mp::mempool-remove mempool txid2))
        (is (= 1 (hash-table-count tracked))
            "a block removal must leave the estimator's tracking to the block hook")))))

(test connect-block-reports-confirmations-to-the-fee-estimator
  "connect-block must call the block hook, and it must run while the block's
transactions are still tracked. Drives the real connect-block."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "bpe-connect")
     (let* ((bl.mp:*block-policy-estimator*
              (bl.mp:make-block-policy-estimator))
            (est bl.mp:*block-policy-estimator*)
            (block1 (make-reorg-test-block genesis-hash
                                           (first (make-test-chain-hashes #xC0 1)) 1))
            (coinbase (first (bl.ser:bitcoin-block-transactions block1)))
            (cb-txid (bl.ser:transaction-hash coinbase)))
       ;; Pretend the coinbase was a tracked mempool transaction entered at
       ;; height 0, so the block at height 1 is a 1-block confirmation.
       (bl.mp::bpe-process-transaction est cb-txid 0 9000d0)
       (is (= 1 (hash-table-count
                 (bl.mp::block-policy-estimator-tracked est))))
       (bl.val:connect-block block1 chain-state block-store utxo-set)
       ;; The hook ran: best height moved and the transaction was untracked by
       ;; the confirmation, not merely dropped.
       (is (= 1 (bl.mp::block-policy-estimator-best-height est))
           "connect-block must report the block to the estimator")
       (is (= 0 (hash-table-count
                 (bl.mp::block-policy-estimator-tracked est)))))
     (clrhash bl.val::*block-undo-data*))))

;;;; --- Persistence ---

(defun %bpe-populated (&key (blocks 40))
  (%bpe-simulate :blocks blocks))

(defun %bpe-bytes (est)
  (flexi-streams:with-output-to-sequence (mem)
    (bl.mp::bpe-write-to-stream est mem)))

(defun %bpe-load-bytes (est bytes)
  (flexi-streams:with-input-from-sequence (in bytes)
    (bl.mp::bpe-read-into est in)))

(test estimator-survives-a-save-load-round-trip
  "Without persistence the estimator answers 0 for hours after every restart,
because MaxUsableEstimate has to re-accumulate a block span. The restored
estimator must give the same answer as the one that was saved."
  (let* ((original (%bpe-populated))
         (bytes (%bpe-bytes original))
         (restored (bl.mp::make-block-policy-estimator)))
    (is-true (%bpe-load-bytes restored bytes))
    (is (= (bl.mp::bpe-estimate-smart-fee original 6)
           (bl.mp::bpe-estimate-smart-fee restored 6)))
    (is (plusp (bl.mp::bpe-estimate-smart-fee restored 6))
        "the round trip must preserve an ANSWER, not agree on zero")
    (is (= (bl.mp::block-policy-estimator-best-height original)
           (bl.mp::block-policy-estimator-best-height restored)))
    ;; The unconfirmed tracking is per-run and deliberately not stored: the
    ;; mempool is reloaded and re-reported after a restart, so persisting it
    ;; would double-count.
    (is (= 0 (hash-table-count
              (bl.mp::block-policy-estimator-tracked restored))))))

(test estimator-discards-a-corrupt-file-rather-than-half-loading-it
  "The load discipline that matters: nothing is installed until every horizon
has parsed and every check has passed. A partially applied estimator would
answer confidently from nonsense, and fee estimates are spent money."
  (let* ((bytes (%bpe-bytes (%bpe-populated)))
         (truncated (subseq bytes 0 (floor (length bytes) 2)))
         (victim (%bpe-simulate :blocks 40 :fast-feerate 7000d0))
         (before (bl.mp::bpe-estimate-smart-fee victim 6)))
    (is (plusp before))
    ;; A truncated file is rejected...
    (is (null (%bpe-load-bytes victim truncated)))
    ;; ...and the estimator is exactly as it was.
    (is (= before (bl.mp::bpe-estimate-smart-fee victim 6))
        "a rejected file must leave the existing estimator untouched")
    ;; Garbage in the middle is rejected too.
    (let ((mangled (copy-seq bytes)))
      (loop for i from 40 below 200 do (setf (aref mangled i) #xFF))
      (is (null (%bpe-load-bytes victim mangled)))
      (is (= before (bl.mp::bpe-estimate-smart-fee victim 6))))))

(test estimator-rejects-a-file-written-for-a-different-bucket-set
  "Per-bucket counts only mean anything against the bucket set they were
recorded in. A file whose buckets differ must be DISCARDED, never remapped —
silently reinterpreting them would make every count mean something else."
  (let* ((bytes (%bpe-bytes (%bpe-populated)))
         (est (bl.mp::make-block-policy-estimator)))
    ;; The bucket vector starts after best-height + the two range words (12
    ;; bytes) and a 4-byte count; corrupt its first entry.
    (let ((mangled (copy-seq bytes)))
      (setf (aref mangled 16) (logxor (aref mangled 16) #x0F))
      (is (null (%bpe-load-bytes est mangled))))))

(test estimator-rejects-an-impossible-decay-or-scale
  "Core's TxConfirmStats::Read sanity checks: decay strictly inside (0,1) and a
non-zero scale. Both are load-bearing — a decay of 1 never forgets and a decay
of 0 forgets everything, and EstimateMedianVal divides by (1 - decay)."
  (let* ((est (%bpe-populated))
         (bytes (%bpe-bytes est))
         (target (bl.mp::make-block-policy-estimator))
         ;; The first horizon's decay sits right after the bucket vector.
         (offset (+ 4 4 4 4 (* 8 (length (bl.mp::make-fee-buckets))))))
    ;; decay = 1.0 exactly -> rejected
    (let ((mangled (copy-seq bytes)))
      (let ((one (flexi-streams:with-output-to-sequence (m)
                   (bl.mp::%write-double-le m 1d0))))
        (replace mangled one :start1 offset))
      (is (null (%bpe-load-bytes target mangled))))
    ;; decay = 0.0 -> rejected
    (let ((mangled (copy-seq bytes)))
      (let ((zero (flexi-streams:with-output-to-sequence (m)
                    (bl.mp::%write-double-le m 0d0))))
        (replace mangled zero :start1 offset))
      (is (null (%bpe-load-bytes target mangled))))
    ;; scale = 0 -> rejected
    (let ((mangled (copy-seq bytes)))
      (fill mangled 0 :start (+ offset 8) :end (+ offset 12))
      (is (null (%bpe-load-bytes target mangled))))))

;;;; --- The fee_estimates.dat file: the seam, and the staleness rule ---

(defconstant +unix-epoch-universal+ 2208988800
  "Universal time at the Unix epoch, for backdating a file with utime(2).")

(defun %backdate-file (path seconds)
  (let ((when (- (get-universal-time) +unix-epoch-universal+ seconds)))
    (sb-posix:utime (namestring path) when when)))

(defun %fee-stats-fixture (name)
  (let ((dir (ensure-directories-exist
              (merge-pathnames (format nil "test-feeest-~A/" name)
                               (uiop:temporary-directory)))))
    (let ((p (merge-pathnames "fee_estimates.dat" dir)))
      (when (probe-file p) (delete-file p)))
    dir))

(test fee-estimates-file-carries-the-policy-estimator
  "The seam: save-fee-stats and load-fee-stats must actually carry the Core
estimator's state. Writing a perfect serializer that the file path never calls
would leave every restart back at zero — and the estimator would look fine in
its own unit tests."
  (let* ((dir (%fee-stats-fixture "seam"))
         (legacy (bl.mp:make-fee-estimator :data-directory dir)))
    (let ((bl.mp:*block-policy-estimator* (%bpe-populated)))
      (let ((expected (bl.mp::bpe-estimate-smart-fee
                       bl.mp:*block-policy-estimator* 6)))
        (is (plusp expected))
        (bl.mp:save-fee-stats legacy)
        ;; A fresh process: new estimator, new legacy history.
        (let ((bl.mp:*block-policy-estimator*
                (bl.mp::make-block-policy-estimator))
              (legacy2 (bl.mp:make-fee-estimator :data-directory dir)))
          (is (= 0 (bl.mp::bpe-estimate-smart-fee
                    bl.mp:*block-policy-estimator* 6))
              "a fresh estimator answers 0 before loading")
          (is-true (bl.mp:load-fee-stats legacy2))
          (is (= expected (bl.mp::bpe-estimate-smart-fee
                           bl.mp:*block-policy-estimator* 6))
              "load-fee-stats must restore the policy estimator, not just the legacy history"))))))

(test fee-estimates-file-past-max-age-is-ignored
  "Core MAX_FILE_AGE (60 hours): estimates that old describe a network whose
activity has moved on. Refusing them costs a few hours of accuracy; trusting
them costs money on every transaction built from them."
  (let* ((dir (%fee-stats-fixture "stale"))
         (path (merge-pathnames "fee_estimates.dat" dir))
         (legacy (bl.mp:make-fee-estimator :data-directory dir)))
    (let ((bl.mp:*block-policy-estimator* (%bpe-populated)))
      (bl.mp:save-fee-stats legacy))
    (is-true (probe-file path))
    ;; Fresh file: read.
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp::make-block-policy-estimator)))
      (is-true (bl.mp:load-fee-stats
                (bl.mp:make-fee-estimator :data-directory dir))))
    ;; 61 hours old: refused outright, before anything is parsed.
    (%backdate-file path (* 61 60 60))
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp::make-block-policy-estimator)))
      (is (null (bl.mp:load-fee-stats
                 (bl.mp:make-fee-estimator :data-directory dir))))
      (is (= 0 (bl.mp::bpe-estimate-smart-fee
                bl.mp:*block-policy-estimator* 6))))
    ;; 59 hours old: still inside the window.
    (%backdate-file path (* 59 60 60))
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp::make-block-policy-estimator)))
      (is-true (bl.mp:load-fee-stats
                (bl.mp:make-fee-estimator :data-directory dir))))
    ;; -acceptstalefeeestimates overrides it, as Core allows on regtest.
    (%backdate-file path (* 61 60 60))
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp::make-block-policy-estimator))
          (bl.mp:*accept-stale-fee-estimates* t))
      (is-true (bl.mp:load-fee-stats
                (bl.mp:make-fee-estimator :data-directory dir)))
      (is (plusp (bl.mp::bpe-estimate-smart-fee
                  bl.mp:*block-policy-estimator* 6))))))
