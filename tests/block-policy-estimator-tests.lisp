(in-package #:bitcoin-lisp.tests)

(def-suite :block-policy-estimator-tests
  :description "Bitcoin Core CBlockPolicyEstimator port"
  :in :bitcoin-lisp-tests)

(in-suite :block-policy-estimator-tests)

(defun %bpe-stats (&key (periods 24) (decay 0.9952d0) (scale 2))
  (bitcoin-lisp.mempool::make-tx-confirm-stats
   (bitcoin-lisp.mempool::make-fee-buckets) periods decay scale))

(test fee-buckets-match-core-spacing
  "Core's bucket set: geometric from MIN_BUCKET_FEERATE (100) to
MAX_BUCKET_FEERATE (1e7) at FEE_SPACING (1.05), then an INF catch-all. Bucket
lookup is lower_bound — the first bucket whose upper bound is >= the feerate."
  (let ((b (bitcoin-lisp.mempool::make-fee-buckets)))
    (is (= 100d0 (aref b 0)))
    (is (= 105d0 (aref b 1)))
    (is (= bitcoin-lisp.mempool::+inf-feerate+ (aref b (1- (length b)))))
    (is (<= (aref b (- (length b) 2)) bitcoin-lisp.mempool::+fee-max-bucket-feerate+))
    ;; lower_bound: a feerate AT a boundary belongs to that bucket, not the next.
    (is (= 0 (bitcoin-lisp.mempool::fee-bucket-index b 99d0)))
    (is (= 0 (bitcoin-lisp.mempool::fee-bucket-index b 100d0)))
    (is (= 1 (bitcoin-lisp.mempool::fee-bucket-index b 101d0)))
    ;; Anything above the top finite bucket lands in INF.
    (is (= (1- (length b)) (bitcoin-lisp.mempool::fee-bucket-index b 1d8)))))

(test estimator-reports-the-feerate-that-confirmed
  "A population that confirms within the target is reported back at its own
feerate."
  (let ((s (%bpe-stats)))
    (dotimes (i 100) (bitcoin-lisp.mempool::tx-confirm-stats-record s 1 10000d0))
    (is (= 10000d0 (bitcoin-lisp.mempool::tx-confirm-stats-estimate-median
                    s 1 0.1d0 0.85d0 100)))
    ;; A longer target is satisfied by the same data.
    (is (= 10000d0 (bitcoin-lisp.mempool::tx-confirm-stats-estimate-median
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
      (bitcoin-lisp.mempool::tx-confirm-stats-record failed 1 10000d0)
      (bitcoin-lisp.mempool::tx-confirm-stats-record confirmed 1 10000d0))
    ;; FAILED: 100 cheap ones enter and are evicted unconfirmed 30 blocks later.
    (dotimes (i 100)
      (let ((b (bitcoin-lisp.mempool::tx-confirm-stats-new-tx failed 100 500d0)))
        (bitcoin-lisp.mempool::tx-confirm-stats-remove-tx failed 100 130 b nil)))
    ;; CONFIRMED: the same 100 cheap ones confirm in one block.
    (dotimes (i 100)
      (bitcoin-lisp.mempool::tx-confirm-stats-record confirmed 1 500d0))
    (is (= 10000d0 (bitcoin-lisp.mempool::tx-confirm-stats-estimate-median
                    failed 1 0.1d0 0.85d0 130))
        "a feerate that did not confirm must not be recommended")
    (is (= 500d0 (bitcoin-lisp.mempool::tx-confirm-stats-estimate-median
                  confirmed 1 0.1d0 0.85d0 130))
        "the cheapest feerate that DID confirm is the answer")))

(test estimator-returns-minus-one-without-enough-data
  "Below SUFFICIENT_FEETXS/(1-decay) transactions, no bucket range may answer:
-1, not a confident guess off two samples."
  (let ((s (%bpe-stats)))
    (is (= -1d0 (bitcoin-lisp.mempool::tx-confirm-stats-estimate-median
                 s 1 0.1d0 0.85d0 100)))
    (dotimes (i 3) (bitcoin-lisp.mempool::tx-confirm-stats-record s 1 10000d0))
    (is (= -1d0 (bitcoin-lisp.mempool::tx-confirm-stats-estimate-median
                 s 1 0.1d0 0.85d0 100)))))

(test estimator-decay-fades-old-history
  "UpdateMovingAverages decays every counter, so history fades continuously
instead of falling off a hard window edge."
  (let ((s (%bpe-stats :decay 0.5d0)))
    (dotimes (i 100) (bitcoin-lisp.mempool::tx-confirm-stats-record s 1 10000d0))
    (let ((bucket (bitcoin-lisp.mempool::fee-bucket-index
                   (bitcoin-lisp.mempool::make-fee-buckets) 10000d0)))
      (let ((before (aref (bitcoin-lisp.mempool::tx-confirm-stats-txct-avg s) bucket)))
        (bitcoin-lisp.mempool::tx-confirm-stats-update-moving-averages s)
        (is (= (/ before 2)
               (aref (bitcoin-lisp.mempool::tx-confirm-stats-txct-avg s) bucket)))))))

(test estimator-confirmation-is-not-a-failure
  "removeTx's IN-BLOCK flag is the difference between 'confirmed' and 'gave up'.
Only the latter records a failure — counting confirmations as failures would
push every estimate upward without bound."
  (let ((s (%bpe-stats))
        (bucket (bitcoin-lisp.mempool::fee-bucket-index
                 (bitcoin-lisp.mempool::make-fee-buckets) 500d0)))
    ;; Confirmed after 30 blocks: no failure recorded.
    (let ((b (bitcoin-lisp.mempool::tx-confirm-stats-new-tx s 100 500d0)))
      (bitcoin-lisp.mempool::tx-confirm-stats-remove-tx s 100 130 b t))
    (is (= 0d0 (aref (aref (bitcoin-lisp.mempool::tx-confirm-stats-fail-avg s) 0) bucket)))
    ;; Evicted after 30 blocks: failure recorded.
    (let ((b (bitcoin-lisp.mempool::tx-confirm-stats-new-tx s 100 500d0)))
      (bitcoin-lisp.mempool::tx-confirm-stats-remove-tx s 100 130 b nil))
    (is (plusp (aref (aref (bitcoin-lisp.mempool::tx-confirm-stats-fail-avg s) 0) bucket)))))

(test estimator-clear-current-ages-unconfirmed-into-the-old-bucket
  "ClearCurrent rolls the circular buffer: whatever still sits in a slot when it
comes round again has aged out of the window and moves to OLD-UNCONF-TXS, where
it still counts against success rates. Dropping it instead would make a bucket
nobody can confirm look perfect for lack of evidence."
  (let* ((s (%bpe-stats))
         (bucket (bitcoin-lisp.mempool::tx-confirm-stats-new-tx s 7 500d0)))
    (is (= 1 (aref (aref (bitcoin-lisp.mempool::tx-confirm-stats-unconf-txs s)
                         (mod 7 (length (bitcoin-lisp.mempool::tx-confirm-stats-unconf-txs s))))
                   bucket)))
    (is (= 0 (aref (bitcoin-lisp.mempool::tx-confirm-stats-old-unconf-txs s) bucket)))
    (bitcoin-lisp.mempool::tx-confirm-stats-clear-current s 7)
    (is (= 0 (aref (aref (bitcoin-lisp.mempool::tx-confirm-stats-unconf-txs s)
                         (mod 7 (length (bitcoin-lisp.mempool::tx-confirm-stats-unconf-txs s))))
                   bucket)))
    (is (= 1 (aref (bitcoin-lisp.mempool::tx-confirm-stats-old-unconf-txs s) bucket)))))

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
  (let ((e (bitcoin-lisp.mempool::make-block-policy-estimator)))
    (loop for h from 1 to blocks
          do (let ((confirmed '()))
               (dotimes (i per-block)
                 (let ((txid (%bpe-id 1 h i)))
                   (bitcoin-lisp.mempool::bpe-process-transaction e txid h fast-feerate)
                   (push (cons txid fast-feerate) confirmed)))
               (dotimes (i per-block)
                 (let ((txid (%bpe-id 2 h i)))
                   (bitcoin-lisp.mempool::bpe-process-transaction e txid h slow-feerate)
                   (when confirm-slow
                     (push (cons txid slow-feerate) confirmed))))
               (bitcoin-lisp.mempool::bpe-process-block e (1+ h) confirmed)))
    e))

(test estimator-smart-fee-reports-the-confirming-feerate
  "End to end: sixty blocks in which 20000 sat/kvB confirms next-block and 800
never does. estimateSmartFee must report 20000 — the cheap population is
plentiful but useless, which is exactly the case a block-percentile heuristic
gets wrong."
  (let ((e (%bpe-simulate)))
    (is (= 61 (bitcoin-lisp.mempool::block-policy-estimator-best-height e)))
    (is (= 20000 (bitcoin-lisp.mempool::bpe-estimate-smart-fee e 2)))
    (is (= 20000 (bitcoin-lisp.mempool::bpe-estimate-smart-fee e 6)))
    (is (= 20000 (bitcoin-lisp.mempool::bpe-estimate-smart-fee e 6 :conservative t)))
    ;; The unconfirmed cheap transactions are still tracked, still counting
    ;; against their bucket's success rate.
    (is (plusp (hash-table-count
                (bitcoin-lisp.mempool::block-policy-estimator-tracked e))))))

(test estimator-smart-fee-drops-when-cheap-transactions-confirm
  "The control for the test above: identical volumes and buckets, the only
difference being that the cheap population CONFIRMS. The estimate must fall to
it — otherwise the previous test would pass on an estimator that simply always
returns the most expensive bucket."
  (let ((e (%bpe-simulate :confirm-slow t)))
    (is (= 800 (bitcoin-lisp.mempool::bpe-estimate-smart-fee e 6)))))

(test estimator-refuses-targets-it-cannot-support
  "Targets outside the tracked range, and a history too short to justify one,
both return 0 rather than a fabricated number."
  (let ((fresh (bitcoin-lisp.mempool::make-block-policy-estimator)))
    (is (= 0 (bitcoin-lisp.mempool::bpe-estimate-smart-fee fresh 0)))
    (is (= 0 (bitcoin-lisp.mempool::bpe-estimate-smart-fee fresh 6)))
    ;; Beyond the longest horizon.
    (is (= 0 (bitcoin-lisp.mempool::bpe-estimate-smart-fee fresh 100000))))
  ;; A short run cannot justify a distant target: MaxUsableEstimate halves the
  ;; observed block span. Ten simulated blocks record from height 2 (the first
  ;; block that confirmed anything) to height 11, a span of 9, so targets are
  ;; capped at 4.
  (let ((short-run (%bpe-simulate :blocks 10)))
    (is (= 2 (bitcoin-lisp.mempool::block-policy-estimator-first-recorded-height short-run)))
    (is (= 11 (bitcoin-lisp.mempool::block-policy-estimator-best-height short-run)))
    (is (= 4 (bitcoin-lisp.mempool::bpe-max-usable-estimate short-run))))
  ;; An estimator that has seen blocks but never counted a transaction has no
  ;; span at all — the clock starts on DATA, not on blocks.
  (let ((empty (bitcoin-lisp.mempool::make-block-policy-estimator)))
    (bitcoin-lisp.mempool::bpe-process-block empty 100 (list))
    (bitcoin-lisp.mempool::bpe-process-block empty 200 (list))
    (is (= 0 (bitcoin-lisp.mempool::block-policy-estimator-first-recorded-height empty)))
    (is (= 0 (bitcoin-lisp.mempool::bpe-max-usable-estimate empty)))))

(test estimator-a-confirmed-transaction-stops-being-tracked
  "processBlock must untrack what it confirms; otherwise every confirmed
transaction would go on counting as 'still in the mempool' against its own
bucket forever."
  (let ((e (bitcoin-lisp.mempool::make-block-policy-estimator))
        (txid (%bpe-id 9 9 9)))
    (bitcoin-lisp.mempool::bpe-process-transaction e txid 1 5000d0)
    (is (= 1 (hash-table-count
              (bitcoin-lisp.mempool::block-policy-estimator-tracked e))))
    (bitcoin-lisp.mempool::bpe-process-block e 2 (list (cons txid 5000d0)))
    (is (= 0 (hash-table-count
              (bitcoin-lisp.mempool::block-policy-estimator-tracked e))))))

(test estimator-ignores-a-block-it-has-already-seen
  "A block at or below the best seen height must not be processed twice — the
decay step would run again and silently age all history by an extra block."
  (let ((e (%bpe-simulate :blocks 5)))
    (let ((height (bitcoin-lisp.mempool::block-policy-estimator-best-height e)))
      (is (= 0 (bitcoin-lisp.mempool::bpe-process-block e height '())))
      (is (= 0 (bitcoin-lisp.mempool::bpe-process-block e (1- height) '())))
      (is (= height (bitcoin-lisp.mempool::block-policy-estimator-best-height e))))))
