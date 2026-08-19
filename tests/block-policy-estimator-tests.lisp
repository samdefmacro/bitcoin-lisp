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
