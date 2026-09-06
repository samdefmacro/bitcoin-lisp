(in-package #:bitcoin-lisp.tests)

(def-suite :block-policy-estimator-tests
  :description "Bitcoin Core CBlockPolicyEstimator port"
  :in :bitcoin-lisp-tests)

(in-suite :block-policy-estimator-tests)

;;;; File-local accessors for the estimator's internals. One reach each,
;;;; rather than one per assertion (tests/ :: ratchet).

(defun %bpe-tracked (est)
  (bl.mp::block-policy-estimator-tracked est))

(defun %bpe-tracked-count (est)
  (hash-table-count (%bpe-tracked est)))

(defun %bpe-best-height (est)
  (bl.mp::block-policy-estimator-best-height est))

(defun (setf %bpe-best-height) (height est)
  "Put EST at HEIGHT. A live estimator's best height IS the chain tip, and
Core records a transaction only at that height, so a synthetic fixture has to
say where it stands."
  (setf (bl.mp::block-policy-estimator-best-height est) height))

(defun %bpe-tracked-txs (est)
  (bl.mp::block-policy-estimator-tracked-txs est))

(defun %bpe-untracked-txs (est)
  (bl.mp::block-policy-estimator-untracked-txs est))

(defun %bpe-first-recorded (est)
  (bl.mp::block-policy-estimator-first-recorded-height est))


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

(test estimator-smart-fee-reports-the-confirming-feerate
  "End to end: sixty blocks in which 20000 sat/kvB confirms next-block and 800
never does. estimateSmartFee must report 20000 — the cheap population is
plentiful but useless, which is exactly the case a block-percentile heuristic
gets wrong."
  (let ((e (bpe-simulate)))
    (is (= 61 (%bpe-best-height e)))
    (is (= 20000 (bl.mp:bpe-estimate-smart-fee e 2)))
    (is (= 20000 (bl.mp:bpe-estimate-smart-fee e 6)))
    (is (= 20000 (bl.mp:bpe-estimate-smart-fee e 6 :conservative t)))
    ;; The unconfirmed cheap transactions are still tracked, still counting
    ;; against their bucket's success rate.
    (is (plusp (%bpe-tracked-count e)))))

(test estimator-smart-fee-drops-when-cheap-transactions-confirm
  "The control for the test above: identical volumes and buckets, the only
difference being that the cheap population CONFIRMS. The estimate must fall to
it — otherwise the previous test would pass on an estimator that simply always
returns the most expensive bucket."
  (let ((e (bpe-simulate :confirm-slow t)))
    (is (= 800 (bl.mp:bpe-estimate-smart-fee e 6)))))

(test estimator-refuses-targets-it-cannot-support
  "Targets outside the tracked range, and a history too short to justify one,
both return 0 rather than a fabricated number."
  (let ((fresh (bl.mp:make-block-policy-estimator)))
    (is (= 0 (bl.mp:bpe-estimate-smart-fee fresh 0)))
    (is (= 0 (bl.mp:bpe-estimate-smart-fee fresh 6)))
    ;; Beyond the longest horizon.
    (is (= 0 (bl.mp:bpe-estimate-smart-fee fresh 100000))))
  ;; A short run cannot justify a distant target: MaxUsableEstimate halves the
  ;; observed block span. Ten simulated blocks record from height 2 (the first
  ;; block that confirmed anything) to height 11, a span of 9, so targets are
  ;; capped at 4.
  (let ((short-run (bpe-simulate :blocks 10)))
    (is (= 2 (%bpe-first-recorded short-run)))
    (is (= 11 (%bpe-best-height short-run)))
    (is (= 4 (bl.mp::bpe-max-usable-estimate short-run))))
  ;; An estimator that has seen blocks but never counted a transaction has no
  ;; span at all — the clock starts on DATA, not on blocks.
  (let ((empty (bl.mp:make-block-policy-estimator)))
    (bpe-add-block empty 100 (list))
    (bpe-add-block empty 200 (list))
    (is (= 0 (%bpe-first-recorded empty)))
    (is (= 0 (bl.mp::bpe-max-usable-estimate empty)))))

(test estimator-a-confirmed-transaction-stops-being-tracked
  "processBlock must untrack what it confirms; otherwise every confirmed
transaction would go on counting as 'still in the mempool' against its own
bucket forever."
  (let ((e (bl.mp:make-block-policy-estimator))
        (txid (bpe-test-id 9 9 9)))
    (setf (%bpe-best-height e) 1)
    (bpe-add-tx e txid 1 5000d0)
    (is (= 1 (%bpe-tracked-count e)))
    (bpe-add-block e 2 (list txid))
    (is (= 0 (%bpe-tracked-count e)))))

(test estimator-ignores-a-block-it-has-already-seen
  "A block at or below the best seen height must not be processed twice — the
decay step would run again and silently age all history by an extra block."
  (let ((e (bpe-simulate :blocks 5)))
    (let ((height (%bpe-best-height e)))
      (is (= 0 (bpe-add-block e height '())))
      (is (= 0 (bpe-add-block e (1- height) '())))
      (is (= height (%bpe-best-height e))))))

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
    ;; The estimator's best height IS the tip; a transaction entering at any
    ;; other height is a side chain or a start-up replay and Core drops it.
    (setf (%bpe-best-height est) 200)
    (is (= 0 (%bpe-tracked-count est)))
    (bl.mp:accept-validated-tx mempool txid tx 5000 200)
    (is (= 1 (%bpe-tracked-count est))
        "the mempool must report acceptances to the estimator")
    ;; It recorded the ENTRY HEIGHT, which is what a confirmation is measured
    ;; against.
    (is (= 200 (first (gethash txid (%bpe-tracked est)))))))

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
         (tracked (%bpe-tracked est)))
    (setf (%bpe-best-height est) 200)
    ;; Evicted for size: untracked, and a failure is recorded.
    (bl.mp:accept-validated-tx mempool txid tx 5000 200)
    (setf (%bpe-best-height est) 260)
    (let ((bl.mp:*mempool-removal-reason* :size-limit))
      (bl.mp:mempool-remove mempool txid))
    (is (= 0 (hash-table-count tracked)))
    ;; Removed BY A BLOCK: the removal path leaves it alone.
    (let ((tx2 (make-mempool-test-tx :input-id 122)))
      (let ((txid2 (bl.ser:transaction-hash tx2)))
        (setf (%bpe-best-height est) 200)
        (bl.mp:accept-validated-tx mempool txid2 tx2 5000 200)
        (is (= 1 (hash-table-count tracked)))
        (let ((bl.mp:*mempool-removal-reason* :block))
          (bl.mp:mempool-remove mempool txid2))
        (is (= 1 (hash-table-count tracked))
            "a block removal must leave the estimator's tracking to the block hook")))))

(test connect-block-reports-confirmations-to-the-fee-estimator
  "connect-block must call the block hook, and it must run while the block's
transactions are still tracked. Drives the real connect-block."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "bpe-connect")
     (let* ((bl.mp:*block-policy-estimator*
              (bl.mp:make-block-policy-estimator))
            (est bl.mp:*block-policy-estimator*)
            (block1 (make-reorg-test-block genesis-hash
                                           (first (make-test-chain-hashes #xC0 1)) 1))
            (coinbase (first (bl.ser:bitcoin-block-transactions block1)))
            (cb-txid (bl.ser:transaction-hash coinbase)))
       ;; Pretend the coinbase was a tracked mempool transaction entered at
       ;; height 0, so the block at height 1 is a 1-block confirmation.
       (bpe-add-tx est cb-txid 0 9000d0)
       (is (= 1 (%bpe-tracked-count est)))
       (bl.val:connect-block block1 chain-state block-store utxo-set)
       ;; The hook ran: best height moved and the transaction was untracked by
       ;; the confirmation, not merely dropped.
       (is (= 1 (%bpe-best-height est))
           "connect-block must report the block to the estimator")
       (is (= 0 (%bpe-tracked-count est))))
     (clear-undo-cache))))

;;;; --- Persistence ---

(defun %bpe-bytes (est)
  (flexi-streams:with-output-to-sequence (mem)
    (bl.mp:bpe-write-to-stream est mem)))

(defun %bpe-load-bytes (est bytes)
  (flexi-streams:with-input-from-sequence (in bytes)
    (bl.mp:bpe-read-into est in)))

(test estimator-survives-a-save-load-round-trip
  "Without persistence the estimator answers 0 for hours after every restart,
because MaxUsableEstimate has to re-accumulate a block span. The restored
estimator must give the same answer as the one that was saved."
  (let* ((original (bpe-populated-estimator))
         (bytes (%bpe-bytes original))
         (restored (bl.mp:make-block-policy-estimator)))
    (is-true (%bpe-load-bytes restored bytes))
    (is (= (bl.mp:bpe-estimate-smart-fee original 6)
           (bl.mp:bpe-estimate-smart-fee restored 6)))
    (is (plusp (bl.mp:bpe-estimate-smart-fee restored 6))
        "the round trip must preserve an ANSWER, not agree on zero")
    (is (= (%bpe-best-height original)
           (%bpe-best-height restored)))
    ;; The unconfirmed tracking is per-run and deliberately not stored: the
    ;; mempool is reloaded and re-reported after a restart, so persisting it
    ;; would double-count.
    (is (= 0 (hash-table-count
              (%bpe-tracked restored))))))

(test estimator-discards-a-corrupt-file-rather-than-half-loading-it
  "The load discipline that matters: nothing is installed until every horizon
has parsed and every check has passed. A partially applied estimator would
answer confidently from nonsense, and fee estimates are spent money."
  (let* ((bytes (%bpe-bytes (bpe-populated-estimator)))
         (truncated (subseq bytes 0 (floor (length bytes) 2)))
         (victim (bpe-simulate :blocks 40 :fast-feerate 7000d0))
         (before (bl.mp:bpe-estimate-smart-fee victim 6)))
    (is (plusp before))
    ;; A truncated file is rejected...
    (is (null (%bpe-load-bytes victim truncated)))
    ;; ...and the estimator is exactly as it was.
    (is (= before (bl.mp:bpe-estimate-smart-fee victim 6))
        "a rejected file must leave the existing estimator untouched")
    ;; Garbage in the middle is rejected too.
    (let ((mangled (copy-seq bytes)))
      (loop for i from 40 below 200 do (setf (aref mangled i) #xFF))
      (is (null (%bpe-load-bytes victim mangled)))
      (is (= before (bl.mp:bpe-estimate-smart-fee victim 6))))))

(test estimator-rejects-a-file-written-for-a-different-bucket-set
  "Per-bucket counts only mean anything against the bucket set they were
recorded in. A file whose buckets differ must be DISCARDED, never remapped —
silently reinterpreting them would make every count mean something else."
  (let* ((bytes (%bpe-bytes (bpe-populated-estimator)))
         (est (bl.mp:make-block-policy-estimator)))
    ;; The bucket vector starts after best-height + the two range words (12
    ;; bytes) and a 4-byte count; corrupt its first entry.
    (let ((mangled (copy-seq bytes)))
      (setf (aref mangled 16) (logxor (aref mangled 16) #x0F))
      (is (null (%bpe-load-bytes est mangled))))))

(test estimator-rejects-an-impossible-decay-or-scale
  "Core's TxConfirmStats::Read sanity checks: decay strictly inside (0,1) and a
non-zero scale. Both are load-bearing — a decay of 1 never forgets and a decay
of 0 forgets everything, and EstimateMedianVal divides by (1 - decay)."
  (let* ((est (bpe-populated-estimator))
         (bytes (%bpe-bytes est))
         (target (bl.mp:make-block-policy-estimator))
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
    (let ((bl.mp:*block-policy-estimator* (bpe-populated-estimator)))
      (let ((expected (bl.mp:bpe-estimate-smart-fee
                       bl.mp:*block-policy-estimator* 6)))
        (is (plusp expected))
        (bl.mp:save-fee-stats legacy)
        ;; A fresh process: new estimator, new legacy history.
        (let ((bl.mp:*block-policy-estimator*
                (bl.mp:make-block-policy-estimator))
              (legacy2 (bl.mp:make-fee-estimator :data-directory dir)))
          (is (= 0 (bl.mp:bpe-estimate-smart-fee
                    bl.mp:*block-policy-estimator* 6))
              "a fresh estimator answers 0 before loading")
          (is-true (bl.mp:load-fee-stats legacy2))
          (is (= expected (bl.mp:bpe-estimate-smart-fee
                           bl.mp:*block-policy-estimator* 6))
              "load-fee-stats must restore the policy estimator, not just the legacy history"))))))

(test fee-estimates-file-past-max-age-is-ignored
  "Core MAX_FILE_AGE (60 hours): estimates that old describe a network whose
activity has moved on. Refusing them costs a few hours of accuracy; trusting
them costs money on every transaction built from them."
  (let* ((dir (%fee-stats-fixture "stale"))
         (path (merge-pathnames "fee_estimates.dat" dir))
         (legacy (bl.mp:make-fee-estimator :data-directory dir)))
    (let ((bl.mp:*block-policy-estimator* (bpe-populated-estimator)))
      (bl.mp:save-fee-stats legacy))
    (is-true (probe-file path))
    ;; Fresh file: read.
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp:make-block-policy-estimator)))
      (is-true (bl.mp:load-fee-stats
                (bl.mp:make-fee-estimator :data-directory dir))))
    ;; 61 hours old: refused outright, before anything is parsed.
    (%backdate-file path (* 61 60 60))
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp:make-block-policy-estimator)))
      (is (null (bl.mp:load-fee-stats
                 (bl.mp:make-fee-estimator :data-directory dir))))
      (is (= 0 (bl.mp:bpe-estimate-smart-fee
                bl.mp:*block-policy-estimator* 6))))
    ;; 59 hours old: still inside the window.
    (%backdate-file path (* 59 60 60))
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp:make-block-policy-estimator)))
      (is-true (bl.mp:load-fee-stats
                (bl.mp:make-fee-estimator :data-directory dir))))
    ;; -acceptstalefeeestimates overrides it, as Core allows on regtest.
    (%backdate-file path (* 61 60 60))
    (let ((bl.mp:*block-policy-estimator*
            (bl.mp:make-block-policy-estimator))
          (bl.mp:*accept-stale-fee-estimates* t))
      (is-true (bl.mp:load-fee-stats
                (bl.mp:make-fee-estimator :data-directory dir)))
      (is (plusp (bl.mp:bpe-estimate-smart-fee
                  bl.mp:*block-policy-estimator* 6))))))

;;;; --- Core's validForFeeEstimation gate (block_policy_estimator.cpp:595-637)
;;;;
;;;; The estimator's arithmetic was faithful; what fed it was not. Every
;;;; successful mempool add was recorded, so the estimator learned from
;;;; transactions whose confirmation time somebody else bought.

(defmacro with-live-estimator ((est mempool &key (height 200)) &body body)
  "BODY with a fresh policy estimator bound as the node's, its best height set
to HEIGHT (a live estimator's best height IS the tip), and a fresh mempool."
  `(let* ((bl.mp:*block-policy-estimator* (bl.mp:make-block-policy-estimator))
          (,est bl.mp:*block-policy-estimator*)
          (,mempool (bl.mp:make-mempool)))
     (setf (%bpe-best-height ,est) ,height)
     ,@body))

(test estimator-ignores-a-transaction-from-another-height
  "Core's FIRST gate: `Ignore side chains and re-orgs; ... Ignore txs if
BlockPolicyEstimator is not in sync with ActiveChain().Tip()' -- txHeight must
equal nBestSeenHeight. There was no height comparison at all, so a fresh
estimator (best height 0) tracked a transaction announced at height 500, and
every transaction replayed from mempool.dat at start-up was recorded as if it
had entered at the current tip."
  (let ((est (bl.mp:make-block-policy-estimator))
        (txid (bpe-test-id 7 7 1)))
    (is (= 0 (%bpe-best-height est)))
    (is-false (bpe-add-tx est txid 500 20000d0))
    (is (= 0 (%bpe-tracked-count est))
        "a transaction from another height was tracked")
    ;; Positive control: at the estimator's own height it IS tracked.
    (is-true (bpe-add-tx est (bpe-test-id 7 7 2) 0 20000d0))
    (is (= 1 (%bpe-tracked-count est)))))

(test estimator-applies-cores-four-validity-flags
  "validForFeeEstimation = !m_mempool_limit_bypassed && !m_submitted_in_package
&& m_chainstate_is_current && m_has_no_mempool_parents
(block_policy_estimator.cpp:614). ACCEPT-VALIDATED-TX is the shared tail of
every acceptance path and took none of them, so a reorg re-add, a package
member, an acceptance made while catching up and a CPFP child were all
recorded."
  (dolist (row (list (list :bypass-limits t "reorg re-add")
                     (list :package-submission t "package member")
                     (list :chainstate-current nil "not caught up")))
    (destructuring-bind (key value label) row
      (with-live-estimator (est mempool)
        (let* ((tx (make-mempool-test-tx :input-id 140))
               (txid (bl.ser:transaction-hash tx)))
          (is (eq :ok (apply #'bl.mp:accept-validated-tx
                             mempool txid tx 5000 200 (list key value))))
          (is (= 0 (%bpe-tracked-count est)) "~A was tracked" label)
          (is (= 1 (%bpe-untracked-txs est))
              "~A was not counted as untracked" label)
          (is (= 0 (%bpe-tracked-txs est)))))))
  ;; Positive control: with none of them, the same transaction IS tracked.
  (with-live-estimator (est mempool)
    (let* ((tx (make-mempool-test-tx :input-id 140))
           (txid (bl.ser:transaction-hash tx)))
      (is (eq :ok (bl.mp:accept-validated-tx mempool txid tx 5000 200)))
      (is (= 1 (%bpe-tracked-count est)))
      (is (= 1 (%bpe-tracked-txs est)))
      (is (= 0 (%bpe-untracked-txs est))))))

(test estimator-ignores-a-child-of-an-unconfirmed-parent
  "HasNoInputsOf. A CPFP child teaches the estimator that its own low feerate
confirmed in one block, which is precisely the inference the parent paid for.
The parent is tracked; the child is not."
  (with-live-estimator (est mempool)
    (let* ((parent (make-mempool-test-tx :input-id 141))
           (ptxid (bl.ser:transaction-hash parent))
           (child (make-spending-test-tx ptxid))
           (ctxid (bl.ser:transaction-hash child)))
      (is (eq :ok (bl.mp:accept-validated-tx mempool ptxid parent 20000 200)))
      (is (= 1 (%bpe-tracked-count est)) "the parent must be tracked")
      (is (eq :ok (bl.mp:accept-validated-tx mempool ctxid child 500 200)))
      (is (= 2 (bl.mp:mempool-count mempool)) "the child must be in the pool")
      (is (= 1 (%bpe-tracked-count est))
          "the child of an unconfirmed parent was tracked")
      (is (= 1 (%bpe-untracked-txs est))))))

(test estimator-block-resets-the-tracked-counters
  "Core reports and resets trackedTxs / untrackedTxs in processBlock
(:704-712); without the reset the numbers are cumulative and the log line says
nothing about the block it names."
  (with-live-estimator (est mempool :height 200)
    (let* ((tx (make-mempool-test-tx :input-id 142))
           (txid (bl.ser:transaction-hash tx)))
      (bl.mp:accept-validated-tx mempool txid tx 5000 200)
      (is (= 1 (%bpe-tracked-txs est)))
      (bpe-add-block est 201 (list txid))
      (is (= 0 (%bpe-tracked-txs est)))
      (is (= 0 (%bpe-untracked-txs est))))))

(test estimator-cpfp-children-do-not-drag-the-estimate-down
  "The differential the survey measured, in miniature: parents at 20000 sat/kvB
that confirm in three blocks, and children at 1000 that confirm in one. With
Core's gate the estimate is the parents' feerate; with the children recorded --
which is what tracking them amounts to -- it collapses to theirs. Same blocks,
same code path, the only difference is whether the child is fed in."
  (flet ((replay (track-children)
           (let ((e (bl.mp:make-block-policy-estimator))
                 (pending '()))
             (setf (%bpe-best-height e) 1)
             (loop for h from 1 to 60
                   do (let ((confirmed '()))
                        ;; Parents entered three blocks ago confirm now.
                        (dolist (txid (cdr (assoc (- h 3) pending)))
                          (push txid confirmed))
                        (dotimes (i 20)
                          (let ((txid (bpe-test-id 3 h i)))
                            (bpe-add-tx e txid h 20000d0)
                            (push txid (cdr (or (assoc h pending)
                                                (car (push (cons h '()) pending)))))))
                        (dotimes (i 20)
                          (let ((txid (bpe-test-id 4 h i)))
                            ;; The child: an in-mempool parent, so Core's gate
                            ;; refuses it. TRACK-CHILDREN feeds it anyway.
                            (bpe-add-tx e txid h 1000d0
                                         :has-no-mempool-parents track-children)
                            (push txid confirmed)))
                        (bpe-add-block e (1+ h) confirmed)))
             e)))
    (let ((gated (replay nil))
          (ungated (replay t)))
      (is (= 20000 (bl.mp:bpe-estimate-smart-fee gated 6))
          "with Core's gate the estimate must be the parents' feerate")
      (is (= 1000 (bl.mp:bpe-estimate-smart-fee ungated 6))
          "positive control: feeding the children in must collapse it"))))

(test start-node-creates-the-estimator-before-loading-its-state
  "⚠️ The unfiled sibling of the gate: start-node called LOAD-FEE-STATS before
it created *BLOCK-POLICY-ESTIMATOR*, so the special was still NIL when the file
was read and its policy-estimator section was discarded with a warning -- on
every start. The node then began each run with an EMPTY Core estimator and a
fully restored percentile history.

This drives the real init step. The existing serializer test stays green either
way, because it binds the special to a fresh estimator before calling
LOAD-FEE-STATS, which is exactly what production did not do."
  (let* ((dir (%fee-stats-fixture "init-order"))
         (saved (let ((bl.mp:*block-policy-estimator* (bpe-populated-estimator)))
                  (setf (%bpe-best-height bl.mp:*block-policy-estimator*) 60)
                  (bl.mp:save-fee-stats
                   (bl.mp:make-fee-estimator :data-directory dir))
                  (bl.mp:bpe-estimate-smart-fee bl.mp:*block-policy-estimator* 6))))
    (is (plusp saved))
    ;; Production's state at start-up: no estimator installed at all.
    (let ((bl.mp:*block-policy-estimator* nil)
          (bl:*node* (make-test-node)))
      (bl::%init-fee-estimation dir)
      (is-true bl.mp:*block-policy-estimator*
               "the init step must install a policy estimator")
      (is (= 60 (%bpe-best-height bl.mp:*block-policy-estimator*))
          "the saved policy-estimator state was discarded")
      (is (= saved (bl.mp:bpe-estimate-smart-fee
                    bl.mp:*block-policy-estimator* 6))
          "the restored estimator must answer what the saved one did"))))
