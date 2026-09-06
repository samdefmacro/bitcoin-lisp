(in-package #:bitcoin-lisp.mempool)

;;;; Bitcoin Core's CBlockPolicyEstimator (policy/fees/block_policy_estimator.cpp)
;;;;
;;;; The estimator answers "what feerate gets confirmed within N blocks?" from
;;;; observed history, not from a percentile of what recent blocks happened to
;;;; contain. The distinction matters: a block-percentile heuristic reports what
;;;; miners took, which during a lull is whatever cheap transactions existed,
;;;; and it can never say "transactions at this feerate FAILED to confirm" —
;;;; the signal that actually moves an estimate up.
;;;;
;;;; The design tracks each transaction from mempool entry to confirmation:
;;;;
;;;;   entry      -> bucket it by feerate, remember the height it arrived
;;;;   confirmed  -> record how many blocks it waited, in that bucket
;;;;   evicted    -> record a FAILURE in that bucket
;;;;
;;;; Three horizons run in parallel over the same buckets, differing only in how
;;;; fast history decays and how many blocks one "period" spans, so a short
;;;; target reacts quickly while a long one stays stable.

;;;; --- Constants (block_policy_estimator.h:152-199) ---

(defconstant +fee-min-bucket-feerate+ 100d0
  "Core MIN_BUCKET_FEERATE: the lowest feerate bucket, in satoshis per kvB.")

(defconstant +fee-max-bucket-feerate+ 1d7
  "Core MAX_BUCKET_FEERATE.")

(defconstant +fee-spacing+ 1.05d0
  "Core FEE_SPACING: each bucket is 5% above the previous one.")

(defconstant +inf-feerate+ 1d99
  "Core INF_FEERATE: the catch-all top bucket.")

(defconstant +short-block-periods+ 12)
(defconstant +short-scale+ 1)
(defconstant +short-decay+ 0.962d0)

(defconstant +med-block-periods+ 24)
(defconstant +med-scale+ 2)
(defconstant +med-decay+ 0.9952d0)

(defconstant +long-block-periods+ 42)
(defconstant +long-scale+ 24)
(defconstant +long-decay+ 0.99931d0)

(defconstant +half-success-pct+ 0.6d0)
(defconstant +success-pct+ 0.85d0)
(defconstant +double-success-pct+ 0.95d0)

(defconstant +sufficient-feetxs+ 0.1d0
  "Core SUFFICIENT_FEETXS: required average confirmations per block in a bucket
range before that range is allowed to answer.")

(defconstant +sufficient-txs-short+ 0.5d0
  "Core SUFFICIENT_TXS_SHORT: the short horizon demands more data, having less
history to average over.")

(defconstant +oldest-estimate-history+ (* 6 1008)
  "Core OLDEST_ESTIMATE_HISTORY: estimates older than this many blocks are not
reported at all.")

;;;; --- Buckets ---

(defun make-fee-buckets ()
  "The bucket upper bounds (Core's CBlockPolicyEstimator constructor): geometric
from MIN_BUCKET_FEERATE to MAX_BUCKET_FEERATE by FEE_SPACING, then a final
INF_FEERATE catch-all."
  (let ((bounds '()))
    (loop for b = +fee-min-bucket-feerate+ then (* b +fee-spacing+)
          while (<= b +fee-max-bucket-feerate+)
          do (push b bounds))
    (push +inf-feerate+ bounds)
    (coerce (nreverse bounds) 'simple-vector)))

(defun fee-bucket-index (buckets feerate)
  "Index of the bucket FEERATE falls in — Core's bucketMap.lower_bound(feerate),
i.e. the FIRST bucket whose upper bound is >= FEERATE. Binary search, since this
runs per transaction."
  (let ((lo 0)
        (hi (1- (length buckets))))
    (loop while (< lo hi)
          do (let ((mid (floor (+ lo hi) 2)))
               (if (< (aref buckets mid) feerate)
                   (setf lo (1+ mid))
                   (setf hi mid))))
    lo))

;;;; --- TxConfirmStats ---

(defstruct (tx-confirm-stats (:constructor %make-tx-confirm-stats))
  "One horizon's history over the shared bucket set (Core TxConfirmStats).

CONF-AVG[p][b] is the decayed count of transactions in bucket B that confirmed
within period P+1; FAIL-AVG[p][b] the count that left the mempool unconfirmed
after that long. TXCT-AVG and FEERATE-AVG carry the decayed transaction count
and summed feerate per bucket, which is how a bucket's representative feerate is
recovered. UNCONF-TXS is a circular buffer, indexed by entry height, of
still-unconfirmed transactions; OLD-UNCONF-TXS holds those that fell off it."
  (buckets #() :type simple-vector)
  (decay 1d0 :type double-float)
  (scale 1 :type (integer 1))
  (conf-avg #() :type simple-vector)      ; period -> bucket -> double
  (fail-avg #() :type simple-vector)
  (txct-avg #() :type (simple-array double-float (*)))
  (feerate-avg #() :type (simple-array double-float (*)))
  (unconf-txs #() :type simple-vector)    ; blockindex -> bucket -> fixnum
  (old-unconf-txs #() :type (simple-array fixnum (*))))

(defun %make-double-grid (rows cols)
  (let ((g (make-array rows)))
    (dotimes (i rows g)
      (setf (aref g i) (make-array cols :element-type 'double-float
                                        :initial-element 0d0)))))

(defun %make-fixnum-grid (rows cols)
  (let ((g (make-array rows)))
    (dotimes (i rows g)
      (setf (aref g i) (make-array cols :element-type 'fixnum
                                        :initial-element 0)))))

(defun make-tx-confirm-stats (buckets max-periods decay scale)
  "A horizon tracking MAX-PERIODS periods of SCALE blocks each."
  (let ((n (length buckets)))
    (%make-tx-confirm-stats
     :buckets buckets :decay decay :scale scale
     :conf-avg (%make-double-grid max-periods n)
     :fail-avg (%make-double-grid max-periods n)
     :txct-avg (make-array n :element-type 'double-float :initial-element 0d0)
     :feerate-avg (make-array n :element-type 'double-float :initial-element 0d0)
     :unconf-txs (%make-fixnum-grid (* scale max-periods) n)
     :old-unconf-txs (make-array n :element-type 'fixnum :initial-element 0))))

(defun tx-confirm-stats-max-confirms (stats)
  "Core GetMaxConfirms: scale * number of periods."
  (* (tx-confirm-stats-scale stats)
     (length (tx-confirm-stats-conf-avg stats))))

(defun tx-confirm-stats-clear-current (stats height)
  "Roll the unconfirmed circular buffer for HEIGHT (Core ClearCurrent): whatever
still sits in this slot has now aged out of the window, so it moves to
OLD-UNCONF-TXS rather than being forgotten."
  (let* ((unconf (tx-confirm-stats-unconf-txs stats))
         (old (tx-confirm-stats-old-unconf-txs stats))
         (row (aref unconf (mod height (length unconf)))))
    (dotimes (j (length (tx-confirm-stats-buckets stats)))
      (incf (aref old j) (aref row j))
      (setf (aref row j) 0))))

(defun tx-confirm-stats-record (stats blocks-to-confirm feerate)
  "Record that a transaction at FEERATE confirmed after BLOCKS-TO-CONFIRM blocks
(Core Record). BLOCKS-TO-CONFIRM is 1-based; anything under 1 is ignored.

The confirmation counts every period at or beyond the one it landed in, so
CONF-AVG[p] answers \"how many confirmed within p+1 periods\" directly."
  (when (< blocks-to-confirm 1)
    (return-from tx-confirm-stats-record))
  (let* ((scale (tx-confirm-stats-scale stats))
         (periods-to-confirm (floor (+ blocks-to-confirm scale -1) scale))
         (conf-avg (tx-confirm-stats-conf-avg stats))
         (bucket (fee-bucket-index (tx-confirm-stats-buckets stats) feerate)))
    (loop for i from periods-to-confirm to (length conf-avg)
          do (incf (aref (aref conf-avg (1- i)) bucket) 1d0))
    (incf (aref (tx-confirm-stats-txct-avg stats) bucket) 1d0)
    (incf (aref (tx-confirm-stats-feerate-avg stats) bucket) feerate)))

(defun tx-confirm-stats-update-moving-averages (stats)
  "Decay every counter one step (Core UpdateMovingAverages), so old blocks fade
out of the estimate instead of being dropped at a hard boundary."
  (let ((decay (tx-confirm-stats-decay stats))
        (conf-avg (tx-confirm-stats-conf-avg stats))
        (fail-avg (tx-confirm-stats-fail-avg stats))
        (txct (tx-confirm-stats-txct-avg stats))
        (feerate (tx-confirm-stats-feerate-avg stats)))
    (dotimes (i (length conf-avg))
      (let ((crow (aref conf-avg i))
            (frow (aref fail-avg i)))
        (dotimes (j (length crow))
          (setf (aref crow j) (* (aref crow j) decay)
                (aref frow j) (* (aref frow j) decay)))))
    (dotimes (j (length txct))
      (setf (aref txct j) (* (aref txct j) decay)
            (aref feerate j) (* (aref feerate j) decay)))))

(defun tx-confirm-stats-new-tx (stats height feerate)
  "Note a transaction entering the mempool at HEIGHT. Returns its bucket index,
which the caller must remember in order to remove it later."
  (let* ((bucket (fee-bucket-index (tx-confirm-stats-buckets stats) feerate))
         (unconf (tx-confirm-stats-unconf-txs stats)))
    (incf (aref (aref unconf (mod height (length unconf))) bucket))
    bucket))

(defun tx-confirm-stats-remove-tx (stats entry-height best-height bucket in-block)
  "Remove a tracked transaction (Core removeTx). IN-BLOCK distinguishes a
confirmation from an eviction: only an eviction after a full period counts as a
FAILURE, which is the signal that pushes estimates up."
  (let* ((unconf (tx-confirm-stats-unconf-txs stats))
         (bins (length unconf))
         (blocks-ago (if (zerop best-height) 0 (- best-height entry-height))))
    (when (minusp blocks-ago)
      (return-from tx-confirm-stats-remove-tx nil))
    (if (>= blocks-ago bins)
        (let ((old (tx-confirm-stats-old-unconf-txs stats)))
          (when (plusp (aref old bucket))
            (decf (aref old bucket))))
        (let ((row (aref unconf (mod entry-height bins))))
          (when (plusp (aref row bucket))
            (decf (aref row bucket)))))
    (let ((scale (tx-confirm-stats-scale stats)))
      (when (and (not in-block) (>= blocks-ago scale))
        (let ((periods-ago (floor blocks-ago scale))
              (fail-avg (tx-confirm-stats-fail-avg stats)))
          (dotimes (i (min periods-ago (length fail-avg)))
            (incf (aref (aref fail-avg i) bucket) 1d0)))))
    t))

(defun tx-confirm-stats-estimate-median (stats conf-target sufficient-tx-val
                                         success-break-point height)
  "The feerate that confirmed within CONF-TARGET blocks at least
SUCCESS-BREAK-POINT of the time, or -1 when the data cannot support an answer
(Core EstimateMedianVal).

Walks buckets from the most expensive down, merging them until a range holds
enough confirmations to judge, then asks whether that range's success rate
clears the bar. The lowest range that still clears it wins, and its
transaction-weighted average feerate is the answer. Transactions still sitting
in the mempool past the target, and those evicted unconfirmed, both count
AGAINST the rate — without them a bucket nobody could get confirmed would look
perfect for lack of evidence."
  (let* ((buckets (tx-confirm-stats-buckets stats))
         (scale (tx-confirm-stats-scale stats))
         (decay (tx-confirm-stats-decay stats))
         (conf-avg (tx-confirm-stats-conf-avg stats))
         (fail-avg (tx-confirm-stats-fail-avg stats))
         (txct (tx-confirm-stats-txct-avg stats))
         (feerate-avg (tx-confirm-stats-feerate-avg stats))
         (unconf (tx-confirm-stats-unconf-txs stats))
         (old-unconf (tx-confirm-stats-old-unconf-txs stats))
         (bins (length unconf))
         (max-bucket (1- (length buckets)))
         (period-target (floor (+ conf-target scale -1) scale))
         (n-conf 0d0) (total-num 0d0) (extra-num 0) (fail-num 0d0)
         (partial-num 0d0)
         (cur-near max-bucket) (cur-far max-bucket)
         (best-near max-bucket) (best-far max-bucket)
         (found-answer nil)
         (new-range t)
         ;; Core's EstimationResult bookkeeping (block_policy_estimator.cpp:
         ;; 276-277, 300-340). Reported by estimaterawfee, which is the only
         ;; way an operator can see WHY an estimate came out where it did.
         (passing t)
         (pass-bucket nil)
         (fail-bucket nil))
    (when (or (< period-target 1) (> period-target (length conf-avg)))
      (return-from tx-confirm-stats-estimate-median -1d0))
    (loop for bucket from max-bucket downto 0
          do (when new-range
               (setf cur-near bucket new-range nil))
             (setf cur-far bucket)
             (incf n-conf (aref (aref conf-avg (1- period-target)) bucket))
             (incf partial-num (aref txct bucket))
             (incf total-num (aref txct bucket))
             (incf fail-num (aref (aref fail-avg (1- period-target)) bucket))
             (loop for confct from conf-target below (tx-confirm-stats-max-confirms stats)
                   do (incf extra-num (aref (aref unconf (mod (- height confct) bins)) bucket)))
             (incf extra-num (aref old-unconf bucket))
             (when (>= partial-num (/ sufficient-tx-val (- 1d0 decay)))
               (setf partial-num 0d0)
               (let ((cur-pct (/ n-conf (+ total-num fail-num extra-num))))
                 (cond
                   ((< cur-pct success-break-point)
                    ;; Record the FIRST failing range only (Core's `passing`
                    ;; latch): later ranges are worse and would overwrite the
                    ;; boundary the operator needs to see.
                    (when passing
                      (let ((lo (min cur-near cur-far))
                            (hi (max cur-near cur-far)))
                        (setf fail-bucket
                              (list :start (if (plusp lo) (aref buckets (1- lo)) 0)
                                    :end (aref buckets hi)
                                    :within-target n-conf
                                    :total-confirmed total-num
                                    :in-mempool extra-num
                                    :left-mempool fail-num)
                              passing nil))))
                   (t
                    ;; Passing again clears any recorded failure, as Core does.
                    (setf fail-bucket nil
                          passing t
                          found-answer t)
                    (setf pass-bucket
                          (list :start 0 :end 0   ; filled from the winning range below
                                :within-target n-conf
                                :total-confirmed total-num
                                :in-mempool extra-num
                                :left-mempool fail-num))
                    (setf n-conf 0d0 total-num 0d0 fail-num 0d0 extra-num 0
                          best-near cur-near best-far cur-far
                          new-range t))))))
    ;; The winning range's transaction-weighted average feerate: find the bucket
    ;; holding the median transaction and report ITS average, which is as close
    ;; to a median as a bucketed history can get.
    (let ((min-bucket (min best-near best-far))
          (max-b (max best-near best-far))
          (tx-sum 0d0)
          (median -1d0))
      (loop for j from min-bucket to max-b do (incf tx-sum (aref txct j)))
      (when (and found-answer (/= tx-sum 0d0))
        (setf tx-sum (/ tx-sum 2))
        (loop for j from min-bucket to max-b
              do (if (< (aref txct j) tx-sum)
                     (decf tx-sum (aref txct j))
                     (progn (setf median (/ (aref feerate-avg j) (aref txct j)))
                            (return))))
        ;; The winning range's boundaries (Core :367-368), known only now.
        (when pass-bucket
          (setf (getf pass-bucket :start)
                (if (plusp min-bucket) (aref buckets (1- min-bucket)) 0)
                (getf pass-bucket :end) (aref buckets max-b))))
      ;; Second value: Core's EstimationResult, for estimaterawfee. Callers
      ;; that only want the median ignore it, which is every caller but one.
      (values median
              (list :pass pass-bucket :fail fail-bucket
                    :decay decay :scale scale)))))

;;;; --- The estimator: three horizons over one bucket set ---

(defstruct (block-policy-estimator (:constructor %make-block-policy-estimator))
  "Core CBlockPolicyEstimator. SHORT/MED/LONG track the same buckets with
different decay rates and period lengths, so a near target can react quickly
while a distant one stays stable.

TRACKED maps a txid to (entry-height short-bucket med-bucket long-bucket) for
every transaction currently in the mempool that counts toward estimates."
  (buckets #() :type simple-vector)
  (short nil) (med nil) (long nil)
  (tracked (make-hash-table :test 'equalp) :type hash-table)
  ;; Core trackedTxs / untrackedTxs (block_policy_estimator.h:249-252): how
  ;; many transactions since the last block were recorded and how many were
  ;; dropped by validForFeeEstimation. Reported and reset by processBlock.
  (tracked-txs 0 :type (integer 0))
  (untracked-txs 0 :type (integer 0))
  (best-height 0 :type (integer 0))
  (first-recorded-height 0 :type (integer 0))
  (historical-first 0 :type (integer 0))
  (historical-best 0 :type (integer 0)))

(defun make-block-policy-estimator ()
  (let ((buckets (make-fee-buckets)))
    (%make-block-policy-estimator
     :buckets buckets
     :short (make-tx-confirm-stats buckets +short-block-periods+ +short-decay+ +short-scale+)
     :med (make-tx-confirm-stats buckets +med-block-periods+ +med-decay+ +med-scale+)
     :long (make-tx-confirm-stats buckets +long-block-periods+ +long-decay+ +long-scale+))))

(defun bpe-process-transaction (est txid height feerate
                                &key bypass-limits package-submission
                                     (chainstate-current t)
                                     (has-no-mempool-parents t))
  "A transaction entered the mempool at HEIGHT paying FEERATE sat/kvB (Core
processTransaction, block_policy_estimator.cpp:595-637). Returns T when it was
recorded in all three horizons, NIL when a gate dropped it.

TWO gates, and both are Core's, because an estimator that learns from the wrong
transactions is worse than one with no data:

  - HEIGHT must equal the estimator's own best seen height. Core: `Ignore side
    chains and re-orgs; ... Ignore txs if BlockPolicyEstimator is not in sync
    with ActiveChain().Tip()'. This alone drops every transaction replayed
    from mempool.dat at start-up, when the estimator's best height is still 0.
  - validForFeeEstimation, which is the AND of the four flags Core carries in
    NewMempoolTransactionInfo (kernel/mempool_entry.h:173-199) and fills in at
    the ATMP call site (validation.cpp:1304-1307, 1408-1411): not re-added
    during a reorg with the mempool limits bypassed, not submitted as part of
    a package, the chainstate current, and no unconfirmed parents.

The last one is the expensive one to get wrong: a CPFP child teaches the
estimator that its own low feerate confirmed in one block, which is exactly
the inference the parent paid for. Measured on a 400-block synthetic replay,
tracking the children answered 1000 sat/kvB where Core's gate answers 20000.

The defaults are the ordinary single-transaction acceptance, so a caller that
names nothing gets Core's normal path; the two exclusions that must be
declared are declared by the two callers Core declares them at."
  (let ((tracked (block-policy-estimator-tracked est)))
    (when (gethash txid tracked)
      (return-from bpe-process-transaction nil))
    (unless (= height (block-policy-estimator-best-height est))
      (return-from bpe-process-transaction nil))
    (unless (and (not bypass-limits)
                 (not package-submission)
                 chainstate-current
                 has-no-mempool-parents)
      (incf (block-policy-estimator-untracked-txs est))
      (return-from bpe-process-transaction nil))
    (incf (block-policy-estimator-tracked-txs est))
    (setf (gethash txid tracked)
          (list height feerate
                (tx-confirm-stats-new-tx (block-policy-estimator-short est) height feerate)
                (tx-confirm-stats-new-tx (block-policy-estimator-med est) height feerate)
                (tx-confirm-stats-new-tx (block-policy-estimator-long est) height feerate)))
    t))

(defun bpe-remove-tx (est txid in-block)
  "A tracked transaction left the mempool (Core removeTx). IN-BLOCK means it
confirmed; otherwise it was evicted or replaced, which is recorded as a failure
at its feerate. Returns T if the transaction was tracked."
  (let* ((tracked (block-policy-estimator-tracked est))
         (entry (gethash txid tracked)))
    (when entry
      (destructuring-bind (height feerate short-b med-b long-b) entry
        (declare (ignore feerate))
       (let ((best (block-policy-estimator-best-height est)))
          (tx-confirm-stats-remove-tx (block-policy-estimator-short est)
                                      height best short-b in-block)
          (tx-confirm-stats-remove-tx (block-policy-estimator-med est)
                                      height best med-b in-block)
          (tx-confirm-stats-remove-tx (block-policy-estimator-long est)
                                      height best long-b in-block)))
      (remhash txid tracked)
      t)))

(defun bpe-process-block (est height confirmed)
  "A block at HEIGHT confirmed the transactions named by CONFIRMED, a list of
txids (Core processBlock). Untracked txids are ignored, so the caller can pass
every txid in the block; the feerate comes from what was recorded at entry,
which is the only feerate the estimate may use.

Order matters and mirrors Core: roll the circular buffer and decay FIRST, so
this block's own data is not immediately decayed, then record each confirmation
against the number of blocks it waited."
  (when (<= height (block-policy-estimator-best-height est))
    (return-from bpe-process-block 0))
  (setf (block-policy-estimator-best-height est) height)
  (dolist (stats (list (block-policy-estimator-short est)
                       (block-policy-estimator-med est)
                       (block-policy-estimator-long est)))
    (tx-confirm-stats-clear-current stats height)
    (tx-confirm-stats-update-moving-averages stats))
  (let ((counted 0))
    (dolist (txid confirmed)
      (let ((entry (gethash txid (block-policy-estimator-tracked est))))
        (when entry
          (let ((blocks-to-confirm (- height (first entry)))
                (feerate (second entry)))
            ;; removeTx first, so the transaction stops counting as unconfirmed
            ;; before its confirmation is recorded.
            (bpe-remove-tx est txid t)
            (when (plusp blocks-to-confirm)
              (incf counted)
              (tx-confirm-stats-record (block-policy-estimator-short est)
                                       blocks-to-confirm feerate)
              (tx-confirm-stats-record (block-policy-estimator-med est)
                                       blocks-to-confirm feerate)
              (tx-confirm-stats-record (block-policy-estimator-long est)
                                       blocks-to-confirm feerate))))))
    ;; Only a block that actually CONTRIBUTED data starts the clock (Core
    ;; :704 requires countedTxs > 0). Starting it on an empty block would
    ;; inflate the observed block span and let MaxUsableEstimate answer targets
    ;; the history cannot support.
    (when (and (zerop (block-policy-estimator-first-recorded-height est))
               (plusp counted))
      (setf (block-policy-estimator-first-recorded-height est) height))
    ;; Core reports and RESETS the per-block counters here (:704-712), which is
    ;; what makes the validForFeeEstimation gate observable rather than a
    ;; silent drop.
    (bl:log-cat "estimatefee"
                "Fee estimates updated by ~D of ~D block txs, since last ~
block ~D of ~D tracked, mempool map size ~D"
                counted (length confirmed)
                (block-policy-estimator-tracked-txs est)
                (+ (block-policy-estimator-tracked-txs est)
                   (block-policy-estimator-untracked-txs est))
                (hash-table-count (block-policy-estimator-tracked est)))
    (setf (block-policy-estimator-tracked-txs est) 0
          (block-policy-estimator-untracked-txs est) 0)
    counted))

(defun %bpe-block-span (est)
  (let ((first (block-policy-estimator-first-recorded-height est)))
    (if (zerop first) 0 (- (block-policy-estimator-best-height est) first))))

(defun %bpe-historical-block-span (est)
  (let ((first (block-policy-estimator-historical-first est))
        (best (block-policy-estimator-historical-best est)))
    (cond ((or (zerop first) (zerop best)) 0)
          ((> (- (block-policy-estimator-best-height est) best)
              +oldest-estimate-history+)
           0)
          (t (- best first)))))

(defun bpe-max-usable-estimate (est)
  "The furthest target this much history can justify (Core MaxUsableEstimate).
Halved because an estimate needs enough potential FAILURES to be meaningful, not
just enough confirmations."
  (min (tx-confirm-stats-max-confirms (block-policy-estimator-long est))
       (floor (max (%bpe-block-span est) (%bpe-historical-block-span est)) 2)))

(defun %bpe-combined-fee (est conf-target success-threshold check-shorter)
  "Core estimateCombinedFee: answer from the SHORTEST horizon that tracks
CONF-TARGET, and when CHECK-SHORTER is set let a shorter horizon's maximum
target lower the answer — that is what keeps estimates monotonic in the target."
  (let ((short (block-policy-estimator-short est))
        (med (block-policy-estimator-med est))
        (long (block-policy-estimator-long est))
        (height (block-policy-estimator-best-height est))
        (estimate -1d0))
    (when (and (>= conf-target 1)
               (<= conf-target (tx-confirm-stats-max-confirms long)))
      (setf estimate
            (cond
              ((<= conf-target (tx-confirm-stats-max-confirms short))
               (tx-confirm-stats-estimate-median short conf-target
                                                 +sufficient-txs-short+
                                                 success-threshold height))
              ((<= conf-target (tx-confirm-stats-max-confirms med))
               (tx-confirm-stats-estimate-median med conf-target
                                                 +sufficient-feetxs+
                                                 success-threshold height))
              (t
               (tx-confirm-stats-estimate-median long conf-target
                                                 +sufficient-feetxs+
                                                 success-threshold height))))
      (when check-shorter
        (when (> conf-target (tx-confirm-stats-max-confirms med))
          (let ((med-max (tx-confirm-stats-estimate-median
                          med (tx-confirm-stats-max-confirms med)
                          +sufficient-feetxs+ success-threshold height)))
            (when (and (plusp med-max) (or (= estimate -1d0) (< med-max estimate)))
              (setf estimate med-max))))
        (when (> conf-target (tx-confirm-stats-max-confirms short))
          (let ((short-max (tx-confirm-stats-estimate-median
                            short (tx-confirm-stats-max-confirms short)
                            +sufficient-txs-short+ success-threshold height)))
            (when (and (plusp short-max) (or (= estimate -1d0) (< short-max estimate)))
              (setf estimate short-max))))))
    estimate))

(defun %bpe-conservative-fee (est double-target)
  "Core estimateConservativeFee: require DOUBLE_SUCCESS_PCT at twice the target
on the LONGER horizons too, so a short-term dip cannot pull the answer down."
  (let ((short (block-policy-estimator-short est))
        (med (block-policy-estimator-med est))
        (long (block-policy-estimator-long est))
        (height (block-policy-estimator-best-height est))
        (estimate -1d0))
    (when (<= double-target (tx-confirm-stats-max-confirms short))
      (setf estimate (tx-confirm-stats-estimate-median
                      med double-target +sufficient-feetxs+
                      +double-success-pct+ height)))
    (when (<= double-target (tx-confirm-stats-max-confirms med))
      (let ((long-estimate (tx-confirm-stats-estimate-median
                            long double-target +sufficient-feetxs+
                            +double-success-pct+ height)))
        (when (> long-estimate estimate)
          (setf estimate long-estimate))))
    estimate))

(defun bpe-estimate-smart-fee (est conf-target &key conservative)
  "Core estimateSmartFee: the MAX of three sub-estimates — 60% success at half
the target, 85% at the target, 95% at twice it — each taken from the shortest
horizon that tracks it. Returns satoshis per kvB, or 0 when history cannot
support an answer.

Taking the max is what makes the estimate monotonic in the target and keeps a
single quiet stretch from collapsing it."
  (let ((long (block-policy-estimator-long est)))
    (when (or (<= conf-target 0)
              (> conf-target (tx-confirm-stats-max-confirms long)))
      (return-from bpe-estimate-smart-fee (values 0 conf-target)))
    ;; A 1-block target cannot be estimated: there is no shorter horizon to
    ;; cross-check it against (Core does the same substitution).
    (when (= conf-target 1) (setf conf-target 2))
    (let ((max-usable (bpe-max-usable-estimate est)))
      (when (> conf-target max-usable) (setf conf-target max-usable)))
    (when (<= conf-target 1)
      (return-from bpe-estimate-smart-fee (values 0 conf-target)))
    (let ((median (%bpe-combined-fee est (floor conf-target 2) +half-success-pct+ t)))
      (let ((actual (%bpe-combined-fee est conf-target +success-pct+ t)))
        (when (> actual median) (setf median actual)))
      (let ((double-est (%bpe-combined-fee est (* 2 conf-target)
                                           +double-success-pct+
                                           (not conservative))))
        (when (> double-est median) (setf median double-est)))
      (when (or conservative (= median -1d0))
        (let ((cons-est (%bpe-conservative-fee est (* 2 conf-target))))
          (when (> cons-est median) (setf median cons-est))))
      ;; The SECOND value is Core's feeCalc.returnedTarget: the target the
      ;; answer is actually for, after the 1->2 substitution and the clamp to
      ;; what the history can justify. estimatesmartfee reports THIS as
      ;; "blocks", not the number the caller asked for — a caller told
      ;; "blocks: 1008" when the estimator could only justify 100 has been
      ;; misinformed about what it is paying for.
      (values (if (minusp median) 0 (round median)) conf-target))))

;;;; --- The node-wide instance and its reporting seam ---
;;;;
;;;; Core routes these three events through the validation interface. We use a
;;;; special variable for the same reason: the mempool and connect-block should
;;;; report what happened without holding a reference to the estimator, and a
;;;; node that has no estimator (tests, tools) should cost nothing.

(defvar *block-policy-estimator* nil
  "The node's CBlockPolicyEstimator, installed at startup. NIL disables
collection entirely.")

(defun bpe-note-entry (txid fee vsize height
                       &key bypass-limits package-submission
                            (chainstate-current t)
                            (has-no-mempool-parents t))
  "A transaction entered the mempool. FEE in satoshis, VSIZE in vbytes -- the
same pair Core's CFeeRate(fee, size) takes, converted to satoshis per kvB.

The four keywords are Core's NewMempoolTransactionInfo flags, carried here
rather than decided at the call site so a future acceptance path cannot opt
out of the gate by forgetting to apply it; BPE-PROCESS-TRANSACTION is where
they are read."
  (let ((est *block-policy-estimator*))
    (when (and est (plusp vsize))
      (bpe-process-transaction est txid height
                               (/ (* (float fee 1d0) 1000d0) (float vsize 1d0))
                               :bypass-limits bypass-limits
                               :package-submission package-submission
                               :chainstate-current chainstate-current
                               :has-no-mempool-parents has-no-mempool-parents))))

(defun bpe-note-removal (txid &key in-block)
  "A transaction left the mempool. IN-BLOCK means it confirmed; anything else
counts as a failure at its feerate, which is the signal that raises estimates."
  (let ((est *block-policy-estimator*))
    (when est
      (bpe-remove-tx est txid in-block))))

(defun bpe-note-block (height txids)
  "A block at HEIGHT confirmed TXIDS. Untracked ones are ignored, so callers may
pass every txid in the block."
  (let ((est *block-policy-estimator*))
    (when est
      (bpe-process-block est height txids))))

(defun bpe-estimate-raw-fee (conf-target threshold horizon)
  "Core CBlockPolicyEstimator::estimateRawFee: the feerate for one HORIZON at
one success THRESHOLD, plus the pass/fail buckets that produced it.

Returns (values sat-per-kvb result), or (values nil nil) when the horizon does
not track CONF-TARGET. Unlike estimateSmartFee this asks ONE horizon at ONE
threshold and reports the raw answer, which is exactly what makes it a
debugging tool: it shows the evidence rather than the max of three estimates."
  (let ((est *block-policy-estimator*))
    (when est
      (let* ((stats (ecase horizon
                      (:short (block-policy-estimator-short est))
                      (:medium (block-policy-estimator-med est))
                      (:long (block-policy-estimator-long est))))
             (sufficient (if (eq horizon :short)
                             +sufficient-txs-short+
                             +sufficient-feetxs+)))
        (when (and (>= conf-target 1)
                   (<= conf-target (tx-confirm-stats-max-confirms stats)))
          (multiple-value-bind (median result)
              (tx-confirm-stats-estimate-median
               stats conf-target sufficient threshold
               (block-policy-estimator-best-height est))
            (values (if (minusp median) 0 median) result)))))))

(defun horizon-max-confirms (horizon)
  "The furthest target HORIZON tracks (Core HighestTargetTracked)."
  (let ((est *block-policy-estimator*))
    (when est
      (tx-confirm-stats-max-confirms
       (ecase horizon
         (:short (block-policy-estimator-short est))
         (:medium (block-policy-estimator-med est))
         (:long (block-policy-estimator-long est)))))))

(defun highest-target-tracked ()
  "The furthest conf_target estimatesmartfee will accept — Core
HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE), which is the long
horizon's max_confirms (rpc/fees.cpp:70). Bounding by a fixed 1008 instead, as
we did, accepts targets the estimator provably cannot answer and then reports
the fabricated fallback for them."
  (let ((est *block-policy-estimator*))
    (if est
        (tx-confirm-stats-max-confirms (block-policy-estimator-long est))
        1008)))

(defun bpe-smart-fee-sat-per-vb (conf-target &key conservative)
  "estimateSmartFee in satoshis per VBYTE — the unit ESTIMATE-FEE-RATE reports —
or NIL when the history cannot support an answer. The second value is the
target the answer is FOR (Core feeCalc.returnedTarget), which is not always the
one asked for."
  (let ((est *block-policy-estimator*))
    (when est
      (multiple-value-bind (per-kvb returned-target)
          (bpe-estimate-smart-fee est conf-target :conservative conservative)
        (when (plusp per-kvb)
          (values (/ per-kvb 1000) returned-target))))))

;;;; --- Persistence (Core CBlockPolicyEstimator::Write / Read) ---
;;;;
;;;; The layout is ours, not Core's: this file is read by nothing but this node,
;;;; so there is no interop requirement to pay for, and our fee_estimates.dat
;;;; already carries a CRC32 that Core's does not. What IS copied from Core is
;;;; the part that matters — WHICH state is durable, and the discipline on load.
;;;;
;;;; Everything is read into temporaries and swapped in only once every check
;;;; has passed (Core: "so existing data structures aren't corrupted if there is
;;;; an exception"). A half-loaded estimator would answer with confidence from
;;;; nonsense, and fee estimates are spent money.
;;;;
;;;; The unconfirmed-transaction counters are deliberately NOT stored. They
;;;; describe transactions this process was watching; after a restart the
;;;; mempool is reloaded and re-reported, so persisting them would double-count.

(defun %write-double-le (stream d)
  "A double-float as its 8 IEEE-754 bytes, little-endian."
  (let ((u (ldb (byte 64 0) (sb-kernel:double-float-bits (float d 1d0)))))
    (dotimes (i 8)
      (write-byte (ldb (byte 8 (* 8 i)) u) stream))))

(defun %read-double-le (stream)
  (let ((u 0))
    (dotimes (i 8)
      (setf u (logior u (ash (read-byte stream) (* 8 i)))))
    (let ((hi (ldb (byte 32 32) u))
          (lo (ldb (byte 32 0) u)))
      (sb-kernel:make-double-float
       (if (>= hi #x80000000) (- hi #x100000000) hi)
       lo))))

(defun %write-double-vector (stream v)
  (bl.ser:write-uint32-le stream (length v))
  (loop for x across v do (%write-double-le stream x)))

(defun %read-double-vector (stream expected-length)
  "A double vector whose length must equal EXPECTED-LENGTH, or NIL when it does
not — every per-bucket array in the file has to agree with the bucket set."
  (let ((n (bl.ser:read-uint32-le stream)))
    (unless (= n expected-length)
      (return-from %read-double-vector nil))
    (let ((v (make-array n :element-type 'double-float)))
      (dotimes (i n v)
        (setf (aref v i) (%read-double-le stream))))))

(defun %write-tx-confirm-stats (stream stats)
  (%write-double-le stream (tx-confirm-stats-decay stats))
  (bl.ser:write-uint32-le stream (tx-confirm-stats-scale stats))
  (%write-double-vector stream (tx-confirm-stats-feerate-avg stats))
  (%write-double-vector stream (tx-confirm-stats-txct-avg stats))
  (let ((conf (tx-confirm-stats-conf-avg stats))
        (fail (tx-confirm-stats-fail-avg stats)))
    (bl.ser:write-uint32-le stream (length conf))
    (loop for row across conf do (%write-double-vector stream row))
    (bl.ser:write-uint32-le stream (length fail))
    (loop for row across fail do (%write-double-vector stream row))))

(defun %read-tx-confirm-stats (stream buckets)
  "One horizon, or NIL if anything about it fails Core's sanity checks
(TxConfirmStats::Read). The caller discards the whole file on NIL."
  (let* ((n-buckets (length buckets))
         (decay (%read-double-le stream))
         (scale (bl.ser:read-uint32-le stream)))
    ;; Core: decay must be strictly inside (0,1), scale non-zero.
    (when (or (<= decay 0d0) (>= decay 1d0) (zerop scale))
      (return-from %read-tx-confirm-stats nil))
    (let ((feerate-avg (%read-double-vector stream n-buckets)))
      (unless feerate-avg (return-from %read-tx-confirm-stats nil))
      (let ((txct-avg (%read-double-vector stream n-buckets)))
        (unless txct-avg (return-from %read-tx-confirm-stats nil))
        (let ((n-periods (bl.ser:read-uint32-le stream)))
          ;; Core: between 1 and 1008 confirms (one week) may be tracked.
          (let ((max-confirms (* scale n-periods)))
            (when (or (zerop max-confirms) (> max-confirms (* 6 24 7)))
              (return-from %read-tx-confirm-stats nil)))
          (let ((conf (make-array n-periods)))
            (dotimes (i n-periods)
              (let ((row (%read-double-vector stream n-buckets)))
                (unless row (return-from %read-tx-confirm-stats nil))
                (setf (aref conf i) row)))
            (let ((n-fail (bl.ser:read-uint32-le stream)))
              (unless (= n-fail n-periods)
                (return-from %read-tx-confirm-stats nil))
              (let ((fail (make-array n-periods)))
                (dotimes (i n-periods)
                  (let ((row (%read-double-vector stream n-buckets)))
                    (unless row (return-from %read-tx-confirm-stats nil))
                    (setf (aref fail i) row)))
                ;; The unconfirmed counters are per-run, not persisted: a fresh
                ;; zeroed set, sized to this bucket count.
                (let ((stats (make-tx-confirm-stats buckets n-periods decay scale)))
                  (setf (tx-confirm-stats-feerate-avg stats) feerate-avg
                        (tx-confirm-stats-txct-avg stats) txct-avg
                        (tx-confirm-stats-conf-avg stats) conf
                        (tx-confirm-stats-fail-avg stats) fail)
                  stats)))))))))

(defun bpe-write-to-stream (est stream)
  "Serialize EST. Mirrors Core's choice of which block range to record: the
live one while it is the longer, otherwise the range carried over from the
file we loaded."
  (bl.ser:write-uint32-le stream (block-policy-estimator-best-height est))
  (if (> (%bpe-block-span est) (floor (%bpe-historical-block-span est) 2))
      (progn
        (bl.ser:write-uint32-le
         stream (block-policy-estimator-first-recorded-height est))
        (bl.ser:write-uint32-le
         stream (block-policy-estimator-best-height est)))
      (progn
        (bl.ser:write-uint32-le
         stream (block-policy-estimator-historical-first est))
        (bl.ser:write-uint32-le
         stream (block-policy-estimator-historical-best est))))
  (%write-double-vector stream (block-policy-estimator-buckets est))
  (%write-tx-confirm-stats stream (block-policy-estimator-med est))
  (%write-tx-confirm-stats stream (block-policy-estimator-short est))
  (%write-tx-confirm-stats stream (block-policy-estimator-long est))
  t)

(defun bpe-read-into (est stream)
  "Load EST from STREAM, or return NIL and leave EST untouched.

Nothing is installed until every horizon has parsed and every check has passed
— a partially applied estimator would answer confidently from nonsense."
  (handler-case
      (let* ((best-height (bl.ser:read-uint32-le stream))
             (hist-first (bl.ser:read-uint32-le stream))
             (hist-best (bl.ser:read-uint32-le stream)))
        ;; Core: the recorded range must be ordered and must not claim to run
        ;; past the best height the file itself reports.
        (when (or (> hist-first hist-best) (> hist-best best-height))
          (return-from bpe-read-into nil))
        (let ((n-buckets (bl.ser:read-uint32-le stream)))
          ;; Core: between 2 and 1000 feerate buckets.
          (when (or (< n-buckets 2) (> n-buckets 1000))
            (return-from bpe-read-into nil))
          (let ((buckets (make-array n-buckets)))
            (dotimes (i n-buckets)
              (setf (aref buckets i) (%read-double-le stream)))
            ;; A file written against a different bucket set cannot be
            ;; reinterpreted against this one -- every per-bucket count would
            ;; silently mean something else. Discard rather than remap.
            (unless (equalp buckets (make-fee-buckets))
              (return-from bpe-read-into nil))
            (let ((med (%read-tx-confirm-stats stream buckets)))
              (unless med (return-from bpe-read-into nil))
              (let ((short (%read-tx-confirm-stats stream buckets)))
                (unless short (return-from bpe-read-into nil))
                (let ((long (%read-tx-confirm-stats stream buckets)))
                  (unless long (return-from bpe-read-into nil))
                  ;; Everything parsed: install as one step.
                  (setf (block-policy-estimator-buckets est) buckets
                        (block-policy-estimator-med est) med
                        (block-policy-estimator-short est) short
                        (block-policy-estimator-long est) long
                        (block-policy-estimator-best-height est) best-height
                        (block-policy-estimator-historical-first est) hist-first
                        (block-policy-estimator-historical-best est) hist-best
                        (block-policy-estimator-first-recorded-height est) 0)
                  (clrhash (block-policy-estimator-tracked est))
                  t))))))
    (error () nil)))
