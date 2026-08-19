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
         (new-range t))
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
                 (when (>= cur-pct success-break-point)
                   (setf found-answer t
                         n-conf 0d0 total-num 0d0 fail-num 0d0 extra-num 0
                         best-near cur-near best-far cur-far
                         new-range t)))))
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
                            (return)))))
      median)))
