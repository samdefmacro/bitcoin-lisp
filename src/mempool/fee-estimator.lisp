(in-package #:bitcoin-lisp.mempool)

;;; fee_estimates.dat: where the policy estimator (block-policy-estimator.lisp,
;;; Core's CBlockPolicyEstimator) is read from at start-up and flushed to --
;;; hourly, and at shutdown after recording the still-unconfirmed -- and the
;;; estimate the fee RPCs answer from it.

(defconstant +fee-estimates-max-file-age-hours+ 60
  "Core MAX_FILE_AGE (block_policy_estimator.h:33): fee estimates older than 60
hours are not read at all. They are historical data about a network whose
activity has since moved on, and a confidently wrong estimate is spent money.")

(defvar *accept-stale-fee-estimates* nil
  "Core -acceptstalefeeestimates (DEFAULT_ACCEPT_STALE_FEE_ESTIMATES = false):
load a fee_estimates.dat older than MAX_FILE_AGE anyway. Core allows this only
on regtest.")

(defun fee-estimates-path (data-directory)
  "The fee_estimates.dat in DATA-DIRECTORY (Core FeeestPath,
policy/fees/block_policy_estimator_args.cpp:10-16), or NIL without one."
  (when data-directory
    (merge-pathnames "fee_estimates.dat" data-directory)))

(defun save-fee-estimates (est)
  "Core CBlockPolicyEstimator::FlushFeeEstimates (block_policy_estimator.cpp:
963-976): write EST to its fee_estimates.dat. T when written; a failure is
Core's warning and nothing else -- the node carries on."
  (let ((path (block-policy-estimator-estimation-filepath est)))
    (when path
      (handler-case
          (with-open-file (stream path :direction :output
                                       :element-type '(unsigned-byte 8)
                                       :if-exists :supersede
                                       :if-does-not-exist :create)
            (bpe-write-to-stream est stream))
        (error ()
          (bl:log-warn "Failed to write fee estimates to ~A. Continue anyway."
                       (namestring path))
          (return-from save-fee-estimates nil)))
      ;; feature_fee_estimation.py:344 builds the whole sentence from the path
      ;; it expects the file at, so the path is part of it.
      (bl:log-cat "estimatefee" "Flushed fee estimates to ~A." (namestring path))
      t)))

(defun %file-age-hours (path)
  "Core GetFeeEstimatorFileAge: whole hours, truncated, against the FILESYSTEM
clock -- a mocked now and a real mtime would make a nonsense age."
  (floor (- (get-universal-time) (file-write-date path)) 3600))

(defun load-fee-estimates (est)
  "The file half of Core's CBlockPolicyEstimator constructor (block_policy_
estimator.cpp:561-576): read EST's fee_estimates.dat into it, unless there is
none or it is older than MAX_FILE_AGE. T when the file was read."
  (let ((path (block-policy-estimator-estimation-filepath est)))
    (cond
      ((null path) nil)
      ((not (probe-file path))
       (bl:log-info "~A is not found. Continue anyway." (namestring path))
       nil)
      ((and (> (%file-age-hours path) +fee-estimates-max-file-age-hours+)
            (not *accept-stale-fee-estimates*))
       (bl:log-warn "Fee estimation file ~A too old (age=~D > ~D hours) and will not be used to avoid serving stale estimates."
                    (namestring path) (%file-age-hours path)
                    +fee-estimates-max-file-age-hours+)
       nil)
      ((with-open-file (stream path :element-type '(unsigned-byte 8))
         (bpe-read-into est stream)))
      (t
       (bl:log-warn "Failed to read fee estimates from ~A. Continue anyway."
                    (namestring path))
       nil))))

(defconstant +fee-flush-interval-seconds+ 3600
  "Core FEE_FLUSH_INTERVAL (policy/fees/block_policy_estimator.h:27): the
scheduler calls FlushFeeEstimates once an hour (init.cpp:1662).")

(defvar *last-fee-estimate-flush-time* nil
  "When the hourly flush last ran, on the mockable clock. NIL until the first
call arms it, so the first flush is an hour after the node started rather
than at once — Core's scheduleEvery fires after the first interval.")

(defun flush-fee-estimates-at-shutdown (est)
  "Core CBlockPolicyEstimator::Flush, the shutdown flush (init.cpp:344-345,
block_policy_estimator.cpp:958-961): record every transaction EST still
tracks as unconfirmed (BPE-FLUSH-UNCONFIRMED), then write the file. The hourly
flush (MAYBE-FLUSH-FEE-ESTIMATES) writes without the first step, as Core's
scheduled FlushFeeEstimates does."
  (bpe-flush-unconfirmed est)
  (save-fee-estimates est))

(defun arm-fee-estimate-flush-clock ()
  "Start the hourly flush interval now (Core schedules FlushFeeEstimates at
startup, init.cpp:1662). Called from init rather than left to the first idle
tick: a node still inside its first sync pass has not ticked yet, and
`mockscheduler\' forwards the clock from wherever it is -- so a late arm puts
the deadline an hour PAST the forwarded time and the flush never comes."
  (setf *last-fee-estimate-flush-time* (bl.ser:get-scheduler-time)))

(defun maybe-flush-fee-estimates (est)
  "Flush EST to fee_estimates.dat on Core's hourly cadence (init.cpp:1662).

Driven off GET-SCHEDULER-TIME rather than a separate scheduler thread, which
is what makes Core's `mockscheduler' RPC advance it: feature_fee_estimation.py:
345 forwards an hour and then waits ONE second for the log line."
  (let ((now (bl.ser:get-scheduler-time)))
    (cond
      ((null *last-fee-estimate-flush-time*)
       (setf *last-fee-estimate-flush-time* now)
       nil)
      ((>= (- now *last-fee-estimate-flush-time*) +fee-flush-interval-seconds+)
       (setf *last-fee-estimate-flush-time* now)
       (save-fee-estimates est)
       t))))

;;;; Fee rate estimation

(defun estimate-fee-rate (conf-target &key (mode :conservative))
  "Core estimateSmartFee (rpc/fees.cpp:62-92, CBlockPolicyEstimator::
estimateSmartFee): the feerate in sat/vB that CONF-TARGET blocks of observed
history justify, or NO answer.

Returns (values fee-rate error-message returned-target). RETURNED-TARGET is
Core's feeCalc.returnedTarget, the target the answer is actually for -- the
estimator substitutes 2 for a 1-block target and clamps to what its history
can support -- and on failure the answer is NIL with Core's own message, never
a number.

⚠️ There used to be a second estimator behind this one: when the policy
estimator had no answer, a percentile of the median feerates of the last N
blocks was returned WITHOUT an error message, so the RPC reported it as a real
feerate and a wallet could not tell it apart from one. Core has no such
fallback, and the reason is the whole content of a fee estimate: a percentile
of what miners TOOK cannot express that a feerate FAILED to confirm, which is
the only thing that makes an estimate worth acting on. feature_fee_estimation.py
asserts the errors array twice. The per-block statistics that fallback read
are gone too."
  (multiple-value-bind (rate returned-target)
      (bpe-smart-fee-sat-per-vb conf-target :conservative (eq mode :conservative))
    (if (and rate (plusp rate))
        (values rate nil (or returned-target conf-target))
        (values nil "Insufficient data or no feerate found" conf-target))))
