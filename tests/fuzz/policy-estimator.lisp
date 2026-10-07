(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/policy_estimator.cpp and policy_estimator_io.cpp at the
;;;; pin (d3056bc149): CBlockPolicyEstimator (src/mempool/
;;;; block-policy-estimator.lisp) under random arrivals, removals, blocks and
;;;; flushes, queried after every step through estimateRawFee, estimateSmartFee
;;;; and HighestTargetTracked; then written and read back.
;;;;
;;;; Core's policy_estimator target asserts nothing beyond not crashing. The
;;;; port adds what Core's code guarantees and the estimator's callers rely
;;;; on: the set of tracked transactions is exactly what processTransaction's
;;;; gates admit (the estimator's own best height, the four
;;;; validForFeeEstimation flags) and processBlock / removeTx / FlushUnconfirmed
;;;; release; a tracked feerate is GetFeePerK, a whole number of sat/kvB; the
;;;; estimates are integers, zero for no answer, for a target the history can
;;;; support; each horizon tracks Core's number of targets; and what Write
;;;; writes, Read accepts and Write reproduces byte for byte. Core's
;;;; estimateFee (the deprecated plain estimate) has no counterpart.
;;;; policy_estimator_io's arbitrary-bytes reader is ported as a Read of any
;;;; buffer (fee_estimates.dat is Core's layout) that must either refuse it or
;;;; leave an estimator that writes back what it read.

(def-suite :fuzz-policy-estimator-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/policy_estimator.cpp and policy_estimator_io.cpp targets")

(in-suite :fuzz-policy-estimator-tests)

(defun policy-estimator-bytes (est)
  (flexi-streams:with-output-to-sequence (mem)
    (bl.mp:bpe-write-to-stream est mem)))

(defun policy-estimator-read (est bytes)
  (flexi-streams:with-input-from-sequence (in bytes)
    (bl.mp:bpe-read-into est in)))

(defun policy-estimator-consume-tx (fdp)
  "ConsumeDeserializable<CMutableTransaction>(TX_WITH_WITNESS)."
  (consume-deserializable
   fdp (lambda (bytes) (bl.ser:br-read-transaction (bl.ser:make-byte-reader-from bytes)))))

(define-fuzz-target policy-estimator
    (buffer :core "policy_estimator.cpp:30-116" :iterations 60 :max-len 1500
            :corpus (lambda (fdp)
                      ;; Serialized transactions where the target reads one,
                      ;; so arrivals get past the decoder.
                      (let ((out (make-array 0 :element-type '(unsigned-byte 8)
                                               :adjustable t :fill-pointer 0)))
                        (loop repeat (consume-integral-in-range fdp 1 8)
                              do (loop for b across (fdp-random-length-bytes
                                                     (bl.ser:serialize-transaction
                                                      (consume-transaction fdp :max-num-in 3 :max-num-out 3)))
                                       do (vector-push-extend b out)))
                        ;; A tail of its own for the integral reads, which
                        ;; come off the END and would otherwise eat into the
                        ;; last transaction.
                        (loop for b across (insecure-rand-bytes
                                            (make-insecure-random-context (consume-integral fdp :u64))
                                            512)
                              do (vector-push-extend b out))
                        (coerce out '(simple-array (unsigned-byte 8) (*))))))
  "The estimator tracks exactly the transactions Core's gates admit, at Core's
whole-satoshi feerate, releases them as blocks, removals and flushes say,
answers every query with a non-negative integer for a supportable target, and
round-trips its own file."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (est (bl.mp:make-block-policy-estimator))
         (bl.mp:*block-policy-estimator* est)
         (model (make-hash-table :test 'equalp)) ; txid -> t: what should be tracked
         (best 0)
         (current-height 0)
         (good t))
    (flet ((advance-height ()
             (setf current-height (consume-integral-in-range fdp current-height (ash 1 30) 32)))
           (check-tracked ()
             (let ((tracked (%bpe-tracked est)))
               (fuzz-assert (= (fuzz-sabotage (hash-table-count tracked)) (hash-table-count model))
                            "tracking ~D transactions, the gates admit ~D"
                            (hash-table-count tracked) (hash-table-count model))
               (maphash (lambda (txid v) (declare (ignore v))
                          (fuzz-assert (gethash txid tracked) "an admitted transaction is not tracked"))
                        model))))
      (advance-height)
      (limited-while ((and good (consume-bool fdp)) 10000)
        (call-one-of fdp
          ;; processTransaction, and maybe removeTx.
          (let ((tx (policy-estimator-consume-tx fdp)))
            (if (null tx)
                (setf good nil)
                (let* ((entry (consume-tx-mempool-entry fdp tx current-height))
                       (txid (bl.ser:transaction-hash tx))
                       (in-package (consume-bool fdp))
                       (has-parents (consume-bool fdp)))
                  (bl.mp:bpe-note-entry txid (getf entry :fee) (getf entry :vsize) (getf entry :height)
                                        :package-submission in-package
                                        :has-no-mempool-parents (not has-parents))
                  ;; Core processTransaction's gates (block_policy_estimator.cpp:
                  ;; 595-637): not already tracked, at the best height, valid
                  ;; for estimation.
                  (when (and (not (gethash txid model))
                             (= (getf entry :height) best)
                             (plusp (getf entry :vsize))
                             (not in-package) (not has-parents))
                    (setf (gethash txid model) t)
                    (let ((rec (gethash txid (%bpe-tracked est))))
                      (fuzz-assert (and rec (= (second rec)
                                               (floor (* (getf entry :fee) 1000) (getf entry :vsize))))
                                   "tracked at ~A sat/kvB, Core's GetFeePerK is ~D"
                                   (and rec (second rec))
                                   (floor (* (getf entry :fee) 1000) (getf entry :vsize)))))
                  (when (consume-bool fdp)
                    (bl.mp:bpe-note-removal txid)
                    (remhash txid model)))))
          ;; processBlock.
          (let ((txids '()))
            (limited-while ((consume-bool fdp) 10000)
              (let ((tx (policy-estimator-consume-tx fdp)))
                (when (null tx) (setf good nil) (return))
                (consume-tx-mempool-entry fdp tx current-height)
                (push (bl.ser:transaction-hash tx) txids)))
            (advance-height)
            (bl.mp:bpe-note-block current-height (nreverse txids))
            (when (> current-height best)
              (setf best current-height)
              (dolist (txid txids) (remhash txid model))))
          ;; removeTx of a random txid.
          (let ((txid (consume-uint256 fdp)))
            (bl.mp:bpe-note-removal txid)
            (remhash txid model))
          ;; FlushUnconfirmed.
          (progn
            (bl.mp:bpe-flush-unconfirmed est)
            (clrhash model)))
        (check-tracked)
        ;; estimateRawFee.
        (let* ((conf-target (consume-integral fdp :i32))
               (threshold (consume-floating-point fdp))
               (horizon (pick-value-in-array fdp '(:short :medium :long))))
          (consume-bool fdp)
          (let ((rate (bl.mp:bpe-estimate-raw-fee conf-target threshold horizon)))
            (if (<= 1 conf-target (bl.mp:horizon-max-confirms horizon))
                (fuzz-assert (and (integerp rate) (>= rate 0)) "estimateRawFee answered ~S" rate)
                (fuzz-assert (null rate) "estimateRawFee answered ~S for an untracked target" rate))))
        ;; estimateSmartFee.
        (let ((conf-target (consume-integral fdp :i32)))
          (consume-bool fdp)
          (multiple-value-bind (rate returned)
              (bl.mp:bpe-estimate-smart-fee est conf-target :conservative (consume-bool fdp))
            (fuzz-assert (and (integerp rate) (>= rate 0)) "estimateSmartFee answered ~S" rate)
            (when (plusp rate)
              (fuzz-assert (<= 2 returned (bl.mp:horizon-max-confirms :long))
                           "an estimate for target ~D, returned for ~D" conf-target returned))))
        ;; HighestTargetTracked, Core's periods x scale per horizon.
        (let ((horizon (pick-value-in-array fdp '(:short :medium :long))))
          (fuzz-assert (= (bl.mp:horizon-max-confirms horizon)
                          (ecase horizon (:short 12) (:medium 48) (:long 1008)))))))
    ;; Write, and Read back what was written.
    (let* ((bytes (policy-estimator-bytes est))
           (fresh (bl.mp:make-block-policy-estimator)))
      (fuzz-assert (policy-estimator-read fresh bytes) "the estimator refused its own file")
      (fuzz-assert (equalp (fuzz-sabotage (policy-estimator-bytes fresh)) bytes)
                   "a read-back estimator writes a different file"))))

(define-fuzz-target policy-estimator-io
    (buffer :core "policy_estimator_io.cpp:25-37" :iterations 40 :max-len 2000
            :corpus (lambda (fdp)
                      ;; A valid file from a fresh estimator, then mutated.
                      (declare (ignore fdp))
                      (policy-estimator-bytes (bl.mp:make-block-policy-estimator))))
  "Reading any bytes either refuses them, leaving the estimator as it was, or
leaves an estimator whose file reads back as the same file."
  (let* ((est (bl.mp:make-block-policy-estimator))
         (before (policy-estimator-bytes est)))
    (if (policy-estimator-read est buffer)
        (let ((written (policy-estimator-bytes est))
              (again (bl.mp:make-block-policy-estimator)))
          (fuzz-assert (policy-estimator-read again written))
          (fuzz-assert (equalp (fuzz-sabotage (policy-estimator-bytes again)) written)))
        (fuzz-assert (equalp (fuzz-sabotage (policy-estimator-bytes est)) before)
                     "a refused file changed the estimator"))))
