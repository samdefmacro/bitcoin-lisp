(in-package #:bitcoin-lisp.mempool)

;;; FeeFrac - fee/size fractions with division-free comparisons
;;;
;;; Port of Bitcoin Core util/feefrac.{h,cpp}: the exact-arithmetic fee/size
;;; pair underlying cluster mempool (chunk feerates, feerate diagrams, the
;;; diagram-RBF predicate). Core needs 96-bit Mul/Div helpers for the
;;; cross-multiplied comparisons; CL bignums make those exact for free, so
;;; behavior within Core's documented domain (|fee| < 2^63, |size| < 2^31)
;;; is identical without the fallback paths.
;;;
;;; Ordering (feefrac.h:15-38): the full order sorts by increasing feerate
;;; (fee/size ratio), ties broken by DECREASING size; the empty feefrac
;;; (0/0) sorts after everything. "Better" = sorts later. The feerate-only
;;; comparisons (Core's <<, >>, FeeRateCompare) treat equal-feerate but
;;; different-size values as equivalent, and the empty feefrac as neither
;;; higher nor lower than anything.

(defstruct (feefrac (:constructor make-feefrac (&optional (fee 0) (size 0))))
  "A fee (satoshis) and size (bytes/vbytes/weight units) pair (feefrac.h:39).
The empty feefrac has fee = size = 0; size 0 with nonzero fee is invalid."
  (fee 0 :type (signed-byte 64))
  (size 0 :type (signed-byte 32)))

(declaim (inline feefrac-empty-p))
(defun feefrac-empty-p (f)
  "True when F is the empty feefrac (feefrac.h:120-122; size 0 implies fee 0)."
  (zerop (feefrac-size f)))

(defun feefrac+ (a b)
  "Componentwise sum of A and B (feefrac.h:138-142)."
  (make-feefrac (+ (feefrac-fee a) (feefrac-fee b))
                (+ (feefrac-size a) (feefrac-size b))))

(defun feefrac- (a b)
  "Componentwise difference A - B (feefrac.h:144-148)."
  (make-feefrac (- (feefrac-fee a) (feefrac-fee b))
                (- (feefrac-size a) (feefrac-size b))))

(defun feefrac= (a b)
  "True when A and B have the same fee AND the same size (feefrac.h:150-154)."
  (and (= (feefrac-fee a) (feefrac-fee b))
       (= (feefrac-size a) (feefrac-size b))))

(declaim (inline %feefrac-cross))
(defun %feefrac-cross (a b)
  "Cross-multiplied feerate comparison a.fee*b.size - b.fee*a.size; its sign
is the feerate order of A vs B (Core's Mul-based comparisons, feefrac.h:157-175)."
  (- (* (feefrac-fee a) (feefrac-size b))
     (* (feefrac-fee b) (feefrac-size a))))

(defun feerate-compare (a b)
  "Compare A and B by feerate only: -1/0/1 (Core FeeRateCompare,
feefrac.h:157-161). Equal feerate but different size compares 0; the empty
feefrac compares 0 against everything."
  (signum (%feefrac-cross a b)))

(defun feefrac<< (a b)
  "True when A has strictly lower feerate than B (Core operator<<,
feefrac.h:163-168)."
  (minusp (%feefrac-cross a b)))

(defun feefrac>> (a b)
  "True when A has strictly higher feerate than B (Core operator>>,
feefrac.h:170-175)."
  (plusp (%feefrac-cross a b)))

(defun feefrac-compare (a b)
  "Full-order comparison of A and B: -1/0/1 (Core operator<=>,
feefrac.h:177-183). Orders by feerate, ties broken by descending size (so the
empty feefrac sorts after everything)."
  (let ((cross (%feefrac-cross a b)))
    (if (zerop cross)
        (signum (- (feefrac-size b) (feefrac-size a)))
        (signum cross))))

(defun feefrac< (a b) (minusp (feefrac-compare a b)))
(defun feefrac> (a b) (plusp (feefrac-compare a b)))
(defun feefrac<= (a b) (not (plusp (feefrac-compare a b))))
(defun feefrac>= (a b) (not (minusp (feefrac-compare a b))))

(defun feefrac-evaluate-fee-down (f at-size)
  "Fee for AT-SIZE at F's feerate, rounded towards negative infinity (Core
EvaluateFeeDown, feefrac.h:201-221). Requires F's size > 0 and AT-SIZE >= 0."
  (assert (plusp (feefrac-size f)))
  (assert (not (minusp at-size)))
  (values (floor (* (feefrac-fee f) at-size) (feefrac-size f))))

(defun feefrac-evaluate-fee-up (f at-size)
  "Fee for AT-SIZE at F's feerate, rounded towards positive infinity (Core
EvaluateFeeUp, feefrac.h:201-223). Requires F's size > 0 and AT-SIZE >= 0."
  (assert (plusp (feefrac-size f)))
  (assert (not (minusp at-size)))
  (values (ceiling (* (feefrac-fee f) at-size) (feefrac-size f))))

(defun compare-chunks (chunks0 chunks1)
  "Compare the feerate diagrams implied by two chunk sequences: :less,
:greater, :equal, or :unordered (Core CompareChunks, feefrac.cpp:10-73).

Each argument is a sequence of feefracs sorted by decreasing feerate. Its
implied diagram is the concave cumulative fee-vs-size curve starting at
\(0,0), with one point per chunk at the cumulative fee/size, extended
infinitely to the right with a horizontal line. :greater means CHUNKS0's
diagram is somewhere above and nowhere below CHUNKS1's; :unordered means
each is strictly better than the other somewhere. The caller must ensure
cumulative fees/sizes stay within Core's int64/int32 domains."
  (let ((chunk (vector (coerce chunks0 'simple-vector)
                       (coerce chunks1 'simple-vector)))
        ;; How many elements we have processed in each input.
        (next-index (vector 0 0))
        ;; Accumulated fee/sizes in diagrams, up to next-index[i] - 1.
        (accum (vector (make-feefrac) (make-feefrac)))
        ;; Whether the corresponding input is strictly better than the other
        ;; at least in one place.
        (better-somewhere (vector nil nil)))
    (flet ((next-point (dia)         ; first unprocessed point of diagram DIA
             (feefrac+ (svref (svref chunk dia) (svref next-index dia))
                       (svref accum dia)))
           (prev-point (dia)         ; last processed point of diagram DIA
             (svref accum dia))
           (advance (dia)            ; move to the next point of diagram DIA
             (setf (svref accum dia)
                   (feefrac+ (svref accum dia)
                             (svref (svref chunk dia) (svref next-index dia))))
             (incf (svref next-index dia))))
      (loop
        (let ((done-0 (= (svref next-index 0) (length (svref chunk 0))))
              (done-1 (= (svref next-index 1) (length (svref chunk 1)))))
          (when (and done-0 done-1) (return))
          ;; Determine which diagram has the first unprocessed point. If a
          ;; single side is finished, use the other one (feefrac.cpp:32-34).
          (let* ((unproc-side
                   (cond ((or done-0 done-1) (if done-0 1 0))
                         ((> (feefrac-size (next-point 0))
                             (feefrac-size (next-point 1))) 1)
                         (t 0)))
                 (other-side (- 1 unproc-side))
                 ;; Let P be the next point on diagram unproc-side, and A and
                 ;; B the previous and next points on the other diagram. P
                 ;; lies above/below line AB iff slope AP exceeds/undercuts
                 ;; slope AB; slopes are fee-per-size, i.e. feefracs
                 ;; (feefrac.cpp:36-60).
                 (point-p (next-point unproc-side))
                 (point-a (prev-point other-side))
                 (slope-ap (feefrac- point-p point-a))
                 (cmp
                   (if (or done-0 done-1)
                       ;; A single side has no points left: act as if AB has
                       ;; the tail feerate of 0.
                       (feerate-compare slope-ap (make-feefrac 0 1))
                       (let* ((point-b (next-point other-side))
                              (slope-ab (feefrac- point-b point-a))
                              (c (feerate-compare slope-ap slope-ab)))
                         ;; If B and P have the same size, B can be marked as
                         ;; processed too: a comparison happened at this size.
                         (when (= (feefrac-size point-b) (feefrac-size point-p))
                           (advance other-side))
                         c))))
            ;; P above AB: unproc-side better at P; below: the other side is.
            (when (plusp cmp) (setf (svref better-somewhere unproc-side) t))
            (when (minusp cmp) (setf (svref better-somewhere other-side) t))
            (advance unproc-side)
            ;; Both better somewhere: incomparable.
            (when (and (svref better-somewhere 0) (svref better-somewhere 1))
              (return-from compare-chunks :unordered))))))
    (cond ((svref better-somewhere 0) :greater)
          ((svref better-somewhere 1) :less)
          (t :equal))))
