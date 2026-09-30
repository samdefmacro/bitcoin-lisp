(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/feefrac.cpp, feeratediagram.cpp and fees.cpp at the pin
;;;; (d3056bc149): FeeFrac's comparisons and fee evaluation
;;;; (src/mempool/feefrac.lisp), CompareChunks against a direct evaluation of
;;;; the two diagrams, and the feefilter rounder
;;;; (src/networking/peer.lisp).
;;;;
;;;; FeeFrac arithmetic here is exact (Lisp integers), so Core's Mul / Div and
;;;; their 32-bit fallbacks have no counterpart: feefrac_div_fallback is not
;;;; ported, and feefrac_mul_div keeps what it asks of EvaluateFeeDown /
;;;; EvaluateFeeUp -- the exact rounded quotient, and agreement with
;;;; CFeeRate::GetFee (policy/feerate.cpp:21-27), itself evaluated from its
;;;; definition. fee_rate.cpp (CFeeRate's operators) has no counterpart:
;;;; feerates are integers here.

(def-suite :fuzz-feefrac-tests :in :bitcoin-lisp-tests
  :description "Core fuzz/feefrac.cpp, feeratediagram.cpp and fees.cpp targets")

(in-suite :fuzz-feefrac-tests)

(defun feefrac-fuzz-cmp (a b)
  "C++ `A <=> B' on integers, as -1/0/1."
  (cond ((< a b) -1) ((> a b) 1) (t 0)))

;;; --- feefrac (:69-108) -------------------------------------------------------------

(define-fuzz-target feefrac
    (buffer :core "feefrac.cpp:69-108" :iterations 3000 :max-len 32)
  "FeeRateCompare, << and >> agree with the sign of f1*s2 - f2*s1 computed
exactly, and the total order (<=>, <, >, <=, >=, ==) is that comparison with
ties broken by the larger size first."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (f1 (consume-integral fdp :i64))
         (s1 (consume-integral fdp :i32))
         (f1 (if (zerop s1) 0 f1))
         (fr1 (bl.mp:make-feefrac f1 s1))
         (f2 (consume-integral fdp :i64))
         (s2 (consume-integral fdp :i32))
         (f2 (if (zerop s2) 0 f2))
         (fr2 (bl.mp:make-feefrac f2 s2)))
    (fuzz-assert (eq (bl.mp:feefrac-empty-p fr1) (zerop s1)))
    (fuzz-assert (eq (bl.mp:feefrac-empty-p fr2) (zerop s2)))
    ;; MulCompare(f1, s2, f2, s1), exactly.
    (let* ((cmp-feerate (feefrac-fuzz-cmp (* f1 s2) (* f2 s1)))
           (cmp-total (if (zerop cmp-feerate) (feefrac-fuzz-cmp s2 s1) cmp-feerate)))
      (fuzz-assert (= (fuzz-sabotage (bl.mp:feerate-compare fr1 fr2)) cmp-feerate)
                   "FeeRateCompare(~A, ~A) = ~D, expected ~D" fr1 fr2
                   (bl.mp:feerate-compare fr1 fr2) cmp-feerate)
      (fuzz-assert (eq (bl.mp:feefrac<< fr1 fr2) (minusp cmp-feerate)))
      (fuzz-assert (eq (bl.mp:feefrac>> fr1 fr2) (plusp cmp-feerate)))
      (fuzz-assert (= (bl.mp:feefrac-compare fr1 fr2) cmp-total))
      (fuzz-assert (eq (bl.mp:feefrac< fr1 fr2) (minusp cmp-total)))
      (fuzz-assert (eq (bl.mp:feefrac> fr1 fr2) (plusp cmp-total)))
      (fuzz-assert (eq (bl.mp:feefrac<= fr1 fr2) (<= cmp-total 0)))
      (fuzz-assert (eq (bl.mp:feefrac>= fr1 fr2) (>= cmp-total 0)))
      (fuzz-assert (eq (bl.mp:feefrac= fr1 fr2) (zerop cmp-total))))))

;;; --- feefrac_mul_div (:158-233), the Evaluate half -------------------------------

(defun feefrac-fuzz-div (num den round-down)
  "NUM / DEN rounded down or up, exactly."
  (if round-down (floor num den) (ceiling num den)))

(define-fuzz-target feefrac-mul-div
    (buffer :core "feefrac.cpp:158-233" :iterations 3000 :max-len 32)
  "EvaluateFeeDown / EvaluateFeeUp of FeeFrac{mul64, div} at mul32 are the
exactly rounded quotient, whenever the quotient fits an int64; and CFeeRate's
GetFee over the same rate (which rounds up, and answers -1 rather than 0 for a
negative rate) stays within mul32/1000 + 3 of them."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (mul32 (consume-integral fdp :i32))
         (mul64 (consume-integral fdp :i64))
         (div (consume-integral-in-range fdp 1 (1- (ash 1 31)) 32))
         (round-down (consume-bool fdp))
         (quot (feefrac-fuzz-div (* mul32 mul64) div round-down)))
    (unless (<= (- (ash 1 63)) quot (1- (ash 1 63)))
      ;; Only a negative or oversized at-size can make the result overflow.
      (fuzz-assert (or (minusp mul32) (> mul32 div)))
      (fuzz-reject))
    (when (>= mul32 0)
      (let* ((ff (bl.mp:make-feefrac mul64 div))
             (res (if round-down
                      (bl.mp:feefrac-evaluate-fee-down ff mul32)
                      (bl.mp:feefrac-evaluate-fee-up ff mul32))))
        (fuzz-assert (= (fuzz-sabotage res) quot)
                     "Evaluate~:[Up~;Down~](~D/~D, ~D) = ~D, expected ~D"
                     round-down mul64 div mul32 res quot)
        (when (and (< (- (floor (1- (ash 1 63)) 1000)) mul64 (floor (1- (ash 1 63)) 1000))
                   (< (abs quot) (floor (1- (ash 1 63)) 1000)))
          ;; CFeeRate(mul64, div).GetFee(mul32) (policy/feerate.cpp:11-27):
          ;; the rate is FeePerVSize(mul64, div), evaluated rounding up; a
          ;; negative rate never rounds a positive size to 0.
          (let* ((fee (ceiling (* mul64 mul32) div))
                 (fee (if (and (zerop fee) (/= mul32 0) (minusp mul64)) -1 fee))
                 (gap (+ (floor mul32 1000) 3 (if round-down 1 0))))
            (fuzz-assert (<= (- gap) (- fee res) gap))))))))

;;; --- build_and_compare_feerate_diagram (feeratediagram.cpp:104-139) ----------------

(defun feerate-diagram-from-chunks (chunks)
  "BuildDiagramFromChunks: the cumulative points, starting at (0, 0)."
  (let ((out (list (bl.mp:make-feefrac 0 0))))
    (dolist (c chunks (nreverse out))
      (push (bl.mp:feefrac+ (first out) c) out))))

(defun feerate-diagram-evaluate (size diagram)
  "EvaluateDiagram (feeratediagram.cpp:36-67): the diagram's fee at SIZE as a
fraction, interpolated between the points around it, extended flat outside."
  (let* ((d (coerce diagram 'simple-vector))
         (not-above 0)
         (not-below (1- (length d))))
    (when (< size (bl.mp:feefrac-size (svref d not-above)))
      (return-from feerate-diagram-evaluate (bl.mp:make-feefrac (bl.mp:feefrac-fee (svref d not-above)) 1)))
    (when (> size (bl.mp:feefrac-size (svref d not-below)))
      (return-from feerate-diagram-evaluate (bl.mp:make-feefrac (bl.mp:feefrac-fee (svref d not-below)) 1)))
    (loop while (> not-below (1+ not-above))
          do (let ((mid (floor (+ not-below not-above) 2)))
               (when (<= (bl.mp:feefrac-size (svref d mid)) size) (setf not-above mid))
               (when (>= (bl.mp:feefrac-size (svref d mid)) size) (setf not-below mid))))
    (if (= not-below not-above)
        (bl.mp:make-feefrac (bl.mp:feefrac-fee (svref d not-below)) 1)
        (let* ((a (svref d not-above))
               (dir (bl.mp:feefrac- (svref d not-below) a)))
          (assert (plusp (bl.mp:feefrac-size dir)))
          ;; Kept as a plain pair of integers: the numerator can pass int64.
          (cons (+ (* (bl.mp:feefrac-fee a) (bl.mp:feefrac-size dir))
                   (* (bl.mp:feefrac-fee dir) (- size (bl.mp:feefrac-size a))))
                (bl.mp:feefrac-size dir))))))

(defun feerate-diagram-fraction (x)
  "An evaluation as (numerator . denominator)."
  (if (consp x) x (cons (bl.mp:feefrac-fee x) (bl.mp:feefrac-size x))))

(defun feerate-diagram-compare-point (ff diagram)
  "CompareFeeFracWithDiagram: FF's fee against the diagram at FF's size."
  (destructuring-bind (num . den) (feerate-diagram-fraction
                                   (feerate-diagram-evaluate (bl.mp:feefrac-size ff) diagram))
    (feefrac-fuzz-cmp (* (bl.mp:feefrac-fee ff) den) num)))

(defun feerate-diagram-compare (dia1 dia2)
  "CompareDiagrams (feeratediagram.cpp:74-93): every point of each diagram
against the other one, as :greater / :less / :equal / :unordered."
  (let ((all-ge t) (all-le t))
    (dolist (p dia1)
      (let ((c (feerate-diagram-compare-point p dia2)))
        (when (minusp c) (setf all-ge nil))
        (when (plusp c) (setf all-le nil))))
    (dolist (p dia2)
      (let ((c (feerate-diagram-compare-point p dia1)))
        (when (minusp c) (setf all-le nil))
        (when (plusp c) (setf all-ge nil))))
    (cond ((and all-ge all-le) :equal)
          (all-ge :greater)
          (all-le :less)
          (t :unordered))))

(define-fuzz-target build-and-compare-feerate-diagram
    (buffer :core "feeratediagram.cpp:104-139" :iterations 2000 :max-len 600)
  "CompareChunks answers what comparing the two diagrams point by point
answers, and no evaluation of the two at a common size contradicts it."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (populate (lambda ()
                     (let ((out '()))
                       (limited-while ((consume-bool fdp) 50)
                         (push (bl.mp:make-feefrac
                                (consume-integral-in-range fdp (ash (- (ash 1 31)) -1)
                                                           (ash (1- (ash 1 31)) -1))
                                (consume-integral-in-range fdp 1 1000000 32))
                               out))
                       (nreverse out))))
         (chunks1 (funcall populate))
         (chunks2 (funcall populate))
         (diagram1 (feerate-diagram-from-chunks chunks1))
         (diagram2 (feerate-diagram-from-chunks chunks2))
         (real (bl.mp:compare-chunks chunks1 chunks2)))
    (fuzz-assert (bl.mp:feefrac-empty-p (first diagram1)))
    (fuzz-assert (bl.mp:feefrac-empty-p (first diagram2)))
    (fuzz-assert (eq (fuzz-sabotage real) (feerate-diagram-compare diagram1 diagram2))
                 "CompareChunks ~A, the diagrams compare ~A" real
                 (feerate-diagram-compare diagram1 diagram2))
    (limited-while ((plusp (remaining-bytes fdp)) 1000)
      (let* ((size (consume-integral-in-range fdp 0 (bl.mp:feefrac-size (car (last diagram2))) 32))
             (e1 (feerate-diagram-fraction (feerate-diagram-evaluate size diagram1)))
             (e2 (feerate-diagram-fraction (feerate-diagram-evaluate size diagram2)))
             (cmp (feefrac-fuzz-cmp (* (car e1) (cdr e2)) (* (car e2) (cdr e1)))))
        (when (minusp cmp) (fuzz-assert (not (eq real :greater))))
        (when (plusp cmp) (fuzz-assert (not (eq real :less))))))))

;;; --- fees (fees.cpp:18-32) ----------------------------------------------------------

(define-fuzz-target fees
    (buffer :core "fees.cpp:18-32" :iterations 1000 :max-len 400)
  "The feefilter rounder quantizes any money amount to an amount still in the
money range. The rounder's buckets are fixed at the node's
(DEFAULT_MIN_RELAY_TX_FEE, as Core's PeerManager builds it,
net_processing.cpp), so Core's random minimal incremental fee is not an input
here."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (consume-money fdp)
    (limited-while ((consume-bool fdp) 10000)
      (let ((rounded (bl.net:fee-filter-round (consume-money fdp))))
        ;; The positive control shrinks the range to nothing but zero.
        (fuzz-assert (<= 0 rounded (if (eq *fuzz-sabotage* :assert) 0 bl.val:+max-money+))
                     "rounded fee ~D outside the money range" rounded)))))
