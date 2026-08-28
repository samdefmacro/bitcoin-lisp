(in-package #:bitcoin-lisp.tests)

;;;; FeeFrac tests
;;;;
;;;; Transcription of Bitcoin Core src/test/feefrac_tests.cpp (feefrac_operators)
;;;; against src/mempool/feefrac.lisp, plus CompareChunks diagram-comparison
;;;; cases exercising all four partial-ordering outcomes (Core only covers
;;;; CompareChunks via fuzz; these cases are hand-derived from the
;;;; feefrac.cpp:10-73 sweep semantics).

(def-suite :feefrac-tests
  :description "FeeFrac + CompareChunks vs Bitcoin Core feefrac_tests"
  :in :bitcoin-lisp-tests)

(in-suite :feefrac-tests)

(defun %ff (fee size)
  (bl.mp:make-feefrac fee size))

(defun %ff-down (f at-size)
  (bl.mp:feefrac-evaluate-fee-down f at-size))

(defun %ff-up (f at-size)
  (bl.mp:feefrac-evaluate-fee-up f at-size))

(test feefrac-evaluate-fee
  "EvaluateFeeDown/EvaluateFeeUp rounding table (feefrac_tests.cpp:20-56)."
  (let ((zero-fee (%ff 0 1)))                    ; zero-fee allowed
    (is (= 0 (%ff-down zero-fee 0)))
    (is (= 0 (%ff-down zero-fee 1)))
    (is (= 0 (%ff-down zero-fee 1000000)))
    (is (= 0 (%ff-down zero-fee #x7fffffff)))
    (is (= 0 (%ff-up zero-fee 0)))
    (is (= 0 (%ff-up zero-fee 1)))
    (is (= 0 (%ff-up zero-fee 1000000)))
    (is (= 0 (%ff-up zero-fee #x7fffffff))))
  (let ((p1 (%ff 1000 100)))
    (is (= 0 (%ff-down p1 0)))
    (is (= 10 (%ff-down p1 1)))
    (is (= 1000000000 (%ff-down p1 100000000)))
    (is (= (* #x7fffffff 10) (%ff-down p1 #x7fffffff)))
    (is (= 0 (%ff-up p1 0)))
    (is (= 10 (%ff-up p1 1)))
    (is (= 1000000000 (%ff-up p1 100000000)))
    (is (= (* #x7fffffff 10) (%ff-up p1 #x7fffffff))))
  ;; Negative fee: down rounds towards -inf, up towards +inf.
  (let ((neg (%ff -1001 100)))
    (is (= 0 (%ff-down neg 0)))
    (is (= -11 (%ff-down neg 1)))
    (is (= -21 (%ff-down neg 2)))
    (is (= -31 (%ff-down neg 3)))
    (is (= -1001 (%ff-down neg 100)))
    (is (= -1012 (%ff-down neg 101)))
    (is (= -1001000000 (%ff-down neg 100000000)))
    (is (= -1001000011 (%ff-down neg 100000001)))
    (is (= -21496311307 (%ff-down neg #x7fffffff)))
    (is (= 0 (%ff-up neg 0)))
    (is (= -10 (%ff-up neg 1)))
    (is (= -20 (%ff-up neg 2)))
    (is (= -30 (%ff-up neg 3)))
    (is (= -1001 (%ff-up neg 100)))
    (is (= -1011 (%ff-up neg 101)))
    (is (= -1001000000 (%ff-up neg 100000000)))
    (is (= -1001000010 (%ff-up neg 100000001)))
    (is (= -21496311306 (%ff-up neg #x7fffffff))))
  ;; Values above Core's uint64 fast path (fee >= 2^33) use Mul/Div there;
  ;; exact bignum arithmetic must agree on both sides of the threshold
  ;; (feefrac_tests.cpp:108-123).
  (let ((oversized-1 (%ff 4611686000000 4000000)))
    (is (= 0 (%ff-down oversized-1 0)))
    (is (= 1152921 (%ff-down oversized-1 1)))
    (is (= 2305843 (%ff-down oversized-1 2)))
    (is (= 1784758530396540 (%ff-down oversized-1 1548031267)))
    (is (= 0 (%ff-up oversized-1 0)))
    (is (= 1152922 (%ff-up oversized-1 1)))
    (is (= 2305843 (%ff-up oversized-1 2)))
    (is (= 1784758530396541 (%ff-up oversized-1 1548031267))))
  (is (= 6871947728 (%ff-down (%ff #x1ffffffff 123456789) 98765432)))
  (is (= 6871947729 (%ff-down (%ff #x200000000 123456789) 98765432)))
  (is (= 6871947730 (%ff-down (%ff #x200000001 123456789) 98765432)))
  (is (= 6871947729 (%ff-up (%ff #x1ffffffff 123456789) 98765432)))
  (is (= 6871947730 (%ff-up (%ff #x200000000 123456789) 98765432)))
  (is (= 6871947731 (%ff-up (%ff #x200000001 123456789) 98765432)))
  (let ((max-fee (%ff 2100000000000000 #x7fffffff)))
    (is (= 0 (%ff-down max-fee 0)))
    (is (= 977888 (%ff-down max-fee 1)))
    (is (= 1955777 (%ff-down max-fee 2)))
    (is (= 2933666 (%ff-down max-fee 3)))
    (is (= 1229006664189047 (%ff-down max-fee 1256796054)))
    (is (= 2100000000000000 (%ff-down max-fee #x7fffffff)))
    (is (= 0 (%ff-up max-fee 0)))
    (is (= 977889 (%ff-up max-fee 1)))
    (is (= 1955778 (%ff-up max-fee 2)))
    (is (= 2933667 (%ff-up max-fee 3)))
    (is (= 1229006664189048 (%ff-up max-fee 1256796054)))
    (is (= 2100000000000000 (%ff-up max-fee #x7fffffff))))
  ;; Integer-overflow regression (bitcoin/bitcoin#32294): exact result is
  ;; exactly INT64_MAX (feefrac_tests.cpp:151-152).
  (is (= #x7fffffffffffffff
         (%ff-down (%ff #x7ffffffdfffffffb #x7ffffffd) #x7fffffff))))

(test feefrac-arithmetic-and-equality
  "Componentwise +/- and equality (feefrac_tests.cpp:58-70)."
  (let ((p1 (%ff 1000 100)) (p2 (%ff 500 300))
        (sum (%ff 1500 400)) (diff (%ff 500 -200))
        (empty (%ff 0 0))
        (p3 (%ff 2000 200)) (p4 (%ff 3000 300)))
    (is-true (bl.mp:feefrac= empty (bl.mp:make-feefrac)))
    (is-true (bl.mp:feefrac-empty-p empty))
    (is-false (bl.mp:feefrac-empty-p p1))
    (is-true (bl.mp:feefrac= p1 p1))
    (is-true (bl.mp:feefrac= (bl.mp:feefrac+ p1 p2) sum))
    (is-true (bl.mp:feefrac= (bl.mp:feefrac- p1 p2) diff))
    ;; feefracs only equal if both fee and size are same
    (is-false (bl.mp:feefrac= p1 p3))
    (is-false (bl.mp:feefrac= p2 p3))
    (is-true (bl.mp:feefrac= p1 (bl.mp:feefrac- p4 p3)))
    (is-true (bl.mp:feefrac= (bl.mp:feefrac+ p1 p3) p4))))

(test feefrac-comparisons
  "Full-order and feerate-only comparisons (feefrac_tests.cpp:72-149)."
  (let ((p1 (%ff 1000 100)) (p2 (%ff 500 300)) (p3 (%ff 2000 200))
        (p4 (%ff 3000 300)) (empty (%ff 0 0)))
    (is-true (bl.mp:feefrac> p1 p2))
    (is-true (bl.mp:feefrac>= p1 p2))
    (is-true (bl.mp:feefrac>= p1 (bl.mp:feefrac- p4 p3)))
    (is-false (bl.mp:feefrac>> p1 p3)) ; not strictly better
    (is-true (bl.mp:feefrac>> p1 p2))  ; strictly greater feerate
    (is-true (bl.mp:feefrac< p2 p1))
    (is-true (bl.mp:feefrac<= p2 p1))
    (is-true (bl.mp:feefrac<= p1 (bl.mp:feefrac- p4 p3)))
    (is-false (bl.mp:feefrac<< p3 p1)) ; not strictly worse
    (is-true (bl.mp:feefrac<< p2 p1))  ; strictly lower feerate
    ;; "empty" feerate-only comparisons always result in false
    (is-false (bl.mp:feefrac>> p1 empty))
    (is-false (bl.mp:feefrac<< p1 empty))
    (is-false (bl.mp:feefrac>> empty empty))
    (is-false (bl.mp:feefrac<< empty empty))
    ;; empty is always bigger than everything else in the full order
    (is-true (bl.mp:feefrac> empty p1))
    (is-true (bl.mp:feefrac> empty p2))
    (is-true (bl.mp:feefrac> empty p3))
    (is-true (bl.mp:feefrac>= empty p1))
    (is-true (bl.mp:feefrac>= empty p2))
    (is-true (bl.mp:feefrac>= empty p3))
    ;; "max" values whose cross products exceed 64 bits
    (let ((oversized-1 (%ff 4611686000000 4000000))
          (oversized-2 (%ff 184467440000000 100000)))
      (is-true (bl.mp:feefrac< oversized-1 oversized-2))
      (is-true (bl.mp:feefrac<= oversized-1 oversized-2))
      (is-true (bl.mp:feefrac<< oversized-1 oversized-2))
      (is-false (bl.mp:feefrac= oversized-1 oversized-2)))
    ;; Paths where Core needs double/int128 arithmetic
    (let ((busted (%ff (1+ #x7fffffff) #x7fffffff)))
      (is-false (bl.mp:feefrac< busted busted)))
    (let ((max-fee (%ff 2100000000000000 #x7fffffff))
          (max-fee2 (%ff 1 1)))
      (is-false (bl.mp:feefrac< max-fee max-fee))
      (is-false (bl.mp:feefrac> max-fee max-fee))
      (is-true (bl.mp:feefrac<= max-fee max-fee))
      (is-true (bl.mp:feefrac>= max-fee max-fee))
      (is-true (bl.mp:feefrac>= max-fee max-fee2)))
    ;; Full-order tie-break: equal feerate sorts by DECREASING size
    ;; (feefrac.h:19-31: (2,2) sorts before (1,1); empty sorts last).
    (is-true (bl.mp:feefrac< (%ff 2 2) (%ff 1 1)))
    (is-true (bl.mp:feefrac> (%ff 1 1) (%ff 2 2)))
    (is (= 0 (bl.mp:feerate-compare (%ff 2 2) (%ff 1 1))))
    (is (= -1 (bl.mp:feerate-compare (%ff 1 2) (%ff 2 1))))
    (is (= 1 (bl.mp:feerate-compare (%ff 2 1) (%ff 1 2))))))

(test feefrac-compare-chunks
  "CompareChunks diagram comparison (feefrac.cpp:10-73): concave cumulative
curves from (0,0), extended right with a horizontal line; :unordered when
each is strictly better somewhere."
  (flet ((cmp (a b) (bl.mp:compare-chunks a b)))
    ;; Empty diagrams.
    (is (eq :equal (cmp '() '())))
    (is (eq :less (cmp '() (list (%ff 1 1)))))
    (is (eq :greater (cmp (list (%ff 1 1)) '())))
    ;; A diagram that only loses fee compares below the empty one.
    (is (eq :greater (cmp '() (list (%ff -1 1)))))
    ;; Identical diagrams.
    (is (eq :equal (cmp (list (%ff 10 10)) (list (%ff 10 10)))))
    ;; Same curve, different chunk split: still :equal.
    (is (eq :equal (cmp (list (%ff 10 10)) (list (%ff 5 5) (%ff 5 5)))))
    ;; Strictly above / below everywhere.
    (is (eq :greater (cmp (list (%ff 20 10)) (list (%ff 10 10)))))
    (is (eq :less (cmp (list (%ff 10 10)) (list (%ff 20 10)))))
    ;; Same endpoint, different concavity: the steeper-first diagram is
    ;; better in the middle, equal at the end => :greater / :less.
    (is (eq :greater (cmp (list (%ff 3 1) (%ff 1 3)) (list (%ff 2 2) (%ff 2 2)))))
    (is (eq :less (cmp (list (%ff 2 2) (%ff 2 2)) (list (%ff 3 1) (%ff 1 3)))))
    ;; Crossing curves: A better early (3 > 1.5 at size 1), B better late
    ;; (5 > 4 at size 4) => :unordered.
    (is (eq :unordered (cmp (list (%ff 3 1) (%ff 1 3)) (list (%ff 3 2) (%ff 2 2)))))
    (is (eq :unordered (cmp (list (%ff 3 2) (%ff 2 2)) (list (%ff 3 1) (%ff 1 3)))))
    ;; Different total sizes: the shorter diagram extends horizontally, so a
    ;; pure zero-fee tail changes nothing...
    (is (eq :equal (cmp (list (%ff 10 10)) (list (%ff 10 10) (%ff 0 5)))))
    ;; ...but a fee-adding tail makes the longer diagram better...
    (is (eq :less (cmp (list (%ff 10 10)) (list (%ff 10 10) (%ff 2 5)))))
    (is (eq :greater (cmp (list (%ff 10 10) (%ff 2 5)) (list (%ff 10 10)))))
    ;; ...and a fee-losing tail makes it worse.
    (is (eq :greater (cmp (list (%ff 10 10)) (list (%ff 10 10) (%ff -2 5)))))
    ;; Different total sizes with a crossing: A ends higher, B is better in
    ;; the middle => :unordered.
    (is (eq :unordered (cmp (list (%ff 4 8)) (list (%ff 3 2)))))
    ;; RBF-style: replacement diagram must be strictly better somewhere and
    ;; nowhere worse (is_gt(CompareChunks(new, old)), policy/rbf.cpp:127-140).
    (is (eq :greater (cmp (list (%ff 30 10) (%ff 5 10)) (list (%ff 20 10) (%ff 5 10)))))
    ;; Sequences may be vectors too.
    (is (eq :equal (cmp (vector (%ff 10 10)) (list (%ff 5 5) (%ff 5 5)))))))
