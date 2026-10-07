(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/timeoffsets.cpp at the pin: a TimeOffsets fed fuzzed
;;;; int64 offsets, reading the median and checking the warning after each.
;;;; Core asserts nothing beyond not crashing (std::chrono::abs of INT64_MIN
;;;; is clamped first, timeoffsets.cpp:44-45). Ours also restates the median
;;;; -- the upper median of the last 50 samples, 0 below five -- and holds the
;;;; warning to |median| > ten minutes.

(def-suite :fuzz-timeoffsets-tests :in :bitcoin-lisp-tests
  :description "Core fuzz timeoffsets.cpp")

(in-suite :fuzz-timeoffsets-tests)

(define-fuzz-target timeoffsets
    (buffer :core "timeoffsets.cpp:20-30" :iterations 600 :max-len 600)
  "The median is the upper median of the last fifty offsets (0 below five),
and the clock warning is raised exactly when it is more than ten minutes off."
  (let ((fdp (make-fuzzed-data-provider buffer))
        (offsets (bl.net:make-time-offsets))
        (kept '()))
    (bl.log:reset-warnings)
    (unwind-protect
         (limited-while ((plusp (remaining-bytes fdp)) 4000)
           (bl.net:time-offsets-median offsets)
           (let ((offset (if (consume-bool fdp)
                             (consume-integral-in-range fdp -1200 1200)
                             (consume-integral fdp :i64))))
             (bl.net:time-offsets-add offsets offset)
             (setf kept (last (append kept (list offset)) 50)))
           (let ((median (if (< (length kept) 5)
                             0
                             (nth (floor (length kept) 2) (sort (copy-list kept) #'<)))))
             (fuzz-assert (= (fuzz-sabotage (bl.net:time-offsets-median offsets)) median)
                          "median ~D, expected ~D" (bl.net:time-offsets-median offsets) median)
             (fuzz-assert (eq (bl.net:time-offsets-warn-if-out-of-sync offsets)
                              (> (abs median) (* 10 60)))
                          "the warning disagrees with a median of ~D" median)))
      (bl.log:reset-warnings))))
