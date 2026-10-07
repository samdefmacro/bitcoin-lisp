(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/muhash.cpp at the pin: num3072_mul (:16-42) and
;;;; num3072_inv (:44-71) -- the muhash target of the same file is in
;;;; crypto.lisp. Core checks its hand-written 3072-bit Num3072 against a
;;;; generic 6144-bit integer reduced modulo 2^3072 - 1103717. Ours keeps a
;;;; MuHash as a fraction of integers and multiplies with a special-form
;;;; reduction (%MUHASH-REDUCE) and inverts with an extended Euclid, reached
;;;; through the MuHash operations that use them: COMBINE multiplies
;;;; numerators (held to CL's own MOD), DIVIDE puts a value in the
;;;; denominator that FINALIZE inverts (n / n must finalize as one, Core's
;;;; uint * inv == 1). Values arrive as Core's do: any 384 little-endian
;;;; bytes, so also at or above the modulus.

(def-suite :fuzz-muhash-tests :in :bitcoin-lisp-tests
  :description "Core fuzz muhash.cpp (num3072_mul, num3072_inv)")

(in-suite :fuzz-muhash-tests)

(defun %consume-num3072 (fdp n)
  "N bytes (zero-filled to 384) as Core's Num3072{data}: little-endian."
  (let ((data (make-array 384 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace data (consume-bytes fdp n))
    (bl.crypto:bytes-to-le-integer data)))

(define-fuzz-target num3072-mul
    (buffer :core "muhash.cpp:16-42" :iterations 1500 :max-len 800)
  "The product of any two 3072-bit values is their product modulo
2^3072 - 1103717."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (a (%consume-num3072 fdp (consume-integral-in-range fdp 0 384)))
         (b (%consume-num3072 fdp 384))
         (mu (bl.crypto:muhash-combine (bl.crypto:make-muhash-raw :numerator a)
                                       (bl.crypto:make-muhash-raw :numerator b))))
    (fuzz-assert (= (fuzz-sabotage (bl.crypto:muhash-numerator mu)) (mod (* a b) bl.crypto:+muhash-modulus+))
                 "a 3072-bit product reduced wrongly")))

(define-fuzz-target num3072-inv
    (buffer :core "muhash.cpp:44-71" :iterations 600 :max-len 800)
  "Any value that is not a multiple of the modulus, divided by itself,
finalizes to the empty set: its inverse times the value is one."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (n (%consume-num3072 fdp 384)))
    (when (zerop (mod n bl.crypto:+muhash-modulus+))
      (fuzz-reject))
    (let ((mu (bl.crypto:muhash-divide (bl.crypto:make-muhash-raw :numerator n)
                                       (bl.crypto:make-muhash-raw :numerator n))))
      (fuzz-assert (equalp (fuzz-sabotage (bl.crypto:muhash-finalize mu))
                           (bl.crypto:muhash-finalize (bl.crypto:make-muhash-raw)))
                   "n / n is not one"))))
