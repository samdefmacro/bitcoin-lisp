(in-package #:bitcoin-lisp.tests)

(def-suite :minisketch-tests
  :description "Set reconciliation sketches over GF(2^32) (BIP-330)"
  :in :bitcoin-lisp-tests)

(in-suite :minisketch-tests)

;;;; Vectors in tests/data/minisketch_vectors.json come from an INDEPENDENTLY
;;;; written reference implementation of the same specification
;;;; (refs/bitcoin/src/minisketch/doc/math.md), not from this code. That is a
;;;; second opinion on the field arithmetic and the sketch construction, where
;;;; a single implementation checked only against itself would be worthless.
;;;;
;;;; What it is NOT is proof of interop with Bitcoin Core's minisketch library,
;;;; which cannot be built in this project's container. That gap is recorded in
;;;; the source and matters only when Erlay is enabled against a Core node —
;;;; which cannot happen, because Core has not merged the reconciliation
;;;; protocol either.

(defun %msk-vectors ()
  (let ((path (merge-pathnames "tests/data/minisketch_vectors.json"
                               (asdf:system-source-directory :bitcoin-lisp))))
    (with-open-file (s path :direction :input) (yason:parse s))))

(test minisketch-field-multiplication-matches-the-reference
  "GF(2^32) with the modulus minisketch uses: x^32 + x^7 + x^3 + x^2 + 1."
  (let ((bad '()))
    (dolist (v (gethash "mul" (%msk-vectors)))
      (let ((got (bitcoin-lisp.networking::ms-mul (gethash "a" v) (gethash "b" v))))
        (unless (= got (gethash "r" v))
          (push (format nil "~X * ~X = ~X, want ~X"
                        (gethash "a" v) (gethash "b" v) got (gethash "r" v))
                bad))))
    (is (null bad) "~{~A~^~%~}" bad))
  ;; The reduction itself, spelled out: x^31 * x must fold in the modulus.
  (is (= #x8D (bitcoin-lisp.networking::ms-mul #x80000000 2)))
  ;; Multiplication is commutative and 1 is the identity.
  (is (= (bitcoin-lisp.networking::ms-mul #xDEADBEEF #xCAFEBABE)
         (bitcoin-lisp.networking::ms-mul #xCAFEBABE #xDEADBEEF)))
  (is (= #xDEADBEEF (bitcoin-lisp.networking::ms-mul #xDEADBEEF 1))))

(test minisketch-inverses-match-the-reference
  (dolist (v (gethash "inv" (%msk-vectors)))
    (let ((got (bitcoin-lisp.networking::ms-inv (gethash "a" v))))
      (is (= got (gethash "r" v)))
      (is (= 1 (bitcoin-lisp.networking::ms-mul (gethash "a" v) got)))))
  ;; Zero has no inverse, and asking must be loud rather than returning junk.
  (signals error (bitcoin-lisp.networking::ms-inv 0)))

(test minisketch-serialized-sketches-match-the-reference
  "The wire form: c field elements, each 4 bytes little-endian."
  (dolist (v (gethash "sketch" (%msk-vectors)))
    (let ((sk (bitcoin-lisp.networking::ms-make-sketch (gethash "capacity" v))))
      (dolist (e (gethash "elements" v))
        (bitcoin-lisp.networking::ms-sketch-add sk e))
      (is (string= (string-downcase (gethash "hex" v))
                   (string-downcase
                    (bitcoin-lisp.crypto:bytes-to-hex
                     (bitcoin-lisp.networking::ms-sketch-serialize sk))))
          "sketch of ~S" (gethash "elements" v))
      ;; And the terms themselves, so a serialization bug and an arithmetic bug
      ;; cannot cancel each other out.
      (is (equal (gethash "terms" v) (coerce sk 'list))))))

(test a-sketch-round-trips-through-serialization
  (let ((sk (bitcoin-lisp.networking::ms-make-sketch 4)))
    (dolist (e '(#xDEADBEEF #x12345678 1 #xFFFFFFFF))
      (bitcoin-lisp.networking::ms-sketch-add sk e))
    (is (equalp sk (bitcoin-lisp.networking::ms-sketch-deserialize
                    (bitcoin-lisp.networking::ms-sketch-serialize sk))))))

(test adding-an-element-twice-removes-it
  "The property the whole scheme rests on: addition is XOR, so an element added
twice cancels. That is why merging two sketches yields their symmetric
difference rather than their union."
  (let ((sk (bitcoin-lisp.networking::ms-make-sketch 4))
        (empty (bitcoin-lisp.networking::ms-make-sketch 4)))
    (bitcoin-lisp.networking::ms-sketch-add sk #xDEADBEEF)
    (is (not (equalp sk empty)))
    (bitcoin-lisp.networking::ms-sketch-add sk #xDEADBEEF)
    (is (equalp sk empty))))

(test merging-two-sketches-decodes-the-symmetric-difference
  "The point of the exercise: each side sketches its own set, the sketches are
XORed, and what decodes out is exactly what one side has and the other does
not — the elements they SHARE never appear."
  (let* ((cap 8)
         (a (bitcoin-lisp.networking::ms-make-sketch cap))
         (b (bitcoin-lisp.networking::ms-make-sketch cap))
         (common '(#x11111111 #x22222222 #x33333333))
         (only-a '(#xAAAA0001 #xAAAA0002))
         (only-b '(#xBBBB0001 #xBBBB0002 #xBBBB0003)))
    (dolist (e (append common only-a)) (bitcoin-lisp.networking::ms-sketch-add a e))
    (dolist (e (append common only-b)) (bitcoin-lisp.networking::ms-sketch-add b e))
    (let ((decoded (bitcoin-lisp.networking::ms-decode
                    (bitcoin-lisp.networking::ms-sketch-merge a b))))
      (is-true decoded)
      (is (equal (sort (append only-a only-b) #'<)
                 (sort (copy-list decoded) #'<))))))

(test decoding-works-across-difference-sizes
  "From an empty difference up to the full capacity, and one past it."
  (let ((cap 6))
    (loop for n from 0 to cap
          do (let ((sk (bitcoin-lisp.networking::ms-make-sketch cap))
                   (elements (loop for i from 1 to n collect (+ #x1000 (* i 7919)))))
               (dolist (e elements) (bitcoin-lisp.networking::ms-sketch-add sk e))
               (let ((decoded (bitcoin-lisp.networking::ms-decode sk)))
                 (is (equal (sort (copy-list elements) #'<)
                            (sort (copy-list decoded) #'<))
                     "a ~D-element difference must decode at capacity ~D" n cap))))))

(test a-decoded-set-is-a-claim-not-a-guarantee
  "The property that has to be understood rather than tested away: a capacity-c
sketch does not DETERMINE its set once the set is larger than c. {1,2,3,4,5}
and {6,7} share a capacity-2 sketch, so decoding the first yields the second —
consistently, and wrongly.

No check at this layer can see that, which is why BIP-330 has the peers
exchange the resulting short IDs afterwards. Asserted here so the property
stays documented in something that runs."
  (let ((over (bitcoin-lisp.networking::ms-make-sketch 2))
        (small (bitcoin-lisp.networking::ms-make-sketch 2)))
    (dolist (e '(1 2 3 4 5)) (bitcoin-lisp.networking::ms-sketch-add over e))
    (dolist (e '(6 7)) (bitcoin-lisp.networking::ms-sketch-add small e))
    (is (equalp over small)
        "the two sets genuinely collide at this capacity")
    (let ((decoded (bitcoin-lisp.networking::ms-decode over)))
      (is (equal '(6 7) (sort (copy-list decoded) #'<))
          "so the decode returns the SMALLER consistent set, not the input"))))

(test element-zero-is-refused
  "0 has no sketch — its powers are all 0, so it would be invisible. Minisketch
excludes it from the element range rather than silently dropping it."
  (let ((sk (bitcoin-lisp.networking::ms-make-sketch 4)))
    (signals error (bitcoin-lisp.networking::ms-sketch-add sk 0))))

(test decoding-is-deterministic
  "The trace algorithm picks random multipliers, which affect only how quickly
the locator splits — never the answer. A decode that varied run to run would
make reconciliation unreproducible."
  (let ((sk (bitcoin-lisp.networking::ms-make-sketch 5)))
    (dolist (e '(#x1234 #xABCD #x99999999 #x2 #xFFFFFFFE))
      (bitcoin-lisp.networking::ms-sketch-add sk e))
    (let ((first (sort (copy-list (bitcoin-lisp.networking::ms-decode sk)) #'<)))
      (dotimes (i 5)
        (is (equal first (sort (copy-list (bitcoin-lisp.networking::ms-decode sk)) #'<)))))))
