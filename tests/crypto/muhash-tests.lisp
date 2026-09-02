(in-package #:bitcoin-lisp.tests)

;;;; MuHash3072 tests
;;;;
;;;; Known-answer vectors and algebraic properties from Bitcoin Core
;;;; src/test/crypto_tests.cpp (muhash_tests). FromInt(i) is Core's helper: a
;;;; singleton MuHash over the 32-byte little-endian element {i, 0, ...}.

(def-suite :muhash-tests
  :description "MuHash3072 vs Bitcoin Core muhash_tests"
  :in :bitcoin-lisp-tests)

(in-suite :muhash-tests)

(defun %mh-from-int (i)
  "Core's FromInt(i): a MuHash singleton over the 32-byte element {i,0,...}."
  (let ((tmp (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref tmp 0) i)
    (bl.crypto:make-muhash tmp)))

(defun %mh-hex (mu)
  "Finalized MuHash in DISPLAY order (byte-reversed), matching Core's uint256
GetHex() and the gettxoutsetinfo muhash field. muhash-finalize itself returns
internal (SHA256) byte order like Core's uint256 storage."
  (bl.crypto:bytes-to-hex
   (bl.crypto:reverse-bytes (bl.crypto:muhash-finalize mu))))

(test muhash-known-answer
  "Core's two fixed known-answer vectors: (0 * 1 / 2) via combine/divide, and
the equivalent via insert/remove of 32-byte elements, both finalize to the
same published hash."
  (let ((expected "10d312b100cbd32ada024a6646e40d3482fcff103668d2625f10002a607d5863"))
    ;; acc = FromInt(0); acc *= FromInt(1); acc /= FromInt(2)
    (let ((acc (%mh-from-int 0)))
      (bl.crypto:muhash-combine acc (%mh-from-int 1))
      (bl.crypto:muhash-divide acc (%mh-from-int 2))
      (is (string= expected (%mh-hex acc))))
    ;; acc2 = FromInt(0); Insert({1,0..}); Remove({2,0..})
    (let ((acc2 (%mh-from-int 0))
          (tmp1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
          (tmp2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref tmp1 0) 1 (aref tmp2 0) 2)
      (bl.crypto:muhash-insert acc2 tmp1)
      (bl.crypto:muhash-remove acc2 tmp2)
      (is (string= expected (%mh-hex acc2))))))

(test muhash-order-independence
  "Core's permutation test: for a fixed multiset of insert/remove operations
(bit 2 = remove, bits 0-1 = which of 4 elements), every application order
finalizes to the same hash."
  (let* ((table #(3 6 1 5))               ; some inserts (bit2=0) and removes (bit2=1)
         (baseline nil))
    (dotimes (order 4)
      (let ((acc (bl.crypto:make-muhash)))
        (dotimes (i 4)
          (let ((tv (aref table (logxor i order))))
            (if (logtest tv 4)
                (bl.crypto:muhash-divide acc (%mh-from-int (logand tv 3)))
                (bl.crypto:muhash-combine acc (%mh-from-int (logand tv 3))))))
        (let ((h (%mh-hex acc)))
          (if baseline (is (string= baseline h)) (setf baseline h)))))))

(test muhash-fraction-cancellation
  "Core's z = X*Y / (Y*X) identity finalizes to the empty-set hash (the
denominator exactly cancels the numerator)."
  (let ((x (%mh-from-int 9))
        (y (%mh-from-int 5))
        (z (bl.crypto:make-muhash)))
    (bl.crypto:muhash-combine z x)       ; z = X
    (bl.crypto:muhash-combine z y)       ; z = X*Y
    (bl.crypto:muhash-combine y x)       ; y = Y*X
    (bl.crypto:muhash-divide z y)        ; z = 1
    (is (string= (%mh-hex (bl.crypto:make-muhash)) (%mh-hex z)))))

(test muhash-insert-remove-inverse
  "Inserting then removing the same element returns to the prior hash, in any
interleaving."
  (let ((acc (bl.crypto:make-muhash))
        (a (make-array 5 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3 4 5)))
        (b (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(9 8 7))))
    (bl.crypto:muhash-insert acc a)
    (let ((before (%mh-hex acc)))
      (bl.crypto:muhash-insert acc b)
      (bl.crypto:muhash-remove acc b)
      (is (string= before (%mh-hex acc))))))

(test muhash-coin-element-format
  "The per-coin MuHash element (Core coinstats.cpp TxOutSer) serializes to the
exact bytes, and the whole-coin MuHash matches Core's Python reference:
txid=0xAB*32, vout=1, height=100, coinbase, amount=5e9, script=OP_TRUE."
  (let* ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAB))
         (script (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))
         (elem (coerce (bl.store:coin-muhash-element
                        txid 1 100 t 5000000000 script)
                       '(simple-array (unsigned-byte 8) (*)))))
    (is (string= "abababababababababababababababababababababababababababababababab01000000c900000000f2052a010000000151"
                 (bl.crypto:bytes-to-hex elem)))
    (let ((mu (bl.crypto:make-muhash)))
      (bl.crypto:muhash-insert mu elem)
      (is (string= "87101942ab24a59445c85423bea02c27bdacc22d55fb0bdf4dc08efc9991f696"
                   (bl.crypto:bytes-to-hex
                    (bl.crypto:reverse-bytes
                     (bl.crypto:muhash-finalize mu))))))))

(test muhash-empty-set
  "The empty set finalizes to a stable, specific hash (denominator = numerator
= 1, so value = 1, SHA256 of the 384-byte LE encoding of 1)."
  (let* ((one (bl.crypto:le-integer-to-bytes 1 384))
         (expected (bl.crypto:bytes-to-hex
                    (bl.crypto:reverse-bytes (bl.crypto:sha256 one)))))
    (is (string= expected (%mh-hex (bl.crypto:make-muhash))))))
