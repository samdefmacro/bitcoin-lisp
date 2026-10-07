(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/crypto_poly1305.cpp at the pin: crypto_poly1305 (:16-24)
;;;; and crypto_poly1305_split (:27-52). Our Poly1305 is the MAC the BIP324
;;;; AEAD computes its tags with (ironclad's :poly1305, as %AEAD-COMPUTE-TAG
;;;; drives it). Core's first target only runs the MAC; ours also holds it to
;;;; RFC 8439's definition, restated in %REF-POLY1305 over integers. The split
;;;; target is Core's: the tag of a message fed in pieces is the tag of the
;;;; whole.

(def-suite :fuzz-crypto-poly1305-tests :in :bitcoin-lisp-tests
  :description "Core fuzz crypto_poly1305.cpp")

(in-suite :fuzz-crypto-poly1305-tests)

(defun %ref-poly1305 (key message)
  "RFC 8439 section 2.5.1: r is the clamped first half of KEY, s the second;
each 16-byte block, with a 1 byte appended, is added to the accumulator,
which is multiplied by r modulo 2^130 - 5; the tag is the accumulator plus s,
modulo 2^128, little-endian."
  (flet ((le (bytes) (loop for b across bytes for i from 0 sum (ash b (* 8 i)))))
    (let ((r (logand (le (subseq key 0 16)) #x0ffffffc0ffffffc0ffffffc0fffffff))
          (s (le (subseq key 16 32)))
          (p (- (ash 1 130) 5))
          (acc 0))
      (loop for start from 0 below (length message) by 16
            do (let ((chunk (subseq message start (min (length message) (+ start 16)))))
                 (setf acc (mod (* (+ acc (le chunk) (ash 1 (* 8 (length chunk)))) r) p))))
      (let ((tag (ldb (byte 128 0) (+ acc s)))
            (out (make-array 16 :element-type '(unsigned-byte 8))))
        (dotimes (i 16 out)
          (setf (aref out i) (ldb (byte 8 (* 8 i)) tag)))))))

(defun %poly1305-tag (key chunks)
  "Our Poly1305 over CHUNKS fed one Update each."
  (let ((mac (ironclad:make-mac :poly1305 key)))
    (dolist (c chunks (ironclad:produce-mac mac))
      (ironclad:update-mac mac c))))

(define-fuzz-target crypto-poly1305
    (buffer :core "crypto_poly1305.cpp:16-24" :iterations 3000 :max-len 400)
  "Poly1305 under any key over any message is RFC 8439's tag."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (%fuzz-key32 fdp))
         (in (consume-random-length-byte-vector fdp)))
    (fuzz-assert (equalp (fuzz-sabotage (%poly1305-tag key (list in))) (%ref-poly1305 key in))
                 "the tag of ~D bytes is not RFC 8439's" (length in))))

(define-fuzz-target crypto-poly1305-split
    (buffer :core "crypto_poly1305.cpp:27-52" :iterations 3000 :max-len 600)
  "The tag of a message fed in any pieces is the tag of the whole message."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (%fuzz-key32 fdp))
         (pieces '()))
    (limited-while ((plusp (remaining-bytes fdp)) 100)
      (push (consume-random-length-byte-vector fdp) pieces))
    (let ((pieces (reverse pieces)))
      (fuzz-assert (equalp (fuzz-sabotage (%poly1305-tag key pieces))
                           (%poly1305-tag key (list (%concat-octets pieces))))
                   "~D pieces tag differently from the whole" (length pieces)))))
