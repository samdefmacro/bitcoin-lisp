(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/secp256k1_ecdsa_signature_parse_der_lax.cpp at the pin:
;;;; ecdsa_signature_parse_der_lax (pubkey.cpp:45-176) over any bytes. Ours is
;;;; NORMALIZE-SIGNATURE-LAX, which VERIFY-SIGNATURE runs for every signature
;;;; checked without DERSIG -- consensus before BIP66.
;;;;
;;;; Core's target only parses (and asks SigHasLowR of what parsed). Ours
;;;; parses arbitrary bytes too, and also builds the encodings the lax parser
;;;; exists to tolerate around a real signature -- leading zero bytes,
;;;; long-form lengths with zero length bytes, a wrong or long-form sequence
;;;; length, trailing bytes -- and the ones it refuses or overflows: four
;;;; significant length bytes, an integer of 33 significant bytes. The
;;;; signature must verify exactly when Core's parser hands back the signed R
;;;; and S.

(def-suite :fuzz-secp256k1-ecdsa-signature-parse-der-lax-tests :in :bitcoin-lisp-tests
  :description "Core fuzz secp256k1_ecdsa_signature_parse_der_lax.cpp")

(in-suite :fuzz-secp256k1-ecdsa-signature-parse-der-lax-tests)

(defun %lax-der-int (fdp digits)
  "DIGITS (an integer's significant bytes) as an INTEGER the lax parser may
meet: up to three zero bytes in front and a short- or long-form length --
and now and then a non-zero byte in front of the 32-byte value (33
significant bytes: overflow) or a length of four significant bytes (no
parse). Second value: :ok, :overflow or :unparsable."
  (let* ((verdict :ok)
         (value (if (zerop (consume-integral-in-range fdp 0 7))
                    (progn (setf verdict :overflow)
                           (%concat-octets
                            (list (vector (consume-integral-in-range fdp 1 255))
                                  (make-array (- 32 (length digits)) :initial-element 0)
                                  digits)))
                    digits))
         (body (%concat-octets
                (list (make-array (consume-integral-in-range fdp 0 3) :initial-element 0) value)))
         (len (length body)))
    (values (%concat-octets
             (list #(2)
                   (call-one-of fdp
                     (if (< len 128) (vector len) (vector #x81 len))
                     (vector #x81 len)
                     (vector #x83 0 0 len)
                     (progn (setf verdict :unparsable) (vector #x84 1 0 0 len)))
                   body))
            verdict)))

(defun %lax-der-sequence (fdp ints)
  "INTS under a SEQUENCE header whose length is right, wrong, or long form,
with up to four trailing bytes."
  (let ((len (length ints)))
    (%concat-octets
     (list (call-one-of fdp
             (if (< len 128) (vector #x30 len) (vector #x30 #x81 len))
             (vector #x30 (consume-integral-in-range fdp 0 127))
             (vector #x30 #x82 0 (ldb (byte 8 0) len))
             (vector #x30 #x80))
           ints
           (consume-bytes fdp (consume-integral-in-range fdp 0 4))))))

(define-fuzz-target secp256k1-ecdsa-signature-parse-der-lax
    (buffer :core "secp256k1_ecdsa_signature_parse_der_lax.cpp:19-35" :iterations 2000 :max-len 200)
  "Any bytes are refused without a crash; a real signature in any encoding
Core's lax parser tolerates verifies, and one whose R or S overflows or whose
length does not parse does not."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (if (consume-bool fdp)
        ;; Any bytes: parsed and refused, never a crash, never a signature.
        (let ((key (bl.crypto:sha256 (consume-bytes fdp 32))))
          (fuzz-assert (null (fuzz-sabotage (bl.crypto:verify-signature
                                             (consume-uint256 fdp) (consume-random-length-byte-vector fdp)
                                             (bl.crypto:derive-public-key key))))
                       "random bytes verified as a signature"))
        (let* ((key (bl.crypto:sha256 (consume-bytes fdp 32)))
               (hash (consume-uint256 fdp))
               (der (bl.crypto:sign-ecdsa key hash))
               (r (subseq der 4 (+ 4 (aref der 3))))
               (s (subseq der (+ 6 (length r)))))
          (flet ((digits (bytes) (subseq bytes (or (position-if #'plusp bytes) (length bytes)))))
            (multiple-value-bind (r-int r-verdict) (%lax-der-int fdp (digits r))
              (multiple-value-bind (s-int s-verdict) (%lax-der-int fdp (digits s))
                (let ((sig (%lax-der-sequence fdp (%concat-octets (list r-int s-int))))
                      (expected (and (eq r-verdict :ok) (eq s-verdict :ok))))
                  (fuzz-assert (eq (fuzz-sabotage (and (bl.crypto:verify-signature
                                                         hash sig (bl.crypto:derive-public-key key))
                                                        t))
                                   expected)
                               "~A (R ~A, S ~A) ~:[does not verify~;verifies~]"
                               (bl.crypto:bytes-to-hex sig) r-verdict s-verdict (not expected))))))))))
