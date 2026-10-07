(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/crypto_aes256cbc.cpp at the pin: AES-256-CBC with any
;;;; key and IV round-trips any plaintext. Ours is the wallet's
;;;; AES-256-CBC-ENCRYPT / -DECRYPT, Core's AES256CBCEncrypt/Decrypt with
;;;; pad = true -- the only mode the wallet uses; pad = false has no
;;;; counterpart and the draw is consumed and ignored. Our decrypt answers
;;;; NIL where Core's returns 0, and it also refuses a plaintext that unpads
;;;; to nothing (CCrypter::Decrypt's rule, crypter.cpp:104), so an empty
;;;; plaintext round-trips to NIL here where Core's to zero bytes.

(def-suite :fuzz-crypto-aes256cbc-tests :in :bitcoin-lisp-tests
  :description "Core fuzz crypto_aes256cbc.cpp")

(in-suite :fuzz-crypto-aes256cbc-tests)

(define-fuzz-target crypto-aes256cbc
    (buffer :core "crypto_aes256cbc.cpp:13-33" :iterations 2000 :max-len 400)
  "Any plaintext encrypted under any key and IV decrypts back to itself, the
ciphertext a whole number of blocks one padding block longer than the
plaintext rounded down; a ciphertext with one bit flipped never decrypts to
the plaintext."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (%fuzz-key32 fdp))
         (iv (let ((v (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
               (replace v (consume-bytes fdp 16)))))
    (consume-bool fdp)                  ; pad
    (limited-while ((consume-bool fdp) 10000)
      (let* ((plain (consume-random-length-byte-vector fdp))
             (cipher (bl.crypto:aes-256-cbc-encrypt key iv plain))
             (back (bl.crypto:aes-256-cbc-decrypt key iv cipher)))
        (fuzz-assert (= (length cipher) (* 16 (1+ (floor (length plain) 16))))
                     "~D bytes encrypt to ~D" (length plain) (length cipher))
        (fuzz-assert (if (zerop (length plain))
                         (null back)
                         (equalp (fuzz-sabotage back) plain))
                     "~D bytes decrypt to ~S" (length plain) back)
        (let ((flipped (copy-seq cipher))
              (i (consume-integral-in-range fdp 0 (1- (length cipher)))))
          (setf (aref flipped i) (logxor (aref flipped i) (ash 1 (consume-integral-in-range fdp 0 7))))
          (fuzz-assert (not (equalp (bl.crypto:aes-256-cbc-decrypt key iv flipped) plain))
                       "a flipped ciphertext bit still decrypts to the plaintext"))))))
