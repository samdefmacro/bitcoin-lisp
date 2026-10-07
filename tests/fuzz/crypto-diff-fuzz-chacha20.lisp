(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/crypto_diff_fuzz_chacha20.cpp at the pin: our ChaCha20
;;;; against D. J. Bernstein's reference implementation (ECRYPT chacha-ref),
;;;; which Core's file carries inline (:24-262). The reference is restated
;;;; here, word for word in what it computes: a 16-word state whose words
;;;; 12-13 are one 64-bit block counter and 14-15 the IV, and a keystream that
;;;; is whole 64-byte blocks -- a request of N bytes consumes ceil(N/64) of
;;;; them. Core's Seek({iv_prefix, iv}, counter) is that state with
;;;; input[12] = counter, input[13] = iv_prefix, input[14..15] = iv, so after
;;;; every partial-block request the target re-seeks ours to the reference's
;;;; next block, as Core's does (:300-306).

(def-suite :fuzz-crypto-diff-fuzz-chacha20-tests :in :bitcoin-lisp-tests
  :description "Core fuzz crypto_diff_fuzz_chacha20.cpp: ChaCha20 against the reference")

(in-suite :fuzz-crypto-diff-fuzz-chacha20-tests)

(defun %ref-chacha20-block (key-words w12 w13 w14 w15)
  "One 64-byte block of chacha-ref's salsa20_wordtobyte over the state
\"expand 32-byte k\", KEY-WORDS (eight little-endian words), W12-W15."
  (let ((x (make-array 16)) (in (make-array 16)))
    (replace in (list #x61707865 #x3320646e #x79622d32 #x6b206574))
    (replace in key-words :start1 4)
    (setf (aref in 12) w12 (aref in 13) w13 (aref in 14) w14 (aref in 15) w15)
    (replace x in)
    (flet ((rotl (v n) (ldb (byte 32 0) (logior (ash v n) (ash v (- n 32)))))
           (plus (a b) (ldb (byte 32 0) (+ a b))))
      (flet ((qr (a b c d)
               (setf (aref x a) (plus (aref x a) (aref x b))
                     (aref x d) (rotl (logxor (aref x d) (aref x a)) 16)
                     (aref x c) (plus (aref x c) (aref x d))
                     (aref x b) (rotl (logxor (aref x b) (aref x c)) 12)
                     (aref x a) (plus (aref x a) (aref x b))
                     (aref x d) (rotl (logxor (aref x d) (aref x a)) 8)
                     (aref x c) (plus (aref x c) (aref x d))
                     (aref x b) (rotl (logxor (aref x b) (aref x c)) 7))))
        (loop repeat 10
              do (qr 0 4 8 12) (qr 1 5 9 13) (qr 2 6 10 14) (qr 3 7 11 15)
                 (qr 0 5 10 15) (qr 1 6 11 12) (qr 2 7 8 13) (qr 3 4 9 14)))
      (let ((out (make-array 64 :element-type '(unsigned-byte 8))))
        (dotimes (i 16 out)
          (let ((w (plus (aref x i) (aref in i))))
            (dotimes (k 4)
              (setf (aref out (+ (* 4 i) k)) (ldb (byte 8 (* 8 k)) w)))))))))

(defstruct (%ref-chacha (:conc-name %ref-))
  "chacha-ref's ECRYPT_ctx: the key words, the 64-bit counter of words 12-13
and the IV words 14-15."
  key-words (counter 0) (w14 0) (w15 0))

(defun %ref-keysetup (key)
  "ECRYPT_keysetup then ECRYPT_ivsetup with a zero IV: counter and IV zero."
  (make-%ref-chacha :key-words (loop for i below 8
                                     collect (loop for k below 4 sum (ash (aref key (+ (* 4 i) k)) (* 8 k))))))

(defun %ref-keystream (ctx n)
  "ECRYPT_keystream_bytes: N bytes from whole blocks, the counter advanced by
every block begun."
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (loop for pos from 0 below n by 64
          do (let ((block (%ref-chacha20-block (%ref-key-words ctx)
                                               (ldb (byte 32 0) (%ref-counter ctx))
                                               (ldb (byte 32 32) (%ref-counter ctx))
                                               (%ref-w14 ctx) (%ref-w15 ctx))))
               (replace out block :start1 pos)
               (setf (%ref-counter ctx) (ldb (byte 64 0) (1+ (%ref-counter ctx))))))
    out))

(define-fuzz-target crypto-diff-fuzz-chacha20
    (buffer :core "crypto_diff_fuzz_chacha20.cpp:264-323" :iterations 1500 :max-len 500)
  "Under any sequence of SetKey, Seek, Keystream and Crypt our ChaCha20
produces the bytes Bernstein's reference implementation does, and the block
counter stays where the reference's is."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (%fuzz-key32 fdp))
         (ours (raw-chacha20 key))
         (ref (%ref-keysetup key))
         (nonce1 0) (nonce2 0) (counter 0))
    (flet ((after-request (n)
             ;; The reference seeks to a whole block after every request.
             (let ((old counter))
               (setf counter (ldb (byte 32 0) (+ counter (ceiling n 64))))
               (when (< counter old) (setf nonce1 (ldb (byte 32 0) (1+ nonce1))))
               (when (plusp (mod n 64))
                 (raw-chacha20-seek ours nonce1 nonce2 counter)))
             (fuzz-assert (= counter (ldb (byte 32 0) (%ref-counter ref)))
                          "our counter ~D, the reference's ~D" counter (ldb (byte 32 0) (%ref-counter ref)))))
      (limited-while ((consume-bool fdp) 3000)
        (call-one-of fdp
          (let ((key (%fuzz-key32 fdp)))
            (setf ours (raw-chacha20 key) ref (%ref-keysetup key)
                  nonce1 0 nonce2 0 counter 0))
          (progn
            (setf nonce1 (consume-integral fdp :u32)
                  nonce2 (consume-integral fdp :u64)
                  counter (consume-integral fdp :u32))
            (raw-chacha20-seek ours nonce1 nonce2 counter)
            (setf (%ref-counter ref) (logior counter (ash nonce1 32))
                  (%ref-w14 ref) (ldb (byte 32 0) nonce2)
                  (%ref-w15 ref) (ldb (byte 32 32) nonce2)))
          (let* ((n (consume-integral-in-range fdp 0 4096))
                 (out (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
            (raw-chacha20-keystream ours out)
            (fuzz-assert (equalp (fuzz-sabotage out) (%ref-keystream ref n))
                         "~D bytes of keystream differ from the reference's" n)
            (after-request n))
          (let* ((n (consume-integral-in-range fdp 0 4096))
                 (in (let ((v (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
                       (replace v (consume-bytes fdp n))))
                 (out (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
            (raw-chacha20-crypt ours in out)
            (fuzz-assert (equalp (fuzz-sabotage out)
                                 (map '(vector (unsigned-byte 8)) #'logxor in (%ref-keystream ref n)))
                         "Crypt of ~D bytes differs from the reference's" n)
            (after-request n)))))))
