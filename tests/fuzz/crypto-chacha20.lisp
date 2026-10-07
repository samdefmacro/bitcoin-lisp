(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/crypto_chacha20.cpp at the pin, its first target,
;;;; crypto_chacha20 (:19-46): a ChaCha20 under any sequence of SetKey, Seek,
;;;; Keystream and Crypt. The file's other three targets (the two split
;;;; targets and crypto_fschacha20) are in crypto.lisp.
;;;;
;;;; Core asserts nothing but that the calls return. Ours runs a TWIN cipher
;;;; through the same SetKey and Seek calls and asks it for keystream only:
;;;; every Crypt must be its input XOR the twin's keystream for the same span,
;;;; and every Keystream the twin's -- so the buffered partial block, the
;;;; counter carry into the nonce and a seek that discards the buffer are
;;;; held to the one stream they must all agree on.

(def-suite :fuzz-crypto-chacha20-tests :in :bitcoin-lisp-tests
  :description "Core fuzz crypto_chacha20.cpp (crypto_chacha20)")

(in-suite :fuzz-crypto-chacha20-tests)

(defun %fuzz-key32 (fdp)
  "ConsumeFixedLengthByteVector(fdp, 32): zero-filled when the buffer runs dry."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace v (consume-bytes fdp 32))))

(define-fuzz-target crypto-chacha20
    (buffer :core "crypto_chacha20.cpp:19-46" :iterations 2000 :max-len 600)
  "A ChaCha20 under any sequence of SetKey, Seek, Keystream and Crypt: each
Crypt is its input XOR the keystream a twin cipher under the same keys and
seeks produces for that span, and each Keystream is the twin's."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (key (%fuzz-key32 fdp))
         (cipher (raw-chacha20 key))
         (twin (raw-chacha20 (copy-seq key))))
    (limited-while ((consume-bool fdp) 10000)
      (call-one-of fdp
        (let ((key (%fuzz-key32 fdp)))
          (setf cipher (raw-chacha20 key) twin (raw-chacha20 (copy-seq key))))
        (let ((nonce1 (consume-integral fdp :u32))
              (nonce2 (consume-integral fdp :u64))
              (counter (consume-integral fdp :u32)))
          (raw-chacha20-seek cipher nonce1 nonce2 counter)
          (raw-chacha20-seek twin nonce1 nonce2 counter))
        (let* ((n (consume-integral-in-range fdp 0 4096))
               (out (make-array n :element-type '(unsigned-byte 8) :initial-element 0))
               (want (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
          (raw-chacha20-keystream cipher out)
          (raw-chacha20-keystream twin want)
          (fuzz-assert (equalp (fuzz-sabotage out) want) "~D bytes of keystream differ from the twin's" n))
        (let* ((n (consume-integral-in-range fdp 0 4096))
               (in (let ((v (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
                     (replace v (consume-bytes fdp n))))
               (out (make-array n :element-type '(unsigned-byte 8) :initial-element 0))
               (stream (make-array n :element-type '(unsigned-byte 8) :initial-element 0)))
          (raw-chacha20-crypt cipher in out)
          (raw-chacha20-keystream twin stream)
          (fuzz-assert (equalp (fuzz-sabotage out) (map '(vector (unsigned-byte 8)) #'logxor in stream))
                       "Crypt of ~D bytes is not the input XOR the keystream" n))))))
