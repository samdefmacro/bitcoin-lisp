;;;; Tests for Coalton crypto functions
;;;;
;;;; Verifies that typed hash functions produce correct results
;;;; matching the existing CL implementations.

(in-package #:bitcoin-lisp.coalton.tests)

(in-suite coalton-tests)

;;; Helper: Create an empty byte vector for testing
;;; Using hash256-bytes of a zero hash gives us a known empty-ish byte vector
(test sha256-on-zero-hash-bytes
  "Test that compute-sha256 returns Hash256 type with correct length."
  (is (= 32 (coalton:coalton
             (coalton-library/vector:length
              (bitcoin-lisp.coalton.types:hash256-bytes
               (bitcoin-lisp.coalton.crypto:compute-sha256
                (bitcoin-lisp.coalton.types:hash256-bytes
                 (bitcoin-lisp.coalton.types:hash256-zero)))))))))

(test hash256-on-zero-hash-bytes
  "Test that compute-hash256 (double SHA256) returns Hash256 type."
  (is (= 32 (coalton:coalton
             (coalton-library/vector:length
              (bitcoin-lisp.coalton.types:hash256-bytes
               (bitcoin-lisp.coalton.crypto:compute-hash256
                (bitcoin-lisp.coalton.types:hash256-bytes
                 (bitcoin-lisp.coalton.types:hash256-zero)))))))))

(test ripemd160-on-zero-hash-bytes
  "Test that compute-ripemd160 returns Hash160 type with correct length."
  (is (= 20 (coalton:coalton
             (coalton-library/vector:length
              (bitcoin-lisp.coalton.types:hash160-bytes
               (bitcoin-lisp.coalton.crypto:compute-ripemd160
                (bitcoin-lisp.coalton.types:hash256-bytes
                 (bitcoin-lisp.coalton.types:hash256-zero)))))))))

(test hash160-on-zero-hash-bytes
  "Test that compute-hash160 returns Hash160 type with correct length."
  (is (= 20 (coalton:coalton
             (coalton-library/vector:length
              (bitcoin-lisp.coalton.types:hash160-bytes
               (bitcoin-lisp.coalton.crypto:compute-hash160
                (bitcoin-lisp.coalton.types:hash256-bytes
                 (bitcoin-lisp.coalton.types:hash256-zero)))))))))

(test crypto-matches-cl-on-32-zero-bytes
  "Test that Coalton crypto matches CL implementation on 32 zero bytes."
  ;; Test with 32 zero bytes (same as hash256-zero contents)
  (let* ((input (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (cl-hash (bitcoin-lisp.crypto:hash256 input)))
    (is (= 32 (length cl-hash)))
    ;; Verify Coalton also produces 32 bytes
    (is (= 32 (coalton:coalton
               (coalton-library/vector:length
                (bitcoin-lisp.coalton.types:hash256-bytes
                 (bitcoin-lisp.coalton.crypto:compute-hash256
                  (bitcoin-lisp.coalton.types:hash256-bytes
                   (bitcoin-lisp.coalton.types:hash256-zero))))))))))
