;;;; Tests for Coalton core types
;;;;
;;;; Tests that Hash256, Hash160, Satoshi, and BlockHeight types
;;;; work correctly and provide type safety.

(in-package #:bitcoin-lisp.coalton.tests)

(in-suite coalton-tests)

(test satoshi-creation
  "Test Satoshi type creation."
  (is (= 100 (coalton:coalton
              (bitcoin-lisp.coalton.types:satoshi-value
               (bitcoin-lisp.coalton.types:make-satoshi 100))))))

(test satoshi-arithmetic
  "Test Satoshi arithmetic operations."
  (is (= 150 (coalton:coalton
              (bitcoin-lisp.coalton.types:satoshi-value
               (bitcoin-lisp.coalton.types:satoshi-add
                (bitcoin-lisp.coalton.types:make-satoshi 100)
                (bitcoin-lisp.coalton.types:make-satoshi 50)))))))

(test satoshi-subtraction
  "Test Satoshi subtraction."
  (is (= 70 (coalton:coalton
             (bitcoin-lisp.coalton.types:satoshi-value
              (bitcoin-lisp.coalton.types:satoshi-sub
               (bitcoin-lisp.coalton.types:make-satoshi 100)
               (bitcoin-lisp.coalton.types:make-satoshi 30)))))))

(test block-height-creation
  "Test BlockHeight type creation."
  (is (= 100 (coalton:coalton
              (bitcoin-lisp.coalton.types:block-height-value
               (bitcoin-lisp.coalton.types:make-block-height 100))))))

(test block-height-next
  "Test BlockHeight increment operation."
  (is (= 101 (coalton:coalton
              (bitcoin-lisp.coalton.types:block-height-value
               (bitcoin-lisp.coalton.types:block-height-next
                (bitcoin-lisp.coalton.types:make-block-height 100)))))))

(test hash256-zero-length
  "Test Hash256 zero value has correct length."
  (is (= 32 (coalton:coalton
             (coalton-library/vector:length
              (bitcoin-lisp.coalton.types:hash256-bytes
               (bitcoin-lisp.coalton.types:hash256-zero)))))))

(test hash160-zero-length
  "Test Hash160 zero value has correct length."
  (is (= 20 (coalton:coalton
             (coalton-library/vector:length
              (bitcoin-lisp.coalton.types:hash160-bytes
               (bitcoin-lisp.coalton.types:hash160-zero)))))))

(test satoshi-zero-value
  "Test Satoshi zero value."
  (is (= 0 (coalton:coalton
            (bitcoin-lisp.coalton.types:satoshi-value
             (bitcoin-lisp.coalton.types:satoshi-zero))))))

(test block-height-zero-value
  "Test BlockHeight zero value."
  (is (= 0 (coalton:coalton
            (bitcoin-lisp.coalton.types:block-height-value
             (bitcoin-lisp.coalton.types:block-height-zero))))))
