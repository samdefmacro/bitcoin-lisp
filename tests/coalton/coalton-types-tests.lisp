;;;; Tests for Coalton core types
;;;;
;;;; Tests that Hash256, Hash160, Satoshi, and BlockHeight types
;;;; work correctly and provide type safety.

(in-package #:bitcoin-lisp.coalton.tests)

(in-suite coalton-tests)

(test satoshi-creation
  "Test Satoshi type creation."
  (is (= 100 (coalton:coalton
              (bl.ctypes:satoshi-value
               (bl.ctypes:make-satoshi 100))))))

(test satoshi-arithmetic
  "Test Satoshi arithmetic operations."
  (is (= 150 (coalton:coalton
              (bl.ctypes:satoshi-value
               (bl.ctypes:satoshi-add
                (bl.ctypes:make-satoshi 100)
                (bl.ctypes:make-satoshi 50)))))))

(test satoshi-subtraction
  "Test Satoshi subtraction."
  (is (= 70 (coalton:coalton
             (bl.ctypes:satoshi-value
              (bl.ctypes:satoshi-sub
               (bl.ctypes:make-satoshi 100)
               (bl.ctypes:make-satoshi 30)))))))

(test block-height-creation
  "Test BlockHeight type creation."
  (is (= 100 (coalton:coalton
              (bl.ctypes:block-height-value
               (bl.ctypes:make-block-height 100))))))

(test block-height-next
  "Test BlockHeight increment operation."
  (is (= 101 (coalton:coalton
              (bl.ctypes:block-height-value
               (bl.ctypes:block-height-next
                (bl.ctypes:make-block-height 100)))))))

(test hash256-zero-length
  "Test Hash256 zero value has correct length."
  (is (= 32 (coalton:coalton
             (coalton-library/vector:length
              (bl.ctypes:hash256-bytes
               (bl.ctypes:hash256-zero)))))))

(test hash160-zero-length
  "Test Hash160 zero value has correct length."
  (is (= 20 (coalton:coalton
             (coalton-library/vector:length
              (bl.ctypes:hash160-bytes
               (bl.ctypes:hash160-zero)))))))

(test satoshi-zero-value
  "Test Satoshi zero value."
  (is (= 0 (coalton:coalton
            (bl.ctypes:satoshi-value
             (bl.ctypes:satoshi-zero))))))

(test block-height-zero-value
  "Test BlockHeight zero value."
  (is (= 0 (coalton:coalton
            (bl.ctypes:block-height-value
             (bl.ctypes:block-height-zero))))))

(test the-script-vector-conversion-keeps-its-elements-and-its-type
  "CL-ARRAY-TO-COALTON-VECTOR hands every script, witness item and stack
element to the Coalton interpreter: the round-10 IBD profile (2,100 regtest
blocks of ~925 KB, sb-sprof over the syncing node) put 12.5% of all samples
under it -- a generic (map 'vector #'identity x) calling IDENTITY per byte,
five times per P2WSH input (validate-p2wsh, is-witness-program-p,
get-witness-version, get-witness-program-bytes, is-p2sh-script-p). The typed
copy must hand the interpreter exactly what the generic map did: a
SIMPLE-VECTOR (element type T) with the same elements, for octet vectors of
every length a script path sees, and for the non-simple inputs the generic
path still serves."
  (dolist (n '(0 1 2 22 32 34 35 72 520 10000))
    (let ((octets (make-array n :element-type '(unsigned-byte 8))))
      (dotimes (i n) (setf (aref octets i) (mod (* 31 (1+ i)) 256)))
      (let ((generic (map 'vector #'identity octets))
            (got (bl.interop:cl-array-to-coalton-vector octets)))
        (is (equalp generic got) "length ~D: same elements" n)
        (is (typep got 'simple-vector) "length ~D: a simple-vector" n)
        (is (= n (length got))))))
  (let ((adjustable (make-array 3 :element-type '(unsigned-byte 8) :adjustable t
                                  :initial-contents '(1 2 255))))
    (is (equalp #(1 2 255) (bl.interop:cl-array-to-coalton-vector adjustable)))
    (is (typep (bl.interop:cl-array-to-coalton-vector adjustable) 'simple-vector)))
  (is (equalp #(7 8) (bl.interop:cl-array-to-coalton-vector (list 7 8)))))
