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

(test a-stack-element-leaves-the-interpreter-as-coerce-would-hand-it-over
  "COALTON-VECTOR-TO-CL-ARRAY hands CHECKSIG, CHECKMULTISIG, the hash opcodes
and OP_CODESEPARATOR their octets. Its typed copy must return exactly what
(coerce (subseq v start) '(simple-array (unsigned-byte 8) (*))) returned: the
same octets for every start, the argument itself when it already is an octet
vector and START is 0, and a TYPE-ERROR for an element that is not an octet."
  (let ((octet-type '(simple-array (unsigned-byte 8) (*))))
    (dolist (n '(0 1 33 72 520 10000))
      (let ((v (make-array n)))
        (dotimes (i n) (setf (svref v i) (mod (* 37 (1+ i)) 256)))
        (dolist (start (remove-duplicates (list 0 1 (floor n 2) n)))
          (when (<= start n)
            (let ((generic (coerce (subseq v start) octet-type))
                  (got (bl.interop:coalton-vector-to-cl-array v start)))
              (is (equalp generic got) "length ~D from ~D: same octets" n start)
              (is (typep got octet-type) "length ~D from ~D: an octet vector" n start))))))
    (let ((octets (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(1 2 3))))
      (is (eq octets (bl.interop:coalton-vector-to-cl-array octets)))
      (is (equalp #(2 3) (bl.interop:coalton-vector-to-cl-array octets 1))))
    (is (equalp #(4 5) (bl.interop:coalton-vector-to-cl-array (list 4 5))))
    (signals type-error (bl.interop:coalton-vector-to-cl-array (vector 1 256 3)))
    (signals type-error (bl.interop:coalton-vector-to-cl-array (vector 1 -1)))))

(test the-script-execution-cache-key-reads-the-flags-string-it-is-given
  "MAKE-SCRIPT-EXECUTION-CACHE-KEY remembers the bytes of the last flags
string by EQ. A key must still depend on the string's CHARACTERS alone: the
same flags in a fresh string give the same key, different flags give a
different one, and alternating between two strings (every block after a
flag-changing height does) never answers with the other string's bytes."
  (let* ((wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
         (a (bl.val:compute-script-flags-for-height 1000))
         (b (concatenate 'string a ",CLEANSTACK"))
         (key-a (bl.interop:make-script-execution-cache-key wtxid a))
         (key-b (bl.interop:make-script-execution-cache-key wtxid b)))
    (is (not (equalp key-a key-b)) "different flags, different keys")
    (is (equalp key-a (bl.interop:make-script-execution-cache-key wtxid (copy-seq a))))
    (is (equalp key-b (bl.interop:make-script-execution-cache-key wtxid (copy-seq b))))
    (dotimes (i 3)
      (is (equalp key-a (bl.interop:make-script-execution-cache-key wtxid a)))
      (is (equalp key-b (bl.interop:make-script-execution-cache-key wtxid b))))
    (is (not (equalp key-a (bl.interop:make-script-execution-cache-key wtxid nil))))
    (is (equalp (bl.interop:make-script-execution-cache-key wtxid nil)
                (bl.interop:make-script-execution-cache-key wtxid "")))))

(test flag-lookups-answer-for-the-flags-string-bound-now
  "FLAG-ENABLED-P recognizes the last flags string by EQ before its
synchronized EQUAL-keyed cache (the round-10 IBD profile put 10.2% of all
samples in that cache's lock). The answer must still be the one a fresh parse
of the string bound NOW gives: after a different string, after an EQUAL copy
of an earlier one, with no flags at all, and with two threads asking about
two different strings at the same time."
  (let ((a "P2SH,WITNESS,DERSIG")
        (b "TAPROOT,P2SH"))
    (flet ((answers (flags)
             (let ((bl.interop:*script-flags* flags))
               (list (bl.interop:flag-enabled-p "P2SH")
                     (bl.interop:flag-enabled-p "WITNESS")
                     (bl.interop:flag-enabled-p "TAPROOT")))))
      (is (equal '(t t nil) (answers a)))
      (is (equal '(t nil t) (answers b)) "a different string is not the last one")
      (is (equal '(t t nil) (answers (copy-seq a))) "an EQUAL copy answers the same")
      (is (equal '(nil nil nil) (answers nil)) "no flags, nothing enabled")
      (let* ((wrong 0)
             (lock (bt:make-lock))
             (threads
               (loop for (flags expected) in (list (list a '(t t nil)) (list b '(t nil t)))
                     collect (let ((flags flags) (expected expected))
                               (bt:make-thread
                                (lambda ()
                                  (handler-case
                                      (dotimes (i 20000)
                                        (declare (ignorable i))
                                        (unless (equal expected (answers flags))
                                          (bt:with-lock-held (lock) (incf wrong))))
                                    (error () (bt:with-lock-held (lock) (incf wrong))))))))))
        (mapc #'bt:join-thread threads)
        (is (= 0 wrong) "two threads, two strings: ~D wrong answers" wrong)))))
