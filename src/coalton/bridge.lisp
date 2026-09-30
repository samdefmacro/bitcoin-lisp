;;;; The byte-vector crossing between CL and the Coalton interpreter.
;;;;
;;;; Coalton's (Vector U8) is a (VECTOR T): the interpreter's scripts, witness
;;;; items and stack elements are SIMPLE-VECTORs of fixnums, while every CL
;;;; layer (the wire, the crypto FFI, the sighash writers) holds octets. These
;;;; two functions are the whole crossing. They load before the Coalton files
;;;; (in the bridge's own package, defined in package.lisp) so the interpreter
;;;; and the hash wrappers can call them directly.

(in-package #:bitcoin-lisp.coalton.interop)

(defun cl-array-to-coalton-vector (cl-array)
  "Convert a CL byte array to a Coalton vector: a SIMPLE-VECTOR holding the
same elements, which is what (map 'vector #'identity cl-array) returns.

An octet vector -- every script, witness item and stack element the script
paths hand over -- is copied by a typed loop. The generic MAP calls IDENTITY
per element, and the round-10 IBD profile (2,100 regtest blocks of ~925 KB,
sb-sprof over the syncing node) put 12.5% of all samples here: each P2WSH
input converts its scriptPubKey five times. Anything else keeps the generic
path."
  (if (typep cl-array '(simple-array (unsigned-byte 8) (*)))
      (let* ((n (length cl-array))
             (v (make-array n)))
        (declare (type (simple-array (unsigned-byte 8) (*)) cl-array)
                 (type simple-vector v))
        (dotimes (i n v)
          (setf (svref v i) (aref cl-array i))))
      (map 'vector #'identity cl-array)))

(defun coalton-vector-to-cl-array (vec &optional (start 0))
  "VEC's elements from START as a (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)): what
(coerce (subseq vec start) '(simple-array (unsigned-byte 8) (*))) returns,
VEC itself included when it already is one and START is 0. An element that is
not an octet is a TYPE-ERROR, as it is for COERCE.

A Coalton vector (a SIMPLE-VECTOR) is copied by a typed loop. COERCE ran it
through the generic REPLACE, checking each element's type through a full
call: every CHECKSIG converted its signature, its pubkey and the script from
the last OP_CODESEPARATOR that way (the last one twice, SUBSEQ then COERCE),
10.4% of the samples of the interpreter over a fixed P2WSH set and 2.6% of
the round-10 IBD profile, as REPLACE under EXECUTE-OPCODE."
  (typecase vec
    ((simple-array (unsigned-byte 8) (*))
     (if (zerop start) vec (subseq vec start)))
    (simple-vector
     (let* ((n (- (length vec) start))
            (out (make-array n :element-type '(unsigned-byte 8))))
       (declare (type fixnum start n))
       (dotimes (i n out)
         (setf (aref out i) (the (unsigned-byte 8) (svref vec (+ start i)))))))
    (t
     (coerce (subseq vec start) '(simple-array (unsigned-byte 8) (*))))))
