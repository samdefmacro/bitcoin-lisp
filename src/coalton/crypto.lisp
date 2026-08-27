;;;; Typed cryptographic operations for Bitcoin
;;;;
;;;; This module provides typed wrappers around the existing CL crypto
;;;; functions, ensuring that hash functions return the correct type
;;;; (Hash256 or Hash160) at compile time.

(in-package #:bitcoin-lisp.coalton.crypto)

(named-readtables:in-readtable coalton:coalton)

(coalton-toplevel

  (declare compute-sha256 ((Vector U8) -> bl.ctypes:Hash256))
  (define (compute-sha256 data)
    "Compute SHA-256 hash. Returns Hash256 (32 bytes)."
    (bl.ctypes:Hash256
     (lisp (Vector U8) (data)
       (cl:let* ((cl-data (cl:coerce data '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                 (result (bl.crypto:sha256 cl-data)))
         (cl:map 'cl:vector #'cl:identity result)))))

  (declare compute-hash256 ((Vector U8) -> bl.ctypes:Hash256))
  (define (compute-hash256 data)
    "Compute double SHA-256 hash (Bitcoin standard). Returns Hash256."
    (bl.ctypes:Hash256
     (lisp (Vector U8) (data)
       (cl:let* ((cl-data (cl:coerce data '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                 (result (bl.crypto:hash256 cl-data)))
         (cl:map 'cl:vector #'cl:identity result)))))

  (declare compute-ripemd160 ((Vector U8) -> bl.ctypes:Hash160))
  (define (compute-ripemd160 data)
    "Compute RIPEMD-160 hash. Returns Hash160 (20 bytes)."
    (bl.ctypes:Hash160
     (lisp (Vector U8) (data)
       (cl:let* ((cl-data (cl:coerce data '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                 (result (bl.crypto:ripemd160 cl-data)))
         (cl:map 'cl:vector #'cl:identity result)))))

  (declare compute-hash160 ((Vector U8) -> bl.ctypes:Hash160))
  (define (compute-hash160 data)
    "Compute Hash160: RIPEMD160(SHA256(data)). Used for addresses."
    (bl.ctypes:Hash160
     (lisp (Vector U8) (data)
       (cl:let* ((cl-data (cl:coerce data '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                 (result (bl.crypto:hash160 cl-data)))
         (cl:map 'cl:vector #'cl:identity result)))))

  (declare bytes-to-hex ((Vector U8) -> String))
  (define (bytes-to-hex bytes)
    "Convert a byte vector to a hexadecimal string."
    (lisp String (bytes)
      (cl:let ((cl-bytes (cl:coerce bytes '(cl:simple-array (cl:unsigned-byte 8) (cl:*)))))
        (bl.crypto:bytes-to-hex cl-bytes)))))
