;;;; Typed binary serialization primitives
;;;;
;;;; This module provides statically-typed binary read/write operations
;;;; for Bitcoin protocol serialization. Functions work on byte vectors
;;;; with explicit position tracking for pure functional semantics.
;;;;
;;;; Reading: (Vector U8) -> UFix -> (Tuple Value UFix)
;;;; Writing: Value -> (Vector U8)

(in-package #:bitcoin-lisp.coalton.binary)

(named-readtables:in-readtable coalton:coalton)

(coalton-toplevel

  ;;;; Result type for read operations
  ;;;; Returns the value read and the new position

  (define-type (ReadResult :a)
    "Result of a binary read operation: value and new position."
    (ReadResult :a UFix))

  (declare read-result-value ((ReadResult :a) -> :a))
  (define (read-result-value rr)
    (match rr
      ((ReadResult v _) v)))

  (declare read-result-position ((ReadResult :a) -> UFix))
  (define (read-result-position rr)
    (match rr
      ((ReadResult _ pos) pos)))

  ;;;; Basic byte access

  (declare read-u8 ((Vector U8) -> UFix -> (ReadResult U8)))
  (define (read-u8 bytes pos)
    "Read an unsigned 8-bit integer at position POS."
    (ReadResult (coalton-library/vector:index-unsafe pos bytes)
                (+ pos 1)))

  ;;;; Little-endian unsigned integers

  (declare read-u16-le ((Vector U8) -> UFix -> (ReadResult U16)))
  (define (read-u16-le bytes pos)
    "Read an unsigned 16-bit little-endian integer."
    (lisp (ReadResult U16) (bytes pos)
      (cl:let ((b0 (cl:aref bytes pos))
               (b1 (cl:aref bytes (cl:1+ pos))))
        (ReadResult (cl:logior b0 (cl:ash b1 8))
                    (cl:+ pos 2)))))

  (declare read-u32-le ((Vector U8) -> UFix -> (ReadResult U32)))
  (define (read-u32-le bytes pos)
    "Read an unsigned 32-bit little-endian integer."
    (lisp (ReadResult U32) (bytes pos)
      (cl:let ((b0 (cl:aref bytes pos))
               (b1 (cl:aref bytes (cl:+ pos 1)))
               (b2 (cl:aref bytes (cl:+ pos 2)))
               (b3 (cl:aref bytes (cl:+ pos 3))))
        (ReadResult (cl:logior b0 (cl:ash b1 8) (cl:ash b2 16) (cl:ash b3 24))
                    (cl:+ pos 4)))))

  (declare read-u64-le ((Vector U8) -> UFix -> (ReadResult U64)))
  (define (read-u64-le bytes pos)
    "Read an unsigned 64-bit little-endian integer."
    (lisp (ReadResult U64) (bytes pos)
      (cl:let* ((b0 (cl:aref bytes pos))
                (b1 (cl:aref bytes (cl:+ pos 1)))
                (b2 (cl:aref bytes (cl:+ pos 2)))
                (b3 (cl:aref bytes (cl:+ pos 3)))
                (b4 (cl:aref bytes (cl:+ pos 4)))
                (b5 (cl:aref bytes (cl:+ pos 5)))
                (b6 (cl:aref bytes (cl:+ pos 6)))
                (b7 (cl:aref bytes (cl:+ pos 7))))
        (ReadResult (cl:logior b0
                               (cl:ash b1 8)
                               (cl:ash b2 16)
                               (cl:ash b3 24)
                               (cl:ash b4 32)
                               (cl:ash b5 40)
                               (cl:ash b6 48)
                               (cl:ash b7 56))
                    (cl:+ pos 8)))))

  ;;;; Little-endian signed integers

  (declare read-i32-le ((Vector U8) -> UFix -> (ReadResult I32)))
  (define (read-i32-le bytes pos)
    "Read a signed 32-bit little-endian integer."
    (lisp (ReadResult I32) (bytes pos)
      (cl:let* ((b0 (cl:aref bytes pos))
                (b1 (cl:aref bytes (cl:+ pos 1)))
                (b2 (cl:aref bytes (cl:+ pos 2)))
                (b3 (cl:aref bytes (cl:+ pos 3)))
                (val (cl:logior b0 (cl:ash b1 8) (cl:ash b2 16) (cl:ash b3 24))))
        (ReadResult (cl:if (cl:logbitp 31 val)
                           (cl:- val #x100000000)
                           val)
                    (cl:+ pos 4)))))

  (declare read-i64-le ((Vector U8) -> UFix -> (ReadResult I64)))
  (define (read-i64-le bytes pos)
    "Read a signed 64-bit little-endian integer."
    (lisp (ReadResult I64) (bytes pos)
      (cl:let* ((b0 (cl:aref bytes pos))
                (b1 (cl:aref bytes (cl:+ pos 1)))
                (b2 (cl:aref bytes (cl:+ pos 2)))
                (b3 (cl:aref bytes (cl:+ pos 3)))
                (b4 (cl:aref bytes (cl:+ pos 4)))
                (b5 (cl:aref bytes (cl:+ pos 5)))
                (b6 (cl:aref bytes (cl:+ pos 6)))
                (b7 (cl:aref bytes (cl:+ pos 7)))
                (val (cl:logior b0
                                (cl:ash b1 8)
                                (cl:ash b2 16)
                                (cl:ash b3 24)
                                (cl:ash b4 32)
                                (cl:ash b5 40)
                                (cl:ash b6 48)
                                (cl:ash b7 56))))
        (ReadResult (cl:if (cl:logbitp 63 val)
                           (cl:- val #x10000000000000000)
                           val)
                    (cl:+ pos 8)))))

  ;;;; CompactSize (Bitcoin variable-length integer)

  (declare read-compact-size ((Vector U8) -> UFix -> (ReadResult U64)))
  (define (read-compact-size bytes pos)
    "Read a CompactSize-encoded integer."
    (lisp (ReadResult U64) (bytes pos)
      (cl:let ((first-byte (cl:aref bytes pos)))
        (cl:cond
          ((cl:< first-byte 253)
           (ReadResult first-byte (cl:1+ pos)))
          ((cl:= first-byte 253)
           (cl:let ((b0 (cl:aref bytes (cl:+ pos 1)))
                    (b1 (cl:aref bytes (cl:+ pos 2))))
             (ReadResult (cl:logior b0 (cl:ash b1 8))
                         (cl:+ pos 3))))
          ((cl:= first-byte 254)
           (cl:let ((b0 (cl:aref bytes (cl:+ pos 1)))
                    (b1 (cl:aref bytes (cl:+ pos 2)))
                    (b2 (cl:aref bytes (cl:+ pos 3)))
                    (b3 (cl:aref bytes (cl:+ pos 4))))
             (ReadResult (cl:logior b0 (cl:ash b1 8) (cl:ash b2 16) (cl:ash b3 24))
                         (cl:+ pos 5))))
          (cl:t
           (cl:let* ((b0 (cl:aref bytes (cl:+ pos 1)))
                     (b1 (cl:aref bytes (cl:+ pos 2)))
                     (b2 (cl:aref bytes (cl:+ pos 3)))
                     (b3 (cl:aref bytes (cl:+ pos 4)))
                     (b4 (cl:aref bytes (cl:+ pos 5)))
                     (b5 (cl:aref bytes (cl:+ pos 6)))
                     (b6 (cl:aref bytes (cl:+ pos 7)))
                     (b7 (cl:aref bytes (cl:+ pos 8))))
             (ReadResult (cl:logior b0
                                    (cl:ash b1 8)
                                    (cl:ash b2 16)
                                    (cl:ash b3 24)
                                    (cl:ash b4 32)
                                    (cl:ash b5 40)
                                    (cl:ash b6 48)
                                    (cl:ash b7 56))
                         (cl:+ pos 9))))))))

  ;;;; Byte slice reading

  (declare read-bytes ((Vector U8) -> UFix -> UFix -> (ReadResult (Vector U8))))
  (define (read-bytes source pos count)
    "Read COUNT bytes starting at POS, returning a new vector."
    (let ((result (lisp (Vector U8) (source pos count)
                    (cl:let ((dest (cl:make-array count :element-type 'cl:t)))
                      (cl:dotimes (i count dest)
                        (cl:setf (cl:aref dest i)
                                 (cl:aref source (cl:+ pos i))))))))
      (ReadResult result (+ pos count))))

  ;;;; Writing primitives - build byte vectors

  (declare write-u8 (U8 -> (Vector U8)))
  (define (write-u8 val)
    "Write an unsigned 8-bit integer to a 1-byte vector."
    (lisp (Vector U8) (val)
      (cl:vector val)))

  (declare write-u16-le (U16 -> (Vector U8)))
  (define (write-u16-le val)
    "Write an unsigned 16-bit little-endian integer to a 2-byte vector."
    (lisp (Vector U8) (val)
      (cl:vector (cl:logand val #xFF)
                 (cl:logand (cl:ash val -8) #xFF))))

  (declare write-u32-le (U32 -> (Vector U8)))
  (define (write-u32-le val)
    "Write an unsigned 32-bit little-endian integer to a 4-byte vector."
    (lisp (Vector U8) (val)
      (cl:vector (cl:logand val #xFF)
                 (cl:logand (cl:ash val -8) #xFF)
                 (cl:logand (cl:ash val -16) #xFF)
                 (cl:logand (cl:ash val -24) #xFF))))

  (declare write-u64-le (U64 -> (Vector U8)))
  (define (write-u64-le val)
    "Write an unsigned 64-bit little-endian integer to an 8-byte vector."
    (lisp (Vector U8) (val)
      (cl:vector (cl:logand val #xFF)
                 (cl:logand (cl:ash val -8) #xFF)
                 (cl:logand (cl:ash val -16) #xFF)
                 (cl:logand (cl:ash val -24) #xFF)
                 (cl:logand (cl:ash val -32) #xFF)
                 (cl:logand (cl:ash val -40) #xFF)
                 (cl:logand (cl:ash val -48) #xFF)
                 (cl:logand (cl:ash val -56) #xFF))))

  (declare write-i32-le (I32 -> (Vector U8)))
  (define (write-i32-le val)
    "Write a signed 32-bit little-endian integer to a 4-byte vector."
    (lisp (Vector U8) (val)
      (cl:let ((uval (cl:if (cl:minusp val)
                            (cl:+ val #x100000000)
                            val)))
        (cl:vector (cl:logand uval #xFF)
                   (cl:logand (cl:ash uval -8) #xFF)
                   (cl:logand (cl:ash uval -16) #xFF)
                   (cl:logand (cl:ash uval -24) #xFF)))))

  (declare write-i64-le (I64 -> (Vector U8)))
  (define (write-i64-le val)
    "Write a signed 64-bit little-endian integer to an 8-byte vector."
    (lisp (Vector U8) (val)
      (cl:let ((uval (cl:if (cl:minusp val)
                            (cl:+ val #x10000000000000000)
                            val)))
        (cl:vector (cl:logand uval #xFF)
                   (cl:logand (cl:ash uval -8) #xFF)
                   (cl:logand (cl:ash uval -16) #xFF)
                   (cl:logand (cl:ash uval -24) #xFF)
                   (cl:logand (cl:ash uval -32) #xFF)
                   (cl:logand (cl:ash uval -40) #xFF)
                   (cl:logand (cl:ash uval -48) #xFF)
                   (cl:logand (cl:ash uval -56) #xFF)))))

  (declare write-compact-size (U64 -> (Vector U8)))
  (define (write-compact-size val)
    "Write a CompactSize-encoded integer."
    (lisp (Vector U8) (val)
      (cl:cond
        ((cl:< val 253)
         (cl:vector val))
        ((cl:<= val #xFFFF)
         (cl:vector 253
                    (cl:logand val #xFF)
                    (cl:logand (cl:ash val -8) #xFF)))
        ((cl:<= val #xFFFFFFFF)
         (cl:vector 254
                    (cl:logand val #xFF)
                    (cl:logand (cl:ash val -8) #xFF)
                    (cl:logand (cl:ash val -16) #xFF)
                    (cl:logand (cl:ash val -24) #xFF)))
        (cl:t
         (cl:vector 255
                    (cl:logand val #xFF)
                    (cl:logand (cl:ash val -8) #xFF)
                    (cl:logand (cl:ash val -16) #xFF)
                    (cl:logand (cl:ash val -24) #xFF)
                    (cl:logand (cl:ash val -32) #xFF)
                    (cl:logand (cl:ash val -40) #xFF)
                    (cl:logand (cl:ash val -48) #xFF)
                    (cl:logand (cl:ash val -56) #xFF))))))

  ;;;; Vector concatenation helper

  (declare concat-bytes ((Vector U8) -> (Vector U8) -> (Vector U8)))
  (define (concat-bytes a b)
    "Concatenate two byte vectors."
    (lisp (Vector U8) (a b)
      (cl:let* ((len-a (cl:length a))
                (len-b (cl:length b))
                (result (cl:make-array (cl:+ len-a len-b) :element-type 'cl:t)))
        (cl:dotimes (i len-a)
          (cl:setf (cl:aref result i) (cl:aref a i)))
        (cl:dotimes (i len-b result)
          (cl:setf (cl:aref result (cl:+ len-a i)) (cl:aref b i)))))))
