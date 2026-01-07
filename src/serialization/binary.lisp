(in-package #:bitcoin-lisp.serialization)

;;; Binary serialization primitives for Bitcoin protocol
;;;
;;; Bitcoin uses little-endian byte order for most integer fields.
;;; This module provides functions to read and write binary data
;;; from/to streams in the correct format.

;;;; Reading primitives

(defun read-uint8 (stream)
  "Read an unsigned 8-bit integer from STREAM."
  (read-byte stream))

(defun read-uint16-le (stream)
  "Read an unsigned 16-bit little-endian integer from STREAM."
  (let ((b0 (read-byte stream))
        (b1 (read-byte stream)))
    (logior b0 (ash b1 8))))

(defun read-uint32-le (stream)
  "Read an unsigned 32-bit little-endian integer from STREAM."
  (let ((b0 (read-byte stream))
        (b1 (read-byte stream))
        (b2 (read-byte stream))
        (b3 (read-byte stream)))
    (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))

(defun read-uint64-le (stream)
  "Read an unsigned 64-bit little-endian integer from STREAM."
  (let ((low (read-uint32-le stream))
        (high (read-uint32-le stream)))
    (logior low (ash high 32))))

(defun read-int32-le (stream)
  "Read a signed 32-bit little-endian integer from STREAM."
  (let ((val (read-uint32-le stream)))
    (if (logbitp 31 val)
        (- val #x100000000)
        val)))

(defun read-int64-le (stream)
  "Read a signed 64-bit little-endian integer from STREAM."
  (let ((val (read-uint64-le stream)))
    (if (logbitp 63 val)
        (- val #x10000000000000000)
        val)))

;;;; Writing primitives

(defun write-uint8 (stream value)
  "Write an unsigned 8-bit integer to STREAM."
  (write-byte (logand value #xFF) stream))

(defun write-uint16-le (stream value)
  "Write an unsigned 16-bit little-endian integer to STREAM."
  (write-byte (logand value #xFF) stream)
  (write-byte (logand (ash value -8) #xFF) stream))

(defun write-uint32-le (stream value)
  "Write an unsigned 32-bit little-endian integer to STREAM."
  (write-byte (logand value #xFF) stream)
  (write-byte (logand (ash value -8) #xFF) stream)
  (write-byte (logand (ash value -16) #xFF) stream)
  (write-byte (logand (ash value -24) #xFF) stream))

(defun write-uint64-le (stream value)
  "Write an unsigned 64-bit little-endian integer to STREAM."
  (write-uint32-le stream (logand value #xFFFFFFFF))
  (write-uint32-le stream (logand (ash value -32) #xFFFFFFFF)))

(defun write-int32-le (stream value)
  "Write a signed 32-bit little-endian integer to STREAM."
  (write-uint32-le stream (if (minusp value)
                              (+ value #x100000000)
                              value)))

(defun write-int64-le (stream value)
  "Write a signed 64-bit little-endian integer to STREAM."
  (write-uint64-le stream (if (minusp value)
                              (+ value #x10000000000000000)
                              value)))

;;;; CompactSize (variable-length integer encoding)
;;;
;;; Bitcoin uses a variable-length integer encoding called CompactSize:
;;; - 0-252: 1 byte (value as-is)
;;; - 253-65535: 3 bytes (0xFD followed by uint16)
;;; - 65536-4294967295: 5 bytes (0xFE followed by uint32)
;;; - Larger: 9 bytes (0xFF followed by uint64)

(defun read-compact-size (stream)
  "Read a CompactSize-encoded integer from STREAM."
  (let ((first-byte (read-byte stream)))
    (cond
      ((< first-byte 253) first-byte)
      ((= first-byte 253) (read-uint16-le stream))
      ((= first-byte 254) (read-uint32-le stream))
      ((= first-byte 255) (read-uint64-le stream)))))

(defun write-compact-size (stream value)
  "Write a CompactSize-encoded integer to STREAM."
  (cond
    ((< value 253)
     (write-byte value stream))
    ((<= value #xFFFF)
     (write-byte 253 stream)
     (write-uint16-le stream value))
    ((<= value #xFFFFFFFF)
     (write-byte 254 stream)
     (write-uint32-le stream value))
    (t
     (write-byte 255 stream)
     (write-uint64-le stream value))))

;;;; Byte vector operations

(defun read-bytes (stream count)
  "Read COUNT bytes from STREAM, returning a byte vector."
  (let ((bytes (make-array count :element-type '(unsigned-byte 8))))
    (read-sequence bytes stream)
    bytes))

(defun write-bytes (stream bytes)
  "Write byte vector BYTES to STREAM."
  (write-sequence bytes stream))

(defun read-var-bytes (stream)
  "Read a variable-length byte vector (prefixed with CompactSize length)."
  (let ((length (read-compact-size stream)))
    (read-bytes stream length)))

(defun write-var-bytes (stream bytes)
  "Write a variable-length byte vector (prefixed with CompactSize length)."
  (write-compact-size stream (length bytes))
  (write-bytes stream bytes))

;;;; Hash reading/writing (32 bytes, used for txid, block hash, etc.)

(defun read-hash256 (stream)
  "Read a 256-bit hash (32 bytes) from STREAM."
  (read-bytes stream 32))

(defun write-hash256 (stream hash)
  "Write a 256-bit hash (32 bytes) to STREAM."
  (assert (= (length hash) 32))
  (write-bytes stream hash))
