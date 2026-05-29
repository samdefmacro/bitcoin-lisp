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

(defconstant +max-compact-size+ #x02000000
  "Bitcoin Core MAX_SIZE (serialize.h:32): 32 MiB upper bound on any
   ReadCompactSize. Caps allocations driven by attacker-controlled length
   prefixes during transaction/block deserialization.")

(defun read-compact-size (stream &key (range-check t))
  "Read a CompactSize-encoded integer from STREAM.
Mirrors Bitcoin Core's ReadCompactSize (serialize.h:330-360):
- Rejects non-canonical encodings (e.g., 200 must use the 1-byte form).
- Caps the value at +max-compact-size+ when range-check is true."
  (let* ((first-byte (read-byte stream))
         (value (cond
                  ((< first-byte 253) first-byte)
                  ((= first-byte 253)
                   (let ((v (read-uint16-le stream)))
                     (when (< v 253)
                       (error "non-canonical ReadCompactSize"))
                     v))
                  ((= first-byte 254)
                   (let ((v (read-uint32-le stream)))
                     (when (< v #x10000)
                       (error "non-canonical ReadCompactSize"))
                     v))
                  ((= first-byte 255)
                   (let ((v (read-uint64-le stream)))
                     (when (< v #x100000000)
                       (error "non-canonical ReadCompactSize"))
                     v)))))
    (when (and range-check (> value +max-compact-size+))
      (error "ReadCompactSize: size too large (~D > ~D)"
             value +max-compact-size+))
    value))

(defun read-bounded-count (stream max name)
  "Read a CompactSize count from STREAM and signal an error if it exceeds MAX.
NAME labels the field. Rejecting an over-limit count up front — rather than
looping/allocating for it — is Bitcoin Core's misbehaving-peer posture for
protocol vectors (inv, headers, addr, block txns)."
  (let ((count (read-compact-size stream)))
    (when (> count max)
      (error "~A count ~D exceeds maximum ~D" name count max))
    count))

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

(defun compact-size-length (value)
  "Return the byte length of VALUE encoded as a CompactSize."
  (cond
    ((< value 253) 1)
    ((<= value #xFFFF) 3)
    ((<= value #xFFFFFFFF) 5)
    (t 9)))

;;;; Byte vector operations

(defun read-bytes (stream count)
  "Read COUNT bytes from STREAM, returning a byte vector. Signals an error if
the stream ends first, rather than silently returning a short, zero-padded
vector — truncated peer/disk input must be rejected, not parsed as garbage."
  (let* ((bytes (make-array count :element-type '(unsigned-byte 8)))
         (got (read-sequence bytes stream)))
    (unless (= got count)
      (error "read-bytes: unexpected end of input (wanted ~D bytes, got ~D)"
             count got))
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

;;;; Auto-growing byte buffer
;;;
;;; Drop-in replacement for flexi-streams:with-output-to-sequence in hot
;;; paths. flexi-streams routes every write-byte through Gray-stream CLOS
;;; dispatch, which the May 2 testnet4 profile pinned at ~50% of CPU.
;;; A direct simple-array + index pair with doubling growth gives
;;; ~10-100x speedup on per-byte-heavy workloads (sighash, txid, etc.).

(defstruct (byte-buf (:conc-name bb-))
  (data (make-array 1024 :element-type '(unsigned-byte 8))
        :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum))

(declaim (inline bb-ensure bb-write-u8 bb-write-u16-le bb-write-u32-le
                 bb-write-u64-le bb-write-i32-le bb-write-i64-le
                 bb-write-bytes bb-write-varint bb-finish))

(defun bb-ensure (buf needed-pos)
  "Ensure DATA has room to write up to NEEDED-POS. Doubles on overflow."
  (declare (type byte-buf buf) (type fixnum needed-pos)
           (optimize (speed 3) (safety 1)))
  (let ((cur (length (bb-data buf))))
    (declare (type fixnum cur))
    (when (> needed-pos cur)
      (let ((new-size cur))
        (declare (type fixnum new-size))
        (loop while (< new-size needed-pos)
              do (setf new-size (the fixnum (* new-size 2))))
        (let ((new-data (make-array new-size :element-type '(unsigned-byte 8))))
          (declare (type (simple-array (unsigned-byte 8) (*)) new-data))
          (replace new-data (bb-data buf) :end2 (bb-pos buf))
          (setf (bb-data buf) new-data))))))

(defun bb-write-u8 (buf v)
  (declare (type byte-buf buf) (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 1)))
  (let ((p (bb-pos buf)))
    (declare (type fixnum p))
    (bb-ensure buf (the fixnum (1+ p)))
    (setf (aref (bb-data buf) p) v)
    (setf (bb-pos buf) (the fixnum (1+ p)))))

;; bb-write-u{16,32,64}-le accept any integer and mask with logand —
;; signed-int32 fields like transaction-version are valid input.

(defun bb-write-u16-le (buf v)
  (declare (type byte-buf buf) (type integer v)
           (optimize (speed 3) (safety 1)))
  (let ((p (bb-pos buf))
        (mv (logand v #xffff)))
    (declare (type fixnum p) (type (unsigned-byte 16) mv))
    (bb-ensure buf (the fixnum (+ p 2)))
    (let ((d (bb-data buf)))
      (setf (aref d p) (logand mv #xff))
      (setf (aref d (the fixnum (+ p 1))) (logand (ash mv -8) #xff)))
    (setf (bb-pos buf) (the fixnum (+ p 2)))))

(defun bb-write-u32-le (buf v)
  (declare (type byte-buf buf) (type integer v)
           (optimize (speed 3) (safety 1)))
  (let ((p (bb-pos buf))
        (mv (logand v #xffffffff)))
    (declare (type fixnum p) (type (unsigned-byte 32) mv))
    (bb-ensure buf (the fixnum (+ p 4)))
    (let ((d (bb-data buf)))
      (setf (aref d p)                       (logand mv #xff))
      (setf (aref d (the fixnum (+ p 1)))    (logand (ash mv  -8) #xff))
      (setf (aref d (the fixnum (+ p 2)))    (logand (ash mv -16) #xff))
      (setf (aref d (the fixnum (+ p 3)))    (logand (ash mv -24) #xff)))
    (setf (bb-pos buf) (the fixnum (+ p 4)))))

(defun bb-write-u64-le (buf v)
  (declare (type byte-buf buf) (type integer v)
           (optimize (speed 3) (safety 1)))
  (let ((p (bb-pos buf))
        (mv (logand v #xffffffffffffffff)))
    (declare (type fixnum p) (type (unsigned-byte 64) mv))
    (bb-ensure buf (the fixnum (+ p 8)))
    (let ((d (bb-data buf)))
      (setf (aref d p)                       (logand mv #xff))
      (setf (aref d (the fixnum (+ p 1)))    (logand (ash mv  -8) #xff))
      (setf (aref d (the fixnum (+ p 2)))    (logand (ash mv -16) #xff))
      (setf (aref d (the fixnum (+ p 3)))    (logand (ash mv -24) #xff))
      (setf (aref d (the fixnum (+ p 4)))    (logand (ash mv -32) #xff))
      (setf (aref d (the fixnum (+ p 5)))    (logand (ash mv -40) #xff))
      (setf (aref d (the fixnum (+ p 6)))    (logand (ash mv -48) #xff))
      (setf (aref d (the fixnum (+ p 7)))    (logand (ash mv -56) #xff)))
    (setf (bb-pos buf) (the fixnum (+ p 8)))))

(defun bb-write-i32-le (buf v)
  (bb-write-u32-le buf v))

(defun bb-write-i64-le (buf v)
  (bb-write-u64-le buf v))

(defun bb-write-bytes (buf src)
  (declare (type byte-buf buf) (type vector src)
           (optimize (speed 3) (safety 1)))
  (let ((p (bb-pos buf))
        (n (length src)))
    (declare (type fixnum p n))
    (bb-ensure buf (the fixnum (+ p n)))
    (replace (bb-data buf) src :start1 p)
    (setf (bb-pos buf) (the fixnum (+ p n)))))

(defun bb-write-varint (buf v)
  "CompactSize varint write into BUF."
  (declare (type byte-buf buf) (type (unsigned-byte 64) v)
           (optimize (speed 3) (safety 1)))
  (cond
    ((< v 253)
     (bb-write-u8 buf v))
    ((< v #x10000)
     (bb-write-u8 buf 253)
     (bb-write-u16-le buf v))
    ((< v #x100000000)
     (bb-write-u8 buf 254)
     (bb-write-u32-le buf v))
    (t
     (bb-write-u8 buf 255)
     (bb-write-u64-le buf v))))

(defun bb-finish (buf)
  "Return a fresh simple-array containing exactly the written bytes."
  (declare (type byte-buf buf) (optimize (speed 3) (safety 1)))
  (let* ((n (bb-pos buf))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (declare (type fixnum n))
    (replace out (bb-data buf) :end2 n)
    out))

;;;; Byte-reader (zero-copy index-based input)
;;;
;;; Mirror of byte-buf for the input direction. Wraps a source
;;; (simple-array (unsigned-byte 8) (*)) plus an index counter. Each
;;; reader bumps the index and reads via aref directly, avoiding
;;; flexi-streams:with-input-from-sequence + Gray-stream read-byte
;;; dispatch on every byte.

(defstruct (byte-reader (:conc-name br-))
  (data #() :type (simple-array (unsigned-byte 8) (*)))
  (pos 0 :type fixnum))

(declaim (inline make-byte-reader-from
                 br-read-u8 br-read-u16-le br-read-u32-le
                 br-read-u64-le br-read-i32-le br-read-i64-le
                 br-read-bytes br-read-compact-size br-read-var-bytes
                 br-eof-p))

(defun make-byte-reader-from (bytes)
  "Wrap a byte-vector in a fresh byte-reader at position 0."
  (declare (type vector bytes))
  (make-byte-reader
   :data (if (typep bytes '(simple-array (unsigned-byte 8) (*)))
             bytes
             (coerce bytes '(simple-array (unsigned-byte 8) (*))))))

(defun br-eof-p (br)
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (>= (br-pos br) (length (br-data br))))

(defun br-read-u8 (br)
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (let ((p (br-pos br)))
    (declare (type fixnum p))
    (prog1 (aref (br-data br) p)
      (setf (br-pos br) (the fixnum (1+ p))))))

(defun br-read-u16-le (br)
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (let ((p (br-pos br))
        (d (br-data br)))
    (declare (type fixnum p))
    (prog1 (logior (aref d p)
                   (ash (aref d (the fixnum (+ p 1))) 8))
      (setf (br-pos br) (the fixnum (+ p 2))))))

(defun br-read-u32-le (br)
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (let ((p (br-pos br))
        (d (br-data br)))
    (declare (type fixnum p))
    (prog1 (logior (aref d p)
                   (ash (aref d (the fixnum (+ p 1)))  8)
                   (ash (aref d (the fixnum (+ p 2))) 16)
                   (ash (aref d (the fixnum (+ p 3))) 24))
      (setf (br-pos br) (the fixnum (+ p 4))))))

(defun br-read-u64-le (br)
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (let ((p (br-pos br))
        (d (br-data br)))
    (declare (type fixnum p))
    (prog1 (logior (aref d p)
                   (ash (aref d (the fixnum (+ p 1)))  8)
                   (ash (aref d (the fixnum (+ p 2))) 16)
                   (ash (aref d (the fixnum (+ p 3))) 24)
                   (ash (aref d (the fixnum (+ p 4))) 32)
                   (ash (aref d (the fixnum (+ p 5))) 40)
                   (ash (aref d (the fixnum (+ p 6))) 48)
                   (ash (aref d (the fixnum (+ p 7))) 56))
      (setf (br-pos br) (the fixnum (+ p 8))))))

(defun br-read-i32-le (br)
  "Read a 32-bit signed little-endian integer."
  (let ((u (br-read-u32-le br)))
    (declare (type (unsigned-byte 32) u))
    (if (>= u #x80000000) (- u #x100000000) u)))

(defun br-read-i64-le (br)
  "Read a 64-bit signed little-endian integer."
  (let ((u (br-read-u64-le br)))
    (declare (type (unsigned-byte 64) u))
    (if (>= u #x8000000000000000) (- u #x10000000000000000) u)))

(defun br-read-bytes (br n)
  "Read N bytes, returning a fresh simple-array (unsigned-byte 8). Bounds-checks
BEFORE allocating, so a malicious length field can't force a large allocation
ahead of an overrun error."
  (declare (type byte-reader br) (type fixnum n)
           (optimize (speed 3) (safety 1)))
  (let ((p (br-pos br)))
    (declare (type fixnum p))
    (when (> (+ p n) (length (br-data br)))
      (error "br-read-bytes: read past end of buffer (pos ~D + ~D > ~D)"
             p n (length (br-data br))))
    (let ((out (make-array n :element-type '(unsigned-byte 8))))
      (declare (type (simple-array (unsigned-byte 8) (*)) out))
      (replace out (br-data br) :start2 p :end2 (the fixnum (+ p n)))
      (setf (br-pos br) (the fixnum (+ p n)))
      out)))

(defun br-read-compact-size (br)
  "Read a CompactSize. Mirrors read-compact-size — non-canonical
encodings rejected and value capped at +max-compact-size+."
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (let* ((first (br-read-u8 br))
         (value
           (cond
             ((< first 253) first)
             ((= first 253)
              (let ((v (br-read-u16-le br)))
                (when (< v 253)
                  (error "non-canonical ReadCompactSize"))
                v))
             ((= first 254)
              (let ((v (br-read-u32-le br)))
                (when (< v #x10000)
                  (error "non-canonical ReadCompactSize"))
                v))
             (t
              (let ((v (br-read-u64-le br)))
                (when (< v #x100000000)
                  (error "non-canonical ReadCompactSize"))
                v)))))
    (when (> value +max-compact-size+)
      (error "ReadCompactSize: size too large (~D > ~D)"
             value +max-compact-size+))
    value))

(defun br-read-var-bytes (br)
  "Read a length-prefixed byte vector."
  (let ((len (br-read-compact-size br)))
    (br-read-bytes br len)))
