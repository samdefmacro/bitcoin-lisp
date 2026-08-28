(in-package #:bitcoin-lisp.bytes)

;;;; Byte buffers and readers
;;;
;;; The one implementation of index-based byte I/O in the tree. Every
;;; serializer that matters for throughput writes through a BYTE-BUF and
;;; every deserializer reads through a BYTE-READER: a simple-array plus an
;;; index, one AREF per byte, everything inlined. flexi-streams routes each
;;; byte through Gray-stream CLOS dispatch, which the May 2 testnet4 profile
;;; pinned at ~50% of CPU during validation and which the 2026-08-22 profile
;;; found to be the block-deserialization bottleneck; the stream codecs in
;;; serialization/binary.lisp remain only for callers not yet moved.
;;;
;;; This file loads before everything else that does I/O (see
;;; bitcoin-lisp.asd) so that the script interpreter's sighash code -- the
;;; hottest writer -- compiles against these definitions and gets them
;;; inlined. It used to carry a second, identical copy for that reason.

(defconstant +max-compact-size+ #x02000000
  "Bitcoin Core MAX_SIZE (serialize.h:32): 32 MiB upper bound on any
   ReadCompactSize. Caps allocations driven by attacker-controlled length
   prefixes during transaction/block deserialization.")

;;;; Positional writers into a pre-sized array
;;;
;;; For writers that know their upper bound (BIP 143's fixed-layout sighash
;;; preimage): write at POS and return the new position, no bounds check
;;; beyond the array's own.

(declaim (inline buf-set-u8 buf-set-u16-le buf-set-u32-le buf-set-u64-le
                 buf-set-bytes buf-set-varint))

(defun buf-set-u8 (buf pos v)
  (declare (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum pos)
           (type (unsigned-byte 8) v)
           (optimize (speed 3) (safety 1)))
  (setf (aref buf pos) v)
  (the fixnum (1+ pos)))

(defmacro define-buf-set-le (name nbytes)
  "Define NAME (buf pos v): write V as NBYTES little-endian bytes at POS and
return the position after them. Expands to the hand-unrolled AREFs."
  `(defun ,name (buf pos v)
     (declare (type (simple-array (unsigned-byte 8) (*)) buf)
              (type fixnum pos)
              (type (unsigned-byte ,(* 8 nbytes)) v)
              (optimize (speed 3) (safety 1)))
     ,@(loop for i below nbytes
             collect `(setf (aref buf (+ pos ,i)) (logand (ash v ,(* -8 i)) #xff)))
     (the fixnum (+ pos ,nbytes))))

(define-buf-set-le buf-set-u16-le 2)
(define-buf-set-le buf-set-u32-le 4)
(define-buf-set-le buf-set-u64-le 8)

(defun buf-set-bytes (buf pos src)
  "Copy SRC bytes into BUF at POS using REPLACE (single ub8-bash-copy)."
  (declare (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum pos)
           (type vector src)
           (optimize (speed 3) (safety 1)))
  (let ((n (length src)))
    (declare (type fixnum n))
    (replace buf src :start1 pos)
    (the fixnum (+ pos n))))

(defun buf-set-varint (buf pos v)
  "CompactSize write at POS."
  (declare (type (simple-array (unsigned-byte 8) (*)) buf)
           (type fixnum pos)
           (type (unsigned-byte 64) v)
           (optimize (speed 3) (safety 1)))
  (cond
    ((< v #xfd)
     (buf-set-u8 buf pos v))
    ((< v #x10000)
     (setf (aref buf pos) #xfd)
     (buf-set-u16-le buf (1+ pos) v))
    ((< v #x100000000)
     (setf (aref buf pos) #xfe)
     (buf-set-u32-le buf (1+ pos) v))
    (t
     (setf (aref buf pos) #xff)
     (buf-set-u64-le buf (1+ pos) v))))

;;;; Auto-growing byte buffer
;;;
;;; For writers whose upper bound is awkward to compute (legacy sighash,
;;; whole transactions): the same one-AREF-per-byte cost as the positional
;;; writers above, plus a check-and-double on the slow path.

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
    (setf (bb-pos buf) (buf-set-u8 (bb-data buf) p v))))

(defmacro define-bb-write-le (name setter nbytes)
  "Define NAME (buf v): grow BUF if needed and append V as NBYTES little-endian
bytes through SETTER. V may be any integer -- it is masked to NBYTES, so a
signed-int32 field like transaction-version is valid input; a strict
(unsigned-byte 32) declaration would break sighash on any tx with a negative
version."
  `(defun ,name (buf v)
     (declare (type byte-buf buf) (type integer v)
              (optimize (speed 3) (safety 1)))
     (let ((p (bb-pos buf))
           (mv (logand v ,(1- (ash 1 (* 8 nbytes))))))
       (declare (type fixnum p) (type (unsigned-byte ,(* 8 nbytes)) mv))
       (bb-ensure buf (the fixnum (+ p ,nbytes)))
       (setf (bb-pos buf) (,setter (bb-data buf) p mv)))))

(define-bb-write-le bb-write-u16-le buf-set-u16-le 2)
(define-bb-write-le bb-write-u32-le buf-set-u32-le 4)
(define-bb-write-le bb-write-u64-le buf-set-u64-le 8)

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
    (setf (bb-pos buf) (buf-set-bytes (bb-data buf) p src))))

(defun bb-write-varint (buf v)
  "CompactSize varint write into BUF."
  (declare (type byte-buf buf) (type (unsigned-byte 64) v)
           (optimize (speed 3) (safety 1)))
  (let ((p (bb-pos buf)))
    (declare (type fixnum p))
    (bb-ensure buf (the fixnum (+ p 9)))
    (setf (bb-pos buf) (buf-set-varint (bb-data buf) p v))))

(defun bb-write-var-bytes (buf bytes)
  "CompactSize length prefix, then BYTES."
  (bb-write-varint buf (length bytes))
  (bb-write-bytes buf bytes))

(defun bb-write-hash256 (buf hash)
  "Write a 32-byte hash, refusing any other length: a hash of the wrong size
would otherwise silently become a malformed message."
  (assert (= (length hash) 32) (hash) "bb-write-hash256: ~D bytes, not 32" (length hash))
  (bb-write-bytes buf hash))

(defun bb-finish (buf)
  "Return a fresh simple-array containing exactly the written bytes."
  (declare (type byte-buf buf) (optimize (speed 3) (safety 1)))
  (let* ((n (bb-pos buf))
         (out (make-array n :element-type '(unsigned-byte 8))))
    (declare (type fixnum n))
    (replace out (bb-data buf) :end2 n)
    out))

(defmacro with-byte-buf ((var) &body body)
  "Bind VAR to a fresh byte-buf around BODY and return the written bytes.
The byte-buf counterpart of flexi-streams:with-output-to-sequence."
  `(let ((,var (make-byte-buf)))
     ,@body
     (bb-finish ,var)))

;;;; Byte-reader (zero-copy index-based input)
;;;
;;; Mirror of byte-buf for the input direction: a source simple-array plus an
;;; index; each reader bumps the index and reads via AREF directly.

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

(defmacro with-byte-reader ((var bytes) &body body)
  "Bind VAR to a byte-reader over BYTES around BODY. The byte-reader
counterpart of flexi-streams:with-input-from-sequence."
  `(let ((,var (make-byte-reader-from ,bytes)))
     ,@body))

(defun br-eof-p (br)
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (>= (br-pos br) (length (br-data br))))

(defun br-read-u8 (br)
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (let ((p (br-pos br)))
    (declare (type fixnum p))
    (prog1 (aref (br-data br) p)
      (setf (br-pos br) (the fixnum (1+ p))))))

(defmacro define-br-read-le (name nbytes)
  "Define NAME (br): read NBYTES little-endian bytes as an unsigned integer
and advance. Expands to the hand-unrolled AREFs."
  `(defun ,name (br)
     (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
     (let ((p (br-pos br))
           (d (br-data br)))
       (declare (type fixnum p))
       (prog1 (logior ,@(loop for i below nbytes
                              collect `(ash (aref d (the fixnum (+ p ,i))) ,(* 8 i))))
         (setf (br-pos br) (the fixnum (+ p ,nbytes)))))))

(define-br-read-le br-read-u16-le 2)
(define-br-read-le br-read-u32-le 4)
(define-br-read-le br-read-u64-le 8)

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
      (serialization-error "br-read-bytes: read past end of buffer (pos ~D + ~D > ~D)"
             p n (length (br-data br))))
    (let ((out (make-array n :element-type '(unsigned-byte 8))))
      (declare (type (simple-array (unsigned-byte 8) (*)) out))
      (replace out (br-data br) :start2 p :end2 (the fixnum (+ p n)))
      (setf (br-pos br) (the fixnum (+ p n)))
      out)))

(defun br-read-compact-size (br &key (range-check t))
  "Read a CompactSize. Mirrors Bitcoin Core's ReadCompactSize
(serialize.h:330-360): non-canonical encodings rejected and, when RANGE-CHECK
(the default), the value capped at +max-compact-size+. RANGE-CHECK NIL is for
the few fields Core reads with range_check=false, such as addrv2 service
bits."
  (declare (type byte-reader br) (optimize (speed 3) (safety 1)))
  (let* ((first (br-read-u8 br))
         (value
           (cond
             ((< first 253) first)
             ((= first 253)
              (let ((v (br-read-u16-le br)))
                (when (< v 253)
                  (serialization-error "non-canonical ReadCompactSize"))
                v))
             ((= first 254)
              (let ((v (br-read-u32-le br)))
                (when (< v #x10000)
                  (serialization-error "non-canonical ReadCompactSize"))
                v))
             (t
              (let ((v (br-read-u64-le br)))
                (when (< v #x100000000)
                  (serialization-error "non-canonical ReadCompactSize"))
                v)))))
    (when (and range-check (> value +max-compact-size+))
      (serialization-error "ReadCompactSize: size too large (~D > ~D)"
             value +max-compact-size+))
    value))

(defun br-read-var-bytes (br)
  "Read a length-prefixed byte vector."
  (let ((len (br-read-compact-size br)))
    (br-read-bytes br len)))
