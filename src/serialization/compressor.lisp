(in-package #:bitcoin-lisp.serialization)

;;; TxOutCompression — Bitcoin Core's compact UTXO encoding.
;;;
;;; Byte-exact port of refs/bitcoin/src/compressor.{h,cpp}: the
;;; compressed-amount codec, the compressed-script codec (6 special
;;; forms + raw fallback), the compressed TxOut record
;;; (compressor.h:112-116 TxOutCompression), and the per-output Coin
;;; record VARINT(2*height + coinbase) + compressed TxOut
;;; (coins.h:63-79). Consumers: assumeutxo snapshot files
;;; (node/utxo_snapshot.h) and Core's undo/rev + chainstate value
;;; encodings.
;;;
;;; Also home to Bitcoin Core's VARINT (serialize.h:363-384) — the MSB
;;; base-128 encoding with a +1 offset on all non-final bytes. This is
;;; NOT CompactSize (bb-write-varint); the two must never be mixed.

;;;; Core VARINT (serialize.h:363-384)
;;;;
;;;; Bytes are an MSB base-128 encoding of the number. The high bit in
;;;; each byte signifies whether another digit follows. To make the
;;;; encoding one-to-one, one is subtracted from all but the last digit:
;;;;   0:    [0x00]   128:   [0x80 0x00]   16511:      [0xFF 0x7F]
;;;;   1:    [0x01]   255:   [0x80 0x7F]   65535: [0x82 0xFE 0x7F]
;;;;   127:  [0x7F]   16384: [0xFF 0x00]   2^32: [0x8E 0xFE 0xFE 0xFF 0x00]

(defun bb-write-core-varint (buf n)
  "Write N as a Bitcoin Core VARINT into BUF (serialize.h:424-440
WriteVarInt): emit base-128 digits MSB-first, subtracting one from every
non-final digit and setting its high bit."
  (declare (type byte-buf buf) (type (unsigned-byte 64) n))
  (let ((tmp (make-array 10 :element-type '(unsigned-byte 8)))
        (len 0))
    (declare (type fixnum len)
             (dynamic-extent tmp))
    (loop
      (setf (aref tmp len) (logior (logand n #x7F) (if (plusp len) #x80 #x00)))
      (when (<= n #x7F) (return))
      (setf n (1- (ash n -7)))
      (incf len))
    (loop for i from len downto 0
          do (bb-write-u8 buf (aref tmp i)))))

(defun br-read-core-varint (br)
  "Read a Bitcoin Core VARINT from BR (serialize.h:442-462 ReadVarInt).
Errors if the value would exceed 64 bits, mirroring Core's
\"ReadVarInt(): size too large\" overflow checks."
  (declare (type byte-reader br))
  (let ((n 0))
    (loop
      (let ((b (br-read-u8 br)))
        (when (> n (ash #xFFFFFFFFFFFFFFFF -7))
          (serialization-error "ReadVarInt(): size too large"))
        (setf n (logior (ash n 7) (logand b #x7F)))
        (if (logtest b #x80)
            (progn
              (when (= n #xFFFFFFFFFFFFFFFF)
                (serialization-error "ReadVarInt(): size too large"))
              (incf n))
            (return n))))))

;;;; Amount compression (compressor.cpp:140-192)
;;;;
;;;; * If the amount is 0, output 0
;;;; * first, divide the amount (in base units) by the largest power of
;;;;   10 possible; call the exponent e (e is max 9)
;;;; * if e<9, the last digit of the resulting number cannot be 0; store
;;;;   it as d, and drop it (divide by 10); call the result n
;;;;   * output 1 + 10*(9*n + d - 1) + e
;;;; * if e==9, we only know the resulting number is not zero, so output
;;;;   1 + 10*(n - 1) + 9
;;;; (this is decodable, as d is in [1-9] and e is in [0-9])

(defun compress-amount (n)
  "Compress the satoshi amount N (compressor.cpp:149-166 CompressAmount).
Defined for 0 <= N <= MAX_MONEY."
  (declare (type (unsigned-byte 64) n))
  (when (zerop n)
    (return-from compress-amount 0))
  (let ((e 0))
    (loop while (and (zerop (mod n 10)) (< e 9))
          do (setf n (floor n 10))
             (incf e))
    (if (< e 9)
        (let ((d (mod n 10)))
          (assert (<= 1 d 9))
          (setf n (floor n 10))
          (+ 1 (* (+ (* n 9) d -1) 10) e))
        (+ 1 (* (- n 1) 10) 9))))

(defun decompress-amount (x)
  "Inverse of compress-amount (compressor.cpp:168-192 DecompressAmount)."
  (declare (type (unsigned-byte 64) x))
  ;; x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
  (when (zerop x)
    (return-from decompress-amount 0))
  (decf x)
  ;; x = 10*(9*n + d - 1) + e
  (let ((e (mod x 10))
        (n 0))
    (setf x (floor x 10))
    (if (< e 9)
        ;; x = 9*n + d - 1
        (let ((d (+ (mod x 9) 1)))
          (setf x (floor x 9))
          ;; x = n
          (setf n (+ (* x 10) d)))
        (setf n (+ x 1)))
    (loop while (plusp e)
          do (setf n (* n 10))
             (decf e))
    n))

;;;; Script compression (compressor.cpp:11-138)
;;;;
;;;; 6 special forms, identified by the first compressed byte:
;;;;   0x00: P2PKH             -> 20-byte key hash
;;;;   0x01: P2SH              -> 20-byte script hash
;;;;   0x02, 0x03: P2PK        -> 32-byte x (id = compressed key prefix)
;;;;   0x04, 0x05: P2PK uncomp -> 32-byte x (id = 0x04 | y-parity)
;;;; Everything else serializes raw as VARINT(size + 6) + script bytes.

(defconstant +special-scripts+ 6
  "Number of special script forms (compressor.h:62 nSpecialScripts).")

(defconstant +compress-max-script-size+ 10000
  "MAX_SCRIPT_SIZE (script/script.h:40). A decompressed raw script above
this is replaced by a one-byte OP_RETURN (compressor.h:87-90).")

;; Script opcode bytes are kept as bare literals to mirror the exact
;; byte-sequence tests of IsToKeyID/IsToScriptID/IsToPubKey
;; (compressor.cpp:19-53) — they check bytes, not script templates.

(defun compress-script (script)
  "Compress SCRIPT into one of the 6 special forms (compressor.cpp:55-84
CompressScript). Returns the 21- or 33-byte compressed form, or NIL when
no special form applies (caller falls back to raw encoding)."
  (let ((len (length script)))
    (cond
      ;; P2PKH -> 0x00 + key hash (IsToKeyID, compressor.cpp:19-28)
      ((and (= len 25)
            (= (aref script 0) #x76)   ; OP_DUP
            (= (aref script 1) #xa9)   ; OP_HASH160
            (= (aref script 2) 20)
            (= (aref script 23) #x88)  ; OP_EQUALVERIFY
            (= (aref script 24) #xac)) ; OP_CHECKSIG
       (let ((out (make-array 21 :element-type '(unsigned-byte 8))))
         (setf (aref out 0) #x00)
         (replace out script :start1 1 :start2 3 :end2 23)
         out))
      ;; P2SH -> 0x01 + script hash (IsToScriptID, compressor.cpp:30-38)
      ((and (= len 23)
            (= (aref script 0) #xa9)   ; OP_HASH160
            (= (aref script 1) 20)
            (= (aref script 22) #x87)) ; OP_EQUAL
       (let ((out (make-array 21 :element-type '(unsigned-byte 8))))
         (setf (aref out 0) #x01)
         (replace out script :start1 1 :start2 2 :end2 22)
         out))
      ;; P2PK, compressed key -> id = the key's own 0x02/0x03 prefix + x.
      ;; Compressed-prefix keys are NOT validated here, matching Core
      ;; (IsToPubKey, compressor.cpp:42-46).
      ((and (= len 35)
            (= (aref script 0) 33)
            (= (aref script 34) #xac)  ; OP_CHECKSIG
            (or (= (aref script 1) #x02)
                (= (aref script 1) #x03)))
       (let ((out (make-array 33 :element-type '(unsigned-byte 8))))
         (setf (aref out 0) (aref script 1))
         (replace out script :start1 1 :start2 2 :end2 34)
         out))
      ;; P2PK, uncompressed key -> id = 0x04 | y-parity + x. The point
      ;; must be fully valid (on the curve) — invalid ones cannot be
      ;; represented in compressed form (IsToPubKey, compressor.cpp:47-53).
      ((and (= len 67)
            (= (aref script 0) 65)
            (= (aref script 66) #xac)  ; OP_CHECKSIG
            (= (aref script 1) #x04)
            (bl.crypto:public-key-valid-p (subseq script 1 66)))
       (let ((out (make-array 33 :element-type '(unsigned-byte 8))))
         (setf (aref out 0) (logior #x04 (logand (aref script 65) #x01)))
         (replace out script :start1 1 :start2 2 :end2 34)
         out)))))

(defun special-script-size (size-id)
  "Payload size of special script form SIZE-ID (compressor.cpp:86-93
GetSpecialScriptSize)."
  (case size-id
    ((0 1) 20)
    ((2 3 4 5) 32)
    (t 0)))

(defun decompress-script (size-id payload)
  "Decompress special form SIZE-ID with PAYLOAD bytes back into a full
scriptPubKey (compressor.cpp:95-138 DecompressScript). Returns NIL when
SIZE-ID is not special or a 0x04/0x05 x-coordinate is not on the curve."
  (case size-id
    (#x00
     (let ((script (make-array 25 :element-type '(unsigned-byte 8))))
       (setf (aref script 0) #x76      ; OP_DUP
             (aref script 1) #xa9      ; OP_HASH160
             (aref script 2) 20)
       (replace script payload :start1 3 :end2 20)
       (setf (aref script 23) #x88     ; OP_EQUALVERIFY
             (aref script 24) #xac)    ; OP_CHECKSIG
       script))
    (#x01
     (let ((script (make-array 23 :element-type '(unsigned-byte 8))))
       (setf (aref script 0) #xa9      ; OP_HASH160
             (aref script 1) 20)
       (replace script payload :start1 2 :end2 20)
       (setf (aref script 22) #x87)    ; OP_EQUAL
       script))
    ((#x02 #x03)
     (let ((script (make-array 35 :element-type '(unsigned-byte 8))))
       (setf (aref script 0) 33
             (aref script 1) size-id)
       (replace script payload :start1 2 :end2 32)
       (setf (aref script 34) #xac)    ; OP_CHECKSIG
       script))
    ((#x04 #x05)
     ;; Rebuild the compressed key (prefix = id - 2 = 0x02/0x03), then
     ;; recover the full uncompressed point via secp256k1
     ;; (compressor.cpp:122-135; CPubKey::Decompress).
     (let ((compressed (make-array 33 :element-type '(unsigned-byte 8))))
       (setf (aref compressed 0) (- size-id 2))
       (replace compressed payload :start1 1 :end2 32)
       (let ((full (bl.crypto:decompress-public-key compressed)))
         (when full
           (let ((script (make-array 67 :element-type '(unsigned-byte 8))))
             (setf (aref script 0) 65)
             (replace script full :start1 1)
             (setf (aref script 66) #xac) ; OP_CHECKSIG
             script)))))))

(defun bb-write-compressed-script (buf script)
  "Serialize SCRIPT in compressed form into BUF (compressor.h:64-74
ScriptCompression::Ser): a special form's bytes verbatim, or
VARINT(size + 6) + raw script bytes."
  (declare (type byte-buf buf))
  (let ((compressed (compress-script script)))
    (if compressed
        (bb-write-bytes buf compressed)
        (progn
          (bb-write-core-varint buf (+ (length script) +special-scripts+))
          (bb-write-bytes buf script)))))

(defun br-read-compressed-script (br)
  "Read a compressed script from BR (compressor.h:76-95
ScriptCompression::Unser). An invalid special form (0x04/0x05 point not
on curve) signals an error; a raw script longer than MAX_SCRIPT_SIZE is
skipped and replaced with a one-byte OP_RETURN, matching Core."
  (declare (type byte-reader br))
  (let ((n (br-read-core-varint br)))
    (if (< n +special-scripts+)
        (let* ((payload (br-read-bytes br (special-script-size n)))
               (script (decompress-script n payload)))
          (or script
              (serialization-error "br-read-compressed-script: invalid special script (id ~D)" n)))
        (let ((size (- n +special-scripts+)))
          (if (> size +compress-max-script-size+)
              ;; Overly long script, replace with a short invalid one
              ;; (compressor.h:87-90).
              (let ((p (br-pos br)))
                (when (> (+ p size) (length (br-data br)))
                  (serialization-error "br-read-compressed-script: script overruns buffer (~D bytes)" size))
                (setf (br-pos br) (+ p size))
                (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element #x6a)) ; OP_RETURN
              (br-read-bytes br size))))))

;;;; Compressed TxOut record (compressor.h:98-116)

(defun bb-write-compressed-tx-out (buf value script)
  "Serialize a TxOut in compressed form into BUF (compressor.h:112-116
TxOutCompression): VARINT(compressed amount) + compressed script."
  (bb-write-core-varint buf (compress-amount value))
  (bb-write-compressed-script buf script))

(defun br-read-compressed-tx-out (br)
  "Read a compressed TxOut from BR. Returns (values value script)."
  (let ((value (decompress-amount (br-read-core-varint br))))
    (values value (br-read-compressed-script br))))

;;;; Stream read variants
;;;;
;;;; Assumeutxo snapshot files are multi-GB and streamed from disk, so
;;;; the readers below consume CL binary streams directly instead of a
;;;; fully materialized byte-reader. Byte-exact mirrors of the br-
;;;; functions above.

(defun read-core-varint (stream)
  "Stream variant of br-read-core-varint (serialize.h:442-462 ReadVarInt)."
  (let ((n 0))
    (loop
      (let ((b (read-byte stream)))
        (when (> n (ash #xFFFFFFFFFFFFFFFF -7))
          (serialization-error "ReadVarInt(): size too large"))
        (setf n (logior (ash n 7) (logand b #x7F)))
        (if (logtest b #x80)
            (progn
              (when (= n #xFFFFFFFFFFFFFFFF)
                (serialization-error "ReadVarInt(): size too large"))
              (incf n))
            (return n))))))

(defun read-compressed-script (stream)
  "Stream variant of br-read-compressed-script (compressor.h:76-95
ScriptCompression::Unser)."
  (let ((n (read-core-varint stream)))
    (if (< n +special-scripts+)
        (let* ((payload (read-bytes stream (special-script-size n)))
               (script (decompress-script n payload)))
          (or script
              (serialization-error "read-compressed-script: invalid special script (id ~D)" n)))
        (let ((size (- n +special-scripts+)))
          (if (> size +compress-max-script-size+)
              ;; Overly long script: skip its bytes and replace with a
              ;; short invalid one (compressor.h:87-90).
              (let ((chunk (make-array (min size 65536)
                                       :element-type '(unsigned-byte 8))))
                (loop with remaining = size
                      while (plusp remaining)
                      do (let ((got (read-sequence chunk stream
                                                   :end (min remaining (length chunk)))))
                           (when (zerop got)
                             (serialization-error "read-compressed-script: unexpected end of input"))
                           (decf remaining got)))
                (make-array 1 :element-type '(unsigned-byte 8)
                              :initial-element #x6a)) ; OP_RETURN
              (read-bytes stream size))))))

(defun read-compressed-tx-out (stream)
  "Stream variant of br-read-compressed-tx-out. Returns (values value script)."
  (let ((value (decompress-amount (read-core-varint stream))))
    (values value (read-compressed-script stream))))

;;;; Per-output Coin record (coins.h:63-79)
;;;;
;;;; The chainstate/undo/snapshot per-output serialization:
;;;;   VARINT((coinbase ? 1 : 0) | (height << 1)) + compressed TxOut.
;;;; Consumed by the assumeutxo snapshot format (node/utxo_snapshot.h)
;;;; and Core's rev-file undo records.

(defun bb-write-compressed-coin (buf height coinbase value script)
  "Serialize one unspent output into BUF (coins.h:63-69 Coin::Serialize):
VARINT(height*2 + coinbase) then the compressed TxOut."
  (bb-write-core-varint buf (+ (* height 2) (if coinbase 1 0)))
  (bb-write-compressed-tx-out buf value script))

(defun br-read-compressed-coin (br)
  "Read one unspent output from BR (coins.h:71-79 Coin::Unserialize).
Returns (values height coinbase-p value script)."
  (let ((code (br-read-core-varint br)))
    (multiple-value-bind (value script) (br-read-compressed-tx-out br)
      (values (ash code -1) (logtest code 1) value script))))

(defun read-compressed-coin (stream)
  "Stream variant of br-read-compressed-coin.
Returns (values height coinbase-p value script)."
  (let ((code (read-core-varint stream)))
    (multiple-value-bind (value script) (read-compressed-tx-out stream)
      (values (ash code -1) (logtest code 1) value script))))
