(in-package #:bitcoin-lisp.storage)

;;; UTXO Set Management
;;;
;;; The UTXO (Unspent Transaction Output) set tracks all outputs
;;; that have not yet been spent. This is essential for validating
;;; new transactions.

(defstruct utxo-entry
  "An entry in the UTXO set."
  (value 0 :type (signed-byte 64))
  (script-pubkey #() :type (simple-array (unsigned-byte 8) (*)))
  (height 0 :type (unsigned-byte 32))
  (coinbase nil :type boolean))

;;; UTXO-KEY — the per-output identity used as the hash-table key.
;;;
;;; Pack the 32-byte txid as four (unsigned-byte 64) words (LE-interpreted)
;;; plus the (unsigned-byte 32) vout. SBCL inlines = on fixnums to a
;;; single CMP, so utxo-key= is ~5 instructions; the previous
;;; byte-vector-with-equalp key dispatched to SB-IMPL::ARRAY-EQUALP and
;;; looped through 36 bytes via DATA-VECTOR-REF — ~72% of stress-region
;;; CPU per the May 2026 profile, mirroring Core's COutPoint operator==
;;; which compiles to an inlined memcmp(32) + uint32 compare
;;; (primitives/transaction.h:49).

(defstruct (utxo-key (:conc-name uk-)
                     (:constructor %make-utxo-key (a b c d vout))
                     (:copier nil)
                     (:predicate nil))
  (a 0 :type (unsigned-byte 64) :read-only t)
  (b 0 :type (unsigned-byte 64) :read-only t)
  (c 0 :type (unsigned-byte 64) :read-only t)
  (d 0 :type (unsigned-byte 64) :read-only t)
  (vout 0 :type (unsigned-byte 32) :read-only t))

(declaim (inline txid-bytes->u64-le))
(defun txid-bytes->u64-le (bytes offset)
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type (unsigned-byte 32) offset)
           (optimize (speed 3) (safety 0)))
  (logior (aref bytes offset)
          (ash (aref bytes (+ offset 1)) 8)
          (ash (aref bytes (+ offset 2)) 16)
          (ash (aref bytes (+ offset 3)) 24)
          (ash (aref bytes (+ offset 4)) 32)
          (ash (aref bytes (+ offset 5)) 40)
          (ash (aref bytes (+ offset 6)) 48)
          (ash (aref bytes (+ offset 7)) 56)))

(declaim (inline make-utxo-key))
(defun make-utxo-key (txid output-index)
  "Pack TXID (32 bytes, treated as four LE uint64 words) and OUTPUT-INDEX
into a utxo-key struct."
  (declare (type (simple-array (unsigned-byte 8) (*)) txid)
           (type (unsigned-byte 32) output-index)
           (optimize (speed 3) (safety 0)))
  (%make-utxo-key (txid-bytes->u64-le txid 0)
                  (txid-bytes->u64-le txid 8)
                  (txid-bytes->u64-le txid 16)
                  (txid-bytes->u64-le txid 24)
                  output-index))

(declaim (inline utxo-key=))
(defun utxo-key= (x y)
  (declare (type utxo-key x y) (optimize (speed 3) (safety 0)))
  (and (= (uk-vout x) (uk-vout y))
       (= (uk-a x) (uk-a y))
       (= (uk-b x) (uk-b y))
       (= (uk-c x) (uk-c y))
       (= (uk-d x) (uk-d y))))

(declaim (inline utxo-key-hash))
(defun utxo-key-hash (k)
  "Custom :hash-function. The first 8 bytes of the txid are SHA256 output
and already uniformly random — return them as a fixnum-masked uint64.
Same pattern as the previous byte-vector-keyed table; this just reads
the pre-extracted slot."
  (declare (type utxo-key k) (optimize (speed 3) (safety 0)))
  (logand (uk-a k) most-positive-fixnum))

#+sbcl (sb-ext:define-hash-table-test utxo-key= utxo-key-hash)

(declaim (inline make-utxo-key-hash-table))
(defun make-utxo-key-hash-table (&optional (size 16))
  "Allocate a hash-table keyed by utxo-key. Under SBCL this uses the
custom utxo-key= test (inlined fixnum compares); falls back to equalp
on other implementations. Shared by utxo-set and coins-view-cache."
  (make-hash-table #+sbcl :test #+sbcl 'utxo-key=
                   #-sbcl :test #-sbcl 'equalp
                   :size size))

(defstruct utxo-set
  "In-memory UTXO set.
The set maps (txid, output-index) -> utxo-entry."
  (entries (make-utxo-key-hash-table) :type hash-table)
  (dirty nil :type boolean))

(declaim (inline write-u64-le-into write-u32-le-into))
(defun write-u64-le-into (bytes offset v)
  "Write 64-bit V into BYTES at OFFSET as 8 LE bytes. Inverse of
txid-bytes->u64-le."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type (unsigned-byte 32) offset)
           (type (unsigned-byte 64) v)
           (optimize (speed 3) (safety 0)))
  (setf (aref bytes offset)        (logand v #xFF)
        (aref bytes (+ offset 1))  (logand (ash v -8) #xFF)
        (aref bytes (+ offset 2))  (logand (ash v -16) #xFF)
        (aref bytes (+ offset 3))  (logand (ash v -24) #xFF)
        (aref bytes (+ offset 4))  (logand (ash v -32) #xFF)
        (aref bytes (+ offset 5))  (logand (ash v -40) #xFF)
        (aref bytes (+ offset 6))  (logand (ash v -48) #xFF)
        (aref bytes (+ offset 7))  (logand (ash v -56) #xFF)))

(defun write-u32-le-into (bytes offset v)
  "Write 32-bit V into BYTES at OFFSET as 4 LE bytes."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (type (unsigned-byte 32) offset)
           (type (unsigned-byte 32) v)
           (optimize (speed 3) (safety 0)))
  (setf (aref bytes offset)        (logand v #xFF)
        (aref bytes (+ offset 1))  (logand (ash v -8) #xFF)
        (aref bytes (+ offset 2))  (logand (ash v -16) #xFF)
        (aref bytes (+ offset 3))  (logand (ash v -24) #xFF)))

(defun utxo-key-bytes (k)
  "Reconstruct the 36-byte on-disk form (32-byte txid || 4-byte LE vout)
from a utxo-key. Used by save-utxo-set, utxo-set-iterate, and
hash_serialized_3 — never on the inv/validate hot path."
  (declare (type utxo-key k))
  (let ((bytes (make-array 36 :element-type '(unsigned-byte 8))))
    (write-u64-le-into bytes 0 (uk-a k))
    (write-u64-le-into bytes 8 (uk-b k))
    (write-u64-le-into bytes 16 (uk-c k))
    (write-u64-le-into bytes 24 (uk-d k))
    (write-u32-le-into bytes 32 (uk-vout k))
    bytes))

(defun utxo-key-txid (k)
  "Extract the 32-byte txid from a utxo-key as a fresh byte vector."
  (declare (type utxo-key k))
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (write-u64-le-into bytes 0 (uk-a k))
    (write-u64-le-into bytes 8 (uk-b k))
    (write-u64-le-into bytes 16 (uk-c k))
    (write-u64-le-into bytes 24 (uk-d k))
    bytes))

(defun add-utxo (utxo-set txid output-index value script-pubkey height &key coinbase)
  "Add a UTXO to the set."
  (let ((key (make-utxo-key txid output-index))
        (entry (make-utxo-entry :value value
                                :script-pubkey script-pubkey
                                :height height
                                :coinbase coinbase)))
    (setf (gethash key (utxo-set-entries utxo-set)) entry)
    (setf (utxo-set-dirty utxo-set) t)
    entry))

(defun remove-utxo (utxo-set txid output-index)
  "Remove a UTXO from the set. Returns the removed entry or NIL."
  (let ((key (make-utxo-key txid output-index)))
    (prog1
        (gethash key (utxo-set-entries utxo-set))
      (remhash key (utxo-set-entries utxo-set))
      (setf (utxo-set-dirty utxo-set) t))))

(defun get-utxo (utxo-set txid output-index)
  "Look up a UTXO in the set. Returns the entry or NIL."
  (let ((key (make-utxo-key txid output-index)))
    (gethash key (utxo-set-entries utxo-set))))

(defun utxo-exists-p (utxo-set txid output-index)
  "Check if a UTXO exists in the set."
  (not (null (get-utxo utxo-set txid output-index))))

(defun utxo-count (utxo-set)
  "Return the number of UTXOs in the set."
  (hash-table-count (utxo-set-entries utxo-set)))

(defun any-utxo-for-txid-p (utxo-set txid)
  "Check if any unspent output exists for TXID (BIP 30 duplicate check).
Scans UTXO keys whose txid portion matches TXID."
  (declare (type (simple-array (unsigned-byte 8) (*)) txid))
  (let ((a (txid-bytes->u64-le txid 0))
        (b (txid-bytes->u64-le txid 8))
        (c (txid-bytes->u64-le txid 16))
        (d (txid-bytes->u64-le txid 24)))
    (declare (type (unsigned-byte 64) a b c d))
    (maphash (lambda (key entry)
               (declare (ignore entry) (type utxo-key key))
               (when (and (= (uk-a key) a) (= (uk-b key) b)
                          (= (uk-c key) c) (= (uk-d key) d))
                 (return-from any-utxo-for-txid-p t)))
             (utxo-set-entries utxo-set)))
  nil)

(defun apply-block-to-utxo-set (utxo-set block height)
  "Apply a block's transactions to the UTXO set.
Adds new outputs and removes spent outputs.
Returns a list of (txid index entry) for all spent UTXOs (undo data for reorgs)."
  (let ((transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block))
        (spent-utxos '()))
    (loop for tx in transactions
          for tx-index from 0
          do
             (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
                   (is-coinbase (zerop tx-index)))
               ;; Remove spent UTXOs (skip for coinbase inputs)
               (unless is-coinbase
                 (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
                   (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                          (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
                          (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
                          ;; Capture the entry before removing (for undo)
                          (entry (get-utxo utxo-set prev-txid prev-index)))
                     (when entry
                       (push (list prev-txid prev-index entry) spent-utxos))
                     (remove-utxo utxo-set prev-txid prev-index))))
               ;; Add new UTXOs
               (loop for output in (bitcoin-lisp.serialization:transaction-outputs tx)
                     for output-index from 0
                     do (add-utxo utxo-set
                                  txid
                                  output-index
                                  (bitcoin-lisp.serialization:tx-out-value output)
                                  (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                                  height
                                  :coinbase is-coinbase))))
    (nreverse spent-utxos)))

(defun disconnect-block-from-utxo-set (utxo-set block previous-utxos)
  "Disconnect a block from the UTXO set (for reorgs).
PREVIOUS-UTXOS should be a list of (txid index entry) for restored UTXOs."
  ;; Remove outputs created by this block
  (dolist (tx (bitcoin-lisp.serialization:bitcoin-block-transactions block))
    (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
      (loop for output-index from 0
            below (length (bitcoin-lisp.serialization:transaction-outputs tx))
            do (remove-utxo utxo-set txid output-index))))
  ;; Restore previously spent UTXOs
  (dolist (prev previous-utxos)
    (destructuring-bind (txid index entry) prev
      (setf (gethash (make-utxo-key txid index) (utxo-set-entries utxo-set))
            entry))))

;;; UTXO Set Persistence
;;;
;;; File format (v1):
;;;   [4 bytes: magic "UTXO"]
;;;   [4 bytes: format version (1)]
;;;   [4 bytes: entry count]
;;;   [... entries ...]
;;;   [4 bytes: CRC32 of all preceding bytes]
;;;
;;; Each entry: 36-byte key, 8-byte value, 4-byte height, 1-byte coinbase,
;;;             4-byte script-len, N-byte script.

;;; Shared UTXO entry serialization helpers

(defun write-utxo-entry-fields (stream entry)
  "Write the fields of a utxo-entry to STREAM: value, height, coinbase, script."
  (bitcoin-lisp.serialization:write-int64-le stream (utxo-entry-value entry))
  (bitcoin-lisp.serialization:write-uint32-le stream (utxo-entry-height entry))
  (write-byte (if (utxo-entry-coinbase entry) 1 0) stream)
  (let ((script (utxo-entry-script-pubkey entry)))
    (bitcoin-lisp.serialization:write-uint32-le stream (length script))
    (write-sequence script stream)))

(declaim (inline bb-write-utxo-entry-fields))
(defun bb-write-utxo-entry-fields (bb entry)
  "Write utxo-entry fields directly into byte-buf BB. Hot path: called
1.2M+ times during save-utxo-set."
  (bitcoin-lisp.serialization:bb-write-i64-le bb (utxo-entry-value entry))
  (bitcoin-lisp.serialization:bb-write-u32-le bb (utxo-entry-height entry))
  (bitcoin-lisp.serialization:bb-write-u8 bb (if (utxo-entry-coinbase entry) 1 0))
  (let ((script (utxo-entry-script-pubkey entry)))
    (bitcoin-lisp.serialization:bb-write-u32-le bb (length script))
    (bitcoin-lisp.serialization:bb-write-bytes bb script)))

(defun read-utxo-entry-fields (stream)
  "Read utxo-entry fields from STREAM. Returns a utxo-entry."
  (let* ((value (bitcoin-lisp.serialization:read-int64-le stream))
         (height (bitcoin-lisp.serialization:read-uint32-le stream))
         (coinbase (= (read-byte stream) 1))
         (script-len (bitcoin-lisp.serialization:read-uint32-le stream))
         (script (make-array script-len :element-type '(unsigned-byte 8))))
    (read-sequence script stream)
    (make-utxo-entry :value value
                     :script-pubkey script
                     :height height
                     :coinbase coinbase)))

;;; Atomic file I/O with CRC32 integrity

(defun fsync-file (path)
  "Force the OS to flush PATH's data to durable storage. Without this,
   a temp+rename atomic write can still leave the destination empty after
   a crash because the kernel hadn't flushed the buffered writes yet."
  #+sbcl
  (handler-case
      (with-open-file (s path :direction :input
                              :element-type '(unsigned-byte 8))
        (sb-posix:fsync (sb-sys:fd-stream-fd s)))
    (error () nil)))

(defun save-file-with-crc32 (path write-fn)
  "Write data to PATH atomically with CRC32 integrity.
WRITE-FN receives a stream and writes the payload (including magic/version/count).
Uses temp file + fsync + rename for crash-safe atomicity.

Stream-based variant. For hot-path saves (save-utxo-set), prefer
SAVE-FILE-WITH-CRC32-BB which avoids flexi-streams' per-byte CLOS
dispatch — was 18% of total CPU on the May 2 testnet4 profile."
  (ensure-directories-exist path)
  (let ((tmp-path (make-pathname :defaults path
                                 :type (concatenate 'string
                                                    (or (pathname-type path) "dat")
                                                    ".tmp"))))
    (let ((all-bytes (flexi-streams:with-output-to-sequence (stream)
                       (funcall write-fn stream))))
      (with-open-file (out tmp-path
                           :direction :output
                           :if-exists :supersede
                           :element-type '(unsigned-byte 8))
        (write-sequence all-bytes out)
        (write-sequence (compute-crc32 all-bytes) out)
        (finish-output out))
      ;; fsync the data before rename — guarantees the new file is on disk
      ;; before any other process (or our crash) sees the rename.
      (fsync-file tmp-path)
      (rename-file tmp-path path))))

(defun save-file-with-crc32-streaming-bb (path bb-fn &key (flush-threshold (* 4 1024 1024)))
  "Streaming variant of save-file-with-crc32-bb. BB-FN receives
(byte-buf flush-fn); calling flush-fn writes the current contents of
the byte-buf to disk, advances the running CRC, and resets bb-pos to
0 so the same buffer can keep growing.

Used for very large payloads (UTXO at 10M+ entries) where buffering
the entire serialization in memory exhausts the heap — observed at
testnet4 h≈70k where a 322MB single-buffer allocation overran the
remaining contiguous heap. The CRC32 still covers the full payload
exactly as if it had been one byte vector.

FLUSH-THRESHOLD is a soft hint: BB-FN may call flush-fn whenever
bb-pos exceeds it. The final flush + CRC append are automatic; bb-fn
must NOT call bb-finish."
  (declare (ignore flush-threshold))
  (ensure-directories-exist path)
  (let ((tmp-path (make-pathname :defaults path
                                 :type (concatenate 'string
                                                    (or (pathname-type path) "dat")
                                                    ".tmp"))))
    (with-open-file (out tmp-path
                         :direction :output
                         :if-exists :supersede
                         :element-type '(unsigned-byte 8))
      (let* ((bb (bitcoin-lisp.serialization:make-byte-buf))
             (digest (ironclad:make-digest :crc32))
             (flush-fn
               (lambda ()
                 (let ((n (bitcoin-lisp.serialization:bb-pos bb)))
                   (when (> n 0)
                     (let ((data (bitcoin-lisp.serialization:bb-data bb)))
                       (ironclad:update-digest digest data :end n)
                       (write-sequence data out :end n)
                       (setf (bitcoin-lisp.serialization:bb-pos bb) 0)))))))
        (funcall bb-fn bb flush-fn)
        (funcall flush-fn)
        (write-sequence (ironclad:produce-digest digest) out)
        (finish-output out)))
    (fsync-file tmp-path)
    (rename-file tmp-path path)))

(defun save-file-with-crc32-bb (path bb-fn)
  "Like SAVE-FILE-WITH-CRC32 but BB-FN receives a byte-buf and writes
into it directly. Avoids the flexi-streams + Gray-stream CLOS dispatch
that dominated CPU on UTXO/state flushes."
  (ensure-directories-exist path)
  (let ((tmp-path (make-pathname :defaults path
                                 :type (concatenate 'string
                                                    (or (pathname-type path) "dat")
                                                    ".tmp"))))
    (let* ((bb (bitcoin-lisp.serialization:make-byte-buf))
           (_ (funcall bb-fn bb))
           (all-bytes (bitcoin-lisp.serialization:bb-finish bb)))
      (declare (ignore _))
      (with-open-file (out tmp-path
                           :direction :output
                           :if-exists :supersede
                           :element-type '(unsigned-byte 8))
        (write-sequence all-bytes out)
        (write-sequence (compute-crc32 all-bytes) out)
        (finish-output out))
      (fsync-file tmp-path)
      (rename-file tmp-path path))))

(defun load-file-with-crc32 (path min-size)
  "Load and verify a CRC32-protected file at PATH.
MIN-SIZE is the minimum valid file size (header + crc).
Returns the file bytes (without CRC) on success, NIL on failure."
  (handler-case
      (with-open-file (in path :direction :input
                               :element-type '(unsigned-byte 8)
                               :if-does-not-exist nil)
        (when in
          (let* ((file-len (file-length in))
                 (data (make-array file-len :element-type '(unsigned-byte 8))))
            (read-sequence data in)
            (when (< file-len min-size)
              (return-from load-file-with-crc32 nil))
            (let* ((payload (subseq data 0 (- file-len 4)))
                   (stored-crc (subseq data (- file-len 4)))
                   (computed-crc (compute-crc32 payload)))
              (if (equalp stored-crc computed-crc)
                  data
                  nil)))))
    (error () nil)))

;;; UTXO Set Persistence

(defvar *utxo-magic* (map '(vector (unsigned-byte 8)) #'char-code "UTXO")
  "Magic bytes identifying a UTXO set file.")

(defconstant +utxo-format-version+ 1
  "Current UTXO persistence format version.")

(defun compute-crc32 (data)
  "Compute CRC32 checksum of byte vector DATA. Returns 4-byte vector."
  (let ((digest (ironclad:make-digest :crc32))
        (simple-data (if (typep data '(simple-array (unsigned-byte 8) (*)))
                         data
                         (coerce data '(simple-array (unsigned-byte 8) (*))))))
    (ironclad:update-digest digest simple-data)
    (ironclad:produce-digest digest)))

(defparameter +utxo-save-flush-threshold+ (* 4 1024 1024)
  "Bytes to accumulate in the byte-buf before flushing to disk during
save-utxo-set. Caps peak save-time memory at ~4MB regardless of UTXO
set size, which matters at testnet4 h>~70k (10M+ entries → ~800MB
serialized). Set lower if heap pressure shows up earlier.")

(defun save-utxo-set (utxo-set path)
  "Save the UTXO set to a binary file at PATH with integrity checks.
Uses atomic write: writes to temporary file, then renames.

Streaming: byte-buf is flushed to disk whenever bb-pos exceeds
+utxo-save-flush-threshold+. Required at testnet4 h>~70k where the
serialized image is hundreds of MB and the previous one-shot byte-buf
exhausted the heap during a single contiguous allocation."
  (save-file-with-crc32-streaming-bb
   path
   (lambda (bb flush-fn)
     (bitcoin-lisp.serialization:bb-write-bytes bb *utxo-magic*)
     (bitcoin-lisp.serialization:bb-write-u32-le bb +utxo-format-version+)
     (bitcoin-lisp.serialization:bb-write-u32-le
      bb (hash-table-count (utxo-set-entries utxo-set)))
     (maphash (lambda (key entry)
                (declare (type utxo-key key))
                (bitcoin-lisp.serialization:bb-write-u64-le bb (uk-a key))
                (bitcoin-lisp.serialization:bb-write-u64-le bb (uk-b key))
                (bitcoin-lisp.serialization:bb-write-u64-le bb (uk-c key))
                (bitcoin-lisp.serialization:bb-write-u64-le bb (uk-d key))
                (bitcoin-lisp.serialization:bb-write-u32-le bb (uk-vout key))
                (bb-write-utxo-entry-fields bb entry)
                (when (>= (bitcoin-lisp.serialization:bb-pos bb)
                          +utxo-save-flush-threshold+)
                  (funcall flush-fn)))
              (utxo-set-entries utxo-set))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun starts-with-magic-p (stream magic)
  "Check if STREAM starts with MAGIC bytes without consuming them."
  (let ((bytes (make-array (length magic) :element-type '(unsigned-byte 8))))
    (let ((n (read-sequence bytes stream)))
      (and (= n (length magic))
           (equalp bytes magic)))))

(defun load-utxo-set (utxo-set path)
  "Load the UTXO set from a binary file at PATH with integrity verification.
Returns T if loaded, NIL if file does not exist or is corrupted."
  (unless (probe-file path)
    ;; Check for interrupted write (.tmp file)
    (let ((tmp-path (make-pathname :defaults path
                                   :type (concatenate 'string
                                                      (or (pathname-type path) "dat")
                                                      ".tmp"))))
      (when (probe-file tmp-path)
        (format *error-output* "WARNING: Found ~A without ~A - interrupted write detected~%"
                tmp-path path)))
    (return-from load-utxo-set nil))
  ;; Read entire file
  (let ((file-bytes (with-open-file (stream path
                                            :direction :input
                                            :element-type '(unsigned-byte 8))
                      (let ((bytes (make-array (file-length stream)
                                               :element-type '(unsigned-byte 8))))
                        (read-sequence bytes stream)
                        bytes))))
    ;; Detect old format (no magic bytes)
    (if (and (>= (length file-bytes) 4)
             (not (equalp (subseq file-bytes 0 4) *utxo-magic*)))
        ;; Old format: load using legacy parser
        (load-utxo-set-legacy utxo-set file-bytes)
        ;; New format: verify integrity
        (load-utxo-set-v1 utxo-set file-bytes))))

(defun load-utxo-set-legacy (utxo-set file-bytes)
  "Load UTXO set from old format (no magic, no checksum)."
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    (let ((count (bitcoin-lisp.serialization:read-uint32-le stream))
          (entries (utxo-set-entries utxo-set))
          (txid-buf (make-array 32 :element-type '(unsigned-byte 8))))
      (clrhash entries)
      (dotimes (i count)
        (read-sequence txid-buf stream)
        (let* ((vout (bitcoin-lisp.serialization:read-uint32-le stream))
               (key (make-utxo-key txid-buf vout)))
          (setf (gethash key entries) (read-utxo-entry-fields stream))))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun load-utxo-set-v1 (utxo-set file-bytes)
  "Load UTXO set from v1 format with integrity checks."
  ;; Need at least magic(4) + version(4) + count(4) + crc(4) = 16 bytes
  (when (< (length file-bytes) 16)
    (format *error-output* "WARNING: UTXO file too short~%")
    (return-from load-utxo-set-v1 nil))
  ;; Verify CRC32
  (let* ((data-len (- (length file-bytes) 4))
         (data-bytes (subseq file-bytes 0 data-len))
         (stored-crc (subseq file-bytes data-len))
         (computed-crc (compute-crc32 data-bytes)))
    (unless (equalp stored-crc computed-crc)
      (format *error-output* "WARNING: UTXO file CRC32 mismatch - file corrupted~%")
      (return-from load-utxo-set-v1 nil)))
  ;; Parse data
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    ;; Skip magic (already verified)
    (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
      (read-sequence magic stream))
    ;; Check version
    (let ((version (bitcoin-lisp.serialization:read-uint32-le stream)))
      (unless (= version +utxo-format-version+)
        (format *error-output* "WARNING: UTXO file version ~D not supported (expected ~D)~%"
                version +utxo-format-version+)
        (return-from load-utxo-set-v1 nil)))
    ;; Read entries
    (let ((count (bitcoin-lisp.serialization:read-uint32-le stream))
          (entries (utxo-set-entries utxo-set))
          (txid-buf (make-array 32 :element-type '(unsigned-byte 8))))
      (clrhash entries)
      (dotimes (i count)
        (read-sequence txid-buf stream)
        (let* ((vout (bitcoin-lisp.serialization:read-uint32-le stream))
               (key (make-utxo-key txid-buf vout)))
          (setf (gethash key entries) (read-utxo-entry-fields stream))))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun utxo-set-file-path (base-path)
  "Get the UTXO set file path from a base data directory."
  (merge-pathnames "utxoset.dat" (pathname base-path)))

;;; UTXO Set Iteration and Statistics

(defun utxo-set-iterate (utxo-set callback)
  "Iterate over all UTXOs in deterministic order.
Order is the on-disk 36-byte (txid || LE vout) lexicographic order, matching
the input to Bitcoin Core's hash_serialized_3 computation.
CALLBACK is called with (txid vout entry) for each UTXO."
  (let ((keys '()))
    (maphash (lambda (key entry)
               (declare (ignore entry))
               (push (cons (utxo-key-bytes key) key) keys))
             (utxo-set-entries utxo-set))
    (setf keys (sort keys #'key-bytes-less-than :key #'car))
    (dolist (pair keys)
      (let* ((key (cdr pair))
             (entry (gethash key (utxo-set-entries utxo-set))))
        (when entry
          (funcall callback (utxo-key-txid key) (uk-vout key) entry))))))

(defun key-bytes-less-than (a b)
  "Compare two 36-byte UTXO key vectors lexicographically."
  (loop for i from 0 below 36
        do (cond
             ((< (aref a i) (aref b i)) (return t))
             ((> (aref a i) (aref b i)) (return nil))))
  nil)

(defun utxo-set-total-amount (utxo-set)
  "Calculate total satoshis in the UTXO set."
  (let ((total 0))
    (maphash (lambda (key entry)
               (declare (ignore key))
               (incf total (utxo-entry-value entry)))
             (utxo-set-entries utxo-set))
    total))

(defun utxo-set-distinct-txids (utxo-set)
  "Count distinct transaction IDs with unspent outputs."
  (let ((txids (make-hash-table :test 'equal)))
    (maphash (lambda (key entry)
               (declare (ignore entry) (type utxo-key key))
               (setf (gethash (list (uk-a key) (uk-b key) (uk-c key) (uk-d key))
                              txids)
                     t))
             (utxo-set-entries utxo-set))
    (hash-table-count txids)))

(defun compute-utxo-set-hash (utxo-set)
  "Compute the hash_serialized_3 UTXO set hash.
This matches Bitcoin Core's format for UTXO set verification.
Returns a 32-byte hash."
  (let ((data (flexi-streams:with-output-to-sequence (out)
                (utxo-set-iterate
                 utxo-set
                 (lambda (txid vout entry)
                   ;; Serialize: txid || vout || height || coinbase || value || scriptPubKey
                   (write-sequence txid out)
                   ;; vout as 4-byte little-endian
                   (write-byte (logand vout #xFF) out)
                   (write-byte (logand (ash vout -8) #xFF) out)
                   (write-byte (logand (ash vout -16) #xFF) out)
                   (write-byte (logand (ash vout -24) #xFF) out)
                   ;; height as 4-byte little-endian
                   (let ((h (utxo-entry-height entry)))
                     (write-byte (logand h #xFF) out)
                     (write-byte (logand (ash h -8) #xFF) out)
                     (write-byte (logand (ash h -16) #xFF) out)
                     (write-byte (logand (ash h -24) #xFF) out))
                   ;; coinbase flag as 1 byte
                   (write-byte (if (utxo-entry-coinbase entry) 1 0) out)
                   ;; value as 8-byte little-endian
                   (let ((v (utxo-entry-value entry)))
                     (loop for i from 0 below 8
                           do (write-byte (logand (ash v (* -8 i)) #xFF) out)))
                   ;; scriptPubKey with length prefix (varint)
                   (let ((script (utxo-entry-script-pubkey entry)))
                     (bitcoin-lisp.serialization:write-compact-size out (length script))
                     (write-sequence script out)))))))
    ;; Return SHA256 of concatenated serializations
    (bitcoin-lisp.crypto:sha256 (coerce data '(simple-array (unsigned-byte 8) (*))))))
