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

(defconstant +max-script-size+ 10000
  "Core MAX_SCRIPT_SIZE: a scriptPubKey larger than this is unspendable.")

(declaim (inline script-unspendable-p))
(defun script-unspendable-p (script)
  "T if SCRIPT is provably unspendable (Bitcoin Core CScript::IsUnspendable):
it begins with OP_RETURN (0x6a) or exceeds MAX_SCRIPT_SIZE. Such outputs can
never be spent, so Core's AddCoin drops them from the UTXO set; block
application here does the same."
  (declare (type (simple-array (unsigned-byte 8) (*)) script))
  (or (and (plusp (length script)) (= (aref script 0) #x6a))
      (> (length script) +max-script-size+)))

(defconstant +max-opcode+ #xb9
  "Bitcoin Core MAX_OPCODE (script.h:216) = OP_NOP10. Byte values above it are
undefined opcodes.")

(defconstant +max-script-element-size+ 520
  "Bitcoin Core MAX_SCRIPT_ELEMENT_SIZE (script.h:28).")

(defun script-has-valid-ops-p (script)
  "T if SCRIPT parses cleanly (Bitcoin Core CScript::HasValidOps, script.cpp):
every opcode decodes, none is above MAX_OPCODE, and no push carries more than
MAX_SCRIPT_ELEMENT_SIZE bytes. A truncated push makes GetOp fail, so the script
is invalid.

Core pairs this with SCRIPT-UNSPENDABLE-P in exactly one place — the
maxburnamount rail on the raw-transaction RPCs (rpc/mempool.cpp:100) — where
`unspendable OR unparseable` is the definition of an output whose value is
burned rather than merely hard to spend."
  (declare (type (simple-array (unsigned-byte 8) (*)) script))
  (let ((len (length script))
        (pos 0))
    (loop
      (when (>= pos len) (return t))
      (let ((opcode (aref script pos)))
        (incf pos)
        (cond
          ;; Direct push: the opcode IS the byte count, so at most 75 — never
          ;; over MAX_SCRIPT_ELEMENT_SIZE, but it can still run off the end.
          ((< opcode #x4c)
           (when (> (+ pos opcode) len) (return nil))
           (incf pos opcode))
          ;; OP_PUSHDATA1/2/4: a 1-, 2- or 4-byte little-endian length follows.
          ((<= #x4c opcode #x4e)
           (let ((size-bytes (ecase opcode (#x4c 1) (#x4d 2) (#x4e 4))))
             (when (> (+ pos size-bytes) len) (return nil))   ; truncated length
             (let ((n 0))
               (dotimes (k size-bytes)
                 (setf n (logior n (ash (aref script (+ pos k)) (* 8 k)))))
               (incf pos size-bytes)
               (when (or (> n +max-script-element-size+)
                         (> (+ pos n) len))                   ; truncated payload
                 (return nil))
               (incf pos n))))
          ;; Non-push byte: valid only up to MAX_OPCODE.
          ((> opcode +max-opcode+) (return nil)))))))

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

;; Public add/get/remove/utxo-count/any-utxo-for-txid-p/apply-block-to-utxo-set
;; /disconnect-block-from-utxo-set used to live here. They moved to
;; coins-view-cache.lisp where they dispatch on view type (utxo-set or
;; coins-view-cache) — the utxo-set branch is the same logic that lived
;; here before; the cache branch delegates to coin-view-*.

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
  (bl.ser:write-int64-le stream (utxo-entry-value entry))
  (bl.ser:write-uint32-le stream (utxo-entry-height entry))
  (write-byte (if (utxo-entry-coinbase entry) 1 0) stream)
  (let ((script (utxo-entry-script-pubkey entry)))
    (bl.ser:write-uint32-le stream (length script))
    (write-sequence script stream)))

(declaim (inline bb-write-utxo-entry-fields))
(defun bb-write-utxo-entry-fields (bb entry)
  "Write utxo-entry fields directly into byte-buf BB. Hot path: called
1.2M+ times during save-utxo-set."
  (bl.ser:bb-write-i64-le bb (utxo-entry-value entry))
  (bl.ser:bb-write-u32-le bb (utxo-entry-height entry))
  (bl.ser:bb-write-u8 bb (if (utxo-entry-coinbase entry) 1 0))
  (let ((script (utxo-entry-script-pubkey entry)))
    (bl.ser:bb-write-u32-le bb (length script))
    (bl.ser:bb-write-bytes bb script)))

(defun read-utxo-entry-fields (stream)
  "Read utxo-entry fields from STREAM. Returns a utxo-entry."
  (let* ((value (bl.ser:read-int64-le stream))
         (height (bl.ser:read-uint32-le stream))
         (coinbase (= (read-byte stream) 1))
         (script-len (bl.ser:read-uint32-le stream))
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

(defun fsync-directory (dir)
  "fsync directory DIR so newly created or renamed names in it are durable
(Core DirectoryCommit, util/fs_helpers.cpp). POSIX does not guarantee a
rename survives a crash until the parent directory is fsynced -- without
this, an atomic temp+fsync+rename can still revert to the old file (or
vanish) after a power loss even though the new data was synced."
  #+sbcl
  (handler-case
      (let ((fd (sb-posix:open (namestring dir) sb-posix:o-rdonly)))
        (unwind-protect (sb-posix:fsync fd)
          (sb-posix:close fd)))
    (error () nil))
  #-sbcl nil)

(defun fsync-parent-directory (path)
  "FSYNC-DIRECTORY of the directory containing PATH, for a file just renamed
into place. This used to be a second FSYNC-DIRECTORY taking a file path; the
later-loaded directory-taking one silently replaced it (same package, same
name), so these calls fsynced the file itself and the parent directory never."
  (let ((dir (directory-namestring path)))
    (fsync-directory (if (string= dir "") "." dir))))

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
      (rename-file tmp-path path)
      (fsync-parent-directory path))))

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
      (let* ((bb (bl.ser:make-byte-buf))
             (digest (ironclad:make-digest :crc32))
             (flush-fn
               (lambda ()
                 (let ((n (bl.ser:bb-pos bb)))
                   (when (> n 0)
                     (let ((data (bl.ser:bb-data bb)))
                       (ironclad:update-digest digest data :end n)
                       (write-sequence data out :end n)
                       (setf (bl.ser:bb-pos bb) 0)))))))
        (funcall bb-fn bb flush-fn)
        (funcall flush-fn)
        (write-sequence (ironclad:produce-digest digest) out)
        (finish-output out)))
    (fsync-file tmp-path)
    (rename-file tmp-path path)
    (fsync-parent-directory path)))

(defun save-file-with-crc32-bb (path bb-fn)
  "Like SAVE-FILE-WITH-CRC32 but BB-FN receives a byte-buf and writes
into it directly. Avoids the flexi-streams + Gray-stream CLOS dispatch
that dominated CPU on UTXO/state flushes."
  (ensure-directories-exist path)
  (let ((tmp-path (make-pathname :defaults path
                                 :type (concatenate 'string
                                                    (or (pathname-type path) "dat")
                                                    ".tmp"))))
    (let* ((bb (bl.ser:make-byte-buf))
           (_ (funcall bb-fn bb))
           (all-bytes (bl.ser:bb-finish bb)))
      (declare (ignore _))
      (with-open-file (out tmp-path
                           :direction :output
                           :if-exists :supersede
                           :element-type '(unsigned-byte 8))
        (write-sequence all-bytes out)
        (write-sequence (compute-crc32 all-bytes) out)
        (finish-output out))
      (fsync-file tmp-path)
      (rename-file tmp-path path)
      (fsync-parent-directory path))))

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
     (bl.ser:bb-write-bytes bb *utxo-magic*)
     (bl.ser:bb-write-u32-le bb +utxo-format-version+)
     (bl.ser:bb-write-u32-le
      bb (hash-table-count (utxo-set-entries utxo-set)))
     (maphash (lambda (key entry)
                (declare (type utxo-key key))
                (bl.ser:bb-write-u64-le bb (uk-a key))
                (bl.ser:bb-write-u64-le bb (uk-b key))
                (bl.ser:bb-write-u64-le bb (uk-c key))
                (bl.ser:bb-write-u64-le bb (uk-d key))
                (bl.ser:bb-write-u32-le bb (uk-vout key))
                (bb-write-utxo-entry-fields bb entry)
                (when (>= (bl.ser:bb-pos bb)
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
    (let ((count (bl.ser:read-uint32-le stream))
          (entries (utxo-set-entries utxo-set))
          (txid-buf (make-array 32 :element-type '(unsigned-byte 8))))
      (clrhash entries)
      (dotimes (i count)
        (read-sequence txid-buf stream)
        (let* ((vout (bl.ser:read-uint32-le stream))
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
    (let ((version (bl.ser:read-uint32-le stream)))
      (unless (= version +utxo-format-version+)
        (format *error-output* "WARNING: UTXO file version ~D not supported (expected ~D)~%"
                version +utxo-format-version+)
        (return-from load-utxo-set-v1 nil)))
    ;; Read entries
    (let ((count (bl.ser:read-uint32-le stream))
          (entries (utxo-set-entries utxo-set))
          (txid-buf (make-array 32 :element-type '(unsigned-byte 8))))
      (clrhash entries)
      (dotimes (i count)
        (read-sequence txid-buf stream)
        (let* ((vout (bl.ser:read-uint32-le stream))
               (key (make-utxo-key txid-buf vout)))
          (setf (gethash key entries) (read-utxo-entry-fields stream))))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun utxo-set-file-path (base-path)
  "Get the UTXO set file path from a base data directory."
  (merge-pathnames "utxoset.dat" (pathname base-path)))

;;; UTXO Set Iteration and Statistics

(defun key-bytes-less-than (a b)
  "Compare two 36-byte UTXO key vectors lexicographically. Strict
less-than: T iff A < B byte-by-byte; NIL if equal or A > B."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b))
  (dotimes (i 36 nil)
    (let ((ai (aref a i))
          (bi (aref b i)))
      (cond ((< ai bi) (return-from key-bytes-less-than t))
            ((> ai bi) (return-from key-bytes-less-than nil))))))

;; utxo-set-iterate / utxo-set-total-amount / utxo-set-distinct-txids /
;; compute-utxo-set-hash live in coins-view-cache.lisp where they
;; dispatch on view type (utxo-set or coins-view-cache).
