(in-package #:bitcoin-lisp.storage)

;;;; Flat-file storage engine (Core flatfile.{h,cpp}, util/obfuscation.h)
;;;;
;;;; Core keeps blocks and undo data in numbered append-only files —
;;;; blk00000.dat, rev00000.dat — rather than one file per block. This is the
;;;; engine underneath that: file naming, chunked preallocation, the
;;;; truncate-on-finalize/fsync discipline, the record framing, the undo
;;;; checksum, and the XOR obfuscation layer applied to both file kinds.
;;;;
;;;; P1 of docs/block-file-format-plan.md. Standalone: nothing in the node
;;;; reads or writes through it yet, so this file can be exercised in
;;;; isolation before any block ever lands in it.

;;;; --- Constants (node/blockstorage.h:118-129) ---------------------------

(defconstant +blockfile-chunk-size+ #x1000000
  "Preallocation granularity for blk?????.dat (Core BLOCKFILE_CHUNK_SIZE, 16 MiB).")

(defconstant +undofile-chunk-size+ #x100000
  "Preallocation granularity for rev?????.dat (Core UNDOFILE_CHUNK_SIZE, 1 MiB).")

(defvar *blocks-xor* t
  "Obfuscate blocksdir contents with a per-datadir key (Core -blocksxor,
DEFAULT_XOR_BLOCKSDIR = true, kernel/blockmanager_opts.h:18). Disabling it
affects only NEW directories: an existing key is always read and used, because
data written under one cannot be read without it.")

(defvar *fast-prune* nil
  "Core's -fastprune: use tiny block files so a pruning test can produce many
of them without mining a real chain (blockstorage.cpp:857-862). Test-only, and
it changes only the ROLLOVER threshold — records already written keep their
positions.")

(defconstant +fast-prune-blockfile-size+ #x10000
  "The 64 KiB cap -fastprune substitutes for +MAX-BLOCKFILE-SIZE+
(blockstorage.cpp:858). Core grows it further when a single block would not
fit, which is the check MAX-BLOCKFILE-SIZE below reproduces.")

(defconstant +max-blockfile-size+ #x8000000
  "A blk?????.dat is rolled over past this (Core MAX_BLOCKFILE_SIZE, 128 MiB).")

(defun max-blockfile-size (record-size)
  "The rollover threshold for a record of RECORD-SIZE bytes.

Normally +MAX-BLOCKFILE-SIZE+. Under -fastprune it is 64 KiB — raised just past
the record when a single one would not fit, because a block that cannot fit in
ANY file could never be written at all (Core blockstorage.cpp:857-862)."
  (if *fast-prune*
      (max +fast-prune-blockfile-size+ (1+ record-size))
      +max-blockfile-size+))

(defconstant +storage-header-bytes+ 8
  "4-byte network magic + 4-byte LE length written before every record
(Core STORAGE_HEADER_BYTES).")

(defconstant +undo-data-disk-overhead+ 40
  "Header plus the 32-byte checksum an undo record carries
(Core UNDO_DATA_DISK_OVERHEAD).")

;;;; --- FlatFilePos --------------------------------------------------------

(defstruct (flat-file-pos (:constructor make-flat-file-pos (&optional (file -1) (pos 0))))
  "A position in a numbered file (Core FlatFilePos, flatfile.h:12-35).
FILE -1 is Core's null position."
  (file -1 :type (signed-byte 32))
  (pos 0 :type (unsigned-byte 32)))

(defun flat-file-pos-null-p (p)
  (= -1 (flat-file-pos-file p)))

;;;; --- Obfuscation (util/obfuscation.h) -----------------------------------
;;;;
;;;; plain[i] = disk[i] XOR key[(file_offset + i) mod 8].
;;;;
;;;; Core's implementation is an aggressively unrolled word-at-a-time XOR over
;;;; a table of eight pre-rotated copies of the key; on a little-endian machine
;;;; rotations[i] is the key with byte i first, and XorWord copies target bytes
;;;; into a little-endian word, so byte n of the target meets key byte
;;;; (key_offset + n) mod 8. That identity is the whole specification, and it
;;;; is what this implements — the rotation table is a speed trick, not part of
;;;; the format.
;;;;
;;;; An all-zero key means "not obfuscated", which is what a pre-existing
;;;; blocksdir without an xor.dat gets, so old data stays readable.

(defconstant +obfuscation-key-size+ 8)

(defun obfuscation-key-active-p (key)
  "NIL for the all-zero key, which Core treats as no obfuscation at all
(Obfuscation::operator bool)."
  (and key (notevery #'zerop key)))

(defun obfuscate! (bytes key &key (key-offset 0) (start 0) (end (length bytes)))
  "XOR BYTES[START,END) in place with KEY, as if the byte at START sat at file
offset KEY-OFFSET. Its own inverse. A no-op for an inactive key.

Declared and unrolled because this is a genuinely hot loop: profiling an
offline reindex of a Core testnet4 datadir put it at 8.3% of total runtime,
with its per-byte AREF showing up as SB-KERNEL:VECTOR-HAIRY-DATA-VECTOR-REF/
CHECK-BOUNDS (2.3% on its own) and its (MOD offset 8) as generic FLOOR (1.4%).
Every block read from a Core-written blocksdir passes through here.

The range is bounds-checked ONCE at entry, before SAFETY drops — so a caller
passing a bad START/END gets an error rather than a write past the end of the
vector, which is the only thing SAFETY 0 would otherwise have cost us."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes key)
           (type fixnum key-offset start end))
  (when (obfuscation-key-active-p key)
    (assert (<= 0 start end (length bytes)) (start end)
            "obfuscate!: range [~D,~D) is outside a ~D-byte vector"
            start end (length bytes))
    (assert (= +obfuscation-key-size+ (length key)) (key)
            "obfuscate!: key is ~D bytes, expected ~D"
            (length key) +obfuscation-key-size+)
    ;; The key size is a power of two, so the wrap is a mask rather than a
    ;; division. Asserted at compile time: a future non-power-of-two key size
    ;; would make LOGAND silently read the wrong key byte and corrupt every
    ;; block written after it.
    (locally (declare (optimize (speed 3) (safety 0)))
      (let ((mask (load-time-value
                   (progn
                     (assert (zerop (logand +obfuscation-key-size+
                                            (1- +obfuscation-key-size+))))
                     (1- +obfuscation-key-size+))
                   t)))
        (declare (type fixnum mask))
        (loop for i of-type fixnum from start below end
              for offset of-type fixnum from key-offset
              do (setf (aref bytes i)
                       (logxor (aref bytes i)
                               (aref key (logand offset mask))))))))
  bytes)

(defun make-obfuscation-key ()
  "A fresh random 8-byte key."
  (let ((key (make-array +obfuscation-key-size+ :element-type '(unsigned-byte 8)))
        (bytes (ironclad:random-data +obfuscation-key-size+)))
    (replace key bytes)
    key))

(defun zero-obfuscation-key ()
  (make-array +obfuscation-key-size+ :element-type '(unsigned-byte 8) :initial-element 0))

(defun %blocksdir-first-run-p (dir)
  "T when DIR holds no block data of either form.

Core's test is \"the blocksdir contains only hidden files\", with a comment
saying a fully-empty check would be too aggressive because a .lock may already
be there (blockstorage.cpp:1173-1183). The files that are not hidden and not
block data are exactly the ones we also create — so naming the block data
directly says the same thing and does not depend on how SBCL's DIRECTORY treats
dotfiles."
  (and (null (directory (merge-pathnames "blk*.dat" dir)))
       (null (directory (merge-pathnames "rev*.dat" dir)))
       (null (directory (merge-pathnames "*.blk" dir)))))

(defun %write-xor-key (path key)
  "Write KEY to PATH durably and return it."
  (ensure-directories-exist path)
  (with-open-file (s path :direction :output :element-type '(unsigned-byte 8)
                          :if-exists :error :if-does-not-exist :create)
    (write-sequence key s))
  (fsync-file path)
  key)

(defun read-or-create-xor-key (dir &key (use-xor t))
  "The blocksdir's obfuscation key (Core InitBlocksdirXorKey,
blockstorage.cpp:1167-1222). Core's shape exactly:

- A RANDOM key only when USE-XOR and this is the first run — a directory that
  already holds block data must not acquire one, or every byte already in it
  becomes unreadable.
- A PRE-EXISTING xor.dat always wins, whatever USE-XOR now says: a directory
  written with a key has to keep being read with it.
- Otherwise the file is CREATED, holding whatever key was chosen — all zeros
  when obfuscation is off or this is not a first run. Core creates it
  unconditionally when it is missing, and feature_blocksxor.py checks exactly
  that: delete xor.dat, restart with -blocksxor=0, and the file must come back
  holding the null key.

Returns the key. The caller decides what a stored NON-ZERO key means when
USE-XOR is off — that is a fatal init error, and it needs the path to say so."
  (let ((path (merge-pathnames "xor.dat" dir)))
    (if (probe-file path)
        (let ((key (make-array +obfuscation-key-size+ :element-type '(unsigned-byte 8))))
          (with-open-file (s path :element-type '(unsigned-byte 8))
            (unless (= +obfuscation-key-size+ (read-sequence key s))
              (storage-error "xor.dat must be exactly ~D bytes" +obfuscation-key-size+))
            ;; Core rejects a longer file too: the key is fixed-size.
            (when (read-byte s nil nil)
              (storage-error "xor.dat must be exactly ~D bytes" +obfuscation-key-size+)))
          key)
        (%write-xor-key path
                        (if (and use-xor (%blocksdir-first-run-p dir))
                            (make-obfuscation-key)
                            (zero-obfuscation-key))))))

;;;; --- FlatFileSeq --------------------------------------------------------

(defstruct (flat-file-seq (:constructor %make-flat-file-seq (dir prefix chunk-size)))
  "A sequence of numbered files storing raw data (Core FlatFileSeq,
flatfile.h:37-84)."
  (dir nil)
  (prefix "" :type string)
  (chunk-size 1 :type (integer 1)))

(defun make-flat-file-seq (dir prefix chunk-size)
  (when (zerop chunk-size)
    (internal-error "chunk-size must be positive"))
  (%make-flat-file-seq dir prefix chunk-size))

(defun flat-file-name (seq pos)
  "The path of the file at POS (Core FlatFileSeq::FileName): <prefix>%05u.dat."
  (merge-pathnames (format nil "~A~5,'0D.dat"
                           (flat-file-seq-prefix seq)
                           (flat-file-pos-file pos))
                   (flat-file-seq-dir seq)))

(defmacro with-flat-file ((var seq pos &key read-only) &body body)
  "Open the file at POS, seek to its position, and run BODY with the stream
bound to VAR (Core FlatFileSeq::Open). NIL for a null position."
  (let ((s (gensym "SEQ")) (p (gensym "POS")) (path (gensym "PATH")))
    `(let ((,s ,seq) (,p ,pos))
       (if (flat-file-pos-null-p ,p)
           nil
           (let ((,path (flat-file-name ,s ,p)))
             (ensure-directories-exist ,path)
             (with-open-file (,var ,path
                                   :direction ,(if read-only :input :io)
                                   :element-type '(unsigned-byte 8)
                                   :if-exists ,(if read-only nil :overwrite)
                                   :if-does-not-exist ,(if read-only nil :create))
               (when (plusp (flat-file-pos-pos ,p))
                 (file-position ,var (flat-file-pos-pos ,p)))
               ,@body))))))

(defun flat-file-allocate (seq pos add-size)
  "Grow the file at POS so ADD-SIZE more bytes fit, rounding up to whole chunks
(Core FlatFileSeq::Allocate). Returns the number of bytes added.

Core's preallocation is advisory — it exists to keep a growing block file
contiguous on disk, and its own fallback path simply writes zeros. This does
the same by extending the file's length, which is what the fallback achieves;
no format depends on it."
  (let* ((chunk (flat-file-seq-chunk-size seq))
         (old-pos (flat-file-pos-pos pos))
         (old-chunks (ceiling old-pos chunk))
         (new-chunks (ceiling (+ old-pos add-size) chunk)))
    (if (<= new-chunks old-chunks)
        0
        (let* ((new-size (* new-chunks chunk))
               (inc (- new-size old-pos))
               (path (flat-file-name seq pos)))
          (ensure-directories-exist path)
          (with-open-file (s path :direction :io :element-type '(unsigned-byte 8)
                                  :if-exists :overwrite :if-does-not-exist :create)
            (let ((zeros (make-array (min inc 65536) :element-type '(unsigned-byte 8)
                                                     :initial-element 0)))
              (file-position s old-pos)
              (loop with left = inc
                    while (plusp left)
                    for now = (min left (length zeros))
                    do (write-sequence zeros s :end now)
                       (decf left now))))
          inc))))

(defun flat-file-flush (seq pos &key finalize)
  "Commit the file at POS to disk, truncating away unwritten preallocation when
FINALIZE (Core FlatFileSeq::Flush). POS is the first UNWRITTEN position."
  (let ((path (flat-file-name seq pos)))
    (unless (probe-file path)
      (return-from flat-file-flush nil))
    (when finalize
      (with-open-file (s path :direction :io :element-type '(unsigned-byte 8)
                              :if-exists :overwrite)
        #+sbcl (sb-posix:ftruncate (sb-sys:fd-stream-fd s) (flat-file-pos-pos pos))))
    (fsync-file path)
    ;; Core fsyncs the directory too, so a rename or a new file name is durable
    ;; and not just its contents (DirectoryCommit).
    (fsync-directory (flat-file-seq-dir seq))
    t))

;;;; --- Record framing -----------------------------------------------------
;;;;
;;;; Every record on disk is [4-byte network magic][4-byte LE length][payload],
;;;; and an undo record additionally carries a 32-byte checksum after its
;;;; payload. The position recorded in the block index points PAST the 8-byte
;;;; header, at the payload — so a reader seeks to it directly and the header
;;;; is only consulted when scanning a file from the outside, which is what
;;;; makes a full -reindex possible.

(defun flat-record-bytes (magic payload)
  "Frame PAYLOAD as a stored record: magic, LE length, payload."
  (let ((out (make-array (+ +storage-header-bytes+ (length payload))
                         :element-type '(unsigned-byte 8))))
    (replace out magic)
    (let ((n (length payload)))
      (setf (aref out 4) (ldb (byte 8 0) n)
            (aref out 5) (ldb (byte 8 8) n)
            (aref out 6) (ldb (byte 8 16) n)
            (aref out 7) (ldb (byte 8 24) n)))
    (replace out payload :start1 +storage-header-bytes+)
    out))

(defun undo-record-checksum (prev-block-hash undo-bytes)
  "Core's undo checksum: SHA256d(prev block hash || serialized CBlockUndo)
(blockstorage.cpp:996-999). Binding the PREVIOUS block's hash means a rev
record cannot be silently mistaken for a different block's."
  (bl.crypto:hash256
   (concatenate '(vector (unsigned-byte 8)) prev-block-hash undo-bytes)))

(defun undo-record-bytes (magic prev-block-hash undo-bytes)
  "A complete rev-file record: header, CBlockUndo, checksum."
  (concatenate '(vector (unsigned-byte 8))
               (flat-record-bytes magic undo-bytes)
               (undo-record-checksum prev-block-hash undo-bytes)))

(defun parse-flat-record-header (bytes &optional (start 0))
  "Read a record header from BYTES at START. Returns (values magic length), or
NIL if there are not enough bytes."
  (when (<= (+ start +storage-header-bytes+) (length bytes))
    (values (subseq bytes start (+ start 4))
            (logior (aref bytes (+ start 4))
                    (ash (aref bytes (+ start 5)) 8)
                    (ash (aref bytes (+ start 6)) 16)
                    (ash (aref bytes (+ start 7)) 24)))))

(defun find-next-record (bytes magic &key (start 0))
  "Scan forward from START for the next record whose header carries MAGIC, and
return (values payload-start length) or NIL.

This is the byte-wise magic hunt Core's LoadExternalBlockFile does
(validation.cpp:4988-5155): a block file may contain garbage — a torn write, a
partially preallocated tail, or another network's data — so a reindex resyncs
to the next magic rather than giving up at the first bad byte."
  (loop for i from start to (- (length bytes) +storage-header-bytes+)
        do (when (and (= (aref bytes i) (aref magic 0))
                      (= (aref bytes (+ i 1)) (aref magic 1))
                      (= (aref bytes (+ i 2)) (aref magic 2))
                      (= (aref bytes (+ i 3)) (aref magic 3)))
             (multiple-value-bind (found length) (parse-flat-record-header bytes i)
               (declare (ignore found))
               (when (<= (+ i +storage-header-bytes+ length) (length bytes))
                 (return (values (+ i +storage-header-bytes+) length)))))))
