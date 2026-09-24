(in-package #:bitcoin-lisp.storage)

;;;; The block tree database: Core's BlockTreeDB (node/blockstorage.{h,cpp},
;;;; kernel namespace), a LevelDB at <datadir>/<net>/blocks/index.
;;;;
;;;; This is where the block index persists, record for record in Core's
;;;; format, so that a datadir written by Core loads here and one written here
;;;; loads in Core. The keys (node/blockstorage.cpp:58-62):
;;;;
;;;;   'b' + hash   -> CDiskBlockIndex (chain.h:316-376)
;;;;   'f' + nFile  -> CBlockFileInfo  (node/blockstorage.h:56-90), nFile an
;;;;                   int32 little-endian, as std::pair<uint8_t,int> serializes
;;;;   'l'          -> the highest blk file number (int32 little-endian)
;;;;   'R'          -> '1' while a reindex is under way; absent otherwise
;;;;   'F' + name   -> '1' / '0'; the name is a serialized std::string
;;;;                   (CompactSize length + bytes). Only "prunedblockfiles"
;;;;                   is written today.
;;;;
;;;; What CDiskBlockIndex does NOT hold is as much a part of the format as what
;;;; it does. The hash is not stored: it is the double-SHA256 of the header,
;;;; recomputed on load (CDiskBlockIndex::ConstructBlockHash). Chain work is not
;;;; stored: LoadBlockIndex sums GetBlockProof up each chain, sorted by height
;;;; (node/blockstorage.cpp:452-461). And the proof of work is re-checked on
;;;; every load (:148-151) -- a record whose header does not meet its own nBits
;;;; fails the whole load, which is Core's "Error loading block database".
;;;;
;;;; Our BLOCK-INDEX-ENTRY keeps its status as a keyword and its positions as
;;;; nullable integers; nStatus is derived from them on write and decoded into
;;;; them on read (ENTRY-DISK-STATUS, %APPLY-DISK-STATUS). The bits we do not
;;;; model -- BLOCK_OPT_WITNESS above all -- travel in STATUS-FLAGS.

;;; Keys (node/blockstorage.cpp:58-62)

(defconstant +db-block-files+ (char-code #\f) "Core DB_BLOCK_FILES.")
(defconstant +db-block-index+ (char-code #\b) "Core DB_BLOCK_INDEX.")
(defconstant +db-flag+ (char-code #\F) "Core DB_FLAG.")
(defconstant +db-reindex-flag+ (char-code #\R) "Core DB_REINDEX_FLAG.")
(defconstant +db-last-block+ (char-code #\l) "Core DB_LAST_BLOCK.")

;;; BlockStatus (chain.h:42-86)

(defconstant +block-valid-tree+ 2 "Core BLOCK_VALID_TREE.")
(defconstant +block-valid-transactions+ 3 "Core BLOCK_VALID_TRANSACTIONS.")
(defconstant +block-valid-scripts+ 5 "Core BLOCK_VALID_SCRIPTS.")
(defconstant +block-valid-mask+ 7 "Core BLOCK_VALID_MASK.")
(defconstant +block-have-data+ 8 "Core BLOCK_HAVE_DATA.")
(defconstant +block-have-undo+ 16 "Core BLOCK_HAVE_UNDO.")
(defconstant +block-failed-valid+ 32 "Core BLOCK_FAILED_VALID.")
(defconstant +block-failed-child+ 64
  "Core BLOCK_FAILED_CHILD: no longer set, but still found on disk, and read
as BLOCK_FAILED_VALID (node/blockstorage.cpp:483-487).")
(defconstant +block-opt-witness+ 128
  "Core BLOCK_OPT_WITNESS: the block's data was received by a node enforcing
segwit at that height (validation.cpp:3817-3819). NeedsRedownload refuses a
chain whose segwit-active blocks lack it.")

(defconstant +disk-block-index-version+ 259900
  "CDiskBlockIndex::DUMMY_VERSION (chain.h:324): the client-version field every
record opens with. Core writes this constant and never reads it back.")

(defparameter *obfuscation-key-record*
  (let ((name "obfuscate_key"))
    (concatenate '(vector (unsigned-byte 8))
                 (vector 14 0) (map 'vector #'char-code name)))
  "CDBWrapper::OBFUSCATION_KEY as it lands on disk: the 14-byte string
\"\\000obfuscate_key\" (dbwrapper.h:192) serialized with its CompactSize length.
Core opens blocks/index with obfuscation OFF (DBParams::obfuscate defaults to
false, init.cpp:1339-1345), so it never writes this record there; a record that
IS present is honoured on read, as CDBWrapper does for every database.")

;;; Segwit activation, for BLOCK_OPT_WITNESS

(defvar *segwit-height-fn* nil
  "A function of no arguments answering the active network's segwit activation
height, -testactivationheight included. Installed by the validation layer,
which owns the deployment table; NIL (a bare storage-layer test) means segwit
is never active, so nothing is flagged.")

(defun segwit-active-at-p (height)
  "T when segwit is active for a block at HEIGHT -- Core's DeploymentActiveAt(
*pindex, DEPLOYMENT_SEGWIT), which is `height >= SegwitHeight'."
  (and *segwit-height-fn* (>= height (funcall *segwit-height-fn*))))

(defun note-block-witness-received (entry)
  "Core ReceivedBlockTransactions (validation.cpp:3817-3819): a block body
stored at a height where segwit is active marks its entry BLOCK_OPT_WITNESS.
We fetch and store bodies with witness data whenever segwit applies, so every
body we store qualifies. Returns ENTRY."
  (when (and entry (segwit-active-at-p (block-index-entry-height entry)))
    (setf (block-index-entry-status-flags entry)
          (logior (block-index-entry-status-flags entry) +block-opt-witness+)))
  entry)

(defun fake-opt-witness-below (entry)
  "Core ActivateSnapshot (validation.cpp:5947-5957): every block of the
snapshot chain above genesis is marked BLOCK_OPT_WITNESS where segwit is
active, so the snapshot chainstate -- whose bodies were never received -- does
not trip NeedsRedownload on the next start."
  (loop for e = entry then (block-index-entry-prev-entry e)
        while (and e (plusp (block-index-entry-height e)))
        do (note-block-witness-received e)))

(defun chain-needs-redownload-p (state)
  "Core Chainstate::NeedsRedownload (validation.cpp:4892-4908): walking down
from the tip while segwit is active, T at the first block without
BLOCK_OPT_WITNESS -- a block this node accepted without enforcing segwit, which
therefore still has to be validated under it."
  (loop for e = (get-block-index-entry state (chain-state-best-block-hash state))
          then (block-index-entry-prev-entry e)
        while (and e (segwit-active-at-p (block-index-entry-height e)))
        unless (logtest (block-index-entry-status-flags e) +block-opt-witness+)
          return t))

;;; nStatus <-> our entry
;;;
;;; Core keeps a block's validity LEVEL and its FAILURE bits apart in nStatus
;;; (chain.h:42-86): InvalidateBlock and InvalidBlockFound set
;;; BLOCK_FAILED_VALID, ResetBlockFailureFlags clears only BLOCK_FAILED_MASK
;;; (validation.cpp:3754-3784), and a block that reached BLOCK_VALID_SCRIPTS is
;;; SCRIPTS-valid again after reconsiderblock -- servable to peers
;;; (BlockRequestAllowed) and connectable without re-validation. Our status is
;;; one keyword, so an :invalid entry keeps the level it had in the
;;; BLOCK_VALID_MASK bits of STATUS-FLAGS, which only an :invalid entry uses.

(defun mark-entry-failed (entry)
  "Core's `pindex->nStatus |= BLOCK_FAILED_VALID': ENTRY becomes :invalid,
remembering whether it had reached BLOCK_VALID_SCRIPTS. Idempotent."
  (unless (eq (block-index-entry-status entry) :invalid)
    (setf (block-index-entry-status-flags entry)
          (logior (logandc2 (block-index-entry-status-flags entry) +block-valid-mask+)
                  (if (eq (block-index-entry-status entry) :valid)
                      +block-valid-scripts+
                      0))
          (block-index-entry-status entry) :invalid))
  entry)

(defun clear-entry-failure (entry)
  "Core ResetBlockFailureFlags for one entry (validation.cpp:3769-3772): the
failure is cleared and the validity level it had comes back -- :valid for a
block that had reached BLOCK_VALID_SCRIPTS, :header-valid otherwise."
  (when (eq (block-index-entry-status entry) :invalid)
    (let ((flags (block-index-entry-status-flags entry)))
      (setf (block-index-entry-status entry)
            (if (>= (logand flags +block-valid-mask+) +block-valid-scripts+)
                :valid
                :header-valid)
            (block-index-entry-status-flags entry)
            (logandc2 flags +block-valid-mask+))))
  entry)

(defun entry-disk-status (entry)
  "ENTRY's Core nStatus. The validity level comes from the status keyword and
from whether the body is held (a body we hold has passed Core's
BLOCK_VALID_TRANSACTIONS, validation.cpp:3829); HAVE_DATA and HAVE_UNDO are the
positions' presence; FAILED_VALID is :invalid; the rest is STATUS-FLAGS."
  (let* ((data (block-index-entry-data-pos entry))
         (status (block-index-entry-status entry))
         (flags (block-index-entry-status-flags entry))
         (level (ecase status
                  (:unknown 0)
                  (:valid +block-valid-scripts+)
                  (:header-valid (if data +block-valid-transactions+ +block-valid-tree+))
                  (:invalid (max (logand flags +block-valid-mask+)
                                 (if data +block-valid-transactions+ +block-valid-tree+))))))
    (logior level
            (if data +block-have-data+ 0)
            (if (block-index-entry-undo-pos entry) +block-have-undo+ 0)
            (if (eq status :invalid) +block-failed-valid+ 0)
            (logandc2 flags +block-valid-mask+))))

(defun %disk-status-keyword (nstatus)
  "The status keyword NSTATUS decodes to: failed (either failure bit) is
:invalid, BLOCK_VALID_SCRIPTS is :valid, no validity at all is :unknown, and
every level between is :header-valid."
  (let ((level (logand nstatus +block-valid-mask+)))
    (cond ((logtest nstatus (logior +block-failed-valid+ +block-failed-child+))
           :invalid)
          ((zerop level) :unknown)
          ((>= level +block-valid-scripts+) :valid)
          (t :header-valid))))

(defun %disk-status-extra-bits (nstatus)
  "The bits of NSTATUS the entry keeps verbatim in STATUS-FLAGS: everything but
the validity level, HAVE_DATA/HAVE_UNDO and the two failure bits, which the
status keyword and the positions already carry -- except that a FAILED entry
that had reached BLOCK_VALID_SCRIPTS keeps that level (MARK-ENTRY-FAILED)."
  (logior (logand nstatus
                  (lognot (logior +block-valid-mask+ +block-have-data+ +block-have-undo+
                                  +block-failed-valid+ +block-failed-child+))
                  #xFFFFFFFF)
          (if (and (logtest nstatus (logior +block-failed-valid+ +block-failed-child+))
                   (>= (logand nstatus +block-valid-mask+) +block-valid-scripts+))
              +block-valid-scripts+
              0)))

;;; CDiskBlockIndex (chain.h:316-376)

(defun block-index-record-key (hash)
  "The 33-byte key of HASH's 'b' record: the prefix, then the hash in its
internal byte order (uint256 serializes its bytes as they are)."
  (let ((key (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref key 0) +db-block-index+)
    (replace key hash :start1 1)
    key))

(defun encode-disk-block-index (entry)
  "ENTRY as Core's CDiskBlockIndex value (chain.h:339-360): VARINT client
version, VARINT nHeight, VARINT nStatus, VARINT nTx, nFile if the block has data
or undo, nDataPos if data, nUndoPos if undo, then the 80-byte header.

Core writes hashPrev from pprev; we write the header as it is, whose prev-block
IS the parent's hash for every linked entry. The two could differ only for an
entry whose parent is not in the index, and there the header's own field is the
one that makes the reloaded hash come out right."
  (let ((bb (bl.ser:make-byte-buf))
        (nstatus (entry-disk-status entry)))
    (bl.ser:bb-write-core-varint bb +disk-block-index-version+)
    (bl.ser:bb-write-core-varint bb (block-index-entry-height entry))
    (bl.ser:bb-write-core-varint bb nstatus)
    (bl.ser:bb-write-core-varint bb (block-index-entry-tx-count entry))
    (when (logtest nstatus (logior +block-have-data+ +block-have-undo+))
      (bl.ser:bb-write-core-varint bb (or (block-index-entry-file entry) 0)))
    (when (logtest nstatus +block-have-data+)
      (bl.ser:bb-write-core-varint bb (block-index-entry-data-pos entry)))
    (when (logtest nstatus +block-have-undo+)
      (bl.ser:bb-write-core-varint bb (block-index-entry-undo-pos entry)))
    (bl.bytes:bb-write-bytes
     bb (bl.ser:serialize-block-header (block-index-entry-header entry)))
    (bl.ser:bb-finish bb)))

(defun decode-disk-block-index (bytes)
  "Parse a CDiskBlockIndex value. Returns (values ENTRY PREV-HASH NSTATUS):
a fresh entry whose hash is its header's (ConstructBlockHash), with no parent
link and no chain work yet -- LOAD-HEADER-INDEX supplies both."
  (let* ((br (bl.bytes:make-byte-reader-from bytes))
         (_version (bl.ser:br-read-core-varint br))
         (height (bl.ser:br-read-core-varint br))
         (nstatus (bl.ser:br-read-core-varint br))
         (tx-count (bl.ser:br-read-core-varint br))
         (file (when (logtest nstatus (logior +block-have-data+ +block-have-undo+))
                 (bl.ser:br-read-core-varint br)))
         (data-pos (when (logtest nstatus +block-have-data+)
                     (bl.ser:br-read-core-varint br)))
         (undo-pos (when (logtest nstatus +block-have-undo+)
                     (bl.ser:br-read-core-varint br)))
         (header-bytes (bl.bytes:br-read-bytes br 80))
         (hash (bl.crypto:hash256 header-bytes))
         (hbr (bl.bytes:make-byte-reader-from header-bytes))
         (header (bl.ser:make-block-header
                  :version (bl.bytes:br-read-i32-le hbr)
                  :prev-block (bl.bytes:br-read-bytes hbr 32)
                  :merkle-root (bl.bytes:br-read-bytes hbr 32)
                  :timestamp (bl.bytes:br-read-u32-le hbr)
                  :bits (bl.bytes:br-read-u32-le hbr)
                  :nonce (bl.bytes:br-read-u32-le hbr)
                  :cached-hash hash)))
    (declare (ignore _version))
    (values (make-block-index-entry
             :hash hash
             :height height
             :header header
             :status (%disk-status-keyword nstatus)
             :status-flags (%disk-status-extra-bits nstatus)
             :tx-count tx-count
             :file file
             :data-pos data-pos
             :undo-pos undo-pos)
            (bl.ser:block-header-prev-block header)
            nstatus)))

;;; CBlockFileInfo (node/blockstorage.h:56-90)

(defun block-file-info-record-key (file)
  "The 5-byte key of FILE's 'f' record: the prefix, then nFile as an int32
little-endian (std::pair<uint8_t, int>)."
  (concatenate '(simple-array (unsigned-byte 8) (*))
               (vector +db-block-files+) (%int32-le-bytes file)))

(defun encode-block-file-info (info &key size)
  "INFO as Core's CBlockFileInfo: seven VARINTs, nBlocks, nSize, nUndoSize,
nHeightFirst, nHeightLast, nTimeFirst, nTimeLast. SIZE overrides nSize -- the
block store's cursor is the used size of the file still being appended to,
whose length on disk includes its preallocated tail."
  (let ((bb (bl.ser:make-byte-buf)))
    (dolist (v (list (block-file-info-blocks info)
                     (or size (block-file-info-size info))
                     (block-file-info-undo-size info)
                     (or (block-file-info-height-first info) 0)
                     (or (block-file-info-height-last info) 0)
                     (or (block-file-info-time-first info) 0)
                     (or (block-file-info-time-last info) 0)))
      (bl.ser:bb-write-core-varint bb v))
    (bl.ser:bb-finish bb)))

(defun decode-block-file-info (bytes)
  "Parse a CBlockFileInfo value into a BLOCK-FILE-INFO."
  (let ((br (bl.bytes:make-byte-reader-from bytes)))
    (flet ((v () (bl.ser:br-read-core-varint br)))
      (let* ((blocks (v)) (size (v)) (undo-size (v))
             (height-first (v)) (height-last (v))
             (time-first (v)) (time-last (v)))
        (make-block-file-info
         :blocks blocks :size size :undo-size undo-size
         :height-first height-first :height-last height-last
         :time-first time-first :time-last time-last)))))

(defun %int32-le-bytes (n)
  "N as the four bytes of an int32 little-endian."
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
    (loop for i from 0 below 4 do (setf (aref v i) (ldb (byte 8 (* 8 i)) n)))
    v))

(defun %db-flag-key (name)
  "The key of flag NAME: 'F', then NAME serialized as a std::string."
  (concatenate '(vector (unsigned-byte 8))
               (vector +db-flag+ (length name))
               (map 'vector #'char-code name)))

(defparameter *reindex-flag-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element +db-reindex-flag+)
  "The single-byte key of Core's reindexing record.")

(defparameter *last-block-file-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element +db-last-block+)
  "The single-byte key of Core's last-block-file record.")

;;; The database handle

(defstruct (block-tree-db (:constructor %make-block-tree-db))
  "One open blocks/index LevelDB.

OBFUSCATION is the XOR key read from the database's own key record, or NIL.
FILE-INFO-WRITTEN maps a file number to the 'f' value last written for it, so
a flush writes only the files whose record changed (Core's m_dirty_fileinfo,
derived here from the value rather than marked at each mutation site, for the
reason %ENTRY-PERSIST-KEY gives). LOCK serialises writers: the periodic flush
and the coins-sync hook reach the database from different threads."
  (handle nil)
  (directory nil)
  (obfuscation nil)
  (file-info-written (make-hash-table :test 'eql))
  (last-file-written nil)
  (pruned-flag-written nil)
  (lock (bt:make-lock "block-tree-db")))

(defvar *block-tree-dbs* (make-hash-table :test 'equal :synchronized t)
  "Open block tree databases, keyed by the NAMESTRING of the chain-state base
path (the network data directory) whose blocks/index they are. The node opens
its own at start-up and closes it at shutdown; a chain-state with no open
database (a test fixture) opens one for the duration of each call.")

(defun block-tree-db-path (base-path)
  "BASE-PATH's blocks/index directory."
  (datadir-block-index-path base-path))

(defun %base-path-key (base-path)
  (namestring (or base-path #p"")))

(defun %read-obfuscation-key (handle)
  "The database's XOR key when it has a key record, else NIL. The value is an
8-byte vector serialized with its CompactSize length (util/obfuscation.h:44-59)."
  (let ((v (leveldb-get handle *obfuscation-key-record*)))
    (when v
      (unless (and (= (length v) 9) (= (aref v 0) 8))
        (storage-error "Obfuscation key size should be exactly 8 bytes long"))
      (let ((key (subseq v 1)))
        (when (obfuscation-key-active-p key) key)))))

(defun %open-block-tree-handle (base-path)
  "Open BASE-PATH's blocks/index and wrap it; signals on failure."
  (let* ((path (block-tree-db-path base-path))
         (handle (progn (ensure-directories-exist path)
                        (leveldb-open-tuned
                         path
                         :cache-bytes (if *cache-sizes*
                                          (cache-sizes-block-tree-db *cache-sizes*)
                                          0)))))
    (handler-bind ((error (lambda (e) (declare (ignore e)) (leveldb-close handle))))
      (let ((db (%make-block-tree-db :handle handle :directory path
                                     :obfuscation (%read-obfuscation-key handle))))
        (%seed-file-info-written db)
        db))))

(defun %int32-le-value (bytes &optional (start 0))
  "The int32 little-endian number at START of BYTES (nFile in an 'f' key, the
'l' value)."
  (logior (aref bytes start) (ash (aref bytes (+ start 1)) 8)
          (ash (aref bytes (+ start 2)) 16) (ash (aref bytes (+ start 3)) 24)))

(defun %map-prefix-records (db prefix key-length fn &key verify-checksums)
  "Call FN with the key and the (de-obfuscated) value of every record of DB
whose key is KEY-LENGTH bytes starting with the byte PREFIX, in key order --
Core's cursor Seek to the prefix, stopping at the first key of another kind.
Signals if the scan stopped on an error rather than at the end."
  (with-leveldb-iterator (it (block-tree-db-handle db) :verify-checksums verify-checksums)
    (leveldb-iter-seek it (vector-of-octet prefix))
    (loop while (leveldb-iter-valid-p it)
          do (let ((key (leveldb-iter-key it)))
               (unless (and (= (length key) key-length) (= (aref key 0) prefix))
                 (return))
               (funcall fn key (%db-value db (leveldb-iter-value it))))
             (leveldb-iter-next it))
    (leveldb-iter-check-error it)))

(defun %seed-file-info-written (db)
  "Remember the 'f' records DB already holds, so the first flush rewrites only
the ones that changed and zeroes the ones for files pruned since."
  (%map-prefix-records db +db-block-files+ 5
                       (lambda (key value)
                         (setf (gethash (%int32-le-value key 1)
                                        (block-tree-db-file-info-written db))
                               value))))

(defun open-block-tree-db (base-path)
  "Open BASE-PATH's block tree database for the life of the node and register
it, or return the one already open. Signals when LevelDB cannot open it --
Core's `Error opening block database' (init.cpp:1353-1358)."
  (let ((key (%base-path-key base-path)))
    (or (gethash key *block-tree-dbs*)
        (setf (gethash key *block-tree-dbs*)
              (%open-block-tree-handle base-path)))))

(defun close-block-tree-db (base-path)
  "Close BASE-PATH's registered block tree database, if one is open."
  (let* ((key (%base-path-key base-path))
         (db (gethash key *block-tree-dbs*)))
    (when db
      (remhash key *block-tree-dbs*)
      (bt:with-lock-held ((block-tree-db-lock db))
        (leveldb-close (block-tree-db-handle db))
        (setf (block-tree-db-handle db) nil)))
    t))

(defun call-with-block-tree-db (base-path fn)
  "Call FN with BASE-PATH's block tree database, holding its lock: the
registered one when the node has it open, else one opened for this call only."
  (let ((db (gethash (%base-path-key base-path) *block-tree-dbs*)))
    (if db
        (bt:with-lock-held ((block-tree-db-lock db)) (funcall fn db))
        (let ((db (%open-block-tree-handle base-path)))
          (unwind-protect (funcall fn db)
            (leveldb-close (block-tree-db-handle db)))))))

(defmacro with-block-tree-db ((var base-path) &body body)
  "Run BODY with VAR bound to BASE-PATH's block tree database; see
CALL-WITH-BLOCK-TREE-DB."
  `(call-with-block-tree-db ,base-path (lambda (,var) ,@body)))

(defun %db-value (db bytes)
  "BYTES as stored, or as read back: XORed with the database's key, if any."
  (let ((key (block-tree-db-obfuscation db)))
    (if key (obfuscate! (copy-seq bytes) key) bytes)))

(defun %db-get (db key)
  (let ((v (leveldb-get (block-tree-db-handle db) key)))
    (and v (%db-value db v))))

(defun %db-put (db key value &key sync)
  (leveldb-put (block-tree-db-handle db) key (%db-value db value) :sync sync))

;;; Flags (node/blockstorage.cpp:73-118)

(defun forget-pruned-block-files (base-path)
  "Erase the prunedblockfiles flag -- the state Core's -reindex leaves, since it
wipes the whole block tree database (init.cpp:1344)."
  (with-block-tree-db (db base-path)
    (leveldb-delete (block-tree-db-handle db) (%db-flag-key "prunedblockfiles") :sync t)
    (setf (block-tree-db-pruned-flag-written db) nil))
  t)

(defun vector-of-octet (octet)
  "A one-byte octet vector holding OCTET."
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element octet))

(defun read-block-tree-flag (base-path name)
  "Core BlockTreeDB::ReadFlag: (values VALUE PRESENT-P)."
  (with-block-tree-db (db base-path)
    (let ((v (%db-get db (%db-flag-key name))))
      (values (and v (plusp (length v)) (= (aref v 0) (char-code #\1)))
              (and v t)))))

(defun write-reindex-flag (data-dir on)
  "Core BlockTreeDB::WriteReindexing (node/blockstorage.cpp:73-80): record in
DATA-DIR's block tree database that a reindex is under way when ON, erase the
record when ON is NIL. Returns ON.

Written before the first block file is read and erased only after the last one,
so a record found at start-up means exactly `a reindex began here and did not
finish'. Written synchronously: a marker the crash it exists for can lose is no
marker. The marker FILE blocks/index/reindex that preceded this record is
removed by the same call, so an erase clears both."
  (with-block-tree-db (db data-dir)
    (if on
        (%db-put db *reindex-flag-key* (vector-of-octet (char-code #\1)) :sync t)
        (leveldb-delete (block-tree-db-handle db) *reindex-flag-key* :sync t)))
  (unless on
    (let ((legacy (%legacy-reindex-marker-path data-dir)))
      (when (probe-file legacy) (delete-file legacy))))
  on)

(defun %legacy-reindex-marker-path (data-dir)
  "The file that recorded an unfinished reindex before the record moved into
the block tree database: blocks/index/reindex."
  (merge-pathnames "reindex" (datadir-block-index-path data-dir)))

(defun reindex-flag-set-p (data-dir)
  "Core BlockTreeDB::ReadReindexing (node/blockstorage.cpp:82-85): T when an
unfinished reindex is recorded for DATA-DIR -- the 'R' record, or the marker
file an earlier build wrote in its place."
  (or (and (probe-file (%legacy-reindex-marker-path data-dir)) t)
      (with-block-tree-db (db data-dir)
        (and (%db-get db *reindex-flag-key*) t))))

;;; Writing (Core BlockTreeDB::WriteBatchSync, node/blockstorage.cpp:92-103)

(defun %entry-persist-key (entry)
  "The MUTABLE state of ENTRY packed into one 64-bit integer, or 0 for an entry
that has never been written.

This is the change detector behind the incremental write: a flush writes the
'b' record of every entry whose key moved since it was last written, and only
those (Core keeps the same set as m_dirty_blockindex, filled at each mutation
site). It is deliberately derived from the entry's CURRENT state rather than
announced by whoever mutated it. Marking entries dirty at each of the ~15 setf
sites would be miss-prone in the worst direction: a missed status mark means a
block marked :invalid quietly reverts to :valid on the next restart.

hash and chain-work never change after creation, and neither is stored.
header and prev-entry are set-once (NIL -> object), which the two presence bits
catch; the one place an existing header is REPLACED is the genesis fix-up at
startup, which forces a full write rather than relying on this key."
  (logior 1
          (ash (ecase (block-index-entry-status entry)
                 (:unknown 0) (:header-valid 1) (:valid 2) (:invalid 3))
               1)
          (ash (if (block-index-entry-header entry) 1 0) 3)
          (ash (if (block-index-entry-prev-entry entry) 1 0) 4)
          ;; Height and tx-count are each clamped to 27 bits — ~134M, which is
          ;; 2500 years of blocks and more transactions than a block can hold.
          ;; The clamps also keep a corrupt value from overflowing into a
          ;; neighbouring field, and they keep the whole key inside a fixnum,
          ;; which matters because a flush computes it for EVERY entry (963k on
          ;; mainnet) to find the few that changed.
          (ash (min (block-index-entry-height entry) #x7FFFFFF) 5)
          (ash (min (block-index-entry-tx-count entry) #x7FFFFFF) 32)
          ;; The flat-file position is recorded by PRESENCE, not by value.
          ;; A position is written once, when the block's body or undo record
          ;; lands, and cleared once, when it is pruned; it is never moved
          ;; within a file. So the two transitions that exist are exactly the
          ;; ones a presence bit catches, and the value itself travels in the
          ;; record that this key schedules.
          (ash (if (block-index-entry-data-pos entry) 1 0) 59)
          (ash (if (block-index-entry-undo-pos entry) 1 0) 60)
          ;; BLOCK_OPT_WITNESS is set once, when the body arrives.
          (ash (if (logtest (block-index-entry-status-flags entry)
                            +block-opt-witness+)
                   1 0)
               61)))

(defun %changed-header-index-entries (state)
  "Entries whose persisted packing no longer matches their current one."
  (let ((changed '()))
    (maphash (lambda (hash entry)
               (declare (ignore hash))
               (unless (= (block-index-entry-persisted-key entry)
                          (%entry-persist-key entry))
                 (push entry changed)))
             (chain-state-block-index state))
    changed))

(defun %store-file-sizes (block-store)
  "BLOCK-STORE's file number -> BLOCK-FILE-INFO table and the used size of the
file it is appending to, as (values TABLE CURSOR-FILE CURSOR-POS), or NIL."
  (when block-store
    (values (block-store-file-info block-store)
            (block-store-cursor-file block-store)
            (block-store-cursor-pos block-store))))

(defun %batch-file-info (db batch block-store)
  "Add to BATCH the 'f' record of every file whose value changed since it was
last written, and the 'l' record. Returns an alist (file . value) of what was
added, to be remembered once the batch has committed."
  (let ((written '()))
    (multiple-value-bind (table cursor-file cursor-pos) (%store-file-sizes block-store)
      (when table
        (let ((last-file (block-tree-db-last-file-written db)))
          (flet ((put (file value)
                   (unless (equalp value (gethash file (block-tree-db-file-info-written db)))
                     (leveldb-writebatch-put batch (block-file-info-record-key file)
                                             (%db-value db value))
                     (push (cons file value) written))))
            (maphash (lambda (file info)
                       (put file (encode-block-file-info
                                  info :size (when (eql file cursor-file) cursor-pos))))
                     table)
            ;; A file the store no longer accounts for was pruned: Core resets
            ;; its record to an empty CBlockFileInfo (PruneOneBlockFile,
            ;; node/blockstorage.cpp:258-276), which is what a Core node reading
            ;; this database must find rather than the counts it held.
            (loop for file being the hash-keys of (block-tree-db-file-info-written db)
                  unless (gethash file table)
                    do (put file (encode-block-file-info (make-block-file-info)))))
          ;; Core writes nLastFile with every batch (MaxBlockfileNum).
          (let ((max-file (max cursor-file
                               (loop for f being the hash-keys of table maximize f))))
            (unless (eql max-file last-file)
              (leveldb-writebatch-put batch *last-block-file-key*
                                      (%db-value db (%int32-le-bytes max-file)))
              (push (cons :last max-file) written))))))
    written))

(defun %commit-file-info (db written)
  (dolist (w written)
    (if (eq (car w) :last)
        (setf (block-tree-db-last-file-written db) (cdr w))
        (setf (gethash (car w) (block-tree-db-file-info-written db)) (cdr w)))))

(defun %write-block-index-batch (db entries &key block-store pruned (sync t))
  "One atomic LevelDB write: the changed 'f' records and 'l' (from BLOCK-STORE,
when given), the 'b' record of each of ENTRIES, and the prunedblockfiles flag
the first time PRUNED is true. Marks each written entry persisted once the
batch commits. An entry with no header cannot be written -- its key is its
header's hash -- and is skipped. Returns the number of 'b' records written."
  (let ((count 0) (written-entries '()) (file-info '()))
    (with-leveldb-writebatch (batch)
      (setf file-info (%batch-file-info db batch block-store))
      (when (and pruned (not (block-tree-db-pruned-flag-written db)))
        (leveldb-writebatch-put batch (%db-flag-key "prunedblockfiles")
                                (%db-value db (vector-of-octet (char-code #\1)))))
      (dolist (e entries)
        (when (block-index-entry-header e)
          (leveldb-writebatch-put batch (block-index-record-key
                                         (block-index-entry-hash e))
                                  (%db-value db (encode-disk-block-index e)))
          (push e written-entries)
          (incf count)))
      (leveldb-write (block-tree-db-handle db) batch :sync sync))
    (%commit-file-info db file-info)
    (when pruned (setf (block-tree-db-pruned-flag-written db) t))
    (dolist (e written-entries)
      (setf (block-index-entry-persisted-key e) (%entry-persist-key e)))
    count))

(defun save-header-index (state &key force-full block-store)
  "Persist the block index to the block tree database -- Core
BlockManager::WriteBlockIndexDB (node/blockstorage.cpp:510-527): the 'b' record
of every entry that changed since it was last written, the 'f' record of every
block file whose accounting changed and 'l', in ONE synchronous batch.
FORCE-FULL writes every entry (after a mutation the change detector cannot
see). BLOCK-STORE supplies the file accounting; without it only 'b' records are
written.

One atomic batch is the whole crash-safety story that the former snapshot +
delta pair had to build by hand: LevelDB's log makes the batch all-or-nothing,
and the flush order around this call -- block and undo files first, the coins
after (validation.cpp:2780-2812) -- is %FLUSH-CHAINSTATE's."
  (with-block-tree-db (db (chain-state-base-path state))
    (let ((entries (if force-full
                       (loop for e being the hash-values of (chain-state-block-index state)
                             collect e)
                       (%changed-header-index-entries state))))
      (%write-block-index-batch db entries
                                :block-store block-store
                                ;; Core sets m_have_pruned only when prune mode
                                ;; deletes a file; an unpruned node with a
                                ;; leftover horizon must not record it.
                                :pruned (and (pruning-enabled-p)
                                             (plusp (chain-state-pruned-height state))))
      t)))

;;; Reading (Core LoadBlockIndexGuts + LoadBlockIndex, node/blockstorage.cpp:120-162, 423-508)

(defun %header-meets-its-target-p (header)
  "Core CheckProofOfWork (pow.cpp:161-171) over a stored header: nBits decodes
to an in-range target and the hash does not exceed it."
  (let ((target (derive-target (bl.ser:block-header-bits header))))
    (and target
         (<= (loop with hash = (bl.ser:block-header-hash header)
                   for i from 0 below 32
                   sum (ash (aref hash i) (* 8 i)))
             target))))

(defun %read-block-index-records (db)
  "Every 'b' record of DB, decoded: a list of (ENTRY PREV-HASH NSTATUS).
Iterates with checksums verified, as Core's CDBWrapper does, and signals on an
undecodable record or a scan that stopped on an error."
  (let ((records '()))
    (%map-prefix-records db +db-block-index+ 33
                         (lambda (key value)
                           (declare (ignore key))
                           (push (multiple-value-list (decode-disk-block-index value))
                                 records))
                         :verify-checksums t)
    records))

(defun %link-and-weigh (records)
  "Core LoadBlockIndex's pass over the loaded records, sorted by height: link
each to its parent, sum chain work, read BLOCK_FAILED_CHILD as
BLOCK_FAILED_VALID and mark every descendant of a failed block failed
(node/blockstorage.cpp:452-505). Returns (values TABLE REASON), REASON a string
when the index is unusable: a header that fails its own proof of work, or a
height with no entry below one that has."
  (let ((table (make-hash-table :test 'equalp :size (max 16 (length records))))
        (prevs (make-hash-table :test 'equalp :size (max 16 (length records)))))
    (dolist (r records)
      (destructuring-bind (entry prev-hash nstatus) r
        (declare (ignore nstatus))
        (unless (%header-meets-its-target-p (block-index-entry-header entry))
          (return-from %link-and-weigh
            (values nil (format nil "CheckProofOfWork failed: ~A"
                                (bl.crypto:bytes-to-hex
                                 (bl.crypto:reverse-bytes
                                  (block-index-entry-hash entry)))))))
        (setf (gethash (block-index-entry-hash entry) table) entry)
        (unless (every #'zerop prev-hash)
          (setf (gethash (block-index-entry-hash entry) prevs) prev-hash))))
    (let ((sorted (sort (map 'vector #'first records) #'<
                        :key #'block-index-entry-height))
          (previous nil))
      (loop for entry across sorted
            do (when (and previous
                          (> (block-index-entry-height entry)
                             (1+ (block-index-entry-height previous))))
                 (return-from %link-and-weigh
                   (values nil (format nil "block index is non-contiguous, index of height ~D missing"
                                       (1+ (block-index-entry-height previous))))))
               (setf previous entry)
               (let* ((prev-hash (gethash (block-index-entry-hash entry) prevs))
                      (parent (and prev-hash (gethash prev-hash table))))
                 (setf (block-index-entry-prev-entry entry) parent
                       (block-index-entry-chain-work entry)
                       (calculate-chain-work
                        (bl.ser:block-header-bits (block-index-entry-header entry))
                        (if parent (block-index-entry-chain-work parent) 0)))
                 (setf (block-index-entry-persisted-key entry)
                       (%entry-persist-key entry))
                 (when (and parent
                            (eq (block-index-entry-status parent) :invalid)
                            (not (eq (block-index-entry-status entry) :invalid)))
                   ;; All descendants of invalid blocks are invalid too, and
                   ;; the change is written back at the next flush.
                   (mark-entry-failed entry)))))
    (dolist (r records)
      ;; A deprecated FAILED_CHILD is rewritten as FAILED_VALID (:483-487).
      (when (logtest (third r) +block-failed-child+)
        (setf (block-index-entry-persisted-key (first r)) 0)))
    (values table nil)))

(defun load-header-index (state)
  "Load the block index from STATE's block tree database -- Core
LoadBlockIndexGuts + LoadBlockIndex.

Returns (values T NIL) when records were loaded, (values NIL NIL) when there are
none (a first run), and (values NIL REASON) when the database holds records
that cannot be trusted: one that does not decode, a scan stopped by
corruption, a header failing its proof of work, or a hole in the heights. The
caller MUST refuse to start on the third case, as Core refuses with `Error
loading block database' (node/chainstate.cpp:42-45): an empty index under a
chainstate that names a tip leaves the node claiming a height it holds no
headers for."
  (multiple-value-bind (records error)
      (handler-case
          (with-block-tree-db (db (chain-state-base-path state))
            (%read-block-index-records db))
        (error (e) (values nil (format nil "~A" e))))
    (cond
      (error (values nil error))
      ((null records) (values nil nil))
      (t
       (multiple-value-bind (table reason) (%link-and-weigh records)
         (if reason
             (values nil reason)
             (progn
               (setf (chain-state-block-index state) table)
               (values t nil))))))))

(defun read-block-tree-file-info (base-path)
  "Core LoadBlockIndexDB's file-info read (node/blockstorage.cpp:535-552): the
'l' record and every 'f' record from 0 up, as (values LAST-FILE TABLE)."
  (with-block-tree-db (db base-path)
    (let* ((l (%db-get db *last-block-file-key*))
           (last-file (if l (%int32-le-value l) 0))
           (table (make-hash-table :test 'eql)))
      (loop for file from 0
            for v = (%db-get db (block-file-info-record-key file))
            while (or v (<= file last-file))
            when v do (setf (gethash file table) (decode-block-file-info v)))
      (values last-file table))))

(defun data-files-missing (state blocks-exist-p)
  "Core LoadBlockIndexDB's `Checking all blk files are present'
(node/blockstorage.cpp:555-568): the sorted numbers of the blk files that some
entry with data points into and that BLOCKS-EXIST-P, a predicate on a file
number, says are absent."
  (let ((files (make-hash-table :test 'eql)))
    (maphash (lambda (hash entry)
               (declare (ignore hash))
               (when (block-index-entry-data-pos entry)
                 (setf (gethash (or (block-index-entry-file entry) 0) files) t)))
             (chain-state-block-index state))
    (sort (loop for f being the hash-keys of files
                unless (funcall blocks-exist-p f) collect f)
          #'<)))

;;; Migration from headerindex.dat / headerindex.delta

(defconstant +migration-batch-entries+ 50000
  "Records per LevelDB batch when converting a former header index: large
enough that a 900k-entry index is eighteen writes, small enough that no single
batch holds more than a few MB.")

(defun %count-block-index-records (db)
  "The number of 'b' records in DB."
  (let ((n 0))
    (%map-prefix-records db +db-block-index+ 33
                         (lambda (key value) (declare (ignore key value)) (incf n)))
    n))

(defun %rename-migrated (path)
  "Rename PATH to PATH.migrated, keeping the name's own dots (a pathname TYPE
would escape an inner dot)."
  (when (probe-file path)
    (let ((to (concatenate 'string (namestring path) ".migrated")))
      (rename-path path (pathname to))
      (fsync-parent-directory to))))

(defun migrate-legacy-header-index (state &key block-store)
  "Convert a datadir that still holds the former headerindex.dat (and
headerindex.delta) into Core's block tree database, in place. Returns the number
of entries migrated, NIL when there is nothing to migrate, and signals
STORAGE-ERROR when the former index is unreadable or the count written does not
match the count read.

Every entry is written, in batches of +MIGRATION-BATCH-ENTRIES+, whatever the
database already holds: a migration interrupted part-way leaves the old files in
place, so the next start simply runs it again over the same records. Only once
the database's record count has been read back and matched are the old files
renamed to *.migrated -- kept, not deleted, so a downgrade has something to go
back to.

Entries get BLOCK_OPT_WITNESS here, which the former format never recorded:
every body this node stored, and every block it connected, was fetched and
validated with witness data wherever segwit applied, which is exactly what the
flag attests. Without it the migrated chain would trip NeedsRedownload on the
first start."
  (let ((legacy (datadir-header-index-file (chain-state-base-path state))))
    (unless (probe-file legacy)
      (return-from migrate-legacy-header-index nil))
    (let ((scratch (make-chain-state :base-path (chain-state-base-path state)))
          (started (get-internal-real-time)))
      (bl.log:log-info "Migrating the block index from ~A into the block tree database at ~A..."
                       (namestring legacy)
                       (namestring (block-tree-db-path (chain-state-base-path state))))
      (multiple-value-bind (ok reason) (load-legacy-header-index scratch)
        (unless ok
          (storage-error "Cannot migrate the block index: ~A is unreadable (~A)"
                         (namestring legacy) (or reason "no entries"))))
      (let* ((entries (loop for e being the hash-values of (chain-state-block-index scratch)
                            when (block-index-entry-header e) collect e))
             (total (length entries)))
        (dolist (e entries)
          (when (or (eq (block-index-entry-status e) :valid)
                    (block-index-entry-data-pos e)
                    (and block-store (block-exists-p block-store (block-index-entry-hash e))))
            (note-block-witness-received e)))
        (with-block-tree-db (db (chain-state-base-path state))
          (loop for n from 0
                while entries
                do (let ((batch (loop repeat +migration-batch-entries+
                                      while entries collect (pop entries))))
                     (%write-block-index-batch db batch :sync (null entries))
                     (bl.log:log-info "Migrating the block index: ~D of ~D entries written"
                                      (min total (* (1+ n) +migration-batch-entries+))
                                      total)))
          (let ((found (%count-block-index-records db)))
            (unless (>= found total)
              (storage-error "Block index migration wrote ~D entries but reads back ~D; ~A is left in place"
                             total found (namestring legacy)))))
        (%rename-migrated legacy)
        (%rename-migrated (legacy-header-index-delta-path scratch))
        (bl.log:log-info "Migrated ~D block index entries to the block tree database in ~,1Fs"
                         total
                         (/ (- (get-internal-real-time) started)
                            internal-time-units-per-second))
        total))))
