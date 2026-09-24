(in-package #:bitcoin-lisp.storage)

;;;; base-index (Core index/base.h BaseIndex)
;;;
;;; Four indexes -- txindex, txospenderindex, blockfilterindex, coinstatsindex
;;; -- each keep a LevelDB, a best-block marker, a connect-time write, a
;;; disconnect-time erase and a startup catch-up, and until this file each
;;; re-implemented that skeleton, with a third and fourth copy of the
;;; catch-up living in node/indexes.lisp. BASE-INDEX is the shared state and the
;;; generic functions below are the protocol the node drives them through:
;;; one catch-up driver, one connect hook, one disconnect hook, whatever the
;;; number of indexes. Adding an index is its file plus its methods.
;;;
;;; What differs per index (key layouts, meta encodings, what a block
;;; contributes) stays in the index's own file, as its methods.

(defparameter *index-meta-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element (char-code #\B))
  "ASCII B, Core's DB_BEST_BLOCK (index/base.cpp:47): the best-block record's
key. One byte, so it can never be mistaken for a record key, all of which
start with a different prefix byte.")

(defstruct (base-index (:constructor nil) (:copier nil) (:predicate nil))
  "What every index shares: where its LevelDB lives, the open handle (NIL
until INIT-* opens it, and for a disabled index), whether it is on, and the
one-byte key of its best-block marker. Never instantiated directly; the
indexes :INCLUDE it."
  (base-path nil :type (or null pathname))
  (db nil)
  (enabled nil :type boolean)
  ;; The marker record's key (ASCII B in every index), and which share of the
  ;; -dbcache budget the DB gets: Core divides one budget across the indexes
  ;; (node/caches.cpp:66-70); the txindex has its own line.
  (meta-key *index-meta-key* :type (simple-array (unsigned-byte 8) (1)))
  (cache-share :filter-index :type (member :filter-index :tx-index))
  ;; Core's m_best_block_index: the block the index has processed, held in
  ;; memory and moved per block (SetBestBlockIndex, index/base.cpp:487-504).
  ;; (HASH . HEIGHT), HEIGHT -1 until RESOLVE-INDEX-BEST places a record read
  ;; from disk on the chain. Only COMMIT-INDEX writes it to the database.
  (best-entry nil :type (or null cons)))

;;; --- The skeleton: open, close, key layout ---

(defun open-index-db (index path &key wipe)
  "Open (creating if needed) INDEX's LevelDB at PATH with its cache share,
when the index is enabled; a disabled index keeps no handle.

WIPE destroys whatever is at PATH first, so the index opens with no records and
no best-block marker and its catch-up rebuilds it from genesis. That is Core's
DBParams::wipe_data, which every index takes from init.cpp's do_reindex
(init.cpp:1905/1909/1915/1920 -> index/base.cpp:68-73): a wiped DB reads a null
DB_BEST_BLOCK, so BaseIndex::Init starts the index from nothing (:119-133).
Wipe-and-resync, not catch-up -- the point being that a block index rebuilt
from the block files must not be described by rows derived from the old one."
  (when (base-index-enabled index)
    (when wipe
      (leveldb-destroy-db path))
    (ensure-directories-exist path)
    (let ((db (leveldb-open-tuned
               path :cache-bytes (if *cache-sizes*
                                     (ecase (base-index-cache-share index)
                                       (:filter-index (cache-sizes-filter-index *cache-sizes*))
                                       (:tx-index (cache-sizes-tx-index *cache-sizes*)))
                                     0))))
      ;; Core BaseIndex::Init's first read, GetDB().ReadBestBlock()
      ;; (index/base.cpp:119), checksums verified as every CDBWrapper read is
      ;; (dbwrapper.cpp:221): a damaged table under the marker is
      ;; HandleError's dbwrapper_error and start-up fails with LevelDB's
      ;; Corruption sentence (feature_init.py:170-189 damages each index's
      ;; files and expects exactly that). Unverified, our later reads of the
      ;; same record decoded the damaged block and the node came up.
      (let ((record (handler-bind ((error (lambda (e)
                                            (declare (ignore e))
                                            (leveldb-close db))))
                      (leveldb-get db (base-index-meta-key index)
                                   :verify-checksums t))))
        (setf (base-index-db index) db
              (base-index-best-entry index)
              (and record
                   (multiple-value-bind (hash height)
                       (decode-index-best-block-record index record)
                     (and hash (cons hash (or height -1)))))))))
  index)

(defun close-index (index)
  "Close INDEX's LevelDB handle, if open."
  (when (base-index-db index)
    (leveldb-close (base-index-db index))
    (setf (base-index-db index) nil)))

(defun index-key (prefix &rest parts)
  "A record key: the PREFIX byte followed by PARTS, each an octet vector."
  (let* ((n (reduce #'+ parts :key #'length :initial-value 1))
         (key (make-array n :element-type '(unsigned-byte 8)))
         (pos 1))
    (setf (aref key 0) prefix)
    (dolist (part parts key)
      (replace key part :start1 pos)
      (incf pos (length part)))))

(defun index-meta-decode (v)
  "(values height hash) from an old height LE32 || hash best-block record."
  (values (loop for i below 4 sum (ash (aref v i) (* 8 i)))
          (subseq v 4 36)))

(defgeneric index-name (index)
  (:documentation "The index's name as Core spells it: \"txindex\", ..."))

(defgeneric index-height (index chainstate)
  (:documentation "The highest height INDEX has indexed contiguously from
genesis, or -1. CHAINSTATE lets an index whose marker is a hash, or a
(hash, height) pair whose height only means something while the hash is on
the active chain, resolve it there -- the txindex, the spender index and the
filter index all do, where Core reads a locator (BaseIndex::Init)."))

(defgeneric index-best-block (index)
  (:documentation "(values block-hash height) of the highest indexed block,
or NIL when nothing has been indexed."))

(defgeneric index-set-best (index block-hash height)
  (:documentation "Record BLOCK-HASH/HEIGHT as the highest indexed block
(Core BaseIndex's locator)."))

(defgeneric index-clear-best (index)
  (:documentation "Forget the best-block marker, so the next catch-up
rebuilds from genesis."))

(defgeneric index-write-block (index chainstate block block-hash height spent-utxos)
  (:documentation "Fold BLOCK, connected at HEIGHT with SPENT-UTXOS as its
undo list, into the index (Core CustomAppend). Returns (values result status);
a STATUS of :noncontiguous means the index refused a block above a gap and
waits for the startup catch-up. May signal; the node's hook catches."))

(defgeneric index-rewind-block (index chainstate block block-hash height)
  (:documentation "Erase what INDEX-WRITE-BLOCK wrote for BLOCK, on
disconnect (Core CustomRemove). Default: nothing, for indexes keyed by height
whose records the next connect overwrites.")
  (:method ((index base-index) chainstate block block-hash height)
    (declare (ignore chainstate block block-hash height))
    nil))

(defgeneric index-prepare-sync (index chainstate block-store)
  (:documentation "Make the best marker trustworthy before a catch-up builds
on it: repair one left above the tip, rewind one off the active chain
(Core BaseIndex::Rewind / the CustomInit checks). Default: nothing.")
  (:method ((index base-index) chainstate block-store)
    (declare (ignore chainstate block-store))
    nil))

(defgeneric index-sync (index chainstate block-store &key undo-fn subsidy-fn progress)
  (:documentation "Backfill from just past the best marker to CHAINSTATE's tip
(Core BaseIndex::Sync). UNDO-FN maps a block hash to its undo data and
SUBSIDY-FN a height to its subsidy, for the indexes that need them; PROGRESS
is called with (height percent). Returns how many blocks (or entries) were
added."))

;;; --- The best-block record: Core's CBlockLocator (DB_BEST_BLOCK) ---
;;;
;;; Core keeps ONE record per index under DB_BEST_BLOCK ('B'): a serialized
;;; CBlockLocator (index/base.cpp:78-93) -- an int32 version, the DUMMY_VERSION
;;; 70016 that is never read, then a CompactSize count and that many 32-byte
;;; hashes, the index's best block first (primitives/block.h:116-138). Commit
;;; alone writes it (base.cpp:270-288), from Sync when the index catches up and
;;; from ChainStateFlushed after every full chainstate flush (:380-422): never
;;; per block, so the record only ever names a block the block index has
;;; already made durable. Between commits the index's position lives in
;;; memory (the BEST-ENTRY slot, Core's m_best_block_index).
;;;
;;; This tree wrote its own layouts per block before: 32 bytes (txindex, the
;;; hash), 36 bytes (blockfilterindex and coinstatsindex, height LE32 || hash;
;;; txospenderindex, hash || height LE32). None can be mistaken for a locator,
;;; which is 4 + CompactSize + 32n bytes, never 32 or 36. INDEX-DECODE-LEGACY-
;;; BEST reads them once; the next commit writes the locator.

(defconstant +locator-dummy-version+ 70016
  "CBlockLocator::DUMMY_VERSION (primitives/block.h:125).")

(defun encode-block-locator (hashes)
  "HASHES (internal byte order, best first) serialized as Core's CBlockLocator."
  (let ((bb (bl.bytes:make-byte-buf)))
    (bl.bytes:bb-write-u32-le bb +locator-dummy-version+)
    (bl.bytes:bb-write-varint bb (length hashes))
    (dolist (h hashes) (bl.bytes:bb-write-bytes bb h))
    (bl.bytes:bb-finish bb)))

(defun %decode-block-locator (bytes)
  "The hashes of a serialized CBlockLocator, or NIL when BYTES is not one."
  (ignore-errors
   (bl.bytes:with-byte-reader (br bytes)
     (when (= (bl.bytes:br-read-u32-le br) +locator-dummy-version+)
       (let* ((n (bl.bytes:br-read-compact-size br))
              (hashes (loop repeat n collect (bl.bytes:br-read-bytes br 32))))
         (when (and hashes (bl.bytes:br-eof-p br))
           hashes))))))

(defgeneric index-decode-legacy-best (index bytes)
  (:documentation "(values hash height) from a best-block record this tree
wrote before it wrote Core's locator, or NIL. Default: height LE32 || hash, the
blockfilterindex and coinstatsindex layout.")
  (:method ((index base-index) bytes)
    (when (= (length bytes) 36)
      (multiple-value-bind (height hash) (index-meta-decode bytes)
        (values hash height)))))

(defun decode-index-best-block-record (index bytes)
  "(values hash height) from INDEX's DB_BEST_BLOCK record: a CBlockLocator's
first hash (HEIGHT NIL, a locator carries none), or an old layout's."
  (let ((hashes (%decode-block-locator bytes)))
    (if hashes
        (values (first hashes) nil)
        (index-decode-legacy-best index bytes))))

(defmethod index-best-block ((index base-index))
  (let ((best (base-index-best-entry index)))
    (when best (values (car best) (cdr best)))))

(defmethod index-set-best ((index base-index) block-hash height)
  "Core SetBestBlockIndex: memory only. COMMIT-INDEX persists it."
  (setf (base-index-best-entry index) (cons (copy-seq block-hash) height)))

(defmethod index-clear-best ((index base-index))
  "Forget the position in memory and on disk, so the next catch-up rebuilds
from genesis (Core's wiped database reads a null DB_BEST_BLOCK)."
  (setf (base-index-best-entry index) nil)
  (when (base-index-db index)
    (leveldb-delete (base-index-db index) (base-index-meta-key index))))

(defgeneric resolve-index-best (index chainstate)
  (:documentation "Place INDEX's best block on CHAINSTATE's block index, as
BaseIndex::Init does with the locator's first hash (index/base.cpp:124-134):
its entry, with the entry's height recorded in the BEST-ENTRY slot; :NOT-FOUND
when the block index does not hold it; NIL when the index has no best block.")
  (:method ((index base-index) chainstate)
    (let ((best (base-index-best-entry index)))
      (when best
        (let ((entry (get-block-index-entry chainstate (car best))))
          (cond
            (entry (setf (cdr best) (block-index-entry-height entry)) entry)
            (t :not-found)))))))

(defun commit-index (index &optional chainstate)
  "Core BaseIndex::Commit (index/base.cpp:270-288): write the in-memory best
block to the index's database as a CBlockLocator -- GetLocator over
CHAINSTATE's block index, byte for byte Core's -- and nothing when the index
has processed no block yet. Without CHAINSTATE, or with a best block it does
not hold, the locator is that one hash, which ReadBestBlock (vHave.at(0))
reads the same way. Returns T when a record was written."
  (let ((best (base-index-best-entry index))
        (db (base-index-db index)))
    (when (and best db)
      (let ((entry (and chainstate
                        (get-block-index-entry chainstate (car best)))))
        (leveldb-put db (base-index-meta-key index)
                     (encode-block-locator
                      (if entry
                          (build-block-locator chainstate entry)
                          (list (car best)))))
        t))))
