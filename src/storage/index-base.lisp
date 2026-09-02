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
  "ASCII B: the best-block marker's LevelDB key. One byte, so it can never be
mistaken for a record key, all of which start with a different prefix byte.")

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
  (cache-share :filter-index :type (member :filter-index :tx-index)))

;;; --- The skeleton: open, close, key layout, the 36-byte marker ---

(defun open-index-db (index path)
  "Open (creating if needed) INDEX's LevelDB at PATH with its cache share,
when the index is enabled; a disabled index keeps no handle."
  (when (base-index-enabled index)
    (ensure-directories-exist path)
    (setf (base-index-db index)
          (leveldb-open-tuned
           path :cache-bytes (if *cache-sizes*
                                 (ecase (base-index-cache-share index)
                                   (:filter-index (cache-sizes-filter-index *cache-sizes*))
                                   (:tx-index (cache-sizes-tx-index *cache-sizes*)))
                                 0))))
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

(defun index-meta-encode (height hash)
  "The best-block marker's value: HEIGHT as 4 little-endian bytes, then the
32-byte HASH (the blockfilterindex and coinstatsindex layout)."
  (let ((v (make-array 36 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref v i) (logand (ash height (* -8 i)) #xff)))
    (replace v hash :start1 4)
    v))

(defun index-meta-decode (v)
  "(values height hash) from a marker value written by INDEX-META-ENCODE."
  (values (loop for i below 4 sum (ash (aref v i) (* 8 i)))
          (subseq v 4 36)))

(defgeneric index-name (index)
  (:documentation "The index's name as Core spells it: \"txindex\", ..."))

(defgeneric index-height (index chainstate)
  (:documentation "The highest height INDEX has indexed contiguously from
genesis, or -1. CHAINSTATE lets an index whose marker is a hash only (the
txindex, like Core's locator) resolve it against the active chain."))

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

;;; --- Default marker methods (the height||hash layout) ---
;;; The txindex (hash-only marker) and the txospenderindex (hash||height)
;;; keep their own; the blockfilterindex and coinstatsindex use these.

(defmethod index-best-block ((index base-index))
  (let ((db (base-index-db index)))
    (when db
      (let ((v (leveldb-get db (base-index-meta-key index))))
        (when (and v (>= (length v) 36))
          (multiple-value-bind (height hash) (index-meta-decode v)
            (values hash height)))))))

(defmethod index-set-best ((index base-index) block-hash height)
  (when (base-index-db index)
    (leveldb-put (base-index-db index) (base-index-meta-key index)
                 (index-meta-encode height block-hash))))

(defmethod index-clear-best ((index base-index))
  (when (base-index-db index)
    (leveldb-delete (base-index-db index) (base-index-meta-key index))))
