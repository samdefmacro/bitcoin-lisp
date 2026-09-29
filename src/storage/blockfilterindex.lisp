(in-package #:bitcoin-lisp.storage)

;;;; BIP157/158 block filter index (Core index/blockfilterindex.cpp)
;;;;
;;;; Stores one basic (type 0x00) GCS filter per block plus the BIP157 filter
;;;; header chain, so getblockfilter / scanblocks / getdescriptoractivity and
;;;; the cfilters P2P messages can serve light clients. Filters are built at
;;;; block-connect time from the undo data (the scriptPubKeys the block
;;;; spends).
;;;;
;;;; Core's layout, to the byte (blockfilterindex.cpp:38-68, db_key.h):
;;;;
;;;;   indexes/blockfilter/basic/db/   LevelDB
;;;;     't' || height u32 BE  ->  block hash(32) || DBVal     (active chain)
;;;;     's' || block hash(32) ->  DBVal     (a block a reorg took off it)
;;;;     'P'                   ->  FlatFilePos of the next filter to write
;;;;     'B'                   ->  the best-block CBlockLocator
;;;;   DBVal = dSHA256(filter)(32) || filter header(32) || FlatFilePos
;;;;   indexes/blockfilter/basic/fltr?????.dat
;;;;     block hash(32) || CompactSize length || encoded filter, per block;
;;;;     16 MiB files, preallocated in 1 MiB chunks, never obfuscated.
;;;;
;;;; A height record's block moves to the hash key when another branch's
;;;; block takes the height (Core's CustomRemove copies it during the rewind;
;;;; here the write that reuses the height does, which leaves the same state),
;;;; so a reorged-out block's filter stays retrievable. 'P' is written with the
;;;; locator (CustomCommit, :128-149), so a restart after a crash resumes
;;;; writing where the committed index ended.
;;;;
;;;; Until 2026-09-29 this index kept header || filter under 'f' || block hash
;;;; and no filter files; MIGRATE-BLOCKFILTERINDEX rewrites such a database in
;;;; place.

(defconstant +bfi-key-height+ #x74 "Core DB_BLOCK_HEIGHT, 't'.")
(defconstant +bfi-key-hash+ #x73 "Core DB_BLOCK_HASH, 's'.")
(defconstant +bfi-key-old-filter+ #x66
  "'f': this tree's record before 2026-09-29, read only by the migration.")

(defparameter *bfi-filter-pos-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element (char-code #\P))
  "Core DB_FILTER_POS (blockfilterindex.cpp:52).")

(defparameter *bfi-migration-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element (char-code #\m))
  "The next height of an unfinished MIGRATE-BLOCKFILTERINDEX (ours).")

(defconstant +max-fltr-file-size+ #x1000000 "Core MAX_FLTR_FILE_SIZE, 16 MiB.")
(defconstant +fltr-file-chunk-size+ #x100000 "Core FLTR_FILE_CHUNK_SIZE, 1 MiB.")

(defstruct (blockfilterindex (:include base-index))
  "Block filter index state: the LevelDB (BASE-INDEX), the fltr?????.dat
sequence and the position the next filter goes to (Core m_next_filter_pos)."
  (fltr-seq nil)
  (next-filter-pos (make-flat-file-pos 0 0)))

(defmethod index-name ((index blockfilterindex)) "basic block filter index")
;; INDEX-HEIGHT is a method in src/node/indexes.lisp, not here: resolving the
;; marker against the active chain needs the fork walk, and that needs the
;; validation layer.
(defmethod index-write-block ((index blockfilterindex) chainstate block block-hash height spent-utxos)
  (declare (ignore chainstate))
  (blockfilterindex-add-block index block block-hash height spent-utxos))
(defmethod index-commit-records ((index blockfilterindex))
  "Core CustomCommit (blockfilterindex.cpp:128-149): the current filter file is
synced first, then 'P', the next filter position, goes beside the locator."
  (let ((pos (blockfilterindex-next-filter-pos index)))
    (when (blockfilterindex-fltr-seq index)
      (flat-file-flush (blockfilterindex-fltr-seq index) pos))
    (list (cons *bfi-filter-pos-key* (%bfi-encode-flat-pos pos)))))

(defun blockfilterindex-path (base-path)
  "Directory holding the block filter index LevelDB. Core's
indexes/blockfilter/basic/db/ (index/blockfilterindex.cpp:88), falling back to
the flat blockfilterindex/ this tree used before — see kv/datadir.lisp.

:MIGRATE moves a database this tree left one level up, in basic/ itself, down
into basic/db/ the first time such a datadir is opened; a populated index must
not be rebuilt from genesis just because the name for it changed."
  (datadir-index-path (pathname base-path) :blockfilter :migrate t))

(defun %bfi-fltr-directory (db-path)
  "Where the fltr?????.dat files go: the directory holding db/ (Core's
indexes/blockfilter/basic/), or the database's own directory in the flat
legacy layout."
  (let ((dir (pathname-directory db-path)))
    (if (equal (car (last dir)) "db")
        (make-pathname :directory (butlast dir) :defaults db-path)
        db-path)))

;;; --- encodings ---

(defun %bfi-encode-flat-pos (pos)
  "Core FlatFilePos serialization: VARINT nFile (NONNEGATIVE_SIGNED), VARINT nPos."
  (let ((bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-core-varint bb (flat-file-pos-file pos))
    (bl.ser:bb-write-core-varint bb (flat-file-pos-pos pos))
    (bl.ser:bb-finish bb)))

(defun %bfi-read-flat-pos (br)
  (let* ((file (bl.ser:br-read-core-varint br))
         (pos (bl.ser:br-read-core-varint br)))
    (make-flat-file-pos file pos)))

(defun %bfi-height-key (height)
  "Core DBHeightKey: 't' || height as 4 big-endian bytes, so keys sort by height."
  (let ((key (make-array 5 :element-type '(unsigned-byte 8))))
    (setf (aref key 0) +bfi-key-height+)
    (dotimes (i 4 key)
      (setf (aref key (- 4 i)) (ldb (byte 8 (* 8 i)) height)))))

(defun %bfi-hash-key (block-hash)
  "Core DBHashKey: 's' || block hash."
  (index-key +bfi-key-hash+ block-hash))

(defun %bfi-encode-dbval (filter-hash header pos)
  (concatenate '(simple-array (unsigned-byte 8) (*))
               filter-hash header (%bfi-encode-flat-pos pos)))

(defun %bfi-decode-dbval (bytes &optional (start 0))
  "(values filter-hash header pos) of a DBVal starting at START, or NIL."
  (ignore-errors
   (let ((br (bl.ser:make-byte-reader-from (subseq bytes (+ start 64)))))
     (values (subseq bytes start (+ start 32))
             (subseq bytes (+ start 32) (+ start 64))
             (%bfi-read-flat-pos br)))))

;;; --- open/close ---

(defun init-blockfilterindex (base-path &key (enabled t) wipe)
  "Open (creating if needed) the block filter index under BASE-PATH, with its
fltr?????.dat sequence and the next filter position Core keeps under 'P'
(CustomInit, blockfilterindex.cpp:99-125). A disabled index ignores writes and
reads and holds no DB handle.

WIPE discards the stored index first (Core's f_wipe for -reindex,
init.cpp:1915), so the caller's catch-up rebuilds it from genesis."
  (let* ((path (blockfilterindex-path base-path))
         (bfi (open-index-db (make-blockfilterindex :base-path (pathname base-path)
                                                    :enabled enabled)
                             path :wipe wipe)))
    (when (blockfilterindex-db bfi)
      (setf (blockfilterindex-fltr-seq bfi)
            (make-flat-file-seq (%bfi-fltr-directory path) "fltr" +fltr-file-chunk-size+))
      (let ((p (leveldb-get (blockfilterindex-db bfi) *bfi-filter-pos-key*)))
        (setf (blockfilterindex-next-filter-pos bfi)
              (if p
                  (%bfi-read-flat-pos (bl.ser:make-byte-reader-from p))
                  (make-flat-file-pos 0 0)))))
    bfi))

(defun close-blockfilterindex (bfi)
  "Close the index's LevelDB handle."
  (close-index bfi))

(defun %bfi-live-p (bfi)
  (and (blockfilterindex-enabled bfi) (blockfilterindex-db bfi) t))

;;; --- the filter files (Core ReadFilterFromDisk / WriteFilterToDisk) ---

(defun %bfi-write-filter (bfi block-hash filter)
  "Core WriteFilterToDisk (blockfilterindex.cpp:176-233): append block hash ||
the filter as a length-prefixed vector at the next position, rolling to the
next file (the old one truncated to its data and synced) when it would pass
16 MiB. Returns the position written at; advances the next position."
  (let* ((seq (blockfilterindex-fltr-seq bfi))
         (pos (blockfilterindex-next-filter-pos bfi))
         (bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-bytes bb block-hash)
    (bl.ser:bb-write-varint bb (length filter))
    (bl.ser:bb-write-bytes bb filter)
    (let ((data (bl.ser:bb-finish bb)))
      (when (> (+ (flat-file-pos-pos pos) (length data)) +max-fltr-file-size+)
        (flat-file-flush seq pos :finalize t)
        (setf pos (make-flat-file-pos (1+ (flat-file-pos-file pos)) 0)))
      (flat-file-allocate seq pos (length data))
      (with-flat-file (out seq pos)
        (write-sequence data out))
      (setf (blockfilterindex-next-filter-pos bfi)
            (make-flat-file-pos (flat-file-pos-file pos)
                                (+ (flat-file-pos-pos pos) (length data))))
      pos)))

(defun %bfi-read-filter (bfi pos filter-hash)
  "Core ReadFilterFromDisk (blockfilterindex.cpp:151-174): the encoded filter
at POS, or NIL when it cannot be read or its double SHA-256 is not
FILTER-HASH (`Checksum mismatch in filter decode')."
  (ignore-errors
   (with-flat-file (in (blockfilterindex-fltr-seq bfi) pos :read-only t)
     (let ((head (make-array 41 :element-type '(unsigned-byte 8))))
       (let ((n (read-sequence head in)))
         (when (> n 32)
           (let* ((br (bl.ser:make-byte-reader-from (subseq head 32 n)))
                  (len (bl.ser:br-read-compact-size br))
                  (filter (make-array len :element-type '(unsigned-byte 8))))
             (file-position in (+ (flat-file-pos-pos pos) 32 (bl.ser:br-pos br)))
             (read-sequence filter in)
             (when (equalp (block-filter-hash filter) filter-hash)
               filter))))))))

;;; --- lookups (Core index_util::LookUpOne) ---

(defun %bfi-lookup (bfi block-hash height)
  "(values filter-hash header pos) of the DBVal for the block BLOCK-HASH at
HEIGHT: the height record when it names this block (the active chain), else
the hash record a reorg left (db_key.h:96-113), or NIL."
  (when (%bfi-live-p bfi)
    (let* ((db (blockfilterindex-db bfi))
           (v (and height (>= height 0) (leveldb-get db (%bfi-height-key height)))))
      (if (and v (> (length v) 96) (equalp (subseq v 0 32) block-hash))
          (%bfi-decode-dbval v 32)
          (let ((hv (leveldb-get db (%bfi-hash-key block-hash))))
            (when (and hv (> (length hv) 64))
              (%bfi-decode-dbval hv 0)))))))

(defun blockfilterindex-get (bfi block-hash height)
  "Return (values encoded-filter filter-header) for BLOCK-HASH at HEIGHT (Core
LookupFilter + LookupFilterHeader), or (values nil nil) if the block is not
indexed or its filter does not read back."
  (multiple-value-bind (filter-hash header pos) (%bfi-lookup bfi block-hash height)
    (let ((filter (and pos (%bfi-read-filter bfi pos filter-hash))))
      (if filter (values filter header) (values nil nil)))))

(defun blockfilterindex-get-filter (bfi block-hash height)
  "Return the encoded basic filter bytes for BLOCK-HASH at HEIGHT, or NIL."
  (nth-value 0 (blockfilterindex-get bfi block-hash height)))

(defun blockfilterindex-get-header (bfi block-hash height)
  "Return the 32-byte basic filter header for BLOCK-HASH at HEIGHT, or NIL --
from the database alone, as Core's LookupFilterHeader answers."
  (nth-value 1 (%bfi-lookup bfi block-hash height)))

(defun blockfilterindex-has-block-p (bfi block-hash height)
  "T if BLOCK-HASH at HEIGHT has an indexed filter."
  (and (%bfi-lookup bfi block-hash height) t))

(defun blockfilterindex-best (bfi)
  "Return (values height hash) of the highest indexed block, or (values -1 nil).
Note the order: INDEX-BEST-BLOCK, the generic underneath, answers (hash height)."
  (multiple-value-bind (hash height) (index-best-block bfi)
    (if hash (values height hash) (values -1 nil))))

(defun blockfilterindex-height (bfi)
  "Height of the highest indexed block, or -1 if empty."
  (nth-value 0 (blockfilterindex-best bfi)))

;;; --- writes ---

(defun %spent-utxos->scripts (spent-utxos)
  "Extract the scriptPubKeys from an undo list of (txid index utxo-entry)."
  (mapcar (lambda (e) (utxo-entry-script-pubkey (third e))) spent-utxos))

(defun %bfi-write-record (bfi block-hash height filter header &key extra)
  "Core BlockFilterIndex::Write (blockfilterindex.cpp:260-275): the filter to its
file, then the height record, in one batch with EXTRA (key . value) records.
Whatever the height held for ANOTHER block moves to that block's hash key
first (Core's CopyHeightIndexToHashIndex, db_key.h:70-91)."
  (let* ((db (blockfilterindex-db bfi))
         (old (leveldb-get db (%bfi-height-key height)))
         (pos (%bfi-write-filter bfi block-hash filter)))
    (with-leveldb-writebatch (batch)
      (when (and old (> (length old) 96) (not (equalp (subseq old 0 32) block-hash)))
        (leveldb-writebatch-put batch (%bfi-hash-key (subseq old 0 32)) (subseq old 32)))
      (leveldb-writebatch-put batch (%bfi-height-key height)
                              (concatenate '(simple-array (unsigned-byte 8) (*))
                                           block-hash
                                           (%bfi-encode-dbval (block-filter-hash filter)
                                                              header pos)))
      (loop for (k . v) in extra do (leveldb-writebatch-put batch k v))
      (leveldb-write db batch))))

(defun blockfilterindex-add-block (bfi block block-hash height spent-utxos)
  "Build BLOCK's basic filter from its outputs and SPENT-UTXOS (the undo list of
(txid index utxo-entry)) and store it, chaining the filter header off the
parent's (Core CustomAppend, blockfilterindex.cpp:251-258). Marks BLOCK as the
best-indexed block. Returns the encoded filter, or NIL if the index is
disabled, or (values nil :noncontiguous) when BLOCK's parent has no stored
filter header while the index is non-empty: storing it would seed a second
header chain on top of a gap (observed after a mid-backfill crash left a hole
and the connect hook then re-seeded at the tip, stranding the hole behind an
advanced best marker). Refusing leaves the best marker where the indexed range
really ends, so the startup backfill can heal the gap."
  (unless (%bfi-live-p bfi)
    (return-from blockfilterindex-add-block nil))
  (let* ((prev-hash (bl.ser:block-header-prev-block
                     (bl.ser:bitcoin-block-header block)))
         ;; Chain the filter header off the parent's. Blocks are indexed in
         ;; order (connect hook + contiguous backfill), so the parent is present
         ;; for every block except the first one of the indexed range, which
         ;; seeds from the all-zero header. On an unpruned node that first block
         ;; is GENESIS, giving the BIP157 anchor filter_header(genesis) =
         ;; H(filter_hash(genesis) || 0^32) -- Core's m_last_header starts at
         ;; zero. Only a pruned node, whose early bodies are gone, still seeds
         ;; mid-chain.
         (prev-header (and (plusp height)
                           (blockfilterindex-get-header bfi prev-hash (1- height)))))
    (when (and (null prev-header) (>= (blockfilterindex-height bfi) 0))
      (return-from blockfilterindex-add-block (values nil :noncontiguous)))
    (let* ((scripts (%spent-utxos->scripts spent-utxos))
           (filter (build-basic-block-filter block block-hash scripts))
           (header (compute-block-filter-header
                    filter (or prev-header +zero-filter-header+))))
      (%bfi-write-record bfi block-hash height filter header)
      (index-set-best bfi block-hash height)
      filter)))

;;; --- backfill over already-stored blocks ---

(defun %block-spends-p (block)
  "T if BLOCK has any non-coinbase transaction (i.e. spends prior outputs), so
that a correct basic filter needs its undo data."
  (> (length (bl.ser:bitcoin-block-transactions block)) 1))

(defun blockfilterindex-set-best (bfi height hash)
  "Force the recorded best-indexed block to HEIGHT/HASH (used to repair the meta
record after a rollback such as invalidateblock)."
  (index-set-best bfi hash height))

(defun blockfilterindex-clear-best (bfi)
  "Delete the best-indexed metadata (forces a full backfill from height 0)."
  (index-clear-best bfi))

(defun blockfilterindex-wipe (bfi)
  "Delete the on-disk filter index entirely and reopen it empty. Used when the
stored header chain is not anchored at genesis (a legacy index built before
genesis indexing existed) and must be rebuilt from scratch."
  (when (and (blockfilterindex-enabled bfi) (blockfilterindex-db bfi))
    (let ((path (blockfilterindex-path (blockfilterindex-base-path bfi))))
      (close-blockfilterindex bfi)
      (leveldb-destroy-db path)
      (open-index-db bfi path)
      ;; No 'P' any more: the next filter goes to the start of fltr00000.dat.
      (setf (blockfilterindex-next-filter-pos bfi) (make-flat-file-pos 0 0)))
    t))

(defun blockfilterindex-ensure-genesis-anchor (bfi chain-state)
  "BIP157 anchors the filter-header chain at genesis: filter_header(genesis) =
H(filter_hash(genesis) || 0^32). Indexes built before genesis indexing existed
seeded their header chain at the FIRST STORED block instead, so every absolute
cfheaders/cfcheckpt/getblockfilter header they serve diverges from Core and
BIP157 light clients ban the node. Detect that shape — no genesis record, or a
genesis / height-1 record that does not recompute — and wipe the index so the
caller's backfill rebuilds it from height 0. Safe on fresh and healthy indexes
(no-op). Returns:
  :ok                 anchored (or empty checks all pass)
  :empty              nothing indexed yet — backfill will seed genesis
  :rebuilt            bad chain wiped; backfill must rebuild from scratch
  :unanchored-pruned  bad chain kept: bodies below the prune horizon are gone
                      so a rebuild is impossible (Core refuses -blockfilterindex
                      with pruning outright; we keep the internally consistent
                      chain and warn)
  NIL                 index disabled"
  (unless (and (blockfilterindex-enabled bfi) (blockfilterindex-db bfi))
    (return-from blockfilterindex-ensure-genesis-anchor nil))
  (let ((genesis-hash (network-genesis-hash bl.chain:*network*)))
    (flet ((rebuild (reason)
             (cond ((plusp (chain-state-pruned-height chain-state))
                    (bl.log:log-warn
                     "Block filter index ~A, and block bodies below the prune horizon (~D) are gone so it cannot be rebuilt; BIP157 headers stay internally consistent but do NOT match the network's absolute values"
                     reason (chain-state-pruned-height chain-state))
                    :unanchored-pruned)
                   (t
                    (bl.log:log-warn
                     "Block filter index ~A; wiping ~A for a full rebuild from genesis"
                     reason (blockfilterindex-path (blockfilterindex-base-path bfi)))
                    (blockfilterindex-wipe bfi)
                    :rebuilt))))
      (multiple-value-bind (gfilter gheader) (blockfilterindex-get bfi genesis-hash 0)
        (cond
          ;; Fresh/empty index: the backfill seeds genesis itself.
          ((and (null gfilter) (< (blockfilterindex-height bfi) 0)) :empty)
          ;; Legacy shape: entries exist but no genesis anchor.
          ((null gfilter)
           (rebuild "is not anchored at genesis (built before genesis indexing)"))
          ;; Genesis present: verify the anchor and the height-1 link recompute.
          ((not (equalp gheader (compute-block-filter-header
                                 gfilter +zero-filter-header+)))
           (rebuild "has a corrupt genesis filter header"))
          (t
           (let* ((e1 (get-block-at-height chain-state 1))
                  (h1 (and e1 (block-index-entry-hash e1))))
             (multiple-value-bind (f1 hdr1)
                 (if h1 (blockfilterindex-get bfi h1 1) (values nil nil))
               (if (and f1 (not (equalp hdr1 (compute-block-filter-header
                                              f1 gheader))))
                   (rebuild "has a height-1 filter header that does not chain off the genesis anchor")
                   :ok)))))))))

(defun build-blockfilterindex (bfi chain-state block-store get-undo-fn
                               &key progress-callback)
  "Backfill the filter index from just past the last indexed block up to the
active tip, using stored blocks and their undo data. GET-UNDO-FN maps a
block-hash to its undo list of (txid index utxo-entry), or NIL when absent.
An empty index on an UNPRUNED chain first indexes GENESIS, constructed from
chain parameters (its body is never in block storage), so the filter-header
chain gets its BIP157 anchor: filter_header(genesis) over the all-zero
previous header (Core indexes genesis like any block,
index/blockfilterindex.cpp CustomAppend). While the index is still empty on a
PRUNED chain, heights whose block body or (for a spending block) undo data is
unavailable are SKIPPED -- the whole pruned prefix is absent -- so the indexed
range seeds at the first indexable block (internally consistent, not
BIP157-absolute; Core refuses -blockfilterindex with pruning). Once anything
is indexed, the first such unavailable height STOPS the backfill instead,
keeping the stored filter-header chain contiguous (a skipped block would
leave the next block chained off a wrong parent header). PROGRESS-CALLBACK,
if given, is called with (height percent). Returns the number of blocks
indexed."
  (unless (and (blockfilterindex-enabled bfi) (blockfilterindex-db bfi))
    (return-from build-blockfilterindex 0))
  (let ((count 0))
    ;; BIP157 genesis anchor: seed height 0 from chain parameters. The
    ;; genesis block spends nothing, so its filter needs no undo data.
    (when (and (< (blockfilterindex-height bfi) 0)
               (zerop (chain-state-pruned-height chain-state)))
      (let ((genesis-hash (network-genesis-hash bl.chain:*network*)))
        (when (blockfilterindex-add-block
               bfi (make-genesis-block bl.chain:*network*)
               genesis-hash 0 nil)
          (incf count))))
    (let* ((tip (current-height chain-state))
           ;; An empty index starts its seed-seek at the pruned horizon: block
           ;; bodies at or below chain-state-pruned-height are deleted, and
           ;; probing each height costs a LevelDB block-index read -- observed
           ;; ~14 ms/height on the pruned mainnet node, i.e. a ~3.7 h stall
           ;; scanning ~950k pruned heights that cannot contain the seed.
           (start (if (< (blockfilterindex-height bfi) 0)
                      (1+ (chain-state-pruned-height chain-state))
                      (1+ (blockfilterindex-height bfi))))
           (seeded (>= (blockfilterindex-height bfi) 0))
           (last-report (get-internal-real-time)))
      (block done
        ;; One pass over the range, as Core's Sync walks it with NextSyncBlock
        ;; (index/base.cpp:160-179); see %BUILD-TX-INDEX-FROM.
        (loop for entry in (and (<= start tip)
                                (active-chain-entries-from chain-state start (1+ (- tip start))))
              for height = (block-index-entry-height entry)
              do (let* ((hash (block-index-entry-hash entry))
                        (block (and hash (get-block block-store hash)))
                        (undo (and block (funcall get-undo-fn hash)))
                        ;; FILTER is nil when the height is unindexable (missing
                        ;; body, or missing undo for a spending block) or when
                        ;; add-block refused a non-contiguous store (a stale best
                        ;; marker naming an orphaned block). Either way: skip
                        ;; pre-seed, stop post-seed.
                        (filter (and block
                                     (or undo (not (%block-spends-p block)))
                                     (blockfilterindex-add-block
                                      bfi block hash height undo))))
                   (cond (filter
                          (setf seeded t)
                          (incf count))
                         (seeded (return-from done))))
                 (when progress-callback
                   (let ((now (get-internal-real-time)))
                     (when (> (- now last-report) internal-time-units-per-second)
                       (funcall progress-callback height
                                (if (zerop tip) 100.0 (* 100.0 (/ height tip))))
                       (setf last-report now))))))
      (when progress-callback (funcall progress-callback tip 100.0))
      count)))

;;; --- Migration: this tree's records -> Core's (2026-09-29) ---
;;;
;;; The old record is 'f' || block hash -> header || filter. Core's needs the
;;; block's HEIGHT for its key and the filter in a fltr file, so the migration
;;; walks the active chain up to the index's best block, moving each block's
;;; record: the filter appended to the fltr files, the height record written
;;; and the old key deleted -- one batch per BATCH-BLOCKS blocks carrying the
;;; next height ('m') and the next filter position ('P'), so an interruption
;;; resumes where the last batch left both. Old records nothing on the active
;;; chain reaches -- blocks a reorg took off it -- then go under their hash
;;; key, as Core keeps such a block's filter. No block is read: the filters
;;; and headers carry over as they are.

(defun %bfi-old-record (bfi block-hash)
  "(values header filter) of BLOCK-HASH's old 'f' record, or NIL."
  (let ((v (leveldb-get (blockfilterindex-db bfi) (index-key +bfi-key-old-filter+ block-hash))))
    (when (and v (>= (length v) 32))
      (values (subseq v 0 32) (subseq v 32)))))

(defun %bfi-first-old-key (bfi)
  (with-leveldb-iterator (it (blockfilterindex-db bfi))
    (leveldb-iter-seek it (make-array 1 :element-type '(unsigned-byte 8)
                                        :initial-element +bfi-key-old-filter+))
    (when (leveldb-iter-valid-p it)
      (let ((k (leveldb-iter-key it)))
        (and (= (length k) 33) (= (aref k 0) +bfi-key-old-filter+) k)))))

(defun blockfilterindex-needs-migration-p (bfi)
  "T when BFI still holds records in this tree's pre-Core layout."
  (and (%bfi-live-p bfi)
       (or (leveldb-get (blockfilterindex-db bfi) *bfi-migration-key*)
           (%bfi-first-old-key bfi))
       t))

(defun %bfi-migration-flush (bfi puts deletes &optional next-height)
  (with-leveldb-writebatch (batch)
    (dolist (k deletes) (leveldb-writebatch-delete batch k))
    (loop for (k . v) in puts do (leveldb-writebatch-put batch k v))
    (when next-height
      (leveldb-writebatch-put batch *bfi-migration-key* (%u32-le next-height)))
    (flat-file-flush (blockfilterindex-fltr-seq bfi) (blockfilterindex-next-filter-pos bfi))
    (leveldb-writebatch-put batch *bfi-filter-pos-key*
                            (%bfi-encode-flat-pos (blockfilterindex-next-filter-pos bfi)))
    (leveldb-write (blockfilterindex-db bfi) batch)))

(defun migrate-blockfilterindex (bfi chain-state &key (batch-blocks 1000))
  "Rewrite BFI's records in Core's layout, in place and resumably (see above).
A no-op for an index already in Core's layout. Returns the number of filters
moved, or NIL when there was nothing to do."
  (unless (blockfilterindex-needs-migration-p bfi)
    (return-from migrate-blockfilterindex nil))
  (let* ((start-time (get-internal-real-time))
         (db (blockfilterindex-db bfi))
         (mark (leveldb-get db *bfi-migration-key*))
         (from (if (and mark (= 4 (length mark)))
                   (loop for i below 4 sum (ash (aref mark i) (* 8 i)))
                   ;; An index built on a pruned node starts where its
                   ;; first stored filter is, at or above the prune horizon.
                   0))
         (to (min (current-height chain-state) (blockfilterindex-height bfi)))
         (moved 0) (stale 0) (puts '()) (deletes '()))
    (bl.log:log-info "Block filter index: migrating records to Core's layout (filters into fltr files), heights ~D to ~D"
                     from to)
    (when (<= from to)
      (loop for entry in (active-chain-entries-from chain-state from (1+ (- to from)))
            for h = (block-index-entry-height entry)
            for hash = (block-index-entry-hash entry)
            do (multiple-value-bind (header filter) (%bfi-old-record bfi hash)
                 (when header
                   (let ((pos (%bfi-write-filter bfi hash filter)))
                     (push (cons (%bfi-height-key h)
                                 (concatenate '(simple-array (unsigned-byte 8) (*)) hash
                                              (%bfi-encode-dbval (block-filter-hash filter)
                                                                 header pos)))
                           puts)
                     (push (index-key +bfi-key-old-filter+ hash) deletes)
                     (incf moved))))
               (when (zerop (mod (1+ (- h from)) batch-blocks))
                 (%bfi-migration-flush bfi puts deletes (1+ h))
                 (setf puts '() deletes '())
                 (bl.log:log-info "Block filter index: migrated to height ~D of ~D" h to))))
    (%bfi-migration-flush bfi puts deletes (1+ to))
    ;; What is left is off the active chain: under its hash, as Core keeps it.
    (loop for key = (%bfi-first-old-key bfi)
          while key
          do (let ((hash (subseq key 1)))
               (multiple-value-bind (header filter) (%bfi-old-record bfi hash)
                 (if header
                     (let ((pos (%bfi-write-filter bfi hash filter)))
                       (%bfi-migration-flush
                        bfi (list (cons (%bfi-hash-key hash)
                                        (%bfi-encode-dbval (block-filter-hash filter) header pos)))
                        (list key))
                       (incf stale))
                     (%bfi-migration-flush bfi '() (list key))))))
    (leveldb-delete db *bfi-migration-key*)
    (bl.log:log-info "Block filter index: migration done -- ~D filter~:P on the active chain, ~D off it, in ~,1Fs"
                     moved stale (/ (- (get-internal-real-time) start-time)
                                    internal-time-units-per-second))
    (+ moved stale)))

(defmethod index-migrate-records ((index blockfilterindex) chainstate)
  (migrate-blockfilterindex index chainstate))
