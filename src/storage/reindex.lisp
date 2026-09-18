(in-package #:bitcoin-lisp.storage)

;;;; Rebuilding the block index from the block files (Core -reindex)
;;;;
;;;; The capability the flat block files were worth having for. Until now a
;;;; corrupt or lost headerindex.dat meant re-downloading the chain: the node
;;;; refuses to start rather than run with an empty index that contradicts its
;;;; chainstate, and there was nothing to rebuild it from — one file per
;;;; block, named by a hash, with no way to know what was in them without
;;;; opening all of them.
;;;;
;;;; A blk file is self-describing, so the index is recoverable: walk the
;;;; records, read each 80-byte header, and rebuild the tree. Together with
;;;; -reindex-chainstate (which rebuilds the UTXO set from the index) that is a
;;;; full -reindex, and it turns "lost index" from a resync into minutes of
;;;; local work.
;;;;
;;;; Core's ImportBlocks does the same thing and hits the same problem: blocks
;;;; are stored in the order they ARRIVED, so a block's parent may be later in
;;;; the file, or in a later file. Core parks such blocks in a multimap keyed
;;;; by their parent's hash and drains it recursively after each accepted
;;;; block; so does this.

;;;; The persisted reindex flag (Core BlockTreeDB's 'R' record)
;;;;
;;;; A reindex that is interrupted -- a kill, a power cut, an operator's
;;;; Ctrl-C partway through a chain's worth of block files -- must not come
;;;; back as an ordinary start over a half-rebuilt index. Core records the fact
;;;; on disk: DB_REINDEX_FLAG 'R' in blocks/index (node/blockstorage.cpp:61),
;;;; written when the block tree db is wiped (:1234-1236, through
;;;; WriteReindexing at :73-80), read back by LoadBlockIndexDB (:583-586),
;;;; where it clears m_blockfiles_indexed, and erased only once ImportBlocks
;;;; has read every block file (:1288-1290). The NEXT start therefore reindexes
;;;; WITHOUT the option, and keeps doing so until one run finishes.
;;;;
;;;; Ours is a file rather than a database record for the same reason our block
;;;; index is a file: there is no blocks/index LevelDB to hold a key. It lives
;;;; in the directory Core's key lives in.

(defun reindex-flag-path (data-dir)
  "The reindex-in-progress marker's path under DATA-DIR: blocks/index/reindex,
beside the block index whose rebuild it describes."
  (merge-pathnames "reindex" (datadir-block-index-path data-dir)))

(defun write-reindex-flag (data-dir on)
  "Core BlockTreeDB::WriteReindexing (node/blockstorage.cpp:73-80): record that
a reindex is under way when ON, erase the record when ON is NIL. Returns ON.

Written before the first block file is read and erased only after the last one,
so a marker found at start-up means exactly `a reindex began here and did not
finish'. Both the byte and the NAME are fsynced: a marker the crash it exists
for can lose is no marker."
  (let ((path (reindex-flag-path data-dir)))
    (cond (on
           (ensure-directories-exist path)
           (with-open-file (out path :direction :output
                                     :element-type '(unsigned-byte 8)
                                     :if-exists :supersede
                                     :if-does-not-exist :create)
             ;; Core's record value is the one byte '1'; the marker is its
             ;; PRESENCE, and nothing reads the contents back.
             (write-byte (char-code #\1) out))
           (fsync-file path)
           (fsync-parent-directory path))
          (t
           (when (probe-file path)
             (delete-file path)
             (fsync-parent-directory path))))
    on))

(defun reindex-flag-set-p (data-dir)
  "Core BlockTreeDB::ReadReindexing (node/blockstorage.cpp:82-85): T when an
unfinished reindex is recorded under DATA-DIR. Its presence is the answer."
  (and (probe-file (reindex-flag-path data-dir)) t))

(defun %reindex-header-of-record (store pos)
  "Read just the 80-byte header at POS, de-obfuscated. Returns (values header
hash) or NIL — a block's identity needs nothing more, and deserializing whole
blocks to rebuild an index would read the entire chain into memory."
  (let* ((seq (%blk-seq store))
         (path (flat-file-name seq pos)))
    (when (probe-file path)
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (when (<= (+ (flat-file-pos-pos pos) 80) (file-length in))
          (file-position in (flat-file-pos-pos pos))
          (let ((bytes (make-array 80 :element-type '(unsigned-byte 8))))
            (read-sequence bytes in)
            (obfuscate! bytes (block-store-xor-key store)
                        :key-offset (flat-file-pos-pos pos))
            (handler-case
                (let ((header (flexi-streams:with-input-from-sequence (hs bytes)
                                (bl.ser:read-block-header hs))))
                  (values header (bl.crypto:hash256 bytes)))
              (error () nil))))))))

(defun %reindex-add-entry (chain-state hash header located parent)
  "Add HASH's index entry under PARENT, carrying the record's position. Returns
T when an entry was added."
  (unless (get-block-index-entry chain-state hash)
    (let ((entry (make-block-index-entry
                  :hash hash
                  :height (1+ (block-index-entry-height parent))
                  :header header
                  :prev-entry parent
                  :chain-work (calculate-chain-work
                               (bl.ser:block-header-bits header)
                               (block-index-entry-chain-work parent))
                  ;; The body is on disk but nothing has been re-validated, so
                  ;; the entry claims only that its header is good. The
                  ;; chainstate rebuild is what promotes blocks to :valid by
                  ;; re-applying them.
                  :status :header-valid)))
      (%record-block-position entry located)
      (add-block-index-entry chain-state entry)
      t)))

(defun %reindex-drain-children (chain-state pending hash)
  "Core's recursive successor drain (validation.cpp:5110-5134): everything
parked under HASH, then everything parked under those, breadth first. Returns
the number of entries added.

A queue rather than recursion: a parked run can be hundreds of thousands deep
and recursion would exhaust the stack."
  (let ((added 0)
        (queue (list hash)))
    (loop while queue
          do (let* ((head (pop queue))
                    (children (gethash head pending))
                    (parent (get-block-index-entry chain-state head)))
               (remhash head pending)
               (when parent
                 (dolist (child (reverse children))
                   (destructuring-bind (child-hash child-header located) child
                     ;; Core logs one line per child it reads back, before
                     ;; AcceptBlock (validation.cpp:5122).
                     (bl.log:log-cat "reindex"
                                     "LoadExternalBlockFile: Processing out of order child ~A of ~A"
                                     (%reindex-hash-text child-hash)
                                     (%reindex-hash-text head))
                     (when (%reindex-add-entry chain-state child-hash child-header
                                               located parent)
                       (incf added))
                     (when (gethash child-hash pending)
                       (push child-hash queue)))))))
    added))

(defun %reindex-hash-text (hash)
  "HASH as Core's uint256::ToString spells it in these log lines: big-endian
hex, the way every RPC reports a block hash."
  (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash)))

(defun %reindex-records-in-file-order (store)
  "Every flat record in STORE as (hash pos), in the order the files hold them.

File order is the contract: Core reads a blk file record by record and decides
each one against the index AS IT STANDS at that point, so which blocks come out
`out of order' is a property of the bytes on disk. Walking the store's
hash -> position map in hash-table order instead would make that answer depend
on the table's iteration, which is arrival order and not file order."
  (let ((records '()))
    (maphash (lambda (hash located)
               (when (flat-file-pos-p located)
                 (push (cons hash located) records)))
             (block-store-index store))
    (sort records
          (lambda (a b)
            (let ((fa (flat-file-pos-file (cdr a)))
                  (fb (flat-file-pos-file (cdr b))))
              (if (= fa fb)
                  (< (flat-file-pos-pos (cdr a)) (flat-file-pos-pos (cdr b)))
                  (< fa fb)))))))

(defun reindex-block-index (store chain-state)
  "Rebuild CHAIN-STATE's block index from STORE's block files.

Returns (values entries-added orphans-left). Orphans are records whose parent
never turned up: on a pruned node that is expected -- the chain below the prune
horizon is gone -- and they are reported rather than treated as corruption.

The genesis entry is assumed to be present already; every other block is linked
to its parent, which is what supplies its height and chain work.

Core's shape, and it is the shape and not just the outcome that matters
(LoadExternalBlockFile, validation.cpp:5006-5134): each record is judged as it
is read, against the index as it stands. A block whose parent is not known YET
is logged and parked in mapBlocksUnknownParent under its parent's hash
(:5048-5054); a block whose parent IS known is added, and then everything
parked under it -- and under those in turn -- is processed at once
(:5110-5134). Ours read every record into one table first and drained
afterwards, which reaches the same index but can say nothing about which
blocks were out of order, and feature_reindex.py:69-73 swaps two blocks inside
blk00000.dat precisely to watch for those two lines."
  (let ((pending (make-hash-table :test 'equalp))   ; prev-hash -> list of (hash header pos)
        (genesis (chain-state-genesis-hash chain-state))
        (added 0))
    (loop for (hash . located) in (%reindex-records-in-file-order store)
          do (multiple-value-bind (header record-hash)
                 (%reindex-header-of-record store located)
               (when (and header record-hash)
                 (let ((prev (bl.ser:block-header-prev-block header)))
                   (cond
                     ;; Already in the index: nothing to do, and never a
                     ;; parent-lookup (genesis takes this arm on every run).
                     ((get-block-index-entry chain-state record-hash))
                     ;; Genesis's parent is the zero hash and will never be in
                     ;; the index; Core excludes it from the check by name
                     ;; (validation.cpp:5049).
                     ((and genesis (equalp record-hash genesis)))
                     (t
                      (let ((parent (get-block-index-entry chain-state prev)))
                        (cond
                          ((null parent)
                           (bl.log:log-cat "reindex"
                                           "LoadExternalBlockFile: Out of order block ~A, parent ~A not known"
                                           (%reindex-hash-text record-hash)
                                           (%reindex-hash-text prev))
                           (push (list record-hash header located)
                                 (gethash prev pending)))
                          (t
                           ;; The record's position travels with the header:
                           ;; the entry built here is the only thing that will
                           ;; ever carry nFile/nDataPos, and without them a
                           ;; reindexed datadir writes undo data in the legacy
                           ;; format forever. Core drives the same field from
                           ;; its reindex path (UpdateBlockInfo,
                           ;; blockstorage.cpp:923-940, called from
                           ;; AcceptBlock's reindex branch,
                           ;; validation.cpp:4402-4403).
                           (when (%reindex-add-entry chain-state record-hash
                                                     header located parent)
                             (incf added))
                           (incf added (%reindex-drain-children
                                        chain-state pending record-hash)))))))))))
    ;; A parent that was already in the index when its children were parked
    ;; cannot happen -- the check above would have taken the other arm -- but a
    ;; run whose parents arrive only as OTHER parked blocks land does, so drain
    ;; from every index entry once more before counting what is left.
    (let ((roots '()))
      (maphash (lambda (prev children)
                 (declare (ignore children))
                 (when (get-block-index-entry chain-state prev) (push prev roots)))
               pending)
      (dolist (root roots)
        (incf added (%reindex-drain-children chain-state pending root))))
    (values added
            (let ((left 0))
              (maphash (lambda (k v) (declare (ignore k)) (incf left (length v))) pending)
              left))))

;;;; Reading blocks out of an EXTERNAL file (Core -loadblock)
;;;;
;;;; Same framing as a blk file — magic, 4-byte size, block — but nothing else
;;;; can be assumed. The file was produced by another tool (contrib/linearize
;;;; writes bootstrap.dat), it carries no xor.dat, and it may hold garbage
;;;; between records or be truncated mid-block. Core therefore HUNTS the magic
;;;; a byte at a time and treats any failure as "resume scanning one byte
;;;; further", which is what makes the reader tolerant of a partial download
;;;; (LoadExternalBlockFile, validation.cpp:4988-5060).

(defconstant +max-block-serialized-size+ 4000000
  "Core MAX_BLOCK_SERIALIZED_SIZE. A size field outside [80, this] is not a
record, so the scan resumes hunting rather than trying to read it.")

(defun map-external-block-file (path fn)
  "Call FN with each serialized block found in the file at PATH, in file order.
Returns the number of records handed over.

FN receives the raw bytes; deserializing is the caller's business, and a caller
that only wants to count or index need not pay for it.

Records are located by hunting the network magic, so leading junk, trailing
junk, and a record that fails to read all leave the rest of the file readable —
the property that makes this usable on a bootstrap.dat someone stopped
downloading halfway."
  (let ((magic (block-network-magic))
        (found 0))
    (with-open-file (in path :direction :input :element-type '(unsigned-byte 8)
                             :if-does-not-exist nil)
      (unless in (return-from map-external-block-file 0))
      (let ((length (file-length in))
            (window (make-array 8 :element-type '(unsigned-byte 8)))
            (pos 0))
        (loop
          (when (> (+ pos 8) length) (return))
          (file-position in pos)
          (read-sequence window in)
          (cond
            ((not (loop for i below 4 always (= (aref window i) (aref magic i))))
             ;; Not a record here. One byte further, as Core does — a record
             ;; can start at any offset once the file has junk in it.
             (incf pos))
            (t
             (let ((size (logior (aref window 4)
                                 (ash (aref window 5) 8)
                                 (ash (aref window 6) 16)
                                 (ash (aref window 7) 24))))
               (cond
                 ((or (< size 80) (> size +max-block-serialized-size+)
                      (> (+ pos 8 size) length))
                  ;; A plausible magic with an implausible length is a
                  ;; coincidence in the data, not a record.
                  (incf pos))
                 (t
                  (let ((bytes (make-array size :element-type '(unsigned-byte 8))))
                    (read-sequence bytes in)
                    (funcall fn bytes)
                    (incf found)
                    (setf pos (+ pos 8 size)))))))))))
    found))
