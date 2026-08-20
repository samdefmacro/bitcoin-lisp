(in-package #:bitcoin-lisp.storage)

;;; Block storage
;;;
;;; Simple file-based block storage for the Bitcoin client.
;;; Blocks are stored as individual files named by their hash.

(defvar *data-directory* nil
  "Base directory for all data storage.")

(defvar *blocks-directory* nil
  "Directory for block files.")

(defstruct block-file-info
  "Per-file accounting for a blk/rev pair (Core CBlockFileInfo, kernel/blockmanager_opts
or chain.h). HEIGHT-FIRST and HEIGHT-LAST bound what the file contains, and
they are the whole reason a file can be pruned safely: Core deletes a file only
when its entire range lies inside the prunable window."
  (blocks 0 :type (integer 0))
  (size 0 :type (integer 0))
  (undo-size 0 :type (integer 0))
  (height-first nil :type (or null (unsigned-byte 32)))
  (height-last nil :type (or null (unsigned-byte 32))))

(defvar *flat-block-files* nil
  "Write new blocks into Core's numbered blk?????.dat files instead of one file
per block.

Transitional, and default OFF, for one reason: pruning is still per-block
deletion, and a flat file cannot have a block cut out of the middle of it. A
pruned node — which is what our mainnet node is — would silently stop reclaiming
space the moment its new blocks went into flat files. File-granular pruning is
P3 of docs/block-file-format-plan.md; this flag goes away with P4's migration.

READING is not gated: a store always reads whichever form each block is in, so
turning the flag on and off again leaves every block reachable.")

(defstruct block-store
  "Block storage manager."
  (base-path nil :type (or null pathname))
  ;; hash -> where the block is: a PATHNAME for a legacy per-block file, or a
  ;; FLAT-FILE-POS for a record inside a blk?????.dat. Both forms coexist for
  ;; the whole life of a store that has ever held either.
  (index (make-hash-table :test 'equalp) :type hash-table)
  ;; The blk sequence and where the next record goes. Core keeps the same pair
  ;; as m_blockfile_cursors (blockstorage.h:151-175).
  (blk-seq nil)
  (cursor-file 0 :type (unsigned-byte 32))
  (cursor-pos 0 :type (unsigned-byte 32))
  ;; The blocksdir obfuscation key, read or created once at init.
  (xor-key nil)
  ;; File number -> BLOCK-FILE-INFO (Core m_blockfile_info). What makes
  ;; file-granular pruning possible: a whole blk/rev pair can be deleted only
  ;; when EVERY block in it is inside the prunable window, which needs the
  ;; file's height range.
  (file-info (make-hash-table :test 'eql) :type hash-table)
  ;; Running total of all .blk file sizes, maintained by store-block and
  ;; prune-block and initialized by the init-block-store scan. Pruning
  ;; consults this after EVERY connected block (validation/block.lisp), so
  ;; it must be O(1) — re-scanning the blocks directory per block collapsed
  ;; mainnet IBD from ~220 b/s to ~0.3 b/s the moment the chain crossed
  ;; *prune-after-height*. Mirrors Bitcoin Core, which sums in-memory
  ;; per-file stats (m_blockfile_info) in CalculateCurrentUsage() rather
  ;; than touching the filesystem (validation.cpp).
  (total-bytes 0 :type (integer 0)))

(defun ensure-directories (store)
  "Ensure storage directories exist."
  (let ((blocks-path (merge-pathnames "blocks/" (block-store-base-path store))))
    (ensure-directories-exist blocks-path)
    blocks-path))

(defun block-file-path (store hash)
  "Get the file path for a block with given HASH."
  (let ((hash-hex (bitcoin-lisp.crypto:bytes-to-hex hash)))
    (merge-pathnames (format nil "blocks/~A.blk" hash-hex)
                     (block-store-base-path store))))

(defun file-size-bytes (path)
  "Size of the file at PATH in bytes, or NIL if it doesn't exist.
Uses stat on SBCL — one syscall, no file open."
  #+sbcl
  (handler-case
      (sb-posix:stat-size (sb-posix:stat (namestring path)))
    (error () nil))
  #-sbcl
  (handler-case
      (with-open-file (s path :direction :input
                              :element-type '(unsigned-byte 8))
        (file-length s))
    (error () nil)))

(defun block-network-magic ()
  "The 4-byte network magic that prefixes every stored record, which is the
same value the P2P message header uses (Core MessageStart)."
  (bitcoin-lisp:network-magic bitcoin-lisp:*network*))

(defun %blk-seq (store)
  "The blk file sequence, created on demand."
  (or (block-store-blk-seq store)
      (setf (block-store-blk-seq store)
            (make-flat-file-seq (ensure-directories store) "blk"
                                +blockfile-chunk-size+))))

(defun %store-block-flat (store data)
  "Append a block's serialized DATA to the current blk file and return its
FLAT-FILE-POS. The position points PAST the 8-byte header, at the payload,
which is what Core records as nDataPos."
  (let* ((seq (%blk-seq store))
         (record (flat-record-bytes (block-network-magic) data))
         (need (length record)))
    ;; Roll over rather than exceed Core's maximum file size, finalizing the
    ;; file we are leaving so its preallocated tail is truncated away.
    (when (and (plusp (block-store-cursor-pos store))
               (> (+ (block-store-cursor-pos store) need) +max-blockfile-size+))
      (flat-file-flush seq
                       (make-flat-file-pos (block-store-cursor-file store)
                                           (block-store-cursor-pos store))
                       :finalize t)
      (incf (block-store-cursor-file store))
      (setf (block-store-cursor-pos store) 0))
    (let* ((file (block-store-cursor-file store))
           (start (block-store-cursor-pos store))
           (pos (make-flat-file-pos file start)))
      (flat-file-allocate seq pos need)
      ;; Obfuscated at the record's real file offset: the key alignment of
      ;; every byte depends on where it lands, not on where the buffer starts.
      (let ((on-disk (obfuscate! (copy-seq record) (block-store-xor-key store)
                                 :key-offset start)))
        (with-open-file (out (flat-file-name seq pos)
                             :direction :io :element-type '(unsigned-byte 8)
                             :if-exists :overwrite :if-does-not-exist :create)
          (file-position out start)
          (write-sequence on-disk out)
          (finish-output out)
          ;; Same durability rule as the per-block path: connect-block stores
          ;; the block before the chainstate flush that references it.
          #+sbcl (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd out)))))
      (setf (block-store-cursor-pos store) (+ start need))
      (make-flat-file-pos file (+ start +storage-header-bytes+)))))

(defun %read-block-flat (store pos)
  "Read and deserialize the block whose payload starts at POS. Returns NIL if
the record is missing, mis-framed, or unreadable."
  (let* ((seq (%blk-seq store))
         (path (flat-file-name seq pos))
         (record-start (- (flat-file-pos-pos pos) +storage-header-bytes+)))
    (when (probe-file path)
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (when (<= (+ record-start +storage-header-bytes+) (file-length in))
          (file-position in record-start)
          (let ((header (make-array +storage-header-bytes+
                                    :element-type '(unsigned-byte 8))))
            (read-sequence header in)
            (obfuscate! header (block-store-xor-key store) :key-offset record-start)
            (multiple-value-bind (magic length) (parse-flat-record-header header)
              (when (and (equalp magic (block-network-magic))
                         (<= (+ (flat-file-pos-pos pos) length) (file-length in)))
                (let ((payload (make-array length :element-type '(unsigned-byte 8))))
                  (read-sequence payload in)
                  (obfuscate! payload (block-store-xor-key store)
                              :key-offset (flat-file-pos-pos pos))
                  (flexi-streams:with-input-from-sequence (bs payload)
                    (bitcoin-lisp.serialization:read-bitcoin-block bs)))))))))))

(defun %store-file-info (store file)
  (or (gethash file (block-store-file-info store))
      (setf (gethash file (block-store-file-info store)) (make-block-file-info))))

(defun %note-block-in-file (store file height bytes)
  "Fold one stored block into FILE's accounting."
  (let ((info (%store-file-info store file)))
    (incf (block-file-info-blocks info))
    (incf (block-file-info-size info) bytes)
    ;; A file with a block of unknown height has an unknown range, and an
    ;; unknown range can never be shown to lie inside the prunable window — so
    ;; it is never pruned. That is the safe direction: the alternative is
    ;; deleting a block the chain still needs.
    (when height
      (let ((first (block-file-info-height-first info))
            (last (block-file-info-height-last info)))
        (setf (block-file-info-height-first info) (if first (min first height) height)
              (block-file-info-height-last info) (if last (max last height) height))))
    info))

(defun store-block (store block &key height)
  "Store a block in the block store.
BLOCK should be a bitcoin-block structure.
Returns (values hash location), where LOCATION is a FLAT-FILE-POS when the
block went into a blk?????.dat and a PATHNAME when it went into a per-block
file (see *FLAT-BLOCK-FILES*).

HEIGHT is what lets the block's file be pruned later: pruning a flat file is
all-or-nothing, so the decision needs the file's height range. Omitting it
stores the block correctly and makes its file unprunable."
  (ensure-directories store)
  (let* ((hash (bitcoin-lisp.serialization:block-header-hash
                (bitcoin-lisp.serialization:bitcoin-block-header block)))
         (path (block-file-path store hash))
         ;; Persist blocks witness-complete (BIP144). The generic SERIALIZE
         ;; writes transactions in legacy form, which DROPS witness data — that
         ;; left on-disk blocks unservable to peers (a witness-stripped block
         ;; fails segwit validation, so a peer answering a MSG_WITNESS_BLOCK with
         ;; one gets rejected) and unusable for witness re-validation on reorg.
         ;; serialize-witness-block writes each tx witness-serialized only when it
         ;; carries witness, so non-segwit blocks are byte-identical to before.
         (data (bitcoin-lisp.serialization:serialize-witness-block block))
         ;; If we're overwriting an already-stored block, its old size is
         ;; in total-bytes and must be replaced, not added to.
         ;; Re-storing a block that is already here replaces its contribution
         ;; to the running total rather than adding to it. For a flat record
         ;; that is the payload plus its header; for a legacy file, the file.
         (old-size (let ((existing (gethash hash (block-store-index store))))
                     (typecase existing
                       (null nil)
                       (flat-file-pos (+ (length data) +storage-header-bytes+))
                       (t (file-size-bytes path))))))
    (cond
      (*flat-block-files*
       (let ((pos (%store-block-flat store data)))
         (setf (gethash hash (block-store-index store)) pos)
         (%note-block-in-file store (flat-file-pos-file pos) height
                              (+ (length data) +storage-header-bytes+))
         ;; The record's overhead counts toward the storage total, as it does
         ;; in Core's per-file accounting.
         (incf (block-store-total-bytes store)
               (- (+ (length data) +storage-header-bytes+) (or old-size 0)))
         (values hash pos)))
      (t
       ;; Write block to file and fsync it: connect-block stores the block before
       ;; the periodic chainstate flush, so the block must be durable before the
       ;; chainstate can reference it — otherwise a power loss can leave the
       ;; chainstate (or its coinbase-probe recovery) pointing at a block file
       ;; that never reached the platter.
       (with-open-file (stream path
                               :direction :output
                               :if-exists :supersede
                               :element-type '(unsigned-byte 8))
         (write-sequence data stream)
         (finish-output stream)
         #+sbcl (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd stream))))
       ;; Update index and running storage total
       (setf (gethash hash (block-store-index store)) path)
       (incf (block-store-total-bytes store) (- (length data) (or old-size 0)))
       (values hash path)))))

(defun get-block (store hash)
  "Retrieve a block by its hash.
Returns the bitcoin-block structure, or NIL if not found.

A corrupt / truncated / unreadable block file is treated as ABSENT and PRUNED
rather than allowed to signal. read-bitcoin-block raises on a malformed body;
before this guard that raise escaped through the reorg/download paths
(%best-completable-reorg-target, perform-reorg, retry-best-reorg-candidate) up
to the sync-thread top level and TERMINATED the sync thread — a live-but-wedged
zombie until restart (a real risk given this node's history of corrupt block/
undo files, e.g. a crash mid store-block leaves a truncated-but-indexed .blk).
Pruning is essential, not optional: returning NIL alone leaves probe-file true
so the block is never re-requested (silent permanent stall); deleting the file
makes probe + index agree so the normal download path re-fetches it and
store-block (:if-exists :supersede) overwrites. Every caller already treats NIL
as absent, so none relies on the raise."
  (let ((located (gethash hash (block-store-index store))))
    (when (flat-file-pos-p located)
      (return-from get-block
        (handler-case (%read-block-flat store located)
          (error (e)
            (bitcoin-lisp:log-warn
             "CORRUPT BLOCK record for ~A (~A) — dropping from the index"
             (bitcoin-lisp.crypto:bytes-to-hex hash) e)
            (remhash hash (block-store-index store))
            nil)))))
  (let ((path (block-file-path store hash)))
    (when (probe-file path)
      (handler-case
          (with-open-file (stream path
                                  :direction :input
                                  :element-type '(unsigned-byte 8))
            (let ((data (make-array (file-length stream)
                                    :element-type '(unsigned-byte 8))))
              (read-sequence data stream)
              (flexi-streams:with-input-from-sequence (in data)
                (bitcoin-lisp.serialization:read-bitcoin-block in))))
        (error (e)
          (bitcoin-lisp:log-warn
           "CORRUPT BLOCK file for ~A (~A) — pruning for re-download"
           (bitcoin-lisp.crypto:bytes-to-hex hash) e)
          (ignore-errors (prune-block store hash))
          nil)))))

(defun block-exists-p (store hash)
  "Check if a block with HASH exists in storage, in either form."
  (let ((located (gethash hash (block-store-index store))))
    (if (flat-file-pos-p located)
        t
        (probe-file (block-file-path store hash)))))

(defun %scan-flat-block-files (store)
  "Rebuild the hash -> position map by walking every blk?????.dat, and leave the
cursor at the end of the last one. Returns the bytes accounted for.

This is most of what a full -reindex does, and it is cheap: each record is
found by hopping over the previous one's length, and identifying a block needs
only its 80-byte header, never a full deserialization. Walking a file stops at
the first header that is not a record — which is exactly what the preallocated
zero tail of the file currently being appended to looks like."
  (let ((seq (%blk-seq store))
        (key (block-store-xor-key store))
        (magic (block-network-magic))
        (bytes 0)
        (last-file 0)
        (last-pos 0))
    (loop for file from 0
          for path = (flat-file-name seq (make-flat-file-pos file 0))
          while (probe-file path)
          do (with-open-file (in path :direction :input
                                      :element-type '(unsigned-byte 8))
               (let ((size (file-length in))
                     (offset 0)
                     (header (make-array +storage-header-bytes+
                                         :element-type '(unsigned-byte 8)))
                     (hdr80 (make-array 80 :element-type '(unsigned-byte 8))))
                 (loop
                   (when (> (+ offset +storage-header-bytes+) size) (return))
                   (file-position in offset)
                   (read-sequence header in)
                   (obfuscate! header key :key-offset offset)
                   (multiple-value-bind (found length) (parse-flat-record-header header)
                     (unless (and (equalp found magic)
                                  (plusp length)
                                  (>= length 80)
                                  (<= (+ offset +storage-header-bytes+ length) size))
                       (return))
                     (read-sequence hdr80 in)
                     (obfuscate! hdr80 key
                                 :key-offset (+ offset +storage-header-bytes+))
                     (let ((hash (bitcoin-lisp.crypto:hash256 hdr80)))
                       (setf (gethash hash (block-store-index store))
                             (make-flat-file-pos file (+ offset +storage-header-bytes+))))
                     (incf bytes (+ +storage-header-bytes+ length))
                     (setf offset (+ offset +storage-header-bytes+ length)
                           last-file file
                           last-pos offset)))))
          finally (setf (block-store-cursor-file store) last-file
                        (block-store-cursor-pos store) last-pos))
    bytes))

(defun init-block-store (base-path)
  "Initialize a block store at BASE-PATH."
  (let ((store (make-block-store :base-path (pathname base-path))))
    (ensure-directories store)
    ;; The obfuscation key is read before anything is scanned: without it every
    ;; record header would look like garbage and the scan would find nothing.
    ;; A key is only CREATED for a directory with no block data in it.
    (setf (block-store-xor-key store)
          (read-or-create-xor-key (merge-pathnames "blocks/" base-path)
                                  :create *flat-block-files*))
    ;; Scan for existing blocks (the only full-directory scan — from here
    ;; on, total-bytes is maintained incrementally)
    (let ((blocks-dir (merge-pathnames "blocks/" base-path))
          (total-bytes 0))
      (when (probe-file blocks-dir)
        (dolist (file (directory (merge-pathnames "*.blk" blocks-dir)))
          (let* ((name (pathname-name file))
                 (hash (bitcoin-lisp.crypto:hex-to-bytes name)))
            (setf (gethash hash (block-store-index store)) file)
            (incf total-bytes (or (file-size-bytes file) 0)))))
      ;; Then the flat files. Both forms are indexed, which is what makes the
      ;; store readable across the transition in either direction.
      (incf total-bytes (%scan-flat-block-files store))
      (setf (block-store-total-bytes store) total-bytes))
    store))

;;; Block Pruning

(defun prune-block (store hash)
  "Delete a block file from disk by HASH.
Returns the size in bytes of the deleted file, or NIL if the file didn't exist."
  ;; A block inside a blk?????.dat cannot be removed on its own — Core prunes
  ;; whole files, which is P3 of the block-file-format plan. Refuse loudly
  ;; rather than returning NIL, which the caller reads as "already gone" and
  ;; would let a pruned node stop reclaiming space in silence.
  (when (flat-file-pos-p (gethash hash (block-store-index store)))
    (bitcoin-lisp:log-warn
     "Cannot prune ~A: it is inside a flat block file, which prunes per FILE ~
      (block-file-format P3). Pruning is why *FLAT-BLOCK-FILES* is off by default."
     (bitcoin-lisp.crypto:bytes-to-hex hash))
    (return-from prune-block nil))
  (let* ((path (block-file-path store hash))
         ;; One stat serves both the existence check and the size — NIL
         ;; means the file isn't there.
         (size (file-size-bytes path)))
    (when size
      (delete-file path)
      (remhash hash (block-store-index store))
      (decf (block-store-total-bytes store) size)
      size)))

(defun rebuild-block-file-info (store chain-state)
  "Recover per-file accounting by joining the store's hash -> position map with
the header index's hash -> height. Called once at startup, after both are
loaded.

Core persists CBlockFileInfo in its block-index database; deriving it instead
means there is no second file to fall out of step with the block files. The
join is the only place the two halves meet: the flat files know WHERE each
block is and the header index knows WHAT HEIGHT it is, and pruning needs both."
  (clrhash (block-store-file-info store))
  (maphash
   (lambda (hash located)
     (when (flat-file-pos-p located)
       (let* ((entry (get-block-index-entry chain-state hash))
              (height (and entry (block-index-entry-height entry))))
         ;; The record's own byte count is not known without re-reading it;
         ;; the running total is maintained elsewhere, and pruning only needs
         ;; the height range plus a per-file byte figure, which the file's own
         ;; size on disk supplies.
         (%note-block-in-file store (flat-file-pos-file located) height 0))))
   (block-store-index store))
  ;; Take each file's byte count from the filesystem rather than summing
  ;; records: the difference is the preallocated tail, and pruning frees the
  ;; whole file including that tail.
  (maphash (lambda (file info)
             (let ((path (flat-file-name (%blk-seq store) (make-flat-file-pos file 0))))
               (setf (block-file-info-size info) (or (file-size-bytes path) 0))))
           (block-store-file-info store))
  (hash-table-count (block-store-file-info store)))

(defun %prunable-flat-files (store min-height max-height)
  "File numbers whose ENTIRE height range lies within [MIN-HEIGHT, MAX-HEIGHT]
(Core FindFilesToPrune's per-file test). A file with an unknown range, or one
holding a single block outside the window, is not prunable — pruning a flat
file is all or nothing."
  (let ((files '()))
    (maphash (lambda (file info)
               (let ((first (block-file-info-height-first info))
                     (last (block-file-info-height-last info)))
                 (when (and first last
                            (>= first min-height)
                            (<= last max-height)
                            (plusp (block-file-info-blocks info)))
                   (push file files))))
             (block-store-file-info store))
    (sort files #'<)))

(defun prune-flat-block-file (store file &key on-prune)
  "Delete the blk/rev pair FILE and forget every block in it (Core
PruneOneBlockFile plus the unlink). Returns the bytes freed.

ON-PRUNE is called with each block's hash, so the caller can drop the matching
undo data and clear the index entry's HAVE_DATA — Core does the second inside
PruneOneBlockFile because its index and its files share a lock; here the
callback keeps storage from having to reach into the chain state."
  (let ((freed 0)
        (hashes '()))
    (maphash (lambda (hash located)
               (when (and (flat-file-pos-p located)
                          (= (flat-file-pos-file located) file))
                 (push hash hashes)))
             (block-store-index store))
    (dolist (hash hashes)
      (remhash hash (block-store-index store))
      (when on-prune (funcall on-prune hash)))
    (dolist (prefix '("blk" "rev"))
      (let ((path (flat-file-name
                   (make-flat-file-seq (ensure-directories store) prefix
                                       +blockfile-chunk-size+)
                   (make-flat-file-pos file 0))))
        (let ((size (file-size-bytes path)))
          (when size
            (ignore-errors (delete-file path))
            (incf freed size)))))
    (remhash file (block-store-file-info store))
    (decf (block-store-total-bytes store) (min freed (block-store-total-bytes store)))
    (bitcoin-lisp:log-info "Pruned block file ~D: ~D blocks, ~D bytes"
                           file (length hashes) freed)
    freed))

(defun block-storage-size-mib (store)
  "Total size of all block files in MiB. O(1) — reads the running counter
maintained by store-block/prune-block (initialized by init-block-store)."
  (/ (block-store-total-bytes store) 1048576.0))  ; 1024 * 1024

(defun prune-old-blocks (store chain-state &key on-prune)
  "Prune old blocks when storage exceeds target.
Deletes oldest block files until storage is at or below the effective prune
target (halved while an assumeutxo historical chainstate exists — Core
BlockManager::FindFilesToPrune, node/blockstorage.cpp:330-338), respecting
+min-blocks-to-keep+, *prune-after-height*, and CHAIN-STATE's per-chainstate
prune floor (an unvalidated snapshot chainstate never prunes at or below its
base — Core Chainstate::GetPruneRange).
Only runs in automatic pruning mode.
Returns the number of blocks pruned."
  (unless (bitcoin-lisp:automatic-pruning-p)
    (return-from prune-old-blocks 0))
  (let ((current-height (chain-state-best-height chain-state))
        (prune-after (or bitcoin-lisp:*prune-after-height* 0)))
    ;; Don't prune until chain reaches prune-after-height
    (when (< current-height prune-after)
      (return-from prune-old-blocks 0))
    (let ((target-bytes (bitcoin-lisp:effective-prune-target-bytes)))
      (when (<= (block-store-total-bytes store) target-bytes)
        (return-from prune-old-blocks 0))
      ;; Calculate the allowed prune window: (floor, min-keep-height].
      (let* ((min-keep-height (max 0 (- current-height bitcoin-lisp:+min-blocks-to-keep+)))
             (start (chain-state-prune-walk-start chain-state))
             (pruned 0))
        ;; Flat files first, whole pairs at a time (Core FindFilesToPrune).
        ;; A blk file cannot have a block cut out of it, so the unit is the
        ;; file and the test is that its ENTIRE height range sits inside the
        ;; window. Legacy per-block files are handled by the walk below; a
        ;; store mid-transition holds both.
        (dolist (file (%prunable-flat-files store (1+ start) min-keep-height))
          (when (<= (block-store-total-bytes store) target-bytes)
            (return))
          (let ((info (gethash file (block-store-file-info store))))
            (let ((last (and info (block-file-info-height-last info)))
                  (blocks (if info (block-file-info-blocks info) 0)))
              (prune-flat-block-file store file :on-prune on-prune)
              (incf pruned blocks)
              (when last
                (setf (chain-state-pruned-height chain-state)
                      (max (chain-state-pruned-height chain-state) last))))))
        ;; Walk from start+1 upward, deleting blocks until the running
        ;; total (maintained by prune-block) is back under target.
        ;; One active-chain walk for the whole range — get-block-at-height
        ;; per height would re-walk from the tip each time, quadratic for
        ;; the initial catch-up prune that deletes a large range at once.
        (loop for entry in (active-chain-entries-from
                            chain-state (1+ start)
                            (- min-keep-height start))
              while (> (block-store-total-bytes store) target-bytes)
              do (when (prune-block store (block-index-entry-hash entry))
                   (incf pruned))
                 ;; The undo file goes with the block (Core deletes rev
                 ;; files alongside blk files): a pruned node can't reorg
                 ;; below its window, so undo there is dead weight.
                 (when on-prune
                   (funcall on-prune (block-index-entry-hash entry)))
                 ;; Advance even when the file was already gone — the block
                 ;; is off disk either way, and a permanent gap would force
                 ;; every later call to re-walk from the same height.
                 (setf (chain-state-pruned-height chain-state)
                       (block-index-entry-height entry)))
        pruned))))

(defun prune-blocks-to-height (store chain-state target-height &key on-prune)
  "Prune all block files below TARGET-HEIGHT.
Respects +min-blocks-to-keep+ retention and CHAIN-STATE's per-chainstate
prune floor (Core FindFilesToPruneManual also bounds the manual range by
GetPruneRange, node/blockstorage.cpp:292-319).
Returns the number of blocks pruned."
  (unless (bitcoin-lisp:pruning-enabled-p)
    (return-from prune-blocks-to-height 0))
  (let* ((current-height (chain-state-best-height chain-state))
         (max-prune-height (max 0 (- current-height bitcoin-lisp:+min-blocks-to-keep+)))
         (effective-target (min target-height max-prune-height))
         (start (chain-state-prune-walk-start chain-state))
         (pruned 0))
    (when (<= effective-target start)
      (return-from prune-blocks-to-height 0))
    (dolist (entry (active-chain-entries-from
                    chain-state (1+ start)
                    (- effective-target start 1)))
      (when (prune-block store (block-index-entry-hash entry))
        (incf pruned))
      (when on-prune
        (funcall on-prune (block-index-entry-hash entry)))
      (setf (chain-state-pruned-height chain-state)
            (block-index-entry-height entry)))
    pruned))
