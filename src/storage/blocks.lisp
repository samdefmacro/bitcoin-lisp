(in-package #:bitcoin-lisp.storage)

;;; Block storage
;;;
;;; Simple file-based block storage for the Bitcoin client.
;;; Blocks are stored as individual files named by their hash.

(defvar *data-directory* nil
  "Base directory for all data storage.")

(defvar *blocks-directory* nil
  "Directory for block files.")

(defstruct block-store
  "Block storage manager."
  (base-path nil :type (or null pathname))
  (index (make-hash-table :test 'equalp) :type hash-table)
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

(defun store-block (store block)
  "Store a block in the block store.
BLOCK should be a bitcoin-block structure.
Returns the block hash."
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
         (old-size (when (gethash hash (block-store-index store))
                     (file-size-bytes path))))
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
    hash))

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
  "Check if a block with HASH exists in storage."
  (probe-file (block-file-path store hash)))

(defun init-block-store (base-path)
  "Initialize a block store at BASE-PATH."
  (let ((store (make-block-store :base-path (pathname base-path))))
    (ensure-directories store)
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
      (setf (block-store-total-bytes store) total-bytes))
    store))

;;; Block Pruning

(defun prune-block (store hash)
  "Delete a block file from disk by HASH.
Returns the size in bytes of the deleted file, or NIL if the file didn't exist."
  (let* ((path (block-file-path store hash))
         ;; One stat serves both the existence check and the size — NIL
         ;; means the file isn't there.
         (size (file-size-bytes path)))
    (when size
      (delete-file path)
      (remhash hash (block-store-index store))
      (decf (block-store-total-bytes store) size)
      size)))

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
