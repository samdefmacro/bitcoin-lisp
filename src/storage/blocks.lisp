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
  (index (make-hash-table :test 'equalp) :type hash-table))

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

(defun store-block (store block)
  "Store a block in the block store.
BLOCK should be a bitcoin-block structure.
Returns the block hash."
  (ensure-directories store)
  (let* ((hash (bitcoin-lisp.serialization:block-header-hash
                (bitcoin-lisp.serialization:bitcoin-block-header block)))
         (path (block-file-path store hash))
         (data (bitcoin-lisp.serialization:serialize block)))
    ;; Write block to file
    (with-open-file (stream path
                            :direction :output
                            :if-exists :supersede
                            :element-type '(unsigned-byte 8))
      (write-sequence data stream))
    ;; Update index
    (setf (gethash hash (block-store-index store)) path)
    hash))

(defun get-block (store hash)
  "Retrieve a block by its hash.
Returns the bitcoin-block structure, or NIL if not found."
  (let ((path (block-file-path store hash)))
    (when (probe-file path)
      (with-open-file (stream path
                              :direction :input
                              :element-type '(unsigned-byte 8))
        (let ((data (make-array (file-length stream)
                                :element-type '(unsigned-byte 8))))
          (read-sequence data stream)
          (flexi-streams:with-input-from-sequence (in data)
            (bitcoin-lisp.serialization:read-bitcoin-block in)))))))

(defun block-exists-p (store hash)
  "Check if a block with HASH exists in storage."
  (probe-file (block-file-path store hash)))

(defun init-block-store (base-path)
  "Initialize a block store at BASE-PATH."
  (let ((store (make-block-store :base-path (pathname base-path))))
    (ensure-directories store)
    ;; Scan for existing blocks
    (let ((blocks-dir (merge-pathnames "blocks/" base-path)))
      (when (probe-file blocks-dir)
        (dolist (file (directory (merge-pathnames "*.blk" blocks-dir)))
          (let* ((name (pathname-name file))
                 (hash (bitcoin-lisp.crypto:hex-to-bytes name)))
            (setf (gethash hash (block-store-index store)) file)))))
    store))

;;; Block Pruning

(defun prune-block (store hash)
  "Delete a block file from disk by HASH.
Returns the size in bytes of the deleted file, or NIL if the file didn't exist."
  (let ((path (block-file-path store hash)))
    (when (probe-file path)
      (let ((size (with-open-file (s path :direction :input
                                         :element-type '(unsigned-byte 8))
                    (file-length s))))
        (delete-file path)
        (remhash hash (block-store-index store))
        size))))

(defun block-storage-size-mib (store)
  "Calculate the total size of all block files in MiB."
  (let ((total-bytes 0)
        (blocks-dir (merge-pathnames "blocks/" (block-store-base-path store))))
    (when (probe-file blocks-dir)
      (dolist (file (directory (merge-pathnames "*.blk" blocks-dir)))
        (let ((size (with-open-file (s file :direction :input
                                           :element-type '(unsigned-byte 8))
                      (file-length s))))
          (incf total-bytes size))))
    (/ total-bytes 1048576.0)))  ; 1024 * 1024

(defun prune-old-blocks (store chain-state)
  "Prune old blocks when storage exceeds target.
Deletes oldest block files until storage is at or below *prune-target-mib*,
respecting +min-blocks-to-keep+ and *prune-after-height*.
Only runs in automatic pruning mode.
Returns the number of blocks pruned."
  (unless (bitcoin-lisp:automatic-pruning-p)
    (return-from prune-old-blocks 0))
  (let ((current-height (chain-state-best-height chain-state))
        (prune-after (or bitcoin-lisp:*prune-after-height* 0)))
    ;; Don't prune until chain reaches prune-after-height
    (when (< current-height prune-after)
      (return-from prune-old-blocks 0))
    ;; Check if we exceed the target (scan once, then track via running total)
    (let ((current-size (block-storage-size-mib store))
          (target bitcoin-lisp:*prune-target-mib*))
      (when (<= current-size target)
        (return-from prune-old-blocks 0))
      ;; Calculate the lowest height we're allowed to prune to
      (let* ((min-keep-height (max 0 (- current-height bitcoin-lisp:+min-blocks-to-keep+)))
             (pruned-height (chain-state-pruned-height chain-state))
             (pruned 0))
        ;; Walk from pruned-height+1 upward, deleting blocks
        ;; Use running total to avoid rescanning all files each iteration
        (loop for height from (1+ pruned-height) to min-keep-height
              while (> current-size target)
              do (let ((entry (get-block-at-height chain-state height)))
                   (when entry
                     (let* ((hash (block-index-entry-hash entry))
                            (deleted-bytes (prune-block store hash)))
                       (when deleted-bytes
                         (decf current-size (/ deleted-bytes 1048576.0))
                         (incf pruned)
                         (setf (chain-state-pruned-height chain-state) height))))))
        pruned))))

(defun prune-blocks-to-height (store chain-state target-height)
  "Prune all block files below TARGET-HEIGHT.
Respects +min-blocks-to-keep+ retention.
Returns the number of blocks pruned."
  (unless (bitcoin-lisp:pruning-enabled-p)
    (return-from prune-blocks-to-height 0))
  (let* ((current-height (chain-state-best-height chain-state))
         (max-prune-height (max 0 (- current-height bitcoin-lisp:+min-blocks-to-keep+)))
         (effective-target (min target-height max-prune-height))
         (pruned-height (chain-state-pruned-height chain-state))
         (pruned 0))
    (when (<= effective-target pruned-height)
      (return-from prune-blocks-to-height 0))
    (loop for height from (1+ pruned-height) below effective-target
          do (let ((entry (get-block-at-height chain-state height)))
               (when entry
                 (let ((hash (block-index-entry-hash entry)))
                   (when (prune-block store hash)
                     (incf pruned)
                     (setf (chain-state-pruned-height chain-state) height))))))
    pruned))
