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
