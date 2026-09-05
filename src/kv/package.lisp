(in-package #:cl-user)

(defpackage #:bitcoin-lisp.kv
  (:documentation "Persistence primitives with no idea what a block is: the
LevelDB binding and its cache sizing, the flat append-only file sequence
with XOR obfuscation, the datadir layout and migration, and fsync. A layer
of its own (bitcoin-lisp/kv) below serialization. BITCOIN-LISP.STORAGE
:USEs it and re-exports the entry points, so its callers are unchanged.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   #:*blocks-xor*
   #:*cache-sizes*
   #:*fast-prune*
   #:+blockfile-chunk-size+
   #:+default-db-cache-bytes+
   #:+max-blockfile-size+
   #:+storage-header-bytes+
   #:+undo-data-disk-overhead+
   #:+undofile-chunk-size+
   #:cache-sizes-block-tree-db
   #:cache-sizes-coins
   #:cache-sizes-coins-db
   #:cache-sizes-filter-index
   #:cache-sizes-tx-index
   #:calculate-cache-sizes
   #:datadir-block-index-path
   #:datadir-header-index-file
   #:datadir-index-path
   #:datadir-layout-report
   #:ensure-libleveldb-loaded
   #:find-next-record
   ;; Record checksums
   #:compute-crc32
   #:flat-file-allocate
   #:flat-file-flush
   #:flat-file-name
   #:flat-file-pos
   #:flat-file-pos-file
   #:flat-file-pos-null-p
   #:flat-file-pos-p
   #:flat-file-pos-pos
   #:flat-record-bytes
   #:fsync-directory
   #:fsync-file
   #:fsync-parent-directory
   #:leveldb-close
   #:leveldb-compact
   #:leveldb-delete
   #:leveldb-destroy-db
   #:leveldb-destroy-options
   #:leveldb-destroy-writebatch
   #:leveldb-get
   #:leveldb-iter-check-error
   #:leveldb-iter-key
   #:leveldb-iter-next
   #:leveldb-iter-seek
   #:leveldb-iter-seek-to-first
   #:leveldb-iter-valid-p
   #:leveldb-iter-value
   #:leveldb-make-options
   #:leveldb-make-writebatch
   #:leveldb-open
   #:leveldb-open-tuned
   #:leveldb-put
   #:leveldb-write
   #:leveldb-writebatch-clear
   #:leveldb-writebatch-delete
   #:leveldb-writebatch-put
   #:make-flat-file-pos
   #:make-flat-file-seq
   #:make-obfuscation-key
   #:max-blockfile-size
   #:migrate-datadir-layout
   #:obfuscate!
   #:obfuscation-key-active-p
   #:parse-flat-record-header
   #:read-or-create-xor-key
   #:rename-path
   #:undo-record-bytes
   #:undo-record-checksum
   #:with-flat-file
   #:with-leveldb
   #:with-leveldb-iterator
   #:with-leveldb-writebatch
   #:zero-obfuscation-key))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
