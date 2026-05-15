(in-package #:bitcoin-lisp.storage)

;;; CFFI bindings for libleveldb's C API (leveldb/c.h).
;;;
;;; Why LevelDB: Bitcoin Core stores the UTXO set in LevelDB
;;; (refs/bitcoin/src/dbwrapper.cpp:7-16, refs/bitcoin/src/txdb.cpp).
;;; Per-flush work is proportional to *dirty* entries (typically a few
;;; thousand at the tip), not the full set of ~135M entries on mainnet
;;; or ~23M on testnet4. Our previous flat-file approach rewrote the
;;; whole utxoset.dat each flush — ~13s at h=82k, scaling with set size.
;;;
;;; We bind the C API (leveldb/c.h) rather than the C++ API because CFFI
;;; works naturally with C. The C API covers everything we need:
;;; open/close, get/put/delete, batched writes, options.

(cffi:define-foreign-library libleveldb
  (:darwin (:or "libleveldb.1.dylib" "libleveldb.dylib"))
  (:unix (:or "libleveldb.so.1" "libleveldb.so"))
  (t (:default "libleveldb")))

;;; Raw C bindings. `%` prefix marks these as the low-level FFI surface;
;;; callers go through the Lisp wrappers below for pinning, error checks,
;;; and cached options.

(cffi:defcfun ("leveldb_open" %leveldb-open) :pointer
  (options :pointer) (name :string) (errptr :pointer))

(cffi:defcfun ("leveldb_close" %leveldb-close) :void
  (db :pointer))

(cffi:defcfun ("leveldb_destroy_db" %leveldb-destroy-db) :void
  (options :pointer) (name :string) (errptr :pointer))

(cffi:defcfun ("leveldb_put" %leveldb-put) :void
  (db :pointer) (options :pointer)
  (key :pointer) (keylen :size)
  (val :pointer) (vallen :size)
  (errptr :pointer))

(cffi:defcfun ("leveldb_get" %leveldb-get) :pointer
  (db :pointer) (options :pointer)
  (key :pointer) (keylen :size)
  (vallen :pointer)
  (errptr :pointer))

(cffi:defcfun ("leveldb_delete" %leveldb-delete) :void
  (db :pointer) (options :pointer)
  (key :pointer) (keylen :size)
  (errptr :pointer))

(cffi:defcfun ("leveldb_write" %leveldb-write) :void
  (db :pointer) (options :pointer)
  (batch :pointer) (errptr :pointer))

(cffi:defcfun ("leveldb_options_create" %leveldb-options-create) :pointer)
(cffi:defcfun ("leveldb_options_destroy" %leveldb-options-destroy) :void
  (options :pointer))
(cffi:defcfun ("leveldb_options_set_create_if_missing"
               %leveldb-options-set-create-if-missing) :void
  (options :pointer) (flag :uint8))
(cffi:defcfun ("leveldb_options_set_write_buffer_size"
               %leveldb-options-set-write-buffer-size) :void
  (options :pointer) (size :size))
(cffi:defcfun ("leveldb_options_set_max_open_files"
               %leveldb-options-set-max-open-files) :void
  (options :pointer) (n :int))
(cffi:defcfun ("leveldb_options_set_paranoid_checks"
               %leveldb-options-set-paranoid-checks) :void
  (options :pointer) (flag :uint8))
(cffi:defcfun ("leveldb_options_set_compression"
               %leveldb-options-set-compression) :void
  (options :pointer) (compression :int))  ; 0 = none, 1 = snappy

(cffi:defcfun ("leveldb_readoptions_create" %leveldb-readoptions-create) :pointer)
(cffi:defcfun ("leveldb_readoptions_destroy" %leveldb-readoptions-destroy) :void
  (options :pointer))

(cffi:defcfun ("leveldb_writeoptions_create" %leveldb-writeoptions-create) :pointer)
(cffi:defcfun ("leveldb_writeoptions_destroy" %leveldb-writeoptions-destroy) :void
  (options :pointer))
(cffi:defcfun ("leveldb_writeoptions_set_sync"
               %leveldb-writeoptions-set-sync) :void
  (options :pointer) (flag :uint8))

(cffi:defcfun ("leveldb_writebatch_create" %leveldb-writebatch-create) :pointer)
(cffi:defcfun ("leveldb_writebatch_destroy" %leveldb-writebatch-destroy) :void
  (batch :pointer))
(cffi:defcfun ("leveldb_writebatch_clear" %leveldb-writebatch-clear) :void
  (batch :pointer))
(cffi:defcfun ("leveldb_writebatch_put" %leveldb-writebatch-put) :void
  (batch :pointer)
  (key :pointer) (keylen :size)
  (val :pointer) (vallen :size))
(cffi:defcfun ("leveldb_writebatch_delete" %leveldb-writebatch-delete) :void
  (batch :pointer)
  (key :pointer) (keylen :size))

;; libc bindings — LevelDB returns malloc'd buffers from leveldb_get and
;; errptr, which we copy out then free. memcpy is the fast bulk-copy
;; primitive for value buffers.

(cffi:defcfun ("free" %libc-free) :void (ptr :pointer))
(cffi:defcfun ("memcpy" %libc-memcpy) :pointer
  (dst :pointer) (src :pointer) (n :size))

(defvar *libleveldb-loaded* nil)

(defun ensure-libleveldb-loaded ()
  "Load libleveldb on first call; no-op subsequently."
  (unless *libleveldb-loaded*
    (cffi:use-foreign-library libleveldb)
    (setf *libleveldb-loaded* t)))

;;;; Error handling. LevelDB reports errors via `char** errptr`: caller
;;;; passes a pointer to a NULL pointer; on success it stays NULL, on
;;;; error LevelDB malloc's an error string and writes it through. The
;;;; caller is responsible for freeing the string and signaling.

(defun %check-errptr (errptr)
  "Signal a Lisp error if ERRPTR contains a non-NULL malloc'd message,
freeing the C string before raising."
  (let ((msg-ptr (cffi:mem-ref errptr :pointer)))
    (unless (cffi:null-pointer-p msg-ptr)
      (let ((msg (cffi:foreign-string-to-lisp msg-ptr)))
        (%libc-free msg-ptr)
        (error "LevelDB error: ~A" msg)))))

(defmacro with-errptr ((var) &body body)
  "Allocate a stack-local char** ERRPTR pre-initialized to NULL, run BODY,
then check for an error message. Mandatory wrapper for any %leveldb-*
function that takes an errptr."
  `(cffi:with-foreign-object (,var :pointer)
     (setf (cffi:mem-ref ,var :pointer) (cffi:null-pointer))
     (multiple-value-prog1 (progn ,@body)
       (%check-errptr ,var))))

;;;; Options creation/destruction. Most callers won't need these; the
;;;; cached options above cover open/get/put/delete/write. These exist
;;;; for users who need custom-tuned options (e.g., paranoid_checks off
;;;; for a one-time bulk import).

(defun leveldb-make-options (&key (create-if-missing t)
                                  (write-buffer-size (* 4 1024 1024))
                                  (max-open-files 64)
                                  (paranoid-checks t)
                                  (compression nil))
  "Allocate a leveldb_options_t. Defaults follow Core's GetOptions
(dbwrapper.cpp:139-) for the chainstate DB: no compression, paranoid
checks on, small write buffer. Caller must call leveldb-destroy-options."
  (ensure-libleveldb-loaded)
  (let ((opts (%leveldb-options-create)))
    (%leveldb-options-set-create-if-missing opts (if create-if-missing 1 0))
    (%leveldb-options-set-write-buffer-size opts write-buffer-size)
    (%leveldb-options-set-max-open-files opts max-open-files)
    (%leveldb-options-set-paranoid-checks opts (if paranoid-checks 1 0))
    (%leveldb-options-set-compression opts (if compression 1 0))
    opts))

(defun leveldb-destroy-options (options)
  (%leveldb-options-destroy options))

;;;; DB lifecycle.

(defun leveldb-open (path &optional options)
  "Open or create a LevelDB at PATH. Returns an opaque handle. Caller
must call leveldb-close. OPTIONS, if NIL, are created and destroyed
internally with defaults."
  (ensure-libleveldb-loaded)
  (let* ((own-options (null options))
         (opts (or options (leveldb-make-options))))
    (unwind-protect
         (with-errptr (errptr)
           (%leveldb-open opts (namestring path) errptr))
      (when own-options (leveldb-destroy-options opts)))))

(defun leveldb-close (db)
  (%leveldb-close db))

(defmacro with-leveldb ((var path &optional options) &body body)
  `(let ((,var (leveldb-open ,path ,options)))
     (unwind-protect (progn ,@body)
       (leveldb-close ,var))))

(defun leveldb-destroy-db (path)
  "Remove the LevelDB directory at PATH and all its contents."
  (ensure-libleveldb-loaded)
  (let ((opts (leveldb-make-options)))
    (unwind-protect
         (with-errptr (errptr)
           (%leveldb-destroy-db opts (namestring path) errptr))
      (leveldb-destroy-options opts))))

;;;; Per-key operations. We create writeoptions/readoptions per call. A
;;;; future refactor should cache these (Core keeps one set per
;;;; CDBWrapper) but a naive defvar cache hit a libleveldb-side issue
;;;; that needs more investigation. Per-call cost is one malloc/free
;;;; pair — acceptable for the first pass.

(defmacro with-write-options ((var &key sync) &body body)
  "Allocate a leveldb_writeoptions_t bound to VAR, optionally with SYNC=T,
destroy on unwind."
  `(let ((,var (%leveldb-writeoptions-create)))
     (unwind-protect
          (progn
            (when ,sync (%leveldb-writeoptions-set-sync ,var 1))
            ,@body)
       (%leveldb-writeoptions-destroy ,var))))

(defmacro with-read-options ((var) &body body)
  `(let ((,var (%leveldb-readoptions-create)))
     (unwind-protect (progn ,@body)
       (%leveldb-readoptions-destroy ,var))))

(declaim (inline leveldb-put leveldb-get leveldb-delete))

(defun leveldb-put (db key val &key sync)
  "Write KEY -> VAL to DB."
  (declare (type (simple-array (unsigned-byte 8) (*)) key val))
  (with-write-options (wopts :sync sync)
    (with-errptr (errptr)
      (cffi:with-pointer-to-vector-data (kptr key)
        (cffi:with-pointer-to-vector-data (vptr val)
          (%leveldb-put db wopts kptr (length key) vptr (length val) errptr))))))

(defun leveldb-get (db key)
  "Return the value for KEY as a fresh byte vector, or NIL if absent."
  (declare (type (simple-array (unsigned-byte 8) (*)) key))
  (with-read-options (ropts)
    (cffi:with-foreign-object (vallen :size)
      (with-errptr (errptr)
        (cffi:with-pointer-to-vector-data (kptr key)
          (let ((val-ptr (%leveldb-get db ropts kptr (length key) vallen errptr)))
            (unless (cffi:null-pointer-p val-ptr)
              (unwind-protect
                   (let* ((n (cffi:mem-ref vallen :size))
                          (out (make-array n :element-type '(unsigned-byte 8))))
                     ;; memcpy via libc — much faster than a per-byte
                     ;; mem-aref loop for the ~50-200 byte UTXO values.
                     (cffi:with-pointer-to-vector-data (out-ptr out)
                       (%libc-memcpy out-ptr val-ptr n))
                     out)
                (%libc-free val-ptr)))))))))

(defun leveldb-delete (db key &key sync)
  (declare (type (simple-array (unsigned-byte 8) (*)) key))
  (with-write-options (wopts :sync sync)
    (with-errptr (errptr)
      (cffi:with-pointer-to-vector-data (kptr key)
        (%leveldb-delete db wopts kptr (length key) errptr)))))

;;;; WriteBatch — Core's CDBBatch equivalent. The bulk of flush traffic
;;;; goes through here: thousands of puts/deletes accumulated, then a
;;;; single leveldb-write commits them atomically.

(defun leveldb-make-writebatch ()
  (ensure-libleveldb-loaded)
  (%leveldb-writebatch-create))

(defun leveldb-destroy-writebatch (batch)
  (%leveldb-writebatch-destroy batch))

(defun leveldb-writebatch-clear (batch)
  (%leveldb-writebatch-clear batch))

(declaim (inline leveldb-writebatch-put leveldb-writebatch-delete))

(defun leveldb-writebatch-put (batch key val)
  (declare (type (simple-array (unsigned-byte 8) (*)) key val))
  (cffi:with-pointer-to-vector-data (kptr key)
    (cffi:with-pointer-to-vector-data (vptr val)
      (%leveldb-writebatch-put batch kptr (length key) vptr (length val)))))

(defun leveldb-writebatch-delete (batch key)
  (declare (type (simple-array (unsigned-byte 8) (*)) key))
  (cffi:with-pointer-to-vector-data (kptr key)
    (%leveldb-writebatch-delete batch kptr (length key))))

(defun leveldb-write (db batch &key sync)
  "Atomically apply BATCH to DB."
  (with-write-options (wopts :sync sync)
    (with-errptr (errptr)
      (%leveldb-write db wopts batch errptr))))

(defmacro with-leveldb-writebatch ((var) &body body)
  `(let ((,var (leveldb-make-writebatch)))
     (unwind-protect (progn ,@body)
       (leveldb-destroy-writebatch ,var))))
