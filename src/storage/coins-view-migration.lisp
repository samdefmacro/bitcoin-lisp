(in-package #:bitcoin-lisp.storage)

;;; Migration: utxoset.dat → LevelDB.
;;;
;;; The flat-file utxoset.dat written by save-utxo-set holds the full
;;; in-memory UTXO set as a single CRC32'd blob. Once the node switches
;;; to LevelDB-backed storage (coins-view-db), existing operators with
;;; a populated utxoset.dat need a one-shot import so they don't lose
;;; their synced state.
;;;
;;; Strategy: load the source via existing load-utxo-set (peak heap ≈
;;; source-file-size + parsed-utxo-set ≈ ~7 GB at testnet4 h=135k),
;;; then walk via maphash and stream into LevelDB in batched writes.
;;; A fully streaming load + write variant would lower peak memory but
;;; is significant complexity for a one-shot operation — defer.
;;;
;;; Crash safety: a migration that's interrupted partway leaves the
;;; target LevelDB in an unknown state. We write a one-byte "complete"
;;; marker under +db-prefix-migration-marker+ as the final step, with
;;; :sync T so it's durable past an OS crash. leveldb-utxo-migration-
;;; complete-p checks for the marker; absent → caller should wipe the
;;; LevelDB and re-run.

(defparameter +migration-batch-size+ 50000
  "Number of entries per LevelDB writebatch during migration. Larger
batches trade off peak transient memory and crash-window granularity.
50k × ~100 bytes ≈ 5 MB per batch — modest.")

(defparameter *migration-marker-key*
  (make-array 1 :element-type '(unsigned-byte 8)
                :initial-element +db-prefix-migration-marker+)
  "Constant 1-byte LevelDB key for the migration-complete marker.")

(defparameter *migration-marker-value*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1)
  "Constant 1-byte LevelDB value (any non-empty byte vector works).")

(defun leveldb-utxo-migration-complete-p (leveldb-path)
  "Return T if a UTXO migration has been completed at LEVELDB-PATH.
A successful migration writes a one-byte marker as its last step; a
missing marker means the LevelDB is empty, never migrated, or was
interrupted mid-migration — in any of those cases the caller should
treat the LevelDB as not-yet-migrated."
  (when (probe-file (pathname leveldb-path))
    (with-leveldb (db leveldb-path)
      (not (null (leveldb-get db *migration-marker-key*))))))

(defun migrate-utxoset-dat-to-leveldb (dat-path leveldb-path
                                        &key (batch-size +migration-batch-size+))
  "One-shot migration of the flat-file UTXO set at DAT-PATH into a
LevelDB at LEVELDB-PATH. Progress is reported via log-info; on
completion, the marker write makes the migration idempotent under
restart. Returns the number of UTXO entries written.

Signals an error if the source is missing or load-utxo-set rejects
it (CRC mismatch, version mismatch, truncated file)."
  (unless (probe-file (pathname dat-path))
    (storage-error "source file does not exist: ~A" dat-path))
  (let ((utxo-set (make-utxo-set)))
    (unless (load-utxo-set utxo-set dat-path)
      (storage-error "failed to load source: ~A" dat-path))
    (let* ((total (hash-table-count (utxo-set-entries utxo-set)))
           (written 0)
           (in-batch 0)
           (batch nil))
      (bl:log-info "Migrating ~D UTXO entries from ~A → ~A"
                             total dat-path leveldb-path)
      (with-coins-view-db (view leveldb-path)
        (flet ((open-batch () (setf batch (leveldb-make-writebatch)))
               (commit-batch ()
                 (when batch
                   (leveldb-write (cvdb-db view) batch)
                   (leveldb-destroy-writebatch batch)
                   (setf batch nil
                         in-batch 0)
                   (bl:log-info "Migration progress: ~D / ~D" written total))))
          (open-batch)
          (unwind-protect
               (progn
                 (maphash (lambda (key entry)
                            (coins-view-batch-put batch key entry)
                            (incf written)
                            (incf in-batch)
                            (when (>= in-batch batch-size)
                              (commit-batch)
                              (open-batch)))
                          (utxo-set-entries utxo-set))
                 (commit-batch))
            ;; If maphash signaled mid-batch, drop the unfinished batch
            ;; so we don't leak the libleveldb writebatch.
            (when batch (leveldb-destroy-writebatch batch))))
        ;; Durable marker — fsync so a kernel-level crash here can't
        ;; leave us with a complete-looking but missing-marker DB.
        (leveldb-put (cvdb-db view) *migration-marker-key* *migration-marker-value*
                     :sync t))
      ;; Release the ~5 GB in-memory utxo-set back to the OS before the
      ;; caller continues — they have no reason to keep it.
      #+sbcl (sb-ext:gc :full t)
      (bl:log-info "Migration complete: ~D entries written" written)
      written)))
