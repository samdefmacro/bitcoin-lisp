(in-package #:bitcoin-lisp.storage)

;;;; Migrating per-block files into flat block files (block-file-format P4)
;;;;
;;;; The transition for a node that already holds years of one-file-per-block
;;;; storage. Bitcoin Core has no counterpart: it has only ever had the flat
;;;; format, so it has never needed to convert anything. That absence is why
;;;; this file is conservative in ways Core's block storage is not.
;;;;
;;;; Dual read means both forms work at every point, so the conversion does not
;;;; have to be atomic — and deliberately is not:
;;;;
;;;; - It runs in HEIGHT ORDER, which is not cosmetic. A flat file prunes whole,
;;;;   and only when its entire height range lies inside the prunable window
;;;;   (%PRUNABLE-FLAT-FILES). Converting in hash or arrival order would give
;;;;   every file a range spanning the chain, and a pruned node would silently
;;;;   stop reclaiming space forever.
;;;; - It converts one block at a time and unlinks the legacy file only after
;;;;   the flat record is durable AND has been read back. A crash costs at most
;;;;   one duplicated block, never a lost one.
;;;; - It is RESUMABLE and idempotent: a block already flat is skipped, so
;;;;   re-running continues where the last call stopped.
;;;; - It takes a budget, so an operator converts a slice, watches the node, and
;;;;   continues — rather than committing a live node to hours of unattended
;;;;   rewriting.

(defun %legacy-block-p (store hash)
  "T when HASH is stored as a per-block file rather than as a flat record."
  (let ((located (gethash hash (block-store-index store))))
    (and located (not (flat-file-pos-p located)))))

(defun count-legacy-blocks (store)
  "How many blocks are still in per-block files. 0 means the migration is done."
  (let ((n 0))
    (maphash (lambda (hash located)
               (declare (ignore hash))
               (unless (flat-file-pos-p located) (incf n)))
             (block-store-index store))
    n))

(defun %resolve-duplicate-block (store hash)
  "Reconcile a block that exists BOTH as a flat record and as a per-block file.
Returns :SWEPT when the per-block file was removed, :RECOVERED when the index
was pointed back at it, or NIL when there is no duplicate.

This is the crash window between the flat write and the unlink, made harmless.
INIT-BLOCK-STORE indexes the per-block files first and the flat records second,
so after such a crash the flat record wins the index and the per-block file
becomes an orphan nothing reads — while its bytes still count toward the
pruning total, making a pruned node prune earlier than it should.

Which copy wins is decided by which one READS, never by which one the index
happens to name. If the flat record reads back the orphan goes; if it does not,
the per-block file is the surviving copy and the index is put back on it, which
also makes the block eligible for the migration to retry."
  (let ((legacy-path (block-file-path store hash)))
    (when (probe-file legacy-path)
      (cond
        ((get-block store hash)
         (let ((size (file-size-bytes legacy-path)))
           (ignore-errors (delete-file legacy-path))
           (when size
             (decf (block-store-total-bytes store)
                   (min size (block-store-total-bytes store))))
           :swept))
        (t
         (setf (gethash hash (block-store-index store)) legacy-path)
         :recovered)))))

(defun %migrate-one-block (store entry)
  "Convert one legacy block to a flat record. Returns :MIGRATED, :SKIPPED (not
legacy, or unreadable), or NIL when the flat record did not read back — which
the caller must treat as a reason to stop, not to continue."
  (let ((hash (block-index-entry-hash entry))
        (height (block-index-entry-height entry)))
    (cond
      ((not (%legacy-block-p store hash))
       (case (%resolve-duplicate-block store hash)
         (:swept
          (bitcoin-lisp:log-info
           "Migration: swept an orphaned per-block file at height ~D left by an ~
            interrupted migration" height))
         (:recovered
          (bitcoin-lisp:log-warn
           "Migration: the flat record for height ~D does not read; the ~
            per-block file is the surviving copy and the index now points at it"
           height)))
       :skipped)
      (t
       (let ((block (get-block store hash)))
         (cond
           ((null block)
            ;; Unreadable. GET-BLOCK has already pruned it for re-download;
            ;; there is nothing to convert and stopping here would strand every
            ;; block above it.
            (bitcoin-lisp:log-warn
             "Migration: block at height ~D (~A) is unreadable; skipped"
             height (bitcoin-lisp.crypto:bytes-to-hex hash))
            :skipped)
           (t
            (let ((legacy-path (block-file-path store hash))
                  (old-located (gethash hash (block-store-index store)))
                  (old-total (block-store-total-bytes store)))
              ;; STORE-BLOCK already replaces the legacy file's contribution to
              ;; the running byte total (its OLD-SIZE branch stats the per-block
              ;; file), so the unlink below must NOT decrement it again.
              (let ((*flat-block-files* t))
                (store-block store block :height height))
              ;; Read it back through the flat path while the legacy copy is
              ;; still on disk. This is the whole safety argument: the legacy
              ;; file is the only copy, and a migration that lost blocks would
              ;; be indistinguishable from corruption afterwards.
              (let ((check (get-block store hash)))
                (cond
                  ((and check
                        (equalp hash
                                (bitcoin-lisp.serialization:block-header-hash
                                 (bitcoin-lisp.serialization:bitcoin-block-header check))))
                   (when (probe-file legacy-path)
                     (ignore-errors (delete-file legacy-path)))
                   :migrated)
                  (t
                   ;; Keeping the per-block file is not enough on its own:
                   ;; STORE-BLOCK has already repointed the index at the flat
                   ;; record, so dual read would serve the copy that just failed
                   ;; to read back and the good file would never be consulted
                   ;; again. Put the index and the byte total back the way they
                   ;; were. The written flat record is left in place as dead
                   ;; bytes — rewinding the file is a far more dangerous
                   ;; operation than leaking a record, and a rescan re-derives
                   ;; the index from the files anyway.
                   (setf (gethash hash (block-store-index store)) old-located
                         (block-store-total-bytes store) old-total)
                   (bitcoin-lisp:log-error
                    "Migration: block at height ~D (~A) did not read back from its flat ~
                     file; the per-block file is kept and the migration stops"
                    height (bitcoin-lisp.crypto:bytes-to-hex hash))
                   nil)))))))))))

(defun migrate-blocks-to-flat-files (store chain-state &key (max-blocks 1000)
                                                           (start-height 0))
  "Convert up to MAX-BLOCKS legacy per-block files into flat records, walking the
active chain upward from START-HEIGHT.

Returns (values migrated next-height remaining), where NEXT-HEIGHT is where a
following call should resume and REMAINING is COUNT-LEGACY-BLOCKS afterwards.
Call it until REMAINING is 0.

Only blocks on the ACTIVE chain are converted. Side-chain blocks keep their
per-block files: they have no place in a height-ordered flat file, they are a
handful of blocks, and dual read keeps them served."
  (let ((tip-height (chain-state-best-height chain-state))
        (migrated 0)
        (next start-height))
    (when (> start-height tip-height)
      (return-from migrate-blocks-to-flat-files
        (values 0 start-height (count-legacy-blocks store))))
    ;; One backward walk from the tip collects the window in ascending order.
    ;; Asking for 256 heights at a time instead would re-walk the chain from the
    ;; tip on every call — quadratic in the chain length, which at mainnet
    ;; height is the difference between a walk and a wait.
    (let ((entries (active-chain-entries-from chain-state start-height
                                              (1+ (- tip-height start-height)))))
      (dolist (entry entries)
        (when (>= migrated max-blocks) (return))
        (setf next (1+ (block-index-entry-height entry)))
        (let ((result (%migrate-one-block store entry)))
          (cond
            ((eq result :migrated) (incf migrated))
            ((eq result :skipped))
            (t ;; read-back failure: stop, and report the height that failed as
               ;; the resume point so a retry starts exactly there.
             (setf next (block-index-entry-height entry))
             (return))))))
    (values migrated next (count-legacy-blocks store))))
