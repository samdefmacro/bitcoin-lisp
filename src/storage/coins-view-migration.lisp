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
;;; :sync T so it's durable past an OS crash.
;;; coins-view-db-migration-complete-p checks for the marker; absent →
;;; caller should wipe the LevelDB and re-run.

(defconstant +migration-batch-size+ 50000
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

(defun coins-view-db-migration-complete-p (view)
  "Return T if a UTXO migration has been completed into the coins VIEW.
A successful migration writes a one-byte marker as its last step; a missing
marker means the LevelDB is empty, never migrated, or was interrupted
mid-migration -- in any of those cases the caller should treat it as
not-yet-migrated. It asks the view start-up has already opened, so chainstate/
is opened once, as Core opens its coins database once (Chainstate::InitCoinsDB,
validation.cpp:1910-1925)."
  (and (leveldb-get (cvdb-db view) *migration-marker-key*) t))

(defun migrate-utxoset-dat-to-leveldb (dat-path leveldb-path
                                        &key (batch-size +migration-batch-size+)
                                             into-view)
  "One-shot migration of the flat-file UTXO set at DAT-PATH into a
LevelDB at LEVELDB-PATH -- or into INTO-VIEW, that LevelDB's coins view when
the caller already has it open. Progress is reported via log-info; on
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
      (bl.log:log-info "Migrating ~D UTXO entries from ~A → ~A"
                             total dat-path leveldb-path)
      (flet ((migrate-into (view)
               (flet ((open-batch () (setf batch (leveldb-make-writebatch)))
                      (commit-batch ()
                        (when batch
                          (leveldb-write (cvdb-db view) batch)
                          (leveldb-destroy-writebatch batch)
                          (setf batch nil
                                in-batch 0)
                          (bl.log:log-info "Migration progress: ~D / ~D" written total))))
                 (open-batch)
                 (unwind-protect
                      (progn
                        (maphash (lambda (key entry)
                                   (coins-view-batch-put view batch key entry)
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
                            :sync t)))
        (if into-view
            (migrate-into into-view)
            (with-coins-view-db (view leveldb-path)
              (migrate-into view))))
      ;; Release the ~5 GB in-memory utxo-set back to the OS before the
      ;; caller continues — they have no reason to keep it.
      #+sbcl (sb-ext:gc :full t)
      (bl.log:log-info "Migration complete: ~D entries written" written)
      written)))


;;;; Upgrade: this tree's pre-2026-09-29 coin layout -> Core's.
;;;;
;;;; Until 2026-09-29 a coin was stored under 'C' + txid + a fixed 4-byte LE
;;;; vout (37 bytes) as an i64 value, u32 height, u8 coinbase, u32 script
;;;; length and the script, plain, under the all-zero obfuscation key. Core's
;;;; CoinEntry key is 34-36 bytes for any vout a block can hold (a 37-byte
;;;; VARINT needs a vout of 2,113,664 or more), so the key LENGTH tells the two
;;;; layouts apart record by record, and both can share the database while it
;;;; converts.
;;;;
;;;; The procedure is Core's own 0.15 conversion, CCoinsViewDB::Upgrade
;;;; (txdb.cpp in v0.15.0, removed since): walk the old records in key order,
;;;; write each coin in the new layout and erase the old record IN THE SAME
;;;; BATCH, commit every ~16 MiB, compact the range just converted, log a
;;;; percentage from the txid's leading bytes, and stop between batches when
;;;; the node is asked to. Every durable state is a mix of converted and
;;;; unconverted records that the next start simply continues from. Two things
;;;; are ours: each batch also records the last key it converted
;;;; (*LEGACY-UPGRADE-MARKER-KEY*), so a resumed run seeks there rather than
;;;; walking the converted part again, and the FIRST batch installs a random
;;;; obfuscation key and rewrites 'B'/'H' under it, as a database Core created
;;;; would have. The final batch erases the marker; from then on the database
;;;; is byte-compatible with Core's.

(defconstant +legacy-coin-key-bytes+ 37
  "Length of a coin key in the pre-2026-09-29 layout: 'C' + txid + LE u32 vout.")

(defparameter *legacy-upgrade-marker-key*
  (let ((name (map 'list #'char-code "coins_upgrade")))
    (coerce (list* 14 0 name) '(simple-array (unsigned-byte 8) (*))))
  "Key of the upgrade's progress record, shaped like Core's obfuscate_key
record (a CompactSize-prefixed \\000-led string) so it sorts ahead of every
Core record. Its value is the last old-layout key the upgrade converted.
Present only while a conversion is unfinished.")

(defparameter *legacy-upgrade-batch-bytes* (ash 1 24)
  "Size at which the upgrade commits a batch: Core 0.15's `batch_size = 1 << 24'.")

(declaim (inline %legacy-coin-key-p))
(defun %legacy-coin-key-p (key)
  (declare (type (simple-array (unsigned-byte 8) (*)) key))
  (and (= (length key) +legacy-coin-key-bytes+)
       (= (aref key 0) +db-prefix-coin+)))

(defun %decode-legacy-coin-record (key value)
  "An old-layout record as (values txid vout utxo-entry)."
  (declare (type (simple-array (unsigned-byte 8) (*)) key value))
  (let* ((br (bl.bytes:make-byte-reader :data value))
         (amount (bl.bytes:br-read-i64-le br))
         (height (bl.bytes:br-read-u32-le br))
         (coinbase (= 1 (bl.bytes:br-read-u8 br)))
         (script (bl.bytes:br-read-bytes br (bl.bytes:br-read-u32-le br))))
    (values (subseq key 1 +coin-key-txid-end+)
            (bl.bytes:br-read-u32-le
             (bl.bytes:make-byte-reader :data key :pos +coin-key-txid-end+))
            (make-utxo-entry :value amount :script-pubkey script
                             :height height :coinbase coinbase))))

(defun coins-view-db-legacy-layout-p (view)
  "T when VIEW's database still holds coins in this tree's pre-2026-09-29
layout: an upgrade is under way (its marker is there) or the first coin record
has an old 37-byte key. One get and one seek."
  (declare (type coins-view-db view))
  (let ((db (cvdb-db view)))
    (or (and (leveldb-get db *legacy-upgrade-marker-key*) t)
        (with-leveldb-iterator (iter db)
          (leveldb-iter-seek iter (make-array 1 :element-type '(unsigned-byte 8)
                                                :initial-element +db-prefix-coin+))
          (and (leveldb-iter-valid-p iter)
               (%legacy-coin-key-p (leveldb-iter-key iter)))))))

(defun %upgrade-percentage (key)
  "Core 0.15's progress estimate from a key's first two txid bytes."
  (round (* 100 (+ (* 256 (aref key 1)) (aref key 2))) 65536))

(defun %install-fresh-obfuscation-key (view batch)
  "Stage, in the upgrade's first BATCH, a random obfuscation key and the 'B'
and 'H' records re-encoded under it, and switch VIEW to that key. The old
layout was always stored plain; a database holding a live key is not ours."
  (let ((old (%read-obfuscation-key (cvdb-db view))))
    (when (obfuscation-key-active-p old)
      (storage-error "A coins database in the old layout holds a non-zero obfuscation key; restart with -reindex-chainstate")))
  (let ((best (coins-view-db-best-block view))
        (heads (coins-view-db-head-blocks view))
        (key (make-obfuscation-key)))
    (leveldb-writebatch-put batch *obfuscation-key-key* (%obfuscation-key-record key))
    (setf (cvdb-obfuscation view) key)
    (when best (coins-view-batch-set-best-block view batch best))
    (when heads
      (coins-view-batch-set-head-blocks view batch (first heads) (second heads)))))

(defun upgrade-coins-view-db (view &key (batch-bytes *legacy-upgrade-batch-bytes*))
  "Convert VIEW's database from this tree's pre-2026-09-29 coin layout to
Core's, in place (see the section comment). Returns T when the database is in
Core's layout -- at once when it already was -- and NIL when the node was asked
to stop part way; the next call continues where this one committed. Memory
stays bounded by BATCH-BYTES: one batch and one iterator, re-opened per batch
so the tables a compaction replaced can be deleted."
  (declare (type coins-view-db view))
  (let* ((db (cvdb-db view))
         (resume (leveldb-get db *legacy-upgrade-marker-key*)))
    (unless (or resume (coins-view-db-legacy-layout-p view))
      (return-from upgrade-coins-view-db t))
    (bl.log:log-info "Upgrading utxo-set database~:[~; (resuming)~]..." resume)
    (let ((batch (leveldb-make-writebatch))
          (start (or resume (make-array 1 :element-type '(unsigned-byte 8)
                                          :initial-element +db-prefix-coin+)))
          (converted 0)
          (reported (if resume -1 0))
          (last nil))
      (unwind-protect
           (progn
             (unless resume (%install-fresh-obfuscation-key view batch))
             (loop
               (let ((bytes 0) (more nil))
                 ;; One batch: convert records from START on until the batch
                 ;; is full or the old records run out.
                 (with-leveldb-iterator (iter db)
                   (leveldb-iter-seek iter start)
                   (loop while (and (leveldb-iter-valid-p iter) (<= bytes batch-bytes))
                         do (let ((k (leveldb-iter-key iter)))
                              (unless (= (aref k 0) +db-prefix-coin+) (return))
                              ;; A key in Core's layout is one this upgrade
                              ;; already wrote for the txid it stopped in.
                              (when (%legacy-coin-key-p k)
                                (multiple-value-bind (txid vout entry)
                                    (%decode-legacy-coin-record k (leveldb-iter-value iter))
                                  (unless (script-unspendable-p (utxo-entry-script-pubkey entry))
                                    (incf bytes (coins-view-batch-put
                                                 view batch (make-utxo-key txid vout) entry)))
                                  (leveldb-writebatch-delete batch k)
                                  (incf bytes (+ 2 (length k)))
                                  (incf converted)
                                  (setf last k)))
                              (leveldb-iter-next iter)))
                   (setf more (and (leveldb-iter-valid-p iter)
                                   (= (aref (leveldb-iter-key iter) 0) +db-prefix-coin+))))
                 (unless more (return))
                 (leveldb-writebatch-put batch *legacy-upgrade-marker-key* last)
                 (leveldb-write db batch :sync nil)
                 (leveldb-writebatch-clear batch)
                 (leveldb-compact-range db start last)
                 (let ((pct (%upgrade-percentage last)))
                   (when (> (floor pct 10) reported)
                     (bl.log:log-info "Upgrading utxo-set database: [~D%] ~:D coins converted"
                                      pct converted)
                     (setf reported (floor pct 10))))
                 (setf start last)
                 (when (bl.ctx:interrupt-requested-p)
                   (bl.log:log-info "Upgrading utxo-set database: [CANCELLED] after ~:D coins; the next start continues"
                                    converted)
                   (return-from upgrade-coins-view-db nil))))
             (leveldb-writebatch-delete batch *legacy-upgrade-marker-key*)
             (leveldb-write db batch :sync t)
             (when last (leveldb-compact-range db start last))
             (bl.log:log-info "Upgrading utxo-set database: [DONE] ~:D coins converted" converted)
             t)
        (leveldb-destroy-writebatch batch)))))
