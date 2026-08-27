(in-package #:bitcoin-lisp.storage)

;;; Coins-view-db: LevelDB-backed UTXO view.
;;;
;;; Mirrors Bitcoin Core's CCoinsViewDB (refs/bitcoin/src/txdb.cpp:53).
;;; This is the persistent layer: every operation hits LevelDB. A future
;;; PR will add an in-memory caching layer on top (Core's
;;; CCoinsViewCache) so reads/writes during a block's validation pass
;;; don't all round-trip to disk.
;;;
;;; Key encoding follows Core's CoinEntry (txdb.cpp:43-49): a single
;;; namespacing byte ('C' = 0x43) followed by the outpoint. Core uses
;;; VARINT for the vout; we use a fixed 4-byte LE vout for simplicity
;;; and to match our in-memory key layout. A future PR can switch to
;;; VARINT for closer Core compatibility if/when that matters.
;;;
;;; Value encoding reuses our existing utxo-entry layout (i64 value,
;;; u32 height, u8 coinbase, u32 script-len + script bytes). Core uses
;;; TxOutCompression for value/script compression; we leave that for
;;; a future optimization PR — it's domain-specific compression that
;;; doesn't affect correctness, just disk footprint.

(defconstant +db-prefix-coin+ #x43             ; 'C' — same as Core's DB_COIN
  "1-byte namespacing prefix for coin entries in the LevelDB.")

(defconstant +db-prefix-migration-marker+ #x4D ; 'M'
  "1-byte namespacing prefix for the utxoset.dat → LevelDB migration
marker. coins-view-migration.lisp writes this as its last step so an
interrupted migration is detectable on the next startup.")

(defconstant +db-prefix-best-block+ #x42        ; 'B' — Core's DB_BEST_BLOCK
  "1-byte prefix for the block hash this UTXO set corresponds to.

Core keeps this INSIDE the coins database and writes it in the same batch as
the coin changes (CCoinsViewDB::BatchWrite, txdb.cpp:100-159), so the UTXO
state and the block it belongs to are one object that cannot disagree. We have
historically kept the tip in a separate chainstate.dat, which can and does
disagree — that divergence is the root of the reorg-interrupt hazard and of the
BIP30 replay brick. See docs/coins-db-best-block-plan.md; this key is phase 1.")

(defun encode-best-block-key ()
  "The single key under which the coins DB stores its own best block."
  (make-array 1 :element-type '(unsigned-byte 8)
                :initial-element +db-prefix-best-block+))

;; Future prefixes for DB_BEST_BLOCK ('B') and DB_HEAD_BLOCKS ('H')
;; will land here when those move into the same LevelDB.

(defconstant +coin-key-bytes+ 37
  "LevelDB key size: 1 prefix + 32 txid + 4 vout.")

(defconstant +coin-key-vout-offset+ 33
  "Byte offset of the 4-byte LE vout within a coin key.")

(defconstant +coin-value-fixed-bytes+ 17
  "Fixed-size part of an encoded coin value: 8 value + 4 height + 1
coinbase + 4 script-len. Variable part is the script bytes that follow.")

(declaim (inline encode-coin-key))
(defun encode-coin-key (utxo-key)
  "Encode UTXO-KEY as the 37-byte LevelDB key (prefix + txid + LE vout)."
  (declare (type utxo-key utxo-key))
  (let ((bytes (make-array +coin-key-bytes+ :element-type '(unsigned-byte 8))))
    (setf (aref bytes 0) +db-prefix-coin+)
    (write-u64-le-into bytes 1 (uk-a utxo-key))
    (write-u64-le-into bytes 9 (uk-b utxo-key))
    (write-u64-le-into bytes 17 (uk-c utxo-key))
    (write-u64-le-into bytes 25 (uk-d utxo-key))
    (write-u32-le-into bytes +coin-key-vout-offset+ (uk-vout utxo-key))
    bytes))

(defun encode-coin-value (entry)
  "Encode a utxo-entry to bytes. Format matches what save-utxo-set
writes per entry, so a migration tool can read both layouts."
  (declare (type utxo-entry entry))
  (let* ((script (utxo-entry-script-pubkey entry))
         (script-len (length script))
         (bytes (make-array (+ +coin-value-fixed-bytes+ script-len)
                            :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) script))
    ;; Inlined to avoid byte-buf's 1024-byte default allocation when the
    ;; typical UTXO value is ~42 bytes.
    (let ((value (utxo-entry-value entry)))
      (declare (type (signed-byte 64) value))
      (let ((uv (logand value #xFFFFFFFFFFFFFFFF)))
        (declare (type (unsigned-byte 64) uv))
        (write-u64-le-into bytes 0 uv)))
    (write-u32-le-into bytes 8 (utxo-entry-height entry))
    (setf (aref bytes 12) (if (utxo-entry-coinbase entry) 1 0))
    (write-u32-le-into bytes 13 script-len)
    (replace bytes script :start1 +coin-value-fixed-bytes+)
    bytes))

(defun decode-coin-value (bytes)
  "Inverse of encode-coin-value. Direct aref reads — no byte-reader
struct alloc on the per-block hot path."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes)
           (optimize (speed 3) (safety 1)))
  (let* ((value-u64 (logior (aref bytes 0)
                            (ash (aref bytes 1) 8)
                            (ash (aref bytes 2) 16)
                            (ash (aref bytes 3) 24)
                            (ash (aref bytes 4) 32)
                            (ash (aref bytes 5) 40)
                            (ash (aref bytes 6) 48)
                            (ash (aref bytes 7) 56)))
         ;; Convert u64 → i64 (utxo-entry-value is signed-byte 64).
         (value (if (zerop (logand value-u64 (ash 1 63)))
                    value-u64
                    (- value-u64 (ash 1 64))))
         (height (logior (aref bytes 8)
                         (ash (aref bytes 9) 8)
                         (ash (aref bytes 10) 16)
                         (ash (aref bytes 11) 24)))
         (coinbase (= (aref bytes 12) 1))
         (script-len (logior (aref bytes 13)
                             (ash (aref bytes 14) 8)
                             (ash (aref bytes 15) 16)
                             (ash (aref bytes 16) 24)))
         (script (subseq bytes
                         +coin-value-fixed-bytes+
                         (+ +coin-value-fixed-bytes+ script-len))))
    (make-utxo-entry :value value
                     :script-pubkey script
                     :height height
                     :coinbase coinbase)))

;;;; Public API
;;;;
;;;; coins-view-db is opaque from the outside; callers use the
;;;; coins-view-db-* functions. The struct itself is just a handle.

(defstruct (coins-view-db (:conc-name cvdb-))
  (db nil))

(defun open-coins-view-db (path)
  "Open or create the coins-view LevelDB at PATH. Caller must call
close-coins-view-db. Use with-coins-view-db for RAII-style scope.

max-open-files is leveldb's own default of 1000, which is also what Core uses
on 64-bit Unix (dbwrapper.cpp SetMaxOpenFiles: it lowers the value to 64 only
when sizeof(void*) < 8).

It was 4096, and that cost us the mainnet node. Core's comment there spells out
why the ceiling matters: a large count is safe on Windows `because the handles
do not interfere with select() loops', and safe on 64-bit Unix only up to that
amount, `because up to that amount LevelDB will use an mmap implementation that
does not use extra file descriptors (the fds are closed after being mmap-ed)' —
`increasing the value beyond the default is dangerous because LevelDB will fall
back to a non-mmap implementation when the file count is too large'.

That is exactly what happened on 2026-08-17/18: past the mmap threshold the
chainstate held ~3100 REAL descriptors, every new socket was allocated above
fd 1023, and usocket's select-based readiness check signalled
`The value <fd+1> is not of type (UNSIGNED-BYTE 10)' on each one until the node
sat at zero peers. The accompanying comment claimed 64 was \"leveldb's default\"
and that Core \"pairs 64 with a large block cache\"; both are wrong, and the
mistake is what made 4096 look like a free win.

The original tuning problem was real — at 64 the table cache thrashes
Table::Open/mmap/munmap on every point-Get, ~12% of IBD CPU by sb-sprof at
h≈280k — but 1000 is well clear of that and stays inside the mmap regime, where
cached tables cost address space rather than descriptors."
  (make-coins-view-db
   :db (leveldb-open-tuned
        path
        ;; Core gives the coins DB its own share of -dbcache and a bloom
        ;; filter; we gave it neither, so every negative coin lookup — most of
        ;; them during IBD, since an input's coin is checked before it is
        ;; found — read a data block per level off disk.
        :cache-bytes (if *cache-sizes* (cache-sizes-coins-db *cache-sizes*) 0)
        :max-open-files 1000)))

(defun close-coins-view-db (view)
  (when (cvdb-db view)
    (leveldb-close (cvdb-db view))
    (setf (cvdb-db view) nil)))

(defmacro with-coins-view-db ((var path) &body body)
  `(let ((,var (open-coins-view-db ,path)))
     (unwind-protect (progn ,@body)
       (close-coins-view-db ,var))))

(declaim (inline coins-view-db-get
                 coins-view-db-put
                 coins-view-db-erase
                 coins-view-db-has-p))

(defun coins-view-db-get (view utxo-key)
  "Return the utxo-entry stored under UTXO-KEY, or NIL if absent.
Mirrors CCoinsViewDB::GetCoin (txdb.cpp:72)."
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (let ((bytes (leveldb-get (cvdb-db view) (encode-coin-key utxo-key))))
    (when bytes (decode-coin-value bytes))))

(defun coins-view-db-put (view utxo-key entry)
  "Write ENTRY under UTXO-KEY. NOT atomic with other ops — use
coins-view-db-write-batch for multi-op atomicity."
  (declare (type coins-view-db view)
           (type utxo-key utxo-key)
           (type utxo-entry entry))
  (leveldb-put (cvdb-db view)
               (encode-coin-key utxo-key)
               (encode-coin-value entry)))

(defun coins-view-db-erase (view utxo-key)
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (leveldb-delete (cvdb-db view) (encode-coin-key utxo-key)))

(defun coins-view-db-best-block (view)
  "The block hash this UTXO set corresponds to, or NIL if never recorded.

Core's CCoinsView::GetBestBlock. NIL means the database predates this key —
every write path now sets it, so NIL only ever appears on a chainstate written
by an older build, not on one that has been flushed since."
  (declare (type coins-view-db view))
  (leveldb-get (cvdb-db view) (encode-best-block-key)))

(defun coins-view-batch-set-best-block (batch block-hash)
  "Stage the coins DB's best-block pointer in BATCH.

Staging it in the SAME batch as the coin puts and erases is the whole point:
the UTXO changes and the block they belong to then commit or fail together, so
the pair can never be observed or persisted in disagreement (Core does this in
CCoinsViewDB::BatchWrite, txdb.cpp:100-159)."
  (declare (type (simple-array (unsigned-byte 8) (32)) block-hash))
  (leveldb-writebatch-put batch (encode-best-block-key) block-hash))

(defun coins-view-db-has-p (view utxo-key)
  "Mirrors CCoinsViewDB::HaveCoin (txdb.cpp:81)."
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (not (null (leveldb-get (cvdb-db view) (encode-coin-key utxo-key)))))

(defun coins-view-db-erase-all-coins (view)
  "Delete every coin ('C'-prefixed) entry from the base LevelDB, in bounded
writebatches, leaving non-coin keys (e.g. the 'M' migration marker) intact.
Used by chainstate reindex to empty the UTXO set. Returns the count erased."
  (declare (type coins-view-db view))
  (let ((db (cvdb-db view))
        (erased 0)
        (batch (leveldb-make-writebatch))
        (pending 0))
    (unwind-protect
         (progn
           (with-leveldb-iterator (iter db)
             (leveldb-iter-seek-to-first iter)
             (loop
               (unless (leveldb-iter-valid-p iter) (return))
               (let ((k (leveldb-iter-key iter)))
                 (when (and (>= (length k) 1) (= (aref k 0) +db-prefix-coin+))
                   (leveldb-writebatch-delete batch k)
                   (incf pending)
                   (incf erased)
                   ;; Commit in chunks so the writebatch can't grow unbounded
                   ;; across a multi-million-entry set.
                   (when (>= pending 100000)
                     (leveldb-write db batch :sync nil)
                     (leveldb-destroy-writebatch batch)
                     (setf batch (leveldb-make-writebatch) pending 0))))
               (leveldb-iter-next iter)))
           ;; Final batch always written with :sync t — even when empty
           ;; (coin count a multiple of the chunk size) — so the whole wipe,
           ;; whose earlier chunks were :sync nil in the same WAL, is durable
           ;; before callers persist state that assumes the coins are gone.
           (leveldb-write db batch :sync t))
      (leveldb-destroy-writebatch batch))
    erased))

;;;; Batch writes — the CDBBatch equivalent. The expected pattern is:
;;;; build a list of ops during a block's validation pass (adds + erases
;;;; for each input/output), then commit them atomically. Core's
;;;; CCoinsViewCache::BatchWrite drives this via CDBBatch under the hood.

;;;; Low-level batch API. BATCH is a libleveldb writebatch handle;
;;;; coins-view-batch-put / -erase encode the key/value and append to it.
;;;; Used by coins-view-cache-flush to avoid materializing an
;;;; intermediate ops list.

(defmacro with-coins-view-batch ((batch view &key sync) &body body)
  "Bind BATCH to a fresh writebatch on VIEW's underlying LevelDB. BODY
accumulates ops via coins-view-batch-put / -erase. On normal exit the
batch is committed atomically; on non-local exit the cleanup forms of
multiple-value-prog1 are skipped, so nothing is written. SYNC=T forces
fsync on commit."
  (let ((view-sym (gensym "VIEW"))
        (sync-sym (gensym "SYNC")))
    `(let ((,view-sym ,view)
           (,sync-sym ,sync))
       (with-leveldb-writebatch (,batch)
         (multiple-value-prog1 (progn ,@body)
           (leveldb-write (cvdb-db ,view-sym) ,batch :sync ,sync-sym))))))

(declaim (inline coins-view-batch-put coins-view-batch-erase))

(defun coins-view-batch-put (batch utxo-key entry)
  "Stage a put of ENTRY under UTXO-KEY in BATCH."
  (declare (type utxo-key utxo-key) (type utxo-entry entry))
  (leveldb-writebatch-put batch
                          (encode-coin-key utxo-key)
                          (encode-coin-value entry)))

(defun coins-view-batch-erase (batch utxo-key)
  "Stage an erase of UTXO-KEY in BATCH."
  (declare (type utxo-key utxo-key))
  (leveldb-writebatch-delete batch (encode-coin-key utxo-key)))

(defun coins-view-db-write-batch (view ops &key sync)
  "Atomically apply OPS to VIEW. Each op is either
  (:put utxo-key utxo-entry) or (:erase utxo-key).
Convenience wrapper over with-coins-view-batch for callers that
naturally produce an ops list (tests, ad-hoc bulk loads). Hot-path
callers should use with-coins-view-batch directly."
  (declare (type coins-view-db view))
  (with-coins-view-batch (batch view :sync sync)
    (dolist (op ops)
      (ecase (first op)
        (:put   (coins-view-batch-put batch (second op) (third op)))
        (:erase (coins-view-batch-erase batch (second op)))))))
