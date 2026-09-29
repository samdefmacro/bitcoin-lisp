(in-package #:bitcoin-lisp.storage)

;;; Coins-view-db: Bitcoin Core's chainstate LevelDB, byte for byte.
;;;
;;; Mirrors CCoinsViewDB (refs/bitcoin/src/txdb.cpp, txdb.h) over CDBWrapper
;;; (dbwrapper.cpp), so a chainstate/ written by Core opens here and one
;;; written here opens in Core. The records:
;;;
;;;   \000obfuscate_key  CompactSize 8 + the 8-byte XOR key, stored PLAIN
;;;                      (dbwrapper.cpp:253-261): drawn at random when the
;;;                      database is created, XORed over every other VALUE
;;;                      (CDBBatch::WriteImpl, CDBWrapper::Read); keys are
;;;                      never obfuscated.
;;;   'C' txid VARINT(n) CoinEntry (txdb.cpp:43-50) -> Coin (coins.h:63-79):
;;;                      VARINT(height*2 + coinbase) then TxOutCompression
;;;                      (compressor.h:98-116) -- the codec in
;;;                      src/serialization/compressor.lisp, shared with the
;;;                      assumeutxo snapshot and the undo files.
;;;   'B'                DB_BEST_BLOCK, the uint256 of the block the coins are at.
;;;   'H'                DB_HEAD_BLOCKS, std::vector<uint256>{new, old} while a
;;;                      flush is between its first and its last batch.
;;;   'c'                DB_COINS, Core's pre-0.15 per-transaction records:
;;;                      never written, only looked for (NeedsUpgrade).
;;;
;;; ⚠️ VARINT is NOT order-preserving across encoded lengths: 16512 is
;;; 80 80 00 and sorts before 256, 81 00. The raw key walk of a txid's coins
;;; (Core's CCoinsViewDBCursor) is therefore not numeric vout order, which is
;;; why kernel/coinstats.cpp buffers each txid into a std::map before hashing
;;; and UTXO-SET-ITERATE regroups the same way.
;;;
;;; Two records are ours, and Core ignores both: 'M', the marker of the
;;; one-shot utxoset.dat import (coins-view-migration.lisp), and
;;; *LEGACY-UPGRADE-MARKER-KEY*, present only while a database in this tree's
;;; pre-2026-09-29 layout is being converted (UPGRADE-COINS-VIEW-DB).

(defconstant +db-prefix-coin+ #x43             ; 'C' — Core's DB_COIN
  "1-byte namespacing prefix for coin entries in the LevelDB.")

(defconstant +db-prefix-migration-marker+ #x4D ; 'M'
  "1-byte namespacing prefix for the utxoset.dat → LevelDB migration
marker. coins-view-migration.lisp writes this as its last step so an
interrupted migration is detectable on the next startup.")

(defconstant +db-prefix-best-block+ #x42        ; 'B' — Core's DB_BEST_BLOCK
  "1-byte key of the block hash this UTXO set corresponds to (txdb.cpp:24).
CCoinsViewDB::BatchWrite erases it in a flush's first batch and writes it in
the last (txdb.cpp:126-160), so the coins and the block they belong to cannot
disagree once the flush has committed. See docs/coins-db-best-block-plan.md.")

(defun encode-best-block-key ()
  "The single key under which the coins DB stores its own best block."
  (make-array 1 :element-type '(unsigned-byte 8)
                :initial-element +db-prefix-best-block+))

(defconstant +db-prefix-head-blocks+ #x48       ; 'H' — Core's DB_HEAD_BLOCKS
  "1-byte key of the in-progress marker a partial-batch flush leaves: the block
the coins are being moved TO and the one they were moved FROM
(CCoinsViewDB::BatchWrite, txdb.cpp:126-129). Present only while a flush is
between its first and its last batch; REPLAY-COINS-DB-BLOCKS resolves it.")

(defun encode-head-blocks-key ()
  "The single key of the coins DB's DB_HEAD_BLOCKS record."
  (make-array 1 :element-type '(unsigned-byte 8)
                :initial-element +db-prefix-head-blocks+))

(defvar *coins-db-batch-bytes* (* 32 1024 1024)
  "-dbbatchsize: the size at which a coins flush commits a partial batch (Core
DEFAULT_DB_CACHE_BATCH, kernel/caches.h:15; CCoinsViewDB::BatchWrite,
txdb.cpp:147-160).")

(defvar *coins-db-crash-ratio* 0
  "-dbcrashratio, a hidden test option: after each partial coins batch, exit
at a 1-in-N chance, logging `Simulating a crash. Goodbye.' (txdb.cpp:150-157).
0 never does.")

(defun %simulate-crash ()
  "Core's `_Exit(0)': no unwinding, no flush, no shutdown."
  (sb-ext:exit :code 0 :abort t))

(defvar *coins-db-simulated-crash* '%simulate-crash
  "What -dbcrashratio's crash does: end the process, as Core's _Exit(0).
Tests bind it to a non-local exit to observe the database the crash leaves.")

(defconstant +coin-key-txid-end+ 33
  "Byte offset where a coin key's VARINT vout starts: 1 prefix + 32 txid.")

(defun encode-coin-key (utxo-key)
  "UTXO-KEY as Core's CoinEntry (txdb.cpp:43-50): 'C', the 32-byte txid, then
the vout as a VARINT (serialize.h:424-440) -- 34 to 36 bytes for any vout a
block can hold."
  (declare (type utxo-key utxo-key))
  (let ((buf (bl.bytes:make-byte-buf
              :data (make-array 40 :element-type '(unsigned-byte 8)))))
    (bl.bytes:bb-write-u8 buf +db-prefix-coin+)
    (bl.bytes:bb-write-u64-le buf (uk-a utxo-key))
    (bl.bytes:bb-write-u64-le buf (uk-b utxo-key))
    (bl.bytes:bb-write-u64-le buf (uk-c utxo-key))
    (bl.bytes:bb-write-u64-le buf (uk-d utxo-key))
    (bl.ser:bb-write-core-varint buf (uk-vout utxo-key))
    (bl.bytes:bb-finish buf)))

(defun decode-coin-key (key)
  "Core CCoinsViewDBCursor::GetKey: KEY's (values txid vout), or NIL when KEY
is not a 'C' record or its VARINT does not parse."
  (declare (type (simple-array (unsigned-byte 8) (*)) key))
  (when (and (> (length key) +coin-key-txid-end+)
             (= (aref key 0) +db-prefix-coin+))
    (let ((br (bl.bytes:make-byte-reader :data key :pos +coin-key-txid-end+)))
      (let ((vout (ignore-errors (bl.ser:br-read-core-varint br))))
        (when (and vout (<= vout #xFFFFFFFF))
          (values (subseq key 1 +coin-key-txid-end+) vout))))))

(defun encode-coin-value (entry)
  "ENTRY as Core serializes a Coin (coins.h:63-69), before obfuscation:
VARINT(height*2 + coinbase), then the compressed amount and script."
  (declare (type utxo-entry entry))
  (let* ((script (utxo-entry-script-pubkey entry))
         (buf (bl.bytes:make-byte-buf
               :data (make-array (+ 24 (length script))
                                 :element-type '(unsigned-byte 8)))))
    (bl.ser:bb-write-compressed-coin buf
                                     (utxo-entry-height entry)
                                     (utxo-entry-coinbase entry)
                                     (logand (utxo-entry-value entry)
                                             #xFFFFFFFFFFFFFFFF)
                                     script)
    (bl.bytes:bb-finish buf)))

(defun decode-coin-value (bytes)
  "Core Coin::Unserialize (coins.h:71-79) over BYTES, already de-obfuscated.
A value read back as uint64 is Core's int64 nValue, so the top bit is the sign.
Signals on a record that ends early."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
  (multiple-value-bind (height coinbase value script)
      (bl.ser:br-read-compressed-coin (bl.bytes:make-byte-reader-from bytes))
    (let ((v (logand value #xFFFFFFFFFFFFFFFF)))
      (make-utxo-entry :value (if (logbitp 63 v) (- v (ash 1 64)) v)
                       :script-pubkey script
                       :height (logand height #xFFFFFFFF)
                       :coinbase coinbase))))

;;;; Public API
;;;;
;;;; coins-view-db is opaque from the outside; callers use the
;;;; coins-view-db-* functions. The struct itself is just a handle.

(defstruct (coins-view-db (:conc-name cvdb-))
  (db nil)
  ;; CDBWrapper::m_obfuscation: the 8-byte XOR key every value is stored
  ;; under, read from the database at open (all zero = stored plain).
  (obfuscation (zero-obfuscation-key)
   :type (simple-array (unsigned-byte 8) (*))))

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
cached tables cost address space rather than descriptors.

The open ends with Core's obfuscation-key step (%READ-OR-WRITE-OBFUSCATION-KEY),
which is also the read that finds a damaged database at open time; the key it
answers is the one every value of this handle is XORed with."
  (let ((db (leveldb-open-tuned
             path
             ;; Core gives the coins DB its own share of -dbcache and a bloom
             ;; filter; we gave it neither, so every negative coin lookup —
             ;; most of them during IBD, since an input's coin is checked
             ;; before it is found — read a data block per level off disk.
             :cache-bytes (if *cache-sizes* (cache-sizes-coins-db *cache-sizes*) 0)
             :max-open-files 1000)))
    (handler-bind ((error (lambda (e)
                            (declare (ignore e))
                            (leveldb-close db))))
      (make-coins-view-db :db db
                          :obfuscation (%read-or-write-obfuscation-key db path)))))

(defparameter *obfuscation-key-key*
  (let ((name (map 'list #'char-code "obfuscate_key")))
    (coerce (list* 14 0 name) '(simple-array (unsigned-byte 8) (*))))
  "Core's OBFUSCATION_KEY (dbwrapper.h:192), `\\000obfuscate_key', serialized as
the std::string it is written as: a CompactSize length of 14, then the bytes.
It sorts ahead of every coins-DB record, so it is the first key of the
database. The block tree database reads the same record.")

(defun %obfuscation-key-record (key)
  "KEY as Core serializes it (util/obfuscation.h:44-51): a CompactSize 8, then
the eight bytes."
  (let ((v (make-array 9 :element-type '(unsigned-byte 8) :initial-element 8)))
    (replace v key :start1 1)
    v))

(defun %read-obfuscation-key (db &key verify-checksums)
  "DB's stored XOR key (8 bytes), or NIL when it has no key record. Core's
Obfuscation::Unserialize refuses a key that is not exactly 8 bytes
(util/obfuscation.h:53-59)."
  (let ((v (leveldb-get db *obfuscation-key-key* :verify-checksums verify-checksums)))
    (when v
      (unless (and (= (length v) 9) (= (aref v 0) 8))
        (storage-error "Obfuscation key size should be exactly 8 bytes long"))
      (subseq v 1))))

(defun %read-or-write-obfuscation-key (db path)
  "Core's CDBWrapper constructor tail for the coins DB (dbwrapper.cpp:253-261,
`.obfuscate = true' at validation.cpp:1921): read the obfuscation key; on a
database that is still EMPTY draw a RANDOM one and write it (plain); log
`Using obfuscation key'. Returns the key -- all zero for a database that has
none, which Core reads as `stored plain' (Obfuscation's operator bool).

The read is what makes a damaged coins database a failure at OPEN, Core's
`Error opening coins database' (node/chainstate.cpp:89-97): the key is the
first record, so it sits in the first block of the oldest table, and the read
verifies that block's checksum. feature_init.py:160 overwrites 200 bytes at
offset 150 of every chainstate/*.ldb and expects that sentence."
  (let ((name (string-right-trim "/" (namestring path)))
        (key (%read-obfuscation-key db :verify-checksums t)))
    (unless (or key
                (with-leveldb-iterator (iter db)
                  (leveldb-iter-seek-to-first iter)
                  (leveldb-iter-valid-p iter)))
      (setf key (make-obfuscation-key))
      (leveldb-put db *obfuscation-key-key* (%obfuscation-key-record key))
      (bl.log:log-info "Wrote new obfuscation key for ~A: ~A"
                       name (bl.crypto:bytes-to-hex key)))
    (let ((key (or key (zero-obfuscation-key))))
      (bl.log:log-info "Using obfuscation key for ~A: ~A"
                       name (bl.crypto:bytes-to-hex key))
      key)))

(declaim (inline %xor-value))
(defun %xor-value (view bytes)
  "BYTES XORed in place with VIEW's key from offset 0 -- CDBBatch::WriteImpl
on the way in, CDBWrapper::Read on the way out (dbwrapper.cpp:173-180, :218).
Its own inverse; BYTES must be a fresh vector nobody else holds."
  (obfuscate! bytes (cvdb-obfuscation view)))

(defun close-coins-view-db (view)
  (when (cvdb-db view)
    (leveldb-close (cvdb-db view))
    (setf (cvdb-db view) nil)))

(defmacro with-coins-view-db ((var path) &body body)
  `(let ((,var (open-coins-view-db ,path)))
     (unwind-protect (progn ,@body)
       (close-coins-view-db ,var))))

(defun coins-view-db-get (view utxo-key)
  "Return the utxo-entry stored under UTXO-KEY, or NIL if absent.
Mirrors CCoinsViewDB::GetCoin (txdb.cpp:72)."
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (let ((bytes (leveldb-get (cvdb-db view) (encode-coin-key utxo-key))))
    (when bytes (decode-coin-value (%xor-value view bytes)))))

(defun coins-view-db-put (view utxo-key entry)
  "Write ENTRY under UTXO-KEY. NOT atomic with other ops — use
coins-view-db-write-batch for multi-op atomicity."
  (declare (type coins-view-db view)
           (type utxo-key utxo-key)
           (type utxo-entry entry))
  (leveldb-put (cvdb-db view)
               (encode-coin-key utxo-key)
               (%xor-value view (encode-coin-value entry))))

(defun coins-view-db-erase (view utxo-key)
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (leveldb-delete (cvdb-db view) (encode-coin-key utxo-key)))

(defun coins-view-db-best-block (view)
  "The block hash this UTXO set corresponds to, or NIL if never recorded.

Core's CCoinsViewDB::GetBestBlock (txdb.cpp:83-88): the DB_BEST_BLOCK value,
de-obfuscated, read as a uint256; absent (or short) is the null hash, NIL here.
A flush erases it in its first batch and writes it back in its last, so NIL is
also what a database part way through a partial-batch flush answers, and
COINS-VIEW-DB-HEAD-BLOCKS then says which transition it was in."
  (declare (type coins-view-db view))
  (let ((v (leveldb-get (cvdb-db view) (encode-best-block-key))))
    (when (and v (>= (length v) 32))
      (subseq (%xor-value view v) 0 32))))

(defun coins-view-db-head-blocks (view)
  "Core CCoinsViewDB::GetHeadBlocks (txdb.cpp:90-96): the DB_HEAD_BLOCKS record
as a list of hashes, the new tip first -- empty when no flush is in progress.
The value is a serialized std::vector<uint256>: a CompactSize count, then the
hashes, obfuscated like every value."
  (declare (type coins-view-db view))
  (let ((v (leveldb-get (cvdb-db view) (encode-head-blocks-key))))
    (when (and v (plusp (length v)))
      (%xor-value view v)
      (loop for i from 0 below (aref v 0)
            while (<= (+ 33 (* 32 i)) (length v))
            collect (subseq v (+ 1 (* 32 i)) (+ 33 (* 32 i)))))))

(defun %head-blocks-value (new old)
  "NEW and OLD as Core's two-hash vector, before obfuscation; OLD NIL is the
null hash."
  (let ((v (make-array 65 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref v 0) 2)
    (replace v new :start1 1)
    (when old (replace v old :start1 33))
    v))

(defun coins-view-batch-set-head-blocks (view batch new old)
  "Stage DB_HEAD_BLOCKS = {NEW, OLD} in BATCH (txdb.cpp:126-129)."
  (leveldb-writebatch-put batch (encode-head-blocks-key)
                          (%xor-value view (%head-blocks-value new old))))

(defun coins-view-batch-set-best-block (view batch block-hash)
  "Stage the coins DB's best-block pointer in BATCH, obfuscated as Core's
CDBBatch::Write obfuscates every value.

Staging it in the SAME batch as the coin puts and erases is the whole point:
the UTXO changes and the block they belong to then commit or fail together, so
the pair can never be observed or persisted in disagreement (Core does this in
CCoinsViewDB::BatchWrite, txdb.cpp:100-159)."
  (declare (type (simple-array (unsigned-byte 8) (32)) block-hash))
  (leveldb-writebatch-put batch (encode-best-block-key)
                          (%xor-value view (copy-seq block-hash))))

(defun coins-view-db-has-p (view utxo-key)
  "Mirrors CCoinsViewDB::HaveCoin (txdb.cpp:81)."
  (declare (type coins-view-db view) (type utxo-key utxo-key))
  (and (leveldb-get (cvdb-db view) (encode-coin-key utxo-key)) t))

(defun coins-view-db-any-coin-p (view)
  "T iff the base LevelDB holds at least one coin ('C'-prefixed) entry.

Core's is_coinsview_empty asks GetBestBlock().IsNull() (node/chainstate.cpp:69),
which is enough there because DB_BEST_BLOCK lives in the database the wipe
destroys. This is the same question asked of the coins themselves, for the
databases an older build could leave with coins gone and a pointer standing.
One iterator seek, no full scan."
  (declare (type coins-view-db view))
  (with-leveldb-iterator (iter (cvdb-db view))
    (leveldb-iter-seek iter (make-array 1 :element-type '(unsigned-byte 8)
                                          :initial-element +db-prefix-coin+))
    (and (leveldb-iter-valid-p iter)
         (let ((k (leveldb-iter-key iter)))
           (and (>= (length k) 1) (= (aref k 0) +db-prefix-coin+))))))

(defconstant +db-prefix-legacy-coins+ #x63     ; 'c' -- Core's DB_COINS
  "Key prefix of the per-transaction coin records Core wrote before 0.15
(txdb.cpp:27, deprecated by commit 1088b02f). Nothing here writes it; it is
only looked for, to refuse such a database the way Core does.")

(defun coins-view-db-needs-upgrade-p (view)
  "T iff the coins LevelDB still holds a pre-0.15 per-transaction record
(Core CCoinsViewDB::NeedsUpgrade, txdb.cpp:32-39: a seek to DB_COINS that
lands on a valid key). Core refuses to load such a chainstate and names
-reindex-chainstate as the way out (node/chainstate.cpp:103-109); a wipe
makes the question moot, which is why the caller skips it under -reindex and
-reindex-chainstate. One iterator seek, no scan."
  (declare (type coins-view-db view))
  (with-leveldb-iterator (iter (cvdb-db view))
    (leveldb-iter-seek iter (make-array 1 :element-type '(unsigned-byte 8)
                                          :initial-element +db-prefix-legacy-coins+))
    (and (leveldb-iter-valid-p iter)
         (let ((k (leveldb-iter-key iter)))
           (and (>= (length k) 1) (= (aref k 0) +db-prefix-legacy-coins+))))))

(defun coins-view-db-erase-all-coins (view)
  "Empty the base LevelDB: delete every coin ('C') entry AND the best-block
('B') pointer, in bounded writebatches, keeping only the 'M' migration marker
and the obfuscation key record, which the final batch replaces with a fresh
RANDOM key that VIEW then uses (Core's wiped database gets a new key from the
very constructor that wiped it, dbwrapper.cpp:230-259). Used by chainstate
reindex. Returns the count of COINS erased.

The pointer goes with the coins, and that is the whole point rather than a
tidy-up: Core's -reindex-chainstate opens the coins DB with should_wipe, a
leveldb::DestroyDB of the whole database (node/chainstate.cpp:93,
dbwrapper.cpp:39-41), and CCoinsViewDB::BatchWrite erases and rewrites
DB_BEST_BLOCK inside the coin batch (txdb.cpp:128,159) -- so an emptied coins
DB can never name a block. Ours could: the pointer survived a wipe that only
deleted 'C' keys, and a crash before the rebuild's first flush then left the
node claiming the pre-reindex tip over an EMPTY UTXO set, with startup
reconciliation moving chainstate.dat FORWARD onto it and logging 'Recovered'.

The keep-list is explicit ('M' and the key) rather than a delete-'C'-only rule, so a
prefix added later is erased by default instead of silently surviving. 'B'
sorts before 'C', so it also leaves in the FIRST committed chunk: from the
first commit onward a partially-wiped database names no block either."
  (declare (type coins-view-db view))
  (let ((db (cvdb-db view))
        (erased 0)
        (batch (leveldb-make-writebatch))
        (pending 0))
    (unwind-protect
         (progn
           ;; Staged before the walk so it is in the first chunk regardless of
           ;; where the key sorts; deleting an absent key is a no-op.
           (leveldb-writebatch-delete batch (encode-best-block-key))
           (incf pending)
           (with-leveldb-iterator (iter db)
             (leveldb-iter-seek-to-first iter)
             (loop
               (unless (leveldb-iter-valid-p iter) (return))
               (let ((k (leveldb-iter-key iter)))
                 (when (and (>= (length k) 1)
                            (/= (aref k 0) +db-prefix-migration-marker+)
                            (not (equalp k *obfuscation-key-key*)))
                   (leveldb-writebatch-delete batch k)
                   (incf pending)
                   (when (= (aref k 0) +db-prefix-coin+) (incf erased))
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
           (let ((key (make-obfuscation-key)))
             (leveldb-writebatch-put batch *obfuscation-key-key*
                                     (%obfuscation-key-record key))
             (leveldb-write db batch :sync t)
             (setf (cvdb-obfuscation view) key)))
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

(defun coins-view-batch-put (view batch utxo-key entry)
  "Stage a put of ENTRY under UTXO-KEY in BATCH, obfuscated with VIEW's key
(CDBBatch::Write, dbwrapper.h:98-107). Returns the bytes the record adds to
the batch, LevelDB's WriteBatch::ApproximateSize growth: a tag, two length
prefixes, the key and the value."
  (declare (type coins-view-db view) (type utxo-key utxo-key) (type utxo-entry entry))
  (let ((k (encode-coin-key utxo-key))
        (v (%xor-value view (encode-coin-value entry))))
    (leveldb-writebatch-put batch k v)
    (+ 3 (length k) (length v))))

(defun coins-view-batch-erase (batch utxo-key)
  "Stage an erase of UTXO-KEY in BATCH. Returns the bytes it adds to the batch."
  (declare (type utxo-key utxo-key))
  (let ((k (encode-coin-key utxo-key)))
    (leveldb-writebatch-delete batch k)
    (+ 2 (length k))))

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
        (:put   (coins-view-batch-put view batch (second op) (third op)))
        (:erase (coins-view-batch-erase batch (second op)))))))
