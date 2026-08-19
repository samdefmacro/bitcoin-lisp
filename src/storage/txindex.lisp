(in-package #:bitcoin-lisp.storage)

;;; Transaction Index
;;;
;;; Maps transaction IDs to their location in the blockchain.
;;; Uses an append-only file for persistence with an in-memory hash table index.
;;;
;;; File format:
;;;   Each entry: [32-byte txid][32-byte block-hash][4-byte position] = 68 bytes
;;;
;;; The in-memory index maps txid -> file offset for O(1) lookups.

(defstruct tx-location
  "Location of a transaction in the blockchain."
  (block-hash nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (tx-position 0 :type (unsigned-byte 32)))

(defstruct tx-index
  "Transaction index state — a LevelDB index, as Core's TxIndex is.

Core's TxIndex holds only a DB (index/txindex.h:32): ReadTxPos is one DB read
and WriteTxs one batch write (index/txindex.cpp:32-75). Ours used to be an
append-only 68-byte-record FILE plus a FULL IN-MEMORY HASH TABLE of every txid,
rebuilt by walking the entire file on startup, with each lookup re-opening the
file.

At roughly 80 bytes per SBCL equalp entry, mainnet's ~1e9 transactions is on
the order of 100 GB of heap, and startup had to stream tens of GB before
serving anything — so -txindex died of heap exhaustion during backfill on the
network the node claims to support. A hard OOM, not a diagnosable refusal.

Moving to LevelDB deletes the in-memory table, the startup replay and the
per-lookup file open together, and gives the index the persisted best-block
marker it never had."
  (base-path nil :type (or null pathname))
  (db nil)
  (enabled nil :type boolean))

(defconstant +txindex-record-size+ 36
  "Value size: 32 (block-hash) + 4 (tx position, little-endian).")

(defparameter +txindex-key-prefix+ 116
  "ASCII #\t — the per-transaction key prefix, keeping txid keys clear of the
metadata key below.")

(defparameter *txindex-meta-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 66)
  "ASCII #\B: the best-block marker (Core's BaseIndex locator). A single byte,
distinct from the 33-byte transaction keys, so it can never collide.")

(defun txindex-db-path (base-path)
  "Directory of the txindex LevelDB."
  (merge-pathnames "txindex/" (pathname base-path)))

(defun %txindex-key (txid)
  "DB key for TXID: the prefix byte followed by the 32-byte hash."
  (let ((key (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref key 0) +txindex-key-prefix+)
    (replace key txid :start1 1)
    key))

(defun %txindex-encode (block-hash tx-position)
  (let ((v (make-array +txindex-record-size+ :element-type '(unsigned-byte 8))))
    (replace v block-hash)
    (setf (aref v 32) (logand tx-position #xFF)
          (aref v 33) (logand (ash tx-position -8) #xFF)
          (aref v 34) (logand (ash tx-position -16) #xFF)
          (aref v 35) (logand (ash tx-position -24) #xFF))
    v))

(defun init-tx-index (base-path &key (enabled t))
  "Initialize a transaction index at BASE-PATH.
If ENABLED is nil, creates a disabled index that ignores add operations.
No startup replay: the DB is the index."
  (let ((txindex (make-tx-index :base-path (pathname base-path) :enabled enabled)))
    (when enabled
      (let ((path (txindex-db-path base-path)))
        (ensure-directories-exist path)
        (setf (tx-index-db txindex) (leveldb-open path))))
    txindex))

(defun close-tx-index (txindex)
  "Close the txindex database."
  (when (tx-index-db txindex)
    (leveldb-close (tx-index-db txindex))
    (setf (tx-index-db txindex) nil)))

(defun txindex-add (txindex txid block-hash tx-position)
  "Add or UPDATE a transaction's location (upsert).

Core's txindex only processes block connects and a connect OVERWRITES any
existing entry (CustomAppend batch-writes unconditionally); nothing is erased
on disconnect (index/base.h:136 CustomRemove is a no-op and txindex does not
override it). The upsert is what re-points a transaction disconnected by a
reorg and re-mined on the new chain — a plain LevelDB put is that upsert."
  (unless (and (tx-index-enabled txindex) (tx-index-db txindex))
    (return-from txindex-add nil))
  (leveldb-put (tx-index-db txindex)
               (%txindex-key txid)
               (%txindex-encode block-hash tx-position))
  t)

(defun txindex-lookup (txindex txid)
  "Look up a transaction. Returns a TX-LOCATION, or NIL. One DB read."
  (unless (and (tx-index-enabled txindex) (tx-index-db txindex))
    (return-from txindex-lookup nil))
  (let ((v (leveldb-get (tx-index-db txindex) (%txindex-key txid))))
    (when (and v (>= (length v) +txindex-record-size+))
      (make-tx-location
       :block-hash (subseq v 0 32)
       :tx-position (logior (aref v 32)
                            (ash (aref v 33) 8)
                            (ash (aref v 34) 16)
                            (ash (aref v 35) 24))))))

(defun txindex-remove (txindex txid)
  "Delete a transaction's entry. Returns T if the index is live.
Core never removes on disconnect; this exists for callers that manage the
index explicitly."
  (unless (and (tx-index-enabled txindex) (tx-index-db txindex))
    (return-from txindex-remove nil))
  (leveldb-delete (tx-index-db txindex) (%txindex-key txid))
  t)

(defun txindex-contains-p (txindex txid)
  "Check if a transaction is indexed."
  (and (tx-index-enabled txindex)
       (tx-index-db txindex)
       (not (null (leveldb-get (tx-index-db txindex) (%txindex-key txid))))
       t))

(defun txindex-set-best-block (txindex block-hash)
  "Record the block this index is caught up to (Core BaseIndex's locator).
The file-based index had no such marker at all, so nothing could tell whether
it was current."
  (when (and (tx-index-enabled txindex) (tx-index-db txindex))
    (leveldb-put (tx-index-db txindex) *txindex-meta-key* block-hash)
    t))

(defun txindex-best-block (txindex)
  "The block hash this index is caught up to, or NIL."
  (when (and (tx-index-enabled txindex) (tx-index-db txindex))
    (leveldb-get (tx-index-db txindex) *txindex-meta-key*)))

(defun txindex-count (txindex)
  "Number of indexed transactions, by DB scan.

O(n) and deliberately so: LevelDB has no cheap count, and the only caller is a
diagnostic RPC field. The predecessor answered in O(1) from an in-memory table
whose existence was the bug."
  (unless (and (tx-index-enabled txindex) (tx-index-db txindex))
    (return-from txindex-count 0))
  (let ((n 0))
    (with-leveldb-iterator (iter (tx-index-db txindex))
      (leveldb-iter-seek iter (make-array 1 :element-type '(unsigned-byte 8)
                                            :initial-element +txindex-key-prefix+))
      (loop while (leveldb-iter-valid-p iter)
            for key = (leveldb-iter-key iter)
            while (and key (plusp (length key))
                       (= (aref key 0) +txindex-key-prefix+))
            do (incf n) (leveldb-iter-next iter)))
    n))

(defun load-tx-index (txindex)
  "Retained for compatibility; the DB needs no replay.
The file-based index rebuilt a full in-memory map by streaming the whole file
on every startup. Returns T when the index is live."
  (and (tx-index-enabled txindex) (tx-index-db txindex) t))

(defun txindex-add-block (txindex block block-hash)
  "Index all transactions in a block.
BLOCK is a bitcoin-block structure.
BLOCK-HASH is the 32-byte block hash.
Returns the number of transactions indexed."
  (unless (tx-index-enabled txindex)
    (return-from txindex-add-block 0))
  (let ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions block))
        (count 0))
    (loop for tx in txs
          for position from 0
          do (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
               (when (txindex-add txindex txid block-hash position)
                 (incf count))))
    count))

(defun txindex-remove-block (txindex block)
  "Remove all transactions in a block from the in-memory index.
NOT used by the reorg path: Core's txindex never erases entries for
disconnected blocks (stale-branch entries stay resolvable through the
still-stored stale block, and re-mined txs are re-pointed by the connect-time
upsert). Kept as a maintenance utility.
BLOCK is a bitcoin-block structure.
Returns the number of transactions removed from index."
  (unless (tx-index-enabled txindex)
    (return-from txindex-remove-block 0))
  (let ((txs (bitcoin-lisp.serialization:bitcoin-block-transactions block))
        (count 0))
    (dolist (tx txs)
      (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
        (when (txindex-remove txindex txid)
          (incf count))))
    count))

;;; Background Index Building

(defun %txindex-block-indexed-p (txindex block block-hash)
  "T when BLOCK is already fully indexed AT BLOCK-HASH: its LAST transaction's
stored location points into this block. Entries are appended in tx order and
flushed per entry, so the last tx being present at this block implies every
earlier tx of the block was written before it (crash-safe, unlike checking the
coinbase, which is written first). Verifying the stored BLOCK-HASH — not mere
txid presence — matters now that TXINDEX-ADD upserts: after a reorg the txid
can exist but point at a stale branch's block, and the catch-up scan must
re-index it at its active-chain location."
  (let ((last-tx (car (last (bitcoin-lisp.serialization:bitcoin-block-transactions
                             block)))))
    (and last-tx
         (let ((loc (txindex-lookup
                     txindex
                     (bitcoin-lisp.serialization:transaction-hash last-tx))))
           (and loc (equalp (tx-location-block-hash loc) block-hash))))))

(defun build-tx-index (txindex chain-state block-store &key progress-callback)
  "Build the transaction index from existing blocks.
Scans all blocks from genesis to current tip; blocks whose transactions are
already indexed at their active-chain location are skipped (verified via the
block's last transaction, see %TXINDEX-BLOCK-INDEXED-P — a plain
txid-existence check would both bloat the append-only file on every restart
under upsert semantics AND leave stale-branch locations in place after a
reorg that happened while the index was offline).
PROGRESS-CALLBACK, if provided, is called with (height percentage) periodically.
Returns the number of transactions indexed."
  (unless (tx-index-enabled txindex)
    (return-from build-tx-index 0))
  (let* ((current-height (current-height chain-state))
         (total-indexed 0)
         (last-report-time (get-internal-real-time)))
    (loop for height from 0 to current-height
          do (let ((entry (get-block-at-height chain-state height)))
               (when entry
                 (let* ((block-hash (block-index-entry-hash entry))
                        (block (get-block block-store block-hash)))
                   (when (and block
                              (not (%txindex-block-indexed-p txindex block block-hash)))
                     (let ((count (txindex-add-block txindex block block-hash)))
                       (incf total-indexed count))))))
             ;; Report progress every second
             (when progress-callback
               (let ((now (get-internal-real-time)))
                 (when (> (- now last-report-time) internal-time-units-per-second)
                   (let ((pct (if (zerop current-height) 100.0
                                  (* 100.0 (/ height current-height)))))
                     (funcall progress-callback height pct))
                   (setf last-report-time now)))))
    ;; Final progress report
    (when progress-callback
      (funcall progress-callback current-height 100.0))
    total-indexed))
