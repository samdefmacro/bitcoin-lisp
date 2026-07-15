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
  "Transaction index state."
  (base-path nil :type (or null pathname))
  (index (make-hash-table :test 'equalp) :type hash-table)  ; txid -> file-offset
  (file-stream nil)  ; Open file stream for appending
  (entry-count 0 :type (unsigned-byte 64))
  (enabled nil :type boolean))

(defconstant +txindex-entry-size+ 68
  "Size of each txindex entry in bytes: 32 (txid) + 32 (block-hash) + 4 (position).")

(defun txindex-file-path (base-path)
  "Get the txindex file path from base data directory."
  (merge-pathnames "txindex.dat" (pathname base-path)))

(defun init-tx-index (base-path &key (enabled t))
  "Initialize a transaction index at BASE-PATH.
If ENABLED is nil, creates a disabled index that ignores add operations."
  (let ((txindex (make-tx-index
                  :base-path (pathname base-path)
                  :enabled enabled)))
    (when enabled
      (load-tx-index txindex))
    txindex))

(defun close-tx-index (txindex)
  "Close the txindex file stream."
  (when (tx-index-file-stream txindex)
    (close (tx-index-file-stream txindex))
    (setf (tx-index-file-stream txindex) nil)))

(defun ensure-txindex-stream (txindex)
  "Ensure the txindex file stream is open for appending."
  (unless (tx-index-file-stream txindex)
    (let ((path (txindex-file-path (tx-index-base-path txindex))))
      (ensure-directories-exist path)
      (setf (tx-index-file-stream txindex)
            (open path
                  :direction :output
                  :if-exists :append
                  :if-does-not-exist :create
                  :element-type '(unsigned-byte 8))))))

(defun txindex-add (txindex txid block-hash tx-position)
  "Add or UPDATE a transaction's location in the index (upsert).
TXID is a 32-byte transaction hash.
BLOCK-HASH is the 32-byte hash of the containing block.
TX-POSITION is the transaction's position in the block (0 = coinbase).
Core's txindex only processes block connects, and a connect OVERWRITES any
existing entry for the txid (index/txindex.cpp CustomAppend batch-writes
unconditionally); nothing is ever erased on disconnect (index/base.h:136
CustomRemove defaults to a no-op and txindex does not override it). The
upsert is what re-points a transaction that was disconnected by a reorg and
re-mined in the new chain. An early return on an existing txid here used to
leave such transactions pointing at the stale branch — or, combined with the
old disconnect-time removal, entirely unindexed. The file stays append-only:
the in-memory map takes the new offset, and LOAD-TX-INDEX's sequential replay
is last-entry-wins, so restarts resolve to the newest location too.
Returns T on success, NIL if index is disabled."
  (unless (tx-index-enabled txindex)
    (return-from txindex-add nil))
  ;; Calculate file offset for this entry
  (let ((offset (* (tx-index-entry-count txindex) +txindex-entry-size+)))
    ;; Write to file
    (ensure-txindex-stream txindex)
    (let ((stream (tx-index-file-stream txindex)))
      ;; Write txid (32 bytes)
      (write-sequence txid stream)
      ;; Write block-hash (32 bytes)
      (write-sequence block-hash stream)
      ;; Write tx-position (4 bytes, little-endian)
      (write-byte (logand tx-position #xFF) stream)
      (write-byte (logand (ash tx-position -8) #xFF) stream)
      (write-byte (logand (ash tx-position -16) #xFF) stream)
      (write-byte (logand (ash tx-position -24) #xFF) stream)
      ;; Flush to ensure durability
      (force-output stream))
    ;; Update in-memory index
    (setf (gethash (copy-seq txid) (tx-index-index txindex)) offset)
    (incf (tx-index-entry-count txindex)))
  t)

(defun txindex-lookup (txindex txid)
  "Look up a transaction in the index.
Returns a TX-LOCATION struct if found, NIL otherwise."
  (unless (tx-index-enabled txindex)
    (return-from txindex-lookup nil))
  (let ((offset (gethash txid (tx-index-index txindex))))
    (unless offset
      (return-from txindex-lookup nil))
    ;; Read entry from file
    (let ((path (txindex-file-path (tx-index-base-path txindex))))
      (with-open-file (stream path
                              :direction :input
                              :element-type '(unsigned-byte 8))
        (file-position stream (+ offset 32))  ; Skip txid, read block-hash
        (let ((block-hash (make-array 32 :element-type '(unsigned-byte 8))))
          (read-sequence block-hash stream)
          ;; Read tx-position (4 bytes, little-endian)
          (let ((pos (logior (read-byte stream)
                             (ash (read-byte stream) 8)
                             (ash (read-byte stream) 16)
                             (ash (read-byte stream) 24))))
            (make-tx-location :block-hash block-hash
                              :tx-position pos)))))))

(defun txindex-remove (txindex txid)
  "Remove a transaction from the in-memory index.
Note: This does not remove the entry from the file (append-only).
The entry is simply unmarked in memory.
Returns T if removed, NIL if not found."
  (unless (tx-index-enabled txindex)
    (return-from txindex-remove nil))
  (remhash txid (tx-index-index txindex)))

(defun txindex-contains-p (txindex txid)
  "Check if a transaction is in the index."
  (and (tx-index-enabled txindex)
       (not (null (gethash txid (tx-index-index txindex))))))

(defun txindex-count (txindex)
  "Return the number of indexed transactions."
  (hash-table-count (tx-index-index txindex)))

(defun load-tx-index (txindex)
  "Load the transaction index from disk.
Rebuilds the in-memory hash table from the file.
Returns T if loaded, NIL if no file exists."
  (let ((path (txindex-file-path (tx-index-base-path txindex))))
    (unless (probe-file path)
      (return-from load-tx-index nil))
    ;; Clear existing index
    (clrhash (tx-index-index txindex))
    (setf (tx-index-entry-count txindex) 0)
    ;; Read file and rebuild index
    (with-open-file (stream path
                            :direction :input
                            :element-type '(unsigned-byte 8))
      (let ((file-size (file-length stream)))
        (loop for offset from 0 below file-size by +txindex-entry-size+
              do (let ((txid (make-array 32 :element-type '(unsigned-byte 8))))
                   (let ((bytes-read (read-sequence txid stream)))
                     (when (< bytes-read 32)
                       (return)))  ; Incomplete entry, stop
                   ;; Skip block-hash and position (we only need txid for index)
                   (file-position stream (+ offset +txindex-entry-size+))
                   ;; Add to in-memory index
                   (setf (gethash txid (tx-index-index txindex)) offset)
                   (incf (tx-index-entry-count txindex))))))
    t))

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
