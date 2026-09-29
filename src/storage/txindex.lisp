(in-package #:bitcoin-lisp.storage)

;;; Transaction Index (Core index/txindex.{h,cpp})
;;;
;;; Maps each confirmed transaction's txid to where it lives on disk:
;;;
;;;   't' || txid(32)  ->  CDiskTxPos   (Core DB_TXINDEX, txindex.cpp:34, 57-67)
;;;   'B'              ->  the best-block CBlockLocator (index-base.lisp)
;;;
;;; the record Core writes, so a Core node started on this datadir reads this
;;; index and ours reads Core's. Genesis is not indexed (txindex.cpp:75-76).
;;;
;;; Two record kinds of our own, under keys Core never reads:
;;;
;;;   'L' || txid(32)  ->  block hash(32) || position in the block (u32 LE)
;;;       for a transaction whose block this node still keeps in a LEGACY
;;;       per-block file, which has no FlatFilePos (see disktxpos.lisp);
;;;   'm'              ->  next height (u32 LE) of an unfinished migration.
;;;
;;; Until 2026-09-29 every record was the 'L' layout under 't', a value Core
;;; cannot read (Core v28.2 started on such an index resolved nothing).
;;; MIGRATE-TXINDEX rewrites them in place; until it has, a 36-byte 't' value
;;; is still read the old way.

(defconstant +txindex-legacy-record-size+ 36
  "The (block hash, u32 position) value of an 'L' record, and of every 't'
record written before the migration. A CDiskTxPos is three VARINTs, at most
15 bytes, so the two can never be confused.")

(defstruct (tx-index (:include base-index))
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
  ;; Where the indexed blocks live: a CDiskTxPos is written from the block's
  ;; FlatFilePos and read back through the block files.
  (block-store nil))

(defmethod index-name ((index tx-index)) "txindex")
(defmethod index-height ((index tx-index) chainstate)
  "The marker is a hash only (Core TxIndex stores a locator), so resolve it
against CHAINSTATE: the marker's height while it is still on the active chain
there, the fork point after a reorg, -1 with no usable marker -- one below
what %TXINDEX-RESUME-HEIGHT scans from."
  (1- (%txindex-resume-height index chainstate)))
(defmethod index-decode-legacy-best ((index tx-index) bytes)
  "The txindex's old record: the best block's 32-byte hash, no height."
  (when (= (length bytes) 32)
    (values (copy-seq bytes) nil)))
(defmethod index-write-block ((index tx-index) chainstate block block-hash height spent-utxos)
  (declare (ignore chainstate spent-utxos))
  (txindex-add-block index block block-hash height)
  (txindex-set-best-block index block-hash)
  (values t nil))
(defmethod index-rewind-block ((index tx-index) chainstate block block-hash height)
  "Move the best-block marker back to BLOCK's parent when it names BLOCK
(Core BaseIndex::Rewind moves the locator to the fork; the disconnect hook
walks the disconnected blocks tip-first, so this lands there). The entries
stay: Core's TxIndex has no CustomRemove, and a stale-branch tx keeps
resolving through the still-stored block. Without this the marker sat above
the tip after invalidateblock and the next start rescanned from genesis."
  (declare (ignore chainstate height))
  (let ((best (txindex-best-block index)))
    (when (and best (equalp best block-hash))
      (txindex-set-best-block
       index (bl.ser:block-header-prev-block (bl.ser:bitcoin-block-header block))))))
(defmethod index-migrate-records ((index tx-index) chainstate)
  (migrate-txindex index chainstate))
(defmethod index-sync ((index tx-index) chainstate block-store &key undo-fn subsidy-fn progress)
  (declare (ignore undo-fn subsidy-fn))
  (build-tx-index index chainstate block-store :progress-callback progress))

;;; --- keys and records ---

(defconstant +txindex-key-prefix+ 116
  "ASCII 't', Core's DB_TXINDEX (index/txindex.cpp:34).")

(defconstant +txindex-legacy-key-prefix+ 76
  "ASCII 'L': a transaction in a legacy per-block file (see the file header).")

(defparameter *txindex-migration-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 109)
  "ASCII 'm': the next height of an unfinished MIGRATE-TXINDEX.")

(defun txindex-db-path (base-path)
  "Directory of the txindex LevelDB. Core's indexes/txindex/, falling back to
the flat txindex/ this tree used before — see kv/datadir.lisp."
  (datadir-index-path (pathname base-path) :txindex))

(defun %txindex-key (txid)
  "Core's key for TXID: 't' followed by the 32-byte hash."
  (index-key +txindex-key-prefix+ txid))

(defun %txindex-legacy-key (txid)
  (index-key +txindex-legacy-key-prefix+ txid))

(defun %txindex-legacy-encode (block-hash tx-position)
  (let ((v (make-array +txindex-legacy-record-size+ :element-type '(unsigned-byte 8))))
    (replace v block-hash)
    (dotimes (i 4 v)
      (setf (aref v (+ 32 i)) (ldb (byte 8 (* 8 i)) tx-position)))))

(defun %txindex-legacy-decode (v)
  "(values block-hash position) of a 36-byte legacy value."
  (values (subseq v 0 32)
          (loop for i below 4 sum (ash (aref v (+ 32 i)) (* 8 i)))))

(defun init-tx-index (base-path &key (enabled t) wipe block-store)
  "Open the transaction index at BASE-PATH over the blocks in BLOCK-STORE.
If ENABLED is nil, creates a disabled index that ignores add operations.
No startup replay: the DB is the index.

WIPE discards the stored index first (Core's f_wipe for -reindex,
init.cpp:1905), so the caller's catch-up rebuilds it from genesis."
  (open-index-db (make-tx-index :base-path (pathname base-path) :enabled enabled
                                :cache-share :tx-index :block-store block-store)
                 (txindex-db-path base-path)
                 :wipe wipe))

(defun close-tx-index (txindex)
  "Close the txindex database."
  (close-index txindex))

(defun %txindex-live-p (txindex)
  (and (tx-index-enabled txindex) (tx-index-db txindex) t))

(defun %txindex-block-records (txindex block block-hash)
  "The (key . value) records BLOCK contributes: Core's CDiskTxPos per
transaction when the block is in a flat file, else one 'L' record each."
  (let* ((txs (bl.ser:bitcoin-block-transactions block))
         (store (tx-index-block-store txindex))
         (position (and store (block-flat-position store block-hash))))
    (if position
        (loop for tx in txs
              for dtp in (block-disk-tx-positions block position)
              collect (cons (%txindex-key (bl.ser:transaction-hash tx))
                            (encode-disk-tx-pos dtp)))
        (loop for tx in txs
              for i from 0
              collect (cons (%txindex-legacy-key (bl.ser:transaction-hash tx))
                            (%txindex-legacy-encode block-hash i))))))

(defun %txindex-write-records (txindex records &key delete extra)
  "Write RECORDS ((key . value) ...) and DELETE (keys) in one batch, with the
EXTRA (key . value) records -- Core's WriteTxs is one batch per block."
  (with-leveldb-writebatch (batch)
    (dolist (k delete) (leveldb-writebatch-delete batch k))
    (dolist (r records) (leveldb-writebatch-put batch (car r) (cdr r)))
    (dolist (r extra) (leveldb-writebatch-put batch (car r) (cdr r)))
    (leveldb-write (tx-index-db txindex) batch)))

(defun txindex-add-block (txindex block block-hash &optional height)
  "Core TxIndex::CustomAppend (index/txindex.cpp:73-90): write every
transaction of BLOCK, at HEIGHT, in one batch. A connect OVERWRITES what an
earlier branch wrote for the same txid, which is what re-points a transaction
a reorg moved (Core has no CustomRemove for this index). Genesis (HEIGHT 0) is
not indexed. Returns the number of transactions written."
  (if (or (not (%txindex-live-p txindex)) (eql height 0))
      0
      (let ((records (%txindex-block-records txindex block block-hash)))
        (%txindex-write-records txindex records)
        (length records))))

(defun %txindex-read-legacy (txindex v txid)
  "The transaction a 36-byte VALUE locates, as (values tx block-hash), or NIL."
  (multiple-value-bind (block-hash position) (%txindex-legacy-decode v)
    (let* ((store (tx-index-block-store txindex))
           (block (and store (get-block store block-hash)))
           (tx (and block (nth position (bl.ser:bitcoin-block-transactions block)))))
      (when (and tx (equalp (bl.ser:transaction-hash tx) txid))
        (values tx block-hash)))))

(defun txindex-find-tx (txindex txid)
  "Core TxIndex::FindTx (index/txindex.cpp:95-123): the confirmed transaction
TXID, as (values tx block-hash), or NIL when it is not indexed or cannot be
read back. The record's position is read through the block files and the
transaction's hash checked against TXID, as Core's `txid mismatch' check does."
  (when (%txindex-live-p txindex)
    (let* ((db (tx-index-db txindex))
           (v (leveldb-get db (%txindex-key txid))))
      (cond
        ((and v (= (length v) +txindex-legacy-record-size+))
         ;; A record MIGRATE-TXINDEX has not reached yet.
         (%txindex-read-legacy txindex v txid))
        (v
         (let ((dtp (decode-disk-tx-pos v))
               (store (tx-index-block-store txindex)))
           (when (and dtp store)
             (multiple-value-bind (tx block-hash) (read-tx-at-disk-pos store dtp)
               (when (and tx (equalp (bl.ser:transaction-hash tx) txid))
                 (values tx block-hash))))))
        (t
         (let ((lv (leveldb-get db (%txindex-legacy-key txid))))
           (when (and lv (= (length lv) +txindex-legacy-record-size+))
             (%txindex-read-legacy txindex lv txid))))))))

(defun txindex-contains-p (txindex txid)
  "Check if a transaction is indexed."
  (and (%txindex-live-p txindex)
       (or (leveldb-get (tx-index-db txindex) (%txindex-key txid))
           (leveldb-get (tx-index-db txindex) (%txindex-legacy-key txid)))
       t))

(defun txindex-set-best-block (txindex block-hash)
  "Move the block this index is caught up to (Core SetBestBlockIndex). In
memory: COMMIT-INDEX writes it to the database, as Core's Commit does."
  (when (%txindex-live-p txindex)
    (index-set-best txindex block-hash -1)
    t))

(defun txindex-best-block (txindex)
  "The block hash this index is caught up to, or NIL."
  (when (%txindex-live-p txindex)
    (values (index-best-block txindex))))

(defun %count-prefix (db prefix)
  (let ((n 0))
    (with-leveldb-iterator (iter db)
      (leveldb-iter-seek iter (make-array 1 :element-type '(unsigned-byte 8)
                                            :initial-element prefix))
      (loop while (leveldb-iter-valid-p iter)
            for key = (leveldb-iter-key iter)
            while (and key (plusp (length key)) (= (aref key 0) prefix))
            do (incf n) (leveldb-iter-next iter)))
    n))

(defun txindex-count (txindex)
  "Number of indexed transactions, by DB scan.

O(n) and deliberately so: LevelDB has no cheap count, and the only caller is a
diagnostic log line."
  (if (%txindex-live-p txindex)
      (+ (%count-prefix (tx-index-db txindex) +txindex-key-prefix+)
         (%count-prefix (tx-index-db txindex) +txindex-legacy-key-prefix+))
      0))

;;; Background Index Building

(defun %txindex-block-indexed-p (txindex block block-hash)
  "T when BLOCK is already fully indexed AT BLOCK-HASH: its LAST transaction's
stored record is the one this block writes for it. A block's records go in one
batch, so the last one being there means all are. Comparing the record -- not
mere txid presence -- matters because a connect overwrites: after a reorg the
txid can exist but point at a stale branch's block, and the catch-up scan must
re-index it at its active-chain location."
  (let ((records (last (%txindex-block-records txindex block block-hash))))
    (and records
         (equalp (leveldb-get (tx-index-db txindex) (car (first records)))
                 (cdr (first records))))))

(defun %txindex-resume-height (txindex chain-state)
  "Height to resume the catch-up scan from: one past the recorded best-indexed
block, but only when that block is STILL on the active chain at the height it
claims. Otherwise 0, a full rescan.

The marker alone is not enough. A reorg while the index was offline can leave
entries below it pointing at a branch that is no longer the active chain, and
skipping those heights would leave the stale locations in place forever. The
on-chain check is what makes the shortcut safe: if the recorded block is still
where it says it is, everything below it was indexed against this same chain.

Without this the scan re-read EVERY block from disk on every start just to ask
whether it was already indexed — 149k blocks and about nine minutes on the live
testnet4 node."
  (let ((best (txindex-best-block txindex)))
    (if best
        (let ((entry (get-block-index-entry chain-state best)))
          (if entry
              (let* ((height (block-index-entry-height entry))
                     (on-chain (get-block-at-height chain-state height)))
                (cond
                  ((null on-chain) (values 0 :height-above-tip))
                  ((not (equalp (block-index-entry-hash on-chain) best))
                   ;; The marker sits on a block a reorg disconnected. Core
                   ;; REWINDS the index to the fork point (BaseIndex::Rewind,
                   ;; index/base.cpp:290) rather than starting over; answering
                   ;; 0 here rescans from GENESIS, which on the live testnet4
                   ;; node is a full rebuild of a 149k-block index on a restart
                   ;; that happened to follow a reorg — and testnet4 reorgs
                   ;; often. Observed 2026-08-25.
                   ;;
                   ;; Walking the marker's own ancestry finds that fork point:
                   ;; the first ancestor that IS the active chain's block at
                   ;; its height. Entries above it were indexed for a branch
                   ;; that lost, and %TXINDEX-BLOCK-INDEXED-P re-checks each
                   ;; block as the scan reaches it, so resuming there is safe
                   ;; rather than merely cheaper.
                   (%txindex-fork-point chain-state entry))
                  (t (values (1+ height) :resumed))))
              (values 0 :marker-not-in-index)))
        (values 0 :no-marker))))

(defun %txindex-fork-point (chain-state entry)
  "(values NEXT-HEIGHT REASON) for a marker ENTRY that is not on the active
chain: resume just after its deepest ancestor that is."
  (loop for e = (block-index-entry-prev-entry entry)
          then (block-index-entry-prev-entry e)
        while e
        do (let* ((h (block-index-entry-height e))
                  (on-chain (get-block-at-height chain-state h)))
             (when (and on-chain
                        (equalp (block-index-entry-hash on-chain)
                                (block-index-entry-hash e)))
               (return (values (1+ h) :rewound-to-fork))))
        ;; No common ancestor reachable — the only honest answer is a full
        ;; rescan, which is what this used to do unconditionally.
        finally (return (values 0 :marker-off-chain))))

(defun build-tx-index (txindex chain-state block-store
                       &key progress-callback from-genesis)
  "Build the transaction index from existing blocks.
Scans all blocks from genesis to current tip; blocks whose transactions are
already indexed at their active-chain location are skipped (verified via the
block's last transaction, see %TXINDEX-BLOCK-INDEXED-P — a plain
txid-existence check would both bloat the append-only file on every restart
under upsert semantics AND leave stale-branch locations in place after a
reorg that happened while the index was offline).
PROGRESS-CALLBACK, if provided, is called with (height percentage) periodically.
Returns the number of transactions indexed.

By default the scan RESUMES from the recorded best-indexed block, so a startup
costs nothing when the index is already current. FROM-GENESIS forces the full
verify-every-block scan, which is what repairs an index damaged by something
other than a clean crash — resuming cannot detect arbitrary damage below the
marker, and neither can Core, which also resumes from its locator."
  (unless (tx-index-enabled txindex)
    (return-from build-tx-index 0))
  (multiple-value-bind (resume-height resume-reason)
      (if from-genesis
          (values 0 :forced-full)
          (%txindex-resume-height txindex chain-state))
    ;; State the decision. Without this the log shows a scan and gives no way
    ;; to tell a resume from a full rescan, or why -- which is exactly the
    ;; question a nine-minute startup raises.
    (bl.log:log-info "Transaction index: ~(~A~), scanning from height ~D"
                           resume-reason resume-height)
    (%build-tx-index-from txindex chain-state block-store resume-height
                          progress-callback)))

(defun %build-tx-index-from (txindex chain-state block-store start-height
                             progress-callback)
  (let* ((current-height (current-height chain-state))
         (total-indexed 0)
         (last-report-time (get-internal-real-time)))
    (loop for height from start-height to current-height
          do (let ((entry (get-block-at-height chain-state height)))
               (when entry
                 (let* ((block-hash (block-index-entry-hash entry))
                        (block (get-block block-store block-hash)))
                   (when (and block
                              (plusp height)
                              (not (%txindex-block-indexed-p txindex block block-hash)))
                     (let ((count (txindex-add-block txindex block block-hash height)))
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
    ;; Record where we got to, so the next start resumes instead of re-reading
    ;; every block from genesis.
    (let ((tip (get-block-at-height chain-state current-height)))
      (when tip
        (txindex-set-best-block txindex (block-index-entry-hash tip))))
    total-indexed))

;;; --- Migration: this tree's records -> Core's (2026-09-29) ---
;;;
;;; An index written before this commit holds (block hash, position) under
;;; every 't' key. Its CDiskTxPos cannot be derived from the record alone --
;;; nTxOffset is the byte distance from the header, which only the block
;;; knows -- so the migration walks the active chain from height 1 to the
;;; index's best block, reads each block once and rewrites its transactions'
;;; records in Core's form (one batch per BATCH-BLOCKS blocks, the next height
;;; written in the same batch under 'm', so a restart resumes where it
;;; stopped). Then a scan of what is left -- transactions of blocks a reorg
;;; took off the active chain -- converts those the same way, block by block,
;;; or moves them to 'L' when their block is not in a flat file. The index
;;; answers throughout: a 36-byte 't' value is still read the old way.

(defun %txindex-migration-height (txindex)
  (let ((v (leveldb-get (tx-index-db txindex) *txindex-migration-key*)))
    (and v (= (length v) 4) (loop for i below 4 sum (ash (aref v i) (* 8 i))))))

(defun %u32-le (n)
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 v) (setf (aref v i) (ldb (byte 8 (* 8 i)) n)))))

(defun %txindex-first-record-legacy-p (txindex)
  "T when the first 't' record in key order still has the old 36-byte value."
  (with-leveldb-iterator (it (tx-index-db txindex))
    (leveldb-iter-seek it (make-array 1 :element-type '(unsigned-byte 8)
                                        :initial-element +txindex-key-prefix+))
    (and (leveldb-iter-valid-p it)
         (let ((k (leveldb-iter-key it)))
           (and (= (length k) 33) (= (aref k 0) +txindex-key-prefix+)))
         (= (length (leveldb-iter-value it)) +txindex-legacy-record-size+))))

(defun txindex-needs-migration-p (txindex)
  "T when TXINDEX still holds records in this tree's pre-Core layout."
  (and (%txindex-live-p txindex)
       (or (%txindex-migration-height txindex)
           (%txindex-first-record-legacy-p txindex))
       t))

(defun %txindex-leftover-legacy-records (txindex)
  "Every 't' record still in the old layout, as (key . value), grouped in an
EQUALP table by the block hash it names."
  (let ((by-block (make-hash-table :test 'equalp)))
    (with-leveldb-iterator (it (tx-index-db txindex))
      (leveldb-iter-seek it (make-array 1 :element-type '(unsigned-byte 8)
                                          :initial-element +txindex-key-prefix+))
      (loop while (leveldb-iter-valid-p it)
            for k = (leveldb-iter-key it)
            while (and (= (length k) 33) (= (aref k 0) +txindex-key-prefix+))
            do (let ((v (leveldb-iter-value it)))
                 (when (= (length v) +txindex-legacy-record-size+)
                   (push (cons k v) (gethash (subseq v 0 32) by-block))))
               (leveldb-iter-next it)))
    by-block))

(defun %txindex-convert-leftovers (txindex)
  "Convert the old-layout records the chain walk did not reach; returns how
many were converted to Core's form and how many were moved to 'L'."
  (let ((store (tx-index-block-store txindex))
        (core 0) (legacy 0))
    (maphash
     (lambda (block-hash rows)
       (let* ((block (and store (get-block store block-hash)))
              (position (and block (block-flat-position store block-hash)))
              (dtps (and position (coerce (block-disk-tx-positions block position) 'vector))))
         (let ((records '()) (deletes '()))
           (dolist (row rows)
             (let ((txid (subseq (car row) 1))
                   (i (nth-value 1 (%txindex-legacy-decode (cdr row)))))
               (cond
                 ((and dtps (< i (length dtps)))
                  (push (cons (car row) (encode-disk-tx-pos (aref dtps i))) records)
                  (incf core))
                 (t
                  (push (car row) deletes)
                  (push (cons (%txindex-legacy-key txid) (cdr row)) records)
                  (incf legacy)))))
           (%txindex-write-records txindex records :delete deletes))))
     (%txindex-leftover-legacy-records txindex))
    (values core legacy)))

(defun migrate-txindex (txindex chain-state &key (batch-blocks 1000))
  "Rewrite TXINDEX's records in Core's layout, in place and resumably (see
above). A no-op for an index already in Core's layout. Returns the number of
transactions rewritten, or NIL when there was nothing to do."
  (unless (txindex-needs-migration-p txindex)
    (return-from migrate-txindex nil))
  (let* ((start-time (get-internal-real-time))
         (store (tx-index-block-store txindex))
         (from (or (%txindex-migration-height txindex) 1))
         (to (min (current-height chain-state) (index-height txindex chain-state)))
         (written 0)
         (pending '())
         (deletes '()))
    (bl.log:log-info "txindex: migrating records to Core's CDiskTxPos layout, heights ~D to ~D"
                     from to)
    (flet ((flush (next)
             (%txindex-write-records txindex pending :delete deletes
                                     :extra (list (cons *txindex-migration-key* (%u32-le next))))
             (setf pending '() deletes '())))
      ;; One backward walk collects the range (GET-BLOCK-AT-HEIGHT per height
      ;; walks from the tip each time: quadratic over a whole chain).
      (loop for entry in (and (<= from to)
                              (active-chain-entries-from chain-state from (1+ (- to from))))
            for h = (block-index-entry-height entry)
            for hash = (block-index-entry-hash entry)
            for block = (and store (get-block store hash))
            do (when block
                 (let ((records (%txindex-block-records txindex block hash)))
                   (incf written (length records))
                   (dolist (r records)
                     (push r pending)
                     ;; An 'L' record replaces the old 't' one for its txid.
                     (when (= (aref (car r) 0) +txindex-legacy-key-prefix+)
                       (push (%txindex-key (subseq (car r) 1)) deletes)))))
               (when (zerop (mod (1+ (- h from)) batch-blocks))
                 (flush (1+ h))
                 (bl.log:log-info "txindex: migrated to height ~D of ~D" h to)))
      (flush (1+ to)))
    (multiple-value-bind (core legacy) (%txindex-convert-leftovers txindex)
      (leveldb-delete (tx-index-db txindex) *txindex-migration-key*)
      (bl.log:log-info "txindex: migration done -- ~D transaction~:P on the active chain, ~
~D off it rewritten, ~D left in legacy per-block files, in ~,1Fs"
                       written core legacy
                       (/ (- (get-internal-real-time) start-time)
                          internal-time-units-per-second)))
    written))
