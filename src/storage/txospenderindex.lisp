(in-package #:bitcoin-lisp.storage)

;;;; txospenderindex — "which transaction spent this output?"
;;;; (Bitcoin Core index/txospenderindex.{h,cpp})
;;;;
;;;; The one index Core has that this node lacked. Without it
;;;; gettxspendingprevout can only answer for the mempool, so a client asking
;;;; who spent a CONFIRMED output gets "not found" rather than an answer —
;;;; Core falls back to this index for exactly that case
;;;; (rpc/mempool.cpp, gettxspendingprevout's mempool_only option).
;;;;
;;;; Layout, per key -- Core's (index/txospenderindex.cpp:41-58, 95-107):
;;;;
;;;;   's' | SipHash(outpoint) u64 LE | CDiskTxPos of the spending tx (VARINTs)
;;;;   value: the empty std::string, serialized (one 0x00 byte)
;;;;
;;;; and two metadata keys: 'B' holds the best block's locator, and the
;;;; std::string "siphash_key" (serialized: its CompactSize length, then the
;;;; bytes) holds this index's random 2x64-bit salt, both u64 LE.
;;;;
;;;; The hash is a SALTED digest of the outpoint rather than the outpoint
;;;; itself (Core does the same, txospenderindex.cpp:66-70 and :81-83): 8 bytes
;;;; instead of 36 across every spent output in the chain is a large saving,
;;;; and the salt means an attacker cannot precompute keys that collide.
;;;; PresaltedSipHasher over (uint256, uint32) is SipHash-2-4 over the 36
;;;; bytes txid || vout LE, which is what %TXOSPENDER-HASH computes, so with
;;;; the same salt the keys are Core's to the byte.
;;;;
;;;; Collisions are TOLERATED, not prevented. Two different outpoints can share
;;;; a hash, so the locator is part of the key and a lookup walks every entry
;;;; under the hash, reads each candidate transaction and keeps the one that
;;;; really spends the outpoint (txospenderindex.cpp:141-176).
;;;;
;;;; A spending transaction whose block this node keeps in a LEGACY per-block
;;;; file has no CDiskTxPos (see disktxpos.lisp). Its entry is ours, under a
;;;; prefix Core never reads:
;;;;
;;;;   'S' | SipHash(outpoint) u64 LE | block hash 32 | byte offset u32 LE
;;;;
;;;; the offset counted from the first transaction. Until 2026-09-29 every
;;;; entry had that layout under 's', and the salt key was the bare
;;;; characters; MIGRATE-TXOSPENDERINDEX rewrites both in place.

(defconstant +txospender-key-prefix+ #x73
  "ASCII 's' — Core's DB_TXOSPENDERINDEX (index/txospenderindex.cpp:41). Its
own database, so this cannot collide with the coins DB's 'C'/'B'/'M' or the
coinstatsindex's 'S'/'B'.")

(defconstant +txospender-legacy-key-prefix+ #x53
  "ASCII 'S': an entry whose spending block is in a legacy per-block file.")

(defconstant +txospender-legacy-key-size+ 45
  "1 prefix + 8 hash + 32 block hash + 4 offset: an 'S' entry, and every 's'
entry written before 2026-09-29. A Core key is 1 + 8 + at most 15 bytes of
VARINTs, so the two cannot be confused.")

(defparameter *txospender-salt-key*
  (let ((name (map '(vector (unsigned-byte 8)) #'char-code "siphash_key")))
    (concatenate '(simple-array (unsigned-byte 8) (*)) (vector (length name)) name))
  "Core's key for the salt: the std::string \"siphash_key\" serialized,
CompactSize length first (txospenderindex.cpp:66).")

(defparameter *txospender-old-salt-key*
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code "siphash_key")
  "Where this tree kept the salt before 2026-09-29: the bare characters.")

(defparameter *txospender-migration-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 109)
  "ASCII 'm': the next height of an unfinished MIGRATE-TXOSPENDERINDEX.")

(defparameter *txospender-empty-value*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 0)
  "Core writes the empty std::string as each entry's value: one 0x00 byte.")

(defstruct (txospender-index (:include base-index))
  "Spender index state. Like the txindex, the database IS the index: there is
no in-memory table and no startup replay."
  (k0 0 :type (unsigned-byte 64))
  (k1 0 :type (unsigned-byte 64))
  ;; Where the indexed blocks live: a CDiskTxPos is written from the block's
  ;; FlatFilePos and read back through the block files.
  (block-store nil))

(defmethod index-name ((index txospender-index)) "txospenderindex")
;;; INDEX-HEIGHT for this index is chainstate-aware and lives in
;;; node/indexes.lisp beside the rewind that repairs an off-chain marker: the
;;; fork walk it needs is above this layer. TXOSPENDERINDEX-HEIGHT below is
;;; the raw stored height, which getindexinfo reports.
(defmethod index-decode-legacy-best ((index txospender-index) bytes)
  "The spender index's old record: hash || height LE32."
  (when (= (length bytes) 36)
    (values (subseq bytes 0 32)
            (logior (aref bytes 32) (ash (aref bytes 33) 8)
                    (ash (aref bytes 34) 16) (ash (aref bytes 35) 24)))))
(defmethod index-write-block ((index txospender-index) chainstate block block-hash height spent-utxos)
  "Record BLOCK's spends, refusing one that would sit above a GAP (Core's
indexes only ever append to a contiguous range; the blockfilterindex refuses
the same way). Without the refusal a connect above a hole moved the marker
forward over it, so every later start saw index-height >= tip, skipped the
backfill, and the hole became permanent -- which is what made a missing
startup rewind cost a silent wrong answer rather than one slow rebuild."
  (declare (ignore spent-utxos))
  (let ((best (index-height index chainstate)))
    (when (and (>= best 0) (> height (1+ best)))
      (return-from index-write-block (values nil :noncontiguous))))
  (txospenderindex-add-block index block block-hash)
  (txospenderindex-set-best-block index block-hash height)
  (values t nil))
(defmethod index-rewind-block ((index txospender-index) chainstate block block-hash height)
  (declare (ignore chainstate height))
  (txospenderindex-remove-block index block block-hash))

(defun txospenderindex-db-path (base-path)
  "Directory of the spender index LevelDB: Core's indexes/txospenderindex/db/
(index/txospenderindex.cpp:64). :MIGRATE moves a database left in the index
directory itself down into its db/ the first time such a datadir is opened."
  (datadir-index-path (pathname base-path) :txospenderindex :migrate t))

(defun %txospender-hash (index txid vout)
  "The salted 64-bit digest of the outpoint TXID:VOUT.

Core hashes the txid and the index together through a presalted SipHasher
(txospenderindex.cpp:81-83), whose (uint256, uint32) form is SipHash-2-4 over
these same 36 bytes (crypto/siphash.cpp SipHashUint256Extra)."
  (let ((buf (make-array 36 :element-type '(unsigned-byte 8))))
    (replace buf txid)
    (setf (aref buf 32) (logand vout #xFF)
          (aref buf 33) (logand (ash vout -8) #xFF)
          (aref buf 34) (logand (ash vout -16) #xFF)
          (aref buf 35) (logand (ash vout -24) #xFF))
    (bl.crypto:siphash-2-4 (txospender-index-k0 index)
                                     (txospender-index-k1 index)
                                     buf)))

;;; --- keys ---

(defun %txospender-hash-prefix (index txid vout)
  "The 9-byte seek prefix, 's' and the salted outpoint hash: every entry
recorded under one outpoint's hash starts with it."
  (let ((key (make-array 9 :element-type '(unsigned-byte 8)))
        (h (%txospender-hash index txid vout)))
    (setf (aref key 0) +txospender-key-prefix+)
    (dotimes (i 8 key)
      (setf (aref key (+ 1 i)) (ldb (byte 8 (* 8 i)) h)))))

(defun %txospender-key (index txid vout dtp)
  "Core's DBKey (txospenderindex.cpp:43-58): the prefix, then the CDiskTxPos
of the transaction that spent TXID:VOUT."
  (concatenate '(simple-array (unsigned-byte 8) (*))
               (%txospender-hash-prefix index txid vout)
               (encode-disk-tx-pos dtp)))

(defun %txospender-legacy-key (index txid vout block-hash offset &key (prefix +txospender-legacy-key-prefix+))
  "An entry whose spending block has no FlatFilePos: PREFIX, the hash, the
block hash and the spending transaction's byte OFFSET from the first."
  (let ((key (make-array +txospender-legacy-key-size+ :element-type '(unsigned-byte 8))))
    (replace key (%txospender-hash-prefix index txid vout))
    (setf (aref key 0) prefix)
    (replace key block-hash :start1 9)
    (dotimes (i 4 key)
      (setf (aref key (+ 41 i)) (ldb (byte 8 (* 8 i)) offset)))))

(defun %txospender-legacy-locator (key)
  "(values block-hash offset) from a 45-byte legacy key."
  (values (subseq key 9 41)
          (loop for i below 4 sum (ash (aref key (+ 41 i)) (* 8 i)))))

(defun %txospender-load-salt (index)
  "Read this index's salt, generating and persisting one on first use.

Core does the same (txospenderindex.cpp:66-70). The salt must be STABLE for the
life of the database: regenerating it would silently orphan every key already
written, and the index would answer `not found' for every output it had
already recorded. A salt kept under the old bare key is moved to Core's."
  (let* ((db (txospender-index-db index))
         (stored (or (leveldb-get db *txospender-salt-key*)
                     (let ((old (leveldb-get db *txospender-old-salt-key*)))
                       (when (and old (= 16 (length old)))
                         (with-leveldb-writebatch (batch)
                           (leveldb-writebatch-put batch *txospender-salt-key* old)
                           (leveldb-writebatch-delete batch *txospender-old-salt-key*)
                           (leveldb-write db batch :sync t))
                         old)))))
    (if (and stored (= 16 (length stored)))
        (setf (txospender-index-k0 index)
              (loop for i from 0 below 8 sum (ash (aref stored i) (* 8 i)))
              (txospender-index-k1 index)
              (loop for i from 0 below 8 sum (ash (aref stored (+ 8 i)) (* 8 i))))
        (let ((k0 (random (expt 2 64) (make-random-state t)))
              (k1 (random (expt 2 64) (make-random-state t)))
              (buf (make-array 16 :element-type '(unsigned-byte 8))))
          (dotimes (i 8)
            (setf (aref buf i) (logand (ash k0 (* -8 i)) #xFF)
                  (aref buf (+ 8 i)) (logand (ash k1 (* -8 i)) #xFF)))
          (leveldb-put db *txospender-salt-key* buf :sync t)
          (setf (txospender-index-k0 index) k0
                (txospender-index-k1 index) k1)))
    index))

(defun init-txospender-index (base-path &key (enabled t) wipe block-store)
  "Open the spender index at BASE-PATH over the blocks in BLOCK-STORE. A
disabled index ignores every write, so callers do not have to test for it.

WIPE discards the stored index first (Core's f_wipe for -reindex,
init.cpp:1909), so the caller's catch-up rebuilds it from genesis. The salt is
drawn afresh on the next open, which is right: it keyed hashes of rows that no
longer exist."
  (let ((index (open-index-db (make-txospender-index :base-path (pathname base-path)
                                                     :enabled enabled
                                                     :block-store block-store)
                              (txospenderindex-db-path base-path)
                              :wipe wipe)))
    (when (txospender-index-db index)
      (%txospender-load-salt index))
    index))

(defun close-txospender-index (index)
  (close-index index))

(defun %txospender-index-live-p (index)
  (and index (txospender-index-enabled index) (txospender-index-db index)))

(defun %txospender-block-keys (index block block-hash)
  "Core BuildSpenderPositions (txospenderindex.cpp:110-127) as the keys: one per
input of every non-coinbase transaction, locating the spending transaction by
its CDiskTxPos when BLOCK is in a flat file, else by an 'S' entry. Connect and
disconnect build the same list from the block alone, which is why a reorg
erases exactly what the connect wrote."
  (let* ((store (txospender-index-block-store index))
         (position (and store (block-flat-position store block-hash)))
         (txs (bl.ser:bitcoin-block-transactions block))
         (dtps (and position (block-disk-tx-positions block position)))
         (offset 0)
         (keys '()))
    (loop for tx in txs
          for i from 0
          for inputs = (bl.ser:transaction-inputs tx)
          for coinbase = (and (= 1 (length inputs))
                              (bl.ser:coinbase-input-p (aref inputs 0)))
          do (unless coinbase
               (loop for input across inputs
                     for op = (bl.ser:tx-in-previous-output input)
                     for txid = (bl.ser:outpoint-hash op)
                     for vout = (bl.ser:outpoint-index op)
                     do (push (if dtps
                                  (%txospender-key index txid vout (nth i dtps))
                                  (%txospender-legacy-key index txid vout block-hash offset))
                              keys)))
             (incf offset (length (bl.ser:transaction-wire-bytes tx))))
    (nreverse keys)))

(defun %txospender-write (index puts deletes &optional extra)
  (with-leveldb-writebatch (batch)
    (dolist (k deletes) (leveldb-writebatch-delete batch k))
    (dolist (k puts) (leveldb-writebatch-put batch k *txospender-empty-value*))
    (dolist (r extra) (leveldb-writebatch-put batch (car r) (cdr r)))
    (leveldb-write (txospender-index-db index) batch)))

(defun txospenderindex-add-block (index block block-hash)
  "Core WriteSpenderInfos: record every output BLOCK spends, in one batch.
Returns the number of entries written."
  (if (%txospender-index-live-p index)
      (let ((keys (%txospender-block-keys index block block-hash)))
        (%txospender-write index keys '())
        (length keys))
      0))

(defun txospenderindex-remove-block (index block block-hash)
  "Core EraseSpenderInfos (CustomRemove): erase what TXOSPENDERINDEX-ADD-BLOCK
wrote for BLOCK.

⚠️ This is what makes the index correct across a reorg. A spender key
carries no height: after a reorg the disconnected block is still on disk, so an
entry left behind resolves to a spending transaction from an ABANDONED chain --
a wrong answer, not a stale one (txospenderindex.cpp:135-139)."
  (if (%txospender-index-live-p index)
      (let ((keys (%txospender-block-keys index block block-hash)))
        (%txospender-write index '() keys)
        (length keys))
      0))

(defun %tx-spends-outpoint-p (tx txid vout)
  (some (lambda (input)
          (let ((op (bl.ser:tx-in-previous-output input)))
            (and (equalp (bl.ser:outpoint-hash op) txid)
                 (= (bl.ser:outpoint-index op) vout))))
        (bl.ser:transaction-inputs tx)))

(defun %txospender-read-legacy (index key)
  "(values tx block-hash) at a legacy key's (block hash, offset), or NIL."
  (multiple-value-bind (block-hash offset) (%txospender-legacy-locator key)
    (let* ((store (txospender-index-block-store index))
           (block (and store (get-block store block-hash)))
           (at 0))
      (when block
        (dolist (tx (bl.ser:bitcoin-block-transactions block) nil)
          (when (= at offset) (return (values tx block-hash)))
          (incf at (length (bl.ser:transaction-wire-bytes tx))))))))

(defun %txospender-candidates (index prefix-byte txid vout)
  "Every key under PREFIX-BYTE whose next 8 bytes are TXID:VOUT's hash."
  (let ((prefix (%txospender-hash-prefix index txid vout))
        (found '()))
    (setf (aref prefix 0) prefix-byte)
    (with-leveldb-iterator (iter (txospender-index-db index))
      (leveldb-iter-seek iter prefix)
      (loop while (leveldb-iter-valid-p iter)
            for k = (leveldb-iter-key iter)
            while (and (> (length k) 9) (not (mismatch prefix k :end2 9)))
            do (push k found)
               (leveldb-iter-next iter)))
    (nreverse found)))

(defun txospenderindex-find-spender (index txid vout)
  "Core TxoSpenderIndex::FindSpender (index/txospenderindex.cpp:156-176): the
confirmed transaction that spent TXID:VOUT, as (values tx block-hash), or NIL.
Every entry under the outpoint's hash is read back and kept only if it really
spends the outpoint -- a salted-hash collision is skipped. Nothing is asked
about the chain: an entry a reorg left behind answers until the index is
rewound, as Core's does (rpc_gettxspendingprevout.py:200)."
  (when (%txospender-index-live-p index)
    (let ((store (txospender-index-block-store index)))
      (dolist (key (append (%txospender-candidates index +txospender-key-prefix+ txid vout)
                           (%txospender-candidates index +txospender-legacy-key-prefix+ txid vout))
                   nil)
        (multiple-value-bind (tx block-hash)
            (if (= (length key) +txospender-legacy-key-size+)
                ;; An 'S' entry, or an 's' one the migration has not reached.
                (%txospender-read-legacy index key)
                (let ((dtp (decode-disk-tx-pos (subseq key 9))))
                  (and dtp store (read-tx-at-disk-pos store dtp))))
          (when (and tx (%tx-spends-outpoint-p tx txid vout))
            (return (values tx block-hash))))))))

(defun txospenderindex-set-best-block (index block-hash height)
  "Move how far the index has got (Core SetBestBlockIndex), in memory;
COMMIT-INDEX writes it to the database as Core's Commit does."
  (when (%txospender-index-live-p index)
    (index-set-best index block-hash height)
    t))

(defun txospenderindex-best-block (index)
  "(values block-hash height), or NIL when nothing has been indexed."
  (when (%txospender-index-live-p index)
    (index-best-block index)))

(defun txospenderindex-height (index)
  "How far the index has got, or -1 when it holds nothing — the shape
getindexinfo wants."
  (multiple-value-bind (hash height) (txospenderindex-best-block index)
    (if hash height -1)))

;;; --- Migration: this tree's entries -> Core's (2026-09-29) ---
;;;
;;; An old entry is 's' | hash | block hash | offset, and Core's is
;;; 's' | hash | CDiskTxPos: the first nine bytes carry over unchanged, and the
;;; CDiskTxPos comes from the block alone. So the migration scans the old
;;; entries in key order, a chunk at a time, groups each chunk by block, reads
;;; each block once and rewrites its entries -- one batch per block, new keys
;;; in and old keys out together, so an interruption leaves every entry in
;;; one layout or the other and the next start simply scans on. An entry
;;; whose block is not in a flat file moves to 'S'; one whose block is gone
;;; is dropped, as nothing could read it.

(defun %txospender-old-entries (index &key (limit 100000))
  "Up to LIMIT old-layout 's' keys, grouped in an EQUALP table by block hash."
  (let ((by-block (bl.bytes:make-octets-hash-table))
        (n 0))
    (with-leveldb-iterator (it (txospender-index-db index))
      (leveldb-iter-seek it (make-array 1 :element-type '(unsigned-byte 8)
                                          :initial-element +txospender-key-prefix+))
      (loop while (and (leveldb-iter-valid-p it) (< n limit))
            for k = (leveldb-iter-key it)
            while (and (plusp (length k)) (= (aref k 0) +txospender-key-prefix+))
            do (when (= (length k) +txospender-legacy-key-size+)
                 (push k (gethash (subseq k 9 41) by-block))
                 (incf n))
               (leveldb-iter-next it)))
    by-block))

(defun %txospender-migrate-block (index block-hash keys)
  "Rewrite the old KEYS of one block; returns :core, :legacy or :dropped."
  (let* ((store (txospender-index-block-store index))
         (block (and store (get-block store block-hash)))
         (position (and block (block-flat-position store block-hash)))
         (by-offset (make-hash-table)))
    (when position
      (loop with offset = 0
            for tx in (bl.ser:bitcoin-block-transactions block)
            for dtp in (block-disk-tx-positions block position)
            do (setf (gethash offset by-offset) dtp)
               (incf offset (length (bl.ser:transaction-wire-bytes tx)))))
    (let ((puts '()))
      (dolist (k keys)
        (let ((dtp (gethash (nth-value 1 (%txospender-legacy-locator k)) by-offset)))
          (cond
            (dtp (push (concatenate '(simple-array (unsigned-byte 8) (*))
                                    (subseq k 0 9) (encode-disk-tx-pos dtp))
                       puts))
            (block (let ((moved (copy-seq k)))
                     (setf (aref moved 0) +txospender-legacy-key-prefix+)
                     (push moved puts))))))
      (%txospender-write index puts keys)
      (cond (position :core) (block :legacy) (t :dropped)))))

(defun txospenderindex-needs-migration-p (index)
  "T when INDEX still holds entries in this tree's pre-Core layout."
  (and (%txospender-index-live-p index)
       (plusp (hash-table-count (%txospender-old-entries index :limit 1)))))

(defun migrate-txospenderindex (index &key (chunk 100000))
  "Rewrite INDEX's old entries in Core's layout, in place (see above). Returns
how many entries were rewritten, or NIL when there was nothing to do."
  (unless (txospenderindex-needs-migration-p index)
    (return-from migrate-txospenderindex nil))
  (let ((start (get-internal-real-time))
        (entries 0)
        (counts (list :core 0 :legacy 0 :dropped 0)))
    (bl.log:log-info "txospenderindex: migrating entries to Core's CDiskTxPos layout")
    (loop for groups = (%txospender-old-entries index :limit chunk)
          until (zerop (hash-table-count groups))
          do (maphash (lambda (block-hash keys)
                        (incf (getf counts (%txospender-migrate-block index block-hash keys)))
                        (incf entries (length keys)))
                      groups)
             (bl.log:log-info "txospenderindex: ~D entries migrated" entries))
    (bl.log:log-info "txospenderindex: migration done -- ~D entr~:@P in ~,1Fs (blocks: ~D in flat files, ~
~D in legacy per-block files, ~D gone)"
                     entries (/ (- (get-internal-real-time) start) internal-time-units-per-second)
                     (getf counts :core) (getf counts :legacy) (getf counts :dropped))
    entries))

(defmethod index-migrate-records ((index txospender-index) chainstate)
  (declare (ignore chainstate))
  (migrate-txospenderindex index))
