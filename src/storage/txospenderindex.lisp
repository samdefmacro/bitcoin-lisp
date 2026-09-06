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
;;;; Layout, per key:
;;;;
;;;;   #x73 's' | SipHash-2-4(outpoint) u64 LE | block hash 32 | tx offset u32 LE
;;;;   value: empty
;;;;
;;;; and two metadata keys: #x42 'B' holds the best block indexed, and the
;;;; literal "siphash_key" holds this index's own random 2x64-bit salt.
;;;;
;;;; The hash is a SALTED digest of the outpoint rather than the outpoint
;;;; itself (Core does the same, txospenderindex.cpp:66-70 and :81-83): 8 bytes
;;;; instead of 36 across every spent output in the chain is a large saving,
;;;; and the salt means an attacker cannot precompute keys that collide.
;;;;
;;;; Collisions are TOLERATED, not prevented. Two different outpoints can share
;;;; a hash, so the locator is part of the key and a lookup walks every entry
;;;; under the hash, reads each candidate transaction and keeps the one that
;;;; really spends the outpoint. That is Core's design too
;;;; (txospenderindex.cpp:141-156 reads the transaction back before answering).
;;;;
;;;; ⚠️ Unlike mempool.dat, this file is NEVER read by Bitcoin Core. Nothing
;;;; here has to match Core byte for byte, so the locator is OUR (block hash,
;;;; offset) pair — the same shape the txindex already stores — rather than
;;;; Core's CDiskTxPos, which is tied to its blocks-file layout.

(defconstant +txospender-key-prefix+ #x73
  "ASCII 's' — Core's DB_TXOSPENDERINDEX (index/txospenderindex.cpp:41). Its
own database, so this cannot collide with the coins DB's 'C'/'B'/'M' or the
coinstatsindex's 'S'/'B'.")

(defconstant +txospender-key-size+ 45
  "1 prefix + 8 hash + 32 block hash + 4 offset.")

(defparameter *txospender-salt-key*
  (map '(vector (unsigned-byte 8)) #'char-code "siphash_key")
  "Core stores its salt under this literal key (txospenderindex.cpp:66).")

(defstruct (txospender-index (:include base-index))
  "Spender index state. Like the txindex, the database IS the index: there is
no in-memory table and no startup replay."
  (k0 0 :type (unsigned-byte 64))
  (k1 0 :type (unsigned-byte 64)))

(defmethod index-name ((index txospender-index)) "txospenderindex")
;;; INDEX-HEIGHT for this index is chainstate-aware and lives in
;;; node/indexes.lisp beside the rewind that repairs an off-chain marker: the
;;; fork walk it needs is above this layer. TXOSPENDERINDEX-HEIGHT below is
;;; the raw stored height, which getindexinfo reports.
(defmethod index-best-block ((index txospender-index)) (txospenderindex-best-block index))
(defmethod index-set-best ((index txospender-index) block-hash height)
  (txospenderindex-set-best-block index block-hash height))
(defmethod index-clear-best ((index txospender-index))
  (when (%txospender-index-live-p index)
    (leveldb-delete (txospender-index-db index) *index-meta-key*)))
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
  "Directory of the spender index LevelDB (Core's indexes/txospenderindex/)."
  (datadir-index-path (pathname base-path) :txospenderindex))

(defun %txospender-hash (index txid vout)
  "The salted 64-bit digest of the outpoint TXID:VOUT.

Core hashes the txid and the index together through a presalted SipHasher
(txospenderindex.cpp:81-83). We hash the same two values in the same order over
our own SipHash-2-4; the digests differ from Core's and that is fine, because
nothing outside this node ever reads this database."
  (let ((buf (make-array 36 :element-type '(unsigned-byte 8))))
    (replace buf txid)
    (setf (aref buf 32) (logand vout #xFF)
          (aref buf 33) (logand (ash vout -8) #xFF)
          (aref buf 34) (logand (ash vout -16) #xFF)
          (aref buf 35) (logand (ash vout -24) #xFF))
    (bl.crypto:siphash-2-4 (txospender-index-k0 index)
                                     (txospender-index-k1 index)
                                     buf)))

(defun %txospender-key (index txid vout block-hash tx-position)
  "The full DB key: prefix, salted outpoint hash, then the locator of the
transaction that spent it."
  (let ((key (make-array +txospender-key-size+ :element-type '(unsigned-byte 8)))
        (h (%txospender-hash index txid vout)))
    (setf (aref key 0) +txospender-key-prefix+)
    (dotimes (i 8)
      (setf (aref key (+ 1 i)) (logand (ash h (* -8 i)) #xFF)))
    (replace key block-hash :start1 9)
    (setf (aref key 41) (logand tx-position #xFF)
          (aref key 42) (logand (ash tx-position -8) #xFF)
          (aref key 43) (logand (ash tx-position -16) #xFF)
          (aref key 44) (logand (ash tx-position -24) #xFF))
    key))

(defun %txospender-hash-prefix (index txid vout)
  "The 9-byte seek prefix — everything before the locator — so an iterator can
walk every entry recorded under one outpoint's hash."
  (subseq (%txospender-key index txid vout
                           (make-array 32 :element-type '(unsigned-byte 8))
                           0)
          0 9))

(defun %txospender-key-locator (key)
  "(values block-hash tx-position) from a 45-byte spender key."
  (values (subseq key 9 41)
          (logior (aref key 41)
                  (ash (aref key 42) 8)
                  (ash (aref key 43) 16)
                  (ash (aref key 44) 24))))

(defun %txospender-load-salt (index)
  "Read this index's salt, generating and persisting one on first use.

Core does the same (txospenderindex.cpp:66-70). The salt must be STABLE for the
life of the database: regenerating it would silently orphan every key already
written, and the index would answer `not found' for every output it had
already recorded."
  (let ((stored (leveldb-get (txospender-index-db index) *txospender-salt-key*)))
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
          (leveldb-put (txospender-index-db index) *txospender-salt-key* buf)
          (setf (txospender-index-k0 index) k0
                (txospender-index-k1 index) k1)))
    index))

(defun init-txospender-index (base-path &key (enabled t))
  "Open the spender index at BASE-PATH. A disabled index ignores every write,
so callers do not have to test for it."
  (let ((index (open-index-db (make-txospender-index :base-path (pathname base-path)
                                                     :enabled enabled)
                              (txospenderindex-db-path base-path))))
    (when (txospender-index-db index)
      (%txospender-load-salt index))
    index))

(defun close-txospender-index (index)
  (close-index index))

(defun %txospender-index-live-p (index)
  (and index (txospender-index-enabled index) (txospender-index-db index)))

(defun %txospender-block-entries (block)
  "(outpoint-txid outpoint-vout tx-position) for every input this block spends.

Core builds the same list for BOTH the connect and the disconnect side from the
block alone (BuildSpenderPositions, txospenderindex.cpp:110-127) — which is why
a reorg can erase exactly what the connect wrote. The coinbase is skipped: its
input spends nothing.

TX-POSITION is the offset of the spending transaction within the block's
serialization, the same locator the txindex stores."
  (let ((entries '())
        (position 0))
    (loop for tx in (bl.ser:bitcoin-block-transactions block)
          for inputs = (bl.ser:transaction-inputs tx)
          for coinbase = (and (= 1 (length inputs))
                              (bl.ser:coinbase-input-p (aref inputs 0)))
          do (unless coinbase
               (loop for input across inputs
                     for outpoint = (bl.ser:tx-in-previous-output input)
                     do (push (list (bl.ser:outpoint-hash outpoint)
                                    (bl.ser:outpoint-index outpoint)
                                    position)
                              entries)))
             (incf position (length (bl.ser:transaction-wire-bytes tx))))
    (nreverse entries)))

(defun txospenderindex-add-block (index block block-hash)
  "Record every output BLOCK spends. Returns the number of entries written."
  (unless (%txospender-index-live-p index)
    (return-from txospenderindex-add-block 0))
  (let ((entries (%txospender-block-entries block))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (let ((batch (leveldb-make-writebatch)))
      (unwind-protect
           (progn
             (dolist (e entries)
               (destructuring-bind (txid vout position) e
                 (leveldb-writebatch-put
                  batch (%txospender-key index txid vout block-hash position) empty)))
             (leveldb-write (txospender-index-db index) batch))
        (leveldb-destroy-writebatch batch)))
    (length entries)))

(defun txospenderindex-remove-block (index block block-hash)
  "Erase what TXOSPENDERINDEX-ADD-BLOCK wrote for BLOCK.

⚠️ This is what makes the index correct across a reorg, and it has no analogue
in the other indexes here. coinstatsindex and blockfilterindex key their
records on HEIGHT, so a reconnect simply overwrites a disconnected block's
record and a stale one is never read. A spender key carries no height: after a
reorg the disconnected block is still on disk, so an entry left behind resolves
to a spending transaction from an ABANDONED chain — a wrong answer, not a stale
one. Core erases through CustomRemove (txospenderindex.cpp:135-139) for the
same reason."
  (unless (%txospender-index-live-p index)
    (return-from txospenderindex-remove-block 0))
  (let ((entries (%txospender-block-entries block)))
    (let ((batch (leveldb-make-writebatch)))
      (unwind-protect
           (progn
             (dolist (e entries)
               (destructuring-bind (txid vout position) e
                 (leveldb-writebatch-delete
                  batch (%txospender-key index txid vout block-hash position))))
             (leveldb-write (txospender-index-db index) batch))
        (leveldb-destroy-writebatch batch)))
    (length entries)))

(defun txospenderindex-locators (index txid vout)
  "Every (block-hash . tx-position) recorded for the outpoint TXID:VOUT.

Usually one. More than one means either a SipHash collision between two
outpoints or a reorg whose disconnect side was never applied; the caller
resolves both the same way, by reading each candidate transaction and keeping
the one that really spends this outpoint."
  (unless (%txospender-index-live-p index)
    (return-from txospenderindex-locators nil))
  (let ((prefix (%txospender-hash-prefix index txid vout))
        (found '()))
    (with-leveldb-iterator (iter (txospender-index-db index))
      (leveldb-iter-seek iter prefix)
      (loop
        (unless (leveldb-iter-valid-p iter) (return))
        (let ((k (leveldb-iter-key iter)))
          (unless (and (= (length k) +txospender-key-size+)
                       (loop for i from 0 below 9
                             always (= (aref k i) (aref prefix i))))
            (return))
          (multiple-value-bind (block-hash position) (%txospender-key-locator k)
            (push (cons block-hash position) found)))
        (leveldb-iter-next iter)))
    (nreverse found)))

(defun txospenderindex-set-best-block (index block-hash height)
  "Record how far the index has got: the block hash and its height.

The HEIGHT is stored beside the hash purely so getindexinfo can report
best_block_height without a chain-state lookup — Core's BaseIndex keeps a
locator and reads the height off it. The layout is hash||height, the
reverse of INDEX-META-ENCODE's height||hash (the other two indexes); it is
on disk, so it stays."
  (when (%txospender-index-live-p index)
    (let ((v (make-array 36 :element-type '(unsigned-byte 8))))
      (replace v block-hash)
      (dotimes (i 4)
        (setf (aref v (+ 32 i)) (logand (ash height (* -8 i)) #xFF)))
      (leveldb-put (txospender-index-db index) *index-meta-key* v))
    t))

(defun txospenderindex-best-block (index)
  "(values block-hash height), or NIL when nothing has been indexed."
  (when (%txospender-index-live-p index)
    (let ((v (leveldb-get (txospender-index-db index) *index-meta-key*)))
      (when (and v (= 36 (length v)))
        (values (subseq v 0 32)
                (logior (aref v 32) (ash (aref v 33) 8)
                        (ash (aref v 34) 16) (ash (aref v 35) 24)))))))

(defun txospenderindex-height (index)
  "How far the index has got, or -1 when it holds nothing — the shape
getindexinfo wants."
  (multiple-value-bind (hash height) (txospenderindex-best-block index)
    (if hash height -1)))
