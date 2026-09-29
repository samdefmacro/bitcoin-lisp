(in-package #:bitcoin-lisp.storage)

;;;; coinstatsindex — per-height UTXO-set statistics (Bitcoin Core
;;;; src/index/coinstatsindex.cpp + kernel/coinstats.cpp).
;;;;
;;;; Maintains, at every block height, the MuHash of the UTXO set plus the
;;;; amount/count tallies gettxoutsetinfo reports (total amount, txout count,
;;;; bogosize, subsidy, spent/created/coinbase amounts, and the four
;;;; unspendable buckets). Because MuHash is incremental, each block only adds
;;;; its created outputs and removes its spent prevouts -- no full UTXO rescan.
;;;;
;;;; Core's layout, to the byte (coinstatsindex.cpp:44-80, db_key.h), under
;;;; indexes/coinstatsindex/db/:
;;;;
;;;;   't' || height u32 BE  ->  block hash(32) || DBVal     (active chain)
;;;;   's' || block hash(32) ->  DBVal       (a block a reorg took off it)
;;;;   'M'                   ->  the running MuHash3072: numerator || denominator,
;;;;                             each 384 bytes little-endian (Num3072's limbs)
;;;;   'B'                   ->  the best-block CBlockLocator
;;;;
;;;;   DBVal = muhash digest(32) || txouts u64 || bogosize u64 || total_amount
;;;;           i64 || total_subsidy i64 || total_prevout_spent uint256 ||
;;;;           total_new_outputs_ex_coinbase uint256 || total_coinbase uint256 ||
;;;;           the four unspendable buckets, i64 each -- all little-endian.
;;;;
;;;; A record carries the FINALIZED MuHash only. The running fraction lives in
;;;; memory (Core's m_muhash and tallies, the RUNNING slot here) and reaches
;;;; disk as 'M' beside the locator at each commit (CustomCommit), so the two
;;;; always describe the same block. Connecting folds a block into the running
;;;; state; a rewind reverses it block by block with the block and its undo
;;;; data (RevertBlock, :329-399) and checks the result against the parent's
;;;; record. When a height is reused by another branch's block, what it held
;;;; moves to the hash key first (CopyHeightIndexToHashIndex), which keeps a
;;;; reorged-out block's statistics retrievable -- feature_coinstatsindex.py:280
;;;; asks for exactly that.
;;;;
;;;; Until 2026-09-29 this index stored the whole running state per height
;;;; ('S' || height, and 'H' || hash off the active chain) and no 'M';
;;;; MIGRATE-COINSTATSINDEX rewrites such a database in place.

(defconstant +csi-key-height+ #x74 "Core DB_BLOCK_HEIGHT, 't'.")
(defconstant +csi-key-hash+ #x73 "Core DB_BLOCK_HASH, 's'.")
(defconstant +csi-old-key-stat+ #x53
  "'S': this tree's per-height full-state record before 2026-09-29.")
(defconstant +csi-old-key-hash+ #x48
  "'H': this tree's full-state record keyed by block hash before 2026-09-29.")

(defparameter *csi-muhash-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element (char-code #\M))
  "Core DB_MUHASH (coinstatsindex.cpp:38).")

(defstruct (coinstatsindex (:include base-index))
  "coinstatsindex state: the LevelDB (BASE-INDEX), and Core's running state --
m_muhash and the tallies as a COINSTATS (NIL until loaded or seeded) and
m_current_block_hash."
  (running nil)
  (current-hash nil))

(defmethod index-name ((index coinstatsindex)) "coinstatsindex")
(defmethod index-height ((index coinstatsindex) chainstate)
  (declare (ignore chainstate))
  (coinstatsindex-height index))
;; index-write-block for the coinstatsindex lives in src/node/indexes.lisp: the block
;; subsidy it folds in is consensus (validation), which loads after storage.

(defstruct coinstats
  "The UTXO statistics at one height (Core CCoinsStats subset). MUHASH is a
bl.crypto:muhash accumulator when the running fraction is known; a record read
back from the index carries only its finalized MUHASH-DIGEST. The rest are
satoshi/count integers."
  (muhash (bl.crypto:make-muhash))
  (muhash-digest nil)
  (txout-count 0 :type integer)
  (bogo-size 0 :type integer)
  (total-amount 0 :type integer)
  (total-subsidy 0 :type integer)
  (total-prevout-spent 0 :type integer)
  (total-new-outputs-ex-coinbase 0 :type integer)
  (total-coinbase 0 :type integer)
  (unspendable-genesis 0 :type integer)
  (unspendable-bip30 0 :type integer)
  (unspendable-scripts 0 :type integer)
  (unspendable-unclaimed 0 :type integer))

(defun coinstats-muhash-hash (stats)
  "The 32-byte finalized MuHash of STATS (what gettxoutsetinfo reports as
`muhash'), from the record or computed from the running fraction."
  (or (coinstats-muhash-digest stats)
      (bl.crypto:muhash-finalize (coinstats-muhash stats))))

;;; --- key/value encoding ---

(defun %csi-height-key (height)
  "Core DBHeightKey: 't' || height as 4 big-endian bytes (key order is height
order)."
  (let ((key (make-array 5 :element-type '(unsigned-byte 8))))
    (setf (aref key 0) +csi-key-height+)
    (dotimes (i 4 key)
      (setf (aref key (- 4 i)) (ldb (byte 8 (* 8 i)) height)))))

(defun %csi-hash-key (hash)
  "Core DBHashKey: 's' || block hash."
  (index-key +csi-key-hash+ hash))

(defun %write-le (vec offset value size)
  "Write VALUE as SIZE little-endian bytes at OFFSET (two's complement)."
  (let ((v (if (minusp value) (+ value (ash 1 (* 8 size))) value)))
    (dotimes (i size) (setf (aref vec (+ offset i)) (ldb (byte 8 (* 8 i)) v)))))

(defun %read-le (vec offset size &key signed)
  (let ((v (loop for i below size sum (ash (aref vec (+ offset i)) (* 8 i)))))
    (if (and signed (>= v (ash 1 (1- (* 8 size))))) (- v (ash 1 (* 8 size))) v)))

(defconstant +csi-dbval-size+ (+ 32 (* 4 8) (* 3 32) (* 4 8))
  "Core's DBVal: the digest, four 8-byte fields, three uint256, four CAmount.")

(defun %csi-encode-dbval (stats)
  "STATS as Core's serialized DBVal (coinstatsindex.cpp:61-80)."
  (let ((v (make-array +csi-dbval-size+ :element-type '(unsigned-byte 8))))
    (replace v (coinstats-muhash-hash stats))
    (loop with off = 32
          for (value size) in (list (list (coinstats-txout-count stats) 8)
                                    (list (coinstats-bogo-size stats) 8)
                                    (list (coinstats-total-amount stats) 8)
                                    (list (coinstats-total-subsidy stats) 8)
                                    (list (coinstats-total-prevout-spent stats) 32)
                                    (list (coinstats-total-new-outputs-ex-coinbase stats) 32)
                                    (list (coinstats-total-coinbase stats) 32)
                                    (list (coinstats-unspendable-genesis stats) 8)
                                    (list (coinstats-unspendable-bip30 stats) 8)
                                    (list (coinstats-unspendable-scripts stats) 8)
                                    (list (coinstats-unspendable-unclaimed stats) 8))
          do (%write-le v off value size)
             (incf off size))
    v))

(defun %csi-decode-dbval (v &optional (start 0))
  "The COINSTATS a serialized DBVal at START holds (digest only, no fraction),
or NIL when V is too short."
  (when (>= (length v) (+ start +csi-dbval-size+))
    (let ((off (+ start 32)))
      (flet ((next (size &optional signed)
               (prog1 (%read-le v off size :signed signed) (incf off size))))
        (make-coinstats
         :muhash nil
         :muhash-digest (subseq v start (+ start 32))
         :txout-count (next 8) :bogo-size (next 8)
         :total-amount (next 8 t) :total-subsidy (next 8 t)
         :total-prevout-spent (next 32) :total-new-outputs-ex-coinbase (next 32)
         :total-coinbase (next 32)
         :unspendable-genesis (next 8 t) :unspendable-bip30 (next 8 t)
         :unspendable-scripts (next 8 t) :unspendable-unclaimed (next 8 t))))))

(defun %csi-encode-muhash (mu)
  "Core MuHash3072 serialization: numerator then denominator, 384 LE bytes each."
  (concatenate '(simple-array (unsigned-byte 8) (*))
               (bl.crypto:le-integer-to-bytes (bl.crypto:muhash-numerator mu) 384)
               (bl.crypto:le-integer-to-bytes (bl.crypto:muhash-denominator mu) 384)))

(defun %csi-decode-muhash (v)
  (when (= (length v) 768)
    (bl.crypto:make-muhash-raw
     :numerator (bl.crypto:bytes-to-le-integer (subseq v 0 384))
     :denominator (bl.crypto:bytes-to-le-integer (subseq v 384 768)))))

(defmethod index-commit-records ((index coinstatsindex))
  "Core CustomCommit (coinstatsindex.cpp:311-317): DB_MUHASH beside the locator,
so the running fraction on disk always belongs to the committed best block."
  (let ((running (coinstatsindex-running index)))
    (when (and running (coinstats-muhash running))
      (list (cons *csi-muhash-key* (%csi-encode-muhash (coinstats-muhash running)))))))

;;; --- open/close ---

(defun coinstatsindex-path (base-path)
  "Core's indexes/coinstatsindex/db/ (index/coinstatsindex.cpp:106), falling
back to the flat coinstatsindex/ this tree used before — see kv/datadir.lisp.

:MIGRATE moves a database this tree left one level up, in coinstatsindex/
itself, down into its db/ the first time such a datadir is opened."
  (datadir-index-path (pathname base-path) :coinstats :migrate t))

(defun init-coinstatsindex (base-path &key (enabled t) wipe)
  "Open (creating if needed) the coinstatsindex under BASE-PATH. It shares the
filter index's cache line: Core divides one budget across n_indexes
(node/caches.cpp:66-70). The running state is loaded once the best block has
been placed on the chain (COINSTATSINDEX-LOAD-RUNNING).

WIPE discards the stored index first (Core's f_wipe for -reindex,
init.cpp:1920), so the caller's catch-up rebuilds it from genesis."
  (open-index-db (make-coinstatsindex :base-path (pathname base-path) :enabled enabled)
                 (coinstatsindex-path base-path)
                 :wipe wipe))

(defun close-coinstatsindex (csi)
  (close-index csi))

;;; --- reads (Core index_util::LookUpOne) ---

(defun coinstatsindex-best (csi)
  "Return (values height hash) of the highest indexed block, or (values -1 nil).
Note the order: INDEX-BEST-BLOCK, the generic underneath, answers (hash height)."
  (multiple-value-bind (hash height) (index-best-block csi)
    (if hash (values height hash) (values -1 nil))))

(defun coinstatsindex-height (csi)
  (nth-value 0 (coinstatsindex-best csi)))

(defun %csi-height-record (csi height)
  "(values block-hash stats) of the record at HEIGHT, or NIL."
  (let* ((db (coinstatsindex-db csi))
         (v (and db (>= height 0) (leveldb-get db (%csi-height-key height)))))
    (when (and v (>= (length v) (+ 32 +csi-dbval-size+)))
      (values (subseq v 0 32) (%csi-decode-dbval v 32)))))

(defun coinstatsindex-get-stats (csi height)
  "The coinstats record at HEIGHT, whatever block holds it now, or NIL. Ask
COINSTATSINDEX-GET-BLOCK-STATS when the question is about a particular block."
  (nth-value 1 (%csi-height-record csi height)))

(defun coinstatsindex-get-block-stats (csi hash height)
  "The coinstats record for the block HASH at HEIGHT, or NIL -- Core's
index_util::LookUpOne (index/db_key.h:96-113): the height record when it names
this block (the active chain), else the record a reorg left under the hash."
  (let ((db (coinstatsindex-db csi)))
    (when db
      (multiple-value-bind (stored stats) (%csi-height-record csi height)
        (if (and stored (equalp stored hash))
            stats
            (let ((hv (leveldb-get db (%csi-hash-key hash))))
              (and hv (%csi-decode-dbval hv))))))))

(defun coinstatsindex-set-best (csi height hash)
  (index-set-best csi hash height))

(defun coinstatsindex-clear-best (csi)
  "Forget the best block and the running state, so the next catch-up rebuilds
from genesis."
  (setf (coinstatsindex-running csi) nil
        (coinstatsindex-current-hash csi) nil)
  (index-clear-best csi))

(defun coinstatsindex-load-running (csi)
  "Core CoinStatsIndex::CustomInit (coinstatsindex.cpp:275-309): the running
fraction from 'M' and the tallies from the best block's record, which must
agree -- the record's digest is the fraction's. Returns T when the running
state now names the best block; NIL for an empty index. An index whose 'M' is
missing or disagrees is Core's `Cannot read current coinstatsindex state;
index may be corrupted', which stops Core's start-up; here the index is
cleared for a rebuild instead, the recovery Core's message asks the operator
for, since an optional index should not keep the node down."
  (multiple-value-bind (height hash) (coinstatsindex-best csi)
    (cond
      ((null hash)
       (setf (coinstatsindex-running csi) nil (coinstatsindex-current-hash csi) nil)
       nil)
      ((and (coinstatsindex-running csi)
            (equalp hash (coinstatsindex-current-hash csi)))
       t)
      (t
       (let* ((mu (let ((v (leveldb-get (coinstatsindex-db csi) *csi-muhash-key*)))
                    (and v (%csi-decode-muhash v))))
              (record (and mu (>= height 0)
                           (coinstatsindex-get-block-stats csi hash height))))
         (cond
           ((and record (equalp (coinstats-muhash-digest record)
                                (bl.crypto:muhash-finalize mu)))
            (setf (coinstats-muhash record) mu
                  (coinstats-muhash-digest record) nil
                  (coinstatsindex-running csi) record
                  (coinstatsindex-current-hash csi) (copy-seq hash))
            t)
           (t
            (bl.log:log-warn "Cannot read current coinstatsindex state; index may be corrupted -- rebuilding it from genesis")
            (coinstatsindex-clear-best csi)
            nil)))))))

;;; --- per-block update ---

(defun %csi-bip30-unspendable-p (height)
  "The two mainnet coinbases (heights 91722, 91812) BIP30-overwritten and thus
unspendable (Core IsBIP30Unspendable). Height-only match; only mainnet."
  (and (eq bl.chain:*network* :mainnet)
       (or (= height 91722) (= height 91812))))

(defun %copy-coinstats (s)
  (make-coinstats
   :muhash (let ((mu (coinstats-muhash s)))
             (and mu (bl.crypto:make-muhash-raw
                      :numerator (bl.crypto:muhash-numerator mu)
                      :denominator (bl.crypto:muhash-denominator mu))))
   :muhash-digest (coinstats-muhash-digest s)
   :txout-count (coinstats-txout-count s) :bogo-size (coinstats-bogo-size s)
   :total-amount (coinstats-total-amount s) :total-subsidy (coinstats-total-subsidy s)
   :total-prevout-spent (coinstats-total-prevout-spent s)
   :total-new-outputs-ex-coinbase (coinstats-total-new-outputs-ex-coinbase s)
   :total-coinbase (coinstats-total-coinbase s)
   :unspendable-genesis (coinstats-unspendable-genesis s)
   :unspendable-bip30 (coinstats-unspendable-bip30 s)
   :unspendable-scripts (coinstats-unspendable-scripts s)
   :unspendable-unclaimed (coinstats-unspendable-unclaimed s)))

(defun apply-block-to-coinstats (stats block block-hash height spent-utxos subsidy)
  "Fold BLOCK (at HEIGHT, hash BLOCK-HASH, spending SPENT-UTXOS = undo list of
(txid index utxo-entry)) into the running STATS in place (Core
CoinStatsIndex::CustomAppend). SUBSIDY is the block reward for HEIGHT. Returns
STATS."
  (declare (ignore block-hash))
  (incf (coinstats-total-subsidy stats) subsidy)
  (let ((txs (bl.ser:bitcoin-block-transactions block))
        (mu (coinstats-muhash stats)))
    (if (zerop height)
        ;; Genesis coinbase is unspendable (its outputs never enter the UTXO set).
        (incf (coinstats-unspendable-genesis stats) subsidy)
        (progn
          ;; Created outputs.
          (loop for tx in txs
                for tx-idx from 0
                for coinbase = (zerop tx-idx)
                for txid = (bl.ser:transaction-hash tx)
                do (if (and coinbase (%csi-bip30-unspendable-p height))
                       (incf (coinstats-unspendable-bip30 stats) subsidy)
                       (loop for out across (bl.ser:transaction-outputs tx)
                             for vout from 0
                             for spk = (bl.ser:tx-out-script-pubkey out)
                             for value = (bl.ser:tx-out-value out)
                             ;; Provably-unspendable outputs are dropped from the
                             ;; UTXO set (Core AddCoin / our block apply), so they
                             ;; contribute to the unspendable-scripts bucket, not
                             ;; the MuHash or the live counts.
                             do (cond
                                  ((script-unspendable-p spk)
                                   (incf (coinstats-unspendable-scripts stats) value))
                                  (t
                                   (bl.crypto:muhash-insert
                                    mu (coerce (coin-muhash-element txid vout height coinbase value spk)
                                               '(simple-array (unsigned-byte 8) (*))))
                                   (if coinbase
                                       (incf (coinstats-total-coinbase stats) value)
                                       (incf (coinstats-total-new-outputs-ex-coinbase stats) value))
                                   (incf (coinstats-txout-count stats))
                                   (incf (coinstats-total-amount stats) value)
                                   (incf (coinstats-bogo-size stats)
                                         (+ +bogo-size-overhead+ (length spk))))))))
          ;; Spent prevouts (from undo data).
          (dolist (entry spent-utxos)
            (destructuring-bind (ptxid pidx putxo) entry
              (let ((value (utxo-entry-value putxo))
                    (spk (utxo-entry-script-pubkey putxo)))
                (bl.crypto:muhash-remove
                 mu (coerce (coin-muhash-element ptxid pidx
                                                 (utxo-entry-height putxo)
                                                 (utxo-entry-coinbase putxo)
                                                 value spk)
                            '(simple-array (unsigned-byte 8) (*))))
                (incf (coinstats-total-prevout-spent stats) value)
                (decf (coinstats-txout-count stats))
                (decf (coinstats-total-amount stats) value)
                (decf (coinstats-bogo-size stats)
                      (+ +bogo-size-overhead+ (length spk))))))))
    ;; Unclaimed reward (miner took less than subsidy + fees) is unspendable.
    (let* ((unspendable-total (+ (coinstats-unspendable-genesis stats)
                                 (coinstats-unspendable-bip30 stats)
                                 (coinstats-unspendable-scripts stats)
                                 (coinstats-unspendable-unclaimed stats)))
           (unclaimed (- (+ (coinstats-total-prevout-spent stats)
                            (coinstats-total-subsidy stats))
                         (+ (coinstats-total-new-outputs-ex-coinbase stats)
                            (coinstats-total-coinbase stats)
                            unspendable-total))))
      (incf (coinstats-unspendable-unclaimed stats) unclaimed)))
  stats)

;; GetBogoSize = 32 (txid) + 4 (vout) + 4 (height+coinbase) + 8 (amount)
;; + 2 (script len) + script.size = 44 + scriptlen.

;; GetBogoSize = 32 (txid) + 4 (vout) + 4 (height+coinbase) + 8 (amount)
;; + 2 (script len) + script.size = 44 + scriptlen.

(defun %csi-write-record (csi stats block-hash height)
  "Core CustomAppend's write (coinstatsindex.cpp:237-241): STATS as the height
record. Whatever the height held for ANOTHER block moves to that block's hash
key first (CopyHeightIndexToHashIndex, as CustomRemove does it)."
  (let ((db (coinstatsindex-db csi)))
    (with-leveldb-writebatch (batch)
      (let ((old (leveldb-get db (%csi-height-key height))))
        (when (and old (>= (length old) 32) (not (equalp (subseq old 0 32) block-hash)))
          (leveldb-writebatch-put batch (%csi-hash-key (subseq old 0 32)) (subseq old 32))))
      (leveldb-writebatch-put batch (%csi-height-key height)
                              (concatenate '(simple-array (unsigned-byte 8) (*))
                                           block-hash (%csi-encode-dbval stats)))
      (leveldb-write db batch))))

(defun %csi-advance (csi stats block-hash height)
  "Make STATS, for BLOCK-HASH at HEIGHT, the running state and the best block."
  (setf (coinstats-muhash-digest stats) nil
        (coinstatsindex-running csi) stats
        (coinstatsindex-current-hash csi) (copy-seq block-hash))
  (index-set-best csi block-hash height)
  stats)

(defun coinstatsindex-seed-genesis (csi genesis-subsidy genesis-hash)
  "Index genesis (Core CustomAppend's height-0 branch): its coinbase is
unspendable, so it contributes an empty MuHash and adds GENESIS-SUBSIDY to
total_subsidy and the genesis unspendable bucket, leaving unclaimed rewards at
0. Only for an empty index."
  (when (and (coinstatsindex-enabled csi) (coinstatsindex-db csi)
             (< (coinstatsindex-height csi) 0))
    (let ((stats (make-coinstats :total-subsidy genesis-subsidy
                                 :unspendable-genesis genesis-subsidy)))
      (%csi-write-record csi stats genesis-hash 0)
      (%csi-advance csi stats genesis-hash 0))))

(defun coinstatsindex-add-block (csi block block-hash height spent-utxos subsidy)
  "Core CoinStatsIndex::CustomAppend (coinstatsindex.cpp:112-243): fold BLOCK at
HEIGHT into the running state, store the record, and advance the best block.
Returns the new coinstats, or NIL if disabled, or when the running state is not
BLOCK's parent's (Core's `previous block header belongs to unexpected block')
-- the caller rewinds or backfills."
  (unless (and (coinstatsindex-enabled csi) (coinstatsindex-db csi))
    (return-from coinstatsindex-add-block nil))
  (let ((parent (cond ((zerop height) (make-coinstats))
                      ((and (or (coinstatsindex-running csi)
                                (coinstatsindex-load-running csi))
                            (equalp (coinstatsindex-current-hash csi)
                                    (bl.ser:block-header-prev-block
                                     (bl.ser:bitcoin-block-header block))))
                       (coinstatsindex-running csi)))))
    (when parent
      (let ((stats (apply-block-to-coinstats (%copy-coinstats parent)
                                             block block-hash height spent-utxos subsidy)))
        (%csi-write-record csi stats block-hash height)
        (%csi-advance csi stats block-hash height)))))

(defun coinstatsindex-revert-block (csi block block-hash height spent-utxos)
  "Core CoinStatsIndex::CustomRemove + RevertBlock (coinstatsindex.cpp:245-262,
329-399) for BLOCK, the running state's block: its record is copied to its hash
key, the MuHash loses the outputs BLOCK created and regains the coins it spent
(SPENT-UTXOS, its undo list), and the tallies come back from the parent's
record -- whose digest must be what the reversed MuHash finalizes to (Core
asserts it). Returns T, or NIL when the state is not BLOCK's or the parent's
record disagrees; the caller then rebuilds the index."
  (let ((running (coinstatsindex-running csi))
        (db (coinstatsindex-db csi))
        (prev-hash (bl.ser:block-header-prev-block (bl.ser:bitcoin-block-header block))))
    (when (and running (coinstats-muhash running) (plusp height)
               (equalp (coinstatsindex-current-hash csi) block-hash))
      (multiple-value-bind (stored) (%csi-height-record csi height)
        (when (and stored (equalp stored block-hash))
          (leveldb-put db (%csi-hash-key block-hash)
                       (subseq (leveldb-get db (%csi-height-key height)) 32))))
      (let ((mu (coinstats-muhash (%copy-coinstats running)))
            (parent (coinstatsindex-get-block-stats csi prev-hash (1- height))))
        (loop for tx in (bl.ser:bitcoin-block-transactions block)
              for coinbase = t then nil
              for txid = (bl.ser:transaction-hash tx)
              unless (and coinbase (%csi-bip30-unspendable-p height))
                do (loop for out across (bl.ser:transaction-outputs tx)
                         for vout from 0
                         for spk = (bl.ser:tx-out-script-pubkey out)
                         unless (script-unspendable-p spk)
                           do (bl.crypto:muhash-remove
                               mu (coerce (coin-muhash-element txid vout height coinbase
                                                               (bl.ser:tx-out-value out) spk)
                                          '(simple-array (unsigned-byte 8) (*))))))
        (dolist (entry spent-utxos)
          (destructuring-bind (ptxid pidx putxo) entry
            (bl.crypto:muhash-insert
             mu (coerce (coin-muhash-element ptxid pidx (utxo-entry-height putxo)
                                             (utxo-entry-coinbase putxo)
                                             (utxo-entry-value putxo)
                                             (utxo-entry-script-pubkey putxo))
                        '(simple-array (unsigned-byte 8) (*))))))
        (when (and parent (equalp (coinstats-muhash-digest parent)
                                  (bl.crypto:muhash-finalize mu)))
          (setf (coinstats-muhash parent) mu)
          (%csi-advance csi parent prev-hash (1- height))
          t)))))

;;; --- backfill over stored blocks ---

(defun %csi-block-spends-p (block)
  (> (length (bl.ser:bitcoin-block-transactions block)) 1))

(defun build-coinstatsindex (csi chain-state block-store get-undo-fn subsidy-fn
                             &key progress-callback)
  "Backfill from just past the last indexed height to the active tip, using
stored blocks and undo data. Each block folds into the running state, so the
backfill starts at genesis or resumes exactly at best+1, and stops at the first
block it cannot fold (missing body or undo data). SUBSIDY-FN maps a height to
its block subsidy. Returns the number of blocks indexed."
  (unless (and (coinstatsindex-enabled csi) (coinstatsindex-db csi))
    (return-from build-coinstatsindex 0))
  (when (< (coinstatsindex-height csi) 0)
    (coinstatsindex-seed-genesis csi (funcall subsidy-fn 0)
                                 (network-genesis-hash bl.chain:*network*)))
  (let* ((tip (current-height chain-state))
         (start (max 1 (1+ (coinstatsindex-height csi))))
         (count 0)
         (last-report (get-internal-real-time)))
    (block done
      ;; One backward walk for the whole range, not a tip walk per height.
      (dolist (entry (and (<= start tip)
                          (active-chain-entries-from chain-state start (1+ (- tip start)))))
        (let* ((height (block-index-entry-height entry))
               (hash (block-index-entry-hash entry))
               (block (get-block block-store hash))
               (undo (and block (funcall get-undo-fn hash))))
          ;; A spending block with no undo data cannot be folded in; stop
          ;; (keeps the running chain contiguous).
          (when (or (null block) (and (null undo) (%csi-block-spends-p block))
                    (null (coinstatsindex-add-block csi block hash height undo
                                                    (funcall subsidy-fn height))))
            (return-from done))
          (incf count)
          (when progress-callback
            (let ((now (get-internal-real-time)))
              (when (> (- now last-report) internal-time-units-per-second)
                (funcall progress-callback height
                         (if (zerop tip) 100.0 (* 100.0 (/ height tip))))
                (setf last-report now)))))))
    (when progress-callback (funcall progress-callback tip 100.0))
    count))

;;; --- Migration: this tree's records -> Core's (2026-09-29) ---
;;;
;;; The old record held the whole running state per height -- numerator and
;;; denominator (384 LE bytes each), eleven i64 tallies, then (since
;;; 2026-09-13) the block hash -- under 'S' || height u32 BE, and under
;;; 'H' || hash for a block a reorg took off the active chain. Core's record
;;; keeps the finalized digest and the tallies, and the fraction exists once,
;;; under 'M', for the best block. So the migration writes 'M' from the best
;;; height's old record first, then converts every 'S' record in height order
;;; (finalizing each fraction: one modular inversion per height) and every
;;; 'H' record, deleting each old key in the batch that writes its
;;; replacement. An interruption leaves the unconverted records in place and
;;; the next start converts on; nothing is read from the block files. A record
;;; from before the block hash was stored names its block through the active
;;; chain at its height.

(defun %read-be (vec offset size)
  (loop for i below size sum (ash (aref vec (+ offset i)) (* 8 (- size 1 i)))))

(defconstant +csi-old-record-size+ (+ 384 384 (* 8 11))
  "The old full-state record without its trailing block hash.")

(defun %csi-decode-old-record (v)
  "(values stats block-hash-or-nil) of an old full-state record."
  (when (>= (length v) +csi-old-record-size+)
    (let ((mu (bl.crypto:make-muhash-raw
               :numerator (bl.crypto:bytes-to-le-integer (subseq v 0 384))
               :denominator (bl.crypto:bytes-to-le-integer (subseq v 384 768))))
          (tallies (loop for off from 768 below +csi-old-record-size+ by 8
                         collect (%read-le v off 8 :signed t))))
      (destructuring-bind (txouts bogo amount subsidy spent new coinbase
                           genesis bip30 scripts unclaimed)
          tallies
        (values (make-coinstats :muhash mu :txout-count txouts :bogo-size bogo
                                :total-amount amount :total-subsidy subsidy
                                :total-prevout-spent spent
                                :total-new-outputs-ex-coinbase new
                                :total-coinbase coinbase
                                :unspendable-genesis genesis :unspendable-bip30 bip30
                                :unspendable-scripts scripts
                                :unspendable-unclaimed unclaimed)
                (and (>= (length v) (+ +csi-old-record-size+ 32))
                     (subseq v +csi-old-record-size+ (+ +csi-old-record-size+ 32))))))))

(defun %csi-old-records (csi prefix limit)
  "Up to LIMIT (key . value) old records under PREFIX, in key order."
  (let ((out '()) (n 0))
    (with-leveldb-iterator (it (coinstatsindex-db csi))
      (leveldb-iter-seek it (make-array 1 :element-type '(unsigned-byte 8) :initial-element prefix))
      (loop while (and (leveldb-iter-valid-p it) (< n limit))
            for k = (leveldb-iter-key it)
            while (and (plusp (length k)) (= (aref k 0) prefix))
            do (push (cons k (leveldb-iter-value it)) out)
               (incf n)
               (leveldb-iter-next it)))
    (nreverse out)))

(defun coinstatsindex-needs-migration-p (csi)
  "T when CSI still holds records in this tree's pre-Core layout."
  (and (coinstatsindex-enabled csi) (coinstatsindex-db csi)
       (or (%csi-old-records csi +csi-old-key-stat+ 1)
           (%csi-old-records csi +csi-old-key-hash+ 1))
       t))

(defun migrate-coinstatsindex (csi chain-state &key (batch 1000))
  "Rewrite CSI's records in Core's layout, in place (see above). Returns the
number of records converted, or NIL when there was nothing to do."
  (unless (coinstatsindex-needs-migration-p csi)
    (return-from migrate-coinstatsindex nil))
  (let* ((start-time (get-internal-real-time))
         (db (coinstatsindex-db csi))
         (best (coinstatsindex-height csi))
         (tip (current-height chain-state))
         (active (let ((table (make-hash-table)))
                   (dolist (e (active-chain-entries-from chain-state 0 (1+ tip)) table)
                     (setf (gethash (block-index-entry-height e) table)
                           (block-index-entry-hash e)))))
         (converted 0))
    (bl.log:log-info "coinstatsindex: migrating records to Core's layout (best height ~D)" best)
    ;; 'M' first, from the best block's old record, while it is still there.
    (let ((v (and (>= best 0)
                  (leveldb-get db (index-key +csi-old-key-stat+
                                             (subseq (%csi-height-key best) 1))))))
      (when v
        (leveldb-put db *csi-muhash-key*
                     (%csi-encode-muhash (coinstats-muhash (%csi-decode-old-record v))))))
    (dolist (prefix (list +csi-old-key-stat+ +csi-old-key-hash+))
      (loop for rows = (%csi-old-records csi prefix batch)
            while rows
            do (with-leveldb-writebatch (b)
                 (dolist (row rows)
                   (multiple-value-bind (stats stored-hash) (%csi-decode-old-record (cdr row))
                     (let* ((key (car row))
                            (height (and (= prefix +csi-old-key-stat+) (%read-be key 1 4)))
                            (hash (or stored-hash
                                      (if height (gethash height active) (subseq key 1)))))
                       (when (and stats hash)
                         (leveldb-writebatch-put
                          b (if height (%csi-height-key height) (%csi-hash-key hash))
                          (if height
                              (concatenate '(simple-array (unsigned-byte 8) (*))
                                           hash (%csi-encode-dbval stats))
                              (%csi-encode-dbval stats)))
                         (incf converted))
                       (leveldb-writebatch-delete b key))))
                 (leveldb-write db b))
               (bl.log:log-info "coinstatsindex: ~D records migrated" converted)))
    (bl.log:log-info "coinstatsindex: migration done -- ~D record~:P in ~,1Fs"
                     converted (/ (- (get-internal-real-time) start-time)
                                  internal-time-units-per-second))
    converted))

(defmethod index-migrate-records ((index coinstatsindex) chainstate)
  (migrate-coinstatsindex index chainstate))
