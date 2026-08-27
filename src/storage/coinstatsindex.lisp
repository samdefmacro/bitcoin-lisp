(in-package #:bitcoin-lisp.storage)

;;;; coinstatsindex — per-height UTXO-set statistics (Bitcoin Core
;;;; src/index/coinstatsindex.cpp + kernel/coinstats.cpp).
;;;;
;;;; Maintains, at every block height, the running MuHash of the UTXO set plus
;;;; the amount/count tallies gettxoutsetinfo reports (total amount, txout
;;;; count, bogosize, subsidy, spent/created/coinbase amounts, and the four
;;;; unspendable buckets). Because MuHash is incremental, each block only adds
;;;; its created outputs and removes its spent prevouts -- no full UTXO rescan.
;;;;
;;;; DESIGN: each height record stores the COMPLETE running state (the MuHash
;;;; numerator/denominator fraction plus every tally), not just a delta. So
;;;; connecting a block at height H loads height H-1's record, applies H's
;;;; delta, and writes H. That makes reorgs correct with no rewind logic: the
;;;; reconnected fork blocks (applied oldest-first) each load their parent's
;;;; stored state and recompute forward from the unchanged common ancestor.
;;;; The cost is ~800 bytes/height of MuHash fraction; acceptable for an
;;;; opt-in index, and it sidesteps the disconnect/revert bugs a running-only
;;;; index is prone to.
;;;;
;;;; LevelDB layout (dedicated DB under <datadir>/coinstatsindex/):
;;;;   key 0x53 || height(u32 BE)  ->  serialized stat record (see below)
;;;;   key 0x42 (meta)             ->  best-height(u32 LE) || best-hash(32)

(defconstant +csi-key-stat+ #x53 "LevelDB key prefix ('S') for per-height records.")
(defconstant +csi-key-meta+ #x42 "LevelDB key ('B') for the best-indexed metadata.")

(defstruct (coinstatsindex (:include base-index))
  "coinstatsindex state (open LevelDB handle + enabled flag).")

(defmethod index-name ((index coinstatsindex)) "coinstatsindex")
(defmethod index-height ((index coinstatsindex)) (coinstatsindex-height index))
(defmethod index-best-block ((index coinstatsindex))
  (multiple-value-bind (height hash) (coinstatsindex-best index)
    (and hash (values hash height))))
(defmethod index-set-best ((index coinstatsindex) block-hash height)
  (coinstatsindex-set-best index height block-hash))
(defmethod index-clear-best ((index coinstatsindex)) (coinstatsindex-clear-best index))
;; index-write-block for the coinstatsindex lives in src/node.lisp: the block
;; subsidy it folds in is consensus (validation), which loads after storage.

(defstruct coinstats
  "The running UTXO statistics at one height (Core CCoinsStats subset). MUHASH
is a bl.crypto:muhash accumulator; the rest are satoshi/count
integers."
  (muhash (bl.crypto:make-muhash))
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

;;; --- key/value encoding ---

(defun %csi-stat-key (height)
  "Key for HEIGHT's record: prefix byte + height as 4 big-endian bytes (so the
key order is height order)."
  (let ((k (make-array 5 :element-type '(unsigned-byte 8))))
    (setf (aref k 0) +csi-key-stat+)
    (dotimes (i 4) (setf (aref k (- 4 i)) (logand (ash height (* -8 i)) #xff)))
    k))

(defparameter *csi-meta-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element +csi-key-meta+))

(defun %csi-encode-meta (height hash)
  (let ((v (make-array 36 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref v i) (logand (ash height (* -8 i)) #xff)))
    (replace v hash :start1 4)
    v))

(defun %csi-decode-meta (v)
  (values (loop for i below 4 sum (ash (aref v i) (* 8 i)))
          (subseq v 4 36)))

;; A record is: muhash numerator (384 LE) || denominator (384 LE) || 11 tallies
;; each as a signed 64-bit little-endian value.
(defconstant +csi-record-fields+ 11)
(defconstant +csi-record-size+ (+ 384 384 (* 8 +csi-record-fields+)))

(defun %write-i64-le (vec offset value)
  "Write VALUE as 8 little-endian bytes at OFFSET (two's complement)."
  (let ((v (if (minusp value) (+ value (ash 1 64)) value)))
    (dotimes (i 8) (setf (aref vec (+ offset i)) (logand (ash v (* -8 i)) #xff)))))

(defun %read-i64-le (vec offset)
  (let ((v (loop for i below 8 sum (ash (aref vec (+ offset i)) (* 8 i)))))
    (if (>= v (ash 1 63)) (- v (ash 1 64)) v)))

(defun %csi-encode-stat (stats)
  (let ((v (make-array +csi-record-size+ :element-type '(unsigned-byte 8)))
        (mu (coinstats-muhash stats)))
    (replace v (bl.crypto::%le-integer-to-bytes
                (bl.crypto:muhash-numerator mu) 384))
    (replace v (bl.crypto::%le-integer-to-bytes
                (bl.crypto:muhash-denominator mu) 384)
             :start1 384)
    (loop for off from 768 by 8
          for val in (list (coinstats-txout-count stats)
                           (coinstats-bogo-size stats)
                           (coinstats-total-amount stats)
                           (coinstats-total-subsidy stats)
                           (coinstats-total-prevout-spent stats)
                           (coinstats-total-new-outputs-ex-coinbase stats)
                           (coinstats-total-coinbase stats)
                           (coinstats-unspendable-genesis stats)
                           (coinstats-unspendable-bip30 stats)
                           (coinstats-unspendable-scripts stats)
                           (coinstats-unspendable-unclaimed stats))
          do (%write-i64-le v off val))
    v))

(defun %csi-decode-stat (v)
  (let ((mu (bl.crypto::%make-muhash
             :numerator (bl.crypto::%bytes-to-le-integer (subseq v 0 384))
             :denominator (bl.crypto::%bytes-to-le-integer (subseq v 384 768)))))
    (make-coinstats
     :muhash mu
     :txout-count (%read-i64-le v 768)
     :bogo-size (%read-i64-le v 776)
     :total-amount (%read-i64-le v 784)
     :total-subsidy (%read-i64-le v 792)
     :total-prevout-spent (%read-i64-le v 800)
     :total-new-outputs-ex-coinbase (%read-i64-le v 808)
     :total-coinbase (%read-i64-le v 816)
     :unspendable-genesis (%read-i64-le v 824)
     :unspendable-bip30 (%read-i64-le v 832)
     :unspendable-scripts (%read-i64-le v 840)
     :unspendable-unclaimed (%read-i64-le v 848))))

;;; --- open/close ---

(defun coinstatsindex-path (base-path)
  "Core's indexes/coinstatsindex/, falling back to the flat coinstatsindex/
this tree used before — see storage/datadir.lisp."
  (datadir-index-path (pathname base-path) :coinstats))

(defun init-coinstatsindex (base-path &key (enabled t))
  "Open (creating if needed) the coinstatsindex under BASE-PATH."
  (let ((csi (make-coinstatsindex :base-path (pathname base-path) :enabled enabled)))
    (when enabled
      (let ((path (coinstatsindex-path base-path)))
        (ensure-directories-exist path)
        ;; coinstats shares the filter index's per-index share: Core
        ;; divides one budget across n_indexes (node/caches.cpp:66-70).
        (setf (coinstatsindex-db csi)
              (leveldb-open-tuned
               path :cache-bytes (if *cache-sizes*
                                     (cache-sizes-filter-index *cache-sizes*)
                                     0)))))
    csi))

(defun close-coinstatsindex (csi)
  (when (coinstatsindex-db csi)
    (leveldb-close (coinstatsindex-db csi))
    (setf (coinstatsindex-db csi) nil)))

;;; --- reads ---

(defun coinstatsindex-best (csi)
  "Return (values height hash) of the highest indexed block, or (values -1 nil)."
  (let ((db (coinstatsindex-db csi)))
    (if (null db)
        (values -1 nil)
        (let ((v (leveldb-get db *csi-meta-key*)))
          (if (and v (>= (length v) 36)) (%csi-decode-meta v) (values -1 nil))))))

(defun coinstatsindex-height (csi)
  (nth-value 0 (coinstatsindex-best csi)))

(defun coinstatsindex-get-stats (csi height)
  "Return the coinstats record at HEIGHT, or NIL if not indexed."
  (let ((db (coinstatsindex-db csi)))
    (when db
      (let ((v (leveldb-get db (%csi-stat-key height))))
        (when (and v (>= (length v) +csi-record-size+))
          (%csi-decode-stat v))))))

(defun coinstatsindex-set-best (csi height hash)
  (when (coinstatsindex-db csi)
    (leveldb-put (coinstatsindex-db csi) *csi-meta-key* (%csi-encode-meta height hash))))

(defun coinstatsindex-clear-best (csi)
  (when (coinstatsindex-db csi)
    (leveldb-delete (coinstatsindex-db csi) *csi-meta-key*)))

;;; --- per-block update ---

(defun %csi-bip30-unspendable-p (height)
  "The two mainnet coinbases (heights 91722, 91812) BIP30-overwritten and thus
unspendable (Core IsBIP30Unspendable). Height-only match; only mainnet."
  (and (eq bl:*network* :mainnet)
       (or (= height 91722) (= height 91812))))

(defun %copy-coinstats (s)
  (make-coinstats
   :muhash (bl.crypto::%make-muhash
            :numerator (bl.crypto:muhash-numerator (coinstats-muhash s))
            :denominator (bl.crypto:muhash-denominator (coinstats-muhash s)))
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
                                   (incf (coinstats-bogo-size stats) (+ 44 (length spk))))))))
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
                (decf (coinstats-bogo-size stats) (+ 44 (length spk))))))))
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

(defun coinstatsindex-seed-genesis (csi genesis-subsidy genesis-hash)
  "Write the height-0 record without the genesis block body (which the node
does not store). Genesis's coinbase is unspendable, so it contributes an empty
MuHash and adds GENESIS-SUBSIDY to both total_subsidy and the genesis
unspendable bucket (Core's genesis branch), leaving unclaimed rewards at 0.
Only writes if the index is empty."
  (when (and (coinstatsindex-enabled csi) (coinstatsindex-db csi)
             (< (coinstatsindex-height csi) 0))
    (let ((stats (make-coinstats :total-subsidy genesis-subsidy
                                 :unspendable-genesis genesis-subsidy)))
      (leveldb-put (coinstatsindex-db csi) (%csi-stat-key 0) (%csi-encode-stat stats))
      (leveldb-put (coinstatsindex-db csi) *csi-meta-key*
                   (%csi-encode-meta 0 genesis-hash))
      stats)))

(defun coinstatsindex-add-block (csi block block-hash height spent-utxos subsidy)
  "Index BLOCK at HEIGHT: load the parent (height-1) running state, fold in the
block, store the new record, and advance the best marker. Returns the new
coinstats, or NIL if disabled or the parent record is missing (non-contiguous;
the caller should stop/backfill)."
  (unless (and (coinstatsindex-enabled csi) (coinstatsindex-db csi))
    (return-from coinstatsindex-add-block nil))
  (let ((parent (if (zerop height)
                    (make-coinstats)
                    (coinstatsindex-get-stats csi (1- height)))))
    (when (or parent (zerop height))
      (let ((stats (apply-block-to-coinstats
                    (if parent (%copy-coinstats parent) (make-coinstats))
                    block block-hash height spent-utxos subsidy)))
        ;; Record and best marker in ONE batch (Core BaseIndex::Commit writes
        ;; CustomCommit's entries and the best-block locator in a single
        ;; CDBBatch, index/base.cpp:270-288). As two separate puts, a kill
        ;; between them left the marker naming a height whose record was not
        ;; written, or a record no marker vouched for.
        (let ((batch (leveldb-make-writebatch)))
          (unwind-protect
               (progn
                 (leveldb-writebatch-put batch (%csi-stat-key height)
                                         (%csi-encode-stat stats))
                 (leveldb-writebatch-put batch *csi-meta-key*
                                         (%csi-encode-meta height block-hash))
                 (leveldb-write (coinstatsindex-db csi) batch))
            (leveldb-destroy-writebatch batch)))
        stats))))

(defun coinstatsindex-record-matches-block-p (csi block block-hash height
                                              spent-utxos subsidy)
  "T iff the stored record at HEIGHT is exactly what folding BLOCK into the
stored record at HEIGHT-1 produces — that is, the record at HEIGHT was written
for THIS block and not for a competing branch's block at the same height.

Records are keyed by height alone, with no block hash. Core keys each record by
pair<uint256, DBVal> and compares the stored hash against the expected one in
RevertBlock (index/coinstatsindex.cpp:337-348); recomputing is the equivalent
evidence, since a 3072-bit MuHash fraction plus eleven tallies cannot coincide
by accident. NIL if either record is missing (nothing to compare against)."
  (let ((stored (coinstatsindex-get-stats csi height))
        (parent (and (plusp height) (coinstatsindex-get-stats csi (1- height)))))
    (when (and stored parent)
      (let ((computed (apply-block-to-coinstats
                       (%copy-coinstats parent)
                       block block-hash height spent-utxos subsidy)))
        (equalp (%csi-encode-stat computed) (%csi-encode-stat stored))))))

;;; --- backfill over stored blocks ---

(defun build-coinstatsindex (csi chain-state block-store get-undo-fn subsidy-fn
                             &key progress-callback)
  "Backfill from just past the last indexed height to the active tip, using
stored blocks and undo data. Because each record needs its parent's state, the
backfill must start at height 0 (or resume exactly at best+1); if the parent
record is missing it stops. SUBSIDY-FN maps a height to its block subsidy.
Returns the number of blocks indexed."
  (unless (and (coinstatsindex-enabled csi) (coinstatsindex-db csi))
    (return-from build-coinstatsindex 0))
  ;; Seed the synthetic genesis record so height 1 has a parent to build on.
  (when (< (coinstatsindex-height csi) 0)
    (coinstatsindex-seed-genesis csi (funcall subsidy-fn 0)
                                 (network-genesis-hash bl:*network*)))
  (let* ((tip (current-height chain-state))
         (start (1+ (coinstatsindex-height csi)))
         (count 0)
         (last-report (get-internal-real-time)))
    (block done
      (loop for height from (max 1 start) to tip
            do (let* ((entry (get-block-at-height chain-state height))
                      (hash (and entry (block-index-entry-hash entry)))
                      (block (and hash (get-block block-store hash)))
                      (undo (and block (funcall get-undo-fn hash))))
                 ;; A spending block with no undo data cannot be folded in;
                 ;; stop (keeps the running chain contiguous).
                 (when (null block) (return-from done))
                 (when (and (null undo) (%csi-block-spends-p block)) (return-from done))
                 (unless (coinstatsindex-add-block csi block hash height undo
                                                   (funcall subsidy-fn height))
                   (return-from done))
                 (incf count))
               (when progress-callback
                 (let ((now (get-internal-real-time)))
                   (when (> (- now last-report) internal-time-units-per-second)
                     (funcall progress-callback height
                              (if (zerop tip) 100.0 (* 100.0 (/ height tip))))
                     (setf last-report now))))))
    (when progress-callback (funcall progress-callback tip 100.0))
    count))

(defun %csi-block-spends-p (block)
  (> (length (bl.ser:bitcoin-block-transactions block)) 1))
