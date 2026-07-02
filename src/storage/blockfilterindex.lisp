(in-package #:bitcoin-lisp.storage)

;;;; BIP157/158 block filter index (persistent, LevelDB-backed)
;;;;
;;;; Stores one basic (type 0x00) GCS filter per block plus the BIP157 filter
;;;; header chain, so getblockfilter / scanblocks / getdescriptoractivity can
;;;; serve light clients. Filters are built at block-connect time from the undo
;;;; data (the scriptPubKeys the block spends) already computed for the UTXO set,
;;;; so indexing adds no extra block scan.
;;;;
;;;; LevelDB layout (dedicated DB under <datadir>/blockfilterindex/):
;;;;   key 0x66 || block-hash(32)  ->  filter-header(32) || encoded-filter
;;;;   key 0x42 (meta)             ->  best-height(u32-le) || best-block-hash(32)
;;;;
;;;; Filters are keyed by block hash, so blocks orphaned by a reorg keep their
;;;; filters queryable (as Bitcoin Core keeps them in its hash index). The meta
;;;; key is overwritten on every connect (including reorg reconnects), so it
;;;; always names the active-chain tip; no disconnect hook is required.

(defconstant +bfi-key-filter+ #x66
  "LevelDB key prefix byte ('f') for per-block filter records.")

(defconstant +bfi-key-meta+ #x42
  "LevelDB key byte ('B') for the best-indexed-block metadata record.")

(defstruct blockfilterindex
  "Block filter index state."
  (base-path nil :type (or null pathname))
  (db nil)
  (enabled nil :type boolean))

(defun blockfilterindex-path (base-path)
  "Directory holding the block filter index LevelDB."
  (merge-pathnames "blockfilterindex/" (pathname base-path)))

(defun init-blockfilterindex (base-path &key (enabled t))
  "Open (creating if needed) the block filter index under BASE-PATH.
A disabled index ignores writes and reads and holds no DB handle."
  (let ((bfi (make-blockfilterindex :base-path (pathname base-path) :enabled enabled)))
    (when enabled
      (let ((path (blockfilterindex-path base-path)))
        (ensure-directories-exist path)
        (setf (blockfilterindex-db bfi) (leveldb-open path))))
    bfi))

(defun close-blockfilterindex (bfi)
  "Close the index's LevelDB handle."
  (when (blockfilterindex-db bfi)
    (leveldb-close (blockfilterindex-db bfi))
    (setf (blockfilterindex-db bfi) nil)))

;;; --- key/value encoding ---

(defun %bfi-filter-key (block-hash)
  (let ((k (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref k 0) +bfi-key-filter+)
    (replace k block-hash :start1 1)
    k))

(defparameter *bfi-meta-key*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element +bfi-key-meta+)
  "The single-byte LevelDB key of the best-indexed-block metadata record.")

(defun %bfi-encode-record (header filter)
  (concatenate '(simple-array (unsigned-byte 8) (*)) header filter))

(defun %bfi-encode-meta (height hash)
  (let ((v (make-array 36 :element-type '(unsigned-byte 8))))
    (dotimes (i 4) (setf (aref v i) (logand (ash height (* -8 i)) #xff)))
    (replace v hash :start1 4)
    v))

(defun %bfi-decode-meta (v)
  (values (loop for i below 4 sum (ash (aref v i) (* 8 i)))
          (subseq v 4 36)))

;;; --- reads ---

(defun blockfilterindex-get (bfi block-hash)
  "Return (values encoded-filter filter-header) for BLOCK-HASH, or
(values nil nil) if the block is not indexed."
  (let ((db (blockfilterindex-db bfi)))
    (if (null db)
        (values nil nil)
        (let ((rec (leveldb-get db (%bfi-filter-key block-hash))))
          (if (and rec (>= (length rec) 32))
              (values (subseq rec 32) (subseq rec 0 32))
              (values nil nil))))))

(defun blockfilterindex-get-filter (bfi block-hash)
  "Return the encoded basic filter bytes for BLOCK-HASH, or NIL."
  (nth-value 0 (blockfilterindex-get bfi block-hash)))

(defun blockfilterindex-get-header (bfi block-hash)
  "Return the 32-byte basic filter header for BLOCK-HASH, or NIL."
  (nth-value 1 (blockfilterindex-get bfi block-hash)))

(defun blockfilterindex-has-block-p (bfi block-hash)
  "T if BLOCK-HASH has an indexed filter."
  (and (blockfilterindex-db bfi)
       (not (null (leveldb-get (blockfilterindex-db bfi) (%bfi-filter-key block-hash))))))

(defun blockfilterindex-best (bfi)
  "Return (values height hash) of the highest indexed block, or (values -1 nil)."
  (let ((db (blockfilterindex-db bfi)))
    (if (null db)
        (values -1 nil)
        (let ((v (leveldb-get db *bfi-meta-key*)))
          (if (and v (>= (length v) 36))
              (%bfi-decode-meta v)
              (values -1 nil))))))

(defun blockfilterindex-height (bfi)
  "Height of the highest indexed block, or -1 if empty."
  (nth-value 0 (blockfilterindex-best bfi)))

;;; --- writes ---

(defun %spent-utxos->scripts (spent-utxos)
  "Extract the scriptPubKeys from an undo list of (txid index utxo-entry)."
  (mapcar (lambda (e) (utxo-entry-script-pubkey (third e))) spent-utxos))

(defun blockfilterindex-add-block (bfi block block-hash height spent-utxos)
  "Build BLOCK's basic filter from its outputs and SPENT-UTXOS (the undo list of
(txid index utxo-entry)) and store it, chaining the filter header off the
parent's. Marks BLOCK as the best-indexed block. Returns the encoded filter, or
NIL if the index is disabled, or (values nil :noncontiguous) when BLOCK's
parent has no stored filter header while the index is non-empty: storing it
would seed a second header chain on top of a gap (observed after a mid-backfill
crash left a hole and the connect hook then re-seeded at the tip, stranding the
hole behind an advanced best marker). Refusing leaves the best marker where the
indexed range really ends, so the startup backfill can heal the gap."
  (unless (and (blockfilterindex-enabled bfi) (blockfilterindex-db bfi))
    (return-from blockfilterindex-add-block nil))
  (let* ((db (blockfilterindex-db bfi))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block
                     (bitcoin-lisp.serialization:bitcoin-block-header block)))
         ;; Chain the filter header off the parent's. Blocks are indexed in
         ;; order (connect hook + contiguous backfill), so the parent is present
         ;; for every block except the first one of the indexed range, which
         ;; seeds from the all-zero header. That first block is genesis on a
         ;; from-genesis full node -- but our genesis block body is not stored,
         ;; so genesis itself cannot be indexed and the range starts at the first
         ;; connected/backfilled block. The FILTERS are always Core-exact; the
         ;; header chain is internally consistent but its absolute values match
         ;; BIP157 only when the range starts at genesis (not currently possible).
         (prev-header (blockfilterindex-get-header bfi prev-hash)))
    (when (and (null prev-header) (>= (blockfilterindex-height bfi) 0))
      (return-from blockfilterindex-add-block (values nil :noncontiguous)))
    (let* ((scripts (%spent-utxos->scripts spent-utxos))
           (filter (build-basic-block-filter block block-hash scripts))
           (header (compute-block-filter-header
                    filter (or prev-header +zero-filter-header+))))
      (leveldb-put db (%bfi-filter-key block-hash) (%bfi-encode-record header filter))
      (leveldb-put db *bfi-meta-key* (%bfi-encode-meta height block-hash))
      filter)))

;;; --- backfill over already-stored blocks ---

(defun %block-spends-p (block)
  "T if BLOCK has any non-coinbase transaction (i.e. spends prior outputs), so
that a correct basic filter needs its undo data."
  (> (length (bitcoin-lisp.serialization:bitcoin-block-transactions block)) 1))

(defun blockfilterindex-set-best (bfi height hash)
  "Force the recorded best-indexed block to HEIGHT/HASH (used to repair the meta
record after a rollback such as invalidateblock)."
  (when (blockfilterindex-db bfi)
    (leveldb-put (blockfilterindex-db bfi) *bfi-meta-key* (%bfi-encode-meta height hash))))

(defun blockfilterindex-clear-best (bfi)
  "Delete the best-indexed metadata (forces a full backfill from height 0)."
  (when (blockfilterindex-db bfi)
    (leveldb-delete (blockfilterindex-db bfi) *bfi-meta-key*)))

(defun build-blockfilterindex (bfi chain-state block-store get-undo-fn
                               &key progress-callback)
  "Backfill the filter index from just past the last indexed block up to the
active tip, using stored blocks and their undo data. GET-UNDO-FN maps a
block-hash to its undo list of (txid index utxo-entry), or NIL when absent.
While the index is still empty, heights whose block body or (for a spending
block) undo data is unavailable are SKIPPED -- the genesis body is never
stored, and on a pruned node the whole pruned prefix is absent -- so the
indexed range seeds at the first indexable block. Once anything is indexed,
the first such unavailable height STOPS the backfill instead, keeping the
stored filter-header chain contiguous (a skipped block would leave the next
block chained off a wrong parent header). PROGRESS-CALLBACK, if given, is
called with (height percent). Returns the number of blocks indexed."
  (unless (and (blockfilterindex-enabled bfi) (blockfilterindex-db bfi))
    (return-from build-blockfilterindex 0))
  (let* ((tip (current-height chain-state))
         (start (max 0 (1+ (blockfilterindex-height bfi))))
         (seeded (>= (blockfilterindex-height bfi) 0))
         (count 0)
         (last-report (get-internal-real-time)))
    (block done
      (loop for height from start to tip
            do (let* ((entry (get-block-at-height chain-state height))
                      (hash (and entry (block-index-entry-hash entry)))
                      (block (and hash (get-block block-store hash)))
                      (undo (and block (funcall get-undo-fn hash)))
                      ;; FILTER is nil when the height is unindexable (missing
                      ;; body, or missing undo for a spending block) or when
                      ;; add-block refused a non-contiguous store (a stale best
                      ;; marker naming an orphaned block). Either way: skip
                      ;; pre-seed, stop post-seed.
                      (filter (and block
                                   (or undo (not (%block-spends-p block)))
                                   (blockfilterindex-add-block
                                    bfi block hash height undo))))
                 (cond (filter
                        (setf seeded t)
                        (incf count))
                       (seeded (return-from done))))
               (when progress-callback
                 (let ((now (get-internal-real-time)))
                   (when (> (- now last-report) internal-time-units-per-second)
                     (funcall progress-callback height
                              (if (zerop tip) 100.0 (* 100.0 (/ height tip))))
                     (setf last-report now))))))
    (when progress-callback (funcall progress-callback tip 100.0))
    count))
