(in-package #:bitcoin-lisp.storage)

;;; Coins-view-cache: in-memory dirty-tracking layer on top of
;;; coins-view-db. Mirrors Bitcoin Core's CCoinsViewCache
;;; (refs/bitcoin/src/coins.cpp:60-220).
;;;
;;; Why this exists: hitting LevelDB on every UTXO read/write during
;;; block validation is too slow. CCoinsViewCache batches the dirties.
;;; Reads pull through from the base view and remain in cache. Writes
;;; (AddCoin / SpendCoin) only modify the cache. On flush, the dirty
;;; subset is committed to the base via a single CDBBatch — Core's
;;; design that turns a ~13s full-set rewrite into a sub-second delta.
;;;
;;; Per-entry flags (Core mirrors them via a sentinel-linked list; we
;;; just use slots since our scale is fine without the dirty-list trick):
;;;
;;;   :dirty  — entry was modified since last flush. Must be written to
;;;             base on flush. Set by add and spend.
;;;   :fresh  — entry was added to this cache and does not exist in the
;;;             base view. If spent before flush, drop from cache
;;;             entirely; never write to disk.
;;;
;;; Spent entries are represented as cache-entry with utxo-entry = NIL.
;;; This distinguishes "spent (delete from base on flush)" from "not in
;;; cache, must fetch from base next time."
;;;
;;; Caller contract: the cache assumes that for a brand-new add (no
;;; existing cache slot), the key does NOT exist in the base view.
;;; Mirrors Core's CCoinsViewCache::AddCoin which derives FRESH purely
;;; from cache state (coins.cpp:113). Block-validation order respects
;;; this: outputs are added at new (txid, vout) which is unique chain-
;;; wide (BIP30 violations go through the explicit :allow-overwrite
;;; path). If you need defensive base-aware behavior for some other
;;; caller, pass :allow-overwrite t.
;;;
;;; Memory: the cache is unbounded by design — Core uses dbcache to
;;; cap. For now, the caller is responsible for invoking
;;; coins-view-cache-flush periodically (e.g., every N blocks) to
;;; bound memory.

(defstruct (cache-entry (:conc-name ce-))
  (entry nil :type (or null utxo-entry))
  (dirty nil :type boolean)
  (fresh nil :type boolean))

(defstruct (coins-view-cache (:conc-name cvc-)
                             (:constructor make-coins-view-cache (base)))
  (entries (make-utxo-key-hash-table) :type hash-table :read-only t)
  (base nil :type coins-view-db :read-only t)
  (dirty-count 0 :type fixnum)
  (fresh-count 0 :type fixnum))

;;;; Internal: fetch a coin into the cache. Mirrors Core's FetchCoin
;;;; (coins.cpp:68): if the key isn't in the cache, try the base view;
;;;; on hit, populate; on miss, leave the cache untouched (no negative
;;;; cache entry — Core does the same).

(declaim (inline fetch-coin))
(defun fetch-coin (cache key)
  "Return the cache-entry for KEY, populating from base if needed.
Returns NIL only when both cache and base have nothing under KEY."
  (declare (type coins-view-cache cache) (type utxo-key key))
  (multiple-value-bind (existing present-p) (gethash key (cvc-entries cache))
    (when present-p (return-from fetch-coin existing)))
  (let ((from-base (coins-view-db-get (cvc-base cache) key)))
    (when from-base
      (setf (gethash key (cvc-entries cache))
            (make-cache-entry :entry from-base :dirty nil :fresh nil)))))

;;;; Public reads.

(defun coins-view-cache-get (cache key)
  "Return the unspent utxo-entry for KEY, or NIL if absent / spent.
Mirrors CCoinsViewCache::GetCoin (coins.cpp:83)."
  (declare (type coins-view-cache cache) (type utxo-key key))
  (let ((ce (fetch-coin cache key)))
    (when ce (ce-entry ce))))

(defun coins-view-cache-has-p (cache key)
  "Return generalized boolean: truthy iff KEY currently maps to an
unspent coin. Mirrors CCoinsViewCache::HaveCoin (coins.cpp:188)."
  (declare (type coins-view-cache cache) (type utxo-key key))
  (let ((ce (fetch-coin cache key)))
    (and ce (ce-entry ce))))

;;;; Public writes.

(defun coins-view-cache-add (cache key entry &key allow-overwrite)
  "Add ENTRY under KEY. Mirrors CCoinsViewCache::AddCoin (coins.cpp:89).

If KEY already exists as unspent and ALLOW-OVERWRITE is NIL, signals an
error — Core throws std::logic_error here (pre-BIP30 coinbase rewrites
go through the allow-overwrite path).

Marks DIRTY. Marks FRESH if neither the cache nor an unflushed-spent
state requires us to coordinate with the base on flush. FRESH is derived
purely from cache state; see the file header for the caller contract."
  (declare (type coins-view-cache cache)
           (type utxo-key key)
           (type utxo-entry entry))
  (let ((existing (gethash key (cvc-entries cache))))
    (when (and existing (ce-entry existing) (not allow-overwrite))
      (error "coins-view-cache-add: refusing to overwrite unspent coin"))
    (cond
      ;; Reuse the existing struct: mutate slots, fix the counts to
      ;; reflect the transition. Avoids an alloc on the hot path.
      (existing
       (when (ce-dirty existing) (decf (cvc-dirty-count cache)))
       (when (ce-fresh existing) (decf (cvc-fresh-count cache)))
       (let ((fresh (and (not (ce-entry existing))      ; was spent
                         (not (ce-dirty existing)))))   ; and already-flushed
         (setf (ce-entry existing) entry
               (ce-dirty existing) t
               (ce-fresh existing) fresh)
         (incf (cvc-dirty-count cache))
         (when fresh (incf (cvc-fresh-count cache)))
         existing))
      ;; Brand-new slot. Per caller contract, base does not have KEY,
      ;; so the add can drop on spend without touching disk → FRESH=T.
      (t
       (setf (gethash key (cvc-entries cache))
             (make-cache-entry :entry entry :dirty t :fresh t))
       (incf (cvc-dirty-count cache))
       (incf (cvc-fresh-count cache))))))

(defun coins-view-cache-spend (cache key)
  "Mark KEY as spent. Returns T if the coin was unspent before this
call; NIL otherwise (already spent or never existed).

If the entry was FRESH (created in this cache, never flushed), we
remove it entirely — its addition and spending net to nothing as far
as the base view is concerned. Otherwise we mark it spent + dirty so
flush will issue an erase on the base.

Mirrors CCoinsViewCache::SpendCoin (coins.cpp:153)."
  (declare (type coins-view-cache cache) (type utxo-key key))
  (let ((ce (fetch-coin cache key)))
    (unless (and ce (ce-entry ce))
      (return-from coins-view-cache-spend nil))
    (cond
      ((ce-fresh ce)
       (remhash key (cvc-entries cache))
       (when (ce-dirty ce) (decf (cvc-dirty-count cache)))
       (decf (cvc-fresh-count cache)))
      (t
       (unless (ce-dirty ce) (incf (cvc-dirty-count cache)))
       (setf (ce-entry ce) nil
             (ce-dirty ce) t)))
    t))

;;;; Flush: walk dirty entries, write to base via a single writebatch.
;;;; Mirrors CCoinsViewCache::BatchWrite + Flush (coins.cpp:208-289).

(defun coins-view-cache-flush (cache &key sync)
  "Commit all dirty entries to the base view in a single atomic batch
then clear the cache. SYNC=T forces fsync. Returns the number of
entries written (puts + erases)."
  (declare (type coins-view-cache cache))
  (let ((count 0))
    (with-coins-view-batch (batch (cvc-base cache) :sync sync)
      (maphash (lambda (key ce)
                 (when (ce-dirty ce)
                   (if (ce-entry ce)
                       (coins-view-batch-put batch key (ce-entry ce))
                       (coins-view-batch-erase batch key))
                   (incf count)))
               (cvc-entries cache)))
    (clrhash (cvc-entries cache))
    (setf (cvc-dirty-count cache) 0
          (cvc-fresh-count cache) 0)
    count))
