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
  (fresh-count 0 :type fixnum)
  ;; Estimated in-memory byte usage of the cached entries — Bitcoin Core's
  ;; CCoinsViewCache::cachedCoinsUsage. Maintained incrementally at every entry
  ;; mutation and reset on flush; drives the node's size-based flush so the cache
  ;; stays bounded (Core dbcache). See cache-entry-mem-bytes.
  (mem-bytes 0 :type fixnum)
  ;; The block this cached UTXO state corresponds to — Core's
  ;; CCoinsViewCache::hashBlock, moved by SetBestBlock inside ConnectBlock and
  ;; DisconnectBlock (validation.cpp:2651, :2242). Tracking it HERE rather than
  ;; reading the chain's tip at flush time is the whole point: during a reorg's
  ;; disconnect phase the chain tip still names the old tip while these coins
  ;; are being rewound, so a flush that asked the chain would stamp a hash the
  ;; coins no longer match. NIL until the first block-level mutation or a load
  ;; from disk.
  (best-block nil :type (or null (simple-array (unsigned-byte 8) (32)))))

(defconstant +coins-cache-entry-overhead-bytes+ 200
  "Fixed per-entry memory estimate for a cached coin (SBCL hash bucket +
cache-entry + utxo-key + utxo-entry struct + byte-vector header), excluding the
scriptPubKey bytes. Deliberately a round, slightly-high estimate so the size
bound errs toward flushing early rather than under-counting toward OOM.")

(declaim (inline entry-script-bytes cache-entry-mem-bytes))

(defun entry-script-bytes (entry)
  "Variable byte usage of a utxo-entry — its scriptPubKey length (Bitcoin Core
Coin::DynamicMemoryUsage = DynamicUsage(scriptPubKey)). NIL (spent) is 0."
  (if entry (length (utxo-entry-script-pubkey entry)) 0))

(defun cache-entry-mem-bytes (ce)
  "Estimated bytes a cache-entry occupies: fixed overhead + scriptPubKey length
(0 script for a spent tombstone, which still holds the slot overhead)."
  (+ +coins-cache-entry-overhead-bytes+ (entry-script-bytes (ce-entry ce))))

(declaim (inline coins-view-cache-base))
(defun coins-view-cache-base (cache)
  "Return the underlying coins-view-db backing CACHE. Callers that own
the cache's lifecycle (e.g. the node) use this to close the LevelDB
on shutdown."
  (cvc-base cache))

(defun coins-view-cache-load-best-block (cache)
  "Adopt the base DB's recorded best block as this cache's starting pointer.

Call once after opening. Without it a freshly-opened cache reports NIL until
the first block-level mutation, so a flush in between (a shutdown flush, say)
would leave the stored pointer untouched while the coins moved. Returns the
hash, or NIL for a database written before the pointer existed."
  (declare (type coins-view-cache cache))
  (let ((recorded (coins-view-db-best-block (cvc-base cache))))
    (when recorded
      (setf (cvc-best-block cache) (copy-seq recorded)))))

(defun coins-view-best-block (view)
  "The block VIEW's coins actually correspond to, or NIL when it does not track
one (a test-only utxo-set, or a database written before the pointer existed).

This is NOT the chain tip, and the difference is the point: partway through a
reorg's disconnect phase the tip still names the block being rewound away from
while the coins have already moved to its parent. Core reports coins-view state
against `coins_view->GetBestBlock()` for exactly that reason
(rpc/blockchain.cpp:1083) — and it matters beyond cosmetics, because
hash_serialized_3 IS the assumeutxo commitment: a hash of one set of coins
labelled with another block's hash commits to nothing."
  (etypecase view
    (utxo-set nil)
    (coins-view-cache (cvc-best-block view))))

(defun coins-view-cache-compact (cache)
  "Full-compact the LevelDB backing CACHE (leveldb-compact over the whole
keyspace) to reclaim tombstone space after a large deletion churn such as a
reindex-chainstate wipe. No-op if the base DB is already closed."
  (let ((db (cvdb-db (cvc-base cache))))
    (when db (leveldb-compact db))))

;;;; Internal: fetch a coin into the cache. Mirrors Core's FetchCoin
;;;; (coins.cpp:68): if the key isn't in the cache, try the base view;
;;;; on hit, populate; on miss, leave the cache untouched (no negative
;;;; cache entry — Core does the same).

(declaim (inline fetch-coin))
(defvar *coins-to-uncache* nil
  "When bound to a cons cell, FETCH-COIN pushes onto its CAR every key it pulls
in from the base view that was not already cached — Core's coins_to_uncache
(validation.cpp:851). WITH-COINS-TO-UNCACHE binds it; nothing else should.

A cons cell rather than a bare list so the callee can push without the binding
form having to be a place.")

(defmacro with-coins-to-uncache ((cache) &body body)
  "Run BODY recording every coin FETCH-COIN pulls in from the base, and drop
those coins again if BODY returns NIL as its first value.

This is Core's shape: PreChecks records coins_to_uncache, and any non-VALID
result uncaches them, `to prevent memory DoS in case we receive a large number
of invalid transactions that attempt to overrun the in-memory coins cache'
(validation.cpp:1787-1790).

Only coins the cache did not already hold are recorded, and
COINS-VIEW-CACHE-UNCACHE additionally refuses to drop a dirty entry, so nothing
this can touch is an unwritten change."
  (let ((box (gensym "BOX")) (c (gensym "CACHE")) (vals (gensym "VALS")))
    ;; MULTIPLE-VALUE-LIST, not MULTIPLE-VALUE-BIND with a &rest: that lambda
    ;; list has no &rest, so `(multiple-value-bind (ok &rest rest) ...)' binds
    ;; three ordinary variables -- one of them literally named &REST -- to the
    ;; first three values and DROPS the others. The wrapped
    ;; validate-transaction-for-mempool returns seven, so every caller
    ;; destructuring (valid error fee replaced sigops) silently got the wrong
    ;; ones. Preserving an arbitrary number of values is the whole contract of
    ;; a wrapper like this.
    `(let* ((,c ,cache)
            (,box (cons '() nil))
            (,vals (multiple-value-list
                    (let ((*coins-to-uncache* ,box)) ,@body))))
       (unless (first ,vals)
         (when (typep ,c 'coins-view-cache)
           (dolist (key (car ,box))
             (coins-view-cache-uncache ,c key))))
       (values-list ,vals))))

(defun fetch-coin (cache key)
  "Return the cache-entry for KEY, populating from base if needed.
Returns NIL only when both cache and base have nothing under KEY."
  (declare (type coins-view-cache cache) (type utxo-key key))
  (multiple-value-bind (existing present-p) (gethash key (cvc-entries cache))
    (when present-p (return-from fetch-coin existing)))
  (let ((from-base (coins-view-db-get (cvc-base cache) key)))
    (when from-base
      (let ((ce (make-cache-entry :entry from-base :dirty nil :fresh nil)))
        (setf (gethash key (cvc-entries cache)) ce)
        (incf (cvc-mem-bytes cache) (cache-entry-mem-bytes ce))
        ;; Record it as evictable: it entered the cache only to answer a read.
        (when *coins-to-uncache*
          (push key (car *coins-to-uncache*)))
        ce))))

(defun coins-view-cache-uncache (cache key)
  "Drop KEY from the cache if it is present and NOT dirty — Core
CCoinsViewCache::Uncache (coins.cpp:310-322). Returns T if an entry was
dropped.

The not-dirty guard is load bearing: a dirty entry is an unwritten change, and
erasing it loses a real add or a real spend. Only entries pulled in from the
base purely to answer a read are eligible.

Exists so a rejected transaction does not leave its inputs resident. Core
records every prevout not already cached (coins_to_uncache, validation.cpp:851)
and uncaches them on any non-VALID result, with the reason stated verbatim:
`to prevent memory DoS in case we receive a large number of invalid
transactions that attempt to overrun the in-memory coins cache\' (:1787-1790).

We had no uncache at all, and our only size check lives in
maybe-periodic-flush, reachable solely from connect-block — so a peer streaming
transactions that fail AFTER input fetch (a bad signature is enough) made us
retain one entry per distinct prevout with no eviction until the next block. A
~1 MB transaction can name ~24,000 outpoints, so the amplification is several
times the bandwidth and is held for a whole inter-block interval."
  (declare (type coins-view-cache cache) (type utxo-key key))
  (multiple-value-bind (ce present-p) (gethash key (cvc-entries cache))
    (when (and present-p ce (not (ce-dirty ce)))
      (decf (cvc-mem-bytes cache) (cache-entry-mem-bytes ce))
      (when (ce-fresh ce) (decf (cvc-fresh-count cache)))
      (remhash key (cvc-entries cache))
      t)))

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
      (internal-error "coins-view-cache-add: refusing to overwrite unspent coin"))
    (cond
      ;; Reuse the existing struct: mutate slots, fix the counts to
      ;; reflect the transition. Avoids an alloc on the hot path.
      (existing
       (when (ce-dirty existing) (decf (cvc-dirty-count cache)))
       (when (ce-fresh existing) (decf (cvc-fresh-count cache)))
       ;; Overhead unchanged (same slot); adjust by the scriptPubKey delta.
       (incf (cvc-mem-bytes cache)
             (- (entry-script-bytes entry) (entry-script-bytes (ce-entry existing))))
       ;; FRESH is computed ONLY when overwriting is not permitted. Core
       ;; initialises fresh=false and enters the computation inside
       ;; `if (!possible_overwrite)` (coins.cpp:95-110); we computed it either
       ;; way, and BOTH live callers take the overwrite path
       ;; (:allow-overwrite is-coinbase, and :allow-overwrite t for every
       ;; restored input on disconnect).
       ;;
       ;; Core's comment names the exact hazard: a coin marked FRESH and then
       ;; spent before the flush is DROPPED from the cache, so its spentness
       ;; never reaches the parent — and a real base row survives as unspent.
       ;; Silent UTXO corruption, on the reorg path.
       (let ((fresh (and (not allow-overwrite)
                         (not (ce-entry existing))      ; was spent
                         (not (ce-dirty existing)))))   ; and already-flushed
         (setf (ce-entry existing) entry
               (ce-dirty existing) t
               (ce-fresh existing) fresh)
         (incf (cvc-dirty-count cache))
         (when fresh (incf (cvc-fresh-count cache)))
         existing))
      ;; Brand-new slot: the add can drop on spend without touching disk, so
      ;; FRESH — but only when the caller did NOT permit an overwrite. With
      ;; ALLOW-OVERWRITE the base may hold this key after all, and Core keeps
      ;; fresh=false for the same reason (coins.cpp:94-110).
      (t
       (let* ((fresh (not allow-overwrite))
              (ce (make-cache-entry :entry entry :dirty t :fresh fresh)))
         (setf (gethash key (cvc-entries cache)) ce)
         (incf (cvc-mem-bytes cache) (cache-entry-mem-bytes ce))
         (incf (cvc-dirty-count cache))
         (when fresh (incf (cvc-fresh-count cache)))
         ce)))))

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
       ;; Entry removed entirely: reclaim overhead + script bytes.
       (decf (cvc-mem-bytes cache) (cache-entry-mem-bytes ce))
       (remhash key (cvc-entries cache))
       (when (ce-dirty ce) (decf (cvc-dirty-count cache)))
       (decf (cvc-fresh-count cache)))
      (t
       ;; Tombstone keeps the slot overhead; only the scriptPubKey is freed.
       (decf (cvc-mem-bytes cache) (entry-script-bytes (ce-entry ce)))
       (unless (ce-dirty ce) (incf (cvc-dirty-count cache)))
       (setf (ce-entry ce) nil
             (ce-dirty ce) t)))
    t))

;;;; Flush: walk dirty entries, write to base via a single writebatch.
;;;; Mirrors CCoinsViewCache::BatchWrite + Flush (coins.cpp:208-289).

(defun coins-view-cache-wipe (cache)
  "Empty the entire UTXO set: drop the in-memory cache (discarding any dirty
entries -- the caller is rebuilding from scratch), forget the block the coins
corresponded to, and erase the coins AND the best-block pointer from the base
LevelDB. Used only by chainstate reindex. Returns the base count erased.

Clearing the cache's own pointer is half of the same invariant the base wipe
carries (see COINS-VIEW-DB-ERASE-ALL-COINS): an empty UTXO set names no block,
so a flush that happens before the rebuild has re-applied anything cannot
re-stamp the pre-wipe tip over the empty database."
  (declare (type coins-view-cache cache))
  (clrhash (cvc-entries cache))
  (setf (cvc-dirty-count cache) 0
        (cvc-fresh-count cache) 0
        (cvc-mem-bytes cache) 0
        (cvc-best-block cache) nil)
  (coins-view-db-erase-all-coins (cvc-base cache)))

(defun coins-view-empty-p (view)
  "T iff VIEW currently holds no unspent coin at all.

Core asks this as `CoinsTip().GetBestBlock().IsNull()` (is_coinsview_empty,
node/chainstate.cpp:69-70) and skips LoadChainTip under it, so an empty coins
database leaves the chain at genesis instead of adopting a tip it has no coins
for. Ours asks the coins directly, because a database written by a build whose
reindex wipe kept the pointer can be empty and still name a block."
  (etypecase view
    (utxo-set (zerop (hash-table-count (utxo-set-entries view))))
    (coins-view-cache
     ;; A tombstone (entry NIL) is a coin the cache has SPENT, so it counts
     ;; toward emptiness rather than against it.
     (and (loop for ce being the hash-values of (cvc-entries view)
                never (ce-entry ce))
          (not (coins-view-db-any-coin-p (cvc-base view)))))))

(defvar *persist-block-index-hook* nil
  "Thunk that durably writes the block index, installed by the node; NIL for a
test fixture or an offline tool that has no index to write.

Core's FlushStateToDisk writes the block files and then the block-index
database BEFORE CoinsTip().Sync()/Flush() (validation.cpp:2780-2812), so the
coins database can never name a block the block index does not hold. Our
periodic flush has that order in %FLUSH-CHAINSTATE's Phase 1, but the coins
pointer is also written from paths that never reach it: every RPC that walks
the UTXO set syncs the cache first (gettxoutsetinfo, dumptxoutset,
scantxoutset, the assumeutxo hash check), and loadtxoutset stamps the snapshot
base and flushes. Hooking the ONE place the pointer is staged, rather than
those call sites, is what keeps the two from drifting apart again.

What it costs when the pointer outruns the index: the coins DB names a block
the header index cannot place, RECONCILE-COINS-DB-BEST-BLOCK returns
:unresolvable, and start-up refuses to run until the node is reindexed — so a
read-only RPC plus an ordinary unclean shutdown becomes a mandatory reindex.")

(defun %stage-dirty-coins (cache batch best-block)
  "Stage every dirty entry of CACHE into BATCH — a put for a coin, an erase for
a spent tombstone — plus BEST-BLOCK when the caller has one. Returns the number
of entries staged.

Core writes both Sync and Flush through the one CCoinsViewCache::BatchWrite
(coins.cpp:208); the two differ only in what they then do with the entries, so
this half is shared here as well and cannot drift between them."
  (declare (type coins-view-cache cache))
  (let ((count 0))
    (maphash (lambda (key ce)
               (when (ce-dirty ce)
                 (if (ce-entry ce)
                     (coins-view-batch-put batch key (ce-entry ce))
                     (coins-view-batch-erase batch key))
                 (incf count)))
             (cvc-entries cache))
    (when best-block
      ;; The block index reaches disk BEFORE the pointer that names one of its
      ;; entries — Core's WriteBlockIndexDB / CoinsTip().Sync() order. Inside
      ;; the periodic flush this is a second look at an index Phase 1 has just
      ;; written, which finds nothing changed and writes nothing.
      (when *persist-block-index-hook* (funcall *persist-block-index-hook*))
      (coins-view-batch-set-best-block batch best-block))
    count))

(defun coins-view-cache-sync (cache &key sync (best-block (cvc-best-block cache)))
  "Write dirty entries to the base view and KEEP them in the cache — Core's
CCoinsViewCache::Sync, as opposed to Flush which also drops the entries.

This exists because iterating the UTXO set from an RPC thread must not clear
the live table. COINS-VIEW-CACHE-FLUSH does MAPHASH and then CLRHASH; the
validation thread mutates that same table under the node lock, so entries
inserted while the RPC thread was inside the MAPHASH might never be visited and
the following CLRHASH then dropped them UNWRITTEN. A dropped tombstone leaves a
spent coin alive in LevelDB — we would accept a double-spend Core rejects — and
a dropped add loses a real UTXO. Keeping the entries removes that class: an
entry the MAPHASH misses is still in the table afterwards instead of being
discarded unwritten. Holding the node lock across the call — the contract
below — is what then makes the write walk and the flag-clearing walk after it
agree on which entries the batch committed.

It also stops a `gettxoutsetinfo' throwing away the warm cache mid-IBD, which
Flush did as a side effect of answering a read-only question.

CALLER CONTRACT: hold the node lock across this call AND the creation of the
iterator that follows it. Core takes cs_main across exactly that pair
(rpc/blockchain.cpp:1075-1084) — coins connected between the two would
otherwise be in neither the snapshot nor the write."
  (declare (type coins-view-cache cache))
  (let ((count 0))
    (with-coins-view-batch (batch (cvc-base cache) :sync sync)
      (setf count (%stage-dirty-coins cache batch best-block)))
    ;; The entries stay, but nothing about them may still say `unwritten'.
    ;; Core's CoinsViewCacheCursor::NextAndMaybeErase with will_erase = false
    ;; (coins.h:279-295) drops a SPENT entry from the map and calls SetClean()
    ;; on every other one — and SetClean is `m_flags = 0' (coins.h:173-181),
    ;; which clears FRESH as well as DIRTY.
    ;;
    ;; FRESH is the half that costs a consensus split when it survives. It
    ;; asserts `the base view does not have this coin' (coins.h:150-159), which
    ;; the batch above just made false, and COINS-VIEW-CACHE-SPEND drops a
    ;; FRESH entry outright instead of staging an erase. A coin left FRESH here
    ;; is therefore spent in the cache and still unspent in LevelDB: the next
    ;; read pulls it back from the base and a SECOND spend of the same outpoint
    ;; is accepted. A spent tombstone that survives is the milder half — its
    ;; erase is already committed, so it costs only memory — but Core drops it
    ;; and so do we, which is also what keeps FRESH honest for a later re-add.
    ;;
    ;; The tombstone keys are collected and removed afterwards: removing an
    ;; entry from inside MAPHASH is defined only for the entry being visited,
    ;; and the cost is one cons per tombstone on a path that is about to walk
    ;; the whole of LevelDB anyway.
    (let ((spent '()))
      (maphash (lambda (key ce)
                 (when (ce-dirty ce) (decf (cvc-dirty-count cache)))
                 (when (ce-fresh ce) (decf (cvc-fresh-count cache)))
                 (cond ((ce-entry ce)
                        (setf (ce-dirty ce) nil
                              (ce-fresh ce) nil))
                       (t
                        (decf (cvc-mem-bytes cache) (cache-entry-mem-bytes ce))
                        (push key spent))))
               (cvc-entries cache))
      (dolist (key spent)
        (remhash key (cvc-entries cache))))
    ;; Core's post-condition: Sync throws `Not all unspent flagged entries were
    ;; cleared' when a flagged entry survived BatchWrite (coins.cpp:291-300).
    ;; The walk above decrements the two counters entry by entry rather than
    ;; zeroing them, so a non-zero remainder means the counts the mutators
    ;; maintain have drifted from the flags actually in the table — the drift
    ;; whose FRESH half is the double-spend above.
    (unless (and (zerop (cvc-dirty-count cache)) (zerop (cvc-fresh-count cache)))
      (internal-error
       "coins-view-cache-sync: ~D dirty and ~D fresh entries unaccounted for after the sync"
       (cvc-dirty-count cache) (cvc-fresh-count cache)))
    count))

(defun coins-view-cache-flush (cache &key sync (best-block (cvc-best-block cache)))
  "Commit all dirty entries to the base view in a single atomic batch
then clear the cache. SYNC=T forces fsync. Returns the number of
entries written (puts + erases).

BEST-BLOCK is the block hash this UTXO state corresponds to and is staged in
the SAME batch as the coin changes, so the two commit or fail together (Core's
CCoinsViewDB::BatchWrite, txdb.cpp:100-159). It defaults to the cache's OWN
pointer, which block application and disconnection maintain — deliberately not
to the chain's current tip, which disagrees with these coins for the whole of a
reorg's disconnect phase and would stamp a hash the coins no longer match. A
cache that has seen no block-level mutation has NIL and the stored pointer is
left untouched rather than invented."
  (declare (type coins-view-cache cache))
  (let ((count 0))
    (with-coins-view-batch (batch (cvc-base cache) :sync sync)
      (setf count (%stage-dirty-coins cache batch best-block)))
    ;; Core's cursor with will_erase = true leaves the entries alone precisely
    ;; because the caller wipes the whole map next (coins.h:260-268), so no
    ;; per-entry flag needs clearing here: nothing survives to carry one.
    (clrhash (cvc-entries cache))
    (setf (cvc-dirty-count cache) 0
          (cvc-fresh-count cache) 0
          (cvc-mem-bytes cache) 0)
    count))

;;;; coin-view-* convenience API
;;;;
;;;; The cache's native interface takes a pre-built utxo-key. Most
;;;; callers in validation/RPC have a (txid bytes, vout int) pair from
;;;; the wire format. These wrappers do the make-utxo-key construction
;;;; inline so the signatures mirror the legacy get-utxo / add-utxo /
;;;; remove-utxo functions on utxo-set. They keep call-site churn small
;;;; when the wire-in PR swaps utxo-set → coins-view-cache.

(declaim (inline coin-view-get coin-view-has-p))

(defun coin-view-get (cache txid vout)
  "Read the unspent utxo-entry for (TXID, VOUT), or NIL if absent."
  (declare (type coins-view-cache cache)
           (type (simple-array (unsigned-byte 8) (*)) txid)
           (type (unsigned-byte 32) vout))
  (coins-view-cache-get cache (make-utxo-key txid vout)))

(defun coin-view-has-p (cache txid vout)
  "Truthy iff (TXID, VOUT) currently maps to an unspent coin."
  (declare (type coins-view-cache cache)
           (type (simple-array (unsigned-byte 8) (*)) txid)
           (type (unsigned-byte 32) vout))
  (coins-view-cache-has-p cache (make-utxo-key txid vout)))

(defun coin-view-add (cache txid vout value script-pubkey height
                      &key coinbase allow-overwrite)
  "Add a UTXO. Mirrors add-utxo's signature on utxo-set."
  (declare (type coins-view-cache cache)
           (type (simple-array (unsigned-byte 8) (*)) txid script-pubkey)
           (type (unsigned-byte 32) vout))
  (let ((entry (make-utxo-entry :value value
                                :script-pubkey script-pubkey
                                :height height
                                :coinbase coinbase)))
    (coins-view-cache-add cache (make-utxo-key txid vout) entry
                          :allow-overwrite allow-overwrite)
    entry))

(defun coin-view-spend (cache txid vout)
  "Spend a UTXO. Returns the prior utxo-entry (for undo data) or NIL
if the coin was already spent / never existed. Mirrors remove-utxo's
contract on utxo-set."
  (declare (type coins-view-cache cache)
           (type (simple-array (unsigned-byte 8) (*)) txid)
           (type (unsigned-byte 32) vout))
  (let* ((key (make-utxo-key txid vout))
         (entry (coins-view-cache-get cache key)))
    (when entry
      (coins-view-cache-spend cache key)
      entry)))

;;;; BIP30: any-utxo-for-txid-p over (cache + base).
;;;;
;;;; The check fires when a new block contains a tx whose hash matches
;;;; a previous tx with at least one unspent output (forbidden post-
;;;; BIP30). We have to scan both the cache (for recently-touched
;;;; outputs, possibly tombstoned by an in-cache spend) and the base
;;;; (via a LevelDB iterator over keys with prefix 'C' + txid).
;;;;
;;;; A base hit only counts as "unspent" if the cache doesn't have a
;;;; tombstone (entry=NIL) for that exact key — otherwise the in-cache
;;;; spend supersedes the base.

(defun %txid-matches-key-p (key txid)
  "T if the 32 txid bytes at KEY[1..33] equal the 32 bytes of TXID."
  (declare (type (simple-array (unsigned-byte 8) (*)) key txid))
  (and (>= (length key) 33)
       (= (aref key 0) +db-prefix-coin+)
       (loop for i from 0 below 32
             always (= (aref key (1+ i)) (aref txid i)))))

(defun coin-view-any-utxo-for-txid-p (cache txid)
  "T if any UTXO for TXID is currently unspent in CACHE or its base.
Mirrors any-utxo-for-txid-p on utxo-set; used for the BIP30 duplicate-
txid check."
  (declare (type coins-view-cache cache)
           (type (simple-array (unsigned-byte 8) (*)) txid))
  ;; Cache scan: any in-cache unspent entry with matching txid wins.
  (let ((a (txid-bytes->u64-le txid 0))
        (b (txid-bytes->u64-le txid 8))
        (c (txid-bytes->u64-le txid 16))
        (d (txid-bytes->u64-le txid 24)))
    (maphash (lambda (key ce)
               (declare (type utxo-key key))
               (when (and (ce-entry ce)
                          (= (uk-a key) a) (= (uk-b key) b)
                          (= (uk-c key) c) (= (uk-d key) d))
                 (return-from coin-view-any-utxo-for-txid-p t)))
             (cvc-entries cache)))
  ;; Base scan via iterator, skipping keys tombstoned in cache.
  (let ((prefix (make-array 33 :element-type '(unsigned-byte 8))))
    (setf (aref prefix 0) +db-prefix-coin+)
    (replace prefix txid :start1 1)
    (with-leveldb-iterator (iter (cvdb-db (cvc-base cache)))
      (leveldb-iter-seek iter prefix)
      (loop
        (unless (leveldb-iter-valid-p iter) (return))
        (let ((k (leveldb-iter-key iter)))
          (unless (%txid-matches-key-p k txid) (return))
          (let* ((vout (logior (aref k 33)
                               (ash (aref k 34) 8)
                               (ash (aref k 35) 16)
                               (ash (aref k 36) 24)))
                 (uk (make-utxo-key txid vout))
                 (ce (gethash uk (cvc-entries cache))))
            ;; Base says this output exists. The cache supersedes iff
            ;; it has a tombstone (entry=NIL); otherwise it's unspent.
            (unless (and ce (null (ce-entry ce)))
              (return-from coin-view-any-utxo-for-txid-p t)))
          (leveldb-iter-next iter)))))
  nil)

;;;; Block apply / disconnect over the coin view.
;;;;
;;;; These mirror apply-block-to-utxo-set / disconnect-block-from-utxo-set
;;;; on utxo-set, but operate on a coins-view-cache and return undo
;;;; data in the same (txid index entry) shape so the rest of the
;;;; validator (which records / replays undo lists) doesn't have to
;;;; change when the wire-in PR swaps storage backends.

(defun log-missing-block-spend (height txid index)
  "Report an input of a connecting block that spent nothing. Core asserts this
cannot happen (UpdateCoins, validation.cpp:2004): every input of a validated
block spends a coin the view still holds. Reaching it means the block was
validated against a stale or double-spent view, and the undo data is now short
an entry — disconnecting the block would leave the UTXO set wrong."
  (bl.log:log-error
   "COIN-SPEND-MISSING: block-apply at height ~D found no coin for ~A:~D"
   height (bl.crypto:bytes-to-hex txid) index))

(defun coin-view-apply-block (cache block height)
  "Spend a block's inputs and add its outputs in CACHE. Returns the
undo list — (txid index entry) for every spent UTXO, in apply order."
  (declare (type coins-view-cache cache))
  (let ((spent '()))
    (loop for tx in (bl.ser:bitcoin-block-transactions block)
          for tx-index from 0
          for is-coinbase = (zerop tx-index)
          do (let ((txid (bl.ser:transaction-hash tx)))
               (unless is-coinbase
                 (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
                   (let* ((prevout (bl.ser:tx-in-previous-output input))
                          (prev-txid (bl.ser:outpoint-hash prevout))
                          (prev-index (bl.ser:outpoint-index prevout))
                          (entry (coin-view-spend cache prev-txid prev-index)))
                     (if entry
                         (push (list prev-txid prev-index entry) spent)
                         (log-missing-block-spend height prev-txid prev-index)))))
               (loop for output across (bl.ser:transaction-outputs tx)
                     for out-idx from 0
                     for spk = (bl.ser:tx-out-script-pubkey output)
                     ;; Drop provably-unspendable outputs (Core AddCoin returns
                     ;; early on IsUnspendable). They can never be spent, so
                     ;; keeping them only bloats the UTXO set and diverges our
                     ;; gettxoutsetinfo hashes from Core.
                     unless (script-unspendable-p spk)
                     do (coin-view-add cache txid out-idx
                                       (bl.ser:tx-out-value output)
                                       spk
                                       height
                                       :coinbase is-coinbase
                                       ;; Coinbase tx outputs at a pre-BIP30 height
                                       ;; can clobber an earlier coinbase with the
                                       ;; same hash; the caller is responsible for
                                       ;; passing the right flag via this path.
                                       :allow-overwrite is-coinbase))))
    (nreverse spent)))

(defun coin-view-disconnect-block (cache block previous-utxos &key height)
  "Reverse coin-view-apply-block for reorg.

Order matters when a block contains intra-block dependencies — tx N
spends an output O created by tx M (M < N) in the same block. After
apply, M's output O was created then immediately spent within the
block; the cache has M:0 in a spent/removed state.

Bitcoin Core's DisconnectBlock (refs/bitcoin/src/validation.cpp ~1640)
processes transactions in REVERSE order, doing (remove outputs THEN
restore inputs) per-tx. That guarantees M's output is removed AFTER
N's undo data restores it — net cache state is correctly empty for
M:0.

Our undo data is a flat list (not per-tx), so we achieve the same
end-state with a simpler equivalent: restore ALL inputs first, then
walk transactions forward to remove their outputs. The restoration
re-adds M:0 to the cache; the forward walk then removes M:0 along
with N:0. Net result is the same as Bitcoin Core's reverse iteration.

Returns T when the disconnect was CLEAN, NIL when it was not: Core's
DISCONNECT_OK vs DISCONNECT_UNCLEAN. Unclean means the UTXO set did not look
the way this block says it should — an output that was already gone, one whose
value/script/height/coinbase disagreed with the block, or an input restore that
overwrote a coin already present. Each is logged. Core carries the same
distinction and does not abort on it, because a reorg over a slightly-off view
still produces the right end state; what it must not do is stay SILENT, which
is what ours did.

HEIGHT, when supplied, enables Core's height comparison on each removed output.

The old forward order (remove outputs first, then restore inputs)
silently failed for intra-block deps: M:0's removal was a no-op
(already gone via N's spend), then M:0 got restored via N's undo data,
and stayed in the cache as falsely unspent. Subsequent re-apply (e.g.
the same tx in a competing fork's block) would then trip the
\"refusing to overwrite unspent coin\" guard. Observed live on
test-bitcoin-server 2026-05-19 at h=135597."
  (declare (type coins-view-cache cache))
  (let ((clean t))
    (flet ((unclean (format &rest args)
             (setf clean nil)
             (bl.log:log-warn "DisconnectBlock: ~?" format args)))
      ;; Restore inputs first (from undo data).
      (dolist (prev previous-utxos)
        (destructuring-bind (txid index entry) prev
          (let* ((key (make-utxo-key txid index))
                 ;; Core checks HaveCoin BEFORE restoring and passes
                 ;; possible_overwrite = !fClean — permissive about the
                 ;; operation, loud about the observation (ApplyTxInUndo,
                 ;; validation.cpp:2146-2170). We passed :allow-overwrite T
                 ;; unconditionally, which turned the guard off entirely and
                 ;; made "overwriting transaction output" invisible.
                 (present (coins-view-cache-get cache key)))
            (when present
              (unclean "overwriting transaction output ~A:~D"
                       (bl.crypto:bytes-to-hex txid) index))
            (coins-view-cache-add cache key entry :allow-overwrite (and present t)))))
      ;; Then walk transactions forward, removing their outputs.
      (loop for tx in (bl.ser:bitcoin-block-transactions block)
            for tx-index from 0
            for is-coinbase = (zerop tx-index)
            do (let ((txid (bl.ser:transaction-hash tx)))
                 (loop for output across (bl.ser:transaction-outputs tx)
                       for out-idx from 0
                       for spk = (bl.ser:tx-out-script-pubkey output)
                       ;; Unspendable outputs were never added, so their
                       ;; absence is expected rather than a mismatch (Core
                       ;; skips them here too, validation.cpp:2209).
                       unless (script-unspendable-p spk)
                         do (let ((spent (coin-view-spend cache txid out-idx)))
                              ;; Core requires the coin to be there AND to
                              ;; match the block's output exactly — value,
                              ;; script, height and coinbase flag — and calls
                              ;; any difference "transaction output mismatch"
                              ;; (validation.cpp:2213-2219). We removed the
                              ;; output through a function that returns NIL
                              ;; silently, so a disconnect over a UTXO set that
                              ;; did not match the block reported nothing and
                              ;; corrupted quietly.
                              (cond
                                ((null spent)
                                 (unclean "output ~A:~D was already absent"
                                          (bl.crypto:bytes-to-hex txid)
                                          out-idx))
                                ((not (and (= (utxo-entry-value spent)
                                              (bl.ser:tx-out-value output))
                                           (equalp (utxo-entry-script-pubkey spent) spk)
                                           (eq (and (utxo-entry-coinbase spent) t)
                                               is-coinbase)
                                           (or (null height)
                                               (= (utxo-entry-height spent) height))))
                                 (unclean "transaction output mismatch at ~A:~D"
                                          (bl.crypto:bytes-to-hex txid)
                                          out-idx))))))))
    clean))

;;;; Polymorphic dispatch for the legacy UTXO API.
;;;;
;;;; The legacy add-utxo / get-utxo / remove-utxo / etc. functions in
;;;; utxo.lisp took a utxo-set. Production now uses a coins-view-cache
;;;; backed by LevelDB; lots of tests still construct utxo-set directly.
;;;; Rather than fork into utxo-set-* and coin-view-* parallel call
;;;; trees, we redefine the legacy names to dispatch on view type via
;;;; etypecase. Tag check compiles to a single CMP on SBCL — negligible
;;;; vs. the hash-table or LevelDB lookup that follows.
;;;;
;;;; Redefining functions defined in utxo.lisp produces a STYLE-WARNING
;;;; at compile time. That's intentional; the new definitions are
;;;; strictly more general (handle utxo-set as before, plus
;;;; coins-view-cache).

(declaim (inline get-utxo utxo-exists-p))

(defun get-utxo (view txid output-index)
  "Polymorphic UTXO read. Returns the utxo-entry or NIL."
  (etypecase view
    (utxo-set
     (gethash (make-utxo-key txid output-index) (utxo-set-entries view)))
    (coins-view-cache
     (coin-view-get view txid output-index))))

(defun utxo-exists-p (view txid output-index)
  (etypecase view
    (utxo-set
     (and (gethash (make-utxo-key txid output-index)
                         (utxo-set-entries view)) t))
    (coins-view-cache
     (and (coin-view-has-p view txid output-index) t))))

(defun add-utxo (view txid output-index value script-pubkey height
                 &key coinbase)
  "Polymorphic UTXO add. For coins-view-cache, passes :allow-overwrite=T
to match legacy utxo-set semantics (which silently clobbers); strict
overwrite checking lives only on the direct coins-view-cache-add path."
  (etypecase view
    (utxo-set
     (let ((key (make-utxo-key txid output-index))
           (entry (make-utxo-entry :value value
                                   :script-pubkey script-pubkey
                                   :height height
                                   :coinbase coinbase)))
       (setf (gethash key (utxo-set-entries view)) entry)
       (setf (utxo-set-dirty view) t)
       entry))
    (coins-view-cache
     (coin-view-add view txid output-index value script-pubkey height
                    :coinbase coinbase :allow-overwrite t))))

(defun remove-utxo (view txid output-index)
  "Polymorphic UTXO removal. Returns the prior entry or NIL."
  (etypecase view
    (utxo-set
     (let ((key (make-utxo-key txid output-index)))
       (prog1
           (gethash key (utxo-set-entries view))
         (remhash key (utxo-set-entries view))
         (setf (utxo-set-dirty view) t))))
    (coins-view-cache
     (coin-view-spend view txid output-index))))

(defun any-utxo-for-txid-p (view txid)
  "Polymorphic BIP30 scan: T if any unspent UTXO exists for TXID."
  (declare (type (simple-array (unsigned-byte 8) (*)) txid))
  (etypecase view
    (utxo-set
     (let ((a (txid-bytes->u64-le txid 0))
           (b (txid-bytes->u64-le txid 8))
           (c (txid-bytes->u64-le txid 16))
           (d (txid-bytes->u64-le txid 24)))
       (declare (type (unsigned-byte 64) a b c d))
       (maphash (lambda (key entry)
                  (declare (ignore entry) (type utxo-key key))
                  (when (and (= (uk-a key) a) (= (uk-b key) b)
                             (= (uk-c key) c) (= (uk-d key) d))
                    (return-from any-utxo-for-txid-p t)))
                (utxo-set-entries view)))
     nil)
    (coins-view-cache
     (coin-view-any-utxo-for-txid-p view txid))))

(defun apply-block-to-utxo-set (view block height)
  "Polymorphic block-apply: spends inputs, adds outputs. Returns undo
data — (txid index entry) for each spent UTXO, in apply order."
  (etypecase view
    (utxo-set
     ;; Inlined from the legacy utxo-set body. Kept here so the
     ;; redefinition in this file fully shadows the utxo.lisp version.
     (let ((spent '()))
       (loop for tx in (bl.ser:bitcoin-block-transactions block)
             for tx-index from 0
             for is-coinbase = (zerop tx-index)
             do (let ((txid (bl.ser:transaction-hash tx)))
                  (unless is-coinbase
                    (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
                      (let* ((prevout (bl.ser:tx-in-previous-output input))
                             (prev-txid (bl.ser:outpoint-hash prevout))
                             (prev-index (bl.ser:outpoint-index prevout))
                             (key (make-utxo-key prev-txid prev-index))
                             (entry (gethash key (utxo-set-entries view))))
                        (if entry
                            (push (list prev-txid prev-index entry) spent)
                            (log-missing-block-spend height prev-txid prev-index))
                        (remhash key (utxo-set-entries view))
                        (setf (utxo-set-dirty view) t))))
                  (loop for output across (bl.ser:transaction-outputs tx)
                        for out-idx from 0
                        for spk = (bl.ser:tx-out-script-pubkey output)
                        ;; Drop provably-unspendable outputs (see the
                        ;; coins-view-cache branch above / Core AddCoin).
                        unless (script-unspendable-p spk)
                        do (let ((key (make-utxo-key txid out-idx))
                                 (entry (make-utxo-entry
                                         :value (bl.ser:tx-out-value output)
                                         :script-pubkey spk
                                         :height height
                                         :coinbase is-coinbase)))
                             (setf (gethash key (utxo-set-entries view)) entry)
                             (setf (utxo-set-dirty view) t)))))
       (nreverse spent)))
    (coins-view-cache
     (multiple-value-prog1
         (coin-view-apply-block view block height)
       ;; These coins now correspond to THIS block — Core's ConnectBlock ends
       ;; with SetBestBlock(pindex->GetBlockHash()) (validation.cpp:2651). The
       ;; header caches its hash, so this costs nothing on the hot path.
       (setf (cvc-best-block view)
             (copy-seq (bl.ser:block-header-hash
                        (bl.ser:bitcoin-block-header block))))))))

(defun utxo-count (view)
  "Polymorphic UTXO count. For utxo-set, exact. For coins-view-cache,
returns ONLY the in-memory entries — base count requires an O(N)
LevelDB scan and is left to future work. Callers that need an exact
count for a LevelDB-backed view must compute it themselves."
  (etypecase view
    (utxo-set (hash-table-count (utxo-set-entries view)))
    (coins-view-cache (hash-table-count (cvc-entries view)))))

(defun view-mem-bytes (view)
  "Estimated in-memory byte usage of VIEW's coin cache, mirroring Bitcoin Core's
CCoinsViewCache::DynamicMemoryUsage — drives the node's size-based flush. A
utxo-set (test-only, fully in memory) returns 0: it is not the bounded
production store, so the size trigger never fires for it."
  (etypecase view
    (utxo-set 0)
    (coins-view-cache (cvc-mem-bytes view))))

(defun disconnect-block-from-utxo-set (view block previous-utxos &key height)
  "Reverse BLOCK's effect on VIEW using PREVIOUS-UTXOS, its undo data.

Returns T when the disconnect was CLEAN and NIL when it was not -- Core's
DISCONNECT_OK vs DISCONNECT_UNCLEAN, the distinction COIN-VIEW-DISCONNECT-BLOCK
draws and logs. Only a plain UTXO-SET, which has no such observation to make,
always answers T. VerifyDB's level 3 is the caller that acts on the answer; the
reorg paths log it and carry on, as Core does."
  (etypecase view
    (utxo-set
     ;; Same intra-block-deps reasoning as coin-view-disconnect-block:
     ;; restore inputs FIRST, then remove outputs. Without this order
     ;; the in-block-spent-output gets restored after its remhash pass
     ;; runs as a no-op, leaving stale entries. The utxo-set hash table
     ;; doesn't fail on overwrite (no allow-overwrite check), so this
     ;; bug was silent here — but the cache surface caught it on
     ;; testnet4 at h=135597. Fix both for state consistency.
     (dolist (prev previous-utxos)
       (destructuring-bind (txid index entry) prev
         (setf (gethash (make-utxo-key txid index) (utxo-set-entries view))
               entry)))
     (dolist (tx (bl.ser:bitcoin-block-transactions block))
       (let ((txid (bl.ser:transaction-hash tx)))
         (loop for out-idx from 0
               below (length (bl.ser:transaction-outputs tx))
               do (remhash (make-utxo-key txid out-idx)
                           (utxo-set-entries view)))))
     t)
    (coins-view-cache
     (let ((clean (coin-view-disconnect-block view block previous-utxos
                                              :height height)))
       ;; These coins now correspond to the PARENT block — Core's
       ;; DisconnectBlock ends with SetBestBlock(pindex->pprev->GetBlockHash())
       ;; (validation.cpp:2242), and hashPrevBlock is that same hash. Moving the
       ;; pointer here, with the coins, is what keeps a flush honest partway
       ;; through a reorg's disconnect phase, when the chain's tip still names the
       ;; block we are rewinding away from.
       (setf (cvc-best-block view)
             (copy-seq (bl.ser:block-header-prev-block
                        (bl.ser:bitcoin-block-header block))))
       ;; ...and the pointer move must not become the answer: this used to be
       ;; the last form, so every disconnect reported CLEAN.
       clean))))

;;;; Polymorphic iteration + full-set statistics.
;;;;
;;;; For a utxo-set: walk the in-memory hash table sorted by on-disk
;;;; key bytes. For a coins-view-cache: flush dirty entries to the
;;;; base, then walk the LevelDB iterator in lex order. The
;;;; flush-then-walk approach mirrors Bitcoin Core's gettxoutsetinfo
;;;; (rpc/blockchain.cpp), which flushes pcoinsTip before scanning
;;;; pcoinsdbview.
;;;;
;;;; These functions are NOT on the validation hot path. They're for
;;;; RPC stats (rpc-gettxoutsetinfo) and bring-up verification.
;;;; Side-effect: on a coins-view-cache, iterate / total-amount /
;;;; distinct-txids / compute-utxo-set-hash all force a cache flush.

(defun %utxo-set-iterate (utxo-set callback)
  "In-memory iteration over a utxo-set."
  (let ((keys '()))
    (maphash (lambda (key entry)
               (declare (ignore entry))
               (push (cons (utxo-key-bytes key) key) keys))
             (utxo-set-entries utxo-set))
    (setf keys (sort keys #'key-bytes-less-than :key #'car))
    (dolist (pair keys)
      (let* ((key (cdr pair))
             (entry (gethash key (utxo-set-entries utxo-set))))
        (when entry
          (funcall callback (utxo-key-txid key) (uk-vout key) entry))))))

(defun %coin-view-iterate (cache callback)
  "Raw iteration over a coins-view-cache: flush, then walk base via
LevelDB iterator. The iterator emits keys in lex order, which for our
key encoding ('C' + txid + LE vout, all fixed-width) equals the
on-disk 36-byte key order — same raw order %utxo-set-iterate produces.
utxo-set-iterate layers Core's numeric-vout cursor order on top."
  ;; SYNC, not FLUSH: this runs from RPC threads (gettxoutsetinfo,
  ;; dumptxoutset) while the validation thread mutates the same entries table
  ;; under the node lock. Flush CLRHASHes it, so an entry inserted while we
  ;; were inside its MAPHASH could be dropped unwritten -- a lost tombstone
  ;; leaves a spent coin alive in LevelDB. Sync keeps the entries instead of
  ;; clearing the table, so nothing can be discarded unwritten.
  (coins-view-cache-sync cache)
  (with-leveldb-iterator (iter (cvdb-db (cvc-base cache)))
    ;; SEEK to the coin prefix rather than seeking to the first key. The loop
    ;; below stops at the first non-'C' key, which is only a correct scan if
    ;; every other prefix sorts AFTER 'C' — an assumption this code used to
    ;; state and that the best-block key ('B', matching Core's DB_BEST_BLOCK)
    ;; broke: it became the first key in the database, so the scan terminated
    ;; immediately and the whole UTXO set iterated as EMPTY. Seeking makes the
    ;; scan independent of where any metadata prefix sorts.
    (leveldb-iter-seek iter (make-array 1 :element-type '(unsigned-byte 8)
                                          :initial-element +db-prefix-coin+))
    (let ((txid-buf (make-array 32 :element-type '(unsigned-byte 8))))
      (loop
        (unless (leveldb-iter-valid-p iter) (return))
        (let ((k (leveldb-iter-key iter)))
          ;; Only 'C'-prefixed coin entries; bail on any future
          ;; metadata prefix that sorts after 'C' (e.g. 'M' marker).
          (unless (and (>= (length k) +coin-key-bytes+)
                       (= (aref k 0) +db-prefix-coin+))
            (return))
          (replace txid-buf k :start2 1 :end2 33)
          (let* ((vout (logior (aref k 33)
                               (ash (aref k 34) 8)
                               (ash (aref k 35) 16)
                               (ash (aref k 36) 24)))
                 (v (leveldb-iter-value iter))
                 (entry (decode-coin-value v)))
            (funcall callback (copy-seq txid-buf) vout entry)))
        (leveldb-iter-next iter)))))

(defun utxo-set-iterate (view callback)
  "Iterate over all UTXOs in Bitcoin Core's canonical UTXO cursor
order: coins grouped per txid in serialized-txid lex order, vouts
NUMERICALLY ascending within each txid — the order ComputeUTXOStats
consumes (kernel/coinstats.cpp:112-146, which buffers each txid's
outputs into a std::map<uint32_t, Coin>) and the assumeutxo snapshot
cursor order (node/utxo_snapshot.h). The raw key walk yields LE-u32
vout byte order, which diverges from numeric at vout >= 256
(256 = #x00 #x01 sorts before 1 = #x01 #x00), so each txid's coins
are buffered and sorted before delivery. CALLBACK is called with
(txid vout entry) for each UTXO.

For coins-view-cache, this forces a flush so the iteration sees a
single consistent snapshot (matches Core's CCoinsViewDB::Cursor usage
in gettxoutsetinfo)."
  (let ((group-txid nil)
        (group '()))                    ; (vout . entry) for group-txid
    (labels ((emit-group ()
               (when group
                 (dolist (pair (sort group #'< :key #'car))
                   (funcall callback group-txid (car pair) (cdr pair)))
                 (setf group '())))
             (collect (txid vout entry)
               (unless (and group-txid (equalp txid group-txid))
                 (emit-group)
                 (setf group-txid txid))
               (push (cons vout entry) group)))
      (etypecase view
        (utxo-set         (%utxo-set-iterate view #'collect))
        (coins-view-cache (%coin-view-iterate view #'collect)))
      (emit-group))))

(defun utxo-set-total-amount (view)
  "Sum of all utxo-entry-value across the set."
  (let ((total 0))
    (utxo-set-iterate view
                      (lambda (txid vout entry)
                        (declare (ignore txid vout))
                        (incf total (utxo-entry-value entry))))
    total))

(defun utxo-set-distinct-txids (view)
  "Count distinct transaction IDs with at least one unspent output.

Counts group transitions rather than collecting the txids. The set version
held every distinct txid in a hash table — tens of millions of 32-byte keys on
a real chain, on the same gettxoutsetinfo path whose set-hash buffering already
proved fatal (see COMPUTE-UTXO-SET-HASH). This is exact, not an estimate:
UTXO-SET-ITERATE delivers coins grouped per txid, because both backends walk
the 36-byte 'C'+txid+vout key in lex order, which places every vout of a txid
contiguously. Memory is now one txid."
  (let ((count 0)
        (previous nil))
    (utxo-set-iterate view
                      (lambda (txid vout entry)
                        (declare (ignore vout entry))
                        (unless (and previous (equalp txid previous))
                          (incf count)
                          ;; the iterator hands out a fresh copy per coin, but
                          ;; retain our own so this cannot depend on that
                          (setf previous (copy-seq txid)))))
    count))

(defun coin-muhash-element (txid vout height coinbase amount script)
  "Serialize one UTXO into the byte string MuHash hashes (Bitcoin Core
coinstats.cpp TxOutSer): outpoint (txid || vout LE32), then the packed
code (height << 1 | coinbase) as LE32, then the amount as LE64, then the
scriptPubKey with a compactsize length prefix. Used for gettxoutsetinfo
muhash mode and (per added/removed coin) the coinstats index. Built directly
into a byte vector -- this is per-UTXO on the coinstatsindex backfill, where
the flexi-streams gray-stream path was measurable overhead.

AMOUNT is the utxo-entry value, a (signed-byte 64) because Core's CAmount is
an int64_t that `ss << coin.out\' streams raw; the positional writers are
declared unsigned, so write its 64-bit pattern rather than the signed value."
  (declare (type (simple-array (unsigned-byte 8) (*)) txid script))
  (let* ((slen (length script))
         (out (make-array (+ 32 4 4 8 (bl.ser:compact-size-length slen) slen)
                          :element-type '(unsigned-byte 8)))
         (code (logior (ash height 1) (if coinbase 1 0)))
         (i 0))
    (declare (type fixnum i))
    (setf i (bl.bytes:buf-set-bytes out i txid))
    (setf i (bl.bytes:buf-set-u32-le out i vout))
    (setf i (bl.bytes:buf-set-u32-le out i code))
    (setf i (bl.bytes:buf-set-u64-le out i (ldb (byte 64 0) amount)))
    (setf i (bl.bytes:buf-set-varint out i slen))
    (bl.bytes:buf-set-bytes out i script)
    out))

(defun coin-muhash-element* (txid vout entry)
  "coin-muhash-element for a utxo-entry ENTRY."
  (coin-muhash-element txid vout
                       (utxo-entry-height entry)
                       (utxo-entry-coinbase entry)
                       (utxo-entry-value entry)
                       (utxo-entry-script-pubkey entry)))

(defun compute-utxo-set-muhash (view)
  "Compute the MuHash of the whole UTXO set (Core gettxoutsetinfo
hash_type=muhash). Returns the 32-byte finalized hash in internal byte order
(reverse for display). MuHash is order-independent, so the iteration order
does not affect the result."
  (let ((mu (bl.crypto:make-muhash)))
    (utxo-set-iterate
     view
     (lambda (txid vout entry)
       (bl.crypto:muhash-insert
        mu (coerce (coin-muhash-element* txid vout entry)
                   '(simple-array (unsigned-byte 8) (*))))))
    (bl.crypto:muhash-finalize mu)))

(defun compute-utxo-set-hash (view)
  "Compute the hash_serialized_3 UTXO set hash: a double-SHA256 over
per-coin preimages in Bitcoin Core's exact order and format
(kernel/coinstats.cpp:88-146 ApplyHash/ComputeUTXOStats). Each coin
contributes the same bytes TxOutSer feeds the MuHash path
(coinstats.cpp:47-52): outpoint (txid || vout LE32), packed code
(height << 1 | coinbase) as LE32, then the uncompressed CTxOut
(value LE64 + compactsize-prefixed scriptPubKey) — coin-muhash-element.

Ordering (txid-lex groups, numerically ascending vouts — Core's
std::map<uint32_t, Coin>, coinstats.cpp:118-141) is guaranteed by
utxo-set-iterate's cursor contract.

Returns the 32-byte digest in internal byte order (hash-to-hex reverses
for display, matching Core's uint256::GetHex).

Hashes INCREMENTALLY. Accumulating the whole set into one buffer and hashing
it at the end needs memory proportional to the UTXO set — measured at ~1.1 GB
on testnet4's 14.2M coins, which killed a live node outright: the buffer's
final doubling asked for 1,156,098,560 bytes with 632 MB left in a 6 GB heap,
and the fail-fast debugger hook turned the heap exhaustion into process exit.
Mainnet's set is an order of magnitude larger, so this could never have worked
there. Core streams it the same way (ApplyHash, coinstats.cpp:88-146). Memory
is now flat in the size of one coin's preimage."
  (let ((digest (ironclad:make-digest :sha256)))
    (utxo-set-iterate
     view
     (lambda (txid vout entry)
       (ironclad:update-digest digest (coin-muhash-element* txid vout entry))))
    ;; hash_serialized_3 is a DOUBLE SHA-256: finalize the streamed inner pass,
    ;; then hash that 32-byte digest again.
    (bl.crypto:sha256 (ironclad:produce-digest digest))))
