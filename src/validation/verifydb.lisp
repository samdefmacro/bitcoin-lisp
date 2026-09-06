(in-package #:bitcoin-lisp.validation)

;;;; VerifyDB: does the block database agree with the UTXO set?
;;;;
;;;; Core's CVerifyDB::VerifyDB (validation.cpp:4643-4775), run over every
;;;; non-empty chainstate on every boot by VerifyLoadedChainstate
;;;; (node/chainstate.cpp:240-276) and on demand by the verifychain RPC.
;;;; CORRUPTED_BLOCK_DB is a hard startup failure there ("Corrupted block
;;;; database detected"), which is what turns a chainstate that disagrees with
;;;; its blocks from "runs and reports success" into "refuses to start".
;;;;
;;;; The four levels are cumulative, tip-downward over the last N blocks:
;;;;
;;;;   0  the block reads back from the store
;;;;   1  + CheckBlock: PoW, merkle root / CVE-2012-2459, weight, size, the
;;;;      per-transaction context-free checks and the legacy sigop budget
;;;;   2  + its undo record reads back
;;;;   3  + it DISCONNECTS cleanly against a scratch coins view over the
;;;;      chainstate's own coins database -- the only level that compares the
;;;;      two databases against each other
;;;;   4  + the same blocks reconnect back up to the tip
;;;;
;;;; Level 3 is where GA11 bbf6e679's state is caught: the UTXO set is empty
;;;; while the tip, the block index and every blk/rev record stand, so every
;;;; output the tip block removes is already gone, the disconnect is UNCLEAN
;;;; and the answer is CORRUPTED-BLOCK-DB rather than "true".

(defconstant +default-checkblocks+ 6
  "How many blocks -checkblocks verifies at startup by default. Core's
DEFAULT_CHECKBLOCKS (validation.h:77); 0 or a value past the chain height
means the whole chain.")

(defconstant +default-checklevel+ 3
  "How thorough -checklevel is by default. Core's DEFAULT_CHECKLEVEL
(validation.h:78). Clamped to 0-4, as Core clamps it (validation.cpp:4659).")

(defun %hash-hex (hash)
  "HASH as an operator reads it: big-endian hex."
  (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash)))

(defun %verify-db-scratch-view (chain-state)
  "A scratch coins view over CHAIN-STATE's own coins database for the level-3
disconnect, or NIL when the chainstate has no database-backed view.

Core builds `CCoinsViewCache coins(&coinsview)` over the view the caller hands
in and never flushes it -- the disconnects live and die in memory. Ours is a
second COINS-VIEW-CACHE over the same LevelDB, so the same holds: nothing here
calls flush or sync on it. The chainstate's own cache is SYNCED first (not
flushed, so its entries survive) so the scratch view reads the coins the node
has actually accepted and not only the last flushed ones -- the same
sync-then-read-the-base pattern %COIN-VIEW-ITERATE uses for gettxoutsetinfo,
and the reason Core can pass CoinsTip() to the RPC and CoinsDB() at startup and
get one answer.

A plain in-memory UTXO-SET (test fixtures only; a live node always has the
cache) has no base to stand on and no clean/unclean answer to give, so levels
3 and 4 report SKIPPED-L3-CHECKS over one instead of guessing."
  (let ((view (bl.store:chain-state-coins-view chain-state)))
    (when (typep view 'bl.store:coins-view-cache)
      (bl.store:coins-view-cache-sync view)
      (let ((scratch (bl.store:make-coins-view-cache
                      (bl.store:coins-view-cache-base view))))
        (bl.store:coins-view-cache-load-best-block scratch)
        scratch))))

(defun %verify-db-block-spends-p (block)
  "T when BLOCK spends anything, i.e. it has a non-coinbase transaction with
inputs -- so it MUST have a readable undo record.

A block that spends nothing has an EMPTY undo record, and GET-UNDO-DATA
answers NIL for an empty record and for an unreadable one alike. Core tells
them apart because ReadBlockUndo returns a bool separate from the record's
contents; ours cannot, so levels 2 and 3 assert the undo record only where
its absence is unambiguous. Every block with a spend is covered; a corrupt
EMPTY record on a coinbase-only block is the gap, and its CRC is checked by
the reader either way."
  (loop for tx in (rest (bl.ser:bitcoin-block-transactions block))
        thereis (plusp (length (bl.ser:transaction-inputs tx)))))

(defun %verify-db-block-checks (entry block chain-state check-level)
  "Levels 1 and 2 over one block: NIL when they pass, :CORRUPTED-BLOCK-DB
when they do not.

Level 1 is Core's CheckBlock, which is context-free plus the proof of work
(its fCheckPOW argument) -- so %CHECK-BLOCK with SKIP-HEADER, which would
otherwise add the CONTEXTUAL header rules (difficulty bits, MTP, timewarp),
Core's ContextualCheckBlockHeader and no part of CheckBlock, plus the PoW
check supplied separately. Level 2 reads the undo record back when the index
entry claims one, exactly as Core gates it on !GetUndoPos().IsNull()
(validation.cpp:4703-4712)."
  (let ((height (bl.store:block-index-entry-height entry))
        (hash (bl.store:block-index-entry-hash entry)))
    (when (and (>= check-level 1)
               (not (and (check-proof-of-work (bl.ser:bitcoin-block-header block))
                         (values (%check-block block chain-state height
                                               (bl.ser:get-unix-time)
                                               :skip-header t)))))
      (bl:log-error "Verification error: found bad block at ~D, hash=~A"
                    height (%hash-hex hash))
      (return-from %verify-db-block-checks :corrupted-block-db))
    (when (and (>= check-level 2)
               (bl.store:block-index-entry-undo-pos entry)
               (%verify-db-block-spends-p block)
               (null (get-undo-data hash)))
      (bl:log-error "Verification error: found bad undo data at ~D, hash=~A"
                    height (%hash-hex hash))
      (return-from %verify-db-block-checks :corrupted-block-db))
    nil))

(defun %verify-db-disconnect (entry block scratch)
  "Level 3 over one block: disconnect it from SCRATCH. Returns :OK, :UNCLEAN
(Core's DISCONNECT_UNCLEAN -- the view did not look the way the block says it
should) or :FAILED (DISCONNECT_FAILED -- the undo record cannot cover the
block, or the view is not standing on this block at all)."
  (let* ((hash (bl.store:block-index-entry-hash entry))
         (height (bl.store:block-index-entry-height entry))
         (best (bl.store:coins-view-best-block scratch)))
    ;; Core asserts this (validation.cpp:4718). A hard abort is the wrong
    ;; answer for a diagnostic, and what it asserts is itself a coins/blocks
    ;; disagreement, so report it as one.
    (unless (and best (equalp best hash))
      (bl:log-error "Verification error: the UTXO set is at ~A, not at the block being disconnected (~A)"
                    (if best (%hash-hex best) "no recorded block") (%hash-hex hash))
      (return-from %verify-db-disconnect :failed))
    (let ((undo (get-undo-data hash)))
      (when (and (null undo) (%verify-db-block-spends-p block))
        (bl:log-error "Verification error: irrecoverable inconsistency in block data at ~D, hash=~A"
                      height (%hash-hex hash))
        (return-from %verify-db-disconnect :failed))
      (if (bl.store:disconnect-block-from-utxo-set
           scratch block (or undo '()) :height height)
          :ok
          :unclean))))

(defun %verify-db-reconnect (chain-state block-store scratch from-entry tip-entry)
  "Level 4: reconnect every block above FROM-ENTRY up to TIP-ENTRY into
SCRATCH (Core validation.cpp:4747-4769). Returns :SUCCESS, :INTERRUPTED or
:CORRUPTED-BLOCK-DB.

Core calls ConnectBlock here, the same full pass a live connect makes; ours is
VALIDATE-BLOCK against the scratch view with SKIP-HEADER, since the header was
checked at index admission and a re-read body carries no cached hash."
  (let ((up from-entry))
    (loop
      (let ((next (bl.store:get-block-at-height
                   chain-state (1+ (bl.store:block-index-entry-height up)))))
        (when (null next) (return :success))
        (setf up next))
      (let* ((hash (bl.store:block-index-entry-hash up))
             (height (bl.store:block-index-entry-height up))
             (block (bl.store:get-block block-store hash)))
        (unless block
          (bl:log-error "Verification error: reading block failed at ~D, hash=~A"
                        height (%hash-hex hash))
          (return :corrupted-block-db))
        (multiple-value-bind (valid error)
            (validate-block block chain-state scratch height
                            (bl.ser:get-unix-time) :skip-header t)
          (unless valid
            (bl:log-error "Verification error: found unconnectable block at ~D, hash=~A (~A)"
                          height (%hash-hex hash) error)
            (return :corrupted-block-db)))
        (bl.store:apply-block-to-utxo-set scratch block height)
        (when (bl:interrupt-requested-p) (return :interrupted))
        (when (equalp hash (bl.store:block-index-entry-hash tip-entry))
          (return :success))))))

(defun verify-db (chain-state block-store
                  &key (check-level +default-checklevel+)
                       (check-depth +default-checkblocks+)
                       coins-cache-bytes)
  "Verify the last CHECK-DEPTH blocks of CHAIN-STATE at CHECK-LEVEL.

Returns one of :SUCCESS, :SKIPPED-MISSING-BLOCKS (a pruned or snapshot
chainstate ran out of block data first), :SKIPPED-L3-CHECKS (the coins-cache
budget would not hold the disconnected coins, or the chainstate has no
database-backed view), :INTERRUPTED, or :CORRUPTED-BLOCK-DB. Core's
VerifyDBResult, with Core's meanings: the caller decides what a skip costs --
startup accepts it unless -checkblocks/-checklevel were given explicitly
(Core's require_full_verification), and the RPC answers true for :SUCCESS
alone.

COINS-CACHE-BYTES is the chainstate's coins-cache budget, Core's
m_coinstip_cache_size_bytes: past it the level-3 disconnects stop rather than
grow the scratch view without bound (validation.cpp:4716-4732). Storage and
validation never read the node's flush globals, so the budget arrives as an
argument the way PRUNE-OLD-BLOCKS's byte target does. NIL means no bound."
  (let* ((tip-entry (bl.store:get-block-index-entry
                     chain-state (bl.store:best-block-hash chain-state)))
         (chain-height (bl.store:current-height chain-state)))
    ;; An empty or genesis-only chain has nothing to verify (validation.cpp:4651).
    (when (or (null tip-entry)
              (null (bl.store:block-index-entry-prev-entry tip-entry)))
      (return-from verify-db :success))
    (when (or (<= check-depth 0) (> check-depth chain-height))
      (setf check-depth chain-height))
    (setf check-level (max 0 (min 4 check-level)))
    (bl:log-info "Verifying last ~D block~:P at level ~D" check-depth check-level)
    (let* ((snapshot-p (and (bl.store:chain-state-from-snapshot-blockhash chain-state) t))
           (scratch (when (>= check-level 3) (%verify-db-scratch-view chain-state)))
           (tip-view (bl.store:chain-state-coins-view chain-state))
           ;; Two reasons to skip level 3, and they say different things: no
           ;; database-backed view at all (a test fixture; a live node always
           ;; has the cache), or Core's cache-size guard below.
           (no-coins-db (and (>= check-level 3) (null scratch)))
           (skipped-l3 no-coins-db)
           (skipped-no-data nil)
           (failure-entry nil)
           (good-transactions 0)
           (entry tip-entry))
      (when no-coins-db
        (bl:log-warn "Skipped verification of level >=3: this chainstate has no coins database"))
      (loop
        (unless (and entry (bl.store:block-index-entry-prev-entry entry)) (return))
        (let* ((height (bl.store:block-index-entry-height entry))
               (hash (bl.store:block-index-entry-hash entry)))
          (when (<= height (- chain-height check-depth)) (return))
          (let ((block (bl.store:get-block block-store hash)))
            ;; Level 0: the body reads back. A pruned or snapshot chainstate
            ;; stops at the first block it has no data for instead of failing
            ;; (validation.cpp:4684-4690).
            (unless block
              (unless (or snapshot-p (bl:pruning-enabled-p))
                (bl:log-error "Verification error: reading block failed at ~D, hash=~A"
                              height (%hash-hex hash))
                (return-from verify-db :corrupted-block-db))
              (bl:log-info "Block verification stopping at height ~D (no data). This could be due to pruning or use of an assumeutxo snapshot." height)
              (setf skipped-no-data t)
              (return))
            (let ((bad (%verify-db-block-checks entry block chain-state check-level)))
              (when bad (return-from verify-db bad)))
            (when (and scratch (not skipped-l3))
              (if (and coins-cache-bytes
                       (> (+ (bl.store:view-mem-bytes scratch)
                             (bl.store:view-mem-bytes tip-view))
                          coins-cache-bytes))
                  (setf skipped-l3 t)
                  (ecase (%verify-db-disconnect entry block scratch)
                    (:failed (return-from verify-db :corrupted-block-db))
                    ;; UNCLEAN keeps going, remembering the lowest block that
                    ;; disagreed (validation.cpp:4726).
                    (:unclean (setf good-transactions 0 failure-entry entry))
                    (:ok (incf good-transactions
                               (length (bl.ser:bitcoin-block-transactions block))))))))
          (when (bl:interrupt-requested-p) (return-from verify-db :interrupted))
          (setf entry (bl.store:block-index-entry-prev-entry entry))))
      (when failure-entry
        (bl:log-error "Verification error: coin database inconsistencies found (last ~D block~:P, ~D good transaction~:P before that)"
                      (1+ (- chain-height
                             (bl.store:block-index-entry-height failure-entry)))
                      good-transactions)
        (return-from verify-db :corrupted-block-db))
      (when (and (>= check-level 4) (not skipped-l3) entry)
        (let ((r (%verify-db-reconnect chain-state block-store scratch entry tip-entry)))
          (unless (eq r :success) (return-from verify-db r))))
      (when (and skipped-l3 (not no-coins-db))
        (bl:log-warn "Skipped verification of level >=3 (insufficient database cache size). Consider increasing -dbcache."))
      (bl:log-info "Verification: No coin database inconsistencies in last ~D block~:P (~D transaction~:P)"
                   (- chain-height (if entry
                                       (bl.store:block-index-entry-height entry)
                                       chain-height))
                   good-transactions)
      (cond (skipped-l3 :skipped-l3-checks)
            (skipped-no-data :skipped-missing-blocks)
            (t :success)))))
