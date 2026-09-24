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

A block that spends nothing has an EMPTY undo record. GET-UNDO-DATA's second
value -- READABLE-P, Core's ReadBlockUndo verdict -- catches a rev file that
is gone for every block, coinbase-only ones included (feature_abortnode.py:41
restarts a node whose rev00000.dat was deleted and expects the start to fail);
this predicate covers the remaining case, an empty record where the block
spends. A corrupt EMPTY record inside a present rev file is caught by the
reader's checksum."
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
    (when (>= check-level 1)
      (multiple-value-bind (ok error)
          (%check-block block chain-state height (bl.ser:get-unix-time)
                        :skip-header t)
        ;; CheckBlock's PoW test comes first (validation.cpp:3963), so its
        ;; verdict is the one reported.
        (unless (check-proof-of-work (bl.ser:bitcoin-block-header block))
          (setf ok nil error :bad-proof-of-work))
        (unless ok
          (bl:log-error "Verification error: found bad block at ~D, hash=~A (~A)"
                        height (%hash-hex hash) (block-reject-reason-string error))
          (return-from %verify-db-block-checks :corrupted-block-db))))
    (when (and (>= check-level 2)
               (bl.store:block-index-entry-undo-pos entry)
               (multiple-value-bind (undo readable) (get-undo-data hash)
                 ;; READABLE-P NIL is Core's failed ReadBlockUndo whatever
                 ;; the block holds: its rev record is gone. An empty record
                 ;; for a block that spends is the other way to be unreadable.
                 (or (not readable)
                     (and (null undo) (%verify-db-block-spends-p block)))))
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
    (multiple-value-bind (undo readable) (get-undo-data hash)
      (when (or (not readable)
                (and (null undo) (%verify-db-block-spends-p block)))
        (bl:log-error "Verification error: irrecoverable inconsistency in block data at ~D, hash=~A"
                      height (%hash-hex hash))
        (return-from %verify-db-disconnect :failed))
      (if (bl.store:disconnect-block-from-utxo-set
           scratch block (or undo '()) :height height)
          :ok
          :unclean))))

(defun %verify-db-progress (report-done percentage)
  "Core's progress line, once per 10% step (validation.cpp:4675-4679 and
:4750-4754): log `Verification progress: N%' when PERCENTAGE, clamped to
1-99 as Core clamps it, enters a new tens step past REPORT-DONE. Returns the
new REPORT-DONE. The walk down reports before its depth test, as Core does,
so the step it stops on is logged too; at level 4 the walk down is the first
half of the bar and the reconnect the second."
  (let ((pct (max 1 (min 99 percentage))))
    (if (< report-done (floor pct 10))
        (progn (bl:log-info "Verification progress: ~D%" pct)
               (floor pct 10))
        report-done)))

(defun %verify-db-reconnect (chain-state block-store scratch from-entry tip-entry
                             chain-height check-depth report-done)
  "Level 4: reconnect every block above FROM-ENTRY up to TIP-ENTRY into
SCRATCH (Core validation.cpp:4747-4769). Returns :SUCCESS, :INTERRUPTED or
:CORRUPTED-BLOCK-DB. The progress it reports runs on from REPORT-DONE, the
walk down's last tens step, from 50% to 99% (Core's second half of the
bar at level 4).

Core calls ConnectBlock here and nothing else -- not ContextualCheckBlock,
which runs in AcceptBlock -- so ours is VALIDATE-BLOCK with CONNECT-ONLY
against the scratch view, and SKIP-HEADER, since the header was checked at
index admission and a re-read body carries no cached hash. The difference is
visible: rpc_blockchain.py:106 calls verifychain(4, 0) after restarting with
-testactivationheight=segwit@6 over blocks mined with segwit active from
genesis, and block 1's coinbase witness is `unexpected-witness' to
ContextualCheckBlock but nothing to ConnectBlock."
  (let ((up from-entry))
    (loop
      (setf report-done
            (%verify-db-progress
             report-done
             (- 100 (truncate (* 50 (- chain-height
                                       (bl.store:block-index-entry-height up)))
                              check-depth))))
      (let ((next (bl.store:get-block-at-height
                   chain-state (1+ (bl.store:block-index-entry-height up)))))
        (when (null next) (return :success))
        (setf up next))
      (let* ((hash (bl.store:block-index-entry-hash up))
             (height (bl.store:block-index-entry-height up))
             (block (bl.store:get-block block-store hash)))
        (unless block
          (bl:log-error "Verification error: ReadBlock failed at ~D, hash=~A"
                        height (%hash-hex hash))
          (return :corrupted-block-db))
        (multiple-value-bind (valid error)
            (validate-block block chain-state scratch height
                            (bl.ser:get-unix-time) :skip-header t :connect-only t)
          (unless valid
            (bl:log-error "Verification error: found unconnectable block at ~D, hash=~A (~A)"
                          height (%hash-hex hash) (block-reject-reason-string error))
            (return :corrupted-block-db)))
        (bl.store:apply-block-to-utxo-set scratch block height)
        (when (bl:interrupt-requested-p) (return :interrupted))
        (when (equalp hash (bl.store:block-index-entry-hash tip-entry))
          (return :success))))))

(defun %verify-db-finish (chain-height entry good-transactions
                          skipped-l3 skipped-no-data)
  "VerifyDB's closing line and verdict (validation.cpp:4771-4780): the block
count is measured from ENTRY, where the walk down stopped, and a skip is
reported ahead of success in Core's order."
  (bl:log-info "Verification: No coin database inconsistencies in last ~D blocks (~D transactions)"
               (- chain-height (if entry
                                   (bl.store:block-index-entry-height entry)
                                   chain-height))
               good-transactions)
  (cond (skipped-l3 :skipped-l3-checks)
        (skipped-no-data :skipped-missing-blocks)
        (t :success)))

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
    (bl:log-info "Verifying last ~D blocks at level ~D" check-depth check-level)
    (bl:log-info "Verification progress: 0%")
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
           (report-done 0)
           (entry tip-entry))
      (when no-coins-db
        (bl:log-warn "Skipped verification of level >=3: this chainstate has no coins database"))
      (loop
        (unless (and entry (bl.store:block-index-entry-prev-entry entry)) (return))
        (let* ((height (bl.store:block-index-entry-height entry))
               (hash (bl.store:block-index-entry-hash entry)))
          (setf report-done
                (%verify-db-progress report-done (truncate (* (- chain-height height) (if (>= check-level 4) 50 100)) check-depth)))
          (when (<= height (- chain-height check-depth)) (return))
          (let ((block (bl.store:get-block block-store hash)))
            ;; Level 0: the body reads back. A pruned or snapshot chainstate
            ;; stops at the first block it has no data for instead of failing
            ;; (validation.cpp:4684-4690).
            (unless block
              (unless (or snapshot-p (bl:pruning-enabled-p))
                (bl:log-error "Verification error: ReadBlock failed at ~D, hash=~A"
                              height (%hash-hex hash))
                (return-from verify-db :corrupted-block-db))
              (bl:log-info "Block verification stopping at height ~D (no data). This could be due to pruning or use of an assumeutxo snapshot." height)
              (setf skipped-no-data t)
              (return))
            (let ((bad (%verify-db-block-checks entry block chain-state check-level)))
              (when bad (return-from verify-db bad)))
            (when (and scratch (not skipped-l3))
              ;; Past Core's cache-size guard (validation.cpp:4716), level 3
              ;; stops for good; UNCLEAN keeps going, remembering the lowest
              ;; block that disagreed (validation.cpp:4726).
              (ecase (if (and coins-cache-bytes
                              (> (+ (bl.store:view-mem-bytes scratch)
                                    (bl.store:view-mem-bytes tip-view))
                                 coins-cache-bytes))
                         :skipped
                         (%verify-db-disconnect entry block scratch))
                (:skipped (setf skipped-l3 t))
                (:failed (return-from verify-db :corrupted-block-db))
                (:unclean (setf good-transactions 0 failure-entry entry))
                (:ok (incf good-transactions
                           (length (bl.ser:bitcoin-block-transactions block)))))))
          (when (bl:interrupt-requested-p) (return-from verify-db :interrupted))
          (setf entry (bl.store:block-index-entry-prev-entry entry))))
      (when failure-entry
        (bl:log-error "Verification error: coin database inconsistencies found (last ~D blocks, ~D good transactions before that)"
                      (1+ (- chain-height
                             (bl.store:block-index-entry-height failure-entry)))
                      good-transactions)
        (return-from verify-db :corrupted-block-db))
      (when (and skipped-l3 (not no-coins-db))
        (bl:log-warn "Skipped verification of level >=3 (insufficient database cache size). Consider increasing -dbcache."))
      (when (and (>= check-level 4) (not skipped-l3) entry)
        (let ((r (%verify-db-reconnect chain-state block-store scratch entry tip-entry
                                       chain-height check-depth report-done)))
          (unless (eq r :success) (return-from verify-db r))))
      (%verify-db-finish chain-height entry good-transactions
                         skipped-l3 skipped-no-data))))
