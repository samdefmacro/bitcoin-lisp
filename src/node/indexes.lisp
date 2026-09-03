(in-package #:bitcoin-lisp)

;;; coinstatsindex rewind (Core BaseIndex::Rewind, index/base.cpp:239/290)
;;;
;;; coinstats records are keyed by HEIGHT with no block hash, there is no
;;; disconnect hook, and index writes reach the OS immediately while the
;;; chainstate tip only becomes durable at a flush (600s / N blocks / cache
;;; size — and a reorg does not trigger one). So a process kill inside that
;;; window leaves records holding an ABANDONED chain's state at heights at or
;;; below the tip that startup restores. The repair loop this replaces blessed
;;; any record it found at height <= tip and overwrote the stored meta hash,
;;; destroying the one piece of evidence that could have detected the
;;; divergence; every later query then served abandoned-chain numbers labelled
;;; with the active chain's hash. Core defends this with a per-record block
;;; hash it re-checks in RevertBlock; we recover the same guarantee at startup.

(defconstant +coinstatsindex-max-rewind+ 1000
  "How far back the coinstats rewind will verify records by recomputation
before giving up and rebuilding from genesis. Far deeper than any plausible
reorg; the cheap header-index walk is tried first and has no such bound.")

(defmethod bl.store:index-prepare-sync ((bfi bl.store:blockfilterindex) cs store)
  "BIP157 genesis-anchor migration, then repair a best marker left above the
tip (e.g. after invalidateblock): an index built before genesis indexing
existed seeded its header chain at the first STORED block, so every absolute
cfheaders/cfcheckpt/getblockfilter header it serves diverges from Core and
BIP157 light clients ban us. Detect and wipe it here; the backfill then
rebuilds from height 0 (the genesis filter is computed from chain
parameters). No-op on fresh and healthy indexes; on a pruned node a bad
index is kept (rebuild impossible) with a warning."
  (declare (ignore store))
  (let ((tip (bl.store:current-height cs)))
    (when (eq :rebuilt (bl.store:blockfilterindex-ensure-genesis-anchor bfi cs))
      (log-info "Block filter index wiped; rebuilding from genesis"))
    (when (> (bl.store:blockfilterindex-height bfi) tip)
      (log-warn "Block filter index best above tip (~D > ~D); repairing"
                (bl.store:blockfilterindex-height bfi) tip)
      (loop for h from tip downto 0
            for e = (bl.store:get-block-at-height cs h)
            when (and e (bl.store:blockfilterindex-has-block-p
                         bfi (bl.store:block-index-entry-hash e)))
              do (bl.store:blockfilterindex-set-best
                  bfi h (bl.store:block-index-entry-hash e))
                 (return)
            finally (bl.store:blockfilterindex-clear-best bfi)))))

(defmethod bl.store:index-prepare-sync ((csi bl.store:coinstatsindex) cs store)
  "Rewind a best marker that is not on the active chain (including one left
above the tip) before backfilling on top of it -- see %REWIND-COINSTATSINDEX."
  (%rewind-coinstatsindex csi cs store))

(defmethod bl.store:index-sync ((bfi bl.store:blockfilterindex) cs store &key undo-fn subsidy-fn progress)
  (declare (ignore subsidy-fn))
  (bl.store:build-blockfilterindex bfi cs store undo-fn :progress-callback progress))

(defmethod bl.store:index-sync ((csi bl.store:coinstatsindex) cs store &key undo-fn subsidy-fn progress)
  (bl.store:build-coinstatsindex csi cs store undo-fn subsidy-fn :progress-callback progress))

(defmethod bl.store:index-sync ((idx bl.store:txospender-index) cs store &key undo-fn subsidy-fn progress)
  "Walk forward from the best indexed height: the entries are keyed by
outpoint rather than by height, so they must be written in some order but
not necessarily this one; forward keeps the best marker meaningful if the
walk is interrupted. Stops, with a warning, at the first block whose body is
unavailable."
  (declare (ignore undo-fn subsidy-fn progress))
  (let* ((tip (bl.store:current-height cs))
         (from (1+ (bl.store:txospenderindex-height idx)))
         (done 0))
    (when (> from tip)
      (return-from bl.store:index-sync 0))
    (loop for h from from to tip
          for entry = (bl.store:get-block-at-height cs h)
          while entry
          do (when (bl:interrupt-requested-p)
               (log-warn "Spender index backfill stopped at height ~D" h)
               (return))
             (let* ((hash (bl.store:block-index-entry-hash entry))
                    (block (and store (bl.store:get-block store hash))))
               (cond
                 (block
                  (bl.store:txospenderindex-add-block idx block hash)
                  (bl.store:txospenderindex-set-best-block idx hash h)
                  (incf done))
                 (t
                  (log-warn "Spender index backfill stopped at height ~D: block body unavailable" h)
                  (return)))))
    done))

(defun catch-up-index (node index)
  "Catch INDEX up to NODE's validated chainstate tip (Core BaseIndex::Sync):
make its best marker trustworthy (INDEX-PREPARE-SYNC), then backfill the
shortfall (INDEX-SYNC), logging progress and the final height. Indexes bind
the validated chainstate (Core ValidatedChainstate) and index blocks in order
from genesis -- identical to the current chainstate while only the primary
exists, and the promoted snapshot chainstate after assumeutxo completion.
Shared by startup and the post-promotion index rebind. Synchronous, unlike
Core's background BaseIndex thread. Returns what INDEX-SYNC returned, or NIL
when there was nothing to do."
  (let* ((cs (node-validated-chainstate node))
         (tip (bl.store:current-height cs))
         (name (bl.store:index-name index)))
    (bl.store:index-prepare-sync index cs (node-block-store node))
    (when (< (bl.store:index-height index cs) tip)
      (log-info "Building ~A to height ~D..." name tip)
      (let ((n (bl.store:index-sync index cs (node-block-store node)
                                    :undo-fn #'bl.val:get-undo-data
                                    :subsidy-fn #'bl.val:calculate-block-subsidy
                                    :progress (lambda (h pct)
                                                (log-info "~A: height ~D (~,1F%)" name h pct)))))
        (log-info "~A build complete: ~D block~:P indexed" name n)
        (when (< (bl.store:index-height index cs) tip)
          (log-warn "~A stopped at height ~D of ~D (missing block/undo data ~
below the pruned horizon; the index needs genesis-contiguous history)"
                    name (bl.store:index-height index cs) tip))
        n))))

(defun restart-indexes-for-validated-chainstate (node)
  "Rebind every index onto the node's (now promoted) validated chainstate and
catch it up to its tip (Core restarts all indexes on background-sync
completion, init.cpp:1367-1383). During the background sync the indexes
tracked the historical chainstate up to the snapshot base; the promoted
chainstate carries the full chain past the base, so this resumes indexing
from where each index left off. A no-op when no index is enabled."
  (dolist (index (node-indexes node))
    (catch-up-index node index)))

(defun %coinstatsindex-fork-height (cs best-hash)
  "The height of the last block common to the active chain and the branch
BEST-HASH sits on (Core walks pprev in Rewind / FindForkInGlobalIndex). NIL
when the header index does not know BEST-HASH — headers are only persisted at
flush time, so the crash that produces a stale marker can also lose the branch
it names — or when the two chains do not actually meet."
  (let* ((stale (bl.store:get-block-index-entry cs best-hash))
         (tip (and stale (bl.store:get-block-index-entry
                          cs (bl.store:best-block-hash cs))))
         (fork (and tip (bl.val:find-fork-point stale tip))))
    ;; find-fork-point returns wherever its first walk stopped if the chains
    ;; never meet (a broken prev-entry link), so confirm the answer really is
    ;; on the active chain rather than trusting a fail-open result.
    (when (and fork (bl.store:entry-on-active-chain-p cs fork))
      (bl.store:block-index-entry-height fork))))

(defun %coinstatsindex-verified-height (csi cs store from)
  "The highest height at or below FROM whose stored record provably belongs to
the ACTIVE chain, found by recomputing it from its stored parent and the active
block at that height (see coinstatsindex-record-matches-block-p). This is the
fallback for when the header index cannot resolve the fork point, and it is
what keeps an ordinary unclean shutdown — index a few blocks ahead of the last
flushed tip, same chain — from costing a rebuild from genesis: the record at
the restored tip verifies on the first try. NIL if nothing verifies within
+coinstatsindex-max-rewind+."
  (loop for h from from downto (max 0 (- from +coinstatsindex-max-rewind+))
        do (when (zerop h)
             ;; Genesis is on every chain; its record is synthesized, not
             ;; folded from a parent, so presence is the whole check.
             (return (and (bl.store:coinstatsindex-get-stats csi 0) 0)))
           (let* ((entry (bl.store:get-block-at-height cs h))
                  (hash (and entry (bl.store:block-index-entry-hash entry)))
                  (block (and hash (bl.store:get-block store hash))))
             (when (and block
                        (bl.store:coinstatsindex-record-matches-block-p
                         csi block hash h
                         (bl.val:get-undo-data hash)
                         (bl.val:calculate-block-subsidy h)))
               (return h)))))

(defun %rewind-coinstatsindex (csi cs store)
  "Make the coinstats index's best marker name a block on the ACTIVE chain
before anything backfills on top of it, moving it back to the last common
ancestor when it does not (Core BaseIndex::Rewind). Records above the new best
are then rewritten by the backfill.

Returns NIL when the index was already consistent — the common case, and it
costs one hash comparison: a rewind that always rebuilt would be a severe
performance regression. Otherwise returns the height rewound to, or -1 when no
trustworthy record could be identified and the index must be rebuilt."
  (let ((tip (bl.store:current-height cs)))
    (multiple-value-bind (best-height best-hash)
        (bl.store:coinstatsindex-best csi)
      (when (minusp best-height)
        (return-from %rewind-coinstatsindex nil))
      (let ((active (and (<= best-height tip)
                         (bl.store:get-block-at-height cs best-height))))
        (when (and active best-hash
                   (equalp (bl.store:block-index-entry-hash active) best-hash))
          (return-from %rewind-coinstatsindex nil)))
      (log-warn "Coinstats index best (height ~D, ~A) is not on the active chain (tip ~D); rewinding"
                best-height
                (if best-hash (bl.crypto:bytes-to-hex best-hash) "no hash")
                tip)
      (let* ((fork (and best-hash (%coinstatsindex-fork-height cs best-hash)))
             (target (or (and fork
                              (<= fork tip)
                              (bl.store:coinstatsindex-get-stats csi fork)
                              fork)
                         (%coinstatsindex-verified-height csi cs store (min best-height tip))))
             (entry (and target (bl.store:get-block-at-height cs target))))
        (cond
          (entry
           (log-warn "Coinstats index rewound to height ~D (~A records above it will be rebuilt)"
                     target (- tip target))
           (bl.store:coinstatsindex-set-best
            csi target (bl.store:block-index-entry-hash entry))
           target)
          (t
           (log-warn "Coinstats index: no record below height ~D could be tied to the active chain; rebuilding from genesis"
                     (min best-height tip))
           (bl.store:coinstatsindex-clear-best csi)
           -1))))))

(defvar *index-stall-logged* '()
  "Names of indexes whose non-contiguous refusal has been logged: once per
index per process, not once per block.")

(defun node-indexes (node)
  "NODE's enabled indexes -- transaction, block filter, coinstats and spender
-- in the order they are driven. Every connect, disconnect and catch-up
reaches them through this list, so no call site can switch one off by
forgetting an argument (the shape of the 3rd, 6th, 7th and 15th no-caller
bugs, all of them the txindex)."
  (remove-if-not #'bl.store:base-index-enabled
                 (remove nil (list (node-tx-index node)
                                   (node-blockfilterindex node)
                                   (node-coinstatsindex node)
                                   (node-txospenderindex node)))))

(bl.vi:define-validation-hook :block-connected index-block-connected (chainstate block block-hash height spent-utxos)
  "Connect-time hook (Core BaseIndex::BlockConnected): fold BLOCK, connected
at HEIGHT with SPENT-UTXOS as its undo list, into every enabled index.
CHAINSTATE is the chainstate the block connected to; signals from any
chainstate other than the node's VALIDATED one are dropped -- indexes index
blocks in order from genesis, so they bind Core's ValidatedChainstate
(init.cpp:1367-1383) and must ignore an unvalidated snapshot chainstate's
tip-range connects. Never signals: an index failure must not abort a block
connect, so consensus is unaffected whether an index is on or off."
  (when (and *node* (eq chainstate (node-validated-chainstate *node*)))
    (dolist (index (node-indexes *node*))
      (let ((name (bl.store:index-name index)))
        (handler-case
            (multiple-value-bind (result status)
                (bl.store:index-write-block index chainstate block block-hash height spent-utxos)
              (declare (ignore result))
              (when (and (eq status :noncontiguous)
                         (not (member name *index-stall-logged* :test #'string=)))
                (push name *index-stall-logged*)
                (log-warn "~A stalled at height ~D: gap below best-indexed height ~D; ~
the startup backfill will heal it on next restart"
                          name height (bl.store:index-height index chainstate))))
          (error (e)
            (log-warn "~A failed at height ~D: ~A" name height e)))))))

(bl.vi:define-validation-hook :block-disconnected index-block-disconnected (chainstate block block-hash height)
  "Disconnect-time hook (Core BaseIndex's rewind): erase what
INDEX-BLOCK-CONNECTED wrote for BLOCK (at HEIGHT) in every enabled index.
Same chainstate rule and same never-signals rule as the connect hook."
  (when (and *node* (eq chainstate (node-validated-chainstate *node*)))
    (dolist (index (node-indexes *node*))
      (handler-case
          (bl.store:index-rewind-block index chainstate block block-hash height)
        (error (e)
          (log-warn "~A failed to rewind ~A: ~A"
                    (bl.store:index-name index) (bl.crypto:bytes-to-hex block-hash) e))))))

(defmethod bl.store:index-write-block ((csi bl.store:coinstatsindex) chainstate block block-hash height spent-utxos)
  "The coinstats fold needs the block subsidy, which is consensus; that is
why this method lives here rather than in storage."
  (declare (ignore chainstate))
  (values (bl.store:coinstatsindex-add-block csi block block-hash height spent-utxos
                                             (bl.val:calculate-block-subsidy height))
          nil))

(defun %start-indexes (txindex blockfilterindex txospenderindex coinstatsindex
                       reindex-chainstate)
  "Open every enabled index on *NODE* and catch it up to the tip (Core
init.cpp \"Step 8: start indexers\" -- our catch-ups are synchronous, see
CATCH-UP-INDEX). Prune locks are re-registered from scratch."
  ;; Transaction index. The catch-up is what makes enabling -txindex on a
  ;; synced node index history (build-tx-index had no caller until the txindex fix);
  ;; it resumes from the best-block marker, so a current index costs one
  ;; marker lookup (ga9-txindex-startup-catch-up-is-wired pins the call).
  (when txindex
    (log-info "Initializing transaction index...")
    (setf (node-tx-index *node*)
          (bl.store:init-tx-index (node-data-directory *node*) :enabled t))
    (bl.rpc:set-rpc-warmup-status "Catching up transaction index...")
    (catch-up-index *node* (node-tx-index *node*))
    (log-info "Transaction index loaded: ~D entries"
              (bl.store:txindex-count (node-tx-index *node*))))
  ;; Prune locks are re-registered from scratch on every start: registration is
  ;; by name, so a re-init replaces rather than accumulates, but an index that
  ;; was enabled last run and is disabled this one would otherwise leave a lock
  ;; behind holding the prune horizon down forever.
  (bl.store:clear-prune-locks)
  ;; Likewise the once-per-run stall latch of the connect-time index hook.
  (setf *index-stall-logged* '())

  ;; Initialize BIP158 block filter index (optional)
  (when blockfilterindex
    (log-info "Initializing block filter index...")
    (setf (node-blockfilterindex *node*)
          (bl.store:init-blockfilterindex (node-data-directory *node*)
                                                       :enabled t))
    (log-info "Block filter index loaded: indexed to height ~D"
              (bl.store:blockfilterindex-height (node-blockfilterindex *node*)))
    ;; The filter index needs each block's undo data to build its filter, so
    ;; pruning must not run ahead of it (Core blockfilterindex AllowPrune() ->
    ;; true, and BaseIndex::SetBestBlockIndex takes a lock at its best height).
    (let ((bfi (node-blockfilterindex *node*)))
      (bl.store:register-prune-lock
       "blockfilterindex"
       (lambda ()
         ;; -1 is "nothing indexed yet", which is Core's height_first ==
         ;; INT_MAX: no height to protect, so no constraint. Returning it
         ;; verbatim would drive the ceiling to 1 and stop pruning outright.
         (let ((h (bl.store:blockfilterindex-height bfi)))
           (and (plusp h) h)))))
    ;; One-time catch-up over already-stored blocks, before the sync thread
    ;; starts (single-threaded here, so no writer races). Fresh-from-genesis
    ;; nodes have nothing to do; the connect-time hook then indexes forward.
    (bl.rpc:set-rpc-warmup-status "Catching up block filter index...")
    (catch-up-index *node* (node-blockfilterindex *node*)))

  ;; Initialize txospenderindex (optional). Core starts every index's
  ;; background sync from init, so enabling -txospenderindex on a synced node
  ;; indexes history; until P2e-1 this index was only ever caught up on
  ;; assumeutxo promotion, and the flag indexed nothing historical (the same
  ;; no-caller shape as ga9-txindex-startup-catch-up-is-wired).
  (when txospenderindex
    (log-info "Initializing spender index...")
    (setf (node-txospenderindex *node*)
          (bl.store:init-txospender-index (node-data-directory *node*)
                                                      :enabled t))
    (let ((best (bl.store:txospenderindex-best-block
                 (node-txospenderindex *node*))))
      (log-info "Spender index loaded: best block ~A"
                (if best (bl.crypto:bytes-to-hex best) "none")))
    (bl.rpc:set-rpc-warmup-status "Catching up txospender index...")
    (catch-up-index *node* (node-txospenderindex *node*)))

  ;; Initialize coinstatsindex (optional). Like the filter index, catch up over
  ;; already-stored blocks before the sync thread starts, then the connect-time
  ;; hook advances it. Its running MuHash must be contiguous from genesis, so a
  ;; pruned node (missing early undo data) can only build it if its stored
  ;; history reaches genesis -- otherwise the backfill stops at the first gap.
  (when coinstatsindex
    (log-info "Initializing coinstats index...")
    (setf (node-coinstatsindex *node*)
          (bl.store:init-coinstatsindex (node-data-directory *node*)
                                                    :enabled t))
    (log-info "Coinstats index loaded: indexed to height ~D"
              (bl.store:coinstatsindex-height (node-coinstatsindex *node*)))
    ;; Same reasoning as the filter index (Core coinstatsindex AllowPrune() ->
    ;; true): its per-block statistics are derived from undo data.
    (let ((csi (node-coinstatsindex *node*)))
      (bl.store:register-prune-lock
       "coinstatsindex"
       (lambda ()
         (let ((h (bl.store:coinstatsindex-height csi)))
           (and (plusp h) h)))))
    ;; A chainstate reindex may have changed UTXO-set contents (e.g. dropping
    ;; unspendable outputs), so the coinstats records must be rebuilt to stay
    ;; consistent. Clear the best marker to force a full rebuild below.
    (when reindex-chainstate
      (bl.store:coinstatsindex-clear-best (node-coinstatsindex *node*))
      (log-info "Coinstats index: rebuilding after chainstate reindex"))
    (bl.rpc:set-rpc-warmup-status "Catching up coinstats index...")
    (catch-up-index *node* (node-coinstatsindex *node*))))
