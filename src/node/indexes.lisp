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
  "BIP157 genesis-anchor migration (see BLOCKFILTERINDEX-ENSURE-GENESIS-ANCHOR:
an index built before genesis indexing existed seeded its header chain at the
first STORED block, so every absolute cfheaders/cfcheckpt/getblockfilter header
it served diverged from Core), then rewind a best marker that is not on the
active chain -- see %REWIND-BLOCKFILTERINDEX."
  (declare (ignore store))
  (when (eq :rebuilt (bl.store:blockfilterindex-ensure-genesis-anchor bfi cs))
    (log-info "Block filter index wiped; rebuilding from genesis"))
  (%rewind-blockfilterindex bfi cs))

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
         ;; The raw stored height, which INDEX-PREPARE-SYNC has just made
         ;; trustworthy -- Core's Sync likewise walks from the
         ;; m_best_block_index its Rewind moved (index/base.cpp:201-247). The
         ;; chain-resolving INDEX-HEIGHT is what the CALLER's guard uses,
         ;; before that repair has run.
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

(defvar *index-start-check* nil
  "When T, CATCH-UP-INDEX refuses an index whose sync would need block data
this node no longer has, instead of syncing as far as it can.

Core asks that question once, in StartIndexBackgroundSync, before any index
starts (init.cpp:2314-2382); everywhere else -- the restart after an
assumeutxo promotion -- an index simply resumes. Binding it at the start-up
call site rather than testing it inside keeps both callers of CATCH-UP-INDEX
spelled the way they are, including the one a structural test names.")

(defun %index-connects-undo-data-p (index)
  "T when INDEX needs each block's undo data to index it -- Core's
IndexOptions::connect_undo_data, set by the filter index
(index/blockfilterindex.cpp:95) and coinstatsindex (:320) and left false by
the txindex and the spender index. It decides which of Core's two refusals
an unreachable start height gets, because block data and undo data are
pruned together but reported apart."
  (typep index '(or bl.store:blockfilterindex bl.store:coinstatsindex)))

(defun %lowest-block-on-disk (chainstate)
  "The lowest height whose block body is still on disk. Our prune cursor names
the highest height that has been REMOVED, so nothing pruned (0) still leaves
genesis in place."
  (let ((pruned (bl.store:chain-state-pruned-height chainstate)))
    (if (plusp pruned) (1+ pruned) 0)))

(defun %init-index (node index)
  "Core BaseIndex::Init (index/base.cpp:119-134): place the best block read from
INDEX's own database on the node's block index. A block the block index does
not hold is an InitError -- `best block of <name> not found. Please rebuild the
index.' -- which Init returns to AppInitMain's Step 8 (init.cpp:1925), ending
start-up; a null record starts the index from nothing.

The record can only name a block the block index made durable because it is
written by COMMIT-INDEX alone, from the end of a catch-up and after each
chainstate flush (%COMMIT-INDEXES-AFTER-FLUSH), as Core's Commit is."
  (when (eq :not-found (bl.store:resolve-index-best
                        index (node-validated-chainstate node)))
    (init-error "best block of ~A not found. Please rebuild the index."
                (bl.store:index-name index))))

(defun %refuse-index-beyond-pruned-data (node index)
  "Stop start-up when INDEX would have to read blocks this node has pruned.

Core verifies, before it starts ANY index, that every block from each index's
sync position up to the tip is on disk -- with undo data for the indexes that
need it -- and turns a gap into an InitError naming the index
(init.cpp:2366-2381). StartIndexBackgroundSync then returns false and its
caller reports the fatal error that stops the node (:2040-2043). An index
whose best block is below the prune horizon has nothing to resume from: the
blocks it still has to read are gone and will not come back.

Ours synced as far as it could and logged a warning, so a node in that state
started and ran with an index silently stuck, which is the state
feature_index_prune.py:154-159 restarts three nodes to refuse.

Core skips the check entirely while the chain is empty (`if (current_height >
0)', :2321), and so must this: a fresh pruned datadir has indexed nothing and
pruned nothing, and refusing there would stop every first start with
-prune and an index."
  (let* ((cs (node-validated-chainstate node))
         (tip (bl.store:current-height cs)))
    (when (plusp tip)
      (let ((next-needed (1+ (bl.store:index-height index cs)))
            (lowest (%lowest-block-on-disk cs)))
        (when (< next-needed lowest)
          (let ((name (bl.store:index-name index)))
            ;; Core's two sentences differ only in naming undo data, and each
            ;; goes out as its own InitError line before the fatal one.
            (report-init-error
             (if (%index-connects-undo-data-p index)
                 "~A best block of the index goes beyond pruned data (including undo data). Please disable the index or reindex (which will download the whole blockchain again)"
                 "~A best block of the index goes beyond pruned data. Please disable the index or reindex (which will download the whole blockchain again)")
             name)
            (init-error
             "A fatal internal error occurred, see debug.log for details: ~
Failed to start indexes, shutting down~A"
             (code-char 8230))))))))

(defun catch-up-index (node index)
  "Catch INDEX up to NODE's validated chainstate tip (Core BaseIndex::Sync):
place its best block on the chain (RESOLVE-INDEX-BEST), make it trustworthy
(INDEX-PREPARE-SYNC), backfill the shortfall (%CATCH-UP-INDEX-SYNC), and commit
the best block reached (COMMIT-INDEX), as Core's Sync does on both of its
exits. Indexes bind the validated chainstate (Core ValidatedChainstate) and index blocks in order
from genesis -- identical to the current chainstate while only the primary
exists, and the promoted snapshot chainstate after assumeutxo completion.
Shared by startup and the post-promotion index rebind. Synchronous, unlike
Core's background BaseIndex thread. Returns what INDEX-SYNC returned, or NIL
when there was nothing to do."
  (bl.store:resolve-index-best index (node-validated-chainstate node))
  (when *index-start-check*
    (%refuse-index-beyond-pruned-data node index))
  (let* ((cs (node-validated-chainstate node))
         (tip (bl.store:current-height cs))
         (name (bl.store:index-name index)))
    (bl.store:index-prepare-sync index cs (node-block-store node))
    ;; Core's Sync commits when it catches up, and when it is interrupted
    ;; (index/base.cpp:214-236): the locator of wherever the index got to.
    (unwind-protect (%catch-up-index-sync node index cs tip name)
      (bl.store:commit-index index cs))))

(defun %catch-up-index-sync (node index cs tip name)
  "CATCH-UP-INDEX's backfill: INDEX-SYNC from the best block to CS's TIP,
logging progress and the final height."
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
      n)))

(defparameter +index-thread-specials+
  '(*node* bl.chain:*network* bl.log:*log-stream* bl.log:*log-buffer*
    bl.log:*log-buffer-index* bl.log:*log-buffer-count*)
  "The specials an index's sync thread takes over from the thread that starts
it: a thread sees only GLOBAL values, and a caller that binds the node or the
log destination (a test, an in-image restart) means those.")

(defun start-index-background-sync (node index)
  "Core BaseIndex::StartBackgroundSync (index/base.cpp:453-459): INDEX's
catch-up (CATCH-UP-INDEX) on a thread of its own, traced under the index's
name -- `txindex thread start', `basic block filter index thread start',
`coinstatsindex thread start', `txospenderindex thread start', which
feature_init.py:79-82 interrupts on. Unlike Core's, start-up waits for it
before going on: the connect-time index hooks assume an index that is already
at the tip, where Core's BaseIndex ignores the blocks it is notified of until
its own sync has caught up (BaseIndex::BlockConnected's m_synced guard). The
thread is real; only the concurrency is not ported. What the catch-up
signals is signalled again here, on the caller's thread."
  (%init-index node index)
  (when *index-start-check*
    (%refuse-index-beyond-pruned-data node index))
  (let* ((specials +index-thread-specials+)
         (values (mapcar #'symbol-value specials))
         (result nil)
         (failure nil)
         (thread (bt:make-thread
                  (lambda ()
                    (progv specials values
                      (handler-case
                          (let ((*index-start-check* nil)) ; asked above
                            (bl.log:trace-thread
                             (bl.store:index-name index)
                             (lambda () (setf result (catch-up-index node index)))))
                        (error (c) (setf failure c)))))
                  :name (format nil "bitcoin-~A" (bl.store:index-name index)))))
    (bt:join-thread thread)
    (when failure (error failure))
    result))

(defun restart-indexes-for-validated-chainstate (node)
  "Rebind every index onto the node's (now promoted) validated chainstate and
catch it up to its tip (Core restarts all indexes on background-sync
completion, init.cpp:1367-1383). During the background sync the indexes
tracked the historical chainstate up to the snapshot base; the promoted
chainstate carries the full chain past the base, so this resumes indexing
from where each index left off. A no-op when no index is enabled."
  (dolist (index (node-indexes node))
    (catch-up-index node index)))

(defun %index-fork-entry (cs best-hash)
  "The last block common to the active chain and the branch BEST-HASH sits on
(Core walks pprev in Rewind / FindForkInGlobalIndex), as a block-index entry.
NIL when the header index does not know BEST-HASH — headers are only persisted
at flush time, so the crash that produces a stale marker can also lose the
branch it names — or when the two chains do not actually meet.

Shared by the coinstats and spender rewinds: one walk, so two indexes reading
the same stale marker cannot disagree about where its branch left the active
chain."
  (let* ((stale (bl.store:get-block-index-entry cs best-hash))
         (tip (and stale (bl.store:get-block-index-entry
                          cs (bl.store:best-block-hash cs))))
         (fork (and tip (bl.val:find-fork-point stale tip))))
    ;; find-fork-point returns wherever its first walk stopped if the chains
    ;; never meet (a broken prev-entry link), so confirm the answer really is
    ;; on the active chain rather than trusting a fail-open result.
    (when (and fork (bl.store:entry-on-active-chain-p cs fork))
      fork)))

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
      (let* ((fork-entry (and best-hash (%index-fork-entry cs best-hash)))
             (fork (and fork-entry (bl.store:block-index-entry-height fork-entry)))
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

(defmethod bl.store:index-prepare-sync ((idx bl.store:txospender-index) cs store)
  "Rewind a best marker that is not on the active chain (including one left
above the tip) before backfilling on top of it -- see
%REWIND-TXOSPENDERINDEX."
  (%rewind-txospenderindex idx cs store))

(defun %index-active-chain-height (chainstate hash)
  "How far an index whose best marker names HASH has got ON THE ACTIVE CHAIN.

The stored marker is a (hash, height) pair, and the height is only meaningful
while the hash is still the active chain's block at it: a marker left on an
abandoned branch names a height that says nothing about how much of the ACTIVE
chain is indexed. Answering the raw stored height is what let CATCH-UP-INDEX's
(< height tip) guard be satisfied by an off-chain marker -- with a no-op
prepare-sync, nothing was rewound AND nothing was backfilled, so the active
chain's blocks between the fork point and the marker's height were never
indexed, and gettxspendingprevout then answered that an output is UNSPENT for
an outpoint a confirmed transaction spends. Core cannot say this: its height
comes off a locator resolved against the chain (BaseIndex::Init,
index/base.cpp:120-131).

Off-chain answers the FORK height, and an unplaceable marker (or an empty
index) -1 -- both strictly below the tip, so the backfill runs whatever
prepare-sync did. Shared by the spender and filter indexes, and it lives here
rather than in storage because the fork walk needs the validation layer, like
the coinstats index-write-block below."
  (if (null hash)
      -1
      (let ((entry (bl.store:get-block-index-entry chainstate hash)))
        (if (and entry (bl.store:entry-on-active-chain-p chainstate entry))
            (bl.store:block-index-entry-height entry)
            (let ((fork (%index-fork-entry chainstate hash)))
              (if fork (bl.store:block-index-entry-height fork) -1))))))

(defmethod bl.store:index-height ((idx bl.store:txospender-index) chainstate)
  "How far the spender index has got on the active chain; see
%INDEX-ACTIVE-CHAIN-HEIGHT, whose narrative is this index's."
  (%index-active-chain-height chainstate (bl.store:txospenderindex-best-block idx)))

(defmethod bl.store:index-height ((bfi bl.store:blockfilterindex) chainstate)
  "How far the filter index has got on the active chain; see
%INDEX-ACTIVE-CHAIN-HEIGHT. BLOCKFILTERINDEX-HEIGHT stays the RAW stored
height, because that is what the backfill resumes from once
INDEX-PREPARE-SYNC has made the marker trustworthy."
  (%index-active-chain-height chainstate
                              (nth-value 1 (bl.store:blockfilterindex-best bfi))))

(defun %bfi-anchor-entry (bfi cs height)
  "The highest block at or below HEIGHT on CS's ACTIVE chain whose filter is
stored, as a block-index entry, or NIL.

This is where a rewind may leave the best marker: BLOCKFILTERINDEX-ADD-BLOCK
chains each filter header off the PARENT's stored one and refuses a block whose
parent has none, so the marker must name a block the next write can chain from.
Core states the same requirement as an assertion -- the last line of
BlockFilterIndex::CustomRemove reads the parent's header back and dereferences
it (index/blockfilterindex.cpp:296).

Ordinarily the fork point itself is the answer and the loop stops on its first
probe. It walks down only for an index seeded mid-chain, which is a pruned
node's (Core refuses -blockfilterindex with pruning outright)."
  (loop for h from (min height (bl.store:current-height cs)) downto 0
        for e = (bl.store:get-block-at-height cs h)
        when (and e (bl.store:blockfilterindex-has-block-p
                     bfi (bl.store:block-index-entry-hash e)))
          return e))

(defun %rewind-blockfilterindex (bfi cs)
  "Make the filter index's best marker name a block on the ACTIVE chain before
anything backfills on top of it (Core BaseIndex::Rewind, index/base.cpp:290-326,
driven from Sync at :239 once NextSyncBlock has answered the block after the
fork point).

Core's per-block work for THIS index is BlockFilterIndex::CustomRemove
(index/blockfilterindex.cpp:277-297), and every step of it is already true here
or has nothing to undo. It copies the abandoned block's record from the height
index to the HASH index -- our records are only ever keyed by hash, so an
orphaned filter stays queryable exactly as Core keeps it, deliberately (\"filter
data for any block that becomes part of the active chain can always be
retrieved\", :41-42). It rewrites the filter-file position, which we do not
have. And it resets the cached m_last_header to the parent's, which we do not
cache: every write reads the parent's stored header. Its CustomOptions asks for
connect_undo_data ONLY (:92-97), so Core reads neither block bodies nor undo
data while rewinding a filter index -- the new branch's headers are re-derived
by the forward re-index, chained off the fork point's stored header. What is
left is Core's last line, SetBestBlockIndex(new_tip): move the marker back to
the fork point.

Until this existed the marker was only repaired when it stood ABOVE the tip. A
branch switch at the SAME heights -- a reorg while the index was off, or a deep
reorg across a restart -- left it naming an abandoned block, and the backfill
then started at its height + 1 on the ACTIVE chain, where the parent filter
header does not exist and BLOCKFILTERINDEX-ADD-BLOCK refuses the write as
:noncontiguous. So the index stopped at the fork for good: it went on serving
the abandoned branch's filters and never indexed the active chain past it.

Returns NIL when the marker was already on the active chain -- the common case,
and it costs one lookup. Otherwise the height rewound to, or -1 when no stored
filter could be tied to the active chain and the index must be rebuilt."
  (multiple-value-bind (best-height best-hash) (bl.store:blockfilterindex-best bfi)
    (when (minusp best-height)
      (return-from %rewind-blockfilterindex nil))
    ;; The marker is asked about at its own HEIGHT rather than through
    ;; ENTRY-ON-ACTIVE-CHAIN-P, because the raw stored height is what
    ;; BUILD-BLOCKFILTERINDEX resumes from: a hash that is on the active chain
    ;; at some OTHER height would restart the backfill in the wrong place.
    (let* ((tip (bl.store:current-height cs))
           (active (and (<= best-height tip)
                        (bl.store:get-block-at-height cs best-height))))
      (when (and active best-hash
                 (equalp (bl.store:block-index-entry-hash active) best-hash))
        (return-from %rewind-blockfilterindex nil))
      (log-warn "Block filter index best (height ~D, ~A) is not on the active chain (tip ~D); rewinding"
                best-height
                (if best-hash (bl.crypto:bytes-to-hex best-hash) "no hash")
                tip)
      ;; The fork point is Core's new_tip. When the header index cannot place
      ;; the marker's branch at all -- headers are only persisted at flush time,
      ;; so the crash that strands a marker can also lose the branch it names --
      ;; Core refuses to start ("best block of %s not found. Please rebuild the
      ;; index.", index/base.cpp:129-131). Falling back to the tip asks
      ;; %BFI-ANCHOR-ENTRY the same question the marker-above-the-tip repair
      ;; this replaces asked, and costs no rebuild.
      (let* ((fork (and best-hash (%index-fork-entry cs best-hash)))
             (entry (%bfi-anchor-entry
                     bfi cs (if fork (bl.store:block-index-entry-height fork) tip))))
        (cond
          (entry
           (let ((height (bl.store:block-index-entry-height entry)))
             (log-warn "Block filter index rewound from height ~D to ~D (the abandoned branch's filters stay queryable by hash, as Core's hash index keeps them)"
                       best-height height)
             (bl.store:blockfilterindex-set-best
              bfi height (bl.store:block-index-entry-hash entry))
             height))
          (t
           (log-warn "Block filter index: no stored filter at or below height ~D is on the active chain; rebuilding from genesis"
                     (min best-height tip))
           (bl.store:blockfilterindex-clear-best bfi)
           -1))))))

(defun %rewind-txospenderindex (idx cs store)
  "Make the spender index's best marker name a block on the ACTIVE chain before
anything backfills on top of it, erasing the abandoned branch's rows on the way
back (Core BaseIndex::Rewind, index/base.cpp:290-320).

The spender index is the one index here whose stale rows are wrong rather than
merely old: coinstats and blockfilter records are keyed by HEIGHT, so a
reconnect overwrites them, while a spender key carries the spending block's
hash and no height. That is why Core has it opt into disconnect_data
(index/txospenderindex.cpp:73-78) and implement CustomRemove (:136-139), and
why the erase is exact: both sides build the outpoint list from the block
alone, so what the rewind deletes is exactly what the connect wrote.

Until this existed the index had no OFFLINE rewind at all -- INDEX-REWIND-BLOCK
was reachable only from the live :block-disconnected hook, which cannot fire
for blocks disconnected while the process was down (a kill with the index ahead
of the flushed chainstate, or an invalidateblock across a restart).

Returns NIL when the marker was already on the active chain -- the common case,
and it costs one lookup. Otherwise the height rewound to, or -1 when the branch
could not be walked and the index must be rebuilt."
  (multiple-value-bind (best-hash best-height) (bl.store:txospenderindex-best-block idx)
    (unless best-hash
      (return-from %rewind-txospenderindex nil))
    (let ((stale (bl.store:get-block-index-entry cs best-hash))
          (tip (bl.store:current-height cs)))
      (when (and stale (bl.store:entry-on-active-chain-p cs stale))
        (return-from %rewind-txospenderindex nil))
      (log-warn "Spender index best (height ~D, ~A) is not on the active chain (tip ~D); rewinding"
                best-height (bl.crypto:bytes-to-hex best-hash) tip)
      (let ((fork (and stale (%index-fork-entry cs best-hash))))
        (unless fork
          (log-warn "Spender index: the branch its marker names cannot be placed ~
in the header index; rebuilding from genesis")
          (bl.store:index-clear-best idx)
          (return-from %rewind-txospenderindex -1))
        ;; Core's Rewind loop: walk pprev from the stale tip to (not including)
        ;; the fork point, reading each block and calling CustomRemove. A body
        ;; we cannot read is Core's ReadBlock failure, which aborts the rewind;
        ;; here the marker is cleared instead, so the backfill rebuilds rather
        ;; than leaving a gap nothing will ever fill. The abandoned rows then
        ;; survive, but they are inert: %TXOSPENDER-CONFIRMED-SPENDER discards
        ;; any locator whose block is not on the active chain.
        (let ((fork-hash (bl.store:block-index-entry-hash fork)))
          (loop for e = stale then (bl.store:block-index-entry-prev-entry e)
                while (and e (not (equalp (bl.store:block-index-entry-hash e)
                                          fork-hash)))
                do (let* ((hash (bl.store:block-index-entry-hash e))
                          (block (and store (bl.store:get-block store hash))))
                     (unless block
                       (log-warn "Spender index: block ~A of the abandoned branch ~
is unavailable; rebuilding from genesis" (bl.crypto:bytes-to-hex hash))
                       (bl.store:index-clear-best idx)
                       (return-from %rewind-txospenderindex -1))
                     ;; Core's CustomRemove, reached the one way it is ever
                     ;; reached: from a rewind (index/base.cpp:313).
                     (bl.store:index-rewind-block
                      idx cs block hash
                      (bl.store:block-index-entry-height e)))))
        (let ((height (bl.store:block-index-entry-height fork)))
          (log-warn "Spender index rewound to height ~D (~D block~:P of the abandoned branch erased)"
                    height (- best-height height))
          (bl.store:txospenderindex-set-best-block
           idx (bl.store:block-index-entry-hash fork) height)
          height)))))

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

(defun %index-rewind-if-not-parent (index chainstate block)
  "Core BaseIndex::BlockConnected's rewind step (index/base.cpp:363-367): a
block whose parent is not the index's best block means the chain moved under
the index, so rewind it to the active chain BEFORE writing.

This is the only place an index removes anything: Core is never told about a
disconnected block (there is no BlockDisconnected handler), so the removal
happens here, when a replacement has arrived. INDEX-PREPARE-SYNC is the same
rewind the startup catch-up runs -- walk the best marker back to the last
block it shares with the active chain, removing what the abandoned branch
wrote on the way. It runs only on the rare connect that is not a
continuation."
  (let ((best (bl.store:index-best-block index)))
    (when (and best
               (not (equalp best (bl.ser:block-header-prev-block
                                  (bl.ser:bitcoin-block-header block)))))
      (bl.store:index-prepare-sync index chainstate (node-block-store *node*)))))

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
                (progn
                  (%index-rewind-if-not-parent index chainstate block)
                  (bl.store:index-write-block index chainstate block block-hash height spent-utxos))
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
  "Disconnect-time hook: the indexes are NOT told, and that is Core's shape.

BaseIndex has no BlockDisconnected handler at all. Its rewind is driven from
the next BlockConnected, which notices the stored best block is not the
arriving block's parent and only then walks pprev calling CustomRemove
(index/base.cpp:363-367, :290-320) -- see %INDEX-REWIND-IF-NOT-PARENT. So a
disconnected block's rows stay readable until a block replaces it, which is
what rpc_gettxspendingprevout.py:198-200 asserts across an invalidateblock:
`tx2 is not in the mempool anymore, but still in txospender index which has
not been rewound yet'.

Erasing here answered UNSPENT in that window -- Core's shape for `nothing ever
spent it', and so indistinguishable from a real answer -- and made a reorg
that re-connects the same block rebuild what it had just thrown away. The hook
stays declared because the disconnect signal is part of the interface and a
reader looking for the index's half of it should find this.

What DOES happen at disconnect is the prune locks' half: Core's DisconnectTip
moves every lock that began above the new tip back to it
(validation.cpp:2954-2962), so pruning keeps the blocks an index still has to
rewind through. Active chainstate only -- a background chainstate's blocks
are not what the indexes read."
  (declare (ignore block block-hash))
  (unless (bl.store:chain-state-target-blockhash chainstate)
    (bl.store:move-prune-locks-back (1- height)))
  nil)

(defmethod bl.store:index-write-block ((csi bl.store:coinstatsindex) chainstate block block-hash height spent-utxos)
  "The coinstats fold needs the block subsidy, which is consensus; that is
why this method lives here rather than in storage."
  (declare (ignore chainstate))
  (values (bl.store:coinstatsindex-add-block csi block block-hash height spent-utxos
                                             (bl.val:calculate-block-subsidy height))
          nil))

;;; -reindex WIPES every index here before it is opened. Core passes do_reindex
;;; as each index's f_wipe (init.cpp:1905, :1909, :1915, :1920), which becomes
;;; DBParams::wipe_data (index/base.cpp:68-73), so the index opens with a null
;;; DB_BEST_BLOCK and BaseIndex::Init starts it from nothing (:119-133): a
;;; rebuild from scratch, not a catch-up. What that is for is the case a
;;; catch-up cannot reach -- an index whose best block is no longer on disk.
;;; Its marker names a block a pruned node has dropped
;;; (feature_index_prune.py:187-190), or one the rebuilt block index does not
;;; place, and the catch-up has nothing to resume from; only a wipe gives it a
;;; starting point again.
;;;
;;; The cost lands on a pruned node: a wiped index can only be rebuilt from the
;;; blocks still on disk, so its history begins at the prune horizon. Core pays
;;; the same price by another route -- its -reindex in prune mode deletes the
;;; block files outright (CleanupBlockRevFiles, node/blockstorage.cpp:654-688)
;;; and re-downloads the chain.
(defun %start-indexes (txindex blockfilterindex txospenderindex coinstatsindex
                       reindex reindex-chainstate)
  "Open every enabled index on *NODE* and catch it up to the tip (Core
init.cpp \"Step 8: start indexers\"; our catch-ups are synchronous). Prune
locks are re-registered from scratch; REINDEX wipes each index -- see above."
  ;; Transaction index. The catch-up is what makes enabling -txindex on a
  ;; synced node index history (build-tx-index had no caller until the txindex fix);
  ;; it resumes from the best-block marker, so a current index costs one
  ;; marker lookup (ga9-txindex-startup-catch-up-is-wired pins the call).
  (when txindex
    (log-info "Initializing transaction index...")
    (setf (node-tx-index *node*)
          (bl.store:init-tx-index (node-data-directory *node*) :enabled t
                                  :wipe reindex))
    (bl.rpc:set-rpc-warmup-status "Catching up transaction index...")
    (start-index-background-sync *node* (node-tx-index *node*))
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
                                          :enabled t :wipe reindex))
    (log-info "Block filter index loaded: indexed to height ~D"
              (bl.store:blockfilterindex-height (node-blockfilterindex *node*)))
    ;; The filter index needs each block's undo data to build its filter, so
    ;; pruning must not run ahead of it (Core blockfilterindex AllowPrune() ->
    ;; true, and BaseIndex::SetBestBlockIndex takes a lock at its best height).
    (let ((bfi (node-blockfilterindex *node*)))
      (bl.store:register-prune-lock
       ;; Under the INDEX's name, as Core registers it (index/base.cpp:494) --
       ;; it is what PRUNE-LOCK-CEILING's "limited pruning to height" prints.
       (bl.store:index-name bfi)
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
    (start-index-background-sync *node* (node-blockfilterindex *node*)))

  ;; Initialize txospenderindex (optional). Core starts every index's
  ;; background sync from init, so enabling -txospenderindex on a synced node
  ;; indexes history; until P2e-1 this index was only ever caught up on
  ;; assumeutxo promotion, and the flag indexed nothing historical (the same
  ;; no-caller shape as ga9-txindex-startup-catch-up-is-wired).
  (when txospenderindex
    (log-info "Initializing spender index...")
    (setf (node-txospenderindex *node*)
          (bl.store:init-txospender-index (node-data-directory *node*)
                                          :enabled t :wipe reindex))
    (let ((best (bl.store:txospenderindex-best-block
                 (node-txospenderindex *node*))))
      (log-info "Spender index loaded: best block ~A"
                (if best (bl.crypto:bytes-to-hex best) "none")))
    (bl.rpc:set-rpc-warmup-status "Catching up txospender index...")
    (start-index-background-sync *node* (node-txospenderindex *node*)))

  ;; Initialize coinstatsindex (optional). Like the filter index, catch up over
  ;; already-stored blocks before the sync thread starts, then the connect-time
  ;; hook advances it. Its running MuHash must be contiguous from genesis, so a
  ;; pruned node (missing early undo data) can only build it if its stored
  ;; history reaches genesis -- otherwise the backfill stops at the first gap.
  (when coinstatsindex
    (log-info "Initializing coinstats index...")
    (setf (node-coinstatsindex *node*)
          (bl.store:init-coinstatsindex (node-data-directory *node*)
                                        :enabled t :wipe reindex))
    (log-info "Coinstats index loaded: indexed to height ~D"
              (bl.store:coinstatsindex-height (node-coinstatsindex *node*)))
    ;; Same reasoning as the filter index (Core coinstatsindex AllowPrune() ->
    ;; true): its per-block statistics are derived from undo data.
    (let ((csi (node-coinstatsindex *node*)))
      (bl.store:register-prune-lock
       (bl.store:index-name csi)
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
    (start-index-background-sync *node* (node-coinstatsindex *node*))))

(defun %commit-indexes-after-flush (chainstate)
  "Core BaseIndex::ChainStateFlushed (index/base.cpp:380-422), signalled after
every full chainstate flush (validation.cpp:2828-2831): an index on the
validated chainstate whose best block is on the flushed chain at or above its
tip commits its locator (COMMIT-INDEX). One behind the tip is not synced and
is skipped quietly; one on another branch is skipped with Core's warning.

This is the ONLY place a running node writes an index's best-block record
(besides the catch-up's end), which is what makes Core's refusal of a record
naming an unknown block (%INIT-INDEX) safe: the flush wrote the block index
first."
  (when (and *node* chainstate (eq chainstate (node-validated-chainstate *node*)))
    (let* ((tip-hash (bl.store:best-block-hash chainstate))
           (tip (and tip-hash (bl.store:get-block-index-entry chainstate tip-hash))))
      (when tip
        (dolist (index (node-indexes *node*))
          (let* ((best-hash (values (bl.store:index-best-block index)))
                 (best (and best-hash
                            (bl.store:get-block-index-entry chainstate best-hash))))
            (cond
              ;; Nothing indexed, or behind the tip: Core's `if (!m_synced)
              ;; return' (:387-389) -- an index still catching up commits from
              ;; its own sync.
              ((or (null best)
                   (< (bl.store:block-index-entry-height best)
                      (bl.store:block-index-entry-height tip))))
              ((eq (bl.store:entry-ancestor-at-height
                    best (bl.store:block-index-entry-height tip))
                   tip)
               (bl.store:commit-index index chainstate))
              (t
               (log-warn "Locator contains block (hash=~A) not on known best chain (tip=~A); not writing index locator"
                         (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes tip-hash))
                         (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes best-hash)))))))))))
