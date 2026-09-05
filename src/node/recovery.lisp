(in-package #:bitcoin-lisp)

(defvar *chainstates-reset-to-genesis* nil
  "Chainstates RECOVER-INCONSISTENT-CHAINSTATE reset to an empty UTXO set at
genesis during THIS startup (its interrupted-reindex-chainstate branch).

The two recoveries run several steps apart -- %INIT-RECOVER-CHAIN resolves the
interrupted reindex, %INIT-SERVICES then reconciles the coins pointer -- and
the later one used to undo the earlier one: it read the pointer the old wipe
had left standing, placed it, and moved chainstate.dat FORWARD to the
pre-reindex tip over the empty set it had just been reset from. A chainstate
listed here has already been settled by the branch that understands why it is
empty, so the reconcile leaves it alone.")

(defun reconcile-coins-db-best-block (node)
  "Make chainstate.dat agree with where the coins actually are.

Returns :match, :reconciled, :unresolvable, :unrecorded (a chainstate written
before the coins DB carried the pointer), :empty (the coins view holds nothing,
so there is no state to reconcile toward), :reset (this chainstate was just
reset to genesis by the interrupted-reindex recovery) or NIL when there is
nothing to compare.

The coins DB records the block its UTXO state corresponds to, moved with the
coins themselves, so a disagreement with chainstate.dat is not ambiguous: the
pointer is the fact and the tip record is the stale copy. THE COINS WIN. That
direction is not a preference — a UTXO set cannot be reconstructed from the tip
record, while the tip record is one hash we can rewrite, and the same choice is
what the older in-transition recovery already makes by probing.

Core reaches the same end differently: DB_HEAD_BLOCKS gives it a RANGE, so
ReplayBlocks must roll the coins to one end of it (validation.cpp:4812-4889).
Our pointer is exact, so there is nothing to roll — we move the cheap record to
the expensive one and let normal sync re-validate the gap.

Unresolvable means the coins name a block we have no index entry for, which no
amount of local reasoning can fix; the caller should treat that as fatal rather
than proceed on a tip we cannot place.

An EMPTY coins view is never reconciled toward, in either direction: Core's
is_coinsview_empty (node/chainstate.cpp:69-70) is exactly \"wipe requested OR
GetBestBlock().IsNull()\", and LoadChainTip is SKIPPED under it, so an empty
UTXO set leaves the chain where it is and the rebuild supplies the tip. A
pointer left standing over an emptied database by an older build's reindex
wipe is that case wearing a hash."
  (let* ((chainstate (node-chain-state node))
         (view (and chainstate
                    (bl.store:chain-state-coins-view chainstate))))
    (unless (typep view 'bl.store:coins-view-cache)
      (return-from reconcile-coins-db-best-block nil))
    (when (member chainstate *chainstates-reset-to-genesis*)
      (log-info "Chainstate was just reset to genesis by reindex recovery; not reconciling its coins pointer")
      (return-from reconcile-coins-db-best-block :reset))
    (let ((recorded (bl.store:coins-view-db-best-block
                     (bl.store:coins-view-cache-base view)))
          (tip (bl.store:best-block-hash chainstate)))
      (cond
        ((null recorded)
         (log-info "Coins DB has no best-block pointer yet; it will be written on the next flush")
         :unrecorded)
        ((and tip (equalp recorded tip))
         :match)
        ;; Core's is_coinsview_empty gate. The genesis pointer is exempt: an
        ;; empty set AT genesis is the correct, ordinary state of a node that
        ;; has connected nothing, and moving the tip record back to it is what
        ;; a from-genesis restart needs.
        ((and (bl.store:coins-view-empty-p view)
              (not (equalp recorded (bl.store:chain-state-genesis-hash
                                     chainstate))))
         (log-warn "Coins DB best-block names ~A but the UTXO set is EMPTY; leaving chainstate.dat at height ~D"
                   (bl.crypto:bytes-to-hex
                    (bl.crypto:reverse-bytes recorded))
                   (bl.store:current-height chainstate))
         (log-warn "Rebuild the UTXO set with -reindex-chainstate; blocks marked invalid while the set was empty need reconsiderblock")
         :empty)
        (t
         (let ((entry (bl.store:get-block-index-entry chainstate recorded)))
           (cond
             ((null entry)
              (log-error "Coins DB best-block ~A is not in the block index; cannot place the UTXO set"
                         (bl.crypto:bytes-to-hex
                          (bl.crypto:reverse-bytes recorded)))
              :unresolvable)
             (t
              (let ((coins-height (bl.store:block-index-entry-height entry))
                    (tip-height (bl.store:current-height chainstate)))
                (log-warn "UTXO set is at height ~D (~A) but chainstate.dat records tip height ~D; a reorg or flush was interrupted"
                          coins-height
                          (bl.crypto:bytes-to-hex
                           (bl.crypto:reverse-bytes recorded))
                          tip-height)
                (setf (bl.store:chain-state-best-block-hash chainstate)
                      (copy-seq recorded)
                      (bl.store:chain-state-best-height chainstate)
                      coins-height)
                (bl.store:save-state chainstate :in-transition nil)
                (log-warn "Recovered: chainstate.dat moved to the UTXO set's own block; sync will re-validate the gap")
                :reconciled)))))))))

;;; --- Chainstate crash recovery -------------------------------------------
;;;
;;; do-flush is a 3-phase commit (see do-flush): Phase 1 marks chainstate.dat
;;; in-transition, Phase 2 commits the UTXO LevelDB in ONE atomic writebatch,
;;; Phase 3 clears the marker. A crash between Phase 1 and Phase 3 leaves the
;;; marker set. Because Phase 2 is a single atomic batch, the on-disk UTXO set
;;; is at EXACTLY the new tip (Phase 2 finished) or the previous committed tip
;;; (Phase 2 hadn't run) — never a torn mix. We tell the two apart by probing
;;; coinbase outputs and rewrite chainstate.dat to match the UTXO set, instead
;;; of the old "move aside and re-sync from genesis" — mirrors Bitcoin Core
;;; resolving its DB_HEAD_BLOCKS marker on startup rather than reindexing.

(defvar *pending-chainstate-recovery* nil
  "List of chainstates whose load-state reported :inconsistent, so their
recovery runs after the block store, UTXO caches, and header index are all
open. Per-chainstate: the primary and a snapshot chainstate recover
independently against their own state files and coins views.")

(defun %coinbase-committed-p (node chainstate block-hash)
  "T iff BLOCK-HASH's coinbase output 0 is an unspent coin in CHAINSTATE's
coins view. A coinbase is unspendable for +coinbase-maturity+ (100) blocks,
so once its block is committed to the UTXO set the coin is necessarily
present — and every block above the committed tip contributes no coins at
all. That makes coinbase-presence a monotone probe for 'is the UTXO set at
or past this block', with no false positives from later spends. Returns
NIL if the block isn't on disk (the block store is shared across
chainstates)."
  (let ((block (bl.store:get-block (node-block-store node) block-hash)))
    (when block
      (let* ((cb (first (bl.ser:bitcoin-block-transactions block)))
             (txid (bl.ser:transaction-hash cb)))
        (and (bl.store:get-utxo
              (bl.store:chain-state-coins-view chainstate) txid 0)
             t)))))

(defun recover-inconsistent-chainstate
    (node &optional (chain-state (node-current-chainstate node)))
  "Resolve an in-transition chainstate without a from-genesis resync.
Per-chainstate: probes CHAIN-STATE's own coins view and rewrites its own
state file (storage-suffix-named), so recovering one chainstate can never
touch another's on-disk state. The 3-phase commit semantics are unchanged.
Probes whether the recorded tip's coins were committed; if so just clears
the marker, otherwise walks back to the highest ancestor whose coins ARE
committed (the true UTXO tip) and rewrites the state file there so IBD
re-validates only the gap. A recorded tip AT genesis is an interrupted
-reindex-chainstate (see do-reindex-chainstate): the coins DB is re-wiped
and the marker cleared, resuming as an ordinary from-genesis sync. Returns
T on success, NIL if the blocks needed to resolve it aren't on disk (caller
then aborts for a resync).

For a snapshot chainstate, its base block is always treated as committed:
the populate step verified and durably flushed the whole snapshot UTXO set
before the chainstate ever existed, and its coins only move forward from
there — so both the tip==base case (nothing dirty could have been flushed)
and the walk-back floor (rewind to the base, whose coins ARE the verified
snapshot) resolve without probing blocks below the base, which are not on
disk on the snapshot side."
  (let* ((new-hash (bl.store:best-block-hash chain-state))
         (new-height (bl.store:current-height chain-state))
         (snapshot-base (bl.store:chain-state-from-snapshot-blockhash
                         chain-state)))
    (flet ((committed-p (hash)
             (or (and snapshot-base (equalp hash snapshot-base))
                 (%coinbase-committed-p node chain-state hash))))
      (cond
        ((null new-hash)
         (log-error "Chainstate recovery: no recorded tip to recover from")
         nil)
        ;; Recorded tip = genesis: an interrupted -reindex-chainstate.
        ;; do-reindex-chainstate rewinds chainstate.dat to genesis (marker
        ;; set) before wiping the coins DB, so this state means the wipe or
        ;; the replay's first flush never completed. Nothing SHOULD be
        ;; committed at genesis — whatever the coins DB holds is refuse from
        ;; the interrupted wipe — so the one consistent resolution is an
        ;; empty set: re-wipe and clear the marker. The node then resumes as
        ;; an ordinary from-genesis sync (or rebuilds from stored blocks if
        ;; -reindex-chainstate is passed again after IBD re-covers the tip).
        ((and (not snapshot-base)
              (equalp new-hash (bl.store:chain-state-genesis-hash
                                chain-state)))
         (let ((view (bl.store:chain-state-coins-view chain-state)))
           (when (typep view 'bl.store:coins-view-cache)
             (let ((erased (bl.store:coins-view-cache-wipe view)))
               (when (plusp erased)
                 (log-info "Chainstate recovery: erased ~D leftover coin~:P from the interrupted wipe"
                           erased)))))
         (bl.store:save-state chain-state :in-transition nil)
         ;; Tell RECONCILE-COINS-DB-BEST-BLOCK, which runs later in startup,
         ;; that this chainstate's emptiness is understood and settled.
         (pushnew chain-state *chainstates-reset-to-genesis*)
         (log-warn "Chainstate recovery: interrupted reindex-chainstate; UTXO set reset to empty at genesis (chain will re-sync)")
         (log-warn "Any block marked invalid while the UTXO set was empty stays marked; clear it with reconsiderblock")
         t)
        ;; Phase 2 committed the new tip — chainstate.dat already holds it,
        ;; just drop the marker.
        ((committed-p new-hash)
         (bl.store:save-state chain-state :in-transition nil)
         (log-info "Chainstate recovery: UTXO set already at recorded tip h=~D; marker cleared"
                   new-height)
         t)
        ;; UTXO set is behind: find the real tip by walking back.
        (t
         (let ((entry (bl.store:get-block-index-entry chain-state new-hash)))
           (loop while entry
                 do (setf entry (bl.store:block-index-entry-prev-entry entry))
                 until (or (null entry)
                           (committed-p
                            (bl.store:block-index-entry-hash entry))))
           (cond
             (entry
              (let ((h (bl.store:block-index-entry-height entry))
                    (hash (bl.store:block-index-entry-hash entry)))
                ;; pruned-height is left as recorded — pruning is monotone and
                ;; lags the tip by the whole block window, so it is far below
                ;; this rewind point and those files are gone regardless.
                (setf (bl.store:chain-state-best-block-hash chain-state) hash
                      (bl.store:chain-state-best-height chain-state) h)
                (bl.store:save-state chain-state :in-transition nil)
                (log-warn "Chainstate recovery: UTXO set at h=~D (recorded tip h=~D); rewound chainstate.dat ~D block~:P, will re-validate the gap"
                          h new-height (- new-height h))
                t))
             (t
              (log-error "Chainstate recovery: no committed ancestor found on disk (blocks pruned below the UTXO tip?); resync required")
              nil))))))))
