(in-package #:bitcoin-lisp)

(defun do-reindex-chainstate ()
  "Rebuild the UTXO set from already-stored blocks (Bitcoin Core
-reindex-chainstate): wipe the coins view, reset the chainstate to genesis,
and re-apply every stored active-chain block's UTXO effects, trusting the
already-validated stored blocks (no script re-validation, no re-download).
The undo files are left as-is -- they record spent prevouts, which the rebuild
does not change. Clears the coinstatsindex best marker so its startup backfill
rebuilds it against the reindexed set; the blockfilterindex is unaffected
(its filters are over block scripts, not the UTXO set).

This realizes UTXO-set-content changes (e.g. dropping now-skipped unspendable
outputs) on an existing node without a full network resync, and doubles as
chainstate disaster-recovery when blocks+index are intact but the coins DB is
suspect.

Crash safety: before the wipe, chainstate.dat is rewound to genesis WITH the
in-transition marker, and every flush during the replay (size-triggered and
final) goes through the 3-phase %flush-chainstate. In Core the coins DB owns
its own tip (DB_BEST_BLOCK is erased by the -reindex-chainstate wipe and
re-committed atomically with the coins in each BatchWrite, txdb.cpp:124-159),
so a crashed rebuild can never load a tip ahead of the coins; our separate
chainstate.dat needs the marker discipline to get the same guarantee. A crash
before the first replay flush completes leaves tip=genesis + marker, which
recover-inconsistent-chainstate resolves by re-wiping (nothing should be
committed at genesis; anything on disk is refuse from the interrupted wipe).
A crash later leaves the marker at the current replay height with the coins
DB at exactly the last committed flush height, so the standard walk-back
recovery rewinds chainstate.dat to it. Previously the old CLEAN pre-reindex
chainstate.dat sat untouched over the gutted coins DB for the whole replay —
a crash loaded it silently over garbage."
  (let* ((cs (node-chain-state *node*))
         (store (node-block-store *node*))
         (utxo (node-utxo-set *node*))
         (tip-hash (bl.store:best-block-hash cs))
         (tip-entry (and tip-hash (bl.store:get-block-index-entry cs tip-hash)))
         (tip-height (bl.store:current-height cs)))
    (when (or (null tip-entry) (zerop tip-height))
      (log-info "Reindex-chainstate: empty chain, nothing to rebuild")
      (return-from do-reindex-chainstate))
    (log-info "Reindex-chainstate: rebuilding UTXO set from ~D stored blocks..." tip-height)
    ;; Active chain genesis+1 .. tip, ascending (push while walking prev-entry
    ;; down from the tip leaves the list in height order).
    (let ((entries '()))
      (loop with e = tip-entry
            while (and e (plusp (bl.store:block-index-entry-height e)))
            do (push e entries)
               (setf e (bl.store:block-index-entry-prev-entry e)))
      ;; Rewind the chainstate to genesis and persist it WITH the
      ;; in-transition marker BEFORE touching the coins DB: from here until
      ;; the first replay flush commits, a crash is detected at load-state
      ;; and resolved by recover-inconsistent-chainstate's genesis branch
      ;; (re-wipe + clear), never loaded as clean state over a gutted set.
      (bl.store:update-chain-tip
       cs (bl.store::chain-state-genesis-hash cs) 0)
      (bl.store:save-state cs :in-transition t)
      ;; Empty the coins view.
      (let ((erased (bl.store:coins-view-cache-wipe utxo)))
        (log-info "Reindex-chainstate: erased ~D coin~:P; replaying..." erased))
      ;; NB: the coinstatsindex is opened AFTER this runs; its rebuild is
      ;; forced in its own init block (keyed off the reindex flag), not here.
      ;; The blockfilterindex is left alone -- its filters are over block
      ;; scripts, unaffected by a UTXO-set rebuild.
      ;; Replay every block's UTXO effects.
      (let ((n 0) (last-report (get-internal-real-time)))
        (block replay
          (dolist (entry entries)
            (let* ((hash (bl.store:block-index-entry-hash entry))
                   (height (bl.store:block-index-entry-height entry))
                   (blk (bl.store:get-block store hash)))
              (unless blk
                (log-warn "Reindex-chainstate: block at height ~D missing from store; ~
stopping (UTXO set rebuilt to height ~D)" height (1- height))
                (return-from replay))
              ;; Apply removes spent prevouts + adds spendable outputs (the
              ;; unspendable skip lives in apply-block-to-utxo-set). Discard the
              ;; returned undo list -- the on-disk undo files are unchanged.
              (bl.store:apply-block-to-utxo-set utxo blk height)
              (bl.store:update-chain-tip cs hash height)
              (incf n)
              ;; Size-triggered flushes go through the 3-phase commit like
              ;; the periodic flush: marker at the replay height, one atomic
              ;; synced coins batch, marker cleared — so the on-disk pair is
              ;; always chainstate.dat <= coins DB by an identifiable gap.
              (when (>= (bl.store:view-mem-bytes utxo)
                        (large-coins-cache-threshold *coins-cache-budget-bytes*))
                (%flush-chainstate cs :label "Reindex"))
              (let ((now (get-internal-real-time)))
                (when (> (- now last-report) internal-time-units-per-second)
                  (log-info "Reindex-chainstate: height ~D (~,1F%)"
                            height (* 100.0 (/ height tip-height)))
                  (setf last-report now))))))
        (%flush-chainstate cs :label "Reindex")
        (log-info "Reindex-chainstate complete: ~D block~:P re-applied, tip at height ~D"
                  n (bl.store:current-height cs))))))

(defun force-compact-databases ()
  "Full-compact every LevelDB the node has open -- the coins/chainstate DB plus
the block-filter and coinstats indexes -- reclaiming the disk that tombstones
still pin after a large deletion churn (e.g. a reindex-chainstate wipe). Mirrors
Bitcoin Core's -forcecompactdb, which sets CDBWrapper force_compact on each
database it opens. Synchronous and potentially slow on a large chainstate."
  (flet ((compact (label db)
           (when db
             (log-info "Starting database compaction of ~A" label)
             (bl.store:leveldb-compact db)
             (log-info "Finished database compaction of ~A" label))))
    (let ((utxo (node-utxo-set *node*))
          (bfi (node-blockfilterindex *node*))
          (csi (node-coinstatsindex *node*)))
      (when utxo
        (log-info "Starting database compaction of chainstate")
        (bl.store:coins-view-cache-compact utxo)
        (log-info "Finished database compaction of chainstate"))
      (when bfi (compact "blockfilterindex" (bl.store:blockfilterindex-db bfi)))
      (when csi (compact "coinstatsindex" (bl.store:coinstatsindex-db csi))))))
