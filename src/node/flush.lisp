(in-package #:bitcoin-lisp)

(defparameter +flush-every-n-blocks+ 25000
  "Block-count flush backstop. The 600s time trigger and the 450MiB
   coins-cache size trigger are the real guards; this count only caps the
   redo window if both somehow fail to fire. Was 1000, which at mainnet
   IBD speed (~30 b/s) meant a full header-index rewrite + CRC every
   ~35s — ~6% of CPU by sb-sprof at h≈280k. A crash now redoes at most
   ~10 min of validation (the time trigger), like Core's
   DATABASE_WRITE_INTERVAL bounding work by time, not block count.")

(defparameter +flush-every-n-seconds+ 600
  "Time-based flush trigger (10 min): flush if at least N seconds have
   elapsed since the last flush, regardless of block count. Without this,
   a slow sync window (~2 b/s on testnet4 stress regions) takes ~8 min
   to accumulate 1000 blocks, and a connect-tip stall halts flushes
   entirely (May 2 crash: stuck at h=70700 for 1h40m, last save was at
   h=70000 at 14:34, lost 700 blocks of progress + caused full re-sync
   from genesis on restart). Bitcoin Core uses DATABASE_WRITE_INTERVAL
   = 1h (validation.cpp:DATABASE_WRITE_INTERVAL) — we use 10 min because
   our re-validation from a checkpoint is much slower than Core's.")

(defvar *coins-cache-budget-bytes* (* 450 1024 1024)
  "Memory budget for the in-memory UTXO (coins) cache before a size-triggered
flush. Default mirrors Bitcoin Core's DEFAULT_DB_CACHE (kernel/caches.h,
450 MiB); start-node's :dbcache-mib raises it (Core's -dbcache). A larger
budget keeps more of the UTXO set in RAM, cutting LevelDB disk reads during
IBD — the dominant cost once the chainstate outgrows the LevelDB table cache
(profiled I/O-wait-bound at mainnet h~828k). The cache flushes-and-clears at
the LARGE threshold, so memory stays bounded (the unbounded cache was the
original mainnet OOM blocker).")

(defun large-coins-cache-threshold (budget)
  "The coins-cache usage at which a periodic flush is due. Mirrors Bitcoin Core's
LargeCoinsCacheThreshold (validation.h): flush once less than 10 MiB (or 10% of
the budget, whichever is larger free margin) remains."
  (max (floor (* budget 9) 10)
       (- budget (* 10 1024 1024))))

(defun maybe-critical-flush (chainstate)
  "Flush CHAINSTATE only when its coins cache has exceeded its whole budget —
Core's CRITICAL tier (validation.cpp:2690), the one FlushStateMode::IF_NEEDED
acts on (:2763).

This exists for the reorg loops. Core calls FlushStateToDisk(IF_NEEDED) at the
end of BOTH DisconnectTip (validation.cpp:2966) and ConnectTip (:3093), so the
cache is size-checked once per disconnected AND per connected block, including
mid-reorg. We had exactly one flush call site in the whole tree — the
tip-extension path of connect-block — so perform-reorg ran its disconnect and
connect loops with nothing draining the cache at all. Every disconnected block
restores its spent prevouts as dirty entries and every connected fork block
adds its outputs; a deep rollback (dumptxoutset to an assumeutxo height, or
invalidateblock on an old hash) walks tens of thousands of blocks in one
uninterrupted loop. This heap has already been OOM-killed twice on this cache.

CRITICAL rather than the LARGE threshold MAYBE-PERIODIC-FLUSH uses, and
deliberately NOT that function: its count and time triggers would fire
repeatedly inside a deep reorg and turn a rollback into a flush storm. Core
draws the same distinction — PERIODIC acts on LARGE, IF_NEEDED only on
CRITICAL.

MUST be called where the coins-view best-block pointer already names the block
whose coins are in the cache, i.e. AFTER the apply/disconnect call rather than
between the mutation and the pointer move. Both COIN-VIEW-APPLY-BLOCK and
DISCONNECT-BLOCK-FROM-UTXO-SET set that pointer as their last act, so calling
this immediately after either is safe; anywhere else would persist a cache and
a pointer that disagree."
  (when *node*
    (let ((view (and chainstate
                     (bl.store:chain-state-coins-view chainstate))))
      (when (and view
                 (>= (bl.store:view-mem-bytes view)
                     (chainstate-coins-cache-budget chainstate)))
        (log-info "Coins cache past its budget mid-reorg; flushing")
        (log-memory-snapshot "pre-flush-critical")
        (%flush-chainstate chainstate)
        (setf *blocks-since-flush* 0
              *last-flush-universal-time* (bl.ser:get-node-time))
        t))))

(defun chainstate-coins-cache-budget (chainstate)
  "CHAINSTATE's coins-cache budget in bytes: its per-chainstate allocation
when maybe-rebalance-caches has split the global budget (assumeutxo dual
chainstates), otherwise the whole *coins-cache-budget-bytes*."
  (or (bl.store:chain-state-coins-cache-bytes chainstate)
      *coins-cache-budget-bytes*))

(defun maybe-rebalance-caches (node)
  "Split the coins-cache budget between NODE's chainstates (Core
ChainstateManager::MaybeRebalanceCaches, validation.cpp:6103-6134). A sole
chainstate gets everything — both the ordinary no-snapshot case and the
snapshot chainstate after background validation completes. While BOTH
chainstates exist, the one doing the urgent work gets 95%: the snapshot
(current) chainstate while the node is still in IBD, the historical
chainstate once the tip is synced. Core calls this at chainstate init,
snapshot activation (incl. the activation-failure cleanup), background-
validation completion, and on IBD exit; our call sites mirror those.

Divergence from Core: Core sizes TWO caches per chainstate (coinstip +
coinsdb) from separate totals; we keep one coins cache per chainstate whose
budget is a flush-trigger threshold (maybe-periodic-flush), so the same
ratios apply to the single global budget and take effect at the next flush
check rather than through an immediate resize/eviction."
  (let ((current (node-current-chainstate node))
        (historical (node-historical-chainstate node)))
    (cond
      ((null historical)
       (when (and current
                  (bl.store:chain-state-from-snapshot-blockhash current))
         (log-info "[snapshot] allocating all cache to the snapshot chainstate"))
       (when current
         (setf (bl.store:chain-state-coins-cache-bytes current) nil)))
      (t
       (let ((total *coins-cache-budget-bytes*))
         (multiple-value-bind (current-share historical-share)
             (if (bl.net:initial-block-download-p current)
                 (values 0.95d0 0.05d0)
                 (values 0.05d0 0.95d0))
           (setf (bl.store:chain-state-coins-cache-bytes current)
                 (floor (* total current-share))
                 (bl.store:chain-state-coins-cache-bytes historical)
                 (floor (* total historical-share)))
           (log-info "[snapshot] coins-cache budgets rebalanced: current chainstate ~D MiB, historical chainstate ~D MiB"
                     (floor (chainstate-coins-cache-budget current) 1048576)
                     (floor (chainstate-coins-cache-budget historical) 1048576))))))))

(defun rebalance-caches-on-ibd-exit ()
  "Rebalance the coins-cache allocation when the node leaves initial block
download while a background (historical) chainstate is in use (Core
ActivateBestChain's exited_ibd hook, validation.cpp:3479-3486). Called from
the IBD latch flip in bl.net:initial-block-download-p."
  (let ((node *node*))
    (when (and node (node-historical-chainstate node))
      (maybe-rebalance-caches node))))

(defun effective-prune-target-bytes ()
  "The automatic-prune target in bytes (Core BlockManager::FindFilesToPrune,
node/blockstorage.cpp:330-338): the -prune target divided by the number of
chainstates — halved while an assumeutxo historical chainstate exists, so
half the block storage is reserved for the historical chainstate's
re-derivation and the other half for the most-work chainstate — and floored
at +min-disk-space-for-block-files+ (550 MiB, validation.h:87)."
  (let ((num-chainstates (if (and *node* (node-historical-chainstate *node*)) 2 1)))
    (max +min-disk-space-for-block-files+
         (floor (* *prune-target-mib* 1048576) num-chainstates))))

(defvar *blocks-since-flush* 0
  "Counter incremented per connected block; reset to 0 when a flush runs.")

(defvar *last-flush-universal-time* 0
  "Node-clock time (GET-NODE-TIME) of the last successful periodic flush. Used
   by the time-based trigger.

   Mockable on purpose: Core reads NodeClock::now() for the PERIODIC flush
   decision (validation.cpp:2759,2765) and SteadyClock only for the durations
   it logs (:2301,2382).")

(defun log-memory-snapshot (label)
  "Log a snapshot of the major in-memory caches plus SBCL heap usage.
Used to diagnose memory growth — call before/after flush so we can
correlate cache sizes with the heap watermark.

The May 5 OOM at h=72814 had heap at 8.55 GB but the explainable
state (UTXO 600MB + headers 30MB + sig-cache 5MB + queues 80MB) only
accounts for ~700 MB. This logger surfaces the gap."
  #+sbcl
  (let* ((utxo-count (and (node-utxo-set *node*)
                          (bl.store:utxo-count
                           (node-utxo-set *node*))))
         (coins-cache-mb (and (node-utxo-set *node*)
                              (/ (bl.store:view-mem-bytes
                                  (node-utxo-set *node*))
                                 1048576.0)))
         (header-count (and (node-chain-state *node*)
                            (hash-table-count
                             (bl.store::chain-state-block-index
                              (node-chain-state *node*)))))
         (sig-cache-count
           (+ (hash-table-count bl.interop:*signature-cache*)
              (hash-table-count bl.interop:*signature-cache-prev*)))
         (ibd-pending
           (and bl.net::*ibd-context*
                (hash-table-count
                 (bl.net::ibd-context-pending-blocks
                  bl.net::*ibd-context*))))
         (ibd-queue
           (and bl.net::*ibd-context*
                (hash-table-count
                 (bl.net::ibd-context-block-queue
                  bl.net::*ibd-context*))))
         (ibd-in-flight
           (and bl.net::*ibd-context*
                (hash-table-count
                 (bl.net::ibd-context-in-flight
                  bl.net::*ibd-context*))))
         (dyn-bytes (sb-ext:dynamic-space-size))
         (used-bytes (sb-kernel:dynamic-usage)))
    (log-info "MEM[~A]: utxo=~D coins-cache=~,1FMB headers=~D sigcache=~D ibd-pend=~A queue=~A inflight=~A heap-used=~,1FMB heap-cap=~,1FMB"
              label utxo-count coins-cache-mb header-count sig-cache-count
              ibd-pending ibd-queue ibd-in-flight
              (/ used-bytes 1048576.0) (/ dyn-bytes 1048576.0))))

(defvar *flush-mid-commit-hook* nil
  "When non-NIL, funcalled with the chainstate between Phase 1 (in-transition
marker written) and Phase 2 (coins flush) of %flush-chainstate — inside the
window where a crash must be detected at the next startup. Production leaves
it NIL; crash-safety tests bind it to observe the on-disk marker or abort
(via THROW) to simulate a crash at the most dangerous point.")

(defun %flush-chainstate (chainstate &key (label "Periodic") force-full-header-index)
  "Synchronously flush one CHAINSTATE (its state file, its coins view, and
the shared header index) with 3-phase commit (mirrors Bitcoin Core's
DB_HEAD_BLOCKS marker pattern in txdb.cpp::CCoinsViewDB::BatchWrite).
Each chainstate flushes its own storage-suffix-named files, so flushing one
can never mark another's state file in-transition. Per-flush-CYCLE concerns
(trigger counter resets, the post-flush GC, memory snapshots) live in the
callers — this is strictly the per-chainstate mechanism. LABEL names the
flush in log lines (\"Periodic\", \"Shutdown\", \"Reindex\").

  Phase 1: save-state with in-transition=1 — chainstate.dat marked unsafe.
           If we crash anywhere from here through Phase 3, on restart
           load-state returns :inconsistent and the caller refuses to
           start (must re-sync).
  Phase 2: save-utxo-set — the slow 90-MB write. Uses temp + fsync +
           rename internally so the file itself is atomic, but it might
           be old-or-new depending on whether the rename completed.
  Phase 3: save-state with in-transition=0 — commits the new chainstate.

The previous non-atomic flush ordered chainstate-then-utxo. If
interrupted between, on-disk best-height was ahead of the saved UTXO
entries, which then cascaded into MISSING-INPUT validation failures on
restart (observed at testnet4 h=70541 — block 70514 tx-2's outputs
were nowhere in utxoset.dat despite chainstate showing h=70540)."
  ;; Free-disk-space gate (Core FlushStateToDisk's CheckDiskSpace calls,
  ;; validation.cpp:2775/2808): refuse to start a flush the disk cannot
  ;; absorb, and request shutdown like Core's FatalError.
  (when (and chainstate *node* (node-data-directory *node*)
             (not (check-disk-space (node-data-directory *node*))))
    (%abort-on-low-disk-space label)
    (return-from %flush-chainstate nil))
  (handler-case
      (#+sbcl sb-sys:without-interrupts
       #-sbcl progn
        ;; Phase 1: mark the chainstate as in-transition.
        (when chainstate
          (bl.store:save-state chainstate :in-transition t)
          ;; A shutdown writes the FULL header index rather than a delta: it
          ;; is the one moment we can guarantee the on-disk snapshot matches
          ;; memory exactly, which bounds any drift the packed change-detector
          ;; could not see (a replaced header object on an existing entry).
          (bl.store:save-header-index
           chainstate :force-full force-full-header-index))
        (when *flush-mid-commit-hook*
          (funcall *flush-mid-commit-hook* chainstate))
        ;; Phase 2: flush cache → LevelDB. Per-flush work is proportional
        ;; to dirty entries (typically a few thousand at the tip), not
        ;; the full ~17M-entry set — replaces the ~13s utxoset.dat
        ;; rewrite that previously froze the sync thread.
        (let ((view (and chainstate
                         (bl.store:chain-state-coins-view chainstate))))
          (when (typep view 'bl.store:coins-view-cache)
            ;; :sync t fdatasyncs the LevelDB writebatch before we proceed, so a
            ;; power loss after Phase 3 clears the marker cannot leave the coins
            ;; un-durable while chainstate.dat says they are committed. (Was
            ;; :sync nil — atomic but not durable; the shutdown flush already
            ;; syncs, the periodic one now matches it.)
            ;; The coins DB is stamped with the block THESE COINS correspond to,
            ;; inside the same batch. The cache tracks that itself (moved by
            ;; block apply/disconnect, as Core does in Connect/DisconnectBlock),
            ;; so we deliberately do NOT pass the chain's tip here: during a
            ;; reorg's disconnect phase the tip still names the block being
            ;; rewound away from, and stamping it would record a hash the coins
            ;; no longer match. chainstate.dat (Phase 3 below) remains a second
            ;; record of the tip; startup compares the two.
            (bl.store:coins-view-cache-flush view :sync t)))
        ;; Phase 3: commit by re-saving chainstate without the marker.
        (when chainstate
          (bl.store:save-state chainstate :in-transition nil))
        (log-info "~A flush: chainstate~@[~A~] at height ~D"
                  label
                  (let ((suffix (and chainstate
                                     (bl.store:chain-state-storage-suffix
                                      chainstate))))
                    (and suffix (plusp (length suffix)) suffix))
                  (and chainstate
                       (bl.store:current-height chainstate))))
    (error (c)
      ;; Was log-warn before — surfaced silently. Bumped to log-error so
      ;; persistence failures are obvious in the log instead of getting
      ;; lost between progress lines.
      (log-error "~A flush FAILED: ~A" label c)
      ;; And now FATAL, as it is in Core: FlushStateToDisk wraps its writes in
      ;; a try/catch whose handler is `AbortNode(state, ...)`
      ;; (validation.cpp:2698, 2775-2777), because a node that keeps connecting
      ;; blocks after a failed flush is advancing a chain whose coins are not
      ;; on disk — and the loss is only discovered by the NEXT crash, as a
      ;; chainstate ahead of its UTXO entries. That exact cascade is what
      ;; testnet4 h=70541 was; logging it and carrying on is how it stayed
      ;; invisible until restart.
      (%abort-on-flush-failure label c)
      nil)))

(defun do-flush (&optional (chainstate (and *node* (node-current-chainstate *node*))))
  "Flush CHAINSTATE (default: the node's current chainstate) and run the
per-cycle bookkeeping: reset the periodic-flush triggers, request a major GC
so reachable post-flush memory is the only thing in the old generations next
time we measure (the same pattern as Bitcoin Core's CCoinsViewCache::Flush
returning bytes freed to the system allocator), and log memory snapshots."
  (log-memory-snapshot "pre-flush")
  (%flush-chainstate chainstate)
  (setf *last-flush-universal-time* (bl.ser:get-node-time)
        *blocks-since-flush* 0)
  #+sbcl (sb-ext:gc :full t)
  (log-memory-snapshot "post-flush"))

(defun maybe-periodic-flush (&optional chainstate)
  "Flush chainstates (state file, coins view, and the header index) to disk
if either:
- N blocks have been connected since the last flush, OR
- N seconds have elapsed since the last flush (catches slow-sync regions
  where 1000 blocks would take many minutes to accumulate).

Called from connect-block, which passes the chainstate the block connected
to; defaults to the node's current chainstate. The size trigger checks the
connecting chainstate's own coins cache; once ANY trigger fires, EVERY
chainstate is flushed — with an assumeutxo background sync two chainstates
connect blocks concurrently but the global time/count triggers reset on any
flush, so flushing only the triggering one would let the other's dirty
coins and redo window grow unboundedly. Flushing a clean chainstate is
cheap (work is proportional to dirty entries). Cheap if no flush needed;
durable if it does flush (atomic temp+fsync+rename inside save-*)."
  (unless *node* (return-from maybe-periodic-flush))
  (let* ((cs (or chainstate (node-current-chainstate *node*)))
         (view (and cs (bl.store:chain-state-coins-view cs))))
    (incf *blocks-since-flush*)
    (when (zerop *last-flush-universal-time*)
      (setf *last-flush-universal-time* (bl.ser:get-node-time)))
    (when (or (>= *blocks-since-flush* +flush-every-n-blocks+)
              (>= (- (bl.ser:get-node-time) *last-flush-universal-time*)
                  +flush-every-n-seconds+)
              ;; Size trigger (Bitcoin Core dbcache): flush once the coins cache
              ;; reaches its memory budget, so it can't grow unbounded between the
              ;; block-count / time flushes. The budget is per-chainstate while an
              ;; assumeutxo background sync splits it (maybe-rebalance-caches).
              (and view
                   (>= (bl.store:view-mem-bytes view)
                       (large-coins-cache-threshold
                        (chainstate-coins-cache-budget cs)))))
      ;; Triggering chainstate first (its cache may be the urgent one),
      ;; then the rest. Per-cycle bookkeeping (trigger resets, ONE major
      ;; GC, memory snapshots) runs once around the whole pass — not per
      ;; chainstate, which would double the stop-the-world GC pauses
      ;; during an assumeutxo background sync.
      (log-memory-snapshot "pre-flush")
      (%flush-chainstate cs)
      (dolist (other (node-chainstates *node*))
        (unless (eq other cs)
          (%flush-chainstate other)))
      (setf *last-flush-universal-time* (bl.ser:get-node-time)
            *blocks-since-flush* 0)
      #+sbcl (sb-ext:gc :full t)
      (log-memory-snapshot "post-flush"))))
