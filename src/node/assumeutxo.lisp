(in-package #:bitcoin-lisp)

;;; --- Assumeutxo snapshot chainstate lifecycle ------------------------------
;;;
;;; Core model (validation.cpp ActivateSnapshot/AddChainstate + node/
;;; chainstate.cpp LoadChainstate): a verified snapshot becomes a SECOND
;;; chainstate with storage suffix "_snapshot", status :unvalidated (never
;;; persisted — re-derived every startup), sharing the block index / block
;;; store / undo storage with the primary. The primary is retargeted at the
;;; snapshot base and becomes the HISTORICAL chainstate, re-deriving history
;;; in the background while the snapshot chainstate follows the network tip.
;;; The only persistent marker is chainstate_snapshot/base_blockhash.
;;;
;;; The streaming/verification half of activation (Core
;;; PopulateAndValidateSnapshot) lives with the loadtxoutset RPC
;;; (rpc/blockchain.lisp), which parses the snapshot format; the chainstate
;;; mechanics live here.

(defun call-with-sync-paused (node thunk)
  "Run THUNK with the sync thread's IBD loops paused — the coarse equivalent
of Core holding cs_main across snapshot activation. Requests an IBD stop,
waits (bounded) for the in-progress sync-blockchain pass to unwind, runs
THUNK, then clears the stop request so the next sync cycle resumes against
the (possibly changed) chainstate arrangement. A no-op without a live sync
thread (tests, :sync nil nodes)."
  (if (and (node-sync-thread node)
           (bt:thread-alive-p (node-sync-thread node)))
      (progn
        (bl.net:request-ibd-stop)
        (loop repeat 600                ; <= 120s; the IBD loops poll the flag
              while (node-syncing node)
              do (sleep 0.2))
        (when (node-syncing node)
          (log-warn "Sync pass did not pause within 120s; proceeding with snapshot activation anyway"))
        (unwind-protect (funcall thunk)
          (bl.net:reset-ibd-stop)))
      (funcall thunk)))

(defun %make-snapshot-chainstate (node base-hash)
  "The snapshot chain-state struct for BASE-HASH: status :unvalidated (Core
derives it from from_snapshot_blockhash, validation.cpp:1868 — never
persisted), storage suffix \"_snapshot\", and the block index SHARED with
the primary chainstate (Core keeps it in m_blockman, outside any
chainstate). Used by both activation (create-snapshot-chainstate) and
startup re-detection (load-snapshot-chainstate)."
  (let ((primary (node-current-chainstate node)))
    (bl.store:make-chain-state
     :base-path (node-data-directory node)
     :genesis-hash (bl.store:chain-state-genesis-hash primary)
     :block-index (bl.store:chain-state-block-index primary)
     :from-snapshot-blockhash (copy-seq base-hash)
     :assumeutxo-status :unvalidated
     :storage-suffix "_snapshot")))

(defun create-snapshot-chainstate (node base-hash)
  "Construct an :unvalidated snapshot chainstate for BASE-HASH with a fresh
coins LevelDB at <data-dir>/chainstate_snapshot/ (Core ActivateSnapshot's
Chainstate construction + InitCoinsDB). Stale on-disk leftovers from an
aborted or unadoptable earlier activation are removed first — startup
adopts any intact snapshot chainstate, so anything still here is refuse.
The caller owns cleanup on failure (abort-snapshot-chainstate)."
  (let ((snap (%make-snapshot-chainstate node base-hash)))
    (when (bl.store:find-assumeutxo-chainstate-dir
           (node-data-directory node))
      (log-warn "[snapshot] removing stale snapshot chainstate leftovers before activation")
      (bl.store:delete-snapshot-chainstate-files
       (node-data-directory node)))
    (bl.store:open-chainstate-coins-view snap)
    snap))

(defun abort-snapshot-chainstate (node snap)
  "Tear down SNAP mid-activation (Core cleanup_bad_snapshot): close its coins
DB (releasing the LevelDB lock) and delete its on-disk footprint. Never
signals — this runs on the activation failure path."
  ;; Core's cleanup_bad_snapshot rebalances first (validation.cpp:5697) —
  ;; the failed activation must not leave a split cache allocation behind.
  (ignore-errors (maybe-rebalance-caches node))
  (bl.store:close-chainstate-coins-view snap)
  (ignore-errors
    (bl.store:delete-snapshot-chainstate-files
     (node-data-directory node)))
  nil)

(defun add-snapshot-chainstate (node snap)
  "Adopt a populated, verified snapshot chainstate (Core AddChainstate,
validation.cpp:6189-6206): retarget the previously-current chainstate at the
snapshot base — making it the historical chainstate — and append SNAP, which
select-current-chainstate then returns as the new current chainstate.

The mempool needs no explicit hand-off (Core swaps the pointer): ours lives
on the node and every mempool call site reads the CURRENT chainstate's coins
view, which this swap redirects. Callers must have verified the mempool is
empty first (Core asserts it). Core's PopulateBlockIndexCandidates has no
equivalent here — our fork choice is per-block (activate-block) and the
historical chainstate's candidate filtering is the target guard there."
  (let* ((prev (node-current-chainstate node))
         (base-hash (bl.store:chain-state-from-snapshot-blockhash snap))
         (base-entry (bl.store:get-block-index-entry prev base-hash)))
    (assert (eq (bl.store:chain-state-assumeutxo-status prev) :validated))
    (assert (null (bl.store:chain-state-target-blockhash prev)))
    (assert base-entry)
    (bl.store:set-chainstate-target prev base-entry)
    (bt:with-recursive-lock-held ((node-lock node))
      (setf (node-chainstates node)
            (append (node-chainstates node) (list snap))))
    ;; Split the coins-cache budget across the two chainstates (Core calls
    ;; MaybeRebalanceCaches at the end of ActivateSnapshot,
    ;; validation.cpp:5745).
    (maybe-rebalance-caches node)
    (log-info "[snapshot] successfully activated snapshot ~A: current chainstate now at height ~D following the network tip; historical chainstate (h=~D) re-derives history toward the base in the background"
              (bl.crypto:bytes-to-hex base-hash)
              (bl.store:current-height snap)
              (bl.store:current-height prev))
    snap))

(defun load-snapshot-chainstate (node)
  "Detect and re-adopt a persisted snapshot chainstate at startup (Core
LoadAssumeutxoChainstate, validation.cpp:6170-6187, in node/chainstate.cpp
LoadChainstate ordering). The chainstate_snapshot/ dir plus its
base_blockhash marker are the only persistent evidence; assumeutxo-status is
re-derived as :unvalidated (never persisted). Must run after the primary
chainstate's header index is loaded — the base entry has to resolve — and
before crash-recovery resolution (a torn snapshot flush joins
*pending-chainstate-recovery*). Returns the snapshot chainstate or NIL."
  (let* ((data-dir (node-data-directory node))
         (dir (bl.store:find-assumeutxo-chainstate-dir data-dir)))
    (when dir
      (let* ((base-hash (bl.store:read-snapshot-base-blockhash dir))
             (primary (node-current-chainstate node))
             (base-entry (and base-hash
                              (bl.store:get-block-index-entry
                               primary base-hash))))
        (cond
          ((null base-hash)
           (log-warn "[snapshot] snapshot chainstate dir is malformed! no base blockhash file exists at path ~A. Try deleting ~A and calling loadtxoutset again"
                     (namestring (bl.store:snapshot-base-blockhash-path dir))
                     (namestring dir))
           nil)
          ((null base-entry)
           ;; Header index lost/regressed below the base. Leave the snapshot
           ;; chainstate on disk and run single-chainstate this boot; once
           ;; headers re-cover the base, the next restart adopts it.
           (log-warn "[snapshot] snapshot base block ~A is not in the header index; not loading the snapshot chainstate this run"
                     (bl.crypto:bytes-to-hex base-hash))
           nil)
          (t
           (log-info "[snapshot] detected active snapshot chainstate (~A) - loading"
                     (namestring dir))
           (let ((snap (%make-snapshot-chainstate node base-hash))
                 (base-height (bl.store:block-index-entry-height base-entry)))
             ;; Tip from chainstate_snapshot.dat; a torn flush defers to the
             ;; per-chainstate recovery pass; a missing .dat means activation
             ;; completed (dir + marker prove the populate did) but the first
             ;; save-state never landed — start the chainstate at its base.
             (case (bl.store:load-state snap)
               ((:inconsistent)
                (log-warn "[snapshot] snapshot chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
                (push snap *pending-chainstate-recovery*))
               ((t) nil)
               ((nil)
                (log-warn "[snapshot] no chainstate_snapshot.dat; starting the snapshot chainstate at its base (h=~D)" base-height)
                (bl.store:update-chain-tip
                 snap (copy-seq base-hash) base-height)))
             ;; The recorded tip must resolve in the shared header index;
             ;; otherwise fall back to the base (blocks above it re-sync).
             (let ((tip-hash (bl.store:best-block-hash snap)))
               (unless (and tip-hash
                            (bl.store:get-block-index-entry primary tip-hash))
                 (log-warn "[snapshot] snapshot chainstate tip not in the header index; resetting to the base (h=~D)" base-height)
                 (bl.store:update-chain-tip
                  snap (copy-seq base-hash) base-height)))
             ;; Open its coins DB (chainstate_snapshot/).
             (bl.store:open-chainstate-coins-view snap)
             ;; Retarget the primary (it becomes the historical chainstate)
             ;; and adopt the snapshot chainstate as current.
             (bl.store:set-chainstate-target primary base-entry)
             (setf (node-chainstates node)
                   (append (node-chainstates node) (list snap)))
             ;; Split the coins-cache budget across the re-adopted pair (Core
             ;; LoadChainstate's MaybeRebalanceCaches, node/chainstate.cpp:146).
             (maybe-rebalance-caches node)
             (log-info "[snapshot] switching active chainstate to the snapshot chainstate (tip h=~D); historical chainstate at h=~D targets the base at h=~D"
                       (bl.store:current-height snap)
                       (bl.store:current-height primary)
                       base-height)
             snap)))))))

;;;; --- Assumeutxo P5: background-validation completion + promotion --------
;;;;
;;;; When the historical (validated-from-genesis) chainstate finishes
;;;; re-deriving history up to the snapshot base, its UTXO set must reproduce
;;;; the committed hash_serialized_3 exactly. maybe-validate-snapshot re-hashes
;;;; it and, on a match, promotes the snapshot chainstate to VALIDATED (Core
;;;; ChainstateManager::MaybeValidateSnapshot, validation.cpp:5986-6096); on a
;;;; mismatch it marks the snapshot INVALID, renames its dir aside for
;;;; forensics, and fires a fatal shutdown. A mid-run success keeps both
;;;; chainstates running until the next restart, when
;;;; validated-snapshot-cleanup swaps the LevelDB dirs so the snapshot
;;;; chainstate becomes the sole chainstate (Core ValidatedSnapshotCleanup,
;;;; validation.cpp:6299-6364). Assumeutxo status is never persisted, so it is
;;;; re-proven by re-hashing on every startup.

(defun %node-snapshot-chainstate (node)
  "The node's snapshot-derived chainstate (the one carrying a
from-snapshot-blockhash), regardless of its assumeutxo status, or NIL."
  (find-if #'bl.store:chain-state-from-snapshot-blockhash
           (node-chainstates node)))

(defun %default-snapshot-fatal (message)
  "Production reaction to a snapshot that failed background validation (Core
GetNotifications().fatalError): log the error and request node shutdown. The
invalid snapshot chainstate dir was already renamed aside for forensics; on
the next restart the node resumes normal IBD from the validated chain. Runs
on the sync thread, so it flips node-running (letting the loops wind
themselves down) and REQUESTS the shutdown rather than joining threads via
stop-node itself — the main thread runs the teardown, and the restart-worthy
exit code tells the supervisor to respawn."
  (log-error "[snapshot] !!! ~A" message)
  (log-error "[snapshot] the node will shut down and stop using any state built on the snapshot")
  (when *node*
    (setf (node-running *node*) nil)
    (request-node-shutdown "assumeutxo snapshot failed background validation"
                           :exit-code +node-exit-watchdog+)))

(defvar *snapshot-fatal-hook* '%default-snapshot-fatal
  "Funcalled with a message string when an assumeutxo snapshot fails
background validation mid-run. Production shuts the node down; tests rebind
it to record the fatal DECISION without exiting the image.")

(defun %snapshot-validation-preconditions-p (node historical snap)
  "T iff HISTORICAL is a validated-from-genesis chainstate that has reached
the snapshot base SNAP was built from — the point at which the snapshot can
be validated (Core MaybeValidateSnapshot's guard, validation.cpp:5990-6003).
A no-op-guarding predicate: false in every arrangement other than a
background sync that has just landed on its target."
  (and node snap historical
       (member historical (node-chainstates node))
       (bl.store:chain-state-from-snapshot-blockhash snap)
       (eq (bl.store:chain-state-assumeutxo-status snap) :unvalidated)
       (eq (bl.store:chain-state-assumeutxo-status historical) :validated)
       (bl.store:best-block-hash historical)
       (bl.store:chain-state-target-blockhash historical)
       (equalp (bl.store:chain-state-target-blockhash historical)
               (bl.store:chain-state-from-snapshot-blockhash snap))
       ;; ReachedTarget: the historical tip IS the target/base block.
       (equalp (bl.store:best-block-hash historical)
               (bl.store:chain-state-target-blockhash historical))))

(defun %mark-snapshot-invalid (node historical snap)
  "State mutation Core performs when a snapshot fails validation
(MaybeValidateSnapshot's handle_invalid_snapshot + InvalidateCoinsDBOnDisk,
validation.cpp:6026-6036): reset the historical chainstate's target back to
the network tip, mark the snapshot chainstate :invalid, close its coins DB and
rename its dir aside for forensics. No process shutdown here — the caller
drives that."
  (bl.store:set-chainstate-target historical nil)
  (setf (bl.store:chain-state-assumeutxo-status snap) :invalid)
  (bl.store:close-chainstate-coins-view snap)
  (ignore-errors
    (bl.store:rename-snapshot-chainstate-dir-invalid
     (node-data-directory node))))

(defun %validate-snapshot-against-commitment (node historical snap)
  "The core of Core's MaybeValidateSnapshot (validation.cpp:6039-6095), minus
the shutdown/cleanup reactions the callers own. Flush HISTORICAL, hash its
coins DB, and compare to the chainparams commitment for the snapshot base.

MATCH -> SNAP becomes :validated and HISTORICAL records its target-utxohash,
         so select-historical-chainstate stops returning it (the background
         work is done). Returns (values :success NIL).
MISMATCH / no chainparams entry -> %mark-snapshot-invalid, and returns
         (values :hash-mismatch MESSAGE) or (values :missing-chainparams MESSAGE)."
  ;; Core holds cs_main so the historical chainstate can't advance during
  ;; hashing; our caller runs on the single sync/startup thread, so it is
  ;; likewise frozen. Flush it first (Core ForceFlushStateToDisk) — this also
  ;; persists the historical's final tip so a crash right after validation
  ;; doesn't lose it.
  (%flush-chainstate historical)
  (let* ((base-hash (bl.store:chain-state-target-blockhash historical))
         (au (assumeutxo-data-for-blockhash (node-network node) base-hash)))
    (cond
      ((null au)
       (let ((msg (format nil "assumeutxo data not found for the snapshot base at height ~D — refusing to validate snapshot"
                          (bl.store:current-height historical))))
         (log-warn "[snapshot] ~A" msg)
         (%mark-snapshot-invalid node historical snap)
         (values :missing-chainparams msg)))
      (t
       (log-info "[snapshot] computing UTXO stats for the background chainstate to validate the snapshot — this may take a few minutes")
       (let ((got (bl.store:compute-utxo-set-hash
                   (bl.store:chain-state-coins-view historical)))
             (want (assumeutxo-data-hash-serialized au)))
         (cond
           ((equalp got want)
            (setf (bl.store:chain-state-assumeutxo-status snap) :validated
                  (bl.store:chain-state-target-utxohash historical) got)
            ;; VALIDATED lifts the snapshot chainstate's prune floor (Core: a
            ;; validated chainstate's GetPruneRange starts at 0 again); the
            ;; prune-walk cursor rewinds so the window the floor protected
            ;; becomes reclaimable.
            (bl.store:lift-prune-floor-on-promotion snap historical)
            ;; Core rebalances the caches immediately after promotion
            ;; (validation.cpp:6093): everything to the snapshot chainstate.
            (maybe-rebalance-caches node)
            (log-info "[snapshot] snapshot beginning at ~A has been fully validated"
                      (bl.crypto:bytes-to-hex
                       (bl.store:chain-state-from-snapshot-blockhash snap)))
            (values :success nil))
           (t
            (let ((msg (format nil "failed to validate the -assumeutxo snapshot state: hash mismatch (computed ~A, expected ~A)"
                               (bl.crypto:bytes-to-hex got)
                               (bl.crypto:bytes-to-hex want))))
              (log-error "[snapshot] ~A" msg)
              (%mark-snapshot-invalid node historical snap)
              (values :hash-mismatch msg)))))))))

(defun maybe-validate-snapshot (historical)
  "Connect-tip hook (Core MaybeValidateSnapshot at ConnectTip,
validation.cpp:3134-3135): when HISTORICAL — a background-validation
chainstate — reaches its snapshot base, re-hash its coins DB against the
chainparams commitment. On a match, the snapshot chainstate becomes the
node's validated chainstate (services regain NODE_NETWORK once no historical
chainstate remains, and getchainstates/validated-chainstate reflect it, all
via the select-* accessors) and the indexes rebind onto it (Core
init.cpp:1367-1383); the on-disk dir swap waits for the next restart. On a
mismatch the snapshot dir is renamed aside and the fatal hook is fired (Core
fatalError). Returns a SnapshotCompletionResult-style keyword; :skipped when
the preconditions aren't met (the common per-connect case), so it is safe to
call for any chainstate."
  (let* ((node *node*)
         (snap (and node (%node-snapshot-chainstate node))))
    (if (not (%snapshot-validation-preconditions-p node historical snap))
        :skipped
        (multiple-value-bind (result message)
            (%validate-snapshot-against-commitment node historical snap)
          (case result
            (:success
             (restart-indexes-for-validated-chainstate node)
             (log-info "[snapshot] promotion complete: the current chainstate (h=~D) is now fully validated; the background chainstate directories are consolidated on the next restart"
                       (bl.store:current-height
                        (node-current-chainstate node)))
             :success)
            (t
             (funcall *snapshot-fatal-hook* message)
             result))))))

(defun finalize-snapshot-validation-at-startup (node)
  "Startup completion + cleanup (Core LoadChainstate's MaybeValidateSnapshot +
ValidatedSnapshotCleanup, node/chainstate.cpp:196-235). If a persisted
historical chainstate has already reached the snapshot base (its background
sync completed on a previous run), re-prove the commitment hash: on success,
swap the LevelDB dirs so the snapshot chainstate becomes the sole
fully-validated chainstate (validated-snapshot-cleanup) — Core does this
shuffle on restart, not mid-run, because moving LevelDB dirs at runtime is
risky; on failure, abort startup (Core FAILURE_FATAL). Returns the result
keyword, or :skipped when there is nothing to finalize."
  (let ((historical (node-historical-chainstate node))
        (snap (%node-snapshot-chainstate node)))
    (if (not (%snapshot-validation-preconditions-p node historical snap))
        :skipped
        (multiple-value-bind (result message)
            (%validate-snapshot-against-commitment node historical snap)
          (case result
            (:success
             (validated-snapshot-cleanup node)
             :success)
            (t
             (init-error "Unable to complete -assumeutxo snapshot validation: ~A. ~
Restart to resume normal initial block download, or load a different snapshot."
                    message)))))))

(defun validated-snapshot-cleanup (node)
  "Startup-only LevelDB-dir consolidation after a snapshot was fully validated
on a previous run (Core ChainstateManager::ValidatedSnapshotCleanup,
validation.cpp:6299-6364): close every chainstate's coins DB, move the
snapshot chainstate's files into the default chainstate names (deleting the
now-unneeded background chainstate), and re-init the node with a single
fully-validated chainstate. Returns T when it swapped, NIL when there was
nothing to do."
  (let ((snap (%node-snapshot-chainstate node)))
    (unless (and snap (eq (bl.store:chain-state-assumeutxo-status snap)
                          :validated))
      (return-from validated-snapshot-cleanup nil))
    ;; ResetChainstates: release every coins DB handle before shuffling dirs.
    (dolist (cs (node-chainstates node))
      (bl.store:close-chainstate-coins-view cs))
    ;; Swap chainstate_snapshot/ into chainstate/ and delete the background one.
    (bl.store:promote-snapshot-chainstate-files (node-data-directory node))
    ;; Morph the snapshot chainstate struct into the sole primary chainstate:
    ;; drop its snapshot identity (default file names, no target/snapshot
    ;; marking) and reopen its coins view over the now-promoted chainstate/
    ;; LevelDB. Its shared block index and its (snapshot-tip) chain carry over
    ;; intact, so no block re-download is needed.
    (bl.store:clear-snapshot-chainstate-identity snap)
    (bl.store:open-chainstate-coins-view snap)
    (setf (node-chainstates node) (list snap))
    (log-info "[snapshot] background chainstate consolidated; running as a single fully-validated chainstate at height ~D"
              (bl.store:current-height snap))
    t))
