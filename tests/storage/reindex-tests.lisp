(in-package #:bitcoin-lisp.tests)

;;;; -reindex-chainstate tests.
;;;;
;;;; do-reindex-chainstate rebuilds the UTXO set from stored blocks. The
;;;; load-bearing check: after polluting/corrupting the coins view, a reindex
;;;; restores it exactly (same whole-set MuHash, same tip), and it uses a
;;;; coins-view-cache like the live node (the wipe + flush are cache-specific).

(def-suite :reindex-tests
  :description "-reindex-chainstate UTXO rebuild"
  :in :bitcoin-lisp-tests)

(in-suite :reindex-tests)

(defun %reindex-node-fixture (tag)
  "(values node coins-db-path) — a regtest node whose UTXO set is a
LevelDB-backed coins-view-cache (matching the live node), with undo storage
initialized so mining can connect blocks."
  (let* ((node (regtest-node-fixture tag))
         (base (merge-pathnames (format nil "test-reindex-~A/" tag)
                                (uiop:temporary-directory)))
         (cspath (namestring (merge-pathnames "chainstate/" base)))
         (undopath (merge-pathnames "undo/" base)))
    (ensure-directories-exist cspath)
    (ensure-directories-exist undopath)
    (setf (bl:node-utxo-set node)
          (bl.store:make-coins-view-cache
           (bl.store:open-coins-view-db cspath)))
    (bl.val:initialize-undo-storage undopath)
    (values node cspath)))

(test reindex-chainstate-rebuilds-utxo-set
  "Mining builds a UTXO set; polluting the coins view then reindexing restores
the exact set (same whole-set MuHash) and the same chain tip."
  (with-network (:regtest)
   (let* ((tag (format nil "rbld~D" (get-internal-real-time)))
          (node (%reindex-node-fixture tag)))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 8)
       (let* ((cs (bl:node-chain-state node))
              (utxo (bl:node-utxo-set node))
              (tip (bl.store:current-height cs))
              ;; Truth: the correct set after mining.
              (truth-muhash (bl.store:compute-utxo-set-muhash utxo))
              (truth-amount (bl.store:utxo-set-total-amount utxo)))
         (is (= 8 tip))
         ;; Pollute the coins view with a coin that was never created on-chain.
         (bl.store:add-utxo
          utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99)
          0 424242 (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51) 1)
         (is (not (equalp truth-muhash
                          (bl.store:compute-utxo-set-muhash utxo))))
         ;; Reindex rebuilds from the stored blocks.
         (bl::do-reindex-chainstate)
         ;; Tip preserved, and the set matches the pre-pollution truth exactly.
         (is (= tip (bl.store:current-height cs)))
         (is (equalp truth-muhash
                     (bl.store:compute-utxo-set-muhash utxo)))
         (is (= truth-amount (bl.store:utxo-set-total-amount utxo)))
         ;; And no unspendable outputs snuck in (the coinbase witness-commitment
         ;; OP_RETURN is dropped, as during normal apply).
         (let ((unspendable 0))
           (bl.store:utxo-set-iterate
            utxo (lambda (txid vout entry)
                   (declare (ignore txid vout))
                   (when (bl.store:script-unspendable-p
                          (bl.store:utxo-entry-script-pubkey entry))
                     (incf unspendable))))
           (is (zerop unspendable)))
         ;; The on-disk chainstate.dat was committed clean by the final
         ;; 3-phase flush (the marker set during the rebuild is cleared).
         (let ((reload (bl.store:make-chain-state
                        :base-path (bl.store::chain-state-base-path cs))))
           (is (eq t (bl.store:load-state reload)))
           (is (= tip (bl.store:current-height reload)))))))))

(test reindex-chainstate-recovers-emptied-coins-view
  "Reindex rebuilds even from a fully-emptied coins view (disaster recovery:
blocks + index intact, chainstate DB wiped)."
  (with-network (:regtest)
   (let* ((tag (format nil "recov~D" (get-internal-real-time)))
          (node (%reindex-node-fixture tag)))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 5)
       (let* ((utxo (bl:node-utxo-set node))
              (truth (bl.store:compute-utxo-set-muhash utxo)))
         ;; Nuke the coins view entirely, then reindex.
         (bl.store:coins-view-cache-wipe utxo)
         (bl::do-reindex-chainstate)
         (is (equalp truth (bl.store:compute-utxo-set-muhash utxo))))))))

;;;; Crash safety. do-reindex-chainstate rewinds chainstate.dat to genesis
;;;; WITH the in-transition marker before wiping the coins DB, and every
;;;; replay flush goes through the 3-phase commit -- so a crash at ANY point
;;;; of the rebuild is detected at load-state (:inconsistent) and routed to
;;;; recover-inconsistent-chainstate, instead of the old behavior (the clean
;;;; pre-reindex chainstate.dat loading silently over a gutted coins DB).

(test reindex-crash-mid-replay-recovers
  "A crash inside a replay flush's unsafe window (marker written at the
replay height, coins batch not yet committed) is detected at load-state and
recovered to exactly the height the coins DB last committed."
  (with-network (:regtest)
   (let ((tag (format nil "crashr~D" (get-internal-real-time))))
     (multiple-value-bind (node cspath) (%reindex-node-fixture tag)
       (let ((bl:*node* node))
         (generate-regtest-blocks node 8)
         (let* ((cs (bl:node-chain-state node))
                (flushes 0)
                ;; Budget 0 => size trigger after EVERY replayed block, so
                ;; flush N happens right after block N is applied. The 3rd
                ;; flush dies in the marker window: on disk the marker is at
                ;; h=3 while the coins DB committed through h=2.
                (bl::*coins-cache-budget-bytes* 0)
                (bl::*flush-mid-commit-hook*
                  (lambda (flushing)
                    (declare (ignore flushing))
                    (when (= (incf flushes) 3)
                      (throw 'reindex-crash :crashed)))))
           (is (eq :crashed (catch 'reindex-crash
                              (bl::do-reindex-chainstate)
                              :completed))))
         ;; Simulate the process death: drop the in-memory cache and reload
         ;; both the on-disk LevelDB and chainstate.dat, as startup would.
         (let ((cs (bl:node-chain-state node)))
           (bl.store:close-chainstate-coins-view cs)
           (setf (bl:node-utxo-set node)
                 (bl.store:make-coins-view-cache
                  (bl.store:open-coins-view-db cspath)))
           (is (eq :inconsistent (bl.store:load-state cs)))
           (is (= 3 (bl.store:current-height cs)))
           (is (eq t (bl::recover-inconsistent-chainstate node cs)))
           ;; Rewound to the last committed replay flush: block 2.
           (is (= 2 (bl.store:current-height cs)))
           (let ((reload (bl.store:make-chain-state
                          :base-path (bl.store::chain-state-base-path cs))))
             (is (eq t (bl.store:load-state reload)))
             (is (= 2 (bl.store:current-height reload))))
           ;; And the coins DB is exactly the height-2 set: two 50-BTC
           ;; coinbases, nothing from block 3.
           (is (= 10000000000 (bl.store:utxo-set-total-amount
                               (bl:node-utxo-set node))))))))))

(test reindex-crash-mid-wipe-recovers-to-genesis
  "A crash between the genesis+marker rewind and the first replay flush
(e.g. mid-wipe, when the coins DB holds arbitrary leftovers of the old set)
recovers to a clean EMPTY set at genesis -- the leftovers are re-wiped, never
loaded as live state."
  (with-network (:regtest)
   (let* ((tag (format nil "crashw~D" (get-internal-real-time)))
          (node (%reindex-node-fixture tag)))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 5)
       (let* ((cs (bl:node-chain-state node))
              (utxo (bl:node-utxo-set node))
              (genesis (bl.store:chain-state-genesis-hash cs)))
         ;; Make the mined coins durable, then reproduce the crash state by
         ;; hand: tip rewound to genesis with the marker while the coins DB
         ;; still holds the old set (killed right before the wipe -- the
         ;; worst case: ALL old coins left behind as garbage).
         (bl.store:coins-view-cache-flush utxo :sync t)
         (bl.store:update-chain-tip cs genesis 0)
         (bl.store:save-state cs :in-transition t)
         (is (eq :inconsistent (bl.store:load-state cs)))
         (is (eq t (bl::recover-inconsistent-chainstate node cs)))
         ;; Clean at genesis over an EMPTY coins DB.
         (is (= 0 (bl.store:current-height cs)))
         (is (equalp genesis (bl.store:best-block-hash cs)))
         (is (= 0 (bl.store:utxo-set-total-amount utxo)))
         (let ((reload (bl.store:make-chain-state
                        :base-path (bl.store::chain-state-base-path cs))))
           (is (eq t (bl.store:load-state reload)))
           (is (= 0 (bl.store:current-height reload)))))))))

;;;; The interrupted reindex must not resurrect the pre-reindex tip.
;;;;
;;;; GA11 bbf6e679 (S1). The coins DB's best-block pointer used to survive the
;;;; reindex wipe (only 'C' keys were deleted), so after a crash between the
;;;; wipe and the first replay flush the node started at genesis with an empty
;;;; set -- correct -- and then RECONCILE-COINS-DB-BEST-BLOCK read the standing
;;;; pointer, placed it, moved chainstate.dat FORWARD to the pre-reindex tip and
;;;; logged "Recovered". Every UTXO-set answer was then an empty set at that
;;;; height, and the first competing fork marked the honest chain :invalid.
;;;; Core cannot reach it: -reindex-chainstate destroys the whole coins LevelDB
;;;; (node/chainstate.cpp:93, dbwrapper.cpp:39-41), DB_BEST_BLOCK lives inside
;;;; the coin batch (txdb.cpp:128,159), and is_coinsview_empty skips LoadChainTip
;;;; over an empty view (node/chainstate.cpp:69-70).

(test reindex-crash-before-first-flush-restarts-at-genesis
  "End to end through bl:start-node: mine, run the reindex prefix, die before
the first replay flush, restart with no flags. The node must come back AT
GENESIS with an empty UTXO set -- never at the pre-reindex tip."
  (let ((base (merge-pathnames (format nil "test-reindex-crash-~D/"
                                       (get-internal-real-time))
                               (uiop:temporary-directory))))
    (ensure-directories-exist base)
    (unwind-protect
         (progn
           ;; A chain on disk, committed by a clean shutdown.
           (bl.net:reset-ibd-stop)
           (bl:start-node :data-directory base :network :regtest :sync nil
                          :rpc-port nil :listen nil :console-log nil)
           (generate-regtest-blocks bl:*node* 8)
           (is (= 8 (bl.store:current-height (bl:node-chain-state bl:*node*))))
           (bl:stop-node)
           ;; Restart, then reproduce do-reindex-chainstate's prefix (rewind to
           ;; genesis with the marker, wipe) and die with nothing flushed --
           ;; exactly what a killed process leaves behind.
           (bl.net:reset-ibd-stop)
           (bl:start-node :data-directory base :network :regtest :sync nil
                          :rpc-port nil :listen nil :console-log nil)
           (let ((cs (bl:node-chain-state bl:*node*))
                 (utxo (bl:node-utxo-set bl:*node*)))
             (is (= 8 (bl.store:current-height cs)))
             (is (= 40000000000 (bl.store:utxo-set-total-amount utxo)))
             (bl.store:update-chain-tip
              cs (bl.store:chain-state-genesis-hash cs) 0)
             (bl.store:save-state cs :in-transition t)
             (bl.store:coins-view-cache-wipe utxo)
             ;; The emptied database names no block: that is the invariant.
             (is (null (bl.store:coins-view-db-best-block
                        (bl.store:coins-view-cache-base utxo))))
             (bl.store:close-chainstate-coins-view cs)
             (bl::unlock-data-directory)
             (setf bl:*node* nil))
           ;; Ordinary restart, no flags.
           (bl.net:reset-ibd-stop)
           (bl:start-node :data-directory base :network :regtest :sync nil
                          :rpc-port nil :listen nil :console-log nil)
           (let ((cs (bl:node-chain-state bl:*node*))
                 (utxo (bl:node-utxo-set bl:*node*)))
             (is (= 0 (bl.store:current-height cs))
                 "the node re-advanced onto the pre-reindex tip over an empty set")
             (is (equalp (bl.store:chain-state-genesis-hash cs)
                         (bl.store:best-block-hash cs)))
             (is (= 0 (bl.store:utxo-set-total-amount utxo)))
             (is (null (bl.store:coins-view-db-best-block
                        (bl.store:coins-view-cache-base utxo)))))
           (bl:stop-node))
      (progn
        (ignore-errors (when bl:*node* (bl:stop-node)))
        (bl.net:reset-ibd-stop)
        (ignore-errors (uiop:delete-directory-tree
                        base :validate t :if-does-not-exist :ignore))))))

(test reconcile-never-places-a-pointer-over-an-empty-utxo-set
  "A datadir an OLDER build left in the bad shape -- coins gone, pointer still
naming the old tip -- must not be reconciled toward. Core's is_coinsview_empty
(node/chainstate.cpp:69-70) skips LoadChainTip over an empty view; ours leaves
chainstate.dat where the recovery put it and says a rebuild is needed."
  (with-network (:regtest)
    (let* ((tag (format nil "recempty~D" (get-internal-real-time)))
           (node (%reindex-node-fixture tag)))
      (let ((bl:*node* node))
        (generate-regtest-blocks node 5)
        (let* ((cs (bl:node-chain-state node))
               (utxo (bl:node-utxo-set node))
               (tip (bl.store:best-block-hash cs)))
          (bl.store:coins-view-cache-flush utxo :sync t)
          ;; The pre-fix on-disk shape, rebuilt by hand: every coin gone, the
          ;; pointer re-stamped at the old tip, chainstate.dat still at genesis
          ;; where the interrupted-reindex recovery left it.
          (bl.store:coins-view-cache-wipe utxo)
          (bl.store:coins-view-cache-sync utxo :sync t :best-block tip)
          (is (equalp tip (bl.store:coins-view-db-best-block
                           (bl.store:coins-view-cache-base utxo))))
          (bl.store:update-chain-tip
           cs (bl.store:chain-state-genesis-hash cs) 0)
          (let ((bl::*chainstates-reset-to-genesis* '()))
            (is (eq :empty (bl::reconcile-coins-db-best-block node))))
          (is (= 0 (bl.store:current-height cs)))
          ;; And the ordering guard: a chainstate the interrupted-reindex
          ;; branch has just reset is skipped outright, whatever the pointer
          ;; says, so the later recovery cannot undo the earlier one.
          (let ((bl::*chainstates-reset-to-genesis* (list cs)))
            (is (eq :reset (bl::reconcile-coins-db-best-block node))))
          (is (= 0 (bl.store:current-height cs))))))))
