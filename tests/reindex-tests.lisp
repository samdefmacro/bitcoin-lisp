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
  (let* ((node (%regtest-node-fixture tag))
         (base (merge-pathnames (format nil "test-reindex-~A/" tag)
                                (uiop:temporary-directory)))
         (cspath (namestring (merge-pathnames "chainstate/" base)))
         (undopath (merge-pathnames "undo/" base)))
    (ensure-directories-exist cspath)
    (ensure-directories-exist undopath)
    (setf (bitcoin-lisp::node-utxo-set node)
          (bitcoin-lisp.storage:make-coins-view-cache
           (bitcoin-lisp.storage:open-coins-view-db cspath)))
    (bitcoin-lisp.validation:initialize-undo-storage undopath)
    (values node cspath)))

(test reindex-chainstate-rebuilds-utxo-set
  "Mining builds a UTXO set; polluting the coins view then reindexing restores
the exact set (same whole-set MuHash) and the same chain tip."
  (%with-regtest
   (let* ((tag (format nil "rbld~D" (get-internal-real-time)))
          (node (%reindex-node-fixture tag)))
     (let ((bitcoin-lisp::*node* node))
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 8 "raw(51)"))
       (let* ((cs (bitcoin-lisp::node-chain-state node))
              (utxo (bitcoin-lisp::node-utxo-set node))
              (tip (bitcoin-lisp.storage:current-height cs))
              ;; Truth: the correct set after mining.
              (truth-muhash (bitcoin-lisp.storage:compute-utxo-set-muhash utxo))
              (truth-amount (bitcoin-lisp.storage:utxo-set-total-amount utxo)))
         (is (= 8 tip))
         ;; Pollute the coins view with a coin that was never created on-chain.
         (bitcoin-lisp.storage:add-utxo
          utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99)
          0 424242 (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51) 1)
         (is (not (equalp truth-muhash
                          (bitcoin-lisp.storage:compute-utxo-set-muhash utxo))))
         ;; Reindex rebuilds from the stored blocks.
         (bitcoin-lisp::do-reindex-chainstate)
         ;; Tip preserved, and the set matches the pre-pollution truth exactly.
         (is (= tip (bitcoin-lisp.storage:current-height cs)))
         (is (equalp truth-muhash
                     (bitcoin-lisp.storage:compute-utxo-set-muhash utxo)))
         (is (= truth-amount (bitcoin-lisp.storage:utxo-set-total-amount utxo)))
         ;; And no unspendable outputs snuck in (the coinbase witness-commitment
         ;; OP_RETURN is dropped, as during normal apply).
         (let ((unspendable 0))
           (bitcoin-lisp.storage:utxo-set-iterate
            utxo (lambda (txid vout entry)
                   (declare (ignore txid vout))
                   (when (bitcoin-lisp.storage:script-unspendable-p
                          (bitcoin-lisp.storage:utxo-entry-script-pubkey entry))
                     (incf unspendable))))
           (is (zerop unspendable)))
         ;; The on-disk chainstate.dat was committed clean by the final
         ;; 3-phase flush (the marker set during the rebuild is cleared).
         (let ((reload (bitcoin-lisp.storage:make-chain-state
                        :base-path (bitcoin-lisp.storage::chain-state-base-path cs))))
           (is (eq t (bitcoin-lisp.storage:load-state reload)))
           (is (= tip (bitcoin-lisp.storage:current-height reload)))))))))

(test reindex-chainstate-recovers-emptied-coins-view
  "Reindex rebuilds even from a fully-emptied coins view (disaster recovery:
blocks + index intact, chainstate DB wiped)."
  (%with-regtest
   (let* ((tag (format nil "recov~D" (get-internal-real-time)))
          (node (%reindex-node-fixture tag)))
     (let ((bitcoin-lisp::*node* node))
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 5 "raw(51)"))
       (let* ((utxo (bitcoin-lisp::node-utxo-set node))
              (truth (bitcoin-lisp.storage:compute-utxo-set-muhash utxo)))
         ;; Nuke the coins view entirely, then reindex.
         (bitcoin-lisp.storage:coins-view-cache-wipe utxo)
         (bitcoin-lisp::do-reindex-chainstate)
         (is (equalp truth (bitcoin-lisp.storage:compute-utxo-set-muhash utxo))))))))

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
  (%with-regtest
   (let ((tag (format nil "crashr~D" (get-internal-real-time))))
     (multiple-value-bind (node cspath) (%reindex-node-fixture tag)
       (let ((bitcoin-lisp::*node* node))
         (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 8 "raw(51)"))
         (let* ((cs (bitcoin-lisp::node-chain-state node))
                (flushes 0)
                ;; Budget 0 => size trigger after EVERY replayed block, so
                ;; flush N happens right after block N is applied. The 3rd
                ;; flush dies in the marker window: on disk the marker is at
                ;; h=3 while the coins DB committed through h=2.
                (bitcoin-lisp::*coins-cache-budget-bytes* 0)
                (bitcoin-lisp::*flush-mid-commit-hook*
                  (lambda (flushing)
                    (declare (ignore flushing))
                    (when (= (incf flushes) 3)
                      (throw 'reindex-crash :crashed)))))
           (is (eq :crashed (catch 'reindex-crash
                              (bitcoin-lisp::do-reindex-chainstate)
                              :completed))))
         ;; Simulate the process death: drop the in-memory cache and reload
         ;; both the on-disk LevelDB and chainstate.dat, as startup would.
         (let ((cs (bitcoin-lisp::node-chain-state node)))
           (bitcoin-lisp.storage:close-chainstate-coins-view cs)
           (setf (bitcoin-lisp::node-utxo-set node)
                 (bitcoin-lisp.storage:make-coins-view-cache
                  (bitcoin-lisp.storage:open-coins-view-db cspath)))
           (is (eq :inconsistent (bitcoin-lisp.storage:load-state cs)))
           (is (= 3 (bitcoin-lisp.storage:current-height cs)))
           (is (eq t (bitcoin-lisp::recover-inconsistent-chainstate node cs)))
           ;; Rewound to the last committed replay flush: block 2.
           (is (= 2 (bitcoin-lisp.storage:current-height cs)))
           (let ((reload (bitcoin-lisp.storage:make-chain-state
                          :base-path (bitcoin-lisp.storage::chain-state-base-path cs))))
             (is (eq t (bitcoin-lisp.storage:load-state reload)))
             (is (= 2 (bitcoin-lisp.storage:current-height reload))))
           ;; And the coins DB is exactly the height-2 set: two 50-BTC
           ;; coinbases, nothing from block 3.
           (is (= 10000000000 (bitcoin-lisp.storage:utxo-set-total-amount
                               (bitcoin-lisp::node-utxo-set node))))))))))

(test reindex-crash-mid-wipe-recovers-to-genesis
  "A crash between the genesis+marker rewind and the first replay flush
(e.g. mid-wipe, when the coins DB holds arbitrary leftovers of the old set)
recovers to a clean EMPTY set at genesis -- the leftovers are re-wiped, never
loaded as live state."
  (%with-regtest
   (let* ((tag (format nil "crashw~D" (get-internal-real-time)))
          (node (%reindex-node-fixture tag)))
     (let ((bitcoin-lisp::*node* node))
       (bitcoin-lisp.rpc::rpc-generatetodescriptor node (list 5 "raw(51)"))
       (let* ((cs (bitcoin-lisp::node-chain-state node))
              (utxo (bitcoin-lisp::node-utxo-set node))
              (genesis (bitcoin-lisp.storage::chain-state-genesis-hash cs)))
         ;; Make the mined coins durable, then reproduce the crash state by
         ;; hand: tip rewound to genesis with the marker while the coins DB
         ;; still holds the old set (killed right before the wipe -- the
         ;; worst case: ALL old coins left behind as garbage).
         (bitcoin-lisp.storage:coins-view-cache-flush utxo :sync t)
         (bitcoin-lisp.storage:update-chain-tip cs genesis 0)
         (bitcoin-lisp.storage:save-state cs :in-transition t)
         (is (eq :inconsistent (bitcoin-lisp.storage:load-state cs)))
         (is (eq t (bitcoin-lisp::recover-inconsistent-chainstate node cs)))
         ;; Clean at genesis over an EMPTY coins DB.
         (is (= 0 (bitcoin-lisp.storage:current-height cs)))
         (is (equalp genesis (bitcoin-lisp.storage:best-block-hash cs)))
         (is (= 0 (bitcoin-lisp.storage:utxo-set-total-amount utxo)))
         (let ((reload (bitcoin-lisp.storage:make-chain-state
                        :base-path (bitcoin-lisp.storage::chain-state-base-path cs))))
           (is (eq t (bitcoin-lisp.storage:load-state reload)))
           (is (= 0 (bitcoin-lisp.storage:current-height reload)))))))))
