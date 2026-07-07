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
  "A regtest node whose UTXO set is a LevelDB-backed coins-view-cache (matching
the live node), with undo storage initialized so mining can connect blocks."
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
    node))

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
           (is (zerop unspendable))))))))

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
