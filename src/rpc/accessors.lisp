(in-package #:bitcoin-lisp.rpc)

;;; Thread-Safe Node State Accessors
;;;
;;; These functions acquire the node lock before accessing state,
;;; ensuring safe concurrent access from RPC handler threads.

(defun rpc-get-chain-state (node)
  "Get the current (active) chainstate with lock protection. RPC reports the
active chainstate (Core getblockchaininfo reports CurrentChainstate)."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-current-chainstate node)))

(defun rpc-get-utxo-set (node)
  "Get the current chainstate's coins view with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (let ((cs (bitcoin-lisp::node-current-chainstate node)))
      (and cs (bitcoin-lisp.storage:chain-state-coins-view cs)))))

(defun rpc-get-chainstates (node)
  "Get a copy of the full chainstates list with lock protection (for
getchainstates, which reports every chainstate)."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (copy-list (bitcoin-lisp::node-chainstates node))))

(defun rpc-get-peers (node)
  "Get a copy of the peer list with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (copy-list (bitcoin-lisp::node-peers node))))

(defun rpc-get-mempool (node)
  "Get mempool with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-mempool node)))

(defun rpc-get-block-store (node)
  "Get block-store with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-block-store node)))

(defun rpc-get-network (node)
  "Get network type with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-network node)))

(defun rpc-is-syncing (node)
  "Check if node is currently syncing."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-syncing node)))

(defun rpc-get-tx-index (node)
  "Get tx-index with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-tx-index node)))

(defun rpc-get-blockfilterindex (node)
  "Get the block filter index with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-blockfilterindex node)))

(defun rpc-get-coinstatsindex (node)
  "Get the coinstats index with lock protection."
  (bt:with-recursive-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-coinstatsindex node)))
