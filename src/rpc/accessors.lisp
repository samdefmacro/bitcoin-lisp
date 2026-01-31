(in-package #:bitcoin-lisp.rpc)

;;; Thread-Safe Node State Accessors
;;;
;;; These functions acquire the node lock before accessing state,
;;; ensuring safe concurrent access from RPC handler threads.

(defun rpc-get-chain-state (node)
  "Get chain-state with lock protection."
  (bt:with-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-chain-state node)))

(defun rpc-get-utxo-set (node)
  "Get utxo-set with lock protection."
  (bt:with-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-utxo-set node)))

(defun rpc-get-peers (node)
  "Get a copy of the peer list with lock protection."
  (bt:with-lock-held ((bitcoin-lisp::node-lock node))
    (copy-list (bitcoin-lisp::node-peers node))))

(defun rpc-get-mempool (node)
  "Get mempool with lock protection."
  (bt:with-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-mempool node)))

(defun rpc-get-block-store (node)
  "Get block-store with lock protection."
  (bt:with-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-block-store node)))

(defun rpc-get-network (node)
  "Get network type with lock protection."
  (bt:with-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-network node)))

(defun rpc-is-syncing (node)
  "Check if node is currently syncing."
  (bt:with-lock-held ((bitcoin-lisp::node-lock node))
    (bitcoin-lisp::node-syncing node)))
