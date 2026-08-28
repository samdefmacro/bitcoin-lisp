(in-package #:bitcoin-lisp.rpc)

;;; Thread-Safe Node State Accessors
;;;
;;; These functions acquire the node lock before accessing state,
;;; ensuring safe concurrent access from RPC handler threads.
;;;
;;; LOCKING DISCIPLINE. The node has ONE state lock — the recursive
;;; node-lock — guarding the chainstates list, each chainstate's tip/index/
;;; coins view, the mempool (entries, txgraph, deltas, unbroadcast set,
;;; orphan pool), and the peer list. It is our single-lock analogue of
;;; Core's cs_main + pool.cs pair. The P2P sync thread holds it around
;;; every message handler that touches shared state (networking's
;;; WITH-NODE-LOCK, protocol.lisp:7); RPC handler threads run concurrently
;;; on hunchentoot worker threads, so every RPC that MUTATES that state —
;;; or wants a torn-free consistent read of it — must hold the same lock
;;; for the whole operation, not just while fetching the object reference
;;; (which is all the accessors below do).
;;;
;;; Lock ORDERING (deadlock freedom): the node-lock is the OUTERMOST lock.
;;; Code holding it may take leaf locks (per-connection send locks,
;;; *tx-request-lock*, *ban-lock*, *log-lock*, SBCL's synchronized
;;; sig-cache tables); no code path acquires the node-lock while holding
;;; any of those, so the ordering is acyclic. The lock is recursive, so a
;;; locked RPC body may freely call helpers that re-acquire it
;;; (broadcast-transaction-to-peers, the mining assembler's chunk walk,
;;; these accessors). Long-polling RPCs (waitfornewblock/waitforblock*)
;;; must NEVER hold it across their sleep loops — the sync thread needs it
;;; to advance the tip they are waiting on.

(defmacro with-node-lock ((node) &body body)
  "Execute BODY holding NODE's recursive state lock. Use around any RPC
handler section that mutates — or must consistently read — the mempool,
chainstate, or peer list (see the locking discipline above)."
  `(bt:with-recursive-lock-held ((bl::node-lock ,node))
     ,@body))

(defun rpc-get-chain-state (node)
  "Get the current (active) chainstate with lock protection. RPC reports the
active chainstate (Core getblockchaininfo reports CurrentChainstate)."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-current-chainstate node)))

(defun rpc-get-utxo-set (node)
  "Get the current chainstate's coins view with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (let ((cs (bl::node-current-chainstate node)))
      (and cs (bl.store:chain-state-coins-view cs)))))

(defun rpc-get-chainstates (node)
  "Get a copy of the full chainstates list with lock protection (for
getchainstates, which reports every chainstate)."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (copy-list (bl::node-chainstates node))))

(defun rpc-get-peers (node)
  "Get a copy of the peer list with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (copy-list (bl::node-peers node))))

(defun rpc-get-mempool (node)
  "Get mempool with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-mempool node)))

(defun rpc-get-block-store (node)
  "Get block-store with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-block-store node)))

(defun rpc-get-network (node)
  "Get network type with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-network node)))

(defun rpc-is-syncing (node)
  "Check if node is currently syncing."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-syncing node)))

(defun rpc-get-tx-index (node)
  "Get tx-index with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-tx-index node)))

(defun rpc-get-blockfilterindex (node)
  "Get the block filter index with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-blockfilterindex node)))

(defun rpc-get-coinstatsindex (node)
  "Get the coinstats index with lock protection."
  (bt:with-recursive-lock-held ((bl::node-lock node))
    (bl::node-coinstatsindex node)))
