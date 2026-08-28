(in-package #:bitcoin-lisp.storage)

;;;; Block pruning policy (Core -prune, BlockManager::FindFilesToPrune)
;;;
;;; The knobs prune-old-blocks (blocks.lisp) reads: the target, the floor, the
;;; retention window and the start height. They used to live in config.lisp,
;;; which made storage reach up into the node package for its own policy;
;;; the node sets them (start-node's %init-parameters) and re-exports them
;;; unchanged, so its callers and the tests still say bl:*prune-target-mib*.

(defconstant +min-blocks-to-keep+ 288
  "Minimum number of recent blocks to keep on disk (matches Bitcoin Core).")

(defconstant +min-disk-space-for-block-files+ (* 550 1024 1024)
  "Floor for the effective automatic-prune target in bytes (Bitcoin Core
MIN_DISK_SPACE_FOR_BLOCK_FILES, validation.h:87). The per-chainstate halving
while an assumeutxo historical chainstate exists never pushes the target
below this.")

(defvar *prune-target-mib* nil
  "Block pruning target in MiB.
NIL = pruning disabled (default).
1 = manual-only mode (pruneblockchain RPC works, no automatic pruning).
>= 550 = automatic pruning to this target size.
Any other value signals an error at startup.")

(defvar *prune-after-height* nil
  "Minimum chain height before pruning can begin.
Set automatically based on network: 100000 for mainnet, 1000 for testnet.")

(defun pruning-enabled-p ()
  "Return T if pruning is enabled (any mode)."
  (and *prune-target-mib* (> *prune-target-mib* 0)))

(defun automatic-pruning-p ()
  "Return T if automatic pruning is enabled (not manual-only)."
  (and *prune-target-mib* (>= *prune-target-mib* 550)))

(defun prune-after-height (network)
  "Return the minimum chain height before pruning begins for NETWORK."
  (bl.chain:chain-params-prune-after-height (bl.chain:find-chain-params network)))

(defun prune-target-bytes (&optional (chainstates 1))
  "The automatic-prune target in bytes shared by CHAINSTATES chainstates
(Core BlockManager::FindFilesToPrune, node/blockstorage.cpp:330-338): the
-prune target divided by their number -- halved while an assumeutxo
historical chainstate exists -- and floored at
+min-disk-space-for-block-files+ (550 MiB, validation.h:87)."
  (max +min-disk-space-for-block-files+
       (floor (* *prune-target-mib* 1048576) chainstates)))
