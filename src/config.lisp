(in-package #:bitcoin-lisp)

;;; Configuration
;;;
;;; Global configuration variables and constants that are referenced
;;; across multiple subsystems. Loaded early so that storage, validation,
;;; and networking modules can reference these symbols at compile time.

;;;; Block Pruning Configuration

(defconstant +min-blocks-to-keep+ 288
  "Minimum number of recent blocks to keep on disk (matches Bitcoin Core).")

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
  (ecase network
    (:mainnet 100000)
    (:testnet 1000)))
