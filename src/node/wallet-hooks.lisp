(in-package #:bitcoin-lisp)

;;; Wallet chain-tracking hooks (wallet P2). Hardcoded call sites like the
;;; index hooks above: connect-block / perform-reorg call the block pair,
;;; mempool-add / mempool-remove call the mempool pair. Each is a cheap
;;; no-op — one special read + a hash-table count — unless the running node
;;; has wallets loaded, and never signals: a wallet failure must not abort
;;; a block connect or a mempool mutation (logged loudly instead; the
;;; wallet re-derives missed state on the next rescan).

(defun %wallet-hook-manager ()
  "The running node's wallet manager when at least one wallet is loaded,
else NIL — the fast-path gate shared by the wallet hooks."
  (let ((manager (and *node* (node-wallet-manager *node*))))
    (and manager
         (bl.wallet:wallet-manager-has-wallets-p manager)
         manager)))

(defun wallet-notify-block-connected (chainstate block block-hash height)
  "Connect-time hook: let loaded wallets scan BLOCK (Core
CWallet::blockConnected). Only the active chainstate's connects are
delivered — an assumeutxo historical (targeted) chainstate's re-derived
old blocks are Core's ChainstateRole::historical, which the wallet ignores
(wallet.cpp:1526-1529)."
  (let ((manager (%wallet-hook-manager)))
    (when (and manager
               (not (bl.store:chain-state-target-blockhash chainstate)))
      (handler-case
          (bl.wallet:wallets-block-connected
           manager (node-mempool *node*) chainstate block block-hash height)
        (error (e)
          (log-error "Wallet processing of connected block at height ~D FAILED: ~A"
                     height e))))))

(defun wallet-notify-block-disconnected (chainstate block height)
  "Reorg hook: let loaded wallets demote BLOCK's transactions (Core
CWallet::blockDisconnected). Called from perform-reorg's commit phase,
tip-first."
  (let ((manager (%wallet-hook-manager)))
    (when (and manager
               (not (bl.store:chain-state-target-blockhash chainstate)))
      (handler-case
          (bl.wallet:wallets-block-disconnected manager block height)
        (error (e)
          (log-error "Wallet processing of disconnected block at height ~D FAILED: ~A"
                     height e))))))

(defun wallet-notify-mempool-tx-added (tx)
  "Mempool hook: Core CWallet::transactionAddedToMempool."
  (let ((manager (%wallet-hook-manager)))
    (when manager
      (handler-case
          (bl.wallet:wallets-mempool-tx-added
           manager (node-mempool *node*) tx)
        (error (e)
          (log-error "Wallet processing of mempool tx add FAILED: ~A" e))))))

(defun wallet-notify-mempool-tx-removed (tx reason)
  "Mempool hook: Core CWallet::transactionRemovedFromMempool. REASON :block
is skipped — the wallet learns about mined txs from the block-connected
hook (Core removeUnchecked, txmempool.cpp:269-275)."
  (unless (eq reason :block)
    (let ((manager (%wallet-hook-manager)))
      (when manager
        (handler-case
            (bl.wallet:wallets-mempool-tx-removed
             manager (node-mempool *node*) tx reason)
          (error (e)
            (log-error "Wallet processing of mempool tx removal FAILED: ~A" e)))))))
