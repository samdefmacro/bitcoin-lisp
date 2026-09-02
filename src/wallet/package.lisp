(in-package #:cl-user)

(defpackage #:bitcoin-lisp.wallet
  (:use #:cl #:bitcoin-lisp.conditions)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:documentation "The descriptor wallet (Core wallet/ and wallet/rpc/): stores,
manager, encryption, transaction tracking, coin selection, spending, PSBT and
the wallet RPCs. Reaches the node through bl.rpc's accessors and the chain
through the lower packages; the node reaches it only through these exports.")
  (:export
   #:close-wallet-manager
   #:init-wallet-manager
   #:load-wallets-on-startup
   #:wallet-manager
   #:wallet-manager-has-wallets-p
   #:wallets-block-connected
   #:wallets-block-disconnected
   #:wallets-maybe-resend
   #:wallets-mempool-tx-added
   #:wallets-mempool-tx-removed)
  ;; Reached from another package with :: before the second-round review
  ;; (docs/refactoring-review-2026-09-02.md, wave B): API by use, so exported.
  (:export
   #:*wallet-confirm-target*
   #:*wallet-consolidate-feerate*
   #:*wallet-directory*
   #:*wallet-discard-rate*
   #:*wallet-max-aps-fee*
   #:*wallet-min-tx-fee*
   #:*wallet-notify-command*
   #:*wallet-reject-long-chains*
   #:*wallet-signal-rbf*
   #:*wallet-spend-zero-conf-change*
   #:*default-keypool-size*))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
