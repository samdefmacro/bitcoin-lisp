(in-package #:cl-user)

(defpackage #:bitcoin-lisp.wallet
  (:use #:cl)
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
   #:wallets-mempool-tx-removed))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
