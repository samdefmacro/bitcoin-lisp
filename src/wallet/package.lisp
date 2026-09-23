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
   #:set-wallet-default-output-type
   #:init-wallet-manager
   #:load-wallets-on-startup
   #:wallet-manager
   #:wallet-manager-has-wallets-p
   #:wallets-block-connected
   #:wallets-block-disconnected
   #:wallets-maybe-resend
   #:wallets-mempool-tx-added
   #:wallets-mempool-tx-removed
   ;; Core FillPSBT for an unsigned transaction (FinishTransaction's PSBT);
   ;; send and sendall build theirs with it.
   #:wallet-fill-psbt)
  ;; Reached from another package with :: before the second-round review
  ;; (docs/refactoring-review-2026-09-02.md, wave B): API by use, so exported.
  (:export
   #:*wallet-confirm-target*
   #:*wallet-dump-max-line-bytes*
   #:*wallet-avoid-partial-spends*
   #:*wallet-default-address-type*
   #:*wallet-default-change-type*
   #:*wallet-consolidate-feerate*
   #:*wallet-cross-chain*
   #:*wallet-directory*
   #:*wallet-discard-rate*
   #:*wallet-max-aps-fee*
   #:*wallet-min-tx-fee*
   #:*wallet-notify-command*
   #:*signer-command*
   #:run-command-parse-json
   #:wallet-tool-execute
   #:*wallet-reject-long-chains*
   #:*wallet-signal-rbf*
   #:*wallet-spend-zero-conf-change*
   #:*default-keypool-size*
   ;; chain.getPackageLimits, which in this version of Core only the wallet's
   ;; coin-eligibility ladder reads (-limitancestorcount / -limitdescendantcount)
   #:*package-ancestor-limit*
   #:*package-descendant-limit*))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
