(in-package #:cl-user)

(defpackage #:bitcoin-lisp.rpc
  (:use #:cl)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   ;; Server control
   #:start-rpc-server
   #:stop-rpc-server
   #:*rpc-server*
   #:open-browser-to-ui

   ;; Thread-safe accessors
   #:rpc-get-chain-state
   #:rpc-get-chainstates
   #:rpc-get-utxo-set
   #:rpc-get-peers
   #:rpc-get-mempool
   #:rpc-get-block-store
   #:rpc-get-tx-index

   ;; Method registry
   #:register-rpc-method
   #:dispatch-rpc-method

   ;; Wallet manager (wallet P1; owned by the node)
   #:init-wallet-manager
   #:close-wallet-manager

   ;; Error codes
   #:+rpc-parse-error+
   #:+rpc-invalid-request+
   #:+rpc-method-not-found+
   #:+rpc-invalid-params+
   #:+rpc-internal-error+
   #:+rpc-misc-error+
   #:+rpc-invalid-address-or-key+
   #:+rpc-invalid-parameter+

   ;; JSON boolean helpers (Core booleans are true/false, never null)
   #:+json-false+
   #:json-bool))
