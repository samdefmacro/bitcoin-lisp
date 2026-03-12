(in-package #:cl-user)

(defpackage #:bitcoin-lisp.rpc
  (:use #:cl)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   ;; Server control
   #:start-rpc-server
   #:stop-rpc-server
   #:*rpc-server*

   ;; Thread-safe accessors
   #:rpc-get-chain-state
   #:rpc-get-utxo-set
   #:rpc-get-peers
   #:rpc-get-mempool
   #:rpc-get-block-store
   #:rpc-get-tx-index

   ;; Method registry
   #:register-rpc-method
   #:dispatch-rpc-method

   ;; Error codes
   #:+rpc-parse-error+
   #:+rpc-invalid-request+
   #:+rpc-method-not-found+
   #:+rpc-invalid-params+
   #:+rpc-internal-error+
   #:+rpc-misc-error+
   #:+rpc-invalid-address-or-key+
   #:+rpc-invalid-parameter+))
