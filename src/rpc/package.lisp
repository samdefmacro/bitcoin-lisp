(in-package #:cl-user)

(defpackage #:bitcoin-lisp.rpc
  (:use #:cl)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   ;; Server control
   #:start-rpc-server
   #:*rpc-threads*
   #:*rpc-server-timeout*
   #:*rpc-cookie-file*
   #:*rpc-cookie-perms*
   #:parse-rpc-cookie-perms
   #:set-rpc-warmup-status
   #:finish-rpc-warmup
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
   #:define-rpc
   #:dispatch-rpc-method

   ;; The wallet manager, its chain-tracking fan-out and the rebroadcast
   ;; timer are BITCOIN-LISP.WALLET's exports (src/wallet/package.lisp).

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
   #:json-bool

   ;; Empty-collection helpers (Core renders [] / {}, never null)
   #:json-array
   #:json-object))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
