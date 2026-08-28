;;;; Package bitcoin-lisp.rpc -- the public API of src/rpc/.
;;;;
;;;; First component of the bitcoin-lisp/rpc-server sub-system
;;;; (bitcoin-lisp.asd): the package exists before any file in src/rpc/
;;;; compiles, and the INSTALL-PACKAGE-NICKNAMES call at the end of this file
;;;; gives those files their bl.* prefixes. The package spans two systems: the
;;;; JSON-RPC/HTTP server (errors, define-rpc, json, server) is
;;;; bitcoin-lisp/rpc-server and knows no chain; the handlers, the REST
;;;; interface and the web UI load in the main system. Add an export here when
;;;; a definition in src/rpc/ becomes API; keep %-prefixed names internal.

(in-package #:cl-user)

(defpackage #:bitcoin-lisp.rpc
  (:documentation "The JSON-RPC/HTTP server (bitcoin-lisp/rpc-server:
requests, replies, auth, ACL, warmup, DEFINE-RPC) and, in the main system,
the methods one file per Core rpc/*.cpp, the REST interface and the web
UI. Core rpc/server.cpp, httprpc.cpp, httpserver.cpp, rest.cpp. src/rpc/.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   ;; Server control
   #:start-rpc-server
   #:rpc-server-data-directory
   #:register-http-surface
   #:*rpc-request-uri*
   #:*rpc-rate-limit*
   #:+max-rpc-body-size+
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
