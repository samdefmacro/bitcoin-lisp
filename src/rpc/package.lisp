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
   #:json-object)
  ;; Reached from another package with :: before the second-round review
  ;; (docs/refactoring-review-2026-09-02.md, wave B): API by use, so exported.
  (:export
   #:+rpc-deserialization-error+
   #:+rpc-invalid-amount+
   #:+rpc-method-deprecated+
   #:+rpc-type-error+
   #:+rpc-wallet-already-exists+
   #:+rpc-wallet-already-loaded+
   #:+rpc-wallet-encryption-failed+
   #:+rpc-wallet-error+
   #:+rpc-wallet-insufficient-funds+
   #:+rpc-wallet-invalid-label-name+
   #:+rpc-wallet-keypool-ran-out+
   #:+rpc-wallet-not-found+
   #:+rpc-wallet-not-specified+
   #:+rpc-wallet-passphrase-incorrect+
   #:+rpc-wallet-unlock-needed+
   #:+rpc-wallet-wrong-enc-state+
   #:+tapleaf-version-tapscript+
   #:activate-submitted-block
   #:amount-from-value
   #:build-spent-utxos
   #:compute-input-signatures
   #:desc-key-compressed-p
   #:desc-key-derive
   #:desc-key-ext-privkey
   #:desc-key-extkey
   #:desc-key-has-privkey-p
   #:desc-key-origin-fingerprint
   #:desc-key-origin-path
   #:desc-key-path
   #:desc-key-privkey
   #:desc-key-privkey-for
   #:desc-key-pubkey
   #:desc-key-root-xprv
   #:desc-key-xonly-p
   #:descriptor-add-checksum
   #:descriptor-cache-derived
   #:descriptor-cache-derived-xpubs
   #:descriptor-cache-last-hardened
   #:descriptor-cache-last-hardened-xpubs
   #:descriptor-cache-merge-and-diff
   #:descriptor-cache-parent
   #:descriptor-cache-parent-xpubs
   #:descriptor-derivation-error
   #:descriptor-id
   #:expand-multipath-descriptor
   #:feerate-fee
   #:format-key-path
   #:format-money
   #:hash-to-hex
   #:input-sig-ecdsa
   #:input-sig-kind
   #:input-sig-redeem
   #:input-sig-tap
   #:input-sig-tap-leaf
   #:input-sig-tap-script-sigs
   #:input-sig-witness-script
   #:key-xonly-bytes
   #:make-descriptor-cache
   #:make-recipient
   #:obj-get
   #:out-desc-expand-from-cache
   #:out-desc-expand-with-provider
   #:out-desc-kind
   #:out-desc-node
   #:out-desc-ordered-keys
   #:out-desc-ranged-p
   #:out-desc-solvable-p
   #:out-desc-string
   #:out-desc-string-normalized
   #:out-desc-string-private
   #:out-desc-sub
   #:out-desc-threshold
   #:out-desc-tree
   #:out-desc-xonly-script-p
   #:outpoint-key
   #:parse-descriptor
   #:parse-descriptor-range
   #:parse-hex-hash
   #:parse-multisig
   #:parse-multisig-pubkey
   #:parse-outputs
   #:parse-sighash-type
   #:positional-array
   #:positional-bool
   #:positional-bool-or
   #:pubkey-lessp
   #:recipient-address
   #:recipient-amount
   #:recipient-script
   #:recipient-sffo
   #:rpc-error
   #:rpc-error-code
   #:rpc-error-message
   #:rpc-get-blockfilterindex
   #:rpc-get-network
   #:rpc-signmessagewithprivkey
   #:satoshi->btc
   #:script->address
   #:sign-tx-inputs
   #:tr-spend-data
   #:tr-tree-string
   #:tx-input-witness
   #:tx-to-json
   #:txout-serialize-size
   #:valid-hex-hash-p
   #:with-node-lock))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
