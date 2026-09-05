;;;; Package bitcoin-lisp.test-support -- the fixtures every test file shares.
;;;;
;;;; Loaded before tests/package.lisp, which :USEs it, so a test file names
;;;; a fixture unqualified. A fixture belongs here the moment a second test
;;;; file wants it: the same temp-directory macro had been written seven
;;;; times, and the regtest bindings three, each file depending on whichever
;;;; other file happened to define them earlier in the load. White-box tests
;;;; keep reaching internals with :: -- that is legitimate and the structural
;;;; ratchet only asks that the count not grow.

(defpackage #:bitcoin-lisp.test-support
  (:documentation "Shared test fixtures: temporary directories, network
bindings, the minimal test node, synthetic transactions, blocks and chains,
a funded mempool fixture, a wallet-bearing regtest node. tests/support/.")
  (:use #:cl)
  (:export
   #:with-temp-directory
   #:make-temp-directory
   #:with-network
   #:make-test-node
   #:with-ibd-context
   #:signals-rpc-error
   #:rpc-error-code-of
   #:make-deterministic-rng
   #:coins-cache-entries
   #:coins-cache-fresh-count
   #:coins-cache-dirty-count
   #:coins-cache-entry-fresh-p
   #:coins-cache-entry-dirty-p
   #:start-node-plist
   #:rest-request
   #:deliver-getdata
   #:drain-peer-once
   #:ingest-gossiped-addresses
   #:peer-pending-getdata
   #:send-buffer-bytes
   ;; transactions.lisp
   #:make-mempool-test-tx
   #:make-witness-test-tx-bytes
   ;; chain.lisp
   #:make-test-chain-hashes
   #:make-versionbits-chain
   #:make-reorg-test-block
   #:make-forged-body-block
   #:make-two-coinbase-block
   #:regtest-node-fixture
   #:activate-block-base-path
   #:make-activate-block-fixture
   #:build-and-connect
   #:deliver-block
   ;; mempool-fixtures.lisp
   #:+optrue-redeem+
   #:p2sh-optrue-script-pubkey
   #:make-package-fixture
   ;; wallet.lisp
   #:make-wallet-rng
   #:with-rpc-wallet
   #:make-wallet-chain-node
   #:with-wallet-chain-node
   #:descriptor-spend-e2e))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
