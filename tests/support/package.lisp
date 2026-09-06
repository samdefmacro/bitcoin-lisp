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
   #:project-source-text
   #:make-test-connection
   #:signals-rpc-error
   #:rpc-error-code-of
   #:capture-log-lines
   #:make-deterministic-rng
   #:clear-undo-cache
   #:coins-cache-entries
   #:coins-cache-fresh-count
   #:coins-cache-dirty-count
   #:coins-cache-entry-fresh-p
   #:coins-cache-entry-dirty-p
   #:start-node-plist
   #:apply-config-globals
   #:rest-request
   #:deliver-getdata
   #:deliver-tx
   #:deliver-inv
   #:tx-inv-payload
   #:deliver-notfound
   #:flush-peer-invs
   #:deliver-ibd-message
   #:with-tx-relay-out-of-ibd
   #:with-tx-request-salt
   #:tx-request-in-flight-peer
   #:tx-request-announcement-peers
   #:tx-request-completed-p
   #:tx-request-wtxid-entry-p
   #:backdate-tx-announcements
   #:expire-tx-request
   #:tx-request-peer-count
   #:tx-request-peer-in-flight-count
   #:drain-peer-once
   #:ingest-gossiped-addresses
   #:peer-pending-getdata
   #:send-buffer-bytes
   ;; transactions.lisp
   #:make-mempool-test-tx
   #:make-spending-test-tx
   #:bpe-test-id
   #:bpe-simulate
   #:bpe-populated-estimator
   #:make-witness-test-tx-bytes
   ;; chain.lisp
   #:make-test-chain-hashes
   #:make-versionbits-chain
   #:make-reorg-test-block
   #:make-forged-body-block
   #:make-two-coinbase-block
   #:regtest-node-fixture
   #:regtest-node-base-path
   #:generate-regtest-blocks
   #:coins-db-node-fixture
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
   #:wallet-db-record-list
   #:loaded-wallet
   #:with-rpc-wallet
   #:make-wallet-chain-node
   #:with-wallet-chain-node
   #:regtest-wif
   #:descriptor-spend-e2e))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
