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
   #:raw-chacha20
   #:raw-chacha20-seek
   #:raw-chacha20-crypt
   #:raw-chacha20-keystream
   #:raw-aead
   #:raw-aead-encrypt
   #:raw-aead-decrypt
   #:raw-aead-keystream
   #:with-temp-directory
   #:mine-regtest-header
   #:add-regtest-genesis-entry
   #:add-mined-chain
   #:%cbi-received
   #:wallet-data-directory
   #:wallet-directory-of
   #:make-temp-directory
   #:with-network
   #:make-test-node
   #:synthetic-index-test
   #:with-ibd-context
   #:project-source-text
   #:make-test-connection
   #:%fake-ready-peer
   #:%dispatch-to-fake-peer
   #:signals-rpc-error
   #:bpe-add-block
   #:bpe-add-tx
   #:btc-amount
   #:json-number-token
   #:rpc-error-code-of
   #:capture-log-lines
   #:claim-directory
   #:claim-data-directories
   #:release-directory-locks
   #:directory-locks-held
   #:next-message-within
   #:clear-recent-block-txs
   #:rpc-error-of
   #:wire-params
   #:grind-header-pow
   #:rpc-result-json
   #:one-input-tx-hex
   #:make-deterministic-rng
   #:clear-undo-cache
   #:txindex-resume-height
   #:coins-cache-entries
   #:hash-table-occupied-buckets
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
   #:call-setban
   #:call-listbanned
   #:call-clearbanned
   #:block-request-allowed-p
   #:reject-incoming-txs-p
   #:whitebind-address-refusal
   #:inv-vector-description
   #:tx-inv-payload
   #:deliver-notfound
   #:flush-peer-invs
   #:captured-sends
   #:message-command
   #:deliver-ibd-message
   #:with-tx-relay-out-of-ibd
   #:with-tx-request-salt
   #:test-txdownloadman
   #:test-txrequest
   #:test-orphanage
   #:reconsiderable-reject-p
   #:add-reconsiderable-reject
   #:recently-confirmed-p
   #:clear-recent-confirmed
   #:drain-orphan-work
   #:announce-tx
   #:run-tx-requests
   #:forget-tx-hash
   #:tx-request-received-response
   #:tx-request-candidate-peers
   #:tx-request-count
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
   #:test-pubkey
   #:make-mempool-test-tx
   #:make-spending-test-tx
   #:multisig-script
   #:%bpe-tracked
   #:bpe-test-id
   #:bpe-simulate
   #:bpe-populated-estimator
   #:make-witness-test-tx-bytes
   ;; chain.lisp
   #:make-test-chain-hashes
   #:make-versionbits-chain
   #:make-versionbits-chain-with-tip
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
   #:p2sh-optrue-scriptsig
   #:pkg-tx
   #:pkg-tx-2in
   #:make-simple-tx
   #:make-package-fixture
   ;; wallet.lisp
   #:make-wallet-rng
   #:with-wallet-rng
   #:wallet-db-record-list
   #:wallet-best-block-locator
   #:loaded-wallet
   #:with-rpc-wallet
   #:make-wallet-chain-node
   #:with-wallet-chain-node
   #:regtest-wif
   #:descriptor-spend-e2e
   ;; fixtures.lisp (handshake)
   #:with-private-outbound-nonces
   #:closed-loopback-port
   #:call-with-scripted-peer
   ;; fixtures.lisp (net permissions)
   #:with-whitelist
   ;; fixtures.lisp (logging)
   #:log-text-of))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
