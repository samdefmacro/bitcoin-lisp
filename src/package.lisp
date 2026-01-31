(defpackage #:bitcoin-lisp.crypto
  (:use #:cl)
  (:export
   ;; Hash functions
   #:sha256
   #:hash256
   #:ripemd160
   #:hash160
   ;; Tagged hashes (BIP 340)
   #:tagged-hash
   #:tap-leaf-hash
   #:tap-branch-hash
   #:tap-tweak-hash
   #:+tag-bip340-challenge+
   #:+tag-bip340-aux+
   #:+tag-tap-leaf+
   #:+tag-tap-branch+
   #:+tag-tap-tweak+
   #:+tag-tap-sighash+
   ;; Utilities
   #:bytes-to-hex
   #:hex-to-bytes
   #:reverse-bytes
   ;; secp256k1 ECDSA
   #:verify-signature
   #:parse-public-key
   #:public-key-valid-p
   #:ensure-secp256k1-loaded
   #:cleanup-secp256k1
   ;; Schnorr / x-only pubkeys (BIP 340)
   #:verify-schnorr-signature
   #:parse-xonly-pubkey
   #:xonly-pubkey-valid-p
   #:tweak-xonly-pubkey
   #:verify-xonly-tweak))

(defpackage #:bitcoin-lisp.serialization
  (:use #:cl)
  (:export
   ;; Binary primitives
   #:read-uint8
   #:read-uint16-le
   #:read-uint32-le
   #:read-uint64-le
   #:read-int32-le
   #:read-int64-le
   #:write-uint8
   #:write-uint16-le
   #:write-uint32-le
   #:write-uint64-le
   #:write-int32-le
   #:write-int64-le
   #:read-compact-size
   #:write-compact-size
   #:read-bytes
   #:write-bytes
   #:read-var-bytes
   #:write-var-bytes
   ;; Types
   #:outpoint
   #:make-outpoint
   #:outpoint-hash
   #:outpoint-index
   #:tx-in
   #:make-tx-in
   #:tx-in-previous-output
   #:tx-in-script-sig
   #:tx-in-sequence
   #:tx-out
   #:make-tx-out
   #:tx-out-value
   #:tx-out-script-pubkey
   #:transaction
   #:make-transaction
   #:transaction-version
   #:transaction-inputs
   #:transaction-outputs
   #:transaction-lock-time
   #:transaction-hash
   #:transaction-witness
   #:transaction-wtxid
   #:transaction-has-witness-p
   #:serialize-witness-transaction
   #:block-header
   #:make-block-header
   #:block-header-version
   #:block-header-prev-block
   #:block-header-merkle-root
   #:block-header-timestamp
   #:block-header-bits
   #:block-header-nonce
   #:block-header-hash
   #:bitcoin-block
   #:make-bitcoin-block
   #:bitcoin-block-header
   #:bitcoin-block-transactions
   ;; Serialization
   #:serialize
   #:deserialize
   ;; Messages
   #:message-header
   #:make-message-header
   #:message-header-magic
   #:message-header-command
   #:message-header-payload-length
   #:message-header-checksum
   #:read-message-header
   #:serialize-message
   #:compute-checksum
   #:*network-magic*
   #:+testnet-magic+
   #:+mainnet-magic+
   ;; Version message
   #:version-message
   #:make-version-message-bytes
   #:read-version-message
   #:version-message-version
   #:version-message-services
   #:version-message-start-height
   #:version-message-user-agent
   #:make-verack-message
   #:make-ping-message
   #:make-pong-message
   #:make-getblocks-message
   #:make-getheaders-message
   #:make-getdata-message
   #:make-inv-message
   #:make-tx-message
   #:parse-tx-payload
   ;; Inventory
   #:inv-vector
   #:make-inv-vector
   #:inv-vector-type
   #:inv-vector-hash
   #:+inv-type-tx+
   #:+inv-type-block+
   #:+inv-type-witness-tx+
   #:+inv-type-witness-block+
   ;; Parsing
   #:parse-inv-payload
   #:parse-headers-payload
   #:parse-block-payload
   #:read-bitcoin-block
   #:read-transaction
   #:serialize-transaction
   #:coinbase-input-p
   #:get-unix-time
   #:read-net-addr
   #:read-hash256
   #:write-hash256))

(defpackage #:bitcoin-lisp.storage
  (:use #:cl)
  (:export
   ;; Block store
   #:block-store
   #:make-block-store
   #:init-block-store
   #:store-block
   #:get-block
   #:block-exists-p
   ;; UTXO set
   #:utxo-set
   #:make-utxo-set
   #:utxo-entry
   #:utxo-entry-value
   #:utxo-entry-script-pubkey
   #:utxo-entry-height
   #:utxo-entry-coinbase
   #:add-utxo
   #:remove-utxo
   #:get-utxo
   #:utxo-exists-p
   #:utxo-count
   #:apply-block-to-utxo-set
   #:disconnect-block-from-utxo-set
   ;; Chain state
   #:chain-state
   #:make-chain-state
   #:init-chain-state
   #:block-index-entry
   #:make-block-index-entry
   #:block-index-entry-hash
   #:block-index-entry-height
   #:block-index-entry-header
   #:block-index-entry-prev-entry
   #:block-index-entry-chain-work
   #:block-index-entry-status
   #:get-block-index-entry
   #:add-block-index-entry
   #:get-block-at-height
   #:best-block-hash
   #:current-height
   #:update-chain-tip
   #:build-block-locator
   #:bits-to-target
   #:calculate-chain-work
   #:save-state
   #:load-state
   ;; UTXO persistence
   #:save-utxo-set
   #:load-utxo-set
   #:utxo-set-file-path
   #:utxo-set-dirty
   ;; Header index persistence
   #:save-header-index
   #:load-header-index
   #:append-header-entry
   ;; Integrity utilities
   #:compute-crc32))

(defpackage #:bitcoin-lisp.mempool
  (:use #:cl)
  (:export
   ;; Constants
   #:+default-max-mempool-bytes+
   #:+default-min-relay-fee-rate+
   ;; Mempool entry
   #:mempool-entry
   #:make-mempool-entry
   #:mempool-entry-transaction
   #:mempool-entry-fee
   #:mempool-entry-size
   #:mempool-entry-entry-time
   #:mempool-entry-fee-rate
   ;; Mempool
   #:mempool
   #:make-mempool
   #:mempool-has
   #:mempool-get
   #:mempool-add
   #:mempool-remove
   #:mempool-count
   #:mempool-total-size
   #:mempool-check-conflict
   #:mempool-remove-for-block
   #:mempool-get-transactions))

(defpackage #:bitcoin-lisp.validation
  (:use #:cl)
  (:export
   ;; Transaction validation
   #:validate-transaction-structure
   #:validate-transaction-contextual
   #:validate-transaction-scripts
   #:validate-transaction-for-mempool
   ;; Script execution
   #:validate-script
   #:execute-script
   ;; Block validation
   #:validate-block-header
   #:validate-block
   #:validate-block-scripts
   #:find-witness-commitment
   #:validate-witness-commitment
   #:compute-witness-merkle-root
   #:check-proof-of-work
   #:compute-merkle-root
   #:connect-block
   #:find-fork-point
   #:perform-reorg
   #:decode-coinbase-height
   ;; Constants
   #:+coinbase-maturity+
   #:+max-money+))

(defpackage #:bitcoin-lisp.networking
  (:use #:cl)
  (:export
   ;; Connection
   #:connection
   #:connection-connected
   #:make-tcp-connection
   #:close-connection
   #:send-bytes
   #:receive-bytes
   ;; Peer
   #:peer
   #:make-peer
   #:peer-state
   #:peer-version
   #:peer-services
   #:peer-start-height
   #:peer-user-agent
   #:peer-ping-latency
   #:connect-peer
   #:disconnect-peer
   #:send-message
   #:receive-message
   #:perform-handshake
   #:send-ping
   ;; Peer manager
   #:peer-manager
   #:make-peer-manager
   #:discover-peers
   ;; Protocol
   #:handle-message
   #:request-headers
   #:request-blocks
   #:sync-with-peer
   #:relay-transaction
   #:peer-announced-txs
   ;; Peer health
   #:check-peer-health
   #:record-block-timeout
   #:peer-consecutive-ping-failures
   #:peer-block-timeout-count
   #:peer-address
   #:+max-ping-failures+
   #:+max-block-timeouts+
   ;; Misbehavior and banning
   #:record-misbehavior
   #:ban-peer
   #:peer-banned-p
   #:clear-ban-list
   #:peer-misbehavior-score
   #:+misbehavior-ban-threshold+
   #:*banned-peers*
   ;; Network params
   #:*testnet-port*
   #:*mainnet-port*
   #:*current-port*
   #:*dns-seeds*
   #:*testnet-dns-seeds*
   #:*mainnet-dns-seeds*))

(defpackage #:bitcoin-lisp
  (:use #:cl)
  (:use #:bitcoin-lisp.crypto)
  (:use #:bitcoin-lisp.serialization)
  (:use #:bitcoin-lisp.storage)
  (:use #:bitcoin-lisp.validation)
  (:use #:bitcoin-lisp.networking)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   ;; Network parameters
   #:*network*
   #:+testnet+
   #:+mainnet+
   #:network-magic
   #:network-port
   #:network-dns-seeds
   ;; Node
   #:node
   #:*node*
   #:start-node
   #:stop-node
   #:node-status
   #:sync-blockchain
   ;; Logging
   #:*log-stream*
   #:*current-log-level*
   #:node-log
   #:log-debug
   #:log-info
   #:log-warn
   #:log-error
   #:show-logs
   #:clear-logs
   #:enable-console-logging
   #:disable-console-logging
   #:start-file-logging
   #:stop-file-logging))

