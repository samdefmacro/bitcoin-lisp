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
   ;; SipHash (BIP 152)
   #:siphash-2-4
   #:compute-siphash-key
   #:compute-short-txid
   #:bytes-to-uint64-le
   #:uint64-to-bytes-le
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
   #:verify-xonly-tweak
   ;; Address encoding/decoding
   #:base58-encode
   #:base58-decode
   #:base58check-encode
   #:base58check-decode
   #:bech32-encode
   #:bech32-decode
   #:segwit-address-encode
   #:segwit-address-decode
   #:decode-address
   #:encode-p2pkh-address
   #:encode-p2sh-address
   #:encode-p2wpkh-address
   #:encode-p2wsh-address
   #:encode-p2tr-address
   #:+p2pkh-version-mainnet+
   #:+p2pkh-version-testnet+
   #:+p2sh-version-mainnet+
   #:+p2sh-version-testnet+))

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
   #:transaction-vsize
   #:transaction-weight
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
   #:serialize-block-header
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
   ;; Service bit constants
   #:+node-network+
   #:+node-witness+
   #:+node-network-limited+
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
   #:+inv-type-cmpct-block+
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
   #:net-addr
   #:make-net-addr
   #:net-addr-services
   #:net-addr-ip
   #:net-addr-port
   #:read-hash256
   #:write-hash256
   ;; Compact block (BIP 152)
   #:compact-block
   #:make-compact-block
   #:compact-block-header
   #:compact-block-nonce
   #:compact-block-short-ids
   #:compact-block-prefilled-txs
   #:prefilled-tx
   #:make-prefilled-tx
   #:prefilled-tx-index
   #:prefilled-tx-transaction
   #:block-txn-request
   #:make-block-txn-request
   #:block-txn-request-block-hash
   #:block-txn-request-indexes
   #:block-txn-response
   #:make-block-txn-response
   #:block-txn-response-block-hash
   #:block-txn-response-transactions
   #:parse-sendcmpct-payload
   #:make-sendcmpct-message
   #:parse-cmpctblock-payload
   #:make-getblocktxn-message
   #:parse-getblocktxn-payload
   #:parse-blocktxn-payload
   #:read-compact-block
   #:write-compact-block
   ;; Addr message
   #:make-addr-message
   ;; ADDRv2 (BIP 155)
   #:+addrv2-net-ipv4+
   #:+addrv2-net-ipv6+
   #:+addrv2-net-torv2+
   #:+addrv2-net-torv3+
   #:+addrv2-net-i2p+
   #:+addrv2-net-cjdns+
   #:*addrv2-addr-sizes*
   #:read-net-addr-v2
   #:write-net-addr-v2
   #:make-sendaddrv2-message
   #:make-addrv2-message
   #:parse-addrv2-payload))

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
   ;; Block pruning
   #:prune-block
   #:block-storage-size-mib
   #:prune-old-blocks
   #:prune-blocks-to-height
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
   #:network-genesis-hash
   #:*testnet-genesis-hash*
   #:*mainnet-genesis-hash*
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
   #:target-to-bits
   #:calculate-chain-work
   #:calculate-next-work-required
   ;; Difficulty constants
   #:+difficulty-adjustment-interval+
   #:+pow-target-timespan+
   #:+pow-limit-bits+
   #:save-state
   #:load-state
   #:chain-state-pruned-height
   ;; UTXO persistence
   #:save-utxo-set
   #:load-utxo-set
   #:utxo-set-file-path
   #:utxo-set-dirty
   ;; UTXO iteration and statistics
   #:utxo-set-iterate
   #:utxo-set-total-amount
   #:utxo-set-distinct-txids
   #:compute-utxo-set-hash
   ;; Header index persistence
   #:save-header-index
   #:load-header-index
   #:append-header-entry
   ;; Integrity utilities
   #:compute-crc32
   ;; Transaction index
   #:tx-index
   #:make-tx-index
   #:tx-index-enabled
   #:tx-location
   #:make-tx-location
   #:tx-location-block-hash
   #:tx-location-tx-position
   #:init-tx-index
   #:close-tx-index
   #:txindex-add
   #:txindex-lookup
   #:txindex-remove
   #:txindex-contains-p
   #:txindex-count
   #:load-tx-index
   #:txindex-add-block
   #:txindex-remove-block
   #:build-tx-index))

(defpackage #:bitcoin-lisp.mempool
  (:use #:cl)
  (:export
   ;; Constants
   #:+default-max-mempool-bytes+
   #:+default-min-relay-fee-rate+
   #:+fee-history-size+
   #:+min-blocks-for-estimate+
   #:+fee-stats-flush-interval+
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
   #:mempool-min-fee-rate
   #:mempool-check-conflict
   #:mempool-remove-for-block
   #:mempool-get-transactions
   #:mempool-for-each
   ;; Block fee stats
   #:block-fee-stats
   #:make-block-fee-stats
   #:block-fee-stats-height
   #:block-fee-stats-median-rate
   #:block-fee-stats-low-rate
   #:block-fee-stats-high-rate
   #:block-fee-stats-tx-count
   ;; Fee estimator
   #:fee-estimator
   #:make-fee-estimator
   #:fee-estimator-entry-count
   #:fee-estimator-data-directory
   #:fee-estimator-blocks-since-flush
   #:fee-estimator-add-stats
   #:fee-estimator-ready-p
   #:fee-estimator-get-history
   #:calculate-tx-fee-rate
   #:compute-block-fee-stats
   ;; Fee stats persistence
   #:save-fee-stats
   #:load-fee-stats
   #:maybe-flush-fee-stats
   ;; Fee estimation
   #:estimate-fee-rate))

(defpackage #:bitcoin-lisp.validation
  (:use #:cl)
  (:export
   ;; Transaction validation
   #:validate-transaction-structure
   #:validate-transaction-contextual
   #:validate-transaction-scripts
   #:validate-transaction-for-mempool
   ;; Script execution and input validation
   #:execute-script
   #:script-is-witness-program-p
   #:get-input-witness
   #:validate-input-script
   ;; Script disassembly and classification
   #:disassemble-script
   #:classify-script
   #:script-type-to-string
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
   #:get-bip34-activation-height
   ;; Locktime validation
   #:check-transaction-final
   #:compute-median-time-past
   #:check-sequence-locks
   #:compute-script-flags-for-height
   ;; Difficulty validation
   #:validate-difficulty
   #:get-expected-bits
   #:testnet-min-difficulty-allowed-p
   #:testnet-walk-back-bits
   ;; Block weight
   #:calculate-block-weight
   #:+max-block-weight+
   ;; Sigops validation
   #:count-script-sigops
   #:count-transaction-sigops-cost
   #:+max-block-sigops-cost+
   #:+witness-scale-factor+
   ;; Constants
   #:+coinbase-maturity+
   #:+max-money+
   #:+bip34-activation-height-testnet+
   #:+bip34-activation-height-mainnet+
   #:+bip66-activation-height-testnet+
   #:+bip66-activation-height-mainnet+))

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
   ;; Compact block peer state (BIP 152)
   #:peer-compact-block-version
   #:peer-compact-block-high-bandwidth
   #:peer-pending-compact-block
   #:pending-compact-block
   #:make-pending-compact-block
   #:pending-compact-block-block-hash
   #:pending-compact-block-header
   #:pending-compact-block-transactions
   #:pending-compact-block-missing-indexes
   #:pending-compact-block-request-time
   #:pending-compact-block-use-wtxid
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
   ;; Compact block relay (BIP 152)
   #:send-compact-block-negotiation
   #:should-use-compact-blocks-p
   #:check-compact-block-timeout
   #:clear-pending-compact-block
   #:compact-block-stats
   ;; Peer health
   #:check-peer-health
   #:record-block-timeout
   #:peer-consecutive-ping-failures
   #:peer-block-timeout-count
   #:peer-address
   #:+max-ping-failures+
   #:+max-block-timeouts+
   ;; Peer database (peer-address struct shares symbol with peer accessor above)
   #:make-peer-address
   #:peer-address-ip
   #:peer-address-port
   #:peer-address-services
   #:peer-address-last-seen
   #:peer-address-last-attempt
   #:peer-address-successes
   #:peer-address-failures
   #:address-book
   #:make-address-book
   #:address-book-add
   #:address-book-lookup
   #:address-book-count
   #:address-book-sorted-peers
   #:address-book-record-success
   #:address-book-record-failure
   #:compute-peer-score
   #:save-address-book
   #:load-address-book
   #:peers-dat-path
   #:ipv4-to-mapped-ipv6
   #:ip-bytes-to-string
   #:string-to-ip-bytes
   ;; ADDRv2 support (BIP 155)
   #:peer-wants-addrv2
   #:handle-addrv2
   ;; Misbehavior and banning
   #:record-misbehavior
   #:ban-peer
   #:peer-banned-p
   #:clear-ban-list
   #:peer-misbehavior-score
   #:+misbehavior-ban-threshold+
   #:*banned-peers*
   ;; DoS protection
   #:check-peer-rate-limit
   #:check-handshake-timeout
   #:init-peer-rate-limiters
   #:peer-connect-time
   ;; Network params
   #:*testnet-port*
   #:*mainnet-port*
   #:*current-port*
   #:*dns-seeds*
   #:*testnet-dns-seeds*
   #:*mainnet-dns-seeds*
   ;; Checkpoints
   #:*testnet-checkpoints*
   #:*mainnet-checkpoints*
   #:network-checkpoints
   #:get-checkpoint-hash
   #:last-checkpoint-height
   #:relay-enabled-p))

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
   #:network-rpc-port
   #:*mainnet-relay-enabled*
   ;; Pruning
   #:*prune-target-mib*
   #:*prune-after-height*
   #:+min-blocks-to-keep+
   #:pruning-enabled-p
   #:automatic-pruning-p
   ;; Token bucket rate limiter
   #:token-bucket
   #:make-token-bucket
   #:make-rate-limiter
   #:token-bucket-allow-p
   #:token-bucket-rate
   #:token-bucket-burst
   #:token-bucket-tokens
   ;; Recent rejects filter
   #:recent-rejects
   #:make-rejects-filter
   #:recent-reject-p
   #:add-recent-reject
   #:clear-recent-rejects
   ;; DoS protection configuration
   #:*rate-limit-inv*
   #:*rate-limit-tx*
   #:*rate-limit-addr*
   #:*rate-limit-getdata*
   #:*rate-limit-headers*
   #:*rpc-rate-limit*
   #:+max-message-payload+
   #:+max-rpc-body-size+
   #:+handshake-timeout-seconds+
   #:*recent-rejects-max-size*
   ;; Node
   #:node
   #:*node*
   #:start-node
   #:stop-node
   #:node-status
   #:node-fee-estimator
   #:node-recent-rejects
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

