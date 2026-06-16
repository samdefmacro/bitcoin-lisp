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
   #:compact-size-length
   #:read-bytes
   #:write-bytes
   #:read-var-bytes
   #:write-var-bytes
   ;; Auto-growing byte buffer (faster than flexi-streams in hot paths)
   #:byte-buf
   #:make-byte-buf
   #:bb-pos
   #:bb-data
   #:bb-write-u8
   #:bb-write-u16-le
   #:bb-write-u32-le
   #:bb-write-u64-le
   #:bb-write-i32-le
   #:bb-write-i64-le
   #:bb-write-bytes
   #:bb-write-varint
   #:bb-finish
   ;; Byte-reader (zero-copy index-based input)
   #:byte-reader
   #:make-byte-reader
   #:make-byte-reader-from
   #:br-data
   #:br-pos
   #:br-eof-p
   #:br-read-u8
   #:br-read-u16-le
   #:br-read-u32-le
   #:br-read-u64-le
   #:br-read-i32-le
   #:br-read-i64-le
   #:br-read-bytes
   #:br-read-compact-size
   #:br-read-var-bytes
   #:br-read-transaction
   ;; Types
   #:dovector
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
   #:block-header-cached-hash
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
   #:+testnet3-magic+
   #:+testnet4-magic+
   #:+signet-magic+
   #:+regtest-magic+
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
   #:make-headers-message
   #:make-getdata-message
   #:make-inv-message
   #:make-tx-message
   #:make-block-message
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
   #:parse-block-locator-payload
   #:+max-inv-count+
   #:+max-headers-count+
   #:+max-addr-count+
   #:+max-locator-count+
   #:parse-block-payload
   #:read-bitcoin-block
   #:serialize-witness-block
   #:read-transaction
   #:serialize-transaction
   #:coinbase-input-p
   #:get-unix-time
   #:+universal-unix-epoch-offset+
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
   #:make-sendheaders-message
   #:make-wtxidrelay-message
   #:parse-feefilter-payload
   #:make-feefilter-message
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
   #:block-store-total-bytes
   #:block-storage-size-mib
   #:prune-old-blocks
   #:prune-blocks-to-height
   ;; UTXO set
   #:utxo-set
   #:make-utxo-set
   #:utxo-entry
   #:make-utxo-entry
   #:any-utxo-for-txid-p
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
   #:*testnet3-genesis-hash*
   #:*testnet4-genesis-hash*
   #:*signet-genesis-hash*
   #:*mainnet-genesis-hash*
   #:block-index-entry
   #:make-block-index-entry
   #:block-index-entry-hash
   #:block-index-entry-height
   #:block-index-entry-header
   #:block-index-entry-prev-entry
   #:block-index-entry-chain-work
   #:block-index-entry-status
   #:block-index-entry-tx-count
   #:get-block-index-entry
   #:add-block-index-entry
   #:get-block-at-height
   #:best-block-hash
   #:current-height
   #:update-chain-tip
   #:build-block-locator
   #:entry-on-active-chain-p
   #:find-fork-in-active-chain
   #:active-chain-entries-from
   #:bits-to-target
   #:derive-target
   #:target-to-bits
   #:calculate-chain-work
   #:calculate-next-work-required
   ;; Difficulty constants
   #:+difficulty-adjustment-interval+
   #:+pow-target-timespan+
   #:+pow-limit-bits+
   #:+pow-limit-target+
   #:+regtest-pow-limit-bits+
   #:+regtest-pow-limit-target+
   #:*pow-limit-target*
   #:save-state
   #:load-state
   #:chain-state-pruned-height
   ;; UTXO persistence
   #:save-utxo-set
   #:load-utxo-set
   #:utxo-set-file-path
   #:utxo-set-dirty
   ;; LevelDB CFFI bindings
   #:ensure-libleveldb-loaded
   #:leveldb-make-options
   #:leveldb-destroy-options
   #:leveldb-open
   #:leveldb-close
   #:leveldb-destroy-db
   #:with-leveldb
   #:leveldb-put
   #:leveldb-get
   #:leveldb-delete
   #:leveldb-write
   #:leveldb-make-writebatch
   #:leveldb-destroy-writebatch
   #:leveldb-writebatch-clear
   #:leveldb-writebatch-put
   #:leveldb-writebatch-delete
   #:with-leveldb-writebatch
   #:with-leveldb-iterator
   #:leveldb-iter-valid-p
   #:leveldb-iter-seek-to-first
   #:leveldb-iter-seek
   #:leveldb-iter-next
   #:leveldb-iter-key
   #:leveldb-iter-value
   ;; Coins-view (LevelDB-backed CCoinsViewDB equivalent)
   #:coins-view-db
   #:open-coins-view-db
   #:close-coins-view-db
   #:with-coins-view-db
   #:coins-view-db-get
   #:coins-view-db-put
   #:coins-view-db-erase
   #:coins-view-db-has-p
   #:coins-view-db-write-batch
   #:with-coins-view-batch
   #:coins-view-batch-put
   #:coins-view-batch-erase
   ;; Coins-view-cache (in-memory dirty-tracking layer)
   #:coins-view-cache
   #:make-coins-view-cache
   #:coins-view-cache-get
   #:coins-view-cache-has-p
   #:coins-view-cache-add
   #:coins-view-cache-spend
   #:coins-view-cache-flush
   #:coins-view-cache-base
   #:view-mem-bytes
   ;; coin-view-* (txid+vout signatures mirroring legacy utxo-set API)
   #:coin-view-get
   #:coin-view-has-p
   #:coin-view-add
   #:coin-view-spend
   #:coin-view-any-utxo-for-txid-p
   #:coin-view-apply-block
   #:coin-view-disconnect-block
   ;; Migration: utxoset.dat → LevelDB
   #:migrate-utxoset-dat-to-leveldb
   #:leveldb-utxo-migration-complete-p
   ;; UTXO iteration and statistics
   #:utxo-set-iterate
   #:utxo-set-total-amount
   #:utxo-set-distinct-txids
   #:compute-utxo-set-hash
   ;; Header index persistence
   #:save-header-index
   #:load-header-index
   ;; Integrity utilities
   #:compute-crc32
   #:save-file-with-crc32
   #:save-file-with-crc32-bb
   #:bb-write-utxo-entry-fields
   #:load-file-with-crc32
   #:write-utxo-entry-fields
   #:read-utxo-entry-fields
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
   #:make-entry-from-tx
   #:mempool-entry-transaction
   #:mempool-entry-fee
   #:mempool-entry-modified-fee
   #:mempool-deltas
   #:mempool-prioritise
   #:mempool-dat-path
   #:save-mempool-file
   #:read-mempool-file
   #:mempool-entry-size
   #:mempool-entry-vsize
   #:mempool-entry-wtxid
   #:mempool-entry-sigops
   #:mempool-entry-height
   #:mempool-entry-entry-time
   #:mempool-entry-fee-rate
   ;; Mempool entry links
   #:mempool-entry-parents
   #:mempool-entry-children
   ;; Mempool
   #:mempool
   #:make-mempool
   #:mempool-by-wtxid
   #:mempool-find-parents
   #:mempool-ancestors
   #:mempool-descendants
   #:mempool-ancestor-stats
   #:mempool-descendant-stats
   #:mempool-ancestor-fee-rate
   #:mempool-descendant-fee-rate
   #:mempool-remove-recursive
   #:mempool-expire
   #:mempool-trim
   #:mempool-effective-min-fee-rate
   #:mempool-orphan-pool
   ;; Orphan pool
   #:make-orphan-pool
   #:orphan-pool-count
   #:orphan-entry-transaction
   #:orphan-entry-from-peer
   #:orphan-add
   #:orphan-remove
   #:orphan-tx
   #:orphans-depending-on
   #:orphan-erase-for-peer
   #:orphan-expire
   #:tx-signals-rbf-p
   #:find-rbf-conflicts
   #:check-rbf-rules
   #:*mempool-full-rbf*
   #:mempool-has
   #:mempool-get
   #:mempool-spending-tx
   #:mempool-add
   #:accept-validated-tx
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
   ;; Package relay (submitpackage)
   #:validate-package-for-mempool
   #:package-well-formed
   #:package-child-with-parents-tree-p
   #:+max-package-count+
   #:+max-package-weight+
   #:package-tx-result
   #:package-tx-result-txid
   #:package-tx-result-wtxid
   #:package-tx-result-status
   #:package-tx-result-vsize
   #:package-tx-result-fee
   #:package-tx-result-effective-feerate
   #:package-tx-result-effective-includes
   #:package-tx-result-other-wtxid
   #:package-tx-result-error
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
   #:activate-block
   #:find-fork-point
   #:perform-reorg
   #:invalidate-block
   #:reconsider-block
   #:precious-block
   #:decode-coinbase-height
   #:get-bip34-activation-height
   #:get-bip66-activation-height
   #:get-bip65-activation-height
   #:get-csv-activation-height
   #:get-taproot-activation-height
   #:initialize-undo-storage
   #:delete-undo-file
   #:prune-stale-undo-files
   ;; Locktime validation
   #:check-transaction-final
   #:compute-median-time-past
   #:check-sequence-locks
   #:compute-script-flags-for-height
   #:compute-standard-script-flags-for-height
   #:get-segwit-activation-height
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
   #:+bip34-activation-height-testnet3+
   #:+bip34-activation-height-mainnet+
   #:+bip66-activation-height-testnet3+
   #:+bip66-activation-height-mainnet+
   ;; Coinbase / subsidy (for the block assembler)
   #:calculate-block-subsidy
   #:encode-bip34-height))

(defpackage #:bitcoin-lisp.mining
  (:use #:cl)
  (:export
   #:assemble-block-template
   #:next-block-required-bits
   #:build-witness-commitment-script
   #:*last-block-template*
   ;; block construction + mining (builder.lisp)
   #:build-coinbase-transaction
   #:assemble-full-block
   #:mine-block
   ;; block-template struct + accessors
   #:block-template
   #:block-template-height
   #:block-template-prev-hash
   #:block-template-bits
   #:block-template-version
   #:block-template-curtime
   #:block-template-mintime
   #:block-template-transactions
   #:block-template-total-fees
   #:block-template-total-weight
   #:block-template-total-sigops
   #:block-template-coinbase-value
   #:block-template-witness-commitment
   #:block-template-default-witness-commitment-script
   ;; constants
   #:+block-reserved-weight+))

(defpackage #:bitcoin-lisp.networking
  (:use #:cl)
  (:export
   ;; Connection
   #:connection
   #:connection-connected
   #:connection-host
   #:make-tcp-connection
   #:close-connection
   #:send-bytes
   #:receive-bytes
   ;; Inbound listening
   #:open-listener
   #:close-listener
   #:accept-connection
   ;; Shutdown
   #:request-ibd-stop
   #:reset-ibd-stop
   #:ibd-stop-requested-p
   ;; Tx-request tracking
   #:retry-timed-out-tx-requests
   #:reset-tx-requests
   #:tx-request-wanted-p
   #:tx-request-received
   ;; Peer
   #:peer
   #:make-peer
   #:peer-state
   #:peer-version
   #:peer-services
   #:peer-start-height
   #:peer-user-agent
   #:peer-ping-latency
   #:peer-inbound
   #:peer-getaddr-sent
   #:connect-peer
   #:disconnect-peer
   #:make-inbound-peer
   #:send-message
   #:receive-message
   #:perform-handshake
   #:perform-inbound-handshake
   #:send-post-handshake-messages
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
   #:diversify-by-netgroup
   #:ip-netgroup
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
   #:record-block-received-from-peer
   #:peer-stalling-p
   #:consider-peer-eviction
   #:peer-consecutive-ping-failures
   #:peer-block-timeout-count
   #:peer-last-block-received-time
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
   #:peer-address-last-success
   #:peer-address-n-attempts
   #:peer-address-ref-count
   #:peer-address-in-tried
   #:address-book
   #:make-address-book
   #:address-book-add
   #:address-book-lookup
   #:address-book-count
   #:address-book-good
   #:address-book-attempt
   #:address-book-connected
   #:address-book-select
   #:address-book-get-addr
   #:resolve-tried-collisions
   #:addr-info-terrible-p
   #:net-group-key
   #:save-address-book
   #:load-address-book
   #:peers-dat-path
   #:ipv4-to-mapped-ipv6
   #:ip-bytes-to-string
   #:string-to-ip-bytes
   ;; ADDRv2 support (BIP 155)
   #:peer-wants-addrv2
   #:peer-prefers-headers
   #:peer-feefilter-rate
   #:peer-wtxid-relay
   #:handle-addrv2
   ;; Misbehavior and banning
   #:record-misbehavior
   #:ban-peer
   #:peer-banned-p
   #:clear-ban-list
   #:ban-address
   #:unban-address
   #:list-bans
   #:*total-bytes-sent*
   #:*total-bytes-received*
   #:discourage-peer
   #:peer-discouraged-p
   #:clear-discouraged
   #:peer-misbehavior-score
   #:+misbehavior-discourage-threshold+
   #:*banned-peers*
   ;; DoS protection
   #:check-peer-rate-limit
   #:check-handshake-timeout
   #:init-peer-rate-limiters
   #:peer-connect-time
   ;; Network params
   #:*testnet3-port*
   #:*testnet4-port*
   #:*signet-port*
   #:*mainnet-port*
   #:*current-port*
   #:*dns-seeds*
   #:*testnet3-dns-seeds*
   #:*testnet4-dns-seeds*
   #:*testnet4-fixed-seeds*
   #:*signet-dns-seeds*
   #:*regtest-dns-seeds*
   #:*mainnet-dns-seeds*
   ;; Checkpoints
   #:*testnet3-checkpoints*
   #:*testnet4-checkpoints*
   #:*signet-checkpoints*
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
   #:+testnet3+
   #:+testnet4+
   #:+signet+
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
   #:*accept-datacarrier*
   #:*max-datacarrier-bytes*
   #:*permit-bare-multisig*
   #:pruning-enabled-p
   #:automatic-pruning-p
   #:minimum-chain-work
   #:*minimum-chain-work-override*
   #:*parallel-block-validation*
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
   #:*rate-limit-serve*
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
   #:stop-file-logging
   #:maybe-periodic-flush))

