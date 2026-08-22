(defpackage #:bitcoin-lisp.crypto
  (:use #:cl)
  (:export
   ;; Hash functions
   #:sha256
   #:hash256
   #:sha3-256
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
   ;; Wallet crypter (wallet P6): SHA-512 passphrase KDF + AES-256-CBC.
   ;; PKCS7-PAD/PKCS7-UNPAD stay internal -- they are only meaningful as
   ;; part of the two AES entry points below.
   #:crypter-derive-key
   #:aes-256-cbc-encrypt
   #:aes-256-cbc-decrypt
   #:+wallet-crypto-key-size+
   #:+wallet-crypto-salt-size+
   #:+wallet-crypto-iv-size+
   ;; SipHash (BIP 152)
   #:siphash-2-4
   #:compute-siphash-key
   #:compute-short-txid
   #:bytes-to-uint64-le
   #:uint64-to-bytes-le
   ;; Utilities
   #:bytes-to-hex
   #:hmac-sha256
   #:hex-to-bytes
   #:reverse-bytes
   ;; BIP324 cipher suite: forward-secure wrappers + HKDF only. The bare
   ;; ChaCha20/AEAD primitives stay internal -- BIP324's cipher/transport
   ;; layers consume exactly this surface (as in Core), and exposing the
   ;; unratcheted primitives would invite bypassing forward secrecy.
   #:+poly1305-taglen+
   #:make-fschacha20
   #:fschacha20-crypt
   #:make-fschacha20poly1305
   #:fsaead-encrypt
   #:fsaead-decrypt
   #:hkdf-sha256-extract
   #:hkdf-sha256-expand32
   ;; MuHash3072 (BIP-less; Core coinstats / gettxoutsetinfo muhash mode)
   #:+muhash-modulus+
   #:make-muhash
   #:muhash
   #:muhash-insert
   #:muhash-remove
   #:muhash-combine
   #:muhash-divide
   #:muhash-finalize
   #:muhash-element-num
   #:muhash-numerator
   #:muhash-denominator
   ;; ElligatorSwift (BIP324 key exchange; optional libsecp256k1 module)
   #:ellswift-available-p
   #:ellswift-create
   #:ellswift-decode
   #:bip324-ecdh
   ;; BIP324 session cipher (Core BIP324Cipher)
   #:make-bip324-cipher
   #:bip324-cipher-initialize
   #:bip324-cipher-initialized-p
   #:bip324-cipher-encrypt
   #:bip324-cipher-decrypt-length
   #:bip324-cipher-decrypt
   #:bip324-cipher-our-pubkey
   #:bip324-cipher-session-id
   #:bip324-cipher-send-garbage-terminator
   #:bip324-cipher-recv-garbage-terminator
   #:+bip324-expansion+
   #:+bip324-garbage-terminator-len+
   #:+bip324-length-len+
   #:+bip324-header-len+
   ;; secp256k1 ECDSA
   #:verify-signature
   #:parse-public-key
   #:public-key-valid-p
   #:decompress-public-key
   #:ensure-secp256k1-loaded
   #:cleanup-secp256k1
   ;; Signing (private key -> pubkey / signature) + WIF
   #:valid-private-key-p
   #:derive-public-key
   #:sign-ecdsa
   #:sign-recoverable-compact
   #:recover-public-key
   #:private-key-to-wif
   #:wif-to-private-key
   #:tweak-add-public-key
   ;; BIP32 hierarchical deterministic keys
   #:hmac-sha512
   #:ext-key
   #:make-ext-key
   #:ext-key-p
   #:ext-key-version
   #:ext-key-depth
   #:ext-key-parent-fingerprint
   #:ext-key-child-number
   #:ext-key-chain-code
   #:ext-key-key
   #:ext-key-privatep
   #:ext-key-public-bytes
   #:bip32-master-key
   #:bip32-derive-child
   #:bip32-derive-path
   #:bip32-neuter
   #:bip32-serialize
   #:bip32-parse
   #:+bip32-hardened+
   #:+secp256k1-order+
   #:+xprv-mainnet+
   #:+xpub-mainnet+
   #:+xprv-testnet+
   #:+xpub-testnet+
   #:taproot-tweak-private-key
   ;; Schnorr / x-only pubkeys (BIP 340)
   #:verify-schnorr-signature
   #:sign-schnorr
   #:derive-xonly-pubkey
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
   #:write-tx-out
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
   #:br-read-witness-stack
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
   #:br-read-tx-out
   #:bb-write-tx-out
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
   #:transaction-wire-bytes
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
   #:+node-p2p-v2+
   ;; Message framing helpers
   #:command-to-bytes
   #:bytes-to-command
   ;; Version message
   #:+protocol-version+
   #:version-message
   #:make-version-message-bytes
   #:*user-agent*
   #:+client-version+
   #:client-version-string
   #:format-user-agent
   #:subversion-with-build-rev
   #:read-version-message
   #:version-message-version
   #:version-message-services
   #:version-message-start-height
   #:version-message-user-agent
   #:version-message-relay
   #:make-verack-message
   #:make-ping-message
   #:make-pong-message
   #:make-getblocks-message
   #:make-getheaders-message
   #:make-headers-message
   #:make-getdata-message
   #:make-inv-message
   #:make-notfound-message
   #:+node-compact-filters+
   #:parse-getcfilters-payload
   #:parse-getcfcheckpt-payload
   #:make-cfilter-message
   #:make-cfheaders-message
   #:make-cfcheckpt-message
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
   #:+inv-type-wtx+
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
   ;; BIP174 PSBT
   #:psbt #:make-psbt #:psbt-p #:psbt-tx #:psbt-global #:psbt-inputs #:psbt-outputs
   #:psbt-map #:make-psbt-map #:psbt-map-records
   #:psbt-key-type #:psbt-make-record #:psbt-map-find #:psbt-map-collect
   #:psbt-map-set #:psbt-map-remove-type
   #:parse-psbt #:serialize-psbt #:encode-psbt #:decode-psbt #:make-empty-psbt
   #:*psbt-magic*
   #:+psbt-global-unsigned-tx+ #:+psbt-global-xpub+ #:+psbt-global-version+
   #:+psbt-global-proprietary+
   #:+psbt-in-non-witness-utxo+ #:+psbt-in-witness-utxo+ #:+psbt-in-partial-sig+
   #:+psbt-in-sighash+ #:+psbt-in-redeem-script+ #:+psbt-in-witness-script+
   #:+psbt-in-bip32+ #:+psbt-in-final-scriptsig+ #:+psbt-in-final-scriptwitness+
   #:+psbt-in-ripemd160+ #:+psbt-in-sha256+ #:+psbt-in-hash160+ #:+psbt-in-hash256+
   #:+psbt-in-tap-key-sig+ #:+psbt-in-tap-internal-key+ #:+psbt-in-proprietary+
   #:+psbt-out-redeem-script+ #:+psbt-out-witness-script+ #:+psbt-out-bip32+
   #:+psbt-out-tap-internal-key+ #:+psbt-out-proprietary+
   #:coinbase-input-p
   #:get-unix-time
   #:get-real-unix-time
   #:*mock-time*
   #:+universal-unix-epoch-offset+
   #:read-net-addr
   #:write-net-addr
   #:net-addr
   #:make-net-addr
   #:make-empty-net-addr
   #:net-addr-services
   #:net-addr-ip
   #:net-addr-port
   #:net-addr-net
   #:net-addr-network
   #:v1-compatible-network-p
   #:read-hash256
   #:write-hash256
   ;; Compact block (BIP 152)
   #:compact-block
   #:make-cmpctblock-message
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
   #:make-blocktxn-message
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
   #:+max-addrv2-address-size+
   #:*addrv2-addr-sizes*
   #:network-bip155-id
   #:bip155-network-keyword
   #:read-net-addr-v2
   #:write-net-addr-v2
   #:make-sendaddrv2-message
   #:make-getaddr-message
   #:make-sendheaders-message
   #:make-wtxidrelay-message
   #:+txreconciliation-version+
   #:+recon-q-precision+
   #:make-reqrecon-message
   #:parse-reqrecon-payload
   #:make-sketch-message
   #:parse-sketch-payload
   #:make-reqsketchext-message
   #:make-reconcildiff-message
   #:parse-reconcildiff-payload
   #:make-sendtxrcncl-message
   #:parse-sendtxrcncl-payload
   #:parse-feefilter-payload
   #:make-feefilter-message
   #:make-addrv2-message
   #:parse-addrv2-payload
   ;; TxOutCompression (compressor.lisp — Core compressor.{h,cpp})
   #:bb-write-core-varint
   #:br-read-core-varint
   #:compress-amount
   #:decompress-amount
   #:compress-script
   #:decompress-script
   #:special-script-size
   #:bb-write-compressed-script
   #:br-read-compressed-script
   #:bb-write-compressed-tx-out
   #:br-read-compressed-tx-out
   #:bb-write-compressed-coin
   #:br-read-compressed-coin
   #:read-core-varint
   #:read-compressed-script
   #:read-compressed-tx-out
   #:read-compressed-coin))

(defpackage #:bitcoin-lisp.storage
  (:use #:cl)
  (:export
   ;; Block store
   #:block-store
   #:make-block-store
   #:init-block-store
   #:*flat-block-files*
   #:block-flat-file-number
   #:store-undo-flat
   #:read-undo-flat
   #:block-file-info
   #:block-file-info-blocks
   #:block-file-info-size
   #:block-file-info-height-first
   #:block-file-info-height-last
   #:block-store-file-info
   #:rebuild-block-file-info
   #:reindex-block-index
   #:migrate-blocks-to-flat-files
   #:count-legacy-blocks
   #:prune-flat-block-file
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
   #:script-unspendable-p
   #:script-has-valid-ops-p
   #:+max-script-size+
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
   #:make-genesis-block
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
   #:block-index-entry-file
   #:block-index-entry-data-pos
   #:block-index-entry-undo-pos
   #:note-block-position
   #:%record-block-position
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
   #:+signet-pow-limit-bits+
   #:+signet-pow-limit-target+
   #:+regtest-pow-limit-target+
   #:*pow-limit-target*
   #:save-state
   #:load-state
   #:chain-state-pruned-height
   #:chain-state-prune-floor
   #:lift-prune-floor-on-promotion
   ;; Chainstate roles / assumeutxo identity (Core ChainstateManager)
   #:chain-state-coins-view
   #:chain-state-coins-cache-bytes
   #:chain-state-from-snapshot-blockhash
   #:chain-state-assumeutxo-status
   #:chain-state-target-blockhash
   #:chain-state-target-utxohash
   #:chain-state-storage-suffix
   #:select-current-chainstate
   #:select-historical-chainstate
   #:select-validated-chainstate
   #:state-file-path
   #:chainstate-leveldb-path
   ;; Target block / historical-chainstate path (Core SetTargetBlock)
   #:entry-ancestor-at-height
   #:set-chainstate-target
   #:clear-snapshot-chainstate-identity
   #:target-ancestor-entry
   #:entry-target-ancestor-p
   #:chain-state-target-height
   #:best-header-entry
   ;; Per-chainstate coins-view lifecycle
   #:open-chainstate-coins-view
   #:close-chainstate-coins-view
   ;; Snapshot chainstate on-disk marker (Core node/utxo_snapshot)
   #:snapshot-base-blockhash-path
   #:write-snapshot-base-blockhash
   #:read-snapshot-base-blockhash
   #:find-assumeutxo-chainstate-dir
   #:delete-snapshot-chainstate-files
   #:rename-snapshot-chainstate-dir-invalid
   #:promote-snapshot-chainstate-files
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
   #:leveldb-open-tuned
   #:calculate-cache-sizes
   #:cache-sizes-tx-index
   #:cache-sizes-filter-index
   #:cache-sizes-block-tree-db
   #:cache-sizes-coins-db
   #:cache-sizes-coins
   #:leveldb-close
   #:leveldb-destroy-db
   #:with-leveldb
   #:leveldb-put
   #:leveldb-get
   #:leveldb-delete
   #:leveldb-write
   #:leveldb-compact
   #:leveldb-make-writebatch
   #:leveldb-destroy-writebatch
   #:leveldb-writebatch-clear
   #:leveldb-writebatch-put
   #:leveldb-writebatch-delete
   #:with-leveldb-writebatch
   #:with-leveldb-iterator
   #:leveldb-iter-valid-p
   #:leveldb-iter-check-error
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
   #:coins-view-cache-compact
   #:coins-view-cache-get
   #:coins-view-cache-has-p
   #:coins-view-cache-add
   #:coins-view-cache-spend
   #:coins-view-cache-flush
   #:coins-view-cache-sync
   #:coins-view-cache-uncache
   #:with-coins-to-uncache
   #:coins-view-db-best-block
   #:coins-view-cache-load-best-block
   #:coins-view-batch-set-best-block
   #:coins-view-cache-wipe
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
   #:compute-utxo-set-muhash
   #:coin-muhash-element
   #:coin-muhash-element*
   ;; coinstatsindex (per-height UTXO stats + MuHash)
   #:coinstatsindex
   #:coinstats
   #:init-coinstatsindex
   #:close-coinstatsindex
   #:coinstatsindex-db
   #:coinstatsindex-enabled
   #:coinstatsindex-height
   #:coinstatsindex-best
   #:coinstatsindex-get-stats
   #:coinstatsindex-add-block
   #:coinstatsindex-record-matches-block-p
   #:coinstatsindex-seed-genesis
   #:coinstatsindex-set-best
   #:coinstatsindex-clear-best
   #:build-coinstatsindex
   #:apply-block-to-coinstats
   #:coinstats-muhash
   #:coinstats-txout-count
   #:coinstats-bogo-size
   #:coinstats-total-amount
   #:coinstats-total-subsidy
   #:coinstats-total-prevout-spent
   #:coinstats-total-new-outputs-ex-coinbase
   #:coinstats-total-coinbase
   #:coinstats-unspendable-genesis
   #:coinstats-unspendable-bip30
   #:coinstats-unspendable-scripts
   #:coinstats-unspendable-unclaimed
   ;; Header index persistence
   #:save-header-index
   #:load-header-index
   ;; Integrity utilities
   #:compute-crc32
   #:save-file-with-crc32
   #:save-file-with-crc32-bb
   #:bb-write-utxo-entry-fields
   ;; Flat-file storage engine (flatfile.{h,cpp}, util/obfuscation.h)
   #:+blockfile-chunk-size+
   #:+undofile-chunk-size+
   #:+max-blockfile-size+
   #:+storage-header-bytes+
   #:+undo-data-disk-overhead+
   #:make-flat-file-pos
   #:flat-file-pos-file
   #:flat-file-pos-pos
   #:flat-file-pos-null-p
   #:obfuscate!
   #:obfuscation-key-active-p
   #:make-obfuscation-key
   #:zero-obfuscation-key
   #:read-or-create-xor-key
   #:make-flat-file-seq
   #:flat-file-name
   #:with-flat-file
   #:flat-file-allocate
   #:flat-file-flush
   #:flat-record-bytes
   #:undo-record-checksum
   #:undo-record-bytes
   #:parse-flat-record-header
   #:find-next-record
   ;; Core CBlockUndo record (undo.h)
   #:serialize-block-undo
   #:deserialize-block-undo
   #:block-undo-from-spent-utxos
   #:spent-utxos-from-block-undo
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
   #:txindex-set-best-block
   #:txindex-best-block
   #:load-tx-index
   #:txindex-add-block
   #:txindex-remove-block
   #:build-tx-index
   ;; BIP158 block filters (basic filter)
   #:+basic-filter-type+
   #:+basic-filter-p+
   #:+basic-filter-m+
   #:build-gcs-filter
   #:gcs-filter-match
   #:gcs-filter-match-any
   #:gcs-fast-range
   #:block-filter-siphash-keys
   #:basic-filter-elements
   #:build-basic-block-filter
   #:block-filter-hash
   #:block-filter-header
   #:compute-block-filter-header
   #:+zero-filter-header+
   ;; BIP157/158 block filter index
   #:blockfilterindex
   #:make-blockfilterindex
   #:blockfilterindex-enabled
   #:blockfilterindex-db
   #:init-blockfilterindex
   #:close-blockfilterindex
   #:blockfilterindex-add-block
   #:blockfilterindex-get
   #:blockfilterindex-get-filter
   #:blockfilterindex-get-header
   #:blockfilterindex-has-block-p
   #:blockfilterindex-best
   #:blockfilterindex-height
   #:blockfilterindex-set-best
   #:blockfilterindex-clear-best
   #:blockfilterindex-wipe
   #:blockfilterindex-ensure-genesis-anchor
   #:build-blockfilterindex))

(defpackage #:bitcoin-lisp.mempool
  (:use #:cl)
  (:export
   ;; Constants
   #:+default-max-mempool-bytes+
   #:*max-mempool-bytes*
   #:+default-min-relay-fee-rate+
   #:+fee-history-size+
   #:+min-blocks-for-estimate+
   #:+fee-stats-flush-interval+
   ;; FeeFrac (Core util/feefrac.{h,cpp})
   #:feefrac
   #:make-feefrac
   #:copy-feefrac
   #:feefrac-p
   #:feefrac-fee
   #:feefrac-size
   #:feefrac-empty-p
   #:feefrac+
   #:feefrac-
   #:feefrac=
   #:feerate-compare
   #:feefrac<<
   #:feefrac>>
   #:feefrac-compare
   #:feefrac<
   #:feefrac>
   #:feefrac<=
   #:feefrac>=
   #:feefrac-evaluate-fee-down
   #:feefrac-evaluate-fee-up
   #:compare-chunks
   ;; Cluster linearization (Core cluster_linearize.h)
   #:+max-cluster-count+
   #:do-bits
   #:depgraph
   #:make-depgraph
   #:depgraph-p
   #:depgraph-positions
   #:depgraph-position-range
   #:depgraph-tx-count
   #:depgraph-tx-feerate
   #:depgraph-ancestors
   #:depgraph-descendants
   #:depgraph-add-transaction
   #:depgraph-remove-transactions
   #:depgraph-add-dependencies
   #:depgraph-reduced-parents
   #:depgraph-reduced-children
   #:depgraph-subset-feerate
   #:depgraph-connected-component
   #:depgraph-find-connected-component
   #:depgraph-connected-p
   #:depgraph-acyclic-p
   #:depgraph-topo-sorted
   #:topological-subset-p
   #:linearization-topological-p
   #:setinfo
   #:make-setinfo
   #:setinfo-transactions
   #:setinfo-feerate
   #:chunk-linearization
   #:chunk-linearization-info
   #:ancestor-sort-linearization
   #:post-linearize
   #:linearize
   ;; TxGraph (Core txgraph.{h,cpp})
   #:+max-cluster-size+
   #:txgraph
   #:make-txgraph
   #:txgraph-p
   #:txgraph-tx-count
   #:txgraph-oversized-p
   #:tx-handle
   #:tx-handle-p
   #:tx-handle-id
   #:tx-handle-data
   #:txgraph-add-transaction
   #:txgraph-remove-transaction
   #:txgraph-add-dependency
   #:txgraph-add-dependencies
   #:txgraph-set-transaction-fee
   #:txgraph-exists-p
   #:txgraph-get-individual-feerate
   #:txgraph-get-main-chunk-feerate
   #:txgraph-get-cluster
   #:txgraph-get-cluster-chunks
   #:txgraph-get-ancestors
   #:txgraph-get-descendants
   #:txgraph-get-ancestors-union
   #:txgraph-get-descendants-union
   #:txgraph-compare-main-order
   #:txgraph-count-distinct-clusters
   #:txgraph-rbf-diagrams
   #:txgraph-package-rbf-diagrams
   #:txgraph-get-worst-main-chunk
   #:txgraph-trim
   #:txgraph-sanity-check
   #:block-builder
   #:block-builder-p
   #:make-block-builder
   #:block-builder-current-chunk
   #:block-builder-current-chunk-feerate
   #:block-builder-include
   #:block-builder-skip
   #:block-builder-finish
   ;; Mempool entry
   #:mempool-entry
   #:make-mempool-entry
   #:make-entry-from-tx
   #:sigop-adjusted-vsize
   #:mempool-entry-transaction
   #:mempool-entry-fee
   #:mempool-entry-modified-fee
   #:mempool-deltas
   #:mempool-prioritise
   #:mempool-unbroadcast
   #:mempool-add-unbroadcast
   #:mempool-remove-unbroadcast
   #:mempool-unbroadcast-txids
   #:mempool-unbroadcast-count
   #:mempool-unbroadcast-p
   #:mempool-dat-path
   #:save-mempool-file
   #:read-mempool-file
   #:mempool-entry-size
   #:mempool-entry-usage
   #:mempool-entry-vsize
   #:mempool-entry-wtxid
   #:mempool-entry-sigops
   #:mempool-entry-height
   #:mempool-entry-entry-time
   #:mempool-entry-sequence
   #:mempool-sequence
   #:mempool-entry-fee-rate
   ;; Mempool entry links
   #:mempool-entry-parents
   #:mempool-entry-children
   #:mempool-entry-graph-handle
   ;; Mempool
   #:mempool
   #:make-mempool
   #:mempool-graph
   #:*txgraph-shadow-checks*
   #:mempool-by-wtxid
   #:mempool-find-parents
   #:single-truc-checks
   #:+truc-version+
   #:+truc-max-vsize+
   #:+truc-child-max-vsize+
   #:+truc-ancestor-limit+
   #:mempool-ancestors
   #:mempool-descendants
   #:mempool-ancestor-stats
   #:mempool-descendant-stats
   #:mempool-ancestor-fee-rate
   #:mempool-descendant-fee-rate
   #:mempool-remove-recursive
   #:mempool-expire
   #:*mempool-expiry-hours*
   #:*min-relay-fee-rate*
   #:mempool-trim-to-size
   #:*cluster-count-limit*
   #:*cluster-size-limit*
   #:mempool-effective-min-fee-rate
   #:mempool-decayed-rolling-min-fee-rate
   #:mempool-orphan-pool
   ;; Orphan pool (Core TxOrphanage at d3056bc: wtxid-keyed, per-peer
   ;; announcement accounting, DoS-bounded eviction, no time expiry)
   #:make-orphan-pool
   #:orphan-pool-count
   #:orphan-entry-transaction
   #:orphan-add
   #:orphan-remove
   #:orphan-tx
   #:orphan-have
   #:orphan-have-from-peer
   #:orphan-announcers
   #:orphan-children-from-peer
   #:orphans-depending-on
   #:orphan-erase-for-peer
   #:orphan-erase-for-block
   #:orphan-total-usage
   #:orphan-total-latency-score
   #:orphan-usage-by-peer
   #:orphan-announcements-from-peer
   #:+max-orphanage-latency-score+
   #:+reserved-orphan-weight-per-peer+
   #:tx-signals-rbf-p
   #:find-rbf-conflicts
   #:check-rbf-rules
   #:check-package-rbf-rules
   #:*mempool-full-rbf*
   #:mempool-has
   #:mempool-get
   #:mempool-get-by-wtxid
   #:mempool-spending-tx
   #:mempool-add
   #:accept-validated-tx
   #:mempool-remove
   #:*mempool-removal-reason*
   #:mempool-count
   #:mempool-total-size
   #:mempool-dynamic-usage
   #:transaction-dynamic-usage
   #:mempool-min-fee-rate
   #:mempool-check-conflict
   #:mempool-package-fits-cluster-limits-p
   #:mempool-remove-for-block
   #:mempool-remove-spenders
   #:mempool-update-for-reorg
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
   ;; Core CBlockPolicyEstimator (G7-21)
   #:*block-policy-estimator*
   #:make-block-policy-estimator
   #:bpe-note-entry
   #:bpe-note-removal
   #:bpe-note-block
   #:bpe-smart-fee-sat-per-vb
   #:bpe-estimate-smart-fee
   #:bpe-write-to-stream
   #:bpe-read-into
   #:*accept-stale-fee-estimates*
   ;; Fee estimation
   #:estimate-fee-rate
   #:highest-target-tracked))

(defpackage #:bitcoin-lisp.validation
  (:use #:cl)
  (:export
   ;; Transaction validation
   #:validate-transaction-structure
   #:validate-transaction-contextual
   #:validate-transaction-scripts
   #:validate-transaction-for-mempool
   ;; Package relay (submitpackage + opportunistic 1p1c)
   #:validate-package-for-mempool
   #:package-hash
   #:package-truc-checks
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
   #:test-block-validity
   #:validate-block-scripts
   #:find-witness-commitment
   #:validate-witness-commitment
   #:update-uncommitted-block-structures
   #:witness-reserved-value
   #:block-witness-stripped-p
   #:compute-witness-merkle-root
   #:check-proof-of-work
   #:compute-merkle-root
   ;; BIP325 signet block-solution validation
   #:check-signet-block-solution
   #:make-signet-txs
   #:signet-challenge-for-network
   #:*signet-challenge*
   #:*default-signet-challenge*
   #:connect-block
   #:activate-block
   #:find-fork-point
   ;; Tx-relay tip structures (Core recent-confirmed filter +
   ;; most-recent-block tx map)
   #:recently-confirmed-p
   #:most-recent-block-tx
   #:most-recent-cmpctblock
   #:note-block-connected
   #:reset-recent-confirmed
   ;; The reconsiderable rejects filter (Core's second rejects filter)
   #:*recent-rejects-reconsiderable*
   #:reconsiderable-reject-p
   #:add-reconsiderable-reject
   #:clear-reconsiderable-rejects
   #:perform-reorg
   #:activate-best-chain
   #:best-valid-tip
   #:get-undo-data
   #:invalidate-block
   #:reconsider-block
   #:precious-block
   #:decode-coinbase-height
   #:get-bip34-activation-height
   #:get-bip66-activation-height
   #:get-bip65-activation-height
   #:get-csv-activation-height
   #:+max-future-block-time+
   #:+max-timewarp+
   #:get-taproot-activation-height
   #:initialize-undo-storage
   #:migrate-undo-to-flat
   #:delete-undo-file
   #:prune-stale-undo-files
   ;; Locktime validation
   #:check-transaction-final
   #:compute-median-time-past
   #:compute-median-time-past-from-entry
   #:header-time-too-old-p
   #:check-sequence-locks
   #:compute-script-flags-for-height
   #:+standard-script-verify-flags+
   #:get-segwit-activation-height
   ;; Difficulty validation
   #:validate-difficulty
   #:bip94-timewarp-violation-p
   #:get-expected-bits
   #:testnet-min-difficulty-allowed-p
   #:testnet-walk-back-bits
   ;; Block weight
   #:script-checks-skippable-p
   #:calculate-block-weight
   #:+max-block-weight+
   ;; Sigops validation
   #:count-script-sigops
   #:count-transaction-sigops-cost
   #:+max-block-sigops-cost+
   #:+witness-scale-factor+
   ;; Dust / standardness (wallet spend path)
   #:dust-threshold
   #:+dust-relay-fee-rate+
   #:+max-standard-tx-weight+
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
   #:next-block-mintime
   #:build-witness-commitment-script
   #:*last-block-template*
   #:*block-min-tx-fee-rate*
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
   #:+block-reserved-weight+
   #:+minimum-block-reserved-weight+
   #:*block-reserved-weight*
   #:*block-max-weight*))

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
   ;; Non-blocking send buffer (Core vSendMsg / fPauseSend / SocketSendData)
   #:connection-send-paused-p
   #:connection-send-stalled-p
   #:flush-send-buffer
   #:flush-peer-send-buffers
   #:+max-send-buffer-bytes+
   ;; BIP324 v2 transport
   #:*v2-transport-enabled*
   #:v2-available-p
   ;; SOCKS5 outbound proxy (Core netbase.cpp Socks5)
   #:*proxy*
   #:*onion-proxy*
   #:proxy
   #:make-proxy
   #:proxy-host
   #:proxy-port
   #:proxy-randomize-credentials
   #:socks5-connect
   #:socks5-error
   #:socks5-error-phase
   #:next-proxy-credentials
   #:*onion-proxy-explicit*
   ;; Tor control client (Core torcontrol.cpp): inbound onion service
   #:tor-controller
   #:tor-controller-service-id
   #:tor-controller-running
   #:start-tor-control
   #:stop-tor-control
   #:parse-torcontrol-spec
   ;; Inbound listening
   #:open-listener
   #:close-listener
   #:accept-connection
   ;; Shutdown
   #:request-ibd-stop
   #:reset-ibd-stop
   #:ibd-stop-requested-p
   #:join-thread-or-destroy
   ;; Tx-request tracking
   #:retry-timed-out-tx-requests
   #:reset-tx-requests
   #:tx-request-wanted-p
   #:tx-request-received
   #:tx-request-notfound
   #:tx-request-disconnected-peer
   #:tx-request-count
   #:process-tx-requests
   ;; Steady-state message pump (post-IBD receive loop)
   #:pump-peer-messages
   #:ibd-context-headers-received
   ;; Trickled tx announcement flushing
   #:flush-tx-announcements
   ;; Local-submission broadcast (unbroadcast set)
   #:announce-mempool-tx
   #:reattempt-initial-broadcast
   #:maybe-reattempt-initial-broadcast
   #:reset-initial-broadcast-schedule
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
   #:peer-live-p
   #:release-outbound-protection
   #:maybe-protect-outbound-peer
   #:credit-block-announcement
   #:peer-last-block-announcement
   #:consider-chain-sync-eviction
   #:evict-extra-outbound-peers
   #:any-blocks-in-flight-p
   #:socket-input-ready-p
   #:capture-recv-backtrace
   #:*recv-backtrace-budget*
   #:select-extra-block-relay-eviction
   #:select-extra-full-relay-eviction
   #:maybe-set-peer-announcing-hb
   #:maybe-send-feefilter
   #:maybe-start-reconciliation
   #:fee-filter-round
   #:peer-manual
   #:peer-outbound-or-block-relay-p
   #:loopback-address-p
   #:peer-conn-type
   #:peer-relays-txs-p
   #:peer-tx-relay-p
   #:peer-last-inv-sequence
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
   #:ingest-headers-from-peer
   #:request-headers
   #:relay-transaction
   #:peer-announced-txs
   #:peer-known-addrs
   #:initial-block-download-p
   #:near-tip-p
   ;; Compact block relay (BIP 152)
   #:send-compact-block-negotiation
   #:check-compact-block-timeout
   #:clear-pending-compact-block
   #:compact-block-stats
   ;; Peer health
   #:check-peer-health
   #:record-block-timeout
   #:record-block-received-from-peer
   #:consider-peer-eviction
   #:peer-block-timeout-count
   #:peer-last-block-received-time
   #:peer-address
   #:+max-block-timeouts+
   ;; Peer database (peer-address struct shares symbol with peer accessor above)
   #:make-peer-address
   #:peer-address-net
   #:peer-address-network
   #:peer-address-string
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
   #:select-dialable-address
   #:address-book-get-addr
   #:resolve-tried-collisions
   #:select-tried-collision
   #:addr-info-terrible-p
   #:net-group-key
   #:make-address-key
   #:address-routable-p
   #:network-key-id
   #:key-id-network
   #:save-address-book
   #:load-address-book
   #:peers-dat-path
   #:ipv4-to-mapped-ipv6
   #:ip-bytes-to-string
   #:string-to-ip-bytes
   ;; Network-typed addresses (BIP155): codecs + reachability (netaddress.lisp)
   #:+bip155-networks+
   #:network-address-length
   #:*reachable-networks*
   #:*cjdns-reachable*
   #:*onlynet-networks*
   #:reachable-network-p
   #:dialable-network-p
   ;; Local addresses (Core mapLocalHost) + self-advertisement
   #:+local-manual+
   #:local-address
   #:make-local-address
   #:local-address-network
   #:local-address-bytes
   #:local-address-port
   #:local-address-score
   #:add-local
   #:remove-local
   #:clear-local-addresses
   #:local-addresses
   #:best-local-address
   #:privacy-network-p
   #:peer-inbound-onion
   ;; Read by the inbound evictor (GA9 S2-6): Core protects by MINIMUM ping
   ;; and by most-recent novel tx/block, all of which we already tracked.
   #:peer-min-ping-latency
   #:peer-last-tx-time
   #:peer-last-block-time
   #:peer-connected-through-network
   #:peer-next-local-addr-send
   #:get-local-addr-for-peer
   #:maybe-advertise-local-address
   #:local-services
   #:maybe-flip-ipv6-to-cjdns
   #:proxy-for-target
   #:base32-encode
   #:base32-decode
   #:onion-address-string
   #:parse-onion-address
   #:i2p-address-string
   #:parse-i2p-address
   #:network-address-to-string
   #:parse-network-address
   #:parse-subnet
   #:subnet-match-p
   #:address-in-subnets-p
   ;; ADDRv2 support (BIP 155)
   #:peer-wants-addrv2
   #:peer-prefers-headers
   #:peer-feefilter-rate
   #:peer-wtxid-relay
   #:handle-addr
   #:handle-addrv2
   ;; Misbehavior and banning
   #:record-misbehavior
   #:ban-peer
   #:peer-banned-p
   #:clear-ban-list
   #:ban-address
   #:*default-ban-time-seconds*
   #:*banlist-path*
   #:save-banlist
   #:load-banlist
   #:*external-ips*
   #:unban-address
   #:list-bans
   #:*total-bytes-sent*
   #:*total-bytes-received*
   #:discourage-peer
   #:peer-discouraged-p
   #:clear-discouraged
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
   #:relay-enabled-p
   #:ignore-incoming-txs-p))

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
   #:*blocksonly*
   ;; Wallet fee rails (config.lisp; consumed by the wallet spend path)
   #:*wallet-max-tx-fee*
   #:*wallet-fallback-fee*
   ;; Pruning
   #:*prune-target-mib*
   #:*prune-after-height*
   #:+min-blocks-to-keep+
   #:+min-disk-space-for-block-files+
   #:effective-prune-target-bytes
   #:*accept-datacarrier*
   #:*max-datacarrier-bytes*
   #:*permit-bare-multisig*
   #:*peer-block-filters*
   #:*tx-reconciliation*
   #:pruning-enabled-p
   #:automatic-pruning-p
   #:minimum-chain-work
   #:*minimum-chain-work-override*
   #:*assumevalid-override*
   #:network-assumevalid
   #:*p2p-port-override*
   #:*stop-at-height*
   #:*dns-seed-enabled*
   #:*fixed-seeds-enabled*
   #:check-cli-args
   #:unknown-config-file-keys
   #:known-config-option-p
   #:conf-parse-money
   #:conf-parse-user-hex
   #:ua-comment-safe-p
   #:+max-subversion-length+
   ;; Assumeutxo snapshot commitments (Core m_assumeutxo_data)
   #:assumeutxo-data
   #:make-assumeutxo-data
   #:assumeutxo-data-height
   #:assumeutxo-data-blockhash
   #:assumeutxo-data-hash-serialized
   #:assumeutxo-data-chain-tx-count
   #:*assumeutxo-data-override*
   #:network-assumeutxo-data
   #:assumeutxo-data-for-blockhash
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
   #:start-node-from-args
   #:stop-node
   ;; Shutdown coordination (internal paths request; the main thread performs)
   #:request-node-shutdown
   #:node-shutdown-requested-p
   #:run-node-watchdog
   #:node-main
   #:+node-exit-clean+
   #:+node-exit-error+
   #:+node-exit-watchdog+
   #:node-status
   #:node-fee-estimator
   #:node-recent-rejects
   #:sync-blockchain
   ;; Logging
   #:*log-stream*
   #:*current-log-level*
   #:node-log
   #:log-debug
   #:log-cat
   #:log-category-enabled-p
   #:log-info
   #:log-warn
   #:log-error
   #:show-logs
   #:clear-logs
   #:enable-console-logging
   #:disable-console-logging
   #:start-file-logging
   #:stop-file-logging
   #:maybe-periodic-flush
   #:maybe-critical-flush
   #:maybe-stop-at-height
   ;; ZMQ notifications (G7-23)
   #:zmq-notify-block-connected
   #:zmq-notify-block-disconnected
   #:zmq-notify-tx-accepted
   #:zmq-notify-tx-removed
   #:zmq-start-publishers
   #:zmq-stop-publishers
   #:zmq-specs-from-config
   #:zmq-notifications-info
   #:zmq-topic-active-p
   ;; Cooperative-stop seam (config.lisp): the networking layer installs the
   ;; predicate, lower layers poll it — never the other way round.
   #:*interrupt-check*
   #:interrupt-requested-p
   #:listen-port
   #:index-block-filter
   #:index-block-coinstats
   ;; Wallet chain-tracking hooks (wallet P2; defined in node.lisp, called
   ;; from connect-block / perform-reorg / the mempool like the index hooks)
   #:wallet-notify-block-connected
   #:wallet-notify-block-disconnected
   #:wallet-notify-mempool-tx-added
   #:wallet-notify-mempool-tx-removed
   #:maybe-validate-snapshot
   #:rebalance-caches-on-ibd-exit))

