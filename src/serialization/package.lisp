;;;; Package bitcoin-lisp.serialization -- the public API of src/serialization/.
;;;;
;;;; First component of the bitcoin-lisp/serialization sub-system (bitcoin-lisp.asd):
;;;; the package exists before any file in src/serialization/ compiles, and the
;;;; INSTALL-PACKAGE-NICKNAMES call at the end of this file gives those files
;;;; their bl.* prefixes. Add an export here when a definition in src/serialization/
;;;; becomes API; keep %-prefixed names internal.

(defpackage #:bitcoin-lisp.serialization
  (:documentation "Bitcoin's wire and disk encodings: little-endian
integers and CompactSize, DEFINE-MESSAGE for the P2P messages, transaction
and block structs with their hashes, PSBT, the script/amount compressor.
Core serialize.h, primitives/, protocol.cpp, psbt.cpp, compressor.cpp.
src/serialization/.")
  (:use #:cl #:bitcoin-lisp.conditions)
  ;; The byte-buf / byte-reader live in bitcoin-lisp.bytes (src/util/bytes.lisp)
  ;; and are re-exported here, so every existing bl.ser:bb-*
  ;; / br-* reference keeps working.
  (:import-from #:bitcoin-lisp.bytes
                #:+max-compact-size+
                #:byte-buf #:make-byte-buf #:bb-data #:bb-pos
                #:bb-write-u8 #:bb-write-u16-le #:bb-write-u32-le #:bb-write-u64-le
                #:bb-write-i32-le #:bb-write-i64-le #:bb-write-bytes #:bb-write-varint
                #:bb-write-var-bytes #:bb-write-hash256 #:bb-finish #:with-byte-buf
                #:byte-reader #:make-byte-reader #:make-byte-reader-from
                #:br-data #:br-pos #:br-eof-p
                #:br-read-u8 #:br-read-u16-le #:br-read-u32-le #:br-read-u64-le
                #:br-read-i32-le #:br-read-i64-le #:br-read-bytes
                #:br-read-compact-size #:br-read-var-bytes #:with-byte-reader)
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
   #:script-push-data
   ;; define-message (message-macro.lisp)
   #:define-message
   #:define-message-field-type
   #:field-codec-forms
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
   #:br-read-bitcoin-block
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
   #:+psbt-in-tap-script-sig+ #:+psbt-in-tap-leaf-script+
   #:+psbt-in-tap-bip32+ #:+psbt-in-tap-merkle-root+
   #:+psbt-in-musig2-participant-pubkeys+ #:+psbt-in-musig2-pub-nonce+
   #:+psbt-in-musig2-partial-sig+ #:+psbt-out-musig2-participant-pubkeys+
   #:+psbt-out-redeem-script+ #:+psbt-out-witness-script+ #:+psbt-out-bip32+
   #:+psbt-out-tap-internal-key+ #:+psbt-out-proprietary+
   #:+psbt-out-tap-tree+ #:+psbt-out-tap-bip32+
   #:coinbase-input-p
   #:get-unix-time
   #:get-real-unix-time
   #:get-node-time
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
   #:read-compressed-coin)
  ;; Reached from another package with :: before the second-round review
  ;; (docs/refactoring-review-2026-09-02.md, wave B): API by use, so exported.
  (:export
   #:read-block-header
   #:read-outpoint
   #:read-tx-in
   #:read-tx-out
   #:transaction-cached-weight
   #:version-message-addr-recv
   #:version-message-nonce
   #:version-message-timestamp
   #:write-outpoint
   #:write-tx-in))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
