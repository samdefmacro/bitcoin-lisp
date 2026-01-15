;;;; Coalton package definitions for bitcoin-lisp
;;;;
;;;; This file defines the Coalton packages used for statically-typed
;;;; Bitcoin protocol types and operations.

(defpackage #:bitcoin-lisp.coalton.types
  (:documentation "Core Bitcoin types with static type safety.")
  (:use #:coalton
        #:coalton-prelude)
  (:export
   ;; Hash types
   #:Hash256
   #:Hash160
   #:Satoshi
   #:BlockHeight
   ;; Constructors
   #:make-hash256
   #:make-hash160
   #:make-satoshi
   #:make-block-height
   ;; Accessors
   #:hash256-bytes
   #:hash160-bytes
   #:satoshi-value
   #:block-height-value
   ;; Utilities
   #:hash256-zero
   #:hash160-zero
   #:satoshi-zero
   #:satoshi-add
   #:satoshi-sub
   #:block-height-zero
   #:block-height-next))

(defpackage #:bitcoin-lisp.coalton.crypto
  (:documentation "Typed cryptographic operations for Bitcoin.")
  (:use #:coalton
        #:coalton-prelude)
  (:export
   #:compute-sha256
   #:compute-hash256
   #:compute-ripemd160
   #:compute-hash160
   #:bytes-to-hex))

(defpackage #:bitcoin-lisp.coalton.binary
  (:documentation "Typed binary serialization primitives.")
  (:use #:coalton
        #:coalton-prelude)
  (:export
   ;; Read result type
   #:ReadResult
   #:read-result-value
   #:read-result-position
   ;; Read operations
   #:read-u8
   #:read-u16-le
   #:read-u32-le
   #:read-u64-le
   #:read-i32-le
   #:read-i64-le
   #:read-compact-size
   #:read-bytes
   ;; Write operations
   #:write-u8
   #:write-u16-le
   #:write-u32-le
   #:write-u64-le
   #:write-i32-le
   #:write-i64-le
   #:write-compact-size
   ;; Utilities
   #:concat-bytes))

(defpackage #:bitcoin-lisp.coalton.serialization
  (:documentation "Typed Bitcoin protocol structures and serialization.")
  (:use #:coalton
        #:coalton-prelude)
  (:import-from #:bitcoin-lisp.coalton.types
                #:Hash256
                #:Hash160
                #:Satoshi
                #:hash256-bytes
                #:hash256-zero
                #:make-satoshi
                #:satoshi-value)
  (:import-from #:bitcoin-lisp.coalton.binary
                #:ReadResult
                #:read-result-value
                #:read-result-position
                #:read-u8
                #:read-u32-le
                #:read-u64-le
                #:read-i32-le
                #:read-compact-size
                #:read-bytes
                #:write-u32-le
                #:write-u64-le
                #:write-i32-le
                #:write-compact-size
                #:concat-bytes)
  (:export
   ;; Empty list helpers (for FFI/testing)
   #:empty-tx-in-list
   #:empty-tx-out-list
   #:empty-transaction-list
   ;; Protocol types
   #:Outpoint
   #:TxIn
   #:TxOut
   #:Transaction
   #:BlockHeader
   #:BitcoinBlock
   ;; Constructors
   #:make-outpoint
   #:make-tx-in
   #:make-tx-out
   #:make-transaction
   #:make-block-header
   #:make-bitcoin-block
   ;; Accessors
   #:outpoint-hash
   #:outpoint-index
   #:tx-in-previous-output
   #:tx-in-script-sig
   #:tx-in-sequence
   #:tx-out-value
   #:tx-out-script-pubkey
   #:transaction-version
   #:transaction-inputs
   #:transaction-outputs
   #:transaction-lock-time
   #:block-header-version
   #:block-header-prev-block
   #:block-header-merkle-root
   #:block-header-timestamp
   #:block-header-bits
   #:block-header-nonce
   #:bitcoin-block-header
   #:bitcoin-block-transactions
   ;; Serialization
   #:serialize-outpoint
   #:serialize-tx-in
   #:serialize-tx-out
   #:serialize-transaction
   #:serialize-block-header
   #:serialize-block
   ;; Deserialization
   #:deserialize-outpoint
   #:deserialize-tx-in
   #:deserialize-tx-out
   #:deserialize-transaction
   #:deserialize-block-header
   #:deserialize-block))
