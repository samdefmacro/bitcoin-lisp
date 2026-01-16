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

(defpackage #:bitcoin-lisp.coalton.script
  (:documentation "Typed Bitcoin script interpreter with compile-time type safety.")
  (:use #:coalton
        #:coalton-prelude)
  (:import-from #:bitcoin-lisp.coalton.types
                #:Hash256
                #:Hash160
                #:hash256-bytes
                #:hash160-bytes)
  (:import-from #:bitcoin-lisp.coalton.crypto
                #:compute-sha256
                #:compute-hash256
                #:compute-ripemd160
                #:compute-hash160)
  (:export
   ;; Core types
   #:ScriptNum
   #:make-script-num
   #:script-num-value
   #:ScriptError
   #:SE-StackUnderflow
   #:SE-StackOverflow
   #:SE-InvalidNumber
   #:SE-VerifyFailed
   #:SE-OpReturn
   #:SE-DisabledOpcode
   #:SE-UnknownOpcode
   #:SE-ScriptTooLarge
   #:SE-TooManyOps
   #:SE-InvalidStackOperation
   #:SE-UnbalancedConditional
   #:ScriptResult
   #:script-ok
   #:script-err
   ;; Opcode type
   #:Opcode
   #:OP-0 #:OP-FALSE
   #:OP-PUSHBYTES
   #:OP-PUSHDATA1 #:OP-PUSHDATA2 #:OP-PUSHDATA4
   #:OP-1NEGATE
   #:OP-1 #:OP-2 #:OP-3 #:OP-4 #:OP-5 #:OP-6 #:OP-7 #:OP-8
   #:OP-9 #:OP-10 #:OP-11 #:OP-12 #:OP-13 #:OP-14 #:OP-15 #:OP-16
   #:OP-NOP #:OP-IF #:OP-NOTIF #:OP-ELSE #:OP-ENDIF
   #:OP-VERIFY #:OP-RETURN
   #:OP-TOALTSTACK #:OP-FROMALTSTACK
   #:OP-2DROP #:OP-2DUP #:OP-3DUP #:OP-2OVER #:OP-2ROT #:OP-2SWAP
   #:OP-IFDUP #:OP-DEPTH #:OP-DROP #:OP-DUP #:OP-NIP #:OP-OVER
   #:OP-PICK #:OP-ROLL #:OP-ROT #:OP-SWAP #:OP-TUCK
   #:OP-1ADD #:OP-1SUB #:OP-NEGATE #:OP-ABS #:OP-NOT #:OP-0NOTEQUAL
   #:OP-ADD #:OP-SUB #:OP-BOOLAND #:OP-BOOLOR
   #:OP-NUMEQUAL #:OP-NUMEQUALVERIFY #:OP-NUMNOTEQUAL
   #:OP-LESSTHAN #:OP-GREATERTHAN #:OP-LESSTHANOREQUAL #:OP-GREATERTHANOREQUAL
   #:OP-MIN #:OP-MAX #:OP-WITHIN
   #:OP-RIPEMD160 #:OP-SHA1 #:OP-SHA256 #:OP-HASH160 #:OP-HASH256
   #:OP-CODESEPARATOR #:OP-CHECKSIG #:OP-CHECKSIGVERIFY
   #:OP-CHECKMULTISIG #:OP-CHECKMULTISIGVERIFY
   #:OP-EQUAL #:OP-EQUALVERIFY
   #:OP-DISABLED #:OP-UNKNOWN
   ;; Opcode conversions
   #:opcode-to-byte
   #:byte-to-opcode
   #:is-push-op
   #:is-disabled-op
   #:is-conditional-op
   ;; Value conversions
   #:bytes-to-script-num
   #:script-num-to-bytes
   #:cast-to-bool
   #:script-num-in-range
   ;; Stack operations
   #:ScriptStack
   #:stack-push
   #:stack-pop
   #:stack-top
   #:stack-depth
   #:stack-pick
   #:stack-roll
   #:empty-stack
   ;; Execution context
   #:ScriptContext
   #:make-script-context
   #:context-main-stack
   #:context-alt-stack
   #:context-position
   #:context-executing
   ;; Execution
   #:execute-script
   #:execute-script-with-stack
   #:execute-scripts
   #:execute-opcode
   ;; P2SH support
   #:is-p2sh-script
   #:validate-p2sh
   ;; Result helpers (for CL interop)
   #:script-result-ok-p
   #:script-result-err-p
   #:script-result-stack
   #:script-result-error
   #:get-ok-stack))
