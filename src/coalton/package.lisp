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
   #:script-error-name
   #:SE-StackUnderflow
   #:SE-StackOverflow
   #:SE-InvalidNumber
   #:SE-NumberOverflow
   #:SE-VerifyFailed
   #:SE-EvalFalse
   #:SE-EqualVerify
   #:SE-NumEqualVerify
   #:SE-CheckSigVerify
   #:SE-CheckMultisigVerify
   #:SE-OpReturn
   #:SE-DisabledOpcode
   #:SE-UnknownOpcode
   #:SE-InvalidPushData
   #:SE-MinimalData
   #:SE-PushSize
   #:SE-ScriptTooLarge
   #:SE-TooManyOps
   #:SE-InvalidStackOperation
   #:SE-InvalidAltstackOperation
   #:SE-UnbalancedConditional
   #:SE-NegativeLocktime
   #:SE-UnsatisfiedLocktime
   #:SE-DiscourageUpgradableNops
   #:SE-SigCount
   #:SE-PubkeyCount
   #:SE-SigDer
   #:SE-SigHighS
   #:SE-SigHashtype
   #:SE-SigNullFail
   #:SE-SigNullDummy
   #:SE-SigFindAndDelete
   #:SE-PubkeyType
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
   ;; Core's SigVersion
   #:SigVersion
   #:SigVersionBase
   #:SigVersionWitnessV0
   #:SigVersionTaproot
   #:SigVersionTapscript
   ;; Execution context
   #:ScriptContext
   #:context-main-stack
   #:context-alt-stack
   #:context-position
   #:context-executing
   #:context-tx-locktime
   #:context-tx-version
   #:context-input-sequence
   ;; Execution
   #:execute-script
   #:execute-script-with-tx
   #:execute-script-with-stack
   #:execute-script-with-stack-tx
   #:execute-scripts
   #:execute-scripts-with-tx
   #:execute-opcode
   ;; P2SH support
   #:is-p2sh-script
   #:validate-p2sh
   ;; SegWit support
   #:is-witness-program
   #:get-witness-version
   #:get-witness-program
   #:is-valid-v0-witness-program-length
   #:is-p2wpkh-program
   #:is-p2wsh-program
   ;; SegWit errors
   #:SE-WitnessProgramWrongLength
   #:SE-WitnessProgramWitnessEmpty
   #:SE-WitnessProgramMismatch
   #:SE-WitnessUnexpected
   #:SE-WitnessMalleated
   #:SE-WitnessPubkeyType
   #:SE-DiscourageUpgradableWitnessProgram
   ;; Taproot errors (BIP 341/342)
   #:SE-TaprootInvalidSignature
   #:SE-TaprootInvalidControlBlock
   #:SE-TaprootMerkleMismatch
   #:SE-TapscriptInvalidOpcode
   #:SE-SchnorrSignatureSize
   #:SE-SchnorrSigHashtype
   #:SE-TapscriptMinimalIf
   #:SE-TapscriptCheckmultisig
   #:SE-TapscriptInvalidSig
   #:SE-TapscriptEmptyPubkey
   #:SE-TapscriptValidationWeight
   #:SE-MinimalIf
   #:SE-DiscourageUpgradablePubkeyType
   ;; Taproot support (BIP 341)
   #:is-taproot-program
   #:OP-CHECKSIGADD
   ;; Result helpers (for CL interop)
   #:script-result-ok-p
   #:script-result-err-p
   #:script-result-stack
   #:script-result-error
   #:get-ok-stack))

;; The CL bridge (interop.lisp) loads AFTER the interpreter, but its package
;; is defined here, before it: the interpreter's LISP forms call back into the
;; bridge (flag lookups, CHECKSIG, CHECKMULTISIG), and with the package in
;; existence the reader resolves those names once, at compile time. Before,
;; each call site INTERNed the name and took its FDEFINITION on every call.
(defpackage #:bitcoin-lisp.coalton.interop
  (:documentation "CL wrapper functions for Coalton Bitcoin types.")
  (:use #:cl)
  ;; Byte I/O (src/util/bytes.lisp). Loads before this file, so the sighash
  ;; writers below inline it.
  (:import-from #:bitcoin-lisp.bytes
                #:make-byte-buf #:bb-write-u32-le #:bb-write-u64-le #:bb-write-i64-le
                #:bb-write-bytes #:bb-write-varint #:bb-finish
                #:buf-set-u8 #:buf-set-u16-le #:buf-set-u32-le #:buf-set-u64-le
                #:buf-set-bytes #:buf-set-varint)
  (:export
   ;; Script bytes into the interpreter, and a stack element back out
   #:cl-array-to-coalton-vector
   #:coalton-vector-to-cl-array
   ;; Satoshi operations
   #:wrap-satoshi
   #:unwrap-satoshi
   #:satoshi+
   #:satoshi-
   #:satoshi<
   #:satoshi<=
   #:satoshi>
   #:satoshi>=
   #:satoshi=
   #:zero-satoshi
   ;; BlockHeight operations
   #:wrap-block-height
   #:unwrap-block-height
   #:block-height+
   #:block-height<
   #:block-height<=
   #:block-height>
   #:block-height>=
   #:block-height=
   #:zero-block-height
   #:next-block-height
   ;; Struct ↔ Coalton vector converters
   #:cl-array-to-coalton-vector
   ;; Constants
   #:+max-money+
   #:+coin+
   #:+coinbase-maturity+
   ;; Script execution
   #:run-script
   #:run-scripts-with-p2sh
   #:is-p2sh-script-p
   #:stack-top-truthy-p
   ;; Script errors in Core's vocabulary
   #:+script-errors+
   #:script-error-keyword
   #:script-error-for-keyword
   #:script-error-name
   #:script-error-message
   #:last-checksig-script-error
   #:last-checkmultisig-script-error
   ;; Script flags
   #:*script-flags*
   #:set-script-flags
   #:flag-enabled-p
   ;; Signature verification
   #:verify-script
   #:p2sh-redeem-script
   #:verify-checksig
   #:verify-checksig-for-script
   #:last-checksig-had-strictenc-error-p
   ;; Multisig verification
   #:verify-checkmultisig
   #:verify-checkmultisig-for-script
   #:last-checkmultisig-had-error-p
   #:do-checkmultisig-stack-op
   ;; MINIMALDATA validation
   #:minimal-push-encoding-p
   #:minimal-number-encoding-p
   ;; SIGPUSHONLY validation
   #:script-is-push-only-p
   #:reseed-signature-cache
   ;; Transaction context for block validation
   #:*current-tx*
   #:*current-spent-utxos*
   #:*debug-bip341-sighash*
   #:*current-input-index*
   #:*debug-checksig*
   #:compute-legacy-sighash
   ;; Sighash precomputation
   #:*precomputed-sighash*
   #:init-precomputed-sighash
   #:precomputed-sighash-data
   #:precomputed-sighash-data-hash-prevouts
   #:precomputed-sighash-data-hash-sequence
   #:precomputed-sighash-data-hash-outputs-all
   #:precomputed-sighash-data-sha-prevouts
   #:precomputed-sighash-data-sha-sequences
   #:precomputed-sighash-data-sha-outputs
   #:precomputed-sighash-data-sha-amounts
   #:precomputed-sighash-data-sha-script-pubkeys
   ;; Signature cache
   #:*signature-cache*
   #:*signature-cache-prev*
   #:*signature-cache-enabled*
   #:*signature-cache-store*
   #:clear-signature-cache
   ;; SegWit / BIP 143
   #:*witness-input-amount*
   #:*original-script-pubkey*
   #:compute-bip143-sighash
   #:make-p2pkh-script-code
   #:validate-witness-program
   #:validate-p2wpkh
   #:validate-p2wsh
   #:is-witness-program-p
   #:get-witness-version
   #:get-witness-program-bytes
   #:is-compressed-pubkey-p
   ;; Taproot / BIP 341
   #:is-taproot-program-p
   #:validate-taproot
   #:validate-taproot-key-path
   #:validate-taproot-script-path
   #:compute-bip341-sighash
   #:compute-taproot-tweak
   #:compute-tweaked-pubkey
   #:verify-taproot-tweak
   #:parse-control-block
   #:compute-merkle-root-from-path
   ;; Tapscript / BIP 342
   #:*tapscript-leaf-hash*
   #:*tapscript-amount*
   #:verify-tapscript-signature
   #:is-op-success-p
   #:scan-for-op-success
   #:run-tapscript
   #:increment-script-number
   ;; Core's CScriptNum decode and the two halves of CheckSignatureEncoding
   ;; under SCRIPT_VERIFY_STRICTENC. The script renderer (ScriptToAsmStr)
   ;; needs the same three the interpreter does: a push of four bytes or
   ;; fewer prints as its CScriptNum value, and a longer one prints its
   ;; sighash type only when it passes the interpreter's own encoding test.
   #:script-number-to-int
   #:check-der-signature-format
   #:valid-sighash-type-p)
  ;; Reached from another package with :: before the second-round review
  ;; (docs/refactoring-review-2026-09-02.md, wave B): API by use, so exported.
  (:export
   #:*script-execution-cache-enabled*
   #:*script-execution-cache-hits*
   #:*tapscript-codesep-pos*
   #:*signature-cache-max-entries*
   #:make-script-execution-cache-key
   #:script-execution-cache-store
   #:script-execution-cached-p))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
