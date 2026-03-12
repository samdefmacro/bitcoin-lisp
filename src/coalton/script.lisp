;;;; Typed Bitcoin Script Interpreter
;;;;
;;;; This module provides a statically-typed Bitcoin script interpreter
;;;; using Coalton. All stack operations, opcodes, and execution contexts
;;;; are type-safe, catching errors at compile time rather than runtime.

(in-package #:bitcoin-lisp.coalton.script)

(named-readtables:in-readtable coalton:coalton)

(coalton-toplevel

  ;;; ============================================================
  ;;; Core Types
  ;;; ============================================================

  ;;;; ScriptNum - Script numeric values
  ;;;;
  ;;;; Bitcoin script numbers are signed integers with a maximum of 4 bytes
  ;;;; for arithmetic operations. They use a special little-endian encoding
  ;;;; with a sign bit in the most significant byte.

  (define-type ScriptNum
    "A Bitcoin script number (signed, variable-length, max 4 bytes for arithmetic)."
    (ScriptNum Integer))

  (declare make-script-num (Integer -> ScriptNum))
  (define (make-script-num n)
    "Create a ScriptNum from an Integer."
    (ScriptNum n))

  (declare script-num-value (ScriptNum -> Integer))
  (define (script-num-value sn)
    "Extract the Integer value from a ScriptNum."
    (match sn
      ((ScriptNum n) n)))

  ;;;; ScriptError - Error types for script execution

  (define-type ScriptError
    "Errors that can occur during script execution."
    SE-StackUnderflow          ; Attempted to pop from empty stack
    SE-StackOverflow           ; Stack exceeded maximum size (1000)
    SE-InvalidNumber           ; Invalid numeric encoding
    SE-VerifyFailed            ; OP_VERIFY failed
    SE-OpReturn                ; OP_RETURN encountered
    SE-DisabledOpcode          ; Disabled opcode executed
    SE-UnknownOpcode           ; Unknown opcode
    SE-ScriptTooLarge          ; Script exceeds 10,000 bytes
    SE-TooManyOps              ; More than 201 non-push operations
    SE-InvalidStackOperation   ; Invalid stack operation (e.g., bad index)
    SE-UnbalancedConditional   ; Unbalanced IF/ELSE/ENDIF
    SE-InvalidPushData         ; Invalid push data size
    SE-MinimalData             ; Non-minimal data encoding (MINIMALDATA flag)
    SE-NegativeLocktime        ; Negative locktime value (BIP 65/112)
    SE-UnsatisfiedLocktime     ; Locktime condition not satisfied
    SE-DiscourageUpgradableNops ; NOP1/NOP4-10 when DISCOURAGE_UPGRADABLE_NOPS flag set
    SE-PushSize                ; Push data exceeds 520 bytes
    SE-NumberOverflow          ; Arithmetic operand exceeds 4 bytes
    ;; Witness errors (SegWit BIP 141)
    SE-WitnessProgramWrongLength   ; Witness program not 20 or 32 bytes for v0
    SE-WitnessProgramWitnessEmpty  ; Empty witness for witness program
    SE-WitnessProgramMismatch      ; SHA256(witnessScript) != program (P2WSH)
    SE-WitnessUnexpected           ; Witness for non-witness input
    SE-WitnessMalleated            ; Non-empty scriptSig for native witness
    SE-WitnessPubkeyType           ; Uncompressed pubkey in witness
    SE-DiscourageUpgradableWitnessProgram ; Unknown witness version when flag set
    ;; Taproot errors (BIP 341/342)
    SE-TaprootInvalidSignature     ; Schnorr signature verification failed
    SE-TaprootInvalidControlBlock  ; Malformed control block
    SE-TaprootMerkleMismatch       ; Merkle proof doesn't match output key
    SE-TapscriptInvalidOpcode      ; Disabled opcode in Tapscript context
    SE-SchnorrSignatureSize        ; Signature not 64 or 65 bytes
    ;; Tapscript-specific errors (BIP 342)
    SE-TapscriptMinimalIf          ; IF/NOTIF argument not empty or [0x01]
    SE-TapscriptCheckmultisig      ; CHECKMULTISIG used in Tapscript (disabled)
    SE-TapscriptInvalidSig)        ; Non-empty invalid signature in Tapscript

  ;;;; ScriptResult - Result type for script operations

  (define-type (ScriptResult :a)
    "Result of a script operation - either success with value or failure with error."
    (ScriptOk :a)
    (ScriptErr ScriptError))

  (declare script-ok (:a -> (ScriptResult :a)))
  (define (script-ok x)
    "Wrap a successful result."
    (ScriptOk x))

  (declare script-err (ScriptError -> (ScriptResult :a)))
  (define (script-err e)
    "Wrap an error result."
    (ScriptErr e))

  ;;; ============================================================
  ;;; Opcode Definitions
  ;;; ============================================================

  (define-type Opcode
    "Bitcoin script opcodes as an algebraic data type.
     Pattern matching ensures exhaustive handling of all opcodes."

    ;; Constants
    OP-0                      ; 0x00 - Push empty byte vector (false)
    OP-1NEGATE                ; 0x4f - Push -1
    OP-1                      ; 0x51 - Push 1
    OP-2                      ; 0x52 - Push 2
    OP-3                      ; 0x53 - Push 3
    OP-4                      ; 0x54 - Push 4
    OP-5                      ; 0x55 - Push 5
    OP-6                      ; 0x56 - Push 6
    OP-7                      ; 0x57 - Push 7
    OP-8                      ; 0x58 - Push 8
    OP-9                      ; 0x59 - Push 9
    OP-10                     ; 0x5a - Push 10
    OP-11                     ; 0x5b - Push 11
    OP-12                     ; 0x5c - Push 12
    OP-13                     ; 0x5d - Push 13
    OP-14                     ; 0x5e - Push 14
    OP-15                     ; 0x5f - Push 15
    OP-16                     ; 0x60 - Push 16

    ;; Push data
    (OP-PUSHBYTES U8)         ; 0x01-0x4b - Push N bytes directly
    OP-PUSHDATA1              ; 0x4c - Next byte is length, then data
    OP-PUSHDATA2              ; 0x4d - Next 2 bytes are length (LE)
    OP-PUSHDATA4              ; 0x4e - Next 4 bytes are length (LE)

    ;; Flow control
    OP-NOP                    ; 0x61 - No operation
    OP-IF                     ; 0x63 - Execute if top is true
    OP-NOTIF                  ; 0x64 - Execute if top is false
    OP-ELSE                   ; 0x67 - Else branch
    OP-ENDIF                  ; 0x68 - End if block
    OP-VERIFY                 ; 0x69 - Fail if top is false
    OP-RETURN                 ; 0x6a - Fail immediately

    ;; Stack operations
    OP-TOALTSTACK             ; 0x6b - Move to alt stack
    OP-FROMALTSTACK           ; 0x6c - Move from alt stack
    OP-2DROP                  ; 0x6d - Drop top 2 items
    OP-2DUP                   ; 0x6e - Duplicate top 2 items
    OP-3DUP                   ; 0x6f - Duplicate top 3 items
    OP-2OVER                  ; 0x70 - Copy 3rd and 4th items to top
    OP-2ROT                   ; 0x71 - Rotate top 6 items
    OP-2SWAP                  ; 0x72 - Swap top 2 pairs
    OP-IFDUP                  ; 0x73 - Duplicate if non-zero
    OP-DEPTH                  ; 0x74 - Push stack depth
    OP-DROP                   ; 0x75 - Drop top item
    OP-DUP                    ; 0x76 - Duplicate top item
    OP-NIP                    ; 0x77 - Remove second item
    OP-OVER                   ; 0x78 - Copy second item to top
    OP-PICK                   ; 0x79 - Copy nth item to top
    OP-ROLL                   ; 0x7a - Move nth item to top
    OP-ROT                    ; 0x7b - Rotate top 3 items
    OP-SWAP                   ; 0x7c - Swap top 2 items
    OP-TUCK                   ; 0x7d - Copy top item before second
    OP-SIZE                   ; 0x82 - Push byte length of top element

    ;; Comparison
    OP-EQUAL                  ; 0x87 - Push true if equal
    OP-EQUALVERIFY            ; 0x88 - Fail if not equal

    ;; Arithmetic
    OP-1ADD                   ; 0x8b - Add 1
    OP-1SUB                   ; 0x8c - Subtract 1
    OP-NEGATE                 ; 0x8f - Negate
    OP-ABS                    ; 0x90 - Absolute value
    OP-NOT                    ; 0x91 - Logical not
    OP-0NOTEQUAL              ; 0x92 - True if not 0
    OP-ADD                    ; 0x93 - Add
    OP-SUB                    ; 0x94 - Subtract
    OP-BOOLAND                ; 0x9a - Logical and
    OP-BOOLOR                 ; 0x9b - Logical or
    OP-NUMEQUAL               ; 0x9c - Numeric equal
    OP-NUMEQUALVERIFY         ; 0x9d - Fail if not numerically equal
    OP-NUMNOTEQUAL            ; 0x9e - Numeric not equal
    OP-LESSTHAN               ; 0x9f - Less than
    OP-GREATERTHAN            ; 0xa0 - Greater than
    OP-LESSTHANOREQUAL        ; 0xa1 - Less than or equal
    OP-GREATERTHANOREQUAL     ; 0xa2 - Greater than or equal
    OP-MIN                    ; 0xa3 - Minimum
    OP-MAX                    ; 0xa4 - Maximum
    OP-WITHIN                 ; 0xa5 - Value within range

    ;; Crypto
    OP-RIPEMD160              ; 0xa6 - RIPEMD160 hash
    OP-SHA1                   ; 0xa7 - SHA1 hash
    OP-SHA256                 ; 0xa8 - SHA256 hash
    OP-HASH160                ; 0xa9 - RIPEMD160(SHA256(x))
    OP-HASH256                ; 0xaa - SHA256(SHA256(x))
    OP-CODESEPARATOR          ; 0xab - Mark for signature
    OP-CHECKSIG               ; 0xac - Verify signature
    OP-CHECKSIGVERIFY         ; 0xad - Verify and fail if invalid
    OP-CHECKMULTISIG          ; 0xae - Multi-signature verify
    OP-CHECKMULTISIGVERIFY    ; 0xaf - Multi-sig verify and fail

    ;; Tapscript (BIP 342)
    OP-CHECKSIGADD            ; 0xba - Tapscript signature counting

    ;; Timelocks
    OP-NOP1                   ; 0xb0 - NOP (reserved)
    OP-CHECKLOCKTIMEVERIFY    ; 0xb1 - Check locktime
    OP-CHECKSEQUENCEVERIFY    ; 0xb2 - Check sequence
    OP-NOP4                   ; 0xb3 - NOP (reserved)
    OP-NOP5                   ; 0xb4 - NOP (reserved)
    OP-NOP6                   ; 0xb5 - NOP (reserved)
    OP-NOP7                   ; 0xb6 - NOP (reserved)
    OP-NOP8                   ; 0xb7 - NOP (reserved)
    OP-NOP9                   ; 0xb8 - NOP (reserved)
    OP-NOP10                  ; 0xb9 - NOP (reserved)

    ;; Disabled/Unknown
    (OP-DISABLED U8)          ; Disabled opcodes (OP_CAT, OP_SUBSTR, etc.)
    (OP-UNKNOWN U8))          ; Unknown/reserved opcodes

  ;; Alias for OP-0
  (declare op-false (Unit -> Opcode))
  (define (op-false)
    "OP_FALSE is an alias for OP_0."
    OP-0)

  ;;; ============================================================
  ;;; Opcode Conversions
  ;;; ============================================================

  (declare opcode-to-byte (Opcode -> U8))
  (define (opcode-to-byte op)
    "Convert an Opcode to its byte representation."
    (match op
      ((OP-0) 0)
      ((OP-PUSHBYTES n) n)
      ((OP-PUSHDATA1) #x4c)
      ((OP-PUSHDATA2) #x4d)
      ((OP-PUSHDATA4) #x4e)
      ((OP-1NEGATE) #x4f)
      ((OP-1) #x51)
      ((OP-2) #x52)
      ((OP-3) #x53)
      ((OP-4) #x54)
      ((OP-5) #x55)
      ((OP-6) #x56)
      ((OP-7) #x57)
      ((OP-8) #x58)
      ((OP-9) #x59)
      ((OP-10) #x5a)
      ((OP-11) #x5b)
      ((OP-12) #x5c)
      ((OP-13) #x5d)
      ((OP-14) #x5e)
      ((OP-15) #x5f)
      ((OP-16) #x60)
      ((OP-NOP) #x61)
      ((OP-IF) #x63)
      ((OP-NOTIF) #x64)
      ((OP-ELSE) #x67)
      ((OP-ENDIF) #x68)
      ((OP-VERIFY) #x69)
      ((OP-RETURN) #x6a)
      ((OP-TOALTSTACK) #x6b)
      ((OP-FROMALTSTACK) #x6c)
      ((OP-2DROP) #x6d)
      ((OP-2DUP) #x6e)
      ((OP-3DUP) #x6f)
      ((OP-2OVER) #x70)
      ((OP-2ROT) #x71)
      ((OP-2SWAP) #x72)
      ((OP-IFDUP) #x73)
      ((OP-DEPTH) #x74)
      ((OP-DROP) #x75)
      ((OP-DUP) #x76)
      ((OP-NIP) #x77)
      ((OP-OVER) #x78)
      ((OP-PICK) #x79)
      ((OP-ROLL) #x7a)
      ((OP-ROT) #x7b)
      ((OP-SWAP) #x7c)
      ((OP-TUCK) #x7d)
      ((OP-SIZE) #x82)
      ((OP-EQUAL) #x87)
      ((OP-EQUALVERIFY) #x88)
      ((OP-1ADD) #x8b)
      ((OP-1SUB) #x8c)
      ((OP-NEGATE) #x8f)
      ((OP-ABS) #x90)
      ((OP-NOT) #x91)
      ((OP-0NOTEQUAL) #x92)
      ((OP-ADD) #x93)
      ((OP-SUB) #x94)
      ((OP-BOOLAND) #x9a)
      ((OP-BOOLOR) #x9b)
      ((OP-NUMEQUAL) #x9c)
      ((OP-NUMEQUALVERIFY) #x9d)
      ((OP-NUMNOTEQUAL) #x9e)
      ((OP-LESSTHAN) #x9f)
      ((OP-GREATERTHAN) #xa0)
      ((OP-LESSTHANOREQUAL) #xa1)
      ((OP-GREATERTHANOREQUAL) #xa2)
      ((OP-MIN) #xa3)
      ((OP-MAX) #xa4)
      ((OP-WITHIN) #xa5)
      ((OP-RIPEMD160) #xa6)
      ((OP-SHA1) #xa7)
      ((OP-SHA256) #xa8)
      ((OP-HASH160) #xa9)
      ((OP-HASH256) #xaa)
      ((OP-CODESEPARATOR) #xab)
      ((OP-CHECKSIG) #xac)
      ((OP-CHECKSIGVERIFY) #xad)
      ((OP-CHECKMULTISIG) #xae)
      ((OP-CHECKMULTISIGVERIFY) #xaf)
      ((OP-NOP1) #xb0)
      ((OP-CHECKLOCKTIMEVERIFY) #xb1)
      ((OP-CHECKSEQUENCEVERIFY) #xb2)
      ((OP-NOP4) #xb3)
      ((OP-NOP5) #xb4)
      ((OP-NOP6) #xb5)
      ((OP-NOP7) #xb6)
      ((OP-NOP8) #xb7)
      ((OP-NOP9) #xb8)
      ((OP-NOP10) #xb9)
      ((OP-CHECKSIGADD) #xba)
      ((OP-DISABLED n) n)
      ((OP-UNKNOWN n) n)))

  (declare byte-to-opcode (U8 -> Opcode))
  (define (byte-to-opcode b)
    "Convert a byte to an Opcode."
    (cond
      ;; OP_0 / OP_FALSE
      ((== b 0) OP-0)
      ;; Push 1-75 bytes directly
      ((and (>= b 1) (<= b 75)) (OP-PUSHBYTES b))
      ;; Push data opcodes
      ((== b #x4c) OP-PUSHDATA1)
      ((== b #x4d) OP-PUSHDATA2)
      ((== b #x4e) OP-PUSHDATA4)
      ;; OP_1NEGATE
      ((== b #x4f) OP-1NEGATE)
      ;; Reserved (OP_RESERVED)
      ((== b #x50) (OP-UNKNOWN b))
      ;; OP_1 through OP_16
      ((== b #x51) OP-1)
      ((== b #x52) OP-2)
      ((== b #x53) OP-3)
      ((== b #x54) OP-4)
      ((== b #x55) OP-5)
      ((== b #x56) OP-6)
      ((== b #x57) OP-7)
      ((== b #x58) OP-8)
      ((== b #x59) OP-9)
      ((== b #x5a) OP-10)
      ((== b #x5b) OP-11)
      ((== b #x5c) OP-12)
      ((== b #x5d) OP-13)
      ((== b #x5e) OP-14)
      ((== b #x5f) OP-15)
      ((== b #x60) OP-16)
      ;; Flow control
      ((== b #x61) OP-NOP)
      ((== b #x63) OP-IF)
      ((== b #x64) OP-NOTIF)
      ((== b #x67) OP-ELSE)
      ((== b #x68) OP-ENDIF)
      ((== b #x69) OP-VERIFY)
      ((== b #x6a) OP-RETURN)
      ;; Stack
      ((== b #x6b) OP-TOALTSTACK)
      ((== b #x6c) OP-FROMALTSTACK)
      ((== b #x6d) OP-2DROP)
      ((== b #x6e) OP-2DUP)
      ((== b #x6f) OP-3DUP)
      ((== b #x70) OP-2OVER)
      ((== b #x71) OP-2ROT)
      ((== b #x72) OP-2SWAP)
      ((== b #x73) OP-IFDUP)
      ((== b #x74) OP-DEPTH)
      ((== b #x75) OP-DROP)
      ((== b #x76) OP-DUP)
      ((== b #x77) OP-NIP)
      ((== b #x78) OP-OVER)
      ((== b #x79) OP-PICK)
      ((== b #x7a) OP-ROLL)
      ((== b #x7b) OP-ROT)
      ((== b #x7c) OP-SWAP)
      ((== b #x7d) OP-TUCK)
      ;; Splice (disabled)
      ((and (>= b #x7e) (<= b #x81)) (OP-DISABLED b))
      ;; Size (enabled)
      ((== b #x82) OP-SIZE)
      ;; Bitwise (disabled)
      ((and (>= b #x83) (<= b #x86)) (OP-DISABLED b))
      ;; Comparison
      ((== b #x87) OP-EQUAL)
      ((== b #x88) OP-EQUALVERIFY)
      ;; Reserved
      ((and (>= b #x89) (<= b #x8a)) (OP-UNKNOWN b))
      ;; Arithmetic
      ((== b #x8b) OP-1ADD)
      ((== b #x8c) OP-1SUB)
      ;; Disabled arithmetic
      ((and (>= b #x8d) (<= b #x8e)) (OP-DISABLED b))
      ((== b #x8f) OP-NEGATE)
      ((== b #x90) OP-ABS)
      ((== b #x91) OP-NOT)
      ((== b #x92) OP-0NOTEQUAL)
      ((== b #x93) OP-ADD)
      ((== b #x94) OP-SUB)
      ;; Disabled arithmetic
      ((and (>= b #x95) (<= b #x99)) (OP-DISABLED b))
      ((== b #x9a) OP-BOOLAND)
      ((== b #x9b) OP-BOOLOR)
      ((== b #x9c) OP-NUMEQUAL)
      ((== b #x9d) OP-NUMEQUALVERIFY)
      ((== b #x9e) OP-NUMNOTEQUAL)
      ((== b #x9f) OP-LESSTHAN)
      ((== b #xa0) OP-GREATERTHAN)
      ((== b #xa1) OP-LESSTHANOREQUAL)
      ((== b #xa2) OP-GREATERTHANOREQUAL)
      ((== b #xa3) OP-MIN)
      ((== b #xa4) OP-MAX)
      ((== b #xa5) OP-WITHIN)
      ;; Crypto
      ((== b #xa6) OP-RIPEMD160)
      ((== b #xa7) OP-SHA1)
      ((== b #xa8) OP-SHA256)
      ((== b #xa9) OP-HASH160)
      ((== b #xaa) OP-HASH256)
      ((== b #xab) OP-CODESEPARATOR)
      ((== b #xac) OP-CHECKSIG)
      ((== b #xad) OP-CHECKSIGVERIFY)
      ((== b #xae) OP-CHECKMULTISIG)
      ((== b #xaf) OP-CHECKMULTISIGVERIFY)
      ;; Timelocks and NOP1-10
      ((== b #xb0) OP-NOP1)
      ((== b #xb1) OP-CHECKLOCKTIMEVERIFY)
      ((== b #xb2) OP-CHECKSEQUENCEVERIFY)
      ((== b #xb3) OP-NOP4)
      ((== b #xb4) OP-NOP5)
      ((== b #xb5) OP-NOP6)
      ((== b #xb6) OP-NOP7)
      ((== b #xb7) OP-NOP8)
      ((== b #xb8) OP-NOP9)
      ((== b #xb9) OP-NOP10)
      ;; Tapscript opcode
      ((== b #xba) OP-CHECKSIGADD)
      ;; Everything else
      (True (OP-UNKNOWN b))))

  ;;;; Opcode predicates

  (declare is-push-op (Opcode -> Boolean))
  (define (is-push-op op)
    "Return True if this opcode pushes data onto the stack."
    (match op
      ((OP-0) True)
      ((OP-PUSHBYTES _n) True)
      ((OP-PUSHDATA1) True)
      ((OP-PUSHDATA2) True)
      ((OP-PUSHDATA4) True)
      ((OP-1NEGATE) True)
      ((OP-1) True)
      ((OP-2) True)
      ((OP-3) True)
      ((OP-4) True)
      ((OP-5) True)
      ((OP-6) True)
      ((OP-7) True)
      ((OP-8) True)
      ((OP-9) True)
      ((OP-10) True)
      ((OP-11) True)
      ((OP-12) True)
      ((OP-13) True)
      ((OP-14) True)
      ((OP-15) True)
      ((OP-16) True)
      (_ False)))

  (declare is-disabled-op (Opcode -> Boolean))
  (define (is-disabled-op op)
    "Return True if this opcode is disabled."
    (match op
      ((OP-DISABLED _n) True)
      (_ False)))

  (declare is-conditional-op (Opcode -> Boolean))
  (define (is-conditional-op op)
    "Return True if this opcode is a conditional flow control opcode."
    (match op
      ((OP-IF) True)
      ((OP-NOTIF) True)
      ((OP-ELSE) True)
      ((OP-ENDIF) True)
      (_other False)))

  ;;; ============================================================
  ;;; Value Conversions
  ;;; ============================================================

  (declare bytes-to-script-num ((Vector U8) -> (ScriptResult ScriptNum)))
  (define (bytes-to-script-num bytes)
    "Convert script bytes to a ScriptNum.
     Uses little-endian encoding with sign bit in MSB.
     When MINIMALDATA flag is enabled, validates minimal encoding."
    (let ((len (the UFix (coalton-library/vector:length bytes))))
      (if (== len 0)
          (ScriptOk (ScriptNum 0))
          (lisp (ScriptResult ScriptNum) (bytes len)
            ;; Check MINIMALDATA validation if flag is enabled
            (cl:let* ((flag-fn (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP")))
                      (minimal-fn (cl:fdefinition (cl:intern "MINIMAL-NUMBER-ENCODING-P" "BITCOIN-LISP.COALTON.INTEROP"))))
              (cl:when (cl:and (cl:funcall flag-fn "MINIMALDATA")
                               (cl:not (cl:funcall minimal-fn bytes)))
                (cl:return-from bytes-to-script-num (ScriptErr SE-MinimalData))))
            ;; Convert to number
            (cl:let* ((negative (cl:logbitp 7 (cl:aref bytes (cl:1- len))))
                      (abs-value
                        (cl:loop :for i :from 0 :below len
                                 :sum (cl:ash (cl:logand
                                                (cl:aref bytes i)
                                                (cl:if (cl:= i (cl:1- len))
                                                       #x7F
                                                       #xFF))
                                              (cl:* i 8)))))
              (ScriptOk (ScriptNum (cl:if negative (cl:- abs-value) abs-value))))))))

  (declare script-num-to-bytes (ScriptNum -> (Vector U8)))
  (define (script-num-to-bytes sn)
    "Convert a ScriptNum to minimally-encoded bytes.
     Uses little-endian encoding with sign bit in MSB."
    (let ((n (script-num-value sn)))
      (if (== n 0)
          (lisp (Vector U8) () (cl:vector))
          (lisp (Vector U8) (n)
            (cl:let* ((negative (cl:minusp n))
                      (abs-num (cl:abs n))
                      (bytes-list (cl:loop :for val = abs-num :then (cl:ash val -8)
                                           :while (cl:plusp val)
                                           :collect (cl:logand val #xFF)))
                      (result (cl:coerce bytes-list 'cl:vector))
                      (last-idx (cl:1- (cl:length result))))
              ;; If high bit is set, we need an extra byte for sign
              (cl:when (cl:logbitp 7 (cl:aref result last-idx))
                (cl:setf result (cl:concatenate 'cl:vector result
                                                (cl:if negative #(#x80) #(#x00))))
                (cl:setf last-idx (cl:1- (cl:length result))))
              ;; Set sign bit if negative
              (cl:when (cl:and negative (cl:> (cl:length result) 0))
                (cl:setf (cl:aref result (cl:1- (cl:length result)))
                         (cl:logior (cl:aref result (cl:1- (cl:length result))) #x80)))
              result)))))

  (declare cast-to-bool ((Vector U8) -> Boolean))
  (define (cast-to-bool bytes)
    "Convert script bytes to boolean.
     Returns False for empty vector, all zeros, or negative zero (0x80)."
    (lisp Boolean (bytes)
      (cl:not (cl:or (cl:zerop (cl:length bytes))
                     (cl:every #'cl:zerop bytes)
                     (cl:and (cl:= (cl:length bytes) 1)
                             (cl:= (cl:aref bytes 0) #x80))))))

  (declare script-num-in-range (ScriptNum -> Boolean))
  (define (script-num-in-range sn)
    "Check if a ScriptNum is within the 4-byte arithmetic range.
     Bitcoin script arithmetic is limited to signed 32-bit values."
    (let ((n (script-num-value sn)))
      (and (>= n -2147483647) (<= n 2147483647))))

  (declare require-minimal-encoding ((Vector U8) -> (ScriptResult Unit)))
  (define (require-minimal-encoding bytes)
    "Validate that bytes use minimal encoding for script numbers.
     Rejects unnecessary leading zero bytes."
    (let ((len (the UFix (coalton-library/vector:length bytes))))
      (cond
        ;; Empty is valid
        ((== len 0) (ScriptOk Unit))
        ;; Single byte is always minimal
        ((== len 1) (ScriptOk Unit))
        ;; Check for non-minimal encoding
        (True
         (lisp (ScriptResult Unit) (bytes len)
           (cl:let ((last-byte (cl:aref bytes (cl:1- len)))
                    (second-last (cl:aref bytes (cl:- len 2))))
             ;; Non-minimal if last byte is 0x00 or 0x80 and second-last
             ;; doesn't have high bit set
             (cl:if (cl:and (cl:or (cl:= last-byte 0)
                                   (cl:= last-byte #x80))
                            (cl:not (cl:logbitp 7 second-last)))
                    (ScriptErr SE-InvalidNumber)
                    (ScriptOk Unit))))))))

  (declare check-minimal-push (U8 -> (Vector U8) -> (ScriptResult Unit)))
  (define (check-minimal-push opcode data)
    "Check if a push operation uses minimal encoding.
     Returns ScriptErr SE-MinimalData if MINIMALDATA flag is enabled and push is non-minimal.
     OPCODE is the push opcode byte."
    (lisp (ScriptResult Unit) (opcode data)
      (cl:let* ((flag-fn (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP")))
                (minimal-fn (cl:fdefinition (cl:intern "MINIMAL-PUSH-ENCODING-P" "BITCOIN-LISP.COALTON.INTEROP"))))
        (cl:if (cl:and (cl:funcall flag-fn "MINIMALDATA")
                       (cl:not (cl:funcall minimal-fn opcode (cl:length data) data)))
               (ScriptErr SE-MinimalData)
               (ScriptOk Unit)))))

  (declare bytes-to-script-num-limited ((Vector U8) -> UFix -> (ScriptResult ScriptNum)))
  (define (bytes-to-script-num-limited bytes max-len)
    "Convert script bytes to a ScriptNum, enforcing maximum length.
     Used for arithmetic operations which are limited to 4 bytes."
    (let ((len (the UFix (coalton-library/vector:length bytes))))
      (if (> len max-len)
          (ScriptErr SE-NumberOverflow)
          (bytes-to-script-num bytes))))

  ;;; ============================================================
  ;;; Stack Operations
  ;;; ============================================================

  ;; Stack is a list of byte vectors (top of stack is head of list)
  (define-type-alias ScriptStack (List (Vector U8)))

  (declare empty-stack (Unit -> ScriptStack))
  (define (empty-stack)
    "Return an empty script stack."
    Nil)

  (declare stack-push ((Vector U8) -> ScriptStack -> ScriptStack))
  (define (stack-push value stack)
    "Push a value onto the stack."
    (Cons value stack))

  (declare stack-pop (ScriptStack -> (Optional (Tuple (Vector U8) ScriptStack))))
  (define (stack-pop stack)
    "Pop a value from the stack. Returns None if stack is empty."
    (match stack
      ((Nil) None)
      ((Cons top rest) (Some (Tuple top rest)))))

  (declare stack-top (ScriptStack -> (Optional (Vector U8))))
  (define (stack-top stack)
    "Peek at the top value without removing it."
    (match stack
      ((Nil) None)
      ((Cons top _) (Some top))))

  (declare stack-depth (ScriptStack -> UFix))
  (define (stack-depth stack)
    "Return the number of items on the stack."
    (lisp UFix (stack)
      (cl:length stack)))

  (declare stack-pick (UFix -> ScriptStack -> (Optional (Vector U8))))
  (define (stack-pick n stack)
    "Get the nth item from the stack (0 = top)."
    (lisp (Optional (Vector U8)) (n stack)
      (cl:if (cl:>= n (cl:length stack))
             None
             (Some (cl:nth n stack)))))

  (declare stack-roll (UFix -> ScriptStack -> (Optional ScriptStack)))
  (define (stack-roll n stack)
    "Move the nth item to the top of the stack."
    (lisp (Optional ScriptStack) (n stack)
      (cl:if (cl:>= n (cl:length stack))
             None
             (cl:let* ((item (cl:nth n stack))
                       (before (cl:subseq stack 0 n))
                       (after (cl:nthcdr (cl:1+ n) stack)))
               (Some (cl:cons item (cl:append before after)))))))

  ;;;; Multi-element stack operations

  (declare stack-2dup (ScriptStack -> (Optional ScriptStack)))
  (define (stack-2dup stack)
    "Duplicate the top 2 items: [a b ...] -> [a b a b ...]"
    (match stack
      ((Cons a (Cons b rest))
       (Some (Cons a (Cons b (Cons a (Cons b rest))))))
      (_other None)))

  (declare stack-2drop (ScriptStack -> (Optional ScriptStack)))
  (define (stack-2drop stack)
    "Drop the top 2 items."
    (match stack
      ((Cons _ (Cons _ rest)) (Some rest))
      (_other None)))

  (declare stack-2swap (ScriptStack -> (Optional ScriptStack)))
  (define (stack-2swap stack)
    "Swap the top 2 pairs: [a b c d ...] -> [c d a b ...]"
    (match stack
      ((Cons a (Cons b (Cons c (Cons d rest))))
       (Some (Cons c (Cons d (Cons a (Cons b rest))))))
      (_other None)))

  (declare stack-2over (ScriptStack -> (Optional ScriptStack)))
  (define (stack-2over stack)
    "Copy 3rd and 4th items to top: [a b c d ...] -> [c d a b c d ...]"
    (match stack
      ((Cons a (Cons b (Cons c (Cons d rest))))
       (Some (Cons c (Cons d (Cons a (Cons b (Cons c (Cons d rest))))))))
      (_other None)))

  (declare stack-2rot (ScriptStack -> (Optional ScriptStack)))
  (define (stack-2rot stack)
    "Rotate top 6 items: [a b c d e f ...] -> [e f a b c d ...]"
    (match stack
      ((Cons a (Cons b (Cons c (Cons d (Cons e (Cons f rest))))))
       (Some (Cons e (Cons f (Cons a (Cons b (Cons c (Cons d rest))))))))
      (_other None)))

  (declare stack-3dup (ScriptStack -> (Optional ScriptStack)))
  (define (stack-3dup stack)
    "Duplicate the top 3 items."
    (match stack
      ((Cons a (Cons b (Cons c rest)))
       (Some (Cons a (Cons b (Cons c (Cons a (Cons b (Cons c rest))))))))
      (_other None)))

  (declare stack-rot (ScriptStack -> (Optional ScriptStack)))
  (define (stack-rot stack)
    "Rotate top 3 items: [a b c ...] -> [c a b ...]"
    (match stack
      ((Cons a (Cons b (Cons c rest)))
       (Some (Cons c (Cons a (Cons b rest)))))
      (_other None)))

  (declare stack-over (ScriptStack -> (Optional ScriptStack)))
  (define (stack-over stack)
    "Copy second item to top: [a b ...] -> [b a b ...]"
    (match stack
      ((Cons a (Cons b rest))
       (Some (Cons b (Cons a (Cons b rest)))))
      (_other None)))

  (declare stack-nip (ScriptStack -> (Optional ScriptStack)))
  (define (stack-nip stack)
    "Remove second item: [a b ...] -> [a ...]"
    (match stack
      ((Cons a (Cons _ rest))
       (Some (Cons a rest)))
      (_other None)))

  (declare stack-tuck (ScriptStack -> (Optional ScriptStack)))
  (define (stack-tuck stack)
    "Copy top before second: [a b ...] -> [a b a ...]"
    (match stack
      ((Cons a (Cons b rest))
       (Some (Cons a (Cons b (Cons a rest)))))
      (_other None)))

  (declare stack-swap (ScriptStack -> (Optional ScriptStack)))
  (define (stack-swap stack)
    "Swap top 2 items: [a b ...] -> [b a ...]"
    (match stack
      ((Cons a (Cons b rest))
       (Some (Cons b (Cons a rest))))
      (_other None)))

  (declare stack-ifdup (ScriptStack -> (Optional ScriptStack)))
  (define (stack-ifdup stack)
    "Duplicate top if non-zero."
    (match stack
      ((Cons top rest)
       (if (cast-to-bool top)
           (Some (Cons top (Cons top rest)))
           (Some stack)))
      (_other None)))

  ;;; ============================================================
  ;;; Execution Context
  ;;; ============================================================

  ;; Script limits (as UFix for comparison with vector lengths)
  (declare +max-script-size+ UFix)
  (define +max-script-size+ 10000)
  (declare +max-stack-size+ UFix)
  (define +max-stack-size+ 1000)
  (declare +max-ops-per-script+ UFix)
  (define +max-ops-per-script+ 201)
  (declare +max-push-size+ UFix)
  (define +max-push-size+ 520)

  (define-type ScriptContext
    "Execution context for script validation.
     Fields: main-stack, alt-stack, script, position, condition-stack,
             executing, op-count, codesep-pos, tx-locktime, tx-version,
             input-sequence"
    (ScriptContext
     ScriptStack      ; main-stack
     ScriptStack      ; alt-stack
     (Vector U8)      ; script
     UFix             ; position
     (List Boolean)   ; condition-stack (for IF/ELSE nesting)
     Boolean          ; executing (False in unexecuted IF branch)
     UFix             ; op-count (for 201 limit)
     UFix             ; codesep-pos (for CHECKSIG)
     U32           ; tx-locktime (nLockTime for CLTV)
     I32           ; tx-version (for CSV version >= 2 check)
     U32))         ; input-sequence (nSequence for CSV)

  (declare make-script-context ((Vector U8) -> ScriptContext))
  (define (make-script-context script)
    "Create a new script execution context with default transaction values."
    (make-script-context-with-tx script 0 1 #xFFFFFFFF))

  (declare make-script-context-with-tx ((Vector U8) -> U32 -> I32 -> U32 -> ScriptContext))
  (define (make-script-context-with-tx script locktime version sequence)
    "Create a new script execution context with transaction context."
    (ScriptContext
     (empty-stack)      ; main-stack
     (empty-stack)      ; alt-stack
     script             ; script
     0                  ; position
     Nil                ; condition-stack
     True               ; executing
     0                  ; op-count
     0                  ; codesep-pos
     locktime           ; tx-locktime
     version            ; tx-version
     sequence))         ; input-sequence

  ;; Context accessors
  (declare context-main-stack (ScriptContext -> ScriptStack))
  (define (context-main-stack ctx)
    (match ctx ((ScriptContext s _ _ _ _ _ _ _ _ _ _) s)))

  (declare context-alt-stack (ScriptContext -> ScriptStack))
  (define (context-alt-stack ctx)
    (match ctx ((ScriptContext _ a _ _ _ _ _ _ _ _ _) a)))

  (declare context-script (ScriptContext -> (Vector U8)))
  (define (context-script ctx)
    (match ctx ((ScriptContext _ _ s _ _ _ _ _ _ _ _) s)))

  (declare context-position (ScriptContext -> UFix))
  (define (context-position ctx)
    (match ctx ((ScriptContext _ _ _ p _ _ _ _ _ _ _) p)))

  (declare context-condition-stack (ScriptContext -> (List Boolean)))
  (define (context-condition-stack ctx)
    (match ctx ((ScriptContext _ _ _ _ c _ _ _ _ _ _) c)))

  (declare context-executing (ScriptContext -> Boolean))
  (define (context-executing ctx)
    (match ctx ((ScriptContext _ _ _ _ _ e _ _ _ _ _) e)))

  (declare context-op-count (ScriptContext -> UFix))
  (define (context-op-count ctx)
    (match ctx ((ScriptContext _ _ _ _ _ _ o _ _ _ _) o)))

  (declare context-codesep-pos (ScriptContext -> UFix))
  (define (context-codesep-pos ctx)
    (match ctx ((ScriptContext _ _ _ _ _ _ _ c _ _ _) c)))

  (declare context-tx-locktime (ScriptContext -> U32))
  (define (context-tx-locktime ctx)
    (match ctx ((ScriptContext _ _ _ _ _ _ _ _ locktime _ _) locktime)))

  (declare context-tx-version (ScriptContext -> I32))
  (define (context-tx-version ctx)
    (match ctx ((ScriptContext _ _ _ _ _ _ _ _ _ ver _) ver)))

  (declare context-input-sequence (ScriptContext -> U32))
  (define (context-input-sequence ctx)
    (match ctx ((ScriptContext _ _ _ _ _ _ _ _ _ _ sq) sq)))

  ;; Context update helpers
  (declare context-with-main-stack (ScriptStack -> ScriptContext -> ScriptContext))
  (define (context-with-main-stack stack ctx)
    (match ctx
      ((ScriptContext _ alt script pos cond exec ops codesep locktime version seqnum)
       (ScriptContext stack alt script pos cond exec ops codesep locktime version seqnum))))

  (declare context-with-alt-stack (ScriptStack -> ScriptContext -> ScriptContext))
  (define (context-with-alt-stack alt ctx)
    (match ctx
      ((ScriptContext main _ script pos cond exec ops codesep locktime version seqnum)
       (ScriptContext main alt script pos cond exec ops codesep locktime version seqnum))))

  (declare context-with-position (UFix -> ScriptContext -> ScriptContext))
  (define (context-with-position pos ctx)
    (match ctx
      ((ScriptContext main alt script _ cond exec ops codesep locktime version seqnum)
       (ScriptContext main alt script pos cond exec ops codesep locktime version seqnum))))

  (declare context-with-condition-stack ((List Boolean) -> ScriptContext -> ScriptContext))
  (define (context-with-condition-stack cond ctx)
    (match ctx
      ((ScriptContext main alt script pos _ exec ops codesep locktime version seqnum)
       (ScriptContext main alt script pos cond exec ops codesep locktime version seqnum))))

  (declare context-with-executing (Boolean -> ScriptContext -> ScriptContext))
  (define (context-with-executing exec ctx)
    (match ctx
      ((ScriptContext main alt script pos cond _ ops codesep locktime version seqnum)
       (ScriptContext main alt script pos cond exec ops codesep locktime version seqnum))))

  (declare context-with-op-count (UFix -> ScriptContext -> ScriptContext))
  (define (context-with-op-count ops ctx)
    (match ctx
      ((ScriptContext main alt script pos cond exec _ codesep locktime version seqnum)
       (ScriptContext main alt script pos cond exec ops codesep locktime version seqnum))))

  (declare context-with-codesep-pos (UFix -> ScriptContext -> ScriptContext))
  (define (context-with-codesep-pos codesep ctx)
    (match ctx
      ((ScriptContext main alt script pos cond exec ops _ locktime version seqnum)
       (ScriptContext main alt script pos cond exec ops codesep locktime version seqnum))))

  (declare advance-position (UFix -> ScriptContext -> ScriptContext))
  (define (advance-position n ctx)
    "Advance the script position by n bytes."
    (context-with-position (+ (context-position ctx) n) ctx))

  (declare increment-op-count (ScriptContext -> ScriptContext))
  (define (increment-op-count ctx)
    "Increment the non-push operation count."
    (context-with-op-count (+ (context-op-count ctx) 1) ctx))

  ;;; ============================================================
  ;;; Conditional Execution Helpers
  ;;; ============================================================

  (declare all-true ((List Boolean) -> Boolean))
  (define (all-true lst)
    "Return True if all elements are True (or list is empty)."
    (match lst
      ((Nil) True)
      ((Cons x xs) (if x (all-true xs) False))))

  (declare update-executing-flag ((List Boolean) -> ScriptContext -> ScriptContext))
  (define (update-executing-flag cond-stack ctx)
    "Update both condition-stack and executing flag."
    (let ((new-exec (all-true cond-stack)))
      (context-with-executing new-exec
                              (context-with-condition-stack cond-stack ctx))))

  (declare push-condition (Boolean -> ScriptContext -> ScriptContext))
  (define (push-condition cond ctx)
    "Push a condition onto the condition stack and update executing."
    (let ((new-stack (Cons cond (context-condition-stack ctx))))
      (update-executing-flag new-stack ctx)))

  (declare pop-condition (ScriptContext -> (Optional ScriptContext)))
  (define (pop-condition ctx)
    "Pop a condition from the stack, return None if empty."
    (match (context-condition-stack ctx)
      ((Nil) None)
      ((Cons _ rest)
       (Some (update-executing-flag rest ctx)))))

  (declare toggle-top-condition (ScriptContext -> (Optional ScriptContext)))
  (define (toggle-top-condition ctx)
    "Toggle the top condition (for ELSE), return None if empty."
    (match (context-condition-stack ctx)
      ((Nil) None)
      ((Cons top rest)
       (let ((new-stack (Cons (not top) rest)))
         (Some (update-executing-flag new-stack ctx))))))

  (declare is-control-flow-op (Opcode -> Boolean))
  (define (is-control-flow-op op)
    "Return True if opcode is a control flow opcode that must always be processed."
    (match op
      ((OP-IF) True)
      ((OP-NOTIF) True)
      ((OP-ELSE) True)
      ((OP-ENDIF) True)
      (_other False)))

  (declare check-always-illegal-opcode (Opcode -> (ScriptResult Unit)))
  (define (check-always-illegal-opcode op)
    "Check if opcode is always illegal, even in non-executing branches.
     Disabled opcodes (OP_CAT, OP_SUBSTR, etc.) and reserved opcodes
     (OP_VERIF, OP_VERNOTIF) must fail everywhere.
     Returns (ScriptOk Unit) if OK to skip, (ScriptErr ...) if must fail."
    (match op
      ;; Disabled opcodes always fail
      ((OP-DISABLED _) (ScriptErr SE-DisabledOpcode))
      ;; VERIF (0x65) and VERNOTIF (0x66) are always illegal
      ;; They're decoded as OP-UNKNOWN, check the byte value
      ((OP-UNKNOWN byte)
       (if (or (== byte #x65) (== byte #x66))
           (ScriptErr SE-UnknownOpcode)
           ;; Other unknown opcodes only fail when executed
           (ScriptOk Unit)))
      ;; All other opcodes are OK to skip when not executing
      (_ (ScriptOk Unit))))

  ;;; ============================================================
  ;;; Script Reading Helpers
  ;;; ============================================================

  (declare read-script-byte (ScriptContext -> (ScriptResult (Tuple U8 ScriptContext))))
  (define (read-script-byte ctx)
    "Read a single byte from the script at current position."
    (let ((pos (context-position ctx))
          (script (context-script ctx)))
      (if (>= pos (the UFix (coalton-library/vector:length script)))
          (ScriptErr SE-InvalidPushData)
          (let ((byte (lisp U8 (script pos) (cl:aref script pos))))
            (ScriptOk (Tuple byte (advance-position 1 ctx)))))))

  (declare read-script-bytes (UFix -> ScriptContext -> (ScriptResult (Tuple (Vector U8) ScriptContext))))
  (define (read-script-bytes n ctx)
    "Read n bytes from the script at current position."
    (let ((pos (context-position ctx))
          (script (context-script ctx)))
      (if (> (+ pos n) (the UFix (coalton-library/vector:length script)))
          (ScriptErr SE-InvalidPushData)
          (let ((bytes (lisp (Vector U8) (script pos n)
                         (cl:subseq script pos (cl:+ pos n)))))
            (ScriptOk (Tuple bytes (advance-position n ctx)))))))

  ;;; ============================================================
  ;;; Opcode Execution
  ;;; ============================================================

  ;; Helper to push result onto stack in context
  (declare context-push ((Vector U8) -> ScriptContext -> ScriptContext))
  (define (context-push value ctx)
    (context-with-main-stack (stack-push value (context-main-stack ctx)) ctx))

  ;; Helper to get true/false bytes
  (declare true-bytes (Unit -> (Vector U8)))
  (define (true-bytes)
    (lisp (Vector U8) () #(1)))

  (declare false-bytes (Unit -> (Vector U8)))
  (define (false-bytes)
    (lisp (Vector U8) () #()))

  ;; Helper: check DISCOURAGE_UPGRADABLE_NOPS and return error or pass
  (declare check-discouraged-nop (ScriptContext -> (ScriptResult ScriptContext)))
  (define (check-discouraged-nop ctx)
    "If DISCOURAGE_UPGRADABLE_NOPS flag is set, return error; otherwise pass."
    (let ((discourage (lisp Boolean ()
                        (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                    "DISCOURAGE_UPGRADABLE_NOPS"))))
      (if discourage
          (ScriptErr SE-DiscourageUpgradableNops)
          (ScriptOk ctx))))

  ;; Helper: check if a script flag is enabled
  (declare flag-enabled (String -> Boolean))
  (define (flag-enabled flag-name)
    "Check if a script verification flag is enabled."
    (lisp Boolean (flag-name)
      (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                  flag-name)))

  ;; Execute a single opcode
  (declare execute-opcode (Opcode -> ScriptContext -> (ScriptResult ScriptContext)))
  (define (execute-opcode op ctx)
    "Execute a single opcode and return the updated context."
    (match op
      ;; OP_0 / OP_FALSE - push empty vector
      ((OP-0)
       (ScriptOk (context-push (false-bytes) ctx)))

      ;; OP_1NEGATE - push -1
      ((OP-1NEGATE)
       (ScriptOk (context-push (script-num-to-bytes (ScriptNum -1)) ctx)))

      ;; OP_1 through OP_16
      ((OP-1) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 1)) ctx)))
      ((OP-2) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 2)) ctx)))
      ((OP-3) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 3)) ctx)))
      ((OP-4) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 4)) ctx)))
      ((OP-5) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 5)) ctx)))
      ((OP-6) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 6)) ctx)))
      ((OP-7) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 7)) ctx)))
      ((OP-8) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 8)) ctx)))
      ((OP-9) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 9)) ctx)))
      ((OP-10) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 10)) ctx)))
      ((OP-11) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 11)) ctx)))
      ((OP-12) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 12)) ctx)))
      ((OP-13) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 13)) ctx)))
      ((OP-14) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 14)) ctx)))
      ((OP-15) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 15)) ctx)))
      ((OP-16) (ScriptOk (context-push (script-num-to-bytes (ScriptNum 16)) ctx)))

      ;; OP_NOP - no operation
      ((OP-NOP) (ScriptOk ctx))

      ;; OP_VERIFY - fail if top is false
      ((OP-VERIFY)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple top new-stack))
          (if (cast-to-bool top)
              (ScriptOk (context-with-main-stack new-stack ctx))
              (ScriptErr SE-VerifyFailed)))))

      ;; OP_RETURN - immediate failure
      ((OP-RETURN) (ScriptErr SE-OpReturn))

      ;; OP_DUP - duplicate top
      ((OP-DUP)
       (match (stack-top (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some top)
          (ScriptOk (context-push top ctx)))))

      ;; OP_DROP - drop top
      ((OP-DROP)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple _ new-stack))
          (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_SWAP - swap top 2
      ((OP-SWAP)
       (match (stack-swap (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_ROT - rotate top 3
      ((OP-ROT)
       (match (stack-rot (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_OVER - copy second to top
      ((OP-OVER)
       (match (stack-over (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_NIP - remove second
      ((OP-NIP)
       (match (stack-nip (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_TUCK - copy top before second
      ((OP-TUCK)
       (match (stack-tuck (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_SIZE - push byte length of top element (without removing it)
      ((OP-SIZE)
       (match (stack-top (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some top)
          (let ((size (lisp Integer (top) (cl:length top))))
            ;; Push size as script number (already on stack, we push size on top)
            (ScriptOk (context-with-main-stack
                       (stack-push (script-num-to-bytes (make-script-num size))
                                   (context-main-stack ctx))
                       ctx))))))

      ;; OP_2DROP
      ((OP-2DROP)
       (match (stack-2drop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_2DUP
      ((OP-2DUP)
       (match (stack-2dup (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_3DUP
      ((OP-3DUP)
       (match (stack-3dup (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_2SWAP
      ((OP-2SWAP)
       (match (stack-2swap (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_2OVER
      ((OP-2OVER)
       (match (stack-2over (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_2ROT
      ((OP-2ROT)
       (match (stack-2rot (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_IFDUP
      ((OP-IFDUP)
       (match (stack-ifdup (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some new-stack) (ScriptOk (context-with-main-stack new-stack ctx)))))

      ;; OP_DEPTH - push stack depth
      ((OP-DEPTH)
       (let ((depth (stack-depth (context-main-stack ctx))))
         (ScriptOk (context-push (script-num-to-bytes (ScriptNum (lisp Integer (depth) depth))) ctx))))

      ;; OP_PICK - copy nth item to top
      ((OP-PICK)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple n-bytes new-stack))
          (match (bytes-to-script-num n-bytes)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (let ((sn-val (script-num-value sn)))
               ;; Negative index is invalid
               (if (< sn-val 0)
                   (ScriptErr SE-InvalidStackOperation)
                   (let ((n (lisp UFix (sn-val) sn-val)))
                     (match (stack-pick n new-stack)
                       ((None) (ScriptErr SE-InvalidStackOperation))
                       ((Some value)
                        (ScriptOk (context-with-main-stack (stack-push value new-stack) ctx))))))))))))

      ;; OP_ROLL - move nth item to top
      ((OP-ROLL)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple n-bytes new-stack))
          (match (bytes-to-script-num n-bytes)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (let ((sn-val (script-num-value sn)))
               ;; Negative index is invalid
               (if (< sn-val 0)
                   (ScriptErr SE-InvalidStackOperation)
                   (let ((n (lisp UFix (sn-val) sn-val)))
                     (match (stack-roll n new-stack)
                       ((None) (ScriptErr SE-InvalidStackOperation))
                       ((Some rolled-stack)
                        (ScriptOk (context-with-main-stack rolled-stack ctx))))))))))))

      ;; OP_TOALTSTACK
      ((OP-TOALTSTACK)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple value new-main))
          (ScriptOk (context-with-alt-stack
                     (stack-push value (context-alt-stack ctx))
                     (context-with-main-stack new-main ctx))))))

      ;; OP_FROMALTSTACK
      ((OP-FROMALTSTACK)
       (match (stack-pop (context-alt-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple value new-alt))
          (ScriptOk (context-with-main-stack
                     (stack-push value (context-main-stack ctx))
                     (context-with-alt-stack new-alt ctx))))))

      ;; OP_EQUAL - push true if equal
      ((OP-EQUAL)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b new-stack))
             (let ((equal (lisp Boolean (a b) (cl:equalp a b))))
               (ScriptOk (context-with-main-stack
                          (stack-push (if equal (true-bytes) (false-bytes)) new-stack)
                          ctx))))))))

      ;; OP_EQUALVERIFY - fail if not equal
      ((OP-EQUALVERIFY)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b new-stack))
             (let ((equal (lisp Boolean (a b) (cl:equalp a b))))
               (if equal
                   (ScriptOk (context-with-main-stack new-stack ctx))
                   (ScriptErr SE-VerifyFailed))))))))

      ;; OP_HASH160 - RIPEMD160(SHA256(x))
      ((OP-HASH160)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple data new-stack))
          (let ((hash (compute-hash160 data)))
            (ScriptOk (context-with-main-stack
                       (stack-push (hash160-bytes hash) new-stack)
                       ctx))))))

      ;; OP_HASH256 - SHA256(SHA256(x))
      ((OP-HASH256)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple data new-stack))
          (let ((hash (compute-hash256 data)))
            (ScriptOk (context-with-main-stack
                       (stack-push (hash256-bytes hash) new-stack)
                       ctx))))))

      ;; OP_SHA256
      ((OP-SHA256)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple data new-stack))
          (let ((hash (compute-sha256 data)))
            (ScriptOk (context-with-main-stack
                       (stack-push (hash256-bytes hash) new-stack)
                       ctx))))))

      ;; OP_RIPEMD160
      ((OP-RIPEMD160)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple data new-stack))
          (let ((hash (compute-ripemd160 data)))
            (ScriptOk (context-with-main-stack
                       (stack-push (hash160-bytes hash) new-stack)
                       ctx))))))

      ;; Arithmetic operations

      ;; OP_1ADD
      ((OP-1ADD)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple bytes new-stack))
          (match (bytes-to-script-num-limited bytes 4)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (ScriptOk (context-with-main-stack
                        (stack-push (script-num-to-bytes (ScriptNum (+ (script-num-value sn) 1))) new-stack)
                        ctx)))))))

      ;; OP_1SUB
      ((OP-1SUB)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple bytes new-stack))
          (match (bytes-to-script-num-limited bytes 4)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (ScriptOk (context-with-main-stack
                        (stack-push (script-num-to-bytes (ScriptNum (- (script-num-value sn) 1))) new-stack)
                        ctx)))))))

      ;; OP_NEGATE
      ((OP-NEGATE)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple bytes new-stack))
          (match (bytes-to-script-num-limited bytes 4)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (ScriptOk (context-with-main-stack
                        (stack-push (script-num-to-bytes (ScriptNum (negate (script-num-value sn)))) new-stack)
                        ctx)))))))

      ;; OP_ABS
      ((OP-ABS)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple bytes new-stack))
          (match (bytes-to-script-num-limited bytes 4)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (ScriptOk (context-with-main-stack
                        (stack-push (script-num-to-bytes (ScriptNum (abs (script-num-value sn)))) new-stack)
                        ctx)))))))

      ;; OP_NOT - logical not (0 -> 1, non-zero -> 0)
      ((OP-NOT)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple bytes new-stack))
          (match (bytes-to-script-num-limited bytes 4)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (let ((result (if (== (script-num-value sn) 0) 1 0)))
               (ScriptOk (context-with-main-stack
                          (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                          ctx))))))))

      ;; OP_0NOTEQUAL
      ((OP-0NOTEQUAL)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple bytes new-stack))
          (match (bytes-to-script-num-limited bytes 4)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk sn)
             (let ((result (if (/= (script-num-value sn) 0) 1 0)))
               (ScriptOk (context-with-main-stack
                          (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                          ctx))))))))

      ;; OP_ADD
      ((OP-ADD)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (ScriptOk (context-with-main-stack
                              (stack-push (script-num-to-bytes
                                           (ScriptNum (+ (script-num-value b) (script-num-value a))))
                                          new-stack)
                              ctx)))))))))))

      ;; OP_SUB
      ((OP-SUB)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (ScriptOk (context-with-main-stack
                              (stack-push (script-num-to-bytes
                                           (ScriptNum (- (script-num-value b) (script-num-value a))))
                                          new-stack)
                              ctx)))))))))))

      ;; OP_BOOLAND
      ((OP-BOOLAND)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (and (/= (script-num-value a) 0)
                                          (/= (script-num-value b) 0))
                                     1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_BOOLOR
      ((OP-BOOLOR)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (or (/= (script-num-value a) 0)
                                         (/= (script-num-value b) 0))
                                     1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_NUMEQUAL
      ((OP-NUMEQUAL)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (== (script-num-value a) (script-num-value b)) 1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_NUMEQUALVERIFY
      ((OP-NUMEQUALVERIFY)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (if (== (script-num-value a) (script-num-value b))
                       (ScriptOk (context-with-main-stack new-stack ctx))
                       (ScriptErr SE-VerifyFailed)))))))))))

      ;; OP_NUMNOTEQUAL
      ((OP-NUMNOTEQUAL)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (/= (script-num-value a) (script-num-value b)) 1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_LESSTHAN
      ((OP-LESSTHAN)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (< (script-num-value b) (script-num-value a)) 1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_GREATERTHAN
      ((OP-GREATERTHAN)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (> (script-num-value b) (script-num-value a)) 1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_LESSTHANOREQUAL
      ((OP-LESSTHANOREQUAL)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (<= (script-num-value b) (script-num-value a)) 1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_GREATERTHANOREQUAL
      ((OP-GREATERTHANOREQUAL)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (if (>= (script-num-value b) (script-num-value a)) 1 0)))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_MIN
      ((OP-MIN)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (min (script-num-value a) (script-num-value b))))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_MAX
      ((OP-MAX)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple a-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple b-bytes new-stack))
             (match (bytes-to-script-num-limited a-bytes 4)
               ((ScriptErr e) (ScriptErr e))
               ((ScriptOk a)
                (match (bytes-to-script-num-limited b-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk b)
                   (let ((result (max (script-num-value a) (script-num-value b))))
                     (ScriptOk (context-with-main-stack
                                (stack-push (script-num-to-bytes (ScriptNum result)) new-stack)
                                ctx))))))))))))

      ;; OP_WITHIN - check if x is in [min, max)
      ((OP-WITHIN)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple max-bytes stack1))
          (match (stack-pop stack1)
            ((None) (ScriptErr SE-StackUnderflow))
            ((Some (Tuple min-bytes stack2))
             (match (stack-pop stack2)
               ((None) (ScriptErr SE-StackUnderflow))
               ((Some (Tuple x-bytes new-stack))
                (match (bytes-to-script-num-limited max-bytes 4)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk max-val)
                   (match (bytes-to-script-num-limited min-bytes 4)
                     ((ScriptErr e) (ScriptErr e))
                     ((ScriptOk min-val)
                      (match (bytes-to-script-num-limited x-bytes 4)
                        ((ScriptErr e) (ScriptErr e))
                        ((ScriptOk x)
                         (let ((in-range (and (>= (script-num-value x) (script-num-value min-val))
                                              (< (script-num-value x) (script-num-value max-val)))))
                           (ScriptOk (context-with-main-stack
                                      (stack-push (if in-range (true-bytes) (false-bytes)) new-stack)
                                      ctx))))))))))))))))

      ;; OP_CODESEPARATOR - mark position for CHECKSIG
      ((OP-CODESEPARATOR)
       (ScriptOk (context-with-codesep-pos (context-position ctx) ctx)))

      ;; Disabled opcodes
      ((OP-DISABLED _opcode) (ScriptErr SE-DisabledOpcode))

      ;; Unknown opcodes
      ((OP-UNKNOWN _opcode) (ScriptErr SE-UnknownOpcode))

      ;; Push data operations - these are handled by the execution loop
      ;; because they need to read additional bytes from the script
      ((OP-PUSHBYTES _opcode) (ScriptErr SE-InvalidPushData))
      ((OP-PUSHDATA1) (ScriptErr SE-InvalidPushData))
      ((OP-PUSHDATA2) (ScriptErr SE-InvalidPushData))
      ((OP-PUSHDATA4) (ScriptErr SE-InvalidPushData))

      ;; Flow control - IF/NOTIF/ELSE/ENDIF
      ((OP-IF)
       ;; If currently executing, pop and evaluate condition
       ;; If not executing, push False onto condition stack
       (if (context-executing ctx)
           (match (stack-pop (context-main-stack ctx))
             ((None) (ScriptErr SE-StackUnderflow))
             ((Some (Tuple top new-stack))
              ;; BIP 342: In Tapscript, IF/NOTIF argument must be empty or [0x01]
              (let ((is-tapscript (lisp Boolean ()
                                    (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                                "TAPSCRIPT"))))
                (if is-tapscript
                    ;; Tapscript: strict MINIMALIF - only empty or [0x01]
                    (let ((len (lisp UFix (top) (cl:length top))))
                      (cond
                        ;; Empty = false
                        ((== len 0)
                         (ScriptOk (push-condition False
                                                   (context-with-main-stack new-stack ctx))))
                        ;; [0x01] = true
                        ((== len 1)
                         (let ((b (lisp U8 (top) (cl:aref top 0))))
                           (if (== b 1)
                               (ScriptOk (push-condition True
                                                         (context-with-main-stack new-stack ctx)))
                               (ScriptErr SE-TapscriptMinimalIf))))
                        ;; Anything else is invalid
                        (True (ScriptErr SE-TapscriptMinimalIf))))
                    ;; Legacy: normal bool cast
                    (let ((cond-val (cast-to-bool top)))
                      (ScriptOk (push-condition cond-val
                                                (context-with-main-stack new-stack ctx))))))))
           ;; Not executing - just track nesting
           (ScriptOk (push-condition False ctx))))

      ((OP-NOTIF)
       ;; Same as IF but inverted
       (if (context-executing ctx)
           (match (stack-pop (context-main-stack ctx))
             ((None) (ScriptErr SE-StackUnderflow))
             ((Some (Tuple top new-stack))
              ;; BIP 342: In Tapscript, IF/NOTIF argument must be empty or [0x01]
              (let ((is-tapscript (lisp Boolean ()
                                    (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                                "TAPSCRIPT"))))
                (if is-tapscript
                    ;; Tapscript: strict MINIMALIF - only empty or [0x01]
                    (let ((len (lisp UFix (top) (cl:length top))))
                      (cond
                        ;; Empty = true (inverted)
                        ((== len 0)
                         (ScriptOk (push-condition True
                                                   (context-with-main-stack new-stack ctx))))
                        ;; [0x01] = false (inverted)
                        ((== len 1)
                         (let ((b (lisp U8 (top) (cl:aref top 0))))
                           (if (== b 1)
                               (ScriptOk (push-condition False
                                                         (context-with-main-stack new-stack ctx)))
                               (ScriptErr SE-TapscriptMinimalIf))))
                        ;; Anything else is invalid
                        (True (ScriptErr SE-TapscriptMinimalIf))))
                    ;; Legacy: normal bool cast (inverted)
                    (let ((cond-val (not (cast-to-bool top))))
                      (ScriptOk (push-condition cond-val
                                                (context-with-main-stack new-stack ctx))))))))
           ;; Not executing - just track nesting
           (ScriptOk (push-condition False ctx))))

      ((OP-ELSE)
       ;; Toggle the current condition
       (match (toggle-top-condition ctx)
         ((None) (ScriptErr SE-UnbalancedConditional))
         ((Some new-ctx) (ScriptOk new-ctx))))

      ((OP-ENDIF)
       ;; Pop a condition from the stack
       (match (pop-condition ctx)
         ((None) (ScriptErr SE-UnbalancedConditional))
         ((Some new-ctx) (ScriptOk new-ctx))))

      ;; Signature operations - placeholder implementations
      ((OP-SHA1)
       (match (stack-pop (context-main-stack ctx))
         ((None) (ScriptErr SE-StackUnderflow))
         ((Some (Tuple data new-stack))
          ;; SHA1 using Ironclad - convert types properly
          (let ((hash (lisp (Vector U8) (data)
                        (cl:let* ((cl-data (cl:coerce data '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                  (result (ironclad:digest-sequence :sha1 cl-data)))
                          (cl:map 'cl:vector #'cl:identity result)))))
            (ScriptOk (context-with-main-stack
                       (stack-push hash new-stack)
                       ctx))))))

      ((OP-CHECKSIG)
       ;; Pop pubkey and sig, verify signature
       (let ((is-tapscript (lisp Boolean ()
                             (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                         "TAPSCRIPT"))))
         (match (stack-pop (context-main-stack ctx))
           ((None) (ScriptErr SE-StackUnderflow))
           ((Some (Tuple pubkey stack1))
            (match (stack-pop stack1)
              ((None) (ScriptErr SE-StackUnderflow))
              ((Some (Tuple sig new-stack))
               (if is-tapscript
                   ;; Tapscript: Use Schnorr verification, fail on invalid non-empty sig
                   (let ((result (lisp UFix (sig pubkey)
                                   (cl:let* ((sig-arr (cl:coerce sig '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                             (pk-arr (cl:coerce pubkey '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                             (verify-fn (cl:fdefinition (cl:intern "VERIFY-TAPSCRIPT-SIGNATURE" "BITCOIN-LISP.COALTON.INTEROP"))))
                                     (cl:multiple-value-bind (status valid)
                                         (cl:funcall verify-fn sig-arr pk-arr)
                                       (cl:cond
                                         ((cl:eq status :empty-sig) 0)
                                         ((cl:and (cl:eq status :ok) valid) 1)
                                         (cl:t 2)))))))
                     (cond
                       ((== result 0)
                        (ScriptOk (context-with-main-stack
                                   (stack-push (false-bytes) new-stack)
                                   ctx)))
                       ((== result 1)
                        (ScriptOk (context-with-main-stack
                                   (stack-push (true-bytes) new-stack)
                                   ctx)))
                       (True
                        (ScriptErr SE-TapscriptInvalidSig))))
                   ;; Legacy/SegWit v0: Use ECDSA verification
                   (let ((valid (lisp Boolean (sig pubkey ctx)
                                  (cl:let* ((script (context-script ctx))
                                            (codesep-pos (context-codesep-pos ctx))
                                            (subscript-raw (cl:subseq script codesep-pos))
                                            ;; Ensure subscript is properly typed as (unsigned-byte 8) vector
                                            (subscript (cl:coerce subscript-raw '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                            (sig-arr (cl:coerce sig '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                            (pk-arr (cl:coerce pubkey '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                            (fn (cl:fdefinition (cl:intern "VERIFY-CHECKSIG-FOR-SCRIPT" "BITCOIN-LISP.COALTON.INTEROP"))))
                                    (cl:funcall fn sig-arr pk-arr subscript)))))
                     (let ((strictenc-error (lisp Boolean ()
                                              (cl:funcall (cl:fdefinition (cl:intern "LAST-CHECKSIG-HAD-STRICTENC-ERROR-P" "BITCOIN-LISP.COALTON.INTEROP"))))))
                       (if strictenc-error
                           (ScriptErr SE-VerifyFailed)
                           (ScriptOk (context-with-main-stack
                                      (stack-push (if valid (true-bytes) (false-bytes)) new-stack)
                                      ctx))))))))))))

      ((OP-CHECKSIGVERIFY)
       ;; CHECKSIG then VERIFY - verify signature and fail if invalid
       (let ((is-tapscript (lisp Boolean ()
                             (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                         "TAPSCRIPT"))))
         (match (stack-pop (context-main-stack ctx))
           ((None) (ScriptErr SE-StackUnderflow))
           ((Some (Tuple pubkey stack1))
            (match (stack-pop stack1)
              ((None) (ScriptErr SE-StackUnderflow))
              ((Some (Tuple sig new-stack))
               (if is-tapscript
                   ;; Tapscript: Use Schnorr verification
                   (let ((result (lisp UFix (sig pubkey)
                                   (cl:let* ((sig-arr (cl:coerce sig '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                             (pk-arr (cl:coerce pubkey '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                             (verify-fn (cl:fdefinition (cl:intern "VERIFY-TAPSCRIPT-SIGNATURE" "BITCOIN-LISP.COALTON.INTEROP"))))
                                     (cl:multiple-value-bind (status valid)
                                         (cl:funcall verify-fn sig-arr pk-arr)
                                       (cl:cond
                                         ((cl:eq status :empty-sig) 0)
                                         ((cl:and (cl:eq status :ok) valid) 1)
                                         (cl:t 2)))))))
                     (cond
                       ((== result 0)
                        (ScriptErr SE-VerifyFailed))
                       ((== result 1)
                        (ScriptOk (context-with-main-stack new-stack ctx)))
                       (True
                        (ScriptErr SE-TapscriptInvalidSig))))
                   ;; Legacy/SegWit v0: Use ECDSA verification
                   (let ((valid (lisp Boolean (sig pubkey ctx)
                                  (cl:let* ((script (context-script ctx))
                                            (codesep-pos (context-codesep-pos ctx))
                                            (subscript-raw (cl:subseq script codesep-pos))
                                            ;; Ensure subscript is properly typed as (unsigned-byte 8) vector
                                            (subscript (cl:coerce subscript-raw '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                            (sig-arr (cl:coerce sig '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                            (pk-arr (cl:coerce pubkey '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                            (fn (cl:fdefinition (cl:intern "VERIFY-CHECKSIG-FOR-SCRIPT" "BITCOIN-LISP.COALTON.INTEROP"))))
                                    (cl:funcall fn sig-arr pk-arr subscript)))))
                     (let ((strictenc-error (lisp Boolean ()
                                              (cl:funcall (cl:fdefinition (cl:intern "LAST-CHECKSIG-HAD-STRICTENC-ERROR-P" "BITCOIN-LISP.COALTON.INTEROP"))))))
                       (if strictenc-error
                           (ScriptErr SE-VerifyFailed)
                           (if valid
                               (ScriptOk (context-with-main-stack new-stack ctx))
                               (ScriptErr SE-VerifyFailed))))))))))))

      ((OP-CHECKMULTISIG)
       ;; m-of-n multisig verification
       ;; Stack: ... dummy sig1..sigM M pubkey1..pubkeyN N
       ;; Pops all, pushes true/false
       ;; Note: CHECKMULTISIG adds pubkey_count to op count for limit checking
       ;; BIP 342: Disabled in Tapscript context
       (let ((is-tapscript (lisp Boolean ()
                             (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                         "TAPSCRIPT"))))
         (if is-tapscript
             (ScriptErr SE-TapscriptCheckmultisig)
             (let ((result (lisp (Tuple3 UFix ScriptStack UFix) (ctx)
                       (cl:let* ((stack (context-main-stack ctx))
                                 (script (context-script ctx))
                                 (codesep-pos (context-codesep-pos ctx))
                                 (subscript-raw (cl:subseq script codesep-pos))
                                 ;; Ensure subscript is properly typed as (unsigned-byte 8) vector
                                 (subscript (cl:coerce subscript-raw '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                 (fn (cl:fdefinition (cl:intern "DO-CHECKMULTISIG-STACK-OP" "BITCOIN-LISP.COALTON.INTEROP"))))
                         (cl:multiple-value-bind (status new-stack pubkey-count)
                             (cl:funcall fn stack subscript)
                           (cl:case status
                             (:ok (Tuple3 0 new-stack pubkey-count))        ; success
                             (:fail (Tuple3 1 new-stack pubkey-count))      ; verify failed, push false
                             (:error (Tuple3 2 stack pubkey-count))         ; STRICTENC/NULLDUMMY error
                             (:underflow (Tuple3 3 stack pubkey-count))     ; stack underflow
                             (:pubkey-count (Tuple3 4 stack 0))  ; invalid pubkey count
                             (:sig-count (Tuple3 5 stack pubkey-count))     ; invalid sig count
                             (cl:otherwise (Tuple3 6 stack 0)))))))) ; unknown error
         (match result
           ((Tuple3 0 new-stack n-pubkeys)
            ;; Add pubkey count to op count and check limit
            (let ((new-op-count (+ (context-op-count ctx) n-pubkeys)))
              (if (> new-op-count +max-ops-per-script+)
                  (ScriptErr SE-TooManyOps)
                  (ScriptOk (context-with-op-count new-op-count
                              (context-with-main-stack new-stack ctx))))))
           ((Tuple3 1 new-stack n-pubkeys)
            ;; Add pubkey count to op count and check limit
            (let ((new-op-count (+ (context-op-count ctx) n-pubkeys)))
              (if (> new-op-count +max-ops-per-script+)
                  (ScriptErr SE-TooManyOps)
                  (ScriptOk (context-with-op-count new-op-count
                              (context-with-main-stack new-stack ctx))))))
           ((Tuple3 2 _ _) (ScriptErr SE-VerifyFailed))
           ((Tuple3 3 _ _) (ScriptErr SE-StackUnderflow))
           ((Tuple3 4 _ _) (ScriptErr SE-VerifyFailed))  ; invalid pubkey count
           ((Tuple3 5 _ _) (ScriptErr SE-VerifyFailed))  ; invalid sig count
           (_ (ScriptErr SE-UnknownOpcode)))))))

      ((OP-CHECKMULTISIGVERIFY)
       ;; CHECKMULTISIG then VERIFY - fail if result is false
       ;; Note: CHECKMULTISIGVERIFY adds pubkey_count to op count for limit checking
       ;; BIP 342: Disabled in Tapscript context
       (let ((is-tapscript (lisp Boolean ()
                             (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                         "TAPSCRIPT"))))
         (if is-tapscript
             (ScriptErr SE-TapscriptCheckmultisig)
             (let ((result (lisp (Tuple3 UFix ScriptStack UFix) (ctx)
                       (cl:let* ((stack (context-main-stack ctx))
                                 (script (context-script ctx))
                                 (codesep-pos (context-codesep-pos ctx))
                                 (subscript-raw (cl:subseq script codesep-pos))
                                 ;; Ensure subscript is properly typed as (unsigned-byte 8) vector
                                 (subscript (cl:coerce subscript-raw '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                 (fn (cl:fdefinition (cl:intern "DO-CHECKMULTISIG-STACK-OP" "BITCOIN-LISP.COALTON.INTEROP"))))
                         (cl:multiple-value-bind (status new-stack pubkey-count)
                             (cl:funcall fn stack subscript)
                           (cl:case status
                             (:ok (Tuple3 0 new-stack pubkey-count))
                             (:fail (Tuple3 1 new-stack pubkey-count))
                             (:error (Tuple3 2 stack pubkey-count))
                             (:underflow (Tuple3 3 stack pubkey-count))
                             (:pubkey-count (Tuple3 4 stack 0))
                             (:sig-count (Tuple3 5 stack pubkey-count))
                             (cl:otherwise (Tuple3 6 stack 0))))))))
         (match result
           ((Tuple3 0 new-stack n-pubkeys)
            ;; Add pubkey count to op count and check limit
            (let ((new-op-count (+ (context-op-count ctx) n-pubkeys)))
              (if (> new-op-count +max-ops-per-script+)
                  (ScriptErr SE-TooManyOps)
                  ;; Success - pop the true value that was pushed and continue
                  (match (stack-pop new-stack)
                    ((None) (ScriptErr SE-StackUnderflow))
                    ((Some (Tuple _ final-stack))
                     (ScriptOk (context-with-op-count new-op-count
                                 (context-with-main-stack final-stack ctx))))))))
           ((Tuple3 1 _ _) (ScriptErr SE-VerifyFailed))  ; multisig failed
           ((Tuple3 2 _ _) (ScriptErr SE-VerifyFailed))  ; STRICTENC/NULLDUMMY error
           ((Tuple3 3 _ _) (ScriptErr SE-StackUnderflow))
           ((Tuple3 4 _ _) (ScriptErr SE-VerifyFailed))  ; invalid pubkey count
           ((Tuple3 5 _ _) (ScriptErr SE-VerifyFailed))  ; invalid sig count
           (_ (ScriptErr SE-UnknownOpcode)))))))

      ;; OP_CHECKSIGADD (BIP 342) - only valid in Tapscript context
      ;; Stack: sig n pubkey -> n' (n+1 if valid, n if empty sig, fail if invalid)
      ((OP-CHECKSIGADD)
       (let ((is-tapscript (lisp Boolean ()
                             (cl:funcall (cl:fdefinition (cl:intern "FLAG-ENABLED-P" "BITCOIN-LISP.COALTON.INTEROP"))
                                         "TAPSCRIPT"))))
         (if (not is-tapscript)
             ;; In non-Tapscript context, this is an unknown opcode
             (ScriptErr SE-UnknownOpcode)
             ;; Tapscript: Pop pubkey, n, sig; verify; push n+valid
             (match (stack-pop (context-main-stack ctx))
               ((None) (ScriptErr SE-StackUnderflow))
               ((Some (Tuple pubkey stack1))
                (match (stack-pop stack1)
                  ((None) (ScriptErr SE-StackUnderflow))
                  ((Some (Tuple n-bytes stack2))
                   (match (stack-pop stack2)
                     ((None) (ScriptErr SE-StackUnderflow))
                     ((Some (Tuple sig new-stack))
                      ;; Verify signature and compute result
                      (let ((result (lisp UFix (sig pubkey)
                                      (cl:let* ((sig-arr (cl:coerce sig '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                                (pk-arr (cl:coerce pubkey '(cl:simple-array (cl:unsigned-byte 8) (cl:*))))
                                                (verify-fn (cl:fdefinition (cl:intern "VERIFY-TAPSCRIPT-SIGNATURE" "BITCOIN-LISP.COALTON.INTEROP"))))
                                        (cl:multiple-value-bind (status valid)
                                            (cl:funcall verify-fn sig-arr pk-arr)
                                          (cl:cond
                                            ((cl:eq status :empty-sig) 0)
                                            ((cl:and (cl:eq status :ok) valid) 1)
                                            (cl:t 2)))))))
                        (cond
                          ;; Empty sig: push n unchanged
                          ((== result 0)
                           (ScriptOk (context-with-main-stack
                                      (stack-push n-bytes new-stack)
                                      ctx)))
                          ;; Valid sig: push n+1 (increment the script number)
                          ((== result 1)
                           (let ((n-plus-1 (lisp (Vector U8) (n-bytes)
                                             (cl:funcall (cl:fdefinition (cl:intern "INCREMENT-SCRIPT-NUMBER" "BITCOIN-LISP.COALTON.INTEROP")) n-bytes))))
                             (ScriptOk (context-with-main-stack
                                        (stack-push n-plus-1 new-stack)
                                        ctx))))
                          ;; Invalid non-empty sig: fail
                          (True
                           (ScriptErr SE-TapscriptInvalidSig)))))))))))))

      ;; Timelocks and NOP1-10
      ;; NOP1 and NOP4-10 are true no-ops unless DISCOURAGE_UPGRADABLE_NOPS flag is set
      ((OP-NOP1) (check-discouraged-nop ctx))
      ((OP-NOP4) (check-discouraged-nop ctx))
      ((OP-NOP5) (check-discouraged-nop ctx))
      ((OP-NOP6) (check-discouraged-nop ctx))
      ((OP-NOP7) (check-discouraged-nop ctx))
      ((OP-NOP8) (check-discouraged-nop ctx))
      ((OP-NOP9) (check-discouraged-nop ctx))
      ((OP-NOP10) (check-discouraged-nop ctx))

      ;; CHECKLOCKTIMEVERIFY (BIP 65)
      ((OP-CHECKLOCKTIMEVERIFY)
       (if (not (flag-enabled "CHECKLOCKTIMEVERIFY"))
           ;; No CLTV flag - treat as NOP2
           (check-discouraged-nop ctx)
           ;; CLTV flag enabled - full BIP 65 validation
             ;; Does NOT pop the stack value
             (match (stack-top (context-main-stack ctx))
               ((None) (ScriptErr SE-StackUnderflow))
               ((Some top)
                ;; 5-byte script number (not the default 4-byte arithmetic limit)
                (match (bytes-to-script-num-limited top 5)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk sn)
                   (let ((n (script-num-value sn)))
                     ;; Must be non-negative
                     (if (< n 0)
                         (ScriptErr SE-NegativeLocktime)
                         (let ((tx-lt (the Integer (into (context-tx-locktime ctx)))))
                           ;; Type match: both height-based or both time-based
                           ;; Height: < 500,000,000. Time: >= 500,000,000
                           (if (lisp Boolean (n tx-lt)
                                 (cl:not (cl:or (cl:and (cl:< n 500000000) (cl:< tx-lt 500000000))
                                                (cl:and (cl:>= n 500000000) (cl:>= tx-lt 500000000)))))
                               (ScriptErr SE-UnsatisfiedLocktime)
                               ;; Stack top must be <= nLockTime
                               (if (> n tx-lt)
                                   (ScriptErr SE-UnsatisfiedLocktime)
                                   ;; Input nSequence must not be 0xFFFFFFFF (locktime disabled)
                                   (if (== (context-input-sequence ctx) #xFFFFFFFF)
                                       (ScriptErr SE-UnsatisfiedLocktime)
                                       (ScriptOk ctx)))))))))))))

      ;; CHECKSEQUENCEVERIFY (BIP 112)
      ((OP-CHECKSEQUENCEVERIFY)
       (if (not (flag-enabled "CHECKSEQUENCEVERIFY"))
           ;; No CSV flag - treat as NOP3
           (check-discouraged-nop ctx)
           ;; CSV flag enabled - full BIP 112 validation
             ;; Does NOT pop the stack value
             (match (stack-top (context-main-stack ctx))
               ((None) (ScriptErr SE-StackUnderflow))
               ((Some top)
                ;; 5-byte script number (not the default 4-byte arithmetic limit)
                (match (bytes-to-script-num-limited top 5)
                  ((ScriptErr e) (ScriptErr e))
                  ((ScriptOk sn)
                   (let ((n (script-num-value sn)))
                     ;; Must be non-negative
                     (if (< n 0)
                         (ScriptErr SE-NegativeLocktime)
                         ;; If bit 31 (disable flag) is set on stack value, pass as NOP
                         (if (/= 0 (lisp Integer (n) (cl:logand n #x80000000)))
                             (ScriptOk ctx)
                             ;; Transaction version must be >= 2
                             (if (< (context-tx-version ctx) 2)
                                 (ScriptErr SE-UnsatisfiedLocktime)
                                 ;; Input nSequence bit 31 must not be set (disable flag)
                                 (let ((input-seq (the Integer (into (context-input-sequence ctx)))))
                                   (if (/= 0 (lisp Integer (input-seq) (cl:logand input-seq #x80000000)))
                                       (ScriptErr SE-UnsatisfiedLocktime)
                                       ;; Mask both with 0x0040FFFF and compare
                                       (let ((n-masked (lisp Integer (n) (cl:logand n #x0040FFFF)))
                                             (seq-masked (lisp Integer (input-seq) (cl:logand input-seq #x0040FFFF))))
                                         ;; Type flags (bit 22) must match
                                         (if (lisp Boolean (n-masked seq-masked)
                                               (cl:not (cl:or
                                                        (cl:and (cl:< n-masked #x00400000) (cl:< seq-masked #x00400000))
                                                        (cl:and (cl:>= n-masked #x00400000) (cl:>= seq-masked #x00400000)))))
                                             (ScriptErr SE-UnsatisfiedLocktime)
                                             ;; Stack top masked value must be <= nSequence masked value
                                             (if (> n-masked seq-masked)
                                                 (ScriptErr SE-UnsatisfiedLocktime)
                                                 (ScriptOk ctx))))))))))))))))))

  ;;; ============================================================
  ;;; Script Execution
  ;;; ============================================================

  (declare execute-script ((Vector U8) -> (ScriptResult ScriptStack)))
  (define (execute-script script)
    "Execute a script and return the final stack (default tx context)."
    (execute-script-with-tx script 0 1 #xFFFFFFFF))

  (declare execute-script-with-tx ((Vector U8) -> U32 -> I32 -> U32 -> (ScriptResult ScriptStack)))
  (define (execute-script-with-tx script locktime version sequence)
    "Execute a script with transaction context.
     Returns ScriptErr on failure or ScriptOk with final stack on success."
    (let ((len (the UFix (coalton-library/vector:length script))))
      ;; Check script size limit
      (if (> len +max-script-size+)
          (ScriptErr SE-ScriptTooLarge)
          (execute-script-loop (make-script-context-with-tx script locktime version sequence)))))

  (declare execute-script-loop (ScriptContext -> (ScriptResult ScriptStack)))
  (define (execute-script-loop ctx)
    "Main execution loop for script processing."
    (let ((pos (context-position ctx))
          (script (context-script ctx))
          (len (the UFix (coalton-library/vector:length script)))
          (exec (context-executing ctx)))
      (if (>= pos len)
          ;; Script finished - check for unbalanced conditionals
          (match (context-condition-stack ctx)
            ((Nil) (ScriptOk (context-main-stack ctx)))
            (_other (ScriptErr SE-UnbalancedConditional)))
          ;; Read and execute next opcode
          (match (read-script-byte ctx)
            ((ScriptErr e) (ScriptErr e))
            ((ScriptOk (Tuple byte new-ctx))
             (let ((op (byte-to-opcode byte)))
               ;; Check op count limit: only opcodes > OP_16 (0x60) count towards limit
               ;; This includes all ops except push data ops (0x00-0x4e), OP_1NEGATE (0x4f),
               ;; OP_RESERVED (0x50), and OP_1-OP_16 (0x51-0x60)
               (let ((ctx-with-count
                       (if (<= byte #x60)
                           new-ctx
                           ;; Always increment count (even past limit) so check can detect it
                           (context-with-op-count (+ (context-op-count new-ctx) 1) new-ctx))))
                 ;; Check if we exceeded op count (always, even in non-executing branches)
                 (if (> (context-op-count ctx-with-count) +max-ops-per-script+)
                     (ScriptErr SE-TooManyOps)
                     ;; Handle push operations specially
                     (match op
                       ;; Direct push (1-75 bytes)
                       ((OP-PUSHBYTES n)
                        (match (read-script-bytes (lisp UFix (n) n) ctx-with-count)
                          ((ScriptErr e) (ScriptErr e))
                          ((ScriptOk (Tuple data next-ctx))
                           ;; Only push if executing
                           (if exec
                               ;; MINIMALDATA: check if push encoding is minimal
                               (match (check-minimal-push n data)
                                 ((ScriptErr e) (ScriptErr e))
                                 ((ScriptOk _)
                                  (execute-script-loop (context-push data next-ctx))))
                               (execute-script-loop next-ctx)))))

                       ;; OP_PUSHDATA1 - 1 byte length prefix
                       ((OP-PUSHDATA1)
                        (match (read-script-byte ctx-with-count)
                          ((ScriptErr e) (ScriptErr e))
                          ((ScriptOk (Tuple len-byte len-ctx))
                           (let ((push-len (lisp UFix (len-byte) len-byte)))
                             ;; Check push size limit (always, even in non-executing branches)
                             (if (> push-len +max-push-size+)
                                 (ScriptErr SE-PushSize)
                                 (match (read-script-bytes push-len len-ctx)
                                   ((ScriptErr e) (ScriptErr e))
                                   ((ScriptOk (Tuple data next-ctx))
                                    (if exec
                                        ;; MINIMALDATA: check if PUSHDATA1 encoding is minimal
                                        (match (check-minimal-push #x4c data)
                                          ((ScriptErr e) (ScriptErr e))
                                          ((ScriptOk _)
                                           (execute-script-loop (context-push data next-ctx))))
                                        (execute-script-loop next-ctx)))))))))

                       ;; OP_PUSHDATA2 - 2 byte length prefix (little endian)
                       ((OP-PUSHDATA2)
                        (match (read-script-bytes 2 ctx-with-count)
                          ((ScriptErr e) (ScriptErr e))
                          ((ScriptOk (Tuple len-bytes len-ctx))
                           (let ((data-len (lisp UFix (len-bytes)
                                             (cl:+ (cl:aref len-bytes 0)
                                                   (cl:ash (cl:aref len-bytes 1) 8)))))
                             ;; Check push size limit (always, even in non-executing branches)
                             (if (> data-len +max-push-size+)
                                 (ScriptErr SE-PushSize)
                                 (match (read-script-bytes data-len len-ctx)
                                   ((ScriptErr e) (ScriptErr e))
                                   ((ScriptOk (Tuple data next-ctx))
                                    (if exec
                                        ;; MINIMALDATA: check if PUSHDATA2 encoding is minimal
                                        (match (check-minimal-push #x4d data)
                                          ((ScriptErr e) (ScriptErr e))
                                          ((ScriptOk _)
                                           (execute-script-loop (context-push data next-ctx))))
                                        (execute-script-loop next-ctx)))))))))

                       ;; OP_PUSHDATA4 - 4 byte length prefix (little endian)
                       ((OP-PUSHDATA4)
                        (match (read-script-bytes 4 ctx-with-count)
                          ((ScriptErr e) (ScriptErr e))
                          ((ScriptOk (Tuple len-bytes len-ctx))
                           (let ((data-len (lisp UFix (len-bytes)
                                             (cl:+ (cl:aref len-bytes 0)
                                                   (cl:ash (cl:aref len-bytes 1) 8)
                                                   (cl:ash (cl:aref len-bytes 2) 16)
                                                   (cl:ash (cl:aref len-bytes 3) 24)))))
                             ;; Check push size limit (always, even in non-executing branches)
                             (if (> data-len +max-push-size+)
                                 (ScriptErr SE-PushSize)
                                 (match (read-script-bytes data-len len-ctx)
                                   ((ScriptErr e) (ScriptErr e))
                                   ((ScriptOk (Tuple data next-ctx))
                                    (if exec
                                        ;; MINIMALDATA: check if PUSHDATA4 encoding is minimal
                                        (match (check-minimal-push #x4e data)
                                          ((ScriptErr e) (ScriptErr e))
                                          ((ScriptOk _)
                                           (execute-script-loop (context-push data next-ctx))))
                                        (execute-script-loop next-ctx)))))))))

                       ;; All other opcodes
                       (_
                        ;; Execute if: currently executing OR it's a control flow opcode
                        (if (or exec (is-control-flow-op op))
                            (match (execute-opcode op ctx-with-count)
                              ((ScriptErr e) (ScriptErr e))
                              ((ScriptOk next-ctx)
                               ;; Check combined stack + altstack size limit
                               (let ((total-stack-size (+ (stack-depth (context-main-stack next-ctx))
                                                          (stack-depth (context-alt-stack next-ctx)))))
                                 (if (> total-stack-size +max-stack-size+)
                                     (ScriptErr SE-StackOverflow)
                                     (execute-script-loop next-ctx)))))
                            ;; Not executing and not control flow - but check for always-illegal opcodes
                            (match (check-always-illegal-opcode op)
                              ((ScriptErr e) (ScriptErr e))
                              ((ScriptOk _) (execute-script-loop ctx-with-count))))))))))))))

  ;;; ============================================================
  ;;; Extended Execution Functions
  ;;; ============================================================

  (declare execute-script-with-stack ((Vector U8) -> ScriptStack -> (ScriptResult ScriptStack)))
  (define (execute-script-with-stack script initial-stack)
    "Execute a script with an initial stack (default tx context)."
    (execute-script-with-stack-tx script initial-stack 0 1 #xFFFFFFFF))

  (declare execute-script-with-stack-tx ((Vector U8) -> ScriptStack -> U32 -> I32 -> U32 -> (ScriptResult ScriptStack)))
  (define (execute-script-with-stack-tx script initial-stack locktime version sequence)
    "Execute a script with an initial stack and transaction context."
    (let ((len (the UFix (coalton-library/vector:length script))))
      (if (> len +max-script-size+)
          (ScriptErr SE-ScriptTooLarge)
          (execute-script-loop (make-script-context-with-stack-tx script initial-stack locktime version sequence)))))

  (declare make-script-context-with-stack-tx ((Vector U8) -> ScriptStack -> U32 -> I32 -> U32 -> ScriptContext))
  (define (make-script-context-with-stack-tx script initial-stack locktime version sequence)
    "Create a script context with a pre-populated stack and transaction context."
    (ScriptContext initial-stack (empty-stack) script 0 Nil True 0 0 locktime version sequence))

  ;;; P2SH Support

  (declare is-p2sh-script ((Vector U8) -> Boolean))
  (define (is-p2sh-script script)
    "Check if script matches P2SH pattern: OP_HASH160 <20 bytes> OP_EQUAL"
    (and (== (coalton-library/vector:length script) 23)
         (== (coalton-library/vector:index-unsafe 0 script) #xa9)   ; OP_HASH160
         (== (coalton-library/vector:index-unsafe 1 script) #x14)   ; Push 20 bytes
         (== (coalton-library/vector:index-unsafe 22 script) #x87))) ; OP_EQUAL

  (declare get-p2sh-hash ((Vector U8) -> (Vector U8)))
  (define (get-p2sh-hash script)
    "Extract the 20-byte hash from a P2SH scriptPubKey."
    (lisp (Vector U8) (script)
      (cl:subseq script 2 22)))

  (declare validate-p2sh (ScriptStack -> (Vector U8) -> (ScriptResult ScriptStack)))
  (define (validate-p2sh stack script-pubkey)
    "Validate P2SH: pop redeem script, check hash, execute redeem script."
    (validate-p2sh-with-tx stack script-pubkey 0 1 #xFFFFFFFF))

  (declare validate-p2sh-with-tx (ScriptStack -> (Vector U8) -> U32 -> I32 -> U32 -> (ScriptResult ScriptStack)))
  (define (validate-p2sh-with-tx stack script-pubkey locktime version sequence)
    "Validate P2SH with transaction context."
    (match (stack-pop stack)
      ((None) (ScriptErr SE-StackUnderflow))
      ((Some (Tuple redeem-script remaining-stack))
       ;; Hash the redeem script
       (let ((redeem-hash (compute-hash160 redeem-script)))
         ;; Compare with expected hash in scriptPubKey
         (let ((expected-hash (get-p2sh-hash script-pubkey)))
           (if (lisp Boolean (redeem-hash expected-hash)
                 (cl:equalp (hash160-bytes redeem-hash) expected-hash))
               ;; Hash matches - execute redeem script with remaining stack
               (execute-script-with-stack-tx redeem-script remaining-stack locktime version sequence)
               ;; Hash mismatch
               (ScriptErr SE-VerifyFailed)))))))

  ;;; ============================================================
  ;;; SegWit Support (BIP 141)
  ;;; ============================================================

  ;;; Witness Program Detection
  ;;;
  ;;; A witness program is identified by:
  ;;; 1. scriptPubKey length between 4 and 42 bytes
  ;;; 2. First byte is version: 0x00 for v0, 0x51-0x60 for v1-v16
  ;;; 3. Second byte is direct push of program (0x02-0x28)
  ;;; 4. Remaining bytes are the program itself
  ;;;
  ;;; For v0:
  ;;; - 20-byte program = P2WPKH (pay to witness public key hash)
  ;;; - 32-byte program = P2WSH (pay to witness script hash)

  (declare is-witness-program ((Vector U8) -> Boolean))
  (define (is-witness-program script)
    "Check if scriptPubKey is a witness program.
     A witness program has:
     - Length 4-42 bytes
     - First byte is version (0x00 for v0, 0x51-0x60 for v1-v16)
     - Second byte is push length matching remaining bytes"
    (let ((len (coalton-library/vector:length script)))
      (if (or (< len 4) (> len 42))
          False
          (let ((version-byte (coalton-library/vector:index-unsafe 0 script))
                (push-len-u8 (coalton-library/vector:index-unsafe 1 script)))
            (let ((push-len (the UFix (into push-len-u8))))
              ;; Version must be OP_0 (0x00) or OP_1-OP_16 (0x51-0x60)
              (if (not (or (== version-byte 0)
                           (and (>= version-byte #x51) (<= version-byte #x60))))
                  False
                  ;; Push length must be a direct push (2-40 bytes) matching remaining length
                  (and (>= push-len 2)
                       (<= push-len 40)
                       (== (+ push-len 2) len))))))))

  (declare get-witness-version ((Vector U8) -> (Optional U8)))
  (define (get-witness-version script)
    "Extract witness version from a witness program scriptPubKey.
     Returns None if not a witness program.
     Version 0 = 0x00, Version 1-16 = value - 0x50"
    (if (not (is-witness-program script))
        None
        (let ((version-byte (coalton-library/vector:index-unsafe 0 script)))
          (if (== version-byte 0)
              (Some 0)
              ;; OP_1 (0x51) = version 1, OP_16 (0x60) = version 16
              (Some (- version-byte #x50))))))

  (declare get-witness-program ((Vector U8) -> (Optional (Vector U8))))
  (define (get-witness-program script)
    "Extract the witness program bytes from a witness program scriptPubKey.
     Returns None if not a witness program."
    (if (not (is-witness-program script))
        None
        (let ((push-len (coalton-library/vector:index-unsafe 1 script)))
          (Some (lisp (Vector U8) (script push-len)
                  (cl:subseq script 2 (cl:+ 2 push-len)))))))

  (declare is-valid-v0-witness-program-length (UFix -> Boolean))
  (define (is-valid-v0-witness-program-length len)
    "Check if length is valid for witness v0 program (20 or 32 bytes)."
    (or (== len 20) (== len 32)))

  (declare is-p2wpkh-program ((Vector U8) -> Boolean))
  (define (is-p2wpkh-program script)
    "Check if scriptPubKey is a P2WPKH witness program (OP_0 <20-byte-hash>)."
    (and (is-witness-program script)
         (match (get-witness-version script)
           ((None) False)
           ((Some v) (== v 0)))
         (== (coalton-library/vector:length script) 22))) ; OP_0 + push(20) + 20 bytes

  (declare is-p2wsh-program ((Vector U8) -> Boolean))
  (define (is-p2wsh-program script)
    "Check if scriptPubKey is a P2WSH witness program (OP_0 <32-byte-hash>)."
    (and (is-witness-program script)
         (match (get-witness-version script)
           ((None) False)
           ((Some v) (== v 0)))
         (== (coalton-library/vector:length script) 34))) ; OP_0 + push(32) + 32 bytes

  ;;; ============================================================
  ;;; Taproot Support (BIP 341)
  ;;; ============================================================

  (declare is-taproot-program ((Vector U8) -> Boolean))
  (define (is-taproot-program script)
    "Check if scriptPubKey is a Taproot (SegWit v1) program.
     Taproot: OP_1 (0x51) <32-byte-key>"
    (and (is-witness-program script)
         (match (get-witness-version script)
           ((None) False)
           ((Some v) (== v 1)))
         (== (coalton-library/vector:length script) 34))) ; OP_1 + push(32) + 32 bytes

  (declare execute-scripts ((Vector U8) -> (Vector U8) -> Boolean -> (ScriptResult ScriptStack)))
  (define (execute-scripts script-sig script-pubkey p2sh-enabled)
    "Execute scriptSig then scriptPubKey, with optional P2SH support (default tx context)."
    (execute-scripts-with-tx script-sig script-pubkey p2sh-enabled 0 1 #xFFFFFFFF))

  (declare execute-scripts-with-tx ((Vector U8) -> (Vector U8) -> Boolean -> U32 -> I32 -> U32 -> (ScriptResult ScriptStack)))
  (define (execute-scripts-with-tx script-sig script-pubkey p2sh-enabled locktime version sequence)
    "Execute scriptSig then scriptPubKey, with optional P2SH support and transaction context."
    ;; First execute scriptSig
    (match (execute-script-with-tx script-sig locktime version sequence)
      ((ScriptErr e) (ScriptErr e))
      ((ScriptOk sig-stack)
       ;; Then execute scriptPubKey with the resulting stack
       (match (execute-script-with-stack-tx script-pubkey sig-stack locktime version sequence)
         ((ScriptErr e) (ScriptErr e))
         ((ScriptOk final-stack)
          ;; Check if we need to do P2SH
          (if (and p2sh-enabled (is-p2sh-script script-pubkey))
              ;; For P2SH, use the stack after scriptSig (before scriptPubKey consumed it)
              (validate-p2sh-with-tx sig-stack script-pubkey locktime version sequence)
              ;; Not P2SH - just return the result
              (ScriptOk final-stack)))))))

  ;;; ============================================================
  ;;; Helper functions for CL interop
  ;;; ============================================================

  (declare script-result-ok-p ((ScriptResult :a) -> Boolean))
  (define (script-result-ok-p result)
    "Return True if the result is ScriptOk."
    (match result
      ((ScriptOk _val) True)
      ((ScriptErr _e) False)))

  (declare script-result-err-p ((ScriptResult :a) -> Boolean))
  (define (script-result-err-p result)
    "Return True if the result is ScriptErr."
    (match result
      ((ScriptOk _val) False)
      ((ScriptErr _e) True)))

  (declare script-result-stack ((ScriptResult ScriptStack) -> (Optional ScriptStack)))
  (define (script-result-stack result)
    "Extract the stack from a successful result."
    (match result
      ((ScriptOk stack) (Some stack))
      ((ScriptErr _e) None)))

  (declare script-result-error ((ScriptResult :a) -> (Optional ScriptError)))
  (define (script-result-error result)
    "Extract the error from a failed result."
    (match result
      ((ScriptOk _val) None)
      ((ScriptErr e) (Some e))))

  ;; Direct accessors for CL interop (avoid Optional unwrapping in CL)
  (declare get-ok-stack ((ScriptResult ScriptStack) -> ScriptStack))
  (define (get-ok-stack result)
    "Get stack from ScriptOk, or empty-stack if error. For CL interop."
    (match result
      ((ScriptOk stack) stack)
      ((ScriptErr _e) (empty-stack))))

) ; end coalton-toplevel
