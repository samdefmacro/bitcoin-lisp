;;;; Common Lisp interop for Coalton Bitcoin types
;;;;
;;;; This module provides CL-side wrapper functions that make it easy
;;;; to use Coalton types (Satoshi, BlockHeight) from regular Common Lisp code.
;;;;
;;;; Coalton functions can be called directly as CL functions since
;;;; Coalton compiles to CL.

(defpackage #:bitcoin-lisp.coalton.interop
  (:documentation "CL wrapper functions for Coalton Bitcoin types.")
  (:use #:cl)
  (:export
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
   ;; Constants
   #:+max-money+
   #:+coin+
   #:+coinbase-maturity+
   ;; Script execution
   #:run-script
   #:run-scripts-with-p2sh
   #:is-p2sh-script-p
   #:stack-top-truthy-p
   ;; Script flags
   #:set-script-flags
   #:flag-enabled-p
   ;; Signature verification
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
   #:is-compressed-pubkey-p))

(in-package #:bitcoin-lisp.coalton.interop)

;;; Conversion utilities

(defun cl-array-to-coalton-vector (cl-array)
  "Convert a CL byte array to a Coalton vector."
  (map 'vector #'identity cl-array))

(defun coalton-vector-to-cl-array (vec)
  "Convert a Coalton vector to a CL byte array."
  (coerce vec '(simple-array (unsigned-byte 8) (*))))

;;; Bitcoin constants
(defconstant +coin+ 100000000
  "Number of satoshis per bitcoin.")

(defconstant +max-money+ (* 21000000 +coin+)
  "Maximum total supply in satoshis (21 million BTC).")

(defconstant +coinbase-maturity+ 100
  "Number of blocks before coinbase outputs can be spent.")

;;; Satoshi operations
;;; Coalton functions are directly callable from CL

(defun wrap-satoshi (value)
  "Convert an integer to a Satoshi type."
  (bitcoin-lisp.coalton.types:make-satoshi value))

(defun unwrap-satoshi (sat)
  "Extract the integer value from a Satoshi."
  (bitcoin-lisp.coalton.types:satoshi-value sat))

(defun satoshi+ (a b)
  "Add two Satoshi values."
  (bitcoin-lisp.coalton.types:satoshi-add a b))

(defun satoshi- (a b)
  "Subtract Satoshi values."
  (bitcoin-lisp.coalton.types:satoshi-sub a b))

(defun satoshi< (a b)
  "Compare Satoshi values."
  (< (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi<= (a b)
  "Compare Satoshi values."
  (<= (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi> (a b)
  "Compare Satoshi values."
  (> (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi>= (a b)
  "Compare Satoshi values."
  (>= (unwrap-satoshi a) (unwrap-satoshi b)))

(defun satoshi= (a b)
  "Check Satoshi equality."
  (= (unwrap-satoshi a) (unwrap-satoshi b)))

(defun zero-satoshi ()
  "Return zero satoshis."
  (wrap-satoshi 0))

;;; BlockHeight operations

(defun wrap-block-height (height)
  "Convert an integer to a BlockHeight type."
  (bitcoin-lisp.coalton.types:make-block-height height))

(defun unwrap-block-height (bh)
  "Extract the integer value from a BlockHeight."
  (bitcoin-lisp.coalton.types:block-height-value bh))

(defun block-height+ (bh n)
  "Add N to a BlockHeight."
  (wrap-block-height (+ (unwrap-block-height bh) n)))

(defun block-height< (a b)
  "Compare BlockHeight values."
  (< (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height<= (a b)
  "Compare BlockHeight values."
  (<= (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height> (a b)
  "Compare BlockHeight values."
  (> (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height>= (a b)
  "Compare BlockHeight values."
  (>= (unwrap-block-height a) (unwrap-block-height b)))

(defun block-height= (a b)
  "Check BlockHeight equality."
  (= (unwrap-block-height a) (unwrap-block-height b)))

(defun zero-block-height ()
  "Return block height zero (genesis)."
  (wrap-block-height 0))

(defun next-block-height (bh)
  "Return the next block height."
  (bitcoin-lisp.coalton.types:block-height-next bh))

;;; Script execution operations

(defun run-script (script-bytes)
  "Execute a script and return (values success stack-or-error).
   SCRIPT-BYTES should be a simple-array of (unsigned-byte 8)."
  (let* ((script-vec (cl-array-to-coalton-vector script-bytes))
         (result (bitcoin-lisp.coalton.script:execute-script script-vec)))
    (if (bitcoin-lisp.coalton.script:script-result-ok-p result)
        (values t (bitcoin-lisp.coalton.script:get-ok-stack result))
        (values nil :error))))

(defvar *original-script-pubkey* nil
  "The original scriptPubKey being executed. Used for sighash computation in P2SH.
   For P2SH, the credit transaction must use the P2SH scriptPubKey (OP_HASH160 <hash> OP_EQUAL),
   while the sighash scriptCode uses the redeemScript.")

(defun run-scripts-with-p2sh (script-sig script-pubkey p2sh-enabled)
  "Execute scriptSig then scriptPubKey with optional P2SH.
   Returns (values success stack-or-error)."
  (let* ((sig-vec (cl-array-to-coalton-vector script-sig))
         (pubkey-vec (cl-array-to-coalton-vector script-pubkey))
         ;; Store original scriptPubKey for sighash computation
         (*original-script-pubkey* script-pubkey)
         (result (bitcoin-lisp.coalton.script:execute-scripts
                  sig-vec
                  pubkey-vec
                  (if p2sh-enabled coalton:True coalton:False))))
    (if (bitcoin-lisp.coalton.script:script-result-ok-p result)
        (values t (bitcoin-lisp.coalton.script:get-ok-stack result))
        (values nil :error))))

(defun is-p2sh-script-p (script-bytes)
  "Check if script matches P2SH pattern."
  (let ((script-vec (cl-array-to-coalton-vector script-bytes)))
    (bitcoin-lisp.coalton.script:is-p2sh-script script-vec)))

(defun stack-top-truthy-p (stack)
  "Check if the stack is non-empty and the top element is truthy.
   Returns T if stack has at least one element and top is true.
   Returns NIL if stack is empty or top is false/zero/empty.
   Note: Coalton ScriptStack is (List (Vector U8)), which is just a CL list."
  ;; Stack is a CL list (Coalton List compiles to CL list)
  (when (consp stack)
    ;; Top element is first element (car), which is a Vector (CL array-like)
    (let ((top (car stack)))
      ;; Check if it's truthy: non-empty and not all zeros
      ;; cast-to-bool returns Coalton Boolean
      (eq (bitcoin-lisp.coalton.script:cast-to-bool top) coalton:True))))

;;; ============================================================
;;; Script Execution Flags
;;; ============================================================

(defvar *script-flags* nil
  "Current script execution flags. Set by test harness before execution.
   Supported flags: STRICTENC, P2SH, etc.")

(defun set-script-flags (flags-string)
  "Set script execution flags from a comma-separated string."
  (setf *script-flags* flags-string))

(defun flag-enabled-p (flag)
  "Check if a flag is enabled in *script-flags*."
  (and *script-flags*
       (or (string= *script-flags* flag)
           (search flag *script-flags*)
           (search (concatenate 'string "," flag) *script-flags*)
           (search (concatenate 'string flag ",") *script-flags*))))

;;; ============================================================
;;; SIGPUSHONLY Validation
;;; ============================================================

(defun script-is-push-only-p (script-bytes)
  "Check if a script contains only push operations (no other opcodes).
   Used for SIGPUSHONLY flag validation of scriptSig."
  (let ((len (length script-bytes))
        (pos 0))
    (loop while (< pos len)
          do (let ((op (aref script-bytes pos)))
               (cond
                 ;; OP_0 (0x00) - push empty
                 ((= op 0)
                  (incf pos))
                 ;; Direct push 1-75 bytes (0x01-0x4b)
                 ((<= op #x4b)
                  (incf pos (1+ op))  ; op + data
                  (when (> pos len)
                    (return-from script-is-push-only-p nil)))
                 ;; OP_PUSHDATA1 (0x4c)
                 ((= op #x4c)
                  (when (>= (1+ pos) len)
                    (return-from script-is-push-only-p nil))
                  (let ((data-len (aref script-bytes (1+ pos))))
                    (incf pos (+ 2 data-len))
                    (when (> pos len)
                      (return-from script-is-push-only-p nil))))
                 ;; OP_PUSHDATA2 (0x4d)
                 ((= op #x4d)
                  (when (>= (+ pos 2) len)
                    (return-from script-is-push-only-p nil))
                  (let ((data-len (+ (aref script-bytes (+ pos 1))
                                     (ash (aref script-bytes (+ pos 2)) 8))))
                    (incf pos (+ 3 data-len))
                    (when (> pos len)
                      (return-from script-is-push-only-p nil))))
                 ;; OP_PUSHDATA4 (0x4e)
                 ((= op #x4e)
                  (when (>= (+ pos 4) len)
                    (return-from script-is-push-only-p nil))
                  (let ((data-len (+ (aref script-bytes (+ pos 1))
                                     (ash (aref script-bytes (+ pos 2)) 8)
                                     (ash (aref script-bytes (+ pos 3)) 16)
                                     (ash (aref script-bytes (+ pos 4)) 24))))
                    (incf pos (+ 5 data-len))
                    (when (> pos len)
                      (return-from script-is-push-only-p nil))))
                 ;; OP_1NEGATE (0x4f) - push -1
                 ((= op #x4f)
                  (incf pos))
                 ;; OP_RESERVED (0x50) - NOT a push
                 ((= op #x50)
                  (return-from script-is-push-only-p nil))
                 ;; OP_1 through OP_16 (0x51-0x60)
                 ((and (>= op #x51) (<= op #x60))
                  (incf pos))
                 ;; Anything else is NOT a push operation
                 (t
                  (return-from script-is-push-only-p nil)))))
    t))

;;; ============================================================
;;; Signature Verification Support
;;; ============================================================

(defvar *signature-checker* nil
  "Function to verify signatures. Set by test harness.
   Should be (lambda (sig pubkey subscript) -> boolean).")

(defun set-signature-checker (fn)
  "Set the signature verification function."
  (setf *signature-checker* fn))

(defun verify-script-signature (sig pubkey subscript)
  "Verify a signature using the configured checker."
  (if *signature-checker*
      (funcall *signature-checker* sig pubkey subscript)
      nil))  ; Default to false if no checker

;;; Bitcoin Core Test Transaction Sighash
;;;
;;; Bitcoin Core's script_tests.cpp uses a standardized transaction:
;;; - Credit tx: creates output with scriptPubKey
;;; - Spend tx: spends that output with scriptSig
;;;
;;; The sighash is computed per BIP 143 for SegWit, or legacy for pre-SegWit.

(defun write-u32-le (value stream)
  "Write a 32-bit unsigned integer in little-endian."
  (write-byte (logand value #xff) stream)
  (write-byte (logand (ash value -8) #xff) stream)
  (write-byte (logand (ash value -16) #xff) stream)
  (write-byte (logand (ash value -24) #xff) stream))

(defun write-u64-le (value stream)
  "Write a 64-bit unsigned integer in little-endian."
  (write-u32-le (logand value #xffffffff) stream)
  (write-u32-le (ash value -32) stream))

(defun write-varint (value stream)
  "Write a Bitcoin varint."
  (cond
    ((< value #xfd)
     (write-byte value stream))
    ((< value #x10000)
     (write-byte #xfd stream)
     (write-byte (logand value #xff) stream)
     (write-byte (ash value -8) stream))
    ((< value #x100000000)
     (write-byte #xfe stream)
     (write-u32-le value stream))
    (t
     (write-byte #xff stream)
     (write-u64-le value stream))))

(defun compute-test-sighash (subscript sighash-type)
  "Compute the sighash for Bitcoin Core test transaction format.
   This matches the standardized transaction structure used in script_tests.cpp.
   SUBSCRIPT is the script to use as scriptCode in the sighash (redeemScript for P2SH).
   The credit transaction uses *original-script-pubkey* if set, for P2SH support."
  ;; For P2SH, credit tx must use original P2SH scriptPubKey, not the redeemScript
  (let ((credit-script (or *original-script-pubkey* subscript)))
    ;; Build the credit transaction hash first
    (let* ((credit-tx-data
             (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
               ;; Version
               (write-u32-le 1 s)
               ;; Input count
               (write-varint 1 s)
               ;; Input: prevout (null)
               (loop repeat 32 do (write-byte 0 s))  ; txid
               (write-u32-le #xffffffff s)          ; vout
               ;; Input: scriptSig (OP_0 OP_0)
               (write-varint 2 s)
               (write-byte 0 s)  ; OP_0
               (write-byte 0 s)  ; OP_0
               ;; Input: sequence
               (write-u32-le #xffffffff s)
               ;; Output count
               (write-varint 1 s)
               ;; Output: value (0)
               (write-u64-le 0 s)
               ;; Output: scriptPubKey (original, not redeemScript for P2SH)
               (write-varint (length credit-script) s)
               (loop for b across credit-script do (write-byte b s))
               ;; Locktime
               (write-u32-le 0 s)))
           (credit-txid (bitcoin-lisp.crypto:hash256 credit-tx-data)))

      ;; Now build the spending transaction for sighash
      (let ((preimage
              (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                ;; Version
                (write-u32-le 1 s)
                ;; Input count
                (write-varint 1 s)
                ;; Input: prevout
                (loop for b across credit-txid do (write-byte b s))
                (write-u32-le 0 s)  ; vout = 0
                ;; Input: scriptCode (subscript = redeemScript for P2SH, scriptPubKey otherwise)
                (write-varint (length subscript) s)
                (loop for b across subscript do (write-byte b s))
                ;; Input: sequence
                (write-u32-le #xffffffff s)
                ;; Output count
                (write-varint 1 s)
                ;; Output: value (0)
                (write-u64-le 0 s)
                ;; Output: scriptPubKey (empty)
                (write-varint 0 s)
                ;; Locktime
                (write-u32-le 0 s)
                ;; Sighash type (4 bytes LE)
                (write-u32-le (logand sighash-type #xff) s))))
        (bitcoin-lisp.crypto:hash256 preimage)))))

;;; ============================================================
;;; BIP 143 Sighash (SegWit)
;;; ============================================================
;;;
;;; BIP 143 defines a new transaction digest algorithm for SegWit that:
;;; - Commits to the input value (amount being spent)
;;; - Prevents quadratic hashing by pre-computing hash components
;;; - Uses different serialization order
;;;
;;; The preimage is:
;;;   version + hashPrevouts + hashSequence + outpoint + scriptCode +
;;;   value + sequence + hashOutputs + locktime + sighash_type

(defvar *witness-input-amount* 0
  "Amount (in satoshis) of the input being spent. Required for BIP 143 sighash.")

(defun compute-hash-prevouts ()
  "Compute hashPrevouts for BIP 143: double SHA256 of all input outpoints.
   For test transactions with single input spending the credit tx."
  ;; For Bitcoin Core test format: single input spending credit tx output 0
  ;; First we need to compute the credit txid
  (let* ((credit-script (or *original-script-pubkey*
                            (make-array 0 :element-type '(unsigned-byte 8))))
         (credit-tx-data
           (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
             (write-u32-le 1 s)               ; version
             (write-varint 1 s)               ; input count
             (loop repeat 32 do (write-byte 0 s))  ; null txid
             (write-u32-le #xffffffff s)      ; null vout
             (write-varint 2 s)               ; scriptSig length
             (write-byte 0 s) (write-byte 0 s) ; OP_0 OP_0
             (write-u32-le #xffffffff s)      ; sequence
             (write-varint 1 s)               ; output count
             (write-u64-le 0 s)               ; value
             (write-varint (length credit-script) s)
             (loop for b across credit-script do (write-byte b s))
             (write-u32-le 0 s)))             ; locktime
         (credit-txid (bitcoin-lisp.crypto:hash256 credit-tx-data)))
    ;; hashPrevouts = hash256(outpoint)
    (bitcoin-lisp.crypto:hash256
     (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
       (loop for b across credit-txid do (write-byte b s))
       (write-u32-le 0 s)))))  ; vout = 0

(defun compute-hash-sequence ()
  "Compute hashSequence for BIP 143: double SHA256 of all input sequences."
  ;; For test transactions: single input with sequence 0xffffffff
  (bitcoin-lisp.crypto:hash256
   (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
     (write-u32-le #xffffffff s))))

(defun compute-hash-outputs ()
  "Compute hashOutputs for BIP 143: double SHA256 of all outputs."
  ;; For test transactions: single output with value 0 and empty scriptPubKey
  (bitcoin-lisp.crypto:hash256
   (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
     (write-u64-le 0 s)       ; value = 0
     (write-varint 0 s))))    ; empty scriptPubKey

(defun make-p2pkh-script-code (keyhash)
  "Create the scriptCode for P2WPKH: OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY OP_CHECKSIG"
  (let ((result (make-array 25 :element-type '(unsigned-byte 8))))
    (setf (aref result 0) #x76)   ; OP_DUP
    (setf (aref result 1) #xa9)   ; OP_HASH160
    (setf (aref result 2) #x14)   ; Push 20 bytes
    (loop for i from 0 below 20
          do (setf (aref result (+ 3 i)) (aref keyhash i)))
    (setf (aref result 23) #x88)  ; OP_EQUALVERIFY
    (setf (aref result 24) #xac)  ; OP_CHECKSIG
    result))

(defun compute-bip143-sighash (script-code amount sighash-type)
  "Compute BIP 143 signature hash for SegWit transactions.
   SCRIPT-CODE is the script to use (P2PKH for P2WPKH, witness script for P2WSH).
   AMOUNT is the value in satoshis of the input being spent.
   SIGHASH-TYPE is the signature hash type."
  (let* ((base-type (logand sighash-type #x1f))
         (anyonecanpay (plusp (logand sighash-type #x80)))
         ;; Compute credit txid for outpoint
         (credit-script (or *original-script-pubkey*
                            (make-array 0 :element-type '(unsigned-byte 8))))
         (credit-tx-data
           (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
             (write-u32-le 1 s)
             (write-varint 1 s)
             (loop repeat 32 do (write-byte 0 s))
             (write-u32-le #xffffffff s)
             (write-varint 2 s)
             (write-byte 0 s) (write-byte 0 s)
             (write-u32-le #xffffffff s)
             (write-varint 1 s)
             (write-u64-le 0 s)
             (write-varint (length credit-script) s)
             (loop for b across credit-script do (write-byte b s))
             (write-u32-le 0 s)))
         (credit-txid (bitcoin-lisp.crypto:hash256 credit-tx-data))
         ;; Compute hash components based on sighash type
         (hash-prevouts (if anyonecanpay
                            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                            (compute-hash-prevouts)))
         (hash-sequence (if (or anyonecanpay
                                (= base-type 2)   ; SIGHASH_NONE
                                (= base-type 3))  ; SIGHASH_SINGLE
                            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                            (compute-hash-sequence)))
         (hash-outputs (cond
                         ((= base-type 2)  ; SIGHASH_NONE
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                         ((= base-type 3)  ; SIGHASH_SINGLE
                          ;; For input index 0, hash output 0
                          (compute-hash-outputs))
                         (t (compute-hash-outputs)))))
    ;; Build the preimage
    (let ((preimage
            (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
              ;; 1. nVersion (4 bytes)
              (write-u32-le 1 s)
              ;; 2. hashPrevouts (32 bytes)
              (loop for b across hash-prevouts do (write-byte b s))
              ;; 3. hashSequence (32 bytes)
              (loop for b across hash-sequence do (write-byte b s))
              ;; 4. outpoint (36 bytes): txid + vout
              (loop for b across credit-txid do (write-byte b s))
              (write-u32-le 0 s)
              ;; 5. scriptCode (varlen)
              (write-varint (length script-code) s)
              (loop for b across script-code do (write-byte b s))
              ;; 6. value (8 bytes)
              (write-u64-le amount s)
              ;; 7. nSequence (4 bytes)
              (write-u32-le #xffffffff s)
              ;; 8. hashOutputs (32 bytes)
              (loop for b across hash-outputs do (write-byte b s))
              ;; 9. nLockTime (4 bytes)
              (write-u32-le 0 s)
              ;; 10. sighash type (4 bytes)
              (write-u32-le sighash-type s))))
      (bitcoin-lisp.crypto:hash256 preimage))))

(defun valid-sighash-type-p (sighash-type)
  "Check if sighash type is valid.
   Valid types: SIGHASH_ALL (1), SIGHASH_NONE (2), SIGHASH_SINGLE (3),
   with optional SIGHASH_ANYONECANPAY (0x80) flag."
  (let ((base-type (logand sighash-type #x1f)))
    (and (member base-type '(1 2 3))
         (or (zerop (logand sighash-type #x60))  ; Only 0x80 flag allowed
             nil))))

(defun valid-pubkey-format-p (pubkey-bytes)
  "Check if pubkey has valid format (not hybrid).
   Compressed: 33 bytes, prefix 0x02 or 0x03
   Uncompressed: 65 bytes, prefix 0x04
   Hybrid (invalid): 65 bytes, prefix 0x06 or 0x07"
  (let ((len (length pubkey-bytes)))
    (cond
      ((zerop len) nil)
      ((= len 33)
       ;; Compressed: must start with 0x02 or 0x03
       (member (aref pubkey-bytes 0) '(#x02 #x03)))
      ((= len 65)
       ;; Uncompressed: must start with 0x04 (reject hybrid 0x06, 0x07)
       (= (aref pubkey-bytes 0) #x04))
      (t nil))))

(defun check-der-integer-encoding (bytes start)
  "Check if an integer at position START in BYTES is properly DER encoded.
   Returns (values valid new-pos) where new-pos is position after the integer."
  (let ((len (length bytes)))
    ;; Need at least tag + length + 1 byte of data
    (when (>= (+ start 2) len)
      (return-from check-der-integer-encoding (values nil 0)))
    ;; Must be INTEGER tag (0x02)
    (unless (= (aref bytes start) #x02)
      (return-from check-der-integer-encoding (values nil 0)))
    (let ((int-len (aref bytes (+ start 1))))
      ;; Length must be non-zero
      (when (zerop int-len)
        (return-from check-der-integer-encoding (values nil 0)))
      ;; Must have enough bytes
      (when (> (+ start 2 int-len) len)
        (return-from check-der-integer-encoding (values nil 0)))
      ;; DER encoding rules for R and S:
      ;; - First byte with high bit (0x80+) means negative in DER
      ;; - For positive integers, if first byte has high bit, must have 0x00 prefix
      ;; - No unnecessary padding (0x00 prefix only allowed if next byte has high bit)
      (let ((first-byte (aref bytes (+ start 2))))
        (cond
          ;; Single byte: reject if negative (high bit set)
          ((= int-len 1)
           (when (>= first-byte #x80)
             (return-from check-der-integer-encoding (values nil 0))))
          ;; Multi-byte: check padding rules
          (t
           (let ((second-byte (aref bytes (+ start 3))))
             ;; First byte 0x00: second must have high bit (otherwise unnecessary padding)
             (when (and (zerop first-byte) (< second-byte #x80))
               (return-from check-der-integer-encoding (values nil 0)))
             ;; First byte has high bit but isn't 0x00: this is negative!
             ;; (Valid positive numbers with high bit would have 0x00 prefix)
             (when (and (>= first-byte #x80) (/= first-byte #x00))
               (return-from check-der-integer-encoding (values nil 0)))))))
      (values t (+ start 2 int-len)))))

(defun check-der-signature-format (sig-bytes)
  "Check if signature bytes are valid strict DER format per BIP66.
   Returns T if valid, NIL if invalid."
  (let ((len (length sig-bytes)))
    ;; Minimum: 0x30 len 0x02 r-len r 0x02 s-len s (8 bytes with 1-byte R and S)
    (when (< len 8)
      (return-from check-der-signature-format nil))
    ;; Maximum: 73 bytes (0x30 + len + 0x02 + 33 + r + 0x02 + 33 + s)
    (when (> len 73)
      (return-from check-der-signature-format nil))
    ;; Must start with SEQUENCE tag (0x30)
    (unless (= (aref sig-bytes 0) #x30)
      (return-from check-der-signature-format nil))
    ;; Length byte must equal remaining length
    (let ((seq-len (aref sig-bytes 1)))
      (unless (= (+ 2 seq-len) len)
        (return-from check-der-signature-format nil))
      ;; Check R integer encoding
      (multiple-value-bind (r-valid r-end)
          (check-der-integer-encoding sig-bytes 2)
        (unless r-valid
          (return-from check-der-signature-format nil))
        ;; Check S integer encoding
        (multiple-value-bind (s-valid s-end)
            (check-der-integer-encoding sig-bytes r-end)
          (unless s-valid
            (return-from check-der-signature-format nil))
          ;; S must end exactly at the end of the signature
          (unless (= s-end len)
            (return-from check-der-signature-format nil))
          ;; All checks passed
          t)))))

(defun verify-checksig (sig-bytes pubkey-bytes script-pubkey)
  "Verify a CHECKSIG operation using Bitcoin Core test transaction format.
   When STRICTENC flag is set in *script-flags*, validates encoding.
   When DERSIG flag is set, uses strict DER signature parsing and returns
   error if parsing fails.
   When NULLFAIL flag is set, non-empty signatures that fail must return error.
   When LOW_S flag is set, rejects signatures with high-S values.
   Returns (values result error-type) where error-type is :sig-der, :sig-hashtype,
   :pubkeytype, :nullfail, :sig-high-s, or NIL."
  ;; Empty signature - no DER to check, no NULLFAIL violation
  (when (zerop (length sig-bytes))
    (return-from verify-checksig (values nil nil)))

  ;; Extract sighash type from signature (last byte)
  (let* ((sighash-type (aref sig-bytes (1- (length sig-bytes))))
         (der-sig (subseq sig-bytes 0 (1- (length sig-bytes))))
         ;; Both DERSIG and STRICTENC require DER signature validation
         (strict-der (or (flag-enabled-p "DERSIG")
                         (flag-enabled-p "STRICTENC"))))

    ;; DERSIG/STRICTENC: Check DER format BEFORE anything else
    ;; This ensures we error on bad DER even with empty pubkey
    (when strict-der
      (unless (check-der-signature-format der-sig)
        (return-from verify-checksig (values nil :sig-der))))

    ;; Empty pubkey - with STRICTENC, this is a format error
    (when (zerop (length pubkey-bytes))
      (if (flag-enabled-p "STRICTENC")
          (return-from verify-checksig (values nil :pubkeytype))
          (return-from verify-checksig (values nil nil))))

    ;; STRICTENC validation when flag is enabled
    (when (flag-enabled-p "STRICTENC")
      (unless (valid-sighash-type-p sighash-type)
        (return-from verify-checksig (values nil :sig-hashtype)))
      (unless (valid-pubkey-format-p pubkey-bytes)
        (return-from verify-checksig (values nil :pubkeytype))))

    ;; Compute sighash and verify
    ;; Use strict DER parsing when DERSIG flag is set
    ;; Reject high-S when LOW_S flag is set
    (let ((sighash (compute-test-sighash script-pubkey sighash-type))
          (require-low-s (flag-enabled-p "LOW_S")))
      (multiple-value-bind (result status)
          (bitcoin-lisp.crypto:verify-signature sighash der-sig pubkey-bytes
                                                :strict strict-der
                                                :low-s require-low-s)
        (cond
          ;; If LOW_S flag and signature had high-S, return :sig-high-s error
          ((eq status :high-s)
           (values nil :sig-high-s))
          ;; If DERSIG is set and DER parsing failed, return :sig-der error
          ((and strict-der (not status))
           (values nil :sig-der))
          ;; NULLFAIL: if sig is non-empty and verification failed, error
          ((and (not result)
                (flag-enabled-p "NULLFAIL"))
           (values nil :nullfail))
          ;; Normal result
          (t (values result nil)))))))

(defvar *last-checksig-error* nil
  "Set to error keyword (:sig-hashtype, :pubkeytype, :sig-der) if validation failed.")

(defun verify-checksig-for-script (sig-bytes pubkey-bytes script-pubkey)
  "Wrapper for verify-checksig that sets *last-checksig-error* on validation failures.
   Returns T for success, NIL for any failure.
   Check *last-checksig-error* for :sig-hashtype, :pubkeytype, or :sig-der errors."
  (setf *last-checksig-error* nil)
  (multiple-value-bind (result error-type)
      (verify-checksig sig-bytes pubkey-bytes script-pubkey)
    (when error-type
      (setf *last-checksig-error* error-type))
    result))

(defun last-checksig-had-strictenc-error-p ()
  "Returns T if the last checksig had a STRICTENC/DERSIG validation error."
  (not (null *last-checksig-error*)))

;;; ============================================================
;;; CHECKMULTISIG Support
;;; ============================================================

(defun verify-checkmultisig (sigs pubkeys script-pubkey)
  "Verify m-of-n multisig. SIGS and PUBKEYS are lists of byte arrays.
   Returns (values success error-type).
   Error-type is nil on success, or :sig-hashtype, :pubkeytype, :nulldummy, :nullfail on failure.

   Bitcoin's multisig algorithm:
   - For each signature (in order), find a matching pubkey
   - Pubkeys are consumed in order (can't go back)
   - Empty signatures never match and consume pubkeys until exhausted
   - With NULLFAIL: non-empty signatures that fail verification cause error
   - With STRICTENC: pubkey format is validated only when actually used"
  (let ((num-sigs (length sigs))
        (num-pubkeys (length pubkeys))
        (sig-index 0)
        (pubkey-index 0)
        (error-result nil))

    ;; Note: STRICTENC pubkey validation happens in verify-checksig,
    ;; only when a pubkey is actually checked against a signature.
    ;; This matches Bitcoin Core's behavior where unused pubkeys
    ;; don't need to be valid format.

    ;; Process signatures in order
    ;; Bitcoin algorithm: each sig tries pubkeys until one matches or we run out
    (loop while (and (< sig-index num-sigs)
                     (null error-result))
          do
             ;; Check if there are enough pubkeys remaining for remaining sigs
             (when (> (- num-sigs sig-index) (- num-pubkeys pubkey-index))
               ;; Not enough pubkeys left - break out to NULLFAIL check
               (return))

             (let ((sig (nth sig-index sigs)))
               (cond
                 ;; Empty signature - can never match, just consume pubkeys
                 ;; until we run out (checked at top of loop)
                 ((zerop (length sig))
                  ;; Empty sig doesn't advance, just consume a pubkey
                  (incf pubkey-index))

                 ;; Non-empty signature - try to verify with current pubkey
                 (t
                  (let ((pk (nth pubkey-index pubkeys)))
                    (multiple-value-bind (valid err-type)
                        (verify-checksig sig pk script-pubkey)
                      ;; STRICTENC/NULLFAIL error - record and exit loop
                      (when err-type
                        (setf error-result err-type)
                        (return))

                      (if valid
                          ;; Match! Advance both indices
                          (progn
                            (incf sig-index)
                            (incf pubkey-index))
                          ;; No match - try next pubkey (sig stays)
                          (incf pubkey-index))))))))

    ;; If we got an error during verification, return it
    (when error-result
      (return-from verify-checkmultisig (values nil error-result)))

    ;; Check result
    (let ((success (= sig-index num-sigs)))
      ;; NULLFAIL: if verification failed and any signature is non-empty, error
      (when (and (not success)
                 (flag-enabled-p "NULLFAIL"))
        (dolist (sig sigs)
          (when (plusp (length sig))
            (return-from verify-checkmultisig (values nil :nullfail)))))
      (values success nil))))

(defvar *last-checkmultisig-error* nil
  "Error from last CHECKMULTISIG: :sig-hashtype, :pubkeytype, :nulldummy, or nil.")

(defun verify-checkmultisig-for-script (sigs pubkeys script-pubkey dummy)
  "Wrapper for CHECKMULTISIG that validates dummy element and tracks errors.
   DUMMY is the dummy element that Bitcoin pops (should be empty with NULLDUMMY flag).
   Returns T for success, NIL for failure."
  (setf *last-checkmultisig-error* nil)

  ;; NULLDUMMY: dummy element must be empty
  (when (and (flag-enabled-p "NULLDUMMY")
             (plusp (length dummy)))
    (setf *last-checkmultisig-error* :nulldummy)
    (return-from verify-checkmultisig-for-script nil))

  (multiple-value-bind (result error-type)
      (verify-checkmultisig sigs pubkeys script-pubkey)
    (when error-type
      (setf *last-checkmultisig-error* error-type))
    result))

(defun last-checkmultisig-had-error-p ()
  "Returns T if the last CHECKMULTISIG had a validation error."
  (not (null *last-checkmultisig-error*)))

(defun script-number-to-int (bytes)
  "Convert script number bytes to integer. Empty = 0."
  (if (or (null bytes) (zerop (length bytes)))
      0
      (let ((result 0)
            (negative nil))
        ;; Check sign bit in last byte
        (when (plusp (logand (aref bytes (1- (length bytes))) #x80))
          (setf negative t)
          ;; Clear sign bit for magnitude calculation
          (setf bytes (copy-seq bytes))
          (setf (aref bytes (1- (length bytes)))
                (logand (aref bytes (1- (length bytes))) #x7f)))
        ;; Little-endian decode
        (loop for i from 0 below (length bytes)
              do (setf result (logior result (ash (aref bytes i) (* i 8)))))
        (if negative (- result) result))))

(defun script-number-to-int-validated (bytes)
  "Convert script number bytes to integer, validating MINIMALDATA if enabled.
   Returns (values integer success-p). Second value is NIL if MINIMALDATA validation fails."
  (when (and (flag-enabled-p "MINIMALDATA")
             (not (minimal-number-encoding-p bytes)))
    (return-from script-number-to-int-validated (values 0 nil)))
  (values (script-number-to-int bytes) t))

(defun coalton-vec-to-array (vec)
  "Convert a Coalton vector to a CL simple-array."
  (coerce vec '(simple-array (unsigned-byte 8) (*))))

(defun do-checkmultisig-stack-op (stack script-pubkey)
  "Perform the full CHECKMULTISIG stack operation.
   Returns (values status new-stack pubkey-count) where:
   - status is :ok (success), :fail (verification failed), or :error (script error)
   - new-stack is the stack after operation (with result pushed for :ok/:fail)
   - pubkey-count is the number of pubkeys (for op count calculation)"
  (setf *last-checkmultisig-error* nil)

  ;; Pop n (number of pubkeys)
  (when (null stack)
    (return-from do-checkmultisig-stack-op (values :underflow nil 0)))
  (let* ((n-bytes (coalton-vec-to-array (car stack)))
         (stack (cdr stack)))
    ;; MINIMALDATA: validate n encoding
    (multiple-value-bind (n valid)
        (script-number-to-int-validated n-bytes)
      (unless valid
        (setf *last-checkmultisig-error* :minimaldata)
        (return-from do-checkmultisig-stack-op (values :error nil 0)))

      ;; Validate n: must be 0-20
      (when (or (< n 0) (> n 20))
        (return-from do-checkmultisig-stack-op (values :pubkey-count nil 0)))

      ;; Pop n pubkeys
      (let ((pubkeys nil))
        (dotimes (i n)
          (when (null stack)
            (return-from do-checkmultisig-stack-op (values :underflow nil n)))
          (push (coalton-vec-to-array (car stack)) pubkeys)
          (setf stack (cdr stack)))
        (setf pubkeys (nreverse pubkeys))

        ;; Pop m (number of signatures)
        (when (null stack)
          (return-from do-checkmultisig-stack-op (values :underflow nil n)))
        (let* ((m-bytes (coalton-vec-to-array (car stack)))
               (stack (cdr stack)))
          ;; MINIMALDATA: validate m encoding
          (multiple-value-bind (m valid)
              (script-number-to-int-validated m-bytes)
            (unless valid
              (setf *last-checkmultisig-error* :minimaldata)
              (return-from do-checkmultisig-stack-op (values :error nil n)))

            ;; Validate m: must be 0-n
            (when (or (< m 0) (> m n))
              (return-from do-checkmultisig-stack-op (values :sig-count nil n)))

            ;; Pop m signatures
            (let ((sigs nil))
              (dotimes (i m)
                (when (null stack)
                  (return-from do-checkmultisig-stack-op (values :underflow nil n)))
                (push (coalton-vec-to-array (car stack)) sigs)
                (setf stack (cdr stack)))
              (setf sigs (nreverse sigs))

              ;; Pop dummy element (Bitcoin's off-by-one bug)
              (when (null stack)
                (return-from do-checkmultisig-stack-op (values :underflow nil n)))
              (let ((dummy (coalton-vec-to-array (car stack)))
                    (stack (cdr stack)))

                ;; Verify the multisig
                (let ((result (verify-checkmultisig-for-script sigs pubkeys script-pubkey dummy)))
                  ;; Check if there was a validation error (STRICTENC/NULLDUMMY)
                  (if *last-checkmultisig-error*
                      (values :error nil n)
                      ;; Push result: true (1) or false (empty)
                      ;; Convert to Coalton vector format for the stack
                      (let ((result-vec (if result
                                            (cl-array-to-coalton-vector
                                             (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))
                                            (cl-array-to-coalton-vector
                                             (make-array 0 :element-type '(unsigned-byte 8))))))
                        (values (if result :ok :fail)
                                (cons result-vec stack)
                                n))))))))))))

;;; ============================================================
;;; MINIMALDATA Validation
;;; ============================================================

(defun minimal-push-encoding-p (opcode data-len data)
  "Check if a push operation uses minimal encoding.
   OPCODE is the push opcode byte (0x01-0x4b for direct, 0x4c-0x4e for PUSHDATA).
   DATA-LEN is the length of data being pushed.
   DATA is the actual data bytes (for checking if content could use OP_0/OP_1-16/OP_1NEGATE).
   Returns T if encoding is minimal, NIL if not."
  (cond
    ;; Direct push (0x01-0x4b): check if data content could use a special opcode
    ((<= opcode #x4b)
     (cond
       ;; Empty data should use OP_0 (0x00), not 0x01 with 0 bytes
       ;; Actually, 0x01 with 0 bytes is invalid; but 0x01 0x00 (push 1 byte of 0x00) is not minimal
       ;; Empty should be OP_0, not a direct push
       ((zerop data-len) nil)  ; Empty should use OP_0

       ;; Single byte push - check if value could use OP_N or OP_1NEGATE
       ;; Note: OP_0 pushes empty array, not [0x00], so 0x00 is NOT caught here
       ((= data-len 1)
        (let ((byte (aref data 0)))
          (cond
            ;; 0x81 (-1) should use OP_1NEGATE
            ((= byte #x81) nil)
            ;; 0x01-0x10 should use OP_1 through OP_16
            ((and (>= byte 1) (<= byte 16)) nil)
            ;; Other single bytes (including 0x00) are fine
            (t t))))

       ;; Multi-byte push is always fine for direct push
       (t t)))

    ;; OP_PUSHDATA1 (0x4c): only valid for lengths > 75 (but <= 255)
    ((= opcode #x4c)
     (> data-len 75))

    ;; OP_PUSHDATA2 (0x4d): only valid for lengths > 255 (but <= 65535)
    ((= opcode #x4d)
     (> data-len 255))

    ;; OP_PUSHDATA4 (0x4e): only valid for lengths > 65535
    ((= opcode #x4e)
     (> data-len 65535))

    ;; Unknown opcode
    (t t)))

(defun minimal-number-encoding-p (bytes)
  "Check if script number bytes are minimally encoded.
   Returns T if encoding is minimal, NIL if not.
   Rules:
   - Empty encoding for zero is minimal
   - No unnecessary leading zero bytes
   - No negative zero (0x80 alone, or 0x0080, etc.)"
  (let ((len (length bytes)))
    (cond
      ;; Empty is always minimal (represents 0)
      ((zerop len) t)

      ;; Single byte: check for zero (0x00) and negative zero (0x80)
      ((= len 1)
       ;; Both 0x00 and 0x80 represent zero, which should be encoded as empty
       (and (/= (aref bytes 0) #x00)
            (/= (aref bytes 0) #x80)))

      ;; Multiple bytes: check for extra bytes
      (t
       (let ((last-byte (aref bytes (1- len)))
             (second-last-byte (aref bytes (- len 2))))
         (cond
           ;; If last byte is 0x00 and second-last doesn't have high bit set,
           ;; the 0x00 is unnecessary padding
           ((and (zerop last-byte)
                 (zerop (logand second-last-byte #x80)))
            nil)

           ;; If last byte is 0x80 (sign bit only) and second-last doesn't have high bit set,
           ;; this is negative zero or unnecessary sign extension
           ((and (= last-byte #x80)
                 (zerop (logand second-last-byte #x80)))
            nil)

           ;; Otherwise it's minimal
           (t t)))))))

;;; ============================================================
;;; SegWit Witness Validation
;;; ============================================================

(defun is-witness-program-p (script)
  "Check if SCRIPT is a witness program."
  (let ((vec (cl-array-to-coalton-vector script)))
    (eq (bitcoin-lisp.coalton.script:is-witness-program vec) coalton:True)))

(defun get-witness-version (script)
  "Get witness version from SCRIPT. Returns NIL if not a witness program."
  (let ((vec (cl-array-to-coalton-vector script)))
    ;; If not a witness program, return nil
    (unless (eq (bitcoin-lisp.coalton.script:is-witness-program vec) coalton:True)
      (return-from get-witness-version nil))
    ;; Extract version byte directly
    (let ((version-byte (aref script 0)))
      (if (zerop version-byte)
          0  ; Version 0
          (- version-byte #x50)))))  ; OP_1-OP_16 -> 1-16

(defun get-witness-program-bytes (script)
  "Get witness program bytes from SCRIPT. Returns NIL if not a witness program."
  (let ((vec (cl-array-to-coalton-vector script)))
    ;; If not a witness program, return nil
    (unless (eq (bitcoin-lisp.coalton.script:is-witness-program vec) coalton:True)
      (return-from get-witness-program-bytes nil))
    ;; Extract program bytes directly (skip version and push length)
    (let ((push-len (aref script 1)))
      (subseq script 2 (+ 2 push-len)))))

(defun is-compressed-pubkey-p (pubkey)
  "Check if PUBKEY is a compressed public key (33 bytes, starts with 0x02 or 0x03)."
  (and (= (length pubkey) 33)
       (member (aref pubkey 0) '(#x02 #x03))))

(defvar *witness-stack* nil
  "Current witness stack for SegWit validation. List of byte arrays.")

(defun verify-checksig-witness (sig-bytes pubkey-bytes script-code amount)
  "Verify a CHECKSIG operation for witness input using BIP 143 sighash.
   Returns (values result error-type)."
  ;; Empty signature
  (when (zerop (length sig-bytes))
    (return-from verify-checksig-witness (values nil nil)))

  (let* ((sighash-type (aref sig-bytes (1- (length sig-bytes))))
         (der-sig (subseq sig-bytes 0 (1- (length sig-bytes))))
         (strict-der (or (flag-enabled-p "DERSIG")
                         (flag-enabled-p "STRICTENC"))))

    ;; DER format check
    (when strict-der
      (unless (check-der-signature-format der-sig)
        (return-from verify-checksig-witness (values nil :sig-der))))

    ;; Empty pubkey check
    (when (zerop (length pubkey-bytes))
      (if (flag-enabled-p "STRICTENC")
          (return-from verify-checksig-witness (values nil :pubkeytype))
          (return-from verify-checksig-witness (values nil nil))))

    ;; WITNESS_PUBKEYTYPE: witness requires compressed pubkeys
    (when (flag-enabled-p "WITNESS_PUBKEYTYPE")
      (unless (is-compressed-pubkey-p pubkey-bytes)
        (return-from verify-checksig-witness (values nil :witness-pubkeytype))))

    ;; STRICTENC validation
    (when (flag-enabled-p "STRICTENC")
      (unless (valid-sighash-type-p sighash-type)
        (return-from verify-checksig-witness (values nil :sig-hashtype)))
      (unless (valid-pubkey-format-p pubkey-bytes)
        (return-from verify-checksig-witness (values nil :pubkeytype))))

    ;; Compute BIP 143 sighash
    (let ((sighash (compute-bip143-sighash script-code amount sighash-type))
          (require-low-s (flag-enabled-p "LOW_S")))
      (multiple-value-bind (result status)
          (bitcoin-lisp.crypto:verify-signature sighash der-sig pubkey-bytes
                                                :strict strict-der
                                                :low-s require-low-s)
        (cond
          ((eq status :high-s)
           (values nil :sig-high-s))
          ((and strict-der (not status))
           (values nil :sig-der))
          ((and (not result) (flag-enabled-p "NULLFAIL"))
           (values nil :nullfail))
          (t (values result nil)))))))

(defun validate-p2wpkh (witness program amount)
  "Validate P2WPKH spend.
   WITNESS is list of (signature pubkey).
   PROGRAM is the 20-byte keyhash.
   AMOUNT is the input value in satoshis.
   Returns (values success error-keyword)."
  ;; Witness must have exactly 2 elements
  (unless (= (length witness) 2)
    (return-from validate-p2wpkh (values nil :witness-program-witness-empty)))

  (let ((sig (first witness))
        (pubkey (second witness)))
    ;; WITNESS_PUBKEYTYPE: pubkey must be compressed
    (when (flag-enabled-p "WITNESS_PUBKEYTYPE")
      (unless (is-compressed-pubkey-p pubkey)
        (return-from validate-p2wpkh (values nil :witness-pubkeytype))))

    ;; Verify HASH160(pubkey) == program
    (let ((pubkey-hash (bitcoin-lisp.crypto:hash160 pubkey)))
      (unless (equalp pubkey-hash program)
        (return-from validate-p2wpkh (values nil :witness-program-mismatch))))

    ;; Build script code: OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY OP_CHECKSIG
    (let ((script-code (make-p2pkh-script-code program)))
      (verify-checksig-witness sig pubkey script-code amount))))

(defun validate-p2wsh (witness program amount)
  "Validate P2WSH spend.
   WITNESS is list of (args... witness-script).
   PROGRAM is the 32-byte script hash.
   AMOUNT is the input value in satoshis.
   Returns (values success error-keyword)."
  ;; Witness must have at least 1 element (the witness script)
  (when (zerop (length witness))
    (return-from validate-p2wsh (values nil :witness-program-witness-empty)))

  (let ((witness-script (car (last witness))))
    ;; Verify SHA256(witness-script) == program
    (let ((script-hash (bitcoin-lisp.crypto:sha256 witness-script)))
      (unless (equalp script-hash program)
        (return-from validate-p2wsh (values nil :witness-program-mismatch))))

    ;; Execute the witness script with remaining witness items as stack
    ;; For now, return success as placeholder - full script execution integration needed
    (values t nil)))

(defun validate-witness-program (script-pubkey witness amount &optional script-sig)
  "Validate a witness program.
   SCRIPT-PUBKEY is the witness program scriptPubKey.
   WITNESS is the witness stack (list of byte arrays).
   AMOUNT is the input value in satoshis.
   SCRIPT-SIG is the scriptSig (must be empty for native witness).
   Returns (values success error-keyword)."
  (let ((version (get-witness-version script-pubkey))
        (program (get-witness-program-bytes script-pubkey)))

    ;; Native witness: scriptSig must be empty
    (when (and script-sig (plusp (length script-sig)))
      (return-from validate-witness-program (values nil :witness-malleated)))

    ;; Empty witness is an error
    (when (or (null witness) (zerop (length witness)))
      (return-from validate-witness-program (values nil :witness-program-witness-empty)))

    (cond
      ;; Version 0
      ((= version 0)
       (let ((prog-len (length program)))
         (cond
           ;; P2WPKH: 20-byte program
           ((= prog-len 20)
            (validate-p2wpkh witness program amount))
           ;; P2WSH: 32-byte program
           ((= prog-len 32)
            (validate-p2wsh witness program amount))
           ;; Invalid length for v0
           (t
            (values nil :witness-program-wrong-length)))))

      ;; Unknown version
      (t
       (if (flag-enabled-p "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM")
           (values nil :discourage-upgradable-witness-program)
           ;; Anyone-can-spend for unknown versions
           (values t nil))))))
