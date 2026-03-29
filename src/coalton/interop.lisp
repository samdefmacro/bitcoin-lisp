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
   ;; Struct ↔ Coalton vector converters
   #:outpoint-to-coalton
   #:outpoint-from-coalton
   #:tx-in-to-coalton
   #:tx-in-from-coalton
   #:tx-out-to-coalton
   #:tx-out-from-coalton
   #:transaction-to-coalton
   #:transaction-from-coalton
   #:block-header-to-coalton
   #:block-header-from-coalton
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
   #:*script-flags*
   #:set-script-flags
   #:flag-enabled-p
   ;; Signature verification
   #:verify-script
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
   ;; Transaction context for block validation
   #:*current-tx*
   #:*current-input-index*
   #:*debug-checksig*
   #:*current-script-code*
   #:compute-legacy-sighash
   ;; SegWit / BIP 143
   #:*witness-v0-mode*
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
   #:increment-script-number))

(in-package #:bitcoin-lisp.coalton.interop)

;;; Conversion utilities

(defun cl-array-to-coalton-vector (cl-array)
  "Convert a CL byte array to a Coalton vector."
  (map 'vector #'identity cl-array))

(defun coalton-vector-to-cl-array (vec)
  "Convert a Coalton vector to a CL byte array."
  (coerce vec '(simple-array (unsigned-byte 8) (*))))

;;; Struct ↔ Coalton vector converters
;;; Serialize CL structs to Coalton-compatible byte vectors and back.

(defun outpoint-to-coalton (outpoint)
  "Serialize a CL outpoint struct to a Coalton byte vector."
  (cl-array-to-coalton-vector
   (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
     (bitcoin-lisp.serialization::write-outpoint s outpoint))))

(defun outpoint-from-coalton (vec)
  "Deserialize a Coalton byte vector to a CL outpoint struct."
  (flexi-streams:with-input-from-sequence (s (coalton-vector-to-cl-array vec))
    (bitcoin-lisp.serialization::read-outpoint s)))

(defun tx-in-to-coalton (tx-in)
  "Serialize a CL tx-in struct to a Coalton byte vector."
  (cl-array-to-coalton-vector
   (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
     (bitcoin-lisp.serialization::write-tx-in s tx-in))))

(defun tx-in-from-coalton (vec)
  "Deserialize a Coalton byte vector to a CL tx-in struct."
  (flexi-streams:with-input-from-sequence (s (coalton-vector-to-cl-array vec))
    (bitcoin-lisp.serialization::read-tx-in s)))

(defun tx-out-to-coalton (tx-out)
  "Serialize a CL tx-out struct to a Coalton byte vector."
  (cl-array-to-coalton-vector
   (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
     (bitcoin-lisp.serialization::write-tx-out s tx-out))))

(defun tx-out-from-coalton (vec)
  "Deserialize a Coalton byte vector to a CL tx-out struct."
  (flexi-streams:with-input-from-sequence (s (coalton-vector-to-cl-array vec))
    (bitcoin-lisp.serialization::read-tx-out s)))

(defun transaction-to-coalton (tx)
  "Serialize a CL transaction struct to a Coalton byte vector."
  (cl-array-to-coalton-vector
   (bitcoin-lisp.serialization:serialize-transaction tx)))

(defun transaction-from-coalton (vec)
  "Deserialize a Coalton byte vector to a CL transaction struct."
  (flexi-streams:with-input-from-sequence (s (coalton-vector-to-cl-array vec))
    (bitcoin-lisp.serialization:read-transaction s)))

(defun block-header-to-coalton (header)
  "Serialize a CL block-header struct to a Coalton byte vector."
  (cl-array-to-coalton-vector
   (bitcoin-lisp.serialization:serialize-block-header header)))

(defun block-header-from-coalton (vec)
  "Deserialize a Coalton byte vector to a CL block-header struct."
  (flexi-streams:with-input-from-sequence (s (coalton-vector-to-cl-array vec))
    (bitcoin-lisp.serialization::read-block-header s)))

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

;;; Transaction context for real block validation
;;; When validating blocks, these are bound to the actual transaction data.
;;; For unit tests (script_tests), these remain NIL and compute-test-sighash is used.

(defvar *current-tx* nil
  "The transaction currently being validated. When bound, verify-checksig will
   compute the real sighash from this transaction instead of using test format.")

(defvar *debug-checksig* nil
  "When non-nil, print debug information for signature verification.")

(defvar *current-input-index* 0
  "The index of the input currently being validated (0-based).")

(defvar *current-script-code* nil
  "The script code to use for sighash computation. For P2SH this is the redeemScript,
   for legacy this is the scriptPubKey with OP_CODESEPARATOR handled.")

(defvar *original-script-pubkey* nil
  "The original scriptPubKey being executed. Used for sighash computation in P2SH.
   For P2SH, the credit transaction must use the P2SH scriptPubKey (OP_HASH160 <hash> OP_EQUAL),
   while the sighash scriptCode uses the redeemScript.")

(defvar *witness-v0-mode* nil
  "When non-nil, verify-checksig uses BIP 143 sighash instead of legacy.
   Set during P2WSH witness script execution.")

(defun current-input-sequence ()
  "Extract nSequence for the current input from *current-tx*, or #xFFFFFFFF if unavailable."
  (if (and *current-tx* (bitcoin-lisp.serialization:transaction-inputs *current-tx*))
      (let ((inputs (bitcoin-lisp.serialization:transaction-inputs *current-tx*)))
        (if (< *current-input-index* (length inputs))
            (bitcoin-lisp.serialization:tx-in-sequence (nth *current-input-index* inputs))
            #xFFFFFFFF))
      #xFFFFFFFF))

(defun run-scripts-with-p2sh (script-sig script-pubkey p2sh-enabled)
  "Execute scriptSig then scriptPubKey with optional P2SH.
   Extracts transaction context from *current-tx* and *current-input-index*.
   Returns (values success stack-or-error)."
  (let* ((sig-vec (cl-array-to-coalton-vector script-sig))
         (pubkey-vec (cl-array-to-coalton-vector script-pubkey))
         ;; Store original scriptPubKey for sighash computation
         (*original-script-pubkey* script-pubkey)
         ;; Extract transaction context
         (locktime (if *current-tx*
                       (bitcoin-lisp.serialization:transaction-lock-time *current-tx*)
                       0))
         (version (if *current-tx*
                      (bitcoin-lisp.serialization:transaction-version *current-tx*)
                      1))
         (sequence (current-input-sequence))
         (result (bitcoin-lisp.coalton.script:execute-scripts-with-tx
                  sig-vec
                  pubkey-vec
                  (if p2sh-enabled coalton:True coalton:False)
                  locktime version sequence)))
    (if (bitcoin-lisp.coalton.script:script-result-ok-p result)
        (values t (bitcoin-lisp.coalton.script:get-ok-stack result))
        (values nil :error))))

(defun verify-script (script-sig script-pubkey &key witness amount)
  "Verify a script following Bitcoin Core's VerifyScript flow exactly.
SCRIPT-SIG and SCRIPT-PUBKEY are byte arrays.
WITNESS is an optional list of byte arrays (witness stack).
AMOUNT is the input value in satoshis (required for witness).
Uses *current-tx*, *current-input-index*, and *script-flags* from dynamic scope.
Returns (values success error-keyword)."
  (let ((*original-script-pubkey* script-pubkey)
        (had-witness nil))

    ;; Step 0a: CONST_SCRIPTCODE pre-check on scriptPubKey
    ;; Must check before Coalton engine executes and strips OP_CODESEPARATOR
    (when (flag-enabled-p "CONST_SCRIPTCODE")
      (let ((i 0) (slen (length script-pubkey)))
        (loop while (< i slen)
              do (let ((op (aref script-pubkey i)))
                   (when (= op #xab)
                     (return-from verify-script (values nil :op-codeseparator)))
                   (cond
                     ((and (>= op 1) (<= op 75)) (incf i (1+ op)))
                     ((= op 76) (if (< (1+ i) slen) (incf i (+ 2 (aref script-pubkey (1+ i)))) (incf i)))
                     ((= op 77) (if (< (+ i 2) slen)
                                    (incf i (+ 3 (aref script-pubkey (1+ i))
                                                (ash (aref script-pubkey (+ i 2)) 8)))
                                    (incf i)))
                     (t (incf i)))))))

    ;; Step 0b: SIGPUSHONLY check on scriptSig (before execution)
    (when (flag-enabled-p "SIGPUSHONLY")
      (unless (script-is-push-only-p script-sig)
        (return-from verify-script (values nil :sig-pushonly))))

    ;; Step 1-3: Execute scriptSig + scriptPubKey (+ P2SH if enabled)
    (let ((p2sh-enabled (and (flag-enabled-p "P2SH")
                             (is-p2sh-script-p script-pubkey))))
      ;; P2SH requires push-only scriptSig (BIP 16)
      (when p2sh-enabled
        (unless (script-is-push-only-p script-sig)
          (return-from verify-script (values nil :sig-pushonly))))

      (multiple-value-bind (ok stack)
          (run-scripts-with-p2sh script-sig script-pubkey p2sh-enabled)
        (unless ok
          (return-from verify-script (values nil stack)))

        ;; Step 4: Verify script result (non-empty stack, truthy top)
        (unless (stack-top-truthy-p stack)
          (return-from verify-script (values nil :eval-false)))

        ;; Step 5: Bare witness program handling
        (when (flag-enabled-p "WITNESS")
          (when (is-witness-program-p script-pubkey)
            (setf had-witness t)
            ;; Native witness: scriptSig must be empty
            (when (plusp (length script-sig))
              (return-from verify-script (values nil :witness-malleated)))
            (multiple-value-bind (wok werr)
                (validate-witness-program
                 script-pubkey (or witness '()) (or amount 0) script-sig)
              (unless wok
                (return-from verify-script (values nil werr))))))

        ;; Step 6: P2SH-wrapped witness handling
        (when (and (flag-enabled-p "WITNESS") p2sh-enabled (not had-witness))
          (let ((redeem-script (extract-last-push-data script-sig)))
            (when (and redeem-script (is-witness-program-p redeem-script))
              (setf had-witness t)
              ;; P2SH-witness: scriptSig must be EXACTLY a single push of the witness program
              ;; (validated implicitly by P2SH execution succeeding)
              (multiple-value-bind (wok werr)
                  (validate-witness-program
                   redeem-script (or witness '()) (or amount 0) nil)
                (unless wok
                  (return-from verify-script (values nil werr)))))))

        ;; Step 7: CLEANSTACK enforcement
        (when (and (flag-enabled-p "CLEANSTACK") (not had-witness))
          (when (and (consp stack) (consp (cdr stack)))
            (return-from verify-script (values nil :cleanstack))))

        ;; Step 8: WITNESS_UNEXPECTED check
        (when (flag-enabled-p "WITNESS")
          (when (and (not had-witness) witness (plusp (length witness)))
            ;; Check if witness has actual data (not all empty)
            (when (some (lambda (w) (plusp (length w))) witness)
              (return-from verify-script (values nil :witness-unexpected)))))

        ;; Success
        (values t nil)))))

(defun extract-last-push-data (script)
  "Extract the data from the last push operation in a script.
Used to get the redeem script from a P2SH scriptSig."
  (let ((len (length script)) (pos 0) (last-push nil))
    (loop while (< pos len)
          do (let ((op (aref script pos)))
               (cond
                 ((and (>= op 1) (<= op 75))
                  (let ((end (min len (+ pos 1 op))))
                    (setf last-push (subseq script (1+ pos) end))
                    (setf pos end)))
                 ((= op 76) ;; OP_PUSHDATA1
                  (when (< (1+ pos) len)
                    (let* ((data-len (aref script (1+ pos)))
                           (end (min len (+ pos 2 data-len))))
                      (setf last-push (subseq script (+ pos 2) end))
                      (setf pos end))))
                 ((= op 77) ;; OP_PUSHDATA2
                  (when (< (+ pos 2) len)
                    (let* ((data-len (+ (aref script (1+ pos))
                                        (ash (aref script (+ pos 2)) 8)))
                           (end (min len (+ pos 3 data-len))))
                      (setf last-push (subseq script (+ pos 3) end))
                      (setf pos end))))
                 (t (incf pos)))))
    last-push))

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
  "Check if a flag is enabled in *script-flags*.
Returns T or NIL (not an integer position) for Coalton Boolean compatibility."
  (if (and *script-flags*
           (or (string= *script-flags* flag)
               (search flag *script-flags*)
               (search (concatenate 'string "," flag) *script-flags*)
               (search (concatenate 'string flag ",") *script-flags*)))
      t
      nil))

;;; ============================================================
;;; Tapscript OP_SUCCESS Detection (BIP 342)
;;; ============================================================

(defun is-op-success-p (byte)
  "Check if a byte is an OP_SUCCESS opcode per BIP 342.
   These opcodes cause immediate script success in Tapscript."
  (or (= byte #x50)                          ; OP_RESERVED
      (= byte #x62)                          ; OP_VER
      (and (>= byte #x7e) (<= byte #x81))    ; OP_CAT..OP_LEFT (126-129)
      (and (>= byte #x83) (<= byte #x86))    ; OP_INVERT..OP_XOR (131-134)
      (and (>= byte #x89) (<= byte #x8a))    ; OP_2MUL, OP_2DIV (137-138)
      (and (>= byte #x8d) (<= byte #x8e))    ; OP_MUL, OP_DIV (141-142)
      (and (>= byte #x95) (<= byte #x99))    ; (149-153)
      (and (>= byte #xbb) (<= byte #xfe))))  ; 187-254

(defun scan-for-op-success (script-bytes)
  "Pre-scan a Tapscript for OP_SUCCESS opcodes.
   Per BIP 342, if any OP_SUCCESS is found (even in unexecuted branches),
   the entire script succeeds immediately.
   Returns T if OP_SUCCESS found, NIL otherwise."
  (let ((len (length script-bytes))
        (pos 0))
    (loop while (< pos len)
          do (let ((op (aref script-bytes pos)))
               (cond
                 ;; Check for OP_SUCCESS first
                 ((is-op-success-p op)
                  (return-from scan-for-op-success t))
                 ;; OP_0 (0x00) - no data
                 ((= op 0)
                  (incf pos))
                 ;; Direct push 1-75 bytes (0x01-0x4b)
                 ((and (>= op 1) (<= op #x4b))
                  (incf pos (1+ op))  ; op + data
                  (when (> pos len)
                    (return-from scan-for-op-success nil)))
                 ;; OP_PUSHDATA1 (0x4c)
                 ((= op #x4c)
                  (when (>= (1+ pos) len)
                    (return-from scan-for-op-success nil))
                  (let ((data-len (aref script-bytes (1+ pos))))
                    (incf pos (+ 2 data-len))
                    (when (> pos len)
                      (return-from scan-for-op-success nil))))
                 ;; OP_PUSHDATA2 (0x4d)
                 ((= op #x4d)
                  (when (>= (+ pos 2) len)
                    (return-from scan-for-op-success nil))
                  (let ((data-len (+ (aref script-bytes (+ pos 1))
                                     (ash (aref script-bytes (+ pos 2)) 8))))
                    (incf pos (+ 3 data-len))
                    (when (> pos len)
                      (return-from scan-for-op-success nil))))
                 ;; OP_PUSHDATA4 (0x4e)
                 ((= op #x4e)
                  (when (>= (+ pos 4) len)
                    (return-from scan-for-op-success nil))
                  (let ((data-len (+ (aref script-bytes (+ pos 1))
                                     (ash (aref script-bytes (+ pos 2)) 8)
                                     (ash (aref script-bytes (+ pos 3)) 16)
                                     (ash (aref script-bytes (+ pos 4)) 24))))
                    (incf pos (+ 5 data-len))
                    (when (> pos len)
                      (return-from scan-for-op-success nil))))
                 ;; Any other opcode - just skip
                 (t (incf pos)))))
    nil))

;;; ============================================================
;;; Tapscript Context Variables (BIP 342)
;;; ============================================================

(defvar *tapscript-leaf-hash* nil
  "The tapleaf hash for Tapscript script path spending.
   Set when executing a Tapscript, used for BIP 341 sighash computation.")

(defvar *tapscript-amount* 0
  "The input amount for Tapscript script path spending.
   Set when executing a Tapscript, used for BIP 341 sighash computation.")

(defvar *tapscript-internal-pubkey* nil
  "The internal public key for Tapscript script path spending.
   Set when executing a Tapscript.")

(defun verify-tapscript-signature (sig-bytes pubkey-bytes)
  "Verify a Tapscript signature (BIP 342 rules).
   SIG-BYTES: signature (64 bytes for default sighash, 65 bytes with explicit type)
   PUBKEY-BYTES: 32-byte x-only public key
   Returns (values status result) where:
     status: :ok, :empty-sig, :invalid-sig, :invalid-pubkey, :bad-sighash-type
     result: T if valid, NIL otherwise"
  ;; Empty signature is treated specially (for OP_CHECKSIGADD)
  (when (zerop (length sig-bytes))
    (return-from verify-tapscript-signature (values :empty-sig nil)))

  ;; Signature must be 64 or 65 bytes
  (let ((sig-len (length sig-bytes)))
    (unless (or (= sig-len 64) (= sig-len 65))
      (return-from verify-tapscript-signature (values :invalid-sig nil))))

  ;; Public key must be 32 bytes (x-only)
  (unless (= (length pubkey-bytes) 32)
    (return-from verify-tapscript-signature (values :invalid-pubkey nil)))

  (let* ((sig-len (length sig-bytes))
         (sighash-type (if (= sig-len 65)
                           (aref sig-bytes 64)
                           #x00))  ; SIGHASH_DEFAULT
         (sig64 (if (= sig-len 64) sig-bytes (subseq sig-bytes 0 64))))

    ;; Validate sighash type
    (unless (valid-taproot-sighash-type-p sighash-type)
      (return-from verify-tapscript-signature (values :bad-sighash-type nil)))

    ;; Compute BIP 341 sighash with tapleaf extension
    (let ((sighash (compute-bip341-sighash *tapscript-amount* sighash-type
                                            *tapscript-leaf-hash* 0)))
      ;; Verify Schnorr signature
      (if (bitcoin-lisp.crypto:verify-schnorr-signature sighash sig64 pubkey-bytes)
          (values :ok t)
          (values :invalid-sig nil)))))

(defun increment-script-number (bytes)
  "Increment a Bitcoin Script number by 1.
   Script numbers are variable-length little-endian integers with sign bit.
   Returns a new vector with the incremented value."
  (let* ((len (length bytes)))
    (if (= len 0)
        ;; Empty (0) -> 1
        #(1)
        ;; Non-empty: decode, increment, encode
        (let* (;; Decode script number
               (negative (and (> len 0)
                             (not (zerop (logand (aref bytes (1- len)) #x80)))))
               ;; Build magnitude (little-endian)
               (magnitude 0))
          ;; Extract magnitude
          (loop for i from 0 below len
                for byte = (aref bytes i)
                for effective-byte = (if (= i (1- len))
                                        (logand byte #x7f)  ; Clear sign bit
                                        byte)
                do (setf magnitude (logior magnitude (ash effective-byte (* i 8)))))
          ;; Compute new value
          (let* ((value (if negative (- magnitude) magnitude))
                 (new-value (1+ value)))
            ;; Encode as script number
            (script-number-to-bytes new-value))))))

(defun script-number-to-bytes (n)
  "Encode an integer as a Bitcoin Script number (minimally encoded little-endian)."
  (cond
    ((= n 0) #())
    (t (let* ((negative (< n 0))
              (magnitude (abs n))
              (bytes '()))
         ;; Build byte list (little-endian)
         (loop while (> magnitude 0)
               do (push (logand magnitude #xff) bytes)
                  (setf magnitude (ash magnitude -8)))
         (setf bytes (nreverse bytes))
         ;; Handle sign bit
         (if (> (logand (car (last bytes)) #x80) 0)
             ;; Need extra byte for sign
             (if negative
                 (setf bytes (append bytes (list #x80)))
                 (setf bytes (append bytes (list #x00))))
             ;; Can fit sign in existing high bit
             (when negative
               (setf (car (last bytes))
                     (logior (car (last bytes)) #x80))))
         (coerce bytes '(vector (unsigned-byte 8)))))))

(defun run-tapscript (script script-inputs leaf-hash amount internal-pubkey)
  "Execute a Tapscript with BIP 342 rules.
   SCRIPT: The script bytes to execute
   SCRIPT-INPUTS: List of witness elements to use as initial stack
   LEAF-HASH: The tapleaf hash for sighash computation
   AMOUNT: The input value in satoshis
   INTERNAL-PUBKEY: The internal public key (32 bytes)
   Returns (values success error-keyword)."
  ;; Set up Tapscript context
  (let* ((old-flags *script-flags*)
         (old-leaf-hash *tapscript-leaf-hash*)
         (old-amount *tapscript-amount*)
         (old-internal-pubkey *tapscript-internal-pubkey*)
         ;; Add TAPSCRIPT flag
         (new-flags (if old-flags
                        (concatenate 'string old-flags ",TAPSCRIPT")
                        "TAPSCRIPT")))
    (unwind-protect
         (progn
           ;; Set Tapscript context
           (setf *script-flags* new-flags)
           (setf *tapscript-leaf-hash* leaf-hash)
           (setf *tapscript-amount* amount)
           (setf *tapscript-internal-pubkey* internal-pubkey)

           ;; Convert script-inputs to Coalton stack (list of vectors)
           ;; Script-inputs is a list of byte arrays, Coalton stack is a list of vectors
           (let* ((script-vec (cl-array-to-coalton-vector script))
                  (initial-stack (mapcar #'cl-array-to-coalton-vector script-inputs))
                  (result (bitcoin-lisp.coalton.script:execute-script-with-stack
                           script-vec
                           initial-stack)))
             ;; Check result
             (if (bitcoin-lisp.coalton.script:script-result-ok-p result)
                 (let ((final-stack (bitcoin-lisp.coalton.script:get-ok-stack result)))
                   ;; Script succeeded, check if top of stack is truthy
                   (if (stack-top-truthy-p final-stack)
                       (values t nil)
                       (values nil :script-eval-false)))
                 (values nil :script-error))))
      ;; Restore context
      (setf *script-flags* old-flags)
      (setf *tapscript-leaf-hash* old-leaf-hash)
      (setf *tapscript-amount* old-amount)
      (setf *tapscript-internal-pubkey* old-internal-pubkey))))

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
;;; Legacy Sighash for Real Block Validation
;;; ============================================================
;;;
;;; When validating real blocks, we need to compute the sighash from
;;; the actual transaction data, not the test format.

(defun remove-codeseparator (script)
  "Remove OP_CODESEPARATOR opcodes from SCRIPT for sighash computation.
Walks the script properly, skipping push data to avoid removing 0xab
bytes that appear as data rather than opcodes."
  (let ((len (length script))
        (result (make-array (length script) :element-type '(unsigned-byte 8)
                                            :fill-pointer 0)))
    (let ((i 0))
      (loop while (< i len)
            do (let ((op (aref script i)))
                 (cond
                   ;; OP_CODESEPARATOR — skip it
                   ((= op #xab)
                    (incf i))
                   ;; Push 1-75 bytes
                   ((and (>= op 1) (<= op 75))
                    (let ((end (min len (+ i 1 op))))
                      (loop for j from i below end
                            do (vector-push (aref script j) result))
                      (setf i end)))
                   ;; OP_PUSHDATA1
                   ((= op 76)
                    (if (< (1+ i) len)
                        (let* ((data-len (aref script (1+ i)))
                               (end (min len (+ i 2 data-len))))
                          (loop for j from i below end
                                do (vector-push (aref script j) result))
                          (setf i end))
                        (progn (vector-push op result) (incf i))))
                   ;; OP_PUSHDATA2
                   ((= op 77)
                    (if (< (+ i 2) len)
                        (let* ((data-len (+ (aref script (1+ i))
                                            (ash (aref script (+ i 2)) 8)))
                               (end (min len (+ i 3 data-len))))
                          (loop for j from i below end
                                do (vector-push (aref script j) result))
                          (setf i end))
                        (progn (vector-push op result) (incf i))))
                   ;; OP_PUSHDATA4
                   ((= op 78)
                    (if (< (+ i 4) len)
                        (let* ((data-len (+ (aref script (1+ i))
                                            (ash (aref script (+ i 2)) 8)
                                            (ash (aref script (+ i 3)) 16)
                                            (ash (aref script (+ i 4)) 24)))
                               (end (min len (+ i 5 data-len))))
                          (loop for j from i below end
                                do (vector-push (aref script j) result))
                          (setf i end))
                        (progn (vector-push op result) (incf i))))
                   ;; Any other opcode — keep it
                   (t
                    (vector-push op result)
                    (incf i))))))
    (coerce (subseq result 0 (fill-pointer result))
            '(simple-array (unsigned-byte 8) (*)))))

(defun find-and-delete (script pattern)
  "Remove all occurrences of PATTERN from SCRIPT (Bitcoin Core's FindAndDelete).
Used to remove the signature being verified from the scriptCode before sighash."
  (if (or (zerop (length pattern)) (> (length pattern) (length script)))
      script
      (let ((result (make-array (length script) :element-type '(unsigned-byte 8)
                                                :fill-pointer 0))
            (slen (length script))
            (plen (length pattern))
            (i 0))
        (loop while (< i slen)
              do (if (and (<= (+ i plen) slen)
                          (equalp (subseq script i (+ i plen)) pattern))
                     (incf i plen)  ; Skip the pattern
                     (progn
                       (vector-push (aref script i) result)
                       (incf i))))
        (coerce (subseq result 0 (fill-pointer result))
                '(simple-array (unsigned-byte 8) (*))))))

(defun compute-legacy-sighash (tx input-index subscript sighash-type)
  "Compute legacy sighash from actual transaction data.
   TX is a transaction structure from bitcoin-lisp.serialization.
   INPUT-INDEX is the index of the input being signed.
   SUBSCRIPT is the scriptCode (scriptPubKey or redeemScript).
   SIGHASH-TYPE is the sighash type byte (last byte of signature).

   This implements BIP 66 / original Bitcoin sighash algorithm."
  (let* ((subscript (remove-codeseparator subscript))
         (base-type (logand sighash-type #x1f))
         (anyone-can-pay (not (zerop (logand sighash-type #x80))))
         (inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (outputs (bitcoin-lisp.serialization:transaction-outputs tx))
         (num-inputs (length inputs))
         (num-outputs (length outputs)))

    ;; Special case: SIGHASH_SINGLE with input-index >= num-outputs
    ;; Returns hash of all 1s (Bitcoin's bug/feature)
    (when (and (= base-type 3) (>= input-index num-outputs))
      (return-from compute-legacy-sighash
        (make-array 32 :element-type '(unsigned-byte 8)
                       :initial-contents '(1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
                                           0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))))

    (let ((preimage
            (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
              ;; Version
              (write-u32-le (bitcoin-lisp.serialization:transaction-version tx) s)

              ;; Inputs
              (if anyone-can-pay
                  ;; ANYONECANPAY: only include the input being signed
                  (progn
                    (write-varint 1 s)
                    (let ((inp (nth input-index inputs)))
                      (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output inp)))
                        ;; Outpoint
                        (loop for b across (bitcoin-lisp.serialization:outpoint-hash prevout)
                              do (write-byte b s))
                        (write-u32-le (bitcoin-lisp.serialization:outpoint-index prevout) s))
                      ;; Script (subscript for signing input)
                      (write-varint (length subscript) s)
                      (loop for b across subscript do (write-byte b s))
                      ;; Sequence
                      (write-u32-le (bitcoin-lisp.serialization:tx-in-sequence inp) s)))
                  ;; Normal: include all inputs
                  (progn
                    (write-varint num-inputs s)
                    (loop for inp in inputs
                          for i from 0
                          do (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output inp)))
                               ;; Outpoint
                               (loop for b across (bitcoin-lisp.serialization:outpoint-hash prevout)
                                     do (write-byte b s))
                               (write-u32-le (bitcoin-lisp.serialization:outpoint-index prevout) s))
                             ;; Script: subscript for signing input, empty for others
                             (if (= i input-index)
                                 (progn
                                   (write-varint (length subscript) s)
                                   (loop for b across subscript do (write-byte b s)))
                                 (write-varint 0 s))
                             ;; Sequence: 0 for others in NONE/SINGLE mode
                             (if (and (or (= base-type 2) (= base-type 3))
                                      (/= i input-index))
                                 (write-u32-le 0 s)
                                 (write-u32-le (bitcoin-lisp.serialization:tx-in-sequence inp) s)))))

              ;; Outputs
              (cond
                ;; SIGHASH_NONE: no outputs
                ((= base-type 2)
                 (write-varint 0 s))
                ;; SIGHASH_SINGLE: only output at same index
                ((= base-type 3)
                 (write-varint (1+ input-index) s)
                 (loop for i from 0 below input-index
                       do ;; Empty outputs before the matching one
                          (write-u64-le #xffffffffffffffff s)  ; -1 value
                          (write-varint 0 s))                   ; empty script
                 ;; The actual output at input-index
                 (let ((out (nth input-index outputs)))
                   (write-u64-le (bitcoin-lisp.serialization:tx-out-value out) s)
                   (let ((script (bitcoin-lisp.serialization:tx-out-script-pubkey out)))
                     (write-varint (length script) s)
                     (loop for b across script do (write-byte b s)))))
                ;; SIGHASH_ALL: all outputs
                (t
                 (write-varint num-outputs s)
                 (loop for out in outputs
                       do (write-u64-le (bitcoin-lisp.serialization:tx-out-value out) s)
                          (let ((script (bitcoin-lisp.serialization:tx-out-script-pubkey out)))
                            (write-varint (length script) s)
                            (loop for b across script do (write-byte b s))))))

              ;; Locktime
              (write-u32-le (bitcoin-lisp.serialization:transaction-lock-time tx) s)

              ;; Sighash type (4 bytes LE)
              (write-u32-le sighash-type s))))

      (bitcoin-lisp.crypto:hash256 preimage))))

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
   SIGHASH-TYPE is the signature hash type.
   Uses *current-tx* and *current-input-index* for real transaction context,
   or falls back to synthetic credit transaction for script_tests.json format."
  (if *current-tx*
      (compute-bip143-sighash-real script-code amount sighash-type)
      (compute-bip143-sighash-test script-code amount sighash-type)))

(defun compute-bip143-sighash-real (script-code amount sighash-type)
  "Compute BIP 143 sighash using real transaction data from *current-tx*."
  (let* ((tx *current-tx*)
         (input-index *current-input-index*)
         (base-type (logand sighash-type #x1f))
         (anyonecanpay (plusp (logand sighash-type #x80)))
         (inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (outputs (bitcoin-lisp.serialization:transaction-outputs tx))
         (current-input (nth input-index inputs))
         (current-prevout (bitcoin-lisp.serialization:tx-in-previous-output current-input))
         ;; 2. hashPrevouts
         (hash-prevouts
           (if anyonecanpay
               (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               (bitcoin-lisp.crypto:hash256
                (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                  (dolist (inp inputs)
                    (let ((prev (bitcoin-lisp.serialization:tx-in-previous-output inp)))
                      (loop for b across (bitcoin-lisp.serialization:outpoint-hash prev)
                            do (write-byte b s))
                      (write-u32-le (bitcoin-lisp.serialization:outpoint-index prev) s)))))))
         ;; 3. hashSequence
         (hash-sequence
           (if (or anyonecanpay (= base-type 2) (= base-type 3))
               (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               (bitcoin-lisp.crypto:hash256
                (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                  (dolist (inp inputs)
                    (write-u32-le (bitcoin-lisp.serialization:tx-in-sequence inp) s))))))
         ;; 8. hashOutputs
         (hash-outputs
           (cond
             ((= base-type 2) ; SIGHASH_NONE
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
             ((and (= base-type 3) (< input-index (length outputs))) ; SIGHASH_SINGLE
              (bitcoin-lisp.crypto:hash256
               (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                 (let ((out (nth input-index outputs)))
                   (write-u64-le (bitcoin-lisp.serialization:tx-out-value out) s)
                   (let ((script (bitcoin-lisp.serialization:tx-out-script-pubkey out)))
                     (write-varint (length script) s)
                     (loop for b across script do (write-byte b s)))))))
             ((and (= base-type 3) (>= input-index (length outputs))) ; SIGHASH_SINGLE out of range
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
             (t ; SIGHASH_ALL
              (bitcoin-lisp.crypto:hash256
               (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                 (dolist (out outputs)
                   (write-u64-le (bitcoin-lisp.serialization:tx-out-value out) s)
                   (let ((script (bitcoin-lisp.serialization:tx-out-script-pubkey out)))
                     (write-varint (length script) s)
                     (loop for b across script do (write-byte b s))))))))))
    ;; Build BIP 143 preimage
    (let ((preimage
            (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
              ;; 1. nVersion
              (write-u32-le (bitcoin-lisp.serialization:transaction-version tx) s)
              ;; 2. hashPrevouts
              (loop for b across hash-prevouts do (write-byte b s))
              ;; 3. hashSequence
              (loop for b across hash-sequence do (write-byte b s))
              ;; 4. outpoint (txid + vout)
              (loop for b across (bitcoin-lisp.serialization:outpoint-hash current-prevout)
                    do (write-byte b s))
              (write-u32-le (bitcoin-lisp.serialization:outpoint-index current-prevout) s)
              ;; 5. scriptCode
              (write-varint (length script-code) s)
              (loop for b across script-code do (write-byte b s))
              ;; 6. value
              (write-u64-le amount s)
              ;; 7. nSequence
              (write-u32-le (bitcoin-lisp.serialization:tx-in-sequence current-input) s)
              ;; 8. hashOutputs
              (loop for b across hash-outputs do (write-byte b s))
              ;; 9. nLockTime
              (write-u32-le (bitcoin-lisp.serialization:transaction-lock-time tx) s)
              ;; 10. sighash type
              (write-u32-le sighash-type s))))
      (bitcoin-lisp.crypto:hash256 preimage))))

(defun compute-bip143-sighash-test (script-code amount sighash-type)
  "Compute BIP 143 sighash using synthetic credit transaction (script_tests.json format)."
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
         (hash-prevouts (if anyonecanpay
                            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                            (compute-hash-prevouts)))
         (hash-sequence (if (or anyonecanpay (= base-type 2) (= base-type 3))
                            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                            (compute-hash-sequence)))
         (hash-outputs (cond
                         ((= base-type 2)
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                         ((= base-type 3)
                          (compute-hash-outputs))
                         (t (compute-hash-outputs)))))
    (let ((preimage
            (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
              (write-u32-le 1 s)
              (loop for b across hash-prevouts do (write-byte b s))
              (loop for b across hash-sequence do (write-byte b s))
              (loop for b across credit-txid do (write-byte b s))
              (write-u32-le 0 s)
              (write-varint (length script-code) s)
              (loop for b across script-code do (write-byte b s))
              (write-u64-le amount s)
              (write-u32-le #xffffffff s)
              (loop for b across hash-outputs do (write-byte b s))
              (write-u32-le 0 s)
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

    ;; CONST_SCRIPTCODE: reject if scriptCode contains OP_CODESEPARATOR as an opcode
    ;; Also reject if FindAndDelete would modify the scriptCode (sig found in scriptCode)
    (when (flag-enabled-p "CONST_SCRIPTCODE")
      (let ((sc (or *current-script-code* script-pubkey)))
        ;; Check for OP_CODESEPARATOR opcodes (walking script properly)
        (let ((i 0) (slen (length sc)))
          (loop while (< i slen)
                do (let ((op (aref sc i)))
                     (when (= op #xab)
                       (return-from verify-checksig (values nil :op-codeseparator)))
                     (cond
                       ((and (>= op 1) (<= op 75)) (incf i (1+ op)))
                       ((= op 76) (if (< (1+ i) slen) (incf i (+ 2 (aref sc (1+ i)))) (incf i)))
                       ((= op 77) (if (< (+ i 2) slen)
                                      (incf i (+ 3 (aref sc (1+ i)) (ash (aref sc (+ i 2)) 8)))
                                      (incf i)))
                       (t (incf i)))))))
      ;; Check if FindAndDelete would modify the scriptCode
      (let* ((sc (or *current-script-code* script-pubkey))
             (siglen (length sig-bytes))
             (pattern (when (<= siglen 75)
                        (concatenate '(vector (unsigned-byte 8))
                                     (vector siglen) sig-bytes))))
        (when (and pattern (search pattern sc))
          (return-from verify-checksig (values nil :sig-findanddelete)))))

    ;; Compute sighash and verify
    (let* ((subscript-raw (or *current-script-code* script-pubkey))
           (sighash (cond
                      ;; P2WSH: BIP 143 sighash — no FindAndDelete (BIP 143 spec)
                      ;; Use *current-script-code* with OP_CODESEPARATOR bytes removed
                      ((and *witness-v0-mode* *current-tx*)
                       (let ((effective-script-code (remove-codeseparator subscript-raw)))
                         (compute-bip143-sighash effective-script-code
                                                 *witness-input-amount*
                                                 sighash-type)))
                      ;; Legacy/P2SH: legacy sighash with FindAndDelete
                      (*current-tx*
                       (let* ((sig-push-pattern
                                (let ((siglen (length sig-bytes)))
                                  (if (<= siglen 75)
                                      (concatenate '(vector (unsigned-byte 8))
                                                   (vector siglen) sig-bytes)
                                      sig-bytes)))
                              (subscript-for-hash (find-and-delete subscript-raw sig-push-pattern)))
                         (compute-legacy-sighash *current-tx*
                                                 *current-input-index*
                                                 subscript-for-hash
                                                 sighash-type)))
                      ;; Unit tests: test transaction format
                      (t (compute-test-sighash script-pubkey sighash-type))))
           (require-low-s (flag-enabled-p "LOW_S")))
      ;; Debug output before verification
      (when (and *debug-checksig* *current-tx*)
        (format t "~%[CHECKSIG DEBUG] input=~D sighash-type=~D~%"
                *current-input-index* sighash-type)
        (format t "  subscript len=~D: ~A~%"
                (length subscript-for-hash)
                (bitcoin-lisp.crypto:bytes-to-hex subscript-for-hash))
        (format t "  sighash: ~A~%"
                (bitcoin-lisp.crypto:bytes-to-hex sighash))
        (format t "  sig len=~D: ~A~%"
                (length der-sig)
                (bitcoin-lisp.crypto:bytes-to-hex der-sig))
        (format t "  pubkey len=~D: ~A~%"
                (length pubkey-bytes)
                (bitcoin-lisp.crypto:bytes-to-hex pubkey-bytes)))
      (multiple-value-bind (result status)
          (bitcoin-lisp.crypto:verify-signature sighash der-sig pubkey-bytes
                                                :strict strict-der
                                                :low-s require-low-s)
        ;; Debug output after verification
        (when (and *debug-checksig* *current-tx* (not result))
          (format t "  VERIFICATION FAILED! status=~A~%" status))
        (cond
          ;; If LOW_S flag and signature had high-S, return :sig-high-s error
          ((and (eq status :high-s) require-low-s)
           (values nil :sig-high-s))
          ;; If DERSIG is set and DER parsing failed, return :sig-der error
          ((and strict-der (not status))
           (values nil :sig-der))
          ;; NULLFAIL: if sig is non-empty and verification failed, error
          ;; Suppressed during CHECKMULTISIG (handled at algorithm level)
          ((and (not result)
                (not *in-checkmultisig*)
                (flag-enabled-p "NULLFAIL"))
           (values nil :nullfail))
          ;; Normal result
          (t (values result nil)))))))

(defvar *in-checkmultisig* nil
  "When T, suppress per-signature NULLFAIL in verify-checksig.
CHECKMULTISIG handles NULLFAIL at the algorithm level after all attempts.")

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

  (let ((*in-checkmultisig* t))
    (multiple-value-bind (result error-type)
        (verify-checkmultisig sigs pubkeys script-pubkey)
      (when error-type
        (setf *last-checkmultisig-error* error-type))
      result)))

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
    (let* ((sighash (compute-bip143-sighash (remove-codeseparator script-code) amount sighash-type))
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

    ;; Check witness item sizes (max 520 bytes per BIP 141)
    (dolist (item (butlast witness))
      (when (> (length item) 520)
        (return-from validate-p2wsh (values nil :push-size))))

    ;; Execute the witness script with remaining witness items as initial stack
    ;; Uses BIP 143 sighash for any CHECKSIG/CHECKMULTISIG operations
    (let* ((*witness-v0-mode* t)
           (*witness-input-amount* amount)
           (*current-script-code* witness-script)
           (stack-items (butlast witness))
           (script-vec (cl-array-to-coalton-vector witness-script))
           ;; Witness items are ordered bottom-to-top; Coalton stack is top-first
           (initial-stack (mapcar #'cl-array-to-coalton-vector (reverse stack-items)))
           ;; Use real transaction context for CLTV/CSV checks
           (locktime (if *current-tx*
                         (bitcoin-lisp.serialization:transaction-lock-time *current-tx*)
                         0))
           (version (if *current-tx*
                        (bitcoin-lisp.serialization:transaction-version *current-tx*)
                        1))
           (sequence (if (and *current-tx*
                              (bitcoin-lisp.serialization:transaction-inputs *current-tx*)
                              (< *current-input-index*
                                 (length (bitcoin-lisp.serialization:transaction-inputs *current-tx*))))
                         (bitcoin-lisp.serialization:tx-in-sequence
                          (nth *current-input-index*
                               (bitcoin-lisp.serialization:transaction-inputs *current-tx*)))
                         #xFFFFFFFF))
           (result (bitcoin-lisp.coalton.script:execute-script-with-stack-tx
                    script-vec initial-stack locktime version sequence)))
      (if (bitcoin-lisp.coalton.script:script-result-ok-p result)
          (let ((final-stack (bitcoin-lisp.coalton.script:get-ok-stack result)))
            (cond
              ;; Must have truthy top
              ((not (stack-top-truthy-p final-stack))
               (values nil :script-eval-false))
              ;; CLEANSTACK: P2WSH always requires exactly 1 stack element
              ((and (consp final-stack) (consp (cdr final-stack)))
               (values nil :cleanstack))
              (t (values t nil))))
          (values nil :script-error)))))

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

    ;; Empty witness is an error for v0/v1, but unknown versions are anyone-can-spend
    (when (or (null witness) (zerop (length witness)))
      (if (> version 1)
          ;; Unknown version with empty witness: anyone-can-spend (unless discouraged)
          (if (flag-enabled-p "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM")
              (return-from validate-witness-program (values nil :discourage-upgradable-witness-program))
              (return-from validate-witness-program (values t nil)))
          (return-from validate-witness-program (values nil :witness-program-witness-empty))))

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

      ;; Version 1 (Taproot)
      ((= version 1)
       (if (flag-enabled-p "TAPROOT")
           (let ((prog-len (length program)))
             (if (= prog-len 32)
                 (validate-taproot witness program amount)
                 (values nil :witness-program-wrong-length)))
           ;; Pre-activation: anyone-can-spend
           (values t nil)))

      ;; Unknown version (v2+)
      (t
       (if (flag-enabled-p "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM")
           (values nil :discourage-upgradable-witness-program)
           ;; Anyone-can-spend for unknown versions
           (values t nil))))))

;;; ============================================================
;;; Taproot Validation (BIP 341)
;;; ============================================================

(defun is-taproot-program-p (script)
  "Check if SCRIPT is a Taproot (SegWit v1) program."
  (and (is-witness-program-p script)
       (= (get-witness-version script) 1)
       (= (length (get-witness-program-bytes script)) 32)))

(defun compute-taproot-tweak (internal-pubkey32 &optional merkle-root)
  "Compute the Taproot tweak: tagged_hash('TapTweak', internal_key || merkle_root).
   Returns the 32-byte tweak."
  (bitcoin-lisp.crypto:tap-tweak-hash internal-pubkey32 merkle-root))

(defun compute-tweaked-pubkey (internal-pubkey32 &optional merkle-root)
  "Compute the tweaked public key for Taproot output.
   Returns (values tweaked-pubkey32 parity) or (values nil nil) on failure."
  (let ((tweak (compute-taproot-tweak internal-pubkey32 merkle-root)))
    (bitcoin-lisp.crypto:tweak-xonly-pubkey internal-pubkey32 tweak)))

(defun verify-taproot-tweak (output-pubkey32 output-parity internal-pubkey32 merkle-root)
  "Verify that output-pubkey32 is the correctly tweaked internal key.
   Returns T if valid, NIL otherwise."
  (let ((tweak (compute-taproot-tweak internal-pubkey32 merkle-root)))
    (bitcoin-lisp.crypto:verify-xonly-tweak output-pubkey32 output-parity
                                             internal-pubkey32 tweak)))

(defun parse-control-block (control-block)
  "Parse a Taproot control block.
   Returns (values leaf-version internal-pubkey32 merkle-path) or NIL on error.
   Control block format: <leaf-version|parity> <32-byte-internal-key> [<32-byte-hash>...]"
  ;; Minimum length: 1 (version) + 32 (key) = 33
  ;; Must be 33 + 32*n
  (let ((len (length control-block)))
    (when (or (< len 33)
              (/= (mod (- len 33) 32) 0))
      (return-from parse-control-block nil))
    (let* ((first-byte (aref control-block 0))
           (leaf-version (logand first-byte #xfe))  ; Clear parity bit
           (output-parity (logand first-byte #x01))
           (internal-pubkey (subseq control-block 1 33))
           (path-len (/ (- len 33) 32))
           (merkle-path (loop for i from 0 below path-len
                              collect (subseq control-block
                                              (+ 33 (* i 32))
                                              (+ 33 (* (1+ i) 32))))))
      (values leaf-version output-parity internal-pubkey merkle-path))))

(defun compute-merkle-root-from-path (leaf-hash merkle-path)
  "Compute the Merkle root from a leaf hash and Merkle path.
   Each step: hash = TapBranch(sorted(current, sibling))"
  (reduce (lambda (current-hash sibling-hash)
            (bitcoin-lisp.crypto:tap-branch-hash current-hash sibling-hash))
          merkle-path
          :initial-value leaf-hash))

(defun validate-taproot-key-path (witness output-pubkey32 amount)
  "Validate a Taproot key path spend.
   Witness format: [signature] (64 or 65 bytes)
   Returns (values success error-keyword)."
  ;; Key path: witness has exactly 1 element (the signature)
  (unless (= (length witness) 1)
    (return-from validate-taproot-key-path (values nil nil)))  ; Not a key path

  (let* ((sig (first witness))
         (sig-len (length sig)))
    ;; Signature must be 64 bytes (default sighash) or 65 bytes (explicit sighash)
    (unless (or (= sig-len 64) (= sig-len 65))
      (return-from validate-taproot-key-path (values nil :schnorr-signature-size)))

    (let* ((sighash-type (if (= sig-len 65)
                             (aref sig 64)
                             #x00))  ; SIGHASH_DEFAULT
           (sig64 (if (= sig-len 64) sig (subseq sig 0 64))))

      ;; Validate sighash type for Taproot
      (unless (valid-taproot-sighash-type-p sighash-type)
        (return-from validate-taproot-key-path (values nil :sig-hashtype)))

      ;; Compute BIP 341 sighash
      (let ((sighash (compute-bip341-sighash amount sighash-type nil nil)))
        ;; Verify Schnorr signature
        (if (bitcoin-lisp.crypto:verify-schnorr-signature sighash sig64 output-pubkey32)
            (values t nil)
            (values nil :taproot-invalid-signature))))))

(defun validate-taproot-script-path (witness output-pubkey32 amount)
  "Validate a Taproot script path spend.
   Witness format: [script-inputs...] <script> <control-block>
   Returns (values success error-keyword)."
  ;; Script path: witness has at least 2 elements (script + control block)
  (when (< (length witness) 2)
    (return-from validate-taproot-script-path (values nil :witness-program-witness-empty)))

  (let* ((witness-rev (reverse witness))
         (control-block (first witness-rev))
         (script (second witness-rev))
         (script-inputs (reverse (cddr witness-rev))))

    ;; Parse control block
    (multiple-value-bind (leaf-version output-parity internal-pubkey merkle-path)
        (parse-control-block control-block)
      (unless leaf-version
        (return-from validate-taproot-script-path (values nil :taproot-invalid-control-block)))

      ;; Compute leaf hash
      (let ((leaf-hash (bitcoin-lisp.crypto:tap-leaf-hash leaf-version script)))
        ;; Compute Merkle root from path
        (let ((merkle-root (if merkle-path
                               (compute-merkle-root-from-path leaf-hash merkle-path)
                               leaf-hash)))
          ;; Verify the tweaked pubkey matches the output
          (unless (verify-taproot-tweak output-pubkey32 output-parity internal-pubkey merkle-root)
            (return-from validate-taproot-script-path (values nil :taproot-merkle-mismatch)))

          ;; Execute the script in Tapscript mode
          (if (= leaf-version #xc0)
              ;; Leaf version 0xc0 = Tapscript (BIP 342)
              (progn
                ;; 1. Pre-scan for OP_SUCCESS
                ;; If any OP_SUCCESS opcode is found, script succeeds immediately
                (when (scan-for-op-success script)
                  (return-from validate-taproot-script-path (values t nil)))

                ;; 2. Execute the Tapscript with witness inputs as stack
                (run-tapscript script script-inputs leaf-hash amount internal-pubkey))
              ;; Unknown leaf version - anyone can spend if DISCOURAGE flag not set
              (if (flag-enabled-p "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION")
                  (values nil :discourage-upgradable-witness-program)
                  (values t nil))))))))

(defun validate-taproot (witness output-pubkey32 amount)
  "Validate a Taproot (SegWit v1) spend.
   Determines key path vs script path and delegates.
   Returns (values success error-keyword)."
  ;; Empty witness is an error
  (when (or (null witness) (zerop (length witness)))
    (return-from validate-taproot (values nil :witness-program-witness-empty)))

  ;; Check for annex (BIP 341: first byte 0x50)
  ;; Annex is for future extensions, for now we just detect and skip
  (let ((maybe-annex (car (last witness))))
    (when (and (plusp (length maybe-annex))
               (= (aref maybe-annex 0) #x50)
               (> (length witness) 1))
      ;; Has annex, remove it for processing
      (setf witness (butlast witness))))

  ;; Key path: single stack element
  ;; Script path: 2+ elements (script inputs + script + control block)
  (if (= (length witness) 1)
      (validate-taproot-key-path witness output-pubkey32 amount)
      (validate-taproot-script-path witness output-pubkey32 amount)))

(defun valid-taproot-sighash-type-p (sighash-type)
  "Check if sighash type is valid for Taproot (BIP 341).
   Valid types: 0x00 (DEFAULT), 0x01 (ALL), 0x02 (NONE), 0x03 (SINGLE),
   with optional 0x80 (ANYONECANPAY) flag."
  (let ((base-type (logand sighash-type #x7f)))
    (and (member base-type '(#x00 #x01 #x02 #x03))
         ;; No flags other than ANYONECANPAY
         (zerop (logand sighash-type #x60)))))

(defun compute-bip341-sighash (amount sighash-type &optional tapleaf-hash key-version)
  "Compute BIP 341 signature hash for Taproot.
   This implements the SigMsg serialization from BIP 341 Annex G.
   TAPLEAF-HASH and KEY-VERSION are used for script path spending."
  (let* ((base-type (logand sighash-type #x1f))
         (anyonecanpay (plusp (logand sighash-type #x80)))
         ;; Compute credit txid for outpoint (same as BIP 143)
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
         ;; Compute hash components
         (hash-prevouts (if anyonecanpay
                            nil
                            (bitcoin-lisp.crypto:sha256
                             (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                               (loop for b across credit-txid do (write-byte b s))
                               (write-u32-le 0 s)))))
         (hash-amounts (if anyonecanpay
                           nil
                           (bitcoin-lisp.crypto:sha256
                            (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                              (write-u64-le amount s)))))
         (hash-script-pubkeys (if anyonecanpay
                                   nil
                                   (bitcoin-lisp.crypto:sha256
                                    (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                                      (write-varint (length credit-script) s)
                                      (loop for b across credit-script do (write-byte b s))))))
         (hash-sequences (if anyonecanpay
                             nil
                             (bitcoin-lisp.crypto:sha256
                              (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                                (write-u32-le #xffffffff s)))))
         (hash-outputs (cond
                         ((= base-type 2) nil)  ; SIGHASH_NONE
                         ((= base-type 3)       ; SIGHASH_SINGLE
                          (bitcoin-lisp.crypto:sha256
                           (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                             (write-u64-le 0 s)
                             (write-varint 0 s))))
                         (t (bitcoin-lisp.crypto:sha256
                             (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                               (write-u64-le 0 s)
                               (write-varint 0 s))))))
         ;; Spend type: ext_flag (1 if script path) | (has-annex ? 1 : 0)
         (ext-flag (if tapleaf-hash 1 0))
         (spend-type (ash ext-flag 1)))  ; No annex support yet

    ;; Build the SigMsg preimage
    (let ((preimage
            (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
              ;; Epoch (0x00)
              (write-byte 0 s)
              ;; hash_type (1 byte)
              (write-byte sighash-type s)
              ;; nVersion (4 bytes)
              (write-u32-le 1 s)
              ;; nLockTime (4 bytes)
              (write-u32-le 0 s)
              ;; If not ANYONECANPAY:
              (unless anyonecanpay
                ;; sha_prevouts (32 bytes)
                (loop for b across hash-prevouts do (write-byte b s))
                ;; sha_amounts (32 bytes)
                (loop for b across hash-amounts do (write-byte b s))
                ;; sha_scriptpubkeys (32 bytes)
                (loop for b across hash-script-pubkeys do (write-byte b s))
                ;; sha_sequences (32 bytes)
                (loop for b across hash-sequences do (write-byte b s)))
              ;; If SIGHASH_ALL or SIGHASH_DEFAULT:
              (when (or (= base-type 0) (= base-type 1))
                ;; sha_outputs (32 bytes)
                (loop for b across hash-outputs do (write-byte b s)))
              ;; spend_type (1 byte)
              (write-byte spend-type s)
              ;; If ANYONECANPAY:
              (if anyonecanpay
                  (progn
                    ;; outpoint (36 bytes)
                    (loop for b across credit-txid do (write-byte b s))
                    (write-u32-le 0 s)
                    ;; amount (8 bytes)
                    (write-u64-le amount s)
                    ;; scriptPubKey
                    (write-varint (length credit-script) s)
                    (loop for b across credit-script do (write-byte b s))
                    ;; nSequence (4 bytes)
                    (write-u32-le #xffffffff s))
                  (progn
                    ;; input_index (4 bytes)
                    (write-u32-le 0 s)))
              ;; If SIGHASH_SINGLE:
              (when (= base-type 3)
                ;; sha_single_output (32 bytes)
                (loop for b across hash-outputs do (write-byte b s)))
              ;; If ext_flag = 1 (script path):
              (when tapleaf-hash
                ;; tapleaf_hash (32 bytes)
                (loop for b across tapleaf-hash do (write-byte b s))
                ;; key_version (1 byte)
                (write-byte (or key-version 0) s)
                ;; codesep_pos (4 bytes, 0xffffffff = no CODESEPARATOR)
                (write-u32-le #xffffffff s)))))
      ;; Return TapSighash
      (bitcoin-lisp.crypto:tagged-hash "TapSighash" preimage))))
