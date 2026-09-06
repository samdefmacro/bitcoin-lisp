(in-package #:bitcoin-lisp.validation)

;;; Bitcoin Script Interpreter
;;;
;;; Bitcoin uses a stack-based scripting language for transaction validation.
;;; This implements the core opcodes needed for P2PKH (Pay-to-Public-Key-Hash)
;;; and basic transaction validation.

;;;; Opcode definitions

(defconstant +op-0+ #x00)
(defconstant +op-false+ #x00)
(defconstant +op-pushdata1+ #x4c)
(defconstant +op-pushdata2+ #x4d)
(defconstant +op-pushdata4+ #x4e)
(defconstant +op-1negate+ #x4f)
(defconstant +op-1+ #x51)
(defconstant +op-true+ #x51)
(defconstant +op-2+ #x52)
(defconstant +op-16+ #x60)

;; Flow control
(defconstant +op-nop+ #x61)
(defconstant +op-if+ #x63)
(defconstant +op-notif+ #x64)
(defconstant +op-else+ #x67)
(defconstant +op-endif+ #x68)
(defconstant +op-verify+ #x69)
(defconstant +op-return+ #x6a)

;; Stack operations
(defconstant +op-toaltstack+ #x6b)
(defconstant +op-fromaltstack+ #x6c)
(defconstant +op-ifdup+ #x73)
(defconstant +op-depth+ #x74)
(defconstant +op-drop+ #x75)
(defconstant +op-dup+ #x76)
(defconstant +op-nip+ #x77)
(defconstant +op-over+ #x78)
(defconstant +op-pick+ #x79)
(defconstant +op-roll+ #x7a)
(defconstant +op-rot+ #x7b)
(defconstant +op-swap+ #x7c)
(defconstant +op-tuck+ #x7d)
(defconstant +op-2drop+ #x6d)
(defconstant +op-2dup+ #x6e)
(defconstant +op-3dup+ #x6f)
(defconstant +op-2over+ #x70)
(defconstant +op-2rot+ #x71)
(defconstant +op-2swap+ #x72)

;; Arithmetic
(defconstant +op-1add+ #x8b)
(defconstant +op-1sub+ #x8c)
(defconstant +op-negate+ #x8f)
(defconstant +op-abs+ #x90)
(defconstant +op-not+ #x91)
(defconstant +op-0notequal+ #x92)
(defconstant +op-add+ #x93)
(defconstant +op-sub+ #x94)
(defconstant +op-booland+ #x9a)
(defconstant +op-boolor+ #x9b)
(defconstant +op-numequal+ #x9c)
(defconstant +op-numequalverify+ #x9d)
(defconstant +op-numnotequal+ #x9e)
(defconstant +op-lessthan+ #x9f)
(defconstant +op-greaterthan+ #xa0)
(defconstant +op-lessthanorequal+ #xa1)
(defconstant +op-greaterthanorequal+ #xa2)
(defconstant +op-min+ #xa3)
(defconstant +op-max+ #xa4)
(defconstant +op-within+ #xa5)

;; Crypto
(defconstant +op-ripemd160+ #xa6)
(defconstant +op-sha1+ #xa7)
(defconstant +op-sha256+ #xa8)
(defconstant +op-hash160+ #xa9)
(defconstant +op-hash256+ #xaa)
(defconstant +op-codeseparator+ #xab)
(defconstant +op-checksig+ #xac)
(defconstant +op-checksigverify+ #xad)
(defconstant +op-checkmultisig+ #xae)
(defconstant +op-checkmultisigverify+ #xaf)

;; Comparison
(defconstant +op-equal+ #x87)
(defconstant +op-equalverify+ #x88)

;;;; Sigops counting

(defconstant +max-pubkeys-per-multisig+ 20
  "Maximum number of public keys in a multisig. Used as inaccurate sigops count.")

(defun count-script-sigops (script &key accurate)
  "Count signature operations in a raw script byte vector.
When ACCURATE is NIL (legacy counting), OP_CHECKMULTISIG(VERIFY) counts as 20.
When ACCURATE is T (P2SH/witness counting), uses the preceding small-integer
opcode (OP_1..OP_16) as the key count, or 20 if not present."
  (let ((len (length script))
        (i 0)
        (count 0)
        (last-opcode 0))
    (loop while (< i len)
          do (let ((opcode (aref script i)))
               (cond
                 ;; Push data: skip over pushed bytes
                 ((<= 1 opcode 75)
                  (setf last-opcode opcode)
                  (incf i (1+ opcode)))
                 ((= opcode +op-pushdata1+)
                  (setf last-opcode opcode)
                  (if (< (1+ i) len)
                      (incf i (+ 2 (aref script (1+ i))))
                      (return)))
                 ((= opcode +op-pushdata2+)
                  (setf last-opcode opcode)
                  (if (< (+ i 2) len)
                      (incf i (+ 3 (logior (aref script (1+ i))
                                           (ash (aref script (+ i 2)) 8))))
                      (return)))
                 ((= opcode +op-pushdata4+)
                  (setf last-opcode opcode)
                  (if (< (+ i 4) len)
                      (incf i (+ 5 (logior (aref script (1+ i))
                                           (ash (aref script (+ i 2)) 8)
                                           (ash (aref script (+ i 3)) 16)
                                           (ash (aref script (+ i 4)) 24))))
                      (return)))
                 ;; OP_CHECKSIG / OP_CHECKSIGVERIFY
                 ((or (= opcode +op-checksig+) (= opcode +op-checksigverify+))
                  (incf count)
                  (setf last-opcode opcode)
                  (incf i))
                 ;; OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
                 ((or (= opcode +op-checkmultisig+) (= opcode +op-checkmultisigverify+))
                  (if (and accurate (<= +op-1+ last-opcode +op-16+))
                      (incf count (1+ (- last-opcode +op-1+)))
                      (incf count +max-pubkeys-per-multisig+))
                  (setf last-opcode opcode)
                  (incf i))
                 ;; All other opcodes
                 (t
                  (setf last-opcode opcode)
                  (incf i)))))
    count))

;;;; Script execution context

(defstruct script-context
  "Execution context for script validation."
  (stack '() :type list)
  (alt-stack '() :type list)
  (script #() :type (simple-array (unsigned-byte 8) (*)))
  (position 0 :type (unsigned-byte 32))
  (tx nil)
  (input-index 0 :type (unsigned-byte 32))
  (flags 0 :type (unsigned-byte 32))
  (error nil))

;;;; Stack operations

(defun stack-push (ctx value)
  "Push VALUE onto the stack."
  (push value (script-context-stack ctx)))

(defun stack-pop (ctx)
  "Pop and return the top value from the stack."
  (if (script-context-stack ctx)
      (pop (script-context-stack ctx))
      (progn
        (setf (script-context-error ctx) :stack-underflow)
        nil)))

(defun stack-top (ctx)
  "Return the top value without popping."
  (first (script-context-stack ctx)))

(defun stack-size (ctx)
  "Return the number of items on the stack."
  (length (script-context-stack ctx)))

;;;; Value conversions

(defun bytes-to-script-num (bytes)
  "Convert script bytes to a number (little-endian with sign bit)."
  (if (zerop (length bytes))
      0
      (let* ((negative (logbitp 7 (aref bytes (1- (length bytes)))))
             (abs-value (loop for i from 0 below (length bytes)
                              sum (ash (logand (aref bytes i)
                                               (if (= i (1- (length bytes)))
                                                   #x7F
                                                   #xFF))
                                       (* i 8)))))
        (if negative (- abs-value) abs-value))))

(defun script-num-to-bytes (num)
  "Convert a number to script bytes."
  (if (zerop num)
      #()
      (let* ((negative (minusp num))
             (abs-num (abs num))
             (bytes (loop for n = abs-num then (ash n -8)
                          while (plusp n)
                          collect (logand n #xFF))))
        (let ((result (coerce bytes '(vector (unsigned-byte 8)))))
          (when (logbitp 7 (aref result (1- (length result))))
            (setf result (concatenate '(vector (unsigned-byte 8))
                                      result (if negative #(#x80) #(#x00)))))
          (when (and negative (not (zerop (length result))))
            (setf (aref result (1- (length result)))
                  (logior (aref result (1- (length result))) #x80)))
          result))))

(defun cast-to-bool (bytes)
  "Script truth, transliterated from Core CastToBool
(script/interpreter.cpp:36-48): scan for the first non-zero byte; false only
when that byte is the LAST one and equals 0x80 — every negative zero at any
length, not just the one-byte form.

Kept identical to the Coalton interpreter's CAST-TO-BOOL, which is the one on
the consensus path. Both carried the same one-byte-only test; fixing only the
live copy would leave the two free to drift apart again, and this one is the
reference a reader reaches for first."
  (let ((n (length bytes)))
    (loop for i below n
          for b = (aref bytes i)
          unless (zerop b)
            do (return (not (and (= i (1- n)) (= b #x80))))
          finally (return nil))))

;;;; Script parsing

(defun read-script-byte (ctx)
  "Read a byte from the script."
  (if (>= (script-context-position ctx)
          (length (script-context-script ctx)))
      (progn
        (setf (script-context-error ctx) :script-overrun)
        nil)
      (prog1
          (aref (script-context-script ctx) (script-context-position ctx))
        (incf (script-context-position ctx)))))

(defun read-script-bytes (ctx n)
  "Read N bytes from the script."
  (let ((pos (script-context-position ctx))
        (script (script-context-script ctx)))
    (if (> (+ pos n) (length script))
        (progn
          (setf (script-context-error ctx) :script-overrun)
          nil)
        (prog1
            (subseq script pos (+ pos n))
          (incf (script-context-position ctx) n)))))

;;;; Opcode execution

(defun execute-opcode (ctx opcode)
  "Execute a single opcode. Returns T on success, NIL on failure."
  (cond
    ;; Push data (1-75 bytes)
    ((<= 1 opcode 75)
     (let ((data (read-script-bytes ctx opcode)))
       (when data (stack-push ctx data) t)))

    ;; OP_0 / OP_FALSE
    ((= opcode +op-0+)
     (stack-push ctx #()) t)

    ;; OP_1 through OP_16
    ((<= +op-1+ opcode +op-16+)
     (stack-push ctx (script-num-to-bytes (1+ (- opcode +op-1+)))) t)

    ;; OP_1NEGATE
    ((= opcode +op-1negate+)
     (stack-push ctx (script-num-to-bytes -1)) t)

    ;; OP_NOP
    ((= opcode +op-nop+) t)

    ;; OP_VERIFY
    ((= opcode +op-verify+)
     (let ((top (stack-pop ctx)))
       (if (cast-to-bool top) t
           (progn (setf (script-context-error ctx) :verify-failed) nil))))

    ;; OP_RETURN
    ((= opcode +op-return+)
     (setf (script-context-error ctx) :op-return) nil)

    ;; OP_DUP
    ((= opcode +op-dup+)
     (let ((top (stack-top ctx)))
       (when top (stack-push ctx (copy-seq top)) t)))

    ;; OP_DROP
    ((= opcode +op-drop+)
     (stack-pop ctx) t)

    ;; OP_SWAP
    ((= opcode +op-swap+)
     (when (>= (stack-size ctx) 2)
       (rotatef (first (script-context-stack ctx))
                (second (script-context-stack ctx)))
       t))

    ;; OP_EQUAL
    ((= opcode +op-equal+)
     (let ((a (stack-pop ctx))
           (b (stack-pop ctx)))
       (when (and a b)
         (stack-push ctx (if (equalp a b) #(1) #()))
         t)))

    ;; OP_EQUALVERIFY
    ((= opcode +op-equalverify+)
     (let ((a (stack-pop ctx))
           (b (stack-pop ctx)))
       (if (equalp a b) t
           (progn (setf (script-context-error ctx) :equalverify-failed) nil))))

    ;; OP_HASH160
    ((= opcode +op-hash160+)
     (let ((data (stack-pop ctx)))
       (when data
         (stack-push ctx (bl.crypto:hash160 data))
         t)))

    ;; OP_HASH256
    ((= opcode +op-hash256+)
     (let ((data (stack-pop ctx)))
       (when data
         (stack-push ctx (bl.crypto:hash256 data))
         t)))

    ;; OP_SHA256
    ((= opcode +op-sha256+)
     (let ((data (stack-pop ctx)))
       (when data
         (stack-push ctx (bl.crypto:sha256 data))
         t)))

    ;; OP_CHECKSIG
    ((= opcode +op-checksig+)
     (let ((pubkey (stack-pop ctx))
           (sig (stack-pop ctx)))
       (if (and pubkey sig (script-context-tx ctx))
           (let ((valid (verify-signature-for-tx
                         ctx sig pubkey)))
             (stack-push ctx (if valid #(1) #()))
             t)
           (progn
             (stack-push ctx #())
             t))))

    ;; Unknown opcode
    (t
     (setf (script-context-error ctx) :unknown-opcode)
     nil)))

;;;; Signature verification helper

(defun verify-signature-for-tx (ctx sig pubkey)
  "Verify a signature against the transaction being validated.
Delegates to compute-legacy-sighash from the Coalton interop layer for
proper SIGHASH_ALL/NONE/SINGLE/ANYONECANPAY computation."
  (when (and (> (length sig) 0)
             (> (length pubkey) 0)
             (script-context-tx ctx))
    ;; Extract sighash type from last byte of signature
    (let* ((sighash-type (aref sig (1- (length sig))))
           (der-sig (subseq sig 0 (1- (length sig))))
           ;; The subscript is the currently executing script (scriptPubKey)
           (subscript (script-context-script ctx))
           (sighash (bl.interop:compute-legacy-sighash
                     (script-context-tx ctx)
                     (script-context-input-index ctx)
                     subscript
                     sighash-type)))
      (bl.crypto:verify-signature sighash der-sig pubkey))))

;;;; Main script execution

(defun execute-script (script &key tx input-index initial-stack)
  "Execute a script and return the result.
Returns T if script succeeds (non-empty, non-false top of stack).
Returns NIL if script fails."
  (let ((ctx (make-script-context
              :script script
              :stack (or initial-stack '())
              :tx tx
              :input-index (or input-index 0))))
    (loop while (< (script-context-position ctx)
                   (length (script-context-script ctx)))
          do (let ((opcode (read-script-byte ctx)))
               (unless (and opcode (execute-opcode ctx opcode))
                 (return-from execute-script
                   (values nil (script-context-error ctx))))))
    ;; Check final stack
    (let ((top (stack-top ctx)))
      (values (and top (cast-to-bool top))
              nil))))

;;;; Witness and script type helpers (shared by transaction and block validation)

(defun script-is-witness-program-p (script-pubkey)
  "Check if SCRIPT-PUBKEY is a witness program (SegWit v0 or Taproot).
Witness programs: OP_n <2-40 bytes> where n is 0-16."
  (let ((len (length script-pubkey)))
    (and (>= len 4) (<= len 42)
         (let ((version-byte (aref script-pubkey 0))
               (push-len (aref script-pubkey 1)))
           (and (or (zerop version-byte)              ; OP_0
                    (<= #x51 version-byte #x60))      ; OP_1..OP_16
                (<= 2 push-len 40)
                (= len (+ 2 push-len)))))))

(defun get-input-witness (tx input-idx)
  "Get the witness stack for input INPUT-IDX of TX.
Returns a list of byte vectors, or NIL if no witness data."
  (let ((witness (bl.ser:transaction-witness tx)))
    (when (and witness (< input-idx (length witness)))
      (aref witness input-idx))))

(defun validate-input-script (tx input-idx utxo)
  "Validate a single transaction input's script against its spent UTXO by
running the full Bitcoin Core VerifyScript flow (interpreter.cpp:2002-2126)
via the Coalton interop port: scriptSig/scriptPubKey evaluation, EVAL_FALSE,
P2SH, native and P2SH-wrapped witness programs, and the per-input
unexpected-witness rule — all gated on the flags bound in *script-flags*
(per-height consensus flags for block connect, standard flags callers).

A MISSING witness is validated as an EMPTY witness stack, exactly as Core's
VerifyScript substitutes emptyWitness for a null witness pointer
(interpreter.cpp:2004-2007). Under SCRIPT_VERIFY_WITNESS a v0 or v1-taproot
program spend with no witness therefore FAILS
(SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY / MISMATCH), while unknown witness
versions — including pay-to-anchor — consensus-pass as upgradeable. Without
the WITNESS flag (pre-activation heights) a witness-program-shaped
scriptPubKey is nothing special and evaluates as an ordinary legacy script,
so historical pre-segwit spends of such outputs stay valid.

Binds *current-tx* and *current-input-index* for sighash computation.
Returns (VALUES T NIL) on success and (VALUES NIL ERROR-KEYWORD) on failure,
where the keyword is the one Core's SCRIPT_ERR_* value BL.INTEROP names --
what MemPoolAccept puts in the parenthetical of
\"mempool-script-verify-flag-failed (%s)\" (validation.cpp:2117-2119)."
  (let ((script-sig (bl.ser:tx-in-script-sig
                     (aref (bl.ser:transaction-inputs tx) input-idx)))
        (script-pubkey (bl.store:utxo-entry-script-pubkey utxo))
        (amount (bl.store:utxo-entry-value utxo))
        (witness (get-input-witness tx input-idx))
        (bl.interop:*current-tx* tx)
        (bl.interop:*current-input-index* input-idx))
    (multiple-value-bind (success error)
        (bl.interop:verify-script
         script-sig script-pubkey :witness witness :amount amount)
      (unless success
        (bl:log-warn
         "validate-input-script failed: input-idx=~D error=~A"
         input-idx error))
      (values success error))))

;;; ============================================================
;;; Script Disassembly
;;; ============================================================

(defparameter *opcode-names*
  (let ((table (make-hash-table)))
    ;; Push values. OP_0, OP_1NEGATE and OP_1..OP_16 spell their VALUE, not
    ;; their opcode name: that is what Core's GetOpName returns for them.
    (setf (gethash #x00 table) "0")
    (setf (gethash #x4c table) "OP_PUSHDATA1")
    (setf (gethash #x4d table) "OP_PUSHDATA2")
    (setf (gethash #x4e table) "OP_PUSHDATA4")
    (setf (gethash #x4f table) "-1")
    (setf (gethash #x50 table) "OP_RESERVED")
    (loop for i from #x51 to #x60
          do (setf (gethash i table) (format nil "~D" (- i #x50))))
    ;; Flow control
    (setf (gethash #x61 table) "OP_NOP")
    (setf (gethash #x62 table) "OP_VER")
    (setf (gethash #x63 table) "OP_IF")
    (setf (gethash #x64 table) "OP_NOTIF")
    (setf (gethash #x65 table) "OP_VERIF")
    (setf (gethash #x66 table) "OP_VERNOTIF")
    (setf (gethash #x67 table) "OP_ELSE")
    (setf (gethash #x68 table) "OP_ENDIF")
    (setf (gethash #x69 table) "OP_VERIFY")
    (setf (gethash #x6a table) "OP_RETURN")
    ;; Stack
    (setf (gethash #x6b table) "OP_TOALTSTACK")
    (setf (gethash #x6c table) "OP_FROMALTSTACK")
    (setf (gethash #x6d table) "OP_2DROP")
    (setf (gethash #x6e table) "OP_2DUP")
    (setf (gethash #x6f table) "OP_3DUP")
    (setf (gethash #x70 table) "OP_2OVER")
    (setf (gethash #x71 table) "OP_2ROT")
    (setf (gethash #x72 table) "OP_2SWAP")
    (setf (gethash #x73 table) "OP_IFDUP")
    (setf (gethash #x74 table) "OP_DEPTH")
    (setf (gethash #x75 table) "OP_DROP")
    (setf (gethash #x76 table) "OP_DUP")
    (setf (gethash #x77 table) "OP_NIP")
    (setf (gethash #x78 table) "OP_OVER")
    (setf (gethash #x79 table) "OP_PICK")
    (setf (gethash #x7a table) "OP_ROLL")
    (setf (gethash #x7b table) "OP_ROT")
    (setf (gethash #x7c table) "OP_SWAP")
    (setf (gethash #x7d table) "OP_TUCK")
    ;; Splice (disabled)
    (setf (gethash #x7e table) "OP_CAT")
    (setf (gethash #x7f table) "OP_SUBSTR")
    (setf (gethash #x80 table) "OP_LEFT")
    (setf (gethash #x81 table) "OP_RIGHT")
    (setf (gethash #x82 table) "OP_SIZE")
    ;; Bitwise (some disabled)
    (setf (gethash #x83 table) "OP_INVERT")
    (setf (gethash #x84 table) "OP_AND")
    (setf (gethash #x85 table) "OP_OR")
    (setf (gethash #x86 table) "OP_XOR")
    (setf (gethash #x87 table) "OP_EQUAL")
    (setf (gethash #x88 table) "OP_EQUALVERIFY")
    (setf (gethash #x89 table) "OP_RESERVED1")
    (setf (gethash #x8a table) "OP_RESERVED2")
    ;; Arithmetic
    (setf (gethash #x8b table) "OP_1ADD")
    (setf (gethash #x8c table) "OP_1SUB")
    (setf (gethash #x8d table) "OP_2MUL")
    (setf (gethash #x8e table) "OP_2DIV")
    (setf (gethash #x8f table) "OP_NEGATE")
    (setf (gethash #x90 table) "OP_ABS")
    (setf (gethash #x91 table) "OP_NOT")
    (setf (gethash #x92 table) "OP_0NOTEQUAL")
    (setf (gethash #x93 table) "OP_ADD")
    (setf (gethash #x94 table) "OP_SUB")
    (setf (gethash #x95 table) "OP_MUL")
    (setf (gethash #x96 table) "OP_DIV")
    (setf (gethash #x97 table) "OP_MOD")
    (setf (gethash #x98 table) "OP_LSHIFT")
    (setf (gethash #x99 table) "OP_RSHIFT")
    (setf (gethash #x9a table) "OP_BOOLAND")
    (setf (gethash #x9b table) "OP_BOOLOR")
    (setf (gethash #x9c table) "OP_NUMEQUAL")
    (setf (gethash #x9d table) "OP_NUMEQUALVERIFY")
    (setf (gethash #x9e table) "OP_NUMNOTEQUAL")
    (setf (gethash #x9f table) "OP_LESSTHAN")
    (setf (gethash #xa0 table) "OP_GREATERTHAN")
    (setf (gethash #xa1 table) "OP_LESSTHANOREQUAL")
    (setf (gethash #xa2 table) "OP_GREATERTHANOREQUAL")
    (setf (gethash #xa3 table) "OP_MIN")
    (setf (gethash #xa4 table) "OP_MAX")
    (setf (gethash #xa5 table) "OP_WITHIN")
    ;; Crypto
    (setf (gethash #xa6 table) "OP_RIPEMD160")
    (setf (gethash #xa7 table) "OP_SHA1")
    (setf (gethash #xa8 table) "OP_SHA256")
    (setf (gethash #xa9 table) "OP_HASH160")
    (setf (gethash #xaa table) "OP_HASH256")
    (setf (gethash #xab table) "OP_CODESEPARATOR")
    (setf (gethash #xac table) "OP_CHECKSIG")
    (setf (gethash #xad table) "OP_CHECKSIGVERIFY")
    (setf (gethash #xae table) "OP_CHECKMULTISIG")
    (setf (gethash #xaf table) "OP_CHECKMULTISIGVERIFY")
    ;; Expansion
    (setf (gethash #xb0 table) "OP_NOP1")
    (setf (gethash #xb1 table) "OP_CHECKLOCKTIMEVERIFY")
    (setf (gethash #xb2 table) "OP_CHECKSEQUENCEVERIFY")
    (setf (gethash #xb3 table) "OP_NOP4")
    (setf (gethash #xb4 table) "OP_NOP5")
    (setf (gethash #xb5 table) "OP_NOP6")
    (setf (gethash #xb6 table) "OP_NOP7")
    (setf (gethash #xb7 table) "OP_NOP8")
    (setf (gethash #xb8 table) "OP_NOP9")
    (setf (gethash #xb9 table) "OP_NOP10")
    ;; Taproot
    (setf (gethash #xba table) "OP_CHECKSIGADD")
    (setf (gethash #xff table) "OP_INVALIDOPCODE")
    table)
  "Bitcoin Core GetOpName (script/script.cpp:20-160), byte -> name.

Not every entry is an OP_ name: GetOpName spells OP_0 \"0\", OP_1NEGATE
\"-1\" and OP_1..OP_16 \"1\"..\"16\", because that is what those opcodes
PUSH, and Core's own decodescript test corpus asserts those spellings
(test/functional/rpc_decodescript.py:53,93,166,187,197). A byte with no
entry is \"OP_UNKNOWN\" -- GetOpName's default, and one that
rpc_decodescript.json pins for `6aee'.")

(defparameter *sighash-type-names*
  '((#x01 . "ALL") (#x81 . "ALL|ANYONECANPAY")
    (#x02 . "NONE") (#x82 . "NONE|ANYONECANPAY")
    (#x03 . "SINGLE") (#x83 . "SINGLE|ANYONECANPAY"))
  "Bitcoin Core mapSigHashTypes (core_io.cpp:330-341): the six sighash bytes
IsDefinedHashtypeSignature accepts, and the name ScriptToAsmStr prints for
each in brackets after the signature it stripped the byte from.")

(defun %asm-sighash-suffix (push-data)
  "The `[ALL]'-style suffix ScriptToAsmStr appends to PUSH-DATA when it is a
signature, or NIL (core_io.cpp:376-390).

Core's gate is CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr),
which under that one flag is IsValidSignatureEncoding AND
IsDefinedHashtypeSignature -- strict DER over the bytes WITHOUT the trailing
hashtype byte, plus that byte being one of the six defined ones. The empty-
signature arm cannot be reached here: the caller only asks about pushes over
four bytes long."
  (let ((len (length push-data)))
    (when (plusp len)
      (let ((hashtype (aref push-data (1- len))))
        (when (and (bl.interop:check-der-signature-format
                    (subseq push-data 0 (1- len)))
                   (bl.interop:valid-sighash-type-p hashtype))
          (let ((name (cdr (assoc hashtype *sighash-type-names*))))
            (when name (format nil "[~A]" name))))))))

(defun %asm-push-token (data sighash-decode unspendable)
  "How ScriptToAsmStr renders one data push (core_io.cpp:370-395).

A push of four bytes or fewer is its CScriptNum value in DECIMAL -- with
fRequireMinimal false, so a non-minimal push still renders as its value, and
an empty push (OP_0 reaches this arm) as 0. A longer push is hex, and only
there does the scriptSig sighash decode apply; Core suppresses it for an
UNSPENDABLE script so OP_RETURN data that happens to look like a signature is
not decoded as one."
  (cond
    ((<= (length data) 4)
     (format nil "~D" (bl.interop:script-number-to-int data)))
    ((and sighash-decode (not unspendable))
     (let ((suffix (%asm-sighash-suffix data)))
       (if suffix
           (concatenate 'string
                        (bl.crypto:bytes-to-hex (subseq data 0 (1- (length data))))
                        suffix)
           (bl.crypto:bytes-to-hex data))))
    (t (bl.crypto:bytes-to-hex data))))

(defun disassemble-script (script &key sighash-decode)
  "Bitcoin Core ScriptToAsmStr (core_io.cpp:357-401): SCRIPT's assembly
string, tokens separated by single spaces.

SIGHASH-DECODE is Core's fAttemptSighashDecode. Pass it only for a
scriptSig, which is the one place Core passes it (TxToUniv's
`ScriptToAsmStr(txin.scriptSig, true)', core_io.cpp:460, and decodepsbt's
final_scriptSig); a scriptPubKey renders without it, or an OP_RETURN payload
shaped like a signature would be printed as one.

A push that runs off the end of the script (Core's GetOp returning false)
ends the string with `[error]', exactly as Core does -- the tokens before it
are kept."
  (when (zerop (length script))
    (return-from disassemble-script ""))
  (let ((parts '())
        (pos 0)
        (len (length script))
        (unspendable (bl.store:script-unspendable-p script)))
    (labels ((fail ()
               (push "[error]" parts)
               (setf pos len))
             (push-data (n)
               ;; Core: `if (end - pc < 0 || (unsigned)(end - pc) < nSize) return false'.
               (if (<= (+ pos n) len)
                   (progn
                     (push (%asm-push-token (subseq script pos (+ pos n))
                                            sighash-decode unspendable)
                           parts)
                     (incf pos n))
                   (fail)))
             (read-le (n)
               ;; The push length that follows OP_PUSHDATA1/2/4, or NIL when
               ;; the script is too short to hold it (Core's GetOp fails).
               (when (<= (+ pos n) len)
                 (let ((v 0))
                   (dotimes (k n) (setf v (logior v (ash (aref script (+ pos k)) (* 8 k)))))
                   (incf pos n)
                   v))))
      (loop while (< pos len)
            do (let ((opcode (aref script pos)))
                 (incf pos)
                 (cond
                   ;; Direct push of OPCODE bytes; OP_0 is the empty one.
                   ((<= opcode 75) (push-data opcode))
                   ((<= #x4c opcode #x4e)
                    (let ((n (read-le (ecase opcode (#x4c 1) (#x4d 2) (#x4e 4)))))
                      (if n (push-data n) (fail))))
                   (t
                    (push (or (gethash opcode *opcode-names*) "OP_UNKNOWN")
                          parts))))))
    (format nil "~{~A~^ ~}" (nreverse parts))))

