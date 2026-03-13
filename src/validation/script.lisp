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
  (if (null (script-context-stack ctx))
      (progn
        (setf (script-context-error ctx) :stack-underflow)
        nil)
      (pop (script-context-stack ctx))))

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
  "Convert script bytes to boolean."
  (not (or (zerop (length bytes))
           (every #'zerop bytes)
           (and (= (length bytes) 1)
                (= (aref bytes 0) #x80)))))

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
         (stack-push ctx (bitcoin-lisp.crypto:hash160 data))
         t)))

    ;; OP_HASH256
    ((= opcode +op-hash256+)
     (let ((data (stack-pop ctx)))
       (when data
         (stack-push ctx (bitcoin-lisp.crypto:hash256 data))
         t)))

    ;; OP_SHA256
    ((= opcode +op-sha256+)
     (let ((data (stack-pop ctx)))
       (when data
         (stack-push ctx (bitcoin-lisp.crypto:sha256 data))
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
This is a simplified implementation - full implementation would need
proper sighash computation."
  (when (and (> (length sig) 0)
             (> (length pubkey) 0)
             (script-context-tx ctx))
    ;; Extract sighash type from last byte of signature
    (let* ((sighash-type (aref sig (1- (length sig))))
           (der-sig (subseq sig 0 (1- (length sig))))
           ;; Compute signature hash (simplified - needs proper implementation)
           (sighash (compute-sighash (script-context-tx ctx)
                                     (script-context-input-index ctx)
                                     sighash-type)))
      (bitcoin-lisp.crypto:verify-signature sighash der-sig pubkey))))

(defun compute-sighash (tx input-index sighash-type)
  "Compute the signature hash for a transaction input.
This is a simplified placeholder - full implementation needed."
  (declare (ignore sighash-type))
  ;; Simplified: just hash the serialized transaction
  ;; Real implementation needs proper SIGHASH algorithm
  (bitcoin-lisp.crypto:hash256
   (bitcoin-lisp.serialization:serialize-transaction tx)))

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

(defun validate-script (script-sig script-pubkey &key tx input-index)
  "Validate a transaction input by executing scriptSig + scriptPubKey.
Returns T if validation succeeds."
  ;; Execute scriptSig
  (multiple-value-bind (success error)
      (execute-script script-sig :tx tx :input-index input-index)
    (declare (ignore success))
    (when error
      (return-from validate-script (values nil error))))
  ;; Get stack from scriptSig execution and use for scriptPubKey
  (let ((ctx (make-script-context :script script-sig)))
    (loop while (< (script-context-position ctx)
                   (length script-sig))
          do (let ((opcode (read-script-byte ctx)))
               (execute-opcode ctx opcode)))
    ;; Execute scriptPubKey with scriptSig's stack
    (execute-script script-pubkey
                    :tx tx
                    :input-index input-index
                    :initial-stack (script-context-stack ctx))))

;;; ============================================================
;;; Script Disassembly
;;; ============================================================

(defparameter *opcode-names*
  (let ((table (make-hash-table)))
    ;; Push values
    (setf (gethash #x00 table) "OP_0")
    (setf (gethash #x4c table) "OP_PUSHDATA1")
    (setf (gethash #x4d table) "OP_PUSHDATA2")
    (setf (gethash #x4e table) "OP_PUSHDATA4")
    (setf (gethash #x4f table) "OP_1NEGATE")
    (loop for i from #x51 to #x60
          do (setf (gethash i table) (format nil "OP_~D" (- i #x50))))
    ;; Flow control
    (setf (gethash #x61 table) "OP_NOP")
    (setf (gethash #x63 table) "OP_IF")
    (setf (gethash #x64 table) "OP_NOTIF")
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
    table)
  "Mapping from opcode byte to name string.")

(defun disassemble-script (script)
  "Disassemble a script to human-readable ASM string.
SCRIPT is a byte vector. Returns a string like 'OP_DUP OP_HASH160 <hex> OP_EQUALVERIFY OP_CHECKSIG'."
  (when (zerop (length script))
    (return-from disassemble-script ""))
  (let ((parts '())
        (pos 0)
        (len (length script)))
    (loop while (< pos len)
          do (let ((opcode (aref script pos)))
               (incf pos)
               (cond
                 ;; Direct push (1-75 bytes)
                 ((<= 1 opcode 75)
                  (if (<= (+ pos opcode) len)
                      (let ((data (subseq script pos (+ pos opcode))))
                        (push (bitcoin-lisp.crypto:bytes-to-hex data) parts)
                        (incf pos opcode))
                      (progn (push "[error]" parts) (setf pos len))))
                 ;; OP_PUSHDATA1
                 ((= opcode #x4c)
                  (when (< pos len)
                    (let ((n (aref script pos)))
                      (incf pos)
                      (if (<= (+ pos n) len)
                          (let ((data (subseq script pos (+ pos n))))
                            (push (bitcoin-lisp.crypto:bytes-to-hex data) parts)
                            (incf pos n))
                          (progn (push "[error]" parts) (setf pos len))))))
                 ;; OP_PUSHDATA2
                 ((= opcode #x4d)
                  (when (<= (+ pos 2) len)
                    (let ((n (+ (aref script pos) (ash (aref script (1+ pos)) 8))))
                      (incf pos 2)
                      (if (<= (+ pos n) len)
                          (let ((data (subseq script pos (+ pos n))))
                            (push (bitcoin-lisp.crypto:bytes-to-hex data) parts)
                            (incf pos n))
                          (progn (push "[error]" parts) (setf pos len))))))
                 ;; OP_PUSHDATA4
                 ((= opcode #x4e)
                  (when (<= (+ pos 4) len)
                    (let ((n (+ (aref script pos)
                                (ash (aref script (+ pos 1)) 8)
                                (ash (aref script (+ pos 2)) 16)
                                (ash (aref script (+ pos 3)) 24))))
                      (incf pos 4)
                      (if (<= (+ pos n) len)
                          (let ((data (subseq script pos (+ pos n))))
                            (push (bitcoin-lisp.crypto:bytes-to-hex data) parts)
                            (incf pos n))
                          (progn (push "[error]" parts) (setf pos len))))))
                 ;; Named opcode
                 (t
                  (let ((name (gethash opcode *opcode-names*)))
                    (push (or name (format nil "OP_UNKNOWN[~2,'0x]" opcode)) parts))))))
    (format nil "~{~A~^ ~}" (nreverse parts))))

;;; ============================================================
;;; Script Type Classification
;;; ============================================================

(defun classify-script (script)
  "Classify a script and extract relevant data.
Returns (VALUES type extracted-data) where:
- type is one of: :pubkeyhash, :scripthash, :witness-v0-keyhash, :witness-v0-scripthash,
                  :witness-v1-taproot, :multisig, :nulldata, :pubkey, :nonstandard
- extracted-data is a plist with keys like :hash, :pubkey, :pubkeys, :m, :n, :data, :witness-version, :witness-program"
  (let ((len (length script)))
    (cond
      ;; Empty script
      ((zerop len)
       (values :nonstandard nil))

      ;; P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      ((and (= len 25)
            (= (aref script 0) #x76)   ; OP_DUP
            (= (aref script 1) #xa9)   ; OP_HASH160
            (= (aref script 2) #x14)   ; Push 20 bytes
            (= (aref script 23) #x88)  ; OP_EQUALVERIFY
            (= (aref script 24) #xac)) ; OP_CHECKSIG
       (values :pubkeyhash (list :hash (subseq script 3 23))))

      ;; P2SH: OP_HASH160 <20 bytes> OP_EQUAL
      ((and (= len 23)
            (= (aref script 0) #xa9)   ; OP_HASH160
            (= (aref script 1) #x14)   ; Push 20 bytes
            (= (aref script 22) #x87)) ; OP_EQUAL
       (values :scripthash (list :hash (subseq script 2 22))))

      ;; Witness v0 keyhash (P2WPKH): OP_0 <20 bytes>
      ((and (= len 22)
            (= (aref script 0) #x00)   ; OP_0
            (= (aref script 1) #x14))  ; Push 20 bytes
       (values :witness-v0-keyhash
               (list :witness-version 0
                     :witness-program (subseq script 2 22))))

      ;; Witness v0 scripthash (P2WSH): OP_0 <32 bytes>
      ((and (= len 34)
            (= (aref script 0) #x00)   ; OP_0
            (= (aref script 1) #x20))  ; Push 32 bytes
       (values :witness-v0-scripthash
               (list :witness-version 0
                     :witness-program (subseq script 2 34))))

      ;; Witness v1 taproot (P2TR): OP_1 <32 bytes>
      ((and (= len 34)
            (= (aref script 0) #x51)   ; OP_1
            (= (aref script 1) #x20))  ; Push 32 bytes
       (values :witness-v1-taproot
               (list :witness-version 1
                     :witness-program (subseq script 2 34))))

      ;; General witness program: OP_n <2-40 bytes> where n in 0-16
      ((and (>= len 4) (<= len 42)
            (or (= (aref script 0) #x00)  ; OP_0
                (<= #x51 (aref script 0) #x60))  ; OP_1 to OP_16
            (= (aref script 1) (- len 2))
            (<= 2 (aref script 1) 40))
       (let ((version (if (= (aref script 0) #x00) 0 (- (aref script 0) #x50))))
         (values :witness-unknown
                 (list :witness-version version
                       :witness-program (subseq script 2)))))

      ;; OP_RETURN (nulldata): OP_RETURN [data]
      ((and (>= len 1)
            (= (aref script 0) #x6a))  ; OP_RETURN
       (values :nulldata
               (list :data (if (> len 1) (subseq script 1) #()))))

      ;; P2PK (pay to pubkey): <33 or 65 bytes pubkey> OP_CHECKSIG
      ((and (or (= len 35) (= len 67))  ; 33+1+1 or 65+1+1
            (= (aref script (- len 1)) #xac)  ; OP_CHECKSIG
            (= (aref script 0) (- len 2)))    ; Push length
       (values :pubkey (list :pubkey (subseq script 1 (- len 1)))))

      ;; Bare multisig: OP_m <pubkeys> OP_n OP_CHECKMULTISIG
      ((and (>= len 37)  ; Minimum: OP_1 <33-byte pubkey> OP_1 OP_CHECKMULTISIG
            (= (aref script (- len 1)) #xae)  ; OP_CHECKMULTISIG
            (<= #x51 (aref script 0) #x60)    ; OP_1 to OP_16 (m)
            (<= #x51 (aref script (- len 2)) #x60))  ; OP_1 to OP_16 (n)
       (let ((m (- (aref script 0) #x50))
             (n (- (aref script (- len 2)) #x50))
             (pubkeys '())
             (pos 1))
         ;; Parse pubkeys
         (loop while (and (< pos (- len 2))
                          (< (length pubkeys) n))
               do (let ((push-len (aref script pos)))
                    (when (or (= push-len 33) (= push-len 65))
                      (incf pos)
                      (when (<= (+ pos push-len) (- len 2))
                        (push (subseq script pos (+ pos push-len)) pubkeys)
                        (incf pos push-len)))))
         (if (= (length pubkeys) n)
             (values :multisig (list :m m :n n :pubkeys (nreverse pubkeys)))
             (values :nonstandard nil))))

      ;; Nonstandard
      (t (values :nonstandard nil)))))

(defun script-type-to-string (type)
  "Convert script type keyword to Bitcoin Core compatible string."
  (case type
    (:pubkeyhash "pubkeyhash")
    (:scripthash "scripthash")
    (:witness-v0-keyhash "witness_v0_keyhash")
    (:witness-v0-scripthash "witness_v0_scripthash")
    (:witness-v1-taproot "witness_v1_taproot")
    (:witness-unknown "witness_unknown")
    (:multisig "multisig")
    (:nulldata "nulldata")
    (:pubkey "pubkey")
    (:nonstandard "nonstandard")
    (otherwise "nonstandard")))
