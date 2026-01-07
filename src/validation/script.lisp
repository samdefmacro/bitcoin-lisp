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
