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
   #:minimal-number-encoding-p))

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

(defun run-scripts-with-p2sh (script-sig script-pubkey p2sh-enabled)
  "Execute scriptSig then scriptPubKey with optional P2SH.
   Returns (values success stack-or-error)."
  (let* ((sig-vec (cl-array-to-coalton-vector script-sig))
         (pubkey-vec (cl-array-to-coalton-vector script-pubkey))
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
       (or (search flag *script-flags*)
           (search (concatenate 'string "," flag) *script-flags*)
           (search (concatenate 'string flag ",") *script-flags*))))

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

(defun compute-test-sighash (script-pubkey sighash-type)
  "Compute the sighash for Bitcoin Core test transaction format.
   This matches the standardized transaction structure used in script_tests.cpp."
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
             ;; Output: scriptPubKey
             (write-varint (length script-pubkey) s)
             (loop for b across script-pubkey do (write-byte b s))
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
              ;; Input: scriptCode (subscript = scriptPubKey for SIGHASH_ALL)
              (write-varint (length script-pubkey) s)
              (loop for b across script-pubkey do (write-byte b s))
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
   Returns (values result error-type) where error-type is :sig-der, :sig-hashtype,
   :pubkeytype, or NIL."
  ;; Empty signature - no DER to check
  (when (zerop (length sig-bytes))
    (return-from verify-checksig (values nil nil)))

  ;; Extract sighash type from signature (last byte)
  (let* ((sighash-type (aref sig-bytes (1- (length sig-bytes))))
         (der-sig (subseq sig-bytes 0 (1- (length sig-bytes))))
         (strict-der (flag-enabled-p "DERSIG")))

    ;; DERSIG: Check DER format BEFORE anything else
    ;; This ensures we error on bad DER even with empty pubkey
    (when strict-der
      (unless (check-der-signature-format der-sig)
        (return-from verify-checksig (values nil :sig-der))))

    ;; Empty pubkey - can't verify but not an encoding error
    (when (zerop (length pubkey-bytes))
      (return-from verify-checksig (values nil nil)))

    ;; STRICTENC validation when flag is enabled
    (when (flag-enabled-p "STRICTENC")
      (unless (valid-sighash-type-p sighash-type)
        (return-from verify-checksig (values nil :sig-hashtype)))
      (unless (valid-pubkey-format-p pubkey-bytes)
        (return-from verify-checksig (values nil :pubkeytype))))

    ;; Compute sighash and verify
    ;; Use strict DER parsing when DERSIG flag is set
    (let ((sighash (compute-test-sighash script-pubkey sighash-type)))
      (multiple-value-bind (result parse-ok)
          (bitcoin-lisp.crypto:verify-signature sighash der-sig pubkey-bytes
                                                :strict strict-der)
        ;; If DERSIG is set and DER parsing failed, return :sig-der error
        (if (and strict-der (not parse-ok))
            (values nil :sig-der)
            (values result nil))))))

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
   Error-type is nil on success, or :sig-hashtype, :pubkeytype, :nulldummy on STRICTENC failure."
  (let ((num-sigs (length sigs))
        (num-pubkeys (length pubkeys))
        (sig-index 0)
        (pubkey-index 0))

    ;; STRICTENC: validate all pubkey formats upfront
    (when (flag-enabled-p "STRICTENC")
      (dolist (pk pubkeys)
        (when (and (plusp (length pk))
                   (not (valid-pubkey-format-p pk)))
          (return-from verify-checkmultisig (values nil :pubkeytype)))))

    ;; Process signatures in order
    (loop while (and (< sig-index num-sigs)
                     (< pubkey-index num-pubkeys))
          do
             (let* ((sig (nth sig-index sigs))
                    (pk (nth pubkey-index pubkeys)))
               (cond
                 ;; Empty signature - skip (counts as non-matching)
                 ((zerop (length sig))
                  (incf sig-index))

                 ;; Try to verify this sig with current pubkey
                 (t
                  (multiple-value-bind (valid error-type)
                      (verify-checksig sig pk script-pubkey)
                    ;; STRICTENC error - fail immediately
                    (when error-type
                      (return-from verify-checkmultisig (values nil error-type)))

                    (if valid
                        ;; Match! Advance both indices
                        (progn
                          (incf sig-index)
                          (incf pubkey-index))
                        ;; No match - try next pubkey
                        (incf pubkey-index)))))))

    ;; Success if all signatures were matched
    (values (= sig-index num-sigs) nil)))

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
   Returns (values status new-stack) where:
   - status is :ok (success), :fail (verification failed), or :error (script error)
   - new-stack is the stack after operation (with result pushed for :ok/:fail)"
  (setf *last-checkmultisig-error* nil)

  ;; Pop n (number of pubkeys)
  (when (null stack)
    (return-from do-checkmultisig-stack-op (values :underflow nil)))
  (let* ((n-bytes (coalton-vec-to-array (car stack)))
         (stack (cdr stack)))
    ;; MINIMALDATA: validate n encoding
    (multiple-value-bind (n valid)
        (script-number-to-int-validated n-bytes)
      (unless valid
        (setf *last-checkmultisig-error* :minimaldata)
        (return-from do-checkmultisig-stack-op (values :error nil)))

      ;; Validate n: must be 0-20
      (when (or (< n 0) (> n 20))
        (return-from do-checkmultisig-stack-op (values :pubkey-count nil)))

      ;; Pop n pubkeys
      (let ((pubkeys nil))
        (dotimes (i n)
          (when (null stack)
            (return-from do-checkmultisig-stack-op (values :underflow nil)))
          (push (coalton-vec-to-array (car stack)) pubkeys)
          (setf stack (cdr stack)))
        (setf pubkeys (nreverse pubkeys))

        ;; Pop m (number of signatures)
        (when (null stack)
          (return-from do-checkmultisig-stack-op (values :underflow nil)))
        (let* ((m-bytes (coalton-vec-to-array (car stack)))
               (stack (cdr stack)))
          ;; MINIMALDATA: validate m encoding
          (multiple-value-bind (m valid)
              (script-number-to-int-validated m-bytes)
            (unless valid
              (setf *last-checkmultisig-error* :minimaldata)
              (return-from do-checkmultisig-stack-op (values :error nil)))

            ;; Validate m: must be 0-n
            (when (or (< m 0) (> m n))
              (return-from do-checkmultisig-stack-op (values :sig-count nil)))

            ;; Pop m signatures
            (let ((sigs nil))
              (dotimes (i m)
                (when (null stack)
                  (return-from do-checkmultisig-stack-op (values :underflow nil)))
                (push (coalton-vec-to-array (car stack)) sigs)
                (setf stack (cdr stack)))
              (setf sigs (nreverse sigs))

              ;; Pop dummy element (Bitcoin's off-by-one bug)
              (when (null stack)
                (return-from do-checkmultisig-stack-op (values :underflow nil)))
              (let ((dummy (coalton-vec-to-array (car stack)))
                    (stack (cdr stack)))

                ;; Verify the multisig
                (let ((result (verify-checkmultisig-for-script sigs pubkeys script-pubkey dummy)))
                  ;; Check if there was a validation error (STRICTENC/NULLDUMMY)
                  (if *last-checkmultisig-error*
                      (values :error nil)
                      ;; Push result: true (1) or false (empty)
                      ;; Convert to Coalton vector format for the stack
                      (let ((result-vec (if result
                                            (cl-array-to-coalton-vector
                                             (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))
                                            (cl-array-to-coalton-vector
                                             (make-array 0 :element-type '(unsigned-byte 8))))))
                        (values (if result :ok :fail)
                                (cons result-vec stack)))))))))))))

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
