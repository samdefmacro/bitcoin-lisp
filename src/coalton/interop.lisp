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
   ;; Script flags
   #:set-script-flags
   #:flag-enabled-p
   ;; Signature verification
   #:verify-checksig
   #:verify-checksig-for-script
   #:last-checksig-had-strictenc-error-p))

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

(defun verify-checksig (sig-bytes pubkey-bytes script-pubkey)
  "Verify a CHECKSIG operation using Bitcoin Core test transaction format.
   When STRICTENC flag is set in *script-flags*, validates encoding."
  (when (or (zerop (length sig-bytes))
            (zerop (length pubkey-bytes)))
    (return-from verify-checksig (values nil nil)))

  ;; Extract sighash type from signature (last byte)
  (let* ((sighash-type (aref sig-bytes (1- (length sig-bytes))))
         (der-sig (subseq sig-bytes 0 (1- (length sig-bytes)))))

    ;; STRICTENC validation when flag is enabled
    (when (flag-enabled-p "STRICTENC")
      (unless (valid-sighash-type-p sighash-type)
        (return-from verify-checksig (values nil :sig-hashtype)))
      (unless (valid-pubkey-format-p pubkey-bytes)
        (return-from verify-checksig (values nil :pubkeytype))))

    ;; Compute sighash and verify
    (let ((sighash (compute-test-sighash script-pubkey sighash-type)))
      (bitcoin-lisp.crypto:verify-signature sighash der-sig pubkey-bytes))))

(defvar *last-checksig-error* nil
  "Set to error keyword (:sig-hashtype, :pubkeytype) if STRICTENC validation failed.")

(defun verify-checksig-for-script (sig-bytes pubkey-bytes script-pubkey)
  "Wrapper for verify-checksig that sets *last-checksig-error* on STRICTENC failures.
   Returns T for success, NIL for any failure."
  (setf *last-checksig-error* nil)
  (multiple-value-bind (result error-type)
      (verify-checksig sig-bytes pubkey-bytes script-pubkey)
    (when error-type
      (setf *last-checksig-error* error-type))
    result))

(defun last-checksig-had-strictenc-error-p ()
  "Returns T if the last checksig had a STRICTENC validation error."
  (not (null *last-checksig-error*)))
