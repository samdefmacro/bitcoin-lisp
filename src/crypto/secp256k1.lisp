(in-package #:bitcoin-lisp.crypto)

;;; secp256k1 ECDSA bindings via CFFI
;;;
;;; This provides bindings to libsecp256k1 for:
;;; - Public key parsing and validation
;;; - ECDSA signature verification
;;;
;;; libsecp256k1 must be installed on the system.

(cffi:define-foreign-library libsecp256k1
  (:darwin (:or "/opt/homebrew/lib/libsecp256k1.dylib"
                "/usr/local/lib/libsecp256k1.dylib"
                "libsecp256k1.dylib"
                "libsecp256k1.1.dylib"))
  (:unix (:or "libsecp256k1.so.1" "libsecp256k1.so"))
  (t (:default "libsecp256k1")))

(defvar *secp256k1-context* nil
  "The secp256k1 context used for verification operations.")

;;; Constants
(defconstant +secp256k1-context-verify+ #x0101)
(defconstant +secp256k1-context-sign+ #x0201)
(defconstant +secp256k1-pubkey-size+ 64)
(defconstant +secp256k1-signature-size+ 64)

;;; Foreign function definitions

(cffi:defcfun ("secp256k1_context_create" secp256k1-context-create) :pointer
  (flags :uint))

(cffi:defcfun ("secp256k1_context_destroy" secp256k1-context-destroy) :void
  (ctx :pointer))

(cffi:defcfun ("secp256k1_ec_pubkey_parse" secp256k1-ec-pubkey-parse) :int
  (ctx :pointer)
  (pubkey :pointer)
  (input :pointer)
  (inputlen :size))

(cffi:defcfun ("secp256k1_ecdsa_signature_parse_der" secp256k1-ecdsa-signature-parse-der) :int
  (ctx :pointer)
  (sig :pointer)
  (input :pointer)
  (inputlen :size))

(cffi:defcfun ("secp256k1_ecdsa_verify" secp256k1-ecdsa-verify) :int
  (ctx :pointer)
  (sig :pointer)
  (msghash32 :pointer)
  (pubkey :pointer))

;;; Context management

(defun ensure-secp256k1-loaded ()
  "Ensure libsecp256k1 is loaded and context is initialized."
  (unless *secp256k1-context*
    (cffi:load-foreign-library 'libsecp256k1)
    (setf *secp256k1-context*
          (secp256k1-context-create +secp256k1-context-verify+)))
  *secp256k1-context*)

(defun cleanup-secp256k1 ()
  "Clean up secp256k1 context. Call on shutdown."
  (when *secp256k1-context*
    (secp256k1-context-destroy *secp256k1-context*)
    (setf *secp256k1-context* nil)))

;;; Public key operations

(defun parse-public-key (pubkey-bytes)
  "Parse a public key from bytes.
PUBKEY-BYTES should be either:
- 33 bytes (compressed, prefix 0x02 or 0x03)
- 65 bytes (uncompressed, prefix 0x04)
Returns an internal public key structure, or NIL if invalid."
  (ensure-secp256k1-loaded)
  (let ((len (length pubkey-bytes)))
    (unless (or (= len 33) (= len 65))
      (return-from parse-public-key nil))
    (cffi:with-foreign-objects ((pubkey :uint8 +secp256k1-pubkey-size+)
                                 (input :uint8 len))
      ;; Copy input bytes
      (loop for i from 0 below len
            do (setf (cffi:mem-aref input :uint8 i) (aref pubkey-bytes i)))
      ;; Parse
      (let ((result (secp256k1-ec-pubkey-parse *secp256k1-context*
                                                pubkey
                                                input
                                                len)))
        (when (= result 1)
          ;; Return copy of parsed pubkey
          (let ((parsed (make-array +secp256k1-pubkey-size+
                                    :element-type '(unsigned-byte 8))))
            (loop for i from 0 below +secp256k1-pubkey-size+
                  do (setf (aref parsed i) (cffi:mem-aref pubkey :uint8 i)))
            parsed))))))

(defun public-key-valid-p (pubkey-bytes)
  "Check if PUBKEY-BYTES represents a valid secp256k1 public key."
  (not (null (parse-public-key pubkey-bytes))))

;;; Lax DER signature parsing
;;;
;;; Bitcoin's pre-DERSIG signatures could have various encoding issues:
;;; - Extra padding bytes in R or S
;;; - Missing leading zeros for negative numbers
;;; - Wrong length indicators
;;;
;;; This lax parser extracts R and S values tolerantly and re-encodes them.

(defun parse-der-integer-lax (bytes pos)
  "Parse an integer from DER-ish encoding, starting at POS.
   Returns (values integer new-pos) or (values nil nil) on error.
   Tolerates extra padding and missing sign bytes."
  (when (>= pos (length bytes))
    (return-from parse-der-integer-lax (values nil nil)))
  ;; Expect 0x02 (INTEGER tag)
  (unless (= (aref bytes pos) #x02)
    (return-from parse-der-integer-lax (values nil nil)))
  (incf pos)
  (when (>= pos (length bytes))
    (return-from parse-der-integer-lax (values nil nil)))
  ;; Get length
  (let ((len (aref bytes pos)))
    (incf pos)
    (when (or (zerop len) (> (+ pos len) (length bytes)))
      (return-from parse-der-integer-lax (values nil nil)))
    ;; Extract bytes, stripping leading zeros (but keep at least 1 byte)
    (let ((start pos)
          (end (+ pos len)))
      ;; Skip leading zeros (except the last byte)
      (loop while (and (< start (1- end))
                       (zerop (aref bytes start))
                       ;; But keep a zero if next byte has high bit set
                       (zerop (logand (aref bytes (1+ start)) #x80)))
            do (incf start))
      ;; Convert to integer
      (let ((result 0))
        (loop for i from start below end
              do (setf result (logior (ash result 8) (aref bytes i))))
        (values result end)))))

(defun integer-to-bytes-be (n byte-count)
  "Convert integer N to big-endian byte array of BYTE-COUNT bytes."
  (let ((result (make-array byte-count :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from (1- byte-count) downto 0
          for shift from 0 by 8
          do (setf (aref result i) (logand (ash n (- shift)) #xff)))
    result))

(defun normalize-signature-lax (der-sig)
  "Parse a lax DER signature and return a 64-byte compact signature (r||s).
   Returns NIL if parsing fails."
  (when (< (length der-sig) 8)
    (return-from normalize-signature-lax nil))
  ;; Expect SEQUENCE tag
  (unless (= (aref der-sig 0) #x30)
    (return-from normalize-signature-lax nil))
  ;; Get sequence length (may not match actual content in lax mode)
  (let ((pos 2))  ; Skip tag and length
    ;; Handle extended length encoding
    (when (> (aref der-sig 1) #x80)
      (let ((len-bytes (logand (aref der-sig 1) #x7f)))
        (setf pos (+ 2 len-bytes))))
    ;; Parse R
    (multiple-value-bind (r new-pos)
        (parse-der-integer-lax der-sig pos)
      (unless r
        (return-from normalize-signature-lax nil))
      ;; Parse S
      (multiple-value-bind (s final-pos)
          (parse-der-integer-lax der-sig new-pos)
        (declare (ignore final-pos))
        (unless s
          (return-from normalize-signature-lax nil))
        ;; Convert R and S to 32-byte big-endian
        (let ((r-bytes (integer-to-bytes-be r 32))
              (s-bytes (integer-to-bytes-be s 32)))
          ;; Concatenate for 64-byte compact format
          (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
            (loop for i from 0 below 32
                  do (setf (aref result i) (aref r-bytes i))
                  do (setf (aref result (+ i 32)) (aref s-bytes i)))
            result))))))

;;; Compact signature parsing (for secp256k1)

(cffi:defcfun ("secp256k1_ecdsa_signature_parse_compact" secp256k1-ecdsa-signature-parse-compact) :int
  (ctx :pointer)
  (sig :pointer)
  (input64 :pointer))

;;; Signature normalization (convert high-S to low-S)
;;; libsecp256k1's verify function requires normalized (low-S) signatures.
;;; Bitcoin Core normalizes signatures internally during verification.

(cffi:defcfun ("secp256k1_ecdsa_signature_normalize" secp256k1-ecdsa-signature-normalize) :int
  (ctx :pointer)
  (sigout :pointer)
  (sigin :pointer))

;;; ============================================================
;;; Schnorr Signatures (BIP 340)
;;; ============================================================

;;; Constants for x-only pubkeys
(defconstant +secp256k1-xonly-pubkey-size+ 64
  "Internal size of an x-only pubkey structure (same as regular pubkey).")

;;; Foreign function definitions for Schnorr

(cffi:defcfun ("secp256k1_xonly_pubkey_parse" secp256k1-xonly-pubkey-parse) :int
  "Parse a 32-byte x-only public key.
   Returns 1 on success, 0 on failure."
  (ctx :pointer)
  (pubkey :pointer)     ; Output: internal pubkey structure (64 bytes)
  (input32 :pointer))   ; Input: 32 bytes x-coordinate

(cffi:defcfun ("secp256k1_xonly_pubkey_serialize" secp256k1-xonly-pubkey-serialize) :int
  "Serialize an x-only pubkey to 32 bytes.
   Returns 1 always."
  (ctx :pointer)
  (output32 :pointer)   ; Output: 32 bytes
  (pubkey :pointer))    ; Input: internal pubkey structure

(cffi:defcfun ("secp256k1_xonly_pubkey_from_pubkey" secp256k1-xonly-pubkey-from-pubkey) :int
  "Convert a regular pubkey to an x-only pubkey.
   Returns 1 always. pk_parity is set to the parity of the Y coordinate."
  (ctx :pointer)
  (xonly_pubkey :pointer)  ; Output: x-only pubkey structure
  (pk_parity :pointer)     ; Output: int* for Y parity (0=even, 1=odd), can be NULL
  (pubkey :pointer))       ; Input: regular pubkey structure

(cffi:defcfun ("secp256k1_xonly_pubkey_tweak_add" secp256k1-xonly-pubkey-tweak-add) :int
  "Tweak an x-only public key by adding tweak*G.
   Returns 1 on success, 0 if the tweak is invalid."
  (ctx :pointer)
  (output_pubkey :pointer)    ; Output: regular pubkey structure (tweaked key may have odd Y)
  (internal_pubkey :pointer)  ; Input: x-only pubkey to tweak
  (tweak32 :pointer))         ; Input: 32-byte tweak

(cffi:defcfun ("secp256k1_xonly_pubkey_tweak_add_check" secp256k1-xonly-pubkey-tweak-add-check) :int
  "Verify that output_pubkey = x-only(internal_pubkey + tweak*G) with expected parity.
   Returns 1 if valid, 0 otherwise."
  (ctx :pointer)
  (tweaked_pubkey32 :pointer)   ; Input: 32-byte serialized tweaked pubkey
  (tweaked_pk_parity :int)      ; Input: expected parity (0 or 1)
  (internal_pubkey :pointer)    ; Input: x-only pubkey structure
  (tweak32 :pointer))           ; Input: 32-byte tweak

(cffi:defcfun ("secp256k1_schnorrsig_verify" secp256k1-schnorrsig-verify) :int
  "Verify a Schnorr signature (BIP 340).
   Returns 1 if valid, 0 if invalid."
  (ctx :pointer)
  (sig64 :pointer)      ; 64-byte signature
  (msg :pointer)        ; Message bytes
  (msglen :size)        ; Message length (typically 32 for hash)
  (pubkey :pointer))    ; x-only pubkey structure

;;; X-only public key operations

(defun parse-xonly-pubkey (pubkey32)
  "Parse a 32-byte x-only public key.
   Returns internal pubkey structure (64 bytes), or NIL if invalid."
  (ensure-secp256k1-loaded)
  (unless (= (length pubkey32) 32)
    (return-from parse-xonly-pubkey nil))
  (cffi:with-foreign-objects ((pubkey :uint8 +secp256k1-xonly-pubkey-size+)
                               (input :uint8 32))
    ;; Copy input bytes
    (loop for i from 0 below 32
          do (setf (cffi:mem-aref input :uint8 i) (aref pubkey32 i)))
    ;; Parse
    (let ((result (secp256k1-xonly-pubkey-parse *secp256k1-context* pubkey input)))
      (when (= result 1)
        ;; Return copy of parsed pubkey structure
        (let ((parsed (make-array +secp256k1-xonly-pubkey-size+
                                  :element-type '(unsigned-byte 8))))
          (loop for i from 0 below +secp256k1-xonly-pubkey-size+
                do (setf (aref parsed i) (cffi:mem-aref pubkey :uint8 i)))
          parsed)))))

(defun xonly-pubkey-valid-p (pubkey32)
  "Check if 32 bytes represent a valid x-only public key (point on curve)."
  (not (null (parse-xonly-pubkey pubkey32))))

(defun tweak-xonly-pubkey (xonly-pubkey32 tweak32)
  "Tweak an x-only public key: output = internal_pubkey + tweak*G.
   Returns (values tweaked-pubkey32 parity) where:
   - tweaked-pubkey32 is the 32-byte x-coordinate of the result
   - parity is 0 if Y is even, 1 if Y is odd
   Returns (values nil nil) on failure."
  (ensure-secp256k1-loaded)
  (let ((internal-pubkey (parse-xonly-pubkey xonly-pubkey32)))
    (unless internal-pubkey
      (return-from tweak-xonly-pubkey (values nil nil))))
  (cffi:with-foreign-objects ((output-pubkey :uint8 +secp256k1-pubkey-size+)
                               (internal :uint8 +secp256k1-xonly-pubkey-size+)
                               (tweak :uint8 32)
                               (output32 :uint8 32)
                               (parity :int))
    ;; Copy internal pubkey
    (let ((parsed (parse-xonly-pubkey xonly-pubkey32)))
      (loop for i from 0 below +secp256k1-xonly-pubkey-size+
            do (setf (cffi:mem-aref internal :uint8 i) (aref parsed i))))
    ;; Copy tweak
    (loop for i from 0 below 32
          do (setf (cffi:mem-aref tweak :uint8 i) (aref tweak32 i)))
    ;; Perform tweak
    (let ((result (secp256k1-xonly-pubkey-tweak-add
                   *secp256k1-context*
                   output-pubkey
                   internal
                   tweak)))
      (unless (= result 1)
        (return-from tweak-xonly-pubkey (values nil nil)))
      ;; Convert output to x-only and serialize
      (cffi:with-foreign-objects ((output-xonly :uint8 +secp256k1-xonly-pubkey-size+))
        (secp256k1-xonly-pubkey-from-pubkey
         *secp256k1-context*
         output-xonly
         parity
         output-pubkey)
        (secp256k1-xonly-pubkey-serialize
         *secp256k1-context*
         output32
         output-xonly)
        ;; Copy result
        (let ((result-bytes (make-array 32 :element-type '(unsigned-byte 8))))
          (loop for i from 0 below 32
                do (setf (aref result-bytes i) (cffi:mem-aref output32 :uint8 i)))
          (values result-bytes (cffi:mem-ref parity :int)))))))

(defun verify-xonly-tweak (tweaked-pubkey32 tweaked-parity internal-pubkey32 tweak32)
  "Verify that tweaked-pubkey32 = x-only(internal-pubkey32 + tweak32*G).
   Returns T if valid, NIL otherwise."
  (ensure-secp256k1-loaded)
  (let ((internal-parsed (parse-xonly-pubkey internal-pubkey32)))
    (unless internal-parsed
      (return-from verify-xonly-tweak nil)))
  (cffi:with-foreign-objects ((tweaked :uint8 32)
                               (internal :uint8 +secp256k1-xonly-pubkey-size+)
                               (tweak :uint8 32))
    ;; Copy tweaked pubkey
    (loop for i from 0 below 32
          do (setf (cffi:mem-aref tweaked :uint8 i) (aref tweaked-pubkey32 i)))
    ;; Copy internal pubkey
    (let ((parsed (parse-xonly-pubkey internal-pubkey32)))
      (loop for i from 0 below +secp256k1-xonly-pubkey-size+
            do (setf (cffi:mem-aref internal :uint8 i) (aref parsed i))))
    ;; Copy tweak
    (loop for i from 0 below 32
          do (setf (cffi:mem-aref tweak :uint8 i) (aref tweak32 i)))
    ;; Verify
    (= 1 (secp256k1-xonly-pubkey-tweak-add-check
          *secp256k1-context*
          tweaked
          tweaked-parity
          internal
          tweak))))

;;; Schnorr signature verification

(defun verify-schnorr-signature (message-hash signature64 xonly-pubkey32)
  "Verify a BIP 340 Schnorr signature.
   MESSAGE-HASH: 32-byte hash of the message
   SIGNATURE64: 64-byte Schnorr signature (r || s)
   XONLY-PUBKEY32: 32-byte x-only public key
   Returns T if valid, NIL if invalid."
  (ensure-secp256k1-loaded)
  ;; Validate sizes
  (unless (= (length message-hash) 32)
    (return-from verify-schnorr-signature nil))
  (unless (= (length signature64) 64)
    (return-from verify-schnorr-signature nil))
  (unless (= (length xonly-pubkey32) 32)
    (return-from verify-schnorr-signature nil))
  ;; Parse the x-only pubkey
  (let ((parsed-pubkey (parse-xonly-pubkey xonly-pubkey32)))
    (unless parsed-pubkey
      (return-from verify-schnorr-signature nil))
    (cffi:with-foreign-objects ((sig :uint8 64)
                                 (msg :uint8 32)
                                 (pubkey :uint8 +secp256k1-xonly-pubkey-size+))
      ;; Copy signature
      (loop for i from 0 below 64
            do (setf (cffi:mem-aref sig :uint8 i) (aref signature64 i)))
      ;; Copy message hash
      (loop for i from 0 below 32
            do (setf (cffi:mem-aref msg :uint8 i) (aref message-hash i)))
      ;; Copy parsed pubkey
      (loop for i from 0 below +secp256k1-xonly-pubkey-size+
            do (setf (cffi:mem-aref pubkey :uint8 i) (aref parsed-pubkey i)))
      ;; Verify
      (= 1 (secp256k1-schnorrsig-verify
            *secp256k1-context*
            sig
            msg
            32  ; message length
            pubkey)))))

;;; Signature verification (ECDSA)

(defun verify-signature (message-hash signature pubkey-bytes &key strict low-s)
  "Verify an ECDSA signature.
MESSAGE-HASH: 32-byte hash of the message
SIGNATURE: DER-encoded signature bytes
PUBKEY-BYTES: 33 or 65 byte public key
STRICT: if T, use strict DER parsing (for DERSIG flag); otherwise use lax parsing
LOW-S: if T, reject high-S signatures (return :high-s as second value)
Returns (values result status) where:
  - result is T if valid, NIL if verification failed
  - status is T if OK, NIL if DER parsing failed, :HIGH-S if signature has high-S and LOW-S is set
When strict=T and DER parsing fails, returns (values nil nil).
When strict=NIL, parse-ok is always T (lax mode never fails on format).
When low-s=T and signature has high-S, returns (values nil :high-s)."
  (ensure-secp256k1-loaded)
  (unless (= (length message-hash) 32)
    (return-from verify-signature (values nil t)))  ; parse ok, verification failed
  (let ((parsed-pubkey (parse-public-key pubkey-bytes)))
    (unless parsed-pubkey
      (return-from verify-signature (values nil t)))  ; parse ok, verification failed
    (cffi:with-foreign-objects ((sig :uint8 +secp256k1-signature-size+)
                                 (msghash :uint8 32)
                                 (pubkey :uint8 +secp256k1-pubkey-size+)
                                 (sig-input :uint8 (max 64 (length signature))))
      ;; Copy message hash
      (loop for i from 0 below 32
            do (setf (cffi:mem-aref msghash :uint8 i) (aref message-hash i)))
      ;; Copy parsed pubkey
      (loop for i from 0 below +secp256k1-pubkey-size+
            do (setf (cffi:mem-aref pubkey :uint8 i) (aref parsed-pubkey i)))

      ;; Parse signature
      (let ((parse-result
              (if strict
                  ;; Strict DER parsing
                  (progn
                    (loop for i from 0 below (length signature)
                          do (setf (cffi:mem-aref sig-input :uint8 i) (aref signature i)))
                    (secp256k1-ecdsa-signature-parse-der
                     *secp256k1-context*
                     sig
                     sig-input
                     (length signature)))
                  ;; Lax parsing - normalize then use compact format
                  (let ((compact (normalize-signature-lax signature)))
                    (if compact
                        (progn
                          (loop for i from 0 below 64
                                do (setf (cffi:mem-aref sig-input :uint8 i) (aref compact i)))
                          (secp256k1-ecdsa-signature-parse-compact
                           *secp256k1-context*
                           sig
                           sig-input))
                        0)))))  ; Return 0 (failure) if lax parse failed
        (unless (= parse-result 1)
          ;; Signature parsing failed
          ;; In strict mode, report DER parse failure; in lax mode, just verification failure
          (return-from verify-signature (values nil (not strict))))
        ;; Normalize signature (convert high-S to low-S if needed)
        ;; libsecp256k1's verify function requires normalized signatures.
        ;; Note: sigout can be same as sigin for in-place normalization.
        ;; Returns 1 if signature was modified (had high-S), 0 if already low-S.
        (let ((was-high-s (= 1 (secp256k1-ecdsa-signature-normalize *secp256k1-context* sig sig))))
          ;; If LOW_S flag is set and signature had high-S, reject it
          (when (and low-s was-high-s)
            (return-from verify-signature (values nil :high-s)))
          ;; Verify
          (let ((verify-result (secp256k1-ecdsa-verify
                                *secp256k1-context*
                                sig
                                msghash
                                pubkey)))
            (values (= verify-result 1) t)))))))
