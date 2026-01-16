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

;;; Signature verification

(defun verify-signature (message-hash signature pubkey-bytes &key strict)
  "Verify an ECDSA signature.
MESSAGE-HASH: 32-byte hash of the message
SIGNATURE: DER-encoded signature bytes
PUBKEY-BYTES: 33 or 65 byte public key
STRICT: if T, use strict DER parsing (for DERSIG flag); otherwise use lax parsing
Returns (values result parse-ok) where:
  - result is T if valid, NIL if verification failed
  - parse-ok is T if signature parsed successfully, NIL if DER parsing failed
When strict=T and DER parsing fails, returns (values nil nil).
When strict=NIL, parse-ok is always T (lax mode never fails on format)."
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
        ;; Verify
        (let ((verify-result (secp256k1-ecdsa-verify
                              *secp256k1-context*
                              sig
                              msghash
                              pubkey)))
          (values (= verify-result 1) t))))))
