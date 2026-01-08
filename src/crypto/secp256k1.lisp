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

;;; Signature verification

(defun verify-signature (message-hash signature pubkey-bytes)
  "Verify an ECDSA signature.
MESSAGE-HASH: 32-byte hash of the message
SIGNATURE: DER-encoded signature bytes
PUBKEY-BYTES: 33 or 65 byte public key
Returns T if valid, NIL otherwise."
  (ensure-secp256k1-loaded)
  (unless (= (length message-hash) 32)
    (return-from verify-signature nil))
  (let ((parsed-pubkey (parse-public-key pubkey-bytes)))
    (unless parsed-pubkey
      (return-from verify-signature nil))
    (cffi:with-foreign-objects ((sig :uint8 +secp256k1-signature-size+)
                                 (msghash :uint8 32)
                                 (pubkey :uint8 +secp256k1-pubkey-size+)
                                 (der-sig :uint8 (length signature)))
      ;; Copy message hash
      (loop for i from 0 below 32
            do (setf (cffi:mem-aref msghash :uint8 i) (aref message-hash i)))
      ;; Copy parsed pubkey
      (loop for i from 0 below +secp256k1-pubkey-size+
            do (setf (cffi:mem-aref pubkey :uint8 i) (aref parsed-pubkey i)))
      ;; Copy DER signature
      (loop for i from 0 below (length signature)
            do (setf (cffi:mem-aref der-sig :uint8 i) (aref signature i)))
      ;; Parse DER signature
      (let ((parse-result (secp256k1-ecdsa-signature-parse-der
                           *secp256k1-context*
                           sig
                           der-sig
                           (length signature))))
        (unless (= parse-result 1)
          (return-from verify-signature nil))
        ;; Verify
        (let ((verify-result (secp256k1-ecdsa-verify
                              *secp256k1-context*
                              sig
                              msghash
                              pubkey)))
          (= verify-result 1))))))
