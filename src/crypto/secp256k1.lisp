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
;; secp256k1_ec_pubkey_serialize flags
(defconstant +secp256k1-ec-compressed+ #x0102)
(defconstant +secp256k1-ec-uncompressed+ #x0002)

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

;;; Signing bindings (private key -> public key / signature)

(cffi:defcfun ("secp256k1_ec_seckey_verify" secp256k1-ec-seckey-verify) :int
  (ctx :pointer)
  (seckey :pointer))

(cffi:defcfun ("secp256k1_ec_pubkey_create" secp256k1-ec-pubkey-create) :int
  (ctx :pointer)
  (pubkey :pointer)
  (seckey :pointer))

(cffi:defcfun ("secp256k1_ec_pubkey_serialize" secp256k1-ec-pubkey-serialize) :int
  (ctx :pointer)
  (output :pointer)
  (outputlen :pointer)
  (pubkey :pointer)
  (flags :uint))

(cffi:defcfun ("secp256k1_ecdsa_sign" secp256k1-ecdsa-sign) :int
  (ctx :pointer)
  (sig :pointer)
  (msghash32 :pointer)
  (seckey :pointer)
  (noncefp :pointer)
  (ndata :pointer))

(cffi:defcfun ("secp256k1_ecdsa_signature_serialize_der" secp256k1-ecdsa-signature-serialize-der) :int
  (ctx :pointer)
  (output :pointer)
  (outputlen :pointer)
  (sig :pointer))

;;; Recoverable signatures (BIP137 message signing) — libsecp recovery module.

(cffi:defcfun ("secp256k1_ecdsa_sign_recoverable" secp256k1-ecdsa-sign-recoverable) :int
  (ctx :pointer)
  (sig :pointer)
  (msghash32 :pointer)
  (seckey :pointer)
  (noncefp :pointer)
  (ndata :pointer))

(cffi:defcfun ("secp256k1_ecdsa_recoverable_signature_serialize_compact"
               secp256k1-ecdsa-recoverable-signature-serialize-compact) :int
  (ctx :pointer)
  (output64 :pointer)
  (recid :pointer)
  (sig :pointer))

(cffi:defcfun ("secp256k1_ecdsa_recoverable_signature_parse_compact"
               secp256k1-ecdsa-recoverable-signature-parse-compact) :int
  (ctx :pointer)
  (sig :pointer)
  (input64 :pointer)
  (recid :int))

(cffi:defcfun ("secp256k1_ecdsa_recover" secp256k1-ecdsa-recover) :int
  (ctx :pointer)
  (pubkey :pointer)
  (sig :pointer)
  (msghash32 :pointer))

(cffi:defcfun ("secp256k1_ec_pubkey_tweak_add" secp256k1-ec-pubkey-tweak-add) :int
  (ctx :pointer)
  (pubkey :pointer)
  (tweak32 :pointer))

;; BIP 340 tagged hash: hash32 = SHA256(SHA256(tag) || SHA256(tag) || msg).
;; Internally caches/reuses the SHA256 midstate after feeding the tag prefix
;; once, so repeated calls with the same tag avoid the 64-byte tag-prefix
;; compression. Public symbol; preferred over hand-rolled tagged-hash.
(cffi:defcfun ("secp256k1_tagged_sha256" secp256k1-tagged-sha256) :int
  (ctx :pointer)
  (hash32 :pointer)
  (tag :pointer)
  (taglen :size)
  (msg :pointer)
  (msglen :size))

;;; Context management

(defun ensure-secp256k1-loaded ()
  "Ensure libsecp256k1 is loaded and context is initialized."
  (unless *secp256k1-context*
    (cffi:load-foreign-library 'libsecp256k1)
    ;; Both VERIFY and SIGN capabilities — modern libsecp256k1 treats these
    ;; legacy flags as no-ops (one context does everything), but older builds
    ;; need SIGN for secp256k1_ecdsa_sign / ec_pubkey_create.
    (setf *secp256k1-context*
          (secp256k1-context-create
           (logior +secp256k1-context-verify+ +secp256k1-context-sign+))))
  *secp256k1-context*)

;; Override hash.lisp's tagged-hash with a libsecp256k1-backed version.
;; libsecp's secp256k1_tagged_sha256 keeps the SHA256 midstate after feeding
;; the tag prefix internally, so repeated calls with the same tag skip a
;; full 64-byte tag-prefix compression — meaningful for Taproot hot paths
;; (TapLeaf, TapSighash, TapBranch, TapTweak) called per-input on every
;; tapscript spend.
(defun tagged-hash (tag data)
  "Compute BIP 340 tagged hash via libsecp256k1's secp256k1_tagged_sha256.
   TAG is a string; DATA is a byte vector. Returns a 32-byte vector."
  (declare (type string tag)
           (optimize (speed 3) (safety 1)))
  (ensure-secp256k1-loaded)
  (let* ((tag-octets (flexi-streams:string-to-octets tag :external-format :utf-8))
         (data-octets (if (typep data '(simple-array (unsigned-byte 8) (*)))
                          data
                          (coerce data '(simple-array (unsigned-byte 8) (*)))))
         (taglen (length tag-octets))
         (msglen (length data-octets))
         (out (make-array 32 :element-type '(unsigned-byte 8))))
    (declare (type (simple-array (unsigned-byte 8) (*)) tag-octets data-octets)
             (type (simple-array (unsigned-byte 8) (32)) out))
    (cffi:with-pointer-to-vector-data (tag-ptr tag-octets)
      (cffi:with-pointer-to-vector-data (msg-ptr data-octets)
        (cffi:with-pointer-to-vector-data (out-ptr out)
          (let ((rc (secp256k1-tagged-sha256
                     *secp256k1-context*
                     out-ptr tag-ptr taglen msg-ptr msglen)))
            (unless (= rc 1)
              (error "secp256k1_tagged_sha256 returned ~A" rc))))))
    out))

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

;;; Signing operations (private key -> public key / signature)

(defun valid-private-key-p (privkey)
  "T if PRIVKEY is a 32-byte vector that is a valid secp256k1 secret key
(in range [1, n-1])."
  (ensure-secp256k1-loaded)
  (and (= (length privkey) 32)
       (cffi:with-foreign-object (sk :uint8 32)
         (loop for i below 32 do (setf (cffi:mem-aref sk :uint8 i) (aref privkey i)))
         (= 1 (secp256k1-ec-seckey-verify *secp256k1-context* sk)))))

(defun derive-public-key (privkey &key (compressed t))
  "Serialized public key for the 32-byte secret PRIVKEY: 33 bytes compressed
(default) or 65 uncompressed. Errors if PRIVKEY is not a valid secret key."
  (ensure-secp256k1-loaded)
  (unless (= (length privkey) 32)
    (error "private key must be 32 bytes"))
  (cffi:with-foreign-objects ((sk :uint8 32)
                              (pk :uint8 +secp256k1-pubkey-size+)
                              (out :uint8 65)
                              (outlen :size))
    (loop for i below 32 do (setf (cffi:mem-aref sk :uint8 i) (aref privkey i)))
    (unless (= 1 (secp256k1-ec-pubkey-create *secp256k1-context* pk sk))
      (error "invalid private key"))
    (let ((len (if compressed 33 65)))
      (setf (cffi:mem-ref outlen :size) len)
      (unless (= 1 (secp256k1-ec-pubkey-serialize
                    *secp256k1-context* out outlen pk
                    (if compressed +secp256k1-ec-compressed+ +secp256k1-ec-uncompressed+)))
        (error "public key serialization failed"))
      (let* ((n (cffi:mem-ref outlen :size))
             (result (make-array n :element-type '(unsigned-byte 8))))
        (loop for i below n do (setf (aref result i) (cffi:mem-aref out :uint8 i)))
        result))))

(defun tweak-add-public-key (pubkey-bytes tweak32)
  "EC point addition: PUBKEY-BYTES + TWEAK32*G, returned as a 33-byte compressed
public key, or NIL if the result is invalid (point at infinity / tweak out of
range). Used for BIP32 CKDpub (child pubkey = Kpar + IL*G)."
  (ensure-secp256k1-loaded)
  (let ((pk (parse-public-key pubkey-bytes)))
    (when (and pk (= (length tweak32) 32))
      (cffi:with-foreign-objects ((pkobj :uint8 +secp256k1-pubkey-size+)
                                  (tw :uint8 32)
                                  (out :uint8 65)
                                  (outlen :size))
        (loop for i below +secp256k1-pubkey-size+
              do (setf (cffi:mem-aref pkobj :uint8 i) (aref pk i)))
        (loop for i below 32 do (setf (cffi:mem-aref tw :uint8 i) (aref tweak32 i)))
        (when (= 1 (secp256k1-ec-pubkey-tweak-add *secp256k1-context* pkobj tw))
          (setf (cffi:mem-ref outlen :size) 33)
          (when (= 1 (secp256k1-ec-pubkey-serialize
                      *secp256k1-context* out outlen pkobj +secp256k1-ec-compressed+))
            (let ((result (make-array 33 :element-type '(unsigned-byte 8))))
              (loop for i below 33 do (setf (aref result i) (cffi:mem-aref out :uint8 i)))
              result)))))))

(defun sign-ecdsa (privkey hash32)
  "DER-encoded ECDSA signature of the 32-byte HASH32 under the 32-byte secret
PRIVKEY, using libsecp256k1's RFC6979 deterministic nonce (low-S, like Core).
Returns the DER signature bytes. Errors if PRIVKEY is invalid."
  (ensure-secp256k1-loaded)
  (unless (= (length hash32) 32) (error "message hash must be 32 bytes"))
  (unless (= (length privkey) 32) (error "private key must be 32 bytes"))
  (cffi:with-foreign-objects ((sk :uint8 32)
                              (msg :uint8 32)
                              (sig :uint8 +secp256k1-signature-size+)
                              (der :uint8 72)
                              (derlen :size))
    (loop for i below 32 do (setf (cffi:mem-aref sk :uint8 i) (aref privkey i)))
    (loop for i below 32 do (setf (cffi:mem-aref msg :uint8 i) (aref hash32 i)))
    (unless (= 1 (secp256k1-ecdsa-sign *secp256k1-context* sig msg sk
                                       (cffi:null-pointer) (cffi:null-pointer)))
      (error "ECDSA signing failed (invalid private key?)"))
    (setf (cffi:mem-ref derlen :size) 72)
    (unless (= 1 (secp256k1-ecdsa-signature-serialize-der
                  *secp256k1-context* der derlen sig))
      (error "DER signature serialization failed"))
    (let* ((n (cffi:mem-ref derlen :size))
           (result (make-array n :element-type '(unsigned-byte 8))))
      (loop for i below n do (setf (aref result i) (cffi:mem-aref der :uint8 i)))
      result)))

(defun sign-recoverable-compact (privkey hash32)
  "Recoverable ECDSA signature of HASH32 under the 32-byte secret PRIVKEY (RFC6979
nonce). Returns (VALUES compact-64-byte-vector recid) — the form used by Bitcoin
message signing (the caller prepends the 27+recid[+4] header byte)."
  (ensure-secp256k1-loaded)
  (unless (= (length hash32) 32) (error "message hash must be 32 bytes"))
  (unless (= (length privkey) 32) (error "private key must be 32 bytes"))
  (cffi:with-foreign-objects ((sk :uint8 32)
                              (msg :uint8 32)
                              (rsig :uint8 65)
                              (out :uint8 64)
                              (recid :int))
    (loop for i below 32 do (setf (cffi:mem-aref sk :uint8 i) (aref privkey i)))
    (loop for i below 32 do (setf (cffi:mem-aref msg :uint8 i) (aref hash32 i)))
    (unless (= 1 (secp256k1-ecdsa-sign-recoverable
                  *secp256k1-context* rsig msg sk
                  (cffi:null-pointer) (cffi:null-pointer)))
      (error "recoverable ECDSA signing failed"))
    (unless (= 1 (secp256k1-ecdsa-recoverable-signature-serialize-compact
                  *secp256k1-context* out recid rsig))
      (error "recoverable signature serialization failed"))
    (let ((compact (make-array 64 :element-type '(unsigned-byte 8))))
      (loop for i below 64 do (setf (aref compact i) (cffi:mem-aref out :uint8 i)))
      (values compact (cffi:mem-ref recid :int)))))

(defun recover-public-key (compact64 recid hash32 &key (compressed t))
  "Recover the serialized public key that produced the COMPACT64 recoverable
signature over HASH32 with the given RECID (0-3). Returns the pubkey bytes
(33 compressed / 65 uncompressed), or NIL if recovery fails."
  (ensure-secp256k1-loaded)
  (when (and (= (length compact64) 64) (<= 0 recid 3) (= (length hash32) 32))
    (cffi:with-foreign-objects ((in :uint8 64)
                                (msg :uint8 32)
                                (rsig :uint8 65)
                                (pk :uint8 +secp256k1-pubkey-size+)
                                (out :uint8 65)
                                (outlen :size))
      (loop for i below 64 do (setf (cffi:mem-aref in :uint8 i) (aref compact64 i)))
      (loop for i below 32 do (setf (cffi:mem-aref msg :uint8 i) (aref hash32 i)))
      (when (and (= 1 (secp256k1-ecdsa-recoverable-signature-parse-compact
                       *secp256k1-context* rsig in recid))
                 (= 1 (secp256k1-ecdsa-recover *secp256k1-context* pk rsig msg)))
        (let ((len (if compressed 33 65)))
          (setf (cffi:mem-ref outlen :size) len)
          (when (= 1 (secp256k1-ec-pubkey-serialize
                      *secp256k1-context* out outlen pk
                      (if compressed +secp256k1-ec-compressed+ +secp256k1-ec-uncompressed+)))
            (let* ((n (cffi:mem-ref outlen :size))
                   (result (make-array n :element-type '(unsigned-byte 8))))
              (loop for i below n do (setf (aref result i) (cffi:mem-aref out :uint8 i)))
              result)))))))

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

(defconstant +secp256k1-keypair-size+ 96
  "Internal size of a secp256k1_keypair structure.")

(cffi:defcfun ("secp256k1_keypair_create" secp256k1-keypair-create) :int
  "Compute a keypair from a 32-byte secret key. Returns 1 on success, 0 if the
   secret key is invalid."
  (ctx :pointer)
  (keypair :pointer)   ; Output: 96-byte keypair structure
  (seckey32 :pointer)) ; Input: 32-byte secret key

(cffi:defcfun ("secp256k1_keypair_xonly_pub" secp256k1-keypair-xonly-pub) :int
  "Extract the x-only public key from a keypair. Returns 1 always."
  (ctx :pointer)
  (xonly_pubkey :pointer)  ; Output: x-only pubkey structure
  (pk_parity :pointer)     ; Output: int* parity, can be NULL
  (keypair :pointer))      ; Input: keypair structure

(cffi:defcfun ("secp256k1_schnorrsig_sign32" secp256k1-schnorrsig-sign32) :int
  "Create a BIP340 Schnorr signature of a 32-byte message. Returns 1 on success.
   AUX_RAND32 may be NULL (BIP340 recommends 32 random bytes; deterministic if
   zero/NULL)."
  (ctx :pointer)
  (sig64 :pointer)     ; Output: 64-byte signature
  (msg32 :pointer)     ; Input: 32-byte message
  (keypair :pointer)   ; Input: keypair structure
  (aux_rand32 :pointer)) ; Input: 32-byte aux randomness, or NULL

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
   Returns T if valid, NIL if invalid.

Hot path on tapscript-heavy blocks. The earlier code did
parse-xonly-pubkey (32 mem-aref + 64 mem-aref round trip into Lisp)
then verify-schnorr-signature (64 + 32 + 64 mem-aref into fresh foreign
buffers). ~256 mem-aref + 4 foreign-object allocations per verify.
Now: cffi:with-pointer-to-vector-data pins the input byte vectors in
place, the parsed pubkey lives in one foreign buffer that's reused
for the verify call. ~10x reduction in CFFI overhead."
  (declare (type (simple-array (unsigned-byte 8) (*)) message-hash signature64 xonly-pubkey32)
           (optimize (speed 3) (safety 1)))
  (ensure-secp256k1-loaded)
  (unless (= (length message-hash) 32)
    (return-from verify-schnorr-signature nil))
  (unless (= (length signature64) 64)
    (return-from verify-schnorr-signature nil))
  (unless (= (length xonly-pubkey32) 32)
    (return-from verify-schnorr-signature nil))
  ;; Allocate one foreign buffer for the parsed pubkey; pin all input
  ;; vectors via with-pointer-to-vector-data so no per-byte copies happen.
  (cffi:with-foreign-objects ((pubkey :uint8 +secp256k1-xonly-pubkey-size+))
    (cffi:with-pointer-to-vector-data (pk-input xonly-pubkey32)
      (when (zerop (secp256k1-xonly-pubkey-parse
                    *secp256k1-context* pubkey pk-input))
        (return-from verify-schnorr-signature nil)))
    (cffi:with-pointer-to-vector-data (sig-ptr signature64)
      (cffi:with-pointer-to-vector-data (msg-ptr message-hash)
        (= 1 (secp256k1-schnorrsig-verify
              *secp256k1-context* sig-ptr msg-ptr 32 pubkey))))))

;;; Schnorr signing (BIP 340)

(defun derive-xonly-pubkey (privkey)
  "The 32-byte x-only (BIP340) public key for the 32-byte secret PRIVKEY. Errors
if PRIVKEY is invalid."
  (ensure-secp256k1-loaded)
  (unless (= (length privkey) 32) (error "private key must be 32 bytes"))
  (cffi:with-foreign-objects ((keypair :uint8 +secp256k1-keypair-size+)
                              (xonly :uint8 +secp256k1-xonly-pubkey-size+)
                              (out :uint8 32))
    (cffi:with-pointer-to-vector-data (sk-ptr privkey)
      (unless (= 1 (secp256k1-keypair-create *secp256k1-context* keypair sk-ptr))
        (error "invalid private key")))
    (secp256k1-keypair-xonly-pub *secp256k1-context* xonly (cffi:null-pointer) keypair)
    (secp256k1-xonly-pubkey-serialize *secp256k1-context* out xonly)
    (let ((result (make-array 32 :element-type '(unsigned-byte 8))))
      (loop for i below 32 do (setf (aref result i) (cffi:mem-aref out :uint8 i)))
      result)))

(defun sign-schnorr (privkey hash32 &optional aux-rand32)
  "64-byte BIP340 Schnorr signature of the 32-byte HASH32 under the 32-byte secret
PRIVKEY. AUX-RAND32, if given, is 32 bytes of auxiliary randomness (BIP340
recommends fresh randomness; omitting it signs with all-zero aux, which is
deterministic and matches the BIP340 test vectors). Errors if PRIVKEY is invalid."
  (ensure-secp256k1-loaded)
  (unless (= (length privkey) 32) (error "private key must be 32 bytes"))
  (unless (= (length hash32) 32) (error "message hash must be 32 bytes"))
  (when (and aux-rand32 (/= (length aux-rand32) 32))
    (error "aux randomness must be 32 bytes"))
  (cffi:with-foreign-objects ((keypair :uint8 +secp256k1-keypair-size+)
                              (sig :uint8 64)
                              (aux :uint8 32))
    (cffi:with-pointer-to-vector-data (sk-ptr privkey)
      (unless (= 1 (secp256k1-keypair-create *secp256k1-context* keypair sk-ptr))
        (error "invalid private key")))
    (loop for i below 32
          do (setf (cffi:mem-aref aux :uint8 i) (if aux-rand32 (aref aux-rand32 i) 0)))
    (cffi:with-pointer-to-vector-data (msg-ptr hash32)
      (unless (= 1 (secp256k1-schnorrsig-sign32 *secp256k1-context* sig msg-ptr keypair aux))
        (error "schnorr signing failed")))
    (let ((result (make-array 64 :element-type '(unsigned-byte 8))))
      (loop for i below 64 do (setf (aref result i) (cffi:mem-aref sig :uint8 i)))
      result)))

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
  (let ((pk-len (length pubkey-bytes)))
    (unless (or (= pk-len 33) (= pk-len 65))
      (return-from verify-signature (values nil t))))
  (cffi:with-foreign-objects ((sig :uint8 +secp256k1-signature-size+)
                               (pubkey :uint8 +secp256k1-pubkey-size+))
    ;; Parse pubkey directly into foreign buffer (no Lisp round-trip).
    (cffi:with-pointer-to-vector-data (pk-input pubkey-bytes)
      (when (zerop (secp256k1-ec-pubkey-parse
                    *secp256k1-context* pubkey pk-input (length pubkey-bytes)))
        (return-from verify-signature (values nil t))))
    ;; Parse signature: strict (DER over pinned input) or lax (compact after Lisp-side normalization).
    (let ((parse-result
            (if strict
                (cffi:with-pointer-to-vector-data (sig-input signature)
                  (secp256k1-ecdsa-signature-parse-der
                   *secp256k1-context* sig sig-input (length signature)))
                (let ((compact (normalize-signature-lax signature)))
                  (if compact
                      (cffi:with-pointer-to-vector-data (sig-input compact)
                        (secp256k1-ecdsa-signature-parse-compact
                         *secp256k1-context* sig sig-input))
                      0)))))
      (unless (= parse-result 1)
        ;; In strict mode, report DER parse failure; in lax mode, just verification failure.
        (return-from verify-signature (values nil (not strict))))
      (let ((was-high-s (= 1 (secp256k1-ecdsa-signature-normalize *secp256k1-context* sig sig))))
        (when (and low-s was-high-s)
          (return-from verify-signature (values nil :high-s)))
        (cffi:with-pointer-to-vector-data (msg-ptr message-hash)
          (values (= 1 (secp256k1-ecdsa-verify *secp256k1-context* sig msg-ptr pubkey))
                  t))))))

;;; ============================================================
;;; ElligatorSwift (BIP324) — 64-byte uniformly-random-looking pubkey
;;; encodings + x-only ECDH, via libsecp256k1's ellswift module.
;;; ============================================================
;;;
;;; The module is optional at build time (--enable-module-ellswift); distro
;;; libraries may lack it, so everything here is gated on
;;; ellswift-available-p and callers must degrade to v1 transport when it
;;; returns NIL. Mirrors Core key.cpp EllSwiftCreate / ComputeBIP324ECDHSecret.

(cffi:defcfun ("secp256k1_ellswift_create" secp256k1-ellswift-create) :int
  (ctx :pointer)
  (ell64 :pointer)
  (seckey32 :pointer)
  (auxrnd32 :pointer))

(cffi:defcfun ("secp256k1_ellswift_decode" secp256k1-ellswift-decode) :int
  (ctx :pointer)
  (pubkey :pointer)
  (ell64 :pointer))

(cffi:defcfun ("secp256k1_ellswift_xdh" secp256k1-ellswift-xdh) :int
  (ctx :pointer)
  (output :pointer)
  (ell-a64 :pointer)
  (ell-b64 :pointer)
  (seckey32 :pointer)
  (party :int)
  (hashfp :pointer)
  (data :pointer))

(defun ellswift-available-p ()
  "T when the loaded libsecp256k1 was built with the ellswift module.
Old system libraries lack it; the v2 transport must fall back to v1 then."
  (ensure-secp256k1-loaded)
  (not (null (cffi:foreign-symbol-pointer "secp256k1_ellswift_create"))))

(defun %ellswift-bip324-hashfp ()
  "The library's BIP324 xdh hash function: an exported const VARIABLE holding
the function pointer, so it needs one dereference."
  (cffi:mem-ref
   (or (cffi:foreign-symbol-pointer "secp256k1_ellswift_xdh_hash_function_bip324")
       (error "libsecp256k1 lacks the ellswift module"))
   :pointer))

(defun ellswift-create (seckey &optional auxrnd32)
  "Compute the 64-byte ElligatorSwift encoding of SECKEY's public key.
AUXRND32 is optional entropy that randomizes the (many-to-one) encoding;
without it the encoding is still indistinguishable from uniform. Returns the
64-byte encoding, or NIL if SECKEY is invalid."
  (declare (type (simple-array (unsigned-byte 8) (*)) seckey))
  (ensure-secp256k1-loaded)
  (assert (= (length seckey) 32))
  (let ((ell64 (make-array 64 :element-type '(unsigned-byte 8))))
    (cffi:with-pointer-to-vector-data (sec-ptr seckey)
      (cffi:with-pointer-to-vector-data (ell-ptr ell64)
        (flet ((create (aux-ptr)
                 (secp256k1-ellswift-create *secp256k1-context*
                                            ell-ptr sec-ptr aux-ptr)))
          (when (= 1 (if auxrnd32
                         (cffi:with-pointer-to-vector-data (aux-ptr auxrnd32)
                           (create aux-ptr))
                         (create (cffi:null-pointer))))
            ell64))))))

(defun ellswift-decode (ell64)
  "Decode a 64-byte ElligatorSwift encoding to a 33-byte compressed public
key. Every 64-byte string decodes to some valid key (that is the point of the
encoding), so this always succeeds."
  (declare (type (simple-array (unsigned-byte 8) (*)) ell64))
  (ensure-secp256k1-loaded)
  (assert (= (length ell64) 64))
  (let ((out (make-array 33 :element-type '(unsigned-byte 8))))
    (cffi:with-foreign-objects ((pubkey :uint8 +secp256k1-pubkey-size+)
                                (outlen :size))
      (cffi:with-pointer-to-vector-data (ell-ptr ell64)
        (secp256k1-ellswift-decode *secp256k1-context* pubkey ell-ptr))
      (setf (cffi:mem-ref outlen :size) 33)
      (cffi:with-pointer-to-vector-data (out-ptr out)
        (secp256k1-ec-pubkey-serialize *secp256k1-context* out-ptr outlen
                                       pubkey +secp256k1-ec-compressed+))
      out)))

(defun bip324-ecdh (their-ell64 our-ell64 seckey initiating)
  "Compute the 32-byte BIP324 shared secret via x-only ECDH over
ElligatorSwift keys, using libsecp256k1's own BIP324 hash function
(tagged hash of ell_a64 || ell_b64 || ecdh_x). BIP324 designates the
INITIATOR as party A, so the a/b argument order and the party flag both
derive from INITIATING (Core key.cpp ComputeBIP324ECDHSecret). Returns the
secret, or NIL if SECKEY is invalid."
  (declare (type (simple-array (unsigned-byte 8) (*)) their-ell64 our-ell64 seckey))
  (ensure-secp256k1-loaded)
  (assert (and (= (length their-ell64) 64) (= (length our-ell64) 64)
               (= (length seckey) 32)))
  (let ((output (make-array 32 :element-type '(unsigned-byte 8)))
        (ell-a (if initiating our-ell64 their-ell64))
        (ell-b (if initiating their-ell64 our-ell64)))
    (cffi:with-pointer-to-vector-data (out-ptr output)
      (cffi:with-pointer-to-vector-data (a-ptr ell-a)
        (cffi:with-pointer-to-vector-data (b-ptr ell-b)
          (cffi:with-pointer-to-vector-data (sec-ptr seckey)
            (when (= 1 (secp256k1-ellswift-xdh *secp256k1-context*
                                               out-ptr a-ptr b-ptr sec-ptr
                                               (if initiating 0 1)
                                               (%ellswift-bip324-hashfp)
                                               (cffi:null-pointer)))
              output)))))))
