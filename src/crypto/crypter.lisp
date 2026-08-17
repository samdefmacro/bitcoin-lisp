(in-package #:bitcoin-lisp.crypto)

;;; Wallet crypter primitives (wallet P6)
;;;
;;; A byte-exact port of Bitcoin Core's wallet encryption primitives:
;;; the SHA-512 passphrase KDF (src/wallet/crypter.cpp:15-61,
;;; CCrypter::BytesToKeySHA512AES + SetKeyFromPassphrase) and AES-256-CBC
;;; with PKCS#7 padding (src/crypto/aes.cpp:43-116, CBCEncrypt/CBCDecrypt
;;; with pad=true).
;;;
;;; We drive ironclad's CBC mode with NO padding mode and pad/unpad
;;; ourselves. That is deliberate, not an oversight: ironclad's :pkcs7
;;; padding accepts a final byte of 0 (Core rejects it), signals TYPE-ERROR
;;; rather than IRONCLAD:INVALID-PADDING on a pad byte above the block size,
;;; and its INVALID-PADDING report string embeds the decrypted final block —
;;; key-adjacent material that must never reach a log. Core's rules are
;;; simple enough to state directly, so we do.

(defconstant +wallet-crypto-key-size+ 32
  "WALLET_CRYPTO_KEY_SIZE (crypter.h:14): AES-256 key length.")

(defconstant +wallet-crypto-salt-size+ 8
  "WALLET_CRYPTO_SALT_SIZE (crypter.h:15): CMasterKey::vchSalt length.")

(defconstant +wallet-crypto-iv-size+ 16
  "WALLET_CRYPTO_IV_SIZE (crypter.h:16): AES-CBC initialization vector.")

(defconstant +aes-block-size+ 16
  "AES_BLOCKSIZE (aes.h).")

(deftype octet-vector () '(simple-array (unsigned-byte 8) (*)))

(declaim (inline %octets))
(defun %octets (v)
  "V as a simple (unsigned-byte 8) vector — ironclad's UPDATE-DIGEST and
MAKE-CIPHER both CHECK-TYPE their arguments against exactly that. Free on
SBCL when V is already simple."
  (if (typep v 'octet-vector)
      v
      (coerce v 'octet-vector)))

;;; --- SHA-512 passphrase KDF (Core BytesToKeySHA512AES) ---

(defun crypter-derive-key (passphrase-octets salt rounds &optional (method 0))
  "Derive (values key32 iv16) from a passphrase, Core's
CCrypter::SetKeyFromPassphrase (crypter.cpp:41-61).

This mimics OpenSSL's EVP_BytesToKey with an aes256cbc cipher and an sha512
digest: because SHA-512's 64-byte output already covers the 32-byte key plus
the 16-byte IV, only one D_i block is ever needed.

  buf = SHA512(passphrase || salt)          ; passphrase FIRST, no separator
  repeat (rounds - 1): buf = SHA512(buf)
  key = buf[0..32), iv = buf[32..48)

Returns (values NIL NIL) on the parameter combinations Core rejects: a
derivation method other than 0, fewer than 1 round, or a salt that is not
exactly WALLET-CRYPTO-SALT-SIZE bytes."
  (unless (and (eql method 0)
               (integerp rounds) (>= rounds 1)
               (= (length salt) +wallet-crypto-salt-size+))
    (return-from crypter-derive-key (values nil nil)))
  (let ((digest (ironclad:make-digest :sha512))
        (buf (make-array 64 :element-type '(unsigned-byte 8))))
    (unwind-protect
         (progn
           ;; Two UPDATE-DIGEST calls are byte-identical to hashing the
           ;; concatenation, and avoid copying the passphrase into a
           ;; second buffer.
           (ironclad:update-digest digest (%octets passphrase-octets))
           (ironclad:update-digest digest (%octets salt))
           (ironclad:produce-digest digest :digest buf)
           (dotimes (i (1- rounds))
             (reinitialize-instance digest)
             (ironclad:update-digest digest buf)
             (ironclad:produce-digest digest :digest buf))
           (values (subseq buf 0 +wallet-crypto-key-size+)
                   (subseq buf +wallet-crypto-key-size+
                           (+ +wallet-crypto-key-size+ +wallet-crypto-iv-size+))))
      (fill buf 0))))

;;; --- PKCS#7 padding (Core aes.cpp CBCEncrypt/CBCDecrypt, pad=true) ---

(defun pkcs7-pad (bytes)
  "Append PKCS#7 padding to BYTES (Core aes.cpp:67-75). A length that is
already a multiple of the block size gains a full extra block, so the result
always grows and its length is always a multiple of +AES-BLOCK-SIZE+."
  (let* ((len (length bytes))
         (n (- +aes-block-size+ (mod len +aes-block-size+)))
         (out (make-array (+ len n) :element-type '(unsigned-byte 8))))
    (replace out bytes)
    (fill out n :start len)
    out))

(defun pkcs7-unpad (bytes)
  "Strip and validate PKCS#7 padding, or NIL if it is not well formed
(Core aes.cpp:100-116, whose result is 0 — never a partial length — on any
malformed padding).

Core's checks, all of them: the length must be a positive multiple of the
block size; the final byte must be in [1, 16]; every one of the last N bytes
must equal N; and a plaintext that unpads to nothing is a failure
 (CCrypter::Decrypt treats len == 0 as false, crypter.cpp:104)."
  (let ((len (length bytes)))
    (when (or (zerop len) (plusp (mod len +aes-block-size+)))
      (return-from pkcs7-unpad nil))
    (let* ((n (aref bytes (1- len)))
           ;; Core accumulates the verdict over a fixed 16 iterations rather
           ;; than exiting early; keep the shape so the work does not depend
           ;; on where the first mismatch is.
           (fail (if (or (zerop n) (> n +aes-block-size+)) 1 0)))
      (let ((effective (if (plusp fail) 0 n)))
        (loop for i from 1 to +aes-block-size+
              for byte = (aref bytes (- len i))
              do (setf fail (logior fail
                                    (if (and (<= i effective) (/= byte n)) 1 0))))
        (when (or (plusp fail) (>= effective len))
          (return-from pkcs7-unpad nil))
        (subseq bytes 0 (- len effective))))))

;;; --- AES-256-CBC (Core AES256CBCEncrypt/AES256CBCDecrypt, pad=true) ---

(defun aes-256-cbc-encrypt (key32 iv16 plaintext)
  "AES-256-CBC encrypt PLAINTEXT with PKCS#7 padding — Core
AES256CBCEncrypt(key, iv, /*pad=*/true). The ciphertext is always
16 bytes longer than the plaintext rounded down to a block boundary."
  (assert (= (length key32) +wallet-crypto-key-size+))
  (assert (= (length iv16) +wallet-crypto-iv-size+))
  (let ((padded (pkcs7-pad plaintext)))
    ;; A misaligned input makes ironclad return an empty ciphertext rather
    ;; than signalling, so assert alignment instead of trusting the caller.
    (assert (zerop (mod (length padded) +aes-block-size+)))
    ;; A cipher object chains CBC state across calls; never reuse one.
    (ironclad:encrypt-message
     (ironclad:make-cipher :aes :mode :cbc
                                :key (%octets key32)
                                :initialization-vector (%octets iv16))
     padded)))

(defun aes-256-cbc-decrypt (key32 iv16 ciphertext)
  "AES-256-CBC decrypt CIPHERTEXT and strip PKCS#7 padding, or NIL — Core
AES256CBCDecrypt(key, iv, /*pad=*/true), whose every failure mode is a
false return. No condition escapes this function.

The length check is load-bearing: ironclad silently truncates a ciphertext
that is not a whole number of blocks."
  (when (and (= (length key32) +wallet-crypto-key-size+)
             (= (length iv16) +wallet-crypto-iv-size+)
             (plusp (length ciphertext))
             (zerop (mod (length ciphertext) +aes-block-size+)))
    (let ((raw (ironclad:decrypt-message
                (ironclad:make-cipher :aes :mode :cbc
                                           :key (%octets key32)
                                           :initialization-vector (%octets iv16))
                (%octets ciphertext))))
      (pkcs7-unpad raw))))
