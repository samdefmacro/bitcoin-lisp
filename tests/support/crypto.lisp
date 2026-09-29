(in-package #:bitcoin-lisp.test-support)

;;;; The unratcheted ChaCha20 and RFC 8439 AEAD primitives, for the tests that
;;;; check them against Core's vectors and fuzz properties. BL.CRYPTO keeps
;;;; them internal on purpose -- only the forward-secure wrappers BIP324 uses
;;;; are API (src/crypto/package.lisp) -- so the tests reach them here, once,
;;;; under names that say what they are.

(defun raw-chacha20 (key)
  "Core ChaCha20(key): nonce 0, block 0."
  (bl.crypto::make-chacha20 key))

(defun raw-chacha20-seek (cipher nonce1 nonce2 block-counter)
  "Core ChaCha20::Seek({NONCE1, NONCE2}, BLOCK-COUNTER)."
  (bl.crypto::chacha20-seek cipher nonce1 nonce2 block-counter))

(defun raw-chacha20-crypt (cipher in out &rest keys &key start end out-start)
  "Core ChaCha20::Crypt over IN[START..END) into OUT."
  (declare (ignore start end out-start))
  (apply #'bl.crypto::chacha20-crypt cipher in out keys))

(defun raw-chacha20-keystream (cipher out &rest keys &key start end)
  "Core ChaCha20::Keystream into OUT[START..END)."
  (declare (ignore start end))
  (apply #'bl.crypto::chacha20-keystream cipher out keys))

(defun raw-aead (key)
  "Core AEADChaCha20Poly1305(key)."
  (bl.crypto::make-aead-chacha20-poly1305 key))

(defun raw-aead-encrypt (aead plain aad nonce1 nonce2 cipher &optional plain2 (out-start 0))
  "Core AEADChaCha20Poly1305::Encrypt: PLAIN (+ PLAIN2) and AAD into CIPHER."
  (bl.crypto::aead-encrypt aead plain aad nonce1 nonce2 cipher plain2 out-start))

(defun raw-aead-decrypt (aead cipher aad nonce1 nonce2 plain &optional plain2)
  "Core AEADChaCha20Poly1305::Decrypt: T when CIPHER authenticates."
  (bl.crypto::aead-decrypt aead cipher aad nonce1 nonce2 plain plain2))

(defun raw-aead-keystream (aead nonce1 nonce2 out)
  "Core AEADChaCha20Poly1305::Keystream."
  (bl.crypto::aead-keystream aead nonce1 nonce2 out))
