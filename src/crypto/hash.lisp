(in-package #:bitcoin-lisp.crypto)

;;; Hash functions for Bitcoin
;;;
;;; Bitcoin uses several hash functions:
;;; - SHA256: Standard SHA-256
;;; - Hash256: Double SHA-256, used for block hashes, transaction hashes
;;; - RIPEMD160: Used in combination with SHA256 for addresses
;;; - Hash160: RIPEMD160(SHA256(x)), used for public key hashes

(defun sha256 (data)
  "Compute SHA-256 hash of DATA (a byte vector).
Returns a 32-byte vector."
  (let ((digest (ironclad:make-digest :sha256))
        ;; Coerce to simple array if needed
        (input (if (typep data '(simple-array (unsigned-byte 8) (*)))
                   data
                   (coerce data '(simple-array (unsigned-byte 8) (*))))))
    (ironclad:update-digest digest input)
    (ironclad:produce-digest digest)))

(defun hash256 (data)
  "Compute double SHA-256 hash of DATA (a byte vector).
This is SHA256(SHA256(data)), used for Bitcoin block and transaction hashes.
Returns a 32-byte vector."
  (sha256 (sha256 data)))

(defun ripemd160 (data)
  "Compute RIPEMD-160 hash of DATA (a byte vector).
Returns a 20-byte vector."
  (let ((digest (ironclad:make-digest :ripemd-160)))
    (ironclad:update-digest digest data)
    (ironclad:produce-digest digest)))

(defun hash160 (data)
  "Compute Hash160 of DATA: RIPEMD160(SHA256(data)).
Used for Bitcoin public key hashes and script hashes.
Returns a 20-byte vector."
  (ripemd160 (sha256 data)))

;;; Utility functions

(defun bytes-to-hex (bytes)
  "Convert a byte vector to a lowercase hexadecimal string."
  (ironclad:byte-array-to-hex-string bytes))

(defun hex-to-bytes (hex-string)
  "Convert a hexadecimal string to a byte vector."
  (ironclad:hex-string-to-byte-array hex-string))

(defun reverse-bytes (bytes)
  "Return a new byte vector with bytes in reverse order.
Bitcoin often displays hashes in reverse byte order."
  (let* ((len (length bytes))
         (result (make-array len :element-type '(unsigned-byte 8))))
    (loop for i from 0 below len
          do (setf (aref result i) (aref bytes (- len 1 i))))
    result))
