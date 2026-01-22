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

;;; ============================================================
;;; Tagged Hashes (BIP 340)
;;; ============================================================
;;;
;;; BIP 340 defines tagged hashes to prevent cross-protocol attacks:
;;; tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
;;;
;;; Pre-computed tag hashes are cached for efficiency.

(defvar *tagged-hash-cache* (make-hash-table :test 'equal)
  "Cache for pre-computed SHA256(tag) values.")

(defun get-tag-hash (tag)
  "Get or compute SHA256(tag) for a given tag string."
  (or (gethash tag *tagged-hash-cache*)
      (setf (gethash tag *tagged-hash-cache*)
            (sha256 (flexi-streams:string-to-octets tag :external-format :utf-8)))))

(defun tagged-hash (tag data)
  "Compute BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
   TAG is a string (e.g., \"BIP0340/challenge\", \"TapLeaf\").
   DATA is a byte vector.
   Returns a 32-byte hash."
  (let ((tag-hash (get-tag-hash tag)))
    (sha256 (concatenate '(vector (unsigned-byte 8))
                         tag-hash tag-hash data))))

;; Pre-defined tag constants for Taproot
(defconstant +tag-bip340-challenge+ "BIP0340/challenge")
(defconstant +tag-bip340-aux+ "BIP0340/aux")
(defconstant +tag-bip340-nonce+ "BIP0340/nonce")
(defconstant +tag-tap-leaf+ "TapLeaf")
(defconstant +tag-tap-branch+ "TapBranch")
(defconstant +tag-tap-tweak+ "TapTweak")
(defconstant +tag-tap-sighash+ "TapSighash")

;; Convenience functions for common tagged hashes
(defun tap-leaf-hash (leaf-version script)
  "Compute TapLeaf hash: tagged_hash('TapLeaf', leaf_version || compact_size(script) || script).
   LEAF-VERSION is a byte (typically 0xc0 for Tapscript).
   SCRIPT is the script bytes."
  (let ((preimage (flexi-streams:with-output-to-sequence (s :element-type '(unsigned-byte 8))
                    (write-byte leaf-version s)
                    ;; Compact size encoding of script length
                    (let ((len (length script)))
                      (cond
                        ((< len #xfd)
                         (write-byte len s))
                        ((< len #x10000)
                         (write-byte #xfd s)
                         (write-byte (logand len #xff) s)
                         (write-byte (ash len -8) s))
                        (t
                         (write-byte #xfe s)
                         (write-byte (logand len #xff) s)
                         (write-byte (logand (ash len -8) #xff) s)
                         (write-byte (logand (ash len -16) #xff) s)
                         (write-byte (ash len -24) s))))
                    (loop for b across script do (write-byte b s)))))
    (tagged-hash +tag-tap-leaf+ preimage)))

(defun tap-branch-hash (left-hash right-hash)
  "Compute TapBranch hash: tagged_hash('TapBranch', sorted(left || right)).
   Hashes are sorted lexicographically before concatenation."
  (let ((sorted (if (loop for i from 0 below 32
                          for l = (aref left-hash i)
                          for r = (aref right-hash i)
                          thereis (< l r))
                    (concatenate '(vector (unsigned-byte 8)) left-hash right-hash)
                    (concatenate '(vector (unsigned-byte 8)) right-hash left-hash))))
    (tagged-hash +tag-tap-branch+ sorted)))

(defun tap-tweak-hash (internal-pubkey32 &optional merkle-root)
  "Compute TapTweak hash: tagged_hash('TapTweak', pubkey || merkle_root).
   INTERNAL-PUBKEY32 is the 32-byte x-only internal public key.
   MERKLE-ROOT is the optional 32-byte Merkle root (nil for key-path only)."
  (let ((preimage (if merkle-root
                      (concatenate '(vector (unsigned-byte 8))
                                   internal-pubkey32 merkle-root)
                      internal-pubkey32)))
    (tagged-hash +tag-tap-tweak+ preimage)))

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
