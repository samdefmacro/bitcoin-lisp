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
;; Use alexandria:define-constant for SBCL reload compatibility
(alexandria:define-constant +tag-bip340-challenge+ "BIP0340/challenge" :test #'equal)
(alexandria:define-constant +tag-bip340-aux+ "BIP0340/aux" :test #'equal)
(alexandria:define-constant +tag-bip340-nonce+ "BIP0340/nonce" :test #'equal)
(alexandria:define-constant +tag-tap-leaf+ "TapLeaf" :test #'equal)
(alexandria:define-constant +tag-tap-branch+ "TapBranch" :test #'equal)
(alexandria:define-constant +tag-tap-tweak+ "TapTweak" :test #'equal)
(alexandria:define-constant +tag-tap-sighash+ "TapSighash" :test #'equal)

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

;;; ============================================================
;;; SipHash-2-4 (BIP 152)
;;; ============================================================
;;;
;;; SipHash is a fast, secure pseudorandom function used in BIP 152
;;; for computing short transaction IDs in compact blocks.
;;; We implement SipHash-2-4: 2 compression rounds, 4 finalization rounds.

(declaim (inline siphash-rotl64))
(defun siphash-rotl64 (x n)
  "Rotate 64-bit integer X left by N bits."
  (declare (type (unsigned-byte 64) x)
           (type (integer 0 63) n)
           (optimize (speed 3) (safety 0)))
  (logand #xFFFFFFFFFFFFFFFF
          (logior (ash x n)
                  (ash x (- n 64)))))

(defun siphash-2-4 (k0 k1 data)
  "Compute SipHash-2-4 of DATA using keys K0 and K1.
   K0 and K1 are 64-bit unsigned integers.
   DATA is a byte vector.
   Returns a 64-bit unsigned integer."
  (declare (type (unsigned-byte 64) k0 k1)
           (optimize (speed 3)))
  (let ((v0 (logxor k0 #x736f6d6570736575))
        (v1 (logxor k1 #x646f72616e646f6d))
        (v2 (logxor k0 #x6c7967656e657261))
        (v3 (logxor k1 #x7465646279746573))
        (len (length data))
        (b 0))
    (declare (type (unsigned-byte 64) v0 v1 v2 v3 b))
    ;; Set length byte in high byte of b
    (setf b (ash (logand len #xff) 56))

    ;; Process 8-byte blocks
    (let ((blocks (floor len 8)))
      (dotimes (i blocks)
        (let ((m 0))
          (declare (type (unsigned-byte 64) m))
          ;; Read 8 bytes little-endian
          (dotimes (j 8)
            (setf m (logior m (ash (aref data (+ (* i 8) j)) (* j 8)))))
          (setf v3 (logxor v3 m))
          ;; 2 compression rounds
          (dotimes (round 2)
            (declare (ignore round))
            (setf v0 (logand #xFFFFFFFFFFFFFFFF (+ v0 v1)))
            (setf v1 (siphash-rotl64 v1 13))
            (setf v1 (logxor v1 v0))
            (setf v0 (siphash-rotl64 v0 32))
            (setf v2 (logand #xFFFFFFFFFFFFFFFF (+ v2 v3)))
            (setf v3 (siphash-rotl64 v3 16))
            (setf v3 (logxor v3 v2))
            (setf v0 (logand #xFFFFFFFFFFFFFFFF (+ v0 v3)))
            (setf v3 (siphash-rotl64 v3 21))
            (setf v3 (logxor v3 v0))
            (setf v2 (logand #xFFFFFFFFFFFFFFFF (+ v2 v1)))
            (setf v1 (siphash-rotl64 v1 17))
            (setf v1 (logxor v1 v2))
            (setf v2 (siphash-rotl64 v2 32)))
          (setf v0 (logxor v0 m)))))

    ;; Process remaining bytes (< 8)
    (let ((remaining (mod len 8))
          (start (* (floor len 8) 8)))
      (dotimes (i remaining)
        (setf b (logior b (ash (aref data (+ start i)) (* i 8))))))

    ;; Final block
    (setf v3 (logxor v3 b))
    ;; 2 compression rounds
    (dotimes (round 2)
      (declare (ignore round))
      (setf v0 (logand #xFFFFFFFFFFFFFFFF (+ v0 v1)))
      (setf v1 (siphash-rotl64 v1 13))
      (setf v1 (logxor v1 v0))
      (setf v0 (siphash-rotl64 v0 32))
      (setf v2 (logand #xFFFFFFFFFFFFFFFF (+ v2 v3)))
      (setf v3 (siphash-rotl64 v3 16))
      (setf v3 (logxor v3 v2))
      (setf v0 (logand #xFFFFFFFFFFFFFFFF (+ v0 v3)))
      (setf v3 (siphash-rotl64 v3 21))
      (setf v3 (logxor v3 v0))
      (setf v2 (logand #xFFFFFFFFFFFFFFFF (+ v2 v1)))
      (setf v1 (siphash-rotl64 v1 17))
      (setf v1 (logxor v1 v2))
      (setf v2 (siphash-rotl64 v2 32)))
    (setf v0 (logxor v0 b))

    ;; Finalization
    (setf v2 (logxor v2 #xff))
    ;; 4 finalization rounds
    (dotimes (round 4)
      (declare (ignore round))
      (setf v0 (logand #xFFFFFFFFFFFFFFFF (+ v0 v1)))
      (setf v1 (siphash-rotl64 v1 13))
      (setf v1 (logxor v1 v0))
      (setf v0 (siphash-rotl64 v0 32))
      (setf v2 (logand #xFFFFFFFFFFFFFFFF (+ v2 v3)))
      (setf v3 (siphash-rotl64 v3 16))
      (setf v3 (logxor v3 v2))
      (setf v0 (logand #xFFFFFFFFFFFFFFFF (+ v0 v3)))
      (setf v3 (siphash-rotl64 v3 21))
      (setf v3 (logxor v3 v0))
      (setf v2 (logand #xFFFFFFFFFFFFFFFF (+ v2 v1)))
      (setf v1 (siphash-rotl64 v1 17))
      (setf v1 (logxor v1 v2))
      (setf v2 (siphash-rotl64 v2 32)))

    ;; Return final hash
    (logxor v0 v1 v2 v3)))

(defun bytes-to-uint64-le (bytes &optional (offset 0))
  "Read a 64-bit little-endian unsigned integer from BYTES at OFFSET."
  (let ((result 0))
    (dotimes (i 8)
      (setf result (logior result (ash (aref bytes (+ offset i)) (* i 8)))))
    result))

(defun uint64-to-bytes-le (value)
  "Convert a 64-bit unsigned integer to 8 bytes in little-endian order."
  (let ((bytes (make-array 8 :element-type '(unsigned-byte 8))))
    (dotimes (i 8)
      (setf (aref bytes i) (logand (ash value (- (* i 8))) #xff)))
    bytes))

(defun compute-siphash-key (header-bytes nonce)
  "Compute SipHash keys from block header bytes and nonce.
   HEADER-BYTES is the serialized 80-byte block header.
   NONCE is a 64-bit unsigned integer.
   Returns (VALUES k0 k1) as two 64-bit integers."
  (let* ((nonce-bytes (uint64-to-bytes-le nonce))
         (data (concatenate '(vector (unsigned-byte 8)) header-bytes nonce-bytes))
         (hash (sha256 data)))
    ;; First 8 bytes = k0, next 8 bytes = k1 (little-endian)
    (values (bytes-to-uint64-le hash 0)
            (bytes-to-uint64-le hash 8))))

(defun compute-short-txid (k0 k1 txid)
  "Compute 6-byte short transaction ID using SipHash-2-4.
   K0 and K1 are the SipHash keys.
   TXID is a 32-byte transaction ID (or wtxid for version 2).
   Returns a 48-bit unsigned integer (6 bytes)."
  (let ((hash (siphash-2-4 k0 k1 txid)))
    ;; Take lower 6 bytes (drop 2 MSB)
    (logand hash #xFFFFFFFFFFFF)))
