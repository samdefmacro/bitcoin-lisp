(in-package #:bitcoin-lisp.crypto)

;;; MuHash3072 — a multiplicative, order-independent, incremental set hash
;;; (Bitcoin Core src/crypto/muhash.{h,cpp}).
;;;
;;; MuHash represents a set as a running value in the multiplicative group
;;; modulo the 3072-bit safe prime 2^3072 - 1103717. Each element hashes to a
;;; 3072-bit group member (SHA256 of the element, expanded to 384 bytes with
;;; ChaCha20, read little-endian); the set value is the product of all its
;;; elements. Insert multiplies, Remove divides -- so elements can be added
;;; and removed in any order, and two set hashes combine by multiplying.
;;;
;;; Core carries a hand-written 3072-bit fixed-limb bignum (Num3072) with a
;;; safegcd modular inverse because C++ has no bignums. SBCL does, so this is
;;; just arithmetic mod the prime: the value is kept as a fraction
;;; numerator/denominator (Core's trick to defer the one expensive inverse to
;;; Finalize), and Finalize is SHA256 of the 384-byte little-endian encoding
;;; of numerator * denominator^-1 mod p.

(defconstant +muhash-modulus+ (- (ash 1 3072) 1103717)
  "The MuHash group modulus: 2^3072 - 1103717, the largest 3072-bit safe prime
(Core Num3072 MAX_PRIME_DIFF).")

(defconstant +muhash-byte-size+ 384
  "Serialized size of a Num3072 (3072 bits, little-endian).")

(defun %bytes-to-le-integer (bytes)
  "Interpret BYTES as an unsigned little-endian integer."
  (declare (type (simple-array (unsigned-byte 8) (*)) bytes))
  (let ((acc 0))
    (loop for i from (1- (length bytes)) downto 0
          do (setf acc (logior (ash acc 8) (aref bytes i))))
    acc))

(defun %le-integer-to-bytes (value n)
  "Encode VALUE as N little-endian bytes (VALUE must fit)."
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (loop for i below n
          do (setf (aref out i) (ldb (byte 8 (* 8 i)) value)))
    out))

(defun %mod-inverse (a m)
  "Modular inverse of A mod M via the extended Euclidean algorithm (M prime,
A coprime to M)."
  (let ((old-r a) (r m) (old-s 1) (s 0))
    (loop until (zerop r)
          do (let ((q (floor old-r r)))
               (psetf old-r r r (- old-r (* q r)))
               (psetf old-s s s (- old-s (* q s)))))
    (mod old-s m)))

(defun muhash-element-num (data)
  "Map an element (byte vector) to its Num3072 group value: the little-endian
integer read from 384 ChaCha20 keystream bytes keyed by SHA256(DATA), reduced
mod the modulus. (Core MuHash3072::ToNum3072; the raw value only ever enters a
reduce-on-multiply, so reducing here is equivalent and keeps values bounded.)"
  (let* ((key (sha256 data))
         (keystream (make-array +muhash-byte-size+ :element-type '(unsigned-byte 8)))
         (cipher (make-chacha20 key)))
    (chacha20-keystream cipher keystream)
    (mod (%bytes-to-le-integer keystream) +muhash-modulus+)))

(defstruct (muhash (:constructor %make-muhash))
  "A MuHash3072 accumulator, held as the fraction numerator/denominator mod the
modulus (both default 1 = the empty set)."
  (numerator 1 :type integer)
  (denominator 1 :type integer))

(defun make-muhash (&optional data)
  "An empty MuHash, or a singleton containing the one element DATA."
  (if data
      (%make-muhash :numerator (muhash-element-num data))
      (%make-muhash)))

(defun muhash-insert (mu data)
  "Add element DATA to the set (multiply it into the numerator)."
  (setf (muhash-numerator mu)
        (mod (* (muhash-numerator mu) (muhash-element-num data)) +muhash-modulus+))
  mu)

(defun muhash-remove (mu data)
  "Remove element DATA from the set (multiply it into the denominator)."
  (setf (muhash-denominator mu)
        (mod (* (muhash-denominator mu) (muhash-element-num data)) +muhash-modulus+))
  mu)

(defun muhash-combine (mu other)
  "Multiply OTHER's set into MU (union of the two sets); the operands'
numerators and denominators multiply independently (Core operator*=)."
  (setf (muhash-numerator mu)
        (mod (* (muhash-numerator mu) (muhash-numerator other)) +muhash-modulus+)
        (muhash-denominator mu)
        (mod (* (muhash-denominator mu) (muhash-denominator other)) +muhash-modulus+))
  mu)

(defun muhash-divide (mu other)
  "Divide OTHER's set out of MU (set difference); OTHER's numerator goes into
MU's denominator and vice versa (Core operator/=)."
  (setf (muhash-numerator mu)
        (mod (* (muhash-numerator mu) (muhash-denominator other)) +muhash-modulus+)
        (muhash-denominator mu)
        (mod (* (muhash-denominator mu) (muhash-numerator other)) +muhash-modulus+))
  mu)

(defun muhash-finalize (mu)
  "Collapse the fraction to a single group value and return its 32-byte hash:
SHA256 of the 384-byte little-endian encoding of numerator * denominator^-1
mod the modulus. Does not modify MU."
  (let* ((value (mod (* (muhash-numerator mu)
                        (%mod-inverse (muhash-denominator mu) +muhash-modulus+))
                     +muhash-modulus+)))
    (sha256 (%le-integer-to-bytes value +muhash-byte-size+))))
