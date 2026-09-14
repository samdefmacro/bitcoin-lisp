(in-package #:bitcoin-lisp.crypto)

;;; Bitcoin Address Encoding/Decoding
;;;
;;; This module provides Base58Check and Bech32/Bech32m encoding for Bitcoin addresses.

;;; ============================================================
;;; Base58 Encoding/Decoding
;;; ============================================================

(defparameter *base58-alphabet*
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  "Base58 alphabet (no 0, O, I, l to avoid visual confusion).")

(defparameter *base58-decode-map*
  (let ((map (make-array 128 :initial-element -1)))
    (loop for i from 0 below 58
          do (setf (aref map (char-code (char *base58-alphabet* i))) i))
    map)
  "Lookup table for Base58 decoding.")

(defun base58-encode (bytes)
  "Encode a byte vector to Base58 string.
Preserves leading zeros as '1' characters."
  (let ((leading-zeros 0)
        (result '()))
    ;; Count leading zero bytes
    (loop for b across bytes
          while (zerop b)
          do (incf leading-zeros))
    ;; Convert to big integer
    (let ((num (reduce (lambda (acc b) (+ (* acc 256) b)) bytes :initial-value 0)))
      ;; Convert to base58
      (loop while (plusp num)
            do (multiple-value-bind (q r) (floor num 58)
                 (push (char *base58-alphabet* r) result)
                 (setf num q))))
    ;; Add leading '1's for each leading zero byte
    (concatenate 'string
                 (make-string leading-zeros :initial-element #\1)
                 (coerce result 'string))))

(defun %base58-space-p (code)
  "Core's IsSpace (util/strencodings.h:166): space, form feed, newline,
carriage return, tab, vertical tab -- and nothing else, locale independently."
  (or (= code 32) (= code 12) (= code 10) (= code 13) (= code 9) (= code 11)))

(defun base58-decode (str max-ret-len)
  "Decode a Base58 string to a byte vector of at most MAX-RET-LEN bytes, or
NIL. Core's DecodeBase58 (base58.cpp:40-84), argument for argument.

MAX-RET-LEN is not a post-hoc length check: the decoder gives up inside the
per-character loop the moment the accumulated result would pass the bound
(base58.cpp:50 for the leading '1's, :71 for the digits), so the cost stays
linear in a string it is going to reject. Accumulating one big integer over
the whole string instead is quadratic -- measured on this tree before the
bound existed: 200,000 'z's took 3.0 s, and an address argument reaches this
through an RPC body that may be 32 MiB.

Leading and trailing whitespace is skipped, as Core does (base58.cpp:42-43
and :73-74); whitespace in the middle ends the digits and then fails the
end-of-string check. An invalid character -- NUL included, which is why Core
tests the string for one up front -- returns NIL."
  (let ((n (length str))
        (i 0)
        (zeroes 0)
        (out-len 0))
    (flet ((skip-spaces ()
             (loop while (and (< i n) (%base58-space-p (char-code (char str i))))
                   do (incf i))))
      (skip-spaces)
      ;; Leading '1's are zero bytes and count against the bound directly.
      (loop while (and (< i n) (char= (char str i) #\1))
            do (incf zeroes)
               (when (> zeroes max-ret-len)
                 (return-from base58-decode nil))
               (incf i))
      ;; Big-endian base-256 accumulator. Core sizes it from what is left of
      ;; the string (log(58)/log(256) rounded up); capping that at
      ;; MAX-RET-LEN+1 is the same buffer for every string that can still
      ;; succeed, because the loop below stops as soon as OUT-LEN passes the
      ;; bound and one carry can extend the result by at most one byte.
      (let* ((size (max 1 (min (1+ (floor (* (- n i) 733) 1000))
                               (1+ max-ret-len))))
             (b256 (make-array size :element-type '(unsigned-byte 8)
                                    :initial-element 0)))
        (loop while (< i n)
              do (let ((code (char-code (char str i))))
                   (when (%base58-space-p code) (return))
                   (let ((carry (if (< code 128) (aref *base58-decode-map* code) -1))
                         (used 0))
                     (when (minusp carry)
                       (return-from base58-decode nil))
                     ;; b256 = b256 * 58 + carry, high byte last.
                     (loop for j downfrom (1- size) to 0
                           while (or (plusp carry) (< used out-len))
                           do (incf carry (* 58 (aref b256 j)))
                              (setf (aref b256 j) (logand carry #xff))
                              (setf carry (ash carry -8))
                              (incf used))
                     (setf out-len used)
                     (when (> (+ out-len zeroes) max-ret-len)
                       (return-from base58-decode nil))))
                 (incf i))
        (skip-spaces)
        (unless (= i n)
          (return-from base58-decode nil))
        (let ((out (make-array (+ zeroes out-len) :element-type '(unsigned-byte 8)
                                                  :initial-element 0)))
          (replace out b256 :start1 zeroes :start2 (- size out-len))
          out)))))

;;; ============================================================
;;; Base58Check Encoding/Decoding
;;; ============================================================

(defun base58check-encode (version payload)
  "Encode VERSION byte and PAYLOAD to Base58Check string.
Adds checksum (first 4 bytes of double SHA256)."
  (let* ((versioned (concatenate '(vector (unsigned-byte 8))
                                 (vector version)
                                 payload))
         (checksum (subseq (hash256 versioned) 0 4))
         (with-checksum (concatenate '(vector (unsigned-byte 8))
                                     versioned checksum)))
    (base58-encode with-checksum)))

(defun base58check-decode (str max-ret-len)
  "Decode a Base58Check string.
Returns (VALUES version payload) or NIL if invalid.

MAX-RET-LEN bounds the decoded bytes WITHOUT the four checksum bytes -- the
version byte plus the payload -- so it is the number Core's callers pass to
DecodeBase58Check (21 for a destination, 34 for WIF, 78 for an extended key);
like Core (base58.cpp:146-148) it hands the raw decoder that bound plus four."
  (let ((bytes (base58-decode str (+ max-ret-len 4))))
    (when (and bytes (>= (length bytes) 5))
      (let* ((version (aref bytes 0))
             (payload (subseq bytes 1 (- (length bytes) 4)))
             (checksum (subseq bytes (- (length bytes) 4)))
             (expected (subseq (hash256 (subseq bytes 0 (- (length bytes) 4))) 0 4)))
        (when (equalp checksum expected)
          (values version payload))))))

;;; ============================================================
;;; WIF (Wallet Import Format) private keys
;;; ============================================================


(defun private-key-to-wif (privkey &key (network :mainnet) (compressed t))
  "Encode a 32-byte private key as WIF for NETWORK (chainparams SECRET_KEY:
#x80 on mainnet, #xef on every test chain). COMPRESSED appends the 0x01 flag,
meaning the corresponding public key is the 33-byte form."
  (base58check-encode (bl.chain:chain-params-base58-secret-prefix
                       (bl.chain:find-chain-params network))
                      (if compressed
                          (concatenate '(vector (unsigned-byte 8)) privkey #(#x01))
                          privkey)))

(defun wif-to-private-key (wif)
  "Decode a WIF string to (VALUES privkey-32-bytes compressed-p version-byte),
or NIL if invalid. VERSION-BYTE is the chainparams SECRET_KEY prefix the key
was encoded under -- compare it with the expected chain's, as Core's
DecodeSecret does; the byte alone cannot tell the test chains apart."
  ;; Core DecodeSecret (key_io.cpp:214-217) bounds this at 34: the
  ;; SECRET_KEY prefix, the 32-byte scalar and the compression flag.
  (multiple-value-bind (version payload) (base58check-decode wif 34)
    (when (and version payload
               (bl.chain:secret-prefix-known-p version)
               (or (= (length payload) 32)
                   (and (= (length payload) 33) (= (aref payload 32) #x01))))
      (values (subseq payload 0 32)
              (= (length payload) 33)
              version))))

;;; ============================================================
;;; Address Version Prefixes
;;; ============================================================


;;; ============================================================
;;; Bech32/Bech32m Encoding/Decoding (BIP 173, BIP 350)
;;; ============================================================

(defparameter *bech32-charset* "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
  "Bech32 character set (32 characters).")

(defparameter *bech32-decode-map*
  (let ((map (make-array 128 :initial-element -1)))
    (loop for i from 0 below 32
          for c = (char *bech32-charset* i)
          do (setf (aref map (char-code c)) i)
             (setf (aref map (char-code (char-upcase c))) i))
    map)
  "Lookup table for Bech32 decoding.")

(defconstant +bech32-const+ 1 "Bech32 checksum constant (BIP 173)")
(defconstant +bech32m-const+ #x2bc830a3 "Bech32m checksum constant (BIP 350)")

(defun bech32-polymod (values)
  "Compute Bech32 polymod checksum."
  (let ((chk 1))
    (dolist (v values)
      (let ((top (ash chk -25)))
        (setf chk (logxor (ash (logand chk #x1ffffff) 5) v))
        (when (logbitp 0 top) (setf chk (logxor chk #x3b6a57b2)))
        (when (logbitp 1 top) (setf chk (logxor chk #x26508e6d)))
        (when (logbitp 2 top) (setf chk (logxor chk #x1ea119fa)))
        (when (logbitp 3 top) (setf chk (logxor chk #x3d4233dd)))
        (when (logbitp 4 top) (setf chk (logxor chk #x2a1462b3)))))
    chk))

(defun bech32-hrp-expand (hrp)
  "Expand HRP for checksum computation."
  (append (mapcar (lambda (c) (ash (char-code c) -5)) (coerce hrp 'list))
          '(0)
          (mapcar (lambda (c) (logand (char-code c) 31)) (coerce hrp 'list))))

(defun bech32-verify-checksum (hrp data)
  "Verify Bech32/Bech32m checksum. Returns :bech32, :bech32m, or NIL."
  (let ((polymod (bech32-polymod (append (bech32-hrp-expand hrp) data))))
    (cond
      ((= polymod +bech32-const+) :bech32)
      ((= polymod +bech32m-const+) :bech32m))))

(defun bech32-create-checksum (hrp data variant)
  "Create Bech32/Bech32m checksum."
  (let* ((const (if (eq variant :bech32m) +bech32m-const+ +bech32-const+))
         (values (append (bech32-hrp-expand hrp) data '(0 0 0 0 0 0)))
         (polymod (logxor (bech32-polymod values) const)))
    (loop for i from 0 below 6
          collect (logand (ash polymod (- (* (- 5 i) 5))) 31))))

(defun bech32-encode (hrp data variant)
  "Encode to Bech32/Bech32m string.
HRP is human-readable part (e.g., 'bc', 'tb').
DATA is list of 5-bit values.
VARIANT is :bech32 or :bech32m."
  (let ((checksum (bech32-create-checksum hrp data variant)))
    (format nil "~(~a~)1~{~c~}"
            hrp
            (mapcar (lambda (d) (char *bech32-charset* d))
                    (append data checksum)))))

(defun bech32-decode (str)
  "Decode a Bech32/Bech32m string.
Returns (VALUES hrp data variant) or NIL if invalid.
DATA is a list of 5-bit values (excluding checksum)."
  ;; Every character must be printable US-ASCII: BIP173 restricts the whole
  ;; string to [33,126] (Core bech32::Decode rejects c < 33 || c > 126). The
  ;; data part is implicitly covered by the charset lookup below, but the HRP
  ;; is not -- without this, a space, DEL or any high byte in the HRP sails
  ;; through and " 1nwldj5" decodes as a valid bech32 string.
  (when (some (lambda (c) (let ((code (char-code c)))
                            (or (< code 33) (> code 126))))
              str)
    (return-from bech32-decode nil))
  ;; Check for mixed case
  (when (and (some #'lower-case-p str) (some #'upper-case-p str))
    (return-from bech32-decode nil))
  (let* ((str (string-downcase str))
         (sep-pos (position #\1 str :from-end t)))
    ;; Validate structure
    (when (or (null sep-pos)
              (< sep-pos 1)
              (< (length str) (+ sep-pos 7))
              (> (length str) 90))
      (return-from bech32-decode nil))
    (let ((hrp (subseq str 0 sep-pos))
          (data-part (subseq str (1+ sep-pos))))
      ;; Decode data part
      (let ((data (loop for c across data-part
                        for code = (char-code c)
                        for d = (if (< code 128) (aref *bech32-decode-map* code) -1)
                        when (minusp d) do (return-from bech32-decode nil)
                        collect d)))
        ;; Verify checksum
        (let ((variant (bech32-verify-checksum hrp data)))
          (when variant
            (values hrp (butlast data 6) variant)))))))

;;;; Bech32 error location (Core bech32::LocateErrors, bech32.cpp:403-572)
;;;;
;;;; A bech32 string whose checksum fails carries more information than "no":
;;;; the BCH code it is built on can locate one or two wrong characters, and
;;;; Core reports those positions so a user mistyping an address is told WHERE
;;;; rather than only THAT. validateaddress returns them as error_locations
;;;; (rpc_invalid_address_message.py compares both the sentence and the
;;;; positions).
;;;;
;;;; The arithmetic is in GF(1024), a degree-2 extension of GF(32) with
;;;; defining polynomial x^2+9x+23; (e), a root of it, generates the field, so
;;;; every non-zero element is (e)^k and multiplication is addition of
;;;; discrete logs. The two tables below are that correspondence, generated
;;;; exactly as Core generates them.

(defun %generate-gf1024-tables ()
  "Core GenerateGFTables (bech32.cpp:46-113). Returns (values exp log): EXP
has 1023 entries with EXP[k] = (e)^k, LOG has 1024 with LOG[EXP[k]] = k and
LOG[0] = -1, the zero element having no logarithm."
  (let ((gf32-exp (make-array 31 :initial-element 0))
        (gf32-log (make-array 32 :initial-element 0))
        (exp (make-array 1023 :initial-element 0))
        (log (make-array 1024 :initial-element 0))
        (fmod 41))                      ; x^5 + x^3 + 1, packed as 101001
    (setf (aref gf32-exp 0) 1
          (aref gf32-log 0) -1
          (aref gf32-log 1) 0)
    (let ((v 1))
      (loop for i from 1 below 31
            do (setf v (ash v 1))
               (when (logtest v 32) (setf v (logxor v fmod)))
               (setf (aref gf32-exp i) v
                     (aref gf32-log v) i)))
    (setf (aref exp 0) 1
          (aref log 0) -1
          (aref log 1) 0)
    ;; v = v1 || v0 as two GF(32) elements; (e)*v = (9*v1 + v0) || (23*v1).
    (let ((v 1))
      (loop for i from 1 below 1023
            do (let* ((v0 (logand v 31))
                      (v1 (ash v -5))
                      (v0n (if (plusp v1)
                               (aref gf32-exp (mod (+ (aref gf32-log v1)
                                                      (aref gf32-log 23))
                                                   31))
                               0))
                      (v1n (logxor (if (plusp v1)
                                       (aref gf32-exp (mod (+ (aref gf32-log v1)
                                                              (aref gf32-log 9))
                                                           31))
                                       0)
                                   v0)))
                 (setf v (logior (ash v1n 5) v0n))
                 (setf (aref exp i) v
                       (aref log v) i))))
    (values exp log)))

(defparameter *gf1024-exp* (nth-value 0 (%generate-gf1024-tables))
  "GF(1024) powers of the generator (e): Core's GF1024_EXP.")

(defparameter *gf1024-log* (nth-value 1 (%generate-gf1024-tables))
  "GF(1024) discrete logarithms: Core's GF1024_LOG, with -1 for zero.")

(defparameter *bech32-syndrome-constants*
  (let ((consts (make-array 25 :initial-element 0)))
    (loop for k from 1 to 5
          do (loop for shift from 0 below 5
                   do (let* ((b (aref *gf1024-log* (ash 1 shift)))
                             (c0 (aref *gf1024-exp* (mod (+ (* 997 k) b) 1023)))
                             (c1 (aref *gf1024-exp* (mod (+ (* 998 k) b) 1023)))
                             (c2 (aref *gf1024-exp* (mod (+ (* 999 k) b) 1023))))
                        (setf (aref consts (+ (* 5 (1- k)) shift))
                              (logior (ash c2 20) (ash c1 10) c0)))))
    consts)
  "Core GenerateSyndromeConstants (bech32.cpp:240-256): the precomputed
(e)^(j*i) for j in 997..999 and each bit of each residue coefficient, packed
three 10-bit values to a word so one pass computes all three syndromes.")

(defun %bech32-syndrome (residue)
  "Core Syndrome (bech32.cpp:261-278): s_997, s_998 and s_999 of the residue
polynomial, packed 10 bits each."
  (let* ((low (logand residue #x1f))
         (result (logxor low (ash low 10) (ash low 20))))
    (dotimes (i 25 result)
      (when (logbitp (+ 5 i) residue)
        (setf result (logxor result (aref *bech32-syndrome-constants* i)))))))

(defun %bech32-character-errors (str)
  "Core CheckCharacters (bech32.cpp:287-309): the indices of characters that
are outside printable ASCII, or that make the string mixed-case. The FIRST
case seen sets the case of the string, so the offenders are the later ones."
  (let ((lower nil) (upper nil) (errors '()))
    (dotimes (i (length str) (nreverse errors))
      (let ((c (char-code (char str i))))
        (cond ((<= (char-code #\a) c (char-code #\z))
               (if upper (push i errors) (setf lower t)))
              ((<= (char-code #\A) c (char-code #\Z))
               (if lower (push i errors) (setf upper t)))
              ((or (< c 33) (> c 126)) (push i errors)))))))

(defun %bech32-single-error (l-s0 l-s1 l-s2 length n)
  "One wrong character, if the syndromes are consistent with exactly one:
s1^2 == s0*s2 in logarithms. Returns a one-element location list or NIL
(bech32.cpp:470-490)."
  (when (and (/= l-s0 -1) (/= l-s1 -1) (/= l-s2 -1)
             (zerop (mod (+ (* 2 l-s1) (- l-s2) (- l-s0) 2046) 1023)))
    (let* ((p1 (mod (+ (- l-s1 l-s0) 1023) 1023))
           (l-e1 (+ l-s0 (* (- 1023 997) p1))))
      ;; The position must be inside the data, and the error value must lie in
      ;; GF(32) -- (e)^(33k). Core does not return the VALUE: suggesting a
      ;; correction would invite the user to trust it.
      (when (and (< p1 length) (zerop (mod l-e1 33)))
        (list (- n p1 1))))))

(defun %bech32-two-errors (s0 s1 s2 l-s0 l-s1 l-s2 length n)
  "Two wrong characters: guess the first position and solve for the second,
keeping the pair only when both error values land in GF(32)
(bech32.cpp:492-556). Returns the two locations, leftmost first, or NIL."
  (loop named search for p1 from 0 below length
        do (block next
             (let ((s2-s1p1 (logxor s2 (if (zerop s1)
                                           0
                                           (aref *gf1024-exp* (mod (+ l-s1 p1) 1023))))))
               (when (zerop s2-s1p1) (return-from next))
               (let ((s1-s0p1 (logxor s1 (if (zerop s0)
                                             0
                                             (aref *gf1024-exp* (mod (+ l-s0 p1) 1023))))))
                 (when (zerop s1-s0p1) (return-from next))
                 (let* ((l-s2-s1p1 (aref *gf1024-log* s2-s1p1))
                        (l-s1-s0p1 (aref *gf1024-log* s1-s0p1))
                        (p2 (mod (+ (- l-s2-s1p1 l-s1-s0p1) 1023) 1023)))
                   (when (or (>= p2 length) (= p1 p2)) (return-from next))
                   (let ((s1-s0p2 (logxor s1 (if (zerop s0)
                                                 0
                                                 (aref *gf1024-exp* (mod (+ l-s0 p2) 1023))))))
                     (when (zerop s1-s0p2) (return-from next))
                     (let* ((l-s1-s0p2 (aref *gf1024-log* s1-s0p2))
                            (inv-p1-p2 (- 1023 (aref *gf1024-log*
                                                     (logxor (aref *gf1024-exp* p1)
                                                             (aref *gf1024-exp* p2)))))
                            (l-e2 (+ l-s1-s0p1 inv-p1-p2 (* (- 1023 997) p2)))
                            (l-e1 (+ l-s1-s0p2 inv-p1-p2 (* (- 1023 997) p1))))
                       (when (or (plusp (mod l-e2 33)) (plusp (mod l-e1 33)))
                         (return-from next))
                       (return-from search
                         (if (> p1 p2)
                             (list (- n p1 1) (- n p2 1))
                             (list (- n p2 1) (- n p1 1)))))))))))) 

(defun bech32-locate-errors (str &optional (limit 90))
  "Core bech32::LocateErrors (bech32.cpp:403-572): why STR is not a bech32
string, and where. Returns (values message locations) -- locations is a list
of 0-based indices into STR, empty when the fault is not localizable.

An empty MESSAGE means the string checksums after all, which is how Core's
callers tell `LocateErrors found nothing' from a real fault."
  (let ((n (length str)))
    (when (> n limit)
      (return-from bech32-locate-errors
        (values "Bech32 string too long" (loop for i from limit below n collect i))))
    (let ((char-errors (%bech32-character-errors str)))
      (when char-errors
        (return-from bech32-locate-errors
          (values "Invalid character or mixed case" char-errors))))
    (let ((pos (position #\1 str :from-end t)))
      (when (null pos)
        (return-from bech32-locate-errors (values "Missing separator" '())))
      (when (or (zerop pos) (>= (+ pos 6) n))
        (return-from bech32-locate-errors
          (values "Invalid separator position" (list pos))))
      (let* ((hrp (string-downcase (subseq str 0 pos)))
             (length (- n 1 pos))
             (values (make-array length :initial-element 0)))
        (loop for i from (1+ pos) below n
              for c = (char-code (char str i))
              for rev = (if (< c 128) (aref *bech32-decode-map* c) -1)
              do (when (minusp rev)
                   (return-from bech32-locate-errors
                     (values "Invalid Base 32 character" (list i))))
                 (setf (aref values (- i pos 1)) rev))
        ;; Both encodings are tried and the one with FEWER located errors wins:
        ;; the witness version may itself be one of the wrong characters, so
        ;; the string cannot be trusted to say which checksum it meant.
        (let ((error-locations '())
              (error-encoding nil)
              (coefficients (append (bech32-hrp-expand hrp) (coerce values 'list))))
          (dolist (encoding '(:bech32 :bech32m))
            (let* ((residue (logxor (bech32-polymod coefficients)
                                    (if (eq encoding :bech32)
                                        +bech32-const+
                                        +bech32m-const+)))
                   (possible
                     (if (zerop residue)
                         ;; A valid codeword under this encoding: nothing to
                         ;; locate, and the caller's own decode said no for
                         ;; some other reason.
                         (return-from bech32-locate-errors (values "" '()))
                         (let* ((syn (%bech32-syndrome residue))
                                (s0 (logand syn #x3ff))
                                (s1 (logand (ash syn -10) #x3ff))
                                (s2 (ash syn -20))
                                (l-s0 (aref *gf1024-log* s0))
                                (l-s1 (aref *gf1024-log* s1))
                                (l-s2 (aref *gf1024-log* s2)))
                           (or (%bech32-single-error l-s0 l-s1 l-s2 length n)
                               (and (not (and (/= l-s0 -1) (/= l-s1 -1) (/= l-s2 -1)
                                              (zerop (mod (+ (* 2 l-s1) (- l-s2)
                                                             (- l-s0) 2046)
                                                          1023))))
                                    (%bech32-two-errors s0 s1 s2 l-s0 l-s1 l-s2
                                                        length n)))))))
              (when (or (null error-locations)
                        (and possible (< (length possible) (length error-locations))))
                (setf error-locations possible)
                (when error-locations (setf error-encoding encoding)))))
          (values (case error-encoding
                    (:bech32m "Invalid Bech32m checksum")
                    (:bech32 "Invalid Bech32 checksum")
                    (t "Invalid checksum"))
                  error-locations))))))


(defun convert-bits (data from-bits to-bits &key pad)
  "Convert between bit widths (e.g., 8-bit to 5-bit)."
  (let ((acc 0)
        (bits 0)
        (result '())
        (maxv (1- (ash 1 to-bits))))
    (dolist (value data)
      (setf acc (logior (ash acc from-bits) value))
      (incf bits from-bits)
      (loop while (>= bits to-bits)
            do (decf bits to-bits)
               (push (logand (ash acc (- bits)) maxv) result)))
    (when pad
      (when (plusp bits)
        (push (logand (ash acc (- to-bits bits)) maxv) result)))
    (when (and (not pad)
               (or (>= bits from-bits)
                   (plusp (logand acc (1- (ash 1 bits))))))
      (return-from convert-bits nil))
    (nreverse result)))

;;; ============================================================
;;; SegWit Address Encoding/Decoding
;;; ============================================================

(defun segwit-address-encode (hrp witness-version witness-program)
  "Encode a SegWit address.
WITNESS-VERSION is 0-16.
WITNESS-PROGRAM is byte vector.
Uses Bech32 for v0, Bech32m for v1+."
  (let ((variant (if (zerop witness-version) :bech32 :bech32m))
        (data5 (convert-bits (coerce witness-program 'list) 8 5 :pad t)))
    (bech32-encode hrp (cons witness-version data5) variant)))

(defun segwit-address-decode (str)
  "Decode a SegWit address.
Returns (VALUES hrp witness-version witness-program) or NIL."
  (multiple-value-bind (hrp data variant) (bech32-decode str)
    (when (and hrp data (>= (length data) 1))
      (let ((witness-version (first data))
            (data5 (rest data)))
        ;; Validate witness version
        (when (or (> witness-version 16)
                  ;; v0 must use bech32, v1+ must use bech32m
                  (and (zerop witness-version) (not (eq variant :bech32)))
                  (and (plusp witness-version) (not (eq variant :bech32m))))
          (return-from segwit-address-decode nil))
        ;; Convert 5-bit to 8-bit
        (let ((program (convert-bits data5 5 8 :pad nil)))
          (when program
            ;; Validate program length
            (let ((len (length program)))
              (when (and (>= len 2) (<= len 40)
                         ;; v0 must be 20 or 32 bytes
                         (or (plusp witness-version)
                             (= len 20) (= len 32)))
                (values hrp
                        witness-version
                        (coerce program '(vector (unsigned-byte 8))))))))))))

;;; ============================================================
;;; High-Level Address Functions
;;; ============================================================

(defun decode-address (address network)
  "Decode a Bitcoin address and return its components.
Returns (VALUES type script-pubkey witness-version witness-program) or NIL.
TYPE is :p2pkh, :p2sh, :p2wpkh, :p2wsh, or :p2tr.
SCRIPT-PUBKEY is the corresponding scriptPubKey bytes.
NETWORK is :testnet3, :testnet4, :signet, or :mainnet."
  (let ((expected-hrp (segwit-hrp network)))
    ;; Try SegWit (Bech32/Bech32m) first
    (multiple-value-bind (hrp wit-ver wit-prog) (segwit-address-decode address)
      (when (and hrp (string= hrp expected-hrp))
        (let ((script-pubkey
                (concatenate '(vector (unsigned-byte 8))
                             (vector (if (zerop wit-ver) #x00 (+ #x50 wit-ver)))
                             (vector (length wit-prog))
                             wit-prog))
              (type (cond
                      ((and (zerop wit-ver) (= (length wit-prog) 20)) :p2wpkh)
                      ((and (zerop wit-ver) (= (length wit-prog) 32)) :p2wsh)
                      ((and (= wit-ver 1) (= (length wit-prog) 32)) :p2tr)
                      (t :unknown-witness))))
          (return-from decode-address
            (values type script-pubkey wit-ver wit-prog)))))
    ;; Try Base58Check
    ;; Core DecodeDestination (key_io.cpp:93) bounds this at 21: the version
    ;; byte and a 20-byte hash160.
    (multiple-value-bind (version payload) (base58check-decode address 21)
      (when version
        ;; Core DecodeDestination: the version byte must be THIS chain's
        ;; PUBKEY_ADDRESS or SCRIPT_ADDRESS prefix (the test chains share one pair).
        (let* ((params (bl.chain:find-chain-params network))
               (type (cond ((= version (bl.chain:chain-params-base58-pubkey-prefix params)) :p2pkh)
                           ((= version (bl.chain:chain-params-base58-script-prefix params)) :p2sh))))
          (when (and type
                     (= (length payload) 20))
            (let ((script-pubkey
                    (case type
                      (:p2pkh
                       ;; OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
                       (concatenate '(vector (unsigned-byte 8))
                                    #(#x76 #xa9 #x14) payload #(#x88 #xac)))
                      (:p2sh
                       ;; OP_HASH160 <20 bytes> OP_EQUAL
                       (concatenate '(vector (unsigned-byte 8))
                                    #(#xa9 #x14) payload #(#x87))))))
              (return-from decode-address
                (values type script-pubkey nil payload)))))))
    nil))

(defun decode-address-error (address network)
  "Why ADDRESS is not an address on NETWORK, as Core says it: the error_str
and error_locations DecodeDestination fills in (key_io.cpp:84-207). Returns
(values message locations), locations being 0-based indices into ADDRESS and
empty for every fault that is not one or two wrong bech32 characters.

Core decides between the two encodings by PREFIX, not by trying both: a
string starting with this chain's bech32 HRP is judged as bech32 and never
falls back to base58 (:91-92), which is why a mistyped bech32 address is
answered with a checksum position rather than `not base58'.

Only reached once DECODE-ADDRESS has refused the string, so every branch here
ends in a message; the shapes that would succeed are the ones DECODE-ADDRESS
already returned."
  (let* ((hrp (segwit-hrp network))
         (is-bech32 (and (>= (length address) (length hrp))
                         (string-equal hrp (subseq address 0 (length hrp))))))
    (if (not is-bech32)
        ;; Base58: a valid checksum means the prefix or the length is wrong,
        ;; and Core tells those two apart (:110-118). No checksum at all is
        ;; either a base58 string that is not an address or not base58 at all
        ;; (:120-126).
        (multiple-value-bind (version payload) (base58check-decode address 21)
          (declare (ignore payload))
          (if version
              (let ((params (bl.chain:find-chain-params network)))
                (values (if (or (= version (bl.chain:chain-params-base58-pubkey-prefix params))
                                (= version (bl.chain:chain-params-base58-script-prefix params)))
                            "Invalid length for Base58 address (P2PKH or P2SH)"
                            "Invalid or unsupported Base58-encoded address.")
                        '()))
              (if (base58-decode address 100)
                  (values "Invalid checksum or length of Base58 address (P2PKH or P2SH)" '())
                  (values "Invalid or unsupported Segwit (Bech32) or Base58 encoding." '()))))
        (multiple-value-bind (decoded-hrp data variant) (bech32-decode address)
          (if (null variant)
              ;; The string does not checksum: locate the fault (:205-207).
              (bech32-locate-errors address)
              (cond
                ((null data) (values "Empty Bech32 data section" '()))
                ((not (string= decoded-hrp hrp))
                 (values (format nil "Invalid or unsupported prefix for Segwit (Bech32) address (expected ~A, got ~A)."
                                 hrp decoded-hrp)
                         '()))
                (t
                 (let ((version (first data)))
                   (cond
                     ;; The checksum and the witness version must agree: v0 is
                     ;; Bech32, v1+ is Bech32m (BIP350).
                     ((and (zerop version) (not (eq variant :bech32)))
                      (values "Version 0 witness address must use Bech32 checksum" '()))
                     ((and (plusp version) (not (eq variant :bech32m)))
                      (values "Version 1+ witness address must use Bech32m checksum" '()))
                     (t
                      (let ((program (convert-bits (rest data) 5 8 :pad nil)))
                        (if (null program)
                            (values "Invalid padding in Bech32 data section" '())
                            (let* ((size (length program))
                                   (byte-str (if (= size 1) "byte" "bytes")))
                              (cond
                                ;; BIP141 fixes v0 at 20 or 32 bytes; the
                                ;; message names the size that was offered.
                                ((zerop version)
                                 (values (format nil "Invalid Bech32 v0 address program size (~D ~A), per BIP141"
                                                 size byte-str)
                                         '()))
                                ((> version 16)
                                 (values "Invalid Bech32 address witness version" '()))
                                (t
                                 (values (format nil "Invalid Bech32 address program size (~D ~A)"
                                                 size byte-str)
                                         '()))))))))))))))))

(defun encode-p2pkh-address (pubkey-hash network)
  "Encode a 20-byte pubkey hash as a P2PKH address (chainparams PUBKEY_ADDRESS)."
  (base58check-encode (bl.chain:chain-params-base58-pubkey-prefix
                       (bl.chain:find-chain-params network))
                      pubkey-hash))

(defun encode-p2sh-address (script-hash network)
  "Encode a 20-byte script hash as a P2SH address (chainparams SCRIPT_ADDRESS)."
  (base58check-encode (bl.chain:chain-params-base58-script-prefix
                       (bl.chain:find-chain-params network))
                      script-hash))

(defun segwit-hrp (network)
  "Bech32 human-readable part for NETWORK (Core chainparams bech32_hrp):
bc mainnet, tb test chains, bcrt regtest."
  (bl.chain:chain-params-bech32-hrp (bl.chain:find-chain-params network)))

(defun encode-p2wpkh-address (pubkey-hash network)
  "Encode a 20-byte pubkey hash as P2WPKH address."
  (segwit-address-encode (segwit-hrp network) 0 pubkey-hash))

(defun encode-p2wsh-address (script-hash network)
  "Encode a 32-byte script hash as P2WSH address."
  (segwit-address-encode (segwit-hrp network) 0 script-hash))

(defun encode-p2tr-address (output-key network)
  "Encode a 32-byte output key as P2TR address."
  (segwit-address-encode (segwit-hrp network) 1 output-key))
