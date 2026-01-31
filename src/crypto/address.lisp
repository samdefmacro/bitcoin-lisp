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

(defun base58-decode (str)
  "Decode a Base58 string to byte vector.
Returns NIL if string contains invalid characters."
  (let ((leading-ones 0))
    ;; Count leading '1's (representing zero bytes)
    (loop for c across str
          while (char= c #\1)
          do (incf leading-ones))
    ;; Convert from base58 to big integer
    (let ((num 0))
      (loop for c across str
            for code = (char-code c)
            for digit = (if (< code 128) (aref *base58-decode-map* code) -1)
            do (when (minusp digit)
                 (return-from base58-decode nil))
               (setf num (+ (* num 58) digit)))
      ;; Convert big integer to bytes
      (let ((result-bytes '()))
        (loop while (plusp num)
              do (push (logand num #xff) result-bytes)
                 (setf num (ash num -8)))
        ;; Add leading zero bytes
        (concatenate '(vector (unsigned-byte 8))
                     (make-array leading-ones :element-type '(unsigned-byte 8)
                                              :initial-element 0)
                     (coerce result-bytes '(vector (unsigned-byte 8))))))))

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

(defun base58check-decode (str)
  "Decode a Base58Check string.
Returns (VALUES version payload) or NIL if invalid."
  (let ((bytes (base58-decode str)))
    (when (and bytes (>= (length bytes) 5))
      (let* ((version (aref bytes 0))
             (payload (subseq bytes 1 (- (length bytes) 4)))
             (checksum (subseq bytes (- (length bytes) 4)))
             (expected (subseq (hash256 (subseq bytes 0 (- (length bytes) 4))) 0 4)))
        (when (equalp checksum expected)
          (values version payload))))))

;;; ============================================================
;;; Address Version Prefixes
;;; ============================================================

(defconstant +p2pkh-version-mainnet+ #x00)
(defconstant +p2pkh-version-testnet+ #x6f)
(defconstant +p2sh-version-mainnet+ #x05)
(defconstant +p2sh-version-testnet+ #xc4)

(defun address-version-to-type (version)
  "Convert address version byte to address type and network.
Returns (VALUES type network) or NIL."
  (case version
    (#x00 (values :p2pkh :mainnet))
    (#x6f (values :p2pkh :testnet))
    (#x05 (values :p2sh :mainnet))
    (#xc4 (values :p2sh :testnet))
    (otherwise nil)))

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
      ((= polymod +bech32m-const+) :bech32m)
      (t nil))))

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
NETWORK is :testnet or :mainnet."
  (let ((expected-hrp (if (eq network :testnet) "tb" "bc")))
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
    (multiple-value-bind (version payload) (base58check-decode address)
      (when version
        (multiple-value-bind (type addr-network) (address-version-to-type version)
          (when (and type (eq addr-network network) (= (length payload) 20))
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

(defun encode-p2pkh-address (pubkey-hash network)
  "Encode a 20-byte pubkey hash as P2PKH address."
  (let ((version (if (eq network :testnet)
                     +p2pkh-version-testnet+
                     +p2pkh-version-mainnet+)))
    (base58check-encode version pubkey-hash)))

(defun encode-p2sh-address (script-hash network)
  "Encode a 20-byte script hash as P2SH address."
  (let ((version (if (eq network :testnet)
                     +p2sh-version-testnet+
                     +p2sh-version-mainnet+)))
    (base58check-encode version script-hash)))

(defun encode-p2wpkh-address (pubkey-hash network)
  "Encode a 20-byte pubkey hash as P2WPKH address."
  (let ((hrp (if (eq network :testnet) "tb" "bc")))
    (segwit-address-encode hrp 0 pubkey-hash)))

(defun encode-p2wsh-address (script-hash network)
  "Encode a 32-byte script hash as P2WSH address."
  (let ((hrp (if (eq network :testnet) "tb" "bc")))
    (segwit-address-encode hrp 0 script-hash)))

(defun encode-p2tr-address (output-key network)
  "Encode a 32-byte output key as P2TR address."
  (let ((hrp (if (eq network :testnet) "tb" "bc")))
    (segwit-address-encode hrp 1 output-key)))
