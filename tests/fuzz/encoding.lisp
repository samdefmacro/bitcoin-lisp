(in-package #:bitcoin-lisp.tests)

;;;; Core's text-encoding targets at the pin: fuzz/base_encode_decode.cpp
;;;; (base58, base58check, base32, base64, psbt_base64_decode), bech32.cpp
;;;; (bech32_random_decode, bech32_roundtrip), key_io.cpp.

(def-suite :fuzz-encoding-tests :in :bitcoin-lisp-tests
  :description "Core fuzz base_encode_decode.cpp / bech32.cpp / key_io.cpp targets")

(in-suite :fuzz-encoding-tests)

(defun %trim-core-space (string)
  "Core TrimStringView: the six IsSpace characters off both ends."
  (string-trim (list #\Space #\Page #\Newline #\Return #\Tab (code-char 11)) string))

(defun %be-integer (bytes)
  (loop for b across bytes for acc = b then (+ (* acc 256) b) finally (return (or acc 0))))

(defun %octets-of-string (string)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

;;; --- base_encode_decode.cpp ----------------------------------------------------

(define-fuzz-target base58-encode-decode
    (buffer :core "base_encode_decode.cpp:20-36" :iterations 8000 :max-len 160)
  "DecodeBase58 inverts EncodeBase58 up to the whitespace it trims, and its
length bound is exact: a decoding of N bytes needed a bound of at least N and
fails under any smaller one."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (random (consume-random-length-string fdp 100))
         (encoded (bl.crypto:base58-encode (%octets-of-string random)))
         (input (if (consume-bool fdp) random encoded))
         (max-len (consume-integral-in-range fdp -1 (1+ (length input)) 32))
         (decoded (bl.crypto:base58-decode input max-len)))
    (when decoded
      (let ((again (bl.crypto:base58-encode decoded)))
        (fuzz-assert (string= (fuzz-sabotage again) (%trim-core-space input))
                     "~S decodes to bytes that encode as ~S" input again))
      (when (plusp (length decoded))
        (fuzz-assert (and (plusp max-len) (<= (length decoded) max-len))
                     "~D bytes decoded under a bound of ~D" (length decoded) max-len)
        (fuzz-assert (null (bl.crypto:base58-decode
                            input (consume-integral-in-range fdp 0 (1- (length decoded)) 32)))
                     "~S decodes under a bound smaller than its length" input)))))

(define-fuzz-target base58check-encode-decode
    (buffer :core "base_encode_decode.cpp:38-54" :iterations 8000 :max-len 160)
  "DecodeBase58Check inverts EncodeBase58Check (version byte and payload,
checksum appended) up to trimmed whitespace, under the same exact bound."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (random (consume-random-length-string fdp 100))
         (data (%octets-of-string random))
         (encoded (if (plusp (length data))
                      (bl.crypto:base58check-encode (aref data 0) (subseq data 1))
                      random))
         (input (if (consume-bool fdp) random encoded))
         (max-len (consume-integral-in-range fdp -1 (1+ (length input)) 32)))
    (multiple-value-bind (version payload) (bl.crypto:base58check-decode input max-len)
      (when version
        (let ((again (bl.crypto:base58check-encode version payload)))
          (fuzz-assert (string= (fuzz-sabotage again) (%trim-core-space input))
                       "~S decodes to bytes that encode as ~S" input again))
        (fuzz-assert (and (plusp max-len) (<= (1+ (length payload)) max-len))
                     "~D bytes decoded under a bound of ~D" (1+ (length payload)) max-len)
        (fuzz-assert (null (bl.crypto:base58check-decode
                            input (consume-integral-in-range fdp 0 (length payload) 32)))
                     "~S decodes under a bound smaller than its length" input)))))

(define-fuzz-target base32-encode-decode
    (buffer :core "base_encode_decode.cpp:56-69" :iterations 8000 :max-len 120)
  "DecodeBase32 of any string that decodes re-encodes to that string in lower
case, and any bytes survive EncodeBase32 (padded) then DecodeBase32."
  (let* ((string (map 'string #'code-char buffer))
         (decoded (bl.net:base32-decode string)))
    (when decoded
      (fuzz-assert (string= (bl.net:base32-encode decoded :pad t) (string-downcase string))
                   "~S decodes to bytes that encode differently" string))
    (fuzz-assert (equalp (fuzz-sabotage (bl.net:base32-decode (bl.net:base32-encode buffer :pad t)))
                         buffer)
                 "~A does not survive base32" (bl.crypto:bytes-to-hex buffer))))

(define-fuzz-target base64-encode-decode
    (buffer :core "base_encode_decode.cpp:71-84" :iterations 8000 :max-len 120)
  "DecodeBase64 of any string that decodes re-encodes to that string, and any
bytes survive EncodeBase64 then DecodeBase64."
  (let* ((string (map 'string #'code-char buffer))
         (decoded (bl.ser:decode-base64 string)))
    (when decoded
      (fuzz-assert (string= (bl.ser:encode-base64 decoded) (%trim-core-space string))
                   "~S decodes to bytes that encode differently" string))
    (fuzz-assert (equalp (fuzz-sabotage (bl.ser:decode-base64 (bl.ser:encode-base64 buffer))) buffer)
                 "~A does not survive base64" (bl.crypto:bytes-to-hex buffer))))

(define-fuzz-target psbt-base64-decode
    (buffer :core "base_encode_decode.cpp:86-94" :iterations 4000 :max-len 400
            :control :parse :min-reached 0
            :corpus (lambda (fdp)
                      (%octets-of-string
                       (bl.ser:encode-psbt
                        (bl.ser:make-empty-psbt (consume-transaction fdp :max-num-in 2 :max-num-out 2))))))
  "DecodeBase64PSBT succeeds exactly when it reports no error: any text is a
PSBT, or is refused with the declared condition and Core's message."
  (fuzz-deserialize (bl.ser:decode-psbt (map 'string #'code-char buffer))))

;;; --- bech32.cpp --------------------------------------------------------------------

(define-fuzz-target bech32-random-decode
    (buffer :core "bech32.cpp:18-34" :iterations 8000 :max-len 120
            :corpus (lambda (fdp)
                      (%octets-of-string
                       (bl.crypto:bech32-encode
                        (pick-value-in-array fdp '("bc" "tb" "bcrt" "a" "an83characterlonghumanreadablepart"))
                        (map 'list (lambda (b) (ldb (byte 5 0) b)) (consume-bytes fdp (consume-integral-in-range fdp 0 40)))
                        (pick-value-in-array fdp '(:bech32 :bech32m))))))
  "bech32::Decode of any string: a decoding with no HRP has no encoding and no
data; one with an HRP has an encoding and re-encodes to the same string, up
to case."
  (let ((string (consume-random-length-string (make-fuzzed-data-provider buffer) 91)))
    (multiple-value-bind (hrp data variant) (bl.crypto:bech32-decode string)
      (if (or (null hrp) (zerop (length hrp)))
          (fuzz-assert (and (null data) (null variant)) "no HRP, but data or an encoding")
          (progn
            (fuzz-assert (member variant '(:bech32 :bech32m)) "an HRP but no encoding")
            (fuzz-assert (string-equal (fuzz-sabotage (bl.crypto:bech32-encode hrp data variant)) string)
                         "~S decodes to something that encodes otherwise" string))))))

(define-fuzz-target bech32-roundtrip
    (buffer :core "bech32.cpp:36-73" :iterations 8000 :max-len 160)
  "Any HRP of lower-case printable characters and any data within the 90
character limit encode, in both variants, to a string that decodes to that
encoding, HRP and data."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (hrp (coerce (loop repeat (consume-integral-in-range fdp 1 83)
                            collect (code-char (if (consume-bool fdp)
                                                   (consume-integral-in-range fdp 33 64 8)
                                                   (consume-integral-in-range fdp 91 126 8))))
                      'string))
         (input (consume-bytes fdp (consume-integral-in-range fdp 0 82)))
         (data (bl.crypto:convert-bits (coerce input 'list) 8 5 :pad t)))
    (when (<= (+ (length data) (length hrp) 1 6) 90)
      (dolist (variant '(:bech32 :bech32m))
        (let ((encoded (bl.crypto:bech32-encode hrp data variant)))
          (fuzz-assert (plusp (length encoded)) "nothing encoded")
          (multiple-value-bind (dhrp ddata dvariant) (bl.crypto:bech32-decode encoded)
            (fuzz-assert (eq dvariant (fuzz-sabotage variant)) "~S decodes as ~S" variant dvariant)
            (fuzz-assert (equal dhrp hrp) "HRP ~S decodes as ~S" hrp dhrp)
            (fuzz-assert (equal ddata data) "the data does not survive")))))))

;;; --- key_io.cpp --------------------------------------------------------------------

(defun %key-io-corpus (fdp)
  "A WIF, an xprv or an xpub on one of the five chains, over a key the input
chooses -- invalid scalars included."
  (let ((network (pick-value-in-array fdp +fuzz-networks+)))
    (%octets-of-string
     (call-one-of fdp
       (bl.crypto:private-key-to-wif (consume-uint256 fdp) :network network
                                                            :compressed (consume-bool fdp))
       (let ((seed (consume-bytes fdp 32)))
         (handler-case
             (let ((k (bl.crypto:bip32-master-key (if (< (length seed) 16) (make-array 16 :element-type '(unsigned-byte 8) :initial-element 7) seed)
                                                  :network network)))
               (loop repeat (consume-integral-in-range fdp 0 3)
                     do (setf k (bl.crypto:bip32-derive-child k (consume-integral fdp :u32))))
               (bl.crypto:bip32-serialize (if (consume-bool fdp) (bl.crypto:bip32-neuter k) k)))
           (bl.err:crypto-error () "")))))))

(define-fuzz-target key-io
    (buffer :core "key_io.cpp:23-40" :iterations 3000 :max-len 120
            :corpus #'%key-io-corpus)
  "DecodeSecret yields a valid key or none, and a valid key survives
EncodeSecret; an extended private or public key that decodes survives its
encoding -- on every chain."
  (let ((string (map 'string #'code-char buffer)))
    (multiple-value-bind (privkey compressed version) (bl.crypto:wif-to-private-key string)
      (when privkey
        (fuzz-assert (< 0 (%be-integer privkey) bl.crypto:+secp256k1-order+)
                     "~S decodes to an invalid secret" string)
        (let ((network (if (= version #x80) :mainnet :testnet3)))
          (fuzz-assert (equalp (fuzz-sabotage privkey)
                               (bl.crypto:wif-to-private-key
                                (bl.crypto:private-key-to-wif privkey :network network
                                                                      :compressed compressed)))
                       "~S does not survive EncodeSecret" string))))
    (dolist (network +fuzz-networks+)
      (let ((key (bl.crypto:bip32-parse string network)))
        (when key
          (let ((again (bl.crypto:bip32-serialize key)))
            (fuzz-assert (string= (fuzz-sabotage again)
                                  (bl.crypto:bip32-serialize (bl.crypto:bip32-parse again network)))
                         "~S does not survive its encoding on ~S" string network)))))))
