(in-package #:bitcoin-lisp.tests)

(in-suite :crypto-tests)

(test sha256-empty-input
  "SHA256 of empty input should match known hash."
  (let ((result (bitcoin-lisp.crypto:sha256
                 (make-array 0 :element-type '(unsigned-byte 8)))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))))

(test sha256-hello
  "SHA256 of 'hello' should match known hash."
  (let ((result (bitcoin-lisp.crypto:sha256
                 (flexi-streams:string-to-octets "hello" :external-format :ascii))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")))))

(test hash256-double-sha256
  "Hash256 should compute double SHA256."
  (let* ((input (flexi-streams:string-to-octets "hello" :external-format :ascii))
         (single (bitcoin-lisp.crypto:sha256 input))
         (double (bitcoin-lisp.crypto:sha256 single))
         (hash256 (bitcoin-lisp.crypto:hash256 input)))
    (is (equalp hash256 double))))

(test ripemd160-hello
  "RIPEMD160 of 'hello' should match known hash."
  (let ((result (bitcoin-lisp.crypto:ripemd160
                 (flexi-streams:string-to-octets "hello" :external-format :ascii))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "108f07b8382412612c048d07d13f814118445acd")))))

(test hash160-pubkey-hash
  "Hash160 should compute RIPEMD160(SHA256(x))."
  (let* ((input (flexi-streams:string-to-octets "test" :external-format :ascii))
         (sha (bitcoin-lisp.crypto:sha256 input))
         (ripe (bitcoin-lisp.crypto:ripemd160 sha))
         (hash160 (bitcoin-lisp.crypto:hash160 input)))
    (is (equalp hash160 ripe))))

;;; --- Address Encoding Tests ---

(test base58-encode-decode-roundtrip
  "Test Base58 encode/decode round-trip."
  (let* ((original #(1 2 3 4 5 6 7 8 9 10))
         (encoded (bitcoin-lisp.crypto:base58-encode original))
         (decoded (bitcoin-lisp.crypto:base58-decode encoded)))
    (is (stringp encoded))
    (is (vectorp decoded))
    (is (equalp original decoded))))

(test base58-leading-zeros
  "Test Base58 preserves leading zeros as '1' characters."
  (let* ((with-zeros #(0 0 0 1 2 3))
         (encoded (bitcoin-lisp.crypto:base58-encode with-zeros)))
    (is (char= (char encoded 0) #\1))
    (is (char= (char encoded 1) #\1))
    (is (char= (char encoded 2) #\1))))

(test base58check-encode-decode
  "Test Base58Check encode/decode with checksum."
  (let* ((payload #(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))
         (version 111)  ; Testnet P2PKH
         (encoded (bitcoin-lisp.crypto:base58check-encode version payload)))
    (multiple-value-bind (dec-version dec-payload)
        (bitcoin-lisp.crypto:base58check-decode encoded)
      (is (= dec-version version))
      (is (equalp dec-payload payload)))))

(test base58check-invalid-checksum
  "Test Base58Check detects invalid checksum."
  ;; A valid address with modified character to corrupt checksum
  (let ((invalid "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfX"))  ; Changed last char
    (is (null (bitcoin-lisp.crypto:base58check-decode invalid)))))

(test bech32-encode-decode-v0
  "Test Bech32 encode/decode for witness v0."
  (let* ((hrp "tb")
         (data '(0 14 20 15 7 13 26 0 25 18 6 11 13 8 21 4 20 3 17 2 29 3 12 29 3 4 15 24 20 6 11 29 8))
         (encoded (bitcoin-lisp.crypto:bech32-encode hrp data :bech32)))
    (multiple-value-bind (dec-hrp dec-data dec-variant)
        (bitcoin-lisp.crypto:bech32-decode encoded)
      (is (string= dec-hrp hrp))
      (is (equal dec-data data))
      (is (eq dec-variant :bech32)))))

(test segwit-address-p2wpkh
  "Test SegWit P2WPKH address encoding/decoding."
  (let* ((hrp "tb")
         (witness-version 0)
         (witness-program (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x42))
         (address (bitcoin-lisp.crypto:segwit-address-encode hrp witness-version witness-program)))
    (multiple-value-bind (dec-hrp dec-version dec-program)
        (bitcoin-lisp.crypto:segwit-address-decode address)
      (is (string= dec-hrp hrp))
      (is (= dec-version witness-version))
      (is (equalp dec-program witness-program)))))

(test segwit-address-p2tr
  "Test SegWit P2TR (Taproot) address encoding/decoding."
  (let* ((hrp "tb")
         (witness-version 1)
         (witness-program (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
         (address (bitcoin-lisp.crypto:segwit-address-encode hrp witness-version witness-program)))
    ;; Should use bech32m for v1+
    (multiple-value-bind (dec-hrp dec-version dec-program)
        (bitcoin-lisp.crypto:segwit-address-decode address)
      (is (string= dec-hrp hrp))
      (is (= dec-version witness-version))
      (is (equalp dec-program witness-program)))))

(test decode-address-p2pkh-testnet
  "Test decode-address for testnet P2PKH."
  (multiple-value-bind (type script-pubkey wit-ver wit-prog)
      (bitcoin-lisp.crypto:decode-address "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" :testnet)
    (is (eq type :p2pkh))
    (is (vectorp script-pubkey))
    (is (null wit-ver))
    ;; P2PKH scriptPubKey is 25 bytes
    (is (= (length script-pubkey) 25))))

(test decode-address-p2wpkh-testnet
  "Test decode-address for testnet P2WPKH."
  (multiple-value-bind (type script-pubkey wit-ver wit-prog)
      (bitcoin-lisp.crypto:decode-address "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" :testnet)
    (is (eq type :p2wpkh))
    (is (vectorp script-pubkey))
    (is (= wit-ver 0))
    (is (= (length wit-prog) 20))))

(test decode-address-wrong-network
  "Test decode-address returns nil for wrong network."
  ;; Mainnet address on testnet
  (is (null (bitcoin-lisp.crypto:decode-address "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" :testnet)))
  ;; Testnet address on mainnet
  (is (null (bitcoin-lisp.crypto:decode-address "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" :mainnet))))

;;; --- SipHash-2-4 Tests (BIP 152) ---

(test siphash-empty-input
  "SipHash-2-4 of empty input with zero keys."
  (let ((result (bitcoin-lisp.crypto:siphash-2-4 0 0 #())))
    (is (integerp result))
    (is (<= 0 result (1- (expt 2 64))))))

(test siphash-deterministic
  "SipHash-2-4 is deterministic."
  (let ((data #(1 2 3 4 5 6 7 8))
        (k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908))
    (is (= (bitcoin-lisp.crypto:siphash-2-4 k0 k1 data)
           (bitcoin-lisp.crypto:siphash-2-4 k0 k1 data)))))

(test siphash-different-keys
  "SipHash-2-4 produces different results for different keys."
  (let ((data #(1 2 3 4 5 6 7 8)))
    (is (not (= (bitcoin-lisp.crypto:siphash-2-4 0 0 data)
                (bitcoin-lisp.crypto:siphash-2-4 1 0 data))))))

(test siphash-different-data
  "SipHash-2-4 produces different results for different data."
  (let ((k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908))
    (is (not (= (bitcoin-lisp.crypto:siphash-2-4 k0 k1 #(1 2 3))
                (bitcoin-lisp.crypto:siphash-2-4 k0 k1 #(1 2 4)))))))

(test siphash-test-vector
  "SipHash-2-4 test vector from reference implementation."
  ;; Test vector: 15-byte input with standard test keys
  (let* ((k0 #x0706050403020100)
         (k1 #x0f0e0d0c0b0a0908)
         (data (make-array 15 :element-type '(unsigned-byte 8)
                           :initial-contents '(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14)))
         (result (bitcoin-lisp.crypto:siphash-2-4 k0 k1 data)))
    ;; Expected value from SipHash reference implementation
    (is (= result #xa129ca6149be45e5))))

(test compute-siphash-key-deterministic
  "compute-siphash-key is deterministic."
  (let ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 0))
        (nonce #x123456789abcdef0))
    (multiple-value-bind (k0a k1a)
        (bitcoin-lisp.crypto:compute-siphash-key header nonce)
      (multiple-value-bind (k0b k1b)
          (bitcoin-lisp.crypto:compute-siphash-key header nonce)
        (is (= k0a k0b))
        (is (= k1a k1b))))))

(test compute-siphash-key-different-nonce
  "compute-siphash-key produces different keys for different nonces."
  (let ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 0)))
    (multiple-value-bind (k0a k1a)
        (bitcoin-lisp.crypto:compute-siphash-key header 0)
      (multiple-value-bind (k0b k1b)
          (bitcoin-lisp.crypto:compute-siphash-key header 1)
        (is (or (not (= k0a k0b))
                (not (= k1a k1b))))))))

(test compute-short-txid-truncation
  "compute-short-txid returns 48-bit value."
  (let ((k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908)
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (let ((short-id (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid)))
      (is (integerp short-id))
      (is (<= 0 short-id #xffffffffffff))  ; 6 bytes max
      (is (< short-id (expt 2 48))))))

(test compute-short-txid-different-txids
  "compute-short-txid produces different IDs for different transactions."
  (let ((k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908)
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x00))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xff)))
    (is (not (= (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid1)
                (bitcoin-lisp.crypto:compute-short-txid k0 k1 txid2))))))
