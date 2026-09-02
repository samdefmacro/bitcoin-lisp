(in-package #:bitcoin-lisp.tests)

(in-suite :crypto-tests)

(test sha256-empty-input
  "SHA256 of empty input should match known hash."
  (let ((result (bl.crypto:sha256
                 (make-array 0 :element-type '(unsigned-byte 8)))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")))))

(test sha256-hello
  "SHA256 of 'hello' should match known hash."
  (let ((result (bl.crypto:sha256
                 (flexi-streams:string-to-octets "hello" :external-format :ascii))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")))))

(test hash256-double-sha256
  "Hash256 should compute double SHA256."
  (let* ((input (flexi-streams:string-to-octets "hello" :external-format :ascii))
         (single (bl.crypto:sha256 input))
         (double (bl.crypto:sha256 single))
         (hash256 (bl.crypto:hash256 input)))
    (is (equalp hash256 double))))

(test ripemd160-hello
  "RIPEMD160 of 'hello' should match known hash."
  (let ((result (bl.crypto:ripemd160
                 (flexi-streams:string-to-octets "hello" :external-format :ascii))))
    (is (equalp result
                (ironclad:hex-string-to-byte-array
                 "108f07b8382412612c048d07d13f814118445acd")))))

(test hash160-pubkey-hash
  "Hash160 should compute RIPEMD160(SHA256(x))."
  (let* ((input (flexi-streams:string-to-octets "test" :external-format :ascii))
         (sha (bl.crypto:sha256 input))
         (ripe (bl.crypto:ripemd160 sha))
         (hash160 (bl.crypto:hash160 input)))
    (is (equalp hash160 ripe))))

;;; --- Address Encoding Tests ---

(test base58-encode-decode-roundtrip
  "Test Base58 encode/decode round-trip."
  (let* ((original #(1 2 3 4 5 6 7 8 9 10))
         (encoded (bl.crypto:base58-encode original))
         (decoded (bl.crypto:base58-decode encoded)))
    (is (stringp encoded))
    (is (vectorp decoded))
    (is (equalp original decoded))))

(test base58-leading-zeros
  "Test Base58 preserves leading zeros as '1' characters."
  (let* ((with-zeros #(0 0 0 1 2 3))
         (encoded (bl.crypto:base58-encode with-zeros)))
    (is (char= (char encoded 0) #\1))
    (is (char= (char encoded 1) #\1))
    (is (char= (char encoded 2) #\1))))

(test base58check-encode-decode
  "Test Base58Check encode/decode with checksum."
  (let* ((payload #(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20))
         (version 111)  ; Testnet P2PKH
         (encoded (bl.crypto:base58check-encode version payload)))
    (multiple-value-bind (dec-version dec-payload)
        (bl.crypto:base58check-decode encoded)
      (is (= dec-version version))
      (is (equalp dec-payload payload)))))

(test base58check-invalid-checksum
  "Test Base58Check detects invalid checksum."
  ;; A valid address with modified character to corrupt checksum
  (let ((invalid "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfX"))  ; Changed last char
    (is (null (bl.crypto:base58check-decode invalid)))))

(test bech32-encode-decode-v0
  "Test Bech32 encode/decode for witness v0."
  (let* ((hrp "tb")
         (data '(0 14 20 15 7 13 26 0 25 18 6 11 13 8 21 4 20 3 17 2 29 3 12 29 3 4 15 24 20 6 11 29 8))
         (encoded (bl.crypto:bech32-encode hrp data :bech32)))
    (multiple-value-bind (dec-hrp dec-data dec-variant)
        (bl.crypto:bech32-decode encoded)
      (is (string= dec-hrp hrp))
      (is (equal dec-data data))
      (is (eq dec-variant :bech32)))))

(test segwit-address-p2wpkh
  "Test SegWit P2WPKH address encoding/decoding."
  (let* ((hrp "tb")
         (witness-version 0)
         (witness-program (make-array 20 :element-type '(unsigned-byte 8) :initial-element #x42))
         (address (bl.crypto:segwit-address-encode hrp witness-version witness-program)))
    (multiple-value-bind (dec-hrp dec-version dec-program)
        (bl.crypto:segwit-address-decode address)
      (is (string= dec-hrp hrp))
      (is (= dec-version witness-version))
      (is (equalp dec-program witness-program)))))

(test segwit-address-p2tr
  "Test SegWit P2TR (Taproot) address encoding/decoding."
  (let* ((hrp "tb")
         (witness-version 1)
         (witness-program (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab))
         (address (bl.crypto:segwit-address-encode hrp witness-version witness-program)))
    ;; Should use bech32m for v1+
    (multiple-value-bind (dec-hrp dec-version dec-program)
        (bl.crypto:segwit-address-decode address)
      (is (string= dec-hrp hrp))
      (is (= dec-version witness-version))
      (is (equalp dec-program witness-program)))))

(test decode-address-p2pkh-testnet
  "Test decode-address for testnet P2PKH."
  (multiple-value-bind (type script-pubkey wit-ver wit-prog)
      (bl.crypto:decode-address "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" :testnet3)
    (is (eq type :p2pkh))
    (is (vectorp script-pubkey))
    (is (null wit-ver))
    ;; P2PKH scriptPubKey is 25 bytes
    (is (= (length script-pubkey) 25))))

(test decode-address-p2wpkh-testnet
  "Test decode-address for testnet P2WPKH."
  (multiple-value-bind (type script-pubkey wit-ver wit-prog)
      (bl.crypto:decode-address "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" :testnet3)
    (is (eq type :p2wpkh))
    (is (vectorp script-pubkey))
    (is (= wit-ver 0))
    (is (= (length wit-prog) 20))))

(test decode-address-wrong-network
  "Test decode-address returns nil for wrong network."
  ;; Mainnet address on testnet
  (is (null (bl.crypto:decode-address "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2" :testnet3)))
  ;; Testnet address on mainnet
  (is (null (bl.crypto:decode-address "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" :mainnet))))

;;; --- SipHash-2-4 Tests (BIP 152) ---

(test siphash-empty-input
  "SipHash-2-4 of empty input with zero keys."
  (let ((result (bl.crypto:siphash-2-4 0 0 #())))
    (is (integerp result))
    (is (<= 0 result (1- (expt 2 64))))))

(test siphash-deterministic
  "SipHash-2-4 is deterministic."
  (let ((data #(1 2 3 4 5 6 7 8))
        (k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908))
    (is (= (bl.crypto:siphash-2-4 k0 k1 data)
           (bl.crypto:siphash-2-4 k0 k1 data)))))

(test siphash-different-keys
  "SipHash-2-4 produces different results for different keys."
  (let ((data #(1 2 3 4 5 6 7 8)))
    (is (not (= (bl.crypto:siphash-2-4 0 0 data)
                (bl.crypto:siphash-2-4 1 0 data))))))

(test siphash-different-data
  "SipHash-2-4 produces different results for different data."
  (let ((k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908))
    (is (not (= (bl.crypto:siphash-2-4 k0 k1 #(1 2 3))
                (bl.crypto:siphash-2-4 k0 k1 #(1 2 4)))))))

(test siphash-test-vector
  "SipHash-2-4 test vector from reference implementation."
  ;; Test vector: 15-byte input with standard test keys
  (let* ((k0 #x0706050403020100)
         (k1 #x0f0e0d0c0b0a0908)
         (data (make-array 15 :element-type '(unsigned-byte 8)
                           :initial-contents '(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14)))
         (result (bl.crypto:siphash-2-4 k0 k1 data)))
    ;; Expected value from SipHash reference implementation
    (is (= result #xa129ca6149be45e5))))

(test compute-siphash-key-deterministic
  "compute-siphash-key is deterministic."
  (let ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 0))
        (nonce #x123456789abcdef0))
    (multiple-value-bind (k0a k1a)
        (bl.crypto:compute-siphash-key header nonce)
      (multiple-value-bind (k0b k1b)
          (bl.crypto:compute-siphash-key header nonce)
        (is (= k0a k0b))
        (is (= k1a k1b))))))

(test compute-siphash-key-different-nonce
  "compute-siphash-key produces different keys for different nonces."
  (let ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 0)))
    (multiple-value-bind (k0a k1a)
        (bl.crypto:compute-siphash-key header 0)
      (multiple-value-bind (k0b k1b)
          (bl.crypto:compute-siphash-key header 1)
        (is (or (not (= k0a k0b))
                (not (= k1a k1b))))))))

(test compute-short-txid-truncation
  "compute-short-txid returns 48-bit value."
  (let ((k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908)
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xab)))
    (let ((short-id (bl.crypto:compute-short-txid k0 k1 txid)))
      (is (integerp short-id))
      (is (<= 0 short-id #xffffffffffff))  ; 6 bytes max
      (is (< short-id (expt 2 48))))))

(test compute-short-txid-different-txids
  "compute-short-txid produces different IDs for different transactions."
  (let ((k0 #x0706050403020100)
        (k1 #x0f0e0d0c0b0a0908)
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x00))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xff)))
    (is (not (= (bl.crypto:compute-short-txid k0 k1 txid1)
                (bl.crypto:compute-short-txid k0 k1 txid2))))))

;;;; Signing primitives + WIF (signing foundation)

(defun %secret-key (last-byte)
  "32-byte secret key with the given low byte (the rest zero)."
  (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref k 31) last-byte)
    k))

(test ecdsa-derive-public-key
  "derive-public-key yields the generator point G (compressed + uncompressed) for
secret key 1; valid-private-key-p accepts it and rejects the all-zero key."
  (let ((k1 (%secret-key 1)))
    (is-true (bl.crypto:valid-private-key-p k1))
    (is (null (bl.crypto:valid-private-key-p
               (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
    ;; G compressed is well-known.
    (is (string-equal
         "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
         (bl.crypto:bytes-to-hex (bl.crypto:derive-public-key k1))))
    (is (= 65 (length (bl.crypto:derive-public-key k1 :compressed nil))))))

(test ecdsa-sign-verify-roundtrip
  "sign-ecdsa produces a DER signature verify-signature accepts under the derived
public key (and rejects under a different key); RFC6979 makes it deterministic."
  (let ((k1 (%secret-key 1))
        (k2 (%secret-key 2))
        (h  (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x42)))
    (let ((sig (bl.crypto:sign-ecdsa k1 h)))
      (is-true (bl.crypto:verify-signature
                h sig (bl.crypto:derive-public-key k1)))
      (is (null (bl.crypto:verify-signature
                 h sig (bl.crypto:derive-public-key k2))))
      (is (equalp sig (bl.crypto:sign-ecdsa k1 h))))))

(test wif-roundtrip
  "WIF encode/decode round-trips and matches the canonical WIF for secret key 1
(compressed, mainnet)."
  (let ((k1 (%secret-key 1)))
    (is (string= "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
                 (bl.crypto:private-key-to-wif k1 :network :mainnet :compressed t)))
    (multiple-value-bind (sk comp version)
        (bl.crypto:wif-to-private-key
         (bl.crypto:private-key-to-wif k1 :network :testnet3 :compressed nil))
      (is (equalp k1 sk))
      (is (null comp))
      ;; the test chains' SECRET_KEY prefix; the byte cannot say which one
      (is (= #xef version)))
    (is (null (bl.crypto:wif-to-private-key "not-a-wif")))))

(test bip32-test-vector-1
  "BIP32 test vector 1 (seed 000102...0f): master + m/0' + m/0'/1 xprv/xpub all
match the canonical strings; CKDpub (derive the normal child m/0'/1 from the
neutered m/0' xpub) matches the private path; derive-path and parse round-trip."
  (let* ((seed (bl.crypto:hex-to-bytes "000102030405060708090a0b0c0d0e0f"))
         (m (bl.crypto:bip32-master-key seed :network :mainnet))
         (m0h (bl.crypto:bip32-derive-child
               m (+ 0 bl.crypto:+bip32-hardened+)))
         (m0h1 (bl.crypto:bip32-derive-child m0h 1)))
    ;; master
    (is (string= "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
                 (bl.crypto:bip32-serialize m)))
    (is (string= "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
                 (bl.crypto:bip32-serialize (bl.crypto:bip32-neuter m))))
    ;; m/0' (hardened CKDpriv)
    (is (string= "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
                 (bl.crypto:bip32-serialize m0h)))
    (is (string= "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
                 (bl.crypto:bip32-serialize (bl.crypto:bip32-neuter m0h))))
    ;; m/0'/1 (normal CKDpriv)
    (is (string= "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
                 (bl.crypto:bip32-serialize m0h1)))
    (is (string= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                 (bl.crypto:bip32-serialize (bl.crypto:bip32-neuter m0h1))))
    ;; CKDpub: deriving the same normal child from the neutered parent xpub
    ;; (no private key) yields the identical xpub.
    (is (string= "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
                 (bl.crypto:bip32-serialize
                  (bl.crypto:bip32-derive-child
                   (bl.crypto:bip32-neuter m0h) 1))))
    ;; derive-path string form equals the step-by-step private derivation
    (is (string= (bl.crypto:bip32-serialize m0h1)
                 (bl.crypto:bip32-serialize
                  (bl.crypto:bip32-derive-path m "m/0'/1"))))
    ;; parse round-trips
    (let ((parsed (bl.crypto:bip32-parse (bl.crypto:bip32-serialize m0h))))
      (is (bl.crypto:ext-key-privatep parsed))
      (is (string= (bl.crypto:bip32-serialize m0h)
                   (bl.crypto:bip32-serialize parsed))))
    (is (null (bl.crypto:bip32-parse "not-an-xkey")))))

(test schnorr-sign-bip340-vector-0
  "BIP340 test vector 0: secret key 3, message 0, aux 0 -> the canonical x-only
pubkey and the exact known-answer 64-byte signature, which verifies."
  (let* ((sk (bl.crypto:hex-to-bytes
              "0000000000000000000000000000000000000000000000000000000000000003"))
         (msg (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (aux (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (pub (bl.crypto:derive-xonly-pubkey sk))
         (sig (bl.crypto:sign-schnorr sk msg aux)))
    (is (equalp (bl.crypto:hex-to-bytes
                 "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
                pub))
    (is (equalp (bl.crypto:hex-to-bytes
                 "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
                sig))
    (is-true (bl.crypto:verify-schnorr-signature msg sig pub))))

(test schnorr-sign-verify-roundtrip
  "sign-schnorr produces a signature that verifies under the derived x-only key
for an arbitrary key/message (default zero aux), and signing is deterministic."
  (let* ((sk (%secret-key 7))
         (msg (bl.crypto:sha256
               (flexi-streams:string-to-octets "bitcoin-lisp schnorr roundtrip")))
         (pub (bl.crypto:derive-xonly-pubkey sk))
         (sig1 (bl.crypto:sign-schnorr sk msg))
         (sig2 (bl.crypto:sign-schnorr sk msg)))
    (is (= 64 (length sig1)))
    (is (equalp sig1 sig2))                       ; deterministic (zero aux)
    (is-true (bl.crypto:verify-schnorr-signature msg sig1 pub))
    ;; a different message must not verify against this signature
    (is (null (bl.crypto:verify-schnorr-signature
               (%secret-key 9) sig1 pub)))))

(test chain-prefixes-are-cores-base58prefixes
  "Every chain's address, WIF and BIP32 prefixes are Core's chainparams.cpp
base58Prefixes (mainnet 0/5/128 + xpub/xprv; every test chain 111/196/239 +
tpub/tprv), and the SLIP-44 coin type is 0 on mainnet and 1 elsewhere. The
address, WIF and extended-key codecs all read these fields now; before, the
bytes lived in constants that collapsed five chains into two."
  (flet ((row (chain) (let ((p (bl.chain:find-chain-params chain)))
                        (list (bl.chain:chain-params-base58-pubkey-prefix p)
                              (bl.chain:chain-params-base58-script-prefix p)
                              (bl.chain:chain-params-base58-secret-prefix p)
                              (bl.chain:chain-params-ext-public-prefix p)
                              (bl.chain:chain-params-ext-secret-prefix p)
                              (bl.chain:chain-params-bip44-coin-type p)))))
    (is (equal '(#x00 #x05 #x80 #x0488B21E #x0488ADE4 0) (row :mainnet)))
    (dolist (chain '(:testnet3 :testnet4 :signet :regtest))
      (is (equal '(#x6f #xc4 #xef #x043587CF #x04358394 1) (row chain))
          "~A does not carry the test-chain prefixes" chain))
    ;; A WIF reports the version byte it was encoded under; the chain it is
    ;; valid for is whoever's SECRET_KEY prefix that is.
    (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
      (multiple-value-bind (sk compressed version)
          (bl.crypto:wif-to-private-key (bl.crypto:private-key-to-wif k :network :regtest))
        (is (equalp k sk)) (is-true compressed) (is (= #xef version))))
    ;; The extended-key prefix names its chain family.
    (is (eq :mainnet (bl.chain:chain-params-name (bl.chain:chain-params-of-ext-prefix #x0488B21E))))
    (is (eq :testnet3 (bl.chain:chain-params-name (bl.chain:chain-params-of-ext-prefix #x04358394))))
    (is (null (bl.chain:chain-params-of-ext-prefix 0)))))
