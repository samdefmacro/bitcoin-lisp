;;;; Package bitcoin-lisp.crypto -- the public API of src/crypto/.
;;;;
;;;; Loaded with the other package files before any code (bitcoin-lisp.asd,
;;;; the "packages" phase): src/config.lisp loads third and already names
;;;; most of these packages, and every package must exist before
;;;; src/package.lisp installs the bl.* nicknames. Add an export here when a
;;;; definition in src/crypto/ becomes API; keep %-prefixed names internal.

(defpackage #:bitcoin-lisp.crypto
  (:documentation "Hashes, HMAC/HKDF, the ChaCha20 family behind BIP324,
libsecp256k1 through CFFI (ECDSA, Schnorr, ellswift, tweaks), BIP32, hex
and byte-order helpers, MuHash. Core crypto/, key.cpp, pubkey.cpp,
hash.cpp. src/crypto/.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:export
   ;; Hash functions
   #:sha256
   #:hash256
   #:sha3-256
   #:ripemd160
   #:hash160
   ;; Tagged hashes (BIP 340)
   #:tagged-hash
   #:tap-leaf-hash
   #:tap-branch-hash
   #:tap-tweak-hash
   #:+tag-bip340-challenge+
   #:+tag-bip340-aux+
   #:+tag-tap-leaf+
   #:+tag-tap-branch+
   #:+tag-tap-tweak+
   #:+tag-tap-sighash+
   ;; Wallet crypter (wallet P6): SHA-512 passphrase KDF + AES-256-CBC.
   ;; PKCS7-PAD/PKCS7-UNPAD stay internal -- they are only meaningful as
   ;; part of the two AES entry points below.
   #:crypter-derive-key
   #:aes-256-cbc-encrypt
   #:aes-256-cbc-decrypt
   #:+wallet-crypto-key-size+
   #:+wallet-crypto-salt-size+
   #:+wallet-crypto-iv-size+
   ;; SipHash (BIP 152)
   #:siphash-2-4
   #:compute-siphash-key
   #:compute-short-txid
   #:bytes-to-uint64-le
   #:uint64-to-bytes-le
   ;; Utilities
   #:bytes-to-hex
   #:hmac-sha256
   #:hex-to-bytes
   #:reverse-bytes
   ;; BIP324 cipher suite: forward-secure wrappers + HKDF only. The bare
   ;; ChaCha20/AEAD primitives stay internal -- BIP324's cipher/transport
   ;; layers consume exactly this surface (as in Core), and exposing the
   ;; unratcheted primitives would invite bypassing forward secrecy.
   #:+poly1305-taglen+
   #:make-fschacha20
   #:fschacha20-crypt
   #:make-fschacha20poly1305
   #:fsaead-encrypt
   #:fsaead-decrypt
   #:hkdf-sha256-extract
   #:hkdf-sha256-expand32
   ;; MuHash3072 (BIP-less; Core coinstats / gettxoutsetinfo muhash mode)
   #:+muhash-modulus+
   #:make-muhash
   #:muhash
   #:muhash-insert
   #:muhash-remove
   #:muhash-combine
   #:muhash-divide
   #:muhash-finalize
   #:muhash-element-num
   #:muhash-numerator
   #:muhash-denominator
   ;; ElligatorSwift (BIP324 key exchange; optional libsecp256k1 module)
   #:ellswift-available-p
   #:ellswift-create
   #:ellswift-decode
   #:bip324-ecdh
   ;; BIP324 session cipher (Core BIP324Cipher)
   #:make-bip324-cipher
   #:bip324-cipher-initialize
   #:bip324-cipher-initialized-p
   #:bip324-cipher-encrypt
   #:bip324-cipher-decrypt-length
   #:bip324-cipher-decrypt
   #:bip324-cipher-our-pubkey
   #:bip324-cipher-session-id
   #:bip324-cipher-send-garbage-terminator
   #:bip324-cipher-recv-garbage-terminator
   #:+bip324-expansion+
   #:+bip324-garbage-terminator-len+
   #:+bip324-length-len+
   #:+bip324-header-len+
   ;; secp256k1 ECDSA
   #:verify-signature
   #:check-signature-encoding
   #:parse-public-key
   #:public-key-valid-p
   #:decompress-public-key
   #:ensure-secp256k1-loaded
   #:cleanup-secp256k1
   ;; Signing (private key -> pubkey / signature) + WIF
   #:valid-private-key-p
   #:derive-public-key
   #:sign-ecdsa
   #:sign-recoverable-compact
   #:recover-public-key
   #:private-key-to-wif
   #:wif-to-private-key
   #:tweak-add-public-key
   ;; BIP32 hierarchical deterministic keys
   #:hmac-sha512
   #:ext-key
   #:make-ext-key
   #:ext-key-p
   #:ext-key-version
   #:ext-key-depth
   #:ext-key-parent-fingerprint
   #:ext-key-child-number
   #:ext-key-chain-code
   #:ext-key-key
   #:ext-key-privatep
   #:ext-key-public-bytes
   #:bip32-master-key
   #:bip32-derive-child
   #:bip32-derive-path
   #:bip32-neuter
   #:bip32-serialize
   #:bip32-parse
   #:+bip32-hardened+
   #:+secp256k1-order+
   #:+xprv-mainnet+
   #:+xpub-mainnet+
   #:+xprv-testnet+
   #:+xpub-testnet+
   #:taproot-tweak-private-key
   ;; Schnorr / x-only pubkeys (BIP 340)
   #:verify-schnorr-signature
   #:sign-schnorr
   #:musig-aggregate-pubkeys
   #:derive-xonly-pubkey
   #:parse-xonly-pubkey
   #:xonly-pubkey-valid-p
   #:tweak-xonly-pubkey
   #:verify-xonly-tweak
   ;; Address encoding/decoding
   #:base58-encode
   #:base58-decode
   #:base58check-encode
   #:base58check-decode
   #:bech32-encode
   #:bech32-decode
   #:segwit-address-encode
   #:segwit-address-decode
   #:decode-address
   #:encode-p2pkh-address
   #:encode-p2sh-address
   #:encode-p2wpkh-address
   #:encode-p2wsh-address
   #:encode-p2tr-address
   #:+p2pkh-version-mainnet+
   #:+p2pkh-version-testnet+
   #:+p2sh-version-mainnet+
   #:+p2sh-version-testnet+))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))
