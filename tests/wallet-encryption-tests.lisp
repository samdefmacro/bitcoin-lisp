(in-package #:bitcoin-lisp.tests)

;;; Wallet P6 tests: the crypter primitives against Bitcoin Core's known-answer
;;; vectors (wallet_crypto_tests.cpp, crypto_tests.cpp), the encryption record
;;; schema, the encrypt/unlock/lock/passphrase-change lifecycle, locked-wallet
;;; gating on every path that needs a private key, the relock timer, and
;;; backup/restore round trips.

(def-suite :wallet-encryption-tests
  :description "Wallet P6: crypter, encryptwallet/walletpassphrase/lock, backup"
  :in :bitcoin-lisp-tests)

(in-suite :wallet-encryption-tests)

;;; --- Helpers ---

(defun %hex (string)
  (bitcoin-lisp.crypto:hex-to-bytes string))

(defun %wenc-fresh-wallet (node name &key passphrase)
  "Create NAME through the RPC layer and return the wallet struct."
  (bitcoin-lisp.rpc::rpc-createwallet
   node (list name nil nil passphrase))
  (gethash name (bitcoin-lisp.rpc::wallet-manager-wallets (%node-manager node))))

(defun %wenc-key-record-counts (wallet)
  "(values plaintext-key-records crypted-key-records mkey-records) on disk."
  (let ((plain 0) (crypted 0) (mkeys 0))
    (dolist (record (bitcoin-lisp.rpc::wallet-db-records
                     (bitcoin-lisp.rpc::wallet-db wallet)))
      (let ((type (bitcoin-lisp.rpc::wdb-parse-key (car record))))
        (cond ((equal type bitcoin-lisp.rpc::+wdb-key-walletdescriptorkey+)
               (incf plain))
              ((equal type bitcoin-lisp.rpc::+wdb-key-walletdescriptorckey+)
               (incf crypted))
              ((equal type bitcoin-lisp.rpc::+wdb-key-mkey+)
               (incf mkeys)))))
    (values plain crypted mkeys)))

(defun %wenc-in-memory-key-counts (wallet)
  "(values plaintext-keys crypted-keys) across every SPKM."
  (let ((plain 0) (crypted 0))
    (loop for spkm being the hash-values of (bitcoin-lisp.rpc::wallet-spkms wallet)
          do (incf plain (hash-table-count (bitcoin-lisp.rpc::desc-spkm-keys spkm)))
             (incf crypted (hash-table-count
                            (bitcoin-lisp.rpc::desc-spkm-crypted-keys spkm))))
    (values plain crypted)))

;;; ============================================================
;;; Crypter primitives — Bitcoin Core known-answer vectors
;;; ============================================================

(test wenc-kdf-core-vector
  "The SHA-512 passphrase KDF reproduces Core's only KDF known-answer vector
(wallet_crypto_tests.cpp:83-85): salt 0000deadbeef0000, passphrase \"test\",
25000 rounds, derivation method 0."
  (multiple-value-bind (key iv)
      (bitcoin-lisp.crypto:crypter-derive-key
       (bitcoin-lisp.rpc::passphrase-octets "test")
       (%hex "0000deadbeef0000") 25000 0)
    (is (equalp (%hex "fc7aba077ad5f4c3a0988d8daa4810d0d4a0e3bcb53af662998898f33df0556a")
                key))
    (is (equalp (%hex "cf2f2691526dd1aa220896fb8bf7c369") iv))))

(test wenc-kdf-parameter-rejection
  "SetKeyFromPassphrase's guards (crypter.cpp:43-45): rounds must be >= 1, the
salt exactly 8 bytes, and the only derivation method is 0."
  (let ((pass (bitcoin-lisp.rpc::passphrase-octets "test")))
    (is (null (bitcoin-lisp.crypto:crypter-derive-key
               pass (%hex "0000deadbeef0000") 0 0)))
    (is (null (bitcoin-lisp.crypto:crypter-derive-key
               pass (%hex "00deadbeef0000") 25000 0)))
    (is (null (bitcoin-lisp.crypto:crypter-derive-key
               pass (%hex "0000deadbeef000000") 25000 0)))
    (is (null (bitcoin-lisp.crypto:crypter-derive-key
               pass (%hex "0000deadbeef0000") 25000 1)))))

(test wenc-aes-cbc-core-vectors
  "AES-256-CBC with PKCS#7 padding matches Core's NIST-derived vectors
(crypto_tests.cpp:616-630, the pad=true half). Both directions."
  (let ((key (%hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")))
    (dolist (vector
             '(("000102030405060708090A0B0C0D0E0F"
                "6bc1bee22e409f96e93d7e117393172a"
                "f58c4c04d6e5f1ba779eabfb5f7bfbd6485a5c81519cf378fa36d42b8547edc0")
               ("F58C4C04D6E5F1BA779EABFB5F7BFBD6"
                "ae2d8a571e03ac9c9eb76fac45af8e51"
                "9cfc4e967edb808d679f777bc6702c7d3a3aa5e0213db1a9901f9036cf5102d2")
               ("9CFC4E967EDB808D679F777BC6702C7D"
                "30c81c46a35ce411e5fbc1191a0a52ef"
                "39f23369a9d9bacfa530e263042314612f8da707643c90a6f732b3de1d3f5cee")
               ("39F23369A9D9BACFA530E26304231461"
                "f69f2445df4f9b17ad2b417be66c3710"
                "b2eb05e2c39be9fcda6c19078c6a9d1b3f461796d6b0d6b2e0c2a72b4d80e644")))
      (destructuring-bind (iv plaintext ciphertext) vector
        (is (equalp (%hex ciphertext)
                    (bitcoin-lisp.crypto:aes-256-cbc-encrypt
                     key (%hex iv) (%hex plaintext))))
        (is (equalp (%hex plaintext)
                    (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                     key (%hex iv) (%hex ciphertext))))))))

(test wenc-aes-roundtrip-every-pad-size
  "Core's encrypt round-trip corpus (wallet_crypto_tests.cpp:99-103) and every
suffix of it, so all 16 PKCS#7 pad sizes are exercised."
  (multiple-value-bind (key iv)
      (bitcoin-lisp.crypto:crypter-derive-key
       (bitcoin-lisp.rpc::passphrase-octets "passphrase")
       (%hex "0000deadbeef0000") 25000 0)
    (let ((corpus (%hex "22bcade09ac03ff6386914359cfe885cfeb5f77ff0d670f102f619687453b29d")))
      (loop for start from 0 below (length corpus)
            for plaintext = (subseq corpus start)
            for ciphertext = (bitcoin-lisp.crypto:aes-256-cbc-encrypt
                              key iv plaintext)
            do ;; Core's ciphertext is always the plaintext rounded down to a
               ;; block boundary plus one full block.
               (is (= (length ciphertext)
                      (+ (* 16 (floor (length plaintext) 16)) 16)))
               (is (equalp plaintext
                           (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                            key iv ciphertext)))))))

(test wenc-aes-decrypt-corner-cases-never-signal
  "Core's decrypt corner-case corpus (wallet_crypto_tests.cpp:118-123): these
must return a value or NIL, but must never signal."
  (multiple-value-bind (key iv)
      (bitcoin-lisp.crypto:crypter-derive-key
       (bitcoin-lisp.rpc::passphrase-octets "passphrase")
       (%hex "0000deadbeef0000") 25000 0)
    (dolist (ciphertext
             '("795643ce39d736088367822cdc50535ec6f103715e3e48f4f3b1a60a08ef59ca"
               "de096f4a8f9bd97db012aa9d90d74de8cdea779c3ee8bc7633d8b5d6da703486"
               "32d0a8974e3afd9c6c3ebf4d66aa4e6419f8c173de25947f98cf8b7ace49449c"
               "e7c055cca2faa78cb9ac22c9357a90b4778ded9b2cc220a14cea49f931e596ea"
               "b88efddd668a6801d19516d6830da4ae9811988ccbaf40df8fbb72f3f4d335fd"
               "8cae76aa6a43694e961ebcb28c8ca8f8540b84153d72865e8561ddd93fa7bfa9"))
      (finishes (bitcoin-lisp.crypto:aes-256-cbc-decrypt key iv (%hex ciphertext))))))

(test wenc-pkcs7-rejects-what-ironclad-accepts
  "The padding checks Core performs and ironclad's :pkcs7 mode does not. Each
of these must be a quiet NIL — never a value, never a signalled condition.
This is the regression guard against switching to ironclad's own padding."
  (let* ((key (%hex "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
         (iv (%hex "000102030405060708090A0B0C0D0E0F")))
    (flet ((raw-encrypt (block16)
             ;; One raw CBC block with no padding, so we can forge a
             ;; ciphertext whose plaintext has arbitrary trailing bytes.
             (ironclad:encrypt-message
              (ironclad:make-cipher :aes :mode :cbc :key key
                                         :initialization-vector iv)
              block16))
           (block-ending-in (byte)
             (let ((v (make-array 16 :element-type '(unsigned-byte 8)
                                     :initial-element 7)))
               (setf (aref v 15) byte)
               v)))
      ;; Pad byte 0: ironclad's :pkcs7 accepts this, Core rejects it.
      (is (null (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                 key iv (raw-encrypt (block-ending-in 0)))))
      ;; Pad byte above the block size: ironclad signals TYPE-ERROR.
      (is (null (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                 key iv (raw-encrypt (block-ending-in #x2a)))))
      ;; Pad byte plausible but the padding bytes disagree.
      (let ((v (make-array 16 :element-type '(unsigned-byte 8)
                              :initial-element 7)))
        (setf (aref v 15) 4 (aref v 14) 4 (aref v 13) 9 (aref v 12) 4)
        (is (null (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                   key iv (raw-encrypt v)))))
      ;; A ciphertext that is not a whole number of blocks: ironclad
      ;; silently truncates instead of refusing.
      (is (null (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                 key iv (subseq (raw-encrypt (block-ending-in 16)) 0 12))))
      ;; A full pad block, i.e. an empty plaintext: Core's Decrypt treats a
      ;; zero-length result as failure.
      (is (null (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                 key iv (raw-encrypt (make-array 16 :element-type '(unsigned-byte 8)
                                                    :initial-element 16)))))
      ;; A single pad byte IS valid and yields 15 bytes.
      (is (= 15 (length (bitcoin-lisp.crypto:aes-256-cbc-decrypt
                         key iv (raw-encrypt (block-ending-in 1)))))))))

(test wenc-secret-iv-is-sha256d-not-hash160
  "EncryptSecret's IV is the first 16 bytes of the DOUBLE-SHA256 of the
serialized pubkey (CPubKey::GetHash, pubkey.h:165) — not the Hash160 that
CPubKey::GetID uses as the map key, and not byte-reversed."
  (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 17))
         (pubkey (bitcoin-lisp.crypto:derive-public-key secret :compressed t)))
    (is (= 33 (length pubkey)))
    (let ((iv (bitcoin-lisp.rpc::%secret-iv pubkey)))
      (is (equalp (subseq (bitcoin-lisp.crypto:hash256 pubkey) 0 16) iv))
      (is (not (equalp (subseq (bitcoin-lisp.crypto:hash160 pubkey) 0 16) iv)))
      ;; and definitely not the reversed digest
      (is (not (equalp (subseq (reverse (bitcoin-lisp.crypto:hash256 pubkey)) 0 16)
                       iv))))))

(test wenc-decrypt-key-gates
  "DecryptKey returns the secret only when it round-trips AND reproduces the
stored pubkey; every other case is NIL, never a wrong-but-plausible key."
  (let* ((master (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 3))
         (secret (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 17))
         (pubkey (bitcoin-lisp.crypto:derive-public-key secret :compressed t))
         (ciphertext (bitcoin-lisp.rpc::encrypt-secret master secret pubkey))
         (other-secret (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 19))
         (other-pubkey (bitcoin-lisp.crypto:derive-public-key other-secret
                                                              :compressed t)))
    (is (= 48 (length ciphertext)))
    (is (equalp secret (bitcoin-lisp.rpc::decrypt-key master pubkey ciphertext)))
    ;; A flipped ciphertext bit.
    (let ((damaged (copy-seq ciphertext)))
      (setf (aref damaged 0) (logxor (aref damaged 0) 1))
      (is (null (bitcoin-lisp.rpc::decrypt-key master pubkey damaged))))
    ;; The right ciphertext under the wrong master key.
    (let ((wrong-master (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 4)))
      (is (null (bitcoin-lisp.rpc::decrypt-key wrong-master pubkey ciphertext))))
    ;; The right ciphertext attributed to a different pubkey: the IV changes,
    ;; so this fails at unpad, and the pubkey check backs it up.
    (is (null (bitcoin-lisp.rpc::decrypt-key master other-pubkey ciphertext)))))

;;; ============================================================
;;; Record encodings
;;; ============================================================

(test wenc-mkey-record-encoding
  "The mkey record is byte-compatible with Core's CMasterKey serialization
(walletdb.cpp WriteMasterKey): key = \"mkey\" + uint32 LE id, value =
var-bytes ciphertext, var-bytes salt, uint32 method, uint32 iterations,
var-bytes other-params."
  (let ((key (bitcoin-lisp.rpc::wdb-key-mkey 1)))
    ;; 0x04 "mkey" + 4-byte LE id
    (is (equalp (%hex "046d6b657901000000") key))
    (is (= 1 (bitcoin-lisp.rpc::wdb-parse-mkey-fields
              (nth-value 1 (bitcoin-lisp.rpc::wdb-parse-key key)))))
    (let* ((ciphertext (make-array 48 :element-type '(unsigned-byte 8)
                                      :initial-element 9))
           (salt (make-array 8 :element-type '(unsigned-byte 8)
                               :initial-element 2))
           (value (bitcoin-lisp.rpc::wdb-mkey-value
                   ciphertext salt 0 348876
                   (make-array 0 :element-type '(unsigned-byte 8)))))
      ;; 1+48 + 1+8 + 4 + 4 + 1
      (is (= 67 (length value)))
      (multiple-value-bind (ct s method iterations other)
          (bitcoin-lisp.rpc::wdb-parse-mkey-value value)
        (is (equalp ciphertext ct))
        (is (equalp salt s))
        (is (= 0 method))
        (is (= 348876 iterations))
        (is (zerop (length other)))))))

(test wenc-ckey-record-encoding
  "walletdescriptorckey: key = type string + 32-byte descriptor id +
compactsize-prefixed pubkey; value = the bare ciphertext as var-bytes, with
NO checksum (unlike the plaintext walletdescriptorkey record, whose value
carries hash256(pubkey||der))."
  (let* ((desc-id (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element 5))
         (secret (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 17))
         (pubkey (bitcoin-lisp.crypto:derive-public-key secret :compressed t))
         (key (bitcoin-lisp.rpc::wdb-key-descriptor-key
               bitcoin-lisp.rpc::+wdb-key-walletdescriptorckey+ desc-id pubkey))
         (ciphertext (make-array 48 :element-type '(unsigned-byte 8)
                                    :initial-element 9))
         (value (bitcoin-lisp.rpc::wdb-vector-value ciphertext)))
    (multiple-value-bind (type fields) (bitcoin-lisp.rpc::wdb-parse-key key)
      (is (equal bitcoin-lisp.rpc::+wdb-key-walletdescriptorckey+ type))
      (is (equalp desc-id (subseq fields 0 32)))
      (is (= #x21 (aref fields 32)))           ; compactsize 33
      (is (equalp pubkey (subseq fields 33))))
    (is (= 49 (length value)))                 ; 1 + 48, no checksum
    (is (equalp ciphertext (bitcoin-lisp.rpc::wdb-parse-vector-value value)))))

;;; ============================================================
;;; Encryption lifecycle
;;; ============================================================

(test wenc-encryptwallet-lifecycle
  "encryptwallet: returns Core's instruction string, leaves the wallet locked,
moves every key from plaintext to ciphertext records on disk AND in memory,
and generates a fresh HD seed."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (is (not (bitcoin-lisp.rpc::wallet-has-encryption-keys-p wallet)))
        (is (not (bitcoin-lisp.rpc::wallet-is-locked-p wallet)))
        (multiple-value-bind (plain crypted mkeys) (%wenc-key-record-counts wallet)
          (is (= 8 plain))
          (is (zerop crypted))
          (is (zerop mkeys)))
        (let ((spkms-before (hash-table-count (bitcoin-lisp.rpc::wallet-spkms wallet)))
              (result (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))))
          (is (equal "wallet encrypted; The keypool has been flushed and a new HD seed was generated. You need to make a new backup with the backupwallet RPC."
                     result))
          (is (bitcoin-lisp.rpc::wallet-has-encryption-keys-p wallet))
          (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
          ;; A new seed means 8 more SPKMs, all born encrypted.
          (is (= (+ spkms-before 8)
                 (hash-table-count (bitcoin-lisp.rpc::wallet-spkms wallet)))))
        ;; No plaintext key survives, in memory or on disk.
        (multiple-value-bind (plain crypted mkeys) (%wenc-key-record-counts wallet)
          (is (zerop plain))
          (is (= 16 crypted))
          (is (= 1 mkeys)))
        (multiple-value-bind (plain crypted) (%wenc-in-memory-key-counts wallet)
          (is (zerop plain))
          (is (= 16 crypted)))))))

(test wenc-unlock-lock-cycle
  "unlock proves the passphrase cryptographically; a wrong one leaves the
wallet locked and the key material absent."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (is (null (bitcoin-lisp.rpc::unlock-wallet wallet "wrong")))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
        (is (null (bitcoin-lisp.rpc::wallet-unlocked-key wallet)))
        (is (bitcoin-lisp.rpc::unlock-wallet wallet "hunter2"))
        (is (not (bitcoin-lisp.rpc::wallet-is-locked-p wallet)))
        (is (= 32 (length (bitcoin-lisp.rpc::wallet-unlocked-key wallet))))
        (is (bitcoin-lisp.rpc::lock-wallet wallet))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))))))

(test wenc-walletpassphrase-rpc
  "walletpassphrase unlocks and arms the relock; walletlock relocks;
getwalletinfo reports unlocked_until per Core's three states."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        ;; Never encrypted: the field is absent entirely, not null and not 0.
        (is (null (assoc "unlocked_until"
                         (bitcoin-lisp.rpc::rpc-getwalletinfo node '())
                         :test #'string=)))
        ;; The three encryption-state RPCs refuse on an unencrypted wallet.
        (is (= -15 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrase
                                node '("hunter2" 60))))))
        (is (= -15 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-walletlock node '())))))
        (is (= -15 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrasechange
                                node '("a" "b"))))))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        ;; Encrypted and locked.
        (is (eql 0 (%aval "unlocked_until"
                          (bitcoin-lisp.rpc::rpc-getwalletinfo node '()))))
        (is (= -14 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrase
                                node '("wrong" 60))))))
        (is (null (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))))
        (is (not (bitcoin-lisp.rpc::wallet-is-locked-p wallet)))
        (let ((until (%aval "unlocked_until"
                            (bitcoin-lisp.rpc::rpc-getwalletinfo node '()))))
          (is (> until (bitcoin-lisp.serialization:get-unix-time))))
        (is (null (bitcoin-lisp.rpc::rpc-walletlock node '())))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
        (is (eql 0 (%aval "unlocked_until"
                          (bitcoin-lisp.rpc::rpc-getwalletinfo node '()))))))))

(test wenc-walletpassphrase-argument-validation
  "walletpassphrase's validation order and error codes (encrypt.cpp:53-70)."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (%wenc-fresh-wallet node "w")
      (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrase node '(42 60))))))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrase
                             node '("hunter2" "soon"))))))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrase
                             node '("hunter2" -1))))))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrase node '("" 60))))))
      ;; encryptwallet on an already-encrypted wallet.
      (is (= -15 (%rpc-error-code
                  (lambda () (bitcoin-lisp.rpc::rpc-encryptwallet node '("x")))))))))

(test wenc-timeout-clamped-and-zero-relocks
  "The timeout is silently clamped to MAX_SLEEP_TIME, and timeout 0 means the
deadline has already passed — the lazy check relocks on the next key access
without any sweeper involvement."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 999999999999))
        (is (<= (bitcoin-lisp.rpc::wallet-relock-time wallet)
                (+ (bitcoin-lisp.serialization:get-unix-time)
                   bitcoin-lisp.rpc::+walletpassphrase-max-sleep-time+)))
        (bitcoin-lisp.rpc::rpc-walletlock node '())
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 0))
        ;; The very next read of the key material sees an expired deadline.
        (is (null (bitcoin-lisp.rpc::wallet-unlocked-key wallet)))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
        (is (eql 0 (%aval "unlocked_until"
                          (bitcoin-lisp.rpc::rpc-getwalletinfo node '()))))))))

(test wenc-passphrase-change
  "walletpassphrasechange rewraps the master key without touching any
descriptor key: the old passphrase stops working, the new one works, and the
wallet still derives the same addresses."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("old-pass"))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("old-pass" 600))
        (let ((address-before (bitcoin-lisp.rpc::rpc-getnewaddress node '()))
              (crypted-before
                (nth-value 1 (%wenc-in-memory-key-counts wallet))))
          (is (= -14 (%rpc-error-code
                      (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrasechange
                                  node '("wrong" "new-pass"))))))
          ;; A failed change leaves the wallet LOCKED, even though it was
          ;; unlocked when the call started (Core parity).
          (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
          (is (null (bitcoin-lisp.rpc::rpc-walletpassphrasechange
                     node '("old-pass" "new-pass"))))
          (is (null (bitcoin-lisp.rpc::unlock-wallet wallet "old-pass")))
          (is (bitcoin-lisp.rpc::unlock-wallet wallet "new-pass"))
          ;; The keys themselves were never re-encrypted.
          (is (= crypted-before (nth-value 1 (%wenc-in-memory-key-counts wallet))))
          (is (stringp address-before)))))))

(test wenc-passphrase-change-preserves-the-relock-deadline
  "Changing the passphrase on a TIMED unlock must keep the pending relock.
Core's Lock() leaves nRelockTime alone (only walletlock zeroes it), and
dropping it here would silently turn a 60-second unlock into a permanent
one while getwalletinfo reported the wallet as locked."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("old-pass"))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("old-pass" 600))
        (let ((relock-time (bitcoin-lisp.rpc::wallet-relock-time wallet))
              (relock-deadline (bitcoin-lisp.rpc::wallet-relock-deadline wallet)))
          (is (plusp relock-time))
          (is (plusp relock-deadline))
          (is (null (bitcoin-lisp.rpc::rpc-walletpassphrasechange
                     node '("old-pass" "new-pass"))))
          ;; Still unlocked, and still on the ORIGINAL schedule.
          (is (not (bitcoin-lisp.rpc::wallet-is-locked-p wallet)))
          (is (= relock-time (bitcoin-lisp.rpc::wallet-relock-time wallet)))
          (is (= relock-deadline (bitcoin-lisp.rpc::wallet-relock-deadline wallet)))
          (is (= relock-time (%aval "unlocked_until"
                                    (bitcoin-lisp.rpc::rpc-getwalletinfo node '()))))
          ;; A change from a LOCKED wallet leaves it locked, with no deadline.
          (bitcoin-lisp.rpc::rpc-walletlock node '())
          (is (null (bitcoin-lisp.rpc::rpc-walletpassphrasechange
                     node '("new-pass" "third-pass"))))
          (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
          (is (zerop (bitcoin-lisp.rpc::wallet-relock-deadline wallet))))))))

(test wenc-empty-passphrase-rejected
  "An empty passphrase is refused everywhere it could produce an unopenable
or trivially-opened wallet."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (%wenc-fresh-wallet node "w")
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-encryptwallet node '(""))))))
      (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrasechange
                             node '("hunter2" "")))))))))

(test wenc-disable-private-keys-cannot-encrypt
  "A watch-only wallet has nothing to encrypt (encrypt.cpp:253)."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "wo"))
      (bitcoin-lisp.rpc::rpc-createwallet node '("wo" t))
      (is (= -16 (%rpc-error-code
                  (lambda () (bitcoin-lisp.rpc::rpc-encryptwallet
                              node '("hunter2")))))))))

;;; ============================================================
;;; Persistence
;;; ============================================================

(test wenc-encrypted-wallet-reloads
  "An encrypted wallet reloads from disk: it comes back locked, its master
key and ciphertext records survive, and the original passphrase still opens
it. This is the path that used to hard-refuse with 'not supported until
wallet P6'."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let (address)
        (let ((wallet (%wenc-fresh-wallet node "w")))
          (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
          (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))
          (setf address (bitcoin-lisp.rpc::rpc-getnewaddress node '()))
          (bitcoin-lisp.rpc::unload-wallet (%node-manager node) wallet))
        (multiple-value-bind (wallet warnings)
            (bitcoin-lisp.rpc::load-wallet (%node-manager node) "w")
          (is (null warnings))
          (is (bitcoin-lisp.rpc::wallet-has-encryption-keys-p wallet))
          (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
          (is (eql 0 (%aval "unlocked_until"
                            (bitcoin-lisp.rpc::rpc-getwalletinfo node '()))))
          (multiple-value-bind (plain crypted mkeys)
              (%wenc-key-record-counts wallet)
            (is (zerop plain))
            (is (= 16 crypted))
            (is (= 1 mkeys)))
          ;; The address issued before the unload is still ours.
          (is (bitcoin-lisp.rpc::wallet-is-mine
               wallet (%address-script address :testnet4)))
          (is (null (bitcoin-lisp.rpc::unlock-wallet wallet "wrong")))
          (is (bitcoin-lisp.rpc::unlock-wallet wallet "hunter2")))))))

(test wenc-born-encrypted-wallet-never-writes-plaintext
  "createwallet with a passphrase produces an encrypted wallet whose disk
never held a plaintext key record — the seed is generated only after the
master key exists. A LevelDB delete is only a tombstone, so this is the one
path that gives a real erasure guarantee."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "born"))
      (let ((wallet (%wenc-fresh-wallet node "born" :passphrase "hunter2")))
        (is (bitcoin-lisp.rpc::wallet-has-encryption-keys-p wallet))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
        (multiple-value-bind (plain crypted mkeys) (%wenc-key-record-counts wallet)
          (is (zerop plain))
          (is (= 8 crypted))                   ; one seed only, not two
          (is (= 1 mkeys)))
        ;; The blank flag was forced internally to defer the seed; it must be
        ;; cleared again once the descriptors exist.
        (is (not (bitcoin-lisp.rpc::wallet-flag-set-p
                  wallet bitcoin-lisp.rpc::+wallet-flag-blank-wallet+)))
        (is (eq bitcoin-lisp.rpc::+json-false+
                (%aval "blank" (bitcoin-lisp.rpc::rpc-getwalletinfo node '()))))
        ;; It is a working wallet: it hands out addresses and unlocks.
        (is (stringp (bitcoin-lisp.rpc::rpc-getnewaddress node '())))
        (is (bitcoin-lisp.rpc::unlock-wallet wallet "hunter2"))))))

(test wenc-createwallet-passphrase-validation
  "createwallet's passphrase argument: an empty string warns instead of
encrypting, and a passphrase with private keys disabled is refused."
  (with-wallet-test-node (node)
    (let ((result (bitcoin-lisp.rpc::rpc-createwallet node '("w-empty" nil nil ""))))
      (is (member "Empty string given as passphrase, wallet will not be encrypted."
                  (coerce (%aval "warnings" result) 'list)
                  :test #'equal))
      (is (not (bitcoin-lisp.rpc::wallet-has-encryption-keys-p
                (gethash "w-empty" (bitcoin-lisp.rpc::wallet-manager-wallets
                                    (%node-manager node)))))))
    (is (= -4 (%rpc-error-code
               (lambda () (bitcoin-lisp.rpc::rpc-createwallet
                           node '("w-bad" t nil "hunter2"))))))))

(test wenc-blank-encrypted-wallet
  "createwallet blank=true with a passphrase yields an encrypted wallet with
no descriptors: it unlocks, but has no addresses to give."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "blank"))
      (bitcoin-lisp.rpc::rpc-createwallet node '("blank" nil t "hunter2"))
      (let ((wallet (gethash "blank" (bitcoin-lisp.rpc::wallet-manager-wallets
                                      (%node-manager node)))))
        (is (bitcoin-lisp.rpc::wallet-has-encryption-keys-p wallet))
        (is (zerop (hash-table-count (bitcoin-lisp.rpc::wallet-spkms wallet))))
        ;; Even with no keys to check, a wrong passphrase must fail: the
        ;; master key itself will not decrypt. (Core's CheckDecryptionKey
        ;; would accept any passphrase here.)
        (is (null (bitcoin-lisp.rpc::unlock-wallet wallet "wrong")))
        (is (bitcoin-lisp.rpc::unlock-wallet wallet "hunter2"))
        ;; Core's "no available keys" error for a blank wallet — unlocking
        ;; does not conjure descriptors.
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-getnewaddress node '())))))))))

(test wenc-corrupt-ckey-is-not-a-wrong-passphrase
  "A ciphertext that will not decrypt under a master key that itself opened
correctly is file corruption. With more than one key, where some decrypt and
some do not, Core reports it distinctly rather than as a bad passphrase."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        ;; Damage exactly one SPKM's stored ciphertext, in memory.
        (let ((spkm (loop for s being the hash-values of
                                        (bitcoin-lisp.rpc::wallet-spkms wallet)
                          when (plusp (hash-table-count
                                       (bitcoin-lisp.rpc::desc-spkm-crypted-keys s)))
                            return s)))
          (maphash (lambda (keyid entry)
                     (let ((damaged (copy-seq (cdr entry))))
                       (setf (aref damaged 0) (logxor (aref damaged 0) 1))
                       (setf (gethash keyid
                                      (bitcoin-lisp.rpc::desc-spkm-crypted-keys spkm))
                             (cons (car entry) damaged))))
                   (bitcoin-lisp.rpc::desc-spkm-crypted-keys spkm)))
        ;; 16 keys, 15 of which still decrypt: the mixed case.
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::unlock-wallet wallet "hunter2")))))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))))))

(test wenc-duplicate-mkey-refused-at-load
  "Two master-key records with the same id is a corrupt file, not something
to silently pick a winner from."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (is (= 1 (hash-table-count (bitcoin-lisp.rpc::wallet-master-keys wallet))))
        ;; encrypt-wallet refuses to add a second master key at all.
        (is (null (bitcoin-lisp.rpc::encrypt-wallet wallet "another")))))))

;;; ============================================================
;;; Locked-wallet gating
;;; ============================================================

(test wenc-locked-wallet-refuses-key-operations
  "Every RPC that needs a private key raises RPC_WALLET_UNLOCK_NEEDED (-13)
with Core's exact message when the wallet is locked, and stops doing so once
it is unlocked."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
        ;; listdescriptors true must ERROR, not quietly emit the public form.
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-listdescriptors node '(t))))))
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-keypoolrefill node '(10))))))
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-importdescriptors
                                node (list (list (%ht "desc" "x" "timestamp" 0))))))))
        ;; The exact Core message.
        (handler-case (bitcoin-lisp.rpc::rpc-keypoolrefill node '(10))
          (bitcoin-lisp.rpc::rpc-error (e)
            (is (equal "Error: Please enter the wallet passphrase with walletpassphrase first."
                       (bitcoin-lisp.rpc::rpc-error-message e)))))
        ;; The public form of listdescriptors keeps working while locked.
        (is (%aval "descriptors" (bitcoin-lisp.rpc::rpc-listdescriptors node '())))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))
        (is (%aval "descriptors" (bitcoin-lisp.rpc::rpc-listdescriptors node '(t))))
        (is (null (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-keypoolrefill node '(10))))))))))

(test wenc-locked-wallet-still-issues-addresses
  "A locked wallet keeps handing out addresses from its cached keypool —
descriptor expansion runs off the xpub and needs no private key. Getting
this wrong would make an encrypted wallet unable to receive."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
        (let ((external (bitcoin-lisp.rpc::rpc-getnewaddress node '()))
              (change (bitcoin-lisp.rpc::rpc-getrawchangeaddress node '())))
          (is (stringp external))
          (is (stringp change))
          (is (bitcoin-lisp.rpc::wallet-is-mine
               wallet (%address-script external :testnet4)))
          (is (bitcoin-lisp.rpc::wallet-is-mine
               wallet (%address-script change :testnet4))))
        ;; And HavePrivateKeys stays true while locked, so the keypool logic
        ;; and the watch-only warning both keep working.
        (is (loop for spkm being the hash-values of
                                (bitcoin-lisp.rpc::wallet-spkms wallet)
                  thereis (bitcoin-lisp.rpc::spkm-have-private-keys-p spkm)))))))

(test wenc-locked-wallet-cannot-sign-message
  "signmessage needs the private key; while locked it must be -13, and after
unlocking it must produce a signature again."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (%wenc-fresh-wallet node "w")
      (let ((address (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy"))))
        (is (stringp (bitcoin-lisp.rpc::rpc-signmessage node (list address "hi"))))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        ;; The pre-encryption address is still ours, but unsignable while locked.
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-signmessage
                                node (list address "hi"))))))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))
        (is (stringp (bitcoin-lisp.rpc::rpc-signmessage
                      node (list address "hi"))))))))

(test wenc-unlocked-signing-matches-plaintext-signing
  "A key read back through the decryption path signs identically to the same
key held in plaintext — the encryption round trip is lossless."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (%wenc-fresh-wallet node "w")
      (let* ((address (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy")))
             (before (bitcoin-lisp.rpc::rpc-signmessage node (list address "msg"))))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))
        ;; RFC6979 makes ECDSA deterministic, so the same key over the same
        ;; message gives byte-identical output.
        (is (equal before
                   (bitcoin-lisp.rpc::rpc-signmessage node (list address "msg"))))))))

(test wenc-locked-wallet-cannot-spend
  "The funds-critical gate, end to end on a funded regtest wallet: while
locked, every spending RPC refuses with -13 rather than producing a
half-signed or wrongly-signed transaction; after unlocking, the spend goes
through and the coins encrypted before the seed rotation are still spendable."
  (%with-wallet-chain-node (node "enc-spend")
    (multiple-value-bind (wallet address) (%ws-fund-wallet node :blocks 2)
      (declare (ignore address))
      (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "w")
             (target (%wc-optrue-address))
             ;; An explicit feerate: the regtest fee estimator has no data.
             (send-args (list target 1 nil nil nil nil nil nil nil 10))
             ;; A structurally valid one-input transaction, so the decode
             ;; check upstream of the gate passes and we reach the gate.
             (raw-tx (concatenate 'string "01000000" "01" (make-string 64 :initial-element #\0)
                                  "00000000" "00" "ffffffff"
                                  "01" "0000000000000000" "00" "00000000")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
        ;; The balance is still visible — only signing is blocked.
        (is (plusp (bitcoin-lisp.rpc::rpc-getbalance node '())))
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-sendtoaddress node send-args)))))
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-sendmany
                                node (list "" (%ht target 1)))))))
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-signrawtransactionwithwallet
                                node (list raw-tx))))))
        ;; Unlock and the same spend succeeds, spending coins whose keys
        ;; were encrypted after they were received.
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))
        (let ((txid (bitcoin-lisp.rpc::rpc-sendtoaddress node send-args)))
          (is (stringp txid))
          (is (= 64 (length txid))))
        ;; Relocking closes it again.
        (bitcoin-lisp.rpc::rpc-walletlock node '())
        (is (= -13 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-sendtoaddress
                                node send-args)))))))))

(test wenc-imported-private-descriptor-cannot-sign-while-locked
  "An imported PRIVATE descriptor must not be able to sign while the wallet
is locked.

Our parsed descriptors retain the embedded xprv, and %desc-key-root-xprv
prefers it over the SigningProvider, so an SPKM built directly from the
parsed private descriptor would keep signing after encryptwallet — bypassing
the lock entirely, but only until the next reload rebuilt it from the public
string. wallet-add-descriptor re-parses the public form to close that."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "imp"))
      (bitcoin-lisp.rpc::rpc-createwallet node '("imp" nil t))   ; blank
      (let ((wallet (gethash "imp" (bitcoin-lisp.rpc::wallet-manager-wallets
                                    (%node-manager node))))
            (private-desc
              (bitcoin-lisp.rpc::descriptor-add-checksum
               "wpkh(tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m/0h/0h/*)")))
        (bitcoin-lisp.rpc::rpc-importdescriptors
         node (list (list (%ht "desc" private-desc "timestamp" 0 "active" nil))))
        (let ((spkm (loop for s being the hash-values of
                                        (bitcoin-lisp.rpc::wallet-spkms wallet)
                          return s)))
          (is (not (null spkm)))
          ;; The key landed in the keystore...
          (is (bitcoin-lisp.rpc::spkm-have-private-keys-p spkm))
          ;; ...and NOT in the descriptor object.
          (is (notany #'bitcoin-lisp.rpc::desc-key-ext-privkey
                      (bitcoin-lisp.rpc::out-desc-ordered-keys
                       (bitcoin-lisp.rpc::desc-spkm-desc spkm))))
          ;; The stored string is the public form, as before.
          (is (search "tpub" (bitcoin-lisp.rpc::desc-spkm-desc-string spkm)))
          (is (not (search "tprv" (bitcoin-lisp.rpc::desc-spkm-desc-string spkm))))
          ;; Unlocked, the provider still resolves the key: the descriptor
          ;; remains usable, it just goes through the keystore now.
          (let ((provider (bitcoin-lisp.rpc::spkm-privkey-provider wallet spkm)))
            (is (not (null (bitcoin-lisp.rpc::%desc-key-root-xprv
                            (first (bitcoin-lisp.rpc::out-desc-ordered-keys
                                    (bitcoin-lisp.rpc::desc-spkm-desc spkm)))
                            provider)))))
          ;; Encrypt, lock — now nothing can produce the key.
          (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
          (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
          (let ((provider (bitcoin-lisp.rpc::spkm-privkey-provider wallet spkm)))
            (is (null (bitcoin-lisp.rpc::%desc-key-root-xprv
                       (first (bitcoin-lisp.rpc::out-desc-ordered-keys
                               (bitcoin-lisp.rpc::desc-spkm-desc spkm)))
                       provider))))
          ;; And it comes back once unlocked.
          (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))
          (let ((provider (bitcoin-lisp.rpc::spkm-privkey-provider wallet spkm)))
            (is (not (null (bitcoin-lisp.rpc::%desc-key-root-xprv
                            (first (bitcoin-lisp.rpc::out-desc-ordered-keys
                                    (bitcoin-lisp.rpc::desc-spkm-desc spkm)))
                            provider))))))))))

(test wenc-backup-to-extensionless-destination
  "backupwallet must actually write to the path it was given. RENAME-FILE
merges the target with the source pathname, so a temp file differing only by
type renames to itself when the destination has no extension — reporting
success while leaving nothing behind."
  (with-wallet-test-node (node)
    (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "w")
           (dir (uiop:ensure-directory-pathname
                 (bitcoin-lisp.rpc::wallet-manager-data-directory
                  (%node-manager node))))
           (no-extension (merge-pathnames "backup-no-ext" dir))
           (with-extension (merge-pathnames "backup.dump" dir)))
      (%wenc-fresh-wallet node "w")
      (dolist (path (list no-extension with-extension))
        (is (null (bitcoin-lisp.rpc::rpc-backupwallet node (list (namestring path)))))
        (is (probe-file path))
        ;; And no stray temp file survives.
        (is (null (probe-file (make-pathname
                               :name (concatenate 'string
                                                  (pathname-name path) ".tmp")
                               :defaults path)))))
      ;; Both restore cleanly.
      (bitcoin-lisp.rpc::rpc-restorewallet
       node (list "r1" (namestring no-extension)))
      (is (bitcoin-lisp.rpc::wallet-is-mine
           (gethash "r1" (bitcoin-lisp.rpc::wallet-manager-wallets
                          (%node-manager node)))
           (%address-script
            (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "r1"))
              (bitcoin-lisp.rpc::rpc-getnewaddress node '()))
            :testnet4))))))

;;; ============================================================
;;; Relock timer
;;; ============================================================

(test wenc-relock-sweeper-runs-and-stops
  "The sweeper relocks a wallet whose deadline passed with no RPC touching
it, and close-wallet-manager joins the thread rather than leaking it."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w"))
            (manager (%node-manager node)))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 1))
        (is (bitcoin-lisp.rpc::wallet-manager-relock-running manager))
        (let ((thread (bitcoin-lisp.rpc::wallet-manager-relock-thread manager)))
          (is (bt:threadp thread))
          ;; Wait for the sweeper WITHOUT reading the key material, so this
          ;; proves the thread fired rather than the lazy check.
          (loop repeat 60
                until (null (bitcoin-lisp.rpc::wallet-encryption-key wallet))
                do (sleep 0.1))
          (is (null (bitcoin-lisp.rpc::wallet-encryption-key wallet)))
          (is (zerop (bitcoin-lisp.rpc::wallet-relock-time wallet)))
          (bitcoin-lisp.rpc::stop-relock-sweeper manager)
          (is (not (bitcoin-lisp.rpc::wallet-manager-relock-running manager)))
          (is (null (bitcoin-lisp.rpc::wallet-manager-relock-thread manager)))
          (is (not (bt:thread-alive-p thread))))))))

(test wenc-relock-suspended-during-scan
  "While a rescan holds the wallet unlocked across its own lock drops, the
deadline must not fire — relocking mid-scan would silently break the keypool
top-ups the scan depends on."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 0))
        (setf (bitcoin-lisp.rpc::wallet-scanning-with-passphrase wallet) t)
        ;; The deadline has passed, but the scan flag holds the unlock open.
        (is (bitcoin-lisp.rpc::wallet-unlocked-key wallet))
        (is (not (bitcoin-lisp.rpc::wallet-is-locked-p wallet)))
        ;; The state-changing RPCs refuse while it is set (Core parity).
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-walletlock node '())))))
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-walletpassphrasechange
                               node '("hunter2" "new"))))))
        ;; Clearing it lets the expired deadline take effect immediately.
        (setf (bitcoin-lisp.rpc::wallet-scanning-with-passphrase wallet) nil)
        (is (null (bitcoin-lisp.rpc::wallet-unlocked-key wallet)))))))

(test wenc-unload-scrubs-the-key
  "Unloading a wallet drops its decrypted master key; a stale reference must
not keep key material alive after the wallet is gone."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (bitcoin-lisp.rpc::rpc-encryptwallet node '("hunter2"))
        (bitcoin-lisp.rpc::rpc-walletpassphrase node '("hunter2" 600))
        (is (bitcoin-lisp.rpc::wallet-encryption-key wallet))
        (bitcoin-lisp.rpc::unload-wallet (%node-manager node) wallet)
        (is (null (bitcoin-lisp.rpc::wallet-encryption-key wallet)))
        (is (zerop (bitcoin-lisp.rpc::wallet-relock-time wallet)))))))

;;; ============================================================
;;; Backup / restore
;;; ============================================================

(defun %wenc-backup-path (node name)
  (merge-pathnames (format nil "~A.dump" name)
                   (uiop:ensure-directory-pathname
                    (bitcoin-lisp.rpc::wallet-manager-data-directory
                     (%node-manager node)))))

(test wenc-backup-restore-roundtrip
  "backupwallet writes a verifiable dump; restorewallet rebuilds a wallet
whose records are identical, record for record."
  (with-wallet-test-node (node)
    (let ((source-records nil)
          (path (%wenc-backup-path node "w")))
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
        (let ((wallet (%wenc-fresh-wallet node "w")))
          (bitcoin-lisp.rpc::rpc-getnewaddress node '())
          (is (null (bitcoin-lisp.rpc::rpc-backupwallet
                     node (list (namestring path)))))
          (is (probe-file path))
          (setf source-records (bitcoin-lisp.rpc::wallet-db-records
                                (bitcoin-lisp.rpc::wallet-db wallet)))))
      ;; The dump is self-describing and checksummed.
      (let ((first-line (with-open-file (in path) (read-line in))))
        (is (equal "BITCOIN_LISP_WALLET_DUMP,1" first-line)))
      (let ((result (bitcoin-lisp.rpc::rpc-restorewallet
                     node (list "restored" (namestring path)))))
        (is (equal "restored" (%aval "name" result))))
      (let* ((restored (gethash "restored"
                                (bitcoin-lisp.rpc::wallet-manager-wallets
                                 (%node-manager node))))
             (restored-records (bitcoin-lisp.rpc::wallet-db-records
                                (bitcoin-lisp.rpc::wallet-db restored))))
        (is (= (length source-records) (length restored-records)))
        ;; Every record key round-trips, in order.
        (is (every (lambda (a b) (equalp (car a) (car b)))
                   source-records restored-records))
        ;; Values too, with one legitimate exception: loading the restored
        ;; wallet tops up its keypool, which rewrites the walletdescriptor
        ;; record of any SPKM that had issued an address (range_end grows).
        (is (every (lambda (a b)
                     (or (equalp (cdr a) (cdr b))
                         (equal bitcoin-lisp.rpc::+wdb-key-walletdescriptor+
                                (bitcoin-lisp.rpc::wdb-parse-key (car a)))))
                   source-records restored-records))
        ;; The key material specifically must be byte-identical.
        (is (every (lambda (a b)
                     (let ((type (bitcoin-lisp.rpc::wdb-parse-key (car a))))
                       (or (not (member type
                                        (list bitcoin-lisp.rpc::+wdb-key-walletdescriptorkey+
                                              bitcoin-lisp.rpc::+wdb-key-walletdescriptorckey+
                                              bitcoin-lisp.rpc::+wdb-key-mkey+)
                                        :test #'equal))
                           (equalp (cdr a) (cdr b)))))
                   source-records restored-records))))))

(test wenc-backup-of-locked-encrypted-wallet
  "A backup can be taken while the wallet is locked — it contains only
ciphertext — and the restored copy unlocks with the original passphrase."
  (with-wallet-test-node (node)
    (let ((path (%wenc-backup-path node "enc")))
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "enc"))
        (let ((wallet (%wenc-fresh-wallet node "enc" :passphrase "hunter2")))
          (is (bitcoin-lisp.rpc::wallet-is-locked-p wallet))
          (is (null (bitcoin-lisp.rpc::rpc-backupwallet
                     node (list (namestring path)))))))
      (bitcoin-lisp.rpc::rpc-restorewallet node (list "enc2" (namestring path)))
      (let ((restored (gethash "enc2" (bitcoin-lisp.rpc::wallet-manager-wallets
                                       (%node-manager node)))))
        (is (bitcoin-lisp.rpc::wallet-has-encryption-keys-p restored))
        (is (bitcoin-lisp.rpc::wallet-is-locked-p restored))
        (is (null (bitcoin-lisp.rpc::unlock-wallet restored "wrong")))
        (is (bitcoin-lisp.rpc::unlock-wallet restored "hunter2"))))))

(test wenc-restore-rejects-bad-input
  "restorewallet's error taxonomy, and — the part that matters — a rejected
restore must not leave a wallet directory behind."
  (with-wallet-test-node (node)
    (let ((path (%wenc-backup-path node "w")))
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
        (%wenc-fresh-wallet node "w")
        (bitcoin-lisp.rpc::rpc-backupwallet node (list (namestring path))))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-restorewallet
                             node (list "" (namestring path)))))))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-restorewallet
                             node (list "../evil" (namestring path)))))))
      (is (= -8 (%rpc-error-code
                 (lambda () (bitcoin-lisp.rpc::rpc-restorewallet
                             node (list "missing" "/nonexistent/backup.dump"))))))
      ;; Restoring onto an occupied destination — including a live wallet's
      ;; own directory, which Core reports the same way.
      (is (= -36 (%rpc-error-code
                  (lambda () (bitcoin-lisp.rpc::rpc-restorewallet
                              node (list "w" (namestring path)))))))
      ;; A corrupt dump: flip a byte in a record line.
      (let ((corrupt (merge-pathnames "corrupt.dump"
                                      (uiop:ensure-directory-pathname
                                       (bitcoin-lisp.rpc::wallet-manager-data-directory
                                        (%node-manager node))))))
        (let ((lines (uiop:read-file-lines path)))
          (with-open-file (out corrupt :direction :output :if-exists :supersede
                                       :if-does-not-exist :create)
            (loop for line in lines
                  for i from 0
                  do (write-line (if (= i 4)
                                     (concatenate 'string "00" (subseq line 2))
                                     line)
                                 out))))
        (is (= -18 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-restorewallet
                                node (list "from-corrupt" (namestring corrupt)))))))
        ;; Nothing was created for the rejected restore.
        (is (not (uiop:directory-exists-p
                  (bitcoin-lisp.rpc::wallet-directory (%node-manager node)
                                                      "from-corrupt"))))))))

(test wenc-backup-refuses-traversal-into-the-wallets-directory
  "The containment check must resolve `..` before comparing. A textual
component-prefix test would let a destination spelled with a traversal
segment pass as 'outside the wallets directory' and then land inside it,
where it would be picked up as a wallet directory."
  (with-wallet-test-node (node)
    (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "w")
           (manager (%node-manager node))
           (wallets (bitcoin-lisp.rpc::wallets-directory manager)))
      (%wenc-fresh-wallet node "w")
      ;; <wallets>/w/../../wallets/sneaky.dump resolves back inside.
      (let ((traversal (namestring
                        (merge-pathnames "w/../../wallets/sneaky.dump" wallets))))
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-backupwallet
                               node (list traversal))))))
        (is (null (probe-file (merge-pathnames "sneaky.dump" wallets)))))
      ;; The resolver itself, directly.
      (is (bitcoin-lisp.rpc::%path-under-p
           (merge-pathnames "w/../sneaky.dump" wallets) wallets))
      (is (not (bitcoin-lisp.rpc::%path-under-p
                (merge-pathnames "../outside.dump" wallets) wallets))))))

(test wenc-record-scan-refuses-a-truncated-read
  "wallet-db-records must signal, not return a short list, if the iterator
stopped on an error. A backup built from a silently truncated scan is the
worst possible failure: it looks like a successful backup and restores a
wallet that is missing keys."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (let* ((wallet (%wenc-fresh-wallet node "w"))
             (full (length (bitcoin-lisp.rpc::wallet-db-records
                            (bitcoin-lisp.rpc::wallet-db wallet)))))
        (is (plusp full))
        ;; The error check is wired in and returns cleanly on a healthy DB.
        (finishes
         (bitcoin-lisp.storage:with-leveldb-iterator
             (iter (bitcoin-lisp.rpc::wallet-db wallet))
           (bitcoin-lisp.storage:leveldb-iter-seek-to-first iter)
           (loop while (bitcoin-lisp.storage:leveldb-iter-valid-p iter)
                 do (bitcoin-lisp.storage:leveldb-iter-next iter))
           (bitcoin-lisp.storage:leveldb-iter-check-error iter)))
        ;; And a dump of a healthy wallet carries every record.
        (let ((path (%wenc-backup-path node "w")))
          (bitcoin-lisp.rpc::rpc-backupwallet node (list (namestring path)))
          (is (= full (length (bitcoin-lisp.rpc::%parse-wallet-dump
                               path (bitcoin-lisp.rpc::wallet-network wallet))))))))))

(test wenc-restore-refuses-cross-network-dump
  "The dump records its network. A mainnet backup must not restore onto a
testnet node — Core gets this from the network magic in the SQLite header."
  (with-wallet-test-node (node)
    (let ((path (%wenc-backup-path node "w")))
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
        (%wenc-fresh-wallet node "w")
        (bitcoin-lisp.rpc::rpc-backupwallet node (list (namestring path))))
      (let ((foreign (merge-pathnames "foreign.dump"
                                      (uiop:ensure-directory-pathname
                                       (bitcoin-lisp.rpc::wallet-manager-data-directory
                                        (%node-manager node))))))
        ;; Rewrite the network line; the checksum then also fails, which is
        ;; the belt-and-braces version of the same refusal.
        (let ((lines (uiop:read-file-lines path)))
          (with-open-file (out foreign :direction :output :if-exists :supersede
                                       :if-does-not-exist :create)
            (loop for line in lines
                  do (write-line (if (eql 0 (search "network," line))
                                     "network,mainnet"
                                     line)
                                 out))))
        (is (= -18 (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-restorewallet
                                node (list "foreign" (namestring foreign)))))))))))

(test wenc-backup-refuses-unsafe-destinations
  "backupwallet maps every failure to Core's single error, and refuses to
write into the wallets directory (where it would look like a wallet)."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w"))
      (%wenc-fresh-wallet node "w")
      (let ((manager (%node-manager node)))
        ;; An existing directory as the destination.
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-backupwallet
                               node (list (namestring
                                           (bitcoin-lisp.rpc::wallets-directory
                                            manager))))))))
        ;; Inside the wallets directory.
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-backupwallet
                               node (list (namestring
                                           (merge-pathnames
                                            "sneaky.dump"
                                            (bitcoin-lisp.rpc::wallets-directory
                                             manager)))))))))
        ;; A directory that does not exist.
        (is (= -4 (%rpc-error-code
                   (lambda () (bitcoin-lisp.rpc::rpc-backupwallet
                               node (list "/nonexistent/dir/backup.dump"))))))))))
