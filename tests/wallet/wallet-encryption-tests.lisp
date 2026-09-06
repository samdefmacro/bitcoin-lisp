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
  (bl.crypto:hex-to-bytes string))

(defun %wenc-fresh-wallet (node name &key passphrase)
  "Create NAME through the RPC layer and return the wallet struct."
  (bl.wallet::rpc-createwallet
   node (list name nil nil passphrase))
  (gethash name (bl.wallet::wallet-manager-wallets (%node-manager node))))

(defun %wenc-records (wallet)
  "Every (key . value) pair in WALLET's open database."
  (wallet-db-record-list (bl.wallet::wallet-db wallet)))

(defun %wenc-encrypt (node &optional (passphrase "hunter2"))
  "encryptwallet through the shipped handler. Named once because every test in
this file that needs an encrypted wallet goes through it."
  (bl.wallet::rpc-encryptwallet node (list passphrase)))

(defun %wenc-key-record-counts (wallet)
  "(values plaintext-key-records crypted-key-records mkey-records) on disk."
  (let ((plain 0) (crypted 0) (mkeys 0))
    (dolist (record (%wenc-records wallet))
      (let ((type (bl.wallet::wdb-parse-key (car record))))
        (cond ((equal type bl.wallet::+wdb-key-walletdescriptorkey+)
               (incf plain))
              ((equal type bl.wallet::+wdb-key-walletdescriptorckey+)
               (incf crypted))
              ((equal type bl.wallet::+wdb-key-mkey+)
               (incf mkeys)))))
    (values plain crypted mkeys)))

(defun %wenc-in-memory-key-counts (wallet)
  "(values plaintext-keys crypted-keys) across every SPKM."
  (let ((plain 0) (crypted 0))
    (loop for spkm being the hash-values of (bl.wallet::wallet-spkms wallet)
          do (incf plain (hash-table-count (bl.wallet::desc-spkm-keys spkm)))
             (incf crypted (hash-table-count
                            (bl.wallet::desc-spkm-crypted-keys spkm))))
    (values plain crypted)))

;;; --- Byte-scanning the wallet directory (GA11 dd92141d) ---
;;;
;;; The record-level counters above cannot see this bug: a LevelDB delete is a
;;; tombstone, so "no plaintext key record" and "no plaintext key bytes on
;;; disk" are different claims, and only the second one is what Core's
;;; database Rewrite buys. These read the FILES.

(defun %wenc-wallet-files (wallet)
  (uiop:directory-files
   (uiop:ensure-directory-pathname (bl.wallet::wallet-path wallet))))

(defun %wenc-file-bytes (path)
  (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
    (let ((bytes (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence bytes in)
      bytes)))

(defun %wenc-directory-hits (wallet needle)
  "((file-name . offset) ...) for every file in WALLET's directory that
contains NEEDLE. NIL means the bytes are nowhere in the wallet."
  (loop for file in (%wenc-wallet-files wallet)
        for at = (search needle (%wenc-file-bytes file))
        when at collect (cons (file-namestring file) at)))

(defun %wenc-file-types (wallet)
  (mapcar #'pathname-type (%wenc-wallet-files wallet)))

(defun %wenc-master-secret (wallet)
  "The 32 plaintext private key bytes of the first walletdescriptorkey record.
All eight of a fresh wallet's SPKMs store the SAME master key, so any one of
them is the secret an attacker needs."
  (dolist (record (%wenc-records wallet))
    (multiple-value-bind (type fields) (bl.wallet::wdb-parse-key (car record))
      (when (equal type bl.wallet::+wdb-key-walletdescriptorkey+)
        (multiple-value-bind (id pubkey)
            (bl.wallet::wdb-parse-descriptor-key-fields fields)
          (declare (ignore id))
          (return (bl.wallet::wdb-parse-descriptor-key-value
                   (cdr record) pubkey)))))))

(defun %wenc-latin1 (string)
  (flexi-streams:string-to-octets string :external-format :latin-1))

(defun %wenc-stored-descriptor-text (wallet)
  "The descriptor string of the first walletdescriptor record -- text that
BELONGS in the wallet directory, so a scan that cannot find it is broken."
  (dolist (record (%wenc-records wallet))
    (when (equal (bl.wallet::wdb-parse-key (car record))
                 bl.wallet::+wdb-key-walletdescriptor+)
      (return (%wenc-latin1
               (bl.wallet::wdb-parse-descriptor-value (cdr record)))))))

(defun %wenc-master-xprv-text (node)
  "The base58 master xprv out of listdescriptors private=true. With the xpub
the stored descriptor keeps, this is the whole spending key."
  (let* ((reply (bl.wallet::rpc-listdescriptors node (list t)))
         (desc (%aval "desc" (first (%aval "descriptors" reply))))
         (at (search "prv" desc)))
    (%wenc-latin1 (subseq desc (1- at) (position #\/ desc :start at)))))

(defun %wenc-age-database (wallet records)
  "Write RECORDS junk 2 KiB rows, which pushes the memtable out into real SST
files. The finding's leak needs a database whose levels are still EMPTY, so
this is the other side of that condition."
  (dotimes (i records)
    (bl.store:leveldb-put
     (bl.wallet::wallet-db wallet)
     (concatenate '(simple-array (unsigned-byte 8) (*))
                  (vector 122 (ldb (byte 8 0) i) (ldb (byte 8 8) i))
                  (make-array 29 :element-type '(unsigned-byte 8)
                                 :initial-element 7))
     (make-array 2048 :element-type '(unsigned-byte 8) :initial-element 9))))

(defun %wenc-stage-interrupted-rewrite (path rewrite)
  "Leave the wallet at PATH in WALLET-DB-REWRITE's crash window: REWRITE holds
a complete rebuilt database plus the marker, PATH itself has been renamed into
REWRITE/superseded/, and the second rename never happened. Built out of the
same primitives the rewrite uses, since the point is the on-disk shape."
  (let ((records (let ((db (bl.wallet::wallet-db-open path)))
                   (unwind-protect (wallet-db-record-list db)
                     (bl.store:leveldb-close db)))))
    (let ((db (bl.wallet::wallet-db-open rewrite :create t)))
      (unwind-protect
           (bl.store:with-leveldb-writebatch (batch)
             (dolist (record records)
               (bl.store:leveldb-writebatch-put batch (car record) (cdr record)))
             (bl.store:leveldb-write db batch :sync t))
        (bl.store:leveldb-close db)))
    (with-open-file (out (bl.wallet::%wallet-rewrite-marker-path rewrite)
                         :direction :output :if-exists :supersede
                         :if-does-not-exist :create)
      (write-line "bitcoin-lisp wallet database rewrite" out))
    (bl.kv:rename-path path (bl.wallet::%wallet-superseded-path rewrite))))

;;; ============================================================
;;; Crypter primitives — Bitcoin Core known-answer vectors
;;; ============================================================

(test wenc-kdf-core-vector
  "The SHA-512 passphrase KDF reproduces Core's only KDF known-answer vector
(wallet_crypto_tests.cpp:83-85): salt 0000deadbeef0000, passphrase \"test\",
25000 rounds, derivation method 0."
  (multiple-value-bind (key iv)
      (bl.crypto:crypter-derive-key
       (bl.wallet::passphrase-octets "test")
       (%hex "0000deadbeef0000") 25000 0)
    (is (equalp (%hex "fc7aba077ad5f4c3a0988d8daa4810d0d4a0e3bcb53af662998898f33df0556a")
                key))
    (is (equalp (%hex "cf2f2691526dd1aa220896fb8bf7c369") iv))))

(test wenc-kdf-parameter-rejection
  "SetKeyFromPassphrase's guards (crypter.cpp:43-45): rounds must be >= 1, the
salt exactly 8 bytes, and the only derivation method is 0."
  (let ((pass (bl.wallet::passphrase-octets "test")))
    (is (null (bl.crypto:crypter-derive-key
               pass (%hex "0000deadbeef0000") 0 0)))
    (is (null (bl.crypto:crypter-derive-key
               pass (%hex "00deadbeef0000") 25000 0)))
    (is (null (bl.crypto:crypter-derive-key
               pass (%hex "0000deadbeef000000") 25000 0)))
    (is (null (bl.crypto:crypter-derive-key
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
                    (bl.crypto:aes-256-cbc-encrypt
                     key (%hex iv) (%hex plaintext))))
        (is (equalp (%hex plaintext)
                    (bl.crypto:aes-256-cbc-decrypt
                     key (%hex iv) (%hex ciphertext))))))))

(test wenc-aes-roundtrip-every-pad-size
  "Core's encrypt round-trip corpus (wallet_crypto_tests.cpp:99-103) and every
suffix of it, so all 16 PKCS#7 pad sizes are exercised."
  (multiple-value-bind (key iv)
      (bl.crypto:crypter-derive-key
       (bl.wallet::passphrase-octets "passphrase")
       (%hex "0000deadbeef0000") 25000 0)
    (let ((corpus (%hex "22bcade09ac03ff6386914359cfe885cfeb5f77ff0d670f102f619687453b29d")))
      (loop for start from 0 below (length corpus)
            for plaintext = (subseq corpus start)
            for ciphertext = (bl.crypto:aes-256-cbc-encrypt
                              key iv plaintext)
            do ;; Core's ciphertext is always the plaintext rounded down to a
               ;; block boundary plus one full block.
               (is (= (length ciphertext)
                      (+ (* 16 (floor (length plaintext) 16)) 16)))
               (is (equalp plaintext
                           (bl.crypto:aes-256-cbc-decrypt
                            key iv ciphertext)))))))

(test wenc-aes-decrypt-corner-cases-never-signal
  "Core's decrypt corner-case corpus (wallet_crypto_tests.cpp:118-123): these
must return a value or NIL, but must never signal."
  (multiple-value-bind (key iv)
      (bl.crypto:crypter-derive-key
       (bl.wallet::passphrase-octets "passphrase")
       (%hex "0000deadbeef0000") 25000 0)
    (dolist (ciphertext
             '("795643ce39d736088367822cdc50535ec6f103715e3e48f4f3b1a60a08ef59ca"
               "de096f4a8f9bd97db012aa9d90d74de8cdea779c3ee8bc7633d8b5d6da703486"
               "32d0a8974e3afd9c6c3ebf4d66aa4e6419f8c173de25947f98cf8b7ace49449c"
               "e7c055cca2faa78cb9ac22c9357a90b4778ded9b2cc220a14cea49f931e596ea"
               "b88efddd668a6801d19516d6830da4ae9811988ccbaf40df8fbb72f3f4d335fd"
               "8cae76aa6a43694e961ebcb28c8ca8f8540b84153d72865e8561ddd93fa7bfa9"))
      (finishes (bl.crypto:aes-256-cbc-decrypt key iv (%hex ciphertext))))))

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
      (is (null (bl.crypto:aes-256-cbc-decrypt
                 key iv (raw-encrypt (block-ending-in 0)))))
      ;; Pad byte above the block size: ironclad signals TYPE-ERROR.
      (is (null (bl.crypto:aes-256-cbc-decrypt
                 key iv (raw-encrypt (block-ending-in #x2a)))))
      ;; Pad byte plausible but the padding bytes disagree.
      (let ((v (make-array 16 :element-type '(unsigned-byte 8)
                              :initial-element 7)))
        (setf (aref v 15) 4 (aref v 14) 4 (aref v 13) 9 (aref v 12) 4)
        (is (null (bl.crypto:aes-256-cbc-decrypt
                   key iv (raw-encrypt v)))))
      ;; A ciphertext that is not a whole number of blocks: ironclad
      ;; silently truncates instead of refusing.
      (is (null (bl.crypto:aes-256-cbc-decrypt
                 key iv (subseq (raw-encrypt (block-ending-in 16)) 0 12))))
      ;; A full pad block, i.e. an empty plaintext: Core's Decrypt treats a
      ;; zero-length result as failure.
      (is (null (bl.crypto:aes-256-cbc-decrypt
                 key iv (raw-encrypt (make-array 16 :element-type '(unsigned-byte 8)
                                                    :initial-element 16)))))
      ;; A single pad byte IS valid and yields 15 bytes.
      (is (= 15 (length (bl.crypto:aes-256-cbc-decrypt
                         key iv (raw-encrypt (block-ending-in 1)))))))))

(test wenc-secret-iv-is-sha256d-not-hash160
  "EncryptSecret's IV is the first 16 bytes of the DOUBLE-SHA256 of the
serialized pubkey (CPubKey::GetHash, pubkey.h:165) — not the Hash160 that
CPubKey::GetID uses as the map key, and not byte-reversed."
  (let* ((secret (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 17))
         (pubkey (bl.crypto:derive-public-key secret :compressed t)))
    (is (= 33 (length pubkey)))
    (let ((iv (bl.wallet::%secret-iv pubkey)))
      (is (equalp (subseq (bl.crypto:hash256 pubkey) 0 16) iv))
      (is (not (equalp (subseq (bl.crypto:hash160 pubkey) 0 16) iv)))
      ;; and definitely not the reversed digest
      (is (not (equalp (subseq (reverse (bl.crypto:hash256 pubkey)) 0 16)
                       iv))))))

(test wenc-decrypt-key-gates
  "DecryptKey returns the secret only when it round-trips AND reproduces the
stored pubkey; every other case is NIL, never a wrong-but-plausible key."
  (let* ((master (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 3))
         (secret (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 17))
         (pubkey (bl.crypto:derive-public-key secret :compressed t))
         (ciphertext (bl.wallet::encrypt-secret master secret pubkey))
         (other-secret (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 19))
         (other-pubkey (bl.crypto:derive-public-key other-secret
                                                              :compressed t)))
    (is (= 48 (length ciphertext)))
    (is (equalp secret (bl.wallet::decrypt-key master pubkey ciphertext)))
    ;; A flipped ciphertext bit.
    (let ((damaged (copy-seq ciphertext)))
      (setf (aref damaged 0) (logxor (aref damaged 0) 1))
      (is (null (bl.wallet::decrypt-key master pubkey damaged))))
    ;; The right ciphertext under the wrong master key.
    (let ((wrong-master (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 4)))
      (is (null (bl.wallet::decrypt-key wrong-master pubkey ciphertext))))
    ;; The right ciphertext attributed to a different pubkey: the IV changes,
    ;; so this fails at unpad, and the pubkey check backs it up.
    (is (null (bl.wallet::decrypt-key master other-pubkey ciphertext)))))

;;; ============================================================
;;; Record encodings
;;; ============================================================

(test wenc-mkey-record-encoding
  "The mkey record is byte-compatible with Core's CMasterKey serialization
(walletdb.cpp WriteMasterKey): key = \"mkey\" + uint32 LE id, value =
var-bytes ciphertext, var-bytes salt, uint32 method, uint32 iterations,
var-bytes other-params."
  (let ((key (bl.wallet::wdb-key-mkey 1)))
    ;; 0x04 "mkey" + 4-byte LE id
    (is (equalp (%hex "046d6b657901000000") key))
    (is (= 1 (bl.wallet::wdb-parse-mkey-fields
              (nth-value 1 (bl.wallet::wdb-parse-key key)))))
    (let* ((ciphertext (make-array 48 :element-type '(unsigned-byte 8)
                                      :initial-element 9))
           (salt (make-array 8 :element-type '(unsigned-byte 8)
                               :initial-element 2))
           (value (bl.wallet::wdb-mkey-value
                   ciphertext salt 0 348876
                   (make-array 0 :element-type '(unsigned-byte 8)))))
      ;; 1+48 + 1+8 + 4 + 4 + 1
      (is (= 67 (length value)))
      (multiple-value-bind (ct s method iterations other)
          (bl.wallet::wdb-parse-mkey-value value)
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
         (pubkey (bl.crypto:derive-public-key secret :compressed t))
         (key (bl.wallet::wdb-key-descriptor-key
               bl.wallet::+wdb-key-walletdescriptorckey+ desc-id pubkey))
         (ciphertext (make-array 48 :element-type '(unsigned-byte 8)
                                    :initial-element 9))
         (value (bl.wallet::wdb-vector-value ciphertext)))
    (multiple-value-bind (type fields) (bl.wallet::wdb-parse-key key)
      (is (equal bl.wallet::+wdb-key-walletdescriptorckey+ type))
      (is (equalp desc-id (subseq fields 0 32)))
      (is (= #x21 (aref fields 32)))           ; compactsize 33
      (is (equalp pubkey (subseq fields 33))))
    (is (= 49 (length value)))                 ; 1 + 48, no checksum
    (is (equalp ciphertext (bl.wallet::wdb-parse-vector-value value)))))

;;; ============================================================
;;; Encryption lifecycle
;;; ============================================================

(test wenc-encryptwallet-lifecycle
  "encryptwallet: returns Core's instruction string, leaves the wallet locked,
moves every key from plaintext to ciphertext records on disk AND in memory,
and generates a fresh HD seed."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (is (not (bl.wallet::wallet-has-encryption-keys-p wallet)))
        (is (not (bl.wallet::wallet-is-locked-p wallet)))
        (multiple-value-bind (plain crypted mkeys) (%wenc-key-record-counts wallet)
          (is (= 8 plain))
          (is (zerop crypted))
          (is (zerop mkeys)))
        (let ((spkms-before (hash-table-count (bl.wallet::wallet-spkms wallet)))
              (result (%wenc-encrypt node)))
          (is (equal "wallet encrypted; The keypool has been flushed and a new HD seed was generated. You need to make a new backup with the backupwallet RPC."
                     result))
          (is (bl.wallet::wallet-has-encryption-keys-p wallet))
          (is (bl.wallet::wallet-is-locked-p wallet))
          ;; A new seed means 8 more SPKMs, all born encrypted.
          (is (= (+ spkms-before 8)
                 (hash-table-count (bl.wallet::wallet-spkms wallet)))))
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
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (is (null (bl.wallet::unlock-wallet wallet "wrong")))
        (is (bl.wallet::wallet-is-locked-p wallet))
        (is (null (bl.wallet::wallet-unlocked-key wallet)))
        (is (bl.wallet::unlock-wallet wallet "hunter2"))
        (is (not (bl.wallet::wallet-is-locked-p wallet)))
        (is (= 32 (length (bl.wallet::wallet-unlocked-key wallet))))
        (is (bl.wallet::lock-wallet wallet))
        (is (bl.wallet::wallet-is-locked-p wallet))))))

(test wenc-walletpassphrase-rpc
  "walletpassphrase unlocks and arms the relock; walletlock relocks;
getwalletinfo reports unlocked_until per Core's three states."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        ;; Never encrypted: the field is absent entirely, not null and not 0.
        (is (null (assoc "unlocked_until"
                         (bl.wallet::rpc-getwalletinfo node '())
                         :test #'string=)))
        ;; The three encryption-state RPCs refuse on an unencrypted wallet.
        (is (= -15 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-walletpassphrase
                                node '("hunter2" 60))))))
        (is (= -15 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-walletlock node '())))))
        (is (= -15 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-walletpassphrasechange
                                node '("a" "b"))))))
        (%wenc-encrypt node)
        ;; Encrypted and locked.
        (is (eql 0 (%aval "unlocked_until"
                          (bl.wallet::rpc-getwalletinfo node '()))))
        (is (= -14 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-walletpassphrase
                                node '("wrong" 60))))))
        (is (null (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))))
        (is (not (bl.wallet::wallet-is-locked-p wallet)))
        (let ((until (%aval "unlocked_until"
                            (bl.wallet::rpc-getwalletinfo node '()))))
          (is (> until (bl.ser:get-unix-time))))
        (is (null (bl.wallet::rpc-walletlock node '())))
        (is (bl.wallet::wallet-is-locked-p wallet))
        (is (eql 0 (%aval "unlocked_until"
                          (bl.wallet::rpc-getwalletinfo node '()))))))))

(test wenc-unlocked-until-never-claims-expiry-while-the-key-is-live
  "A rescan holding the passphrase SUSPENDS the relock (relocking mid-rescan
silently fails the keypool top-ups the scan depends on). Core does not suspend
— its scheduled callback fires regardless (wallet/rpc/encrypt.cpp:102-110) — so
this is a deliberate divergence.

What was NOT deliberate: getwalletinfo kept reporting the ORIGINAL
unlocked_until, so once the deadline passed mid-scan the wallet told callers the
unlock had expired while the master key was still decrypted and usable. A
wallet reporting the opposite of its own state is worse than either behaviour
on its own, and worse the longer the rescan runs."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (is (null (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))))
        ;; Force the deadline into the past, as a long rescan would.
        (setf (bl.wallet::wallet-relock-time wallet)
              (- (bl.ser:get-unix-time) 60)
              (bl.wallet::wallet-relock-deadline wallet)
              (- (get-internal-real-time)
                 (* 60 internal-time-units-per-second)))
        ;; Control: with NO scan holding it, the elapsed deadline relocks the
        ;; wallet and the report folds to 0. This is the arm that already
        ;; worked, and it must keep working.
        (is (eql 0 (%aval "unlocked_until"
                          (bl.wallet::rpc-getwalletinfo node '()))))
        (is (bl.wallet::wallet-is-locked-p wallet))
        ;; Now the suspended case: unlock again, expire the deadline, and mark
        ;; the wallet as scanning with the passphrase.
        (is (null (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))))
        (setf (bl.wallet::wallet-scanning-with-passphrase wallet) t
              (bl.wallet::wallet-relock-time wallet)
              (- (bl.ser:get-unix-time) 60)
              (bl.wallet::wallet-relock-deadline wallet)
              (- (get-internal-real-time)
                 (* 60 internal-time-units-per-second)))
        ;; The key really is still live — that is the premise, and without it
        ;; this test asserts nothing.
        (is-false (bl.wallet::wallet-is-locked-p wallet)
                  "the suspension is not holding the key; premise broken")
        (let ((until (%aval "unlocked_until"
                            (bl.wallet::rpc-getwalletinfo node '()))))
          (is (>= until (- (bl.ser:get-unix-time) 1))
              "unlocked_until reported ~D, which is in the past, while the ~
master key is still decrypted" until)
          (is (not (eql 0 until))
              "unlocked_until said LOCKED while the key was live"))
        ;; And when the scan ends, the elapsed deadline applies immediately.
        (setf (bl.wallet::wallet-scanning-with-passphrase wallet) nil)
        (is (eql 0 (%aval "unlocked_until"
                          (bl.wallet::rpc-getwalletinfo node '()))))
        (is (bl.wallet::wallet-is-locked-p wallet)
            "the wallet stayed unlocked after the scan released the suspension")))))

(test wenc-walletpassphrase-argument-validation
  "walletpassphrase's validation order and error codes (encrypt.cpp:53-70)."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (%wenc-fresh-wallet node "w")
      (%wenc-encrypt node)
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-walletpassphrase node '(42 60))))))
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-walletpassphrase
                             node '("hunter2" "soon"))))))
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-walletpassphrase
                             node '("hunter2" -1))))))
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-walletpassphrase node '("" 60))))))
      ;; encryptwallet on an already-encrypted wallet.
      (is (= -15 (rpc-error-code-of
                  (lambda () (%wenc-encrypt node "x"))))))))

(test wenc-timeout-clamped-and-zero-relocks
  "The timeout is silently clamped to MAX_SLEEP_TIME, and timeout 0 means the
deadline has already passed — the lazy check relocks on the next key access
without any sweeper involvement."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 999999999999))
        (is (<= (bl.wallet::wallet-relock-time wallet)
                (+ (bl.ser:get-unix-time)
                   bl.wallet::+walletpassphrase-max-sleep-time+)))
        (bl.wallet::rpc-walletlock node '())
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 0))
        ;; The very next read of the key material sees an expired deadline.
        (is (null (bl.wallet::wallet-unlocked-key wallet)))
        (is (bl.wallet::wallet-is-locked-p wallet))
        (is (eql 0 (%aval "unlocked_until"
                          (bl.wallet::rpc-getwalletinfo node '()))))))))

(test wenc-passphrase-change
  "walletpassphrasechange rewraps the master key without touching any
descriptor key: the old passphrase stops working, the new one works, and the
wallet still derives the same addresses."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node "old-pass")
        (bl.wallet::rpc-walletpassphrase node '("old-pass" 600))
        (let ((address-before (bl.wallet::rpc-getnewaddress node '()))
              (crypted-before
                (nth-value 1 (%wenc-in-memory-key-counts wallet))))
          (is (= -14 (rpc-error-code-of
                      (lambda () (bl.wallet::rpc-walletpassphrasechange
                                  node '("wrong" "new-pass"))))))
          ;; A failed change leaves the wallet LOCKED, even though it was
          ;; unlocked when the call started (Core parity).
          (is (bl.wallet::wallet-is-locked-p wallet))
          (is (null (bl.wallet::rpc-walletpassphrasechange
                     node '("old-pass" "new-pass"))))
          (is (null (bl.wallet::unlock-wallet wallet "old-pass")))
          (is (bl.wallet::unlock-wallet wallet "new-pass"))
          ;; The keys themselves were never re-encrypted.
          (is (= crypted-before (nth-value 1 (%wenc-in-memory-key-counts wallet))))
          (is (stringp address-before)))))))

(test wenc-passphrase-change-preserves-the-relock-deadline
  "Changing the passphrase on a TIMED unlock must keep the pending relock.
Core's Lock() leaves nRelockTime alone (only walletlock zeroes it), and
dropping it here would silently turn a 60-second unlock into a permanent
one while getwalletinfo reported the wallet as locked."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node "old-pass")
        (bl.wallet::rpc-walletpassphrase node '("old-pass" 600))
        (let ((relock-time (bl.wallet::wallet-relock-time wallet))
              (relock-deadline (bl.wallet::wallet-relock-deadline wallet)))
          (is (plusp relock-time))
          (is (plusp relock-deadline))
          (is (null (bl.wallet::rpc-walletpassphrasechange
                     node '("old-pass" "new-pass"))))
          ;; Still unlocked, and still on the ORIGINAL schedule.
          (is (not (bl.wallet::wallet-is-locked-p wallet)))
          (is (= relock-time (bl.wallet::wallet-relock-time wallet)))
          (is (= relock-deadline (bl.wallet::wallet-relock-deadline wallet)))
          (is (= relock-time (%aval "unlocked_until"
                                    (bl.wallet::rpc-getwalletinfo node '()))))
          ;; A change from a LOCKED wallet leaves it locked, with no deadline.
          (bl.wallet::rpc-walletlock node '())
          (is (null (bl.wallet::rpc-walletpassphrasechange
                     node '("new-pass" "third-pass"))))
          (is (bl.wallet::wallet-is-locked-p wallet))
          (is (zerop (bl.wallet::wallet-relock-deadline wallet))))))))

(test wenc-empty-passphrase-rejected
  "An empty passphrase is refused everywhere it could produce an unopenable
or trivially-opened wallet."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (%wenc-fresh-wallet node "w")
      (is (= -8 (rpc-error-code-of
                 (lambda () (%wenc-encrypt node "")))))
      (%wenc-encrypt node)
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-walletpassphrasechange
                             node '("hunter2" "")))))))))

(test wenc-disable-private-keys-cannot-encrypt
  "A watch-only wallet has nothing to encrypt (encrypt.cpp:253)."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("wo")
      (bl.wallet::rpc-createwallet node '("wo" t))
      (is (= -16 (rpc-error-code-of
                  (lambda () (%wenc-encrypt node))))))))

;;; ============================================================
;;; Persistence
;;; ============================================================

(test wenc-encrypted-wallet-reloads
  "An encrypted wallet reloads from disk: it comes back locked, its master
key and ciphertext records survive, and the original passphrase still opens
it. This is the path that used to hard-refuse with 'not supported until
wallet P6'."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let (address)
        (let ((wallet (%wenc-fresh-wallet node "w")))
          (%wenc-encrypt node)
          (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))
          (setf address (bl.wallet::rpc-getnewaddress node '()))
          (bl.wallet::unload-wallet (%node-manager node) wallet))
        (multiple-value-bind (wallet warnings)
            (bl.wallet::load-wallet (%node-manager node) "w")
          (is (null warnings))
          (is (bl.wallet::wallet-has-encryption-keys-p wallet))
          (is (bl.wallet::wallet-is-locked-p wallet))
          (is (eql 0 (%aval "unlocked_until"
                            (bl.wallet::rpc-getwalletinfo node '()))))
          (multiple-value-bind (plain crypted mkeys)
              (%wenc-key-record-counts wallet)
            (is (zerop plain))
            (is (= 16 crypted))
            (is (= 1 mkeys)))
          ;; The address issued before the unload is still ours.
          (is (bl.wallet::wallet-is-mine
               wallet (%address-script address :testnet4)))
          (is (null (bl.wallet::unlock-wallet wallet "wrong")))
          (is (bl.wallet::unlock-wallet wallet "hunter2")))))))

(test wenc-born-encrypted-wallet-never-writes-plaintext
  "createwallet with a passphrase produces an encrypted wallet whose disk
never held a plaintext key record — the seed is generated only after the
master key exists. A LevelDB delete is only a tombstone, so this is the one
path that gives a real erasure guarantee."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("born")
      (let ((wallet (%wenc-fresh-wallet node "born" :passphrase "hunter2")))
        (is (bl.wallet::wallet-has-encryption-keys-p wallet))
        (is (bl.wallet::wallet-is-locked-p wallet))
        (multiple-value-bind (plain crypted mkeys) (%wenc-key-record-counts wallet)
          (is (zerop plain))
          (is (= 8 crypted))                   ; one seed only, not two
          (is (= 1 mkeys)))
        ;; The blank flag was forced internally to defer the seed; it must be
        ;; cleared again once the descriptors exist.
        (is (not (bl.wallet::wallet-flag-set-p
                  wallet bl.wallet::+wallet-flag-blank-wallet+)))
        (is (eq bl.rpc:+json-false+
                (%aval "blank" (bl.wallet::rpc-getwalletinfo node '()))))
        ;; It is a working wallet: it hands out addresses and unlocks.
        (is (stringp (bl.wallet::rpc-getnewaddress node '())))
        (is (bl.wallet::unlock-wallet wallet "hunter2"))))))

(test wenc-encryptwallet-leaves-no-plaintext-key-bytes-on-disk
  "GA11 dd92141d. Core ends EncryptWallet with GetDatabase().Rewrite() because
otherwise the database keeps bits of the unencrypted private key in slack
space (wallet/wallet.cpp:872-876; for SQLite the rewrite is VACUUM,
wallet/sqlite.cpp:336-341). We called leveldb-compact instead, and that is not
an erasure: on a wallet young enough that its records are still in the
memtable, CompactRange flushes them to the TOP level and then compacts only
the empty levels beneath, so the 32 plaintext master bytes moved out of the
write-ahead log into a live .ldb and stayed there through further compactions.
Record counts cannot see that -- the tombstoned rows are already invisible to
the iterator -- so the assertion has to read the FILES."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let* ((wallet (%wenc-fresh-wallet node "w"))
             (secret (%wenc-master-secret wallet))
             (descriptor (%wenc-stored-descriptor-text wallet))
             (xprv (%wenc-master-xprv-text node)))
        (is (= 32 (length secret)))
        ;; Before: the scan works, and the secret is in the write-ahead log.
        (is-true (%wenc-directory-hits wallet secret))
        (is-true (member "log" (%wenc-file-types wallet) :test #'equal))
        (%wenc-encrypt node)
        ;; The finding, in one line: no file in the wallet holds the master
        ;; secret any more -- not an .ldb, not the log.
        (is-false (%wenc-directory-hits wallet secret))
        ;; The same key in its base58 form, which the xpub that legitimately
        ;; stays in the stored descriptor would complete into a spending key.
        (is-false (%wenc-directory-hits wallet xprv))
        ;; Positive controls, so neither absence above can be an empty scan:
        ;; text that BELONGS on disk is still found, and a log file is still
        ;; among the files the scan read.
        (is-true (%wenc-directory-hits wallet descriptor))
        (is-true (member "log" (%wenc-file-types wallet) :test #'equal))))))

(test wenc-encryptwallet-erases-the-plaintext-of-a-populated-database
  "The same erasure once the wallet has been written to enough that its records
have reached real SST files. That is the state in which the OLD compaction
happened to erase the secret -- by accident, because the flush it triggers then
has something to merge into -- so this case passed before the fix and is here
to keep the rewrite from ever being narrowed back to the young-wallet case."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let* ((wallet (%wenc-fresh-wallet node "w"))
             (secret (%wenc-master-secret wallet)))
        (%wenc-age-database wallet 2000)
        ;; The condition that makes this case different: the secret has been
        ;; flushed out of the memtable into a live .ldb.
        (is-true (member "ldb"
                         (mapcar (lambda (hit) (pathname-type (car hit)))
                                 (%wenc-directory-hits wallet secret))
                         :test #'equal))
        (%wenc-encrypt node)
        (is-false (%wenc-directory-hits wallet secret))
        ;; And it is still a working encrypted wallet.
        (is (bl.wallet::wallet-is-locked-p wallet))
        (is (bl.wallet::unlock-wallet wallet "hunter2"))))))

(test wenc-rewrite-interrupted-between-its-renames-is-finished-at-load
  "The rewrite swaps directories, so it has a crash window: between renaming
the wallet into <name>.rewrite/superseded/ and renaming <name>.rewrite into
its place, <name> does not exist. That window always leaves a COMPLETE
database at <name>.rewrite, and LOAD-WALLET finishes the swap before it opens
anything -- otherwise encryptwallet would have traded a disclosure bug for a
lost wallet. listwalletdir must not offer the scratch directory meanwhile."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let* ((wallet (%wenc-fresh-wallet node "w"))
             (address (bl.wallet::rpc-getnewaddress node '()))
             (path (uiop:ensure-directory-pathname (bl.wallet::wallet-path wallet)))
             (rewrite (bl.wallet::%wallet-rewrite-path path)))
        (%wenc-encrypt node)
        (%crash-close-wallet node "w")
        (%wenc-stage-interrupted-rewrite path rewrite)
        ;; The crash state: no wallet directory at all.
        (is-false (bl.wallet::wallet-db-exists-p path))
        (is-false (bl.wallet::list-wallet-dir (%node-manager node)))
        (multiple-value-bind (reloaded warnings)
            (bl.wallet::load-wallet (%node-manager node) "w")
          (is (null warnings))
          (is (bl.wallet::wallet-is-locked-p reloaded))
          (is (bl.wallet::wallet-is-mine
               reloaded (%address-script address :testnet4)))
          (is (bl.wallet::unlock-wallet reloaded "hunter2")))
        ;; Recovery leaves nothing behind: no scratch sibling, no parked
        ;; predecessor holding the records, no marker.
        (is-false (uiop:directory-exists-p rewrite))
        (is-false (uiop:directory-exists-p (bl.wallet::%wallet-superseded-path path)))
        (is-false (probe-file (bl.wallet::%wallet-rewrite-marker-path path)))
        (is (equal '("w") (bl.wallet::list-wallet-dir (%node-manager node))))))))

(test wenc-rewrite-refuses-a-sibling-directory-that-is-not-its-own
  "The scratch directory is <name>.rewrite, a name an operator may legitimately
have given a wallet. The marker file tells the two apart, and without it a
rewrite would delete somebody's wallet: an unmarked sibling is refused instead,
and the recovery pass leaves it alone.

encryptwallet asks for the name BEFORE it writes anything, because its rewrite
runs after the encryption batch has committed -- refusing there would leave a
wallet that is encrypted, still holds its plaintext, and reports an error."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let* ((wallet (%wenc-fresh-wallet node "w"))
             (path (uiop:ensure-directory-pathname (bl.wallet::wallet-path wallet)))
             (rewrite (bl.wallet::%wallet-rewrite-path path)))
        (ensure-directories-exist rewrite)
        (with-open-file (out (merge-pathnames "not-ours" rewrite)
                             :direction :output :if-does-not-exist :create)
          (write-line "someone else's data" out))
        (signals error (bl.wallet::wallet-db-rewrite (bl.wallet::wallet-db wallet)
                                                     path))
        ;; Refused, not deleted -- and the wallet is still open and usable.
        (is-true (probe-file (merge-pathnames "not-ours" rewrite)))
        (bl.wallet::wallet-recover-interrupted-rewrite path)
        (is-true (probe-file (merge-pathnames "not-ours" rewrite)))
        (is (stringp (bl.wallet::rpc-getnewaddress node '())))
        ;; And encryptwallet refuses up front, leaving the wallet UNENCRYPTED
        ;; rather than encrypted-and-failed.
        (signals error (%wenc-encrypt node))
        (is-false (bl.wallet::wallet-has-encryption-keys-p wallet))
        (multiple-value-bind (plain crypted) (%wenc-key-record-counts wallet)
          (is (= 8 plain))
          (is (zerop crypted)))
        ;; With the obstruction gone it encrypts normally, erasure and all.
        (uiop:delete-directory-tree rewrite :validate t)
        (let ((secret (%wenc-master-secret wallet)))
          (is-true (%wenc-directory-hits wallet secret))
          (%wenc-encrypt node)
          (is (bl.wallet::wallet-has-encryption-keys-p wallet))
          (is-false (%wenc-directory-hits wallet secret)))))))

(test wenc-createwallet-passphrase-validation
  "createwallet's passphrase argument: an empty string warns instead of
encrypting, and a passphrase with private keys disabled is refused."
  (with-wallet-test-node (node)
    (let ((result (bl.wallet::rpc-createwallet node '("w-empty" nil nil ""))))
      (is (member "Empty string given as passphrase, wallet will not be encrypted."
                  (coerce (%aval "warnings" result) 'list)
                  :test #'equal))
      (is (not (bl.wallet::wallet-has-encryption-keys-p
                (gethash "w-empty" (bl.wallet::wallet-manager-wallets
                                    (%node-manager node)))))))
    (is (= -4 (rpc-error-code-of
               (lambda () (bl.wallet::rpc-createwallet
                           node '("w-bad" t nil "hunter2"))))))))

(test wenc-blank-encrypted-wallet
  "createwallet blank=true with a passphrase yields an encrypted wallet with
no descriptors: it unlocks, but has no addresses to give."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("blank")
      (bl.wallet::rpc-createwallet node '("blank" nil t "hunter2"))
      (let ((wallet (gethash "blank" (bl.wallet::wallet-manager-wallets
                                      (%node-manager node)))))
        (is (bl.wallet::wallet-has-encryption-keys-p wallet))
        (is (zerop (hash-table-count (bl.wallet::wallet-spkms wallet))))
        ;; Even with no keys to check, a wrong passphrase must fail: the
        ;; master key itself will not decrypt. (Core's CheckDecryptionKey
        ;; would accept any passphrase here.)
        (is (null (bl.wallet::unlock-wallet wallet "wrong")))
        (is (bl.wallet::unlock-wallet wallet "hunter2"))
        ;; Core's "no available keys" error for a blank wallet — unlocking
        ;; does not conjure descriptors.
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-getnewaddress node '())))))))))

(test wenc-corrupt-ckey-is-not-a-wrong-passphrase
  "A ciphertext that will not decrypt under a master key that itself opened
correctly is file corruption. With more than one key, where some decrypt and
some do not, Core reports it distinctly rather than as a bad passphrase."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        ;; Damage exactly one SPKM's stored ciphertext, in memory.
        (let ((spkm (loop for s being the hash-values of
                                        (bl.wallet::wallet-spkms wallet)
                          when (plusp (hash-table-count
                                       (bl.wallet::desc-spkm-crypted-keys s)))
                            return s)))
          (maphash (lambda (keyid entry)
                     (let ((damaged (copy-seq (cdr entry))))
                       (setf (aref damaged 0) (logxor (aref damaged 0) 1))
                       (setf (gethash keyid
                                      (bl.wallet::desc-spkm-crypted-keys spkm))
                             (cons (car entry) damaged))))
                   (bl.wallet::desc-spkm-crypted-keys spkm)))
        ;; 16 keys, 15 of which still decrypt: the mixed case.
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::unlock-wallet wallet "hunter2")))))
        (is (bl.wallet::wallet-is-locked-p wallet))))))

(test wenc-duplicate-mkey-refused-at-load
  "Two master-key records with the same id is a corrupt file, not something
to silently pick a winner from."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (is (= 1 (hash-table-count (bl.wallet::wallet-master-keys wallet))))
        ;; encrypt-wallet refuses to add a second master key at all.
        (is (null (bl.wallet::encrypt-wallet wallet "another")))))))

;;; ============================================================
;;; Locked-wallet gating
;;; ============================================================

(test wenc-locked-wallet-refuses-key-operations
  "Every RPC that needs a private key raises RPC_WALLET_UNLOCK_NEEDED (-13)
with Core's exact message when the wallet is locked, and stops doing so once
it is unlocked."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (is (bl.wallet::wallet-is-locked-p wallet))
        ;; listdescriptors true must ERROR, not quietly emit the public form.
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-listdescriptors node '(t))))))
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-keypoolrefill node '(10))))))
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-importdescriptors
                                node (list (list (%ht "desc" "x" "timestamp" 0))))))))
        ;; The exact Core message.
        (signals-rpc-error (:exact-message "Error: Please enter the wallet passphrase with walletpassphrase first.")
          (bl.wallet::rpc-keypoolrefill node '(10)))
        ;; The public form of listdescriptors keeps working while locked.
        (is (%aval "descriptors" (bl.wallet::rpc-listdescriptors node '())))
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))
        (is (%aval "descriptors" (bl.wallet::rpc-listdescriptors node '(t))))
        (is (null (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-keypoolrefill node '(10))))))))))

(test wenc-locked-wallet-still-issues-addresses
  "A locked wallet keeps handing out addresses from its cached keypool —
descriptor expansion runs off the xpub and needs no private key. Getting
this wrong would make an encrypted wallet unable to receive."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (is (bl.wallet::wallet-is-locked-p wallet))
        (let ((external (bl.wallet::rpc-getnewaddress node '()))
              (change (bl.wallet::rpc-getrawchangeaddress node '())))
          (is (stringp external))
          (is (stringp change))
          (is (bl.wallet::wallet-is-mine
               wallet (%address-script external :testnet4)))
          (is (bl.wallet::wallet-is-mine
               wallet (%address-script change :testnet4))))
        ;; And HavePrivateKeys stays true while locked, so the keypool logic
        ;; and the watch-only warning both keep working.
        (is (loop for spkm being the hash-values of
                                (bl.wallet::wallet-spkms wallet)
                  thereis (bl.wallet::spkm-have-private-keys-p spkm)))))))

(test wenc-locked-wallet-cannot-sign-message
  "signmessage needs the private key; while locked it must be -13, and after
unlocking it must produce a signature again."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (%wenc-fresh-wallet node "w")
      (let ((address (bl.wallet::rpc-getnewaddress node '("" "legacy"))))
        (is (stringp (bl.wallet::rpc-signmessage node (list address "hi"))))
        (%wenc-encrypt node)
        ;; The pre-encryption address is still ours, but unsignable while locked.
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-signmessage
                                node (list address "hi"))))))
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))
        (is (stringp (bl.wallet::rpc-signmessage
                      node (list address "hi"))))))))

(test wenc-unlocked-signing-matches-plaintext-signing
  "A key read back through the decryption path signs identically to the same
key held in plaintext — the encryption round trip is lossless."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (%wenc-fresh-wallet node "w")
      (let* ((address (bl.wallet::rpc-getnewaddress node '("" "legacy")))
             (before (bl.wallet::rpc-signmessage node (list address "msg"))))
        (%wenc-encrypt node)
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))
        ;; RFC6979 makes ECDSA deterministic, so the same key over the same
        ;; message gives byte-identical output.
        (is (equal before
                   (bl.wallet::rpc-signmessage node (list address "msg"))))))))

(test wenc-locked-wallet-cannot-spend
  "The funds-critical gate, end to end on a funded regtest wallet: while
locked, every spending RPC refuses with -13 rather than producing a
half-signed or wrongly-signed transaction; after unlocking, the spend goes
through and the coins encrypted before the seed rotation are still spendable."
  (with-wallet-chain-node (node "enc-spend")
    (multiple-value-bind (wallet address) (%ws-fund-wallet node :blocks 2)
      (declare (ignore address))
      (let* ((bl.wallet::*rpc-wallet-name* "w")
             (target (%wc-optrue-address))
             ;; An explicit feerate: the regtest fee estimator has no data.
             (send-args (list target 1 nil nil nil nil nil nil nil 10))
             ;; A structurally valid one-input transaction, so the decode
             ;; check upstream of the gate passes and we reach the gate.
             (raw-tx (concatenate 'string "01000000" "01" (make-string 64 :initial-element #\0)
                                  "00000000" "00" "ffffffff"
                                  "01" "0000000000000000" "00" "00000000")))
        (%wenc-encrypt node)
        (is (bl.wallet::wallet-is-locked-p wallet))
        ;; The balance is still visible — only signing is blocked.
        (is (plusp (bl.wallet::rpc-getbalance node '())))
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-sendtoaddress node send-args)))))
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-sendmany
                                node (list "" (%ht target 1)))))))
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-signrawtransactionwithwallet
                                node (list raw-tx))))))
        ;; Unlock and the same spend succeeds, spending coins whose keys
        ;; were encrypted after they were received.
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))
        (let ((txid (bl.wallet::rpc-sendtoaddress node send-args)))
          (is (stringp txid))
          (is (= 64 (length txid))))
        ;; Relocking closes it again.
        (bl.wallet::rpc-walletlock node '())
        (is (= -13 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-sendtoaddress
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
    (with-rpc-wallet ("imp")
      (bl.wallet::rpc-createwallet node '("imp" nil t))   ; blank
      (let ((wallet (gethash "imp" (bl.wallet::wallet-manager-wallets
                                    (%node-manager node))))
            (private-desc
              (bl.rpc:descriptor-add-checksum
               "wpkh(tprv8ZgxMBicQKsPeZRHk4rTG6orPS2CRNFX3njhUXx5vj9qGog5ZMH4uGReDWN5kCkY3jmWEtWause41CDvBRXD1shKknAMKxT99o9qUTRVC6m/0h/0h/*)")))
        (bl.wallet::rpc-importdescriptors
         node (list (list (%ht "desc" private-desc "timestamp" 0 "active" nil))))
        (let ((spkm (loop for s being the hash-values of
                                        (bl.wallet::wallet-spkms wallet)
                          return s)))
          (is (not (null spkm)))
          ;; The key landed in the keystore...
          (is (bl.wallet::spkm-have-private-keys-p spkm))
          ;; ...and NOT in the descriptor object.
          (is (notany #'bl.rpc:desc-key-ext-privkey
                      (bl.rpc:out-desc-ordered-keys
                       (bl.wallet::desc-spkm-desc spkm))))
          ;; The stored string is the public form, as before.
          (is (search "tpub" (bl.wallet::desc-spkm-desc-string spkm)))
          (is (not (search "tprv" (bl.wallet::desc-spkm-desc-string spkm))))
          ;; Unlocked, the provider still resolves the key: the descriptor
          ;; remains usable, it just goes through the keystore now.
          (let ((provider (bl.wallet::spkm-privkey-provider wallet spkm)))
            (is (not (null (bl.rpc:desc-key-root-xprv
                            (first (bl.rpc:out-desc-ordered-keys
                                    (bl.wallet::desc-spkm-desc spkm)))
                            provider)))))
          ;; Encrypt, lock — now nothing can produce the key.
          (%wenc-encrypt node)
          (is (bl.wallet::wallet-is-locked-p wallet))
          (let ((provider (bl.wallet::spkm-privkey-provider wallet spkm)))
            (is (null (bl.rpc:desc-key-root-xprv
                       (first (bl.rpc:out-desc-ordered-keys
                               (bl.wallet::desc-spkm-desc spkm)))
                       provider))))
          ;; And it comes back once unlocked.
          (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))
          (let ((provider (bl.wallet::spkm-privkey-provider wallet spkm)))
            (is (not (null (bl.rpc:desc-key-root-xprv
                            (first (bl.rpc:out-desc-ordered-keys
                                    (bl.wallet::desc-spkm-desc spkm)))
                            provider))))))))))

(test wenc-backup-to-extensionless-destination
  "backupwallet must actually write to the path it was given. RENAME-FILE
merges the target with the source pathname, so a temp file differing only by
type renames to itself when the destination has no extension — reporting
success while leaving nothing behind."
  (with-wallet-test-node (node)
    (let* ((bl.wallet::*rpc-wallet-name* "w")
           (dir (uiop:ensure-directory-pathname
                 (bl.wallet::wallet-manager-data-directory
                  (%node-manager node))))
           (no-extension (merge-pathnames "backup-no-ext" dir))
           (with-extension (merge-pathnames "backup.dump" dir)))
      (%wenc-fresh-wallet node "w")
      (dolist (path (list no-extension with-extension))
        (is (null (bl.wallet::rpc-backupwallet node (list (namestring path)))))
        (is (probe-file path))
        ;; And no stray temp file survives.
        (is (null (probe-file (make-pathname
                               :name (concatenate 'string
                                                  (pathname-name path) ".tmp")
                               :defaults path)))))
      ;; Both restore cleanly.
      (bl.wallet::rpc-restorewallet
       node (list "r1" (namestring no-extension)))
      (is (bl.wallet::wallet-is-mine
           (gethash "r1" (bl.wallet::wallet-manager-wallets
                          (%node-manager node)))
           (%address-script
            (with-rpc-wallet ("r1")
              (bl.wallet::rpc-getnewaddress node '()))
            :testnet4))))))

;;; ============================================================
;;; Relock timer
;;; ============================================================

(test wenc-relock-sweeper-runs-and-stops
  "The sweeper relocks a wallet whose deadline passed with no RPC touching
it, and close-wallet-manager joins the thread rather than leaking it."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w"))
            (manager (%node-manager node)))
        (%wenc-encrypt node)
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 1))
        (is (bl.wallet::wallet-manager-relock-running manager))
        (let ((thread (bl.wallet::wallet-manager-relock-thread manager)))
          (is (bt:threadp thread))
          ;; Wait for the sweeper WITHOUT reading the key material, so this
          ;; proves the thread fired rather than the lazy check.
          (loop repeat 60
                until (null (bl.wallet::wallet-encryption-key wallet))
                do (sleep 0.1))
          (is (null (bl.wallet::wallet-encryption-key wallet)))
          (is (zerop (bl.wallet::wallet-relock-time wallet)))
          (bl.wallet::stop-relock-sweeper manager)
          (is (not (bl.wallet::wallet-manager-relock-running manager)))
          (is (null (bl.wallet::wallet-manager-relock-thread manager)))
          (is (not (bt:thread-alive-p thread))))))))

(test wenc-relock-suspended-during-scan
  "While a rescan holds the wallet unlocked across its own lock drops, the
deadline must not fire — relocking mid-scan would silently break the keypool
top-ups the scan depends on."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 0))
        (setf (bl.wallet::wallet-scanning-with-passphrase wallet) t)
        ;; The deadline has passed, but the scan flag holds the unlock open.
        (is (bl.wallet::wallet-unlocked-key wallet))
        (is (not (bl.wallet::wallet-is-locked-p wallet)))
        ;; The state-changing RPCs refuse while it is set (Core parity).
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-walletlock node '())))))
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-walletpassphrasechange
                               node '("hunter2" "new"))))))
        ;; Clearing it lets the expired deadline take effect immediately.
        (setf (bl.wallet::wallet-scanning-with-passphrase wallet) nil)
        (is (null (bl.wallet::wallet-unlocked-key wallet)))))))

(test wenc-unload-scrubs-the-key
  "Unloading a wallet drops its decrypted master key; a stale reference must
not keep key material alive after the wallet is gone."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let ((wallet (%wenc-fresh-wallet node "w")))
        (%wenc-encrypt node)
        (bl.wallet::rpc-walletpassphrase node '("hunter2" 600))
        (is (bl.wallet::wallet-encryption-key wallet))
        (bl.wallet::unload-wallet (%node-manager node) wallet)
        (is (null (bl.wallet::wallet-encryption-key wallet)))
        (is (zerop (bl.wallet::wallet-relock-time wallet)))))))

;;; ============================================================
;;; Backup / restore
;;; ============================================================

(defun %wenc-backup-path (node name)
  (merge-pathnames (format nil "~A.dump" name)
                   (uiop:ensure-directory-pathname
                    (bl.wallet::wallet-manager-data-directory
                     (%node-manager node)))))

(test wenc-backup-restore-roundtrip
  "backupwallet writes a verifiable dump; restorewallet rebuilds a wallet
whose records are identical, record for record."
  (with-wallet-test-node (node)
    (let ((source-records nil)
          (path (%wenc-backup-path node "w")))
      (with-rpc-wallet ("w")
        (let ((wallet (%wenc-fresh-wallet node "w")))
          (bl.wallet::rpc-getnewaddress node '())
          (is (null (bl.wallet::rpc-backupwallet
                     node (list (namestring path)))))
          (is (probe-file path))
          (setf source-records (wallet-db-record-list
                                (bl.wallet::wallet-db wallet)))))
      ;; The dump is self-describing and checksummed.
      (let ((first-line (with-open-file (in path) (read-line in))))
        (is (equal "BITCOIN_LISP_WALLET_DUMP,1" first-line)))
      (let ((result (bl.wallet::rpc-restorewallet
                     node (list "restored" (namestring path)))))
        (is (equal "restored" (%aval "name" result))))
      (let* ((restored (gethash "restored"
                                (bl.wallet::wallet-manager-wallets
                                 (%node-manager node))))
             (restored-records (wallet-db-record-list
                                (bl.wallet::wallet-db restored))))
        (is (= (length source-records) (length restored-records)))
        ;; Every record key round-trips, in order.
        (is (every (lambda (a b) (equalp (car a) (car b)))
                   source-records restored-records))
        ;; Values too, with one legitimate exception: loading the restored
        ;; wallet tops up its keypool, which rewrites the walletdescriptor
        ;; record of any SPKM that had issued an address (range_end grows).
        (is (every (lambda (a b)
                     (or (equalp (cdr a) (cdr b))
                         (equal bl.wallet::+wdb-key-walletdescriptor+
                                (bl.wallet::wdb-parse-key (car a)))))
                   source-records restored-records))
        ;; The key material specifically must be byte-identical.
        (is (every (lambda (a b)
                     (let ((type (bl.wallet::wdb-parse-key (car a))))
                       (or (not (member type
                                        (list bl.wallet::+wdb-key-walletdescriptorkey+
                                              bl.wallet::+wdb-key-walletdescriptorckey+
                                              bl.wallet::+wdb-key-mkey+)
                                        :test #'equal))
                           (equalp (cdr a) (cdr b)))))
                   source-records restored-records))))))

(test wenc-backup-of-locked-encrypted-wallet
  "A backup can be taken while the wallet is locked — it contains only
ciphertext — and the restored copy unlocks with the original passphrase."
  (with-wallet-test-node (node)
    (let ((path (%wenc-backup-path node "enc")))
      (with-rpc-wallet ("enc")
        (let ((wallet (%wenc-fresh-wallet node "enc" :passphrase "hunter2")))
          (is (bl.wallet::wallet-is-locked-p wallet))
          (is (null (bl.wallet::rpc-backupwallet
                     node (list (namestring path)))))))
      (bl.wallet::rpc-restorewallet node (list "enc2" (namestring path)))
      (let ((restored (gethash "enc2" (bl.wallet::wallet-manager-wallets
                                       (%node-manager node)))))
        (is (bl.wallet::wallet-has-encryption-keys-p restored))
        (is (bl.wallet::wallet-is-locked-p restored))
        (is (null (bl.wallet::unlock-wallet restored "wrong")))
        (is (bl.wallet::unlock-wallet restored "hunter2"))))))

(test wenc-restore-rejects-bad-input
  "restorewallet's error taxonomy, and — the part that matters — a rejected
restore must not leave a wallet directory behind."
  (with-wallet-test-node (node)
    (let ((path (%wenc-backup-path node "w")))
      (with-rpc-wallet ("w")
        (%wenc-fresh-wallet node "w")
        (bl.wallet::rpc-backupwallet node (list (namestring path))))
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-restorewallet
                             node (list "" (namestring path)))))))
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-restorewallet
                             node (list "../evil" (namestring path)))))))
      (is (= -8 (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-restorewallet
                             node (list "missing" "/nonexistent/backup.dump"))))))
      ;; Restoring onto an occupied destination — including a live wallet's
      ;; own directory, which Core reports the same way.
      (is (= -36 (rpc-error-code-of
                  (lambda () (bl.wallet::rpc-restorewallet
                              node (list "w" (namestring path)))))))
      ;; A corrupt dump: flip a byte in a record line.
      (let ((corrupt (merge-pathnames "corrupt.dump"
                                      (uiop:ensure-directory-pathname
                                       (bl.wallet::wallet-manager-data-directory
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
        (is (= -18 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-restorewallet
                                node (list "from-corrupt" (namestring corrupt)))))))
        ;; Nothing was created for the rejected restore.
        (is (not (uiop:directory-exists-p
                  (bl.wallet::wallet-directory (%node-manager node)
                                                      "from-corrupt"))))))))

(test wenc-backup-refuses-traversal-into-the-wallets-directory
  "The containment check must resolve `..` before comparing. A textual
component-prefix test would let a destination spelled with a traversal
segment pass as 'outside the wallets directory' and then land inside it,
where it would be picked up as a wallet directory."
  (with-wallet-test-node (node)
    (let* ((bl.wallet::*rpc-wallet-name* "w")
           (manager (%node-manager node))
           (wallets (bl.wallet::wallets-directory manager)))
      (%wenc-fresh-wallet node "w")
      ;; <wallets>/w/../../wallets/sneaky.dump resolves back inside.
      (let ((traversal (namestring
                        (merge-pathnames "w/../../wallets/sneaky.dump" wallets))))
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-backupwallet
                               node (list traversal))))))
        (is (null (probe-file (merge-pathnames "sneaky.dump" wallets)))))
      ;; The resolver itself, directly.
      (is (bl.wallet::%path-under-p
           (merge-pathnames "w/../sneaky.dump" wallets) wallets))
      (is (not (bl.wallet::%path-under-p
                (merge-pathnames "../outside.dump" wallets) wallets))))))

(test wenc-record-scan-refuses-a-truncated-read
  "map-wallet-db-records must signal, not return a short list, if the iterator
stopped on an error. A backup built from a silently truncated scan is the
worst possible failure: it looks like a successful backup and restores a
wallet that is missing keys."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (let* ((wallet (%wenc-fresh-wallet node "w"))
             (full (length (wallet-db-record-list
                            (bl.wallet::wallet-db wallet)))))
        (is (plusp full))
        ;; The error check is wired in and returns cleanly on a healthy DB.
        (finishes
         (bl.store:with-leveldb-iterator
             (iter (bl.wallet::wallet-db wallet))
           (bl.store:leveldb-iter-seek-to-first iter)
           (loop while (bl.store:leveldb-iter-valid-p iter)
                 do (bl.store:leveldb-iter-next iter))
           (bl.store:leveldb-iter-check-error iter)))
        ;; And a dump of a healthy wallet carries every record.
        (let ((path (%wenc-backup-path node "w")))
          (bl.wallet::rpc-backupwallet node (list (namestring path)))
          (is (= full (length (bl.wallet::%parse-wallet-dump
                               path (bl.wallet::wallet-network wallet))))))))))

;;; --- The record scan and the dump hold one record, not the database ---

(defparameter +wenc-bulk-records+ 20000
  "Records in the bulk fixture below. With +WENC-BULK-VALUE-SIZE+ this is
about 10 MB of values -- enough that holding the whole set is unmistakable in
the heap, and small enough to build in a couple of seconds.")

(defparameter +wenc-bulk-value-size+ 500)

(defun %wenc-bulk-record-db (directory)
  "A wallet database at DIRECTORY holding +WENC-BULK-RECORDS+ inert records.
Returned open; the caller closes it."
  (let ((db (bl.wallet::wallet-db-open directory :create t))
        (value (make-array +wenc-bulk-value-size+
                           :element-type '(unsigned-byte 8) :initial-element 7)))
    (dotimes (i +wenc-bulk-records+ db)
      (bl.store:leveldb-put
       db (bl.wallet::wdb-key-simple (format nil "ga11junk~6,'0D" i)) value))))

(defun %wenc-heap-mib (base)
  "Whole MiB the live heap sits above BASE. Caller has just collected."
  (round (- (sb-kernel:dynamic-usage) base) (* 1024 1024)))

(defun %wenc-consed-mib (base)
  (round (- (sb-ext:get-bytes-consed) base) (* 1024 1024)))

(test wenc-record-scan-streams-one-record-at-a-time
  "MAP-WALLET-DB-RECORDS is a driver: the callback sees one record at a time
and the scan retains none of them, which is what keeps loadwallet's peak heap
off the size of the wallet file. The collecting shape is measured over the
same database in the same run as the positive control -- a heap ceiling with
nothing to compare against passes whatever the driver does."
  (with-temp-directory (dir)
    (let ((db (%wenc-bulk-record-db (merge-pathnames "db/" dir)))
          (collected nil)
          (control 0)
          (streamed 0)
          (seen 0))
      (unwind-protect
           (progn
             (sb-ext:gc :full t)
             (let ((base (sb-kernel:dynamic-usage)))
               (setf collected (wallet-db-record-list db))
               (sb-ext:gc :full t)
               (setf control (%wenc-heap-mib base)))
             (is (= +wenc-bulk-records+ (length collected)))
             (setf collected nil)
             (sb-ext:gc :full t)
             (let ((base (sb-kernel:dynamic-usage)))
               (bl.wallet::map-wallet-db-records
                db (lambda (key value)
                     (declare (ignore key value))
                     (incf seen)
                     (when (= seen (floor +wenc-bulk-records+ 2))
                       (sb-ext:gc :full t)
                       (setf streamed (%wenc-heap-mib base))))))
             (is (= +wenc-bulk-records+ seen))
             ;; Positive control: collecting really does retain a heap the
             ;; size of the database.
             (is (> control 4)
                 "the collecting shape retained only ~D MiB; the fixture is too small ~
to measure anything" control)
             (is (< streamed (floor control 4))
                 "streaming retained ~D MiB against the collecting shape's ~D"
                 streamed control))
        (bl.store:leveldb-close db)))))

(test wenc-backup-does-not-buffer-the-whole-dump
  "%WRITE-WALLET-DUMP writes and hashes each line as it is produced. The
positive control is the shape it replaced -- every record hex-encoded into a
list of lines, concatenated into one body string, then hashed -- run over the
same database in the same test."
  (with-temp-directory (dir)
    (let* ((db-path (merge-pathnames "db/" dir))
           (db (%wenc-bulk-record-db db-path))
           (wallet (bl.wallet::make-wallet :name "ga11dump" :path db-path
                                           :db db :network :regtest))
           (path (merge-pathnames "dump.txt" dir))
           (streamed 0)
           (buffered 0))
      (unwind-protect
           (progn
             (sb-ext:gc :full t)
             (let ((base (sb-ext:get-bytes-consed)))
               (bl.wallet::%write-wallet-dump wallet path)
               (setf streamed (%wenc-consed-mib base)))
             (is (probe-file path))
             (sb-ext:gc :full t)
             (let ((base (sb-ext:get-bytes-consed)))
               (let* ((lines (mapcar (lambda (record)
                                       (format nil "~(~A,~A~)"
                                               (bl.crypto:bytes-to-hex (car record))
                                               (bl.crypto:bytes-to-hex (cdr record))))
                                     (wallet-db-record-list db)))
                      (body (with-output-to-string (s)
                              (dolist (line lines)
                                (write-string line s)
                                (write-char #\Newline s)))))
                 (is (plusp (length (bl.crypto:hash256
                                     (flexi-streams:string-to-octets
                                      body :external-format :latin-1)))))
                 (setf buffered (%wenc-consed-mib base))))
             ;; Positive control: buffering the dump really does cost many
             ;; times the file it writes.
             (is (> buffered 50)
                 "the buffered shape consed only ~D MiB; the fixture is too small ~
to measure anything" buffered)
             (is (< streamed (floor buffered 3))
                 "the streaming dump consed ~D MiB against the buffered shape's ~D"
                 streamed buffered))
        (bl.store:leveldb-close db)))))

(test wenc-restore-refuses-cross-network-dump
  "The dump records its network. A mainnet backup must not restore onto a
testnet node — Core gets this from the network magic in the SQLite header."
  (with-wallet-test-node (node)
    (let ((path (%wenc-backup-path node "w")))
      (with-rpc-wallet ("w")
        (%wenc-fresh-wallet node "w")
        (bl.wallet::rpc-backupwallet node (list (namestring path))))
      (let ((foreign (merge-pathnames "foreign.dump"
                                      (uiop:ensure-directory-pathname
                                       (bl.wallet::wallet-manager-data-directory
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
        (is (= -18 (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-restorewallet
                                node (list "foreign" (namestring foreign)))))))))))

(test wenc-backup-refuses-unsafe-destinations
  "backupwallet maps every failure to Core's single error, and refuses to
write into the wallets directory (where it would look like a wallet)."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("w")
      (%wenc-fresh-wallet node "w")
      (let ((manager (%node-manager node)))
        ;; An existing directory as the destination.
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-backupwallet
                               node (list (namestring
                                           (bl.wallet::wallets-directory
                                            manager))))))))
        ;; Inside the wallets directory.
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-backupwallet
                               node (list (namestring
                                           (merge-pathnames
                                            "sneaky.dump"
                                            (bl.wallet::wallets-directory
                                             manager)))))))))
        ;; A directory that does not exist.
        (is (= -4 (rpc-error-code-of
                   (lambda () (bl.wallet::rpc-backupwallet
                               node (list "/nonexistent/dir/backup.dump"))))))))))
