(in-package #:bitcoin-lisp.rpc)

;;; Wallet record storage (wallet P1)
;;;
;;; Core's wallet database is a key/value store (SQLite at d3056bc) whose
;;; records are serialized with the standard Bitcoin serializer; the record
;;; schema is the DBKeys string table (refs/bitcoin src/wallet/walletdb.cpp:32-63)
;;; and the Write* methods below it. We keep the record encodings byte-for-byte
;;; identical but store them in a per-wallet LevelDB at <datadir>/wallets/<name>/
;;; (docs/wallet-plan.md §4 "Storage" — record-level compat makes any future
;;; SQLite-container interop mechanical).
;;;
;;; Key encoding: each key is the DataStream serialization of the C++ key
;;; tuple — a compactsize-length-prefixed type string followed by the typed
;;; fields (uint256 = 32 raw bytes, CPubKey = compactsize + bytes,
;;; uint32/int32/int64 little-endian, std::string = compactsize + bytes).

;;; --- DBKeys (walletdb.cpp:32-63) ---
;;; Only the record types used by descriptor wallets; the legacy-only types
;;; (key/ckey/keymeta/pool/...) are intentionally absent since we never
;;; create or load legacy wallets.

(alexandria:define-constant +wdb-key-walletdescriptor+ "walletdescriptor" :test #'equal)
(alexandria:define-constant +wdb-key-walletdescriptorkey+ "walletdescriptorkey" :test #'equal)
(alexandria:define-constant +wdb-key-walletdescriptorckey+ "walletdescriptorckey" :test #'equal)
(alexandria:define-constant +wdb-key-walletdescriptorcache+ "walletdescriptorcache" :test #'equal)
(alexandria:define-constant +wdb-key-walletdescriptorlhcache+ "walletdescriptorlhcache" :test #'equal)
(alexandria:define-constant +wdb-key-activeexternalspk+ "activeexternalspk" :test #'equal)
(alexandria:define-constant +wdb-key-activeinternalspk+ "activeinternalspk" :test #'equal)
(alexandria:define-constant +wdb-key-bestblock+ "bestblock" :test #'equal)
(alexandria:define-constant +wdb-key-bestblock-nomerkle+ "bestblock_nomerkle" :test #'equal)
(alexandria:define-constant +wdb-key-name+ "name" :test #'equal)
(alexandria:define-constant +wdb-key-purpose+ "purpose" :test #'equal)
(alexandria:define-constant +wdb-key-destdata+ "destdata" :test #'equal)
(alexandria:define-constant +wdb-key-flags+ "flags" :test #'equal)
(alexandria:define-constant +wdb-key-mkey+ "mkey" :test #'equal)
(alexandria:define-constant +wdb-key-orderposnext+ "orderposnext" :test #'equal)
(alexandria:define-constant +wdb-key-lockedutxo+ "lockedutxo" :test #'equal)
(alexandria:define-constant +wdb-key-minversion+ "minversion" :test #'equal)
(alexandria:define-constant +wdb-key-version+ "version" :test #'equal)
;; Transaction records (CWalletTx) land in wallet P2; the key string is fixed
;; here so P2 storage slots into the same schema.
(alexandria:define-constant +wdb-key-tx+ "tx" :test #'equal)

;;; --- Serialization helpers over in-memory octet streams ---

(defmacro %wser ((stream) &body body)
  "Serialize BODY's writes into a fresh (simple-array (unsigned-byte 8))."
  `(coerce (flexi-streams:with-output-to-sequence (,stream) ,@body)
           '(simple-array (unsigned-byte 8) (*))))

(defun %wser-string (s str)
  "std::string: compactsize length + raw bytes."
  (bitcoin-lisp.serialization:write-var-bytes
   s (flexi-streams:string-to-octets str :external-format :ascii)))

(defun %wread-string (s)
  (flexi-streams:octets-to-string
   (bitcoin-lisp.serialization:read-var-bytes s)
   :external-format :ascii))

(defmacro %wparse ((stream bytes &key (start 0)) &body body)
  "Deserialize BODY's reads from BYTES starting at START."
  `(flexi-streams:with-input-from-sequence (,stream ,bytes :start ,start)
     ,@body))

;;; --- CPrivKey: DER-encoded EC private key (Core key.cpp ec_seckey_export_der) ---
;;;
;;; Core stores each descriptor private key as CPrivKey — the SEC1 C.4
;;; ECPrivateKey DER encoding with parameters and public key included. The
;;; encoding is a fixed template with the 32-byte secret and the serialized
;;; public key spliced in (key.cpp:96-155).

(alexandria:define-constant +privkey-der-begin-compressed+
    #(#x30 #x81 #xD3 #x02 #x01 #x01 #x04 #x20)
  :test #'equalp)

(alexandria:define-constant +privkey-der-middle-compressed+
    #(#xA0 #x81 #x85 #x30 #x81 #x82 #x02 #x01 #x01 #x30 #x2C #x06 #x07 #x2A #x86 #x48
      #xCE #x3D #x01 #x01 #x02 #x21 #x00 #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
      #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
      #xFF #xFF #xFE #xFF #xFF #xFC #x2F #x30 #x06 #x04 #x01 #x00 #x04 #x01 #x07 #x04
      #x21 #x02 #x79 #xBE #x66 #x7E #xF9 #xDC #xBB #xAC #x55 #xA0 #x62 #x95 #xCE #x87
      #x0B #x07 #x02 #x9B #xFC #xDB #x2D #xCE #x28 #xD9 #x59 #xF2 #x81 #x5B #x16 #xF8
      #x17 #x98 #x02 #x21 #x00 #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
      #xFF #xFF #xFF #xFF #xFE #xBA #xAE #xDC #xE6 #xAF #x48 #xA0 #x3B #xBF #xD2 #x5E
      #x8C #xD0 #x36 #x41 #x41 #x02 #x01 #x01 #xA1 #x24 #x03 #x22 #x00)
  :test #'equalp)

(alexandria:define-constant +privkey-der-begin-uncompressed+
    #(#x30 #x82 #x01 #x13 #x02 #x01 #x01 #x04 #x20)
  :test #'equalp)

(alexandria:define-constant +privkey-der-middle-uncompressed+
    #(#xA0 #x81 #xA5 #x30 #x81 #xA2 #x02 #x01 #x01 #x30 #x2C #x06 #x07 #x2A #x86 #x48
      #xCE #x3D #x01 #x01 #x02 #x21 #x00 #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
      #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
      #xFF #xFF #xFE #xFF #xFF #xFC #x2F #x30 #x06 #x04 #x01 #x00 #x04 #x01 #x07 #x04
      #x41 #x04 #x79 #xBE #x66 #x7E #xF9 #xDC #xBB #xAC #x55 #xA0 #x62 #x95 #xCE #x87
      #x0B #x07 #x02 #x9B #xFC #xDB #x2D #xCE #x28 #xD9 #x59 #xF2 #x81 #x5B #x16 #xF8
      #x17 #x98 #x48 #x3A #xDA #x77 #x26 #xA3 #xC4 #x65 #x5D #xA4 #xFB #xFC #x0E #x11
      #x08 #xA8 #xFD #x17 #xB4 #x48 #xA6 #x85 #x54 #x19 #x9C #x47 #xD0 #x8F #xFB #x10
      #xD4 #xB8 #x02 #x21 #x00 #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF #xFF
      #xFF #xFF #xFF #xFF #xFE #xBA #xAE #xDC #xE6 #xAF #x48 #xA0 #x3B #xBF #xD2 #x5E
      #x8C #xD0 #x36 #x41 #x41 #x02 #x01 #x01 #xA1 #x44 #x03 #x42 #x00)
  :test #'equalp)

(defun privkey-to-der (priv32 compressed-p)
  "Encode a 32-byte secret as Core's CPrivKey DER form (key.cpp
ec_seckey_export_der): fixed template + secret + serialized public key.
214 bytes compressed, 279 uncompressed."
  (let ((pubkey (bitcoin-lisp.crypto:derive-public-key
                 priv32 :compressed compressed-p)))
    (if compressed-p
        (concatenate '(vector (unsigned-byte 8))
                     +privkey-der-begin-compressed+ priv32
                     +privkey-der-middle-compressed+ pubkey)
        (concatenate '(vector (unsigned-byte 8))
                     +privkey-der-begin-uncompressed+ priv32
                     +privkey-der-middle-uncompressed+ pubkey))))

(defun der-to-privkey (der)
  "Extract the 32-byte secret from a CPrivKey DER encoding (Core key.cpp
ec_seckey_import_der), or NIL if malformed."
  (let ((len (length der)) (pos 0))
    (flet ((next () (when (< pos len) (prog1 (aref der pos) (incf pos)))))
      ;; sequence header
      (unless (eql (next) #x30) (return-from der-to-privkey nil))
      ;; sequence length constructor: high bit set, 1-2 length bytes, and the
      ;; declared sequence length must fit the buffer (key.cpp:58-63)
      (let ((lb (next)))
        (unless (and lb (logtest lb #x80)) (return-from der-to-privkey nil))
        (let ((lenb (logand lb #x7f)))
          (unless (<= 1 lenb 2) (return-from der-to-privkey nil))
          (when (> (+ pos lenb) len) (return-from der-to-privkey nil))
          (let ((seq-len (if (= lenb 1)
                             (aref der pos)
                             (logior (ash (aref der pos) 8) (aref der (1+ pos))))))
            (incf pos lenb)
            (when (> (+ pos seq-len) len) (return-from der-to-privkey nil)))))
      ;; sequence element 0: version number (=1)
      (unless (and (eql (next) #x02) (eql (next) #x01) (eql (next) #x01))
        (return-from der-to-privkey nil))
      ;; sequence element 1: octet string, up to 32 bytes
      (unless (eql (next) #x04) (return-from der-to-privkey nil))
      (let ((oslen (next)))
        (unless (and oslen (<= oslen 32) (<= (+ pos oslen) len))
          (return-from der-to-privkey nil))
        (let ((out (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 0)))
          (replace out der :start1 (- 32 oslen) :start2 pos :end2 (+ pos oslen))
          out)))))

;;; --- CExtPubKey 74-byte encoding (pubkey.h CExtPubKey::Encode) ---

(defconstant +bip32-extkey-size+ 74)

(defun %ext-pubkey-encode (k)
  "The BIP32_EXTKEY_SIZE encoding: depth(1) fingerprint(4) child(4,BE)
chaincode(32) pubkey(33)."
  (%wser (s)
    (bitcoin-lisp.serialization:write-uint8 s (bitcoin-lisp.crypto:ext-key-depth k))
    (loop for shift in '(-24 -16 -8 0)
          do (bitcoin-lisp.serialization:write-uint8
              s (logand (ash (bitcoin-lisp.crypto:ext-key-parent-fingerprint k) shift)
                        #xff)))
    (loop for shift in '(-24 -16 -8 0)
          do (bitcoin-lisp.serialization:write-uint8
              s (logand (ash (bitcoin-lisp.crypto:ext-key-child-number k) shift) #xff)))
    (bitcoin-lisp.serialization:write-bytes s (bitcoin-lisp.crypto:ext-key-chain-code k))
    (bitcoin-lisp.serialization:write-bytes
     s (bitcoin-lisp.crypto:ext-key-public-bytes k))))

(defun %ext-pubkey-decode (bytes network)
  "Inverse of %ext-pubkey-encode. NETWORK supplies the xpub version prefix
 (the 74-byte form does not carry one)."
  (unless (= (length bytes) +bip32-extkey-size+)
    (error "bad extended pubkey encoding: ~D bytes" (length bytes)))
  (flet ((be32 (offset)
           (loop with r = 0
                 for i from offset below (+ offset 4)
                 do (setf r (logior (ash r 8) (aref bytes i)))
                 finally (return r))))
    (bitcoin-lisp.crypto:make-ext-key
     :version (if (eq network :mainnet)
                  bitcoin-lisp.crypto:+xpub-mainnet+
                  bitcoin-lisp.crypto:+xpub-testnet+)
     :depth (aref bytes 0)
     :parent-fingerprint (be32 1)
     :child-number (be32 5)
     :chain-code (subseq bytes 9 41)
     :key (subseq bytes 41 74)
     :privatep nil)))

;;; --- Record keys ---

(defun wdb-key-simple (type)
  "Key for a singleton record: just the type string."
  (%wser (s) (%wser-string s type)))

(defun wdb-key-descriptor (desc-id)
  (%wser (s) (%wser-string s +wdb-key-walletdescriptor+)
             (bitcoin-lisp.serialization:write-bytes s desc-id)))

(defun wdb-key-descriptor-key (type desc-id pubkey)
  "Key for walletdescriptorkey / walletdescriptorckey: type + desc id +
CPubKey (compactsize-prefixed)."
  (%wser (s) (%wser-string s type)
             (bitcoin-lisp.serialization:write-bytes s desc-id)
             (bitcoin-lisp.serialization:write-var-bytes s pubkey)))

(defun wdb-key-descriptor-parent-cache (type desc-id key-exp-index)
  "Key for a parent (or last-hardened) xpub cache record."
  (%wser (s) (%wser-string s type)
             (bitcoin-lisp.serialization:write-bytes s desc-id)
             (bitcoin-lisp.serialization:write-uint32-le s key-exp-index)))

(defun wdb-key-descriptor-derived-cache (desc-id key-exp-index der-index)
  (%wser (s) (%wser-string s +wdb-key-walletdescriptorcache+)
             (bitcoin-lisp.serialization:write-bytes s desc-id)
             (bitcoin-lisp.serialization:write-uint32-le s key-exp-index)
             (bitcoin-lisp.serialization:write-uint32-le s der-index)))

(defun wdb-key-active-spk (internal-p output-type-code)
  (%wser (s) (%wser-string s (if internal-p
                                 +wdb-key-activeinternalspk+
                                 +wdb-key-activeexternalspk+))
             (bitcoin-lisp.serialization:write-uint8 s output-type-code)))

(defun wdb-key-address-string (type address)
  "Key for the address-book records name/purpose: type + address string."
  (%wser (s) (%wser-string s type)
             (%wser-string s address)))

(defun wdb-key-destdata (address key)
  "Key for a destination-data record: type + address string + data key
string (walletdb.cpp WriteAddressPreviouslySpent uses the data key \"used\";
receive requests use \"rr<id>\")."
  (%wser (s) (%wser-string s +wdb-key-destdata+)
             (%wser-string s address)
             (%wser-string s key)))

(defun wdb-parse-destdata-fields (fields)
  "(values address data-key) from a destdata record key's field bytes."
  (%wparse (s fields)
    (values (%wread-string s) (%wread-string s))))

(defun wdb-key-mkey (id)
  (%wser (s) (%wser-string s +wdb-key-mkey+)
             (bitcoin-lisp.serialization:write-uint32-le s id)))

(defun wdb-parse-mkey-fields (fields)
  "The uint32 nID from an mkey record key's field bytes."
  (%wparse (s fields) (bitcoin-lisp.serialization:read-uint32-le s)))

(defun wdb-key-lockedutxo (txid n)
  (%wser (s) (%wser-string s +wdb-key-lockedutxo+)
             (bitcoin-lisp.serialization:write-bytes s txid)
             (bitcoin-lisp.serialization:write-uint32-le s n)))

(defun wdb-key-tx (txid)
  "Key for a CWalletTx record (value serialization lands in wallet P2)."
  (%wser (s) (%wser-string s +wdb-key-tx+)
             (bitcoin-lisp.serialization:write-bytes s txid)))

(defun wdb-parse-key (key-bytes)
  "Split a stored record key into (values type-string field-bytes). Every
type string in the schema is shorter than 253 bytes, so its compactsize
prefix is always a single byte."
  (let ((type-len (aref key-bytes 0)))
    (values (flexi-streams:octets-to-string
             (subseq key-bytes 1 (1+ type-len)) :external-format :ascii)
            (subseq key-bytes (1+ type-len)))))

;;; --- Record values ---

(defun wdb-descriptor-value (desc-string creation-time next-index range-start range-end)
  "WalletDescriptor value (walletutil.h SERIALIZE_METHODS: descriptor string
with checksum, creation time, next_index, range_start, range_end — note the
field order)."
  (%wser (s)
    (%wser-string s desc-string)
    (bitcoin-lisp.serialization:write-uint64-le s creation-time)
    (bitcoin-lisp.serialization:write-int32-le s next-index)
    (bitcoin-lisp.serialization:write-int32-le s range-start)
    (bitcoin-lisp.serialization:write-int32-le s range-end)))

(defun wdb-parse-descriptor-value (bytes)
  "(values desc-string creation-time next-index range-start range-end)."
  (%wparse (s bytes)
    (values (%wread-string s)
            (bitcoin-lisp.serialization:read-uint64-le s)
            (bitcoin-lisp.serialization:read-int32-le s)
            (bitcoin-lisp.serialization:read-int32-le s)
            (bitcoin-lisp.serialization:read-int32-le s))))

(defun wdb-descriptor-key-value (pubkey privkey-der)
  "walletdescriptorkey value: (CPrivKey, Hash(pubkey||privkey)) — the double-
SHA256 checksum accelerates load-time verification (walletdb.cpp:220-228)."
  (let ((checksum (bitcoin-lisp.crypto:hash256
                   (concatenate '(vector (unsigned-byte 8)) pubkey privkey-der))))
    (%wser (s)
      (bitcoin-lisp.serialization:write-var-bytes s privkey-der)
      (bitcoin-lisp.serialization:write-bytes s checksum))))

(defun wdb-parse-descriptor-key-value (bytes pubkey)
  "(values priv32 nil) — verifies the stored Hash(pubkey||privkey) checksum,
returning NIL on mismatch or malformed DER."
  (%wparse (s bytes)
    (let* ((der (bitcoin-lisp.serialization:read-var-bytes s))
           (checksum (bitcoin-lisp.serialization:read-bytes s 32)))
      (when (equalp checksum
                    (bitcoin-lisp.crypto:hash256
                     (concatenate '(vector (unsigned-byte 8)) pubkey der)))
        (der-to-privkey der)))))

(defun wdb-uint64-value (n)
  (%wser (s) (bitcoin-lisp.serialization:write-uint64-le s n)))

(defun wdb-parse-uint64-value (bytes)
  (%wparse (s bytes) (bitcoin-lisp.serialization:read-uint64-le s)))

(defun wdb-int64-value (n)
  (%wser (s) (bitcoin-lisp.serialization:write-int64-le s n)))

(defun wdb-parse-int64-value (bytes)
  (%wparse (s bytes) (bitcoin-lisp.serialization:read-int64-le s)))

(defun wdb-int32-value (n)
  (%wser (s) (bitcoin-lisp.serialization:write-int32-le s n)))

(defun wdb-parse-int32-value (bytes)
  (%wparse (s bytes) (bitcoin-lisp.serialization:read-int32-le s)))

(defun wdb-string-value (str)
  (%wser (s) (%wser-string s str)))

(defun wdb-parse-string-value (bytes)
  (%wparse (s bytes) (%wread-string s)))

(defun wdb-vector-value (bytes)
  (%wser (s) (bitcoin-lisp.serialization:write-var-bytes s bytes)))

(defun wdb-parse-vector-value (bytes)
  (%wparse (s bytes) (bitcoin-lisp.serialization:read-var-bytes s)))

(defun wdb-xpub-value (ext-key)
  "Cache record value: the 74-byte extended pubkey as a vector."
  (wdb-vector-value (%ext-pubkey-encode ext-key)))

(defun wdb-parse-xpub-value (bytes network)
  (%ext-pubkey-decode (wdb-parse-vector-value bytes) network))

(defconstant +block-locator-dummy-version+ 70016
  "CBlockLocator's hard-coded serialized version field (primitives/block.h:125;
written but never read).")

(defun wdb-block-locator-value (hashes)
  "CBlockLocator: dummy int32 version + vector<uint256>."
  (%wser (s)
    (bitcoin-lisp.serialization:write-int32-le s +block-locator-dummy-version+)
    (bitcoin-lisp.serialization:write-compact-size s (length hashes))
    (dolist (h hashes)
      (bitcoin-lisp.serialization:write-bytes s h))))

(defun wdb-parse-block-locator-value (bytes)
  "The locator's hash list (dummy version discarded)."
  (%wparse (s bytes)
    (bitcoin-lisp.serialization:read-int32-le s)
    (loop repeat (bitcoin-lisp.serialization:read-compact-size s)
          collect (bitcoin-lisp.serialization:read-bytes s 32))))

(defstruct wallet-master-key
  "Core CMasterKey (crypter.h:33-60): the wallet's random 32-byte keying
material, itself encrypted under a passphrase-derived key. Every descriptor
private key is encrypted with the plaintext master key, so changing the
passphrase rewraps only this record and never touches the keys.

Lives here beside the mkey record codec so the loader in wallet.lisp — which
compiles first — can SETF its slots."
  (crypted-key nil)                              ; 48-byte AES-256-CBC ciphertext
  (salt nil)                                     ; exactly 8 bytes
  (derivation-method 0 :type (unsigned-byte 32)) ; 0 = SHA-512; nothing else exists
  (derive-iterations 25000 :type (unsigned-byte 32))
  (other-params (make-array 0 :element-type '(unsigned-byte 8))))

(defun wdb-mkey-value (crypted-key salt derivation-method derive-iterations
                       other-params)
  "CMasterKey (crypter.h:33-60): vchCryptedKey, vchSalt, nDerivationMethod,
nDeriveIterations, vchOtherDerivationParameters."
  (%wser (s)
    (bitcoin-lisp.serialization:write-var-bytes s crypted-key)
    (bitcoin-lisp.serialization:write-var-bytes s salt)
    (bitcoin-lisp.serialization:write-uint32-le s derivation-method)
    (bitcoin-lisp.serialization:write-uint32-le s derive-iterations)
    (bitcoin-lisp.serialization:write-var-bytes s other-params)))

(defun wdb-parse-mkey-value (bytes)
  "(values crypted-key salt derivation-method derive-iterations other-params)."
  (%wparse (s bytes)
    (values (bitcoin-lisp.serialization:read-var-bytes s)
            (bitcoin-lisp.serialization:read-var-bytes s)
            (bitcoin-lisp.serialization:read-uint32-le s)
            (bitcoin-lisp.serialization:read-uint32-le s)
            (bitcoin-lisp.serialization:read-var-bytes s))))

(alexandria:define-constant +wdb-lockedutxo-value+
    (coerce (vector (char-code #\1)) '(simple-array (unsigned-byte 8) (*)))
  :test #'equalp
  :documentation "WriteLockedUTXO's value: the single byte '1' (walletdb.cpp:288).")

;;; --- Wallet LevelDB lifecycle ---

(defun wallet-db-open (path &key create)
  "Open (or with CREATE, create) the wallet LevelDB at directory PATH."
  (ensure-directories-exist (uiop:ensure-directory-pathname path))
  (bitcoin-lisp.storage:leveldb-open
   (namestring (uiop:ensure-directory-pathname path))
   (bitcoin-lisp.storage:leveldb-make-options :create-if-missing (and create t))))

(defun wallet-db-exists-p (path)
  "T when PATH holds a LevelDB (its CURRENT file exists)."
  (and (probe-file (merge-pathnames "CURRENT"
                                    (uiop:ensure-directory-pathname path)))
       t))

(defun wallet-db-records (db)
  "All (key . value) byte-vector pairs in DB, in key order.

Signals rather than returning a short list if the scan stopped on an I/O or
corruption error: a bad block only makes the iterator go invalid, which is
indistinguishable from reaching the end. Every caller here — wallet load and
backup — is wrong in a dangerous way if it silently sees a subset."
  (let ((out '()))
    (bitcoin-lisp.storage:with-leveldb-iterator (iter db)
      (bitcoin-lisp.storage:leveldb-iter-seek-to-first iter)
      (loop while (bitcoin-lisp.storage:leveldb-iter-valid-p iter)
            do (push (cons (bitcoin-lisp.storage:leveldb-iter-key iter)
                           (bitcoin-lisp.storage:leveldb-iter-value iter))
                     out)
               (bitcoin-lisp.storage:leveldb-iter-next iter))
      (bitcoin-lisp.storage:leveldb-iter-check-error iter))
    (nreverse out)))
