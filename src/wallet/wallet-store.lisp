(in-package #:bitcoin-lisp.wallet)

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

;;; --- Serialization helpers ---
;;;
;;; Two substrates, one byte layout. The %WSER / %WPARSE pair is the
;;; flexi-streams one the CWalletTx codecs in wallet-tx.lisp / wallet-spend.lisp
;;; still write against (they feed a stream to the transaction codecs); the
;;; %WBUF / %WBR pair is byte-buf / byte-reader (bl.bytes), which the record
;;; schema below and this file's own codecs use. Moving the three callers of
;;; the stream pair onto bl.bytes retires it.

(defmacro %wser ((stream) &body body)
  "Serialize BODY's stream writes into a fresh (simple-array (unsigned-byte 8))."
  `(coerce (flexi-streams:with-output-to-sequence (,stream) ,@body)
           '(simple-array (unsigned-byte 8) (*))))

(defun %wser-string (s str)
  "std::string: compactsize length + raw bytes."
  (bl.ser:write-var-bytes
   s (flexi-streams:string-to-octets str :external-format :ascii)))

(defun %wread-string (s)
  (flexi-streams:octets-to-string
   (bl.ser:read-var-bytes s)
   :external-format :ascii))

(defmacro %wparse ((stream bytes &key (start 0)) &body body)
  "Deserialize BODY's stream reads from BYTES starting at START."
  `(flexi-streams:with-input-from-sequence (,stream ,bytes :start ,start)
     ,@body))

(defmacro %wbuf ((buf) &body body)
  "Serialize BODY's byte-buf writes into a fresh (simple-array (unsigned-byte 8))."
  `(bl.bytes:with-byte-buf (,buf) ,@body))

(defun %wser-string-into (bb str)
  "std::string into the byte-buf BB: compactsize length + ASCII bytes."
  (bl.bytes:bb-write-var-bytes
   bb (flexi-streams:string-to-octets str :external-format :ascii)))

(defmacro %wbr ((reader bytes) &body body)
  "Deserialize BODY's byte-reader reads from BYTES."
  `(bl.bytes:with-byte-reader (,reader ,bytes) ,@body))

;;; --- The record schema: one form per key or value type ---
;;;
;;; Core's walletdb.cpp writes each record as a (key, value) pair of
;;; serialized fields; walletdb.h's DBKeys lists the key types. Before this
;;; schema every key and value here was a hand-written pair of functions --
;;; 34 writers and 13 parsers, each a 2-6 line %WSER / %WPARSE body over the
;;; same five field kinds. DEFINE-WDB-KEY and DEFINE-WDB-VALUE generate the
;;; writer and the parser from one field list, so the two cannot disagree,
;;; and the field kinds are DEFINE-MESSAGE's (bl.ser:field-codec-forms):
;;; :var-string (std::string), :var-bytes, (:bytes N), :u8 :u32 :i32 :u64 :i64.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun %wdb-field-parts (fields)
    "FIELDS, a list of (VAR KIND) -> (values lambda-list write-forms read-forms)
over the byte-buf BB and the byte-reader BR."
    (let ((args '()) (writes '()) (reads '()))
      (dolist (field fields)
        (destructuring-bind (var kind) field
          (multiple-value-bind (slot-type read write)
              (bl.ser:field-codec-forms kind 'br 'bb var)
            (declare (ignore slot-type))
            (push var args)
            (push write writes)
            (push read reads))))
      (values (nreverse args) (nreverse writes) (nreverse reads)))))

(defmacro define-wdb-key (name (type &rest fields) &optional doc)
  "Define WDB-KEY-<NAME>, the writer of a record key whose type string is
TYPE -- a constant naming one of the DBKeys strings above, or (:parameter
VAR) when the caller supplies it -- followed by FIELDS, and, when FIELDS is
not empty, WDB-PARSE-<NAME>-FIELDS, which reads the field values back from
the bytes after the type string (see WDB-PARSE-KEY)."
  (let* ((writer (intern (format nil "WDB-KEY-~A" name)))
         (parser (intern (format nil "WDB-PARSE-~A-FIELDS" name)))
         (type-args (if (and (consp type) (eq (first type) :parameter))
                        (list (second type))
                        '()))
         (type-form (if type-args (second type) type))
         (type-write (nth-value 2 (bl.ser:field-codec-forms :var-string 'br 'bb type-form))))
    (multiple-value-bind (args writes reads) (%wdb-field-parts fields)
      `(progn
         (defun ,writer (,@type-args ,@args)
           ,@(when doc (list doc))
           (%wbuf (bb) ,type-write ,@writes))
         ,@(when fields
             `((defun ,parser (fields)
                 ,(format nil "The ~A key's field values, in schema order, from FIELDS (the bytes after the type string)." name)
                 (%wbr (br fields) (values ,@reads)))))
         ',writer))))

(defmacro define-wdb-value (name fields &optional doc)
  "Define WDB-<NAME>-VALUE, the writer of a record value made of FIELDS, and
WDB-PARSE-<NAME>-VALUE, which returns the fields as multiple values."
  (let ((writer (intern (format nil "WDB-~A-VALUE" name)))
        (parser (intern (format nil "WDB-PARSE-~A-VALUE" name))))
    (multiple-value-bind (args writes reads) (%wdb-field-parts fields)
      `(progn
         (defun ,writer ,args
           ,@(when doc (list doc))
           (%wbuf (bb) ,@writes))
         (defun ,parser (bytes)
           ,(format nil "The ~A value's fields, in schema order, as multiple values." name)
           (%wbr (br bytes) (values ,@reads)))
         ',writer))))

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
  (let ((pubkey (bl.crypto:derive-public-key
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
  (%wbuf (s)
    (bl.bytes:bb-write-u8 s (bl.crypto:ext-key-depth k))
    (loop for shift in '(-24 -16 -8 0)
          do (bl.bytes:bb-write-u8
              s (logand (ash (bl.crypto:ext-key-parent-fingerprint k) shift)
                        #xff)))
    (loop for shift in '(-24 -16 -8 0)
          do (bl.bytes:bb-write-u8
              s (logand (ash (bl.crypto:ext-key-child-number k) shift) #xff)))
    (bl.bytes:bb-write-bytes s (bl.crypto:ext-key-chain-code k))
    (bl.bytes:bb-write-bytes
     s (bl.crypto:ext-key-public-bytes k))))

(defun %ext-pubkey-decode (bytes network)
  "Inverse of %ext-pubkey-encode. NETWORK supplies the xpub version prefix
 (the 74-byte form does not carry one)."
  (unless (= (length bytes) +bip32-extkey-size+)
    (wallet-error "bad extended pubkey encoding: ~D bytes" (length bytes)))
  (flet ((be32 (offset)
           (loop with r = 0
                 for i from offset below (+ offset 4)
                 do (setf r (logior (ash r 8) (aref bytes i)))
                 finally (return r))))
    (bl.crypto:make-ext-key
     :version (bl.chain:chain-params-ext-public-prefix
               (bl.chain:find-chain-params network))
     :depth (aref bytes 0)
     :parent-fingerprint (be32 1)
     :child-number (be32 5)
     :chain-code (subseq bytes 9 41)
     :key (subseq bytes 41 74)
     :privatep nil)))

;;; --- Record keys ---

(define-wdb-key simple ((:parameter type))
  "Key for a singleton record: just the type string.")

(define-wdb-key descriptor (+wdb-key-walletdescriptor+ (desc-id (:bytes 32))))

(define-wdb-key descriptor-key ((:parameter type) (desc-id (:bytes 32)) (pubkey :var-bytes))
  "Key for walletdescriptorkey / walletdescriptorckey: type + desc id +
CPubKey (compactsize-prefixed).")

(define-wdb-key descriptor-parent-cache ((:parameter type) (desc-id (:bytes 32)) (key-exp-index :u32))
  "Key for a parent (or last-hardened) xpub cache record.")

(define-wdb-key descriptor-derived-cache
    (+wdb-key-walletdescriptorcache+ (desc-id (:bytes 32)) (key-exp-index :u32) (der-index :u32)))

(define-wdb-key address-string ((:parameter type) (address :var-string))
  "Key for the address-book records name/purpose: type + address string.")

(define-wdb-key destdata (+wdb-key-destdata+ (address :var-string) (key :var-string))
  "Key for a destination-data record: type + address string + data key
string (walletdb.cpp WriteAddressPreviouslySpent uses the data key \"used\";
receive requests use \"rr<id>\").")

(define-wdb-key mkey (+wdb-key-mkey+ (id :u32)))

(define-wdb-key lockedutxo (+wdb-key-lockedutxo+ (txid (:bytes 32)) (n :u32)))

(define-wdb-key tx (+wdb-key-tx+ (txid (:bytes 32)))
  "Key for a CWalletTx record (value serialization lands in wallet P2).")

(defun wdb-key-active-spk (internal-p output-type-code)
  "Key for the active-descriptor records: the internal or external type
string, then the output type's code."
  (%wbuf (bb)
    (%wser-string-into bb (if internal-p
                              +wdb-key-activeinternalspk+
                              +wdb-key-activeexternalspk+))
    (bl.bytes:bb-write-u8 bb output-type-code)))

(defun wdb-parse-key (key-bytes)
  "Split a stored record key into (values type-string field-bytes). Every
type string in the schema is shorter than 253 bytes, so its compactsize
prefix is always a single byte."
  (let ((type-len (aref key-bytes 0)))
    (values (flexi-streams:octets-to-string
             (subseq key-bytes 1 (1+ type-len)) :external-format :ascii)
            (subseq key-bytes (1+ type-len)))))

;;; --- Record values ---

(define-wdb-value descriptor
    ((desc-string :var-string) (creation-time :u64) (next-index :i32) (range-start :i32) (range-end :i32))
  "WalletDescriptor value (walletutil.h SERIALIZE_METHODS: descriptor string
with checksum, creation time, next_index, range_start, range_end -- note the
field order).")

(define-wdb-value uint64 ((n :u64)))
(define-wdb-value int64 ((n :i64)))
(define-wdb-value int32 ((n :i32)))
(define-wdb-value string ((str :var-string)))
(define-wdb-value vector ((bytes :var-bytes)))

(define-wdb-value mkey
    ((crypted-key :var-bytes) (salt :var-bytes) (derivation-method :u32)
     (derive-iterations :u32) (other-params :var-bytes))
  "CMasterKey (crypter.h:33-60): vchCryptedKey, vchSalt, nDerivationMethod,
nDeriveIterations, vchOtherDerivationParameters.")

(defun wdb-descriptor-key-value (pubkey privkey-der)
  "walletdescriptorkey value: (CPrivKey, Hash(pubkey||privkey)) — the double-
SHA256 checksum accelerates load-time verification (walletdb.cpp:220-228)."
  (let ((checksum (bl.crypto:hash256
                   (concatenate '(vector (unsigned-byte 8)) pubkey privkey-der))))
    (%wbuf (s)
      (bl.bytes:bb-write-var-bytes s privkey-der)
      (bl.bytes:bb-write-bytes s checksum))))

(defun wdb-parse-descriptor-key-value (bytes pubkey)
  "(values priv32 nil) — verifies the stored Hash(pubkey||privkey) checksum,
returning NIL on mismatch or malformed DER."
  (%wbr (s bytes)
    (let* ((der (bl.bytes:br-read-var-bytes s))
           (checksum (bl.bytes:br-read-bytes s 32)))
      (when (equalp checksum
                    (bl.crypto:hash256
                     (concatenate '(vector (unsigned-byte 8)) pubkey der)))
        (der-to-privkey der)))))

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
  (%wbuf (s)
    (bl.bytes:bb-write-i32-le s +block-locator-dummy-version+)
    (bl.bytes:bb-write-varint s (length hashes))
    (dolist (h hashes)
      (bl.bytes:bb-write-bytes s h))))

(defun wdb-parse-block-locator-value (bytes)
  "The locator's hash list (dummy version discarded)."
  (%wbr (s bytes)
    (bl.bytes:br-read-i32-le s)
    (loop repeat (bl.bytes:br-read-compact-size s)
          collect (bl.bytes:br-read-bytes s 32))))

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

(alexandria:define-constant +wdb-lockedutxo-value+
    (coerce (vector (char-code #\1)) '(simple-array (unsigned-byte 8) (*)))
  :test #'equalp
  :documentation "WriteLockedUTXO's value: the single byte '1' (walletdb.cpp:288).")

;;; --- Wallet LevelDB lifecycle ---

(defun wallet-db-open (path &key create)
  "Open (or with CREATE, create) the wallet LevelDB at directory PATH."
  (ensure-directories-exist (uiop:ensure-directory-pathname path))
  (bl.store:leveldb-open
   (namestring (uiop:ensure-directory-pathname path))
   (bl.store:leveldb-make-options :create-if-missing (and create t))))

(defun wallet-db-exists-p (path)
  "T when PATH holds a LevelDB (its CURRENT file exists)."
  (and (probe-file (merge-pathnames "CURRENT"
                                    (uiop:ensure-directory-pathname path)))
       t))

(defun map-wallet-db-records (db function)
  "Call FUNCTION with the key and the value of every record in DB, in key
order. Both are fresh byte vectors, so the callback may keep either one.

A DRIVER, not a collector: Core's loader never holds more than one record
either (LoadRecords runs a cursor through a per-type load function,
walletdb.cpp:471-506), and a wallet's whole record set is the wallet file. A
caller that needs two orderings iterates twice — LevelDB re-reads are cheap
next to holding the file in the heap.

Signals rather than stopping quietly if the scan ended on an I/O or
corruption error: a bad block only makes the iterator go invalid, which is
indistinguishable from reaching the end. Every caller here — wallet load,
backup and rewrite — is wrong in a dangerous way if it silently sees a
subset."
  (declare (type function function))
  (bl.store:with-leveldb-iterator (iter db)
    (bl.store:leveldb-iter-seek-to-first iter)
    (loop while (bl.store:leveldb-iter-valid-p iter)
          do (funcall function
                      (bl.store:leveldb-iter-key iter)
                      (bl.store:leveldb-iter-value iter))
             (bl.store:leveldb-iter-next iter))
    (bl.store:leveldb-iter-check-error iter)))

(defmacro with-wallet-db-records ((key value db) &body body)
  "Run BODY once per record of DB, in key order, with KEY and VALUE bound to
that record's byte vectors. MAP-WALLET-DB-RECORDS with the callback written
inline, so the truncated-scan guarantee is the same one."
  `(map-wallet-db-records
    ,db
    (lambda (,key ,value)
      (declare (ignorable ,key ,value))
      ,@body)))

;;; --- Rewriting the database (Core WalletDatabase::Rewrite) ---
;;;
;;; Core's EncryptWallet ends with GetDatabase().Rewrite(), commented "Need to
;;; completely rewrite the wallet file; if we don't, the database might keep
;;; bits of the unencrypted private key in slack space in the database file"
;;; (refs/bitcoin/src/wallet/wallet.cpp:872-876). For SQLite that is VACUUM
;;; (refs/bitcoin/src/wallet/sqlite.cpp:336-341): the file is rebuilt, so the
;;; deleted rows sit in no live page.
;;;
;;; A LevelDB delete is a tombstone, and a compaction is NOT the analogue --
;;; see LEVELDB-COMPACT's docstring for why CompactRange leaves a young
;;; database's plaintext in a live .ldb. The analogue of a rebuild is a
;;; rebuild: write the records the iterator still returns into a brand-new
;;; directory and swap that in.
;;;
;;; The swap uses ONE reserved sibling name, <name>.rewrite, and parks the
;;; wallet it replaces INSIDE it (<name>.rewrite/superseded/) rather than at a
;;; second sibling -- one name to reason about, and one name that could
;;; collide with a wallet an operator really did create. The marker file is
;;; what settles that collision: a directory without it is never touched.

(alexandria:define-constant +wallet-rewrite-suffix+ ".rewrite"
  :test #'equal
  :documentation "Appended to a wallet directory's name for the rebuilt copy.")

(alexandria:define-constant +wallet-superseded-subdirectory+ "superseded"
  :test #'equal
  :documentation "Where the database being replaced is parked, inside the
rebuilt directory, between the two renames.")

(alexandria:define-constant +wallet-rewrite-marker+ "BITCOIN_LISP_REWRITE"
  :test #'equal
  :documentation "The file that says a <name>.rewrite directory is ours. It is
written before anything else goes in, so it means \"this is scratch\" and not
\"this is finished\" -- without it a wallet an operator really did name
w.rewrite would be deleted as a leftover.")

(defun wallet-rewrite-directory-p (name)
  "T when NAME is the reserved name of a rewrite scratch directory rather than
a wallet someone created. LIST-WALLET-DIR uses it so a leftover from an
interrupted rewrite is never offered as a wallet to load."
  (and (> (length name) (length +wallet-rewrite-suffix+))
       (alexandria:ends-with-subseq +wallet-rewrite-suffix+ name)))

(defun %wallet-rewrite-path (path)
  "PATH's sibling directory with +WALLET-REWRITE-SUFFIX+ appended to its name."
  (let* ((dir (uiop:ensure-directory-pathname path))
         (components (pathname-directory dir)))
    (make-pathname :directory (append (butlast components)
                                      (list (concatenate 'string
                                                         (car (last components))
                                                         +wallet-rewrite-suffix+)))
                   :name nil :type nil :defaults dir)))

(defun %wallet-superseded-path (directory)
  (merge-pathnames (concatenate 'string +wallet-superseded-subdirectory+ "/")
                   (uiop:ensure-directory-pathname directory)))

(defun %wallet-rewrite-marker-path (directory)
  (merge-pathnames +wallet-rewrite-marker+
                   (uiop:ensure-directory-pathname directory)))

(defun %wallet-rewrite-scratch-p (directory)
  "T when DIRECTORY exists and carries the rewrite marker."
  (and (uiop:directory-exists-p directory)
       (probe-file (%wallet-rewrite-marker-path directory))
       t))

(defun wallet-rewrite-name-conflict (path)
  "The sibling directory a rewrite of the wallet at PATH needs, when something
that is not ours already occupies it; NIL when the name is free.

Asked BEFORE the work that will need it, not when the rewrite reaches the
name: EncryptWallet's rewrite runs after the encryption batch has committed,
so refusing there would leave a wallet that is encrypted, is missing the
erasure the encryption promised, and reports an error."
  (let ((rewrite (%wallet-rewrite-path path)))
    (when (and (uiop:directory-exists-p rewrite)
               (not (%wallet-rewrite-scratch-p rewrite)))
      rewrite)))

(defun %delete-wallet-directory (path)
  (uiop:delete-directory-tree (uiop:ensure-directory-pathname path)
                              :validate t :if-does-not-exist :ignore))

(defun %fsync-wallet-directory (path)
  "fsync every file in PATH and then PATH itself: the records AND the names
they live under have to be on disk before the rename that publishes them."
  (let ((dir (uiop:ensure-directory-pathname path)))
    (dolist (file (uiop:directory-files dir))
      (bl.kv:fsync-file file))
    (bl.kv:fsync-directory dir)))

(defun %wallet-drop-rewrite-remnants (path)
  "Remove what a completed swap leaves inside the wallet directory: the parked
predecessor and the marker that travelled with the rebuilt copy."
  (%delete-wallet-directory (%wallet-superseded-path path))
  (uiop:delete-file-if-exists (%wallet-rewrite-marker-path path)))

(defun wallet-recover-interrupted-rewrite (path)
  "Finish or discard a WALLET-DB-REWRITE of the wallet at PATH that did not
run to completion, and return PATH. A no-op when no rewrite is outstanding.

WALLET-DB-REWRITE has the rebuilt directory complete and fsynced before it
touches PATH, so the only interruption that can leave PATH missing is the one
between its two renames -- which is why the scratch directory may be promoted
there without inspecting it, and why a half-built one (PATH still in place) is
discarded unread instead."
  (let* ((path (uiop:ensure-directory-pathname path))
         (rewrite (%wallet-rewrite-path path))
         (ours (%wallet-rewrite-scratch-p rewrite)))
    (cond
      ;; The wallet is where it belongs; anything beside or inside it is scrap.
      ((wallet-db-exists-p path)
       (when ours (%delete-wallet-directory rewrite))
       (%wallet-drop-rewrite-remnants path))
      ;; Interrupted between the two renames: the rebuilt database is complete
      ;; and carries the wallet it replaced under superseded/.
      ((and ours (wallet-db-exists-p rewrite))
       (bl.kv:rename-path rewrite path)
       (%wallet-drop-rewrite-remnants path)))
    path))

(defun wallet-db-rewrite (db path)
  "Rebuild the wallet database at PATH and return a handle on the rebuilt
copy; DB is closed. Our WalletDatabase::Rewrite -- the call EncryptWallet ends
with so that the deleted plaintext keys stop living in the database's slack
space (wallet/wallet.cpp:872-876, wallet/sqlite.cpp:336-341).

Only the records the iterator still returns are written, so a tombstoned
plaintext key is never copied, and the directory that held its bytes is
removed. The caller holds the wallet lock: nothing may write to DB between the
record scan and the swap.

The order is the crash contract. The rebuilt directory is complete, marked and
fsynced before anything moves, so every interruption leaves at least one
complete database on disk and WALLET-RECOVER-INTERRUPTED-REWRITE -- which
LOAD-WALLET runs before it opens anything -- puts it back at PATH. The swap
itself must not signal: by then the old handle is closed, so an escaping error
would hand the caller a dead pointer. It logs instead, and the recovery pass
that follows decides which directory gets opened."
  (let* ((path (uiop:ensure-directory-pathname path))
         (rewrite (%wallet-rewrite-path path)))
    (when (wallet-rewrite-name-conflict path)
      (wallet-error "wallet rewrite: ~A already exists and is not ours" rewrite))
    (%delete-wallet-directory rewrite)
    ;; The marker first: from here the directory is identifiably scratch, so an
    ;; interrupted build is cleaned up rather than blocking every later rewrite.
    (ensure-directories-exist rewrite)
    (with-open-file (out (%wallet-rewrite-marker-path rewrite)
                         :direction :output :if-exists :supersede
                         :if-does-not-exist :create)
      (write-line "bitcoin-lisp wallet database rewrite" out))
    (let ((new-db (wallet-db-open rewrite :create t)))
      (unwind-protect
           (bl.store:with-leveldb-writebatch (batch)
             (with-wallet-db-records (key value db)
               (bl.store:leveldb-writebatch-put batch key value))
             (bl.store:leveldb-write new-db batch :sync t))
        (bl.store:leveldb-close new-db)))
    (%fsync-wallet-directory rewrite)
    (handler-case
        (progn
          (bl.store:leveldb-close db)
          (bl.kv:rename-path path (%wallet-superseded-path rewrite))
          (bl.kv:rename-path rewrite path)
          (bl.kv:fsync-directory (uiop:pathname-parent-directory-pathname path)))
      (error (e)
        ;; Loud, because this is the branch where the encryption is committed
        ;; and the pre-encryption key bytes may still be on disk.
        (bl:log-warn "wallet rewrite: swapping ~A into place failed (~A); the ~
wallet is intact but the plaintext this rewrite exists to remove may remain"
                     path e)))
    (wallet-recover-interrupted-rewrite path)
    (wallet-db-open path)))
