(in-package #:bitcoin-lisp.tests)

;;; Wallet P1 tests: record schema round-trips (Core walletdb.cpp encodings),
;;; descriptor SPKM keypool semantics (persist-before-issue), default-wallet
;;; descriptor derivation, wallet lifecycle RPCs, /wallet/<name> routing, and
;;; importdescriptors — with derivations cross-checked against Bitcoin Core
;;; known vectors (descriptor_tests.cpp, test/functional/wallet_taproot.py).

(def-suite wallet-tests
  :description "Wallet P1: container + keystore + wallet RPCs"
  :in :bitcoin-lisp-tests)

(in-suite wallet-tests)

;;; --- Helpers ---

(defun %make-wallet-test-node (dir &key (network :testnet4) (keypool 5))
  "A minimal node with a wallet manager rooted at DIR."
  (let ((node (bl:make-node :network network)))
    (setf (bl:node-chain-state node)
          (bl.store:make-chain-state))
    (setf (bl:node-wallet-manager node)
          (bl.wallet::make-wallet-manager
           :data-directory dir :network network :keypool-size keypool))
    node))

(defun %node-manager (node)
  (bl:node-wallet-manager node))

(defmacro with-wallet-test-node ((node &key (network :testnet4) (keypool 5))
                                 &body body)
  "Run BODY with NODE bound to a wallet-enabled test node in a fresh temp
datadir; the directory is deleted on unwind."
  (let ((dir (gensym "DIR")))
    `(let* ((,dir (make-temp-directory))
            (,node (%make-wallet-test-node ,dir :network ,network
                                                :keypool ,keypool)))
       (unwind-protect (progn ,@body)
         (ignore-errors
          (bl.wallet:close-wallet-manager (%node-manager ,node)))
         (uiop:delete-directory-tree ,dir :validate t
                                          :if-does-not-exist :ignore)))))

(defun %aval (key alist)
  "One field of an RPC result alist, with an amount TOKEN decoded to an exact
rational (BTC-AMOUNT). Core's functional framework parses its JSON with
parse_float=Decimal for the same reason: an amount field carries Core's
ValueFromAmount spelling, and a test asserting a value should not have to
know how that spelling is written."
  (btc-amount (cdr (assoc key alist :test #'string=))))

(defun %crash-close-wallet (node name)
  "Simulate a crash: close the wallet DB with no graceful unload bookkeeping
(no best-block write) and drop it from the manager."
  (let* ((manager (%node-manager node))
         (wallet (loaded-wallet manager name)))
    (bl.store:leveldb-close (bl.wallet::wallet-db wallet))
    (remhash name (bl.wallet::wallet-manager-wallets manager))
    (setf (bl.wallet::wallet-manager-wallet-order manager)
          (remove name (bl.wallet::wallet-manager-wallet-order manager)
                  :test #'string=))))

(defun %address-script (address network)
  (nth-value 1 (bl.crypto:decode-address address network)))

(defun %ht (&rest kvs)
  "Build a yason-style request object."
  (let ((ht (make-hash-table :test 'equal)))
    (loop for (k v) on kvs by #'cddr do (setf (gethash k ht) v))
    ht))

;;; --- Record schema: byte-level encodings + round-trip ---

(test wallet-record-key-encodings
  "Record keys serialize as compactsize-prefixed type string + typed fields
(the DataStream encoding Core writes)."
  ;; Singleton key: 0x05 'flags'
  (is (equalp (concatenate '(vector (unsigned-byte 8))
                           (vector 5) (map 'vector #'char-code "flags"))
              (bl.wallet::wdb-key-simple "flags")))
  ;; Typed key round-trip through wdb-parse-key
  (let ((id (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (multiple-value-bind (type fields)
        (bl.wallet::wdb-parse-key (bl.wallet::wdb-key-descriptor id))
      (is (string= type "walletdescriptor"))
      (is (equalp id fields)))
    (multiple-value-bind (type fields)
        (bl.wallet::wdb-parse-key
         (bl.wallet::wdb-key-lockedutxo id 5))
      (is (string= type "lockedutxo"))
      (is (= (length fields) 36))
      (is (equalp id (subseq fields 0 32)))
      (is (equalp #(5 0 0 0) (subseq fields 32))))))

(test wallet-record-value-encodings
  "WalletDescriptor and CBlockLocator values match Core's serialize methods
byte for byte."
  ;; WalletDescriptor: string, u64 creation, i32 next, i32 start, i32 end
  ;; (walletutil.h:90-96 — note next_index serializes before range_start).
  (is (equalp #(3 97 98 99                    ; "abc"
                42 0 0 0 0 0 0 0              ; creation_time 42
                1 0 0 0                       ; next_index 1
                0 0 0 0                       ; range_start 0
                10 0 0 0)                     ; range_end 10
              (bl.wallet::wdb-descriptor-value "abc" 42 1 0 10)))
  (multiple-value-bind (str time next start end)
      (bl.wallet::wdb-parse-descriptor-value
       (bl.wallet::wdb-descriptor-value "abc" 42 1 0 10))
    (is (string= str "abc"))
    (is (= time 42)) (is (= next 1)) (is (= start 0)) (is (= end 10)))
  ;; CBlockLocator: dummy version 70016 LE + vector<uint256>
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (let ((bytes (bl.wallet::wdb-block-locator-value (list h))))
      (is (equalp #(#x80 #x11 #x01 #x00 1) (subseq bytes 0 5)))
      (is (equalp (list h) (bl.wallet::wdb-parse-block-locator-value bytes))))
    (is (null (bl.wallet::wdb-parse-block-locator-value
               (bl.wallet::wdb-block-locator-value '()))))))

(test wallet-privkey-der-roundtrip
  "CPrivKey DER encoding matches Core's sizes (214/279) and round-trips."
  (let ((priv (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-contents (loop for i below 32 collect (1+ i)))))
    (let ((der-c (bl.wallet::privkey-to-der priv t))
          (der-u (bl.wallet::privkey-to-der priv nil)))
      (is (= 214 (length der-c)))          ; CKey::COMPRESSED_SIZE
      (is (= 279 (length der-u)))          ; CKey::SIZE
      (is (equalp priv (bl.wallet::der-to-privkey der-c)))
      (is (equalp priv (bl.wallet::der-to-privkey der-u)))
      (is (null (bl.wallet::der-to-privkey (subseq der-c 0 40)))))))

(test wallet-record-schema-roundtrip
  "Write one record of every schema type, reopen the DB, read back identical."
  (let* ((dir (make-temp-directory))
         (path (merge-pathnames "roundtrip/" dir))
         (id (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))
         (pubkey (bl.crypto:derive-public-key
                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                  :compressed t))
         (priv (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (xpub (bl.crypto:bip32-neuter
                (bl.crypto:bip32-master-key
                 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
                 :network :testnet3)))
         (written '()))
    (unwind-protect
         (progn
           (let ((db (bl.wallet::wallet-db-open path :create t)))
             (flet ((put (key value)
                      (push (cons key value) written)
                      (bl.store:leveldb-put db key value)))
               (put (bl.wallet::wdb-key-descriptor id)
                    (bl.wallet::wdb-descriptor-value "wpkh(x)#00000000" 7 1 0 5))
               (put (bl.wallet::wdb-key-descriptor-key
                     bl.wallet::+wdb-key-walletdescriptorkey+ id pubkey)
                    (bl.wallet::wdb-descriptor-key-value
                     pubkey (bl.wallet::privkey-to-der priv t)))
               (put (bl.wallet::wdb-key-descriptor-key
                     bl.wallet::+wdb-key-walletdescriptorckey+ id pubkey)
                    (bl.wallet::wdb-vector-value #(1 2 3 4)))
               (put (bl.wallet::wdb-key-descriptor-parent-cache
                     bl.wallet::+wdb-key-walletdescriptorcache+ id 0)
                    (bl.wallet::wdb-xpub-value xpub))
               (put (bl.wallet::wdb-key-descriptor-derived-cache id 0 11)
                    (bl.wallet::wdb-xpub-value xpub))
               (put (bl.wallet::wdb-key-descriptor-parent-cache
                     bl.wallet::+wdb-key-walletdescriptorlhcache+ id 0)
                    (bl.wallet::wdb-xpub-value xpub))
               (put (bl.wallet::wdb-key-active-spk nil 2) id)
               (put (bl.wallet::wdb-key-active-spk t 3) id)
               (put (bl.wallet::wdb-key-simple
                     bl.wallet::+wdb-key-bestblock+)
                    (bl.wallet::wdb-block-locator-value '()))
               (put (bl.wallet::wdb-key-simple
                     bl.wallet::+wdb-key-bestblock-nomerkle+)
                    (bl.wallet::wdb-block-locator-value (list txid)))
               (put (bl.wallet::wdb-key-address-string
                     bl.wallet::+wdb-key-name+ "addr1")
                    (bl.wallet::wdb-string-value "label1"))
               (put (bl.wallet::wdb-key-address-string
                     bl.wallet::+wdb-key-purpose+ "addr1")
                    (bl.wallet::wdb-string-value "receive"))
               (put (bl.wallet::wdb-key-simple
                     bl.wallet::+wdb-key-flags+)
                    (bl.wallet::wdb-uint64-value
                     bl.wallet::+wallet-flag-descriptors+))
               (put (bl.wallet::wdb-key-mkey 1)
                    (bl.wallet::wdb-mkey-value #(9 9) #(8 8 8) 0 25000 #()))
               (put (bl.wallet::wdb-key-simple
                     bl.wallet::+wdb-key-orderposnext+)
                    (bl.wallet::wdb-int64-value 12345))
               (put (bl.wallet::wdb-key-lockedutxo txid 1)
                    bl.wallet::+wdb-lockedutxo-value+)
               (put (bl.wallet::wdb-key-simple
                     bl.wallet::+wdb-key-minversion+)
                    (bl.wallet::wdb-int32-value 169900))
               (put (bl.wallet::wdb-key-simple
                     bl.wallet::+wdb-key-version+)
                    (bl.wallet::wdb-int32-value
                     bl.wallet::+wallet-client-version+))
               (put (bl.wallet::wdb-key-tx txid)
                    (bl.wallet::wdb-vector-value #())))
             (bl.store:leveldb-close db))
           ;; Reopen and compare every record byte-for-byte.
           (let* ((db (bl.wallet::wallet-db-open path))
                  (records (wallet-db-record-list db)))
             (is (= (length written) (length records)))
             (dolist (w written)
               (let ((found (find (car w) records :key #'car :test #'equalp)))
                 (is (not (null found)))
                 (when found
                   (is (equalp (cdr w) (cdr found))))))
             ;; mkey parses back
             (let ((mkey (find (bl.wallet::wdb-key-mkey 1) records
                               :key #'car :test #'equalp)))
               (multiple-value-bind (ck salt method iters other)
                   (bl.wallet::wdb-parse-mkey-value (cdr mkey))
                 (is (equalp #(9 9) ck))
                 (is (equalp #(8 8 8) salt))
                 (is (= 0 method))
                 (is (= 25000 iters))
                 (is (zerop (length other)))))
             ;; xpub value decodes to the same extended key
             (let ((rec (find (bl.wallet::wdb-key-descriptor-derived-cache id 0 11)
                              records :key #'car :test #'equalp)))
               (let ((decoded (bl.wallet::wdb-parse-xpub-value (cdr rec) :testnet4)))
                 (is (string= (bl.crypto:bip32-serialize xpub)
                              (bl.crypto:bip32-serialize decoded)))))
             (bl.store:leveldb-close db)))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

;;; --- DescriptorID (compat form) ---

(test wallet-descriptor-id-compat-form
  "DescriptorID hashes the checksummed COMPAT-format string (apostrophe
hardened markers), so h-style and '-style inputs share one id."
  (let* ((xpub "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
         (desc-h (bl.rpc:parse-descriptor
                  (format nil "wpkh(~A/1h/2/*)" xpub) :mainnet))
         (desc-a (bl.rpc:parse-descriptor
                  (format nil "wpkh(~A/1'/2/*)" xpub) :mainnet)))
    (is (equalp (bl.rpc:descriptor-id desc-h)
                (bl.rpc:descriptor-id desc-a)))
    ;; And it is SHA256 over the checksummed compat body.
    (is (equalp (bl.crypto:sha256
                 (flexi-streams:string-to-octets
                  (bl.rpc:descriptor-add-checksum
                   (format nil "wpkh(~A/1'/2/*)" xpub))
                  :external-format :ascii))
                (bl.rpc:descriptor-id desc-h)))))

;;; --- Default wallet SPKMs (fixed master key, cross-checked derivation) ---

(test wallet-default-descriptors-and-derivation
  "createwallet's 8 default SPKMs follow Core GenerateWalletDescriptor
exactly, and the addresses they issue match an independent expansion of the
same descriptors through the P0 engine (direct BIP32 derivation, no wallet
cache)."
  (with-wallet-test-node (node :network :testnet4 :keypool 3)
    (let* ((manager (%node-manager node))
           (seed (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-contents (loop for i below 32
                                                        collect (+ 10 i))))
           (master (bl.crypto:bip32-master-key seed :network :testnet3))
           (xpub-str (bl.crypto:bip32-serialize
                      (bl.crypto:bip32-neuter master)))
           (xprv-str (bl.crypto:bip32-serialize master))
           (wallet (bl.wallet::create-wallet manager "fixed" :blank t)))
      (bl.wallet::with-wallet-lock (wallet)
        (bl.wallet::wallet-setup-descriptor-spkms wallet master))
      (is (= 8 (hash-table-count (bl.wallet::wallet-spkms wallet))))
      (is (= 4 (hash-table-count (bl.wallet::wallet-external-spkms wallet))))
      (is (= 4 (hash-table-count (bl.wallet::wallet-internal-spkms wallet))))
      ;; Descriptor strings have Core's exact shape (testnet coin type 1h).
      (loop for (type prefix purpose suffix)
              in '((:legacy "pkh(" 44 "/*)") (:p2sh-segwit "sh(wpkh(" 49 "/*))")
                   (:bech32 "wpkh(" 84 "/*)") (:bech32m "tr(" 86 "/*)"))
            do (let ((spkm (gethash type (bl.wallet::wallet-external-spkms
                                          wallet))))
                 (is (string= (format nil "~A~A/~Ah/1h/0h/0~A"
                                      prefix xpub-str purpose suffix)
                              (first (uiop:split-string
                                      (bl.wallet::desc-spkm-desc-string spkm)
                                      :separator "#"))))))
      ;; Issued addresses match the P0 engine expanding the PRIVATE
      ;; descriptor by direct derivation (independent of the SPKM cache path).
      (dolist (spec '((:bech32 84 0) (:bech32m 86 0) (:legacy 44 0)
                      (:p2sh-segwit 49 0) (:bech32 84 1)))
        (destructuring-bind (type purpose internal) spec
          (let* ((spkm (gethash type (if (= internal 1)
                                         (bl.wallet::wallet-internal-spkms wallet)
                                         (bl.wallet::wallet-external-spkms wallet))))
                 (desc-str (format nil "~A~A/~Ah/1h/0h/~A~A"
                                   (ecase type (:legacy "pkh(") (:p2sh-segwit "sh(wpkh(")
                                          (:bech32 "wpkh(") (:bech32m "tr("))
                                   xprv-str purpose internal
                                   (if (eq type :p2sh-segwit) "/*))" "/*)")))
                 (desc (bl.rpc:parse-descriptor desc-str :testnet4))
                 (next (bl.wallet::desc-spkm-next-index spkm))
                 (expected (bl.rpc:script->address
                            (first (bl.rpc::out-desc-expand desc next))
                            :testnet4))
                 (issued (bl.wallet::with-wallet-lock (wallet)
                           (bl.wallet::spkm-get-new-destination
                            wallet spkm type))))
            (is (string= expected issued))))))))

;;; --- Core-known vectors ---

(test wallet-import-core-wpkh-vector
  "importdescriptors of Core descriptor_tests.cpp's hardened-origin wpkh
vector produces Core's exact scriptPubKeys in the SPKM map, and getnewaddress
hands out Core's script at index 0."
  (with-wallet-test-node (node :network :mainnet :keypool 3)
    (let* ((manager (%node-manager node))
           (wallet (bl.wallet::create-wallet manager "corevec" :blank t))
           (desc-body "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)")
           (desc-str (bl.rpc:descriptor-add-checksum desc-body))
           (core-scripts '("0014326b2249e3a25d5dc60935f044ee835d090ba859"
                           "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"
                           "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27")))
      (declare (ignore wallet))
      (let* ((bl.wallet::*rpc-wallet-name* "corevec")
             (results (bl.wallet::rpc-importdescriptors
                       node (list (list (%ht "desc" desc-str
                                             "timestamp" "now"
                                             "active" t
                                             "range" '(0 2)))))))
        (is (= 1 (length results)))
        (is (eq t (%aval "success" (first results)))))
      (let* ((wallet (loaded-wallet manager "corevec"))
             (spkm (gethash :bech32
                            (bl.wallet::wallet-external-spkms wallet))))
        (is (not (null spkm)))
        (loop for hex in core-scripts
              for i from 0
              do (is (eql i (bl.wallet::spkm-is-mine
                             spkm (bl.crypto:hex-to-bytes hex)))))
        ;; getnewaddress bech32 = Core's script at index 0
        (with-rpc-wallet ("corevec")
          (let ((address (bl.wallet::rpc-getnewaddress
                          node '("" "bech32"))))
            (is (equalp (bl.crypto:hex-to-bytes (first core-scripts))
                        (%address-script address :mainnet)))))))))

(test wallet-import-core-taproot-vector
  "tr(tprv.../*) issues addresses whose x-only internal keys match Core's
wallet_taproot.py independent-implementation vectors, tweaked per BIP341."
  (with-wallet-test-node (node :network :testnet4 :keypool 4)
    (let* ((manager (%node-manager node))
           (xprv "tprv8ZgxMBicQKsPeNLUGrbv3b7qhUk1LQJZAGMuk9gVuKh9sd4BWGp1eMsehUni6qGb8bjkdwBxCbgNGdh2bYGACK5C5dRTaif9KBKGVnSezxV")
           (desc-str (bl.rpc:descriptor-add-checksum
                      (format nil "tr(~A/*)" xprv)))
           ;; m/* derived x-only pubkeys, indexes 0-3 (wallet_taproot.py KEYS[0])
           (core-pubs '("83d8ee77a0f3a32a5cea96fd1624d623b836c1e5d1ac2dcde46814b619320c18"
                        "a30253b018ea6fca966135bf7dd8026915427f24ccf10d4e03f7870f4128569b"
                        "a61e5749f2f3db9dc871d7b187e30bfd3297eea2557e9be99897ea8ff7a29a21"
                        "8110cf482f66dc37125e619d73075af932521724ffc7108309e88f361efe8c8a")))
      (bl.wallet::create-wallet manager "trvec" :blank t)
      (let* ((bl.wallet::*rpc-wallet-name* "trvec")
             (results (bl.wallet::rpc-importdescriptors
                       node (list (list (%ht "desc" desc-str
                                             "timestamp" 1
                                             "active" t
                                             "range" '(0 3)))))))
        (is (eq t (%aval "success" (first results))))
        (dolist (pub-hex core-pubs)
          (let* ((internal (bl.crypto:hex-to-bytes pub-hex))
                 (tweaked (bl.crypto:tweak-xonly-pubkey
                           internal (bl.crypto:tap-tweak-hash internal)))
                 (expected (bl.crypto:encode-p2tr-address
                            tweaked :testnet4))
                 (address (bl.wallet::rpc-getnewaddress
                           node '("" "bech32m"))))
            (is (string= expected address))))))))

;;; --- Keypool persistence (funds-critical: no reuse after crash) ---

(test wallet-keypool-persistence-across-reload
  "Issued addresses are persisted (next_index fsynced) BEFORE being handed
out: after a crash-simulating close and reload, no previously issued address
is ever reissued."
  (with-wallet-test-node (node :network :testnet4 :keypool 5)
    (let ((issued '()))
      (with-rpc-wallet (nil)
        (bl.wallet::rpc-createwallet node '("crashy"))
        ;; 7 bech32 (crosses the initial keypool window and forces TopUp),
        ;; plus a few of the other types and a change address.
        (dotimes (i 7)
          (push (bl.wallet::rpc-getnewaddress node '("" "bech32")) issued))
        (dolist (type '("legacy" "p2sh-segwit" "bech32m"))
          (push (bl.wallet::rpc-getnewaddress node (list "" type)) issued)
          (push (bl.wallet::rpc-getrawchangeaddress node (list type)) issued))
        (push (bl.wallet::rpc-getrawchangeaddress node '("bech32")) issued))
      (is (= 14 (length issued)))
      (is (= 14 (length (remove-duplicates issued :test #'string=))))
      ;; Crash: close the DB without any graceful-unload writes.
      (%crash-close-wallet node "crashy")
      ;; Reload and issue more of everything: zero overlap allowed.
      (let ((bl.wallet::*rpc-wallet-name* nil)
            (fresh '()))
        (bl.wallet::rpc-loadwallet node '("crashy"))
        (dotimes (i 3)
          (push (bl.wallet::rpc-getnewaddress node '("" "bech32")) fresh))
        (dolist (type '("legacy" "p2sh-segwit" "bech32m"))
          (push (bl.wallet::rpc-getnewaddress node (list "" type)) fresh)
          (push (bl.wallet::rpc-getrawchangeaddress node (list type)) fresh))
        (push (bl.wallet::rpc-getrawchangeaddress node '("bech32")) fresh)
        (is (= 10 (length (remove-duplicates fresh :test #'string=))))
        (is (null (intersection issued fresh :test #'string=)))))))

(test wallet-state-survives-reload
  "Descriptors, next_index, keys, and the IsMine map are identical after a
close/reopen (record schema round-trip at the wallet level)."
  (with-wallet-test-node (node :network :testnet4 :keypool 5)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("persist")))
    (let* ((manager (%node-manager node))
           (wallet (loaded-wallet manager "persist"))
           (addr1 (with-rpc-wallet (nil)
                    (bl.wallet::rpc-getnewaddress node '("" "bech32"))))
           ;; range_end is legitimately extended by the reload-time TopUp
           ;; (Core LoadExisting -> TopUpKeyPool), so compare descriptor
           ;; string + next_index and check range_end monotonicity separately.
           (spkm-state (lambda (w)
                         (sort (loop for spkm being the hash-values
                                       of (bl.wallet::wallet-spkms w)
                                     collect (list (bl.wallet::desc-spkm-desc-string spkm)
                                                   (bl.wallet::desc-spkm-next-index spkm)
                                                   (bl.wallet::desc-spkm-range-end spkm)))
                               #'string< :key #'first)))
           (descs-before (funcall spkm-state wallet)))
      (with-rpc-wallet (nil)
        (bl.wallet::rpc-unloadwallet node '("persist"))
        (bl.wallet::rpc-loadwallet node '("persist")))
      (let* ((wallet2 (loaded-wallet manager "persist"))
             (descs-after (funcall spkm-state wallet2)))
        (is (equal (mapcar (lambda (d) (list (first d) (second d))) descs-before)
                   (mapcar (lambda (d) (list (first d) (second d))) descs-after)))
        (loop for before in descs-before
              for after in descs-after
              do (is (>= (third after) (third before))))
        ;; The issued address is still IsMine at an index below next_index.
        (let* ((script (%address-script addr1 :testnet4))
               (spkm (gethash :bech32 (bl.wallet::wallet-external-spkms
                                       wallet2)))
               (index (bl.wallet::spkm-is-mine spkm script)))
          (is (eql 0 index))
          (is (< index (bl.wallet::desc-spkm-next-index spkm)))
          (is (bl.wallet::wallet-is-mine wallet2 script)))))))

;;; --- The `version` record (GA11 b314f13a) ---

(defun %version-record-key ()
  (bl.wallet::wdb-key-simple bl.wallet::+wdb-key-version+))

(defun %stored-client-version (path)
  "The `version` record of the CLOSED wallet at PATH, or NIL when there is
none. Read on the file rather than through the wallet, because absent and
present-with-this-build's-value are the two cases that have to be told apart."
  (let ((db (bl.wallet::wallet-db-open path)))
    (unwind-protect
         (let ((value (bl.store:leveldb-get db (%version-record-key))))
           (and value (bl.wallet::wdb-parse-int32-value value)))
      (bl.store:leveldb-close db))))

(defun %set-stored-client-version (path version)
  "Overwrite the closed wallet's `version` record with VERSION, or remove the
record when VERSION is NIL."
  (let ((db (bl.wallet::wallet-db-open path)))
    (unwind-protect
         (if version
             (bl.store:leveldb-put db (%version-record-key)
                                   (bl.wallet::wdb-int32-value version) :sync t)
             (bl.store:leveldb-delete db (%version-record-key) :sync t))
      (bl.store:leveldb-close db))))

(test wallet-load-stamps-the-client-version-record
  "GA11 b314f13a. Core reads DBKeys::VERSION into last_client at the top of
WalletBatch::LoadWallet, logs it, and after a clean load rewrites it whenever
it was absent or named a different version -- `if (!has_last_client ||
last_client != CLIENT_VERSION) WriteVersion(CLIENT_VERSION)`
(walletdb.cpp:1122-1125, 1177-1178). We wrote the record once at creation and
never read or refreshed it, so a wallet stamped 999999 stayed 999999 forever
and a wallet with no stamp never got one. The two are separate branches of
Core's condition, so both are here."
  (with-wallet-test-node (node)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("ver")))
    (let ((path (bl.wallet::wallet-path
                 (loaded-wallet (%node-manager node) "ver"))))
      (with-rpc-wallet (nil)
        ;; Creation writes this build's version (CWallet::CreateNew).
        (bl.wallet::rpc-unloadwallet node '("ver"))
        (is (eql bl.wallet::+wallet-client-version+ (%stored-client-version path)))
        ;; Stale: a file from another build is restamped on load.
        (%set-stored-client-version path 999999)
        (bl.wallet::rpc-loadwallet node '("ver"))
        (bl.wallet::rpc-unloadwallet node '("ver"))
        (is (eql bl.wallet::+wallet-client-version+ (%stored-client-version path)))
        ;; Absent: !has_last_client is the other half of Core's condition, and
        ;; the pre-fix code failed it identically -- no record went in.
        (%set-stored-client-version path nil)
        (is (null (%stored-client-version path)))
        (bl.wallet::rpc-loadwallet node '("ver"))
        (bl.wallet::rpc-unloadwallet node '("ver"))
        (is (eql bl.wallet::+wallet-client-version+
                 (%stored-client-version path)))))))

;;; --- A wallet database that cannot be read (GA11 5b7d945a) ---

(defun %make-damaged-wallet-dir (manager name shape)
  "Build <wallets>/NAME/ in a damaged state.

:MISSING leaves it absent. :EMPTY makes an empty directory. :GARBAGE-CURRENT
writes a CURRENT that names nothing -- the shape that fails Core's format
probe. :GARBAGE-MANIFEST writes a CURRENT naming a MANIFEST that is there and
is not one, which passes the probe and still cannot be opened, so it is the
half that must answer -4 rather than -18."
  (let ((path (bl.wallet::wallet-path-for manager name)))
    (flet ((write-file (file text)
             (with-open-file (s (merge-pathnames file path)
                                :direction :output :if-exists :supersede
                                :if-does-not-exist :create)
               (write-line text s))))
      (ecase shape
        (:missing)
        (:empty (ensure-directories-exist path))
        (:garbage-current
         (ensure-directories-exist path)
         (write-file "CURRENT" "garbage"))
        (:garbage-manifest
         (ensure-directories-exist path)
         (write-file "MANIFEST-000999" "not a manifest")
         (write-file "CURRENT" "MANIFEST-000999")
         ;; The id file too: this shape must pass the probe.
         (bl.wallet:wallet-write-id path bl:*network*))))
    path))

(test wallet-unreadable-database-answers-core-s-database-status
  "GA11 5b7d945a. Every database failure in Core carries a DatabaseStatus and
HandleWalletError maps it (rpc/util.cpp:127-157): FAILED_NOT_FOUND and
FAILED_BAD_FORMAT are -18, everything else is -4, and no Core path answers a
wallet-load request with an internal error -- protocol.h:34 reserves that for
\"genuine errors in bitcoind\". Ours let BL.ERR:STORAGE-ERROR escape
wallet-db-open and the record scan, so a wallet whose file was present but
unreadable reached the client as -32603 carrying a raw LevelDB string.

The split follows Core's own: the format probe answers -18 before the engine
is handed the path (MakeDatabase, walletdb.cpp:1329-1382), and a failure after
it is -4."
  (with-wallet-test-node (node)
    (with-rpc-wallet (nil)
      (let ((manager (%node-manager node)))
        (flet ((load-wallet-rpc (name)
                 (bl.wallet::rpc-loadwallet node (list name))))
          (%make-damaged-wallet-dir manager "gone" :missing)
          (signals-rpc-error (:code -18 :message "Path does not exist.")
            (load-wallet-rpc "gone"))
          ;; Core answers a directory with no data file -18 too, but with the
          ;; other sentence (wallet_multiwallet.py:305); we used to give the
          ;; missing-path one for both.
          (%make-damaged-wallet-dir manager "hollow" :empty)
          (signals-rpc-error (:code -18 :message "Data is not in recognized format.")
            (load-wallet-rpc "hollow"))
          (%make-damaged-wallet-dir manager "junk" :garbage-current)
          (signals-rpc-error (:code -18 :message "Data is not in recognized format.")
            (load-wallet-rpc "junk"))
          ;; Past the probe and still unopenable: Core's FAILED_LOAD, -4, with
          ;; the engine's own text -- which is what Core puts there too
          ;; (sqlite.cpp:691-707). The message check names the engine, not the
          ;; shared "Wallet file verification failed." prefix that the three
          ;; -18 answers above carry as well.
          (%make-damaged-wallet-dir manager "broken" :garbage-manifest)
          (signals-rpc-error (:code -4 :message "LevelDB error")
            (load-wallet-rpc "broken")))))))

;;; --- A walletdescriptor record that will not read (GA11 69862ba9) ---

(defun %damage-descriptor-record (path shape)
  "Damage the first walletdescriptor record of the CLOSED wallet at PATH.

The three shapes are three different failures in our old code and one single
class in Core's, which is the whole finding: :FLIP turns a bit inside the
serialized descriptor string, :NON-CHARSET writes a byte outside Core's
descriptor INPUT_CHARSET (descriptor.cpp:121-124), and :TRUNCATE cuts the
value short so the byte reader runs off the end."
  (let ((db (bl.wallet::wallet-db-open path)))
    (unwind-protect
         (dolist (record (wallet-db-record-list db))
           (when (equal (bl.wallet::wdb-parse-key (car record))
                        bl.wallet::+wdb-key-walletdescriptor+)
             (let ((value (copy-seq (cdr record))))
               (return
                 (bl.store:leveldb-put
                  db (car record)
                  (ecase shape
                    (:flip (setf (aref value 12) (logxor 1 (aref value 12)))
                           value)
                    (:non-charset (setf (aref value 12) 1)
                                  value)
                    (:truncate (subseq value 0 (- (length value) 6))))
                  :sync t)))))
      (bl.store:leveldb-close db))))

(defun %load-damaged-descriptor-wallet (node shape &key version)
  "Create wallet wd, unload it, damage its descriptor record per SHAPE (and
stamp VERSION when given), then load it. Returns the lines that load logged;
the load itself is expected to signal."
  (with-rpc-wallet (nil)
    (bl.wallet::rpc-createwallet node '("wd"))
    (let ((path (bl.wallet::wallet-path
                 (loaded-wallet (%node-manager node) "wd"))))
      (bl.wallet::rpc-unloadwallet node '("wd"))
      (%damage-descriptor-record path shape)
      (when version (%set-stored-client-version path version))
      (capture-log-lines
       (lambda ()
         (ignore-errors (bl.wallet::rpc-loadwallet node '("wd"))))))))

(test wallet-unreadable-descriptor-record-is-core-s-unknown-descriptor
  "GA11 69862ba9. Core runs the descriptor parser inside WalletDescriptor's
deserializer and throws ios_base::failure for ANY parse failure
(walletutil.h:41-64), so LoadDescriptorWalletRecords answers a bit flip, a
non-charset byte and a truncated record with the one DBErrors::UNKNOWN_DESCRIPTOR
(walletdb.cpp:764-784), worded at wallet.cpp:2400-2404 and reaching the client
as RPC_WALLET_ERROR. We answered the first two with the descriptor parser's own
-5 about a checksum or invalid characters, and the third with -32603 carrying an
SBCL array-index report, because the value codec was unguarded."
  (dolist (shape '(:flip :non-charset :truncate))
    (with-wallet-test-node (node)
      (signals-rpc-error (:code -4
                          :message "Unrecognized descriptor found. Loading wallet")
        (with-rpc-wallet (nil)
          (bl.wallet::rpc-createwallet node '("wd"))
          (let ((path (bl.wallet::wallet-path
                       (loaded-wallet (%node-manager node) "wd"))))
            (bl.wallet::rpc-unloadwallet node '("wd"))
            (%damage-descriptor-record path shape)
            (bl.wallet::rpc-loadwallet node '("wd"))))))))

(test wallet-unreadable-descriptor-logs-core-s-detail-line
  "The reply is short and fixed; the detail goes to the log, and its middle
sentence is the one thing last_client picks (walletdb.cpp:782-783). A version
record from the future says the wallet may be too new; this build's own
version says the database may be corrupt. Core appends \"\\nDetails: %s\" to
both, which is where the underlying condition survives without being shipped
to the client."
  (with-wallet-test-node (node)
    (let ((lines (%load-damaged-descriptor-wallet node :truncate :version 999999)))
      (is-true (find-if (lambda (line)
                          (search "might have been created on a newer version" line))
                        lines))
      (is-true (find-if (lambda (line) (search "Details:" line)) lines))))
  (with-wallet-test-node (node)
    (let ((lines (%load-damaged-descriptor-wallet node :truncate)))
      (is-true (find-if (lambda (line)
                          (search "database might be corrupted" line))
                        lines))
      (is-true (find-if (lambda (line) (search "Details:" line)) lines)))))

(test wallet-hardened-ranged-cache-reload
  "A hardened-ranged descriptor (/*') persists derived-xpub cache records and
reloads to Core's exact scripts (descriptor_tests.cpp sh(wpkh(...)) vector)."
  (with-wallet-test-node (node :network :mainnet :keypool 3)
    (let* ((manager (%node-manager node))
           (desc-str (bl.rpc:descriptor-add-checksum
                      "sh(wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))"))
           (core-scripts '("a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87"
                           "a914bed59fc0024fae941d6e20a3b44a109ae740129287"
                           "a9148483aa1116eb9c05c482a72bada4b1db24af654387")))
      (bl.wallet::create-wallet manager "hardened" :blank t)
      (with-rpc-wallet ("hardened")
        (let ((results (bl.wallet::rpc-importdescriptors
                        node (list (list (%ht "desc" desc-str
                                              "timestamp" 1
                                              "active" t
                                              "range" '(0 2)))))))
          (is (eq t (%aval "success" (first results))))))
      ;; Reload: SetCache must rebuild the map purely from the persisted
      ;; derived-xpub records (no private keys consulted).
      (with-rpc-wallet (nil)
        (bl.wallet::rpc-unloadwallet node '("hardened"))
        (bl.wallet::rpc-loadwallet node '("hardened")))
      (let* ((wallet (loaded-wallet manager "hardened"))
             (spkm (gethash :p2sh-segwit
                            (bl.wallet::wallet-external-spkms wallet))))
        (is (not (null spkm)))
        (loop for hex in core-scripts
              for i from 0
              do (is (eql i (bl.wallet::spkm-is-mine
                             spkm (bl.crypto:hex-to-bytes hex)))))))))

;;; --- Lifecycle RPCs ---

(test wallet-lifecycle-rpcs
  "createwallet / loadwallet / unloadwallet / listwallets / listwalletdir
behave like Core, including the exact error codes."
  (with-wallet-test-node (node)
    (with-rpc-wallet (nil)
      (is (string= "w1" (%aval "name" (bl.wallet::rpc-createwallet
                                       node '("w1")))))
      (is (equal '("w1") (bl.wallet::rpc-listwallets node nil)))
      (bl.wallet::rpc-createwallet node '("w2"))
      (is (equal '("w1" "w2") (bl.wallet::rpc-listwallets node nil)))
      ;; duplicate create -> -36; reload of loaded -> -35; unknown -> -18
      (is (= bl.rpc:+rpc-wallet-already-exists+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-createwallet node '("w1"))))))
      (is (= bl.rpc:+rpc-wallet-already-loaded+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-loadwallet node '("w1"))))))
      (is (= bl.rpc:+rpc-wallet-not-found+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-loadwallet node '("nope"))))))
      ;; unload w1, reload it
      (bl.wallet::rpc-unloadwallet node '("w1"))
      (is (equal '("w2") (bl.wallet::rpc-listwallets node nil)))
      (is (= bl.rpc:+rpc-wallet-not-found+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-unloadwallet node '("w1"))))))
      (bl.wallet::rpc-loadwallet node '("w1"))
      (is (equal '("w2" "w1") (bl.wallet::rpc-listwallets node nil)))
      ;; unloadwallet endpoint/param mismatch -> -8; neither -> -8
      (with-rpc-wallet ("w1")
        (is (= bl.rpc:+rpc-invalid-parameter+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-unloadwallet node '("w2")))))))
      (is (= bl.rpc:+rpc-invalid-parameter+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-unloadwallet node '())))))
      ;; listwalletdir sees both, loaded or not
      (let ((dir-names (mapcar (lambda (w) (%aval "name" w))
                               (%aval "wallets"
                                      (bl.wallet::rpc-listwalletdir node nil)))))
        (is (equal '("w1" "w2") (sort (copy-list dir-names) #'string<))))
      ;; createwallet flag semantics: explicit descriptors=false is
      ;; rejected; a null descriptors argument takes Core's default (true).
      (is (= bl.rpc:+rpc-wallet-error+
             (rpc-error-code-of    ; descriptors=false rejected like Core
              (lambda () (bl.wallet::rpc-createwallet
                          node (list "legacy0" nil nil nil nil
                                     bl.rpc:+json-false+))))))
      ;; A passphrase now creates a born-encrypted wallet (wallet P6). It is
      ;; refused only with private keys disabled, where there would be
      ;; nothing for it to protect.
      (is (null (rpc-error-code-of
                 (lambda () (bl.wallet::rpc-createwallet
                             node '("enc0" nil nil "hunter2"))))))
      (is (bl.wallet::wallet-has-encryption-keys-p
           (loaded-wallet (%node-manager node) "enc0")))
      (is (= bl.rpc:+rpc-wallet-error+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-createwallet
                          node '("enc1" t nil "hunter2"))))))
      (is (= bl.rpc:+rpc-invalid-parameter+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-createwallet node '("")))))))))

(test wallet-flags-and-getwalletinfo
  "disable_private_keys / blank / avoid_reuse land in the flags record and
getwalletinfo reports Core's fields."
  (with-wallet-test-node (node)
    (with-rpc-wallet ("wo")
      ;; watch-only + blank + avoid_reuse
      (with-rpc-wallet (nil)
        (bl.wallet::rpc-createwallet node '("wo" t t nil t)))
      (let ((info (bl.wallet::rpc-getwalletinfo node nil)))
        (is (string= "wo" (%aval "walletname" info)))
        (is (eq 'yason:false (%aval "private_keys_enabled" info)))
        (is (eq t (%aval "avoid_reuse" info)))
        (is (eq t (%aval "blank" info)))
        (is (eq t (%aval "descriptors" info)))
        (is (= 0 (%aval "txcount" info)))
        (is (= 0 (%aval "keypoolsize" info)))
        ;; DELIBERATE DIVERGENCE, pinned so a change to it is a decision:
        ;; Core answers "sqlite" here for every descriptor wallet
        ;; (wallet/rpc/wallet.cpp getwalletinfo, GetDatabase().Format()), and
        ;; wallet_descriptor.py:93 asserts it. Our store is a LevelDB
        ;; directory and Core's wallet.dat file format is out of scope by
        ;; docs/wallet-plan.md §1, so the field names the database a caller
        ;; would really have to open. See the getwalletinfo comment.
        (is (string= "leveldb" (%aval "format" info)))
        (let ((flags (%aval "flags" info)))
          (is (member "avoid_reuse" flags :test #'string=))
          (is (member "blank" flags :test #'string=))
          (is (member "disable_private_keys" flags :test #'string=))
          (is (member "descriptor_wallet" flags :test #'string=))
          (is (member "last_hardened_xpub_cached" flags :test #'string=)))
        (is (assoc "lastprocessedblock" info :test #'string=)))
      ;; a watch-only blank wallet has no keys to hand out
      (is (= bl.rpc:+rpc-wallet-error+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-getnewaddress node nil))))))
    ;; full wallet: keypool counts are per-side
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("full")))
    (let* ((bl.wallet::*rpc-wallet-name* "full")
           (info (bl.wallet::rpc-getwalletinfo node nil)))
      (is (= 20 (%aval "keypoolsize" info)))               ; 4 external x 5
      (is (= 20 (%aval "keypoolsize_hd_internal" info)))   ; 4 internal x 5
      (is (eq t (%aval "private_keys_enabled" info)))
      (is (integerp (%aval "birthtime" info))))))

;;; --- /wallet/<name> routing ---

(test wallet-endpoint-routing
  "Requests resolve to the endpoint's wallet; Core's error codes for unknown
wallet (-18), no wallet loaded (-18), and ambiguous wallet (-19)."
  ;; URI parsing
  (is (string= "foo" (bl.wallet::wallet-name-from-uri "/wallet/foo")))
  (is (string= "a b" (bl.wallet::wallet-name-from-uri "/wallet/a b")))
  (is (null (bl.wallet::wallet-name-from-uri "/")))
  (is (null (bl.wallet::wallet-name-from-uri "/wallet/")))
  (is (null (bl.wallet::wallet-name-from-uri "/walletx/foo")))
  (with-wallet-test-node (node)
    ;; no wallet loaded -> -18
    (with-rpc-wallet (nil)
      (is (= bl.rpc:+rpc-wallet-not-found+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-getwalletinfo node nil)))))
      (bl.wallet::rpc-createwallet node '("r1"))
      ;; single wallet: base endpoint resolves to it
      (is (string= "r1" (%aval "walletname"
                               (bl.wallet::rpc-getwalletinfo node nil))))
      (bl.wallet::rpc-createwallet node '("r2"))
      ;; two wallets: base endpoint is ambiguous -> -19
      (is (= bl.rpc:+rpc-wallet-not-specified+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-getwalletinfo node nil))))))
    ;; endpoint routing picks the named wallet
    (with-rpc-wallet ("r2")
      (is (string= "r2" (%aval "walletname"
                               (bl.wallet::rpc-getwalletinfo node nil)))))
    ;; unknown wallet endpoint -> -18 with Core's message
    (with-rpc-wallet ("missing")
      (signals-rpc-error (:code bl.rpc:+rpc-wallet-not-found+ :exact-message "Requested wallet does not exist or is not loaded")
        (bl.wallet::rpc-getwalletinfo node nil)))
    ;; unloadwallet via endpoint (no param)
    (with-rpc-wallet ("r2")
      (bl.wallet::rpc-unloadwallet node '()))
    (with-rpc-wallet (nil)
      (is (equal '("r1") (bl.wallet::rpc-listwallets node nil))))))

(test wallet-disabled-node-rejects-wallet-rpcs
  "Without a wallet manager the wallet RPCs report method-not-found, like a
no-wallet Core build."
  (let ((node (bl:make-node :network :testnet4)))
    (setf (bl:node-chain-state node)
          (bl.store:make-chain-state))
    (is (= bl.rpc:+rpc-method-not-found+
           (rpc-error-code-of
            (lambda () (bl.wallet::rpc-createwallet node '("x"))))))
    (is (= bl.rpc:+rpc-method-not-found+
           (rpc-error-code-of
            (lambda () (bl.wallet::rpc-listwallets node nil)))))))

;;; --- getnewaddress across all four types ---

(test wallet-getnewaddress-all-types
  "getnewaddress/getrawchangeaddress issue distinct, IsMine addresses of the
right form for all four address types (testnet4 prefixes), default bech32."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("types"))
      (let ((wallet (loaded-wallet (%node-manager node) "types")))
        ;; default type is bech32 (Core DEFAULT_ADDRESS_TYPE)
        (let ((address (bl.wallet::rpc-getnewaddress node nil)))
          (is (string= "tb1q" (subseq address 0 4))))
        (loop for (type . prefix-test)
                in `(("legacy" . ,(lambda (a) (member (char a 0) '(#\m #\n))))
                     ("p2sh-segwit" . ,(lambda (a) (char= (char a 0) #\2)))
                     ("bech32" . ,(lambda (a) (string= "tb1q" (subseq a 0 4))))
                     ("bech32m" . ,(lambda (a) (string= "tb1p" (subseq a 0 4)))))
              do (let ((recv (bl.wallet::rpc-getnewaddress
                              node (list "" type)))
                       (change (bl.wallet::rpc-getrawchangeaddress
                                node (list type))))
                   (is (funcall prefix-test recv))
                   (is (funcall prefix-test change))
                   (is (not (string= recv change)))
                   (is (bl.wallet::wallet-is-mine
                        wallet (%address-script recv :testnet4)))
                   (is (bl.wallet::wallet-is-mine
                        wallet (%address-script change :testnet4)))))
        ;; unknown type -> -5; label "*" -> -11
        (is (= bl.rpc:+rpc-invalid-address-or-key+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-getnewaddress
                            node '("" "p2wpkh"))))))
        (is (= bl.rpc:+rpc-wallet-invalid-label-name+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-getnewaddress node '("*"))))))))))

;;; --- listdescriptors / importdescriptors ---

(test wallet-listdescriptors
  "listdescriptors lists all 8 default SPKMs sorted, with range/next fields;
private=true returns xprv-bearing strings; watch-only wallets reject
private=true."
  (with-wallet-test-node (node :keypool 3)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("ld")))
    (let* ((bl.wallet::*rpc-wallet-name* "ld")
           (result (bl.wallet::rpc-listdescriptors node nil))
           (descs (%aval "descriptors" result)))
      (is (string= "ld" (%aval "wallet_name" result)))
      (is (= 8 (length descs)))
      (is (equal (mapcar (lambda (d) (%aval "desc" d)) descs)
                 (sort (mapcar (lambda (d) (%aval "desc" d)) descs) #'string<)))
      (dolist (d descs)
        (is (eq t (%aval "active" d)))
        (is (equal '(0 2) (%aval "range" d)))
        (is (= 0 (%aval "next_index" d)))
        ;; normalized public form: origin + xpub, no private material
        (is (search "[" (%aval "desc" d)))
        (is (not (search "tprv" (%aval "desc" d)))))
      (is (= 4 (count t descs :key (lambda (d) (%aval "internal" d)))))
      ;; private=true shows master tprvs
      (let ((priv-descs (%aval "descriptors"
                               (bl.wallet::rpc-listdescriptors
                                node '(t)))))
        (is (= 8 (length priv-descs)))
        (dolist (d priv-descs)
          (is (search "tprv" (%aval "desc" d))))))
    ;; watch-only wallet rejects private=true
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("ldwo" t)))
    (with-rpc-wallet ("ldwo")
      (is (= bl.rpc:+rpc-wallet-error+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-listdescriptors node '(t)))))))))

(test wallet-importdescriptors-validation
  "importdescriptors returns Core-shaped per-request results: checksum
required, watch-only rules, label/range constraints; a missing timestamp
throws out of the whole call."
  (with-wallet-test-node (node :keypool 3)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("imp"))     ; privkeys enabled
      (bl.wallet::rpc-createwallet node '("impwo" t t))) ; watch-only blank
    (with-rpc-wallet ("imp")
      ;; missing timestamp -> whole-RPC type error
      (is (= bl.rpc:+rpc-type-error+
             (rpc-error-code-of
              (lambda ()
                (bl.wallet::rpc-importdescriptors
                 node (list (list (%ht "desc" "wpkh(x)"))))))))
      ;; missing checksum -> per-request failure with Core's parse error code
      (let* ((results (bl.wallet::rpc-importdescriptors
                       node (list (list (%ht "desc" "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
                                             "timestamp" 1))))
                      )
             (err (%aval "error" (first results))))
        (is (eq 'yason:false (%aval "success" (first results))))
        (is (= bl.rpc:+rpc-invalid-address-or-key+ (%aval "code" err)))
        (is (string= "Missing checksum" (%aval "message" err))))
      ;; watch-only descriptor into a privkey wallet -> per-request error
      (let* ((desc (bl.rpc:descriptor-add-checksum
                    "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"))
             (results (bl.wallet::rpc-importdescriptors
                       node (list (list (%ht "desc" desc "timestamp" 1)))))
             (err (%aval "error" (first results))))
        (is (= bl.rpc:+rpc-wallet-error+ (%aval "code" err)))
        (is (search "without private keys" (%aval "message" err)))))
    ;; watch-only wallet accepts public descriptors, stores + reports them
    (with-rpc-wallet ("impwo")
      (let* ((xpub "tpubD6NzVbkrYhZ4XqNGAWGWSzmxGWFwVjVTjZxh2fioKbVYi7Jx8fdbprVWsdW7mHwqjchBVas8TLZG4Xwuz4RKU4iaCqiCvoSkFCzQptqk5Y1")
             (desc (bl.rpc:descriptor-add-checksum
                    (format nil "wpkh(~A/0/*)" xpub)))
             (results (bl.wallet::rpc-importdescriptors
                       node (list (list (%ht "desc" desc "timestamp" "now"
                                             "active" t "range" 9))))))
        (is (eq t (%aval "success" (first results))))
        ;; the wallet can now hand out watch-only bech32 addresses
        (let ((address (bl.wallet::rpc-getnewaddress node '("" "bech32"))))
          (is (string= "tb1q" (subseq address 0 4))))
        ;; and listdescriptors shows it active
        (let ((descs (%aval "descriptors"
                            (bl.wallet::rpc-listdescriptors node nil))))
          (is (= 1 (length descs)))
          (is (eq t (%aval "active" (first descs))))
          (is (equal '(0 9) (%aval "range" (first descs))))))
      ;; importing a private key into the watch-only wallet fails
      (let* ((wif (bl.crypto:private-key-to-wif
                   (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 7)
                   :network :testnet3 :compressed t))
             (results (bl.wallet::rpc-importdescriptors
                       node (list (list (%ht "desc" (bl.rpc:descriptor-add-checksum
                                                     (format nil "wpkh(~A)" wif))
                                             "timestamp" 1)))))
             (err (%aval "error" (first results))))
        (is (= bl.rpc:+rpc-wallet-error+ (%aval "code" err)))
        (is (search "private keys disabled" (%aval "message" err)))))))

;;; --- Wallet P7: signmessage (rpc/signmessage.lisp) + received-by / keypoolrefill /
;;; simulaterawtransaction / listaddressgroupings (wallet-coins.lisp) ---

(defun %wt= (a b)
  "Two BTC amounts equal to sub-satoshi tolerance. Either may be an amount
TOKEN as an RPC emits it (BTC-AMOUNT decodes it) or a plain number."
  (< (abs (- (btc-amount a) (btc-amount b))) 1d-6))

(defun %wt-at-height (wallet height)
  "Put WALLET's chain view at HEIGHT, so a transaction confirmed at HEIGHT has
depth 1. Six tests in this file set the same slot; one reach between them."
  (setf (bl.wallet::wallet-last-block-height wallet) height))

(defun %wt-dummy-txid (n)
  "A distinct non-zero 32-byte outpoint hash (so it never reads as coinbase)."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element n)))
    (setf (aref h 0) (logior 1 n))
    h))

(defun %wt-add-confirmed-tx (wallet inputs outputs &key (height 100))
  "Build and AddToWallet a confirmed tx. INPUTS: ((hash . vout) ...) prevouts;
OUTPUTS: ((script . value-sats) ...). Returns the tx's txid."
  (%wt-add-confirmed-tx-object wallet (%wt-confirmed-tx inputs outputs)
                              :height height))

(defun %wt-add-confirmed-tx-object (wallet tx &key (height 100))
  "AddToWallet TX as confirmed at HEIGHT. Returns its txid. Split out of
%WT-ADD-CONFIRMED-TX so a test that cares about the ORDER transactions reach
the wallet in can build them first and choose."
  (let ((block-hash (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 9)))
    (bl.wallet::wallet-add-to-wallet
     wallet tx (list :confirmed block-hash height 0))
    (bl.ser:transaction-hash tx)))

(defun %wt-confirmed-tx (inputs outputs)
  "The v2 transaction %WT-ADD-CONFIRMED-TX would add, unadded."
  (let* ((tx (bl.ser:make-transaction
              :version 2
              :inputs (coerce
                       (mapcar (lambda (in)
                                 (bl.ser:make-tx-in
                                  :previous-output
                                  (bl.ser:make-outpoint
                                   :hash (car in) :index (cdr in))
                                  :script-sig (make-array 0 :element-type
                                                          '(unsigned-byte 8))
                                  :sequence #xffffffff))
                               inputs)
                       'simple-vector)
              :outputs (coerce
                        (mapcar (lambda (out)
                                  (bl.ser:make-tx-out
                                   :value (cdr out) :script-pubkey (car out)))
                                outputs)
                        'simple-vector)
              :lock-time 0)))
    tx))

(defun %wt-raw-tx-hex (inputs outputs)
  "Wire hex of a v2 tx over INPUTS ((hash . vout) ...) and OUTPUTS
((script . value) ...)."
  (let ((tx (bl.ser:make-transaction
             :version 2
             :inputs (coerce
                      (mapcar (lambda (in)
                                (bl.ser:make-tx-in
                                 :previous-output
                                 (bl.ser:make-outpoint
                                  :hash (car in) :index (cdr in))
                                 :script-sig (make-array 0 :element-type
                                                         '(unsigned-byte 8))
                                 :sequence #xffffffff))
                              inputs)
                      'simple-vector)
             :outputs (coerce
                       (mapcar (lambda (out)
                                 (bl.ser:make-tx-out
                                  :value (cdr out) :script-pubkey (car out)))
                               outputs)
                       'simple-vector)
             :lock-time 0)))
    (bl.crypto:bytes-to-hex
     (bl.ser:transaction-wire-bytes tx))))

(test wallet-signmessage-roundtrip
  "signmessage on a legacy (P2PKH) getnewaddress verifies true via
verifymessage; a tampered message verifies false; a valid non-P2PKH (bech32)
address is -3, an undecodable address -5, and a foreign P2PKH address the
wallet does not own -4 (Core wallet/rpc/signmessage.cpp error codes)."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("signer")))
    (let* ((bl.wallet::*rpc-wallet-name* "signer")
           (address (bl.wallet::rpc-getnewaddress node '("" "legacy")))
           (message "hello from bitcoin-lisp")
           (sig (bl.wallet::rpc-signmessage node (list address message))))
      (is (stringp sig))
      ;; Round-trips through verifymessage.
      (is (eq t (bl.rpc::rpc-verifymessage
                 node (list address sig message))))
      ;; A tampered message no longer verifies.
      (is (eq 'yason:false
              (bl.rpc::rpc-verifymessage
               node (list address sig "a different message"))))
      ;; Valid bech32 address (not a key hash) -> -3.
      (let ((bech32 (bl.wallet::rpc-getnewaddress node '("" "bech32"))))
        (is (= bl.rpc:+rpc-type-error+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-signmessage
                            node (list bech32 message)))))))
      ;; Garbage address -> -5.
      (is (= bl.rpc:+rpc-invalid-address-or-key+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-signmessage
                          node (list "not-a-real-address" message))))))
      ;; A valid P2PKH address the wallet does not own -> -4.
      (let ((foreign (bl.crypto:encode-p2pkh-address
                      (make-array 20 :element-type '(unsigned-byte 8)
                                     :initial-element 7)
                      :testnet4)))
        (is (= bl.rpc:+rpc-wallet-error+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-signmessage
                            node (list foreign message))))))))))

(test setwalletflag-changes-only-the-mutable-flag
  "Core setwalletflag (wallet/rpc/wallet.cpp:300-345). Only avoid_reuse is
mutable; the rest record how the wallet was BUILT and cannot be retrofitted, so
Core refuses them BY NAME rather than ignoring the request.

The persistence half is what makes this more than a getter: a flag that lived
only in memory would come back on the next load, which for avoid_reuse means
silently resuming address reuse."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("flags")))
    (let* ((bl.wallet::*rpc-wallet-name* "flags")
           (manager (%node-manager node))
           (wallet (loaded-wallet manager "flags")))
      ;; Setting it on: Core's exact result shape, including the caveat.
      (let ((r (bl.wallet::rpc-setwalletflag node '("avoid_reuse"))))
        (is (equal "avoid_reuse" (cdr (assoc "flag_name" r :test #'string=))))
        (is (eq t (cdr (assoc "flag_state" r :test #'string=))))
        (is (search "rescan the blockchain"
                    (or (cdr (assoc "warnings" r :test #'string=)) ""))
            "the avoid_reuse caveat was not reported"))
      (is-true (bl.wallet::wallet-flag-set-p
                wallet bl.wallet::+wallet-flag-avoid-reuse+))
      ;; Setting it to the value it already holds is an error, not a no-op:
      ;; the caller has misunderstood the state.
      (is (= bl.rpc:+rpc-invalid-parameter+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-setwalletflag node '("avoid_reuse"))))))
      ;; Off again, and no caveat this time (Core reports it only when SETTING).
      (let ((r (bl.wallet::rpc-setwalletflag
                node (list "avoid_reuse" bl.rpc:+json-false+))))
        (is (eq bl.rpc:+json-false+
                (cdr (assoc "flag_state" r :test #'string=))))
        (is-false (assoc "warnings" r :test #'string=)))
      (is-false (bl.wallet::wallet-flag-set-p
                 wallet bl.wallet::+wallet-flag-avoid-reuse+))
      ;; An immutable flag is refused by name; an unknown one likewise.
      (dolist (immutable '("blank" "descriptor_wallet" "disable_private_keys"
                           "key_origin_metadata"))
        (is (= bl.rpc:+rpc-invalid-parameter+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-setwalletflag node (list immutable)))))
            "~A was not refused as immutable" immutable))
      (is (= bl.rpc:+rpc-invalid-parameter+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-setwalletflag node '("no_such_flag"))))))
      ;; And it PERSISTED: the flag word is on disk, not just in the struct.
      (bl.wallet::rpc-setwalletflag node '("avoid_reuse"))
      (is-true (bl.wallet::wallet-flag-set-p
                wallet bl.wallet::+wallet-flag-avoid-reuse+))
      (let ((stored (bl.store:leveldb-get
                     (bl.wallet::wallet-db wallet)
                     (bl.wallet::wdb-key-simple bl.wallet::+wdb-key-flags+))))
        (is-true stored "the flag word was never written")))))

(test createwalletdescriptor-adds-only-what-is-missing
  "Core createwalletdescriptor (wallet/rpc/wallet.cpp:745-836). A fresh wallet
already has all four address types on both sides, so the interesting case is
the one Core makes an ERROR: asking for a descriptor that exists must not
silently succeed, or an operator would believe they had added something.

The descriptor is built through the SAME path wallet creation uses, so the
derivation paths cannot drift between the two."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("cwd")))
    (let* ((bl.wallet::*rpc-wallet-name* "cwd")
           (manager (%node-manager node))
           (wallet (loaded-wallet manager "cwd")))
      ;; Everything already exists on a freshly created wallet.
      (is (= bl.rpc:+rpc-wallet-error+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-createwalletdescriptor node '("bech32m"))))))
      ;; An unknown address type is refused by name.
      (is (= bl.rpc:+rpc-invalid-address-or-key+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-createwalletdescriptor node '("nosuchtype"))))))
      ;; Now remove one side and re-create it: the real path.
      (let* ((removed (gethash :bech32m (bl.wallet::wallet-internal-spkms wallet)))
             (id (and removed (bl.wallet::desc-spkm-id removed))))
        (is-true removed "fixture: the wallet should have an internal bech32m spkm")
        (remhash :bech32m (bl.wallet::wallet-internal-spkms wallet))
        (remhash id (bl.wallet::wallet-spkms wallet))
        (let* ((opts (let ((h (make-hash-table :test 'equal)))
                       (setf (gethash "internal" h) t) h))
               (r (bl.wallet::rpc-createwalletdescriptor
                   node (list "bech32m" opts)))
               (descs (cdr (assoc "descs" r :test #'string=))))
          (is (= 1 (length descs)) "expected exactly one descriptor, got ~S" descs)
          ;; It is the CHANGE descriptor (/1/*), not the external one — the
          ;; internal option is what decides, and getting it backwards would
          ;; silently make change addresses the wallet hands out publicly.
          (is (search "/1/*" (first descs))
              "internal=true produced ~S, which is not a change descriptor"
              (first descs))
          (is-true (gethash :bech32m (bl.wallet::wallet-internal-spkms wallet))
                   "the new descriptor was not activated")))
      ;; A malformed hdkey is refused rather than silently falling back to the
      ;; wallet's own root — which would create a descriptor for a key the
      ;; caller did not ask for.
      (let ((opts (let ((h (make-hash-table :test 'equal)))
                    (setf (gethash "hdkey" h) "not-an-xpub") h)))
        (is (= bl.rpc:+rpc-invalid-address-or-key+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-createwalletdescriptor
                            node (list "bech32" opts))))))))))

(test createwalletdescriptor-takes-the-private-half-from-the-wallet
  "Core createwalletdescriptor asks the WALLET for the private half of the
hdkey it was given (wallet/rpc/wallet.cpp:795-813: DecodeExtPubKey, then
CWallet::GetKey(xpub.pubkey.GetID()), wallet.cpp:4519-4532). Three answers
follow from that and all three are Core's own:

  - the wallet's OWN xpub, for a type it already has, is -4 \"Descriptor
    already exists\" (wallet_createwalletdescriptor.py:93). Reading the
    privateness of the PARSED STRING instead answered -5 \"Private key for
    <xpub> is not known\" for every xpub, since an xpub has no private half by
    construction -- the wallet does;
  - an XPRV is not an xpub: DecodeExtPubKey reads the public prefix alone, so
    it is -5 \"Unable to parse HD key. Please provide a valid xpub\" (:94);
  - an xpub whose secret the wallet does not hold keeps -5 \"Private key for
    <xpub> is not known\" (:42), the control that the message did not merely
    move. It has to be an xpub of THIS chain: DecodeExtPubKey compares the
    prefix with Params()'s (key_io.cpp:249-252), so another chain's key never
    reaches CWallet::GetKey at all and is the parse refusal above."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.rpc:dispatch-rpc-method node "createwallet" (wire-params '("cwd-hdkey"))))
    (with-rpc-wallet ("cwd-hdkey")
      (let* ((rows (bl.rpc:dispatch-rpc-method
                    node "gethdkeys"
                    (wire-params (list (let ((h (make-hash-table :test 'equal)))
                                         (setf (gethash "private" h) t) h)))))
             (row (first rows))
             (own-xpub (cdr (assoc "xpub" row :test #'string=)))
             (own-xprv (cdr (assoc "xprv" row :test #'string=))))
        (is (stringp own-xpub) "fixture: gethdkeys reported no xpub")
        (is (stringp own-xprv) "fixture: gethdkeys reported no xprv")
        (flet ((answer (type key)
                 (rpc-error-of
                  (lambda ()
                    (bl.rpc:dispatch-rpc-method
                     node "createwalletdescriptor"
                     (wire-params
                      (list type (let ((h (make-hash-table :test 'equal)))
                                   (setf (gethash "hdkey" h) key) h))))))))
          ;; The wallet's own root, for a type it already has.
          (is (equal (cons bl.rpc:+rpc-wallet-error+ "Descriptor already exists")
                     (answer "bech32m" own-xpub)))
          ;; An xprv where an xpub is wanted.
          (is (equal (cons bl.rpc:+rpc-invalid-address-or-key+
                           "Unable to parse HD key. Please provide a valid xpub")
                     (answer "bech32m" own-xprv)))
          ;; A well-formed xpub of THIS chain that the wallet holds no secret
          ;; for: BIP32's own test-vector-1 seed, so nothing in the fixture
          ;; (whose keys come from the wallet's RNG) can have it.
          (let ((foreign (bl.crypto:bip32-serialize
                          (bl.crypto:bip32-neuter
                           (bl.crypto:bip32-master-key
                            (bl.crypto:hex-to-bytes "000102030405060708090a0b0c0d0e0f")
                            :network :testnet4)))))
            (is (equal (cons bl.rpc:+rpc-invalid-address-or-key+
                             (format nil "Private key for ~A is not known" foreign))
                       (answer "bech32m" foreign))))
          ;; ANOTHER chain's xpub -- BIP32 vector 1's mainnet master, on a
          ;; testnet4 wallet -- is not an extended key here at all, so it is
          ;; the parse refusal and never reaches CWallet::GetKey.
          (is (equal (cons bl.rpc:+rpc-invalid-address-or-key+
                           "Unable to parse HD key. Please provide a valid xpub")
                     (answer "bech32m"
                             "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"))))))))

(test gethdkeys-groups-descriptors-under-their-root-key
  "Core gethdkeys. The grouping is the point: two descriptors derived from one
HD root must appear as ONE entry with two descriptors, not two entries — that
is what tells an operator which key their wallet actually depends on."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("hd")))
    (with-rpc-wallet ("hd")
      (let ((rows (bl.wallet::rpc-gethdkeys node nil)))
        (is (plusp (length rows)) "a fresh descriptor wallet reported no HD keys")
        ;; A freshly created wallet derives every descriptor from ONE seed, so
        ;; there is exactly one root and every descriptor hangs off it.
        (is (= 1 (length rows))
            "~D roots reported for a single-seed wallet" (length rows))
        (let* ((row (first rows))
               (xpub (cdr (assoc "xpub" row :test #'string=)))
               (descs (cdr (assoc "descriptors" row :test #'string=))))
          (is (and (stringp xpub) (plusp (length xpub))))
          (is (> (length descs) 1)
              "only ~D descriptor(s) grouped under the root" (length descs))
          (is (eq t (cdr (assoc "has_private" row :test #'string=))))
          ;; No xprv unless asked for.
          (is-false (assoc "xprv" row :test #'string=)))
        ;; private=true yields the xprv.
        (let* ((opts (let ((h (make-hash-table :test 'equal)))
                       (setf (gethash "private" h) t) h))
               (priv (first (bl.wallet::rpc-gethdkeys node (list opts)))))
          (is-true (assoc "xprv" priv :test #'string=)
                   "private=true did not return the extended private key"))
        ;; active_only excludes nothing here (every descriptor is active), but
        ;; the option must at least be accepted and not change the root count.
        (let* ((opts (let ((h (make-hash-table :test 'equal)))
                       (setf (gethash "active_only" h) t) h))
               (active (bl.wallet::rpc-gethdkeys node (list opts))))
          (is (= 1 (length active))))))))

(test importdescriptors-reads-the-label-before-it-parses-the-descriptor
  "Core wallet/rpc/backup.cpp:147-157 ProcessDescriptorImport reads the desc
STRING, then active, then LabelFromValue(data[\"label\"]), and only then
calls Parse(descriptor, keys, error, /*require_checksum=*/true). The order
decides which error a doubly-invalid request is given, and
wallet_labels.py:40-48 asserts exactly that pair: a request whose label is
\"*\" AND whose descriptor carries no checksum answers -11 \"Invalid label
name\", not the parse error.

Ours bound the parsed descriptor first, so the same request answered -5
\"Missing checksum\". Both single faults keep their own answer."
  (with-wallet-test-node (node :keypool 3)
    (with-rpc-wallet (nil)
      (bl.rpc:dispatch-rpc-method node "createwallet" '("lbl")))
    (with-rpc-wallet ("lbl")
      (let ((bare "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"))
        ;; wallet_labels.py:40-48: no checksum AND label "*".
        (let ((err (%aval "error"
                          (first (bl.rpc:dispatch-rpc-method
                                  node "importdescriptors" (list (list (%ht "desc" bare
                                                        "label" "*"
                                                        "timestamp" "now"))))))))
          (is (= -11 (%aval "code" err))
              "a \"*\" label with an unchecksummed descriptor answered ~D"
              (%aval "code" err))
          (is (string= "Invalid label name" (%aval "message" err))))
        ;; A well-formed descriptor with the same label: still -11.
        (let ((err (%aval "error"
                          (first (bl.rpc:dispatch-rpc-method
                                  node "importdescriptors" (list (list (%ht "desc" (bl.rpc:descriptor-add-checksum bare)
                                                        "label" "*"
                                                        "timestamp" "now"))))))))
          (is (= -11 (%aval "code" err)))
          (is (string= "Invalid label name" (%aval "message" err))))
        ;; No label, no checksum: the parse error is still the answer.
        (let ((err (%aval "error"
                          (first (bl.rpc:dispatch-rpc-method
                                  node "importdescriptors" (list (list (%ht "desc" bare
                                                        "timestamp" "now"))))))))
          (is (= bl.rpc:+rpc-invalid-address-or-key+ (%aval "code" err)))
          (is (string= "Missing checksum" (%aval "message" err))))))))

(test gethdkeys-ignores-a-key-expression-with-no-extended-key
  "Core wallet/rpc/wallet.cpp:701-704: gethdkeys asks the descriptor for
GetPubKeys(desc_pubkeys, desc_xpubs) and then iterates the XPUBS only, so a
key expression that is a raw pubkey or a WIF key contributes nothing at all.

Every functional test's default wallet carries exactly such a descriptor:
the framework imports combo(<WIF>) into it at setup
(test/functional/test_framework/util.py:740-748, called from
test_framework.py:411), and that SPKM is inactive, so only a gethdkeys
WITHOUT active_only reaches it. Ours asked such a key for its root xprv,
which hashed a NIL extended key, and both wallet_gethdkeys.py:94 and
wallet_createwalletdescriptor.py:34 answered -32603 Internal error.

wallet_gethdkeys.py:107-114 is the other half: a wallet holding ONLY a
WIF-key descriptor reports no HD keys, rather than reporting one or
erroring."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.rpc:dispatch-rpc-method node "createwallet" '("hd")))
    (with-rpc-wallet ("hd")
      (let ((rows (bl.rpc:dispatch-rpc-method node "gethdkeys" nil)))
        (is (= 1 (length rows))
            "~D roots before the combo() import" (length rows)))
      ;; The framework's coinbase import, verbatim in shape.
      (let ((results (bl.rpc:dispatch-rpc-method
                      node "importdescriptors" (list (list (%ht "desc" (bl.rpc:descriptor-add-checksum
                                                    (format nil "combo(~A)" (regtest-wif 9)))
                                            "timestamp" 0
                                            "label" "coinbase"))))))
        (is (eq t (%aval "success" (first results)))
            "the combo(WIF) import failed, so the case under test never arose"))
      (let ((rows (bl.rpc:dispatch-rpc-method node "gethdkeys" nil)))
        (is (= 1 (length rows))
            "~D roots after importing a WIF-key descriptor" (length rows))
        (is (every (lambda (row)
                     (let ((xpub (cdr (assoc "xpub" row :test #'string=))))
                       (and (stringp xpub) (plusp (length xpub)))))
                   rows)
            "a row without an xpub came back")))
    ;; A wallet whose only descriptor is a WIF key has no HD key at all.
    (with-rpc-wallet (nil)
      (bl.rpc:dispatch-rpc-method node "createwallet" (list "lonekey" nil t)))
    (with-rpc-wallet ("lonekey")
      (let ((results (bl.rpc:dispatch-rpc-method
                      node "importdescriptors" (list (list (%ht "desc" (bl.rpc:descriptor-add-checksum
                                                    (format nil "wpkh(~A)" (regtest-wif 11)))
                                            "timestamp" 0))))))
        (is (eq t (%aval "success" (first results)))))
      (is (zerop (length (bl.rpc:dispatch-rpc-method node "gethdkeys" nil)))
          "a WIF-only wallet reported an HD key"))))

(test walletnotify-runs-on-every-add-to-wallet
  "-walletnotify (Core wallet.cpp:1125-1150). Asserted through the FILE the
hook creates, and specifically on a RE-ADD of the same transaction in the same
state: Core's hook sits OUTSIDE the inserted-or-updated branch, so a wallet tx
seen again still notifies, and a test that only added once would pass against a
hook wired inside the branch."
  (let ((dir (merge-pathnames (format nil "bl-wn-~D/" (get-internal-real-time))
                              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           (with-wallet-test-node (node :keypool 4)
             (with-rpc-wallet (nil)
               (bl.wallet::rpc-createwallet node '("notif")))
             (let* ((manager (%node-manager node))
                    (wallet (loaded-wallet manager "notif"))
                    (bl.wallet::*rpc-wallet-name* "notif")
                    (bl.wallet:*wallet-notify-command*
                      ;; %w and %h prove the placeholders beyond %s reach the
                      ;; command line; %b would be the block hash, which is
                      ;; the file name below.
                      (format nil "touch ~A%w-%h-%b" (namestring dir))))
               (%wt-at-height wallet 100)
               (let* ((addr (bl.wallet::rpc-getnewaddress
                             node '("" "legacy")))
                      (script (%address-script addr :testnet4))
                      ;; The confirming block hash %wt-add-confirmed-tx uses.
                      (expected (merge-pathnames
                                 (format nil "notif-100-~A"
                                         (bl.rpc:hash-to-hex
                                          (make-array 32 :element-type
                                                         '(unsigned-byte 8)
                                                      :initial-element 9)))
                                 dir)))
                 (%wt-add-confirmed-tx wallet (list (cons (%wt-dummy-txid 1) 0))
                                       (list (cons script 500000)))
                 ;; Detached, as Core's is ("thread runs free") — poll.
                 (loop repeat 100
                       until (probe-file expected)
                       do (sleep 0.05))
                 (is-true (probe-file expected)
                          "-walletnotify did not run for a new wallet tx")
                 (ignore-errors (delete-file expected))
                 ;; Re-add the SAME tx in the SAME state: nothing is inserted
                 ;; or updated, and Core notifies anyway.
                 (%wt-add-confirmed-tx wallet (list (cons (%wt-dummy-txid 1) 0))
                                       (list (cons script 500000)))
                 (loop repeat 100
                       until (probe-file expected)
                       do (sleep 0.05))
                 (is-true (probe-file expected)
                          "-walletnotify did not run for a re-added wallet tx")))))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore))))
  ;; A command with an unsafe wallet name can never be built, because a name
  ;; carrying a path separator cannot exist in the first place.
  ;;
  ;; Core's own rule: on anything but Windows only `/' is disallowed
  ;; (feature_notifications.py:24), and that test builds a wallet name out of
  ;; every remaining byte from 1 to 127 -- backslash, quotes and control
  ;; characters included -- then creates the wallet with it.
  ;; A name carrying a Lisp namestring wildcard must reach the filesystem as
  ;; itself. `*', `?', `[' and `]' are pattern syntax when a namestring is
  ;; PARSED, so building the wallet directory by concatenating the name into a
  ;; string made a WILD pathname out of `w*t' and refused `a[b' outright with
  ;; "parse error in namestring: #\[ with no corresponding #\]" -- an RPC -32603
  ;; from createwallet, which is where feature_notifications.py:85 stopped.
  (let ((manager (bl.wallet::make-wallet-manager :data-directory #p"/tmp/wdtest/"))
        (bl.wallet:*wallet-directory* "/tmp/wdtest/wallets/"))
    (dolist (name '("a[b]c" "star*" "quest?" "plain"))
      (let ((directory (bl.wallet::wallet-directory manager name)))
        (is (equal name (first (last (pathname-directory directory))))
            "~S must be one literal directory component" name)
        (is-false (wild-pathname-p directory)
                  "~S must not produce a wild pathname" name)
        ;; And the sentence an RPC prints is the name the caller passed, not
        ;; NAMESTRING's re-readable escaping of it.
        (is (equal (format nil "/tmp/wdtest/wallets/~A" name)
                   (bl.wallet::wallet-path-string directory))
            "~S must print unescaped" name))))
  (flet ((accepted-p (name) (and (bl.wallet::%valid-wallet-name-p name) t)))
    ;; A trailing `/' is a relative path Core accepts (the directory
    ;; `a;rm -rf '); what -walletnotify's %w then carries is the notify
    ;; layer's shell-safety check's business, as ShellEscape is Core's
    ;; (wallet.cpp:1146). A LEADING `/' is absolute and refused.
    (is-true (accepted-p "a;rm -rf /"))
    (is-false (accepted-p "/a;rm -rf"))
    (is-true (accepted-p (coerce (loop for i from 1 below 128
                                       unless (= i (char-code #\/))
                                         collect (code-char i))
                                 'string))
             "the name feature_notifications.py creates must be accepted")
    (is-true (accepted-p "back\\slash")
             "a backslash is an ordinary filename character off Windows")
    ;; The containment rule itself still holds.
    (is-false (accepted-p "../evil"))
    (is-false (accepted-p ".."))
    (is-false (accepted-p "")))
  (dolist (name '("walletnotify"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test listreceivedbyaddress-orders-its-txids-by-txid-not-by-arrival
  "Core's mapWallet is std::unordered_map<Txid, CWalletTx, SaltedTxidHasher>
(wallet/wallet.h:498) and ListReceived walks it as it stands
(wallet/rpc/coins.cpp:58, `for (const auto& [_, wtx] : wallet.mapWallet)'),
so the txids of one address come back in an order derived from the TXID and
a per-process salt -- never in the order the transactions arrived.

wallet_resendwallettransactions.py:97-117 depends on exactly that. It bumps
a child transaction in a loop until listreceivedbyaddress reports the child
BEFORE its parent, saying so at :82-89 (\"We cannot predict the position in
mapWallet, but we can observe it\"), and each bump gives the child a fresh
txid, so Core converges in a couple of rounds. Ours walked the table in
ARRIVAL order, where the newest child is always last, so the loop could
never converge: it ground on for 1,470 bumps until one replacement finally
failed the feerate-diagram test, and the -26 the test then saw
(\"replacement-failed\") was not the one it was written to tolerate.

Ours orders by the txid itself, which is deterministic where Core's salt is
not -- what matters is that it varies with the transaction rather than with
when it was seen. The two transactions below are added in DESCENDING txid
order, so arrival order and txid order cannot agree by luck."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.rpc:dispatch-rpc-method node "createwallet" '("ord")))
    (let* ((manager (%node-manager node))
           (wallet (loaded-wallet manager "ord")))
      (%wt-at-height wallet 100)
      (with-rpc-wallet ("ord")
        (let* ((addr (bl.rpc:dispatch-rpc-method node "getnewaddress" '("" "legacy")))
               (script (%address-script addr :testnet4))
               (one (%wt-confirmed-tx (list (cons (%wt-dummy-txid 1) 0))
                                      (list (cons script 500000))))
               (two (%wt-confirmed-tx (list (cons (%wt-dummy-txid 2) 0))
                                      (list (cons script 300000))))
               (by-txid (sort (list one two) #'string<
                              :key (lambda (tx) (bl.rpc:hash-to-hex
                                                 (bl.ser:transaction-hash tx))))))
          ;; Newest-first arrival: the LAST transaction by txid arrives first.
          (dolist (tx (reverse by-txid))
            (%wt-add-confirmed-tx-object wallet tx))
          (let ((txids (%aval "txids"
                              (find addr (bl.rpc:dispatch-rpc-method
                                          node "listreceivedbyaddress" nil)
                                    :key (lambda (r) (%aval "address" r))
                                    :test #'string=))))
            (is (= 2 (length txids)))
            (is (equal txids (mapcar (lambda (tx)
                                       (bl.rpc:hash-to-hex
                                        (bl.ser:transaction-hash tx)))
                                     by-txid))
                "the txids came back in arrival order, not txid order: ~S"
                txids)))))))

(test wallet-received-by-rpcs
  "getreceivedbyaddress/bylabel and listreceivedbyaddress/bylabel tally owned
outputs over mapWallet; unknown address -> -4, garbage -> -5, unknown label
-> -4."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("recv")))
    (let* ((manager (%node-manager node))
           (wallet (loaded-wallet manager "recv"))
           (bl.wallet::*rpc-wallet-name* "recv"))
      (%wt-at-height wallet 100)
      (let* ((addr (bl.wallet::rpc-getnewaddress node '("" "legacy")))
             (script (%address-script addr :testnet4)))
        (bl.wallet::rpc-setlabel node (list addr "L1"))
        ;; Two confirmed receives to the same address: 0.005 + 0.003 BTC.
        (%wt-add-confirmed-tx wallet (list (cons (%wt-dummy-txid 1) 0))
                              (list (cons script 500000)))
        (%wt-add-confirmed-tx wallet (list (cons (%wt-dummy-txid 2) 0))
                              (list (cons script 300000)))
        (is (%wt= 0.008d0 (bl.wallet::rpc-getreceivedbyaddress
                           node (list addr))))
        (is (%wt= 0.008d0 (bl.wallet::rpc-getreceivedbylabel
                           node (list "L1"))))
        ;; minconf 200 excludes the depth-1 receives.
        (is (%wt= 0.0d0 (bl.wallet::rpc-getreceivedbyaddress
                         node (list addr 200))))
        ;; listreceivedbyaddress: one row for addr with both txids.
        (let* ((rows (bl.wallet::rpc-listreceivedbyaddress node nil))
               (row (find addr rows :key (lambda (r) (%aval "address" r))
                                    :test #'string=)))
          (is (not (null row)))
          (is (%wt= 0.008d0 (%aval "amount" row)))
          (is (string= "L1" (%aval "label" row)))
          (is (= 1 (%aval "confirmations" row)))
          (is (= 2 (length (%aval "txids" row)))))
        ;; listreceivedbylabel: one row for L1.
        (let* ((rows (bl.wallet::rpc-listreceivedbylabel node nil))
               (row (find "L1" rows :key (lambda (r) (%aval "label" r))
                                    :test #'string=)))
          (is (not (null row)))
          (is (%wt= 0.008d0 (%aval "amount" row))))
        ;; Error codes.
        (let ((foreign (bl.crypto:encode-p2pkh-address
                        (make-array 20 :element-type '(unsigned-byte 8)
                                       :initial-element 3)
                        :testnet4)))
          (is (= bl.rpc:+rpc-wallet-error+
                 (rpc-error-code-of
                  (lambda () (bl.wallet::rpc-getreceivedbyaddress
                              node (list foreign)))))))
        (is (= bl.rpc:+rpc-invalid-address-or-key+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-getreceivedbyaddress
                            node (list "garbage"))))))
        (is (= bl.rpc:+rpc-wallet-error+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-getreceivedbylabel
                            node (list "no-such-label"))))))))))

(test wallet-keypoolrefill-grows-active-spkms
  "keypoolrefill tops every active SPKM up to newsize; a negative size is -8."
  (with-wallet-test-node (node :keypool 5)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("kp")))
    (let* ((manager (%node-manager node))
           (wallet (loaded-wallet manager "kp"))
           (bl.wallet::*rpc-wallet-name* "kp")
           (spkm (gethash :bech32
                          (bl.wallet::wallet-external-spkms wallet))))
      (is (= 5 (bl.wallet::spkm-keypool-count spkm)))
      (is (null (bl.wallet::rpc-keypoolrefill node '(20))))
      (is (>= (bl.wallet::spkm-keypool-count spkm) 20))
      ;; Every active SPKM grew.
      (dolist (s (bl.wallet::%wallet-active-spkms wallet))
        (is (>= (bl.wallet::spkm-keypool-count s) 20)))
      (is (= bl.rpc:+rpc-invalid-parameter+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-keypoolrefill node '(-1)))))))))

(test wallet-simulaterawtransaction-balance-change
  "simulaterawtransaction reports +owned-output and -owned-input deltas, and
rejects a double-spend across the array.

The node carries a UTXO set holding the coins these transactions spend,
because simulaterawtransaction runs Core's findCoins over every input and
refuses one the chain does not have."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("sim")))
    (let* ((manager (%node-manager node))
           (wallet (loaded-wallet manager "sim"))
           (utxo-set (bl.store:make-utxo-set))
           (bl.wallet::*rpc-wallet-name* "sim"))
      (%wt-at-height wallet 100)
      (setf (bl:node-utxo-set node) utxo-set)
      (let* ((addr (bl.wallet::rpc-getnewaddress node '("" "bech32")))
             (script (%address-script addr :testnet4))
             (foreign (%address-script
                       (bl.crypto:encode-p2wpkh-address
                        (make-array 20 :element-type '(unsigned-byte 8)
                                       :initial-element 4)
                        :testnet4)
                       :testnet4)))
        ;; A pure receive to an owned script: +0.007.
        (bl.store:add-utxo utxo-set (%wt-dummy-txid 5) 0 900000 foreign 100
                           :coinbase nil)
        (let ((result (bl.wallet::rpc-simulaterawtransaction
                       node (list (list (%wt-raw-tx-hex
                                         (list (cons (%wt-dummy-txid 5) 0))
                                         (list (cons script 700000))))))))
          (is (%wt= 0.007d0 (%aval "balance_change" result))))
        ;; Fund an owned coin, then spend it to a foreign output: -0.01.
        (let ((funded (%wt-add-confirmed-tx
                       wallet (list (cons (%wt-dummy-txid 6) 0))
                       (list (cons script 1000000)))))
          (bl.store:add-utxo utxo-set funded 0 1000000 script 100
                             :coinbase nil)
          (let ((result (bl.wallet::rpc-simulaterawtransaction
                         node (list (list (%wt-raw-tx-hex
                                           (list (cons funded 0))
                                           (list (cons foreign 900000))))))))
            (is (%wt= -0.01d0 (%aval "balance_change" result))))
          ;; Two txs spending the same funded coin -> -8.
          (is (= bl.rpc:+rpc-invalid-parameter+
                 (rpc-error-code-of
                  (lambda ()
                    (bl.wallet::rpc-simulaterawtransaction
                     node (list (list (%wt-raw-tx-hex (list (cons funded 0))
                                                      (list (cons foreign 900000)))
                                      (%wt-raw-tx-hex (list (cons funded 0))
                                                      (list (cons foreign 800000)))))))))))))))

(test importdescriptors-sees-the-private-key-inside-a-musig
  "importdescriptors accepts a musig() descriptor one of whose PARTICIPANTS is
an xprv. A musig() key expression carries no secret of its own; Core parses
each participant with the SAME FlatSigningProvider the enclosing expression
was given (ParseMuSig -> ParsePubkey, descriptor.cpp), so the participant's
key lands in `keys' like any other and ProcessDescriptorImport's
`keys.keys.empty()' test passes (wallet/rpc/backup.cpp:259-262).

We collected the key material from the top-level key expressions alone, found
none inside a musig(), and answered -4 `Cannot import descriptor without
private keys to a wallet with private keys enabled' for every musig descriptor
a wallet could own (wallet_musig.py:89)."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.rpc:dispatch-rpc-method node "createwallet" '("musig")))
    (with-rpc-wallet ("musig")
      (let* ((tprv "tprv8ZgxMBicQKsPeZSeYx7VXDDTs3XrTcmZQpRLbAeSQFCQGgKwR4gKpcxHaKdoTNHniv4EPDJNdzA3KxRrrBHcAgth8fU5X4oCndkkxk39iAt")
             (tpub "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B")
             (desc (bl.rpc:descriptor-add-checksum
                    (format nil "rawtr(musig(~A/86h/1h/0h/0/*,[00000000/86h/1h/0h]~A/0/*))"
                            tprv tpub)))
             ;; Control: the same shape with BOTH participants public. Core
             ;; refuses that one, and for the same reason we used to refuse
             ;; both -- so it says the -4 arm still works.
             (watch (bl.rpc:descriptor-add-checksum
                     (format nil "rawtr(musig([00000000/86h/1h/0h]~A/0/*,[00000000/86h/1h/0h]~A/0/*))"
                             tpub tpub)))
             (result (first (bl.rpc:dispatch-rpc-method
                             node "importdescriptors"
                             (list (list (%ht "desc" desc
                                                   "timestamp" "now"
                                                   "active" nil
                                                   "range" 2)))))))
        (is (eq t (cdr (assoc "success" result :test #'string=)))
            "musig with an xprv participant: ~S"
            (cdr (assoc "error" result :test #'string=)))
        (let ((watch-result
                (first (bl.rpc:dispatch-rpc-method
                        node "importdescriptors"
                        (list (list (%ht "desc" watch
                                              "timestamp" "now"
                                              "active" nil
                                              "range" 2)))))))
          (is (eq 'yason:false
                  (cdr (assoc "success" watch-result :test #'string=)))
              "a musig with no private participant must still be refused")
          (is (= -4 (cdr (assoc "code"
                                (cdr (assoc "error" watch-result :test #'string=))
                                :test #'string=)))))))))

(test wallet-simulaterawtransaction-refuses-an-input-nothing-holds
  "simulaterawtransaction refuses an input that neither the chain nor an
earlier transaction in the array provides, with Core's -8 `One or more
transaction inputs are missing or have been spent already'. Core runs
chain().findCoins over each transaction's inputs and throws on an outpoint
whose coin IsSpent -- which includes one nothing knows at all
(wallet/rpc/wallet.cpp, simulaterawtransaction).

Ours computed the delta from the wallet's own view alone and answered a
NUMBER for a transaction spending an output that does not exist; the same
call with the creating transaction prepended has to keep working, which is
the whole point of the in-array new_utxos map (wallet_simulaterawtx.py:93)."
  (with-wallet-test-node (node :keypool 4)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("simmiss")))
    (let* ((manager (%node-manager node))
           (wallet (loaded-wallet manager "simmiss"))
           (utxo-set (bl.store:make-utxo-set))
           (bl.wallet::*rpc-wallet-name* "simmiss"))
      (%wt-at-height wallet 100)
      (setf (bl:node-utxo-set node) utxo-set)
      (let* ((addr (bl.wallet::rpc-getnewaddress node '("" "bech32")))
             (script (%address-script addr :testnet4))
             (foreign (%address-script
                       (bl.crypto:encode-p2wpkh-address
                        (make-array 20 :element-type '(unsigned-byte 8)
                                       :initial-element 7)
                        :testnet4)
                       :testnet4))
             ;; tx1 spends a real chain coin and pays the wallet.
             (chain-coin (%wt-dummy-txid 11)))
        (bl.store:add-utxo utxo-set chain-coin 0 1000000 foreign 100
                           :coinbase nil)
        (let* ((tx1-hex (%wt-raw-tx-hex (list (cons chain-coin 0))
                                        (list (cons script 900000))))
               (tx1-id (bl.ser:transaction-hash
                        (bl.rpc:decode-hex-tx tx1-hex)))
               ;; tx2 spends tx1's output, which is not on chain yet.
               (tx2-hex (%wt-raw-tx-hex (list (cons tx1-id 0))
                                        (list (cons foreign 800000)))))
          ;; Control: tx1 alone is fine -- its input IS on chain.
          (is (%wt= 0.009d0
                    (%aval "balance_change"
                           (bl.rpc:dispatch-rpc-method
                            node "simulaterawtransaction" (list (list tx1-hex))))))
          ;; tx2 on its own spends an output nothing holds.
          (signals-rpc-error
              (:code -8 :exact-message
               "One or more transaction inputs are missing or have been spent already")
            (bl.rpc:dispatch-rpc-method node "simulaterawtransaction"
                                        (list (list tx2-hex))))
          ;; With tx1 in front of it the output exists inside the array, and
          ;; the pair is accepted: 0.009 in, then 0.009 back out.
          (is (%wt= 0.0d0
                    (%aval "balance_change"
                           (bl.rpc:dispatch-rpc-method
                            node "simulaterawtransaction"
                            (list (list tx1-hex tx2-hex)))))))))))

(test wallet-listaddressgroupings-clusters
  "listaddressgroupings clusters addresses co-spent as inputs of one tx and
keeps an unrelated lone address in its own group."
  (with-wallet-test-node (node :keypool 5)
    (with-rpc-wallet (nil)
      (bl.wallet::rpc-createwallet node '("grp")))
    (let* ((manager (%node-manager node))
           (wallet (loaded-wallet manager "grp"))
           (bl.wallet::*rpc-wallet-name* "grp"))
      (%wt-at-height wallet 100)
      (let* ((addr1 (bl.wallet::rpc-getnewaddress node '("" "legacy")))
             (addr2 (bl.wallet::rpc-getnewaddress node '("" "legacy")))
             (addr3 (bl.wallet::rpc-getnewaddress node '("" "legacy")))
             (s1 (%address-script addr1 :testnet4))
             (s2 (%address-script addr2 :testnet4))
             (s3 (%address-script addr3 :testnet4))
             ;; tx A funds addr1 and addr2.
             (txa (%wt-add-confirmed-tx
                   wallet (list (cons (%wt-dummy-txid 8) 0))
                   (list (cons s1 400000) (cons s2 600000)))))
        ;; tx B co-spends addr1 and addr2, paying addr3 -> {addr1,addr2} cluster.
        (%wt-add-confirmed-tx wallet
                              (list (cons txa 0) (cons txa 1))
                              (list (cons s3 900000)))
        (let* ((groups (bl.wallet::rpc-listaddressgroupings node nil))
               (addr-of (lambda (info) (aref info 0)))
               (group-addrs (lambda (g) (mapcar addr-of g)))
               (g-with (lambda (addr)
                         (find-if (lambda (g)
                                    (member addr (funcall group-addrs g)
                                            :test #'string=))
                                  groups))))
          (is (>= (length groups) 2))
          ;; addr1 and addr2 land in one group.
          (let ((g1 (funcall g-with addr1)))
            (is (not (null g1)))
            (is (member addr2 (funcall group-addrs g1) :test #'string=))
            ;; each entry is a [address, amount, label] vector
            (is (every #'vectorp g1))
            (is (>= (length (first g1)) 2)))
          ;; addr3 is alone.
          (let ((g3 (funcall g-with addr3)))
            (is (not (null g3)))
            (is (= 1 (length g3)))
            (is (not (member addr1 (funcall group-addrs g3) :test #'string=)))))))))

;;; ==============================================================
;;; Wallet P5 — PSBT signer (walletprocesspsbt / walletcreatefundedpsbt) +
;;; RBF fee-bump (bumpfee / psbtbumpfee): hermetic regtest round-trips.
;;;
;;; wallet-tests.lisp loads BEFORE wallet-chain/spend-tests, so their
;;; with-wallet-chain-node / %ws-fund-wallet fixtures are not yet defined here;
;;; this section carries its own %pp-* equivalents built on the
;;; regtest-node-fixture + %with-regtest primitives (mining-tests.lisp).
;;; ==============================================================

(defvar *pp-counter* 0)

(defun %pp-optrue-address ()
  (bl.crypto:encode-p2sh-address
   (bl.crypto:hash160 +optrue-redeem+) :regtest))

(defun %pp-fixture (suffix &key (keypool 5))
  "A regtest node at genesis with a wallet manager + genesis block stored."
  (let* ((id (format nil "~A-~D-~D" suffix (get-universal-time) (incf *pp-counter*)))
         (node (regtest-node-fixture (format nil "pp-~A" id)))
         (wallet-dir (merge-pathnames (format nil "pp-wallet-~A/" id)
                                      (uiop:temporary-directory))))
    (bl.store:store-block
     (bl:node-block-store node)
     (bl.store:make-genesis-block :regtest))
    (setf (bl:node-wallet-manager node)
          (bl.wallet::make-wallet-manager
           :data-directory wallet-dir :network :regtest :keypool-size keypool))
    node))

(defmacro %with-pp-node ((node suffix) &body body)
  "BODY under regtest bindings with NODE a %pp-fixture and bl:*node*
bound so the wallet chain hooks fire."
  `(with-network (:regtest)
    (let* ((,node (%pp-fixture ,suffix))
           (bl:*node* ,node))
      (unwind-protect (progn ,@body)
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl:node-wallet-manager ,node)))))))

(defun %pp-mine (node n address)
  (bl.rpc:dispatch-rpc-method node "generatetoaddress"
                              (wire-params (list n address))))

(defun %pp-fund-wallet (node &key (blocks 1))
  "createwallet \"w\", mine BLOCKS coinbases to a fresh bech32 (P2WPKH) address,
mature them. Returns the wallet."
  (bl.wallet::rpc-createwallet node '("w"))
  (let* ((wallet (loaded-wallet (bl:node-wallet-manager node) "w"))
         (address (bl.wallet::rpc-getnewaddress node '("" "bech32"))))
    (dotimes (i blocks) (%pp-mine node 1 address))
    (%pp-mine node 101 (%pp-optrue-address))
    wallet))

(defun %pp-mempool-tx (node txid)
  (bl.rpc:with-node-lock (node)
    (let* ((mp (bl:node-mempool node))
           (e (and mp (bl.mp:mempool-get mp txid))))
      (and e (bl.mp:mempool-entry-transaction e)))))

(defun %pp-verify-ok-p (node wallet tx)
  (bl.rpc:with-node-lock (node)
    (bl.wallet::with-wallet-lock (wallet)
      (let ((coins (bl.wallet::%wallet-input-coins node wallet tx)))
        (nth-value 0 (bl.wallet::%verify-tx-scripts tx coins))))))

(defun %pp-input-outpoints (tx)
  (map 'list (lambda (in)
               (let ((op (bl.ser:tx-in-previous-output in)))
                 (cons (bl.ser:outpoint-hash op)
                       (bl.ser:outpoint-index op))))
       (bl.ser:transaction-inputs tx)))

(test pp-walletcreatefundedpsbt-roundtrip
  "walletcreatefundedpsbt funds an UNSIGNED PSBT (witness_utxo + bip32 derivs per
input, no sigs); walletprocesspsbt signs + finalizes it into a valid network tx
that our own script verifier accepts and the mempool relays."
  (%with-pp-node (node "pp-wcfp")
    (let ((wallet (%pp-fund-wallet node)))
      (let* ((bl.wallet::*wallet-rng* (make-wallet-rng 42))
             (dest (%pp-optrue-address))
             (created (bl.rpc:dispatch-rpc-method
                       node "walletcreatefundedpsbt"
                       (wire-params (list '() (list (%ht dest 1))
                                          0 (%ht "fee_rate" 5)))))
             (b64 (%aval "psbt" created)))
        (is (stringp b64))
        (is (> (%aval "fee" created) 0))
        ;; The created PSBT is unsigned: every input has a witness_utxo + bip32
        ;; derivation but no partial sigs and no final scripts.
        (let ((psbt (bl.ser:decode-psbt b64)))
          (is (> (length (bl.ser:psbt-inputs psbt)) 0))
          (loop for m across (bl.ser:psbt-inputs psbt)
                do (is-true (bl.ser:psbt-map-find
                             m bl.ser:+psbt-in-witness-utxo+))
                   (is-true (bl.ser:psbt-map-find
                             m bl.ser:+psbt-in-bip32+))
                   (is (null (bl.ser:psbt-map-collect
                              m bl.ser:+psbt-in-partial-sig+)))
                   (is (null (bl.ser:psbt-map-find
                              m bl.ser:+psbt-in-final-scriptsig+)))))
        ;; walletprocesspsbt (defaults: sign + finalize) completes it.
        (let* ((processed (bl.rpc:dispatch-rpc-method
                           node "walletprocesspsbt" (wire-params (list b64))))
               (hex (%aval "hex" processed)))
          (is (eq t (%aval "complete" processed)))
          (is (stringp hex))
          (let ((tx (bl.ser:parse-tx-payload
                     (bl.crypto:hex-to-bytes hex))))
            (is (%pp-verify-ok-p node wallet tx))
            ;; The extracted tx relays.
            (is (stringp (bl.rpc:dispatch-rpc-method
                          node "sendrawtransaction"
                          (wire-params (list hex)))))))))))

(test pp-walletprocesspsbt-is-idempotent-on-a-complete-psbt
  "Every FillPSBT loop Core runs SKIPS an input that is already signed --
CWallet::FillPSBT (wallet.cpp:2197-2198) and
DescriptorScriptPubKeyMan::FillPSBT (scriptpubkeyman.cpp:1318-1320) both open
with `if (PSBTInputSigned(input)) continue;', and PSBTInputSigned is the
presence of a final scriptSig or scriptWitness (psbt.cpp:320-323). So
processing an already-complete PSBT a second time changes nothing, which is
what rpc_psbt.py:780-782 asserts:

    complete_psbt = self.nodes[0].walletprocesspsbt(psbtx_info['psbt'])
    double_processed_psbt = self.nodes[0].walletprocesspsbt(complete_psbt['psbt'])
    assert_equal(complete_psbt, double_processed_psbt)

Our updater half ran over EVERY input. Finalizing drops an input's derivation
records -- Core's PSBTInput::FromSignatureData clears hd_keypaths on the
complete branch (psbt.cpp) and %PSBT-SET-FINAL does the same -- so the second
pass put a PSBT_IN_BIP32_DERIVATION back onto each finalized input and the two
results differed by exactly those records: a finalized input carrying updater
fields no signer will ever read.

The control is the first pass: it must still complete AND come back with the
derivations gone, so a change that simply stopped writing derivations at all
would fail there rather than pass here."
  (%with-pp-node (node "pp-twice")
    (%pp-fund-wallet node)
    (with-wallet-rng (7)
      (let* ((dest (%pp-optrue-address))
             (b64 (%aval "psbt"
                         (bl.rpc:dispatch-rpc-method
                          node "walletcreatefundedpsbt"
                          (wire-params (list '() (list (%ht dest 1))
                                             0 (%ht "fee_rate" 5))))))
             (once (bl.rpc:dispatch-rpc-method
                    node "walletprocesspsbt" (wire-params (list b64))))
             (twice (bl.rpc:dispatch-rpc-method
                     node "walletprocesspsbt"
                     (wire-params (list (%aval "psbt" once))))))
        (is (eq t (%aval "complete" once))
            "fixture: the first pass did not complete")
        ;; A finalized input keeps only its utxo and its final scripts.
        (loop for m across (bl.ser:psbt-inputs
                            (bl.ser:decode-psbt (%aval "psbt" once)))
              do (is (null (bl.ser:psbt-map-collect m bl.ser:+psbt-in-bip32+))
                     "a finalized input still carries a bip32 derivation"))
        (is (equal (%aval "psbt" once) (%aval "psbt" twice))
            "processing a complete PSBT again changed it")
        (is (equal (%aval "hex" once) (%aval "hex" twice)))
        (is (eq (%aval "complete" once) (%aval "complete" twice)))))))

(test pp-walletprocesspsbt-sign-false-then-sign
  "walletprocesspsbt with sign=false only fills data (no sigs, incomplete); a
second call with sign=true (default) completes it."
  (%with-pp-node (node "pp-signflag")
    (%pp-fund-wallet node)
    (let* ((bl.wallet::*wallet-rng* (make-wallet-rng 99))
           (dest (%pp-optrue-address))
           (b64 (%aval "psbt" (bl.rpc:dispatch-rpc-method
                               node "walletcreatefundedpsbt"
                               (wire-params
                                (list '() (list (%ht dest 1)) 0
                                      (%ht "fee_rate" 5))))))
           ;; sign=false, finalize=false: no partial sigs, incomplete.
           (unsigned (bl.rpc:dispatch-rpc-method
                      node "walletprocesspsbt"
                      (wire-params (list b64 bl.rpc:+json-false+ nil nil
                                         bl.rpc:+json-false+)))))
      (is (eq bl.rpc:+json-false+ (%aval "complete" unsigned)))
      (let ((psbt (bl.ser:decode-psbt (%aval "psbt" unsigned))))
        (loop for m across (bl.ser:psbt-inputs psbt)
              do (is (null (bl.ser:psbt-map-collect
                            m bl.ser:+psbt-in-partial-sig+)))))
      ;; Now sign (defaults) -> complete + extractable.
      (let ((signed (bl.rpc:dispatch-rpc-method
                     node "walletprocesspsbt"
                     (wire-params (list (%aval "psbt" unsigned))))))
        (is (eq t (%aval "complete" signed)))
        (is (stringp (%aval "hex" signed)))))))

(test walletprocesspsbt-signs-for-a-key-a-foreign-script-lists
  "Core's DescriptorScriptPubKeyMan::FillPSBT asks GetSigningProvider(script)
first, and when the wallet does NOT own the script it falls back on the input's
own key list -- \"Maybe there are pubkeys listed that we can sign for\"
(scriptpubkeyman.cpp:1340-1377): every PSBT_IN_BIP32_DERIVATION pubkey, plus a
taproot output key in both parities and the PSBT_IN_TAP_BIP32_DERIVATION keys,
is looked up in m_map_pubkeys (:1216-1233) and the provider for that index is
merged in. That fallback is the whole of multi-party signing: a cosigner's
wallet holds the KEY and never the multisig script.

We collected signing keys from the owning SPKM alone, so a wallet asked to
cosign a script it does not own signed nothing and walletprocesspsbt answered
complete false with no `hex'. wallet_fundrawtransaction.py:591 (a 2-of-2 whose
two keys the DEFAULT wallet holds, signed in one call) and
wallet_multisig_descriptor_psbt.py:123 (M participants signing in turn) both
end in KeyError 'hex' on that.

The watch-only wallet is the control: it holds the descriptor and no key, so
its own walletprocesspsbt must still leave the PSBT incomplete -- a change that
signed with any key in reach would fail there."
  (%with-pp-node (node "pp-cosign")
    (%pp-fund-wallet node)
    (let ((bl.wallet::*wallet-rng* (make-wallet-rng 31)))
      (flet ((rpc (wallet method &rest params)
               (with-rpc-wallet (wallet)
                 (bl.rpc:dispatch-rpc-method node method params))))
        (rpc "w" "keypoolrefill" 20)
        (let* ((a (rpc "w" "getnewaddress" "" "bech32"))
               (b (rpc "w" "getnewaddress" "" "bech32"))
               (pk-a (%aval "pubkey" (rpc "w" "getaddressinfo" a)))
               (pk-b (%aval "pubkey" (rpc "w" "getaddressinfo" b)))
               (msig (rpc "w" "createmultisig" 2 (list pk-a pk-b) "bech32"))
               (msig-address (%aval "address" msig))
               (msig-descriptor (%aval "descriptor" msig)))
          (is (stringp msig-address) "fixture: createmultisig gave no address")
          ;; The multisig is a script the signing wallet does NOT own.
          (is (equal bl.rpc:+json-false+
                     (%aval "ismine" (rpc "w" "getaddressinfo" msig-address)))
              "fixture: the signing wallet already owns the multisig script")
          (rpc "w" "sendtoaddress" msig-address "1.20000000"
               nil nil nil nil nil nil nil 10)
          (%pp-mine node 1 (%pp-optrue-address))
          ;; A watch-only wallet that knows the descriptor and no key.
          (rpc nil "createwallet" "wmulti" t)
          (rpc "wmulti" "importdescriptors"
               (list (%ht "desc" msig-descriptor "timestamp" "now")))
          (let* ((funded (rpc "wmulti" "walletcreatefundedpsbt"
                              '() (list (%ht (%pp-optrue-address) 1))
                              0 (%ht "fee_rate" 10
                                     "changeAddress" (rpc "w" "getrawchangeaddress" "bech32"))))
                 (psbt (%aval "psbt" funded)))
            (is (stringp psbt) "fixture: walletcreatefundedpsbt gave no psbt")
            ;; The control: another wallet, with keys of its own and none of
            ;; these, must sign nothing. The fallback looks up the input's
            ;; pubkeys in the SPKM's own map, so a wallet that derives none of
            ;; them has no business completing this.
            (rpc nil "createwallet" "other")
            (let ((stranger (rpc "other" "walletprocesspsbt" psbt)))
              (is (equal bl.rpc:+json-false+ (%aval "complete" stranger))
                  "a wallet holding neither key completed the 2-of-2")
              (is (null (%aval "hex" stranger))
                  "an incomplete PSBT must carry no network transaction"))
            ;; And the wallet that owns neither the script nor its descriptor,
            ;; only the two KEYS, signs it to completion.
            (let ((signed (rpc "w" "walletprocesspsbt" psbt)))
              (is (eq t (%aval "complete" signed))
                  "the key holder did not complete the 2-of-2")
              (is (stringp (%aval "hex" signed))
                  "a complete PSBT must carry the network transaction")
              ;; And it is a transaction the node accepts, which is the full
              ;; script verification of the witness the wallet produced.
              (is-true (and (stringp (%aval "hex" signed))
                            (stringp (rpc nil "sendrawtransaction"
                                          (%aval "hex" signed))))
                       "the finalized transaction was refused by the node"))))))))

(test walletprocesspsbt-drops-the-full-transaction-a-taproot-input-cannot-need
  "Core FillPSBT ends with RemoveUnnecessaryTransactions (wallet.cpp:2229, and
rpc/rawtransaction.cpp:211 for descriptorprocesspsbt): the non_witness_utxo it
attached a moment earlier is dropped again from EVERY input when all of them
are segwit v1-or-later and none asks for ANYONECANPAY (psbt.cpp:514-549). One
non-segwit or segwit-v0 input, or one ANYONECANPAY sighash, and nothing is
dropped -- the list is cleared and the loop breaks.

The rule reads the input's OWN recorded sighash, which Core settles in
SignPSBTInput before any key work (psbt.cpp:445-456): the resolved type is
written whenever it is not the default for that input type, whether or not a
signature follows. We wrote it only where a signature had succeeded, so on
sign=false or for an input we hold no key for the ANYONECANPAY guard could not
have fired -- which is why the drop was left unported and every taproot PSBT
went out carrying the previous transactions in full.
wallet_taproot.py:352-354 asserts a tr() input has witness_utxo and NO
non_witness_utxo.

PP-WALLETPROCESSPSBT-ATTACHES-NON-WITNESS-UTXO is the other half of the
control and stays green: its inputs are segwit v0, where nothing may be
dropped."
  (%with-pp-node (node "pp-trdrop")
    (%pp-fund-wallet node :blocks 2)
    (with-wallet-rng (41)
     (let* ((rpc (lambda (method &rest params)
                   (bl.rpc:dispatch-rpc-method node method params)))
           (tr-address (funcall rpc "getnewaddress" "" "bech32m"))
           (tr-spk (nth-value 1 (bl.crypto:decode-address tr-address :regtest)))
           (funding (bl.rpc:parse-hex-hash
                     (funcall rpc "sendtoaddress" tr-address 1
                              nil nil nil nil nil nil nil 5)))
           (funding-tx (%pp-mempool-tx node funding)))
      (is (not (null funding-tx)) "fixture: the taproot funding never confirmed")
      (%pp-mine node 1 (%pp-optrue-address))
      (let ((vout (position tr-spk (bl.ser:transaction-outputs funding-tx)
                            :key #'bl.ser:tx-out-script-pubkey :test #'equalp)))
        (is (not (null vout)) "fixture: no output paid the taproot address")
        (let* ((b64 (%aval "psbt"
                           (funcall rpc "walletcreatefundedpsbt"
                                    (list (%ht "txid" (bl.rpc:hash-to-hex funding)
                                               "vout" vout))
                                    (list (%ht (%pp-optrue-address) "0.50000000"))
                                    0
                                    (%ht "fee_rate" 10
                                         "add_inputs" bl.rpc:+json-false+
                                         "change_type" "bech32m"))))
               (processed (funcall rpc "walletprocesspsbt" b64))
               (out (bl.ser:decode-psbt (%aval "psbt" processed))))
          ;; Every input of this PSBT is the taproot one.
          (loop for m across (bl.ser:psbt-inputs out)
                do (is-true (bl.ser:psbt-map-find m bl.ser:+psbt-in-witness-utxo+)
                            "a taproot input keeps its witness_utxo")
                   (is-false (bl.ser:psbt-map-find
                              m bl.ser:+psbt-in-non-witness-utxo+)
                             "a taproot input must not carry the whole previous transaction"))))))))

(test pp-walletprocesspsbt-attaches-non-witness-utxo
  "Core FillPSBT (wallet.cpp:2201-2212) attaches the full previous transaction
whenever an input lacks non_witness_utxo — a witness_utxo already present does
not suppress it, because a hardware signer needs the full transaction to
authenticate a segwit v0 input's amount. Before the fix an imported PSBT that
carried only witness_utxo was never upgraded, so Trezor/Ledger/Coldcard refused
to cosign it. The v0 inputs here also pin RemoveUnnecessaryTransactions
(psbt.cpp:514-549): with a segwit-v0 input present nothing may be dropped."
  (%with-pp-node (node "pp-nwutxo")
    (%pp-fund-wallet node)
    (let* ((bl.wallet::*wallet-rng* (make-wallet-rng 17))
           (dest (%pp-optrue-address))
           (b64 (%aval "psbt" (bl.rpc:dispatch-rpc-method
                               node "walletcreatefundedpsbt"
                               (wire-params
                                (list '() (list (%ht dest 1)) 0
                                      (%ht "fee_rate" 5))))))
           (psbt (bl.ser:decode-psbt b64)))
      ;; Strip every non_witness_utxo, as an external creator that only
      ;; supplied witness_utxo would have left it.
      (loop for m across (bl.ser:psbt-inputs psbt)
            do (is-true (bl.ser:psbt-map-find
                         m bl.ser:+psbt-in-witness-utxo+))
               (bl.ser:psbt-map-remove-type
                m bl.ser:+psbt-in-non-witness-utxo+))
      (let* ((stripped (bl.ser:encode-psbt psbt))
             (filled (bl.rpc:dispatch-rpc-method
                      node "walletprocesspsbt"
                      (wire-params (list stripped bl.rpc:+json-false+ nil nil
                                         bl.rpc:+json-false+))))
             (out (bl.ser:decode-psbt (%aval "psbt" filled))))
        (loop for m across (bl.ser:psbt-inputs out)
              do (is-true (bl.ser:psbt-map-find
                           m bl.ser:+psbt-in-non-witness-utxo+)
                          "non_witness_utxo attached from the wallet"))
        ;; And the attached copy is the AUTHENTICATED one: with a lying
        ;; witness_utxo present, the amount the signer sees comes from the
        ;; wallet's own previous transaction, not the counterparty's TxOut
        ;; (GA9 S2-14's fee-spoofing path, now closed from both sides).
        (loop for m across (bl.ser:psbt-inputs out)
              for in across (bl.ser:transaction-inputs
                             (bl.ser:psbt-tx out))
              do (let ((real (bl.ser:tx-out-value
                              (bl.wallet::%psbt-input-prevout m in))))
                   (is (plusp real))
                   ;; Overwrite witness_utxo with a 1-sat lie; the resolved
                   ;; prevout must not move.
                   (bl.ser:psbt-map-set
                    m bl.ser:+psbt-in-witness-utxo+
                    (make-array 0 :element-type '(unsigned-byte 8))
                    (flexi-streams:with-output-to-sequence (s)
                      (bl.ser:write-tx-out
                       s (bl.ser:make-tx-out
                          :value 1 :script-pubkey
                          (bl.ser:tx-out-script-pubkey
                           (bl.wallet::%psbt-input-prevout m in))))))
                   (is (= real (bl.ser:tx-out-value
                                (bl.wallet::%psbt-input-prevout m in)))
                       "authenticated non_witness_utxo still wins")))))))

(test pp-wallet-fill-psbt-stores-non-witness-utxo-without-witness
  "A non_witness_utxo is the previous transaction WITHOUT its witness: Core
writes it TX_NO_WITNESS (psbt.h:303-305), since the record authenticates a
txid and the witness is no part of one. The wallet updaters (FillPSBT,
wallet.cpp:2201-2212) stored the wallet transaction's full wire bytes, and
only the PSBT writer's normalization (a5b1c888) kept them out of what we
sent. The funding coins here are segwit coinbases, which carry a witness
(the witness reserved value), so the difference is visible in the record."
  (%with-pp-node (node "pp-nwnw")
    (let* ((wallet (%pp-fund-wallet node))
           (b64 (%aval "psbt" (bl.rpc:dispatch-rpc-method
                               node "walletcreatefundedpsbt"
                               (wire-params
                                (list '() (list (%ht (%pp-optrue-address) 1)) 0
                                      (%ht "fee_rate" 5))))))
           (tx (bl.ser:psbt-tx (bl.ser:decode-psbt b64)))
           (psbt (bl.wallet:wallet-fill-psbt wallet tx)))
      (is (plusp (length (bl.ser:psbt-inputs psbt))))
      (loop for m across (bl.ser:psbt-inputs psbt)
            for in across (bl.ser:transaction-inputs tx)
            do (let* ((txid (bl.rpc:hash-to-hex
                             (bl.ser:outpoint-hash (bl.ser:tx-in-previous-output in))))
                      (wire (bl.crypto:hex-to-bytes
                             (%aval "hex" (bl.rpc:dispatch-rpc-method
                                           node "gettransaction" (wire-params (list txid))))))
                      (parent (bl.ser:br-read-transaction
                               (bl.ser:make-byte-reader-from wire))))
                 ;; Control: the parent has a witness, so the two forms differ.
                 (is-true (bl.ser:transaction-has-witness-p parent))
                 (is (equalp (bl.ser:serialize-transaction parent)
                             (bl.ser:psbt-map-find m bl.ser:+psbt-in-non-witness-utxo+))
                     "input ~A's non_witness_utxo is not the legacy serialization" txid))))))

(test pp-bumpfee-rbf-chain
  "bumpfee rebuilds a higher-feerate replacement re-spending ALL original inputs,
signs + broadcasts it (RBF-evicting the original), records replaced_by_txid, and
refuses to bump an already-bumped tx."
  (%with-pp-node (node "pp-bump")
    (let ((wallet (%pp-fund-wallet node :blocks 2)))
      (let* ((bl.wallet::*wallet-rng* (make-wallet-rng 7))
             (dest (%pp-optrue-address))
             (txid-hex (bl.wallet::rpc-sendtoaddress
                        node (list dest 1 nil nil nil nil nil nil nil 5)))
             (txid (bl.rpc:parse-hex-hash txid-hex))
             (orig-tx (%pp-mempool-tx node txid)))
        (is (not (null orig-tx)))
        (let ((orig-inputs (%pp-input-outpoints orig-tx))
              (result (bl.wallet::rpc-bumpfee
                       node (list txid-hex (%ht "fee_rate" 20)))))
          (let* ((new-txid-hex (%aval "txid" result))
                 (new-tx (%pp-mempool-tx node (bl.rpc:parse-hex-hash new-txid-hex))))
            (is (stringp new-txid-hex))
            (is (> (%aval "fee" result) (%aval "origfee" result)))
            (is (equalp #() (%aval "errors" result)))
            ;; Replacement is in the mempool (accepted => RBF evicted the original).
            (is (not (null new-tx)))
            (is (null (%pp-mempool-tx node txid)))
            ;; All original inputs are re-spent.
            (dolist (op orig-inputs)
              (is-true (member op (%pp-input-outpoints new-tx) :test #'equalp)))
            ;; Replacement verifies against the exact spent scripts.
            (is (%pp-verify-ok-p node wallet new-tx))
            ;; Original tx is marked replaced.
            (let ((owtx (bl.wallet::wallet-get-wallet-tx wallet txid)))
              (is (string= new-txid-hex
                           (cdr (assoc "replaced_by_txid"
                                       (bl.wallet::wallet-tx-map-value owtx)
                                       :test #'string=)))))
            ;; Cannot bump the same (already-bumped) tx again.
            (signals bl.rpc:rpc-error
              (bl.wallet::rpc-bumpfee node (list txid-hex (%ht "fee_rate" 40))))))))))

(test bumpfee-outputs-replaces-the-original-outputs
  "Core's bumpfee takes an `outputs' option -- a whole new output set that
REPLACES the original transaction's (wallet/rpc/spend.cpp:1073-1080 builds it
with AddOutputs; feebumper::CreateRateBumpTransaction:250 then reads
`outputs.empty() ? wtx.tx->vout : outputs' and fills its recipients from that,
:251-262). Its sibling `original_change_index' names which of the ORIGINAL
outputs is the change to recycle, and the two are refused together
(:161-165), as is an index past the end (:180-183).

We accepted both option names in the argument table and then ignored them, so
bumpfee(txid, outputs={addr: amount}) rebuilt the ORIGINAL outputs and paid the
old destination -- wallet_bumpfee.py:345 asserts the bumped wallet transaction
has one detail and that it names the NEW address.

The default bump is the control: with no `outputs' the replacement must still
carry the original destination, so a change that always rebuilt from the option
would fail there."
  (%with-pp-node (node "pp-bumpouts")
    (%pp-fund-wallet node :blocks 5)
    (with-wallet-rng (23)
     (let* ((dest (%pp-optrue-address))
            (rpc (lambda (method &rest params)
                   (bl.rpc:dispatch-rpc-method node method params))))
      (flet ((send (rate)
               (funcall rpc "sendtoaddress" dest 1
                        nil nil nil nil nil nil nil rate))
             (spk-of (address)
               (nth-value 1 (bl.crypto:decode-address address :regtest)))
             (outputs-of (txid-hex)
               (map 'list #'bl.ser:tx-out-script-pubkey
                    (bl.ser:transaction-outputs
                     (%pp-mempool-tx node (bl.rpc:parse-hex-hash txid-hex))))))
        ;; Control: no `outputs' option, so the original destination survives.
        (let* ((plain (send 5))
               (bumped (%aval "txid" (funcall rpc "bumpfee" plain
                                              (%ht "fee_rate" 20)))))
          (is-true (member (spk-of dest) (outputs-of bumped) :test #'equalp)
                   "a plain bump must keep the original destination"))
        ;; And with it, the new set replaces the old one entirely.
        (let* ((new-address (funcall rpc "getnewaddress" "" "bech32"))
               (txid (send 5))
               (bumped (%aval "txid"
                              (funcall rpc "bumpfee" txid
                                       (%ht "fee_rate" 20
                                            "outputs" (list (%ht new-address "0.00030000"))))))
               (scripts (outputs-of bumped)))
          (is-true (member (spk-of new-address) scripts :test #'equalp)
                   "the replacement does not pay the address `outputs' names")
          (is-false (member (spk-of dest) scripts :test #'equalp)
                    "the replacement still pays the ORIGINAL destination"))
        ;; The two options Core refuses together, and an index past the end.
        (let ((txid (send 5)))
          (is (equal (cons -8 "The options 'outputs' and 'original_change_index' are incompatible. You can only either specify a new set of outputs, or designate a change output to be recycled.")
                     (rpc-error-of
                      (lambda ()
                        (funcall rpc "bumpfee" txid
                                 (%ht "outputs" (list (%ht dest "0.00030000"))
                                      "original_change_index" 0))))))
          (is (equal (cons -8 "Change position is out of range")
                     (rpc-error-of
                      (lambda ()
                        (funcall rpc "bumpfee" txid
                                 (%ht "original_change_index" 9))))))))))))

(test bumpfee-prices-a-given-fee-rate-against-maxtxfee
  "Core checks a USER-GIVEN feerate BEFORE it builds the replacement
(feebumper.cpp:278-292): CheckFeeRate prices the feerate over the
replacement's maximum signed size and refuses a total fee above -maxtxfee with
-4 `Specified or calculated fee X is too high (cannot be higher than -maxtxfee
Y)' (:105-113).

We capped only inside the build, where a fee nobody can pay is a coin-selection
failure, so the caller who typed the feerate was told about the funds or about
the relay's own cap rather than about -maxtxfee -- wallet_bumpfee.py:132 reads
Core's sentence for fee_rate=100000.

A bump that fits under the cap is the control: a change that always refused
would fail there."
  (%with-pp-node (node "pp-bumpmax")
    (%pp-fund-wallet node :blocks 5)
    (with-wallet-rng (31)
      (let* ((dest (%pp-optrue-address))
             (rpc (lambda (method &rest params)
                    (bl.rpc:dispatch-rpc-method node method params))))
        (flet ((send (rate)
                 (funcall rpc "sendtoaddress" dest 1
                          nil nil nil nil nil nil nil rate)))
          (is (stringp (%aval "txid" (funcall rpc "bumpfee" (send 5)
                                              (%ht "fee_rate" 20))))
              "a bump whose fee fits under -maxtxfee must still be built")
          (let ((err (rpc-error-of
                      (lambda ()
                        (funcall rpc "bumpfee" (send 5)
                                 (%ht "fee_rate" 100000))))))
            (is (eql bl.rpc:+rpc-wallet-error+ (car err))
                "bumpfee(fee_rate=100000) answered ~S" err)
            (is-true (and (stringp (cdr err))
                          (search "Specified or calculated fee 0.14" (cdr err)))
                     "the message does not price the feerate over the replacement: ~S"
                     (cdr err))
            (is-true (and (stringp (cdr err))
                          (search "is too high (cannot be higher than -maxtxfee 0.10)"
                                  (cdr err)))
                     "the message does not name -maxtxfee: ~S" (cdr err)))
          ;; The cap the message names is the one in force.
          (let* ((bl:*wallet-max-tx-fee* 100000)
                 (err (rpc-error-of
                       (lambda ()
                         (funcall rpc "bumpfee" (send 5)
                                  (%ht "fee_rate" 100000))))))
            (is-true (and (stringp (cdr err))
                          (search "-maxtxfee 0.001" (cdr err)))
                     "a lowered -maxtxfee is not the one reported: ~S" (cdr err))))))))

(test pp-psbtbumpfee-unsigned
  "psbtbumpfee returns an UNSIGNED PSBT of the replacement without broadcasting;
the original stays in the mempool, and walletprocesspsbt completes the PSBT."
  (%with-pp-node (node "pp-psbtbump")
    (%pp-fund-wallet node :blocks 2)
    (let* ((bl.wallet::*wallet-rng* (make-wallet-rng 13))
           (dest (%pp-optrue-address))
           (txid-hex (bl.wallet::rpc-sendtoaddress
                      node (list dest 1 nil nil nil nil nil nil nil 5)))
           (txid (bl.rpc:parse-hex-hash txid-hex))
           (result (bl.wallet::rpc-psbtbumpfee
                    node (list txid-hex (%ht "fee_rate" 20))))
           (b64 (%aval "psbt" result)))
      (is (stringp b64))
      (is (> (%aval "fee" result) (%aval "origfee" result)))
      ;; The returned PSBT is unsigned but carries witness_utxo per input.
      (let ((psbt (bl.ser:decode-psbt b64)))
        (loop for m across (bl.ser:psbt-inputs psbt)
              do (is (null (bl.ser:psbt-map-find
                            m bl.ser:+psbt-in-final-scriptsig+)))
                 (is (null (bl.ser:psbt-map-collect
                            m bl.ser:+psbt-in-partial-sig+)))
                 (is-true (bl.ser:psbt-map-find
                           m bl.ser:+psbt-in-witness-utxo+))))
      ;; The original is untouched (psbtbumpfee does not broadcast).
      (is (not (null (%pp-mempool-tx node txid))))
      ;; walletprocesspsbt completes the replacement PSBT into a network tx.
      (let ((processed (bl.rpc:dispatch-rpc-method
                        node "walletprocesspsbt" (wire-params (list b64)))))
        (is (eq t (%aval "complete" processed)))
        (is (stringp (%aval "hex" processed)))))))

;;;; ============================================================
;;;; G7-04: load_on_startup persistence (Core settings.json)
;;;;
;;;; The bug: the node only ever created the wallet manager, and
;;;; load_on_startup was accepted and discarded — so every restart silently
;;;; dropped all wallets. Under a respawn supervisor that means balances
;;;; vanish and rebroadcast stops unattended; it already stranded a funded
;;;; testnet4 deposit.
;;;; ============================================================

(defun %wallet-settings-dir (node)
  (wallet-data-directory (%node-manager node)))

(defun %wallet-settings-path (node)
  (bl.wallet::settings-json-path (%wallet-settings-dir node)))

(defun %wallet-settings-raw (node)
  "Parsed settings.json, or NIL when the file does not exist."
  (let ((path (%wallet-settings-path node)))
    (when (probe-file path)
      (with-open-file (s path :direction :input :external-format :utf-8)
        (yason:parse s)))))

(defun %startup-names (node)
  (bl.wallet::wallet-startup-names (%wallet-settings-dir node)))

(defun %write-raw-settings (node text)
  (let ((path (%wallet-settings-path node)))
    (ensure-directories-exist path)
    (with-open-file (s path :direction :output :external-format :utf-8
                           :if-exists :supersede :if-does-not-exist :create)
      (write-string text s))))

(defun %restart-wallet-manager (node)
  "Simulate a node restart: unload every wallet and rebuild the manager over
the same datadir, leaving settings.json in place."
  (let ((dir (%wallet-settings-dir node)))
    (bl.wallet:close-wallet-manager (%node-manager node))
    (setf (bl:node-wallet-manager node)
          (bl.wallet::make-wallet-manager
           :data-directory dir :network :testnet4 :keypool-size 5))))

(defun %loaded-wallet-names (node)
  (coerce (bl.wallet::rpc-listwallets node nil) 'list))

(test g7-04-load-on-startup-is-tristate
  "load_on_startup is Core's std::optional<bool> (wallet.cpp:124-135):
omitted/null leaves the setting untouched, true records the wallet, false
removes it. Only an explicit value writes anything."
  (with-wallet-test-node (node)
    ;; Omitted: no setting recorded, and no settings.json written at all.
    (bl.wallet::rpc-createwallet node '("plain"))
    (is (null (%startup-names node)))
    (is (null (%wallet-settings-raw node))
        "a no-op update must not create settings.json")
    ;; Explicit true records it.
    (bl.wallet::rpc-createwallet node (list "auto" nil nil nil nil nil t))
    (is (equal '("auto") (%startup-names node)))
    ;; Explicit null on an already-recorded wallet leaves it recorded.
    (bl.wallet::rpc-unloadwallet node '("auto"))
    (is (equal '("auto") (%startup-names node)))
    (bl.wallet::rpc-loadwallet node '("auto"))
    (is (equal '("auto") (%startup-names node)))
    ;; Explicit false removes it.
    (bl.wallet::rpc-unloadwallet
     node (list "auto" bl.rpc:+json-false+))
    (is (null (%startup-names node)))
    ;; loadwallet with true records a wallet created without it.
    (bl.wallet::rpc-unloadwallet node '("plain"))
    (bl.wallet::rpc-loadwallet node '("plain" t))
    (is (equal '("plain") (%startup-names node)))))

(test g7-04-settings-store-semantics
  "Add/remove mirror Core AddWalletSetting/RemoveWalletSetting: duplicate adds
and absent removes are SKIP_WRITE no-ops that still report success, and file
order is preserved."
  (with-wallet-test-node (node)
    (let ((dir (%wallet-settings-dir node)))
      (is (bl.wallet::update-wallet-setting dir "a" :true))
      (is (bl.wallet::update-wallet-setting dir "a" :true))
      (is (equal '("a") (bl.wallet::wallet-startup-names dir))
          "adding twice must not duplicate the entry")
      (bl.wallet::update-wallet-setting dir "b" :true)
      (bl.wallet::update-wallet-setting dir "c" :true)
      (is (equal '("a" "b" "c") (bl.wallet::wallet-startup-names dir)))
      (is (bl.wallet::update-wallet-setting dir "nosuch" :false)
          "removing an absent name is a successful no-op")
      (is (equal '("a" "b" "c") (bl.wallet::wallet-startup-names dir)))
      (bl.wallet::update-wallet-setting dir "b" :false)
      (is (equal '("a" "c") (bl.wallet::wallet-startup-names dir))
          "removal from the middle keeps the rest in order")
      ;; NIL action never touches the file.
      (is (bl.wallet::update-wallet-setting dir "zzz" nil))
      (is (equal '("a" "c") (bl.wallet::wallet-startup-names dir))))))

(test g7-04-settings-preserves-other-keys
  "settings.json is node-wide in Core, so a wallet update must rewrite only
the \"wallet\" key and leave every other setting intact. The list is written
as a JSON array, not an object."
  (with-wallet-test-node (node)
    (%write-raw-settings node "{\"prune\":1234,\"other\":[\"x\",\"y\"]}")
    (is (bl.wallet::update-wallet-setting (%wallet-settings-dir node) "w" :true))
    (let ((raw (%wallet-settings-raw node)))
      (is (eql 1234 (gethash "prune" raw)))
      (is (equal '("x" "y") (gethash "other" raw)))
      (is (equal '("w") (gethash "wallet" raw))
          "the wallet list must round-trip as a JSON array"))))

(test g7-04-non-string-entries-ignored
  "Core filters the settings list with isStr(); a malformed entry must be
skipped rather than crashing startup."
  (with-wallet-test-node (node)
    (%write-raw-settings node "{\"wallet\":[\"ok\",42,null,[\"nested\"],\"fine\"]}")
    (is (equal '("ok" "fine") (%startup-names node)))
    ;; A non-array value contributes nothing but is still replaceable.
    (%write-raw-settings node "{\"wallet\":\"notalist\"}")
    (is (null (%startup-names node)))
    ;; Duplicates in a hand-edited file collapse to the first occurrence
    ;; (Core's wallet_paths set), so startup never double-loads a wallet.
    (%write-raw-settings node "{\"wallet\":[\"a\",\"b\",\"a\"]}")
    (is (equal '("a" "b") (%startup-names node)))))

(test g7-04-corrupt-settings-not-clobbered
  "An unparseable settings.json must disable auto-load AND refuse updates.
Treating it as empty would rewrite the file and destroy a wallet list the
operator can still repair by hand."
  (with-wallet-test-node (node)
    (let ((garbage "{ this is not json"))
      (%write-raw-settings node garbage)
      (is (null (%startup-names node)))
      (is (null (bl.wallet::update-wallet-setting
                 (%wallet-settings-dir node) "w" :true))
          "an update against corrupt settings must report failure")
      (is (string= garbage
                   (with-open-file (s (%wallet-settings-path node)) (read-line s)))
          "the corrupt file must be left exactly as found")
      ;; A NIL action has nothing to write, so it still succeeds.
      (is (bl.wallet::update-wallet-setting
           (%wallet-settings-dir node) "w" nil)))))

(test g7-04-failed-update-returns-core-warning
  "Core surfaces a warning rather than failing the RPC when the setting cannot
be persisted (wallet.cpp:131-133)."
  (with-wallet-test-node (node)
    (%write-raw-settings node "{ corrupt")
    (let* ((result (bl.wallet::rpc-createwallet
                    node (list "w" nil nil nil nil nil t)))
           (warnings (%aval "warnings" result)))
      (is (string= "w" (%aval "name" result)) "the wallet is still created")
      (is (member "Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."
                  warnings :test #'string=)))))

(test g7-04-wallets-auto-load-at-startup
  "THE BUG: a restart dropped every wallet. A wallet recorded with
load_on_startup must come back by itself; one that was not recorded must not."
  (with-wallet-test-node (node)
    (bl.wallet::rpc-createwallet node (list "keeper" nil nil nil nil nil t))
    (bl.wallet::rpc-createwallet node '("transient"))
    (is (equal '("keeper" "transient") (%loaded-wallet-names node)))
    (%restart-wallet-manager node)
    (is (null (%loaded-wallet-names node))
        "the restart must start with nothing loaded")
    (bl.wallet:load-wallets-on-startup node)
    (is (equal '("keeper") (%loaded-wallet-names node))
        "only the wallet recorded for startup comes back")))

(test g7-04-startup-skips-unloadable-wallet
  "DELIBERATE divergence from Core, which aborts startup with an init error
when a listed wallet fails to load. The node runs under a respawn supervisor,
so aborting would turn one bad wallet into an endless restart loop with no
node at all. A failure is logged and the remaining wallets still load — and
the broken entry is listed FIRST here, so this fails if the loop aborts."
  (with-wallet-test-node (node)
    (bl.wallet::rpc-createwallet node '("good"))
    (let ((dir (%wallet-settings-dir node)))
      (bl.wallet::update-wallet-setting dir "ghost" :true)
      (bl.wallet::update-wallet-setting dir "good" :true)
      (is (equal '("ghost" "good") (bl.wallet::wallet-startup-names dir))))
    (%restart-wallet-manager node)
    (bl.wallet:load-wallets-on-startup node)
    (is (equal '("good") (%loaded-wallet-names node))
        "a wallet listed before a broken one must still load")))

(test negated-wallet-on-the-command-line-hides-the-settings-list
  "Core GetSettingsList (common/settings.cpp:238-240): a negated command-line
value ends the merge, so `-nowallet -wallet=foo' loads foo ALONE, whatever
settings.json records. The startup loader used to read settings.json again on
top of the merged list, loaded both wallets, and getwalletinfo then answered
-19 \"Multiple wallets are loaded\" (tool_wallet.py:224-227)."
  (with-wallet-test-node (node)
    (bl.wallet::rpc-createwallet node (list "keeper" nil nil nil nil nil t))
    (bl.wallet::rpc-createwallet node '("foo"))
    (%restart-wallet-manager node)
    (let* ((rows (bl:settings-config-rows '(("wallet" . #("keeper")))))
           (negated (getf (start-node-plist '("-regtest" "-nowallet" "-wallet=foo")
                                            nil rows)
                          :wallet-names))
           (plain (getf (start-node-plist '("-regtest" "-wallet=foo") nil rows)
                        :wallet-names)))
      ;; The merged list itself is Core's, both ways.
      (is (equal '("foo") negated))
      (is (equal '("foo" "keeper") plain)
          "without the negation settings.json's list follows the command line")
      ;; The loader takes the merged list as the whole list.
      (bl.wallet:load-wallets-on-startup node negated)
      (is (equal '("foo") (%loaded-wallet-names node))
          "-nowallet -wallet=foo must not load settings.json's wallets too")
      ;; Control: the list with keeper in it loads keeper.
      (%restart-wallet-manager node)
      (bl.wallet:load-wallets-on-startup node plain)
      (is (equal '("foo" "keeper") (%loaded-wallet-names node))))))

(test start-up-says-verifying-wallets-when-the-wallet-runs
  "Core's VerifyWallets announces `Verifying wallet(s)' before it opens any
wallet database (wallet/load.cpp:57), and feature_init.py:88 interrupts
start-up on that line; VerifyWallets runs only when the wallet does."
  (let ((dir (ensure-directories-exist
              (merge-pathnames (format nil "test-verify-wallets-~D/" (get-internal-real-time))
                               (uiop:temporary-directory))))
        (node (bl:make-node)))
    (setf (bl:node-data-directory node) dir)
    (unwind-protect
         (flet ((said-p (lines) (find "init message: Verifying wallet(s)" lines :test #'search)))
           (is-true (said-p (capture-log-lines
                             (lambda () (bl:start-wallets node :regtest nil nil '())))))
           (is-true (bl:node-wallet-manager node) "the wallet runs by default on regtest")
           (bl.wallet:close-wallet-manager (bl:node-wallet-manager node))
           (setf (bl:node-wallet-manager node) nil)
           (is-false (said-p (capture-log-lines
                              (lambda () (bl:start-wallets node :regtest nil t '()))))
                     "-disablewallet: no wallet, nothing to verify"))
      (when (bl:node-wallet-manager node)
        (ignore-errors (bl.wallet:close-wallet-manager (bl:node-wallet-manager node))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test start-up-says-loading-wallet-for-each-wallet-it-loads
  "Core's LoadWallets announces `Loading wallet…' before EACH wallet it opens
(wallet/load.cpp:149, the InitMessage the GUI's splash screen shows), after
the one `Verifying wallet(s)…'. A name listed twice is loaded, and
announced, once (wallet_paths is a set, load.cpp:129-131)."
  (with-wallet-test-node (node :network :regtest)
    (bl.rpc:dispatch-rpc-method node "createwallet" '("one"))
    (bl.rpc:dispatch-rpc-method node "createwallet" '("two"))
    (setf (bl:node-data-directory node) (%wallet-settings-dir node))
    (bl.wallet:close-wallet-manager (%node-manager node))
    (setf (bl:node-wallet-manager node) nil)
    (let ((lines (capture-log-lines
                  (lambda () (bl:start-wallets node :regtest nil nil '("one" "two" "one"))))))
      (is (= 2 (count-if (lambda (l) (search "init message: Loading wallet…" l)) lines)))
      (is (< (position-if (lambda (l) (search "init message: Verifying wallet(s)…" l)) lines)
             (position-if (lambda (l) (search "init message: Loading wallet…" l)) lines))
          "verification is announced first")
      (is (equal '("one" "two") (sort (%loaded-wallet-names node) #'string<))))))

(test startup-refuses-a-wallet-another-instance-holds
  "Core's VerifyWallets stops startup when a -wallet cannot be opened
(load.cpp:106-110), and a database another process holds is SQLiteDatabase's
exclusive-lock failure (wallet/sqlite.cpp:276-283), which feature_filelock.py:51
reads off stderr. The skip-and-log divergence above is for a wallet that is
broken; a wallet that is BUSY means two nodes point at it, which is the
datadir lock's situation one directory down."
  (with-wallet-test-node (node)
    (bl.rpc:dispatch-rpc-method node "createwallet" '("held"))
    (let ((second (%make-wallet-test-node (%wallet-settings-dir node))))
      (unwind-protect
           (let ((refusal (handler-case
                              (progn (bl.wallet:load-wallets-on-startup
                                      second '("held"))
                                     :started)
                            (bl.err:init-error (e) (princ-to-string e)))))
             (is (equal "SQLiteDatabase: Unable to obtain an exclusive lock on the database, is it being used by another instance of bitcoin-lisp?"
                        refusal)))
        (ignore-errors
         (bl.wallet:close-wallet-manager (%node-manager second)))))
    ;; Control: once the holder lets go, the same startup load succeeds.
    (bl.wallet:close-wallet-manager (%node-manager node))
    (let ((second (%make-wallet-test-node (%wallet-settings-dir node))))
      (unwind-protect
           (progn (bl.wallet:load-wallets-on-startup second '("held"))
                  (is (equal '("held") (%loaded-wallet-names second))))
        (ignore-errors
         (bl.wallet:close-wallet-manager (%node-manager second)))))))

;;;; --- tr() script trees through the WALLET signer -------------------------

(test wallet-signs-a-tr-script-path
  "The wallet drive site for tr() script-path spending.

%SPKM-TR-SCRIPT-LEAVES is reached only from %WALLET-SIGN-MAPS, and a signer that
never receives its map fails every tr()-with-tree input with 'no key for P2TR'
while every unit test of the machinery below it stays green — the shape this
project has shipped fourteen times. This imports such a descriptor into a real
wallet and signs through %WALLET-SIGN-TRANSACTION.

The internal key is a bare pubkey the wallet holds no secret for, so the key
path is unavailable by construction and only a script path can spend."
  (with-wallet-test-node (node :network :mainnet :keypool 2)
    (let* ((manager (%node-manager node))
           (internal "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
           (leaf-wif "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1")
           (desc-str (bl.rpc:descriptor-add-checksum
                      (format nil "tr(~A,pk(~A))" internal leaf-wif))))
      (bl.wallet::create-wallet manager "trtree" :blank t)
      (with-rpc-wallet ("trtree")
        (let ((results (bl.wallet::rpc-importdescriptors
                        ;; Not "active": Core requires an active descriptor to
                        ;; be ranged, and a fixed tree has no range.
                        node (list (list (%ht "desc" desc-str
                                              "timestamp" "now"))))))
          (is (eq t (%aval "success" (first results)))
              "import failed: ~A"
              (let ((err (%aval "error" (first results))))
                (if err (%aval "message" err) (first results))))))
      (let* ((wallet (loaded-wallet manager "trtree"))
             (desc (bl.rpc:parse-descriptor
                    (format nil "tr(~A,pk(~A))" internal leaf-wif) :mainnet))
             (spk (first (bl.rpc::out-desc-expand desc 0)))
             (amount 100000)
             (empty (make-array 0 :element-type '(unsigned-byte 8)))
             (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 9))
             (tx (bl.ser:make-transaction
                  :version 2
                  :inputs (vector (bl.ser:make-tx-in
                                   :previous-output
                                   (bl.ser:make-outpoint
                                    :hash prev-txid :index 0)
                                   :script-sig empty :sequence #xffffffff))
                  :outputs (vector (bl.ser:make-tx-out
                                    :value (- amount 1000)
                                    :script-pubkey
                                    (coerce (bl.crypto:hex-to-bytes
                                             "0014751e76e8199196d454941c45d1b3a323f1433bd6")
                                            '(simple-array (unsigned-byte 8) (*)))))))
             (coins (make-hash-table :test 'equalp)))
        ;; The wallet must recognise the output before it can sign it.
        (is-true (bl.wallet::%wallet-owning-spkm wallet spk)
                 "the wallet does not recognise its own tr() tree output")
        (setf (gethash (cons prev-txid 0) coins) (list spk amount nil nil))
        (let ((errs (bl.wallet::%wallet-sign-transaction wallet tx coins)))
          (is (null errs) "wallet signing reported ~S" errs))
        (let* ((witness (bl.ser:transaction-witness tx))
               (stack (and witness (plusp (length witness)) (aref witness 0))))
          (is-true stack "no witness was installed")
          ;; signature, leaf script, control block — a script path, not a key path.
          (is (= 3 (length stack))
              "witness has ~D elements, wanted 3 (sig, script, control block)"
              (length stack)))
        (is-true (nth-value 0 (bl.wallet::%verify-tx-scripts tx coins))
                 "the wallet-signed script-path spend does not verify")))))

;;; --- -addresstype / -changetype (finding 4d28b231) --------------------------

(defun %w-bare-addresses (address-type change-type)
  "(getnewaddress getrawchangeaddress), both called with NO arguments, on a
regtest wallet whose -addresstype is ADDRESS-TYPE and -changetype CHANGE-TYPE.
Through the shipped dispatcher, because what this finding is about is the
address an operator is handed."
  (with-wallet-chain-node (node "addrtype" :wallet "at")
    (let ((bl.wallet:*wallet-default-address-type* address-type)
          (bl.wallet:*wallet-default-change-type* change-type))
      (list (bl.rpc:dispatch-rpc-method node "getnewaddress" '())
            (bl.rpc:dispatch-rpc-method node "getrawchangeaddress" '())))))

(test addresstype-and-changetype-are-the-wallets-defaults
  "Core parses -addresstype into m_default_address_type and -changetype into
m_default_change_type (wallet.cpp:2955-2972); getnewaddress uses the first
(rpc/addresses.cpp:53) and getrawchangeaddress
m_default_change_type.value_or(m_default_address_type) (:99). Both options were
accepted and dropped and both RPCs hardcoded bech32, so an operator who
configured taproot kept being handed P2WPKH (GA11 4d28b231).

The unset case is the positive control: it must still be bech32, so a change
that simply moved the hardcoded type would fail here."
  (destructuring-bind (recv change) (%w-bare-addresses :bech32 nil)
    (is (eql 0 (search "bcrt1q" recv)) "unset must stay bech32: ~A" recv)
    (is (eql 0 (search "bcrt1q" change)) "unset must stay bech32: ~A" change))
  ;; -addresstype=bech32m: the receiving address follows it, and so does the
  ;; change address, because -changetype is empty and falls back to it.
  (destructuring-bind (recv change) (%w-bare-addresses :bech32m nil)
    (is (eql 0 (search "bcrt1p" recv)) "-addresstype ignored: ~A" recv)
    (is (eql 0 (search "bcrt1p" change)) "the change fallback ignored it: ~A" change))
  ;; -changetype wins over the address type for change only.
  (destructuring-bind (recv change) (%w-bare-addresses :bech32m :p2sh-segwit)
    (is (eql 0 (search "bcrt1p" recv)))
    (is (eql 0 (search "2" change)) "-changetype ignored: ~A" change))
  ;; An unparseable value is refused with Core's own wording rather than
  ;; silently leaving the default (Core refuses to load the wallet).
  (signals error (bl.wallet:set-wallet-default-output-type :address "nosuchtype"))
  (signals error (bl.wallet:set-wallet-default-output-type :change "nosuchtype"))
  ;; An empty value leaves the default, as Core's `if (!...empty())' does.
  (let ((bl.wallet:*wallet-default-address-type* :bech32))
    (bl.wallet:set-wallet-default-output-type :address "")
    (is (eq :bech32 bl.wallet:*wallet-default-address-type*))))

(defun %utf8-label-classes ()
  "One label per class the wallet's label field spans: ASCII, Latin-1, CJK and
an astral-plane emoji. Built with CODE-CHAR so this source file stays ASCII."
  (list "plain"
        (string (code-char #xE9))                              ; U+00E9
        (coerce (list (code-char #x4E2D) (code-char #x6587)) 'string) ; U+4E2D U+6587
        (string (code-char #x1F600))))                         ; U+1F600

(test wallet-label-survives-the-wallet-file-in-cores-utf-8-bytes
  "GA11 2cae91f5. The wallet's `name' record holds the label through the same
:var-string codec row DEFINE-MESSAGE uses, and that row was Latin-1: a label
with any character above U+00FF made the leveldb write a raw TYPE-ERROR, which
escaped the wallet store and reached the client as -32603 `Internal error: The
value 20013 is not of type (UNSIGNED-BYTE 8)' -- setlabel and getnewaddress
with a label were simply unavailable for CJK, Cyrillic and emoji. A Latin-1
label did survive our own round trip, but went to disk as ONE byte where Core
writes the two UTF-8 bytes, so the record diverged from Core's walletdb
encoding for every accented character.

What this asserts is the wallet SURFACE: that the label reaches the file and
parses back, so writer and reader agree on the new encoding. It cannot see
whether those bytes are Core's -- our own Latin-1 write and Latin-1 read were
self-consistent, which is exactly why the divergence went unnoticed -- so the
bytes themselves are pinned in the serialization suite
(VAR-STRING-FIELDS-ARE-UTF-8-BYTES-NOT-ONE-BYTE-PER-CODE-POINT). The ASCII
label is the control: identical under either encoding."
  (with-wallet-chain-node (node "utf8label" :wallet "u8")
    (let* ((labels (%utf8-label-classes))
           (addresses (mapcar (lambda (label)
                                (bl.rpc:dispatch-rpc-method
                                 node "getnewaddress" (list label)))
                              labels)))
      (flet ((address-for (label)
               (mapcar #'car (bl.rpc:dispatch-rpc-method
                              node "getaddressesbylabel" (list label)))))
        (loop for label in labels
              for address in addresses
              do (is (equal (list address) (address-for label))
                     "label class ~D was not stored" (char-code (char label 0))))
        ;; Close the wallet and read it back from the file: the labels now
        ;; come from the bytes on disk, not from the address book in memory.
        (with-rpc-wallet (nil)
          (bl.rpc:dispatch-rpc-method node "unloadwallet" '("u8"))
          (bl.rpc:dispatch-rpc-method node "loadwallet" '("u8")))
        (loop for label in labels
              for address in addresses
              do (is (equal (list address) (address-for label))
                     "label class ~D did not survive the wallet file"
                     (char-code (char label 0))))))))

;;; --- SignPSBTInput's require_witness_sig and the taproot script path ---------

(test walletprocesspsbt-signs-a-tr-script-path-from-the-witness-utxo-alone
  "Core SignPSBTInput's require_witness_sig (psbt.cpp:428-435, :488) refuses a
NON-witness signature over an input whose only prevout source is the
witness_utxo, and ProduceSignature sets sigdata.witness for every segwit
solution -- the taproot SCRIPT path included (sign.cpp:781-786). Ours named the
witness kinds by hand and left the script path out, so a tr() tree input
carried by its witness_utxo alone -- the shape a PSBT from another creator
arrives in -- was refused as if it were a legacy spend.

The internal key is a bare pubkey the wallet holds no secret for, so only the
script path can spend. The same input with a non_witness_utxo attached is the
control that the signer itself is fine."
  (with-wallet-test-node (node :network :regtest :keypool 2)
    (let* ((internal "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
           (desc (bl.rpc:descriptor-add-checksum
                  (format nil "tr(~A,pk(~A))" internal (regtest-wif 41)))))
      (bl.rpc:dispatch-rpc-method node "createwallet" (list "trtree" nil t))
      (with-rpc-wallet ("trtree")
        (let ((imported (first (bl.rpc:dispatch-rpc-method
                                node "importdescriptors"
                                (list (list (%ht "desc" desc "timestamp" "now")))))))
          (is (eq t (%aval "success" imported)) "importdescriptors refused: ~S" imported))
        (let* ((address (first (bl.rpc:dispatch-rpc-method node "deriveaddresses" (list desc))))
               (spk (nth-value 1 (bl.crypto:decode-address address :regtest))))
          (flet ((complete-p (psbt)
                   (%aval "complete"
                          (bl.rpc:dispatch-rpc-method
                           node "walletprocesspsbt" (list (bl.ser:encode-psbt psbt))))))
            (is (eq t (complete-p (%psbt-funded-spending spk 100000)))
                "control: the tree input does not sign even with its non_witness_utxo")
            (is (eq t (complete-p (%psbt-spending spk 100000)))
                "a tr() script-path input carried by witness_utxo alone was refused")))))))

(test walletcreatefundedpsbt-locks-the-coins-it-selected
  "walletcreatefundedpsbt funds through the SAME wallet::FundTransaction as
fundrawtransaction (wallet/rpc/spend.cpp:1766 -> :682), whose last step locks
every input of the funded transaction when lock_unspents was asked for
(wallet/spend.cpp:1538-1542).

Ours parsed the option and then threw it away -- CreateTransaction was called
directly and the flag was declared ignored -- so the coins stayed spendable and
two successive calls funded the SAME UTXOs, leaving a pair of PSBTs of which
only one could ever be broadcast. The first call here is the control: without
the option nothing is locked, so the lock below comes from the option and not
from funding."
  (%with-pp-node (node "pp-lockunspent")
    (%pp-fund-wallet node)
    (let* ((bl.wallet::*wallet-rng* (make-wallet-rng 77))
           (dest (%pp-optrue-address)))
      (flet ((fund (&rest option-kvs)
               (bl.rpc:dispatch-rpc-method
                node "walletcreatefundedpsbt"
                (wire-params (list '() (list (%ht dest 1)) 0
                                   (apply #'%ht "fee_rate" 5 option-kvs)))))
             (locked ()
               (let ((rows (bl.rpc:dispatch-rpc-method
                            node "listlockunspent" (wire-params '()))))
                 (if (vectorp rows) '() rows))))
        (is (null (locked)) "fixture: the wallet starts with no locked coins")
        ;; Control: no lock_unspents, nothing locked.
        (let ((psbt (bl.ser:decode-psbt (%aval "psbt" (fund)))))
          (is (plusp (length (bl.ser:psbt-inputs psbt)))
              "the control funded no inputs, so it proves nothing")
          (is (null (locked))
              "funding locked coins with no lock_unspents: ~S" (locked)))
        ;; With the option, every input of the funded transaction is locked.
        (let* ((psbt (bl.ser:decode-psbt (%aval "psbt" (fund "lock_unspents" t))))
               (inputs (%pp-input-outpoints (bl.ser:psbt-tx psbt)))
               (rows (locked)))
          (is (= (length inputs) (length rows))
              "~D input~:P funded, ~D locked" (length inputs) (length rows))
          (dolist (op inputs)
            (is-true (find-if (lambda (row)
                                (and (string= (bl.rpc:hash-to-hex (car op))
                                              (cdr (assoc "txid" row :test #'string=)))
                                     (eql (cdr op)
                                          (cdr (assoc "vout" row :test #'string=)))))
                              rows)
                     "input ~A:~D was not locked"
                     (bl.rpc:hash-to-hex (car op)) (cdr op))))))))

;;; --- migratewallet: registered, and Core's refusal ------------------------

(test migratewallet-answers-cores-already-a-descriptor-wallet
  "migratewallet exists and refuses, in Core's own words.

Core migrates a Berkeley DB wallet into a descriptor one
(wallet/rpc/wallet.cpp:582-639). This tree has no legacy wallet format at all,
so MigrateLegacyToDescriptor's two early refusals are the whole answer
(wallet/wallet.cpp:4250-4271, both RPC_WALLET_ERROR = -4): a wallet that is
loaded, or on disk and not a BDB file, is already a descriptor wallet; a name
with nothing behind it does not exist.

The method was simply absent, which is not the same answer: rpc_help.py:110
fails a node whose dump_all_command_conversions is missing a method Core's
client.cpp lists, and migratewallet's two arguments were the last such rows.
An operator running the migration got \"Method not found\" -- which reads as a
node too old to have it -- instead of being told there is nothing to migrate."
  (with-wallet-test-node (node)
    (bl.rpc:dispatch-rpc-method node "createwallet" (wire-params '("mw")))
    (let ((bl.wallet::*rpc-wallet-name* nil))
      ;; A loaded wallet: Core asserts it is a descriptor wallet and says so.
      (signals-rpc-error (:code -4 :exact-message
                                "Error: This wallet is already a descriptor wallet")
        (bl.rpc:dispatch-rpc-method node "migratewallet" (wire-params '("mw"))))
      ;; The passphrase argument an encrypted wallet would need is accepted and
      ;; changes nothing: the refusal comes before any secret is used.
      (signals-rpc-error (:code -4 :exact-message
                                "Error: This wallet is already a descriptor wallet")
        (bl.rpc:dispatch-rpc-method node "migratewallet"
                                    (wire-params '("mw" "hunter2"))))
      ;; A name with nothing behind it is Core's other sentence.
      (signals-rpc-error (:code -4 :exact-message "Error: Wallet does not exist")
        (bl.rpc:dispatch-rpc-method node "migratewallet" (wire-params '("nosuch"))))
      ;; Neither endpoint nor argument is EnsureUniqueWalletName's own refusal
      ;; (wallet/rpc/util.cpp:46-49), which unloadwallet already answered.
      (signals-rpc-error (:code -8 :exact-message
                                "Either the RPC endpoint wallet or the wallet name parameter must be provided")
        (bl.rpc:dispatch-rpc-method node "migratewallet" (wire-params '()))))
    ;; And it is a method `help' knows, so its two arguments reach
    ;; dump_all_command_conversions -- what rpc_help.py:110 reads.
    (let ((dump (bl.rpc:dispatch-rpc-method
                 node "help" (wire-params '("dump_all_command_conversions")))))
      (is (= 2 (count "migratewallet" (coerce dump 'list)
                      :key (lambda (row) (aref row 0)) :test #'string=))
          "migratewallet contributes ~D conversion rows, Core lists 2"
          (count "migratewallet" (coerce dump 'list)
                 :key (lambda (row) (aref row 0)) :test #'string=)))))

(test bumpfee-replaces-a-transaction-that-does-not-signal
  "feebumper::PreconditionChecks (wallet/feebumper.cpp:23-57) has no BIP125
signaling arm -- the mempool replaces by full RBF whatever the original
signals -- so a wallet transaction sent with replaceable=false is bumpable
(wallet_bumpfee.py:374-377, test_nonrbf_bumpfee_succeeds). We refused it with
\"Transaction is not BIP 125 replaceable\". The replacement must reach the
mempool and evict the original (the control that full RBF really takes it)."
  (%with-pp-node (node "pp-bump-nonrbf")
    (%pp-fund-wallet node :blocks 5)
    (with-wallet-rng (29)
      (let* ((rpc (lambda (method &rest params)
                    (bl.rpc:dispatch-rpc-method node method params)))
             (txid (funcall rpc "sendtoaddress" (%pp-optrue-address) 1
                            nil nil nil bl.rpc:+json-false+ nil nil nil 5))
             (bumped (rpc-error-of
                      (lambda () (funcall rpc "bumpfee" txid (%ht "fee_rate" 20))))))
        (is (null bumped) "a non-signaling transaction is bumped: ~S" bumped)
        (is (not (member txid (coerce (funcall rpc "getrawmempool") 'list)
                         :test #'equal))
            "the original left the mempool")))))

(test bumpfee-of-a-mined-transaction-says-its-input-is-spent
  "CreateRateBumpTransaction looks every original input up in the chain's
view (findCoins: the mempool over the UTXO set) BEFORE the precondition
checks, and a coin that is gone is -1 \"<txid>:<n> is already spent\"
(wallet/feebumper.cpp:187-199) -- wallet_bumpfee.py:670 bumps a transaction
already mined. We read the wallet's own record of the output, which outlives
the spend, and answered the depth check's \"Transaction has been mined\"."
  (%with-pp-node (node "pp-bump-mined")
    (%pp-fund-wallet node :blocks 5)
    (with-wallet-rng (31)
      (let* ((rpc (lambda (method &rest params)
                    (bl.rpc:dispatch-rpc-method node method params)))
             (txid (funcall rpc "sendtoaddress" (%pp-optrue-address) 1
                            nil nil nil nil nil nil nil 5))
             (spent (bl.ser:tx-in-previous-output
                     (aref (bl.ser:transaction-inputs
                            (%pp-mempool-tx node (bl.rpc:parse-hex-hash txid)))
                           0))))
        (%pp-mine node 1 (%pp-optrue-address))
        (is (equal (cons -1 (format nil "~A:~D is already spent"
                                    (bl.rpc:hash-to-hex (bl.ser:outpoint-hash spent))
                                    (bl.ser:outpoint-index spent)))
                   (rpc-error-of
                    (lambda () (funcall rpc "bumpfee" txid (%ht "fee_rate" 20))))))))))

(test bumpfee-carries-the-comment-to-the-replacement
  "feebumper::CommitTransaction commits the replacement with the ORIGINAL's
whole mapValue plus replaces_txid (wallet/feebumper.cpp:370-373), so the
comment and to of a sendtoaddress survive a bump (wallet_bumpfee.py:726). We
committed replaces_txid alone. The original keeps its own (the control)."
  (%with-pp-node (node "pp-bump-metadata")
    (%pp-fund-wallet node :blocks 5)
    (with-wallet-rng (33)
      (let* ((rpc (lambda (method &rest params)
                    (bl.rpc:dispatch-rpc-method node method params)))
             (txid (funcall rpc "sendtoaddress" (%pp-optrue-address) 1
                            "comment value" "to value" nil nil nil nil nil 5))
             (bumped (%aval "txid" (funcall rpc "bumpfee" txid (%ht "fee_rate" 20))))
             (orig (funcall rpc "gettransaction" txid))
             (new (funcall rpc "gettransaction" bumped)))
        (is (equal "comment value" (%aval "comment" orig)))
        (is (equal "comment value" (%aval "comment" new)))
        (is (equal "to value" (%aval "to" new)))))))

(test bumpfee-checks-a-given-rate-against-the-replacement-outputs
  "CheckFeeRate prices a USER-GIVEN feerate over the maximum signed size of
temp_mtx -- the original inputs with the replacement's outputs -- against the
old fee plus one incremental relay fee over that size, BEFORE building
(wallet/feebumper.cpp:278-292, :86-99). wallet_bumpfee.py:785-808 replaces
fifty outputs by one and bumps at one sat/vB under the minimum that
arithmetic gives: -8 \"Insufficient total fee\". Ours checked only the BUILT
replacement, whose change output made the rate look sufficient. At the minimum
itself the bump goes through (the control)."
  (%with-pp-node (node "pp-bump-replaced-outputs")
    (%pp-fund-wallet node :blocks 5)
    (with-wallet-rng (37)
      (let* ((rpc (lambda (method &rest params)
                    (bl.rpc:dispatch-rpc-method node method params)))
             (outputs (loop repeat 20
                            collect (%ht (funcall rpc "getnewaddress" "" "bech32") "1")))
             (txid (%aval "txid" (funcall rpc "send" outputs nil nil 5)))
             (decoded (%aval "decoded" (funcall rpc "gettransaction" txid nil t)))
             (est (- (%aval "vsize" decoded)
                     (* 31 (1- (length (coerce (%aval "vout" decoded) 'list))))))
             (old-fee (- (btc-amount (%aval "fee" (funcall rpc "gettransaction" txid)))))
             ;; get_fee(est, 0.00000100 BTC/kvB) in BTC, as the Python test has it
             (min-fee (* (+ old-fee (/ (ceiling (* est 100) 1000) 100000000)) 100000000))
             (min-rate (/ (round (* 1000 (/ min-fee est))) 1000))
             (new-outputs (list (%ht (funcall rpc "getnewaddress" "" "bech32") "19"))))
        (flet ((bump (rate)
                 (rpc-error-of
                  (lambda ()
                    (funcall rpc "bumpfee" txid
                             (%ht "fee_rate" (coerce rate 'double-float)
                                  "outputs" new-outputs))))))
          (let ((low (bump (- min-rate 1))))
            (is (equal -8 (car low)) "one under the minimum: ~S" low)
            (is (eql 0 (search "Insufficient total fee" (or (cdr low) "")))))
          (is (null (bump min-rate)) "the minimum itself bumps"))))))

;;; --- The wallet directory, as Core's GetWalletDir/ListDatabases see it ---

(defun %listed-wallets (node)
  "listwalletdir's names, sorted."
  (sort (mapcar (lambda (entry) (cdr (assoc "name" entry :test #'string=)))
                (coerce (cdr (assoc "wallets"
                                    (bl.rpc:dispatch-rpc-method node "listwalletdir" '())
                                    :test #'string=))
                        'list))
        #'string<))

(test wallet-directory-falls-back-to-the-datadir-without-wallets
  "Core GetWalletDir (wallet/walletutil.cpp:24-30): <datadir>/wallets when it
IS a directory, the data directory itself when it is not. ListDatabases
(wallet/db.cpp:23-72) then walks it and lists only wallet databases -- here a
LevelDB carrying this network's id file -- so the node's own chainstate
LevelDB beside them is not a wallet. Ours always used wallets/."
  (with-wallet-test-node (node)
    (let* ((data (uiop:ensure-directory-pathname
                  (wallet-data-directory (%node-manager node))))
           (wallets (merge-pathnames "wallets/" data)))
      (uiop:delete-directory-tree wallets :validate t :if-does-not-exist :ignore)
      ;; A LevelDB that is not a wallet, where the chainstate would be.
      (let ((db (bl.store:leveldb-open
                 (namestring (merge-pathnames "chainstate/" data))
                 (bl.store:leveldb-make-options :create-if-missing t))))
        (bl.store:leveldb-close db))
      (bl.rpc:dispatch-rpc-method node "createwallet" (list "top"))
      (is-true (probe-file (merge-pathnames "top/CURRENT" data))
               "without wallets/, the wallet lives in the data directory")
      (is (equal '("top") (%listed-wallets node)))
      ;; Once wallets/ exists it is the wallet directory again.
      (ensure-directories-exist wallets)
      (is (equal '() (%listed-wallets node)))
      (bl.rpc:dispatch-rpc-method node "createwallet" (list "inner"))
      (is-true (probe-file (merge-pathnames "inner/CURRENT" wallets)))
      (is (equal '("inner") (%listed-wallets node))))))

(test wallet-names-may-be-relative-paths-but-not-escape
  "Core joins a wallet name onto the wallet directory (AbsPathJoin,
wallet/wallet.cpp:2926), so `sub/w5' is a wallet in a subdirectory and
listwalletdir walks into it (wallet_multiwallet.py:128). An absolute path
and a `..' segment stay refused (the Round-5 containment decision)."
  (flet ((accepted-p (name) (and (bl.wallet::%valid-wallet-name-p name) t)))
    (is-true (accepted-p "sub/w5"))
    (is-true (accepted-p "a/./b"))
    (is-false (accepted-p "/abs/w"))
    (is-false (accepted-p "sub/../../w"))
    (is-false (accepted-p "./"))
    (is-false (accepted-p ".")))
  (with-wallet-test-node (node)
    (bl.rpc:dispatch-rpc-method node "createwallet" (list "sub/w5"))
    (bl.rpc:dispatch-rpc-method node "createwallet" (list "plain"))
    (is (equal '("plain" "sub/w5") (%listed-wallets node)))
    (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "sub/w5"))
    (finishes (bl.rpc:dispatch-rpc-method node "loadwallet" (list "sub/w5")))
    (signals-rpc-error (:code -8)
      (bl.rpc:dispatch-rpc-method node "createwallet" (list "../escape")))))

(test wallet-from-another-network-is-not-a-database-here
  "Core refuses another network's wallet at the FORMAT PROBE: IsSQLiteFile
compares the file's application_id with this network's magic
(wallet/db.cpp:149-150), so MakeDatabase finds no database -- FAILED_BAD_FORMAT,
-18 behind `Wallet file verification failed.' (walletdb.cpp:1340-1344,
wallet.cpp:281) -- and ListDatabases does not list it. wallet_crosschain.py:42-45
asserts the -18. Ours opened it and refused it later, at -4, from AttachChain."
  (with-wallet-test-node (node)
    (let ((manager (%node-manager node)))
      (bl.rpc:dispatch-rpc-method node "createwallet" (list "w"))
      (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "w"))
      ;; Control: this network's id loads.
      (finishes (bl.rpc:dispatch-rpc-method node "loadwallet" (list "w")))
      (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "w"))
      (bl.wallet:wallet-write-id (wallet-directory-of manager "w") :signet)
      (signals-rpc-error (:code -18 :message "Wallet file verification failed. Failed to load database path")
        (bl.rpc:dispatch-rpc-method node "loadwallet" (list "w")))
      (is (equal '() (%listed-wallets node))))))

(test wallets-written-before-the-id-file-are-stamped-at-start-up
  "A wallet directory written before the id file existed is a LevelDB with no
BITCOIN_LISP_WALLET. Every LevelDB directly under a dedicated wallet directory
was a wallet then, so the manager's start-up stamps those with its network
and they keep loading."
  (let* ((dir (make-temp-directory))
         (wallets (merge-pathnames "wallets/" dir)))
    (unwind-protect
         (let ((db (bl.store:leveldb-open
                    (namestring (ensure-directories-exist
                                 (merge-pathnames "old/" wallets)))
                    (bl.store:leveldb-make-options :create-if-missing t))))
           (bl.store:leveldb-close db)
           (is-false (bl.wallet::wallet-db-format-recognized-p
                      (merge-pathnames "old/" wallets) :testnet4))
           (let ((manager (bl.wallet:init-wallet-manager dir :testnet4)))
             (is-true (bl.wallet::wallet-db-format-recognized-p
                       (merge-pathnames "old/" wallets) :testnet4))
             (is (equal '("old") (bl.wallet::list-wallet-dir manager)))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))
