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

(defun %aval (key alist) (cdr (assoc key alist :test #'string=)))

(defun %crash-close-wallet (node name)
  "Simulate a crash: close the wallet DB with no graceful unload bookkeeping
(no best-block write) and drop it from the manager."
  (let* ((manager (%node-manager node))
         (wallet (gethash name (bl.wallet::wallet-manager-wallets manager))))
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
      (let* ((wallet (gethash "corevec"
                              (bl.wallet::wallet-manager-wallets manager)))
             (spkm (gethash :bech32
                            (bl.wallet::wallet-external-spkms wallet))))
        (is (not (null spkm)))
        (loop for hex in core-scripts
              for i from 0
              do (is (eql i (bl.wallet::spkm-is-mine
                             spkm (bl.crypto:hex-to-bytes hex)))))
        ;; getnewaddress bech32 = Core's script at index 0
        (let ((bl.wallet::*rpc-wallet-name* "corevec"))
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
      (let ((bl.wallet::*rpc-wallet-name* nil))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("persist")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "persist" (bl.wallet::wallet-manager-wallets
                                       manager)))
           (addr1 (let ((bl.wallet::*rpc-wallet-name* nil))
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
      (let ((bl.wallet::*rpc-wallet-name* nil))
        (bl.wallet::rpc-unloadwallet node '("persist"))
        (bl.wallet::rpc-loadwallet node '("persist")))
      (let* ((wallet2 (gethash "persist" (bl.wallet::wallet-manager-wallets
                                          manager)))
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
                 (gethash "ver" (bl.wallet::wallet-manager-wallets
                                 (%node-manager node))))))
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
      (let ((bl.wallet::*rpc-wallet-name* "hardened"))
        (let ((results (bl.wallet::rpc-importdescriptors
                        node (list (list (%ht "desc" desc-str
                                              "timestamp" 1
                                              "active" t
                                              "range" '(0 2)))))))
          (is (eq t (%aval "success" (first results))))))
      ;; Reload: SetCache must rebuild the map purely from the persisted
      ;; derived-xpub records (no private keys consulted).
      (let ((bl.wallet::*rpc-wallet-name* nil))
        (bl.wallet::rpc-unloadwallet node '("hardened"))
        (bl.wallet::rpc-loadwallet node '("hardened")))
      (let* ((wallet (gethash "hardened" (bl.wallet::wallet-manager-wallets
                                          manager)))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
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
      (let ((bl.wallet::*rpc-wallet-name* "w1"))
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
           (gethash "enc0" (bl.wallet::wallet-manager-wallets
                            (%node-manager node)))))
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
    (let ((bl.wallet::*rpc-wallet-name* "wo"))
      ;; watch-only + blank + avoid_reuse
      (let ((bl.wallet::*rpc-wallet-name* nil))
        (bl.wallet::rpc-createwallet node '("wo" t t nil t)))
      (let ((info (bl.wallet::rpc-getwalletinfo node nil)))
        (is (string= "wo" (%aval "walletname" info)))
        (is (eq 'yason:false (%aval "private_keys_enabled" info)))
        (is (eq t (%aval "avoid_reuse" info)))
        (is (eq t (%aval "blank" info)))
        (is (eq t (%aval "descriptors" info)))
        (is (= 0 (%aval "txcount" info)))
        (is (= 0 (%aval "keypoolsize" info)))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
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
    (let ((bl.wallet::*rpc-wallet-name* "r2"))
      (is (string= "r2" (%aval "walletname"
                               (bl.wallet::rpc-getwalletinfo node nil)))))
    ;; unknown wallet endpoint -> -18 with Core's message
    (let ((bl.wallet::*rpc-wallet-name* "missing"))
      (signals-rpc-error (:code bl.rpc:+rpc-wallet-not-found+ :exact-message "Requested wallet does not exist or is not loaded")
        (bl.wallet::rpc-getwalletinfo node nil)))
    ;; unloadwallet via endpoint (no param)
    (let ((bl.wallet::*rpc-wallet-name* "r2"))
      (bl.wallet::rpc-unloadwallet node '()))
    (let ((bl.wallet::*rpc-wallet-name* nil))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("types"))
      (let ((wallet (gethash "types"
                             (bl.wallet::wallet-manager-wallets
                              (%node-manager node)))))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("ldwo" t)))
    (let ((bl.wallet::*rpc-wallet-name* "ldwo"))
      (is (= bl.rpc:+rpc-wallet-error+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-listdescriptors node '(t)))))))))

(test wallet-importdescriptors-validation
  "importdescriptors returns Core-shaped per-request results: checksum
required, watch-only rules, label/range constraints; a missing timestamp
throws out of the whole call."
  (with-wallet-test-node (node :keypool 3)
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("imp"))     ; privkeys enabled
      (bl.wallet::rpc-createwallet node '("impwo" t t))) ; watch-only blank
    (let ((bl.wallet::*rpc-wallet-name* "imp"))
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
    (let ((bl.wallet::*rpc-wallet-name* "impwo"))
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
  "Two BTC doubles equal to sub-satoshi tolerance."
  (< (abs (- a b)) 1d-6))

(defun %wt-dummy-txid (n)
  "A distinct non-zero 32-byte outpoint hash (so it never reads as coinbase)."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element n)))
    (setf (aref h 0) (logior 1 n))
    h))

(defun %wt-add-confirmed-tx (wallet inputs outputs &key (height 100))
  "Build and AddToWallet a confirmed tx. INPUTS: ((hash . vout) ...) prevouts;
OUTPUTS: ((script . value-sats) ...). Returns the tx's txid."
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
              :lock-time 0))
         (txid (bl.ser:transaction-hash tx))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 9)))
    (bl.wallet::wallet-add-to-wallet
     wallet tx (list :confirmed block-hash height 0))
    txid))

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
    (let ((bl.wallet::*rpc-wallet-name* nil))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("flags")))
    (let* ((bl.wallet::*rpc-wallet-name* "flags")
           (manager (%node-manager node))
           (wallet (gethash "flags" (bl.wallet::wallet-manager-wallets manager))))
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("cwd")))
    (let* ((bl.wallet::*rpc-wallet-name* "cwd")
           (manager (%node-manager node))
           (wallet (gethash "cwd" (bl.wallet::wallet-manager-wallets manager))))
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

(test gethdkeys-groups-descriptors-under-their-root-key
  "Core gethdkeys. The grouping is the point: two descriptors derived from one
HD root must appear as ONE entry with two descriptors, not two entries — that
is what tells an operator which key their wallet actually depends on."
  (with-wallet-test-node (node :keypool 4)
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("hd")))
    (let ((bl.wallet::*rpc-wallet-name* "hd"))
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
             (let ((bl.wallet::*rpc-wallet-name* nil))
               (bl.wallet::rpc-createwallet node '("notif")))
             (let* ((manager (%node-manager node))
                    (wallet (gethash "notif"
                                     (bl.wallet::wallet-manager-wallets
                                      manager)))
                    (bl.wallet::*rpc-wallet-name* "notif")
                    (bl.wallet:*wallet-notify-command*
                      ;; %w and %h prove the placeholders beyond %s reach the
                      ;; command line; %b would be the block hash, which is
                      ;; the file name below.
                      (format nil "touch ~A%w-%h-%b" (namestring dir))))
               (setf (bl.wallet::wallet-last-block-height wallet) 100)
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
  ;; A command with an unsafe wallet name can never be built, because a wallet
  ;; name outside [A-Za-z0-9._-] cannot exist in the first place.
  (is-false (bl.wallet::%valid-wallet-name-p "a;rm -rf /"))
  (dolist (name '("walletnotify"))
    (is-true (bl:known-config-option-p name) "~A unknown" name)
    (is-false (bl.cfg:core-only-option-p name) "~A still ignored" name)))

(test wallet-received-by-rpcs
  "getreceivedbyaddress/bylabel and listreceivedbyaddress/bylabel tally owned
outputs over mapWallet; unknown address -> -4, garbage -> -5, unknown label
-> -4."
  (with-wallet-test-node (node :keypool 4)
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("recv")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "recv"
                            (bl.wallet::wallet-manager-wallets manager)))
           (bl.wallet::*rpc-wallet-name* "recv"))
      (setf (bl.wallet::wallet-last-block-height wallet) 100)
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
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("kp")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "kp"
                            (bl.wallet::wallet-manager-wallets manager)))
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
rejects a double-spend across the array."
  (with-wallet-test-node (node :keypool 4)
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("sim")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "sim"
                            (bl.wallet::wallet-manager-wallets manager)))
           (bl.wallet::*rpc-wallet-name* "sim"))
      (setf (bl.wallet::wallet-last-block-height wallet) 100)
      (let* ((addr (bl.wallet::rpc-getnewaddress node '("" "bech32")))
             (script (%address-script addr :testnet4))
             (foreign (%address-script
                       (bl.crypto:encode-p2wpkh-address
                        (make-array 20 :element-type '(unsigned-byte 8)
                                       :initial-element 4)
                        :testnet4)
                       :testnet4)))
        ;; A pure receive to an owned script: +0.007.
        (let ((result (bl.wallet::rpc-simulaterawtransaction
                       node (list (list (%wt-raw-tx-hex
                                         (list (cons (%wt-dummy-txid 5) 0))
                                         (list (cons script 700000))))))))
          (is (%wt= 0.007d0 (%aval "balance_change" result))))
        ;; Fund an owned coin, then spend it to a foreign output: -0.01.
        (let ((funded (%wt-add-confirmed-tx
                       wallet (list (cons (%wt-dummy-txid 6) 0))
                       (list (cons script 1000000)))))
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

(test wallet-listaddressgroupings-clusters
  "listaddressgroupings clusters addresses co-spent as inputs of one tx and
keeps an unrelated lone address in its own group."
  (with-wallet-test-node (node :keypool 5)
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("grp")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "grp"
                            (bl.wallet::wallet-manager-wallets manager)))
           (bl.wallet::*rpc-wallet-name* "grp"))
      (setf (bl.wallet::wallet-last-block-height wallet) 100)
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
  (bl.rpc::rpc-generatetoaddress node (list n address)))

(defun %pp-fund-wallet (node &key (blocks 1))
  "createwallet \"w\", mine BLOCKS coinbases to a fresh bech32 (P2WPKH) address,
mature them. Returns the wallet."
  (bl.wallet::rpc-createwallet node '("w"))
  (let* ((wallet (gethash "w" (bl.wallet::wallet-manager-wallets
                               (bl:node-wallet-manager node))))
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
             (created (bl.wallet::rpc-walletcreatefundedpsbt
                       node (list '() (list (%ht dest 1))
                                  0 (%ht "fee_rate" 5))))
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
        (let* ((processed (bl.wallet::rpc-walletprocesspsbt node (list b64)))
               (hex (%aval "hex" processed)))
          (is (eq t (%aval "complete" processed)))
          (is (stringp hex))
          (let ((tx (bl.ser:parse-tx-payload
                     (bl.crypto:hex-to-bytes hex))))
            (is (%pp-verify-ok-p node wallet tx))
            ;; The extracted tx relays.
            (is (stringp (bl.rpc::rpc-sendrawtransaction node (list hex))))))))))

(test pp-walletprocesspsbt-sign-false-then-sign
  "walletprocesspsbt with sign=false only fills data (no sigs, incomplete); a
second call with sign=true (default) completes it."
  (%with-pp-node (node "pp-signflag")
    (%pp-fund-wallet node)
    (let* ((bl.wallet::*wallet-rng* (make-wallet-rng 99))
           (dest (%pp-optrue-address))
           (b64 (%aval "psbt" (bl.wallet::rpc-walletcreatefundedpsbt
                               node (list '() (list (%ht dest 1)) 0 (%ht "fee_rate" 5)))))
           ;; sign=false, finalize=false: no partial sigs, incomplete.
           (unsigned (bl.wallet::rpc-walletprocesspsbt
                      node (list b64 bl.rpc:+json-false+ nil nil
                                 bl.rpc:+json-false+))))
      (is (eq bl.rpc:+json-false+ (%aval "complete" unsigned)))
      (let ((psbt (bl.ser:decode-psbt (%aval "psbt" unsigned))))
        (loop for m across (bl.ser:psbt-inputs psbt)
              do (is (null (bl.ser:psbt-map-collect
                            m bl.ser:+psbt-in-partial-sig+)))))
      ;; Now sign (defaults) -> complete + extractable.
      (let ((signed (bl.wallet::rpc-walletprocesspsbt
                     node (list (%aval "psbt" unsigned)))))
        (is (eq t (%aval "complete" signed)))
        (is (stringp (%aval "hex" signed)))))))

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
           (b64 (%aval "psbt" (bl.wallet::rpc-walletcreatefundedpsbt
                               node (list '() (list (%ht dest 1)) 0 (%ht "fee_rate" 5)))))
           (psbt (bl.ser:decode-psbt b64)))
      ;; Strip every non_witness_utxo, as an external creator that only
      ;; supplied witness_utxo would have left it.
      (loop for m across (bl.ser:psbt-inputs psbt)
            do (is-true (bl.ser:psbt-map-find
                         m bl.ser:+psbt-in-witness-utxo+))
               (bl.ser:psbt-map-remove-type
                m bl.ser:+psbt-in-non-witness-utxo+))
      (let* ((stripped (bl.ser:encode-psbt psbt))
             (filled (bl.wallet::rpc-walletprocesspsbt
                      node (list stripped bl.rpc:+json-false+ nil nil
                                 bl.rpc:+json-false+)))
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
      (let ((processed (bl.wallet::rpc-walletprocesspsbt node (list b64))))
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
  (bl.wallet::wallet-manager-data-directory (%node-manager node)))

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
      (let ((bl.wallet::*rpc-wallet-name* "trtree"))
        (let ((results (bl.wallet::rpc-importdescriptors
                        ;; Not "active": Core requires an active descriptor to
                        ;; be ranged, and a fixed tree has no range.
                        node (list (list (%ht "desc" desc-str
                                              "timestamp" "now"))))))
          (is (eq t (%aval "success" (first results)))
              "import failed: ~A"
              (let ((err (%aval "error" (first results))))
                (if err (%aval "message" err) (first results))))))
      (let* ((wallet (gethash "trtree" (bl.wallet::wallet-manager-wallets manager)))
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
