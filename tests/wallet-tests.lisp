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

(defvar *wallet-test-counter* 0)

(defun %wallet-temp-dir ()
  (merge-pathnames (format nil "wallet-tests-~D-~D/"
                           (get-universal-time) (incf *wallet-test-counter*))
                   (uiop:temporary-directory)))

(defun %make-wallet-test-node (dir &key (network :testnet4) (keypool 5))
  "A minimal node with a wallet manager rooted at DIR."
  (let ((node (bitcoin-lisp::make-node :network network)))
    (setf (bitcoin-lisp::node-chain-state node)
          (bitcoin-lisp.storage:make-chain-state))
    (setf (bitcoin-lisp::node-wallet-manager node)
          (bitcoin-lisp.rpc::make-wallet-manager
           :data-directory dir :network network :keypool-size keypool))
    node))

(defun %node-manager (node)
  (bitcoin-lisp::node-wallet-manager node))

(defmacro with-wallet-test-node ((node &key (network :testnet4) (keypool 5))
                                 &body body)
  "Run BODY with NODE bound to a wallet-enabled test node in a fresh temp
datadir; the directory is deleted on unwind."
  (let ((dir (gensym "DIR")))
    `(let* ((,dir (%wallet-temp-dir))
            (,node (%make-wallet-test-node ,dir :network ,network
                                                :keypool ,keypool)))
       (unwind-protect (progn ,@body)
         (ignore-errors
          (bitcoin-lisp.rpc:close-wallet-manager (%node-manager ,node)))
         (uiop:delete-directory-tree ,dir :validate t
                                          :if-does-not-exist :ignore)))))

(defun %rpc-error-code (thunk)
  "The rpc-error code THUNK signals, or NIL if it returns normally."
  (handler-case (progn (funcall thunk) nil)
    (bitcoin-lisp.rpc::rpc-error (e) (bitcoin-lisp.rpc::rpc-error-code e))))

(defun %aval (key alist) (cdr (assoc key alist :test #'string=)))

(defun %crash-close-wallet (node name)
  "Simulate a crash: close the wallet DB with no graceful unload bookkeeping
(no best-block write) and drop it from the manager."
  (let* ((manager (%node-manager node))
         (wallet (gethash name (bitcoin-lisp.rpc::wallet-manager-wallets manager))))
    (bitcoin-lisp.storage:leveldb-close (bitcoin-lisp.rpc::wallet-db wallet))
    (remhash name (bitcoin-lisp.rpc::wallet-manager-wallets manager))
    (setf (bitcoin-lisp.rpc::wallet-manager-wallet-order manager)
          (remove name (bitcoin-lisp.rpc::wallet-manager-wallet-order manager)
                  :test #'string=))))

(defun %address-script (address network)
  (nth-value 1 (bitcoin-lisp.crypto:decode-address address network)))

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
              (bitcoin-lisp.rpc::wdb-key-simple "flags")))
  ;; Typed key round-trip through wdb-parse-key
  (let ((id (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (multiple-value-bind (type fields)
        (bitcoin-lisp.rpc::wdb-parse-key (bitcoin-lisp.rpc::wdb-key-descriptor id))
      (is (string= type "walletdescriptor"))
      (is (equalp id fields)))
    (multiple-value-bind (type fields)
        (bitcoin-lisp.rpc::wdb-parse-key
         (bitcoin-lisp.rpc::wdb-key-lockedutxo id 5))
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
              (bitcoin-lisp.rpc::wdb-descriptor-value "abc" 42 1 0 10)))
  (multiple-value-bind (str time next start end)
      (bitcoin-lisp.rpc::wdb-parse-descriptor-value
       (bitcoin-lisp.rpc::wdb-descriptor-value "abc" 42 1 0 10))
    (is (string= str "abc"))
    (is (= time 42)) (is (= next 1)) (is (= start 0)) (is (= end 10)))
  ;; CBlockLocator: dummy version 70016 LE + vector<uint256>
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (let ((bytes (bitcoin-lisp.rpc::wdb-block-locator-value (list h))))
      (is (equalp #(#x80 #x11 #x01 #x00 1) (subseq bytes 0 5)))
      (is (equalp (list h) (bitcoin-lisp.rpc::wdb-parse-block-locator-value bytes))))
    (is (null (bitcoin-lisp.rpc::wdb-parse-block-locator-value
               (bitcoin-lisp.rpc::wdb-block-locator-value '()))))))

(test wallet-privkey-der-roundtrip
  "CPrivKey DER encoding matches Core's sizes (214/279) and round-trips."
  (let ((priv (make-array 32 :element-type '(unsigned-byte 8)
                             :initial-contents (loop for i below 32 collect (1+ i)))))
    (let ((der-c (bitcoin-lisp.rpc::privkey-to-der priv t))
          (der-u (bitcoin-lisp.rpc::privkey-to-der priv nil)))
      (is (= 214 (length der-c)))          ; CKey::COMPRESSED_SIZE
      (is (= 279 (length der-u)))          ; CKey::SIZE
      (is (equalp priv (bitcoin-lisp.rpc::der-to-privkey der-c)))
      (is (equalp priv (bitcoin-lisp.rpc::der-to-privkey der-u)))
      (is (null (bitcoin-lisp.rpc::der-to-privkey (subseq der-c 0 40)))))))

(test wallet-record-schema-roundtrip
  "Write one record of every schema type, reopen the DB, read back identical."
  (let* ((dir (%wallet-temp-dir))
         (path (merge-pathnames "roundtrip/" dir))
         (id (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))
         (pubkey (bitcoin-lisp.crypto:derive-public-key
                  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                  :compressed t))
         (priv (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (xpub (bitcoin-lisp.crypto:bip32-neuter
                (bitcoin-lisp.crypto:bip32-master-key
                 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)
                 :network :testnet)))
         (written '()))
    (unwind-protect
         (progn
           (let ((db (bitcoin-lisp.rpc::wallet-db-open path :create t)))
             (flet ((put (key value)
                      (push (cons key value) written)
                      (bitcoin-lisp.storage:leveldb-put db key value)))
               (put (bitcoin-lisp.rpc::wdb-key-descriptor id)
                    (bitcoin-lisp.rpc::wdb-descriptor-value "wpkh(x)#00000000" 7 1 0 5))
               (put (bitcoin-lisp.rpc::wdb-key-descriptor-key
                     bitcoin-lisp.rpc::+wdb-key-walletdescriptorkey+ id pubkey)
                    (bitcoin-lisp.rpc::wdb-descriptor-key-value
                     pubkey (bitcoin-lisp.rpc::privkey-to-der priv t)))
               (put (bitcoin-lisp.rpc::wdb-key-descriptor-key
                     bitcoin-lisp.rpc::+wdb-key-walletdescriptorckey+ id pubkey)
                    (bitcoin-lisp.rpc::wdb-vector-value #(1 2 3 4)))
               (put (bitcoin-lisp.rpc::wdb-key-descriptor-parent-cache
                     bitcoin-lisp.rpc::+wdb-key-walletdescriptorcache+ id 0)
                    (bitcoin-lisp.rpc::wdb-xpub-value xpub))
               (put (bitcoin-lisp.rpc::wdb-key-descriptor-derived-cache id 0 11)
                    (bitcoin-lisp.rpc::wdb-xpub-value xpub))
               (put (bitcoin-lisp.rpc::wdb-key-descriptor-parent-cache
                     bitcoin-lisp.rpc::+wdb-key-walletdescriptorlhcache+ id 0)
                    (bitcoin-lisp.rpc::wdb-xpub-value xpub))
               (put (bitcoin-lisp.rpc::wdb-key-active-spk nil 2) id)
               (put (bitcoin-lisp.rpc::wdb-key-active-spk t 3) id)
               (put (bitcoin-lisp.rpc::wdb-key-simple
                     bitcoin-lisp.rpc::+wdb-key-bestblock+)
                    (bitcoin-lisp.rpc::wdb-block-locator-value '()))
               (put (bitcoin-lisp.rpc::wdb-key-simple
                     bitcoin-lisp.rpc::+wdb-key-bestblock-nomerkle+)
                    (bitcoin-lisp.rpc::wdb-block-locator-value (list txid)))
               (put (bitcoin-lisp.rpc::wdb-key-address-string
                     bitcoin-lisp.rpc::+wdb-key-name+ "addr1")
                    (bitcoin-lisp.rpc::wdb-string-value "label1"))
               (put (bitcoin-lisp.rpc::wdb-key-address-string
                     bitcoin-lisp.rpc::+wdb-key-purpose+ "addr1")
                    (bitcoin-lisp.rpc::wdb-string-value "receive"))
               (put (bitcoin-lisp.rpc::wdb-key-simple
                     bitcoin-lisp.rpc::+wdb-key-flags+)
                    (bitcoin-lisp.rpc::wdb-uint64-value
                     bitcoin-lisp.rpc::+wallet-flag-descriptors+))
               (put (bitcoin-lisp.rpc::wdb-key-mkey 1)
                    (bitcoin-lisp.rpc::wdb-mkey-value #(9 9) #(8 8 8) 0 25000 #()))
               (put (bitcoin-lisp.rpc::wdb-key-simple
                     bitcoin-lisp.rpc::+wdb-key-orderposnext+)
                    (bitcoin-lisp.rpc::wdb-int64-value 12345))
               (put (bitcoin-lisp.rpc::wdb-key-lockedutxo txid 1)
                    bitcoin-lisp.rpc::+wdb-lockedutxo-value+)
               (put (bitcoin-lisp.rpc::wdb-key-simple
                     bitcoin-lisp.rpc::+wdb-key-minversion+)
                    (bitcoin-lisp.rpc::wdb-int32-value 169900))
               (put (bitcoin-lisp.rpc::wdb-key-simple
                     bitcoin-lisp.rpc::+wdb-key-version+)
                    (bitcoin-lisp.rpc::wdb-int32-value
                     bitcoin-lisp.rpc::+wallet-client-version+))
               (put (bitcoin-lisp.rpc::wdb-key-tx txid)
                    (bitcoin-lisp.rpc::wdb-vector-value #())))
             (bitcoin-lisp.storage:leveldb-close db))
           ;; Reopen and compare every record byte-for-byte.
           (let* ((db (bitcoin-lisp.rpc::wallet-db-open path))
                  (records (bitcoin-lisp.rpc::wallet-db-records db)))
             (is (= (length written) (length records)))
             (dolist (w written)
               (let ((found (find (car w) records :key #'car :test #'equalp)))
                 (is (not (null found)))
                 (when found
                   (is (equalp (cdr w) (cdr found))))))
             ;; mkey parses back
             (let ((mkey (find (bitcoin-lisp.rpc::wdb-key-mkey 1) records
                               :key #'car :test #'equalp)))
               (multiple-value-bind (ck salt method iters other)
                   (bitcoin-lisp.rpc::wdb-parse-mkey-value (cdr mkey))
                 (is (equalp #(9 9) ck))
                 (is (equalp #(8 8 8) salt))
                 (is (= 0 method))
                 (is (= 25000 iters))
                 (is (zerop (length other)))))
             ;; xpub value decodes to the same extended key
             (let ((rec (find (bitcoin-lisp.rpc::wdb-key-descriptor-derived-cache id 0 11)
                              records :key #'car :test #'equalp)))
               (let ((decoded (bitcoin-lisp.rpc::wdb-parse-xpub-value (cdr rec) :testnet4)))
                 (is (string= (bitcoin-lisp.crypto:bip32-serialize xpub)
                              (bitcoin-lisp.crypto:bip32-serialize decoded)))))
             (bitcoin-lisp.storage:leveldb-close db)))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

;;; --- DescriptorID (compat form) ---

(test wallet-descriptor-id-compat-form
  "DescriptorID hashes the checksummed COMPAT-format string (apostrophe
hardened markers), so h-style and '-style inputs share one id."
  (let* ((xpub "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")
         (desc-h (bitcoin-lisp.rpc::parse-descriptor
                  (format nil "wpkh(~A/1h/2/*)" xpub) :mainnet))
         (desc-a (bitcoin-lisp.rpc::parse-descriptor
                  (format nil "wpkh(~A/1'/2/*)" xpub) :mainnet)))
    (is (equalp (bitcoin-lisp.rpc::descriptor-id desc-h)
                (bitcoin-lisp.rpc::descriptor-id desc-a)))
    ;; And it is SHA256 over the checksummed compat body.
    (is (equalp (bitcoin-lisp.crypto:sha256
                 (flexi-streams:string-to-octets
                  (bitcoin-lisp.rpc::descriptor-add-checksum
                   (format nil "wpkh(~A/1'/2/*)" xpub))
                  :external-format :ascii))
                (bitcoin-lisp.rpc::descriptor-id desc-h)))))

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
           (master (bitcoin-lisp.crypto:bip32-master-key seed :network :testnet))
           (xpub-str (bitcoin-lisp.crypto:bip32-serialize
                      (bitcoin-lisp.crypto:bip32-neuter master)))
           (xprv-str (bitcoin-lisp.crypto:bip32-serialize master))
           (wallet (bitcoin-lisp.rpc::create-wallet manager "fixed" :blank t)))
      (bitcoin-lisp.rpc::with-wallet-lock (wallet)
        (bitcoin-lisp.rpc::wallet-setup-descriptor-spkms wallet master))
      (is (= 8 (hash-table-count (bitcoin-lisp.rpc::wallet-spkms wallet))))
      (is (= 4 (hash-table-count (bitcoin-lisp.rpc::wallet-external-spkms wallet))))
      (is (= 4 (hash-table-count (bitcoin-lisp.rpc::wallet-internal-spkms wallet))))
      ;; Descriptor strings have Core's exact shape (testnet coin type 1h).
      (loop for (type prefix purpose suffix)
              in '((:legacy "pkh(" 44 "/*)") (:p2sh-segwit "sh(wpkh(" 49 "/*))")
                   (:bech32 "wpkh(" 84 "/*)") (:bech32m "tr(" 86 "/*)"))
            do (let ((spkm (gethash type (bitcoin-lisp.rpc::wallet-external-spkms
                                          wallet))))
                 (is (string= (format nil "~A~A/~Ah/1h/0h/0~A"
                                      prefix xpub-str purpose suffix)
                              (first (uiop:split-string
                                      (bitcoin-lisp.rpc::desc-spkm-desc-string spkm)
                                      :separator "#"))))))
      ;; Issued addresses match the P0 engine expanding the PRIVATE
      ;; descriptor by direct derivation (independent of the SPKM cache path).
      (dolist (spec '((:bech32 84 0) (:bech32m 86 0) (:legacy 44 0)
                      (:p2sh-segwit 49 0) (:bech32 84 1)))
        (destructuring-bind (type purpose internal) spec
          (let* ((spkm (gethash type (if (= internal 1)
                                         (bitcoin-lisp.rpc::wallet-internal-spkms wallet)
                                         (bitcoin-lisp.rpc::wallet-external-spkms wallet))))
                 (desc-str (format nil "~A~A/~Ah/1h/0h/~A~A"
                                   (ecase type (:legacy "pkh(") (:p2sh-segwit "sh(wpkh(")
                                          (:bech32 "wpkh(") (:bech32m "tr("))
                                   xprv-str purpose internal
                                   (if (eq type :p2sh-segwit) "/*))" "/*)")))
                 (desc (bitcoin-lisp.rpc::parse-descriptor desc-str :testnet4))
                 (next (bitcoin-lisp.rpc::desc-spkm-next-index spkm))
                 (expected (bitcoin-lisp.rpc::%script->address
                            (first (bitcoin-lisp.rpc::out-desc-expand desc next))
                            :testnet4))
                 (issued (bitcoin-lisp.rpc::with-wallet-lock (wallet)
                           (bitcoin-lisp.rpc::spkm-get-new-destination
                            wallet spkm type))))
            (is (string= expected issued))))))))

;;; --- Core-known vectors ---

(test wallet-import-core-wpkh-vector
  "importdescriptors of Core descriptor_tests.cpp's hardened-origin wpkh
vector produces Core's exact scriptPubKeys in the SPKM map, and getnewaddress
hands out Core's script at index 0."
  (with-wallet-test-node (node :network :mainnet :keypool 3)
    (let* ((manager (%node-manager node))
           (wallet (bitcoin-lisp.rpc::create-wallet manager "corevec" :blank t))
           (desc-body "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)")
           (desc-str (bitcoin-lisp.rpc::descriptor-add-checksum desc-body))
           (core-scripts '("0014326b2249e3a25d5dc60935f044ee835d090ba859"
                           "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"
                           "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27")))
      (declare (ignore wallet))
      (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "corevec")
             (results (bitcoin-lisp.rpc::rpc-importdescriptors
                       node (list (list (%ht "desc" desc-str
                                             "timestamp" "now"
                                             "active" t
                                             "range" '(0 2)))))))
        (is (= 1 (length results)))
        (is (eq t (%aval "success" (first results)))))
      (let* ((wallet (gethash "corevec"
                              (bitcoin-lisp.rpc::wallet-manager-wallets manager)))
             (spkm (gethash :bech32
                            (bitcoin-lisp.rpc::wallet-external-spkms wallet))))
        (is (not (null spkm)))
        (loop for hex in core-scripts
              for i from 0
              do (is (eql i (bitcoin-lisp.rpc::spkm-is-mine
                             spkm (bitcoin-lisp.crypto:hex-to-bytes hex)))))
        ;; getnewaddress bech32 = Core's script at index 0
        (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "corevec"))
          (let ((address (bitcoin-lisp.rpc::rpc-getnewaddress
                          node '("" "bech32"))))
            (is (equalp (bitcoin-lisp.crypto:hex-to-bytes (first core-scripts))
                        (%address-script address :mainnet)))))))))

(test wallet-import-core-taproot-vector
  "tr(tprv.../*) issues addresses whose x-only internal keys match Core's
wallet_taproot.py independent-implementation vectors, tweaked per BIP341."
  (with-wallet-test-node (node :network :testnet4 :keypool 4)
    (let* ((manager (%node-manager node))
           (xprv "tprv8ZgxMBicQKsPeNLUGrbv3b7qhUk1LQJZAGMuk9gVuKh9sd4BWGp1eMsehUni6qGb8bjkdwBxCbgNGdh2bYGACK5C5dRTaif9KBKGVnSezxV")
           (desc-str (bitcoin-lisp.rpc::descriptor-add-checksum
                      (format nil "tr(~A/*)" xprv)))
           ;; m/* derived x-only pubkeys, indexes 0-3 (wallet_taproot.py KEYS[0])
           (core-pubs '("83d8ee77a0f3a32a5cea96fd1624d623b836c1e5d1ac2dcde46814b619320c18"
                        "a30253b018ea6fca966135bf7dd8026915427f24ccf10d4e03f7870f4128569b"
                        "a61e5749f2f3db9dc871d7b187e30bfd3297eea2557e9be99897ea8ff7a29a21"
                        "8110cf482f66dc37125e619d73075af932521724ffc7108309e88f361efe8c8a")))
      (bitcoin-lisp.rpc::create-wallet manager "trvec" :blank t)
      (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "trvec")
             (results (bitcoin-lisp.rpc::rpc-importdescriptors
                       node (list (list (%ht "desc" desc-str
                                             "timestamp" 1
                                             "active" t
                                             "range" '(0 3)))))))
        (is (eq t (%aval "success" (first results))))
        (dolist (pub-hex core-pubs)
          (let* ((internal (bitcoin-lisp.crypto:hex-to-bytes pub-hex))
                 (tweaked (bitcoin-lisp.crypto:tweak-xonly-pubkey
                           internal (bitcoin-lisp.crypto:tap-tweak-hash internal)))
                 (expected (bitcoin-lisp.crypto:encode-p2tr-address
                            tweaked :testnet4))
                 (address (bitcoin-lisp.rpc::rpc-getnewaddress
                           node '("" "bech32m"))))
            (is (string= expected address))))))))

;;; --- Keypool persistence (funds-critical: no reuse after crash) ---

(test wallet-keypool-persistence-across-reload
  "Issued addresses are persisted (next_index fsynced) BEFORE being handed
out: after a crash-simulating close and reload, no previously issued address
is ever reissued."
  (with-wallet-test-node (node :network :testnet4 :keypool 5)
    (let ((issued '()))
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
        (bitcoin-lisp.rpc::rpc-createwallet node '("crashy"))
        ;; 7 bech32 (crosses the initial keypool window and forces TopUp),
        ;; plus a few of the other types and a change address.
        (dotimes (i 7)
          (push (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32")) issued))
        (dolist (type '("legacy" "p2sh-segwit" "bech32m"))
          (push (bitcoin-lisp.rpc::rpc-getnewaddress node (list "" type)) issued)
          (push (bitcoin-lisp.rpc::rpc-getrawchangeaddress node (list type)) issued))
        (push (bitcoin-lisp.rpc::rpc-getrawchangeaddress node '("bech32")) issued))
      (is (= 14 (length issued)))
      (is (= 14 (length (remove-duplicates issued :test #'string=))))
      ;; Crash: close the DB without any graceful-unload writes.
      (%crash-close-wallet node "crashy")
      ;; Reload and issue more of everything: zero overlap allowed.
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil)
            (fresh '()))
        (bitcoin-lisp.rpc::rpc-loadwallet node '("crashy"))
        (dotimes (i 3)
          (push (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32")) fresh))
        (dolist (type '("legacy" "p2sh-segwit" "bech32m"))
          (push (bitcoin-lisp.rpc::rpc-getnewaddress node (list "" type)) fresh)
          (push (bitcoin-lisp.rpc::rpc-getrawchangeaddress node (list type)) fresh))
        (push (bitcoin-lisp.rpc::rpc-getrawchangeaddress node '("bech32")) fresh)
        (is (= 10 (length (remove-duplicates fresh :test #'string=))))
        (is (null (intersection issued fresh :test #'string=)))))))

(test wallet-state-survives-reload
  "Descriptors, next_index, keys, and the IsMine map are identical after a
close/reopen (record schema round-trip at the wallet level)."
  (with-wallet-test-node (node :network :testnet4 :keypool 5)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("persist")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "persist" (bitcoin-lisp.rpc::wallet-manager-wallets
                                       manager)))
           (addr1 (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
                    (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32"))))
           ;; range_end is legitimately extended by the reload-time TopUp
           ;; (Core LoadExisting -> TopUpKeyPool), so compare descriptor
           ;; string + next_index and check range_end monotonicity separately.
           (spkm-state (lambda (w)
                         (sort (loop for spkm being the hash-values
                                       of (bitcoin-lisp.rpc::wallet-spkms w)
                                     collect (list (bitcoin-lisp.rpc::desc-spkm-desc-string spkm)
                                                   (bitcoin-lisp.rpc::desc-spkm-next-index spkm)
                                                   (bitcoin-lisp.rpc::desc-spkm-range-end spkm)))
                               #'string< :key #'first)))
           (descs-before (funcall spkm-state wallet)))
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
        (bitcoin-lisp.rpc::rpc-unloadwallet node '("persist"))
        (bitcoin-lisp.rpc::rpc-loadwallet node '("persist")))
      (let* ((wallet2 (gethash "persist" (bitcoin-lisp.rpc::wallet-manager-wallets
                                          manager)))
             (descs-after (funcall spkm-state wallet2)))
        (is (equal (mapcar (lambda (d) (list (first d) (second d))) descs-before)
                   (mapcar (lambda (d) (list (first d) (second d))) descs-after)))
        (loop for before in descs-before
              for after in descs-after
              do (is (>= (third after) (third before))))
        ;; The issued address is still IsMine at an index below next_index.
        (let* ((script (%address-script addr1 :testnet4))
               (spkm (gethash :bech32 (bitcoin-lisp.rpc::wallet-external-spkms
                                       wallet2)))
               (index (bitcoin-lisp.rpc::spkm-is-mine spkm script)))
          (is (eql 0 index))
          (is (< index (bitcoin-lisp.rpc::desc-spkm-next-index spkm)))
          (is (bitcoin-lisp.rpc::wallet-is-mine wallet2 script)))))))

(test wallet-hardened-ranged-cache-reload
  "A hardened-ranged descriptor (/*') persists derived-xpub cache records and
reloads to Core's exact scripts (descriptor_tests.cpp sh(wpkh(...)) vector)."
  (with-wallet-test-node (node :network :mainnet :keypool 3)
    (let* ((manager (%node-manager node))
           (desc-str (bitcoin-lisp.rpc::descriptor-add-checksum
                      "sh(wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))"))
           (core-scripts '("a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87"
                           "a914bed59fc0024fae941d6e20a3b44a109ae740129287"
                           "a9148483aa1116eb9c05c482a72bada4b1db24af654387")))
      (bitcoin-lisp.rpc::create-wallet manager "hardened" :blank t)
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "hardened"))
        (let ((results (bitcoin-lisp.rpc::rpc-importdescriptors
                        node (list (list (%ht "desc" desc-str
                                              "timestamp" 1
                                              "active" t
                                              "range" '(0 2)))))))
          (is (eq t (%aval "success" (first results))))))
      ;; Reload: SetCache must rebuild the map purely from the persisted
      ;; derived-xpub records (no private keys consulted).
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
        (bitcoin-lisp.rpc::rpc-unloadwallet node '("hardened"))
        (bitcoin-lisp.rpc::rpc-loadwallet node '("hardened")))
      (let* ((wallet (gethash "hardened" (bitcoin-lisp.rpc::wallet-manager-wallets
                                          manager)))
             (spkm (gethash :p2sh-segwit
                            (bitcoin-lisp.rpc::wallet-external-spkms wallet))))
        (is (not (null spkm)))
        (loop for hex in core-scripts
              for i from 0
              do (is (eql i (bitcoin-lisp.rpc::spkm-is-mine
                             spkm (bitcoin-lisp.crypto:hex-to-bytes hex)))))))))

;;; --- Lifecycle RPCs ---

(test wallet-lifecycle-rpcs
  "createwallet / loadwallet / unloadwallet / listwallets / listwalletdir
behave like Core, including the exact error codes."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (is (string= "w1" (%aval "name" (bitcoin-lisp.rpc::rpc-createwallet
                                       node '("w1")))))
      (is (equal '("w1") (bitcoin-lisp.rpc::rpc-listwallets node nil)))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w2"))
      (is (equal '("w1" "w2") (bitcoin-lisp.rpc::rpc-listwallets node nil)))
      ;; duplicate create -> -36; reload of loaded -> -35; unknown -> -18
      (is (= bitcoin-lisp.rpc::+rpc-wallet-already-exists+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-createwallet node '("w1"))))))
      (is (= bitcoin-lisp.rpc::+rpc-wallet-already-loaded+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-loadwallet node '("w1"))))))
      (is (= bitcoin-lisp.rpc::+rpc-wallet-not-found+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-loadwallet node '("nope"))))))
      ;; unload w1, reload it
      (bitcoin-lisp.rpc::rpc-unloadwallet node '("w1"))
      (is (equal '("w2") (bitcoin-lisp.rpc::rpc-listwallets node nil)))
      (is (= bitcoin-lisp.rpc::+rpc-wallet-not-found+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-unloadwallet node '("w1"))))))
      (bitcoin-lisp.rpc::rpc-loadwallet node '("w1"))
      (is (equal '("w2" "w1") (bitcoin-lisp.rpc::rpc-listwallets node nil)))
      ;; unloadwallet endpoint/param mismatch -> -8; neither -> -8
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "w1"))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-unloadwallet node '("w2")))))))
      (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-unloadwallet node '())))))
      ;; listwalletdir sees both, loaded or not
      (let ((dir-names (mapcar (lambda (w) (%aval "name" w))
                               (%aval "wallets"
                                      (bitcoin-lisp.rpc::rpc-listwalletdir node nil)))))
        (is (equal '("w1" "w2") (sort (copy-list dir-names) #'string<))))
      ;; createwallet flag semantics: explicit descriptors=false is
      ;; rejected; a null descriptors argument takes Core's default (true).
      (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
             (%rpc-error-code    ; descriptors=false rejected like Core
              (lambda () (bitcoin-lisp.rpc::rpc-createwallet
                          node (list "legacy0" nil nil nil nil
                                     bitcoin-lisp.rpc:+json-false+))))))
      (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
             (%rpc-error-code    ; passphrase -> encryption is P6
              (lambda () (bitcoin-lisp.rpc::rpc-createwallet
                          node '("enc0" nil nil "hunter2"))))))
      (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-createwallet node '("")))))))))

(test wallet-flags-and-getwalletinfo
  "disable_private_keys / blank / avoid_reuse land in the flags record and
getwalletinfo reports Core's fields."
  (with-wallet-test-node (node)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "wo"))
      ;; watch-only + blank + avoid_reuse
      (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
        (bitcoin-lisp.rpc::rpc-createwallet node '("wo" t t nil t)))
      (let ((info (bitcoin-lisp.rpc::rpc-getwalletinfo node nil)))
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
      (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-getnewaddress node nil))))))
    ;; full wallet: keypool counts are per-side
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("full")))
    (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "full")
           (info (bitcoin-lisp.rpc::rpc-getwalletinfo node nil)))
      (is (= 20 (%aval "keypoolsize" info)))               ; 4 external x 5
      (is (= 20 (%aval "keypoolsize_hd_internal" info)))   ; 4 internal x 5
      (is (eq t (%aval "private_keys_enabled" info)))
      (is (integerp (%aval "birthtime" info))))))

;;; --- /wallet/<name> routing ---

(test wallet-endpoint-routing
  "Requests resolve to the endpoint's wallet; Core's error codes for unknown
wallet (-18), no wallet loaded (-18), and ambiguous wallet (-19)."
  ;; URI parsing
  (is (string= "foo" (bitcoin-lisp.rpc::wallet-name-from-uri "/wallet/foo")))
  (is (string= "a b" (bitcoin-lisp.rpc::wallet-name-from-uri "/wallet/a b")))
  (is (null (bitcoin-lisp.rpc::wallet-name-from-uri "/")))
  (is (null (bitcoin-lisp.rpc::wallet-name-from-uri "/wallet/")))
  (is (null (bitcoin-lisp.rpc::wallet-name-from-uri "/walletx/foo")))
  (with-wallet-test-node (node)
    ;; no wallet loaded -> -18
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (is (= bitcoin-lisp.rpc::+rpc-wallet-not-found+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-getwalletinfo node nil)))))
      (bitcoin-lisp.rpc::rpc-createwallet node '("r1"))
      ;; single wallet: base endpoint resolves to it
      (is (string= "r1" (%aval "walletname"
                               (bitcoin-lisp.rpc::rpc-getwalletinfo node nil))))
      (bitcoin-lisp.rpc::rpc-createwallet node '("r2"))
      ;; two wallets: base endpoint is ambiguous -> -19
      (is (= bitcoin-lisp.rpc::+rpc-wallet-not-specified+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-getwalletinfo node nil))))))
    ;; endpoint routing picks the named wallet
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "r2"))
      (is (string= "r2" (%aval "walletname"
                               (bitcoin-lisp.rpc::rpc-getwalletinfo node nil)))))
    ;; unknown wallet endpoint -> -18 with Core's message
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "missing"))
      (handler-case (progn (bitcoin-lisp.rpc::rpc-getwalletinfo node nil)
                           (is nil "expected rpc-error"))
        (bitcoin-lisp.rpc::rpc-error (e)
          (is (= bitcoin-lisp.rpc::+rpc-wallet-not-found+
                 (bitcoin-lisp.rpc::rpc-error-code e)))
          (is (string= "Requested wallet does not exist or is not loaded"
                       (bitcoin-lisp.rpc::rpc-error-message e))))))
    ;; unloadwallet via endpoint (no param)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "r2"))
      (bitcoin-lisp.rpc::rpc-unloadwallet node '()))
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (is (equal '("r1") (bitcoin-lisp.rpc::rpc-listwallets node nil))))))

(test wallet-disabled-node-rejects-wallet-rpcs
  "Without a wallet manager the wallet RPCs report method-not-found, like a
no-wallet Core build."
  (let ((node (bitcoin-lisp::make-node :network :testnet4)))
    (setf (bitcoin-lisp::node-chain-state node)
          (bitcoin-lisp.storage:make-chain-state))
    (is (= bitcoin-lisp.rpc::+rpc-method-not-found+
           (%rpc-error-code
            (lambda () (bitcoin-lisp.rpc::rpc-createwallet node '("x"))))))
    (is (= bitcoin-lisp.rpc::+rpc-method-not-found+
           (%rpc-error-code
            (lambda () (bitcoin-lisp.rpc::rpc-listwallets node nil)))))))

;;; --- getnewaddress across all four types ---

(test wallet-getnewaddress-all-types
  "getnewaddress/getrawchangeaddress issue distinct, IsMine addresses of the
right form for all four address types (testnet4 prefixes), default bech32."
  (with-wallet-test-node (node :keypool 4)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("types"))
      (let ((wallet (gethash "types"
                             (bitcoin-lisp.rpc::wallet-manager-wallets
                              (%node-manager node)))))
        ;; default type is bech32 (Core DEFAULT_ADDRESS_TYPE)
        (let ((address (bitcoin-lisp.rpc::rpc-getnewaddress node nil)))
          (is (string= "tb1q" (subseq address 0 4))))
        (loop for (type . prefix-test)
                in `(("legacy" . ,(lambda (a) (member (char a 0) '(#\m #\n))))
                     ("p2sh-segwit" . ,(lambda (a) (char= (char a 0) #\2)))
                     ("bech32" . ,(lambda (a) (string= "tb1q" (subseq a 0 4))))
                     ("bech32m" . ,(lambda (a) (string= "tb1p" (subseq a 0 4)))))
              do (let ((recv (bitcoin-lisp.rpc::rpc-getnewaddress
                              node (list "" type)))
                       (change (bitcoin-lisp.rpc::rpc-getrawchangeaddress
                                node (list type))))
                   (is (funcall prefix-test recv))
                   (is (funcall prefix-test change))
                   (is (not (string= recv change)))
                   (is (bitcoin-lisp.rpc::wallet-is-mine
                        wallet (%address-script recv :testnet4)))
                   (is (bitcoin-lisp.rpc::wallet-is-mine
                        wallet (%address-script change :testnet4)))))
        ;; unknown type -> -5; label "*" -> -11
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-getnewaddress
                            node '("" "p2wpkh"))))))
        (is (= bitcoin-lisp.rpc::+rpc-wallet-invalid-label-name+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-getnewaddress node '("*"))))))))))

;;; --- listdescriptors / importdescriptors ---

(test wallet-listdescriptors
  "listdescriptors lists all 8 default SPKMs sorted, with range/next fields;
private=true returns xprv-bearing strings; watch-only wallets reject
private=true."
  (with-wallet-test-node (node :keypool 3)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("ld")))
    (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "ld")
           (result (bitcoin-lisp.rpc::rpc-listdescriptors node nil))
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
                               (bitcoin-lisp.rpc::rpc-listdescriptors
                                node '(t)))))
        (is (= 8 (length priv-descs)))
        (dolist (d priv-descs)
          (is (search "tprv" (%aval "desc" d))))))
    ;; watch-only wallet rejects private=true
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("ldwo" t)))
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "ldwo"))
      (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-listdescriptors node '(t)))))))))

(test wallet-importdescriptors-validation
  "importdescriptors returns Core-shaped per-request results: checksum
required, watch-only rules, label/range constraints; a missing timestamp
throws out of the whole call."
  (with-wallet-test-node (node :keypool 3)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("imp"))     ; privkeys enabled
      (bitcoin-lisp.rpc::rpc-createwallet node '("impwo" t t))) ; watch-only blank
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "imp"))
      ;; missing timestamp -> whole-RPC type error
      (is (= bitcoin-lisp.rpc::+rpc-type-error+
             (%rpc-error-code
              (lambda ()
                (bitcoin-lisp.rpc::rpc-importdescriptors
                 node (list (list (%ht "desc" "wpkh(x)"))))))))
      ;; missing checksum -> per-request failure with Core's parse error code
      (let* ((results (bitcoin-lisp.rpc::rpc-importdescriptors
                       node (list (list (%ht "desc" "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
                                             "timestamp" 1))))
                      )
             (err (%aval "error" (first results))))
        (is (eq 'yason:false (%aval "success" (first results))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+ (%aval "code" err)))
        (is (string= "Missing checksum" (%aval "message" err))))
      ;; watch-only descriptor into a privkey wallet -> per-request error
      (let* ((desc (bitcoin-lisp.rpc::descriptor-add-checksum
                    "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"))
             (results (bitcoin-lisp.rpc::rpc-importdescriptors
                       node (list (list (%ht "desc" desc "timestamp" 1)))))
             (err (%aval "error" (first results))))
        (is (= bitcoin-lisp.rpc::+rpc-wallet-error+ (%aval "code" err)))
        (is (search "without private keys" (%aval "message" err)))))
    ;; watch-only wallet accepts public descriptors, stores + reports them
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "impwo"))
      (let* ((xpub "tpubD6NzVbkrYhZ4XqNGAWGWSzmxGWFwVjVTjZxh2fioKbVYi7Jx8fdbprVWsdW7mHwqjchBVas8TLZG4Xwuz4RKU4iaCqiCvoSkFCzQptqk5Y1")
             (desc (bitcoin-lisp.rpc::descriptor-add-checksum
                    (format nil "wpkh(~A/0/*)" xpub)))
             (results (bitcoin-lisp.rpc::rpc-importdescriptors
                       node (list (list (%ht "desc" desc "timestamp" "now"
                                             "active" t "range" 9))))))
        (is (eq t (%aval "success" (first results))))
        ;; the wallet can now hand out watch-only bech32 addresses
        (let ((address (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32"))))
          (is (string= "tb1q" (subseq address 0 4))))
        ;; and listdescriptors shows it active
        (let ((descs (%aval "descriptors"
                            (bitcoin-lisp.rpc::rpc-listdescriptors node nil))))
          (is (= 1 (length descs)))
          (is (eq t (%aval "active" (first descs))))
          (is (equal '(0 9) (%aval "range" (first descs))))))
      ;; importing a private key into the watch-only wallet fails
      (let* ((wif (bitcoin-lisp.crypto:private-key-to-wif
                   (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 7)
                   :network :testnet :compressed t))
             (results (bitcoin-lisp.rpc::rpc-importdescriptors
                       node (list (list (%ht "desc" (bitcoin-lisp.rpc::descriptor-add-checksum
                                                     (format nil "wpkh(~A)" wif))
                                             "timestamp" 1)))))
             (err (%aval "error" (first results))))
        (is (= bitcoin-lisp.rpc::+rpc-wallet-error+ (%aval "code" err)))
        (is (search "private keys disabled" (%aval "message" err)))))))

;;; --- Wallet P7: signmessage (methods.lisp) + received-by / keypoolrefill /
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
  (let* ((tx (bitcoin-lisp.serialization:make-transaction
              :version 2
              :inputs (coerce
                       (mapcar (lambda (in)
                                 (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output
                                  (bitcoin-lisp.serialization:make-outpoint
                                   :hash (car in) :index (cdr in))
                                  :script-sig (make-array 0 :element-type
                                                          '(unsigned-byte 8))
                                  :sequence #xffffffff))
                               inputs)
                       'simple-vector)
              :outputs (coerce
                        (mapcar (lambda (out)
                                  (bitcoin-lisp.serialization:make-tx-out
                                   :value (cdr out) :script-pubkey (car out)))
                                outputs)
                        'simple-vector)
              :lock-time 0))
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 9)))
    (bitcoin-lisp.rpc::wallet-add-to-wallet
     wallet tx (list :confirmed block-hash height 0))
    txid))

(defun %wt-raw-tx-hex (inputs outputs)
  "Wire hex of a v2 tx over INPUTS ((hash . vout) ...) and OUTPUTS
((script . value) ...)."
  (let ((tx (bitcoin-lisp.serialization:make-transaction
             :version 2
             :inputs (coerce
                      (mapcar (lambda (in)
                                (bitcoin-lisp.serialization:make-tx-in
                                 :previous-output
                                 (bitcoin-lisp.serialization:make-outpoint
                                  :hash (car in) :index (cdr in))
                                 :script-sig (make-array 0 :element-type
                                                         '(unsigned-byte 8))
                                 :sequence #xffffffff))
                              inputs)
                      'simple-vector)
             :outputs (coerce
                       (mapcar (lambda (out)
                                 (bitcoin-lisp.serialization:make-tx-out
                                  :value (cdr out) :script-pubkey (car out)))
                               outputs)
                       'simple-vector)
             :lock-time 0)))
    (bitcoin-lisp.crypto:bytes-to-hex
     (bitcoin-lisp.serialization:transaction-wire-bytes tx))))

(test wallet-signmessage-roundtrip
  "signmessage on a legacy (P2PKH) getnewaddress verifies true via
verifymessage; a tampered message verifies false; a valid non-P2PKH (bech32)
address is -3, an undecodable address -5, and a foreign P2PKH address the
wallet does not own -4 (Core wallet/rpc/signmessage.cpp error codes)."
  (with-wallet-test-node (node :keypool 4)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("signer")))
    (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "signer")
           (address (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy")))
           (message "hello from bitcoin-lisp")
           (sig (bitcoin-lisp.rpc::rpc-signmessage node (list address message))))
      (is (stringp sig))
      ;; Round-trips through verifymessage.
      (is (eq t (bitcoin-lisp.rpc::rpc-verifymessage
                 node (list address sig message))))
      ;; A tampered message no longer verifies.
      (is (eq 'yason:false
              (bitcoin-lisp.rpc::rpc-verifymessage
               node (list address sig "a different message"))))
      ;; Valid bech32 address (not a key hash) -> -3.
      (let ((bech32 (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32"))))
        (is (= bitcoin-lisp.rpc::+rpc-type-error+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-signmessage
                            node (list bech32 message)))))))
      ;; Garbage address -> -5.
      (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-signmessage
                          node (list "not-a-real-address" message))))))
      ;; A valid P2PKH address the wallet does not own -> -4.
      (let ((foreign (bitcoin-lisp.crypto:encode-p2pkh-address
                      (make-array 20 :element-type '(unsigned-byte 8)
                                     :initial-element 7)
                      :testnet4)))
        (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-signmessage
                            node (list foreign message))))))))))

(test wallet-received-by-rpcs
  "getreceivedbyaddress/bylabel and listreceivedbyaddress/bylabel tally owned
outputs over mapWallet; unknown address -> -4, garbage -> -5, unknown label
-> -4."
  (with-wallet-test-node (node :keypool 4)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("recv")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "recv"
                            (bitcoin-lisp.rpc::wallet-manager-wallets manager)))
           (bitcoin-lisp.rpc::*rpc-wallet-name* "recv"))
      (setf (bitcoin-lisp.rpc::wallet-last-block-height wallet) 100)
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy")))
             (script (%address-script addr :testnet4)))
        (bitcoin-lisp.rpc::rpc-setlabel node (list addr "L1"))
        ;; Two confirmed receives to the same address: 0.005 + 0.003 BTC.
        (%wt-add-confirmed-tx wallet (list (cons (%wt-dummy-txid 1) 0))
                              (list (cons script 500000)))
        (%wt-add-confirmed-tx wallet (list (cons (%wt-dummy-txid 2) 0))
                              (list (cons script 300000)))
        (is (%wt= 0.008d0 (bitcoin-lisp.rpc::rpc-getreceivedbyaddress
                           node (list addr))))
        (is (%wt= 0.008d0 (bitcoin-lisp.rpc::rpc-getreceivedbylabel
                           node (list "L1"))))
        ;; minconf 200 excludes the depth-1 receives.
        (is (%wt= 0.0d0 (bitcoin-lisp.rpc::rpc-getreceivedbyaddress
                         node (list addr 200))))
        ;; listreceivedbyaddress: one row for addr with both txids.
        (let* ((rows (bitcoin-lisp.rpc::rpc-listreceivedbyaddress node nil))
               (row (find addr rows :key (lambda (r) (%aval "address" r))
                                    :test #'string=)))
          (is (not (null row)))
          (is (%wt= 0.008d0 (%aval "amount" row)))
          (is (string= "L1" (%aval "label" row)))
          (is (= 1 (%aval "confirmations" row)))
          (is (= 2 (length (%aval "txids" row)))))
        ;; listreceivedbylabel: one row for L1.
        (let* ((rows (bitcoin-lisp.rpc::rpc-listreceivedbylabel node nil))
               (row (find "L1" rows :key (lambda (r) (%aval "label" r))
                                    :test #'string=)))
          (is (not (null row)))
          (is (%wt= 0.008d0 (%aval "amount" row))))
        ;; Error codes.
        (let ((foreign (bitcoin-lisp.crypto:encode-p2pkh-address
                        (make-array 20 :element-type '(unsigned-byte 8)
                                       :initial-element 3)
                        :testnet4)))
          (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
                 (%rpc-error-code
                  (lambda () (bitcoin-lisp.rpc::rpc-getreceivedbyaddress
                              node (list foreign)))))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-getreceivedbyaddress
                            node (list "garbage"))))))
        (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-getreceivedbylabel
                            node (list "no-such-label"))))))))))

(test wallet-keypoolrefill-grows-active-spkms
  "keypoolrefill tops every active SPKM up to newsize; a negative size is -8."
  (with-wallet-test-node (node :keypool 5)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("kp")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "kp"
                            (bitcoin-lisp.rpc::wallet-manager-wallets manager)))
           (bitcoin-lisp.rpc::*rpc-wallet-name* "kp")
           (spkm (gethash :bech32
                          (bitcoin-lisp.rpc::wallet-external-spkms wallet))))
      (is (= 5 (bitcoin-lisp.rpc::spkm-keypool-count spkm)))
      (is (null (bitcoin-lisp.rpc::rpc-keypoolrefill node '(20))))
      (is (>= (bitcoin-lisp.rpc::spkm-keypool-count spkm) 20))
      ;; Every active SPKM grew.
      (dolist (s (bitcoin-lisp.rpc::%wallet-active-spkms wallet))
        (is (>= (bitcoin-lisp.rpc::spkm-keypool-count s) 20)))
      (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
             (%rpc-error-code
              (lambda () (bitcoin-lisp.rpc::rpc-keypoolrefill node '(-1)))))))))

(test wallet-simulaterawtransaction-balance-change
  "simulaterawtransaction reports +owned-output and -owned-input deltas, and
rejects a double-spend across the array."
  (with-wallet-test-node (node :keypool 4)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("sim")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "sim"
                            (bitcoin-lisp.rpc::wallet-manager-wallets manager)))
           (bitcoin-lisp.rpc::*rpc-wallet-name* "sim"))
      (setf (bitcoin-lisp.rpc::wallet-last-block-height wallet) 100)
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32")))
             (script (%address-script addr :testnet4))
             (foreign (%address-script
                       (bitcoin-lisp.crypto:encode-p2wpkh-address
                        (make-array 20 :element-type '(unsigned-byte 8)
                                       :initial-element 4)
                        :testnet4)
                       :testnet4)))
        ;; A pure receive to an owned script: +0.007.
        (let ((result (bitcoin-lisp.rpc::rpc-simulaterawtransaction
                       node (list (list (%wt-raw-tx-hex
                                         (list (cons (%wt-dummy-txid 5) 0))
                                         (list (cons script 700000))))))))
          (is (%wt= 0.007d0 (%aval "balance_change" result))))
        ;; Fund an owned coin, then spend it to a foreign output: -0.01.
        (let ((funded (%wt-add-confirmed-tx
                       wallet (list (cons (%wt-dummy-txid 6) 0))
                       (list (cons script 1000000)))))
          (let ((result (bitcoin-lisp.rpc::rpc-simulaterawtransaction
                         node (list (list (%wt-raw-tx-hex
                                           (list (cons funded 0))
                                           (list (cons foreign 900000))))))))
            (is (%wt= -0.01d0 (%aval "balance_change" result))))
          ;; Two txs spending the same funded coin -> -8.
          (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
                 (%rpc-error-code
                  (lambda ()
                    (bitcoin-lisp.rpc::rpc-simulaterawtransaction
                     node (list (list (%wt-raw-tx-hex (list (cons funded 0))
                                                      (list (cons foreign 900000)))
                                      (%wt-raw-tx-hex (list (cons funded 0))
                                                      (list (cons foreign 800000)))))))))))))))

(test wallet-listaddressgroupings-clusters
  "listaddressgroupings clusters addresses co-spent as inputs of one tx and
keeps an unrelated lone address in its own group."
  (with-wallet-test-node (node :keypool 5)
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("grp")))
    (let* ((manager (%node-manager node))
           (wallet (gethash "grp"
                            (bitcoin-lisp.rpc::wallet-manager-wallets manager)))
           (bitcoin-lisp.rpc::*rpc-wallet-name* "grp"))
      (setf (bitcoin-lisp.rpc::wallet-last-block-height wallet) 100)
      (let* ((addr1 (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy")))
             (addr2 (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy")))
             (addr3 (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy")))
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
        (let* ((groups (bitcoin-lisp.rpc::rpc-listaddressgroupings node nil))
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
;;; %with-wallet-chain-node / %ws-fund-wallet fixtures are not yet defined here;
;;; this section carries its own %pp-* equivalents built on the
;;; %regtest-node-fixture + %with-regtest primitives (mining-tests.lisp).
;;; ==============================================================

(defvar *pp-counter* 0)

(defun %pp-optrue-address ()
  (bitcoin-lisp.crypto:encode-p2sh-address
   (bitcoin-lisp.crypto:hash160 +optrue-redeem+) :regtest))

(defun %pp-fixture (suffix &key (keypool 5))
  "A regtest node at genesis with a wallet manager + genesis block stored."
  (let* ((id (format nil "~A-~D-~D" suffix (get-universal-time) (incf *pp-counter*)))
         (node (%regtest-node-fixture (format nil "pp-~A" id)))
         (wallet-dir (merge-pathnames (format nil "pp-wallet-~A/" id)
                                      (uiop:temporary-directory))))
    (bitcoin-lisp.storage:store-block
     (bitcoin-lisp::node-block-store node)
     (bitcoin-lisp.storage:make-genesis-block :regtest))
    (setf (bitcoin-lisp::node-wallet-manager node)
          (bitcoin-lisp.rpc::make-wallet-manager
           :data-directory wallet-dir :network :regtest :keypool-size keypool))
    node))

(defmacro %with-pp-node ((node suffix) &body body)
  "BODY under regtest bindings with NODE a %pp-fixture and bitcoin-lisp::*node*
bound so the wallet chain hooks fire."
  `(%with-regtest
    (let* ((,node (%pp-fixture ,suffix))
           (bitcoin-lisp::*node* ,node))
      (unwind-protect (progn ,@body)
        (ignore-errors
         (bitcoin-lisp.rpc:close-wallet-manager
          (bitcoin-lisp::node-wallet-manager ,node)))))))

(defun %pp-mine (node n address)
  (bitcoin-lisp.rpc::rpc-generatetoaddress node (list n address)))

(defun %pp-fund-wallet (node &key (blocks 1))
  "createwallet \"w\", mine BLOCKS coinbases to a fresh bech32 (P2WPKH) address,
mature them. Returns the wallet."
  (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
  (let* ((wallet (gethash "w" (bitcoin-lisp.rpc::wallet-manager-wallets
                               (bitcoin-lisp::node-wallet-manager node))))
         (address (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32"))))
    (dotimes (i blocks) (%pp-mine node 1 address))
    (%pp-mine node 101 (%pp-optrue-address))
    wallet))

(defun %pp-mempool-tx (node txid)
  (bitcoin-lisp.rpc::with-node-lock (node)
    (let* ((mp (bitcoin-lisp::node-mempool node))
           (e (and mp (bitcoin-lisp.mempool:mempool-get mp txid))))
      (and e (bitcoin-lisp.mempool:mempool-entry-transaction e)))))

(defun %pp-verify-ok-p (node wallet tx)
  (bitcoin-lisp.rpc::with-node-lock (node)
    (bitcoin-lisp.rpc::with-wallet-lock (wallet)
      (let ((coins (bitcoin-lisp.rpc::%wallet-input-coins node wallet tx)))
        (nth-value 0 (bitcoin-lisp.rpc::%verify-tx-scripts tx coins))))))

(defun %pp-input-outpoints (tx)
  (map 'list (lambda (in)
               (let ((op (bitcoin-lisp.serialization:tx-in-previous-output in)))
                 (cons (bitcoin-lisp.serialization:outpoint-hash op)
                       (bitcoin-lisp.serialization:outpoint-index op))))
       (bitcoin-lisp.serialization:transaction-inputs tx)))

(test pp-walletcreatefundedpsbt-roundtrip
  "walletcreatefundedpsbt funds an UNSIGNED PSBT (witness_utxo + bip32 derivs per
input, no sigs); walletprocesspsbt signs + finalizes it into a valid network tx
that our own script verifier accepts and the mempool relays."
  (%with-pp-node (node "pp-wcfp")
    (let ((wallet (%pp-fund-wallet node)))
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 42))
             (dest (%pp-optrue-address))
             (created (bitcoin-lisp.rpc::rpc-walletcreatefundedpsbt
                       node (list '() (list (%ht dest 1))
                                  0 (%ht "fee_rate" 5))))
             (b64 (%aval "psbt" created)))
        (is (stringp b64))
        (is (> (%aval "fee" created) 0))
        ;; The created PSBT is unsigned: every input has a witness_utxo + bip32
        ;; derivation but no partial sigs and no final scripts.
        (let ((psbt (bitcoin-lisp.serialization:decode-psbt b64)))
          (is (> (length (bitcoin-lisp.serialization:psbt-inputs psbt)) 0))
          (loop for m across (bitcoin-lisp.serialization:psbt-inputs psbt)
                do (is-true (bitcoin-lisp.serialization:psbt-map-find
                             m bitcoin-lisp.serialization:+psbt-in-witness-utxo+))
                   (is-true (bitcoin-lisp.serialization:psbt-map-find
                             m bitcoin-lisp.serialization:+psbt-in-bip32+))
                   (is (null (bitcoin-lisp.serialization:psbt-map-collect
                              m bitcoin-lisp.serialization:+psbt-in-partial-sig+)))
                   (is (null (bitcoin-lisp.serialization:psbt-map-find
                              m bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)))))
        ;; walletprocesspsbt (defaults: sign + finalize) completes it.
        (let* ((processed (bitcoin-lisp.rpc::rpc-walletprocesspsbt node (list b64)))
               (hex (%aval "hex" processed)))
          (is (eq t (%aval "complete" processed)))
          (is (stringp hex))
          (let ((tx (bitcoin-lisp.serialization:parse-tx-payload
                     (bitcoin-lisp.crypto:hex-to-bytes hex))))
            (is (%pp-verify-ok-p node wallet tx))
            ;; The extracted tx relays.
            (is (stringp (bitcoin-lisp.rpc::rpc-sendrawtransaction node (list hex))))))))))

(test pp-walletprocesspsbt-sign-false-then-sign
  "walletprocesspsbt with sign=false only fills data (no sigs, incomplete); a
second call with sign=true (default) completes it."
  (%with-pp-node (node "pp-signflag")
    (%pp-fund-wallet node)
    (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 99))
           (dest (%pp-optrue-address))
           (b64 (%aval "psbt" (bitcoin-lisp.rpc::rpc-walletcreatefundedpsbt
                               node (list '() (list (%ht dest 1)) 0 (%ht "fee_rate" 5)))))
           ;; sign=false, finalize=false: no partial sigs, incomplete.
           (unsigned (bitcoin-lisp.rpc::rpc-walletprocesspsbt
                      node (list b64 bitcoin-lisp.rpc:+json-false+ nil nil
                                 bitcoin-lisp.rpc:+json-false+))))
      (is (eq bitcoin-lisp.rpc:+json-false+ (%aval "complete" unsigned)))
      (let ((psbt (bitcoin-lisp.serialization:decode-psbt (%aval "psbt" unsigned))))
        (loop for m across (bitcoin-lisp.serialization:psbt-inputs psbt)
              do (is (null (bitcoin-lisp.serialization:psbt-map-collect
                            m bitcoin-lisp.serialization:+psbt-in-partial-sig+)))))
      ;; Now sign (defaults) -> complete + extractable.
      (let ((signed (bitcoin-lisp.rpc::rpc-walletprocesspsbt
                     node (list (%aval "psbt" unsigned)))))
        (is (eq t (%aval "complete" signed)))
        (is (stringp (%aval "hex" signed)))))))

(test pp-bumpfee-rbf-chain
  "bumpfee rebuilds a higher-feerate replacement re-spending ALL original inputs,
signs + broadcasts it (RBF-evicting the original), records replaced_by_txid, and
refuses to bump an already-bumped tx."
  (%with-pp-node (node "pp-bump")
    (let ((wallet (%pp-fund-wallet node :blocks 2)))
      (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 7))
             (dest (%pp-optrue-address))
             (txid-hex (bitcoin-lisp.rpc::rpc-sendtoaddress
                        node (list dest 1 nil nil nil nil nil nil nil 5)))
             (txid (bitcoin-lisp.rpc::parse-hex-hash txid-hex))
             (orig-tx (%pp-mempool-tx node txid)))
        (is (not (null orig-tx)))
        (let ((orig-inputs (%pp-input-outpoints orig-tx))
              (result (bitcoin-lisp.rpc::rpc-bumpfee
                       node (list txid-hex (%ht "fee_rate" 20)))))
          (let* ((new-txid-hex (%aval "txid" result))
                 (new-tx (%pp-mempool-tx node (bitcoin-lisp.rpc::parse-hex-hash new-txid-hex))))
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
            (let ((owtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid)))
              (is (string= new-txid-hex
                           (cdr (assoc "replaced_by_txid"
                                       (bitcoin-lisp.rpc::wallet-tx-map-value owtx)
                                       :test #'string=)))))
            ;; Cannot bump the same (already-bumped) tx again.
            (signals bitcoin-lisp.rpc::rpc-error
              (bitcoin-lisp.rpc::rpc-bumpfee node (list txid-hex (%ht "fee_rate" 40))))))))))

(test pp-psbtbumpfee-unsigned
  "psbtbumpfee returns an UNSIGNED PSBT of the replacement without broadcasting;
the original stays in the mempool, and walletprocesspsbt completes the PSBT."
  (%with-pp-node (node "pp-psbtbump")
    (%pp-fund-wallet node :blocks 2)
    (let* ((bitcoin-lisp.rpc::*wallet-rng* (bitcoin-lisp.rpc::make-wrng 13))
           (dest (%pp-optrue-address))
           (txid-hex (bitcoin-lisp.rpc::rpc-sendtoaddress
                      node (list dest 1 nil nil nil nil nil nil nil 5)))
           (txid (bitcoin-lisp.rpc::parse-hex-hash txid-hex))
           (result (bitcoin-lisp.rpc::rpc-psbtbumpfee
                    node (list txid-hex (%ht "fee_rate" 20))))
           (b64 (%aval "psbt" result)))
      (is (stringp b64))
      (is (> (%aval "fee" result) (%aval "origfee" result)))
      ;; The returned PSBT is unsigned but carries witness_utxo per input.
      (let ((psbt (bitcoin-lisp.serialization:decode-psbt b64)))
        (loop for m across (bitcoin-lisp.serialization:psbt-inputs psbt)
              do (is (null (bitcoin-lisp.serialization:psbt-map-find
                            m bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)))
                 (is (null (bitcoin-lisp.serialization:psbt-map-collect
                            m bitcoin-lisp.serialization:+psbt-in-partial-sig+)))
                 (is-true (bitcoin-lisp.serialization:psbt-map-find
                           m bitcoin-lisp.serialization:+psbt-in-witness-utxo+))))
      ;; The original is untouched (psbtbumpfee does not broadcast).
      (is (not (null (%pp-mempool-tx node txid))))
      ;; walletprocesspsbt completes the replacement PSBT into a network tx.
      (let ((processed (bitcoin-lisp.rpc::rpc-walletprocesspsbt node (list b64))))
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
  (bitcoin-lisp.rpc::wallet-manager-data-directory (%node-manager node)))

(defun %wallet-settings-path (node)
  (bitcoin-lisp.rpc::settings-json-path (%wallet-settings-dir node)))

(defun %wallet-settings-raw (node)
  "Parsed settings.json, or NIL when the file does not exist."
  (let ((path (%wallet-settings-path node)))
    (when (probe-file path)
      (with-open-file (s path :direction :input :external-format :utf-8)
        (yason:parse s)))))

(defun %startup-names (node)
  (bitcoin-lisp.rpc::wallet-startup-names (%wallet-settings-dir node)))

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
    (bitcoin-lisp.rpc:close-wallet-manager (%node-manager node))
    (setf (bitcoin-lisp::node-wallet-manager node)
          (bitcoin-lisp.rpc::make-wallet-manager
           :data-directory dir :network :testnet4 :keypool-size 5))))

(defun %loaded-wallet-names (node)
  (coerce (bitcoin-lisp.rpc::rpc-listwallets node nil) 'list))

(test g7-04-load-on-startup-is-tristate
  "load_on_startup is Core's std::optional<bool> (wallet.cpp:124-135):
omitted/null leaves the setting untouched, true records the wallet, false
removes it. Only an explicit value writes anything."
  (with-wallet-test-node (node)
    ;; Omitted: no setting recorded, and no settings.json written at all.
    (bitcoin-lisp.rpc::rpc-createwallet node '("plain"))
    (is (null (%startup-names node)))
    (is (null (%wallet-settings-raw node))
        "a no-op update must not create settings.json")
    ;; Explicit true records it.
    (bitcoin-lisp.rpc::rpc-createwallet node (list "auto" nil nil nil nil nil t))
    (is (equal '("auto") (%startup-names node)))
    ;; Explicit null on an already-recorded wallet leaves it recorded.
    (bitcoin-lisp.rpc::rpc-unloadwallet node '("auto"))
    (is (equal '("auto") (%startup-names node)))
    (bitcoin-lisp.rpc::rpc-loadwallet node '("auto"))
    (is (equal '("auto") (%startup-names node)))
    ;; Explicit false removes it.
    (bitcoin-lisp.rpc::rpc-unloadwallet
     node (list "auto" bitcoin-lisp.rpc::+json-false+))
    (is (null (%startup-names node)))
    ;; loadwallet with true records a wallet created without it.
    (bitcoin-lisp.rpc::rpc-unloadwallet node '("plain"))
    (bitcoin-lisp.rpc::rpc-loadwallet node '("plain" t))
    (is (equal '("plain") (%startup-names node)))))

(test g7-04-settings-store-semantics
  "Add/remove mirror Core AddWalletSetting/RemoveWalletSetting: duplicate adds
and absent removes are SKIP_WRITE no-ops that still report success, and file
order is preserved."
  (with-wallet-test-node (node)
    (let ((dir (%wallet-settings-dir node)))
      (is (bitcoin-lisp.rpc::update-wallet-setting dir "a" :true))
      (is (bitcoin-lisp.rpc::update-wallet-setting dir "a" :true))
      (is (equal '("a") (bitcoin-lisp.rpc::wallet-startup-names dir))
          "adding twice must not duplicate the entry")
      (bitcoin-lisp.rpc::update-wallet-setting dir "b" :true)
      (bitcoin-lisp.rpc::update-wallet-setting dir "c" :true)
      (is (equal '("a" "b" "c") (bitcoin-lisp.rpc::wallet-startup-names dir)))
      (is (bitcoin-lisp.rpc::update-wallet-setting dir "nosuch" :false)
          "removing an absent name is a successful no-op")
      (is (equal '("a" "b" "c") (bitcoin-lisp.rpc::wallet-startup-names dir)))
      (bitcoin-lisp.rpc::update-wallet-setting dir "b" :false)
      (is (equal '("a" "c") (bitcoin-lisp.rpc::wallet-startup-names dir))
          "removal from the middle keeps the rest in order")
      ;; NIL action never touches the file.
      (is (bitcoin-lisp.rpc::update-wallet-setting dir "zzz" nil))
      (is (equal '("a" "c") (bitcoin-lisp.rpc::wallet-startup-names dir))))))

(test g7-04-settings-preserves-other-keys
  "settings.json is node-wide in Core, so a wallet update must rewrite only
the \"wallet\" key and leave every other setting intact. The list is written
as a JSON array, not an object."
  (with-wallet-test-node (node)
    (%write-raw-settings node "{\"prune\":1234,\"other\":[\"x\",\"y\"]}")
    (is (bitcoin-lisp.rpc::update-wallet-setting (%wallet-settings-dir node) "w" :true))
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
      (is (null (bitcoin-lisp.rpc::update-wallet-setting
                 (%wallet-settings-dir node) "w" :true))
          "an update against corrupt settings must report failure")
      (is (string= garbage
                   (with-open-file (s (%wallet-settings-path node)) (read-line s)))
          "the corrupt file must be left exactly as found")
      ;; A NIL action has nothing to write, so it still succeeds.
      (is (bitcoin-lisp.rpc::update-wallet-setting
           (%wallet-settings-dir node) "w" nil)))))

(test g7-04-failed-update-returns-core-warning
  "Core surfaces a warning rather than failing the RPC when the setting cannot
be persisted (wallet.cpp:131-133)."
  (with-wallet-test-node (node)
    (%write-raw-settings node "{ corrupt")
    (let* ((result (bitcoin-lisp.rpc::rpc-createwallet
                    node (list "w" nil nil nil nil nil t)))
           (warnings (%aval "warnings" result)))
      (is (string= "w" (%aval "name" result)) "the wallet is still created")
      (is (member "Wallet load on startup setting could not be updated, so wallet may not be loaded next node startup."
                  warnings :test #'string=)))))

(test g7-04-wallets-auto-load-at-startup
  "THE BUG: a restart dropped every wallet. A wallet recorded with
load_on_startup must come back by itself; one that was not recorded must not."
  (with-wallet-test-node (node)
    (bitcoin-lisp.rpc::rpc-createwallet node (list "keeper" nil nil nil nil nil t))
    (bitcoin-lisp.rpc::rpc-createwallet node '("transient"))
    (is (equal '("keeper" "transient") (%loaded-wallet-names node)))
    (%restart-wallet-manager node)
    (is (null (%loaded-wallet-names node))
        "the restart must start with nothing loaded")
    (bitcoin-lisp.rpc:load-wallets-on-startup node)
    (is (equal '("keeper") (%loaded-wallet-names node))
        "only the wallet recorded for startup comes back")))

(test g7-04-startup-skips-unloadable-wallet
  "DELIBERATE divergence from Core, which aborts startup with an init error
when a listed wallet fails to load. The node runs under a respawn supervisor,
so aborting would turn one bad wallet into an endless restart loop with no
node at all. A failure is logged and the remaining wallets still load — and
the broken entry is listed FIRST here, so this fails if the loop aborts."
  (with-wallet-test-node (node)
    (bitcoin-lisp.rpc::rpc-createwallet node '("good"))
    (let ((dir (%wallet-settings-dir node)))
      (bitcoin-lisp.rpc::update-wallet-setting dir "ghost" :true)
      (bitcoin-lisp.rpc::update-wallet-setting dir "good" :true)
      (is (equal '("ghost" "good") (bitcoin-lisp.rpc::wallet-startup-names dir))))
    (%restart-wallet-manager node)
    (bitcoin-lisp.rpc:load-wallets-on-startup node)
    (is (equal '("good") (%loaded-wallet-names node))
        "a wallet listed before a broken one must still load")))
