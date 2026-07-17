(in-package #:bitcoin-lisp.rpc)

;;; Wallet P1: wallet container + descriptor keystore (docs/wallet-plan.md §5 P1)
;;;
;;; Ports, from Bitcoin Core @ d3056bc:
;;;  - DescriptorScriptPubKeyMan (src/wallet/scriptpubkeyman.{h:275,cpp}):
;;;    one descriptor + persistent expansion cache per SPKM, the
;;;    script→range-index map behind IsMine, TopUp keypool maintenance
;;;    (cpp:1001) and GetNewDestination (cpp:824).
;;;  - CWallet's SPKM registry + the 8 default descriptor SPKMs
;;;    (wallet.cpp:3594-3685, walletutil.cpp:35-86).
;;;  - Multiwallet RPC routing by /wallet/<name> URL path (httprpc.cpp:340,
;;;    wallet/rpc/util.cpp:19-85) and the wallet management RPCs
;;;    (wallet/rpc/wallet.cpp, addresses.cpp, backup.cpp).
;;;
;;; Chain tracking (mapWallet/TxState/rescan) is wallet P2, in wallet-tx.lisp;
;;; encryption is P6.
;;;
;;; Locking: each wallet carries its own recursive lock (cs_wallet
;;; equivalent). Order: node-lock -> wallet-manager lock -> wallet lock,
;;; never the reverse — handlers that need chain state read it under the
;;; node-lock BEFORE touching wallet state.

;;; --- Wallet RPC error codes (Core rpc/protocol.h:71-86) ---

(defconstant +rpc-wallet-error+ -4)
(defconstant +rpc-wallet-invalid-label-name+ -11)
(defconstant +rpc-wallet-keypool-ran-out+ -12)
(defconstant +rpc-wallet-not-found+ -18)
(defconstant +rpc-wallet-not-specified+ -19)
(defconstant +rpc-wallet-already-loaded+ -35)
(defconstant +rpc-wallet-already-exists+ -36)

;;; --- Wallet flags (Core wallet/walletutil.h WalletFlags) ---

(defconstant +wallet-flag-avoid-reuse+ (ash 1 0))
(defconstant +wallet-flag-key-origin-metadata+ (ash 1 1))
(defconstant +wallet-flag-last-hardened-xpub-cached+ (ash 1 2))
(defconstant +wallet-flag-disable-private-keys+ (ash 1 32))
(defconstant +wallet-flag-blank-wallet+ (ash 1 33))
(defconstant +wallet-flag-descriptors+ (ash 1 34))
(defconstant +wallet-flag-external-signer+ (ash 1 35))

(defconstant +known-wallet-flags+
  (logior +wallet-flag-avoid-reuse+ +wallet-flag-blank-wallet+
          +wallet-flag-key-origin-metadata+ +wallet-flag-last-hardened-xpub-cached+
          +wallet-flag-disable-private-keys+ +wallet-flag-descriptors+
          +wallet-flag-external-signer+))

(defparameter +wallet-flag-names+
  `((,+wallet-flag-avoid-reuse+ . "avoid_reuse")
    (,+wallet-flag-blank-wallet+ . "blank")
    (,+wallet-flag-key-origin-metadata+ . "key_origin_metadata")
    (,+wallet-flag-last-hardened-xpub-cached+ . "last_hardened_xpub_cached")
    (,+wallet-flag-disable-private-keys+ . "disable_private_keys")
    (,+wallet-flag-descriptors+ . "descriptor_wallet")
    (,+wallet-flag-external-signer+ . "external_signer"))
  "Core wallet.h WALLET_FLAG_TO_STRING.")

(defconstant +default-keypool-size+ 1000
  "Core scriptpubkeyman.h:63 DEFAULT_KEYPOOL_SIZE.")

(defconstant +wallet-client-version+ 309900
  "Written to the 'version' record on wallet creation (Core writes
CLIENT_VERSION; 30.99.0 at d3056bc).")

(defconstant +wallet-legacy-version+ 169900
  "getwalletinfo's deprecated walletversion field: Core reports the latest
legacy minversion 169900 for backwards compatibility (rpc/wallet.cpp:86-90).")

;;; --- Output types (Core outputtype.{h,cpp}) ---

(defparameter +output-types+ '(:legacy :p2sh-segwit :bech32 :bech32m)
  "OUTPUT_TYPES in enum order (codes 0-3); the createwallet SPKM set iterates
these for both external and internal (wallet.cpp:3595-3602).")

(defun %output-type-code (type)
  (or (position type +output-types+)
      (error "unknown output type ~S" type)))

(defun %output-type-from-code (code)
  (nth code +output-types+))

(defun %parse-output-type (string)
  "Core ParseOutputType: legacy / p2sh-segwit / bech32 / bech32m, else NIL."
  (cond ((equal string "legacy") :legacy)
        ((equal string "p2sh-segwit") :p2sh-segwit)
        ((equal string "bech32") :bech32)
        ((equal string "bech32m") :bech32m)))

(defun %format-output-type (type)
  (string-downcase (symbol-name type)))

(defun out-desc-output-type (desc)
  "Core Descriptor::GetOutputType: the OutputType a descriptor's scripts pay
to, or NIL when it has none (bare pk/multi/combo)."
  (case (out-desc-kind desc)
    (:pkh :legacy)
    (:wpkh :bech32)
    (:sh (if (member (out-desc-kind (out-desc-sub desc)) '(:wpkh :wsh))
             :p2sh-segwit
             :legacy))
    (:wsh :bech32)
    ((:tr :rawtr) :bech32m)
    (t nil)))

(defun out-desc-single-type-p (desc)
  "Core IsSingleType: false only for combo()."
  (not (eq (out-desc-kind desc) :combo)))

;;; --- Structures ---

(defstruct desc-spkm
  "A DescriptorScriptPubKeyMan (Core scriptpubkeyman.h:275): one wallet
descriptor with its keypool window, persistent expansion cache, IsMine script
map, and the descriptor's private keys."
  (id nil)                       ; 32-byte DescriptorID
  (desc nil)                     ; parsed out-desc (public form)
  (desc-string "" :type string)  ; canonical public descriptor incl. checksum
  (creation-time 0 :type (unsigned-byte 64))
  (range-start 0 :type (signed-byte 32))
  (range-end 0 :type (signed-byte 32))    ; exclusive; grows with TopUp
  (next-index 0 :type (signed-byte 32))   ; next position to hand out
  (cache (make-descriptor-cache))
  ;; script bytes -> descriptor range index (Core m_map_script_pub_keys —
  ;; the IsMine hash lookup)
  (script-map (make-hash-table :test 'equalp) :type hash-table)
  ;; pubkey bytes -> descriptor range index (Core m_map_pubkeys)
  (pubkey-map (make-hash-table :test 'equalp) :type hash-table)
  (max-cached-index -1 :type (signed-byte 32))
  ;; keyid (hash160 of pubkey) -> (priv32 . compressed-p) (Core m_map_keys)
  (keys (make-hash-table :test 'equalp) :type hash-table))

(defstruct wallet
  "A loaded wallet (Core CWallet: P1 keystore + P2 chain tracking)."
  (name "" :type string)
  (path nil)                     ; wallet directory pathname
  (db nil)                       ; LevelDB handle
  (lock (bt:make-recursive-lock "cs-wallet"))
  (network :testnet4 :type keyword)
  (flags 0 :type (unsigned-byte 64))
  (keypool-size +default-keypool-size+ :type (integer 1))
  (spkms (make-hash-table :test 'equalp) :type hash-table)          ; id -> spkm
  (external-spkms (make-hash-table :test 'eql) :type hash-table)    ; type -> spkm
  (internal-spkms (make-hash-table :test 'eql) :type hash-table)
  (orderposnext 0 :type integer)
  (locked-utxos '() :type list)  ; (txid . n) pairs from lockedutxo records
  (last-block-hash nil)          ; 32-byte wire-order hash, or NIL
  (last-block-height 0 :type integer)
  ;; --- Chain tracking (wallet P2) ---
  (map-wallet (make-hash-table :test 'equalp) :type hash-table)  ; txid -> wallet-tx
  (tx-ordered (make-array 0 :adjustable t :fill-pointer 0)
   :type vector)                                                 ; wtxOrdered (nOrderPos ascending)
  (txos (make-hash-table :test 'equalp) :type hash-table)        ; outpoint key -> (wtx . n), Core m_txos
  (tx-spends (make-hash-table :test 'equalp) :type hash-table)   ; outpoint key -> spender txids, Core mapTxSpends
  (address-book (make-hash-table :test 'equal) :type hash-table) ; address -> (label . purpose)
  (birth-time most-positive-fixnum :type integer)                ; Core m_birth_time
  (chain-time-max 0 :type integer)   ; running max block time over processed blocks
  (loaded-locator '() :type list)    ; bestblock locator hashes read at load
  (scanning-since nil)               ; unix time a rescan started, or NIL (reserver)
  (scan-progress 0.0)
  (abort-rescan nil))

(defmacro with-wallet-lock ((wallet) &body body)
  "Execute BODY holding WALLET's recursive cs_wallet-equivalent lock. Never
acquire the node-lock inside this — lock order is node -> manager -> wallet."
  `(bt:with-recursive-lock-held ((wallet-lock ,wallet))
     ,@body))

(defstruct wallet-manager
  "Owns the set of loaded wallets for a node; RPCs resolve wallets by name
through it (Core WalletContext)."
  (data-directory nil)
  (network :testnet4 :type keyword)
  (keypool-size +default-keypool-size+ :type (integer 1))
  (wallets (make-hash-table :test 'equal) :type hash-table)  ; name -> wallet
  (wallet-order '() :type list)                              ; names, load order
  (lock (bt:make-recursive-lock "wallet-manager")))

(defun wallet-flag-set-p (wallet flag)
  (logtest (wallet-flags wallet) flag))

(defun wallet-manager-has-wallets-p (manager)
  "T when at least one wallet is loaded. Lock-free fast-path gate for the
per-block/per-tx chain hooks: a stale read only skips or enters the (locked)
fan-out one event early or late."
  (plusp (hash-table-count (wallet-manager-wallets manager))))

(defun wallets-directory (manager)
  (merge-pathnames "wallets/" (uiop:ensure-directory-pathname
                               (wallet-manager-data-directory manager))))

(defun wallet-directory (manager name)
  (merge-pathnames (concatenate 'string name "/") (wallets-directory manager)))

(defun %valid-wallet-name-p (name)
  "Wallet names name a subdirectory of <datadir>/wallets/. We restrict them
to a safe character set ([A-Za-z0-9._-], not . or ..) rather than supporting
Core's create-at-arbitrary-path form."
  (and (stringp name)
       (plusp (length name))
       (not (member name '("." "..") :test #'string=))
       (every (lambda (ch)
                (or (alphanumericp ch) (member ch '(#\. #\_ #\-))))
              name)))

;;; --- SPKM key management ---

(defun spkm-privkey-provider (spkm)
  "keyid -> 32-byte secret lookup over the SPKM's key map (the SigningProvider
Core threads into descriptor expansion)."
  (let ((keys (desc-spkm-keys spkm)))
    (lambda (keyid)
      (car (gethash keyid keys)))))

(defun spkm-have-private-keys-p (spkm)
  (plusp (hash-table-count (desc-spkm-keys spkm))))

(defun spkm-add-key (wallet spkm priv32 pubkey compressed-p &key batch)
  "Add a descriptor private key and persist its walletdescriptorkey record
(Core AddDescriptorKeyWithDB, scriptpubkeyman.cpp:1103-1133). No-op when the
key is already present."
  (let ((keyid (bitcoin-lisp.crypto:hash160 pubkey)))
    (unless (gethash keyid (desc-spkm-keys spkm))
      (setf (gethash keyid (desc-spkm-keys spkm)) (cons priv32 compressed-p))
      (let ((key (wdb-key-descriptor-key +wdb-key-walletdescriptorkey+
                                         (desc-spkm-id spkm) pubkey))
            (value (wdb-descriptor-key-value
                    pubkey (privkey-to-der priv32 compressed-p))))
        (if batch
            (bitcoin-lisp.storage:leveldb-writebatch-put batch key value)
            (bitcoin-lisp.storage:leveldb-put (wallet-db wallet) key value
                                              :sync t)))))
  t)

;;; --- SPKM persistence helpers ---

(defun %spkm-descriptor-record (spkm)
  (values (wdb-key-descriptor (desc-spkm-id spkm))
          (wdb-descriptor-value (desc-spkm-desc-string spkm)
                                (desc-spkm-creation-time spkm)
                                (desc-spkm-next-index spkm)
                                (desc-spkm-range-start spkm)
                                (desc-spkm-range-end spkm))))

(defun spkm-write-descriptor (wallet spkm &key batch)
  "Persist the SPKM's WalletDescriptor record (Core WriteDescriptor). Without
BATCH the write is synchronous+fsynced — GetNewDestination relies on the
next_index landing on disk BEFORE the address is handed out."
  (multiple-value-bind (key value) (%spkm-descriptor-record spkm)
    (if batch
        (bitcoin-lisp.storage:leveldb-writebatch-put batch key value)
        (bitcoin-lisp.storage:leveldb-put (wallet-db wallet) key value :sync t))))

(defun %spkm-write-cache-diff (spkm diff batch)
  "Queue walletdescriptorcache/-lhcache records for the new entries in DIFF
(Core WriteDescriptorCacheItems, walletdb.cpp:266-287)."
  (let ((id (desc-spkm-id spkm)))
    (maphash (lambda (expr-index xpub)
               (bitcoin-lisp.storage:leveldb-writebatch-put
                batch
                (wdb-key-descriptor-parent-cache +wdb-key-walletdescriptorcache+
                                                 id expr-index)
                (wdb-xpub-value xpub)))
             (descriptor-cache-parent-xpubs diff))
    (maphash (lambda (expr-index inner)
               (maphash (lambda (der-index xpub)
                          (bitcoin-lisp.storage:leveldb-writebatch-put
                           batch
                           (wdb-key-descriptor-derived-cache id expr-index der-index)
                           (wdb-xpub-value xpub)))
                        inner))
             (descriptor-cache-derived-xpubs diff))
    (maphash (lambda (expr-index xpub)
               (bitcoin-lisp.storage:leveldb-writebatch-put
                batch
                (wdb-key-descriptor-parent-cache +wdb-key-walletdescriptorlhcache+
                                                 id expr-index)
                (wdb-xpub-value xpub)))
             (descriptor-cache-last-hardened-xpubs diff))))

;;; --- TopUp (Core DescriptorScriptPubKeyMan::TopUpWithDB, scriptpubkeyman.cpp:1001) ---

(defun %spkm-note-expansion (spkm index scripts pubkeys)
  "Record one range position's expansion into the IsMine script map and the
pubkey map."
  (dolist (script scripts)
    (setf (gethash script (desc-spkm-script-map spkm)) index))
  (dolist (pk pubkeys)
    ;; Any index at which the pubkey can be derived is fine (Core comment).
    (unless (gethash pk (desc-spkm-pubkey-map spkm))
      (setf (gethash pk (desc-spkm-pubkey-map spkm)) index))))

(defun %spkm-top-up-into (wallet spkm size batch)
  "TopUp body writing its records into BATCH; see spkm-top-up."
  (let* ((target (if (plusp size) size (wallet-keypool-size wallet)))
         (new-range-end (max (+ (desc-spkm-next-index spkm) target)
                             (desc-spkm-range-end spkm))))
    ;; A non-ranged descriptor just fills its single cache slot.
    (unless (out-desc-ranged-p (desc-spkm-desc spkm))
      (setf new-range-end 1
            (desc-spkm-range-end spkm) 1
            (desc-spkm-range-start spkm) 0))
    (let ((provider (and (spkm-have-private-keys-p spkm)
                         (spkm-privkey-provider spkm))))
      (loop for i from (1+ (desc-spkm-max-cached-index spkm)) below new-range-end
            do (multiple-value-bind (scripts pubkeys)
                   (out-desc-expand-from-cache (desc-spkm-desc spkm) i
                                               (desc-spkm-cache spkm))
                 (unless scripts
                   (let ((temp-cache (make-descriptor-cache)))
                     (handler-case
                         (multiple-value-setq (scripts pubkeys)
                           (out-desc-expand-with-provider
                            (desc-spkm-desc spkm) i provider temp-cache))
                       (descriptor-derivation-error ()
                         (return-from %spkm-top-up-into nil)))
                     ;; Merge and persist only the genuinely new cache items.
                     (%spkm-write-cache-diff
                      spkm
                      (descriptor-cache-merge-and-diff (desc-spkm-cache spkm)
                                                       temp-cache)
                      batch)))
                 (%spkm-note-expansion spkm i scripts pubkeys)
                 (incf (desc-spkm-max-cached-index spkm)))))
    (setf (desc-spkm-range-end spkm) new-range-end)
    (spkm-write-descriptor wallet spkm :batch batch)
    (assert (= (1- (desc-spkm-range-end spkm))
               (desc-spkm-max-cached-index spkm)))
    t))

(defun spkm-top-up (wallet spkm &optional (size 0) batch)
  "Extend the keypool window: range_end = max(next_index + target, range_end),
expanding and caching every index up to the new end, persisting new cache
records and the descriptor record atomically. With BATCH the records join the
caller's batch (Core TopUpWithDB inside a WalletBatch txn); otherwise one
batch is written+fsynced here (Core TopUp). Returns T on success, NIL when
expansion needs unavailable private keys."
  (if batch
      (%spkm-top-up-into wallet spkm size batch)
      (bitcoin-lisp.storage:with-leveldb-writebatch (own-batch)
        (when (%spkm-top-up-into wallet spkm size own-batch)
          (bitcoin-lisp.storage:leveldb-write (wallet-db wallet) own-batch
                                              :sync t)
          t))))

(defun spkm-set-cache (wallet spkm cache)
  "Install a loaded cache and rebuild the in-memory script/pubkey maps by
expanding every cached index from it (Core SetCache, scriptpubkeyman.cpp:1429).
WALLET is unused beyond symmetry with the other spkm operations."
  (declare (ignore wallet))
  (setf (desc-spkm-cache spkm) cache)
  (loop for i from (desc-spkm-range-start spkm) below (desc-spkm-range-end spkm)
        do (multiple-value-bind (scripts pubkeys)
               (out-desc-expand-from-cache (desc-spkm-desc spkm) i cache)
             (unless scripts
               (error "Error: Unable to expand wallet descriptor from cache"))
             (dolist (script scripts)
               (let ((existing (gethash script (desc-spkm-script-map spkm))))
                 (when (and existing (/= existing i))
                   (error "Error: Already loaded script at index ~D as being at index ~D"
                          i existing))))
             (%spkm-note-expansion spkm i scripts pubkeys)
             (incf (desc-spkm-max-cached-index spkm)))))

(defun spkm-is-mine (spkm script)
  "Range index when SCRIPT belongs to this SPKM, else NIL (Core IsMine —
a hash lookup in m_map_script_pub_keys, scriptpubkeyman.cpp:863)."
  (gethash script (desc-spkm-script-map spkm)))

(defun wallet-is-mine (wallet script)
  "T when SCRIPT belongs to any loaded SPKM of WALLET (Core CWallet::IsMine)."
  (with-wallet-lock (wallet)
    (loop for spkm being the hash-values of (wallet-spkms wallet)
          thereis (and (spkm-is-mine spkm script) t))))

(defun spkm-can-get-addresses (spkm)
  "Core CanGetAddresses: single-type, ranged, and either private keys are
present (TopUp can extend) or precomputed addresses remain."
  (and (out-desc-single-type-p (desc-spkm-desc spkm))
       (out-desc-ranged-p (desc-spkm-desc spkm))
       (or (spkm-have-private-keys-p spkm)
           (< (desc-spkm-next-index spkm) (desc-spkm-range-end spkm)))))

(defun wallet-can-get-addresses (wallet &optional internal)
  (loop for spkm being the hash-values of (if internal
                                              (wallet-internal-spkms wallet)
                                              (wallet-external-spkms wallet))
        thereis (spkm-can-get-addresses spkm)))

(defun spkm-keypool-count (spkm)
  (- (desc-spkm-range-end spkm) (desc-spkm-next-index spkm)))

;;; --- GetNewDestination (Core scriptpubkeyman.cpp:824) ---

(defun spkm-get-new-destination (wallet spkm type)
  "Issue the next address: TopUp, expand at next_index, increment, persist the
descriptor record — the fsynced write happens BEFORE the address is returned,
so a crash can never reissue a handed-out address (funds-critical; Core
GetNewDestination persists via WriteDescriptor before returning)."
  (unless (spkm-can-get-addresses spkm)
    (error 'rpc-error :code +rpc-wallet-keypool-ran-out+
                      :message "No addresses available"))
  (assert (out-desc-single-type-p (desc-spkm-desc spkm)))
  (let ((desc-type (out-desc-output-type (desc-spkm-desc spkm))))
    (unless (eq type desc-type)
      (error 'rpc-error :code +rpc-internal-error+
                        :message "GetNewDestination: Types are inconsistent. Stored type does not match type of newly generated address")))
  (spkm-top-up wallet spkm)
  (when (and (<= (desc-spkm-range-end spkm) (desc-spkm-max-cached-index spkm))
             (not (spkm-top-up wallet spkm 1)))
    (error 'rpc-error :code +rpc-wallet-keypool-ran-out+
                      :message "Error: Keypool ran out, please call keypoolrefill first"))
  (let ((scripts (out-desc-expand-from-cache (desc-spkm-desc spkm)
                                             (desc-spkm-next-index spkm)
                                             (desc-spkm-cache spkm))))
    (unless scripts
      (error 'rpc-error :code +rpc-wallet-keypool-ran-out+
                        :message "Error: Keypool ran out, please call keypoolrefill first"))
    (let ((address (%script->address (first scripts) (wallet-network wallet))))
      (unless address
        (error 'rpc-error :code +rpc-wallet-keypool-ran-out+
                          :message "Error: Cannot extract destination from the generated scriptpubkey"))
      (incf (desc-spkm-next-index spkm))
      ;; Funds-critical ordering: persist next_index (fsync) before returning.
      (spkm-write-descriptor wallet spkm)
      address)))

;;; --- Address book (Core m_address_book / CAddressBookData, wallet/types.h) ---

(defstruct addr-book-entry
  "Core CAddressBookData. LABEL is NIL when never set — such an entry is a
change-only record (IsChange) invisible to label lookups; \"\" is the
default label. PURPOSE is \"send\"/\"receive\"/\"refund\" or NIL (unknown).
PREVIOUSLY-SPENT backs the avoid_reuse feature (destdata \"used\" records)."
  (label nil)
  (purpose nil)
  (previously-spent nil))

(defun %wallet-book-entry (wallet address)
  "ADDRESS's address-book record, created empty if absent (the
m_address_book[dest] idiom)."
  (or (gethash address (wallet-address-book wallet))
      (setf (gethash address (wallet-address-book wallet))
            (make-addr-book-entry))))

(defun wallet-set-address-book (wallet address label purpose)
  "Core SetAddressBookWithDB: set ADDRESS's label, update its purpose only
when PURPOSE is non-NIL, persist the purpose (when given) and name records."
  (let ((entry (%wallet-book-entry wallet address)))
    (setf (addr-book-entry-label entry) label)
    (when purpose
      (setf (addr-book-entry-purpose entry) purpose)
      (bitcoin-lisp.storage:leveldb-put
       (wallet-db wallet)
       (wdb-key-address-string +wdb-key-purpose+ address)
       (wdb-string-value purpose)))
    (bitcoin-lisp.storage:leveldb-put
     (wallet-db wallet)
     (wdb-key-address-string +wdb-key-name+ address)
     (wdb-string-value label)
     :sync t))
  t)

(defun wallet-write-address-book-entry (wallet address label purpose)
  "Backward-compatible alias for wallet-set-address-book (P1/P2 call sites)."
  (wallet-set-address-book wallet address label purpose))

(defun wallet-find-address-book-entry (wallet address &key allow-change)
  "(values label purpose found-p) for ADDRESS's address-book entry (Core
FindAddressBookEntry). Change entries — records whose label was never set,
e.g. pure previously-spent markers — are reported as absent unless
ALLOW-CHANGE. LABEL is the entry's label with NIL folded to \"\" (Core
GetLabel)."
  (let ((entry (gethash address (wallet-address-book wallet))))
    (if (and entry (or allow-change (addr-book-entry-label entry)))
        (values (or (addr-book-entry-label entry) "")
                (addr-book-entry-purpose entry)
                t)
        (values nil nil nil))))

;;; --- Default wallet descriptors (Core walletutil.cpp:35-86 GenerateWalletDescriptor,
;;; wallet.cpp:3594-3685 SetupDescriptorScriptPubKeyMans) ---

(defun generate-wallet-descriptor-string (master-xpub-string type internal network)
  "The default descriptor for TYPE/INTERNAL from the master xpub: pkh 44h,
sh(wpkh) 49h, wpkh 84h, tr 86h; coin 0h mainnet / 1h test chains; account 0h;
/0/* external, /1/* change (walletutil.cpp:35-86)."
  (multiple-value-bind (prefix suffix)
      (ecase type
        (:legacy (values "pkh(" "/*)"))
        (:p2sh-segwit (values "sh(wpkh(" "/*))"))
        (:bech32 (values "wpkh(" "/*)"))
        (:bech32m (values "tr(" "/*)")))
    (format nil "~A~A/~Ah/~Ah/0h/~A~A"
            prefix master-xpub-string
            (ecase type (:legacy 44) (:p2sh-segwit 49) (:bech32 84) (:bech32m 86))
            (if (eq network :mainnet) 0 1)
            (if internal 1 0)
            suffix)))

(defun %make-spkm-from-descriptor (desc creation-time range-start
                                   range-end next-index)
  (let ((canonical (descriptor-add-checksum (out-desc-string desc))))
    (make-desc-spkm :id (descriptor-id desc)
                    :desc desc
                    :desc-string canonical
                    :creation-time creation-time
                    :range-start range-start
                    :range-end range-end
                    :next-index next-index)))

(defun wallet-add-active-spkm (wallet spkm type internal &key (persist t) batch)
  "Mark SPKM active for TYPE/INTERNAL, persisting the active*spk record
(Core AddActiveScriptPubKeyManWithDb + LoadActiveScriptPubKeyMan)."
  (when persist
    (let ((key (wdb-key-active-spk internal (%output-type-code type)))
          (value (coerce (desc-spkm-id spkm)
                         '(simple-array (unsigned-byte 8) (*)))))
      (if batch
          (bitcoin-lisp.storage:leveldb-writebatch-put batch key value)
          (bitcoin-lisp.storage:leveldb-put (wallet-db wallet) key value
                                            :sync t))))
  (let ((table (if internal (wallet-internal-spkms wallet)
                   (wallet-external-spkms wallet)))
        (other (if internal (wallet-external-spkms wallet)
                   (wallet-internal-spkms wallet))))
    (setf (gethash type table) spkm)
    ;; Core LoadActiveScriptPubKeyMan: the same SPKM cannot stay active on
    ;; both sides for one type.
    (when (eq (gethash type other) spkm)
      (remhash type other))))

(defun wallet-deactivate-spkm (wallet spkm type internal)
  "Core DeactivateScriptPubKeyMan (wallet.cpp:3705): drop the active mapping
and erase its record iff SPKM currently holds it."
  (let ((table (if internal (wallet-internal-spkms wallet)
                   (wallet-external-spkms wallet))))
    (when (eq (gethash type table) spkm)
      (bitcoin-lisp.storage:leveldb-delete
       (wallet-db wallet)
       (wdb-key-active-spk internal (%output-type-code type)))
      (remhash type table))))

(defun wallet-setup-descriptor-spkms (wallet master-xprv)
  "Create + activate the 8 default SPKMs — {external, internal} x
{44h, 49h, 84h, 86h} — from MASTER-XPRV (Core SetupDescriptorScriptPubKeyMans,
wallet.cpp:3594-3602)."
  (let* ((network (wallet-network wallet))
         (master-xpub (bitcoin-lisp.crypto:bip32-neuter master-xprv))
         (xpub-string (bitcoin-lisp.crypto:bip32-serialize master-xpub))
         (master-priv (subseq (bitcoin-lisp.crypto:ext-key-key master-xprv) 1 33))
         (master-pub (bitcoin-lisp.crypto:ext-key-public-bytes master-xprv))
         (now (bitcoin-lisp.serialization:get-unix-time)))
    ;; All 8 SPKMs' records — keys, descriptors (written by TopUp), caches,
    ;; active mappings — land in ONE atomic fsynced batch, like Core's
    ;; RunWithinTxn around SetupOwnDescriptorScriptPubKeyMans.
    (bitcoin-lisp.storage:with-leveldb-writebatch (batch)
      (dolist (internal '(nil t))
        (dolist (type +output-types+)
          (let* ((desc-str (generate-wallet-descriptor-string
                            xpub-string type internal network))
                 (desc (parse-descriptor desc-str network))
                 (spkm (%make-spkm-from-descriptor desc now 0 0 0)))
            (setf (gethash (desc-spkm-id spkm) (wallet-spkms wallet)) spkm)
            ;; Store the master private key for this descriptor, then the
            ;; descriptor + keypool via TopUp (SetupDescriptorGeneration,
            ;; scriptpubkeyman.cpp:1136-1161).
            (spkm-add-key wallet spkm master-priv master-pub t :batch batch)
            (unless (spkm-top-up wallet spkm 0 batch)
              (error "wallet setup: keypool top-up failed for ~A" desc-str))
            (wallet-add-active-spkm wallet spkm type internal :batch batch))))
      (bitcoin-lisp.storage:leveldb-write (wallet-db wallet) batch :sync t))
    (wallet-maybe-update-birth-time wallet now)))

(defun generate-wallet-master-key (network)
  "A fresh random HD master key (Core SetupOwnDescriptorScriptPubKeyMans:
GenerateRandomKey -> CExtKey::SetSeed over the 32 secret bytes)."
  (loop
    (let ((seed (ironclad:random-data 32)))
      (let ((n (reduce (lambda (acc b) (logior (ash acc 8) b)) seed
                       :initial-value 0)))
        (when (< 0 n bitcoin-lisp.crypto:+secp256k1-order+)
          (return (bitcoin-lisp.crypto:bip32-master-key
                   seed
                   :network (if (eq network :mainnet) :mainnet :testnet))))))))

;;; --- Best block records (Core WriteBestBlock, walletdb.cpp:180-191) ---

(defun wallet-write-best-block (wallet &optional locator-hashes)
  "Write the bestblock records: an empty locator under 'bestblock' (so old
versions rescan) and the real locator under 'bestblock_nomerkle' (Core
WalletBatch::WriteBestBlock, walletdb.cpp:180-184). LOCATOR-HASHES is the
exponential step-back locator for the wallet's last processed block, built
by callers with chain access; without one (unload/shutdown, where the last
processed block is on the active chain anyway) a single-hash locator is
written — fork lookup still succeeds unless that exact block was reorged
away, in which case the load-time catch-up rescans from genesis (safe)."
  (bitcoin-lisp.storage:leveldb-put (wallet-db wallet)
                                    (wdb-key-simple +wdb-key-bestblock+)
                                    (wdb-block-locator-value '()))
  (bitcoin-lisp.storage:leveldb-put
   (wallet-db wallet)
   (wdb-key-simple +wdb-key-bestblock-nomerkle+)
   (wdb-block-locator-value
    (or locator-hashes
        (and (wallet-last-block-hash wallet)
             (list (wallet-last-block-hash wallet)))
        '()))
   :sync t))

;;; --- Wallet creation (Core CreateWallet, wallet.cpp:377-470 + CWallet::CreateNew) ---

(defun create-wallet (manager name &key disable-private-keys blank avoid-reuse
                                        last-block-hash (last-block-height 0))
  "Create, persist, and register a new descriptor wallet. Returns the wallet.
Flags follow createwallet: DESCRIPTORS and LAST_HARDENED_XPUB_CACHED always
set (wallet.cpp:3097-3099); the 8 default SPKMs are generated unless the
wallet is blank or has private keys disabled."
  (unless (%valid-wallet-name-p name)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message (if (and (stringp name) (zerop (length name)))
                                   "Wallet name cannot be empty"
                                   (format nil "Invalid wallet name ~S" name))))
  (bt:with-recursive-lock-held ((wallet-manager-lock manager))
    (let ((path (wallet-directory manager name)))
      (when (or (gethash name (wallet-manager-wallets manager))
                (probe-file path))
        (error 'rpc-error :code +rpc-wallet-already-exists+
                          :message (format nil "Failed to create database path '~A'. Database already exists."
                                           (namestring path))))
      (let* ((flags (logior +wallet-flag-descriptors+
                            +wallet-flag-last-hardened-xpub-cached+
                            (if disable-private-keys +wallet-flag-disable-private-keys+ 0)
                            (if blank +wallet-flag-blank-wallet+ 0)
                            (if avoid-reuse +wallet-flag-avoid-reuse+ 0)))
             (db (wallet-db-open path :create t))
             (wallet (make-wallet :name name :path path :db db
                                  :network (wallet-manager-network manager)
                                  :flags flags
                                  :keypool-size (wallet-manager-keypool-size manager)
                                  :last-block-hash last-block-hash
                                  :last-block-height last-block-height)))
        (handler-case
            (with-wallet-lock (wallet)
              ;; version record first (CWallet::CreateNew), then flags.
              (bitcoin-lisp.storage:leveldb-put db (wdb-key-simple +wdb-key-version+)
                                                (wdb-int32-value +wallet-client-version+))
              (bitcoin-lisp.storage:leveldb-put db (wdb-key-simple +wdb-key-flags+)
                                                (wdb-uint64-value flags) :sync t)
              (unless (or disable-private-keys blank)
                (wallet-setup-descriptor-spkms wallet (generate-wallet-master-key
                                                       (wallet-network wallet))))
              (wallet-write-best-block wallet))
          (error (e)
            ;; Creation failed mid-way: close the DB so the directory is not
            ;; left open, then re-signal.
            (bitcoin-lisp.storage:leveldb-close db)
            (error e)))
        (setf (gethash name (wallet-manager-wallets manager)) wallet)
        (setf (wallet-manager-wallet-order manager)
              (append (wallet-manager-wallet-order manager) (list name)))
        wallet))))

;;; --- Wallet loading (Core CWallet::LoadExisting + walletdb LoadWallet) ---

(defun %load-wallet-records (wallet warnings &key chain-state)
  "Populate WALLET from its database records. Two-pass: descriptors first,
then keys/caches/active mappings (LevelDB iteration order does not guarantee
descriptor-before-key). Transaction records load last — RefreshTXOs needs
the IsMine script maps the cache install builds. CHAIN-STATE (when given)
resolves stored confirmed/conflicted block heights (CWalletTx::updateState)."
  (let ((records (wallet-db-records (wallet-db wallet)))
        (network (wallet-network wallet))
        (caches (make-hash-table :test 'equalp))   ; id -> descriptor-cache
        (actives '())
        (tx-records '())
        (locator-main '())
        (locator-nomerkle '()))
    ;; Pass 1: singletons + descriptors.
    (dolist (rec records)
      (multiple-value-bind (type fields) (wdb-parse-key (car rec))
        (cond
          ((equal type +wdb-key-flags+)
           (let ((flags (wdb-parse-uint64-value (cdr rec))))
             ;; Unknown flags in the mandatory (upper) region refuse to load
             ;; (Core LoadWalletFlags, wallet.cpp:1767).
             (when (plusp (logxor (ash (logand flags +known-wallet-flags+) -32)
                                  (ash flags -32)))
               (error 'rpc-error :code +rpc-wallet-error+
                                 :message "Unknown wallet flags"))
             (setf (wallet-flags wallet) flags)))
          ((equal type +wdb-key-walletdescriptor+)
           (multiple-value-bind (desc-str creation-time next-index range-start range-end)
               (wdb-parse-descriptor-value (cdr rec))
             (let* ((desc (parse-descriptor desc-str network :require-checksum t))
                    (spkm (%make-spkm-from-descriptor desc creation-time
                                                      range-start range-end
                                                      next-index)))
               ;; The stored id must round-trip; guard against corruption.
               (unless (equalp (desc-spkm-id spkm) fields)
                 (error 'rpc-error :code +rpc-wallet-error+
                                   :message "Wallet descriptor record id mismatch"))
               (setf (gethash (desc-spkm-id spkm) (wallet-spkms wallet)) spkm))))
          ((equal type +wdb-key-mkey+)
           ;; Encrypted wallets need the P6 crypter; refuse rather than
           ;; misbehave.
           (error 'rpc-error :code +rpc-wallet-error+
                             :message "Wallet is encrypted; encrypted wallets are not supported until wallet P6"))
          ((equal type +wdb-key-orderposnext+)
           (setf (wallet-orderposnext wallet) (wdb-parse-int64-value (cdr rec))))
          ((equal type +wdb-key-bestblock-nomerkle+)
           (setf locator-nomerkle (wdb-parse-block-locator-value (cdr rec))))
          ((equal type +wdb-key-bestblock+)
           (setf locator-main (wdb-parse-block-locator-value (cdr rec))))
          ((equal type +wdb-key-lockedutxo+)
           ;; Records on disk are the persistent locks (lockunspent
           ;; persistent=true); memory-only locks never reach the DB.
           (push (%wparse (s fields)
                   (list (bitcoin-lisp.serialization:read-bytes s 32)
                         (bitcoin-lisp.serialization:read-uint32-le s)
                         t))
                 (wallet-locked-utxos wallet)))
          ((equal type +wdb-key-tx+)
           (push (cons fields (cdr rec)) tx-records))
          ((equal type +wdb-key-name+)
           (setf (addr-book-entry-label
                  (%wallet-book-entry wallet (wdb-parse-string-value fields)))
                 (wdb-parse-string-value (cdr rec))))
          ((equal type +wdb-key-purpose+)
           (setf (addr-book-entry-purpose
                  (%wallet-book-entry wallet (wdb-parse-string-value fields)))
                 (wdb-parse-string-value (cdr rec))))
          ((equal type +wdb-key-destdata+)
           ;; Core LoadRecords DESTDATA: "used" -> previously-spent marker;
           ;; "rr<id>" receive requests are GUI-only and skipped.
           (multiple-value-bind (address data-key)
               (wdb-parse-destdata-fields fields)
             (cond ((equal data-key "used")
                    (setf (addr-book-entry-previously-spent
                           (%wallet-book-entry wallet address))
                          t))
                   ((and (>= (length data-key) 2)
                         (string= "rr" data-key :end2 2)))
                   (t (push "Found unknown address data record" warnings)))))
          (t nil))))
    ;; Pass 2: keys, caches, active mappings.
    (dolist (rec records)
      (multiple-value-bind (type fields) (wdb-parse-key (car rec))
        (cond
          ((equal type +wdb-key-walletdescriptorkey+)
           (let* ((id (subseq fields 0 32))
                  (pubkey (subseq fields 33))   ; skip compactsize byte
                  (spkm (gethash id (wallet-spkms wallet))))
             (if (null spkm)
                 (push "Found a descriptor key for an unknown descriptor" warnings)
                 (let ((priv (wdb-parse-descriptor-key-value (cdr rec) pubkey)))
                   (unless priv
                     (error 'rpc-error :code +rpc-wallet-error+
                                       :message "Error reading wallet database: descriptor private key checksum mismatch"))
                   (setf (gethash (bitcoin-lisp.crypto:hash160 pubkey)
                                  (desc-spkm-keys spkm))
                         (cons priv (= (length pubkey) 33)))))))
          ((equal type +wdb-key-walletdescriptorckey+)
           ;; Encrypted descriptor keys arrive with wallet P6.
           (error 'rpc-error :code +rpc-wallet-error+
                             :message "Wallet is encrypted; encrypted wallets are not supported until wallet P6"))
          ((equal type +wdb-key-walletdescriptorcache+)
           (let* ((id (subseq fields 0 32))
                  (cache (or (gethash id caches)
                             (setf (gethash id caches) (make-descriptor-cache))))
                  (xpub (wdb-parse-xpub-value (cdr rec) network)))
             (%wparse (s fields)
               (bitcoin-lisp.serialization:read-bytes s 32)
               (let ((key-exp (bitcoin-lisp.serialization:read-uint32-le s)))
                 (if (= (length fields) 40)      ; id + keyexp + derindex
                     (setf (descriptor-cache-derived
                            cache key-exp (bitcoin-lisp.serialization:read-uint32-le s))
                           xpub)
                     (setf (descriptor-cache-parent cache key-exp) xpub))))))
          ((equal type +wdb-key-walletdescriptorlhcache+)
           (let* ((id (subseq fields 0 32))
                  (cache (or (gethash id caches)
                             (setf (gethash id caches) (make-descriptor-cache))))
                  (xpub (wdb-parse-xpub-value (cdr rec) network)))
             (%wparse (s fields)
               (bitcoin-lisp.serialization:read-bytes s 32)
               (setf (descriptor-cache-last-hardened
                      cache (bitcoin-lisp.serialization:read-uint32-le s))
                     xpub))))
          ((or (equal type +wdb-key-activeexternalspk+)
               (equal type +wdb-key-activeinternalspk+))
           (push (list (equal type +wdb-key-activeinternalspk+)
                       (aref fields 0)
                       (cdr rec))
                 actives))
          (t nil))))
    ;; bestblock preferred when non-empty, else bestblock_nomerkle (Core
    ;; ReadBestBlock; WriteBestBlock deliberately leaves bestblock empty).
    (let ((locator (or locator-main locator-nomerkle)))
      (when locator
        (setf (wallet-loaded-locator wallet) locator)
        (setf (wallet-last-block-hash wallet) (first locator))))
    ;; Install caches (rebuilds script/pubkey maps), then active mappings.
    (loop for spkm being the hash-values of (wallet-spkms wallet)
          do (spkm-set-cache wallet spkm
                             (or (gethash (desc-spkm-id spkm) caches)
                                 (make-descriptor-cache)))
             ;; Core wires NotifyFirstKeyTimeChanged -> MaybeUpdateBirthTime
             ;; per SPKM (wallet.cpp:3556).
             (wallet-maybe-update-birth-time wallet
                                             (desc-spkm-creation-time spkm)))
    (dolist (active actives)
      (destructuring-bind (internal type-code id) active
        (let ((spkm (gethash id (wallet-spkms wallet)))
              (type (%output-type-from-code type-code)))
          (if (and spkm type)
              (wallet-add-active-spkm wallet spkm type internal :persist nil)
              (push "Wallet file references an unknown active ScriptPubKeyMan"
                    warnings)))))
    ;; Transaction records last: RefreshTXOs consults the IsMine maps built
    ;; by the cache installs above (Core LoadTxRecords runs after descriptor
    ;; records too).
    (setf warnings (wallet-load-tx-records wallet (nreverse tx-records)
                                           chain-state warnings))
    warnings))

(defun load-wallet (manager name &key chain-state)
  "Load an existing wallet from <wallets>/<name>/ and register it. Returns
(values wallet warnings). CHAIN-STATE resolves stored tx block heights; the
locator catch-up rescan is a separate step (wallet-attach-chain) run by the
RPC after registration, mirroring Core's LoadWallet -> AttachChain split."
  (bt:with-recursive-lock-held ((wallet-manager-lock manager))
    (when (gethash name (wallet-manager-wallets manager))
      (error 'rpc-error :code +rpc-wallet-already-loaded+
                        :message (format nil "Wallet \"~A\" is already loaded." name)))
    (unless (%valid-wallet-name-p name)
      (error 'rpc-error :code +rpc-wallet-not-found+
                        :message (format nil "Wallet \"~A\" not found." name)))
    (let ((path (wallet-directory manager name)))
      (unless (wallet-db-exists-p path)
        (error 'rpc-error :code +rpc-wallet-not-found+
                          :message (format nil "Wallet file verification failed. Failed to load database path '~A'. Path does not exist."
                                           (namestring path))))
      (let* ((db (wallet-db-open path))
             (wallet (make-wallet :name name :path path :db db
                                  :network (wallet-manager-network manager)
                                  :keypool-size (wallet-manager-keypool-size manager)))
             (warnings '()))
        (handler-case
            (with-wallet-lock (wallet)
              (setf warnings (%load-wallet-records wallet warnings
                                                   :chain-state chain-state))
              (when (and (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+)
                         (loop for spkm being the hash-values of (wallet-spkms wallet)
                               thereis (spkm-have-private-keys-p spkm)))
                (push (format nil "Warning: Private keys detected in wallet {~A} with disabled private keys"
                              name)
                      warnings))
              ;; Try to top up the keypool (CWallet::LoadExisting).
              (loop for spkm being the hash-values of (wallet-external-spkms wallet)
                    do (spkm-top-up wallet spkm))
              (loop for spkm being the hash-values of (wallet-internal-spkms wallet)
                    do (spkm-top-up wallet spkm)))
          (error (e)
            (bitcoin-lisp.storage:leveldb-close db)
            (error e)))
        (setf (gethash name (wallet-manager-wallets manager)) wallet)
        (setf (wallet-manager-wallet-order manager)
              (append (wallet-manager-wallet-order manager) (list name)))
        (values wallet (nreverse warnings))))))

(defun unload-wallet (manager wallet &key force)
  "Write the best-block marker, close the database, and deregister. Refuses
while a rescan is running (the scan thread holds the DB) unless FORCE — the
shutdown path — which flags the scan to abort and proceeds."
  (when (wallet-scanning-since wallet)
    (if force
        (setf (wallet-abort-rescan wallet) t)
        (error 'rpc-error :code +rpc-wallet-error+
                          :message "Wallet is currently rescanning. Abort existing rescan or wait.")))
  (bt:with-recursive-lock-held ((wallet-manager-lock manager))
    (with-wallet-lock (wallet)
      (wallet-write-best-block wallet)
      (bitcoin-lisp.storage:leveldb-close (wallet-db wallet))
      (setf (wallet-db wallet) nil))
    (remhash (wallet-name wallet) (wallet-manager-wallets manager))
    (setf (wallet-manager-wallet-order manager)
          (remove (wallet-name wallet) (wallet-manager-wallet-order manager)
                  :test #'string=))))

(defun list-wallet-dir (manager)
  "Names of wallet databases under <datadir>/wallets/ (Core ListDatabases)."
  (let ((dir (wallets-directory manager)))
    (when (probe-file dir)
      (loop for sub in (uiop:subdirectories dir)
            for name = (first (last (pathname-directory sub)))
            when (wallet-db-exists-p sub)
              collect name))))

;;; --- Manager lifecycle (called from node.lisp) ---

(defun init-wallet-manager (data-directory network)
  "Create the node's wallet manager. Wallets are not auto-loaded: there is no
persistent load_on_startup settings store yet — use loadwallet."
  (make-wallet-manager :data-directory data-directory :network network))

(defun close-wallet-manager (manager)
  "Unload every loaded wallet (shutdown path)."
  (bt:with-recursive-lock-held ((wallet-manager-lock manager))
    (dolist (name (copy-list (wallet-manager-wallet-order manager)))
      (let ((wallet (gethash name (wallet-manager-wallets manager))))
        (when wallet (unload-wallet manager wallet :force t))))))

;;; --- RPC plumbing: /wallet/<name> endpoint resolution ---

(defvar *rpc-wallet-name* nil
  "The wallet name from the request's /wallet/<name> URI path, or NIL when
the request came in on the base endpoint. Bound per-request by rpc-handler.")

(defun wallet-name-from-uri (script-name)
  "The url-decoded wallet name when SCRIPT-NAME is a /wallet/<name> endpoint
(Core GetWalletNameFromJSONRPCRequest; hunchentoot already url-decodes)."
  (when (and (stringp script-name)
             (> (length script-name) (length "/wallet/"))
             (string= "/wallet/" script-name :end2 (length "/wallet/")))
    (subseq script-name (length "/wallet/"))))

(defun node-wallet-manager-checked (node)
  "The node's wallet manager, or the same error a no-wallet Core build gives
for wallet RPCs: method not found."
  (or (bitcoin-lisp::node-wallet-manager node)
      (error 'rpc-error :code +rpc-method-not-found+
                        :message "Method not found (wallet support is disabled)")))

(defun wallet-for-request (node)
  "Resolve the wallet a request addresses (Core GetWalletForJSONRPCRequest,
wallet/rpc/util.cpp:64-88): the /wallet/<name> endpoint's wallet, else the
sole loaded wallet; errors match Core's."
  (let ((manager (node-wallet-manager-checked node)))
    (bt:with-recursive-lock-held ((wallet-manager-lock manager))
      (if *rpc-wallet-name*
          (or (gethash *rpc-wallet-name* (wallet-manager-wallets manager))
              (error 'rpc-error :code +rpc-wallet-not-found+
                                :message "Requested wallet does not exist or is not loaded"))
          (let ((count (hash-table-count (wallet-manager-wallets manager))))
            (case count
              (1 (gethash (first (wallet-manager-wallet-order manager))
                          (wallet-manager-wallets manager)))
              (0 (error 'rpc-error :code +rpc-wallet-not-found+
                                   :message "No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet. (Note: A default wallet is no longer automatically created)"))
              (t (error 'rpc-error :code +rpc-wallet-not-specified+
                                   :message "Multiple wallets are loaded. Please select which wallet to use by requesting the RPC through the /wallet/<walletname> URI path."))))))))

(defun %wallet-current-tip (node)
  "(values hash height) of the active chainstate tip, under the node-lock.
Callers take this BEFORE any wallet lock (lock order)."
  (with-node-lock (node)
    (let ((cs (bitcoin-lisp::node-current-chainstate node)))
      (if cs
          (values (bitcoin-lisp.storage:best-block-hash cs)
                  (max (bitcoin-lisp.storage:current-height cs) 0))
          (values nil 0)))))

(defun %wallet-tip-time-and-mtp (node)
  "(values tip-block-time tip-mtp) for importdescriptors: `now` (the meaning
of a \"now\" timestamp) is the tip's median-time-past and the lowest-timestamp
accumulator starts at the tip's block time (Core backup.cpp:385-388), falling
back to wall-clock time when there is no tip."
  (with-node-lock (node)
    (let* ((cs (bitcoin-lisp::node-current-chainstate node))
           (hash (and cs (bitcoin-lisp.storage:best-block-hash cs)))
           (entry (and hash (bitcoin-lisp.storage:get-block-index-entry cs hash))))
      (if entry
          (values (bitcoin-lisp.serialization:block-header-timestamp
                   (bitcoin-lisp.storage:block-index-entry-header entry))
                  (bitcoin-lisp.validation:compute-median-time-past cs hash))
          (let ((now (bitcoin-lisp.serialization:get-unix-time)))
            (values now now))))))

(defun %label-from-value (value)
  "Core LabelFromValue: NIL -> \"\", \"*\" -> invalid."
  (cond ((null value) "")
        ((not (stringp value))
         (error 'rpc-error :code +rpc-type-error+ :message "label must be a string"))
        ((string= value "*")
         (error 'rpc-error :code +rpc-wallet-invalid-label-name+
                           :message "Invalid label name"))
        (t value)))

(defun %push-warnings (warnings result)
  "Append a \"warnings\" field when WARNINGS is non-empty (Core PushWarnings)."
  (if warnings
      (append result `(("warnings" . ,warnings)))
      result))

;;; --- Wallet management RPCs (Core wallet/rpc/wallet.cpp) ---

(defun rpc-createwallet (node params)
  "Create and load a new wallet (Bitcoin Core createwallet). PARAMS:
 (wallet_name disable_private_keys blank passphrase avoid_reuse descriptors
  load_on_startup external_signer). Only descriptor wallets can be created;
passphrases are rejected until encryption lands (wallet P6)."
  (let ((manager (node-wallet-manager-checked node))
        (name (first params))
        (warnings '()))
    (unless (stringp name)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "wallet_name must be a string"))
    ;; descriptors must be true — legacy wallets cannot be created
    ;; (rpc/wallet.cpp:403-406). yason folds JSON false and null together;
    ;; an explicitly supplied null/false is rejected like Core rejects false.
    (when (and (> (length params) 5) (null (nth 5 params)))
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "descriptors argument must be set to \"true\"; it is no longer possible to create a legacy wallet."))
    (when (and (> (length params) 7) (nth 7 params))
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "Compiled without external signing support (required for external signing)"))
    (let ((passphrase (nth 3 params)))
      (cond ((and (stringp passphrase) (plusp (length passphrase)))
             (error 'rpc-error :code +rpc-wallet-error+
                               :message "Wallet encryption is not yet supported (planned for wallet P6); create the wallet without a passphrase."))
            ((and (stringp passphrase) (zerop (length passphrase)))
             (push "Empty string given as passphrase, wallet will not be encrypted."
                   warnings))))
    (multiple-value-bind (tip-hash tip-height) (%wallet-current-tip node)
      (let ((wallet (create-wallet manager name
                                   :disable-private-keys (nth 1 params)
                                   :blank (nth 2 params)
                                   :avoid-reuse (nth 4 params)
                                   :last-block-hash tip-hash
                                   :last-block-height tip-height)))
        (%push-warnings (nreverse warnings)
                        `(("name" . ,(wallet-name wallet))))))))

(defun rpc-loadwallet (node params)
  "Load a wallet from the wallet directory (Bitcoin Core loadwallet).
PARAMS: (filename load_on_startup); load_on_startup is accepted but has no
persistent settings store yet. After the records load, the wallet is caught
up from its stored best-block locator (Core AttachChain: fork lookup +
rescan to the tip); a failed catch-up unloads the wallet and errors, like
Core's failed-AttachChain load."
  (let ((manager (node-wallet-manager-checked node))
        (name (first params)))
    (unless (stringp name)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "filename must be a string"))
    ;; Record load under the node-lock (outermost; manager/wallet locks nest
    ;; inside): tx-state resolution reads the chain, and no block may connect
    ;; between the load and the wallet becoming hook-visible.
    (multiple-value-bind (wallet warnings)
        (with-node-lock (node)
          (load-wallet manager name
                       :chain-state (bitcoin-lisp::node-current-chainstate node)))
      ;; Catch up from the stored locator OUTSIDE the node-lock hold — the
      ;; scan takes it per segment; blocks connecting meanwhile reach the
      ;; wallet through the hooks (Core registers notifications pre-rescan).
      (let ((error-message (wallet-attach-chain node wallet)))
        (when error-message
          (ignore-errors (unload-wallet manager wallet :force t))
          (error 'rpc-error :code +rpc-wallet-error+ :message error-message)))
      ;; Fold the current mempool in (Core LoadWallet -> postInitProcess ->
      ;; requestMempoolTransactions); the attach-chain scan only does this
      ;; when the wallet was behind the tip. Resubmitting the wallet's own
      ;; unconfirmed txs is wallet P4 (rebroadcast machinery).
      (with-node-lock (node)
        (let ((mempool (bitcoin-lisp::node-mempool node)))
          (when mempool
            (bitcoin-lisp.mempool:mempool-for-each
             mempool
             (lambda (txid entry)
               (declare (ignore txid))
               (wallet-transaction-added-to-mempool
                wallet mempool
                (bitcoin-lisp.mempool:mempool-entry-transaction entry)))))))
      (%push-warnings warnings `(("name" . ,(wallet-name wallet)))))))

(defun rpc-unloadwallet (node params)
  "Unload the wallet named by the endpoint or the wallet_name argument
(Bitcoin Core unloadwallet); both given must match."
  (let* ((manager (node-wallet-manager-checked node))
         (arg (first params))
         (name (cond ((and *rpc-wallet-name* arg)
                      (unless (equal *rpc-wallet-name* arg)
                        (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "The RPC endpoint wallet and the wallet name parameter specify different wallets"))
                      arg)
                     (*rpc-wallet-name*)
                     (arg)
                     (t (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Either the RPC endpoint wallet or the wallet name parameter must be provided")))))
    (let ((wallet (bt:with-recursive-lock-held ((wallet-manager-lock manager))
                    (gethash name (wallet-manager-wallets manager)))))
      (unless wallet
        (error 'rpc-error :code +rpc-wallet-not-found+
                          :message "Requested wallet does not exist or is not loaded"))
      (unload-wallet manager wallet)
      (make-hash-table :test 'equal))))

(defun rpc-listwallets (node params)
  "Names of the currently loaded wallets, in load order (Bitcoin Core
listwallets)."
  (declare (ignore params))
  (let ((manager (node-wallet-manager-checked node)))
    (bt:with-recursive-lock-held ((wallet-manager-lock manager))
      (or (copy-list (wallet-manager-wallet-order manager)) #()))))

(defun rpc-listwalletdir (node params)
  "Wallets present in the wallet directory (Bitcoin Core listwalletdir)."
  (declare (ignore params))
  (let ((manager (node-wallet-manager-checked node)))
    `(("wallets" . ,(or (mapcar (lambda (name)
                                  `(("name" . ,name)
                                    ("warnings" . #())))
                                (sort (list-wallet-dir manager) #'string<))
                        #())))))

(defun rpc-getwalletinfo (node params)
  "Wallet state info (Bitcoin Core getwalletinfo); format reports our storage
backend (leveldb, where Core says sqlite)."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (let* ((active-external (alexandria:hash-table-values
                               (wallet-external-spkms wallet)))
             (active-internal (alexandria:hash-table-values
                               (wallet-internal-spkms wallet)))
             (external-count (reduce #'+ active-external
                                     :key #'spkm-keypool-count :initial-value 0))
             (total-count (+ external-count
                             (reduce #'+ (set-difference active-internal
                                                         active-external)
                                     :key #'spkm-keypool-count :initial-value 0)))
             (birthtime (when (< (wallet-birth-time wallet) most-positive-fixnum)
                          (wallet-birth-time wallet)))
             (flags (wallet-flags wallet)))
        `(("walletname" . ,(wallet-name wallet))
          ("walletversion" . ,+wallet-legacy-version+)
          ("format" . "leveldb")
          ("txcount" . ,(hash-table-count (wallet-map-wallet wallet)))
          ("keypoolsize" . ,external-count)
          ("keypoolsize_hd_internal" . ,(- total-count external-count))
          ;; Core booleans are true/false, never null (wave-10 cleanup);
          ;; "scanning" is Core's false-or-progress-object — the progress
          ;; object during a rescan, false otherwise.
          ("private_keys_enabled" . ,(json-bool
                                      (not (wallet-flag-set-p
                                            wallet +wallet-flag-disable-private-keys+))))
          ("avoid_reuse" . ,(json-bool (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+)))
          ("scanning" . ,(let ((since (wallet-scanning-since wallet)))
                           (if since
                               `(("duration" . ,(- (bitcoin-lisp.serialization:get-unix-time)
                                                   since))
                                 ("progress" . ,(wallet-scan-progress wallet)))
                               +json-false+)))
          ("descriptors" . ,(json-bool (wallet-flag-set-p wallet +wallet-flag-descriptors+)))
          ("external_signer" . ,+json-false+)
          ("blank" . ,(json-bool (wallet-flag-set-p wallet +wallet-flag-blank-wallet+)))
          ,@(when birthtime `(("birthtime" . ,birthtime)))
          ("flags" . ,(or (loop for bit from 0 below 64
                                for flag = (ash 1 bit)
                                when (logtest flags flag)
                                  collect (or (cdr (assoc flag +wallet-flag-names+))
                                              (format nil "unknown_flag_~D" bit)))
                          #()))
          ("lastprocessedblock"
           . (("hash" . ,(if (wallet-last-block-hash wallet)
                             (hash-to-hex (wallet-last-block-hash wallet))
                             (make-string 64 :initial-element #\0)))
              ("height" . ,(wallet-last-block-height wallet)))))))))

;;; --- Address RPCs (Core wallet/rpc/addresses.cpp) ---

(defun %address-type-arg (value default)
  (if (null value)
      default
      (or (and (stringp value) (%parse-output-type value))
          (error 'rpc-error :code +rpc-invalid-address-or-key+
                            :message (format nil "Unknown address type '~A'" value)))))

(defun rpc-getnewaddress (node params)
  "A new receiving address (Bitcoin Core getnewaddress). PARAMS:
 (label address_type); default address type bech32 (wallet.h
DEFAULT_ADDRESS_TYPE)."
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (unless (wallet-can-get-addresses wallet)
        (error 'rpc-error :code +rpc-wallet-error+
                          :message "Error: This wallet has no available keys"))
      (let* ((label (%label-from-value (first params)))
             (type (%address-type-arg (second params) :bech32))
             (spkm (gethash type (wallet-external-spkms wallet))))
        (unless spkm
          (error 'rpc-error :code +rpc-wallet-keypool-ran-out+
                            :message (format nil "Error: No ~A addresses available."
                                             (%format-output-type type))))
        (let ((address (spkm-get-new-destination wallet spkm type)))
          ;; Receiving addresses always get an address book entry
          ;; (CWallet::GetNewDestination -> SetAddressBook, purpose receive).
          (wallet-write-address-book-entry wallet address label "receive")
          address)))))

(defun rpc-getrawchangeaddress (node params)
  "A new change address from the internal SPKMs (Bitcoin Core
getrawchangeaddress). PARAMS: (address_type)."
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (unless (wallet-can-get-addresses wallet t)
        (error 'rpc-error :code +rpc-wallet-error+
                          :message "Error: This wallet has no available keys"))
      (let* ((type (%address-type-arg (first params) :bech32))
             (spkm (gethash type (wallet-internal-spkms wallet))))
        (unless spkm
          (error 'rpc-error :code +rpc-wallet-keypool-ran-out+
                            :message (format nil "Error: No ~A addresses available."
                                             (%format-output-type type))))
        ;; Change addresses get no address book entry.
        (spkm-get-new-destination wallet spkm type)))))

;;; --- listdescriptors / importdescriptors (Core wallet/rpc/backup.cpp) ---

(defun %spkm-descriptor-string (wallet spkm private)
  "The listdescriptors string for SPKM: the private form (master keys, never
derived children) or the normalized public form, checksummed
(Core GetDescriptorString, scriptpubkeyman.cpp:1523)."
  (let ((provider (spkm-privkey-provider spkm)))
    (multiple-value-bind (body ok)
        (if private
            (out-desc-string-private (desc-spkm-desc spkm)
                                     (wallet-network wallet) provider)
            (out-desc-string-normalized (desc-spkm-desc spkm)
                                        (desc-spkm-cache spkm) provider))
      (unless ok
        (error 'rpc-error :code +rpc-wallet-error+
                          :message "Unable to produce descriptor string"))
      (descriptor-add-checksum body))))

(defun %spkm-active-info (wallet spkm)
  "(values active-p internal-p). INTERNAL-P is only meaningful for active
SPKMs (Core IsInternalScriptPubKeyMan's optional bool)."
  (flet ((active-in-p (table)
           (loop for active being the hash-values of table
                 thereis (eq active spkm))))
    (cond ((active-in-p (wallet-external-spkms wallet)) (values t nil))
          ((active-in-p (wallet-internal-spkms wallet)) (values t t))
          (t (values nil nil)))))

(defun rpc-listdescriptors (node params)
  "All wallet descriptors, sorted by string (Bitcoin Core listdescriptors).
PARAMS: (private)."
  (let ((wallet (wallet-for-request node))
        (private (first params)))
    (when (and private
               (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+))
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "Can't get private descriptor string for watch-only wallets"))
    (with-wallet-lock (wallet)
      (let ((entries '()))
        (loop for spkm being the hash-values of (wallet-spkms wallet)
              do (multiple-value-bind (active internal)
                     (%spkm-active-info wallet spkm)
                   (let ((ranged (out-desc-ranged-p (desc-spkm-desc spkm))))
                     (push (list (%spkm-descriptor-string wallet spkm private)
                                 spkm active internal ranged)
                           entries))))
        (setf entries (sort entries #'string< :key #'first))
        `(("wallet_name" . ,(wallet-name wallet))
          ("descriptors"
           . ,(or (mapcar
                   (lambda (entry)
                     (destructuring-bind (desc-str spkm active internal ranged)
                         entry
                       `(("desc" . ,desc-str)
                         ("timestamp" . ,(desc-spkm-creation-time spkm))
                         ("active" . ,(json-bool active))
                         ;; internal is defined only for active descriptors
                         ,@(when active
                             `(("internal" . ,(json-bool internal))))
                         ,@(when ranged
                             `(("range" . (,(desc-spkm-range-start spkm)
                                           ,(1- (desc-spkm-range-end spkm))))
                               ("next" . ,(desc-spkm-next-index spkm))
                               ("next_index" . ,(desc-spkm-next-index spkm)))))))
                   entries)
                  #())))))))

(defun %out-desc-embedded-keys (desc)
  "The private keys carried by a parsed descriptor, as a list of
 (pubkey priv32 compressed-p) — Core Parse's FlatSigningProvider keys."
  (let ((out '()))
    (dolist (key (out-desc-ordered-keys desc) (nreverse out))
      (cond
        ((desc-key-ext-privkey key)
         (let ((xprv (desc-key-ext-privkey key)))
           (push (list (bitcoin-lisp.crypto:ext-key-public-bytes xprv)
                       (subseq (bitcoin-lisp.crypto:ext-key-key xprv) 1 33)
                       t)
                 out)))
        ((desc-key-privkey key)
         (push (list (desc-key-pubkey key)
                     (desc-key-privkey key)
                     (desc-key-compressed-p key))
               out))))))

(defun wallet-add-descriptor (wallet desc timestamp range-start range-end
                              next-index keys label internal)
  "Store (or update) a descriptor as an SPKM: register, add keys, TopUp,
write address-book entries for non-ranged external descriptors, persist
(Core CWallet::AddWalletDescriptor, wallet.cpp:3756-3813). Returns the SPKM."
  (let* ((id (descriptor-id desc))
         (existing (gethash id (wallet-spkms wallet)))
         (spkm existing))
    (if existing
        (progn
          ;; UpdateWalletDescriptor (scriptpubkeyman.cpp:1569): the new range
          ;; must contain the current one; state is replaced wholesale.
          (when (and (out-desc-ranged-p desc)
                     (or (> range-start (desc-spkm-range-start existing))
                         (< range-end (desc-spkm-range-end existing))))
            (error 'rpc-error :code +rpc-wallet-error+
                              :message (format nil "new range must include current range = [~D,~D]"
                                               (desc-spkm-range-start existing)
                                               (1- (desc-spkm-range-end existing)))))
          (setf (desc-spkm-desc existing) desc
                (desc-spkm-desc-string existing)
                (descriptor-add-checksum (out-desc-string desc))
                (desc-spkm-creation-time existing) timestamp
                (desc-spkm-range-start existing) range-start
                (desc-spkm-range-end existing) range-end
                (desc-spkm-next-index existing) next-index
                (desc-spkm-cache existing) (make-descriptor-cache)
                (desc-spkm-max-cached-index existing) -1)
          (clrhash (desc-spkm-script-map existing))
          (clrhash (desc-spkm-pubkey-map existing)))
        (setf spkm (%make-spkm-from-descriptor desc timestamp
                                               range-start range-end
                                               next-index)
              (gethash id (wallet-spkms wallet)) spkm))
    (dolist (key keys)
      (destructuring-bind (pubkey priv compressed) key
        (spkm-add-key wallet spkm priv pubkey compressed)))
    (unless (spkm-top-up wallet spkm)
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "Could not top up scriptPubKeys"))
    (unless (out-desc-ranged-p desc)
      (when (zerop (hash-table-count (desc-spkm-script-map spkm)))
        (error 'rpc-error :code +rpc-wallet-error+
                          :message "Could not generate scriptPubKeys (cache is empty)"))
      (unless internal
        (loop for script being the hash-keys of (desc-spkm-script-map spkm)
              for address = (%script->address script (wallet-network wallet))
              when address
                do (wallet-write-address-book-entry wallet address label "receive"))))
    (spkm-write-descriptor wallet spkm)
    (wallet-maybe-update-birth-time wallet timestamp)
    spkm))

(defun %import-timestamp (data now)
  "Core GetImportTimestamp: a number, or the string \"now\" meaning the tip's
median-time-past."
  (multiple-value-bind (value present) (gethash "timestamp" data)
    (unless present
      (error 'rpc-error :code +rpc-type-error+
                        :message "Missing required timestamp field for key"))
    (cond ((integerp value) value)
          ((equal value "now") now)
          (t (error 'rpc-error :code +rpc-type-error+
                               :message "Expected number or \"now\" timestamp value for key.")))))

(defun %process-descriptor-import (wallet data timestamp)
  "One importdescriptors request (Core ProcessDescriptorImport,
backup.cpp:141-300). Returns the per-request result alist; rpc-errors are
caught into {success: false, error: {...}}."
  (let ((warnings '()))
    (handler-case
        (progn
          (unless (hash-table-p data)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Import request must be an object"))
          (multiple-value-bind (desc-str desc-present) (gethash "desc" data)
            (unless desc-present
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Descriptor not found."))
            (unless (stringp desc-str)
              (error 'rpc-error :code +rpc-type-error+
                                :message "desc must be a string"))
            (let* ((active (and (gethash "active" data) t))
                   (label-present (nth-value 1 (gethash "label" data)))
                   (label (%label-from-value (gethash "label" data)))
                   (internal (and (gethash "internal" data) t))
                   (desc (parse-descriptor desc-str (wallet-network wallet)
                                           :require-checksum t))
                   (ranged (out-desc-ranged-p desc))
                   (range-start 0)
                   (range-end 1)
                   (next-index 0))
              (multiple-value-bind (range range-present) (gethash "range" data)
                (cond
                  ((and (not ranged) range-present)
                   (error 'rpc-error :code +rpc-invalid-parameter+
                                     :message "Range should not be specified for an un-ranged descriptor"))
                  (ranged
                   (if range-present
                       (multiple-value-bind (low high) (%parse-descriptor-range range)
                         (setf range-start low
                               range-end (1+ high)))   ; exclusive end internally
                       (progn
                         (push "Range not given, using default keypool range" warnings)
                         (setf range-start 0
                               range-end (wallet-keypool-size wallet))))
                   (setf next-index range-start)
                   (multiple-value-bind (ni ni-present) (gethash "next_index" data)
                     (when ni-present
                       (unless (and (integerp ni) (<= range-start ni (1- range-end)))
                         (error 'rpc-error :code +rpc-invalid-parameter+
                                           :message "next_index is out of range"))
                       (setf next-index ni))))))
              (when (and active (not ranged))
                (error 'rpc-error :code +rpc-invalid-parameter+
                                  :message "Active descriptors must be ranged"))
              (when (and ranged label-present)
                (error 'rpc-error :code +rpc-invalid-parameter+
                                  :message "Ranged descriptors should not have a label"))
              (when (and internal label-present)
                (error 'rpc-error :code +rpc-invalid-parameter+
                                  :message "Internal addresses should not have a label"))
              (when (and active (not (out-desc-single-type-p desc)))
                (error 'rpc-error :code +rpc-wallet-error+
                                  :message "Combo descriptors cannot be set to active"))
              (let ((keys (%out-desc-embedded-keys desc))
                    (priv-disabled (wallet-flag-set-p
                                    wallet +wallet-flag-disable-private-keys+)))
                (when (and priv-disabled keys)
                  (error 'rpc-error :code +rpc-wallet-error+
                                    :message "Cannot import private keys to a wallet with private keys disabled"))
                ;; Expansion check at position 0 (Core Expand(0, keys, ...)).
                (handler-case
                    (out-desc-expand-with-provider
                     desc range-start
                     (lambda (keyid)
                       (loop for (pubkey priv) in keys
                             when (equalp keyid (bitcoin-lisp.crypto:hash160 pubkey))
                               do (return priv)))
                     (make-descriptor-cache))
                  (descriptor-derivation-error ()
                    (error 'rpc-error :code +rpc-wallet-error+
                                      :message "Cannot expand descriptor. Probably because of hardened derivations without private keys provided")))
                (unless priv-disabled
                  (when (null keys)
                    (error 'rpc-error :code +rpc-wallet-error+
                                      :message "Cannot import descriptor without private keys to a wallet with private keys enabled"))
                  (unless (every #'desc-key-has-privkey-p
                                 (out-desc-ordered-keys desc))
                    (push "Not all private keys provided. Some wallet functionality may return unexpected errors"
                          warnings)))
                (let ((spkm (handler-case
                                (wallet-add-descriptor wallet desc timestamp
                                                       range-start range-end
                                                       next-index keys label
                                                       internal)
                              (rpc-error (e)
                                (error 'rpc-error
                                       :code (rpc-error-code e)
                                       :message (format nil "Could not add descriptor '~A': ~A"
                                                        desc-str (rpc-error-message e))))))
                      (output-type (out-desc-output-type desc)))
                  (if active
                      (if output-type
                          (wallet-add-active-spkm wallet spkm output-type internal)
                          (push "Unknown output type, cannot set descriptor to active."
                                warnings))
                      (when output-type
                        (wallet-deactivate-spkm wallet spkm output-type internal)))))
              (%push-warnings (nreverse warnings) `(("success" . t))))))
      (rpc-error (e)
        (%push-warnings (nreverse warnings)
                        `(("success" . ,+json-false+)
                          ("error" . (("code" . ,(rpc-error-code e))
                                      ("message" . ,(rpc-error-message e))))))))))

(defun rpc-importdescriptors (node params)
  "Import descriptors into the wallet (Bitcoin Core importdescriptors), then
rescan the chain from the lowest request timestamp (backup.cpp:302-462): a
successful import triggers RescanFromTime(lowest_timestamp), and any request
whose timestamp the scan could not cover has its result replaced with Core's
rescan-failed error."
  (let ((wallet (wallet-for-request node))
        (requests (first params)))
    (unless (and (listp requests) requests)
      (error 'rpc-error :code +rpc-type-error+
                        :message "requests must be a non-empty array"))
    (unless (wallet-reserve-rescan wallet)
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "Wallet is currently rescanning. Abort existing rescan or wait."))
    (unwind-protect
        ;; Tip time + MTP read under the node-lock BEFORE the wallet lock
        ;; (lock order): `now` = tip MTP, and the lowest-timestamp
        ;; accumulator starts at the tip's block time (backup.cpp:385-388).
        (multiple-value-bind (tip-time now) (%wallet-tip-time-and-mtp node)
          (let ((lowest-timestamp tip-time)
                (rescan nil)
                (timestamps '())
                (results nil))
            (with-wallet-lock (wallet)
              (setf results
                    (mapcar (lambda (request)
                              ;; A bad timestamp throws out of the whole RPC —
                              ;; Core runs GetImportTimestamp outside the
                              ;; per-request try block (backup.cpp:392).
                              (let ((timestamp (max (%import-timestamp request now) 1)))
                                (push timestamp timestamps)
                                (when (< timestamp lowest-timestamp)
                                  (setf lowest-timestamp timestamp))
                                (let ((result (%process-descriptor-import
                                               wallet request timestamp)))
                                  (when (eq t (cdr (assoc "success" result
                                                          :test #'string=)))
                                    (setf rescan t))
                                  result)))
                            requests))
              ;; Newly imported descriptors can make outputs of already-known
              ;; wallet txs IsMine (Core RefreshAllTXOs, backup.cpp:404).
              (wallet-refresh-all-txos wallet))
            (setf timestamps (nreverse timestamps))
            (if (not rescan)
                results
                (let ((scanned-time (wallet-rescan-from-time
                                     node wallet lowest-timestamp :update t)))
                  (when (wallet-abort-rescan wallet)
                    (error 'rpc-error :code +rpc-misc-error+
                                      :message "Rescan aborted by user."))
                  ;; TODO(wallet P4): ResubmitWalletTransactions after the
                  ;; rescan (backup.cpp:410) — rebroadcast machinery lands
                  ;; with the spend path.
                  (if (<= scanned-time lowest-timestamp)
                      results
                      ;; Replace the result of any request whose timestamp
                      ;; the scan failed to reach (backup.cpp:417-457).
                      (loop for result in results
                            for timestamp in timestamps
                            collect
                            (if (or (<= scanned-time timestamp)
                                    (assoc "error" result :test #'string=))
                                result
                                `(("success" . ,+json-false+)
                                  ("error"
                                   . (("code" . ,+rpc-misc-error+)
                                      ("message"
                                       . ,(format nil "Rescan failed for descriptor with timestamp ~D. There was an error reading a block from time ~D, which is after or within ~D seconds of key creation, and could contain transactions pertaining to the desc. As a result, transactions and coins using this desc may not appear in the wallet. This error could potentially caused by data corruption. If the issue persists you may want to reindex (see -reindex option)."
                                                  timestamp
                                                  (- scanned-time +wallet-timestamp-window+ 1)
                                                  +wallet-timestamp-window+))))))))))))
      (wallet-release-rescan wallet))))
