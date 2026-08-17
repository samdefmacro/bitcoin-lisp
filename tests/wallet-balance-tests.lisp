(in-package #:bitcoin-lisp.tests)

;;; Wallet P3 tests: balances & coins (docs/wallet-plan.md §5 P3).
;;;
;;; Regtest scenarios ported from Bitcoin Core's functional expectations —
;;; wallet_balance.py (immature/trusted/untrusted rollups, listunspent
;;; immature filter, getbalance argument rules) and wallet_abandonconflict.py
;;; (eviction -> abandon -> respend -> unabandon, double-spend
;;; walletconflicts) — plus listunspent filters/query_options, coin locking
;;; with persistence, the address book label RPCs, and getaddressinfo field
;;; checks with descriptor round-trips through deriveaddresses.
;;;
;;; Reuses the %wc-* fixtures (wallet-chain-tests.lisp). Wallet spends are
;;; signed through rpc-signrawtransactionwithkey with WIFs derived from the
;;; wallet's own SPKM master keys.

(def-suite wallet-balance-tests
  :description "Wallet P3: balances, coins, labels, getaddressinfo, abandon"
  :in :bitcoin-lisp-tests)

(in-suite wallet-balance-tests)

;;; --- Helpers ---

(defun %wb-aval (key alist) (cdr (assoc key alist :test #'string=)))

(defun %wb= (a b)
  "Compare two BTC doubles to sub-satoshi tolerance."
  (< (abs (- a b)) 1d-6))

(defun %wb-wallet-wif (node name address)
  "WIF for ADDRESS's private key, derived from wallet NAME's owning SPKM."
  (let* ((wallet (%wc-wallet node name))
         (script (%address-script address :regtest)))
    (loop for spkm being the hash-values of (bitcoin-lisp.rpc::wallet-spkms wallet)
          for index = (bitcoin-lisp.rpc::spkm-is-mine spkm script)
          when index
            do (let* ((key (first (bitcoin-lisp.rpc::out-desc-ordered-keys
                                   (bitcoin-lisp.rpc::desc-spkm-desc spkm))))
                      (k (bitcoin-lisp.rpc::%desc-key-root-xprv
                          key (bitcoin-lisp.rpc::spkm-privkey-provider
                               wallet spkm))))
                 (dolist (entry (bitcoin-lisp.rpc::desc-key-path key))
                   (setf k (bitcoin-lisp.crypto:bip32-derive-child k entry)))
                 (when (eq (bitcoin-lisp.rpc::desc-key-derive key) :unhardened)
                   (setf k (bitcoin-lisp.crypto:bip32-derive-child k index)))
                 (return (bitcoin-lisp.crypto:private-key-to-wif
                          (subseq (bitcoin-lisp.crypto:ext-key-key k) 1 33)
                          :network :regtest :compressed t))))))

(defun %wb-prev-info (node name txid vout)
  "(values script-pubkey value-sats) of a wallet tx's output."
  (let* ((wallet (%wc-wallet node name))
         (wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid))
         (out (aref (bitcoin-lisp.serialization:transaction-outputs
                     (bitcoin-lisp.rpc::wallet-tx-tx wtx))
                    vout)))
    (values (bitcoin-lisp.serialization:tx-out-script-pubkey out)
            (bitcoin-lisp.serialization:tx-out-value out))))

(defun %wb-spend (node name inputs outputs)
  "Spend wallet coins: INPUTS is ((txid . vout) ...) of NAME's coins,
OUTPUTS is ((script-pubkey . value-sats) ...). Signs with the wallet's own
keys and broadcasts. Returns (values txid signed-hex)."
  (let ((tx-inputs '())
        (prevtxs '())
        (wifs '()))
    (dolist (input inputs)
      (multiple-value-bind (spk value)
          (%wb-prev-info node name (car input) (cdr input))
        (push (bitcoin-lisp.serialization:make-tx-in
               :previous-output (bitcoin-lisp.serialization:make-outpoint
                                 :hash (car input) :index (cdr input))
               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
               :sequence #xffffffff)
              tx-inputs)
        (push `(("txid" . ,(bitcoin-lisp.rpc::hash-to-hex (car input)))
                ("vout" . ,(cdr input))
                ("scriptPubKey" . ,(bitcoin-lisp.crypto:bytes-to-hex spk))
                ("amount" . ,(/ value 100000000.0d0)))
              prevtxs)
        (let ((address (bitcoin-lisp.rpc::%script->address spk :regtest)))
          (push (%wb-wallet-wif node name address) wifs))))
    (let* ((tx (bitcoin-lisp.serialization:make-transaction
                :version 2
                :inputs (coerce (nreverse tx-inputs) 'simple-vector)
                :outputs (map 'simple-vector
                              (lambda (output)
                                (bitcoin-lisp.serialization:make-tx-out
                                 :value (cdr output)
                                 :script-pubkey (car output)))
                              outputs)
                :lock-time 0))
           (result (bitcoin-lisp.rpc::rpc-signrawtransactionwithkey
                    node (list (bitcoin-lisp.crypto:bytes-to-hex
                                (bitcoin-lisp.serialization:transaction-wire-bytes tx))
                               (remove-duplicates (nreverse wifs) :test #'string=)
                               (nreverse prevtxs))))
           (hex (%wb-aval "hex" result)))
      (unless (eq t (%wb-aval "complete" result))
        (error "wallet spend signing incomplete: ~S" result))
      (let ((txid-hex (bitcoin-lisp.rpc::rpc-sendrawtransaction node (list hex))))
        (values (bitcoin-lisp.rpc::parse-hex-hash txid-hex) hex)))))

(defun %wb-evict-tx (node txid)
  "Evict TXID (recursively, with descendants) from the mempool as a
non-conflict removal (reason :expiry), firing the wallet hooks."
  (bitcoin-lisp.rpc::with-node-lock (node)
    (let ((mempool (bitcoin-lisp::node-mempool node))
          (bitcoin-lisp.mempool::*mempool-removal-reason* :expiry))
      (bitcoin-lisp.mempool::mempool-remove-recursive mempool txid))))

(defun %wb-balances (node)
  (%wb-aval "mine" (bitcoin-lisp.rpc::rpc-getbalances node nil)))

(defun %wb-listunspent (node &rest params)
  (let ((result (bitcoin-lisp.rpc::rpc-listunspent node params)))
    (if (listp result) result '())))

;;; --- Amount parsing (Core AmountFromValue) ---

(test wallet-amount-from-value
  "AmountFromValue: numbers and decimal strings in BTC, 8 fraction digits,
MoneyRange enforced."
  (is (= 500000 (bitcoin-lisp.rpc::%amount-from-value 0.005)))
  (is (= 500000 (bitcoin-lisp.rpc::%amount-from-value "0.005")))
  (is (= 1 (bitcoin-lisp.rpc::%amount-from-value "0.00000001")))
  (is (= 100000000 (bitcoin-lisp.rpc::%amount-from-value 1)))
  (is (= 100000000 (bitcoin-lisp.rpc::%amount-from-value "1")))
  (is (= 2100000000000000 (bitcoin-lisp.rpc::%amount-from-value 21000000)))
  (is (= bitcoin-lisp.rpc::+rpc-type-error+
         (%rpc-error-code
          (lambda () (bitcoin-lisp.rpc::%amount-from-value 21000001)))))
  (is (= bitcoin-lisp.rpc::+rpc-type-error+
         (%rpc-error-code
          (lambda () (bitcoin-lisp.rpc::%amount-from-value "x")))))
  (is (= bitcoin-lisp.rpc::+rpc-type-error+
         (%rpc-error-code
          (lambda () (bitcoin-lisp.rpc::%amount-from-value "0.000000001")))))
  (is (= bitcoin-lisp.rpc::+rpc-type-error+
         (%rpc-error-code
          (lambda () (bitcoin-lisp.rpc::%amount-from-value -1))))))

;;; --- Balance rollups (wallet_balance.py) ---

(test wallet-balance-rollups
  "getbalance/getbalances track immature -> trusted -> untrusted-pending ->
trusted-change transitions exactly like Core's wallet_balance.py."
  (%with-wallet-chain-node (node "balance")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
             (cb-hash (first (%wc-mine node 1 addr)))            ; h1 wallet cb
             (cb-txid (%wc-coinbase-txid node cb-hash)))
        ;; Immature: only getbalances.immature sees it; listunspent needs
        ;; include_immature_coinbase.
        (let ((mine (%wb-balances node)))
          (is (%wb= 50.0d0 (%wb-aval "immature" mine)))
          (is (%wb= 0.0d0 (%wb-aval "trusted" mine)))
          (is (%wb= 0.0d0 (%wb-aval "untrusted_pending" mine))))
        (is (= 1 (length (%wb-listunspent node nil nil nil t
                                          (%ht "include_immature_coinbase" t)))))
        (is (= 0 (length (%wb-listunspent node nil nil nil t
                                          (%ht "include_immature_coinbase"
                                               nil)))))
        (is (%wb= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
        ;; Mature the wallet coinbase (and one op-true funding coinbase).
        (let ((fund (first (%wc-mine node 1 (%wc-optrue-address)))))  ; h2
          (%wc-mine node 100 (%wc-optrue-address))                    ; tip 102
          (is (%wb= 50.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '("*"))))
          (is (%wb= 50.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '("*" 0))))
          (is (%wb= 50.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '("*" 1))))
          (let ((mine (%wb-balances node)))
            (is (%wb= 50.0d0 (%wb-aval "trusted" mine)))
            (is (%wb= 0.0d0 (%wb-aval "immature" mine))))
          ;; Core rejects a non-"*" dummy with RPC_METHOD_DEPRECATED.
          (is (= bitcoin-lisp.rpc::+rpc-method-deprecated+
                 (%rpc-error-code
                  (lambda () (bitcoin-lisp.rpc::rpc-getbalance node '(""))))))
          ;; Untrusted pending: an external (not-from-me) mempool payment.
          (let* ((addr2 (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
                 (spk2 (%address-script addr2 :regtest))
                 (tx1 (%wc-spend-tx (%wc-coinbase-txid node fund) 0
                                    (- +wc-subsidy+ 10000) spk2))
                 (txid1 (%wc-send node tx1)))
            (declare (ignore txid1))
            (let ((mine (%wb-balances node)))
              (is (%wb= 49.9999d0 (%wb-aval "untrusted_pending" mine)))
              (is (%wb= 50.0d0 (%wb-aval "trusted" mine))))
            ;; getbalance never counts untrusted receives.
            (is (%wb= 50.0d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
            ;; The unsafe coin shows only with include_unsafe (minconf 0).
            (let ((unsafe (%wb-listunspent node 0)))
              (is (= 2 (length unsafe)))
              (let ((zero-conf (find 0 unsafe :key (lambda (e)
                                                     (%wb-aval "confirmations" e)))))
                (is (not (null zero-conf)))
                (is (eq 'yason:false (%wb-aval "safe" zero-conf)))
                ;; In-mempool coins report their ancestor package.
                (is (= 1 (%wb-aval "ancestorcount" zero-conf)))
                (is (plusp (%wb-aval "ancestorsize" zero-conf)))))
            (is (= 1 (length (%wb-listunspent node 0 nil nil
                                               bitcoin-lisp.rpc:+json-false+))))
            (is (= 1 (length (%wb-listunspent node))))
            ;; Trusted zero-conf change: spend our own mature coinbase with
            ;; change to an internal address.
            (let ((change-addr (bitcoin-lisp.rpc::rpc-getrawchangeaddress node nil)))
              (%wb-spend node "w"
                         (list (cons cb-txid 0))
                         (list (cons (%p2sh-optrue-spk) 2000000000)
                               (cons (%address-script change-addr :regtest)
                                     2999990000)))
              (let ((mine (%wb-balances node)))
                (is (%wb= 29.9999d0 (%wb-aval "trusted" mine)))
                (is (%wb= 49.9999d0 (%wb-aval "untrusted_pending" mine))))
              (is (%wb= 29.9999d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
              (is (%wb= 29.9999d0 (bitcoin-lisp.rpc::rpc-getbalance node '("*" 0))))
              ;; minconf=1: the change is unconfirmed, the coinbase spent.
              (is (%wb= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node '("*" 1))))
              ;; Confirm everything.
              (%wc-mine node 1 (%wc-optrue-address))
              (let ((mine (%wb-balances node)))
                (is (%wb= 79.9998d0 (%wb-aval "trusted" mine)))
                (is (%wb= 0.0d0 (%wb-aval "untrusted_pending" mine))))
              (is (%wb= 79.9998d0 (bitcoin-lisp.rpc::rpc-getbalance node '("*" 1))))
              ;; lastprocessedblock rides the tip.
              (let ((lpb (%wb-aval "lastprocessedblock"
                                   (bitcoin-lisp.rpc::rpc-getbalances node nil))))
                (is (= 103 (%wb-aval "height" lpb)))
                (is (string= (%wc-tip-hex node) (%wb-aval "hash" lpb))))
              ;; Cache-coherence: recomputing from scratch (all caches
              ;; dropped) must not change any balance.
              (let ((before (%wb-balances node))
                    (wallet (%wc-wallet node "w")))
                (loop for wtx being the hash-values
                        of (bitcoin-lisp.rpc::wallet-map-wallet wallet)
                      do (bitcoin-lisp.rpc::wtx-mark-dirty wtx))
                (is (equalp before (%wb-balances node)))))))))))

;;; --- listunspent filters + coin locking ---

(test wallet-listunspent-filters-and-locks
  "listunspent filter arguments, query_options, field set, and
lockunspent/listlockunspent with persistence across reload."
  (%with-wallet-chain-node (node "coins")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((addr1 (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
             (addr2 (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
             (b1 (first (%wc-mine node 1 addr1)))
             (b2 (first (%wc-mine node 1 addr2)))
             (cb1 (%wc-coinbase-txid node b1))
             (cb2 (%wc-coinbase-txid node b2)))
        (%wc-mine node 101 (%wc-optrue-address))   ; tip 103; both mature
        (let ((coins (%wb-listunspent node)))
          (is (= 2 (length coins)))
          (let ((entry (find addr1 coins :key (lambda (e) (%wb-aval "address" e))
                                         :test #'string=)))
            (is (not (null entry)))
            (is (string= (bitcoin-lisp.rpc::hash-to-hex cb1) (%wb-aval "txid" entry)))
            (is (= 0 (%wb-aval "vout" entry)))
            (is (= 103 (%wb-aval "confirmations" entry)))
            (is (%wb= 50.0d0 (%wb-aval "amount" entry)))
            (is (string= "" (%wb-aval "label" entry)))
            (is (eq t (%wb-aval "spendable" entry)))
            (is (eq t (%wb-aval "solvable" entry)))
            (is (eq t (%wb-aval "safe" entry)))
            (is (eql 0 (search "wpkh([" (%wb-aval "desc" entry))))
            (is (plusp (length (%wb-aval "parent_descs" entry))))
            (is (null (%wb-aval "ancestorcount" entry)))))
        ;; Address filter; bad addresses.
        (let ((only (%wb-listunspent node 1 9999999 (list addr2))))
          (is (= 1 (length only)))
          (is (string= addr2 (%wb-aval "address" (first only)))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
               (%rpc-error-code
                (lambda () (%wb-listunspent node 1 9999999 '("bogus"))))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
               (%rpc-error-code
                (lambda () (%wb-listunspent node 1 9999999 (list addr1 addr1))))))
        ;; Depth windows.
        (is (= 1 (length (%wb-listunspent node 103))))
        (is (= 0 (length (%wb-listunspent node 104))))
        (is (= 0 (length (%wb-listunspent node 1 1))))
        ;; query_options.
        (is (= 0 (length (%wb-listunspent node nil nil nil t
                                          (%ht "minimumAmount" 60)))))
        (is (= 2 (length (%wb-listunspent node nil nil nil t
                                          (%ht "minimumAmount" "50")))))
        (is (= 0 (length (%wb-listunspent node nil nil nil t
                                          (%ht "maximumAmount" 1)))))
        (is (= 1 (length (%wb-listunspent node nil nil nil t
                                          (%ht "maximumCount" 1)))))
        (is (= 1 (length (%wb-listunspent node nil nil nil t
                                          (%ht "minimumSumAmount" 50)))))
        ;; Locking.
        (let ((outpoint (%ht "txid" (bitcoin-lisp.rpc::hash-to-hex cb1) "vout" 0)))
          (is (eq t (bitcoin-lisp.rpc::rpc-lockunspent
                     node (list nil (list outpoint)))))
          (is (= 1 (length (%wb-listunspent node))))
          (let ((locked (bitcoin-lisp.rpc::rpc-listlockunspent node nil)))
            (is (= 1 (length locked)))
            (is (string= (bitcoin-lisp.rpc::hash-to-hex cb1)
                         (%wb-aval "txid" (first locked)))))
          ;; Already locked (non-persistent relock) / expected locked.
          (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
                 (%rpc-error-code
                  (lambda () (bitcoin-lisp.rpc::rpc-lockunspent
                              node (list nil (list outpoint)))))))
          (is (eq t (bitcoin-lisp.rpc::rpc-lockunspent
                     node (list t (list outpoint)))))
          (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
                 (%rpc-error-code
                  (lambda () (bitcoin-lisp.rpc::rpc-lockunspent
                              node (list t (list outpoint)))))))
          ;; Unknown tx / out-of-bounds vout.
          (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
                 (%rpc-error-code
                  (lambda ()
                    (bitcoin-lisp.rpc::rpc-lockunspent
                     node (list nil (list (%ht "txid" (make-string 64 :initial-element #\7)
                                               "vout" 0))))))))
          (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
                 (%rpc-error-code
                  (lambda ()
                    (bitcoin-lisp.rpc::rpc-lockunspent
                     node (list nil (list (%ht "txid" (bitcoin-lisp.rpc::hash-to-hex cb1)
                                               "vout" 5))))))))
          ;; Persistent vs memory locks across a crash + reload.
          (is (eq t (bitcoin-lisp.rpc::rpc-lockunspent
                     node (list nil (list outpoint) t))))
          (is (eq t (bitcoin-lisp.rpc::rpc-lockunspent
                     node (list nil
                                (list (%ht "txid" (bitcoin-lisp.rpc::hash-to-hex cb2)
                                           "vout" 0))))))
          (is (= 2 (length (bitcoin-lisp.rpc::rpc-listlockunspent node nil))))
          (%crash-close-wallet node "w")
          (bitcoin-lisp.rpc::rpc-loadwallet node '("w"))
          (let ((locked (bitcoin-lisp.rpc::rpc-listlockunspent node nil)))
            (is (= 1 (length locked)))
            (is (string= (bitcoin-lisp.rpc::hash-to-hex cb1)
                         (%wb-aval "txid" (first locked)))))
          ;; Unlock-all clears persistent locks too.
          (is (eq t (bitcoin-lisp.rpc::rpc-lockunspent node (list t))))
          (is (= 0 (length (bitcoin-lisp.rpc::rpc-listlockunspent node nil))))
          (is (= 2 (length (%wb-listunspent node)))))))))

;;; --- Labels + getaddressinfo ---

(test wallet-labels-and-getaddressinfo
  "setlabel/getaddressesbylabel/listlabels semantics and getaddressinfo's
Core field set per address type, with inferred descriptors that derive back
to the same address."
  (%with-wallet-chain-node (node "addrinfo")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((bech32 (bitcoin-lisp.rpc::rpc-getnewaddress node '("gold")))
             (legacy (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "legacy")))
             (p2sh-segwit (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "p2sh-segwit")))
             (bech32m (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32m")))
             (change (bitcoin-lisp.rpc::rpc-getrawchangeaddress node nil))
             (foreign (bitcoin-lisp.crypto:encode-p2pkh-address
                       (make-array 20 :element-type '(unsigned-byte 8)
                                      :initial-element 7)
                       :regtest)))
        ;; --- labels ---
        (is (equal '("" "gold")
                   (bitcoin-lisp.rpc::rpc-listlabels node nil)))
        (is (equal '("" "gold")
                   (bitcoin-lisp.rpc::rpc-listlabels node '("receive"))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-listlabels node '("bogus"))))))
        (let ((by-label (bitcoin-lisp.rpc::rpc-getaddressesbylabel node '("gold"))))
          (is (= 1 (length by-label)))
          (is (string= bech32 (car (first by-label))))
          (is (string= "receive" (%wb-aval "purpose" (cdr (first by-label))))))
        ;; Relabel an own address: purpose stays receive.
        (bitcoin-lisp.rpc::rpc-setlabel node (list bech32 "silver"))
        (is (= bitcoin-lisp.rpc::+rpc-wallet-invalid-label-name+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-getaddressesbylabel node '("gold"))))))
        (is (string= "receive"
                     (%wb-aval "purpose"
                               (cdr (first (bitcoin-lisp.rpc::rpc-getaddressesbylabel
                                            node '("silver")))))))
        ;; Label a foreign address: purpose send.
        (bitcoin-lisp.rpc::rpc-setlabel node (list foreign "them"))
        (is (equal '("them") (bitcoin-lisp.rpc::rpc-listlabels node '("send"))))
        (is (string= "send"
                     (%wb-aval "purpose"
                               (cdr (first (bitcoin-lisp.rpc::rpc-getaddressesbylabel
                                            node '("them")))))))
        (is (= bitcoin-lisp.rpc::+rpc-wallet-invalid-label-name+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-getaddressesbylabel node '("*"))))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-setlabel node '("bogus" "x"))))))
        ;; --- getaddressinfo per address type ---
        (flet ((info (address)
                 (bitcoin-lisp.rpc::rpc-getaddressinfo node (list address)))
               (roundtrips-p (info address)
                 (equal (list address)
                        (bitcoin-lisp.rpc::rpc-deriveaddresses
                         node (list (%wb-aval "desc" info))))))
          (let ((i (info bech32)))
            (is (eq t (%wb-aval "ismine" i)))
            (is (eq t (%wb-aval "solvable" i)))
            (is (eq 'yason:false (%wb-aval "iswatchonly" i)))
            (is (eq 'yason:false (%wb-aval "isscript" i)))
            (is (eq t (%wb-aval "iswitness" i)))
            (is (= 0 (%wb-aval "witness_version" i)))
            (is (= 40 (length (%wb-aval "witness_program" i))))
            (is (= 66 (length (%wb-aval "pubkey" i))))
            (is (eq 'yason:false (%wb-aval "ischange" i)))
            (is (string= "m/84h/1h/0h/0/0" (%wb-aval "hdkeypath" i)))
            (is (string= (make-string 40 :initial-element #\0)
                         (%wb-aval "hdseedid" i)))
            (is (= 8 (length (%wb-aval "hdmasterfingerprint" i))))
            (is (eql 0 (search "wpkh([" (%wb-aval "desc" i))))
            (is (eql 0 (search "wpkh(" (%wb-aval "parent_desc" i))))
            (is (equal '("silver") (%wb-aval "labels" i)))
            (is (roundtrips-p i bech32)))
          (let ((i (info legacy)))
            (is (eq t (%wb-aval "ismine" i)))
            (is (eq 'yason:false (%wb-aval "isscript" i)))
            (is (eq 'yason:false (%wb-aval "iswitness" i)))
            (is (eq t (%wb-aval "iscompressed" i)))
            (is (string= "m/44h/1h/0h/0/0" (%wb-aval "hdkeypath" i)))
            (is (eql 0 (search "pkh([" (%wb-aval "desc" i))))
            (is (roundtrips-p i legacy)))
          (let ((i (info p2sh-segwit)))
            (is (eq t (%wb-aval "ismine" i)))
            (is (eq t (%wb-aval "isscript" i)))
            (is (eq 'yason:false (%wb-aval "iswitness" i)))
            (is (string= "witness_v0_keyhash" (%wb-aval "script" i)))
            (is (stringp (%wb-aval "hex" i)))
            (is (= 66 (length (%wb-aval "pubkey" i))))
            (let ((embedded (%wb-aval "embedded" i)))
              (is (not (null embedded)))
              (is (eq t (%wb-aval "iswitness" embedded)))
              (is (= 0 (%wb-aval "witness_version" embedded)))
              (is (stringp (%wb-aval "address" embedded))))
            (is (string= "m/49h/1h/0h/0/0" (%wb-aval "hdkeypath" i)))
            (is (eql 0 (search "sh(wpkh([" (%wb-aval "desc" i))))
            (is (roundtrips-p i p2sh-segwit)))
          (let ((i (info bech32m)))
            (is (eq t (%wb-aval "ismine" i)))
            (is (eq t (%wb-aval "isscript" i)))
            (is (eq t (%wb-aval "iswitness" i)))
            (is (= 1 (%wb-aval "witness_version" i)))
            (is (= 64 (length (%wb-aval "witness_program" i))))
            (is (string= "m/86h/1h/0h/0/0" (%wb-aval "hdkeypath" i)))
            (is (eql 0 (search "tr([" (%wb-aval "desc" i))))
            (is (roundtrips-p i bech32m)))
          ;; Change addresses have no book entry -> ischange.
          (let ((i (info change)))
            (is (eq t (%wb-aval "ismine" i)))
            (is (eq t (%wb-aval "ischange" i)))
            (is (string= "m/84h/1h/0h/1/0" (%wb-aval "hdkeypath" i)))
            (is (equal '() (coerce (%wb-aval "labels" i) 'list))))
          ;; Foreign address: not ours, not solvable, no desc.
          (let ((i (info foreign)))
            (is (eq 'yason:false (%wb-aval "ismine" i)))
            (is (eq 'yason:false (%wb-aval "solvable" i)))
            (is (null (%wb-aval "desc" i)))
            (is (null (%wb-aval "hdkeypath" i)))
            (is (equal '("them") (%wb-aval "labels" i)))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-getaddressinfo node '("nope"))))))))))

;;; --- abandontransaction (wallet_abandonconflict.py) ---

(test wallet-abandontransaction
  "Eviction -> abandon frees the inputs (descendants abandoned too);
re-broadcast unabandons the parent only; double spends surface in
walletconflicts on both sides."
  (%with-wallet-chain-node (node "abandon")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
             (cb-hash (first (%wc-mine node 1 addr)))              ; h1 wallet cb
             (cb-txid (%wc-coinbase-txid node cb-hash))
             (fund (first (%wc-mine node 1 (%wc-optrue-address)))) ; h2 op-true
             (fund-txid (%wc-coinbase-txid node fund)))
        (%wc-mine node 101 (%wc-optrue-address))                   ; tip 103
        ;; Not-in-wallet txid; confirmed tx: both -5.
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-abandontransaction
                            node (list (make-string 64 :initial-element #\f)))))))
        (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
               (%rpc-error-code
                (lambda () (bitcoin-lisp.rpc::rpc-abandontransaction
                            node (list (bitcoin-lisp.rpc::hash-to-hex cb-txid)))))))
        ;; Parent P spends our coinbase; child C spends P. Both in mempool.
        (let* ((addr-p (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
               (addr-c (bitcoin-lisp.rpc::rpc-getnewaddress node nil)))
          (multiple-value-bind (txid-p hex-p)
              (%wb-spend node "w" (list (cons cb-txid 0))
                         (list (cons (%address-script addr-p :regtest)
                                     4999990000)))
            (multiple-value-bind (txid-c hex-c)
                (%wb-spend node "w" (list (cons txid-p 0))
                           (list (cons (%address-script addr-c :regtest)
                                       4999980000)))
              (declare (ignore hex-c))
              ;; In-mempool: not eligible.
              (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
                     (%rpc-error-code
                      (lambda () (bitcoin-lisp.rpc::rpc-abandontransaction
                                  node (list (bitcoin-lisp.rpc::hash-to-hex txid-p)))))))
              (is (%wb= 49.9998d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
              ;; Evict both without a conflict: balance collapses (inputs
              ;; spent, change unavailable), coins vanish from listunspent.
              (%wb-evict-tx node txid-p)
              (is (%wb= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
              (let ((mine (%wb-balances node)))
                (is (%wb= 0.0d0 (+ (%wb-aval "trusted" mine)
                                   (%wb-aval "untrusted_pending" mine)))))
              (is (= 0 (length (%wb-listunspent node 0))))
              ;; Abandon P: descendants abandoned, inputs respendable.
              (is (null (bitcoin-lisp.rpc::rpc-abandontransaction
                         node (list (bitcoin-lisp.rpc::hash-to-hex txid-p)))))
              (let ((wallet (%wc-wallet node "w")))
                (is (eq t (bitcoin-lisp.rpc::wallet-tx-abandoned
                           (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid-p))))
                (is (eq t (bitcoin-lisp.rpc::wallet-tx-abandoned
                           (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid-c)))))
              (is (%wb= 50.0d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
              (is (= 1 (length (%wb-listunspent node 0))))
              ;; Abandoned send entries in listtransactions.
              (let ((sends (remove-if-not
                            (lambda (e) (equal "send" (%wb-aval "category" e)))
                            (bitcoin-lisp.rpc::rpc-listtransactions
                             node '("*" 100)))))
                (is (plusp (length sends)))
                (dolist (send sends)
                  (is (eq t (%wb-aval "abandoned" send)))
                  (is (= 0 (%wb-aval "confirmations" send)))))
              ;; Re-broadcast P: unabandoned via the mempool hook; C stays
              ;; abandoned, so P's output is again unspent.
              (bitcoin-lisp.rpc::rpc-sendrawtransaction node (list hex-p))
              (let ((wallet (%wc-wallet node "w")))
                (is (eq :in-mempool (bitcoin-lisp.rpc::wallet-tx-state
                                     (bitcoin-lisp.rpc::wallet-get-wallet-tx
                                      wallet txid-p))))
                (is (eq t (bitcoin-lisp.rpc::wallet-tx-abandoned
                           (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid-c)))))
              (is (%wb= 49.9999d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
              ;; Clean up: evict + re-abandon P so part 2 starts from the
              ;; unspent-coinbase state.
              (%wb-evict-tx node txid-p)
              (bitcoin-lisp.rpc::rpc-abandontransaction
               node (list (bitcoin-lisp.rpc::hash-to-hex txid-p)))))
          ;; --- Part 2: double spend -> walletconflicts on both sides ---
          (let* ((addr3 (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
                 (addr3x (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
                 (tx3 (%wc-spend-tx fund-txid 0 (- +wc-subsidy+ 10000)
                                    (%address-script addr3 :regtest)))
                 (txid3 (%wc-send node tx3))
                 (tx3x (%wc-spend-tx fund-txid 0 (- +wc-subsidy+ 20000)
                                     (%address-script addr3x :regtest)))
                 (txid3x (bitcoin-lisp.serialization:transaction-hash tx3x)))
            (bitcoin-lisp.rpc::rpc-generateblock
             node (list (%wc-optrue-address)
                        (list (bitcoin-lisp.crypto:bytes-to-hex
                               (bitcoin-lisp.serialization:transaction-wire-bytes tx3x)))))
            (let ((g3 (%wc-gettx node txid3))
                  (g3x (%wc-gettx node txid3x)))
              (is (= -1 (%wb-aval "confirmations" g3)))
              (is (equal (list (bitcoin-lisp.rpc::hash-to-hex txid3x))
                         (%wb-aval "walletconflicts" g3)))
              (is (= 1 (%wb-aval "confirmations" g3x)))
              (is (equal (list (bitcoin-lisp.rpc::hash-to-hex txid3))
                         (%wb-aval "walletconflicts" g3x))))
            ;; Conflicted tx not eligible for abandonment (depth < 0).
            (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
                   (%rpc-error-code
                    (lambda () (bitcoin-lisp.rpc::rpc-abandontransaction
                                node (list (bitcoin-lisp.rpc::hash-to-hex txid3)))))))
            ;; Balance counts only the confirmed double spend.
            (let ((mine (%wb-balances node)))
              (is (%wb= 99.9998d0 (%wb-aval "trusted" mine)))))))))) ; 50 + 49.9998

;;; --- avoid_reuse: getbalances used / listunspent reused ---

(test wallet-avoid-reuse-accounting
  "With WALLET_FLAG_AVOID_REUSE, spending from an address marks it dirty:
payments to it are excluded from the default balances (reported as used),
listunspent flags them reused, and the destdata record survives reload."
  (%with-wallet-chain-node (node "reuse")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      ;; avoid_reuse is the 5th createwallet argument.
      (bitcoin-lisp.rpc::rpc-createwallet node '("wr" nil nil nil t))
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
             (spk (%address-script addr :regtest))
             (fund1 (first (%wc-mine node 1 (%wc-optrue-address))))
             (fund2 (first (%wc-mine node 1 (%wc-optrue-address)))))
        (%wc-mine node 101 (%wc-optrue-address))   ; tip 103; both mature
        ;; Pay 1 to ADDR, confirm.
        (let* ((tx1 (%wc-spend-tx (%wc-coinbase-txid node fund1) 0
                                  (- +wc-subsidy+ 10000) spk))
               (txid1 (%wc-send node tx1)))
          (%wc-mine node 1 (%wc-optrue-address))
          (is (%wb= 49.9999d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
          ;; Spend it all away: ADDR becomes previously-spent.
          (%wb-spend node "wr" (list (cons txid1 0))
                     (list (cons (%p2sh-optrue-spk) 4999890000)))
          (%wc-mine node 1 (%wc-optrue-address))
          (is (%wb= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
          ;; Pay 2 to the SAME address, confirm: reused.
          (let ((tx2 (%wc-spend-tx (%wc-coinbase-txid node fund2) 0
                                   (- +wc-subsidy+ 10000) spk)))
            (%wc-send node tx2)
            (%wc-mine node 1 (%wc-optrue-address))
            (let ((mine (%wb-balances node)))
              (is (%wb= 0.0d0 (%wb-aval "trusted" mine)))
              (is (%wb= 49.9999d0 (%wb-aval "used" mine))))
            (is (%wb= 0.0d0 (bitcoin-lisp.rpc::rpc-getbalance node nil)))
            ;; Explicit avoid_reuse=false sees the reused funds (a null
            ;; fourth argument keeps the wallet default, like Core).
            (is (%wb= 49.9999d0 (bitcoin-lisp.rpc::rpc-getbalance
                                 node (list "*" 0 nil
                                            bitcoin-lisp.rpc:+json-false+))))
            ;; listunspent still lists the coin, flagged reused.
            (let ((coins (%wb-listunspent node)))
              (is (= 1 (length coins)))
              (is (eq t (%wb-aval "reused" (first coins)))))
            ;; getbalance avoid_reuse=true on a wallet without the flag: -4.
            (bitcoin-lisp.rpc::rpc-createwallet node '("plain"))
            (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "plain"))
              (is (= bitcoin-lisp.rpc::+rpc-wallet-error+
                     (%rpc-error-code
                      (lambda () (bitcoin-lisp.rpc::rpc-getbalance
                                  node '("*" 0 nil t)))))))
            ;; The previously-spent marker survives a crash + reload.
            (let ((bitcoin-lisp.rpc::*rpc-wallet-name* "wr"))
              (%crash-close-wallet node "wr")
              (bitcoin-lisp.rpc::rpc-loadwallet node '("wr"))
              (let ((mine (%wb-balances node)))
                (is (%wb= 0.0d0 (%wb-aval "trusted" mine)))
                (is (%wb= 49.9999d0 (%wb-aval "used" mine)))))))))))
