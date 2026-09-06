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

(defun %wb-aval (key alist)
  (btc-amount (cdr (assoc key alist :test #'string=))))

(defun %wb= (a b)
  "Compare two BTC amounts to sub-satoshi tolerance. Either may be an amount
TOKEN as an RPC emits it (BTC-AMOUNT decodes it) or a plain number."
  (< (abs (- (btc-amount a) (btc-amount b))) 1d-6))

(defun %wb-wallet-wif (node name address)
  "WIF for ADDRESS's private key, derived from wallet NAME's owning SPKM."
  (let* ((wallet (%wc-wallet node name))
         (script (%address-script address :regtest)))
    (loop for spkm being the hash-values of (bl.wallet::wallet-spkms wallet)
          for index = (bl.wallet::spkm-is-mine spkm script)
          when index
            do (let* ((key (first (bl.rpc:out-desc-ordered-keys
                                   (bl.wallet::desc-spkm-desc spkm))))
                      (k (bl.rpc:desc-key-root-xprv
                          key (bl.wallet::spkm-privkey-provider
                               wallet spkm))))
                 (dolist (entry (bl.rpc:desc-key-path key))
                   (setf k (bl.crypto:bip32-derive-child k entry)))
                 (when (eq (bl.rpc:desc-key-derive key) :unhardened)
                   (setf k (bl.crypto:bip32-derive-child k index)))
                 (return (bl.crypto:private-key-to-wif
                          (subseq (bl.crypto:ext-key-key k) 1 33)
                          :network :regtest :compressed t))))))

(defun %wb-prev-info (node name txid vout)
  "(values script-pubkey value-sats) of a wallet tx's output."
  (let* ((wallet (%wc-wallet node name))
         (wtx (bl.wallet::wallet-get-wallet-tx wallet txid))
         (out (aref (bl.ser:transaction-outputs
                     (bl.wallet::wallet-tx-tx wtx))
                    vout)))
    (values (bl.ser:tx-out-script-pubkey out)
            (bl.ser:tx-out-value out))))

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
        (push (bl.ser:make-tx-in
               :previous-output (bl.ser:make-outpoint
                                 :hash (car input) :index (cdr input))
               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
               :sequence #xffffffff)
              tx-inputs)
        (push `(("txid" . ,(bl.rpc:hash-to-hex (car input)))
                ("vout" . ,(cdr input))
                ("scriptPubKey" . ,(bl.crypto:bytes-to-hex spk))
                ("amount" . ,(/ value 100000000.0d0)))
              prevtxs)
        (let ((address (bl.rpc:script->address spk :regtest)))
          (push (%wb-wallet-wif node name address) wifs))))
    (let* ((tx (bl.ser:make-transaction
                :version 2
                :inputs (coerce (nreverse tx-inputs) 'simple-vector)
                :outputs (map 'simple-vector
                              (lambda (output)
                                (bl.ser:make-tx-out
                                 :value (cdr output)
                                 :script-pubkey (car output)))
                              outputs)
                :lock-time 0))
           (result (bl.rpc::rpc-signrawtransactionwithkey
                    node (list (bl.crypto:bytes-to-hex
                                (bl.ser:transaction-wire-bytes tx))
                               (remove-duplicates (nreverse wifs) :test #'string=)
                               (nreverse prevtxs))))
           (hex (%wb-aval "hex" result)))
      (unless (eq t (%wb-aval "complete" result))
        (error "wallet spend signing incomplete: ~S" result))
      (let ((txid-hex (bl.rpc::rpc-sendrawtransaction node (list hex))))
        (values (bl.rpc:parse-hex-hash txid-hex) hex)))))

(defun %wb-evict-tx (node txid)
  "Evict TXID (recursively, with descendants) from the mempool as a
non-conflict removal (reason :expiry), firing the wallet hooks."
  (bl.rpc:with-node-lock (node)
    (let ((mempool (bl:node-mempool node))
          (bl.mp:*mempool-removal-reason* :expiry))
      (bl.mp:mempool-remove-recursive mempool txid))))

(defun %wb-balances (node)
  (%wb-aval "mine" (bl.wallet::rpc-getbalances node nil)))

(defun %wb-listunspent (node &rest params)
  (let ((result (bl.wallet::rpc-listunspent node params)))
    (if (listp result) result '())))

;;; --- Amount parsing (Core AmountFromValue) ---

(test wallet-amount-from-value
  "AmountFromValue: numbers and decimal strings in BTC, 8 fraction digits,
MoneyRange enforced."
  (is (= 500000 (bl.rpc:amount-from-value 0.005)))
  (is (= 500000 (bl.rpc:amount-from-value "0.005")))
  (is (= 1 (bl.rpc:amount-from-value "0.00000001")))
  (is (= 100000000 (bl.rpc:amount-from-value 1)))
  (is (= 100000000 (bl.rpc:amount-from-value "1")))
  (is (= 2100000000000000 (bl.rpc:amount-from-value 21000000)))
  (is (= bl.rpc:+rpc-type-error+
         (rpc-error-code-of
          (lambda () (bl.rpc:amount-from-value 21000001)))))
  (is (= bl.rpc:+rpc-type-error+
         (rpc-error-code-of
          (lambda () (bl.rpc:amount-from-value "x")))))
  (is (= bl.rpc:+rpc-type-error+
         (rpc-error-code-of
          (lambda () (bl.rpc:amount-from-value "0.000000001")))))
  (is (= bl.rpc:+rpc-type-error+
         (rpc-error-code-of
          (lambda () (bl.rpc:amount-from-value -1))))))

;;; --- Balance rollups (wallet_balance.py) ---

(test wallet-balance-rollups
  "getbalance/getbalances track immature -> trusted -> untrusted-pending ->
trusted-change transitions exactly like Core's wallet_balance.py."
  (with-wallet-chain-node (node "balance" :wallet "w")
    (let* ((addr (bl.wallet::rpc-getnewaddress node nil))
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
      (is (%wb= 0.0d0 (bl.wallet::rpc-getbalance node nil)))
      ;; Mature the wallet coinbase (and one op-true funding coinbase).
      (let ((fund (first (%wc-mine node 1 (%wc-optrue-address)))))  ; h2
        (%wc-mine node 100 (%wc-optrue-address))                    ; tip 102
        (is (%wb= 50.0d0 (bl.wallet::rpc-getbalance node '("*"))))
        (is (%wb= 50.0d0 (bl.wallet::rpc-getbalance node '("*" 0))))
        (is (%wb= 50.0d0 (bl.wallet::rpc-getbalance node '("*" 1))))
        (let ((mine (%wb-balances node)))
          (is (%wb= 50.0d0 (%wb-aval "trusted" mine)))
          (is (%wb= 0.0d0 (%wb-aval "immature" mine))))
        ;; Core rejects a non-"*" dummy with RPC_METHOD_DEPRECATED.
        (is (= bl.rpc:+rpc-method-deprecated+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-getbalance node '(""))))))
        ;; Untrusted pending: an external (not-from-me) mempool payment.
        (let* ((addr2 (bl.wallet::rpc-getnewaddress node nil))
               (spk2 (%address-script addr2 :regtest))
               (tx1 (%wc-spend-tx (%wc-coinbase-txid node fund) 0
                                  (- +wc-subsidy+ 10000) spk2))
               (txid1 (%wc-send node tx1)))
          (declare (ignore txid1))
          (let ((mine (%wb-balances node)))
            (is (%wb= 49.9999d0 (%wb-aval "untrusted_pending" mine)))
            (is (%wb= 50.0d0 (%wb-aval "trusted" mine))))
          ;; getbalance never counts untrusted receives.
          (is (%wb= 50.0d0 (bl.wallet::rpc-getbalance node nil)))
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
                                             bl.rpc:+json-false+))))
          (is (= 1 (length (%wb-listunspent node))))
          ;; Trusted zero-conf change: spend our own mature coinbase with
          ;; change to an internal address.
          (let ((change-addr (bl.wallet::rpc-getrawchangeaddress node nil)))
            (%wb-spend node "w"
                       (list (cons cb-txid 0))
                       (list (cons (p2sh-optrue-script-pubkey) 2000000000)
                             (cons (%address-script change-addr :regtest)
                                   2999990000)))
            (let ((mine (%wb-balances node)))
              (is (%wb= 29.9999d0 (%wb-aval "trusted" mine)))
              (is (%wb= 49.9999d0 (%wb-aval "untrusted_pending" mine))))
            (is (%wb= 29.9999d0 (bl.wallet::rpc-getbalance node nil)))
            (is (%wb= 29.9999d0 (bl.wallet::rpc-getbalance node '("*" 0))))
            ;; minconf=1: the change is unconfirmed, the coinbase spent.
            (is (%wb= 0.0d0 (bl.wallet::rpc-getbalance node '("*" 1))))
            ;; Confirm everything.
            (%wc-mine node 1 (%wc-optrue-address))
            (let ((mine (%wb-balances node)))
              (is (%wb= 79.9998d0 (%wb-aval "trusted" mine)))
              (is (%wb= 0.0d0 (%wb-aval "untrusted_pending" mine))))
            (is (%wb= 79.9998d0 (bl.wallet::rpc-getbalance node '("*" 1))))
            ;; lastprocessedblock rides the tip.
            (let ((lpb (%wb-aval "lastprocessedblock"
                                 (bl.wallet::rpc-getbalances node nil))))
              (is (= 103 (%wb-aval "height" lpb)))
              (is (string= (%wc-tip-hex node) (%wb-aval "hash" lpb))))
            ;; Cache-coherence: recomputing from scratch (all caches
            ;; dropped) must not change any balance.
            (let ((before (%wb-balances node))
                  (wallet (%wc-wallet node "w")))
              (loop for wtx being the hash-values
                      of (bl.wallet::wallet-map-wallet wallet)
                    do (bl.wallet::wtx-mark-dirty wtx))
              (is (equalp before (%wb-balances node))))))))))

;;; --- listunspent filters + coin locking ---

(test wallet-listunspent-filters-and-locks
  "listunspent filter arguments, query_options, field set, and
lockunspent/listlockunspent with persistence across reload."
  (with-wallet-chain-node (node "coins" :wallet "w")
    (let* ((addr1 (bl.wallet::rpc-getnewaddress node nil))
           (addr2 (bl.wallet::rpc-getnewaddress node nil))
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
          (is (string= (bl.rpc:hash-to-hex cb1) (%wb-aval "txid" entry)))
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
      (is (= bl.rpc:+rpc-invalid-address-or-key+
             (rpc-error-code-of
              (lambda () (%wb-listunspent node 1 9999999 '("bogus"))))))
      (is (= bl.rpc:+rpc-invalid-parameter+
             (rpc-error-code-of
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
      (let ((outpoint (%ht "txid" (bl.rpc:hash-to-hex cb1) "vout" 0)))
        (is (eq t (bl.wallet::rpc-lockunspent
                   node (list nil (list outpoint)))))
        (is (= 1 (length (%wb-listunspent node))))
        (let ((locked (bl.wallet::rpc-listlockunspent node nil)))
          (is (= 1 (length locked)))
          (is (string= (bl.rpc:hash-to-hex cb1)
                       (%wb-aval "txid" (first locked)))))
        ;; Already locked (non-persistent relock) / expected locked.
        (is (= bl.rpc:+rpc-invalid-parameter+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-lockunspent
                            node (list nil (list outpoint)))))))
        (is (eq t (bl.wallet::rpc-lockunspent
                   node (list t (list outpoint)))))
        (is (= bl.rpc:+rpc-invalid-parameter+
               (rpc-error-code-of
                (lambda () (bl.wallet::rpc-lockunspent
                            node (list t (list outpoint)))))))
        ;; Unknown tx / out-of-bounds vout.
        (is (= bl.rpc:+rpc-invalid-parameter+
               (rpc-error-code-of
                (lambda ()
                  (bl.wallet::rpc-lockunspent
                   node (list nil (list (%ht "txid" (make-string 64 :initial-element #\7)
                                             "vout" 0))))))))
        (is (= bl.rpc:+rpc-invalid-parameter+
               (rpc-error-code-of
                (lambda ()
                  (bl.wallet::rpc-lockunspent
                   node (list nil (list (%ht "txid" (bl.rpc:hash-to-hex cb1)
                                             "vout" 5))))))))
        ;; Persistent vs memory locks across a crash + reload.
        (is (eq t (bl.wallet::rpc-lockunspent
                   node (list nil (list outpoint) t))))
        (is (eq t (bl.wallet::rpc-lockunspent
                   node (list nil
                              (list (%ht "txid" (bl.rpc:hash-to-hex cb2)
                                         "vout" 0))))))
        (is (= 2 (length (bl.wallet::rpc-listlockunspent node nil))))
        (%crash-close-wallet node "w")
        (bl.wallet::rpc-loadwallet node '("w"))
        (let ((locked (bl.wallet::rpc-listlockunspent node nil)))
          (is (= 1 (length locked)))
          (is (string= (bl.rpc:hash-to-hex cb1)
                       (%wb-aval "txid" (first locked)))))
        ;; Unlock-all clears persistent locks too.
        (is (eq t (bl.wallet::rpc-lockunspent node (list t))))
        (is (= 0 (length (bl.wallet::rpc-listlockunspent node nil))))
        (is (= 2 (length (%wb-listunspent node))))))))

;;; --- Labels + getaddressinfo ---

(test wallet-labels-and-getaddressinfo
  "setlabel/getaddressesbylabel/listlabels semantics and getaddressinfo's
Core field set per address type, with inferred descriptors that derive back
to the same address."
  (with-wallet-chain-node (node "addrinfo" :wallet "w")
    (let* ((bech32 (bl.wallet::rpc-getnewaddress node '("gold")))
           (legacy (bl.wallet::rpc-getnewaddress node '("" "legacy")))
           (p2sh-segwit (bl.wallet::rpc-getnewaddress node '("" "p2sh-segwit")))
           (bech32m (bl.wallet::rpc-getnewaddress node '("" "bech32m")))
           (change (bl.wallet::rpc-getrawchangeaddress node nil))
           (foreign (bl.crypto:encode-p2pkh-address
                     (make-array 20 :element-type '(unsigned-byte 8)
                                    :initial-element 7)
                     :regtest)))
      ;; --- labels ---
      (is (equal '("" "gold")
                 (bl.wallet::rpc-listlabels node nil)))
      (is (equal '("" "gold")
                 (bl.wallet::rpc-listlabels node '("receive"))))
      (is (= bl.rpc:+rpc-invalid-parameter+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-listlabels node '("bogus"))))))
      (let ((by-label (bl.wallet::rpc-getaddressesbylabel node '("gold"))))
        (is (= 1 (length by-label)))
        (is (string= bech32 (car (first by-label))))
        (is (string= "receive" (%wb-aval "purpose" (cdr (first by-label))))))
      ;; Relabel an own address: purpose stays receive.
      (bl.wallet::rpc-setlabel node (list bech32 "silver"))
      (is (= bl.rpc:+rpc-wallet-invalid-label-name+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-getaddressesbylabel node '("gold"))))))
      (is (string= "receive"
                   (%wb-aval "purpose"
                             (cdr (first (bl.wallet::rpc-getaddressesbylabel
                                          node '("silver")))))))
      ;; Label a foreign address: purpose send.
      (bl.wallet::rpc-setlabel node (list foreign "them"))
      (is (equal '("them") (bl.wallet::rpc-listlabels node '("send"))))
      (is (string= "send"
                   (%wb-aval "purpose"
                             (cdr (first (bl.wallet::rpc-getaddressesbylabel
                                          node '("them")))))))
      (is (= bl.rpc:+rpc-wallet-invalid-label-name+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-getaddressesbylabel node '("*"))))))
      (is (= bl.rpc:+rpc-invalid-address-or-key+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-setlabel node '("bogus" "x"))))))
      ;; --- getaddressinfo per address type ---
      (flet ((info (address)
               (bl.wallet::rpc-getaddressinfo node (list address)))
             (roundtrips-p (info address)
               (equal (list address)
                      (bl.rpc::rpc-deriveaddresses
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
      (is (= bl.rpc:+rpc-invalid-address-or-key+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-getaddressinfo node '("nope")))))))))

;;; --- abandontransaction (wallet_abandonconflict.py) ---

(test wallet-abandontransaction
  "Eviction -> abandon frees the inputs (descendants abandoned too);
re-broadcast unabandons the parent only; double spends surface in
walletconflicts on both sides."
  (with-wallet-chain-node (node "abandon" :wallet "w")
    (let* ((addr (bl.wallet::rpc-getnewaddress node nil))
           (cb-hash (first (%wc-mine node 1 addr)))              ; h1 wallet cb
           (cb-txid (%wc-coinbase-txid node cb-hash))
           (fund (first (%wc-mine node 1 (%wc-optrue-address)))) ; h2 op-true
           (fund-txid (%wc-coinbase-txid node fund)))
      (%wc-mine node 101 (%wc-optrue-address))                   ; tip 103
      ;; Not-in-wallet txid; confirmed tx: both -5.
      (is (= bl.rpc:+rpc-invalid-address-or-key+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-abandontransaction
                          node (list (make-string 64 :initial-element #\f)))))))
      (is (= bl.rpc:+rpc-invalid-address-or-key+
             (rpc-error-code-of
              (lambda () (bl.wallet::rpc-abandontransaction
                          node (list (bl.rpc:hash-to-hex cb-txid)))))))
      ;; Parent P spends our coinbase; child C spends P. Both in mempool.
      (let* ((addr-p (bl.wallet::rpc-getnewaddress node nil))
             (addr-c (bl.wallet::rpc-getnewaddress node nil)))
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
            (is (= bl.rpc:+rpc-invalid-address-or-key+
                   (rpc-error-code-of
                    (lambda () (bl.wallet::rpc-abandontransaction
                                node (list (bl.rpc:hash-to-hex txid-p)))))))
            (is (%wb= 49.9998d0 (bl.wallet::rpc-getbalance node nil)))
            ;; Evict both without a conflict: balance collapses (inputs
            ;; spent, change unavailable), coins vanish from listunspent.
            (%wb-evict-tx node txid-p)
            (is (%wb= 0.0d0 (bl.wallet::rpc-getbalance node nil)))
            (let ((mine (%wb-balances node)))
              (is (%wb= 0.0d0 (+ (%wb-aval "trusted" mine)
                                 (%wb-aval "untrusted_pending" mine)))))
            (is (= 0 (length (%wb-listunspent node 0))))
            ;; Abandon P: descendants abandoned, inputs respendable.
            (is (null (bl.wallet::rpc-abandontransaction
                       node (list (bl.rpc:hash-to-hex txid-p)))))
            (let ((wallet (%wc-wallet node "w")))
              (is (eq t (bl.wallet::wallet-tx-abandoned
                         (bl.wallet::wallet-get-wallet-tx wallet txid-p))))
              (is (eq t (bl.wallet::wallet-tx-abandoned
                         (bl.wallet::wallet-get-wallet-tx wallet txid-c)))))
            (is (%wb= 50.0d0 (bl.wallet::rpc-getbalance node nil)))
            (is (= 1 (length (%wb-listunspent node 0))))
            ;; Abandoned send entries in listtransactions.
            (let ((sends (remove-if-not
                          (lambda (e) (equal "send" (%wb-aval "category" e)))
                          (bl.wallet::rpc-listtransactions
                           node '("*" 100)))))
              (is (plusp (length sends)))
              (dolist (send sends)
                (is (eq t (%wb-aval "abandoned" send)))
                (is (= 0 (%wb-aval "confirmations" send)))))
            ;; Re-broadcast P: unabandoned via the mempool hook; C stays
            ;; abandoned, so P's output is again unspent.
            (bl.rpc::rpc-sendrawtransaction node (list hex-p))
            (let ((wallet (%wc-wallet node "w")))
              (is (eq :in-mempool (bl.wallet::wallet-tx-state
                                   (bl.wallet::wallet-get-wallet-tx
                                    wallet txid-p))))
              (is (eq t (bl.wallet::wallet-tx-abandoned
                         (bl.wallet::wallet-get-wallet-tx wallet txid-c)))))
            (is (%wb= 49.9999d0 (bl.wallet::rpc-getbalance node nil)))
            ;; Clean up: evict + re-abandon P so part 2 starts from the
            ;; unspent-coinbase state.
            (%wb-evict-tx node txid-p)
            (bl.wallet::rpc-abandontransaction
             node (list (bl.rpc:hash-to-hex txid-p)))))
        ;; --- Part 2: double spend -> walletconflicts on both sides ---
        (let* ((addr3 (bl.wallet::rpc-getnewaddress node nil))
               (addr3x (bl.wallet::rpc-getnewaddress node nil))
               (tx3 (%wc-spend-tx fund-txid 0 (- +wc-subsidy+ 10000)
                                  (%address-script addr3 :regtest)))
               (txid3 (%wc-send node tx3))
               (tx3x (%wc-spend-tx fund-txid 0 (- +wc-subsidy+ 20000)
                                   (%address-script addr3x :regtest)))
               (txid3x (bl.ser:transaction-hash tx3x)))
          (bl.rpc::rpc-generateblock
           node (list (%wc-optrue-address)
                      (list (bl.crypto:bytes-to-hex
                             (bl.ser:transaction-wire-bytes tx3x)))))
          (let ((g3 (%wc-gettx node txid3))
                (g3x (%wc-gettx node txid3x)))
            (is (= -1 (%wb-aval "confirmations" g3)))
            (is (equal (list (bl.rpc:hash-to-hex txid3x))
                       (%wb-aval "walletconflicts" g3)))
            (is (= 1 (%wb-aval "confirmations" g3x)))
            (is (equal (list (bl.rpc:hash-to-hex txid3))
                       (%wb-aval "walletconflicts" g3x))))
          ;; Conflicted tx not eligible for abandonment (depth < 0).
          (is (= bl.rpc:+rpc-invalid-address-or-key+
                 (rpc-error-code-of
                  (lambda () (bl.wallet::rpc-abandontransaction
                              node (list (bl.rpc:hash-to-hex txid3)))))))
          ;; Balance counts only the confirmed double spend.
          (let ((mine (%wb-balances node)))
            (is (%wb= 99.9998d0 (%wb-aval "trusted" mine))))))))) ; 50 + 49.9998

;;; --- avoid_reuse: getbalances used / listunspent reused ---

(test wallet-avoid-reuse-accounting
  "With WALLET_FLAG_AVOID_REUSE, spending from an address marks it dirty:
payments to it are excluded from the default balances (reported as used),
listunspent flags them reused, and the destdata record survives reload."
  (with-wallet-chain-node (node "reuse")
    (let ((bl.wallet::*rpc-wallet-name* nil))
      ;; avoid_reuse is the 5th createwallet argument.
      (bl.wallet::rpc-createwallet node '("wr" nil nil nil t))
      (let* ((addr (bl.wallet::rpc-getnewaddress node nil))
             (spk (%address-script addr :regtest))
             (fund1 (first (%wc-mine node 1 (%wc-optrue-address))))
             (fund2 (first (%wc-mine node 1 (%wc-optrue-address)))))
        (%wc-mine node 101 (%wc-optrue-address))   ; tip 103; both mature
        ;; Pay 1 to ADDR, confirm.
        (let* ((tx1 (%wc-spend-tx (%wc-coinbase-txid node fund1) 0
                                  (- +wc-subsidy+ 10000) spk))
               (txid1 (%wc-send node tx1)))
          (%wc-mine node 1 (%wc-optrue-address))
          (is (%wb= 49.9999d0 (bl.wallet::rpc-getbalance node nil)))
          ;; Spend it all away: ADDR becomes previously-spent.
          (%wb-spend node "wr" (list (cons txid1 0))
                     (list (cons (p2sh-optrue-script-pubkey) 4999890000)))
          (%wc-mine node 1 (%wc-optrue-address))
          (is (%wb= 0.0d0 (bl.wallet::rpc-getbalance node nil)))
          ;; Pay 2 to the SAME address, confirm: reused.
          (let ((tx2 (%wc-spend-tx (%wc-coinbase-txid node fund2) 0
                                   (- +wc-subsidy+ 10000) spk)))
            (%wc-send node tx2)
            (%wc-mine node 1 (%wc-optrue-address))
            (let ((mine (%wb-balances node)))
              (is (%wb= 0.0d0 (%wb-aval "trusted" mine)))
              (is (%wb= 49.9999d0 (%wb-aval "used" mine))))
            (is (%wb= 0.0d0 (bl.wallet::rpc-getbalance node nil)))
            ;; Explicit avoid_reuse=false sees the reused funds (a null
            ;; fourth argument keeps the wallet default, like Core).
            (is (%wb= 49.9999d0 (bl.wallet::rpc-getbalance
                                 node (list "*" 0 nil
                                            bl.rpc:+json-false+))))
            ;; listunspent still lists the coin, flagged reused.
            (let ((coins (%wb-listunspent node)))
              (is (= 1 (length coins)))
              (is (eq t (%wb-aval "reused" (first coins)))))
            ;; getbalance avoid_reuse=true on a wallet without the flag: -4.
            (bl.wallet::rpc-createwallet node '("plain"))
            (let ((bl.wallet::*rpc-wallet-name* "plain"))
              (is (= bl.rpc:+rpc-wallet-error+
                     (rpc-error-code-of
                      (lambda () (bl.wallet::rpc-getbalance
                                  node '("*" 0 nil t)))))))
            ;; The previously-spent marker survives a crash + reload.
            (let ((bl.wallet::*rpc-wallet-name* "wr"))
              (%crash-close-wallet node "wr")
              (bl.wallet::rpc-loadwallet node '("wr"))
              (let ((mine (%wb-balances node)))
                (is (%wb= 0.0d0 (%wb-aval "trusted" mine)))
                (is (%wb= 49.9999d0 (%wb-aval "used" mine)))))))))))
