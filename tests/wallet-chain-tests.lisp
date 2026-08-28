(in-package #:bitcoin-lisp.tests)

;;; Wallet P2 tests: chain tracking (docs/wallet-plan.md §5 P2).
;;;
;;; CWalletTx record encoding round-trips (Core transaction.h Serialize/
;;; Unserialize + TxStateInterpretSerialized), then live regtest scenarios
;;; driving the real hooks — connect-block / perform-reorg / mempool — via
;;; the mining and chain-control RPCs: fund wallet, mine, coinbase maturity,
;;; reorg across the funding tx, block + mempool double-spend conflicts,
;;; rescan-from-genesis equal to live-tracked state, and keypool/tx-state
;;; persistence across a simulated crash + reload.
;;;
;;; Reuses %regtest-node-fixture/%with-regtest (mining-tests.lisp) and the
;;; P2SH(OP_TRUE) spend helpers (package-tests.lisp).

(def-suite wallet-chain-tests
  :description "Wallet P2: chain tracking, conflicts, rescan, tx RPCs"
  :in :bitcoin-lisp-tests)

(in-suite wallet-chain-tests)

;;; --- Fixture ---

(defvar *wallet-chain-counter* 0)

(defun %wc-fixture (suffix &key (keypool 5))
  "A regtest node at genesis with a wallet manager, the genesis block stored
(so rescans from height 0 can read it), ready for the chain hooks."
  (let* ((id (format nil "~A-~D-~D" suffix (get-universal-time)
                     (incf *wallet-chain-counter*)))
         (node (%regtest-node-fixture (format nil "wallet-~A" id)))
         (wallet-dir (merge-pathnames (format nil "wallet-chain-~A/" id)
                                      (uiop:temporary-directory))))
    (bl.store:store-block
     (bl::node-block-store node)
     (bl.store:make-genesis-block :regtest))
    (setf (bl::node-wallet-manager node)
          (bl.wallet::make-wallet-manager
           :data-directory wallet-dir :network :regtest :keypool-size keypool))
    node))

(defmacro %with-wallet-chain-node ((node suffix &key (keypool 5)) &body body)
  "Run BODY under regtest bindings with NODE bound to a %wc-fixture and
bl::*node* bound so the wallet chain hooks fire."
  `(with-network (:regtest)
    (let* ((,node (%wc-fixture ,suffix :keypool ,keypool))
           (bl::*node* ,node))
      (unwind-protect (progn ,@body)
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl::node-wallet-manager ,node)))))))

(defun %wc-wallet (node name)
  (gethash name (bl.wallet::wallet-manager-wallets
                 (bl::node-wallet-manager node))))

(defun %wc-optrue-address ()
  "P2SH(OP_TRUE) address for regtest — the throwaway coinbase target."
  (bl.crypto:encode-p2sh-address
   (bl.crypto:hash160 +optrue-redeem+) :regtest))

(defun %wc-mine (node n address)
  "Mine N regtest blocks to ADDRESS; returns the block hash hex list."
  (bl.rpc::rpc-generatetoaddress node (list n address)))

(defun %wc-tip-hex (node)
  (bl.rpc::hash-to-hex
   (bl.store:best-block-hash (bl::node-chain-state node))))

(defun %wc-coinbase-txid (node block-hash-hex)
  "Txid of the coinbase of the block named by BLOCK-HASH-HEX."
  (let* ((store (bl::node-block-store node))
         (block (bl.store:get-block
                 store (bl.rpc::parse-hex-hash block-hash-hex))))
    (bl.ser:transaction-hash
     (first (bl.ser:bitcoin-block-transactions block)))))

(defun %wc-spend-tx (prev-txid prev-vout value spk &key (sequence #xffffffff))
  "A tx spending a P2SH(OP_TRUE) prevout, paying VALUE satoshis to SPK
(input value minus VALUE is the fee)."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash prev-txid :index prev-vout)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence sequence))
   :outputs (vector (bl.ser:make-tx-out
                     :value value :script-pubkey spk))
   :lock-time 0))

(defun %wc-send (node tx)
  "sendrawtransaction TX; returns its txid."
  (bl.rpc::rpc-sendrawtransaction
   node (list (bl.crypto:bytes-to-hex
               (bl.ser:transaction-wire-bytes tx))))
  (bl.ser:transaction-hash tx))

(defun %wc-gettx (node txid)
  (bl.wallet::rpc-gettransaction
   node (list (bl.rpc::hash-to-hex txid))))

(defun %wc-state-snapshot (wallet)
  "Comparable snapshot of the wallet's tracked tx states: txid-hex ->
(state height index abandoned order-pos time-smart)."
  (let ((snap '()))
    (maphash (lambda (txid wtx)
               (push (list (bl.rpc::hash-to-hex txid)
                           (bl.wallet::wallet-tx-state wtx)
                           (bl.wallet::wallet-tx-block-height wtx)
                           (bl.wallet::wallet-tx-block-index wtx)
                           (bl.wallet::wallet-tx-abandoned wtx)
                           (bl.wallet::wallet-tx-order-pos wtx)
                           (bl.wallet::wallet-tx-time-smart wtx))
                     snap))
             (bl.wallet::wallet-map-wallet wallet))
    (sort snap #'string< :key #'first)))

(defun %wc-details-category (gettx)
  "The category of the first details entry of a gettransaction result."
  (%aval "category" (first (%aval "details" gettx))))

(defun %wc-snapshot-sans-times (snapshot)
  "Snapshot entries without the time-smart field, for comparing wallets that
tracked the same txs through different paths (a rescan stamps nTimeSmart with
the block time; live mempool tracking stamps the arrival time — Core too)."
  (mapcar #'butlast snapshot))

(defconstant +wc-subsidy+ 5000000000)

;;; --- CWalletTx record encoding ---

(test wallet-tx-record-roundtrip
  "CWalletTx records round-trip byte-exactly through Core's layout, and the
TxStateInterpretSerialized vectors map to the right states."
  (let* ((prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (tx (%wc-spend-tx prev 0 12345 (%p2sh-optrue-spk)))
         (txid (bl.ser:transaction-hash tx))
         (bhash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (wtx (bl.wallet::make-wallet-tx :tx tx :txid txid)))
    ;; Confirmed state: hash + index serialized, height NOT (reload -> -1).
    (bl.wallet::%wtx-apply-state wtx :confirmed bhash 42 2)
    (setf (bl.wallet::wallet-tx-time-received wtx) 111
          (bl.wallet::wallet-tx-time-smart wtx) 222
          (bl.wallet::wallet-tx-order-pos wtx) 5
          (bl.wallet::wallet-tx-map-value wtx) '(("comment" . "hi")))
    (let ((bytes (bl.wallet::wallet-tx-record-value wtx)))
      ;; Layout: tx wire bytes, then the state hash.
      (let ((wire (bl.ser:transaction-wire-bytes tx)))
        (is (equalp wire (subseq bytes 0 (length wire))))
        (is (equalp bhash (subseq bytes (length wire) (+ (length wire) 32)))))
      (multiple-value-bind (loaded warning)
          (bl.wallet::parse-wallet-tx-record bytes)
        (is (null warning))
        (is (equalp txid (bl.wallet::wallet-tx-txid loaded)))
        (is (eq :confirmed (bl.wallet::wallet-tx-state loaded)))
        (is (equalp bhash (bl.wallet::wallet-tx-block-hash loaded)))
        (is (= -1 (bl.wallet::wallet-tx-block-height loaded)))
        (is (= 2 (bl.wallet::wallet-tx-block-index loaded)))
        (is (= 111 (bl.wallet::wallet-tx-time-received loaded)))
        (is (= 222 (bl.wallet::wallet-tx-time-smart loaded)))
        (is (= 5 (bl.wallet::wallet-tx-order-pos loaded)))
        ;; Record-only map fields are stripped back out on load.
        (is (equal '(("comment" . "hi"))
                   (bl.wallet::wallet-tx-map-value loaded)))))
    ;; Block-conflicted: hash + index -1.
    (bl.wallet::%wtx-apply-state wtx :block-conflicted bhash 42)
    (let ((loaded (bl.wallet::parse-wallet-tx-record
                   (bl.wallet::wallet-tx-record-value wtx))))
      (is (eq :block-conflicted (bl.wallet::wallet-tx-state loaded)))
      (is (equalp bhash (bl.wallet::wallet-tx-block-hash loaded))))
    ;; Inactive: ZERO/0. Abandoned: ONE/-1. InMempool serializes as
    ;; inactive — Core relies on exactly that (TxStateSerialized*).
    (bl.wallet::%wtx-apply-state wtx :inactive)
    (is (eq :inactive (bl.wallet::wallet-tx-state
                       (bl.wallet::parse-wallet-tx-record
                        (bl.wallet::wallet-tx-record-value wtx)))))
    (bl.wallet::%wtx-apply-state wtx :inactive nil -1 -1 t)
    (let ((loaded (bl.wallet::parse-wallet-tx-record
                   (bl.wallet::wallet-tx-record-value wtx))))
      (is (eq :inactive (bl.wallet::wallet-tx-state loaded)))
      (is (eq t (bl.wallet::wallet-tx-abandoned loaded))))
    (bl.wallet::%wtx-apply-state wtx :in-mempool)
    (let ((loaded (bl.wallet::parse-wallet-tx-record
                   (bl.wallet::wallet-tx-record-value wtx))))
      (is (eq :inactive (bl.wallet::wallet-tx-state loaded)))
      (is (null (bl.wallet::wallet-tx-abandoned loaded))))))

;;; --- Coinbase tracking + maturity ---

(test wallet-coinbase-tracking-and-maturity
  "Mining to a wallet address tracks the coinbase through the connect hook;
categories follow Core's maturity rules (immature until depth 101, the
COINBASE_MATURITY+1 rule)."
  (%with-wallet-chain-node (node "maturity")
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("w"))
      (let* ((addr (bl.wallet::rpc-getnewaddress node nil))
             (hashes (%wc-mine node 1 addr))
             (cb-txid (%wc-coinbase-txid node (first hashes)))
             (wallet (%wc-wallet node "w")))
        ;; Tracked via the hook, confirmed at height 1.
        (is (= 1 (hash-table-count (bl.wallet::wallet-map-wallet wallet))))
        (is (= 1 (%aval "txcount" (bl.wallet::rpc-getwalletinfo node nil))))
        (let ((gettx (%wc-gettx node cb-txid)))
          (is (= 1 (%aval "confirmations" gettx)))
          (is (eq t (%aval "generated" gettx)))
          (is (string= (first hashes) (%aval "blockhash" gettx)))
          (is (= 1 (%aval "blockheight" gettx)))
          (is (= 0 (%aval "blockindex" gettx)))
          (is (plusp (%aval "blocktime" gettx)))
          (is (string= "immature" (%wc-details-category gettx)))
          ;; Immature coinbase credit counts as 0 (receive.cpp).
          (is (< (abs (%aval "amount" gettx)) 1d-9))
          (is (string= "no" (%aval "bip125-replaceable" gettx))))
        ;; Depth 100 = still one block short of spendable (maturity + 1).
        (%wc-mine node 99 (%wc-optrue-address))
        (is (string= "immature" (%wc-details-category (%wc-gettx node cb-txid))))
        (%wc-mine node 1 (%wc-optrue-address))
        (let ((gettx (%wc-gettx node cb-txid)))
          (is (= 101 (%aval "confirmations" gettx)))
          (is (string= "generate" (%wc-details-category gettx)))
          (is (< (abs (- (%aval "amount" gettx) 50.0d0)) 1d-9)))
        ;; listtransactions reports the single generate entry.
        (let ((entries (bl.wallet::rpc-listtransactions node nil)))
          (is (= 1 (length entries)))
          (is (string= "generate" (%aval "category" (first entries))))
          (is (string= addr (%aval "address" (first entries)))))
        ;; lastprocessedblock tracks the tip.
        (let ((lpb (%aval "lastprocessedblock"
                          (bl.wallet::rpc-getwalletinfo node nil))))
          (is (= 101 (%aval "height" lpb))))))))

;;; --- Mempool receive -> confirm -> listsinceblock -> rescan equality ---

(test wallet-receive-confirm-rescan
  "A mempool payment reaches the wallet through the mempool-add hook,
confirms through the connect hook, listsinceblock windows are Core-shaped,
and a from-genesis rescan (rescanblockchain AND a fresh importdescriptors
wallet) reproduces exactly the live-tracked state."
  (%with-wallet-chain-node (node "receive")
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("w"))
      (let* ((wallet (%wc-wallet node "w"))
             (addr (bl.wallet::rpc-getnewaddress node nil))
             (spk (%address-script addr :regtest))
             (fund-hashes (%wc-mine node 1 (%wc-optrue-address))))
        (%wc-mine node 100 (%wc-optrue-address))   ; tip 101, coinbase@1 mature
        (let* ((fund-txid (%wc-coinbase-txid node (first fund-hashes)))
               (tx1 (%wc-spend-tx fund-txid 0 (- +wc-subsidy+ 10000) spk))
               (txid1 (%wc-send node tx1)))
          ;; In-mempool: confirmations 0, trusted false (not from us) —
          ;; the wave-10 JSON false literal, not null.
          (let ((gettx (%wc-gettx node txid1)))
            (is (= 0 (%aval "confirmations" gettx)))
            (is (eq 'yason:false (%aval "trusted" gettx)))
            (is (null (%aval "generated" gettx)))
            (is (string= "receive" (%wc-details-category gettx)))
            (is (< (abs (- (%aval "amount" gettx) 49.9999d0)) 1d-9))
            (is (string= "no" (%aval "bip125-replaceable" gettx))))
          (is (eq :in-mempool (bl.wallet::wallet-tx-state
                               (bl.wallet::wallet-get-wallet-tx
                                wallet txid1))))
          ;; Confirm at height 102.
          (let ((h101 (%wc-tip-hex node)))
            (%wc-mine node 1 (%wc-optrue-address))
            (let ((gettx (%wc-gettx node txid1)))
              (is (= 1 (%aval "confirmations" gettx)))
              (is (= 102 (%aval "blockheight" gettx)))
              (is (plusp (%aval "blocktime" gettx))))
            ;; listsinceblock from height 101: depth window includes tx1;
            ;; from the tip: excludes it; lastblock respects target_confirms.
            (let ((since (bl.wallet::rpc-listsinceblock node (list h101))))
              (is (= 1 (length (%aval "transactions" since))))
              (is (string= (%wc-tip-hex node) (%aval "lastblock" since))))
            (let ((since (bl.wallet::rpc-listsinceblock
                          node (list (%wc-tip-hex node)))))
              (is (zerop (length (%aval "transactions" since)))))
            (let ((since (bl.wallet::rpc-listsinceblock
                          node (list nil 2))))
              ;; No filter block: everything listed; lastblock = height 101.
              (is (plusp (length (%aval "transactions" since))))
              (is (string= h101 (%aval "lastblock" since))))
            ;; Unknown blockhash -> Core's -5.
            (is (= bl.rpc::+rpc-invalid-address-or-key+
                   (%rpc-error-code
                    (lambda ()
                      (bl.wallet::rpc-listsinceblock
                       node (list (make-string 64 :initial-element #\7))))))))
          ;; abortrescan with no scan running: JSON false; not scanning.
          (is (eq 'yason:false (bl.wallet::rpc-abortrescan node nil)))
          (is (eq 'yason:false
                  (%aval "scanning"
                         (bl.wallet::rpc-getwalletinfo node nil))))
          ;; rescanblockchain from genesis must reproduce the live state.
          (let ((before (%wc-state-snapshot wallet))
                (result (bl.wallet::rpc-rescanblockchain node '(0))))
            (is (= 0 (%aval "start_height" result)))
            (is (= 102 (%aval "stop_height" result)))
            (is (equalp before (%wc-state-snapshot wallet))))
          ;; A second wallet importing the same descriptor with an old
          ;; timestamp rescans to the identical tracked state.
          (let* ((descs (%aval "descriptors"
                               (bl.wallet::rpc-listdescriptors node '(t))))
                 (ext-wpkh (find-if (lambda (d)
                                      (let ((s (%aval "desc" d)))
                                        (and (eql 0 (search "wpkh(" s))
                                             (search "/0/*" s))))
                                    descs)))
            (is (not (null ext-wpkh)))
            (bl.wallet::rpc-createwallet node '("w2" nil t)) ; blank
            (let* ((bl.wallet::*rpc-wallet-name* "w2")
                   (results (bl.wallet::rpc-importdescriptors
                             node (list (list (%ht "desc" (%aval "desc" ext-wpkh)
                                                   "timestamp" 1
                                                   "active" t
                                                   "range" 10))))))
              (is (eq t (%aval "success" (first results))))
              (let ((w2 (%wc-wallet node "w2")))
                ;; Same tracked tx set (only tx1 pays the wpkh descriptor;
                ;; wallet w also only has tx1). time-smart legitimately
                ;; differs: live tracking stamps mempool arrival, the
                ;; import rescan stamps the block time.
                (is (equalp (%wc-snapshot-sans-times (%wc-state-snapshot wallet))
                            (%wc-snapshot-sans-times (%wc-state-snapshot w2))))))))))))

;;; --- Reorg: disconnected coinbase abandoned, reconnect restores ---

(test wallet-coinbase-reorg-abandon
  "Disconnecting the wallet's coinbase block marks it inactive+abandoned
(orphan category); reconsidering the block reconfirms it."
  (%with-wallet-chain-node (node "cbreorg")
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("w"))
      (let* ((addr (bl.wallet::rpc-getnewaddress node nil))
             (b1 (first (%wc-mine node 1 addr)))
             (cb-txid (%wc-coinbase-txid node b1))
             (wallet (%wc-wallet node "w")))
        (%wc-mine node 1 (%wc-optrue-address))     ; tip 2
        (is (= 2 (%aval "confirmations" (%wc-gettx node cb-txid))))
        ;; Reorg the funding block away.
        (bl.rpc::rpc-invalidateblock node (list b1))
        (let ((wtx (bl.wallet::wallet-get-wallet-tx wallet cb-txid)))
          (is (eq :inactive (bl.wallet::wallet-tx-state wtx)))
          (is (eq t (bl.wallet::wallet-tx-abandoned wtx))))
        (let ((gettx (%wc-gettx node cb-txid)))
          (is (= 0 (%aval "confirmations" gettx)))
          (is (string= "orphan" (%wc-details-category gettx)))
          (is (eq t (%aval "abandoned" (first (%aval "details" gettx))))))
        (is (= 0 (bl.wallet::wallet-last-block-height wallet)))
        ;; Reconnect: confirmed again at height 1, abandoned cleared.
        (bl.rpc::rpc-reconsiderblock node (list b1))
        (let ((wtx (bl.wallet::wallet-get-wallet-tx wallet cb-txid)))
          (is (eq :confirmed (bl.wallet::wallet-tx-state wtx)))
          (is (= 1 (bl.wallet::wallet-tx-block-height wtx))))
        (is (= 2 (%aval "confirmations" (%wc-gettx node cb-txid))))
        (is (= 2 (bl.wallet::wallet-last-block-height wallet)))))))

;;; --- Reorg across the funding tx + double-spend conflicts ---

(test wallet-funding-reorg-and-conflicts
  "Reorging out the block that confirmed a wallet-funding tx returns it to
the mempool (in-mempool state); a confirmed double-spend marks it
block-conflicted (negative confirmations); disconnecting the conflict block
reverts it to inactive with the double-spend as a mempool conflict; re-mining
the double-spend re-conflicts it and clears the mempool conflict."
  (%with-wallet-chain-node (node "conflicts")
    (let ((bl.wallet::*rpc-wallet-name* nil))
      (bl.wallet::rpc-createwallet node '("w"))
      (let* ((wallet (%wc-wallet node "w"))
             (addr (bl.wallet::rpc-getnewaddress node nil))
             (spk (%address-script addr :regtest))
             (fund1 (first (%wc-mine node 1 (%wc-optrue-address))))   ; h1
             (fund2 (first (%wc-mine node 1 (%wc-optrue-address)))))  ; h2
        (%wc-mine node 100 (%wc-optrue-address))   ; tip 102: both mature
        ;; --- Part 1: reorg across the funding tx ---
        (let* ((tx1 (%wc-spend-tx (%wc-coinbase-txid node fund1) 0
                                  (- +wc-subsidy+ 10000) spk))
               (txid1 (%wc-send node tx1))
               (fblock (first (%wc-mine node 1 (%wc-optrue-address))))) ; h103
          (is (= 1 (%aval "confirmations" (%wc-gettx node txid1))))
          (bl.rpc::rpc-invalidateblock node (list fblock))
          ;; Disconnected -> re-added to the mempool -> wallet sees mempool
          ;; state through the re-add hook.
          (let ((wtx (bl.wallet::wallet-get-wallet-tx wallet txid1)))
            (is (eq :in-mempool (bl.wallet::wallet-tx-state wtx))))
          (is (= 0 (%aval "confirmations" (%wc-gettx node txid1))))
          ;; Mine again — to the WALLET address, so the coinbase (and hence
          ;; the block hash) necessarily differs from the invalidated block;
          ;; re-mining to the same target in the same second can reproduce
          ;; the byte-identical block. tx1 (back in the mempool) reconfirms.
          (let ((fblock2 (first (%wc-mine node 1 addr))))
            (let ((gettx (%wc-gettx node txid1)))
              (is (= 1 (%aval "confirmations" gettx)))
              (is (string= fblock2 (%aval "blockhash" gettx)))
              (is (not (string= fblock (%aval "blockhash" gettx)))))))
        ;; --- Part 2: double-spend conflict via a block ---
        (let* ((cb2 (%wc-coinbase-txid node fund2))
               (tx2 (%wc-spend-tx cb2 0 (- +wc-subsidy+ 10000) spk))
               (txid2 (%wc-send node tx2))
               ;; Double-spend of the same prevout, NOT paying the wallet.
               (tx2x (%wc-spend-tx cb2 0 (- +wc-subsidy+ 1000000)
                                   (%p2sh-optrue-spk)))
               (txid2x (bl.ser:transaction-hash tx2x)))
          (is (= 0 (%aval "confirmations" (%wc-gettx node txid2))))
          ;; Mine a block containing ONLY the double-spend.
          (let ((conflict-block
                  (%aval "hash"
                         (bl.rpc::rpc-generateblock
                          node (list (%wc-optrue-address)
                                     (list (bl.crypto:bytes-to-hex
                                            (bl.ser:transaction-wire-bytes tx2x))))))))
            ;; tx2: removed from the mempool as :conflict, then marked
            ;; block-conflicted by the connect hook's mapTxSpends scan.
            (let ((wtx (bl.wallet::wallet-get-wallet-tx wallet txid2)))
              (is (eq :block-conflicted (bl.wallet::wallet-tx-state wtx))))
            (let ((gettx (%wc-gettx node txid2)))
              (is (= -1 (%aval "confirmations" gettx)))
              (is (eq 'yason:false (%aval "trusted" gettx)))
              (is (zerop (length (%aval "mempoolconflicts" gettx)))))
            ;; Disconnect the conflict block: tx2 reverts to inactive, and
            ;; the re-added double-spend becomes a mempool conflict of tx2.
            (bl.rpc::rpc-invalidateblock node (list conflict-block))
            (let ((wtx (bl.wallet::wallet-get-wallet-tx wallet txid2)))
              (is (eq :inactive (bl.wallet::wallet-tx-state wtx))))
            (let* ((gettx (%wc-gettx node txid2))
                   (mconf (%aval "mempoolconflicts" gettx)))
              (is (= 0 (%aval "confirmations" gettx)))
              (is (equal (list (bl.rpc::hash-to-hex txid2x)) mconf)))
            ;; Mine the double-spend again (it is back in the mempool):
            ;; blockConnected re-conflicts tx2 AND clears the mempool
            ;; conflict (reason-:block removal runs the erase loop).
            (%wc-mine node 1 (%wc-optrue-address))
            (let ((gettx (%wc-gettx node txid2)))
              (is (= -1 (%aval "confirmations" gettx)))
              (is (zerop (length (%aval "mempoolconflicts" gettx)))))))))))

;;; --- Crash + reload persistence, load-time catch-up ---

(test wallet-txstate-persistence-crash-reload
  "Tx state and the keypool survive a crash-simulating close + loadwallet
(records were persisted at hook time), and a wallet unloaded while blocks
were mined catches up from its stored locator on load."
  (%with-wallet-chain-node (node "crash")
    (let ((bl.wallet::*rpc-wallet-name* nil)
          (issued '()))
      (bl.wallet::rpc-createwallet node '("w"))
      (let* ((addr (bl.wallet::rpc-getnewaddress node nil))
             (spk (%address-script addr :regtest))
             (cb-hash (first (%wc-mine node 1 addr)))        ; wallet coinbase h1
             (cb-txid (%wc-coinbase-txid node cb-hash))
             (fund (first (%wc-mine node 1 (%wc-optrue-address))))) ; h2
        (push addr issued)
        (%wc-mine node 100 (%wc-optrue-address))              ; tip 102
        (let* ((tx1 (%wc-spend-tx (%wc-coinbase-txid node fund) 0
                                  (- +wc-subsidy+ 10000) spk))
               (txid1 (%wc-send node tx1)))
          (%wc-mine node 1 (%wc-optrue-address))              ; tip 103
          (push (bl.wallet::rpc-getnewaddress node nil) issued)
          (push (bl.wallet::rpc-getnewaddress node '("" "bech32m")) issued)
          (let* ((wallet (%wc-wallet node "w"))
                 (before (%wc-state-snapshot wallet)))
            (is (= 2 (length before)))          ; coinbase + tx1
            ;; Crash: close the DB without any graceful-unload writes.
            (%crash-close-wallet node "w")
            (bl.wallet::rpc-loadwallet node '("w"))
            (let ((wallet2 (%wc-wallet node "w")))
              (is (not (eq wallet wallet2)))
              (is (equalp before (%wc-state-snapshot wallet2)))
              (is (= 103 (bl.wallet::wallet-last-block-height wallet2)))
              ;; Confirmed states resolved against the chain on load.
              (let ((wtx (bl.wallet::wallet-get-wallet-tx wallet2 txid1)))
                (is (eq :confirmed (bl.wallet::wallet-tx-state wtx)))
                (is (= 103 (bl.wallet::wallet-tx-block-height wtx))))
              (is (= 2 (%aval "txcount"
                              (bl.wallet::rpc-getwalletinfo node nil))))
              ;; Keypool: no previously issued address is reissued.
              (let ((fresh (list (bl.wallet::rpc-getnewaddress node nil)
                                 (bl.wallet::rpc-getnewaddress
                                  node '("" "bech32m")))))
                (is (null (intersection issued fresh :test #'string=)))))
            ;; Unload; mine 3 more to the wallet address while unloaded;
            ;; reload catches up from the stored locator.
            (bl.wallet::rpc-unloadwallet node '("w"))
            (%wc-mine node 3 addr)                            ; tip 106
            (bl.wallet::rpc-loadwallet node '("w"))
            (let ((wallet3 (%wc-wallet node "w")))
              (is (= 5 (hash-table-count
                        (bl.wallet::wallet-map-wallet wallet3))))
              (is (= 106 (bl.wallet::wallet-last-block-height wallet3)))
              ;; The pre-crash coinbase is still tracked and confirmed.
              (let ((wtx (bl.wallet::wallet-get-wallet-tx wallet3 cb-txid)))
                (is (eq :confirmed (bl.wallet::wallet-tx-state wtx)))
                (is (= 1 (bl.wallet::wallet-tx-block-height wtx))))
              ;; And the catch-up blocks' coinbases are listed too:
              ;; cb@1 (generate) + tx1 (receive) + 3 immature coinbases.
              (let ((entries (bl.wallet::rpc-listtransactions node '("*" 20))))
                (is (= 5 (length entries)))))))))))

;;;; ============================================================
;;;; G7-38: fast wallet rescan via the BIP158 filter index
;;;; ============================================================

(defun %wc-build-filter-index (node)
  "Populate a BASIC block-filter index over the whole active chain, as the
connect hook does live. Returns the index."
  (let* ((dir (merge-pathnames (format nil "wc-bfi-~D-~D/"
                                       (get-universal-time)
                                       (incf *wallet-chain-counter*))
                               (uiop:temporary-directory)))
         (bfi (bl.store:init-blockfilterindex dir))
         (state (bl::node-chain-state node))
         (store (bl::node-block-store node)))
    (loop for h from 0 to (bl.store:current-height state)
          for entry = (bl.store:get-block-at-height state h)
          when entry
            do (let* ((hash (bl.store:block-index-entry-hash entry))
                      (blk (bl.store:get-block store hash)))
                 (when blk
                   ;; Coinbase-only blocks spend nothing, so an empty
                   ;; spent-utxo set is the correct input here.
                   (bl.store:blockfilterindex-add-block
                    bfi blk hash h '()))))
    (setf (bl::node-blockfilterindex node) bfi)
    bfi))

(defun %wc-total-end-range (wallet)
  "Sum of every spkm's GetEndRange — grows only when scripts are actually
cached, so a test asserting growth cannot be satisfied by a no-op top-up."
  (let ((total 0))
    (loop for spkm being the hash-values of (bl.wallet::wallet-spkms wallet)
          do (incf total (bl.wallet::%spkm-end-range spkm)))
    total))

(test g7-38-fast-rescan-matches-slow-rescan
  "G7-38: with the BIP158 index available, non-matching blocks are skipped
without being read. The results must be IDENTICAL to the slow path — same
status, same last-scanned height/hash — and last-scanned must advance THROUGH
skipped blocks (Core wallet.cpp:1907-1908). Skipping that advance would make
rescanblockchain report the last MATCHING block as stop_height and make
wallet-attach-chain persist a stale best block."
  (with-network (:regtest)
    (let* ((node (%wc-fixture "g738"))
           (wname "g738w"))
      (unwind-protect
           (progn
             (bl.wallet::rpc-createwallet node (list wname))
             (let ((wallet (%wc-wallet node wname)))
               ;; Blocks that have nothing to do with this wallet.
               (%wc-mine node 6 (%wc-optrue-address))
               (let ((tip (bl.store:current-height
                           (bl::node-chain-state node))))
                 ;; SLOW path first: no filter index on the node.
                 (setf (bl::node-blockfilterindex node) nil)
                 (multiple-value-bind (s-status s-height s-hash s-skipped)
                     (bl.wallet::scan-for-wallet-transactions
                      node wallet
                      (bl.store:block-index-entry-hash
                       (bl.store:get-block-at-height
                        (bl::node-chain-state node) 0))
                      0)
                   (is (eq :success s-status))
                   (is (= tip s-height) "slow path must reach the tip")
                   (is (= 0 s-skipped) "no index => nothing skipped")
                   ;; FAST path: same scan, filters available.
                   (%wc-build-filter-index node)
                   (multiple-value-bind (f-status f-height f-hash f-skipped)
                       (bl.wallet::scan-for-wallet-transactions
                        node wallet
                        (bl.store:block-index-entry-hash
                         (bl.store:get-block-at-height
                          (bl::node-chain-state node) 0))
                        0)
                     (is (plusp f-skipped)
                         "the fast path must actually skip blocks, else this test is vacuous")
                     (is (eq s-status f-status) "status must be identical")
                     (is (= s-height f-height)
                         "last-scanned height must be identical — skipped blocks still advance it")
                     (is (equalp s-hash f-hash)
                         "last-scanned hash must be identical"))))))
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl::node-wallet-manager node)))))))

(test g7-38-missing-filter-falls-back-per-block
  "G7-38: a block with NO stored filter must be inspected, not skipped (Core
blockFilterMatchesAny -> nullopt, node/interfaces.cpp:583-584). The fallback is
PER BLOCK; there is deliberately no whole-scan guard on the index sync height,
because our index can contain holes below its best marker."
  (with-network (:regtest)
    (let* ((node (%wc-fixture "g738b"))
           (wname "g738bw"))
      (unwind-protect
           (progn
             (bl.wallet::rpc-createwallet node (list wname))
             (let ((wallet (%wc-wallet node wname)))
               (%wc-mine node 3 (%wc-optrue-address))
               (let ((bfi (%wc-build-filter-index node))
                     (state (bl::node-chain-state node)))
                 ;; A height that IS indexed => a real verdict.
                 (let ((h1 (bl.store:block-index-entry-hash
                            (bl.store:get-block-at-height state 1))))
                   (is (member (bl.wallet::%rescan-filter-matches-block
                                bfi (bl.wallet::%make-wallet-rescan-filter wallet) h1)
                               '(:match :no-match))))
                 ;; A hash with no stored filter => :unknown, so the caller reads it.
                 (is (eq :unknown
                         (bl.wallet::%rescan-filter-matches-block
                          bfi (bl.wallet::%make-wallet-rescan-filter wallet)
                          (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 99)))))))
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl::node-wallet-manager node)))))))

(test g7-38-filter-set-is-the-ismine-set-and-grows-with-topup
  "G7-38: the query set must be exactly the wallet's IsMine script set, and
UpdateIfNeeded must fold in scripts created by a mid-rescan TopUp — polling
GetEndRange = max-cached-index + 1 (Core scriptpubkeyman.cpp:1518-1521), NOT
range-end and NOT next-index."
  (with-network (:regtest)
    (let* ((node (%wc-fixture "g738c" :keypool 3))
           (wname "g738cw"))
      (unwind-protect
           (progn
             (bl.wallet::rpc-createwallet node (list wname))
             (let* ((wallet (%wc-wallet node wname))
                    (rf (bl.wallet::%make-wallet-rescan-filter wallet))
                    (initial (length (bl.wallet::rescan-filter-scripts rf))))
               (is (plusp initial) "a funded-capable wallet has scripts")
               ;; Every script in the set must be IsMine, and every IsMine
               ;; script must be in the set.
               (let ((ismine-count 0))
                 (loop for spkm being the hash-values
                         of (bl.wallet::wallet-spkms wallet)
                       do (incf ismine-count
                                (hash-table-count
                                 (bl.wallet::desc-spkm-script-map spkm))))
                 (is (= ismine-count initial)
                     "filter set size must equal the IsMine script count"))
               ;; Force real expansion: hand out enough addresses that the
               ;; keypool tops up and max-cached-index grows. A top-up that
               ;; does not grow max-cached-index would make this vacuous.
               (let ((before (%wc-total-end-range wallet)))
                 (dotimes (i 8) (bl.wallet::rpc-getnewaddress node '()))
                 (is (> (%wc-total-end-range wallet) before)
                     "precondition: handing out addresses must grow max-cached-index"))
               (bl.wallet::%rescan-filter-update-if-needed wallet rf)
               (is (> (length (bl.wallet::rescan-filter-scripts rf)) initial)
                   "UpdateIfNeeded must fold in the newly cached scripts")))
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl::node-wallet-manager node)))))))
