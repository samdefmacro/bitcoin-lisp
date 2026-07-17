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
    (bitcoin-lisp.storage:store-block
     (bitcoin-lisp::node-block-store node)
     (bitcoin-lisp.storage:make-genesis-block :regtest))
    (setf (bitcoin-lisp::node-wallet-manager node)
          (bitcoin-lisp.rpc::make-wallet-manager
           :data-directory wallet-dir :network :regtest :keypool-size keypool))
    node))

(defmacro %with-wallet-chain-node ((node suffix &key (keypool 5)) &body body)
  "Run BODY under regtest bindings with NODE bound to a %wc-fixture and
bitcoin-lisp::*node* bound so the wallet chain hooks fire."
  `(%with-regtest
    (let* ((,node (%wc-fixture ,suffix :keypool ,keypool))
           (bitcoin-lisp::*node* ,node))
      (unwind-protect (progn ,@body)
        (ignore-errors
         (bitcoin-lisp.rpc:close-wallet-manager
          (bitcoin-lisp::node-wallet-manager ,node)))))))

(defun %wc-wallet (node name)
  (gethash name (bitcoin-lisp.rpc::wallet-manager-wallets
                 (bitcoin-lisp::node-wallet-manager node))))

(defun %wc-optrue-address ()
  "P2SH(OP_TRUE) address for regtest — the throwaway coinbase target."
  (bitcoin-lisp.crypto:encode-p2sh-address
   (bitcoin-lisp.crypto:hash160 +optrue-redeem+) :regtest))

(defun %wc-mine (node n address)
  "Mine N regtest blocks to ADDRESS; returns the block hash hex list."
  (bitcoin-lisp.rpc::rpc-generatetoaddress node (list n address)))

(defun %wc-tip-hex (node)
  (bitcoin-lisp.rpc::hash-to-hex
   (bitcoin-lisp.storage:best-block-hash (bitcoin-lisp::node-chain-state node))))

(defun %wc-coinbase-txid (node block-hash-hex)
  "Txid of the coinbase of the block named by BLOCK-HASH-HEX."
  (let* ((store (bitcoin-lisp::node-block-store node))
         (block (bitcoin-lisp.storage:get-block
                 store (bitcoin-lisp.rpc::parse-hex-hash block-hash-hex))))
    (bitcoin-lisp.serialization:transaction-hash
     (first (bitcoin-lisp.serialization:bitcoin-block-transactions block)))))

(defun %wc-spend-tx (prev-txid prev-vout value spk &key (sequence #xffffffff))
  "A tx spending a P2SH(OP_TRUE) prevout, paying VALUE satoshis to SPK
(input value minus VALUE is the fee)."
  (bitcoin-lisp.serialization:make-transaction
   :version 2
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash prev-txid :index prev-vout)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence sequence))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value value :script-pubkey spk))
   :lock-time 0))

(defun %wc-send (node tx)
  "sendrawtransaction TX; returns its txid."
  (bitcoin-lisp.rpc::rpc-sendrawtransaction
   node (list (bitcoin-lisp.crypto:bytes-to-hex
               (bitcoin-lisp.serialization:transaction-wire-bytes tx))))
  (bitcoin-lisp.serialization:transaction-hash tx))

(defun %wc-gettx (node txid)
  (bitcoin-lisp.rpc::rpc-gettransaction
   node (list (bitcoin-lisp.rpc::hash-to-hex txid))))

(defun %wc-state-snapshot (wallet)
  "Comparable snapshot of the wallet's tracked tx states: txid-hex ->
(state height index abandoned order-pos time-smart)."
  (let ((snap '()))
    (maphash (lambda (txid wtx)
               (push (list (bitcoin-lisp.rpc::hash-to-hex txid)
                           (bitcoin-lisp.rpc::wallet-tx-state wtx)
                           (bitcoin-lisp.rpc::wallet-tx-block-height wtx)
                           (bitcoin-lisp.rpc::wallet-tx-block-index wtx)
                           (bitcoin-lisp.rpc::wallet-tx-abandoned wtx)
                           (bitcoin-lisp.rpc::wallet-tx-order-pos wtx)
                           (bitcoin-lisp.rpc::wallet-tx-time-smart wtx))
                     snap))
             (bitcoin-lisp.rpc::wallet-map-wallet wallet))
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
         (txid (bitcoin-lisp.serialization:transaction-hash tx))
         (bhash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (wtx (bitcoin-lisp.rpc::make-wallet-tx :tx tx :txid txid)))
    ;; Confirmed state: hash + index serialized, height NOT (reload -> -1).
    (bitcoin-lisp.rpc::%wtx-apply-state wtx :confirmed bhash 42 2)
    (setf (bitcoin-lisp.rpc::wallet-tx-time-received wtx) 111
          (bitcoin-lisp.rpc::wallet-tx-time-smart wtx) 222
          (bitcoin-lisp.rpc::wallet-tx-order-pos wtx) 5
          (bitcoin-lisp.rpc::wallet-tx-map-value wtx) '(("comment" . "hi")))
    (let ((bytes (bitcoin-lisp.rpc::wallet-tx-record-value wtx)))
      ;; Layout: tx wire bytes, then the state hash.
      (let ((wire (bitcoin-lisp.serialization:transaction-wire-bytes tx)))
        (is (equalp wire (subseq bytes 0 (length wire))))
        (is (equalp bhash (subseq bytes (length wire) (+ (length wire) 32)))))
      (multiple-value-bind (loaded warning)
          (bitcoin-lisp.rpc::parse-wallet-tx-record bytes)
        (is (null warning))
        (is (equalp txid (bitcoin-lisp.rpc::wallet-tx-txid loaded)))
        (is (eq :confirmed (bitcoin-lisp.rpc::wallet-tx-state loaded)))
        (is (equalp bhash (bitcoin-lisp.rpc::wallet-tx-block-hash loaded)))
        (is (= -1 (bitcoin-lisp.rpc::wallet-tx-block-height loaded)))
        (is (= 2 (bitcoin-lisp.rpc::wallet-tx-block-index loaded)))
        (is (= 111 (bitcoin-lisp.rpc::wallet-tx-time-received loaded)))
        (is (= 222 (bitcoin-lisp.rpc::wallet-tx-time-smart loaded)))
        (is (= 5 (bitcoin-lisp.rpc::wallet-tx-order-pos loaded)))
        ;; Record-only map fields are stripped back out on load.
        (is (equal '(("comment" . "hi"))
                   (bitcoin-lisp.rpc::wallet-tx-map-value loaded)))))
    ;; Block-conflicted: hash + index -1.
    (bitcoin-lisp.rpc::%wtx-apply-state wtx :block-conflicted bhash 42)
    (let ((loaded (bitcoin-lisp.rpc::parse-wallet-tx-record
                   (bitcoin-lisp.rpc::wallet-tx-record-value wtx))))
      (is (eq :block-conflicted (bitcoin-lisp.rpc::wallet-tx-state loaded)))
      (is (equalp bhash (bitcoin-lisp.rpc::wallet-tx-block-hash loaded))))
    ;; Inactive: ZERO/0. Abandoned: ONE/-1. InMempool serializes as
    ;; inactive — Core relies on exactly that (TxStateSerialized*).
    (bitcoin-lisp.rpc::%wtx-apply-state wtx :inactive)
    (is (eq :inactive (bitcoin-lisp.rpc::wallet-tx-state
                       (bitcoin-lisp.rpc::parse-wallet-tx-record
                        (bitcoin-lisp.rpc::wallet-tx-record-value wtx)))))
    (bitcoin-lisp.rpc::%wtx-apply-state wtx :inactive nil -1 -1 t)
    (let ((loaded (bitcoin-lisp.rpc::parse-wallet-tx-record
                   (bitcoin-lisp.rpc::wallet-tx-record-value wtx))))
      (is (eq :inactive (bitcoin-lisp.rpc::wallet-tx-state loaded)))
      (is (eq t (bitcoin-lisp.rpc::wallet-tx-abandoned loaded))))
    (bitcoin-lisp.rpc::%wtx-apply-state wtx :in-mempool)
    (let ((loaded (bitcoin-lisp.rpc::parse-wallet-tx-record
                   (bitcoin-lisp.rpc::wallet-tx-record-value wtx))))
      (is (eq :inactive (bitcoin-lisp.rpc::wallet-tx-state loaded)))
      (is (null (bitcoin-lisp.rpc::wallet-tx-abandoned loaded))))))

;;; --- Coinbase tracking + maturity ---

(test wallet-coinbase-tracking-and-maturity
  "Mining to a wallet address tracks the coinbase through the connect hook;
categories follow Core's maturity rules (immature until depth 101, the
COINBASE_MATURITY+1 rule)."
  (%with-wallet-chain-node (node "maturity")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
             (hashes (%wc-mine node 1 addr))
             (cb-txid (%wc-coinbase-txid node (first hashes)))
             (wallet (%wc-wallet node "w")))
        ;; Tracked via the hook, confirmed at height 1.
        (is (= 1 (hash-table-count (bitcoin-lisp.rpc::wallet-map-wallet wallet))))
        (is (= 1 (%aval "txcount" (bitcoin-lisp.rpc::rpc-getwalletinfo node nil))))
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
        (let ((entries (bitcoin-lisp.rpc::rpc-listtransactions node nil)))
          (is (= 1 (length entries)))
          (is (string= "generate" (%aval "category" (first entries))))
          (is (string= addr (%aval "address" (first entries)))))
        ;; lastprocessedblock tracks the tip.
        (let ((lpb (%aval "lastprocessedblock"
                          (bitcoin-lisp.rpc::rpc-getwalletinfo node nil))))
          (is (= 101 (%aval "height" lpb))))))))

;;; --- Mempool receive -> confirm -> listsinceblock -> rescan equality ---

(test wallet-receive-confirm-rescan
  "A mempool payment reaches the wallet through the mempool-add hook,
confirms through the connect hook, listsinceblock windows are Core-shaped,
and a from-genesis rescan (rescanblockchain AND a fresh importdescriptors
wallet) reproduces exactly the live-tracked state."
  (%with-wallet-chain-node (node "receive")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((wallet (%wc-wallet node "w"))
             (addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
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
          (is (eq :in-mempool (bitcoin-lisp.rpc::wallet-tx-state
                               (bitcoin-lisp.rpc::wallet-get-wallet-tx
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
            (let ((since (bitcoin-lisp.rpc::rpc-listsinceblock node (list h101))))
              (is (= 1 (length (%aval "transactions" since))))
              (is (string= (%wc-tip-hex node) (%aval "lastblock" since))))
            (let ((since (bitcoin-lisp.rpc::rpc-listsinceblock
                          node (list (%wc-tip-hex node)))))
              (is (zerop (length (%aval "transactions" since)))))
            (let ((since (bitcoin-lisp.rpc::rpc-listsinceblock
                          node (list nil 2))))
              ;; No filter block: everything listed; lastblock = height 101.
              (is (plusp (length (%aval "transactions" since))))
              (is (string= h101 (%aval "lastblock" since))))
            ;; Unknown blockhash -> Core's -5.
            (is (= bitcoin-lisp.rpc::+rpc-invalid-address-or-key+
                   (%rpc-error-code
                    (lambda ()
                      (bitcoin-lisp.rpc::rpc-listsinceblock
                       node (list (make-string 64 :initial-element #\7))))))))
          ;; abortrescan with no scan running: JSON false; not scanning.
          (is (eq 'yason:false (bitcoin-lisp.rpc::rpc-abortrescan node nil)))
          (is (eq 'yason:false
                  (%aval "scanning"
                         (bitcoin-lisp.rpc::rpc-getwalletinfo node nil))))
          ;; rescanblockchain from genesis must reproduce the live state.
          (let ((before (%wc-state-snapshot wallet))
                (result (bitcoin-lisp.rpc::rpc-rescanblockchain node '(0))))
            (is (= 0 (%aval "start_height" result)))
            (is (= 102 (%aval "stop_height" result)))
            (is (equalp before (%wc-state-snapshot wallet))))
          ;; A second wallet importing the same descriptor with an old
          ;; timestamp rescans to the identical tracked state.
          (let* ((descs (%aval "descriptors"
                               (bitcoin-lisp.rpc::rpc-listdescriptors node '(t))))
                 (ext-wpkh (find-if (lambda (d)
                                      (let ((s (%aval "desc" d)))
                                        (and (eql 0 (search "wpkh(" s))
                                             (search "/0/*" s))))
                                    descs)))
            (is (not (null ext-wpkh)))
            (bitcoin-lisp.rpc::rpc-createwallet node '("w2" nil t)) ; blank
            (let* ((bitcoin-lisp.rpc::*rpc-wallet-name* "w2")
                   (results (bitcoin-lisp.rpc::rpc-importdescriptors
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
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
             (b1 (first (%wc-mine node 1 addr)))
             (cb-txid (%wc-coinbase-txid node b1))
             (wallet (%wc-wallet node "w")))
        (%wc-mine node 1 (%wc-optrue-address))     ; tip 2
        (is (= 2 (%aval "confirmations" (%wc-gettx node cb-txid))))
        ;; Reorg the funding block away.
        (bitcoin-lisp.rpc::rpc-invalidateblock node (list b1))
        (let ((wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet cb-txid)))
          (is (eq :inactive (bitcoin-lisp.rpc::wallet-tx-state wtx)))
          (is (eq t (bitcoin-lisp.rpc::wallet-tx-abandoned wtx))))
        (let ((gettx (%wc-gettx node cb-txid)))
          (is (= 0 (%aval "confirmations" gettx)))
          (is (string= "orphan" (%wc-details-category gettx)))
          (is (eq t (%aval "abandoned" (first (%aval "details" gettx))))))
        (is (= 0 (bitcoin-lisp.rpc::wallet-last-block-height wallet)))
        ;; Reconnect: confirmed again at height 1, abandoned cleared.
        (bitcoin-lisp.rpc::rpc-reconsiderblock node (list b1))
        (let ((wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet cb-txid)))
          (is (eq :confirmed (bitcoin-lisp.rpc::wallet-tx-state wtx)))
          (is (= 1 (bitcoin-lisp.rpc::wallet-tx-block-height wtx))))
        (is (= 2 (%aval "confirmations" (%wc-gettx node cb-txid))))
        (is (= 2 (bitcoin-lisp.rpc::wallet-last-block-height wallet)))))))

;;; --- Reorg across the funding tx + double-spend conflicts ---

(test wallet-funding-reorg-and-conflicts
  "Reorging out the block that confirmed a wallet-funding tx returns it to
the mempool (in-mempool state); a confirmed double-spend marks it
block-conflicted (negative confirmations); disconnecting the conflict block
reverts it to inactive with the double-spend as a mempool conflict; re-mining
the double-spend re-conflicts it and clears the mempool conflict."
  (%with-wallet-chain-node (node "conflicts")
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((wallet (%wc-wallet node "w"))
             (addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
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
          (bitcoin-lisp.rpc::rpc-invalidateblock node (list fblock))
          ;; Disconnected -> re-added to the mempool -> wallet sees mempool
          ;; state through the re-add hook.
          (let ((wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid1)))
            (is (eq :in-mempool (bitcoin-lisp.rpc::wallet-tx-state wtx))))
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
               (txid2x (bitcoin-lisp.serialization:transaction-hash tx2x)))
          (is (= 0 (%aval "confirmations" (%wc-gettx node txid2))))
          ;; Mine a block containing ONLY the double-spend.
          (let ((conflict-block
                  (%aval "hash"
                         (bitcoin-lisp.rpc::rpc-generateblock
                          node (list (%wc-optrue-address)
                                     (list (bitcoin-lisp.crypto:bytes-to-hex
                                            (bitcoin-lisp.serialization:transaction-wire-bytes tx2x))))))))
            ;; tx2: removed from the mempool as :conflict, then marked
            ;; block-conflicted by the connect hook's mapTxSpends scan.
            (let ((wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid2)))
              (is (eq :block-conflicted (bitcoin-lisp.rpc::wallet-tx-state wtx))))
            (let ((gettx (%wc-gettx node txid2)))
              (is (= -1 (%aval "confirmations" gettx)))
              (is (eq 'yason:false (%aval "trusted" gettx)))
              (is (zerop (length (%aval "mempoolconflicts" gettx)))))
            ;; Disconnect the conflict block: tx2 reverts to inactive, and
            ;; the re-added double-spend becomes a mempool conflict of tx2.
            (bitcoin-lisp.rpc::rpc-invalidateblock node (list conflict-block))
            (let ((wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet txid2)))
              (is (eq :inactive (bitcoin-lisp.rpc::wallet-tx-state wtx))))
            (let* ((gettx (%wc-gettx node txid2))
                   (mconf (%aval "mempoolconflicts" gettx)))
              (is (= 0 (%aval "confirmations" gettx)))
              (is (equal (list (bitcoin-lisp.rpc::hash-to-hex txid2x)) mconf)))
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
    (let ((bitcoin-lisp.rpc::*rpc-wallet-name* nil)
          (issued '()))
      (bitcoin-lisp.rpc::rpc-createwallet node '("w"))
      (let* ((addr (bitcoin-lisp.rpc::rpc-getnewaddress node nil))
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
          (push (bitcoin-lisp.rpc::rpc-getnewaddress node nil) issued)
          (push (bitcoin-lisp.rpc::rpc-getnewaddress node '("" "bech32m")) issued)
          (let* ((wallet (%wc-wallet node "w"))
                 (before (%wc-state-snapshot wallet)))
            (is (= 2 (length before)))          ; coinbase + tx1
            ;; Crash: close the DB without any graceful-unload writes.
            (%crash-close-wallet node "w")
            (bitcoin-lisp.rpc::rpc-loadwallet node '("w"))
            (let ((wallet2 (%wc-wallet node "w")))
              (is (not (eq wallet wallet2)))
              (is (equalp before (%wc-state-snapshot wallet2)))
              (is (= 103 (bitcoin-lisp.rpc::wallet-last-block-height wallet2)))
              ;; Confirmed states resolved against the chain on load.
              (let ((wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet2 txid1)))
                (is (eq :confirmed (bitcoin-lisp.rpc::wallet-tx-state wtx)))
                (is (= 103 (bitcoin-lisp.rpc::wallet-tx-block-height wtx))))
              (is (= 2 (%aval "txcount"
                              (bitcoin-lisp.rpc::rpc-getwalletinfo node nil))))
              ;; Keypool: no previously issued address is reissued.
              (let ((fresh (list (bitcoin-lisp.rpc::rpc-getnewaddress node nil)
                                 (bitcoin-lisp.rpc::rpc-getnewaddress
                                  node '("" "bech32m")))))
                (is (null (intersection issued fresh :test #'string=)))))
            ;; Unload; mine 3 more to the wallet address while unloaded;
            ;; reload catches up from the stored locator.
            (bitcoin-lisp.rpc::rpc-unloadwallet node '("w"))
            (%wc-mine node 3 addr)                            ; tip 106
            (bitcoin-lisp.rpc::rpc-loadwallet node '("w"))
            (let ((wallet3 (%wc-wallet node "w")))
              (is (= 5 (hash-table-count
                        (bitcoin-lisp.rpc::wallet-map-wallet wallet3))))
              (is (= 106 (bitcoin-lisp.rpc::wallet-last-block-height wallet3)))
              ;; The pre-crash coinbase is still tracked and confirmed.
              (let ((wtx (bitcoin-lisp.rpc::wallet-get-wallet-tx wallet3 cb-txid)))
                (is (eq :confirmed (bitcoin-lisp.rpc::wallet-tx-state wtx)))
                (is (= 1 (bitcoin-lisp.rpc::wallet-tx-block-height wtx))))
              ;; And the catch-up blocks' coinbases are listed too:
              ;; cb@1 (generate) + tx1 (receive) + 3 immature coinbases.
              (let ((entries (bitcoin-lisp.rpc::rpc-listtransactions node '("*" 20))))
                (is (= 5 (length entries)))))))))))
