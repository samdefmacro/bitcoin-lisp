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
;;; Reuses regtest-node-fixture/%with-regtest (mining-tests.lisp) and the
;;; P2SH(OP_TRUE) spend helpers (package-tests.lisp).

(def-suite wallet-chain-tests
  :description "Wallet P2: chain tracking, conflicts, rescan, tx RPCs"
  :in :bitcoin-lisp-tests)

(in-suite wallet-chain-tests)

;;; --- Fixture ---

(defun %wc-wallet (node name)
  (loaded-wallet (bl:node-wallet-manager node) name))

(defun %wc-optrue-address ()
  "P2SH(OP_TRUE) address for regtest — the throwaway coinbase target."
  (bl.crypto:encode-p2sh-address
   (bl.crypto:hash160 +optrue-redeem+) :regtest))

(defun %wc-newaddress (node &optional params)
  "getnewaddress through the exported dispatcher -- eleven call sites in this
file reached the handler symbol directly."
  (bl.rpc:dispatch-rpc-method node "getnewaddress" params))

(defun %wc-mine (node n address)
  "Mine N regtest blocks to ADDRESS; returns the block hash hex list."
  (bl.rpc::rpc-generatetoaddress node (list n address)))

(defun %wc-tip-hex (node)
  (bl.rpc:hash-to-hex
   (bl.store:best-block-hash (bl:node-chain-state node))))

(defun %wc-coinbase-txid (node block-hash-hex)
  "Txid of the coinbase of the block named by BLOCK-HASH-HEX."
  (let* ((store (bl:node-block-store node))
         (block (bl.store:get-block
                 store (bl.rpc:parse-hex-hash block-hash-hex))))
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
                    :script-sig (p2sh-optrue-scriptsig)
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

(defun %wc-since (node &rest params)
  "listsinceblock with PARAMS. One reach for the whole file."
  (apply #'bl.wallet::rpc-listsinceblock node (list params)))

(defun %wc-gettx (node txid)
  "gettransaction for TXID, given as internal bytes or as the hex a client
sends -- the malformed-argument rows pass the hex straight through."
  (bl.wallet::rpc-gettransaction
   node (list (if (stringp txid) txid (bl.rpc:hash-to-hex txid)))))

(defun %wc-state-snapshot (wallet)
  "Comparable snapshot of the wallet's tracked tx states: txid-hex ->
(state height index abandoned order-pos time-smart)."
  (let ((snap '()))
    (maphash (lambda (txid wtx)
               (push (list (bl.rpc:hash-to-hex txid)
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
         (tx (%wc-spend-tx prev 0 12345 (p2sh-optrue-script-pubkey)))
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
  (with-wallet-chain-node (node "maturity" :wallet "w")
    (let* ((addr (%wc-newaddress node nil))
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
        (is (= 101 (%aval "height" lpb)))))))

;;; --- Mempool receive -> confirm -> listsinceblock -> rescan equality ---

(test wallet-receive-confirm-rescan
  "A mempool payment reaches the wallet through the mempool-add hook,
confirms through the connect hook, listsinceblock windows are Core-shaped,
and a from-genesis rescan (rescanblockchain AND a fresh importdescriptors
wallet) reproduces exactly the live-tracked state."
  (with-wallet-chain-node (node "receive" :wallet "w")
    (let* ((wallet (%wc-wallet node "w"))
           (addr (%wc-newaddress node nil))
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
          (let ((since (%wc-since node h101)))
            (is (= 1 (length (%aval "transactions" since))))
            (is (string= (%wc-tip-hex node) (%aval "lastblock" since))))
          (let ((since (%wc-since node (%wc-tip-hex node))))
            (is (zerop (length (%aval "transactions" since)))))
          (let ((since (%wc-since node nil 2)))
            ;; No filter block: everything listed; lastblock = height 101.
            (is (plusp (length (%aval "transactions" since))))
            (is (string= h101 (%aval "lastblock" since))))
          ;; Unknown blockhash -> Core's -5.
          (is (= bl.rpc:+rpc-invalid-address-or-key+
                 (rpc-error-code-of
                  (lambda ()
                    (%wc-since node (make-string 64 :initial-element #\7))))))
          ;; A MALFORMED blockhash is ParseHashV's -8, and Core names the
          ;; argument "blockhash" here (wallet/rpc/transactions.cpp:595) --
          ;; this used to run through a helper whose message said "txid"
          ;; whatever it was parsing, in Core's pre-0.21 wording.
          (is (equal (cons -8 "blockhash must be of length 64 (not 2, for '00')")
                     (rpc-error-of
                      (lambda () (%wc-since node "00")))))
          (is (equal (cons -8 (format nil "blockhash must be hexadecimal string (not '~A')"
                                      (make-string 64 :initial-element #\z)))
                     (rpc-error-of
                      (lambda ()
                        (%wc-since node (make-string 64 :initial-element #\z))))))
          ;; gettransaction names the same helper's argument "txid"
          ;; (transactions.cpp:730), the wallet_basic.py:172 sentence.
          (is (equal (cons -8 "txid must be of length 64 (not 2, for '00')")
                     (rpc-error-of (lambda () (%wc-gettx node "00"))))))
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
                          (%wc-snapshot-sans-times (%wc-state-snapshot w2)))))))))))

;;; --- Reorg: disconnected coinbase abandoned, reconnect restores ---

(test wallet-coinbase-reorg-abandon
  "Disconnecting the wallet's coinbase block marks it inactive+abandoned
(orphan category); reconsidering the block reconfirms it."
  (with-wallet-chain-node (node "cbreorg" :wallet "w")
    (let* ((addr (%wc-newaddress node nil))
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
      (is (= 2 (bl.wallet::wallet-last-block-height wallet))))))

(test wallet-disconnect-writes-the-rolled-back-best-block
  "GA11 652d565b. Core's CWallet::blockDisconnected ends in
SetLastBlockProcessed (wallet.cpp:1598), and SetLastBlockProcessed is the
in-memory pair FOLLOWED BY WriteBestBlock (:681-687) -- so EVERY disconnect
syncs the rolled-back locator to the wallet file. The connect side
deliberately does not: it persists only when a wallet tx changed or every 144
blocks (:1550-1552). Ours mirrored the connect side on both, so between a
reorg and the next qualifying connect the on-disk bestblock_nomerkle record
named a block on the ABANDONED branch while memory held the correct
rolled-back one, and a crash in that window loaded a wallet whose locator
pointed the wrong way.

Both blocks are mined to a wallet address, so each connect updates a wallet
tx and forces the locator to disk -- which is what makes the divergence
visible at all. The pre-disconnect row is the control: it proves the file was
following the tip before the reorg, so a fix that simply stopped writing on
connect would not pass."
  (with-wallet-chain-node (node "bestblock" :wallet "w")
    (let* ((wallet (%wc-wallet node "w"))
           (addr (%wc-newaddress node nil))
           (b1 (first (%wc-mine node 1 addr)))
           (b2 (first (%wc-mine node 1 addr))))
      (is (equal b2 (bl.rpc:hash-to-hex (first (wallet-best-block-locator wallet)))))
      (bl.rpc:dispatch-rpc-method node "invalidateblock" (list b2))
      ;; Memory rolled back to the parent, as it always did.
      (is (= 1 (bl.wallet::wallet-last-block-height wallet)))
      (is (equal b1 (bl.rpc:hash-to-hex (bl.wallet::wallet-last-block-hash wallet))))
      ;; And so did the file. This is the assertion the fix adds.
      (let ((locator (wallet-best-block-locator wallet)))
        (is (equal b1 (bl.rpc:hash-to-hex (first locator))))
        ;; Core's WriteBestBlock stores chain().findBlock(...).locator(loc),
        ;; the exponential step-back form terminating at genesis -- not the
        ;; single-hash fallback, which would cost a full rescan on load.
        (is (= 2 (length locator)))))))

(defun %wc-mutate-proof (proof-hex offset)
  "PROOF-HEX with the header byte at OFFSET (0-based, within the 80-byte
header) INVERTED. The merkle root sits at 36..67 and nTime at 68..71, which is
how the functional test wallet_importprunedfunds.py builds its two bad proofs:
a mutated root breaks ExtractMatches, a mutated nTime changes the block HASH
while leaving the proof internally consistent.

The byte is complemented rather than set to a chosen value because the proof
this fixture produces is not deterministic -- the wallet's keys are fresh per
run, so the coinbase txid, and with it the merkle root, is random. Assigning a
literal (#xEF at 36, #x00 at 68) left the proof UNCHANGED whenever the random
byte already held it, and an unchanged proof imports, which is a 1-in-256 red
per offset. XOR #xFF cannot be a no-op."
  (let ((bytes (bl.crypto:hex-to-bytes proof-hex)))
    (setf (aref bytes offset) (logxor (aref bytes offset) #xFF))
    (bl.crypto:bytes-to-hex bytes)))

(test pruned-funds-import-and-remove
  "GA11 71d5aa9f. importprunedfunds and removeprunedfunds were not registered
at all -- a pruned node, a configuration we support, could not add a known
transaction to a wallet whose blocks are no longer on disk, and no wallet
could delete a transaction record. Core implements the pair in
wallet/rpc/backup.cpp:39-127 over CWallet::RemoveTxs (wallet.cpp:2419-2470),
and test/functional/wallet_importprunedfunds.py is the oracle this follows.

The round trip is the shape of the feature: remove the record, and the
transaction is gone from listtransactions, from the balance and from the
wallet FILE (asserted by unloading and reloading); import it back with its
gettxoutproof, and it returns confirmed at the height and index the proof
gives. Every error Core raises is checked with it, because the whole value of
these two is that they refuse a proof that does not hold up."
  (with-wallet-chain-node (node "prunedfunds" :wallet "w")
    (labels ((rpc (wallet method &rest params)
               (with-rpc-wallet (wallet)
                 (bl.rpc:dispatch-rpc-method node method params)))
             (aval (key alist) (cdr (assoc key alist :test #'string=)))
             (import-code (wallet raw proof)
               (rpc-error-code-of
                (lambda () (rpc wallet "importprunedfunds" raw proof))))
             (import-message (wallet raw proof)
               (handler-case (progn (rpc wallet "importprunedfunds" raw proof) "")
                 (bl.rpc:rpc-error (e) (bl.rpc:rpc-error-message e)))))
      (let* ((addr (%wc-newaddress node nil))
             (b1 (first (%wc-mine node 1 addr))))
        (%wc-mine node 100 (%wc-optrue-address))   ; b1's coinbase matures
        (let* ((cb (bl.rpc:hash-to-hex (%wc-coinbase-txid node b1)))
               (rawtx (aval "hex" (rpc "w" "gettransaction" cb)))
               (proof (rpc nil "gettxoutproof" (list cb) b1))
               (balance (btc-amount (rpc "w" "getbalance"))))
          (is (plusp balance))
          (is (= 101 (aval "confirmations" (rpc "w" "gettransaction" cb))))
          ;; --- removeprunedfunds ---
          (is (null (rpc "w" "removeprunedfunds" cb)))
          (is (zerop (btc-amount (rpc "w" "getbalance"))))
          (is (zerop (length (remove-if-not
                              (lambda (tx) (equal cb (aval "txid" tx)))
                              (rpc "w" "listtransactions")))))
          (is (= -5 (rpc-error-code-of
                     (lambda () (rpc "w" "gettransaction" cb)))))
          ;; The record left the FILE, not just memory.
          (rpc nil "unloadwallet" "w")
          (rpc nil "loadwallet" "w")
          (is (= -5 (rpc-error-code-of
                     (lambda () (rpc "w" "gettransaction" cb)))))
          ;; Removing what the wallet does not hold is Core's -4, and says so.
          (is (= -4 (rpc-error-code-of
                     (lambda () (rpc "w" "removeprunedfunds" cb)))))
          (is (string= (format nil "Transaction ~A does not belong to this wallet" cb)
                       (handler-case
                           (progn (rpc "w" "removeprunedfunds" cb) "")
                         (bl.rpc:rpc-error (e) (bl.rpc:rpc-error-message e)))))
          ;; A malformed txid is Core's ParseHashV(request.params[0], "txid")
          ;; (wallet/rpc/backup.cpp:115, rpc/util.cpp:117-125): -8 in its two
          ;; sentences, not a wallet-local parser's wording.
          (is (equal (cons -8 "txid must be of length 64 (not 2, for '00')")
                     (rpc-error-of (lambda () (rpc "w" "removeprunedfunds" "00")))))
          (is (equal (cons -8 (format nil "txid must be hexadecimal string (not '~A')"
                                      (make-string 64 :initial-element #\z)))
                     (rpc-error-of
                      (lambda ()
                        (rpc "w" "removeprunedfunds"
                             (make-string 64 :initial-element #\z))))))
          ;; --- importprunedfunds ---
          (is (null (rpc "w" "importprunedfunds" rawtx proof)))
          (let ((gettx (rpc "w" "gettransaction" cb)))
            (is (= 101 (aval "confirmations" gettx)))
            (is (equal b1 (aval "blockhash" gettx)))
            (is (= 0 (aval "blockindex" gettx))))
          (is (= balance (btc-amount (rpc "w" "getbalance"))))
          ;; And the re-import reached the file too.
          (rpc nil "unloadwallet" "w")
          (rpc nil "loadwallet" "w")
          (is (= 101 (aval "confirmations" (rpc "w" "gettransaction" cb))))
          ;; --- the errors, in Core's own words ---
          ;; The clean proof imported above is the control for the two mutated
          ;; ones: the mutation is the only reason they are refused.
          ;; -22, the message the spending paths use.
          (is (= -22 (import-code "w" "696e76616c6964207478" proof)))
          (is (string= "TX decode failed. Make sure the tx has at least one input."
                       (import-message "w" "696e76616c6964207478" proof)))
          ;; A proof whose header no longer commits to the tree it carries.
          (is (string= "Something wrong with merkleblock"
                       (import-message "w" rawtx (%wc-mutate-proof proof 36))))
          ;; A header nothing in the block index knows: nTime moved, so the
          ;; proof is still internally consistent but names another block.
          (is (string= "Block not found in chain"
                       (import-message "w" rawtx (%wc-mutate-proof proof 68))))
          ;; A proof for a block that IS ours, of a transaction that is not in it.
          (let* ((b2 (first (%wc-mine node 1 (%wc-optrue-address))))
                 (other-proof (rpc nil "gettxoutproof"
                                   (list (bl.rpc:hash-to-hex
                                          (%wc-coinbase-txid node b2)))
                                   b2)))
            (is (string= "Transaction given doesn't exist in proof"
                         (import-message "w" rawtx other-proof))))
          ;; A wallet none of whose addresses the transaction pays.
          (rpc nil "createwallet" "other")
          (is (= -5 (import-code "other" rawtx proof)))
          (is (string= "No addresses in wallet correspond to included transaction"
                       (import-message "other" rawtx proof))))))))

(test pruned-funds-removal-keeps-a-conflicting-spend
  "wallet_importprunedfunds.py:133-154. Core's RemoveTxs unwinds mapTxSpends by
erasing only the removed transaction's OWN entry for each outpoint
(wallet.cpp:2456-2463), so an outpoint some surviving conflicting transaction
also spends stays spent. Removing a REPLACED transaction must not hand its
input back to coin selection while the replacement is still in flight.

Removing the replacement too is the positive control: with no spender left the
same output is offered again, so the first assertion cannot be passing because
the wallet simply lost track of the coin."
  (with-wallet-chain-node (node "prunedconflict" :wallet "w")
    (labels ((rpc (wallet method &rest params)
               (with-rpc-wallet (wallet)
                 (bl.rpc:dispatch-rpc-method node method params)))
             (aval (key alist) (cdr (assoc key alist :test #'string=)))
             (coinbase-unspent-p (cb)
               (plusp (count-if (lambda (u) (equal cb (aval "txid" u)))
                                (rpc "w" "listunspent" 0)))))
      (let* ((addr (%wc-newaddress node nil))
             (b1 (first (%wc-mine node 1 addr))))
        (%wc-mine node 100 (%wc-optrue-address))
        (let ((cb (bl.rpc:hash-to-hex (%wc-coinbase-txid node b1)))
              (dest (%wc-newaddress node nil)))
          (is-true (coinbase-unspent-p cb))
          (let* ((tx1 (rpc "w" "sendtoaddress" dest 1 nil nil nil nil nil nil nil 10))
                 (tx2 (aval "txid" (rpc "w" "bumpfee" tx1))))
            (is-false (equal tx1 tx2))
            (is-false (coinbase-unspent-p cb))
            ;; The replaced transaction goes; the replacement still spends it.
            (rpc "w" "removeprunedfunds" tx1)
            (is-false (coinbase-unspent-p cb))
            ;; With the replacement gone too, the output comes back.
            (rpc "w" "removeprunedfunds" tx2)
            (is-true (coinbase-unspent-p cb))))))))

;;; --- Reorg across the funding tx + double-spend conflicts ---

(test wallet-mempool-catch-up-visits-a-parent-before-its-child
  "Core Chain::requestMempoolTransactions (node/interfaces.cpp:845-852) walks
CTxMemPool::entryAll(), which is GetSortedScoreWithTopology()
(txmempool.cpp:588-598) -- an ordering in which an in-mempool parent always
precedes its children. The wallet's catch-up needs that: a child whose
outputs are all foreign is recognised ONLY through its inputs, so it is
detectable only once the parent that funded it is already in the wallet.

wallet_rescan_unconfirmed.py builds exactly that pool and says why at
:46-49: it confirms the parent, spends it with a change-less sweep, then
INVALIDATES the parent's block, so the parent re-enters the mempool AFTER
its child. Ours folded the mempool in with a plain hash-table walk, so the
child was visited first, found nothing of the wallet's, and was dropped --
wallet_rescan_unconfirmed.py:77 answered -5 Invalid or non-wallet
transaction id while :76 (the parent) passed.

The watched script here is the P2SH(OP_TRUE) the fixture mines to, which is
what lets the child be assembled without the wallet signing anything."
  (with-wallet-chain-node (node "memcatchup" :wallet "w")
    (let* ((watched (%wc-optrue-address))
           (foreign (concatenate '(vector (unsigned-byte 8))
                                 #(#x00 #x14) (make-array 20 :initial-element 3)))
           (fund (first (%wc-mine node 1 watched))))
      (%wc-mine node 100 watched)               ; tip 101, coinbase@1 mature
      (let* ((parent (%wc-spend-tx (%wc-coinbase-txid node fund) 0
                                   (- +wc-subsidy+ 10000)
                                   (%address-script watched :regtest)))
             (parent-txid (%wc-send node parent))
             (pblock (first (%wc-mine node 1 watched)))
             ;; A change-less sweep of the parent's only output: nothing in
             ;; it belongs to the wallet, so only its INPUT names it.
             (child (%wc-spend-tx parent-txid 0 (- +wc-subsidy+ 20000) foreign))
             (child-txid (%wc-send node child)))
        ;; The reorg: the parent comes back to a mempool the child is in.
        (bl.rpc:dispatch-rpc-method node "invalidateblock" (list pblock))
        (is (= 2 (length (bl.rpc:dispatch-rpc-method node "getrawmempool" nil)))
            "the reorg did not leave both transactions in the mempool")
        ;; A wallet that saw none of it live, catching up through an import.
        (with-rpc-wallet (nil)
          (bl.rpc:dispatch-rpc-method node "createwallet" (list "catchup" t)))
        (with-rpc-wallet ("catchup")
          (let ((results (bl.rpc:dispatch-rpc-method
                          node "importdescriptors"
                          (list (list (%ht "desc" (bl.rpc:descriptor-add-checksum
                                                   (format nil "addr(~A)" watched))
                                           "timestamp" 0))))))
            (is (eq t (%aval "success" (first results)))
                "the watch-only import failed, so no catch-up ran"))
          ;; wallet_rescan_unconfirmed.py:76-77, in order.
          (is (= 0 (%aval "confirmations" (%wc-gettx node parent-txid)))
              "the catch-up missed the mempool PARENT")
          (is (= 0 (%aval "confirmations" (%wc-gettx node child-txid)))
              "the catch-up missed the mempool child, so the fold-in ran it
before its parent"))))))

(test wallet-funding-reorg-and-conflicts
  "Reorging out the block that confirmed a wallet-funding tx returns it to
the mempool (in-mempool state); a confirmed double-spend marks it
block-conflicted (negative confirmations); disconnecting the conflict block
reverts it to inactive with the double-spend as a mempool conflict; re-mining
the double-spend re-conflicts it and clears the mempool conflict."
  (with-wallet-chain-node (node "conflicts" :wallet "w")
    (let* ((wallet (%wc-wallet node "w"))
           (addr (%wc-newaddress node nil))
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
                                 (p2sh-optrue-script-pubkey)))
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
            (is (equal (list (bl.rpc:hash-to-hex txid2x)) mconf)))
          ;; Mine the double-spend again (it is back in the mempool):
          ;; blockConnected re-conflicts tx2 AND clears the mempool
          ;; conflict (reason-:block removal runs the erase loop).
          (%wc-mine node 1 (%wc-optrue-address))
          (let ((gettx (%wc-gettx node txid2)))
            (is (= -1 (%aval "confirmations" gettx)))
            (is (zerop (length (%aval "mempoolconflicts" gettx))))))))))

;;; --- Crash + reload persistence, load-time catch-up ---

(test wallet-txstate-persistence-crash-reload
  "Tx state and the keypool survive a crash-simulating close + loadwallet
(records were persisted at hook time), and a wallet unloaded while blocks
were mined catches up from its stored locator on load."
  (with-wallet-chain-node (node "crash")
    (let ((bl.wallet::*rpc-wallet-name* nil)
          (issued '()))
      (bl.wallet::rpc-createwallet node '("w"))
      (let* ((addr (%wc-newaddress node nil))
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
          (push (%wc-newaddress node nil) issued)
          (push (%wc-newaddress node '("" "bech32m")) issued)
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
              (let ((fresh (list (%wc-newaddress node nil)
                                 (%wc-newaddress node '("" "bech32m")))))
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
;;;; GA11 4e92ca22: a tx record that fails to load is Core's NEED_RESCAN
;;;; ============================================================

(defun %wc-damage-tx-record (path action)
  "Damage the single stored tx record of the closed wallet at PATH. :FLIP
XORs #xFF into a middle byte, which is what a torn write or a bad block looks
like on load; :DELETE removes the record outright."
  (let ((db (bl.wallet::wallet-db-open path)))
    (unwind-protect
         (dolist (record (wallet-db-record-list db))
           (when (equal (bl.wallet::wdb-parse-key (car record))
                        bl.wallet::+wdb-key-tx+)
             (return
               (ecase action
                 (:delete (bl.store:leveldb-delete db (car record) :sync t))
                 (:flip
                  (let* ((value (copy-seq (cdr record)))
                         (at (floor (length value) 2)))
                    (setf (aref value at) (logxor #xFF (aref value at)))
                    (bl.store:leveldb-put db (car record) value :sync t)))))))
      (bl.store:leveldb-close db))))

(defun %wc-fund-and-damage (node action)
  "Create wallet w, mine it one mature coinbase, assert the 50 BTC balance,
unload it, and apply ACTION (:flip, :delete or :none) to its tx record. The
wallet is left UNLOADED, so each caller can bring it back its own way."
  (with-rpc-wallet (nil)
    (bl.wallet::rpc-createwallet node '("w"))
    (let* ((address (%wc-newaddress node '("" "bech32")))
           (path (bl.wallet::wallet-path (%wc-wallet node "w"))))
      (%wc-mine node 1 address)
      (%wc-mine node 101 (%wc-optrue-address))
      (is (= 50 (btc-amount (bl.wallet::rpc-getbalance node '()))))
      (bl.wallet::rpc-unloadwallet node '("w"))
      (unless (eq action :none)
        (%wc-damage-tx-record path action))
      path)))

(defun %wc-balance-and-txcount (node)
  (with-rpc-wallet (nil)
    (values (btc-amount (bl.wallet::rpc-getbalance node '()))
            (%aval "txcount" (bl.wallet::rpc-getwalletinfo node nil)))))

(defun %wc-mentions-p (needle lines)
  (find-if (lambda (line) (search needle line)) lines))

(test wallet-corrupt-tx-record-rescans-from-height-zero
  "GA11 4e92ca22. Core's LoadTxRecords turns a tx row that will not
deserialize, or whose hash is not the key it was stored under, into
DBErrors::NEED_RESCAN (walletdb.cpp:1015-1030); CreateWalletFromFile keeps the
wallet, warns, and AttachChain then leaves rescan_height at 0 instead of
consulting the stored locator (wallet.cpp:3140-3142, 3200-3211), so the block
that carried the lost transaction is read again. We only pushed a warning
string: the wallet came up with a balance of 0, a history of nothing, and no
way back except an operator noticing and running rescanblockchain by hand."
  (with-wallet-chain-node (node "corrupt-tx")
    (%wc-fund-and-damage node :flip)
    (multiple-value-bind (wallet warnings)
        (bl.wallet::%load-and-attach-wallet
         node (bl:node-wallet-manager node) "w")
      (declare (ignore wallet))
      (multiple-value-bind (balance txcount) (%wc-balance-and-txcount node)
        ;; The whole finding: the coin is on chain and the descriptors are
        ;; intact, so the rescan rebuilds what the damaged record held.
        (is (= 50.0d0 balance))
        (is (= 1 txcount)))
      (is-true (%wc-mentions-p "hash mismatch" warnings))
      ;; Core's own wording, added alongside ours (wallet.cpp:2383-2386).
      (is-true (%wc-mentions-p "Rescanning wallet." warnings))))
  ;; The control that keeps the assertion honest: a record that is GONE is not
  ;; a record that failed to load. Core does not rescan for that either, so
  ;; this half must still read 0 -- otherwise the test above would pass on any
  ;; wallet whose transaction went missing, for any reason.
  (with-wallet-chain-node (node "deleted-tx")
    (%wc-fund-and-damage node :delete)
    (multiple-value-bind (wallet warnings)
        (bl.wallet::%load-and-attach-wallet
         node (bl:node-wallet-manager node) "w")
      (declare (ignore wallet))
      (multiple-value-bind (balance txcount) (%wc-balance-and-txcount node)
        (is (= 0.0d0 balance))
        (is (= 0 txcount)))
      (is (null warnings)))))

(test wallet-startup-load-reports-the-warnings-it-used-to-drop
  "The startup auto-load discarded the warnings it got back, so on the path
an operator actually takes -- a restart -- the divergence above left no trace
at all. Core joins them into one initWarning (load.cpp:149)."
  (with-wallet-chain-node (node "startup-warn")
    (%wc-fund-and-damage node :flip)
    (let ((lines (capture-log-lines
                  (lambda ()
                    (bl.wallet:load-wallets-on-startup node '("w"))))))
      (is-true (%wc-mentions-p "hash mismatch" lines))
      (is-true (%wc-mentions-p "Rescanning wallet." lines))
      ;; The load still succeeded, and it rescanned.
      (is-true (%wc-mentions-p "Loaded wallet" lines))
      (multiple-value-bind (balance txcount) (%wc-balance-and-txcount node)
        (is (= 50.0d0 balance))
        (is (= 1 txcount)))))
  ;; Control: an undamaged wallet says none of it, so the lines above come
  ;; from the damage and not from every startup load.
  (with-wallet-chain-node (node "startup-clean")
    (%wc-fund-and-damage node :none)
    (let ((lines (capture-log-lines
                  (lambda ()
                    (bl.wallet:load-wallets-on-startup node '("w"))))))
      (is-true (%wc-mentions-p "Loaded wallet" lines))
      (is-false (%wc-mentions-p "Rescanning wallet." lines))
      (multiple-value-bind (balance txcount) (%wc-balance-and-txcount node)
        (is (= 50.0d0 balance))
        (is (= 1 txcount))))))

;;;; ============================================================
;;;; G7-38: fast wallet rescan via the BIP158 filter index
;;;; ============================================================

(defun %wc-build-filter-index (node)
  "Populate a BASIC block-filter index over the whole active chain, as the
connect hook does live. Returns the index."
  (let* ((dir (make-temp-directory "wc-bfi"))
         (bfi (bl.store:init-blockfilterindex dir))
         (state (bl:node-chain-state node))
         (store (bl:node-block-store node)))
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
    (setf (bl:node-blockfilterindex node) bfi)
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
    (let* ((node (make-wallet-chain-node "g738"))
           (wname "g738w"))
      (unwind-protect
           (progn
             (bl.wallet::rpc-createwallet node (list wname))
             (let ((wallet (%wc-wallet node wname)))
               ;; Blocks that have nothing to do with this wallet.
               (%wc-mine node 6 (%wc-optrue-address))
               (let ((tip (bl.store:current-height
                           (bl:node-chain-state node))))
                 ;; SLOW path first: no filter index on the node.
                 (setf (bl:node-blockfilterindex node) nil)
                 (multiple-value-bind (s-status s-height s-hash s-skipped)
                     (bl.wallet::scan-for-wallet-transactions
                      node wallet
                      (bl.store:block-index-entry-hash
                       (bl.store:get-block-at-height
                        (bl:node-chain-state node) 0))
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
                          (bl:node-chain-state node) 0))
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
          (bl:node-wallet-manager node)))))))

(test g7-38-missing-filter-falls-back-per-block
  "G7-38: a block with NO stored filter must be inspected, not skipped (Core
blockFilterMatchesAny -> nullopt, node/interfaces.cpp:583-584). The fallback is
PER BLOCK; there is deliberately no whole-scan guard on the index sync height,
because our index can contain holes below its best marker."
  (with-network (:regtest)
    (let* ((node (make-wallet-chain-node "g738b"))
           (wname "g738bw"))
      (unwind-protect
           (progn
             (bl.wallet::rpc-createwallet node (list wname))
             (let ((wallet (%wc-wallet node wname)))
               (%wc-mine node 3 (%wc-optrue-address))
               (let ((bfi (%wc-build-filter-index node))
                     (state (bl:node-chain-state node)))
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
          (bl:node-wallet-manager node)))))))

(test g7-38-filter-set-is-the-ismine-set-and-grows-with-topup
  "G7-38: the query set must be exactly the wallet's IsMine script set, and
UpdateIfNeeded must fold in scripts created by a mid-rescan TopUp — polling
GetEndRange = max-cached-index + 1 (Core scriptpubkeyman.cpp:1518-1521), NOT
range-end and NOT next-index."
  (with-network (:regtest)
    (let* ((node (make-wallet-chain-node "g738c" :keypool 3))
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
                 (dotimes (i 8) (%wc-newaddress node '()))
                 (is (> (%wc-total-end-range wallet) before)
                     "precondition: handing out addresses must grow max-cached-index"))
               (bl.wallet::%rescan-filter-update-if-needed wallet rf)
               (is (> (length (bl.wallet::rescan-filter-scripts rf)) initial)
                   "UpdateIfNeeded must fold in the newly cached scripts")))
        (ignore-errors
         (bl.wallet:close-wallet-manager
          (bl:node-wallet-manager node)))))))

(test wallet-from-another-chain-is-refused-without-walletcrosschain
  "Core AttachChain (wallet.cpp:3178-3190) refuses a wallet whose stored
best-block locator ends at a genesis block that is not this chain's, unless
-walletcrosschain (DEFAULT_WALLETCROSSCHAIN = false, wallet.h:135) says
otherwise; wallet_crosschain.py is the oracle.

We compared nothing and kept -walletcrosschain in the accept-and-ignore
table, so we behaved as if it were permanently on: the foreign locator found
no fork, the wallet was rescanned from its birthday, every stored
confirmation was demoted to :inactive by %wtx-update-state-from-chain, its
own transactions were pushed at this node's mempool, and the persisted
locator was overwritten with THIS chain's -- a wallet shown as emptied
instead of an operator told why."
  (with-wallet-chain-node (node "xchain" :wallet "xchainw")
    (%wc-mine node 2 (%wc-optrue-address))
    (let ((foreign-genesis (make-array 32 :element-type '(unsigned-byte 8)
                                          :initial-element #xfe))
          ;; Core's LoadWalletInternal prefixes every LoadExisting failure --
          ;; this one included -- with "Wallet loading failed. "
          ;; (wallet.cpp:286-291).
          (message (concatenate
                    'string
                    "Wallet loading failed. "
                    "Wallet files should not be reused across chains. "
                    "Restart bitcoind with -walletcrosschain to override.")))
      ;; Control: this chain's own locator reloads without complaint.
      (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "xchainw"))
      (finishes (bl.rpc:dispatch-rpc-method node "loadwallet" (list "xchainw")))
      ;; unload-wallet writes a single-hash locator for the wallet's last
      ;; processed block, so stamping that hash makes the STORED locator's
      ;; oldest -- and only -- entry a block this chain has never seen.
      (setf (bl.wallet::wallet-last-block-hash (%wc-wallet node "xchainw"))
            foreign-genesis)
      (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "xchainw"))
      (signals-rpc-error (:code -4 :exact-message message)
        (bl.rpc:dispatch-rpc-method node "loadwallet" (list "xchainw")))
      ;; A refused wallet is not left half-loaded (Core unloads it too).
      (is (null (%wc-wallet node "xchainw")))
      ;; -walletcrosschain is the documented override, and taking it rewrites
      ;; the locator, so the wallet loads unaided afterwards.
      (let ((bl.wallet:*wallet-cross-chain* t))
        (finishes (bl.rpc:dispatch-rpc-method node "loadwallet" (list "xchainw"))))
      (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "xchainw"))
      (finishes (bl.rpc:dispatch-rpc-method node "loadwallet" (list "xchainw"))))))

;;; --- CWalletTx mapValue strings are Core's bytes ---------------------------

(test wallet-tx-map-value-holds-cores-utf-8-bytes
  "CWalletTx::mapValue is std::map<std::string, std::string>
(wallet/transaction.h:167, :222) and a std::string serializes as its BYTES
behind a compactsize (serialize.h:779-784), so the comment a client sent in
its JSON request -- UTF-8 on the wire -- lands on disk as those same bytes.
The stream codec here was ASCII: a comment with any character above U+007F
could not be written at all. UTF-8 keeps an ASCII record byte-identical (the
golden bytes below are what every existing wallet holds) and puts Core's
bytes on disk for everything else. Built with CODE-CHAR so this source file
stays ASCII."
  (let* ((prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (tx (%wc-spend-tx prev 0 12345 (p2sh-optrue-script-pubkey)))
         (e-acute (string (code-char #xE9)))
         (cjk (coerce (list (code-char #x4E2D) (code-char #x6587)) 'string)))
    (flet ((record-with (comment)
             (let ((wtx (bl.wallet::make-wallet-tx :tx tx :txid (bl.ser:transaction-hash tx))))
               (setf (bl.wallet::wallet-tx-map-value wtx) (list (cons "comment" comment)))
               (bl.wallet::wallet-tx-record-value wtx)))
           (comment-of (bytes)
             (cdr (assoc "comment"
                         (bl.wallet::wallet-tx-map-value
                          (bl.wallet::parse-wallet-tx-record bytes))
                         :test #'string=))))
      ;; Golden: an ASCII comment is exactly the bytes it always was,
      ;; 07 "comment" 02 "hi".
      (let ((bytes (record-with "hi")))
        (is-true (search #(7 99 111 109 109 101 110 116 2 104 105) bytes)
                 "the ASCII record changed on disk")
        (is (equal "hi" (comment-of bytes))))
      ;; U+00E9 is TWO UTF-8 bytes, never the single Latin-1 byte.
      (let ((bytes (record-with e-acute)))
        (is-true (search (vector 7 99 111 109 109 101 110 116 2 #xC3 #xA9) bytes)
                 "U+00E9 is not on disk as its UTF-8 bytes")
        (is-false (search (vector 7 99 111 109 109 101 110 116 1 #xE9) bytes)
                  "U+00E9 is on disk as one Latin-1 byte")
        (is (equal e-acute (comment-of bytes))))
      ;; Two CJK characters: six bytes, and the round trip is the same string.
      (let ((bytes (record-with cjk)))
        (is-true (search (vector 7 99 111 109 109 101 110 116 6 #xE4 #xB8 #xAD #xE6 #x96 #x87)
                         bytes)
                 "the CJK comment is not on disk as its UTF-8 bytes")
        (is (equal cjk (comment-of bytes)))))))

(test rescan-logs-cores-start-line-naming-the-block
  "Core opens every rescan with
\"Rescan started from block %s... (%s)\" (wallet/wallet.cpp:1871), the block
being the uint256 the scan starts at and the parenthesis saying which of the
two variants is running. Ours named the start HEIGHT instead, which reads more
easily and is not what a caller can wait for: an importdescriptors rescan runs
on a worker while the caller drives the wallet's lock from another connection,
and wallet_importdescriptors.py:717 catches that window by matching this line
with the genesis hash in it.

The variant text is asserted too: it is the half that says whether the filter
index is being used, and both spellings were already here."
  (with-wallet-chain-node (node "rescan-log")
    (bl.rpc:dispatch-rpc-method node "createwallet" (wire-params '("rlw")))
    (%wc-mine node 2 (%wc-optrue-address))
    (let* ((genesis (bl.store:block-index-entry-hash
                     (bl.store:get-block-at-height (bl:node-chain-state node) 0)))
           (lines (with-rpc-wallet ("rlw")
                    (capture-log-lines
                     (lambda ()
                       (bl.rpc:dispatch-rpc-method node "rescanblockchain"
                                                   (wire-params '(0))))))))
      (is-true (%wc-mentions-p
                (format nil "Rescan started from block ~A... (slow variant inspecting all blocks)"
                        (bl.rpc:hash-to-hex genesis))
                lines)
               "no Core-shaped rescan line among ~S" lines))))

(defun %wc-synthetic-block (node txs)
  "A block carrying TXS, labelled with the node's own tip hash and height so
the wallet's locator write has a block it can place. Only the transaction
list and the header timestamp are read by the block-connected hook."
  (values (bl.ser:make-bitcoin-block
           :header (bl.ser:make-block-header
                    :version 4 :timestamp (bl.ser:get-unix-time)
                    :bits #x207fffff :nonce 0)
           :transactions txs)
          (bl.store:best-block-hash (bl:node-chain-state node))
          (bl.store:current-height (bl:node-chain-state node))))

(test a-spend-of-a-zero-value-output-is-still-from-this-wallet
  "Core's CWallet::IsFromMe asks whether any input spends an outpoint the
wallet holds a TXO for (wallet.cpp:1681-1688) -- PRESENCE, not value. Ours
read it as its pre-m_txos form, GetDebit > 0, which is 0 for a zero-value
output: the transaction SPENDING one was never recorded by
AddToWalletIfInvolvingMe (:1211), so the output stayed in listunspent for
good. A pay-to-anchor output is exactly that, and wallet_anchor.py:80 rescans
the whole chain and expects listunspent to come back EMPTY.

The first block is the positive control: a zero-value output IS received and
listed, so the empty answer below comes from the spend and not from the
wallet having ignored the output in the first place."
  (with-wallet-chain-node (node "wc-zero-spend")
    (bl.rpc:dispatch-rpc-method node "createwallet" (wire-params '("zv")))
    (with-rpc-wallet ("zv")
      (let* ((manager (bl:node-wallet-manager node))
             (address (%wc-newaddress node))
             (spk (nth-value 1 (bl.crypto:decode-address address :regtest)))
             (funding (bl.ser:make-transaction
                       :version 2
                       :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                               :initial-element 9)
                                                          :index 0)
                                        :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                        :sequence #xffffffff))
                       :outputs (vector (bl.ser:make-tx-out :value 0 :script-pubkey spk))
                       :lock-time 0))
             (spend (bl.ser:make-transaction
                     :version 2
                     :inputs (vector (bl.ser:make-tx-in
                                      :previous-output (bl.ser:make-outpoint
                                                        :hash (bl.ser:transaction-hash funding)
                                                        :index 0)
                                      :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                      :sequence #xffffffff))
                     :outputs (vector (bl.ser:make-tx-out
                                       :value 0 :script-pubkey (p2sh-optrue-script-pubkey)))
                     :lock-time 0)))
        (flet ((connect (tx)
                 (multiple-value-bind (block hash height) (%wc-synthetic-block node (list tx))
                   (bl.wallet:wallets-block-connected
                    manager (bl:node-mempool node) (bl:node-chain-state node)
                    block hash height)))
               (unspent ()
                 (let ((rows (bl.rpc:dispatch-rpc-method
                              node "listunspent" (wire-params '(0)))))
                   (if (vectorp rows) '() rows))))
          (connect funding)
          (is (= 1 (length (unspent)))
              "the zero-value output was not received at all: ~S" (unspent))
          (is (eql 0 (btc-amount (cdr (assoc "amount" (first (unspent)) :test #'string=))))
              "the received output is not the zero-value one")
          (connect spend)
          (is (null (unspent))
              "the spent zero-value output is still unspent: ~S" (unspent)))))))

(test a-wallet-needing-blocks-the-background-sync-lacks-is-refused-by-height
  "Core's AttachChain walks block data only when data can be MISSING --
`chain.havePruned() || chain.hasAssumedValidChain()' -- and then descends from
the tip for as long as the block below is on disk; if that walk stops ABOVE the
height the rescan must start from, the load FAILS, naming the height at which
the wallet will load (wallet.cpp:3237-3264). LoadWalletInternal prefixes the
sentence with `Wallet loading failed. ' (wallet.cpp:286-291), which is what
wallet_assumeutxo.py:208-210 reads back with -4.

We compared the rescan height against the PRUNED height instead. An
assumed-valid chain prunes nothing -- its missing blocks are the ones the
background sync has not re-derived yet -- so that comparison never fired: the
wallet loaded and its rescan then ran over blocks the node does not have.

Two wallets on one node, which is the test's own shape (:200-210): the one
whose locator is ABOVE the gap loads, the one below it is refused."
  (with-wallet-chain-node (node "assumeutxo-load" :wallet "below")
    (bl.rpc:dispatch-rpc-method node "createwallet" (list "above"))
    (%wc-mine node 3 (%wc-optrue-address))
    ;; A background (assumeutxo) chainstate is one still re-deriving history
    ;; toward a target block, which is exactly what this slot says. It is a
    ;; SECOND chainstate: the one carrying a target can never be the current
    ;; one (SELECT-CURRENT-CHAINSTATE), which is the shape a loaded snapshot
    ;; has.
    (push (bl.store:make-chain-state
           :target-blockhash (bl.store:best-block-hash (bl:node-chain-state node)))
          (bl:node-chainstates node))
    (is-true (bl:node-historical-chainstate node)
             "the fixture must look like a background sync in progress")
    ;; `below' stops here; `above' follows two more blocks before it stops.
    (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "below"))
    (let ((below-height (bl.store:current-height (bl:node-chain-state node))))
      (%wc-mine node 2 (%wc-optrue-address))
      (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "above"))
      (let ((above-height (bl.store:current-height (bl:node-chain-state node))))
        (%wc-mine node 2 (%wc-optrue-address))
        ;; The body one block above `below' is gone, as it would be while a
        ;; background sync re-derives history: the walk stops at the block
        ;; above it, which is where `above' starts.
        (let ((missing (bl.store:get-block-at-height (bl:node-chain-state node)
                                                     (1+ below-height))))
          (is-true (bl.store:forget-block-body
                    (bl:node-block-store node)
                    (bl.store:block-index-entry-hash missing))
                   "the fixture must remove a block body")
          ;; Control: this wallet's rescan starts at the block the walk
          ;; reaches, so Core loads it during the background sync.
          (finishes (bl.rpc:dispatch-rpc-method node "loadwallet" (list "above")))
          (is (equal (cons bl.rpc:+rpc-wallet-error+
                           (format nil "Wallet loading failed. Error loading wallet. Wallet requires blocks to be downloaded, and software does not currently support loading wallets while blocks are being downloaded out of order when using assumeutxo snapshots. Wallet should be able to load successfully after node sync reaches height ~D"
                                   above-height))
                     (rpc-error-of
                      (lambda ()
                        (bl.rpc:dispatch-rpc-method node "loadwallet" (list "below")))))))))))


(defun %wc-assumeutxo-gap-node-refusal (node)
  "With NODE's wallet `below' unloaded, open a gap the way a background sync
does -- a historical chainstate, two more blocks, the body above `below''s
last block forgotten -- and return a thunk that tries to load `below' and
answers the refusal's message, or NIL when it loaded."
  (%wc-mine node 3 (%wc-optrue-address))
  (push (bl.store:make-chain-state
         :target-blockhash (bl.store:best-block-hash (bl:node-chain-state node)))
        (bl:node-chainstates node))
  (bl.rpc:dispatch-rpc-method node "unloadwallet" (list "below"))
  (let ((below-height (bl.store:current-height (bl:node-chain-state node))))
    (%wc-mine node 4 (%wc-optrue-address))
    (let ((missing (bl.store:get-block-at-height (bl:node-chain-state node)
                                                 (1+ below-height))))
      (bl.store:forget-block-body (bl:node-block-store node)
                                  (bl.store:block-index-entry-hash missing))))
  (lambda ()
    (cdr (rpc-error-of
          (lambda ()
            (bl.rpc:dispatch-rpc-method node "loadwallet" (list "below")))))))

(test a-refused-wallet-load-leaves-the-wallet-where-it-was
  "Core's failed AttachChain sets the last processed block IN MEMORY only
(SetLastBlockProcessedInMem, wallet.cpp:3213-3218) and returns false; the
wallet instance is dropped without RemoveWallet's WriteBestBlock
(wallet.cpp:163-169), so its stored locator still names where it stopped and
the next load is refused again. Ours unloaded the half-loaded wallet through
UNLOAD-WALLET, which writes the best block -- the tip, set before the check
-- so the SECOND attempt found nothing to rescan and loaded a wallet that had
never seen the missing blocks."
  (with-wallet-chain-node (node "refused-stays-refused" :wallet "below")
    (let ((refusal (%wc-assumeutxo-gap-node-refusal node)))
      (let ((first (funcall refusal))
            (second (funcall refusal)))
        (is (search "when using assumeutxo snapshots" (or first "")))
        (is (equal first second) "the second attempt answered ~S" second)))))

(test a-prune-mode-node-that-has-pruned-nothing-gives-the-assumeutxo-refusal
  "Core picks AttachChain's refusal by chain.havePruned() -- whether block files
HAVE been pruned, BlockManager::m_have_pruned -- not by whether the node is in
prune mode (wallet.cpp:3255-3262). A -prune node that loaded a snapshot and
pruned nothing yet refuses a wallet below the gap with the assumeutxo
sentence, which wallet_assumeutxo.py:90 reads; ours gave the prune one to
every prune-mode node."
  (with-wallet-chain-node (node "assumeutxo-prune-mode" :wallet "below")
    (let ((refusal (%wc-assumeutxo-gap-node-refusal node))
          (bl:*prune-target-mib* 550))
      (let ((unpruned (funcall refusal)))
        (is (search "when using assumeutxo snapshots" (or unpruned ""))
            "a prune-mode node with nothing pruned gave: ~S" unpruned))
      ;; Control: once block files HAVE been pruned, the prune sentence.
      (setf (bl.store:chain-state-pruned-height (bl:node-chain-state node)) 1)
      (let ((pruned (funcall refusal)))
        (is (search "Prune: last wallet synchronisation goes beyond pruned data"
                    (or pruned ""))
            "a node that pruned gave: ~S" pruned)))))

(test importdescriptors-rescan-failure-names-its-cause-and-the-last-failed-block
  "Core's importdescriptors replaces a request's result when the rescan failed
to reach its timestamp (wallet/rpc/backup.cpp:417-452). The sentence names the
request's RAW timestamp (GetImportTimestamp, not the clamped one), the max
time of the LAST block the scan could not read (RescanFromTime,
wallet.cpp:1826-1830), and a cause: pruning when blocks have been pruned, an
in-progress assumeutxo background sync, else corruption. Ours printed the
clamped timestamp 1, the scan's START block time, and always the corruption
sentence; wallet_assumeutxo.py:223 reads all three."
  (with-wallet-chain-node (node "import-rescan-cause")
    (%wc-mine node 3 (%wc-optrue-address))
    (bl.rpc:dispatch-rpc-method node "createwallet" (list "wo" t))
    (let* ((cs (bl:node-chain-state node))
           (b2 (bl.store:get-block-at-height cs 2))
           (b2-time-max (loop for e = b2 then (bl.store:block-index-entry-prev-entry e)
                              while e
                              maximize (bl.ser:block-header-timestamp
                                        (bl.store:block-index-entry-header e)))))
      (bl.store:forget-block-body (bl:node-block-store node)
                                  (bl.store:block-index-entry-hash b2))
      (flet ((import-message ()
               (let* ((req (make-hash-table :test 'equal)))
                 (setf (gethash "desc" req)
                       (bl.rpc:dispatch-rpc-method
                        node "getdescriptorinfo"
                        (list (format nil "addr(~A)" (%wc-optrue-address))))
                       (gethash "desc" req) (cdr (assoc "descriptor" (gethash "desc" req)
                                                       :test #'string=))
                       (gethash "timestamp" req) 0)
                 (with-rpc-wallet ("wo")
                   (let ((row (first (coerce (bl.rpc:dispatch-rpc-method
                                              node "importdescriptors" (list (list req)))
                                             'list))))
                     (cdr (assoc "message" (cdr (assoc "error" row :test #'string=))
                                 :test #'string=)))))))
        ;; No background sync, nothing pruned: the corruption sentence.
        (let ((m (import-message)))
          (is (search "timestamp 0. There was an error reading a block from time " (or m "")) "got ~S" m)
          (is (search (format nil "from time ~D," b2-time-max) (or m "")) "got ~S" m)
          (is (search "could potentially caused by data corruption" (or m ""))))
        ;; During a background sync: the assumeutxo sentence.
        (push (bl.store:make-chain-state :target-blockhash (bl.store:best-block-hash cs))
              (bl:node-chainstates node))
        (let ((m (import-message)))
          (is (search "likely caused by an in-progress assumeutxo background sync" (or m ""))
              "got ~S" m))))))

(test rescanblockchain-refuses-a-range-with-missing-bodies-by-cause
  "Core's rescanblockchain refuses up front unless every block of the range has
its body (Chain::hasBlocks, node/interfaces.cpp:637-655), naming the cause:
pruning, an in-progress assumeutxo background sync, or corruption
(wallet/rpc/transactions.cpp:885-893). Ours checked only the prune horizon
and the start block's index entry, scanned into the gap, and answered
`Rescan failed. Potentially corrupted data files.' (wallet_assumeutxo.py:227)."
  (with-wallet-chain-node (node "rescan-gap" :wallet "w")
    (%wc-mine node 4 (%wc-optrue-address))
    (let ((cs (bl:node-chain-state node)))
      (flet ((rescan (&rest params)
               (rpc-error-of (lambda ()
                               (bl.rpc:dispatch-rpc-method node "rescanblockchain" params)))))
        ;; Control: every body present, the rescan runs.
        (is (null (rescan 0)))
        (bl.store:forget-block-body (bl:node-block-store node)
                                    (bl.store:block-index-entry-hash
                                     (bl.store:get-block-at-height cs 2)))
        ;; A range above the gap is still fine.
        (is (null (rescan 3)))
        (is (equal '(-1 . "Failed to rescan unavailable blocks, potentially caused by data corruption. If the issue persists you may want to reindex (see -reindex option).")
                   (rescan 0)))
        (push (bl.store:make-chain-state :target-blockhash (bl.store:best-block-hash cs))
              (bl:node-chainstates node))
        (is (equal '(-1 . "Failed to rescan unavailable blocks likely due to an in-progress assumeutxo background sync. Check logs or getchainstates RPC for assumeutxo background sync progress and try again later.")
                   (rescan 0)))))))
