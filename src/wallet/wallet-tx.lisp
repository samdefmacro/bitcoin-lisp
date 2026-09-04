(in-package #:bitcoin-lisp.wallet)

;;; Wallet P2: chain tracking (docs/wallet-plan.md §5 P2)
;;;
;;; Ports, from Bitcoin Core @ d3056bc:
;;;  - TxState + CWalletTx (src/wallet/transaction.{h,cpp}): the state
;;;    variant (Confirmed / InMempool / BlockConflicted / Inactive incl.
;;;    abandoned), its serialized hash+index encoding, and the CWalletTx
;;;    record layout ("tx" DBKeys record, byte-identical).
;;;  - CWallet tx tracking (src/wallet/wallet.cpp): mapWallet + wtxOrdered,
;;;    m_txos, mapTxSpends, AddToWallet (:1025), AddToWalletIfInvolvingMe
;;;    (:1190), SyncTransaction (:1402), MarkConflicted (:1328),
;;;    RecursiveUpdateTxState (:1363), AbandonTransaction (:1298),
;;;    ComputeTimeSmart (:2812), the four notification handlers
;;;    (:1414/:1457/:1526/:1555), LoadToWallet (:1156), AttachChain (:3171),
;;;    ScanForWalletTransactions (:1857), RescanFromTime (:1813),
;;;    WriteBestBlock (:4534).
;;;  - The transaction RPCs (src/wallet/rpc/transactions.cpp):
;;;    gettransaction / listtransactions / listsinceblock plus
;;;    rescanblockchain / abortrescan, with WalletTxToJSON / ListTransactions
;;;    field sets, and the receive.cpp accounting they need (debit/credit/
;;;    fee via m_txos, the IsChange heuristic, CachedTxIsTrusted). Wallet P3
;;;    added the CWalletTx amount caches + MarkDirty propagation and the
;;;    avoid_reuse previously-spent tracking here; balance rollups, coin
;;;    listing, and the coins/address RPCs live in wallet-coins.lisp.
;;;
;;; Delivery: the node's hardcoded hooks (node/wallet-hooks.lisp wallet-notify-*) call
;;; the wallets-* fan-outs below synchronously from connect-block /
;;; perform-reorg / mempool-add / mempool-remove, where Core delivers the
;;; same events asynchronously on the scheduler thread. Lock order:
;;; node-lock (held by every hook caller) -> wallet-manager lock -> wallet
;;; lock; wallet code below never takes the node-lock while holding a
;;; wallet lock.
;;;
;;; Known divergences from Core (all safe-direction, documented inline):
;;;  - Birthday gating uses a wallet-side running max of processed block
;;;    times instead of the block index's nTimeMax (we do not store one);
;;;    the running max only over-approximates, so blocks are never skipped
;;;    that Core would scan.
;;;  - A rescanned tx's nTimeSmart uses the scanned block's own time where
;;;    Core uses the chain's max-time-so-far at that block (cosmetic:
;;;    affects listtransactions ordering of same-block historical txs).
;;;  - A wallet-record write failure inside the block-connected hook logs
;;;    loudly and continues; Core aborts the node. Aborting a block connect
;;;    over a wallet-side failure would be consensus-affecting here.

(defconstant +wallet-timestamp-window+ 7200
  "Core chain.h TIMESTAMP_WINDOW (= MAX_FUTURE_BLOCK_TIME): the slack applied
to key/birth timestamps when deciding which blocks could contain relevant
transactions.")

(defconstant +wallet-best-block-cadence+ 144
  "Persist the best-block locator every this many blocks when no wallet tx
changed (Core CWallet::blockConnected, wallet.cpp:1550).")

(alexandria:define-constant +uint256-zero+
    (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
  :test #'equalp)

(alexandria:define-constant +uint256-one+
    (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref v 0) 1)
      v)
  :test #'equalp
  :documentation "uint256::ONE — the serialized block-hash marker of an
abandoned TxStateInactive (transaction.h:85-103).")

(defun %wtx-outpoint-key (txid index)
  "36-byte txid||index-LE key for the txos / tx-spends tables."
  (let ((key (make-array 36 :element-type '(unsigned-byte 8))))
    (replace key txid)
    (setf (aref key 32) (logand index #xFF)
          (aref key 33) (logand (ash index -8) #xFF)
          (aref key 34) (logand (ash index -16) #xFF)
          (aref key 35) (logand (ash index -24) #xFF))
    key))

(defun %tx-value-out (tx)
  (reduce #'+ (bl.ser:transaction-outputs tx)
          :key #'bl.ser:tx-out-value :initial-value 0))

(defun %tx-coinbase-p (tx)
  (let ((inputs (bl.ser:transaction-inputs tx)))
    (and (plusp (length inputs))
         (bl.ser:coinbase-input-p (aref inputs 0)))))

;;; --- wallet-tx: CWalletTx (transaction.h:194) ---

(defstruct wallet-tx
  "A wallet transaction (Core CWalletTx). STATE is the TxState variant kind:
:confirmed (block-hash/height/index set), :in-mempool, :block-conflicted
(block-hash/height set), or :inactive (abandoned flag meaningful). A stored
height of -1 means not-yet-resolved against the chain (the serialized form
carries no height; CWalletTx::updateState fills it)."
  (tx nil)
  (txid nil)
  (state :inactive :type keyword)
  (block-hash nil)
  (block-height -1 :type (signed-byte 32))
  (block-index -1 :type (signed-byte 32))
  (abandoned nil)
  (time-received 0 :type (unsigned-byte 32))
  (time-smart 0 :type (unsigned-byte 32))
  (order-pos -1 :type integer)
  (map-value '() :type list)     ; user ("key" . "value") pairs (comment/to/...)
  (order-form '() :type list)
  ;; Mempool txids conflicting with this tx or an ancestor (CWalletTx
  ;; mempool_conflicts) — a set keyed by txid.
  (mempool-conflicts (make-hash-table :test 'equalp) :type hash-table)
  ;; TRUC (v3) child in the mempool spending this tx (truc_child_in_mempool).
  (truc-child nil)
  ;; --- Amount caches (wallet P3; CWalletTx m_amounts / nChangeCached /
  ;; m_cached_from_me, transaction.h:236-251). One slot per amount where
  ;; Core keeps two keyed by avoid_reuse: at d3056bc GetCachableAmount
  ;; computes the identical value for both slots (the computation ignores
  ;; the flag), so a single slot is behavior-identical. NIL = uncached. ---
  (cached-debit nil)
  (cached-credit nil)
  (cached-change nil)
  (cached-from-me :unknown)
  ;; T while both debit and credit slots are empty (m_is_cache_empty; the
  ;; MarkDestinationsDirty short-circuit — deliberately ignores the change/
  ;; from-me caches, like Core).
  (cache-empty t))

(defun %wtx-apply-state (wtx kind &optional block-hash (block-height -1)
                                            (block-index -1) abandoned)
  (setf (wallet-tx-state wtx) kind
        (wallet-tx-block-hash wtx) block-hash
        (wallet-tx-block-height wtx) block-height
        (wallet-tx-block-index wtx) block-index
        (wallet-tx-abandoned wtx) (and abandoned t))
  wtx)

(defun %wtx-apply-state-list (wtx state)
  "STATE is (:confirmed hash height index) | (:in-mempool) |
(:inactive [abandoned]) | (:block-conflicted hash height)."
  (ecase (first state)
    (:confirmed (%wtx-apply-state wtx :confirmed (second state) (third state)
                                  (fourth state)))
    (:in-mempool (%wtx-apply-state wtx :in-mempool))
    (:inactive (%wtx-apply-state wtx :inactive nil -1 -1 (second state)))
    (:block-conflicted (%wtx-apply-state wtx :block-conflicted (second state)
                                         (third state)))))

(defun %wtx-abandoned-p (wtx)
  (and (eq (wallet-tx-state wtx) :inactive) (wallet-tx-abandoned wtx) t))

(defun %wtx-mempool-conflicted-p (wtx)
  (plusp (hash-table-count (wallet-tx-mempool-conflicts wtx))))

(defun %wtx-unconfirmed-p (wtx)
  "Core CWalletTx::isUnconfirmed."
  (not (or (%wtx-abandoned-p wtx)
           (eq (wallet-tx-state wtx) :block-conflicted)
           (%wtx-mempool-conflicted-p wtx)
           (eq (wallet-tx-state wtx) :confirmed))))

(defun %wtx-coinbase-p (wtx)
  (%tx-coinbase-p (wallet-tx-tx wtx)))

(defun wallet-tx-get-time (wtx)
  "Core CWalletTx::GetTxTime: nTimeSmart, else nTimeReceived."
  (let ((n (wallet-tx-time-smart wtx)))
    (if (plusp n) n (wallet-tx-time-received wtx))))

(defun wallet-tx-depth (wallet wtx)
  "Core CWallet::GetTxDepthInMainChain: >0 confirmations, 0 unconfirmed,
<0 conflicted-that-deep. A height of -1 (unresolved against a chain) counts
as depth 0 rather than asserting like Core — reachable only when a wallet is
loaded without any chain state."
  (let ((height (wallet-tx-block-height wtx))
        (last (wallet-last-block-height wallet)))
    (case (wallet-tx-state wtx)
      (:confirmed (if (minusp height) 0 (1+ (- last height))))
      (:block-conflicted (if (minusp height) 0 (- (1+ (- last height)))))
      (t 0))))

(defun wallet-tx-blocks-to-maturity (wallet wtx)
  "Core GetTxBlocksToMaturity: 0 for non-coinbase; else how many blocks until
the coinbase output is spendable (COINBASE_MATURITY + the +1 rule)."
  (if (not (%wtx-coinbase-p wtx))
      0
      (max 0 (- (1+ bl.val:+coinbase-maturity+)
                (wallet-tx-depth wallet wtx)))))

(defun wallet-tx-immature-coinbase-p (wallet wtx)
  (plusp (wallet-tx-blocks-to-maturity wallet wtx)))

;;; --- CWalletTx record serialization ("tx" DBKeys record) ---
;;;
;;; Byte-identical to CWalletTx::Serialize (transaction.h:284-330):
;;;   TX_WITH_WITNESS(tx) | serialized state hash (32) | vMerkleBranch
;;;   (empty vector) | serialized state index (i32) | vtxPrev (empty
;;;   vector) | mapValue (sorted string map incl. fromaccount/n/timesmart)
;;;   | vOrderForm | fTimeReceivedIsTxTime (u32 0) | nTimeReceived (u32) |
;;;   fFromMe (u8 0) | fSpent (u8 0).

(defun %wtx-serialized-state (wtx)
  "(values hash index) — TxStateSerializedBlockHash/Index (transaction.h:100-121)."
  (ecase (wallet-tx-state wtx)
    (:inactive (if (wallet-tx-abandoned wtx)
                   (values +uint256-one+ -1)
                   (values +uint256-zero+ 0)))
    (:in-mempool (values +uint256-zero+ 0))
    (:confirmed (values (wallet-tx-block-hash wtx) (wallet-tx-block-index wtx)))
    (:block-conflicted (values (wallet-tx-block-hash wtx) -1))))

(defun %wtx-interpret-serialized-state (wtx hash index)
  "TxStateInterpretSerialized (transaction.h:85-97). An unrecognized
combination loads as :inactive with a warning string returned (Core keeps a
TxStateUnrecognized preserving the raw values; we have no consumer for it)."
  (cond
    ((equalp hash +uint256-zero+)
     (if (zerop index)
         (progn (%wtx-apply-state wtx :inactive) nil)
         (progn (%wtx-apply-state wtx :inactive)
                "Unrecognized wallet tx state loaded as inactive")))
    ((equalp hash +uint256-one+)
     (if (= index -1)
         (progn (%wtx-apply-state wtx :inactive nil -1 -1 t) nil)
         (progn (%wtx-apply-state wtx :inactive)
                "Unrecognized wallet tx state loaded as inactive")))
    ((>= index 0)
     (%wtx-apply-state wtx :confirmed hash -1 index)
     nil)
    ((= index -1)
     (%wtx-apply-state wtx :block-conflicted hash -1)
     nil)
    (t (%wtx-apply-state wtx :inactive)
       "Unrecognized wallet tx state loaded as inactive")))

(defun %wtx-serialized-map-value (wtx)
  "The mapValue actually serialized: user pairs plus the fromaccount/n/
timesmart record fields, sorted by key (std::map iteration order)."
  (let ((pairs (copy-alist (wallet-tx-map-value wtx))))
    (push (cons "fromaccount" "") pairs)
    (unless (= (wallet-tx-order-pos wtx) -1)
      (push (cons "n" (format nil "~D" (wallet-tx-order-pos wtx))) pairs))
    (when (plusp (wallet-tx-time-smart wtx))
      (push (cons "timesmart" (format nil "~D" (wallet-tx-time-smart wtx)))
            pairs))
    (sort pairs #'string< :key #'car)))

(defun wallet-tx-record-value (wtx)
  "Serialize WTX as Core's CWalletTx record value."
  (multiple-value-bind (state-hash state-index) (%wtx-serialized-state wtx)
    (%wser (s)
      (bl.ser:write-bytes
       s (bl.ser:transaction-wire-bytes (wallet-tx-tx wtx)))
      (bl.ser:write-bytes s state-hash)
      (bl.ser:write-compact-size s 0)   ; vMerkleBranch
      (bl.ser:write-int32-le s state-index)
      (bl.ser:write-compact-size s 0)   ; vtxPrev
      (let ((map-pairs (%wtx-serialized-map-value wtx)))
        (bl.ser:write-compact-size s (length map-pairs))
        (loop for (k . v) in map-pairs
              do (%wser-string s k) (%wser-string s v)))
      (bl.ser:write-compact-size
       s (length (wallet-tx-order-form wtx)))
      (loop for (k . v) in (wallet-tx-order-form wtx)
            do (%wser-string s k) (%wser-string s v))
      (bl.ser:write-uint32-le s 0)      ; fTimeReceivedIsTxTime
      (bl.ser:write-uint32-le s (wallet-tx-time-received wtx))
      (bl.ser:write-uint8 s 0)          ; fFromMe
      (bl.ser:write-uint8 s 0))))       ; fSpent

(defun parse-wallet-tx-record (bytes)
  "(values wallet-tx warning-or-nil) from a CWalletTx record value
(CWalletTx::Unserialize)."
  (%wparse (s bytes)
    (let* ((tx (bl.ser:read-transaction s))
           (state-hash (bl.ser:read-bytes s 32))
           (dummy1-count (bl.ser:read-compact-size s)))
      ;; vMerkleBranch: vector<uint256>, always written empty since 2014.
      (dotimes (i dummy1-count) (bl.ser:read-bytes s 32))
      (let ((state-index (bl.ser:read-int32-le s))
            (vtxprev-count (bl.ser:read-compact-size s)))
        ;; vtxPrev (legacy CMerkleTx list): we never write it and no
        ;; descriptor wallet ever has — refuse rather than mis-parse.
        (unless (zerop vtxprev-count)
          (wallet-error "wallet tx record carries legacy vtxPrev data"))
        (let* ((map-pairs (loop repeat (bl.ser:read-compact-size s)
                                collect (cons (%wread-string s) (%wread-string s))))
               (order-form (loop repeat (bl.ser:read-compact-size s)
                                 collect (cons (%wread-string s) (%wread-string s)))))
          (bl.ser:read-uint32-le s)     ; fTimeReceivedIsTxTime
          (let ((time-received (bl.ser:read-uint32-le s)))
            (bl.ser:read-uint8 s)       ; fFromMe
            (bl.ser:read-uint8 s)       ; fSpent
            (let* ((wtx (make-wallet-tx
                         :tx tx
                         :txid (bl.ser:transaction-hash tx)
                         :time-received time-received
                         :order-form order-form))
                   (n-pair (assoc "n" map-pairs :test #'string=))
                   (ts-pair (assoc "timesmart" map-pairs :test #'string=)))
              (setf (wallet-tx-order-pos wtx)
                    (if n-pair (or (parse-integer (cdr n-pair) :junk-allowed t) -1) -1))
              (setf (wallet-tx-time-smart wtx)
                    (if ts-pair (or (parse-integer (cdr ts-pair) :junk-allowed t) 0) 0))
              (setf (wallet-tx-map-value wtx)
                    (remove-if (lambda (pair)
                                 (member (car pair)
                                         '("fromaccount" "spent" "n" "timesmart")
                                         :test #'string=))
                               map-pairs))
              (values wtx
                      (%wtx-interpret-serialized-state wtx state-hash
                                                       state-index)))))))))

(defun wallet-write-tx (wallet wtx &key batch)
  "Persist WTX's record (Core WalletBatch::WriteTx)."
  (let ((key (wdb-key-tx (wallet-tx-txid wtx)))
        (value (wallet-tx-record-value wtx)))
    (if batch
        (bl.store:leveldb-writebatch-put batch key value)
        (bl.store:leveldb-put (wallet-db wallet) key value :sync t))))

;;; --- mapWallet / m_txos / mapTxSpends primitives ---

(defun wallet-get-wallet-tx (wallet txid)
  (gethash txid (wallet-map-wallet wallet)))

(defun %wallet-tx-ordered-insert (wallet wtx)
  "Insert WTX into the nOrderPos-ordered vector. Live inserts always append
(order positions are handed out monotonically); the load path sorts once."
  (vector-push-extend wtx (wallet-tx-ordered wallet)))

(defun wallet-maybe-update-birth-time (wallet time)
  "Core CWallet::MaybeUpdateBirthTime."
  (when (< time (wallet-birth-time wallet))
    (setf (wallet-birth-time wallet) time)))

(defun wallet-inc-order-pos-next (wallet &optional batch)
  "Core CWallet::IncOrderPosNext: hand out the next order position and
persist the counter."
  (prog1 (wallet-orderposnext wallet)
    (incf (wallet-orderposnext wallet))
    (let ((key (wdb-key-simple +wdb-key-orderposnext+))
          (value (wdb-int64-value (wallet-orderposnext wallet))))
      (if batch
          (bl.store:leveldb-writebatch-put batch key value)
          (bl.store:leveldb-put (wallet-db wallet) key value)))))

(defun %wallet-tx-equivalent-p (a b)
  "Core CWalletTx::IsEquivalentTo: equal after nulling every scriptSig and
witness — same prevouts/sequences/outputs/version/locktime."
  (let ((ta (wallet-tx-tx a)) (tb (wallet-tx-tx b)))
    (flet ((stripped (tx)
             (bl.ser:serialize-transaction
              (bl.ser:make-transaction
               :version (bl.ser:transaction-version tx)
               :inputs (map 'simple-vector
                            (lambda (in)
                              (bl.ser:make-tx-in
                               :previous-output (bl.ser:tx-in-previous-output in)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence (bl.ser:tx-in-sequence in)))
                            (bl.ser:transaction-inputs tx))
               :outputs (bl.ser:transaction-outputs tx)
               :lock-time (bl.ser:transaction-lock-time tx)))))
      (equalp (stripped ta) (stripped tb)))))

(defun %wallet-sync-metadata (wallet key)
  "Core CWallet::SyncMetaData: every equivalent tx spending KEY's outpoint
copies the metadata of the oldest one."
  (let* ((txids (gethash key (wallet-tx-spends wallet)))
         (wtxs (loop for id in txids
                     for w = (wallet-get-wallet-tx wallet id)
                     when w collect w))
         (copy-from (and wtxs
                         (reduce (lambda (a b)
                                   (if (< (wallet-tx-order-pos b)
                                          (wallet-tx-order-pos a))
                                       b a))
                                 wtxs))))
    (when copy-from
      (dolist (copy-to wtxs)
        (unless (or (eq copy-from copy-to)
                    (not (%wallet-tx-equivalent-p copy-from copy-to)))
          (setf (wallet-tx-map-value copy-to)
                (copy-alist (wallet-tx-map-value copy-from))
                (wallet-tx-order-form copy-to)
                (copy-alist (wallet-tx-order-form copy-from))
                ;; nTimeReceived not copied on purpose (Core comment)
                (wallet-tx-time-smart copy-to)
                (wallet-tx-time-smart copy-from)))))))

(defun %wallet-unlock-coin (wallet txid index)
  "Core CWallet::UnlockCoin: drop the locked-coin entry — a (txid index
persist) triple — erasing its record only when it was persisted."
  (let ((entry (find-if (lambda (e)
                          (and (equalp (first e) txid) (= (second e) index)))
                        (wallet-locked-utxos wallet))))
    (when entry
      (setf (wallet-locked-utxos wallet)
            (remove entry (wallet-locked-utxos wallet)))
      (when (third entry)
        (bl.store:leveldb-delete
         (wallet-db wallet) (wdb-key-lockedutxo txid index))))
    t))

(defun wallet-add-to-spends (wallet wtx)
  "Core CWallet::AddToSpends over a whole wtx: register every input's
outpoint in mapTxSpends, unlock any locked coin it spends, and sync metadata
across equivalent spenders. Coinbases spend nothing."
  (unless (%wtx-coinbase-p wtx)
    (let ((txid (wallet-tx-txid wtx)))
      (bl.ser:dovector
          (input (bl.ser:transaction-inputs (wallet-tx-tx wtx)))
        (let* ((prevout (bl.ser:tx-in-previous-output input))
               (prev-hash (bl.ser:outpoint-hash prevout))
               (prev-index (bl.ser:outpoint-index prevout))
               (key (%wtx-outpoint-key prev-hash prev-index)))
          (pushnew txid (gethash key (wallet-tx-spends wallet)) :test #'equalp)
          (%wallet-unlock-coin wallet prev-hash prev-index)
          (%wallet-sync-metadata wallet key))))))

(defun wallet-refresh-txos (wallet wtx)
  "Core CWallet::RefreshTXOsFromTx: cache this tx's IsMine outputs (spent
AND unspent) in m_txos."
  (loop for i from 0
        for output across (bl.ser:transaction-outputs
                           (wallet-tx-tx wtx))
        do (when (%wallet-script-mine-p
                  wallet (bl.ser:tx-out-script-pubkey output))
             (let ((key (%wtx-outpoint-key (wallet-tx-txid wtx) i)))
               (unless (gethash key (wallet-txos wallet))
                 (setf (gethash key (wallet-txos wallet)) (cons wtx i)))))))

(defun wallet-refresh-all-txos (wallet)
  "Core CWallet::RefreshAllTXOs."
  (loop for wtx being the hash-values of (wallet-map-wallet wallet)
        do (wallet-refresh-txos wallet wtx)))

(defun wallet-get-txo (wallet txid index)
  "(values wtx vout-index) of the owned TXO at the outpoint, or NIL
(Core GetTXO)."
  (let ((entry (gethash (%wtx-outpoint-key txid index) (wallet-txos wallet))))
    (if entry (values (car entry) (cdr entry)) nil)))

;;; --- IsMine / debit / credit (receive.cpp; cached amounts are wallet P3) ---

(defun %wallet-script-mine-p (wallet script)
  "IsMine on a script without re-taking the wallet lock (callers hold it)."
  (loop for spkm being the hash-values of (wallet-spkms wallet)
        thereis (and (spkm-is-mine spkm script) t)))

(defun %wallet-tx-any-output-mine-p (wallet tx)
  "Core CWallet::IsMine(CTransaction)."
  (loop for output across (bl.ser:transaction-outputs tx)
        thereis (%wallet-script-mine-p
                 wallet (bl.ser:tx-out-script-pubkey output))))

(defun %wallet-input-debit (wallet input)
  "Core CWallet::GetDebit(CTxIn): the prevout's value when it is an owned
TXO, else 0."
  (let ((prevout (bl.ser:tx-in-previous-output input)))
    (multiple-value-bind (wtx index)
        (wallet-get-txo wallet
                        (bl.ser:outpoint-hash prevout)
                        (bl.ser:outpoint-index prevout))
      (if wtx
          (bl.ser:tx-out-value
           (aref (bl.ser:transaction-outputs
                  (wallet-tx-tx wtx))
                 index))
          0))))

(defun wallet-tx-debit (wallet tx)
  "Core GetDebit(CTransaction): Σ owned prevout values."
  (reduce #'+ (bl.ser:transaction-inputs tx)
          :key (lambda (in) (%wallet-input-debit wallet in))
          :initial-value 0))

(defun wallet-tx-from-me-p (wallet tx)
  "Core CWallet::IsFromMe = GetDebit > 0."
  (plusp (wallet-tx-debit wallet tx)))

(defun wallet-tx-credit-raw (wallet tx)
  "receive.cpp TxGetCredit: Σ IsMine output values (no maturity handling)."
  (reduce #'+ (bl.ser:transaction-outputs tx)
          :key (lambda (out)
                 (if (%wallet-script-mine-p
                      wallet (bl.ser:tx-out-script-pubkey out))
                     (bl.ser:tx-out-value out)
                     0))
          :initial-value 0))

;;; --- CWalletTx amount caches (receive.cpp GetCachableAmount +
;;; CWalletTx::MarkDirty; wallet P3) ---

(defun wtx-mark-dirty (wtx)
  "Core CWalletTx::MarkDirty: drop every cached amount."
  (setf (wallet-tx-cached-debit wtx) nil
        (wallet-tx-cached-credit wtx) nil
        (wallet-tx-cached-change wtx) nil
        (wallet-tx-cached-from-me wtx) :unknown
        (wallet-tx-cache-empty wtx) t))

(defun wallet-mark-inputs-dirty (wallet tx)
  "Core CWallet::MarkInputsDirty: break the amount caches of every wallet tx
TX spends — its state change usually changes their available balance."
  (bl.ser:dovector
      (input (bl.ser:transaction-inputs tx))
    (let ((wtx (wallet-get-wallet-tx
                wallet
                (bl.ser:outpoint-hash
                 (bl.ser:tx-in-previous-output input)))))
      (when wtx (wtx-mark-dirty wtx)))))

(defun wallet-tx-get-debit (wallet wtx)
  "receive.cpp CachedTxGetDebit: 0 when the tx has no inputs, else the
cached GetDebit."
  (if (zerop (length (bl.ser:transaction-inputs
                      (wallet-tx-tx wtx))))
      0
      (or (wallet-tx-cached-debit wtx)
          (setf (wallet-tx-cache-empty wtx) nil
                (wallet-tx-cached-debit wtx)
                (wallet-tx-debit wallet (wallet-tx-tx wtx))))))

(defun wallet-tx-credit (wallet wtx)
  "receive.cpp CachedTxGetCredit: 0 for an immature coinbase, else the
cached TxGetCredit."
  (if (wallet-tx-immature-coinbase-p wallet wtx)
      0
      (or (wallet-tx-cached-credit wtx)
          (setf (wallet-tx-cache-empty wtx) nil
                (wallet-tx-cached-credit wtx)
                (wallet-tx-credit-raw wallet (wallet-tx-tx wtx))))))

(defun wallet-tx-from-me-cached (wallet wtx)
  "receive.cpp CachedTxIsFromMe."
  (if (eq (wallet-tx-cached-from-me wtx) :unknown)
      (setf (wallet-tx-cached-from-me wtx)
            (wallet-tx-from-me-p wallet (wallet-tx-tx wtx)))
      (wallet-tx-cached-from-me wtx)))

(defun %wallet-output-change-p (wallet output)
  "receive.cpp ScriptIsChange heuristic: IsMine but not in the address book
(change-only book records don't count — allow_change=false lookup)."
  (let ((script (bl.ser:tx-out-script-pubkey output)))
    (and (%wallet-script-mine-p wallet script)
         (let ((address (bl.rpc:script->address script (wallet-network wallet))))
           (or (null address)
               (not (nth-value 2 (wallet-find-address-book-entry wallet address))))))))

(defun wallet-tx-get-change (wallet wtx)
  "receive.cpp CachedTxGetChange: cached Σ change-output values."
  (or (wallet-tx-cached-change wtx)
      (setf (wallet-tx-cached-change wtx)
            (reduce #'+ (bl.ser:transaction-outputs
                         (wallet-tx-tx wtx))
                    :key (lambda (out)
                           (if (%wallet-output-change-p wallet out)
                               (bl.ser:tx-out-value out)
                               0))
                    :initial-value 0))))

;;; --- avoid_reuse spent-key tracking (wallet.cpp:993-1021,2863-2891) ---

(defun wallet-set-address-previously-spent (wallet address used &key batch)
  "Core SetAddressPreviouslySpent + WriteAddressPreviouslySpent: flag the
address-book record and write (or erase) its destdata \"used\" record."
  (setf (addr-book-entry-previously-spent (%wallet-book-entry wallet address))
        (and used t))
  (let ((key (wdb-key-destdata address "used")))
    (cond ((not used)
           (bl.store:leveldb-delete (wallet-db wallet) key))
          (batch
           (bl.store:leveldb-writebatch-put
            batch key (wdb-string-value "1")))
          (t
           (bl.store:leveldb-put (wallet-db wallet) key
                                             (wdb-string-value "1"))))))

(defun wallet-address-previously-spent-p (wallet address)
  "Core IsAddressPreviouslySpent."
  (let ((entry (gethash address (wallet-address-book wallet))))
    (and entry (addr-book-entry-previously-spent entry) t)))

(defun wallet-spent-key-script-p (wallet script)
  "Core CWallet::IsSpentKey on a scriptPubKey. DIVERGENCE (cosmetic): only
address-representable scripts are tracked; Core additionally keys bare
pubkey/nonstandard destinations whose encoded form can never be spent to
again anyway."
  (let ((address (bl.rpc:script->address script (wallet-network wallet))))
    (and address (wallet-address-previously-spent-p wallet address))))

(defun %wallet-set-spent-key-state (wallet batch txid n used tx-destinations)
  "Core CWallet::SetSpentKeyState: when the outpoint is a wallet tx's IsMine
output, record its address as previously spent; newly-flagged addresses
collect into TX-DESTINATIONS (an equal-set of address strings)."
  (let ((srctx (wallet-get-wallet-tx wallet txid)))
    (when (and srctx
               (< n (length (bl.ser:transaction-outputs
                             (wallet-tx-tx srctx)))))
      (let* ((script (bl.ser:tx-out-script-pubkey
                      (aref (bl.ser:transaction-outputs
                             (wallet-tx-tx srctx))
                            n)))
             (address (bl.rpc:script->address script (wallet-network wallet))))
        (when (and address (%wallet-script-mine-p wallet script))
          (unless (eq (and used t)
                      (wallet-address-previously-spent-p wallet address))
            (when used
              (setf (gethash address tx-destinations) t))
            (wallet-set-address-previously-spent wallet address used
                                                 :batch batch)))))))

(defun wallet-mark-destinations-dirty (wallet tx-destinations)
  "Core CWallet::MarkDestinationsDirty: break the caches of every wallet tx
paying one of TX-DESTINATIONS (address-string set)."
  (when (plusp (hash-table-count tx-destinations))
    (loop for wtx being the hash-values of (wallet-map-wallet wallet)
          do (unless (wallet-tx-cache-empty wtx)
               (loop for output across (bl.ser:transaction-outputs
                                        (wallet-tx-tx wtx))
                     for address = (bl.rpc:script->address
                                    (bl.ser:tx-out-script-pubkey
                                     output)
                                    (wallet-network wallet))
                     do (when (and address (gethash address tx-destinations))
                          (wtx-mark-dirty wtx)
                          (return)))))))

(defun %wallet-tx-trusted-p (wallet wtx &optional (trusted-parents
                                                   (make-hash-table :test 'equalp)))
  "receive.cpp CachedTxIsTrusted (m_spend_zero_conf_change defaults true)."
  (let ((txid (wallet-tx-txid wtx)))
    (cond
      ((gethash txid trusted-parents) t)
      ((eq (wallet-tx-state wtx) :confirmed) t)
      ((eq (wallet-tx-state wtx) :block-conflicted) nil)
      ((not (wallet-tx-from-me-cached wallet wtx)) nil)
      ((not (eq (wallet-tx-state wtx) :in-mempool)) nil)
      (t
       (block check-parents
         (bl.ser:dovector
             (input (bl.ser:transaction-inputs
                     (wallet-tx-tx wtx)))
           (let* ((prevout (bl.ser:tx-in-previous-output input))
                  (parent (wallet-get-wallet-tx
                           wallet (bl.ser:outpoint-hash prevout))))
             (unless parent (return-from check-parents nil))
             (let ((parent-out
                     (aref (bl.ser:transaction-outputs
                            (wallet-tx-tx parent))
                           (bl.ser:outpoint-index prevout))))
               (unless (%wallet-script-mine-p
                        wallet (bl.ser:tx-out-script-pubkey
                                parent-out))
                 (return-from check-parents nil)))
             (unless (gethash (wallet-tx-txid parent) trusted-parents)
               (unless (%wallet-tx-trusted-p wallet parent trusted-parents)
                 (return-from check-parents nil))
               (setf (gethash (wallet-tx-txid parent) trusted-parents) t))))
         t)))))

(defun wallet-tx-conflicts (wallet wtx)
  "Core GetTxConflicts: other wallet txids spending any of WTX's prevouts."
  (let ((txid (wallet-tx-txid wtx))
        (result '()))
    (bl.ser:dovector
        (input (bl.ser:transaction-inputs (wallet-tx-tx wtx)))
      (let* ((prevout (bl.ser:tx-in-previous-output input))
             (key (%wtx-outpoint-key
                   (bl.ser:outpoint-hash prevout)
                   (bl.ser:outpoint-index prevout)))
             (spenders (gethash key (wallet-tx-spends wallet))))
        (when (> (length spenders) 1)
          (dolist (spender spenders)
            (unless (equalp spender txid)
              (pushnew spender result :test #'equalp))))))
    result))

;;; --- ComputeTimeSmart (wallet.cpp:2812) ---

(defun %compute-time-smart (wallet wtx rescanning block-time)
  "BLOCK-TIME is the containing block's timestamp (NIL for stateless adds).
DIVERGENCE: for rescanned old blocks Core uses the chain's max-time-so-far
at the block; we use the block's own time (no nTimeMax tracking) — cosmetic
ordering of same-block historical txs."
  (let ((received (wallet-tx-time-received wtx)))
    (cond
      ((null block-time) received)
      (rescanning block-time)
      (t (let ((latest-now received)
               (latest-entry 0)
               (latest-tolerated (+ received 300))
               (ordered (wallet-tx-ordered wallet)))
           (loop for i from (1- (fill-pointer ordered)) downto 0
                 for pwtx = (aref ordered i)
                 unless (eq pwtx wtx)
                   do (let ((smart (let ((ts (wallet-tx-time-smart pwtx)))
                                     (if (plusp ts) ts
                                         (wallet-tx-time-received pwtx)))))
                        (when (<= smart latest-tolerated)
                          (setf latest-entry smart)
                          (when (> smart latest-now)
                            (setf latest-now smart))
                          (return))))
           (max latest-entry (min block-time latest-now)))))))

;;; --- AddToWallet (wallet.cpp:1025) ---

(defun %wallet-abandon-coinbase-cascade (wallet wtx batch)
  "Mark an inactive coinbase and its wallet descendants abandoned
(AddToWallet's while-loop, wallet.cpp:1082-1106)."
  (let ((stack (list wtx)))
    (loop while stack
          do (let ((desc (pop stack)))
               (%wtx-apply-state desc :inactive nil -1 -1 t)
               (wtx-mark-dirty desc)
               (wallet-write-tx wallet desc :batch batch)
               (wallet-mark-inputs-dirty wallet (wallet-tx-tx desc))
               (dotimes (i (length (bl.ser:transaction-outputs
                                    (wallet-tx-tx desc))))
                 (dolist (spender (gethash (%wtx-outpoint-key
                                            (wallet-tx-txid desc) i)
                                           (wallet-tx-spends wallet)))
                   (let ((child (wallet-get-wallet-tx wallet spender)))
                     (when child (push child stack)))))))))

(defun wallet-add-to-wallet (wallet tx state &key rescanning block-time map-value)
  "Core CWallet::AddToWallet: insert or update the wallet tx for TX with
STATE (a state list), persist, refresh the TXO cache. Returns the wallet-tx.
MAP-VALUE seeds a freshly-inserted wtx's user mapValue pairs — the
CommitTransaction update callback (wallet.cpp:2464-2472); ignored on update,
where Core asserts the existing mapValue is what it keeps."
  (let* ((txid (bl.ser:transaction-hash tx))
         (existing (wallet-get-wallet-tx wallet txid))
         (wtx (or existing (make-wallet-tx :tx tx :txid txid)))
         (inserted (not existing))
         (updated nil))
    (when (and inserted map-value)
      (setf (wallet-tx-map-value wtx) map-value))
    (bl.store:with-leveldb-writebatch (batch)
      ;; WALLET_FLAG_AVOID_REUSE: destinations this tx spends from become
      ;; previously-spent; txs paying newly-flagged destinations lose their
      ;; caches (wallet.cpp:1032-1042).
      (when (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+)
        (let ((tx-destinations (make-hash-table :test 'equal)))
          (bl.ser:dovector
              (input (bl.ser:transaction-inputs tx))
            (let ((prevout (bl.ser:tx-in-previous-output input)))
              (%wallet-set-spent-key-state
               wallet batch
               (bl.ser:outpoint-hash prevout)
               (bl.ser:outpoint-index prevout)
               t tx-destinations)))
          ;; The batch below only commits on inserted/updated; a queued
          ;; previously-spent record must land regardless (Core's batch
          ;; commits unconditionally on destruction).
          (when (plusp (hash-table-count tx-destinations))
            (setf updated t))
          (wallet-mark-destinations-dirty wallet tx-destinations)))
      (when inserted
        (%wtx-apply-state-list wtx state)
        (setf (gethash txid (wallet-map-wallet wallet)) wtx)
        (setf (wallet-tx-time-received wtx)
              (bl.ser:get-unix-time))
        (setf (wallet-tx-order-pos wtx) (wallet-inc-order-pos-next wallet batch))
        (%wallet-tx-ordered-insert wallet wtx)
        (setf (wallet-tx-time-smart wtx)
              (%compute-time-smart wallet wtx rescanning block-time))
        (wallet-add-to-spends wallet wtx)
        (wallet-maybe-update-birth-time wallet (wallet-tx-get-time wtx)))
      (unless inserted
        (if (not (eq (first state) (wallet-tx-state wtx)))
            (progn (%wtx-apply-state-list wtx state)
                   (setf updated t))
            ;; Same state kind: the serialized forms must already agree
            ;; (Core asserts; we log instead of taking the node down).
            (multiple-value-bind (old-hash old-index) (%wtx-serialized-state wtx)
              (let ((probe (make-wallet-tx :tx tx :txid txid)))
                (%wtx-apply-state-list probe state)
                (multiple-value-bind (new-hash new-index)
                    (%wtx-serialized-state probe)
                  (unless (and (equalp old-hash new-hash)
                               (= old-index new-index))
                    (bl:log-warn
                     "AddToWallet: same-kind state mismatch for ~A (kept existing)"
                     (bl.rpc:hash-to-hex txid)))))))
        ;; Witness upgrade: replace a stored witness-stripped version.
        (when (and (bl.ser:transaction-has-witness-p tx)
                   (not (bl.ser:transaction-has-witness-p
                         (wallet-tx-tx wtx))))
          (setf (wallet-tx-tx wtx) tx)
          (setf updated t)))
      ;; Inactive coinbases (and their descendants) are abandoned.
      (when (and (%wtx-coinbase-p wtx) (eq (wallet-tx-state wtx) :inactive))
        (%wallet-abandon-coinbase-cascade wallet wtx batch)
        (setf updated t))
      (when (or inserted updated)
        (wallet-write-tx wallet wtx :batch batch)
        (bl.store:leveldb-write (wallet-db wallet) batch :sync t)))
    ;; Break debit/credit balance caches (wallet.cpp:1117).
    (wtx-mark-dirty wtx)
    (wallet-refresh-txos wallet wtx)
    (%run-wallet-notify wallet wtx)
    wtx))

(defun %run-wallet-notify (wallet wtx)
  "Fire -walletnotify for WTX (Core wallet.cpp:1125-1150).

Unconditional, exactly as Core's is: the hook sits OUTSIDE the
inserted-or-updated branch, so a transaction re-seen in the same state still
notifies. %s is the txid, %w the wallet name, and %b/%h the confirming block or
the literal \"unconfirmed\"/-1."
  (let ((command *wallet-notify-command*))
    (when command
      (multiple-value-bind (block-hash height)
          (if (eq (wallet-tx-state wtx) :confirmed)
              (values (bl.rpc:hash-to-hex (wallet-tx-block-hash wtx))
                      (princ-to-string (wallet-tx-block-height wtx)))
              (values "unconfirmed" "-1"))
        (bl:run-notify-command
         command
         :substitutions (list (cons #\s (bl.rpc:hash-to-hex (wallet-tx-txid wtx)))
                              (cons #\w (wallet-name wallet))
                              (cons #\b block-hash)
                              (cons #\h height)))))))

;;; --- Keypool advance on observed use (scriptpubkeyman.cpp:1066) ---

(defun spkm-mark-unused-addresses (wallet spkm script)
  "Core DescriptorScriptPubKeyMan::MarkUnusedAddresses: when SCRIPT sits at
or past the keypool cursor, every index up to it is marked used —
next_index advances past it and TopUp (which persists) refills the window.
Returns the newly-marked addresses."
  (let ((index (spkm-is-mine spkm script))
        (result '()))
    (when index
      (when (>= index (desc-spkm-next-index spkm))
        (loop while (>= index (desc-spkm-next-index spkm))
              do (let ((scripts (bl.rpc:out-desc-expand-from-cache
                                 (desc-spkm-desc spkm)
                                 (desc-spkm-next-index spkm)
                                 (desc-spkm-cache spkm))))
                   (unless scripts
                     (wallet-error "MarkUnusedAddresses: unable to expand descriptor from cache"))
                   (let ((address (bl.rpc:script->address (first scripts)
                                                    (wallet-network wallet))))
                     (when address (push address result)))
                   (incf (desc-spkm-next-index spkm)))))
      (spkm-top-up wallet spkm))
    (nreverse result)))

;;; --- AddToWalletIfInvolvingMe / SyncTransaction (wallet.cpp:1190,1402) ---

(defun wallet-add-to-wallet-if-involving-me (wallet tx state
                                             &key (update t) rescanning
                                                  block-time)
  (let ((txid (bl.ser:transaction-hash tx)))
    ;; A confirmed tx marks every OTHER wallet tx spending the same prevouts
    ;; block-conflicted — runs for ALL block txs, ours or not.
    (when (eq (first state) :confirmed)
      (destructuring-bind (block-hash height index) (rest state)
        (declare (ignore index))
        (bl.ser:dovector
            (input (bl.ser:transaction-inputs tx))
          (let* ((prevout (bl.ser:tx-in-previous-output input))
                 (key (%wtx-outpoint-key
                       (bl.ser:outpoint-hash prevout)
                       (bl.ser:outpoint-index prevout))))
            (dolist (spender (gethash key (wallet-tx-spends wallet)))
              (unless (equalp spender txid)
                (bl:log-info
                 "Wallet ~A: tx ~A in block ~A conflicts with wallet tx ~A"
                 (wallet-name wallet) (bl.rpc:hash-to-hex txid)
                 (bl.rpc:hash-to-hex block-hash) (bl.rpc:hash-to-hex spender))
                (wallet-mark-conflicted wallet block-hash height spender)))))))
    (let ((existed (and (wallet-get-wallet-tx wallet txid) t)))
      (cond
        ((and existed (not update)) nil)
        ((or existed
             (%wallet-tx-any-output-mine-p wallet tx)
             (wallet-tx-from-me-p wallet tx))
         ;; Keypool items that turn out used (e.g. restored backup) advance
         ;; next_index; fresh external receiving addresses join the book.
         (bl.ser:dovector
             (output (bl.ser:transaction-outputs tx))
           (let ((script (bl.ser:tx-out-script-pubkey output)))
             (loop for spkm being the hash-values of (wallet-spkms wallet)
                   do (when (spkm-is-mine spkm script)
                        (let ((dests (spkm-mark-unused-addresses wallet spkm script)))
                          (multiple-value-bind (active internal)
                              (%spkm-active-info wallet spkm)
                            ;; internal is inferable only for active SPKMs
                            ;; (Core skips destinations it can't classify).
                            (when (and active (not internal))
                              (dolist (address dests)
                                (unless (nth-value 2 (wallet-find-address-book-entry
                                                      wallet address))
                                  (wallet-write-address-book-entry
                                   wallet address "" "receive"))))))))))
         (wallet-add-to-wallet wallet tx state :rescanning rescanning
                                               :block-time block-time)
         t)))))

(defun wallet-sync-transaction (wallet tx state &key (update t) rescanning
                                                     block-time)
  "Core CWallet::SyncTransaction. Returns T when TX is (now) a wallet tx;
a state change alters the balance available of the outputs it spends, so
their caches are broken (MarkInputsDirty)."
  (when (wallet-add-to-wallet-if-involving-me wallet tx state
                                              :update update
                                              :rescanning rescanning
                                              :block-time block-time)
    (wallet-mark-inputs-dirty wallet tx)
    t))

;;; --- Conflict tracking (wallet.cpp:1328,1363) ---

(defun wallet-recursive-update-tx-state (wallet txid update-fn &key (write t))
  "Core RecursiveUpdateTxState: apply UPDATE-FN (wtx -> :changed | :unchanged)
to TXID's wallet tx and, transitively, to every wallet tx spending a changed
tx's outputs. WRITE persists changed txs (Core's batch variant); the
mempool-conflicts bookkeeping passes NIL (Core passes a null batch)."
  (let ((todo (list txid))
        (done (make-hash-table :test 'equalp)))
    (loop while todo
          do (let ((now (pop todo)))
               (unless (gethash now done)
                 (setf (gethash now done) t)
                 (let ((wtx (wallet-get-wallet-tx wallet now)))
                   (when (and wtx
                              (not (eq (funcall update-fn wtx) :unchanged)))
                     (wtx-mark-dirty wtx)
                     (when write (wallet-write-tx wallet wtx))
                     (dotimes (i (length (bl.ser:transaction-outputs
                                          (wallet-tx-tx wtx))))
                       (dolist (spender (gethash (%wtx-outpoint-key now i)
                                                 (wallet-tx-spends wallet)))
                         (unless (gethash spender done)
                           (push spender todo))))
                     ;; A state change alters the balance available of the
                     ;; outputs this tx spends (Core RecursiveUpdateTxState).
                     (wallet-mark-inputs-dirty wallet (wallet-tx-tx wtx)))))))))

(defun wallet-mark-conflicted (wallet block-hash conflicting-height txid)
  "Core CWallet::MarkConflicted: mark TXID (and its wallet descendants)
conflicted by the block at CONFLICTING-HEIGHT, when that is deeper than
their current state."
  ;; Without a processed chain (wallet loading before any chain attach) the
  ;; conflict depth cannot be computed — do nothing (Core's
  ;; m_last_block_processed_height < 0 guard).
  (when (and (wallet-last-block-hash wallet) (>= conflicting-height 0))
    (let ((conflict-confirms (- (1+ (- (wallet-last-block-height wallet)
                                       conflicting-height)))))
      (when (minusp conflict-confirms)
        (wallet-recursive-update-tx-state
         wallet txid
         (lambda (wtx)
           (if (< conflict-confirms (wallet-tx-depth wallet wtx))
               (progn (%wtx-apply-state wtx :block-conflicted block-hash
                                        conflicting-height)
                      :changed)
               :unchanged)))))))

(defun wallet-abandon-transaction (wallet wtx)
  "Core CWallet::AbandonTransaction: mark WTX and its wallet descendants
abandoned. Only valid for txs neither confirmed/conflicted nor in the
mempool; returns T on success."
  (if (or (/= 0 (wallet-tx-depth wallet wtx))
          (eq (wallet-tx-state wtx) :in-mempool))
      nil
      (progn
        (wallet-recursive-update-tx-state
         wallet (wallet-tx-txid wtx)
         (lambda (w)
           (if (or (eq (wallet-tx-state w) :block-conflicted)
                   (%wtx-abandoned-p w))
               :unchanged
               (progn (%wtx-apply-state w :inactive nil -1 -1 t)
                      :changed))))
        t)))

;;; --- Notification handlers (wallet.cpp:1414,1457,1526,1555) ---

(defun %wallet-refresh-mempool-status (wallet wtx mempool)
  "Core RefreshMempoolStatus (wallet.cpp:142): in-memory only, no disk write
— InMempool serializes as Inactive anyway."
  (declare (ignore wallet))
  (cond ((and mempool (bl.mp:mempool-has
                       mempool (wallet-tx-txid wtx)))
         (%wtx-apply-state wtx :in-mempool))
        ((eq (wallet-tx-state wtx) :in-mempool)
         (%wtx-apply-state wtx :inactive))))

(defun %wallet-update-truc-sibling-conflicts (wallet parent-wtx child-txid add)
  "Core UpdateTrucSiblingConflicts: TRUC policy admits one unconfirmed child
per parent, so other spenders of the parent's outputs are mempool-conflicted
by CHILD-TXID (or released when it leaves)."
  (dotimes (i (length (bl.ser:transaction-outputs
                       (wallet-tx-tx parent-wtx))))
    (dolist (sibling (gethash (%wtx-outpoint-key (wallet-tx-txid parent-wtx) i)
                              (wallet-tx-spends wallet)))
      (unless (equalp sibling child-txid)
        (wallet-recursive-update-tx-state
         wallet sibling
         (lambda (wtx)
           (let ((set (wallet-tx-mempool-conflicts wtx)))
             (if add
                 (if (gethash child-txid set)
                     :unchanged
                     (progn (setf (gethash child-txid set) t) :changed))
                 (if (remhash child-txid set) :changed :unchanged))))
         :write nil)))))

(defun wallet-transaction-added-to-mempool (wallet mempool tx)
  "Core CWallet::transactionAddedToMempool."
  (with-wallet-lock (wallet)
    (wallet-sync-transaction wallet tx '(:in-mempool))
    (let* ((txid (bl.ser:transaction-hash tx))
           (wtx (wallet-get-wallet-tx wallet txid)))
      (when wtx
        (%wallet-refresh-mempool-status wallet wtx mempool))
      ;; Wallet txs spending the same prevouts are now mempool-conflicted.
      (bl.ser:dovector
          (input (bl.ser:transaction-inputs tx))
        (let* ((prevout (bl.ser:tx-in-previous-output input))
               (key (%wtx-outpoint-key
                     (bl.ser:outpoint-hash prevout)
                     (bl.ser:outpoint-index prevout))))
          (dolist (spender (gethash key (wallet-tx-spends wallet)))
            (unless (equalp spender txid)
              (wallet-recursive-update-tx-state
               wallet spender
               (lambda (w)
                 (let ((set (wallet-tx-mempool-conflicts w)))
                   (if (gethash txid set)
                       :unchanged
                       (progn (setf (gethash txid set) t) :changed))))
               :write nil)))))
      ;; TRUC: remember the one unconfirmed child; its siblings conflict.
      (when (= (bl.ser:transaction-version tx)
               bl.mp:+truc-version+)
        (bl.ser:dovector
            (input (bl.ser:transaction-inputs tx))
          (let* ((prevout (bl.ser:tx-in-previous-output input))
                 (parent (wallet-get-wallet-tx
                          wallet (bl.ser:outpoint-hash prevout))))
            (when (and parent (%wtx-unconfirmed-p parent))
              (setf (wallet-tx-truc-child parent) txid)
              (%wallet-update-truc-sibling-conflicts wallet parent txid t))))))))

(defun wallet-transaction-removed-from-mempool (wallet mempool tx reason)
  "Core CWallet::transactionRemovedFromMempool."
  (with-wallet-lock (wallet)
    (let* ((txid (bl.ser:transaction-hash tx))
           (wtx (wallet-get-wallet-tx wallet txid)))
      (when wtx
        (%wallet-refresh-mempool-status wallet wtx mempool))
      ;; Removed for conflicting with a newly connected block: mark it
      ;; UNCONFIRMED, not conflicted — the blockConnected handler's own
      ;; conflict detection upgrades it to BlockConflicted where applicable
      ;; (Core's longstanding heuristic, wallet.cpp:1463-1491).
      (when (eq reason :conflict)
        (wallet-sync-transaction wallet tx '(:inactive)))
      ;; The departed tx no longer mempool-conflicts anything.
      (bl.ser:dovector
          (input (bl.ser:transaction-inputs tx))
        (let* ((prevout (bl.ser:tx-in-previous-output input))
               (key (%wtx-outpoint-key
                     (bl.ser:outpoint-hash prevout)
                     (bl.ser:outpoint-index prevout))))
          (dolist (spender (gethash key (wallet-tx-spends wallet)))
            (wallet-recursive-update-tx-state
             wallet spender
             (lambda (w)
               (if (remhash txid (wallet-tx-mempool-conflicts w))
                   :changed
                   :unchanged))
             :write nil))))
      (when (= (bl.ser:transaction-version tx)
               bl.mp:+truc-version+)
        (bl.ser:dovector
            (input (bl.ser:transaction-inputs tx))
          (let* ((prevout (bl.ser:tx-in-previous-output input))
                 (parent (wallet-get-wallet-tx
                          wallet (bl.ser:outpoint-hash prevout))))
            (when (and parent
                       (equalp (wallet-tx-truc-child parent) txid))
              (setf (wallet-tx-truc-child parent) nil)
              (%wallet-update-truc-sibling-conflicts wallet parent txid nil))))))))

(defun %wallet-chain-locator (chain-state block-hash)
  "Exponential step-back locator for BLOCK-HASH (Core GetLocator), or the
single-hash fallback when the entry is unknown."
  (let ((entry (and chain-state
                    (bl.store:get-block-index-entry chain-state
                                                                block-hash))))
    (if entry
        (bl.store:build-block-locator chain-state entry)
        (list block-hash))))

(defun wallet-block-connected (wallet mempool chain-state block block-hash height)
  "Core CWallet::blockConnected."
  (with-wallet-lock (wallet)
    ;; Best block in memory first — MarkConflicted needs the height.
    (setf (wallet-last-block-hash wallet) block-hash
          (wallet-last-block-height wallet) height)
    (let ((block-time (bl.ser:block-header-timestamp
                       (bl.ser:bitcoin-block-header block))))
      ;; Core SetLastBlockProcessed's m_best_block_time — the rebroadcast
      ;; filter's reference clock (wallet P4).
      (setf (wallet-last-block-time wallet) block-time)
      ;; Birthday gate over a wallet-side running max of processed block
      ;; times (over-approximates Core's per-block nTimeMax — see the
      ;; divergence note at the top of this file).
      (setf (wallet-chain-time-max wallet)
            (max (wallet-chain-time-max wallet) block-time))
      (when (< (wallet-chain-time-max wallet)
               (- (wallet-birth-time wallet) (* 2 +wallet-timestamp-window+)))
        (return-from wallet-block-connected))
      (let ((wallet-updated nil))
        (loop for tx in (bl.ser:bitcoin-block-transactions block)
              for index from 0
              do (when (wallet-sync-transaction
                        wallet tx (list :confirmed block-hash height index)
                        :block-time block-time)
                   (setf wallet-updated t))
                 (wallet-transaction-removed-from-mempool wallet mempool tx :block))
        ;; Persist the locator when a wallet tx changed, or once a day.
        (when (or wallet-updated
                  (zerop (mod height +wallet-best-block-cadence+)))
          (wallet-write-best-block wallet
                                   (%wallet-chain-locator chain-state
                                                          block-hash)))))))

(defun wallet-block-disconnected (wallet block height)
  "Core CWallet::blockDisconnected."
  (with-wallet-lock (wallet)
    (loop for tx in (bl.ser:bitcoin-block-transactions block)
          for index from 0
          ;; A disconnected coinbase is not just inactive but abandoned —
          ;; it can never be relayed standalone.
          do (wallet-sync-transaction wallet tx (list :inactive (zerop index)))
             ;; Wallet txs the disconnected tx had conflicted-out revert to
             ;; unconfirmed when their conflicting block is at/above the
             ;; disconnect height.
             (bl.ser:dovector
                 (input (bl.ser:transaction-inputs tx))
               (let* ((prevout (bl.ser:tx-in-previous-output input))
                      (key (%wtx-outpoint-key
                            (bl.ser:outpoint-hash prevout)
                            (bl.ser:outpoint-index prevout))))
                 (dolist (spender (gethash key (wallet-tx-spends wallet)))
                   (let ((wtx (wallet-get-wallet-tx wallet spender)))
                     (when (and wtx (eq (wallet-tx-state wtx) :block-conflicted))
                       (wallet-recursive-update-tx-state
                        wallet spender
                        (lambda (w)
                          (if (and (eq (wallet-tx-state w) :block-conflicted)
                                   (>= (wallet-tx-block-height w) height))
                              (progn (%wtx-apply-state w :inactive) :changed)
                              :unchanged)))))))))
    (setf (wallet-last-block-hash wallet)
          (bl.ser:block-header-prev-block
           (bl.ser:bitcoin-block-header block))
          (wallet-last-block-height wallet) (1- height))))

;;; --- Manager fan-outs (called by node/wallet-hooks.lisp's wallet-notify-* hooks) ---

(defun %manager-wallets (manager)
  "The loaded wallets, in load order — the manager's immutable lock-free
snapshot. Deliberately does NOT take the manager lock: fan-outs run from
hook contexts that may already hold a wallet lock, and the only lock order
involving the manager is manager -> wallet (see wallet-manager)."
  (wallet-manager-wallet-snapshot manager))

(defmacro %do-fanout-wallets ((wallet manager what) &body body)
  "Iterate the manager's wallet snapshot running BODY per wallet with
per-wallet error isolation: an unloaded wallet (db already closed by a
concurrent unloadwallet — Core's shared_ptr lifetime has no equivalent
here) is skipped, and one wallet's failure is logged loudly without
aborting delivery to the remaining wallets or the calling hook (the
divergence note at the top of this file: hook failures never take the
node down)."
  `(dolist (,wallet (%manager-wallets ,manager))
     (handler-case
         (when (wallet-db ,wallet)
           ,@body)
       (error (e)
         (bl:log-error "Wallet ~A: ~A hook failed: ~A"
                                 (wallet-name ,wallet) ,what e)))))

(defun wallets-block-connected (manager mempool chain-state block block-hash height)
  (%do-fanout-wallets (wallet manager "block-connected")
    (wallet-block-connected wallet mempool chain-state block block-hash height)))

(defun wallets-block-disconnected (manager block height)
  (%do-fanout-wallets (wallet manager "block-disconnected")
    (wallet-block-disconnected wallet block height)))

(defun wallets-mempool-tx-added (manager mempool tx)
  (%do-fanout-wallets (wallet manager "mempool-tx-added")
    (wallet-transaction-added-to-mempool wallet mempool tx)))

(defun wallets-mempool-tx-removed (manager mempool tx reason)
  (%do-fanout-wallets (wallet manager "mempool-tx-removed")
    (wallet-transaction-removed-from-mempool wallet mempool tx reason)))

;;; --- Load-time tx record replay (walletdb.cpp LoadTxRecords + LoadToWallet) ---

(defun %wtx-update-state-from-chain (wtx chain-state)
  "CWalletTx::updateState: resolve the stored block hash against the active
chain — fill the height, or demote to inactive when the block was reorged
away while the wallet was closed."
  (when (member (wallet-tx-state wtx) '(:confirmed :block-conflicted))
    (let ((entry (bl.store:get-block-index-entry
                  chain-state (wallet-tx-block-hash wtx))))
      (if (and entry (bl.store:entry-on-active-chain-p chain-state entry))
          (setf (wallet-tx-block-height wtx)
                (bl.store:block-index-entry-height entry))
          (%wtx-apply-state wtx :inactive)))))

(defun wallet-load-tx-records (wallet tx-records chain-state warnings)
  "Replay the stored CWalletTx records into mapWallet (Core LoadTxRecords +
LoadToWallet). TX-RECORDS is (txid . value-bytes) pairs. Returns WARNINGS."
  (let ((any-unordered nil))
    (dolist (rec tx-records)
      (destructuring-bind (txid . value) rec
        (multiple-value-bind (wtx state-warning)
            (handler-case (parse-wallet-tx-record value)
              (error (e)
                (push (format nil "Error reading wallet tx record: ~A" e)
                      warnings)
                nil))
          (when state-warning (push state-warning warnings))
          (when wtx
            (cond
              ((not (equalp (wallet-tx-txid wtx) txid))
               (push "Wallet tx record hash mismatch; record skipped (rescan to recover)"
                     warnings))
              ((wallet-get-wallet-tx wallet txid)
               (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                                 :message "Error: Corrupt transaction found. This can be fixed by removing transactions from wallet and rescanning."))
              (t
               (when chain-state
                 (%wtx-update-state-from-chain wtx chain-state))
               (setf (gethash txid (wallet-map-wallet wallet)) wtx)
               (when (= (wallet-tx-order-pos wtx) -1)
                 (setf any-unordered t))
               (wallet-add-to-spends wallet wtx)
               ;; A parent already loaded as block-conflicted conflicts its
               ;; spenders too (LoadToWallet, wallet.cpp:1172-1180; no-op
               ;; until a chain height is known, like Core pre-AttachChain).
               (bl.ser:dovector
                   (input (bl.ser:transaction-inputs
                           (wallet-tx-tx wtx)))
                 (let ((prev (wallet-get-wallet-tx
                              wallet
                              (bl.ser:outpoint-hash
                               (bl.ser:tx-in-previous-output input)))))
                   (when (and prev (eq (wallet-tx-state prev) :block-conflicted))
                     (wallet-mark-conflicted wallet
                                             (wallet-tx-block-hash prev)
                                             (wallet-tx-block-height prev)
                                             txid))))
               (wallet-maybe-update-birth-time wallet (wallet-tx-get-time wtx))
               (wallet-refresh-txos wallet wtx)))))))
    ;; Rebuild wtxOrdered: ascending nOrderPos, unordered records (foreign
    ;; wallets only — we always persist an order pos) appended and assigned
    ;; fresh positions (a simplification of Core's ReorderTransactions).
    (let ((wtxs (sort (alexandria:hash-table-values (wallet-map-wallet wallet))
                      (lambda (a b)
                        (let ((pa (wallet-tx-order-pos a))
                              (pb (wallet-tx-order-pos b)))
                          (cond ((= pa -1) nil)
                                ((= pb -1) t)
                                (t (< pa pb))))))))
      (setf (fill-pointer (wallet-tx-ordered wallet)) 0)
      (dolist (wtx wtxs)
        (when (and any-unordered (= (wallet-tx-order-pos wtx) -1))
          (setf (wallet-tx-order-pos wtx) (wallet-inc-order-pos-next wallet))
          (wallet-write-tx wallet wtx))
        (%wallet-tx-ordered-insert wallet wtx)))
    ;; Coinbases no longer in the active chain are abandoned (LoadTxRecords,
    ;; walletdb.cpp:1060-1066).
    (loop for wtx being the hash-values of (wallet-map-wallet wallet)
          do (when (and (%wtx-coinbase-p wtx)
                        (eq (wallet-tx-state wtx) :inactive))
               (wallet-abandon-transaction wallet wtx)))
    warnings))

;;; --- Rescanning (wallet.cpp:1813,1857 + AttachChain:3171) ---

(defconstant +rescan-segment-blocks+ 100
  "Blocks scanned per node-lock hold. Core scans block-at-a-time under
cs_main; segments amortize our O(tip) active-chain walks while keeping each
lock hold short.")

(defun wallet-reserve-rescan (wallet)
  "Reserve the wallet's single rescan slot (Core WalletRescanReserver).
Returns NIL when a rescan is already running."
  (with-wallet-lock (wallet)
    (if (wallet-scanning-since wallet)
        nil
        (progn (setf (wallet-scanning-since wallet)
                     (bl.ser:get-unix-time)
                     (wallet-abort-rescan wallet) nil
                     (wallet-scan-progress wallet) 0.0)
               t))))

(defun wallet-release-rescan (wallet)
  "End a rescan: drop the scan marker, clear the passphrase hold the scan put
on the relock deadline, and apply that deadline now. Core's scheduled relock
fires regardless of a scan (wallet/rpc/encrypt.cpp:102-110); ours suspends the
deadline for the scan's duration so its keypool top-ups cannot fail mid-scan
(see WALLET-UNLOCKED-KEY), and this is the one place that suspension ends."
  (with-wallet-lock (wallet)
    (setf (wallet-scanning-since wallet) nil
          (wallet-scanning-with-passphrase wallet) nil)
    ;; For effect: relocks inline when the deadline passed during the scan.
    (wallet-unlocked-key wallet)))

(defun find-first-block-with-time (chain-state min-time min-height)
  "Core CChain::FindEarliestAtLeast (via findFirstBlockWithTimeAndHeight):
the first active-chain entry whose max-block-time-so-far reaches MIN-TIME
(ties broken by MIN-HEIGHT), or NIL. One O(tip) walk."
  (let ((tip-hash (bl.store:best-block-hash chain-state)))
    (when tip-hash
      (let ((entries '())
            (entry (bl.store:get-block-index-entry chain-state tip-hash)))
        (loop while entry
              do (push entry entries)
                 (setf entry (bl.store:block-index-entry-prev-entry entry)))
        (let ((time-max 0))
          (dolist (e entries)
            (let ((header (bl.store:block-index-entry-header e)))
              (when header
                (setf time-max
                      (max time-max
                           (bl.ser:block-header-timestamp header)))))
            (when (or (> time-max min-time)
                      (and (= time-max min-time)
                           (>= (bl.store:block-index-entry-height e)
                               min-height)))
              (return-from find-first-block-with-time e))))
        nil))))

(defun %entry-chain-time-max (chain-state block-hash)
  "Max block time over BLOCK-HASH's chain up to and including it (Core
CBlockIndex::GetBlockTimeMax). O(height); failure-path only."
  (let ((entry (bl.store:get-block-index-entry chain-state block-hash))
        (time-max 0))
    (loop while entry
          do (let ((header (bl.store:block-index-entry-header entry)))
               (when header
                 (setf time-max
                       (max time-max
                            (bl.ser:block-header-timestamp header)))))
             (setf entry (bl.store:block-index-entry-prev-entry entry)))
    time-max))

;;; --- Fast rescan via the BIP158 filter index (Core FastWalletRescanFilter) ---
;;;
;;; Core wallet.cpp:308-361. Skipping a block on a filter miss is sound because
;;; a BIP158 basic filter contains the scriptPubKeys of the block's outputs AND
;;; of every prevout it spends, while our wallet only ever recognises a tx via a
;;; script in some spkm's script-map (spkm-is-mine, wallet.lisp:398-401). So a
;;; block that pays us or spends from us necessarily names one of our scripts in
;;; its filter.

(defstruct (rescan-filter (:constructor %make-rescan-filter))
  "Query-element set for the fast rescan (Core FastWalletRescanFilter)."
  ;; GCS query elements: every script in the wallet's IsMine set.
  (scripts '() :type list)
  ;; Dedup across spkms (Core's ElementSet).
  (seen (make-hash-table :test 'equalp) :type hash-table)
  ;; spkm id -> the GetEndRange() we last folded in, for UpdateIfNeeded.
  (last-ends (make-hash-table :test 'equalp) :type hash-table))

(defun %spkm-end-range (spkm)
  "Core DescriptorScriptPubKeyMan::GetEndRange (scriptpubkeyman.cpp:1518-1521)
= m_max_cached_index + 1. NOT range-end and NOT next-index: only cached
scripts are in the IsMine map, so only they can be in the query set."
  (1+ (desc-spkm-max-cached-index spkm)))

(defun %rescan-filter-add-spkm (rf spkm min-index)
  "Fold SPKM's cached scripts at range index >= MIN-INDEX into RF (Core
AddScriptPubKeys + GetScriptPubKeys(minimum_index), scriptpubkeyman.cpp:1506)."
  (maphash (lambda (script index)
             (when (and (>= index min-index)
                        (not (gethash script (rescan-filter-seen rf))))
               (setf (gethash script (rescan-filter-seen rf)) t)
               (push script (rescan-filter-scripts rf))))
           (desc-spkm-script-map spkm)))

(defun %make-wallet-rescan-filter (wallet)
  "Build the query set from every spkm's IsMine script map (Core's ctor,
wallet.cpp:311-323). Ranged descriptors also record their end-range so
UpdateIfNeeded can fold in scripts a mid-rescan TopUp creates."
  (let ((rf (%make-rescan-filter)))
    (with-wallet-lock (wallet)
      (loop for spkm being the hash-values of (wallet-spkms wallet)
            do (%rescan-filter-add-spkm rf spkm 0)
               ;; Core guards this on IsHDEnabled() == descriptor IsRange()
               ;; (scriptpubkeyman.cpp:1162-1166): a non-ranged descriptor can
               ;; never grow, so it needs no re-poll.
               (when (bl.rpc:out-desc-ranged-p (desc-spkm-desc spkm))
                 (setf (gethash (desc-spkm-id spkm) (rescan-filter-last-ends rf))
                       (%spkm-end-range spkm)))))
    rf))

(defun %rescan-filter-update-if-needed (wallet rf)
  "Core UpdateIfNeeded (wallet.cpp:325-337): re-poll each ranged spkm's
end-range and fold in anything cached since. Called at the TOP of every block
iteration, so a TopUp triggered by block N-1 is in the set when block N is
matched."
  (with-wallet-lock (wallet)
    (loop for spkm being the hash-values of (wallet-spkms wallet)
          do (let ((previous (gethash (desc-spkm-id spkm) (rescan-filter-last-ends rf))))
               (when previous
                 (let ((current (%spkm-end-range spkm)))
                   (when (> current previous)
                     (%rescan-filter-add-spkm rf spkm previous)
                     (setf (gethash (desc-spkm-id spkm) (rescan-filter-last-ends rf))
                           current))))))))

(defun %rescan-filter-matches-block (bfi rf block-hash)
  "Match RF's script set against BLOCK-HASH's stored BASIC filter.
Returns :match, :no-match, or :unknown when no filter is stored for that block.

:unknown is the per-block fail-safe (Core blockFilterMatchesAny returning
nullopt, node/interfaces.cpp:583-584): the caller inspects the block. There is
deliberately NO whole-scan guard on the index's sync height — Core has none,
our index can legitimately contain holes below its best marker, and 'no filter
=> read the block' is already the safe direction."
  (let ((filter (bl.store:blockfilterindex-get-filter bfi block-hash)))
    (if filter
        (multiple-value-bind (k0 k1)
            (bl.store:block-filter-siphash-keys block-hash)
          (if (bl.store:gcs-filter-match-any
               filter k0 k1 (rescan-filter-scripts rf))
              :match
              :no-match))
        :unknown)))

(defun scan-for-wallet-transactions (node wallet start-hash start-height
                                     &key max-height (update t) save-progress)
  "Port of CWallet::ScanForWalletTransactions. Scans the active chain from
START-HASH/START-HEIGHT (to MAX-HEIGHT, else the tip), syncing every block's
txs into WALLET with :confirmed states; when scanning to the tip, the
mempool's txs are synced afterwards (Core requestMempoolTransactions).

Runs in segments of +rescan-segment-blocks+, each processed under one
node-lock hold (no reorg can interleave mid-segment; the segment start is
re-verified on the active chain after every release — Core's per-block
still-active check). The caller must hold the rescan reservation.

When the BIP158 filter index is available, blocks whose stored basic filter
does not match any of the wallet's scripts are SKIPPED without being read or
deserialized (Core's fast variant, wallet.cpp:1868-1914) — the difference
between hours and minutes on a birthday import. Results are identical; a block
with no stored filter is read as before.

Returns (values status last-scanned-height last-scanned-hash skipped-count),
STATUS one of :success / :failure (a block was unreadable or the chain moved
away) / :user-abort."
  (let ((status :success)
        (last-scanned-height nil)
        (last-scanned-hash nil)
        (height start-height)
        (block-hash start-hash)
        ;; Gate ONLY on the index existing and being enabled, exactly as Core
        ;; gates on hasBlockFilterIndex (wallet.cpp:1869). Never on its sync
        ;; height: the per-block :unknown fallback already covers a lagging or
        ;; gappy index, and a whole-scan guard would disable the fast path
        ;; whenever the index trails the tip by even one block.
        (bfi (let ((b (bl.rpc:rpc-get-blockfilterindex node)))
               (and b (bl.store:blockfilterindex-enabled b) b)))
        (rf nil)
        (skipped 0))
    (when bfi (setf rf (%make-wallet-rescan-filter wallet)))
    (bl:log-info "Wallet ~A: rescan started from height ~D (~A)"
                           (wallet-name wallet) start-height
                           (if rf
                               "fast variant using block filters"
                               "slow variant inspecting all blocks"))
    (block scan
      (loop
        (when (wallet-abort-rescan wallet)
          (setf status :user-abort)
          (return-from scan))
        (let ((done nil))
          (bl.rpc:with-node-lock (node)
            (let* ((chain-state (bl:node-current-chainstate node))
                   (store (bl:node-block-store node))
                   (entry (and chain-state
                               (bl.store:get-block-index-entry
                                chain-state block-hash))))
              (cond
                ((or (null chain-state) (null store) (null entry)
                     (not (bl.store:entry-on-active-chain-p
                           chain-state entry)))
                 ;; Segment start reorged away (or no chain): abort as
                 ;; failure so no tx is marked confirmed in a stale block.
                 (setf status :failure done t))
                (t
                 (let* ((tip-height (bl.store:current-height chain-state))
                        (end-height (min tip-height
                                         (or max-height most-positive-fixnum)
                                         (+ height (1- +rescan-segment-blocks+)))))
                   (if (> height end-height)
                       (setf done t)
                       (progn
                         (dolist (e (bl.store:active-chain-entries-from
                                     chain-state height (1+ (- end-height height))))
                           (when (wallet-abort-rescan wallet)
                             (setf status :user-abort done t)
                             (return))
                           (let* ((ehash (bl.store:block-index-entry-hash e))
                                  (eheight (bl.store:block-index-entry-height e))
                                  ;; Core wallet.cpp:1901-1902: refresh the set
                                  ;; BEFORE matching this block, so a TopUp that
                                  ;; block N-1 triggered is present for block N.
                                  (verdict (when rf
                                             (%rescan-filter-update-if-needed wallet rf)
                                             (%rescan-filter-matches-block bfi rf ehash)))
                                  ;; Only read the block if we might need it.
                                  (blk (unless (eq verdict :no-match)
                                         (bl.store:get-block store ehash))))
                             (cond
                               ((eq verdict :no-match)
                                ;; Filter proves no script of ours appears in
                                ;; this block. Skip the read entirely — but
                                ;; STILL advance last-scanned (Core
                                ;; wallet.cpp:1907-1908). Omitting that would
                                ;; make rpc-rescanblockchain report the last
                                ;; MATCHING block as stop_height and make
                                ;; wallet-attach-chain persist a stale best
                                ;; block, corrupting confirmation depth and
                                ;; re-scanning the tail on every restart.
                                (incf skipped)
                                (setf last-scanned-hash ehash
                                      last-scanned-height eheight))
                               ((null blk)
                                ;; Unreadable block: record failure, keep
                                ;; scanning (Core's could-not-scan branch).
                                (setf status :failure))
                               (t
                                (let ((block-time
                                        (bl.ser:block-header-timestamp
                                         (bl.ser:bitcoin-block-header blk))))
                                  (with-wallet-lock (wallet)
                                    (loop for tx in (bl.ser:bitcoin-block-transactions blk)
                                          for index from 0
                                          do (wallet-sync-transaction
                                              wallet tx
                                              (list :confirmed ehash eheight index)
                                              :update update
                                              :rescanning t
                                              :block-time block-time)))
                                  (setf last-scanned-hash ehash
                                        last-scanned-height eheight))))
                             (let ((target (or max-height tip-height)))
                               (setf (wallet-scan-progress wallet)
                                     (if (> target start-height)
                                         (float (/ (- eheight start-height)
                                                   (- target start-height)))
                                         1.0)))))
                         ;; Checkpoint the locator (Core's 60s save-progress
                         ;; ticks; per segment here).
                         (when (and save-progress last-scanned-hash (not done))
                           (with-wallet-lock (wallet)
                             (wallet-write-best-block
                              wallet (%wallet-chain-locator chain-state
                                                            last-scanned-hash))))
                         (unless done
                           (cond
                             ((and max-height (>= end-height max-height))
                              (setf done t))
                             ((>= end-height tip-height) (setf done t))
                             (t (let ((next (bl.store:get-block-at-height
                                             chain-state (1+ end-height))))
                                  (if next
                                      (setf height (1+ end-height)
                                            block-hash
                                            (bl.store:block-index-entry-hash next))
                                      (setf done t)))))))))))))
          (when done (return-from scan)))))
    ;; Scanning reached the tip: fold the current mempool in.
    (when (and (null max-height) (not (eq status :user-abort)))
      (bl.rpc:with-node-lock (node)
        (let ((mempool (bl:node-mempool node)))
          (when mempool
            (bl.mp:mempool-for-each
             mempool
             (lambda (txid entry)
               (declare (ignore txid))
               (wallet-transaction-added-to-mempool
                wallet mempool
                (bl.mp:mempool-entry-transaction entry))))))))
    (setf (wallet-scan-progress wallet) 1.0)
    (when rf
      (bl:log-info "Wallet ~A: fast rescan skipped ~D block~:P via block filters"
                             (wallet-name wallet) skipped))
    ;; SKIPPED is a 4th value so tests (and operators) can confirm the fast
    ;; path actually fired rather than inferring it; all existing callers
    ;; destructure at most three values.
    (values status last-scanned-height last-scanned-hash skipped)))

(defun wallet-rescan-from-time (node wallet start-time &key (update t))
  "Core CWallet::RescanFromTime: scan from the first block that could
contain a tx with timestamp START-TIME. Returns the earliest timestamp that
was successfully covered (> START-TIME when blocks could not be read). The
caller holds the rescan reservation."
  (let (start-entry-hash start-entry-height)
    (bl.rpc:with-node-lock (node)
      (let* ((chain-state (bl:node-current-chainstate node))
             (entry (and chain-state
                         (find-first-block-with-time
                          chain-state (- start-time +wallet-timestamp-window+) 0))))
        (when entry
          (setf start-entry-hash (bl.store:block-index-entry-hash entry)
                start-entry-height (bl.store:block-index-entry-height entry)))))
    (if start-entry-hash
        (multiple-value-bind (status last-height last-hash)
            (scan-for-wallet-transactions node wallet start-entry-hash
                                          start-entry-height :update update)
          (declare (ignore last-height last-hash))
          (if (eq status :failure)
              ;; Core reads the last FAILED block's max time; our scan aborts
              ;; the segment on failure, so the segment start bounds it.
              (bl.rpc:with-node-lock (node)
                (let ((chain-state (bl:node-current-chainstate node)))
                  (+ (%entry-chain-time-max chain-state start-entry-hash)
                     +wallet-timestamp-window+ 1)))
              start-time))
        start-time)))

(defvar *wallet-cross-chain* nil
  "Core -walletcrosschain (DEFAULT_WALLETCROSSCHAIN = false, wallet/wallet.h:135):
allow attaching a wallet whose stored best-block locator belongs to another
chain (%WALLET-FOREIGN-CHAIN-P). Off, as in Core: such a wallet is refused
instead of being rescanned onto this chain.")

(defun %wallet-foreign-chain-p (wallet chain-state)
  "T when WALLET's stored best-block locator belongs to a different chain.

Core AttachChain (wallet.cpp:3179-3189) asks whether locator.vHave.back() is
chain.getBlockHash(0): a CBlockLocator always ends at the genesis of the
chain it was built on, so its last hash IS the wallet's genesis. Ours ends
there too when it came from BUILD-BLOCK-LOCATOR, which pushes the genesis in
explicitly -- but the unload path writes a single-hash locator naming only
the wallet's last processed block (WALLET-WRITE-BEST-BLOCK), and that is what
a wallet written by this node usually carries. So the question is asked of
the whole list: a locator NO hash of which this block index has ever seen
names a history this node does not have. On a Core-shaped locator that is the
same test, since our own genesis is always in the index; on a single-hash one
it still says yes only for a block this chain never had.

A wallet merely STALE or on a reorged-away branch is not foreign: those
blocks stay in the index, and find-fork-in-active-chain handles them."
  (let ((locator (wallet-loaded-locator wallet)))
    (and locator
         (notany (lambda (hash)
                   (bl.store:get-block-index-entry chain-state hash))
                 locator))))

(defun wallet-attach-chain (node wallet)
  "Port of CWallet::AttachChain's catch-up (wallet.cpp:3171): find the fork
of the wallet's stored locator with the active chain, rescan from there
(birth-time gated) to the tip, and persist the new best block. The hooks are
global, so there is no per-wallet notification registration; blocks that
connect during the scan reach the wallet through them, exactly like Core's
pending notifications. Returns NIL on success or an error string (the wallet
should then be unloaded, like Core's failed AttachChain)."
  (let (rescan-height tip-height start-hash)
    (bl.rpc:with-node-lock (node)
      (let ((chain-state (bl:node-current-chainstate node)))
        (unless (and chain-state
                     (bl.store:best-block-hash chain-state))
          (return-from wallet-attach-chain nil))
        ;; Unless -walletcrosschain, a wallet from another chain is REFUSED
        ;; rather than rescanned onto this one (Core wallet.cpp:3178-3190).
        ;; Without this the foreign locator simply found no fork, the rescan
        ;; started at the birthday, every stored confirmation was demoted to
        ;; :inactive, the balance read as zero-and-pending, and the wallet's
        ;; persisted best block was overwritten with THIS chain's locator --
        ;; a wallet shown as emptied instead of an operator told why.
        (when (and (not *wallet-cross-chain*)
                   (%wallet-foreign-chain-p wallet chain-state))
          (return-from wallet-attach-chain
            "Wallet files should not be reused across chains. Restart bitcoind with -walletcrosschain to override."))
        (setf tip-height (max (bl.store:current-height chain-state) 0))
        (let ((fork (and (wallet-loaded-locator wallet)
                         (bl.store:find-fork-in-active-chain
                          chain-state (wallet-loaded-locator wallet)))))
          (setf rescan-height
                (if fork (bl.store:block-index-entry-height fork) 0)))
        (with-wallet-lock (wallet)
          (setf (wallet-last-block-hash wallet)
                (bl.store:best-block-hash chain-state)
                (wallet-last-block-height wallet) tip-height))
        (when (/= tip-height rescan-height)
          ;; Skip blocks predating the wallet birthday (adjusted for block
          ;; time variability).
          (let ((found (find-first-block-with-time
                        chain-state
                        (- (wallet-birth-time wallet) +wallet-timestamp-window+)
                        rescan-height)))
            (setf rescan-height
                  (if found
                      (bl.store:block-index-entry-height found)
                      tip-height)))
          (when (and (bl:pruning-enabled-p)
                     (< rescan-height
                        (bl.store:chain-state-pruned-height chain-state)))
            (return-from wallet-attach-chain
              "Prune: last wallet synchronisation goes beyond pruned data. You need to -reindex (download the whole blockchain again in case of a pruned node)"))
          (let ((start-entry (bl.store:get-block-at-height
                              chain-state rescan-height)))
            (when start-entry
              (setf start-hash
                    (bl.store:block-index-entry-hash start-entry)))))))
    (when start-hash
      (unless (wallet-reserve-rescan wallet)
        (return-from wallet-attach-chain
          "Failed to acquire rescan reserver during wallet initialization"))
      (unwind-protect
           (multiple-value-bind (status last-height last-hash)
               (scan-for-wallet-transactions node wallet start-hash rescan-height
                                             :update t :save-progress t)
             (unless (eq status :success)
               (return-from wallet-attach-chain
                 "Failed to rescan the wallet during initialization"))
             ;; Last block scanned = last block processed (may differ from
             ;; the pre-scan tip after a reorg), persisted.
             (when last-hash
               (bl.rpc:with-node-lock (node)
                 (let ((chain-state (bl:node-current-chainstate node)))
                   (with-wallet-lock (wallet)
                     (setf (wallet-last-block-hash wallet) last-hash
                           (wallet-last-block-height wallet) last-height)
                     (wallet-write-best-block
                      wallet (%wallet-chain-locator chain-state last-hash)))))))
        (wallet-release-rescan wallet)))
    nil))

;;; --- Transaction RPCs (wallet/rpc/transactions.cpp) ---

(defun %wallet-parse-txid (value)
  (unless (and (stringp value) (bl.rpc:valid-hex-hash-p value))
    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                      :message "txid must be of length 64 (not including any '0x' prefix)"))
  (bl.rpc:parse-hex-hash value))

(defun %wallet-block-time (node block-hash)
  "The timestamp of BLOCK-HASH's header via the block index (WalletTxToJSON's
chain.findBlock time lookup). Caller holds the node-lock."
  (let* ((chain-state (bl:node-current-chainstate node))
         (entry (and chain-state
                     (bl.store:get-block-index-entry chain-state
                                                                 block-hash)))
         (header (and entry (bl.store:block-index-entry-header entry))))
    (if header
        (bl.ser:block-header-timestamp header)
        0)))

(defun %wtx-rbf-status (node wallet wtx confirms)
  "WalletTxToJSON's bip125-replaceable field via IsRBFOptIn (policy/rbf.cpp:24)."
  (declare (ignore wallet))
  (if (plusp confirms)
      "no"
      (let ((tx (wallet-tx-tx wtx))
            (mempool (bl:node-mempool node)))
        (cond
          ((bl.mp:tx-signals-rbf-p tx) "yes")
          ((or (null mempool)
               (not (bl.mp:mempool-has mempool
                                                      (wallet-tx-txid wtx))))
           "unknown")
          ((bl.mp:mempool-tx-or-ancestor-signals-rbf-p
            mempool (wallet-tx-txid wtx))
           "yes")
          (t "no")))))

(defun %wallet-tx-json-fields (node wallet wtx)
  "Core WalletTxToJSON. Caller holds the node-lock and the wallet lock."
  (let ((confirms (wallet-tx-depth wallet wtx)))
    `(("confirmations" . ,confirms)
      ,@(when (%wtx-coinbase-p wtx) `(("generated" . t)))
      ,@(if (eq (wallet-tx-state wtx) :confirmed)
            `(("blockhash" . ,(bl.rpc:hash-to-hex (wallet-tx-block-hash wtx)))
              ("blockheight" . ,(wallet-tx-block-height wtx))
              ("blockindex" . ,(wallet-tx-block-index wtx))
              ("blocktime" . ,(%wallet-block-time node (wallet-tx-block-hash wtx))))
            `(("trusted" . ,(bl.rpc:json-bool (%wallet-tx-trusted-p wallet wtx)))))
      ("txid" . ,(bl.rpc:hash-to-hex (wallet-tx-txid wtx)))
      ("wtxid" . ,(bl.rpc:hash-to-hex (bl.ser:transaction-wtxid (wallet-tx-tx wtx))))
      ("walletconflicts" . ,(or (mapcar #'bl.rpc:hash-to-hex
                                        (wallet-tx-conflicts wallet wtx))
                                #()))
      ("mempoolconflicts" . ,(or (mapcar #'bl.rpc:hash-to-hex
                                         (alexandria:hash-table-keys
                                          (wallet-tx-mempool-conflicts wtx)))
                                 #()))
      ("time" . ,(wallet-tx-get-time wtx))
      ("timereceived" . ,(wallet-tx-time-received wtx))
      ("bip125-replaceable" . ,(%wtx-rbf-status node wallet wtx confirms))
      ,@(loop for (k . v) in (wallet-tx-map-value wtx)
              collect (cons k v)))))

(defun %wallet-parent-descs (wallet script)
  "Core PushParentDescriptors: the NORMALIZED descriptor string of each SPKM
owning SCRIPT (GetDescriptorString priv=false), falling back to the stored
canonical form if normalization fails."
  (loop for spkm being the hash-values of (wallet-spkms wallet)
        when (spkm-is-mine spkm script)
          collect (handler-case (%spkm-descriptor-string wallet spkm nil)
                    (bl.rpc:rpc-error () (desc-spkm-desc-string spkm)))))

(defun %wallet-tx-amounts (wallet wtx include-change)
  "receive.cpp CachedTxGetAmounts: (values received sent fee-sat) where
entries are (address value vout script); FEE-SAT is positive when we funded
the tx."
  (let* ((tx (wallet-tx-tx wtx))
         (debit (wallet-tx-get-debit wallet wtx))
         (fee (if (plusp debit) (- debit (%tx-value-out tx)) 0))
         (received '())
         (sent '()))
    (loop for i from 0
          for output across (bl.ser:transaction-outputs tx)
          do (let* ((script (bl.ser:tx-out-script-pubkey output))
                    (mine (%wallet-script-mine-p wallet script)))
               (unless (or (and (plusp debit)
                                (not include-change)
                                (%wallet-output-change-p wallet output))
                           (and (not (plusp debit)) (not mine)))
                 (let ((entry (list (bl.rpc:script->address script (wallet-network wallet))
                                    (bl.ser:tx-out-value output)
                                    i script)))
                   (when (plusp debit) (push entry sent))
                   (when mine (push entry received))))))
    (values (nreverse received) (nreverse sent) fee)))

(defun %wallet-list-transactions (node wallet wtx min-depth long filter-label
                                  &key include-change)
  "Core ListTransactions: the send/receive entries WTX contributes, in Core's
push order."
  (multiple-value-bind (received sent fee)
      (%wallet-tx-amounts wallet wtx include-change)
    (let ((entries '())
          (abandoned (bl.rpc:json-bool (%wtx-abandoned-p wtx)))
          (long-fields (when long (%wallet-tx-json-fields node wallet wtx))))
      (unless filter-label
        (dolist (s sent)
          (destructuring-bind (address value vout script) s
            (declare (ignore script))
            (multiple-value-bind (label purpose found)
                (if address
                    (wallet-find-address-book-entry wallet address)
                    (values nil nil nil))
              (declare (ignore purpose))
              (push `(,@(when address `(("address" . ,address)))
                      ("category" . "send")
                      ("amount" . ,(- (/ value 100000000.0d0)))
                      ,@(when found `(("label" . ,label)))
                      ("vout" . ,vout)
                      ("fee" . ,(- (/ fee 100000000.0d0)))
                      ,@long-fields
                      ("abandoned" . ,abandoned))
                    entries)))))
      (when (and received (>= (wallet-tx-depth wallet wtx) min-depth))
        (dolist (r received)
          (destructuring-bind (address value vout script) r
            (multiple-value-bind (label purpose found)
                (if address
                    (wallet-find-address-book-entry wallet address)
                    (values nil nil nil))
              (declare (ignore purpose))
              (unless (and filter-label
                           (not (equal (or label "") filter-label)))
                (push `(,@(when address `(("address" . ,address)))
                        ("parent_descs" . ,(or (%wallet-parent-descs wallet script)
                                               #()))
                        ("category"
                         . ,(if (%wtx-coinbase-p wtx)
                                (cond ((< (wallet-tx-depth wallet wtx) 1) "orphan")
                                      ((wallet-tx-immature-coinbase-p wallet wtx)
                                       "immature")
                                      (t "generate"))
                                "receive"))
                        ("amount" . ,(/ value 100000000.0d0))
                        ,@(when found `(("label" . ,label)))
                        ("vout" . ,vout)
                        ("abandoned" . ,abandoned)
                        ,@long-fields)
                      entries))))))
      (nreverse entries))))

(bl.rpc:define-rpc "gettransaction" (node params)
  "Detailed information about an in-wallet transaction (Bitcoin Core
gettransaction). PARAMS: (txid include_watchonly verbose)."
  (let ((wallet (wallet-for-request node))
        (txid (%wallet-parse-txid (first params)))
        (verbose (bl.rpc:positional-bool (third params))))
    (bl.rpc:with-node-lock (node)
      (with-wallet-lock (wallet)
        (let ((wtx (wallet-get-wallet-tx wallet txid)))
          (unless wtx
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                              :message "Invalid or non-wallet transaction id"))
          (let* ((tx (wallet-tx-tx wtx))
                 (credit (wallet-tx-credit wallet wtx))
                 (debit (wallet-tx-get-debit wallet wtx))
                 (net (- credit debit))
                 (from-me (plusp debit))
                 ;; Negative by construction when we funded the tx.
                 (fee (if from-me (- (%tx-value-out tx) debit) 0)))
            `(("amount" . ,(/ (- net fee) 100000000.0d0))
              ,@(when from-me `(("fee" . ,(/ fee 100000000.0d0))))
              ,@(%wallet-tx-json-fields node wallet wtx)
              ("details" . ,(or (%wallet-list-transactions node wallet wtx 0
                                                           nil nil)
                                #()))
              ("hex" . ,(bl.crypto:bytes-to-hex
                         (bl.ser:transaction-wire-bytes tx)))
              ,@(when verbose
                  `(("decoded" . ,(remove "hex" (bl.rpc:tx-to-json tx (wallet-network wallet))
                                          :key #'car :test #'equal))))
              ("lastprocessedblock"
               . (("hash" . ,(if (wallet-last-block-hash wallet)
                                 (bl.rpc:hash-to-hex (wallet-last-block-hash wallet))
                                 (make-string 64 :initial-element #\0)))
                  ("height" . ,(wallet-last-block-height wallet)))))))))))

(bl.rpc:define-rpc "listtransactions" (node params)
  "Most recent wallet transactions (Bitcoin Core listtransactions). PARAMS:
(label count skip include_watchonly)."
  (let ((wallet (wallet-for-request node))
        (filter-label nil)
        (count (if (and (>= (length params) 2) (second params)) (second params) 10))
        (skip (if (and (>= (length params) 3) (third params)) (third params) 0)))
    (let ((label-arg (first params)))
      (when (and label-arg (not (equal label-arg "*")))
        (setf filter-label (%label-from-value label-arg))
        (when (zerop (length filter-label))
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "Label argument must be a valid label name or \"*\"."))))
    (unless (and (integerp count) (>= count 0))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+ :message "Negative count"))
    (unless (and (integerp skip) (>= skip 0))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+ :message "Negative from"))
    (bl.rpc:with-node-lock (node)
      (with-wallet-lock (wallet)
        (let ((ret '())
              (ordered (wallet-tx-ordered wallet)))
          ;; Newest to oldest until count+skip entries are collected.
          (loop for i from (1- (fill-pointer ordered)) downto 0
                for wtx = (aref ordered i)
                do (setf ret (nconc ret (%wallet-list-transactions
                                         node wallet wtx 0 t filter-label)))
                   (when (>= (length ret) (+ count skip)) (return)))
          (let* ((size (length ret))
                 (from (min skip size))
                 (take (min count (- size from))))
            ;; ret is newest-first; the response is oldest-first.
            (or (reverse (subseq ret from (+ from take))) #())))))))

(bl.rpc:define-rpc "listsinceblock" (node params)
  "All wallet transactions in blocks since BLOCKHASH (Bitcoin Core
listsinceblock). PARAMS: (blockhash target_confirmations include_watchonly
include_removed include_change label)."
  (let ((wallet (wallet-for-request node))
        (target-confirms (if (and (>= (length params) 2) (second params))
                             (second params)
                             1))
        (include-removed (bl.rpc:positional-bool-or (fourth params) t))
        (include-change (bl.rpc:positional-bool (fifth params)))
        (filter-label (when (and (>= (length params) 6) (sixth params))
                        (%label-from-value (sixth params)))))
    (unless (and (integerp target-confirms) (>= target-confirms 1))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+ :message "Invalid parameter"))
    (bl.rpc:with-node-lock (node)
      (with-wallet-lock (wallet)
        (let* ((chain-state (bl:node-current-chainstate node))
               (store (bl:node-block-store node))
               (wallet-tip-entry
                 (and chain-state (wallet-last-block-hash wallet)
                      (bl.store:get-block-index-entry
                       chain-state (wallet-last-block-hash wallet))))
               (height nil)      ; common-ancestor height
               (altheight nil)   ; the named block's height (possibly detached)
               (block-entry nil))
          (let ((blockhash-arg (first params)))
            (when (and blockhash-arg (stringp blockhash-arg)
                       (plusp (length blockhash-arg)))
              (let ((bh (%wallet-parse-txid blockhash-arg)))
                (setf block-entry
                      (and chain-state
                           (bl.store:get-block-index-entry chain-state bh)))
                (let ((fork (and block-entry wallet-tip-entry
                                 (bl.val:find-fork-point
                                  block-entry wallet-tip-entry))))
                  (unless fork
                    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                                      :message "Block not found"))
                  (setf height (bl.store:block-index-entry-height fork)
                        altheight (bl.store:block-index-entry-height
                                   block-entry))))))
          (let ((depth (if height
                           (- (1+ (wallet-last-block-height wallet)) height)
                           -1))
                (transactions '()))
            (loop for wtx being the hash-values of (wallet-map-wallet wallet)
                  do (when (or (= depth -1)
                               (< (abs (wallet-tx-depth wallet wtx)) depth))
                       (setf transactions
                             (nconc transactions
                                    (%wallet-list-transactions
                                     node wallet wtx 0 t filter-label
                                     :include-change include-change)))))
            ;; Walk the detached branch for "removed" (Core reads each block).
            (let ((removed '()))
              (when (and include-removed altheight height)
                (let ((walk-hash (bl.store:block-index-entry-hash
                                  block-entry))
                      (walk-height altheight))
                  (loop while (> walk-height height)
                        do (let ((blk (and store
                                           (bl.store:get-block
                                            store walk-hash))))
                             (unless blk
                               (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-internal-error+
                                                 :message "Can't read block from disk"))
                             (dolist (tx (bl.ser:bitcoin-block-transactions blk))
                               (let ((wtx (wallet-get-wallet-tx
                                           wallet
                                           (bl.ser:transaction-hash tx))))
                                 (when wtx
                                   (setf removed
                                         (nconc removed
                                                (%wallet-list-transactions
                                                 node wallet wtx -100000000 t
                                                 filter-label
                                                 :include-change include-change))))))
                             (setf walk-hash
                                   (bl.ser:block-header-prev-block
                                    (bl.ser:bitcoin-block-header blk)))
                             (decf walk-height)))))
              (let* ((last-height (wallet-last-block-height wallet))
                     (confirms (min target-confirms (1+ last-height)))
                     (lastblock-entry
                       (and wallet-tip-entry
                            (bl.store:entry-ancestor-at-height
                             wallet-tip-entry (- (1+ last-height) confirms)))))
                `(("transactions" . ,(or transactions #()))
                  ,@(when include-removed `(("removed" . ,(or removed #()))))
                  ("lastblock" . ,(if lastblock-entry
                                      (bl.rpc:hash-to-hex
                                       (bl.store:block-index-entry-hash
                                        lastblock-entry))
                                      (make-string 64 :initial-element #\0))))))))))))

(bl.rpc:define-rpc "rescanblockchain" (node params)
  "Rescan the local blockchain for wallet transactions (Bitcoin Core
rescanblockchain). PARAMS: (start_height stop_height)."
  (let ((wallet (wallet-for-request node))
        (start-height (or (first params) 0))
        (stop-height (second params)))
    (unless (integerp start-height)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                        :message "start_height must be an integer"))
    (when (and stop-height (not (integerp stop-height)))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                        :message "stop_height must be an integer"))
    (with-wallet-lock (wallet)
      (wallet-ensure-unlocked wallet))
    (unless (wallet-reserve-rescan wallet)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                        :message "Wallet is currently rescanning. Abort existing rescan or wait."))
    ;; The scan drops and retakes the wallet lock between segments, so
    ;; suspend the relock for its duration (Core m_scanning_with_passphrase):
    ;; a timeout landing mid-scan would silently break its keypool top-ups.
    ;; Under the wallet lock: wallet-is-locked-p can relock as a side effect
    ;; (the lazy deadline check writes three slots), so it is a mutator.
    (with-wallet-lock (wallet)
      (setf (wallet-scanning-with-passphrase wallet)
            (not (wallet-is-locked-p wallet))))
    (unwind-protect
         (let (start-hash)
           (bl.rpc:with-node-lock (node)
             (let ((tip-height (with-wallet-lock (wallet)
                                 (wallet-last-block-height wallet)))
                   (chain-state (bl:node-current-chainstate node)))
               (when (or (minusp start-height) (> start-height tip-height))
                 (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                   :message "Invalid start_height"))
               (when stop-height
                 (when (or (minusp stop-height) (> stop-height tip-height))
                   (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                     :message "Invalid stop_height"))
                 (when (< stop-height start-height)
                   (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                     :message "stop_height must be greater than start_height")))
               (when (and (bl:pruning-enabled-p) chain-state
                          (< start-height
                             (bl.store:chain-state-pruned-height
                              chain-state)))
                 (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-misc-error+
                                   :message "Can't rescan beyond pruned data. Use RPC call getblockchaininfo to determine your pruned height."))
               (let ((entry (and chain-state
                                 (bl.store:get-block-at-height
                                  chain-state start-height))))
                 (unless entry
                   (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-misc-error+
                                     :message "Failed to rescan unavailable blocks, potentially caused by data corruption. If the issue persists you may want to reindex (see -reindex option)."))
                 (setf start-hash
                       (bl.store:block-index-entry-hash entry)))))
           (multiple-value-bind (status last-height)
               (scan-for-wallet-transactions node wallet start-hash start-height
                                             :max-height stop-height :update t)
             (ecase status
               (:success
                `(("start_height" . ,start-height)
                  ("stop_height" . ,last-height)))
               (:failure
                (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-misc-error+
                                  :message "Rescan failed. Potentially corrupted data files."))
               (:user-abort
                (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-misc-error+
                                  :message "Rescan aborted.")))))
      (wallet-release-rescan wallet))))

(bl.rpc:define-rpc "abortrescan" (node params)
  "Stop the wallet rescan in progress (Bitcoin Core abortrescan). Returns
whether an abort was triggered."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (if (or (not (wallet-scanning-since wallet))
            (wallet-abort-rescan wallet))
        bl.rpc:+json-false+
        (progn (setf (wallet-abort-rescan wallet) t)
               t))))
