(in-package #:bitcoin-lisp.wallet)

;;; Wallet P3: balances & coins (docs/wallet-plan.md §5 P3)
;;;
;;; Ports, from Bitcoin Core @ d3056bc:
;;;  - receive.cpp balance rollups: GetBalance (:245) over the owned-TXO map
;;;    with the trusted / untrusted-pending / immature split (the per-tx
;;;    accounting — CachedTxGetAmounts/credit/debit/fee, CachedTxIsTrusted,
;;;    the amount caches — lives in wallet-tx.lisp).
;;;  - CWallet::IsSpent (wallet.cpp:770) and the locked-coin set
;;;    (LockCoin/UnlockCoin/UnlockAllCoins/ListLockedCoins, :2737-2787).
;;;  - AvailableCoins (spend.cpp:320), the listunspent subset: tx-level
;;;    eligibility (immature/conflicted/mempool/trusted + the replaces_txid /
;;;    replaced_by_txid safety holds), per-output filters (amount range,
;;;    locks, spentness, spent-key), output-type grouping. The TRUC
;;;    check_version_trucness branch is coin-selection-only (wallet P4);
;;;    listunspent passes it disabled, exactly like Core.
;;;  - InferDescriptor (script/descriptor.cpp:2278) specialized to
;;;    wallet-owned scripts: concrete keys with [fingerprint/path] origins
;;;    (InferPubkey builds origins with apostrophe=false — 'h' markers).
;;;  - The coins RPCs (wallet/rpc/coins.cpp): getbalance / getbalances /
;;;    listunspent / lockunspent / listlockunspent.
;;;  - The address RPCs (wallet/rpc/addresses.cpp): getaddressinfo
;;;    (DescribeWalletAddressVisitor + descriptor-SPKM GetMetadata hd
;;;    fields), setlabel, getaddressesbylabel, listlabels.
;;;  - abandontransaction (wallet/rpc/transactions.cpp:779; the state
;;;    machinery is P2's wallet-abandon-transaction).
;;;
;;; Locking: balance/coin reads take only the wallet lock (Core: cs_wallet);
;;; listunspent additionally reads mempool ancestry, so it takes the
;;; node-lock FIRST (lock order: node -> manager -> wallet).

;;; --- JSON object parameter access ---

(defun %oval (obj key)
  "(values value present-p) for KEY in a JSON object parameter, accepting
the yason hash-table form and the alist form test callers use."
  (cond ((hash-table-p obj) (gethash key obj))
        ((and (listp obj) (every #'consp obj))
         (let ((pair (assoc key obj :test #'equal)))
           (if pair (values (cdr pair) t) (values nil nil))))
        (t (values nil nil))))

;;; --- IsSpent (wallet.cpp:770) ---

(defun %wallet-outpoint-key-spent-p (wallet key)
  "Core CWallet::IsSpent over a prebuilt outpoint KEY: spent when any
non-conflicted, non-abandoned wallet tx spends it."
  (dolist (spender (gethash key (wallet-tx-spends wallet)))
    (let ((wtx (wallet-get-wallet-tx wallet spender)))
      (when (and wtx
                 (not (%wtx-abandoned-p wtx))
                 (not (eq (wallet-tx-state wtx) :block-conflicted))
                 (not (%wtx-mempool-conflicted-p wtx)))
        (return t)))))

(defun wallet-outpoint-spent-p (wallet txid index)
  (%wallet-outpoint-key-spent-p wallet (%wtx-outpoint-key txid index)))

;;; --- Locked coins (wallet.cpp:2737-2787; entries are (txid index persist)) ---

(defun wallet-locked-coin-p (wallet txid index)
  "Core CWallet::IsLockedCoin."
  (and (find-if (lambda (e)
                  (and (equalp (first e) txid) (= (second e) index)))
                (wallet-locked-utxos wallet))
       t))

(defun wallet-lock-coin (wallet txid index persist)
  "Core CWallet::LockCoin: insert the lock if absent (LoadLockedCoin
semantics — an existing entry keeps its persist flag) and write the
lockedutxo record when PERSIST."
  (unless (wallet-locked-coin-p wallet txid index)
    (push (list txid index (and persist t)) (wallet-locked-utxos wallet)))
  (when persist
    (bl.store:leveldb-put (wallet-db wallet)
                                      (wdb-key-lockedutxo txid index)
                                      +wdb-lockedutxo-value+
                                      :sync t))
  t)

(defun wallet-unlock-all-coins (wallet)
  "Core CWallet::UnlockAllCoins: drop every lock, erasing persisted records."
  (dolist (entry (wallet-locked-utxos wallet))
    (when (third entry)
      (bl.store:leveldb-delete
       (wallet-db wallet) (wdb-key-lockedutxo (first entry) (second entry)))))
  (setf (wallet-locked-utxos wallet) '())
  t)

;;; --- GetBalance (receive.cpp:245) ---

(defun wallet-get-balance (wallet &key (min-depth 0) (avoid-reuse t))
  "(values trusted untrusted-pending immature), in satoshis. Caller holds
the wallet lock."
  (let ((allow-used (or (not avoid-reuse)
                        (not (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+))))
        (trusted 0)
        (untrusted 0)
        (immature 0)
        (trusted-parents (make-hash-table :test 'equalp)))
    (maphash
     (lambda (key entry)
       (let* ((wtx (car entry))
              (index (cdr entry))
              (output (aref (bl.ser:transaction-outputs
                             (wallet-tx-tx wtx))
                            index))
              (is-trusted (%wallet-tx-trusted-p wallet wtx trusted-parents))
              (depth (wallet-tx-depth wallet wtx)))
         (when (and (not (%wallet-outpoint-key-spent-p wallet key))
                    (or allow-used
                        (not (wallet-spent-key-script-p
                              wallet
                              (bl.ser:tx-out-script-pubkey
                               output)))))
           (let ((credit (bl.ser:tx-out-value output)))
             (cond ((and (wallet-tx-immature-coinbase-p wallet wtx)
                         (eq (wallet-tx-state wtx) :confirmed))
                    (incf immature credit))
                   ((and is-trusted (>= depth min-depth))
                    (incf trusted credit))
                   ((and (not is-trusted)
                         (eq (wallet-tx-state wtx) :in-mempool))
                    (incf untrusted credit)))))))
     (wallet-txos wallet))
    (values trusted untrusted immature)))

;;; --- Owning SPKM lookup + solving scripts ---

(defun %wallet-owning-spkm (wallet script)
  "(values spkm range-index) of a loaded SPKM owning SCRIPT, or NIL (Core
GetScriptPubKeyMans; ambiguity between several matching SPKMs is resolved
arbitrarily, like Core's *spk_mans.begin())."
  (loop for spkm being the hash-values of (wallet-spkms wallet)
        for index = (spkm-is-mine spkm script)
        when index do (return (values spkm index))))

(defun %spkm-solvable-p (spkm)
  (bl.rpc:out-desc-solvable-p (desc-spkm-desc spkm)))

(defun %spkm-sub-scripts (spkm script)
  "(values redeem-script witness-script) known for SCRIPT at its range
index — the provider GetCScript lookups behind listunspent's redeemScript/
witnessScript fields and getaddressinfo's embedded object."
  (let ((pos (spkm-is-mine spkm script))
        (desc (desc-spkm-desc spkm))
        (cache (desc-spkm-cache spkm)))
    (when pos
      (case (bl.rpc:out-desc-kind desc)
        (:sh
         (let* ((sub (bl.rpc:out-desc-sub desc))
                (redeem (first (bl.rpc:out-desc-expand-from-cache sub pos cache))))
           (if (and redeem (eq (bl.rpc:out-desc-kind sub) :wsh))
               (values redeem
                       (first (bl.rpc:out-desc-expand-from-cache
                               (bl.rpc:out-desc-sub sub) pos cache)))
               (values redeem nil))))
        (:wsh
         (values nil (first (bl.rpc:out-desc-expand-from-cache
                             (bl.rpc:out-desc-sub desc) pos cache))))
        (:combo
         ;; The P2SH form of combo() wraps its P2WPKH script.
         (let ((scripts (bl.rpc:out-desc-expand-from-cache desc pos cache)))
           (when (and scripts (= (length scripts) 4)
                      (equalp script (fourth scripts)))
             (values (third scripts) nil))))))))

(defun %wallet-coin-output-type (wallet script)
  "Core GetOutputType over Solver's class, reclassifying a solvable P2SH
whose redeem script is a witness program as :p2sh-segwit."
  (let ((type (bl.val:classify-script script)))
    (case type
      ((:witness-v0-keyhash :witness-v0-scripthash) :bech32)
      (:witness-v1-taproot :bech32m)
      ;; Core GetOutputType (spend.cpp:250-265): only SCRIPTHASH and
      ;; PUBKEYHASH map to LEGACY; bare PUBKEY / MULTISIG fall through to
      ;; UNKNOWN like every other TxoutType.
      (:pubkeyhash :legacy)
      (:scripthash
       (multiple-value-bind (spkm) (%wallet-owning-spkm wallet script)
         (let ((redeem (and spkm (%spkm-solvable-p spkm)
                            (%spkm-sub-scripts spkm script))))
           (if (and redeem
                    (member (bl.val:classify-script redeem)
                            '(:witness-v0-keyhash :witness-v0-scripthash)))
               :p2sh-segwit
               :legacy))))
      (t :unknown))))

;;; --- AvailableCoins (spend.cpp:320, the listunspent subset) ---

(defstruct wallet-coin
  "One spendable candidate (Core COutput). P3 fills the listunspent fields;
the coin-selection fields (input-bytes/fee/effective-value/from-me/time,
wallet P4) are populated only when wallet-available-coins runs with a
FEERATE + INPUT-BYTES-FN — exactly the fields Core's COutput constructor
fills when a feerate is passed (coinselection.h:75-99)."
  txid
  index
  output
  wtx
  (depth 0 :type integer)
  solvable
  safe
  ;; --- Coin selection fields (wallet P4) ---
  (input-bytes -1 :type integer)   ; max signed input vsize, -1 unknown
  from-me
  (time 0 :type integer)           ; CWalletTx::GetTxTime
  fee                              ; satoshis to spend at the effective feerate, NIL when no feerate
  (long-term-fee 0 :type integer)  ; filled by out-group insertion
  (bump-fee 0 :type integer)       ; ancestor bump fee (always 0 — no bump-fee machinery, see wallet-spend)
  effective-value                  ; value - fee, NIL when no feerate
  output-type)                     ; :legacy/:p2sh-segwit/:bech32/:bech32m/:unknown

(alexandria:define-constant +output-type-order+ '(:legacy :p2sh-segwit :bech32 :bech32m :unknown)
  :test #'equalp :documentation "CoinsResult::All concatenation order (OutputType enum order).")

(defun wallet-available-coins (wallet &key (min-depth 0) (max-depth 9999999)
                                           (only-safe t)
                                           (min-amount 0)
                                           max-amount
                                           min-sum-amount
                                           max-count
                                           include-immature-coinbase
                                           (skip-locked t)
                                           ;; --- Coin-selection extensions (wallet P4) ---
                                           feerate            ; sat/kvB, fills fee/effective-value
                                           input-bytes-fn     ; script -> max signed input vsize or NIL
                                           (allow-used-addresses t)
                                           skip-outpoints     ; equalp hash of outpoint keys to skip
                                           check-version-trucness
                                           (tx-version 2)
                                           mempool)
  "The wallet's unspent, eligible coins as wallet-coin structs, grouped in
output-type order. Caller holds the wallet lock (and, when MEMPOOL /
CHECK-VERSION-TRUCNESS are in play, the node lock outside it)."
  (let ((buckets (make-hash-table :test 'eq))
        (tx-safe-cache (make-hash-table :test 'equalp)) ; txid -> (ok . safe)
        (trusted-parents (make-hash-table :test 'equalp))
        ;; Unconfirmed TRUC coins bucketed aside (spend.cpp:329-330,498-513).
        (truc-coins '())                                ; (type . coin), reversed
        (truc-value (make-hash-table :test 'equalp))    ; txid -> total value
        (total 0)
        (count 0)
        (done nil))
    (maphash
     (lambda (key entry)
       (declare (ignore key))
       (unless done
         (let* ((wtx (car entry))
                (index (cdr entry))
                (txid (wallet-tx-txid wtx))
                (output (aref (bl.ser:transaction-outputs
                               (wallet-tx-tx wtx))
                              index))
                (depth (wallet-tx-depth wallet wtx))
                (checked (gethash txid tx-safe-cache)))
           (block skip-coin
             ;; Tx-level checks, once per tx (spend.cpp:353-425).
             (unless checked
               (setf checked (setf (gethash txid tx-safe-cache) (cons nil nil)))
               (when (and (wallet-tx-immature-coinbase-p wallet wtx)
                          (not include-immature-coinbase))
                 (return-from skip-coin))
               (when (minusp depth) (return-from skip-coin))
               ;; Coins not at least in our mempool may be conflicted via
               ;; ancestors we can never detect.
               (when (and (zerop depth)
                          (not (eq (wallet-tx-state wtx) :in-mempool)))
                 (return-from skip-coin))
               (let ((safe (%wallet-tx-trusted-p wallet wtx trusted-parents)))
                 ;; Replacement participants are never safe (spend.cpp:370-399).
                 (when (and (zerop depth)
                            (or (assoc "replaces_txid" (wallet-tx-map-value wtx)
                                       :test #'string=)
                                (assoc "replaced_by_txid" (wallet-tx-map-value wtx)
                                       :test #'string=)))
                   (setf safe nil))
                 ;; TRUC topology gate (spend.cpp:401-414): a v3 spend may
                 ;; only take unconfirmed v3 coins whose tx has no mempool
                 ;; child yet and no unconfirmed parent (2-generation rule);
                 ;; a non-v3 spend never takes unconfirmed v3 coins.
                 (when (and (zerop depth) check-version-trucness)
                   (let ((v3 (= (bl.ser:transaction-version
                                 (wallet-tx-tx wtx))
                                bl.mp:+truc-version+)))
                     (if (= tx-version bl.mp:+truc-version+)
                         (progn
                           (unless v3 (return-from skip-coin))
                           (when (wallet-tx-truc-child wtx)
                             (return-from skip-coin))
                           (when (and mempool
                                      (> (bl.mp:mempool-ancestor-stats
                                          mempool txid)
                                         1))
                             (return-from skip-coin)))
                         (when v3 (return-from skip-coin)))))
                 (when (and only-safe (not safe)) (return-from skip-coin))
                 (when (or (< depth min-depth) (> depth max-depth))
                   (return-from skip-coin))
                 (setf (car checked) t
                       (cdr checked) safe)))
             (unless (car checked) (return-from skip-coin))
             ;; Per-output checks (spend.cpp:431-446).
             (let ((value (bl.ser:tx-out-value output))
                   (script (bl.ser:tx-out-script-pubkey output)))
               (when (or (< value min-amount)
                         (and max-amount (> value max-amount)))
                 (return-from skip-coin))
               ;; Manually selected coins are fetched by the caller directly.
               (when (and skip-outpoints
                          (gethash (%wtx-outpoint-key txid index) skip-outpoints))
                 (return-from skip-coin))
               (when (and skip-locked (wallet-locked-coin-p wallet txid index))
                 (return-from skip-coin))
               (when (wallet-outpoint-spent-p wallet txid index)
                 (return-from skip-coin))
               (when (and (not allow-used-addresses)
                          (wallet-spent-key-script-p wallet script))
                 (return-from skip-coin))
               (multiple-value-bind (spkm) (%wallet-owning-spkm wallet script)
                 (let* ((input-bytes (or (and input-bytes-fn
                                              (funcall input-bytes-fn script))
                                         -1))
                        (output-type (%wallet-coin-output-type wallet script))
                        (coin (make-wallet-coin
                               :txid txid :index index :output output :wtx wtx
                               :depth depth
                               ;; With an INPUT-BYTES-FN the solvability
                               ;; criterion is Core's: a satisfaction size
                               ;; could be inferred (spend.cpp:453-455).
                               :solvable (if input-bytes-fn
                                             (> input-bytes -1)
                                             (and spkm (%spkm-solvable-p spkm) t))
                               :safe (cdr checked)
                               :input-bytes input-bytes
                               :from-me (wallet-tx-from-me-cached wallet wtx)
                               :time (wallet-tx-get-time wtx)
                               :fee (when feerate
                                      (if (minusp input-bytes)
                                          0
                                          (bl.rpc:feerate-fee feerate input-bytes)))
                               :effective-value
                               (when feerate
                                 (- value (if (minusp input-bytes)
                                              0
                                              (bl.rpc:feerate-fee feerate input-bytes))))
                               :output-type output-type)))
                   (if (and check-version-trucness (zerop depth)
                            (= (bl.ser:transaction-version
                                (wallet-tx-tx wtx))
                               bl.mp:+truc-version+))
                       ;; Bucketed aside; only the highest-value v3 tx's
                       ;; coins join the result (spend.cpp:475-478,498-513).
                       (progn
                         (push (cons output-type coin) truc-coins)
                         (incf (gethash txid truc-value 0) value))
                       (progn
                         (push coin (gethash output-type buckets))
                         (incf total value)
                         (incf count)
                         (when (or (and min-sum-amount (>= total min-sum-amount))
                                   (and max-count (>= count max-count)))
                           (setf done t)))))))))))
     (wallet-txos wallet))
    ;; Fold in the coins of the single highest-value unconfirmed TRUC tx —
    ;; skipped entirely when the min-sum/max-count early return fired, like
    ;; Core's in-loop `return result` (spend.cpp:486-495).
    (when (and truc-coins (not done))
      (let ((best-txid nil) (best-value -1))
        (maphash (lambda (txid value)
                   (when (> value best-value)
                     (setf best-txid txid best-value value)))
                 truc-value)
        (dolist (entry truc-coins)
          (when (equalp (wallet-coin-txid (cdr entry)) best-txid)
            (push (cdr entry) (gethash (car entry) buckets))))))
    (let ((coins (loop for type in +output-type-order+
                       nconc (nreverse (gethash type buckets)))))
      ;; Core AvailableCoins' last step (spend.cpp:515-522): with a feerate in
      ;; hand, every candidate's effective value drops by what its unconfirmed
      ;; ancestors would cost to bump to that feerate, so coin selection sees
      ;; the real price of spending it. Without a mempool there is no
      ;; information and every bump is 0, which is Core's own no-mempool branch
      ;; (node/interfaces.cpp:691-697).
      (when (and feerate mempool)
        (let ((bumps (mini-miner-bump-fees
                      mempool
                      (mapcar (lambda (coin)
                                (cons (wallet-coin-txid coin)
                                      (wallet-coin-index coin)))
                              coins)
                      feerate)))
          (dolist (coin coins)
            (let ((bump (gethash (%wtx-outpoint-key (wallet-coin-txid coin)
                                                    (wallet-coin-index coin))
                                 bumps 0)))
              (when (plusp bump)
                (%apply-bump-fee coin bump))))))
      coins)))

(defun %apply-bump-fee (coin bump)
  "Core COutput::ApplyBumpFee (coinselection.h:108-116): the bump joins the
coin's spending fee, and its effective value falls by the same amount."
  (setf (wallet-coin-bump-fee coin) bump
        (wallet-coin-fee coin) (+ (or (wallet-coin-fee coin) 0) bump)
        (wallet-coin-effective-value coin)
        (- (bl.ser:tx-out-value (wallet-coin-output coin))
           (wallet-coin-fee coin))))

;;; --- Inferred descriptors (script/descriptor.cpp InferDescriptor) ---
;;;
;;; The body renderer itself is BL.RPC:INFER-DESCRIPTOR-BODY, next to the
;;; descriptor parser and the key-expression accessors it is written in terms
;;; of (src/rpc/descriptors.lisp). It moved there when scantxoutset needed the
;;; same thing: Core's scan reports the descriptor INFERRED from each matched
;;; script, through the very InferDescriptor this is a port of, so the renderer
;;; cannot live above the RPC layer that also wants it.

(defun %spkm-expansion-pairs (spkm pos)
  "(values scripts pairs) — the SPKM's expansion at POS with each derived
pubkey paired to its desc-key, in expression order."
  (multiple-value-bind (scripts pubkeys)
      (bl.rpc:out-desc-expand-from-cache (desc-spkm-desc spkm) pos
                                  (desc-spkm-cache spkm))
    (when scripts
      (values scripts
              (mapcar #'cons (bl.rpc:out-desc-ordered-keys (desc-spkm-desc spkm))
                      pubkeys)))))

(defun %wallet-inferred-descriptor (wallet script)
  "Core InferDescriptor via the owning SPKM: the checksummed concrete
descriptor for SCRIPT, or NIL when the wallet cannot solve it."
  (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet script)
    (when (and spkm (%spkm-solvable-p spkm))
      (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
        (when scripts
          (let ((body (bl.rpc:infer-descriptor-body (desc-spkm-desc spkm) script
                                        scripts pairs pos)))
            (and body (bl.rpc:descriptor-add-checksum body))))))))

;;; --- getbalance / getbalances (wallet/rpc/coins.cpp:164,401) ---

(defun %get-avoid-reuse-flag (wallet param)
  "Core GetAvoidReuseFlag: null/omitted PARAM keeps the wallet's avoid_reuse
flag as the default (Core's isNull check); an explicit boolean (incl. the
+json-false+ sentinel) overrides it. Requesting it on a wallet without the
flag errors."
  (let* ((can (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+))
         (avoid (if param (bl.rpc:positional-bool param) can)))
    (when (and avoid (not can))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                        :message "wallet does not have the \"avoid reuse\" feature enabled"))
    avoid))

(defun %wallet-last-processed-block (wallet)
  "Core AppendLastProcessedBlock's object."
  `(("hash" . ,(if (wallet-last-block-hash wallet)
                   (bl.rpc:hash-to-hex (wallet-last-block-hash wallet))
                   (make-string 64 :initial-element #\0)))
    ("height" . ,(wallet-last-block-height wallet))))

(bl.rpc:define-rpc "getbalance" (node params)
  "The wallet's total available (trusted) balance (Bitcoin Core getbalance).
PARAMS: (dummy minconf include_watchonly avoid_reuse)."
  (let ((wallet (wallet-for-request node))
        (dummy (first params))
        (minconf (or (second params) 0)))
    (when (and dummy (not (equal dummy "*")))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-method-deprecated+
                        :message "dummy first argument must be excluded or set to \"*\"."))
    (unless (integerp minconf)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+ :message "minconf must be an integer"))
    (with-wallet-lock (wallet)
      (let ((avoid-reuse (%get-avoid-reuse-flag wallet (fourth params))))
        (bl.rpc:satoshi->btc (wallet-get-balance wallet :min-depth minconf
                                         :avoid-reuse avoid-reuse))))))

(bl.rpc:define-rpc "getbalances" (node params)
  "All wallet balances (Bitcoin Core getbalances)."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (multiple-value-bind (trusted untrusted immature)
          (wallet-get-balance wallet)
        `(("mine"
           . (("trusted" . ,(bl.rpc:satoshi->btc trusted))
              ("untrusted_pending" . ,(bl.rpc:satoshi->btc untrusted))
              ("immature" . ,(bl.rpc:satoshi->btc immature))
              ;; With AVOID_REUSE the default balance excludes reused
              ;; addresses; "used" is the difference against the full one.
              ,@(when (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+)
                  (multiple-value-bind (full-trusted full-untrusted)
                      (wallet-get-balance wallet :avoid-reuse nil)
                    `(("used" . ,(bl.rpc:satoshi->btc (- (+ full-trusted full-untrusted)
                                          trusted untrusted))))))))
          ("lastprocessedblock" . ,(%wallet-last-processed-block wallet)))))))

;;; --- listunspent (wallet/rpc/coins.cpp:456) ---

(defun %listunspent-entry (node wallet coin avoid-reuse)
  (let* ((output (wallet-coin-output coin))
         (script (bl.ser:tx-out-script-pubkey output))
         (address (bl.rpc:script->address script (wallet-network wallet)))
         (txid (wallet-coin-txid coin))
         (mempool (bl:node-mempool node)))
    (multiple-value-bind (spkm) (%wallet-owning-spkm wallet script)
      (multiple-value-bind (redeem witness) (and spkm (%spkm-sub-scripts spkm script))
        `(("txid" . ,(bl.rpc:hash-to-hex txid))
          ("vout" . ,(wallet-coin-index coin))
          ,@(when address
              `(("address" . ,address)
                ,@(multiple-value-bind (label purpose found)
                      (wallet-find-address-book-entry wallet address)
                    (declare (ignore purpose))
                    (when found `(("label" . ,label))))
                ,@(when redeem
                    `(("redeemScript" . ,(bl.crypto:bytes-to-hex redeem))))
                ,@(when witness
                    `(("witnessScript" . ,(bl.crypto:bytes-to-hex witness))))))
          ("scriptPubKey" . ,(bl.crypto:bytes-to-hex script))
          ("amount" . ,(bl.rpc:satoshi->btc (bl.ser:tx-out-value output)))
          ("confirmations" . ,(wallet-coin-depth coin))
          ,@(when (and (zerop (wallet-coin-depth coin))
                       mempool
                       (bl.mp:mempool-has mempool txid))
              (multiple-value-bind (acount avsize afees)
                  (bl.mp:mempool-ancestor-stats mempool txid)
                `(("ancestorcount" . ,acount)
                  ("ancestorsize" . ,avsize)
                  ("ancestorfees" . ,afees))))
          ("spendable" . t)
          ("solvable" . ,(bl.rpc:json-bool (wallet-coin-solvable coin)))
          ,@(when (wallet-coin-solvable coin)
              (let ((desc (%wallet-inferred-descriptor wallet script)))
                (when desc `(("desc" . ,desc)))))
          ("parent_descs" . ,(or (%wallet-parent-descs wallet script) #()))
          ,@(when avoid-reuse
              `(("reused" . ,(bl.rpc:json-bool (wallet-spent-key-script-p wallet script)))))
          ("safe" . ,(bl.rpc:json-bool (wallet-coin-safe coin))))))))

(bl.rpc:define-rpc "listunspent" (node params)
  "Unspent wallet outputs with between minconf and maxconf confirmations
(Bitcoin Core listunspent). PARAMS: (minconf maxconf addresses
include_unsafe query_options)."
  (let ((wallet (wallet-for-request node))
        (minconf (if (and (>= (length params) 1) (first params)) (first params) 1))
        (maxconf (if (and (>= (length params) 2) (second params)) (second params) 9999999))
        (addresses (bl.rpc:positional-array (third params)))
        (include-unsafe (bl.rpc:positional-bool-or (fourth params) t))
        (options (fifth params))
        (min-amount 0)
        (max-amount nil)
        (min-sum-amount nil)
        (max-count nil)
        (include-immature nil)
        (filter-scripts nil))
    (unless (and (integerp minconf) (integerp maxconf))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                        :message "minconf and maxconf must be integers"))
    (when addresses
      (unless (listp addresses)
        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+ :message "addresses must be an array"))
      (setf filter-scripts (make-hash-table :test 'equalp))
      (dolist (address addresses)
        (multiple-value-bind (type script)
            (and (stringp address)
                 (bl.crypto:decode-address address
                                                     (wallet-network wallet)))
          (unless type
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                              :message (format nil "Invalid Bitcoin address: ~A" address)))
          (when (gethash script filter-scripts)
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                              :message (format nil "Invalid parameter, duplicated address: ~A" address)))
          (setf (gethash script filter-scripts) t))))
    (when options
      (multiple-value-bind (value present) (%oval options "minimumAmount")
        (when present (setf min-amount (bl.rpc:amount-from-value value))))
      (multiple-value-bind (value present) (%oval options "maximumAmount")
        (when present (setf max-amount (bl.rpc:amount-from-value value))))
      (multiple-value-bind (value present) (%oval options "minimumSumAmount")
        (when present (setf min-sum-amount (bl.rpc:amount-from-value value))))
      (multiple-value-bind (value present) (%oval options "maximumCount")
        (when present
          (unless (integerp value)
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                              :message "maximumCount must be an integer"))
          (setf max-count value)))
      (multiple-value-bind (value present) (%oval options "include_immature_coinbase")
        (when present (setf include-immature (and value t)))))
    (bl.rpc:with-node-lock (node)   ; mempool ancestry reads; node -> wallet order
      (with-wallet-lock (wallet)
        (let ((coins (wallet-available-coins
                      wallet
                      :min-depth minconf :max-depth maxconf
                      :only-safe (not include-unsafe)
                      :min-amount min-amount :max-amount max-amount
                      :min-sum-amount min-sum-amount
                      :max-count (and max-count (plusp max-count) max-count)
                      :include-immature-coinbase include-immature))
              (avoid-reuse (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+))
              (results '()))
          (dolist (coin coins)
            (let* ((script (bl.ser:tx-out-script-pubkey
                            (wallet-coin-output coin))))
              (when (or (null filter-scripts) (gethash script filter-scripts))
                (push (%listunspent-entry node wallet coin avoid-reuse)
                      results))))
          (or (nreverse results) #()))))))

;;; --- lockunspent / listlockunspent (wallet/rpc/coins.cpp:214,347) ---

(bl.rpc:define-rpc "lockunspent" (node params)
  "Lock or unlock unspent outputs (Bitcoin Core lockunspent). PARAMS:
(unlock transactions persistent)."
  (let ((wallet (wallet-for-request node))
        (unlock (bl.rpc:positional-bool (first params)))
        (outputs-param (second params))
        (persistent (bl.rpc:positional-bool (third params))))
    (with-wallet-lock (wallet)
      (when (null outputs-param)
        (when unlock (wallet-unlock-all-coins wallet))
        (return-from rpc-lockunspent t))
      (unless (listp outputs-param)
        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                          :message "transactions must be an array"))
      (let ((outputs '()))
        (dolist (o outputs-param)
          (multiple-value-bind (txid-value txid-present) (%oval o "txid")
            (multiple-value-bind (vout-value vout-present) (%oval o "vout")
              (unless (and txid-present (stringp txid-value))
                (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                                  :message "Missing txid key"))
              (unless (and vout-present (integerp vout-value))
                (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+
                                  :message "Missing vout key"))
              (when (minusp vout-value)
                (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                  :message "Invalid parameter, vout cannot be negative"))
              (let* ((txid (bl.rpc:parse-hash-v txid-value "txid"))
                     (wtx (wallet-get-wallet-tx wallet txid)))
                (unless wtx
                  (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                    :message "Invalid parameter, unknown transaction"))
                (unless (< vout-value
                           (length (bl.ser:transaction-outputs
                                    (wallet-tx-tx wtx))))
                  (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                    :message "Invalid parameter, vout index out of bounds"))
                (when (wallet-outpoint-spent-p wallet txid vout-value)
                  (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                    :message "Invalid parameter, expected unspent output"))
                (let ((locked (wallet-locked-coin-p wallet txid vout-value)))
                  (when (and unlock (not locked))
                    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                      :message "Invalid parameter, expected locked output"))
                  (when (and (not unlock) locked (not persistent))
                    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                      :message "Invalid parameter, output already locked")))
                (push (cons txid vout-value) outputs)))))
        (dolist (outpoint (nreverse outputs))
          (if unlock
              (%wallet-unlock-coin wallet (car outpoint) (cdr outpoint))
              (wallet-lock-coin wallet (car outpoint) (cdr outpoint) persistent)))
        t))))

(bl.rpc:define-rpc "listlockunspent" (node params)
  "Temporarily unspendable outputs (Bitcoin Core listlockunspent)."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (or (mapcar (lambda (entry)
                    `(("txid" . ,(bl.rpc:hash-to-hex (first entry)))
                      ("vout" . ,(second entry))))
                  (reverse (wallet-locked-utxos wallet)))
          #()))))

;;; --- getaddressinfo (wallet/rpc/addresses.cpp:368) ---

(defun %expansion-pubkey-by-hash160 (pairs hash)
  (find hash pairs :test #'equalp
                   :key (lambda (pair) (bl.crypto:hash160 (cdr pair)))))

(defun %process-sub-script (wallet sub-script pairs witness)
  "Core DescribeWalletAddressVisitor::ProcessSubScript (wallet/rpc/
addresses.cpp:266-297): fields describing a known redeem/witness script.
WITNESS is the witness script, for a P2SH whose redeem script is itself a
P2WSH.

The embedded object's wallet detail is the SAME visitor run on the embedded
destination (:280), so it recurses: sh(pkh(K)) reports K under embedded, and
sh(wsh(pkh(K))) nests a second embedded object. A pubkey found anywhere below
is hoisted to each level (:284-285, \"so that getnewaddress()['pubkey'] always
works\") -- wallet_fundrawtransaction.py:1066 and wallet_send.py:483 read
getaddressinfo(addr)['pubkey'] for exactly those two shapes. Only a P2WPKH
sub-script used to get its detail, so both were a KeyError."
  (multiple-value-bind (type data)
      (bl.val:classify-script sub-script)
    (let ((fields
            `(("script" . ,(bl.val:script-type-to-string type))
              ("hex" . ,(bl.crypto:bytes-to-hex sub-script))))
          (sub-address (bl.rpc:script->address sub-script (wallet-network wallet))))
      (cond
        (sub-address
         (multiple-value-bind (sub-type sub-spk sub-wv sub-wp)
             (bl.crypto:decode-address sub-address (wallet-network wallet))
           (let* ((detail (bl.rpc:describe-address-fields sub-type sub-wv sub-wp))
                  (wallet-detail (%address-wallet-detail
                                  wallet sub-type sub-spk sub-wp pairs nil witness))
                  (hoisted (cdr (assoc "pubkey" wallet-detail :test #'equal))))
             (setf fields
                   (append fields
                           `(,@(when hoisted `(("pubkey" . ,hoisted)))
                             ("embedded"
                              . (,@detail
                                 ,@wallet-detail
                                 ("address" . ,sub-address)
                                 ("scriptPubKey"
                                  . ,(bl.crypto:bytes-to-hex
                                      sub-script))))))))))
        ((eq type :multisig)
         (setf fields
               (append fields
                       `(("sigsrequired" . ,(getf data :m))
                         ("pubkeys" . ,(mapcar #'bl.crypto:bytes-to-hex
                                               (getf data :pubkeys))))))))
      fields)))

(defun %address-wallet-detail (wallet type script wit-prog pairs redeem witness)
  "Core DescribeWalletAddressVisitor's operator() per destination class
(wallet/rpc/addresses.cpp:304-349): pubkey/iscompressed for a key hash, and
ProcessSubScript over the REDEEM (P2SH) or WITNESS (P2WSH) script the wallet
knows. PAIRS are the (key . pubkey) pairs of the expansion, the provider's
GetPubKey."
  (case type
    (:p2pkh
     (let ((pair (and pairs (%expansion-pubkey-by-hash160
                             pairs (subseq script 3 23)))))
       (when pair
         `(("pubkey" . ,(bl.crypto:bytes-to-hex (cdr pair)))
           ("iscompressed" . ,(bl.rpc:json-bool (= (length (cdr pair)) 33)))))))
    (:p2wpkh
     (let ((pair (and pairs (%expansion-pubkey-by-hash160 pairs wit-prog))))
       (when pair
         `(("pubkey" . ,(bl.crypto:bytes-to-hex (cdr pair)))))))
    (:p2sh (when redeem (%process-sub-script wallet redeem pairs witness)))
    (:p2wsh (when witness (%process-sub-script wallet witness pairs nil)))))

(defun %wallet-address-detail (wallet type script wit-prog spkm pos)
  "Core DescribeWalletAddress's visitor for a destination SPKM owns at POS."
  (let ((pairs (and spkm (nth-value 1 (%spkm-expansion-pairs spkm pos)))))
    (multiple-value-bind (redeem witness)
        (and spkm (member type '(:p2sh :p2wsh)) (%spkm-sub-scripts spkm script))
      (%address-wallet-detail wallet type script wit-prog pairs redeem witness))))

(defun %wallet-dest-key-origin (spkm script type)
  "(values desc-key pubkey pos) for single-key destinations —
GetKeyForDestination's supported classes: P2PKH, P2WPKH, P2SH-P2WPKH, and
key-path-only P2TR."
  (let* ((desc (desc-spkm-desc spkm))
         (kind (bl.rpc:out-desc-kind desc))
         (pos (spkm-is-mine spkm script)))
    (when (and pos
               (case type
                 ((:p2pkh :p2wpkh) (member kind '(:pkh :wpkh :combo)))
                 (:p2sh (or (and (eq kind :sh)
                                 (eq (bl.rpc:out-desc-kind (bl.rpc:out-desc-sub desc)) :wpkh))
                            (eq kind :combo)))
                 ;; Key-path-ONLY tr(). Core requires spenddata.merkle_root
                 ;; .IsNull() here (signingprovider.cpp:290): a taproot output
                 ;; with a script tree maps to no single key, so getaddressinfo
                 ;; reports no hdkeypath/hdmasterfingerprint for it. Without the
                 ;; tree test we would report the INTERNAL key's origin, which
                 ;; names a key that cannot by itself spend the output.
                 (:p2tr (and (eq kind :tr) (null (bl.rpc:out-desc-tree desc))))))
      (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
        (declare (ignore scripts))
        (when pairs
          (values (car (first pairs)) (cdr (first pairs)) pos))))))

(bl.rpc:define-rpc "getaddressinfo" (node params)
  "Information about a bitcoin address (Bitcoin Core getaddressinfo).
PARAMS: (address)."
  (let ((wallet (wallet-for-request node))
        (address (first params)))
    (multiple-value-bind (type script wit-ver wit-prog)
        (and (stringp address)
             (bl.crypto:decode-address address (wallet-network wallet)))
      (unless type
        ;; Core throws DecodeDestination's OWN error_msg here and keeps the
        ;; generic "Invalid address" only for the case where it set none
        ;; (wallet/rpc/addresses.cpp:430-438);
        ;; rpc_invalid_address_message.py:110-113 reads three of those
        ;; sentences off getaddressinfo.
        (let ((message (and (stringp address)
                            (bl.crypto:decode-address-error
                             address (wallet-network wallet)))))
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                            :message (if (and message (plusp (length message)))
                                         message
                                         "Invalid address"))))
      (with-wallet-lock (wallet)
        (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet script)
          (let* ((solvable (and spkm (%spkm-solvable-p spkm) t))
                 (desc (and solvable (%wallet-inferred-descriptor wallet script)))
                 (key-origin (and spkm
                                  (multiple-value-list
                                   (%wallet-dest-key-origin spkm script type)))))
            `(("address" . ,address)
              ("scriptPubKey" . ,(bl.crypto:bytes-to-hex script))
              ("ismine" . ,(bl.rpc:json-bool spkm))
              ("solvable" . ,(bl.rpc:json-bool solvable))
              ,@(when desc `(("desc" . ,desc)))
              ,@(when spkm
                  `(("parent_desc" . ,(%spkm-descriptor-string wallet spkm nil))))
              ("iswatchonly" . ,bl.rpc:+json-false+)
              ,@(bl.rpc:describe-address-fields type wit-ver wit-prog)
              ,@(%wallet-address-detail wallet type script wit-prog spkm pos)
              ;; ScriptIsChange: IsMine without a (non-change) book entry.
              ("ischange" . ,(bl.rpc:json-bool
                              (and spkm
                                   (not (nth-value 2 (wallet-find-address-book-entry
                                                      wallet address))))))
              ,@(when (and spkm (first key-origin))
                  (destructuring-bind (key pubkey key-pos) key-origin
                    (multiple-value-bind (fpr path)
                        (bl.rpc:descriptor-key-origin key pubkey key-pos)
                      `(("timestamp" . ,(desc-spkm-creation-time spkm))
                        ("hdkeypath" . ,(format nil "m~A" (bl.rpc:format-key-path path nil)))
                        ;; Descriptor wallets have no HD seed; Core reports
                        ;; the null id (CKeyMetadata default).
                        ("hdseedid" . ,(make-string 40 :initial-element #\0))
                        ("hdmasterfingerprint"
                         . ,(bl.crypto:bytes-to-hex fpr))))))
              ("labels" . ,(multiple-value-bind (label purpose found)
                               (wallet-find-address-book-entry wallet address)
                             (declare (ignore purpose))
                             (if found (list label) #()))))))))))

;;; --- setlabel / getaddressesbylabel / listlabels (addresses.cpp:118,515,576) ---

(bl.rpc:define-rpc "setlabel" (node params)
  "Set the label of an address (Bitcoin Core setlabel). PARAMS:
(address label)."
  (let ((wallet (wallet-for-request node))
        (address (first params)))
    (multiple-value-bind (type script)
        (and (stringp address)
             (bl.crypto:decode-address address (wallet-network wallet)))
      (unless type
        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                          :message "Invalid Bitcoin address"))
      (let ((label (%label-from-value (second params))))
        (with-wallet-lock (wallet)
          (wallet-set-address-book wallet address label
                                   (if (%wallet-owning-spkm wallet script)
                                       "receive"
                                       "send"))))))
  nil)

(bl.rpc:define-rpc "getaddressesbylabel" (node params)
  "The addresses assigned to LABEL (Bitcoin Core getaddressesbylabel)."
  (let ((wallet (wallet-for-request node))
        (label (%label-from-value (first params))))
    (with-wallet-lock (wallet)
      (let ((result '()))
        (maphash (lambda (address entry)
                   ;; Change entries (no label ever set) are skipped.
                   (when (and (addr-book-entry-label entry)
                              (equal (addr-book-entry-label entry) label))
                     (push `(,address
                             . (("purpose" . ,(or (addr-book-entry-purpose entry)
                                                  "unknown"))))
                           result)))
                 (wallet-address-book wallet))
        (unless result
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-invalid-label-name+
                            :message (format nil "No addresses with label ~A" label)))
        (sort result #'string< :key #'car)))))

(bl.rpc:define-rpc "listlabels" (node params)
  "All labels, optionally only those on addresses with PURPOSE (Bitcoin Core
listlabels). PARAMS: (purpose)."
  (let ((wallet (wallet-for-request node))
        (purpose-arg (first params))
        (purpose nil))
    (when (and purpose-arg (stringp purpose-arg) (plusp (length purpose-arg)))
      (unless (member purpose-arg '("send" "receive" "refund") :test #'equal)
        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                          :message "Invalid 'purpose' argument, must be a known purpose string, typically 'send', or 'receive'."))
      (setf purpose purpose-arg))
    (with-wallet-lock (wallet)
      (let ((labels (make-hash-table :test 'equal)))
        (maphash (lambda (address entry)
                   (declare (ignore address))
                   (when (and (addr-book-entry-label entry)
                              (or (null purpose)
                                  (equal purpose (addr-book-entry-purpose entry))))
                     (setf (gethash (addr-book-entry-label entry) labels) t)))
                 (wallet-address-book wallet))
        (or (sort (alexandria:hash-table-keys labels) #'string<) #())))))

;;; --- abandontransaction (wallet/rpc/transactions.cpp:779) ---

(bl.rpc:define-rpc "abandontransaction" (node params)
  "Mark an in-wallet transaction and its wallet descendants abandoned
(Bitcoin Core abandontransaction). PARAMS: (txid)."
  (let ((wallet (wallet-for-request node))
        (txid (bl.rpc:parse-hash-v (first params) "txid")))
    (with-wallet-lock (wallet)
      (let ((wtx (wallet-get-wallet-tx wallet txid)))
        (unless wtx
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                            :message "Invalid or non-wallet transaction id"))
        (unless (wallet-abandon-transaction wallet wtx)
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                            :message "Transaction not eligible for abandonment"))))
    nil))

;;; --- Wallet P7: received-by / keypoolrefill / simulate / groupings ---
;;;
;;; Ports, from Bitcoin Core @ d3056bc:
;;;  - GetReceived (wallet/rpc/coins.cpp:21) behind getreceivedbyaddress /
;;;    getreceivedbylabel; ListReceived (wallet/rpc/transactions.cpp:75) behind
;;;    listreceivedbyaddress / listreceivedbylabel — mapWallet output tallies
;;;    keyed by ExtractDestination, gated by the tx-level depth / coinbase /
;;;    immature-coinbase filters.
;;;  - keypoolrefill (wallet/rpc/addresses.cpp:218): TopUpKeyPool over the
;;;    active SPKMs (wallet.cpp:2591), then RefreshAllTXOs.
;;;  - simulaterawtransaction (wallet/rpc/wallet.cpp:489): the GetDebit /
;;;    IsMine balance delta over an array of raw txs, tracking outputs created
;;;    within the array (new_utxos) and rejecting double-spends across it.
;;;  - listaddressgroupings (wallet/rpc/addresses.cpp:157) over GetAddressGroupings
;;;    + GetAddressBalances (receive.cpp:276,304): co-spend clustering by
;;;    union-find, with change grouped with the inputs and lone owned outputs
;;;    seeding singletons.

;;; --- getreceivedbyaddress / getreceivedbylabel (coins.cpp:21) ---

(defun %wallet-addresses-for-label (wallet label)
  "Core CWallet::ListAddrBookAddresses(AddrBookFilter{label}): the non-change
book addresses whose label equals LABEL."
  (let ((result '()))
    (maphash (lambda (address entry)
               (when (and (addr-book-entry-label entry)
                          (equal (addr-book-entry-label entry) label))
                 (push address result)))
             (wallet-address-book wallet))
    result))

(defun %wallet-received-total (wallet output-scripts min-depth include-immature)
  "Σ over mapWallet of the values of outputs whose script is in the
OUTPUT-SCRIPTS set (Core GetReceived's tally), applying the shared tx-level
filters (depth, sub-1-conf coinbase, immature coinbase). Caller holds the
wallet lock."
  (let ((amount 0))
    (maphash
     (lambda (txid wtx)
       (declare (ignore txid))
       (let ((depth (wallet-tx-depth wallet wtx)))
         (unless (or (< depth min-depth)
                     (and (%wtx-coinbase-p wtx) (< depth 1))
                     (and (wallet-tx-immature-coinbase-p wallet wtx)
                          (not include-immature)))
           (loop for output across (bl.ser:transaction-outputs
                                    (wallet-tx-tx wtx))
                 do (when (gethash (bl.ser:tx-out-script-pubkey
                                    output)
                                   output-scripts)
                      (incf amount (bl.ser:tx-out-value
                                    output)))))))
     (wallet-map-wallet wallet))
    amount))

(defun %rpc-getreceived (node params by-label)
  "Core GetReceived: total received by an address (BY-LABEL nil) or by every
address with a label (BY-LABEL t). PARAMS: (address|label minconf
include_immature_coinbase)."
  (let* ((wallet (wallet-for-request node))
         (min-depth (if (second params) (second params) 1))
         (include-immature (bl.rpc:positional-bool (third params))))
    (unless (integerp min-depth)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+ :message "minconf must be an integer"))
    (with-wallet-lock (wallet)
      (let ((output-scripts (make-hash-table :test 'equalp)))
        (if by-label
            (let ((addresses (%wallet-addresses-for-label
                              wallet (%label-from-value (first params)))))
              (unless addresses
                (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                                  :message "Label not found in wallet"))
              (dolist (address addresses)
                (multiple-value-bind (type script)
                    (bl.crypto:decode-address address
                                                        (wallet-network wallet))
                  (declare (ignore type))
                  (when (and script (%wallet-script-mine-p wallet script))
                    (setf (gethash script output-scripts) t)))))
            (multiple-value-bind (type script)
                (and (stringp (first params))
                     (bl.crypto:decode-address (first params)
                                                         (wallet-network wallet)))
              (unless type
                (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                                  :message "Invalid Bitcoin address"))
              (when (%wallet-script-mine-p wallet script)
                (setf (gethash script output-scripts) t))))
        (when (zerop (hash-table-count output-scripts))
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                            :message "Address not found in wallet"))
        (bl.rpc:satoshi->btc (%wallet-received-total wallet output-scripts min-depth
                                      include-immature))))))

(bl.rpc:define-rpc "getreceivedbyaddress" (node params)
  "Total amount received by an address in txs with >= minconf confirmations
(Bitcoin Core getreceivedbyaddress). PARAMS: (address minconf
include_immature_coinbase)."
  (%rpc-getreceived node params nil))

(bl.rpc:define-rpc "getreceivedbylabel" (node params)
  "Total amount received across all addresses carrying a label (Bitcoin Core
getreceivedbylabel). PARAMS: (label minconf include_immature_coinbase)."
  (%rpc-getreceived node params t))

;;; --- listreceivedbyaddress / listreceivedbylabel (transactions.cpp:75) ---

(defstruct (received-tally (:constructor %make-received-tally))
  "Core ListReceived's tallyitem for one destination."
  (amount 0 :type integer)
  (conf most-positive-fixnum :type integer)  ; numeric_limits<int>::max sentinel
  (txids '()))                               ; wtx txids, reversed

(defun %map-wallet-in-txid-order (wallet)
  "The wallet's transactions as a list of wtx, ordered by TXID.

Core's mapWallet is std::unordered_map<Txid, CWalletTx, SaltedTxidHasher>
(wallet/wallet.h:498) and the RPCs that walk it take it as it stands, so the
order a caller sees is derived from the TXID and a per-process salt -- it is
not the order the transactions arrived in, and Core's own tests rely on
that. A hash table walked with MAPHASH here gives ARRIVAL order instead, and
the difference is observable: wallet_resendwallettransactions.py:97-117
bumps a child transaction until listreceivedbyaddress reports it BEFORE its
parent, which under arrival order can never happen, because the newest child
is always last. That loop ran 1,470 times before a replacement finally
failed for an unrelated reason.

Ordered by the txid as a client SEES it (the reversed hex the RPCs print)
rather than by a salted hash: deterministic where Core's is not, which a
test can rely on, and it varies with the transaction rather than with when
it was seen, which is the property the order has to have."
  (let ((rows '()))
    (maphash (lambda (txid wtx)
               (push (cons (bl.rpc:hash-to-hex txid) wtx) rows))
             (wallet-map-wallet wallet))
    (mapcar #'cdr (sort rows #'string< :key #'car))))

(defun %wallet-received-map-tally (wallet min-depth include-immature filter-address)
  "Core ListReceived's mapTally: address-string -> received-tally over
mapWallet outputs that are IsMine (and, when FILTER-ADDRESS, equal to it).
Caller holds the wallet lock."
  (let ((tally (make-hash-table :test 'equal)))
    (dolist (wtx (%map-wallet-in-txid-order wallet))
      (let ((depth (wallet-tx-depth wallet wtx)))
         (unless (or (< depth min-depth)
                     (and (%wtx-coinbase-p wtx) (< depth 1))
                     (and (wallet-tx-immature-coinbase-p wallet wtx)
                          (not include-immature)))
           (loop for output across (bl.ser:transaction-outputs
                                    (wallet-tx-tx wtx))
                 for script = (bl.ser:tx-out-script-pubkey
                               output)
                 for address = (bl.rpc:script->address script (wallet-network wallet))
                 do (when (and address
                               (or (null filter-address)
                                   (equal address filter-address))
                               (%wallet-script-mine-p wallet script))
                      (let ((item (or (gethash address tally)
                                      (setf (gethash address tally)
                                            (%make-received-tally)))))
                        (incf (received-tally-amount item)
                              (bl.ser:tx-out-value output))
                        (setf (received-tally-conf item)
                              (min (received-tally-conf item) depth))
                        (push (wallet-tx-txid wtx) (received-tally-txids item))))))))
    tally))

(defun %listreceived-address-obj (address label item)
  "One listreceivedbyaddress result object (Core func's non-by_label branch)."
  (let ((amount (if item (received-tally-amount item) 0))
        (conf (if item (received-tally-conf item) most-positive-fixnum)))
    `(("address" . ,address)
      ("amount" . ,(bl.rpc:satoshi->btc amount))
      ("confirmations" . ,(if (= conf most-positive-fixnum) 0 conf))
      ("label" . ,label)
      ("txids" . ,(if (and item (received-tally-txids item))
                      (mapcar #'bl.rpc:hash-to-hex (reverse (received-tally-txids item)))
                      #())))))

(bl.rpc:define-rpc "listreceivedbyaddress" (node params)
  "Balances by receiving address (Bitcoin Core listreceivedbyaddress).
PARAMS: (minconf include_empty include_watchonly address_filter
include_immature_coinbase)."
  (let* ((wallet (wallet-for-request node))
         (min-depth (if (first params) (first params) 1))
         (include-empty (bl.rpc:positional-bool (second params)))
         (address-filter (fourth params))
         (include-immature (bl.rpc:positional-bool (fifth params))))
    (unless (integerp min-depth)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+ :message "minconf must be an integer"))
    (with-wallet-lock (wallet)
      (let ((filter-address nil))
        (when (and address-filter (stringp address-filter)
                   (plusp (length address-filter)))
          (unless (nth-value 0 (bl.crypto:decode-address
                                address-filter (wallet-network wallet)))
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                              :message "address_filter parameter was invalid"))
          (setf filter-address address-filter))
        (let ((tally (%wallet-received-map-tally
                      wallet min-depth include-immature filter-address))
              (result '()))
          (flet ((emit (address label)
                   (let ((item (gethash address tally)))
                     (when (or item include-empty)
                       (push (%listreceived-address-obj address label item)
                             result)))))
            (if filter-address
                ;; FindAddressBookEntry(allow_change=false): skips change.
                (multiple-value-bind (label purpose found)
                    (wallet-find-address-book-entry wallet filter-address)
                  (declare (ignore purpose))
                  (when found (emit filter-address label)))
                ;; ForEachAddrBookEntry, skipping change (nil label = IsChange).
                (maphash (lambda (address entry)
                           (when (addr-book-entry-label entry)
                             (emit address (addr-book-entry-label entry))))
                         (wallet-address-book wallet))))
          (or (nreverse result) #()))))))

(bl.rpc:define-rpc "listreceivedbylabel" (node params)
  "Received amounts by label (Bitcoin Core listreceivedbylabel). PARAMS:
(minconf include_empty include_watchonly include_immature_coinbase)."
  (let* ((wallet (wallet-for-request node))
         (min-depth (if (first params) (first params) 1))
         (include-empty (bl.rpc:positional-bool (second params)))
         (include-immature (bl.rpc:positional-bool (fourth params))))
    (unless (integerp min-depth)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+ :message "minconf must be an integer"))
    (with-wallet-lock (wallet)
      (let ((tally (%wallet-received-map-tally wallet min-depth include-immature nil))
            (label-amount (make-hash-table :test 'equal))
            (label-conf (make-hash-table :test 'equal))
            (result '()))
        ;; label_tally: fold each non-change address's tally into its label.
        (maphash
         (lambda (address entry)
           (let ((label (addr-book-entry-label entry)))
             (when label
               (let ((item (gethash address tally)))
                 (when (or item include-empty)
                   (incf (gethash label label-amount 0)
                         (if item (received-tally-amount item) 0))
                   (setf (gethash label label-conf most-positive-fixnum)
                         (min (gethash label label-conf most-positive-fixnum)
                              (if item (received-tally-conf item)
                                  most-positive-fixnum))))))))
         (wallet-address-book wallet))
        (maphash (lambda (label amount)
                   (let ((conf (gethash label label-conf most-positive-fixnum)))
                     (push `(("amount" . ,(bl.rpc:satoshi->btc amount))
                             ("confirmations" . ,(if (= conf most-positive-fixnum)
                                                     0 conf))
                             ("label" . ,label))
                           result)))
                 label-amount)
        (or (sort result #'string<
                  :key (lambda (o) (cdr (assoc "label" o :test #'string=))))
            #())))))

;;; --- keypoolrefill (addresses.cpp:218; wallet.cpp:2580,2591) ---

(defun %wallet-active-spkms (wallet)
  "Core CWallet::GetActiveScriptPubKeyMans: the active external + internal
SPKMs (one per output type on each side)."
  (append (loop for spkm being the hash-values of (wallet-external-spkms wallet)
                collect spkm)
          (loop for spkm being the hash-values of (wallet-internal-spkms wallet)
                collect spkm)))

(bl.rpc:define-rpc "keypoolrefill" (node params)
  "Refill each active descriptor keypool up to NEWSIZE new keys (Bitcoin Core
keypoolrefill). PARAMS: (newsize). 0/omitted uses the wallet's keypool size."
  (let ((wallet (wallet-for-request node))
        (newsize (first params)))
    (when (and newsize (not (integerp newsize)))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+ :message "newsize must be an integer"))
    (when (and (integerp newsize) (minusp newsize))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "Invalid parameter, expected valid size."))
    (with-wallet-lock (wallet)
      ;; Refilling derives new keys, which a locked wallet cannot do.
      (wallet-ensure-unlocked wallet)
      ;; 0 => TopUp's -keypool default.
      (let ((kp-size (if (integerp newsize) newsize 0))
            (spkms (%wallet-active-spkms wallet)))
        (dolist (spkm spkms)
          (spkm-top-up wallet spkm kp-size))
        ;; GetKeyPoolSize (sum across active SPKMs) must reach the request.
        (when (< (reduce #'+ spkms :key #'spkm-keypool-count :initial-value 0)
                 kp-size)
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                            :message "Error refreshing keypool."))
        (wallet-refresh-all-txos wallet)
        nil))))

;;; --- simulaterawtransaction (wallet.cpp:489) ---

(bl.rpc:define-rpc "simulaterawtransaction" (node params)
  "Wallet balance change from signing+broadcasting the given raw txs (Bitcoin
Core simulaterawtransaction). PARAMS: (rawtxs options). Returns
{\"balance_change\": <btc>}.

An input that neither an earlier transaction in the array creates nor the
chain (or the mempool) still holds is -8 \"One or more transaction inputs are
missing or have been spent already\", as Core reports it: it runs
chain().findCoins over each transaction's inputs and refuses an outpoint whose
coin IsSpent -- which includes one nothing knows at all (wallet/rpc/wallet.cpp,
simulaterawtransaction). Without that check the balance change of a
transaction spending an output that does not exist was reported as a number
rather than refused."
  (let ((wallet (wallet-for-request node))
        (rawtxs (bl.rpc:positional-array (first params))))
    (unless (or (null rawtxs) (listp rawtxs))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-type-error+ :message "rawtxs must be an array"))
    (with-wallet-lock (wallet)
      (let ((changes 0)
            (new-utxos (make-hash-table :test 'equalp))  ; outpoint-key -> value
            (spent (make-hash-table :test 'equalp)))
        (dolist (raw rawtxs)
          (let* ((tx (bl.rpc:decode-hex-tx-or-error
                      raw "Transaction hex string decoding failure."))
                 ;; Core fetches this transaction's input coins before the
                 ;; debit loop, once per transaction; an outpoint missing from
                 ;; the map is its cleared, IsSpent coin.
                 (coins (bl.rpc:find-coins node tx)))
            ;; Debit: these inputs are spent when the tx is broadcast.
            (bl.ser:dovector
                (input (bl.ser:transaction-inputs tx))
              (let* ((prevout (bl.ser:tx-in-previous-output input))
                     (txid (bl.ser:outpoint-hash prevout))
                     (vout (bl.ser:outpoint-index prevout))
                     (key (%wtx-outpoint-key txid vout)))
                (when (gethash key spent)
                  (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                    :message "Transaction(s) are spending the same output more than once"))
                (multiple-value-bind (utxo-value present) (gethash key new-utxos)
                  (if present
                      (progn (decf changes utxo-value)
                             (remhash key new-utxos))
                      (progn
                        ;; Core's order: the same-output check, then the
                        ;; in-array outputs, and only then the chain.
                        (unless (gethash (cons txid vout) coins)
                          (error 'bl.rpc:rpc-error
                                 :code bl.rpc:+rpc-invalid-parameter+
                                 :message "One or more transaction inputs are missing or have been spent already"))
                        (decf changes (%wallet-input-debit wallet input)))))
                (setf (gethash key spent) t)))
            ;; Credit: outputs the wallet considers mine, also feeding new_utxos.
            (let ((hash (bl.ser:transaction-hash tx)))
              (loop for i from 0
                    for output across (bl.ser:transaction-outputs tx)
                    do (let ((value (if (%wallet-script-mine-p
                                         wallet
                                         (bl.ser:tx-out-script-pubkey
                                          output))
                                        (bl.ser:tx-out-value output)
                                        0)))
                         (setf (gethash (%wtx-outpoint-key hash i) new-utxos) value)
                         (incf changes value))))))
        `(("balance_change" . ,(bl.rpc:satoshi->btc changes)))))))

;;; --- listaddressgroupings (addresses.cpp:157; receive.cpp:276,304) ---

(defun %wallet-address-balances (wallet)
  "Core GetAddressBalances: address-string -> spendable satoshis, over owned
TXOs that are trusted, mature, and deep enough (>=0 confs from-me, else >=1);
a spent TXO contributes 0. Caller holds the wallet lock."
  (let ((balances (make-hash-table :test 'equal))
        (trusted-parents (make-hash-table :test 'equalp)))
    (maphash
     (lambda (key entry)
       (let* ((wtx (car entry))
              (index (cdr entry))
              (output (aref (bl.ser:transaction-outputs
                             (wallet-tx-tx wtx))
                            index))
              (script (bl.ser:tx-out-script-pubkey output)))
         (when (and (%wallet-tx-trusted-p wallet wtx trusted-parents)
                    (not (wallet-tx-immature-coinbase-p wallet wtx))
                    (>= (wallet-tx-depth wallet wtx)
                        (if (wallet-tx-from-me-cached wallet wtx) 0 1)))
           (let ((address (bl.rpc:script->address script (wallet-network wallet))))
             (when address
               (incf (gethash address balances 0)
                     (if (%wallet-outpoint-key-spent-p wallet key)
                         0
                         (bl.ser:tx-out-value output))))))))
     (wallet-txos wallet))
    balances))

(defun %tx-input-owned-address (wallet input)
  "The wallet address of INPUT's prevout when the wallet owns that TXO, else
NIL (Core InputIsMine + ExtractDestination on the mapWallet prevout)."
  (let ((prevout (bl.ser:tx-in-previous-output input)))
    (multiple-value-bind (pwtx pindex)
        (wallet-get-txo wallet
                        (bl.ser:outpoint-hash prevout)
                        (bl.ser:outpoint-index prevout))
      (when pwtx
        (values (bl.rpc:script->address
                 (bl.ser:tx-out-script-pubkey
                  (aref (bl.ser:transaction-outputs
                         (wallet-tx-tx pwtx))
                        pindex))
                 (wallet-network wallet))
                t)))))

(defun %wallet-raw-groupings (wallet)
  "The pre-merge groupings (each a list of address strings) Core builds in
GetAddressGroupings before the union-find: co-spent owned inputs plus change
form one group per tx, and every lone owned output seeds a singleton. Caller
holds the wallet lock."
  (let ((groupings '()))
    (maphash
     (lambda (txid wtx)
       (declare (ignore txid))
       (let ((tx (wallet-tx-tx wtx))
             (grouping '()))
         (when (plusp (length (bl.ser:transaction-inputs tx)))
           (let ((any-mine nil))
             (bl.ser:dovector
                 (input (bl.ser:transaction-inputs tx))
               (multiple-value-bind (address owned) (%tx-input-owned-address wallet input)
                 (when owned
                   (setf any-mine t)
                   (when address (pushnew address grouping :test #'equal)))))
             (when any-mine
               (loop for output across (bl.ser:transaction-outputs tx)
                     do (when (%wallet-output-change-p wallet output)
                          (let ((address (bl.rpc:script->address
                                          (bl.ser:tx-out-script-pubkey
                                           output)
                                          (wallet-network wallet))))
                            (when address (pushnew address grouping :test #'equal))))))
             (when grouping (push grouping groupings))))
         ;; lone owned outputs, each its own group
         (loop for output across (bl.ser:transaction-outputs tx)
               for script = (bl.ser:tx-out-script-pubkey output)
               do (when (%wallet-script-mine-p wallet script)
                    (let ((address (bl.rpc:script->address script (wallet-network wallet))))
                      (when address (push (list address) groupings)))))))
     (wallet-map-wallet wallet))
    groupings))

(defun %merge-groupings (groupings)
  "Union-find merge of GROUPINGS (lists of address strings) into the maximal
disjoint groups (Core's setmap loop). Returns a list of address-string lists."
  (let ((setmap (make-hash-table :test 'equal)))  ; address -> shared holder (list of members)
    (dolist (grouping groupings)
      (let ((merged (make-hash-table :test 'equal)))
        (dolist (address grouping)
          (setf (gethash address merged) t)
          (let ((holder (gethash address setmap)))
            (when holder
              (dolist (a (car holder)) (setf (gethash a merged) t)))))
        (let* ((members (loop for a being the hash-keys of merged collect a))
               (holder (list members)))
          (dolist (a members) (setf (gethash a setmap) holder)))))
    (let ((seen '()) (result '()))
      (loop for holder being the hash-values of setmap
            do (unless (member holder seen :test #'eq)
                 (push holder seen)
                 (push (car holder) result)))
      result)))

(bl.rpc:define-rpc "listaddressgroupings" (node params)
  "Groups of addresses whose common ownership is public through shared use as
inputs or change (Bitcoin Core listaddressgroupings). Each address entry is a
[address, amount, label?] array — encoded as a Lisp vector so the JSON layer
emits an array, not an object."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (let ((balances (%wallet-address-balances wallet))
            (groupings (%merge-groupings (%wallet-raw-groupings wallet)))
            (result '()))
        (dolist (grouping groupings)
          (push (mapcar
                 (lambda (address)
                   (multiple-value-bind (label purpose found)
                       (wallet-find-address-book-entry wallet address :allow-change t)
                     (declare (ignore purpose))
                     (apply #'vector address (bl.rpc:satoshi->btc (gethash address balances 0))
                            (when found (list label)))))
                 (sort (copy-list grouping) #'string<))
                result))
        (or (nreverse result) #())))))
