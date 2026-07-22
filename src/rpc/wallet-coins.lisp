(in-package #:bitcoin-lisp.rpc)

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

(defun %amount-from-value (value)
  "Core AmountFromValue: a JSON number or decimal string in BTC to
satoshis, at most 8 fraction digits, within MoneyRange. Sub-satoshi
precision is REJECTED like Core (which parses the decimal text exactly):
rationals/integers are checked exactly; floats (JSON doubles, which cannot
carry the original decimal text) are accepted only when they sit within
double-representation noise of a whole satoshi — 0.001 sat at amounts
where doubles are satoshi-exact, scaling with magnitude above ~2^48 sats
where a double's nearest representation may be off by up to ~0.4 sat."
  (let ((satoshis
          (cond
            ((rationalp value)
             (let ((scaled (* (rational value) 100000000)))
               (unless (integerp scaled)
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               scaled))
            ((floatp value)
             ;; JSON numbers arrive as double-floats; the 2^-48 relative
             ;; slack only covers double-representation noise. Wider
             ;; single-float slack exists solely for direct Lisp callers
             ;; (tests) whose literals default to single precision.
             (let* ((scaled (* (rational value) 100000000))
                    (nearest (round scaled))
                    (tolerance (max 1/1000
                                    (* (abs scaled)
                                       (if (typep value 'double-float)
                                           (expt 2 -48)
                                           (expt 2 -19))))))
               (unless (<= (abs (- scaled nearest)) tolerance)
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               nearest))
            ((stringp value)
             (let* ((dot (position #\. value))
                    (whole (if dot (subseq value 0 dot) value))
                    (frac (if dot (subseq value (1+ dot)) "")))
               (unless (and (plusp (length whole))
                            (every #'digit-char-p whole)
                            (<= (length frac) 8)
                            (or (null dot) (plusp (length frac)))
                            (every #'digit-char-p frac))
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               (+ (* (parse-integer whole) 100000000)
                  (if (plusp (length frac))
                      (* (parse-integer frac)
                         (expt 10 (- 8 (length frac))))
                      0))))
            (t (error 'rpc-error :code +rpc-type-error+
                                 :message "Amount is not a number or string")))))
    (unless (<= 0 satoshis bitcoin-lisp.validation:+max-money+)
      (error 'rpc-error :code +rpc-type-error+ :message "Amount out of range"))
    satoshis))

(defun %btc (satoshis)
  "Satoshis as the BTC double the RPC layer emits."
  (/ satoshis 100000000.0d0))

(defun %feerate-fee (rate-sat-kvb size)
  "Core CFeeRate::GetFee at d3056bc: ceil(RATE-SAT-KVB * SIZE / 1000) —
FeeFrac::EvaluateFeeUp (feerate.cpp:20-27, feefrac.h:196-223, \"rounding
up\"). Round-up is what makes per-part fee budgets additive: the sum of
rounded-up parts always covers the rounded-up whole, so the exact-fee loop's
fee_needed <= current_fee invariant holds. Pure integer math; negative
rates never occur in the wallet."
  (declare (type integer rate-sat-kvb size))
  (ceiling (* rate-sat-kvb size) 1000))

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
    (bitcoin-lisp.storage:leveldb-put (wallet-db wallet)
                                      (wdb-key-lockedutxo txid index)
                                      +wdb-lockedutxo-value+
                                      :sync t))
  t)

(defun wallet-unlock-all-coins (wallet)
  "Core CWallet::UnlockAllCoins: drop every lock, erasing persisted records."
  (dolist (entry (wallet-locked-utxos wallet))
    (when (third entry)
      (bitcoin-lisp.storage:leveldb-delete
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
              (output (aref (bitcoin-lisp.serialization:transaction-outputs
                             (wallet-tx-tx wtx))
                            index))
              (is-trusted (%wallet-tx-trusted-p wallet wtx trusted-parents))
              (depth (wallet-tx-depth wallet wtx)))
         (when (and (not (%wallet-outpoint-key-spent-p wallet key))
                    (or allow-used
                        (not (wallet-spent-key-script-p
                              wallet
                              (bitcoin-lisp.serialization:tx-out-script-pubkey
                               output)))))
           (let ((credit (bitcoin-lisp.serialization:tx-out-value output)))
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
  (out-desc-solvable-p (desc-spkm-desc spkm)))

(defun %spkm-sub-scripts (spkm script)
  "(values redeem-script witness-script) known for SCRIPT at its range
index — the provider GetCScript lookups behind listunspent's redeemScript/
witnessScript fields and getaddressinfo's embedded object."
  (let ((pos (spkm-is-mine spkm script))
        (desc (desc-spkm-desc spkm))
        (cache (desc-spkm-cache spkm)))
    (when pos
      (case (out-desc-kind desc)
        (:sh
         (let* ((sub (out-desc-sub desc))
                (redeem (first (out-desc-expand-from-cache sub pos cache))))
           (if (and redeem (eq (out-desc-kind sub) :wsh))
               (values redeem
                       (first (out-desc-expand-from-cache
                               (out-desc-sub sub) pos cache)))
               (values redeem nil))))
        (:wsh
         (values nil (first (out-desc-expand-from-cache
                             (out-desc-sub desc) pos cache))))
        (:combo
         ;; The P2SH form of combo() wraps its P2WPKH script.
         (let ((scripts (out-desc-expand-from-cache desc pos cache)))
           (when (and scripts (= (length scripts) 4)
                      (equalp script (fourth scripts)))
             (values (third scripts) nil))))
        (t nil)))))

(defun %wallet-coin-output-type (wallet script)
  "Core GetOutputType over Solver's class, reclassifying a solvable P2SH
whose redeem script is a witness program as :p2sh-segwit."
  (let ((type (bitcoin-lisp.validation:classify-script script)))
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
                    (member (bitcoin-lisp.validation:classify-script redeem)
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

(defparameter +output-type-order+ '(:legacy :p2sh-segwit :bech32 :bech32m :unknown)
  "CoinsResult::All concatenation order (OutputType enum order).")

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
                (output (aref (bitcoin-lisp.serialization:transaction-outputs
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
                   (let ((v3 (= (bitcoin-lisp.serialization:transaction-version
                                 (wallet-tx-tx wtx))
                                bitcoin-lisp.mempool:+truc-version+)))
                     (if (= tx-version bitcoin-lisp.mempool:+truc-version+)
                         (progn
                           (unless v3 (return-from skip-coin))
                           (when (wallet-tx-truc-child wtx)
                             (return-from skip-coin))
                           (when (and mempool
                                      (> (bitcoin-lisp.mempool:mempool-ancestor-stats
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
             (let ((value (bitcoin-lisp.serialization:tx-out-value output))
                   (script (bitcoin-lisp.serialization:tx-out-script-pubkey output)))
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
                                          (%feerate-fee feerate input-bytes)))
                               :effective-value
                               (when feerate
                                 (- value (if (minusp input-bytes)
                                              0
                                              (%feerate-fee feerate input-bytes))))
                               :output-type output-type)))
                   (if (and check-version-trucness (zerop depth)
                            (= (bitcoin-lisp.serialization:transaction-version
                                (wallet-tx-tx wtx))
                               bitcoin-lisp.mempool:+truc-version+))
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
    (loop for type in +output-type-order+
          nconc (nreverse (gethash type buckets)))))

;;; --- Inferred descriptors (script/descriptor.cpp InferDescriptor) ---

(defun %desc-key-origin-info (key pubkey pos)
  "(values fingerprint-bytes path) — Core PubkeyProvider::GetKeyOrigin: a
BIP32 key's fingerprint is its root key's, the path is the key's fixed path
plus the range position; a const key's fingerprint is its own keyid prefix
with an empty path; a declared [origin] prefixes both."
  (multiple-value-bind (base-fpr base-path)
      (if (desc-key-extkey key)
          (values (subseq (bitcoin-lisp.crypto:hash160
                           (bitcoin-lisp.crypto:ext-key-public-bytes
                            (desc-key-extkey key)))
                          0 4)
                  (append (desc-key-path key)
                          (ecase (desc-key-derive key)
                            (:none nil)
                            (:unhardened (list pos))
                            (:hardened (list (logior pos #x80000000))))))
          (values (subseq (bitcoin-lisp.crypto:hash160 pubkey) 0 4) nil))
    (if (desc-key-origin-fingerprint key)
        (values (desc-key-origin-fingerprint key)
                (append (desc-key-origin-path key) base-path))
        (values base-fpr base-path))))

(defun %inferred-key-string (key pubkey pos &key xonly)
  "The concrete key expression InferPubkey renders: [origin]pubkey-hex,
hardened markers as 'h' (apostrophe=false)."
  (multiple-value-bind (fpr path) (%desc-key-origin-info key pubkey pos)
    (format nil "[~A~A]~A"
            (bitcoin-lisp.crypto:bytes-to-hex fpr)
            (%format-key-path path nil)
            (bitcoin-lisp.crypto:bytes-to-hex
             (if xonly (%key-xonly-bytes pubkey) pubkey)))))

(defun %infer-desc-body (desc script scripts pairs pos)
  "The inferred descriptor body for SCRIPT owned by DESC at POS. SCRIPTS is
DESC's expansion at POS, PAIRS the (desc-key . derived-pubkey) list in
expression order. NIL when the descriptor kind cannot be inferred."
  (flet ((key-string (pair &key xonly)
           (%inferred-key-string (car pair) (cdr pair) pos :xonly xonly)))
    (ecase (out-desc-kind desc)
      ((:addr :raw) nil)
      (:pk (format nil "pk(~A)" (key-string (first pairs))))
      (:pkh (format nil "pkh(~A)" (key-string (first pairs))))
      (:wpkh (format nil "wpkh(~A)" (key-string (first pairs))))
      (:combo
       ;; InferScript works from the concrete script, so combo() infers to
       ;; the specific form the script takes.
       (let ((n (position script scripts :test #'equalp))
             (ks (key-string (first pairs))))
         (case n
           (0 (format nil "pk(~A)" ks))
           (1 (format nil "pkh(~A)" ks))
           (2 (format nil "wpkh(~A)" ks))
           (3 (format nil "sh(wpkh(~A))" ks))
           (t nil))))
      ((:multi :sortedmulti)
       ;; Core infers the expanded script, so sortedmulti() reports multi()
       ;; with the keys in script (BIP67-sorted) order.
       (let ((ordered (if (eq (out-desc-kind desc) :sortedmulti)
                          (sort (copy-list pairs) #'%pubkey-lessp :key #'cdr)
                          pairs)))
         (format nil "multi(~D~{,~A~})"
                 (out-desc-threshold desc)
                 (mapcar (lambda (pair) (key-string pair)) ordered))))
      (:sh (let ((sub (%infer-desc-body (out-desc-sub desc) nil scripts pairs pos)))
             (and sub (format nil "sh(~A)" sub))))
      (:wsh (let ((sub (%infer-desc-body (out-desc-sub desc) nil scripts pairs pos)))
              (and sub (format nil "wsh(~A)" sub))))
      (:tr (format nil "tr(~A)" (key-string (first pairs) :xonly t)))
      (:rawtr (format nil "rawtr(~A)" (key-string (first pairs) :xonly t))))))

(defun %spkm-expansion-pairs (spkm pos)
  "(values scripts pairs) — the SPKM's expansion at POS with each derived
pubkey paired to its desc-key, in expression order."
  (multiple-value-bind (scripts pubkeys)
      (out-desc-expand-from-cache (desc-spkm-desc spkm) pos
                                  (desc-spkm-cache spkm))
    (when scripts
      (values scripts
              (mapcar #'cons (out-desc-ordered-keys (desc-spkm-desc spkm))
                      pubkeys)))))

(defun %wallet-inferred-descriptor (wallet script)
  "Core InferDescriptor via the owning SPKM: the checksummed concrete
descriptor for SCRIPT, or NIL when the wallet cannot solve it."
  (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet script)
    (when (and spkm (%spkm-solvable-p spkm))
      (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
        (when scripts
          (let ((body (%infer-desc-body (desc-spkm-desc spkm) script
                                        scripts pairs pos)))
            (and body (descriptor-add-checksum body))))))))

;;; --- getbalance / getbalances (wallet/rpc/coins.cpp:164,401) ---

(defun %get-avoid-reuse-flag (wallet param)
  "Core GetAvoidReuseFlag: null/omitted PARAM keeps the wallet's avoid_reuse
flag as the default (Core's isNull check); an explicit boolean (incl. the
+json-false+ sentinel) overrides it. Requesting it on a wallet without the
flag errors."
  (let* ((can (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+))
         (avoid (if (null param) can (%positional-bool param))))
    (when (and avoid (not can))
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "wallet does not have the \"avoid reuse\" feature enabled"))
    avoid))

(defun %wallet-last-processed-block (wallet)
  "Core AppendLastProcessedBlock's object."
  `(("hash" . ,(if (wallet-last-block-hash wallet)
                   (hash-to-hex (wallet-last-block-hash wallet))
                   (make-string 64 :initial-element #\0)))
    ("height" . ,(wallet-last-block-height wallet))))

(defun rpc-getbalance (node params)
  "The wallet's total available (trusted) balance (Bitcoin Core getbalance).
PARAMS: (dummy minconf include_watchonly avoid_reuse)."
  (let ((wallet (wallet-for-request node))
        (dummy (first params))
        (minconf (or (second params) 0)))
    (when (and dummy (not (equal dummy "*")))
      (error 'rpc-error :code +rpc-method-deprecated+
                        :message "dummy first argument must be excluded or set to \"*\"."))
    (unless (integerp minconf)
      (error 'rpc-error :code +rpc-type-error+ :message "minconf must be an integer"))
    (with-wallet-lock (wallet)
      (let ((avoid-reuse (%get-avoid-reuse-flag wallet (fourth params))))
        (%btc (wallet-get-balance wallet :min-depth minconf
                                         :avoid-reuse avoid-reuse))))))

(defun rpc-getbalances (node params)
  "All wallet balances (Bitcoin Core getbalances)."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (multiple-value-bind (trusted untrusted immature)
          (wallet-get-balance wallet)
        `(("mine"
           . (("trusted" . ,(%btc trusted))
              ("untrusted_pending" . ,(%btc untrusted))
              ("immature" . ,(%btc immature))
              ;; With AVOID_REUSE the default balance excludes reused
              ;; addresses; "used" is the difference against the full one.
              ,@(when (wallet-flag-set-p wallet +wallet-flag-avoid-reuse+)
                  (multiple-value-bind (full-trusted full-untrusted)
                      (wallet-get-balance wallet :avoid-reuse nil)
                    `(("used" . ,(%btc (- (+ full-trusted full-untrusted)
                                          trusted untrusted))))))))
          ("lastprocessedblock" . ,(%wallet-last-processed-block wallet)))))))

;;; --- listunspent (wallet/rpc/coins.cpp:456) ---

(defun %listunspent-entry (node wallet coin avoid-reuse)
  (let* ((output (wallet-coin-output coin))
         (script (bitcoin-lisp.serialization:tx-out-script-pubkey output))
         (address (%script->address script (wallet-network wallet)))
         (txid (wallet-coin-txid coin))
         (mempool (bitcoin-lisp::node-mempool node)))
    (multiple-value-bind (spkm) (%wallet-owning-spkm wallet script)
      (multiple-value-bind (redeem witness) (and spkm (%spkm-sub-scripts spkm script))
        `(("txid" . ,(hash-to-hex txid))
          ("vout" . ,(wallet-coin-index coin))
          ,@(when address
              `(("address" . ,address)
                ,@(multiple-value-bind (label purpose found)
                      (wallet-find-address-book-entry wallet address)
                    (declare (ignore purpose))
                    (when found `(("label" . ,label))))
                ,@(when redeem
                    `(("redeemScript" . ,(bitcoin-lisp.crypto:bytes-to-hex redeem))))
                ,@(when witness
                    `(("witnessScript" . ,(bitcoin-lisp.crypto:bytes-to-hex witness))))))
          ("scriptPubKey" . ,(bitcoin-lisp.crypto:bytes-to-hex script))
          ("amount" . ,(%btc (bitcoin-lisp.serialization:tx-out-value output)))
          ("confirmations" . ,(wallet-coin-depth coin))
          ,@(when (and (zerop (wallet-coin-depth coin))
                       mempool
                       (bitcoin-lisp.mempool:mempool-has mempool txid))
              (multiple-value-bind (acount avsize afees)
                  (bitcoin-lisp.mempool:mempool-ancestor-stats mempool txid)
                `(("ancestorcount" . ,acount)
                  ("ancestorsize" . ,avsize)
                  ("ancestorfees" . ,afees))))
          ("spendable" . t)
          ("solvable" . ,(json-bool (wallet-coin-solvable coin)))
          ,@(when (wallet-coin-solvable coin)
              (let ((desc (%wallet-inferred-descriptor wallet script)))
                (when desc `(("desc" . ,desc)))))
          ("parent_descs" . ,(or (%wallet-parent-descs wallet script) #()))
          ,@(when avoid-reuse
              `(("reused" . ,(json-bool (wallet-spent-key-script-p wallet script)))))
          ("safe" . ,(json-bool (wallet-coin-safe coin))))))))

(defun rpc-listunspent (node params)
  "Unspent wallet outputs with between minconf and maxconf confirmations
(Bitcoin Core listunspent). PARAMS: (minconf maxconf addresses
include_unsafe query_options)."
  (let ((wallet (wallet-for-request node))
        (minconf (if (and (>= (length params) 1) (first params)) (first params) 1))
        (maxconf (if (and (>= (length params) 2) (second params)) (second params) 9999999))
        (addresses (third params))
        (include-unsafe (%positional-bool-or (fourth params) t))
        (options (fifth params))
        (min-amount 0)
        (max-amount nil)
        (min-sum-amount nil)
        (max-count nil)
        (include-immature nil)
        (filter-scripts nil))
    (unless (and (integerp minconf) (integerp maxconf))
      (error 'rpc-error :code +rpc-type-error+
                        :message "minconf and maxconf must be integers"))
    (when addresses
      (unless (listp addresses)
        (error 'rpc-error :code +rpc-type-error+ :message "addresses must be an array"))
      (setf filter-scripts (make-hash-table :test 'equalp))
      (dolist (address addresses)
        (multiple-value-bind (type script)
            (and (stringp address)
                 (bitcoin-lisp.crypto:decode-address address
                                                     (wallet-network wallet)))
          (unless type
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message (format nil "Invalid Bitcoin address: ~A" address)))
          (when (gethash script filter-scripts)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message (format nil "Invalid parameter, duplicated address: ~A" address)))
          (setf (gethash script filter-scripts) t))))
    (when options
      (multiple-value-bind (value present) (%oval options "minimumAmount")
        (when present (setf min-amount (%amount-from-value value))))
      (multiple-value-bind (value present) (%oval options "maximumAmount")
        (when present (setf max-amount (%amount-from-value value))))
      (multiple-value-bind (value present) (%oval options "minimumSumAmount")
        (when present (setf min-sum-amount (%amount-from-value value))))
      (multiple-value-bind (value present) (%oval options "maximumCount")
        (when present
          (unless (integerp value)
            (error 'rpc-error :code +rpc-type-error+
                              :message "maximumCount must be an integer"))
          (setf max-count value)))
      (multiple-value-bind (value present) (%oval options "include_immature_coinbase")
        (when present (setf include-immature (and value t)))))
    (with-node-lock (node)   ; mempool ancestry reads; node -> wallet order
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
            (let* ((script (bitcoin-lisp.serialization:tx-out-script-pubkey
                            (wallet-coin-output coin))))
              (when (or (null filter-scripts) (gethash script filter-scripts))
                (push (%listunspent-entry node wallet coin avoid-reuse)
                      results))))
          (or (nreverse results) #()))))))

;;; --- lockunspent / listlockunspent (wallet/rpc/coins.cpp:214,347) ---

(defun rpc-lockunspent (node params)
  "Lock or unlock unspent outputs (Bitcoin Core lockunspent). PARAMS:
(unlock transactions persistent)."
  (let ((wallet (wallet-for-request node))
        (unlock (%positional-bool (first params)))
        (outputs-param (second params))
        (persistent (%positional-bool (third params))))
    (with-wallet-lock (wallet)
      (when (null outputs-param)
        (when unlock (wallet-unlock-all-coins wallet))
        (return-from rpc-lockunspent t))
      (unless (listp outputs-param)
        (error 'rpc-error :code +rpc-type-error+
                          :message "transactions must be an array"))
      (let ((outputs '()))
        (dolist (o outputs-param)
          (multiple-value-bind (txid-value txid-present) (%oval o "txid")
            (multiple-value-bind (vout-value vout-present) (%oval o "vout")
              (unless (and txid-present (stringp txid-value))
                (error 'rpc-error :code +rpc-type-error+
                                  :message "Missing txid key"))
              (unless (and vout-present (integerp vout-value))
                (error 'rpc-error :code +rpc-type-error+
                                  :message "Missing vout key"))
              (when (minusp vout-value)
                (error 'rpc-error :code +rpc-invalid-parameter+
                                  :message "Invalid parameter, vout cannot be negative"))
              (let* ((txid (%wallet-parse-txid txid-value))
                     (wtx (wallet-get-wallet-tx wallet txid)))
                (unless wtx
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "Invalid parameter, unknown transaction"))
                (unless (< vout-value
                           (length (bitcoin-lisp.serialization:transaction-outputs
                                    (wallet-tx-tx wtx))))
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "Invalid parameter, vout index out of bounds"))
                (when (wallet-outpoint-spent-p wallet txid vout-value)
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "Invalid parameter, expected unspent output"))
                (let ((locked (wallet-locked-coin-p wallet txid vout-value)))
                  (when (and unlock (not locked))
                    (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message "Invalid parameter, expected locked output"))
                  (when (and (not unlock) locked (not persistent))
                    (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message "Invalid parameter, output already locked")))
                (push (cons txid vout-value) outputs)))))
        (dolist (outpoint (nreverse outputs))
          (if unlock
              (%wallet-unlock-coin wallet (car outpoint) (cdr outpoint))
              (wallet-lock-coin wallet (car outpoint) (cdr outpoint) persistent)))
        t))))

(defun rpc-listlockunspent (node params)
  "Temporarily unspendable outputs (Bitcoin Core listlockunspent)."
  (declare (ignore params))
  (let ((wallet (wallet-for-request node)))
    (with-wallet-lock (wallet)
      (or (mapcar (lambda (entry)
                    `(("txid" . ,(hash-to-hex (first entry)))
                      ("vout" . ,(second entry))))
                  (reverse (wallet-locked-utxos wallet)))
          #()))))

;;; --- getaddressinfo (wallet/rpc/addresses.cpp:368) ---

(defun %describe-address-fields (type wit-ver wit-prog)
  "Core DescribeAddress: isscript/iswitness/witness_version/witness_program
per destination class."
  (case type
    (:p2pkh `(("isscript" . ,+json-false+) ("iswitness" . ,+json-false+)))
    (:p2sh `(("isscript" . t) ("iswitness" . ,+json-false+)))
    (:p2wpkh `(("isscript" . ,+json-false+) ("iswitness" . t)
               ("witness_version" . 0)
               ("witness_program" . ,(bitcoin-lisp.crypto:bytes-to-hex wit-prog))))
    (:p2wsh `(("isscript" . t) ("iswitness" . t)
              ("witness_version" . 0)
              ("witness_program" . ,(bitcoin-lisp.crypto:bytes-to-hex wit-prog))))
    (:p2tr `(("isscript" . t) ("iswitness" . t)
             ("witness_version" . 1)
             ("witness_program" . ,(bitcoin-lisp.crypto:bytes-to-hex wit-prog))))
    (t `(("iswitness" . ,(json-bool wit-ver))
         ,@(when wit-ver
             `(("witness_version" . ,wit-ver)
               ("witness_program" . ,(bitcoin-lisp.crypto:bytes-to-hex wit-prog))))))))

(defun %expansion-pubkey-by-hash160 (pairs hash)
  (find hash pairs :test #'equalp
                   :key (lambda (pair) (bitcoin-lisp.crypto:hash160 (cdr pair)))))

(defun %process-sub-script (wallet sub-script pairs)
  "Core DescribeWalletAddressVisitor::ProcessSubScript: fields describing a
known redeem/witness script. Returns (values fields hoisted-pubkey-hex)."
  (multiple-value-bind (type data)
      (bitcoin-lisp.validation:classify-script sub-script)
    (let ((fields
            `(("script" . ,(bitcoin-lisp.validation:script-type-to-string type))
              ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex sub-script))))
          (sub-address (%script->address sub-script (wallet-network wallet)))
          (hoisted nil))
      (cond
        (sub-address
         (multiple-value-bind (sub-type sub-spk sub-wv sub-wp)
             (bitcoin-lisp.crypto:decode-address sub-address (wallet-network wallet))
           (declare (ignore sub-spk))
           (let ((detail (%describe-address-fields sub-type sub-wv sub-wp))
                 (wallet-detail
                   (when (and (eq sub-type :p2wpkh) pairs)
                     (let ((pair (%expansion-pubkey-by-hash160 pairs sub-wp)))
                       (when pair
                         `(("pubkey" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                         (cdr pair)))))))))
             (when wallet-detail
               (setf hoisted (cdr (assoc "pubkey" wallet-detail :test #'equal))))
             (setf fields
                   (append fields
                           `(,@(when hoisted `(("pubkey" . ,hoisted)))
                             ("embedded"
                              . (,@detail
                                 ,@wallet-detail
                                 ("address" . ,sub-address)
                                 ("scriptPubKey"
                                  . ,(bitcoin-lisp.crypto:bytes-to-hex
                                      sub-script))))))))))
        ((eq type :multisig)
         (setf fields
               (append fields
                       `(("sigsrequired" . ,(getf data :m))
                         ("pubkeys" . ,(mapcar #'bitcoin-lisp.crypto:bytes-to-hex
                                               (getf data :pubkeys))))))))
      (values fields hoisted))))

(defun %wallet-address-detail (wallet type script wit-prog spkm pos)
  "Core DescribeWalletAddress's visitor: pubkey/iscompressed/embedded fields
for a wallet-solvable destination."
  (let ((pairs (and spkm (nth-value 1 (%spkm-expansion-pairs spkm pos)))))
    (case type
      (:p2pkh
       (let ((pair (and pairs (%expansion-pubkey-by-hash160
                               pairs (subseq script 3 23)))))
         (when pair
           `(("pubkey" . ,(bitcoin-lisp.crypto:bytes-to-hex (cdr pair)))
             ("iscompressed" . ,(json-bool (= (length (cdr pair)) 33)))))))
      (:p2wpkh
       (let ((pair (and pairs (%expansion-pubkey-by-hash160 pairs wit-prog))))
         (when pair
           `(("pubkey" . ,(bitcoin-lisp.crypto:bytes-to-hex (cdr pair)))))))
      ((:p2sh :p2wsh)
       (multiple-value-bind (redeem witness)
           (and spkm (%spkm-sub-scripts spkm script))
         (let ((sub (if (eq type :p2sh) redeem witness)))
           (when sub
             (%process-sub-script wallet sub pairs)))))
      (t nil))))

(defun %wallet-dest-key-origin (spkm script type)
  "(values desc-key pubkey pos) for single-key destinations —
GetKeyForDestination's supported classes: P2PKH, P2WPKH, P2SH-P2WPKH, and
key-path-only P2TR."
  (let* ((desc (desc-spkm-desc spkm))
         (kind (out-desc-kind desc))
         (pos (spkm-is-mine spkm script)))
    (when (and pos
               (case type
                 ((:p2pkh :p2wpkh) (member kind '(:pkh :wpkh :combo)))
                 (:p2sh (or (and (eq kind :sh)
                                 (eq (out-desc-kind (out-desc-sub desc)) :wpkh))
                            (eq kind :combo)))
                 (:p2tr (eq kind :tr))
                 (t nil)))
      (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
        (declare (ignore scripts))
        (when pairs
          (values (car (first pairs)) (cdr (first pairs)) pos))))))

(defun rpc-getaddressinfo (node params)
  "Information about a bitcoin address (Bitcoin Core getaddressinfo).
PARAMS: (address)."
  (let ((wallet (wallet-for-request node))
        (address (first params)))
    (multiple-value-bind (type script wit-ver wit-prog)
        (and (stringp address)
             (bitcoin-lisp.crypto:decode-address address (wallet-network wallet)))
      (unless type
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message "Invalid address"))
      (with-wallet-lock (wallet)
        (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet script)
          (let* ((solvable (and spkm (%spkm-solvable-p spkm) t))
                 (desc (and solvable (%wallet-inferred-descriptor wallet script)))
                 (key-origin (and spkm
                                  (multiple-value-list
                                   (%wallet-dest-key-origin spkm script type)))))
            `(("address" . ,address)
              ("scriptPubKey" . ,(bitcoin-lisp.crypto:bytes-to-hex script))
              ("ismine" . ,(json-bool spkm))
              ("solvable" . ,(json-bool solvable))
              ,@(when desc `(("desc" . ,desc)))
              ,@(when spkm
                  `(("parent_desc" . ,(%spkm-descriptor-string wallet spkm nil))))
              ("iswatchonly" . ,+json-false+)
              ,@(%describe-address-fields type wit-ver wit-prog)
              ,@(%wallet-address-detail wallet type script wit-prog spkm pos)
              ;; ScriptIsChange: IsMine without a (non-change) book entry.
              ("ischange" . ,(json-bool
                              (and spkm
                                   (not (nth-value 2 (wallet-find-address-book-entry
                                                      wallet address))))))
              ,@(when (and spkm (first key-origin))
                  (destructuring-bind (key pubkey key-pos) key-origin
                    (multiple-value-bind (fpr path)
                        (%desc-key-origin-info key pubkey key-pos)
                      `(("timestamp" . ,(desc-spkm-creation-time spkm))
                        ("hdkeypath" . ,(format nil "m~A" (%format-key-path path nil)))
                        ;; Descriptor wallets have no HD seed; Core reports
                        ;; the null id (CKeyMetadata default).
                        ("hdseedid" . ,(make-string 40 :initial-element #\0))
                        ("hdmasterfingerprint"
                         . ,(bitcoin-lisp.crypto:bytes-to-hex fpr))))))
              ("labels" . ,(multiple-value-bind (label purpose found)
                               (wallet-find-address-book-entry wallet address)
                             (declare (ignore purpose))
                             (if found (list label) #()))))))))))

;;; --- setlabel / getaddressesbylabel / listlabels (addresses.cpp:118,515,576) ---

(defun rpc-setlabel (node params)
  "Set the label of an address (Bitcoin Core setlabel). PARAMS:
(address label)."
  (let ((wallet (wallet-for-request node))
        (address (first params)))
    (multiple-value-bind (type script)
        (and (stringp address)
             (bitcoin-lisp.crypto:decode-address address (wallet-network wallet)))
      (unless type
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message "Invalid Bitcoin address"))
      (let ((label (%label-from-value (second params))))
        (with-wallet-lock (wallet)
          (wallet-set-address-book wallet address label
                                   (if (%wallet-owning-spkm wallet script)
                                       "receive"
                                       "send"))))))
  nil)

(defun rpc-getaddressesbylabel (node params)
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
          (error 'rpc-error :code +rpc-wallet-invalid-label-name+
                            :message (format nil "No addresses with label ~A" label)))
        (sort result #'string< :key #'car)))))

(defun rpc-listlabels (node params)
  "All labels, optionally only those on addresses with PURPOSE (Bitcoin Core
listlabels). PARAMS: (purpose)."
  (let ((wallet (wallet-for-request node))
        (purpose-arg (first params))
        (purpose nil))
    (when (and purpose-arg (stringp purpose-arg) (plusp (length purpose-arg)))
      (unless (member purpose-arg '("send" "receive" "refund") :test #'equal)
        (error 'rpc-error :code +rpc-invalid-parameter+
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

(defun rpc-abandontransaction (node params)
  "Mark an in-wallet transaction and its wallet descendants abandoned
(Bitcoin Core abandontransaction). PARAMS: (txid)."
  (let ((wallet (wallet-for-request node))
        (txid (%wallet-parse-txid (first params))))
    (with-wallet-lock (wallet)
      (let ((wtx (wallet-get-wallet-tx wallet txid)))
        (unless wtx
          (error 'rpc-error :code +rpc-invalid-address-or-key+
                            :message "Invalid or non-wallet transaction id"))
        (unless (wallet-abandon-transaction wallet wtx)
          (error 'rpc-error :code +rpc-invalid-address-or-key+
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
           (loop for output across (bitcoin-lisp.serialization:transaction-outputs
                                    (wallet-tx-tx wtx))
                 do (when (gethash (bitcoin-lisp.serialization:tx-out-script-pubkey
                                    output)
                                   output-scripts)
                      (incf amount (bitcoin-lisp.serialization:tx-out-value
                                    output)))))))
     (wallet-map-wallet wallet))
    amount))

(defun %rpc-getreceived (node params by-label)
  "Core GetReceived: total received by an address (BY-LABEL nil) or by every
address with a label (BY-LABEL t). PARAMS: (address|label minconf
include_immature_coinbase)."
  (let* ((wallet (wallet-for-request node))
         (min-depth (if (second params) (second params) 1))
         (include-immature (%positional-bool (third params))))
    (unless (integerp min-depth)
      (error 'rpc-error :code +rpc-type-error+ :message "minconf must be an integer"))
    (with-wallet-lock (wallet)
      (let ((output-scripts (make-hash-table :test 'equalp)))
        (if by-label
            (let ((addresses (%wallet-addresses-for-label
                              wallet (%label-from-value (first params)))))
              (unless addresses
                (error 'rpc-error :code +rpc-wallet-error+
                                  :message "Label not found in wallet"))
              (dolist (address addresses)
                (multiple-value-bind (type script)
                    (bitcoin-lisp.crypto:decode-address address
                                                        (wallet-network wallet))
                  (declare (ignore type))
                  (when (and script (%wallet-script-mine-p wallet script))
                    (setf (gethash script output-scripts) t)))))
            (multiple-value-bind (type script)
                (and (stringp (first params))
                     (bitcoin-lisp.crypto:decode-address (first params)
                                                         (wallet-network wallet)))
              (unless type
                (error 'rpc-error :code +rpc-invalid-address-or-key+
                                  :message "Invalid Bitcoin address"))
              (when (%wallet-script-mine-p wallet script)
                (setf (gethash script output-scripts) t))))
        (when (zerop (hash-table-count output-scripts))
          (error 'rpc-error :code +rpc-wallet-error+
                            :message "Address not found in wallet"))
        (%btc (%wallet-received-total wallet output-scripts min-depth
                                      include-immature))))))

(defun rpc-getreceivedbyaddress (node params)
  "Total amount received by an address in txs with >= minconf confirmations
(Bitcoin Core getreceivedbyaddress). PARAMS: (address minconf
include_immature_coinbase)."
  (%rpc-getreceived node params nil))

(defun rpc-getreceivedbylabel (node params)
  "Total amount received across all addresses carrying a label (Bitcoin Core
getreceivedbylabel). PARAMS: (label minconf include_immature_coinbase)."
  (%rpc-getreceived node params t))

;;; --- listreceivedbyaddress / listreceivedbylabel (transactions.cpp:75) ---

(defstruct (received-tally (:constructor %make-received-tally))
  "Core ListReceived's tallyitem for one destination."
  (amount 0 :type integer)
  (conf most-positive-fixnum :type integer)  ; numeric_limits<int>::max sentinel
  (txids '()))                               ; wtx txids, reversed

(defun %wallet-received-map-tally (wallet min-depth include-immature filter-address)
  "Core ListReceived's mapTally: address-string -> received-tally over
mapWallet outputs that are IsMine (and, when FILTER-ADDRESS, equal to it).
Caller holds the wallet lock."
  (let ((tally (make-hash-table :test 'equal)))
    (maphash
     (lambda (txid wtx)
       (declare (ignore txid))
       (let ((depth (wallet-tx-depth wallet wtx)))
         (unless (or (< depth min-depth)
                     (and (%wtx-coinbase-p wtx) (< depth 1))
                     (and (wallet-tx-immature-coinbase-p wallet wtx)
                          (not include-immature)))
           (loop for output across (bitcoin-lisp.serialization:transaction-outputs
                                    (wallet-tx-tx wtx))
                 for script = (bitcoin-lisp.serialization:tx-out-script-pubkey
                               output)
                 for address = (%script->address script (wallet-network wallet))
                 do (when (and address
                               (or (null filter-address)
                                   (equal address filter-address))
                               (%wallet-script-mine-p wallet script))
                      (let ((item (or (gethash address tally)
                                      (setf (gethash address tally)
                                            (%make-received-tally)))))
                        (incf (received-tally-amount item)
                              (bitcoin-lisp.serialization:tx-out-value output))
                        (setf (received-tally-conf item)
                              (min (received-tally-conf item) depth))
                        (push (wallet-tx-txid wtx) (received-tally-txids item))))))))
     (wallet-map-wallet wallet))
    tally))

(defun %listreceived-address-obj (address label item)
  "One listreceivedbyaddress result object (Core func's non-by_label branch)."
  (let ((amount (if item (received-tally-amount item) 0))
        (conf (if item (received-tally-conf item) most-positive-fixnum)))
    `(("address" . ,address)
      ("amount" . ,(%btc amount))
      ("confirmations" . ,(if (= conf most-positive-fixnum) 0 conf))
      ("label" . ,label)
      ("txids" . ,(if (and item (received-tally-txids item))
                      (mapcar #'hash-to-hex (reverse (received-tally-txids item)))
                      #())))))

(defun rpc-listreceivedbyaddress (node params)
  "Balances by receiving address (Bitcoin Core listreceivedbyaddress).
PARAMS: (minconf include_empty include_watchonly address_filter
include_immature_coinbase)."
  (let* ((wallet (wallet-for-request node))
         (min-depth (if (first params) (first params) 1))
         (include-empty (%positional-bool (second params)))
         (address-filter (fourth params))
         (include-immature (%positional-bool (fifth params))))
    (unless (integerp min-depth)
      (error 'rpc-error :code +rpc-type-error+ :message "minconf must be an integer"))
    (with-wallet-lock (wallet)
      (let ((filter-address nil))
        (when (and address-filter (stringp address-filter)
                   (plusp (length address-filter)))
          (unless (nth-value 0 (bitcoin-lisp.crypto:decode-address
                                address-filter (wallet-network wallet)))
            (error 'rpc-error :code +rpc-wallet-error+
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

(defun rpc-listreceivedbylabel (node params)
  "Received amounts by label (Bitcoin Core listreceivedbylabel). PARAMS:
(minconf include_empty include_watchonly include_immature_coinbase)."
  (let* ((wallet (wallet-for-request node))
         (min-depth (if (first params) (first params) 1))
         (include-empty (%positional-bool (second params)))
         (include-immature (%positional-bool (fourth params))))
    (unless (integerp min-depth)
      (error 'rpc-error :code +rpc-type-error+ :message "minconf must be an integer"))
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
                     (push `(("amount" . ,(%btc amount))
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

(defun rpc-keypoolrefill (node params)
  "Refill each active descriptor keypool up to NEWSIZE new keys (Bitcoin Core
keypoolrefill). PARAMS: (newsize). 0/omitted uses the wallet's keypool size."
  (let ((wallet (wallet-for-request node))
        (newsize (first params)))
    (when (and newsize (not (integerp newsize)))
      (error 'rpc-error :code +rpc-type-error+ :message "newsize must be an integer"))
    (when (and (integerp newsize) (minusp newsize))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid parameter, expected valid size."))
    (with-wallet-lock (wallet)
      ;; 0 => TopUp's -keypool default.
      (let ((kp-size (if (integerp newsize) newsize 0))
            (spkms (%wallet-active-spkms wallet)))
        (dolist (spkm spkms)
          (spkm-top-up wallet spkm kp-size))
        ;; GetKeyPoolSize (sum across active SPKMs) must reach the request.
        (when (< (reduce #'+ spkms :key #'spkm-keypool-count :initial-value 0)
                 kp-size)
          (error 'rpc-error :code +rpc-wallet-error+
                            :message "Error refreshing keypool."))
        (wallet-refresh-all-txos wallet)
        nil))))

;;; --- simulaterawtransaction (wallet.cpp:489) ---

(defun rpc-simulaterawtransaction (node params)
  "Wallet balance change from signing+broadcasting the given raw txs (Bitcoin
Core simulaterawtransaction). PARAMS: (rawtxs options). Returns
{\"balance_change\": <btc>}. DIVERGENCE: Core also runs chain findCoins to
reject inputs that are missing or already spent on-chain; here the delta is
computed from wallet-owned prevouts (GetDebit) and the in-array new_utxos,
which yields the same balance_change without touching the chain UTXO set."
  (let ((wallet (wallet-for-request node))
        (rawtxs (first params)))
    (unless (or (null rawtxs) (listp rawtxs))
      (error 'rpc-error :code +rpc-type-error+ :message "rawtxs must be an array"))
    (with-wallet-lock (wallet)
      (let ((changes 0)
            (new-utxos (make-hash-table :test 'equalp))  ; outpoint-key -> value
            (spent (make-hash-table :test 'equalp)))
        (dolist (raw rawtxs)
          (unless (stringp raw)
            (error 'rpc-error :code +rpc-deserialization-error+
                              :message "Transaction hex string decoding failure."))
          (let ((tx (handler-case
                        (bitcoin-lisp.serialization:parse-tx-payload
                         (bitcoin-lisp.crypto:hex-to-bytes raw))
                      (error ()
                        (error 'rpc-error :code +rpc-deserialization-error+
                                          :message "Transaction hex string decoding failure.")))))
            ;; Debit: these inputs are spent when the tx is broadcast.
            (bitcoin-lisp.serialization:dovector
                (input (bitcoin-lisp.serialization:transaction-inputs tx))
              (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                     (key (%wtx-outpoint-key
                           (bitcoin-lisp.serialization:outpoint-hash prevout)
                           (bitcoin-lisp.serialization:outpoint-index prevout))))
                (when (gethash key spent)
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "Transaction(s) are spending the same output more than once"))
                (multiple-value-bind (utxo-value present) (gethash key new-utxos)
                  (if present
                      (progn (decf changes utxo-value)
                             (remhash key new-utxos))
                      (decf changes (%wallet-input-debit wallet input))))
                (setf (gethash key spent) t)))
            ;; Credit: outputs the wallet considers mine, also feeding new_utxos.
            (let ((hash (bitcoin-lisp.serialization:transaction-hash tx)))
              (loop for i from 0
                    for output across (bitcoin-lisp.serialization:transaction-outputs tx)
                    do (let ((value (if (%wallet-script-mine-p
                                         wallet
                                         (bitcoin-lisp.serialization:tx-out-script-pubkey
                                          output))
                                        (bitcoin-lisp.serialization:tx-out-value output)
                                        0)))
                         (setf (gethash (%wtx-outpoint-key hash i) new-utxos) value)
                         (incf changes value))))))
        `(("balance_change" . ,(%btc changes)))))))

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
              (output (aref (bitcoin-lisp.serialization:transaction-outputs
                             (wallet-tx-tx wtx))
                            index))
              (script (bitcoin-lisp.serialization:tx-out-script-pubkey output)))
         (when (and (%wallet-tx-trusted-p wallet wtx trusted-parents)
                    (not (wallet-tx-immature-coinbase-p wallet wtx))
                    (>= (wallet-tx-depth wallet wtx)
                        (if (wallet-tx-from-me-cached wallet wtx) 0 1)))
           (let ((address (%script->address script (wallet-network wallet))))
             (when address
               (incf (gethash address balances 0)
                     (if (%wallet-outpoint-key-spent-p wallet key)
                         0
                         (bitcoin-lisp.serialization:tx-out-value output))))))))
     (wallet-txos wallet))
    balances))

(defun %tx-input-owned-address (wallet input)
  "The wallet address of INPUT's prevout when the wallet owns that TXO, else
NIL (Core InputIsMine + ExtractDestination on the mapWallet prevout)."
  (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input)))
    (multiple-value-bind (pwtx pindex)
        (wallet-get-txo wallet
                        (bitcoin-lisp.serialization:outpoint-hash prevout)
                        (bitcoin-lisp.serialization:outpoint-index prevout))
      (when pwtx
        (values (%script->address
                 (bitcoin-lisp.serialization:tx-out-script-pubkey
                  (aref (bitcoin-lisp.serialization:transaction-outputs
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
         (when (plusp (length (bitcoin-lisp.serialization:transaction-inputs tx)))
           (let ((any-mine nil))
             (bitcoin-lisp.serialization:dovector
                 (input (bitcoin-lisp.serialization:transaction-inputs tx))
               (multiple-value-bind (address owned) (%tx-input-owned-address wallet input)
                 (when owned
                   (setf any-mine t)
                   (when address (pushnew address grouping :test #'equal)))))
             (when any-mine
               (loop for output across (bitcoin-lisp.serialization:transaction-outputs tx)
                     do (when (%wallet-output-change-p wallet output)
                          (let ((address (%script->address
                                          (bitcoin-lisp.serialization:tx-out-script-pubkey
                                           output)
                                          (wallet-network wallet))))
                            (when address (pushnew address grouping :test #'equal))))))
             (when grouping (push grouping groupings))))
         ;; lone owned outputs, each its own group
         (loop for output across (bitcoin-lisp.serialization:transaction-outputs tx)
               for script = (bitcoin-lisp.serialization:tx-out-script-pubkey output)
               do (when (%wallet-script-mine-p wallet script)
                    (let ((address (%script->address script (wallet-network wallet))))
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

(defun rpc-listaddressgroupings (node params)
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
                     (apply #'vector address (%btc (gethash address balances 0))
                            (when found (list label)))))
                 (sort (copy-list grouping) #'string<))
                result))
        (or (nreverse result) #())))))
