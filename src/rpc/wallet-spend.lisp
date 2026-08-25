(in-package #:bitcoin-lisp.rpc)

;;; Wallet P4: spending (docs/wallet-plan.md §5 P4). FUNDS-CRITICAL.
;;;
;;; Ports, from Bitcoin Core @ d3056bc:
;;;  - Coin selection (src/wallet/coinselection.{h,cpp}): SelectCoinsBnB,
;;;    KnapsackSolver (+ ApproximateBestSubset), SelectCoinsSRD, OutputGroup,
;;;    SelectionResult with the waste metric (RecalculateWaste / GetChange),
;;;    GenerateChangeTarget. CoinGrinder is DEFERRED (wallet-plan §7.3): it
;;;    only activates when the effective feerate exceeds 3x the long-term
;;;    feerate; until it is ported that branch simply contributes no
;;;    candidate result (BnB/Knapsack/SRD still run — divergence noted at
;;;    %choose-selection-result).
;;;  - The selection cascade (src/wallet/spend.cpp): GroupOutputs,
;;;    AttemptSelection, ChooseSelectionResult, SelectCoins,
;;;    AutomaticCoinSelection with Core's exact CoinEligibilityFilter rounds.
;;;  - CreateTransactionInternal / CreateTransaction (APS retry) /
;;;    FundTransaction (spend.cpp:1063-1546), DiscourageFeeSniping,
;;;    CalculateMaximumSignedTxSize / CalculateMaximumSignedInputSize via
;;;    descriptor MaxSatisfactionWeight arithmetic (script/descriptor.cpp).
;;;  - Wallet fees (src/wallet/fees.cpp): GetMinimumFeeRate, GetDiscardRate,
;;;    GetRequiredFeeRate.
;;;  - Wallet signing: CWallet::SignTransaction over the descriptor SPKMs'
;;;    derived keys, through the same signing machinery as
;;;    signrawtransactionwithkey (%sign-tx-inputs).
;;;  - CommitTransaction + SubmitTxMemoryPoolAndRelay +
;;;    ResubmitWalletTransactions / MaybeResendWalletTxs (wallet.cpp:
;;;    2019-2148, 2455).
;;;  - RPCs (src/wallet/rpc/spend.cpp): sendtoaddress, sendmany, send,
;;;    sendall, fundrawtransaction, signrawtransactionwithwallet.
;;;
;;; Money discipline: ALL amounts and feerates in this file are INTEGER
;;; satoshis / integer sat-per-kvB. The only floats are at the JSON edge
;;; (%btc on output; %amount-from-value / %feerate-from-value convert
;;; incoming JSON numbers to integers immediately).
;;;
;;; Locking: the whole build+sign+commit+broadcast sequence runs under
;;; node-lock -> wallet-lock (never inverted). Fee estimation, mempool
;;; ancestry, chain reads, and the final mempool submission all happen
;;; inside the same node-lock hold, so the tip cannot move between fee
;;; computation and broadcast (Core holds cs_wallet and takes cs_main
;;; inside; our lock order is the reverse, so we take both up front).
;;; The mempool-accept hook that fires during submission fans out over the
;;; manager's LOCK-FREE wallet snapshot, so no code path ever takes the
;;; manager lock while holding a wallet lock; the full contract lives on
;;; with-wallet-lock (wallet.lisp).
;;;
;;; Known divergences from Core (each justified inline at its site):
;;;  1. ECDSA size estimation assumes 72-byte signatures (Core use_max_sig):
;;;     our signer does not grind low-R nonces, so 71-byte estimates could
;;;     undershoot. Safe direction: estimated size >= actual, paid feerate
;;;     >= target.
;;;  2. CoinGrinder deferred (above).
;;;  3. No unconfirmed-ancestor bump fees (Core calculateIndividualBumpFees/
;;;     calculateCombinedBumpFee): our node has no bump-fee calculator, so
;;;     bump fees are 0. Spending unconfirmed inputs pays the target feerate
;;;     on the new tx itself but does not additionally bump its ancestors
;;;     (slower confirmation possible; never overpays).
;;;  4. -walletrejectlongchains' pre-commit checkChainLimits simulation is
;;;     not run; the mempool applies the real cluster limits at broadcast,
;;;     and a rejected tx stays in the wallet as unbroadcast (Core commits
;;;     wallet-first on broadcast failure too).
;;;  5. Before commit we run our own script verifier over every input (an
;;;     EXTRA rail Core does not have): a tx that does not verify against
;;;     the exact spent scriptPubKeys/amounts is never stored or relayed.

;;; --- Wallet policy defaults (Core wallet.h:104-137) ---

(defvar *wallet-min-tx-fee* 1000
  "sat/kvB floor for wallet transactions (Core -mintxfee,
DEFAULT_TRANSACTION_MINFEE = 1000).")

(defvar *wallet-discard-rate* 10000
  "sat/kvB ceiling for the discard rate (Core -discardfee,
DEFAULT_DISCARD_FEE = 10000).")

(defvar *wallet-consolidate-feerate* 10000
  "Long-term feerate estimate, sat/kvB (Core -consolidatefeerate,
DEFAULT_CONSOLIDATE_FEERATE = 10000).")

(defvar *wallet-confirm-target* 6
  "Default confirmation target (Core -txconfirmtarget,
DEFAULT_TX_CONFIRM_TARGET = 6).")

(defvar *wallet-signal-rbf* t
  "Core -walletrbf, DEFAULT_WALLET_RBF = true: new spends signal BIP125.")

(defvar *wallet-spend-zero-conf-change* t
  "Core -spendzeroconfchange default true.")

(defvar *wallet-reject-long-chains* t
  "Core -walletrejectlongchains, DEFAULT_WALLET_REJECT_LONG_CHAINS = true;
gates the unlimited-ancestors eligibility filter.")

(defvar *wallet-max-aps-fee* 0
  "Core -maxapsfee, DEFAULT_MAX_AVOIDPARTIALSPEND_FEE = 0: use the
avoid-partial-spends grouping when it costs no more than this many extra
satoshis (-1 disables the APS retry).")

(defconstant +change-lower+ 50000 "coinselection.h CHANGE_LOWER.")
(defconstant +change-upper+ 1000000 "coinselection.h CHANGE_UPPER.")
(defconstant +bnb-total-tries+ 100000 "coinselection.cpp TOTAL_TRIES.")
(defconstant +output-group-max-entries+ 100 "spend.cpp OUTPUT_GROUP_MAX_ENTRIES.")
(defconstant +max-bip125-rbf-sequence+ #xFFFFFFFD "util/rbf.h.")
(defconstant +max-sequence-nonfinal+ #xFFFFFFFE "CTxIn::MAX_SEQUENCE_NONFINAL.")
(defconstant +sequence-final+ #xFFFFFFFF "CTxIn::SEQUENCE_FINAL.")
(defconstant +locktime-threshold+ 500000000 "script.h LOCKTIME_THRESHOLD.")
(defconstant +dummy-nested-p2wpkh-input-size+ 91
  "Core DUMMY_NESTED_P2WPKH_INPUT_SIZE (tx sizes fallback for unknown change).")
(defconstant +min-standard-tx-nonwitness-size+ 65 "policy.h.")
(defconstant +default-ancestor-limit+ 25
  "Core DEFAULT_ANCESTOR_LIMIT / DEFAULT_DESCENDANT_LIMIT — the legacy
package limits chain.getPackageLimits still reports for the eligibility
filters (cluster limits are enforced by the mempool itself).")
(defconstant +truc-max-weight+ (* 4 bitcoin-lisp.mempool:+truc-max-vsize+)
  "policy/truc_policy.h TRUC_MAX_WEIGHT.")
(defconstant +truc-child-max-weight+
  (* 4 bitcoin-lisp.mempool:+truc-child-max-vsize+)
  "policy/truc_policy.h TRUC_CHILD_MAX_WEIGHT.")
(defconstant +uint64-max+ (1- (ash 1 64)))

(defconstant +max-fee-exceeded-message+
  (if (boundp '+max-fee-exceeded-message+)
      (symbol-value '+max-fee-exceeded-message+)
      "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)")
  "common/messages.cpp TransactionErrorString(MAX_FEE_EXCEEDED).")

;;; --- Deterministic-bindable RNG (Core FastRandomContext stand-in) ---
;;;
;;; Randomized wallet behaviors (recipient/coin shuffles, SRD, Knapsack's
;;; approximation, change position, anti-fee-sniping locktime jitter,
;;; resend scheduling) draw from a wrng. Production code seeds one from the
;;; OS RNG per operation, exactly like Core constructs a FastRandomContext;
;;; tests bind *wallet-rng* to a fixed-seed instance for determinism. None
;;; of these uses are cryptographic (Core's comment in
;;; ApproximateBestSubset: the randomness serves no security purpose).

(defstruct (wrng (:constructor make-wrng (state)))
  (state 0 :type (unsigned-byte 64)))

(defvar *wallet-rng* nil
  "When bound to a wrng, all wallet-spend randomness draws from it
(deterministic tests); otherwise each operation seeds a fresh one.")

(defun %fresh-wrng ()
  (make-wrng (let ((bytes (ironclad:random-data 8)))
               (loop with acc = 0
                     for b across bytes
                     do (setf acc (logior (ash acc 8) b))
                     finally (return acc)))))

(defun %rng ()
  (or *wallet-rng* (%fresh-wrng)))

(defun wrng-next64 (rng)
  "SplitMix64 step."
  (let ((z (setf (wrng-state rng)
                 (logand (+ (wrng-state rng) #x9E3779B97F4A7C15)
                         +uint64-max+))))
    (setf z (logand (* (logxor z (ash z -30)) #xBF58476D1CE4E5B9) +uint64-max+))
    (setf z (logand (* (logxor z (ash z -27)) #x94D049BB133111EB) +uint64-max+))
    (logxor z (ash z -31))))

(defun wrng-randrange (rng n)
  "Uniform integer in [0, N). N >= 1."
  (declare (type (integer 1) n))
  (if (= n 1)
      0
      ;; Rejection sampling over the smallest covering power of two.
      (let ((mask (1- (ash 1 (integer-length (1- n))))))
        (loop for v = (logand (wrng-next64 rng) mask)
              when (< v n) return v))))

(defun wrng-randbool (rng)
  (= 1 (logand (wrng-next64 rng) 1)))

(defun wrng-shuffle (rng list)
  "Fisher-Yates shuffle; returns a fresh list."
  (let ((v (coerce list 'simple-vector)))
    (loop for i from (1- (length v)) downto 1
          for j = (wrng-randrange rng (1+ i))
          do (rotatef (aref v i) (aref v j)))
    (coerce v 'list)))

;;; --- Money / feerate helpers (integer satoshis throughout) ---

(defun %compact-size-size (n)
  "GetSizeOfCompactSize."
  (cond ((< n 253) 1)
        ((<= n #xFFFF) 3)
        ((<= n #xFFFFFFFF) 5)
        (t 9)))

;; %txout-serialize-size — GetSerializeSize(CTxOut) — lives in methods.lisp,
;; which is compiled first. It used to be defined here as well, identically;
;; two same-named defuns in one package meant the later file silently won.

(defun %dust-threshold-at-rate (script rate-sat-kvb)
  "Core GetDustThreshold(txout, feerate) at an arbitrary feerate (the
validation-layer dust-threshold is specialized to the 3000 sat/kvB dust
relay rate)."
  (if (and (plusp (length script)) (= (aref script 0) #x6a)) ; OP_RETURN
      0
      (let* ((spend-size (if (bitcoin-lisp.validation::output-witness-program-p
                              script)
                             (+ 32 4 1 (floor 107 4) 4)
                             (+ 32 4 1 107 4)))
             (nsize (+ (%txout-serialize-size script) spend-size)))
        (%feerate-fee rate-sat-kvb nsize))))

(defun %output-dust-p (value script)
  "Core IsDust at the dust relay feerate: strictly nValue < threshold
(policy.cpp). No positive-threshold guard: an OP_RETURN output's threshold
is 0, so a NEGATIVE value (SFFO driving a data output below zero) IS dust —
that is exactly the check that turns it into Core's \"transaction amount is
too small to pay the fee\" error instead of committing a broken tx."
  (< value (bitcoin-lisp.validation:dust-threshold script)))

(defun %format-money (satoshis)
  "Core FormatMoney: BTC decimal string, trailing zeros trimmed but at
least two decimals kept."
  (multiple-value-bind (quotient remainder) (truncate (abs satoshis) 100000000)
    (let ((str (format nil "~D.~8,'0D" quotient remainder)))
      (let ((end (length str)))
        (loop while (and (char= (char str (1- end)) #\0)
                         (digit-char-p (char str (- end 3))))
              do (decf end))
        (concatenate 'string (if (minusp satoshis) "-" "") (subseq str 0 end))))))

(defun %format-feerate-sat-vb (rate-sat-kvb)
  "CFeeRate::ToString(FeeRateFormat::SAT_VB): \"%d.%03d sat/vB\"."
  (multiple-value-bind (whole frac) (truncate rate-sat-kvb 1000)
    (format nil "~D.~3,'0D sat/vB" whole frac)))

(defun %feerate-from-value (value)
  "Core AmountFromValue(fee_rate, /*decimals=*/3): a sat/vB number or
decimal string with at most 3 fraction digits, to integer sat/kvB."
  (let ((milli
          (cond
            ((integerp value) (* value 1000))
            ((rationalp value) (let ((m (* value 1000)))
                                 (unless (integerp m)
                                   (error 'rpc-error :code +rpc-type-error+
                                                     :message "Invalid amount"))
                                 m))
            ((floatp value)
             (let ((m (rational value)))
               (setf m (* m 1000))
               ;; JSON doubles: accept values that are integral to within
               ;; double noise, exactly like UniValue's decimal parse.
               (unless (< (abs (- m (round m))) 1/1000)
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               (round m)))
            ((stringp value)
             (let* ((dot (position #\. value))
                    (whole (if dot (subseq value 0 dot) value))
                    (frac (if dot (subseq value (1+ dot)) "")))
               (unless (and (plusp (length whole))
                            (every #'digit-char-p whole)
                            (<= (length frac) 3)
                            (or (null dot) (plusp (length frac)))
                            (every #'digit-char-p frac))
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid amount"))
               (+ (* (parse-integer whole) 1000)
                  (if (plusp (length frac))
                      (* (parse-integer frac) (expt 10 (- 3 (length frac))))
                      0))))
            (t (error 'rpc-error :code +rpc-type-error+
                                 :message "Amount is not a number or string")))))
    (when (minusp milli)
      (error 'rpc-error :code +rpc-type-error+ :message "Amount out of range"))
    milli))

;;; --- Coin control (Core CCoinControl, the subset the P4 RPCs drive) ---

(defstruct wcc-preset
  "One pre-selected input (Core PreselectedInput)."
  txout            ; external tx-out struct (NIL when the input is wallet-owned)
  sequence         ; explicit nSequence, or NIL
  script-sig       ; existing scriptSig bytes (fundrawtransaction), or NIL
  script-witness   ; existing witness stack (list), or NIL
  weight           ; explicit max input weight, or NIL
  (position 0))    ; order among the preset inputs

(defstruct wcc
  "Core CCoinControl."
  dest-change                ; change scriptPubKey bytes, or NIL
  change-type                ; output-type keyword, or NIL
  (allow-other-inputs t)
  include-unsafe
  feerate                    ; explicit feerate, sat/kvB, or NIL
  override-feerate
  confirm-target
  (fee-mode :unset)          ; :unset / :economical / :conservative
  (signal-bip125-rbf :unset) ; :unset / T / NIL
  avoid-partial-spends
  avoid-address-reuse        ; Core default false
  (min-depth 0)
  (max-depth 9999999)
  (selected '())             ; (txid . vout) conses, selection order
  (presets (make-hash-table :test 'equalp))  ; (txid . vout) -> wcc-preset
  (external-pubkeys (make-hash-table :test 'equalp))  ; hash160 -> pubkey
  (external-scripts (make-hash-table :test 'equalp))  ; hash160/sha256 -> script
  locktime
  (version 2)
  max-tx-weight)

(defun wcc-select (cc txid vout)
  "Core CCoinControl::Select: the preset entry for the outpoint, creating it."
  (let ((key (cons txid vout)))
    (or (gethash key (wcc-presets cc))
        (progn
          (setf (wcc-selected cc) (append (wcc-selected cc) (list key)))
          (setf (gethash key (wcc-presets cc))
                (make-wcc-preset :position (1- (length (wcc-selected cc)))))))))

(defun wcc-selected-p (cc txid vout)
  (nth-value 1 (gethash (cons txid vout) (wcc-presets cc))))

(defun %wcc-signal-rbf (cc)
  (if (eq (wcc-signal-bip125-rbf cc) :unset)
      *wallet-signal-rbf*
      (wcc-signal-bip125-rbf cc)))

(defun %wcc-add-external-script (cc script)
  (setf (gethash (bitcoin-lisp.crypto:hash160 script) (wcc-external-scripts cc))
        script)
  (setf (gethash (bitcoin-lisp.crypto:sha256 script) (wcc-external-scripts cc))
        script))

;;; --- Wallet fee estimation (Core wallet/fees.cpp) ---

(defun %wallet-required-fee-rate ()
  "GetRequiredFeeRate: max(-mintxfee, min relay feerate), sat/kvB."
  (max *wallet-min-tx-fee* bitcoin-lisp.mempool:*min-relay-fee-rate*))

(defun %estimate-smart-fee-sat-kvb (node target conservative)
  "estimateSmartFee via the node's fee estimator, as integer sat/kvB;
0 when no reliable estimate exists (Core CFeeRate(0)). The estimator's
sat/vB value (possibly non-integral) is converted to integer sat/kvB HERE,
at the estimate boundary — all downstream fee math is integer."
  (let ((estimator (bitcoin-lisp:node-fee-estimator node)))
    (if (and estimator
             (bitcoin-lisp.mempool:fee-estimator-ready-p estimator))
        (multiple-value-bind (rate error)
            (bitcoin-lisp.mempool:estimate-fee-rate
             estimator (max 1 (min target 1008))
             :mode (if conservative :conservative :economical))
          (if error 0 (max 0 (round (* (rational rate) 1000)))))
        0)))

(defun %wallet-minimum-fee-rate (node cc)
  "Core GetMinimumFeeRate. Returns (values rate-sat-kvb reason), REASON one
of :payment :estimate :fallback :mempool-min :required. Caller holds the
node lock (fee estimator + mempool reads)."
  (let ((rate 0)
        (reason :estimate))
    (cond
      ((wcc-feerate cc)
       (setf rate (wcc-feerate cc) reason :payment)
       (when (wcc-override-feerate cc)
         (return-from %wallet-minimum-fee-rate (values rate reason))))
      (t
       (let* ((target (or (wcc-confirm-target cc) *wallet-confirm-target*))
              (conservative (case (wcc-fee-mode cc)
                              (:conservative t)
                              (:economical nil)
                              (t (not (%wcc-signal-rbf cc))))))
         (setf rate (%estimate-smart-fee-sat-kvb node target conservative))
         (when (zerop rate)
           (setf rate bitcoin-lisp:*wallet-fallback-fee*
                 reason :fallback)
           (when (zerop rate)
             ;; Fallback disabled: return 0 directly (Core returns the zero
             ;; CFeeRate; the caller errors on the FALLBACK reason).
             (return-from %wallet-minimum-fee-rate (values 0 :fallback))))
         (let* ((mempool (bitcoin-lisp::node-mempool node))
                (mempool-min (if mempool
                                 (bitcoin-lisp.mempool:mempool-effective-min-fee-rate
                                  mempool)
                                 0)))
           (when (< rate mempool-min)
             (setf rate mempool-min reason :mempool-min))))))
    (let ((required (%wallet-required-fee-rate)))
      (when (> required rate)
        (setf rate required reason :required)))
    (values rate reason)))

(defun %wallet-discard-rate (node)
  "Core GetDiscardRate: economical estimate at the longest horizon, capped
by -discardfee, floored at the dust relay feerate."
  (let* ((estimate (%estimate-smart-fee-sat-kvb node 1008 nil))
         (rate (if (zerop estimate)
                   *wallet-discard-rate*
                   (min estimate *wallet-discard-rate*))))
    (max rate bitcoin-lisp.validation:+dust-relay-fee-rate+)))

(defun %fee-reason-string (reason)
  "common/messages.cpp StringForFeeReason. DIVERGENCE (cosmetic): our block
estimator has no half/double-target tiers, so a successful estimate reports
Core's full-target string."
  (ecase reason
    (:payment "PayTxFee set")
    (:estimate "Target 85% Threshold")
    (:fallback "Fallback fee")
    (:mempool-min "Mempool Min Fee")
    (:required "Minimum Required Fee")))

;;; --- Maximum signed input/tx size estimation (spend.cpp:49-192 +
;;; script/descriptor.cpp MaxSatSize/MaxSatisfactionWeight/-Elems) ---
;;;
;;; ECDSA satisfactions are estimated at 72 bytes incl. the sighash byte
;;; (Core's use_max_sig): our signer produces RFC6979 signatures WITHOUT
;;; low-R grinding, so ~half of all signatures are 72 bytes — Core's
;;; can_grind_r 71-byte estimate would undershoot. DIVERGENCE (safe): the
;;; estimate upper-bounds the real size, so the realized feerate is >= the
;;; target, never below.

(defconstant +ecdsa-max-sig-size+ 72)

(defun %known-pubkey-for-script (wallet cc script keyhash)
  "The pubkey with HASH160 = KEYHASH, from the owning SPKM's expansion at
SCRIPT's position, or the coin control's external solving data."
  (or (multiple-value-bind (spkm pos) (and wallet (%wallet-owning-spkm wallet script))
        (when spkm
          (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
            (declare (ignore scripts))
            (let ((pair (%expansion-pubkey-by-hash160 pairs keyhash)))
              (and pair (cdr pair))))))
      (and cc (gethash keyhash (wcc-external-pubkeys cc)))))

(defun %known-sub-scripts (wallet cc script)
  "(values redeem-script witness-script) known for the P2SH/P2WSH SCRIPT."
  (multiple-value-bind (spkm) (and wallet (%wallet-owning-spkm wallet script))
    (multiple-value-bind (redeem witness)
        (and spkm (%spkm-sub-scripts spkm script))
      (when (and cc (wcc-external-scripts cc))
        (multiple-value-bind (type data)
            (bitcoin-lisp.validation:classify-script script)
          (case type
            (:scripthash
             (unless redeem
               (setf redeem (gethash (getf data :hash)
                                     (wcc-external-scripts cc))))
             (when (and redeem (null witness)
                        (= (length redeem) 34)
                        (= (aref redeem 0) #x00) (= (aref redeem 1) #x20))
               (setf witness (gethash (subseq redeem 2 34)
                                      (wcc-external-scripts cc)))))
            (:witness-v0-scripthash
             (unless witness
               (setf witness (gethash (getf data :witness-program)
                                      (wcc-external-scripts cc))))))))
      (values redeem witness))))

(defun %multisig-sat-size (script)
  "1 + (1 + 72) * m for an m-of-n multisig SCRIPT, or NIL."
  (multiple-value-bind (m) (%parse-multisig script)
    (when m (+ 1 (* (+ 1 +ecdsa-max-sig-size+) m)))))

(defun %miniscript-sat-size-and-elems (witness-script)
  "(values sat-bytes elems) for a miniscript WITNESS-SCRIPT, or NIL.

Core's MiniscriptDescriptor answers these from m_node.GetWitnessSize() and
m_node.GetStackSize() (descriptor.cpp:1684-1693), where m_node is the
descriptor's own parse-time node. This estimator is reached with a SCRIPT
rather than a descriptor, so it infers the node back out. The BYTE COUNT is
identical either way — CalcWitnessSize charges a constant 1+72 per signature
and 1+33 per pubkey rather than measuring the actual key (miniscript.h:1188).
The one difference is that inference can fail where a descriptor's node cannot,
and that errs conservative: the coin looks unsolvable and is skipped, never
mis-sized.

ELEMS adds one for the witnessScript itself, which the caller pushes and which
GetWitnessSize deliberately excludes."
  (let ((node (bitcoin-lisp.validation::ms-from-script witness-script)))
    (when node
      (let ((bytes (bitcoin-lisp.validation::ms-node-get-witness-size node))
            (stack (bitcoin-lisp.validation::ms-node-get-stack-size node)))
        (when (and bytes stack)
          (values bytes (1+ stack)))))))

(defun %script-sat-weight (wallet cc script)
  "(values sat-weight segwit-p elems) for the maximum satisfaction of
SCRIPT, mirroring the descriptor MaxSatisfactionWeight arithmetic on the
descriptor InferDescriptor would produce; NIL when not solvable."
  (multiple-value-bind (type data)
      (bitcoin-lisp.validation:classify-script script)
    (case type
      (:pubkey (values (* 4 (+ 1 +ecdsa-max-sig-size+)) nil 1))
      (:pubkeyhash
       (let ((pub (%known-pubkey-for-script wallet cc script (getf data :hash))))
         (when pub
           (values (* 4 (+ 1 +ecdsa-max-sig-size+ 1 (length pub))) nil 2))))
      (:witness-v0-keyhash
       (values (+ 1 +ecdsa-max-sig-size+ 1 33) t 2))
      (:witness-v1-taproot
       ;; Keypath spend assumed, like Core's TRDescriptor (FIXME parity).
       (values (+ 1 65) t 1))
      (:multisig
       (let ((sat (%multisig-sat-size script)))
         (when sat (values (* 4 sat) nil (+ 1 (getf data :m))))))
      (:scripthash
       (multiple-value-bind (redeem witness) (%known-sub-scripts wallet cc script)
         (when redeem
           (cond
             ;; sh(wpkh(...))
             ((and (= (length redeem) 22)
                   (= (aref redeem 0) #x00) (= (aref redeem 1) #x14))
              (values (+ (* 4 (+ 1 (length redeem)))
                         (+ 1 +ecdsa-max-sig-size+ 1 33))
                      t 3))
             ;; sh(wsh(multi(...)))
             ((and (= (length redeem) 34)
                   (= (aref redeem 0) #x00) (= (aref redeem 1) #x20))
              (let ((sat (and witness (%multisig-sat-size witness))))
                (when sat
                  (multiple-value-bind (m) (%parse-multisig witness)
                    (values (+ (* 4 (+ 1 (length redeem)))
                               (+ (%compact-size-size (length witness))
                                  (length witness) sat))
                            t (+ 3 m))))))
             ;; sh(multi(...)) — legacy
             (t
              (let ((sat (%multisig-sat-size redeem)))
                (when sat
                  (multiple-value-bind (m) (%parse-multisig redeem)
                    (values (* 4 (+ (+ 1 (length redeem)) sat))
                            nil (+ 2 m))))))))))
      (:witness-v0-scripthash
       (multiple-value-bind (redeem witness) (%known-sub-scripts wallet cc script)
         (declare (ignore redeem))
         (when witness
           (let ((sat (%multisig-sat-size witness)))
             (if sat
                 (multiple-value-bind (m) (%parse-multisig witness)
                   (values (+ (%compact-size-size (length witness))
                              (length witness) sat)
                           t (+ 2 m)))
                 ;; Not multisig: try miniscript, or the coin looks unsolvable
                 ;; and coin selection silently skips it — which is what kept a
                 ;; funded policy descriptor unspendable through the wallet's
                 ;; own send path even once signing worked.
                 (multiple-value-bind (msat elems)
                     (%miniscript-sat-size-and-elems witness)
                   (when msat
                     (values (+ (%compact-size-size (length witness))
                                (length witness) msat)
                             t elems))))))))
      (t nil))))

(defun %max-input-weight (wallet cc script &key (tx-is-segwit t))
  "Core MaxInputWeight (spend.cpp:69-90): full weight of the signed input
incl. outpoint/sequence/length prefixes, or NIL when unsolvable."
  (multiple-value-bind (sat segwit elems) (%script-sat-weight wallet cc script)
    (when sat
      (let ((scriptsig-len (if segwit
                               1
                               (%compact-size-size (floor sat 4))))
            (witstack-len (if segwit
                              (%compact-size-size elems)
                              (if tx-is-segwit 1 0))))
        (+ (* 4 (+ 32 4 4 scriptsig-len)) witstack-len sat)))))

(defun %max-signed-input-vsize (wallet cc script)
  "Core CalculateMaximumSignedInputSize: signed input vsize, or -1."
  (let ((weight (%max-input-weight wallet cc script :tx-is-segwit t)))
    (if weight (ceiling weight 4) -1)))

(defun %txout-script-segwit-p (wallet cc script)
  "Whether spending SCRIPT contributes witness data — drives the 2-byte
segwit marker/flag in CalculateMaximumSignedTxSize. Native witness
programs count even when unsolvable (Core's InferDescriptor falls back to
an addr() descriptor whose output type is still a witness type,
spend.cpp:150-157); P2SH counts only when the known redeem script wraps a
witness program."
  (case (bitcoin-lisp.validation:classify-script script)
    ((:witness-v0-keyhash :witness-v0-scripthash :witness-v1-taproot) t)
    (:scripthash
     (multiple-value-bind (sat segwit) (%script-sat-weight wallet cc script)
       (and sat segwit t)))
    (t nil)))

(defun %max-signed-tx-size (wallet cc tx txouts)
  "Core CalculateMaximumSignedTxSize over TXOUTS (parallel to the inputs;
each element (script . weight-override) where WEIGHT-OVERRIDE is the coin
control's explicit input weight or NIL). Returns (values vsize weight) or
(values -1 -1)."
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (outputs (bitcoin-lisp.serialization:transaction-outputs tx))
         (weight (* 4 (+ 4 4
                         (%compact-size-size (length inputs))
                         (%compact-size-size (length outputs)))))
         (is-segwit (some (lambda (txo)
                            (%txout-script-segwit-p wallet cc (car txo)))
                          txouts)))
    (when is-segwit (incf weight 2))
    (loop for output across outputs
          do (incf weight (* 4 (%txout-serialize-size
                                (bitcoin-lisp.serialization:tx-out-script-pubkey
                                 output)))))
    (loop for txo in txouts
          for override = (cdr txo)
          for w = (or override
                      (%max-input-weight wallet cc (car txo)
                                         :tx-is-segwit is-segwit))
          do (if w
                 (incf weight w)
                 (return-from %max-signed-tx-size (values -1 -1))))
    (values (ceiling weight 4) weight)))

(defun %wallet-input-txout (node wallet txid vout &optional cc)
  "The tx-out an input spends: the wallet's TXO map, a coin-control external
preset, the UTXO set, or the mempool (Core mapWallet + GetExternalOutput +
chain findCoins). Returns NIL when unknown. Caller holds both locks."
  (or (let ((wtx (wallet-get-wallet-tx wallet txid)))
        (when (and wtx
                   (< vout (length (bitcoin-lisp.serialization:transaction-outputs
                                    (wallet-tx-tx wtx)))))
          (aref (bitcoin-lisp.serialization:transaction-outputs
                 (wallet-tx-tx wtx))
                vout)))
      (let ((preset (and cc (gethash (cons txid vout) (wcc-presets cc)))))
        (and preset (wcc-preset-txout preset)))
      (let* ((utxo-set (rpc-get-utxo-set node))
             (utxo (and utxo-set
                        (bitcoin-lisp.storage:get-utxo utxo-set txid vout))))
        (when utxo
          (bitcoin-lisp.serialization:make-tx-out
           :value (bitcoin-lisp.storage:utxo-entry-value utxo)
           :script-pubkey (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo))))
      (let* ((mempool (bitcoin-lisp::node-mempool node))
             (entry (and mempool (bitcoin-lisp.mempool:mempool-get mempool txid))))
        (when entry
          (let ((outputs (bitcoin-lisp.serialization:transaction-outputs
                          (bitcoin-lisp.mempool:mempool-entry-transaction entry))))
            (when (< vout (length outputs))
              (aref outputs vout)))))))

;;; --- OutputGroup + eligibility filters (coinselection.{h,cpp}) ---

(defstruct out-group
  "Core OutputGroup."
  (outputs '() :type list)         ; wallet-coin structs, insertion order
  (from-me t)
  (value 0 :type integer)
  (depth 999 :type integer)
  (ancestors 0 :type integer)
  (max-cluster-count 0 :type integer)
  (effective-value 0 :type integer)
  (fee 0 :type integer)
  (long-term-fee 0 :type integer)
  (long-term-feerate 0 :type integer)
  subtract-fee-outputs
  (weight 0 :type integer))

(defun out-group-insert (group coin ancestors cluster-count)
  "Core OutputGroup::Insert."
  (setf (out-group-outputs group)
        (nconc (out-group-outputs group) (list coin)))
  (incf (out-group-fee group) (or (wallet-coin-fee coin) 0))
  (setf (wallet-coin-long-term-fee coin)
        (if (minusp (wallet-coin-input-bytes coin))
            0
            (%feerate-fee (out-group-long-term-feerate group)
                          (wallet-coin-input-bytes coin))))
  (incf (out-group-long-term-fee group) (wallet-coin-long-term-fee coin))
  (incf (out-group-effective-value group)
        (or (wallet-coin-effective-value coin)
            (bitcoin-lisp.serialization:tx-out-value (wallet-coin-output coin))))
  (setf (out-group-from-me group)
        (and (out-group-from-me group) (wallet-coin-from-me coin)))
  (incf (out-group-value group)
        (bitcoin-lisp.serialization:tx-out-value (wallet-coin-output coin)))
  (setf (out-group-depth group)
        (min (out-group-depth group) (wallet-coin-depth coin)))
  (incf (out-group-ancestors group) ancestors)
  (setf (out-group-max-cluster-count group)
        (max (out-group-max-cluster-count group) cluster-count))
  (when (plusp (wallet-coin-input-bytes coin))
    (incf (out-group-weight group) (* 4 (wallet-coin-input-bytes coin)))))

(defun out-group-selection-amount (group)
  "GetSelectionAmount: raw value under SFFO, effective value otherwise."
  (if (out-group-subtract-fee-outputs group)
      (out-group-value group)
      (out-group-effective-value group)))

(defstruct elig-filter
  "Core CoinEligibilityFilter (+ SelectionFilter's allow-mixed flag)."
  (conf-mine 1 :type integer)
  (conf-theirs 6 :type integer)
  (max-ancestors 0 :type integer)
  (max-cluster-count 0 :type integer)
  include-partial
  (allow-mixed t))

(defun out-group-eligible-p (group filter)
  "Core OutputGroup::EligibleForSpending."
  (and (>= (out-group-depth group)
           (if (out-group-from-me group)
               (elig-filter-conf-mine filter)
               (elig-filter-conf-theirs filter)))
       (<= (out-group-ancestors group) (elig-filter-max-ancestors filter))
       (<= (out-group-max-cluster-count group)
           (elig-filter-max-cluster-count filter))))

(defstruct type-groups
  "Core Groups: positive-effective-value groups and the mixed set."
  (positive '() :type list)
  (mixed '() :type list))

(defstruct group-map
  "Core OutputGroupTypeMap for one eligibility filter."
  (by-type (make-hash-table :test 'eq) :type hash-table)  ; type -> type-groups
  (all (make-type-groups) :type type-groups))

(defun %group-map-push (map group type insert-positive insert-mixed)
  "Core OutputGroupTypeMap::Push."
  (when (out-group-outputs group)
    (let ((groups (or (gethash type (group-map-by-type map))
                      (setf (gethash type (group-map-by-type map))
                            (make-type-groups)))))
      (when (and insert-positive (plusp (out-group-selection-amount group)))
        (setf (type-groups-positive groups)
              (nconc (type-groups-positive groups) (list group)))
        (setf (type-groups-positive (group-map-all map))
              (nconc (type-groups-positive (group-map-all map)) (list group))))
      (when insert-mixed
        (setf (type-groups-mixed groups)
              (nconc (type-groups-mixed groups) (list group)))
        (setf (type-groups-mixed (group-map-all map))
              (nconc (type-groups-mixed (group-map-all map)) (list group)))))))

(defun %mempool-tx-ancestry (mempool txid)
  "Core chain.getTransactionAncestry: (values ancestors cluster-count) for
TXID's mempool entry, both 0 when not in the mempool."
  (let ((entry (and mempool (bitcoin-lisp.mempool:mempool-get mempool txid))))
    (if (null entry)
        (values 0 0)
        (let ((ancestors (bitcoin-lisp.mempool:mempool-ancestor-stats mempool txid))
              (handle (bitcoin-lisp.mempool::mempool-entry-graph-handle entry)))
          (values ancestors
                  (if handle
                      (length (bitcoin-lisp.mempool::txgraph-get-cluster
                               (bitcoin-lisp.mempool::mempool-graph mempool)
                               handle))
                      ancestors))))))

(defstruct csel-params
  "Core CoinSelectionParams."
  rng
  (change-output-size 0 :type integer)
  (change-spend-size 0 :type integer)
  (min-change-target 0 :type integer)
  (min-viable-change 0 :type integer)
  (change-fee 0 :type integer)
  (cost-of-change 0 :type integer)
  (effective-feerate 0 :type integer)   ; sat/kvB
  (long-term-feerate 0 :type integer)   ; sat/kvB
  (discard-feerate 0 :type integer)     ; sat/kvB
  (tx-noinputs-size 0 :type integer)
  subtract-fee-outputs
  avoid-partial-spends
  include-unsafe-inputs
  (version 2)
  max-tx-weight)

(defun %group-outputs (node coins params filters)
  "Core GroupOutputs: (values filter-maps discarded-groups) — FILTER-MAPS a
list of group-maps parallel to FILTERS. Caller holds the node lock (mempool
ancestry reads)."
  (let ((mempool (bitcoin-lisp::node-mempool node))
        (maps (mapcar (lambda (f) (declare (ignore f)) (make-group-map))
                      filters))
        (discarded '()))
    (if (not (csel-params-avoid-partial-spends params))
        ;; No grouping: one OutputGroup per coin.
        (dolist (coin coins)
          (multiple-value-bind (ancestors cluster-count)
              (%mempool-tx-ancestry mempool (wallet-coin-txid coin))
            (let ((group (make-out-group
                          :long-term-feerate (csel-params-long-term-feerate params)
                          :subtract-fee-outputs (csel-params-subtract-fee-outputs
                                                 params)))
                  (accepted nil))
              (out-group-insert group coin ancestors cluster-count)
              (loop for filter in filters
                    for map in maps
                    do (when (out-group-eligible-p group filter)
                         (%group-map-push map group (wallet-coin-output-type coin)
                                          t t)
                         (setf accepted t)))
              (unless accepted (push group discarded)))))
        ;; Group per (scriptPubKey, type) in OUTPUT_GROUP_MAX_ENTRIES chunks.
        (let ((spk-groups (make-hash-table :test 'equalp))     ; key -> group list (reversed)
              (spk-positive (make-hash-table :test 'equalp))
              (keys '()))                                      ; insertion order
          (flet ((insert-into (table coin ancestors cluster-count key)
                   (let ((groups (gethash key table)))
                     (when (or (null groups)
                               (>= (length (out-group-outputs (first groups)))
                                   +output-group-max-entries+))
                       (push (make-out-group
                              :long-term-feerate (csel-params-long-term-feerate
                                                  params)
                              :subtract-fee-outputs (csel-params-subtract-fee-outputs
                                                     params))
                             groups)
                       (setf (gethash key table) groups))
                     (out-group-insert (first groups) coin ancestors
                                       cluster-count))))
            (dolist (coin coins)
              (multiple-value-bind (ancestors cluster-count)
                  (%mempool-tx-ancestry mempool (wallet-coin-txid coin))
                (let ((key (cons (bitcoin-lisp.serialization:tx-out-script-pubkey
                                  (wallet-coin-output coin))
                                 (wallet-coin-output-type coin))))
                  (unless (gethash key spk-groups)
                    (push key keys))
                  (when (and (wallet-coin-effective-value coin)
                             (plusp (wallet-coin-effective-value coin)))
                    (insert-into spk-positive coin ancestors cluster-count key))
                  (insert-into spk-groups coin ancestors cluster-count key))))
            (setf keys (nreverse keys))
            (flet ((push-groups (table positive-only)
                     (dolist (key keys)
                       (let ((groups (gethash key table)))  ; head = partial group
                         (loop for group in groups
                               for first-p = t then nil
                               do (let ((accepted nil))
                                    (loop for filter in filters
                                          for map in maps
                                          do (when (and (out-group-eligible-p
                                                         group filter)
                                                        (not (and first-p
                                                                  (> (length groups) 1)
                                                                  (not (elig-filter-include-partial
                                                                        filter)))))
                                               (%group-map-push
                                                map group (cdr key)
                                                positive-only (not positive-only))
                                               (setf accepted t)))
                                    (unless accepted (push group discarded))))))))
              (push-groups spk-groups nil)
              (push-groups spk-positive t)))))
    (values maps (nreverse discarded))))

;;; --- SelectionResult + waste metric (coinselection.cpp:809-992) ---

(defstruct sel-result
  "Core SelectionResult."
  (inputs '() :type list)     ; wallet-coin structs
  (target 0 :type integer)
  (algo :manual)
  use-effective
  waste
  (weight 0 :type integer)
  (bump-fee-discount 0 :type integer)
  (algo-completed t))

(defun %sel-insert-inputs (result coins)
  "InsertInputs: append COINS, erroring on any shared outpoint (Core throws
STR_INTERNAL_BUG on shared UTXOs among selection results)."
  (dolist (coin coins)
    (when (find-if (lambda (existing)
                     (and (equalp (wallet-coin-txid existing)
                                  (wallet-coin-txid coin))
                          (= (wallet-coin-index existing)
                             (wallet-coin-index coin))))
                   (sel-result-inputs result))
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "Internal bug detected: Shared UTXOs among selection results"))
    (setf (sel-result-inputs result)
          (nconc (sel-result-inputs result) (list coin)))))

(defun sel-result-add-group (result group)
  "SelectionResult::AddInput(OutputGroup)."
  (%sel-insert-inputs result (out-group-outputs group))
  (setf (sel-result-use-effective result)
        (not (out-group-subtract-fee-outputs group)))
  (incf (sel-result-weight result) (out-group-weight group)))

(defun sel-result-add-coins (result coins subtract-fee-outputs)
  "SelectionResult::AddInputs (preset inputs)."
  (%sel-insert-inputs result coins)
  (setf (sel-result-use-effective result) (not subtract-fee-outputs))
  (incf (sel-result-weight result)
        (reduce #'+ coins
                :key (lambda (coin)
                       (* 4 (max (wallet-coin-input-bytes coin) 0)))
                :initial-value 0)))

(defun sel-result-selected-value (result)
  (reduce #'+ (sel-result-inputs result)
          :key (lambda (coin)
                 (bitcoin-lisp.serialization:tx-out-value
                  (wallet-coin-output coin)))
          :initial-value 0))

(defun sel-result-selected-effective-value (result)
  (+ (reduce #'+ (sel-result-inputs result)
             :key (lambda (coin) (or (wallet-coin-effective-value coin) 0))
             :initial-value 0)
     (sel-result-bump-fee-discount result)))

(defun sel-result-total-bump-fees (result)
  (- (reduce #'+ (sel-result-inputs result)
             :key #'wallet-coin-bump-fee :initial-value 0)
     (sel-result-bump-fee-discount result)))

(defun sel-result-get-change (result min-viable-change change-fee)
  "SelectionResult::GetChange."
  (let ((change (if (sel-result-use-effective result)
                    (- (sel-result-selected-effective-value result)
                       (sel-result-target result)
                       change-fee)
                    (- (sel-result-selected-value result)
                       (sel-result-target result)))))
    (if (< change min-viable-change) 0 change)))

(defun sel-result-recalculate-waste (result min-viable-change change-cost
                                     change-fee)
  "SelectionResult::RecalculateWaste."
  (assert (sel-result-inputs result))
  (let ((waste (reduce #'+ (sel-result-inputs result)
                       :key (lambda (coin)
                              (- (or (wallet-coin-fee coin) 0)
                                 (wallet-coin-long-term-fee coin)))
                       :initial-value 0)))
    (decf waste (sel-result-bump-fee-discount result))
    (if (plusp (sel-result-get-change result min-viable-change change-fee))
        (incf waste change-cost)
        (let ((selected (if (sel-result-use-effective result)
                            (sel-result-selected-effective-value result)
                            (sel-result-selected-value result))))
          (unless (>= selected (sel-result-target result))
            (error 'rpc-error :code +rpc-wallet-error+
                              :message "Internal bug detected: selection below target in waste computation"))
          (incf waste (- selected (sel-result-target result)))))
    (setf (sel-result-waste result) waste)))

(defun sel-result-better-p (a b)
  "SelectionResult::operator<: lower waste; on ties, MORE inputs."
  (or (< (sel-result-waste a) (sel-result-waste b))
      (and (= (sel-result-waste a) (sel-result-waste b))
           (> (length (sel-result-inputs a)) (length (sel-result-inputs b))))))

(defun %best-result (results)
  "std::min_element under sel-result-better-p (first of equals wins)."
  (let ((best (first results)))
    (dolist (result (rest results) best)
      (when (sel-result-better-p result best)
        (setf best result)))))

(defun generate-change-target (payment-value change-fee rng)
  "Core GenerateChangeTarget."
  (if (<= payment-value (floor +change-lower+ 2))
      (+ change-fee +change-lower+)
      (let ((upper-bound (min (* payment-value 2) +change-upper+)))
        (+ change-fee
           (wrng-randrange rng (- upper-bound +change-lower+))
           +change-lower+))))

;;; --- BnB (coinselection.cpp:93-201) ---

(defconstant +max-weight-error-message+
  (if (boundp '+max-weight-error-message+)
      (symbol-value '+max-weight-error-message+)
      "The inputs size exceeds the maximum weight. Please try sending a smaller amount or manually consolidating your wallet's UTXOs"))

(defun %sort-groups-descending (groups)
  "coinselection.cpp `descending`: by selection amount, ties by lower
fee - long_term_fee first. Stable, like std::sort need not be — ties beyond
the comparator keys don't affect the algorithms' correctness."
  (sort (copy-list groups)
        (lambda (a b)
          (let ((av (out-group-selection-amount a))
                (bv (out-group-selection-amount b)))
            (if (= av bv)
                (< (- (out-group-fee a) (out-group-long-term-fee a))
                   (- (out-group-fee b) (out-group-long-term-fee b)))
                (> av bv))))))

(defun select-coins-bnb (utxo-pool selection-target cost-of-change
                         max-selection-weight)
  "Core SelectCoinsBnB. UTXO-POOL is a list of out-groups (positive
selection amounts). Returns (values sel-result error-message):
result NIL + message NIL = plain not-found."
  (let* ((pool (coerce (%sort-groups-descending utxo-pool) 'simple-vector))
         (pool-size (length pool))
         (curr-value 0)
         (curr-selection (make-array 8 :adjustable t :fill-pointer 0))
         (curr-selection-weight 0)
         (curr-available-value 0)
         (curr-waste 0)
         (best-selection nil)
         (best-waste bitcoin-lisp.validation:+max-money+)
         (max-tx-weight-exceeded nil))
    (loop for group across pool
          do (assert (plusp (out-group-selection-amount group)))
             (incf curr-available-value (out-group-selection-amount group)))
    (when (< curr-available-value selection-target)
      (return-from select-coins-bnb (values nil nil)))
    (let ((is-feerate-high (and (plusp pool-size)
                                (> (out-group-fee (aref pool 0))
                                   (out-group-long-term-fee (aref pool 0)))))
          (utxo-pool-index 0))
      (loop for curr-try from 0 below +bnb-total-tries+
            do (let ((backtrack nil))
                 (cond
                   ((or (< (+ curr-value curr-available-value) selection-target)
                        (> curr-value (+ selection-target cost-of-change))
                        (and (> curr-waste best-waste) is-feerate-high))
                    (setf backtrack t))
                   ((> curr-selection-weight max-selection-weight)
                    (setf max-tx-weight-exceeded t backtrack t))
                   ((>= curr-value selection-target)
                    (incf curr-waste (- curr-value selection-target))
                    (when (<= curr-waste best-waste)
                      (setf best-selection (coerce curr-selection 'list)
                            best-waste curr-waste))
                    (decf curr-waste (- curr-value selection-target))
                    (setf backtrack t)))
                 (if backtrack
                     (progn
                       (when (zerop (fill-pointer curr-selection))
                         (return))
                       ;; Add omitted UTXOs back to the lookahead before
                       ;; taking the omission branch of the last inclusion.
                       (decf utxo-pool-index)
                       (loop while (> utxo-pool-index
                                      (aref curr-selection
                                            (1- (fill-pointer curr-selection))))
                             do (incf curr-available-value
                                      (out-group-selection-amount
                                       (aref pool utxo-pool-index)))
                                (decf utxo-pool-index))
                       (assert (= utxo-pool-index
                                  (aref curr-selection
                                        (1- (fill-pointer curr-selection)))))
                       (let ((group (aref pool utxo-pool-index)))
                         (decf curr-value (out-group-selection-amount group))
                         (decf curr-waste (- (out-group-fee group)
                                             (out-group-long-term-fee group)))
                         (decf curr-selection-weight (out-group-weight group))
                         (decf (fill-pointer curr-selection))))
                     (let ((group (aref pool utxo-pool-index)))
                       (decf curr-available-value
                             (out-group-selection-amount group))
                       (when (or (zerop (fill-pointer curr-selection))
                                 (= (1- utxo-pool-index)
                                    (aref curr-selection
                                          (1- (fill-pointer curr-selection))))
                                 (/= (out-group-selection-amount group)
                                     (out-group-selection-amount
                                      (aref pool (1- utxo-pool-index))))
                                 (/= (out-group-fee group)
                                     (out-group-fee
                                      (aref pool (1- utxo-pool-index)))))
                         (vector-push-extend utxo-pool-index curr-selection)
                         (incf curr-value (out-group-selection-amount group))
                         (incf curr-waste (- (out-group-fee group)
                                             (out-group-long-term-fee group)))
                         (incf curr-selection-weight (out-group-weight group)))))
                 ;; Core's ++utxo_pool_index. Indexing past the pool never
                 ;; occurs: once the pool is exhausted curr_available_value
                 ;; is 0, so the next iteration always backtracks before the
                 ;; forward branch touches the vector.
                 (incf utxo-pool-index))))
    (if (null best-selection)
        (values nil (and max-tx-weight-exceeded +max-weight-error-message+))
        (let ((result (make-sel-result :target selection-target :algo :bnb)))
          (dolist (i best-selection)
            (sel-result-add-group result (aref pool i)))
          (sel-result-recalculate-waste result cost-of-change cost-of-change 0)
          (unless (= best-waste (sel-result-waste result))
            (error 'rpc-error :code +rpc-wallet-error+
                              :message "Internal bug detected: BnB waste mismatch"))
          (values result nil)))))

;;; --- Knapsack (coinselection.cpp:602-747) ---

(defun %approximate-best-subset (rng groups total-lower target
                                 max-selection-weight &optional (iterations 1000))
  "Core ApproximateBestSubset. GROUPS a simple-vector sorted descending.
Returns (values best-flags best-value)."
  (let* ((n (length groups))
         (best (make-array n :initial-element t))
         (best-value total-lower)
         (included (make-array n)))
    (loop for rep from 0 below iterations
          while (/= best-value target)
          do (fill included nil)
             (let ((total 0)
                   (selected-weight 0)
                   (reached nil))
               (loop for pass from 0 below 2
                     while (not reached)
                     do (dotimes (i n)
                          (when (if (zerop pass)
                                    (wrng-randbool rng)
                                    (not (aref included i)))
                            (incf total (out-group-selection-amount
                                         (aref groups i)))
                            (incf selected-weight (out-group-weight
                                                   (aref groups i)))
                            (setf (aref included i) t)
                            (when (and (>= total target)
                                       (<= selected-weight max-selection-weight))
                              (setf reached t)
                              (when (< total best-value)
                                (setf best-value total)
                                (replace best included))
                              (decf total (out-group-selection-amount
                                           (aref groups i)))
                              (decf selected-weight (out-group-weight
                                                     (aref groups i)))
                              (setf (aref included i) nil)))))))
    (values best best-value)))

(defun knapsack-solver (groups target-value change-target rng
                        max-selection-weight)
  "Core KnapsackSolver. GROUPS is a list of out-groups (the mixed set).
Returns (values sel-result error-message)."
  (let ((result (make-sel-result :target target-value :algo :knapsack))
        (max-weight-exceeded nil)
        (lowest-larger nil)
        (applicable '())
        (total-lower 0)
        (shuffled (wrng-shuffle rng groups)))
    (dolist (group shuffled)
      (cond
        ((> (out-group-weight group) max-selection-weight)
         (setf max-weight-exceeded t))
        ((= (out-group-selection-amount group) target-value)
         (sel-result-add-group result group)
         (return-from knapsack-solver (values result nil)))
        ((< (out-group-selection-amount group) (+ target-value change-target))
         (push group applicable)
         (incf total-lower (out-group-selection-amount group)))
        ((or (null lowest-larger)
             (< (out-group-selection-amount group)
                (out-group-selection-amount lowest-larger)))
         (setf lowest-larger group))))
    (setf applicable (nreverse applicable))
    (when (= total-lower target-value)
      (dolist (group applicable)
        (sel-result-add-group result group))
      (if (<= (sel-result-weight result) max-selection-weight)
          (return-from knapsack-solver (values result nil))
          (setf max-weight-exceeded t
                result (make-sel-result :target target-value :algo :knapsack))))
    (when (< total-lower target-value)
      (when (null lowest-larger)
        (return-from knapsack-solver
          (values nil (and max-weight-exceeded +max-weight-error-message+))))
      (sel-result-add-group result lowest-larger)
      (return-from knapsack-solver (values result nil)))
    (let ((sorted (coerce (%sort-groups-descending applicable) 'simple-vector)))
      (multiple-value-bind (best best-value)
          (%approximate-best-subset rng sorted total-lower target-value
                                    max-selection-weight)
        (when (and (/= best-value target-value)
                   (>= total-lower (+ target-value change-target)))
          (multiple-value-setq (best best-value)
            (%approximate-best-subset rng sorted total-lower
                                      (+ target-value change-target)
                                      max-selection-weight)))
        (if (and lowest-larger
                 (or (and (/= best-value target-value)
                          (< best-value (+ target-value change-target)))
                     (<= (out-group-selection-amount lowest-larger) best-value)))
            (sel-result-add-group result lowest-larger)
            (progn
              (dotimes (i (length sorted))
                (when (aref best i)
                  (sel-result-add-group result (aref sorted i))))
              (when (> (sel-result-weight result) max-selection-weight)
                (when (null lowest-larger)
                  (return-from knapsack-solver
                    (values nil +max-weight-error-message+)))
                (setf result (make-sel-result :target target-value
                                              :algo :knapsack))
                (sel-result-add-group result lowest-larger))))
        (values result nil)))))

;;; --- SRD (coinselection.cpp:536-588) ---

(defun select-coins-srd (utxo-pool target-value change-fee rng
                         max-selection-weight)
  "Core SelectCoinsSRD over the positive groups. Returns
(values sel-result error-message)."
  (let ((result (make-sel-result :target target-value :algo :srd))
        (target (+ target-value +change-lower+ change-fee))
        (pool (coerce utxo-pool 'simple-vector))
        (heap '())            ; selected groups; min extracted by amount
        (selected-eff 0)
        (weight 0)
        (max-weight-exceeded nil))
    (let ((indexes (wrng-shuffle rng (loop for i from 0 below (length pool)
                                           collect i))))
      (dolist (i indexes)
        (let ((group (aref pool i)))
          (assert (plusp (out-group-selection-amount group)))
          (push group heap)
          (incf selected-eff (out-group-selection-amount group))
          (incf weight (out-group-weight group))
          (when (> weight max-selection-weight)
            (setf max-weight-exceeded t)
            (loop while (and heap (> weight max-selection-weight))
                  do (let ((min-group (reduce
                                       (lambda (a b)
                                         (if (< (out-group-selection-amount b)
                                                (out-group-selection-amount a))
                                             b a))
                                       heap)))
                       (setf heap (remove min-group heap :count 1 :test #'eq))
                       (decf selected-eff (out-group-selection-amount min-group))
                       (decf weight (out-group-weight min-group)))))
          (when (>= selected-eff target)
            (dolist (g heap)
              (sel-result-add-group result g))
            (return-from select-coins-srd (values result nil))))))
    (values nil (and max-weight-exceeded +max-weight-error-message+))))

;;; --- ChooseSelectionResult / AttemptSelection (spend.cpp:702-812) ---

(defun %choose-selection-result (target-value groups params)
  "Core ChooseSelectionResult over one Groups set. Returns
(values sel-result error-message)."
  (let ((results '())
        (errors '())
        (max-transaction-weight (or (csel-params-max-tx-weight params)
                                    bitcoin-lisp.validation:+max-standard-tx-weight+))
        (tx-weight-no-input (* 4 (csel-params-tx-noinputs-size params))))
    (let ((max-selection-weight (- max-transaction-weight tx-weight-no-input)))
      (when (<= max-selection-weight 0)
        (return-from %choose-selection-result
          (values nil "Maximum transaction weight is less than transaction weight without inputs")))
      ;; SFFO frequently misbehaves with changeless input sets: no BnB.
      (unless (csel-params-subtract-fee-outputs params)
        (multiple-value-bind (result error)
            (select-coins-bnb (type-groups-positive groups) target-value
                              (csel-params-cost-of-change params)
                              max-selection-weight)
          (if result (push result results)
              (when error (push error errors)))))
      ;; The remaining algorithms may create a change output.
      (decf max-selection-weight (* 4 (csel-params-change-output-size params)))
      (when (and (minusp max-selection-weight) (null results))
        (return-from %choose-selection-result
          (values nil "Maximum transaction weight is too low, can not accommodate change output")))
      (multiple-value-bind (result error)
          (knapsack-solver (type-groups-mixed groups) target-value
                           (csel-params-min-change-target params)
                           (csel-params-rng params) max-selection-weight)
        (if result (push result results)
            (when error (push error errors))))
      ;; CoinGrinder DEFERRED (wallet-plan §7.3): Core would run it here
      ;; when effective-feerate > 3x long-term-feerate to minimize input
      ;; weight; until ported, high-feerate selections fall through to the
      ;; BnB/Knapsack/SRD candidates (never wrong, occasionally heavier).
      (multiple-value-bind (result error)
          (select-coins-srd (type-groups-positive groups) target-value
                            (csel-params-change-fee params)
                            (csel-params-rng params) max-selection-weight)
        (if result (push result results)
            (when error (push error errors))))
      (when (null results)
        (return-from %choose-selection-result
          (values nil (first (last errors)))))
      ;; Bump-fee synergy discount: no bump-fee machinery — discount 0
      ;; (divergence 3 in the file header).
      (dolist (result results)
        (sel-result-recalculate-waste result
                                      (csel-params-min-viable-change params)
                                      (csel-params-cost-of-change params)
                                      (csel-params-change-fee params)))
      (values (%best-result (nreverse results)) nil))))

(defun %attempt-selection (target-value group-map params allow-mixed)
  "Core AttemptSelection: per-output-type first, mixed as fallback."
  (let ((results '()))
    (dolist (type +output-type-order+)
      (let ((groups (gethash type (group-map-by-type group-map))))
        (when groups
          (multiple-value-bind (result error)
              (%choose-selection-result target-value groups params)
            (when (and (null result) error)
              (return-from %attempt-selection (values nil error)))
            (when result (push result results))))))
    (cond
      (results (values (%best-result (nreverse results)) nil))
      ((and allow-mixed
            (> (hash-table-count (group-map-by-type group-map)) 1))
       (%choose-selection-result target-value (group-map-all group-map) params))
      (t (values nil nil)))))

;;; --- AutomaticCoinSelection + SelectCoins (spend.cpp:814-981) ---

(defun %ordered-filters (include-unsafe)
  "Core AutomaticCoinSelection's eligibility cascade, exactly."
  (let ((max-ancestors (max 1 +default-ancestor-limit+))
        (max-cluster (max 1 +default-ancestor-limit+))
        (filters (list (make-elig-filter :conf-mine 1 :conf-theirs 6
                                         :max-ancestors 0 :max-cluster-count 0
                                         :allow-mixed nil)
                       (make-elig-filter :conf-mine 1 :conf-theirs 1
                                         :max-ancestors 0 :max-cluster-count 0))))
    (when *wallet-spend-zero-conf-change*
      (setf filters
            (nconc filters
                   (list (make-elig-filter :conf-mine 0 :conf-theirs 1
                                           :max-ancestors 2 :max-cluster-count 2)
                         (make-elig-filter :conf-mine 0 :conf-theirs 1
                                           :max-ancestors (min 4 (floor max-ancestors 3))
                                           :max-cluster-count (min 4 (floor max-cluster 3)))
                         (make-elig-filter :conf-mine 0 :conf-theirs 1
                                           :max-ancestors (floor max-ancestors 2)
                                           :max-cluster-count (floor max-cluster 2))
                         (make-elig-filter :conf-mine 0 :conf-theirs 1
                                           :max-ancestors (1- max-ancestors)
                                           :max-cluster-count (1- max-cluster)
                                           :include-partial t))))
      (when include-unsafe
        (setf filters
              (nconc filters
                     (list (make-elig-filter :conf-mine 0 :conf-theirs 0
                                             :max-ancestors (1- max-ancestors)
                                             :max-cluster-count (1- max-cluster)
                                             :include-partial t)))))
      (unless *wallet-reject-long-chains*
        (setf filters
              (nconc filters
                     (list (make-elig-filter :conf-mine 0 :conf-theirs 1
                                             :max-ancestors +uint64-max+
                                             :max-cluster-count +uint64-max+
                                             :include-partial t))))))
    filters))

(defun %automatic-coin-selection (node available-coins value-to-select params)
  "Core AutomaticCoinSelection. AVAILABLE-COINS is the wallet-coin list.
Returns (values sel-result error-message)."
  (let ((coins available-coins)
        (rng (csel-params-rng params)))
    ;; 101+ same-destination outputs: shuffle to break deterministic sort
    ;; privacy leaks (spend.cpp:889-891).
    (when (and (csel-params-avoid-partial-spends params)
               (> (length coins) +output-group-max-entries+))
      (setf coins (wrng-shuffle rng coins)))
    (let ((filters (%ordered-filters (csel-params-include-unsafe-inputs params))))
      (multiple-value-bind (maps discarded)
          (%group-outputs node coins params filters)
        ;; Balance check after the filters possibly discarded groups.
        (let ((total-amount (reduce #'+ coins
                                    :key (lambda (coin)
                                           (bitcoin-lisp.serialization:tx-out-value
                                            (wallet-coin-output coin)))
                                    :initial-value 0))
              (total-discarded 0)
              (total-unconf-long-chain 0))
          (dolist (group discarded)
            (incf total-discarded (out-group-selection-amount group))
            (when (or (>= (out-group-ancestors group) +default-ancestor-limit+)
                      (>= (out-group-max-cluster-count group)
                          +default-ancestor-limit+))
              (incf total-unconf-long-chain
                    (out-group-selection-amount group))))
          (when (< (- total-amount total-discarded) value-to-select)
            ;; Core's precedence quirk (spend.cpp:942) makes its inner
            ;; comparison effectively `1 + total_unconf_long_chain >
            ;; value_to_select`; replicated verbatim.
            (return-from %automatic-coin-selection
              (if (> (+ 1 total-unconf-long-chain) value-to-select)
                  (values nil "Unconfirmed UTXOs are available, but spending them creates a chain of transactions that will be rejected by the mempool")
                  (values nil nil)))))
        (let ((detailed-error nil))
          (loop for filter in filters
                for map in maps
                do (let ((local-params params))
                     ;; TRUC childhood: an unconfirmed-input round caps the
                     ;; weight at TRUC_CHILD_MAX_WEIGHT (spend.cpp:958-962).
                     (when (and (= (csel-params-version params)
                                   bitcoin-lisp.mempool:+truc-version+)
                                (or (zerop (elig-filter-conf-mine filter))
                                    (zerop (elig-filter-conf-theirs filter)))
                                (> (or (csel-params-max-tx-weight params)
                                       bitcoin-lisp.validation:+max-standard-tx-weight+)
                                   +truc-child-max-weight+))
                       (setf local-params (copy-csel-params params))
                       (setf (csel-params-max-tx-weight local-params)
                             +truc-child-max-weight+))
                     (multiple-value-bind (result error)
                         (%attempt-selection value-to-select map local-params
                                             (elig-filter-allow-mixed filter))
                       (when result
                         (return-from %automatic-coin-selection
                           (values result nil)))
                       (when (and error (null detailed-error))
                         (setf detailed-error error)))))
          (values nil detailed-error))))))

(defun %select-coins (node available-coins preset-coins value-to-select params
                      cc)
  "Core SelectCoins: preset inputs first, wallet coins on top. Returns
(values sel-result error-message)."
  (let* ((sffo (csel-params-subtract-fee-outputs params))
         (preset-total (reduce #'+ preset-coins
                               :key (lambda (coin)
                                      (if sffo
                                          (bitcoin-lisp.serialization:tx-out-value
                                           (wallet-coin-output coin))
                                          (or (wallet-coin-effective-value coin) 0)))
                               :initial-value 0))
         (selection-target (- value-to-select preset-total)))
    (when (and (not (wcc-allow-other-inputs cc)) (plusp selection-target))
      (return-from %select-coins
        (values nil "The preselected coins total amount does not cover the transaction target. Please allow other inputs to be automatically selected or include more coins manually")))
    (when (<= selection-target 0)
      (let ((result (make-sel-result :target value-to-select :algo :manual)))
        (sel-result-add-coins result preset-coins sffo)
        (sel-result-recalculate-waste result
                                      (csel-params-min-viable-change params)
                                      (csel-params-cost-of-change params)
                                      (csel-params-change-fee params))
        (return-from %select-coins (values result nil))))
    ;; Early out when the wallet's coins cannot cover the remainder.
    (let ((available-total
            (reduce #'+ available-coins
                    :key (lambda (coin)
                           (if sffo
                               (bitcoin-lisp.serialization:tx-out-value
                                (wallet-coin-output coin))
                               (or (wallet-coin-effective-value coin) 0)))
                    :initial-value 0)))
      (when (> selection-target available-total)
        (return-from %select-coins (values nil nil))))
    (multiple-value-bind (result error)
        (%automatic-coin-selection node available-coins selection-target params)
      (unless result (return-from %select-coins (values nil error)))
      (when preset-coins
        (let ((preselected (make-sel-result :target preset-total :algo :manual)))
          (sel-result-add-coins preselected preset-coins sffo)
          ;; Merge (SelectionResult::Merge).
          (%sel-insert-inputs result (sel-result-inputs preselected))
          (incf (sel-result-target result) (sel-result-target preselected))
          (setf (sel-result-use-effective result)
                (or (sel-result-use-effective result)
                    (sel-result-use-effective preselected)))
          (incf (sel-result-weight result) (sel-result-weight preselected))
          (sel-result-recalculate-waste result
                                        (csel-params-min-viable-change params)
                                        (csel-params-cost-of-change params)
                                        (csel-params-change-fee params))
          (let ((max-inputs-weight
                  (- (or (csel-params-max-tx-weight params)
                         bitcoin-lisp.validation:+max-standard-tx-weight+)
                     (* 4 (csel-params-tx-noinputs-size params)))))
            (when (> (sel-result-weight result) max-inputs-weight)
              (return-from %select-coins
                (values nil "The combination of the pre-selected inputs and the wallet automatic inputs selection exceeds the transaction maximum weight. Please try sending a smaller amount or manually consolidating your wallet's UTXOs"))))))
      (values result nil))))

;;; --- Recipients (Core CRecipient / CreateRecipients) ---

(defstruct recipient
  address        ; destination string, or NIL for data outputs
  script         ; scriptPubKey bytes
  (amount 0 :type integer)
  sffo)          ; subtract fee from this output

(defun %op-return-script (data)
  "CScript() << OP_RETURN << data."
  (concatenate '(vector (unsigned-byte 8)) (vector #x6a) (%script-push data)))

(defun %parse-outputs (network outputs-param)
  "Core ParseOutputs over the outputs argument: an object {address: amount,
\"data\": hex} or an array of single-pair objects. Returns
(values recipient-list key-strings). JSON objects arrive as hash tables
whose key order is NOT preserved (yason); the array-of-objects form
preserves order exactly — DIVERGENCE (cosmetic ordering only) noted in the
send/walletcreatefundedpsbt docstrings."
  (let ((pairs '()))
    (labels ((collect-object (obj)
               (cond
                 ((hash-table-p obj)
                  (maphash (lambda (k v) (push (cons k v) pairs)) obj))
                 ((and (listp obj) (every #'consp obj))
                  (dolist (pair obj) (push (cons (car pair) (cdr pair)) pairs)))
                 (t (error 'rpc-error :code +rpc-type-error+
                                      :message "Invalid parameter, outputs must be objects")))))
      (cond
        ((and (listp outputs-param) outputs-param
              (or (hash-table-p (first outputs-param))
                  (and (consp (first outputs-param))
                       (consp (car (first outputs-param))))))
         ;; Array of single-entry objects (order-preserving).
         (dolist (obj outputs-param) (collect-object obj)))
        (t (collect-object outputs-param))))
    (setf pairs (nreverse pairs))
    (let ((seen (make-hash-table :test 'equal))
          (recipients '())
          (keys '()))
      (loop for (key . value) in pairs
            do (unless (stringp key)
                 (error 'rpc-error :code +rpc-type-error+
                                   :message "Invalid parameter, key must be a string"))
               (when (gethash key seen)
                 (error 'rpc-error :code +rpc-invalid-parameter+
                                   :message (format nil "Invalid parameter, duplicated address: ~A" key)))
               (setf (gethash key seen) t)
               (push key keys)
               (if (string= key "data")
                   (let ((data (handler-case (bitcoin-lisp.crypto:hex-to-bytes value)
                                 (error ()
                                   (error 'rpc-error :code +rpc-invalid-parameter+
                                                     :message "Data must be hexadecimal string")))))
                     (push (make-recipient :address nil
                                           :script (%op-return-script data)
                                           :amount 0)
                           recipients))
                   (multiple-value-bind (type script)
                       (bitcoin-lisp.crypto:decode-address key network)
                     (declare (ignore type))
                     (unless script
                       (error 'rpc-error :code +rpc-invalid-address-or-key+
                                         :message (format nil "Invalid Bitcoin address: ~A" key)))
                     (push (make-recipient :address key :script script
                                           :amount (%amount-from-value value))
                           recipients))))
      (values (nreverse recipients) (nreverse keys)))))

(defun %interpret-sffo (sffo-param keys recipients)
  "Core InterpretSubtractFeeFromOutputInstructions: mark recipients by
index or destination string."
  (when sffo-param
    (unless (listp sffo-param)
      (error 'rpc-error :code +rpc-type-error+
                        :message "subtractfeefrom must be an array"))
    (let ((seen (make-hash-table :test 'eql))
          (n (length recipients)))
      (dolist (sffo sffo-param)
        (let ((pos (cond
                     ((stringp sffo)
                      (or (position sffo keys :test #'string=)
                          (error 'rpc-error :code +rpc-invalid-parameter+
                                            :message (format nil "Invalid parameter 'subtract fee from output', destination ~A not found in tx outputs" sffo))))
                     ((integerp sffo) sffo)
                     (t (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Invalid parameter 'subtract fee from output', invalid value type")))))
          (when (gethash pos seen)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message (format nil "Invalid parameter 'subtract fee from output', duplicated position: ~D" pos)))
          (when (minusp pos)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message (format nil "Invalid parameter 'subtract fee from output', negative position: ~D" pos)))
          (when (>= pos n)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message (format nil "Invalid parameter 'subtract fee from output', position too large: ~D" pos)))
          (setf (gethash pos seen) t)
          (setf (recipient-sffo (nth pos recipients)) t)))))
  recipients)

;;; --- Change type + change address reservation ---

(defun %transaction-change-type (wallet change-type recipients)
  "Core CWallet::TransactionChangeType. Our m_default_address_type is
bech32 (DEFAULT_ADDRESS_TYPE), never legacy."
  (when change-type (return-from %transaction-change-type change-type))
  (let ((any-tr nil) (any-wpkh nil) (any-sh nil) (any-pkh nil))
    (dolist (recipient recipients)
      (let ((script (recipient-script recipient)))
        (case (bitcoin-lisp.validation:classify-script script)
          (:witness-v1-taproot (setf any-tr t))
          (:witness-v0-keyhash (setf any-wpkh t))
          (:scripthash (setf any-sh t))
          (:pubkeyhash (setf any-pkh t)))))
    (let ((has-bech32m (gethash :bech32m (wallet-internal-spkms wallet)))
          (has-bech32 (gethash :bech32 (wallet-internal-spkms wallet)))
          (has-p2sh-segwit (gethash :p2sh-segwit (wallet-internal-spkms wallet)))
          (has-legacy (gethash :legacy (wallet-internal-spkms wallet))))
      (cond
        ((and has-bech32m any-tr) :bech32m)
        ((and has-bech32 any-wpkh) :bech32)
        ((and has-p2sh-segwit any-sh) :p2sh-segwit)
        ((and has-legacy any-pkh) :legacy)
        (has-bech32m :bech32m)
        (has-bech32 :bech32)
        (t :bech32)))))

(defstruct reservedest
  "Core ReserveDestination for a descriptor SPKM: GetReservedDestination is
GetNewDestination (next_index advances and is fsynced BEFORE the address is
visible — the funds-critical persist-before-issue path); ReturnDestination
rewinds next_index only when it is still the most recent
(scriptpubkeyman.cpp:924-941); KeepDestination is a no-op."
  wallet spkm index address script)

(defun reservedest-reserve (rd wallet type)
  "(values address-or-nil error-message)."
  (let ((spkm (gethash type (wallet-internal-spkms wallet))))
    (if (or (null spkm) (not (spkm-can-get-addresses spkm)))
        (values nil "Error: No addresses available")
        (handler-case
            (let ((address (spkm-get-new-destination wallet spkm type)))
              (setf (reservedest-wallet rd) wallet
                    (reservedest-spkm rd) spkm
                    (reservedest-index rd) (1- (desc-spkm-next-index spkm))
                    (reservedest-address rd) address
                    (reservedest-script rd)
                    (nth-value 1 (bitcoin-lisp.crypto:decode-address
                                  address (wallet-network wallet))))
              (values address nil))
          (rpc-error (e) (values nil (rpc-error-message e)))))))

(defun reservedest-return (rd)
  "DescriptorScriptPubKeyMan::ReturnDestination: rewind next_index iff the
reserved index is still the most recent, and persist."
  (let ((wallet (reservedest-wallet rd))
        (spkm (reservedest-spkm rd)))
    (when (and wallet spkm)
      (when (= (1- (desc-spkm-next-index spkm)) (reservedest-index rd))
        (decf (desc-spkm-next-index spkm)))
      (spkm-write-descriptor wallet spkm)
      (setf (reservedest-spkm rd) nil))))

;;; --- Anti-fee-sniping (spend.cpp:983-1051) ---

(defconstant +max-anti-fee-sniping-tip-age+ (* 8 60 60))

(defun %current-for-anti-fee-sniping-p (node block-hash)
  "Core IsCurrentForAntiFeeSniping. Caller holds the node lock."
  (let ((chain-state (bitcoin-lisp::node-current-chainstate node)))
    (and chain-state
         block-hash
         (not (bitcoin-lisp.networking:initial-block-download-p chain-state))
         (let* ((entry (bitcoin-lisp.storage:get-block-index-entry
                        chain-state block-hash))
                (header (and entry
                             (bitcoin-lisp.storage:block-index-entry-header entry))))
           (and header
                (>= (bitcoin-lisp.serialization:block-header-timestamp header)
                    (- (bitcoin-lisp.serialization:get-unix-time)
                       +max-anti-fee-sniping-tip-age+)))))))

(defun discourage-fee-sniping (tx rng node block-hash block-height)
  "Core DiscourageFeeSniping: nLockTime = tip height, 10% of the time
backed off by rand(100); 0 when the chain lags. Core's asserts are ported
as hard internal-bug errors (funds-critical invariants)."
  (when (zerop (length (bitcoin-lisp.serialization:transaction-inputs tx)))
    (error 'rpc-error :code +rpc-wallet-error+
                      :message "Internal bug detected: anti-fee-sniping on an inputless transaction"))
  (if (%current-for-anti-fee-sniping-p node block-hash)
      (progn
        (setf (bitcoin-lisp.serialization:transaction-lock-time tx) block-height)
        (when (zerop (wrng-randrange rng 10))
          (setf (bitcoin-lisp.serialization:transaction-lock-time tx)
                (max 0 (- block-height (wrng-randrange rng 100))))))
      (setf (bitcoin-lisp.serialization:transaction-lock-time tx) 0))
  (let ((locktime (bitcoin-lisp.serialization:transaction-lock-time tx)))
    (unless (and (< locktime +locktime-threshold+) (<= locktime block-height))
      (error 'rpc-error :code +rpc-wallet-error+
                        :message "Internal bug detected: anti-fee-sniping locktime out of range")))
  (bitcoin-lisp.serialization:dovector
      (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let ((sequence (bitcoin-lisp.serialization:tx-in-sequence input)))
      (unless (or (= sequence +max-sequence-nonfinal+)
                  (= sequence +max-bip125-rbf-sequence+))
        (error 'rpc-error :code +rpc-wallet-error+
                          :message "Internal bug detected: unsupported nSequence for anti-fee-sniping")))))

;;; --- Preset input fetch (spend.cpp:269-318 FetchSelectedInputs) ---

(defun %outpoint-string (txid vout)
  "COutPoint::ToString: COutPoint(<10-hex-char prefix>, n)."
  (format nil "COutPoint(~A, ~D)"
          (subseq (hash-to-hex txid) 0 10) vout))

(defun %fetch-selected-inputs (node wallet cc params)
  "(values wallet-coin-list error-message) for the coin control's preset
inputs, in selection order. Caller holds node + wallet locks."
  (declare (ignorable node))
  (let ((coins '()))
    (dolist (outpoint (wcc-selected cc))
      (destructuring-bind (txid . vout) outpoint
        (let* ((preset (gethash outpoint (wcc-presets cc)))
               (input-bytes (if (wcc-preset-weight preset)
                                (ceiling (wcc-preset-weight preset) 4)
                                -1))
               (txout nil))
          (multiple-value-bind (wtx txo-index) (wallet-get-txo wallet txid vout)
            (declare (ignore txo-index))
            (cond
              (wtx
               (setf txout (aref (bitcoin-lisp.serialization:transaction-outputs
                                  (wallet-tx-tx wtx))
                                 vout))
               (when (minusp input-bytes)
                 (setf input-bytes
                       (%max-signed-input-vsize
                        wallet cc (bitcoin-lisp.serialization:tx-out-script-pubkey
                                   txout))))
               ;; TRUC version mixing on unconfirmed preset inputs
               ;; (spend.cpp:286-293).
               (when (zerop (wallet-tx-depth wallet wtx))
                 (let ((parent-version (bitcoin-lisp.serialization:transaction-version
                                        (wallet-tx-tx wtx))))
                   (cond
                     ((and (= parent-version bitcoin-lisp.mempool:+truc-version+)
                           (/= (wcc-version cc) bitcoin-lisp.mempool:+truc-version+))
                      (return-from %fetch-selected-inputs
                        (values nil (format nil "Can't spend unconfirmed version 3 pre-selected input with a version ~D tx"
                                            (wcc-version cc)))))
                     ((and (= (wcc-version cc) bitcoin-lisp.mempool:+truc-version+)
                           (/= parent-version bitcoin-lisp.mempool:+truc-version+))
                      (return-from %fetch-selected-inputs
                        (values nil (format nil "Can't spend unconfirmed version ~D pre-selected input with a version 3 tx"
                                            parent-version))))))))
              (t
               (setf txout (wcc-preset-txout preset))
               (unless txout
                 (return-from %fetch-selected-inputs
                   (values nil (format nil "Not found pre-selected input ~A"
                                       (%outpoint-string txid vout)))))))
            (when (minusp input-bytes)
              (setf input-bytes
                    (%max-signed-input-vsize
                     nil cc (bitcoin-lisp.serialization:tx-out-script-pubkey
                             txout))))
            (when (minusp input-bytes)
              (return-from %fetch-selected-inputs
                (values nil (format nil "Not solvable pre-selected input ~A"
                                    (%outpoint-string txid vout)))))
            (let ((fee (%feerate-fee (csel-params-effective-feerate params)
                                     input-bytes)))
              (push (make-wallet-coin
                     :txid txid :index vout :output txout :wtx nil
                     :depth 0 :solvable t :safe t :time 0 :from-me nil
                     :input-bytes input-bytes
                     :fee fee
                     :effective-value (- (bitcoin-lisp.serialization:tx-out-value
                                          txout)
                                         fee)
                     :output-type :unknown)
                    coins))))))
    (values (nreverse coins) nil)))

;;; --- Wallet signing (CWallet::SignTransaction over the SPKMs' keys) ---

(defun %desc-key-priv-at (key pos provider)
  "The 32-byte private key a descriptor key expression yields at range
position POS, or NIL. BIP32 keys derive from the root xprv along the fixed
path plus the ranged step; const keys come from the parse or PROVIDER."
  (if (desc-key-extkey key)
      (let ((xprv (%desc-key-root-xprv key provider)))
        (when xprv
          (let ((k xprv))
            (dolist (entry (desc-key-path key))
              (setf k (bitcoin-lisp.crypto:bip32-derive-child k entry)))
            (ecase (desc-key-derive key)
              (:none)
              (:unhardened
               (setf k (bitcoin-lisp.crypto:bip32-derive-child k pos)))
              (:hardened
               (setf k (bitcoin-lisp.crypto:bip32-derive-child
                        k (+ pos bitcoin-lisp.crypto:+bip32-hardened+)))))
            (subseq (bitcoin-lisp.crypto:ext-key-key k) 1 33))))
      (nth-value 0 (%desc-key-privkey-for key provider))))

(defun %sign-map-add-key! (keymap pubmap tr-keymap key pubkey priv pos)
  "Verify PRIV reproduces PUBKEY, then register it in the three signing maps:
KEYMAP hash160(pubkey) -> (priv . pubkey); PUBMAP pubkey -> priv; TR-KEYMAP
tweaked-taproot-output-x-only-key -> priv. A mismatch is logged and the key
skipped — a derivation bug MUST surface as a missing-key signing error, never a
wrong-key signature (funds-critical). Shared by the wallet signer
(%wallet-sign-maps) and the descriptor PSBT signer (%descriptor-sign-maps).

X-only descriptor keys (tr()/rawtr() key expressions) persist as bare 32-byte x
hex and reload lifted with a fixed 02 prefix, so an odd-Y key's stored parity
byte is arbitrary: compare X COORDINATES only. Taproot signing normalizes parity
itself (derive-xonly-pubkey + BIP86 tweak). Everything else keeps the strict
full-point check."
  (let* ((derived (bitcoin-lisp.crypto:derive-public-key
                   priv :compressed (= (length pubkey) 33)))
         (matches (if (and (desc-key-xonly-p key)
                           (= (length derived) 33)
                           (= (length pubkey) 33))
                      (equalp (subseq derived 1) (subseq pubkey 1))
                      (equalp derived pubkey))))
    (if matches
        (progn
          (setf (gethash (bitcoin-lisp.crypto:hash160 pubkey) keymap)
                (cons priv pubkey))
          (setf (gethash pubkey pubmap) priv)
          (when (= (length pubkey) 33)
            (let ((qx (bitcoin-lisp.coalton.interop:compute-tweaked-pubkey
                       (bitcoin-lisp.crypto:derive-xonly-pubkey priv))))
              (when qx (setf (gethash qx tr-keymap) priv)))))
        (bitcoin-lisp:log-warn
         "wallet-sign: derived key does not match expected pubkey at index ~D; key skipped"
         pos))))

(defun %spkm-tr-script-leaves (spkm script pos)
  "For a tr()-with-tree SPKM whose expansion at range position POS is SCRIPT,
the list of (SCRIPT LEAF-HASH CONTROL-BLOCK LEAF-DESC LEAF-PUBKEYS) that
%TR-SCRIPT-PATH-WITNESS consumes, or NIL for anything else.

The leaf pubkeys are sliced out of the descriptor's flat expansion the same way
%INFER-DESC-BODY slices them, and for the same reason: ORDERED-KEYS numbers the
tr() internal key first, so a leaf handed the whole list would be signing with
the wrong keys."
  (let ((desc (desc-spkm-desc spkm)))
    (when (and (eq (out-desc-kind desc) :tr) (out-desc-tree desc))
      (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
        (declare (ignore scripts))
        ;; Resolve keys out of PAIRS, which %SPKM-EXPANSION-PAIRS already
        ;; derived through the SPKM's xpub cache. Handing TR-SPEND-DATA a bare
        ;; %DESC-KEY-PUBKEY-AT would redo the whole descriptor's BIP32
        ;; derivation, uncached, for every taproot input signed.
        (multiple-value-bind (output-key leaves)
            (tr-spend-data desc pos
                           (lambda (k) (cdr (assoc k pairs :test #'eq))))
          ;; ⚠️ The spend data must be for the output we are actually spending.
          ;; Core cannot get this wrong -- it looks TaprootSpendData UP BY the
          ;; output key -- while we rebuild it and would otherwise file it under
          ;; the script's key unconditionally. Its sibling %SIGN-MAP-ADD-KEY!
          ;; verifies priv->pub for the same reason: a derivation bug must
          ;; surface as a missing-key signing error, never as a witness built
          ;; for a different output.
          (unless (equalp output-key (subseq script 2 34))
            (bitcoin-lisp:log-warn
             "wallet-sign: tr() spend data derives ~A but the output is ~A; skipped"
             (bitcoin-lisp.crypto:bytes-to-hex output-key)
             (bitcoin-lisp.crypto:bytes-to-hex (subseq script 2 34)))
            (return-from %spkm-tr-script-leaves nil))
          (let ((next (%pairs-splitter (rest pairs))))
            (loop for (script leaf-hash control) in leaves
                  for (nil . leaf) in (out-desc-tree desc)
                  for own = (funcall next leaf)
                  when own
                    collect (list script leaf-hash control leaf
                                  (mapcar #'cdr own)))))))))

(defun %wallet-sign-maps (wallet tx coins)
  "(values keymap pubmap tr-keymap tr-scripts) covering every input of TX whose
spent script belongs to a wallet SPKM. Each derived private key is verified to
reproduce its expected pubkey before it is trusted (funds-critical: a
derivation bug must surface as a missing-key signing error, never as a
wrong-key signature).

TR-SCRIPTS maps a taproot output key to its spendable script paths, which is
the only route by which a tr() descriptor WITH a script tree can be spent: its
output key is the internal key tweaked by the merkle root, so it is absent from
TR-KEYMAP (keyed on the BIP86 untweaked-root form) by construction."
  (let ((keymap (make-hash-table :test 'equalp))
        (pubmap (make-hash-table :test 'equalp))
        (tr-keymap (make-hash-table :test 'equalp))
        (tr-scripts (make-hash-table :test 'equalp)))
    (bitcoin-lisp.serialization:dovector
        (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (entry (gethash (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                                   (bitcoin-lisp.serialization:outpoint-index prevout))
                             coins))
             (script (and entry (first entry))))
        (when script
          (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet script)
            (when (and spkm (spkm-have-private-keys-p spkm))
              (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
                (declare (ignore scripts))
                (let ((provider (spkm-privkey-provider wallet spkm)))
                  (loop for (key . pubkey) in pairs
                        for priv = (%desc-key-priv-at key pos provider)
                        do (when priv
                             (%sign-map-add-key! keymap pubmap tr-keymap
                                                 key pubkey priv pos))))
                (let ((leaves (%spkm-tr-script-leaves spkm script pos)))
                  (when leaves
                    (setf (gethash (subseq script 2 34) tr-scripts) leaves)))))))))
    (values keymap pubmap tr-keymap tr-scripts)))

(defun %wallet-sign-transaction (wallet tx coins &key (sighash-byte 1))
  "Core CWallet::SignTransaction: sign every input COINS covers with keys
from the wallet's SPKMs. COINS: (txid . vout) -> (script-pubkey amount
redeem-script witness-script). Returns the (index . message) error list;
NIL = complete."
  (multiple-value-bind (keymap pubmap tr-keymap tr-scripts)
      (%wallet-sign-maps wallet tx coins)
    (%sign-tx-inputs tx coins keymap pubmap tr-keymap sighash-byte tr-scripts)))

(defun %wallet-input-coins (node wallet tx &optional cc)
  "The signing/verification coins map for TX: (txid . vout) ->
(script-pubkey amount redeem witness-script), sourced from the wallet's
TXOs, the coin control's external outputs, the UTXO set, and the mempool.
Missing prevouts are simply absent. Caller holds node + wallet locks."
  (let ((coins (make-hash-table :test 'equalp)))
    (bitcoin-lisp.serialization:dovector
        (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (txid (bitcoin-lisp.serialization:outpoint-hash prevout))
             (vout (bitcoin-lisp.serialization:outpoint-index prevout))
             (txout (%wallet-input-txout node wallet txid vout cc)))
        (when txout
          (let ((script (bitcoin-lisp.serialization:tx-out-script-pubkey txout)))
            (multiple-value-bind (redeem witness)
                (%known-sub-scripts wallet cc script)
              (setf (gethash (cons txid vout) coins)
                    (list script
                          (bitcoin-lisp.serialization:tx-out-value txout)
                          redeem witness)))))))
    coins))

;;; --- Pre-broadcast script verification (extra funds-safety rail) ---

(defun %verify-tx-scripts (tx coins)
  "Run our own script verifier over every input of TX against the EXACT
spent scriptPubKey/amount in COINS, under the standard flag set. Returns
(values t nil) or (values nil failing-input-index). A missing coin fails
its input (a tx we cannot fully verify is never broadcast)."
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (n (length inputs))
         (spent (make-array n)))
    (dotimes (i n)
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output
                       (aref inputs i)))
             (entry (gethash (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                                   (bitcoin-lisp.serialization:outpoint-index prevout))
                             coins)))
        (unless entry (return-from %verify-tx-scripts (values nil i)))
        (setf (aref spent i)
              (bitcoin-lisp.storage:make-utxo-entry
               :value (second entry)
               :script-pubkey (coerce (first entry)
                                      '(simple-array (unsigned-byte 8) (*)))))))
    (let ((bitcoin-lisp.coalton.interop:*script-flags*
            bitcoin-lisp.validation:+standard-script-verify-flags+)
          (bitcoin-lisp.coalton.interop:*precomputed-sighash*
            (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx spent))
          (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent))
      (dotimes (i n)
        (unless (bitcoin-lisp.validation:validate-input-script tx i (aref spent i))
          (return-from %verify-tx-scripts (values nil i))))
      (values t nil))))

;;; --- CreateTransactionInternal (spend.cpp:1063-1438) ---

(defun %recipient-outputs (recipients)
  (mapcar (lambda (recipient)
            (bitcoin-lisp.serialization:make-tx-out
             :value (recipient-amount recipient)
             :script-pubkey (recipient-script recipient)))
          recipients))

(defun %create-transaction-internal (node wallet recipients change-pos cc sign
                                     rng)
  "Core CreateTransactionInternal. Returns
(values tx fee change-pos fee-reason) or (values nil error-message).
Caller holds node + wallet locks."
  (let ((params (make-csel-params :rng rng))
        (reservation (make-reservedest))
        (reserve-error nil)
        (keep-reservation nil))
    (unwind-protect
        (block build
          (flet ((fail (message)
                   (return-from build (values nil message))))
            (setf (csel-params-avoid-partial-spends params)
                  (wcc-avoid-partial-spends cc)
                  (csel-params-include-unsafe-inputs params)
                  (wcc-include-unsafe cc)
                  (csel-params-max-tx-weight params)
                  (or (wcc-max-tx-weight cc)
                      bitcoin-lisp.validation:+max-standard-tx-weight+)
                  (csel-params-version params) (wcc-version cc))
            (let ((minimum-tx-weight (* 4 +min-standard-tx-nonwitness-size+))
                  (max-weight (csel-params-max-tx-weight params)))
              (when (or (< max-weight minimum-tx-weight)
                        (> max-weight bitcoin-lisp.validation:+max-standard-tx-weight+))
                (fail (format nil "Maximum transaction weight must be between ~D and ~D"
                              minimum-tx-weight
                              bitcoin-lisp.validation:+max-standard-tx-weight+))))
            (setf (csel-params-long-term-feerate params)
                  *wallet-consolidate-feerate*)
            (setf (csel-params-tx-noinputs-size params)
                  (+ 10 (%compact-size-size (length recipients))))
            (let ((recipients-sum 0)
                  (outputs-to-subtract-fee-from 0)
                  (change-type (%transaction-change-type
                                wallet (wcc-change-type cc) recipients)))
              (dolist (recipient recipients)
                (when (%output-dust-p (recipient-amount recipient)
                                      (recipient-script recipient))
                  (fail "Transaction amount too small"))
                (incf (csel-params-tx-noinputs-size params)
                      (%txout-serialize-size (recipient-script recipient)))
                (incf recipients-sum (recipient-amount recipient))
                (when (recipient-sffo recipient)
                  (incf outputs-to-subtract-fee-from)
                  (setf (csel-params-subtract-fee-outputs params) t)))
              ;; Change script: coin control's, else a fresh INTERNAL keypool
              ;; address (persist-before-issue; never an external-chain or
              ;; reused address — funds rule).
              (let ((script-change (wcc-dest-change cc)))
                (unless script-change
                  (multiple-value-bind (address error)
                      (reservedest-reserve reservation wallet change-type)
                    (if address
                        (setf script-change (reservedest-script reservation))
                        (setf reserve-error
                              (format nil "Transaction needs a change address, but we can't generate it. ~A"
                                      error)))))
                (let ((change-script (or script-change
                                         (make-array 0 :element-type
                                                     '(unsigned-byte 8)))))
                  (setf (csel-params-change-output-size params)
                        (%txout-serialize-size change-script))
                  (let ((change-spend-size
                          (%max-signed-input-vsize wallet nil change-script)))
                    (setf (csel-params-change-spend-size params)
                          (if (minusp change-spend-size)
                              +dummy-nested-p2wpkh-input-size+
                              change-spend-size)))
                  (setf (csel-params-discard-feerate params)
                        (%wallet-discard-rate node))
                  (multiple-value-bind (feerate reason)
                      (%wallet-minimum-fee-rate node cc)
                    (when (and (wcc-feerate cc) (> feerate (wcc-feerate cc)))
                      (fail (format nil "Fee rate (~A) is lower than the minimum fee rate setting (~A)"
                                    (%format-feerate-sat-vb (wcc-feerate cc))
                                    (%format-feerate-sat-vb feerate))))
                    (when (and (eq reason :fallback)
                               (zerop bitcoin-lisp:*wallet-fallback-fee*))
                      (fail "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee."))
                    (setf (csel-params-effective-feerate params) feerate)
                    (setf (csel-params-change-fee params)
                          (%feerate-fee feerate
                                        (csel-params-change-output-size params)))
                    (setf (csel-params-cost-of-change params)
                          (+ (%feerate-fee (csel-params-discard-feerate params)
                                           (csel-params-change-spend-size params))
                             (csel-params-change-fee params)))
                    (setf (csel-params-min-change-target params)
                          (generate-change-target
                           (floor recipients-sum (max 1 (length recipients)))
                           (csel-params-change-fee params) rng))
                    ;; Smallest viable change: >= dust at the discard rate,
                    ;; and > the fee to spend it at the discard rate.
                    (let ((dust (%dust-threshold-at-rate
                                 change-script
                                 (csel-params-discard-feerate params)))
                          (change-spend-fee
                            (%feerate-fee (csel-params-discard-feerate params)
                                          (csel-params-change-spend-size params))))
                      (setf (csel-params-min-viable-change params)
                            (max (1+ change-spend-fee) dust)))
                    (let* ((not-input-fees
                             (%feerate-fee feerate
                                           (if (csel-params-subtract-fee-outputs params)
                                               0
                                               (csel-params-tx-noinputs-size params))))
                           (selection-target (+ recipients-sum not-input-fees)))
                      (when (and (zerop selection-target)
                                 (null (wcc-selected cc)))
                        (fail "Transaction requires one destination of non-zero value, a non-zero feerate, or a pre-selected input"))
                      (multiple-value-bind (preset-coins preset-error)
                          (if (wcc-selected cc)
                              (%fetch-selected-inputs node wallet cc params)
                              (values '() nil))
                        (when preset-error (fail preset-error))
                        (let* ((skip (when (wcc-selected cc)
                                       (let ((table (make-hash-table :test 'equalp)))
                                         (dolist (outpoint (wcc-selected cc))
                                           (setf (gethash (%wtx-outpoint-key
                                                           (car outpoint)
                                                           (cdr outpoint))
                                                          table)
                                                 t))
                                         table)))
                               (available-coins
                                 (if (wcc-allow-other-inputs cc)
                                     (wallet-available-coins
                                      wallet
                                      :min-depth (wcc-min-depth cc)
                                      :max-depth (wcc-max-depth cc)
                                      :only-safe (not (wcc-include-unsafe cc))
                                      ;; Core CoinFilterParams default
                                      ;; min_amount = 1: zero-value outputs
                                      ;; are never selection candidates.
                                      :min-amount 1
                                      :feerate feerate
                                      :input-bytes-fn
                                      (lambda (script)
                                        (%max-signed-input-vsize wallet cc script))
                                      :allow-used-addresses
                                      (or (not (wallet-flag-set-p
                                                wallet +wallet-flag-avoid-reuse+))
                                          (not (wcc-avoid-address-reuse cc)))
                                      :skip-outpoints skip
                                      :check-version-trucness t
                                      :tx-version (wcc-version cc)
                                      :mempool (bitcoin-lisp::node-mempool node))
                                     '())))
                          (multiple-value-bind (selection select-error)
                              (%select-coins node available-coins preset-coins
                                             selection-target params cc)
                            (when (null selection)
                              (when select-error (fail select-error))
                              ;; Enough balance but not enough to also cover
                              ;; fees? (spend.cpp:1217-1231)
                              (let ((available-balance
                                      (+ (reduce #'+ preset-coins
                                                 :key (lambda (c)
                                                        (bitcoin-lisp.serialization:tx-out-value
                                                         (wallet-coin-output c)))
                                                 :initial-value 0)
                                         (reduce #'+ available-coins
                                                 :key (lambda (c)
                                                        (bitcoin-lisp.serialization:tx-out-value
                                                         (wallet-coin-output c)))
                                                 :initial-value 0))))
                                (when (>= available-balance recipients-sum)
                                  (let ((effective-balance
                                          (+ (reduce #'+ preset-coins
                                                     :key (lambda (c)
                                                            (or (wallet-coin-effective-value c) 0))
                                                     :initial-value 0)
                                             (reduce #'+ available-coins
                                                     :key (lambda (c)
                                                            (or (wallet-coin-effective-value c) 0))
                                                     :initial-value 0))))
                                    (when (< effective-balance selection-target)
                                      (fail (format nil "The total exceeds your balance when the ~A transaction fee is included."
                                                    (%format-money
                                                     (- selection-target
                                                        recipients-sum)))))))
                                (fail "Insufficient funds")))
                            ;; --- Outputs ---
                            (let ((outputs (%recipient-outputs recipients))
                                  (change-amount
                                    (sel-result-get-change
                                     selection
                                     (csel-params-min-viable-change params)
                                     (csel-params-change-fee params)))
                                  (final-change-pos change-pos))
                              (if (plusp change-amount)
                                  (progn
                                    (cond
                                      ((null final-change-pos)
                                       (setf final-change-pos
                                             (wrng-randrange rng (1+ (length outputs)))))
                                      ((> final-change-pos (length outputs))
                                       (fail "Transaction change output index out of range")))
                                    (let ((change-output
                                            (bitcoin-lisp.serialization:make-tx-out
                                             :value change-amount
                                             :script-pubkey
                                             ;; Empty when the keypool ran
                                             ;; out — the build then fails
                                             ;; with RESERVE-ERROR before
                                             ;; signing (Core's empty
                                             ;; scriptChange + late check).
                                             (or (wcc-dest-change cc)
                                                 (reservedest-script reservation)
                                                 (make-array 0 :element-type
                                                             '(unsigned-byte 8))))))
                                      (setf outputs
                                            (append (subseq outputs 0 final-change-pos)
                                                    (list change-output)
                                                    (subseq outputs final-change-pos)))))
                                  (setf final-change-pos nil))
                              ;; --- Inputs: shuffle, preset order first ---
                              (let ((selected-coins
                                      (wrng-shuffle rng (sel-result-inputs selection))))
                                (when (wcc-selected cc)
                                  (setf selected-coins
                                        (stable-sort
                                         selected-coins
                                         (lambda (a b)
                                           (let* ((pa (gethash (cons (wallet-coin-txid a)
                                                                     (wallet-coin-index a))
                                                               (wcc-presets cc)))
                                                  (pb (gethash (cons (wallet-coin-txid b)
                                                                     (wallet-coin-index b))
                                                               (wcc-presets cc))))
                                             (cond ((and pa pb)
                                                    (< (wcc-preset-position pa)
                                                       (wcc-preset-position pb)))
                                                   (pa t)
                                                   (t nil)))))))
                                (let* ((use-anti-fee-sniping t)
                                       (default-sequence
                                         (if (%wcc-signal-rbf cc)
                                             +max-bip125-rbf-sequence+
                                             +max-sequence-nonfinal+))
                                       (inputs
                                         (mapcar
                                          (lambda (coin)
                                            (let* ((preset (gethash (cons (wallet-coin-txid coin)
                                                                          (wallet-coin-index coin))
                                                                    (wcc-presets cc)))
                                                   (sequence (and preset
                                                                  (wcc-preset-sequence preset))))
                                              (when sequence
                                                (setf use-anti-fee-sniping nil))
                                              (bitcoin-lisp.serialization:make-tx-in
                                               :previous-output
                                               (bitcoin-lisp.serialization:make-outpoint
                                                :hash (wallet-coin-txid coin)
                                                :index (wallet-coin-index coin))
                                               :script-sig
                                               (or (and preset
                                                        (wcc-preset-script-sig preset))
                                                   (make-array 0 :element-type
                                                               '(unsigned-byte 8)))
                                               :sequence (or sequence
                                                             default-sequence))))
                                          selected-coins))
                                       (tx (bitcoin-lisp.serialization:make-transaction
                                            :version (wcc-version cc)
                                            :inputs (coerce inputs 'simple-vector)
                                            :outputs (coerce outputs 'simple-vector)
                                            :lock-time 0)))
                                  ;; Preset witnesses (fundrawtransaction on a
                                  ;; partially-signed tx).
                                  (let ((witnesses (make-array (length inputs)
                                                               :initial-element '()))
                                        (any nil))
                                    (loop for coin in selected-coins
                                          for i from 0
                                          for preset = (gethash (cons (wallet-coin-txid coin)
                                                                      (wallet-coin-index coin))
                                                                (wcc-presets cc))
                                          do (when (and preset
                                                        (wcc-preset-script-witness preset))
                                               (setf (aref witnesses i)
                                                     (wcc-preset-script-witness preset)
                                                     any t)))
                                    (when any
                                      (setf (bitcoin-lisp.serialization:transaction-witness tx)
                                            witnesses)))
                                  (cond
                                    ((wcc-locktime cc)
                                     (setf (bitcoin-lisp.serialization:transaction-lock-time tx)
                                           (wcc-locktime cc))
                                     (setf use-anti-fee-sniping nil))
                                    (t nil))
                                  (when use-anti-fee-sniping
                                    (discourage-fee-sniping
                                     tx rng node
                                     (wallet-last-block-hash wallet)
                                     (wallet-last-block-height wallet)))
                                  ;; --- Exact fee loop ---
                                  (let ((txouts
                                          (mapcar
                                           (lambda (coin)
                                             (let ((preset (gethash (cons (wallet-coin-txid coin)
                                                                          (wallet-coin-index coin))
                                                                    (wcc-presets cc))))
                                               (cons (bitcoin-lisp.serialization:tx-out-script-pubkey
                                                      (wallet-coin-output coin))
                                                     (and preset
                                                          (wcc-preset-weight preset)))))
                                           selected-coins)))
                                    (multiple-value-bind (vsize est-weight)
                                        (%max-signed-tx-size wallet cc tx txouts)
                                      (when (minusp vsize)
                                        (fail "Missing solving data for estimating transaction size"))
                                      (let* ((fee-needed
                                               (+ (%feerate-fee
                                                   (csel-params-effective-feerate params)
                                                   vsize)
                                                  (sel-result-total-bump-fees selection)))
                                             (output-value
                                               (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs tx)
                                                       :key #'bitcoin-lisp.serialization:tx-out-value
                                                       :initial-value 0))
                                             (current-fee
                                               (- (sel-result-selected-value selection)
                                                  output-value)))
                                        (unless (= (+ recipients-sum change-amount)
                                                   output-value)
                                          (fail "Internal bug detected: output value mismatch"))
                                        (when (minusp current-fee)
                                          (fail "Internal bug detected: Fee paid < 0"))
                                        ;; Overpaying? grow the change.
                                        (when (and final-change-pos
                                                   (< fee-needed current-fee))
                                          (let ((change-output
                                                  (aref (bitcoin-lisp.serialization:transaction-outputs tx)
                                                        final-change-pos)))
                                            (incf (bitcoin-lisp.serialization:tx-out-value
                                                   change-output)
                                                  (- current-fee fee-needed))
                                            (setf current-fee
                                                  (- (sel-result-selected-value selection)
                                                     (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs tx)
                                                             :key #'bitcoin-lisp.serialization:tx-out-value
                                                             :initial-value 0)))
                                            (unless (= fee-needed current-fee)
                                              (fail "Internal bug detected: Change adjustment: Fee needed != fee paid"))))
                                        ;; SFFO: reduce the marked outputs.
                                        (when (csel-params-subtract-fee-outputs params)
                                          (let ((to-reduce (- fee-needed current-fee))
                                                (i 0)
                                                (first-p t)
                                                (txvout (bitcoin-lisp.serialization:transaction-outputs tx)))
                                            (dolist (recipient recipients)
                                              (when (and final-change-pos
                                                         (= i final-change-pos))
                                                (incf i))
                                              (let ((output (aref txvout i)))
                                                (when (recipient-sffo recipient)
                                                  ;; C++ integer division
                                                  ;; truncates toward zero:
                                                  ;; truncate/rem, not
                                                  ;; floor/mod (to-reduce can
                                                  ;; be negative in edge
                                                  ;; cases, exactly as in
                                                  ;; Core).
                                                  (decf (bitcoin-lisp.serialization:tx-out-value output)
                                                        (truncate to-reduce
                                                                  outputs-to-subtract-fee-from))
                                                  (when first-p
                                                    (setf first-p nil)
                                                    ;; First recipient pays
                                                    ;; the remainder not
                                                    ;; divisible by the
                                                    ;; output count.
                                                    (decf (bitcoin-lisp.serialization:tx-out-value output)
                                                          (rem to-reduce
                                                               outputs-to-subtract-fee-from)))
                                                  (when (%output-dust-p
                                                         (bitcoin-lisp.serialization:tx-out-value output)
                                                         (bitcoin-lisp.serialization:tx-out-script-pubkey output))
                                                    (if (minusp (bitcoin-lisp.serialization:tx-out-value output))
                                                        (fail "The transaction amount is too small to pay the fee")
                                                        (fail "The transaction amount is too small to send after the fee has been deducted")))))
                                              (incf i))
                                            (setf current-fee
                                                  (- (sel-result-selected-value selection)
                                                     (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs tx)
                                                             :key #'bitcoin-lisp.serialization:tx-out-value
                                                             :initial-value 0)))
                                            (unless (= fee-needed current-fee)
                                              (fail "Internal bug detected: SFFO: Fee needed != fee paid"))))
                                        (when (> fee-needed current-fee)
                                          (fail "Internal bug detected: Fee needed > fee paid"))
                                        ;; Change required but keypool empty.
                                        (when (and final-change-pos
                                                   (null (wcc-dest-change cc))
                                                   (null (reservedest-script reservation)))
                                          (fail reserve-error))
                                        ;; --- Sign + verify ---
                                        (when sign
                                          (let ((coins (%wallet-input-coins
                                                        node wallet tx cc)))
                                            (when (%wallet-sign-transaction
                                                   wallet tx coins)
                                              (fail "Signing transaction failed"))
                                            ;; EXTRA rail (divergence 5): the
                                            ;; fully-signed tx must verify
                                            ;; against the exact spent
                                            ;; scripts/amounts before it can
                                            ;; ever be stored or relayed.
                                            (multiple-value-bind (ok bad-input)
                                                (%verify-tx-scripts tx coins)
                                              (unless ok
                                                (fail (format nil "Internal bug detected: signed transaction fails script verification at input ~D"
                                                              bad-input))))))
                                        ;; --- Caps ---
                                        (let ((final-weight
                                                (if sign
                                                    (bitcoin-lisp.serialization:transaction-weight tx)
                                                    est-weight)))
                                          (when (> final-weight
                                                   bitcoin-lisp.validation:+max-standard-tx-weight+)
                                            (fail "Transaction too large")))
                                        (when (> current-fee
                                                 bitcoin-lisp:*wallet-max-tx-fee*)
                                          (fail +max-fee-exceeded-message+))
                                        ;; -walletrejectlongchains'
                                        ;; checkChainLimits simulation is not
                                        ;; run pre-commit (divergence 4).
                                        (setf keep-reservation t)
                                        (bitcoin-lisp:log-info
                                         "Coin Selection: Algorithm:~(~A~), Waste Metric Score:~D; fee ~D sat over ~D vB"
                                         (sel-result-algo selection)
                                         (sel-result-waste selection)
                                         current-fee vsize)
                                        (values tx current-fee final-change-pos
                                                (%fee-reason-string reason))))))))))))))))))
      ;; A reserved change address is returned to the keypool on ANY failed
      ;; build (Core ReserveDestination destructor); kept on success.
      (unless keep-reservation
        (reservedest-return reservation)))))

;;; --- CreateTransaction (spend.cpp:1440-1492: wrapper + APS retry) ---

(defun %create-transaction (node wallet recipients change-pos cc sign)
  "Core CreateTransaction. Returns (values tx fee change-pos fee-reason) or
(values nil error-message). Caller holds node + wallet locks."
  (when (null recipients)
    (return-from %create-transaction
      (values nil "Transaction must have at least one recipient")))
  (when (some (lambda (recipient) (minusp (recipient-amount recipient)))
              recipients)
    (return-from %create-transaction
      (values nil "Transaction amounts must not be negative")))
  (let ((rng (%rng)))
    (multiple-value-bind (tx fee tx-change-pos fee-reason)
        (%create-transaction-internal node wallet recipients change-pos cc sign
                                      rng)
      (unless tx
        (return-from %create-transaction (values nil fee)))
      ;; Try again with avoid-partial-spends grouping; use that result when
      ;; it costs no more than *wallet-max-aps-fee* extra satoshis.
      (when (and (plusp fee)
                 (> *wallet-max-aps-fee* -1)
                 (not (wcc-avoid-partial-spends cc)))
        (let ((aps-cc (copy-wcc cc)))
          (setf (wcc-avoid-partial-spends aps-cc) t)
          ;; Reuse the first attempt's change destination so BIP44 indexes
          ;; are not skipped.
          (when tx-change-pos
            (setf (wcc-dest-change aps-cc)
                  (bitcoin-lisp.serialization:tx-out-script-pubkey
                   (aref (bitcoin-lisp.serialization:transaction-outputs tx)
                         tx-change-pos))))
          (multiple-value-bind (aps-tx aps-fee aps-change-pos aps-reason)
              (%create-transaction-internal node wallet recipients change-pos
                                            aps-cc sign rng)
            (when (and aps-tx (<= aps-fee (+ fee *wallet-max-aps-fee*)))
              (bitcoin-lisp:log-info
               "Fee non-grouped = ~D, grouped = ~D, using grouped" fee aps-fee)
              (setf tx aps-tx fee aps-fee tx-change-pos aps-change-pos
                    fee-reason aps-reason)))))
      (values tx fee tx-change-pos fee-reason))))

;;; --- FundTransaction core (spend.cpp:1494-1546) ---

(defun %fund-transaction (node wallet tx recipients change-pos lock-unspents cc)
  "Core wallet::FundTransaction: TX's inputs become preset inputs, its
locktime/version transfer to the coin control, and CreateTransaction runs
unsigned. Returns (values tx fee change-pos) or (values nil error-message).
Caller holds node + wallet locks."
  (setf (wcc-locktime cc) (bitcoin-lisp.serialization:transaction-lock-time tx))
  (setf (wcc-version cc) (bitcoin-lisp.serialization:transaction-version tx))
  (bitcoin-lisp.serialization:dovector
      (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
           (txid (bitcoin-lisp.serialization:outpoint-hash prevout))
           (vout (bitcoin-lisp.serialization:outpoint-index prevout))
           (preset (wcc-select cc txid vout))
           (wtx (wallet-get-wallet-tx wallet txid))
           (mine (and wtx
                      (< vout (length (bitcoin-lisp.serialization:transaction-outputs
                                       (wallet-tx-tx wtx))))
                      (%wallet-script-mine-p
                       wallet
                       (bitcoin-lisp.serialization:tx-out-script-pubkey
                        (aref (bitcoin-lisp.serialization:transaction-outputs
                               (wallet-tx-tx wtx))
                              vout))))))
      (unless mine
        (let ((txout (%wallet-input-txout node wallet txid vout cc)))
          (unless txout
            (return-from %fund-transaction
              (values nil "Unable to find UTXO for external input")))
          (setf (wcc-preset-txout preset) txout)))
      (setf (wcc-preset-sequence preset)
            (bitcoin-lisp.serialization:tx-in-sequence input))
      (let ((script-sig (bitcoin-lisp.serialization:tx-in-script-sig input)))
        (when (plusp (length script-sig))
          (setf (wcc-preset-script-sig preset) script-sig)))
      (let* ((witnesses (bitcoin-lisp.serialization:transaction-witness tx))
             (index (position input (bitcoin-lisp.serialization:transaction-inputs tx)))
             (stack (and witnesses index (< index (length witnesses))
                         (aref witnesses index))))
        (when stack
          (setf (wcc-preset-script-witness preset) stack)))))
  (multiple-value-bind (new-tx fee tx-change-pos)
      (%create-transaction node wallet recipients change-pos cc nil)
    (unless new-tx (return-from %fund-transaction (values nil fee)))
    (when lock-unspents
      (bitcoin-lisp.serialization:dovector
          (input (bitcoin-lisp.serialization:transaction-inputs new-tx))
        (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input)))
          (wallet-lock-coin wallet
                            (bitcoin-lisp.serialization:outpoint-hash prevout)
                            (bitcoin-lisp.serialization:outpoint-index prevout)
                            nil))))
    (values new-tx fee tx-change-pos)))

;;; --- Mempool submission + broadcast (node/transaction.cpp
;;; BroadcastTransaction; wallet.cpp SubmitTxMemoryPoolAndRelay) ---

(defun %wallet-submit-tx (node tx &key relay)
  "Submit TX to the mempool, enforcing *wallet-max-tx-fee*; with RELAY, add
it to the unbroadcast set and announce to peers (the sendrawtransaction
path). A tx already in the mempool is only (re)announced. Caller holds the
node lock. Returns (values ok error-string)."
  (let* ((txid (bitcoin-lisp.serialization:transaction-hash tx))
         (utxo-set (rpc-get-utxo-set node))
         (mempool (rpc-get-mempool node))
         (chain-state (rpc-get-chain-state node))
         (current-height (bitcoin-lisp.storage:current-height chain-state)))
    (unless mempool
      (return-from %wallet-submit-tx (values nil "no mempool")))
    (multiple-value-bind (valid error fee replaced sigops)
        (bitcoin-lisp.validation:validate-transaction-for-mempool
         tx utxo-set mempool current-height :chain-state chain-state)
      (cond
        ((and (not valid) (eq error :already-in-mempool))
         (when relay
           (bitcoin-lisp::broadcast-transaction-to-peers node txid))
         (values t nil))
        ((not valid)
         (values nil (format nil "~A" error)))
        ;; Funds rail: never hand the relay layer a tx over -maxtxfee (Core
        ;; BroadcastTransaction's max_tx_fee check, node/transaction.cpp:47).
        ((> fee bitcoin-lisp:*wallet-max-tx-fee*)
         (values nil +max-fee-exceeded-message+))
        (t
         (let ((result (bitcoin-lisp.mempool:accept-validated-tx
                        mempool txid tx fee current-height
                        :sigops sigops :replaced replaced)))
           (if (eq result :ok)
               (progn
                 (when relay
                   (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
                   (bitcoin-lisp::broadcast-transaction-to-peers node txid))
                 (values t nil))
               (values nil (format nil "~A" result)))))))))

(defun %wallet-commit-transaction (node wallet tx map-value)
  "Core CWallet::CommitTransaction: store the tx in the wallet (it spends
our coins; its change is ours), break the input coins' caches, then submit
to the mempool and relay. Broadcast failure is logged, never raised — the
tx stays in the wallet for the rebroadcast timer, exactly like Core.
Caller holds the NODE lock; holding this wallet's (recursive) lock across
the submission is safe because the mempool-accept hook fan-out reads the
manager's lock-free wallet snapshot — the manager LOCK is never taken from
hook context (see with-wallet-lock's lock-order contract)."
  (let ((wtx (with-wallet-lock (wallet)
               (prog1 (wallet-add-to-wallet wallet tx '(:inactive)
                                            :map-value map-value)
                 (wallet-mark-inputs-dirty wallet tx)))))
    (multiple-value-bind (ok error) (%wallet-submit-tx node tx :relay t)
      (unless ok
        (bitcoin-lisp:log-warn
         "CommitTransaction(): Transaction cannot be broadcast immediately, ~A"
         error)))
    wtx))

;;; --- Rebroadcast machinery (wallet.cpp:2061-2148) ---

(defconstant +resend-check-interval+ 60
  "Seconds between MaybeResendWalletTxs passes (Core schedules it every
minute; each wallet then gates on its own 12-36h m_next_resend).")

(defvar *last-resend-check* 0)

(defun %wallet-default-next-resend (&optional (rng (%rng)))
  "Core GetDefaultNextResend: now + 12h + uniform(24h)."
  (+ (bitcoin-lisp.serialization:get-unix-time)
     (* 12 3600)
     (wrng-randrange rng (* 24 3600))))

(defconstant +max-resubmit-per-pass+ 32
  "Cap on transactions one ResubmitWalletTransactions pass will push
through full mempool validation. Core runs its (unbounded) resubmission on
the scheduler thread; ours runs inline on the sync/housekeeping thread, so
each pass is bounded and a wallet with more stuck txs simply continues on
the next pass (~1 min later) — see wallets-maybe-resend.")

(defun wallet-resubmit-transactions (node wallet &key relay force limit)
  "Core ResubmitWalletTransactions: resubmit unconfirmed wallet txs to the
mempool in nOrderPos order; with RELAY also announce them. Without FORCE,
txs received within 5 minutes of the last block are skipped. LIMIT bounds
the number of submissions attempted this pass. Takes the locks itself
(node -> wallet per tx); call WITHOUT holding either. A failure on one tx
is logged and never aborts the rest (nor the caller). Returns
(values submitted remaining-p)."
  (let ((candidates
          (with-wallet-lock (wallet)
            (loop for wtx across (wallet-tx-ordered wallet)
                  when (and (%wtx-unconfirmed-p wtx)
                            (not (%wtx-coinbase-p wtx))
                            (zerop (wallet-tx-depth wallet wtx))
                            (or force
                                (<= (wallet-tx-time-received wtx)
                                    (- (wallet-last-block-time wallet) 300))))
                    collect wtx))))
    (let ((submitted 0)
          (attempted 0)
          (remaining nil))
      (dolist (wtx candidates)
        (when (and limit (>= attempted limit))
          (setf remaining t)
          (return))
        (incf attempted)
        (handler-case
            (with-node-lock (node)
              (let ((ok (with-wallet-lock (wallet)
                          ;; Re-check under the locks: state may have moved.
                          (and (%wtx-unconfirmed-p wtx)
                               (zerop (wallet-tx-depth wallet wtx))))))
                (when (and ok
                           (nth-value 0 (%wallet-submit-tx
                                         node (wallet-tx-tx wtx) :relay relay)))
                  (incf submitted))))
          (error (e)
            (bitcoin-lisp:log-error
             "ResubmitWalletTransactions: error resubmitting ~A (wallet ~A): ~A"
             (hash-to-hex (wallet-tx-txid wtx)) (wallet-name wallet) e))))
      (when (plusp submitted)
        (bitcoin-lisp:log-info "ResubmitWalletTransactions: resubmit ~D unconfirmed transactions (wallet ~A)"
                               submitted (wallet-name wallet)))
      (values submitted remaining))))

(defun wallets-maybe-resend (node)
  "Core MaybeResendWalletTxs, driven from the node's 1s housekeeping loop:
at most one pass per minute; each wallet resubmits only past its own
randomized next-resend time, then reschedules 12-36h out (or continues
next pass when the per-pass cap truncated the batch). No-ops during IBD
(Core isReadyToBroadcast). This runs on the sync thread, whose outer error
handler EXITS the thread with no respawn — so nothing here may ever unwind
into the caller: every wallet is isolated, and the whole pass is fenced.
The inline work is acceptable because each pass is bounded
(+max-resubmit-per-pass+ mempool validations, each under its own
node-lock hold) and this thread is idle between 1s housekeeping ticks."
  (handler-case
      (let ((manager (bitcoin-lisp::node-wallet-manager node)))
        (when (and manager (wallet-manager-has-wallets-p manager))
          (let ((now (bitcoin-lisp.serialization:get-unix-time)))
            (when (>= (- now *last-resend-check*) +resend-check-interval+)
              (setf *last-resend-check* now)
              (let ((chain-state (bitcoin-lisp::node-chain-state node)))
                (unless (or (null chain-state)
                            (bitcoin-lisp.networking:initial-block-download-p
                             chain-state))
                  (dolist (wallet (%manager-wallets manager))
                    (handler-case
                        (let ((next (wallet-next-resend wallet)))
                          (cond
                            ((null (wallet-db wallet)))  ; unloaded: skip
                            ((zerop next)
                             ;; First sighting: schedule, don't resend (Core
                             ;; seeds m_next_resend at construction).
                             (setf (wallet-next-resend wallet)
                                   (%wallet-default-next-resend)))
                            ((>= now next)
                             (multiple-value-bind (submitted remaining)
                                 (wallet-resubmit-transactions
                                  node wallet :relay t
                                  :limit +max-resubmit-per-pass+)
                               (declare (ignore submitted))
                               ;; Truncated pass: resume on the next 60s
                               ;; tick instead of waiting 12-36h.
                               (setf (wallet-next-resend wallet)
                                     (if remaining
                                         now
                                         (%wallet-default-next-resend)))))))
                      (error (e)
                        (bitcoin-lisp:log-error
                         "MaybeResendWalletTxs: wallet ~A resend pass failed: ~A"
                         (wallet-name wallet) e))))))))))
    (error (e)
      (bitcoin-lisp:log-error "MaybeResendWalletTxs: pass failed: ~A" e))))

(defun wallet-post-load-resubmit (node wallet)
  "Core CWallet::postInitProcess: push the loaded wallet's unconfirmed txs
back into OUR mempool (no relay — the periodic timer announces later).
Errors are logged, never raised: a resubmission problem must not fail
wallet loading or an importdescriptors rescan."
  (handler-case
      (wallet-resubmit-transactions node wallet :relay nil :force t)
    (error (e)
      (bitcoin-lisp:log-error
       "postInitProcess resubmit failed for wallet ~A: ~A"
       (wallet-name wallet) e))))

;;; --- RPC option plumbing (rpc/spend.cpp:46-236) ---

(defun %opt (options key)
  "(values value present-p) — options objects arrive as yason hash tables
or (in tests) alists."
  (%oval options key))

(defun %opt-present-p (options key)
  (nth-value 1 (%opt options key)))

(defun %parse-confirm-target (value)
  "Core ParseConfirmTarget."
  (unless (and (integerp value) (<= 1 value 1008))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid conf_target, must be between 1 and 1008"))
  value)

(defconstant +invalid-estimate-mode-message+
  (if (boundp '+invalid-estimate-mode-message+)
      (symbol-value '+invalid-estimate-mode-message+)
      "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\""))

(defun %fee-mode-from-string (string)
  (cond ((or (string-equal string "unset") (string= string "")) :unset)
        ((string-equal string "economical") :economical)
        ((string-equal string "conservative") :conservative)
        (t nil)))

(defun %set-fee-estimate-mode (cc conf-target estimate-mode fee-rate
                               override-min-fee)
  "Core SetFeeEstimateMode."
  (when fee-rate
    (when conf-target
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Cannot specify both conf_target and fee_rate. Please provide either a confirmation target in blocks for automatic fee estimation, or an explicit fee rate."))
    (when (and estimate-mode (not (string-equal estimate-mode "unset")))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Cannot specify both estimate_mode and fee_rate"))
    (setf (wcc-feerate cc) (%feerate-from-value fee-rate))
    (when override-min-fee (setf (wcc-override-feerate cc) t))
    ;; Default RBF to true for explicit fee_rate, if unset.
    (when (eq (wcc-signal-bip125-rbf cc) :unset)
      (setf (wcc-signal-bip125-rbf cc) t))
    (return-from %set-fee-estimate-mode))
  (when estimate-mode
    (let ((mode (%fee-mode-from-string estimate-mode)))
      (unless mode
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message +invalid-estimate-mode-message+))
      (setf (wcc-fee-mode cc) mode)))
  (when conf-target
    (setf (wcc-confirm-target cc) (%parse-confirm-target conf-target))))

(defun %interpret-fee-estimation-options (conf-target estimate-mode fee-rate
                                          options)
  "Core InterpretFeeEstimationInstructions: merge positional fee args into
the options alist. Returns the updated options ALIST (the incoming object's
pairs plus the moved arguments)."
  (let ((pairs '()))
    (cond ((hash-table-p options)
           (maphash (lambda (k v) (push (cons k v) pairs)) options)
           (setf pairs (nreverse pairs)))
          ((listp options) (setf pairs (copy-alist options))))
    (flet ((has (key) (assoc key pairs :test #'string=))
           (put (key value) (setf pairs (append pairs (list (cons key value))))))
      (if (or (has "conf_target") (has "estimate_mode"))
          (when (or conf-target estimate-mode)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Pass conf_target and estimate_mode either as arguments or in the options object, but not both"))
          (progn (when conf-target (put "conf_target" conf-target))
                 (when estimate-mode (put "estimate_mode" estimate-mode))))
      (if (has "fee_rate")
          (when fee-rate
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Pass the fee_rate either as an argument, or in the options object, but not both"))
          (when fee-rate (put "fee_rate" fee-rate)))
      (let ((ct (has "conf_target"))
            (em (has "estimate_mode")))
        (when (and ct (cdr ct)
                   (or (null em) (null (cdr em))
                       (and (stringp (cdr em)) (string-equal (cdr em) "unset"))))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Specify estimate_mode"))))
    pairs))

(defun %prevent-outdated-options (options)
  "Core PreventOutdatedOptions (send/sendall reject the legacy camelCase
fundrawtransaction option names)."
  (loop for (old . new) in '(("feeRate" . "Use fee_rate (sat/vB) instead of feeRate")
                             ("changeAddress" . "Use change_address instead of changeAddress")
                             ("changePosition" . "Use change_position instead of changePosition")
                             ("lockUnspents" . "Use lock_unspents instead of lockUnspents")
                             ("subtractFeeFromOutputs" . "Use subtract_fee_from_outputs instead of subtractFeeFromOutputs"))
        do (when (%opt-present-p options old)
             (error 'rpc-error :code +rpc-invalid-parameter+ :message new))))

(defun %parse-fund-options (node wallet cc options recipients override-min-fee)
  "The shared option block of fundrawtransaction / send /
walletcreatefundedpsbt (rpc/spend.cpp:470-687). Returns
(values change-position lock-unspents)."
  (declare (ignorable node))
  (let ((change-position nil)
        (lock-unspents nil)
        (network (wallet-network wallet)))
    (when (%opt-present-p options "add_inputs")
      (setf (wcc-allow-other-inputs cc) (and (%opt options "add_inputs") t)))
    (let ((change-address (or (%opt options "change_address")
                              (%opt options "changeAddress"))))
      (when change-address
        (multiple-value-bind (type script)
            (and (stringp change-address)
                 (bitcoin-lisp.crypto:decode-address change-address network))
          (declare (ignore type))
          (unless script
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message "Change address must be a valid bitcoin address"))
          (setf (wcc-dest-change cc) script))))
    (multiple-value-bind (pos present)
        (%opt options "change_position")
      (unless present
        (multiple-value-setq (pos present) (%opt options "changePosition")))
      (when present
        (unless (and (integerp pos) (<= 0 pos (length recipients)))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "changePosition out of bounds"))
        (setf change-position pos)))
    (let ((change-type (%opt options "change_type")))
      (when change-type
        (when (wcc-dest-change cc)
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Cannot specify both change address and address type options"))
        (let ((parsed (and (stringp change-type) (%parse-output-type change-type))))
          (unless parsed
            (error 'rpc-error :code +rpc-invalid-address-or-key+
                              :message (format nil "Unknown change type '~A'" change-type)))
          (setf (wcc-change-type cc) parsed))))
    (when (or (%opt options "lockUnspents") (%opt options "lock_unspents"))
      (setf lock-unspents t))
    (when (%opt options "include_unsafe")
      (setf (wcc-include-unsafe cc) t))
    (multiple-value-bind (fee-rate-btc-kvb present) (%opt options "feeRate")
      (when present
        (when (%opt-present-p options "fee_rate")
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Cannot specify both fee_rate (sat/vB) and feeRate (BTC/kvB)"))
        (when (%opt-present-p options "conf_target")
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Cannot specify both conf_target and feeRate. Please provide either a confirmation target in blocks for automatic fee estimation, or an explicit fee rate."))
        (when (%opt-present-p options "estimate_mode")
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Cannot specify both estimate_mode and feeRate"))
        (setf (wcc-feerate cc) (%amount-from-value fee-rate-btc-kvb))
        (setf (wcc-override-feerate cc) t)))
    (multiple-value-bind (replaceable present) (%opt options "replaceable")
      (when present
        (setf (wcc-signal-bip125-rbf cc) (and replaceable t))))
    (multiple-value-bind (minconf present) (%opt options "minconf")
      (when present
        (unless (integerp minconf)
          (error 'rpc-error :code +rpc-type-error+
                            :message "minconf must be an integer"))
        (when (minusp minconf)
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Negative minconf"))
        (setf (wcc-min-depth cc) minconf)))
    (multiple-value-bind (maxconf present) (%opt options "maxconf")
      (when present
        (unless (integerp maxconf)
          (error 'rpc-error :code +rpc-type-error+
                            :message "maxconf must be an integer"))
        (setf (wcc-max-depth cc) maxconf)
        (when (< (wcc-max-depth cc) (wcc-min-depth cc))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message (format nil "maxconf can't be lower than minconf: ~D < ~D"
                                             (wcc-max-depth cc)
                                             (wcc-min-depth cc))))))
    (unless (%opt-present-p options "feeRate")
      (%set-fee-estimate-mode cc
                              (%opt options "conf_target")
                              (%opt options "estimate_mode")
                              (%opt options "fee_rate")
                              override-min-fee))
    ;; solving_data: pubkeys / scripts / descriptors for size estimation of
    ;; external inputs.
    (multiple-value-bind (solving present) (%opt options "solving_data")
      (when present
        (multiple-value-bind (pubkeys pk-present) (%opt solving "pubkeys")
          (when pk-present
            (dolist (hex pubkeys)
              (let ((pubkey (%parse-multisig-pubkey hex)))
                (setf (gethash (bitcoin-lisp.crypto:hash160 pubkey)
                               (wcc-external-pubkeys cc))
                      pubkey)
                ;; Core also registers the P2WPKH witness script for each
                ;; pubkey; our sh(wpkh) sizing consults the pubkey map, so
                ;; nothing further is needed.
                ))))
        (multiple-value-bind (scripts s-present) (%opt solving "scripts")
          (when s-present
            (dolist (hex scripts)
              (unless (and (stringp hex) (evenp (length hex))
                           (every (lambda (ch) (digit-char-p ch 16)) hex))
                (error 'rpc-error :code +rpc-invalid-address-or-key+
                                  :message (format nil "'~A' is not hex" hex)))
              (%wcc-add-external-script cc (bitcoin-lisp.crypto:hex-to-bytes hex)))))
        (multiple-value-bind (descriptors d-present) (%opt solving "descriptors")
          (when d-present
            (dolist (desc-str descriptors)
              (let ((desc (handler-case
                              (parse-descriptor desc-str (wallet-network wallet))
                            (error (e)
                              (error 'rpc-error :code +rpc-invalid-parameter+
                                                :message (format nil "Unable to parse descriptor '~A': ~A"
                                                                 desc-str e))))))
                (multiple-value-bind (scripts pubkeys)
                    (handler-case
                        (out-desc-expand-with-provider
                         desc 0 (constantly nil) (make-descriptor-cache))
                      (descriptor-derivation-error () (values nil nil)))
                  (dolist (script scripts)
                    (%wcc-add-external-script cc script))
                  (dolist (pubkey pubkeys)
                    (setf (gethash (bitcoin-lisp.crypto:hash160 pubkey)
                                   (wcc-external-pubkeys cc))
                          pubkey)))))))))
    ;; input_weights: explicit per-input weight bounds.
    (multiple-value-bind (weights present) (%opt options "input_weights")
      (when present
        (dolist (entry weights)
          (let ((txid (%opt entry "txid"))
                (vout (%opt entry "vout"))
                (weight (%opt entry "weight")))
            (unless (and (stringp txid) (valid-hex-hash-p txid))
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Invalid parameter, missing txid key"))
            (unless (integerp vout)
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Invalid parameter, missing vout key"))
            (when (minusp vout)
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Invalid parameter, vout cannot be negative"))
            (unless (integerp weight)
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Invalid parameter, missing weight key"))
            (when (< weight 165)
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Invalid parameter, weight cannot be less than 165 (41 bytes (size of outpoint + sequence + empty scriptSig) * 4 (witness scaling factor)) + 1 (empty witness)"))
            (when (> weight bitcoin-lisp.validation:+max-standard-tx-weight+)
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message (format nil "Invalid parameter, weight cannot be greater than the maximum standard tx weight of ~D"
                                                 bitcoin-lisp.validation:+max-standard-tx-weight+)))
            (let ((preset (wcc-select cc (parse-hex-hash txid) vout)))
              (setf (wcc-preset-weight preset) weight))))))
    (multiple-value-bind (max-weight present) (%opt options "max_tx_weight")
      (when present
        (unless (integerp max-weight)
          (error 'rpc-error :code +rpc-type-error+
                            :message "max_tx_weight must be an integer"))
        (setf (wcc-max-tx-weight cc) max-weight)))
    ;; TRUC transactions are capped at TRUC_MAX_WEIGHT.
    (when (= (wcc-version cc) bitcoin-lisp.mempool:+truc-version+)
      (when (or (null (wcc-max-tx-weight cc))
                (> (wcc-max-tx-weight cc) +truc-max-weight+))
        (setf (wcc-max-tx-weight cc) +truc-max-weight+)))
    (values change-position lock-unspents)))

(defun %parse-rpc-inputs (inputs-param)
  "The inputs array of send/sendall/walletcreatefundedpsbt: a list of
(txid vout sequence weight) tuples, order preserved."
  (mapcar (lambda (entry)
            (let ((txid (%opt entry "txid"))
                  (vout (%opt entry "vout")))
              (unless (and (stringp txid) (valid-hex-hash-p txid))
                (error 'rpc-error :code +rpc-invalid-parameter+
                                  :message "txid must be of length 64 (not including any '0x' prefix)"))
              (unless (and (integerp vout) (>= vout 0))
                (error 'rpc-error :code +rpc-invalid-parameter+
                                  :message "Invalid parameter, vout cannot be negative"))
              (list (parse-hex-hash txid) vout
                    (%opt entry "sequence")
                    (%opt entry "weight"))))
          inputs-param))

(defun %apply-rpc-inputs (cc inputs rbf locktime)
  "Register the send/sendall preset inputs on CC with Core's
ConstructTransaction sequence defaults."
  (dolist (input inputs)
    (destructuring-bind (txid vout sequence weight) input
      (let ((preset (wcc-select cc txid vout)))
        (setf (wcc-preset-sequence preset)
              (cond (sequence
                     (unless (and (integerp sequence)
                                  (<= 0 sequence +sequence-final+))
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid parameter, sequence number is out of range"))
                     sequence)
                    (rbf +max-bip125-rbf-sequence+)
                    ((and locktime (plusp locktime)) +max-sequence-nonfinal+)
                    (t +sequence-final+)))
        (when weight
          (unless (integerp weight)
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Invalid parameter, missing weight key"))
          (setf (wcc-preset-weight preset) weight))))))

;;; --- FinishTransaction (rpc/spend.cpp:96-150) ---

(defun %serialize-txout-bytes (txout)
  (%wser (s) (bitcoin-lisp.serialization:write-tx-out s txout)))

(defun %serialize-witness-stack (stack)
  (%wser (s)
    (bitcoin-lisp.serialization:write-compact-size s (length stack))
    (dolist (element stack)
      (bitcoin-lisp.serialization:write-compact-size s (length element))
      (bitcoin-lisp.serialization:write-bytes s element))))

(defun %tx-to-finalized-psbt (node wallet signed-tx coins)
  "A PSBT for SIGNED-TX: the unsigned skeleton plus, per input, the known
UTXO (witness_utxo always; non_witness_utxo when the full previous tx is in
the wallet) and — for inputs that carry signatures — the finalized
final_scriptSig / final_scriptWitness, i.e. the state Core's
FillPSBT(sign)+FinalizePSBT leaves behind. DIVERGENCE (wallet P5 closes
it): no partial_sig records for UNSIGNED inputs and no bip32_derivs
metadata yet."
  (declare (ignorable node))
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs signed-tx))
         (n (length inputs))
         (unsigned (bitcoin-lisp.serialization:make-transaction
                    :version (bitcoin-lisp.serialization:transaction-version signed-tx)
                    :inputs (map 'simple-vector
                                 (lambda (input)
                                   (bitcoin-lisp.serialization:make-tx-in
                                    :previous-output (bitcoin-lisp.serialization:tx-in-previous-output input)
                                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                    :sequence (bitcoin-lisp.serialization:tx-in-sequence input)))
                                 inputs)
                    :outputs (bitcoin-lisp.serialization:transaction-outputs signed-tx)
                    :lock-time (bitcoin-lisp.serialization:transaction-lock-time signed-tx)))
         (psbt (bitcoin-lisp.serialization:make-empty-psbt unsigned))
         (witnesses (bitcoin-lisp.serialization:transaction-witness signed-tx))
         (empty-key (make-array 0 :element-type '(unsigned-byte 8))))
    (dotimes (i n)
      (let* ((input (aref inputs i))
             (prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (txid (bitcoin-lisp.serialization:outpoint-hash prevout))
             (vout (bitcoin-lisp.serialization:outpoint-index prevout))
             (entry (gethash (cons txid vout) coins))
             (map (aref (bitcoin-lisp.serialization:psbt-inputs psbt) i)))
        (when entry
          (bitcoin-lisp.serialization:psbt-map-set
           map bitcoin-lisp.serialization:+psbt-in-witness-utxo+ empty-key
           (%serialize-txout-bytes
            (bitcoin-lisp.serialization:make-tx-out
             :value (second entry) :script-pubkey (first entry))))
          (let ((wtx (wallet-get-wallet-tx wallet txid)))
            (when wtx
              (bitcoin-lisp.serialization:psbt-map-set
               map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+
               empty-key
               (bitcoin-lisp.serialization:transaction-wire-bytes
                (wallet-tx-tx wtx))))))
        (let ((script-sig (bitcoin-lisp.serialization:tx-in-script-sig input))
              (stack (and witnesses (< i (length witnesses)) (aref witnesses i))))
          (when (plusp (length script-sig))
            (bitcoin-lisp.serialization:psbt-map-set
             map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+ empty-key
             script-sig))
          (when stack
            (bitcoin-lisp.serialization:psbt-map-set
             map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+
             empty-key (%serialize-witness-stack stack))))))
    (bitcoin-lisp.serialization:encode-psbt psbt)))

(defun %finish-transaction (node wallet options tx)
  "Core FinishTransaction: optional anti-fee-sniping, wallet signing, then
commit-and-broadcast or serialized return per psbt/add_to_wallet. Caller
holds node + wallet locks."
  (let ((can-anti-fee-snipe (not (%opt-present-p options "locktime"))))
    (bitcoin-lisp.serialization:dovector
        (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let ((sequence (bitcoin-lisp.serialization:tx-in-sequence input)))
        (setf can-anti-fee-snipe
              (and can-anti-fee-snipe
                   (or (= sequence +max-sequence-nonfinal+)
                       (= sequence +max-bip125-rbf-sequence+))))))
    (when can-anti-fee-snipe
      (discourage-fee-sniping tx (%rng) node
                              (wallet-last-block-hash wallet)
                              (wallet-last-block-height wallet)))
    (let* ((coins (%wallet-input-coins node wallet tx))
           (sign-errors (%wallet-sign-transaction wallet tx coins))
           (complete (null sign-errors))
           (psbt-opt-in (and (%opt options "psbt") t))
           (add-to-wallet (if (%opt-present-p options "add_to_wallet")
                              (and (%opt options "add_to_wallet") t)
                              t))
           (result '()))
      (when complete
        ;; Funds rail: a complete tx must verify before it is committed,
        ;; returned, or relayed.
        (multiple-value-bind (ok bad-input) (%verify-tx-scripts tx coins)
          (unless ok
            (error 'rpc-error :code +rpc-wallet-error+
                              :message (format nil "Internal bug detected: signed transaction fails script verification at input ~D"
                                               bad-input)))))
      (when (or psbt-opt-in (not complete) (not add-to-wallet))
        (push (cons "psbt" (%tx-to-finalized-psbt node wallet tx coins)) result))
      (when complete
        (push (cons "txid" (hash-to-hex
                            (bitcoin-lisp.serialization:transaction-hash tx)))
              result)
        (if (and add-to-wallet (not psbt-opt-in))
            (%wallet-commit-transaction node wallet tx '())
            (push (cons "hex" (bitcoin-lisp.crypto:bytes-to-hex
                               (bitcoin-lisp.serialization:transaction-wire-bytes tx)))
                  result)))
      (push (cons "complete" (json-bool complete)) result)
      (nreverse result))))

;;; --- SendMoney (rpc/spend.cpp:171-198) ---

(defun %send-money (node wallet cc recipients map-value verbose)
  "Core SendMoney: shuffle recipients, create signed, commit, broadcast.
Caller holds the NODE lock (holding the wallet lock too is fine — it is
recursive, and the mempool hook fan-out reads the manager's lock-free
snapshot, so no lock-order inversion is possible; see with-wallet-lock)."
  (multiple-value-bind (tx fee-or-error change-pos fee-reason)
      (with-wallet-lock (wallet)
        (when (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+)
          (error 'rpc-error :code +rpc-wallet-error+
                            :message "Error: Private keys are disabled for this wallet"))
        ;; Checked inside the lock that also spans creation and signing, so
        ;; a relock cannot land between the check and the signature.
        (wallet-ensure-unlocked wallet)
        (%create-transaction node wallet (wrng-shuffle (%rng) recipients)
                             nil cc t))
    (declare (ignore change-pos))
    (unless tx
      ;; Core maps EVERY CreateTransaction failure to
      ;; RPC_WALLET_INSUFFICIENT_FUNDS here (rpc/spend.cpp:187); the second
      ;; value carries the error string on failure.
      (error 'rpc-error :code +rpc-wallet-insufficient-funds+
                        :message fee-or-error))
    (%wallet-commit-transaction node wallet tx map-value)
    (let ((txid-hex (hash-to-hex
                     (bitcoin-lisp.serialization:transaction-hash tx))))
      (if verbose
          `(("txid" . ,txid-hex)
            ("fee_reason" . ,fee-reason))
          txid-hex))))

;;; --- sendtoaddress (rpc/spend.cpp:238-334) ---

(defun rpc-sendtoaddress (node params)
  "Send an amount to an address (Bitcoin Core sendtoaddress). PARAMS:
(address amount comment comment_to subtractfeefromamount replaceable
conf_target estimate_mode avoid_reuse fee_rate verbose)."
  (let ((wallet (wallet-for-request node)))
    (with-node-lock (node)
      (with-wallet-lock (wallet)
        (let ((map-value '())
              (cc (make-wcc)))
          (let ((comment (nth 2 params))
                (comment-to (nth 3 params)))
            (when (and (stringp comment) (plusp (length comment)))
              (push (cons "comment" comment) map-value))
            (when (and (stringp comment-to) (plusp (length comment-to)))
              (push (cons "to" comment-to) map-value)))
          (let ((replaceable (nth 5 params)))
            ;; Core: `if (!params[5].isNull()) ... get_bool()` — explicit
            ;; false (the sentinel) must turn RBF signaling OFF, while
            ;; null/omitted keeps the wallet default.
            (unless (null replaceable)
              (setf (wcc-signal-bip125-rbf cc)
                    (%positional-bool replaceable))))
          (setf (wcc-avoid-address-reuse cc)
                (%get-avoid-reuse-flag wallet (nth 8 params)))
          (setf (wcc-avoid-partial-spends cc)
                (or (wcc-avoid-partial-spends cc)
                    (wcc-avoid-address-reuse cc)))
          (%set-fee-estimate-mode cc (nth 6 params) (nth 7 params)
                                  (nth 9 params) nil)
          (let ((address (first params)))
            (unless (stringp address)
              (error 'rpc-error :code +rpc-invalid-address-or-key+
                                :message (format nil "Invalid Bitcoin address: ~A" address)))
            (multiple-value-bind (recipients)
                (%parse-outputs (wallet-network wallet)
                                (list (cons address (second params))))
              (when (%positional-bool (nth 4 params))
                (setf (recipient-sffo (first recipients)) t))
              (let ((verbose (%positional-bool (nth 10 params))))
                (%send-money node wallet cc recipients (nreverse map-value)
                             verbose)))))))))

;;; --- sendmany (rpc/spend.cpp:336-428) ---

(defun rpc-sendmany (node params)
  "Send to multiple addresses (Bitcoin Core sendmany). PARAMS:
(dummy amounts minconf comment subtractfeefrom replaceable conf_target
estimate_mode fee_rate verbose)."
  (let ((wallet (wallet-for-request node)))
    (with-node-lock (node)
      (with-wallet-lock (wallet)
        (let ((dummy (first params)))
          (when (and dummy (not (and (stringp dummy) (zerop (length dummy)))))
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Dummy value must be set to \"\"")))
        (let ((map-value '())
              (cc (make-wcc)))
          (let ((comment (nth 3 params)))
            (when (and (stringp comment) (plusp (length comment)))
              (push (cons "comment" comment) map-value)))
          (let ((replaceable (nth 5 params)))
            (unless (null replaceable)
              (setf (wcc-signal-bip125-rbf cc)
                    (%positional-bool replaceable))))
          (%set-fee-estimate-mode cc (nth 6 params) (nth 7 params)
                                  (nth 8 params) nil)
          (multiple-value-bind (recipients keys)
              (%parse-outputs (wallet-network wallet) (second params))
            (%interpret-sffo (nth 4 params) keys recipients)
            (let ((verbose (%positional-bool (nth 9 params))))
              (%send-money node wallet cc recipients (nreverse map-value)
                           verbose))))))))

;;; --- fundrawtransaction (rpc/spend.cpp:706-839) ---

(defun rpc-fundrawtransaction (node params)
  "Fund a raw transaction from the wallet (Bitcoin Core
fundrawtransaction). PARAMS: (hexstring options iswitness)."
  (let ((wallet (wallet-for-request node))
        (hexstring (first params))
        (options (second params)))
    (unless (stringp hexstring)
      (error 'rpc-error :code +rpc-deserialization-error+
                        :message "TX decode failed"))
    (let ((tx (handler-case
                  (bitcoin-lisp.serialization:parse-tx-payload
                   (bitcoin-lisp.crypto:hex-to-bytes hexstring))
                (error () (error 'rpc-error :code +rpc-deserialization-error+
                                            :message "TX decode failed")))))
      (with-node-lock (node)
        (with-wallet-lock (wallet)
          (let ((network (wallet-network wallet))
                (recipients '())
                (keys '()))
            ;; Recipients from the existing outputs; the original script is
            ;; kept verbatim (Core round-trips through CTxDestination).
            (loop for output across (bitcoin-lisp.serialization:transaction-outputs tx)
                  do (push (make-recipient
                            :address (%script->address
                                      (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                                      network)
                            :script (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                            :amount (bitcoin-lisp.serialization:tx-out-value output))
                           recipients)
                     (push "dummy" keys))
            (setf recipients (nreverse recipients)
                  keys (nreverse keys))
            (%interpret-sffo (%opt options "subtractFeeFromOutputs") keys
                             recipients)
            (let ((cc (make-wcc :version (bitcoin-lisp.serialization:transaction-version tx))))
              (multiple-value-bind (change-position lock-unspents)
                  (%parse-fund-options node wallet cc options recipients t)
                (when (null recipients)
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "TX must have at least one output"))
                (multiple-value-bind (funded fee change-pos)
                    (%fund-transaction node wallet tx recipients
                                       change-position lock-unspents cc)
                  (unless funded
                    (error 'rpc-error :code +rpc-wallet-error+ :message fee))
                  `(("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
                               (bitcoin-lisp.serialization:transaction-wire-bytes funded)))
                    ("fee" . ,(%btc fee))
                    ("changepos" . ,(or change-pos -1))))))))))))

;;; --- send (rpc/spend.cpp:1169-1291) ---

(defun rpc-send (node params)
  "Send a transaction (Bitcoin Core send). PARAMS: (outputs conf_target
estimate_mode fee_rate options version). JSON-object outputs arrive as
hash tables whose key order is not preserved; use the array-of-objects
form when output order matters."
  (let ((wallet (wallet-for-request node)))
    (with-node-lock (node)
      (with-wallet-lock (wallet)
        (let* ((options (%interpret-fee-estimation-options
                         (nth 1 params) (nth 2 params) (nth 3 params)
                         (or (nth 4 params) '())))
               (version (if (and (> (length params) 5) (nth 5 params))
                            (nth 5 params)
                            2)))
          (%prevent-outdated-options options)
          ;; Stricter than Core (which accepts any uint32 and then commits
          ;; a tx its own mempool rejects): versions outside 1..3 can never
          ;; relay, so refusing up front is the funds-safe divergence.
          (unless (and (integerp version) (<= 1 version 3))
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Invalid parameter, version must be 1, 2, or 3"))
          (let* ((rbf (if (%opt-present-p options "replaceable")
                          (and (%opt options "replaceable") t)
                          *wallet-signal-rbf*))
                 (locktime (%opt options "locktime"))
                 (inputs (%parse-rpc-inputs (or (%opt options "inputs") '())))
                 (cc (make-wcc :version version)))
            (when (and locktime (not (integerp locktime)))
              (error 'rpc-error :code +rpc-type-error+
                                :message "locktime must be an integer"))
            (multiple-value-bind (recipients keys)
                (%parse-outputs (wallet-network wallet) (first params))
              (%interpret-sffo (%opt options "subtract_fee_from_outputs")
                               keys recipients)
              (%apply-rpc-inputs cc inputs rbf locktime)
              (setf (wcc-allow-other-inputs cc) (null inputs))
              (multiple-value-bind (change-position lock-unspents)
                  (%parse-fund-options node wallet cc options recipients nil)
                (setf (wcc-locktime cc) (or locktime 0))
                (multiple-value-bind (funded fee change-pos)
                    (%fund-transaction-for-send node wallet recipients
                                                change-position lock-unspents
                                                cc)
                  (declare (ignore fee change-pos))
                  (unless funded
                    (error 'rpc-error :code +rpc-wallet-error+
                                      :message "send failed"))
                  (%finish-transaction node wallet options funded))))))))))

(defun %fund-transaction-for-send (node wallet recipients change-position
                                   lock-unspents cc)
  "The FundTransaction step of send/sendall's ConstructTransaction path:
the preset inputs already live on CC (with sequences), so this is
CreateTransaction unsigned + optional coin locking. Errors carry Core's
FundTransaction wrapping (RPC_WALLET_ERROR)."
  (multiple-value-bind (tx fee change-pos)
      (%create-transaction node wallet recipients change-position cc nil)
    (unless tx
      (error 'rpc-error :code +rpc-wallet-error+ :message fee))
    (when lock-unspents
      (bitcoin-lisp.serialization:dovector
          (input (bitcoin-lisp.serialization:transaction-inputs tx))
        (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input)))
          (wallet-lock-coin wallet
                            (bitcoin-lisp.serialization:outpoint-hash prevout)
                            (bitcoin-lisp.serialization:outpoint-index prevout)
                            nil))))
    (values tx fee change-pos)))

;;; --- sendall (rpc/spend.cpp:1293-1571) ---

(defun rpc-sendall (node params)
  "Spend the value of all (or specific) confirmed UTXOs to one or more
recipients (Bitcoin Core sendall). PARAMS: (recipients conf_target
estimate_mode fee_rate options)."
  (let ((wallet (wallet-for-request node)))
    (with-node-lock (node)
      (with-wallet-lock (wallet)
        (let ((options (%interpret-fee-estimation-options
                        (nth 1 params) (nth 2 params) (nth 3 params)
                        (or (nth 4 params) '()))))
          (%prevent-outdated-options options)
          (let ((addresses-without-amount (make-hash-table :test 'equal))
                (pairs '()))
            (unless (and (listp (first params)) (first params))
              (error 'rpc-error :code +rpc-type-error+
                                :message "recipients must be a non-empty array"))
            (dolist (entry (first params))
              (cond
                ((stringp entry)
                 (push (cons entry 0) pairs)
                 (setf (gethash entry addresses-without-amount) t))
                ((hash-table-p entry)
                 (maphash (lambda (k v) (push (cons k v) pairs)) entry))
                ((and (consp entry) (consp (car entry)))
                 (dolist (pair entry) (push (cons (car pair) (cdr pair)) pairs)))
                ((consp entry) (push (cons (car entry) (cdr entry)) pairs))
                (t (error 'rpc-error :code +rpc-type-error+
                                     :message "Invalid recipient"))))
            (when (zerop (hash-table-count addresses-without-amount))
              (error 'rpc-error :code +rpc-invalid-parameter+
                                :message "Must provide at least one address without a specified amount"))
            (multiple-value-bind (recipients)
                (%parse-outputs (wallet-network wallet) (nreverse pairs))
              (let ((cc (make-wcc)))
                (%set-fee-estimate-mode cc
                                        (%opt options "conf_target")
                                        (%opt options "estimate_mode")
                                        (%opt options "fee_rate")
                                        nil)
                (multiple-value-bind (minconf minconf-present)
                    (%opt options "minconf")
                  (when minconf-present
                    (unless (integerp minconf)
                      (error 'rpc-error :code +rpc-type-error+
                                        :message "minconf must be an integer"))
                    (when (minusp minconf)
                      (error 'rpc-error :code +rpc-invalid-parameter+
                                        :message (format nil "Invalid minconf (minconf cannot be negative): ~D" minconf)))
                    (setf (wcc-min-depth cc) minconf)))
                (multiple-value-bind (maxconf maxconf-present)
                    (%opt options "maxconf")
                  (when maxconf-present
                    (unless (integerp maxconf)
                      (error 'rpc-error :code +rpc-type-error+
                                        :message "maxconf must be an integer"))
                    (setf (wcc-max-depth cc) maxconf)
                    (when (< (wcc-max-depth cc) (wcc-min-depth cc))
                      (error 'rpc-error :code +rpc-invalid-parameter+
                                        :message (format nil "maxconf can't be lower than minconf: ~D < ~D"
                                                         (wcc-max-depth cc)
                                                         (wcc-min-depth cc))))))
                (multiple-value-bind (version version-present)
                    (%opt options "version")
                  (when version-present
                    ;; Stricter than Core; see rpc-send's version note.
                    (unless (and (integerp version) (<= 1 version 3))
                      (error 'rpc-error :code +rpc-invalid-parameter+
                                        :message "Invalid parameter, version must be 1, 2, or 3"))
                    (setf (wcc-version cc) version)))
                (setf (wcc-max-tx-weight cc)
                      (if (= (wcc-version cc) bitcoin-lisp.mempool:+truc-version+)
                          +truc-max-weight+
                          bitcoin-lisp.validation:+max-standard-tx-weight+))
                (let ((rbf (if (%opt-present-p options "replaceable")
                               (and (%opt options "replaceable") t)
                               *wallet-signal-rbf*)))
                  (multiple-value-bind (fee-rate fee-reason)
                      (%wallet-minimum-fee-rate node cc)
                    (when (and (wcc-feerate cc) (> fee-rate (wcc-feerate cc)))
                      (error 'rpc-error :code +rpc-invalid-parameter+
                                        :message (format nil "Fee rate (~A) is lower than the minimum fee rate setting (~A)"
                                                         (%format-feerate-sat-vb (wcc-feerate cc))
                                                         (%format-feerate-sat-vb fee-rate))))
                    (when (and (eq fee-reason :fallback)
                               (zerop bitcoin-lisp:*wallet-fallback-fee*))
                      (error 'rpc-error :code +rpc-wallet-error+
                                        :message "Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee."))
                    (let* ((locktime (%opt options "locktime"))
                           (send-max (and (%opt options "send_max") t))
                           (inputs-present (%opt-present-p options "inputs"))
                           (inputs (%parse-rpc-inputs
                                    (or (%opt options "inputs") '())))
                           (total-input-value 0)
                           (tx-inputs '())
                           (outpoints '()))
                      (when (and locktime (not (integerp locktime)))
                        (error 'rpc-error :code +rpc-type-error+
                                          :message "locktime must be an integer"))
                      (when (and inputs-present (%opt-present-p options "send_max"))
                        (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Cannot combine send_max with specific inputs."))
                      (when (and inputs-present
                                 (or (%opt-present-p options "minconf")
                                     (%opt-present-p options "maxconf")))
                        (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Cannot combine minconf or maxconf with specific inputs."))
                      (if inputs-present
                          (dolist (input inputs)
                            (destructuring-bind (txid vout sequence weight) input
                              (declare (ignore weight))
                              (when (wallet-outpoint-spent-p wallet txid vout)
                                (error 'rpc-error :code +rpc-invalid-parameter+
                                                  :message (format nil "Input not available. UTXO (~A:~D) was already spent."
                                                                   (hash-to-hex txid) vout)))
                              (let ((wtx (wallet-get-wallet-tx wallet txid)))
                                (unless (and wtx
                                             (< vout (length (bitcoin-lisp.serialization:transaction-outputs
                                                              (wallet-tx-tx wtx))))
                                             (%wallet-script-mine-p
                                              wallet
                                              (bitcoin-lisp.serialization:tx-out-script-pubkey
                                               (aref (bitcoin-lisp.serialization:transaction-outputs
                                                      (wallet-tx-tx wtx))
                                                     vout))))
                                  (error 'rpc-error :code +rpc-invalid-parameter+
                                                    :message (format nil "Input not found. UTXO (~A:~D) is not part of wallet."
                                                                     (hash-to-hex txid) vout)))
                                (when (zerop (wallet-tx-depth wallet wtx))
                                  (let ((parent-version
                                          (bitcoin-lisp.serialization:transaction-version
                                           (wallet-tx-tx wtx))))
                                    (cond
                                      ((and (= parent-version bitcoin-lisp.mempool:+truc-version+)
                                            (/= (wcc-version cc) bitcoin-lisp.mempool:+truc-version+))
                                       (error 'rpc-error :code +rpc-invalid-parameter+
                                                         :message (format nil "Can't spend unconfirmed version 3 pre-selected input with a version ~D tx"
                                                                          (wcc-version cc))))
                                      ((and (= (wcc-version cc) bitcoin-lisp.mempool:+truc-version+)
                                            (/= parent-version bitcoin-lisp.mempool:+truc-version+))
                                       (error 'rpc-error :code +rpc-invalid-parameter+
                                                         :message (format nil "Can't spend unconfirmed version ~D pre-selected input with a version 3 tx"
                                                                          parent-version))))))
                                (incf total-input-value
                                      (bitcoin-lisp.serialization:tx-out-value
                                       (aref (bitcoin-lisp.serialization:transaction-outputs
                                              (wallet-tx-tx wtx))
                                             vout)))
                                (push (bitcoin-lisp.serialization:make-tx-in
                                       :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                         :hash txid :index vout)
                                       :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                       :sequence (or sequence
                                                     (if rbf
                                                         +max-bip125-rbf-sequence+
                                                         (if (and locktime (plusp locktime))
                                                             +max-sequence-nonfinal+
                                                             +sequence-final+))))
                                      tx-inputs)
                                (push (cons txid vout) outpoints))))
                          (dolist (coin (wallet-available-coins
                                         wallet
                                         :min-depth (wcc-min-depth cc)
                                         :max-depth (wcc-max-depth cc)
                                         :min-amount 0
                                         :feerate fee-rate
                                         :input-bytes-fn
                                         (lambda (script)
                                           (%max-signed-input-vsize wallet cc script))
                                         ;; Core sendall ALWAYS sweeps reused
                                         ;; coins: AvailableCoins' allow_used
                                         ;; = !AVOID_REUSE || (cc &&
                                         ;; !cc->m_avoid_address_reuse)
                                         ;; (spend.cpp:333) and sendall's
                                         ;; default CCoinControl has
                                         ;; m_avoid_address_reuse=false, so
                                         ;; the condition is always true.
                                         ;; (Core's own help text at
                                         ;; rpc/spend.cpp:1298 claims the
                                         ;; opposite — we match BEHAVIOR, not
                                         ;; the doc; excluding reused coins
                                         ;; would strand them, since sendall
                                         ;; is the sweep tool.)
                                         :allow-used-addresses t
                                         :check-version-trucness t
                                         :tx-version (wcc-version cc)
                                         :mempool (bitcoin-lisp::node-mempool node)))
                            (unless (and send-max
                                         (> (%feerate-fee fee-rate
                                                          (max 0 (wallet-coin-input-bytes coin)))
                                            (bitcoin-lisp.serialization:tx-out-value
                                             (wallet-coin-output coin))))
                              (when (and (zerop (wallet-coin-depth coin))
                                         (= (wcc-version cc)
                                            bitcoin-lisp.mempool:+truc-version+))
                                (setf (wcc-max-tx-weight cc) +truc-child-max-weight+))
                              (push (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (wallet-coin-txid coin)
                                                       :index (wallet-coin-index coin))
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                     :sequence (if rbf
                                                   +max-bip125-rbf-sequence+
                                                   +sequence-final+))
                                    tx-inputs)
                              (push (cons (wallet-coin-txid coin)
                                          (wallet-coin-index coin))
                                    outpoints)
                              (incf total-input-value
                                    (bitcoin-lisp.serialization:tx-out-value
                                     (wallet-coin-output coin))))))
                      (setf tx-inputs (nreverse tx-inputs))
                      (let ((tx (bitcoin-lisp.serialization:make-transaction
                                 :version (wcc-version cc)
                                 :inputs (coerce tx-inputs 'simple-vector)
                                 :outputs (coerce (%recipient-outputs recipients)
                                                  'simple-vector)
                                 :lock-time (or locktime 0))))
                        (multiple-value-bind (vsize tx-weight)
                            (%max-signed-tx-size
                             wallet cc tx
                             (loop for (txid . vout) in (reverse outpoints)
                                   collect (cons (bitcoin-lisp.serialization:tx-out-script-pubkey
                                                  (%wallet-input-txout node wallet txid vout))
                                                 nil)))
                          (when (minusp vsize)
                            (error 'rpc-error :code +rpc-wallet-error+
                                              :message "Unable to determine the size of the transaction, the wallet contains unsolvable descriptors"))
                          (let* ((fee-from-size (%feerate-fee fee-rate vsize))
                                 (effective-value (- total-input-value fee-from-size)))
                            (when (> fee-from-size bitcoin-lisp:*wallet-max-tx-fee*)
                              (error 'rpc-error :code +rpc-wallet-error+
                                                :message +max-fee-exceeded-message+))
                            (when (<= effective-value 0)
                              (error 'rpc-error :code +rpc-wallet-insufficient-funds+
                                                :message (if send-max
                                                             "Total value of UTXO pool too low to pay for transaction, try using lower feerate."
                                                             "Total value of UTXO pool too low to pay for transaction. Try using lower feerate or excluding uneconomic UTXOs with 'send_max' option.")))
                            (when (> tx-weight (or (wcc-max-tx-weight cc)
                                                   bitcoin-lisp.validation:+max-standard-tx-weight+))
                              (error 'rpc-error :code +rpc-wallet-error+
                                                :message "Transaction too large."))
                            (let ((claimed (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs tx)
                                                   :key #'bitcoin-lisp.serialization:tx-out-value
                                                   :initial-value 0)))
                              (when (> claimed total-input-value)
                                (error 'rpc-error :code +rpc-wallet-insufficient-funds+
                                                  :message "Assigned more value to outputs than available funds."))
                              (let ((remainder (- effective-value claimed)))
                                (when (minusp remainder)
                                  (error 'rpc-error :code +rpc-wallet-insufficient-funds+
                                                    :message "Insufficient funds for fees after creating specified outputs."))
                                (let ((per-output (floor remainder
                                                         (hash-table-count addresses-without-amount)))
                                      (gave-remaining nil))
                                  (loop for output across (bitcoin-lisp.serialization:transaction-outputs tx)
                                        for recipient in recipients
                                        do (let ((address (recipient-address recipient)))
                                             (if (and address
                                                      (gethash address addresses-without-amount))
                                                 (progn
                                                   (setf (bitcoin-lisp.serialization:tx-out-value output)
                                                         per-output)
                                                   (unless gave-remaining
                                                     (incf (bitcoin-lisp.serialization:tx-out-value output)
                                                           (mod remainder
                                                                (hash-table-count addresses-without-amount)))
                                                     (setf gave-remaining t))
                                                   (when (%output-dust-p
                                                          (bitcoin-lisp.serialization:tx-out-value output)
                                                          (bitcoin-lisp.serialization:tx-out-script-pubkey output))
                                                     (error 'rpc-error :code +rpc-wallet-insufficient-funds+
                                                                       :message "Dynamically assigned remainder results in dust output.")))
                                                 (when (%output-dust-p
                                                        (bitcoin-lisp.serialization:tx-out-value output)
                                                        (bitcoin-lisp.serialization:tx-out-script-pubkey output))
                                                   (error 'rpc-error :code +rpc-invalid-parameter+
                                                                     :message (format nil "Specified output amount to ~A is below dust threshold."
                                                                                      address))))))
                                  (when (and (%opt options "lock_unspents"))
                                    (bitcoin-lisp.serialization:dovector
                                        (input (bitcoin-lisp.serialization:transaction-inputs tx))
                                      (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input)))
                                        (wallet-lock-coin
                                         wallet
                                         (bitcoin-lisp.serialization:outpoint-hash prevout)
                                         (bitcoin-lisp.serialization:outpoint-index prevout)
                                         nil))))
                                  (%finish-transaction node wallet options
                                                       tx))))))))))))))))))

;;; --- signrawtransactionwithwallet (rpc/spend.cpp:841-938) ---

(defun %wallet-sighash-byte (value)
  "Core ParseSighashString: NIL/\"DEFAULT\" -> SIGHASH_DEFAULT, which our
ECDSA machinery signs as ALL. Returns (values sighash-byte default-p) so
callers can reject explicit non-DEFAULT types where only DEFAULT is
supported (taproot inputs, until the P5 signer lands sighash plumbing)."
  (if (or (null value) (and (stringp value) (string-equal value "DEFAULT")))
      (values 1 t)
      (values (%parse-sighash-type value) nil)))

(defun rpc-signrawtransactionwithwallet (node params)
  "Sign a raw transaction with the wallet's keys (Bitcoin Core
signrawtransactionwithwallet). PARAMS: (hexstring prevtxs sighashtype)."
  (let ((wallet (wallet-for-request node))
        (hexstring (first params)))
    (unless (stringp hexstring)
      (error 'rpc-error :code +rpc-deserialization-error+
                        :message "TX decode failed. Make sure the tx has at least one input."))
    (let ((tx (handler-case
                  (bitcoin-lisp.serialization:parse-tx-payload
                   (bitcoin-lisp.crypto:hex-to-bytes hexstring))
                (error () (error 'rpc-error :code +rpc-deserialization-error+
                                            :message "TX decode failed. Make sure the tx has at least one input.")))))
      (when (zerop (length (bitcoin-lisp.serialization:transaction-inputs tx)))
        (error 'rpc-error :code +rpc-deserialization-error+
                          :message "TX decode failed. Make sure the tx has at least one input."))
      (with-node-lock (node)
        (with-wallet-lock (wallet)
          (wallet-ensure-unlocked wallet)
          (multiple-value-bind (sighash-byte sighash-default-p)
              (%wallet-sighash-byte (third params))
            (let ((coins (%wallet-input-coins node wallet tx)))
            ;; ParsePrevouts: caller-supplied prevout data overrides/extends.
            (dolist (prevtx (and (listp (second params)) (second params)))
              (let ((txid (%opt prevtx "txid"))
                    (vout (%opt prevtx "vout"))
                    (spk-hex (%opt prevtx "scriptPubKey"))
                    (amount (%opt prevtx "amount"))
                    (redeem-hex (%opt prevtx "redeemScript"))
                    (witness-hex (%opt prevtx "witnessScript")))
                (unless (and (stringp txid) (valid-hex-hash-p txid)
                             (integerp vout) (stringp spk-hex))
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "Missing txid, vout, or scriptPubKey in prevtxs"))
                (when (minusp vout)
                  (error 'rpc-error :code +rpc-invalid-parameter+
                                    :message "vout cannot be negative"))
                (let* ((key (cons (parse-hex-hash txid) vout))
                       (script (bitcoin-lisp.crypto:hex-to-bytes spk-hex))
                       (known (gethash key coins)))
                  (when (and known (not (equalp (first known) script)))
                    (error 'rpc-error :code +rpc-deserialization-error+
                                      :message "Previous output scriptPubKey mismatch"))
                  (setf (gethash key coins)
                        (list script
                              (if amount
                                  (%amount-from-value amount)
                                  (and known (second known)))
                              (if (stringp redeem-hex)
                                  (bitcoin-lisp.crypto:hex-to-bytes redeem-hex)
                                  (and known (third known)))
                              (if (stringp witness-hex)
                                  (bitcoin-lisp.crypto:hex-to-bytes witness-hex)
                                  (and known (fourth known))))))))
            ;; Explicit non-DEFAULT sighash types cannot be honored on
            ;; taproot inputs yet (the P2TR arm signs keypath
            ;; SIGHASH_DEFAULT): refuse rather than silently sign with a
            ;; different type than requested (P5's signer adds the
            ;; plumbing).
            (unless sighash-default-p
              (maphash
               (lambda (key entry)
                 (declare (ignore key))
                 (when (eq (bitcoin-lisp.validation:classify-script
                            (first entry))
                           :witness-v1-taproot)
                   (error 'rpc-error :code +rpc-invalid-parameter+
                                     :message "Only DEFAULT sighash type is supported for taproot inputs")))
               coins))
            (let* ((sign-errors (%wallet-sign-transaction wallet tx coins
                                                          :sighash-byte sighash-byte))
                   (inputs (bitcoin-lisp.serialization:transaction-inputs tx))
                   (witnesses (bitcoin-lisp.serialization:transaction-witness tx)))
              (append
               `(("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex
                            (bitcoin-lisp.serialization:transaction-wire-bytes tx)))
                 ("complete" . ,(json-bool (null sign-errors))))
               (when sign-errors
                 `(("errors"
                    . ,(mapcar
                        (lambda (entry)
                          (destructuring-bind (index . message) entry
                            (let* ((input (aref inputs index))
                                   (prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                                   (stack (and witnesses
                                               (< index (length witnesses))
                                               (aref witnesses index))))
                              ;; Core SignTransactionResultToJSON entry shape.
                              `(("txid" . ,(hash-to-hex
                                            (bitcoin-lisp.serialization:outpoint-hash prevout)))
                                ("vout" . ,(bitcoin-lisp.serialization:outpoint-index prevout))
                                ("witness" . ,(or (mapcar #'bitcoin-lisp.crypto:bytes-to-hex
                                                          stack)
                                                  #()))
                                ("scriptSig" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                                 (bitcoin-lisp.serialization:tx-in-script-sig input)))
                                ("sequence" . ,(bitcoin-lisp.serialization:tx-in-sequence input))
                                ("error" . ,message)))))
                        sign-errors)))))))))))))
