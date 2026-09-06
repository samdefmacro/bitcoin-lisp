(in-package #:bitcoin-lisp.validation)

;;; Transaction Validation
;;;
;;; This module validates Bitcoin transactions according to consensus rules.
;;; Uses Coalton Satoshi type for amount calculations to ensure type safety.

;;;; Constants
(defconstant +max-money+ 2100000000000000)  ; 21 million BTC in satoshis
(defconstant +coin+ 100000000)               ; 1 BTC in satoshis
(defconstant +max-block-size+ 1000000)       ; 1 MB
(defconstant +coinbase-maturity+ 100)        ; Blocks before coinbase spendable

;; BIP 141's two block-weight constants. Core keeps them in
;; consensus/consensus.h, where both CheckTransaction and the block checks
;; include them; here they have to live in the file the validation module loads
;; FIRST, because VALIDATE-TRANSACTION-STRUCTURE needs them and
;; transaction.lisp compiles ahead of block.lisp (bitcoin-lisp.asd:78,80).
(defconstant +max-block-weight+ 4000000)     ; BIP 141: max block weight in weight units
(defconstant +witness-scale-factor+ 4)       ; BIP 141: legacy sigops weight multiplier

;; Typed constant for max money
(defvar *max-money-satoshi* nil)
(defun max-money-satoshi ()
  "Return +max-money+ as a Satoshi type (lazy initialization)."
  (or *max-money-satoshi*
      (setf *max-money-satoshi* (bl.interop:wrap-satoshi +max-money+))))

(defun money-range-p (value)
  "Core MoneyRange (consensus/amount.h:24-30): 0 <= VALUE <= MAX_MONEY.
Every consensus site that derives an amount from data it did not itself bound
re-asks this question, because an amount outside the band is not a Bitcoin
value at all. Core's own reason for asking is CAmount's int64 overflow; ours
is that the value reached us from a coins view we do not otherwise check."
  (and (not (minusp value)) (<= value +max-money+)))

;;;; Structure validation (context-free)

(defun validate-transaction-structure (tx)
  "Validate basic transaction structure without chain context.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."
  (let ((inputs (bl.ser:transaction-inputs tx))
        (outputs (bl.ser:transaction-outputs tx)))

    ;; Must have at least one input
    (when (zerop (length inputs))
      (return-from validate-transaction-structure
        (values nil :no-inputs)))

    ;; Must have at least one output
    (when (zerop (length outputs))
      (return-from validate-transaction-structure
        (values nil :no-outputs)))

    ;; Consensus size limit, in Core's position: CheckTransaction rejects a
    ;; transaction whose NON-WITNESS serialization exceeds the block weight
    ;; ceiling (tx_check.cpp:17-20), before it looks at values or duplicate
    ;; inputs. The witness is deliberately excluded — at this point it has not
    ;; been checked for malleability, so it cannot be trusted to bound size.
    ;;
    ;; ORDER MATTERS and is pinned by test: Core reaches this at :18 and the
    ;; duplicate-input check only at :44, so an oversize transaction built by
    ;; repeating one input — which is exactly how mempool_accept.py:235 builds
    ;; it — must report oversize, not duplicate inputs.
    (when (> (* +witness-scale-factor+
                (length (bl.ser:serialize-transaction tx)))
             +max-block-weight+)
      (return-from validate-transaction-structure
        (values nil :tx-oversize)))

    ;; Check for duplicate inputs
    (let ((seen-outpoints (make-hash-table :test 'equalp)))
      (bl.ser:dovector (input inputs)
        (let* ((prevout (bl.ser:tx-in-previous-output input))
               (key (cons (bl.ser:outpoint-hash prevout)
                          (bl.ser:outpoint-index prevout))))
          (when (gethash key seen-outpoints)
            (return-from validate-transaction-structure
              (values nil :duplicate-inputs)))
          (setf (gethash key seen-outpoints) t))))

    ;; Validate outputs using typed Satoshi arithmetic
    (let ((total-output (bl.interop:wrap-satoshi 0)))
      (bl.ser:dovector (output outputs)
        (let ((value (bl.ser:tx-out-value output)))
          ;; Output value must be non-negative
          (when (minusp value)
            (return-from validate-transaction-structure
              (values nil :negative-output)))
          ;; Output value must not exceed max money
          (when (> value +max-money+)
            (return-from validate-transaction-structure
              (values nil :output-too-large)))
          ;; Use typed addition
          (setf total-output (bl.interop:satoshi+ total-output (bl.interop:wrap-satoshi value)))))
      ;; Total output must not exceed max money
      (when (bl.interop:satoshi> total-output (max-money-satoshi))
        (return-from validate-transaction-structure
          (values nil :total-output-too-large))))

    ;; Coinbase vs non-coinbase, matching Core CheckTransaction
    ;; (tx_check.cpp:47-57) and IsCoinBase (primitives/transaction.h:341):
    ;; a tx is coinbase IFF it has exactly one input whose prevout is null.
    ;; Coinbase → scriptSig must be 2..100 bytes; non-coinbase → no input
    ;; may have a null prevout (bad-txns-prevout-null).
    (if (and (= (length inputs) 1)
             (bl.ser:coinbase-input-p (aref inputs 0)))
        (let ((sig-len (length (bl.ser:tx-in-script-sig
                                (aref inputs 0)))))
          (when (or (< sig-len 2) (> sig-len 100))
            (return-from validate-transaction-structure
              (values nil :bad-coinbase-length))))
        (bl.ser:dovector (inp inputs)
          (when (bl.ser:coinbase-input-p inp)
            (return-from validate-transaction-structure
              (values nil :bad-prevout-null)))))

    ;; The two size limits above and in %IS-STANDARD-TX are Core's two, and
    ;; they are separate rules with separate reasons: the consensus one here
    ;; (bad-txns-oversize, non-witness size against the block ceiling) and the
    ;; policy one (tx-size, full weight against MAX_STANDARD_TX_WEIGHT).

    (values t nil)))

;;;; Contextual validation (requires chain state)

(defun validate-transaction-contextual (tx utxo-set current-height
                                        &key is-coinbase pending-utxos spent-outpoints)
  "Validate a transaction in the context of the current UTXO set.
PENDING-UTXOS is an optional hash table of (txid . index) -> utxo-entry
for outputs created by earlier transactions in the same block.
SPENT-OUTPOINTS is an optional set of (txid . index) keys already consumed by
an earlier transaction in the same block; such a prevout counts as ABSENT and
falls into :missing-input — Core has spent the coin out of its view, so
HaveInputs fails with bad-txns-inputs-missingorspent (tx_verify.cpp:167-169).
Returns (VALUES T NIL FEE) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure.
FEE is returned as a Satoshi type."
  (let ((inputs (bl.ser:transaction-inputs tx))
        (outputs (bl.ser:transaction-outputs tx))
        (total-input (bl.interop:wrap-satoshi 0))
        (total-output (bl.interop:wrap-satoshi 0)))

    ;; Skip input validation for coinbase
    (unless is-coinbase
      (bl.ser:dovector (input inputs)
        (let* ((prevout (bl.ser:tx-in-previous-output input))
               (prev-txid (bl.ser:outpoint-hash prevout))
               (prev-index (bl.ser:outpoint-index prevout))
               (key (cons prev-txid prev-index))
               (spent-in-block (and spent-outpoints (gethash key spent-outpoints)))
               (utxo (unless spent-in-block
                       (or (bl.store:get-utxo utxo-set prev-txid prev-index)
                           ;; Check intra-block pending UTXOs
                           (when pending-utxos
                             (gethash key pending-utxos))))))

          ;; Input must reference an existing UTXO
          (unless utxo
            (bl:log-warn
             "MISSING-INPUT: height=~D prev-txid=~A:~D in-pending=~A spent-in-block=~A pending-size=~D"
             current-height
             (bl.crypto:bytes-to-hex prev-txid)
             prev-index
             (and pending-utxos
                  (if (gethash key pending-utxos) "yes" "no"))
             (if spent-in-block "yes" "no")
             (if pending-utxos (hash-table-count pending-utxos) -1))
            (return-from validate-transaction-contextual
              (values nil :missing-input nil)))

          ;; Check coinbase maturity
          (when (bl.store:utxo-entry-coinbase utxo)
            (let ((age (- current-height
                         (bl.store:utxo-entry-height utxo))))
              (when (< age +coinbase-maturity+)
                (return-from validate-transaction-contextual
                  (values nil :coinbase-not-mature nil)))))

          ;; Use typed addition for input sum, then "check for negative or
          ;; overflow input values" — Core CheckTxInputs (consensus/
          ;; tx_verify.cpp:184-188), asked AFTER the addition and of BOTH
          ;; terms: the coin's own value and the running sum. Core needs it
          ;; because CAmount is an int64 that wraps; our Satoshi is an
          ;; unbounded Integer, so nothing here can overflow. The REJECTION is
          ;; the consensus rule either way — a coins view holding an
          ;; out-of-range value (a corrupted chainstate record) must not have
          ;; it counted into a fee, and thence into a block's coinbase cap.
          (let ((coin-value (bl.store:utxo-entry-value utxo)))
            (setf total-input
                  (bl.interop:satoshi+ total-input
                                       (bl.interop:wrap-satoshi coin-value)))
            (unless (and (money-range-p coin-value)
                         (money-range-p (bl.interop:unwrap-satoshi total-input)))
              (return-from validate-transaction-contextual
                (values nil :input-values-out-of-range nil)))))))

    ;; Sum outputs with typed addition
    (bl.ser:dovector (output outputs)
      (setf total-output
            (bl.interop:satoshi+ total-output
                      (bl.interop:wrap-satoshi (bl.ser:tx-out-value output)))))

    ;; For non-coinbase, inputs must cover outputs
    (unless is-coinbase
      (when (bl.interop:satoshi> total-output total-input)
        (return-from validate-transaction-contextual
          (values nil :insufficient-funds nil))))

    ;; Return fee as Satoshi type
    (let ((fee (bl.interop:satoshi- total-input total-output)))
      ;; The last statement of Core's CheckTxInputs (tx_verify.cpp:202-209):
      ;; the derived fee must be in MoneyRange. Core annotates its own guard
      ;; as unreachable given the input-range loop above and CheckTransaction's
      ;; output-side checks, and so is ours — but only for a NON-coinbase, and
      ;; only where those preconditions hold. A coinbase has no input sum at
      ;; all (its "fee" here is negative by construction), and Core never calls
      ;; CheckTxInputs on one: PreChecks rejects it at validation.cpp:804 and
      ;; ConnectBlock guards the call with !tx.IsCoinBase().
      (unless (or is-coinbase (money-range-p (bl.interop:unwrap-satoshi fee)))
        (return-from validate-transaction-contextual
          (values nil :fee-out-of-range nil)))
      (values t nil fee))))

;;;; Mempool acceptance validation

(defconstant +max-standard-tx-weight+ 400000
  "Maximum weight of a standard transaction for relay (Bitcoin Core
MAX_STANDARD_TX_WEIGHT).")

(defconstant +min-standard-tx-version+ 1
  "Minimum standard transaction version (Bitcoin Core TX_MIN_STANDARD_VERSION).")

(defconstant +max-standard-tx-version+ 3
  "Maximum standard transaction version. Bitcoin Core (TX_MAX_STANDARD_VERSION)
accepts v3 as standard in lockstep with enforcing TRUC/v3 topology policy
(BIP431). We now enforce that topology per-tx at mempool acceptance via
bl.mp:single-truc-checks (at most 1 unconfirmed ancestor +
1 descendant, TRUC_MAX_VSIZE, a 1000-vsize child cap, and v3<->non-v3 spend
inheritance), so v3 is relayed with its anti-pinning guarantees.")

(defvar *dust-relay-fee-rate* 3000
  "Dust relay fee rate in satoshis per kvB (Bitcoin Core DUST_RELAY_TX_FEE).
An output is dust when spending it would cost more than 1/3 its value at
this rate (~546 sat for P2PKH, ~294 sat for P2WPKH).

A DEFPARAMETER, not a DEFCONSTANT, because Core exposes it as -dustrelayfee:
this is relay POLICY, not consensus, and a node may legitimately run a
different value. The +NAME+ spelling is kept because every caller reads it as a
constant and renaming it would touch far more than this.")

(defconstant +max-standard-scriptsig-size+ 1650
  "Maximum scriptSig size for a standard input (Bitcoin Core
MAX_STANDARD_SCRIPTSIG_SIZE) — fits a 15-of-15 P2SH redeem.")

(defconstant +max-standard-tx-sigops-cost+ 16000
  "Maximum weighted sigop cost for a standard tx: MAX_BLOCK_SIGOPS_COST / 5
= 16,000 (Bitcoin Core MAX_STANDARD_TX_SIGOPS_COST, policy.h:43). Was
mistakenly 80,000 — the full BLOCK budget — letting a single standard tx
carry 5x the sigop density Core relays.")

(defconstant +max-tx-legacy-sigops+ 2500
  "BIP54's per-transaction cap on legacy (non-witness) sigops, counted where
they would execute: every scriptSig's accurate count plus the spent
scriptPubKey's GetSigOpCount(scriptSig) — the redeem script's for P2SH (Core
MAX_TX_LEGACY_SIGOPS, policy.h:45; CheckSigopsBIP54, policy.cpp:169-190). A
relay rule in this Core ref; the consensus rule it anticipates would make such
a transaction unminable, so relaying it is a disservice to the sender.")

(defconstant +max-standard-p2sh-sigops+ 15
  "Maximum sigops in a standard P2SH redeemScript (Bitcoin Core MAX_P2SH_SIGOPS).")

(defconstant +min-standard-tx-nonwitness-size+ 65
  "Minimum non-witness serialized size for a standard tx (Bitcoin Core
MIN_STANDARD_TX_NONWITNESS_SIZE, one larger than 64). Rejects 64-byte
transactions, which a 64-byte internal merkle node can be confused with
(CVE-2017-12842).")

(defconstant +max-standard-p2wsh-script-size+ 3600
  "Maximum standard witnessScript size for a P2WSH spend (Bitcoin Core).")

(defconstant +max-standard-p2wsh-stack-items+ 100
  "Maximum standard witness stack items (excluding the witnessScript) for P2WSH.")

(defconstant +max-standard-p2wsh-stack-item-size+ 80
  "Maximum standard witness stack item size for a P2WSH spend (Bitcoin Core).")

(defconstant +max-standard-tapscript-stack-item-size+ 80
  "Maximum standard witness stack item size for a BIP 342 tapscript spend.")

(defconstant +witness-annex-tag+ #x50
  "First byte marking a Taproot witness annex (Bitcoin Core ANNEX_TAG).")

(defconstant +taproot-leaf-mask+ #xfe
  "Mask isolating the leaf version in a Taproot control block (Bitcoin Core).")

(defconstant +taproot-leaf-tapscript+ #xc0
  "BIP 342 tapscript leaf version (Bitcoin Core TAPROOT_LEAF_TAPSCRIPT).")

(defun spends-non-anchor-witness-program-p (tx utxo-set extra-coins)
  "True if any input of TX spends a witness-program output (any version,
including not-yet-defined ones) other than pay-to-anchor — directly, or via
P2SH whose redeem script (the scriptSig's last push; the scriptSig is known
push-only here from the standardness checks) is a witness program. Port of
Core SpendsNonAnchorWitnessProg (policy/policy.cpp:340-373): the classifier
for a script failure that could be explained by a stripped witness."
  (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
    (let* ((prevout (bl.ser:tx-in-previous-output input))
           (ptxid (bl.ser:outpoint-hash prevout))
           (pidx (bl.ser:outpoint-index prevout))
           (utxo (or (bl.store:get-utxo utxo-set ptxid pidx)
                     (when extra-coins (gethash (cons ptxid pidx) extra-coins))))
           (spk (and utxo (bl.store:utxo-entry-script-pubkey utxo))))
      (when spk
        (cond
          ((and (output-witness-program-p spk)
                (not (pay-to-anchor-p spk)))
           (return-from spends-non-anchor-witness-program-p t))
          ((script-is-p2sh-p spk)
           (let ((redeem (extract-last-push
                          (bl.ser:tx-in-script-sig input))))
             (when (and redeem (output-witness-program-p redeem))
               (return-from spends-non-anchor-witness-program-p t))))))))
  nil)

(defun dust-threshold (script-pubkey)
  "Minimum non-dust value for an output paying to SCRIPT-PUBKEY (Bitcoin Core
GetDustThreshold). Unspendable (OP_RETURN) outputs return 0 — never dust."
  (if (and (plusp (length script-pubkey))
           (= (aref script-pubkey 0) #x6a))   ; OP_RETURN — unspendable
      0
      (let* ((spk-len (length script-pubkey))
             ;; serialized output: 8-byte value + varint(scriptlen) + script
             (output-size (+ 8 (if (< spk-len #xfd) 1 3) spk-len))
             ;; assumed cost to spend the output (witness gets the discount)
             (spend-overhead (if (output-witness-program-p script-pubkey)
                                 (+ 32 4 1 (floor 107 4) 4)   ; 67
                                 (+ 32 4 1 107 4)))           ; 148
             (nsize (+ output-size spend-overhead)))
        ;; CFeeRate::GetFee rounds UP (EvaluateFeeUp) at d3056bc; a no-op at
        ;; the 3000 sat/kvB default (3*nsize is always exact) but keeps this
        ;; aligned with the wallet's parameterized dust threshold.
        (ceiling (* nsize *dust-relay-fee-rate*) 1000))))

(defconstant +max-dust-outputs-per-tx+ 1
  "How many dust outputs a standard transaction may carry (Core
MAX_DUST_OUTPUTS_PER_TX, policy.h:94). Dust is permitted at all only as
EPHEMERAL dust: the carrying tx must pay zero fee and the dust must be swept
by whatever spends it.")

(defun output-is-dust-p (output)
  "Core IsDust (policy.cpp:65): the output's value is below the dust threshold
for its scriptPubKey."
  (< (bl.ser:tx-out-value output)
     (dust-threshold (bl.ser:tx-out-script-pubkey output))))

(defun transaction-dust-output-count (tx)
  "Number of dust outputs in TX (Core GetDust, policy.cpp:70-77, counted
rather than collected)."
  (let ((n 0))
    (bl.ser:dovector (output (bl.ser:transaction-outputs tx))
      (when (output-is-dust-p output) (incf n)))
    n))

(defun transaction-dust-indices (tx)
  "Indices of TX's dust outputs, ascending (Core GetDust)."
  (let ((indices '())
        (i 0))
    (bl.ser:dovector (output (bl.ser:transaction-outputs tx))
      (when (output-is-dust-p output) (push i indices))
      (incf i))
    (nreverse indices)))

(defun check-ephemeral-spends (txns mempool)
  "Core CheckEphemeralSpends (ephemeral_policy.cpp:33): every transaction in
TXNS must spend ALL of the dust outputs of each parent it spends from, where a
parent is looked up first in TXNS itself and then in MEMPOOL. Returns
(values ok-p offending-txid).

Dust is only tolerated because it is ephemeral — created and destroyed inside
one package, never left in the UTXO set for anyone to sweep. A child that
spends a dust-carrying parent without also spending the dust would strand it,
so the whole exemption depends on this check."
  (let ((in-package (make-hash-table :test 'equalp)))
    (dolist (tx txns)
      (setf (gethash (bl.ser:transaction-hash tx) in-package) tx))
    (dolist (tx txns)
      (let ((processed (make-hash-table :test 'equalp))
            ;; (parent-txid . index) of every unspent dust output of every
            ;; parent this tx spends from.
            (unspent-dust '()))
        (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
          (let* ((prevout (bl.ser:tx-in-previous-output input))
                 (parent-txid (bl.ser:outpoint-hash prevout)))
            (unless (gethash parent-txid processed)
              (setf (gethash parent-txid processed) t)
              (let* ((entry (and mempool
                                 (bl.mp:mempool-get mempool parent-txid)))
                     (parent (or (gethash parent-txid in-package)
                                 (and entry
                                      (bl.mp:mempool-entry-transaction entry)))))
                (when parent
                  (dolist (index (transaction-dust-indices parent))
                    (push (cons parent-txid index) unspent-dust)))))))
        (when unspent-dust
          ;; Remove everything this tx actually spends; anything left is dust
          ;; the child stranded.
          (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
            (let ((prevout (bl.ser:tx-in-previous-output input)))
              (setf unspent-dust
                    (remove-if (lambda (od)
                                 (and (equalp (car od)
                                              (bl.ser:outpoint-hash prevout))
                                      (= (cdr od)
                                         (bl.ser:outpoint-index prevout))))
                               unspent-dust))))
          (when unspent-dust
            (return-from check-ephemeral-spends
              (values nil (bl.ser:transaction-hash tx)))))))
    (values t nil)))

(defun scriptsig-push-only-p (script-sig)
  "True if SCRIPT-SIG contains only push opcodes (every opcode <= OP_16),
walking past pushed data. Bitcoin Core CScript::IsPushOnly."
  (let ((len (length script-sig)) (i 0))
    (loop while (< i len)
          do (let ((op (aref script-sig i)))
               (when (> op #x60)        ; > OP_16 → not push-only
                 (return-from scriptsig-push-only-p nil))
               (cond
                 ((<= 1 op 75) (incf i (1+ op)))
                 ((= op #x4c) (if (< (1+ i) len)
                                  (incf i (+ 2 (aref script-sig (1+ i))))
                                  (return-from scriptsig-push-only-p nil)))
                 ((= op #x4d) (if (< (+ i 2) len)
                                  (incf i (+ 3 (logior (aref script-sig (1+ i))
                                                       (ash (aref script-sig (+ i 2)) 8))))
                                  (return-from scriptsig-push-only-p nil)))
                 ((= op #x4e) (if (< (+ i 4) len)
                                  (incf i (+ 5 (logior (aref script-sig (1+ i))
                                                       (ash (aref script-sig (+ i 2)) 8)
                                                       (ash (aref script-sig (+ i 3)) 16)
                                                       (ash (aref script-sig (+ i 4)) 24))))
                                  (return-from scriptsig-push-only-p nil)))
                 (t (incf i)))))         ; OP_0, OP_1NEGATE, OP_1..OP_16
    t))

(defun standard-output-script-p (script-pubkey)
  "Whether SCRIPT-PUBKEY is a standard OUTPUT script type (Core IsStandard,
policy.cpp:79-97): everything Solver classifies except NONSTANDARD, plus
bare multisig's n<=3 cap.

This is Core's IsStandard exactly, which means the -permitbaremultisig gate is
NOT here: Core applies that separately, in IsStandardTx's output loop
(policy.cpp:151-153), and reports it as its own \"bare-multisig\" reason rather
than \"scriptpubkey\". Folding the two together here reported one reason for
both, which mempool_accept.py:311 reads as a divergence."
  (case (classify-script script-pubkey)
    (:nonstandard nil)
    (:multisig (bare-multisig-standard-p script-pubkey))
    (t t)))

(defun bare-multisig-standard-p (script)
  "T if SCRIPT is a standard bare multisig OUTPUT: the multisig shape with
n<=3 (Core IsStandard, policy.cpp:85-93). Consensus allows up to 20 keys;
standardness caps bare multisig outputs at 3. Inputs spending a larger bare
multisig remain standard — see %match-multisig."
  (multiple-value-bind (m n) (%match-multisig script)
    (declare (ignore m))
    (and n (<= n 3) t)))

(defun p2wsh-witness-standard-p (wstack)
  "P2WSH limits: witnessScript (the last stack item) <=
+max-standard-p2wsh-script-size+, and the remaining items (the script's inputs)
number <= +max-standard-p2wsh-stack-items+, each <= +max-standard-p2wsh-stack-item-size+."
  (let ((stack-items (1- (length wstack))))   ; WSTACK is [...args, witnessScript]
    (and (<= (length (car (last wstack))) +max-standard-p2wsh-script-size+)
         (<= stack-items +max-standard-p2wsh-stack-items+)
         (loop for j below stack-items
               always (<= (length (nth j wstack)) +max-standard-p2wsh-stack-item-size+)))))

(defun taproot-witness-standard-p (wstack)
  "Taproot limits: no annex, and for a tapscript (leaf 0xc0) script-path spend
each stack input <= +max-standard-tapscript-stack-item-size+. Key-path spends
have no policy rules."
  (let ((n (length wstack))
        (last-item (car (last wstack))))
    (cond
      ;; Annex present (>=2 items, last non-empty, starts with the tag) ->
      ;; nonstandard (no annex semantics are defined yet).
      ((and (>= n 2) (plusp (length last-item))
            (= (aref last-item 0) +witness-annex-tag+))
       nil)
      ;; Script-path spend: WSTACK is [...args, script, control-block].
      ((>= n 2)
       (cond
         ((zerop (length last-item)) nil)           ; empty control block
         ((= (logand (aref last-item 0) +taproot-leaf-mask+) +taproot-leaf-tapscript+)
          ;; Drop the last two items (control block + script); the rest are args.
          (loop for item in (butlast wstack 2)
                always (<= (length item) +max-standard-tapscript-stack-item-size+)))
         (t t)))                                     ; non-tapscript leaf: no item rule
      ((= n 1) t))))                                     ; 0 items: invalid by consensus

(defun input-witness-standard-p (wstack spk script-sig)
  "Whether one input's witness WSTACK is standard for the output SPK it spends
(SCRIPT-SIG is needed to unwrap a P2SH redeemScript)."
  ;; Witness stuffing: spending a pay-to-anchor output never requires witness
  ;; data, so ANY witness attached to a P2A spend is nonstandard (Core
  ;; IsWitnessStandard, policy.cpp:268-271). This matters beyond bloat —
  ;; a stuffed variant shares the clean spend's TXID, so admitting it makes
  ;; the clean spend bounce off as :already-in-mempool. That is exactly the
  ;; anchor-pinning attack the rule exists to prevent. Checked on the
  ;; DIRECTLY spent scriptPubKey, before any P2SH unwrap, as Core does.
  (when (pay-to-anchor-p spk)
    (return-from input-witness-standard-p nil))
  (let ((prev-script spk)
        (p2sh nil))
    ;; P2SH-wrapped: the redeemScript is the last push of the (push-only) scriptSig
    ;; (Bitcoin Core extracts it by evaluating the scriptSig).
    (when (script-is-p2sh-p spk)
      (let ((redeem (extract-last-push script-sig)))
        (unless redeem (return-from input-witness-standard-p nil))
        (setf prev-script redeem p2sh t)))
    (multiple-value-bind (version program) (witness-program-parts prev-script)
      (cond
        ;; A witness attached to a non-witness program is nonstandard.
        ((null version) nil)
        ((and (= version 0) (= (length program) 32)) (p2wsh-witness-standard-p wstack))
        ((and (= version 1) (= (length program) 32) (not p2sh))
         (taproot-witness-standard-p wstack))
        ;; P2WPKH and other witness versions impose no extra standardness rules.
        (t t)))))

(defun is-witness-standard-p (tx spent-script-fn)
  "Bitcoin Core IsWitnessStandard: every input carrying a witness must spend a
standard witness program (P2WSH/Taproot stack & script limits, no annex).
SPENT-SCRIPT-FN maps (txid index) to the spent output's scriptPubKey. Coinbase
has no witness inputs to check. A tx with no witness at all is vacuously
standard."
  (let ((witness (bl.ser:transaction-witness tx)))
    (or (null witness)
        (loop for input across (bl.ser:transaction-inputs tx)
        for wstack across witness
        ;; An input with no witness data imposes no witness-standardness rule.
        always (or (null wstack)
                   (let* ((prevout (bl.ser:tx-in-previous-output input))
                          (spk (funcall spent-script-fn
                                        (bl.ser:outpoint-hash prevout)
                                        (bl.ser:outpoint-index prevout))))
                     (and spk
                          (input-witness-standard-p
                           wstack spk
                           (bl.ser:tx-in-script-sig input)))))))))

(defun mempool-extra-coins (tx utxo-set mempool spend-height &optional package-coins)
  "Build a (txid . index) -> utxo-entry table for TX inputs that spend
unconfirmed outputs — either an in-mempool tx (chained spends) or, as a final
fallback, a sibling output supplied in PACKAGE-COINS (a package being validated
together, before its members are in the mempool). Returns (values table ok-p);
OK-P is NIL if some input references none of those nor a confirmed UTXO (a
genuinely missing input).

Every entry here is by construction unconfirmed, so it carries SPEND-HEIGHT
(the height TX itself would confirm at, tip+1) as its coin height: Bitcoin
Core's BIP68 evaluation assumes every mempool prevout confirms in the next
block (CalculatePrevHeights maps MEMPOOL_HEIGHT coins to tip.nHeight+1,
validation.cpp:185-192), so any nonzero relative lock on an unconfirmed
input is non-final. Recording the parent's acceptance height instead let
such locks mature while the parent was still unconfirmed."
  (let ((extra (make-hash-table :test 'equalp)))
    (bl.ser:dovector (input (bl.ser:transaction-inputs tx) (values extra t))
      (let* ((prevout (bl.ser:tx-in-previous-output input))
             (ptxid (bl.ser:outpoint-hash prevout))
             (pidx (bl.ser:outpoint-index prevout)))
        (unless (bl.store:get-utxo utxo-set ptxid pidx)
          (let* ((pe (bl.mp:mempool-get mempool ptxid))
                 (ptx (and pe (bl.mp:mempool-entry-transaction pe)))
                 (outs (and ptx (bl.ser:transaction-outputs ptx)))
                 (pkg-coin (and package-coins (gethash (cons ptxid pidx) package-coins))))
            (cond
              ((and outs (< pidx (length outs)))
               (let ((out (aref outs pidx)))
                 (setf (gethash (cons ptxid pidx) extra)
                       (bl.store:make-utxo-entry
                        :value (bl.ser:tx-out-value out)
                        :script-pubkey (bl.ser:tx-out-script-pubkey out)
                        :height spend-height
                        :coinbase nil))))
              (pkg-coin
               (setf (gethash (cons ptxid pidx) extra) pkg-coin))
              (t
               (return-from mempool-extra-coins (values nil nil))))))))))

(defun check-sigops-bip54-p (tx get-spent-script)
  "Core CheckSigopsBIP54 (policy.cpp:169-190): T when TX's legacy sigops,
counted where they would execute — each scriptSig's accurate count plus the
spent scriptPubKey's count for that scriptSig — stay within
+max-tx-legacy-sigops+. GET-SPENT-SCRIPT takes (txid index) and returns the
spent scriptPubKey or NIL. Fails as soon as the running total passes the cap,
as Core does."
  (let ((legacy 0))
    (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
      (let* ((prevout (bl.ser:tx-in-previous-output input))
             (script-sig (bl.ser:tx-in-script-sig input))
             (spk (funcall get-spent-script
                           (bl.ser:outpoint-hash prevout)
                           (bl.ser:outpoint-index prevout))))
        (incf legacy (count-script-sigops script-sig :accurate t))
        (when spk
          (incf legacy (spent-script-sigop-count spk script-sig)))
        (when (> legacy +max-tx-legacy-sigops+)
          (return-from check-sigops-bip54-p nil))))
    t))

(defun are-inputs-standard-p (tx get-spent-script)
  "Core AreInputsStandard (policy.cpp:212-250): the BIP54 legacy-sigop cap
first (:219), then for EVERY spent scriptPubKey refuse the two types that may
not be spent under policy — NONSTANDARD keeps unknown/irregular scripts
reserved as upgrade hooks and blocks DoS via expensive scripts; WITNESS_UNKNOWN
stops us relaying spends of future segwit versions we cannot validate. Both are
standard as OUTPUTS and only nonstandard to SPEND, which is why this cannot
reuse standard-output-script-p — and a P2SH redeem script may carry at most
+max-standard-p2sh-sigops+ sigops (:224-232). GET-SPENT-SCRIPT takes
(txid index) and returns the spent scriptPubKey or NIL."
  (unless (check-sigops-bip54-p tx get-spent-script)
    (return-from are-inputs-standard-p nil))
  (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
    (let* ((prevout (bl.ser:tx-in-previous-output input))
           (spk (funcall get-spent-script
                         (bl.ser:outpoint-hash prevout)
                         (bl.ser:outpoint-index prevout))))
      (when spk
        (case (classify-script spk)
          ((:nonstandard :witness-unknown)
           (return-from are-inputs-standard-p nil)))
        (when (script-is-p2sh-p spk)
          (let ((redeem (extract-last-push
                         (bl.ser:tx-in-script-sig input))))
            (when (and redeem
                       (> (count-script-sigops redeem :accurate t)
                          +max-standard-p2sh-sigops+))
              (return-from are-inputs-standard-p nil)))))))
  t)

(defvar *require-standard*
  t
  "Core's CTxMemPool::Options::require_standard (-acceptnonstdtxn, default
true; mempool_args.cpp:101). NIL relays and mines transactions this node would
otherwise refuse as non-standard.

ONE flag gating ONE set of checks, as Core has it: %IS-STANDARD-TX, the input
and witness standardness tests, and the three ephemeral-dust checks. It does
NOT gate consensus, and it does not gate the 64-byte minimum size (Core keeps
that outside, validation.cpp:813-815 — CVE-2017-12842 applies to every node).

Core REFUSES to start with -acceptnonstdtxn on a non-test chain
(mempool_args.cpp:102-104), and so do we: relaying non-standard transactions on
mainnet is a way to get your transactions dropped by every peer, not a feature.")

(defun %is-standard-tx (tx)
  "Core IsStandardTx (policy.cpp:113-172), as ONE function so -acceptnonstdtxn
can be ONE gate.

Returns (values T NIL) or (values NIL reason-keyword). Everything Core puts
inside IsStandardTx is here and nothing else: version, weight, scriptSig size
and push-only-ness, output script standardness with the shared -datacarriersize
budget, bare multisig, and the dust-output count.

What is deliberately NOT here is the MIN_STANDARD_TX_NONWITNESS_SIZE check.
Core keeps it OUTSIDE IsStandardTx and outside the require_standard branch
(validation.cpp:813-815) because it mitigates CVE-2017-12842 — a 64-byte
transaction is refused even on a node told to relay non-standard ones."
  ;; Policy: standard transaction version
  (let ((version (bl.ser:transaction-version tx)))
    (unless (<= +min-standard-tx-version+ version +max-standard-tx-version+)
      (return-from %is-standard-tx
        (values nil :version-non-standard))))

  ;; Policy: max standard transaction weight (policy.cpp:110-113, Core's
  ;; "tx-size"). This is the POLICY limit and it is not the only size limit —
  ;; CheckTransaction's consensus ceiling is checked in
  ;; VALIDATE-TRANSACTION-STRUCTURE, on the non-witness serialization.
  (when (> (bl.ser:transaction-weight tx) +max-standard-tx-weight+)
    (return-from %is-standard-tx
      (values nil :tx-weight-too-large)))

  ;; Policy: scriptSig must be push-only and within the size limit
  (bl.ser:dovector (input (bl.ser:transaction-inputs tx))
    (let ((script-sig (bl.ser:tx-in-script-sig input)))
      (when (> (length script-sig) +max-standard-scriptsig-size+)
        (return-from %is-standard-tx
          (values nil :scriptsig-too-large)))
      (unless (scriptsig-push-only-p script-sig)
        (return-from %is-standard-tx
          (values nil :scriptsig-not-pushonly)))))

  ;; Policy: all outputs must be standard script types (dust is handled
  ;; separately below — see EPHEMERAL DUST).
  ;; OP_RETURN outputs share ONE -datacarriersize byte budget across the
  ;; whole transaction: each NULL_DATA output's raw scriptPubKey size is
  ;; drawn from it and an output that would overdraw is rejected
  ;; "datacarrier" (Core IsStandardTx, policy.cpp:136-150 — since the 2025
  ;; relaxation there is no per-output cap and no output-count cap, only
  ;; this shared budget). -datacarrier=0 zeroes the budget, so any OP_RETURN
  ;; output fails with the same reason (Core mempool_args.cpp:95-98:
  ;; max_datacarrier_bytes = nullopt -> value_or(0)).
  (let ((datacarrier-bytes-left (if bl:*accept-datacarrier*
                                    bl:*max-datacarrier-bytes*
                                    0)))
    (bl.ser:dovector (output (bl.ser:transaction-outputs tx))
      (let ((spk (bl.ser:tx-out-script-pubkey output)))
        (unless (standard-output-script-p spk)
          (return-from %is-standard-tx
            (values nil :non-standard-output)))
        ;; Core's if/else-if over the classified type (policy.cpp:145-154):
        ;; a NULL_DATA output draws on the shared budget, and ONLY an output
        ;; that is not NULL_DATA can be the bare multisig this gate refuses.
        (cond
          ((null-data-script-p spk)
           (when (> (length spk) datacarrier-bytes-left)
             (return-from %is-standard-tx
               (values nil :datacarrier)))
           (decf datacarrier-bytes-left (length spk)))
          ((and (eq (classify-script spk) :multisig)
                (not bl:*permit-bare-multisig*))
           (return-from %is-standard-tx
             (values nil :bare-multisig)))))))

  ;; EPHEMERAL DUST (Core policy.cpp:157-161 + policy/ephemeral_policy.cpp).
  ;; Dust is no longer rejected on sight. Core permits up to
  ;; MAX_DUST_OUTPUTS_PER_TX (=1) dust output, on the condition that the
  ;; carrying transaction pays NO fee at all — so it is never worth mining
  ;; alone — and that whatever spends it also sweeps the dust (checked by
  ;; check-ephemeral-spends once the package/mempool context is known).
  ;; Rejecting the first dust output, as we used to, refuses a 0-fee TRUC
  ;; parent carrying a P2A anchor: the modern LN 1P1C package that every Core
  ;; peer relays.
  (let ((dust-count (transaction-dust-output-count tx)))
    (when (> dust-count +max-dust-outputs-per-tx+)
      (return-from %is-standard-tx
        (values nil :dust))))
  (values t nil))

;;;; Core's reject-reason vocabulary
;;;
;;; Core carries the reject reason as a STRING inside TxValidationState, so the
;;; string an RPC prints is the same one the validation site chose. Here the
;;; sites choose a keyword, and every RPC that reported one used to render it
;;; mechanically with STRING-DOWNCASE. That is right only where our keyword
;;; happens to spell Core's string, and it silently invented a vocabulary
;;; wherever it did not: "already-in-mempool" for Core's
;;; "txn-already-in-mempool", "missing-input" for "bad-txns-inputs-missingorspent",
;;; "non-bip68-final" for "non-BIP68-final", "scriptsig-too-large" for
;;; "scriptsig-size". Clients that match on the reason — Core's functional
;;; suite among them — read every one of those as a divergence.
;;;
;;; The table is explicit for that reason: a rename here is visible, and the
;;; structural test TX-REJECT-REASONS-COVER-EVERY-KEYWORD fails when a
;;; validation site introduces a keyword nothing maps.

(defparameter *tx-reject-reasons*
  ;; keyword -> Core's state.GetRejectReason(), with the site Core sets it at.
  '((:no-inputs                . "bad-txns-vin-empty")               ; tx_check.cpp:15
    (:no-outputs               . "bad-txns-vout-empty")              ; :17
    (:tx-oversize              . "bad-txns-oversize")                ; :20
    (:negative-output          . "bad-txns-vout-negative")           ; :28
    (:output-too-large         . "bad-txns-vout-toolarge")           ; :30
    (:total-output-too-large   . "bad-txns-txouttotal-toolarge")     ; :33
    (:duplicate-inputs         . "bad-txns-inputs-duplicate")        ; :44
    (:bad-coinbase-length      . "bad-cb-length")                    ; :50
    (:bad-prevout-null         . "bad-txns-prevout-null")            ; :56
    (:coinbase-not-mature      . "bad-txns-premature-spend-of-coinbase") ; tx_verify.cpp:180
    (:input-values-out-of-range . "bad-txns-inputvalues-outofrange")  ; :187
    (:insufficient-funds       . "bad-txns-in-belowout")             ; :197
    (:fee-out-of-range         . "bad-txns-fee-outofrange")          ; :209
    (:coinbase-not-allowed     . "coinbase")                         ; validation.cpp:804
    (:tx-size-small            . "tx-size-small")                    ; :814
    (:non-final                . "non-final")                        ; :820
    (:already-in-mempool       . "txn-already-in-mempool")           ; :825
    (:same-nonwitness-data-in-mempool . "txn-same-nonwitness-data-in-mempool") ; :829
    (:already-known            . "txn-already-known")                ; :862
    (:missing-input            . "bad-txns-inputs-missingorspent")   ; :866
    (:non-bip68-final          . "non-BIP68-final")                  ; :888
    (:nonstandard-inputs       . "bad-txns-nonstandard-inputs")      ; :897
    (:bad-witness-nonstandard  . "bad-witness-nonstandard")          ; :902
    (:too-many-sigops          . "bad-txns-too-many-sigops")         ; :939
    (:version-non-standard     . "version")                          ; policy.cpp:102
    (:tx-weight-too-large      . "tx-size")                          ; :112
    (:scriptsig-too-large      . "scriptsig-size")                   ; :127
    (:scriptsig-not-pushonly   . "scriptsig-not-pushonly")           ; :131
    (:non-standard-output      . "scriptpubkey")                     ; :140
    (:datacarrier              . "datacarrier")                      ; :147
    (:bare-multisig            . "bare-multisig")                    ; :152
    (:dust                     . "dust")                             ; :159
    (:missing-ephemeral-spends . "missing-ephemeral-spends")         ; ephemeral_policy.cpp
    ;; Both script passes carry Core's "(ScriptErrorString)" parenthetical
    ;; (validation.cpp:2117,2119). The two sites return the reason as
    ;; (KEYWORD SCRIPT-ERROR) so TX-REJECT-REASON-STRING can append it; the
    ;; prefix alone is what a caller with no script error gets.
    (:mempool-script-verify-flag-failed . "mempool-script-verify-flag-failed")
    (:block-script-verify-flag-failed   . "block-script-verify-flag-failed")
    ;; A witness stripped from a spend of a witness program is not its own
    ;; reason in Core: the script pass fails and reports itself. Ours pre-gates
    ;; the doomed execution, so it reports what that pass would have.
    (:witness-stripped         . "mempool-script-verify-flag-failed")
    ;; UNSPLIT: Core has two fee reasons — "mempool min fee not met" when the
    ;; pool's dynamic floor rejects (validation.cpp:705) and this one against
    ;; the static relay floor (:709). Our single check compares against the
    ;; effective rate, which is the max of the two, so it cannot say which
    ;; term bound it. Splitting the check is the fix; naming the common case
    ;; is the honest rendering until then.
    (:insufficient-fee         . "min relay fee not met"))
  "Our validation keywords in Core's reject-reason vocabulary.")

(defun tx-reject-reason-string (reason)
  "REASON as Core's state.GetRejectReason() spells it.
REASON is a keyword, or the list (KEYWORD SCRIPT-ERROR) the two script passes
return: Core renders those as `<prefix> (<ScriptErrorString>)'
(validation.cpp:2117-2119), and BL.INTEROP:SCRIPT-ERROR-MESSAGE is that string
verbatim for every error our interpreter reports.
An unmapped keyword falls back to its downcased name and is caught by test
rather than by a client: see TX-REJECT-REASONS-COVER-EVERY-KEYWORD."
  (if (consp reason)
      (format nil "~A (~A)"
              (tx-reject-reason-string (first reason))
              (bl.interop:script-error-message (second reason)))
      (or (cdr (assoc reason *tx-reject-reasons*))
          (string-downcase (symbol-name reason)))))

(defun %policy-script-checks (tx utxo-set extra-coins)
  "Core MemPoolAccept::PolicyScriptChecks (validation.cpp:1132-1153).
Returns (VALUES T NIL), or (VALUES NIL (KEYWORD SCRIPT-ERROR)) -- the reason
carries the script error so it can be rendered with Core's parenthetical."
  ;; Script pass 1 — PolicyScriptChecks (Core MemPoolAccept::
  ;; PolicyScriptChecks, validation.cpp:1132-1153): run the input
  ;; scripts under the full STANDARD flag set (a constant in Core,
  ;; policy/policy.h:118). A failure is a POLICY rejection
  ;; (TX_NOT_STANDARD), reject reason "mempool-script-verify-flag-
  ;; failed (...)" (CheckInputScripts, validation.cpp:2117), which
  ;; the P2P reject cache keys by wtxid only — never misbehavior.
  (multiple-value-bind (scripts-valid failed-input script-error)
      (validate-transaction-scripts tx utxo-set
                                    :flags +standard-script-verify-flags+
                                    :extra-coins extra-coins)
    (declare (ignore failed-input))
    (unless scripts-valid
      (return-from %policy-script-checks
        (values nil (list :mempool-script-verify-flag-failed script-error)))))
  (values t nil))

(defun %consensus-script-checks (tx utxo-set current-height extra-coins)
  "Core MemPoolAccept::ConsensusScriptChecks (validation.cpp:1155-1185).
Returns (VALUES T NIL), or (VALUES NIL (KEYWORD SCRIPT-ERROR)) -- the reason
carries the script error so it can be rendered with Core's parenthetical."
  ;; Script pass 2 — ConsensusScriptChecks (Core MemPoolAccept::
  ;; ConsensusScriptChecks -> CheckInputsFromMempoolAndCache,
  ;; validation.cpp:1155-1185): re-run against the CURRENT TIP's
  ;; consensus flags. Its purposes are (a) never admit a tx that
  ;; standard flags pass but tip consensus flags reject (a
  ;; standardness-bug backstop — Core cites STRICTENC once wrongly
  ;; passing invalid CHECKSIG NOT scripts), and (b) warm the
  ;; validation cache under the flags block connection will use:
  ;; our sig-cache keys include the flag string, so this pass's
  ;; verifies are the ones block connect hits. Standard-pass/
  ;; consensus-fail is a should-never-happen internal error in Core
  ;; ("BUG! ... CheckInputScripts failed against latest-block but
  ;; not STANDARD flags"); we log the same and reject.
  (multiple-value-bind (scripts-valid failed-input script-error)
      (validate-transaction-scripts tx utxo-set :height current-height
                                    :extra-coins extra-coins)
    (unless scripts-valid
      (bl:log-error
       "BUG! PLEASE REPORT THIS! input scripts failed against latest-block but not STANDARD flags: txid=~A input=~A"
       (bl.crypto:bytes-to-hex
        (bl.ser:transaction-hash tx))
       failed-input)
      (return-from %consensus-script-checks
        (values nil (list :block-script-verify-flag-failed script-error)))))
  (values t nil))

(defun %mempool-precheck-context-free (tx)
  "The first four checks of Core's MemPoolAccept::PreChecks (validation.cpp:
798-815) — the ones that read only the transaction, before any chain or pool
state. Returns (VALUES T NIL) or (VALUES NIL ERROR-KEYWORD).

PRECHECK ORDER IS CORE'S ORDER, and it is observable: each of these rejects a
transaction the next one would also reject, so whichever runs first is the
reason the client is told. The functional suite reads those reasons, and
mempool_accept.py:302 is a transaction that is BOTH non-standard and under 65
bytes."
  ;; 1. CheckTransaction (:798) — consensus structure.
  (multiple-value-bind (valid error) (validate-transaction-structure tx)
    (unless valid
      (return-from %mempool-precheck-context-free (values nil error))))

  ;; 2. Coinbase is only valid in a block (:802-804), and AFTER
  ;;    CheckTransaction: a malformed coinbase is reported as malformed.
  (when (and (= (length (bl.ser:transaction-inputs tx)) 1)
             (bl.ser:coinbase-input-p
              (aref (bl.ser:transaction-inputs tx) 0)))
    (return-from %mempool-precheck-context-free
      (values nil :coinbase-not-allowed)))

  ;; 3. The standardness battery, behind Core's single require_standard flag
  ;;    (-acceptnonstdtxn, :807-810). Everything it covers lives in
  ;;    %IS-STANDARD-TX; the size check below does not, because Core's does not.
  (when *require-standard*
    (multiple-value-bind (ok reason) (%is-standard-tx tx)
      (unless ok
        (return-from %mempool-precheck-context-free (values nil reason)))))

  ;; 4. Minimum non-witness size (:813-815, CVE-2017-12842). LAST of the four,
  ;;    and outside require_standard so it holds even for a node told to relay
  ;;    non-standard transactions. SERIALIZE-TRANSACTION emits the legacy
  ;;    (non-witness) encoding, so its length is the stripped size Core measures.
  (when (< (length (bl.ser:serialize-transaction tx))
           +min-standard-tx-nonwitness-size+)
    (return-from %mempool-precheck-context-free (values nil :tx-size-small)))

  (values t nil))

(defun %mempool-lock-context (chain-state current-height)
  "The tip context Core's PreChecks judges both locktime rules against.
A mempool transaction is evaluated as if it were in the NEXT block (tip+1)
with the tip's median-time-past, so the pool never holds a transaction that
cannot yet be mined. Returns (VALUES EVAL-HEIGHT LOCKTIME-TIME MTP
CSV-ACTIVE).

Core reads these off one CBlockIndex (CheckFinalTxAtTip and
CheckSequenceLocksAtTip both take the tip); ours are two calls at two
positions in PreChecks — \"non-final\" before the mempool duplicate probe and
BIP68 after the input lookups — so the context they share is derived here
rather than at either site."
  (let* ((eval-height (1+ current-height))
         (mtp (or (compute-median-time-past
                   chain-state (bl.store:best-block-hash chain-state))
                  0))
         (csv-active (>= eval-height (get-csv-activation-height bl:*network*))))
    ;; BIP113: locktime compares against MTP once CSV is active (true on all
    ;; our networks at tip); fall back to wall-clock for the pre-activation
    ;; window.
    (values eval-height
            (if csv-active mtp (bl.ser:get-unix-time))
            mtp
            csv-active)))

(defun %replacement-checks (mempool tx modified-fee vsize sigops direct-conflicts)
  "Core MemPoolAccept::ReplacementChecks (validation.cpp:981-1032), which is a
method of its own there rather than a stretch of PreChecks: apply the
cluster-mempool replacement rules to TX against DIRECT-CONFLICTS and return
(values ok-p reason replaced-set).

The candidate's size reaches those rules in BOTH of Core's units, and this is
where the second one is derived, beside the rules that read it. VSIZE -- the
sigop-adjusted VIRTUAL size, Core's ws.m_vsize -- prices rules 3 and 4; the
sigop-adjusted WEIGHT is what the candidate is staged into the txgraph with
(Core's ChangeSet::StageAddition builds FeePerWeight from
GetSigOpsAdjustedWeight, txmempool.cpp:1017). Deriving the weight from the
transaction and SIGOPS here rather than passing a second number down is what
keeps the two from ever describing different transactions."
  (bl.mp:check-rbf-rules mempool tx modified-fee vsize
                         (bl.mp:transaction-graph-weight tx sigops)
                         direct-conflicts))

(defun validate-transaction-for-mempool (tx utxo-set mempool current-height
                                         &key package-coins skip-fee-check chain-state
                                              bypass-limits skip-rbf-check
                                              (allow-sibling-eviction t))
  "Validate a transaction for mempool acceptance.
Performs consensus checks plus policy checks.
Returns (VALUES T NIL FEE REPLACED SIGOPS MODIFIED-FEE DIRECT-CONFLICTS) on
success, (VALUES NIL ERROR-KEYWORD NIL) on failure. FEE is the real paid fee
(integer satoshis); REPLACED the txids the RBF rules would evict; SIGOPS the
weighted sigop cost (Core's nSigOpsCost, recorded on the mempool entry so
the block assembler's sigop budget sees real numbers); MODIFIED-FEE the
prioritisation-modified fee and DIRECT-CONFLICTS the directly-conflicting
mempool txids — the workspace values Core's PreChecks leaves in
ws.m_modified_fees / ws.m_conflicts for the package layer to read, returned
so callers need not re-derive them.

PACKAGE-COINS, when supplied, is a (txid . index) -> utxo-entry table of outputs
produced by sibling transactions in a package being validated together (so a
child can spend a not-yet-in-mempool parent). SKIP-FEE-CHECK bypasses the per-tx
minimum-fee floor, used when the package as a whole is evaluated at the package
feerate (Bitcoin Core's package_feerates path).

CHAIN-STATE enables the relay finality + BIP68 sequence-lock checks (Core
PreChecks: a tx that couldn't be mined into the NEXT block doesn't belong in
the mempool). EVERY acceptance path must pass it — Core runs
CheckFinalTxAtTip and CheckSequenceLocksAtTip unconditionally, including
under bypass_limits (validation.cpp:819,886-889), so reorg re-adds,
mempool.dat reloads, and package members are all filtered too. NIL only in
unit tests exercising other layers.

BYPASS-LIMITS mirrors Core's ATMP bypass_limits (the reorg re-add path,
MaybeUpdateMempoolForReorg): the minimum-fee floor (validation.cpp:945) and
the TRUC topology checks (validation.cpp:951) are skipped — the tx was
already confirmed, so reorgs may re-create TRUC-violating topologies (Core's
comment at validation.cpp:340-341). RBF economics still apply.

SKIP-RBF-CHECK skips the per-tx replacement economics while still detecting
conflicts (returned as the 6th value), for the multi-transaction package
path where Core evaluates all conflicts at once through PackageRBFChecks
instead of per-tx ReplacementChecks (validation.cpp:1516); the caller runs
CHECK-PACKAGE-RBF-RULES itself. It also disables the sibling-eviction
fallthrough below regardless of ALLOW-SIBLING-EVICTION — with the economics
skipped there is nothing to evaluate the eviction, so the TRUC error must
surface (the invariant Core encodes as Assume(!m_allow_sibling_eviction) on
its package-feerate args, validation.cpp:573).

ALLOW-SIBLING-EVICTION (default T, matching Core's single-transaction
contexts, validation.cpp:487-497) lets a TRUC descendant-limit failure fall
through to the RBF path when SINGLE-TRUC-CHECKS identifies an evictable
sibling: the sibling is added to the conflict set and replacement economics
decide (Core PreChecks, validation.cpp:950-970)."
  ;; 1-4, the checks that read only the transaction (Core validation.cpp:
  ;; 798-815). See %MEMPOOL-PRECHECK-CONTEXT-FREE for the order and why it is
  ;; observable.
  (multiple-value-bind (ok reason) (%mempool-precheck-context-free tx)
    (unless ok
      (return-from validate-transaction-for-mempool (values nil reason nil))))

  ;; 5. Relay finality (:817-821, CheckFinalTxAtTip). It runs HERE, ahead of
  ;;    the mempool duplicate probe and of the coins lookup, and the position
  ;;    is the point: a transaction that cannot be mined into the next block
  ;;    is rejected as non-final EVEN IF its parents are unknown to us. Report
  ;;    :missing-input instead and the transaction enters the orphanage
  ;;    (src/networking/protocol.lisp branches on that one keyword) and draws
  ;;    getdatas for parents Core never asks for; Core instead remembers the
  ;;    wtxid in RecentRejectsFilter (txdownloadman_impl.cpp:468).
  ;;
  ;;    BIP68 sequence locks are NOT part of this: they need the spent coins'
  ;;    heights, and Core runs them further down at :886-889, after the input
  ;;    lookups. See the second half of the pair below.
  (when chain-state
    (multiple-value-bind (eval-height locktime-time)
        (%mempool-lock-context chain-state current-height)
      (unless (check-transaction-final tx eval-height locktime-time)
        (return-from validate-transaction-for-mempool
          (values nil :non-final nil)))))

  ;; 6. Already in the mempool (:823-830) — two probes, in Core's order, and
  ;;    they say different things. The WTXID probe means we hold this exact
  ;;    transaction, byte for byte. Only if that misses does the TXID probe
  ;;    run, and a hit there means we hold a transaction with the same
  ;;    non-witness data under a different witness: the submitter's witness
  ;;    was replaced somewhere in transit, which is the only signal Core gives
  ;;    that malleation is happening (mempool_accept_wtxid.py asserts on the
  ;;    exact string). A txid hit is a superset of a wtxid hit, so a single
  ;;    txid probe rejects the same set — it just cannot tell the two apart.
  (cond
    ((bl.mp:mempool-get-by-wtxid mempool (bl.ser:transaction-wtxid tx))
     (return-from validate-transaction-for-mempool
       (values nil :already-in-mempool nil)))
    ((bl.mp:mempool-has mempool (bl.ser:transaction-hash tx))
     (return-from validate-transaction-for-mempool
       (values nil :same-nonwitness-data-in-mempool nil))))

  ;; Conflicts with existing mempool entries are handled by BIP125 RBF after
  ;; the fee is known (see the fee section below).

  ;; Check inputs: each must reference a confirmed UTXO or an unconfirmed
  ;; in-mempool output (chained spend). EXTRA-COINS carries the latter, at
  ;; the next-block height (see mempool-extra-coins).
  (multiple-value-bind (extra-coins inputs-ok)
      (mempool-extra-coins tx utxo-set mempool (1+ current-height) package-coins)
    (unless inputs-ok
      ;; "Are inputs missing because we already have the tx?" (Core
      ;; validation.cpp:857-866). A transaction that is ALREADY CONFIRMED
      ;; presents as one with missing inputs — its own inputs were spent by
      ;; itself — so before reporting that, Core looks for any of this
      ;; transaction's OWN outputs among the coins. Finding one means the
      ;; transaction is already known, and it says so.
      ;;
      ;; DIVERGENCE, deliberate: Core consults only the coins CACHE
      ;; ("Optimistically just do efficient check of cache for outputs",
      ;; :860), so a confirmed transaction whose outputs are not cached gets
      ;; Core's missing-inputs instead. We ask the view, which answers the
      ;; question the check exists to ask in every case rather than most of
      ;; them. Both paths reject; only the reason differs.
      (let ((txid (bl.ser:transaction-hash tx))
            (outputs (bl.ser:transaction-outputs tx)))
        (dotimes (i (length outputs))
          (when (bl.store:get-utxo utxo-set txid i)
            (return-from validate-transaction-for-mempool
              (values nil :already-known nil)))))
      (return-from validate-transaction-for-mempool
        (values nil :missing-input nil)))

    ;; BIP68 sequence-locks, the second half of the finality pair (the first,
    ;; "non-final", ran before the mempool probe above). This half needs the
    ;; spent coins' heights, so Core runs it only here, once the inputs are in
    ;; the view (validation.cpp:886-889) — and immediately BEFORE CheckTxInputs
    ;; (:892). Evaluated as if the tx were in the NEXT block (tip+1) with the
    ;; tip's median-time-past (BIP113); same helpers the block connect path
    ;; uses, gated on CHAIN-STATE being supplied.
    (when chain-state
      (multiple-value-bind (eval-height locktime-time mtp csv-active)
          (%mempool-lock-context chain-state current-height)
        (declare (ignore locktime-time))
        (when csv-active
          (unless (check-sequence-locks tx utxo-set eval-height mtp chain-state
                                        :pending-utxos extra-coins)
            (return-from validate-transaction-for-mempool
              (values nil :non-bip68-final nil))))))

    ;; Consensus: Core's Consensus::CheckTxInputs (validation.cpp:892-895) —
    ;; coinbase maturity, input-value range, fee. It runs FIRST of the checks
    ;; that read the spent coins, ahead of every policy one, and the order is
    ;; observable: a transaction that fails a consensus rule AND a standardness
    ;; rule must report the CONSENSUS reason, because that is the verdict
    ;; callers act on — TX_CONSENSUS is a permanent property of the
    ;; transaction, TX_INPUTS_NOT_STANDARD only this node's relay policy.
    ;;
    ;; EXTRA-COINS is passed as pending-utxos so chained-spend inputs resolve.
    ;; The spend height is the NEXT block's height, not the tip's: Core's
    ;; PreChecks calls Consensus::CheckTxInputs with nSpendHeight =
    ;; m_active_chainstate.m_chain.Height() + 1 (validation.cpp, PreChecks:
    ;; "m_view.GetBestBlock() is the tip; a tx enters a block one higher"),
    ;; and maturity is nSpendHeight - coin.nHeight < COINBASE_MATURITY
    ;; (consensus/tx_verify.cpp) — so a coinbase spend maturing at tip+1
    ;; must be accepted NOW. Same tip+1 the finality/BIP68 checks above and
    ;; mempool-extra-coins already use. Block connection is untouched: there
    ;; current-height IS the connecting block's height, already the spend
    ;; height.
    (multiple-value-bind (valid error fee)
        (validate-transaction-contextual tx utxo-set (1+ current-height)
                                         :pending-utxos extra-coins)
      (unless valid
        (return-from validate-transaction-for-mempool
          (values nil error nil)))

      ;; The policy checks that need the spent scriptPubKeys, in Core's order
      ;; (validation.cpp:896-905): AreInputsStandard, IsWitnessStandard, then
      ;; nSigOpsCost — computed once and kept, as Core computes it once and
      ;; stages it into the entry (:905,924) for the assembler's sigop budget.
      (let ((sigops-cost
              (flet ((spent-script (txid index)
                       (let ((u (or (bl.store:get-utxo utxo-set txid index)
                                    (gethash (cons txid index) extra-coins))))
                         (when u (bl.store:utxo-entry-script-pubkey u)))))
                ;; Core AreInputsStandard → TX_INPUTS_NOT_STANDARD
                ;; "bad-txns-nonstandard-inputs" (:896-899). Distinct from the
                ;; TX_NOT_STANDARD cost cap below because this failure depends
                ;; only on the txid (spent scriptPubKeys + scriptSig) — the P2P
                ;; reject cache may key it by txid too.
                (when (and *require-standard*
                           (not (are-inputs-standard-p tx #'spent-script)))
                  (return-from validate-transaction-for-mempool
                    (values nil :nonstandard-inputs nil)))
                ;; Policy: witness must be standard (P2WSH/Taproot stack &
                ;; script limits, no annex), :901-903 — BEFORE the sigop cost
                ;; is even computed, so a witness-nonstandard spend that is
                ;; also sigop-dense reports the witness reason.
                (when (and (bl.ser:transaction-has-witness-p tx)
                           *require-standard*
                           (not (is-witness-standard-p tx #'spent-script)))
                  (return-from validate-transaction-for-mempool
                    (values nil :bad-witness-nonstandard nil)))
                ;; nSigOpsCost (:905). Its CAP runs further down, where Core
                ;; runs it: after PreCheckEphemeralTx (:933-939).
                (count-transaction-sigops-cost tx #'spent-script))))

        ;; Convert typed fee to integer. Policy fee checks (floor, RBF) run on
        ;; the prioritisation-modified fee (Core's ws.m_modified_fees); the
        ;; real fee is what gets recorded. VSIZE is the SIGOP-ADJUSTED virtual
        ;; size — Core's ws.m_vsize is the entry's GetTxSize()
        ;; (validation.cpp:929), not the raw BIP141 vsize — so the fee floor,
        ;; TRUC size caps, and RBF economics all price sigop-dense txs.
        (let* ((fee-value (bl.interop:unwrap-satoshi fee))
               (modified-fee-value
                 (+ fee-value
                    (gethash (bl.ser:transaction-hash tx)
                             (bl.mp:mempool-deltas mempool) 0)))
               (vsize (bl.mp:sigop-adjusted-vsize
                       (bl.ser:transaction-weight tx)
                       sigops-cost))
               (direct-conflicts (bl.mp:find-rbf-conflicts mempool tx))
               (replaced-set nil))

          ;; EPHEMERAL DUST, part 2 (Core PreCheckEphemeralTx,
          ;; ephemeral_policy.cpp:23, at validation.cpp:933 — after the fees
          ;; are known and BEFORE the sigop cap). A tx carrying dust must pay
          ;; NOTHING, base fee AND modified fee, so it is never worth mining
          ;; alone: the dust is safe only while swept as part of a package.
          (when (and *require-standard*
                     (or (/= fee-value 0) (/= modified-fee-value 0))
                     (plusp (transaction-dust-output-count tx)))
            (return-from validate-transaction-for-mempool
              (values nil :dust nil)))

          ;; Total weighted sigop cost <= MAX_STANDARD_TX_SIGOPS_COST
          ;; (validation.cpp:937-939), after the dust check and not before it:
          ;; both are TX_NOT_STANDARD, so only the reported reason differs.
          (when (> sigops-cost +max-standard-tx-sigops-cost+)
            (return-from validate-transaction-for-mempool
              (values nil :too-many-sigops nil)))

          ;; EPHEMERAL DUST, part 3 (Core CheckEphemeralSpends at
          ;; validation.cpp:1372, with package={ptx}). Only MEMPOOL parents are
          ;; visible from here; a parent still inside an unsubmitted package is
          ;; covered by the package-level call in validate-package-for-mempool.
          ;; Core gates this one on require_standard AND !bypass_limits
          ;; (validation.cpp:1370) — both, not either.
          (when (and *require-standard* (not bypass-limits)
                     (not (check-ephemeral-spends (list tx) mempool)))
            (return-from validate-transaction-for-mempool
              (values nil :missing-ephemeral-spends nil)))

          ;; Policy: minimum relay fee rate (relay floor, or the higher rolling
          ;; dynamic minimum when the mempool has been trimming). The rate is
          ;; sat/kvB (Core CFeeRate), so compare fee*1000 against rate*vsize --
          ;; exact integer math, no truncation to whole sat/vB. Skipped when this
          ;; tx is part of a package evaluated at the package feerate, and for
          ;; reorg re-adds (Core: !bypass_limits && !package_feerates &&
          ;; CheckFeeRate, validation.cpp:945).
          (when (and (not skip-fee-check)
                     (not bypass-limits)
                     (< (* modified-fee-value 1000)
                        (* (bl.mp:mempool-effective-min-fee-rate mempool)
                           vsize)))
            (return-from validate-transaction-for-mempool
              (values nil :insufficient-fee nil)))

          ;; BIP431 TRUC (v3) topology: inheritance + ancestor/descendant/size
          ;; limits for this tx and its unconfirmed relatives. Runs on every tx
          ;; (non-v3 spending v3 is also rejected); a no-op for a lone non-v3 tx.
          ;; Skipped under BYPASS-LIMITS (Core validation.cpp:951). A
          ;; :truc-descendant-limit failure with an evictable sibling falls
          ;; through to the RBF path instead when sibling eviction is allowed
          ;; (Core validation.cpp:950-970): the sibling joins the conflict set
          ;; and the replacement economics decide its fate.
          (unless bypass-limits
            (multiple-value-bind (truc-ok truc-reason sibling)
                (bl.mp:single-truc-checks mempool tx vsize direct-conflicts)
              (unless truc-ok
                (if (and sibling allow-sibling-eviction (not skip-rbf-check))
                    (pushnew sibling direct-conflicts :test #'equalp)
                    (return-from validate-transaction-for-mempool
                      (values nil truc-reason nil))))))

          ;; BIP125 replace-by-fee: if this tx conflicts with mempool entries
          ;; (or evicts a TRUC sibling) it must satisfy the replacement rules;
          ;; the set it replaces is returned to the caller (4th value) to evict
          ;; before adding. SKIP-RBF-CHECK defers this to the caller's package
          ;; RBF evaluation.
          (when (and direct-conflicts (not skip-rbf-check))
            (multiple-value-bind (ok reason rset)
                (%replacement-checks mempool tx modified-fee-value vsize
                                     sigops-cost direct-conflicts)
              (unless ok
                (return-from validate-transaction-for-mempool (values nil reason nil)))
              (setf replaced-set rset)))

          ;; Witness-stripped gate: a tx with NO witness data spending a
          ;; (non-anchor) witness program can never satisfy its scripts —
          ;; the witness is simply missing. Core fails these inside
          ;; CheckInputScripts and PolicyScriptChecks then reclassifies the
          ;; failure TX_WITNESS_STRIPPED (validation.cpp:1143-1148,
          ;; SpendsNonAnchorWitnessProg) so the P2P layer never caches it in
          ;; recent-rejects: a stripped tx's wtxid equals its txid, so
          ;; caching would poison the real witnessed tx's txid and block its
          ;; relay permanently. Running the gate BEFORE the script passes is
          ;; equivalent to Core's fail-then-reclassify: under the STANDARD
          ;; flags of the policy pass below, every witnessless non-anchor
          ;; witness-program spend fails (v0/v1 on the empty witness stack,
          ;; unknown versions on DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM), so
          ;; the reclassification would always fire anyway — pre-gating just
          ;; skips the doomed execution and keeps the :witness-stripped
          ;; classification. Anchor (P2A) spends are exempt: they
          ;; legitimately carry no witness.
          (when (and (not (bl.ser:transaction-has-witness-p tx))
                     (spends-non-anchor-witness-program-p tx utxo-set extra-coins))
            (return-from validate-transaction-for-mempool
              (values nil :witness-stripped nil)))

          ;; The two script passes, Core's names (defined above this
          ;; function): STANDARD flags first, then the tip's consensus
          ;; flags to warm the cache block connection will hit.
          (multiple-value-bind (ok error)
              (%policy-script-checks tx utxo-set extra-coins)
            (unless ok
              (return-from validate-transaction-for-mempool (values nil error nil))))
          (multiple-value-bind (ok error)
              (%consensus-script-checks tx utxo-set current-height extra-coins)
            (unless ok
              (return-from validate-transaction-for-mempool (values nil error nil))))


          (values t nil fee-value
                  (when replaced-set
                    (loop for k being the hash-keys of replaced-set collect k))
                  sigops-cost modified-fee-value direct-conflicts))))))

;;;; Script validation

(defun collect-spent-utxos (inputs utxo-set &optional extra-coins)
  "Return a vector of utxo-entry for INPUTS, or NIL if any UTXO is missing.
   EXTRA-COINS is an optional (txid . index) -> utxo-entry table consulted as a
   fallback (used for chained mempool spends, where a parent's output isn't in
   the confirmed UTXO set yet).
   Required for BIP 341 sighash, which hashes spent amounts/scripts across
   all inputs of a tx; without complete coverage, the Taproot sighash would
   be wrong, so callers should fall back when this returns NIL."
  (let ((result (make-array (length inputs))))
    (loop for input across inputs
          for i from 0
          for prevout = (bl.ser:tx-in-previous-output input)
          for utxo = (or (bl.store:get-utxo
                          utxo-set
                          (bl.ser:outpoint-hash prevout)
                          (bl.ser:outpoint-index prevout))
                         (and extra-coins
                              (gethash (cons (bl.ser:outpoint-hash prevout)
                                             (bl.ser:outpoint-index prevout))
                                       extra-coins)))
          unless utxo do (return-from collect-spent-utxos nil)
          do (setf (aref result i) utxo))
    result))

(defun validate-transaction-scripts (tx utxo-set &key (height 0) extra-coins flags)
  "Validate all input scripts for a transaction via Coalton interop.
Uses validate-input-script for each input (same path as block validation).
HEIGHT determines which script verification flags are active; FLAGS, when
supplied, overrides the height-derived flags with an explicit comma-separated
flag string (the mempool's PolicyScriptChecks pass runs the constant
+standard-script-verify-flags+ set this way).
EXTRA-COINS supplies spent outputs not in the confirmed UTXO set (chained
mempool spends). An input whose coin cannot be resolved fails the transaction:
Core asserts the coin is present before verifying (CheckInputScripts,
validation.cpp:2090), so a missing coin must never mean \"no script to check\".
Returns (VALUES T NIL NIL) on success and
(VALUES NIL INPUT-INDEX SCRIPT-ERROR) on failure, where SCRIPT-ERROR is the
Core SCRIPT_ERR_* the input failed on -- NIL when the coin was missing, which
is not a script verdict at all."
  (let* ((inputs (bl.ser:transaction-inputs tx))
         (effective-flags (or flags (compute-script-flags-for-height height)))
         ;; Script-execution cache (Core CheckInputScripts,
         ;; validation.cpp:2075-2081): a transaction whose inputs ALL verified
         ;; under this exact flag set needs none of them re-run. The mempool
         ;; verifies on acceptance and the confirming block verifies again, so
         ;; this turns the second pass into ONE lookup for the whole
         ;; transaction rather than one per signature.
         ;;
         ;; Keyed on the WTXID: the witness is where the signatures live, so a
         ;; malleated copy must not hit.
         (cache-key
           (when (and bl.interop:*script-execution-cache-enabled*
                      ;; Core returns true for a coinbase before touching the
                      ;; cache (validation.cpp:2064); it has no input scripts.
                      (not (and (= 1 (length inputs))
                                (bl.ser:coinbase-input-p
                                 (aref inputs 0)))))
             (bl.interop:make-script-execution-cache-key
              (bl.ser:transaction-wtxid tx)
              effective-flags))))
    (when (and cache-key
               (bl.interop:script-execution-cached-p cache-key))
      (return-from validate-transaction-scripts (values t nil nil)))
    (let* ((spent-utxos (collect-spent-utxos inputs utxo-set extra-coins))
           (bl.interop:*script-flags* effective-flags)
           (bl.interop:*precomputed-sighash*
             (bl.interop:init-precomputed-sighash tx spent-utxos))
           (bl.interop:*current-spent-utxos* spent-utxos))
      (dotimes (input-idx (length inputs))
        (let ((utxo (and spent-utxos (aref spent-utxos input-idx))))
          (unless utxo
            (return-from validate-transaction-scripts (values nil input-idx nil)))
          (multiple-value-bind (ok script-error)
              (validate-input-script tx input-idx utxo)
            (unless ok
              (return-from validate-transaction-scripts
                (values nil input-idx script-error))))))
      ;; Stored only after EVERY input succeeded — a partial success must never
      ;; short-circuit a later pass.
      (when cache-key
        (bl.interop:script-execution-cache-store cache-key))
      (values t nil nil))))
