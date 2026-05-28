(in-package #:bitcoin-lisp.validation)

;;; Transaction Validation
;;;
;;; This module validates Bitcoin transactions according to consensus rules.
;;; Uses Coalton Satoshi type for amount calculations to ensure type safety.

;;;; Imports for typed operations
(defun wrap-satoshi (v) (bitcoin-lisp.coalton.interop:wrap-satoshi v))
(defun unwrap-satoshi (s) (bitcoin-lisp.coalton.interop:unwrap-satoshi s))
(defun satoshi+ (a b) (bitcoin-lisp.coalton.interop:satoshi+ a b))
(defun satoshi> (a b) (bitcoin-lisp.coalton.interop:satoshi> a b))

;;;; Constants
(defconstant +max-money+ 2100000000000000)  ; 21 million BTC in satoshis
(defconstant +coin+ 100000000)               ; 1 BTC in satoshis
(defconstant +max-block-size+ 1000000)       ; 1 MB
(defconstant +coinbase-maturity+ 100)        ; Blocks before coinbase spendable

;; Typed constant for max money
(defvar *max-money-satoshi* nil)
(defun max-money-satoshi ()
  "Return +max-money+ as a Satoshi type (lazy initialization)."
  (or *max-money-satoshi*
      (setf *max-money-satoshi* (wrap-satoshi +max-money+))))

;;;; Structure validation (context-free)

(defun validate-transaction-structure (tx)
  "Validate basic transaction structure without chain context.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
        (outputs (bitcoin-lisp.serialization:transaction-outputs tx)))

    ;; Must have at least one input
    (when (null inputs)
      (return-from validate-transaction-structure
        (values nil :no-inputs)))

    ;; Must have at least one output
    (when (null outputs)
      (return-from validate-transaction-structure
        (values nil :no-outputs)))

    ;; Check for duplicate inputs
    (let ((seen-outpoints (make-hash-table :test 'equalp)))
      (dolist (input inputs)
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (key (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                          (bitcoin-lisp.serialization:outpoint-index prevout))))
          (when (gethash key seen-outpoints)
            (return-from validate-transaction-structure
              (values nil :duplicate-inputs)))
          (setf (gethash key seen-outpoints) t))))

    ;; Validate outputs using typed Satoshi arithmetic
    (let ((total-output (wrap-satoshi 0)))
      (dolist (output outputs)
        (let ((value (bitcoin-lisp.serialization:tx-out-value output)))
          ;; Output value must be non-negative
          (when (minusp value)
            (return-from validate-transaction-structure
              (values nil :negative-output)))
          ;; Output value must not exceed max money
          (when (> value +max-money+)
            (return-from validate-transaction-structure
              (values nil :output-too-large)))
          ;; Use typed addition
          (setf total-output (satoshi+ total-output (wrap-satoshi value)))))
      ;; Total output must not exceed max money
      (when (satoshi> total-output (max-money-satoshi))
        (return-from validate-transaction-structure
          (values nil :total-output-too-large))))

    ;; Coinbase vs non-coinbase, matching Core CheckTransaction
    ;; (tx_check.cpp:47-57) and IsCoinBase (primitives/transaction.h:341):
    ;; a tx is coinbase IFF it has exactly one input whose prevout is null.
    ;; Coinbase → scriptSig must be 2..100 bytes; non-coinbase → no input
    ;; may have a null prevout (bad-txns-prevout-null).
    (if (and (= (length inputs) 1)
             (bitcoin-lisp.serialization:coinbase-input-p (first inputs)))
        (let ((sig-len (length (bitcoin-lisp.serialization:tx-in-script-sig
                                (first inputs)))))
          (when (or (< sig-len 2) (> sig-len 100))
            (return-from validate-transaction-structure
              (values nil :bad-coinbase-length))))
        (dolist (inp inputs)
          (when (bitcoin-lisp.serialization:coinbase-input-p inp)
            (return-from validate-transaction-structure
              (values nil :bad-prevout-null)))))

    ;; Note: there is no consensus-level transaction size limit independent of
    ;; the block weight limit (4M weight units). Bitcoin Core only enforces
    ;; MAX_STANDARD_TX_WEIGHT (400,000 wu) as mempool policy, not consensus.
    ;; The block-weight ceiling is checked at block validation time.

    (values t nil)))

;;;; Contextual validation (requires chain state)

(defun validate-transaction-contextual (tx utxo-set current-height
                                        &key is-coinbase pending-utxos)
  "Validate a transaction in the context of the current UTXO set.
PENDING-UTXOS is an optional hash table of (txid . index) -> utxo-entry
for outputs created by earlier transactions in the same block.
Returns (VALUES T NIL FEE) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure.
FEE is returned as a Satoshi type."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
        (outputs (bitcoin-lisp.serialization:transaction-outputs tx))
        (total-input (wrap-satoshi 0))
        (total-output (wrap-satoshi 0)))

    ;; Skip input validation for coinbase
    (unless is-coinbase
      (dolist (input inputs)
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
               (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
               (utxo (or (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index)
                         ;; Check intra-block pending UTXOs
                         (when pending-utxos
                           (gethash (cons prev-txid prev-index) pending-utxos)))))

          ;; Input must reference an existing UTXO
          (unless utxo
            (bitcoin-lisp:log-warn
             "MISSING-INPUT: height=~D prev-txid=~A:~D in-pending=~A pending-size=~D"
             current-height
             (bitcoin-lisp.crypto:bytes-to-hex prev-txid)
             prev-index
             (and pending-utxos
                  (if (gethash (cons prev-txid prev-index) pending-utxos)
                      "yes" "no"))
             (if pending-utxos (hash-table-count pending-utxos) -1))
            (return-from validate-transaction-contextual
              (values nil :missing-input nil)))

          ;; Check coinbase maturity
          (when (bitcoin-lisp.storage:utxo-entry-coinbase utxo)
            (let ((age (- current-height
                         (bitcoin-lisp.storage:utxo-entry-height utxo))))
              (when (< age +coinbase-maturity+)
                (return-from validate-transaction-contextual
                  (values nil :coinbase-not-mature nil)))))

          ;; Use typed addition for input sum
          (setf total-input
                (satoshi+ total-input
                          (wrap-satoshi (bitcoin-lisp.storage:utxo-entry-value utxo)))))))

    ;; Sum outputs with typed addition
    (dolist (output outputs)
      (setf total-output
            (satoshi+ total-output
                      (wrap-satoshi (bitcoin-lisp.serialization:tx-out-value output)))))

    ;; For non-coinbase, inputs must cover outputs
    (unless is-coinbase
      (when (satoshi> total-output total-input)
        (return-from validate-transaction-contextual
          (values nil :insufficient-funds nil))))

    ;; Return fee as Satoshi type
    (values t nil (bitcoin-lisp.coalton.interop:satoshi- total-input total-output))))

;;;; Mempool acceptance validation

(defconstant +min-relay-fee-rate+ 1
  "Minimum relay fee rate in satoshis per virtual byte.")

(defconstant +max-standard-tx-weight+ 400000
  "Maximum weight of a standard transaction for relay (Bitcoin Core
MAX_STANDARD_TX_WEIGHT).")

(defconstant +min-standard-tx-version+ 1
  "Minimum standard transaction version (Bitcoin Core TX_MIN_STANDARD_VERSION).")

(defconstant +max-standard-tx-version+ 3
  "Maximum standard transaction version (Bitcoin Core TX_MAX_STANDARD_VERSION).")

(defconstant +dust-relay-fee-rate+ 3000
  "Dust relay fee rate in satoshis per kvB (Bitcoin Core DUST_RELAY_TX_FEE).
An output is dust when spending it would cost more than 1/3 its value at
this rate (~546 sat for P2PKH, ~294 sat for P2WPKH).")

(defconstant +max-standard-scriptsig-size+ 1650
  "Maximum scriptSig size for a standard input (Bitcoin Core
MAX_STANDARD_SCRIPTSIG_SIZE) — fits a 15-of-15 P2SH redeem.")

(defconstant +max-standard-tx-sigops-cost+ 80000
  "Maximum weighted sigop cost for a standard tx (MAX_BLOCK_SIGOPS_COST / 5).")

(defconstant +max-standard-p2sh-sigops+ 15
  "Maximum sigops in a standard P2SH redeemScript (Bitcoin Core MAX_P2SH_SIGOPS).")

(defun output-witness-program-p (script-pubkey)
  "True if SCRIPT-PUBKEY is a witness program: a version byte (OP_0, or
OP_1..OP_16) followed by a single push of 2-40 bytes that consumes the rest
of the script."
  (let ((len (length script-pubkey)))
    (and (>= len 4) (<= len 42)
         (let ((v (aref script-pubkey 0)))
           (or (= v #x00) (<= #x51 v #x60)))   ; OP_0 or OP_1..OP_16
         (let ((push (aref script-pubkey 1)))
           (and (<= 2 push 40) (= len (+ 2 push)))))))

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
        (floor (* nsize +dust-relay-fee-rate+) 1000))))

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
  "Check if SCRIPT-PUBKEY is a standard output script type.
Standard types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN (data carrier)."
  (let ((len (length script-pubkey)))
    (or
     ;; P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
     (and (= len 25)
          (= (aref script-pubkey 0) #x76)   ; OP_DUP
          (= (aref script-pubkey 1) #xa9)   ; OP_HASH160
          (= (aref script-pubkey 2) #x14)   ; push 20 bytes
          (= (aref script-pubkey 23) #x88)  ; OP_EQUALVERIFY
          (= (aref script-pubkey 24) #xac)) ; OP_CHECKSIG
     ;; P2SH: OP_HASH160 <20 bytes> OP_EQUAL
     (and (= len 23)
          (= (aref script-pubkey 0) #xa9)   ; OP_HASH160
          (= (aref script-pubkey 1) #x14)   ; push 20 bytes
          (= (aref script-pubkey 22) #x87)) ; OP_EQUAL
     ;; P2WPKH: OP_0 <20 bytes>
     (and (= len 22)
          (= (aref script-pubkey 0) #x00)   ; OP_0
          (= (aref script-pubkey 1) #x14))  ; push 20 bytes
     ;; P2WSH: OP_0 <32 bytes>
     (and (= len 34)
          (= (aref script-pubkey 0) #x00)   ; OP_0
          (= (aref script-pubkey 1) #x20))  ; push 32 bytes
     ;; P2TR: OP_1 <32 bytes>
     (and (= len 34)
          (= (aref script-pubkey 0) #x51)   ; OP_1
          (= (aref script-pubkey 1) #x20))  ; push 32 bytes
     ;; OP_RETURN data carrier (max 80 bytes data)
     (and (>= len 1)
          (<= len 83)
          (= (aref script-pubkey 0) #x6a))))) ; OP_RETURN

(defun mempool-extra-coins (tx utxo-set mempool)
  "Build a (txid . index) -> utxo-entry table for TX inputs that spend
unconfirmed in-mempool outputs (chained spends). Returns (values table ok-p);
OK-P is NIL if some input references neither a confirmed UTXO nor an in-mempool
output (a genuinely missing input)."
  (let ((extra (make-hash-table :test 'equalp)))
    (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx) (values extra t))
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (ptxid (bitcoin-lisp.serialization:outpoint-hash prevout))
             (pidx (bitcoin-lisp.serialization:outpoint-index prevout)))
        (unless (bitcoin-lisp.storage:get-utxo utxo-set ptxid pidx)
          (let* ((pe (bitcoin-lisp.mempool:mempool-get mempool ptxid))
                 (ptx (and pe (bitcoin-lisp.mempool:mempool-entry-transaction pe)))
                 (outs (and ptx (bitcoin-lisp.serialization:transaction-outputs ptx))))
            (if (and outs (< pidx (length outs)))
                (let ((out (nth pidx outs)))
                  (setf (gethash (cons ptxid pidx) extra)
                        (bitcoin-lisp.storage::make-utxo-entry
                         :value (bitcoin-lisp.serialization:tx-out-value out)
                         :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey out)
                         :height (bitcoin-lisp.mempool:mempool-entry-height pe)
                         :coinbase nil)))
                (return-from mempool-extra-coins (values nil nil)))))))))

(defun validate-transaction-for-mempool (tx utxo-set mempool current-height)
  "Validate a transaction for mempool acceptance.
Performs consensus checks plus policy checks.
Returns (VALUES T NIL FEE) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure.
FEE is returned as an integer (satoshis)."
  ;; Must not be coinbase
  (when (and (= (length (bitcoin-lisp.serialization:transaction-inputs tx)) 1)
             (bitcoin-lisp.serialization:coinbase-input-p
              (first (bitcoin-lisp.serialization:transaction-inputs tx))))
    (return-from validate-transaction-for-mempool
      (values nil :coinbase-not-allowed nil)))

  ;; Structure validation (consensus)
  (multiple-value-bind (valid error)
      (validate-transaction-structure tx)
    (unless valid
      (return-from validate-transaction-for-mempool
        (values nil error nil))))

  ;; Policy: standard transaction version
  (let ((version (bitcoin-lisp.serialization:transaction-version tx)))
    (unless (<= +min-standard-tx-version+ version +max-standard-tx-version+)
      (return-from validate-transaction-for-mempool
        (values nil :version-non-standard nil))))

  ;; Policy: max standard transaction weight (Bitcoin Core's only size limit;
  ;; the old serialized-size cap was removed upstream).
  (when (> (bitcoin-lisp.serialization:transaction-weight tx) +max-standard-tx-weight+)
    (return-from validate-transaction-for-mempool
      (values nil :tx-weight-too-large nil)))

  ;; Policy: scriptSig must be push-only and within the size limit
  (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let ((script-sig (bitcoin-lisp.serialization:tx-in-script-sig input)))
      (when (> (length script-sig) +max-standard-scriptsig-size+)
        (return-from validate-transaction-for-mempool
          (values nil :scriptsig-too-large nil)))
      (unless (scriptsig-push-only-p script-sig)
        (return-from validate-transaction-for-mempool
          (values nil :scriptsig-not-pushonly nil)))))

  ;; Policy: all outputs must be standard script types, and none dust
  (dolist (output (bitcoin-lisp.serialization:transaction-outputs tx))
    (let ((spk (bitcoin-lisp.serialization:tx-out-script-pubkey output)))
      (unless (standard-output-script-p spk)
        (return-from validate-transaction-for-mempool
          (values nil :non-standard-output nil)))
      (when (< (bitcoin-lisp.serialization:tx-out-value output)
               (dust-threshold spk))
        (return-from validate-transaction-for-mempool
          (values nil :dust nil)))))

  ;; Check for duplicate in mempool
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (when (bitcoin-lisp.mempool:mempool-has mempool txid)
      (return-from validate-transaction-for-mempool
        (values nil :already-in-mempool nil))))

  ;; Conflicts with existing mempool entries are handled by BIP125 RBF after
  ;; the fee is known (see the fee section below).

  ;; Check inputs: each must reference a confirmed UTXO or an unconfirmed
  ;; in-mempool output (chained spend). EXTRA-COINS carries the latter.
  (multiple-value-bind (extra-coins inputs-ok)
      (mempool-extra-coins tx utxo-set mempool)
    (unless inputs-ok
      (return-from validate-transaction-for-mempool
        (values nil :missing-input nil)))

    ;; Policy: bounded sigop cost (now that spent scripts are available).
    (flet ((spent-script (txid index)
             (let ((u (or (bitcoin-lisp.storage:get-utxo utxo-set txid index)
                          (gethash (cons txid index) extra-coins))))
               (when u (bitcoin-lisp.storage:utxo-entry-script-pubkey u)))))
      ;; Total weighted sigop cost <= MAX_STANDARD_TX_SIGOPS_COST.
      (when (> (count-transaction-sigops-cost tx #'spent-script)
               +max-standard-tx-sigops-cost+)
        (return-from validate-transaction-for-mempool
          (values nil :too-many-sigops nil)))
      ;; Per-input P2SH redeemScript sigops <= MAX_P2SH_SIGOPS.
      (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (spk (spent-script (bitcoin-lisp.serialization:outpoint-hash prevout)
                                  (bitcoin-lisp.serialization:outpoint-index prevout))))
          (when (and spk (script-is-p2sh-p spk))
            (let ((redeem (extract-last-push
                           (bitcoin-lisp.serialization:tx-in-script-sig input))))
              (when (and redeem
                         (> (count-script-sigops redeem :accurate t)
                            +max-standard-p2sh-sigops+))
                (return-from validate-transaction-for-mempool
                  (values nil :too-many-sigops nil))))))))

    ;; Contextual validation (consensus): coinbase maturity, fee calculation.
    ;; EXTRA-COINS is passed as pending-utxos so chained-spend inputs resolve.
    (multiple-value-bind (valid error fee)
        (validate-transaction-contextual tx utxo-set current-height
                                         :pending-utxos extra-coins)
      (unless valid
        (return-from validate-transaction-for-mempool
          (values nil error nil)))

      ;; Convert typed fee to integer; fee-rate is per virtual byte (BIP141).
      (let* ((fee-value (unwrap-satoshi fee))
             (vsize (bitcoin-lisp.serialization:transaction-vsize tx))
             (fee-rate (if (zerop vsize) 0 (floor fee-value vsize)))
             (direct-conflicts (bitcoin-lisp.mempool:find-rbf-conflicts mempool tx))
             (replaced-set nil))

        ;; Policy: minimum relay fee rate
        (when (< fee-rate +min-relay-fee-rate+)
          (return-from validate-transaction-for-mempool
            (values nil :insufficient-fee nil)))

        ;; BIP125 replace-by-fee: if this tx conflicts with mempool entries it
        ;; must satisfy the replacement rules; the set it replaces is returned
        ;; to the caller (4th value) to evict before adding.
        (when direct-conflicts
          (multiple-value-bind (ok reason rset)
              (bitcoin-lisp.mempool:check-rbf-rules mempool tx fee-value vsize
                                                    direct-conflicts)
            (unless ok
              (return-from validate-transaction-for-mempool (values nil reason nil)))
            (setf replaced-set rset)))

        ;; Script validation (consensus)
        (multiple-value-bind (scripts-valid failed-input)
            (validate-transaction-scripts tx utxo-set :height current-height
                                          :extra-coins extra-coins)
          (declare (ignore failed-input))
          (unless scripts-valid
            (return-from validate-transaction-for-mempool
              (values nil :script-failed nil))))

        (values t nil fee-value
                (when replaced-set
                  (loop for k being the hash-keys of replaced-set collect k)))))))

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
    (loop for input in inputs
          for i from 0
          for prevout = (bitcoin-lisp.serialization:tx-in-previous-output input)
          for utxo = (or (bitcoin-lisp.storage:get-utxo
                          utxo-set
                          (bitcoin-lisp.serialization:outpoint-hash prevout)
                          (bitcoin-lisp.serialization:outpoint-index prevout))
                         (and extra-coins
                              (gethash (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                                             (bitcoin-lisp.serialization:outpoint-index prevout))
                                       extra-coins)))
          unless utxo do (return-from collect-spent-utxos nil)
          do (setf (aref result i) utxo))
    result))

(defun validate-transaction-scripts (tx utxo-set &key (height 0) extra-coins)
  "Validate all input scripts for a transaction via Coalton interop.
Uses validate-input-script for each input (same path as block validation).
HEIGHT determines which script verification flags are active.
EXTRA-COINS supplies spent outputs not in the confirmed UTXO set (chained
mempool spends).
Returns (VALUES T NIL) on success, (VALUES NIL INPUT-INDEX) on failure."
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (spent-utxos (collect-spent-utxos inputs utxo-set extra-coins))
         (bitcoin-lisp.coalton.interop:*script-flags*
           (compute-script-flags-for-height height))
         (bitcoin-lisp.coalton.interop:*precomputed-sighash*
           (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx spent-utxos))
         (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent-utxos))
    (loop for input in inputs
          for input-idx from 0
          for utxo = (and spent-utxos (aref spent-utxos input-idx))
          when utxo
            do (unless (validate-input-script tx input-idx utxo)
                 (return-from validate-transaction-scripts
                   (values nil input-idx))))
    (values t nil)))
