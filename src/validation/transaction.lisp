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
    (when (zerop (length inputs))
      (return-from validate-transaction-structure
        (values nil :no-inputs)))

    ;; Must have at least one output
    (when (zerop (length outputs))
      (return-from validate-transaction-structure
        (values nil :no-outputs)))

    ;; Check for duplicate inputs
    (let ((seen-outpoints (make-hash-table :test 'equalp)))
      (bitcoin-lisp.serialization:dovector (input inputs)
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (key (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                          (bitcoin-lisp.serialization:outpoint-index prevout))))
          (when (gethash key seen-outpoints)
            (return-from validate-transaction-structure
              (values nil :duplicate-inputs)))
          (setf (gethash key seen-outpoints) t))))

    ;; Validate outputs using typed Satoshi arithmetic
    (let ((total-output (wrap-satoshi 0)))
      (bitcoin-lisp.serialization:dovector (output outputs)
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
             (bitcoin-lisp.serialization:coinbase-input-p (aref inputs 0)))
        (let ((sig-len (length (bitcoin-lisp.serialization:tx-in-script-sig
                                (aref inputs 0)))))
          (when (or (< sig-len 2) (> sig-len 100))
            (return-from validate-transaction-structure
              (values nil :bad-coinbase-length))))
        (bitcoin-lisp.serialization:dovector (inp inputs)
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
      (bitcoin-lisp.serialization:dovector (input inputs)
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
    (bitcoin-lisp.serialization:dovector (output outputs)
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

(defconstant +max-standard-tx-weight+ 400000
  "Maximum weight of a standard transaction for relay (Bitcoin Core
MAX_STANDARD_TX_WEIGHT).")

(defconstant +min-standard-tx-version+ 1
  "Minimum standard transaction version (Bitcoin Core TX_MIN_STANDARD_VERSION).")

(defconstant +max-standard-tx-version+ 3
  "Maximum standard transaction version. Bitcoin Core (TX_MAX_STANDARD_VERSION)
accepts v3 as standard in lockstep with enforcing TRUC/v3 topology policy
(BIP431). We now enforce that topology per-tx at mempool acceptance via
bitcoin-lisp.mempool:single-truc-checks (at most 1 unconfirmed ancestor +
1 descendant, TRUC_MAX_VSIZE, a 1000-vsize child cap, and v3<->non-v3 spend
inheritance), so v3 is relayed with its anti-pinning guarantees.")

(defconstant +dust-relay-fee-rate+ 3000
  "Dust relay fee rate in satoshis per kvB (Bitcoin Core DUST_RELAY_TX_FEE).
An output is dust when spending it would cost more than 1/3 its value at
this rate (~546 sat for P2PKH, ~294 sat for P2WPKH).")

(defconstant +max-standard-scriptsig-size+ 1650
  "Maximum scriptSig size for a standard input (Bitcoin Core
MAX_STANDARD_SCRIPTSIG_SIZE) — fits a 15-of-15 P2SH redeem.")

(defconstant +max-standard-tx-sigops-cost+ 16000
  "Maximum weighted sigop cost for a standard tx: MAX_BLOCK_SIGOPS_COST / 5
= 16,000 (Bitcoin Core MAX_STANDARD_TX_SIGOPS_COST, policy.h:43). Was
mistakenly 80,000 — the full BLOCK budget — letting a single standard tx
carry 5x the sigop density Core relays.")

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

(defun pay-to-anchor-p (script-pubkey)
  "True for a pay-to-anchor (P2A) output: the witness-v1 program OP_1 <push-2
0x4e73>, byte-exactly #x51 #x02 #x4e #x73 (Core CScript::IsPayToAnchor,
script/script.h). Spending a P2A never requires witness data, so it is
excluded from the witness-stripped classification below."
  (and (= (length script-pubkey) 4)
       (= (aref script-pubkey 0) #x51)
       (= (aref script-pubkey 1) #x02)
       (= (aref script-pubkey 2) #x4e)
       (= (aref script-pubkey 3) #x73)))

(defun spends-non-anchor-witness-program-p (tx utxo-set extra-coins)
  "True if any input of TX spends a witness-program output (any version,
including not-yet-defined ones) other than pay-to-anchor — directly, or via
P2SH whose redeem script (the scriptSig's last push; the scriptSig is known
push-only here from the standardness checks) is a witness program. Port of
Core SpendsNonAnchorWitnessProg (policy/policy.cpp:340-373): the classifier
for a script failure that could be explained by a stripped witness."
  (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
           (ptxid (bitcoin-lisp.serialization:outpoint-hash prevout))
           (pidx (bitcoin-lisp.serialization:outpoint-index prevout))
           (utxo (or (bitcoin-lisp.storage:get-utxo utxo-set ptxid pidx)
                     (when extra-coins (gethash (cons ptxid pidx) extra-coins))))
           (spk (and utxo (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo))))
      (when spk
        (cond
          ((and (output-witness-program-p spk)
                (not (pay-to-anchor-p spk)))
           (return-from spends-non-anchor-witness-program-p t))
          ((script-is-p2sh-p spk)
           (let ((redeem (extract-last-push
                          (bitcoin-lisp.serialization:tx-in-script-sig input))))
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

(defun %op-return-push-only-p (script)
  "T if the bytes after the leading OP_RETURN in SCRIPT are push-only (only data
pushes / OP_0 / OP_1NEGATE / OP_1..OP_16), matching Core CScript::IsPushOnly.
Any non-push opcode -- or a push that runs past the end -- fails."
  (let ((len (length script)) (i 1))    ; skip OP_RETURN at index 0
    (loop while (< i len) do
      (let ((op (aref script i)))
        (cond
          ((<= op #x4b) (incf i (+ 1 op)))                          ; OP_0 / direct push
          ((= op #x4c) (if (< (1+ i) len)                           ; OP_PUSHDATA1
                           (incf i (+ 2 (aref script (1+ i))))
                           (return-from %op-return-push-only-p nil)))
          ((= op #x4d) (if (< (+ i 2) len)                          ; OP_PUSHDATA2
                           (incf i (+ 3 (aref script (1+ i)) (ash (aref script (+ i 2)) 8)))
                           (return-from %op-return-push-only-p nil)))
          ((= op #x4e) (if (< (+ i 4) len)                          ; OP_PUSHDATA4
                           (incf i (+ 5 (aref script (1+ i)) (ash (aref script (+ i 2)) 8)
                                      (ash (aref script (+ i 3)) 16) (ash (aref script (+ i 4)) 24)))
                           (return-from %op-return-push-only-p nil)))
          ((<= op #x60) (incf i))                                   ; OP_1NEGATE / OP_1..OP_16
          (t (return-from %op-return-push-only-p nil)))))           ; non-push opcode
    (= i len)))                          ; NIL if a push overran the script end

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
     ;; Future witness program v1..v16 with a 2..40-byte program: Core's Solver
     ;; classifies these WITNESS_UNKNOWN (or ANCHOR for P2A, OP_1 <0x4e73>) and
     ;; IsStandard accepts them -- the forward-compat mechanism by which segwit/
     ;; taproot outputs relayed before activation. Only version-0 programs are
     ;; restricted to the 20/32-byte forms above (irregular v0 = NONSTANDARD).
     (and (>= len 4) (<= len 42)
          (<= #x51 (aref script-pubkey 0) #x60)   ; OP_1..OP_16
          (= (aref script-pubkey 1) (- len 2)))   ; single direct push of the program
     ;; OP_RETURN data carrier — gated by -datacarrier, sized by
     ;; -datacarriersize (mempool policy, not consensus). The bytes after
     ;; OP_RETURN must be push-only: Core's Solver only classifies NULL_DATA when
     ;; scriptPubKey.IsPushOnly(begin()+1) (solver.cpp), so an OP_RETURN carrying
     ;; any non-push opcode is nonstandard.
     (and bitcoin-lisp:*accept-datacarrier*
          (>= len 1)
          (<= len bitcoin-lisp:*max-datacarrier-bytes*)
          (= (aref script-pubkey 0) #x6a)   ; OP_RETURN
          (%op-return-push-only-p script-pubkey))
     ;; Bare (non-P2SH) multisig — standard only when -permitbaremultisig.
     (and bitcoin-lisp:*permit-bare-multisig*
          (bare-multisig-standard-p script-pubkey)))))

(defun bare-multisig-standard-p (script)
  "T if SCRIPT is a standard bare multisig: OP_m <pubkey>.. OP_n
OP_CHECKMULTISIG with 1<=m<=n<=3 and each key a 33/65-byte push (Bitcoin
Core's TX_MULTISIG standardness limit). Consensus allows up to 20 keys;
standardness caps bare multisig at 3."
  (let ((len (length script)))
    (and (>= len 4)
         (= (aref script (1- len)) #xae)         ; OP_CHECKMULTISIG
         (<= #x51 (aref script 0) #x60)          ; OP_m (1..16)
         (<= #x51 (aref script (- len 2)) #x60)  ; OP_n (1..16)
         (let ((m (- (aref script 0) #x50))
               (n (- (aref script (- len 2)) #x50)))
           (and (<= 1 m n 3)
                ;; Walk the n key pushes between OP_m and OP_n.
                (let ((pos 1) (keys 0))
                  (loop while (< pos (- len 2))
                        do (let ((plen (aref script pos)))
                             (unless (or (= plen 33) (= plen 65))
                               (return-from bare-multisig-standard-p nil))
                             (incf pos (1+ plen))
                             (incf keys)
                             (when (> keys n)
                               (return-from bare-multisig-standard-p nil))))
                  (and (= pos (- len 2)) (= keys n))))))))

(defun witness-program-parts (script)
  "If SCRIPT is a witness program, return (VALUES version program-bytes);
otherwise NIL. Version is 0 for OP_0, 1..16 for OP_1..OP_16."
  (when (output-witness-program-p script)
    (let ((v (aref script 0)))
      (values (if (= v #x00) 0 (- v #x50))   ; OP_1 (#x51) -> version 1
              (subseq script 2)))))

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
      ((= n 1) t)                                    ; key-path: no policy rules
      (t nil))))                                     ; 0 items: invalid by consensus

(defun input-witness-standard-p (wstack spk script-sig)
  "Whether one input's witness WSTACK is standard for the output SPK it spends
(SCRIPT-SIG is needed to unwrap a P2SH redeemScript)."
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
  (let ((witness (bitcoin-lisp.serialization:transaction-witness tx)))
    (or (null witness)
        (loop for input across (bitcoin-lisp.serialization:transaction-inputs tx)
        for wstack across witness
        ;; An input with no witness data imposes no witness-standardness rule.
        always (or (null wstack)
                   (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                          (spk (funcall spent-script-fn
                                        (bitcoin-lisp.serialization:outpoint-hash prevout)
                                        (bitcoin-lisp.serialization:outpoint-index prevout))))
                     (and spk
                          (input-witness-standard-p
                           wstack spk
                           (bitcoin-lisp.serialization:tx-in-script-sig input)))))))))

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
    (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx) (values extra t))
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (ptxid (bitcoin-lisp.serialization:outpoint-hash prevout))
             (pidx (bitcoin-lisp.serialization:outpoint-index prevout)))
        (unless (bitcoin-lisp.storage:get-utxo utxo-set ptxid pidx)
          (let* ((pe (bitcoin-lisp.mempool:mempool-get mempool ptxid))
                 (ptx (and pe (bitcoin-lisp.mempool:mempool-entry-transaction pe)))
                 (outs (and ptx (bitcoin-lisp.serialization:transaction-outputs ptx)))
                 (pkg-coin (and package-coins (gethash (cons ptxid pidx) package-coins))))
            (cond
              ((and outs (< pidx (length outs)))
               (let ((out (aref outs pidx)))
                 (setf (gethash (cons ptxid pidx) extra)
                       (bitcoin-lisp.storage:make-utxo-entry
                        :value (bitcoin-lisp.serialization:tx-out-value out)
                        :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey out)
                        :height spend-height
                        :coinbase nil))))
              (pkg-coin
               (setf (gethash (cons ptxid pidx) extra) pkg-coin))
              (t
               (return-from mempool-extra-coins (values nil nil))))))))))

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
  ;; Must not be coinbase
  (when (and (= (length (bitcoin-lisp.serialization:transaction-inputs tx)) 1)
             (bitcoin-lisp.serialization:coinbase-input-p
              (aref (bitcoin-lisp.serialization:transaction-inputs tx) 0)))
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

  ;; Policy: minimum non-witness size (Bitcoin Core MIN_STANDARD_TX_NONWITNESS_SIZE).
  ;; serialize-transaction emits the legacy (non-witness) encoding, so its length
  ;; is the stripped size — rejecting 64-byte txs (CVE-2017-12842).
  (when (< (length (bitcoin-lisp.serialization:serialize-transaction tx))
           +min-standard-tx-nonwitness-size+)
    (return-from validate-transaction-for-mempool
      (values nil :tx-size-small nil)))

  ;; Policy: scriptSig must be push-only and within the size limit
  (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let ((script-sig (bitcoin-lisp.serialization:tx-in-script-sig input)))
      (when (> (length script-sig) +max-standard-scriptsig-size+)
        (return-from validate-transaction-for-mempool
          (values nil :scriptsig-too-large nil)))
      (unless (scriptsig-push-only-p script-sig)
        (return-from validate-transaction-for-mempool
          (values nil :scriptsig-not-pushonly nil)))))

  ;; Policy: all outputs must be standard script types, and none dust
  (bitcoin-lisp.serialization:dovector (output (bitcoin-lisp.serialization:transaction-outputs tx))
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
  ;; in-mempool output (chained spend). EXTRA-COINS carries the latter, at
  ;; the next-block height (see mempool-extra-coins).
  (multiple-value-bind (extra-coins inputs-ok)
      (mempool-extra-coins tx utxo-set mempool (1+ current-height) package-coins)
    (unless inputs-ok
      (return-from validate-transaction-for-mempool
        (values nil :missing-input nil)))

    ;; Relay finality + BIP68 sequence-locks, evaluated as if the tx were in
    ;; the NEXT block (tip+1) with the tip's median-time-past (BIP113) —
    ;; Bitcoin Core's PreChecks "non-final" / "non-BIP68-final". Without this
    ;; the mempool accepts timelocked txs that can't yet be mined. Same helpers
    ;; the block connect path uses; gated on CHAIN-STATE being supplied.
    (when chain-state
      (let* ((eval-height (1+ current-height))
             (tip-hash (bitcoin-lisp.storage:best-block-hash chain-state))
             (mtp (compute-median-time-past chain-state tip-hash))
             (csv-active (>= eval-height
                             (get-csv-activation-height bitcoin-lisp:*network*)))
             ;; BIP113: locktime compares against MTP once CSV is active
             ;; (true on all our networks at tip); fall back to wall-clock
             ;; for the pre-activation window.
             (locktime-time (if csv-active mtp
                                (bitcoin-lisp.serialization:get-unix-time))))
        (unless (check-transaction-final tx eval-height locktime-time)
          (return-from validate-transaction-for-mempool
            (values nil :non-final nil)))
        (when csv-active
          (unless (check-sequence-locks tx utxo-set eval-height mtp chain-state
                                        :pending-utxos extra-coins)
            (return-from validate-transaction-for-mempool
              (values nil :non-bip68-final nil))))))

    ;; Policy: bounded sigop cost (now that spent scripts are available). The
    ;; computed cost is kept — it is returned to the caller and recorded on
    ;; the mempool entry, exactly as Core's PreChecks computes nSigOpsCost
    ;; once and stages it into the entry (validation.cpp:905,924), so the
    ;; block assembler's sigop budget sees real numbers.
    (let ((sigops-cost
            (flet ((spent-script (txid index)
                     (let ((u (or (bitcoin-lisp.storage:get-utxo utxo-set txid index)
                                  (gethash (cons txid index) extra-coins))))
                       (when u (bitcoin-lisp.storage:utxo-entry-script-pubkey u)))))
              ;; Total weighted sigop cost <= MAX_STANDARD_TX_SIGOPS_COST.
              (let ((cost (count-transaction-sigops-cost tx #'spent-script)))
                (when (> cost +max-standard-tx-sigops-cost+)
                  (return-from validate-transaction-for-mempool
                    (values nil :too-many-sigops nil)))
                ;; Per-input P2SH redeemScript sigops <= MAX_P2SH_SIGOPS.
                (bitcoin-lisp.serialization:dovector (input (bitcoin-lisp.serialization:transaction-inputs tx))
                  (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                         (spk (spent-script (bitcoin-lisp.serialization:outpoint-hash prevout)
                                            (bitcoin-lisp.serialization:outpoint-index prevout))))
                    (when (and spk (script-is-p2sh-p spk))
                      (let ((redeem (extract-last-push
                                     (bitcoin-lisp.serialization:tx-in-script-sig input))))
                        (when (and redeem
                                   (> (count-script-sigops redeem :accurate t)
                                      +max-standard-p2sh-sigops+))
                          ;; Core AreInputsStandard (policy.cpp) →
                          ;; TX_INPUTS_NOT_STANDARD "bad-txns-nonstandard-
                          ;; inputs": distinct from the TX_NOT_STANDARD total
                          ;; sigop-cost cap above, because this failure depends
                          ;; only on the txid (spent scriptPubKeys + scriptSig)
                          ;; — the P2P reject cache may key it by txid too.
                          (return-from validate-transaction-for-mempool
                            (values nil :nonstandard-inputs nil)))))))
                ;; Policy: witness must be standard (P2WSH/Taproot stack &
                ;; script limits, no annex). Needs the spent scriptPubKeys,
                ;; hence inside this flet.
                (when (and (bitcoin-lisp.serialization:transaction-has-witness-p tx)
                           (not (is-witness-standard-p tx #'spent-script)))
                  (return-from validate-transaction-for-mempool
                    (values nil :bad-witness-nonstandard nil)))
                cost))))

      ;; Contextual validation (consensus): coinbase maturity, fee calculation.
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

        ;; Convert typed fee to integer. Policy fee checks (floor, RBF) run on
        ;; the prioritisation-modified fee (Core's ws.m_modified_fees); the
        ;; real fee is what gets recorded. VSIZE is the SIGOP-ADJUSTED virtual
        ;; size — Core's ws.m_vsize is the entry's GetTxSize()
        ;; (validation.cpp:929), not the raw BIP141 vsize — so the fee floor,
        ;; TRUC size caps, and RBF economics all price sigop-dense txs.
        (let* ((fee-value (unwrap-satoshi fee))
               (modified-fee-value
                 (+ fee-value
                    (gethash (bitcoin-lisp.serialization:transaction-hash tx)
                             (bitcoin-lisp.mempool:mempool-deltas mempool) 0)))
               (vsize (bitcoin-lisp.mempool:sigop-adjusted-vsize
                       (bitcoin-lisp.serialization:transaction-weight tx)
                       sigops-cost))
               (direct-conflicts (bitcoin-lisp.mempool:find-rbf-conflicts mempool tx))
               (replaced-set nil))

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
                        (* (bitcoin-lisp.mempool:mempool-effective-min-fee-rate mempool)
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
                (bitcoin-lisp.mempool:single-truc-checks mempool tx vsize direct-conflicts)
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
                (bitcoin-lisp.mempool:check-rbf-rules mempool tx modified-fee-value
                                                      vsize direct-conflicts)
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
          (when (and (not (bitcoin-lisp.serialization:transaction-has-witness-p tx))
                     (spends-non-anchor-witness-program-p tx utxo-set extra-coins))
            (return-from validate-transaction-for-mempool
              (values nil :witness-stripped nil)))

          ;; Script pass 1 — PolicyScriptChecks (Core MemPoolAccept::
          ;; PolicyScriptChecks, validation.cpp:1132-1153): run the input
          ;; scripts under the full STANDARD flag set (a constant in Core,
          ;; policy/policy.h:118). A failure is a POLICY rejection
          ;; (TX_NOT_STANDARD), reject reason "mempool-script-verify-flag-
          ;; failed (...)" (CheckInputScripts, validation.cpp:2117), which
          ;; the P2P reject cache keys by wtxid only — never misbehavior.
          (multiple-value-bind (scripts-valid failed-input)
              (validate-transaction-scripts tx utxo-set
                                            :flags +standard-script-verify-flags+
                                            :extra-coins extra-coins)
            (declare (ignore failed-input))
            (unless scripts-valid
              (return-from validate-transaction-for-mempool
                (values nil :mempool-script-verify-flag-failed nil))))

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
          (multiple-value-bind (scripts-valid failed-input)
              (validate-transaction-scripts tx utxo-set :height current-height
                                            :extra-coins extra-coins)
            (unless scripts-valid
              (bitcoin-lisp:log-error
               "BUG! PLEASE REPORT THIS! input scripts failed against latest-block but not STANDARD flags: txid=~A input=~A"
               (bitcoin-lisp.crypto:bytes-to-hex
                (bitcoin-lisp.serialization:transaction-hash tx))
               failed-input)
              (return-from validate-transaction-for-mempool
                (values nil :block-script-verify-flag-failed nil))))

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

(defun validate-transaction-scripts (tx utxo-set &key (height 0) extra-coins flags)
  "Validate all input scripts for a transaction via Coalton interop.
Uses validate-input-script for each input (same path as block validation).
HEIGHT determines which script verification flags are active; FLAGS, when
supplied, overrides the height-derived flags with an explicit comma-separated
flag string (the mempool's PolicyScriptChecks pass runs the constant
+standard-script-verify-flags+ set this way).
EXTRA-COINS supplies spent outputs not in the confirmed UTXO set (chained
mempool spends).
Returns (VALUES T NIL) on success, (VALUES NIL INPUT-INDEX) on failure."
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (spent-utxos (collect-spent-utxos inputs utxo-set extra-coins))
         (bitcoin-lisp.coalton.interop:*script-flags*
           (or flags (compute-script-flags-for-height height)))
         (bitcoin-lisp.coalton.interop:*precomputed-sighash*
           (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx spent-utxos))
         (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent-utxos))
    (loop for input across inputs
          for input-idx from 0
          for utxo = (and spent-utxos (aref spent-utxos input-idx))
          when utxo
            do (unless (validate-input-script tx input-idx utxo)
                 (return-from validate-transaction-scripts
                   (values nil input-idx))))
    (values t nil)))
