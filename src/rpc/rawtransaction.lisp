(in-package #:bitcoin-lisp.rpc)

;;;; Raw transaction RPCs (Core rpc/rawtransaction.cpp): decode, get, create,
;;;; decodescript and sign with keys, plus estimatesmartfee / estimaterawfee
;;;; (Core rpc/fees.cpp).

;;; --- Extended RPC Methods ---

(define-rpc "decoderawtransaction" (node (hex-str))
  "Decode a raw transaction hex string to JSON."
  (unless (and (stringp hex-str) (> (length hex-str) 0))
    (error 'rpc-error :code +rpc-deserialization-error+
                      :message "Invalid transaction hex"))
  (handler-case
      (let* ((tx-bytes (bl.crypto:hex-to-bytes hex-str))
             (tx (flexi-streams:with-input-from-sequence (stream tx-bytes)
                   (bl.ser:read-transaction stream))))
        (tx-to-json tx (rpc-get-network node)))
    (error (e)
      (error 'rpc-error :code +rpc-deserialization-error+
                        :message (format nil "TX decode failed: ~A" e)))))

(defun %not-found-transaction-message (reason)
  "REASON plus the sentence Core appends to every one of getrawtransaction's
four not-found messages (rawtransaction.cpp:315-329). Its tests match on the
WHOLE string: rpc_rawtransaction.py:129 asserts the no-txindex variant in
full, so the suffix is not decoration."
  (concatenate 'string reason ". Use gettransaction for wallet transactions."))

(defun %genesis-coinbase-txid (network)
  "NETWORK's genesis block merkle root, in internal byte order.

The genesis block carries exactly one transaction, so its merkle root IS that
coinbase's txid -- the value Core compares the requested hash against
(rawtransaction.cpp:290, `hash == Params().GenesisBlock().hashMerkleRoot').
Computed per network from the real coinbase (bl.store:make-genesis-block):
testnet4's pszTimestamp differs, so its root does too."
  (bl.ser:block-header-merkle-root
   (bl.ser:bitcoin-block-header (bl.store:make-genesis-block network))))

(defun %refuse-genesis-coinbase (node txid-str)
  "Core's special exception for the genesis block coinbase
(rawtransaction.cpp:288-293): -5, with no lookup attempted anywhere.

It runs before the verbosity and the blockhash argument are read, and it is
not an optimisation -- the genesis coinbase is in no index and in no UTXO set,
so without it the caller gets whichever not-found message this node's txindex
configuration happens to select, and a caller who names the genesis block hash
as the third argument is told the transaction is not in a block that contains
it."
  (when (equalp (parse-hex-hash txid-str)
                (%genesis-coinbase-txid (rpc-get-network node)))
    (error 'rpc-error :code +rpc-invalid-address-or-key+
                      :message "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved")))

(defun %getrawtransaction-in-block (node block-entry txid verbose prevouts)
  "getrawtransaction's answer when the caller named a block: the transaction
comes from THAT block or the call fails.

Core's GetTransaction skips the mempool entirely once a block index is
supplied (`if (mempool && !block_index)`, node/transaction.cpp:143-145) and
drops a txindex hit whose block hash differs (:150-156), so the third
argument is a containment check and not a hint. A block the index knows but
whose body is not on disk is Core's -1 \"Block not available\"
(rawtransaction.cpp:317-320) — we carry no BLOCK_HAVE_DATA bit, and a block
the store cannot produce (pruned, or not yet downloaded) is exactly that
state. The object carries in_active_chain, which Core adds whenever the
argument was given."
  (let* ((block-hash (bl.store:block-index-entry-hash block-entry))
         (block (bl.store:get-block (rpc-get-block-store node) block-hash)))
    (unless block
      (error 'rpc-error :code +rpc-misc-error+ :message "Block not available"))
    (let ((found-tx (find-tx-in-block block txid)))
      (unless found-tx
        (error 'rpc-error :code +rpc-invalid-address-or-key+
                          :message (%not-found-transaction-message
                                    "No such transaction found in the provided block")))
      (if verbose
          (append (tx-to-json-confirmed found-tx node block-hash
                                        :block block :prevouts prevouts)
                  `(("in_active_chain"
                     . ,(json-bool (%block-on-active-chain-p
                                    block-entry (rpc-get-chain-state node))))))
          (bl.crypto:bytes-to-hex (bl.ser:transaction-wire-bytes found-tx))))))

(define-rpc "getrawtransaction" (node (txid-str verbosity blockhash-hint))
  "Get raw transaction data by txid (Bitcoin Core getrawtransaction).
Verbosity <= 0 (or false, the default) returns the wire-serialized (witness-
complete) tx hex — Core's EncodeHexTx; 1 (or true) the decoded object; 2 adds
the fee and each input's prevout for a CONFIRMED transaction
(rawtransaction.cpp:346-371).
With a blockhash the answer comes from that block alone; without one, the
mempool first and then the txindex (if enabled). The genesis block coinbase is
refused before any of that (rawtransaction.cpp:288-293)."
  (unless (valid-hex-hash-p txid-str)
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid transaction id"))
  (%refuse-genesis-coinbase node txid-str)
  (when (and blockhash-hint (not (valid-hex-hash-p blockhash-hint)))
    (error 'rpc-error :code +rpc-invalid-parameter+
                      :message "Invalid blockhash"))
  (let* ((verbosity (%parse-verbosity params 1 0 :allow-bool t))
         (verbose (plusp verbosity))
         ;; Core's verbosity 2 adds fee + prevout for a CONFIRMED transaction
         ;; (rawtransaction.cpp:346-371); a mempool transaction has no undo
         ;; data, so it stays at the verbosity-1 shape there.
         (prevouts (>= verbosity 2))
         (txid-bytes (parse-hex-hash txid-str))
         ;; Core resolves the blockhash FIRST, under cs_main, and refuses an
         ;; unknown one before any transaction lookup at all
         ;; (rawtransaction.cpp:298-305). Answering from the txindex instead
         ;; hands a caller using this argument as a containment check the
         ;; transaction from a completely different block.
         (block-entry (when blockhash-hint
                        (or (bl.store:get-block-index-entry
                             (rpc-get-chain-state node)
                             (parse-hex-hash blockhash-hint))
                            (error 'rpc-error :code +rpc-invalid-address-or-key+
                                              :message "Block hash not found")))))
    (when block-entry
      (return-from rpc-getrawtransaction
        (%getrawtransaction-in-block node block-entry txid-bytes
                                     verbose prevouts)))

    ;; No blockhash: the mempool, then the txindex (Core GetTransaction,
    ;; node/transaction.cpp:143-158).
    (let* ((mempool (rpc-get-mempool node))
           (mempool-entry (when mempool
                            (bl.mp:mempool-get mempool txid-bytes))))
      (when mempool-entry
        (let ((tx (bl.mp:mempool-entry-transaction mempool-entry)))
          (return-from rpc-getrawtransaction
            (if verbose
                (tx-to-json tx (rpc-get-network node))
                (bl.crypto:bytes-to-hex
                 (bl.ser:transaction-wire-bytes tx)))))))

    ;; No block was named and the mempool has missed, so the txindex is the
    ;; last place to look — and whether it is enabled also decides which of
    ;; Core's not-found messages applies.
    (let* ((tx-index (rpc-get-tx-index node))
           (indexed (and tx-index (bl.store:tx-index-enabled tx-index)))
           (location (and indexed (bl.store:txindex-lookup tx-index txid-bytes)))
           (block-hash (and location (bl.store:tx-location-block-hash location)))
           (block (and block-hash
                       (bl.store:get-block (rpc-get-block-store node) block-hash)))
           (found-tx (and block (find-tx-in-block block txid-bytes))))
      (when found-tx
        (return-from rpc-getrawtransaction
          (if verbose
              (tx-to-json-confirmed found-tx node block-hash
                                    :block block :prevouts prevouts)
              (bl.crypto:bytes-to-hex
               (bl.ser:transaction-wire-bytes found-tx)))))
      ;; Not found. Two of Core's four messages are reachable here; the
      ;; blockhash pair answered above, and the one left out is
      ;; "Blockchain transactions are still in the process of being indexed",
      ;; which needs f_txindex_ready — a readiness flag distinct from
      ;; "enabled", which this txindex does not carry. Inventing an answer for
      ;; a state we cannot observe would be worse than answering the
      ;; enabled-and-absent case, which is what a caught-up node is in.
      (error 'rpc-error :code +rpc-invalid-address-or-key+
                        :message
                        (%not-found-transaction-message
                         (if indexed
                             "No such mempool or blockchain transaction"
                             "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries"))))))

(defun find-tx-in-block (block txid)
  "Find a transaction in a block by txid. Returns the transaction or NIL."
  (let ((txs (bl.ser:bitcoin-block-transactions block)))
    (find-if (lambda (tx)
               (equalp txid (bl.ser:transaction-hash tx)))
             txs)))

(defun tx-to-json-confirmed (tx node block-hash &key block prevouts)
  "Convert a confirmed transaction to JSON with block context, per Core's
TxToJSON (rpc/rawtransaction.cpp:58-86): blockhash is always present; when
the block index knows the block AND it is on the active chain, add
confirmations/time/blocktime; a known but STALE block (e.g. a txindex entry
pointing into a reorged-away branch — Core keeps those) gets confirmations 0
and NO time fields; an unknown block gets blockhash only."
  (let* ((chain-state (rpc-get-chain-state node))
         (block-entry (bl.store:get-block-index-entry chain-state block-hash))
         ;; verbosity 2 (Core rawtransaction.cpp:351-370): find THIS
         ;; transaction's coins in the block's undo data. The undo list has one
         ;; entry per NON-coinbase transaction, so the index is one less than
         ;; the transaction's position — and a coinbase has none at all.
         (coins (and prevouts block (%tx-spent-coins-in-block block tx)))
         (base-json (tx-to-json tx (rpc-get-network node)
                                :spent-coins coins :prevouts (and coins t))))
    (append base-json
            `(("blockhash" . ,(hash-to-hex block-hash)))
            (cond ((null block-entry) '())
                  ((%block-on-active-chain-p block-entry chain-state)
                   (let* ((current-height (bl.store:current-height chain-state))
                          (block-height (bl.store:block-index-entry-height block-entry))
                          (header (bl.store:block-index-entry-header block-entry))
                          (block-time (when header
                                        (bl.ser:block-header-timestamp header))))
                     `(("confirmations" . ,(1+ (- current-height block-height)))
                       ("time" . ,block-time)
                       ("blocktime" . ,block-time))))
                  (t '(("confirmations" . 0)))))))

(define-rpc "estimatesmartfee" (node (conf-target mode-str))
  "Estimate fee rate for confirmation in conf_target blocks.
PARAMS: [conf_target, estimate_mode]
Returns: { feerate?: BTC/kvB, blocks: number, errors?: [strings] }

Bitcoin Core rpc/fees.cpp:32-95. Four parts of that contract were wrong here,
all of them silently:

  - The DEFAULT MODE is \"economical\" (RPCArg::Default{\"economical\"}), not
    conservative. Defaulting to conservative returns a higher number, so every
    caller that did not name a mode was quietly told to overpay.
  - On no estimate Core omits \"feerate\" ENTIRELY and returns only the error.
    We returned a fabricated 0.00001 BTC/kvB (1 sat/vB) fallback, so a wallet
    reading \"feerate\" got a made-up number rather than noticing there was no
    estimate — and built a transaction that would not confirm.
  - Core CLAMPS the answer up to the node's own floors:
    max(estimate, mempool rolling minimum, min relay fee). Unclamped, a node
    whose mempool minimum has risen recommends a fee BELOW its own acceptance
    threshold — it rejects the transaction it just priced.
  - \"blocks\" is feeCalc.returnedTarget, the target the answer is actually
    for, not the one requested. The estimator substitutes 2 for a 1-block
    target and clamps to what its history can justify."
  (let* ((mode (cond
                 ((null mode-str) :economical)
                 ((string-equal mode-str "unset") :economical)
                 ((string-equal mode-str "economical") :economical)
                 ((string-equal mode-str "conservative") :conservative)
                 (t (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message "Invalid estimate_mode parameter, must be one of: \"unset\", \"economical\", \"conservative\"")))))
    ;; Core bounds conf_target by the estimator's highest tracked target rather
    ;; than a fixed constant (ParseConfirmTarget with
    ;; HighestTargetTracked(LONG_HALFLIFE), rpc/util.cpp:369-377).
    (let ((max-target (bl.mp:highest-target-tracked)))
      (unless (and (integerp conf-target) (>= conf-target 1)
                   (<= conf-target max-target))
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Invalid conf_target, must be between ~D and ~D"
                                           1 max-target))))
    ;; Still syncing: no feerate key, as in every other no-estimate case.
    (when (rpc-is-syncing node)
      (return-from rpc-estimatesmartfee
        `(("blocks" . ,conf-target)
          ("errors" . #("Insufficient data (node still syncing)")))))
    (let ((fee-estimator (bl:node-fee-estimator node))
          (mempool (rpc-get-mempool node)))
      (multiple-value-bind (rate-sat-vb error-msg returned-target)
          (if (and fee-estimator
                   (bl.mp:fee-estimator-ready-p fee-estimator))
              (bl.mp:estimate-fee-rate fee-estimator conf-target
                                                      :mode mode)
              (values 0 "Insufficient data or no feerate found" conf-target))
        (let ((blocks (or returned-target conf-target)))
          (if (or error-msg (null rate-sat-vb) (zerop rate-sat-vb))
              ;; Core's failure branch: errors, blocks, and NO feerate.
              `(("blocks" . ,blocks)
                ("errors" . ,(vector (or error-msg
                                         "Insufficient data or no feerate found"))))
              ;; Clamp to the node's own floors before reporting.
              (let* ((rate-sat-kvb (* rate-sat-vb 1000))
                     (floor-sat-kvb
                       (if mempool
                           (bl.mp:mempool-effective-min-fee-rate mempool)
                           0))
                     (clamped (max rate-sat-kvb floor-sat-kvb)))
                `(("feerate" . ,(/ clamped 100000000.0d0))
                  ("blocks" . ,blocks)))))))))

;;; --- signrawtransactionwithkey (non-wallet, P2PKH + P2WPKH) ---

(defun parse-sighash-type (s)
  "Map a sighashtype string (default \"ALL\") to its byte: ALL=1 NONE=2 SINGLE=3,
with |ANYONECANPAY setting 0x80."
  (let* ((str (string-upcase (or s "ALL")))
         (acp (search "ANYONECANPAY" str))
         (base (cond ((search "ALL" str) 1)
                     ((search "NONE" str) 2)
                     ((search "SINGLE" str) 3)
                     (t (error 'rpc-error :code +rpc-invalid-parameter+
                                          :message "Invalid sighashtype")))))
    (logior base (if acp #x80 0))))

(defun parse-multisig (script)
  "If SCRIPT is a bare multisig (OP_m <pubkey>...<pubkey> OP_n OP_CHECKMULTISIG),
return (values m n pubkeys) -- pubkeys a list of the n key vectors in order;
else NIL. The classification is CLASSIFY-SCRIPT's (Core MatchMultisig)."
  (multiple-value-bind (type data) (bl.val:classify-script script)
    (when (eq type :multisig)
      (values (getf data :m) (getf data :n) (getf data :pubkeys)))))

(defun %collect-multisig-sig-pairs (sighash pubmap pubkeys m sighash-byte)
  "ECDSA (pubkey . DER||sighash-byte) pairs for the keys we hold among PUBKEYS,
in pubkey order, capped at M. CHECKMULTISIG requires sigs ordered as the pubkeys
appear, which iterating PUBKEYS in order preserves. The cap at M matches the
in-place signer's historical collection (finalize needs exactly M); the PSBT
signer therefore records at most M partial sigs per multisig input."
  (let ((pairs '()) (count 0))
    (dolist (pub pubkeys (nreverse pairs))
      (when (< count m)
        (let ((sk (gethash pub pubmap)))
          (when sk
            (push (cons pub (concatenate '(vector (unsigned-byte 8))
                                         (bl.crypto:sign-ecdsa sk sighash)
                                         (vector sighash-byte)))
                  pairs)
            (incf count)))))))

;;; --- Per-input signing split into (compute signatures) + (finalize) ---
;;;
;;; sign-tx-inputs historically both computed each input's signature(s) AND
;;; finalized them into scriptSig/witness in one pass. Wallet P5's PSBT signer
;;; needs the FIRST half alone (record partial sigs without finalizing), so the
;;; per-input work is factored into compute-input-signatures (the funds-critical
;;; sighash + sign dispatch) and %finalize-input-signatures (assembly). The spend
;;; path still runs both back-to-back and its output is byte-identical.

(defstruct (input-sig (:constructor %make-input-sig))
  "Signature material for one input, produced by compute-input-signatures
without finalizing. KIND selects the finalize shape; ECDSA is an ordered list of
(pubkey . sig) pairs (sig = DER || sighash-byte); TAP is a taproot key-path
signature; NEEDED is the m-of-n threshold finalize enforces (1 for single-key);
REDEEM/WITNESS-SCRIPT are the P2SH/P2WSH sub-scripts to reveal."
  (kind nil :type symbol)
  (ecdsa '() :type list)
  (tap nil)
  (needed 0 :type fixnum)
  (redeem nil)
  (witness-script nil)
  ;; A finished witness stack, for kinds whose satisfaction is not m-of-n and
  ;; so cannot be described by ECDSA + NEEDED: miniscript, where the satisfier
  ;; chooses which branch to take and what to push for it.
  (stack nil :type list)
  ;; :P2TR-SCRIPT only. A PSBT cannot store the finished witness above — it has
  ;; to store the PARTS, so another signer can add its own signature to the same
  ;; leaf: PSBT_IN_TAP_SCRIPT_SIG keyed by <xonly><leaf hash>, and
  ;; PSBT_IN_TAP_LEAF_SCRIPT keyed by the control block.
  (tap-script-sigs nil :type list)   ; list of (xonly leaf-hash sig)
  (tap-leaf nil))                    ; (script . control-block) of the leaf used

(defun %tap-sig (privkey sighash tap-sighash-type)
  "A BIP341 signature: 64 bytes for SIGHASH_DEFAULT, else 65 with the sighash
byte appended (Core's CreateSchnorrSig, sign.cpp:340)."
  (let ((sig64 (bl.crypto:sign-schnorr privkey sighash)))
    (if (zerop tap-sighash-type)
        sig64
        (concatenate '(vector (unsigned-byte 8)) sig64 (vector tap-sighash-type)))))

(defun %tr-script-path-witness (leaves amount tap-sighash-type pubmap)
  "The complete witness stack for a taproot SCRIPT-path spend, or NIL when no
leaf can be satisfied. LEAVES is a list of
(SCRIPT LEAF-HASH CONTROL-BLOCK LEAF-DESC LEAF-PUBKEYS) -- what TR-SPEND-DATA
produced for this output, each entry extended with the parsed leaf descriptor
and its pubkeys at this range index.

Core tries every leaf and keeps the SMALLEST serialized result
(sign.cpp:601-612); so do we, because which leaf is cheapest depends on both
its script and its merkle depth and neither dominates.

*current-tx* / *current-spent-utxos* / *current-input-index* must be bound by
the caller -- the sighash commits to all of them."
  (let ((best nil) (best-size nil) (best-leaf nil) (best-sigs nil) (signed-by nil))
    (dolist (entry leaves)
      (destructuring-bind (script leaf-hash control leaf pubkeys) entry
        (progn
          (setf signed-by nil)
          (let* (;; BIP341 script-path tail: the tapleaf hash, key version 0,
                 ;; and the codeseparator position. Signing always commits to
                 ;; "no codeseparator executed" -- our tapscript leaves contain
                 ;; none, and a leaf that did would need the position it
                 ;; actually reached at execution time.
                 (bl.interop:*tapscript-codesep-pos* #xFFFFFFFF)
                 (sighash (bl.interop:compute-bip341-sighash
                           amount tap-sighash-type leaf-hash 0)))
            (when sighash
              (let ((satisfaction
                      (tr-leaf-satisfaction
                       leaf pubkeys
                       (lambda (xonly)
                         ;; PUBMAP is keyed by the 33-byte pubkey and an x-only
                         ;; key names both parities, so both are tried. SIGN-
                         ;; SCHNORR builds a keypair, which negates the secret
                         ;; for an odd-Y key itself.
                         (let ((sk (or (gethash (concatenate '(vector (unsigned-byte 8))
                                                             #(2) xonly)
                                                pubmap)
                                       (gethash (concatenate '(vector (unsigned-byte 8))
                                                             #(3) xonly)
                                                pubmap))))
                           (when sk
                             (let ((sig (%tap-sig sk sighash tap-sighash-type)))
                               (push (list xonly leaf-hash sig) signed-by)
                               sig)))))))
                (when satisfaction
                  (let* ((stack (append satisfaction (list script control)))
                         (size (reduce #'+ stack :key #'length)))
                    (when (or (null best-size) (< size best-size))
                      (setf best stack
                            best-size size
                            best-leaf (cons script control)
                            best-sigs (reverse signed-by)))))))))))
    (values best best-sigs best-leaf)))

(defun %wsh-pkh-resolver (keymap)
  "Core's WshSatisfier::FromPKHBytes (sign.cpp:428-436) as MS-FROM-SCRIPT wants
it: a pkh() branch commits to HASH160 of a key rather than to the key, so the
key comes back out of the signing provider -- here KEYMAP, which the P2PKH and
P2WPKH arms already index by exactly that hash. Without it the inferred node
carries no key at all, the satisfier's sign-fn is called with NIL, and a policy
this node holds every private key for is reported unsignable."
  (lambda (hash) (cdr (gethash hash keymap))))

(defun compute-input-signatures (tx i prev keymap pubmap tr-keymap sighash-byte
                                  precomp spent-utxos &optional (tap-sighash-type #x00)
                                                                tr-scripts)
  "Compute the signature material for input I of TX spending PREV
= (script-pubkey amount redeem witness-script), using the key maps. Returns
(values input-sig error-string): the funds-critical sighash + sign dispatch
shared by the in-place spend signer (sign-tx-inputs, which then finalizes) and
the PSBT signer (which records the partial sigs). It never applies the m-of-n
completeness threshold — %finalize-input-signatures does — so the PSBT signer can
record the partial sigs it managed to produce. TAP-SIGHASH-TYPE is the taproot
sighash byte (0 = SIGHASH_DEFAULT; the spend path always passes 0, preserving its
historical DEFAULT-only taproot signing). *current-tx* / *current-spent-utxos*
must be bound by the caller."
  (let* ((spk (first prev)) (amount (second prev))
         (redeem (third prev)) (witness-script (fourth prev))
         (type (bl.val:script-type-name spk))
         (bl.interop:*current-input-index* i)
         (bl.interop:*precomputed-sighash* precomp))
    (macrolet ((fail (msg)
                 `(return-from compute-input-signatures (values nil ,msg))))
      (labels ((legacy-sig (subscript key)
                 (concatenate '(vector (unsigned-byte 8))
                              (bl.crypto:sign-ecdsa
                               key (bl.interop:compute-legacy-sighash
                                    tx i subscript sighash-byte))
                              (vector sighash-byte)))
               (bip143-sig (script-code key)
                 (concatenate '(vector (unsigned-byte 8))
                              (bl.crypto:sign-ecdsa
                               key (bl.interop:compute-bip143-sighash
                                    script-code amount sighash-byte))
                              (vector sighash-byte)))
               (p2wpkh-scriptcode (pkh)
                 (concatenate '(vector (unsigned-byte 8))
                              (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
               (legacy-multisig (subscript)
                 (multiple-value-bind (m nn pubkeys) (parse-multisig subscript)
                   (declare (ignore nn))
                   (values (%collect-multisig-sig-pairs
                            (bl.interop:compute-legacy-sighash
                             tx i subscript sighash-byte)
                            pubmap pubkeys m sighash-byte)
                           m)))
               (bip143-multisig (witscript)
                 (multiple-value-bind (m nn pubkeys) (parse-multisig witscript)
                   (declare (ignore nn))
                   (values (%collect-multisig-sig-pairs
                            (bl.interop:compute-bip143-sighash
                             witscript amount sighash-byte)
                            pubmap pubkeys m sighash-byte)
                           m)))
               (miniscript-stack (witscript)
                 ;; Core's P2WSH miniscript arm (sign.cpp:772-777): only after
                 ;; the legacy solver has failed, inferring the policy back out
                 ;; of the witnessScript with FromScript and demanding a
                 ;; COMPLETE satisfaction (Availability::YES). A partial one is
                 ;; not a smaller witness, it is an unspendable one.
                 ;;
                 ;; A malleable satisfaction is refused outright. MS-SATISFY's
                 ;; second value says a third party could rewrite the witness
                 ;; into another equally valid one, which changes the txid of a
                 ;; transaction already in flight.
                 (let ((node (bl.val:ms-from-script
                              witscript
                              :pkh-resolver (%wsh-pkh-resolver keymap))))
                   (when node
                     (multiple-value-bind (stack malleable)
                         (bl.val:ms-satisfy
                          node
                          (bl.val:make-ms-satisfier
                           :sign-fn
                           (lambda (pubkey)
                             (let ((sk (gethash pubkey pubmap)))
                               (when sk (bip143-sig witscript sk))))
                           ;; No preimage source exists on this path; a hash
                           ;; branch is simply unavailable rather than faked.
                           :check-older-fn
                           (lambda (v) (bl.val:ms-check-older tx i v))
                           :check-after-fn
                           (lambda (v) (bl.val:ms-check-after tx i v))))
                       (and stack (not malleable) stack))))))
        (cond
          ((string= type "pubkeyhash")
           (let ((entry (gethash (subseq spk 3 23) keymap)))
             (unless entry (fail "no key for P2PKH"))
             (values (%make-input-sig
                      :kind :p2pkh :needed 1
                      :ecdsa (list (cons (cdr entry) (legacy-sig spk (car entry))))))))
          ((string= type "witness_v0_keyhash")
           (let ((entry (gethash (subseq spk 2 22) keymap)))
             (cond
               ((null entry) (fail "no key for P2WPKH"))
               ((null amount) (fail "P2WPKH requires amount"))
               (t (values (%make-input-sig
                           :kind :p2wpkh :needed 1
                           :ecdsa (list (cons (cdr entry)
                                              (bip143-sig (p2wpkh-scriptcode (subseq spk 2 22))
                                                          (car entry))))))))))
          ((string= type "witness_v1_taproot")
           (let* ((output-key (subseq spk 2 34))
                  (sk (gethash output-key tr-keymap))
                  (leaves (and tr-scripts (gethash output-key tr-scripts))))
             (cond
               ((and (null sk) (null leaves)) (fail "no key for P2TR (key path)"))
               ((null spent-utxos)
                (fail "P2TR requires prevtx amounts for all inputs"))
               ;; Core tries the key path first and only then the script paths
               ;; (sign.cpp:558-608): a key-path spend is both cheaper and
               ;; smaller, and reveals nothing about the tree.
               (sk
                (let ((sighash (bl.interop:compute-bip341-sighash
                                amount tap-sighash-type nil nil)))
                  ;; No sighash is defined for SIGHASH_SINGLE at an input
                  ;; index with no matching output. Signing the
                  ;; omitted-field preimage would hand back a transaction
                  ;; Core rejects, so fail loudly instead.
                  (unless sighash
                    (fail "P2TR SIGHASH_SINGLE has no output at this input index"))
                  (let ((sig (%tap-sig (bl.crypto:taproot-tweak-private-key sk)
                                       sighash tap-sighash-type)))
                    (values (%make-input-sig :kind :p2tr :needed 1 :tap sig)))))
               (t
                (multiple-value-bind (stack leaf-sigs leaf)
                    (%tr-script-path-witness leaves amount tap-sighash-type pubmap)
                  (unless stack
                    (fail "no satisfiable script path for P2TR"))
                  (values (%make-input-sig :kind :p2tr-script :needed 1
                                           :stack stack
                                           :tap-script-sigs leaf-sigs
                                           :tap-leaf leaf)))))))
          ((string= type "scripthash")   ; P2SH (wrapped)
           (cond
             ((null redeem) (fail "P2SH requires redeemScript"))
             ((not (equalp (bl.crypto:hash160 redeem) (subseq spk 2 22)))
              (fail "redeemScript hash mismatch"))
             ;; P2SH-P2WPKH (nested segwit single-key)
             ((and (= (length redeem) 22) (= (aref redeem 0) #x00) (= (aref redeem 1) #x14))
              (let ((entry (gethash (subseq redeem 2 22) keymap)))
                (cond
                  ((null entry) (fail "no key for P2SH-P2WPKH"))
                  ((null amount) (fail "P2SH-P2WPKH requires amount"))
                  (t (values (%make-input-sig
                              :kind :p2sh-p2wpkh :needed 1 :redeem redeem
                              :ecdsa (list (cons (cdr entry)
                                                 (bip143-sig (p2wpkh-scriptcode (subseq redeem 2 22))
                                                             (car entry))))))))))
             ;; P2SH-P2WSH (nested segwit multisig; witnessScript = real script)
             ((and (= (length redeem) 34) (= (aref redeem 0) #x00) (= (aref redeem 1) #x20))
              (cond
                ((null witness-script) (fail "P2SH-P2WSH requires witnessScript"))
                ((not (equalp (bl.crypto:sha256 witness-script) (subseq redeem 2 34)))
                 (fail "witnessScript hash mismatch (P2SH-P2WSH)"))
                ;; Not multisig: Core's fallback is miniscript, not a refusal.
                ((not (parse-multisig witness-script))
                 (cond
                   ((null amount) (fail "P2WSH requires amount"))
                   (t (let ((stack (miniscript-stack witness-script)))
                        (if stack
                            (values (%make-input-sig
                                     :kind :p2sh-p2wsh-miniscript :redeem redeem
                                     :witness-script witness-script :stack stack))
                            (fail "witnessScript is not multisig"))))))
                ((null amount) (fail "P2WSH requires amount"))
                (t (multiple-value-bind (pairs m) (bip143-multisig witness-script)
                     (values (%make-input-sig :kind :p2sh-p2wsh :needed m :redeem redeem
                                              :witness-script witness-script :ecdsa pairs))))))
             ;; P2SH-multisig (legacy)
             ((parse-multisig redeem)
              (multiple-value-bind (pairs m) (legacy-multisig redeem)
                (values (%make-input-sig :kind :p2sh-multisig :needed m :redeem redeem
                                         :ecdsa pairs))))
             (t (fail "unsupported redeemScript type"))))
          ((string= type "witness_v0_scripthash")   ; native P2WSH
           (cond
             ((null witness-script) (fail "P2WSH requires witnessScript"))
             ((not (equalp (bl.crypto:sha256 witness-script) (subseq spk 2 34)))
              (fail "witnessScript hash mismatch"))
             ;; Not multisig: Core's fallback is miniscript, not a refusal.
             ((not (parse-multisig witness-script))
              (cond
                ((null amount) (fail "P2WSH requires amount"))
                (t (let ((stack (miniscript-stack witness-script)))
                     (if stack
                         (values (%make-input-sig
                                  :kind :p2wsh-miniscript
                                  :witness-script witness-script :stack stack))
                         (fail "witnessScript is not multisig"))))))
             ((null amount) (fail "P2WSH requires amount"))
             (t (multiple-value-bind (pairs m) (bip143-multisig witness-script)
                  (values (%make-input-sig :kind :p2wsh :needed m
                                           :witness-script witness-script :ecdsa pairs))))))
          ((parse-multisig spk)   ; bare multisig
           (multiple-value-bind (pairs m) (legacy-multisig spk)
             (values (%make-input-sig :kind :multisig :needed m :ecdsa pairs))))
          (t (fail (format nil "unsupported scriptPubKey type ~A" type))))))))

(defun %finalize-input-signatures (sig)
  "Re-assemble the input-sig SIG into (values scriptsig witness error),
byte-identical to the historical in-place signer's per-arm assembly. A NIL
scriptsig leaves the input's scriptSig untouched; a NIL witness sets no witness.
ERROR (a string) means the m-of-n threshold was not met — the same 'multisig
needs N sigs, have K' report the old signer produced; single-key kinds never
error here (a missing key already failed in compute-input-signatures)."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8))))
    (labels ((sigs () (mapcar #'cdr (input-sig-ecdsa sig)))
             (threshold-error (prefix)
               (when (< (length (input-sig-ecdsa sig)) (input-sig-needed sig))
                 (format nil "~Amultisig needs ~D sigs, have ~D"
                         prefix (input-sig-needed sig) (length (input-sig-ecdsa sig))))))
      (ecase (input-sig-kind sig)
        (:p2pkh (let ((s (first (input-sig-ecdsa sig))))
                  (values (concatenate '(vector (unsigned-byte 8))
                                       (bl.ser:script-push-data (cdr s)) (bl.ser:script-push-data (car s)))
                          nil nil)))
        (:p2wpkh (let ((s (first (input-sig-ecdsa sig))))
                   (values nil (list (cdr s) (car s)) nil)))
        (:p2tr (values nil (list (input-sig-tap sig)) nil))
        ;; A script-path spend: the satisfaction, then the leaf script, then
        ;; the control block (BIP341). %TR-SCRIPT-PATH-WITNESS already appended
        ;; the last two, so there is nothing to assemble here.
        (:p2tr-script (values nil (input-sig-stack sig) nil))
        (:p2sh-p2wpkh (let ((s (first (input-sig-ecdsa sig))))
                        (values (bl.ser:script-push-data (input-sig-redeem sig))
                                (list (cdr s) (car s)) nil)))
        (:p2wsh (let ((err (threshold-error "")))
                  (if err
                      (values nil nil err)
                      (values nil (concatenate 'list (list empty) (sigs)
                                               (list (input-sig-witness-script sig)))
                              nil))))
        (:p2sh-p2wsh (let ((err (threshold-error "")))
                       (if err
                           (values nil nil err)
                           (values (bl.ser:script-push-data (input-sig-redeem sig))
                                   (concatenate 'list (list empty) (sigs)
                                                (list (input-sig-witness-script sig)))
                                   nil))))
        ;; Miniscript: the satisfier already produced the whole stack, and there
        ;; is no CHECKMULTISIG dummy to prepend. Core appends the witnessScript
        ;; after the satisfaction unconditionally (sign.cpp:777).
        (:p2wsh-miniscript
         (values nil (append (input-sig-stack sig)
                             (list (input-sig-witness-script sig)))
                 nil))
        (:p2sh-p2wsh-miniscript
         (values (bl.ser:script-push-data (input-sig-redeem sig))
                 (append (input-sig-stack sig)
                         (list (input-sig-witness-script sig)))
                 nil))
        (:multisig (let ((err (threshold-error "")))
                     (if err
                         (values nil nil err)
                         (values (apply #'concatenate '(vector (unsigned-byte 8))
                                        (vector 0) (mapcar #'bl.ser:script-push-data (sigs)))
                                 nil nil))))
        (:p2sh-multisig (let ((err (threshold-error "P2SH-")))
                          (if err
                              (values nil nil err)
                              (values (apply #'concatenate '(vector (unsigned-byte 8))
                                             (vector 0)
                                             (append (mapcar #'bl.ser:script-push-data (sigs))
                                                     (list (bl.ser:script-push-data (input-sig-redeem sig)))))
                                      nil nil))))))))

(defun build-spent-utxos (inputs prevmap)
  "Vector of storage:utxo-entry for every input (the spent outputs, needed for the
BIP341/taproot sighash which commits to all input amounts + scriptPubKeys), or NIL
if any input lacks a prevout-with-amount."
  (let* ((n (length inputs))
         (vec (make-array n)))
    (dotimes (i n vec)
      (let* ((in (aref inputs i))
             (op (bl.ser:tx-in-previous-output in))
             (prev (gethash (cons (bl.ser:outpoint-hash op)
                                  (bl.ser:outpoint-index op))
                            prevmap)))
        (unless (and prev (second prev))
          (return-from build-spent-utxos nil))
        (setf (aref vec i)
              (bl.store:make-utxo-entry
               :value (second prev)
               :script-pubkey (coerce (first prev) '(simple-array (unsigned-byte 8) (*)))))))))

(defun sign-tx-inputs (tx prevmap keymap pubmap tr-keymap sighash-byte
                        &optional tr-scripts)
  "Sign every input of TX the key maps can satisfy, in place: scriptSigs are
set on TX's inputs, witness stacks installed on TX (existing witness entries
of inputs we do not touch are preserved). Shared by signrawtransactionwithkey
and the wallet signer (signrawtransactionwithwallet / CreateTransaction).
PREVMAP: (txid . vout) -> (script-pubkey amount-sats redeem witness-script);
KEYMAP: hash160(pubkey) -> (priv32 . pubkey); PUBMAP: pubkey -> priv32;
TR-KEYMAP: tweaked taproot output x-only key -> UNtweaked priv32.
Returns a list of (input-index . error-message), NIL when every input signed."
  (let* ((inputs (bl.ser:transaction-inputs tx))
         (n (length inputs))
         (witness (let ((existing (bl.ser:transaction-witness tx)))
                    (if (and existing (= (length existing) n))
                        (copy-seq existing)
                        (make-array n :initial-element '()))))
         (any-witness nil)
         ;; Which inputs this call actually produced signatures for — the
         ;; VerifyScript rail below checks those and leaves the rest alone.
         (signed (make-array n :initial-element nil))
         (errors '()))
    ;; Precompute is built once for the whole tx; pass spent-utxos (all
    ;; inputs' outputs) so the BIP341 amount/scriptPubKey commitments are
    ;; available for taproot inputs.
    (let* ((spent-utxos (build-spent-utxos inputs prevmap))
           (bl.interop:*current-tx* tx)
           (bl.interop:*current-spent-utxos* spent-utxos)
           (precomp (bl.interop:init-precomputed-sighash tx spent-utxos)))
      (dotimes (i n)
        (let* ((in (aref inputs i))
               (op (bl.ser:tx-in-previous-output in))
               (prev (gethash (cons (bl.ser:outpoint-hash op)
                                    (bl.ser:outpoint-index op))
                              prevmap)))
          ;; Compute the input's signature material then finalize it into
          ;; scriptSig/witness. Taproot signs SIGHASH_DEFAULT (tap-sighash 0),
          ;; the historical spend-path behavior.
          (if prev
              (multiple-value-bind (sig err)
                  (compute-input-signatures tx i prev keymap pubmap tr-keymap
                                             sighash-byte precomp spent-utxos
                                             #x00 tr-scripts)
                (if err
                    (push (cons i err) errors)
                    (multiple-value-bind (ss wit ferr) (%finalize-input-signatures sig)
                      (cond
                        (ferr (push (cons i ferr) errors))
                        (t (setf (aref signed i) t)
                           (when ss
                             (setf (bl.ser:tx-in-script-sig in) ss))
                           (when wit
                             (setf (aref witness i) wit)
                             (setf any-witness t)))))))
              (push (cons i "no prevtx scriptPubKey provided") errors))))
      (when (or any-witness (bl.ser:transaction-witness tx))
        (setf (bl.ser:transaction-witness tx) witness))
      ;; Core's ProduceSignature does not take "no error" for complete: it ENDS
      ;; by running VerifyScript over the scriptSig/witness it just built, with
      ;; a real signature checker, and reports complete only if that passes
      ;; (sign.cpp:799). Without it "complete" here means no more than "the
      ;; assembler raised nothing", and a witness whose ELEMENT ORDER is wrong
      ;; is well-formed, signed, and unspendable -- exactly the failure a
      ;; taproot script path can have, since its stack order is derived rather
      ;; than dictated by a fixed template.
      ;;
      ;; Inputs we did not touch are skipped: this rail is about what WE built,
      ;; and a partially-signed transaction must still come back with only the
      ;; inputs it could not sign reported.
      (when spent-utxos
        (dotimes (i n)
          (when (and (aref signed i) (not (assoc i errors)))
            (unless (handler-case
                        (let ((bl.interop:*script-flags*
                                bl.val:+standard-script-verify-flags+))
                          (bl.val:validate-input-script
                           tx i (aref spent-utxos i)))
                      (error () nil))
              (push (cons i "signing produced a script that does not verify")
                    errors))))))
    (nreverse errors)))

(define-rpc "signrawtransactionwithkey" (node params)
  "Sign inputs of a raw transaction with the supplied WIF private keys (Bitcoin
Core signrawtransactionwithkey). Supports P2PKH, P2WPKH, P2TR key-path, bare
multisig, P2SH(-P2WPKH / -multisig / -P2WSH), and P2WSH multisig inputs.
PARAMS: (hexstring privkeys [prevtxs] [sighashtype]). Each prevtxs entry is
{txid, vout, scriptPubKey, amount?, redeemScript?, witnessScript?} for an output
being spent (amount, in BTC, is required for any segwit input; P2TR also needs
amounts on ALL inputs; redeemScript for P2SH; witnessScript for P2WSH). P2TR signs
with SIGHASH_DEFAULT (64-byte signature). Returns {hex, complete, errors?}."
  (declare (ignore node))
  (let ((hexstring (first params))
        (wifs (positional-array (second params)))
        (prevtxs (positional-array (third params)))
        (sighash-byte (parse-sighash-type (fourth params))))
    (unless (stringp hexstring)
      (error 'rpc-error :code +rpc-deserialization-error+ :message "tx hex string required"))
    (unless (listp wifs)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "privkeys must be an array"))
    (let* ((tx (handler-case
                   (bl.ser:parse-tx-payload
                    (bl.crypto:hex-to-bytes hexstring))
                 (error () (error 'rpc-error :code +rpc-deserialization-error+
                                             :message "Transaction decode failed"))))
           (keymap (make-hash-table :test 'equalp))   ; hash160(pubkey) -> (privkey . pubkey)
           (pubmap (make-hash-table :test 'equalp))   ; full pubkey bytes -> privkey (multisig)
           (tr-keymap (make-hash-table :test 'equalp)) ; tweaked taproot output key (32B) -> privkey
           (prevmap (make-hash-table :test 'equalp))) ; (txid . vout) -> (spk amount-sats redeem witness-script)
      ;; Key map: derive each WIF's pubkey (per its compression flag) -> key-id.
      (dolist (wif wifs)
        (multiple-value-bind (sk compressed) (bl.crypto:wif-to-private-key wif)
          (unless sk
            (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid private key"))
          (let ((pub (bl.crypto:derive-public-key sk :compressed compressed)))
            (setf (gethash (bl.crypto:hash160 pub) keymap) (cons sk pub))
            (setf (gethash pub pubmap) sk))
          ;; Taproot key-path output key (P + H_TapTweak(P)*G) -> privkey.
          (let ((qx (bl.interop:compute-tweaked-pubkey
                     (bl.crypto:derive-xonly-pubkey sk))))
            (when qx (setf (gethash qx tr-keymap) sk)))))
      ;; Prevout map from prevtxs (carries optional redeemScript / witnessScript).
      ;; %OBJ-GET, not ASSOC: each element is a JSON object, which arrives as a
      ;; HASH-TABLE from a real client and an ALIST from these tests, and ASSOC
      ;; on a hash-table is a type error. That error escaped as
      ;; "-32603 Internal error: The value #<HASH-TABLE ...> is not of type
      ;; LIST" — signrawtransactionwithkey could not be called with prevtxs by
      ;; any real client (rpc_signrawtransactionwithkey.py:71 does exactly
      ;; that), while every unit test passed by handing it alists. Same defect
      ;; and same fix as createrawtransaction's inputs.
      (dolist (pt (and (listp prevtxs) prevtxs))
        (let ((txid (obj-get pt "txid"))
              (vout (obj-get pt "vout"))
              (spk-hex (obj-get pt "scriptPubKey"))
              (amount (obj-get pt "amount"))
              (redeem-hex (obj-get pt "redeemScript"))
              (ws-hex (obj-get pt "witnessScript")))
          (when (and (stringp txid) (valid-hex-hash-p txid) (integerp vout) (stringp spk-hex))
            (setf (gethash (cons (parse-hex-hash txid) vout) prevmap)
                  (list (bl.crypto:hex-to-bytes spk-hex)
                        (when (numberp amount) (round (* amount 100000000)))
                        (when (stringp redeem-hex) (bl.crypto:hex-to-bytes redeem-hex))
                        (when (stringp ws-hex) (bl.crypto:hex-to-bytes ws-hex)))))))
      ;; Sign whatever the supplied keys can satisfy (shared machinery).
      (let ((sign-errors (sign-tx-inputs tx prevmap keymap pubmap tr-keymap
                                          sighash-byte)))
        (let ((bytes (bl.ser:transaction-wire-bytes tx)))
          (append
           `(("hex" . ,(bl.crypto:bytes-to-hex bytes))
             ("complete" . ,(json-bool (null sign-errors))))
           (when sign-errors
             `(("errors" . ,(mapcar (lambda (e)
                                      `(("error" . ,(format nil "Input ~D: ~A"
                                                            (car e) (cdr e)))))
                                    sign-errors))))))))))

(define-rpc "createrawtransaction" (node ((inputs :array) outputs (locktime :or 0)))
  "Create an unsigned raw transaction."
  (let ((network (rpc-get-network node)))
    ;; Validate inputs
    (unless (and (listp inputs) (> (length inputs) 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid inputs"))
    ;; Validate locktime
    (unless (and (integerp locktime) (>= locktime 0))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "Invalid locktime"))
    ;; Build transaction inputs
    ;; %OBJ-GET, not ASSOC. A JSON object reaches us as a HASH-TABLE from the
    ;; decoder and as an ALIST from the unit tests, and ASSOC on a hash-table is
    ;; a type error — so createrawtransaction failed for every real JSON-RPC
    ;; client while the suite stayed green. The helper already existed, with a
    ;; docstring naming this exact split; it just had the wrong callers.
    (let ((tx-inputs
            (loop for inp in inputs
                  for txid-str = (obj-get inp "txid")
                  for vout = (obj-get inp "vout")
                  for sequence = (or (obj-get inp "sequence") #xffffffff)
                  do (unless (valid-hex-hash-p txid-str)
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid input txid"))
                     (unless (and (integerp vout) (>= vout 0))
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid input vout"))
                  collect (bl.ser:make-tx-in
                           :previous-output (bl.ser:make-outpoint
                                             :hash (parse-hex-hash txid-str)
                                             :index vout)
                           :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                           :sequence sequence)))
          ;; Core parses this argument in ONE place — NormalizeOutputs then
          ;; ParseOutputs (rawtransaction_util.cpp:74-99,101+) — and every RPC
          ;; taking outputs goes through it. %PARSE-OUTPUTS is that function
          ;; here, and createrawtransaction was the one caller not using it:
          ;; it had its own loop accepting the OBJECT form only. So Core's
          ;; ARRAY-of-single-key-objects form — the order-preserving spelling,
          ;; which rpc_createmultisig.py:117 and much of the suite use — was
          ;; answered "Invalid outputs format", as was every "data" OP_RETURN
          ;; output, and duplicate addresses went unnoticed. Sharing the
          ;; function is also what keeps the amount and address errors from
          ;; drifting into a second dialect.
          (tx-outputs
            (mapcar (lambda (r)
                      (bl.ser:make-tx-out
                       :value (recipient-amount r)
                       :script-pubkey (recipient-script r)))
                    (parse-outputs network outputs))))
      ;; Create transaction
      (let ((tx (bl.ser:make-transaction
                 :version 2
                 :inputs (coerce tx-inputs 'simple-vector)
                 :outputs (coerce tx-outputs 'simple-vector)
                 :lock-time locktime)))
        (bl.crypto:bytes-to-hex
         (bl.ser:transaction-wire-bytes tx))))))

;;; --- estimaterawfee (Core rpc/fees.cpp) and decodescript (rpc/rawtransaction.cpp) ---

(defun %raw-fee-bucket-json (bucket)
  "One EstimatorBucket as Core renders it (rpc/fees.cpp): the range endpoints
rounded to whole sat/kvB and the four counters to two decimals."
  (flet ((r2 (x) (/ (fround (* (float (or x 0) 1d0) 100d0)) 100d0)))
    `(("startrange" . ,(round (or (getf bucket :start) 0)))
      ("endrange" . ,(round (or (getf bucket :end) 0)))
      ("withintarget" . ,(r2 (getf bucket :within-target)))
      ("totalconfirmed" . ,(r2 (getf bucket :total-confirmed)))
      ("inmempool" . ,(r2 (getf bucket :in-mempool)))
      ("leftmempool" . ,(r2 (getf bucket :left-mempool))))))

(define-rpc "estimaterawfee" (node params)
  "The raw per-horizon fee estimates and the buckets behind them (Core
estimaterawfee, rpc/fees.cpp:97-190). PARAMS: (conf_target [threshold]).

Unlike estimatesmartfee this asks ONE horizon at ONE success threshold and
reports the evidence rather than the max of three estimates — which is what
makes it a debugging tool and why Core documents it as such. A horizon that
does not track CONF-TARGET is OMITTED, not reported as zero: absence and \"no
answer\" mean different things to whoever is reading this."
  (declare (ignore node))
  (let ((conf-target (first params))
        (threshold (if (second params) (second params) 0.95d0)))
    (unless (integerp conf-target)
      (error 'rpc-error :code +rpc-type-error+
                        :message "Expected type number for conf_target"))
    (let ((max-target (or (bl.mp:highest-target-tracked) 1008)))
      (unless (<= 1 conf-target max-target)
        (error 'rpc-error :code +rpc-invalid-parameter+
                          :message (format nil "Invalid conf_target, must be between 1 and ~D"
                                           max-target))))
    (unless (realp threshold)
      (error 'rpc-error :code +rpc-type-error+
                        :message "Expected type number for threshold"))
    (let ((threshold (float threshold 1d0)))
      (unless (<= 0 threshold 1)
        (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid threshold"))
      (let ((result '()))
        (dolist (horizon '((:short . "short") (:medium . "medium") (:long . "long")))
          (let ((max-confirms (bl.mp:horizon-max-confirms (car horizon))))
            (when (and max-confirms (<= conf-target max-confirms))
              (multiple-value-bind (rate buckets)
                  (bl.mp:bpe-estimate-raw-fee
                   conf-target threshold (car horizon))
                (when rate
                  (push
                   (cons (cdr horizon)
                         `(("feerate" . ,(/ (float rate 1d0) 100000000d0))
                           ,@(let ((pass (getf buckets :pass)))
                               (when pass `(("pass" . ,(%raw-fee-bucket-json pass)))))
                           ,@(let ((fail (getf buckets :fail)))
                               (when fail `(("fail" . ,(%raw-fee-bucket-json fail)))))
                           ,@(when (zerop rate)
                               ;; Core reports why there is no answer rather
                               ;; than an empty object.
                               `(("errors" . #("Insufficient data or no feerate found"))))))
                   result))))))
        (or (nreverse result) (make-hash-table :test 'equal))))))

(define-rpc "decodescript" (node (hex-str))
  "Decode a hex-encoded script."
  (let ((network (rpc-get-network node)))
    (unless (stringp hex-str)
      (error 'rpc-error :code +rpc-deserialization-error+
                        :message "Invalid script hex"))
    ;; Handle empty script
    (when (zerop (length hex-str))
      (return-from rpc-decodescript
        `(("asm" . "")
          ("type" . "nonstandard"))))
    (handler-case
        (let ((script (bl.crypto:hex-to-bytes hex-str)))
          (multiple-value-bind (type data)
              (bl.val:classify-script script)
            (let ((result `(("asm" . ,(bl.val:disassemble-script script))
                            ("type" . ,(bl.val:script-type-to-string type)))))
              ;; Add type-specific fields
              (case type
                (:multisig
                 ;; Bare multisig: one P2PKH address per key (Core's classic
                 ;; decodescript "addresses" array; classify-script gives :pubkeys).
                 (setf result (append result
                                      `(("reqSigs" . ,(getf data :m))
                                        ("addresses"
                                         . ,(mapcar
                                             (lambda (pk)
                                               (bl.crypto:encode-p2pkh-address
                                                (bl.crypto:hash160 pk) network))
                                             (getf data :pubkeys)))))))
                ((:pubkeyhash :scripthash)
                 (let* ((hash (getf data :hash))
                        (addr (if (eq type :pubkeyhash)
                                  (bl.crypto:encode-p2pkh-address hash network)
                                  (bl.crypto:encode-p2sh-address hash network))))
                   (setf result (append result `(("addresses" . (,addr)))))))
                ((:witness-v0-keyhash :witness-v0-scripthash :witness-v1-taproot)
                 (let* ((prog (getf data :witness-program))
                        (ver (getf data :witness-version))
                        (hrp (bl.crypto:segwit-hrp network))
                        (addr (bl.crypto:segwit-address-encode hrp ver prog)))
                   (setf result (append result `(("segwit" . (("address" . ,addr)))))))))
              ;; Add p2sh address (script wrapped in P2SH)
              (let* ((script-hash (bl.crypto:hash160 script))
                     (p2sh-addr (bl.crypto:encode-p2sh-address script-hash network)))
                (setf result (append result `(("p2sh" . ,p2sh-addr)))))
              result)))
      (error (e)
        (error 'rpc-error :code +rpc-deserialization-error+
                          :message (format nil "Script decode failed: ~A" e))))))
