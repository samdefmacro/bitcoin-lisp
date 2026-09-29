(in-package #:bitcoin-lisp.tests)

;;;; Core's transaction and block targets at the pin: fuzz/transaction.cpp,
;;;; decode_tx.cpp, tx_in.cpp, tx_out.cpp, block.cpp, block_header.cpp.

(def-suite :fuzz-transaction-tests :in :bitcoin-lisp-tests
  :description "Core fuzz transaction.cpp / block.cpp / decode_tx.cpp targets")

(in-suite :fuzz-transaction-tests)

(defun %wire-tx-corpus (fdp)
  (bl.ser:transaction-wire-bytes (consume-transaction fdp)))

;;; --- transaction.cpp ---------------------------------------------------------

(defun %standard-tx-p (tx permit-bare-multisig)
  (let ((bl:*permit-bare-multisig* permit-bare-multisig))
    (values (bl.val:is-standard-tx tx))))

(define-fuzz-target transaction
    (buffer :core "transaction.cpp:31-110" :iterations 6000 :max-len 500
            :corpus #'%wire-tx-corpus)
  "Any transaction that deserializes: CheckTransaction answers a verdict that
agrees with its reason (res == state.IsValid()) and gives the same one when
asked again; IsStandardTx without -permitbaremultisig implies it with; and
every other accessor transaction.cpp calls -- the hashes, sizes, weight
(stripped size x3 + total size, BIP141), sigop count, finality, RBF signal,
AreInputsStandard / IsWitnessStandard over an empty coins view, and TxToUniv
-- answers."
  (let ((tx (fuzz-deserialize (bl.ser:br-read-transaction (bl.ser:make-byte-reader-from buffer)))))
    (multiple-value-bind (ok reason) (bl.val:validate-transaction-structure tx)
      (fuzz-assert (eq (and ok t) (null reason)) "CheckTransaction: ~A with reason ~S" ok reason)
      (fuzz-assert (equal (list ok reason)
                          (fuzz-sabotage (multiple-value-list (bl.val:validate-transaction-structure tx))))
                   "CheckTransaction changed its mind about ~A" reason))
    (when (%standard-tx-p tx nil)
      (fuzz-assert (fuzz-sabotage (%standard-tx-p tx t))
                   "standard without -permitbaremultisig, not with it"))
    (bl.ser:transaction-hash tx)
    (bl.ser:transaction-wtxid tx)
    (bl.val:is-coinbase-tx tx)
    (bl.val:count-legacy-sigops tx)
    (bl.val:check-transaction-final tx 1024 1024)
    (bl.mp:tx-signals-rbf-p tx)
    (bl.val:are-inputs-standard-p tx (constantly nil))
    (bl.val:is-witness-standard-p tx (constantly nil))
    (let ((stripped (length (bl.ser:serialize-transaction tx)))
          (total (length (bl.ser:transaction-wire-bytes tx))))
      (fuzz-assert (= (fuzz-sabotage (bl.ser:transaction-weight tx)) (+ (* 3 stripped) total))
                   "weight ~D, stripped ~D total ~D" (bl.ser:transaction-weight tx) stripped total)
      (fuzz-assert (= (bl.ser:transaction-vsize tx) (ceiling (bl.ser:transaction-weight tx) 4))
                   "vsize ~D of weight ~D" (bl.ser:transaction-vsize tx) (bl.ser:transaction-weight tx))
      (when (< total 250000)
        (bl.rpc:tx-to-json tx :regtest)))))

;;; --- decode_tx.cpp -----------------------------------------------------------

(define-fuzz-target decode-tx
    (buffer :core "decode_tx.cpp:15-34" :iterations 8000 :max-len 400
            :corpus #'%wire-tx-corpus)
  "DecodeHexTx under each (try_no_witness, try_witness) pair: trying neither
never decodes; trying both decodes whenever either alone does; and a legacy
decode never yields a transaction with witness data."
  (let* ((hex (bl.crypto:bytes-to-hex buffer))
         (none (bl.rpc:decode-hex-tx hex :try-no-witness nil :try-witness nil))
         (witness (bl.rpc:decode-hex-tx hex :try-no-witness nil :try-witness t))
         (both (bl.rpc:decode-hex-tx hex :try-no-witness t :try-witness t))
         (legacy (bl.rpc:decode-hex-tx hex :try-no-witness t :try-witness nil)))
    (fuzz-assert (null none) "decoded with neither serialization")
    (when both
      (fuzz-assert (or legacy witness) "decoded both ways but by neither alone"))
    (when legacy
      (fuzz-assert (not (bl.ser:transaction-has-witness-p legacy)) "a legacy decode carries a witness")
      (fuzz-assert (fuzz-sabotage (and both t)) "a legacy decode that the both-ways decode refuses"))))

;;; --- tx_in.cpp / tx_out.cpp ---------------------------------------------------

(define-fuzz-target tx-in
    (buffer :core "tx_in.cpp:17-32" :iterations 6000 :max-len 200
            :corpus (lambda (fdp)
                      (let ((bb (bl.ser:make-byte-buf)))
                        (bl.ser:bb-write-tx-in bb (bl.ser:make-tx-in
                                                   :previous-output (bl.ser:make-outpoint
                                                                     :hash (consume-uint256 fdp)
                                                                     :index (consume-integral fdp :u32))
                                                   :script-sig (consume-script fdp)
                                                   :sequence (consume-sequence fdp)))
                        (bl.ser:bb-finish bb))))
  "A decoded CTxIn's outpoint is null -- the coinbase marker -- exactly when
Core's COutPoint::IsNull says: the zero hash and index 0xffffffff
(primitives/transaction.h:42)."
  (let* ((in (fuzz-deserialize (bl.ser:br-read-tx-in (bl.ser:make-byte-reader-from buffer))))
         (prevout (bl.ser:tx-in-previous-output in)))
    (fuzz-assert (eq (fuzz-sabotage (bl.ser:coinbase-input-p in))
                     (and (every #'zerop (bl.ser:outpoint-hash prevout))
                          (= (bl.ser:outpoint-index prevout) #xffffffff)))
                 "IsNull disagrees for ~A:~D" (bl.crypto:bytes-to-hex (bl.ser:outpoint-hash prevout))
                 (bl.ser:outpoint-index prevout))))

(define-fuzz-target tx-out
    (buffer :core "tx_out.cpp:17-35" :iterations 6000 :max-len 200
            :corpus (lambda (fdp)
                      (let ((bb (bl.ser:make-byte-buf)))
                        (bl.ser:bb-write-tx-out bb (bl.ser:make-tx-out :value (consume-money fdp)
                                                                       :script-pubkey (consume-script fdp :maybe-p2wsh t)))
                        (bl.ser:bb-finish bb))))
  "A decoded CTxOut has a dust threshold, and IsDust is exactly `value below
that threshold' (policy.cpp:66-69) for every output, spendable or not."
  (let* ((out (fuzz-deserialize (bl.ser:br-read-tx-out (bl.ser:make-byte-reader-from buffer))))
         (threshold (bl.val:dust-threshold (bl.ser:tx-out-script-pubkey out))))
    (fuzz-assert (eq (bl.val:output-is-dust-p out)
                     (fuzz-sabotage (< (bl.ser:tx-out-value out) threshold)))
                 "IsDust of ~D sat against a threshold of ~D" (bl.ser:tx-out-value out) threshold)))

;;; --- block.cpp / block_header.cpp --------------------------------------------

(defun %block-verdict (block &key skip-pow)
  "Core CheckBlock over BLOCK with no chain behind it: (values ok reason)."
  (bl.val:validate-block block (bl.store:make-chain-state) nil nil 4000000000
                         :context-free-only t :skip-pow skip-pow))

(defun %coinbase-leaning-block (fdp)
  "A block Core's CheckBlock could accept: a coinbase first (a null prevout,
a scriptSig of 2 to 100 bytes), then ConsumeTransaction transactions, the
merkle root they commit to, regtest's nBits and a nonce ground until the
header meets it -- so the checks past the proof of work are reached and the
PoW implication has passing blocks on its left-hand side."
  (with-network (:regtest)
    (let* ((coinbase (bl.ser:make-transaction
                      :version 2
                      :inputs (vector (bl.ser:make-tx-in
                                       :previous-output (bl.ser:make-outpoint :index #xffffffff)
                                       :script-sig (let ((v (consume-random-length-byte-vector fdp 100)))
                                                     (if (< (length v) 2) (%bytes 1 1) v))))
                      :outputs (vector (bl.ser:make-tx-out :value (consume-money fdp (* 50 100000000))
                                                           :script-pubkey (consume-script fdp)))))
           (txs (cons coinbase (loop repeat (consume-integral-in-range fdp 0 3)
                                     collect (consume-transaction fdp :max-num-in 3 :max-num-out 3))))
           (header (consume-block-header fdp)))
      (setf (bl.ser:block-header-bits header) #x207fffff
            (bl.ser:block-header-merkle-root header)
            (bl.val:compute-merkle-root (mapcar #'bl.ser:transaction-hash txs)))
      (loop for nonce from 0 below 64
            do (setf (bl.ser:block-header-nonce header) nonce
                     (bl.ser:block-header-cached-hash header) nil)
            until (bl.val:check-proof-of-work header))
      (bl.ser:serialize-witness-block (bl.ser:make-bitcoin-block :header header :transactions txs)))))

(define-fuzz-target block
    (buffer :core "block.cpp:33-78" :iterations 3000 :max-len 600
            :corpus (lambda (fdp)
                      (if (consume-bool fdp)
                          (%coinbase-leaning-block fdp)
                          (bl.ser:serialize-witness-block (consume-block fdp)))))
  "CheckBlock over any block that deserializes answers a verdict that agrees
with its reason, and checking proof of work can only turn a pass into a
failure, never the reverse (block.cpp:46-51; our CheckBlock always checks the
merkle root, Core's fCheckMerkleRoot has no counterpart). The block hash,
merkle roots, weight, witness-commitment lookup and mutation check answer."
  (with-network (:regtest)
    (let ((block (fuzz-deserialize (bl.ser:br-read-bitcoin-block (bl.ser:make-byte-reader-from buffer)))))
      (multiple-value-bind (ok reason) (%block-verdict block)
        (fuzz-assert (eq (and ok t) (null reason)) "CheckBlock: ~A with reason ~S" ok reason)
        (multiple-value-bind (ok-no-pow reason-no-pow) (%block-verdict block :skip-pow t)
          (fuzz-assert (eq (and ok-no-pow t) (null reason-no-pow))
                       "CheckBlock without PoW: ~A with reason ~S" ok-no-pow reason-no-pow)
          (when ok
            (fuzz-assert (fuzz-sabotage ok-no-pow) "valid with PoW checked, invalid without: ~S"
                         reason-no-pow))))
      (let ((txs (bl.ser:bitcoin-block-transactions block)))
        (bl.ser:block-header-hash (bl.ser:bitcoin-block-header block))
        (bl.val:compute-merkle-root (mapcar #'bl.ser:transaction-hash txs))
        (when txs
          (bl.val:compute-witness-merkle-root txs)
          (bl.val:find-witness-commitment (first txs)))
        (bl.val:calculate-block-weight txs)
        (bl.val:block-mutated-p block t)))))

(define-fuzz-target block-header
    (buffer :core "block_header.cpp:18-49" :iterations 6000 :max-len 200
            :corpus (lambda (fdp)
                      (fdp-random-length-bytes
                       (bl.ser:serialize-block-header (consume-block-header fdp)))))
  "A CBlockHeader from ConsumeDeserializable: its hash is not all ones, and it
is the double SHA256 of the header's own 80 bytes (the block built from it
has its hash). IsNull (nBits == 0) has no counterpart here."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (header (consume-deserializable
                  fdp (lambda (bytes) (bl.ser:br-read-block-header (bl.ser:make-byte-reader-from bytes))))))
    (when header
      (let ((hash (bl.ser:block-header-hash header)))
        (fuzz-assert (notevery (lambda (b) (= b #xff)) hash) "the header hashes to all ones")
        (fuzz-assert (equalp (fuzz-sabotage hash)
                             (bl.crypto:hash256 (bl.ser:serialize-block-header header)))
                     "the header's hash is not the hash of its bytes")))))
