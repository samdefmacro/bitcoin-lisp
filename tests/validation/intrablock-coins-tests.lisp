(in-package #:bitcoin-lisp.tests)

;;; Intra-block coin overlay (GA8 S1-1 / S1-2).
;;;
;;; Bitcoin Core validates every transaction of a block against a coins view
;;; that UpdateCoins has already advanced over the block's earlier
;;; transactions: inputs spent, then outputs added (validation.cpp:1996-2008,
;;; called at :2597). Two consequences that our per-block overlay used to miss:
;;;
;;;   * a coin created earlier in the same block is IN the view, so a chained
;;;     spend's scripts are checked like any other (CheckInputScripts asserts
;;;     the coin is present, validation.cpp:2090); and
;;;   * a coin consumed earlier in the same block is OUT of the view, so a
;;;     second spender fails HaveInputs with bad-txns-inputs-missingorspent
;;;     (tx_verify.cpp:167-169) — our :missing-input.
;;;
;;; Every test here drives the real VALIDATE-BLOCK on regtest and carries the
;;; control that must still be rejected (or still accepted): the whole bug
;;; class is a check that silently does nothing.

(in-suite :intrablock-coins-tests)

(defparameter +ib-coin-value+ 100000000
  "Value of the confirmed funding coin every fixture block spends.")

(defparameter +ib-privkey+
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 17)
  "Test secret key for the signed (P2PKH / P2TR) fixtures.")

(defun %ib-bytes (&rest bytes-and-seqs)
  "Byte vector from a mix of integers and sequences."
  (coerce (loop for x in bytes-and-seqs
                if (integerp x) collect x
                else append (coerce x 'list))
          '(vector (unsigned-byte 8))))

(defun %ib-empty () (make-array 0 :element-type '(unsigned-byte 8)))

(defun %ib-push (bytes)
  "A single canonical push of BYTES (shorter than 76 bytes)."
  (%ib-bytes (length bytes) bytes))

(defun %ib-coin (&optional (fill 7))
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element fill))

(defun %ib-p2pkh-spk ()
  "P2PKH scriptPubKey for +IB-PRIVKEY+."
  (%ib-bytes #x76 #xa9 #x14
             (bl.crypto:hash160
              (bl.crypto:derive-public-key +ib-privkey+))
             #x88 #xac))

(defun %ib-p2tr-spk ()
  "P2TR scriptPubKey (key-path only) for +IB-PRIVKEY+."
  (%ib-bytes #x51 #x20
             (bl.crypto:derive-xonly-pubkey
              (bl.crypto:taproot-tweak-private-key +ib-privkey+))))

(defun %ib-tx (inputs outputs &key witness)
  "Transaction from INPUTS — a list of (txid index script-sig) — and OUTPUTS,
a list of (value script-pubkey). WITNESS is a vector of per-input stacks."
  (bl.ser:make-transaction
   :version 2
   :inputs (map 'vector
                (lambda (in)
                  (destructuring-bind (txid index script-sig) in
                    (bl.ser:make-tx-in
                     :previous-output (bl.ser:make-outpoint
                                       :hash txid :index index)
                     :script-sig script-sig
                     :sequence #xffffffff)))
                inputs)
   :outputs (map 'vector
                 (lambda (out)
                   (destructuring-bind (value spk) out
                     (bl.ser:make-tx-out
                      :value value :script-pubkey spk)))
                 outputs)
   :witness witness
   :lock-time 0))

(defun %ib-p2pkh-scriptsig (tx input-index &key corrupt)
  "scriptSig <sig> <pubkey> spending a P2PKH output at INPUT-INDEX of TX with
SIGHASH_ALL. With CORRUPT, one byte inside the DER r value is flipped: the
encoding stays canonical and low-S, so only the ECDSA check can reject it."
  (let* ((sighash (bl.interop::compute-legacy-sighash
                   tx input-index (%ib-p2pkh-spk) 1))
         (sig (%ib-bytes (bl.crypto:sign-ecdsa +ib-privkey+ sighash) 1)))
    (when corrupt
      (setf (aref sig 10) (logxor (aref sig 10) #xff)))
    (%ib-bytes (%ib-push sig)
               (%ib-push (bl.crypto:derive-public-key +ib-privkey+)))))

(defun %ib-taproot-witness (tx input-index spent-utxos &key corrupt)
  "BIP341 key-path witness (SIGHASH_DEFAULT) for INPUT-INDEX of TX. SPENT-UTXOS
is the utxo-entry vector for every input — the BIP341 sighash commits to all of
their amounts and scriptPubKeys, so it is exactly what a chained spend needs."
  (let* ((bl.interop::*current-tx* tx)
         (bl.interop::*current-spent-utxos* spent-utxos)
         (bl.interop::*current-input-index* input-index)
         (bl.interop::*precomputed-sighash*
           (bl.interop:init-precomputed-sighash tx spent-utxos))
         (sighash (bl.interop::compute-bip341-sighash
                   (bl.store:utxo-entry-value (aref spent-utxos input-index))
                   0 nil nil))
         (sig (bl.crypto:sign-schnorr
               (bl.crypto:taproot-tweak-private-key +ib-privkey+)
               sighash)))
    (when corrupt
      (setf (aref sig 10) (logxor (aref sig 10) #xff)))
    (list sig)))

(defun %ib-entry (value script-pubkey height)
  "A utxo-entry, as the block's intra-block overlay stores one."
  (bl.store::make-utxo-entry :value value
                                         :script-pubkey script-pubkey
                                         :height height
                                         :coinbase nil))

(defun %ib-env (suffix)
  "Regtest node at genesis with a fresh UTXO set holding one confirmed
P2SH(OP_TRUE) coin of +IB-COIN-VALUE+ at ((%ib-coin) . 0). Returns
(values chain-state utxo-set prev-hash bits now subsidy)."
  (let* ((node (regtest-node-fixture suffix))
         (cs (bl::node-chain-state node))
         (utxo (bl.store:make-utxo-set)))
    (setf (bl::node-utxo-set node) utxo)
    (bl.store:add-utxo utxo (%ib-coin) 0 +ib-coin-value+
                                   (p2sh-optrue-script-pubkey) 0 :coinbase nil)
    (values cs utxo
            (bl.store:best-block-hash cs)
            (bl.ser:block-header-bits
             (bl::make-genesis-header :regtest))
            (bl.ser:get-unix-time)
            (bl.val::calculate-block-subsidy 1))))

(defun %ib-block (txs prev bits timestamp cb-value)
  "A mined height-1 regtest block: coinbase (BIP34 height, BIP141 witness
commitment over TXS) followed by TXS."
  (let* ((wtxids (cons (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 0)
                       (mapcar #'bl.ser:transaction-wtxid txs)))
         (combined (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace combined (bl.val:compute-merkle-root wtxids) :start1 0)
    (let* ((coinbase (bl.mining:build-coinbase-transaction
                      1 cb-value
                      :script-pubkey (p2sh-optrue-script-pubkey)
                      :witness-commitment-script
                      (bl.mining:build-witness-commitment-script
                       (bl.crypto:hash256 combined))))
           (all (cons coinbase txs))
           (blk (bl.ser:make-bitcoin-block
                 :header (bl.ser:make-block-header
                          :version #x20000000
                          :prev-block prev
                          :merkle-root (bl.val:compute-merkle-root
                                        (mapcar #'bl.ser:transaction-hash
                                                all))
                          :timestamp timestamp
                          :bits bits
                          :nonce 0)
                 :transactions all)))
      (or (bl.mining:mine-block blk)
          (error "%ib-block: could not mine")))))

(defun %ib-validate (blk cs utxo now)
  "VALIDATE-BLOCK at height 1, returning (values valid error fee-integer)."
  (multiple-value-bind (valid error fees)
      (bl.val:validate-block blk cs utxo 1 now)
    (values valid error
            (and fees (bl.interop:unwrap-satoshi fees)))))

;;; ------------------------------------------------------------------
;;; S1-1: scripts of a chained (same-block) spend
;;; ------------------------------------------------------------------

(test intrablock-chained-bad-signature-rejected
  "A transaction spending an output created earlier in the SAME block must have
its scripts verified. Before the overlay was threaded into script validation,
COLLECT-SPENT-UTXOS returned NIL for the whole transaction and the loop skipped
every input, so this block was accepted with an invalid signature. Control: the
same P2PKH scriptSig against a CONFIRMED coin is rejected, proving the fixture's
signature really is invalid."
  (with-network (:regtest)
   (multiple-value-bind (cs utxo prev bits now subsidy) (%ib-env "ib-badsig")
     (let* ((p2pkh (%ib-p2pkh-spk))
            (confirmed (%ib-coin #xD1))
            ;; tx A: the confirmed funding coin -> a P2PKH output spent below.
            (tx-a (%ib-tx (list (list (%ib-coin) 0 (%p2sh-optrue-scriptsig)))
                          (list (list 90000000 p2pkh))))
            (a-txid (bl.ser:transaction-hash tx-a))
            (unsigned (%ib-tx (list (list a-txid 0 (%ib-empty)))
                              (list (list 80000000 (p2sh-optrue-script-pubkey)))))
            (tx-b (%ib-tx (list (list a-txid 0 (%ib-p2pkh-scriptsig unsigned 0 :corrupt t)))
                          (list (list 80000000 (p2sh-optrue-script-pubkey)))))
            (blk (%ib-block (list tx-a tx-b) prev bits now (+ subsidy 20000000))))
       (bl.store:add-utxo utxo confirmed 0 90000000 p2pkh 0 :coinbase nil)
       (multiple-value-bind (valid error) (%ib-validate blk cs utxo now)
         (is (null valid))
         (is (eq :script-failed error)))
       ;; CONTROL: identical shape, but the parent coin is confirmed.
       (let* ((unsigned-c (%ib-tx (list (list confirmed 0 (%ib-empty)))
                                  (list (list 80000000 (p2sh-optrue-script-pubkey)))))
              (tx-c (%ib-tx (list (list confirmed 0
                                        (%ib-p2pkh-scriptsig unsigned-c 0 :corrupt t)))
                            (list (list 80000000 (p2sh-optrue-script-pubkey)))))
              (blk-c (%ib-block (list tx-c) prev bits now (+ subsidy 10000000))))
         (multiple-value-bind (valid error) (%ib-validate blk-c cs utxo now)
           (is (null valid))
           (is (eq :script-failed error))))))))

(test intrablock-chained-valid-signature-accepted
  "The other half of the fix: an honestly signed chained spend must still be
accepted. Failing the transaction on a NIL spent-utxos vector without first
supplying the intra-block coins would reject every honest CPFP chain."
  (with-network (:regtest)
   (multiple-value-bind (cs utxo prev bits now subsidy) (%ib-env "ib-goodsig")
     (let* ((p2pkh (%ib-p2pkh-spk))
            (tx-a (%ib-tx (list (list (%ib-coin) 0 (%p2sh-optrue-scriptsig)))
                          (list (list 90000000 p2pkh))))
            (a-txid (bl.ser:transaction-hash tx-a))
            (unsigned (%ib-tx (list (list a-txid 0 (%ib-empty)))
                              (list (list 80000000 (p2sh-optrue-script-pubkey)))))
            (tx-b (%ib-tx (list (list a-txid 0 (%ib-p2pkh-scriptsig unsigned 0)))
                          (list (list 80000000 (p2sh-optrue-script-pubkey)))))
            (blk (%ib-block (list tx-a tx-b) prev bits now (+ subsidy 20000000))))
       (multiple-value-bind (valid error fees) (%ib-validate blk cs utxo now)
         (is (eq t valid))
         (is (null error))
         (is (= 20000000 fees)))))))

(test intrablock-mixed-input-confirmed-script-checked
  "The theft escalation: COLLECT-SPENT-UTXOS was all-or-nothing, so attaching one
throwaway same-block parent to a transaction suppressed the script checks on its
CONFIRMED inputs too — unsigned spending of arbitrary third-party UTXOs. Input 0
here is a confirmed coin with a bad signature, input 1 a same-block coin with a
good one. Control: the identical transaction with both signatures valid is
accepted, so the rejection is attributable to the bad one."
  (with-network (:regtest)
   (multiple-value-bind (cs utxo prev bits now subsidy) (%ib-env "ib-mixed")
     (let ((p2pkh (%ib-p2pkh-spk))
           (confirmed (%ib-coin #xD2)))
       (bl.store:add-utxo utxo confirmed 0 50000000 p2pkh 0 :coinbase nil)
       (flet ((build (corrupt-confirmed)
                (let* ((tx-a (%ib-tx (list (list (%ib-coin) 0 (%p2sh-optrue-scriptsig)))
                                     (list (list 90000000 p2pkh))))
                       (a-txid (bl.ser:transaction-hash tx-a))
                       (ins (list (list confirmed 0 (%ib-empty))
                                  (list a-txid 0 (%ib-empty))))
                       (outs (list (list 130000000 (p2sh-optrue-script-pubkey))))
                       (unsigned (%ib-tx ins outs))
                       (tx-b (%ib-tx
                              (list (list confirmed 0
                                          (%ib-p2pkh-scriptsig unsigned 0
                                                               :corrupt corrupt-confirmed))
                                    (list a-txid 0 (%ib-p2pkh-scriptsig unsigned 1)))
                              outs)))
                  (%ib-block (list tx-a tx-b) prev bits now (+ subsidy 20000000)))))
         (multiple-value-bind (valid error) (%ib-validate (build t) cs utxo now)
           (is (null valid))
           (is (eq :script-failed error)))
         ;; CONTROL: both inputs correctly signed.
         (multiple-value-bind (valid error) (%ib-validate (build nil) cs utxo now)
           (is (eq t valid))
           (is (null error))))))))

(test intrablock-chained-taproot-spend
  "A chained TAPROOT spend needs the complete spent-utxos vector: the BIP341
sighash commits to every input's amount and scriptPubKey, so an incomplete
vector cannot produce a verifiable signature (it was NIL for chained spends).
The honest spend must validate and a corrupted one must not."
  (with-network (:regtest)
   (multiple-value-bind (cs utxo prev bits now subsidy) (%ib-env "ib-taproot")
     (let* ((p2tr (%ib-p2tr-spk))
            (tx-a (%ib-tx (list (list (%ib-coin) 0 (%p2sh-optrue-scriptsig)))
                          (list (list 90000000 p2tr))))
            (a-txid (bl.ser:transaction-hash tx-a))
            (spent (vector (%ib-entry 90000000 p2tr 1)))
            (ins (list (list a-txid 0 (%ib-empty))))
            (outs (list (list 80000000 (p2sh-optrue-script-pubkey))))
            (unsigned (%ib-tx ins outs)))
       (flet ((spend (corrupt)
                (%ib-block
                 (list tx-a
                       (%ib-tx ins outs
                               :witness (vector (%ib-taproot-witness unsigned 0 spent
                                                                     :corrupt corrupt))))
                 prev bits now (+ subsidy 20000000))))
         (multiple-value-bind (valid error) (%ib-validate (spend nil) cs utxo now)
           (is (eq t valid))
           (is (null error)))
         (multiple-value-bind (valid error) (%ib-validate (spend t) cs utxo now)
           (is (null valid))
           (is (eq :script-failed error))))
       ;; The mechanism underneath: without the overlay the vector is NIL and
       ;; the BIP341 fields cannot be precomputed; with it they are present.
       (let ((extra (make-hash-table :test 'equalp))
             (inputs (bl.ser:transaction-inputs unsigned)))
         (setf (gethash (cons a-txid 0) extra) (aref spent 0))
         (is (null (bl.val::collect-spent-utxos inputs utxo)))
         (let ((collected (bl.val::collect-spent-utxos inputs utxo extra)))
           (is (equalp spent collected))
           (is (not (null (bl.interop::precomputed-sighash-data-sha-amounts
                           (bl.interop:init-precomputed-sighash
                            unsigned collected)))))))))))

;;; ------------------------------------------------------------------
;;; S1-2: an outpoint consumed earlier in the same block
;;; ------------------------------------------------------------------

(test intrablock-double-spend-of-confirmed-coin-rejected
  "Two transactions in one block spending the same confirmed prevout. Core spends
the coin out of its view in UpdateCoins, so the second one fails HaveInputs;
we now report the same condition as :missing-input. Control: either transaction
alone is accepted, so the fixture's inputs are genuinely spendable."
  (with-network (:regtest)
   (multiple-value-bind (cs utxo prev bits now subsidy) (%ib-env "ib-dspend")
     (let* ((tx-x (%pkg-tx (%ib-coin) 0 90000000))
            (tx-y (%pkg-tx (%ib-coin) 0 80000000)))
       (is (not (equalp (bl.ser:transaction-hash tx-x)
                        (bl.ser:transaction-hash tx-y))))
       (multiple-value-bind (valid error)
           (%ib-validate (%ib-block (list tx-x tx-y) prev bits now (+ subsidy 30000000))
                         cs utxo now)
         (is (null valid))
         (is (eq :missing-input error)))
       ;; CONTROL: one spender only.
       (multiple-value-bind (valid error fees)
           (%ib-validate (%ib-block (list tx-x) prev bits now (+ subsidy 10000000))
                         cs utxo now)
         (is (eq t valid))
         (is (null error))
         (is (= 10000000 fees)))))))

(test intrablock-double-spend-of-intrablock-output-rejected
  "The same defect one level down: an output CREATED earlier in the block could
also be spent twice, because the overlay was add-only. Control: the block
without the second spender is accepted."
  (with-network (:regtest)
   (multiple-value-bind (cs utxo prev bits now subsidy) (%ib-env "ib-dspend2")
     (let* ((tx-a (%pkg-tx (%ib-coin) 0 90000000))
            (a-txid (bl.ser:transaction-hash tx-a))
            (tx-b (%pkg-tx a-txid 0 80000000))
            (tx-c (%pkg-tx a-txid 0 70000000)))
       (multiple-value-bind (valid error)
           (%ib-validate (%ib-block (list tx-a tx-b tx-c) prev bits now (+ subsidy 30000000))
                         cs utxo now)
         (is (null valid))
         (is (eq :missing-input error)))
       ;; CONTROL: the honest chain of two.
       (multiple-value-bind (valid error fees)
           (%ib-validate (%ib-block (list tx-a tx-b) prev bits now (+ subsidy 20000000))
                         cs utxo now)
         (is (eq t valid))
         (is (null error))
         (is (= 20000000 fees)))))))

(test intrablock-double-spend-fee-not-double-counted
  "The double-spend counted its fee twice, raising the permitted coinbase — a
one-satoshi-larger coinbase was rejected, which pinned the inflated ceiling as
real. The block must now be refused whatever the coinbase claims, and a
legitimate single spend must still report exactly its own fee."
  (with-network (:regtest)
   (multiple-value-bind (cs utxo prev bits now subsidy) (%ib-env "ib-fees")
     (let ((tx-x (%pkg-tx (%ib-coin) 0 90000000))
           (tx-y (%pkg-tx (%ib-coin) 0 80000000)))
       ;; The formerly-accepted coinbase: subsidy + (10M from X) + (20M from Y),
       ;; against only 100M of real input.
       (dolist (claimed (list (+ subsidy 30000000) (+ subsidy 10000000) subsidy))
         (multiple-value-bind (valid error fees)
             (%ib-validate (%ib-block (list tx-x tx-y) prev bits now claimed)
                           cs utxo now)
           (is (null valid))
           (is (eq :missing-input error))
           (is (null fees))))
       ;; Unchanged for the honest block: fees are the single spend's 10M, and
       ;; one satoshi above subsidy + that is still too large.
       (multiple-value-bind (valid error fees)
           (%ib-validate (%ib-block (list tx-x) prev bits now (+ subsidy 10000000))
                         cs utxo now)
         (is (eq t valid))
         (is (null error))
         (is (= 10000000 fees)))
       (multiple-value-bind (valid error)
           (%ib-validate (%ib-block (list tx-x) prev bits now (+ subsidy 10000001))
                         cs utxo now)
         (is (null valid))
         (is (eq :coinbase-too-large error)))))))
