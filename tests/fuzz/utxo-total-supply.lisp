(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/utxo_total_supply.cpp at the pin: a regtest chain
;;;; (BIP34 at height 2) mined block by block while the fuzzer adds spends of
;;;; earlier outputs -- immature coinbases, provably unspendable outputs, the
;;;; same output twice in one transaction (CVE-2018-17144), a coinbase made a
;;;; duplicate of a later one (BIP30) -- and after every block the UTXO set's
;;;; total amount equals the subsidies of the blocks that connected: no block
;;;; prints money, and one that is refused changes nothing.
;;;;
;;;; Ours: a fresh regtest node per buffer (REGTEST-NODE-FIXTURE, the in-memory
;;;; UTXO set), blocks built from BUILD-COINBASE-TRANSACTION and submitted
;;;; through ACTIVATE-SUBMITTED-BLOCK, the total from UTXO-SET-TOTAL-AMOUNT.

(def-suite :fuzz-utxo-total-supply-tests :in :bitcoin-lisp-tests
  :description "Core fuzz utxo_total_supply.cpp over block connection and the UTXO set's total")

(in-suite :fuzz-utxo-total-supply-tests)

(defun %op-script (&rest ops)
  (coerce ops '(simple-array (unsigned-byte 8) (*))))

(defun %supply-block (node txs)
  "A block on NODE's tip holding TXS (coinbase first), with its witness
commitment and merkle root regenerated (Core RegenerateCommitments) and its
header mined."
  (let* ((cs (bl:node-chain-state node))
         (tip (bl.store:get-block-index-entry cs (bl.store:best-block-hash cs)))
         (wtxids (cons (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                       (mapcar #'bl.ser:transaction-wtxid (rest txs))))
         (commitment (bl.crypto:hash256
                      (concatenate '(simple-array (unsigned-byte 8) (*))
                                   (bl.val:compute-merkle-root wtxids)
                                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))))
         (coinbase (first txs))
         (coinbase (bl.ser:make-transaction
                    :version (bl.ser:transaction-version coinbase)
                    :inputs (bl.ser:transaction-inputs coinbase)
                    :outputs (vector (aref (bl.ser:transaction-outputs coinbase) 0)
                                     (bl.ser:make-tx-out :value 0 :script-pubkey
                                                         (bl.mining:build-witness-commitment-script commitment)))
                    :witness (vector (list (bl.val:witness-reserved-value)))
                    :lock-time 0))
         (txs (cons coinbase (rest txs)))
         (block (bl.ser:make-bitcoin-block
                 :header (bl.ser:make-block-header
                          :version #x20000000
                          :prev-block (bl.store:block-index-entry-hash tip)
                          :merkle-root (bl.val:compute-merkle-root (mapcar #'bl.ser:transaction-hash txs))
                          :timestamp (+ bl.ser:*mock-time* (bl.store:block-index-entry-height tip) 1)
                          :bits #x207fffff :nonce 0)
                 :transactions txs)))
    (bl.mining:mine-block block)))

(defun %supply-coinbase (height &optional script-sig)
  "Core's PrepareNextBlock coinbase: the template's, nLockTime 0, paying the
subsidy to OP_TRUE -- or with SCRIPT-SIG in place of the height push."
  (let ((cb (bl.mining:build-coinbase-transaction height (bl.val:calculate-block-subsidy height)
                                                  :script-pubkey (%op-script #x51))))
    (bl.ser:make-transaction
     :version 2
     :inputs (vector (bl.ser:make-tx-in
                      :previous-output (bl.ser:tx-in-previous-output (aref (bl.ser:transaction-inputs cb) 0))
                      :script-sig (or script-sig (bl.ser:tx-in-script-sig (aref (bl.ser:transaction-inputs cb) 0)))
                      :sequence #xfffffffe))
     :outputs (bl.ser:transaction-outputs cb)
     :lock-time 0)))

(defun %utxo-snapshot-of (node)
  (let ((view (bl:node-utxo-set node)))
    (list (bl.store:utxo-set-total-amount view) (bl.store:compute-utxo-set-hash view))))

(define-fuzz-target utxo-total-supply
    (buffer :core "utxo_total_supply.cpp:22-178" :iterations 12 :max-len 400)
  "Whatever spends a fuzzed chain's blocks carry, the UTXO set's total is the
sum of the subsidies of the blocks that connected, a refused block leaves the
UTXO set as it was, and the first block -- a coinbase whose scriptSig
duplicates a later one's -- connects."
  (let ((fdp (make-fuzzed-data-provider buffer))
        (suffix (format nil "fuzz-supply-~D-~D" (get-universal-time) (random 1000000000))))
    (with-network (:regtest)
      (let ((bl.ser:*mock-time* (consume-integral-in-range fdp 1296688602 2000000000))
            (bl.val:*test-activation-heights* (make-hash-table :test 'equal)))
        (setf (gethash "bip34" bl.val:*test-activation-heights*) 2)
        (unwind-protect
             (let* ((node (regtest-node-fixture suffix))
                    (circulation 0)
                    (txos '())
                    (dup-height (consume-integral-in-range fdp 0 300))
                    (dup-script (script-bytes (script-<<-opcode (script-<<-int64 (script-builder) dup-height) 0)))
                    (pending '()))
               (labels ((height () (bl.store:chain-state-best-height (bl:node-chain-state node)))
                        (store-outputs (tx)
                          (let ((txid (bl.ser:transaction-hash tx)))
                            (loop for out across (bl.ser:transaction-outputs tx) for i from 0
                                  do (push (list txid i out) txos))))
                        (random-txo () (pick-value-in-array fdp txos))
                        (spend-tx (inputs)
                          (bl.ser:make-transaction
                           :version 2 :lock-time 0
                           :inputs (coerce (mapcar (lambda (o) (bl.ser:make-tx-in
                                                                 :previous-output (bl.ser:make-outpoint :hash (first o) :index (second o))
                                                                 :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                                                 :sequence #xffffffff))
                                                   inputs)
                                           'simple-vector)
                           ;; Forward each coin with no fee.
                           :outputs (coerce (mapcar #'third inputs) 'simple-vector)))
                        (mine (coinbase)
                          (let* ((before (%utxo-snapshot-of node))
                                 (h (height))
                                 (block (%supply-block node (cons coinbase (mapcar #'spend-tx (reverse pending))))))
                            (bl.rpc:activate-submitted-block node block)
                            (let ((valid (> (height) h)))
                              (when valid
                                (incf circulation (bl.val:calculate-block-subsidy (height)))
                                (dolist (tx (bl.ser:bitcoin-block-transactions block)) (store-outputs tx)))
                              (let ((after (%utxo-snapshot-of node)))
                                (fuzz-assert (= (fuzz-sabotage (first after)) circulation)
                                             "the UTXO set holds ~D after ~D block~:P that pay ~D"
                                             (first after) (height) circulation)
                                (unless valid
                                  (fuzz-assert (equalp before after) "a refused block changed the UTXO set")))
                              (setf pending '())
                              valid))))
                 ;; Block 1: its coinbase's scriptSig is the one block DUP-HEIGHT's
                 ;; would have, so that later coinbase is a duplicate (BIP30).
                 (fuzz-assert (mine (%supply-coinbase 1 dup-script))
                              "block 1 (coinbase scriptSig ~A) did not connect" (bl.crypto:bytes-to-hex dup-script))
                 (limited-while ((plusp (remaining-bytes fdp)) 200)
                   (call-one-of fdp
                     ;; Another input-output pair on the last transaction.
                     (if pending
                         (push (random-txo) (first pending))
                         (push (list (random-txo)) pending))
                     ;; Another transaction.
                     (push (list (random-txo)) pending)
                     ;; Mine the block.
                     (mine (%supply-coinbase (1+ (height))))))))
          (clear-undo-cache)
          (uiop:delete-directory-tree (regtest-node-base-path suffix) :validate t :if-does-not-exist :ignore))))))
