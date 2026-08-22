(in-package #:bitcoin-lisp.mining)

;;; Block construction + CPU mining
;;;
;;; Turns a block-template into a complete, mineable block: builds the coinbase
;;; (BIP34 height, payout, segwit commitment), computes the merkle root, and
;;; grinds the header nonce until the PoW target is met. On regtest the target is
;;; trivial, so a block is found almost immediately — this is how blocks are
;;; produced on demand for testing and the generatetoaddress RPC. None of this
;;; bypasses validation: the resulting block goes through the same connect-block
;;; consensus path as a network block.

(defun build-coinbase-transaction (height value &key script-pubkey
                                                     witness-commitment-script
                                                     (extranonce 0))
  "Build the coinbase for a block at HEIGHT paying VALUE to SCRIPT-PUBKEY. The
scriptSig is the BIP34 height push followed by a 4-byte EXTRANONCE (so it is
always >= 2 bytes). When WITNESS-COMMITMENT-SCRIPT is given, a zero-value output
carrying it is appended and the coinbase gets the BIP141 reserved witness value
(a single 32-byte zero item)."
  (let* ((bip34 (bitcoin-lisp.validation:encode-bip34-height height))
         (extra (let ((b (make-array 4 :element-type '(unsigned-byte 8))))
                  (dotimes (i 4) (setf (aref b i) (logand (ash extranonce (* -8 i)) #xff)))
                  b))
         (script-sig (concatenate '(vector (unsigned-byte 8)) bip34 extra))
         (in (bitcoin-lisp.serialization:make-tx-in
              :previous-output (bitcoin-lisp.serialization:make-outpoint
                                :hash (%zeros32) :index #xffffffff)
              :script-sig script-sig
              ;; Core node/miner.cpp:171: MAX_SEQUENCE_NONFINAL, so the
              ;; coinbase's nLockTime (below) is enforced — BIP54's coinbase
              ;; rule, which Core's templates already satisfy.
              :sequence #xfffffffe))
         (outputs (list (bitcoin-lisp.serialization:make-tx-out
                         :value value
                         :script-pubkey (or script-pubkey
                                            (make-array 0 :element-type '(unsigned-byte 8)))))))
    (when witness-commitment-script
      (setf outputs (append outputs
                            (list (bitcoin-lisp.serialization:make-tx-out
                                   :value 0
                                   :script-pubkey witness-commitment-script)))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (vector in)
     :outputs (coerce outputs 'simple-vector)
     ;; BIP141 reserved witness value (one 32-byte zero item).
     :witness (when witness-commitment-script
                (vector (list (bitcoin-lisp.validation:witness-reserved-value))))
     ;; Core node/miner.cpp:196: the coinbase commits to its height a second
     ;; way, nLockTime = height - 1 (BIP54), final because of the sequence.
     :lock-time (1- height))))

(defun assemble-full-block (chain-state mempool &key coinbase-script-pubkey block-time
                                                     utxo-set)
  "Build a complete (unmined) block extending CHAIN-STATE's tip: assemble a
template, prepend a coinbase paying the template's coinbase-value to
COINBASE-SCRIPT-PUBKEY (carrying the default witness commitment), set the merkle
root, and produce a header with nonce 0. Returns (values block template).

When UTXO-SET is supplied the assembled block is dry-run through
TEST-BLOCK-VALIDITY — CheckBlock + a non-mutating connect against the tip —
and a failure signals an ERROR, exactly as Bitcoin Core's CreateNewBlock
throws when TestBlockValidity rejects its own template (node/miner.cpp:
227-231). This is the server-side net that keeps a mempool bug from mining
a consensus-invalid block; every live template path (getblocktemplate,
generate*) passes UTXO-SET. NIL skips the check (unit tests exercising
assembly against synthetic chain states with no coins view)."
  (let* ((template (assemble-block-template chain-state mempool :block-time block-time))
         (coinbase (build-coinbase-transaction
                    (block-template-height template)
                    (block-template-coinbase-value template)
                    :script-pubkey coinbase-script-pubkey
                    :witness-commitment-script
                    (block-template-default-witness-commitment-script template)))
         (txs (cons coinbase
                    (mapcar #'bitcoin-lisp.mempool:mempool-entry-transaction
                            (block-template-transactions template))))
         (merkle (bitcoin-lisp.validation:compute-merkle-root
                  (mapcar #'bitcoin-lisp.serialization:transaction-hash txs)))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version (block-template-version template)
                  :prev-block (block-template-prev-hash template)
                  :merkle-root merkle
                  :timestamp (block-template-curtime template)
                  :bits (block-template-bits template)
                  :nonce 0))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header header :transactions txs)))
    (when utxo-set
      (multiple-value-bind (ok reason)
          (bitcoin-lisp.validation:test-block-validity block chain-state utxo-set)
        (unless ok
          (error "TestBlockValidity failed on assembled block at height ~D: ~A"
                 (block-template-height template) reason))))
    (values block template)))

(defun mine-block (block &key (max-tries 10000000))
  "Grind the header nonce until BLOCK meets its PoW target. Returns BLOCK (header
mutated) on success, or NIL if MAX-TRIES is exhausted. Trivial on regtest, where
nonce 0 almost always satisfies the target."
  (let ((header (bitcoin-lisp.serialization:bitcoin-block-header block)))
    (dotimes (nonce (min max-tries #x100000000) nil)
      ;; block-header-hash caches; clear it so each nonce is actually rehashed.
      (setf (bitcoin-lisp.serialization:block-header-nonce header) nonce
            (bitcoin-lisp.serialization:block-header-cached-hash header) nil)
      (when (bitcoin-lisp.validation:check-proof-of-work header)
        (return block)))))
