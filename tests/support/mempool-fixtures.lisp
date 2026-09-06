(in-package #:bitcoin-lisp.test-support)

;;;; A funded UTXO set, mempool and chain state for package and relay tests

(defparameter +optrue-redeem+
  (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x51))
  "The redeemScript: OP_TRUE.")

(defun p2sh-optrue-script-pubkey ()
  "scriptPubKey for P2SH(OP_TRUE): OP_HASH160 <hash160(OP_TRUE)> OP_EQUAL."
  (let ((h (bl.crypto:hash160 +optrue-redeem+))
        (spk (make-array 23 :element-type '(unsigned-byte 8))))
    (setf (aref spk 0) #xa9)        ; OP_HASH160
    (setf (aref spk 1) #x14)        ; push 20 bytes
    (replace spk h :start1 2)
    (setf (aref spk 22) #x87)       ; OP_EQUAL
    spk))

(defun make-package-fixture (&key (fund-value 100000000) (fund-height 1) (current-height 200))
  "Return (values utxo-set mempool chain-state funding-txid). The funding UTXO is
a confirmed P2SH(OP_TRUE) output of FUND-VALUE that test parents spend."
  (let ((utxo-set (bl.store:make-utxo-set))
        (mempool (bl.mp:make-mempool))
        (chain-state (bl.store:make-chain-state :best-height current-height))
        (funding-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bl.store:add-utxo utxo-set funding-txid 0 fund-value
                                   (p2sh-optrue-script-pubkey) fund-height :coinbase nil)
    (values utxo-set mempool chain-state funding-txid)))

;;;; The block policy estimator: synthetic ids and a populated estimator
;;;; (Core CBlockPolicyEstimator). Shared by the estimator suite and the
;;;; fee-estimation tests in the mempool suite.

(defun bpe-test-id (a b c)
  "A distinct 32-byte txid from three small integers."
  (let ((v (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref v 0) a
          (aref v 1) (ldb (byte 8 0) b)
          (aref v 2) (ldb (byte 8 8) b)
          (aref v 3) (ldb (byte 8 0) c))
    v))

(defun bpe-simulate (&key (blocks 60) (per-block 40)
                        (fast-feerate 20000d0) (slow-feerate 800d0)
                        confirm-slow)
  "Run BLOCKS blocks. Each block, PER-BLOCK transactions at FAST-FEERATE enter
and confirm in the next block, and PER-BLOCK at SLOW-FEERATE enter. CONFIRM-SLOW
decides whether the cheap ones also confirm or sit unconfirmed forever."
  (let ((e (bl.mp:make-block-policy-estimator)))
    ;; The estimator only records a transaction whose entry height is its own
    ;; best seen height (Core's `Ignore txs if BlockPolicyEstimator is not in
    ;; sync with ActiveChain().Tip()'), so the fixture starts it AT the tip
    ;; the first pass enters transactions against. A live node is in that
    ;; state by construction; a synthetic one has to say so.
    (setf (bl.mp::block-policy-estimator-best-height e) 1)
    (loop for h from 1 to blocks
          do (let ((confirmed '()))
               (dotimes (i per-block)
                 (let ((txid (bpe-test-id 1 h i)))
                   (bl.mp::bpe-process-transaction e txid h fast-feerate)
                   (push txid confirmed)))
               (dotimes (i per-block)
                 (let ((txid (bpe-test-id 2 h i)))
                   (bl.mp::bpe-process-transaction e txid h slow-feerate)
                   (when confirm-slow
                     (push txid confirmed))))
               (bl.mp::bpe-process-block e (1+ h) confirmed)))
    e))

(defun bpe-populated-estimator (&key (blocks 40))
  (bpe-simulate :blocks blocks))
