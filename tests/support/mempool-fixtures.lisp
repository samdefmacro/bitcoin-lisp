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
