(in-package #:bitcoin-lisp.storage)

;;; UTXO Set Management
;;;
;;; The UTXO (Unspent Transaction Output) set tracks all outputs
;;; that have not yet been spent. This is essential for validating
;;; new transactions.

(defstruct utxo-entry
  "An entry in the UTXO set."
  (value 0 :type (signed-byte 64))
  (script-pubkey #() :type (simple-array (unsigned-byte 8) (*)))
  (height 0 :type (unsigned-byte 32))
  (coinbase nil :type boolean))

(defstruct utxo-set
  "In-memory UTXO set.
The set maps (txid, output-index) -> utxo-entry."
  (entries (make-hash-table :test 'equalp) :type hash-table)
  (dirty nil :type boolean))

(defun make-utxo-key (txid output-index)
  "Create a key for the UTXO set from TXID and OUTPUT-INDEX."
  (let ((key (make-array 36 :element-type '(unsigned-byte 8))))
    (replace key txid)
    (setf (aref key 32) (logand output-index #xFF))
    (setf (aref key 33) (logand (ash output-index -8) #xFF))
    (setf (aref key 34) (logand (ash output-index -16) #xFF))
    (setf (aref key 35) (logand (ash output-index -24) #xFF))
    key))

(defun add-utxo (utxo-set txid output-index value script-pubkey height &key coinbase)
  "Add a UTXO to the set."
  (let ((key (make-utxo-key txid output-index))
        (entry (make-utxo-entry :value value
                                :script-pubkey script-pubkey
                                :height height
                                :coinbase coinbase)))
    (setf (gethash key (utxo-set-entries utxo-set)) entry)
    (setf (utxo-set-dirty utxo-set) t)
    entry))

(defun remove-utxo (utxo-set txid output-index)
  "Remove a UTXO from the set. Returns the removed entry or NIL."
  (let ((key (make-utxo-key txid output-index)))
    (prog1
        (gethash key (utxo-set-entries utxo-set))
      (remhash key (utxo-set-entries utxo-set))
      (setf (utxo-set-dirty utxo-set) t))))

(defun get-utxo (utxo-set txid output-index)
  "Look up a UTXO in the set. Returns the entry or NIL."
  (let ((key (make-utxo-key txid output-index)))
    (gethash key (utxo-set-entries utxo-set))))

(defun utxo-exists-p (utxo-set txid output-index)
  "Check if a UTXO exists in the set."
  (not (null (get-utxo utxo-set txid output-index))))

(defun utxo-count (utxo-set)
  "Return the number of UTXOs in the set."
  (hash-table-count (utxo-set-entries utxo-set)))

(defun apply-block-to-utxo-set (utxo-set block height)
  "Apply a block's transactions to the UTXO set.
Adds new outputs and removes spent outputs."
  (let ((transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
    (loop for tx in transactions
          for tx-index from 0
          do
             (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
                   (is-coinbase (zerop tx-index)))
               ;; Remove spent UTXOs (skip for coinbase inputs)
               (unless is-coinbase
                 (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
                   (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                          (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
                          (prev-index (bitcoin-lisp.serialization:outpoint-index prevout)))
                     (remove-utxo utxo-set prev-txid prev-index))))
               ;; Add new UTXOs
               (loop for output in (bitcoin-lisp.serialization:transaction-outputs tx)
                     for output-index from 0
                     do (add-utxo utxo-set
                                  txid
                                  output-index
                                  (bitcoin-lisp.serialization:tx-out-value output)
                                  (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                                  height
                                  :coinbase is-coinbase))))))

(defun disconnect-block-from-utxo-set (utxo-set block previous-utxos)
  "Disconnect a block from the UTXO set (for reorgs).
PREVIOUS-UTXOS should be a list of (txid index entry) for restored UTXOs."
  ;; Remove outputs created by this block
  (dolist (tx (bitcoin-lisp.serialization:bitcoin-block-transactions block))
    (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
      (loop for output-index from 0
            below (length (bitcoin-lisp.serialization:transaction-outputs tx))
            do (remove-utxo utxo-set txid output-index))))
  ;; Restore previously spent UTXOs
  (dolist (prev previous-utxos)
    (destructuring-bind (txid index entry) prev
      (setf (gethash (make-utxo-key txid index) (utxo-set-entries utxo-set))
            entry))))
