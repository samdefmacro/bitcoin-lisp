(in-package #:bitcoin-lisp.serialization)

;;; Bitcoin protocol data structures
;;;
;;; This module defines the core data types used in the Bitcoin protocol:
;;; - Outpoint: Reference to a previous transaction output
;;; - TxIn: Transaction input
;;; - TxOut: Transaction output
;;; - Transaction: Complete transaction
;;; - BlockHeader: Block header (80 bytes)
;;; - Block: Complete block with transactions

;;;; Outpoint - reference to a previous transaction output

(defstruct outpoint
  "Reference to a transaction output.
HASH is the 32-byte transaction hash.
INDEX is the output index within that transaction."
  (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
        :type (simple-array (unsigned-byte 8) (32)))
  (index 0 :type (unsigned-byte 32)))

(defun read-outpoint (stream)
  "Read an outpoint from STREAM."
  (make-outpoint :hash (read-hash256 stream)
                 :index (read-uint32-le stream)))

(defun write-outpoint (stream outpoint)
  "Write an outpoint to STREAM."
  (write-hash256 stream (outpoint-hash outpoint))
  (write-uint32-le stream (outpoint-index outpoint)))

(defun null-outpoint-p (outpoint)
  "Check if OUTPOINT is null (references no previous output)."
  (and (every #'zerop (outpoint-hash outpoint))
       (= (outpoint-index outpoint) #xFFFFFFFF)))

;;;; TxIn - Transaction input

(defstruct tx-in
  "A transaction input.
PREVIOUS-OUTPUT: Outpoint referencing the output being spent.
SCRIPT-SIG: Unlocking script (signature).
SEQUENCE: Sequence number for replacement/locktime."
  (previous-output (make-outpoint) :type outpoint)
  (script-sig #() :type (simple-array (unsigned-byte 8) (*)))
  (sequence #xFFFFFFFF :type (unsigned-byte 32)))

(defun read-tx-in (stream)
  "Read a transaction input from STREAM."
  (make-tx-in :previous-output (read-outpoint stream)
              :script-sig (read-var-bytes stream)
              :sequence (read-uint32-le stream)))

(defun write-tx-in (stream tx-in)
  "Write a transaction input to STREAM."
  (write-outpoint stream (tx-in-previous-output tx-in))
  (write-var-bytes stream (tx-in-script-sig tx-in))
  (write-uint32-le stream (tx-in-sequence tx-in)))

(defun coinbase-input-p (tx-in)
  "Check if TX-IN is a coinbase input."
  (null-outpoint-p (tx-in-previous-output tx-in)))

;;;; TxOut - Transaction output

(defstruct tx-out
  "A transaction output.
VALUE: Amount in satoshis.
SCRIPT-PUBKEY: Locking script."
  (value 0 :type (signed-byte 64))
  (script-pubkey #() :type (simple-array (unsigned-byte 8) (*))))

(defun read-tx-out (stream)
  "Read a transaction output from STREAM."
  (make-tx-out :value (read-int64-le stream)
               :script-pubkey (read-var-bytes stream)))

(defun write-tx-out (stream tx-out)
  "Write a transaction output to STREAM."
  (write-int64-le stream (tx-out-value tx-out))
  (write-var-bytes stream (tx-out-script-pubkey tx-out)))

;;;; Transaction

(defstruct transaction
  "A Bitcoin transaction.
VERSION: Transaction version (currently 1 or 2).
INPUTS: List of transaction inputs.
OUTPUTS: List of transaction outputs.
LOCK-TIME: Block height or timestamp for time-locked transactions."
  (version 1 :type (signed-byte 32))
  (inputs '() :type list)
  (outputs '() :type list)
  (lock-time 0 :type (unsigned-byte 32))
  ;; Cached hash (computed lazily)
  (cached-hash nil))

(defun read-transaction (stream)
  "Read a transaction from STREAM."
  (let* ((version (read-int32-le stream))
         (input-count (read-compact-size stream))
         (inputs (loop repeat input-count collect (read-tx-in stream)))
         (output-count (read-compact-size stream))
         (outputs (loop repeat output-count collect (read-tx-out stream)))
         (lock-time (read-uint32-le stream)))
    (make-transaction :version version
                      :inputs inputs
                      :outputs outputs
                      :lock-time lock-time)))

(defun write-transaction (stream tx)
  "Write a transaction to STREAM."
  (write-int32-le stream (transaction-version tx))
  (write-compact-size stream (length (transaction-inputs tx)))
  (dolist (input (transaction-inputs tx))
    (write-tx-in stream input))
  (write-compact-size stream (length (transaction-outputs tx)))
  (dolist (output (transaction-outputs tx))
    (write-tx-out stream output))
  (write-uint32-le stream (transaction-lock-time tx)))

(defun serialize-transaction (tx)
  "Serialize transaction TX to a byte vector."
  (flexi-streams:with-output-to-sequence (stream)
    (write-transaction stream tx)))

(defun transaction-hash (tx)
  "Compute the transaction hash (txid).
This is the double-SHA256 of the serialized transaction."
  (or (transaction-cached-hash tx)
      (let ((hash (bitcoin-lisp.crypto:hash256 (serialize-transaction tx))))
        (setf (transaction-cached-hash tx) hash)
        hash)))

;;;; Block Header

(defstruct block-header
  "A Bitcoin block header (80 bytes).
VERSION: Block version.
PREV-BLOCK: Hash of the previous block.
MERKLE-ROOT: Merkle root of transactions.
TIMESTAMP: Block timestamp (Unix time).
BITS: Encoded difficulty target.
NONCE: Proof-of-work nonce."
  (version 1 :type (signed-byte 32))
  (prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
              :type (simple-array (unsigned-byte 8) (32)))
  (merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :type (simple-array (unsigned-byte 8) (32)))
  (timestamp 0 :type (unsigned-byte 32))
  (bits 0 :type (unsigned-byte 32))
  (nonce 0 :type (unsigned-byte 32))
  ;; Cached hash
  (cached-hash nil))

(defun read-block-header (stream)
  "Read a block header from STREAM."
  (make-block-header :version (read-int32-le stream)
                     :prev-block (read-hash256 stream)
                     :merkle-root (read-hash256 stream)
                     :timestamp (read-uint32-le stream)
                     :bits (read-uint32-le stream)
                     :nonce (read-uint32-le stream)))

(defun write-block-header (stream header)
  "Write a block header to STREAM."
  (write-int32-le stream (block-header-version header))
  (write-hash256 stream (block-header-prev-block header))
  (write-hash256 stream (block-header-merkle-root header))
  (write-uint32-le stream (block-header-timestamp header))
  (write-uint32-le stream (block-header-bits header))
  (write-uint32-le stream (block-header-nonce header)))

(defun serialize-block-header (header)
  "Serialize block header to a byte vector (80 bytes)."
  (flexi-streams:with-output-to-sequence (stream)
    (write-block-header stream header)))

(defun block-header-hash (header)
  "Compute the block hash from the header.
This is the double-SHA256 of the 80-byte header."
  (or (block-header-cached-hash header)
      (let ((hash (bitcoin-lisp.crypto:hash256 (serialize-block-header header))))
        (setf (block-header-cached-hash header) hash)
        hash)))

;;;; Block

(defstruct bitcoin-block
  "A complete Bitcoin block.
HEADER: The 80-byte block header.
TRANSACTIONS: List of transactions in the block."
  (header (make-block-header) :type block-header)
  (transactions '() :type list))

(defun read-bitcoin-block (stream)
  "Read a complete block from STREAM."
  (let* ((header (read-block-header stream))
         (tx-count (read-compact-size stream))
         (transactions (loop repeat tx-count collect (read-transaction stream))))
    (make-bitcoin-block :header header
                        :transactions transactions)))

(defun write-bitcoin-block (stream block)
  "Write a complete block to STREAM."
  (write-block-header stream (bitcoin-block-header block))
  (write-compact-size stream (length (bitcoin-block-transactions block)))
  (dolist (tx (bitcoin-block-transactions block))
    (write-transaction stream tx)))

;;;; Generic serialization interface

(defgeneric serialize (object)
  (:documentation "Serialize OBJECT to a byte vector."))

(defgeneric deserialize (type stream)
  (:documentation "Deserialize an object of TYPE from STREAM."))

(defmethod serialize ((tx transaction))
  (serialize-transaction tx))

(defmethod serialize ((header block-header))
  (serialize-block-header header))

(defmethod serialize ((block bitcoin-block))
  (flexi-streams:with-output-to-sequence (stream)
    (write-bitcoin-block stream block)))
