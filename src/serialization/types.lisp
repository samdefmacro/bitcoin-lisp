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
LOCK-TIME: Block height or timestamp for time-locked transactions.
WITNESS: List of witness stacks, one per input. Each stack is a list of
  byte vectors. NIL means no witness data (legacy transaction)."
  (version 1 :type (signed-byte 32))
  (inputs '() :type list)
  (outputs '() :type list)
  (lock-time 0 :type (unsigned-byte 32))
  (witness nil :type list)
  ;; Cached hash (computed lazily)
  (cached-hash nil))

(defun transaction-has-witness-p (tx)
  "Check if TX has witness data."
  (and (transaction-witness tx)
       (some (lambda (stack) (and stack (not (null stack))))
             (transaction-witness tx))))

(defun read-witness-stack (stream)
  "Read a single witness stack (for one input) from STREAM.
Returns a list of byte vectors."
  (let ((item-count (read-compact-size stream)))
    (loop repeat item-count
          collect (read-var-bytes stream))))

(defun write-witness-stack (stream stack)
  "Write a single witness stack (list of byte vectors) to STREAM."
  (write-compact-size stream (length stack))
  (dolist (item stack)
    (write-var-bytes stream item)))

(defun read-transaction (stream)
  "Read a transaction from STREAM.
Auto-detects BIP 144 witness format by checking for marker byte 0x00
where the input count would normally be."
  (let* ((version (read-int32-le stream))
         (marker (read-uint8 stream)))
    (if (zerop marker)
        ;; Possible witness format: marker=0x00, check flag
        (let ((flag (read-uint8 stream)))
          (unless (= flag 1)
            (error "Invalid witness flag byte: ~D" flag))
          ;; Witness format: inputs, outputs, witness stacks, lock-time
          (let* ((input-count (read-compact-size stream))
                 (inputs (loop repeat input-count collect (read-tx-in stream)))
                 (output-count (read-compact-size stream))
                 (outputs (loop repeat output-count collect (read-tx-out stream)))
                 (witness (loop repeat input-count
                                collect (read-witness-stack stream)))
                 (lock-time (read-uint32-le stream)))
            (make-transaction :version version
                              :inputs inputs
                              :outputs outputs
                              :lock-time lock-time
                              :witness witness)))
        ;; Legacy format: marker was actually the first byte of input-count
        ;; Re-parse input count using marker as the compact-size value
        (let* ((input-count (decode-compact-size-from-first-byte marker stream))
               (inputs (loop repeat input-count collect (read-tx-in stream)))
               (output-count (read-compact-size stream))
               (outputs (loop repeat output-count collect (read-tx-out stream)))
               (lock-time (read-uint32-le stream)))
          (make-transaction :version version
                            :inputs inputs
                            :outputs outputs
                            :lock-time lock-time)))))

(defun decode-compact-size-from-first-byte (first-byte stream)
  "Decode a CompactSize integer given that FIRST-BYTE has already been read."
  (cond
    ((< first-byte 253) first-byte)
    ((= first-byte 253) (read-uint16-le stream))
    ((= first-byte 254) (read-uint32-le stream))
    (t (read-uint64-le stream))))

(defun write-transaction (stream tx)
  "Write a transaction to STREAM in legacy format (no witness).
Used for txid computation."
  (write-int32-le stream (transaction-version tx))
  (write-compact-size stream (length (transaction-inputs tx)))
  (dolist (input (transaction-inputs tx))
    (write-tx-in stream input))
  (write-compact-size stream (length (transaction-outputs tx)))
  (dolist (output (transaction-outputs tx))
    (write-tx-out stream output))
  (write-uint32-le stream (transaction-lock-time tx)))

(defun write-witness-transaction (stream tx)
  "Write a transaction to STREAM in BIP 144 witness format."
  (write-int32-le stream (transaction-version tx))
  ;; Marker and flag
  (write-uint8 stream #x00)
  (write-uint8 stream #x01)
  ;; Inputs
  (write-compact-size stream (length (transaction-inputs tx)))
  (dolist (input (transaction-inputs tx))
    (write-tx-in stream input))
  ;; Outputs
  (write-compact-size stream (length (transaction-outputs tx)))
  (dolist (output (transaction-outputs tx))
    (write-tx-out stream output))
  ;; Witness stacks
  (let ((witness (transaction-witness tx)))
    (loop for i below (length (transaction-inputs tx))
          for stack = (if (and witness (< i (length witness)))
                          (nth i witness)
                          '())
          do (write-witness-stack stream stack)))
  ;; Lock time
  (write-uint32-le stream (transaction-lock-time tx)))

(defun serialize-transaction (tx)
  "Serialize transaction TX to a byte vector in legacy format (for txid)."
  (flexi-streams:with-output-to-sequence (stream)
    (write-transaction stream tx)))

(defun serialize-witness-transaction (tx)
  "Serialize transaction TX to a byte vector in BIP 144 witness format."
  (flexi-streams:with-output-to-sequence (stream)
    (write-witness-transaction stream tx)))

(defun transaction-hash (tx)
  "Compute the transaction hash (txid).
This is the double-SHA256 of the legacy serialized transaction (no witness)."
  (or (transaction-cached-hash tx)
      (let ((hash (bitcoin-lisp.crypto:hash256 (serialize-transaction tx))))
        (setf (transaction-cached-hash tx) hash)
        hash)))

(defun transaction-wtxid (tx)
  "Compute the witness transaction ID (wtxid).
For transactions with witness data, this is the double-SHA256 of the
witness-serialized transaction. For coinbase transactions, returns 32 zero bytes.
For legacy transactions without witness, wtxid equals txid."
  (cond
    ;; Coinbase: wtxid is all zeros
    ((and (transaction-inputs tx)
          (coinbase-input-p (first (transaction-inputs tx))))
     (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
    ;; Has witness: hash the witness serialization
    ((transaction-has-witness-p tx)
     (bitcoin-lisp.crypto:hash256 (serialize-witness-transaction tx)))
    ;; No witness: wtxid = txid
    (t (transaction-hash tx))))

(defun transaction-vsize (tx)
  "Calculate the virtual size (vsize) of a transaction in vbytes.
For SegWit transactions: vsize = (3 * base_size + total_size) / 4 (rounded up).
For legacy transactions: vsize = total_size.
This is the metric used for fee rate calculation."
  (if (transaction-has-witness-p tx)
      (let* ((base-size (length (serialize-transaction tx)))      ; Without witness
             (total-size (length (serialize-witness-transaction tx)))) ; With witness
        (ceiling (+ (* 3 base-size) total-size) 4))
      (length (serialize-transaction tx))))

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
