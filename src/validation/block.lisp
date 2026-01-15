(in-package #:bitcoin-lisp.validation)

;;; Block Validation
;;;
;;; This module validates Bitcoin blocks according to consensus rules.
;;; Uses Coalton types for amounts (Satoshi) and heights (BlockHeight).

;;;; Imports for typed operations (reuse from transaction.lisp, add BlockHeight)
(defun wrap-block-height (h) (bitcoin-lisp.coalton.interop:wrap-block-height h))
(defun unwrap-block-height (bh) (bitcoin-lisp.coalton.interop:unwrap-block-height bh))

;;;; Constants

(defconstant +max-block-sigops+ 20000)
(defconstant +max-future-block-time+ 7200)  ; 2 hours in seconds

;;;; Proof of Work validation

(defun check-proof-of-work (header)
  "Verify that the block hash meets the difficulty target.
Returns T if valid, NIL if invalid."
  (let* ((bits (bitcoin-lisp.serialization:block-header-bits header))
         (target (bitcoin-lisp.storage:bits-to-target bits))
         (hash (bitcoin-lisp.serialization:block-header-hash header))
         ;; Convert hash to integer (little-endian)
         (hash-value (loop for i from 31 downto 0
                           for byte = (aref hash i)
                           sum (ash byte (* 8 (- 31 i))))))
    (<= hash-value target)))

;;;; Merkle root calculation

(defun hash-pair (a b)
  "Hash two 32-byte values together for Merkle tree."
  (let ((combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined a :start1 0)
    (replace combined b :start1 32)
    (bitcoin-lisp.crypto:hash256 combined)))

(defun compute-merkle-root (tx-hashes)
  "Compute the Merkle root from a list of transaction hashes."
  (when (null tx-hashes)
    (return-from compute-merkle-root
      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))

  (let ((level (mapcar #'copy-seq tx-hashes)))
    (loop while (> (length level) 1)
          do (let ((next-level '()))
               (loop while level
                     do (let* ((a (pop level))
                               (b (or (pop level) a)))  ; Duplicate last if odd
                          (push (hash-pair a b) next-level)))
               (setf level (nreverse next-level))))
    (first level)))

;;;; Block header validation

(defun validate-block-header (header chain-state current-time)
  "Validate a block header.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."
  (declare (ignore chain-state))

  ;; Check proof of work
  (unless (check-proof-of-work header)
    (return-from validate-block-header
      (values nil :bad-proof-of-work)))

  ;; Check timestamp not too far in future
  (let ((timestamp (bitcoin-lisp.serialization:block-header-timestamp header)))
    (when (> timestamp (+ current-time +max-future-block-time+))
      (return-from validate-block-header
        (values nil :time-too-new))))

  ;; Version check (allow versions 1-4 for now)
  (let ((version (bitcoin-lisp.serialization:block-header-version header)))
    (when (or (< version 1) (> version #x3FFFFFFF))
      (return-from validate-block-header
        (values nil :bad-version))))

  (values t nil))

;;;; Full block validation

(defun validate-block (block chain-state utxo-set current-height current-time)
  "Fully validate a block including all transactions.
Returns (VALUES T NIL FEES) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))

    ;; Validate header
    (multiple-value-bind (valid error)
        (validate-block-header header chain-state current-time)
      (unless valid
        (return-from validate-block (values nil error nil))))

    ;; Must have at least one transaction (coinbase)
    (when (null transactions)
      (return-from validate-block
        (values nil :no-transactions nil)))

    ;; First transaction must be coinbase
    (let ((first-tx (first transactions)))
      (unless (is-coinbase-tx first-tx)
        (return-from validate-block
          (values nil :first-tx-not-coinbase nil))))

    ;; Other transactions must not be coinbase
    (loop for tx in (rest transactions)
          when (is-coinbase-tx tx)
            do (return-from validate-block
                 (values nil :multiple-coinbase nil)))

    ;; Validate merkle root
    (let* ((tx-hashes (mapcar #'bitcoin-lisp.serialization:transaction-hash
                              transactions))
           (computed-root (compute-merkle-root tx-hashes))
           (header-root (bitcoin-lisp.serialization:block-header-merkle-root header)))
      (unless (equalp computed-root header-root)
        (return-from validate-block
          (values nil :bad-merkle-root nil))))

    ;; Validate each transaction and collect fees (using Satoshi type)
    (let ((total-fees (wrap-satoshi 0)))
      ;; Validate coinbase structure (skip input validation)
      (multiple-value-bind (valid error)
          (validate-transaction-structure (first transactions))
        (unless valid
          (return-from validate-block (values nil error nil))))

      ;; Validate other transactions
      (loop for tx in (rest transactions)
            do (multiple-value-bind (valid error)
                   (validate-transaction-structure tx)
                 (unless valid
                   (return-from validate-block (values nil error nil))))
               (multiple-value-bind (valid error fee)
                   (validate-transaction-contextual tx utxo-set current-height)
                 (unless valid
                   (return-from validate-block (values nil error nil)))
                 ;; fee is now a Satoshi type, use typed addition
                 (setf total-fees (satoshi+ total-fees fee))))

      ;; Validate coinbase value
      (let* ((coinbase-tx (first transactions))
             (coinbase-output-total
               (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs coinbase-tx)
                       :key #'bitcoin-lisp.serialization:tx-out-value))
             (block-subsidy (calculate-block-subsidy current-height))
             ;; Convert total-fees to integer for comparison
             (max-coinbase-value (+ block-subsidy (unwrap-satoshi total-fees))))
        (when (> coinbase-output-total max-coinbase-value)
          (return-from validate-block
            (values nil :coinbase-too-large nil))))

      ;; Return total-fees as Satoshi type
      (values t nil total-fees))))

;;;; Helper functions

(defun is-coinbase-tx (tx)
  "Check if TX is a coinbase transaction."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx)))
    (and (= (length inputs) 1)
         (bitcoin-lisp.serialization:coinbase-input-p (first inputs)))))

(defun calculate-block-subsidy (height)
  "Calculate the block subsidy for a given height.
Subsidy halves every 210,000 blocks."
  (let* ((halvings (floor height 210000))
         (subsidy (* 50 +coin+)))
    (if (>= halvings 64)
        0
        (ash subsidy (- halvings)))))

;;;; Block connection

(defun connect-block (block chain-state block-store utxo-set)
  "Connect a validated block to the chain.
Updates chain state and UTXO set."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (hash (bitcoin-lisp.serialization:block-header-hash header))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
         (prev-entry (bitcoin-lisp.storage:get-block-index-entry chain-state prev-hash))
         (new-height (if prev-entry
                         (1+ (bitcoin-lisp.storage:block-index-entry-height prev-entry))
                         0))
         (prev-work (if prev-entry
                        (bitcoin-lisp.storage:block-index-entry-chain-work prev-entry)
                        0))
         (chain-work (bitcoin-lisp.storage:calculate-chain-work
                      (bitcoin-lisp.serialization:block-header-bits header)
                      prev-work)))

    ;; Store block
    (bitcoin-lisp.storage:store-block block-store block)

    ;; Create index entry
    (let ((entry (bitcoin-lisp.storage:make-block-index-entry
                  :hash hash
                  :height new-height
                  :header header
                  :prev-entry prev-entry
                  :chain-work chain-work
                  :status :valid)))
      (bitcoin-lisp.storage:add-block-index-entry chain-state entry)

      ;; Update UTXO set
      (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block new-height)

      ;; Update chain tip if this is the new best
      (when (> chain-work
               (or (and (bitcoin-lisp.storage:best-block-hash chain-state)
                        (let ((best-entry (bitcoin-lisp.storage:get-block-index-entry
                                           chain-state
                                           (bitcoin-lisp.storage:best-block-hash chain-state))))
                          (and best-entry
                               (bitcoin-lisp.storage:block-index-entry-chain-work best-entry))))
                   0))
        (bitcoin-lisp.storage:update-chain-tip chain-state hash new-height))

      entry)))
