(in-package #:bitcoin-lisp.validation)

;;; Transaction Validation
;;;
;;; This module validates Bitcoin transactions according to consensus rules.
;;; Uses Coalton Satoshi type for amount calculations to ensure type safety.

;;;; Imports for typed operations
(defun wrap-satoshi (v) (bitcoin-lisp.coalton.interop:wrap-satoshi v))
(defun unwrap-satoshi (s) (bitcoin-lisp.coalton.interop:unwrap-satoshi s))
(defun satoshi+ (a b) (bitcoin-lisp.coalton.interop:satoshi+ a b))
(defun satoshi> (a b) (bitcoin-lisp.coalton.interop:satoshi> a b))

;;;; Constants
(defconstant +max-money+ 2100000000000000)  ; 21 million BTC in satoshis
(defconstant +coin+ 100000000)               ; 1 BTC in satoshis
(defconstant +max-block-size+ 1000000)       ; 1 MB
(defconstant +max-tx-size+ 100000)           ; Max transaction size
(defconstant +coinbase-maturity+ 100)        ; Blocks before coinbase spendable

;; Typed constant for max money
(defvar *max-money-satoshi* nil)
(defun max-money-satoshi ()
  "Return +max-money+ as a Satoshi type (lazy initialization)."
  (or *max-money-satoshi*
      (setf *max-money-satoshi* (wrap-satoshi +max-money+))))

;;;; Structure validation (context-free)

(defun validate-transaction-structure (tx)
  "Validate basic transaction structure without chain context.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
        (outputs (bitcoin-lisp.serialization:transaction-outputs tx)))

    ;; Must have at least one input
    (when (null inputs)
      (return-from validate-transaction-structure
        (values nil :no-inputs)))

    ;; Must have at least one output
    (when (null outputs)
      (return-from validate-transaction-structure
        (values nil :no-outputs)))

    ;; Check for duplicate inputs
    (let ((seen-outpoints (make-hash-table :test 'equalp)))
      (dolist (input inputs)
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (key (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                          (bitcoin-lisp.serialization:outpoint-index prevout))))
          (when (gethash key seen-outpoints)
            (return-from validate-transaction-structure
              (values nil :duplicate-inputs)))
          (setf (gethash key seen-outpoints) t))))

    ;; Validate outputs using typed Satoshi arithmetic
    (let ((total-output (wrap-satoshi 0)))
      (dolist (output outputs)
        (let ((value (bitcoin-lisp.serialization:tx-out-value output)))
          ;; Output value must be non-negative
          (when (minusp value)
            (return-from validate-transaction-structure
              (values nil :negative-output)))
          ;; Output value must not exceed max money
          (when (> value +max-money+)
            (return-from validate-transaction-structure
              (values nil :output-too-large)))
          ;; Use typed addition
          (setf total-output (satoshi+ total-output (wrap-satoshi value)))))
      ;; Total output must not exceed max money
      (when (satoshi> total-output (max-money-satoshi))
        (return-from validate-transaction-structure
          (values nil :total-output-too-large))))

    ;; Check transaction size
    (let ((serialized (bitcoin-lisp.serialization:serialize-transaction tx)))
      (when (> (length serialized) +max-tx-size+)
        (return-from validate-transaction-structure
          (values nil :tx-too-large))))

    (values t nil)))

;;;; Contextual validation (requires chain state)

(defun validate-transaction-contextual (tx utxo-set current-height &key is-coinbase)
  "Validate a transaction in the context of the current UTXO set.
Returns (VALUES T NIL FEE) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure.
FEE is returned as a Satoshi type."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
        (outputs (bitcoin-lisp.serialization:transaction-outputs tx))
        (total-input (wrap-satoshi 0))
        (total-output (wrap-satoshi 0)))

    ;; Skip input validation for coinbase
    (unless is-coinbase
      (dolist (input inputs)
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
               (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
               (utxo (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index)))

          ;; Input must reference an existing UTXO
          (unless utxo
            (return-from validate-transaction-contextual
              (values nil :missing-input nil)))

          ;; Check coinbase maturity
          (when (bitcoin-lisp.storage:utxo-entry-coinbase utxo)
            (let ((age (- current-height
                         (bitcoin-lisp.storage:utxo-entry-height utxo))))
              (when (< age +coinbase-maturity+)
                (return-from validate-transaction-contextual
                  (values nil :coinbase-not-mature nil)))))

          ;; Use typed addition for input sum
          (setf total-input
                (satoshi+ total-input
                          (wrap-satoshi (bitcoin-lisp.storage:utxo-entry-value utxo)))))))

    ;; Sum outputs with typed addition
    (dolist (output outputs)
      (setf total-output
            (satoshi+ total-output
                      (wrap-satoshi (bitcoin-lisp.serialization:tx-out-value output)))))

    ;; For non-coinbase, inputs must cover outputs
    (unless is-coinbase
      (when (satoshi> total-output total-input)
        (return-from validate-transaction-contextual
          (values nil :insufficient-funds nil))))

    ;; Return fee as Satoshi type
    (values t nil (bitcoin-lisp.coalton.interop:satoshi- total-input total-output))))

;;;; Script validation

(defun validate-transaction-scripts (tx utxo-set)
  "Validate all input scripts for a transaction.
Returns (VALUES T NIL) on success, (VALUES NIL INPUT-INDEX) on failure."
  (let ((inputs (bitcoin-lisp.serialization:transaction-inputs tx)))
    (loop for input in inputs
          for i from 0
          do (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                    (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
                    (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
                    (utxo (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index)))
               (when utxo
                 (let ((script-sig (bitcoin-lisp.serialization:tx-in-script-sig input))
                       (script-pubkey (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo)))
                   (unless (validate-script script-sig script-pubkey
                                            :tx tx :input-index i)
                     (return-from validate-transaction-scripts
                       (values nil i)))))))
    (values t nil)))
