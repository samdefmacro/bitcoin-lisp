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

(defun validate-transaction-contextual (tx utxo-set current-height
                                        &key is-coinbase pending-utxos)
  "Validate a transaction in the context of the current UTXO set.
PENDING-UTXOS is an optional hash table of (txid . index) -> utxo-entry
for outputs created by earlier transactions in the same block.
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
               (utxo (or (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index)
                         ;; Check intra-block pending UTXOs
                         (when pending-utxos
                           (gethash (cons prev-txid prev-index) pending-utxos)))))

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

;;;; Mempool acceptance validation

(defconstant +min-relay-fee-rate+ 1
  "Minimum relay fee rate in satoshis per virtual byte.")

(defconstant +max-standard-tx-size+ 100000
  "Maximum size of a standard transaction for relay (100KB).")

(defun standard-output-script-p (script-pubkey)
  "Check if SCRIPT-PUBKEY is a standard output script type.
Standard types: P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN (data carrier)."
  (let ((len (length script-pubkey)))
    (or
     ;; P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
     (and (= len 25)
          (= (aref script-pubkey 0) #x76)   ; OP_DUP
          (= (aref script-pubkey 1) #xa9)   ; OP_HASH160
          (= (aref script-pubkey 2) #x14)   ; push 20 bytes
          (= (aref script-pubkey 23) #x88)  ; OP_EQUALVERIFY
          (= (aref script-pubkey 24) #xac)) ; OP_CHECKSIG
     ;; P2SH: OP_HASH160 <20 bytes> OP_EQUAL
     (and (= len 23)
          (= (aref script-pubkey 0) #xa9)   ; OP_HASH160
          (= (aref script-pubkey 1) #x14)   ; push 20 bytes
          (= (aref script-pubkey 22) #x87)) ; OP_EQUAL
     ;; P2WPKH: OP_0 <20 bytes>
     (and (= len 22)
          (= (aref script-pubkey 0) #x00)   ; OP_0
          (= (aref script-pubkey 1) #x14))  ; push 20 bytes
     ;; P2WSH: OP_0 <32 bytes>
     (and (= len 34)
          (= (aref script-pubkey 0) #x00)   ; OP_0
          (= (aref script-pubkey 1) #x20))  ; push 32 bytes
     ;; P2TR: OP_1 <32 bytes>
     (and (= len 34)
          (= (aref script-pubkey 0) #x51)   ; OP_1
          (= (aref script-pubkey 1) #x20))  ; push 32 bytes
     ;; OP_RETURN data carrier (max 80 bytes data)
     (and (>= len 1)
          (<= len 83)
          (= (aref script-pubkey 0) #x6a))))) ; OP_RETURN

(defun validate-transaction-for-mempool (tx utxo-set mempool current-height)
  "Validate a transaction for mempool acceptance.
Performs consensus checks plus policy checks.
Returns (VALUES T NIL FEE) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure.
FEE is returned as an integer (satoshis)."
  ;; Must not be coinbase
  (when (and (= (length (bitcoin-lisp.serialization:transaction-inputs tx)) 1)
             (bitcoin-lisp.serialization:coinbase-input-p
              (first (bitcoin-lisp.serialization:transaction-inputs tx))))
    (return-from validate-transaction-for-mempool
      (values nil :coinbase-not-allowed nil)))

  ;; Structure validation (consensus)
  (multiple-value-bind (valid error)
      (validate-transaction-structure tx)
    (unless valid
      (return-from validate-transaction-for-mempool
        (values nil error nil))))

  ;; Policy: max standard transaction size
  (let ((serialized (bitcoin-lisp.serialization:serialize-transaction tx)))
    (when (> (length serialized) +max-standard-tx-size+)
      (return-from validate-transaction-for-mempool
        (values nil :tx-too-large nil))))

  ;; Policy: all outputs must be standard script types
  (dolist (output (bitcoin-lisp.serialization:transaction-outputs tx))
    (unless (standard-output-script-p
             (bitcoin-lisp.serialization:tx-out-script-pubkey output))
      (return-from validate-transaction-for-mempool
        (values nil :non-standard-output nil))))

  ;; Check for duplicate in mempool
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (when (bitcoin-lisp.mempool:mempool-has mempool txid)
      (return-from validate-transaction-for-mempool
        (values nil :already-in-mempool nil))))

  ;; Check for conflicts with existing mempool entries
  (let ((conflict (bitcoin-lisp.mempool:mempool-check-conflict mempool tx)))
    (when conflict
      (return-from validate-transaction-for-mempool
        (values nil :mempool-conflict nil))))

  ;; Check inputs: must reference UTXOs not already spent by mempool
  (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
           (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
           (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
           (utxo (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index)))
      (unless utxo
        (return-from validate-transaction-for-mempool
          (values nil :missing-input nil)))))

  ;; Contextual validation (consensus): UTXO existence, coinbase maturity, fee calculation
  (multiple-value-bind (valid error fee)
      (validate-transaction-contextual tx utxo-set current-height)
    (unless valid
      (return-from validate-transaction-for-mempool
        (values nil error nil)))

    ;; Convert typed fee to integer
    (let* ((fee-value (unwrap-satoshi fee))
           (tx-size (length (bitcoin-lisp.serialization:serialize-transaction tx)))
           (fee-rate (if (zerop tx-size) 0 (floor fee-value tx-size))))

      ;; Policy: minimum relay fee rate
      (when (< fee-rate +min-relay-fee-rate+)
        (return-from validate-transaction-for-mempool
          (values nil :insufficient-fee nil)))

      ;; Script validation (consensus)
      (multiple-value-bind (scripts-valid failed-input)
          (validate-transaction-scripts tx utxo-set :height current-height)
        (declare (ignore failed-input))
        (unless scripts-valid
          (return-from validate-transaction-for-mempool
            (values nil :script-failed nil))))

      (values t nil fee-value))))

;;;; Script validation

(defun validate-transaction-scripts (tx utxo-set &key (height 0))
  "Validate all input scripts for a transaction via Coalton interop.
Uses validate-input-script for each input (same path as block validation).
HEIGHT determines which script verification flags are active.
Returns (VALUES T NIL) on success, (VALUES NIL INPUT-INDEX) on failure."
  (let ((bitcoin-lisp.coalton.interop:*script-flags*
          (compute-script-flags-for-height height))
        (inputs (bitcoin-lisp.serialization:transaction-inputs tx)))
    (loop for input in inputs
          for input-idx from 0
          do (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                    (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
                    (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
                    (utxo (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index)))
               (when utxo
                 (unless (validate-input-script tx input-idx utxo)
                   (return-from validate-transaction-scripts
                     (values nil input-idx))))))
    (values t nil)))
