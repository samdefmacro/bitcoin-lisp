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
Adds new outputs and removes spent outputs.
Returns a list of (txid index entry) for all spent UTXOs (undo data for reorgs)."
  (let ((transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block))
        (spent-utxos '()))
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
                          (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
                          ;; Capture the entry before removing (for undo)
                          (entry (get-utxo utxo-set prev-txid prev-index)))
                     (when entry
                       (push (list prev-txid prev-index entry) spent-utxos))
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
                                  :coinbase is-coinbase))))
    (nreverse spent-utxos)))

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

;;; UTXO Set Persistence

(defun write-uint32-le (stream value)
  "Write a 32-bit unsigned integer in little-endian format."
  (write-byte (logand value #xFF) stream)
  (write-byte (logand (ash value -8) #xFF) stream)
  (write-byte (logand (ash value -16) #xFF) stream)
  (write-byte (logand (ash value -24) #xFF) stream))

(defun read-uint32-le (stream)
  "Read a 32-bit unsigned integer in little-endian format."
  (logior (read-byte stream)
          (ash (read-byte stream) 8)
          (ash (read-byte stream) 16)
          (ash (read-byte stream) 24)))

(defun write-uint64-le (stream value)
  "Write a 64-bit unsigned integer in little-endian format."
  (loop for i from 0 below 8
        do (write-byte (logand (ash value (* -8 i)) #xFF) stream)))

(defun read-int64-le (stream)
  "Read a 64-bit signed integer in little-endian format."
  (let ((val 0))
    (loop for i from 0 below 8
          do (setf val (logior val (ash (read-byte stream) (* 8 i)))))
    ;; Sign extension
    (if (logbitp 63 val)
        (- val (expt 2 64))
        val)))

(defun save-utxo-set (utxo-set path)
  "Save the UTXO set to a binary file at PATH.
Each entry: 36-byte key, 8-byte value, 4-byte height, 1-byte coinbase, 4-byte script-len, N-byte script."
  (ensure-directories-exist path)
  (with-open-file (stream path
                          :direction :output
                          :if-exists :supersede
                          :element-type '(unsigned-byte 8))
    ;; Write entry count as 4 bytes
    (write-uint32-le stream (hash-table-count (utxo-set-entries utxo-set)))
    ;; Write each entry
    (maphash (lambda (key entry)
               ;; 36-byte key
               (write-sequence key stream)
               ;; 8-byte value (signed)
               (let ((val (utxo-entry-value entry)))
                 (write-uint64-le stream (if (< val 0) (+ val (expt 2 64)) val)))
               ;; 4-byte height
               (write-uint32-le stream (utxo-entry-height entry))
               ;; 1-byte coinbase flag
               (write-byte (if (utxo-entry-coinbase entry) 1 0) stream)
               ;; 4-byte script length + script bytes
               (let ((script (utxo-entry-script-pubkey entry)))
                 (write-uint32-le stream (length script))
                 (write-sequence script stream)))
             (utxo-set-entries utxo-set)))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun load-utxo-set (utxo-set path)
  "Load the UTXO set from a binary file at PATH.
Returns T if loaded, NIL if file does not exist."
  (unless (probe-file path)
    (return-from load-utxo-set nil))
  (with-open-file (stream path
                          :direction :input
                          :element-type '(unsigned-byte 8))
    (let ((count (read-uint32-le stream))
          (entries (utxo-set-entries utxo-set)))
      ;; Clear existing entries
      (clrhash entries)
      ;; Read each entry
      (dotimes (i count)
        (let ((key (make-array 36 :element-type '(unsigned-byte 8))))
          (read-sequence key stream)
          (let* ((value (read-int64-le stream))
                 (height (read-uint32-le stream))
                 (coinbase (= 1 (read-byte stream)))
                 (script-len (read-uint32-le stream))
                 (script (make-array script-len :element-type '(unsigned-byte 8))))
            (read-sequence script stream)
            (setf (gethash key entries)
                  (make-utxo-entry :value value
                                   :script-pubkey script
                                   :height height
                                   :coinbase coinbase)))))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun utxo-set-file-path (base-path)
  "Get the UTXO set file path from a base data directory."
  (merge-pathnames "utxoset.dat" (pathname base-path)))
