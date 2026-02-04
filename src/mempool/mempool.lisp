(in-package #:bitcoin-lisp.mempool)

;;; Mempool - In-memory Transaction Pool
;;;
;;; Stores validated unconfirmed transactions. Indexed by txid with
;;; secondary index on spent outpoints for conflict detection.
;;; Enforces size limits via lowest-fee-rate eviction.

;;;; Constants

(defconstant +default-max-mempool-bytes+ (* 300 1024 1024)
  "Default maximum mempool size in bytes (300 MB).")

(defconstant +default-min-relay-fee-rate+ 1
  "Default minimum relay fee rate in satoshis per virtual byte.")

;;;; Mempool entry

(defstruct mempool-entry
  "An entry in the mempool."
  (transaction nil :type bitcoin-lisp.serialization:transaction)
  (fee 0 :type (unsigned-byte 64))
  (size 0 :type (unsigned-byte 32))
  (entry-time 0 :type (unsigned-byte 64)))

(defun mempool-entry-fee-rate (entry)
  "Compute the fee rate (satoshis per byte) for a mempool entry."
  (let ((size (mempool-entry-size entry)))
    (if (zerop size)
        0
        (/ (mempool-entry-fee entry) size))))

;;;; Mempool

(defstruct mempool
  "In-memory transaction pool."
  ;; txid (byte vector) -> mempool-entry
  (entries (make-hash-table :test 'equalp) :type hash-table)
  ;; outpoint-key (byte vector) -> txid that spends it
  (spent-outpoints (make-hash-table :test 'equalp) :type hash-table)
  ;; Total serialized size of all transactions
  (total-size 0 :type integer)
  ;; Maximum allowed size in bytes
  (max-size +default-max-mempool-bytes+ :type integer)
  ;; Minimum relay fee rate
  (min-fee-rate +default-min-relay-fee-rate+ :type integer))

;;;; Outpoint key helper

(defun make-outpoint-key (txid index)
  "Create a key for the spent-outpoints table."
  (let ((key (make-array 36 :element-type '(unsigned-byte 8))))
    (replace key txid)
    (setf (aref key 32) (logand index #xFF))
    (setf (aref key 33) (logand (ash index -8) #xFF))
    (setf (aref key 34) (logand (ash index -16) #xFF))
    (setf (aref key 35) (logand (ash index -24) #xFF))
    key))

;;;; Core operations

(defun mempool-has (mempool txid)
  "Check if a transaction is in the mempool."
  (not (null (gethash txid (mempool-entries mempool)))))

(defun mempool-get (mempool txid)
  "Get a mempool entry by txid. Returns the entry or NIL."
  (gethash txid (mempool-entries mempool)))

(defun mempool-count (mempool)
  "Return the number of transactions in the mempool."
  (hash-table-count (mempool-entries mempool)))

(defun mempool-check-conflict (mempool tx)
  "Check if TX conflicts with any existing mempool entry.
Returns the txid of the conflicting transaction, or NIL if no conflict."
  (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
    (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
           (key (make-outpoint-key
                 (bitcoin-lisp.serialization:outpoint-hash prevout)
                 (bitcoin-lisp.serialization:outpoint-index prevout)))
           (spending-txid (gethash key (mempool-spent-outpoints mempool))))
      (when spending-txid
        (return-from mempool-check-conflict spending-txid))))
  nil)

(defun mempool-add (mempool txid entry)
  "Add a transaction to the mempool.
Returns :ok on success, or a keyword indicating the rejection reason."
  ;; Check for duplicate
  (when (mempool-has mempool txid)
    (return-from mempool-add :duplicate))

  ;; Check for conflicts
  (let ((conflict (mempool-check-conflict
                   mempool (mempool-entry-transaction entry))))
    (when conflict
      (return-from mempool-add :conflict)))

  ;; Evict if needed to make room
  (let ((tx-size (mempool-entry-size entry)))
    (when (> (+ (mempool-total-size mempool) tx-size)
             (mempool-max-size mempool))
      ;; Try to evict enough lowest-fee-rate entries
      (unless (mempool-evict-for-size mempool tx-size
                                       (mempool-entry-fee-rate entry))
        (return-from mempool-add :mempool-full))))

  ;; Add to entries table
  (setf (gethash txid (mempool-entries mempool)) entry)

  ;; Index spent outpoints
  (dolist (input (bitcoin-lisp.serialization:transaction-inputs
                  (mempool-entry-transaction entry)))
    (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
           (key (make-outpoint-key
                 (bitcoin-lisp.serialization:outpoint-hash prevout)
                 (bitcoin-lisp.serialization:outpoint-index prevout))))
      (setf (gethash key (mempool-spent-outpoints mempool)) txid)))

  ;; Update total size
  (incf (mempool-total-size mempool) (mempool-entry-size entry))

  :ok)

(defun mempool-remove (mempool txid)
  "Remove a transaction from the mempool by txid.
Returns the removed entry, or NIL if not found."
  (let ((entry (gethash txid (mempool-entries mempool))))
    (when entry
      ;; Remove spent outpoint entries
      (dolist (input (bitcoin-lisp.serialization:transaction-inputs
                      (mempool-entry-transaction entry)))
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (key (make-outpoint-key
                     (bitcoin-lisp.serialization:outpoint-hash prevout)
                     (bitcoin-lisp.serialization:outpoint-index prevout))))
          (remhash key (mempool-spent-outpoints mempool))))
      ;; Remove from entries
      (remhash txid (mempool-entries mempool))
      ;; Update total size
      (decf (mempool-total-size mempool) (mempool-entry-size entry))
      entry)))

;;;; Eviction

(defun mempool-evict-for-size (mempool needed-bytes new-entry-fee-rate)
  "Evict lowest fee-rate entries to free NEEDED-BYTES of space.
Only evicts entries with fee-rate lower than NEW-ENTRY-FEE-RATE.
Returns T if enough space was freed, NIL otherwise."
  (let ((to-free (- (+ (mempool-total-size mempool) needed-bytes)
                     (mempool-max-size mempool))))
    (when (<= to-free 0)
      (return-from mempool-evict-for-size t))

    ;; Collect entries sorted by fee-rate (ascending)
    (let ((sorted-entries '()))
      (maphash (lambda (txid entry)
                 (when (< (mempool-entry-fee-rate entry) new-entry-fee-rate)
                   (push (cons txid entry) sorted-entries)))
               (mempool-entries mempool))
      (setf sorted-entries
            (sort sorted-entries #'<
                  :key (lambda (pair) (mempool-entry-fee-rate (cdr pair)))))

      ;; Evict lowest fee-rate entries until enough space is freed
      (let ((freed 0))
        (dolist (pair sorted-entries)
          (when (>= freed to-free)
            (return-from mempool-evict-for-size t))
          (let ((evicted (mempool-remove mempool (car pair))))
            (when evicted
              (incf freed (mempool-entry-size evicted)))))
        (>= freed to-free)))))

;;;; Block interaction

(defun mempool-remove-for-block (mempool block)
  "Remove transactions confirmed in BLOCK from the mempool.
Also removes any transactions that conflict with block transactions."
  (let ((block-outpoints (make-hash-table :test 'equalp)))
    ;; Collect all outpoints spent by block transactions
    (dolist (tx (bitcoin-lisp.serialization:bitcoin-block-transactions block))
      (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (key (make-outpoint-key
                     (bitcoin-lisp.serialization:outpoint-hash prevout)
                     (bitcoin-lisp.serialization:outpoint-index prevout))))
          (setf (gethash key block-outpoints) t))))

    ;; Remove confirmed transactions
    (dolist (tx (bitcoin-lisp.serialization:bitcoin-block-transactions block))
      (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
        (mempool-remove mempool txid)))

    ;; Remove conflicting transactions (mempool txs that spend same outpoints as block txs)
    (let ((to-remove '()))
      (maphash (lambda (outpoint-key spending-txid)
                 (when (gethash outpoint-key block-outpoints)
                   (pushnew spending-txid to-remove :test #'equalp)))
               (mempool-spent-outpoints mempool))
      (dolist (txid to-remove)
        (mempool-remove mempool txid)))))

(defun mempool-get-transactions (mempool)
  "Return a list of all transactions in the mempool."
  (let ((txs '()))
    (maphash (lambda (txid entry)
               (declare (ignore txid))
               (push (mempool-entry-transaction entry) txs))
             (mempool-entries mempool))
    txs))

(defun mempool-for-each (mempool fn)
  "Call FN with (txid entry) for each transaction in the mempool.
   Used for building short ID maps in compact block reconstruction."
  (maphash fn (mempool-entries mempool)))
