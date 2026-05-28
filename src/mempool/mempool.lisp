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

(defconstant +default-ancestor-limit+ 25
  "Max number of in-mempool ancestors (incl. self) for a tx (Bitcoin Core
DEFAULT_ANCESTOR_LIMIT).")

(defconstant +default-descendant-limit+ 25
  "Max number of in-mempool descendants (incl. self) for a tx (Bitcoin Core
DEFAULT_DESCENDANT_LIMIT).")

(defconstant +default-ancestor-size-limit+ 101000
  "Max total vsize of a tx + its ancestors, in vbytes (Core 101 kvB).")

(defconstant +default-descendant-size-limit+ 101000
  "Max total vsize of a tx + its descendants, in vbytes (Core 101 kvB).")

;;;; Mempool entry

(defstruct mempool-entry
  "An entry in the mempool."
  (transaction nil :type bitcoin-lisp.serialization:transaction)
  (fee 0 :type (unsigned-byte 64))
  ;; Serialized (witness) byte length — used for the byte-based mempool size cap.
  (size 0 :type (unsigned-byte 32))
  ;; BIP141 virtual size — the basis for fee-rate (Core computes fee-rate on vsize).
  (vsize 0 :type (unsigned-byte 32))
  ;; Witness txid (BIP339); 32 bytes once populated.
  (wtxid nil :type (or null (simple-array (unsigned-byte 8) (32))))
  ;; Weighted sigop cost (populated at acceptance once inputs are known).
  (sigops 0 :type (unsigned-byte 32))
  ;; Chain height at the time of acceptance.
  (height 0 :type (unsigned-byte 32))
  (entry-time 0 :type (unsigned-byte 64))
  ;; In-mempool dependency links (txid -> t). Ancestor/descendant aggregates
  ;; are derived on demand by walking these (bounded by the 25/25 limits), so
  ;; there are no cached totals to drift out of sync.
  (parents (make-hash-table :test 'equalp) :type hash-table)
  (children (make-hash-table :test 'equalp) :type hash-table))

(defun make-entry-from-tx (tx fee height &key (sigops 0) (entry-time 0))
  "Build a mempool-entry from TX, computing the derived size/vsize/wtxid fields.
Centralizes entry construction so every acceptance path records the same
fields (handle-tx, sendrawtransaction, reorg re-add)."
  (make-mempool-entry
   :transaction tx
   :fee fee
   ;; Wire-serialized byte length (witness form only when the tx has witness
   ;; data, so legacy txs aren't charged phantom marker/flag bytes).
   :size (length (if (bitcoin-lisp.serialization:transaction-has-witness-p tx)
                     (bitcoin-lisp.serialization:serialize-witness-transaction tx)
                     (bitcoin-lisp.serialization:serialize-transaction tx)))
   :vsize (bitcoin-lisp.serialization:transaction-vsize tx)
   :wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)
   :sigops sigops
   :height height
   :entry-time entry-time))

(defun mempool-entry-fee-rate (entry)
  "Compute the fee rate (satoshis per virtual byte) for a mempool entry."
  (let ((vsize (mempool-entry-vsize entry)))
    (if (zerop vsize)
        0
        (/ (mempool-entry-fee entry) vsize))))

;;;; Mempool

(defstruct mempool
  "In-memory transaction pool."
  ;; txid (byte vector) -> mempool-entry
  (entries (make-hash-table :test 'equalp) :type hash-table)
  ;; wtxid (byte vector) -> txid  (BIP339 witness-txid lookup for getdata)
  (by-wtxid (make-hash-table :test 'equalp) :type hash-table)
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

;;;; Ancestor / descendant graph (derived on demand from parent/child links)

(defun mempool-find-parents (mempool tx)
  "Return the distinct txids of TX's inputs that are themselves in the mempool."
  (let ((seen (make-hash-table :test 'equalp))
        (result '()))
    (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let ((ptxid (bitcoin-lisp.serialization:outpoint-hash
                    (bitcoin-lisp.serialization:tx-in-previous-output input))))
        (when (and (mempool-has mempool ptxid) (not (gethash ptxid seen)))
          (setf (gethash ptxid seen) t)
          (push ptxid result))))
    result))

(defun %walk-mempool-graph (mempool seed-txids link-accessor)
  "BFS from SEED-TXIDS following LINK-ACCESSOR (parents or children of an entry).
Returns a hash-set (txid -> t) of all reached txids (excluding the seeds unless
they are reachable from each other). Bounded by the ancestor/descendant limits."
  (let ((found (make-hash-table :test 'equalp))
        (queue (copy-list seed-txids)))
    (loop while queue
          do (let ((txid (pop queue)))
               (unless (gethash txid found)
                 (let ((entry (mempool-get mempool txid)))
                   (when entry
                     (setf (gethash txid found) t)
                     (maphash (lambda (k v) (declare (ignore v)) (push k queue))
                              (funcall link-accessor entry)))))))
    found))

(defun mempool-ancestors (mempool txid)
  "Hash-set of all in-mempool ancestor txids of TXID (excluding TXID itself)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%walk-mempool-graph mempool
                             (loop for k being the hash-keys of (mempool-entry-parents entry)
                                   collect k)
                             #'mempool-entry-parents)
        (make-hash-table :test 'equalp))))

(defun mempool-descendants (mempool txid)
  "Hash-set of all in-mempool descendant txids of TXID (excluding TXID itself)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%walk-mempool-graph mempool
                             (loop for k being the hash-keys of (mempool-entry-children entry)
                                   collect k)
                             #'mempool-entry-children)
        (make-hash-table :test 'equalp))))

(defun %stats-over (mempool txid-set seed-entry)
  "Return (values count vsize fees) over SEED-ENTRY plus every entry in TXID-SET."
  (let ((count 1)
        (vsize (mempool-entry-vsize seed-entry))
        (fees (mempool-entry-fee seed-entry)))
    (maphash (lambda (txid v)
               (declare (ignore v))
               (let ((e (mempool-get mempool txid)))
                 (when e
                   (incf count)
                   (incf vsize (mempool-entry-vsize e))
                   (incf fees (mempool-entry-fee e)))))
             txid-set)
    (values count vsize fees)))

(defun mempool-ancestor-stats (mempool txid)
  "(values count vsize fees) over TXID and all its ancestors (incl. self)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%stats-over mempool (mempool-ancestors mempool txid) entry)
        (values 0 0 0))))

(defun mempool-descendant-stats (mempool txid)
  "(values count vsize fees) over TXID and all its descendants (incl. self)."
  (let ((entry (mempool-get mempool txid)))
    (if entry
        (%stats-over mempool (mempool-descendants mempool txid) entry)
        (values 0 0 0))))

(defun check-ancestor-descendant-limits (mempool parent-txids new-vsize)
  "Check that adding a new tx of NEW-VSIZE with the given in-mempool PARENT-TXIDS
keeps it within ancestor and descendant limits. Returns (values ok-p reason)."
  ;; Ancestors of the new tx = its parents plus all of their ancestors.
  (let* ((ancestors (%walk-mempool-graph mempool (copy-list parent-txids)
                                         #'mempool-entry-parents))
         (acount 1) (avsize new-vsize))     ; include the new tx itself
    (maphash (lambda (a v) (declare (ignore v))
               (let ((e (mempool-get mempool a)))
                 (when e (incf acount) (incf avsize (mempool-entry-vsize e)))))
             ancestors)
    (cond
      ((> acount +default-ancestor-limit+) (values nil :too-long-mempool-chain))
      ((> avsize +default-ancestor-size-limit+) (values nil :too-long-mempool-chain))
      (t
       ;; Adding the new tx adds one descendant (+new-vsize) to each ancestor.
       (let ((result-ok t) (result-reason nil))
         (block scan
           (maphash (lambda (a v) (declare (ignore v))
                      (multiple-value-bind (dcount dvsize) (mempool-descendant-stats mempool a)
                        (when (or (> (1+ dcount) +default-descendant-limit+)
                                  (> (+ dvsize new-vsize) +default-descendant-size-limit+))
                          (setf result-ok nil result-reason :too-long-mempool-chain)
                          (return-from scan))))
                    ancestors))
         (values result-ok result-reason))))))

(defun %link-entry-parents (mempool txid entry parent-txids)
  "Wire up the parent/child links between ENTRY (TXID) and its in-mempool parents."
  (dolist (p parent-txids)
    (setf (gethash p (mempool-entry-parents entry)) t)
    (let ((pe (mempool-get mempool p)))
      (when pe (setf (gethash txid (mempool-entry-children pe)) t)))))

(defun %unlink-entry (mempool txid entry)
  "Drop ENTRY (TXID) from its parents' children sets and its children's parents."
  (maphash (lambda (p v) (declare (ignore v))
             (let ((pe (mempool-get mempool p)))
               (when pe (remhash txid (mempool-entry-children pe)))))
           (mempool-entry-parents entry))
  (maphash (lambda (c v) (declare (ignore v))
             (let ((ce (mempool-get mempool c)))
               (when ce (remhash txid (mempool-entry-parents ce)))))
           (mempool-entry-children entry)))

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

  ;; Ancestor/descendant package limits.
  (let ((parent-txids (mempool-find-parents
                       mempool (mempool-entry-transaction entry))))
    (multiple-value-bind (ok reason)
        (check-ancestor-descendant-limits mempool parent-txids
                                          (mempool-entry-vsize entry))
      (unless ok
        (return-from mempool-add reason)))

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

  ;; Wire up ancestor/descendant links to in-mempool parents.
  (%link-entry-parents mempool txid entry parent-txids)

  ;; Index by wtxid (BIP339)
  (let ((wtxid (mempool-entry-wtxid entry)))
    (when wtxid
      (setf (gethash wtxid (mempool-by-wtxid mempool)) txid)))

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

  :ok))

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
      ;; Remove wtxid index
      (let ((wtxid (mempool-entry-wtxid entry)))
        (when wtxid
          (remhash wtxid (mempool-by-wtxid mempool))))
      ;; Drop ancestor/descendant links to/from this entry
      (%unlink-entry mempool txid entry)
      ;; Remove from entries
      (remhash txid (mempool-entries mempool))
      ;; Update total size
      (decf (mempool-total-size mempool) (mempool-entry-size entry))
      entry)))

(defun mempool-remove-recursive (mempool txid)
  "Remove TXID and all of its in-mempool descendants. Returns the number of
transactions removed. Used by RBF replacement, eviction, and expiry so a
removed tx never leaves dangling children behind."
  (let ((targets (mempool-descendants mempool txid))
        (removed 0))
    (setf (gethash txid targets) t)        ; include self
    (maphash (lambda (t2 v) (declare (ignore v))
               (when (mempool-remove mempool t2) (incf removed)))
             targets)
    removed))

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

      ;; Evict lowest fee-rate entries until enough space is freed. Remove
      ;; each evictee together with its descendants (a child spends the
      ;; parent's unconfirmed output, so it can't survive its parent) and
      ;; count freed bytes from the total-size delta. PR5 will refine this to
      ;; evict by descendant-package fee-rate.
      (let ((freed 0))
        (dolist (pair sorted-entries)
          (when (>= freed to-free)
            (return-from mempool-evict-for-size t))
          ;; May already be gone if removed as a descendant of an earlier evictee.
          (when (mempool-has mempool (car pair))
            (let ((before (mempool-total-size mempool)))
              (mempool-remove-recursive mempool (car pair))
              (incf freed (- before (mempool-total-size mempool))))))
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
