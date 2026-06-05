(in-package #:bitcoin-lisp.mempool)

;;; Orphan transaction pool
;;;
;;; Holds transactions whose inputs reference outputs not yet available (neither
;;; confirmed nor in the mempool). When a parent later arrives, its children are
;;; re-evaluated (the de-orphan cascade lives in the networking layer). Mirrors
;;; Bitcoin Core's TxOrphanage, bounded by a count cap and a time-based expiry.

(defconstant +max-orphan-transactions+ 100
  "Maximum number of orphan transactions held (Bitcoin Core
DEFAULT_MAX_ORPHAN_TRANSACTIONS).")

(defconstant +orphan-expire-seconds+ 1200
  "Orphans older than this (20 minutes) are dropped (Core ORPHAN_TX_EXPIRE_TIME).")

(defstruct orphan-entry
  "An orphan transaction awaiting a missing parent."
  (transaction nil :type bitcoin-lisp.serialization:transaction)
  (wtxid nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (from-peer nil)
  (entry-time 0 :type integer))

(defstruct orphan-pool
  "Pool of orphan transactions."
  ;; txid -> orphan-entry
  (by-txid (make-hash-table :test 'equalp) :type hash-table)
  ;; parent-txid -> list of orphan txids that reference it as an input parent
  (by-prev (make-hash-table :test 'equalp) :type hash-table)
  (count 0 :type integer))

(defun orphan-pool-has (pool txid)
  (not (null (gethash txid (orphan-pool-by-txid pool)))))

(defun %orphan-deindex (pool txid tx)
  "Remove TXID from every by-prev bucket of its input parents."
  (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
    (let* ((ptxid (bitcoin-lisp.serialization:outpoint-hash
                   (bitcoin-lisp.serialization:tx-in-previous-output in)))
           (bucket (gethash ptxid (orphan-pool-by-prev pool))))
      (when bucket
        (let ((rest (remove txid bucket :test #'equalp)))
          (if rest
              (setf (gethash ptxid (orphan-pool-by-prev pool)) rest)
              (remhash ptxid (orphan-pool-by-prev pool))))))))

(defun orphan-remove (pool txid)
  "Remove orphan TXID from the pool. Returns T if it was present."
  (let ((entry (gethash txid (orphan-pool-by-txid pool))))
    (when entry
      (%orphan-deindex pool txid (orphan-entry-transaction entry))
      (remhash txid (orphan-pool-by-txid pool))
      (decf (orphan-pool-count pool))
      t)))

(defun %orphan-evict-oldest (pool)
  "Drop the oldest orphan to make room."
  (let ((oldest-txid nil) (oldest-time nil))
    (maphash (lambda (txid entry)
               (when (or (null oldest-time)
                         (< (orphan-entry-entry-time entry) oldest-time))
                 (setf oldest-time (orphan-entry-entry-time entry)
                       oldest-txid txid)))
             (orphan-pool-by-txid pool))
    (when oldest-txid (orphan-remove pool oldest-txid))))

(defun orphan-add (pool tx peer)
  "Add TX (from PEER) to the orphan pool, indexed under each input's parent
txid. Evicts the oldest orphan if the pool is at capacity. Returns T if added."
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (unless (orphan-pool-has pool txid)
      (when (>= (orphan-pool-count pool) +max-orphan-transactions+)
        (%orphan-evict-oldest pool))
      (setf (gethash txid (orphan-pool-by-txid pool))
            (make-orphan-entry
             :transaction tx
             :wtxid (bitcoin-lisp.serialization:transaction-wtxid tx)
             :from-peer peer
             :entry-time (bitcoin-lisp.serialization:get-unix-time)))
      (incf (orphan-pool-count pool))
      (bitcoin-lisp.serialization:dovector (in (bitcoin-lisp.serialization:transaction-inputs tx))
        (let ((ptxid (bitcoin-lisp.serialization:outpoint-hash
                      (bitcoin-lisp.serialization:tx-in-previous-output in))))
          (pushnew txid (gethash ptxid (orphan-pool-by-prev pool)) :test #'equalp)))
      t)))

(defun orphans-depending-on (pool parent-txid)
  "Return the txids of orphans that reference PARENT-TXID as an input parent."
  (copy-list (gethash parent-txid (orphan-pool-by-prev pool))))

(defun orphan-tx (pool txid)
  "Return the transaction for orphan TXID, or NIL."
  (let ((e (gethash txid (orphan-pool-by-txid pool))))
    (when e (orphan-entry-transaction e))))

(defun orphan-erase-for-peer (pool peer)
  "Remove all orphans contributed by PEER (called when the peer disconnects)."
  (let ((to-remove '()))
    (maphash (lambda (txid entry)
               (when (eq (orphan-entry-from-peer entry) peer)
                 (push txid to-remove)))
             (orphan-pool-by-txid pool))
    (dolist (txid to-remove) (orphan-remove pool txid))
    (length to-remove)))

(defun orphan-expire (pool &optional (now (bitcoin-lisp.serialization:get-unix-time)))
  "Drop orphans older than +orphan-expire-seconds+. Returns the count removed."
  (let ((to-remove '()))
    (maphash (lambda (txid entry)
               (when (> (- now (orphan-entry-entry-time entry)) +orphan-expire-seconds+)
                 (push txid to-remove)))
             (orphan-pool-by-txid pool))
    (dolist (txid to-remove) (orphan-remove pool txid))
    (length to-remove)))
