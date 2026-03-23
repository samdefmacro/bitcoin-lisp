(in-package #:bitcoin-lisp)

;;; Configuration
;;;
;;; Global configuration variables and constants that are referenced
;;; across multiple subsystems. Loaded early so that storage, validation,
;;; and networking modules can reference these symbols at compile time.

;;;; Block Pruning Configuration

(defconstant +min-blocks-to-keep+ 288
  "Minimum number of recent blocks to keep on disk (matches Bitcoin Core).")

(defvar *prune-target-mib* nil
  "Block pruning target in MiB.
NIL = pruning disabled (default).
1 = manual-only mode (pruneblockchain RPC works, no automatic pruning).
>= 550 = automatic pruning to this target size.
Any other value signals an error at startup.")

(defvar *prune-after-height* nil
  "Minimum chain height before pruning can begin.
Set automatically based on network: 100000 for mainnet, 1000 for testnet.")

(defun pruning-enabled-p ()
  "Return T if pruning is enabled (any mode)."
  (and *prune-target-mib* (> *prune-target-mib* 0)))

(defun automatic-pruning-p ()
  "Return T if automatic pruning is enabled (not manual-only)."
  (and *prune-target-mib* (>= *prune-target-mib* 550)))

(defun prune-after-height (network)
  "Return the minimum chain height before pruning begins for NETWORK."
  (ecase network
    (:mainnet 100000)
    ((:testnet :testnet4 :signet) 1000)))

;;;; Token Bucket Rate Limiter

(defstruct token-bucket
  "Token bucket for rate limiting. Allows RATE tokens per second with
maximum BURST capacity. Tokens accumulate while idle."
  (rate 1.0 :type single-float)
  (burst 1.0 :type single-float)
  (tokens 0.0 :type single-float)
  (last-refill 0 :type integer))

(defun make-rate-limiter (rate burst)
  "Create a token bucket with RATE tokens/sec and BURST max capacity.
Starts full (tokens = burst) to avoid rejecting initial messages."
  (make-token-bucket :rate (float rate)
                     :burst (float burst)
                     :tokens (float burst)
                     :last-refill (get-internal-real-time)))

(defun token-bucket-allow-p (bucket)
  "Consume one token from BUCKET if available.
Returns T if allowed, NIL if rate limited.
Refills tokens based on elapsed time since last check."
  (let* ((now (get-internal-real-time))
         (elapsed (/ (float (- now (token-bucket-last-refill bucket)))
                     (float internal-time-units-per-second)))
         (refilled (min (token-bucket-burst bucket)
                        (+ (token-bucket-tokens bucket)
                           (* elapsed (token-bucket-rate bucket))))))
    (setf (token-bucket-last-refill bucket) now)
    (if (>= refilled 1.0)
        (progn
          (setf (token-bucket-tokens bucket) (- refilled 1.0))
          t)
        (progn
          (setf (token-bucket-tokens bucket) refilled)
          nil))))

;;;; Recent Transaction Rejects Filter

(defstruct recent-rejects
  "Bounded set of recently rejected transaction hashes.
Uses a hash table for O(1) lookup and a ring buffer for FIFO eviction."
  (table (make-hash-table :test 'equalp) :type hash-table)
  (ring nil :type (or null simple-vector))
  (index 0 :type fixnum)
  (max-size 50000 :type fixnum))

(defun make-rejects-filter (&optional (max-size *recent-rejects-max-size*))
  "Create a recent rejects filter with MAX-SIZE capacity."
  (make-recent-rejects :table (make-hash-table :test 'equalp)
                       :ring (make-array max-size :initial-element nil)
                       :max-size max-size))

(defun recent-reject-p (filter hash)
  "Return T if HASH is in the rejects filter."
  (and filter (gethash hash (recent-rejects-table filter))))

(defun add-recent-reject (filter hash)
  "Add HASH to the rejects filter. Evicts oldest entry if at capacity.
Returns T if added, NIL if already present."
  (when filter
    (let ((table (recent-rejects-table filter)))
      ;; Already present
      (when (gethash hash table)
        (return-from add-recent-reject nil))
      ;; Evict oldest if at capacity
      (let* ((ring (recent-rejects-ring filter))
             (idx (recent-rejects-index filter))
             (old (aref ring idx)))
        (when old
          (remhash old table))
        ;; Insert new entry
        (setf (aref ring idx) hash)
        (setf (gethash hash table) t)
        (setf (recent-rejects-index filter)
              (mod (1+ idx) (recent-rejects-max-size filter)))
        t))))

(defun clear-recent-rejects (filter)
  "Clear all entries from the rejects filter."
  (when filter
    (clrhash (recent-rejects-table filter))
    (let ((ring (recent-rejects-ring filter)))
      (dotimes (i (length ring))
        (setf (aref ring i) nil)))
    (setf (recent-rejects-index filter) 0)))

;;;; DoS Protection Configuration

(defvar *rate-limit-inv* '(50.0 . 200.0)
  "Rate limit for INV messages: (rate-per-sec . burst).")

(defvar *rate-limit-tx* '(10.0 . 50.0)
  "Rate limit for TX messages: (rate-per-sec . burst).")

(defvar *rate-limit-addr* '(1.0 . 10.0)
  "Rate limit for ADDR/ADDRV2 messages: (rate-per-sec . burst).")

(defvar *rate-limit-getdata* '(20.0 . 100.0)
  "Rate limit for GETDATA messages: (rate-per-sec . burst).")

(defvar *rate-limit-headers* '(10.0 . 50.0)
  "Rate limit for HEADERS messages: (rate-per-sec . burst).")

(defvar *rpc-rate-limit* '(100.0 . 200.0)
  "Rate limit for RPC requests: (rate-per-sec . burst).")

(defconstant +max-message-payload+ (* 4 1024 1024)
  "Maximum P2P message payload size in bytes (4 MB).")

(defconstant +max-rpc-body-size+ (* 1 1024 1024)
  "Maximum RPC request body size in bytes (1 MB).")

(defconstant +handshake-timeout-seconds+ 30
  "Maximum seconds to complete version handshake.")

(defvar *recent-rejects-max-size* 50000
  "Maximum entries in the recent transaction rejects filter.")
