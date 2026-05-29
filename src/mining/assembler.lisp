(in-package #:bitcoin-lisp.mining)

;;; Block template assembler
;;;
;;; Assembles a candidate block from the mempool, mirroring Bitcoin Core's
;;; BlockAssembler (node/miner.cpp) in its classic ancestor-package form
;;; (addPackageTxs): rank candidate txs by ancestor-package feerate, and for
;;; each, include it together with its not-yet-included unconfirmed ancestors
;;; (parents first) if the package fits the remaining weight and sigop budget.
;;; This is selection/policy only — it never bypasses validation; submitblock
;;; (and network blocks) go through the same connect-block consensus path.

(defconstant +block-reserved-weight+ 8000
  "Weight reserved for the block header, tx-count varint, and coinbase before
filling with mempool txs (Bitcoin Core DEFAULT_BLOCK_RESERVED_WEIGHT).")

(defconstant +coinbase-reserved-sigops+ 400
  "Sigop cost reserved for the coinbase (Bitcoin Core
coinbase_output_max_additional_sigops).")

(defconstant +versionbits-top-bits+ #x20000000
  "Block version with the BIP9 top bits set and no deployment signaling.")

(defvar *last-block-template* nil
  "The most recently assembled block-template (Bitcoin Core's
m_last_block_weight/num). getmininginfo reports its weight/tx-count without
re-assembling.")

(defun %zeros32 ()
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defun %txid< (a b)
  "Lexicographic byte-vector ordering, for a deterministic feerate tiebreak."
  (let ((n (min (length a) (length b))))
    (dotimes (i n (< (length a) (length b)))
      (cond ((< (aref a i) (aref b i)) (return t))
            ((> (aref a i) (aref b i)) (return nil))))))

(defstruct block-template
  "A candidate block assembled from the mempool. TRANSACTIONS is the selected
non-coinbase mempool-entries in block order (parents before children). The
weight/sigops totals already include the reserved coinbase allowance."
  (height 0)
  (prev-hash nil)
  (bits 0)
  (version +versionbits-top-bits+)
  (curtime 0)
  (mintime 0)
  (transactions '())
  (total-fees 0)
  (total-weight +block-reserved-weight+)
  (total-sigops +coinbase-reserved-sigops+)
  (coinbase-value 0)
  (witness-commitment nil)
  (default-witness-commitment-script nil))

(defun next-block-required-bits (chain-state prev-entry block-time)
  "The compact difficulty bits the block after PREV-ENTRY must carry, mirroring
Bitcoin Core's GetNextWorkRequired. Reuses the consensus get-expected-bits and
falls back to the testnet min-difficulty / walk-back rule when it is
non-definitive (testnet non-boundary)."
  (let* ((height (1+ (bitcoin-lisp.storage:block-index-entry-height prev-entry)))
         (expected (bitcoin-lisp.validation:get-expected-bits height prev-entry)))
    (or expected
        (let ((prev-time (bitcoin-lisp.serialization:block-header-timestamp
                          (bitcoin-lisp.storage:block-index-entry-header prev-entry))))
          (if (bitcoin-lisp.validation:testnet-min-difficulty-allowed-p block-time prev-time)
              bitcoin-lisp.storage:+pow-limit-bits+
              (bitcoin-lisp.validation:testnet-walk-back-bits prev-entry))))))

(defun build-witness-commitment-script (commitment)
  "The 38-byte coinbase witness-commitment scriptPubKey for COMMITMENT (a
32-byte hash): OP_RETURN push36 0xaa21a9ed <commitment>."
  (let ((s (make-array 38 :element-type '(unsigned-byte 8))))
    (setf (aref s 0) #x6a (aref s 1) #x24
          (aref s 2) #xaa (aref s 3) #x21 (aref s 4) #xa9 (aref s 5) #xed)
    (replace s commitment :start1 6)
    s))

(defun %topo-order-package (mempool txid-set)
  "Order the txids in TXID-SET (a hash-set, all in MEMPOOL) parents-before-
children via post-order DFS over in-set parent links."
  (let ((placed (make-hash-table :test 'equalp))
        (result '()))
    (labels ((visit (txid)
               (unless (gethash txid placed)
                 (setf (gethash txid placed) t)
                 (let ((e (bitcoin-lisp.mempool:mempool-get mempool txid)))
                   (when e
                     (maphash (lambda (p v) (declare (ignore v))
                                (when (gethash p txid-set) (visit p)))
                              (bitcoin-lisp.mempool:mempool-entry-parents e))))
                 (push txid result))))
      (maphash (lambda (txid v) (declare (ignore v)) (visit txid)) txid-set))
    (nreverse result)))

(defun %default-witness-commitment (selected)
  "(values commitment-hash scriptPubKey) for the witness commitment over a block
whose coinbase wtxid is zero and whose other txs are SELECTED (mempool-entries),
with the all-zero reserved value. Mirrors GenerateCoinbaseCommitment."
  (let* ((wtxids (cons (%zeros32)
                       (mapcar (lambda (e)
                                 (bitcoin-lisp.serialization:transaction-wtxid
                                  (bitcoin-lisp.mempool:mempool-entry-transaction e)))
                               selected)))
         (witness-root (bitcoin-lisp.validation:compute-merkle-root wtxids))
         ;; commitment = hash256(witness-root || 32 zero reserved bytes)
         (combined (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace combined witness-root :start1 0)
    (let ((commitment (bitcoin-lisp.crypto:hash256 combined)))
      (values commitment (build-witness-commitment-script commitment)))))

(defun assemble-block-template (chain-state mempool &key block-time)
  "Assemble a BLOCK-TEMPLATE for the block extending CHAIN-STATE's tip, filling
it from MEMPOOL by descending ancestor-package feerate (CPFP-aware). BLOCK-TIME
defaults to now."
  (let* ((tip (bitcoin-lisp.storage:get-block-index-entry
               chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
         (prev-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (height (if tip (1+ (bitcoin-lisp.storage:block-index-entry-height tip)) 0))
         (now (or block-time (bitcoin-lisp.serialization:get-unix-time)))
         (mintime (1+ (bitcoin-lisp.validation:compute-median-time-past chain-state prev-hash)))
         (curtime (max now mintime))
         (bits (if tip
                   (next-block-required-bits chain-state tip curtime)
                   bitcoin-lisp.storage:+pow-limit-bits+))
         (included (make-hash-table :test 'equalp))
         (selected '())
         (weight +block-reserved-weight+)
         (sigops +coinbase-reserved-sigops+)
         (fees 0))
    ;; Rank every mempool tx by its ancestor-package feerate, descending.
    (let ((ranked '()))
      (bitcoin-lisp.mempool:mempool-for-each
       mempool (lambda (txid e) (declare (ignore e))
                 (push (cons txid (bitcoin-lisp.mempool:mempool-ancestor-fee-rate mempool txid))
                       ranked)))
      ;; Descending ancestor feerate, txid-ascending as a deterministic tiebreak
      ;; (mempool iteration order is arbitrary, so templates must be reproducible).
      (setf ranked (sort ranked
                         (lambda (a b)
                           (cond ((> (cdr a) (cdr b)) t)
                                 ((< (cdr a) (cdr b)) nil)
                                 (t (%txid< (car a) (car b)))))))
      (dolist (pair ranked)
        (let ((txid (car pair)))
          (unless (gethash txid included)
            ;; The package: this tx plus its not-yet-included ancestors.
            (let ((pkg (make-hash-table :test 'equalp)))
              (setf (gethash txid pkg) t)
              (maphash (lambda (a v) (declare (ignore v))
                         (unless (gethash a included) (setf (gethash a pkg) t)))
                       (bitcoin-lisp.mempool:mempool-ancestors mempool txid))
              (let ((order (%topo-order-package mempool pkg))
                    (pkg-weight 0) (pkg-sigops 0) (pkg-fees 0))
                (dolist (tx2 order)
                  (let ((e (bitcoin-lisp.mempool:mempool-get mempool tx2)))
                    (incf pkg-weight (bitcoin-lisp.serialization:transaction-weight
                                      (bitcoin-lisp.mempool:mempool-entry-transaction e)))
                    (incf pkg-sigops (bitcoin-lisp.mempool:mempool-entry-sigops e))
                    (incf pkg-fees (bitcoin-lisp.mempool:mempool-entry-fee e))))
                (when (and (<= (+ weight pkg-weight) bitcoin-lisp.validation:+max-block-weight+)
                           (<= (+ sigops pkg-sigops) bitcoin-lisp.validation:+max-block-sigops-cost+))
                  (dolist (tx2 order)
                    (setf (gethash tx2 included) t)
                    (push (bitcoin-lisp.mempool:mempool-get mempool tx2) selected))
                  (incf weight pkg-weight)
                  (incf sigops pkg-sigops)
                  (incf fees pkg-fees)))))))
      (setf selected (nreverse selected)))
    (multiple-value-bind (commitment script) (%default-witness-commitment selected)
      (setf *last-block-template*
            (make-block-template
             :height height :prev-hash prev-hash :bits bits
             :curtime curtime :mintime mintime
             :transactions selected :total-fees fees :total-weight weight :total-sigops sigops
             :coinbase-value (+ (bitcoin-lisp.validation:calculate-block-subsidy height) fees)
             :witness-commitment commitment
             :default-witness-commitment-script script)))))
