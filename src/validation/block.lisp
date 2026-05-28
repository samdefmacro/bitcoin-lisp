(in-package #:bitcoin-lisp.validation)

;;; Block Validation
;;;
;;; This module validates Bitcoin blocks according to consensus rules.
;;; Uses Coalton types for amounts (Satoshi) and heights (BlockHeight).

;;;; Imports for typed operations (reuse from transaction.lisp, add BlockHeight)
(defun wrap-block-height (h) (bitcoin-lisp.coalton.interop:wrap-block-height h))
(defun unwrap-block-height (bh) (bitcoin-lisp.coalton.interop:unwrap-block-height bh))

;;;; Constants

(defconstant +max-block-sigops-cost+ 80000)  ; BIP 141: max weighted sigops cost
(defconstant +witness-scale-factor+ 4)       ; BIP 141: legacy sigops weight multiplier
(defconstant +max-block-weight+ 4000000)     ; BIP 141: max block weight in weight units
(defconstant +max-future-block-time+ 7200)  ; 2 hours in seconds
(defconstant +max-timewarp+ 600
  "BIP 94 timewarp-attack mitigation: on networks that enforce BIP 94
(testnet4), the first block of each difficulty-adjustment period may not
be timestamped more than this many seconds before the previous block.
Bitcoin Core MAX_TIMEWARP (consensus/consensus.h:35).")

;;; Locktime activation heights (BIPs 65/68/112/113)

(defconstant +bip66-activation-height-mainnet+ 363725
  "BIP 66 (DERSIG/strict DER) activation height on mainnet.")
(defconstant +bip66-activation-height-testnet3+ 330776
  "BIP 66 (DERSIG/strict DER) activation height on testnet.")

(defconstant +bip65-activation-height-mainnet+ 388381
  "BIP 65 (CLTV) activation height on mainnet.")
(defconstant +bip65-activation-height-testnet3+ 581885
  "BIP 65 (CLTV) activation height on testnet.")

(defconstant +csv-activation-height-mainnet+ 419328
  "BIP 68/112/113 (CSV soft fork) activation height on mainnet.")
(defconstant +csv-activation-height-testnet3+ 770112
  "BIP 68/112/113 (CSV soft fork) activation height on testnet.")

(defconstant +segwit-activation-height-mainnet+ 481824
  "BIP 141 (SegWit) activation height on mainnet.")
(defconstant +segwit-activation-height-testnet3+ 834624
  "BIP 141 (SegWit) activation height on testnet3.")

(defconstant +taproot-activation-height-mainnet+ 709632
  "BIP 341 (Taproot) activation height on mainnet.")
(defconstant +taproot-activation-height-testnet3+ 2346882
  "BIP 341 (Taproot) activation height on testnet3.")

;;; P2SH is active from block 173805 (mainnet) but enforced from genesis on testnet.
;;; BIP 66 (DERSIG) and BIP 147 (NULLDUMMY) activate with SegWit on most networks.

(defconstant +locktime-threshold+ 500000000
  "Threshold for height vs time-based locktime. Values below are block heights,
values at or above are Unix timestamps.")

(defconstant +sequence-disable-flag+ #x80000000
  "BIP 68: If set, nSequence is not interpreted as relative locktime.")
(defconstant +sequence-type-flag+ #x00400000
  "BIP 68: If set, relative locktime is time-based (512-second units).")
(defconstant +sequence-locktime-mask+ #x0000FFFF
  "BIP 68: Mask for the relative locktime value.")
(defconstant +sequence-locktime-granularity+ 512
  "BIP 68: Time-based relative locktime granularity in seconds.")
(defconstant +sequence-final+ #xFFFFFFFF
  "Fully final sequence number (disables nLockTime for input).")

;;;; Median-Time-Past (BIP 113)

(defconstant +median-time-span+ 11
  "Number of previous blocks used to compute median-time-past.")

(defun compute-median-time-past (chain-state prev-hash)
  "Compute the median-time-past for the block following PREV-HASH.
Returns the median of up to 11 previous block timestamps."
  (let ((timestamps '())
        (hash prev-hash))
    (dotimes (i +median-time-span+)
      (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state hash)))
        (unless entry (return))
        (push (bitcoin-lisp.serialization:block-header-timestamp
               (bitcoin-lisp.storage:block-index-entry-header entry))
              timestamps)
        (let ((prev (bitcoin-lisp.storage:block-index-entry-prev-entry entry)))
          (if prev
              (setf hash (bitcoin-lisp.storage:block-index-entry-hash prev))
              (return)))))
    (if (null timestamps)
        0
        (let ((sorted (sort timestamps #'<)))
          (nth (floor (length sorted) 2) sorted)))))

;;;; Transaction finality check (IsFinalTx)

(defun check-transaction-final (tx block-height block-time)
  "Check if TX is final per consensus rules.
A transaction is final if:
- nLockTime is 0
- All input sequences are SEQUENCE_FINAL (0xFFFFFFFF)
- nLockTime < block-height (height-based) or nLockTime < block-time (time-based)
Returns T if final, NIL if not."
  (let ((locktime (bitcoin-lisp.serialization:transaction-lock-time tx)))
    ;; nLockTime == 0 means always final
    (when (zerop locktime)
      (return-from check-transaction-final t))
    ;; Check if locktime is satisfied
    (let ((threshold (if (< locktime +locktime-threshold+)
                         block-height    ; height-based
                         block-time)))   ; time-based
      (when (< locktime threshold)
        (return-from check-transaction-final t)))
    ;; If locktime not satisfied, tx is final only if ALL sequences are final
    (every (lambda (input)
             (= (bitcoin-lisp.serialization:tx-in-sequence input) +sequence-final+))
           (bitcoin-lisp.serialization:transaction-inputs tx))))

;;;; BIP 68 Sequence Lock Enforcement

(defun check-sequence-locks (tx utxo-set current-height mtp chain-state
                             &key pending-utxos)
  "Check BIP 68 relative locktime for TX.
For each input with version >= 2 and sequence not disabled (bit 31 clear):
- Height-based: input UTXO must be at least N blocks deep
- Time-based: MTP must be >= N*512 seconds after UTXO's MTP
Returns T if all locks satisfied, NIL if any lock not yet matured."
  ;; BIP 68 only applies to transaction version >= 2
  (when (< (bitcoin-lisp.serialization:transaction-version tx) 2)
    (return-from check-sequence-locks t))
  (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx) t)
    (let ((seq (bitcoin-lisp.serialization:tx-in-sequence input)))
      ;; Skip if disable flag is set
      (unless (logtest seq +sequence-disable-flag+)
        (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
               (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
               (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
               (utxo (or (and pending-utxos
                              (gethash (cons prev-txid prev-index) pending-utxos))
                         (bitcoin-lisp.storage:get-utxo utxo-set prev-txid prev-index))))
          (unless utxo
            (return-from check-sequence-locks nil))
          (let ((utxo-height (bitcoin-lisp.storage:utxo-entry-height utxo)))
            (if (logtest seq +sequence-type-flag+)
                ;; Time-based relative locktime.
                ;; Bitcoin Core uses block.GetAncestor(max(nCoinHeight-1, 0))->GetMedianTimePast()
                ;; — the MTP of the block PRIOR to the input's confirmation block, not the
                ;; confirmation block itself (consensus/tx_verify.cpp:74).
                (let* ((required-time (* (logand seq +sequence-locktime-mask+)
                                         +sequence-locktime-granularity+))
                       (utxo-prev-height (max 0 (1- utxo-height)))
                       (utxo-prev-entry (bitcoin-lisp.storage:get-block-at-height
                                         chain-state utxo-prev-height))
                       (utxo-mtp (if utxo-prev-entry
                                     (compute-median-time-past
                                      chain-state
                                      (bitcoin-lisp.storage:block-index-entry-hash
                                       utxo-prev-entry))
                                     0)))
                  (when (< (- mtp utxo-mtp) required-time)
                    (return-from check-sequence-locks nil)))
                ;; Height-based relative locktime
                (let ((required-height (logand seq +sequence-locktime-mask+)))
                  (when (< (- current-height utxo-height) required-height)
                    (return-from check-sequence-locks nil))))))))))

;;;; Script verification flags

(defun get-bip66-activation-height (network)
  "Return the BIP 66 (DERSIG) activation height for NETWORK."
  (ecase network
    (:testnet3 +bip66-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    (:mainnet +bip66-activation-height-mainnet+)))

(defun get-bip65-activation-height (network)
  "Return the BIP 65 (CLTV) activation height for NETWORK."
  (ecase network
    (:testnet3 +bip65-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    (:mainnet +bip65-activation-height-mainnet+)))

(defun get-csv-activation-height (network)
  "Return the BIP 68/112/113 (CSV) activation height for NETWORK."
  (ecase network
    (:testnet3 +csv-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    (:mainnet +csv-activation-height-mainnet+)))

(defun get-taproot-activation-height (network)
  "Return the BIP 341 (Taproot) activation height for NETWORK."
  (ecase network
    (:testnet3 +taproot-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    (:mainnet +taproot-activation-height-mainnet+)))

(defun get-segwit-activation-height (network)
  "Return the BIP 141 (SegWit) activation height for NETWORK."
  (ecase network
    (:testnet3 +segwit-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    (:mainnet +segwit-activation-height-mainnet+)))

;;; Policy vs Consensus Flag Separation
;;;
;;; Bitcoin Core distinguishes MANDATORY (consensus) flags from STANDARD (policy) flags.
;;; Mandatory flags are required for block validation. Standard flags add policy
;;; restrictions for mempool acceptance and transaction relay.

(defparameter +standard-policy-flags+
  '("STRICTENC" "MINIMALDATA" "DISCOURAGE_UPGRADABLE_NOPS"
    "CLEANSTACK" "MINIMALIF" "NULLFAIL" "LOW_S"
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" "WITNESS_PUBKEYTYPE"
    "CONST_SCRIPTCODE" "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION"
    "DISCOURAGE_OP_SUCCESS" "DISCOURAGE_UPGRADABLE_PUBKEYTYPE")
  "Policy flags layered on top of mandatory consensus flags for mempool acceptance.")

(defun mandatory-script-flags-list (height)
  "Mandatory consensus flags active at HEIGHT, as a list of strings.
   P2SH is included unconditionally; DERSIG/CLTV/CSV/WITNESS/NULLDUMMY/TAPROOT
   gate on their activation heights for the current network."
  (let ((flags (list "P2SH"))
        (network bitcoin-lisp:*network*))
    (when (>= height (get-bip66-activation-height network))
      (push "DERSIG" flags))
    (when (>= height (get-bip65-activation-height network))
      (push "CHECKLOCKTIMEVERIFY" flags))
    (when (>= height (get-csv-activation-height network))
      (push "CHECKSEQUENCEVERIFY" flags))
    (when (>= height (get-segwit-activation-height network))
      (push "WITNESS" flags)
      (push "NULLDUMMY" flags))
    (when (>= height (get-taproot-activation-height network))
      (push "TAPROOT" flags))
    (nreverse flags)))

(defun compute-script-flags-for-height (height)
  "Comma-separated MANDATORY script verification flags for block validation at HEIGHT
   (Bitcoin Core: MANDATORY_SCRIPT_VERIFY_FLAGS)."
  (format nil "~{~A~^,~}" (mandatory-script-flags-list height)))

(defun compute-standard-script-flags-for-height (height)
  "Comma-separated STANDARD script verification flags for mempool acceptance at HEIGHT
   (Bitcoin Core: STANDARD_SCRIPT_VERIFY_FLAGS = mandatory + policy)."
  (format nil "~{~A~^,~}"
          (append (mandatory-script-flags-list height) +standard-policy-flags+)))

;;; BIP 16 (P2SH) exception block hash for testnet3
;;; This block predates proper BIP 16 enforcement and must skip script validation
;;; See Bitcoin Core's chainparams.cpp: consensus.script_flag_exceptions
;;; Note: Block hashes are displayed in big-endian but stored in little-endian (reversed)
(defvar *bip16-exception-testnet*
  (bitcoin-lisp.crypto:reverse-bytes
   (bitcoin-lisp.crypto:hex-to-bytes "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"))
  "Block hash that is exempted from BIP 16 script verification on testnet3 (little-endian).")

;;; BIP 16 (P2SH) exception block hash for mainnet
(defvar *bip16-exception-mainnet*
  (bitcoin-lisp.crypto:reverse-bytes
   (bitcoin-lisp.crypto:hex-to-bytes "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"))
  "Block hash that is exempted from BIP 16 script verification on mainnet (little-endian).")

;;;; Difficulty adjustment validation

(defconstant +testnet-min-difficulty-spacing+ 1200
  "Seconds (20 minutes) after which testnet allows min-difficulty blocks.")

(defun testnet-min-difficulty-allowed-p (block-timestamp prev-timestamp)
  "Check if a testnet block is allowed to use minimum difficulty.
Returns T if more than 20 minutes have elapsed since the previous block."
  (> block-timestamp (+ prev-timestamp +testnet-min-difficulty-spacing+)))

(defun testnet-walk-back-bits (entry)
  "Walk back through the chain from ENTRY to find the last non-min-difficulty bits.
Stops at a block that either sits at a retarget boundary (height % 2016 == 0)
or does not have min-difficulty bits. Returns that block's bits value."
  (let ((current entry))
    (loop while (and current
                     (bitcoin-lisp.storage:block-index-entry-prev-entry current)
                     (/= 0 (mod (bitcoin-lisp.storage:block-index-entry-height current)
                                 bitcoin-lisp.storage:+difficulty-adjustment-interval+))
                     (= (bitcoin-lisp.serialization:block-header-bits
                         (bitcoin-lisp.storage:block-index-entry-header current))
                        bitcoin-lisp.storage:+pow-limit-bits+))
          do (setf current (bitcoin-lisp.storage:block-index-entry-prev-entry current)))
    (if (and current (bitcoin-lisp.storage:block-index-entry-header current))
        (bitcoin-lisp.serialization:block-header-bits
         (bitcoin-lisp.storage:block-index-entry-header current))
        bitcoin-lisp.storage:+pow-limit-bits+)))

(defun get-retarget-ancestor (entry)
  "Walk back from ENTRY to the block at the start of its retarget period.
For a block at height H, this returns the entry at height H - (H mod 2016).
Bitcoin Core's off-by-one: the timespan is measured from this block to ENTRY."
  (let* ((height (bitcoin-lisp.storage:block-index-entry-height entry))
         (interval bitcoin-lisp.storage:+difficulty-adjustment-interval+)
         (blocks-back (mod height interval))
         (current entry))
    (dotimes (i blocks-back)
      (let ((prev (bitcoin-lisp.storage:block-index-entry-prev-entry current)))
        (unless prev (return))
        (setf current prev)))
    current))

(defun get-expected-bits (height prev-entry)
  "Compute the expected bits for a block at HEIGHT with previous block PREV-ENTRY.
Handles: first retarget period, retarget boundaries, non-boundaries,
and testnet min-difficulty exception."
  (let ((interval bitcoin-lisp.storage:+difficulty-adjustment-interval+))
    (cond
      ;; Genesis block or no previous entry
      ((or (zerop height) (null prev-entry))
       bitcoin-lisp.storage:+pow-limit-bits+)

      ;; Retarget boundary (height is a multiple of 2016)
      ((zerop (mod height interval))
       (let* ((last-retarget-entry (get-retarget-ancestor prev-entry))
              (last-retarget-time
                (bitcoin-lisp.serialization:block-header-timestamp
                 (bitcoin-lisp.storage:block-index-entry-header last-retarget-entry)))
              (last-block-time
                (bitcoin-lisp.serialization:block-header-timestamp
                 (bitcoin-lisp.storage:block-index-entry-header prev-entry)))
              ;; BIP 94 (testnet4): the new target is computed from the FIRST block
              ;; of the just-ended retarget period rather than the last block. This
              ;; preserves the real difficulty across periods even when the 20-min
              ;; min-difficulty exception was used near a retarget boundary.
              (basis-entry (if (eq bitcoin-lisp:*network* :testnet4)
                               last-retarget-entry
                               prev-entry))
              (basis-bits
                (bitcoin-lisp.serialization:block-header-bits
                 (bitcoin-lisp.storage:block-index-entry-header basis-entry))))
         (bitcoin-lisp.storage:calculate-next-work-required
          last-retarget-time last-block-time basis-bits)))

      ;; Non-boundary: mainnet just inherits previous bits
      ((eq bitcoin-lisp:*network* :mainnet)
       (bitcoin-lisp.serialization:block-header-bits
        (bitcoin-lisp.storage:block-index-entry-header prev-entry)))

      ;; Non-boundary on testnet: return nil to indicate caller must check
      ;; timestamp-based min-difficulty or walk-back
      (t nil))))

(defun validate-difficulty (header height prev-entry)
  "Validate that HEADER's bits field matches expected difficulty at HEIGHT.
PREV-ENTRY is the block-index-entry for the previous block.
Returns (VALUES T NIL) on success, (VALUES NIL :bad-difficulty) on failure."
  (let ((block-bits (bitcoin-lisp.serialization:block-header-bits header))
        (expected (get-expected-bits height prev-entry)))
    (cond
      ;; Got a definitive expected value (mainnet, retarget boundary, or first period)
      (expected
       (if (= block-bits expected)
           (values t nil)
           (values nil :bad-difficulty)))

      ;; Testnet non-boundary: check min-difficulty or walk-back
      ;; Applies to testnet3 and testnet4 (fPowAllowMinDifficultyBlocks=true)
      ((member bitcoin-lisp:*network* '(:testnet3 :testnet4))
       (let* ((prev-header (bitcoin-lisp.storage:block-index-entry-header prev-entry))
              (prev-timestamp (bitcoin-lisp.serialization:block-header-timestamp prev-header))
              (block-timestamp (bitcoin-lisp.serialization:block-header-timestamp header))
              (min-diff-allowed (testnet-min-difficulty-allowed-p
                                 block-timestamp prev-timestamp)))
         ;; >20 min gap: accept min-difficulty bits directly
         (if (and min-diff-allowed (= block-bits bitcoin-lisp.storage:+pow-limit-bits+))
             (values t nil)
             ;; Otherwise (<=20 min, or >20 min with non-min bits): must match walk-back
             (let ((walk-back-bits (testnet-walk-back-bits prev-entry)))
               (if (= block-bits walk-back-bits)
                   (values t nil)
                   (values nil :bad-difficulty))))))

      ;; Shouldn't reach here, but reject if we do
      (t (values nil :bad-difficulty)))))

;;;; Proof of Work validation

(defun check-proof-of-work (header)
  "Verify the block hash meets the claimed target. Mirrors Bitcoin Core
CheckProofOfWork (pow.cpp:161-171): reject nBits whose target is
negative, zero, overflowing, or above the PoW limit (derive-target
returns NIL), then require hash <= target. Returns T if valid."
  (let ((target (bitcoin-lisp.storage:derive-target
                 (bitcoin-lisp.serialization:block-header-bits header))))
    (when target
      (let* ((hash (bitcoin-lisp.serialization:block-header-hash header))
             ;; little-endian: byte 0 is least significant
             (hash-value (loop for i from 0 below 32
                               for byte = (aref hash i)
                               sum (ash byte (* 8 i)))))
        (<= hash-value target)))))

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

(defun bip94-timewarp-violation-p (header height prev-entry)
  "T if HEADER violates the BIP 94 timewarp-attack rule: on testnet4, the
first block of each difficulty-adjustment period (HEIGHT a nonzero
multiple of the adjustment interval) must be timestamped no more than
+max-timewarp+ seconds before its predecessor's ACTUAL time (not MTP).
enforce_BIP94 is true only on testnet4 among our networks. Genesis is
excluded — it satisfies the modulo but has no predecessor. Mirrors
Bitcoin Core ContextualCheckBlockHeader (validation.cpp:4129-4136)."
  (and (eq bitcoin-lisp:*network* :testnet4)
       height prev-entry (plusp height)
       (zerop (mod height bitcoin-lisp.storage:+difficulty-adjustment-interval+))
       (< (bitcoin-lisp.serialization:block-header-timestamp header)
          (- (bitcoin-lisp.serialization:block-header-timestamp
              (bitcoin-lisp.storage:block-index-entry-header prev-entry))
             +max-timewarp+))))

(defun validate-block-header (header chain-state current-time
                               &key prev-hash height prev-entry)
  "Validate a block header.
PREV-HASH is the hash of the previous block (for MTP calculation).
HEIGHT and PREV-ENTRY are optional; when provided, difficulty adjustment is validated.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."

  ;; Check proof of work
  (unless (check-proof-of-work header)
    (return-from validate-block-header
      (values nil :bad-proof-of-work)))

  ;; Check timestamp not too far in future
  (let ((timestamp (bitcoin-lisp.serialization:block-header-timestamp header)))
    (when (> timestamp (+ current-time +max-future-block-time+))
      (return-from validate-block-header
        (values nil :time-too-new)))

    ;; Check timestamp > median-time-past of previous 11 blocks
    (when (and chain-state prev-hash)
      (let ((mtp (compute-median-time-past chain-state prev-hash)))
        (when (<= timestamp mtp)
          (return-from validate-block-header
            (values nil :time-too-old)))))

    ;; BIP 94 timewarp-attack mitigation (see bip94-timewarp-violation-p).
    (when (bip94-timewarp-violation-p header height prev-entry)
      (return-from validate-block-header
        (values nil :time-timewarp-attack))))

  ;; Version check: enforce minimum version after softfork activation
  ;; Matches Bitcoin Core ContextualCheckBlockHeader (validation.cpp:4145-4147)
  (let ((version (bitcoin-lisp.serialization:block-header-version header)))
    (when (or (< version 1)
              (> version #x3FFFFFFF)
              (and height
                   (or (and (< version 2)
                            (>= height (get-bip34-activation-height bitcoin-lisp:*network*)))
                       (and (< version 3)
                            (>= height (get-bip66-activation-height bitcoin-lisp:*network*)))
                       (and (< version 4)
                            (>= height (get-bip65-activation-height bitcoin-lisp:*network*))))))
      (return-from validate-block-header
        (values nil :bad-version))))

  ;; Validate difficulty adjustment
  (when (and height prev-entry)
    (multiple-value-bind (valid error)
        (validate-difficulty header height prev-entry)
      (unless valid
        (return-from validate-block-header
          (values nil error)))))

  (values t nil))

;;;; Block script validation

(defun block-is-bip16-exception-p (block)
  "Check if this block is a BIP 16 exception that should skip script validation."
  (let ((block-hash (bitcoin-lisp.serialization:block-header-hash
                     (bitcoin-lisp.serialization:bitcoin-block-header block))))
    (or (equalp block-hash *bip16-exception-testnet*)
        (equalp block-hash *bip16-exception-mainnet*))))

(defparameter +parallel-validation-min-txs+ 16
  "Below this tx count we validate sequentially — thread-spawn overhead
   exceeds the parallel speedup for tiny blocks. Bitcoin Core's
   CCheckQueue uses a similar batching threshold.")

(defparameter +parallel-validation-workers+ 4
  "Number of worker threads for parallel block-script validation.
   Set to ~CPU-count for best throughput. 4 is a safe default for
   testnet sync on modest hardware; bordeaux-threads imposes minimal
   overhead per spawn.")

(defun validate-tx-scripts (tx tx-idx utxo-set script-flags height)
  "Validate all input scripts of a single transaction. Returns
T on success or NIL on failure. Designed to be safe to call from
worker threads — binds all required specials locally."
  (let* ((tx-inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (spent-utxos (collect-spent-utxos tx-inputs utxo-set))
         (bitcoin-lisp.coalton.interop:*script-flags* script-flags)
         (bitcoin-lisp.coalton.interop:*precomputed-sighash*
           (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx spent-utxos))
         (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent-utxos))
    (loop for input in tx-inputs
          for input-idx from 0
          for utxo = (and spent-utxos (aref spent-utxos input-idx))
          when utxo
            do (unless (validate-input-script tx input-idx utxo)
                 ;; Re-run with debug to capture the preimage for the log line
                 (let ((bitcoin-lisp.coalton.interop:*debug-bip341-sighash* t))
                   (validate-input-script tx input-idx utxo))
                 (let ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                       (witness (nth input-idx
                                     (bitcoin-lisp.serialization:transaction-witness tx))))
                   (bitcoin-lisp:log-warn
                    "SCRIPT-FAILED: height=~D tx-idx=~D input-idx=~D prev-txid=~A:~D scriptpubkey=~A scriptsig=~A witness-items=~D witness=~A flags=~A"
                    height tx-idx input-idx
                    (bitcoin-lisp.crypto:bytes-to-hex
                     (bitcoin-lisp.serialization:outpoint-hash prevout))
                    (bitcoin-lisp.serialization:outpoint-index prevout)
                    (bitcoin-lisp.crypto:bytes-to-hex
                     (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo))
                    (bitcoin-lisp.crypto:bytes-to-hex
                     (bitcoin-lisp.serialization:tx-in-script-sig input))
                    (length witness)
                    (format nil "[~{~A~^,~}]"
                            (mapcar #'bitcoin-lisp.crypto:bytes-to-hex witness))
                    bitcoin-lisp.coalton.interop:*script-flags*))
                 (return-from validate-tx-scripts nil))
          finally (return t))))

(defun validate-block-scripts-parallel (txs script-flags utxo-set height)
  "Validate all non-coinbase tx scripts in TXS across N worker threads.
Returns T on success or NIL on the first script failure.

Bitcoin Core uses CCheckQueue with a thread pool to do the same — every
sig check is independent across inputs and txs, so this parallelizes
cleanly. The shared sig-cache uses SBCL :synchronized hash-tables for
safe concurrent access."
  (let* ((non-coinbase (rest txs))
         (n-txs (length non-coinbase))
         (n-workers (min +parallel-validation-workers+ n-txs))
         ;; Partition tx indices round-robin across workers so each gets
         ;; a roughly even mix of light and heavy txs.
         (tx-vec (coerce non-coinbase 'vector))
         (failure-flag (cons nil nil))   ; mutable shared cell
         (failure-lock (bt:make-lock "block-script-failure"))
         (threads '()))
    ;; Spawn workers via LOOP, which fresh-binds the iteration variable
    ;; each iteration. SBCL's dotimes shares one binding across iterations
    ;; (verified empirically), so closures captured inside dotimes all
    ;; see the FINAL value — every worker thread would loop the same
    ;; index range and fail to partition work. Replacing dotimes with
    ;; loop fixes the partitioning so each thread gets distinct txs.
    (loop for worker-id below n-workers
          do (push (bt:make-thread
                    (let ((wid worker-id))   ; defensive freeze
                      (lambda ()
                        (loop for i from wid below n-txs by n-workers
                              do (when (car failure-flag) (return))
                                 (let ((tx (aref tx-vec i))
                                       ;; tx-idx is 1-based to match
                                       ;; original (rest transactions).
                                       (tx-idx (1+ i)))
                                   (unless (validate-tx-scripts tx tx-idx utxo-set
                                                                script-flags height)
                                     (bt:with-lock-held (failure-lock)
                                       (setf (car failure-flag) t))
                                     (return))))))
                    :name (format nil "script-check-~D" worker-id))
                   threads))
    (dolist (th threads)
      (bt:join-thread th))
    (not (car failure-flag))))

(defun validate-block-scripts (block utxo-set &key (height 0))
  "Validate all non-coinbase transaction scripts in BLOCK via Coalton interop.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure.
Uses validate-input-script for each input (shared with transaction validation).
Blocks matching BIP 16 exception hashes skip all script validation.
HEIGHT is used to determine which script verification flags to enable."
  ;; Check for BIP 16 exception block - skip ALL script validation
  (when (block-is-bip16-exception-p block)
    (return-from validate-block-scripts (values t nil)))

  (let ((script-flags (compute-script-flags-for-height height))
        (transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
    ;; For non-tiny blocks, parallelize tx-script validation across workers.
    ;; Sequential path is kept for tiny blocks where thread-spawn overhead
    ;; dominates the speedup.
    (if (and (>= (length (rest transactions)) +parallel-validation-min-txs+)
             (> +parallel-validation-workers+ 1))
        (if (validate-block-scripts-parallel transactions script-flags utxo-set height)
            (values t nil)
            (values nil :script-failed))
        ;; Sequential fallback (kept verbatim from the pre-Phase-3 path).
        (let ((bitcoin-lisp.coalton.interop:*script-flags* script-flags))
          (loop for tx in (rest transactions)
                for tx-idx from 1
                do (unless (validate-tx-scripts tx tx-idx utxo-set
                                                script-flags height)
                     (return-from validate-block-scripts
                       (values nil :script-failed))))
          (values t nil)))))


;;;; Witness commitment validation (BIP 141)

(defvar *witness-commitment-header*
  (make-array 4 :element-type '(unsigned-byte 8)
                :initial-contents '(#xaa #x21 #xa9 #xed))
  "4-byte commitment header for witness data in coinbase OP_RETURN.")

(defun find-witness-commitment (coinbase-tx)
  "Find the witness commitment in a coinbase transaction's outputs.
BIP 141: The commitment is in the last OP_RETURN output matching the
header 0xaa21a9ed. Returns the 32-byte commitment hash or NIL."
  (let ((outputs (bitcoin-lisp.serialization:transaction-outputs coinbase-tx))
        (commitment nil))
    ;; Scan all outputs; use the last matching one (per BIP 141)
    (dolist (output outputs)
      (let ((script (bitcoin-lisp.serialization:tx-out-script-pubkey output)))
        (when (and (>= (length script) 38)   ; OP_RETURN + push36 + 4-byte header + 32-byte hash
                   (= (aref script 0) #x6a)  ; OP_RETURN
                   (= (aref script 1) #x24)  ; push 36 bytes
                   (equalp (subseq script 2 6) *witness-commitment-header*))
          (setf commitment (subseq script 6 38)))))
    commitment))

(defun block-has-witness-data-p (block)
  "Check if any transaction in the block has witness data."
  (some #'bitcoin-lisp.serialization:transaction-has-witness-p
        (bitcoin-lisp.serialization:bitcoin-block-transactions block)))

(defun compute-witness-merkle-root (transactions)
  "Compute the witness merkle root from a list of transactions.
Uses wtxids for all transactions. The coinbase wtxid is 32 zero bytes (per BIP 141)."
  (let ((wtxids (mapcar #'bitcoin-lisp.serialization:transaction-wtxid transactions)))
    (compute-merkle-root wtxids)))

(defun validate-witness-commitment (block segwit-active)
  "BIP 141 witness-malleation check. Mirrors Bitcoin Core's
CheckWitnessMalleation (validation.cpp:3902-3948).

SEGWIT-ACTIVE is whether the segwit deployment is active for this block
(Core's expect_witness_commitment). When active and the coinbase carries
a witness commitment output, the coinbase witness stack must be exactly
one 32-byte reserved value (:bad-witness-nonce-size) and the commitment
must equal hash256(witness-merkle-root || reserved-value)
(:bad-witness-merkle-match). Otherwise — segwit inactive, or active with
no commitment present — no transaction may carry witness data at all
(:unexpected-witness). Returns (VALUES T NIL) on success.

Note: the gate is segwit activation, NOT whether the block happens to
carry witness data — a pre-segwit block with witness data must be
rejected, and the no-commitment+witness case is :unexpected-witness
(Core has no separate \"missing commitment\" error here)."
  (let ((transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
    (when segwit-active
      (let* ((coinbase-tx (first transactions))
             (commitment (find-witness-commitment coinbase-tx)))
        (when commitment
          ;; Coinbase input-0 witness stack must be exactly one 32-byte item.
          (let ((cb-stack (first (bitcoin-lisp.serialization:transaction-witness
                                  coinbase-tx))))
            (unless (and (= (length cb-stack) 1)
                         (= (length (first cb-stack)) 32))
              (return-from validate-witness-commitment
                (values nil :bad-witness-nonce-size)))
            (let* ((reserved (first cb-stack))
                   (witness-root (compute-witness-merkle-root transactions))
                   (combined (make-array 64 :element-type '(unsigned-byte 8))))
              (replace combined witness-root :start1 0)
              (replace combined reserved :start1 32)
              (unless (equalp (bitcoin-lisp.crypto:hash256 combined) commitment)
                (return-from validate-witness-commitment
                  (values nil :bad-witness-merkle-match)))))
          ;; Valid commitment — accept without the unexpected-witness scan.
          (return-from validate-witness-commitment (values t nil)))))
    ;; Segwit inactive, or active with no commitment output: no transaction
    ;; may carry witness data.
    (dolist (tx transactions)
      (when (bitcoin-lisp.serialization:transaction-has-witness-p tx)
        (return-from validate-witness-commitment
          (values nil :unexpected-witness))))
    (values t nil)))

;;;; BIP 34 Coinbase Height Validation

(defconstant +bip34-activation-height-testnet3+ 21111
  "BIP 34 activation height on testnet.")

(defconstant +bip34-activation-height-mainnet+ 227931
  "BIP 34 activation height on mainnet.")

(defun get-bip34-activation-height (network)
  "Return the BIP 34 activation height for NETWORK."
  (ecase network
    (:testnet3 +bip34-activation-height-testnet3+)
    ((:testnet4 :signet) 1)
    (:mainnet +bip34-activation-height-mainnet+)))

(defconstant +bip34-implies-bip30-limit+ 1983702
  "BIP 30 is re-enforced unconditionally at this height and above: past
this point the BIP 34 height-in-coinbase guarantee can no longer rule
out duplicate coinbases (pre-BIP34 blocks exist with indicated heights
above it), so the optimization of skipping BIP 30 after BIP 34 is
dropped. Bitcoin Core BIP34_IMPLIES_BIP30_LIMIT (validation.cpp:2427).")

(defun bip30-repeat-block-p (height)
  "T for the two grandfathered mainnet blocks (91842, 91880) that contain
duplicate coinbases predating BIP 30 enforcement; BIP 30 must NOT be
enforced on them or they would be wrongly rejected. Bitcoin Core
IsBIP30Repeat (validation.cpp:6208). Only mainnet has these. (We match on
height only, not the block hash Core also checks — forging a pre-BIP34
mainnet fork to these heights is infeasible, and no other network has
repeat blocks.)"
  (and (eq bitcoin-lisp:*network* :mainnet)
       (or (= height 91842) (= height 91880))))

(defun bip30-enforced-p (height)
  "Whether the BIP 30 duplicate-coinbase check must run for a block at
HEIGHT: enforced below BIP 34 activation (except the grandfathered repeat
blocks), and again unconditionally at or above +bip34-implies-bip30-limit+.
Mirrors Bitcoin Core ConnectBlock (validation.cpp:2399-2464). Note: we
approximate Core's BIP34Hash-ancestor test with a height comparison,
omitting only the extra enforcement Core applies on a non-canonical fork
past the BIP 34 height — infeasible to exploit given the PoW required."
  (or (and (not (bip30-repeat-block-p height))
           (< height (get-bip34-activation-height bitcoin-lisp:*network*)))
      (>= height +bip34-implies-bip30-limit+)))

(defun encode-bip34-height (height)
  "The exact coinbase scriptSig prefix Bitcoin Core requires for a BIP 34
block at HEIGHT: the bytes of `CScript() << height`. Heights 0 and 1..16
use the minimal OP_0 / OP_1..OP_16 single opcodes; larger heights use a
minimally-encoded (positive) CScriptNum pushed as data. Returns a byte
vector. Mirrors validation.cpp:4186."
  (cond
    ((zerop height)
     (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x00))  ; OP_0
    ((<= 1 height 16)
     (make-array 1 :element-type '(unsigned-byte 8)
                 :initial-element (+ #x50 height)))                          ; OP_1..OP_16
    (t
     ;; Minimal little-endian CScriptNum bytes, with a trailing 0x00 sign
     ;; byte if the top byte would otherwise look negative; pushed as data
     ;; (opcode == byte length, always <= 75 for any real height).
     (let ((le '())
           (n height))
       (loop while (plusp n)
             do (push (logand n #xff) le)
                (setf n (ash n -8)))
       (setf le (nreverse le))
       (when (logbitp 7 (car (last le)))
         (setf le (append le (list 0))))
       (let* ((data-len (length le))
              (result (make-array (1+ data-len) :element-type '(unsigned-byte 8))))
         (setf (aref result 0) data-len)
         (loop for b in le for i from 1 do (setf (aref result i) b))
         result)))))

(defun decode-coinbase-height (script-sig)
  "Decode the claimed block height from a coinbase scriptSig, for
inspection/display only (RPC, logging). NOT the consensus check — BIP 34
validation is an exact serialized-prefix match against
`encode-bip34-height` (see validate-coinbase-height), because Core
compares bytes rather than numeric value, rejecting non-minimal encodings.
Returns the decoded height, or NIL if the leading push is malformed."
  (when (zerop (length script-sig))
    (return-from decode-coinbase-height nil))
  (let ((push-len (aref script-sig 0)))
    (cond
      ;; OP_0: height = 0
      ((zerop push-len) 0)
      ;; OP_1 through OP_16: height = 1-16
      ((<= #x51 push-len #x60)
       (1+ (- push-len #x51)))
      ;; Direct push (1-75 bytes): read little-endian integer
      ((<= 1 push-len 75)
       (when (< (length script-sig) (1+ push-len))
         (return-from decode-coinbase-height nil))
       (let ((height 0))
         (loop for i from 1 to push-len
               do (setf height (logior height (ash (aref script-sig i) (* 8 (1- i))))))
         height))
      ;; Other encodings not valid for BIP 34
      (t nil))))

(defun validate-coinbase-height (block current-height)
  "Validate BIP 34: at/above the network activation height, the coinbase
scriptSig must START WITH the exact serialized block height (the byte
prefix of `CScript() << height`). This is a byte-prefix match, not a
numeric decode, so non-minimal or wrong-form encodings are rejected even
when they would decode to the right number. Mirrors validation.cpp:4183-4191.
Returns (VALUES T NIL) on success, (VALUES NIL ERROR-KEYWORD) on failure."
  (let ((activation-height (get-bip34-activation-height bitcoin-lisp:*network*)))
    (when (< current-height activation-height)
      (return-from validate-coinbase-height (values t nil))))
  (let* ((coinbase-tx (first (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
         (first-input (first (bitcoin-lisp.serialization:transaction-inputs coinbase-tx)))
         (script-sig (bitcoin-lisp.serialization:tx-in-script-sig first-input))
         (expect (encode-bip34-height current-height)))
    (if (and (>= (length script-sig) (length expect))
             (loop for i below (length expect)
                   always (= (aref script-sig i) (aref expect i))))
        (values t nil)
        (values nil :bad-coinbase-height))))

(defun calculate-block-weight (transactions)
  "Calculate total block weight as sum of all transaction weights."
  (loop for tx in transactions
        sum (bitcoin-lisp.serialization:transaction-weight tx)))

;;;; Sigops cost calculation

(defun script-is-p2sh-p (script)
  "Check if SCRIPT is a P2SH scriptPubKey: OP_HASH160 <20 bytes> OP_EQUAL."
  (and (= (length script) 23)
       (= (aref script 0) +op-hash160+)
       (= (aref script 1) 20)       ; Push 20 bytes
       (= (aref script 22) +op-equal+)))

(defun extract-last-push (script)
  "Extract the data from the last push operation in SCRIPT.
Used to get the redeemScript from a P2SH scriptSig.
Tracks indices and allocates only once at the end."
  (let ((len (length script))
        (i 0)
        (last-start nil)
        (last-end nil))
    (loop while (< i len)
          do (let ((opcode (aref script i)))
               (cond
                 ((<= 1 opcode 75)
                  (let ((end (min (+ i 1 opcode) len)))
                    (setf last-start (1+ i) last-end end i end)))
                 ((= opcode +op-pushdata1+)
                  (if (< (1+ i) len)
                      (let* ((size (aref script (1+ i)))
                             (end (min (+ i 2 size) len)))
                        (setf last-start (+ i 2) last-end end i end))
                      (return)))
                 ((= opcode +op-pushdata2+)
                  (if (< (+ i 2) len)
                      (let* ((size (logior (aref script (1+ i))
                                           (ash (aref script (+ i 2)) 8)))
                             (end (min (+ i 3 size) len)))
                        (setf last-start (+ i 3) last-end end i end))
                      (return)))
                 ((= opcode +op-pushdata4+)
                  (if (< (+ i 4) len)
                      (let* ((size (logior (aref script (1+ i))
                                           (ash (aref script (+ i 2)) 8)
                                           (ash (aref script (+ i 3)) 16)
                                           (ash (aref script (+ i 4)) 24)))
                             (end (min (+ i 5 size) len)))
                        (setf last-start (+ i 5) last-end end i end))
                      (return)))
                 (t (incf i)))))
    (when (and last-start last-end)
      (subseq script last-start last-end))))

(defun count-legacy-sigops (tx)
  "Count legacy (inaccurate) sigops across all scriptSigs and scriptPubKeys of TX."
  (let ((count 0))
    (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (incf count (count-script-sigops
                   (bitcoin-lisp.serialization:tx-in-script-sig input))))
    (dolist (output (bitcoin-lisp.serialization:transaction-outputs tx))
      (incf count (count-script-sigops
                   (bitcoin-lisp.serialization:tx-out-script-pubkey output))))
    count))

(defun count-witness-sigops-for-input (script-pubkey witness)
  "Count witness sigops for a single input given its spent SCRIPT-PUBKEY and WITNESS.
Returns 1 for P2WPKH, counts from witness script for P2WSH."
  (let ((len (length script-pubkey)))
    (cond
      ;; P2WPKH: OP_0 <20 bytes>
      ((and (= len 22) (= (aref script-pubkey 0) +op-0+) (= (aref script-pubkey 1) 20))
       1)
      ;; P2WSH: OP_0 <32 bytes>
      ((and (= len 34) (= (aref script-pubkey 0) +op-0+) (= (aref script-pubkey 1) 32))
       (if witness
           (let ((witness-script (car (last witness))))
             (if witness-script
                 (count-script-sigops witness-script :accurate t)
                 0))
           0))
      (t 0))))

(defun count-p2sh-and-witness-sigops (tx get-spent-script)
  "Count P2SH and witness sigops in a single pass over TX inputs.
Returns (VALUES p2sh-count witness-count).
GET-SPENT-SCRIPT takes (txid index) and returns the spent scriptPubKey."
  (let ((p2sh-count 0)
        (witness-count 0))
    (loop for input in (bitcoin-lisp.serialization:transaction-inputs tx)
          for input-idx from 0
          do (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
                    (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
                    (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
                    (script-pubkey (funcall get-spent-script prev-txid prev-index)))
               (when script-pubkey
                 (cond
                   ;; Native witness program
                   ((script-is-witness-program-p script-pubkey)
                    (let ((witness (get-input-witness tx input-idx)))
                      (incf witness-count (count-witness-sigops-for-input
                                           script-pubkey witness))))
                   ;; P2SH input
                   ((script-is-p2sh-p script-pubkey)
                    (let ((redeem-script (extract-last-push
                                          (bitcoin-lisp.serialization:tx-in-script-sig input))))
                      (when redeem-script
                        ;; P2SH sigops from redeemScript
                        (incf p2sh-count (count-script-sigops redeem-script :accurate t))
                        ;; P2SH-wrapped witness program
                        (when (script-is-witness-program-p redeem-script)
                          (let ((witness (get-input-witness tx input-idx)))
                            (incf witness-count (count-witness-sigops-for-input
                                                 redeem-script witness)))))))))))
    (values p2sh-count witness-count)))

(defun count-transaction-sigops-cost (tx get-spent-script &key (count-p2sh t) (count-witness t))
  "Calculate the weighted sigops cost for TX (BIP 141).
Cost = (legacy + p2sh) * WITNESS_SCALE_FACTOR + witness.
GET-SPENT-SCRIPT takes (txid index) and returns the spent scriptPubKey.

COUNT-P2SH / COUNT-WITNESS gate the P2SH and witness sigops on their activation,
mirroring Bitcoin Core's GetTransactionSigOpCost, which only adds P2SH sigops
when SCRIPT_VERIFY_P2SH is set and witness sigops when SCRIPT_VERIFY_WITNESS is
set (tx_verify.cpp). Legacy sigops are always counted."
  (let ((legacy (count-legacy-sigops tx)))
    (if (or count-p2sh count-witness)
        (multiple-value-bind (p2sh witness)
            (count-p2sh-and-witness-sigops tx get-spent-script)
          (+ (* (+ legacy (if count-p2sh p2sh 0)) +witness-scale-factor+)
             (if count-witness witness 0)))
        (* legacy +witness-scale-factor+))))

;;;; Full block validation

(defun validate-block (block chain-state utxo-set current-height current-time
                        &key skip-scripts)
  "Fully validate a block including all transactions.
When SKIP-SCRIPTS is true, script validation is skipped (used during IBD for
blocks below the last checkpoint, matching Bitcoin Core behavior).
Returns (VALUES T NIL FEES) on success, (VALUES NIL ERROR-KEYWORD NIL) on failure."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block)))

    ;; Validate header (with difficulty check when prev-entry is available)
    (let ((prev-hash (bitcoin-lisp.serialization:block-header-prev-block header)))
      (multiple-value-bind (valid error)
          (validate-block-header header chain-state current-time
                                 :prev-hash prev-hash
                                 :height current-height
                                 :prev-entry (bitcoin-lisp.storage:get-block-index-entry
                                              chain-state prev-hash))
        (unless valid
          (return-from validate-block (values nil error nil)))))

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

    ;; Validate block weight (BIP 141)
    (let ((weight (calculate-block-weight transactions)))
      (when (> weight +max-block-weight+)
        (return-from validate-block
          (values nil :block-too-heavy nil))))

    ;; Legacy block size limit (non-witness serialization must fit in 1 MB)
    (let ((base-size (+ 80  ; header
                        (bitcoin-lisp.serialization:compact-size-length
                         (length transactions))
                        (loop for tx in transactions
                              sum (length
                                   (bitcoin-lisp.serialization:serialize-transaction tx))))))
      (when (> base-size +max-block-size+)
        (return-from validate-block
          (values nil :block-too-large nil))))

    ;; BIP 30: reject a block that re-creates a still-unspent txid.
    (when (bip30-enforced-p current-height)
      (dolist (tx transactions)
        (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
          (when (bitcoin-lisp.storage:any-utxo-for-txid-p utxo-set txid)
            (return-from validate-block
              (values nil :duplicate-txid nil))))))

    ;; Validate each transaction and collect fees (using Satoshi type)
    ;; Track outputs from earlier transactions for intra-block spending
    (let* ((total-fees (wrap-satoshi 0))
           (total-sigops-cost 0)
           (pending-utxos (make-hash-table :test 'equalp))
           ;; Gate P2SH/witness sigop counting on the block's active flags,
           ;; exactly as Bitcoin Core passes GetBlockScriptFlags into
           ;; GetTransactionSigOpCost. Same source of truth as script validation.
           (active-flags (mandatory-script-flags-list current-height))
           (count-p2sh (and (member "P2SH" active-flags :test #'string=) t))
           (count-witness (and (member "WITNESS" active-flags :test #'string=) t)))

      ;; UTXO lookup function for sigops counting
      (flet ((get-spent-script (txid index)
               (let ((utxo (or (gethash (cons txid index) pending-utxos)
                               (bitcoin-lisp.storage:get-utxo utxo-set txid index))))
                 (when utxo
                   (bitcoin-lisp.storage:utxo-entry-script-pubkey utxo)))))

        ;; Validate coinbase structure (skip input validation)
        (let ((coinbase-tx (first transactions)))
          (multiple-value-bind (valid error)
              (validate-transaction-structure coinbase-tx)
            (unless valid
              (return-from validate-block (values nil error nil))))
          ;; Coinbase sigops: legacy only (no inputs to look up), scaled by witness factor
          (incf total-sigops-cost (* (count-legacy-sigops coinbase-tx) +witness-scale-factor+))
          ;; Add coinbase outputs to pending (for intra-block spending)
          (let ((txid (bitcoin-lisp.serialization:transaction-hash coinbase-tx)))
            (loop for output in (bitcoin-lisp.serialization:transaction-outputs coinbase-tx)
                  for idx from 0
                  do (setf (gethash (cons txid idx) pending-utxos)
                           (bitcoin-lisp.storage::make-utxo-entry
                            :value (bitcoin-lisp.serialization:tx-out-value output)
                            :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                            :height current-height
                            :coinbase t)))))

        ;; Validate other transactions
        (loop for tx in (rest transactions)
              do (multiple-value-bind (valid error)
                     (validate-transaction-structure tx)
                   (unless valid
                     (return-from validate-block (values nil error nil))))
                 (multiple-value-bind (valid error fee)
                     (validate-transaction-contextual tx utxo-set current-height
                                                      :pending-utxos pending-utxos)
                   (unless valid
                     (return-from validate-block (values nil error nil)))
                   ;; fee is now a Satoshi type, use typed addition
                   (setf total-fees (satoshi+ total-fees fee)))
                 ;; Accumulate sigops cost and check limit (early exit for DoS protection)
                 (incf total-sigops-cost
                       (count-transaction-sigops-cost tx #'get-spent-script
                                                      :count-p2sh count-p2sh
                                                      :count-witness count-witness))
                 (when (> total-sigops-cost +max-block-sigops-cost+)
                   (return-from validate-block
                     (values nil :too-many-sigops nil)))
                 ;; Add this transaction's outputs to pending for subsequent txs
                 (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
                   (loop for output in (bitcoin-lisp.serialization:transaction-outputs tx)
                         for idx from 0
                         do (setf (gethash (cons txid idx) pending-utxos)
                                  (bitcoin-lisp.storage::make-utxo-entry
                                   :value (bitcoin-lisp.serialization:tx-out-value output)
                                   :script-pubkey (bitcoin-lisp.serialization:tx-out-script-pubkey output)
                                   :height current-height
                                   :coinbase nil))))))

      ;; Transaction finality check (IsFinalTx) and BIP 68 sequence locks
      (let* ((prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
             (mtp (compute-median-time-past chain-state prev-hash))
             (csv-height (get-csv-activation-height bitcoin-lisp:*network*))
             (csv-active (>= current-height csv-height))
             ;; For IsFinalTx: use MTP after BIP 113 activation, block timestamp before
             (locktime-check-time (if csv-active
                                      mtp
                                      (bitcoin-lisp.serialization:block-header-timestamp header))))
        ;; Check finality for all non-coinbase transactions
        (loop for tx in (rest transactions)
              unless (check-transaction-final tx current-height locktime-check-time)
                do (return-from validate-block (values nil :non-final-tx nil)))
        ;; BIP 68 sequence lock enforcement (only at or above CSV activation)
        (when csv-active
          (loop for tx in (rest transactions)
                unless (check-sequence-locks tx utxo-set current-height mtp chain-state
                                             :pending-utxos pending-utxos)
                  do (return-from validate-block (values nil :bad-sequence-lock nil)))))

      ;; Validate transaction scripts via Coalton interop
      ;; Skip during IBD for blocks below the last checkpoint (performance optimization)
      (unless skip-scripts
        (multiple-value-bind (valid error)
            (validate-block-scripts block utxo-set :height current-height)
          (unless valid
            (return-from validate-block (values nil error nil)))))

      ;; Validate witness commitment / malleation (BIP 141). Gated on
      ;; segwit activation for this height, matching Core's
      ;; expect_witness_commitment = DeploymentActiveAfter(prev, SEGWIT).
      (multiple-value-bind (valid error)
          (validate-witness-commitment
           block
           (>= current-height
               (get-segwit-activation-height bitcoin-lisp:*network*)))
        (unless valid
          (return-from validate-block (values nil error nil))))

      ;; Validate BIP 34 coinbase height
      (multiple-value-bind (valid error)
          (validate-coinbase-height block current-height)
        (unless valid
          (return-from validate-block (values nil error nil))))

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

;;;; Undo data for chain reorganizations

(defvar *block-undo-data* (make-hash-table :test 'equalp)
  "In-memory cache: maps block-hash -> list of (txid index utxo-entry).")

(defvar *undo-base-path* nil
  "Base directory for undo data files. Set during node startup.")

(defconstant +max-undo-cache+ 100
  "Maximum number of blocks to keep in the in-memory undo cache.")

(defvar *undo-cache-heights* (make-hash-table :test 'equalp)
  "Maps block-hash -> height for cache eviction ordering.")

(defvar *undo-magic* (map '(vector (unsigned-byte 8)) #'char-code "UNDO")
  "Magic bytes identifying an undo data file.")

(defconstant +undo-format-version+ 1
  "Current undo data file format version.")

(defun initialize-undo-storage (base-path)
  "Initialize undo data persistence with BASE-PATH as the storage directory."
  (ensure-directories-exist base-path)
  (setf *undo-base-path* base-path))

(defun undo-file-path (block-hash)
  "Return the path for an undo data file given BLOCK-HASH."
  (when *undo-base-path*
    (merge-pathnames
     (make-pathname :name (bitcoin-lisp.crypto:bytes-to-hex block-hash)
                    :type "dat")
     *undo-base-path*)))

(defun save-undo-data-to-disk (block-hash spent-utxos)
  "Serialize spent-utxos to an undo file using atomic temp+rename with CRC32."
  (let ((path (undo-file-path block-hash)))
    (when path
      (bitcoin-lisp.storage:save-file-with-crc32
       path
       (lambda (stream)
         (write-sequence *undo-magic* stream)
         (bitcoin-lisp.serialization:write-uint32-le stream +undo-format-version+)
         (bitcoin-lisp.serialization:write-uint32-le stream (length spent-utxos))
         (dolist (entry spent-utxos)
           (destructuring-bind (txid index utxo) entry
             (write-sequence txid stream)
             (bitcoin-lisp.serialization:write-uint32-le stream index)
             (bitcoin-lisp.storage:write-utxo-entry-fields stream utxo))))))))

(defun load-undo-data-from-disk (block-hash)
  "Load and verify undo data from disk. Returns list of (txid index utxo-entry) or NIL."
  (let ((path (undo-file-path block-hash)))
    (when path
      (let ((data (bitcoin-lisp.storage:load-file-with-crc32 path 16)))
        (when data
          (handler-case
              (flexi-streams:with-input-from-sequence (stream data)
                (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
                  (read-sequence magic stream)
                  (unless (equalp magic *undo-magic*)
                    (return-from load-undo-data-from-disk nil)))
                (let ((version (bitcoin-lisp.serialization:read-uint32-le stream)))
                  (unless (= version +undo-format-version+)
                    (return-from load-undo-data-from-disk nil)))
                (let* ((count (bitcoin-lisp.serialization:read-uint32-le stream))
                       (entries '()))
                  (dotimes (i count)
                    (let* ((txid (make-array 32 :element-type '(unsigned-byte 8)))
                           (_ (read-sequence txid stream))
                           (index (bitcoin-lisp.serialization:read-uint32-le stream))
                           (utxo (bitcoin-lisp.storage:read-utxo-entry-fields stream)))
                      (declare (ignore _))
                      (push (list txid index utxo) entries)))
                  (nreverse entries)))
            (error (c)
              (bitcoin-lisp:log-warn "Failed to load undo data: ~A" c)
              nil)))))))

(defun evict-undo-cache ()
  "Evict the oldest half of cache entries by height (they remain on disk)."
  (let ((entries '()))
    (maphash (lambda (hash height)
               (push (cons hash height) entries))
             *undo-cache-heights*)
    (setf entries (sort entries #'< :key #'cdr))
    (let ((to-evict (subseq entries 0 (floor (length entries) 2))))
      (dolist (pair to-evict)
        (remhash (car pair) *block-undo-data*)
        (remhash (car pair) *undo-cache-heights*)))))

(defun store-undo-data (block-hash spent-utxos height)
  "Store undo data for a block to disk and in-memory cache."
  (save-undo-data-to-disk block-hash spent-utxos)
  (setf (gethash block-hash *block-undo-data*) spent-utxos)
  (setf (gethash block-hash *undo-cache-heights*) height)
  (when (> (hash-table-count *block-undo-data*) +max-undo-cache+)
    (evict-undo-cache)))

(defun get-undo-data (block-hash)
  "Get undo data for a block. Checks in-memory cache first, then disk."
  (or (gethash block-hash *block-undo-data*)
      (let ((loaded (load-undo-data-from-disk block-hash)))
        (when loaded
          (setf (gethash block-hash *block-undo-data*) loaded))
        loaded)))

;;;; Block connection

(defun connect-block (block chain-state block-store utxo-set
                      &key tx-index fee-estimator recent-rejects mempool)
  "Connect a validated block to the chain.
Updates chain state and UTXO set.
Optionally updates TX-INDEX if provided and enabled.
Optionally updates FEE-ESTIMATOR with block fee statistics.
Optionally clears RECENT-REJECTS on chain reorganization.
When MEMPOOL is provided, removes the block's confirmed/conflicting txs from it
(the single removal chokepoint — every connect path, IBD or relay, goes here).
Handles chain reorganizations when a competing chain has more work."
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

      ;; Check if we need a reorganization
      (let* ((current-best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
             (current-best-entry (bitcoin-lisp.storage:get-block-index-entry
                                  chain-state current-best-hash))
             (current-best-work (if current-best-entry
                                    (bitcoin-lisp.storage:block-index-entry-chain-work
                                     current-best-entry)
                                    0)))

        (cond
          ;; New block extends the current best chain (normal case).
          ;; Apply UTXO updates and advance chain tip atomically — without-
          ;; interrupts defers any pending bt:destroy-thread / SIGTERM until
          ;; this critical section completes, so saved state on disk is never
          ;; "chain advanced but UTXOs not applied" or vice versa.
          ((equalp prev-hash current-best-hash)
           #+sbcl (sb-sys:without-interrupts
           (let ((spent-utxos (bitcoin-lisp.storage:apply-block-to-utxo-set
                               utxo-set block new-height)))
             (store-undo-data hash spent-utxos new-height)
             ;; Record fee statistics for fee estimation
             (when fee-estimator
               (let ((stats (bitcoin-lisp.mempool:compute-block-fee-stats
                             block spent-utxos new-height)))
                 (when stats
                   (bitcoin-lisp.mempool:fee-estimator-add-stats fee-estimator stats)
                   (bitcoin-lisp.mempool:maybe-flush-fee-stats fee-estimator)))))
           ;; Update transaction index if enabled
           (when (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
             (bitcoin-lisp.storage:txindex-add-block tx-index block hash))
           (bitcoin-lisp.storage:update-chain-tip chain-state hash new-height)
           ;; Remove now-confirmed (and conflicting) txs from the mempool,
           ;; inside the same critical section as the tip update.
           (when mempool
             (bitcoin-lisp.mempool:mempool-remove-for-block mempool block)))
           (bitcoin-lisp:maybe-periodic-flush)
           ;; Automatic block pruning after connecting a new block
           (when (bitcoin-lisp:automatic-pruning-p)
             (let ((pruned (bitcoin-lisp.storage:prune-old-blocks block-store chain-state)))
               (when (> pruned 0)
                 (bitcoin-lisp:log-info "Pruned ~D old block~:P" pruned)))))

          ;; New chain has more work - reorganize
          ((> chain-work current-best-work)
           (perform-reorg chain-state block-store utxo-set
                          current-best-entry entry
                          :tx-index tx-index
                          :fee-estimator fee-estimator
                          :recent-rejects recent-rejects
                          :mempool mempool))

          ;; New block is on a weaker chain - just store it
          (t nil)))

      entry)))

(defun find-fork-point (entry-a entry-b)
  "Find the common ancestor (fork point) of two chain entries.
Returns the common ancestor block-index-entry."
  ;; Walk both chains back until we find a common block
  (let ((a entry-a)
        (b entry-b))
    ;; First, align heights
    (loop while (and a b (> (bitcoin-lisp.storage:block-index-entry-height a)
                            (bitcoin-lisp.storage:block-index-entry-height b)))
          do (setf a (bitcoin-lisp.storage:block-index-entry-prev-entry a)))
    (loop while (and a b (> (bitcoin-lisp.storage:block-index-entry-height b)
                            (bitcoin-lisp.storage:block-index-entry-height a)))
          do (setf b (bitcoin-lisp.storage:block-index-entry-prev-entry b)))
    ;; Walk both back until they meet
    (loop while (and a b (not (equalp (bitcoin-lisp.storage:block-index-entry-hash a)
                                      (bitcoin-lisp.storage:block-index-entry-hash b))))
          do (setf a (bitcoin-lisp.storage:block-index-entry-prev-entry a))
             (setf b (bitcoin-lisp.storage:block-index-entry-prev-entry b)))
    a))

(defun collect-chain-entries (tip-entry fork-entry)
  "Collect block-index-entries from TIP-ENTRY back to (not including) FORK-ENTRY."
  (let ((entries '())
        (entry tip-entry)
        (fork-hash (bitcoin-lisp.storage:block-index-entry-hash fork-entry)))
    (loop while (and entry
                     (not (equalp (bitcoin-lisp.storage:block-index-entry-hash entry)
                                  fork-hash)))
          do (push entry entries)
             (setf entry (bitcoin-lisp.storage:block-index-entry-prev-entry entry)))
    (nreverse entries)))

(defun readd-disconnected-txs-to-mempool (mempool txs utxo-set height)
  "Best-effort re-add of TXS from reorg-disconnected blocks into the mempool.
Each tx is re-validated against the post-reorg chain state; txs that are no
longer valid (inputs spent on the new chain, or re-confirmed by it) are silently
dropped. Mirrors Bitcoin Core re-adding disconnected-block txs after a reorg."
  (when (and mempool txs)
    (dolist (tx txs)
      (handler-case
          (multiple-value-bind (valid error fee replaced)
              (validate-transaction-for-mempool tx utxo-set mempool height)
            (declare (ignore error))
            (when valid
              (dolist (rt replaced)
                (bitcoin-lisp.mempool:mempool-remove-recursive mempool rt))
              (bitcoin-lisp.mempool:mempool-add
               mempool (bitcoin-lisp.serialization:transaction-hash tx)
               (bitcoin-lisp.mempool:make-entry-from-tx
                tx (or fee 0) height
                :entry-time (bitcoin-lisp.serialization:get-unix-time)))))
        (error () nil)))))

(defun perform-reorg (chain-state block-store utxo-set old-tip-entry new-tip-entry
                      &key tx-index fee-estimator recent-rejects mempool)
  "Perform a chain reorganization from OLD-TIP to NEW-TIP.
Disconnects blocks back to the fork point, then connects blocks on the new chain.
Optionally updates TX-INDEX if provided and enabled.
Optionally updates FEE-ESTIMATOR with block fee statistics.
Clears RECENT-REJECTS if provided (reorg may change transaction validity).
When MEMPOOL is provided, removes connected blocks' txs from it and re-adds the
disconnected blocks' txs (best-effort, re-validated against the new tip)."
  (let ((fork-entry (find-fork-point old-tip-entry new-tip-entry)))
    (unless fork-entry
      (return-from perform-reorg nil))

    (let ((old-height (bitcoin-lisp.storage:block-index-entry-height old-tip-entry))
          (new-height (bitcoin-lisp.storage:block-index-entry-height new-tip-entry))
          (fork-height (bitcoin-lisp.storage:block-index-entry-height fork-entry)))

      ;; Check if reorg requires blocks that have been pruned
      (when (bitcoin-lisp:pruning-enabled-p)
        (let ((pruned-height (bitcoin-lisp.storage:chain-state-pruned-height chain-state)))
          (when (< fork-height pruned-height)
            (bitcoin-lisp:log-error
             "REORG IMPOSSIBLE: fork point ~D is below pruned height ~D. Node must re-sync."
             fork-height pruned-height)
            (return-from perform-reorg nil))))

      ;; Collect blocks to disconnect (old chain, tip to fork)
      (let ((to-disconnect (collect-chain-entries old-tip-entry fork-entry))
            ;; Collect blocks to connect (new chain, fork to new tip)
            (to-connect (collect-chain-entries new-tip-entry fork-entry))
            ;; Per-disconnected-block non-coinbase tx lists, re-added to the
            ;; mempool after the reorg. Pushed during the tip-first disconnect
            ;; loop, so the list ends up oldest-block-first — flattening then
            ;; re-adds parents before children (a child can only spend a parent
            ;; in an equal-or-lower block).
            (disconnected-block-txs '()))

        ;; Precondition: every block on BOTH sides must be in the
        ;; block-store. If anything is missing, refuse the reorg without
        ;; mutating any state — better to defer than to leave the chain
        ;; half-disconnected and corrupt. Return the missing list so
        ;; activate-block's caller can re-queue those blocks for
        ;; download instead of looping forever on the unprocessable
        ;; incoming tip.
        (let ((missing '()))
          (dolist (entry (append to-disconnect to-connect))
            (let ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
              (unless (bitcoin-lisp.storage:get-block block-store block-hash)
                (push (cons block-hash
                            (bitcoin-lisp.storage:block-index-entry-height entry))
                      missing))))
          (when missing
            (bitcoin-lisp:log-warn
             "REORG REFUSED: ~D blocks missing from store (first: height ~D)"
             (length missing) (cdr (first missing)))
            (return-from perform-reorg (values nil missing))))

        (bitcoin-lisp:log-warn "REORG: old tip height ~D -> fork at ~D -> new tip height ~D"
                               old-height fork-height new-height)

        ;; Disconnect blocks tip-to-fork. collect-chain-entries returns
        ;; tip-first; iterate as-is. Order matters across blocks: if A
        ;; (lower) creates output O and B (higher) spends O, disconnecting
        ;; A first leaves O re-added by B's undo data — see
        ;; coin-view-disconnect-block for the analogous within-block case.
        (dolist (entry to-disconnect)
          (let* ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                 (block (bitcoin-lisp.storage:get-block block-store block-hash)))
            (when block
              (let ((undo (get-undo-data block-hash)))
                (bitcoin-lisp.storage:disconnect-block-from-utxo-set
                 utxo-set block (or undo '())))
              ;; Collect this block's non-coinbase txs (in original order) for
              ;; mempool re-add. Pushing whole per-block lists during the
              ;; tip-first loop leaves disconnected-block-txs oldest-first.
              (when mempool
                (push (rest (bitcoin-lisp.serialization:bitcoin-block-transactions block))
                      disconnected-block-txs))
              ;; Remove from txindex during reorg disconnect
              (when (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
                (bitcoin-lisp.storage:txindex-remove-block tx-index block))
              (setf (bitcoin-lisp.storage:block-index-entry-status entry) :header-valid))))

        ;; Clear recent rejects filter (reorg may change tx validity)
        (bitcoin-lisp:clear-recent-rejects recent-rejects)

        ;; Connect new chain blocks (fork to new tip)
        (dolist (entry to-connect)
          (let* ((block-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                 (block (bitcoin-lisp.storage:get-block block-store block-hash)))
            (when block
              (let* ((height (bitcoin-lisp.storage:block-index-entry-height entry))
                     (spent-utxos (bitcoin-lisp.storage:apply-block-to-utxo-set
                                   utxo-set block height)))
                (store-undo-data block-hash spent-utxos height)
                ;; Record fee statistics for fee estimation
                (when fee-estimator
                  (let ((stats (bitcoin-lisp.mempool:compute-block-fee-stats
                                block spent-utxos height)))
                    (when stats
                      (bitcoin-lisp.mempool:fee-estimator-add-stats fee-estimator stats))))
                ;; Add to txindex during reorg connect
                (when (and tx-index (bitcoin-lisp.storage:tx-index-enabled tx-index))
                  (bitcoin-lisp.storage:txindex-add-block tx-index block block-hash))
                ;; Remove this connected block's txs from the mempool.
                (when mempool
                  (bitcoin-lisp.mempool:mempool-remove-for-block mempool block))
                (setf (bitcoin-lisp.storage:block-index-entry-status entry) :valid)))))

        ;; Update chain tip
        (bitcoin-lisp.storage:update-chain-tip
         chain-state
         (bitcoin-lisp.storage:block-index-entry-hash new-tip-entry)
         new-height)

        ;; Re-add disconnected-block txs to the mempool (best-effort, against
        ;; the new tip), parents before children. Txs re-confirmed or
        ;; invalidated by the new chain are dropped by re-validation.
        (readd-disconnected-txs-to-mempool
         mempool (loop for txs in disconnected-block-txs append txs)
         utxo-set new-height)

        (bitcoin-lisp:log-info "REORG complete: disconnected ~D, connected ~D blocks"
                               (length to-disconnect) (length to-connect))

        t))))

;;;; Activate block — validate + connect with reorg awareness.
;;;;
;;;; The validate-then-connect dance in process-received-block does
;;;; validation against the current UTXO set, which is wrong when the
;;;; incoming block sits on a competing fork: its inputs reference
;;;; outputs that exist only on that fork. Validation fails MISSING-INPUT
;;;; before connect-block's chain-work comparison can dispatch to reorg.
;;;;
;;;; activate-block fixes the order: it looks at the incoming block's
;;;; parent and decides whether to extend the current tip, pre-reorg to
;;;; the parent's chain, or just store the block on a weaker side chain.
;;;; Mirrors Bitcoin Core's ActivateBestChainStep in validation.cpp,
;;;; particularly the disconnect/connect interaction before block
;;;; activation.

(defun activate-block (block chain-state block-store utxo-set
                       &key current-time skip-scripts tx-index fee-estimator
                            recent-rejects mempool)
  "Validate and activate BLOCK. Three cases:

  1. BLOCK's parent IS the current best tip — validate then connect
     (normal chain extension).
  2. BLOCK's parent is in the index but on a competing fork that, with
     this block added, has strictly more chain-work than our current
     best — pre-reorg to the parent's chain, then validate + connect.
     This is the case the old validate-then-connect order fumbled.
  3. BLOCK's parent is on a weaker chain or unknown — store the block
     for later use without activating it.

Returns (VALUES T NIL) on activation,
        (VALUES NIL ERROR-KEYWORD) on validation failure or
        non-activation. The :weaker-chain return is informational —
        the block was stored safely, just not made active."
  (let* ((header (bitcoin-lisp.serialization:bitcoin-block-header block))
         (prev-hash (bitcoin-lisp.serialization:block-header-prev-block header))
         (current-best-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (now (or current-time (bitcoin-lisp.serialization:get-unix-time))))
    (cond
      ;; Case 1: extends current tip — normal path.
      ((equalp prev-hash current-best-hash)
       (let ((height (1+ (bitcoin-lisp.storage:current-height chain-state))))
         (multiple-value-bind (valid error)
             (validate-block block chain-state utxo-set height now
                             :skip-scripts skip-scripts)
           (if valid
               (progn
                 (connect-block block chain-state block-store utxo-set
                                :tx-index tx-index
                                :fee-estimator fee-estimator
                                :recent-rejects recent-rejects
                                :mempool mempool)
                 (values t nil))
               (values nil error)))))

      (t
       ;; Cases 2 and 3: prev != current best.
       (let* ((prev-entry (bitcoin-lisp.storage:get-block-index-entry
                           chain-state prev-hash))
              (current-best-entry (bitcoin-lisp.storage:get-block-index-entry
                                   chain-state current-best-hash))
              (this-bits (bitcoin-lisp.serialization:block-header-bits header))
              (prev-work (and prev-entry
                              (bitcoin-lisp.storage:block-index-entry-chain-work
                               prev-entry)))
              (new-chain-work (and prev-work
                                   (bitcoin-lisp.storage:calculate-chain-work
                                    this-bits prev-work)))
              (current-best-work (and current-best-entry
                                      (bitcoin-lisp.storage:block-index-entry-chain-work
                                       current-best-entry))))
         (cond
           ;; Parent unknown — caller should queue and request its parent.
           ((null prev-entry)
            (values nil :unknown-parent))

           ;; Case 2: competing fork with strictly more work — pre-reorg.
           ;;
           ;; perform-reorg disconnects our chain back to the common
           ;; ancestor and connects the fork up to (but not including)
           ;; the incoming block. After it returns T, chain-state's tip
           ;; equals prev-entry and the UTXO set reflects that fork's
           ;; state — so validate-block now sees the correct inputs.
           ((and new-chain-work
                 current-best-work
                 (> new-chain-work current-best-work))
            (multiple-value-bind (reorg-ok missing-blocks)
                (perform-reorg chain-state block-store utxo-set
                               current-best-entry prev-entry
                               :tx-index tx-index
                               :fee-estimator fee-estimator
                               :recent-rejects recent-rejects
                               :mempool mempool)
              (cond
                ((null reorg-ok)
                 ;; Reorg refused (missing fork blocks, fork below pruned
                 ;; height, no common ancestor, ...). chain-state and
                 ;; utxo-set are unchanged — perform-reorg either
                 ;; succeeds fully or no-ops. Pass MISSING-BLOCKS up so
                 ;; the caller (process-received-block) can re-queue
                 ;; them for download. Without this, perform-reorg
                 ;; refuses on the same missing block forever and the
                 ;; incoming tip is retried indefinitely.
                 (values nil :reorg-refused missing-blocks))
                (t
                 (let ((new-height (1+ (bitcoin-lisp.storage:current-height
                                        chain-state))))
                   (multiple-value-bind (valid error)
                       (validate-block block chain-state utxo-set new-height now
                                       :skip-scripts skip-scripts)
                     (if valid
                         (progn
                           (connect-block block chain-state block-store utxo-set
                                          :tx-index tx-index
                                          :fee-estimator fee-estimator
                                          :recent-rejects recent-rejects
                                          :mempool mempool)
                           (values t nil))
                         (progn
                           ;; Validation failed AFTER we reorganized.
                           ;; The chain is now on the fork; the
                           ;; incoming block is rejected but the side
                           ;; effects of the reorg remain. Future PR
                           ;; should roll back; for now, log and
                           ;; surface the error.
                           (bitcoin-lisp:log-error
                            "Block on reorged fork failed validation post-reorg: ~A"
                            error)
                           (values nil error)))))))))

           ;; Case 3: weaker / equal chain — store the block, don't
           ;; activate. Bitcoin Core does the same: blocks on weaker
           ;; tips sit in the block-store until their chain catches up.
           (t
            (bitcoin-lisp.storage:store-block block-store block)
            (values nil :weaker-chain))))))))
