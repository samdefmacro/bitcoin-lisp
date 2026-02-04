(in-package #:bitcoin-lisp.mempool)

;;; Fee Estimator
;;;
;;; Collects fee rate statistics from confirmed blocks and provides
;;; fee rate estimates based on historical data.

;;;; Constants

(defconstant +fee-history-size+ 1008
  "Number of blocks to keep in fee history (~1 week).")

(defconstant +min-blocks-for-estimate+ 6
  "Minimum blocks required before providing computed estimates.")

(defconstant +fee-stats-flush-interval+ 10
  "Flush fee stats to disk every N blocks.")

;;;; Block fee statistics

(defstruct block-fee-stats
  "Fee statistics for a single block."
  (height 0 :type (unsigned-byte 32))
  (median-rate 0 :type (unsigned-byte 32))   ; sat/vB
  (low-rate 0 :type (unsigned-byte 32))      ; 10th percentile
  (high-rate 0 :type (unsigned-byte 32))     ; 90th percentile
  (tx-count 0 :type (unsigned-byte 32)))

;;;; Fee estimator

(defstruct fee-estimator
  "Fee rate estimator based on historical block data."
  ;; Circular buffer of block-fee-stats
  (history (make-array +fee-history-size+ :initial-element nil) :type simple-vector)
  ;; Current write position in circular buffer
  (write-index 0 :type (unsigned-byte 16))
  ;; Number of entries currently stored
  (entry-count 0 :type (unsigned-byte 16))
  ;; Minimum blocks needed for estimation
  (min-blocks +min-blocks-for-estimate+ :type (unsigned-byte 8))
  ;; Data directory for persistence
  (data-directory nil :type (or null pathname))
  ;; Blocks since last flush
  (blocks-since-flush 0 :type (unsigned-byte 16)))

;;;; Fee rate calculation

(defun calculate-tx-fee-rate (tx spent-utxos-map)
  "Calculate the fee rate (sat/vB) for a transaction given spent UTXO values.
TX is a transaction, SPENT-UTXOS-MAP maps (txid . index) to utxo-entry.
Returns the fee rate as an integer, or NIL if inputs cannot be resolved."
  (let ((total-input 0)
        (total-output 0))
    ;; Sum input values from spent UTXOs
    (dolist (input (bitcoin-lisp.serialization:transaction-inputs tx))
      (let* ((prevout (bitcoin-lisp.serialization:tx-in-previous-output input))
             (prev-txid (bitcoin-lisp.serialization:outpoint-hash prevout))
             (prev-index (bitcoin-lisp.serialization:outpoint-index prevout))
             (utxo-entry (gethash (cons prev-txid prev-index) spent-utxos-map)))
        (unless utxo-entry
          (return-from calculate-tx-fee-rate nil))
        (incf total-input (bitcoin-lisp.storage:utxo-entry-value utxo-entry))))
    ;; Sum output values
    (dolist (output (bitcoin-lisp.serialization:transaction-outputs tx))
      (incf total-output (bitcoin-lisp.serialization:tx-out-value output)))
    ;; Calculate fee rate (fee / vsize)
    (let ((fee (- total-input total-output))
          (vsize (bitcoin-lisp.serialization:transaction-vsize tx)))
      (if (and (> fee 0) (> vsize 0))
          (ceiling fee vsize)
          0))))

(defun compute-block-fee-stats (block spent-utxos height)
  "Compute fee statistics for a block given its spent UTXOs.
SPENT-UTXOS is a list of (txid index utxo-entry) from apply-block-to-utxo-set.
Returns a block-fee-stats struct, or NIL if block has no fee-paying transactions."
  (let ((transactions (bitcoin-lisp.serialization:bitcoin-block-transactions block))
        (fee-rates '()))
    ;; Build lookup map for spent UTXOs
    (let ((spent-map (make-hash-table :test 'equalp)))
      (dolist (spent spent-utxos)
        (destructuring-bind (txid index entry) spent
          (setf (gethash (cons txid index) spent-map) entry)))
      ;; Calculate fee rates for non-coinbase transactions
      (dolist (tx (rest transactions))  ; Skip coinbase
        (let ((rate (calculate-tx-fee-rate tx spent-map)))
          (when (and rate (> rate 0))
            (push rate fee-rates)))))
    ;; Need at least one fee-paying transaction
    (when (null fee-rates)
      (return-from compute-block-fee-stats nil))
    ;; Sort fee rates for percentile calculation
    (setf fee-rates (sort fee-rates #'<))
    (let* ((count (length fee-rates))
           (median (nth (floor count 2) fee-rates))
           (low (nth (floor (* count 0.1)) fee-rates))
           (high (nth (min (1- count) (floor (* count 0.9))) fee-rates)))
      (make-block-fee-stats
       :height height
       :median-rate median
       :low-rate low
       :high-rate high
       :tx-count count))))

;;;; Fee estimator operations

(defun fee-estimator-add-stats (estimator stats)
  "Add block fee statistics to the estimator's history."
  (when stats
    (let ((idx (fee-estimator-write-index estimator)))
      (setf (aref (fee-estimator-history estimator) idx) stats)
      (setf (fee-estimator-write-index estimator)
            (mod (1+ idx) +fee-history-size+))
      (when (< (fee-estimator-entry-count estimator) +fee-history-size+)
        (incf (fee-estimator-entry-count estimator)))
      ;; Track blocks since flush for periodic persistence
      (incf (fee-estimator-blocks-since-flush estimator)))))

(defun fee-estimator-ready-p (estimator)
  "Check if the estimator has enough data to provide estimates."
  (>= (fee-estimator-entry-count estimator)
      (fee-estimator-min-blocks estimator)))

(defun fee-estimator-get-history (estimator &optional (max-blocks nil))
  "Get fee statistics from history, most recent first.
Returns up to MAX-BLOCKS entries (or all if NIL)."
  (let* ((count (fee-estimator-entry-count estimator))
         (limit (if max-blocks (min max-blocks count) count))
         (history (fee-estimator-history estimator))
         (write-idx (fee-estimator-write-index estimator))
         (result '()))
    (dotimes (i limit)
      (let* ((idx (mod (- write-idx 1 i) +fee-history-size+))
             (entry (aref history idx)))
        (when entry
          (push entry result))))
    (nreverse result)))

;;;; Persistence

(defconstant +fee-stats-magic+ #x53454546)  ; "FEES" in little-endian
(defconstant +fee-stats-version+ 1)
(defvar +fee-stats-filename+ "fee_estimates.dat")

(defun fee-stats-path (data-directory)
  "Get the path for the fee stats file."
  (when data-directory
    (merge-pathnames +fee-stats-filename+ data-directory)))

(defun save-fee-stats (estimator)
  "Save fee statistics to disk.
File format: magic (4 bytes), version (1 byte), count (2 bytes),
entries (20 bytes each: height, median, low, high, tx-count), CRC32 (4 bytes)."
  (let ((path (fee-stats-path (fee-estimator-data-directory estimator))))
    (unless path
      (return-from save-fee-stats nil))
    (let ((entries (fee-estimator-get-history estimator)))
      ;; Build data in memory for CRC32 calculation
      (let ((data-bytes
              (flexi-streams:with-output-to-sequence (mem)
                ;; Write header
                (bitcoin-lisp.serialization:write-uint32-le mem +fee-stats-magic+)
                (bitcoin-lisp.serialization:write-uint8 mem +fee-stats-version+)
                (bitcoin-lisp.serialization:write-uint16-le mem (length entries))
                ;; Write entries
                (dolist (entry entries)
                  (bitcoin-lisp.serialization:write-uint32-le mem (block-fee-stats-height entry))
                  (bitcoin-lisp.serialization:write-uint32-le mem (block-fee-stats-median-rate entry))
                  (bitcoin-lisp.serialization:write-uint32-le mem (block-fee-stats-low-rate entry))
                  (bitcoin-lisp.serialization:write-uint32-le mem (block-fee-stats-high-rate entry))
                  (bitcoin-lisp.serialization:write-uint32-le mem (block-fee-stats-tx-count entry))))))
        ;; Write data + CRC32 to file
        (with-open-file (stream path
                                :direction :output
                                :element-type '(unsigned-byte 8)
                                :if-exists :supersede
                                :if-does-not-exist :create)
          (write-sequence data-bytes stream)
          (write-sequence (bitcoin-lisp.storage:compute-crc32 data-bytes) stream))))
    ;; Reset flush counter
    (setf (fee-estimator-blocks-since-flush estimator) 0)
    t))

(defun load-fee-stats (estimator)
  "Load fee statistics from disk.
Returns T on success, NIL if file doesn't exist or is corrupt."
  (let ((path (fee-stats-path (fee-estimator-data-directory estimator))))
    (unless (and path (probe-file path))
      (return-from load-fee-stats nil))
    (handler-case
        (let ((file-bytes (with-open-file (stream path
                                                   :direction :input
                                                   :element-type '(unsigned-byte 8))
                            (let ((bytes (make-array (file-length stream)
                                                     :element-type '(unsigned-byte 8))))
                              (read-sequence bytes stream)
                              bytes))))
          ;; Need at least header (7 bytes) + CRC32 (4 bytes)
          (when (< (length file-bytes) 11)
            (bitcoin-lisp:log-warn "Fee stats file too short")
            (return-from load-fee-stats nil))
          ;; Verify CRC32
          (let* ((data-len (- (length file-bytes) 4))
                 (data-bytes (subseq file-bytes 0 data-len))
                 (stored-crc (subseq file-bytes data-len))
                 (computed-crc (bitcoin-lisp.storage:compute-crc32 data-bytes)))
            (unless (equalp stored-crc computed-crc)
              (bitcoin-lisp:log-warn "Fee stats file CRC32 mismatch - file corrupted")
              (return-from load-fee-stats nil)))
          ;; Parse data
          (flexi-streams:with-input-from-sequence (stream file-bytes)
            (let ((magic (bitcoin-lisp.serialization:read-uint32-le stream))
                  (version (bitcoin-lisp.serialization:read-uint8 stream))
                  (count (bitcoin-lisp.serialization:read-uint16-le stream)))
              (unless (= magic +fee-stats-magic+)
                (bitcoin-lisp:log-warn "Fee stats file has invalid magic")
                (return-from load-fee-stats nil))
              (unless (= version +fee-stats-version+)
                (bitcoin-lisp:log-warn "Fee stats file has unsupported version ~D" version)
                (return-from load-fee-stats nil))
              ;; Read entries
              (dotimes (i count)
                (let ((entry (make-block-fee-stats
                              :height (bitcoin-lisp.serialization:read-uint32-le stream)
                              :median-rate (bitcoin-lisp.serialization:read-uint32-le stream)
                              :low-rate (bitcoin-lisp.serialization:read-uint32-le stream)
                              :high-rate (bitcoin-lisp.serialization:read-uint32-le stream)
                              :tx-count (bitcoin-lisp.serialization:read-uint32-le stream))))
                  (fee-estimator-add-stats estimator entry)))
              (bitcoin-lisp:log-info "Loaded ~D fee stats entries" count)
              t)))
      (error (e)
        (bitcoin-lisp:log-warn "Failed to load fee stats: ~A" e)
        nil))))

(defun maybe-flush-fee-stats (estimator)
  "Flush fee stats to disk if enough blocks have accumulated."
  (when (>= (fee-estimator-blocks-since-flush estimator)
            +fee-stats-flush-interval+)
    (save-fee-stats estimator)))

;;;; Fee Rate Estimation

(defun fee-rate-percentile (rates percentile)
  "Calculate the Nth percentile of a list of fee rates using linear interpolation.
RATES should be a sorted list of numbers. PERCENTILE is 0-100.
Returns an integer fee rate (rounded up for safety)."
  (when (null rates)
    (return-from fee-rate-percentile nil))
  (let* ((n (length rates)))
    (if (= n 1)
        (first rates)
        ;; Linear interpolation between adjacent values
        (let* ((pos (* (1- n) (/ percentile 100.0)))
               (lower-idx (floor pos))
               (upper-idx (min (1- n) (ceiling pos)))
               (lower-val (nth lower-idx rates))
               (upper-val (nth upper-idx rates))
               (fraction (- pos lower-idx)))
          ;; Interpolate and round up for conservative estimate
          (ceiling (+ lower-val (* fraction (- upper-val lower-val))))))))

(defun get-percentile-for-target (conf-target mode)
  "Get the percentile to use based on confirmation target and mode.
MODE is :conservative (default) or :economical.
Conservative mode uses higher percentiles for more reliable confirmation."
  (let ((base-percentile
          (cond
            ((<= conf-target 2) 90)
            ((<= conf-target 6) 85)
            ((<= conf-target 12) 75)
            ((<= conf-target 25) 65)
            ((<= conf-target 144) 50)
            (t 25))))
    ;; Economical mode: subtract 15 from percentile (min 10)
    (if (eq mode :economical)
        (max 10 (- base-percentile 15))
        base-percentile)))

(defun get-blocks-to-analyze (conf-target)
  "Get the number of blocks to analyze based on confirmation target."
  (cond
    ((<= conf-target 2) 12)
    ((<= conf-target 6) 36)
    ((<= conf-target 12) 72)
    ((<= conf-target 25) 144)
    ((<= conf-target 144) 288)
    (t 1008)))

(defun estimate-fee-rate (estimator conf-target &key (mode :conservative))
  "Estimate the fee rate needed for confirmation within CONF-TARGET blocks.
MODE is :conservative (default) or :economical.
Returns (values fee-rate-estimate error-message).
Fee rate is in sat/vB."
  (unless (fee-estimator-ready-p estimator)
    (return-from estimate-fee-rate
      (values 1 "Insufficient data for fee estimation")))

  (let* ((blocks-to-analyze (get-blocks-to-analyze conf-target))
         (history (fee-estimator-get-history estimator blocks-to-analyze))
         (percentile (get-percentile-for-target conf-target mode)))

    (when (< (length history) (fee-estimator-min-blocks estimator))
      (return-from estimate-fee-rate
        (values 1 "Insufficient data for fee estimation")))

    ;; Collect all median rates from history
    (let* ((rates (sort (mapcar #'block-fee-stats-median-rate history) #'<))
           (estimate (fee-rate-percentile rates percentile)))
      (values (or estimate 1) nil))))
