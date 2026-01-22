(in-package #:bitcoin-lisp.storage)

;;; Chain State Management
;;;
;;; Tracks the current state of the blockchain:
;;; - Best (tip) block hash and height
;;; - Block index with metadata
;;; - Chain work calculations

(defstruct block-index-entry
  "Metadata for an indexed block."
  (hash nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (height 0 :type (unsigned-byte 32))
  (header nil)
  (prev-entry nil)
  (chain-work 0 :type integer)
  (status :unknown :type keyword))  ; :unknown, :header-valid, :valid, :invalid

(defstruct chain-state
  "Current blockchain state."
  (block-index (make-hash-table :test 'equalp) :type hash-table)
  (best-block-hash nil)
  (best-height 0 :type (unsigned-byte 32))
  (genesis-hash nil)
  (base-path nil :type (or null pathname)))

;;; Testnet genesis block hash (little-endian, as on wire)
(defvar *testnet-genesis-hash*
  (bitcoin-lisp.crypto:hex-to-bytes
   "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000"))

(defun init-chain-state (base-path &key genesis-hash)
  "Initialize chain state at BASE-PATH."
  (make-chain-state
   :base-path (pathname base-path)
   :genesis-hash (or genesis-hash *testnet-genesis-hash*)
   :best-block-hash (or genesis-hash *testnet-genesis-hash*)
   :best-height 0))

(defun get-block-index-entry (state hash)
  "Get the block index entry for HASH."
  (gethash hash (chain-state-block-index state)))

(defun add-block-index-entry (state entry)
  "Add a block index entry to the chain state."
  (setf (gethash (block-index-entry-hash entry)
                 (chain-state-block-index state))
        entry))

(defun best-block-hash (state)
  "Return the hash of the best (tip) block."
  (chain-state-best-block-hash state))

(defun current-height (state)
  "Return the height of the best block."
  (chain-state-best-height state))

(defun update-chain-tip (state hash height)
  "Update the chain tip to the block with HASH at HEIGHT."
  (setf (chain-state-best-block-hash state) hash)
  (setf (chain-state-best-height state) height))

;;; Chain work calculations

(defun bits-to-target (bits)
  "Convert compact 'bits' representation to full 256-bit target."
  (let* ((exponent (ash bits -24))
         (mantissa (logand bits #xFFFFFF)))
    (if (<= exponent 3)
        (ash mantissa (* 8 (- 3 exponent)))
        (ash mantissa (* 8 (- exponent 3))))))

(defun target-to-work (target)
  "Convert a target to the amount of work required.
Work = 2^256 / (target + 1)"
  (if (zerop target)
      0
      (floor (expt 2 256) (1+ target))))

(defun calculate-chain-work (bits prev-work)
  "Calculate cumulative chain work given BITS and previous work."
  (let* ((target (bits-to-target bits))
         (work (target-to-work target)))
    (+ prev-work work)))

;;; State persistence

(defun state-file-path (state)
  "Get the path to the chain state file."
  (merge-pathnames "chainstate.dat" (chain-state-base-path state)))

(defun save-state (state)
  "Save chain state to disk."
  (let ((path (state-file-path state)))
    (ensure-directories-exist path)
    (with-open-file (stream path
                            :direction :output
                            :if-exists :supersede
                            :element-type '(unsigned-byte 8))
      ;; Write best block hash
      (write-sequence (chain-state-best-block-hash state) stream)
      ;; Write best height as 4 bytes
      (let ((height (chain-state-best-height state)))
        (write-byte (logand height #xFF) stream)
        (write-byte (logand (ash height -8) #xFF) stream)
        (write-byte (logand (ash height -16) #xFF) stream)
        (write-byte (logand (ash height -24) #xFF) stream)))
    t))

(defun load-state (state)
  "Load chain state from disk. Returns T if loaded, NIL if no state exists."
  (let ((path (state-file-path state)))
    (when (probe-file path)
      (with-open-file (stream path
                              :direction :input
                              :element-type '(unsigned-byte 8))
        ;; Read best block hash
        (let ((hash (make-array 32 :element-type '(unsigned-byte 8))))
          (read-sequence hash stream)
          (setf (chain-state-best-block-hash state) hash))
        ;; Read best height
        (let ((b0 (read-byte stream))
              (b1 (read-byte stream))
              (b2 (read-byte stream))
              (b3 (read-byte stream)))
          (setf (chain-state-best-height state)
                (logior b0 (ash b1 8) (ash b2 16) (ash b3 24)))))
      t)))

;;; Block locator for syncing

(defun build-block-locator (state)
  "Build a block locator for the getheaders/getblocks messages.
Returns a list of block hashes starting from the tip and going back
with exponentially increasing gaps."
  (let ((locator '())
        (entry (get-block-index-entry state (chain-state-best-block-hash state)))
        (step 1)
        (count 0))
    ;; Walk back through the chain
    (loop while entry
          do (push (block-index-entry-hash entry) locator)
             (incf count)
             (when (> count 10)
               (setf step (* step 2)))
             ;; Move back 'step' blocks
             (let ((moved nil))
               (loop repeat step
                     while (block-index-entry-prev-entry entry)
                     do (setf entry (block-index-entry-prev-entry entry))
                        (setf moved t))
               ;; If we couldn't move back, we're at genesis - exit
               (unless moved
                 (return))))
    ;; Always include genesis
    (when (chain-state-genesis-hash state)
      (pushnew (chain-state-genesis-hash state) locator :test 'equalp))
    (nreverse locator)))
