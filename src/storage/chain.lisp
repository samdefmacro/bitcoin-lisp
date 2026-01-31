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

(defun get-block-at-height (state target-height)
  "Get the block index entry at TARGET-HEIGHT by walking back from tip."
  (let ((current-height (chain-state-best-height state)))
    (when (> target-height current-height)
      (return-from get-block-at-height nil))
    (let ((entry (get-block-index-entry state (chain-state-best-block-hash state))))
      ;; Walk back from tip to target height
      (loop while (and entry (> (block-index-entry-height entry) target-height))
            do (setf entry (block-index-entry-prev-entry entry)))
      (when (and entry (= (block-index-entry-height entry) target-height))
        entry))))

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

;;; Header Index Persistence

(defvar *header-index-magic* (map '(vector (unsigned-byte 8)) #'char-code "HIDX")
  "Magic bytes identifying a header index file.")

(defconstant +header-index-format-version+ 1
  "Current header index persistence format version.")

(defun header-index-file-path (state)
  "Get the path to the header index file."
  (merge-pathnames "headerindex.dat" (chain-state-base-path state)))

(defun serialize-chainwork (stream value)
  "Write a big integer chain-work as 32 bytes (big-endian)."
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (loop for i from 0 below 32
          do (setf (aref bytes (- 31 i))
                   (logand (ash value (* -8 i)) #xFF)))
    (write-sequence bytes stream)))

(defun deserialize-chainwork (stream)
  "Read a 32-byte big-endian integer for chain-work."
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (read-sequence bytes stream)
    (let ((value 0))
      (loop for i from 0 below 32
            do (setf value (logior (ash value 8) (aref bytes i))))
      value)))

(defun write-uint32-le-chain (stream value)
  "Write 4-byte little-endian uint32."
  (write-byte (logand value #xFF) stream)
  (write-byte (logand (ash value -8) #xFF) stream)
  (write-byte (logand (ash value -16) #xFF) stream)
  (write-byte (logand (ash value -24) #xFF) stream))

(defun read-uint32-le-chain (stream)
  "Read 4-byte little-endian uint32."
  (logior (read-byte stream)
          (ash (read-byte stream) 8)
          (ash (read-byte stream) 16)
          (ash (read-byte stream) 24)))

(defun serialize-header-bytes (stream header)
  "Serialize the 80-byte block header to stream."
  (let* ((header-bytes (bitcoin-lisp.serialization::serialize-block-header header))
         (len (length header-bytes)))
    (write-sequence header-bytes stream)
    ;; Pad to 80 bytes if needed
    (when (< len 80)
      (loop repeat (- 80 len)
            do (write-byte 0 stream)))))

(defun save-header-index (state)
  "Save the block index to a binary file with integrity checks.
Format: magic(4) + version(4) + count(4) + entries + CRC32(4)."
  (let ((path (header-index-file-path state)))
    (ensure-directories-exist path)
    (let ((all-bytes
            (coerce (flexi-streams:with-output-to-sequence (stream)
                      ;; Magic
                      (write-sequence *header-index-magic* stream)
                      ;; Version
                      (write-uint32-le-chain stream +header-index-format-version+)
                      ;; Entry count
                      (let ((count (hash-table-count (chain-state-block-index state))))
                        (write-uint32-le-chain stream count))
                      ;; Write each entry
                      (maphash (lambda (hash entry)
                                 (declare (ignore hash))
                                 (write-single-header-entry stream entry))
                               (chain-state-block-index state)))
                    '(simple-array (unsigned-byte 8) (*)))))
      (with-open-file (stream path
                              :direction :output
                              :if-exists :supersede
                              :element-type '(unsigned-byte 8))
        (write-sequence all-bytes stream)
        (write-sequence (compute-crc32 all-bytes) stream)))
    t))

(defun load-header-index (state)
  "Load the block index from a binary file with integrity verification.
Returns T if loaded, NIL if no file exists or file is corrupted."
  (let ((path (header-index-file-path state)))
    (unless (probe-file path)
      (return-from load-header-index nil))
    ;; Read entire file
    (let ((file-bytes (with-open-file (stream path
                                              :direction :input
                                              :element-type '(unsigned-byte 8))
                        (let ((bytes (make-array (file-length stream)
                                                 :element-type '(unsigned-byte 8))))
                          (read-sequence bytes stream)
                          bytes))))
      ;; Detect format: new format starts with magic "HIDX"
      (if (and (>= (length file-bytes) 4)
               (equalp (subseq file-bytes 0 4) *header-index-magic*))
          (load-header-index-v1 state file-bytes)
          (load-header-index-legacy state file-bytes)))))

(defun load-header-index-legacy (state file-bytes)
  "Load header index from old format (no magic, no checksum)."
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    (let ((count (read-uint32-le-chain stream))
          (entries-by-hash (make-hash-table :test 'equalp))
          (prev-hash-map (make-hash-table :test 'equalp)))
      (dotimes (i count)
        (read-single-header-entry stream entries-by-hash prev-hash-map))
      (link-header-entries entries-by-hash prev-hash-map)
      (setf (chain-state-block-index state) entries-by-hash)))
  t)

(defun load-header-index-v1 (state file-bytes)
  "Load header index from v1 format with integrity checks."
  ;; Need at least magic(4) + version(4) + count(4) + crc(4) = 16
  (when (< (length file-bytes) 16)
    (format *error-output* "WARNING: Header index file too short~%")
    (return-from load-header-index-v1 nil))
  ;; Verify CRC32
  (let* ((data-len (- (length file-bytes) 4))
         (data-bytes (subseq file-bytes 0 data-len))
         (stored-crc (subseq file-bytes data-len))
         (computed-crc (compute-crc32 data-bytes)))
    (unless (equalp stored-crc computed-crc)
      (format *error-output* "WARNING: Header index CRC32 mismatch - file corrupted~%")
      (return-from load-header-index-v1 nil)))
  ;; Parse data
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    ;; Skip magic
    (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
      (read-sequence magic stream))
    ;; Check version
    (let ((version (read-uint32-le-chain stream)))
      (unless (= version +header-index-format-version+)
        (format *error-output* "WARNING: Header index version ~D not supported (expected ~D)~%"
                version +header-index-format-version+)
        (return-from load-header-index-v1 nil)))
    ;; Read entries
    (let ((count (read-uint32-le-chain stream))
          (entries-by-hash (make-hash-table :test 'equalp))
          (prev-hash-map (make-hash-table :test 'equalp)))
      (dotimes (i count)
        (read-single-header-entry stream entries-by-hash prev-hash-map))
      (link-header-entries entries-by-hash prev-hash-map)
      (setf (chain-state-block-index state) entries-by-hash)))
  t)

(defun read-single-header-entry (stream entries-by-hash prev-hash-map)
  "Read a single header entry from STREAM into ENTRIES-BY-HASH."
  (let ((hash (make-array 32 :element-type '(unsigned-byte 8))))
    (read-sequence hash stream)
    (let* ((height (read-uint32-le-chain stream))
           (header-bytes (make-array 80 :element-type '(unsigned-byte 8))))
      (read-sequence header-bytes stream)
      (let* ((chainwork (deserialize-chainwork stream))
             (status-byte (read-byte stream))
             (status (ecase status-byte
                       (0 :unknown) (1 :header-valid) (2 :valid) (3 :invalid)))
             (prev-hash (make-array 32 :element-type '(unsigned-byte 8))))
        (read-sequence prev-hash stream)
        (let ((header (handler-case
                          (flexi-streams:with-input-from-sequence (hs header-bytes)
                            (bitcoin-lisp.serialization::read-block-header hs))
                        (error () nil))))
          (let ((entry (make-block-index-entry
                        :hash hash
                        :height height
                        :header header
                        :prev-entry nil
                        :chain-work chainwork
                        :status status)))
            (setf (gethash hash entries-by-hash) entry)
            (unless (every #'zerop prev-hash)
              (setf (gethash hash prev-hash-map) (copy-seq prev-hash)))))))))

(defun link-header-entries (entries-by-hash prev-hash-map)
  "Link prev-entry pointers in the block index."
  (maphash (lambda (hash prev-hash)
             (let ((entry (gethash hash entries-by-hash))
                   (prev-entry (gethash prev-hash entries-by-hash)))
               (when (and entry prev-entry)
                 (setf (block-index-entry-prev-entry entry) prev-entry))))
           prev-hash-map))

(defun append-header-entry (state entry)
  "Append a single block-index-entry to the header index file.
Updates the entry count in the file header."
  (let ((path (header-index-file-path state)))
    (if (probe-file path)
        ;; Append to existing file
        (with-open-file (stream path
                                :direction :output
                                :if-exists :append
                                :element-type '(unsigned-byte 8))
          (write-single-header-entry stream entry))
      ;; Create new file with count=1
      (progn
        (ensure-directories-exist path)
        (with-open-file (stream path
                                :direction :output
                                :if-does-not-exist :create
                                :element-type '(unsigned-byte 8))
          (write-uint32-le-chain stream 0)  ; placeholder count
          (write-single-header-entry stream entry))))
    ;; Update the count at the beginning of the file
    (with-open-file (stream path
                            :direction :output
                            :if-exists :overwrite
                            :element-type '(unsigned-byte 8))
      (let ((count (hash-table-count (chain-state-block-index state))))
        (write-uint32-le-chain stream count)))
    t))

(defun write-single-header-entry (stream entry)
  "Write a single block-index-entry to STREAM."
  ;; 32-byte block hash
  (write-sequence (block-index-entry-hash entry) stream)
  ;; 4-byte height
  (write-uint32-le-chain stream (block-index-entry-height entry))
  ;; 80-byte header (or zeros if no header)
  (if (block-index-entry-header entry)
      (serialize-header-bytes stream (block-index-entry-header entry))
      (loop repeat 80 do (write-byte 0 stream)))
  ;; 32-byte chainwork
  (serialize-chainwork stream (block-index-entry-chain-work entry))
  ;; 1-byte status
  (write-byte (ecase (block-index-entry-status entry)
                (:unknown 0) (:header-valid 1) (:valid 2) (:invalid 3))
              stream)
  ;; 32-byte previous block hash (or zeros)
  (let ((prev (block-index-entry-prev-entry entry)))
    (if prev
        (write-sequence (block-index-entry-hash prev) stream)
        (write-sequence (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)
                        stream))))

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
