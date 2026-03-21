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

(defun any-utxo-for-txid-p (utxo-set txid)
  "Check if any unspent output exists for TXID (BIP 30 duplicate check).
Scans UTXO keys whose first 32 bytes match TXID."
  (maphash (lambda (key entry)
             (declare (ignore entry))
             (when (and (>= (length key) 32)
                        (equalp (subseq key 0 32) txid))
               (return-from any-utxo-for-txid-p t)))
           (utxo-set-entries utxo-set))
  nil)

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
;;;
;;; File format (v1):
;;;   [4 bytes: magic "UTXO"]
;;;   [4 bytes: format version (1)]
;;;   [4 bytes: entry count]
;;;   [... entries ...]
;;;   [4 bytes: CRC32 of all preceding bytes]
;;;
;;; Each entry: 36-byte key, 8-byte value, 4-byte height, 1-byte coinbase,
;;;             4-byte script-len, N-byte script.

;;; Shared UTXO entry serialization helpers

(defun write-utxo-entry-fields (stream entry)
  "Write the fields of a utxo-entry to STREAM: value, height, coinbase, script."
  (bitcoin-lisp.serialization:write-int64-le stream (utxo-entry-value entry))
  (bitcoin-lisp.serialization:write-uint32-le stream (utxo-entry-height entry))
  (write-byte (if (utxo-entry-coinbase entry) 1 0) stream)
  (let ((script (utxo-entry-script-pubkey entry)))
    (bitcoin-lisp.serialization:write-uint32-le stream (length script))
    (write-sequence script stream)))

(defun read-utxo-entry-fields (stream)
  "Read utxo-entry fields from STREAM. Returns a utxo-entry."
  (let* ((value (bitcoin-lisp.serialization:read-int64-le stream))
         (height (bitcoin-lisp.serialization:read-uint32-le stream))
         (coinbase (= (read-byte stream) 1))
         (script-len (bitcoin-lisp.serialization:read-uint32-le stream))
         (script (make-array script-len :element-type '(unsigned-byte 8))))
    (read-sequence script stream)
    (make-utxo-entry :value value
                     :script-pubkey script
                     :height height
                     :coinbase coinbase)))

;;; Atomic file I/O with CRC32 integrity

(defun save-file-with-crc32 (path write-fn)
  "Write data to PATH atomically with CRC32 integrity.
WRITE-FN receives a stream and writes the payload (including magic/version/count).
Uses temp file + rename for atomicity."
  (ensure-directories-exist path)
  (let ((tmp-path (make-pathname :defaults path
                                 :type (concatenate 'string
                                                    (or (pathname-type path) "dat")
                                                    ".tmp"))))
    (let ((all-bytes (flexi-streams:with-output-to-sequence (stream)
                       (funcall write-fn stream))))
      (with-open-file (out tmp-path
                           :direction :output
                           :if-exists :supersede
                           :element-type '(unsigned-byte 8))
        (write-sequence all-bytes out)
        (write-sequence (compute-crc32 all-bytes) out))
      (rename-file tmp-path path))))

(defun load-file-with-crc32 (path min-size)
  "Load and verify a CRC32-protected file at PATH.
MIN-SIZE is the minimum valid file size (header + crc).
Returns the file bytes (without CRC) on success, NIL on failure."
  (handler-case
      (with-open-file (in path :direction :input
                               :element-type '(unsigned-byte 8)
                               :if-does-not-exist nil)
        (when in
          (let* ((file-len (file-length in))
                 (data (make-array file-len :element-type '(unsigned-byte 8))))
            (read-sequence data in)
            (when (< file-len min-size)
              (return-from load-file-with-crc32 nil))
            (let* ((payload (subseq data 0 (- file-len 4)))
                   (stored-crc (subseq data (- file-len 4)))
                   (computed-crc (compute-crc32 payload)))
              (if (equalp stored-crc computed-crc)
                  data
                  nil)))))
    (error () nil)))

;;; UTXO Set Persistence

(defvar *utxo-magic* (map '(vector (unsigned-byte 8)) #'char-code "UTXO")
  "Magic bytes identifying a UTXO set file.")

(defconstant +utxo-format-version+ 1
  "Current UTXO persistence format version.")

(defun compute-crc32 (data)
  "Compute CRC32 checksum of byte vector DATA. Returns 4-byte vector."
  (let ((digest (ironclad:make-digest :crc32))
        (simple-data (if (typep data '(simple-array (unsigned-byte 8) (*)))
                         data
                         (coerce data '(simple-array (unsigned-byte 8) (*))))))
    (ironclad:update-digest digest simple-data)
    (ironclad:produce-digest digest)))

(defun save-utxo-set (utxo-set path)
  "Save the UTXO set to a binary file at PATH with integrity checks.
Uses atomic write: writes to temporary file, then renames."
  (save-file-with-crc32
   path
   (lambda (stream)
     (write-sequence *utxo-magic* stream)
     (bitcoin-lisp.serialization:write-uint32-le stream +utxo-format-version+)
     (bitcoin-lisp.serialization:write-uint32-le stream
                                                  (hash-table-count (utxo-set-entries utxo-set)))
     (maphash (lambda (key entry)
                (write-sequence key stream)
                (write-utxo-entry-fields stream entry))
              (utxo-set-entries utxo-set))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun starts-with-magic-p (stream magic)
  "Check if STREAM starts with MAGIC bytes without consuming them."
  (let ((bytes (make-array (length magic) :element-type '(unsigned-byte 8))))
    (let ((n (read-sequence bytes stream)))
      (and (= n (length magic))
           (equalp bytes magic)))))

(defun load-utxo-set (utxo-set path)
  "Load the UTXO set from a binary file at PATH with integrity verification.
Returns T if loaded, NIL if file does not exist or is corrupted."
  (unless (probe-file path)
    ;; Check for interrupted write (.tmp file)
    (let ((tmp-path (make-pathname :defaults path
                                   :type (concatenate 'string
                                                      (or (pathname-type path) "dat")
                                                      ".tmp"))))
      (when (probe-file tmp-path)
        (format *error-output* "WARNING: Found ~A without ~A - interrupted write detected~%"
                tmp-path path)))
    (return-from load-utxo-set nil))
  ;; Read entire file
  (let ((file-bytes (with-open-file (stream path
                                            :direction :input
                                            :element-type '(unsigned-byte 8))
                      (let ((bytes (make-array (file-length stream)
                                               :element-type '(unsigned-byte 8))))
                        (read-sequence bytes stream)
                        bytes))))
    ;; Detect old format (no magic bytes)
    (if (and (>= (length file-bytes) 4)
             (not (equalp (subseq file-bytes 0 4) *utxo-magic*)))
        ;; Old format: load using legacy parser
        (load-utxo-set-legacy utxo-set file-bytes)
        ;; New format: verify integrity
        (load-utxo-set-v1 utxo-set file-bytes))))

(defun load-utxo-set-legacy (utxo-set file-bytes)
  "Load UTXO set from old format (no magic, no checksum)."
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    (let ((count (bitcoin-lisp.serialization:read-uint32-le stream))
          (entries (utxo-set-entries utxo-set)))
      (clrhash entries)
      (dotimes (i count)
        (let ((key (make-array 36 :element-type '(unsigned-byte 8))))
          (read-sequence key stream)
          (setf (gethash key entries) (read-utxo-entry-fields stream))))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun load-utxo-set-v1 (utxo-set file-bytes)
  "Load UTXO set from v1 format with integrity checks."
  ;; Need at least magic(4) + version(4) + count(4) + crc(4) = 16 bytes
  (when (< (length file-bytes) 16)
    (format *error-output* "WARNING: UTXO file too short~%")
    (return-from load-utxo-set-v1 nil))
  ;; Verify CRC32
  (let* ((data-len (- (length file-bytes) 4))
         (data-bytes (subseq file-bytes 0 data-len))
         (stored-crc (subseq file-bytes data-len))
         (computed-crc (compute-crc32 data-bytes)))
    (unless (equalp stored-crc computed-crc)
      (format *error-output* "WARNING: UTXO file CRC32 mismatch - file corrupted~%")
      (return-from load-utxo-set-v1 nil)))
  ;; Parse data
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    ;; Skip magic (already verified)
    (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
      (read-sequence magic stream))
    ;; Check version
    (let ((version (bitcoin-lisp.serialization:read-uint32-le stream)))
      (unless (= version +utxo-format-version+)
        (format *error-output* "WARNING: UTXO file version ~D not supported (expected ~D)~%"
                version +utxo-format-version+)
        (return-from load-utxo-set-v1 nil)))
    ;; Read entries
    (let ((count (bitcoin-lisp.serialization:read-uint32-le stream))
          (entries (utxo-set-entries utxo-set)))
      (clrhash entries)
      (dotimes (i count)
        (let ((key (make-array 36 :element-type '(unsigned-byte 8))))
          (read-sequence key stream)
          (setf (gethash key entries) (read-utxo-entry-fields stream))))))
  (setf (utxo-set-dirty utxo-set) nil)
  t)

(defun utxo-set-file-path (base-path)
  "Get the UTXO set file path from a base data directory."
  (merge-pathnames "utxoset.dat" (pathname base-path)))

;;; UTXO Set Iteration and Statistics

(defun utxo-set-iterate (utxo-set callback)
  "Iterate over all UTXOs in deterministic order.
Order is (txid, vout) ascending.
CALLBACK is called with (txid vout entry) for each UTXO."
  (let ((keys '()))
    ;; Collect all keys
    (maphash (lambda (key entry)
               (declare (ignore entry))
               (push key keys))
             (utxo-set-entries utxo-set))
    ;; Sort keys lexicographically (this gives us txid order, then vout order)
    (setf keys (sort keys #'key-less-than))
    ;; Iterate in order
    (dolist (key keys)
      (let ((entry (gethash key (utxo-set-entries utxo-set))))
        (when entry
          ;; Extract txid and vout from key
          (let ((txid (subseq key 0 32))
                (vout (logior (aref key 32)
                              (ash (aref key 33) 8)
                              (ash (aref key 34) 16)
                              (ash (aref key 35) 24))))
            (funcall callback txid vout entry)))))))

(defun key-less-than (a b)
  "Compare two 36-byte UTXO keys lexicographically."
  (loop for i from 0 below 36
        do (cond
             ((< (aref a i) (aref b i)) (return t))
             ((> (aref a i) (aref b i)) (return nil))))
  nil)

(defun utxo-set-total-amount (utxo-set)
  "Calculate total satoshis in the UTXO set."
  (let ((total 0))
    (maphash (lambda (key entry)
               (declare (ignore key))
               (incf total (utxo-entry-value entry)))
             (utxo-set-entries utxo-set))
    total))

(defun utxo-set-distinct-txids (utxo-set)
  "Count distinct transaction IDs with unspent outputs."
  (let ((txids (make-hash-table :test 'equalp)))
    (maphash (lambda (key entry)
               (declare (ignore entry))
               (let ((txid (subseq key 0 32)))
                 (setf (gethash txid txids) t)))
             (utxo-set-entries utxo-set))
    (hash-table-count txids)))

(defun compute-utxo-set-hash (utxo-set)
  "Compute the hash_serialized_3 UTXO set hash.
This matches Bitcoin Core's format for UTXO set verification.
Returns a 32-byte hash."
  (let ((data (flexi-streams:with-output-to-sequence (out)
                (utxo-set-iterate
                 utxo-set
                 (lambda (txid vout entry)
                   ;; Serialize: txid || vout || height || coinbase || value || scriptPubKey
                   (write-sequence txid out)
                   ;; vout as 4-byte little-endian
                   (write-byte (logand vout #xFF) out)
                   (write-byte (logand (ash vout -8) #xFF) out)
                   (write-byte (logand (ash vout -16) #xFF) out)
                   (write-byte (logand (ash vout -24) #xFF) out)
                   ;; height as 4-byte little-endian
                   (let ((h (utxo-entry-height entry)))
                     (write-byte (logand h #xFF) out)
                     (write-byte (logand (ash h -8) #xFF) out)
                     (write-byte (logand (ash h -16) #xFF) out)
                     (write-byte (logand (ash h -24) #xFF) out))
                   ;; coinbase flag as 1 byte
                   (write-byte (if (utxo-entry-coinbase entry) 1 0) out)
                   ;; value as 8-byte little-endian
                   (let ((v (utxo-entry-value entry)))
                     (loop for i from 0 below 8
                           do (write-byte (logand (ash v (* -8 i)) #xFF) out)))
                   ;; scriptPubKey with length prefix (varint)
                   (let ((script (utxo-entry-script-pubkey entry)))
                     (bitcoin-lisp.serialization:write-compact-size out (length script))
                     (write-sequence script out)))))))
    ;; Return SHA256 of concatenated serializations
    (bitcoin-lisp.crypto:sha256 (coerce data '(simple-array (unsigned-byte 8) (*))))))
