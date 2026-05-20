(in-package #:bitcoin-lisp.storage)

;;; Chain State Management
;;;
;;; Tracks the current state of the blockchain:
;;; - Best (tip) block hash and height
;;; - Block index with metadata
;;; - Chain work calculations

(defstruct block-index-entry
  "Metadata for an indexed block.

SKIP-ENTRY points to an earlier ancestor at GET-SKIP-HEIGHT(height) so
GET-ANCESTOR runs in O(log depth) instead of O(depth). Built by
BUILD-SKIP-POINTER once PREV-ENTRY is set. Not serialized; rebuilt on
load by REBUILD-SKIP-POINTERS. Mirrors Bitcoin Core's CBlockIndex::pskip
(chain.h:103)."
  (hash nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (height 0 :type (unsigned-byte 32))
  (header nil)
  (prev-entry nil)
  (skip-entry nil)
  (chain-work 0 :type integer)
  (status :unknown :type keyword))  ; :unknown, :header-valid, :valid, :invalid

;;;; Skip-list ancestor support
;;;;
;;;; Mirrors Bitcoin Core's GetSkipHeight + GetAncestor + BuildSkip
;;;; (refs/bitcoin/src/chain.cpp:69-119). Replaces the previous O(depth)
;;;; prev-entry walks for ancestor lookups; skip pointers form a sparse
;;;; index so any ancestor is reached in O(log depth).

(declaim (inline invert-lowest-one get-skip-height))

(defun invert-lowest-one (n)
  "Turn the lowest '1' bit in N's binary representation into a '0'.
N must be a non-negative integer."
  (declare (type (unsigned-byte 32) n))
  (logand n (1- n)))

(defun get-skip-height (height)
  "Height the pskip pointer at HEIGHT should reference. Any value
strictly less than HEIGHT would be correct; this expression matches
Bitcoin Core's choice (chain.cpp:73-81) — empirically ≤110 hops to
reach any ancestor within 2^18 blocks."
  (declare (type (unsigned-byte 32) height))
  (cond
    ((< height 2) 0)
    ((oddp height)
     (1+ (invert-lowest-one (invert-lowest-one (1- height)))))
    (t (invert-lowest-one height))))

(defun get-ancestor (entry target-height)
  "Return the ancestor of ENTRY at TARGET-HEIGHT in O(log depth), or
NIL if TARGET-HEIGHT is negative or above ENTRY's own height.

Mirrors CBlockIndex::GetAncestor (chain.cpp:83-108). Uses SKIP-ENTRY
when the skip lands on or strictly closer to the target than the
alternate prev->prev->...->skip path; falls back to PREV-ENTRY
otherwise."
  (declare (type block-index-entry entry)
           (type (unsigned-byte 32) target-height))
  (let ((walk entry)
        (walk-height (block-index-entry-height entry)))
    (when (> target-height walk-height)
      (return-from get-ancestor nil))
    (loop while (> walk-height target-height)
          do (let ((skip-height (get-skip-height walk-height))
                   (skip-prev-height (get-skip-height (1- walk-height)))
                   (skip (block-index-entry-skip-entry walk)))
               (cond
                 ;; Skip pointer is valid AND (lands exactly on target,
                 ;; OR overshoots target without sliding past what
                 ;; (prev → skip) would reach).
                 ((and skip
                       (or (= skip-height target-height)
                           (and (> skip-height target-height)
                                (not (and (< skip-prev-height (- skip-height 2))
                                          (>= skip-prev-height target-height))))))
                  (setf walk skip
                        walk-height skip-height))
                 (t
                  (setf walk (block-index-entry-prev-entry walk))
                  (decf walk-height)))))
    walk))

(defun build-skip-pointer (entry)
  "Set ENTRY's SKIP-ENTRY based on its current PREV-ENTRY. Idempotent.
Mirrors CBlockIndex::BuildSkip (chain.cpp:115-119)."
  (declare (type block-index-entry entry))
  (let ((prev (block-index-entry-prev-entry entry)))
    (when prev
      (setf (block-index-entry-skip-entry entry)
            (get-ancestor prev (get-skip-height
                                (block-index-entry-height entry)))))))

(defstruct chain-state
  "Current blockchain state."
  (block-index (make-hash-table :test 'equalp) :type hash-table)
  (best-block-hash nil)
  (best-height 0 :type (unsigned-byte 32))
  (genesis-hash nil)
  (base-path nil :type (or null pathname))
  (pruned-height 0 :type (unsigned-byte 32)))

;;; Testnet genesis block hash (little-endian, as on wire)
(defvar *testnet3-genesis-hash*
  (bitcoin-lisp.crypto:hex-to-bytes
   "43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea330900000000"))

(defvar *testnet4-genesis-hash*
  (bitcoin-lisp.crypto:hex-to-bytes
   "43f08bdab050e35b567c864b91f47f50ae725ae2de53bcfbbaf284da00000000"))

(defvar *signet-genesis-hash*
  (bitcoin-lisp.crypto:hex-to-bytes
   "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000"))

;;; Mainnet genesis block hash (little-endian, as on wire)
(defvar *mainnet-genesis-hash*
  (bitcoin-lisp.crypto:hex-to-bytes
   "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"))

(defun network-genesis-hash (network)
  "Return the genesis block hash for NETWORK."
  (ecase network
    (:testnet3 \*testnet3-genesis-hash*)
    (:testnet4 *testnet4-genesis-hash*)
    (:signet *signet-genesis-hash*)
    (:mainnet *mainnet-genesis-hash*)))

(defun init-chain-state (base-path &key genesis-hash network)
  "Initialize chain state at BASE-PATH.
NETWORK defaults to bitcoin-lisp:*network* if not specified."
  (let ((net (or network bitcoin-lisp:*network*)))
    (make-chain-state
     :base-path (pathname base-path)
     :genesis-hash (or genesis-hash (network-genesis-hash net))
     :best-block-hash (or genesis-hash (network-genesis-hash net))
     :best-height 0)))

(defun get-block-index-entry (state hash)
  "Get the block index entry for HASH."
  (gethash hash (chain-state-block-index state)))

(defun add-block-index-entry (state entry)
  "Add a block index entry to the chain state. Builds the skip pointer
if PREV-ENTRY is already linked (callers that link prev-entry after
construction should call BUILD-SKIP-POINTER themselves)."
  (setf (gethash (block-index-entry-hash entry)
                 (chain-state-block-index state))
        entry)
  (build-skip-pointer entry)
  entry)

(defun best-block-hash (state)
  "Return the hash of the best (tip) block."
  (chain-state-best-block-hash state))

(defun get-block-at-height (state target-height)
  "Get the block index entry at TARGET-HEIGHT on the active chain.
Uses the skip-list ancestor walk so the cost is O(log depth) rather
than O(depth)."
  (let ((tip (get-block-index-entry state (chain-state-best-block-hash state))))
    (when tip (get-ancestor tip target-height))))

(defun current-height (state)
  "Return the height of the best block."
  (chain-state-best-height state))

(defun update-chain-tip (state hash height)
  "Update the chain tip to the block with HASH at HEIGHT."
  (setf (chain-state-best-block-hash state) hash)
  (setf (chain-state-best-height state) height))

;;; Difficulty adjustment constants

(defconstant +difficulty-adjustment-interval+ 2016
  "Number of blocks between difficulty retargets.")

(defconstant +pow-target-timespan+ 1209600
  "Target time for one retarget period in seconds (2 weeks = 14 * 24 * 60 * 60).")

(defconstant +pow-limit-bits+ #x1d00ffff
  "Minimum difficulty (maximum target) in compact bits format.
Same for mainnet and testnet.")

;;; Chain work calculations
;;; Note: +pow-limit-target+ is defined after bits-to-target below.

(defun bits-to-target (bits)
  "Convert compact 'bits' representation to full 256-bit target."
  (let* ((exponent (ash bits -24))
         (mantissa (logand bits #xFFFFFF)))
    (if (<= exponent 3)
        (ash mantissa (* 8 (- 3 exponent)))
        (ash mantissa (* 8 (- exponent 3))))))

(defvar +pow-limit-target+ (bits-to-target +pow-limit-bits+)
  "The full 256-bit PoW limit target (precomputed from +pow-limit-bits+).")

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

(defun target-to-bits (target)
  "Convert a full 256-bit target to compact 'bits' representation.
Inverse of bits-to-target. Matches Bitcoin Core's GetCompact()."
  (if (zerop target)
      0
      ;; Count how many bytes are needed to represent the target
      (let* ((size (ceiling (integer-length target) 8))
             ;; Extract the 3 most significant bytes
             ;; ash handles both left (size<3) and right (size>3) shifts
             (compact (ash target (* 8 (- 3 size)))))
        ;; If the high bit of the mantissa is set, shift right by 8
        ;; to avoid it being interpreted as negative
        (when (logtest compact #x800000)
          (setf compact (ash compact -8))
          (incf size))
        (logior (ash size 24) (logand compact #x7FFFFF)))))

(defun calculate-next-work-required (last-retarget-time last-block-time prev-bits)
  "Calculate the new difficulty bits for a retarget boundary.
LAST-RETARGET-TIME is the timestamp of the block at height H-2016.
LAST-BLOCK-TIME is the timestamp of block at height H-1.
PREV-BITS is the bits field of the previous period.
Returns the new compact bits value.
Matches Bitcoin Core's CalculateNextWorkRequired() including the
off-by-one (2015 intervals, not 2016)."
  (let* ((actual-timespan (- last-block-time last-retarget-time))
         ;; Clamp to [timespan/4, timespan*4]
         (min-timespan (floor +pow-target-timespan+ 4))
         (max-timespan (* +pow-target-timespan+ 4))
         (actual-timespan (max min-timespan (min max-timespan actual-timespan)))
         ;; new_target = old_target * actual_timespan / target_timespan
         (old-target (bits-to-target prev-bits))
         (new-target (floor (* old-target actual-timespan) +pow-target-timespan+))
         ;; Cap at PoW limit (precomputed)
         (new-target (min new-target +pow-limit-target+)))
    (target-to-bits new-target)))

;;; State persistence

(defun state-file-path (state)
  "Get the path to the chain state file."
  (merge-pathnames "chainstate.dat" (chain-state-base-path state)))

;;; Persistence format v3: adds in-transition flag (mirrors Bitcoin Core's
;;; DB_HEAD_BLOCKS marker pattern in txdb.cpp::CCoinsViewDB::BatchWrite).
;;;
;;; do-flush performs a 3-phase commit:
;;;   Phase 1: save-state with in-transition=1 (chainstate.dat marked unsafe)
;;;   Phase 2: save-utxo-set (90 MB write + atomic temp+rename)
;;;   Phase 3: save-state with in-transition=0 (commits the new chainstate)
;;;
;;; On load, an in-transition=1 flag means the previous flush was interrupted
;;; mid-write (process killed between Phase 1 and Phase 3). The on-disk
;;; chainstate.dat may be ahead of utxoset.dat or vice versa. We refuse to
;;; load — caller must re-sync. Same model as Bitcoin Core's
;;; "-reindex-chainstate" requirement.
;;;
;;; Format:
;;;   v3 payload = best-block-hash(32) + best-height(4) + pruned-height(4) +
;;;                flags(1) = 41 bytes; file = payload + CRC(4) = 45 bytes
;;;   v2 payload = same without flags byte (40 bytes); file = 44 bytes
;;;   v1 payload = 36 bytes (no pruned-height, no CRC)
;;;
;;; flags byte: bit 0 = in-transition (1 = unsafe, 0 = consistent)

(defconstant +flag-in-transition+ #x01
  "Chainstate flags byte bit 0: marker for an in-progress flush.")

(defun save-state (state &key in-transition)
  "Save chain state to disk atomically with fsync.
v3 format: best-block-hash(32) + best-height(4) + pruned-height(4) + flags(1) + CRC32.
Uses temp + fsync + rename so a crash mid-write never leaves a torn file.

When IN-TRANSITION is non-nil, sets the in-transition flag — the saved
file is a Phase-1 transition marker, not a final commit. do-flush should
call this twice per flush: once with :in-transition t before writing the
UTXO set, then with :in-transition nil after to complete the commit."
  (let ((path (state-file-path state)))
    (save-file-with-crc32
     path
     (lambda (stream)
       (write-sequence (chain-state-best-block-hash state) stream)
       (let ((height (chain-state-best-height state)))
         (write-byte (logand height #xFF) stream)
         (write-byte (logand (ash height -8) #xFF) stream)
         (write-byte (logand (ash height -16) #xFF) stream)
         (write-byte (logand (ash height -24) #xFF) stream))
       (let ((pruned-height (chain-state-pruned-height state)))
         (write-byte (logand pruned-height #xFF) stream)
         (write-byte (logand (ash pruned-height -8) #xFF) stream)
         (write-byte (logand (ash pruned-height -16) #xFF) stream)
         (write-byte (logand (ash pruned-height -24) #xFF) stream))
       ;; v3 flags byte
       (write-byte (if in-transition +flag-in-transition+ 0) stream)))
    t))

(defun load-state (state)
  "Load chain state from disk. Returns:
  T              — loaded successfully, state is consistent with utxoset.dat
  :inconsistent  — chainstate has the in-transition flag set; the previous
                   flush was interrupted between Phase 1 and Phase 3.
                   Caller must abort and require re-sync.
  NIL            — no chainstate exists or the file failed CRC verification.

v3 (45 bytes): payload(41) + CRC(4)
v2 (44 bytes): payload(40) + CRC(4) — pre-flag fallback
v1 (36/40 bytes): no CRC — legacy fallback"
  (let ((path (state-file-path state)))
    (unless (probe-file path)
      (return-from load-state nil))
    ;; Try v3 first (45 bytes).
    (let ((data (load-file-with-crc32 path 45)))
      (when (and data (= (length data) 45))
        (let ((payload (subseq data 0 41)))
          (setf (chain-state-best-block-hash state) (subseq payload 0 32))
          (let ((b0 (aref payload 32)) (b1 (aref payload 33))
                (b2 (aref payload 34)) (b3 (aref payload 35)))
            (setf (chain-state-best-height state)
                  (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))
          (let ((b0 (aref payload 36)) (b1 (aref payload 37))
                (b2 (aref payload 38)) (b3 (aref payload 39)))
            (setf (chain-state-pruned-height state)
                  (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))
          (let ((flags (aref payload 40)))
            (when (logtest flags +flag-in-transition+)
              (return-from load-state :inconsistent)))
          (return-from load-state t))))
    ;; Fallback to v2 (44 bytes) — no flag byte, treat as committed.
    (let ((data (load-file-with-crc32 path 44)))
      (when (and data (= (length data) 44))
        (let ((payload (subseq data 0 40)))
          (setf (chain-state-best-block-hash state) (subseq payload 0 32))
          (let ((b0 (aref payload 32)) (b1 (aref payload 33))
                (b2 (aref payload 34)) (b3 (aref payload 35)))
            (setf (chain-state-best-height state)
                  (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))
          (let ((b0 (aref payload 36)) (b1 (aref payload 37))
                (b2 (aref payload 38)) (b3 (aref payload 39)))
            (setf (chain-state-pruned-height state)
                  (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))
          (return-from load-state t))))
    ;; Legacy fallback: pre-CRC format (36 or 40 bytes total).
    (with-open-file (stream path :direction :input :element-type '(unsigned-byte 8))
      (let ((file-size (file-length stream)))
        (when (or (= file-size 36) (= file-size 40))
          (let ((hash (make-array 32 :element-type '(unsigned-byte 8))))
            (read-sequence hash stream)
            (setf (chain-state-best-block-hash state) hash))
          (let ((b0 (read-byte stream)) (b1 (read-byte stream))
                (b2 (read-byte stream)) (b3 (read-byte stream)))
            (setf (chain-state-best-height state)
                  (logior b0 (ash b1 8) (ash b2 16) (ash b3 24))))
          (when (= file-size 40)
            (let ((b0 (read-byte stream)) (b1 (read-byte stream))
                  (b2 (read-byte stream)) (b3 (read-byte stream)))
              (setf (chain-state-pruned-height state)
                    (logior b0 (ash b1 8) (ash b2 16) (ash b3 24)))))
          t)))))

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

(declaim (inline bb-write-chainwork))
(defun bb-write-chainwork (bb value)
  "byte-buf variant of serialize-chainwork: 32 big-endian bytes."
  (declare (type bitcoin-lisp.serialization::byte-buf bb)
           (optimize (speed 3) (safety 1)))
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (declare (type (simple-array (unsigned-byte 8) (32)) bytes))
    (loop for i fixnum from 0 below 32
          do (setf (aref bytes (- 31 i))
                   (logand (ash value (the fixnum (* -8 i))) #xFF)))
    (bitcoin-lisp.serialization:bb-write-bytes bb bytes)))

(defun deserialize-chainwork (stream)
  "Read a 32-byte big-endian integer for chain-work."
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (read-sequence bytes stream)
    (let ((value 0))
      (loop for i from 0 below 32
            do (setf value (logior (ash value 8) (aref bytes i))))
      value)))

(declaim (inline bb-write-header-bytes bb-write-single-header-entry))
(defun bb-write-header-bytes (bb header)
  "byte-buf variant: write 80-byte block header (zero-padded if short)."
  (declare (optimize (speed 3) (safety 1)))
  (if header
      (let* ((header-bytes (bitcoin-lisp.serialization::serialize-block-header header))
             (len (length header-bytes)))
        (declare (type fixnum len))
        (bitcoin-lisp.serialization:bb-write-bytes bb header-bytes)
        (loop repeat (- 80 len)
              do (bitcoin-lisp.serialization:bb-write-u8 bb 0)))
      (loop repeat 80 do (bitcoin-lisp.serialization:bb-write-u8 bb 0))))

(defun bb-write-single-header-entry (bb entry)
  "byte-buf variant of write-single-header-entry. Writes 181 bytes:
hash(32) + height(4) + header(80) + chainwork(32) + status(1) + prev-hash(32)."
  (declare (optimize (speed 3) (safety 1)))
  (bitcoin-lisp.serialization:bb-write-bytes bb (block-index-entry-hash entry))
  (bitcoin-lisp.serialization:bb-write-u32-le bb (block-index-entry-height entry))
  (bb-write-header-bytes bb (block-index-entry-header entry))
  (bb-write-chainwork bb (block-index-entry-chain-work entry))
  (bitcoin-lisp.serialization:bb-write-u8 bb
   (ecase (block-index-entry-status entry)
     (:unknown 0) (:header-valid 1) (:valid 2) (:invalid 3)))
  (let ((prev-entry (block-index-entry-prev-entry entry)))
    (if prev-entry
        (bitcoin-lisp.serialization:bb-write-bytes bb (block-index-entry-hash prev-entry))
        (loop repeat 32 do (bitcoin-lisp.serialization:bb-write-u8 bb 0)))))

(defun save-header-index (state)
  "Save the block index to a binary file with integrity checks.
Format: magic(4) + version(4) + count(4) + entries + CRC32(4).
Atomic temp + fsync + rename via save-file-with-crc32-bb."
  (let ((path (header-index-file-path state)))
    (bitcoin-lisp.storage:save-file-with-crc32-bb
     path
     (lambda (bb)
       (bitcoin-lisp.serialization:bb-write-bytes bb *header-index-magic*)
       (bitcoin-lisp.serialization:bb-write-u32-le bb +header-index-format-version+)
       (bitcoin-lisp.serialization:bb-write-u32-le
        bb (hash-table-count (chain-state-block-index state)))
       (maphash (lambda (hash entry)
                  (declare (ignore hash))
                  (bb-write-single-header-entry bb entry))
                (chain-state-block-index state))))
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
    (let ((count (bitcoin-lisp.serialization:read-uint32-le stream))
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
    (let ((version (bitcoin-lisp.serialization:read-uint32-le stream)))
      (unless (= version +header-index-format-version+)
        (format *error-output* "WARNING: Header index version ~D not supported (expected ~D)~%"
                version +header-index-format-version+)
        (return-from load-header-index-v1 nil)))
    ;; Read entries
    (let ((count (bitcoin-lisp.serialization:read-uint32-le stream))
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
    (let* ((height (bitcoin-lisp.serialization:read-uint32-le stream))
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
  "Link prev-entry pointers in the block index. Then rebuild skip
pointers in height ascending order so each entry's skip target is
already populated when consulted by deeper entries."
  (maphash (lambda (hash prev-hash)
             (let ((entry (gethash hash entries-by-hash))
                   (prev-entry (gethash prev-hash entries-by-hash)))
               (when (and entry prev-entry)
                 (setf (block-index-entry-prev-entry entry) prev-entry))))
           prev-hash-map)
  (let ((entries '()))
    (maphash (lambda (hash entry) (declare (ignore hash))
                                  (push entry entries))
             entries-by-hash)
    (dolist (entry (sort entries #'< :key #'block-index-entry-height))
      (build-skip-pointer entry))))

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
