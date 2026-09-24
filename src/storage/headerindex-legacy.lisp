(in-package #:bitcoin-lisp.storage)

;;;; The former block-index files, READ-ONLY: headerindex.dat and headerindex.delta.
;;;;
;;;; Until 2026-09-24 the block index persisted in two files of this project's
;;;; own: a CRC-framed snapshot, headerindex.dat (versions 1-3), and a delta log
;;;; of the entries changed since the snapshot, headerindex.delta. It now lives
;;;; where Core keeps it, in the LevelDB at blocks/index (block-tree-db.lisp).
;;;; Nothing writes these files any more. What remains is the reader, whose only
;;;; caller is MIGRATE-LEGACY-HEADER-INDEX: a datadir that still has them is
;;;; converted once, at start-up, and the files are renamed *.migrated.
;;;;
;;;; The delta log is part of the migration's input, not an optimisation to be
;;;; skipped: it holds exactly the entries changed since the last snapshot --
;;;; the most recent statuses, an operator's invalidateblock among them -- so
;;;; converting the snapshot alone could turn an :invalid block :valid again.

(defvar *header-index-magic* (map '(vector (unsigned-byte 8)) #'char-code "HIDX")
  "Magic bytes identifying a header index file.")

(defconstant +header-index-format-version+ 3
  "Current header index persistence format version.
v2 appends a per-entry tx-count (4 bytes); v3 appends the flat-file position
(file, data-pos, undo-pos: 12 bytes). Older files still load — a v1 entry gets
tx-count 0 (backfilled lazily from the block store) and a v1 or v2 entry gets
no position, which is exactly right for a block that predates the flat files:
it lives in the legacy per-block file named by its hash.")

(defvar *header-index-delta-magic*
  (map '(vector (unsigned-byte 8)) #'char-code "HIDD")
  "Magic bytes identifying a header index DELTA log.")

(defconstant +header-index-delta-version+ 2
  "Format version of the header index delta log. Bumped with the entry layout:
a delta records whole entries, so a log written with v2 entries cannot be
replayed by a build that reads v3 ones. The loader refuses an older log rather
than misparsing it -- the cost is one full snapshot on the first start after an
upgrade, which the format change requires anyway.")

(defun legacy-header-index-delta-path (state)
  "Path to the former header index delta log, headerindex.delta at the
network-dir root."
  (merge-pathnames "headerindex.delta" (chain-state-base-path state)))

(defun %file-trailing-crc (path)
  "The last 4 bytes of PATH — for a save-file-with-crc32 file, its CRC32, which
serves as the file's identity. NIL if unreadable."
  (handler-case
      (with-open-file (s path :direction :input
                              :element-type '(unsigned-byte 8)
                              :if-does-not-exist nil)
        (when (and s (>= (file-length s) 4))
          (file-position s (- (file-length s) 4))
          (let ((b (make-array 4 :element-type '(unsigned-byte 8))))
            (read-sequence b s)
            b)))
    (error () nil)))

(defun legacy-header-index-file-path (state)
  "The former header index snapshot, headerindex.dat: in blocks/index/ since
the datadir-layout migration, at the network-dir root before it.
DATADIR-HEADER-INDEX-FILE answers whichever of the two holds the file."
  (datadir-header-index-file (chain-state-base-path state)))

(defun deserialize-chainwork (stream)
  "Read a 32-byte big-endian integer for chain-work."
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8))))
    (read-sequence bytes stream)
    (let ((value 0))
      (loop for i from 0 below 32
            do (setf value (logior (ash value 8) (aref bytes i))))
      value)))

(defun %delta-entry-width (version)
  "Serialized entry width of a delta log at VERSION, or NIL if this build does
not know that layout.

Old logs are REPLAYED at their own width rather than discarded. Discarding one
looks harmless -- it is only the changes since the last snapshot -- but those
changes are exactly the statuses that were most recently updated, so dropping
the log can revert a block from :invalid back to :valid. That is the failure
%ENTRY-PERSIST-KEY's docstring warns about, arriving by a different route."
  (case version
    (1 185)   ; hash+height+header+chainwork+status+prev+tx-count
    (2 197)))   ; ... + file + data-pos + undo-pos

(defun %refresh-block-index-entry (entry record)
  "Copy RECORD's fields into ENTRY, leaving ENTRY's identity and its children's
PREV-ENTRY pointers alone.

This is Core's InsertBlockIndex invariant: LoadBlockIndexGuts materialises
every CBlockIndex through a try_emplace on m_block_index and resolves each
pprev through the SAME function, so there is exactly one object per hash and a
pprev pointer and a map lookup can never disagree
(node/blockstorage.cpp:407-421,425-426). Delta replay used to install a BRAND
NEW object per refreshed hash and relink only the entries the delta carried,
so an unchanged child kept pointing at the SUPERSEDED parent -- and every
ancestry walk follows prev-entry, so the active-chain walk handed out the
orphan while the hash table held the current one. A status written through such
a walk (%reorg-disconnect, %reorg-connect) was then invisible to the save, and
a flat-file position read off one described a body that pruning had deleted.

PREV-ENTRY is deliberately NOT copied: RECORD carries only a prev HASH, which
the caller resolves, and ENTRY's pointer is already correct. The header is
copied only when RECORD has one, since a header that failed to parse reads as
NIL and must not clobber a good one."
  (setf (block-index-entry-height entry) (block-index-entry-height record)
        (block-index-entry-chain-work entry) (block-index-entry-chain-work record)
        (block-index-entry-status entry) (block-index-entry-status record)
        (block-index-entry-tx-count entry) (block-index-entry-tx-count record)
        (block-index-entry-file entry) (block-index-entry-file record)
        (block-index-entry-data-pos entry) (block-index-entry-data-pos record)
        (block-index-entry-undo-pos entry) (block-index-entry-undo-pos record))
  (when (block-index-entry-header record)
    (setf (block-index-entry-header entry) (block-index-entry-header record)))
  entry)

(defun %replay-header-index-delta (state)
  "Apply the delta log beside the snapshot, if it belongs to THIS snapshot.
Returns the number of entries applied.

A delta whose recorded CRC does not match the snapshot on disk was orphaned by
a crash between writing a new snapshot and removing the old log; replaying it
would roll entries BACK to older statuses, so it is discarded instead.

Replay stops at the first frame that is short or fails its CRC — the ordinary
shape of a crash mid-append — and keeps everything before it."
  (let ((path (legacy-header-index-delta-path state))
        (applied 0))
    (unless (probe-file path)
      (return-from %replay-header-index-delta 0))
    (handler-case
        (let ((bytes (with-open-file (in path :direction :input
                                              :element-type '(unsigned-byte 8))
                       (let ((b (make-array (file-length in)
                                            :element-type '(unsigned-byte 8))))
                         (read-sequence b in)
                         b)))
              (header-len 12))
          (if (or (< (length bytes) header-len)
                  (not (equalp (subseq bytes 0 4) *header-index-delta-magic*))
                  ;; A delta records WHOLE entries, so a log written against a
                  ;; different entry layout must be framed at ITS width, not at
                  ;; this build's. The CRC binding does not catch the difference
                  ;; -- on the first start after an entry-format change the old
                  ;; log is bound to the very snapshot still on disk -- so the
                  ;; version field is the only thing that can, and an unknown
                  ;; one is the only case that gets discarded.
                  (null (%delta-entry-width
                         (logior (aref bytes 4)
                                 (ash (aref bytes 5) 8)
                                 (ash (aref bytes 6) 16)
                                 (ash (aref bytes 7) 24))))
                  (not (equalp (subseq bytes 8 12)
                               (or (%file-trailing-crc
                                    (legacy-header-index-file-path state))
                                   #()))))
              ;; Not ours — a stale log from a superseded snapshot, or one
              ;; written in an older entry layout.
              (progn (ignore-errors (delete-file path)) 0)
              (let* ((pos header-len)
                     (index (chain-state-block-index state))
                     (prev-all (make-hash-table :test 'equalp))
                     (delta-version (logior (aref bytes 4)
                                            (ash (aref bytes 5) 8)
                                            (ash (aref bytes 6) 16)
                                            (ash (aref bytes 7) 24)))
                     (entry-width (%delta-entry-width delta-version))
                     (with-position (>= delta-version 2)))
                (loop
                  (when (> (+ pos 4) (length bytes)) (return))
                  (let* ((count (logior (aref bytes pos)
                                        (ash (aref bytes (+ pos 1)) 8)
                                        (ash (aref bytes (+ pos 2)) 16)
                                        (ash (aref bytes (+ pos 3)) 24)))
                         (payload-len (+ 4 (* count entry-width)))
                         (frame-end (+ pos payload-len 4)))
                    ;; Truncated tail: stop, keeping every complete frame.
                    (when (or (zerop count) (> frame-end (length bytes)))
                      (return))
                    (let ((payload (subseq bytes pos (+ pos payload-len)))
                          (crc (subseq bytes (+ pos payload-len) frame-end)))
                      (unless (equalp crc (bl.store:compute-crc32 payload))
                        (return))
                      (let ((batch (make-hash-table :test 'equalp))
                            (prevs (make-hash-table :test 'equalp)))
                        (flexi-streams:with-input-from-sequence
                            (stream (subseq payload 4))
                          (dotimes (i count)
                            (read-single-header-entry stream batch prevs t
                                                      with-position)))
                        ;; Each record refreshes the entry of that hash, so
                        ;; later frames win: the log is last-writer-wins. A
                        ;; hash already in the index is MUTATED, never replaced
                        ;; -- see %REFRESH-BLOCK-INDEX-ENTRY. Only a genuinely
                        ;; new hash joins the relink pass, since only a new
                        ;; object has a prev-entry to resolve.
                        (maphash (lambda (hash e)
                                   (let ((existing (gethash hash index)))
                                     (cond
                                       (existing
                                        (%refresh-block-index-entry existing e))
                                       (t
                                        (setf (gethash hash index) e)
                                        (let ((ph (gethash hash prevs)))
                                          (when ph
                                            (setf (gethash hash prev-all) ph))))))
                                   (incf applied))
                                 batch)))
                    (setf pos frame-end)))
                ;; Re-link once, after every frame is in: a replayed entry must
                ;; point at the real parent object, not at nothing.
                (when (plusp (hash-table-count prev-all))
                  (link-header-entries index prev-all))
                applied)))
      (error () applied))))

(defun load-legacy-header-index (state)
  "Load the block index from a binary file with integrity verification.

Returns (values T NIL) on success, (values NIL NIL) when there is simply no
file — a legitimate first run — and (values NIL REASON) when a file IS present
but cannot be trusted, REASON being a human-readable description.

The caller MUST refuse to start on that third case. Continuing with an empty
index while chainstate.dat still names a tip leaves the node claiming a height
it holds no headers for, which on a pruned node cannot be rebuilt from disk at
all. Core treats a CBlockTreeDB it cannot load the same way: a fatal \"Error
loading block database\" rather than an empty index (init.cpp)."
  (let ((path (legacy-header-index-file-path state)))
    (unless (probe-file path)
      (return-from load-legacy-header-index (values nil nil)))
    (handler-case
        ;; Read entire file
        (let ((file-bytes (with-open-file (stream path
                                                  :direction :input
                                                  :element-type '(unsigned-byte 8))
                            (let ((bytes (make-array (file-length stream)
                                                     :element-type '(unsigned-byte 8))))
                              (read-sequence bytes stream)
                              bytes))))
          ;; Detect format: new format starts with magic "HIDX"
          (multiple-value-bind (ok reason)
              (if (and (>= (length file-bytes) 4)
                       (equalp (subseq file-bytes 0 4) *header-index-magic*))
                  (load-header-index-v1 state file-bytes)
                  (load-header-index-legacy state file-bytes))
            (when ok
              ;; Replay whatever of the delta log bound to this snapshot is
              ;; intact: it holds the most recently changed statuses.
              (%replay-header-index-delta state))
            (values ok reason)))
      ;; A truncated legacy file (no checksum to catch it) runs the entry
      ;; reader off the end. That is corruption, not absence.
      (error (e)
        (values nil (format nil "unreadable (~A)" e))))))

(defun load-header-index-legacy (state file-bytes)
  "Load header index from old format (no magic, no checksum)."
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    (let ((count (bl.ser:read-uint32-le stream))
          (entries-by-hash (make-hash-table :test 'equalp))
          (prev-hash-map (make-hash-table :test 'equalp)))
      (dotimes (i count)
        (read-single-header-entry stream entries-by-hash prev-hash-map))
      (link-header-entries entries-by-hash prev-hash-map)
      (setf (chain-state-block-index state) entries-by-hash)))
  t)

(defun load-header-index-v1 (state file-bytes)
  "Load header index from v1 format with integrity checks. Returns
(values T NIL) or (values NIL REASON), as LOAD-HEADER-INDEX documents."
  ;; Need at least magic(4) + version(4) + count(4) + crc(4) = 16
  (when (< (length file-bytes) 16)
    (return-from load-header-index-v1
      (values nil (format nil "file too short (~D bytes)" (length file-bytes)))))
  ;; Verify CRC32
  (let* ((data-len (- (length file-bytes) 4))
         (data-bytes (subseq file-bytes 0 data-len))
         (stored-crc (subseq file-bytes data-len))
         (computed-crc (compute-crc32 data-bytes)))
    (unless (equalp stored-crc computed-crc)
      (return-from load-header-index-v1
        (values nil "CRC32 mismatch"))))
  ;; Parse data
  (flexi-streams:with-input-from-sequence (stream file-bytes)
    ;; Skip magic
    (let ((magic (make-array 4 :element-type '(unsigned-byte 8))))
      (read-sequence magic stream))
    ;; Check version: v1 entries lack the trailing tx-count (read as 0,
    ;; backfilled lazily); v2 includes it.
    (let ((version (bl.ser:read-uint32-le stream)))
      (unless (member version '(1 2 3))
        (return-from load-header-index-v1
          (values nil (format nil "unsupported format version ~D (this build writes ~D)"
                              version +header-index-format-version+))))
      ;; Read entries
      (let ((count (bl.ser:read-uint32-le stream))
            (entries-by-hash (make-hash-table :test 'equalp))
            (prev-hash-map (make-hash-table :test 'equalp))
            (with-tx-count (>= version 2))
            (with-position (>= version 3)))
        (dotimes (i count)
          (read-single-header-entry stream entries-by-hash prev-hash-map
                                    with-tx-count with-position))
        (link-header-entries entries-by-hash prev-hash-map)
        (setf (chain-state-block-index state) entries-by-hash))))
  t)

(defun read-single-header-entry (stream entries-by-hash prev-hash-map
                                 &optional with-tx-count with-position)
  "Read a single header entry from STREAM into ENTRIES-BY-HASH. WITH-TX-COUNT
reads the trailing v2 tx-count field (v1/legacy entries default it to 0);
WITH-POSITION reads the v3 flat-file position.

An entry without a position is not an error and not a missing block: it is a
block stored before the flat files existed, whose body lives in the legacy
per-block file named by its hash. That is what makes the dual-read of P2
possible, and why the position is nullable rather than defaulted."
  (let ((hash (make-array 32 :element-type '(unsigned-byte 8))))
    (read-sequence hash stream)
    (let* ((height (bl.ser:read-uint32-le stream))
           (header-bytes (make-array 80 :element-type '(unsigned-byte 8))))
      (read-sequence header-bytes stream)
      (let* ((chainwork (deserialize-chainwork stream))
             (status-byte (read-byte stream))
             (status (ecase status-byte
                       (0 :unknown) (1 :header-valid) (2 :valid) (3 :invalid)))
             (prev-hash (make-array 32 :element-type '(unsigned-byte 8))))
        (read-sequence prev-hash stream)
        (let ((tx-count (if with-tx-count
                            (bl.ser:read-uint32-le stream)
                            0))
              (header (handler-case
                          (flexi-streams:with-input-from-sequence (hs header-bytes)
                            (bl.ser:read-block-header hs))
                        (error () nil))))
          (multiple-value-bind (file data-pos undo-pos)
              (if with-position
                  (let ((f (bl.ser:read-int32-le stream))
                        (d (bl.ser:read-uint32-le stream))
                        (u (bl.ser:read-uint32-le stream)))
                    (values (unless (minusp f) f)
                            (unless (= d #xFFFFFFFF) d)
                            (unless (= u #xFFFFFFFF) u)))
                  (values nil nil nil))
          (let ((entry (make-block-index-entry
                        :hash hash
                        :height height
                        :header header
                        :prev-entry nil
                        :chain-work chainwork
                        :status status
                        :tx-count tx-count
                        :file file
                        :data-pos data-pos
                        :undo-pos undo-pos)))
            (setf (gethash hash entries-by-hash) entry)
            (unless (every #'zerop prev-hash)
              (setf (gethash hash prev-hash-map) (copy-seq prev-hash))))))))))

(defun link-header-entries (entries-by-hash prev-hash-map)
  "Link prev-entry pointers in the block index."
  (maphash (lambda (hash prev-hash)
             (let ((entry (gethash hash entries-by-hash))
                   (prev-entry (gethash prev-hash entries-by-hash)))
               (when (and entry prev-entry)
                 (setf (block-index-entry-prev-entry entry) prev-entry))))
           prev-hash-map))
