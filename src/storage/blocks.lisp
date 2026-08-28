(in-package #:bitcoin-lisp.storage)

;;; Block storage
;;;
;;; Simple file-based block storage for the Bitcoin client.
;;; Blocks are stored as individual files named by their hash.

(defvar *data-directory* nil
  "Base directory for all data storage.")

(defvar *blocks-directory* nil
  "Directory for block files.")

(defstruct block-file-info
  "Per-file accounting for a blk/rev pair (Core CBlockFileInfo, kernel/blockmanager_opts
or chain.h). HEIGHT-FIRST and HEIGHT-LAST bound what the file contains, and
they are the whole reason a file can be pruned safely: Core deletes a file only
when its entire range lies inside the prunable window."
  (blocks 0 :type (integer 0))
  (size 0 :type (integer 0))
  (undo-size 0 :type (integer 0))
  (height-first nil :type (or null (unsigned-byte 32)))
  (height-last nil :type (or null (unsigned-byte 32))))

(defvar *flat-block-files* t
  "Write new blocks into Core's numbered blk?????.dat files instead of one file
per block.

Default ON since 2026-08-26. It was OFF while pruning was per-block deletion,
because a flat file cannot have a block cut out of the middle of it and a pruned
node would have silently stopped reclaiming space the moment its new blocks went
into flat files. That is no longer the case: PRUNE-OLD-BLOCKS and
PRUNE-BLOCKS-TO-HEIGHT both select whole blk/rev pairs whose entire height range
lies inside the prune window (Core FindFilesToPrune), and PRUNE-LOCK-CEILING
keeps them off the tail an index still needs — P3 of
docs/block-file-format-plan.md, complete.

Turning it off is still supported and still safe. READING is not gated: a store
always reads whichever form each block is in, so a datadir written in either
form, or in both, stays fully readable whichever way the flag is set.")

(defstruct block-store
  "Block storage manager."
  (base-path nil :type (or null pathname))
  ;; hash -> where the block is: a PATHNAME for a legacy per-block file, or a
  ;; FLAT-FILE-POS for a record inside a blk?????.dat. Both forms coexist for
  ;; the whole life of a store that has ever held either.
  (index (make-hash-table :test 'equalp) :type hash-table)
  ;; The blk sequence and where the next record goes. Core keeps the same pair
  ;; as m_blockfile_cursors (blockstorage.h:151-175).
  (blk-seq nil)
  (cursor-file 0 :type (unsigned-byte 32))
  (cursor-pos 0 :type (unsigned-byte 32))
  ;; The rev sequence. It needs no cursor pair: an undo record goes into the
  ;; file its block went into, at that file's own UNDO-SIZE offset, so the
  ;; per-file accounting IS the cursor (Core CBlockFileInfo::nUndoSize).
  (rev-seq nil)
  ;; The blocksdir obfuscation key, read or created once at init.
  (xor-key nil)
  ;; File number -> BLOCK-FILE-INFO (Core m_blockfile_info). What makes
  ;; file-granular pruning possible: a whole blk/rev pair can be deleted only
  ;; when EVERY block in it is inside the prunable window, which needs the
  ;; file's height range.
  (file-info (make-hash-table :test 'eql) :type hash-table)
  ;; Running total of all .blk file sizes, maintained by store-block and
  ;; prune-block and initialized by the init-block-store scan. Pruning
  ;; consults this after EVERY connected block (validation/block.lisp), so
  ;; it must be O(1) — re-scanning the blocks directory per block collapsed
  ;; mainnet IBD from ~220 b/s to ~0.3 b/s the moment the chain crossed
  ;; *prune-after-height*. Mirrors Bitcoin Core, which sums in-memory
  ;; per-file stats (m_blockfile_info) in CalculateCurrentUsage() rather
  ;; than touching the filesystem (validation.cpp).
  (total-bytes 0 :type (integer 0)))

(defun ensure-directories (store)
  "Ensure storage directories exist."
  (let ((blocks-path (merge-pathnames "blocks/" (block-store-base-path store))))
    (ensure-directories-exist blocks-path)
    blocks-path))

(defun block-file-path (store hash)
  "Get the file path for a block with given HASH."
  (let ((hash-hex (bl.crypto:bytes-to-hex hash)))
    (merge-pathnames (format nil "blocks/~A.blk" hash-hex)
                     (block-store-base-path store))))

(defun file-size-bytes (path)
  "Size of the file at PATH in bytes, or NIL if it doesn't exist.
Uses stat on SBCL — one syscall, no file open."
  #+sbcl
  (handler-case
      (sb-posix:stat-size (sb-posix:stat (namestring path)))
    (error () nil))
  #-sbcl
  (handler-case
      (with-open-file (s path :direction :input
                              :element-type '(unsigned-byte 8))
        (file-length s))
    (error () nil)))

(defun block-network-magic ()
  "The 4-byte network magic that prefixes every stored record, which is the
same value the P2P message header uses (Core MessageStart)."
  (bl.chain:network-magic bl.chain:*network*))

(defun %blk-seq (store)
  "The blk file sequence, created on demand."
  (or (block-store-blk-seq store)
      (setf (block-store-blk-seq store)
            (make-flat-file-seq (ensure-directories store) "blk"
                                +blockfile-chunk-size+))))

(defun %store-block-flat (store data)
  "Append a block's serialized DATA to the current blk file and return its
FLAT-FILE-POS. The position points PAST the 8-byte header, at the payload,
which is what Core records as nDataPos."
  (let* ((seq (%blk-seq store))
         (record (flat-record-bytes (block-network-magic) data))
         (need (length record)))
    ;; Roll over rather than exceed Core's maximum file size, finalizing the
    ;; file we are leaving so its preallocated tail is truncated away.
    (when (and (plusp (block-store-cursor-pos store))
               (> (+ (block-store-cursor-pos store) need)
                  (max-blockfile-size need)))
      (flat-file-flush seq
                       (make-flat-file-pos (block-store-cursor-file store)
                                           (block-store-cursor-pos store))
                       :finalize t)
      (incf (block-store-cursor-file store))
      (setf (block-store-cursor-pos store) 0))
    (let* ((file (block-store-cursor-file store))
           (start (block-store-cursor-pos store))
           (pos (make-flat-file-pos file start)))
      (flat-file-allocate seq pos need)
      ;; Obfuscated at the record's real file offset: the key alignment of
      ;; every byte depends on where it lands, not on where the buffer starts.
      ;; RECORD is freshly built by FLAT-RECORD-BYTES and read by nobody after
      ;; the write, so it is obfuscated in place — a copy is a second full
      ;; block-sized allocation on the IBD hot path.
      (obfuscate! record (block-store-xor-key store) :key-offset start)
      (with-open-file (out (flat-file-name seq pos)
                           :direction :io :element-type '(unsigned-byte 8)
                           :if-exists :overwrite :if-does-not-exist :create)
        (file-position out start)
        (write-sequence record out)
        (finish-output out)
        ;; Same durability rule as the per-block path: connect-block stores
        ;; the block before the chainstate flush that references it.
        #+sbcl (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd out))))
      (setf (block-store-cursor-pos store) (+ start need))
      (make-flat-file-pos file (+ start +storage-header-bytes+)))))

(defun %read-block-flat (store pos)
  "Read and deserialize the block whose payload starts at POS. Returns NIL if
the record is missing, mis-framed, or unreadable."
  (let* ((seq (%blk-seq store))
         (path (flat-file-name seq pos))
         (record-start (- (flat-file-pos-pos pos) +storage-header-bytes+)))
    (when (probe-file path)
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (when (<= (+ record-start +storage-header-bytes+) (file-length in))
          (file-position in record-start)
          (let ((header (make-array +storage-header-bytes+
                                    :element-type '(unsigned-byte 8))))
            (read-sequence header in)
            (obfuscate! header (block-store-xor-key store) :key-offset record-start)
            (multiple-value-bind (magic length) (parse-flat-record-header header)
              (when (and (equalp magic (block-network-magic))
                         (<= (+ (flat-file-pos-pos pos) length) (file-length in)))
                (let ((payload (make-array length :element-type '(unsigned-byte 8))))
                  (read-sequence payload in)
                  (obfuscate! payload (block-store-xor-key store)
                              :key-offset (flat-file-pos-pos pos))
                  ;; BR-READ-BITCOIN-BLOCK, not a flexi-stream: the payload is
                  ;; already a byte vector, so wrapping it in a Gray stream
                  ;; buys nothing and costs a generic-function dispatch per
                  ;; read. Profiling an offline reindex put flexi-streams'
                  ;; STREAM-READ-SEQUENCE at 6.4% of runtime with
                  ;; CLASSOID-TYPEP and the PCL braid lambdas behind it — all
                  ;; of it dispatch. The byte-reader existed and said "hot path
                  ;; (per inbound block)" in its own docstring; the DISK path,
                  ;; which reads every block during a reindex, never used it.
                  (bl.ser:br-read-bitcoin-block
                   (bl.ser:make-byte-reader-from payload)))))))))))

(defun %store-file-info (store file)
  (or (gethash file (block-store-file-info store))
      (setf (gethash file (block-store-file-info store)) (make-block-file-info))))

(defun %note-block-in-file (store file height bytes)
  "Fold one stored block into FILE's accounting."
  (let ((info (%store-file-info store file)))
    (incf (block-file-info-blocks info))
    (incf (block-file-info-size info) bytes)
    ;; A file with a block of unknown height has an unknown range, and an
    ;; unknown range can never be shown to lie inside the prunable window — so
    ;; it is never pruned. That is the safe direction: the alternative is
    ;; deleting a block the chain still needs.
    (when height
      (let ((first (block-file-info-height-first info))
            (last (block-file-info-height-last info)))
        (setf (block-file-info-height-first info) (if first (min first height) height)
              (block-file-info-height-last info) (if last (max last height) height))))
    info))

(defun %rev-seq (store)
  "The rev file sequence, created on demand."
  (or (block-store-rev-seq store)
      (setf (block-store-rev-seq store)
            (make-flat-file-seq (ensure-directories store) "rev"
                                +undofile-chunk-size+))))

(defun block-flat-file-number (store hash)
  "The blk file number HASH's body is in, or NIL when it is not in a flat file.

Read from the store's own hash -> position map, which is the ONE place that is
always current. A block index entry's nFile can be stale — a block stored twice
(the fork path stores it, then activation stores it again) leaves the entry
naming the first record while the store points at the second — and an undo
record written into the wrong file number is deleted by pruning while its block
survives."
  (let ((located (gethash hash (block-store-index store))))
    (and (flat-file-pos-p located) (flat-file-pos-file located))))

(defun store-undo-flat (store file prev-block-hash undo-bytes)
  "Append a serialized CBlockUndo to rev<FILE>.dat and return its
FLAT-FILE-POS, whose POS points PAST the 8-byte header at the payload — which
is what Core records as nUndoPos.

FILE is the BLOCK's own file number, not a cursor of our choosing: Core's
FindUndoPos allocates in _pos.nFile, the file the block itself went into
(blockstorage.cpp:996-1026). That pairing is what makes pruning correct, since
prune-flat-block-file deletes blk<N>.dat and rev<N>.dat together — an undo
record in some other file would be deleted while its block was still needed, or
survive its block forever.

The append offset is the file's own UNDO-SIZE (Core CBlockFileInfo::nUndoSize),
so undo records pack independently of how full the blk file is."
  (let* ((seq (%rev-seq store))
         (record (undo-record-bytes (block-network-magic) prev-block-hash undo-bytes))
         (info (%store-file-info store file))
         (start (block-file-info-undo-size info))
         (pos (make-flat-file-pos file start)))
    (flat-file-allocate seq pos (length record))
    ;; Obfuscated at the record's real file offset, like a block record: the
    ;; key alignment of every byte depends on where it lands. Core applies the
    ;; blocksdir XOR key to rev files exactly as it does to blk files.
    (obfuscate! record (block-store-xor-key store) :key-offset start)
    (with-open-file (out (flat-file-name seq pos)
                         :direction :io :element-type '(unsigned-byte 8)
                         :if-exists :overwrite :if-does-not-exist :create)
      (file-position out start)
      (write-sequence record out)
      (finish-output out)
      ;; Undo data must be durable before the chainstate that depends on it,
      ;; the same rule the block path follows.
      #+sbcl (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd out))))
    (setf (block-file-info-undo-size info) (+ start (length record)))
    ;; Undo bytes count toward the storage total, as they do in Core
    ;; (CalculateCurrentUsage sums nSize + nUndoSize, blockstorage.cpp:793-802).
    ;; Without this the live path never adds what prune-flat-block-file later
    ;; subtracts, so every pruned file walked the total DOWN by its rev file's
    ;; size until pruning decided it was already under target and stopped.
    (incf (block-store-total-bytes store) (length record))
    (make-flat-file-pos file (+ start +storage-header-bytes+))))

(defun read-undo-flat (store pos prev-block-hash)
  "The serialized CBlockUndo payload whose record header sits 8 bytes before
POS, or NIL when the record is missing, mis-framed, or fails its checksum.

Core verifies SHA256d(prev block hash || payload) on every undo read
(UndoReadFromDisk, blockstorage.cpp:1075-1096) and treats a mismatch as a
failed read, not a corrupt-database abort — so this returns NIL and lets the
caller fall back or re-derive."
  (let* ((seq (%rev-seq store))
         (path (flat-file-name seq pos))
         (key (block-store-xor-key store))
         (payload-start (flat-file-pos-pos pos))
         (record-start (- payload-start +storage-header-bytes+)))
    ;; A position inside the header cannot name a record. Core guards the same
    ;; case and names its two sources — pruning, and a default-constructed
    ;; position (UndoReadFromDisk, blockstorage.cpp:1084-1090) — both of which
    ;; reach here as a stale or zero nUndoPos out of the persisted index.
    (when (and (>= record-start 0) (probe-file path))
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (let ((size (file-length in)))
          (when (<= payload-start size)
            (file-position in record-start)
            (let ((header (make-array +storage-header-bytes+
                                      :element-type '(unsigned-byte 8))))
              (read-sequence header in)
              (obfuscate! header key :key-offset record-start)
              (multiple-value-bind (magic length) (parse-flat-record-header header)
                (when (and (equalp magic (block-network-magic))
                           (plusp length)
                           ;; the payload AND the checksum that follows it
                           (<= (+ payload-start length
                                  (- +undo-data-disk-overhead+ +storage-header-bytes+))
                               size))
                  (let ((payload (make-array length :element-type '(unsigned-byte 8)))
                        (checksum (make-array 32 :element-type '(unsigned-byte 8))))
                    (read-sequence payload in)
                    (obfuscate! payload key :key-offset payload-start)
                    (read-sequence checksum in)
                    (obfuscate! checksum key :key-offset (+ payload-start length))
                    (when (equalp checksum
                                  (undo-record-checksum prev-block-hash payload))
                      payload)))))))))))

(defun %existing-rev-file-numbers (store)
  "The file numbers that actually have a rev?????.dat, ascending."
  (sort (loop for path in (directory
                           (merge-pathnames "rev*.dat" (ensure-directories store)))
              for name = (pathname-name path)
              for number = (and (> (length name) 3)
                                (parse-integer name :start 3 :junk-allowed t))
              when number collect number)
        #'<))

(defun %scan-flat-undo-files (store)
  "Set every rev file's append cursor (BLOCK-FILE-INFO UNDO-SIZE) by walking its
records. Returns the bytes accounted for.

Unlike the blk scan this rebuilds no hash index, because it cannot: an undo
record carries no block hash, and the only thing naming it is the block index's
persisted nUndoPos. Core keeps the same split — rev files are pure payload and
CBlockIndex owns the addressing. All this recovers is where the next record may
safely go, so a restart does not overwrite live undo data."
  (let ((seq (%rev-seq store))
        (key (block-store-xor-key store))
        (magic (block-network-magic))
        (bytes 0))
    ;; Enumerated, not counted from 0 until one is missing: rev numbering has
    ;; holes. Pruning deletes the lowest-numbered files first, and a blk file
    ;; holding only never-connected side-chain blocks never gets a rev sibling
    ;; at all. Stopping at the first gap would leave every file above it with
    ;; an UNDO-SIZE of 0, and the next undo record written there would
    ;; preallocate a chunk of zeros over the records already in it.
    (dolist (file (%existing-rev-file-numbers store))
      (let ((path (flat-file-name seq (make-flat-file-pos file 0))))
          (with-open-file (in path :direction :input
                                      :element-type '(unsigned-byte 8))
               (let ((size (file-length in))
                     (offset 0)
                     (header (make-array +storage-header-bytes+
                                         :element-type '(unsigned-byte 8))))
                 (loop
                   (when (> (+ offset +storage-header-bytes+) size) (return))
                   (file-position in offset)
                   (read-sequence header in)
                   (obfuscate! header key :key-offset offset)
                   (multiple-value-bind (found length) (parse-flat-record-header header)
                     ;; Stop at the first thing that is not a record — which is
                     ;; what the preallocated zero tail looks like.
                     (unless (and (equalp found magic)
                                  (plusp length)
                                  (<= (+ offset length +undo-data-disk-overhead+) size))
                       (return))
                     (let ((consumed (+ length +undo-data-disk-overhead+)))
                       (incf bytes consumed)
                       (incf offset consumed))))
                 (setf (block-file-info-undo-size (%store-file-info store file))
                       offset)))))
    bytes))

(defun store-block (store block &key height)
  "Store a block in the block store.
BLOCK should be a bitcoin-block structure.
Returns (values hash location), where LOCATION is a FLAT-FILE-POS when the
block went into a blk?????.dat and a PATHNAME when it went into a per-block
file (see *FLAT-BLOCK-FILES*).

HEIGHT is what lets the block's file be pruned later: pruning a flat file is
all-or-nothing, so the decision needs the file's height range. Omitting it
stores the block correctly and makes its file unprunable."
  (ensure-directories store)
  (let* ((hash (bl.ser:block-header-hash
                (bl.ser:bitcoin-block-header block)))
         (path (block-file-path store hash))
         ;; Persist blocks witness-complete (BIP144). The generic SERIALIZE
         ;; writes transactions in legacy form, which DROPS witness data — that
         ;; left on-disk blocks unservable to peers (a witness-stripped block
         ;; fails segwit validation, so a peer answering a MSG_WITNESS_BLOCK with
         ;; one gets rejected) and unusable for witness re-validation on reorg.
         ;; serialize-witness-block writes each tx witness-serialized only when it
         ;; carries witness, so non-segwit blocks are byte-identical to before.
         (data (bl.ser:serialize-witness-block block))
         ;; If we're overwriting an already-stored block, its old size is
         ;; in total-bytes and must be replaced, not added to.
         ;; Re-storing a block that is already here replaces its contribution
         ;; to the running total rather than adding to it. For a flat record
         ;; that is the payload plus its header; for a legacy file, the file.
         (old-size (let ((existing (gethash hash (block-store-index store))))
                     (typecase existing
                       (null nil)
                       (flat-file-pos (+ (length data) +storage-header-bytes+))
                       (t (file-size-bytes path))))))
    (cond
      (*flat-block-files*
       (let ((pos (%store-block-flat store data)))
         (setf (gethash hash (block-store-index store)) pos)
         (%note-block-in-file store (flat-file-pos-file pos) height
                              (+ (length data) +storage-header-bytes+))
         ;; The record's overhead counts toward the storage total, as it does
         ;; in Core's per-file accounting.
         (incf (block-store-total-bytes store)
               (- (+ (length data) +storage-header-bytes+) (or old-size 0)))
         (values hash pos)))
      (t
       ;; Write block to file and fsync it: connect-block stores the block before
       ;; the periodic chainstate flush, so the block must be durable before the
       ;; chainstate can reference it — otherwise a power loss can leave the
       ;; chainstate (or its coinbase-probe recovery) pointing at a block file
       ;; that never reached the platter.
       (with-open-file (stream path
                               :direction :output
                               :if-exists :supersede
                               :element-type '(unsigned-byte 8))
         (write-sequence data stream)
         (finish-output stream)
         #+sbcl (ignore-errors (sb-posix:fsync (sb-sys:fd-stream-fd stream))))
       ;; Update index and running storage total
       (setf (gethash hash (block-store-index store)) path)
       (incf (block-store-total-bytes store) (- (length data) (or old-size 0)))
       (values hash path)))))

(defun get-block (store hash)
  "Retrieve a block by its hash.
Returns the bitcoin-block structure, or NIL if not found.

A corrupt / truncated / unreadable block file is treated as ABSENT and PRUNED
rather than allowed to signal. read-bitcoin-block raises on a malformed body;
before this guard that raise escaped through the reorg/download paths
(%best-completable-reorg-target, perform-reorg, retry-best-reorg-candidate) up
to the sync-thread top level and TERMINATED the sync thread — a live-but-wedged
zombie until restart (a real risk given this node's history of corrupt block/
undo files, e.g. a crash mid store-block leaves a truncated-but-indexed .blk).
Pruning is essential, not optional: returning NIL alone leaves probe-file true
so the block is never re-requested (silent permanent stall); deleting the file
makes probe + index agree so the normal download path re-fetches it and
store-block (:if-exists :supersede) overwrites. Every caller already treats NIL
as absent, so none relies on the raise."
  (let ((located (gethash hash (block-store-index store))))
    (when (flat-file-pos-p located)
      (return-from get-block
        (handler-case (%read-block-flat store located)
          (error (e)
            (bl.log:log-warn
             "CORRUPT BLOCK record for ~A (~A) — dropping from the index"
             (bl.crypto:bytes-to-hex hash) e)
            (remhash hash (block-store-index store))
            nil)))))
  ;; ⚠️ OR, not two statements. Appending a form after this LET would DISCARD
  ;; its value, so a block read successfully from the legacy per-block file
  ;; would be thrown away and the function would answer with the genesis
  ;; fallback below — i.e. NIL for almost every block. Cost 33 red tests.
  (or
   (let ((path (block-file-path store hash)))
     (when (probe-file path)
      (handler-case
          (with-open-file (stream path
                                  :direction :input
                                  :element-type '(unsigned-byte 8))
            (let ((data (make-array (file-length stream)
                                    :element-type '(unsigned-byte 8))))
              (read-sequence data stream)
              ;; Byte-reader, not a Gray stream — see the note on the flat-file
              ;; read above. This is the legacy per-block file path.
              (bl.ser:br-read-bitcoin-block
               (bl.ser:make-byte-reader-from data))))
        (error (e)
          (bl.log:log-warn
           "CORRUPT BLOCK file for ~A (~A) — pruning for re-download"
           (bl.crypto:bytes-to-hex hash) e)
          (ignore-errors (prune-block store hash))
          nil))))
   ;; The genesis block is never RECEIVED, so nothing ever stores its body — but
  ;; Core has it on disk from initialisation (BlockManager writes it before the
  ;; first sync), so every Core reader can fetch it. getblock(getbestblockhash())
  ;; on a fresh node is genesis, and Core's functional tests open with exactly
  ;; that: p2p_invalid_block.py:45 and p2p_invalid_tx.py:54 both did, and both
  ;; died on "Block not found".
  ;;
  ;; Rebuilt rather than stored, and rebuilt HERE rather than at the twelve
  ;; RPC/REST call sites that want a block body: one of them would have been
  ;; missed. MAKE-GENESIS-BLOCK is self-verifying (it recomputes the merkle root
  ;; and checks the header hash against the network's known genesis), so this
   ;; cannot answer with the wrong block.
   (%genesis-block-body hash)))

(defvar *genesis-body-cache* (make-hash-table :test 'eq :synchronized t)
  "network -> its genesis block, so repeated lookups do not re-derive it.

SYNCHRONIZED because GET-BLOCK is reachable from the parallel script-check
workers, and this is written on first use rather than at load time. There are
at most five entries and they are written once each, so the lock is never
contended — it is here so the table cannot be the next *FLAG-SET-CACHE*.")

(defun %genesis-block-body (hash)
  "The genesis block when HASH is this network's genesis hash, else NIL.

⚠️ Total by construction. GET-BLOCK's MISS is the ordinary case — every
download decision asks it about a block it does not have — so this must answer
NIL and never signal. NETWORK-GENESIS-HASH is an ECASE and MAKE-GENESIS-BLOCK
raises when construction does not reproduce the known hash; letting either
escape turns `absent' into an error on a path that has no handler for one, and
takes the reorg, migration and filter-index tests down with it."
  (let ((network bl.chain:*network*))
    (let ((genesis (ignore-errors (network-genesis-hash network))))
      (when (and genesis (equalp hash genesis))
        (or (gethash network *genesis-body-cache*)
            (let ((block (ignore-errors (make-genesis-block network))))
              (when block
                (setf (gethash network *genesis-body-cache*) block))))))))

(defun block-exists-p (store hash)
  "Check if a block with HASH exists in storage, in either form."
  (let ((located (gethash hash (block-store-index store))))
    (if (flat-file-pos-p located)
        t
        (probe-file (block-file-path store hash)))))

(defun %scan-flat-block-files (store)
  "Rebuild the hash -> position map by walking every blk?????.dat, and leave the
cursor at the end of the last one. Returns the bytes accounted for.

This is most of what a full -reindex does, and it is cheap: each record is
found by hopping over the previous one's length, and identifying a block needs
only its 80-byte header, never a full deserialization. Walking a file stops at
the first header that is not a record — which is exactly what the preallocated
zero tail of the file currently being appended to looks like."
  (let ((seq (%blk-seq store))
        (key (block-store-xor-key store))
        (magic (block-network-magic))
        (bytes 0)
        (last-file 0)
        (last-pos 0))
    (loop for file from 0
          for path = (flat-file-name seq (make-flat-file-pos file 0))
          while (probe-file path)
          do (with-open-file (in path :direction :input
                                      :element-type '(unsigned-byte 8))
               (let ((size (file-length in))
                     (offset 0)
                     (header (make-array +storage-header-bytes+
                                         :element-type '(unsigned-byte 8)))
                     (hdr80 (make-array 80 :element-type '(unsigned-byte 8))))
                 (loop
                   (when (> (+ offset +storage-header-bytes+) size) (return))
                   (file-position in offset)
                   (read-sequence header in)
                   (obfuscate! header key :key-offset offset)
                   (multiple-value-bind (found length) (parse-flat-record-header header)
                     (unless (and (equalp found magic)
                                  (plusp length)
                                  (>= length 80)
                                  (<= (+ offset +storage-header-bytes+ length) size))
                       (return))
                     (read-sequence hdr80 in)
                     (obfuscate! hdr80 key
                                 :key-offset (+ offset +storage-header-bytes+))
                     (let ((hash (bl.crypto:hash256 hdr80)))
                       (setf (gethash hash (block-store-index store))
                             (make-flat-file-pos file (+ offset +storage-header-bytes+))))
                     (incf bytes (+ +storage-header-bytes+ length))
                     (setf offset (+ offset +storage-header-bytes+ length)
                           last-file file
                           last-pos offset)))))
          finally (setf (block-store-cursor-file store) last-file
                        (block-store-cursor-pos store) last-pos))
    bytes))

(defun init-block-store (base-path)
  "Initialize a block store at BASE-PATH."
  (let ((store (make-block-store :base-path (pathname base-path))))
    (ensure-directories store)
    ;; The obfuscation key is read before anything is scanned: without it every
    ;; record header would look like garbage and the scan would find nothing.
    ;; A key is only CREATED for a directory with no block data in it.
    (setf (block-store-xor-key store)
          (let* ((blocks-dir (merge-pathnames "blocks/" base-path))
                 (key (read-or-create-xor-key blocks-dir :use-xor *blocks-xor*)))
            ;; -blocksxor=0 on a blocksdir that already holds a random key is
            ;; REFUSED, not silently honoured (Core InitBlocksdirXorKey,
            ;; blockstorage.cpp:1213-1219). Reading those files without the key
            ;; returns garbage, and a node that started anyway would conclude
            ;; its whole block store was corrupt. Now that a fresh datadir gets
            ;; a key by default, this is the ordinary way an operator meets it.
            (when (and (not *blocks-xor*) (notevery #'zerop key))
              (config-error "The blocksdir XOR-key can not be disabled when a random ~
key was already stored! Stored key: '~A', stored path: '~A'."
                     (bl.crypto:bytes-to-hex key)
                     (namestring (merge-pathnames "xor.dat" blocks-dir))))
            key))
    ;; blocks/index/ eagerly, even though nothing is written into it until the
    ;; first index flush. Core opens its block-index LevelDB in BlockManager's
    ;; constructor, so the directory exists from the moment the node is up — and
    ;; the functional tests treat it as a fixture, deleting it by name to force
    ;; a reindex (feature_reindex_init.py). Here rather than in
    ;; ENSURE-DIRECTORIES, which STORE-BLOCK calls for every block written: the
    ;; directory needs creating once per store, and ENSURE-DIRECTORIES-EXIST
    ;; stats every path component each time it is asked.
    (ensure-directories-exist (datadir-block-index-path base-path))
    ;; Scan for existing blocks (the only full-directory scan — from here
    ;; on, total-bytes is maintained incrementally)
    (let ((blocks-dir (merge-pathnames "blocks/" base-path))
          (total-bytes 0))
      (when (probe-file blocks-dir)
        (dolist (file (directory (merge-pathnames "*.blk" blocks-dir)))
          (let* ((name (pathname-name file))
                 (hash (bl.crypto:hex-to-bytes name)))
            (setf (gethash hash (block-store-index store)) file)
            (incf total-bytes (or (file-size-bytes file) 0)))))
      ;; Then the flat files. Both forms are indexed, which is what makes the
      ;; store readable across the transition in either direction.
      (incf total-bytes (%scan-flat-block-files store))
      ;; And the rev files, which only restore each file's append cursor —
      ;; without this a restart would write the next undo record over the
      ;; records already in the file.
      (incf total-bytes (%scan-flat-undo-files store))
      (setf (block-store-total-bytes store) total-bytes))
    store))

(defun ensure-genesis-on-disk (store)
  "Write the genesis block into STORE if it is not already there.

Core has genesis on disk from initialisation, before the first sync, so
blk00000.dat begins with it and every reader that walks the block files finds
the chain from height 0. We never RECEIVE genesis, so nothing else ever stores
it, and GET-BLOCK answered from a rebuilt in-memory copy instead — enough for
the RPCs, but it left the block FILES starting at height 1.

That gap is invisible from inside the node and fatal to anything outside it.
Core's contrib/linearize walks blk?????.dat looking for each hash its RPC
listed; missing height 0 it matches none of the rest either (it emits in height
order), scans the preallocated zero tail a byte at a time hunting for the magic,
and never finishes — feature_loadblock.py went from failing in seconds to not
terminating at all the moment we started writing real blk files.

Called from node start-up, next to the rest of chain initialisation, and NOT
from INIT-BLOCK-STORE: Core writes genesis while initialising the CHAIN, not in
the storage constructor, and a store opened for a migration, a test fixture or
an offline tool has no business acquiring a block it was not given.

Best effort by construction: a datadir that cannot be written (read-only, full
disk) is a problem for whoever actually needs to write, not for start-up."
  (ignore-errors
   (let ((hash (ignore-errors (network-genesis-hash bl.chain:*network*))))
     (when (and hash (not (gethash hash (block-store-index store))))
       (let ((block (%genesis-block-body hash)))
         (when block
           (store-block store block :height 0)))))))

;;; Block Pruning

(defun prune-block (store hash)
  "Delete a block file from disk by HASH.
Returns the size in bytes of the deleted file, or NIL if the file didn't exist."
  ;; A block inside a blk?????.dat cannot be removed on its own — Core prunes
  ;; whole files, which is P3 of the block-file-format plan. Refuse loudly
  ;; rather than returning NIL, which the caller reads as "already gone" and
  ;; would let a pruned node stop reclaiming space in silence.
  (when (flat-file-pos-p (gethash hash (block-store-index store)))
    (bl.log:log-warn
     "Cannot prune ~A: it is inside a flat block file, which prunes per FILE ~
      (block-file-format P3). Callers that only need the body to become ~
      unreadable want FORGET-BLOCK-BODY."
     (bl.crypto:bytes-to-hex hash))
    (return-from prune-block nil))
  (let* ((path (block-file-path store hash))
         ;; One stat serves both the existence check and the size — NIL
         ;; means the file isn't there.
         (size (file-size-bytes path)))
    (when size
      (delete-file path)
      (remhash hash (block-store-index store))
      (decf (block-store-total-bytes store) size)
      size)))

(defun forget-block-body (store hash)
  "Make HASH's body unreadable so the normal download path re-fetches it, and
return T when there was one to forget.

This is NOT pruning. Pruning reclaims space and is therefore file-granular on
the flat format; this is the narrower \"this copy is unusable, get another\"
operation the reorg path needs when it finds a witness-stripped body. A legacy
per-block file is deleted outright. A flat record cannot be — one blk file holds
many blocks — so the store simply stops pointing at it: GET-BLOCK then reports
the block absent, and the re-downloaded copy is appended as a new record. The
superseded bytes stay in the file as dead space until the whole file prunes,
which is what Core also leaves behind when a block is written twice.

Calling PRUNE-BLOCK here instead would REFUSE for a flat record and leave
GET-BLOCK still serving the witness-stripped body, so the reorg that asked for a
fresh copy would find the same stripped one on every retry, forever."
  (let ((located (gethash hash (block-store-index store))))
    (cond ((flat-file-pos-p located)
           (remhash hash (block-store-index store))
           ;; TOTAL-BYTES is deliberately untouched: the record is still on
           ;; disk and still counts against the prune target until its file
           ;; goes. Decrementing here would walk the total below what the
           ;; filesystem holds and stop a pruned node reclaiming space.
           t)
          (t (and (prune-block store hash) t)))))

(defun rebuild-block-file-info (store chain-state)
  "Recover per-file accounting by joining the store's hash -> position map with
the header index's hash -> height. Called once at startup, after both are
loaded.

Core persists CBlockFileInfo in its block-index database; deriving it instead
means there is no second file to fall out of step with the block files. The
join is the only place the two halves meet: the flat files know WHERE each
block is and the header index knows WHAT HEIGHT it is, and pruning needs both."
  (clrhash (block-store-file-info store))
  (maphash
   (lambda (hash located)
     (when (flat-file-pos-p located)
       (let* ((entry (get-block-index-entry chain-state hash))
              (height (and entry (block-index-entry-height entry))))
         ;; The record's own byte count is not known without re-reading it;
         ;; the running total is maintained elsewhere, and pruning only needs
         ;; the height range plus a per-file byte figure, which the file's own
         ;; size on disk supplies.
         (%note-block-in-file store (flat-file-pos-file located) height 0))))
   (block-store-index store))
  ;; Take each file's byte count from the filesystem rather than summing
  ;; records: the difference is the preallocated tail, and pruning frees the
  ;; whole file including that tail.
  (maphash (lambda (file info)
             (let ((path (flat-file-name (%blk-seq store) (make-flat-file-pos file 0))))
               (setf (block-file-info-size info) (or (file-size-bytes path) 0))))
           (block-store-file-info store))
  ;; The clrhash above dropped every UNDO-SIZE, which is the rev files' append
  ;; cursor and is derived from a different source than everything else here.
  ;; Re-derive it, so this function is the single point at which the table is
  ;; fully populated: leaving it at 0 made the next undo record written to a
  ;; file preallocate a chunk of zeros over the records already in it, and the
  ;; blocks in that chunk became permanently undisconnectable.
  (%scan-flat-undo-files store)
  (hash-table-count (block-store-file-info store)))

(defun %prunable-flat-files (store min-height max-height)
  "File numbers whose ENTIRE height range lies within [MIN-HEIGHT, MAX-HEIGHT]
(Core FindFilesToPrune's per-file test). A file with an unknown range, or one
holding a single block outside the window, is not prunable — pruning a flat
file is all or nothing."
  (let ((files '()))
    (maphash (lambda (file info)
               (let ((first (block-file-info-height-first info))
                     (last (block-file-info-height-last info)))
                 (when (and first last
                            (>= first min-height)
                            (<= last max-height)
                            (plusp (block-file-info-blocks info)))
                   (push file files))))
             (block-store-file-info store))
    (sort files #'<)))

(defconstant +prune-lock-buffer+ 10
  "Blocks kept below a prune lock's floor, on top of the floor itself (Core
PRUNE_LOCK_BUFFER, validation.cpp:113).")

(defvar *prune-locks* (make-hash-table :test 'equal :synchronized t)
  "Name -> a thunk returning that subsystem's earliest height that must survive
pruning, or NIL when it has none yet (Core BlockManager::m_prune_locks).

A THUNK rather than a stored height, deliberately. Core updates its lock inside
SetBestBlockIndex, the one funnel every index passes through; we have no such
funnel — blockfilterindex and coinstatsindex each write their meta record from
several places, and a lock that is only as fresh as the last remembered write
is a lock that silently stops protecting the index the moment a new write site
is added. Asking the index for its height AT PRUNE TIME cannot go stale, and it
makes registration (one site per index) the only thing that can be forgotten.

Synchronized because the two ends run on different threads: registration is on
the startup thread and PRUNE-LOCK-CEILING is called from the validation thread
after every connected block.")

(defun register-prune-lock (name height-fn)
  "Register HEIGHT-FN under NAME as a prune lock. Re-registering replaces."
  (setf (gethash name *prune-locks*) height-fn))

(defun clear-prune-locks ()
  "Forget every registered prune lock."
  (clrhash *prune-locks*))

(defun prune-lock-ceiling (chain-height)
  "The highest block pruning may delete, given the registered locks.

Core: last_prune starts at the chain height and each lock lowers it to
height_first - PRUNE_LOCK_BUFFER - 1, floored at 1 (validation.cpp:2722-2732).
A lock whose subsystem has no height yet does not constrain — that is Core's
height_first == INT_MAX case."
  (let ((ceiling chain-height))
    (maphash (lambda (name height-fn)
               (declare (ignore name))
               (let ((height (ignore-errors (funcall height-fn))))
                 (when height
                   (setf ceiling
                         (max 1 (min ceiling
                                     (- height +prune-lock-buffer+ 1)))))))
             *prune-locks*)
    ceiling))

(defun prune-flat-block-file (store file &key on-prune)
  "Delete the blk/rev pair FILE and forget every block in it (Core
PruneOneBlockFile plus the unlink). Returns the bytes freed.

ON-PRUNE is called with each block's hash, so the caller can drop the matching
undo data and clear the index entry's HAVE_DATA — Core does the second inside
PruneOneBlockFile because its index and its files share a lock; here the
callback keeps storage from having to reach into the chain state."
  (let ((freed 0)
        (hashes '()))
    (maphash (lambda (hash located)
               (when (and (flat-file-pos-p located)
                          (= (flat-file-pos-file located) file))
                 (push hash hashes)))
             (block-store-index store))
    (dolist (hash hashes)
      (remhash hash (block-store-index store))
      (when on-prune (funcall on-prune hash)))
    (dolist (seq (list (%blk-seq store) (%rev-seq store)))
      (let ((path (flat-file-name seq (make-flat-file-pos file 0))))
        (let ((size (file-size-bytes path)))
          (when size
            (ignore-errors (delete-file path))
            (incf freed size)))))
    (remhash file (block-store-file-info store))
    (decf (block-store-total-bytes store) (min freed (block-store-total-bytes store)))
    (bl.log:log-info "Pruned block file ~D: ~D blocks, ~D bytes"
                           file (length hashes) freed)
    freed))

(defun block-storage-size-mib (store)
  "Total size of all block files in MiB. O(1) — reads the running counter
maintained by store-block/prune-block (initialized by init-block-store)."
  (/ (block-store-total-bytes store) 1048576.0))  ; 1024 * 1024

(defun prune-old-blocks (store chain-state &key on-prune target-bytes)
  "Prune old blocks when storage exceeds target.
Deletes oldest block files until storage is at or below the effective prune
target (halved while an assumeutxo historical chainstate exists — Core
BlockManager::FindFilesToPrune, node/blockstorage.cpp:330-338), respecting
+min-blocks-to-keep+, *prune-after-height*, and CHAIN-STATE's per-chainstate
prune floor (an unvalidated snapshot chainstate never prunes at or below its
base — Core Chainstate::GetPruneRange). TARGET-BYTES is the automatic target,
defaulting to the single-chainstate PRUNE-TARGET-BYTES; the node passes
(effective-prune-target-bytes), which halves it while an assumeutxo
historical chainstate exists -- a fact only the node knows.
Only runs in automatic pruning mode.
Returns the number of blocks pruned."
  (unless (automatic-pruning-p)
    (return-from prune-old-blocks 0))
  (let ((current-height (chain-state-best-height chain-state))
        (prune-after (or *prune-after-height* 0)))
    ;; Don't prune until chain reaches prune-after-height
    (when (< current-height prune-after)
      (return-from prune-old-blocks 0))
    ;; Computed here, after the mode and height guards: with pruning off there
    ;; is no target to compute (*prune-target-mib* is NIL).
    (let ((target-bytes (or target-bytes (prune-target-bytes))))
      (when (<= (block-store-total-bytes store) target-bytes)
        (return-from prune-old-blocks 0))
      ;; Calculate the allowed prune window: (floor, min-keep-height].
      ;; MIN of the retention window and the prune-lock ceiling: an index that
      ;; still needs a block's undo data holds the horizon down until it has
      ;; caught up (Core caps last_prune by every lock before calling
      ;; FindFilesToPrune, validation.cpp:2722-2732).
      (let* ((min-keep-height (min (max 0 (- current-height
                                             +min-blocks-to-keep+))
                                   (prune-lock-ceiling current-height)))
             (start (chain-state-prune-walk-start chain-state))
             (pruned 0))
        ;; Nothing left in the window. PRUNE-BLOCKS-TO-HEIGHT has always had
        ;; this guard; without it here a prune lock that drives MIN-KEEP-HEIGHT
        ;; below START — an index parked near genesis on a node that has
        ;; already pruned far — hands ACTIVE-CHAIN-ENTRIES-FROM a NEGATIVE
        ;; count, and that walks prev-entry from the tip all the way down
        ;; before returning nothing. Once per connected block.
        (when (<= min-keep-height start)
          (return-from prune-old-blocks 0))
        ;; Flat files first, whole pairs at a time (Core FindFilesToPrune).
        ;; A blk file cannot have a block cut out of it, so the unit is the
        ;; file and the test is that its ENTIRE height range sits inside the
        ;; window. Legacy per-block files are handled by the walk below; a
        ;; store mid-transition holds both.
        (dolist (file (%prunable-flat-files store (1+ start) min-keep-height))
          (when (<= (block-store-total-bytes store) target-bytes)
            (return))
          (let ((info (gethash file (block-store-file-info store))))
            (let ((last (and info (block-file-info-height-last info)))
                  (blocks (if info (block-file-info-blocks info) 0)))
              (prune-flat-block-file store file :on-prune on-prune)
              (incf pruned blocks)
              (when last
                (setf (chain-state-pruned-height chain-state)
                      (max (chain-state-pruned-height chain-state) last))))))
        ;; Walk from start+1 upward, deleting blocks until the running
        ;; total (maintained by prune-block) is back under target.
        ;; One active-chain walk for the whole range — get-block-at-height
        ;; per height would re-walk from the tip each time, quadratic for
        ;; the initial catch-up prune that deletes a large range at once.
        (loop for entry in (active-chain-entries-from
                            chain-state (1+ start)
                            (- min-keep-height start))
              while (> (block-store-total-bytes store) target-bytes)
              ;; A block inside a blk file is the FLAT pass's business and
              ;; nobody else's. Letting it through here would call PRUNE-BLOCK,
              ;; which refuses for a flat record — and the horizon below would
              ;; then advance PAST a block that is still on disk. On a store in
              ;; the flat format (the default) that is every block: the walk
              ;; start marches up, the file's own first height falls below it,
              ;; %PRUNABLE-FLAT-FILES stops offering the file, and the node
              ;; silently stops reclaiming space for good while reporting a
              ;; prune height it never reached.
              unless (flat-file-pos-p (gethash (block-index-entry-hash entry)
                                               (block-store-index store)))
                do (when (prune-block store (block-index-entry-hash entry))
                     (incf pruned))
                   ;; The undo file goes with the block (Core deletes rev
                   ;; files alongside blk files): a pruned node can't reorg
                   ;; below its window, so undo there is dead weight.
                   (when on-prune
                     (funcall on-prune (block-index-entry-hash entry)))
                   ;; Advance even when the file was already gone — the block
                   ;; is off disk either way, and a permanent gap would force
                   ;; every later call to re-walk from the same height.
                   (setf (chain-state-pruned-height chain-state)
                         (block-index-entry-height entry)))
        pruned))))

(defun prune-blocks-to-height (store chain-state target-height &key on-prune)
  "Prune all block files below TARGET-HEIGHT.
Respects +min-blocks-to-keep+ retention and CHAIN-STATE's per-chainstate
prune floor (Core FindFilesToPruneManual also bounds the manual range by
GetPruneRange, node/blockstorage.cpp:292-319).
Returns the number of blocks pruned."
  (unless (pruning-enabled-p)
    (return-from prune-blocks-to-height 0))
  (let* ((current-height (chain-state-best-height chain-state))
         (max-prune-height (max 0 (- current-height +min-blocks-to-keep+)))
         ;; The locks bound a manual prune too — Core passes the same
         ;; lock-capped last_prune into FindFilesToPruneManual.
         (effective-target (min target-height max-prune-height
                                (prune-lock-ceiling current-height)))
         (start (chain-state-prune-walk-start chain-state))
         (pruned 0))
    (when (<= effective-target start)
      (return-from prune-blocks-to-height 0))
    ;; Flat files first, whole pairs at a time — Core's FindFilesToPruneManual
    ;; selects FILES whose last height is at or below the manual target
    ;; (node/blockstorage.cpp:292-319), because a blk file cannot have a block
    ;; cut out of the middle of it.
    ;;
    ;; Without this, pruneblockchain was a NO-OP on a store using the flat
    ;; format: every block went to PRUNE-BLOCK, which refuses for a flat record
    ;; and returns NIL, so the RPC reported success and freed nothing. That is
    ;; what blocked rolling the flat format out to the pruned mainnet node.
    (dolist (file (%prunable-flat-files store 0 effective-target))
      (let* ((info (gethash file (block-store-file-info store)))
             (last (and info (block-file-info-height-last info)))
             (blocks (if info (block-file-info-blocks info) 0)))
        (prune-flat-block-file store file :on-prune on-prune)
        (incf pruned blocks)
        (when last
          (setf (chain-state-pruned-height chain-state)
                (max (chain-state-pruned-height chain-state) last)))))
    ;; Then any legacy per-block files in the range; a store mid-transition
    ;; holds both forms.
    (dolist (entry (active-chain-entries-from
                    chain-state (1+ start)
                    (- effective-target start 1)))
      ;; Same guard as PRUNE-OLD-BLOCKS: a block in a blk file belongs to the
      ;; flat pass, and the flat pass may deliberately have LEFT its file alone
      ;; (its range reaches above the target, or a prune lock capped it).
      ;; Advancing the horizon over it here would claim heights that are still
      ;; on disk and push the walk start past the file's own first height,
      ;; after which the file can never be offered for pruning again.
      (unless (flat-file-pos-p (gethash (block-index-entry-hash entry)
                                        (block-store-index store)))
        (when (prune-block store (block-index-entry-hash entry))
          (incf pruned))
        (when on-prune
          (funcall on-prune (block-index-entry-hash entry)))
        ;; MAX, not a plain assignment: the flat pass above may already have
        ;; advanced the horizon past this walk's range, and overwriting it with
        ;; the last legacy height would move the horizon BACKWARDS — re-exposing
        ;; heights whose files are gone.
        (setf (chain-state-pruned-height chain-state)
              (max (chain-state-pruned-height chain-state)
                   (block-index-entry-height entry)))))
    pruned))
