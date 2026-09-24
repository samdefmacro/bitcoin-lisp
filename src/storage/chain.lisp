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
  (status :unknown :type keyword)  ; :unknown, :header-valid, :valid, :invalid
  ;; Number of transactions in this block (Bitcoin Core nTx). 0 = unknown —
  ;; header-only entries, or an index persisted before this field existed
  ;; (backfilled lazily from the block store by getchaintxstats).
  (tx-count 0 :type (unsigned-byte 32))
  ;; Where this block's data and undo record live in the flat files (Core
  ;; CBlockIndex nFile / nDataPos / nUndoPos). NIL means "not here": either the
  ;; block has no body yet, or it predates the flat files and lives in the
  ;; legacy per-block file named by its hash, or it was pruned. Core encodes
  ;; the same information as the HAVE_DATA / HAVE_UNDO bits of nStatus
  ;; (chain.h:42-86); keeping the positions themselves nullable makes the two
  ;; impossible to disagree.
  (file nil :type (or null (signed-byte 32)))
  (data-pos nil :type (or null (unsigned-byte 32)))
  (undo-pos nil :type (or null (unsigned-byte 32)))
  ;; The bits of Core's nStatus that the status keyword and the positions do
  ;; not already carry, kept verbatim so a record read from blocks/index is
  ;; written back as it was: BLOCK_OPT_WITNESS (128) above all, which
  ;; NeedsRedownload reads, and the retired BLOCK_STATUS_RESERVED (256). See
  ;; ENTRY-DISK-STATUS in block-tree-db.lisp.
  (status-flags 0 :type (unsigned-byte 32))
  ;; Packed image of the MUTABLE fields as of the last time this entry was
  ;; written to disk; 0 = never written. Comparing it against the entry's
  ;; current packing is what lets a flush write only what changed, instead of
  ;; rewriting the whole index. See %ENTRY-PERSIST-KEY.
  (persisted-key 0 :type (unsigned-byte 64))
  ;; Core CBlockIndex::nSequenceId (chain.h:147-149): the order in which this
  ;; block became a candidate for the active chain -- its body stored with every
  ;; ancestor's body already held. CBlockIndexWorkComparator breaks an
  ;; equal-work tie on it, lower first (node/blockstorage.cpp:180-182), so of
  ;; two equal-work chains the one whose data was COMPLETE first wins. IN MEMORY
  ;; ONLY, never written to the index: an entry starts at
  ;; +SEQ-ID-INIT-FROM-DISK+ and the best chain loaded from disk is lowered to
  ;; +SEQ-ID-BEST-CHAIN-FROM-DISK+ (validation.cpp:4598-4609); preciousblock
  ;; hands out negative values (:3538). See NOTE-BLOCK-RECEIVED.
  (sequence-id 1 :type (signed-byte 32)))

(defstruct chain-state
  "Current blockchain state. One chain-state per chainstate role (Bitcoin
Core's Chainstate, validation.h): today exactly one exists — the primary,
fully-validated chainstate — but the slots below already carry the
assumeutxo identity a snapshot chainstate (a future ActivateSnapshot)
needs, so the node can hold several in a list and select between them."
  (block-index (make-hash-table :test 'equalp) :type hash-table)
  ;; The block tree database this index persists to (blocks/index) is NOT
  ;; per chainstate: every chainstate on one base path shares it, as Core keeps
  ;; the block index in BlockManager, outside any chainstate. See
  ;; *BLOCK-TREE-DBS*.
  (best-block-hash nil)
  (best-height 0 :type (unsigned-byte 32))
  (genesis-hash nil)
  (base-path nil :type (or null pathname))
  (pruned-height 0 :type (unsigned-byte 32))
  ;; The coins view (UTXO set) this chainstate owns — a coins-view-cache on a
  ;; live node, or a plain utxo-set in tests. Core keeps the coins DB + cache
  ;; per chainstate (validation.h m_coins_views); the block/undo stores and
  ;; the header index stay shared across chainstates (Core m_blockman).
  (coins-view nil)
  ;; Base block hash of the snapshot this chainstate was created from (Core
  ;; m_from_snapshot_blockhash); NIL for a chainstate built up from genesis.
  (from-snapshot-blockhash nil)
  ;; :validated | :unvalidated | :invalid (Core enum Assumeutxo,
  ;; validation.h:527-534). NEVER persisted — Core re-derives it on every
  ;; startup by re-proving the snapshot hash, so neither save-state nor the
  ;; header index may ever write it.
  (assumeutxo-status :validated :type keyword)
  ;; Historical-validation target (Core m_target_blockhash, validation.h:643):
  ;; when set, this chainstate only re-derives history up to the target block
  ;; (the snapshot base) instead of following the network tip.
  (target-blockhash nil)
  ;; UTXO-set hash computed once the target block is reached (Core
  ;; m_target_utxohash); NIL before then. A set value means the historical
  ;; validation work is complete.
  (target-utxohash nil)
  ;; On-disk name suffix for this chainstate's files (Core
  ;; SNAPSHOT_CHAINSTATE_SUFFIX \"_snapshot\", node/utxo_snapshot.h:128).
  ;; Empty for the primary chainstate, so its file names are unchanged.
  (storage-suffix "" :type string)
  ;; Per-chainstate coins-cache budget in bytes (Core
  ;; m_coinstip_cache_size_bytes, resized by MaybeRebalanceCaches). NIL means
  ;; the whole global budget — the single-chainstate default. Never persisted:
  ;; Core recomputes cache sizes on every startup/rebalance.
  (coins-cache-bytes nil :type (or null (integer 0)))
  ;; Target-path index: simple-vector mapping height -> the target block's
  ;; ancestor entry at that height (0..target-height), built by
  ;; set-chainstate-target. This is our O(1) form of Core's
  ;; target_block->GetAncestor(h) used by TryAddBlockIndexCandidate
  ;; (validation.cpp:3764-3794) to keep a historical chainstate on the exact
  ;; path to the snapshot base — without it an equal-work sibling fork could
  ;; wedge the background sync. NIL when no target. Never persisted; rebuilt
  ;; whenever the target is set (activation or startup detection).
  (target-ancestors nil :type (or null simple-vector)))

;;; Chainstate selection (Core ChainstateManager, validation.h:1119-1145).
;;; The node holds a list of chain-states ordered like Core's m_chainstates
;;; vector; these pick the one filling each role. With a single (primary)
;;; chainstate all three return it.

(defun select-current-chainstate (chainstates)
  "The chainstate targeting the most-work network tip: the first non-INVALID
entry with no validation target (Core CurrentChainstate). New blocks extend
it and the mempool follows it."
  (find-if (lambda (cs)
             (and (not (eq (chain-state-assumeutxo-status cs) :invalid))
                  (null (chain-state-target-blockhash cs))))
           chainstates))

(defun select-historical-chainstate (chainstates)
  "The chainstate still re-deriving history toward a target block: non-INVALID,
with a target-blockhash but no target-utxohash yet (Core HistoricalChainstate).
NIL when no background validation is in progress."
  (find-if (lambda (cs)
             (and (not (eq (chain-state-assumeutxo-status cs) :invalid))
                  (chain-state-target-blockhash cs)
                  (null (chain-state-target-utxohash cs))))
           chainstates))

(defun select-validated-chainstate (chainstates)
  "The fully-validated chainstate — the one indexes must bind to, since they
index blocks in order from genesis (Core ValidatedChainstate: whichever of
the current/historical chainstates has VALIDATED status)."
  (find-if (lambda (cs)
             (and cs (eq (chain-state-assumeutxo-status cs) :validated)))
           (list (select-current-chainstate chainstates)
                 (select-historical-chainstate chainstates))))

;;; Target block (Core Chainstate::SetTargetBlock / TargetBlock,
;;; validation.h:660-675). A chainstate with a target is \"historical\": it
;;; only re-derives history along the exact ancestor path of the target (the
;;; snapshot base) and stops there.

(defun entry-ancestor-at-height (entry height)
  "ENTRY's chain ancestor at HEIGHT (Core CBlockIndex::GetAncestor), or NIL
when HEIGHT is above ENTRY's height or the prev-entry links don't reach it.
Plain prev-entry walk — O(distance), no skip list."
  (when (and entry (<= height (block-index-entry-height entry)))
    (loop while (and entry (> (block-index-entry-height entry) height))
          do (setf entry (block-index-entry-prev-entry entry)))
    (when (and entry (= (block-index-entry-height entry) height))
      entry)))

(defun set-chainstate-target (chain-state target-entry)
  "Retarget CHAIN-STATE at TARGET-ENTRY (Core SetTargetBlock): record the
target blockhash and build the target-ancestors index (height -> entry along
the target's ancestor path) that keeps a historical chainstate from ever
connecting a block off that path. NIL TARGET-ENTRY clears the target."
  (cond
    ((null target-entry)
     (setf (chain-state-target-blockhash chain-state) nil
           (chain-state-target-ancestors chain-state) nil))
    (t
     (let* ((target-height (block-index-entry-height target-entry))
            (ancestors (make-array (1+ target-height) :initial-element nil)))
       (loop with entry = target-entry
             while entry
             do (setf (aref ancestors (block-index-entry-height entry)) entry)
                (setf entry (block-index-entry-prev-entry entry)))
       (setf (chain-state-target-blockhash chain-state)
             (block-index-entry-hash target-entry)
             (chain-state-target-ancestors chain-state) ancestors))))
  target-entry)

(defun clear-snapshot-chainstate-identity (state)
  "Reset STATE's assumeutxo/snapshot identity so it is a plain, fully-validated
primary chainstate — the inverse of the snapshot-marking slots a snapshot
chainstate carries (storage suffix, from-snapshot-blockhash, :unvalidated
status, target). Keeping this identity-slot set in one place, next to the
chain-state defstruct, means promotion (validated-snapshot-cleanup) can't
drift apart from the snapshot constructor when a slot is added. Returns STATE."
  (set-chainstate-target state nil)
  (setf (chain-state-storage-suffix state) ""
        (chain-state-from-snapshot-blockhash state) nil
        (chain-state-assumeutxo-status state) :validated
        (chain-state-target-utxohash state) nil
        ;; Sole surviving chainstate: back to the whole coins-cache budget
        ;; (Core MaybeRebalanceCaches' single-chainstate arm).
        (chain-state-coins-cache-bytes state) nil)
  state)

(defun chain-state-prune-floor (state)
  "Height of the last UNprunable block for STATE — the per-chainstate prune
range's lower bound (Core Chainstate::GetPruneRange, validation.cpp:6366-6391;
CHAIN-STATE-PRUNE-RANGE-START turns this into Core's prune_start). An
unvalidated snapshot chainstate must never prune a block at or below its
snapshot base: the historical chainstate still has to download and validate
those blocks, and deleting one wedges the background sync permanently. Every other chainstate prunes from genesis (0).
If the base header is somehow missing from the shared index, refuse to prune
anything (most conservative)."
  (let ((base (chain-state-from-snapshot-blockhash state)))
    (if (and base (not (eq (chain-state-assumeutxo-status state) :validated)))
        (let ((entry (get-block-index-entry state base)))
          (if entry
              (block-index-entry-height entry)
              most-positive-fixnum))
        0)))

(defun chain-state-prune-range-start (state)
  "The LOWEST height a prune of STATE may delete — Core GetPruneRange's
prune_start (validation.cpp:6366-6379), which both FindFilesToPrune and
FindFilesToPruneManual apply per file as `nHeightFirst < min_block_to_prune ->
skip' (node/blockstorage.cpp:386 and :308).

0 for an ordinary chainstate, so the file holding genesis is prunable like any
other once its whole range is inside the window; the snapshot base + 1 for an
unvalidated snapshot chainstate, whose earlier blocks the historical chainstate
still has to download and validate.

NOT interchangeable with CHAIN-STATE-PRUNE-WALK-START, which also folds in the
monotone PRUNED-HEIGHT cursor. That cursor is our resume optimization for the
per-block legacy walk and has no counterpart in Core, and using it as the flat
window's floor made blk00000.dat unprunable for the life of the datadir:
PRUNED-HEIGHT starts at 0 so the floor was 1, while that file's height-first is
0 because ENSURE-GENESIS-ON-DISK writes genesis into it, and the floor only
ever rises. The node then retained that pair and pruned an equal volume of
NEWER history in its place."
  (let ((floor (chain-state-prune-floor state)))
    (if (plusp floor) (1+ floor) 0)))

(defun chain-state-prune-walk-start (state)
  "The height a per-block prune walk over STATE resumes ABOVE: the max of the
monotone pruned-height cursor and the per-chainstate prune floor. The legacy
per-block format only; whole-file selection uses
CHAIN-STATE-PRUNE-RANGE-START, which is Core's window floor."
  (max (chain-state-pruned-height state)
       (chain-state-prune-floor state)))

(defun lift-prune-floor-on-promotion (snap historical)
  "Prune-cursor repair when SNAP becomes VALIDATED and its floor lifts:
rewind SNAP's monotone pruned-height cursor to HISTORICAL's, so the window
the floor kept on disk — heights in (historical pruned-height, base] —
becomes reachable again by later prune walks (which skip already-deleted
files harmlessly). Core needs no equivalent: it recomputes GetPruneRange
statelessly on every FindFilesToPrune; the cursor is our walk-resume
optimization, so the floor/cursor interaction is repaired here, next to
where both are defined."
  (setf (chain-state-pruned-height snap)
        (min (chain-state-pruned-height snap)
             (chain-state-pruned-height historical))))

(defun target-ancestor-entry (chain-state height)
  "The target block's ancestor entry at HEIGHT for a targeted (historical)
CHAIN-STATE, or NIL when no target is set / HEIGHT is out of range. O(1) via
the target-ancestors index."
  (let ((ancestors (chain-state-target-ancestors chain-state)))
    (when (and ancestors (< height (length ancestors)))
      (aref ancestors height))))

(defun entry-target-ancestor-p (chain-state entry)
  "T iff ENTRY lies on the exact ancestor path of CHAIN-STATE's target block
(Core target_block->GetAncestor(entry->nHeight) == entry). NIL when no
target is set."
  (and entry
       (eq entry (target-ancestor-entry
                  chain-state (block-index-entry-height entry)))))

(defun chain-state-target-height (chain-state)
  "Height of CHAIN-STATE's target block, or NIL when no target is set."
  (let ((ancestors (chain-state-target-ancestors chain-state)))
    (when ancestors (1- (length ancestors)))))

(defvar *best-header-by-index*
  (make-hash-table :test 'eq :weakness :key :synchronized t)
  "Core ChainstateManager::m_best_header (validation.h:1078), one per block
INDEX: the most-work entry not known to be invalid, kept by
ADD-BLOCK-INDEX-ENTRY and read by BEST-HEADER-ENTRY.

Keyed by the index TABLE rather than kept in a chain-state slot because the
index is shared by every chainstate of one node (a snapshot chainstate is
built on the primary's, node/assumeutxo.lisp) while chain-state structs are
per role -- Core keeps m_best_header on the MANAGER for the same reason -- so a
per-struct slot would let two structs disagree about one index. Weak on the
key so a test's index leaves with it.")

(defun recalculate-best-header (chain-state)
  "Scan the whole block index for the most-work non-invalid entry and make it
the best header -- Core RecalculateBestHeader (validation.cpp:6275-6283), and
what LoadBlockIndex does over the loaded index (validation.cpp:4951-4952).
O(index size): BEST-HEADER-ENTRY calls it only when it has no answer."
  (let ((best nil))
    (maphash (lambda (hash entry)
               (declare (ignore hash))
               (when (and (not (eq (block-index-entry-status entry) :invalid))
                          (or (null best)
                              (> (block-index-entry-chain-work entry)
                                 (block-index-entry-chain-work best))))
                 (setf best entry)))
             (chain-state-block-index chain-state))
    (when best
      (setf (gethash (chain-state-block-index chain-state) *best-header-by-index*)
            best))
    best))

(defun best-header-entry (chain-state)
  "The most-work non-invalid header entry in the block index -- Core
m_best_header. O(1): the entry ADD-BLOCK-INDEX-ENTRY last recorded, unless
that entry has since been marked :invalid (Core recalculates in
InvalidateBlock, validation.cpp:3638-3668) or the index was loaded whole and
nothing has been recorded for it yet, when RECALCULATE-BEST-HEADER scans once
and records the answer. Cheap enough for the per-transaction and per-getdata
paths, which is what Core's cached pointer is for."
  (let ((best (gethash (chain-state-block-index chain-state)
                       *best-header-by-index*)))
    (if (and best (not (eq (block-index-entry-status best) :invalid)))
        best
        (recalculate-best-header chain-state))))

(defun network-genesis-hash (network)
  "NETWORK's genesis block hash, 32 bytes in wire order (chain-params-genesis-hash)."
  (bl.chain:chain-params-genesis-hash (bl.chain:find-chain-params network)))

;;;; Genesis block construction (Core kernel/chainparams.cpp CreateGenesisBlock)
;;;
;;; The genesis block's BODY is never stored in block storage (it is never
;;; received over the wire), but the BIP157 filter index must index it: the
;;; filter-header chain is anchored at filter_header(genesis) computed over the
;;; genesis filter with a 32-zero-byte previous header. So we rebuild the block
;;; from chain parameters exactly as Core does. Construction is self-verifying:
;;; the merkle root is COMPUTED from the constructed coinbase (never a pasted
;;; constant) and the resulting header hash must equal the network's known
;;; genesis hash, or we signal an error rather than return a wrong block.

(defun %ascii-bytes (string)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

(defparameter *genesis-output-pubkey*
  (bl.crypto:hex-to-bytes
   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
  "Satoshi's genesis coinbase pubkey (kernel/chainparams.cpp:71), used by
mainnet, testnet3, signet and regtest. Verified by the genesis-hash check in
MAKE-GENESIS-BLOCK: a transcription error cannot produce the known hash.")

(defun %genesis-coinbase (network)
  "The genesis coinbase transaction for NETWORK, per Core CreateGenesisBlock
(kernel/chainparams.cpp:36-49): scriptSig pushes 486604799, CScriptNum(4) and
the timestamp message; one 50 BTC output to <pubkey> OP_CHECKSIG (testnet4:
33 zero bytes as the \"pubkey\", chainparams.cpp:368)."
  (let* ((testnet4-p (eq network :testnet4))
         (message (%ascii-bytes (bl.chain:chain-params-genesis-timestamp-message
                                 (bl.chain:find-chain-params network))))
         ;; CScript() << 486604799: minimal CScriptNum bytes of 0x1d00ffff,
         ;; little-endian -> ff ff 00 1d, pushed as data.
         (script-sig (concatenate '(simple-array (unsigned-byte 8) (*))
                                  (bl.ser:script-push-data (vector #xff #xff #x00 #x1d))
                                  (bl.ser:script-push-data (vector #x04))
                                  (bl.ser:script-push-data message)))
         (pubkey (if testnet4-p
                     (make-array 33 :element-type '(unsigned-byte 8)
                                    :initial-element 0)
                     *genesis-output-pubkey*))
         (script-pubkey (concatenate '(simple-array (unsigned-byte 8) (*))
                                     (bl.ser:script-push-data pubkey)
                                     (vector #xac)))) ; OP_CHECKSIG
    (bl.ser:make-transaction
     :version 1
     :inputs (vector (bl.ser:make-tx-in
                      :previous-output (bl.ser:make-outpoint
                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                             :initial-element 0)
                                        :index #xffffffff)
                      :script-sig script-sig
                      :sequence #xffffffff))
     :outputs (vector (bl.ser:make-tx-out
                       :value 5000000000
                       :script-pubkey script-pubkey))
     :lock-time 0)))

(defun make-genesis-block (network)
  "Construct NETWORK's full genesis block from chain parameters (Core
CreateGenesisBlock, kernel/chainparams.cpp; per-network time/nonce/bits from
the CreateGenesisBlock call sites). The merkle root is computed from the
constructed coinbase — testnet4's differs from the other networks' — and the
header hash is checked against the known genesis hash, so a wrong construction
signals an error instead of returning a corrupt block."
  (let* ((coinbase (%genesis-coinbase network))
         (merkle-root (bl.ser:transaction-hash coinbase))
         (header
           (let* ((params (bl.chain:find-chain-params network))
                  (timestamp (bl.chain:chain-params-genesis-timestamp params))
                  (bits (bl.chain:chain-params-genesis-bits params))
                  (nonce (bl.chain:chain-params-genesis-nonce params)))
             (bl.ser:make-block-header
              :version 1
              :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 0)
              :merkle-root (copy-seq merkle-root)
              :timestamp timestamp :bits bits :nonce nonce)))
         (hash (bl.ser:block-header-hash header)))
    (unless (equalp hash (network-genesis-hash network))
      (internal-error "make-genesis-block: constructed ~A genesis hashes to ~A, expected ~A"
             network
             (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash))
             (bl.crypto:bytes-to-hex
              (bl.crypto:reverse-bytes (network-genesis-hash network)))))
    (bl.ser:make-bitcoin-block
     :header header
     :transactions (list coinbase))))

(defun init-chain-state (base-path &key genesis-hash network)
  "Initialize chain state at BASE-PATH.
NETWORK defaults to bl.chain:*network* if not specified."
  (let ((net (or network bl.chain:*network*)))
    (make-chain-state
     :base-path (pathname base-path)
     :genesis-hash (or genesis-hash (network-genesis-hash net))
     :best-block-hash (or genesis-hash (network-genesis-hash net))
     :best-height 0)))

(defun %record-block-position (entry located)
  "Copy LOCATED's file and offset onto ENTRY, and return ENTRY. NIL entry or a
non-flat LOCATED leaves the position alone — a legacy per-block file leaves the
fields NIL, which is exactly what NIL means here.

Any stored body, in either form, is a body received by this node, which is what
Core's ReceivedBlockTransactions marks BLOCK_OPT_WITNESS where segwit applies
(validation.cpp:3817-3819); NOTE-BLOCK-WITNESS-RECEIVED does that here."
  (when (and entry (flat-file-pos-p located))
    (setf (block-index-entry-file entry) (flat-file-pos-file located)
          (block-index-entry-data-pos entry) (flat-file-pos-pos located)))
  (when (and entry located)
    (note-block-witness-received entry))
  entry)

(defun note-block-position (chain-state hash located)
  "Record on HASH's index entry where its body landed, and return the entry.

LOCATED is STORE-BLOCK's second value: a FLAT-FILE-POS for a record inside a
blk?????.dat, a PATHNAME for a legacy per-block file. Core does the same copy in
ReceivedBlockTransactions, moving SaveBlockToDisk's FlatFilePos into nFile and
nDataPos and setting the HAVE_DATA bit.

These fields are what make Core's rev-file undo format usable at all: an undo
record is written into the file its block occupies and is addressed by nothing
but nUndoPos on this entry. A legacy per-block file leaves them NIL, which is
exactly what NIL means here — not in a flat file, so no rev file to pair with.

No entry yet is not an error: the caller that adds the entry afterwards notes
the position once it exists."
  (let ((entry (and chain-state (get-block-index-entry chain-state hash))))
    (%record-block-position entry located)
    (when located (note-block-received chain-state entry))
    entry))

;;; Block sequence ids (Core nSequenceId / nBlockSequenceId / m_blocks_unlinked).

(defconstant +seq-id-best-chain-from-disk+ 0
  "Core SEQ_ID_BEST_CHAIN_FROM_DISK (chain.h:39).")

(defconstant +seq-id-init-from-disk+ 1
  "Core SEQ_ID_INIT_FROM_DISK (chain.h:40): what every entry starts with, and
what an entry keeps until its body arrives with all its ancestors' bodies.")

(defvar *next-block-sequence-id* (1+ +seq-id-init-from-disk+)
  "Core ChainstateManager::nBlockSequenceId (validation.h:1058): the next id
NOTE-BLOCK-RECEIVED hands out. Only the ORDER matters, so one counter serves
every chain-state in the process.")

(defvar *blocks-unlinked* (make-hash-table :test 'equalp :synchronized t)
  "Core BlockManager::m_blocks_unlinked (validation.cpp:3849-3853): parent hash
-> the entries, in arrival order, whose body arrived while that parent's chain
still lacked a body. NOTE-BLOCK-RECEIVED on the parent drains them.")

(defvar *block-reverse-sequence-id* -1
  "Core nBlockReverseSequenceId (validation.cpp:3538): the next id
preciousblock hands out, counting down from -1.")

(defvar *last-precious-chainwork* 0
  "Core nLastPreciousChainwork (validation.cpp:3533-3536).")

(defun reset-block-sequence-state ()
  "Forget every unlinked body and restart the preciousblock counter -- the
part of Core's ChainstateManager reset that concerns sequence ids."
  (clrhash *blocks-unlinked*)
  (setf *block-reverse-sequence-id* -1
        *last-precious-chainwork* 0))

(defun %entry-have-chain-txs-p (chain-state entry)
  "Core CBlockIndex::HaveNumChainTxs: ENTRY and every ancestor hold a body. An
entry with an assigned sequence id, or on the active chain, answers at once;
one still at +SEQ-ID-INIT-FROM-DISK+ (a block loaded from disk off the active
chain) walks down while each entry has a recorded position."
  (loop for e = entry then (block-index-entry-prev-entry e)
        do (cond ((null e) (return t))
                 ((/= (block-index-entry-sequence-id e) +seq-id-init-from-disk+)
                  (return t))
                 ((and chain-state (entry-on-active-chain-p chain-state e))
                  (return t))
                 ((null (block-index-entry-data-pos e)) (return nil)))))

(defun note-block-received (chain-state entry)
  "Core ReceivedBlockTransactions' candidate half (validation.cpp:3829-3853):
ENTRY's body has just been stored. When its parent's chain holds every body,
ENTRY takes the next sequence id and so does every body that was waiting on
it, breadth first in arrival order; otherwise ENTRY waits in *BLOCKS-UNLINKED*
under its parent. An entry that already has an id keeps it -- Core does not
re-run this for a body it already holds (validation.cpp:4350)."
  (when (and entry
             (= (block-index-entry-sequence-id entry) +seq-id-init-from-disk+)
             (not (and chain-state (entry-on-active-chain-p chain-state entry))))
    (let ((parent (block-index-entry-prev-entry entry)))
      (if (or (null parent) (%entry-have-chain-txs-p chain-state parent))
          (let ((queue (list entry)))
            (loop while queue
                  do (let* ((e (pop queue))
                            (hash (block-index-entry-hash e)))
                       (setf (block-index-entry-sequence-id e)
                             *next-block-sequence-id*)
                       (incf *next-block-sequence-id*)
                       (let ((waiting (gethash hash *blocks-unlinked*)))
                         (when waiting
                           (remhash hash *blocks-unlinked*)
                           (setf queue (append queue waiting)))))))
          (let ((key (block-index-entry-hash parent)))
            (unless (member entry (gethash key *blocks-unlinked*))
              (setf (gethash key *blocks-unlinked*)
                    (append (gethash key *blocks-unlinked*) (list entry))))))))
  entry)

(defun entry-better-p (a b)
  "T when A beats B as a chain tip -- Core CBlockIndexWorkComparator
(node/blockstorage.cpp:174-192) turned round: more chain work, then the lower
sequence id. Two entries equal on both are not better than each other, so a
tip is never displaced by an entry it ties with."
  (let ((wa (block-index-entry-chain-work a))
        (wb (block-index-entry-chain-work b)))
    (or (> wa wb)
        (and (= wa wb)
             (< (block-index-entry-sequence-id a)
                (block-index-entry-sequence-id b))))))

(defun mark-best-chain-from-disk (chain-state)
  "Core LoadChainTip (validation.cpp:4598-4609): the active chain as loaded
takes +SEQ-ID-BEST-CHAIN-FROM-DISK+, so the tip this node shut down on stays
the tip across a restart when another chain ties it on work."
  (loop for e = (get-block-index-entry chain-state (best-block-hash chain-state))
          then (block-index-entry-prev-entry e)
        while e
        do (setf (block-index-entry-sequence-id e) +seq-id-best-chain-from-disk+)))

(defun precious-block-sequence (chain-state entry)
  "Core PreciousBlock's sequence step (validation.cpp:3530-3542): ENTRY takes
the next NEGATIVE id, so it beats every equal-work entry -- the counter restarts
at -1 whenever the tip has gained work since the last call."
  (let* ((tip (get-block-index-entry chain-state (best-block-hash chain-state)))
         (tip-work (if tip (block-index-entry-chain-work tip) 0)))
    (when (> tip-work *last-precious-chainwork*)
      (setf *block-reverse-sequence-id* -1))
    (setf *last-precious-chainwork* tip-work)
    (setf (block-index-entry-sequence-id entry) *block-reverse-sequence-id*)
    (when (> *block-reverse-sequence-id* (- (expt 2 31)))
      (decf *block-reverse-sequence-id*))
    entry))

(defun get-block-index-entry (state hash)
  "Get the block index entry for HASH."
  (gethash hash (chain-state-block-index state)))

(defun add-block-index-entry (state entry)
  "Add a block index entry to the chain state, and make it the best header
when it carries strictly more work than the current one -- Core
BlockManager::AddToBlockIndex (node/blockstorage.cpp:249-251), whose
comparison is `best_header->nChainWork < pindexNew->nChainWork', so an
equal-work entry never displaces the one seen first. An entry added already
marked :invalid is one Core's AcceptBlockHeader would have refused before
AddToBlockIndex ran, so it does not compete. While no best header has been
recorded for this index, none is recorded here either: the first
BEST-HEADER-ENTRY scans, which is how a loaded index gets its answer."
  (let ((index (chain-state-block-index state)))
    (setf (gethash (block-index-entry-hash entry) index) entry)
    (let ((best (gethash index *best-header-by-index*)))
      (when (and best
                 (not (eq (block-index-entry-status entry) :invalid))
                 (> (block-index-entry-chain-work entry)
                    (block-index-entry-chain-work best)))
        (setf (gethash index *best-header-by-index*) entry)))
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

;;; Difficulty adjustment constants

(defconstant +difficulty-adjustment-interval+ 2016
  "Number of blocks between difficulty retargets.")

(defconstant +pow-target-timespan+ 1209600
  "Target time for one retarget period in seconds (2 weeks = 14 * 24 * 60 * 60).")

(defun difficulty-adjustment-interval (network)
  "Blocks in one retarget period on NETWORK -- Core's
Consensus::Params::DifficultyAdjustmentInterval(), nPowTargetTimespan /
nPowTargetSpacing. Two weeks over ten minutes is 2016 on every chain but
regtest, whose timespan is one DAY (kernel/chainparams.cpp:576-577) and whose
period is therefore 144.

+DIFFICULTY-ADJUSTMENT-INTERVAL+ is the 2016 the retarget arithmetic applies
directly; regtest never retargets (Core fPowNoRetargeting), so the two only
part company where a caller REPORTS the period instead of retargeting on it --
getnetworkhashps's `nblocks = -1', whose window is the blocks mined since the
last difficulty change."
  (if (eq network :regtest) 144 +difficulty-adjustment-interval+))

(defconstant +pow-limit-bits+
  (bl.chain:chain-params-pow-limit-bits (bl.chain:find-chain-params :mainnet))
  "Minimum difficulty (maximum target) in compact bits format, #x1d00ffff.
Same for mainnet and the testnets; from the chain-params table.")

(defconstant +signet-pow-limit-bits+
  (bl.chain:chain-params-pow-limit-bits (bl.chain:find-chain-params :signet))
  "Core signet powLimit, 00000377ae00...00 (kernel/chainparams.cpp:490). Signet
is EASIER than mainnet's minimum, so a signet nBits derives a target ABOVE the
mainnet limit — which is why running signet against the mainnet clamp rejected
even signet's own genesis.")

(defconstant +regtest-pow-limit-bits+
  (bl.chain:chain-params-pow-limit-bits (bl.chain:find-chain-params :regtest))
  "Regtest minimum difficulty (Bitcoin Core CRegTestParams powLimit). Trivial:
the target is ~2^255, so a single hash usually satisfies it — blocks are
CPU-mined on demand.")

;;; Chain work calculations
;;; Note: +pow-limit-target+ is defined after bits-to-target below.

(defun bits-to-target (bits)
  "Decode compact 'bits' (nBits) to a 256-bit target magnitude — the
arith_uint256::SetCompact value. Uses the 23-bit mantissa; the
0x00800000 sign bit and overflow are handled by DERIVE-TARGET, not here.
For exponents <= 3 the mantissa is right-shifted (matching SetCompact's
nWord >>= 8*(3-nSize)); real difficulty values always have exponent > 3."
  (let* ((exponent (ash bits -24))
         (mantissa (logand bits #x7FFFFF)))
    (if (<= exponent 3)
        (ash mantissa (- (* 8 (- 3 exponent))))
        (ash mantissa (* 8 (- exponent 3))))))

(defvar +pow-limit-target+ (bits-to-target +pow-limit-bits+)
  "The full 256-bit PoW limit target (precomputed from +pow-limit-bits+).")

(defvar +signet-pow-limit-target+ (bits-to-target +signet-pow-limit-bits+)
  "The full 256-bit signet PoW limit target.")

(defvar +regtest-pow-limit-target+ (bits-to-target +regtest-pow-limit-bits+)
  "The full 256-bit regtest PoW limit target.")

(defvar *pow-limit-target* +pow-limit-target+
  "The active PoW limit target — the maximum target a block's nBits may decode
to. Defaults to the standard limit; init-node sets it from the chain's
powLimit (chain-params-pow-limit-bits). derive-target rejects any target
above this, so it must be network-aware.")

(defun derive-target (bits)
  "Decode nBits to a target, returning NIL if it is out of range — i.e.
negative (the 0x00800000 sign bit set on a non-zero mantissa), zero,
overflowing, or greater than the PoW limit. Mirrors Bitcoin Core's
DeriveTarget + arith_uint256::SetCompact (pow.cpp:146-159)."
  (let* ((size (ash bits -24))
         (word (logand bits #x7FFFFF))
         (negative (and (/= word 0) (/= (logand bits #x800000) 0)))
         (overflow (and (/= word 0)
                        (or (> size 34)
                            (and (> word #xff) (> size 33))
                            (and (> word #xffff) (> size 32)))))
         (target (bits-to-target bits)))
    (if (or negative (zerop target) overflow (> target *pow-limit-target*))
        nil
        target)))

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

(defun block-proof-equivalent-time (to from tip)
  "Core GetBlockProofEquivalentTime (chain.cpp:136-151): how long the chain-work
difference between the index entries TO and FROM would take to produce at TIP's
difficulty, in seconds. Signed -- negative when TO has less work than FROM.
Core saturates at the int64 range; an integer here needs no clamp.

A header's nTime is attacker-influenced within the median-time-past and
two-hour windows, so an age test on timestamps alone can be talked out of; the
work difference cannot be. Net_processing asks it whether an old side-chain
block may be served, ConnectBlock whether the assumevalid skip is buried deep
enough."
  (let ((to-work (block-index-entry-chain-work to))
        (from-work (block-index-entry-chain-work from)))
    (* (if (> to-work from-work) 1 -1)
       (floor (* (abs (- to-work from-work))
                 (bl.chain:chain-pow-target-spacing bl.chain:*network*))
              (max 1 (calculate-chain-work
                      (bl.ser:block-header-bits (block-index-entry-header tip))
                      0))))))

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
         ;; Cap at the PoW limit of the network we are on. This clamped to the
         ;; MAINNET constant regardless of network, so a signet retarget was
         ;; capped at a limit harder than signet's own — Core clamps to
         ;; params.powLimit (pow.cpp CalculateNextWorkRequired).
         (new-target (min new-target *pow-limit-target*)))
    (target-to-bits new-target)))

;;; State persistence

(defun state-file-path (state)
  "Path to this chainstate's state file. The primary chainstate's
storage-suffix is empty, yielding exactly \"chainstate.dat\" (unchanged
on-disk name); a snapshot chainstate gets \"chainstate_snapshot.dat\"."
  (merge-pathnames (format nil "chainstate~A.dat" (chain-state-storage-suffix state))
                   (chain-state-base-path state)))

(defun chainstate-leveldb-path (state)
  "Directory of this chainstate's coins LevelDB: \"chainstate/\" for the
primary (empty suffix), \"chainstate_snapshot/\" for a snapshot chainstate.
Mirrors Core Chainstate::StoragePath (validation.cpp:1872-1879), which
appends SNAPSHOT_CHAINSTATE_SUFFIX to the datadir/chainstate base. The
block tree database (blocks/index), block store, and undo storage are shared
across chainstates and take no suffix."
  (merge-pathnames (format nil "chainstate~A/" (chain-state-storage-suffix state))
                   (chain-state-base-path state)))

;;; Coins-view lifecycle over a chainstate's own LevelDB. Every chainstate
;;; on a live node owns a coins-view-cache over the LevelDB at its
;;; chainstate-leveldb-path; these pair up at startup/activation and
;;; shutdown/activation-abort.

(defun open-chainstate-coins-view (state)
  "Open STATE's coins LevelDB (at its chainstate-leveldb-path) and install a
coins-view-cache over it as the chainstate's coins view. Returns the view."
  (setf (chain-state-coins-view state)
        (make-coins-view-cache
         (open-coins-view-db (namestring (chainstate-leveldb-path state))))))

(defun close-chainstate-coins-view (state)
  "Close STATE's coins LevelDB (releasing its lock) if the chainstate owns a
DB-backed coins view; plain in-memory views are left alone. Clears the
coins-view slot so a stale handle can never be reused. Never signals."
  (let ((view (chain-state-coins-view state)))
    (when (typep view 'coins-view-cache)
      (let ((base (coins-view-cache-base view)))
        (when base
          (ignore-errors (close-coins-view-db base))))
      (setf (chain-state-coins-view state) nil))))

;;; Snapshot chainstate on-disk marker (Core node/utxo_snapshot.{h,cpp}).
;;; The base_blockhash file inside chainstate_snapshot/ is the ONLY
;;; persistent \"a snapshot chainstate exists\" marker: startup detects the
;;; dir + marker and re-creates the dual-chainstate arrangement. Format is
;;; Core's exactly — the raw 32-byte base block hash (wire order), nothing
;;; else. LevelDB ignores foreign files in its directory, so co-locating the
;;; marker with the coins DB (as Core does) is safe.

(alexandria:define-constant +snapshot-blockhash-filename+ "base_blockhash"
  :test #'equalp :documentation "Core SNAPSHOT_BLOCKHASH_FILENAME (node/utxo_snapshot.h:113).")

(defun snapshot-base-blockhash-path (chainstate-dir)
  "Path of the base_blockhash marker inside CHAINSTATE-DIR."
  (merge-pathnames +snapshot-blockhash-filename+ chainstate-dir))

(defun write-snapshot-base-blockhash (state)
  "Write STATE's from-snapshot-blockhash marker into its coins LevelDB dir
(Core WriteSnapshotBaseBlockhash). The dir must already exist (the coins DB
open creates it). Returns T on success."
  (let ((hash (chain-state-from-snapshot-blockhash state)))
    (assert hash () "write-snapshot-base-blockhash: not a snapshot chainstate")
    (with-open-file (out (snapshot-base-blockhash-path (chainstate-leveldb-path state))
                         :direction :output :element-type '(unsigned-byte 8)
                         :if-exists :supersede)
      (write-sequence hash out))
    t))

(defun read-snapshot-base-blockhash (chainstate-dir)
  "Read the 32-byte base block hash marker from CHAINSTATE-DIR (Core
ReadSnapshotBaseBlockhash), or NIL when the marker is missing or short.
Like Core, trailing data only warrants a warning (via the return-anyway)."
  (let ((path (snapshot-base-blockhash-path chainstate-dir)))
    (when (probe-file path)
      (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
        (let ((hash (make-array 32 :element-type '(unsigned-byte 8))))
          (when (= 32 (read-sequence hash in))
            hash))))))

(defun find-assumeutxo-chainstate-dir (data-dir)
  "The snapshot chainstate LevelDB dir under DATA-DIR, if one exists (Core
FindAssumeutxoChainstateDir): \"chainstate_snapshot/\"."
  (let ((dir (merge-pathnames "chainstate_snapshot/" data-dir)))
    (when (probe-file dir)
      dir)))

(defun delete-snapshot-chainstate-files (data-dir)
  "Remove a snapshot chainstate's on-disk footprint under DATA-DIR: the
chainstate_snapshot/ LevelDB dir (marker included) and the
chainstate_snapshot.dat state file. Core's DeleteCoinsDBFromDisk +
DeleteChainstate equivalent, used for activation-failure cleanup and
-reindex-chainstate. Returns T if anything was removed."
  (let ((removed nil)
        (dir (merge-pathnames "chainstate_snapshot/" data-dir))
        (dat (merge-pathnames "chainstate_snapshot.dat" data-dir)))
    (when (probe-file dir)
      (uiop:delete-directory-tree dir :validate t)
      (setf removed t))
    (when (probe-file dat)
      (delete-file dat)
      (setf removed t))
    removed))

(defun rename-snapshot-chainstate-dir-invalid (data-dir)
  "Move the snapshot chainstate's coins LevelDB dir aside for forensics after
its background validation failed (Core Chainstate::InvalidateCoinsDBOnDisk,
validation.cpp:6220-6250): chainstate_snapshot/ -> chainstate_snapshot_INVALID/.
The dir is MOVED, not deleted, so a hardware/software fault that produced a
bad snapshot can be investigated later. Any stale _INVALID leftover from a
prior failed activation is removed first so the rename can't collide. Returns
the new path, or NIL when there was no snapshot dir to rename."
  (let ((src (merge-pathnames "chainstate_snapshot/" data-dir))
        (dst (merge-pathnames "chainstate_snapshot_INVALID/" data-dir)))
    (when (probe-file src)
      (when (probe-file dst)
        (uiop:delete-directory-tree dst :validate t))
      (sb-posix:rename (namestring src) (namestring dst))
      dst)))

(defun promote-snapshot-chainstate-files (data-dir)
  "Startup-only LevelDB-directory swap that makes a fully-validated snapshot
chainstate the sole chainstate (Core ChainstateManager::ValidatedSnapshotCleanup,
validation.cpp:6299-6364): the background (validated-from-genesis) chainstate's
files are moved aside to *_todelete and deleted, then the snapshot chainstate's
files are moved into the default (unsuffixed) names. Handles both the coins
LevelDB dir and our per-chainstate state file (chainstate.dat, which Core has
no analogue of). Every chainstate's coins DB must already be closed. Returns T."
  (flet ((swap-dir (old new)
           (when (probe-file new) (uiop:delete-directory-tree new :validate t))
           (when (probe-file old) (sb-posix:rename (namestring old) (namestring new))))
         (swap-file (old new)
           (when (probe-file new) (delete-file new))
           (when (probe-file old) (rename-file old new))))
    (let ((cs         (merge-pathnames "chainstate/" data-dir))
          (cs-del     (merge-pathnames "chainstate_todelete/" data-dir))
          (snap       (merge-pathnames "chainstate_snapshot/" data-dir))
          (cs-dat     (merge-pathnames "chainstate.dat" data-dir))
          (cs-dat-del (merge-pathnames "chainstate_todelete.dat" data-dir))
          (snap-dat   (merge-pathnames "chainstate_snapshot.dat" data-dir)))
      ;; Background chainstate aside, snapshot chainstate into place.
      (swap-dir cs cs-del)
      (swap-dir snap cs)
      (swap-file cs-dat cs-dat-del)
      (swap-file snap-dat cs-dat)
      ;; Delete the now-unneeded background chainstate.
      (when (probe-file cs-del) (uiop:delete-directory-tree cs-del :validate t))
      (when (probe-file cs-dat-del) (delete-file cs-dat-del))
      t)))

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
  :corrupt       — the file EXISTS but no format validated (failed CRC, or a
                   size no version recognizes). Distinct from NIL on purpose:
                   the UTXO set on disk belongs to a tip we can no longer
                   identify, so the caller must refuse to run. Treating this
                   as NIL meant replaying from genesis over a populated UTXO
                   set, which on mainnet trips the BIP30 duplicate-txid check
                   and leaves the node with no best-valid-tip at all.
  NIL            — no chainstate file exists (a legitimate first run).

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
    ;; Legacy fallback: pre-CRC format (36 or 40 bytes total). This format
    ;; carries no integrity check at all, so it can only be trusted by size;
    ;; anything else is corruption, not an older version.
    (with-open-file (stream path :direction :input :element-type '(unsigned-byte 8))
      (let ((file-size (file-length stream)))
        (unless (or (= file-size 36) (= file-size 40))
          (return-from load-state :corrupt))
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
        t))))

;;; Block locator for syncing

(defun build-block-locator (state &optional from-entry)
  "Build a block locator for the getheaders/getblocks messages.
Returns a list of block hashes starting from FROM-ENTRY (default: the tip)
and going back with exponentially increasing gaps. The wallet's best-block
record (Core GetLocator over the wallet's last processed block) passes an
explicit FROM-ENTRY."
  (let ((locator '())
        (entry (or from-entry
                   (get-block-index-entry state (chain-state-best-block-hash state))))
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

(defun entry-on-active-chain-p (state entry)
  "T if ENTRY lies on the active chain — i.e. the active-chain block at ENTRY's
height is ENTRY itself. Mirrors Bitcoin Core's CChain::Contains."
  (let ((at-height (get-block-at-height state (block-index-entry-height entry))))
    (and at-height
         (equalp (block-index-entry-hash at-height)
                 (block-index-entry-hash entry)))))

(defun find-fork-in-active-chain (state locator-hashes)
  "Return the block-index-entry for the highest active-chain block the peer
claims to have — the highest active-chain entry whose hash is in LOCATOR-HASHES
— or the genesis entry if none match. Mirrors Bitcoin Core's
Chainstate::FindForkInGlobalIndex. Implemented as a single backward walk from
the tip against a locator hash-set: O(tip - fork), independent of the locator
length, rather than an O(height) active-chain probe per locator hash."
  (let ((genesis (get-block-index-entry state (chain-state-genesis-hash state))))
    (when (null locator-hashes)
      (return-from find-fork-in-active-chain genesis))
    (let ((want (make-hash-table :test 'equalp)))
      (dolist (hash locator-hashes)
        (setf (gethash hash want) t))
      (loop with entry = (get-block-index-entry state (chain-state-best-block-hash state))
            while entry
            when (gethash (block-index-entry-hash entry) want)
              do (return-from find-fork-in-active-chain entry)
            do (setf entry (block-index-entry-prev-entry entry)))
      genesis)))

(defun active-chain-entries-from (state from-height limit)
  "Return up to LIMIT block-index-entries on the active chain at consecutive
heights starting at FROM-HEIGHT, in ascending-height order (empty when
FROM-HEIGHT is above the tip). Answers getheaders/getblocks by replaying
Bitcoin Core's forward ActiveChain().Next() walk, implemented as a single
backward pass from the tip."
  (let* ((tip (get-block-index-entry state (chain-state-best-block-hash state)))
         (tip-height (and tip (block-index-entry-height tip))))
    (when (or (null tip) (> from-height tip-height))
      (return-from active-chain-entries-from nil))
    ;; No forward (height->entry) index exists, so reach the window by walking
    ;; back from the tip: first skip down to END-HEIGHT, then collect the
    ;; [FROM-HEIGHT, END-HEIGHT] entries while continuing to descend — pushing
    ;; each one yields the list in ascending-height order.
    (let ((end-height (min tip-height (+ from-height (1- limit))))
          (entry tip)
          (entries '()))
      (loop while (and entry (> (block-index-entry-height entry) end-height))
            do (setf entry (block-index-entry-prev-entry entry)))
      (loop while (and entry (>= (block-index-entry-height entry) from-height))
            do (push entry entries)
               (setf entry (block-index-entry-prev-entry entry)))
      entries)))
