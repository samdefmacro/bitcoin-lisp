(in-package #:bitcoin-lisp.storage)

;;;; The block index entry and the chain state (Core CBlockIndex, chain.h, and
;;;; Chainstate, validation.h)
;;;
;;; First in the storage layer, ahead of every file that reads them: SBCL
;;; inlines a structure accessor only into code compiled AFTER the DEFSTRUCT,
;;; and blocks.lisp -- which loads before chain.lisp, where these two lived
;;; until 2026-09-30 -- reads BLOCK-INDEX-ENTRY-HEIGHT and CHAIN-STATE-BEST-
;;; HEIGHT on its prune paths through full calls. The chain operations on them
;;; stay in chain.lisp. scripts/check-struct-order.sh fails the cold lane on
;;; any structure compiled after a user of its accessors.

(defstruct block-index-entry
  "Metadata for an indexed block."
  (hash nil :type (or null (simple-array (unsigned-byte 8) (32))))
  (height 0 :type (unsigned-byte 32))
  (header nil)
  (prev-entry nil)
  (chain-work 0 :type integer)
  (status :unknown :type keyword)  ; :unknown, :header-valid, :valid, :invalid
  ;; Number of transactions in this block (Bitcoin Core nTx), recorded when
  ;; the body is stored (ReceivedBlockTransactions) and kept after pruning. 0 =
  ;; never received -- or an entry the pre-tx-count header index wrote with a
  ;; body (start-up counts those; getchaintxstats backfills them lazily).
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
