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
  (tx-count 0 :type (unsigned-byte 32)))

(defstruct chain-state
  "Current blockchain state. One chain-state per chainstate role (Bitcoin
Core's Chainstate, validation.h): today exactly one exists — the primary,
fully-validated chainstate — but the slots below already carry the
assumeutxo identity a snapshot chainstate (a future ActivateSnapshot)
needs, so the node can hold several in a list and select between them."
  (block-index (make-hash-table :test 'equalp) :type hash-table)
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
range's lower bound (Core Chainstate::GetPruneRange, validation.cpp:6366-6391,
whose prune_start is this + 1). An unvalidated snapshot chainstate must never
prune a block at or below its snapshot base: the historical chainstate still
has to download and validate those blocks, and deleting one wedges the
background sync permanently. Every other chainstate prunes from genesis (0).
If the base header is somehow missing from the shared index, refuse to prune
anything (most conservative)."
  (let ((base (chain-state-from-snapshot-blockhash state)))
    (if (and base (not (eq (chain-state-assumeutxo-status state) :validated)))
        (let ((entry (get-block-index-entry state base)))
          (if entry
              (block-index-entry-height entry)
              most-positive-fixnum))
        0)))

(defun chain-state-prune-walk-start (state)
  "The height a prune walk over STATE resumes ABOVE: the max of the monotone
pruned-height cursor and the per-chainstate prune floor. Shared by the
automatic and manual prune paths (Core: FindFilesToPrune and
FindFilesToPruneManual both consume the same GetPruneRange)."
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

(defun best-header-entry (chain-state)
  "The most-work non-invalid header entry in the block index (Core
m_best_header; recomputed by scan like Core RecalculateBestHeader,
validation.cpp:6379-6388). O(index size) — fine for its callers
(snapshot-activation preconditions, RPC), not for per-block paths."
  (let ((best nil))
    (maphash (lambda (hash entry)
               (declare (ignore hash))
               (when (and (not (eq (block-index-entry-status entry) :invalid))
                          (or (null best)
                              (> (block-index-entry-chain-work entry)
                                 (block-index-entry-chain-work best))))
                 (setf best entry)))
             (chain-state-block-index chain-state))
    best))

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

;;; Regtest genesis block hash (little-endian). Big-endian display:
;;; 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
(defvar *regtest-genesis-hash*
  (bitcoin-lisp.crypto:hex-to-bytes
   "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f"))

(defun network-genesis-hash (network)
  "Return the genesis block hash for NETWORK."
  (ecase network
    (:testnet3 \*testnet3-genesis-hash*)
    (:testnet4 *testnet4-genesis-hash*)
    (:signet *signet-genesis-hash*)
    (:regtest *regtest-genesis-hash*)
    (:mainnet *mainnet-genesis-hash*)))

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

(defun %script-push (bytes)
  "Minimal CScript data push of BYTES: direct push below OP_PUSHDATA1 (76),
OP_PUSHDATA1 up to 255 (the testnet4 timestamp message is 76 bytes)."
  (let ((n (length bytes)))
    (cond ((< n 76)
           (concatenate '(simple-array (unsigned-byte 8) (*)) (vector n) bytes))
          ((<= n 255)
           (concatenate '(simple-array (unsigned-byte 8) (*)) (vector #x4c n) bytes))
          (t (error "%script-push: ~D bytes unsupported" n)))))

(defun %ascii-bytes (string)
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

(defparameter *genesis-output-pubkey*
  (bitcoin-lisp.crypto:hex-to-bytes
   "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
  "Satoshi's genesis coinbase pubkey (kernel/chainparams.cpp:71), used by
mainnet, testnet3, signet and regtest. Verified by the genesis-hash check in
MAKE-GENESIS-BLOCK: a transcription error cannot produce the known hash.")

(defparameter *genesis-timestamp-message*
  "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
  "pszTimestamp for mainnet/testnet3/signet/regtest (kernel/chainparams.cpp:70).")

(defparameter *testnet4-timestamp-message*
  "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
  "testnet4's own pszTimestamp (kernel/chainparams.cpp:367).")

(defun %genesis-coinbase (network)
  "The genesis coinbase transaction for NETWORK, per Core CreateGenesisBlock
(kernel/chainparams.cpp:36-49): scriptSig pushes 486604799, CScriptNum(4) and
the timestamp message; one 50 BTC output to <pubkey> OP_CHECKSIG (testnet4:
33 zero bytes as the \"pubkey\", chainparams.cpp:368)."
  (let* ((testnet4-p (eq network :testnet4))
         (message (%ascii-bytes (if testnet4-p
                                    *testnet4-timestamp-message*
                                    *genesis-timestamp-message*)))
         ;; CScript() << 486604799: minimal CScriptNum bytes of 0x1d00ffff,
         ;; little-endian -> ff ff 00 1d, pushed as data.
         (script-sig (concatenate '(simple-array (unsigned-byte 8) (*))
                                  (%script-push (vector #xff #xff #x00 #x1d))
                                  (%script-push (vector #x04))
                                  (%script-push message)))
         (pubkey (if testnet4-p
                     (make-array 33 :element-type '(unsigned-byte 8)
                                    :initial-element 0)
                     *genesis-output-pubkey*))
         (script-pubkey (concatenate '(simple-array (unsigned-byte 8) (*))
                                     (%script-push pubkey)
                                     (vector #xac)))) ; OP_CHECKSIG
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                      :previous-output (bitcoin-lisp.serialization:make-outpoint
                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                             :initial-element 0)
                                        :index #xffffffff)
                      :script-sig script-sig
                      :sequence #xffffffff))
     :outputs (vector (bitcoin-lisp.serialization:make-tx-out
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
         (merkle-root (bitcoin-lisp.serialization:transaction-hash coinbase))
         (header
           (multiple-value-bind (timestamp bits nonce)
               (ecase network
                 (:mainnet  (values 1231006505 #x1d00ffff 2083236893))
                 (:testnet3 (values 1296688602 #x1d00ffff 414098458))
                 (:testnet4 (values 1714777860 #x1d00ffff 393743547))
                 (:signet   (values 1598918400 #x1e0377ae 52613770))
                 (:regtest  (values 1296688602 #x207fffff 2)))
             (bitcoin-lisp.serialization:make-block-header
              :version 1
              :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 0)
              :merkle-root (copy-seq merkle-root)
              :timestamp timestamp :bits bits :nonce nonce)))
         (hash (bitcoin-lisp.serialization:block-header-hash header)))
    (unless (equalp hash (network-genesis-hash network))
      (error "make-genesis-block: constructed ~A genesis hashes to ~A, expected ~A"
             network
             (bitcoin-lisp.crypto:bytes-to-hex (bitcoin-lisp.crypto:reverse-bytes hash))
             (bitcoin-lisp.crypto:bytes-to-hex
              (bitcoin-lisp.crypto:reverse-bytes (network-genesis-hash network)))))
    (bitcoin-lisp.serialization:make-bitcoin-block
     :header header
     :transactions (list coinbase))))

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

;;; Difficulty adjustment constants

(defconstant +difficulty-adjustment-interval+ 2016
  "Number of blocks between difficulty retargets.")

(defconstant +pow-target-timespan+ 1209600
  "Target time for one retarget period in seconds (2 weeks = 14 * 24 * 60 * 60).")

(defconstant +pow-limit-bits+ #x1d00ffff
  "Minimum difficulty (maximum target) in compact bits format.
Same for mainnet and testnet.")

(defconstant +signet-pow-limit-bits+ #x1e0377ae
  "Core signet powLimit, 00000377ae00...00 (kernel/chainparams.cpp:490). Signet
is EASIER than mainnet's minimum, so a signet nBits derives a target ABOVE the
mainnet limit — which is why running signet against the mainnet clamp rejected
even signet's own genesis.")

(defconstant +regtest-pow-limit-bits+ #x207fffff
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
to. Defaults to the standard limit; init-node raises it to
+regtest-pow-limit-target+ on regtest. derive-target rejects any target above
this, so it must be network-aware.")

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
header index (headerindex.dat), block store, and undo storage are shared
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

(defparameter +snapshot-blockhash-filename+ "base_blockhash"
  "Core SNAPSHOT_BLOCKHASH_FILENAME (node/utxo_snapshot.h:113).")

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

;;; Header Index Persistence

(defvar *header-index-magic* (map '(vector (unsigned-byte 8)) #'char-code "HIDX")
  "Magic bytes identifying a header index file.")

(defconstant +header-index-format-version+ 2
  "Current header index persistence format version.
v2 appends a per-entry tx-count (4 bytes); v1 files still load (tx-count 0,
backfilled lazily from the block store).")

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
  "byte-buf variant of write-single-header-entry. Writes 185 bytes (v2):
hash(32) + height(4) + header(80) + chainwork(32) + status(1) + prev-hash(32)
+ tx-count(4)."
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
        (loop repeat 32 do (bitcoin-lisp.serialization:bb-write-u8 bb 0))))
  (bitcoin-lisp.serialization:bb-write-u32-le bb (block-index-entry-tx-count entry)))

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

Returns (values T NIL) on success, (values NIL NIL) when there is simply no
file — a legitimate first run — and (values NIL REASON) when a file IS present
but cannot be trusted, REASON being a human-readable description.

The caller MUST refuse to start on that third case. Continuing with an empty
index while chainstate.dat still names a tip leaves the node claiming a height
it holds no headers for, which on a pruned node cannot be rebuilt from disk at
all. Core treats a CBlockTreeDB it cannot load the same way: a fatal \"Error
loading block database\" rather than an empty index (init.cpp)."
  (let ((path (header-index-file-path state)))
    (unless (probe-file path)
      (return-from load-header-index (values nil nil)))
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
          (if (and (>= (length file-bytes) 4)
                   (equalp (subseq file-bytes 0 4) *header-index-magic*))
              (load-header-index-v1 state file-bytes)
              (load-header-index-legacy state file-bytes)))
      ;; A truncated legacy file (no checksum to catch it) runs the entry
      ;; reader off the end. That is corruption, not absence.
      (error (e)
        (values nil (format nil "unreadable (~A)" e))))))

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
    (let ((version (bitcoin-lisp.serialization:read-uint32-le stream)))
      (unless (member version '(1 2))
        (return-from load-header-index-v1
          (values nil (format nil "unsupported format version ~D (this build writes ~D)"
                              version +header-index-format-version+))))
      ;; Read entries
      (let ((count (bitcoin-lisp.serialization:read-uint32-le stream))
            (entries-by-hash (make-hash-table :test 'equalp))
            (prev-hash-map (make-hash-table :test 'equalp))
            (with-tx-count (>= version 2)))
        (dotimes (i count)
          (read-single-header-entry stream entries-by-hash prev-hash-map
                                    with-tx-count))
        (link-header-entries entries-by-hash prev-hash-map)
        (setf (chain-state-block-index state) entries-by-hash))))
  t)

(defun read-single-header-entry (stream entries-by-hash prev-hash-map
                                 &optional with-tx-count)
  "Read a single header entry from STREAM into ENTRIES-BY-HASH. WITH-TX-COUNT
reads the trailing v2 tx-count field (v1/legacy entries default it to 0)."
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
        (let ((tx-count (if with-tx-count
                            (bitcoin-lisp.serialization:read-uint32-le stream)
                            0))
              (header (handler-case
                          (flexi-streams:with-input-from-sequence (hs header-bytes)
                            (bitcoin-lisp.serialization::read-block-header hs))
                        (error () nil))))
          (let ((entry (make-block-index-entry
                        :hash hash
                        :height height
                        :header header
                        :prev-entry nil
                        :chain-work chainwork
                        :status status
                        :tx-count tx-count)))
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
