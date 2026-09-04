(in-package #:bitcoin-lisp.mining)

;;; Block template assembler
;;;
;;; Assembles a candidate block from the mempool, mirroring Bitcoin Core's
;;; cluster-mempool BlockAssembler (node/miner.cpp, addChunks): walk the
;;; txgraph's chunks across all clusters in descending chunk-feerate order,
;;; including each chunk whole when it fits the weight/sigops budgets and
;;; all its transactions are final, and skipping it otherwise - a skip
;;; suppresses the rest of that chunk's cluster, since later chunks depend
;;; on it. This is selection/policy only - it never bypasses validation;
;;; submitblock (and network blocks) go through the same connect-block
;;; consensus path.

(defconstant +block-reserved-weight+ 8000
  "Weight reserved for the block header, tx-count varint, and coinbase before
filling with mempool txs (Bitcoin Core DEFAULT_BLOCK_RESERVED_WEIGHT).")

(defconstant +minimum-block-reserved-weight+ 2000
  "Bitcoin Core MINIMUM_BLOCK_RESERVED_WEIGHT (policy.h:33): reserving less
than this cannot fit a header plus a realistic coinbase, so Core refuses to
start rather than hand out templates that cannot be completed.")

(defparameter *block-reserved-weight* +block-reserved-weight+
  "Effective -blockreservedweight. Space held back for the header and the
coinbase the mining client will add (Core DEFAULT_BLOCK_RESERVED_WEIGHT).")

(defparameter *block-max-weight* bl.val:+max-block-weight+
  "Effective -blockmaxweight: the weight this node fills templates up to. Core
defaults it to MAX_BLOCK_WEIGHT (policy.h:24) and refuses anything above it.
SELECTION ONLY -- it never relaxes the consensus limit, which
+max-block-weight+ still enforces on every block we validate.")

(defconstant +coinbase-reserved-sigops+ 400
  "Sigop cost reserved for the coinbase (Bitcoin Core
coinbase_output_max_additional_sigops).")

(defconstant +max-consecutive-failures+ 1000
  "Give-up heuristic: after this many consecutive skipped chunks with the
block nearly full, stop selecting (Bitcoin Core MAX_CONSECUTIVE_FAILURES,
node/miner.cpp:286).")

(defconstant +block-full-enough-weight-delta+ 4000
  "The block counts as nearly full for the give-up heuristic when within
this much weight of the limit (Bitcoin Core BLOCK_FULL_ENOUGH_WEIGHT_DELTA,
node/miner.cpp:287).")

(defvar *block-min-tx-fee-rate* 1
  "Chunks whose feerate is strictly below this (satoshis per kvB) are not
mined; selection stops at the first such chunk, as every later chunk pays
less (Bitcoin Core blockMinFeeRate / -blockmintxfee, default
DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB, node/miner.cpp:299-303).")

(defconstant +versionbits-top-bits+ #x20000000
  "Block version with the BIP9 top bits set and no deployment signaling. The
floor COMPUTE-BLOCK-VERSION starts from, and the version of a template built
with no chain behind it.")

(defvar *block-version-override* nil
  "Core -blockversion: the nVersion a template carries instead of the computed
one. Core applies it on MineBlocksOnDemand() chains only -- that is
fPowNoRetargeting, so regtest and nothing else (kernel/chainparams.cpp:580) --
which is what keeps a forking-scenario test from being expressible on a live
chain (node/miner.cpp:141-145).")

(defvar *last-block-template* nil
  "The most recently assembled block-template (Bitcoin Core's
m_last_block_weight/num). getmininginfo reports its weight/tx-count without
re-assembling.")

(defun %zeros32 ()
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))

(defstruct block-template
  "A candidate block assembled from the mempool. TRANSACTIONS is the selected
non-coinbase mempool-entries in block order (parents before children). The
weight/sigops totals already include the reserved coinbase allowance."
  (height 0)
  (prev-hash nil)
  (bits 0)
  (version +versionbits-top-bits+)
  (curtime 0)
  (mintime 0)
  (transactions '())
  (total-fees 0)
  (total-weight *block-reserved-weight*)
  (total-sigops +coinbase-reserved-sigops+)
  (coinbase-value 0)
  (witness-commitment nil)
  (default-witness-commitment-script nil))

(defun next-block-mintime (tip height mtp)
  "Core GetMinimumTime (node/miner.cpp:36-47) for the block at HEIGHT on TIP:
MTP+1, raised at retarget heights to TIP's actual time minus MAX_TIMEWARP (the
BIP94 floor). Shared by the template assembler and getmininginfo's \"next\"
block so the two cannot disagree on the next block's bits.

Core takes the period as a parameter and applies the floor on EVERY network,
whether or not BIP94 is consensus there -- \"Account for BIP94 timewarp rule on
all networks. This makes future activation safer\" (miner.cpp:41-45) -- so the
period must be the chain's, DifficultyAdjustmentInterval(): 144 on regtest,
2016 elsewhere. With the flat 2016 the floor fired at heights regtest never
retargets at, and the template offered a mintime Core would not."
  (let ((mtp-floor (1+ mtp)))
    (if (and tip
             (zerop (mod height (bl.store:difficulty-adjustment-interval
                                 bl:*network*))))
        (max mtp-floor
             (- (bl.ser:block-header-timestamp
                 (bl.store:block-index-entry-header tip))
                bl.val:+max-timewarp+))
        mtp-floor)))

(defun next-block-version (chain-state tip)
  "The nVersion of the block extending TIP (Core CreateNewBlock,
node/miner.cpp:140-145): the versionbits cache's ComputeBlockVersion, then
-blockversion where Core allows it to win.

Before this, every template carried the bare +versionbits-top-bits+ constant,
so this node could not signal a BIP9 deployment at all -- not a pending soft
fork, and not regtest's permanently-STARTED testdummy, which Core signals on
bit 28 in every regtest template it hands out."
  ;; -regtest only, as Core gates it on MineBlocksOnDemand().
  (or (and (eq bl:*network* :regtest) *block-version-override*)
      (bl.val:compute-block-version chain-state tip)))

(defun next-block-required-bits (chain-state prev-entry block-time)
  "The compact difficulty bits the block after PREV-ENTRY must carry, mirroring
Bitcoin Core's GetNextWorkRequired. Reuses the consensus get-expected-bits and
falls back to the testnet min-difficulty / walk-back rule when it is
non-definitive (testnet non-boundary)."
  (let* ((height (1+ (bl.store:block-index-entry-height prev-entry)))
         (expected (bl.val:get-expected-bits height prev-entry)))
    (or expected
        (let ((prev-time (bl.ser:block-header-timestamp
                          (bl.store:block-index-entry-header prev-entry))))
          (if (bl.val:testnet-min-difficulty-allowed-p block-time prev-time)
              bl.store:+pow-limit-bits+
              (bl.val:testnet-walk-back-bits prev-entry))))))

(defun build-witness-commitment-script (commitment)
  "The 38-byte coinbase witness-commitment scriptPubKey for COMMITMENT (a
32-byte hash): OP_RETURN push36 0xaa21a9ed <commitment>."
  (let ((s (make-array 38 :element-type '(unsigned-byte 8))))
    (setf (aref s 0) #x6a (aref s 1) #x24
          (aref s 2) #xaa (aref s 3) #x21 (aref s 4) #xa9 (aref s 5) #xed)
    (replace s commitment :start1 6)
    s))

(defun %default-witness-commitment (selected)
  "(values commitment-hash scriptPubKey) for the witness commitment over a block
whose coinbase wtxid is zero and whose other txs are SELECTED (mempool-entries),
with the all-zero reserved value. Mirrors GenerateCoinbaseCommitment."
  (let* ((wtxids (cons (%zeros32)
                       (mapcar (lambda (e)
                                 (bl.ser:transaction-wtxid
                                  (bl.mp:mempool-entry-transaction e)))
                               selected)))
         (witness-root (bl.val:compute-merkle-root wtxids))
         ;; commitment = hash256(witness-root || 32 zero reserved bytes)
         (combined (make-array 64 :element-type '(unsigned-byte 8) :initial-element 0)))
    (replace combined witness-root :start1 0)
    (let ((commitment (bl.crypto:hash256 combined)))
      (values commitment (build-witness-commitment-script commitment)))))

(defmacro %with-mempool-lock (&body body)
  "Hold the running node's lock while walking the chunk index (Core
BlockAssembler::CreateNewBlock takes the mempool lock around
StartBlockBuilding/addChunks, miner.cpp:151-156): an active block builder
forbids concurrent txgraph mutation, so the walk must exclude the network
and sync threads' mempool writes. Outside a running node (unit tests,
direct calls) there is nothing to lock. Mirrors networking's WITH-NODE-LOCK
(protocol.lisp:7), duplicated because mining loads before networking."
  `(let ((node bl:*node*))
     (if node
         (bt:with-recursive-lock-held ((bl:node-lock node))
           ,@body)
         (progn ,@body))))

(defun %select-chunks (mempool height lock-time-cutoff)
  "Fill a block from MEMPOOL by walking its txgraph's chunks in mining order
(Core BlockAssembler::addChunks, node/miner.cpp:283-334). Each chunk is
included whole when it fits the remaining weight and sigops budgets and all
its transactions are final at HEIGHT / LOCK-TIME-CUTOFF (Core
TestChunkBlockLimits + TestChunkTransactions, node/miner.cpp:244-263), and
skipped otherwise - the block builder then suppresses the rest of that
chunk's cluster, whose later chunks depend on it. Selection stops at the
first chunk whose feerate is strictly below *BLOCK-MIN-TX-FEE-RATE* (all
later chunks pay less), or after +MAX-CONSECUTIVE-FAILURES+ skips once the
block is nearly full. Returns (values entries fees weight sigops), ENTRIES
in block (topological) order, WEIGHT/SIGOPS including the coinbase reserve."
  (%with-mempool-lock
    (let ((builder (bl.mp:make-block-builder
                    (bl.mp:mempool-graph mempool)))
          (min-feerate (bl.mp:make-feefrac *block-min-tx-fee-rate* 1000))
          (selected '())
          (weight *block-reserved-weight*)
          (sigops +coinbase-reserved-sigops+)
          (fees 0)
          (consecutive-failures 0))
      (unwind-protect
           (loop
           (multiple-value-bind (handles feerate)
               (bl.mp:block-builder-current-chunk builder)
             (when (null handles) (return))
             ;; blockMinFeeRate early-out (miner.cpp:299-303): everything
             ;; else the builder would offer has a lower feerate.
             (when (bl.mp:feefrac<< feerate min-feerate)
               (return))
             (let ((entries (mapcar (lambda (h)
                                      (bl.mp:mempool-get
                                       mempool (bl.mp:tx-handle-data h)))
                                    handles))
                   (chunk-weight 0)
                   (chunk-sigops 0)
                   (chunk-fees 0))
               (dolist (e entries)
                 (incf chunk-weight (bl.ser:transaction-weight
                                     (bl.mp:mempool-entry-transaction e)))
                 (incf chunk-sigops (bl.mp:mempool-entry-sigops e))
                 (incf chunk-fees (bl.mp:mempool-entry-fee e)))
               (cond
                 ;; Core rejects on >= for both budgets (miner.cpp:244-253);
                 ;; its weight test uses the graph's sigops-adjusted weight
                 ;; where ours uses the exact transaction weight (see
                 ;; assemble-block-template).
                 ((and (< (+ weight chunk-weight)
                          *block-max-weight*)
                       (< (+ sigops chunk-sigops)
                          bl.val:+max-block-sigops-cost+)
                       (every (lambda (e)
                                (bl.val:check-transaction-final
                                 (bl.mp:mempool-entry-transaction e)
                                 height lock-time-cutoff))
                              entries))
                  (dolist (e entries) (push e selected))
                  (incf weight chunk-weight)
                  (incf sigops chunk-sigops)
                  (incf fees chunk-fees)
                  (setf consecutive-failures 0)
                  (bl.mp:block-builder-include builder))
                 (t
                  (bl.mp:block-builder-skip builder)
                  (when (and (> (incf consecutive-failures)
                                +max-consecutive-failures+)
                             (> (+ weight +block-full-enough-weight-delta+)
                                *block-max-weight*))
                    (return)))))))
        (bl.mp:block-builder-finish builder))
      (values (nreverse selected) fees weight sigops))))

(defun assemble-block-template (chain-state mempool &key block-time)
  "Assemble a BLOCK-TEMPLATE for the block extending CHAIN-STATE's tip, filling
it from MEMPOOL by walking txgraph chunks in descending chunk-feerate order
(cluster mempool; CPFP-aware, since a fee-bumping child shares its parent's
chunk). BLOCK-TIME defaults to now.

Deliberate divergence from Core's fit test: Core sizes graph entries in
sigops-adjusted weight (max(weight, sigops * 20), txmempool.cpp:1017-1018)
and tests that against the weight budget, a conservative overestimate; our
graph is in sigops-adjusted VSIZE (the same value /4, ceilinged — see
sigop-adjusted-vsize), and the chunk's exact weight and exact sigops are
each tested against their own consensus budget instead - equally safe,
marginally less conservative for sigops-dense chunks. Chunk feerates order
by fee/adjusted-vsize, matching Core's fee/adjusted-weight ordering up to
the per-tx ceiling."
  (let* ((tip (bl.store:get-block-index-entry
               chain-state (bl.store:best-block-hash chain-state)))
         (prev-hash (bl.store:best-block-hash chain-state))
         (height (if tip (1+ (bl.store:block-index-entry-height tip)) 0))
         (now (or block-time (bl.ser:get-unix-time)))
         ;; Median-time-past: the locktime cutoff for tx finality (Core
         ;; m_lock_time_cutoff, miner.cpp:150) and, +1, the header floor.
         (mtp (or (bl.val:compute-median-time-past-from-entry tip) 0))
         ;; Header time floor (Core GetMinimumTime, miner.cpp:36-47): MTP+1,
         ;; raised at retarget heights to the previous block's ACTUAL time
         ;; minus MAX_TIMEWARP — the BIP94 timewarp rule, applied on ALL
         ;; networks ("makes future activation safer") at the chain's own
         ;; retarget period; testnet4 and regtest under -test=bip94 enforce it
         ;; in consensus, so a template without the clamp can be a block
         ;; everyone rejects.
         (mintime (next-block-mintime tip height mtp))
         ;; Core UpdateTime (miner.cpp:49-57): nTime = max(mintime, now).
         (curtime (max now mintime))
         (bits (if tip
                   (next-block-required-bits chain-state tip curtime)
                   bl.store:+pow-limit-bits+))
         (version (next-block-version chain-state tip)))
    (multiple-value-bind (selected fees weight sigops)
        (%select-chunks mempool height mtp)
      (multiple-value-bind (commitment script) (%default-witness-commitment selected)
        (setf *last-block-template*
              (make-block-template
               :height height :prev-hash prev-hash :bits bits :version version
               :curtime curtime :mintime mintime
               :transactions selected :total-fees fees :total-weight weight :total-sigops sigops
               :coinbase-value (+ (bl.val:calculate-block-subsidy height) fees)
               :witness-commitment commitment
               :default-witness-commitment-script script))))))
