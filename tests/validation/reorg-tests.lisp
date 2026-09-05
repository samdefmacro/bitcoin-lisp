(in-package #:bitcoin-lisp.tests)

(def-suite :reorg-tests
  :description "Tests for chain reorganization logic"
  :in :bitcoin-lisp-tests)

(in-suite :reorg-tests)

;;;; Helpers for building test chains

(defmacro %with-index-node ((chain-state block-store &rest node-args) &body body)
  "Bind *NODE* to a node holding CHAIN-STATE (its validated chainstate) and
BLOCK-STORE plus NODE-ARGS -- e.g. :tx-index -- the way the connect-time
index hook finds it on a live node. The periodic-flush globals are rebound
so a validation fixture never flushes because of where it landed in the
battery."
  `(let ((bl:*node* (bl:make-node :chainstates (list ,chain-state)
                                    :block-store ,block-store ,@node-args))
         (bl::*blocks-since-flush* 0)
         (bl::*last-flush-universal-time* (get-universal-time)))
     ,@body))

(defun make-reorg-hash (id)
  "Create a unique 32-byte hash from an integer ID."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) (logand id #xFF))
    (setf (aref h 1) (logand (ash id -8) #xFF))
    h))

(defun build-chain-entries (heights &key (base-work 0) (prev nil) (chain-state nil))
  "Build a list of block-index-entries for the given heights.
Returns the tip entry. If CHAIN-STATE provided, entries are added to it."
  (let ((entry prev))
    (dolist (h heights)
      (let ((new-entry (bl.store:make-block-index-entry
                        :hash (make-reorg-hash (+ h (* 1000 (if prev (bl.store:block-index-entry-height prev) 0))))
                        :height h
                        :header nil
                        :prev-entry entry
                        :chain-work (+ base-work h)
                        :status :valid)))
        (when chain-state
          (bl.store:add-block-index-entry chain-state new-entry))
        (setf entry new-entry)))
    entry))

;;; Fork point detection tests

(test find-fork-point-same-chain
  "Fork point of two entries on the same chain is the earlier one."
  (let* ((genesis (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bl.store:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         (block2 (bl.store:make-block-index-entry
                  :hash (make-reorg-hash 2) :height 2 :prev-entry block1 :chain-work 2 :status :valid)))
    (let ((fork (bl.val:find-fork-point block2 block1)))
      (is (not (null fork)))
      (is (= 1 (bl.store:block-index-entry-height fork))))))

(test find-fork-point-diverging-chains
  "Fork point of two diverging chains is the common ancestor."
  (let* ((genesis (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bl.store:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         ;; Chain A: genesis -> 1 -> 2a -> 3a
         (block2a (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 20) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3a (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 30) :height 3 :prev-entry block2a :chain-work 3 :status :valid))
         ;; Chain B: genesis -> 1 -> 2b -> 3b
         (block2b (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 21) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3b (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 31) :height 3 :prev-entry block2b :chain-work 3 :status :valid)))
    (let ((fork (bl.val:find-fork-point block3a block3b)))
      (is (not (null fork)))
      ;; Fork point is block1 (height 1)
      (is (= 1 (bl.store:block-index-entry-height fork)))
      (is (equalp (make-reorg-hash 1) (bl.store:block-index-entry-hash fork))))))

(test find-fork-point-different-lengths
  "Fork point works when chains have different lengths."
  (let* ((genesis (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bl.store:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         ;; Short chain: genesis -> 1 -> 2a
         (block2a (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 20) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         ;; Long chain: genesis -> 1 -> 2b -> 3b -> 4b
         (block2b (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 21) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3b (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 31) :height 3 :prev-entry block2b :chain-work 3 :status :valid))
         (block4b (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 41) :height 4 :prev-entry block3b :chain-work 4 :status :valid)))
    (let ((fork (bl.val:find-fork-point block2a block4b)))
      (is (= 1 (bl.store:block-index-entry-height fork))))))

;;; Collect chain entries tests

(test collect-chain-entries-basic
  "Collect entries from tip back to (not including) fork point."
  (let* ((genesis (bl.store:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bl.store:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         (block2 (bl.store:make-block-index-entry
                  :hash (make-reorg-hash 2) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3 (bl.store:make-block-index-entry
                  :hash (make-reorg-hash 3) :height 3 :prev-entry block2 :chain-work 3 :status :valid)))
    (let ((entries (bl.val::collect-chain-entries block3 genesis)))
      ;; collect-chain-entries walks tip→fork, pushes, then nreverses
      ;; Result order: fork-adjacent first, tip last
      (is (= 3 (length entries)))
      ;; Verify all heights are present (order may vary)
      (let ((heights (mapcar #'bl.store:block-index-entry-height entries)))
        (is (member 1 heights))
        (is (member 2 heights))
        (is (member 3 heights))))))

;;; UTXO reorg consistency

(test utxo-apply-disconnect-roundtrip
  "Apply then disconnect a block should restore original UTXO state."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Initial state: one UTXO
    (bl.store:add-utxo utxo-set prev-txid 0 100000 script 50)
    (let ((initial-count (bl.store:utxo-count utxo-set)))
      ;; Apply block that spends it
      (let* ((coinbase (make-e2e-coinbase-tx))
             (spending (make-e2e-regular-tx :prev-txid prev-txid :prev-index 0 :value 90000))
             (block (make-e2e-block (list coinbase spending))))
        (let ((spent-utxos (bl.store:apply-block-to-utxo-set utxo-set block 51)))
          ;; State changed
          (is (not (= initial-count (bl.store:utxo-count utxo-set))))
          ;; Disconnect
          (bl.store:disconnect-block-from-utxo-set utxo-set block spent-utxos)
          ;; State restored
          (is (= initial-count (bl.store:utxo-count utxo-set)))
          ;; Original UTXO is back
          (is (bl.store:utxo-exists-p utxo-set prev-txid 0))
          (let ((entry (bl.store:get-utxo utxo-set prev-txid 0)))
            (is (= 100000 (bl.store:utxo-entry-value entry)))))))))

(test utxo-multi-block-disconnect
  "Disconnecting multiple blocks in reverse restores the original state."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xE1))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Initial UTXO
    (bl.store:add-utxo utxo-set txid1 0 200000 script 10)
    (let ((initial-count (bl.store:utxo-count utxo-set)))
      ;; Block 1: spends txid1
      (let* ((cb1 (make-e2e-coinbase-tx :height 11))
             (tx1 (make-e2e-regular-tx :prev-txid txid1 :prev-index 0 :value 190000))
             (block1 (make-e2e-block (list cb1 tx1)))
             (spent1 (bl.store:apply-block-to-utxo-set utxo-set block1 11)))
        ;; Block 2: spends block1's coinbase
        (let* ((cb1-txid (bl.ser:transaction-hash cb1))
               (cb2 (make-e2e-coinbase-tx :height 12))
               (tx2 (make-e2e-regular-tx :prev-txid cb1-txid :prev-index 0 :value 4999000000))
               (block2 (make-e2e-block (list cb2 tx2)))
               (spent2 (bl.store:apply-block-to-utxo-set utxo-set block2 12)))
          ;; Disconnect block2 then block1
          (bl.store:disconnect-block-from-utxo-set utxo-set block2 spent2)
          (bl.store:disconnect-block-from-utxo-set utxo-set block1 spent1)
          ;; Original state restored
          (is (= initial-count (bl.store:utxo-count utxo-set)))
          (is (bl.store:utxo-exists-p utxo-set txid1 0)))))))

(test utxo-cross-block-dep-disconnect-order
  "Regression: disconnecting multiple blocks must process them
tip-to-fork. If A (lower height) creates output O and B (higher) spends
O, the buggy fork-to-tip order leaves O re-added by B's undo data
after A's outputs were already removed (no-op'd because B had spent
O during apply). Observed live on test-bitcoin-server 2026-05-20 at
h=135616 during a 17-block testnet4 reorg: perform-reorg's
`(reverse to-disconnect)` flipped collect-chain-entries' tip-first
ordering, causing the symptom on the apply phase of the new chain
(\"refusing to overwrite unspent coin\"). Bitcoin Core's
DisconnectTip iterates from active tip backwards via pindex->pprev."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (initial-txid (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element #xC1))
         (script (make-array 25 :element-type '(unsigned-byte 8)
                                :initial-element #x76)))
    ;; Pre-existing UTXO consumed by block 1.
    (bl.store:add-utxo utxo-set initial-txid 0 200000 script 10)
    (let* ((cb1 (make-e2e-coinbase-tx :height 11))
           ;; Block 1: tx spends initial-txid:0, creates X (this tx's :0).
           (tx-x (make-e2e-regular-tx :prev-txid initial-txid :prev-index 0
                                       :value 190000))
           (block1 (make-e2e-block (list cb1 tx-x)))
           (x-txid (bl.ser:transaction-hash tx-x))
           (spent1 (bl.store:apply-block-to-utxo-set
                    utxo-set block1 11)))
      ;; Block 2: tx spends X (cross-block dependency).
      (let* ((cb2 (make-e2e-coinbase-tx :height 12))
             (tx-y (make-e2e-regular-tx :prev-txid x-txid :prev-index 0
                                         :value 180000))
             (block2 (make-e2e-block (list cb2 tx-y)))
             (spent2 (bl.store:apply-block-to-utxo-set
                      utxo-set block2 12)))
        ;; Disconnect in WRONG order (fork-to-tip: block1 first). This
        ;; emulates the bug: with the (reverse to-disconnect) flip in
        ;; perform-reorg, the lower block was processed first.
        (bl.store:disconnect-block-from-utxo-set
         utxo-set block1 spent1)
        (bl.store:disconnect-block-from-utxo-set
         utxo-set block2 spent2)
        ;; Symptom of the bug: X re-added by block2's undo restoration
        ;; even though it should be net-removed (created and consumed
        ;; on the disconnected chain). The correct ordering — block2
        ;; first then block1 — would have removed X cleanly when
        ;; processing block1's forward output walk.
        ;;
        ;; This test asserts the buggy order leaves X unspent (the
        ;; observable failure mode). A separate assertion below confirms
        ;; the correct order does not.
        (is (bl.store:utxo-exists-p utxo-set x-txid 0))))
    ;; Now repeat with the CORRECT order and assert X is gone.
    (let ((utxo-set2 (bl.store:make-utxo-set)))
      (bl.store:add-utxo utxo-set2 initial-txid 0 200000 script 10)
      (let* ((cb1 (make-e2e-coinbase-tx :height 11))
             (tx-x (make-e2e-regular-tx :prev-txid initial-txid :prev-index 0
                                         :value 190000))
             (block1 (make-e2e-block (list cb1 tx-x)))
             (x-txid (bl.ser:transaction-hash tx-x))
             (spent1 (bl.store:apply-block-to-utxo-set
                      utxo-set2 block1 11)))
        (let* ((cb2 (make-e2e-coinbase-tx :height 12))
               (tx-y (make-e2e-regular-tx :prev-txid x-txid :prev-index 0
                                           :value 180000))
               (block2 (make-e2e-block (list cb2 tx-y)))
               (spent2 (bl.store:apply-block-to-utxo-set
                        utxo-set2 block2 12)))
          ;; Correct order: block2 (tip) first, block1 (fork-adjacent) last.
          (bl.store:disconnect-block-from-utxo-set
           utxo-set2 block2 spent2)
          (bl.store:disconnect-block-from-utxo-set
           utxo-set2 block1 spent1)
          (is (not (bl.store:utxo-exists-p utxo-set2 x-txid 0)))
          (is (bl.store:utxo-exists-p utxo-set2 initial-txid 0)))))))

;;;; activate-block dispatch tests
;;;;
;;;; activate-block is the consensus-correct entry point that replaces
;;;; the (validate-block → if-valid-then-connect-block) dance in
;;;; process-received-block. The bug it fixes: when a received block
;;;; sits on a competing fork with more work, the OLD order ran
;;;; validate-block against the CURRENT (wrong-fork) UTXO state and
;;;; failed MISSING-INPUT before connect-block's reorg branch could
;;;; fire. activate-block reorders: detect competing-fork case first,
;;;; pre-reorg, THEN validate against the corrected UTXO state.
;;;;
;;;; These tests use coinbase-only blocks (via make-reorg-test-block),
;;;; which pass validate-block trivially regardless of UTXO state. They
;;;; verify the dispatch decision is correct: which case fires for
;;;; which input. The deeper "validate runs against post-reorg state"
;;;; assertion is implicit — after activate-block returns T for a
;;;; competing-fork block, chain-state's tip and the UTXO set reflect
;;;; the new fork, which means perform-reorg ran before validate.

;; make-reorg-test-block was replaced by the unified make-reorg-test-block
;; (persistence-tests.lisp) — that helper now derives script-sig from
;; block-hash and computes a real merkle root, so it satisfies both the
;; direct-connect-block path (older tests) and the activate-block / full
;; validate-block path (these tests) without per-test duplication.

(test activate-block-extends-current-tip
  "When the incoming block's parent IS the current tip, activate-block
should extend the chain normally."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "extends-tip")
    ;; Build chain A: genesis → A1 → A2.
    (build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 2))
    (is (= 2 (bl.store:current-height chain-state)))
    ;; Build A3 extending the tip; receive it via activate-block.
    (let* ((a2-hash (bl.store:best-block-hash chain-state))
           (a3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                      (setf (aref h 0) #xA0) (setf (aref h 1) 3) h))
           (a3-block (make-reorg-test-block a2-hash a3-hash 3)))
      (multiple-value-bind (activated error)
          (bl.val:activate-block
           a3-block chain-state block-store utxo-set :skip-scripts t)
        (is (eq t activated))
        (is (null error))
        (is (= 3 (bl.store:current-height chain-state)))
        (is (equalp a3-hash (bl.store:best-block-hash chain-state)))))
    (clear-undo-cache))))

(test activate-block-pre-reorgs-on-stronger-fork
  "When the incoming block's parent sits on a competing fork that, with
this block added, has strictly more chain-work than current tip,
activate-block should pre-reorg to the new fork and then activate the
block. Chain tip should land on the new fork's tip."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "stronger-fork")
    ;; Chain A: genesis → A1 → A2. Active.
    (build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 2))
    (let ((a-tip-hash (bl.store:best-block-hash chain-state)))
      ;; Pre-build chain B: genesis → B1 → B2 (both stored + indexed but
      ;; NOT applied to UTXO). Each B-block's chain-work matches the
      ;; corresponding A-block's, so chain B reaches A's work at h=2 and
      ;; will overtake at h=3.
      (let ((b-hashes (make-test-chain-hashes #xB0 2))
            (prev-hash genesis-hash))
        (loop for h from 1 to 2
              for block-hash in b-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bl.store:store-block block-store block)
                   ;; connect-block on a non-extending block stores it
                   ;; with the appropriate :valid status + chain-work.
                   (bl.val:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash)))
        ;; After both forks have 2 blocks each, A is still tip (race-pick
        ;; — first-seen wins on equal-work).
        (is (equalp a-tip-hash (bl.store:best-block-hash chain-state)))
        (is (= 2 (bl.store:current-height chain-state))))

      ;; Now receive B3, which extends B2. B3 has more chain-work than
      ;; A2, so activate-block must pre-reorg from A2 → B2 then connect.
      (let* ((b2-hash (second (make-test-chain-hashes #xB0 2)))
             (b3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                        (setf (aref h 0) #xB0) (setf (aref h 1) 3) h))
             (b3-block (make-reorg-test-block b2-hash b3-hash 3)))
        (multiple-value-bind (activated error)
            (bl.val:activate-block
             b3-block chain-state block-store utxo-set :skip-scripts t)
          (is (eq t activated))
          (is (null error))
          ;; Chain tip is now B3.
          (is (= 3 (bl.store:current-height chain-state)))
          (is (equalp b3-hash (bl.store:best-block-hash chain-state)))
          ;; UTXO set reflects B chain: B1, B2, B3 coinbase outputs
          ;; present; A1, A2 absent. (Each coinbase txid is unique per
          ;; make-reorg-test-block, derived from block-hash.)
          (is (= 3 (bl.store:utxo-count utxo-set))))))
    (clear-undo-cache))))

(test reorg-rejects-fork-carrying-invalid-block
  "CC-1 regression. A competing fork with strictly more work but carrying an
INVALID block (here B2 has an over-value coinbase) must be REJECTED during the
reorg: the invalid block must never enter the UTXO set, and the node must roll
back to its original valid chain. Before the fix, perform-reorg applied fork
blocks with apply-block-to-utxo-set and NO validate-block — so a more-work fork
(cheap to mine under testnet4's min-difficulty rule) could inject any invalid
block into the chainstate."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "reorg-invalid-fork")
    ;; Chain A: genesis -> A1 -> A2. Active and valid.
    (build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 2))
    (let ((a-tip-hash (bl.store:best-block-hash chain-state))
          (a-utxo-count (bl.store:utxo-count utxo-set)))
      ;; Pre-build chain B: genesis -> B1 -> B2, where B2's coinbase pays
      ;; 50.00000001 BTC — one satoshi over the 50 BTC subsidy, so B2 is
      ;; invalid (:coinbase-too-large). Stored + indexed but not applied
      ;; (equal work with A keeps A active by first-seen).
      (let ((b-hashes (make-test-chain-hashes #xB0 2))
            (prev-hash genesis-hash))
        (loop for h from 1 to 2
              for block-hash in b-hashes
              do (let ((block (make-reorg-test-block
                               prev-hash block-hash h
                               :value (if (= h 2) 5000000001 5000000000))))
                   (bl.store:store-block block-store block)
                   (bl.val:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash)))
        (is (equalp a-tip-hash (bl.store:best-block-hash chain-state)))
        (is (= 2 (bl.store:current-height chain-state))))
      ;; Receive B3 (extends B2): chain B now has more work than A2, so
      ;; activate-block pre-reorgs A2 -> B2. perform-reorg validates B1 (ok)
      ;; then B2 (over-value coinbase) -> fails -> rolls back to A.
      (let* ((b2-hash (second (make-test-chain-hashes #xB0 2)))
             (b3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
                        (setf (aref h 0) #xB0) (setf (aref h 1) 3) h))
             (b3-block (make-reorg-test-block b2-hash b3-hash 3)))
        (multiple-value-bind (activated error)
            (bl.val:activate-block
             b3-block chain-state block-store utxo-set :skip-scripts t)
          ;; Reorg rejected, surfacing the fork block's validation error.
          (is (null activated))
          (is (eq :coinbase-too-large error))
          ;; Node rolled back to chain A — tip, height, and UTXO unchanged.
          (is (equalp a-tip-hash (bl.store:best-block-hash chain-state)))
          (is (= 2 (bl.store:current-height chain-state)))
          (is (= a-utxo-count (bl.store:utxo-count utxo-set)))
          ;; The invalid B2 coinbase never entered the UTXO set.
          (is (null (bl.store:get-utxo
                     utxo-set
                     (bl.ser:transaction-hash
                      (first (bl.ser:bitcoin-block-transactions
                              (make-reorg-test-block
                               (first (make-test-chain-hashes #xB0 2))
                               b2-hash 2 :value 5000000001))))
                     0)))))
      (clear-undo-cache)))))

(test activate-block-stores-weaker-fork-without-activating
  "When the incoming block's parent sits on a competing fork whose
total work doesn't exceed current tip's, activate-block returns
:weaker-chain and stores the block in the block-store but doesn't
update the chain tip."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "weaker-fork")
    ;; Chain A has 3 blocks.
    (build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 3))
    (let ((a-tip-hash (bl.store:best-block-hash chain-state)))
      (is (= 3 (bl.store:current-height chain-state)))
      ;; Pre-store B1 on a competing fork (1 block, weaker than A's 3).
      (let* ((b1-hash (first (make-test-chain-hashes #xB0 1)))
             (b1-block (make-reorg-test-block genesis-hash b1-hash 1)))
        (bl.val:connect-block b1-block chain-state block-store utxo-set)
        ;; Now receive B2 extending B1. Total work for B = 2, still less
        ;; than A's 3. activate-block should NOT reorg.
        (let* ((b2-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                          (setf (aref h 0) #xB0) (setf (aref h 1) 2) h))
               (b2-block (make-reorg-test-block b1-hash b2-hash 2)))
          (multiple-value-bind (activated error)
              (bl.val:activate-block
               b2-block chain-state block-store utxo-set :skip-scripts t)
            (is (null activated))
            (is (eq error :weaker-chain))
            ;; Chain tip unchanged.
            (is (equalp a-tip-hash (bl.store:best-block-hash chain-state)))
            (is (= 3 (bl.store:current-height chain-state)))
            ;; B2 IS in the block store for future reorg consideration.
            (is (not (null (bl.store:get-block block-store b2-hash))))))))
    (clear-undo-cache))))

(test activate-block-unknown-parent
  "When the incoming block's parent isn't in the chain index,
activate-block returns :unknown-parent without doing anything."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "unknown-parent")
    (declare (ignore genesis-hash))
    (build-and-connect chain-state block-store utxo-set
                        (bl.store:best-block-hash chain-state)
                        (make-test-chain-hashes #xA0 1))
    (let* ((mystery-prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC))
           (orphan-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                          (setf (aref h 0) #xCC) (setf (aref h 1) 1) h))
           (orphan (make-reorg-test-block mystery-prev orphan-hash 5)))
      (multiple-value-bind (activated error)
          (bl.val:activate-block
           orphan chain-state block-store utxo-set :skip-scripts t)
        (is (null activated))
        (is (eq error :unknown-parent))
        ;; Chain unchanged.
        (is (= 1 (bl.store:current-height chain-state)))))
    (clear-undo-cache))))

(test invalidate-and-reconsider-block
  "invalidate-block marks a block + descendants invalid and reorgs to its parent;
reconsider-block clears the flags and reorgs back to the best valid chain."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "invalidate")
     ;; genesis -> A1 -> A2 -> A3
     (let ((hashes (make-test-chain-hashes #xA0 3)))
       (build-and-connect chain-state block-store utxo-set genesis-hash hashes)
       (is (= 3 (bl.store:current-height chain-state)))
       (let ((a2-hash (second hashes)))
         ;; invalidate A2 -> chain reorgs back to A1 (height 1); A2 + A3 invalid
         (multiple-value-bind (ok reason)
             (bl.val:invalidate-block
              chain-state block-store utxo-set a2-hash)
           (is (eq t ok))
           (is (null reason)))
         (is (= 1 (bl.store:current-height chain-state)))
         (is (eq :invalid (bl.store:block-index-entry-status
                           (bl.store:get-block-index-entry chain-state a2-hash))))
         (is (eq :invalid (bl.store:block-index-entry-status
                           (bl.store:get-block-index-entry chain-state (third hashes)))))
         ;; reconsider A2 -> chain reorgs forward to A3 (height 3) again
         (multiple-value-bind (ok reason)
             (bl.val:reconsider-block
              chain-state block-store utxo-set a2-hash)
           (is (eq t ok))
           (is (null reason)))
         (is (= 3 (bl.store:current-height chain-state)))
         (is (not (eq :invalid (bl.store:block-index-entry-status
                                (bl.store:get-block-index-entry chain-state a2-hash)))))))
     ;; invalidating genesis is refused; unknown hash too
     (multiple-value-bind (ok reason)
         (bl.val:invalidate-block chain-state block-store utxo-set genesis-hash)
       (is (null ok)) (is (eq :cannot-invalidate-genesis reason)))
     (clear-undo-cache))))

(test precious-block
  "preciousblock reorgs to a chosen block of >= the tip's work; equal-work
competitors don't displace it (strict-> fork choice), and it can flip between
equal-work forks."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "precious")
     (let ((a-hashes (make-test-chain-hashes #xA0 1)))
       (build-and-connect chain-state block-store utxo-set genesis-hash a-hashes)
       (let* ((a1-hash (first a-hashes))
              (a1-entry (bl.store:get-block-index-entry chain-state a1-hash))
              (genesis-entry (bl.store:get-block-index-entry chain-state genesis-hash))
              (b1-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                         (setf (aref h 0) #xB0) (setf (aref h 1) 1) h))
              (b1-block (make-reorg-test-block genesis-hash b1-hash 1)))
         (is (equalp a1-hash (bl.store:best-block-hash chain-state)))
         ;; Stand up an equal-work competing fork B1 (block + header-valid index
         ;; entry, as header sync would in real operation).
         (bl.store:store-block block-store b1-block)
         (bl.store:add-block-index-entry
          chain-state
          (bl.store:make-block-index-entry
           :hash b1-hash :height 1
           :chain-work (bl.store:block-index-entry-chain-work a1-entry)
           :status :header-valid
           :header (bl.ser:bitcoin-block-header b1-block)
           :prev-entry genesis-entry))
         ;; precious the current tip -> no-op
         (is (eq t (bl.val:precious-block chain-state block-store utxo-set a1-hash)))
         (is (equalp a1-hash (bl.store:best-block-hash chain-state)))
         ;; precious B1 -> reorg to the equal-work B1
         (multiple-value-bind (ok reason)
             (bl.val:precious-block chain-state block-store utxo-set b1-hash)
           (is (eq t ok)) (is (null reason)))
         (is (equalp b1-hash (bl.store:best-block-hash chain-state)))
         ;; precious A1 -> flip back (both forks equal work)
         (bl.val:precious-block chain-state block-store utxo-set a1-hash)
         (is (equalp a1-hash (bl.store:best-block-hash chain-state)))
         ;; unknown block -> error
         (multiple-value-bind (ok reason)
             (bl.val:precious-block
              chain-state block-store utxo-set
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE))
           (is (null ok)) (is (eq :block-not-found reason)))))
     (clear-undo-cache))))

(test rpc-verifychain-reads-stored-blocks
  "verifychain (checklevel 0) confirms the last N stored blocks read back from
the block store."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "verifychain")
     (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #x70 3))
     (let ((node (bl:make-node)))
       (setf (bl:node-chain-state node) chain-state)
       (setf (bl:node-block-store node) block-store)
       (is (eq t (bl.rpc::rpc-verifychain node (list 0 3)))))
     (clear-undo-cache))))

(test rpc-getchaintxstats-window
  "getchaintxstats computes window tx counts over connected blocks (coinbase-only
test blocks: 1 tx each), and tx-count round-trips through the v2 header index."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "chaintxstats")
     (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #x71 3))
     (let ((node (bl:make-node)))
       (setf (bl:node-chain-state node) chain-state)
       (setf (bl:node-block-store node) block-store)
       (let ((r (bl.rpc::rpc-getchaintxstats node (list 2))))
         (is (= 3 (cdr (assoc "window_final_block_height" r :test #'string=))))
         (is (= 2 (cdr (assoc "window_block_count" r :test #'string=))))
         (is (= 2 (cdr (assoc "window_tx_count" r :test #'string=))))
         (is (integerp (cdr (assoc "window_interval" r :test #'string=)))))
       ;; tx-count persists through the v2 header index.
       (bl.store:save-header-index chain-state)
       (let ((cs2 (bl.store:make-chain-state
                   :base-path (bl.store::chain-state-base-path chain-state))))
         (is-true (bl.store:load-header-index cs2))
         (let ((tip (bl.store:get-block-index-entry
                     cs2 (bl.store:best-block-hash chain-state))))
           (is (= 1 (bl.store:block-index-entry-tx-count tip)))))
       ;; blockcount >= height -> error (Core's bound).
       (signals bl.rpc:rpc-error
         (bl.rpc::rpc-getchaintxstats node (list 99))))
     (clear-undo-cache))))

(test rpc-getchaintxstats-genesis-backfill
  "txcount stays known on a v1-upgraded index: genesis is never in the block
store, so its zeroed tx-count is backfilled definitionally (exactly its
coinbase) instead of being dropped as unreadable."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "chaintxstats-genesis")
     (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #x72 3))
     ;; Simulate a v1-loaded index: genesis entry's tx-count is 0.
     (let ((genesis-entry (bl.store:get-block-index-entry
                           chain-state genesis-hash)))
       (setf (bl.store:block-index-entry-tx-count genesis-entry) 0)
       (let ((node (bl:make-node)))
         (setf (bl:node-chain-state node) chain-state)
         (setf (bl:node-block-store node) block-store)
         (let ((r (bl.rpc::rpc-getchaintxstats node (list 2))))
           ;; genesis (1) + three coinbase-only blocks.
           (is (= 4 (cdr (assoc "txcount" r :test #'string=))))
           (is (= 2 (cdr (assoc "window_tx_count" r :test #'string=))))))
       ;; The definitional count is cached back onto the entry.
       (is (= 1 (bl.store:block-index-entry-tx-count genesis-entry))))
     (clear-undo-cache))))

;;;; Self-heal: prune a stored witness-stripped fork block during reorg

(defun make-stripped-reorg-block (prev-hash block-hash height &key (value 5000000000))
  "Like make-reorg-test-block, but the coinbase carries a witness-commitment
output and NO coinbase witness — a witness-stripped block (block-witness-stripped-p
=> T). Models a block stored via the old v1-compact :weaker-chain path."
  (let* ((script-sig (let ((s (make-array 4 :element-type '(unsigned-byte 8))))
                       (replace s block-hash :start2 0 :end2 4) s))
         (commit (let ((c (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
                   (setf (aref c 0) #x6a (aref c 1) #x24       ; OP_RETURN push36
                         (aref c 2) #xaa (aref c 3) #x21       ; aa21a9ed
                         (aref c 4) #xa9 (aref c 5) #xed)
                   c))
         (coinbase-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                            :initial-element 0)
                                                          :index #xFFFFFFFF)
                                        :script-sig script-sig))
                       :outputs (vector (bl.ser:make-tx-out
                                         :value value
                                         :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                    :initial-element #x76))
                                        (bl.ser:make-tx-out :value 0 :script-pubkey commit))
                       :lock-time 0))
         (merkle-root (bl.val:compute-merkle-root
                       (list (bl.ser:transaction-hash coinbase-tx))))
         (header (bl.ser:make-block-header
                  :version 1 :prev-block prev-hash :merkle-root merkle-root
                  :timestamp (+ 1231006505 (* height 600)) :bits #x1d00ffff :nonce 0
                  :cached-hash block-hash)))
    (bl.ser:make-bitcoin-block :header header :transactions (list coinbase-tx))))

(test perform-reorg-prunes-witness-stripped-fork-block
  "A stored witness-stripped fork block (commitment but no coinbase nonce, e.g.
from the old v1-compact :weaker-chain path) is pruned during the reorg precondition
and returned as MISSING so it gets re-downloaded witness-complete — instead of
failing the reorg forever and wedging the node (testnet4 stuck ~1800 blocks behind)."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "prune-stripped")
     ;; Active chain A: genesis -> A1 -> A2.
     (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #xA0 2))
     (let* ((a2-entry (bl.store:get-block-index-entry
                       chain-state (bl.store:best-block-hash chain-state)))
            (genesis-entry (bl.store:get-block-index-entry chain-state genesis-hash))
            (b-hashes (make-test-chain-hashes #xB0 2))
            (b1-hash (first b-hashes))
            (b2-hash (second b-hashes))
            (b1-block (make-stripped-reorg-block genesis-hash b1-hash 1))   ; STRIPPED
            (b2-block (make-reorg-test-block b1-hash b2-hash 2)))
       (bl.store:store-block block-store b1-block)
       (bl.store:store-block block-store b2-block)
       (let ((b1-entry (bl.store:make-block-index-entry
                        :hash b1-hash :height 1 :prev-entry genesis-entry
                        :chain-work 100 :status :header-valid
                        :header (bl.ser:bitcoin-block-header b1-block))))
         (bl.store:add-block-index-entry chain-state b1-entry)
         (let ((b2-entry (bl.store:make-block-index-entry
                          :hash b2-hash :height 2 :prev-entry b1-entry
                          :chain-work 200 :status :header-valid
                          :header (bl.ser:bitcoin-block-header b2-block))))
           (bl.store:add-block-index-entry chain-state b2-entry)
           ;; sanity: B1 is stored and detected as stripped
           (is-true (bl.val:block-witness-stripped-p
                     (bl.store:get-block block-store b1-hash)))
           ;; Attempt reorg A2 -> B2.
           (multiple-value-bind (ok missing)
               (bl.val:perform-reorg
                chain-state block-store utxo-set a2-entry b2-entry)
             (is (null ok))                                            ; refused
             (is (not (null missing)))                                 ; missing list returned
             (is (null (bl.store:get-block block-store b1-hash)))   ; B1 pruned
             (is (member b1-hash (mapcar #'car missing) :test #'equalp))
             ;; tip unchanged — no mutation on a refused reorg
             (is (= 2 (bl.store:current-height chain-state)))
             (is (equalp (bl.store:block-index-entry-hash a2-entry)
                         (bl.store:best-block-hash chain-state)))))))
     (clear-undo-cache))))

(test activate-best-chain-switches-to-a-downloaded-heavier-fork
  "The defect this closes: a strictly-heavier fork whose blocks are ALL already
on disk sat unactivated forever, because the only reorg trigger was a block
ARRIVING through connect-block. Nothing ever re-evaluated the candidate set, so
after a refused reorg re-downloaded its missing bodies — or after a restart —
the node stayed on the lighter chain until an unrelated block happened to
arrive.

Live on 2026-08-19: testnet4 held tip 149110 for 40+ minutes while a
fully-downloaded 149120 branch with strictly more work lay on disk."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "activate-best")
     (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #xA0 2))
     (let* ((a2-hash (bl.store:best-block-hash chain-state))
            (a2-entry (bl.store:get-block-index-entry chain-state a2-hash))
            (a2-work (bl.store:block-index-entry-chain-work a2-entry))
            (genesis-entry (bl.store:get-block-index-entry
                            chain-state genesis-hash))
            (b-hashes (make-test-chain-hashes #xB0 3))
            (b1-hash (first b-hashes))
            (b2-hash (second b-hashes))
            (b3-hash (third b-hashes))
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1))
            (b2-block (make-reorg-test-block b1-hash b2-hash 2))
            (b3-block (make-reorg-test-block b2-hash b3-hash 3)))
       ;; Every B body is on disk, exactly as it is after the re-download that
       ;; follows a refused reorg — but no B block is "arriving", so the old
       ;; code had no trigger at all.
       (bl.store:store-block block-store b1-block)
       (bl.store:store-block block-store b2-block)
       (bl.store:store-block block-store b3-block)
       (let* ((b1-entry (bl.store:make-block-index-entry
                         :hash b1-hash :height 1 :prev-entry genesis-entry
                         :chain-work (+ a2-work 1) :status :header-valid
                         :header (bl.ser:bitcoin-block-header b1-block))))
         (bl.store:add-block-index-entry chain-state b1-entry)
         (let* ((b2-entry (bl.store:make-block-index-entry
                           :hash b2-hash :height 2 :prev-entry b1-entry
                           :chain-work (+ a2-work 2) :status :header-valid
                           :header (bl.ser:bitcoin-block-header b2-block))))
           (bl.store:add-block-index-entry chain-state b2-entry)
           (let ((b3-entry (bl.store:make-block-index-entry
                            :hash b3-hash :height 3 :prev-entry b2-entry
                            :chain-work (+ a2-work 3) :status :header-valid
                            :header (bl.ser:bitcoin-block-header b3-block))))
             (bl.store:add-block-index-entry chain-state b3-entry)

             ;; Precondition — the bug state: heavier chain fully on disk, tip
             ;; still on the lighter one.
             (is (= 2 (bl.store:current-height chain-state)))
             (is (equalp a2-hash (bl.store:best-block-hash chain-state)))

             ;; The candidate search finds it, and only looks above the tip.
             (is (equalp b3-hash
                         (bl.store:block-index-entry-hash
                          (bl.val:best-valid-tip
                           chain-state block-store a2-work))))

             ;; ...and activating switches to it with no block arriving.
             (multiple-value-bind (switched missing)
                 (bl.val:activate-best-chain
                  chain-state block-store utxo-set)
               (is-true switched)
               (is (null missing)))
             (is (= 3 (bl.store:current-height chain-state)))
             (is (equalp b3-hash (bl.store:best-block-hash chain-state)))

             ;; Idempotent: once the tip IS the best chain, it does nothing.
             (multiple-value-bind (switched2 missing2)
                 (bl.val:activate-best-chain
                  chain-state block-store utxo-set)
               (is (null switched2))
               (is (null missing2)))
             (is (= 3 (bl.store:current-height chain-state)))))))
     (clear-undo-cache))))

(test activation-steps-report-the-new-tip-to-stopatheight
  "-stopatheight is checked from CONNECT-BLOCK's tip-EXTENSION arm and, since
the stopatheight fix, between ACTIVATION STEPS — because every block of an offline reindex is
connected through PERFORM-REORG instead, where the extension arm never runs.

That fix was verified by reading. A benchmark reindex then ran straight past
-stopatheight=134000 to 134898, so the reading was not enough. This probes the
SEAM: it replaces MAYBE-STOP-AT-HEIGHT with a recorder and asserts
ACTIVATE-BEST-CHAIN calls it with the height it just activated to. Stubbing is
what keeps the test free of the shutdown machinery — the real function would
ask the node to stop."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "stopatheight-seam")
     (unwind-protect
          (let ((seen '())
                (real (symbol-function 'bl:maybe-stop-at-height)))
            (unwind-protect
                 (progn
                   (setf (symbol-function 'bl:maybe-stop-at-height)
                         (lambda (chainstate hash height)
                           (declare (ignore chainstate hash))
                           (push height seen) nil))
                   (%stage-heavier-downloaded-fork chain-state block-store genesis-hash)
                   (multiple-value-bind (switched missing)
                       (bl.val:activate-best-chain
                        chain-state block-store utxo-set)
                     (is-true switched "the fixture did not activate; the probe proves nothing")
                     (is (null missing)))
                   (is (= 3 (bl.store:current-height chain-state)))
                   ;; The seam: the height activation reached must have been
                   ;; offered to the -stopatheight check.
                   (is (member 3 seen)
                       "activate-best-chain never reported its new tip to ~
maybe-stop-at-height; heights seen: ~S" seen))
              (setf (symbol-function 'bl:maybe-stop-at-height) real)))
       (clear-undo-cache)))))

(defun %stage-heavier-downloaded-fork (chain-state block-store genesis-hash)
  "Put a 3-block fork on disk with strictly more work than the current tip, as
index entries only (status :header-valid, bodies stored) — the exact on-disk
shape left behind when a refused reorg\'s missing bodies finish downloading.
Returns the fork tip hash."
  (let* ((tip-work (bl.store:block-index-entry-chain-work
                    (bl.store:get-block-index-entry
                     chain-state (bl.store:best-block-hash chain-state))))
         (genesis-entry (bl.store:get-block-index-entry chain-state genesis-hash))
         (bh (make-test-chain-hashes #xB0 3))
         (blocks (list (make-reorg-test-block genesis-hash (first bh) 1)
                       (make-reorg-test-block (first bh) (second bh) 2)
                       (make-reorg-test-block (second bh) (third bh) 3)))
         (prev genesis-entry))
    (dolist (b blocks) (bl.store:store-block block-store b))
    (loop for b in blocks
          for hash in bh
          for height from 1
          do (let ((e (bl.store:make-block-index-entry
                       :hash hash :height height :prev-entry prev
                       :chain-work (+ tip-work height) :status :header-valid
                       :header (bl.ser:bitcoin-block-header b))))
               (bl.store:add-block-index-entry chain-state e)
               (setf prev e)))
    (third bh)))

(test run-ibd-actually-calls-activate-best-chain
  "The seam must be CONNECTED, not merely correct. activate-best-chain being
right is worthless if nothing invokes it — which is precisely the defect being
fixed here, where best-valid-tip was correct and reachable only from the
reconsiderblock RPC. Drive the real run-ibd (no peers, so nothing else can
move the tip) and require that the heavier downloaded fork gets activated."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "run-ibd-wiring")
     (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #xA0 2))
     (let ((fork-tip (%stage-heavier-downloaded-fork
                      chain-state block-store genesis-hash)))
       (is (= 2 (bl.store:current-height chain-state)))
       ;; No peers: run-ibd downloads nothing, so any tip change can only come
       ;; from the activation pass.
       (let ((bl.net:*ibd-context*
               (bl.net::make-ibd-context)))
         (bl.net::run-ibd nil (bl.ctx:make-node-context :chain-state chain-state :utxo-set utxo-set :block-store block-store)))
       (is (= 3 (bl.store:current-height chain-state)))
       (is (equalp fork-tip (bl.store:best-block-hash chain-state))))
     (clear-undo-cache))))

(test run-ibd-activation-carries-the-txindex
  "The reorg driven by run-ibd's periodic activation must carry the transaction
index with it. This used to depend on a :tx-index argument threaded through
activate-best-chain -> perform-reorg, and that argument was missing from the
run-ibd call site from the day it landed: every such reorg reconnected blocks
with the index switched off, so the best-block marker stayed on a block the
reorg had just disconnected and the next startup rescanned from genesis
(~9 minutes, observed live on testnet4 on 2026-08-20). Since P2e-2 the index is
reached through the connect-time hook over the node's index list -- there is
no argument to forget -- so this binds *NODE* the way a live node has it and
asserts the marker, which is the thing that was wrong."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "run-ibd-txindex")
     (let* ((txdir (ensure-directories-exist
                    (merge-pathnames (format nil "test-txidx-activate-~D/"
                                             (get-internal-real-time))
                                     (uiop:temporary-directory))))
            (txindex (bl.store:init-tx-index txdir)))
       (unwind-protect
            (progn
              (build-and-connect chain-state block-store utxo-set genesis-hash
                                  (make-test-chain-hashes #xA0 2))
              (let ((fork-tip (%stage-heavier-downloaded-fork
                               chain-state block-store genesis-hash)))
                ;; Marker starts behind: nothing has indexed the fork yet.
                (is (not (equalp fork-tip
                                 (bl.store:txindex-best-block txindex))))
                (let ((bl.net:*ibd-context*
                        (bl.net::make-ibd-context)))
                  (%with-index-node (chain-state block-store :tx-index txindex)
                    (bl.net::run-ibd nil (bl.ctx:make-node-context :chain-state chain-state :utxo-set utxo-set :block-store block-store))))
                (is (equalp fork-tip (bl.store:best-block-hash chain-state)))
                ;; THE assertion: the reorg carried the index with it.
                (is (equalp fork-tip
                            (bl.store:txindex-best-block txindex)))))
         (bl.store:close-tx-index txindex)
         (uiop:delete-directory-tree txdir :validate t :if-does-not-exist :ignore)))
     (clear-undo-cache))))

(defun %reorg-relay-state (targeted suffix)
  "Run a reorg on a chainstate that is targeted (the assumeutxo background
chainstate) or not, and report what it did to the tx-relay structures.

Seeded with a MARKER block through the exported NOTE-BLOCK-CONNECTED, so both
structures start non-empty and the two outcomes are distinguishable in BOTH
directions: an active chainstate must reset the recent-confirmed filter (the
marker goes) and publish the fork tip (its coinbase arrives); a targeted one
must do neither."
  (with-network (:mainnet)
    (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
        (make-activate-block-fixture suffix)
      (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #xA0 2))
      (let* ((old-tip (bl.store:get-block-index-entry
                       chain-state (bl.store:best-block-hash chain-state)))
             (fork-tip-hash (%stage-heavier-downloaded-fork
                             chain-state block-store genesis-hash))
             (fork-tip (bl.store:get-block-index-entry chain-state fork-tip-hash))
             (fork-cb (bl.ser:transaction-hash
                       (first (bl.ser:bitcoin-block-transactions
                               (bl.store:get-block block-store fork-tip-hash)))))
             (marker (make-reorg-test-block
                      genesis-hash
                      (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #xEE)
                      1))
             (marker-cb (bl.ser:transaction-hash
                         (first (bl.ser:bitcoin-block-transactions marker)))))
        (bl.val:reset-recent-confirmed)
        (bl.val:note-block-connected marker)
        (when targeted
          (bl.store:set-chainstate-target chain-state fork-tip))
        (let ((reorged (bl.val:perform-reorg chain-state block-store utxo-set
                                             old-tip fork-tip)))
          (list :reorged (and reorged t)
                :height (bl.store:current-height chain-state)
                :filter-reset (not (bl.val:recently-confirmed-p marker-cb))
                :fork-tip-confirmed (and (bl.val:recently-confirmed-p fork-cb) t)
                :fork-tip-servable (and (bl.val:most-recent-block-tx fork-cb) t)))))))

(test reorg-commit-carries-the-background-chainstate-guard
  "%REORG-COMMIT's tx-relay side effects must ask the question CONNECT-BLOCK
already asks. Core never lets a background (assumeutxo) chainstate reach them:
it has no mempool at all (`assert(!curr_chainstate.m_mempool)',
validation.cpp:6203) and its BlockConnected carries the ChainstateRole so
net_processing drops it before the tx-download manager
(`if (!role.historical && ...)', net_processing.cpp:2089), while UpdatedBlockTip
is gated on `this == &m_chainman.ActiveChainstate()' (:3452).

The reorg path IS reachable for such a chainstate: ACTIVATE-BLOCK's target
filter keeps it on the target's ancestor path but not on the extend-tip case,
so a block two above its tip whose parent body is already on disk fast-forwards
through PERFORM-REORG. Its blocks are ancient, so recording them as the relay's
most-recent block, or their txids as recently confirmed, suppresses the relay
of live transactions."
  ;; CONTROL: on an untargeted chainstate the reorg still resets the filter
  ;; and publishes the fork tip -- a guard that merely disabled the code
  ;; would fail this half.
  (is (equal '(:reorged t :height 3
               :filter-reset t :fork-tip-confirmed t :fork-tip-servable t)
             (%reorg-relay-state nil "reorg-role-active")))
  ;; THE assertion: the targeted chainstate reorgs to the same height and
  ;; touches none of them.
  (is (equal '(:reorged t :height 3
               :filter-reset nil :fork-tip-confirmed nil :fork-tip-servable nil)
             (%reorg-relay-state t "reorg-role-background"))))

(test no-index-is-an-activation-argument
  "The structural guard that replaced \"every activation call passes
:tx-index\". That guard existed because the index was an ARGUMENT, and an
argument is exactly what a new call site forgets: it happened three separate
times (the arrival path, the run-ibd activation, and five ibd.lisp sites).
Now every index is reached through the connect-time hook over the node's
index list, so the invariant is the opposite one -- no activation function
takes an index, and both connect sites in block.lisp call the hook."
  (flet ((src (name)
           (uiop:read-file-string
            (merge-pathnames name (asdf:system-source-directory :bitcoin-lisp)))))
    (dolist (f '("src/validation/block.lisp" "src/networking/ibd.lisp"
                 "src/networking/protocol.lisp"))
      (is (null (search ":tx-index" (src f)))
          "~A still threads :tx-index; indexes reach the chain through
           index-block-connected, never an argument" f))
    (let ((block-src (src "src/validation/block.lisp")))
      (is (= 2 (%count-occurrences "(bl.vi:notify-block-connected " block-src))
          "block.lisp must announce BlockConnected at exactly its two connect
           sites (connect-block and perform-reorg's phase C)"))
    (is-true (member 'bl:index-block-connected (bl.vi:validation-hooks :block-connected))
             "the index driver is no longer a :block-connected hook")))

(test best-valid-tip-min-work-floor-prunes-the-search
  "best-valid-tip's MIN-WORK floor is what makes it affordable on the sync
path: BLOCK-EXISTS-P is a filesystem probe per entry, so the chain-work compare
has to come first and the floor has to prune. Behaviourally: nothing at or
below the floor is ever returned."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "bvt-floor")
     (build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #xA0 2))
     (let* ((tip (bl.store:get-block-index-entry
                  chain-state (bl.store:best-block-hash chain-state)))
            (tip-work (bl.store:block-index-entry-chain-work tip)))
       ;; At the tip's own work there is nothing strictly better.
       (is (null (bl.val:best-valid-tip
                  chain-state block-store tip-work)))
       ;; Below it, the tip itself qualifies.
       (is (equalp (bl.store:block-index-entry-hash tip)
                   (bl.store:block-index-entry-hash
                    (bl.val:best-valid-tip
                     chain-state block-store (1- tip-work))))))
     (clear-undo-cache))))

(defun %make-2tx-reorg-block (prev-hash block-hash height)
  "A reorg test block with a coinbase PLUS a dummy second tx, so tx-count > 1 —
exercises the corrupt-undo guard (which exempts coinbase-only blocks, whose
empty undo is legitimate)."
  (let* ((base (make-reorg-test-block prev-hash block-hash height))
         (coinbase (first (bl.ser:bitcoin-block-transactions base)))
         (hdr (bl.ser:bitcoin-block-header base))
         (dummy (bl.ser:make-transaction
                 :version 1
                 :inputs (vector (bl.ser:make-tx-in
                                  :previous-output (bl.ser:make-outpoint
                                                    :hash block-hash :index 0)
                                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                  :sequence #xffffffff))
                 :outputs (vector (bl.ser:make-tx-out
                                   :value 1000
                                   :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                              :initial-element #x51)))
                 :lock-time 0)))
    (bl.ser:make-bitcoin-block
     :header hdr :transactions (list coinbase dummy))))

(test perform-reorg-refuses-on-corrupt-disconnect-undo
  "A to-DISCONNECT spending block (tx-count > 1) whose undo is missing/corrupt
must make perform-reorg REFUSE with :corrupt-undo — not disconnect with empty
undo, which silently corrupts the UTXO set (removes the block's created outputs
but never restores the coins it spent). Coinbase-only disconnect blocks (empty
undo is legitimate) are exempt. The refusal is a DISTINCT keyword, not the
missing-block list."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "corrupt-undo")
     (let* ((genesis-entry (bl.store:get-block-index-entry chain-state genesis-hash))
            (a-hashes (make-test-chain-hashes #xA0 2))
            (a1-hash (first a-hashes)) (a2-hash (second a-hashes))
            (a1-block (make-reorg-test-block genesis-hash a1-hash 1))            ; coinbase-only
            (a2-block (%make-2tx-reorg-block a1-hash a2-hash 2))                 ; SPENDING (tx-count 2)
            (b-hashes (make-test-chain-hashes #xB0 2))
            (b1-hash (first b-hashes)) (b2-hash (second b-hashes))
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1))
            (b2-block (make-reorg-test-block b1-hash b2-hash 2)))
       ;; Build the ACTIVE chain genesis -> A1 -> A2 by hand so A2 is a spending
       ;; block with NO undo stored (the corruption we're modelling). Then a
       ;; competing fork B1 -> B2.
       (dolist (blk (list a1-block a2-block b1-block b2-block))
         (bl.store:store-block block-store blk))
       (let* ((a1-entry (bl.store:make-block-index-entry
                         :hash a1-hash :height 1 :prev-entry genesis-entry :chain-work 100
                         :status :valid
                         :header (bl.ser:bitcoin-block-header a1-block)))
              (_ (bl.store:add-block-index-entry chain-state a1-entry))
              (a2-entry (bl.store:make-block-index-entry
                         :hash a2-hash :height 2 :prev-entry a1-entry :chain-work 200
                         :status :valid
                         :header (bl.ser:bitcoin-block-header a2-block)))
              (__ (bl.store:add-block-index-entry chain-state a2-entry))
              (b1-entry (bl.store:make-block-index-entry
                         :hash b1-hash :height 1 :prev-entry genesis-entry :chain-work 150
                         :status :header-valid
                         :header (bl.ser:bitcoin-block-header b1-block)))
              (___ (bl.store:add-block-index-entry chain-state b1-entry))
              (b2-entry (bl.store:make-block-index-entry
                         :hash b2-hash :height 2 :prev-entry b1-entry :chain-work 300
                         :status :header-valid
                         :header (bl.ser:bitcoin-block-header b2-block))))
         (declare (ignore _ __ ___))
         (bl.store:add-block-index-entry chain-state b2-entry)
         (bl.store:update-chain-tip chain-state a2-hash 2)
         ;; Ensure no undo exists for A2 (the corruption).
         (clear-undo-cache)
         (multiple-value-bind (ok detail)
             (bl.val:perform-reorg
              chain-state block-store utxo-set a2-entry b2-entry)
           (is (null ok))                                   ; refused
           (is (eq detail :corrupt-undo))                   ; distinct keyword, NOT a missing list
           ;; No mutation on a refused reorg — tip still A2.
           (is (= 2 (bl.store:current-height chain-state)))
           (is (equalp a2-hash (bl.store:best-block-hash chain-state))))))
     (clear-undo-cache))))

;;;; Reorg mempool bulk re-add (cluster mempool P8 — Core
;;;; MaybeUpdateMempoolForReorg, validation.cpp:294-389)

(test reorg-readd-bulk-bypass-limits
  "readd-disconnected-txs-to-mempool: a ZERO-fee disconnected tx re-enters
(bypass_limits skips the fee floor, Core validation.cpp:945) and is wired to
its pre-existing pool child; a disconnected tx whose inputs are gone on the
new chain is dropped and its pool spender removed with it (Core
removeRecursive, validation.cpp:317-321)."
  (multiple-value-bind (utxo-set mempool chain-state funding)
      (make-package-fixture)
    (let* ((graph (bl.mp:mempool-graph mempool))
           ;; dtx: spends the confirmed funding output, paying ZERO fee.
           (dtx (%pkg-tx funding 0 100000000))
           (did (bl.ser:transaction-hash dtx))
           ;; Pool child of dtx (entered while dtx was confirmed).
           (child (%pkg-tx did 0 99990000))
           (cid (bl.ser:transaction-hash child))
           ;; dtx2: its input never existed on the new chain.
           (dtx2 (%pkg-tx (make-reorg-hash 4242) 0 500))
           (d2id (bl.ser:transaction-hash dtx2))
           ;; Pool spender of dtx2's output.
           (orphan (%pkg-tx d2id 0 400))
           (oid (bl.ser:transaction-hash orphan)))
      (is (eq :ok (%add-tx mempool child :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool orphan :fee 100 :height 200)))
      (bl.val::readd-disconnected-txs-to-mempool
       mempool (list dtx dtx2) utxo-set 200 chain-state)
      ;; dtx re-entered fee-free and was wired to its child.
      (is (bl.mp:mempool-has mempool did))
      (is (bl.mp:mempool-has mempool cid))
      (is (= 2 (length (bl.mp:txgraph-get-cluster
                        graph
                        (bl.mp:mempool-entry-graph-handle
                         (bl.mp:mempool-get mempool did))))))
      ;; dtx2 failed re-acceptance; its pool spender went with it.
      (is (not (bl.mp:mempool-has mempool d2id)))
      (is (not (bl.mp:mempool-has mempool oid)))
      (is (= 2 (bl.mp:mempool-count mempool)))
      (bl.mp::%mempool-graph-verify mempool))))

(test reorg-readd-drops-nonfinal-tx
  "A disconnected tx whose nLockTime the post-reorg chain no longer satisfies
is NOT re-added: bypass_limits skips the fee floor but never the finality /
BIP68 checks (Core PreChecks CheckFinalTxAtTip runs unconditionally,
validation.cpp:819). Previously the re-add path skipped finality entirely,
letting a premature tx re-enter the pool and get mined."
  (multiple-value-bind (utxo-set mempool chain-state funding)
      (make-package-fixture)
    (let* ((locked (bl.ser:make-transaction
                    :version 1
                    :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash funding :index 0)
                                     :script-sig (%p2sh-optrue-scriptsig)
                                     :sequence 0))   ; locktime enforced
                    :outputs (vector (bl.ser:make-tx-out
                                      :value 99990000
                                      :script-pubkey (p2sh-optrue-script-pubkey)))
                    :lock-time 500))                 ; height 500 > next block 201
           (lid (bl.ser:transaction-hash locked)))
      (bl.val::readd-disconnected-txs-to-mempool
       mempool (list locked) utxo-set 200 chain-state)
      (is (not (bl.mp:mempool-has mempool lid)))
      (is (= 0 (bl.mp:mempool-count mempool))))))

;;;; txindex across reorgs (Core parity: upsert on connect, no erase on
;;;; disconnect — index/txindex.cpp CustomAppend, index/base.h:136)

(defun %make-txindex-test-block (prev-hash block-hash height extra-txs)
  "Like make-reorg-test-block but appending EXTRA-TXS after the coinbase and
computing the real merkle root over all transactions."
  (let* ((script-sig (let ((s (make-array 4 :element-type '(unsigned-byte 8))))
                       (replace s block-hash :start2 0 :end2 4)
                       s))
         (coinbase-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                               :initial-element 0)
                                                          :index #xFFFFFFFF)
                                        :script-sig script-sig))
                       :outputs (vector (bl.ser:make-tx-out
                                         :value 5000000000
                                         :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                       :initial-element #x76)))
                       :lock-time 0))
         (txs (cons coinbase-tx extra-txs))
         (merkle-root (bl.val:compute-merkle-root
                       (mapcar #'bl.ser:transaction-hash txs)))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root merkle-root
                  :timestamp (+ 1231006505 (* height 600))
                  :bits #x1d00ffff
                  :nonce 0
                  :cached-hash block-hash)))
    (bl.ser:make-bitcoin-block :header header :transactions txs)))

(defun %optrue-spk ()
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))

(defun %empty-script ()
  (make-array 0 :element-type '(unsigned-byte 8)))

(test reorg-txindex-remined-and-stale-txs
  "Core txindex reorg semantics: (a) a tx disconnected by a reorg and RE-MINED
in the new chain stays indexed, pointing at its NEW block (connect upserts;
the old early-return + disconnect-time removal left it UNINDEXED); (b) a tx
only in the stale branch keeps its entry and resolves through the still-stored
stale block; (c) the startup catch-up scan is idempotent under upsert
semantics and re-points entries left stale by a crash."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "txidx-remined")
     (let* ((txdir (ensure-directories-exist
                    (merge-pathnames (format nil "test-txidx-reorg-~D/" (get-internal-real-time))
                                     (uiop:temporary-directory))))
            (txindex (bl.store:init-tx-index txdir))
            ;; A mature non-coinbase UTXO for T to spend (OP_TRUE, so the
            ;; full script validation in perform-reorg passes).
            (u-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE))
            (tx-t (bl.ser:make-transaction
                   :version 1
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output (bl.ser:make-outpoint
                                                      :hash u-txid :index 0)
                                    :script-sig (%empty-script)
                                    :sequence #xFFFFFFFF))
                   :outputs (vector (bl.ser:make-tx-out
                                     :value 100000 :script-pubkey (%optrue-spk)))
                   :lock-time 0))
            (t-txid (bl.ser:transaction-hash tx-t))
            (a-hashes (make-test-chain-hashes #xA6 2))
            (b-hashes (make-test-chain-hashes #xB6 3)))
       (bl.store:add-utxo utxo-set u-txid 0 100000 (%optrue-spk) 1)
       (unwind-protect
            ;; The index is reached through the connect hook over *NODE*'s
            ;; index list, as on a live node.
            (%with-index-node (chain-state block-store :tx-index txindex)
              ;; Chain A: A1 (coinbase only), A2 = coinbase + T.
              (let* ((a1 (make-reorg-test-block genesis-hash (first a-hashes) 1))
                     (a2 (%make-txindex-test-block (first a-hashes) (second a-hashes)
                                                   2 (list tx-t))))
                (bl.val:connect-block
                 a1 chain-state block-store utxo-set)
                (bl.val:connect-block
                 a2 chain-state block-store utxo-set))
              (is (= 2 (bl.store:current-height chain-state)))
              (let ((loc (bl.store:txindex-lookup txindex t-txid)))
                (is (equalp (second a-hashes)
                            (bl.store:tx-location-block-hash loc))))
              ;; Chain B (more work): B1, B2 = coinbase + T re-mined, B3.
              ;; B1/B2 are stored as a weaker chain; B3 triggers the reorg,
              ;; which validates B1-B3 fully (scripts included) and re-adds
              ;; their txs to the index in Phase C.
              (let* ((b1 (make-reorg-test-block genesis-hash (first b-hashes) 1))
                     (b2 (%make-txindex-test-block (first b-hashes) (second b-hashes)
                                                   2 (list tx-t)))
                     (b3 (make-reorg-test-block (second b-hashes) (third b-hashes) 3)))
                (bl.val:connect-block
                 b1 chain-state block-store utxo-set)
                (bl.val:connect-block
                 b2 chain-state block-store utxo-set)
                (bl.val:connect-block
                 b3 chain-state block-store utxo-set))
              (is (= 3 (bl.store:current-height chain-state)))
              (is (equalp (third b-hashes) (bl.store:best-block-hash chain-state)))
              ;; (a) T re-mined: indexed at the NEW block.
              (let ((loc (bl.store:txindex-lookup txindex t-txid)))
                (is (not (null loc)))
                (when loc
                  (is (equalp (second b-hashes)
                              (bl.store:tx-location-block-hash loc)))
                  (is (= 1 (bl.store:tx-location-tx-position loc)))))
              ;; (b) A2's coinbase exists only in the stale branch: still
              ;; indexed at A2 and resolvable through the stored stale block.
              (let* ((a2 (bl.store:get-block block-store (second a-hashes)))
                     (a2-cb (first (bl.ser:bitcoin-block-transactions a2)))
                     (a2-cb-id (bl.ser:transaction-hash a2-cb))
                     (loc (bl.store:txindex-lookup txindex a2-cb-id)))
                (is (not (null loc)))
                (when loc
                  (is (equalp (second a-hashes)
                              (bl.store:tx-location-block-hash loc)))
                  ;; The stale block body is still on disk, so the lookup
                  ;; resolves end-to-end (Core keeps stale block data too).
                  (is (not (null a2)))))
              ;; (c1) Catch-up scan is idempotent: nothing re-appended.
              ;; TX-INDEX-ENTRY-COUNT was an accessor on the in-memory txid
              ;; table; the index is now LevelDB-backed (GA9 S2-13) and the
              ;; observable equivalent is TXINDEX-COUNT. Idempotence is the
              ;; property being tested either way.
              (let ((entries-before (bl.store:txindex-count txindex)))
                (is (= 0 (bl.store:build-tx-index
                          txindex chain-state block-store)))
                (is (= entries-before
                       (bl.store:txindex-count txindex))))
              ;; (c2) A stale mapping is re-pointed by a FULL scan: force T
              ;; back to A2, then rescan from genesis — the verified per-block
              ;; check sees B2's last tx pointing elsewhere and re-indexes B2.
              ;; :from-genesis is required now that the ordinary startup scan
              ;; resumes from the best-indexed marker: arbitrary damage below
              ;; that marker is not something resuming can detect (nor can
              ;; Core's, which also resumes from its locator), so repairing it
              ;; is an explicit request rather than a cost paid every start.
              (bl.store:txindex-add txindex t-txid (second a-hashes) 1)
              (is (= 0 (bl.store:build-tx-index
                        txindex chain-state block-store))
                  "the resuming scan must do nothing when the marker is at the tip")
              (is (plusp (bl.store:build-tx-index
                          txindex chain-state block-store :from-genesis t)))
              (let ((loc (bl.store:txindex-lookup txindex t-txid)))
                (is (equalp (second b-hashes)
                            (bl.store:tx-location-block-hash loc)))))
         (bl.store:close-tx-index txindex)
         (ignore-errors (delete-file (merge-pathnames "txindex.dat" txdir)))
         (clear-undo-cache))))))

(test txindex-marker-rewinds-to-the-parent-on-disconnect
  "Core BaseIndex::Rewind moves the index's locator back to the fork when
blocks are disconnected; ours moved nothing, so after an invalidateblock the
marker named a block above the tip and the next start took
:height-above-tip -> a rescan from genesis. The disconnect hook now reaches
the txindex: when the marker names the disconnected block it steps back to
that block's parent (walked tip-first, it ends at the fork); a marker that
names some other block is left alone."
  (let* ((txdir (ensure-directories-exist
                 (merge-pathnames (format nil "test-txidx-rewind-~D/" (get-internal-real-time))
                                  (uiop:temporary-directory))))
         (txindex (bl.store:init-tx-index txdir))
         (hashes (make-test-chain-hashes #xC1 2))
         (b1 (make-reorg-test-block (make-reorg-hash 0) (first hashes) 1))
         (b2 (make-reorg-test-block (first hashes) (second hashes) 2)))
    (unwind-protect
         (progn
           (bl.store:txindex-set-best-block txindex (second hashes))
           ;; Marker names another block: untouched.
           (bl.store:index-rewind-block txindex nil b1 (first hashes) 1)
           (is (equalp (second hashes) (bl.store:txindex-best-block txindex)))
           ;; Marker names the disconnected block: back to its parent.
           (bl.store:index-rewind-block txindex nil b2 (second hashes) 2)
           (is (equalp (first hashes) (bl.store:txindex-best-block txindex)))
           (bl.store:index-rewind-block txindex nil b1 (first hashes) 1)
           (is (equalp (make-reorg-hash 0) (bl.store:txindex-best-block txindex))))
      (bl.store:close-tx-index txindex)
      (uiop:delete-directory-tree txdir :validate t :if-does-not-exist :ignore))))

(test reorg-getrawtransaction-stale-block-core-semantics
  "getrawtransaction for a tx whose txindex entry points into a stale
(reorged-away) block matches Core TxToJSON (rpc/rawtransaction.cpp:58-86):
the tx IS returned, blockhash names the stale block, confirmations is 0, and
no time/blocktime fields are present; a tx on the active chain gets normal
confirmations."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "txidx-rpc")
     (let* ((txdir (ensure-directories-exist
                    (merge-pathnames (format nil "test-txidx-rpc-~D/" (get-internal-real-time))
                                     (uiop:temporary-directory))))
            (txindex (bl.store:init-tx-index txdir))
            (a-hashes (make-test-chain-hashes #xA7 2))
            (b-hashes (make-test-chain-hashes #xB7 3)))
       (unwind-protect
            ;; The index is reached through the connect hook over *NODE*'s
            ;; index list, as on a live node.
            (%with-index-node (chain-state block-store :tx-index txindex)
              ;; Chain A then a longer chain B; A2's coinbase ends up stale-only.
              (dolist (spec (list (list genesis-hash (first a-hashes) 1)
                                  (list (first a-hashes) (second a-hashes) 2)
                                  (list genesis-hash (first b-hashes) 1)
                                  (list (first b-hashes) (second b-hashes) 2)
                                  (list (second b-hashes) (third b-hashes) 3)))
                (bl.val:connect-block
                 (apply #'make-reorg-test-block spec)
                 chain-state block-store utxo-set))
              (is (equalp (third b-hashes) (bl.store:best-block-hash chain-state)))
              (let ((node (bl:make-node :network :mainnet)))
                (setf (bl:node-chain-state node) chain-state
                      (bl:node-block-store node) block-store
                      (bl:node-utxo-set node) utxo-set
                      (bl:node-tx-index node) txindex
                      (bl:node-mempool node) (bl.mp:make-mempool))
                ;; Stale-branch tx: found, blockhash = stale block,
                ;; confirmations 0, no time/blocktime (Core pushes them only
                ;; for active-chain blocks).
                (let* ((a2 (bl.store:get-block block-store (second a-hashes)))
                       (a2-cb-id (bl.ser:transaction-hash
                                  (first (bl.ser:bitcoin-block-transactions a2))))
                       (r (bl.rpc::rpc-getrawtransaction
                           node (list (bl.rpc:hash-to-hex a2-cb-id) 1))))
                  (is (consp r))
                  (is (string= (bl.rpc:hash-to-hex (second a-hashes))
                               (cdr (assoc "blockhash" r :test #'string=))))
                  (is (eql 0 (cdr (assoc "confirmations" r :test #'string=))))
                  (is (null (assoc "time" r :test #'string=)))
                  (is (null (assoc "blocktime" r :test #'string=))))
                ;; Active-chain tx: normal confirmations (tip 3, B2 at 2 -> 2).
                (let* ((b2 (bl.store:get-block block-store (second b-hashes)))
                       (b2-cb-id (bl.ser:transaction-hash
                                  (first (bl.ser:bitcoin-block-transactions b2))))
                       (r (bl.rpc::rpc-getrawtransaction
                           node (list (bl.rpc:hash-to-hex b2-cb-id) 1))))
                  (is (string= (bl.rpc:hash-to-hex (second b-hashes))
                               (cdr (assoc "blockhash" r :test #'string=))))
                  (is (eql 2 (cdr (assoc "confirmations" r :test #'string=)))))))
         (bl.store:close-tx-index txindex)
         (ignore-errors (delete-file (merge-pathnames "txindex.dat" txdir)))
         (clear-undo-cache))))))

;;;; Wave 8A: recent-rejects reset on EVERY tip advance (not just reorgs)

(test tip-advance-clears-recent-rejects
  "Connecting a block that plainly extends the active tip clears the
recent-rejects filter — Core resets it on EVERY active tip change
(ActiveTipChange, net_processing.cpp:2045-2059 ->
txdownloadman_impl.cpp:92-96), because cached failures like non-final,
too-low-fee, or missing-inputs can become valid at the next block.
Previously only the reorg path cleared it."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "wave8-rejects-clear")
     (let ((rejects (bl:make-rejects-filter 100))
           (cached (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 77)))
       (bl:add-recent-reject rejects cached)
       (is-true (bl:recent-reject-p rejects cached))
       ;; Plain tip extension: genesis -> B1 (no reorg involved).
       (let* ((b1-hash (first (make-test-chain-hashes #xE8 1)))
              (b1 (make-reorg-test-block genesis-hash b1-hash 1)))
         (bl.val:connect-block
          b1 chain-state block-store utxo-set :recent-rejects rejects)
         (is (= 1 (bl.store:current-height chain-state)))
         (is (equalp b1-hash (bl.store:best-block-hash chain-state))))
       (is-false (bl:recent-reject-p rejects cached))
       ;; And the filter still works after the reset.
       (bl:add-recent-reject rejects cached)
       (is-true (bl:recent-reject-p rejects cached)))
     (clear-undo-cache))))

;;;; Wave 9C: removeForReorg — re-filter PRE-EXISTING entries after a reorg
;;;; (Core CTxMemPool::removeForReorg, txmempool.cpp:360-386, driven by
;;;; filter_final_and_mature, validation.cpp:334-385)

(test reorg-refilter-drops-nonfinal-preexisting-entry
  "After a reorg the pool's PRE-EXISTING entries are re-filtered: an entry
whose absolute locktime the new (shorter) chain no longer satisfies is
removed WITH its descendants — the re-add loop only vets the disconnected
blocks' txs, never what already sat in the pool."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* (;; LOCKED entered the pool while the tip was high enough; the
           ;; reorg leaves the tip at 200, so locktime 350 > next block 201.
           (locked (bl.ser:make-transaction
                    :version 1
                    :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash funding :index 0)
                                     :script-sig (%p2sh-optrue-scriptsig)
                                     :sequence 0))   ; locktime enforced
                    :outputs (vector (bl.ser:make-tx-out
                                      :value 99990000
                                      :script-pubkey (p2sh-optrue-script-pubkey)))
                    :lock-time 350))
           (lid (bl.ser:transaction-hash locked))
           ;; a pool child of the locked tx: removed as a descendant
           (child (%pkg-tx lid 0 99980000))
           (cid (bl.ser:transaction-hash child))
           ;; an unrelated, final pool tx: stays
           (funding2 (make-reorg-hash 4310))
           (ok-tx (%pkg-tx funding2 0 99990000))
           (okid (bl.ser:transaction-hash ok-tx)))
      (bl.store:add-utxo utxo-set funding2 0 100000000
                                     (p2sh-optrue-script-pubkey) 1 :coinbase nil)
      (is (eq :ok (%add-tx mempool locked :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool child :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool ok-tx :fee 10000 :height 200)))
      ;; No disconnected txs at all — the filter must still run.
      (bl.val::readd-disconnected-txs-to-mempool
       mempool '() utxo-set 200 chain-state)
      (is (not (bl.mp:mempool-has mempool lid)))
      (is (not (bl.mp:mempool-has mempool cid)))
      (is (bl.mp:mempool-has mempool okid))
      (bl.mp::%mempool-graph-verify mempool))))

(test reorg-refilter-drops-immature-coinbase-spend
  "A pool entry spending a coinbase that the reorg made immature again is
removed (Core filter_final_and_mature, validation.cpp:368-379): maturity is
COINBASE_MATURITY at the NEXT block. A spend of a still-mature coinbase
stays."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (declare (ignore funding))
    (let* ((cb-young (make-reorg-hash 4320))     ; coinbase @ 150: age 51 < 100
           (cb-old (make-reorg-hash 4321))       ; coinbase @ 90: age 111 >= 100
           (spend-young (%pkg-tx cb-young 0 99990000))
           (yid (bl.ser:transaction-hash spend-young))
           (spend-old (%pkg-tx cb-old 0 99990000))
           (oid (bl.ser:transaction-hash spend-old)))
      (bl.store:add-utxo utxo-set cb-young 0 100000000
                                     (p2sh-optrue-script-pubkey) 150 :coinbase t)
      (bl.store:add-utxo utxo-set cb-old 0 100000000
                                     (p2sh-optrue-script-pubkey) 90 :coinbase t)
      (is (eq :ok (%add-tx mempool spend-young :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool spend-old :fee 10000 :height 200)))
      ;; New tip 200 -> spend height 201: 201-150 = 51 < 100 immature;
      ;; 201-90 = 111 mature.
      (bl.val::readd-disconnected-txs-to-mempool
       mempool '() utxo-set 200 chain-state)
      (is (not (bl.mp:mempool-has mempool yid)))
      (is (bl.mp:mempool-has mempool oid)))))

(test reorg-refilter-drops-bip68-nonfinal-entry
  "A pool entry whose BIP68 height lock the new chain no longer satisfies is
removed: Core re-tests lockpoints against the new tip
(validation.cpp:350-366). A lock already deep enough stays."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (declare (ignore funding))
    (let* ((coin1 (make-reorg-hash 4330))
           (coin2 (make-reorg-hash 4331))
           ;; 100-block relative lock on a coin confirmed at 150: at the new
           ;; tip 200 (spend height 201) only 51 blocks deep -> non-final.
           (locked (%pkg-tx coin1 0 99990000 :sequence 100))
           (lid (bl.ser:transaction-hash locked))
           ;; 40-block lock on the same depth -> satisfied.
           (ok-tx (%pkg-tx coin2 0 99990000 :sequence 40))
           (okid (bl.ser:transaction-hash ok-tx)))
      (bl.store:add-utxo utxo-set coin1 0 100000000
                                     (p2sh-optrue-script-pubkey) 150 :coinbase nil)
      (bl.store:add-utxo utxo-set coin2 0 100000000
                                     (p2sh-optrue-script-pubkey) 150 :coinbase nil)
      (is (eq :ok (%add-tx mempool locked :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool ok-tx :fee 10000 :height 200)))
      (bl.val::readd-disconnected-txs-to-mempool
       mempool '() utxo-set 200 chain-state)
      (is (not (bl.mp:mempool-has mempool lid)))
      (is (bl.mp:mempool-has mempool okid)))))

(test reorg-refilter-runs-after-readd
  "Ordering matches Core MaybeUpdateMempoolForReorg: re-add first, then the
re-filter — so a disconnected tx that is itself non-final under the new tip
is caught even though the filter, not the re-add validation, is what sees
the pool child it would strand. A re-added final tx survives the filter."
  (multiple-value-bind (utxo-set mempool chain-state funding) (make-package-fixture)
    (let* ((dtx (%pkg-tx funding 0 100000000))   ; zero-fee, final: re-adds
           (did (bl.ser:transaction-hash dtx)))
      (bl.val::readd-disconnected-txs-to-mempool
       mempool (list dtx) utxo-set 200 chain-state)
      ;; the re-added tx passed the filter too
      (is (bl.mp:mempool-has mempool did)))))

;;; ---------------------------------------------------------------------------
;;; Deep-reorg download-path regression (fix-deep-reorg-sequencing)
;;;
;;; A block that does NOT extend the active tip must be accepted CONTEXT-FREE
;;; and stored, then connected by perform-reorg fork-to-tip. Tip-validating
;;; such a fork block against the active UTXO set / height was the testnet4
;;; wedge: MISSING-INPUT (its inputs are on its own branch) or
;;; BAD-COINBASE-HEIGHT (its height is not tip+1), so it was rejected before
;;; storage and perform-reorg never received the branch. These reproduce the
;;; height case (regtest enforces BIP34 from h=1, so a fork block whose height
;;; differs from tip+1 fails the old tip-gate).
;;; ---------------------------------------------------------------------------

(defun %dr-mine-on (node spk)
  "Assemble + PoW-mine a block on NODE's current tip paying coinbase to SPK,
WITHOUT connecting it. Returns the mined block."
  (let ((block (bl.mining:assemble-full-block
                (bl:node-chain-state node)
                (bl:node-mempool node)
                :coinbase-script-pubkey spk)))
    (bl.mining:mine-block block)
    block))

(defun %dr-connect (node block)
  "Connect BLOCK into NODE (advances the tip / stores / reorgs)."
  (bl.val:connect-block
   block
   (bl:node-chain-state node)
   (bl:node-block-store node)
   (bl:node-utxo-set node)))

(test validate-block-context-free-only-skips-contextual
  "CONTEXT-FREE-ONLY returns success before the UTXO/height-dependent checks
(so a fork block validated at the wrong tip height is not spuriously rejected),
while the pure block-integrity checks still run."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "cfo"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (spk (p2sh-optrue-script-pubkey))
          (now (bl.ser:get-unix-time))
          ;; A valid, mined height-1 block on genesis.
          (block (%dr-mine-on node spk)))
     ;; Full validation at the block's real height (1) succeeds.
     (is-true (bl.val:validate-block block cs utxo 1 now))
     ;; Full validation at a WRONG height fails BIP34 (BAD-COINBASE-HEIGHT):
     ;; this is exactly what the old download path did to a fork block.
     (multiple-value-bind (valid error)
         (bl.val:validate-block block cs utxo 9 now)
       (is (null valid))
       (is (eq :bad-coinbase-height error)))
     ;; CONTEXT-FREE-ONLY at the same wrong height succeeds — the height check
     ;; is deferred to perform-reorg.
     (is-true (bl.val:validate-block
               block cs utxo 9 now :context-free-only t))
     ;; But a genuine context-free failure (merkle mismatch) is still caught
     ;; under CONTEXT-FREE-ONLY. Corrupt the header's merkle root; skip-pow so
     ;; the header check (which never looks at merkle) passes and we reach the
     ;; block-level merkle check.
     (let ((bad (bl.ser:make-bitcoin-block
                 :header (copy-structure
                          (bl.ser:bitcoin-block-header block))
                 :transactions (bl.ser:bitcoin-block-transactions
                                block))))
       (setf (bl.ser:block-header-merkle-root
              (bl.ser:bitcoin-block-header bad))
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
       (multiple-value-bind (valid error)
           (bl.val:validate-block
            bad cs utxo 1 now :context-free-only t :skip-pow t)
         (is (null valid))
         (is (eq :bad-merkle-root error)))))))

(test deep-reorg-fork-blocks-accepted-and-reorged
  "A competing longer branch fed to ACCEPT-DOWNLOADED-BLOCK while the node's tip
is already on the shorter branch: every fork block must be stored (not rejected
by tip-validation), and the branch must win via reorg once it outweighs the
active chain. Old code rejected the fork blocks (BAD-COINBASE-HEIGHT, since
their height != tip+1) and never reorged."
  (with-network (:regtest)
   (let* ((spk-a (p2sh-optrue-script-pubkey))
          ;; A distinct coinbase spk so branch B's blocks differ from A's.
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))  ; bare OP_TRUE
          ;; Throwaway node to build branch B (4 blocks on genesis), capturing
          ;; the block objects.
          (nb (regtest-node-fixture "dr-b"))
          (b-blocks (loop repeat 4
                          for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk)
                          collect blk))
          ;; Main node: branch A, 3 blocks on the same genesis.
          (na (regtest-node-fixture "dr-a"))
          (csa (bl:node-chain-state na))
          (utxoa (bl:node-utxo-set na))
          (storea (bl:node-block-store na)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))
     (is (= 3 (bl.store:current-height csa)))
     (let ((a-tip (bl.store:best-block-hash csa)))
       ;; Feed B1: it forks at genesis, so its height (1) != tip+1 (4). The old
       ;; tip-gate rejected this as BAD-COINBASE-HEIGHT; now it is stored as a
       ;; weaker side block and the active tip stays on A.
       (let ((b1-hash (bl.ser:block-header-hash
                       (bl.ser:bitcoin-block-header
                        (first b-blocks)))))
         (multiple-value-bind (valid error)
             (bl.net::accept-downloaded-block
              (first b-blocks) csa utxoa storea)
           (is-true valid)
           (is (null error)))
         (is-true (bl.store:get-block-index-entry csa b1-hash))
         (is (equalp a-tip (bl.store:best-block-hash csa)))
         (is (= 3 (bl.store:current-height csa))))
       ;; Feed B2, B3 (still weaker/equal — A stays active).
       (bl.net::accept-downloaded-block
        (second b-blocks) csa utxoa storea)
       (bl.net::accept-downloaded-block
        (third b-blocks) csa utxoa storea)
       (is (equalp a-tip (bl.store:best-block-hash csa)))
       ;; Feed B4 — branch B now outweighs A (4 > 3): reorg onto B.
       (bl.net::accept-downloaded-block
        (fourth b-blocks) csa utxoa storea)
       (let ((b4-hash (bl.ser:block-header-hash
                       (bl.ser:bitcoin-block-header
                        (fourth b-blocks)))))
         (is (= 4 (bl.store:current-height csa)))
         (is (equalp b4-hash (bl.store:best-block-hash csa)))
         ;; UTXO set is now branch B's 4 coinbases.
         (is (= 4 (bl.store:utxo-count utxoa))))))))

(test context-free-only-runs-checktransaction
  "F2: CONTEXT-FREE-ONLY now runs Core CheckBlock's per-tx CheckTransaction
(and legacy-sigop budget), so a structurally-invalid fork block (here a tx
with duplicate inputs, CVE-2018-17144) is rejected before storage rather than
being stored and only caught later in perform-reorg. A well-formed block still
passes context-free."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "cfo-ct"))
          (cs (bl:node-chain-state node))
          (utxo (bl:node-utxo-set node))
          (now (bl.ser:get-unix-time))
          (block (%dr-mine-on node (p2sh-optrue-script-pubkey)))
          (coinbase (first (bl.ser:bitcoin-block-transactions block))))
     ;; Baseline: the valid coinbase-only block passes context-free.
     (is-true (bl.val:validate-block
               block cs utxo 1 now :context-free-only t :skip-header t))
     ;; Build a non-coinbase tx with two identical inputs (duplicate outpoint).
     (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
            (op (bl.ser:make-outpoint
                 :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)
                 :index 0))
            (in (bl.ser:make-tx-in
                 :previous-output op :script-sig empty :sequence #xFFFFFFFF))
            (out (bl.ser:make-tx-out
                  :value 1000 :script-pubkey (coerce '(#x51) '(vector (unsigned-byte 8)))))
            (dup (bl.ser:make-transaction
                  :version 1 :inputs (vector in in) :outputs (vector out) :lock-time 0))
            (txs (list coinbase dup))
            ;; Correct merkle root over the two txs so the malleation check
            ;; passes and we reach the per-tx CheckTransaction.
            (root (bl.val:compute-merkle-root
                   (mapcar #'bl.ser:transaction-hash txs)))
            (hdr (copy-structure (bl.ser:bitcoin-block-header block)))
            (bad (progn
                   (setf (bl.ser:block-header-merkle-root hdr) root)
                   (bl.ser:make-bitcoin-block :header hdr :transactions txs))))
       (multiple-value-bind (valid error)
           (bl.val:validate-block
            bad cs utxo 1 now :context-free-only t :skip-header t)
         (is (null valid))
         (is (eq :duplicate-inputs error)))))))

(test connect-block-surfaces-missing-fork-blocks-on-refused-reorg
  "When connect-block triggers a reorg that must be REFUSED because intermediate
fork blocks are absent from the store, it returns the missing (hash . height)
list as its second value, so the download path (accept-downloaded-block) can
re-queue them. Regression for the testnet4 deep-reorg wedge: the compact/relay
path swallowed this signal and never re-requested the sub-tip fork blocks."
  (with-network (:regtest)
   (let* ((spk-a (p2sh-optrue-script-pubkey))
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))
          ;; Branch B (4 blocks) built on a throwaway node; capture the blocks.
          (nb (regtest-node-fixture "requeue-b"))
          (b-blocks (loop repeat 4 for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk) collect blk))
          ;; Main node: capture genesis, then branch A (3 blocks). Tip = A3.
          (na (regtest-node-fixture "requeue-a"))
          (csa (bl:node-chain-state na))
          (utxoa (bl:node-utxo-set na))
          (storea (bl:node-block-store na))
          (genesis-hash (bl.store:best-block-hash csa)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))
     (is (= 3 (bl.store:current-height csa)))
     ;; Add branch B's HEADERS (index entries for B1-B3) to na WITHOUT their
     ;; bodies, so a reorg toward B can be attempted but must refuse for the
     ;; missing bodies. B4's entry + body are added by connect-block itself.
     (let ((prev (bl.store:get-block-index-entry csa genesis-hash)))
       (loop for blk in (subseq b-blocks 0 3)
             for h from 1 to 3
             do (let* ((hdr (bl.ser:bitcoin-block-header blk))
                       (bhash (bl.ser:block-header-hash hdr))
                       (work (bl.store:calculate-chain-work
                              (bl.ser:block-header-bits hdr)
                              (bl.store:block-index-entry-chain-work prev)))
                       (e (bl.store:make-block-index-entry
                           :hash bhash :height h :header hdr
                           :prev-entry prev :chain-work work :status :valid)))
                  (bl.store:add-block-index-entry csa e)
                  (setf prev e))))
     ;; connect-block B4: chain-work 4 > active A3's 3, so it triggers a reorg
     ;; toward B4, which refuses because B1-B3 bodies aren't stored.
     (multiple-value-bind (entry outcome)
         (bl.val:connect-block (fourth b-blocks) csa storea utxoa)
       (declare (ignore entry))
       ;; outcome = (reorg-ok detail); refused-for-missing -> (nil <list>).
       (is (null (first outcome)))
       (is (consp (second outcome)))
       ;; The three missing sub-tip fork blocks B1-B3.
       (is (= 3 (length (second outcome))))
       ;; Every element is a (hash . height) cons.
       (is (every (lambda (c) (and (consp c) (integerp (cdr c)))) (second outcome)))
       ;; Reorg refused -> active tip unchanged (still on branch A).
       (is (= 3 (bl.store:current-height csa)))))))

(test find-blocks-to-download-only-on-peer-chain
  "Layer-5 per-peer download: find-blocks-to-download-for-peer returns blocks on
the PEER'S chain only. A peer whose best-known block is on fork B yields fork-B
blocks to download and never fork-A blocks; a peer at our own tip yields nothing.
This is why the node downloads the chains its peers actually serve instead of
fixating on a fork no connected peer has."
  (with-network (:regtest)
   (let* ((spk-a (p2sh-optrue-script-pubkey))
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))
          (nb (regtest-node-fixture "l5-b"))
          (b-blocks (loop repeat 5 for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk) collect blk))
          (na (regtest-node-fixture "l5-a"))
          (csa (bl:node-chain-state na))
          (storea (bl:node-block-store na))
          (genesis-hash (bl.store:best-block-hash csa)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))   ; branch A, tip A3 (h3)
     ;; Add branch B (5 blocks, more work) HEADERS to na, no bodies.
     (let ((prev (bl.store:get-block-index-entry csa genesis-hash)))
       (loop for blk in b-blocks for h from 1 to 5
             do (let* ((hdr (bl.ser:bitcoin-block-header blk))
                       (bhash (bl.ser:block-header-hash hdr))
                       (work (bl.store:calculate-chain-work
                              (bl.ser:block-header-bits hdr)
                              (bl.store:block-index-entry-chain-work prev)))
                       (e (bl.store:make-block-index-entry
                           :hash bhash :height h :header hdr
                           :prev-entry prev :chain-work work :status :header-valid)))
                  (bl.store:add-block-index-entry csa e)
                  (setf prev e))))
     (let* ((ctx (bl.net::make-ibd))
            (b-hashes (mapcar (lambda (blk)
                                (bl.ser:block-header-hash
                                 (bl.ser:bitcoin-block-header blk)))
                              b-blocks))
            ;; Both peers advertise NODE_NETWORK|NODE_WITNESS: with segwit active
            ;; (regtest activates at genesis) the per-peer walk's witness guard
            ;; would otherwise skip a non-witness peer entirely.
            (svc (logior bl.ser:+node-network+
                         bl.ser:+node-witness+))
            (peer-b (bl.net:make-peer :address "1.2.3.4:18333"
                                                        :services svc))
            (peer-tip (bl.net:make-peer :address "5.6.7.8:18333"
                                                          :services svc)))
       (setf (bl.net:peer-best-known-block-hash peer-b) (fifth b-hashes)
             (bl.net:peer-best-known-block-hash peer-tip)
             (bl.store:best-block-hash csa))
       (let ((bl.net:*ibd-context* ctx))
         ;; Peer on fork B: returns exactly the 5 fork-B blocks, none of fork A.
         (let ((got (bl.net::find-blocks-to-download-for-peer
                     peer-b csa storea 16)))
           (is (= 5 (length got)))
           (is (every (lambda (h) (member h b-hashes :test #'equalp)) got)))
         ;; Peer at our own tip (A3): nothing more-work to fetch.
         (is (null (bl.net::find-blocks-to-download-for-peer
                    peer-tip csa storea 16))))))))

(test find-blocks-to-download-service-flag-guards
  "Layer-5 per-peer download service guards (Core FindNextBlocks): with segwit
active (regtest activates it at genesis) a peer that does NOT advertise
NODE_WITNESS yields nothing — from it we could only ever get witness-stripped
blocks. A limited (pruned) peer — NODE_NETWORK_LIMITED set, NODE_NETWORK clear —
is asked only for blocks within NODE_NETWORK_LIMITED_MIN_BLOCKS-2 (=286) of its
best-known height; deeper blocks are skipped, shallower ones still fetched. A
full NODE_NETWORK|NODE_WITNESS peer gets the whole range. Pure synthetic
index/peer setup, no Bitcoin Core vectors."
  (with-network (:regtest)
   (let* ((store (bl.store:make-block-store
                  :base-path #p"/nonexistent/l5-svc-guards/"))
          (cs (bl.store:make-chain-state))
          (tip-height 300)
          ;; Genesis is our active tip (height 0); the peer chain is a 300-block
          ;; more-work extension above it whose bodies we lack (not on disk).
          (genesis (bl.store:make-block-index-entry
                    :hash (make-reorg-hash 0) :height 0 :prev-entry nil
                    :chain-work 1 :status :valid))
          (fork-hashes (make-array (1+ tip-height) :initial-element nil)))
     (bl.store:add-block-index-entry cs genesis)
     (bl.store:update-chain-tip cs (make-reorg-hash 0) 0)
     ;; f1..f300: unique ids offset by 1000, each more-work than the last, all
     ;; header-valid and absent from disk so the walk treats them as lacking.
     (let ((prev genesis))
       (loop for h from 1 to tip-height
             for hash = (make-reorg-hash (+ 1000 h))
             for e = (bl.store:make-block-index-entry
                      :hash hash :height h :header nil
                      :prev-entry prev :chain-work (+ 100 h) :status :header-valid)
             do (setf (aref fork-hashes h) hash)
                (bl.store:add-block-index-entry cs e)
                (setf prev e)))
     (let* ((tip-hash (make-reorg-hash (+ 1000 tip-height)))
            (ctx (bl.net::make-ibd))
            (nowit (bl.net:make-peer
                    :address "1.0.0.1:18444"
                    :services bl.ser:+node-network+))      ; no witness
            (limited (bl.net:make-peer
                      :address "2.0.0.2:18444"
                      :services (logior bl.ser:+node-network-limited+
                                        bl.ser:+node-witness+)))
            (full (bl.net:make-peer
                   :address "3.0.0.3:18444"
                   :services (logior bl.ser:+node-network+
                                     bl.ser:+node-witness+))))
       (dolist (p (list nowit limited full))
         (setf (bl.net:peer-best-known-block-hash p) tip-hash))
       (let ((bl.net:*ibd-context* ctx))
         ;; (a) No-witness peer: segwit active at every height -> nothing at all.
         (is (null (bl.net::find-blocks-to-download-for-peer
                    nowit cs store 512)))
         ;; (c) Full peer: the whole 300-block range, shallowest (f1) first.
         (let ((got (bl.net::find-blocks-to-download-for-peer
                     full cs store 512)))
           (is (= tip-height (length got)))
           (is (equalp (aref fork-hashes 1) (first got))))
         ;; (b) Limited peer: best-known height 300, so heights 1..14
         ;; (300-h >= 286) are skipped; the shallowest fetched is f15.
         (let ((got (bl.net::find-blocks-to-download-for-peer
                     limited cs store 512)))
           (is (equalp (aref fork-hashes 15) (first got)))
           (is (= (- tip-height 14) (length got)))
           (is (not (member (aref fork-hashes 14) got :test #'equalp)))
           (is (not (member (aref fork-hashes 1) got :test #'equalp)))))))))

(test deep-reorg-candidate-activates-fork-winning-above-tip-plus-1
  "THE deep-reorg livelock regression (2026-07-22 liveness review): a fork
whose cumulative work overtakes the active tip only ABOVE tip+1. The fork's
tip+1 block reads as weaker on arrival (stored, no reorg), the decisive
blocks arrive out of order — pre-fix they sat in RAM only, perform-reorg
(all-or-nothing, disk-only) was never attempted, and the tip sat still
forever. Now: the out-of-order path persists them, records the outweighing
block as the pending reorg candidate, and the candidate retry (gated on
fork bodies complete on disk) performs the reorg.

Fork-B index works are hand-set so B's cumulative work crosses the tip's
only at B4 (equal-bits regtest blocks always cross exactly at tip+1, which
would let the ordinary tip+1 path preempt the scenario)."
  (with-network (:regtest)
   (let* ((spk-a (p2sh-optrue-script-pubkey))
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))
          (nb (regtest-node-fixture "drc-b"))
          (b-blocks (loop repeat 4 for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk) collect blk))
          (na (regtest-node-fixture "drc-a"))
          (csa (bl:node-chain-state na))
          (storea (bl:node-block-store na))
          (utxoa (bl:node-utxo-set na))
          (genesis-hash (bl.store:best-block-hash csa)))
     (dotimes (i 2) (%dr-connect na (%dr-mine-on na spk-a)))   ; branch A, tip A2
     (let* ((w1 (bl.store:block-index-entry-chain-work
                 (bl.store:get-block-at-height csa 1)))
            (w2 (bl.store:block-index-entry-chain-work
                 (bl.store:get-block-at-height csa 2)))
            (a2-hash (bl.store:best-block-hash csa))
            ;; Cumulative-work schedule for B: strictly increasing, below
            ;; the tip through B3 (so B3's tip+1 arrival stays weaker even
            ;; after adding one real block-work to B2's ENTRY work), crossing
            ;; at B4. activate-block recomputes the INCOMING block's work
            ;; from its header bits + the prev ENTRY's work, so B3's entry
            ;; work must exceed w1 for the B4 activation to outweigh w2.
            (b-works (list 1 2 (1+ w1) (1+ w2)))
            (b-hashes (mapcar (lambda (blk)
                                (bl.ser:block-header-hash
                                 (bl.ser:bitcoin-block-header blk)))
                              b-blocks)))
       ;; Add fork-B headers to na's index (bodies not yet delivered).
       (let ((prev (bl.store:get-block-index-entry csa genesis-hash)))
         (loop for blk in b-blocks for bw in b-works for h from 1
               do (let* ((hdr (bl.ser:bitcoin-block-header blk))
                         (e (bl.store:make-block-index-entry
                             :hash (bl.ser:block-header-hash hdr)
                             :height h :header hdr :prev-entry prev
                             :chain-work bw :status :header-valid)))
                    (bl.store:add-block-index-entry csa e)
                    (setf prev e))))
       (with-ibd-context
         (let ((ctx bl.net:*ibd-context*))
           ;; B4 arrives FIRST (out of order, above tip+1): persisted to
           ;; disk, recorded as reorg candidate — but gated (fork bodies
           ;; incomplete), so the tip must not move.
           (deliver-block (fourth b-blocks) csa utxoa storea :requested t)
           (is (bl.store:block-exists-p storea (fourth b-hashes)))
           (is (gethash (fourth b-hashes)
                        (bl.net::ibd-context-reorg-candidates ctx)))
           (is (equalp a2-hash (bl.store:best-block-hash csa)))
           ;; B1, B2 arrive (below tip): stored, fork still incomplete (B3
           ;; missing), so the candidate retry on each arrival still can't
           ;; fire — tip stays A2. This is exactly where the pre-fix node
           ;; livelocked (winning bodies present but no reorg attempted).
           (deliver-block (first b-blocks) csa utxoa storea :requested t)
           (deliver-block (second b-blocks) csa utxoa storea :requested t)
           (is (equalp a2-hash (bl.store:best-block-hash csa)))
           ;; B3 (tip+1, cumulatively weaker) completes B1..B3 on disk. Its
           ;; own activate-block stays :weaker-chain, but the candidate retry
           ;; it triggers now finds B4's fork complete and performs the reorg
           ;; eagerly (Core-style: ActivateBestChain after every accepted
           ;; block) -> tip = B4, candidate consumed.
           (deliver-block (third b-blocks) csa utxoa storea :requested t)
           (is (= 4 (bl.store:current-height csa)))
           (is (equalp (fourth b-hashes) (bl.store:best-block-hash csa)))
           (is (null (gethash (fourth b-hashes)
                              (bl.net::ibd-context-reorg-candidates
                               ctx))))))))))

(test drain-connects-persisted-block-after-ram-drop
  "Drain's disk fallback: an out-of-order block is persisted on receipt;
even if its RAM queue slot is lost (cap-drop, fork collision, restart),
drain-block-queue connects it from disk via disk-blocks-above-tip once the
tip reaches its parent — pre-fix the block was silently re-downloaded (or,
post-persist without the fallback, stranded on disk forever)."
  (with-network (:regtest)
   (let* ((spk-a (p2sh-optrue-script-pubkey))
          (na (regtest-node-fixture "ddf-a"))
          (nb (regtest-node-fixture "ddf-b"))
          (csa (bl:node-chain-state na))
          (storea (bl:node-block-store na))
          (utxoa (bl:node-utxo-set na))
          (a1 (%dr-mine-on na spk-a)))
     (%dr-connect na a1) (%dr-connect nb a1)
     (let ((a2 (%dr-mine-on na spk-a)))
       (%dr-connect na a2) (%dr-connect nb a2))          ; both tips at A2
     (let* ((a3 (%dr-mine-on nb spk-a))
            (a4 (progn (%dr-connect nb a3) (%dr-mine-on nb spk-a)))
            (h4 (bl.ser:block-header-hash
                 (bl.ser:bitcoin-block-header a4))))
       ;; Register A3/A4 headers on na (real chain-work).
       (let ((prev (bl.store:get-block-index-entry
                    csa (bl.store:best-block-hash csa))))
         (dolist (blk (list a3 a4))
           (let* ((hdr (bl.ser:bitcoin-block-header blk))
                  (e (bl.store:make-block-index-entry
                      :hash (bl.ser:block-header-hash hdr)
                      :height (1+ (bl.store:block-index-entry-height prev))
                      :header hdr :prev-entry prev
                      :chain-work (bl.store:calculate-chain-work
                                   (bl.ser:block-header-bits hdr)
                                   (bl.store:block-index-entry-chain-work prev))
                      :status :header-valid)))
             (bl.store:add-block-index-entry csa e)
             (setf prev e))))
       (with-ibd-context
         (let ((ctx bl.net:*ibd-context*))
           ;; A4 arrives out of order: persisted + RAM-queued + recorded.
           (deliver-block a4 csa utxoa storea)
           (is (bl.store:block-exists-p storea h4))
           (is (gethash 4 (bl.net:ibd-context-block-queue ctx)))
           ;; Simulate the RAM slot being lost (cap-drop / restart).
           (remhash 4 (bl.net:ibd-context-block-queue ctx))
           (setf (bl.net::ibd-context-block-queue-bytes ctx) 0)
           ;; A3 connects at tip+1; drain must then pull A4 from DISK.
           (deliver-block a3 csa utxoa storea)
           (is (= 4 (bl.store:current-height csa)))
           (is (equalp h4 (bl.store:best-block-hash csa)))
           ;; The consumed disk-map entry is gone.
           (is (null (gethash
                      4 (bl.net::ibd-context-disk-blocks-above-tip
                         ctx))))))))))

(test out-of-order-persist-gated-by-acceptblock
  "Case-C persist DoS gate (Core AcceptBlock, safety review Lens 3): an
UNSOLICITED out-of-order block is kept only if it outweighs the tip, sits
within +min-blocks-to-keep+ of it, and meets minimum chain work — else an
attacker fills disk with unsolicited far-ahead / low-work fork bodies. A
REQUESTED block always passes. Tests %out-of-order-block-acceptable-p directly."
  (with-network (:regtest)
   (let* ((cs (bl.store:make-chain-state))
          (%h (lambda (n) (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element n)))
          (g (bl.store:make-block-index-entry
              :hash (funcall %h 0) :height 0 :chain-work 0 :status :valid))
          (tip (bl.store:make-block-index-entry
                :hash (funcall %h 1) :height 1 :chain-work 100 :prev-entry g
                :status :valid)))
     (bl.store:add-block-index-entry cs g)
     (bl.store:add-block-index-entry cs tip)
     (bl.store:update-chain-tip cs (funcall %h 1) 1)
     (let ((more-work (bl.store:make-block-index-entry
                       :hash (funcall %h 2) :height 3 :chain-work 150 :status :header-valid))
           (less-work (bl.store:make-block-index-entry
                       :hash (funcall %h 3) :height 3 :chain-work 50 :status :header-valid))
           (too-far (bl.store:make-block-index-entry
                     :hash (funcall %h 4) :height 500 :chain-work 200 :status :header-valid)))
       ;; Unsolicited, less work than tip -> rejected.
       (is (null (bl.net::%out-of-order-block-acceptable-p
                  less-work 1 nil cs)))
       ;; Same block, REQUESTED -> accepted (gate lifted).
       (is (bl.net::%out-of-order-block-acceptable-p
            less-work 1 t cs))
       ;; Unsolicited, more work, within the window -> accepted.
       (is (bl.net::%out-of-order-block-acceptable-p
            more-work 1 nil cs))
       ;; Unsolicited, more work but > tip + min-blocks-to-keep ahead -> rejected.
       (is (null (bl.net::%out-of-order-block-acceptable-p
                  too-far 1 nil cs)))))))

(test reorg-candidate-set-prefers-completable-over-higher-work-gated
  "F1 (liveness review): a candidate SET, not a single sticky slot. A
higher-work fork whose bodies are INCOMPLETE (unobtainable) must not starve a
lower-work fork that IS complete — retry-best-reorg-candidate activates the
best COMPLETABLE target. Blocks are stored + candidates populated directly so
the retry, not eager arrival-time activation, is what performs the reorg."
  (with-network (:regtest)
   (let* ((spk-g (coerce '(#x51) '(vector (unsigned-byte 8))))       ; OP_TRUE
          (spk-h (coerce '(#x52) '(vector (unsigned-byte 8))))       ; OP_2 — distinct
          (spk-a (p2sh-optrue-script-pubkey))                                 ; distinct from both
          ;; Distinct coinbase scripts per fork so deterministic regtest mining
          ;; produces genuinely different blocks (same spk => identical hashes).
          (ng (regtest-node-fixture "cand-g"))          ; fork G, fully stored
          (g-blocks (loop repeat 3 for blk = (%dr-mine-on ng spk-g)
                          do (%dr-connect ng blk) collect blk))
          (nh (regtest-node-fixture "cand-h"))          ; fork H, only top stored
          (h-blocks (loop repeat 5 for blk = (%dr-mine-on nh spk-h)
                          do (%dr-connect nh blk) collect blk))
          (na (regtest-node-fixture "cand-a"))
          (csa (bl:node-chain-state na))
          (storea (bl:node-block-store na))
          (utxoa (bl:node-utxo-set na))
          (genesis-hash (bl.store:best-block-hash csa)))
     (dotimes (i 2) (%dr-connect na (%dr-mine-on na spk-a)))   ; tip A2
     (let* ((tip-work (bl.store:block-index-entry-chain-work
                       (bl.store:get-block-at-height csa 2)))
            (g-hash (bl.ser:block-header-hash
                     (bl.ser:bitcoin-block-header (third g-blocks))))
            (h-hash (bl.ser:block-header-hash
                     (bl.ser:bitcoin-block-header (fifth h-blocks)))))
       ;; G index: G2 entry work = tip-work, so activate-block recomputes
       ;; G3's work = tip-work + one block > tip (case 2 fires). Store ALL G
       ;; bodies on disk directly (no activation).
       (let ((prev (bl.store:get-block-index-entry csa genesis-hash)))
         (loop for blk in g-blocks for h from 1
               for w in (list 1 tip-work (1+ tip-work))
               do (let* ((hdr (bl.ser:bitcoin-block-header blk))
                         (e (bl.store:make-block-index-entry
                             :hash (bl.ser:block-header-hash hdr)
                             :height h :header hdr :prev-entry prev
                             :chain-work w :status :header-valid)))
                    (bl.store:add-block-index-entry csa e)
                    (bl.store:store-block storea blk)
                    (setf prev e))))
       ;; H index: H5 work = tip+1000 (higher), but only H5's body on disk.
       (let ((prev (bl.store:get-block-index-entry csa genesis-hash)))
         (loop for blk in h-blocks for h from 1
               for w in (list 1 2 3 4 (+ tip-work 1000))
               do (let* ((hdr (bl.ser:bitcoin-block-header blk))
                         (e (bl.store:make-block-index-entry
                             :hash (bl.ser:block-header-hash hdr)
                             :height h :header hdr :prev-entry prev
                             :chain-work w :status :header-valid)))
                    (bl.store:add-block-index-entry csa e)
                    (setf prev e))))
       (bl.store:store-block storea (fifth h-blocks))
       (with-ibd-context
         (let ((set (bl.net::ibd-context-reorg-candidates
                     bl.net:*ibd-context*)))
           ;; Both are candidates; H5 outranks G3 by work.
           (setf (gethash g-hash set) t
                 (gethash h-hash set) t))
         ;; Retry must skip higher-work INCOMPLETE H5 and activate complete G3.
         (is (eq t (bl.net::retry-best-reorg-candidate
                    csa storea utxoa)))
         (is (equalp g-hash (bl.store:best-block-hash csa)))
         ;; H5 stays a candidate (still not completable); G3 consumed.
         (is (null (gethash g-hash (bl.net::ibd-context-reorg-candidates
                                    bl.net:*ibd-context*)))))))))

;;;; ===========================================================================
;;;; Item 12 — Layer-5 reorg / download REGRESSION SUITE
;;;;
;;;; Locks in the just-shipped layer-5 invariants (per-peer chain-aware
;;;; download, AcceptBlock persist gate, deep-reorg candidate set, witness-
;;;; strip guard). Every test is deterministic and hermetic — synthetic index
;;;; topologies or deterministic regtest mining, no Bitcoin Core test vectors.
;;;; Reuses the layer-5 fixtures (with-network (:regtest), regtest-node-fixture,
;;;; %dr-mine-on/%dr-connect, make-activate-block-fixture, make-reorg-test-block,
;;;; make-stripped-reorg-block, make-reorg-hash). Synthetic peers advertise
;;;; NODE_NETWORK|NODE_WITNESS or the per-peer walk's service guard skips them.
;;;; ===========================================================================

(test l5-invalid-reorg-candidate-rejected-and-never-retried
  "Item 12(1): a consensus-INVALID completable fork noted as a reorg candidate
is PERMANENTLY rejected by retry-best-reorg-candidate — it moves to
ibd-context-rejected-reorg-candidates, the active tip rolls back untouched, and
it is never re-selected (note-reorg-candidate refuses to re-add a rejected
hash). The invalid signal is an over-value coinbase (:coinbase-too-large), the
same deterministic fork failure as reorg-rejects-fork-carrying-invalid-block."
  (with-network (:mainnet)
   (multiple-value-bind (cs utxo store genesis-hash)
       (make-activate-block-fixture "l5-invalid-cand")
     ;; Active chain A: a single block A1 on genesis (tip height 1).
     (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA0 1))
     (let* ((a1-hash (bl.store:best-block-hash cs))
            (a1-entry (bl.store:get-block-index-entry cs a1-hash))
            (a1-work (bl.store:block-index-entry-chain-work a1-entry))
            (b-hashes (make-test-chain-hashes #xB0 2))
            (b1-hash (first b-hashes))
            (b2-hash (second b-hashes))
            ;; B1 valid; B2's coinbase pays one satoshi over the 50 BTC subsidy.
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1))
            (b2-block (make-reorg-test-block b1-hash b2-hash 2 :value 5000000001)))
       ;; B1 enters as an equal-work weaker side block (A stays tip); connect-block
       ;; stores its body + a real-work index entry.
       (bl.val:connect-block b1-block cs store utxo)
       (let ((b1-entry (bl.store:get-block-index-entry cs b1-hash)))
         ;; B2 (invalid) stored + indexed directly with more work than the tip so
         ;; it is the highest-work completable candidate. Its own header bits +
         ;; B1's entry work make activate-block recompute a work that outweighs A1,
         ;; so the pre-reorg fires and reaches B2's over-value coinbase.
         (bl.store:store-block store b2-block)
         (bl.store:add-block-index-entry
          cs (bl.store:make-block-index-entry
              :hash b2-hash :height 2 :prev-entry b1-entry
              :chain-work (+ a1-work 1000) :status :header-valid
              :header (bl.ser:bitcoin-block-header b2-block)))
         (with-ibd-context
           (let ((set (bl.net::ibd-context-reorg-candidates
                       bl.net:*ibd-context*))
                 (rej (bl.net::ibd-context-rejected-reorg-candidates
                       bl.net:*ibd-context*))
                 (b2-entry (bl.store:get-block-index-entry cs b2-hash)))
             (setf (gethash b2-hash set) t)
             ;; Retry attempts the reorg, hits the over-value coinbase, and
             ;; permanently rejects the fork.
             (is (null (bl.net::retry-best-reorg-candidate cs store utxo)))
             (is-true (gethash b2-hash rej))
             (is (null (gethash b2-hash set)))
             ;; Active tip rolled back to A1 — nothing invalid entered the chain.
             (is (equalp a1-hash (bl.store:best-block-hash cs)))
             (is (= 1 (bl.store:current-height cs)))
             ;; NEVER retried: re-noting the rejected candidate is refused, and a
             ;; second retry finds nothing to activate — tip stays put.
             (bl.net::note-reorg-candidate b2-entry cs)
             (is (null (gethash b2-hash set)))
             (is (null (bl.net::retry-best-reorg-candidate cs store utxo)))
             (is (equalp a1-hash (bl.store:best-block-hash cs))))))
       (clear-undo-cache)))))

(test l5-refused-reorg-requeues-missing-and-keeps-candidate
  "Item 12(1) contrast: a tip+1 block that WINS on work but whose intermediate
fork bodies are absent yields a transient :reorg-refused. process-received-block
re-queues the missing (hash . height) blocks into pending (queue-missing-fork-
blocks) and records the winner as a reorg CANDIDATE (recoverable) — never in the
rejected set. The active tip is untouched until the bodies arrive."
  (with-network (:regtest)
   (let* ((spk-a (p2sh-optrue-script-pubkey))
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))
          (nb (regtest-node-fixture "l5-refuse-b"))
          (b-blocks (loop repeat 4 for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk) collect blk))
          (na (regtest-node-fixture "l5-refuse-a"))
          (csa (bl:node-chain-state na))
          (utxoa (bl:node-utxo-set na))
          (storea (bl:node-block-store na))
          (genesis-hash (bl.store:best-block-hash csa)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))   ; tip A3 (height 3)
     (is (= 3 (bl.store:current-height csa)))
     ;; Add ALL four branch-B headers (B1-B4) to na with real chain-work; store
     ;; NO bodies. B4's entry must exist for process-received-block to accept it.
     (let ((prev (bl.store:get-block-index-entry csa genesis-hash)))
       (loop for blk in b-blocks for h from 1 to 4
             do (let* ((hdr (bl.ser:bitcoin-block-header blk))
                       (bhash (bl.ser:block-header-hash hdr))
                       (work (bl.store:calculate-chain-work
                              (bl.ser:block-header-bits hdr)
                              (bl.store:block-index-entry-chain-work prev)))
                       (e (bl.store:make-block-index-entry
                           :hash bhash :height h :header hdr
                           :prev-entry prev :chain-work work :status :header-valid)))
                  (bl.store:add-block-index-entry csa e)
                  (setf prev e))))
     (let* ((b-hashes (mapcar (lambda (blk)
                                (bl.ser:block-header-hash
                                 (bl.ser:bitcoin-block-header blk)))
                              b-blocks))
            (b4-hash (fourth b-hashes)))
       (with-ibd-context
         (let ((ctx bl.net:*ibd-context*))
           ;; Feed B4 (height 4 = tip+1). It outweighs A3, but B1-B3 bodies are
           ;; missing -> perform-reorg refuses -> :reorg-refused + missing list.
           (deliver-block (fourth b-blocks) csa utxoa storea :requested t)
           ;; The three missing sub-tip fork bodies were re-queued for download.
           (is (= 3 (hash-table-count
                     (bl.net:ibd-context-pending-blocks ctx))))
           (dolist (h (subseq b-hashes 0 3))
             (is-true (gethash h (bl.net:ibd-context-pending-blocks ctx))))
           ;; B4 is a live reorg candidate, NOT rejected (recoverable).
           (is-true (gethash b4-hash
                             (bl.net::ibd-context-reorg-candidates ctx)))
           (is (null (gethash b4-hash
                              (bl.net::ibd-context-rejected-reorg-candidates
                               ctx))))
           ;; Active tip untouched (all-or-nothing reorg refused cleanly).
           (is (= 3 (bl.store:current-height csa)))))))))

(test l5-witness-stripped-block-never-persisted
  "Item 12(2): a witness-stripped block is NEVER persisted at any chain position
— below the tip (competing fork), at tip+1, or above tip (out-of-order) — since a
stripped body on disk fails every later reorg (the original testnet4 wedge).
block-exists-p stays NIL for the stripped copy in all three cases. An above-tip
stripped copy of a REQUESTED block re-enters pending so a witness-complete copy is
re-fetched; an unsolicited stripped copy does not."
  (with-network (:mainnet)
   (multiple-value-bind (cs utxo store genesis-hash)
       (make-activate-block-fixture "l5-stripped")
     ;; Active chain A: two blocks, tip A2 at height 2.
     (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA0 2))
     (let* ((a2-hash (bl.store:best-block-hash cs))
            (a2-entry (bl.store:get-block-index-entry cs a2-hash))
            (genesis-entry (bl.store:get-block-index-entry cs genesis-hash))
            (below-hash (make-reorg-hash #xB100))
            (tip1-hash (make-reorg-hash #xB101))
            (above-req-hash (make-reorg-hash #xB102))
            (above-uns-hash (make-reorg-hash #xB103))
            (below (make-stripped-reorg-block genesis-hash below-hash 1))
            (tip1 (make-stripped-reorg-block a2-hash tip1-hash 3))
            (above-req (make-stripped-reorg-block a2-hash above-req-hash 5))
            (above-uns (make-stripped-reorg-block a2-hash above-uns-hash 6)))
       ;; Header-valid index entries only (no bodies on disk). The stripped-drop
       ;; paths read only the entry's height + status, so the above-tip entries'
       ;; height/prev mismatch is immaterial.
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash below-hash :height 1 :prev-entry genesis-entry :chain-work 50
            :status :header-valid
            :header (bl.ser:bitcoin-block-header below)))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash tip1-hash :height 3 :prev-entry a2-entry :chain-work 5000
            :status :header-valid
            :header (bl.ser:bitcoin-block-header tip1)))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash above-req-hash :height 5 :prev-entry a2-entry :chain-work 9000
            :status :header-valid
            :header (bl.ser:bitcoin-block-header above-req)))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash above-uns-hash :height 6 :prev-entry a2-entry :chain-work 9000
            :status :header-valid
            :header (bl.ser:bitcoin-block-header above-uns)))
       (with-ibd-context
         (let ((ctx bl.net:*ibd-context*))
           ;; sanity: all four copies really are witness-stripped.
           (dolist (blk (list below tip1 above-req above-uns))
             (is-true (bl.val:block-witness-stripped-p blk)))
           ;; (a) below the tip (competing fork, height 1) — dropped, not stored.
           (deliver-block below cs utxo store :requested t)
           (is (null (bl.store:block-exists-p store below-hash)))
           ;; (b) tip+1 (height 3) — dropped, not stored.
           (deliver-block tip1 cs utxo store :requested t)
           (is (null (bl.store:block-exists-p store tip1-hash)))
           ;; (c) above tip (height 5), REQUESTED — dropped, not stored, but the
           ;; requested block re-enters pending for a witness-complete re-fetch.
           (deliver-block above-req cs utxo store :requested t)
           (is (null (bl.store:block-exists-p store above-req-hash)))
           (is (eql 5 (gethash above-req-hash
                               (bl.net:ibd-context-pending-blocks ctx))))
           ;; (d) above tip (height 6), UNSOLICITED — dropped, not stored, and NOT
           ;; re-queued (only a requested stripped copy re-arms a fetch).
           (deliver-block above-uns cs utxo store)
           (is (null (bl.store:block-exists-p store above-uns-hash)))
           (is (null (gethash above-uns-hash
                              (bl.net:ibd-context-pending-blocks ctx)))))))
     (clear-undo-cache))))

(test l5-out-of-order-acceptable-boundaries
  "Item 12(3): %out-of-order-block-acceptable-p boundary cases beyond the
existing coverage. Height boundary: a more-work unsolicited block exactly at
tip + +min-blocks-to-keep+ is accepted; one height further is rejected (but a
REQUESTED copy bypasses the gate). Min-work boundary: a more-work in-window
unsolicited block is accepted only when its work meets minimum-chain-work; one
unit below the floor is rejected (again bypassed when REQUESTED). Pure synthetic
index — no Bitcoin Core vectors."
  (with-network (:regtest)
   (let* ((cs (bl.store:make-chain-state))
          (%h (lambda (n) (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element n)))
          (g (bl.store:make-block-index-entry
              :hash (funcall %h 0) :height 0 :chain-work 0 :status :valid))
          (tip (bl.store:make-block-index-entry
                :hash (funcall %h 1) :height 1 :chain-work 100 :prev-entry g
                :status :valid)))
     (bl.store:add-block-index-entry cs g)
     (bl.store:add-block-index-entry cs tip)
     (bl.store:update-chain-tip cs (funcall %h 1) 1)
     ;; --- height boundary (current-height = 1) ---
     (let ((at-window (bl.store:make-block-index-entry
                       :hash (funcall %h 2)
                       :height (+ 1 bl:+min-blocks-to-keep+)
                       :chain-work 150 :status :header-valid))
           (past-window (bl.store:make-block-index-entry
                         :hash (funcall %h 3)
                         :height (+ 2 bl:+min-blocks-to-keep+)
                         :chain-work 150 :status :header-valid)))
       ;; Exactly tip + min-blocks-to-keep ahead: accepted.
       (is (bl.net::%out-of-order-block-acceptable-p at-window 1 nil cs))
       ;; One height further: rejected (unsolicited)...
       (is (null (bl.net::%out-of-order-block-acceptable-p
                  past-window 1 nil cs)))
       ;; ...but a requested copy of the same block is accepted.
       (is (bl.net::%out-of-order-block-acceptable-p past-window 1 t cs)))
     ;; --- minimum-chain-work boundary (in-window, more work than tip) ---
     (let ((cand (bl.store:make-block-index-entry
                  :hash (funcall %h 4) :height 3 :chain-work 150 :status :header-valid)))
       ;; work 150 > tip 100; floor exactly at 150 -> accepted.
       (let ((bl:*minimum-chain-work-override* 150))
         (is (bl.net::%out-of-order-block-acceptable-p cand 1 nil cs)))
       ;; floor one unit above the block's work -> rejected (unsolicited)...
       (let ((bl:*minimum-chain-work-override* 151))
         (is (null (bl.net::%out-of-order-block-acceptable-p cand 1 nil cs)))
         ;; ...unless requested.
         (is (bl.net::%out-of-order-block-acceptable-p cand 1 t cs)))))))

(test l5-multi-peer-same-chain-dedups-in-flight
  "Item 12(4): two ready peers whose best-known block is the SAME fork tip do
not both get the same block in one request-blocks-from-peers pass. Each peer's
chosen blocks are marked in-flight before the next peer is walked (Core
FindNextBlocksToDownload marks mapBlocksInFlight), so the two peers PARTITION the
fork range — no hash is requested twice."
  (with-network (:regtest)
   (let* ((cs (bl.store:make-chain-state))
          (store (bl.store:make-block-store :base-path #p"/nonexistent/l5-dedup/"))
          (genesis (bl.store:make-block-index-entry
                    :hash (make-reorg-hash 0) :height 0 :prev-entry nil
                    :chain-work 1 :status :valid))
          (fork-hashes '()))
     (bl.store:add-block-index-entry cs genesis)
     (bl.store:update-chain-tip cs (make-reorg-hash 0) 0)
     ;; Fork f1..f5 above genesis: more-work each, header-valid, no bodies.
     (let ((prev genesis))
       (loop for h from 1 to 5
             for hash = (make-reorg-hash (+ 2000 h))
             do (push hash fork-hashes)
                (bl.store:add-block-index-entry
                 cs (bl.store:make-block-index-entry
                     :hash hash :height h :header nil :prev-entry prev
                     :chain-work (+ 100 h) :status :header-valid))
                (setf prev (bl.store:get-block-index-entry cs hash))))
     (setf fork-hashes (nreverse fork-hashes))
     (let* ((svc (logior bl.ser:+node-network+
                         bl.ser:+node-witness+))
            (tip-hash (make-reorg-hash (+ 2000 5)))
            (ctx (bl.net::make-ibd))
            (p1 (bl.net:make-peer :address "1.1.1.1:1"
                                                    :state :ready :services svc))
            (p2 (bl.net:make-peer :address "2.2.2.2:2"
                                                    :state :ready :services svc)))
       (setf (bl.net:peer-best-known-block-hash p1) tip-hash
             (bl.net:peer-best-known-block-hash p2) tip-hash)
       ;; Small per-peer cap so BOTH peers must contribute (else p1 takes all 5).
       (setf (bl.net::ibd-context-max-in-flight ctx) 3)
       (let ((bl.net:*ibd-context* ctx))
         (let ((made (bl.net::request-blocks-from-peers
                      (list p1 p2) cs store))
               (in-flight (bl.net:ibd-context-in-flight ctx)))
           ;; All five fork blocks requested exactly once: requests-made equals the
           ;; distinct in-flight count (a duplicate would have collided on a key).
           (is (= 5 made))
           (is (= 5 (hash-table-count in-flight)))
           ;; Both peers contributed and their assignments are disjoint & cover the
           ;; range: the two per-peer counts are {2,3} (order-independent).
           (is (equal '(2 3)
                      (sort (list (bl.net::count-peer-in-flight p1)
                                  (bl.net::count-peer-in-flight p2))
                            #'<)))
           ;; Every fork hash is in-flight.
           (dolist (h fork-hashes)
             (is-true (gethash h in-flight)))))))))

(test l5-gap-only-backpressure-clamps-to-one-request
  "Item 12(5): when the out-of-order block-queue is at capacity and the
next-needed (gap) block is absent from it, request-blocks-from-peers lifts
backpressure for only ONE block — the over-cap gap-only path clamps the total
request budget to 1, so peers can't flood blocks above a stalled gap (the heap
exhaustion this gate exists to prevent)."
  (with-network (:regtest)
   (let* ((cs (bl.store:make-chain-state))
          (store (bl.store:make-block-store :base-path #p"/nonexistent/l5-gap/"))
          (genesis (bl.store:make-block-index-entry
                    :hash (make-reorg-hash 0) :height 0 :prev-entry nil
                    :chain-work 1 :status :valid)))
     (bl.store:add-block-index-entry cs genesis)
     (bl.store:update-chain-tip cs (make-reorg-hash 0) 0)
     ;; A more-work fork of 3 header-valid blocks above genesis (no bodies) so
     ;; there IS something to request.
     (let ((prev genesis))
       (loop for h from 1 to 3
             for hash = (make-reorg-hash (+ 3000 h))
             do (bl.store:add-block-index-entry
                 cs (bl.store:make-block-index-entry
                     :hash hash :height h :header nil :prev-entry prev
                     :chain-work (+ 100 h) :status :header-valid))
                (setf prev (bl.store:get-block-index-entry cs hash))))
     (let* ((svc (logior bl.ser:+node-network+
                         bl.ser:+node-witness+))
            (fork-tip (make-reorg-hash (+ 3000 3)))
            (ctx (bl.net::make-ibd))
            (peer (bl.net:make-peer :address "9.9.9.9:9"
                                                      :state :ready :services svc)))
       (setf (bl.net:peer-best-known-block-hash peer) fork-tip)
       ;; Fill the RAM block-queue to capacity, but leave the gap (next-needed
       ;; height 1) absent so the over-cap gap-only path is taken.
       (let ((q (bl.net:ibd-context-block-queue ctx)))
         (loop for i from 0 below bl.net::+max-block-queue-size+
               do (setf (gethash (+ 2 i) q) t)))
       (let ((bl.net:*ibd-context* ctx))
         ;; Over cap + gap missing: exactly one request is allowed.
         (let ((made (bl.net::request-blocks-from-peers
                      (list peer) cs store)))
           (is (= 1 made))
           (is (= 1 (hash-table-count
                     (bl.net:ibd-context-in-flight ctx))))))))))

(test l5-historical-download-only-for-base-containing-peer
  "Item 12(6): find-historical-blocks-to-download returns the assumeutxo
target-ancestor range [hist-tip+1 .. base] ONLY for a peer whose best-known chain
contains the snapshot base (Core GetAncestor(base->nHeight) == base). A peer on a
fork that does not contain the base gets nothing. Synthetic chainstates, no
Bitcoin Core vectors."
  (with-network (:regtest)
   (let* ((cs (bl.store:make-chain-state))
          (hist (bl.store:make-chain-state))
          (store (bl.store:make-block-store :base-path #p"/nonexistent/l5-hist/"))
          (svc (logior bl.ser:+node-network+
                       bl.ser:+node-witness+))
          (chain '())    ; genesis .. h5, oldest first
          (prev nil))
     ;; Build genesis..h5 as a single linked chain in the shared index (cs).
     (loop for h from 0 to 5
           for hash = (make-reorg-hash (+ 4000 h))
           for e = (bl.store:make-block-index-entry
                    :hash hash :height h :header nil :prev-entry prev
                    :chain-work (+ 10 h) :status (if (zerop h) :valid :header-valid))
           do (bl.store:add-block-index-entry cs e)
              (push e chain)
              (setf prev e))
     (setf chain (nreverse chain))
     (let* ((base-entry (nth 5 chain))            ; h5 = snapshot base = target
            (base-hash (bl.store:block-index-entry-hash base-entry))
            ;; A separate fork off genesis that does NOT contain the base.
            (fork-hash (make-reorg-hash 9999))
            (ctx (bl.net::make-ibd)))
       (bl.store:add-block-index-entry
        cs (bl.store:make-block-index-entry
            :hash fork-hash :height 1 :prev-entry (first chain)
            :chain-work 11 :status :header-valid))
       ;; Point the historical chainstate at the base; its validated tip is genesis
       ;; (height 0), so it must download h1..h5.
       (bl.store:set-chainstate-target hist base-entry)
       (setf (bl.net::ibd-context-historical-chain-state ctx) hist
             (bl.net::ibd-context-snapshot-base-entry ctx) base-entry)
       (let ((base-peer (bl.net:make-peer :address "1.0.0.1:1"
                                                            :state :ready :services svc))
             (fork-peer (bl.net:make-peer :address "2.0.0.2:2"
                                                            :state :ready :services svc)))
         (setf (bl.net:peer-best-known-block-hash base-peer) base-hash
               (bl.net:peer-best-known-block-hash fork-peer) fork-hash)
         (let ((bl.net:*ibd-context* ctx))
           ;; Base-containing peer: the whole h1..h5 target-ancestor range,
           ;; oldest-first, none on disk.
           (let ((got (bl.net::find-historical-blocks-to-download
                       base-peer cs store 16)))
             (is (= 5 (length got)))
             (is (equalp (bl.store:block-index-entry-hash (nth 1 chain))
                         (first got)))
             (is (equalp base-hash (car (last got))))
             (is (equalp (mapcar #'bl.store:block-index-entry-hash
                                 (subseq chain 1))
                         got)))
           ;; A peer whose best chain does not contain the base: nothing.
           (is (null (bl.net::find-historical-blocks-to-download
                      fork-peer cs store 16)))))))))

;;;; ===========================================================================
;;;; Item 14 — Mark deterministically-invalid fork blocks :invalid + propagate
;;;;            to descendants (Core BLOCK_FAILED_VALID / BLOCK_FAILED_CHILD)
;;;;
;;;; The ENTIRE risk is classification: poison ONLY on a deterministic consensus
;;;; verdict, NEVER on a transient / corrupt-body / witness-dependent failure that
;;;; a clean re-download could fix (poisoning a recoverable block re-wedges the
;;;; node). These tests lock both halves: the positive path (an invalid fork block
;;;; + its subtree become :invalid and the download walk aborts above it) and the
;;;; CRITICAL NEGATIVE path (:reorg-refused-with-missing and :corrupt-undo mark
;;;; NOTHING :invalid and stay recoverable).
;;;; ===========================================================================

(test item14-classification-allowlist-is-tight
  "Unit lock on %deterministic-consensus-failure-p: exactly the txid-committed
contextual consensus verdicts poison; every witness-dependent, structural/merkle,
CheckBlock, control, unrecognized, or NIL value is TRANSIENT (never poisons)."
  ;; Every allowlisted keyword classifies as deterministic-invalid.
  (dolist (k '(:duplicate-txid :missing-input :coinbase-not-mature
               :insufficient-funds :non-final-tx :bad-sequence-lock
               :bad-coinbase-height :coinbase-too-large))
    (is-true (bl.val::%deterministic-consensus-failure-p k)
             "~A must be deterministic-invalid" k))
  ;; Everything else must be TRANSIENT (recoverable) — must NOT poison. Includes
  ;; witness-byte-dependent verdicts (script / witness-commitment / contextual
  ;; sigops), corrupt-body signals (merkle), CheckBlock/structural failures,
  ;; header keywords, the reorg control keywords, an unknown keyword, and NIL.
  (dolist (k '(:script-failed :bad-witness-merkle-match :bad-witness-nonce-size
               :unexpected-witness :too-many-sigops
               :bad-merkle-root :bad-txns-duplicate :no-transactions
               :first-tx-not-coinbase :multiple-coinbase :block-too-heavy
               :block-too-large :bad-blk-sigops :no-inputs :no-outputs
               :duplicate-inputs :negative-output :bad-prevout-null
               :corrupt-undo :reorg-refused :weaker-chain :unknown-parent
               :reorg-failed :block-missing :block-not-found
               :some-unrecognized-keyword nil))
    (is (null (bl.val::%deterministic-consensus-failure-p k))
        "~A must be transient (not poisoned)" k)))

(test item14-phase-b-poisons-invalid-fork-and-descendants
  "perform-reorg PHASE B: a fork block that DETERMINISTICALLY fails validate-block
(:coinbase-too-large) is marked :invalid, its descendant subtree is
BLOCK_FAILED_CHILD'd, the reorg rolls back, and ANCESTORS on the fork stay
recoverable (:header-valid). Directly exercises the perform-reorg poisoning hook."
  (with-network (:mainnet)
   (multiple-value-bind (cs utxo store genesis-hash)
       (make-activate-block-fixture "item14-phaseb")
     ;; Active chain A: A1 is the tip (height 1), fully valid.
     (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA0 1))
     (let* ((a1-hash (bl.store:best-block-hash cs))
            (a1-entry (bl.store:get-block-index-entry cs a1-hash))
            (genesis-entry (bl.store:get-block-index-entry cs genesis-hash))
            (b-hashes (make-test-chain-hashes #xB0 2))
            (b1-hash (first b-hashes)) (b2-hash (second b-hashes))
            ;; B3: a descendant header of the invalid B2 (body-less), present only
            ;; to prove BLOCK_FAILED_CHILD reaches the whole subtree.
            (b3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8)
                                            :initial-element 0)))
                       (setf (aref h 0) #xB0) (setf (aref h 1) 3) h))
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1))            ; valid
            (b2-block (make-reorg-test-block b1-hash b2-hash 2 :value 5000000001)) ; over-value coinbase
            (b3-block (make-reorg-test-block b2-hash b3-hash 3)))
       ;; Store B1 + B2 bodies (perform-reorg needs both to-connect bodies present);
       ;; B3 stays header-only (never connected — it's only a descendant to poison).
       (bl.store:store-block store b1-block)
       (bl.store:store-block store b2-block)
       (let* ((b1-entry (bl.store:make-block-index-entry
                         :hash b1-hash :height 1 :prev-entry genesis-entry
                         :chain-work 100 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b1-block)))
              (_ (bl.store:add-block-index-entry cs b1-entry))
              (b2-entry (bl.store:make-block-index-entry
                         :hash b2-hash :height 2 :prev-entry b1-entry
                         :chain-work 200 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b2-block)))
              (__ (bl.store:add-block-index-entry cs b2-entry))
              (b3-entry (bl.store:make-block-index-entry
                         :hash b3-hash :height 3 :prev-entry b2-entry
                         :chain-work 300 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b3-block))))
         (declare (ignore _ __))
         (bl.store:add-block-index-entry cs b3-entry)
         ;; Reorg A1 -> B2. PHASE B connects B1 (valid) then hits B2's over-value
         ;; coinbase -> deterministic :coinbase-too-large -> poison + rollback.
         (multiple-value-bind (ok detail)
             (bl.val:perform-reorg cs store utxo a1-entry b2-entry)
           (is (null ok))
           (is (eq :coinbase-too-large detail)))
         ;; B2 :invalid (BLOCK_FAILED_VALID), B3 :invalid (BLOCK_FAILED_CHILD).
         (is (eq :invalid (bl.store:block-index-entry-status b2-entry)))
         (is (eq :invalid (bl.store:block-index-entry-status b3-entry)))
         ;; B1 (a VALID ancestor of the invalid block) is NOT poisoned — the
         ;; rollback restored it to :header-valid, recoverable.
         (is (eq :header-valid (bl.store:block-index-entry-status b1-entry)))
         ;; Rolled back to chain A: tip + height unchanged, A1 valid.
         (is (equalp a1-hash (bl.store:best-block-hash cs)))
         (is (= 1 (bl.store:current-height cs)))
         (is (eq :valid (bl.store:block-index-entry-status a1-entry)))
         ;; best-valid-tip skips the poisoned subtree (never names B2/B3).
         (let ((bvt (bl.val:best-valid-tip cs store)))
           (is-true bvt)
           (is (not (eq bvt b2-entry)))
           (is (not (eq bvt b3-entry)))))
       (clear-undo-cache)))))

(test item14-download-walk-aborts-above-invalid-block
  "Verifies the already-wired hook fires: find-blocks-to-download-for-peer aborts
the per-peer walk at an :invalid block (Core FindNextBlocks) — blocks BELOW it are
still offered, the invalid block and everything above it are never re-requested."
  (with-network (:regtest)
   (let* ((spk-a (p2sh-optrue-script-pubkey))
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))
          (nb (regtest-node-fixture "item14-walk-b"))
          (b-blocks (loop repeat 5 for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk) collect blk))
          (na (regtest-node-fixture "item14-walk-a"))
          (csa (bl:node-chain-state na))
          (storea (bl:node-block-store na))
          (genesis-hash (bl.store:best-block-hash csa)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))   ; active branch A, tip A3
     ;; Add branch-B headers (5, more work) to na, no bodies. Capture B2's entry.
     (let ((prev (bl.store:get-block-index-entry csa genesis-hash))
           (b-entries '()))
       (loop for blk in b-blocks for h from 1 to 5
             do (let* ((hdr (bl.ser:bitcoin-block-header blk))
                       (bhash (bl.ser:block-header-hash hdr))
                       (work (bl.store:calculate-chain-work
                              (bl.ser:block-header-bits hdr)
                              (bl.store:block-index-entry-chain-work prev)))
                       (e (bl.store:make-block-index-entry
                           :hash bhash :height h :header hdr
                           :prev-entry prev :chain-work work :status :header-valid)))
                  (bl.store:add-block-index-entry csa e)
                  (push e b-entries)
                  (setf prev e)))
       (setf b-entries (nreverse b-entries))
       ;; Poison B2 (as perform-reorg would on a deterministic failure).
       (setf (bl.store:block-index-entry-status (second b-entries)) :invalid)
       (let* ((ctx (bl.net::make-ibd))
              (b-hashes (mapcar (lambda (blk)
                                  (bl.ser:block-header-hash
                                   (bl.ser:bitcoin-block-header blk)))
                                b-blocks))
              (svc (logior bl.ser:+node-network+
                           bl.ser:+node-witness+))
              (peer-b (bl.net:make-peer :address "1.2.3.4:18333"
                                                          :services svc)))
         (setf (bl.net:peer-best-known-block-hash peer-b) (fifth b-hashes))
         (let ((bl.net:*ibd-context* ctx))
           (let ((got (bl.net::find-blocks-to-download-for-peer
                       peer-b csa storea 16)))
             ;; Only B1 (below the invalid B2) is offered; the walk aborts at B2,
             ;; so B2..B5 are never requested.
             (is (= 1 (length got)))
             (is (equalp (first b-hashes) (first got)))
             (dolist (h (subseq b-hashes 1 5))
               (is (null (member h got :test #'equalp)))))))))))

(test item14-header-admission-failed-child
  "process-headers BLOCK_FAILED_CHILD: a header extending a known-:invalid block
is admitted marked :invalid (so its own descendants are recognized) but is NEVER
queued for download; a header on a valid parent is still admitted normally."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "item14-fc"))
          (cs (bl:node-chain-state node))
          (genesis-hash (bl.store:best-block-hash cs))
          (genesis-entry (bl.store:get-block-index-entry cs genesis-hash))
          ;; X: an :invalid block-index entry directly on genesis.
          (x-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                    (setf (aref h 0) #xE0) (setf (aref h 1) 1) h))
          (x-block (make-reorg-test-block genesis-hash x-hash 1))
          (x-entry (bl.store:make-block-index-entry
                    :hash x-hash :height 1 :prev-entry genesis-entry
                    :chain-work 50 :status :invalid
                    :header (bl.ser:bitcoin-block-header x-block)))
          ;; Y: a header extending the INVALID X.
          (y-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                    (setf (aref h 0) #xE0) (setf (aref h 1) 2) h))
          (y-header (bl.ser:bitcoin-block-header
                     (make-reorg-test-block x-hash y-hash 2)))
          ;; V: a header extending VALID genesis (control — normal admission).
          (v-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                    (setf (aref h 0) #xF0) (setf (aref h 1) 1) h))
          (v-header (bl.ser:bitcoin-block-header
                     (make-reorg-test-block genesis-hash v-hash 1))))
     (bl.store:add-block-index-entry cs x-entry)
     (with-ibd-context
       (let ((ctx bl.net:*ibd-context*))
         ;; Feed Y (FAILED_CHILD) and V (valid) together. Only V counts as "added".
         (let ((added (bl.net:process-headers (list y-header v-header) cs)))
           (is (= 1 added)))
         ;; Y is in the index marked :invalid (BLOCK_FAILED_CHILD), not queued.
         (let ((y-entry (bl.store:get-block-index-entry cs y-hash)))
           (is-true y-entry)
           (is (eq :invalid (bl.store:block-index-entry-status y-entry)))
           (is (null (gethash y-hash (bl.net:ibd-context-pending-blocks ctx)))))
         ;; V (valid parent) is admitted :header-valid and queued for download.
         (let ((v-entry (bl.store:get-block-index-entry cs v-hash)))
           (is-true v-entry)
           (is (eq :header-valid (bl.store:block-index-entry-status v-entry)))
           (is-true (gethash v-hash (bl.net:ibd-context-pending-blocks ctx)))))))))

(test item14-negative-missing-fork-bodies-not-poisoned
  "CRITICAL NEGATIVE: a reorg REFUSED because the fork bodies are missing
(:reorg-refused-with-missing) is TRANSIENT — it marks NOTHING :invalid, so the
fork stays recoverable once the bodies arrive. Poisoning here would re-wedge the
node (the exact class of bug this project has fought)."
  (with-network (:mainnet)
   (multiple-value-bind (cs utxo store genesis-hash)
       (make-activate-block-fixture "item14-neg-missing")
     ;; Active chain A: A1 -> A2 (tip height 2), bodies on disk.
     (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA0 2))
     (let* ((a2-hash (bl.store:best-block-hash cs))
            (a2-entry (bl.store:get-block-index-entry cs a2-hash))
            (genesis-entry (bl.store:get-block-index-entry cs genesis-hash))
            (b-hashes (make-test-chain-hashes #xB0 2))
            (b1-hash (first b-hashes)) (b2-hash (second b-hashes))
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1))
            (b2-block (make-reorg-test-block b1-hash b2-hash 2)))
       ;; Fork B headers ONLY — deliberately store NO bodies (the missing case).
       (let* ((b1-entry (bl.store:make-block-index-entry
                         :hash b1-hash :height 1 :prev-entry genesis-entry
                         :chain-work 100 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b1-block)))
              (_ (bl.store:add-block-index-entry cs b1-entry))
              (b2-entry (bl.store:make-block-index-entry
                         :hash b2-hash :height 2 :prev-entry b1-entry
                         :chain-work 200 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b2-block))))
         (declare (ignore _))
         (bl.store:add-block-index-entry cs b2-entry)
         ;; perform-reorg refuses at the missing-body precondition (before PHASE B).
         (multiple-value-bind (ok detail)
             (bl.val:perform-reorg cs store utxo a2-entry b2-entry)
           (is (null ok))
           ;; DETAIL is the missing (hash . height) list, NOT a keyword verdict.
           (is-true (consp detail))
           (is (= 2 (length detail))))
         ;; NOTHING poisoned — both fork entries remain recoverable.
         (is (eq :header-valid (bl.store:block-index-entry-status b1-entry)))
         (is (eq :header-valid (bl.store:block-index-entry-status b2-entry)))
         ;; Active chain untouched.
         (is (equalp a2-hash (bl.store:best-block-hash cs)))
         (is (= 2 (bl.store:current-height cs))))
       (clear-undo-cache)))))

(test item14-negative-corrupt-undo-not-poisoned
  "CRITICAL NEGATIVE: a reorg refused because a to-DISCONNECT spending block's undo
is missing/corrupt (:corrupt-undo) is TRANSIENT — a LOCAL fault, not a verdict on
the fork. It marks NOTHING :invalid; the competing fork stays recoverable."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "item14-neg-corrupt")
     (let* ((genesis-entry (bl.store:get-block-index-entry chain-state genesis-hash))
            (a-hashes (make-test-chain-hashes #xA0 2))
            (a1-hash (first a-hashes)) (a2-hash (second a-hashes))
            (a1-block (make-reorg-test-block genesis-hash a1-hash 1))       ; coinbase-only
            (a2-block (%make-2tx-reorg-block a1-hash a2-hash 2))            ; SPENDING (tx-count 2)
            (b-hashes (make-test-chain-hashes #xB0 2))
            (b1-hash (first b-hashes)) (b2-hash (second b-hashes))
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1))
            (b2-block (make-reorg-test-block b1-hash b2-hash 2)))
       (dolist (blk (list a1-block a2-block b1-block b2-block))
         (bl.store:store-block block-store blk))
       (let* ((a1-entry (bl.store:make-block-index-entry
                         :hash a1-hash :height 1 :prev-entry genesis-entry :chain-work 100
                         :status :valid
                         :header (bl.ser:bitcoin-block-header a1-block)))
              (_ (bl.store:add-block-index-entry chain-state a1-entry))
              (a2-entry (bl.store:make-block-index-entry
                         :hash a2-hash :height 2 :prev-entry a1-entry :chain-work 200
                         :status :valid
                         :header (bl.ser:bitcoin-block-header a2-block)))
              (__ (bl.store:add-block-index-entry chain-state a2-entry))
              (b1-entry (bl.store:make-block-index-entry
                         :hash b1-hash :height 1 :prev-entry genesis-entry :chain-work 150
                         :status :header-valid
                         :header (bl.ser:bitcoin-block-header b1-block)))
              (___ (bl.store:add-block-index-entry chain-state b1-entry))
              (b2-entry (bl.store:make-block-index-entry
                         :hash b2-hash :height 2 :prev-entry b1-entry :chain-work 300
                         :status :header-valid
                         :header (bl.ser:bitcoin-block-header b2-block))))
         (declare (ignore _ __ ___))
         (bl.store:add-block-index-entry chain-state b2-entry)
         (bl.store:update-chain-tip chain-state a2-hash 2)
         ;; No undo for the spending A2 (the modelled corruption).
         (clear-undo-cache)
         (multiple-value-bind (ok detail)
             (bl.val:perform-reorg chain-state block-store utxo-set
                                                    a2-entry b2-entry)
           (is (null ok))
           (is (eq detail :corrupt-undo)))
         ;; NOTHING poisoned — the competing fork B stays recoverable.
         (is (eq :header-valid (bl.store:block-index-entry-status b1-entry)))
         (is (eq :header-valid (bl.store:block-index-entry-status b2-entry)))
         ;; The refused disconnect left the active chain intact (A still valid).
         (is (eq :valid (bl.store:block-index-entry-status a1-entry)))
         (is (eq :valid (bl.store:block-index-entry-status a2-entry)))
         (is (= 2 (bl.store:current-height chain-state)))))
     (clear-undo-cache))))

;;;; Median-time-past on the reorg path (GA8 S1-7)

(defconstant +mtp-reorg-genesis-time+ 1231006505
  "Timestamp of the genesis header make-activate-block-fixture installs.")

(test perform-reorg-refuses-mtp-violating-fork-block
  "CONSENSUS (GA8 S1-7): perform-reorg connects fork blocks with :skip-header t,
mirroring Core's ConnectBlock, which deliberately does not re-run
ContextualCheckBlockHeader. A fork block already in the index whose timestamp is
at or before its parent's median-time-past was therefore applied to the UTXO set
unchecked. PHASE B re-runs that ONE header rule (never PoW/difficulty — a fork
body re-read from the store carries no cached hash) and refuses.
Control: the same block through validate-block WITHOUT :skip-header is
:time-too-old, so the fixture genuinely violates the rule."
  (with-network (:mainnet)
   (multiple-value-bind (cs utxo store genesis-hash)
       (make-activate-block-fixture "mtp-fork")
     ;; Active chain A: A1 is the tip at height 1.
     (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA0 1))
     (let* ((a1-hash (bl.store:best-block-hash cs))
            (a1-entry (bl.store:get-block-index-entry cs a1-hash))
            (genesis-entry (bl.store:get-block-index-entry cs genesis-hash))
            (b-hashes (make-test-chain-hashes #xB0 3))
            (b1-hash (first b-hashes))
            (b2-hash (second b-hashes))
            (b3-hash (third b-hashes))
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1))
            ;; MTP(B1) = median{genesis, B1} = B1's own time (Core takes the
            ;; upper element of an even window), so B2 timestamped exactly there
            ;; is the boundary case of Core's `<=` rejection.
            (b2-block (make-reorg-test-block
                       b1-hash b2-hash 2
                       :timestamp (+ +mtp-reorg-genesis-time+ 600)))
            (b3-block (make-reorg-test-block b2-hash b3-hash 3)))
       (dolist (b (list b1-block b2-block b3-block))
         (bl.store:store-block store b))
       (let* ((b1-entry (bl.store:make-block-index-entry
                         :hash b1-hash :height 1 :prev-entry genesis-entry
                         :chain-work 100 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b1-block)))
              (b2-entry (bl.store:make-block-index-entry
                         :hash b2-hash :height 2 :prev-entry b1-entry
                         :chain-work 200 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b2-block)))
              (b3-entry (bl.store:make-block-index-entry
                         :hash b3-hash :height 3 :prev-entry b2-entry
                         :chain-work 300 :status :header-valid
                         :header (bl.ser:bitcoin-block-header b3-block))))
         (dolist (e (list b1-entry b2-entry b3-entry))
           (bl.store:add-block-index-entry cs e))
         ;; Control: the full header check rejects B2 outright.
         (multiple-value-bind (valid error)
             (bl.val:validate-block
              b2-block cs utxo 2 (bl.ser:get-unix-time))
           (is (null valid))
           (is (eq :time-too-old error)))
         ;; The reorg must refuse rather than connect B2 mid-fork.
         (multiple-value-bind (ok detail)
             (bl.val:perform-reorg cs store utxo a1-entry b3-entry)
           (is (null ok))
           (is (eq :time-too-old detail)))
         ;; Rolled back to chain A, with nothing poisoned: a header-rule verdict
         ;; is not on the deterministic-invalid allowlist.
         (is (equalp a1-hash (bl.store:best-block-hash cs)))
         (is (= 1 (bl.store:current-height cs)))
         (is (eq :valid (bl.store:block-index-entry-status a1-entry)))
         (is (eq :header-valid (bl.store:block-index-entry-status b1-entry)))
         (is (eq :header-valid (bl.store:block-index-entry-status b2-entry))))
       (clear-undo-cache)))))

(test reconsider-block-refuses-mtp-violating-target
  "GA8 S1-7, the case with no descendant: reconsider-block hands its target
straight to perform-reorg, so an MTP-violating block can be the reorg TIP.
The reorg must refuse and reconsiderblock report :reorg-failed."
  (with-network (:mainnet)
   (multiple-value-bind (cs utxo store genesis-hash)
       (make-activate-block-fixture "mtp-reconsider")
     (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA0 1))
     (let* ((a1-hash (bl.store:best-block-hash cs))
            (a1-entry (bl.store:get-block-index-entry cs a1-hash))
            (genesis-entry (bl.store:get-block-index-entry cs genesis-hash))
            (b1-hash (first (make-test-chain-hashes #xB0 1)))
            ;; MTP(genesis) is the genesis timestamp itself.
            (b1-block (make-reorg-test-block genesis-hash b1-hash 1
                                             :timestamp +mtp-reorg-genesis-time+))
            (b1-entry (bl.store:make-block-index-entry
                       :hash b1-hash :height 1 :prev-entry genesis-entry
                       :chain-work (1+ (bl.store:block-index-entry-chain-work
                                        a1-entry))
                       :status :invalid
                       :header (bl.ser:bitcoin-block-header b1-block))))
       (bl.store:store-block store b1-block)
       (bl.store:add-block-index-entry cs b1-entry)
       (multiple-value-bind (ok reason)
           (bl.val:reconsider-block cs store utxo b1-hash)
         (is (null ok))
         (is (eq :reorg-failed reason)))
       (is (equalp a1-hash (bl.store:best-block-hash cs)))
       (is (= 1 (bl.store:current-height cs)))
       (clear-undo-cache)))))

;;;; Cooperative stop inside a reorg (coins-DB alignment plan, phase 3b)
;;;;
;;;; Core checks m_chainman.m_interrupt BETWEEN ActivateBestChainStep calls
;;;; (validation.cpp:3514) and never force-terminates its validation thread.
;;;; perform-reorg now does the same: on a stop request it TRUNCATES at the next
;;;; block boundary — where the coins, the coins-DB best-block pointer and the
;;;; chain tip can all be left naming one block — instead of running to
;;;; completion (shutdown waits out a deep reorg, then destroy-threads it) or
;;;; rolling back (minutes of work that is itself interruptible).
;;;;
;;;; The tests interrupt by binding bl:*interrupt-check* — the same seam
;;;; node/shutdown.lisp installs the real stop predicate into — and choose WHERE it
;;;; fires with a predicate over observable state (UTXO count / coins pointer /
;;;; tip) rather than a call counter, so an extra or missing check cannot silently
;;;; move the assertion.

(defun %p3b-reorg-fixture (suffix &optional view)
  "Active chain genesis -> A1 -> A2 -> A3 applied to VIEW, plus a competing fork
genesis -> B1 -> B2 -> B3 that is stored and indexed but NOT applied (equal work
per block, so connect-block leaves it inactive). VIEW defaults to a plain
utxo-set; pass a coins-view-cache to exercise the best-block pointer.
Returns (values chain-state view block-store a-entries b-entries)."
  (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
      (make-activate-block-fixture suffix view)
    (values chain-state utxo-set block-store
            (mapcar #'cdr (build-and-connect chain-state block-store utxo-set
                                              genesis-hash
                                              (make-test-chain-hashes #xA0 3)))
            (mapcar #'cdr (build-and-connect chain-state block-store utxo-set
                                              genesis-hash
                                              (make-test-chain-hashes #xB0 3))))))

(defun %p3b-coinbase-in-utxo-set-p (view block-store entry)
  "T if ENTRY's block contributed its coinbase output to VIEW — i.e. that block
is currently CONNECTED. Reads the block back from the store so the txid is the
post-round-trip one the UTXO set is actually keyed by."
  (let ((block (bl.store:get-block
                block-store (bl.store:block-index-entry-hash entry))))
    (and block
         (bl.store:utxo-exists-p
          view
          (bl.ser:transaction-hash
           (first (bl.ser:bitcoin-block-transactions block)))
          0))))

(test interrupt-check-is-wired-to-the-node-stop-flag
  "The seam must actually be INSTALLED. perform-reorg polls
bl:interrupt-requested-p, and every truncation test below binds its own
predicate into *interrupt-check* — so if node/shutdown.lisp ever stopped installing the
real one, reorgs would silently become uninterruptible again and every other test
here would stay green."
  (is (null (bl:interrupt-requested-p))
      "no stop requested: the installed predicate must say so")
  (let ((bl.net::*ibd-stop-requested* t))
    (is (bl:interrupt-requested-p)
        "the node-wide stop flag must reach the validation layer"))
  ;; Both flags, because they are set at different moments: the SIGTERM handler
  ;; registers the REQUEST (Core ShutdownRequested) and only stop-node later
  ;; sets the IBD flag. A loop that runs before stop-node — the mempool import
  ;; inside start-node — sees only the first.
  (let ((bl::*shutdown-request* (cons "test" 0)))
    (is (bl:interrupt-requested-p)
        "a REQUESTED shutdown must reach it too, before stop-node runs")))

(test reorg-completes-when-no-stop-is-requested
  "CONTROL for the two truncation tests below: the same fixture and the same
perform-reorg call, with no stop request, must run the whole reorg — otherwise
those tests could pass on a reorg that never worked at all."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store a-entries b-entries)
       (%p3b-reorg-fixture "p3b-control")
     (is (eq t (bl.val:perform-reorg
                chain-state block-store utxo-set
                (third a-entries) (third b-entries) :skip-scripts t)))
     (is (= 3 (bl.store:current-height chain-state)))
     (is (equalp (bl.store:block-index-entry-hash (third b-entries))
                 (bl.store:best-block-hash chain-state)))
     ;; Chain A's three coinbases out, chain B's three in.
     (is (= 3 (bl.store:utxo-count utxo-set)))
     (clear-undo-cache))))

(test reorg-stop-truncates-the-disconnect-at-a-block-boundary
  "A stop request during PHASE A must stop the disconnect on a block boundary and
leave the chain tip on the block the COINS reached — not on the old tip, which is
the state the whole phase is otherwise free to contradict. Before this, PHASE A
rewound the UTXO set for its entire duration without touching the tip, so a
shutdown (or the 600s destroy-thread fallback) landed mid-phase and persisted a
UTXO set that did not match the recorded tip."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store a-entries b-entries)
       (%p3b-reorg-fixture "p3b-disconnect")
     (let* ((a1 (first a-entries))
            ;; Fires at the top of the A1 iteration: A3 and A2 are already
            ;; disconnected (3 coinbases -> 1), A1's are still there.
            (bl:*interrupt-check*
              (lambda () (= 1 (bl.store:utxo-count utxo-set)))))
       (multiple-value-bind (ok detail)
           (bl.val:perform-reorg
            chain-state block-store utxo-set
            (third a-entries) (third b-entries) :skip-scripts t)
         (is (null ok))
         (is (eq :interrupted detail)))
       ;; Tip follows the coins: both are at A1.
       (is (= 1 (bl.store:current-height chain-state)))
       (is (equalp (bl.store:block-index-entry-hash a1)
                   (bl.store:best-block-hash chain-state)))
       (is (= 1 (bl.store:utxo-count utxo-set)))
       ;; The two disconnected blocks were downgraded; A1, still connected,
       ;; was not. (No claim about the B entries' status: connect-block stamps
       ;; a stored competing-fork block :valid, so status says nothing here —
       ;; the UTXO count above is what proves the fork never connected.)
       (is (zerop (count :valid (rest a-entries)
                         :key #'bl.store:block-index-entry-status)))
       (is (eq :valid (bl.store:block-index-entry-status a1)))
       (is (not (%p3b-coinbase-in-utxo-set-p utxo-set block-store (first b-entries)))))
     (clear-undo-cache))))

(test reorg-stop-truncates-the-connect-without-rolling-back
  "A stop request during PHASE B must stop after the last fully connected fork
block and leave the chain there. It must NOT run %rollback-partial-reorg: that is
minutes of interruptible work whose only purpose is to reach a consistent chain,
and a block boundary in PHASE B already IS one (the tip advances per connected
block). The next start simply reorgs the rest of the way."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store a-entries b-entries)
       (%p3b-reorg-fixture "p3b-connect")
     (let* ((b2-hash (bl.store:block-index-entry-hash (second b-entries)))
            ;; Fires at the top of the B3 iteration: B1 and B2 are connected and
            ;; the tip has advanced to B2. The tip never equals B2 during PHASE A
            ;; (it is the old tip A3 throughout, then the fork point), so this
            ;; cannot fire early.
            (bl:*interrupt-check*
              (lambda ()
                (equalp b2-hash (bl.store:best-block-hash chain-state)))))
       (multiple-value-bind (ok detail)
           (bl.val:perform-reorg
            chain-state block-store utxo-set
            (third a-entries) (third b-entries) :skip-scripts t)
         (is (null ok))
         (is (eq :interrupted detail)))
       ;; Parked on B2 — the fork's blocks that DID connect stay connected.
       (is (= 2 (bl.store:current-height chain-state)))
       (is (equalp b2-hash (bl.store:best-block-hash chain-state)))
       (is (= 2 (bl.store:utxo-count utxo-set)))
       ;; The rollback would have put us back on A3 with A's coinbases restored.
       (is (not (equalp (bl.store:block-index-entry-hash (third a-entries))
                        (bl.store:best-block-hash chain-state))))
       ;; B2 connected, B3 did not — the truncation is exactly one block deep.
       (is (%p3b-coinbase-in-utxo-set-p utxo-set block-store (second b-entries)))
       (is (not (%p3b-coinbase-in-utxo-set-p utxo-set block-store (third b-entries)))))
     (clear-undo-cache))))

(test reorg-stop-leaves-the-coins-pointer-and-the-tip-naming-one-block
  "The whole point of truncating on a boundary: the coins-DB best-block pointer
(phase 2) and the in-memory chain tip must name the SAME block afterwards, so the
shutdown flush persists a consistent pair and startup reconciliation (phase 3a)
has nothing to repair. Run against a real coins-view-cache, where the pointer
actually exists."
  (with-network (:mainnet)
   (bl.store:with-coins-view-db
       (base (ensure-directories-exist
              (merge-pathnames "coins/"
                               (activate-block-base-path "p3b-pointer"))))
     (let ((cache (bl.store:make-coins-view-cache base)))
       (multiple-value-bind (chain-state view block-store a-entries b-entries)
           (%p3b-reorg-fixture "p3b-pointer" cache)
         (let* ((a1-hash (bl.store:block-index-entry-hash (first a-entries)))
                ;; Fires once the coins have been rewound to A1 — expressed over
                ;; the pointer itself, which is the thing under test.
                (bl:*interrupt-check*
                  (lambda ()
                    (equalp a1-hash (bl.store:cvc-best-block view)))))
           ;; Control: before the reorg the pointer names the old tip A3.
           (is (equalp (bl.store:block-index-entry-hash (third a-entries))
                       (bl.store:cvc-best-block view)))
           (multiple-value-bind (ok detail)
               (bl.val:perform-reorg
                chain-state block-store view
                (third a-entries) (third b-entries) :skip-scripts t)
             (is (null ok))
             (is (eq :interrupted detail)))
           (is (equalp a1-hash (bl.store:cvc-best-block view)))
           (is (equalp (bl.store:cvc-best-block view)
                       (bl.store:best-block-hash chain-state))
               "the coins pointer and the chain tip must name one block")
           (is (= 1 (bl.store:current-height chain-state)))))
       (clear-undo-cache)))))

;;;; GA9 S1-4: an invalidated entry must never be resurrected

(test ga9-s1-4-invalid-block-is-not-resurrected
  "Core never rebuilds a CBlockIndex — AddToBlockIndex is a try_emplace that
returns the existing object (node/blockstorage.cpp:228-231) — and
AcceptBlockHeader refuses a known-invalid block with `duplicate-invalid'
(validation.cpp:4231-4235) and any block on an invalid parent with
`bad-prevblk' (:4252-4255).

We had none of that: connect-block constructed a FRESH entry with
:status :valid and add-block-index-entry is a plain (setf gethash), a replace
that erased the :invalid mark. So invalidateblock was undone by a single
unsolicited block message — the RPC reorgs down and marks the block invalid,
leaving the tip at its parent, so a peer replaying the block hits the
tip-extension arm, passes validate-block (it IS consensus-valid; the
invalidation is a manual override) and was re-created as valid. The operator's
node silently rejoined the chain they had refused.

Asserted at the acceptance gate, which is where a peer's message actually
arrives."
  (let* ((chain-state (bl.store:make-chain-state))
         (genesis-hash (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 1))
         (bad-hash (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 2))
         (bad-block (make-reorg-test-block genesis-hash bad-hash 1))
         (bad-real-hash (bl.ser:block-header-hash
                         (bl.ser:bitcoin-block-header bad-block))))
    ;; Genesis-ish parent, on the active chain.
    (bl.store:add-block-index-entry
     chain-state (bl.store:make-block-index-entry
                  :hash genesis-hash :height 0 :chain-work 1 :status :valid))
    (bl.store:update-chain-tip chain-state genesis-hash 0)
    ;; The operator (or the validator) has marked this block invalid.
    (bl.store:add-block-index-entry
     chain-state (bl.store:make-block-index-entry
                  :hash bad-real-hash :height 1 :chain-work 2 :status :invalid))
    (multiple-value-bind (ok err)
        (bl.net::accept-downloaded-block
         bad-block chain-state (bl.store:make-utxo-set) nil)
      (is-false ok "a block already marked invalid must not be accepted")
      (is (eq :duplicate-invalid err)
          "and it must be refused as Core's duplicate-invalid, got ~S" err))
    ;; The mark must still be there afterwards — the whole point.
    (is (eq :invalid (bl.store:block-index-entry-status
                      (bl.store:get-block-index-entry
                       chain-state bad-real-hash)))
        "the :invalid mark must survive the acceptance attempt")
    ;; A child of the invalid block: Core's bad-prevblk.
    (let* ((child-hash (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 3))
           (child (make-reorg-test-block bad-real-hash child-hash 2)))
      (multiple-value-bind (ok err)
          (bl.net::accept-downloaded-block
           child chain-state (bl.store:make-utxo-set) nil)
        (is-false ok "a block building on an invalid parent must be refused")
        (is (eq :bad-prevblk err)
            "and refused as Core's bad-prevblk, got ~S" err)))))

(test ga9-s1-5-getblocktxn-depth-limit
  "Core serves a blocktxn only within MAX_BLOCKTXN_DEPTH (10) of the tip and
otherwise sends the whole block, for the reason its own comment gives
(net_processing.cpp:4380-4387): a small reply for an expensive disk read lets a
peer trigger those reads for free, so it is made to receive the data instead.

We had no depth test. Every historical block hash is public, GET-BLOCK has no
cache, and the pump grants each peer 32 messages per pass — so ~40 wire bytes
bought a full read and parse of up to a 4 MB block, on the same thread that
runs validation. This asserts the arithmetic of the gate, which is the part
that decides whether the read happens at all."
  (flet ((within-depth-p (block-height tip-height)
           (>= block-height (- tip-height bl.net::+max-blocktxn-depth+))))
    (is (= 10 bl.net::+max-blocktxn-depth+)
        "Core MAX_BLOCKTXN_DEPTH is 10")
    (is-true (within-depth-p 1000 1000) "the tip itself is servable")
    (is-true (within-depth-p 990 1000) "exactly 10 deep is servable")
    (is-false (within-depth-p 989 1000) "11 deep is not — Core sends the block")
    (is-false (within-depth-p 1 1000)
              "and an ancient block, which is the whole attack, is refused")))

(test ga9-s2-10-reorg-flushes-the-coins-cache
  "Core calls FlushStateToDisk(IF_NEEDED) at the end of BOTH DisconnectTip
(validation.cpp:2966) and ConnectTip (:3093), so the coins cache is size-checked
once per disconnected and per connected block, including mid-reorg. We had
exactly ONE flush call site in the whole tree — the tip-extension path of
connect-block — so perform-reorg's loops ran with nothing draining the cache.

The sharp path is a deep rollback: dumptxoutset to an assumeutxo height, or
invalidateblock on an old hash, disconnects tens of thousands of blocks in one
uninterrupted loop, each restoring its spent prevouts as dirty entries. This
heap has been OOM-killed twice on this cache.

IF_NEEDED acts on Core's CRITICAL tier (cacheSize > total budget,
validation.cpp:2690/2763), NOT the LARGE tier that periodic flushes use — so
this must not reuse maybe-periodic-flush, whose count and time triggers would
turn a deep rollback into a flush storm."
  (is (fboundp 'bl:maybe-critical-flush)
      "the mid-reorg check must exist")
  ;; With no node bound it must be inert rather than erroring: perform-reorg
  ;; runs in unit tests with no *node*.
  (let ((bl:*node* nil))
    (is-false (bl:maybe-critical-flush nil)
              "no node: inert, not an error"))
  ;; And the reorg's disconnect loop must actually call it — the whole finding
  ;; was that the function existed but was unreachable from perform-reorg.
  (let ((src (uiop:read-file-string
              (merge-pathnames "src/validation/block.lisp"
                               (asdf:system-source-directory :bitcoin-lisp)))))
    (is (search "maybe-critical-flush" src)
        "perform-reorg must reference the check; a flush function nothing calls
         is exactly the bug this fixes")))

(test txindex-resume-rewinds-to-the-fork-instead-of-genesis
  "A marker left on a disconnected block must resume at the FORK POINT, not at
genesis.

The sibling tests above fix the causes of an off-chain marker; this fixes its
COST. Core rewinds the index to the fork (BaseIndex::Rewind, index/base.cpp:290);
answering 0 rescans the whole chain. Observed live on testnet4 2026-08-25: a
restart that happened to follow a reorg rebuilt a 149k-block index from height
0, and testnet4 reorgs often. On mainnet that is hours.

The marker is planted on the LOSING branch deliberately — that is the only
state that produced the full rescan, and no amount of fixing the reorg drive
sites removes it, since a crash between disconnect and marker update recreates
it."
  (with-network (:mainnet)
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (make-activate-block-fixture "txindex-rewind")
     (let* ((txdir (ensure-directories-exist
                    (merge-pathnames (format nil "test-txidx-rewind-~D/"
                                             (get-internal-real-time))
                                     (uiop:temporary-directory))))
            (txindex (bl.store:init-tx-index txdir)))
       (unwind-protect
            (progn
              ;; Two blocks on the original branch, then a heavier fork that
              ;; replaces them.
              (build-and-connect chain-state block-store utxo-set genesis-hash
                                  (make-test-chain-hashes #xA0 2))
              (let ((losing-tip (bl.store:best-block-hash chain-state)))
                (%stage-heavier-downloaded-fork chain-state block-store genesis-hash)
                (let ((bl.net:*ibd-context*
                        (bl.net::make-ibd-context)))
                  (bl.net::run-ibd nil (bl.ctx:make-node-context :chain-state chain-state :utxo-set utxo-set :block-store block-store)))
                ;; The marker names a block the reorg disconnected.
                (bl.store:txindex-set-best-block txindex losing-tip)
                (multiple-value-bind (height reason)
                    (bl.store::%txindex-resume-height txindex chain-state)
                  (is (eq :rewound-to-fork reason)
                      "resumed with ~S, wanted :rewound-to-fork" reason)
                  (is (plusp height)
                      "rewound to height ~D — that is a full rescan from genesis"
                      height))))
         (bl.store:close-tx-index txindex)
         (uiop:delete-directory-tree txdir :validate t :if-does-not-exist :ignore)))
     (clear-undo-cache))))
