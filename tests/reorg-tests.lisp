(in-package #:bitcoin-lisp.tests)

(def-suite :reorg-tests
  :description "Tests for chain reorganization logic"
  :in :bitcoin-lisp-tests)

(in-suite :reorg-tests)

;;;; Helpers for building test chains

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
      (let ((new-entry (bitcoin-lisp.storage:make-block-index-entry
                        :hash (make-reorg-hash (+ h (* 1000 (if prev (bitcoin-lisp.storage:block-index-entry-height prev) 0))))
                        :height h
                        :header nil
                        :prev-entry entry
                        :chain-work (+ base-work h)
                        :status :valid)))
        (when chain-state
          (bitcoin-lisp.storage:add-block-index-entry chain-state new-entry))
        (setf entry new-entry)))
    entry))

;;; Fork point detection tests

(test find-fork-point-same-chain
  "Fork point of two entries on the same chain is the earlier one."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         (block2 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 2) :height 2 :prev-entry block1 :chain-work 2 :status :valid)))
    (let ((fork (bitcoin-lisp.validation:find-fork-point block2 block1)))
      (is (not (null fork)))
      (is (= 1 (bitcoin-lisp.storage:block-index-entry-height fork))))))

(test find-fork-point-diverging-chains
  "Fork point of two diverging chains is the common ancestor."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         ;; Chain A: genesis -> 1 -> 2a -> 3a
         (block2a (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 20) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3a (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 30) :height 3 :prev-entry block2a :chain-work 3 :status :valid))
         ;; Chain B: genesis -> 1 -> 2b -> 3b
         (block2b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 21) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 31) :height 3 :prev-entry block2b :chain-work 3 :status :valid)))
    (let ((fork (bitcoin-lisp.validation:find-fork-point block3a block3b)))
      (is (not (null fork)))
      ;; Fork point is block1 (height 1)
      (is (= 1 (bitcoin-lisp.storage:block-index-entry-height fork)))
      (is (equalp (make-reorg-hash 1) (bitcoin-lisp.storage:block-index-entry-hash fork))))))

(test find-fork-point-different-lengths
  "Fork point works when chains have different lengths."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         ;; Short chain: genesis -> 1 -> 2a
         (block2a (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 20) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         ;; Long chain: genesis -> 1 -> 2b -> 3b -> 4b
         (block2b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 21) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 31) :height 3 :prev-entry block2b :chain-work 3 :status :valid))
         (block4b (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 41) :height 4 :prev-entry block3b :chain-work 4 :status :valid)))
    (let ((fork (bitcoin-lisp.validation:find-fork-point block2a block4b)))
      (is (= 1 (bitcoin-lisp.storage:block-index-entry-height fork))))))

;;; Collect chain entries tests

(test collect-chain-entries-basic
  "Collect entries from tip back to (not including) fork point."
  (let* ((genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash (make-reorg-hash 0) :height 0 :prev-entry nil :chain-work 0 :status :valid))
         (block1 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 1) :height 1 :prev-entry genesis :chain-work 1 :status :valid))
         (block2 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 2) :height 2 :prev-entry block1 :chain-work 2 :status :valid))
         (block3 (bitcoin-lisp.storage:make-block-index-entry
                  :hash (make-reorg-hash 3) :height 3 :prev-entry block2 :chain-work 3 :status :valid)))
    (let ((entries (bitcoin-lisp.validation::collect-chain-entries block3 genesis)))
      ;; collect-chain-entries walks tip→fork, pushes, then nreverses
      ;; Result order: fork-adjacent first, tip last
      (is (= 3 (length entries)))
      ;; Verify all heights are present (order may vary)
      (let ((heights (mapcar #'bitcoin-lisp.storage:block-index-entry-height entries)))
        (is (member 1 heights))
        (is (member 2 heights))
        (is (member 3 heights))))))

;;; UTXO reorg consistency

(test utxo-apply-disconnect-roundtrip
  "Apply then disconnect a block should restore original UTXO state."
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xDD))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Initial state: one UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 100000 script 50)
    (let ((initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
      ;; Apply block that spends it
      (let* ((coinbase (make-e2e-coinbase-tx))
             (spending (make-e2e-regular-tx :prev-txid prev-txid :prev-index 0 :value 90000))
             (block (make-e2e-block (list coinbase spending))))
        (let ((spent-utxos (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block 51)))
          ;; State changed
          (is (not (= initial-count (bitcoin-lisp.storage:utxo-count utxo-set))))
          ;; Disconnect
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block spent-utxos)
          ;; State restored
          (is (= initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
          ;; Original UTXO is back
          (is (bitcoin-lisp.storage:utxo-exists-p utxo-set prev-txid 0))
          (let ((entry (bitcoin-lisp.storage:get-utxo utxo-set prev-txid 0)))
            (is (= 100000 (bitcoin-lisp.storage:utxo-entry-value entry)))))))))

(test utxo-multi-block-disconnect
  "Disconnecting multiple blocks in reverse restores the original state."
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xE1))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Initial UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 200000 script 10)
    (let ((initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
      ;; Block 1: spends txid1
      (let* ((cb1 (make-e2e-coinbase-tx :height 11))
             (tx1 (make-e2e-regular-tx :prev-txid txid1 :prev-index 0 :value 190000))
             (block1 (make-e2e-block (list cb1 tx1)))
             (spent1 (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block1 11)))
        ;; Block 2: spends block1's coinbase
        (let* ((cb1-txid (bitcoin-lisp.serialization:transaction-hash cb1))
               (cb2 (make-e2e-coinbase-tx :height 12))
               (tx2 (make-e2e-regular-tx :prev-txid cb1-txid :prev-index 0 :value 4999000000))
               (block2 (make-e2e-block (list cb2 tx2)))
               (spent2 (bitcoin-lisp.storage:apply-block-to-utxo-set utxo-set block2 12)))
          ;; Disconnect block2 then block1
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block2 spent2)
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set utxo-set block1 spent1)
          ;; Original state restored
          (is (= initial-count (bitcoin-lisp.storage:utxo-count utxo-set)))
          (is (bitcoin-lisp.storage:utxo-exists-p utxo-set txid1 0)))))))

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
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (initial-txid (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element #xC1))
         (script (make-array 25 :element-type '(unsigned-byte 8)
                                :initial-element #x76)))
    ;; Pre-existing UTXO consumed by block 1.
    (bitcoin-lisp.storage:add-utxo utxo-set initial-txid 0 200000 script 10)
    (let* ((cb1 (make-e2e-coinbase-tx :height 11))
           ;; Block 1: tx spends initial-txid:0, creates X (this tx's :0).
           (tx-x (make-e2e-regular-tx :prev-txid initial-txid :prev-index 0
                                       :value 190000))
           (block1 (make-e2e-block (list cb1 tx-x)))
           (x-txid (bitcoin-lisp.serialization:transaction-hash tx-x))
           (spent1 (bitcoin-lisp.storage:apply-block-to-utxo-set
                    utxo-set block1 11)))
      ;; Block 2: tx spends X (cross-block dependency).
      (let* ((cb2 (make-e2e-coinbase-tx :height 12))
             (tx-y (make-e2e-regular-tx :prev-txid x-txid :prev-index 0
                                         :value 180000))
             (block2 (make-e2e-block (list cb2 tx-y)))
             (spent2 (bitcoin-lisp.storage:apply-block-to-utxo-set
                      utxo-set block2 12)))
        ;; Disconnect in WRONG order (fork-to-tip: block1 first). This
        ;; emulates the bug: with the (reverse to-disconnect) flip in
        ;; perform-reorg, the lower block was processed first.
        (bitcoin-lisp.storage:disconnect-block-from-utxo-set
         utxo-set block1 spent1)
        (bitcoin-lisp.storage:disconnect-block-from-utxo-set
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
        (is (bitcoin-lisp.storage:utxo-exists-p utxo-set x-txid 0))))
    ;; Now repeat with the CORRECT order and assert X is gone.
    (let ((utxo-set2 (bitcoin-lisp.storage:make-utxo-set)))
      (bitcoin-lisp.storage:add-utxo utxo-set2 initial-txid 0 200000 script 10)
      (let* ((cb1 (make-e2e-coinbase-tx :height 11))
             (tx-x (make-e2e-regular-tx :prev-txid initial-txid :prev-index 0
                                         :value 190000))
             (block1 (make-e2e-block (list cb1 tx-x)))
             (x-txid (bitcoin-lisp.serialization:transaction-hash tx-x))
             (spent1 (bitcoin-lisp.storage:apply-block-to-utxo-set
                      utxo-set2 block1 11)))
        (let* ((cb2 (make-e2e-coinbase-tx :height 12))
               (tx-y (make-e2e-regular-tx :prev-txid x-txid :prev-index 0
                                           :value 180000))
               (block2 (make-e2e-block (list cb2 tx-y)))
               (spent2 (bitcoin-lisp.storage:apply-block-to-utxo-set
                        utxo-set2 block2 12)))
          ;; Correct order: block2 (tip) first, block1 (fork-adjacent) last.
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set
           utxo-set2 block2 spent2)
          (bitcoin-lisp.storage:disconnect-block-from-utxo-set
           utxo-set2 block1 spent1)
          (is (not (bitcoin-lisp.storage:utxo-exists-p utxo-set2 x-txid 0)))
          (is (bitcoin-lisp.storage:utxo-exists-p utxo-set2 initial-txid 0)))))))

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

(defun %use-activate-block-test-base-path (suffix)
  (ensure-directories-exist
   (merge-pathnames (format nil "test-activate-block-~A/" suffix)
                    (uiop:temporary-directory))))

(defmacro %with-mainnet-network (&body body)
  "Bind *network* to :mainnet so version-1 test blocks pass the
BIP34 activation check (testnet4 activates BIP34 at h=1, which would
otherwise reject the synthetic make-reorg-test-block blocks)."
  `(let ((bitcoin-lisp:*network* :mainnet))
     ,@body))

;; make-reorg-test-block was replaced by the unified make-reorg-test-block
;; (persistence-tests.lisp) — that helper now derives script-sig from
;; block-hash and computes a real merkle root, so it satisfies both the
;; direct-connect-block path (older tests) and the activate-block / full
;; validate-block path (these tests) without per-test duplication.

(defun %make-activate-block-fixture (suffix)
  "Returns (values chain-state utxo-set block-store genesis-hash). The
genesis index entry has a dummy header so validate-block's MTP walk
doesn't trip on a NIL header."
  (let* ((base-path (%use-activate-block-test-base-path suffix))
         (chain-state (bitcoin-lisp.storage:init-chain-state base-path))
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (block-store (bitcoin-lisp.storage:init-block-store base-path))
         (genesis-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (genesis-header
           (bitcoin-lisp.serialization:make-block-header
            :version 1
            :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)
            :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 0)
            :timestamp 1231006505 :bits #x1d00ffff :nonce 0
            :cached-hash genesis-hash)))
    (clrhash bitcoin-lisp.validation::*block-undo-data*)
    (bitcoin-lisp.storage:add-block-index-entry
     chain-state
     (bitcoin-lisp.storage:make-block-index-entry
      :hash genesis-hash :height 0 :chain-work 1 :status :valid
      :header genesis-header))
    (values chain-state utxo-set block-store genesis-hash)))

(defun %build-and-connect (chain-state block-store utxo-set genesis-hash hashes)
  "Build a chain of coinbase-only blocks from GENESIS-HASH using HASHES,
connecting each via connect-block. Returns the list of (block . index-entry)
pairs in connect order."
  (let ((prev-hash genesis-hash)
        (results '()))
    (loop for h from 1
          for block-hash in hashes
          do (let ((block (make-reorg-test-block prev-hash block-hash h)))
               (bitcoin-lisp.validation:connect-block
                block chain-state block-store utxo-set)
               (push (cons block (bitcoin-lisp.storage:get-block-index-entry
                                  chain-state block-hash))
                     results)
               (setf prev-hash block-hash)))
    (nreverse results)))

(test activate-block-extends-current-tip
  "When the incoming block's parent IS the current tip, activate-block
should extend the chain normally."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "extends-tip")
    ;; Build chain A: genesis → A1 → A2.
    (%build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 2))
    (is (= 2 (bitcoin-lisp.storage:current-height chain-state)))
    ;; Build A3 extending the tip; receive it via activate-block.
    (let* ((a2-hash (bitcoin-lisp.storage:best-block-hash chain-state))
           (a3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                      (setf (aref h 0) #xA0) (setf (aref h 1) 3) h))
           (a3-block (make-reorg-test-block a2-hash a3-hash 3)))
      (multiple-value-bind (activated error)
          (bitcoin-lisp.validation:activate-block
           a3-block chain-state block-store utxo-set :skip-scripts t)
        (is (eq t activated))
        (is (null error))
        (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
        (is (equalp a3-hash (bitcoin-lisp.storage:best-block-hash chain-state)))))
    (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test activate-block-pre-reorgs-on-stronger-fork
  "When the incoming block's parent sits on a competing fork that, with
this block added, has strictly more chain-work than current tip,
activate-block should pre-reorg to the new fork and then activate the
block. Chain tip should land on the new fork's tip."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "stronger-fork")
    ;; Chain A: genesis → A1 → A2. Active.
    (%build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 2))
    (let ((a-tip-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
      ;; Pre-build chain B: genesis → B1 → B2 (both stored + indexed but
      ;; NOT applied to UTXO). Each B-block's chain-work matches the
      ;; corresponding A-block's, so chain B reaches A's work at h=2 and
      ;; will overtake at h=3.
      (let ((b-hashes (make-test-chain-hashes #xB0 2))
            (prev-hash genesis-hash))
        (loop for h from 1 to 2
              for block-hash in b-hashes
              do (let ((block (make-reorg-test-block prev-hash block-hash h)))
                   (bitcoin-lisp.storage:store-block block-store block)
                   ;; connect-block on a non-extending block stores it
                   ;; with the appropriate :valid status + chain-work.
                   (bitcoin-lisp.validation:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash)))
        ;; After both forks have 2 blocks each, A is still tip (race-pick
        ;; — first-seen wins on equal-work).
        (is (equalp a-tip-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
        (is (= 2 (bitcoin-lisp.storage:current-height chain-state))))

      ;; Now receive B3, which extends B2. B3 has more chain-work than
      ;; A2, so activate-block must pre-reorg from A2 → B2 then connect.
      (let* ((b2-hash (second (make-test-chain-hashes #xB0 2)))
             (b3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                        (setf (aref h 0) #xB0) (setf (aref h 1) 3) h))
             (b3-block (make-reorg-test-block b2-hash b3-hash 3)))
        (multiple-value-bind (activated error)
            (bitcoin-lisp.validation:activate-block
             b3-block chain-state block-store utxo-set :skip-scripts t)
          (is (eq t activated))
          (is (null error))
          ;; Chain tip is now B3.
          (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
          (is (equalp b3-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
          ;; UTXO set reflects B chain: B1, B2, B3 coinbase outputs
          ;; present; A1, A2 absent. (Each coinbase txid is unique per
          ;; make-reorg-test-block, derived from block-hash.)
          (is (= 3 (bitcoin-lisp.storage:utxo-count utxo-set))))))
    (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test reorg-rejects-fork-carrying-invalid-block
  "CC-1 regression. A competing fork with strictly more work but carrying an
INVALID block (here B2 has an over-value coinbase) must be REJECTED during the
reorg: the invalid block must never enter the UTXO set, and the node must roll
back to its original valid chain. Before the fix, perform-reorg applied fork
blocks with apply-block-to-utxo-set and NO validate-block — so a more-work fork
(cheap to mine under testnet4's min-difficulty rule) could inject any invalid
block into the chainstate."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "reorg-invalid-fork")
    ;; Chain A: genesis -> A1 -> A2. Active and valid.
    (%build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 2))
    (let ((a-tip-hash (bitcoin-lisp.storage:best-block-hash chain-state))
          (a-utxo-count (bitcoin-lisp.storage:utxo-count utxo-set)))
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
                   (bitcoin-lisp.storage:store-block block-store block)
                   (bitcoin-lisp.validation:connect-block
                    block chain-state block-store utxo-set)
                   (setf prev-hash block-hash)))
        (is (equalp a-tip-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
        (is (= 2 (bitcoin-lisp.storage:current-height chain-state))))
      ;; Receive B3 (extends B2): chain B now has more work than A2, so
      ;; activate-block pre-reorgs A2 -> B2. perform-reorg validates B1 (ok)
      ;; then B2 (over-value coinbase) -> fails -> rolls back to A.
      (let* ((b2-hash (second (make-test-chain-hashes #xB0 2)))
             (b3-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 0)))
                        (setf (aref h 0) #xB0) (setf (aref h 1) 3) h))
             (b3-block (make-reorg-test-block b2-hash b3-hash 3)))
        (multiple-value-bind (activated error)
            (bitcoin-lisp.validation:activate-block
             b3-block chain-state block-store utxo-set :skip-scripts t)
          ;; Reorg rejected, surfacing the fork block's validation error.
          (is (null activated))
          (is (eq :coinbase-too-large error))
          ;; Node rolled back to chain A — tip, height, and UTXO unchanged.
          (is (equalp a-tip-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
          (is (= 2 (bitcoin-lisp.storage:current-height chain-state)))
          (is (= a-utxo-count (bitcoin-lisp.storage:utxo-count utxo-set)))
          ;; The invalid B2 coinbase never entered the UTXO set.
          (is (null (bitcoin-lisp.storage:get-utxo
                     utxo-set
                     (bitcoin-lisp.serialization:transaction-hash
                      (first (bitcoin-lisp.serialization:bitcoin-block-transactions
                              (make-reorg-test-block
                               (first (make-test-chain-hashes #xB0 2))
                               b2-hash 2 :value 5000000001))))
                     0)))))
      (clrhash bitcoin-lisp.validation::*block-undo-data*)))))

(test activate-block-stores-weaker-fork-without-activating
  "When the incoming block's parent sits on a competing fork whose
total work doesn't exceed current tip's, activate-block returns
:weaker-chain and stores the block in the block-store but doesn't
update the chain tip."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "weaker-fork")
    ;; Chain A has 3 blocks.
    (%build-and-connect chain-state block-store utxo-set genesis-hash
                        (make-test-chain-hashes #xA0 3))
    (let ((a-tip-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
      (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
      ;; Pre-store B1 on a competing fork (1 block, weaker than A's 3).
      (let* ((b1-hash (first (make-test-chain-hashes #xB0 1)))
             (b1-block (make-reorg-test-block genesis-hash b1-hash 1)))
        (bitcoin-lisp.validation:connect-block b1-block chain-state block-store utxo-set)
        ;; Now receive B2 extending B1. Total work for B = 2, still less
        ;; than A's 3. activate-block should NOT reorg.
        (let* ((b2-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                          (setf (aref h 0) #xB0) (setf (aref h 1) 2) h))
               (b2-block (make-reorg-test-block b1-hash b2-hash 2)))
          (multiple-value-bind (activated error)
              (bitcoin-lisp.validation:activate-block
               b2-block chain-state block-store utxo-set :skip-scripts t)
            (is (null activated))
            (is (eq error :weaker-chain))
            ;; Chain tip unchanged.
            (is (equalp a-tip-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
            (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
            ;; B2 IS in the block store for future reorg consideration.
            (is (not (null (bitcoin-lisp.storage:get-block block-store b2-hash))))))))
    (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test activate-block-unknown-parent
  "When the incoming block's parent isn't in the chain index,
activate-block returns :unknown-parent without doing anything."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "unknown-parent")
    (declare (ignore genesis-hash))
    (%build-and-connect chain-state block-store utxo-set
                        (bitcoin-lisp.storage:best-block-hash chain-state)
                        (make-test-chain-hashes #xA0 1))
    (let* ((mystery-prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC))
           (orphan-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                          (setf (aref h 0) #xCC) (setf (aref h 1) 1) h))
           (orphan (make-reorg-test-block mystery-prev orphan-hash 5)))
      (multiple-value-bind (activated error)
          (bitcoin-lisp.validation:activate-block
           orphan chain-state block-store utxo-set :skip-scripts t)
        (is (null activated))
        (is (eq error :unknown-parent))
        ;; Chain unchanged.
        (is (= 1 (bitcoin-lisp.storage:current-height chain-state)))))
    (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test invalidate-and-reconsider-block
  "invalidate-block marks a block + descendants invalid and reorgs to its parent;
reconsider-block clears the flags and reorgs back to the best valid chain."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "invalidate")
     ;; genesis -> A1 -> A2 -> A3
     (let ((hashes (make-test-chain-hashes #xA0 3)))
       (%build-and-connect chain-state block-store utxo-set genesis-hash hashes)
       (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
       (let ((a2-hash (second hashes)))
         ;; invalidate A2 -> chain reorgs back to A1 (height 1); A2 + A3 invalid
         (multiple-value-bind (ok reason)
             (bitcoin-lisp.validation:invalidate-block
              chain-state block-store utxo-set a2-hash)
           (is (eq t ok))
           (is (null reason)))
         (is (= 1 (bitcoin-lisp.storage:current-height chain-state)))
         (is (eq :invalid (bitcoin-lisp.storage:block-index-entry-status
                           (bitcoin-lisp.storage:get-block-index-entry chain-state a2-hash))))
         (is (eq :invalid (bitcoin-lisp.storage:block-index-entry-status
                           (bitcoin-lisp.storage:get-block-index-entry chain-state (third hashes)))))
         ;; reconsider A2 -> chain reorgs forward to A3 (height 3) again
         (multiple-value-bind (ok reason)
             (bitcoin-lisp.validation:reconsider-block
              chain-state block-store utxo-set a2-hash)
           (is (eq t ok))
           (is (null reason)))
         (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
         (is (not (eq :invalid (bitcoin-lisp.storage:block-index-entry-status
                                (bitcoin-lisp.storage:get-block-index-entry chain-state a2-hash)))))))
     ;; invalidating genesis is refused; unknown hash too
     (multiple-value-bind (ok reason)
         (bitcoin-lisp.validation:invalidate-block chain-state block-store utxo-set genesis-hash)
       (is (null ok)) (is (eq :cannot-invalidate-genesis reason)))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test precious-block
  "preciousblock reorgs to a chosen block of >= the tip's work; equal-work
competitors don't displace it (strict-> fork choice), and it can flip between
equal-work forks."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "precious")
     (let ((a-hashes (make-test-chain-hashes #xA0 1)))
       (%build-and-connect chain-state block-store utxo-set genesis-hash a-hashes)
       (let* ((a1-hash (first a-hashes))
              (a1-entry (bitcoin-lisp.storage:get-block-index-entry chain-state a1-hash))
              (genesis-entry (bitcoin-lisp.storage:get-block-index-entry chain-state genesis-hash))
              (b1-hash (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                         (setf (aref h 0) #xB0) (setf (aref h 1) 1) h))
              (b1-block (make-reorg-test-block genesis-hash b1-hash 1)))
         (is (equalp a1-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
         ;; Stand up an equal-work competing fork B1 (block + header-valid index
         ;; entry, as header sync would in real operation).
         (bitcoin-lisp.storage:store-block block-store b1-block)
         (bitcoin-lisp.storage:add-block-index-entry
          chain-state
          (bitcoin-lisp.storage:make-block-index-entry
           :hash b1-hash :height 1
           :chain-work (bitcoin-lisp.storage:block-index-entry-chain-work a1-entry)
           :status :header-valid
           :header (bitcoin-lisp.serialization:bitcoin-block-header b1-block)
           :prev-entry genesis-entry))
         ;; precious the current tip -> no-op
         (is (eq t (bitcoin-lisp.validation:precious-block chain-state block-store utxo-set a1-hash)))
         (is (equalp a1-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
         ;; precious B1 -> reorg to the equal-work B1
         (multiple-value-bind (ok reason)
             (bitcoin-lisp.validation:precious-block chain-state block-store utxo-set b1-hash)
           (is (eq t ok)) (is (null reason)))
         (is (equalp b1-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
         ;; precious A1 -> flip back (both forks equal work)
         (bitcoin-lisp.validation:precious-block chain-state block-store utxo-set a1-hash)
         (is (equalp a1-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
         ;; unknown block -> error
         (multiple-value-bind (ok reason)
             (bitcoin-lisp.validation:precious-block
              chain-state block-store utxo-set
              (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE))
           (is (null ok)) (is (eq :block-not-found reason)))))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test rpc-verifychain-reads-stored-blocks
  "verifychain (checklevel 0) confirms the last N stored blocks read back from
the block store."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "verifychain")
     (%build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #x70 3))
     (let ((node (bitcoin-lisp::make-node)))
       (setf (bitcoin-lisp::node-chain-state node) chain-state)
       (setf (bitcoin-lisp::node-block-store node) block-store)
       (is (eq t (bitcoin-lisp.rpc::rpc-verifychain node (list 0 3)))))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test rpc-getchaintxstats-window
  "getchaintxstats computes window tx counts over connected blocks (coinbase-only
test blocks: 1 tx each), and tx-count round-trips through the v2 header index."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "chaintxstats")
     (%build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #x71 3))
     (let ((node (bitcoin-lisp::make-node)))
       (setf (bitcoin-lisp::node-chain-state node) chain-state)
       (setf (bitcoin-lisp::node-block-store node) block-store)
       (let ((r (bitcoin-lisp.rpc::rpc-getchaintxstats node (list 2))))
         (is (= 3 (cdr (assoc "window_final_block_height" r :test #'string=))))
         (is (= 2 (cdr (assoc "window_block_count" r :test #'string=))))
         (is (= 2 (cdr (assoc "window_tx_count" r :test #'string=))))
         (is (integerp (cdr (assoc "window_interval" r :test #'string=)))))
       ;; tx-count persists through the v2 header index.
       (bitcoin-lisp.storage:save-header-index chain-state)
       (let ((cs2 (bitcoin-lisp.storage:make-chain-state
                   :base-path (bitcoin-lisp.storage::chain-state-base-path chain-state))))
         (is-true (bitcoin-lisp.storage:load-header-index cs2))
         (let ((tip (bitcoin-lisp.storage:get-block-index-entry
                     cs2 (bitcoin-lisp.storage:best-block-hash chain-state))))
           (is (= 1 (bitcoin-lisp.storage:block-index-entry-tx-count tip)))))
       ;; blockcount >= height -> error (Core's bound).
       (signals bitcoin-lisp.rpc::rpc-error
         (bitcoin-lisp.rpc::rpc-getchaintxstats node (list 99))))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

(test rpc-getchaintxstats-genesis-backfill
  "txcount stays known on a v1-upgraded index: genesis is never in the block
store, so its zeroed tx-count is backfilled definitionally (exactly its
coinbase) instead of being dropped as unreadable."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "chaintxstats-genesis")
     (%build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #x72 3))
     ;; Simulate a v1-loaded index: genesis entry's tx-count is 0.
     (let ((genesis-entry (bitcoin-lisp.storage:get-block-index-entry
                           chain-state genesis-hash)))
       (setf (bitcoin-lisp.storage:block-index-entry-tx-count genesis-entry) 0)
       (let ((node (bitcoin-lisp::make-node)))
         (setf (bitcoin-lisp::node-chain-state node) chain-state)
         (setf (bitcoin-lisp::node-block-store node) block-store)
         (let ((r (bitcoin-lisp.rpc::rpc-getchaintxstats node (list 2))))
           ;; genesis (1) + three coinbase-only blocks.
           (is (= 4 (cdr (assoc "txcount" r :test #'string=))))
           (is (= 2 (cdr (assoc "window_tx_count" r :test #'string=))))))
       ;; The definitional count is cached back onto the entry.
       (is (= 1 (bitcoin-lisp.storage:block-index-entry-tx-count genesis-entry))))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

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
         (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                            :initial-element 0)
                                                          :index #xFFFFFFFF)
                                        :script-sig script-sig))
                       :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                         :value value
                                         :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                    :initial-element #x76))
                                        (bitcoin-lisp.serialization:make-tx-out :value 0 :script-pubkey commit))
                       :lock-time 0))
         (merkle-root (bitcoin-lisp.validation:compute-merkle-root
                       (list (bitcoin-lisp.serialization:transaction-hash coinbase-tx))))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1 :prev-block prev-hash :merkle-root merkle-root
                  :timestamp (+ 1231006505 (* height 600)) :bits #x1d00ffff :nonce 0
                  :cached-hash block-hash)))
    (bitcoin-lisp.serialization:make-bitcoin-block :header header :transactions (list coinbase-tx))))

(test perform-reorg-prunes-witness-stripped-fork-block
  "A stored witness-stripped fork block (commitment but no coinbase nonce, e.g.
from the old v1-compact :weaker-chain path) is pruned during the reorg precondition
and returned as MISSING so it gets re-downloaded witness-complete — instead of
failing the reorg forever and wedging the node (testnet4 stuck ~1800 blocks behind)."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "prune-stripped")
     ;; Active chain A: genesis -> A1 -> A2.
     (%build-and-connect chain-state block-store utxo-set genesis-hash
                         (make-test-chain-hashes #xA0 2))
     (let* ((a2-entry (bitcoin-lisp.storage:get-block-index-entry
                       chain-state (bitcoin-lisp.storage:best-block-hash chain-state)))
            (genesis-entry (bitcoin-lisp.storage:get-block-index-entry chain-state genesis-hash))
            (b-hashes (make-test-chain-hashes #xB0 2))
            (b1-hash (first b-hashes))
            (b2-hash (second b-hashes))
            (b1-block (make-stripped-reorg-block genesis-hash b1-hash 1))   ; STRIPPED
            (b2-block (make-reorg-test-block b1-hash b2-hash 2)))
       (bitcoin-lisp.storage:store-block block-store b1-block)
       (bitcoin-lisp.storage:store-block block-store b2-block)
       (let ((b1-entry (bitcoin-lisp.storage:make-block-index-entry
                        :hash b1-hash :height 1 :prev-entry genesis-entry
                        :chain-work 100 :status :header-valid
                        :header (bitcoin-lisp.serialization:bitcoin-block-header b1-block))))
         (bitcoin-lisp.storage:add-block-index-entry chain-state b1-entry)
         (let ((b2-entry (bitcoin-lisp.storage:make-block-index-entry
                          :hash b2-hash :height 2 :prev-entry b1-entry
                          :chain-work 200 :status :header-valid
                          :header (bitcoin-lisp.serialization:bitcoin-block-header b2-block))))
           (bitcoin-lisp.storage:add-block-index-entry chain-state b2-entry)
           ;; sanity: B1 is stored and detected as stripped
           (is-true (bitcoin-lisp.validation:block-witness-stripped-p
                     (bitcoin-lisp.storage:get-block block-store b1-hash)))
           ;; Attempt reorg A2 -> B2.
           (multiple-value-bind (ok missing)
               (bitcoin-lisp.validation:perform-reorg
                chain-state block-store utxo-set a2-entry b2-entry)
             (is (null ok))                                            ; refused
             (is (not (null missing)))                                 ; missing list returned
             (is (null (bitcoin-lisp.storage:get-block block-store b1-hash)))   ; B1 pruned
             (is (member b1-hash (mapcar #'car missing) :test #'equalp))
             ;; tip unchanged — no mutation on a refused reorg
             (is (= 2 (bitcoin-lisp.storage:current-height chain-state)))
             (is (equalp (bitcoin-lisp.storage:block-index-entry-hash a2-entry)
                         (bitcoin-lisp.storage:best-block-hash chain-state)))))))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

;;;; Reorg mempool bulk re-add (cluster mempool P8 — Core
;;;; MaybeUpdateMempoolForReorg, validation.cpp:294-389)

(test reorg-readd-bulk-bypass-limits
  "readd-disconnected-txs-to-mempool: a ZERO-fee disconnected tx re-enters
(bypass_limits skips the fee floor, Core validation.cpp:945) and is wired to
its pre-existing pool child; a disconnected tx whose inputs are gone on the
new chain is dropped and its pool spender removed with it (Core
removeRecursive, validation.cpp:317-321)."
  (multiple-value-bind (utxo-set mempool chain-state funding)
      (%pkg-fixture)
    (let* ((graph (bitcoin-lisp.mempool:mempool-graph mempool))
           ;; dtx: spends the confirmed funding output, paying ZERO fee.
           (dtx (%pkg-tx funding 0 100000000))
           (did (bitcoin-lisp.serialization:transaction-hash dtx))
           ;; Pool child of dtx (entered while dtx was confirmed).
           (child (%pkg-tx did 0 99990000))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           ;; dtx2: its input never existed on the new chain.
           (dtx2 (%pkg-tx (make-reorg-hash 4242) 0 500))
           (d2id (bitcoin-lisp.serialization:transaction-hash dtx2))
           ;; Pool spender of dtx2's output.
           (orphan (%pkg-tx d2id 0 400))
           (oid (bitcoin-lisp.serialization:transaction-hash orphan)))
      (is (eq :ok (%add-tx mempool child :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool orphan :fee 100 :height 200)))
      (bitcoin-lisp.validation::readd-disconnected-txs-to-mempool
       mempool (list dtx dtx2) utxo-set 200 chain-state)
      ;; dtx re-entered fee-free and was wired to its child.
      (is (bitcoin-lisp.mempool:mempool-has mempool did))
      (is (bitcoin-lisp.mempool:mempool-has mempool cid))
      (is (= 2 (length (bitcoin-lisp.mempool:txgraph-get-cluster
                        graph
                        (bitcoin-lisp.mempool:mempool-entry-graph-handle
                         (bitcoin-lisp.mempool:mempool-get mempool did))))))
      ;; dtx2 failed re-acceptance; its pool spender went with it.
      (is (not (bitcoin-lisp.mempool:mempool-has mempool d2id)))
      (is (not (bitcoin-lisp.mempool:mempool-has mempool oid)))
      (is (= 2 (bitcoin-lisp.mempool:mempool-count mempool)))
      (bitcoin-lisp.mempool::%mempool-graph-verify mempool))))

(test reorg-readd-drops-nonfinal-tx
  "A disconnected tx whose nLockTime the post-reorg chain no longer satisfies
is NOT re-added: bypass_limits skips the fee floor but never the finality /
BIP68 checks (Core PreChecks CheckFinalTxAtTip runs unconditionally,
validation.cpp:819). Previously the re-add path skipped finality entirely,
letting a premature tx re-enter the pool and get mined."
  (multiple-value-bind (utxo-set mempool chain-state funding)
      (%pkg-fixture)
    (let* ((locked (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash funding :index 0)
                                     :script-sig (%p2sh-optrue-scriptsig)
                                     :sequence 0))   ; locktime enforced
                    :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 99990000
                                      :script-pubkey (%p2sh-optrue-spk)))
                    :lock-time 500))                 ; height 500 > next block 201
           (lid (bitcoin-lisp.serialization:transaction-hash locked)))
      (bitcoin-lisp.validation::readd-disconnected-txs-to-mempool
       mempool (list locked) utxo-set 200 chain-state)
      (is (not (bitcoin-lisp.mempool:mempool-has mempool lid)))
      (is (= 0 (bitcoin-lisp.mempool:mempool-count mempool))))))

;;;; txindex across reorgs (Core parity: upsert on connect, no erase on
;;;; disconnect — index/txindex.cpp CustomAppend, index/base.h:136)

(defun %make-txindex-test-block (prev-hash block-hash height extra-txs)
  "Like make-reorg-test-block but appending EXTRA-TXS after the coinbase and
computing the real merkle root over all transactions."
  (let* ((script-sig (let ((s (make-array 4 :element-type '(unsigned-byte 8))))
                       (replace s block-hash :start2 0 :end2 4)
                       s))
         (coinbase-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                               :initial-element 0)
                                                          :index #xFFFFFFFF)
                                        :script-sig script-sig))
                       :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                         :value 5000000000
                                         :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                       :initial-element #x76)))
                       :lock-time 0))
         (txs (cons coinbase-tx extra-txs))
         (merkle-root (bitcoin-lisp.validation:compute-merkle-root
                       (mapcar #'bitcoin-lisp.serialization:transaction-hash txs)))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root merkle-root
                  :timestamp (+ 1231006505 (* height 600))
                  :bits #x1d00ffff
                  :nonce 0
                  :cached-hash block-hash)))
    (bitcoin-lisp.serialization:make-bitcoin-block :header header :transactions txs)))

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
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "txidx-remined")
     (let* ((txdir (ensure-directories-exist
                    (merge-pathnames (format nil "test-txidx-reorg-~D/" (get-internal-real-time))
                                     (uiop:temporary-directory))))
            (txindex (bitcoin-lisp.storage:init-tx-index txdir))
            ;; A mature non-coinbase UTXO for T to spend (OP_TRUE, so the
            ;; full script validation in perform-reorg passes).
            (u-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xEE))
            (tx-t (bitcoin-lisp.serialization:make-transaction
                   :version 1
                   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                      :hash u-txid :index 0)
                                    :script-sig (%empty-script)
                                    :sequence #xFFFFFFFF))
                   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                     :value 100000 :script-pubkey (%optrue-spk)))
                   :lock-time 0))
            (t-txid (bitcoin-lisp.serialization:transaction-hash tx-t))
            (a-hashes (make-test-chain-hashes #xA6 2))
            (b-hashes (make-test-chain-hashes #xB6 3)))
       (bitcoin-lisp.storage:add-utxo utxo-set u-txid 0 100000 (%optrue-spk) 1)
       (unwind-protect
            (progn
              ;; Chain A: A1 (coinbase only), A2 = coinbase + T.
              (let* ((a1 (make-reorg-test-block genesis-hash (first a-hashes) 1))
                     (a2 (%make-txindex-test-block (first a-hashes) (second a-hashes)
                                                   2 (list tx-t))))
                (bitcoin-lisp.validation:connect-block
                 a1 chain-state block-store utxo-set :tx-index txindex)
                (bitcoin-lisp.validation:connect-block
                 a2 chain-state block-store utxo-set :tx-index txindex))
              (is (= 2 (bitcoin-lisp.storage:current-height chain-state)))
              (let ((loc (bitcoin-lisp.storage:txindex-lookup txindex t-txid)))
                (is (equalp (second a-hashes)
                            (bitcoin-lisp.storage:tx-location-block-hash loc))))
              ;; Chain B (more work): B1, B2 = coinbase + T re-mined, B3.
              ;; B1/B2 are stored as a weaker chain; B3 triggers the reorg,
              ;; which validates B1-B3 fully (scripts included) and re-adds
              ;; their txs to the index in Phase C.
              (let* ((b1 (make-reorg-test-block genesis-hash (first b-hashes) 1))
                     (b2 (%make-txindex-test-block (first b-hashes) (second b-hashes)
                                                   2 (list tx-t)))
                     (b3 (make-reorg-test-block (second b-hashes) (third b-hashes) 3)))
                (bitcoin-lisp.validation:connect-block
                 b1 chain-state block-store utxo-set :tx-index txindex)
                (bitcoin-lisp.validation:connect-block
                 b2 chain-state block-store utxo-set :tx-index txindex)
                (bitcoin-lisp.validation:connect-block
                 b3 chain-state block-store utxo-set :tx-index txindex))
              (is (= 3 (bitcoin-lisp.storage:current-height chain-state)))
              (is (equalp (third b-hashes) (bitcoin-lisp.storage:best-block-hash chain-state)))
              ;; (a) T re-mined: indexed at the NEW block.
              (let ((loc (bitcoin-lisp.storage:txindex-lookup txindex t-txid)))
                (is (not (null loc)))
                (when loc
                  (is (equalp (second b-hashes)
                              (bitcoin-lisp.storage:tx-location-block-hash loc)))
                  (is (= 1 (bitcoin-lisp.storage:tx-location-tx-position loc)))))
              ;; (b) A2's coinbase exists only in the stale branch: still
              ;; indexed at A2 and resolvable through the stored stale block.
              (let* ((a2 (bitcoin-lisp.storage:get-block block-store (second a-hashes)))
                     (a2-cb (first (bitcoin-lisp.serialization:bitcoin-block-transactions a2)))
                     (a2-cb-id (bitcoin-lisp.serialization:transaction-hash a2-cb))
                     (loc (bitcoin-lisp.storage:txindex-lookup txindex a2-cb-id)))
                (is (not (null loc)))
                (when loc
                  (is (equalp (second a-hashes)
                              (bitcoin-lisp.storage:tx-location-block-hash loc)))
                  ;; The stale block body is still on disk, so the lookup
                  ;; resolves end-to-end (Core keeps stale block data too).
                  (is (not (null a2)))))
              ;; (c1) Catch-up scan is idempotent: nothing re-appended.
              (let ((entries-before (bitcoin-lisp.storage::tx-index-entry-count txindex)))
                (is (= 0 (bitcoin-lisp.storage:build-tx-index
                          txindex chain-state block-store)))
                (is (= entries-before
                       (bitcoin-lisp.storage::tx-index-entry-count txindex))))
              ;; (c2) A stale mapping (e.g. crash before the reorg's index
              ;; update) is re-pointed by the catch-up scan: force T back to
              ;; A2, then rescan — the verified per-block check sees B2's
              ;; last tx pointing elsewhere and re-indexes B2.
              (bitcoin-lisp.storage:txindex-add txindex t-txid (second a-hashes) 1)
              (is (plusp (bitcoin-lisp.storage:build-tx-index
                          txindex chain-state block-store)))
              (let ((loc (bitcoin-lisp.storage:txindex-lookup txindex t-txid)))
                (is (equalp (second b-hashes)
                            (bitcoin-lisp.storage:tx-location-block-hash loc)))))
         (bitcoin-lisp.storage:close-tx-index txindex)
         (ignore-errors (delete-file (merge-pathnames "txindex.dat" txdir)))
         (clrhash bitcoin-lisp.validation::*block-undo-data*))))))

(test reorg-getrawtransaction-stale-block-core-semantics
  "getrawtransaction for a tx whose txindex entry points into a stale
(reorged-away) block matches Core TxToJSON (rpc/rawtransaction.cpp:58-86):
the tx IS returned, blockhash names the stale block, confirmations is 0, and
no time/blocktime fields are present; a tx on the active chain gets normal
confirmations."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "txidx-rpc")
     (let* ((txdir (ensure-directories-exist
                    (merge-pathnames (format nil "test-txidx-rpc-~D/" (get-internal-real-time))
                                     (uiop:temporary-directory))))
            (txindex (bitcoin-lisp.storage:init-tx-index txdir))
            (a-hashes (make-test-chain-hashes #xA7 2))
            (b-hashes (make-test-chain-hashes #xB7 3)))
       (unwind-protect
            (progn
              ;; Chain A then a longer chain B; A2's coinbase ends up stale-only.
              (dolist (spec (list (list genesis-hash (first a-hashes) 1)
                                  (list (first a-hashes) (second a-hashes) 2)
                                  (list genesis-hash (first b-hashes) 1)
                                  (list (first b-hashes) (second b-hashes) 2)
                                  (list (second b-hashes) (third b-hashes) 3)))
                (bitcoin-lisp.validation:connect-block
                 (apply #'make-reorg-test-block spec)
                 chain-state block-store utxo-set :tx-index txindex))
              (is (equalp (third b-hashes) (bitcoin-lisp.storage:best-block-hash chain-state)))
              (let ((node (bitcoin-lisp::make-node :network :mainnet)))
                (setf (bitcoin-lisp::node-chain-state node) chain-state
                      (bitcoin-lisp::node-block-store node) block-store
                      (bitcoin-lisp::node-utxo-set node) utxo-set
                      (bitcoin-lisp::node-tx-index node) txindex
                      (bitcoin-lisp::node-mempool node) (bitcoin-lisp.mempool:make-mempool))
                ;; Stale-branch tx: found, blockhash = stale block,
                ;; confirmations 0, no time/blocktime (Core pushes them only
                ;; for active-chain blocks).
                (let* ((a2 (bitcoin-lisp.storage:get-block block-store (second a-hashes)))
                       (a2-cb-id (bitcoin-lisp.serialization:transaction-hash
                                  (first (bitcoin-lisp.serialization:bitcoin-block-transactions a2))))
                       (r (bitcoin-lisp.rpc::rpc-getrawtransaction
                           node (list (bitcoin-lisp.rpc::hash-to-hex a2-cb-id) 1))))
                  (is (consp r))
                  (is (string= (bitcoin-lisp.rpc::hash-to-hex (second a-hashes))
                               (cdr (assoc "blockhash" r :test #'string=))))
                  (is (eql 0 (cdr (assoc "confirmations" r :test #'string=))))
                  (is (null (assoc "time" r :test #'string=)))
                  (is (null (assoc "blocktime" r :test #'string=))))
                ;; Active-chain tx: normal confirmations (tip 3, B2 at 2 -> 2).
                (let* ((b2 (bitcoin-lisp.storage:get-block block-store (second b-hashes)))
                       (b2-cb-id (bitcoin-lisp.serialization:transaction-hash
                                  (first (bitcoin-lisp.serialization:bitcoin-block-transactions b2))))
                       (r (bitcoin-lisp.rpc::rpc-getrawtransaction
                           node (list (bitcoin-lisp.rpc::hash-to-hex b2-cb-id) 1))))
                  (is (string= (bitcoin-lisp.rpc::hash-to-hex (second b-hashes))
                               (cdr (assoc "blockhash" r :test #'string=))))
                  (is (eql 2 (cdr (assoc "confirmations" r :test #'string=)))))))
         (bitcoin-lisp.storage:close-tx-index txindex)
         (ignore-errors (delete-file (merge-pathnames "txindex.dat" txdir)))
         (clrhash bitcoin-lisp.validation::*block-undo-data*))))))

;;;; Wave 8A: recent-rejects reset on EVERY tip advance (not just reorgs)

(test tip-advance-clears-recent-rejects
  "Connecting a block that plainly extends the active tip clears the
recent-rejects filter — Core resets it on EVERY active tip change
(ActiveTipChange, net_processing.cpp:2045-2059 ->
txdownloadman_impl.cpp:92-96), because cached failures like non-final,
too-low-fee, or missing-inputs can become valid at the next block.
Previously only the reorg path cleared it."
  (%with-mainnet-network
   (multiple-value-bind (chain-state utxo-set block-store genesis-hash)
       (%make-activate-block-fixture "wave8-rejects-clear")
     (let ((rejects (bitcoin-lisp:make-rejects-filter 100))
           (cached (make-array 32 :element-type '(unsigned-byte 8)
                                  :initial-element 77)))
       (bitcoin-lisp:add-recent-reject rejects cached)
       (is-true (bitcoin-lisp:recent-reject-p rejects cached))
       ;; Plain tip extension: genesis -> B1 (no reorg involved).
       (let* ((b1-hash (first (make-test-chain-hashes #xE8 1)))
              (b1 (make-reorg-test-block genesis-hash b1-hash 1)))
         (bitcoin-lisp.validation:connect-block
          b1 chain-state block-store utxo-set :recent-rejects rejects)
         (is (= 1 (bitcoin-lisp.storage:current-height chain-state)))
         (is (equalp b1-hash (bitcoin-lisp.storage:best-block-hash chain-state))))
       (is-false (bitcoin-lisp:recent-reject-p rejects cached))
       ;; And the filter still works after the reset.
       (bitcoin-lisp:add-recent-reject rejects cached)
       (is-true (bitcoin-lisp:recent-reject-p rejects cached)))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

;;;; Wave 9C: removeForReorg — re-filter PRE-EXISTING entries after a reorg
;;;; (Core CTxMemPool::removeForReorg, txmempool.cpp:360-386, driven by
;;;; filter_final_and_mature, validation.cpp:334-385)

(test reorg-refilter-drops-nonfinal-preexisting-entry
  "After a reorg the pool's PRE-EXISTING entries are re-filtered: an entry
whose absolute locktime the new (shorter) chain no longer satisfies is
removed WITH its descendants — the re-add loop only vets the disconnected
blocks' txs, never what already sat in the pool."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (let* (;; LOCKED entered the pool while the tip was high enough; the
           ;; reorg leaves the tip at 200, so locktime 350 > next block 201.
           (locked (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash funding :index 0)
                                     :script-sig (%p2sh-optrue-scriptsig)
                                     :sequence 0))   ; locktime enforced
                    :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 99990000
                                      :script-pubkey (%p2sh-optrue-spk)))
                    :lock-time 350))
           (lid (bitcoin-lisp.serialization:transaction-hash locked))
           ;; a pool child of the locked tx: removed as a descendant
           (child (%pkg-tx lid 0 99980000))
           (cid (bitcoin-lisp.serialization:transaction-hash child))
           ;; an unrelated, final pool tx: stays
           (funding2 (make-reorg-hash 4310))
           (ok-tx (%pkg-tx funding2 0 99990000))
           (okid (bitcoin-lisp.serialization:transaction-hash ok-tx)))
      (bitcoin-lisp.storage:add-utxo utxo-set funding2 0 100000000
                                     (%p2sh-optrue-spk) 1 :coinbase nil)
      (is (eq :ok (%add-tx mempool locked :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool child :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool ok-tx :fee 10000 :height 200)))
      ;; No disconnected txs at all — the filter must still run.
      (bitcoin-lisp.validation::readd-disconnected-txs-to-mempool
       mempool '() utxo-set 200 chain-state)
      (is (not (bitcoin-lisp.mempool:mempool-has mempool lid)))
      (is (not (bitcoin-lisp.mempool:mempool-has mempool cid)))
      (is (bitcoin-lisp.mempool:mempool-has mempool okid))
      (bitcoin-lisp.mempool::%mempool-graph-verify mempool))))

(test reorg-refilter-drops-immature-coinbase-spend
  "A pool entry spending a coinbase that the reorg made immature again is
removed (Core filter_final_and_mature, validation.cpp:368-379): maturity is
COINBASE_MATURITY at the NEXT block. A spend of a still-mature coinbase
stays."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (declare (ignore funding))
    (let* ((cb-young (make-reorg-hash 4320))     ; coinbase @ 150: age 51 < 100
           (cb-old (make-reorg-hash 4321))       ; coinbase @ 90: age 111 >= 100
           (spend-young (%pkg-tx cb-young 0 99990000))
           (yid (bitcoin-lisp.serialization:transaction-hash spend-young))
           (spend-old (%pkg-tx cb-old 0 99990000))
           (oid (bitcoin-lisp.serialization:transaction-hash spend-old)))
      (bitcoin-lisp.storage:add-utxo utxo-set cb-young 0 100000000
                                     (%p2sh-optrue-spk) 150 :coinbase t)
      (bitcoin-lisp.storage:add-utxo utxo-set cb-old 0 100000000
                                     (%p2sh-optrue-spk) 90 :coinbase t)
      (is (eq :ok (%add-tx mempool spend-young :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool spend-old :fee 10000 :height 200)))
      ;; New tip 200 -> spend height 201: 201-150 = 51 < 100 immature;
      ;; 201-90 = 111 mature.
      (bitcoin-lisp.validation::readd-disconnected-txs-to-mempool
       mempool '() utxo-set 200 chain-state)
      (is (not (bitcoin-lisp.mempool:mempool-has mempool yid)))
      (is (bitcoin-lisp.mempool:mempool-has mempool oid)))))

(test reorg-refilter-drops-bip68-nonfinal-entry
  "A pool entry whose BIP68 height lock the new chain no longer satisfies is
removed: Core re-tests lockpoints against the new tip
(validation.cpp:350-366). A lock already deep enough stays."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (declare (ignore funding))
    (let* ((coin1 (make-reorg-hash 4330))
           (coin2 (make-reorg-hash 4331))
           ;; 100-block relative lock on a coin confirmed at 150: at the new
           ;; tip 200 (spend height 201) only 51 blocks deep -> non-final.
           (locked (%pkg-tx coin1 0 99990000 :sequence 100))
           (lid (bitcoin-lisp.serialization:transaction-hash locked))
           ;; 40-block lock on the same depth -> satisfied.
           (ok-tx (%pkg-tx coin2 0 99990000 :sequence 40))
           (okid (bitcoin-lisp.serialization:transaction-hash ok-tx)))
      (bitcoin-lisp.storage:add-utxo utxo-set coin1 0 100000000
                                     (%p2sh-optrue-spk) 150 :coinbase nil)
      (bitcoin-lisp.storage:add-utxo utxo-set coin2 0 100000000
                                     (%p2sh-optrue-spk) 150 :coinbase nil)
      (is (eq :ok (%add-tx mempool locked :fee 10000 :height 200)))
      (is (eq :ok (%add-tx mempool ok-tx :fee 10000 :height 200)))
      (bitcoin-lisp.validation::readd-disconnected-txs-to-mempool
       mempool '() utxo-set 200 chain-state)
      (is (not (bitcoin-lisp.mempool:mempool-has mempool lid)))
      (is (bitcoin-lisp.mempool:mempool-has mempool okid)))))

(test reorg-refilter-runs-after-readd
  "Ordering matches Core MaybeUpdateMempoolForReorg: re-add first, then the
re-filter — so a disconnected tx that is itself non-final under the new tip
is caught even though the filter, not the re-add validation, is what sees
the pool child it would strand. A re-added final tx survives the filter."
  (multiple-value-bind (utxo-set mempool chain-state funding) (%pkg-fixture)
    (let* ((dtx (%pkg-tx funding 0 100000000))   ; zero-fee, final: re-adds
           (did (bitcoin-lisp.serialization:transaction-hash dtx)))
      (bitcoin-lisp.validation::readd-disconnected-txs-to-mempool
       mempool (list dtx) utxo-set 200 chain-state)
      ;; the re-added tx passed the filter too
      (is (bitcoin-lisp.mempool:mempool-has mempool did)))))

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
  (let ((block (bitcoin-lisp.mining:assemble-full-block
                (bitcoin-lisp::node-chain-state node)
                (bitcoin-lisp::node-mempool node)
                :coinbase-script-pubkey spk)))
    (bitcoin-lisp.mining:mine-block block)
    block))

(defun %dr-connect (node block)
  "Connect BLOCK into NODE (advances the tip / stores / reorgs)."
  (bitcoin-lisp.validation:connect-block
   block
   (bitcoin-lisp::node-chain-state node)
   (bitcoin-lisp::node-block-store node)
   (bitcoin-lisp::node-utxo-set node)))

(test validate-block-context-free-only-skips-contextual
  "CONTEXT-FREE-ONLY returns success before the UTXO/height-dependent checks
(so a fork block validated at the wrong tip height is not spuriously rejected),
while the pure block-integrity checks still run."
  (%with-regtest
   (let* ((node (%regtest-node-fixture "cfo"))
          (cs (bitcoin-lisp::node-chain-state node))
          (utxo (bitcoin-lisp::node-utxo-set node))
          (spk (%p2sh-optrue-spk))
          (now (bitcoin-lisp.serialization:get-unix-time))
          ;; A valid, mined height-1 block on genesis.
          (block (%dr-mine-on node spk)))
     ;; Full validation at the block's real height (1) succeeds.
     (is-true (bitcoin-lisp.validation:validate-block block cs utxo 1 now))
     ;; Full validation at a WRONG height fails BIP34 (BAD-COINBASE-HEIGHT):
     ;; this is exactly what the old download path did to a fork block.
     (multiple-value-bind (valid error)
         (bitcoin-lisp.validation:validate-block block cs utxo 9 now)
       (is (null valid))
       (is (eq :bad-coinbase-height error)))
     ;; CONTEXT-FREE-ONLY at the same wrong height succeeds — the height check
     ;; is deferred to perform-reorg.
     (is-true (bitcoin-lisp.validation:validate-block
               block cs utxo 9 now :context-free-only t))
     ;; But a genuine context-free failure (merkle mismatch) is still caught
     ;; under CONTEXT-FREE-ONLY. Corrupt the header's merkle root; skip-pow so
     ;; the header check (which never looks at merkle) passes and we reach the
     ;; block-level merkle check.
     (let ((bad (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (copy-structure
                          (bitcoin-lisp.serialization:bitcoin-block-header block))
                 :transactions (bitcoin-lisp.serialization:bitcoin-block-transactions
                                block))))
       (setf (bitcoin-lisp.serialization:block-header-merkle-root
              (bitcoin-lisp.serialization:bitcoin-block-header bad))
             (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
       (multiple-value-bind (valid error)
           (bitcoin-lisp.validation:validate-block
            bad cs utxo 1 now :context-free-only t :skip-pow t)
         (is (null valid))
         (is (eq :bad-merkle-root error)))))))

(test deep-reorg-fork-blocks-accepted-and-reorged
  "A competing longer branch fed to ACCEPT-DOWNLOADED-BLOCK while the node's tip
is already on the shorter branch: every fork block must be stored (not rejected
by tip-validation), and the branch must win via reorg once it outweighs the
active chain. Old code rejected the fork blocks (BAD-COINBASE-HEIGHT, since
their height != tip+1) and never reorged."
  (%with-regtest
   (let* ((spk-a (%p2sh-optrue-spk))
          ;; A distinct coinbase spk so branch B's blocks differ from A's.
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))  ; bare OP_TRUE
          ;; Throwaway node to build branch B (4 blocks on genesis), capturing
          ;; the block objects.
          (nb (%regtest-node-fixture "dr-b"))
          (b-blocks (loop repeat 4
                          for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk)
                          collect blk))
          ;; Main node: branch A, 3 blocks on the same genesis.
          (na (%regtest-node-fixture "dr-a"))
          (csa (bitcoin-lisp::node-chain-state na))
          (utxoa (bitcoin-lisp::node-utxo-set na))
          (storea (bitcoin-lisp::node-block-store na)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))
     (is (= 3 (bitcoin-lisp.storage:current-height csa)))
     (let ((a-tip (bitcoin-lisp.storage:best-block-hash csa)))
       ;; Feed B1: it forks at genesis, so its height (1) != tip+1 (4). The old
       ;; tip-gate rejected this as BAD-COINBASE-HEIGHT; now it is stored as a
       ;; weaker side block and the active tip stays on A.
       (let ((b1-hash (bitcoin-lisp.serialization:block-header-hash
                       (bitcoin-lisp.serialization:bitcoin-block-header
                        (first b-blocks)))))
         (multiple-value-bind (valid error)
             (bitcoin-lisp.networking::accept-downloaded-block
              (first b-blocks) csa utxoa storea)
           (is-true valid)
           (is (null error)))
         (is-true (bitcoin-lisp.storage:get-block-index-entry csa b1-hash))
         (is (equalp a-tip (bitcoin-lisp.storage:best-block-hash csa)))
         (is (= 3 (bitcoin-lisp.storage:current-height csa))))
       ;; Feed B2, B3 (still weaker/equal — A stays active).
       (bitcoin-lisp.networking::accept-downloaded-block
        (second b-blocks) csa utxoa storea)
       (bitcoin-lisp.networking::accept-downloaded-block
        (third b-blocks) csa utxoa storea)
       (is (equalp a-tip (bitcoin-lisp.storage:best-block-hash csa)))
       ;; Feed B4 — branch B now outweighs A (4 > 3): reorg onto B.
       (bitcoin-lisp.networking::accept-downloaded-block
        (fourth b-blocks) csa utxoa storea)
       (let ((b4-hash (bitcoin-lisp.serialization:block-header-hash
                       (bitcoin-lisp.serialization:bitcoin-block-header
                        (fourth b-blocks)))))
         (is (= 4 (bitcoin-lisp.storage:current-height csa)))
         (is (equalp b4-hash (bitcoin-lisp.storage:best-block-hash csa)))
         ;; UTXO set is now branch B's 4 coinbases.
         (is (= 4 (bitcoin-lisp.storage:utxo-count utxoa))))))))

(test context-free-only-runs-checktransaction
  "F2: CONTEXT-FREE-ONLY now runs Core CheckBlock's per-tx CheckTransaction
(and legacy-sigop budget), so a structurally-invalid fork block (here a tx
with duplicate inputs, CVE-2018-17144) is rejected before storage rather than
being stored and only caught later in perform-reorg. A well-formed block still
passes context-free."
  (%with-regtest
   (let* ((node (%regtest-node-fixture "cfo-ct"))
          (cs (bitcoin-lisp::node-chain-state node))
          (utxo (bitcoin-lisp::node-utxo-set node))
          (now (bitcoin-lisp.serialization:get-unix-time))
          (block (%dr-mine-on node (%p2sh-optrue-spk)))
          (coinbase (first (bitcoin-lisp.serialization:bitcoin-block-transactions block))))
     ;; Baseline: the valid coinbase-only block passes context-free.
     (is-true (bitcoin-lisp.validation:validate-block
               block cs utxo 1 now :context-free-only t :skip-header t))
     ;; Build a non-coinbase tx with two identical inputs (duplicate outpoint).
     (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
            (op (bitcoin-lisp.serialization:make-outpoint
                 :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)
                 :index 0))
            (in (bitcoin-lisp.serialization:make-tx-in
                 :previous-output op :script-sig empty :sequence #xFFFFFFFF))
            (out (bitcoin-lisp.serialization:make-tx-out
                  :value 1000 :script-pubkey (coerce '(#x51) '(vector (unsigned-byte 8)))))
            (dup (bitcoin-lisp.serialization:make-transaction
                  :version 1 :inputs (vector in in) :outputs (vector out) :lock-time 0))
            (txs (list coinbase dup))
            ;; Correct merkle root over the two txs so the malleation check
            ;; passes and we reach the per-tx CheckTransaction.
            (root (bitcoin-lisp.validation::compute-merkle-root
                   (mapcar #'bitcoin-lisp.serialization:transaction-hash txs)))
            (hdr (copy-structure (bitcoin-lisp.serialization:bitcoin-block-header block)))
            (bad (progn
                   (setf (bitcoin-lisp.serialization:block-header-merkle-root hdr) root)
                   (bitcoin-lisp.serialization:make-bitcoin-block :header hdr :transactions txs))))
       (multiple-value-bind (valid error)
           (bitcoin-lisp.validation:validate-block
            bad cs utxo 1 now :context-free-only t :skip-header t)
         (is (null valid))
         (is (eq :duplicate-inputs error)))))))

(test connect-block-surfaces-missing-fork-blocks-on-refused-reorg
  "When connect-block triggers a reorg that must be REFUSED because intermediate
fork blocks are absent from the store, it returns the missing (hash . height)
list as its second value, so the download path (accept-downloaded-block) can
re-queue them. Regression for the testnet4 deep-reorg wedge: the compact/relay
path swallowed this signal and never re-requested the sub-tip fork blocks."
  (%with-regtest
   (let* ((spk-a (%p2sh-optrue-spk))
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))
          ;; Branch B (4 blocks) built on a throwaway node; capture the blocks.
          (nb (%regtest-node-fixture "requeue-b"))
          (b-blocks (loop repeat 4 for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk) collect blk))
          ;; Main node: capture genesis, then branch A (3 blocks). Tip = A3.
          (na (%regtest-node-fixture "requeue-a"))
          (csa (bitcoin-lisp::node-chain-state na))
          (utxoa (bitcoin-lisp::node-utxo-set na))
          (storea (bitcoin-lisp::node-block-store na))
          (genesis-hash (bitcoin-lisp.storage:best-block-hash csa)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))
     (is (= 3 (bitcoin-lisp.storage:current-height csa)))
     ;; Add branch B's HEADERS (index entries for B1-B3) to na WITHOUT their
     ;; bodies, so a reorg toward B can be attempted but must refuse for the
     ;; missing bodies. B4's entry + body are added by connect-block itself.
     (let ((prev (bitcoin-lisp.storage:get-block-index-entry csa genesis-hash)))
       (loop for blk in (subseq b-blocks 0 3)
             for h from 1 to 3
             do (let* ((hdr (bitcoin-lisp.serialization:bitcoin-block-header blk))
                       (bhash (bitcoin-lisp.serialization:block-header-hash hdr))
                       (work (bitcoin-lisp.storage:calculate-chain-work
                              (bitcoin-lisp.serialization:block-header-bits hdr)
                              (bitcoin-lisp.storage:block-index-entry-chain-work prev)))
                       (e (bitcoin-lisp.storage:make-block-index-entry
                           :hash bhash :height h :header hdr
                           :prev-entry prev :chain-work work :status :valid)))
                  (bitcoin-lisp.storage:add-block-index-entry csa e)
                  (setf prev e))))
     ;; connect-block B4: chain-work 4 > active A3's 3, so it triggers a reorg
     ;; toward B4, which refuses because B1-B3 bodies aren't stored.
     (multiple-value-bind (entry outcome)
         (bitcoin-lisp.validation:connect-block (fourth b-blocks) csa storea utxoa)
       (declare (ignore entry))
       ;; outcome = (reorg-ok detail); refused-for-missing -> (nil <list>).
       (is (null (first outcome)))
       (is (consp (second outcome)))
       ;; The three missing sub-tip fork blocks B1-B3.
       (is (= 3 (length (second outcome))))
       ;; Every element is a (hash . height) cons.
       (is (every (lambda (c) (and (consp c) (integerp (cdr c)))) (second outcome)))
       ;; Reorg refused -> active tip unchanged (still on branch A).
       (is (= 3 (bitcoin-lisp.storage:current-height csa)))))))

(test find-blocks-to-download-only-on-peer-chain
  "Layer-5 per-peer download: find-blocks-to-download-for-peer returns blocks on
the PEER'S chain only. A peer whose best-known block is on fork B yields fork-B
blocks to download and never fork-A blocks; a peer at our own tip yields nothing.
This is why the node downloads the chains its peers actually serve instead of
fixating on a fork no connected peer has."
  (%with-regtest
   (let* ((spk-a (%p2sh-optrue-spk))
          (spk-b (coerce '(#x51) '(vector (unsigned-byte 8))))
          (nb (%regtest-node-fixture "l5-b"))
          (b-blocks (loop repeat 5 for blk = (%dr-mine-on nb spk-b)
                          do (%dr-connect nb blk) collect blk))
          (na (%regtest-node-fixture "l5-a"))
          (csa (bitcoin-lisp::node-chain-state na))
          (storea (bitcoin-lisp::node-block-store na))
          (genesis-hash (bitcoin-lisp.storage:best-block-hash csa)))
     (dotimes (i 3) (%dr-connect na (%dr-mine-on na spk-a)))   ; branch A, tip A3 (h3)
     ;; Add branch B (5 blocks, more work) HEADERS to na, no bodies.
     (let ((prev (bitcoin-lisp.storage:get-block-index-entry csa genesis-hash)))
       (loop for blk in b-blocks for h from 1 to 5
             do (let* ((hdr (bitcoin-lisp.serialization:bitcoin-block-header blk))
                       (bhash (bitcoin-lisp.serialization:block-header-hash hdr))
                       (work (bitcoin-lisp.storage:calculate-chain-work
                              (bitcoin-lisp.serialization:block-header-bits hdr)
                              (bitcoin-lisp.storage:block-index-entry-chain-work prev)))
                       (e (bitcoin-lisp.storage:make-block-index-entry
                           :hash bhash :height h :header hdr
                           :prev-entry prev :chain-work work :status :header-valid)))
                  (bitcoin-lisp.storage:add-block-index-entry csa e)
                  (setf prev e))))
     (let* ((ctx (bitcoin-lisp.networking::make-ibd))
            (b-hashes (mapcar (lambda (blk)
                                (bitcoin-lisp.serialization:block-header-hash
                                 (bitcoin-lisp.serialization:bitcoin-block-header blk)))
                              b-blocks))
            (peer-b (bitcoin-lisp.networking::make-peer :address "1.2.3.4:18333"))
            (peer-tip (bitcoin-lisp.networking::make-peer :address "5.6.7.8:18333")))
       (setf (bitcoin-lisp.networking::peer-best-known-block-hash peer-b) (fifth b-hashes)
             (bitcoin-lisp.networking::peer-best-known-block-hash peer-tip)
             (bitcoin-lisp.storage:best-block-hash csa))
       (let ((bitcoin-lisp.networking::*ibd-context* ctx))
         ;; Peer on fork B: returns exactly the 5 fork-B blocks, none of fork A.
         (let ((got (bitcoin-lisp.networking::find-blocks-to-download-for-peer
                     peer-b csa storea 16)))
           (is (= 5 (length got)))
           (is (every (lambda (h) (member h b-hashes :test #'equalp)) got)))
         ;; Peer at our own tip (A3): nothing more-work to fetch.
         (is (null (bitcoin-lisp.networking::find-blocks-to-download-for-peer
                    peer-tip csa storea 16))))))))
