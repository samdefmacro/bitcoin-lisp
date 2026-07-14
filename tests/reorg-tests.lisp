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
    (declare (ignore chain-state))
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
       mempool (list dtx dtx2) utxo-set 200)
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
