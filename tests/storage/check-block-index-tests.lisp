(in-package #:bitcoin-lisp.tests)

;;;; -checkblockindex: Core's ChainstateManager::CheckBlockIndex
;;;; (validation.cpp:5157-5470; src/storage/check-block-index.lisp) and its
;;;; drive sites (BL.VAL:CHECK-BLOCK-INDEX).
;;;
;;; Each invariant family is shown twice: on a consistent index the walk
;;; answers T, and with one field broken it names the invariant. The index is
;;; built from mined regtest headers with the fields a node gives a connected
;;; block (one transaction, a body position, an undo position) and a stored
;;; but unconnected fork, so the walk sees every shape it meets on a node.

(def-suite :check-block-index-tests :in :bitcoin-lisp-tests
  :description "Core CheckBlockIndex over our block index, and -checkblockindex")

(in-suite :check-block-index-tests)

(defun %cbi-index (&key (main 5) (fork 2) (fork-at 2))
  "A consistent regtest index: genesis, MAIN connected headers and a FORK of
stored-but-unconnected headers off height FORK-AT -- shorter than the main
chain, so the best header is the main tip. Returns (values
chain-state main-entries fork-entries), lowest first. Call under
(with-network (:regtest))."
  (bl.store:reset-block-sequence-state)
  (let* ((cs (bl.store:make-chain-state))
         (genesis (%cbi-received (add-regtest-genesis-entry cs) 8))
         (chain (add-mined-chain cs genesis main))
         (branch (add-mined-chain cs (nth (1- fork-at) chain) fork
                                  :status :header-valid :tag 1)))
    (loop for e in chain for i from 1 do (%cbi-received e (* 1000 i) :undo t))
    (loop for e in branch for i from 1 do (%cbi-received e (+ 500 (* 1000 i))))
    (let ((tip (car (last chain))))
      (bl.store:update-chain-tip cs (bl.store:block-index-entry-hash tip)
                                 (bl.store:block-index-entry-height tip)))
    (values cs chain branch)))

(defun %cbi-failure (chain-state)
  "NIL when CHECK-BLOCK-INDEX-NOW passes CHAIN-STATE, else the failure's text."
  (handler-case (progn (bl.store:check-block-index-now chain-state) nil)
    (bl.store:block-index-check-failed (c) (princ-to-string c))))

(defmacro %cbi-fails-with (phrase form)
  "FORM (a chain-state) fails the check naming PHRASE."
  `(let ((failure (%cbi-failure ,form)))
     (is (and failure (search ,phrase failure))
         "expected a failure naming ~S, got ~S" ,phrase failure)))

(test check-block-index-passes-a-consistent-index
  "Positive control for every test below: genesis, a connected chain and a
stored fork pass, and so does an index with no active chain and one entry
(Core's reindex case, validation.cpp:5173-5179)."
  (with-network (:regtest)
    (is (null (%cbi-failure (%cbi-index))))
    (is (null (%cbi-failure (%cbi-index :fork 0))))
    (let ((cs (bl.store:make-chain-state)))
      (add-regtest-genesis-entry cs)
      (is (null (%cbi-failure cs))))))

(test check-block-index-finds-a-broken-tree
  "The tree itself (validation.cpp:5194-5200, :5294-5295, :5469): a height
that is not the depth, an entry with no parent, an entry whose parent link
is an object the index does not hold, chain work below the parent's."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (incf (bl.store:block-index-entry-height (first fork)))
      (%cbi-fails-with "nHeight must be consistent" cs)
      (decf (bl.store:block-index-entry-height (first fork)))
      (setf (bl.store:block-index-entry-prev-entry (second fork)) nil)
      (%cbi-fails-with "only genesis" cs)
      (setf (bl.store:block-index-entry-prev-entry (second fork))
            (copy-structure (first fork)))
      (%cbi-fails-with "the walk must visit every entry" cs)
      (setf (bl.store:block-index-entry-prev-entry (second fork)) (first fork))
      (is (null (%cbi-failure cs)))
      (setf (bl.store:block-index-entry-chain-work (second fork))
            (1- (bl.store:block-index-entry-chain-work (first fork))))
      (%cbi-fails-with "chain work must not be below" cs))))

(test check-block-index-finds-a-foreign-genesis
  "Genesis must be the chain's (validation.cpp:5262): the same index checked
as if the node ran testnet4."
  (with-network (:regtest)
    (let ((cs (%cbi-index)))
      (with-network (:testnet4)
        (%cbi-fails-with "the genesis block's hash must match" cs)))))

(test check-block-index-finds-validity-levels-out-of-order
  "Every entry is TREE valid (:5297), and a SCRIPTS-valid block's parents
are CHAIN and SCRIPTS valid (:5299-5300). Our levels are TREE, TRANSACTIONS
(:header-valid) and SCRIPTS (:valid) -- nothing is ever exactly CHAIN valid --
so a :valid block on a :header-valid parent fails the CHAIN check first."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (setf (bl.store:block-index-entry-status (first fork)) :unknown
            (bl.store:block-index-entry-tx-count (first fork)) 0
            (bl.store:block-index-entry-data-pos (first fork)) nil)
      (%cbi-fails-with "at least TREE valid" cs))
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (setf (bl.store:block-index-entry-status (second fork)) :valid)
      (%cbi-fails-with "CHAIN valid implies all parents are CHAIN valid" cs))))

(test check-block-index-finds-a-failure-that-did-not-propagate
  "A failed block's descendants are failed (validation.cpp:5302-5306)."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (bl.store:mark-entry-failed (first fork))
      (%cbi-fails-with "descendants must be marked as invalid" cs)
      (bl.store:mark-entry-failed (second fork))
      (is (null (%cbi-failure cs))))))

(test check-block-index-finds-body-bookkeeping-that-disagrees
  "nStatus against nTx (validation.cpp:5273-5289): a body without a
transaction count, a count without a body while nothing was pruned -- which a
pruned node may have -- and an undo record without a body."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (setf (bl.store:block-index-entry-tx-count (second fork)) 0)
      (%cbi-fails-with "HAVE_DATA is equivalent to nTx > 0 when nothing was pruned" cs)
      (setf (bl.store:block-index-entry-tx-count (second fork)) 1
            (bl.store:block-index-entry-data-pos (second chain)) nil)
      (%cbi-fails-with "HAVE_DATA is equivalent to nTx > 0 when nothing was pruned" cs)
      (setf (bl.store:chain-state-pruned-height cs) 2)
      (%cbi-fails-with "HAVE_UNDO implies HAVE_DATA" cs)
      (setf (bl.store:block-index-entry-undo-pos (second chain)) nil)
      (is (null (%cbi-failure cs)))
      (setf (bl.store:block-index-entry-tx-count (second fork)) 0)
      (%cbi-fails-with "HAVE_DATA implies nTx > 0" cs))))

(test check-block-index-finds-a-sequence-id-over-a-missing-body
  "An entry with a sequence id has every ancestor's transactions
(validation.cpp:5271)."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (dolist (e fork)
        (setf (bl.store:block-index-entry-tx-count e) 0
              (bl.store:block-index-entry-data-pos e) nil
              (bl.store:block-index-entry-file e) nil))
      (is (null (%cbi-failure cs)))
      (setf (bl.store:block-index-entry-sequence-id (second fork)) 9)
      (%cbi-fails-with "an entry with a sequence id must have every ancestor's transactions" cs))))

(test check-block-index-finds-a-body-that-should-be-unlinked
  "m_blocks_unlinked (validation.cpp:5379-5395): a body whose parent's never
arrived waits there -- NOTE-BLOCK-RECEIVED parks it -- and once the parent's
body is in and the wait drained, it no longer does."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (destructuring-bind (f1 f2) fork
        (setf (bl.store:block-index-entry-tx-count f1) 0
              (bl.store:block-index-entry-data-pos f1) nil
              (bl.store:block-index-entry-file f1) nil)
        (%cbi-fails-with "must be unlinked" cs)
        (bl.store:note-block-received cs f2)
        (is (null (%cbi-failure cs)))
        ;; F1's body arrives, but nothing drained the wait yet.
        (%cbi-received f1 1500)
        (%cbi-fails-with "missing no ancestor's data cannot be unlinked" cs)
        (bl.store:note-block-received cs f1)
        (is (null (%cbi-failure cs)))))))

(test check-block-index-finds-work-above-the-best-header
  "No valid block has more work than m_best_header (validation.cpp:5320)."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (bl.store:best-header-entry cs)
      (incf (bl.store:block-index-entry-chain-work (second fork)) 1000)
      (%cbi-fails-with "more work than the best header" cs)
      (bl.store:mark-entry-failed (second fork))
      (is (null (%cbi-failure cs))))))

(test check-block-index-checks-above-a-snapshot-base-as-if-below-were-there
  "The snapshot base (validation.cpp:5218-5232, :5283-5286): the blocks below
it were never downloaded, yet those above it -- downloaded, with sequence ids
-- pass, because the walk stashes the firsts at the base. Without the base
the same index fails; and the base's ancestors must still be TREE valid."
  (with-network (:regtest)
    (multiple-value-bind (cs chain) (%cbi-index :main 5 :fork 0)
      (let ((base (third chain)))
        (loop for e in (list (first chain) (second chain) base)
              do (setf (bl.store:block-index-entry-status e) :header-valid
                       (bl.store:block-index-entry-tx-count e) 0
                       (bl.store:block-index-entry-data-pos e) nil
                       (bl.store:block-index-entry-undo-pos e) nil
                       (bl.store:block-index-entry-file e) nil))
        (loop for e in (nthcdr 3 chain) for id from 2
              do (setf (bl.store:block-index-entry-sequence-id e) id))
        (%cbi-fails-with "sequence id" cs)
        (setf (bl.store:chain-state-from-snapshot-blockhash cs)
              (bl.store:block-index-entry-hash base))
        (is (null (%cbi-failure cs)))
        (setf (bl.store:block-index-entry-status (second chain)) :unknown)
        (%cbi-fails-with "the snapshot base's ancestors must be TREE valid" cs)))))

(test checkblockindex-ratio-is-the-option-or-the-chains-default
  "Core: -checkblockindex=<n> runs the check on one call in N, 0 never; an
empty value is 1 (node/chainstatemanager_args.cpp:27-30); absent, 1 where
fDefaultConsistencyChecks holds -- regtest alone -- and 0 elsewhere
(init.cpp:642). The option used to be accepted and ignored."
  (is-false (bl.cfg:core-only-option-p "checkblockindex"))
  (is-true (bl:known-config-option-p "checkblockindex"))
  (flet ((ratio (network setting)
           (let ((bl:*network* network)
                 (bl.val:*check-block-index* setting))
             (bl.val:check-block-index-ratio))))
    (is (= 1 (ratio :regtest nil)))
    (is (= 0 (ratio :mainnet nil)))
    (is (= 0 (ratio :testnet4 nil)))
    (is (= 0 (ratio :regtest 0)))
    (is (= 7 (ratio :mainnet 7))))
  (let ((bl.val:*check-block-index* nil))
    (loop for (raw want) in '(("" 1) ("1" 1) ("0" 0) ("5" 5))
          do (bl.cfg:apply-option-globals (list (cons "checkblockindex" raw)))
             (is (eql want bl.val:*check-block-index*) "-checkblockindex=~A" raw))))

;;;; The bookkeeping the walk reads, kept the way Core keeps it

(test a-received-body-stays-transactions-valid-after-pruning
  "ReceivedBlockTransactions raises a block to BLOCK_VALID_TRANSACTIONS and
PruneOneBlockFile clears HAVE_DATA only (validation.cpp:3829,
blockstorage.cpp:266-267): a stored, unconnected block whose body was pruned
is still TRANSACTIONS valid on disk. Ours derived the level from the body's
presence and wrote TREE."
  (let ((entry (bl.store:make-block-index-entry :height 3 :status :header-valid
                                                :tx-count 2)))
    (is (= 3 (logand 7 (bl.store:entry-disk-status entry))))
    (setf (bl.store:block-index-entry-tx-count entry) 0)
    (is (= 2 (logand 7 (bl.store:entry-disk-status entry))))))

(test a-restart-finds-the-bodies-waiting-on-an-ancestor
  "LoadBlockIndex puts every block whose transactions were received but whose
parent's chain lacks some into m_blocks_unlinked (node/blockstorage.cpp:
470-486), so the parent's arrival still hands it a sequence id. Ours started
with the table empty; and pruning a waiting body takes it out again
(:273-284)."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (destructuring-bind (f1 f2) fork
        (setf (bl.store:block-index-entry-tx-count f1) 0
              (bl.store:block-index-entry-data-pos f1) nil
              (bl.store:block-index-entry-file f1) nil)
        ;; As a restart finds it: nothing parked.
        (bl.store:reset-block-sequence-state)
        (%cbi-fails-with "must be unlinked" cs)
        (bl.store:link-unlinked-bodies cs)
        (is (null (%cbi-failure cs)))
        ;; F1's body arrives: F2, parked, takes a sequence id after it.
        (%cbi-received f1 1500)
        (bl.store:note-block-received cs f1)
        (is (< 1 (bl.store:block-index-entry-sequence-id f1)
               (bl.store:block-index-entry-sequence-id f2)))
        (is (null (%cbi-failure cs)))))
    ;; Pruning a parked body unparks it.
    (multiple-value-bind (cs chain fork) (%cbi-index)
      (declare (ignore chain))
      (destructuring-bind (f1 f2) fork
        (setf (bl.store:block-index-entry-tx-count f1) 0
              (bl.store:block-index-entry-data-pos f1) nil
              (bl.store:block-index-entry-file f1) nil)
        (bl.store:link-unlinked-bodies cs)
        (setf (bl.store:block-index-entry-data-pos f2) nil
              (bl.store:chain-state-pruned-height cs) 1)
        (%cbi-fails-with "without HAVE_DATA cannot be unlinked" cs)
        (bl.store:drop-unlinked-block f2)
        (is (null (%cbi-failure cs)))))))

(test a-stale-body-below-a-snapshot-base-waits-unlinked
  "feature_assumeutxo.py:606-612: a block forking off the snapshot chain BELOW
the base, submitted before the background chainstate gets there, has a parent
whose transactions were never downloaded -- it is on the snapshot
chainstate's active chain only as a header. Core parks it in m_blocks_unlinked
(HaveNumChainTxs is false for that parent). Ours took the active chain as
proof of a complete chain and gave the block a sequence id, and the node's own
CheckBlockIndex then stopped it."
  (with-network (:regtest)
    (multiple-value-bind (cs chain fork) (%cbi-index :main 5 :fork 1 :fork-at 2)
      (let ((base (third chain))
            (stale (first fork)))
        (loop for e in (list (first chain) (second chain) base)
              do (setf (bl.store:block-index-entry-status e) :header-valid
                       (bl.store:block-index-entry-tx-count e) 0
                       (bl.store:block-index-entry-data-pos e) nil
                       (bl.store:block-index-entry-undo-pos e) nil
                       (bl.store:block-index-entry-file e) nil))
        (setf (bl.store:chain-state-from-snapshot-blockhash cs)
              (bl.store:block-index-entry-hash base))
        ;; The blocks above the base arrived: they take sequence ids.
        (dolist (e (nthcdr 3 chain))
          (setf (bl.store:block-index-entry-sequence-id e) 0))
        ;; The stale body is submitted on top of the header-only parent.
        (bl.store:note-block-received cs stale)
        (is (= bl.store:+seq-id-init-from-disk+
               (bl.store:block-index-entry-sequence-id stale))
            "the stale block waits rather than taking a sequence id")
        (is (null (%cbi-failure cs)))))))

(test the-snapshot-base-is-complete-for-its-children-but-its-own-body-waits
  "The snapshot base has a chain transaction count from the snapshot
(blockstorage.cpp:438-443), so a restart links the blocks above it however
little is below; but a body for the base itself, submitted before the
background chainstate gets there, waits in m_blocks_unlinked like any other
whose parent was never downloaded (ReceivedBlockTransactions,
validation.cpp:3849-3855; feature_assumeutxo.py:660-667). Ours parked the
blocks above the base at restart, and gave the base's body nothing."
  (with-network (:regtest)
    (multiple-value-bind (cs chain) (%cbi-index :main 5 :fork 0)
      (let ((base (third chain)))
        (loop for e in (list (first chain) (second chain) base)
              do (setf (bl.store:block-index-entry-status e) :header-valid
                       (bl.store:block-index-entry-tx-count e) 0
                       (bl.store:block-index-entry-data-pos e) nil
                       (bl.store:block-index-entry-undo-pos e) nil
                       (bl.store:block-index-entry-file e) nil))
        (setf (bl.store:chain-state-from-snapshot-blockhash cs)
              (bl.store:block-index-entry-hash base))
        ;; A restart: the active chain is the best chain from disk, and
        ;; nothing above the base waits.
        (bl.store:mark-best-chain-from-disk cs)
        (bl.store:link-unlinked-bodies cs (bl.store:block-index-entry-hash base))
        (is (null (%cbi-failure cs)))
        ;; The base's body arrives out of order: it waits on its parent,
        ;; although it is on the active chain and carries the restart's id.
        (%cbi-received base 3000)
        (%cbi-fails-with "must be unlinked" cs)
        (bl.store:note-block-received cs base)
        (is (<= (bl.store:block-index-entry-sequence-id base)
                bl.store:+seq-id-init-from-disk+))
        (is (null (%cbi-failure cs)))))))

(test a-body-without-a-transaction-count-is-counted-at-load-and-stops-the-check
  "The header index this tree kept before nTx was stored wrote entries that
hold a body and nTx = 0; blocks/index migrated from it keeps them. Core never
holds that state (ReceivedBlockTransactions sets nTx with the body,
validation.cpp:3812), so nothing backfills them and CheckBlockIndex refuses
them -- :5276 while nothing was pruned, :5280 after. LOAD-HEADER-INDEX says how
many there are, once, so an operator who enables -checkblockindex knows why the
node stops. Control: the same index with every count recorded loads silently
and passes."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-cbi-ntx")
      (let* ((cs (bl.store:init-chain-state dir :network :regtest))
             (genesis (add-regtest-genesis-entry cs))
             (chain (add-mined-chain cs genesis 4)))
        (loop for e in (cons genesis chain) for i from 1
              do (%cbi-received e (* 1000 i)))
        (flet ((reload ()
                 (bl.store:save-header-index cs :force-full t)
                 (let* ((back (bl.store:init-chain-state dir :network :regtest))
                        (lines (capture-log-lines
                                (lambda () (bl.store:load-header-index back))))
                        (tip (car (last chain))))
                   (bl.store:update-chain-tip back (bl.store:block-index-entry-hash tip)
                                              (bl.store:block-index-entry-height tip))
                   (values back (find "hold a body but record no transaction count"
                                      lines :test #'search)))))
          (multiple-value-bind (back line) (reload)
            (is (null line) "a complete index says nothing: ~S" line)
            (is (null (%cbi-failure back))))
          ;; Two bodies the old format wrote without their count.
          (setf (bl.store:block-index-entry-tx-count (second chain)) 0
                (bl.store:block-index-entry-tx-count (third chain)) 0)
          (multiple-value-bind (back line) (reload)
            (is (and line (search "2 blocks hold a body" line)) "the load line: ~S" line)
            (%cbi-fails-with "HAVE_DATA is equivalent to nTx > 0 when nothing was pruned" back)
            (setf (bl.store:chain-state-pruned-height back) 1)
            (%cbi-fails-with "HAVE_DATA implies nTx > 0" back)))))))
