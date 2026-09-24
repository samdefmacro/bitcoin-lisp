(in-package #:bitcoin-lisp.tests)

;;;; -reindex-chainstate tests.
;;;;
;;;; do-reindex-chainstate rebuilds the UTXO set from stored blocks. The
;;;; load-bearing check: after polluting/corrupting the coins view, a reindex
;;;; restores it exactly (same whole-set MuHash, same tip), and it uses a
;;;; coins-view-cache like the live node (the wipe + flush are cache-specific).

(def-suite :reindex-tests
  :description "-reindex-chainstate UTXO rebuild"
  :in :bitcoin-lisp-tests)

(in-suite :reindex-tests)

(test reindex-chainstate-rebuilds-utxo-set
  "Mining builds a UTXO set; polluting the coins view then reindexing restores
the exact set (same whole-set MuHash) and the same chain tip."
  (with-network (:regtest)
   (let* ((tag (format nil "rbld~D" (get-internal-real-time)))
          (node (coins-db-node-fixture tag)))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 8)
       (let* ((cs (bl:node-chain-state node))
              (utxo (bl:node-utxo-set node))
              (tip (bl.store:current-height cs))
              ;; Truth: the correct set after mining.
              (truth-muhash (bl.store:compute-utxo-set-muhash utxo))
              (truth-amount (bl.store:utxo-set-total-amount utxo)))
         (is (= 8 tip))
         ;; Pollute the coins view with a coin that was never created on-chain.
         (bl.store:add-utxo
          utxo (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x99)
          0 424242 (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51) 1)
         (is (not (equalp truth-muhash
                          (bl.store:compute-utxo-set-muhash utxo))))
         ;; Reindex rebuilds from the stored blocks.
         (bl::do-reindex-chainstate)
         ;; Tip preserved, and the set matches the pre-pollution truth exactly.
         (is (= tip (bl.store:current-height cs)))
         (is (equalp truth-muhash
                     (bl.store:compute-utxo-set-muhash utxo)))
         (is (= truth-amount (bl.store:utxo-set-total-amount utxo)))
         ;; And no unspendable outputs snuck in (the coinbase witness-commitment
         ;; OP_RETURN is dropped, as during normal apply).
         (let ((unspendable 0))
           (bl.store:utxo-set-iterate
            utxo (lambda (txid vout entry)
                   (declare (ignore txid vout))
                   (when (bl.store:script-unspendable-p
                          (bl.store:utxo-entry-script-pubkey entry))
                     (incf unspendable))))
           (is (zerop unspendable)))
         ;; The on-disk chainstate.dat was committed clean by the final
         ;; 3-phase flush (the marker set during the rebuild is cleared).
         (let ((reload (bl.store:make-chain-state
                        :base-path (bl.store::chain-state-base-path cs))))
           (is (eq t (bl.store:load-state reload)))
           (is (= tip (bl.store:current-height reload)))))))))

(test reindex-chainstate-recovers-emptied-coins-view
  "Reindex rebuilds even from a fully-emptied coins view (disaster recovery:
blocks + index intact, chainstate DB wiped)."
  (with-network (:regtest)
   (let* ((tag (format nil "recov~D" (get-internal-real-time)))
          (node (coins-db-node-fixture tag)))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 5)
       (let* ((utxo (bl:node-utxo-set node))
              (truth (bl.store:compute-utxo-set-muhash utxo)))
         ;; Nuke the coins view entirely, then reindex.
         (bl.store:coins-view-cache-wipe utxo)
         (bl::do-reindex-chainstate)
         (is (equalp truth (bl.store:compute-utxo-set-muhash utxo))))))))

;;;; Crash safety. do-reindex-chainstate rewinds chainstate.dat to genesis
;;;; WITH the in-transition marker before wiping the coins DB, and every
;;;; replay flush goes through the 3-phase commit -- so a crash at ANY point
;;;; of the rebuild is detected at load-state (:inconsistent) and routed to
;;;; recover-inconsistent-chainstate, instead of the old behavior (the clean
;;;; pre-reindex chainstate.dat loading silently over a gutted coins DB).

(test reindex-crash-mid-replay-recovers
  "A crash inside a replay flush's unsafe window (marker written at the
replay height, coins batch not yet committed) is detected at load-state and
recovered to exactly the height the coins DB last committed."
  (with-network (:regtest)
   (let ((tag (format nil "crashr~D" (get-internal-real-time))))
     (multiple-value-bind (node cspath) (coins-db-node-fixture tag)
       (let ((bl:*node* node))
         (generate-regtest-blocks node 8)
         (let* ((cs (bl:node-chain-state node))
                (flushes 0)
                ;; Budget 0 => size trigger after EVERY replayed block, so
                ;; flush N happens right after block N is applied. The 3rd
                ;; flush dies in the marker window: on disk the marker is at
                ;; h=3 while the coins DB committed through h=2.
                (bl::*coins-cache-budget-bytes* 0)
                (bl::*flush-mid-commit-hook*
                  (lambda (flushing)
                    (declare (ignore flushing))
                    (when (= (incf flushes) 3)
                      (throw 'reindex-crash :crashed)))))
           (is (eq :crashed (catch 'reindex-crash
                              (bl::do-reindex-chainstate)
                              :completed))))
         ;; Simulate the process death: drop the in-memory cache and reload
         ;; both the on-disk LevelDB and chainstate.dat, as startup would.
         (let ((cs (bl:node-chain-state node)))
           (bl.store:close-chainstate-coins-view cs)
           (setf (bl:node-utxo-set node)
                 (bl.store:make-coins-view-cache
                  (bl.store:open-coins-view-db cspath)))
           (is (eq :inconsistent (bl.store:load-state cs)))
           (is (= 3 (bl.store:current-height cs)))
           (is (eq t (bl::recover-inconsistent-chainstate node cs)))
           ;; Rewound to the last committed replay flush: block 2.
           (is (= 2 (bl.store:current-height cs)))
           (let ((reload (bl.store:make-chain-state
                          :base-path (bl.store::chain-state-base-path cs))))
             (is (eq t (bl.store:load-state reload)))
             (is (= 2 (bl.store:current-height reload))))
           ;; And the coins DB is exactly the height-2 set: two 50-BTC
           ;; coinbases, nothing from block 3.
           (is (= 10000000000 (bl.store:utxo-set-total-amount
                               (bl:node-utxo-set node))))))))))

(test reindex-crash-mid-wipe-recovers-to-genesis
  "A crash between the genesis+marker rewind and the first replay flush
(e.g. mid-wipe, when the coins DB holds arbitrary leftovers of the old set)
recovers to a clean EMPTY set at genesis -- the leftovers are re-wiped, never
loaded as live state."
  (with-network (:regtest)
   (let* ((tag (format nil "crashw~D" (get-internal-real-time)))
          (node (coins-db-node-fixture tag)))
     (let ((bl:*node* node))
       (generate-regtest-blocks node 5)
       (let* ((cs (bl:node-chain-state node))
              (utxo (bl:node-utxo-set node))
              (genesis (bl.store:chain-state-genesis-hash cs)))
         ;; Make the mined coins durable, then reproduce the crash state by
         ;; hand: tip rewound to genesis with the marker while the coins DB
         ;; still holds the old set (killed right before the wipe -- the
         ;; worst case: ALL old coins left behind as garbage).
         (bl.store:coins-view-cache-flush utxo :sync t)
         (bl.store:update-chain-tip cs genesis 0)
         (bl.store:save-state cs :in-transition t)
         (is (eq :inconsistent (bl.store:load-state cs)))
         (is (eq t (bl::recover-inconsistent-chainstate node cs)))
         ;; Clean at genesis over an EMPTY coins DB.
         (is (= 0 (bl.store:current-height cs)))
         (is (equalp genesis (bl.store:best-block-hash cs)))
         (is (= 0 (bl.store:utxo-set-total-amount utxo)))
         (let ((reload (bl.store:make-chain-state
                        :base-path (bl.store::chain-state-base-path cs))))
           (is (eq t (bl.store:load-state reload)))
           (is (= 0 (bl.store:current-height reload)))))))))

(test reconcile-never-places-a-pointer-over-an-empty-utxo-set
  "A datadir an OLDER build left in the bad shape -- coins gone, pointer still
naming the old tip -- must not be reconciled toward. Core's is_coinsview_empty
(node/chainstate.cpp:69-70) skips LoadChainTip over an empty view; ours leaves
chainstate.dat where the recovery put it and says a rebuild is needed."
  (with-network (:regtest)
    (let* ((tag (format nil "recempty~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (generate-regtest-blocks node 5)
        (let* ((cs (bl:node-chain-state node))
               (utxo (bl:node-utxo-set node))
               (tip (bl.store:best-block-hash cs)))
          (bl.store:coins-view-cache-flush utxo :sync t)
          ;; The pre-fix on-disk shape, rebuilt by hand: every coin gone, the
          ;; pointer re-stamped at the old tip, chainstate.dat still at genesis
          ;; where the interrupted-reindex recovery left it.
          (bl.store:coins-view-cache-wipe utxo)
          (bl.store:coins-view-cache-sync utxo :sync t :best-block tip)
          (is (equalp tip (bl.store:coins-view-db-best-block
                           (bl.store:coins-view-cache-base utxo))))
          (bl.store:update-chain-tip
           cs (bl.store:chain-state-genesis-hash cs) 0)
          (let ((bl::*chainstates-reset-to-genesis* '()))
            (is (eq :empty (bl::reconcile-coins-db-best-block node))))
          (is (= 0 (bl.store:current-height cs)))
          ;; And the ordering guard: a chainstate the interrupted-reindex
          ;; branch has just reset is skipped outright, whatever the pointer
          ;; says, so the later recovery cannot undo the earlier one.
          (let ((bl::*chainstates-reset-to-genesis* (list cs)))
            (is (eq :reset (bl::reconcile-coins-db-best-block node))))
          (is (= 0 (bl.store:current-height cs))))))))

(test a-tip-record-the-block-index-cannot-place-is-a-load-failure
  "Core's LoadChainTip returns early only when m_chain.Tip() -- a block it HAS
-- carries the coins pointer's hash (validation.cpp:4835-4838); otherwise it
looks the pointer up in the block index and returns false when it is not there,
which CompleteChainstateInitialization reports as `Error initializing block
database' (node/chainstate.cpp:122-124). Our tip is a hash in chainstate.dat,
which can name a block the index does not hold, and a pointer that agreed with
it was taken as :match -- so removing blocks/ index left the node coming up at
height 5 over an index holding only genesis. feature_reindex_init.py:23 removes
exactly that directory and compares the whole of stderr against Core's
sentence.

The retry is Core's too: a chainstate-load FAILURE is the one startup failure
it offers to rebuild from, and the functional tests pre-answer yes with
-test=reindex_after_failure_noninteractive_yes (init.cpp:1860-1879)."
  (with-network (:regtest)
    (let* ((tag (format nil "loadtip~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (generate-regtest-blocks node 5)
        (let* ((cs (bl:node-chain-state node))
               (utxo (bl:node-utxo-set node))
               (tip (bl.store:best-block-hash cs))
               (genesis (bl.store:get-block-index-entry
                         cs (bl.store:chain-state-genesis-hash cs))))
          (bl.store:coins-view-cache-flush utxo :sync t :best-block tip)
          (flet ((verdict () (bl::reconcile-coins-db-best-block node))
                 (load-tip (options)
                   (let ((bl::*test-options* options))
                     (handler-case (bl::%init-chain-tip nil)
                       (bl.err:chainstate-load-error (e) (princ-to-string e))))))
            (is (eq :match (verdict))
                "control: with the index intact the two records agree")
            ;; blocks/index removed: only genesis is left, while chainstate.dat
            ;; and the coins pointer both still name block 5.
            (clrhash (bl.store:chain-state-block-index cs))
            (bl.store:add-block-index-entry cs genesis)
            (is (eq :unresolvable (verdict))
                "a tip record the index cannot place is not a match")
            ;; Without the operator's yes, that is Core's refusal, in its words.
            (is (equal "Error initializing block database" (load-tip '())))
            ;; With it, the block index is rebuilt from the block files and the
            ;; pointer is placed again.
            (is (member (load-tip (list "reindex_after_failure_noninteractive_yes"))
                        '(:match :reconciled))
                "the retry rebuilds the index and places the UTXO set")
            (is (equalp tip (bl.store:best-block-hash cs))
                "and the tip record still names block 5")))))))

(test a-tip-timestamped-in-the-future-is-a-load-failure
  "Core's VerifyLoadedChainstate refuses a tip more than MAX_FUTURE_BLOCK_TIME
ahead of the node's clock before it runs VerifyDB at all, and the refusal names
the CLOCK rather than the database (node/chainstate.cpp:250-255). GetTime()
honours -mocktime and so does ours, which is what makes rpc_blockchain.py:125
drivable: it restarts the node with a mocktime one second below the tip's
timestamp minus the window and compares the whole of stderr against this
sentence."
  (with-network (:regtest)
    (let* ((cs (bl.store:make-chain-state))
           (now (bl.ser:get-unix-time))
           (hash (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element #xB7)))
      (flet ((tip-at (timestamp)
               (clrhash (bl.store:chain-state-block-index cs))
               (bl.store:add-block-index-entry
                cs (bl.store:make-block-index-entry
                    :hash hash :height 1 :chain-work 2 :status :valid
                    :header (bl.ser:make-block-header
                             :version 4
                             :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                        :initial-element 0)
                             :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0)
                             :timestamp timestamp :bits #x207fffff :nonce 0)))
               (bl.store:update-chain-tip cs hash 1)))
        (flet ((refusal ()
                 (handler-case (bl::%refuse-a-tip-from-the-future cs)
                   (bl.err:chainstate-load-error (e) (princ-to-string e)))))
        ;; Exactly at the window: accepted, as Core's strict > accepts it.
        (tip-at (+ now bl.val:+max-future-block-time+))
        (is (null (refusal))
            "a tip exactly MAX_FUTURE_BLOCK_TIME ahead is still fine")
        ;; One second past it: refused, in Core's words.
        (tip-at (+ now bl.val:+max-future-block-time+ 1))
        (let ((refusal (refusal)))
          ;; FORMAT, not a bare literal: the message is built from a control
          ;; string whose tilde-newlines fold the source lines away, so the
          ;; expectation has to be folded the same way to compare equal.
          (is (equal (format nil "The block database contains a block which ~
appears to be from the future. This may be due to your computer's date and ~
time being set incorrectly. Only rebuild the block database if you are sure ~
that your computer's date and time are correct")
                     refusal))))))))

(test the-block-file-reindex-says-when-it-finished
  "Core ends ImportBlocks' reindex branch with `Reindexing finished'
(node/blockstorage.cpp:1291). It is what says the block files were all read
rather than the node having given up partway, and
feature_reindex_readonly.py:78 waits for it after making one block file
unwritable -- precisely to check that a read-only file is READ and not an
abort. Ours logged the count it added and then nothing."
  (with-network (:regtest)
    (let* ((tag (format nil "rfin~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (generate-regtest-blocks node 3)
        (let ((lines (capture-log-lines
                      (lambda () (bl::%rebuild-block-index-from-block-files)))))
          (is-true (find "Reindexing finished" lines :test #'search)
                   "Core's closing sentence; got ~S" lines))))))

;;;; Partial-batch coins flushes and ReplayBlocks (-dbbatchsize, -dbcrashratio)

(defun %crash-flush (utxo)
  "Flush UTXO in one-byte batches with a crash after the first: the database a
-dbcrashratio=1 crash leaves, observed instead of exited."
  (let ((bl.store:*coins-db-batch-bytes* 1)
        (bl.store:*coins-db-crash-ratio* 1)
        (bl.store:*coins-db-simulated-crash* (lambda () (throw 'crashed :crashed))))
    (catch 'crashed
      (bl.store:coins-view-cache-flush utxo :sync t))))

(defun %restart-coins-view (node)
  "A fresh coins cache over NODE's coins database, as a restart opens it."
  (let ((base (bl.store:coins-view-cache-base (bl:node-utxo-set node))))
    (setf (bl:node-utxo-set node) (bl.store:make-coins-view-cache base))
    (bl.store:coins-view-cache-load-best-block (bl:node-utxo-set node))
    base))

(test an-interrupted-partial-batch-flush-is-replayed-forward
  "Core CCoinsViewDB::BatchWrite writes a large flush in batches of
-dbbatchsize, recording DB_HEAD_BLOCKS (new, old) and erasing the best-block
pointer in the first and reversing that in the last (txdb.cpp:100-164); a crash
between them is finished at start-up by ReplayBlocks, which rolls forward from
the old tip to the new one (validation.cpp:4808-4889). feature_dbcrash.py
crashes nodes at exactly that point, again and again."
  (with-network (:regtest)
    (let* ((tag (format nil "replayfwd~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (let ((h1 (first (generate-regtest-blocks node 1))))
          (bl.store:coins-view-cache-flush (bl:node-utxo-set node) :sync t)
          (let ((h3 (second (generate-regtest-blocks node 2))))
            (is (eq :crashed (%crash-flush (bl:node-utxo-set node))))
            (let ((base (%restart-coins-view node))
                  (cs (bl:node-chain-state node)))
              (is (null (bl.store:coins-view-db-best-block base))
                  "the first partial batch erases the best-block pointer")
              (is (equalp (list (hex-to-internal h3) (hex-to-internal h1))
                          (bl.store:coins-view-db-head-blocks base)))
              (is-true (bl:replay-coins-db-blocks node cs))
              (is (null (bl.store:coins-view-db-head-blocks base)))
              (is (equalp (hex-to-internal h3) (bl.store:coins-view-db-best-block base)))
              (is (= (* 3 5000000000)
                     (bl.store:utxo-set-total-amount (bl:node-utxo-set node)))
                  "every coinbase of the three blocks, once each"))))))))

(test an-interrupted-flush-across-a-disconnect-is-rolled-back
  "The rollback half of ReplayBlocks: a flush interrupted while the coins moved
from a block BACK to its parent is resolved by disconnecting the old branch
down to the fork with its undo data (validation.cpp:4845-4870)."
  (with-network (:regtest)
    (let* ((tag (format nil "replayback~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (let* ((hashes (generate-regtest-blocks node 3))
               (cs (bl:node-chain-state node))
               (utxo (bl:node-utxo-set node)))
          (bl.store:coins-view-cache-flush utxo :sync t)
          (is-true (bl.val:invalidate-block cs (bl:node-block-store node) utxo
                                            (hex-to-internal (third hashes))))
          (is (eq :crashed (%crash-flush utxo)))
          (let ((base (%restart-coins-view node)))
            (is (equalp (list (hex-to-internal (second hashes))
                              (hex-to-internal (third hashes)))
                        (bl.store:coins-view-db-head-blocks base)))
            (is-true (bl:replay-coins-db-blocks node cs))
            (is (equalp (hex-to-internal (second hashes))
                        (bl.store:coins-view-db-best-block base)))
            (is (= (* 2 5000000000)
                   (bl.store:utxo-set-total-amount (bl:node-utxo-set node))))))))))

(defun hex-to-internal (hex)
  "A block hash as RPC prints it, in internal byte order."
  (bl.crypto:reverse-bytes (bl.crypto:hex-to-bytes hex)))

(test reindex-reaccepts-blocks-taken-without-segwit
  "Under -reindex, the active-chain blocks at segwit heights without
BLOCK_OPT_WITNESS are disconnected, reset to header-only and re-offered through
the ordinary accept path -- the outcome of Core's wiping reindex, which feeds
every stored body back through AcceptBlock (validation.cpp:4988-5155), for the
blocks NeedsRedownload names (:4892-4908). Bodies that pass come back
connected and marked; feature_presegwit_node_upgrade.py:47-53 has the ones that
do not."
  (with-network (:regtest)
    (let* ((tag (format nil "reaccept~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (let* ((hashes (generate-regtest-blocks node 3))
               (cs (bl:node-chain-state node))
               (entries (mapcar (lambda (h) (bl.store:get-block-index-entry
                                             cs (hex-to-internal h)))
                                hashes)))
          ;; As if blocks 2 and 3 had been accepted by a node not enforcing
          ;; segwit: no witness mark.
          (dolist (e (rest entries))
            (setf (bl.store:block-index-entry-status-flags e) 0))
          (is-true (bl.store:chain-needs-redownload-p cs))
          (is (= 2 (bl:reaccept-unwitnessed-active-chain)))
          (is (= 3 (bl.store:current-height cs)) "valid bodies connect again")
          (is-false (bl.store:chain-needs-redownload-p cs)
                    "and carry the witness mark once re-accepted"))))))
