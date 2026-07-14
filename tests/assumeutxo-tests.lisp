(in-package #:bitcoin-lisp.tests)

;;;; Assumeutxo P4: dual chainstate + background IBD
;;;;
;;;; Covers the chainstate mechanics AROUND the snapshot load (the load
;;;; itself is covered in snapshot-tests.lisp): target-ancestor indexing and
;;;; the activate-block target guard (Core TryAddBlockIndexCandidate),
;;;; startup re-detection of a persisted snapshot chainstate (Core
;;;; LoadAssumeutxoChainstate), the dual-cursor download queue and its
;;;; base-in-chain peer filter (Core FindNextBlocksToDownload /
;;;; TryDownloadingHistoricalBlocks), per-chainstate crash recovery for the
;;;; snapshot chainstate, service-bit selection (Core init.cpp:1946-1953),
;;;; per-chainstate flush isolation, and the dual getchainstates report.

(def-suite :assumeutxo-tests
  :description "Assumeutxo dual chainstate + background IBD (P4)"
  :in :bitcoin-lisp-tests)

(in-suite :assumeutxo-tests)

;;; Temp dirs use snapshot-tests' %with-snap-dir (same package, loads first).

(defun %au-hash (byte &optional (second 0))
  "A 32-byte hash with BYTE at index 0 and SECOND at index 1."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) byte (aref h 1) second)
    h))

(defun %au-entry (hash height prev &key (status :header-valid) (chain-work 0))
  (bitcoin-lisp.storage:make-block-index-entry
   :hash hash :height height :prev-entry prev
   :chain-work chain-work :status status))

(defun %au-close-chainstate-dbs (node)
  "Close every chainstate's coins LevelDB so the same datadir can be
re-opened by a second in-process node (simulated restart)."
  (dolist (cs (bitcoin-lisp::node-chainstates node))
    (bitcoin-lisp.storage:close-chainstate-coins-view cs)))

;;;; Target-ancestor index + activate-block target guard

(test assumeutxo-target-ancestors-index
  "set-chainstate-target builds the height->entry ancestor index; siblings
off the target path and heights past the target are excluded."
  (let* ((g (%au-entry (%au-hash 0) 0 nil :status :valid))
         (e1 (%au-entry (%au-hash 1) 1 g))
         (e2 (%au-entry (%au-hash 2) 2 e1))
         (s2 (%au-entry (%au-hash 2 99) 2 e1))   ; sibling of e2
         (e3 (%au-entry (%au-hash 3) 3 e2))
         (cs (bitcoin-lisp.storage:make-chain-state)))
    (bitcoin-lisp.storage:set-chainstate-target cs e3)
    (is (equalp (%au-hash 3) (bitcoin-lisp.storage:chain-state-target-blockhash cs)))
    (is (= 3 (bitcoin-lisp.storage:chain-state-target-height cs)))
    (is (eq g (bitcoin-lisp.storage:target-ancestor-entry cs 0)))
    (is (eq e2 (bitcoin-lisp.storage:target-ancestor-entry cs 2)))
    (is (eq e3 (bitcoin-lisp.storage:target-ancestor-entry cs 3)))
    (is (null (bitcoin-lisp.storage:target-ancestor-entry cs 4)))
    (is (bitcoin-lisp.storage:entry-target-ancestor-p cs e1))
    (is (bitcoin-lisp.storage:entry-target-ancestor-p cs e3))
    (is (not (bitcoin-lisp.storage:entry-target-ancestor-p cs s2)))
    ;; entry-ancestor-at-height (the GetAncestor walk).
    (is (eq e1 (bitcoin-lisp.storage:entry-ancestor-at-height e3 1)))
    (is (eq e1 (bitcoin-lisp.storage:entry-ancestor-at-height s2 1)))
    (is (null (bitcoin-lisp.storage:entry-ancestor-at-height e1 3)))
    ;; Clearing the target drops the index.
    (bitcoin-lisp.storage:set-chainstate-target cs nil)
    (is (null (bitcoin-lisp.storage:chain-state-target-blockhash cs)))
    (is (null (bitcoin-lisp.storage:chain-state-target-height cs)))))

(test assumeutxo-activate-block-target-guard
  "A targeted (historical) chainstate connects ONLY blocks on the exact
ancestor path of its target: an equal-work sibling extending the same tip is
stored but refused (:weaker-chain) — Core TryAddBlockIndexCandidate — and so
is any block past the target (ReachedTarget stops the chainstate)."
  (%with-mainnet-network
   (multiple-value-bind (cs utxo store genesis-hash)
       (%make-activate-block-fixture "target-guard")
     ;; Connect A1; then index A2 (target), S2 (sibling of A2), A3 (past).
     (%build-and-connect cs store utxo genesis-hash
                         (make-test-chain-hashes #xA1 1))
     (let* ((a1-hash (bitcoin-lisp.storage:best-block-hash cs))
            (a1-entry (bitcoin-lisp.storage:get-block-index-entry cs a1-hash))
            (a2-hash (%au-hash #xA2))
            (s2-hash (%au-hash #xB2))
            (a3-hash (%au-hash #xA3))
            (a2-entry (%au-entry a2-hash 2 a1-entry :chain-work 200))
            (s2-entry (%au-entry s2-hash 2 a1-entry :chain-work 200))
            (a3-entry (%au-entry a3-hash 3 a2-entry :chain-work 300)))
       (bitcoin-lisp.storage:add-block-index-entry cs a2-entry)
       (bitcoin-lisp.storage:add-block-index-entry cs s2-entry)
       (bitcoin-lisp.storage:add-block-index-entry cs a3-entry)
       (bitcoin-lisp.storage:set-chainstate-target cs a2-entry)
       ;; Sibling S2 extends the current tip (A1) but is off-path: refused,
       ;; tip unmoved. Without the guard this would connect (case 1) and
       ;; wedge the historical chainstate forever.
       (multiple-value-bind (ok err)
           (bitcoin-lisp.validation:activate-block
            (make-reorg-test-block a1-hash s2-hash 2) cs store utxo
            :skip-scripts t)
         (is (null ok))
         (is (eq :weaker-chain err)))
       (is (= 1 (bitcoin-lisp.storage:current-height cs)))
       ;; ... but the refused block was stored for the block store's benefit.
       (is (not (null (bitcoin-lisp.storage:get-block store s2-hash))))
       ;; On-path A2 connects and reaches the target.
       (multiple-value-bind (ok err)
           (bitcoin-lisp.validation:activate-block
            (make-reorg-test-block a1-hash a2-hash 2) cs store utxo
            :skip-scripts t)
         (is (eq t ok))
         (is (null err)))
       (is (= 2 (bitcoin-lisp.storage:current-height cs)))
       (is (equalp a2-hash (bitcoin-lisp.storage:best-block-hash cs)))
       ;; A3 extends the tip but lies PAST the target: refused.
       (multiple-value-bind (ok err)
           (bitcoin-lisp.validation:activate-block
            (make-reorg-test-block a2-hash a3-hash 3) cs store utxo
            :skip-scripts t)
         (is (null ok))
         (is (eq :weaker-chain err)))
       (is (= 2 (bitcoin-lisp.storage:current-height cs)))
       ;; An untargeted chainstate is unaffected: clearing the target lets
       ;; A3 connect normally.
       (bitcoin-lisp.storage:set-chainstate-target cs nil)
       (multiple-value-bind (ok err)
           (bitcoin-lisp.validation:activate-block
            (make-reorg-test-block a2-hash a3-hash 3) cs store utxo
            :skip-scripts t)
         (is (eq t ok))
         (is (null err)))
       (is (= 3 (bitcoin-lisp.storage:current-height cs))))
     (clrhash bitcoin-lisp.validation::*block-undo-data*))))

;;;; Startup re-detection of a persisted snapshot chainstate

(test assumeutxo-startup-redetection
  "After a verified loadtxoutset, a fresh node over the same datadir
re-detects the snapshot chainstate from the chainstate_snapshot/ dir + its
base_blockhash marker: dual chainstates are rebuilt with the snapshot
chainstate current (:unvalidated — never persisted, re-derived), its tip
loaded from chainstate_snapshot.dat, its coins reopened, and the primary
retargeted at the base."
  (%with-snap-dir (src-dir)
    (%with-snap-dir (dir)
      (let* ((bitcoin-lisp:*prune-target-mib* nil) ; deterministic: pruning off
             (h5 (%snap-fill 32 5))
             (txid (%snap-fill 32 #x33))
             (spk (%snap-cat #(#x51)))
             (src (%snap-node src-dir h5 5))
             (snap-path (namestring (merge-pathnames "utxo.dat" src-dir))))
        ;; Produce a 1-coin snapshot from the source node.
        (bitcoin-lisp.storage:update-chain-tip
         (bitcoin-lisp::node-chain-state src) h5 5)
        (bitcoin-lisp.storage:add-utxo (bitcoin-lisp::node-utxo-set src)
                                       txid 0 1000 spk 1)
        (bitcoin-lisp.rpc::rpc-dumptxoutset src (list snap-path "latest"))
        (let ((hash (bitcoin-lisp.storage:compute-utxo-set-hash
                     (bitcoin-lisp::node-utxo-set src))))
          ;; Load it into the destination node (activation).
          (let ((node (%snap-node dir h5 5))
                (bitcoin-lisp:*assumeutxo-data-override*
                  (list (%snap-au 5 h5 hash 7))))
            (bitcoin-lisp.rpc::rpc-loadtxoutset node (list snap-path))
            (is (= 2 (length (bitcoin-lisp::node-chainstates node))))
            ;; "Restart": close the LevelDBs, build a fresh node over the
            ;; same datadir (header index recreated by %snap-node), detect.
            (%au-close-chainstate-dbs node)
            (let ((fresh (%snap-node dir h5 5)))
              (unwind-protect
                   (let ((snap-cs (bitcoin-lisp::load-snapshot-chainstate fresh)))
                     (is (not (null snap-cs)))
                     (is (= 2 (length (bitcoin-lisp::node-chainstates fresh))))
                     (let ((current (bitcoin-lisp::node-current-chainstate fresh))
                           (historical (bitcoin-lisp::node-historical-chainstate fresh)))
                       (is (eq current snap-cs))
                       (is (eq :unvalidated
                               (bitcoin-lisp.storage:chain-state-assumeutxo-status
                                current)))
                       (is (equalp h5 (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash
                                       current)))
                       ;; Tip restored from chainstate_snapshot.dat.
                       (is (= 5 (bitcoin-lisp.storage:current-height current)))
                       (is (equalp h5 (bitcoin-lisp.storage:best-block-hash current)))
                       ;; Primary retargeted at the base; target index built.
                       (is (not (null historical)))
                       (is (equalp h5 (bitcoin-lisp.storage:chain-state-target-blockhash
                                       historical)))
                       (is (= 5 (bitcoin-lisp.storage:chain-state-target-height
                                 historical)))
                       ;; Shared block index.
                       (is (eq (bitcoin-lisp.storage::chain-state-block-index current)
                               (bitcoin-lisp.storage::chain-state-block-index historical)))
                       ;; Coins reopened from chainstate_snapshot/.
                       (let ((c (bitcoin-lisp.storage:get-utxo
                                 (bitcoin-lisp.storage:chain-state-coins-view current)
                                 txid 0)))
                         (is (and c (= 1000 (bitcoin-lisp.storage:utxo-entry-value c)))))))
                (%au-close-chainstate-dbs fresh)))))))))

(test assumeutxo-startup-redetection-rejects
  "Startup detection is conservative: a snapshot dir without a base_blockhash
marker, or whose base header is missing from the index, does NOT create a
second chainstate (single-chainstate startup, dir left for later adoption)."
  (%with-snap-dir (dir)
    ;; Case 1: dir exists but no marker.
    (ensure-directories-exist (merge-pathnames "chainstate_snapshot/" dir))
    (let ((node (make-test-node)))
      (setf (bitcoin-lisp::node-data-directory node) (pathname dir))
      (is (null (bitcoin-lisp::load-snapshot-chainstate node)))
      (is (= 1 (length (bitcoin-lisp::node-chainstates node))))
      ;; Case 2: marker present but the base header is unknown.
      (with-open-file (out (bitcoin-lisp.storage:snapshot-base-blockhash-path
                            (merge-pathnames "chainstate_snapshot/" dir))
                           :direction :output :element-type '(unsigned-byte 8)
                           :if-exists :supersede)
        (write-sequence (%au-hash #x77) out))
      (is (null (bitcoin-lisp::load-snapshot-chainstate node)))
      (is (= 1 (length (bitcoin-lisp::node-chainstates node))))
      (is (null (bitcoin-lisp.storage:chain-state-target-blockhash
                 (bitcoin-lisp::node-chain-state node)))))))

;;;; Dual-cursor download queue + base-in-chain peer filter

(test assumeutxo-dual-cursor-queueing
  "queue-historical-blocks queues exactly the target-ancestor path above the
historical tip (never sibling forks); get-next-blocks-to-request windows the
two ranges independently and orders tip-range blocks first (Core fills
FindNextBlocksToDownload slots before TryDownloadingHistoricalBlocks)."
  (let* ((g (%au-entry (%au-hash 0) 0 nil :status :valid))
         (e1 (%au-entry (%au-hash 1) 1 g :status :valid))
         (e2 (%au-entry (%au-hash 2) 2 e1))
         (e3 (%au-entry (%au-hash 3) 3 e2))
         (s3 (%au-entry (%au-hash 3 99) 3 e2))   ; sibling off the path
         (e4 (%au-entry (%au-hash 4) 4 e3))
         (e5 (%au-entry (%au-hash 5) 5 e4))      ; snapshot base
         (hist (bitcoin-lisp.storage:make-chain-state))
         (bitcoin-lisp.networking::*ibd-context*
           (bitcoin-lisp.networking::make-ibd)))
    (dolist (e (list g e1 e2 e3 s3 e4 e5))
      (bitcoin-lisp.storage:add-block-index-entry hist e))
    (bitcoin-lisp.storage:update-chain-tip hist (%au-hash 1) 1)
    (bitcoin-lisp.storage:set-chainstate-target hist e5)
    (let ((ctx bitcoin-lisp.networking::*ibd-context*))
      ;; Queue the historical range: exactly e2..e5, sibling excluded.
      (is (= 4 (bitcoin-lisp.networking::queue-historical-blocks hist)))
      (let ((pending (bitcoin-lisp.networking::ibd-context-pending-blocks ctx)))
        (is (= 4 (hash-table-count pending)))
        (is (gethash (%au-hash 2) pending))
        (is (gethash (%au-hash 5) pending))
        (is (null (gethash (%au-hash 3 99) pending)))
        ;; Re-queueing is idempotent.
        (is (= 0 (bitcoin-lisp.networking::queue-historical-blocks hist)))
        ;; Add tip-range pending blocks (heights above the base).
        (setf (gethash (%au-hash 100) pending) 100
              (gethash (%au-hash 101) pending) 101)
        ;; Configure the dual-cursor context.
        (setf (bitcoin-lisp.networking::ibd-context-historical-chain-state ctx) hist
              (bitcoin-lisp.networking::ibd-context-snapshot-base-entry ctx) e5)
        ;; Tip range first (100, 101), then historical ascending (2..5).
        (let ((order (mapcar (lambda (h) (gethash h pending))
                             (bitcoin-lisp.networking::get-next-blocks-to-request 10 99))))
          (is (equal '(100 101 2 3 4 5) order)))
        ;; A tight historical window: with the historical tip at 1 the
        ;; window is min(base, 1+window) = base here; blocks beyond a
        ;; far-below-base tip would be excluded (exercised via the sort
        ;; result above staying within base).
        (is (= 6 (length (bitcoin-lisp.networking::get-next-blocks-to-request 10 99))))))))

(test assumeutxo-base-in-chain-peer-filter
  "peer-chain-contains-base-p admits only peers whose best-known chain
contains the snapshot base (Core net_processing.cpp:1412-1421): descendants
of the base pass, sibling-branch tips and no-availability peers fail."
  (let* ((g (%au-entry (%au-hash 0) 0 nil :status :valid))
         (e1 (%au-entry (%au-hash 1) 1 g))
         (e2 (%au-entry (%au-hash 2) 2 e1))      ; snapshot base
         (e3 (%au-entry (%au-hash 3) 3 e2))      ; descendant of base
         (s2 (%au-entry (%au-hash 2 99) 2 e1))   ; sibling branch
         (s3 (%au-entry (%au-hash 3 99) 3 s2))
         (cs (bitcoin-lisp.storage:make-chain-state))
         (bitcoin-lisp.networking::*ibd-context*
           (bitcoin-lisp.networking::make-ibd)))
    (dolist (e (list g e1 e2 e3 s2 s3))
      (bitcoin-lisp.storage:add-block-index-entry cs e))
    (setf (bitcoin-lisp.networking::ibd-context-snapshot-base-entry
           bitcoin-lisp.networking::*ibd-context*)
          e2)
    (let ((p-good (bitcoin-lisp.networking::make-peer))
          (p-base (bitcoin-lisp.networking::make-peer))
          (p-fork (bitcoin-lisp.networking::make-peer))
          (p-none (bitcoin-lisp.networking::make-peer)))
      (setf (bitcoin-lisp.networking::peer-best-known-block-hash p-good) (%au-hash 3)
            (bitcoin-lisp.networking::peer-best-known-block-hash p-base) (%au-hash 2)
            (bitcoin-lisp.networking::peer-best-known-block-hash p-fork) (%au-hash 3 99))
      (is (eq t (bitcoin-lisp.networking::peer-chain-contains-base-p p-good cs)))
      ;; The base itself IS in a chain ending at the base.
      (is (eq t (bitcoin-lisp.networking::peer-chain-contains-base-p p-base cs)))
      (is (not (bitcoin-lisp.networking::peer-chain-contains-base-p p-fork cs)))
      (is (not (bitcoin-lisp.networking::peer-chain-contains-base-p p-none cs)))
      ;; Memoized answers are stable.
      (is (eq t (bitcoin-lisp.networking::peer-chain-contains-base-p p-good cs)))
      (is (not (bitcoin-lisp.networking::peer-chain-contains-base-p p-fork cs))))))

;;;; Snapshot chainstate crash recovery (simulated partial flush)

(test assumeutxo-snapshot-crash-recovery
  "Per-chainstate 3-phase-commit recovery for a snapshot chainstate: a torn
flush at tip==base just clears the marker (populate committed the coins
atomically before the tip ever moved); a torn flush above the base with no
committed descendant block on disk rewinds to the base — whose coins ARE the
verified snapshot — never below it."
  (%with-snap-dir (dir)
    (let* ((base-hash (%au-hash 5))
           (g (%au-entry (%au-hash 0) 0 nil :status :valid))
           (e5 (%au-entry base-hash 5 g :status :valid))
           (e6 (%au-entry (%au-hash 6) 6 e5 :status :valid))
           (e7 (%au-entry (%au-hash 7) 7 e6 :status :valid))
           (node (make-test-node))
           (snap (bitcoin-lisp.storage:make-chain-state
                  :base-path (pathname dir)
                  :from-snapshot-blockhash base-hash
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot")))
      (setf (bitcoin-lisp::node-data-directory node) (pathname dir)
            (bitcoin-lisp::node-block-store node)
            (bitcoin-lisp.storage:init-block-store dir))
      (dolist (e (list g e5 e6 e7))
        (bitcoin-lisp.storage:add-block-index-entry snap e))
      (setf (bitcoin-lisp.storage:chain-state-coins-view snap)
            (bitcoin-lisp.storage:make-utxo-set))
      ;; Case A: torn flush with the recorded tip AT the base.
      (bitcoin-lisp.storage:update-chain-tip snap base-hash 5)
      (bitcoin-lisp.storage:save-state snap :in-transition t)
      (is (eq :inconsistent (bitcoin-lisp.storage:load-state snap)))
      (is (eq t (bitcoin-lisp::recover-inconsistent-chainstate node snap)))
      (is (eq t (bitcoin-lisp.storage:load-state snap)))
      (is (= 5 (bitcoin-lisp.storage:current-height snap)))
      ;; Case B: torn flush with the tip ABOVE the base, and none of the
      ;; blocks above the base on disk — recovery walks back and settles on
      ;; the base itself instead of failing (blocks below it don't exist on
      ;; the snapshot side).
      (bitcoin-lisp.storage:update-chain-tip snap (%au-hash 7) 7)
      (bitcoin-lisp.storage:save-state snap :in-transition t)
      (is (eq :inconsistent (bitcoin-lisp.storage:load-state snap)))
      (is (eq t (bitcoin-lisp::recover-inconsistent-chainstate node snap)))
      (is (= 5 (bitcoin-lisp.storage:current-height snap)))
      (is (equalp base-hash (bitcoin-lisp.storage:best-block-hash snap)))
      (is (eq t (bitcoin-lisp.storage:load-state snap)))
      ;; The snapshot chainstate's state file is the suffix-named one; the
      ;; primary's file was never created by any of this.
      (is (not (null (probe-file (merge-pathnames "chainstate_snapshot.dat" dir)))))
      (is (null (probe-file (merge-pathnames "chainstate.dat" dir)))))))

;;;; Per-chainstate flush isolation

(test assumeutxo-flush-isolation
  "do-flush writes only the given chainstate's storage-suffix-named state
file: flushing the snapshot chainstate never marks the primary's
chainstate.dat in-transition, and vice versa."
  (%with-snap-dir (dir)
    (let* ((primary (bitcoin-lisp.storage:make-chain-state
                     :base-path (pathname dir)
                     :best-block-hash (%au-hash 1) :best-height 1))
           (snap (bitcoin-lisp.storage:make-chain-state
                  :base-path (pathname dir)
                  :best-block-hash (%au-hash 5) :best-height 5
                  :from-snapshot-blockhash (%au-hash 5)
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot"))
           (node (bitcoin-lisp::make-node :network :testnet3))
           (bitcoin-lisp::*node* node))
      (setf (bitcoin-lisp::node-chainstates node) (list primary snap))
      ;; Flush the snapshot chainstate only.
      (bitcoin-lisp::do-flush snap)
      (is (not (null (probe-file (merge-pathnames "chainstate_snapshot.dat" dir)))))
      (is (null (probe-file (merge-pathnames "chainstate.dat" dir))))
      ;; Flush the primary; both exist now, each with its own tip.
      (bitcoin-lisp::do-flush primary)
      (is (not (null (probe-file (merge-pathnames "chainstate.dat" dir)))))
      (let ((p2 (bitcoin-lisp.storage:make-chain-state :base-path (pathname dir)))
            (s2 (bitcoin-lisp.storage:make-chain-state :base-path (pathname dir)
                                                       :storage-suffix "_snapshot")))
        (is (eq t (bitcoin-lisp.storage:load-state p2)))
        (is (eq t (bitcoin-lisp.storage:load-state s2)))
        (is (= 1 (bitcoin-lisp.storage:current-height p2)))
        (is (= 5 (bitcoin-lisp.storage:current-height s2))))
      ;; A torn marker on one never contaminates the other.
      (bitcoin-lisp.storage:save-state snap :in-transition t)
      (let ((p3 (bitcoin-lisp.storage:make-chain-state :base-path (pathname dir)))
            (s3 (bitcoin-lisp.storage:make-chain-state :base-path (pathname dir)
                                                       :storage-suffix "_snapshot")))
        (is (eq t (bitcoin-lisp.storage:load-state p3)))
        (is (eq :inconsistent (bitcoin-lisp.storage:load-state s3)))))))

;;;; Service bits (Core init.cpp:863,1946-1953)

(test assumeutxo-service-bits
  "local-service-bits mirrors Core's g_local_services: the base is always
NODE_NETWORK_LIMITED | NODE_WITNESS; NODE_NETWORK is added only when not
pruning AND no historical chainstate exists (i.e. no assumeutxo background
sync in progress)."
  (let ((limited bitcoin-lisp.serialization:+node-network-limited+)
        (network bitcoin-lisp.serialization:+node-network+)
        (witness bitcoin-lisp.serialization:+node-witness+))
    ;; No node at all: full service (not pruning).
    (let ((bitcoin-lisp::*node* nil)
          (bitcoin-lisp::*prune-target-mib* nil))
      (let ((bits (bitcoin-lisp.networking::local-service-bits)))
        (is (logtest bits network))
        (is (logtest bits limited))
        (is (logtest bits witness))))
    ;; A node with a historical chainstate: NODE_NETWORK dropped.
    (let* ((primary (bitcoin-lisp.storage:make-chain-state))
           (snap (bitcoin-lisp.storage:make-chain-state
                  :from-snapshot-blockhash (%au-hash 5)
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot"))
           (node (bitcoin-lisp::make-node :network :testnet3)))
      (setf (bitcoin-lisp.storage:chain-state-target-blockhash primary) (%au-hash 5))
      (setf (bitcoin-lisp::node-chainstates node) (list primary snap))
      (let ((bitcoin-lisp::*node* node)
            (bitcoin-lisp::*prune-target-mib* nil))
        (is (not (null (bitcoin-lisp::node-historical-chainstate node))))
        (let ((bits (bitcoin-lisp.networking::local-service-bits)))
          (is (not (logtest bits network)))
          (is (logtest bits limited))
          (is (logtest bits witness)))))))

;;;; getchainstates over dual chainstates

(test assumeutxo-getchainstates-dual
  "getchainstates reports both chainstates truthfully: historical first
(validated true, no snapshot_blockhash), current snapshot chainstate last
(validated false, snapshot_blockhash present), headers from the best header."
  (let* ((base-hash (%au-hash 5))
         (g (%au-entry (%au-hash 0) 0 nil :status :valid :chain-work 1))
         (e1 (%au-entry (%au-hash 1) 1 g :status :valid :chain-work 10))
         (e5 (%au-entry base-hash 5 e1 :status :valid :chain-work 500))
         (e6 (%au-entry (%au-hash 6) 6 e5 :chain-work 600))
         (primary (bitcoin-lisp.storage:make-chain-state
                   :best-block-hash (%au-hash 1) :best-height 1))
         (snap (bitcoin-lisp.storage:make-chain-state
                :best-block-hash base-hash :best-height 5
                :block-index (bitcoin-lisp.storage::chain-state-block-index primary)
                :from-snapshot-blockhash base-hash
                :assumeutxo-status :unvalidated
                :storage-suffix "_snapshot"))
         (node (bitcoin-lisp::make-node :network :testnet3)))
    (dolist (e (list g e1 e5 e6))
      (bitcoin-lisp.storage:add-block-index-entry primary e))
    (bitcoin-lisp.storage:set-chainstate-target primary e5)
    (setf (bitcoin-lisp::node-chainstates node) (list primary snap))
    (let* ((r (bitcoin-lisp.rpc::rpc-getchainstates node nil))
           (entries (cdr (assoc "chainstates" r :test #'string=)))
           (hist-entry (first entries))
           (cur-entry (second entries)))
      (is (= 2 (length entries)))
      ;; headers = best header height (e6), above both tips.
      (is (= 6 (cdr (assoc "headers" r :test #'string=))))
      ;; Historical entry: the primary, still validated, no snapshot hash.
      (is (= 1 (cdr (assoc "blocks" hist-entry :test #'string=))))
      (is (eq t (cdr (assoc "validated" hist-entry :test #'string=))))
      (is (null (assoc "snapshot_blockhash" hist-entry :test #'string=)))
      ;; Current entry: the snapshot chainstate, unvalidated, hash present.
      (is (= 5 (cdr (assoc "blocks" cur-entry :test #'string=))))
      (is (null (cdr (assoc "validated" cur-entry :test #'string=))))
      (is (string= (bitcoin-lisp.rpc::hash-to-hex base-hash)
                   (cdr (assoc "snapshot_blockhash" cur-entry :test #'string=)))))))
