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

;;; Temp dirs use the shared WITH-TEMP-DIRECTORY (tests/support/).

(defun %au-hash (byte &optional (second 0))
  "A 32-byte hash with BYTE at index 0 and SECOND at index 1."
  (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref h 0) byte (aref h 1) second)
    h))

(defun %au-entry (hash height prev &key (status :header-valid) (chain-work 0))
  (bl.store:make-block-index-entry
   :hash hash :height height :prev-entry prev
   :chain-work chain-work :status status))

(defun %au-close-chainstate-dbs (node)
  "Close every chainstate's coins LevelDB so the same datadir can be
re-opened by a second in-process node (simulated restart)."
  (dolist (cs (bl:node-chainstates node))
    (bl.store:close-chainstate-coins-view cs)))

;;;; Target-ancestor index + activate-block target guard

(test assumeutxo-target-ancestors-index
  "set-chainstate-target builds the height->entry ancestor index; siblings
off the target path and heights past the target are excluded."
  (let* ((g (%au-entry (%au-hash 0) 0 nil :status :valid))
         (e1 (%au-entry (%au-hash 1) 1 g))
         (e2 (%au-entry (%au-hash 2) 2 e1))
         (s2 (%au-entry (%au-hash 2 99) 2 e1))   ; sibling of e2
         (e3 (%au-entry (%au-hash 3) 3 e2))
         (cs (bl.store:make-chain-state)))
    (bl.store:set-chainstate-target cs e3)
    (is (equalp (%au-hash 3) (bl.store:chain-state-target-blockhash cs)))
    (is (= 3 (bl.store:chain-state-target-height cs)))
    (is (eq g (bl.store:target-ancestor-entry cs 0)))
    (is (eq e2 (bl.store:target-ancestor-entry cs 2)))
    (is (eq e3 (bl.store:target-ancestor-entry cs 3)))
    (is (null (bl.store:target-ancestor-entry cs 4)))
    (is (bl.store:entry-target-ancestor-p cs e1))
    (is (bl.store:entry-target-ancestor-p cs e3))
    (is (not (bl.store:entry-target-ancestor-p cs s2)))
    ;; entry-ancestor-at-height (the GetAncestor walk).
    (is (eq e1 (bl.store:entry-ancestor-at-height e3 1)))
    (is (eq e1 (bl.store:entry-ancestor-at-height s2 1)))
    (is (null (bl.store:entry-ancestor-at-height e1 3)))
    ;; Clearing the target drops the index.
    (bl.store:set-chainstate-target cs nil)
    (is (null (bl.store:chain-state-target-blockhash cs)))
    (is (null (bl.store:chain-state-target-height cs)))))

(test assumeutxo-activate-block-target-guard
  "A targeted (historical) chainstate connects ONLY blocks on the exact
ancestor path of its target: an equal-work sibling extending the same tip is
stored but refused (:weaker-chain) — Core TryAddBlockIndexCandidate — and so
is any block past the target (ReachedTarget stops the chainstate)."
  (with-network (:mainnet)
   (multiple-value-bind (cs utxo store genesis-hash)
       (make-activate-block-fixture "target-guard")
     ;; Connect A1; then index A2 (target), S2 (sibling of A2), A3 (past).
     (build-and-connect cs store utxo genesis-hash
                         (make-test-chain-hashes #xA1 1))
     (let* ((a1-hash (bl.store:best-block-hash cs))
            (a1-entry (bl.store:get-block-index-entry cs a1-hash))
            (a2-hash (%au-hash #xA2))
            (s2-hash (%au-hash #xB2))
            (a3-hash (%au-hash #xA3))
            (a2-entry (%au-entry a2-hash 2 a1-entry :chain-work 200))
            (s2-entry (%au-entry s2-hash 2 a1-entry :chain-work 200))
            (a3-entry (%au-entry a3-hash 3 a2-entry :chain-work 300)))
       (bl.store:add-block-index-entry cs a2-entry)
       (bl.store:add-block-index-entry cs s2-entry)
       (bl.store:add-block-index-entry cs a3-entry)
       (bl.store:set-chainstate-target cs a2-entry)
       ;; Sibling S2 extends the current tip (A1) but is off-path: refused,
       ;; tip unmoved. Without the guard this would connect (case 1) and
       ;; wedge the historical chainstate forever.
       (multiple-value-bind (ok err)
           (bl.val:activate-block
            (make-reorg-test-block a1-hash s2-hash 2) cs store utxo
            :skip-scripts t)
         (is (null ok))
         (is (eq :weaker-chain err)))
       (is (= 1 (bl.store:current-height cs)))
       ;; ... but the refused block was stored for the block store's benefit.
       (is (not (null (bl.store:get-block store s2-hash))))
       ;; On-path A2 connects and reaches the target.
       (multiple-value-bind (ok err)
           (bl.val:activate-block
            (make-reorg-test-block a1-hash a2-hash 2) cs store utxo
            :skip-scripts t)
         (is (eq t ok))
         (is (null err)))
       (is (= 2 (bl.store:current-height cs)))
       (is (equalp a2-hash (bl.store:best-block-hash cs)))
       ;; A3 extends the tip but lies PAST the target: refused.
       (multiple-value-bind (ok err)
           (bl.val:activate-block
            (make-reorg-test-block a2-hash a3-hash 3) cs store utxo
            :skip-scripts t)
         (is (null ok))
         (is (eq :weaker-chain err)))
       (is (= 2 (bl.store:current-height cs)))
       ;; An untargeted chainstate is unaffected: clearing the target lets
       ;; A3 connect normally.
       (bl.store:set-chainstate-target cs nil)
       (multiple-value-bind (ok err)
           (bl.val:activate-block
            (make-reorg-test-block a2-hash a3-hash 3) cs store utxo
            :skip-scripts t)
         (is (eq t ok))
         (is (null err)))
       (is (= 3 (bl.store:current-height cs))))
     (clrhash bl.val::*block-undo-data*))))

;;;; Startup re-detection of a persisted snapshot chainstate

(test assumeutxo-startup-redetection
  "After a verified loadtxoutset, a fresh node over the same datadir
re-detects the snapshot chainstate from the chainstate_snapshot/ dir + its
base_blockhash marker: dual chainstates are rebuilt with the snapshot
chainstate current (:unvalidated — never persisted, re-derived), its tip
loaded from chainstate_snapshot.dat, its coins reopened, and the primary
retargeted at the base."
  (with-temp-directory (src-dir)
    (with-temp-directory (dir)
      (let* ((bl:*prune-target-mib* nil) ; deterministic: pruning off
             (h5 (%snap-fill 32 5))
             (txid (%snap-fill 32 #x33))
             (spk (%snap-cat #(#x51)))
             (src (%snap-node src-dir h5 5))
             (snap-path (namestring (merge-pathnames "utxo.dat" src-dir))))
        ;; Produce a 1-coin snapshot from the source node.
        (bl.store:update-chain-tip
         (bl:node-chain-state src) h5 5)
        (bl.store:add-utxo (bl:node-utxo-set src)
                                       txid 0 1000 spk 1)
        (bl.rpc::rpc-dumptxoutset src (list snap-path "latest"))
        (let ((hash (bl.store:compute-utxo-set-hash
                     (bl:node-utxo-set src))))
          ;; Load it into the destination node (activation).
          (let ((node (%snap-node dir h5 5))
                (bl:*assumeutxo-data-override*
                  (list (%snap-au 5 h5 hash 7))))
            (bl.rpc::rpc-loadtxoutset node (list snap-path))
            (is (= 2 (length (bl:node-chainstates node))))
            ;; "Restart": close the LevelDBs, build a fresh node over the
            ;; same datadir (header index recreated by %snap-node), detect.
            (%au-close-chainstate-dbs node)
            (let ((fresh (%snap-node dir h5 5)))
              (unwind-protect
                   (let ((snap-cs (bl::load-snapshot-chainstate fresh)))
                     (is (not (null snap-cs)))
                     (is (= 2 (length (bl:node-chainstates fresh))))
                     (let ((current (bl:node-current-chainstate fresh))
                           (historical (bl:node-historical-chainstate fresh)))
                       (is (eq current snap-cs))
                       (is (eq :unvalidated
                               (bl.store:chain-state-assumeutxo-status
                                current)))
                       (is (equalp h5 (bl.store:chain-state-from-snapshot-blockhash
                                       current)))
                       ;; Tip restored from chainstate_snapshot.dat.
                       (is (= 5 (bl.store:current-height current)))
                       (is (equalp h5 (bl.store:best-block-hash current)))
                       ;; Primary retargeted at the base; target index built.
                       (is (not (null historical)))
                       (is (equalp h5 (bl.store:chain-state-target-blockhash
                                       historical)))
                       (is (= 5 (bl.store:chain-state-target-height
                                 historical)))
                       ;; Shared block index.
                       (is (eq (bl.store:chain-state-block-index current)
                               (bl.store:chain-state-block-index historical)))
                       ;; Coins reopened from chainstate_snapshot/.
                       (let ((c (bl.store:get-utxo
                                 (bl.store:chain-state-coins-view current)
                                 txid 0)))
                         (is (and c (= 1000 (bl.store:utxo-entry-value c)))))))
                (%au-close-chainstate-dbs fresh)))))))))

(test assumeutxo-startup-redetection-rejects
  "Startup detection is conservative: a snapshot dir without a base_blockhash
marker, or whose base header is missing from the index, does NOT create a
second chainstate (single-chainstate startup, dir left for later adoption)."
  (with-temp-directory (dir)
    ;; Case 1: dir exists but no marker.
    (ensure-directories-exist (merge-pathnames "chainstate_snapshot/" dir))
    (let ((node (make-test-node)))
      (setf (bl:node-data-directory node) (pathname dir))
      (is (null (bl::load-snapshot-chainstate node)))
      (is (= 1 (length (bl:node-chainstates node))))
      ;; Case 2: marker present but the base header is unknown.
      (with-open-file (out (bl.store:snapshot-base-blockhash-path
                            (merge-pathnames "chainstate_snapshot/" dir))
                           :direction :output :element-type '(unsigned-byte 8)
                           :if-exists :supersede)
        (write-sequence (%au-hash #x77) out))
      (is (null (bl::load-snapshot-chainstate node)))
      (is (= 1 (length (bl:node-chainstates node))))
      (is (null (bl.store:chain-state-target-blockhash
                 (bl:node-chain-state node)))))))

;;;; Dual-cursor download queue + base-in-chain peer filter

(test assumeutxo-dual-cursor-queueing
  "queue-historical-blocks queues exactly the target-ancestor path above the
historical tip (never sibling forks); find-historical-blocks-to-download windows
the historical range per peer, yielding [hist-tip+1 .. base] only to peers whose
chain contains the base (Core fills FindNextBlocksToDownload slots before
TryDownloadingHistoricalBlocks)."
  (let* ((g (%au-entry (%au-hash 0) 0 nil :status :valid))
         (e1 (%au-entry (%au-hash 1) 1 g :status :valid))
         (e2 (%au-entry (%au-hash 2) 2 e1))
         (e3 (%au-entry (%au-hash 3) 3 e2))
         (s3 (%au-entry (%au-hash 3 99) 3 e2))   ; sibling off the path
         (e4 (%au-entry (%au-hash 4) 4 e3))
         (e5 (%au-entry (%au-hash 5) 5 e4))      ; snapshot base
         (hist (bl.store:make-chain-state))
         (bl.net:*ibd-context*
           (bl.net::make-ibd)))
    (dolist (e (list g e1 e2 e3 s3 e4 e5))
      (bl.store:add-block-index-entry hist e))
    (bl.store:update-chain-tip hist (%au-hash 1) 1)
    (bl.store:set-chainstate-target hist e5)
    (let ((ctx bl.net:*ibd-context*))
      ;; Queue the historical range: exactly e2..e5, sibling excluded.
      (is (= 4 (bl.net::queue-historical-blocks hist)))
      (let ((pending (bl.net:ibd-context-pending-blocks ctx)))
        (is (= 4 (hash-table-count pending)))
        (is (gethash (%au-hash 2) pending))
        (is (gethash (%au-hash 5) pending))
        (is (null (gethash (%au-hash 3 99) pending)))
        ;; Re-queueing is idempotent.
        (is (= 0 (bl.net::queue-historical-blocks hist)))
        ;; Configure the dual-cursor context.
        (setf (bl.net::ibd-context-historical-chain-state ctx) hist
              (bl.net::ibd-context-snapshot-base-entry ctx) e5)
        ;; Historical download now comes from the per-peer walk
        ;; (find-historical-blocks-to-download, Core
        ;; TryDownloadingHistoricalBlocks): a peer whose best-known chain
        ;; contains the base yields exactly the target-ancestor range
        ;; [hist-tip+1 .. base] ascending — e2..e5, sibling s3 excluded —
        ;; and a peer on a chain without the base yields nothing.
        (let ((probe-store (bl.store:make-block-store
                            :base-path #p"/nonexistent/au-hist-walk/"))
              (p-base (bl.net:make-peer))
              (p-fork (bl.net:make-peer)))
          (setf (bl.net:peer-best-known-block-hash p-base)
                (%au-hash 5)
                (bl.net:peer-best-known-block-hash p-fork)
                (%au-hash 3 99))
          (let ((got (bl.net::find-historical-blocks-to-download
                      p-base hist probe-store 10)))
            (is (equalp (list (%au-hash 2) (%au-hash 3) (%au-hash 4) (%au-hash 5))
                        got)))
          ;; Budget respected: only the first COUNT ascending hashes.
          (is (= 2 (length (bl.net::find-historical-blocks-to-download
                            p-base hist probe-store 2))))
          (is (null (bl.net::find-historical-blocks-to-download
                     p-fork hist probe-store 10))))))))

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
         (cs (bl.store:make-chain-state))
         (bl.net:*ibd-context*
           (bl.net::make-ibd)))
    (dolist (e (list g e1 e2 e3 s2 s3))
      (bl.store:add-block-index-entry cs e))
    (setf (bl.net::ibd-context-snapshot-base-entry
           bl.net:*ibd-context*)
          e2)
    (let ((p-good (bl.net:make-peer))
          (p-base (bl.net:make-peer))
          (p-fork (bl.net:make-peer))
          (p-none (bl.net:make-peer)))
      (setf (bl.net:peer-best-known-block-hash p-good) (%au-hash 3)
            (bl.net:peer-best-known-block-hash p-base) (%au-hash 2)
            (bl.net:peer-best-known-block-hash p-fork) (%au-hash 3 99))
      (is (eq t (bl.net::peer-chain-contains-base-p p-good cs)))
      ;; The base itself IS in a chain ending at the base.
      (is (eq t (bl.net::peer-chain-contains-base-p p-base cs)))
      (is (not (bl.net::peer-chain-contains-base-p p-fork cs)))
      (is (not (bl.net::peer-chain-contains-base-p p-none cs)))
      ;; Memoized answers are stable.
      (is (eq t (bl.net::peer-chain-contains-base-p p-good cs)))
      (is (not (bl.net::peer-chain-contains-base-p p-fork cs))))))

;;;; Snapshot chainstate crash recovery (simulated partial flush)

(test assumeutxo-snapshot-crash-recovery
  "Per-chainstate 3-phase-commit recovery for a snapshot chainstate: a torn
flush at tip==base just clears the marker (populate committed the coins
atomically before the tip ever moved); a torn flush above the base with no
committed descendant block on disk rewinds to the base — whose coins ARE the
verified snapshot — never below it."
  (with-temp-directory (dir)
    (let* ((base-hash (%au-hash 5))
           (g (%au-entry (%au-hash 0) 0 nil :status :valid))
           (e5 (%au-entry base-hash 5 g :status :valid))
           (e6 (%au-entry (%au-hash 6) 6 e5 :status :valid))
           (e7 (%au-entry (%au-hash 7) 7 e6 :status :valid))
           (node (make-test-node))
           (snap (bl.store:make-chain-state
                  :base-path (pathname dir)
                  :from-snapshot-blockhash base-hash
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot")))
      (setf (bl:node-data-directory node) (pathname dir)
            (bl:node-block-store node)
            (bl.store:init-block-store dir))
      (dolist (e (list g e5 e6 e7))
        (bl.store:add-block-index-entry snap e))
      (setf (bl.store:chain-state-coins-view snap)
            (bl.store:make-utxo-set))
      ;; Case A: torn flush with the recorded tip AT the base.
      (bl.store:update-chain-tip snap base-hash 5)
      (bl.store:save-state snap :in-transition t)
      (is (eq :inconsistent (bl.store:load-state snap)))
      (is (eq t (bl::recover-inconsistent-chainstate node snap)))
      (is (eq t (bl.store:load-state snap)))
      (is (= 5 (bl.store:current-height snap)))
      ;; Case B: torn flush with the tip ABOVE the base, and none of the
      ;; blocks above the base on disk — recovery walks back and settles on
      ;; the base itself instead of failing (blocks below it don't exist on
      ;; the snapshot side).
      (bl.store:update-chain-tip snap (%au-hash 7) 7)
      (bl.store:save-state snap :in-transition t)
      (is (eq :inconsistent (bl.store:load-state snap)))
      (is (eq t (bl::recover-inconsistent-chainstate node snap)))
      (is (= 5 (bl.store:current-height snap)))
      (is (equalp base-hash (bl.store:best-block-hash snap)))
      (is (eq t (bl.store:load-state snap)))
      ;; The snapshot chainstate's state file is the suffix-named one; the
      ;; primary's file was never created by any of this.
      (is (not (null (probe-file (merge-pathnames "chainstate_snapshot.dat" dir)))))
      (is (null (probe-file (merge-pathnames "chainstate.dat" dir)))))))

;;;; Per-chainstate flush isolation

(test assumeutxo-flush-isolation
  "do-flush writes only the given chainstate's storage-suffix-named state
file: flushing the snapshot chainstate never marks the primary's
chainstate.dat in-transition, and vice versa."
  (with-temp-directory (dir)
    (let* ((primary (bl.store:make-chain-state
                     :base-path (pathname dir)
                     :best-block-hash (%au-hash 1) :best-height 1))
           (snap (bl.store:make-chain-state
                  :base-path (pathname dir)
                  :best-block-hash (%au-hash 5) :best-height 5
                  :from-snapshot-blockhash (%au-hash 5)
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot"))
           (node (bl:make-node :network :testnet3))
           (bl:*node* node))
      (setf (bl:node-chainstates node) (list primary snap))
      ;; Flush the snapshot chainstate only.
      (bl::do-flush snap)
      (is (not (null (probe-file (merge-pathnames "chainstate_snapshot.dat" dir)))))
      (is (null (probe-file (merge-pathnames "chainstate.dat" dir))))
      ;; Flush the primary; both exist now, each with its own tip.
      (bl::do-flush primary)
      (is (not (null (probe-file (merge-pathnames "chainstate.dat" dir)))))
      (let ((p2 (bl.store:make-chain-state :base-path (pathname dir)))
            (s2 (bl.store:make-chain-state :base-path (pathname dir)
                                                       :storage-suffix "_snapshot")))
        (is (eq t (bl.store:load-state p2)))
        (is (eq t (bl.store:load-state s2)))
        (is (= 1 (bl.store:current-height p2)))
        (is (= 5 (bl.store:current-height s2))))
      ;; A torn marker on one never contaminates the other.
      (bl.store:save-state snap :in-transition t)
      (let ((p3 (bl.store:make-chain-state :base-path (pathname dir)))
            (s3 (bl.store:make-chain-state :base-path (pathname dir)
                                                       :storage-suffix "_snapshot")))
        (is (eq t (bl.store:load-state p3)))
        (is (eq :inconsistent (bl.store:load-state s3)))))))

;;;; Service bits (Core init.cpp:863,1946-1953)

(test assumeutxo-service-bits
  "local-services mirrors Core's g_local_services: the base is always
NODE_NETWORK_LIMITED | NODE_WITNESS; NODE_NETWORK is added only when not
pruning AND no historical chainstate exists (i.e. no assumeutxo background
sync in progress)."
  (let ((limited bl.ser:+node-network-limited+)
        (network bl.ser:+node-network+)
        (witness bl.ser:+node-witness+))
    ;; No node at all: full service (not pruning).
    (let ((bl:*node* nil)
          (bl:*prune-target-mib* nil))
      (let ((bits (bl.net:local-services)))
        (is (logtest bits network))
        (is (logtest bits limited))
        (is (logtest bits witness))))
    ;; A node with a historical chainstate: NODE_NETWORK dropped.
    (let* ((primary (bl.store:make-chain-state))
           (snap (bl.store:make-chain-state
                  :from-snapshot-blockhash (%au-hash 5)
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot"))
           (node (bl:make-node :network :testnet3)))
      (setf (bl.store:chain-state-target-blockhash primary) (%au-hash 5))
      (setf (bl:node-chainstates node) (list primary snap))
      (let ((bl:*node* node)
            (bl:*prune-target-mib* nil))
        (is (not (null (bl:node-historical-chainstate node))))
        (let ((bits (bl.net:local-services)))
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
         (primary (bl.store:make-chain-state
                   :best-block-hash (%au-hash 1) :best-height 1))
         (snap (bl.store:make-chain-state
                :best-block-hash base-hash :best-height 5
                :block-index (bl.store:chain-state-block-index primary)
                :from-snapshot-blockhash base-hash
                :assumeutxo-status :unvalidated
                :storage-suffix "_snapshot"))
         (node (bl:make-node :network :testnet3)))
    (dolist (e (list g e1 e5 e6))
      (bl.store:add-block-index-entry primary e))
    (bl.store:set-chainstate-target primary e5)
    (setf (bl:node-chainstates node) (list primary snap))
    (let* ((r (bl.rpc::rpc-getchainstates node nil))
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
      (is (eq 'yason:false (cdr (assoc "validated" cur-entry :test #'string=))))
      (is (string= (bl.rpc:hash-to-hex base-hash)
                   (cdr (assoc "snapshot_blockhash" cur-entry :test #'string=)))))))

;;;; P5: background-validation completion + promotion
;;;;
;;;; MaybeValidateSnapshot (Core validation.cpp:5986-6096) at the connect-tip
;;;; hook and at startup, the INVALID/fatal path, and the startup
;;;; ValidatedSnapshotCleanup dir swap (validation.cpp:6299-6364).

(defun %snap-validation-fixture (dir)
  "Build the shared dual-chainstate setup for the P5 invalid-snapshot tests: a
historical (validated-from-genesis) chainstate sitting on the snapshot base
(h5) with a known in-memory 1-coin UTXO set, and a snapshot chainstate whose
coins live in a REAL LevelDB at chainstate_snapshot/ so the rename-aside /
dir-swap paths run against a genuine open+closed DB. Returns
(values node historical snap base-hash); the caller binds *node* and commits
the assumeutxo-data-override hash."
  (let* ((base-hash (%au-hash 5))
         (g (%au-entry (%au-hash 0) 0 nil :status :valid :chain-work 1))
         (e5 (%au-entry base-hash 5 g :status :valid :chain-work 500))
         (historical (bl.store:make-chain-state
                      :base-path (pathname dir)
                      :best-block-hash base-hash :best-height 5))
         (snap-dir (namestring (ensure-directories-exist
                                (merge-pathnames "chainstate_snapshot/" dir))))
         (snap (bl.store:make-chain-state
                :base-path (pathname dir)
                :best-block-hash base-hash :best-height 5
                :block-index (bl.store:chain-state-block-index historical)
                :from-snapshot-blockhash base-hash
                :assumeutxo-status :unvalidated
                :storage-suffix "_snapshot"))
         (node (bl:make-node :network :testnet3))
         (hv (bl.store:make-utxo-set)))
    (setf (bl:node-data-directory node) (pathname dir))
    (dolist (e (list g e5))
      (bl.store:add-block-index-entry historical e))
    (bl.store:add-utxo hv (%snap-fill 32 #x44) 0 1000 (%snap-cat #(#x51)) 1)
    (setf (bl.store:chain-state-coins-view historical) hv
          (bl.store:chain-state-coins-view snap)
          (bl.store:make-coins-view-cache
           (bl.store:open-coins-view-db snap-dir))
          (bl:node-chainstates node) (list historical snap))
    (bl.store:set-chainstate-target historical e5)
    (values node historical snap base-hash)))

(test assumeutxo-maybe-validate-snapshot-promotes
  "maybe-validate-snapshot at the connect-tip hook: when the historical
chainstate reaches the snapshot base and its UTXO set re-hashes to the
committed hash_serialized_3, the snapshot chainstate is promoted to VALIDATED,
the historical records its target-utxohash (so it is no longer selected as the
historical chainstate), services regain NODE_NETWORK, and getchainstates
reports a single validated current chainstate (Core MaybeValidateSnapshot
SUCCESS, validation.cpp:6088-6095). A second call is a no-op."
  (with-temp-directory (dir)
    (let* ((base-hash (%au-hash 5))
           (txid (%snap-fill 32 #x44))
           (spk (%snap-cat #(#x51)))
           (g (%au-entry (%au-hash 0) 0 nil :status :valid :chain-work 1))
           (e5 (%au-entry base-hash 5 g :status :valid :chain-work 500))
           (e6 (%au-entry (%au-hash 6) 6 e5 :chain-work 600))
           (historical (bl.store:make-chain-state
                        :base-path (pathname dir)
                        :best-block-hash base-hash :best-height 5))
           (snap (bl.store:make-chain-state
                  :base-path (pathname dir)
                  :best-block-hash (%au-hash 6) :best-height 6
                  :block-index (bl.store:chain-state-block-index historical)
                  :from-snapshot-blockhash base-hash
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot"))
           (node (bl:make-node :network :testnet3))
           (bl:*node* node)
           (bl:*prune-target-mib* nil))
      (dolist (e (list g e5 e6))
        (bl.store:add-block-index-entry historical e))
      (let ((hv (bl.store:make-utxo-set)))
        (bl.store:add-utxo hv txid 0 1000 spk 1)
        (setf (bl.store:chain-state-coins-view historical) hv))
      (setf (bl.store:chain-state-coins-view snap)
            (bl.store:make-utxo-set)
            (bl:node-chainstates node) (list historical snap))
      ;; Retarget the historical at the base (it becomes the historical cs).
      (bl.store:set-chainstate-target historical e5)
      (is (eq historical (bl:node-historical-chainstate node)))
      (is (eq snap (bl:node-current-chainstate node)))
      ;; P6 pre-state: a floored prune cursor above the base and a split
      ;; cache budget, to prove promotion rewinds/releases them.
      (setf (bl.store:chain-state-pruned-height snap) 100
            (bl.store:chain-state-pruned-height historical) 3
            (bl.store:chain-state-coins-cache-bytes snap) 12345)
      ;; While background validation is in progress, NODE_NETWORK is dropped.
      (is (not (logtest (bl.net:local-services)
                        bl.ser:+node-network+)))
      ;; Commit the historical's real hash and run the completion hook.
      (let* ((hash (bl.store:compute-utxo-set-hash
                    (bl.store:chain-state-coins-view historical)))
             (bl:*assumeutxo-data-override*
               (list (%snap-au 5 base-hash hash 7))))
        (is (eq :success (bl:maybe-validate-snapshot historical)))
        ;; Idempotent: the snapshot is already validated now.
        (is (eq :skipped (bl:maybe-validate-snapshot historical))))
      ;; Snapshot chainstate promoted; historical marked done.
      (is (eq :validated (bl.store:chain-state-assumeutxo-status snap)))
      (is (not (null (bl.store:chain-state-target-utxohash historical))))
      ;; P6: promotion lifts the prune floor — the cursor rewinds to the
      ;; historical chainstate's so the protected window can be reclaimed —
      ;; and rebalances the whole coins-cache budget onto the promoted cs.
      (is (= 0 (bl.store:chain-state-prune-floor snap)))
      (is (= 3 (bl.store:chain-state-pruned-height snap)))
      (is (null (bl.store:chain-state-coins-cache-bytes snap)))
      ;; No historical chainstate remains; the snapshot cs is now validated.
      (is (null (bl:node-historical-chainstate node)))
      (is (eq snap (bl:node-current-chainstate node)))
      (is (eq snap (bl:node-validated-chainstate node)))
      ;; Services regain NODE_NETWORK (unpruned + no historical chainstate).
      (is (logtest (bl.net:local-services)
                   bl.ser:+node-network+))
      ;; getchainstates now reports a single validated chainstate.
      (let* ((r (bl.rpc::rpc-getchainstates node nil))
             (entries (cdr (assoc "chainstates" r :test #'string=))))
        (is (= 1 (length entries)))
        (is (eq t (cdr (assoc "validated" (first entries) :test #'string=))))))))

(test assumeutxo-maybe-validate-snapshot-rejects-bad-hash
  "A background chainstate whose UTXO set does NOT reproduce the committed
hash_serialized_3 marks the snapshot chainstate :invalid, resets the
historical chainstate's target back to the network tip, renames the snapshot
LevelDB dir to chainstate_snapshot_INVALID for forensics, and fires the fatal
shutdown decision (Core handle_invalid_snapshot + InvalidateCoinsDBOnDisk,
validation.cpp:6006-6036). The decision path is exercised via a rebound
*snapshot-fatal-hook* — no actual process exit."
  (with-temp-directory (dir)
    (multiple-value-bind (node historical snap base-hash)
        (%snap-validation-fixture dir)
      (let ((bl:*node* node)
            (bl:*prune-target-mib* nil)
            (fatal-msg nil))
        ;; Commit a DIFFERENT hash than the historical set actually produces.
        (let ((bl:*assumeutxo-data-override*
                (list (%snap-au 5 base-hash (%au-hash #x99) 7)))
              (bl::*snapshot-fatal-hook*
                (lambda (msg) (setf fatal-msg msg))))
          (is (eq :hash-mismatch (bl:maybe-validate-snapshot historical))))
        ;; The fatal DECISION fired (message recorded) — but no process exit.
        (is (not (null fatal-msg)))
        (is (search "hash mismatch" fatal-msg))
        ;; Snapshot chainstate marked invalid; historical target reset to tip.
        (is (eq :invalid (bl.store:chain-state-assumeutxo-status snap)))
        (is (null (bl.store:chain-state-target-blockhash historical)))
        ;; Reverts to the validated chain: no historical; current = historical.
        (is (null (bl:node-historical-chainstate node)))
        (is (eq historical (bl:node-current-chainstate node)))
        ;; Coins dir renamed aside for forensics; the original name is gone.
        (is (null (bl.store:find-assumeutxo-chainstate-dir dir)))
        (is (not (null (probe-file (merge-pathnames "chainstate_snapshot_INVALID/" dir)))))))))

(test assumeutxo-validated-snapshot-cleanup-startup
  "Startup ValidatedSnapshotCleanup (Core validation.cpp:6299-6364): when a
persisted historical chainstate has already reached the snapshot base,
finalize-snapshot-validation-at-startup re-proves the hash and swaps the
LevelDB dirs — chainstate_snapshot/ becomes chainstate/, the old background
chainstate is deleted — leaving the node with a single fully-validated
chainstate whose coins view is the (formerly snapshot) promoted set."
  (with-temp-directory (dir)
    (let* ((base-hash (%au-hash 5))
           (txid-h (%snap-fill 32 #x11))     ; only in the background chainstate
           (txid-s (%snap-fill 32 #x22))     ; only in the snapshot chainstate
           (spk (%snap-cat #(#x51)))
           (g (%au-entry (%au-hash 0) 0 nil :status :valid :chain-work 1))
           (e5 (%au-entry base-hash 5 g :status :valid :chain-work 500))
           (cs-dir (namestring (ensure-directories-exist
                                (merge-pathnames "chainstate/" dir))))
           (snap-dir (namestring (ensure-directories-exist
                                  (merge-pathnames "chainstate_snapshot/" dir))))
           (historical (bl.store:make-chain-state
                        :base-path (pathname dir)
                        :best-block-hash base-hash :best-height 5))
           (snap (bl.store:make-chain-state
                  :base-path (pathname dir)
                  :best-block-hash base-hash :best-height 5
                  :block-index (bl.store:chain-state-block-index historical)
                  :from-snapshot-blockhash base-hash
                  :assumeutxo-status :unvalidated
                  :storage-suffix "_snapshot"))
           (node (bl:make-node :network :testnet3))
           (bl:*node* node)
           (bl:*prune-target-mib* nil))
      (setf (bl:node-data-directory node) (pathname dir))
      (dolist (e (list g e5))
        (bl.store:add-block-index-entry historical e))
      ;; Background chainstate coins at chainstate/ (its hash is committed).
      (let ((hv (bl.store:make-coins-view-cache
                 (bl.store:open-coins-view-db cs-dir))))
        (bl.store:add-utxo hv txid-h 0 1000 spk 1)
        (bl.store:coins-view-cache-flush hv)
        (setf (bl.store:chain-state-coins-view historical) hv))
      ;; Snapshot chainstate coins at chainstate_snapshot/ (a DISTINCT set, so
      ;; we can prove the dir physically moved into place).
      (let ((sv (bl.store:make-coins-view-cache
                 (bl.store:open-coins-view-db snap-dir))))
        (bl.store:add-utxo sv txid-s 0 2000 spk 1)
        (bl.store:coins-view-cache-flush sv)
        (setf (bl.store:chain-state-coins-view snap) sv))
      (bl.store:write-snapshot-base-blockhash snap)
      (bl.store:save-state historical)
      (bl.store:save-state snap)
      (setf (bl:node-chainstates node) (list historical snap))
      (bl.store:set-chainstate-target historical e5)
      (let* ((hash (bl.store:compute-utxo-set-hash
                    (bl.store:chain-state-coins-view historical)))
             (bl:*assumeutxo-data-override*
               (list (%snap-au 5 base-hash hash 7))))
        (is (eq :success (bl::finalize-snapshot-validation-at-startup node))))
      ;; A single fully-validated chainstate remains.
      (is (= 1 (length (bl:node-chainstates node))))
      (is (null (bl:node-historical-chainstate node)))
      (let ((cs (bl:node-current-chainstate node)))
        (is (string= "" (bl.store:chain-state-storage-suffix cs)))
        (is (null (bl.store:chain-state-from-snapshot-blockhash cs)))
        (is (null (bl.store:chain-state-target-blockhash cs)))
        (is (eq :validated (bl.store:chain-state-assumeutxo-status cs)))
        (is (eq cs (bl:node-validated-chainstate node)))
        ;; The promoted coins view is the (formerly snapshot) set at chainstate/.
        (let ((s (bl.store:get-utxo
                  (bl.store:chain-state-coins-view cs) txid-s 0))
              (h (bl.store:get-utxo
                  (bl.store:chain-state-coins-view cs) txid-h 0)))
          (is (and s (= 2000 (bl.store:utxo-entry-value s))))
          (is (null h)))
        ;; On-disk: snapshot dir consumed, default dir present, marker gone.
        (is (null (bl.store:find-assumeutxo-chainstate-dir dir)))
        (is (not (null (probe-file (merge-pathnames "chainstate/" dir)))))
        (is (null (probe-file (merge-pathnames "chainstate_snapshot.dat" dir))))
        (is (not (null (probe-file (merge-pathnames "chainstate.dat" dir)))))
        (bl.store:close-chainstate-coins-view cs)))))

(test assumeutxo-finalize-startup-aborts-on-bad-hash
  "At startup a persisted historical chainstate that reached the base but
whose UTXO set fails the commitment aborts node startup (Core FAILURE_FATAL,
node/chainstate.cpp:231-235) and still renames the snapshot dir aside."
  (with-temp-directory (dir)
    (multiple-value-bind (node historical snap base-hash)
        (%snap-validation-fixture dir)
      (declare (ignore historical))
      (let ((bl:*node* node)
            (bl:*prune-target-mib* nil))
        (let ((bl:*assumeutxo-data-override*
                (list (%snap-au 5 base-hash (%au-hash #x99) 7))))
          (signals error (bl::finalize-snapshot-validation-at-startup node)))
        (is (eq :invalid (bl.store:chain-state-assumeutxo-status snap)))
        (is (null (bl.store:find-assumeutxo-chainstate-dir dir)))
        (is (not (null (probe-file (merge-pathnames "chainstate_snapshot_INVALID/" dir)))))))))

;;;; P6: coins-cache rebalancing (Core ChainstateManager::MaybeRebalanceCaches,
;;;; validation.cpp:6103-6134)

(test assumeutxo-cache-rebalance
  "maybe-rebalance-caches splits the coins-cache budget 95/5 by IBD status
while both chainstates exist — snapshot(current)-heavy during IBD,
historical-heavy once the tip is synced (the IBD-exit latch drives
rebalance-caches-on-ibd-exit, Core validation.cpp:3479-3486) — and hands
everything back to a sole chainstate (budget slot NIL = whole global
budget)."
  (let* ((base-hash (%au-hash 5))
         (g (%au-entry (%au-hash 0) 0 nil :status :valid :chain-work 1))
         (e5 (%au-entry base-hash 5 g :status :valid :chain-work 500))
         (primary (bl.store:make-chain-state
                   :best-block-hash (%au-hash 0) :best-height 0))
         (snap (bl.store:make-chain-state
                :best-block-hash base-hash :best-height 5
                :block-index (bl.store:chain-state-block-index primary)
                :from-snapshot-blockhash base-hash
                :assumeutxo-status :unvalidated
                :storage-suffix "_snapshot"))
         (node (bl:make-node :network :testnet3))
         (total (* 1000 1048576))
         (bl::*coins-cache-budget-bytes* total))
    (dolist (e (list g e5))
      (bl.store:add-block-index-entry primary e))
    (bl.store:set-chainstate-target primary e5)
    (setf (bl:node-chainstates node) (list primary snap))
    ;; During IBD: 95% to the snapshot (current) chainstate.
    (let ((bl.net:*cached-is-ibd* t))
      (bl::maybe-rebalance-caches node))
    (is (= (floor (* total 0.95d0))
           (bl.store:chain-state-coins-cache-bytes snap)))
    (is (= (floor (* total 0.05d0))
           (bl.store:chain-state-coins-cache-bytes primary)))
    (is (= (floor (* total 0.95d0))
           (bl:chainstate-coins-cache-budget snap)))
    ;; IBD exit flips the split toward the historical chainstate.
    (let ((bl.net:*cached-is-ibd* nil)
          (bl:*node* node))
      (bl:rebalance-caches-on-ibd-exit))
    (is (= (floor (* total 0.05d0))
           (bl.store:chain-state-coins-cache-bytes snap)))
    (is (= (floor (* total 0.95d0))
           (bl.store:chain-state-coins-cache-bytes primary)))
    ;; Background completion ends the historical role: everything to the
    ;; current chainstate (NIL slot = the whole global budget).
    (setf (bl.store:chain-state-target-utxohash primary) (%au-hash 9))
    (bl::maybe-rebalance-caches node)
    (is (null (bl.store:chain-state-coins-cache-bytes snap)))
    (is (= total (bl:chainstate-coins-cache-budget snap)))
    ;; A no-op when no historical chainstate exists and *node* is unset.
    (let ((bl:*node* nil))
      (bl:rebalance-caches-on-ibd-exit))
    (is (null (bl.store:chain-state-coins-cache-bytes snap)))))
