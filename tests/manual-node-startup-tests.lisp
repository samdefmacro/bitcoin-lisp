(in-package #:bitcoin-lisp.tests)

;;;; End-to-end node-startup tests -- NOT in the bitcoin-lisp/tests system.
;;;;
;;;; These drive the whole of BL:START-NODE over a real datadir, which is the
;;;; only way to test what GA11 bbf6e679 and 4452772a are about: a node that
;;;; comes back up over a chainstate that disagrees with its blocks. Run them
;;;; on their own, in a fresh image:
;;;;
;;;;   scripts/dev.sh load tests/manual-node-startup-tests.lisp
;;;;   scripts/dev.sh eval '(fiveam:run! :node-startup-tests)'
;;;;
;;;; They are kept OUT of the battery because a full BL:START-NODE stalls when
;;;; it runs late in one: the first start in
;;;; STARTUP-REFUSES-A-CORRUPTED-BLOCK-DATABASE gets as far as opening its log
;;;; file and never returns, and the run then ends with no red test and no
;;;; check count at all ("gate reported success but no checks were counted"),
;;;; which is worse than either passing or failing. Reproduced on four
;;;; cold-unit-fresh runs and on the warm battery; the same tests pass every
;;;; time on their own. What a node start depends on is not only its arguments
;;;; -- it is the globals it reads on the way in and every LevelDB handle and
;;;; thread the thousand tests before it left open -- and running them first
;;;; is not available either, since fiveam does not order child suites by load
;;;; order. Two of those globals ARE now handled (%WITH-TEMPORARY-NODE clears
;;;; BL:*NODE* and the block-index persist hook, which START-NODE and a later
;;;; coins-cache sync respectively read); what remains is unidentified, and
;;;; putting a stall into the battery to keep chasing it is the wrong trade.

(def-suite :node-startup-tests
  :description "BL:START-NODE end to end over a real datadir (manual)")

(in-suite :node-startup-tests)

(defun %release-datadir-lock ()
  "Drop the datadir lock a running node holds, without any of the flushing
STOP-NODE does -- what a killed process leaves behind, and what a test that
restarts a node over the same directory needs before it can."
  (bl::unlock-data-directory))

(defun %start-test-node (&rest args)
  "BL:START-NODE, with the fail-fast debugger hook it installs handed straight
back. Returns the node.

START-NODE sets SB-EXT:*INVOKE-DEBUGGER-HOOK* to a hook that logs a condition
and calls (sb-ext:exit :code 1) -- right for a supervised node, fatal for a
test image, where it turns the NEXT unhandled condition anywhere into a
process exit with no failure and no check count. A test wants the node, not
its process-suicide policy, so this puts the caller's hook back at once rather
than at the end of the fixture: an error later in the same test is then
reported by the runner instead of killing it."
  (let ((hook sb-ext:*invoke-debugger-hook*))
    (unwind-protect
         ;; Report a condition raised INSIDE start-node before the hook it has
         ;; already installed can exit the process on it: declining leaves the
         ;; behaviour unchanged, but the message reaches the test log instead
         ;; of dying with it.
         (handler-bind ((serious-condition
                          (lambda (c)
                            (format *standard-output*
                                    "~&start-test-node: ~A: ~A~%" (type-of c) c)
                            (finish-output *standard-output*))))
           (apply #'bl:start-node args))
      (setf sb-ext:*invoke-debugger-hook* hook))))

(defmacro %with-temporary-node ((base-var prefix) &body body)
  "Run BODY over a fresh datadir bound to BASE-VAR, restoring every
process-global a full BL:START-NODE leaves behind and deleting the directory
afterwards. BODY starts and stops the node itself -- some tests start it more
than once over the same directory.

BL:*NODE* and BL.STORE:*PERSIST-BLOCK-INDEX-HOOK* are cleared BEFORE the body,
not only restored after. START-NODE opens with (when *node* ... (stop-node)),
and STOP-NODE waits up to 600 SECONDS for that node's sync thread, so a global
node another suite left behind is a ten-minute stall rather than a failure; and
the persist hook reads BL:*NODE* whenever a coins-cache sync stages the coins
pointer, so a foreign node there makes a later flush persist THAT node's header
index -- a chain-state with no base path type-errors inside merge-pathnames."
  (let ((hook (gensym "HOOK")) (node (gensym "NODE"))
        (persist (gensym "PERSIST")) (network (gensym "NETWORK")))
    `(let ((,base-var (ensure-directories-exist
                       (merge-pathnames (format nil "~A-~D/" ,prefix
                                                (get-internal-real-time))
                                        (uiop:temporary-directory))))
           (,hook sb-ext:*invoke-debugger-hook*)
           (,node bl:*node*)
           (,persist bl.store:*persist-block-index-hook*)
           (,network bl:*network*))
       (setf bl:*node* nil
             bl.store:*persist-block-index-hook* nil)
       (bl.net:reset-ibd-stop)
       (unwind-protect (progn ,@body)
         (ignore-errors (when bl:*node* (bl:stop-node)))
         (ignore-errors (%release-datadir-lock))
         (bl.net:reset-ibd-stop)
         (setf sb-ext:*invoke-debugger-hook* ,hook
               bl:*node* ,node
               bl.store:*persist-block-index-hook* ,persist
               bl:*network* ,network
               bl::*shutdown-request* nil
               bl::*shutdown-complete* nil
               bl::*stop-node-in-progress* nil
               bl::*node-starting* nil)
         (ignore-errors
          (uiop:delete-directory-tree ,base-var :validate t
                                                :if-does-not-exist :ignore))))))

;;;; The interrupted reindex must not resurrect the pre-reindex tip.
;;;;
;;;; GA11 bbf6e679 (S1). The coins DB's best-block pointer used to survive the
;;;; reindex wipe (only 'C' keys were deleted), so after a crash between the
;;;; wipe and the first replay flush the node started at genesis with an empty
;;;; set -- correct -- and then RECONCILE-COINS-DB-BEST-BLOCK read the standing
;;;; pointer, placed it, moved chainstate.dat FORWARD to the pre-reindex tip and
;;;; logged "Recovered". Every UTXO-set answer was then an empty set at that
;;;; height, and the first competing fork marked the honest chain :invalid.
;;;; Core cannot reach it: -reindex-chainstate destroys the whole coins LevelDB
;;;; (node/chainstate.cpp:93, dbwrapper.cpp:39-41), DB_BEST_BLOCK lives inside
;;;; the coin batch (txdb.cpp:128,159), and is_coinsview_empty skips LoadChainTip
;;;; over an empty view (node/chainstate.cpp:69-70).

(test reindex-crash-before-first-flush-restarts-at-genesis
  "End to end through bl:start-node: mine, run the reindex prefix, die before
the first replay flush, restart with no flags. The node must come back AT
GENESIS with an empty UTXO set -- never at the pre-reindex tip."
  (%with-temporary-node (base "test-reindex-crash")
    ;; A chain on disk, committed by a clean shutdown.
    (%start-test-node :data-directory base :network :regtest :sync nil
                   :rpc-port nil :listen nil :console-log nil)
    (generate-regtest-blocks bl:*node* 8)
    (is (= 8 (bl.store:current-height (bl:node-chain-state bl:*node*))))
    (bl:stop-node)
    ;; Restart, then reproduce do-reindex-chainstate's prefix (rewind to
    ;; genesis with the marker, wipe) and die with nothing flushed -- exactly
    ;; what a killed process leaves behind.
    (bl.net:reset-ibd-stop)
    (%start-test-node :data-directory base :network :regtest :sync nil
                   :rpc-port nil :listen nil :console-log nil)
    (let ((cs (bl:node-chain-state bl:*node*))
          (utxo (bl:node-utxo-set bl:*node*)))
      (is (= 8 (bl.store:current-height cs)))
      (is (= 40000000000 (bl.store:utxo-set-total-amount utxo)))
      (bl.store:update-chain-tip cs (bl.store:chain-state-genesis-hash cs) 0)
      (bl.store:save-state cs :in-transition t)
      (bl.store:coins-view-cache-wipe utxo)
      ;; The emptied database names no block: that is the invariant.
      (is (null (bl.store:coins-view-db-best-block
                 (bl.store:coins-view-cache-base utxo))))
      (bl.store:close-chainstate-coins-view cs)
      (%release-datadir-lock)
      (setf bl:*node* nil))
    ;; Ordinary restart, no flags.
    (bl.net:reset-ibd-stop)
    (%start-test-node :data-directory base :network :regtest :sync nil
                   :rpc-port nil :listen nil :console-log nil)
    (let ((cs (bl:node-chain-state bl:*node*))
          (utxo (bl:node-utxo-set bl:*node*)))
      (is (= 0 (bl.store:current-height cs))
          "the node re-advanced onto the pre-reindex tip over an empty set")
      (is (equalp (bl.store:chain-state-genesis-hash cs)
                  (bl.store:best-block-hash cs)))
      (is (= 0 (bl.store:utxo-set-total-amount utxo)))
      (is (null (bl.store:coins-view-db-best-block
                 (bl.store:coins-view-cache-base utxo)))))
    (bl:stop-node)))


(test startup-refuses-a-corrupted-block-database
  "Core's VerifyLoadedChainstate (node/chainstate.cpp:240-276) turns
CORRUPTED_BLOCK_DB into a hard startup failure. End to end through
bl:start-node: mine a chain, empty the UTXO set underneath it while the
chainstate and the coins pointer keep naming the tip, and the next start must
refuse rather than come up and serve the empty set."
  (%with-temporary-node (base "test-verifydb-start")
    (%start-test-node :data-directory base :network :regtest :sync nil
                   :rpc-port nil :listen nil :console-log nil)
    (generate-regtest-blocks bl:*node* 8)
    (bl:stop-node)
    ;; A clean restart passes verification.
    (bl.net:reset-ibd-stop)
    (%start-test-node :data-directory base :network :regtest :sync nil
                   :rpc-port nil :listen nil :console-log nil)
    (let* ((cs (bl:node-chain-state bl:*node*))
           (utxo (bl:node-utxo-set bl:*node*))
           (tip (bl.store:best-block-hash cs)))
      (is (= 8 (bl.store:current-height cs)))
      ;; Now the bbf6e679 shape: coins gone, everything else standing.
      (bl.store:coins-view-cache-wipe utxo)
      (bl.store:coins-view-cache-sync utxo :sync t :best-block tip)
      (bl.store:close-chainstate-coins-view cs)
      (%release-datadir-lock)
      (setf bl:*node* nil))
    (bl.net:reset-ibd-stop)
    (signals error
      (%start-test-node :data-directory base :network :regtest :sync nil
                       :rpc-port nil :listen nil :console-log nil))))

(test verify-db-passes-over-blocks-that-actually-spend
  "The startup pass must not cry corruption on a healthy node, and a chain of
coinbase-only blocks does not test that: it never reads an undo record. This
one mines past coinbase maturity, spends an early coinbase into a block, and
restarts -- so startup's own VerifyDB runs over a block WITH undo data -- then
asserts levels 3 and 4 directly.

It is also the test that found the level-2 divergence: GET-UNDO-DATA answers
NIL for an EMPTY undo record and for an unreadable one alike, so an
undo-pos-carrying coinbase-only block read as 'bad undo data' and every clean
restart refused to start."
  (%with-temporary-node (base "test-verifydb-spend")
    (%start-test-node :data-directory base :network :regtest :sync nil
                   :rpc-port nil :listen nil :console-log nil)
    ;; 101 blocks so block 1's coinbase is mature, then a block holding a
    ;; transaction that spends it. generateblock, not the mempool: a bare
    ;; OP_TRUE output is consensus-valid but not standard.
    (generate-regtest-blocks bl:*node* 101)
    (let* ((node bl:*node*)
           (cs (bl:node-chain-state node))
           (entry (bl.store:get-block-at-height cs 1))
           (blk (bl.store:get-block (bl:node-block-store node)
                                    (bl.store:block-index-entry-hash entry)))
           (cb (first (bl.ser:bitcoin-block-transactions blk)))
           (out (aref (bl.ser:transaction-outputs cb) 0))
           (spend (bl.ser:make-transaction
                   :version 1
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output
                                    (bl.ser:make-outpoint
                                     :hash (bl.ser:transaction-hash cb) :index 0)
                                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                    :sequence #xFFFFFFFF))
                   :outputs (vector (bl.ser:make-tx-out
                                     :value (- (bl.ser:tx-out-value out) 1000)
                                     :script-pubkey
                                     (make-array 1 :element-type '(unsigned-byte 8)
                                                   :initial-element #x51)))
                   :lock-time 0)))
      (bl.rpc::rpc-generateblock
       node (list "raw(51)"
                  (list (bl.crypto:bytes-to-hex
                         (bl.ser:serialize-transaction spend)))))
      (is (= 102 (bl.store:current-height cs))))
    (bl:stop-node)
    ;; The restart runs VerifyDB at startup; reaching here at all means it did
    ;; not refuse.
    (bl.net:reset-ibd-stop)
    (%start-test-node :data-directory base :network :regtest :sync nil
                   :rpc-port nil :listen nil :console-log nil)
    (let ((cs (bl:node-chain-state bl:*node*))
          (store (bl:node-block-store bl:*node*)))
      (is (= 102 (bl.store:current-height cs)))
      (dolist (level '(2 3 4))
        (is (eq :success (bl.val:verify-db cs store :check-level level))
            "a healthy spending chain failed verification at level ~D" level)))
    (bl:stop-node)))

