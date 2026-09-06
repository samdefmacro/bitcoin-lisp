(in-package #:bitcoin-lisp.tests)

;;;; VerifyDB (GA11 4452772a).
;;;;
;;;; Core runs CVerifyDB::VerifyDB over every non-empty chainstate on every
;;;; boot (node/chainstate.cpp:240-276) and turns CORRUPTED_BLOCK_DB into
;;;; "Corrupted block database detected", a hard startup failure. Ours ran
;;;; nowhere, and the verifychain RPC that exists to answer the same question
;;;; stopped at Core's level 1 -- so a chainstate that disagreed with its
;;;; blocks was never detected and the RPC answered true.
;;;;
;;;; The state under test is GA11 bbf6e679's: the tip, the block index and
;;;; every blk/rev record stand while the UTXO set is empty. That is what
;;;; level 3 exists to catch, and it is this suite's positive control -- with
;;;; the pre-fix RPC the same call returned T on it.

(def-suite :verifydb-tests
  :description "Core VerifyDB levels 0-4 and the verifychain RPC over them"
  :in :bitcoin-lisp-tests)

(in-suite :verifydb-tests)

(defun %verifychain (node &optional params)
  "The shipped verifychain handler. One reach, so the suite's many calls do
not each name an internal."
  (bl.rpc::rpc-verifychain node params))

(defun %verifydb-emptied-set-node (tag blocks)
  "(values node chain-state) — a regtest node with BLOCKS mined and its whole
UTXO set erased underneath them, with the coins DB's best-block pointer left
naming the tip. Exactly the on-disk state bbf6e679 produced: blocks and index
intact, coins gone, the two databases disagreeing."
  (let ((node (coins-db-node-fixture tag)))
    (let ((bl:*node* node))
      (generate-regtest-blocks node blocks))
    (let* ((cs (bl:node-chain-state node))
           (utxo (bl:node-utxo-set node))
           (tip (bl.store:best-block-hash cs)))
      (bl.store:coins-view-cache-flush utxo :sync t)
      (bl.store:coins-view-cache-wipe utxo)
      (bl.store:coins-view-cache-sync utxo :sync t :best-block tip)
      (values node cs))))

(test verify-db-level-3-detects-a-utxo-set-that-lost-its-coins
  "The load-bearing level. On a healthy chain every level answers :SUCCESS;
once the coins are gone under an unchanged tip, level 3 disconnects the tip
block against an empty view, every output it removes is already missing, and
the answer is Core's CORRUPTED_BLOCK_DB."
  (with-network (:regtest)
    (let* ((tag (format nil "vdbok~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (generate-regtest-blocks node 8))
      (let ((cs (bl:node-chain-state node))
            (store (bl:node-block-store node)))
        (bl.store:coins-view-cache-flush (bl:node-utxo-set node) :sync t)
        (dolist (level '(0 1 2 3 4))
          (is (eq :success (bl.val:verify-db cs store :check-level level))
              "healthy chain failed at level ~D" level))))
    (let* ((tag (format nil "vdbbad~D" (get-internal-real-time))))
      (multiple-value-bind (node cs) (%verifydb-emptied-set-node tag 8)
        (let ((store (bl:node-block-store node)))
          ;; Levels 0-2 read blocks and undo records; those are intact, so they
          ;; still pass -- which is precisely why stopping at level 1 detected
          ;; nothing.
          (is (eq :success (bl.val:verify-db cs store :check-level 0)))
          (is (eq :success (bl.val:verify-db cs store :check-level 2)))
          (is (eq :corrupted-block-db (bl.val:verify-db cs store :check-level 3)))
          (is (eq :corrupted-block-db (bl.val:verify-db cs store :check-level 4))))))))

(test verify-db-clamps-checklevel-and-checkdepth
  "checklevel is clamped to 0-4 and nblocks <= 0 means the whole chain
(validation.cpp:4656-4659). Pinned from both ends on the corrupted state: a
level below the range behaves as 0 and passes, one above it behaves as 4 and
fails."
  (with-network (:regtest)
    (multiple-value-bind (node cs)
        (%verifydb-emptied-set-node (format nil "vdbclamp~D" (get-internal-real-time)) 6)
      (let ((store (bl:node-block-store node)))
        (is (eq :success (bl.val:verify-db cs store :check-level -5)))
        (is (eq :corrupted-block-db (bl.val:verify-db cs store :check-level 99)))
        ;; 0 and a depth past the chain both mean "all of it", and the default
        ;; depth of 6 is not what makes this fail.
        (is (eq :corrupted-block-db
                (bl.val:verify-db cs store :check-level 3 :check-depth 0)))
        (is (eq :corrupted-block-db
                (bl.val:verify-db cs store :check-level 3 :check-depth 9999)))))))

(test rpc-verifychain-answers-false-on-a-corrupted-chainstate
  "The shipped RPC over the same state: true at its Core defaults on a healthy
chain, JSON false once the coins are gone. The pre-fix handler answered T for
both, at every level, because it never opened a coins view."
  (with-network (:regtest)
    (let* ((tag (format nil "vdbrpc~D" (get-internal-real-time)))
           (node (coins-db-node-fixture tag)))
      (let ((bl:*node* node))
        (generate-regtest-blocks node 8)
        (bl.store:coins-view-cache-flush (bl:node-utxo-set node) :sync t)
        (is (eq t (%verifychain node nil)))
        (let* ((cs (bl:node-chain-state node))
               (utxo (bl:node-utxo-set node))
               (tip (bl.store:best-block-hash cs)))
          (bl.store:coins-view-cache-wipe utxo)
          (bl.store:coins-view-cache-sync utxo :sync t :best-block tip))
        (is (eq 'yason:false (%verifychain node nil)))
        (is (eq 'yason:false (%verifychain node (list 4 6))))
        (is (eq 'yason:false (%verifychain node (list 99 6))))
        ;; Not vacuous: level 0 still reads every body back and says so.
        (is (eq t (%verifychain node (list 0 6))))))))

(test rpc-verifychain-answers-false-when-a-body-is-missing
  "Level 0's own control: with the block bodies gone from the store the answer
is JSON false even at level 0, so a passing run at a higher level is never
just level 0 answering for everything."
  (with-network (:regtest)
    (multiple-value-bind (node cspath base)
        (coins-db-node-fixture (format nil "vdbbody~D" (get-internal-real-time)))
      (declare (ignore cspath))
      (let ((bl:*node* node))
        (generate-regtest-blocks node 4)
        (bl.store:coins-view-cache-flush (bl:node-utxo-set node) :sync t)
        (is (eq t (%verifychain node (list 0 4))))
        ;; Delete the flat block files under the store, leaving the index and
        ;; the chainstate alone -- a blk file lost on its own.
        (dolist (f (directory (merge-pathnames "blocks/blk*.dat" base)))
          (delete-file f))
        (setf (bl:node-block-store node) (bl.store:init-block-store base))
        (is (eq 'yason:false (%verifychain node (list 0 4))))))))

(test checkblocks-and-checklevel-are-real-options
  "-checkblocks and -checklevel left the accept-and-drop list for the option
table with Core's defaults (init.cpp:1388-1389, GetIntArg 6 and 3), so they
reach start-node instead of being parsed and thrown away."
  (is (eq :start-node (bl.cfg:config-option-kind
                       (bl.cfg::find-config-option "checkblocks"))))
  (is (eq :start-node (bl.cfg:config-option-kind
                       (bl.cfg::find-config-option "checklevel"))))
  (is (= 6 bl.val:+default-checkblocks+))
  (is (= 3 bl.val:+default-checklevel+))
  (let ((plist (start-node-plist '("-regtest" "-checkblocks=12" "-checklevel=4"))))
    (is (= 12 (getf plist :check-blocks)))
    (is (= 4 (getf plist :check-level))))
  ;; Absent, they carry no value at all, so start-node can tell "not given"
  ;; from "given" (Core's require_full_verification, init.cpp:1390).
  (let ((plist (start-node-plist '("-regtest"))))
    (is (null (getf plist :check-blocks)))
    (is (null (getf plist :check-level)))))
