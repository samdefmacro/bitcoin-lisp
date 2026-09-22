(in-package #:bitcoin-lisp.tests)

;;;; Chainstate plumbing tests (assumeutxo P3 — shadow refactor).
;;;;
;;;; The chain-state struct owns its coins view and carries the assumeutxo
;;;; identity slots (Core Chainstate, validation.h:527-534,643-674); the
;;;; node holds a chainstates list selected over like Core's
;;;; ChainstateManager (validation.h:1119-1145). Exactly one chainstate
;;;; exists on a running node today, so these tests exercise the selection
;;;; accessors over synthetic lists, the storage-suffix naming scheme
;;;; (the primary's file names must be byte-identical to before), and the
;;;; node-level compatibility accessors the rest of the tree reads through.

(def-suite :chainstate-tests
  :description "Chainstate list + selection accessors + storage suffix"
  :in :bitcoin-lisp-tests)

(in-suite :chainstate-tests)

(defun %cs-hash (byte)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte))

;;;; Selection accessors (Core CurrentChainstate / HistoricalChainstate /
;;;; ValidatedChainstate, validation.h:1119-1145)

(test chainstate-selection-single-validated
  "With one primary chainstate (validated, no target), all three selectors
return it."
  (let* ((primary (bl.store:make-chain-state))
         (chainstates (list primary)))
    (is (eq primary (bl.store:select-current-chainstate chainstates)))
    (is (null (bl.store:select-historical-chainstate chainstates)))
    (is (eq primary (bl.store:select-validated-chainstate chainstates)))))

(test chainstate-defaults-are-primary
  "A fresh chain-state defaults to the primary role: validated, not from a
snapshot, no target, empty storage suffix."
  (let ((cs (bl.store:make-chain-state)))
    (is (eq :validated (bl.store:chain-state-assumeutxo-status cs)))
    (is (null (bl.store:chain-state-from-snapshot-blockhash cs)))
    (is (null (bl.store:chain-state-target-blockhash cs)))
    (is (null (bl.store:chain-state-target-utxohash cs)))
    (is (null (bl.store:chain-state-coins-view cs)))
    (is (string= "" (bl.store:chain-state-storage-suffix cs)))))

(test chainstate-selection-snapshot-pair
  "After a snapshot activation (Core AddChainstate, validation.cpp:6189-6206):
the retargeted original chainstate is historical, the unvalidated snapshot
chainstate is current, and the validated one (for indexes) is the original."
  (let* ((base-hash (%cs-hash #xAA))
         (original (bl.store:make-chain-state
                    :target-blockhash base-hash))          ; retargeted at base
         (snapshot (bl.store:make-chain-state
                    :from-snapshot-blockhash base-hash
                    :assumeutxo-status :unvalidated
                    :storage-suffix "_snapshot"))
         (chainstates (list original snapshot)))
    (is (eq snapshot (bl.store:select-current-chainstate chainstates)))
    (is (eq original (bl.store:select-historical-chainstate chainstates)))
    (is (eq original (bl.store:select-validated-chainstate chainstates)))))

(test chainstate-selection-skips-invalid
  "An INVALID chainstate is never selected for any role, regardless of list
position."
  (let* ((invalid (bl.store:make-chain-state
                   :from-snapshot-blockhash (%cs-hash #xBB)
                   :assumeutxo-status :invalid))
         (valid (bl.store:make-chain-state))
         (chainstates (list invalid valid)))
    (is (eq valid (bl.store:select-current-chainstate chainstates)))
    (is (null (bl.store:select-historical-chainstate chainstates)))
    (is (eq valid (bl.store:select-validated-chainstate chainstates)))))

(test chainstate-selection-historical-completion
  "Setting target-utxohash completes the historical chainstate: it stops being
historical, and once the snapshot chainstate is proven VALIDATED it becomes
both the current and the validated chainstate (Core MaybeValidateSnapshot
success path)."
  (let* ((base-hash (%cs-hash #xCC))
         (original (bl.store:make-chain-state
                    :target-blockhash base-hash
                    :target-utxohash (%cs-hash #xDD)))     ; target reached
         (snapshot (bl.store:make-chain-state
                    :from-snapshot-blockhash base-hash
                    :assumeutxo-status :validated          ; hash matched
                    :storage-suffix "_snapshot"))
         (chainstates (list original snapshot)))
    (is (null (bl.store:select-historical-chainstate chainstates)))
    (is (eq snapshot (bl.store:select-current-chainstate chainstates)))
    (is (eq snapshot (bl.store:select-validated-chainstate chainstates)))))

;;;; Storage suffix scheme (Core Chainstate::StoragePath +
;;;; SNAPSHOT_CHAINSTATE_SUFFIX, node/utxo_snapshot.h:128)

(test chainstate-primary-storage-names-unchanged
  "The primary chainstate (empty suffix) yields today's exact on-disk names —
deployed nodes must restart onto the same files with no migration."
  (let ((cs (bl.store:make-chain-state
             :base-path #p"/data/bitcoin-lisp/testnet4/")))
    (is (equal "chainstate.dat"
               (file-namestring (bl.store:state-file-path cs))))
    (is (equal "/data/bitcoin-lisp/testnet4/chainstate.dat"
               (namestring (bl.store:state-file-path cs))))
    (is (equal "/data/bitcoin-lisp/testnet4/chainstate/"
               (namestring (bl.store:chainstate-leveldb-path cs))))))

(test chainstate-snapshot-storage-names-distinct
  "A suffixed chainstate names distinct files; the header index (shared across
chainstates, like Core's block index) is NOT suffixed."
  (let ((primary (bl.store:make-chain-state
                  :base-path #p"/data/bitcoin-lisp/testnet4/"))
        (snapshot (bl.store:make-chain-state
                   :base-path #p"/data/bitcoin-lisp/testnet4/"
                   :storage-suffix "_snapshot")))
    (is (equal "chainstate_snapshot.dat"
               (file-namestring (bl.store:state-file-path snapshot))))
    (is (equal "/data/bitcoin-lisp/testnet4/chainstate_snapshot/"
               (namestring (bl.store:chainstate-leveldb-path snapshot))))
    (is (not (equal (namestring (bl.store:state-file-path primary))
                    (namestring (bl.store:state-file-path snapshot)))))
    (is (not (equal (namestring (bl.store:chainstate-leveldb-path primary))
                    (namestring (bl.store:chainstate-leveldb-path snapshot)))))
    ;; headerindex.dat is shared: same path whatever the suffix.
    (is (equal (namestring (bl.store::header-index-file-path primary))
               (namestring (bl.store::header-index-file-path snapshot))))))

(test chainstate-assumeutxo-status-never-persisted
  "save-state writes the same 45-byte v3 format as before — the assumeutxo
slots are never persisted (Core re-derives them every startup), so a
chainstate saved as :unvalidated loads back with the :validated default."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames (format nil "test-csstate-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (cs (bl.store:init-chain-state dir :network :regtest)))
    (setf (bl.store:chain-state-assumeutxo-status cs) :unvalidated
          (bl.store:chain-state-target-blockhash cs) (%cs-hash #xEE))
    (is (eq t (bl.store:save-state cs)))
    ;; On-disk format unchanged: 41-byte payload + CRC32 = 45 bytes.
    (with-open-file (in (bl.store:state-file-path cs)
                        :element-type '(unsigned-byte 8))
      (is (= 45 (file-length in))))
    (let ((reload (bl.store:init-chain-state dir :network :regtest)))
      (is (eq t (bl.store:load-state reload)))
      (is (eq :validated (bl.store:chain-state-assumeutxo-status reload)))
      (is (null (bl.store:chain-state-target-blockhash reload))))))

;;;; Node-level accessors (selection + the chain-state / utxo-set
;;;; compatibility accessors over the chainstates list)

(test node-chainstates-compat-accessors
  "The node's chain-state / utxo-set compatibility accessors read and write
the current chainstate in the chainstates list."
  (let ((node (bl:make-node :network :regtest))
        (cs (bl.store:make-chain-state))
        (view (bl.store:make-utxo-set)))
    (is (null (bl:node-chain-state node)))
    (is (null (bl:node-utxo-set node)))
    (setf (bl:node-chain-state node) cs
          (bl:node-utxo-set node) view)
    (is (equal (list cs) (bl:node-chainstates node)))
    (is (eq cs (bl:node-chain-state node)))
    (is (eq cs (bl:node-current-chainstate node)))
    (is (eq cs (bl:node-validated-chainstate node)))
    (is (null (bl:node-historical-chainstate node)))
    ;; The view lives in the chainstate now.
    (is (eq view (bl.store:chain-state-coins-view cs)))
    (is (eq view (bl:node-utxo-set node)))))

(test node-chain-state-replacement-keeps-view
  "Replacing the node's chain-state (the former independent slot) does not
clobber a previously-installed coins view — matching the old two-slot
semantics."
  (let ((node (bl:make-node :network :regtest))
        (cs1 (bl.store:make-chain-state))
        (cs2 (bl.store:make-chain-state))
        (view (bl.store:make-utxo-set)))
    (setf (bl:node-chain-state node) cs1
          (bl:node-utxo-set node) view)
    (setf (bl:node-chain-state node) cs2)
    (is (equal (list cs2) (bl:node-chainstates node)))
    (is (eq view (bl:node-utxo-set node)))))

;;;; The best header (Core ChainstateManager::m_best_header, validation.h:1078)

(defun %cs-entry (byte height work prev &optional (status :header-valid))
  (bl.store:make-block-index-entry
   :hash (%cs-hash byte) :height height :chain-work work :prev-entry prev
   :status status))

(test best-header-follows-the-most-work-valid-entry
  "BEST-HEADER-ENTRY is Core's m_best_header: ADD-BLOCK-INDEX-ENTRY moves it to
an entry with strictly more work (BlockManager::AddToBlockIndex,
node/blockstorage.cpp:249-251), an equal-work entry leaves it where it is, an
entry added as :invalid never takes it, and when the best header itself is
marked invalid the next-best valid entry takes over (InvalidateBlock,
validation.cpp:3638-3668)."
  (let* ((cs (bl.store:make-chain-state))
         (g (%cs-entry 0 0 1 nil :valid))
         (a1 (%cs-entry 1 1 3 g))
         (b1 (%cs-entry 2 1 2 g))
         (a2 (%cs-entry 3 2 5 a1))
         (a2-twin (%cs-entry 4 2 5 a1))
         (bad (%cs-entry 5 2 9 b1 :invalid)))
    (is (null (bl.store:best-header-entry cs)) "an empty index has no best header")
    (bl.store:add-block-index-entry cs g)
    (is (eq g (bl.store:best-header-entry cs)))
    (bl.store:add-block-index-entry cs a1)
    (bl.store:add-block-index-entry cs b1)
    (is (eq a1 (bl.store:best-header-entry cs)) "more work wins, less does not move it")
    (bl.store:add-block-index-entry cs a2)
    (is (eq a2 (bl.store:best-header-entry cs)))
    (bl.store:add-block-index-entry cs a2-twin)
    (is (eq a2 (bl.store:best-header-entry cs)) "equal work keeps the first")
    (bl.store:add-block-index-entry cs bad)
    (is (eq a2 (bl.store:best-header-entry cs))
        "an entry known to be invalid never becomes the best header")
    ;; invalidateblock on a2: the best header has to move off it.
    (setf (bl.store:block-index-entry-status a2) :invalid)
    (is (eq a2-twin (bl.store:best-header-entry cs))
        "the next-best valid entry takes over")
    (setf (bl.store:block-index-entry-status a2-twin) :invalid)
    (is (eq a1 (bl.store:best-header-entry cs)))
    ;; A header arriving after the recalculation is tracked again.
    (let ((a3 (%cs-entry 6 2 4 a1)))
      (bl.store:add-block-index-entry cs a3)
      (is (eq a3 (bl.store:best-header-entry cs))))))

(test best-header-is-shared-by-every-chainstate-on-one-index
  "The block index is one table shared by the chainstates of a node (the
assumeutxo snapshot chainstate is built on the primary's), and Core keeps
m_best_header on the MANAGER, outside any chainstate. A header added through
one chainstate is the best header seen through the other."
  (let* ((primary (bl.store:make-chain-state))
         (snapshot (bl.store:make-chain-state
                    :block-index (bl.store:chain-state-block-index primary)))
         (g (%cs-entry 0 0 1 nil :valid))
         (h1 (%cs-entry 1 1 2 g)))
    (bl.store:add-block-index-entry primary g)
    (is (eq g (bl.store:best-header-entry snapshot)))
    (bl.store:add-block-index-entry snapshot h1)
    (is (eq h1 (bl.store:best-header-entry primary)))))

(test a-pre-0-15-coins-database-is-recognised-as-one
  "Core refuses to load a chainstate that still holds the per-transaction coin
records it stopped writing in 0.15 (DB_COINS, key prefix 'c'), telling the
operator to run -reindex-chainstate (node/chainstate.cpp:103-109,
txdb.cpp:32-39). feature_unsupported_utxo_db.py:48 puts a v0.14.3 chainstate
under the node and expects that refusal; ours opened it, found none of its
'C' coins, and started as if the set were empty.

The positive case is a database holding one 'c' record; the controls are an
empty database and one holding only today's 'C' coins, neither of which may
be refused."
  (with-temp-directory (dir "bl-legacy-coins")
    (let ((legacy (namestring (merge-pathnames "legacy/" dir)))
          (modern (namestring (merge-pathnames "modern/" dir)))
          (empty (namestring (merge-pathnames "empty/" dir))))
      ;; Key shape of Core's pre-0.15 record: 'c' then the 32-byte txid.
      (bl.store:with-leveldb (db legacy)
        (let ((key (make-array 33 :element-type '(unsigned-byte 8) :initial-element 7)))
          (setf (aref key 0) (char-code #\c))
          (bl.store:leveldb-put db key (make-array 3 :element-type '(unsigned-byte 8)
                                                     :initial-element 1))))
      ;; A current-format coin: 'C' + txid + vout, written through the view.
      (bl.store:with-coins-view-db (view modern)
        (bl.store:coins-view-db-put
         view (bl.store:make-utxo-key (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 9)
                                      0)
         (bl.store:make-utxo-entry :value 5000000000
                                   :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                              :initial-element #x51)
                                   :height 1 :coinbase t)))
      (bl.store:with-coins-view-db (view empty)
        (is-false (bl.store:coins-view-db-needs-upgrade-p view)
                  "an empty chainstate is not a legacy one"))
      (bl.store:with-coins-view-db (view modern)
        (is-false (bl.store:coins-view-db-needs-upgrade-p view)
                  "a chainstate of 'C' coins is today's format"))
      (bl.store:with-coins-view-db (view legacy)
        (is-true (bl.store:coins-view-db-needs-upgrade-p view)
                 "a 'c' record is Core's pre-0.15 coins format")))))
