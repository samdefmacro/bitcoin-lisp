(in-package #:bitcoin-lisp.tests)

;;;; txospenderindex tests.
;;;;
;;;; Two levels, deliberately. The unit tests pin the record format and the
;;;; reorg erase; the integration test drives the index through a real regtest
;;;; node, because this codebase's most repeated defect is an index that is
;;;; correct in isolation and maintained by nothing.

(def-suite :txospenderindex-tests
  :description "outpoint -> spending transaction index"
  :in :bitcoin-lisp-tests)

(in-suite :txospenderindex-tests)

(defun %tsi-tmpdir (tag)
  (let ((p (merge-pathnames (format nil "tsi-~A-~D/" tag (get-internal-real-time))
                            (uiop:temporary-directory))))
    (ensure-directories-exist p)
    p))

(defun %tsi-outpoint (seed &optional (index 0))
  (bl.ser:make-outpoint
   :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
   :index index))

(defun %tsi-spending-block (outpoints)
  "A block whose single non-coinbase transaction spends OUTPOINTS."
  (let* ((coinbase
           (bl.ser:make-transaction
            :version 1
            :inputs (vector (bl.ser:make-tx-in
                             :previous-output (bl.ser:make-outpoint
                                               :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                    :initial-element 0)
                                               :index #xFFFFFFFF)
                             :script-sig (coerce #(1 2) '(vector (unsigned-byte 8)))
                             :sequence #xFFFFFFFF))
            :outputs (vector (bl.ser:make-tx-out
                              :value 5000000000
                              :script-pubkey (coerce #(#x51) '(vector (unsigned-byte 8)))))
            :lock-time 0))
         (spender
           (bl.ser:make-transaction
            :version 2
            :inputs (map 'vector
                         (lambda (op)
                           (bl.ser:make-tx-in
                            :previous-output op
                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                            :sequence #xFFFFFFFF))
                         outpoints)
            :outputs (vector (bl.ser:make-tx-out
                              :value 1000
                              :script-pubkey (coerce #(#x51) '(vector (unsigned-byte 8)))))
            :lock-time 0)))
    (values (bl.ser:make-bitcoin-block
             :header (make-test-block-header)
             :transactions (list coinbase spender))
            spender)))

(defun %tsi-real-hash (block)
  "Give BLOCK's header its REAL hash and return it: FindSpender reports the hash
of the header it reads back from the block file."
  (let* ((header (bl.ser:bitcoin-block-header block))
         (hash (bl.crypto:hash256 (bl.ser:serialize-block-header header))))
    (setf (bl.ser:block-header-cached-hash header) hash)
    hash))

(defmacro with-tsi-flat-index ((store idx) &body body)
  "A regtest flat-file block store and a spender index over it."
  (let ((dir (gensym "DIR")))
    `(with-network (:regtest)
       (with-temp-directory (,dir "bl-tsi-flat")
         (let* ((bl.store:*flat-block-files* t)
                (,store (bl.store:init-block-store ,dir))
                (,idx (bl.store:init-txospender-index ,dir :block-store ,store)))
           (unwind-protect (progn ,@body)
             (bl.store:close-txospender-index ,idx)))))))

(defun %tsi-keys (idx)
  "Every entry key of IDX (not the salt or the best block), in key order."
  (let ((keys '()))
    (bl.kv:with-leveldb-iterator (it (bl.store:base-index-db idx))
      (bl.kv:leveldb-iter-seek-to-first it)
      (loop while (bl.kv:leveldb-iter-valid-p it)
            do (let ((k (bl.kv:leveldb-iter-key it)))
                 (when (member (aref k 0) '(#x73 #x53)) (push k keys)))
               (bl.kv:leveldb-iter-next it)))
    (nreverse keys)))

(test txospenderindex-records-and-finds-a-spend
  "The whole point: given an outpoint, say which transaction spent it. Each
entry is Core's key -- 's', the salted outpoint hash, the spending
transaction's CDiskTxPos -- with the empty string as its value
(index/txospenderindex.cpp:95-107), and FindSpender reads the transaction back
through the block file and checks it spends the outpoint (:156-176)."
  (with-tsi-flat-index (store idx)
    (multiple-value-bind (block spender) (%tsi-spending-block
                                          (list (%tsi-outpoint #xA1 0)
                                                (%tsi-outpoint #xA2 7)))
      (let ((hash (%tsi-real-hash block)))
        (bl.store:store-block store block :height 1)
        ;; Two inputs, so two entries -- and the coinbase is skipped.
        (is (= 2 (bl.store:txospenderindex-add-block idx block hash)))
        (let ((keys (%tsi-keys idx))
              (pos (bl.store:block-flat-position store hash))
              (coinbase (first (bl.ser:bitcoin-block-transactions block))))
          (is (= 2 (length keys)))
          ;; 's', eight hash bytes, then VARINT nFile 0, nPos, and nTxOffset:
          ;; the CompactSize count (1) plus the coinbase's bytes.
          (is (every (lambda (k)
                       (equalp (subseq k 9)
                               (let ((bb (bl.ser:make-byte-buf)))
                                 (bl.ser:bb-write-core-varint bb 0)
                                 (bl.ser:bb-write-core-varint bb (bl.kv:flat-file-pos-pos pos))
                                 (bl.ser:bb-write-core-varint
                                  bb (1+ (length (bl.ser:transaction-wire-bytes coinbase))))
                                 (bl.ser:bb-finish bb))))
                     keys))
          (is (equalp #(0) (bl.kv:leveldb-get (bl.store:base-index-db idx) (first keys)))))
        (multiple-value-bind (tx block-hash)
            (bl.store:txospenderindex-find-spender
             idx (bl.ser:outpoint-hash (%tsi-outpoint #xA2 7)) 7)
          (is (equalp (bl.ser:transaction-hash spender) (and tx (bl.ser:transaction-hash tx))))
          (is (equalp hash block-hash)))
        ;; The vout is part of the key, so a different index of the same txid
        ;; is a different outpoint; and an outpoint nothing spent is absent.
        (is (null (bl.store:txospenderindex-find-spender
                   idx (bl.ser:outpoint-hash (%tsi-outpoint #xA1 0)) 1)))
        (is (null (bl.store:txospenderindex-find-spender
                   idx (bl.ser:outpoint-hash (%tsi-outpoint #xFF 0)) 0)))))))

(test txospenderindex-reorg-erases-exactly-what-it-wrote
  "⚠️ A spender key carries no height. After a reorg the disconnected block is
still on disk and still spends the outpoint, so an entry left behind resolves
to a spending transaction from an ABANDONED chain -- a wrong answer, not a
stale one. Core erases through CustomRemove and builds the same keys for both
sides from the block alone (index/txospenderindex.cpp:110-139)."
  (with-tsi-flat-index (store idx)
    (let* ((block (%tsi-spending-block (list (%tsi-outpoint #xB1 0))))
           (hash (%tsi-real-hash block))
           (txid (bl.ser:outpoint-hash (%tsi-outpoint #xB1 0))))
      (bl.store:store-block store block :height 1)
      (bl.store:txospenderindex-add-block idx block hash)
      (is-true (bl.store:txospenderindex-find-spender idx txid 0))
      (is (= 1 (bl.store:txospenderindex-remove-block idx block hash)))
      (is (null (bl.store:txospenderindex-find-spender idx txid 0))
          "a disconnected block left its spender entries behind")
      (is (null (%tsi-keys idx)))
      ;; Idempotent.
      (bl.store:txospenderindex-remove-block idx block hash)
      (is (null (bl.store:txospenderindex-find-spender idx txid 0))))))

(test txospenderindex-salt-survives-a-reopen-under-cores-key
  "⚠️ The salt must be STABLE for the life of the database: every key is
hash(salt, outpoint). Core keeps it under the serialized std::string
\"siphash_key\" -- its CompactSize length first -- as two u64 LE
(index/txospenderindex.cpp:66-70); a salt this tree kept under the bare
characters moves there on open."
  (with-network (:regtest)
    (with-temp-directory (dir "bl-tsi-salt")
      (let* ((bl.store:*flat-block-files* t)
             (store (bl.store:init-block-store dir))
             (block (%tsi-spending-block (list (%tsi-outpoint #xC1 0))))
             (hash (%tsi-real-hash block))
             (salt nil))
        (bl.store:store-block store block :height 1)
        (let ((idx (bl.store:init-txospender-index dir :block-store store)))
          (let ((db (bl.store:base-index-db idx))
                (core-key (concatenate '(vector (unsigned-byte 8)) #(11)
                                       (map 'vector #'char-code "siphash_key"))))
            (setf salt (bl.kv:leveldb-get db core-key))
            (is (= 16 (length salt)))
            ;; Put it back where this tree used to keep it.
            (bl.kv:leveldb-put db (map '(vector (unsigned-byte 8)) #'char-code "siphash_key") salt)
            (bl.kv:leveldb-delete db core-key))
          (bl.store:txospenderindex-add-block idx block hash)
          (bl.store:close-txospender-index idx))
        (let ((idx (bl.store:init-txospender-index dir :block-store store)))
          (unwind-protect
               (progn
                 (is (equalp salt (bl.kv:leveldb-get
                                   (bl.store:base-index-db idx)
                                   (concatenate '(vector (unsigned-byte 8)) #(11)
                                                (map 'vector #'char-code "siphash_key")))))
                 (is (null (bl.kv:leveldb-get
                            (bl.store:base-index-db idx)
                            (map '(vector (unsigned-byte 8)) #'char-code "siphash_key"))))
                 ;; And the entry written before the reopen is still found.
                 (is-true (bl.store:txospenderindex-find-spender
                           idx (bl.ser:outpoint-hash (%tsi-outpoint #xC1 0)) 0)))
            (bl.store:close-txospender-index idx)))))))

(test txospenderindex-migrates-the-old-entries-in-place
  "An index written before 2026-09-29 holds 's' | hash | block hash | offset.
MIGRATE-TXOSPENDERINDEX keeps the first nine bytes and replaces the rest with
the CDiskTxPos the block gives, one batch per block, and the answer is the same
before and after."
  (with-tsi-flat-index (store idx)
    (let* ((block (%tsi-spending-block (list (%tsi-outpoint #xD1 0) (%tsi-outpoint #xD2 3))))
           (hash (%tsi-real-hash block)))
      (bl.store:store-block store block :height 1)
      (bl.store:txospenderindex-add-block idx block hash)
      (let* ((db (bl.store:base-index-db idx))
             (core-keys (%tsi-keys idx))
             (coinbase-size (length (bl.ser:transaction-wire-bytes
                                     (first (bl.ser:bitcoin-block-transactions block))))))
        ;; Rewrite them in the old layout.
        (dolist (k core-keys)
          (bl.kv:leveldb-delete db k)
          (bl.kv:leveldb-put db (concatenate '(vector (unsigned-byte 8)) (subseq k 0 9) hash
                                             (vector (ldb (byte 8 0) coinbase-size)
                                                     (ldb (byte 8 8) coinbase-size) 0 0))
                             (make-array 0 :element-type '(unsigned-byte 8))))
        (is-true (bl.store:txospenderindex-needs-migration-p idx))
        ;; Dual read before the migration.
        (is (equalp hash (nth-value 1 (bl.store:txospenderindex-find-spender
                                       idx (bl.ser:outpoint-hash (%tsi-outpoint #xD2 3)) 3))))
        (is (= 2 (bl.store:migrate-txospenderindex idx)))
        (is (null (bl.store:txospenderindex-needs-migration-p idx)))
        (is (equalp core-keys (%tsi-keys idx)))
        (is (equalp hash (nth-value 1 (bl.store:txospenderindex-find-spender
                                       idx (bl.ser:outpoint-hash (%tsi-outpoint #xD1 0)) 0))))))))

(test txospenderindex-best-block-round-trips-with-its-height
  "getindexinfo reports best_block_height, so the height is stored beside the
hash. An index that has recorded nothing reports -1, which is the shape
getindexinfo's `synced' comparison expects."
  (let ((dir (%tsi-tmpdir "best")))
    (unwind-protect
         (let ((idx (bl.store:init-txospender-index dir)))
           (unwind-protect
                (let ((hash (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element #xD1)))
                  (is (= -1 (bl.store:txospenderindex-height idx)))
                  (bl.store:txospenderindex-set-best-block idx hash 12345)
                  (multiple-value-bind (h height)
                      (bl.store:txospenderindex-best-block idx)
                    (is (equalp hash h))
                    (is (= 12345 height)))
                  (is (= 12345 (bl.store:txospenderindex-height idx))))
             (bl.store:close-txospender-index idx)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

(test txospenderindex-disabled-is-inert
  "A disabled index accepts every call and does nothing, so the connect path
does not have to test for it — the same contract the txindex has."
  (let ((idx (bl.store:init-txospender-index
              (uiop:temporary-directory) :enabled nil)))
    (multiple-value-bind (block) (%tsi-spending-block (list (%tsi-outpoint #xE1 0)))
      (let ((hash (bl.ser:block-header-hash
                   (bl.ser:bitcoin-block-header block))))
        (is (= 0 (bl.store:txospenderindex-add-block idx block hash)))
        (is (= 0 (bl.store:txospenderindex-remove-block idx block hash)))
        (is (null (bl.store:txospenderindex-find-spender
                   idx (bl.ser:outpoint-hash (%tsi-outpoint #xE1 0)) 0)))
        (is (null (bl.store:txospenderindex-best-block idx)))
        (is (= -1 (bl.store:txospenderindex-height idx)))))))

;;;; Startup rewind (Core BaseIndex::Sync -> Rewind, index/base.cpp:239/290)

(defun %tsi-hash (byte)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element byte))

(defun %tsi-branch-block (prev-hash block-hash outpoint)
  "A block extending PREV-HASH, identified by BLOCK-HASH, whose one
non-coinbase transaction spends OUTPOINT. The coinbase's script-sig carries
four bytes of BLOCK-HASH so sibling blocks serialize -- and their coinbase
txids hash -- differently."
  (let ((coinbase
          (bl.ser:make-transaction
           :version 1
           :inputs (vector (bl.ser:make-tx-in
                            :previous-output (bl.ser:make-outpoint
                                              :hash (%tsi-hash 0)
                                              :index #xFFFFFFFF)
                            :script-sig (subseq block-hash 0 4)
                            :sequence #xFFFFFFFF))
           :outputs (vector (bl.ser:make-tx-out
                             :value 5000000000
                             :script-pubkey (coerce #(#x51) '(vector (unsigned-byte 8)))))
           :lock-time 0))
        (spender
          (bl.ser:make-transaction
           :version 2
           :inputs (vector (bl.ser:make-tx-in
                            :previous-output outpoint
                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                            :sequence #xFFFFFFFF))
           :outputs (vector (bl.ser:make-tx-out
                             :value 1000
                             :script-pubkey (coerce #(#x51) '(vector (unsigned-byte 8)))))
           :lock-time 0)))
    (bl.ser:make-bitcoin-block
     :header (bl.ser:make-block-header
              :version 1 :prev-block prev-hash
              :merkle-root (%tsi-hash 0)
              :timestamp 1231006505 :bits #x1d00ffff :nonce 0
              :cached-hash block-hash)
     :transactions (list coinbase spender))))

(defun %tsi-extend (cs store prev-entry hash outpoint)
  "Store one block extending PREV-ENTRY, identified by HASH and spending
OUTPOINT, and enter it in CS's block index. Returns (values entry block)."
  (let* ((height (1+ (bl.store:block-index-entry-height prev-entry)))
         (block (%tsi-branch-block (bl.store:block-index-entry-hash prev-entry)
                                   hash outpoint))
         (entry (bl.store:make-block-index-entry
                 :hash hash :height height :chain-work height :status :valid
                 :header (bl.ser:bitcoin-block-header block)
                 :prev-entry prev-entry)))
    ;; A per-block file: these fixtures name blocks by placeholder hashes,
    ;; which only the legacy ('S') entry carries -- a flat block would be
    ;; answered under its real header hash.
    (let ((bl.store:*flat-block-files* nil))
      (bl.store:store-block store block :height height))
    (bl.store:add-block-index-entry cs entry)
    (values entry block)))

(defun %tsi-spender-block-hash (idx outpoint)
  "The block hash the index answers as spending OUTPOINT, or NIL."
  (nth-value 1 (bl.store:txospenderindex-find-spender
                idx (bl.ser:outpoint-hash outpoint) (bl.ser:outpoint-index outpoint))))

(defun %tsi-stale-marker-fixture (cs store idx)
  "Branch A (genesis, #x1A, #x2A) indexed by IDX while it was the active chain,
then branch B (#x1B, #x2B) made active at the same heights while the index was
stopped: IDX's marker names #x2A, a block the active chain no longer holds.
Returns (values a1-op a2-op b1-op b2-op), the outpoint each block spends."
  (let* ((genesis-hash (bl.store:best-block-hash cs))
         (genesis (bl.store:make-block-index-entry
                   :hash genesis-hash :height 0 :chain-work 0
                   :status :valid
                   :header (bl.ser:make-block-header
                            :version 1 :prev-block (%tsi-hash 0)
                            :merkle-root (%tsi-hash 0)
                            :timestamp 1231006505 :bits #x1d00ffff
                            :nonce 0 :cached-hash genesis-hash)))
         (a1-op (%tsi-outpoint #xA1 0))
         (a2-op (%tsi-outpoint #xA2 0))
         (b1-op (%tsi-outpoint #xB1 0))
         (b2-op (%tsi-outpoint #xB2 0)))
    (bl.store:add-block-index-entry cs genesis)
    ;; Branch A, indexed while it was the active chain.
    (multiple-value-bind (a1 a1-block)
        (%tsi-extend cs store genesis (%tsi-hash #x1A) a1-op)
      (multiple-value-bind (a2 a2-block)
          (%tsi-extend cs store a1 (%tsi-hash #x2A) a2-op)
        (bl.store:update-chain-tip
         cs (bl.store:block-index-entry-hash a2) 2)
        (bl.store:txospenderindex-add-block
         idx a1-block (bl.store:block-index-entry-hash a1))
        (bl.store:txospenderindex-add-block
         idx a2-block (bl.store:block-index-entry-hash a2))
        (bl.store:txospenderindex-set-best-block
         idx (bl.store:block-index-entry-hash a2) 2)))
    ;; Branch B wins while the index is stopped: same heights, so
    ;; the marker is not above the tip and the height guard alone
    ;; can see nothing wrong with it.
    (multiple-value-bind (b1) (%tsi-extend cs store genesis (%tsi-hash #x1B) b1-op)
      (multiple-value-bind (b2) (%tsi-extend cs store b1 (%tsi-hash #x2B) b2-op)
        (bl.store:update-chain-tip
         cs (bl.store:block-index-entry-hash b2) 2)))
    (values a1-op a2-op b1-op b2-op)))

(test txospenderindex-rewinds-a-marker-left-on-an-abandoned-branch
  "A branch switch that happens while the process is DOWN leaves the marker on
a block the active chain no longer holds, and the online :block-disconnected
hook cannot have fired for it. Core repairs that at startup: BaseIndex::Sync
notices the stored best block is not the parent of the next block to index and
calls Rewind (index/base.cpp:239), which walks pprev calling CustomRemove per
block (:290-320) -- and TxoSpenderIndex opts into disconnect_data
(index/txospenderindex.cpp:73-78) precisely so this index gets that treatment.

Both directions are asserted, and the second is the one that cost a wrong
answer. Before this, the marker naming an abandoned block at a height at or
above the tip passed neither of CATCH-UP-INDEX's tests -- prepare-sync was the
base no-op and the (< index-height tip) guard was satisfied by an off-chain
marker -- so nothing was rewound AND nothing was backfilled, and the ACTIVE
chain's spends in that height range were never recorded at all.
gettxspendingprevout then reported an outpoint that a confirmed transaction
spends as unspent, which is Core's shape for `nothing spent it' and therefore
indistinguishable from a real answer."
  (let ((dir (%tsi-tmpdir "rewind")))
    (unwind-protect
         (let* ((cs (bl.store:init-chain-state dir))
               (store (bl.store:init-block-store dir))
               (idx (bl.store:init-txospender-index dir :block-store store))
               (node (bl:make-node)))
           (unwind-protect
                (multiple-value-bind (a1-op a2-op b1-op b2-op)
                    (%tsi-stale-marker-fixture cs store idx)
                  (is (equalp (%tsi-hash #x1A) (%tsi-spender-block-hash idx a1-op))
                      "the fixture did not record branch A")
                  (is (null (%tsi-spender-block-hash idx b1-op))
                      "the fixture recorded branch B before the restart")
                  ;; The restart.
                  (setf (bl:node-chainstates node) (list cs)
                        (bl:node-block-store node) store)
                  (bl:catch-up-index node idx)
                  ;; The abandoned branch's rows are gone (Core CustomRemove)...
                  (is (null (%tsi-spender-block-hash idx a1-op))
                      "branch A's spend survived the rewind")
                  (is (null (%tsi-spender-block-hash idx a2-op))
                      "branch A's spend survived the rewind")
                  ;; ...and the ACTIVE branch is indexed, which is the direction
                  ;; that answered a false `unspent' before.
                  (is (equalp (%tsi-hash #x1B) (%tsi-spender-block-hash idx b1-op))
                      "an outpoint spent on the ACTIVE chain is still reported unspent")
                  (is (equalp (%tsi-hash #x2B) (%tsi-spender-block-hash idx b2-op))
                      "an outpoint spent on the ACTIVE chain is still reported unspent")
                  ;; And the marker names the new tip, so a second start is a
                  ;; no-op rather than a second rewind.
                  (multiple-value-bind (hash height)
                      (bl.store:txospenderindex-best-block idx)
                    (is (equalp (%tsi-hash #x2B) hash))
                    (is (= 2 height)))
                  (is (= 2 (bl.store:index-height idx cs))))
             (bl.store:close-txospender-index idx)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

(test txospenderindex-rewind-that-cannot-read-a-block-aborts-the-node
  "Core's Rewind reads every abandoned block's body for this index
 (disconnect_data, index/txospenderindex.cpp:73-78) and returns false when one
cannot be read (index/base.cpp:299-305); Sync then FatalErrorf's `Failed to
rewind txospenderindex to a previous chain tip' (:239-241). Ours cleared the
marker and rebuilt the index from genesis. The control is the test above,
where every body is readable and the same rewind succeeds."
  (let ((dir (%tsi-tmpdir "rewindfail")))
    (unwind-protect
         (let* ((cs (bl.store:init-chain-state dir))
                (store (bl.store:init-block-store dir))
                (idx (bl.store:init-txospender-index dir :block-store store))
                (node (bl:make-node))
                (stderr (make-string-output-stream))
                (requested '()))
           (unwind-protect
                (multiple-value-bind (a1-op a2-op b1-op)
                    (%tsi-stale-marker-fixture cs store idx)
                  (declare (ignore a2-op))
                  (is-true (bl.store:forget-block-body store (%tsi-hash #x2A))
                           "the fixture's abandoned tip must have had a body to lose")
                  (setf (bl:node-chainstates node) (list cs)
                        (bl:node-block-store node) store)
                  (bl.log:reset-warnings)
                  (let ((bl.log:*fatal-error-shutdown-function*
                          (lambda (message) (push message requested))))
                    (let ((*error-output* stderr))
                      (bl:catch-up-index node idx)))
                  (is (equalp (%tsi-hash #x2A) (bl.store:txospenderindex-best-block idx))
                      "the marker was cleared instead of left for the operator")
                  ;; A2's own row cannot be read back without its body (the
                  ;; lookup re-reads the transaction, as Core's FindTx does);
                  ;; A1's, which the rewind never reached, is still there.
                  (is (equalp (%tsi-hash #x1A) (%tsi-spender-block-hash idx a1-op))
                      "the abandoned branch's rows were rewritten")
                  (is (null (%tsi-spender-block-hash idx b1-op))
                      "the index was rebuilt on top of a rewind that failed")
                  (is (equal (format nil "Error: A fatal internal error occurred, see debug.log for details: Failed to rewind txospenderindex to a previous chain tip~%")
                             (get-output-stream-string stderr)))
                  (is (equal '("Failed to rewind txospenderindex to a previous chain tip")
                             requested)))
             (bl.log:reset-warnings)
             (bl.store:close-txospender-index idx)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

(test txospenderindex-rows-outlive-a-disconnect-and-go-at-the-next-connect
  "Core's indexes are never told about a disconnected block. BaseIndex has no
BlockDisconnected handler at all: the rewind is driven from the NEXT
BlockConnected, which notices the stored best block is not the new block's
parent and walks pprev calling CustomRemove (index/base.cpp:363-367, :290-320).
So between an invalidateblock and the next block, the spender index still
answers with the transaction that spent the outpoint on the abandoned branch
-- and rpc_gettxspendingprevout.py:198-200 asserts exactly that, naming the
now-stale block: `tx2 is not in the mempool anymore, but still in txospender
index which has not been rewound yet'.

Our :block-disconnected hook erased the block's rows the moment it was
disconnected, so the outpoint came back UNSPENT in that window -- Core's shape
for `nothing ever spent it', and therefore indistinguishable from a real
answer -- and a reorg that ended up re-connecting the same block paid to
rebuild what it had just thrown away."
  (let ((dir (%tsi-tmpdir "disconnect")))
    (unwind-protect
         (let* ((cs (bl.store:init-chain-state dir))
               (store (bl.store:init-block-store dir))
               (idx (bl.store:init-txospender-index dir :block-store store))
               (node (bl:make-node)))
           (unwind-protect
                (let* ((genesis-hash (bl.store:best-block-hash cs))
                       (genesis (bl.store:make-block-index-entry
                                 :hash genesis-hash :height 0 :chain-work 0
                                 :status :valid
                                 :header (bl.ser:make-block-header
                                          :version 1 :prev-block (%tsi-hash 0)
                                          :merkle-root (%tsi-hash 0)
                                          :timestamp 1231006505 :bits #x1d00ffff
                                          :nonce 0 :cached-hash genesis-hash)))
                       (a-op (%tsi-outpoint #xD1 0))
                       (b-op (%tsi-outpoint #xD2 0))
                       (bl:*node* node))
                  (bl.store:add-block-index-entry cs genesis)
                  (setf (bl:node-chainstates node) (list cs)
                        (bl:node-block-store node) store
                        (bl:node-txospenderindex node) idx)
                  (multiple-value-bind (a a-block)
                      (%tsi-extend cs store genesis (%tsi-hash #x1D) a-op)
                    (let ((a-hash (bl.store:block-index-entry-hash a)))
                      (bl.store:update-chain-tip cs a-hash 1)
                      (bl:index-block-connected cs a-block a-hash 1 nil)
                      (is (equalp a-hash (%tsi-spender-block-hash idx a-op))
                          "the fixture did not index the connected block")
                      ;; The disconnect. Core tells no index about it.
                      (bl.store:update-chain-tip cs genesis-hash 0)
                      (bl:index-block-disconnected cs a-block a-hash 1)
                      (is (equalp a-hash (%tsi-spender-block-hash idx a-op))
                          "the disconnected block's row was erased before any ~
block replaced it")
                      ;; The next block on the new branch: NOW the index
                      ;; rewinds, because its best marker is not this block's
                      ;; parent, and then indexes the arrival.
                      (multiple-value-bind (b b-block)
                          (%tsi-extend cs store genesis (%tsi-hash #x2D) b-op)
                        (let ((b-hash (bl.store:block-index-entry-hash b)))
                          (bl.store:update-chain-tip cs b-hash 1)
                          (bl:index-block-connected cs b-block b-hash 1 nil)
                          (is (null (%tsi-spender-block-hash idx a-op))
                              "the abandoned branch's row survived the next connect")
                          (is (equalp b-hash (%tsi-spender-block-hash idx b-op)))
                          (multiple-value-bind (hash height)
                              (bl.store:txospenderindex-best-block idx)
                            (is (equalp b-hash hash))
                            (is (= 1 height))))))))
             (bl.store:close-txospender-index idx)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

(test gettxspendingprevout-names-the-block-a-confirmed-spend-is-in
  "Core's index answer carries a `blockhash' the mempool answer cannot: the
mempool branch pushes spendingtxid (and spendingtx), the txospenderindex
branch pushes spendingtxid, BLOCKHASH and spendingtx
(rpc/mempool.cpp:1015-1024). Without it a caller cannot tell a confirmed
spend from an unconfirmed one, and rpc_gettxspendingprevout.py:132 compares
the whole object.

Driven through the RPC handler over a real index so the field comes from the
index lookup rather than from a hand-built result."
  (let ((dir (%tsi-tmpdir "rpc-blockhash")))
    (unwind-protect
         (let* ((cs (bl.store:init-chain-state dir))
               (store (bl.store:init-block-store dir))
               (idx (bl.store:init-txospender-index dir :block-store store))
               (node (bl:make-node)))
           (unwind-protect
                (let* ((genesis-hash (bl.store:best-block-hash cs))
                       (genesis (bl.store:make-block-index-entry
                                 :hash genesis-hash :height 0 :chain-work 0
                                 :status :valid
                                 :header (bl.ser:make-block-header
                                          :version 1 :prev-block (%tsi-hash 0)
                                          :merkle-root (%tsi-hash 0)
                                          :timestamp 1231006505 :bits #x1d00ffff
                                          :nonce 0 :cached-hash genesis-hash)))
                       (spent (%tsi-outpoint #xC1 0))
                       (unspent (%tsi-outpoint #xC2 0))
                       (block-hash (%tsi-hash #x1C)))
                  (bl.store:add-block-index-entry cs genesis)
                  (multiple-value-bind (entry block)
                      (%tsi-extend cs store genesis block-hash spent)
                    (bl.store:update-chain-tip
                     cs (bl.store:block-index-entry-hash entry) 1)
                    (bl.store:txospenderindex-add-block idx block block-hash)
                    (bl.store:txospenderindex-set-best-block idx block-hash 1))
                  (setf (bl:node-chainstates node) (list cs)
                        (bl:node-block-store node) store
                        (bl:node-txospenderindex node) idx)
                  (flet ((query (op)
                           (let ((h (make-hash-table :test 'equal)))
                             (setf (gethash "txid" h)
                                   (bl.rpc:hash-to-hex (bl.ser:outpoint-hash op))
                                   (gethash "vout" h) (bl.ser:outpoint-index op))
                             (first (bl.rpc:dispatch-rpc-method
                                     node "gettxspendingprevout"
                                     (wire-params (list (vector h))))))))
                    (let ((r (query spent)))
                      (is-true (assoc "spendingtxid" r :test #'string=)
                               "the fixture's confirmed spend was not found")
                      (is (string= (bl.rpc:hash-to-hex block-hash)
                                   (cdr (assoc "blockhash" r :test #'string=)))))
                    ;; Control: an outpoint nothing spent gets neither key, so
                    ;; blockhash really comes from the index hit.
                    (let ((r (query unspent)))
                      (is-false (assoc "spendingtxid" r :test #'string=))
                      (is-false (assoc "blockhash" r :test #'string=)))
                    ;; And the index is answered whether or not its block is
                    ;; still on the ACTIVE chain. Core's FindSpender asks
                    ;; nothing about the chain (index/txospenderindex.cpp:
                    ;; 160-176), so a row a reorg has left behind is still
                    ;; reported until the index is rewound --
                    ;; rpc_gettxspendingprevout.py:200 invalidates the block
                    ;; and still expects the spend. An active-chain gate here
                    ;; answered "unspent" instead, which is Core's shape for
                    ;; "nothing spent it".
                    (bl.store:update-chain-tip cs genesis-hash 0)
                    (let ((r (query spent)))
                      (is-true (assoc "spendingtxid" r :test #'string=)
                               "the spend went missing once its block left the active chain")
                      (is (string= (bl.rpc:hash-to-hex block-hash)
                                   (cdr (assoc "blockhash" r :test #'string=)))))))
             (bl.store:close-txospender-index idx)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))
