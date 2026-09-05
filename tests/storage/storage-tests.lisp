(in-package #:bitcoin-lisp.tests)

(in-suite :storage-tests)

;;;; Block store

(test datadir-layout-prefers-core-and-falls-back-to-legacy
  "Core doc/files.md: blocks/index/, indexes/txindex/,
indexes/blockfilter/basic/, indexes/coinstatsindex/. This tree kept
headerindex.dat at the network-dir root and the indexes as flat siblings.

Every resolver PREFERS Core's path and falls back only when the legacy one
actually holds data. That asymmetry is the whole safety property: adopting
Core's layout unconditionally would present an EMPTY datadir to a node that has
one, which on mainnet means discarding a synced chain and starting IBD from
genesis."
  (let ((dir (merge-pathnames (format nil "bl-datadir-~D/" (get-internal-real-time))
                              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           ;; A FRESH datadir is Core-shaped from the first byte — which is
           ;; what the conformance harness needs.
           (is (search "indexes/txindex"
                       (namestring (bl.store:datadir-index-path dir :txindex))))
           (is (search "blocks/index"
                       (namestring (bl.store:datadir-header-index-file dir))))
           (is (null (bl.store:datadir-layout-report dir)))
           ;; An EMPTY Core-side directory must not win against a legacy one
           ;; that holds data: ensure-directories-exist creates empty ones
           ;; freely, so existence alone cannot be the test.
           (ensure-directories-exist (merge-pathnames "indexes/txindex/" dir))
           (ensure-directories-exist (merge-pathnames "txindex/" dir))
           (with-open-file (out (merge-pathnames "txindex/CURRENT" dir)
                                :direction :output :if-exists :supersede)
             (write-line "x" out))
           (multiple-value-bind (path legacy-p)
               (bl.store:datadir-index-path dir :txindex)
             (is-true legacy-p "an empty Core directory beat a populated legacy one")
             (is (search "/txindex" (namestring path))))
           ;; Legacy headerindex.dat likewise.
           (with-open-file (out (merge-pathnames "headerindex.dat" dir)
                                :direction :output :if-exists :supersede)
             (write-line "x" out))
           (multiple-value-bind (path legacy-p)
               (bl.store:datadir-header-index-file dir)
             (is-true legacy-p)
             (is (equal (merge-pathnames "headerindex.dat" dir) path)))
           ;; And the report names them, so an operator is told WHICH directory
           ;; is keeping their node off Core's layout.
           (let ((report (bl.store:datadir-layout-report dir)))
             (is (member "block index" report :key #'first :test #'string=))
             (is (member "txindex" report :key #'first :test #'string=))))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore)))))

(test disk-block-reads-use-the-byte-reader
  "BR-READ-BITCOIN-BLOCK's own docstring calls itself the hot path, and only
the inbound-network path used it — the DISK path, which reads every block
during a reindex, still wrapped its byte vector in a flexi-streams Gray stream.

That is pure overhead: the bytes are already in memory, and the stream adds a
generic-function dispatch per read. Profiling an offline reindex put
STREAM-READ-SEQUENCE at 6.4% of runtime with CLASSOID-TYPEP and the PCL braid
lambdas behind it.

Both readers must agree exactly — this is consensus-critical parsing, so the
test compares their OUTPUT rather than trusting that swapping them is safe."
  (let* ((blk (bl.store:make-genesis-block :testnet4))
         (bytes (bl.ser:serialize-witness-block blk))
         (via-stream (flexi-streams:with-input-from-sequence (s bytes)
                       (bl.ser:read-bitcoin-block s)))
         (via-reader (bl.ser:br-read-bitcoin-block
                      (bl.ser:make-byte-reader-from bytes))))
    (is (equalp (bl.ser:block-header-hash
                 (bl.ser:bitcoin-block-header via-stream))
                (bl.ser:block-header-hash
                 (bl.ser:bitcoin-block-header via-reader)))
        "the two block readers disagree on the block hash")
    (is (= (length (bl.ser:bitcoin-block-transactions via-stream))
           (length (bl.ser:bitcoin-block-transactions via-reader))))
    ;; And re-serializing the byte-reader result reproduces the input exactly,
    ;; which is the property that matters for a block read off disk.
    (is (equalp bytes (bl.ser:serialize-witness-block via-reader))))
  ;; The disk read sites must actually USE it — the whole defect was an
  ;; optimized reader with the wrong callers.
  (let ((src (with-open-file (in (merge-pathnames
                                  "src/storage/blocks.lisp"
                                  (asdf:system-source-directory :bitcoin-lisp)))
               (let ((text (make-string (file-length in))))
                 (subseq text 0 (read-sequence text in))))))
    (is (not (search "with-input-from-sequence" src))
        "a disk block read went back to a flexi-stream")
    (is (search "br-read-bitcoin-block" src))))

(test reindex-needs-a-genesis-root-in-the-index
  "REINDEX-BLOCK-INDEX links each record to a parent already in the index and
parks the rest, so the index needs a ROOT or the drain never starts.

Against a real Core testnet4 datadir that produced 134,923 records read,
134,923 orphaned and ZERO linked — a -reindex that silently accomplished
nothing. It went unnoticed because reindexing a datadir that ALREADY has an
index (the only case ever exercised) has genesis for a root; on a fresh datadir,
which is exactly when an operator reaches for -reindex, there was none.

This pins the property directly: with no root, nothing links; with genesis
seeded, the chain links."
  (let* ((bl:*network* :regtest)
         (empty (bl.store:make-chain-state))
         (seeded (bl.store:make-chain-state))
         (ghash (bl.store:network-genesis-hash :regtest))
         (ghdr (bl::make-genesis-header :regtest)))
    (is (= 0 (hash-table-count
              (bl.store:chain-state-block-index empty)))
        "a fresh chain-state must have an EMPTY block index, or this test ~
asserts nothing about the root")
    (bl.store:add-block-index-entry
     seeded (bl.store:make-block-index-entry
             :hash ghash :height 0 :header ghdr :chain-work 0 :status :valid))
    (is (= 1 (hash-table-count
              (bl.store:chain-state-block-index seeded))))
    ;; And the node seeds genesis BEFORE it reindexes — the ordering is the
    ;; whole fix, so assert it structurally rather than trusting the diff.
    (let ((src (%node-source-text)))
      (let ((genesis-at (search "(%ensure-genesis-index-entry network)" src))
            (reindex-at (search "Reindex: rebuilding the block index" src)))
        (is-true genesis-at "the genesis seeding call is gone")
        (is-true reindex-at "the reindex call is gone")
        (is (< genesis-at reindex-at)
            "genesis is seeded AFTER the reindex again; every record will orphan")))))

(test undo-storage-always-gets-the-legacy-per-block-directory
  "INITIALIZE-UNDO-STORAGE's argument is not \"where undo lives\" — it is
specifically the LEGACY PER-BLOCK directory. Core's revNNNNN.dat records are
addressed through the block store and chain state instead: a rev record is
found by the block index entry that points at it, never by scanning a
directory.

A later change briefly routed this through a resolver that preferred blocks/ whenever
blocks/ held anything. blocks/ ALWAYS holds something — the block files — so on
a real testnet4 node it pointed undo storage at blocks/ while 154,198 legacy
per-block records sat in undo/, making every one of them unreachable and every
one of those blocks undisconnectable. This pins the call site so the mistake
cannot be repeated as a refactor."
  (let ((form (with-output-to-string (out)
                ;; Read the node's undo-init form back out of the source, since
                ;; the property is about WHICH PATH the call site passes and
                ;; there is no runtime handle on that.
                (with-input-from-string (in (%node-source-text))
                  (loop for line = (read-line in nil) while line
                        do (when (search "(initialize-undo-storage" line)
                             (write-line line out))
                           (when (search "(let ((undo-path" line)
                             (write-line line out)))))))
    (is (search "\"undo/\"" form)
        "the undo directory is no longer the literal legacy path: ~S" form)
    (is (not (search "datadir-undo-path" form))
        "undo storage was routed through a path resolver again: ~S" form)))

(test datadir-resolvers-have-callers
  "Every resolver in kv/datadir.lisp must be REACHED by the node, not
merely defined. The datadir-layout change shipped DATADIR-UNDO-PATH with no caller — the undo site
still hardcoded \"undo/\" — so the resolver was dead code and the option it
implements did nothing. That was found by starting a real node and reading its
log, not by any unit test, which is why this one exists."
  (dolist (fn '(bl.store:datadir-header-index-file
                bl.store:datadir-index-path
                bl.store:datadir-layout-report))
    (let ((callers (remove-if (lambda (c)
                                ;; Its own file and the test package do not
                                ;; count as production callers.
                                (let ((name (if (consp c) (second c) c)))
                                  (and (symbolp name)
                                       (member (symbol-package name)
                                               (list (find-package :bitcoin-lisp.tests))))))
                              (mapcar #'car (sb-introspect:who-calls fn)))))
      (is-true callers "~A has no caller outside its own file" fn))))

(test migrate-datadir-layout-moves-and-is-idempotent
  "-migratedatadir moves a legacy datadir to Core's layout. Asserted through
the FILES, and specifically that the data ARRIVES — a migration that reports
success and moves nothing is the failure mode this project has already hit once
(backupwallet, where RENAME-FILE merged the target with the source pathname)."
  (let ((dir (merge-pathnames (format nil "bl-migrate-~D/" (get-internal-real-time))
                              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           (with-open-file (out (merge-pathnames "headerindex.dat" dir)
                                :direction :output :if-exists :supersede)
             (write-line "header-index-content" out))
           (ensure-directories-exist (merge-pathnames "txindex/" dir))
           (with-open-file (out (merge-pathnames "txindex/CURRENT" dir)
                                :direction :output :if-exists :supersede)
             (write-line "txindex-content" out))
           ;; Dry run reports the moves and changes nothing.
           (let ((planned (bl.store:migrate-datadir-layout dir :dry-run t)))
             (is (= 2 (length planned)) "planned ~S" planned)
             (is-true (probe-file (merge-pathnames "headerindex.dat" dir))
                      "a dry run moved a file"))
           (let ((moves (bl.store:migrate-datadir-layout dir)))
             (is (= 2 (length moves))))
           ;; The data is at Core's path, with its CONTENT, and gone from the old one.
           (let ((moved (merge-pathnames "blocks/index/headerindex.dat" dir)))
             (is-true (probe-file moved) "the block index did not arrive")
             (is (equal "header-index-content"
                        (with-open-file (in moved) (read-line in nil)))))
           (is-false (probe-file (merge-pathnames "headerindex.dat" dir))
                     "the legacy block index was left behind")
           (is-true (probe-file (merge-pathnames "indexes/txindex/CURRENT" dir))
                    "the txindex did not arrive")
           ;; The datadir now reports as Core-shaped.
           (is (null (bl.store:datadir-layout-report dir)))
           ;; And running it again is a no-op rather than an error.
           (is (null (bl.store:migrate-datadir-layout dir))))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore)))))

(test get-block-treats-corrupt-file-as-absent-and-prunes
  "A truncated / corrupt block file must NOT raise out of get-block — before the
guard, read-bitcoin-block's raise escaped the reorg/download paths to the
sync-thread top level and killed it (a live-but-wedged zombie). get-block now
returns NIL (treated as absent) AND prunes the file so the normal download path
re-fetches it (store-block :supersede overwrites).

Legacy per-block files specifically — hence the binding. A store on the flat
format keeps many blocks in one blk file and cannot delete it for one bad
record; that path is covered by GET-BLOCK-TREATS-CORRUPT-FLAT-RECORD-AS-ABSENT."
  (let* ((bl.store:*flat-block-files* nil)
         (dir (merge-pathnames "test-corrupt-block/" (uiop:temporary-directory)))
         (store (bl.store:init-block-store dir))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (tx (bl.ser:make-transaction
              :version 1
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash zeros :index #xffffffff)
                               :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out
                                :value 5000000000
                                :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                           :initial-element #x51)))
              :lock-time 0))
         (hdr (bl.ser:make-block-header
               :version 1 :prev-block zeros :merkle-root zeros
               :timestamp 1700000000 :bits #x207fffff :nonce 0))
         (blk (bl.ser:make-bitcoin-block
               :header hdr :transactions (list tx))))
    (unwind-protect
         (let ((hash (bl.store:store-block store blk)))
           ;; Reads back fine while intact.
           (is-true (bl.store:get-block store hash))
           ;; Truncate the on-disk file to garbage so read-bitcoin-block raises.
           (let ((path (bl.store::block-file-path store hash)))
             (with-open-file (s path :direction :output :if-exists :supersede
                                     :element-type '(unsigned-byte 8))
               (write-sequence (make-array 3 :element-type '(unsigned-byte 8)
                                             :initial-contents '(1 2 3)) s))
             ;; get-block must NOT raise: returns NIL and prunes the file.
             (is (null (bl.store:get-block store hash)))
             (is (null (probe-file path))
                 "corrupt block file must be pruned so re-download can self-heal")))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test get-block-treats-corrupt-flat-record-as-absent
  "The flat-format counterpart. A corrupt record inside a blk file must also
return NIL rather than raise — but it must NOT take the file with it: one
blk?????.dat holds many blocks, and deleting it for one bad record would
discard every good block beside it. Core does the same, failing the single read
(ReadBlock returns false) and leaving the file alone."
  (let* ((bl.store:*flat-block-files* t)
         (dir (merge-pathnames "test-corrupt-flat/" (uiop:temporary-directory)))
         (store (bl.store:init-block-store dir))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (blk (lambda (prev-byte)
                (bl.ser:make-bitcoin-block
                 :header (bl.ser:make-block-header
                          :version 1
                          :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element prev-byte)
                          :merkle-root zeros :timestamp 1700000000
                          :bits #x207fffff :nonce 0)
                 :transactions
                 (list (bl.ser:make-transaction
                        :version 1
                        :inputs (vector (bl.ser:make-tx-in
                                         :previous-output
                                         (bl.ser:make-outpoint
                                          :hash zeros :index #xffffffff)
                                         :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                                                   :initial-element 0)
                                         :sequence #xffffffff))
                        :outputs (vector (bl.ser:make-tx-out
                                          :value 5000000000
                                          :script-pubkey
                                          (make-array 1 :element-type '(unsigned-byte 8)
                                                        :initial-element #x51)))
                        :lock-time 0))))))
    (unwind-protect
         (let ((victim (bl.store:store-block store (funcall blk 7)))
               (bystander (bl.store:store-block store (funcall blk 9))))
           (is-true (bl.store:get-block store victim))
           (is-true (bl.store:get-block store bystander))
           ;; Scribble over the first record's framing header in place.
           (let* ((pos (gethash victim (bl.store::block-store-index store)))
                  (path (bl.kv:flat-file-name
                         (bl.store::%blk-seq store) pos)))
             (is-true (bl.kv:flat-file-pos-p pos)
                      "the flat default did not put the block in a blk file")
             (with-open-file (s path :direction :io :element-type '(unsigned-byte 8)
                                     :if-exists :overwrite)
               (file-position s (- (bl.kv:flat-file-pos-pos pos)
                                   bl.kv:+storage-header-bytes+))
               (write-sequence (make-array 8 :element-type '(unsigned-byte 8)
                                             :initial-element #xff)
                               s))
             (is (null (bl.store:get-block store victim))
                 "a corrupt flat record must read as absent, not raise")
             (is-true (probe-file path)
                      "the blk file must survive one bad record")
             (is-true (bl.store:get-block store bystander)
                      "the other blocks in the same file must still be readable")))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test store-block-preserves-witness
  "store-block must persist witness data (BIP144) so blocks read back from disk
are witness-complete — needed to serve MSG_WITNESS_BLOCK to peers (the
serve-blocks fix) and to re-validate witness on reorg. Before the fix store-block
used the legacy serializer, which dropped witness."
  (let* ((dir (merge-pathnames "test-store-witness/" (uiop:temporary-directory)))
         (store (bl.store:init-block-store dir))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (wtx (bl.ser:make-transaction
               :version 2
               :inputs (vector (bl.ser:make-tx-in
                                :previous-output (bl.ser:make-outpoint
                                                  :hash prev :index 0)
                                :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                :sequence #xffffffff))
               :outputs (vector (bl.ser:make-tx-out
                                 :value 1000
                                 :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                            :initial-element #x51)))
               :witness (vector (list (make-array 3 :element-type '(unsigned-byte 8)
                                                  :initial-contents '(1 2 3))))
               :lock-time 0))
         (hdr (bl.ser:make-block-header
               :version 1 :prev-block zeros :merkle-root zeros
               :timestamp 1700000000 :bits #x207fffff :nonce 0))
         (blk (bl.ser:make-bitcoin-block
               :header hdr :transactions (list wtx))))
    (is-true (bl.ser:transaction-has-witness-p wtx))
    (let* ((hash (bl.store:store-block store blk))
           (retrieved (bl.store:get-block store hash))
           (rtx (first (bl.ser:bitcoin-block-transactions retrieved))))
      (is-true (bl.ser:transaction-has-witness-p rtx)
               "retrieved block tx must retain witness data")
      (is (equalp (bl.ser:serialize-witness-transaction wtx)
                  (bl.ser:serialize-witness-transaction rtx))
          "round-tripped witness tx must be byte-identical"))
    (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))

;;;; UTXO Set Tests

(test utxo-set-add-and-get
  "Adding a UTXO should make it retrievable."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid 0 50000000 script 100)
    (let ((entry (bl.store:get-utxo utxo-set txid 0)))
      (is (not (null entry)))
      (is (= 50000000 (bl.store:utxo-entry-value entry)))
      (is (= 100 (bl.store:utxo-entry-height entry)))
      (is (equalp script (bl.store:utxo-entry-script-pubkey entry))))))

(test utxo-set-remove
  "Removing a UTXO should make it no longer retrievable."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid 0 25000000 script 50)
    (is (bl.store:utxo-exists-p utxo-set txid 0))
    (bl.store:remove-utxo utxo-set txid 0)
    (is (not (bl.store:utxo-exists-p utxo-set txid 0)))))

(test utxo-set-count
  "UTXO count should track additions and removals."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (is (= 0 (bl.store:utxo-count utxo-set)))
    (bl.store:add-utxo utxo-set txid1 0 1000 script 1)
    (is (= 1 (bl.store:utxo-count utxo-set)))
    (bl.store:add-utxo utxo-set txid1 1 2000 script 1)
    (is (= 2 (bl.store:utxo-count utxo-set)))
    (bl.store:add-utxo utxo-set txid2 0 3000 script 1)
    (is (= 3 (bl.store:utxo-count utxo-set)))
    (bl.store:remove-utxo utxo-set txid1 0)
    (is (= 2 (bl.store:utxo-count utxo-set)))))

(test utxo-set-coinbase-flag
  "Coinbase UTXOs should be flagged correctly."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid1 0 5000000000 script 0 :coinbase t)
    (bl.store:add-utxo utxo-set txid2 0 1000000 script 1 :coinbase nil)
    (is (bl.store:utxo-entry-coinbase
         (bl.store:get-utxo utxo-set txid1 0)))
    (is (not (bl.store:utxo-entry-coinbase
              (bl.store:get-utxo utxo-set txid2 0))))))

(test utxo-set-multiple-outputs-same-tx
  "Multiple outputs from the same transaction should be distinguishable."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid 0 1000 script 10)
    (bl.store:add-utxo utxo-set txid 1 2000 script 10)
    (bl.store:add-utxo utxo-set txid 2 3000 script 10)
    (is (= 3 (bl.store:utxo-count utxo-set)))
    (is (= 1000 (bl.store:utxo-entry-value
                 (bl.store:get-utxo utxo-set txid 0))))
    (is (= 2000 (bl.store:utxo-entry-value
                 (bl.store:get-utxo utxo-set txid 1))))
    (is (= 3000 (bl.store:utxo-entry-value
                 (bl.store:get-utxo utxo-set txid 2))))))

;;;; Chain State Tests

(test chain-state-init
  "Chain state should initialize with genesis hash."
  (let ((state (bl.store:init-chain-state "/tmp/btc-test/")))
    (is (not (null (bl.store:best-block-hash state))))
    (is (= 0 (bl.store:current-height state)))))

(test chain-state-update-tip
  "Updating chain tip should change best block and height."
  (let ((state (bl.store:init-chain-state "/tmp/btc-test/"))
        (new-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)))
    (bl.store:update-chain-tip state new-hash 100)
    (is (equalp new-hash (bl.store:best-block-hash state)))
    (is (= 100 (bl.store:current-height state)))))

(test chain-state-block-index
  "Block index entries should be storable and retrievable."
  (let ((state (bl.store:init-chain-state "/tmp/btc-test/"))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (let ((entry (bl.store:make-block-index-entry
                  :hash hash
                  :height 50
                  :chain-work 12345
                  :status :valid)))
      (bl.store:add-block-index-entry state entry)
      (let ((retrieved (bl.store:get-block-index-entry state hash)))
        (is (not (null retrieved)))
        (is (= 50 (bl.store:block-index-entry-height retrieved)))
        (is (= 12345 (bl.store:block-index-entry-chain-work retrieved)))
        (is (eq :valid (bl.store:block-index-entry-status retrieved)))))))

;;;; Chain Work Tests

(test bits-to-target-conversion
  "Bits to target conversion should match expected values."
  ;; Testnet genesis bits: 0x1d00ffff
  (let ((target (bl.store:bits-to-target #x1d00ffff)))
    ;; This should give a very large target (low difficulty)
    (is (> target 0))
    (is (< target (expt 2 256)))))

(test chain-work-calculation
  "Chain work calculation should accumulate correctly."
  (let ((work1 (bl.store:calculate-chain-work #x1d00ffff 0)))
    (is (> work1 0))
    (let ((work2 (bl.store:calculate-chain-work #x1d00ffff work1)))
      (is (> work2 work1))
      ;; Work should roughly double (same difficulty)
      (is (< (abs (- work2 (* 2 work1))) 1)))))

;;;; Block Locator Tests

(test block-locator-empty-chain
  "Block locator for empty chain should include genesis."
  (let ((state (bl.store:init-chain-state "/tmp/btc-test/")))
    (let ((locator (bl.store:build-block-locator state)))
      (is (not (null locator)))
      ;; Should at least have genesis
      (is (>= (length locator) 1)))))

;;;; UTXO Set Iteration Tests

(test utxo-set-iterate-empty
  "Iterating empty UTXO set should not call callback."
  (let ((utxo-set (bl.store:make-utxo-set))
        (count 0))
    (bl.store:utxo-set-iterate
     utxo-set
     (lambda (txid vout entry)
       (declare (ignore txid vout entry))
       (incf count)))
    (is (= count 0))))

(test utxo-set-iterate-all-entries
  "Iterating UTXO set should visit all entries."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0))
        (visited nil))
    ;; Add 3 UTXOs
    (bl.store:add-utxo utxo-set txid1 0 1000 script 1)
    (bl.store:add-utxo utxo-set txid1 1 2000 script 1)
    (bl.store:add-utxo utxo-set txid2 0 3000 script 2)
    ;; Iterate and collect
    (bl.store:utxo-set-iterate
     utxo-set
     (lambda (txid vout entry)
       (push (list txid vout (bl.store:utxo-entry-value entry)) visited)))
    ;; Should have visited all 3
    (is (= (length visited) 3))))

(test utxo-set-iterate-deterministic-order
  "UTXO iteration order should be deterministic across multiple calls."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0))
        (order1 nil)
        (order2 nil))
    ;; Add in non-sorted order
    (bl.store:add-utxo utxo-set txid-b 1 300 script 1)
    (bl.store:add-utxo utxo-set txid-a 0 100 script 1)
    (bl.store:add-utxo utxo-set txid-b 0 200 script 1)
    (bl.store:add-utxo utxo-set txid-a 1 150 script 1)
    ;; First iteration
    (bl.store:utxo-set-iterate
     utxo-set
     (lambda (txid vout entry)
       (declare (ignore entry))
       (push (cons (aref txid 0) vout) order1)))
    (setf order1 (nreverse order1))
    ;; Second iteration - should produce same order
    (bl.store:utxo-set-iterate
     utxo-set
     (lambda (txid vout entry)
       (declare (ignore entry))
       (push (cons (aref txid 0) vout) order2)))
    (setf order2 (nreverse order2))
    ;; Check consistency
    (is (= (length order1) 4))
    (is (equal order1 order2))))

(test utxo-set-total-amount
  "Total amount should sum all UTXO values."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Empty set
    (is (= (bl.store:utxo-set-total-amount utxo-set) 0))
    ;; Add UTXOs
    (bl.store:add-utxo utxo-set txid1 0 100000000 script 1) ; 1 BTC
    (bl.store:add-utxo utxo-set txid1 1 50000000 script 1)  ; 0.5 BTC
    (bl.store:add-utxo utxo-set txid2 0 25000000 script 2)  ; 0.25 BTC
    ;; Total: 1.75 BTC = 175000000 satoshis
    (is (= (bl.store:utxo-set-total-amount utxo-set) 175000000))))

(test utxo-set-distinct-txids
  "Distinct txids should count unique transactions."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (txid3 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Empty set
    (is (= (bl.store:utxo-set-distinct-txids utxo-set) 0))
    ;; Add multiple outputs from same tx
    (bl.store:add-utxo utxo-set txid1 0 1000 script 1)
    (bl.store:add-utxo utxo-set txid1 1 2000 script 1)
    (is (= (bl.store:utxo-set-distinct-txids utxo-set) 1))
    ;; Add from different txs
    (bl.store:add-utxo utxo-set txid2 0 3000 script 2)
    (bl.store:add-utxo utxo-set txid3 0 4000 script 3)
    (is (= (bl.store:utxo-set-distinct-txids utxo-set) 3))))

(test compute-utxo-set-hash-empty
  "Hash of empty UTXO set should be consistent."
  (let ((utxo-set (bl.store:make-utxo-set)))
    (let ((hash1 (bl.store:compute-utxo-set-hash utxo-set))
          (hash2 (bl.store:compute-utxo-set-hash utxo-set)))
      ;; Should return same hash for same state
      (is (equalp hash1 hash2))
      ;; Should be 32 bytes
      (is (= (length hash1) 32)))))

(test compute-utxo-set-hash-deterministic
  "UTXO set hash should be deterministic on repeated calls."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Add UTXOs
    (bl.store:add-utxo utxo-set txid-a 0 1000 script 1)
    (bl.store:add-utxo utxo-set txid-b 0 2000 script 2)
    ;; Hash should be identical on repeated calls
    (let ((hash1 (bl.store:compute-utxo-set-hash utxo-set))
          (hash2 (bl.store:compute-utxo-set-hash utxo-set)))
      (is (equalp hash1 hash2))
      ;; Hash should change when UTXO set changes
      (bl.store:add-utxo utxo-set txid-a 1 500 script 1)
      (let ((hash3 (bl.store:compute-utxo-set-hash utxo-set)))
        (is (not (equalp hash1 hash3)))))))

;;;; Transaction Index Tests

(test txindex-init-and-close
  "Transaction index should initialize and close cleanly."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bl.store:init-tx-index test-dir)))
    (is (not (null txindex)))
    (is (bl.store:tx-index-enabled txindex))
    (bl.store:close-tx-index txindex)
    ;; Cleanup
    (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir)))))

(test txindex-add-and-lookup
  "Adding to txindex should make entry retrievable."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bl.store:init-tx-index test-dir))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (unwind-protect
        (progn
          ;; Add entry
          (bl.store:txindex-add txindex txid block-hash 5)
          ;; Lookup
          (let ((location (bl.store:txindex-lookup txindex txid)))
            (is (not (null location)))
            (is (equalp (bl.store:tx-location-block-hash location) block-hash))
            (is (= (bl.store:tx-location-tx-position location) 5))))
      ;; Cleanup
      (bl.store:close-tx-index txindex)
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-lookup-missing
  "Looking up missing txid should return nil."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bl.store:init-tx-index test-dir))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99)))
    (unwind-protect
        (is (null (bl.store:txindex-lookup txindex txid)))
      (bl.store:close-tx-index txindex)
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-remove
  "Removing from txindex should make entry no longer retrievable."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bl.store:init-tx-index test-dir))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4)))
    (unwind-protect
        (progn
          ;; Add then remove
          (bl.store:txindex-add txindex txid block-hash 0)
          (is (not (null (bl.store:txindex-lookup txindex txid))))
          (bl.store:txindex-remove txindex txid)
          (is (null (bl.store:txindex-lookup txindex txid))))
      (bl.store:close-tx-index txindex)
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-persistence
  "Transaction index should persist across close/reopen."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6)))
    (unwind-protect
        (progn
          ;; First session: add entry
          (let ((txindex (bl.store:init-tx-index test-dir)))
            (bl.store:txindex-add txindex txid block-hash 10)
            (bl.store:close-tx-index txindex))
          ;; Second session: verify entry persisted
          (let ((txindex (bl.store:init-tx-index test-dir)))
            (unwind-protect
                (let ((location (bl.store:txindex-lookup txindex txid)))
                  (is (not (null location)))
                  (is (equalp (bl.store:tx-location-block-hash location) block-hash))
                  (is (= (bl.store:tx-location-tx-position location) 10)))
              (bl.store:close-tx-index txindex))))
      ;; Cleanup
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-upsert-overwrites
  "txindex-add UPSERTS: adding an existing txid overwrites its stored location
(Core index/txindex.cpp CustomAppend batch-writes unconditionally), both live
and across a close/reopen (load-tx-index's sequential replay is
last-entry-wins). This is what re-points a reorg-disconnected tx re-mined in
the new chain; the old early-return left it at the stale branch's block."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A-up/" (get-universal-time)))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8))
         (block-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
         (block-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB)))
    (unwind-protect
        (progn
          (let ((txindex (bl.store:init-tx-index test-dir)))
            (bl.store:txindex-add txindex txid block-a 1)
            (bl.store:txindex-add txindex txid block-b 3)
            ;; Live: the newest location wins; still a single distinct txid.
            (let ((loc (bl.store:txindex-lookup txindex txid)))
              (is (equalp block-b (bl.store:tx-location-block-hash loc)))
              (is (= 3 (bl.store:tx-location-tx-position loc))))
            (is (= 1 (bl.store:txindex-count txindex)))
            (bl.store:close-tx-index txindex))
          ;; Reopen: the file replay resolves to the newest location too.
          (let ((txindex (bl.store:init-tx-index test-dir)))
            (unwind-protect
                (let ((loc (bl.store:txindex-lookup txindex txid)))
                  (is (equalp block-b (bl.store:tx-location-block-hash loc)))
                  (is (= 3 (bl.store:tx-location-tx-position loc)))
                  (is (= 1 (bl.store:txindex-count txindex))))
              (bl.store:close-tx-index txindex))))
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-multiple-entries
  "Transaction index should handle multiple entries."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bl.store:init-tx-index test-dir))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (unwind-protect
        (progn
          ;; Add multiple entries
          (dotimes (i 10)
            (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element i)))
              (bl.store:txindex-add txindex txid block-hash i)))
          ;; Verify all retrievable
          (dotimes (i 10)
            (let* ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))
                   (location (bl.store:txindex-lookup txindex txid)))
              (is (not (null location)))
              (is (= (bl.store:tx-location-tx-position location) i)))))
      (bl.store:close-tx-index txindex)
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))


;;;; LevelDB CFFI binding tests

(defun %tmp-leveldb-path ()
  (namestring
   (merge-pathnames (format nil "bitcoin-lisp-leveldb-test-~D-~D/"
                            (get-universal-time) (random 100000))
                    (uiop:temporary-directory))))

(defmacro %with-tmp-leveldb-path ((path-var) &body body)
  "Bind PATH-VAR to a fresh tmp leveldb path. On unwind, destroy-db +
delete-directory-tree as belt-and-braces cleanup."
  `(let ((,path-var (%tmp-leveldb-path)))
     (unwind-protect (progn ,@body)
       (ignore-errors (bl.store:leveldb-destroy-db ,path-var))
       (ignore-errors
         (uiop:delete-directory-tree (pathname ,path-var)
                                     :validate t
                                     :if-does-not-exist :ignore)))))

(defmacro %with-tmp-leveldb ((db-var) &body body)
  "Open a fresh LevelDB at a tmp path; bind DB-VAR to the handle."
  (let ((path-var (gensym "PATH-")))
    `(%with-tmp-leveldb-path (,path-var)
       (bl.store:with-leveldb (,db-var ,path-var)
         ,@body))))

(test leveldb-put-get-round-trip
  "PUT then GET returns the value bytes verbatim."
  (%with-tmp-leveldb (db)
    (let ((k (make-array 3 :element-type '(unsigned-byte 8)
                           :initial-contents #(1 2 3)))
          (v (make-array 5 :element-type '(unsigned-byte 8)
                           :initial-contents #(10 20 30 40 50))))
      (bl.store:leveldb-put db k v)
      (is (equalp v (bl.store:leveldb-get db k))))))

(test leveldb-compact-preserves-data
  "leveldb-compact (full CompactRange) runs without error and leaves live keys
readable while deleted keys stay gone -- exercises the FFI binding end-to-end."
  (%with-tmp-leveldb (db)
    (flet ((b (n) (make-array 1 :element-type '(unsigned-byte 8)
                                :initial-contents (list n))))
      (dotimes (i 50) (bl.store:leveldb-put db (b i) (b (* 2 i))))
      (dotimes (i 25) (bl.store:leveldb-delete db (b i))) ; leave tombstones
      (bl.store:leveldb-compact db)
      ;; deleted keys are gone; surviving keys are intact after compaction
      (is (null (bl.store:leveldb-get db (b 0))))
      (is (null (bl.store:leveldb-get db (b 24))))
      (is (equalp (b 50) (bl.store:leveldb-get db (b 25))))
      (is (equalp (b 98) (bl.store:leveldb-get db (b 49)))))))

(test leveldb-get-missing
  "GET on an absent key returns NIL (not an error)."
  (%with-tmp-leveldb (db)
    (is (null (bl.store:leveldb-get
               db (make-array 1 :element-type '(unsigned-byte 8)
                                :initial-contents #(99)))))))

(test leveldb-delete
  "DELETE removes a previously put key."
  (%with-tmp-leveldb (db)
    (let ((k (make-array 2 :element-type '(unsigned-byte 8)
                           :initial-contents #(1 1)))
          (v (make-array 1 :element-type '(unsigned-byte 8)
                           :initial-contents #(42))))
      (bl.store:leveldb-put db k v)
      (is (equalp v (bl.store:leveldb-get db k)))
      (bl.store:leveldb-delete db k)
      (is (null (bl.store:leveldb-get db k))))))

(test leveldb-writebatch-atomic
  "A WriteBatch applies put + delete atomically."
  (%with-tmp-leveldb (db)
    (let ((k1 (make-array 1 :element-type '(unsigned-byte 8)
                            :initial-contents #(1)))
          (k2 (make-array 1 :element-type '(unsigned-byte 8)
                            :initial-contents #(2)))
          (v1 (make-array 1 :element-type '(unsigned-byte 8)
                            :initial-contents #(11)))
          (v2 (make-array 1 :element-type '(unsigned-byte 8)
                            :initial-contents #(22))))
      (bl.store:leveldb-put db k1 v1)
      (bl.store:with-leveldb-writebatch (b)
        (bl.store:leveldb-writebatch-delete b k1)
        (bl.store:leveldb-writebatch-put b k2 v2)
        (bl.store:leveldb-write db b))
      (is (null (bl.store:leveldb-get db k1)))
      (is (equalp v2 (bl.store:leveldb-get db k2))))))

(test leveldb-persistence-across-open-close
  "Data written in one open survives close + reopen."
  (%with-tmp-leveldb-path (path)
    (let ((k (make-array 4 :element-type '(unsigned-byte 8)
                           :initial-contents #(7 7 7 7)))
          (v (make-array 4 :element-type '(unsigned-byte 8)
                           :initial-contents #(8 8 8 8))))
      (bl.store:with-leveldb (db path)
        (bl.store:leveldb-put db k v))
      (bl.store:with-leveldb (db path)
        (is (equalp v (bl.store:leveldb-get db k)))))))

;;;; coins-view-db tests

(defmacro %with-tmp-coins-view ((view-var) &body body)
  "Open a fresh coins-view-db at a tmp path; bind VIEW-VAR."
  (let ((path-var (gensym "PATH-")))
    `(%with-tmp-leveldb-path (,path-var)
       (bl.store:with-coins-view-db (,view-var ,path-var)
         ,@body))))

(defun %sample-utxo-entry (&optional (value 50000000) (height 100))
  (bl.store:make-utxo-entry
   :value value
   :height height
   :coinbase nil
   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                 :initial-element #x76)))

(defun %sample-utxo-key (&optional (txid-element 1) (vout 0))
  (bl.store:make-utxo-key
   (make-array 32 :element-type '(unsigned-byte 8) :initial-element txid-element)
   vout))

(test coins-view-db-put-get-round-trip
  "Putting then getting a coin returns an equivalent utxo-entry."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 1 5))
          (e (%sample-utxo-entry 12345 99)))
      (bl.store:coins-view-db-put view k e)
      (let ((got (bl.store:coins-view-db-get view k)))
        (is (not (null got)))
        (is (= 12345 (bl.store:utxo-entry-value got)))
        (is (= 99 (bl.store:utxo-entry-height got)))
        (is (null (bl.store:utxo-entry-coinbase got)))
        (is (equalp (bl.store:utxo-entry-script-pubkey e)
                    (bl.store:utxo-entry-script-pubkey got)))))))

(test coins-view-db-get-missing
  "Getting an absent key returns NIL."
  (%with-tmp-coins-view (view)
    (is (null (bl.store:coins-view-db-get
               view (%sample-utxo-key 99 0))))))

(test coins-view-db-has-p
  "has-p reflects present/absent state."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 7 0)))
      (is (null (bl.store:coins-view-db-has-p view k)))
      (bl.store:coins-view-db-put view k (%sample-utxo-entry))
      (is (not (null (bl.store:coins-view-db-has-p view k)))))))

(test coins-view-db-erase
  "erase removes a previously-put coin."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 3 1))
          (e (%sample-utxo-entry)))
      (bl.store:coins-view-db-put view k e)
      (is (not (null (bl.store:coins-view-db-get view k))))
      (bl.store:coins-view-db-erase view k)
      (is (null (bl.store:coins-view-db-get view k))))))

(test coins-view-db-coinbase-flag-preserved
  "coinbase boolean round-trips correctly."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 11 0))
          (e (bl.store:make-utxo-entry
              :value 5000000000
              :height 1
              :coinbase t
              :script-pubkey (make-array 0 :element-type '(unsigned-byte 8)))))
      (bl.store:coins-view-db-put view k e)
      (let ((got (bl.store:coins-view-db-get view k)))
        (is (eq t (bl.store:utxo-entry-coinbase got)))))))

(test coins-view-db-write-batch
  "A batch of put + erase ops applies atomically."
  (%with-tmp-coins-view (view)
    (let ((k1 (%sample-utxo-key 1 0))
          (k2 (%sample-utxo-key 2 0))
          (e1 (%sample-utxo-entry 100 10))
          (e2 (%sample-utxo-entry 200 20)))
      ;; Seed k1; then a batch erases k1 and adds k2.
      (bl.store:coins-view-db-put view k1 e1)
      (bl.store:coins-view-db-write-batch
       view (list (list :erase k1) (list :put k2 e2)))
      (is (null (bl.store:coins-view-db-get view k1)))
      (let ((got (bl.store:coins-view-db-get view k2)))
        (is (not (null got)))
        (is (= 200 (bl.store:utxo-entry-value got)))))))

(test coins-view-db-persistence-across-open-close
  "Coins written then closed are visible on reopen."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 5 7))
          (e (%sample-utxo-entry 999 42)))
      (bl.store:with-coins-view-db (view path)
        (bl.store:coins-view-db-put view k e))
      (bl.store:with-coins-view-db (view path)
        (let ((got (bl.store:coins-view-db-get view k)))
          (is (not (null got)))
          (is (= 999 (bl.store:utxo-entry-value got))))))))

;;;; coins-view-cache tests
;;;;
;;;; The cache is layered over a coins-view-db. Each test creates a
;;;; fresh tmp db + cache. We exercise the dirty-tracking + FRESH
;;;; semantics, then verify post-flush state via the underlying base.

(defmacro %with-tmp-cache ((cache-var) &body body)
  "Open a fresh coins-view-db + layered cache. Belt-and-braces cleanup."
  (let ((path-var (gensym "PATH-"))
        (base-var (gensym "BASE-")))
    `(%with-tmp-leveldb-path (,path-var)
       (bl.store:with-coins-view-db (,base-var ,path-var)
         (let ((,cache-var (bl.store:make-coins-view-cache ,base-var)))
           ,@body)))))

(test coins-view-cache-add-then-get
  "Add via cache; subsequent get returns the entry."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 1 0))
          (e (%sample-utxo-entry 42 7)))
      (bl.store:coins-view-cache-add cache k e)
      (let ((got (bl.store:coins-view-cache-get cache k)))
        (is (not (null got)))
        (is (= 42 (bl.store:utxo-entry-value got)))))))

(test coins-view-cache-pulls-from-base
  "Get on a key absent from cache but present in base falls through to base."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 2 0))
          (e (%sample-utxo-entry 999 10)))
      ;; First, populate the base view directly.
      (bl.store:with-coins-view-db (base path)
        (bl.store:coins-view-db-put base k e))
      ;; New cache over same base — should see the base entry.
      (bl.store:with-coins-view-db (base path)
        (let ((cache (bl.store:make-coins-view-cache base)))
          (let ((got (bl.store:coins-view-cache-get cache k)))
            (is (not (null got)))
            (is (= 999 (bl.store:utxo-entry-value got)))))))))

(test coins-view-cache-spend-marks-spent
  "Spend on a cached unspent coin returns T; subsequent get returns NIL."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 3 0))
          (e (%sample-utxo-entry)))
      (bl.store:coins-view-cache-add cache k e)
      (is (eq t (bl.store:coins-view-cache-spend cache k)))
      (is (null (bl.store:coins-view-cache-get cache k)))
      (is (null (bl.store:coins-view-cache-has-p cache k))))))

(test coins-view-cache-spend-fresh-drops-entry
  "Spending a FRESH (add-then-spend, never flushed) coin drops the
cache entry entirely — flush has nothing to do."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 4 0))
          (e (%sample-utxo-entry)))
      (bl.store:coins-view-cache-add cache k e)
      (is (= 1 (coins-cache-fresh-count cache)))
      (is (= 1 (coins-cache-dirty-count cache)))
      (bl.store:coins-view-cache-spend cache k)
      (is (= 0 (coins-cache-fresh-count cache)))
      (is (= 0 (coins-cache-dirty-count cache)))
      (is (= 0 (hash-table-count (coins-cache-entries cache)))))))

(test coins-view-cache-spend-non-fresh-keeps-tombstone
  "Spending a coin that came from base leaves a NIL tombstone in
cache (so flush issues the erase). FRESH-count stays zero."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 5 0))
          (e (%sample-utxo-entry)))
      (bl.store:with-coins-view-db (base path)
        (bl.store:coins-view-db-put base k e))
      (bl.store:with-coins-view-db (base path)
        (let ((cache (bl.store:make-coins-view-cache base)))
          (bl.store:coins-view-cache-spend cache k)
          (is (= 1 (coins-cache-dirty-count cache)))
          (is (= 0 (coins-cache-fresh-count cache)))
          (is (= 1 (hash-table-count (coins-cache-entries cache)))))))))

(test coins-view-cache-flush-writes-and-clears
  "Flush writes dirty entries to base, then clears the cache."
  (%with-tmp-leveldb-path (path)
    (let ((k1 (%sample-utxo-key 6 0))
          (k2 (%sample-utxo-key 7 0))
          (e1 (%sample-utxo-entry 100 1))
          (e2 (%sample-utxo-entry 200 2)))
      (bl.store:with-coins-view-db (base path)
        (let ((cache (bl.store:make-coins-view-cache base)))
          (bl.store:coins-view-cache-add cache k1 e1)
          (bl.store:coins-view-cache-add cache k2 e2)
          (let ((written (bl.store:coins-view-cache-flush cache)))
            (is (= 2 written)))
          ;; Cache is empty after flush.
          (is (= 0 (hash-table-count (coins-cache-entries cache))))
          ;; Base now has both entries.
          (is (not (null (bl.store:coins-view-db-get base k1))))
          (is (not (null (bl.store:coins-view-db-get base k2)))))))))

(test coins-view-cache-flush-issues-erase
  "Flushing a spent (NIL) entry erases it from base."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 8 0))
          (e (%sample-utxo-entry)))
      (bl.store:with-coins-view-db (base path)
        (bl.store:coins-view-db-put base k e))
      (bl.store:with-coins-view-db (base path)
        (let ((cache (bl.store:make-coins-view-cache base)))
          (bl.store:coins-view-cache-spend cache k)
          (bl.store:coins-view-cache-flush cache)
          (is (null (bl.store:coins-view-db-get base k))))))))

(test coins-view-cache-add-overwrite-error
  "Adding to an already-unspent key without :allow-overwrite signals."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 9 0))
          (e (%sample-utxo-entry)))
      (bl.store:coins-view-cache-add cache k e)
      (signals error
        (bl.store:coins-view-cache-add cache k e)))))

(test coins-view-cache-add-overwrite-allowed
  ":allow-overwrite T silently overwrites (coinbase rewrite case)."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 10 0))
          (e1 (%sample-utxo-entry 100 1))
          (e2 (%sample-utxo-entry 200 2)))
      (bl.store:coins-view-cache-add cache k e1)
      (bl.store:coins-view-cache-add cache k e2 :allow-overwrite t)
      (is (= 200 (bl.store:utxo-entry-value
                  (bl.store:coins-view-cache-get cache k)))))))

;;;; Migration: utxoset.dat → LevelDB tests
;;;;
;;;; Strategy: build an in-memory utxo-set with known entries, save it
;;;; to a temp utxoset.dat, run the migration into a temp LevelDB,
;;;; verify the LevelDB-backed view contains every entry with the same
;;;; values. Also verify the migration-complete marker is set, and that
;;;; an interrupted migration is detectable (marker absent).

(defun %tmp-dat-path ()
  (namestring
   (merge-pathnames (format nil "bitcoin-lisp-migration-test-~D-~D.dat"
                            (get-universal-time) (random 100000))
                    (uiop:temporary-directory))))

(defmacro %with-tmp-dat-and-leveldb ((dat-var ldb-var) &body body)
  "Bind DAT-VAR to a fresh tmp utxoset.dat path and LDB-VAR to a fresh
tmp LevelDB path. Both are cleaned up on exit."
  `(let ((,dat-var (%tmp-dat-path)))
     (unwind-protect
          (%with-tmp-leveldb-path (,ldb-var)
            ,@body)
       (ignore-errors (delete-file ,dat-var)))))

(defun %populated-utxo-set (count)
  "Build an in-memory utxo-set with COUNT distinct entries. Keys vary
in their txid first-byte to give a mix; values vary in amount/height."
  (let ((set (bl.store:make-utxo-set)))
    (dotimes (i count)
      (let ((txid (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element (mod i 256)))
            (script (make-array 25 :element-type '(unsigned-byte 8)
                                   :initial-element #x76)))
        (bl.store:add-utxo set txid (mod i 4)
                                       (* 1000 (1+ i)) script (1+ i))))
    set))

(test migration-empty-set
  "Migrating an empty utxo-set yields an empty LevelDB but still marks complete."
  (%with-tmp-dat-and-leveldb (dat-path ldb-path)
    (let ((empty-set (bl.store:make-utxo-set)))
      (bl.store:save-utxo-set empty-set dat-path))
    (let ((written (bl.store:migrate-utxoset-dat-to-leveldb
                    dat-path ldb-path)))
      (is (= 0 written)))
    (is (eq t (bl.store:leveldb-utxo-migration-complete-p ldb-path)))))

(test migration-round-trip
  "After migration, every entry in the source set is retrievable from
the LevelDB via coins-view-db-get."
  (%with-tmp-dat-and-leveldb (dat-path ldb-path)
    (let* ((source (%populated-utxo-set 50)))
      (bl.store:save-utxo-set source dat-path)
      (let ((written (bl.store:migrate-utxoset-dat-to-leveldb
                      dat-path ldb-path)))
        (is (= 50 written)))
      ;; Verify equivalence: every (key, entry) in source is in LevelDB.
      (bl.store:with-coins-view-db (view ldb-path)
        (maphash (lambda (key src-entry)
                   (let ((dst-entry (bl.store:coins-view-db-get view key)))
                     (is (not (null dst-entry)))
                     (is (= (bl.store:utxo-entry-value src-entry)
                            (bl.store:utxo-entry-value dst-entry)))
                     (is (= (bl.store:utxo-entry-height src-entry)
                            (bl.store:utxo-entry-height dst-entry)))
                     (is (equalp (bl.store:utxo-entry-script-pubkey src-entry)
                                 (bl.store:utxo-entry-script-pubkey dst-entry)))))
                 (bl.store::utxo-set-entries source))))))

(test migration-marker-detection
  "leveldb-utxo-migration-complete-p returns NIL for an empty LevelDB
(never migrated) and T after a successful migration."
  (%with-tmp-leveldb-path (ldb-path)
    ;; Empty LevelDB — marker absent.
    (bl.store:with-leveldb (db ldb-path) db)
    (is (null (bl.store:leveldb-utxo-migration-complete-p ldb-path)))
    ;; Migrate an empty set; marker should now be present.
    (let ((dat-path (%tmp-dat-path)))
      (unwind-protect
           (progn
             (bl.store:save-utxo-set
              (bl.store:make-utxo-set) dat-path)
             (bl.store:migrate-utxoset-dat-to-leveldb dat-path ldb-path)
             (is (eq t (bl.store:leveldb-utxo-migration-complete-p
                        ldb-path))))
        (ignore-errors (delete-file dat-path))))))

(test migration-missing-source-signals
  "Migrating from a non-existent source path signals an error."
  (%with-tmp-leveldb-path (ldb-path)
    (signals error
      (bl.store:migrate-utxoset-dat-to-leveldb
       "/tmp/this-file-does-not-exist-12345.dat" ldb-path))))

(test migration-larger-set
  "Migration handles a multi-batch set (batch-size smaller than total)."
  (%with-tmp-dat-and-leveldb (dat-path ldb-path)
    (let ((source (%populated-utxo-set 250)))
      (bl.store:save-utxo-set source dat-path)
      ;; Force several batches by using a small batch-size.
      (let ((written (bl.store:migrate-utxoset-dat-to-leveldb
                      dat-path ldb-path :batch-size 32)))
        (is (= 250 written))))
    (is (eq t (bl.store:leveldb-utxo-migration-complete-p ldb-path)))))

;;;; LevelDB iterator tests

(test leveldb-iterator-seek-to-first-walks-in-order
  "After put of three keys in arbitrary order, seek-to-first + repeated
next visits them in lexicographic order."
  (%with-tmp-leveldb (db)
    (let ((k1 (make-array 2 :element-type '(unsigned-byte 8) :initial-contents #(1 1)))
          (k2 (make-array 2 :element-type '(unsigned-byte 8) :initial-contents #(1 2)))
          (k3 (make-array 2 :element-type '(unsigned-byte 8) :initial-contents #(1 3)))
          (v  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 9)))
      ;; Insert out of order; LevelDB sorts internally.
      (bl.store:leveldb-put db k3 v)
      (bl.store:leveldb-put db k1 v)
      (bl.store:leveldb-put db k2 v)
      (bl.store:with-leveldb-iterator (it db)
        (bl.store:leveldb-iter-seek-to-first it)
        (is (bl.store:leveldb-iter-valid-p it))
        (is (equalp k1 (bl.store:leveldb-iter-key it)))
        (bl.store:leveldb-iter-next it)
        (is (equalp k2 (bl.store:leveldb-iter-key it)))
        (bl.store:leveldb-iter-next it)
        (is (equalp k3 (bl.store:leveldb-iter-key it)))
        (bl.store:leveldb-iter-next it)
        (is (not (bl.store:leveldb-iter-valid-p it)))))))

(test leveldb-iterator-seek-prefix-scan
  "Seek to a prefix; iterator stops emitting once keys leave the prefix.
This is the BIP30-style scan: 'all keys starting with C+txid'."
  (%with-tmp-leveldb (db)
    (let ((ka (make-array 2 :element-type '(unsigned-byte 8) :initial-contents #(1 0)))
          (kb (make-array 2 :element-type '(unsigned-byte 8) :initial-contents #(2 0)))
          (kc (make-array 2 :element-type '(unsigned-byte 8) :initial-contents #(2 5)))
          (kd (make-array 2 :element-type '(unsigned-byte 8) :initial-contents #(3 0)))
          (v  (make-array 1 :element-type '(unsigned-byte 8) :initial-element 9))
          (prefix (make-array 1 :element-type '(unsigned-byte 8) :initial-element 2)))
      (dolist (k (list ka kb kc kd))
        (bl.store:leveldb-put db k v))
      (bl.store:with-leveldb-iterator (it db)
        (bl.store:leveldb-iter-seek it prefix)
        ;; First hit is kb (#(2 0)).
        (is (bl.store:leveldb-iter-valid-p it))
        (is (equalp kb (bl.store:leveldb-iter-key it)))
        (bl.store:leveldb-iter-next it)
        (is (equalp kc (bl.store:leveldb-iter-key it)))
        (bl.store:leveldb-iter-next it)
        ;; Next key is kd which leaves the prefix — caller is responsible
        ;; for stopping; the iterator itself remains valid.
        (is (equalp kd (bl.store:leveldb-iter-key it)))))))

(test leveldb-iterator-empty-db
  "Seek-to-first on an empty DB yields an invalid iterator immediately."
  (%with-tmp-leveldb (db)
    (bl.store:with-leveldb-iterator (it db)
      (bl.store:leveldb-iter-seek-to-first it)
      (is (not (bl.store:leveldb-iter-valid-p it))))))

(test leveldb-iterator-value-copy-out
  "Iterator key and value bytes are owned by the caller (survive next)."
  (%with-tmp-leveldb (db)
    (let ((k1 (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))
          (k2 (make-array 1 :element-type '(unsigned-byte 8) :initial-element 2))
          (v1 (make-array 3 :element-type '(unsigned-byte 8) :initial-contents #(10 11 12)))
          (v2 (make-array 3 :element-type '(unsigned-byte 8) :initial-contents #(20 21 22))))
      (bl.store:leveldb-put db k1 v1)
      (bl.store:leveldb-put db k2 v2)
      (bl.store:with-leveldb-iterator (it db)
        (bl.store:leveldb-iter-seek-to-first it)
        (let ((k-copy (bl.store:leveldb-iter-key it))
              (v-copy (bl.store:leveldb-iter-value it)))
          (bl.store:leveldb-iter-next it)
          ;; After advancing, the previously copied buffers must still
          ;; hold the original bytes — they're caller-owned.
          (is (equalp k1 k-copy))
          (is (equalp v1 v-copy)))))))

;;;; coin-view-* convenience wrapper tests
;;;;
;;;; These should behave identically to the legacy utxo-set add-/get-/
;;;; remove-utxo on a fresh cache (no base content). The cache-vs-base
;;;; semantics are exercised more thoroughly in the coins-view-cache-*
;;;; tests above; here we just verify the txid+vout dispatch path.

(defun %sample-txid (&optional (element 1))
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element element))

(defun %sample-script ()
  (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))

(test coin-view-add-get-round-trip
  (%with-tmp-cache (cache)
    (let ((txid (%sample-txid 7)))
      (bl.store:coin-view-add cache txid 0
                                          12345 (%sample-script) 99)
      (let ((got (bl.store:coin-view-get cache txid 0)))
        (is (not (null got)))
        (is (= 12345 (bl.store:utxo-entry-value got)))
        (is (= 99 (bl.store:utxo-entry-height got)))))))

(test coin-view-has-p-reflects-spend
  (%with-tmp-cache (cache)
    (let ((txid (%sample-txid 8)))
      (bl.store:coin-view-add cache txid 0
                                          1 (%sample-script) 1)
      (is (bl.store:coin-view-has-p cache txid 0))
      (let ((prev (bl.store:coin-view-spend cache txid 0)))
        (is (not (null prev)))
        (is (= 1 (bl.store:utxo-entry-value prev))))
      (is (not (bl.store:coin-view-has-p cache txid 0)))
      (is (null (bl.store:coin-view-spend cache txid 0))))))

(test coin-view-any-utxo-for-txid-p-cache-hit
  "Returns T when only the cache has unspent outputs for TXID."
  (%with-tmp-cache (cache)
    (let ((txid (%sample-txid 9)))
      (bl.store:coin-view-add cache txid 0
                                          1 (%sample-script) 1)
      (is (bl.store:coin-view-any-utxo-for-txid-p cache txid)))))

(test coin-view-any-utxo-for-txid-p-base-hit
  "Returns T when only the base has unspent outputs for TXID — iterator
discovers them through the empty cache."
  (%with-tmp-leveldb-path (path)
    (let ((txid (%sample-txid 10)))
      ;; Pre-populate the base directly.
      (bl.store:with-coins-view-db (view path)
        (bl.store:coins-view-db-put
         view (bl.store:make-utxo-key txid 0) (%sample-utxo-entry)))
      (bl.store:with-coins-view-db (view path)
        (let ((cache (bl.store:make-coins-view-cache view)))
          (is (bl.store:coin-view-any-utxo-for-txid-p cache txid))
          ;; A different txid should miss.
          (is (not (bl.store:coin-view-any-utxo-for-txid-p
                    cache (%sample-txid 11)))))))))

(test coin-view-any-utxo-for-txid-p-cache-tombstone-supersedes-base
  "Base has the coin, but the cache tombstones it — must report absent."
  (%with-tmp-leveldb-path (path)
    (let ((txid (%sample-txid 12)))
      (bl.store:with-coins-view-db (view path)
        (bl.store:coins-view-db-put
         view (bl.store:make-utxo-key txid 0) (%sample-utxo-entry)))
      (bl.store:with-coins-view-db (view path)
        (let ((cache (bl.store:make-coins-view-cache view)))
          ;; Spend pulls the coin through cache then tombstones it.
          (is (not (null (bl.store:coin-view-spend cache txid 0))))
          (is (not (bl.store:coin-view-any-utxo-for-txid-p
                    cache txid))))))))

;;;; coin-view-apply-block / coin-view-disconnect-block round-trip

(defun %make-test-block (transactions)
  "Wrap TRANSACTIONS in a bitcoin-block with a stub header."
  (bl.ser:make-bitcoin-block
   :header (bl.ser:make-block-header
            :version 1
            :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
            :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
            :timestamp 0 :bits 0 :nonce 0
            :cached-hash (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element #xBB))
   :transactions transactions))

(defun %make-coinbase-tx (txid value script)
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output
                  (bl.ser:make-outpoint
                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)
                   :index #xFFFFFFFF)
                  :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                            :initial-element 1)))
   :outputs (vector (bl.ser:make-tx-out
                   :value value :script-pubkey script))
   :lock-time 0
   :cached-hash txid))

(defun %make-spending-tx (txid prev-txid prev-index value script)
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output
                  (bl.ser:make-outpoint
                   :hash prev-txid :index prev-index)
                  :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                            :initial-element 2)))
   :outputs (vector (bl.ser:make-tx-out
                   :value value :script-pubkey script))
   :lock-time 0
   :cached-hash txid))

(test coin-view-apply-block-then-disconnect-restores-state
  "coin-view-apply-block + coin-view-disconnect-block round-trip leaves
the cache equivalent to its pre-apply state."
  (%with-tmp-cache (cache)
    (let* ((script (%sample-script))
           (prev-txid (%sample-txid #xDD))
           (cb-txid (%sample-txid #x01))
           (spend-txid (%sample-txid #x02)))
      ;; Seed: one pre-existing UTXO which the block will spend.
      (bl.store:coin-view-add cache prev-txid 0
                                          9000000 script 5)
      (let* ((block (%make-test-block
                     (list (%make-coinbase-tx cb-txid 500000000 script)
                           (%make-spending-tx spend-txid prev-txid 0
                                              8000000 script))))
             (spent (bl.store:coin-view-apply-block cache block 10)))
        ;; Undo data captured the spent UTXO.
        (is (= 1 (length spent)))
        (is (equalp prev-txid (first (first spent))))
        (is (= 0 (second (first spent))))
        (is (= 9000000 (bl.store:utxo-entry-value
                        (third (first spent)))))
        ;; After apply: coinbase output + spending output present,
        ;; prev-txid:0 absent.
        (is (bl.store:coin-view-has-p cache cb-txid 0))
        (is (bl.store:coin-view-has-p cache spend-txid 0))
        (is (not (bl.store:coin-view-has-p cache prev-txid 0)))
        ;; Disconnect: undoes the block.
        (bl.store:coin-view-disconnect-block cache block spent)
        (is (not (bl.store:coin-view-has-p cache cb-txid 0)))
        (is (not (bl.store:coin-view-has-p cache spend-txid 0)))
        (let ((restored (bl.store:coin-view-get cache prev-txid 0)))
          (is (not (null restored)))
          (is (= 9000000 (bl.store:utxo-entry-value restored)))
          (is (= 5 (bl.store:utxo-entry-height restored))))))))

(test coin-view-apply-block-coinbase-only
  "A block with just a coinbase produces no undo data."
  (%with-tmp-cache (cache)
    (let* ((script (%sample-script))
           (cb-txid (%sample-txid #x03))
           (block (%make-test-block
                   (list (%make-coinbase-tx cb-txid 500000000 script)))))
      (let ((spent (bl.store:coin-view-apply-block cache block 1)))
        (is (null spent))
        (is (bl.store:coin-view-has-p cache cb-txid 0))))))

(test coin-view-disconnect-intra-block-dep-leaves-clean-state
  "Regression: a block with intra-block tx dependencies (tx N spends
output created by tx M in the same block) must disconnect cleanly —
no stale UTXOs left in cache.

This is the bug observed live on test-bitcoin-server 2026-05-19 at
h=135597: the old forward-order disconnect (remove all outputs THEN
restore inputs) left an intra-block-spent output incorrectly restored
in the cache. Re-applying the block (e.g., same tx in a competing
fork) then refused with 'overwrite unspent coin'. Bitcoin Core's
DisconnectBlock processes txs in reverse order with per-tx (remove
outputs THEN restore inputs); our flat-undo-data equivalent restores
ALL inputs first then walks forward removing outputs, achieving the
same final cache state."
  (%with-tmp-cache (cache)
    (let* ((script (%sample-script))
           (cb-txid (%sample-txid #x77))
           (intra-txid (%sample-txid #x78))
           ;; tx M (the coinbase) creates output cb-txid:0 (value=5e9).
           (coinbase (%make-coinbase-tx cb-txid 5000000000 script))
           ;; tx N spends coinbase output, creates intra-txid:0
           ;; (this is the intra-block dependency).
           (spending (%make-spending-tx intra-txid cb-txid 0 4000000000 script))
           (block (%make-test-block (list coinbase spending))))
      ;; Apply: cb-txid:0 is created then immediately spent in the same
      ;; block. intra-txid:0 is created.
      (let ((spent (bl.store:coin-view-apply-block cache block 100)))
        (is (= 1 (length spent)))
        ;; After apply: cb-txid:0 is gone (spent intra-block).
        ;; intra-txid:0 is unspent.
        (is (not (bl.store:coin-view-has-p cache cb-txid 0)))
        (is (bl.store:coin-view-has-p cache intra-txid 0))
        ;; Now disconnect. After the fix, the cache must be empty
        ;; (no stale unspent entries).
        (bl.store:coin-view-disconnect-block cache block spent)
        (is (not (bl.store:coin-view-has-p cache cb-txid 0)))
        (is (not (bl.store:coin-view-has-p cache intra-txid 0)))
        ;; Critical: re-applying the same block must succeed. With the
        ;; old buggy order, cb-txid:0 was left in the cache as
        ;; unspent, so this would raise "refusing to overwrite unspent
        ;; coin" via the bip30 guard on coins-view-cache-add.
        (let ((spent2 (bl.store:coin-view-apply-block cache block 100)))
          (is (= 1 (length spent2))))))))

;;;; Polymorphic-dispatch parity tests
;;;;
;;;; The legacy add-utxo / get-utxo / remove-utxo / apply-block-to-utxo-set
;;;; / disconnect-block-from-utxo-set / any-utxo-for-txid-p functions
;;;; now dispatch on view type. Production passes a coins-view-cache;
;;;; many tests still pass utxo-set. These tests confirm that both
;;;; types reach the same observable end-state for the same operations.

(test polymorphic-add-get-utxo-set-and-cache-parity
  "add-utxo + get-utxo behave the same on utxo-set and coins-view-cache."
  (%with-tmp-cache (cache)
    (let ((set (bl.store:make-utxo-set))
          (txid (%sample-txid 42))
          (script (%sample-script)))
      ;; Same operation on both views.
      (bl.store:add-utxo set   txid 0 12345 script 99)
      (bl.store:add-utxo cache txid 0 12345 script 99)
      ;; Same observable result.
      (let ((from-set   (bl.store:get-utxo set   txid 0))
            (from-cache (bl.store:get-utxo cache txid 0)))
        (is (not (null from-set)))
        (is (not (null from-cache)))
        (is (= 12345 (bl.store:utxo-entry-value from-set)))
        (is (= 12345 (bl.store:utxo-entry-value from-cache)))))))

(test polymorphic-apply-block-utxo-set-and-cache-parity
  "apply-block-to-utxo-set / disconnect-block-from-utxo-set produce the
same undo data shape and end-state on utxo-set vs coins-view-cache."
  (%with-tmp-cache (cache)
    (let* ((set (bl.store:make-utxo-set))
           (script (%sample-script))
           (prev-txid (%sample-txid #xDD))
           (cb-txid (%sample-txid #x01))
           (spend-txid (%sample-txid #x02))
           (block (%make-test-block
                   (list (%make-coinbase-tx cb-txid 500000000 script)
                         (%make-spending-tx spend-txid prev-txid 0
                                            8000000 script)))))
      ;; Seed both views with the same prev UTXO.
      (bl.store:add-utxo set   prev-txid 0 9000000 script 5)
      (bl.store:add-utxo cache prev-txid 0 9000000 script 5)
      (let ((spent-set   (bl.store:apply-block-to-utxo-set set   block 10))
            (spent-cache (bl.store:apply-block-to-utxo-set cache block 10)))
        (is (= 1 (length spent-set)))
        (is (= 1 (length spent-cache)))
        ;; Undo data shape is identical (txid index entry).
        (is (equalp (first (first spent-set)) (first (first spent-cache))))
        (is (= (second (first spent-set)) (second (first spent-cache))))
        ;; End-state: outputs present, prev absent.
        (is (bl.store:utxo-exists-p set   cb-txid 0))
        (is (bl.store:utxo-exists-p cache cb-txid 0))
        (is (not (bl.store:utxo-exists-p set   prev-txid 0)))
        (is (not (bl.store:utxo-exists-p cache prev-txid 0)))
        ;; Round-trip back via disconnect.
        (bl.store:disconnect-block-from-utxo-set set   block spent-set)
        (bl.store:disconnect-block-from-utxo-set cache block spent-cache)
        (is (bl.store:utxo-exists-p set   prev-txid 0))
        (is (bl.store:utxo-exists-p cache prev-txid 0))))))

(test polymorphic-any-utxo-for-txid-p-parity
  (%with-tmp-cache (cache)
    (let ((set (bl.store:make-utxo-set))
          (txid (%sample-txid 7))
          (other (%sample-txid 8))
          (script (%sample-script)))
      (bl.store:add-utxo set   txid 0 1 script 1)
      (bl.store:add-utxo cache txid 0 1 script 1)
      (is (bl.store:any-utxo-for-txid-p set   txid))
      (is (bl.store:any-utxo-for-txid-p cache txid))
      (is (not (bl.store:any-utxo-for-txid-p set   other)))
      (is (not (bl.store:any-utxo-for-txid-p cache other))))))

;;;; Polymorphic iteration + statistics
;;;;
;;;; utxo-set-iterate / utxo-set-total-amount / utxo-set-distinct-txids /
;;;; compute-utxo-set-hash now dispatch on view type. For
;;;; coins-view-cache, they flush first then walk the LevelDB base via
;;;; iterator. These tests confirm parity with the utxo-set branch.

(defun %seed-three-coins (view)
  "Populate VIEW with three coins: (txidA, 0), (txidA, 1), (txidB, 0).
Returns the txids and the value+script used so a caller can assert on
the totals."
  (let ((txid-a (%sample-txid #xAA))
        (txid-b (%sample-txid #xBB))
        (script (%sample-script)))
    (bl.store:add-utxo view txid-a 0 100 script 1)
    (bl.store:add-utxo view txid-a 1 200 script 1)
    (bl.store:add-utxo view txid-b 0 300 script 1)
    (values txid-a txid-b script)))

(test polymorphic-utxo-set-iterate-parity
  "utxo-set-iterate emits the same (txid, vout, entry) sequence on
both views for the same seed data."
  (%with-tmp-cache (cache)
    (let ((set (bl.store:make-utxo-set))
          (set-emits '())
          (cache-emits '()))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (bl.store:utxo-set-iterate
       set
       (lambda (txid vout entry)
         (push (list (copy-seq txid) vout (bl.store:utxo-entry-value entry))
               set-emits)))
      (bl.store:utxo-set-iterate
       cache
       (lambda (txid vout entry)
         (push (list (copy-seq txid) vout (bl.store:utxo-entry-value entry))
               cache-emits)))
      (is (= 3 (length set-emits)))
      (is (= 3 (length cache-emits)))
      (is (equalp (nreverse set-emits) (nreverse cache-emits))))))

(test polymorphic-utxo-set-total-amount-parity
  (%with-tmp-cache (cache)
    (let ((set (bl.store:make-utxo-set)))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (is (= 600 (bl.store:utxo-set-total-amount set)))
      (is (= 600 (bl.store:utxo-set-total-amount cache))))))

(test polymorphic-utxo-set-distinct-txids-parity
  "Two outputs of txid-a + one of txid-b = 2 distinct txids."
  (%with-tmp-cache (cache)
    (let ((set (bl.store:make-utxo-set)))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (is (= 2 (bl.store:utxo-set-distinct-txids set)))
      (is (= 2 (bl.store:utxo-set-distinct-txids cache))))))

(test polymorphic-compute-utxo-set-hash-parity
  "The hash_serialized_3 digest is byte-identical across views."
  (%with-tmp-cache (cache)
    (let ((set (bl.store:make-utxo-set)))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (is (equalp (bl.store:compute-utxo-set-hash set)
                  (bl.store:compute-utxo-set-hash cache))))))

(test polymorphic-iterate-cache-syncs-without-clearing
  "Iterating a coins-view-cache SYNCS it — the dirty entries are written to the
base, and the entries themselves are RETAINED.

This asserted the opposite (cvc-entries empty afterwards), and that clearing is
the bug. Iteration runs from RPC threads (gettxoutsetinfo, dumptxoutset) while
the validation thread mutates the same table under the node lock: MAPHASH
followed by CLRHASH could drop an entry inserted mid-walk WITHOUT writing it,
and a lost tombstone leaves a spent coin alive in LevelDB — a double-spend Core
rejects. Keeping the entries means a missed one is not discarded unwritten. It
also stops a read-only RPC discarding the warm cache mid-IBD. Core's equivalent
is Sync (write dirty, keep) rather than Flush (rpc/blockchain.cpp:1075-1084
uses ForceFlushStateToDisk with wipe_cache=false)."
  (%with-tmp-cache (cache)
    (%seed-three-coins cache)
    ;; %seed-three-coins goes through ADD-UTXO, which permits an overwrite and
    ;; is therefore never FRESH; one direct add puts a FRESH entry in the walk.
    (bl.store:coin-view-add cache (%sample-txid #xCC) 0 400 (%sample-script) 1
                            :allow-overwrite nil)
    (is (= 4 (hash-table-count
              (coins-cache-entries cache))))
    (is (= 1 (coins-cache-fresh-count cache)))
    (bl.store:utxo-set-iterate
     cache (lambda (txid vout entry)
             (declare (ignore txid vout entry))))
    (is (= 4 (hash-table-count (coins-cache-entries cache)))
        "entries are retained, not cleared")
    (is (zerop (coins-cache-dirty-count cache))
        "but they are no longer dirty — the sync committed them")
    ;; BOTH flags clear, not just DIRTY: Core's SetClean is `m_flags = 0'
    ;; (coins.h:173-181). A surviving FRESH says the base has no such coin,
    ;; which the sync just made false — see the double-spend test below.
    (is (zerop (coins-cache-fresh-count cache))
        "and no longer FRESH — the sync put them in the base")
    (maphash (lambda (key ce)
               (declare (ignore key))
               (is-false (coins-cache-entry-fresh-p ce))
               (is-false (coins-cache-entry-dirty-p ce)))
             (coins-cache-entries cache))))

(test coins-view-cache-sync-clears-fresh-so-the-next-spend-cannot-repeat
  "A coin added the way block application adds one, then SYNCED, must not stay
FRESH — or the outpoint can be spent TWICE.

FRESH means `the base view does not have this coin' (Core coins.h:150-159), so
COINS-VIEW-CACHE-SPEND drops a FRESH entry outright instead of staging an
erase. COINS-VIEW-CACHE-SYNC writes the coin to LevelDB, which makes FRESH a
lie; Core clears it in the same walk (CoinsViewCacheCursor::NextAndMaybeErase,
coins.h:279-295). While it survived, the spend removed the cache entry and
staged nothing, the next read pulled the still-unspent coin back out of
LevelDB, and a SECOND spend of the same outpoint was accepted — a consensus
split plus UTXO inflation, reachable from gettxoutsetinfo, dumptxoutset,
scantxoutset and the assumeutxo hash check, all of which sync the live
chainstate coins view."
  (%with-tmp-cache (cache)
    (let* ((base (bl.store:coins-view-cache-base cache))
           (txid (%sample-txid #xC0))
           (key (bl.store:make-utxo-key txid 0)))
      ;; COIN-VIEW-APPLY-BLOCK adds every non-coinbase output exactly so.
      (bl.store:coin-view-add cache txid 0 5000 (%sample-script) 101
                              :coinbase nil :allow-overwrite nil)
      (is-true (coins-cache-entry-fresh-p (gethash key (coins-cache-entries cache)))
               "the add is FRESH before the sync")
      (bl.store:utxo-set-iterate cache (lambda (a b c) (declare (ignore a b c))))
      (is-true (bl.store:coins-view-db-get base key)
               "the sync wrote the coin to the base")
      (let ((ce (gethash key (coins-cache-entries cache))))
        (is-false (coins-cache-entry-fresh-p ce) "and cleared FRESH")
        (is-false (coins-cache-entry-dirty-p ce)))
      (is (zerop (coins-cache-fresh-count cache)))
      ;; The spend must leave a tombstone that stages the base erase, not
      ;; silently drop the entry.
      (is (eq t (bl.store:coins-view-cache-spend cache key)))
      (is-true (nth-value 1 (gethash key (coins-cache-entries cache)))
               "the spend leaves a tombstone")
      (is (= 1 (coins-cache-dirty-count cache)))
      (is-false (bl.store:coins-view-cache-has-p cache key))
      (is-false (bl.store:coins-view-cache-spend cache key)
                "a second spend of the same outpoint must be refused")
      (bl.store:coins-view-cache-flush cache)
      (is-false (bl.store:coins-view-db-get base key)
                "and the flushed erase removed it from the base"))))

(test coins-view-cache-sync-drops-spent-tombstones
  "A spent entry does not survive the sync: its erase is in the batch, so
keeping it would only hold memory and leave a flagged entry behind. Core erases
it from the map in the same walk and asserts the coin is already empty
(coins.h:279-295)."
  (%with-tmp-cache (cache)
    (let* ((base (bl.store:coins-view-cache-base cache))
           (txid (%sample-txid #xD0))
           (key (bl.store:make-utxo-key txid 0)))
      ;; Flush first, so the spend below sees a NON-fresh coin and tombstones it.
      (bl.store:coin-view-add cache txid 0 7000 (%sample-script) 202
                              :coinbase nil :allow-overwrite nil)
      (bl.store:coins-view-cache-flush cache)
      (is (eq t (bl.store:coins-view-cache-spend cache key)))
      (is (= 1 (hash-table-count (coins-cache-entries cache))))
      (bl.store:utxo-set-iterate cache (lambda (a b c) (declare (ignore a b c))))
      (is (zerop (hash-table-count (coins-cache-entries cache)))
          "the tombstone is gone from the table")
      (is (zerop (coins-cache-dirty-count cache)))
      (is (zerop (coins-cache-fresh-count cache)))
      (is (zerop (bl.store:view-mem-bytes cache))
          "and its slot overhead was returned to the memory estimate")
      (is-false (bl.store:coins-view-db-get base key)
                "the sync committed the erase"))))

(test coins-view-cache-sync-signals-when-the-flag-counts-drift
  "The sync's post-condition — Core's Sync throws `Not all unspent flagged
entries were cleared' (coins.cpp:291-300). Our walk decrements the two
counters entry by entry, so a leftover means the counts the mutators maintain
disagree with the flags in the table.

The first sync here is the positive control's counterpart: it must return
normally, so the drifted count and not the check itself is what fails."
  (%with-tmp-cache (cache)
    (%seed-three-coins cache)
    (is (= 3 (bl.store:coins-view-cache-sync cache)))
    ;; Drop a FRESH entry behind the cache's back, so the counters now claim
    ;; flags the table no longer holds.
    (let ((txid (%sample-txid #xE0)))
      (bl.store:coin-view-add cache txid 0 11 (%sample-script) 3
                              :allow-overwrite nil)
      (is (= 1 (coins-cache-fresh-count cache)))
      (remhash (bl.store:make-utxo-key txid 0) (coins-cache-entries cache))
      (signals bl.err:internal-error (bl.store:coins-view-cache-sync cache)))))

(test polymorphic-iterate-cache-merges-flushed-base-and-recent-adds
  "After a partial flush, the next iterate still sees everything —
because iterate itself flushes again before walking the base."
  (%with-tmp-cache (cache)
    ;; First batch — flush manually.
    (bl.store:add-utxo cache (%sample-txid 1) 0 10 (%sample-script) 1)
    (bl.store:coins-view-cache-flush cache)
    ;; Second batch — leave dirty.
    (bl.store:add-utxo cache (%sample-txid 2) 0 20 (%sample-script) 2)
    (is (= 30 (bl.store:utxo-set-total-amount cache)))))

;;;; Coins-cache memory accounting (Bitcoin Core dbcache byte bound)

(defun %overhead () bl.store::+coins-cache-entry-overhead-bytes+)

(test coins-cache-mem-bytes-fresh-zero
  "A fresh cache reports 0 bytes; an empty utxo-set view also reports 0."
  (%with-tmp-cache (cache)
    (is (= 0 (bl.store:view-mem-bytes cache))))
  (is (= 0 (bl.store:view-mem-bytes (bl.store:make-utxo-set)))))

(test coins-cache-mem-bytes-add-rises
  "Each add raises usage by overhead + scriptPubKey length."
  (%with-tmp-cache (cache)
    (bl.store:coins-view-cache-add cache (%sample-utxo-key 1 0)
                                               (%sample-utxo-entry))     ; 25-byte script
    (is (= (+ (%overhead) 25) (bl.store:view-mem-bytes cache)))
    (bl.store:coins-view-cache-add cache (%sample-utxo-key 2 0)
                                               (%sample-utxo-entry))
    (is (= (* 2 (+ (%overhead) 25)) (bl.store:view-mem-bytes cache)))))

(test coins-cache-mem-bytes-spend-fresh-drops
  "Spending a fresh (in-cache-only) coin reclaims its full bytes."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 5 0)))
      (bl.store:coins-view-cache-add cache k (%sample-utxo-entry))
      (is (= (+ (%overhead) 25) (bl.store:view-mem-bytes cache)))
      (bl.store:coins-view-cache-spend cache k)
      (is (= 0 (bl.store:view-mem-bytes cache))))))

(test coins-cache-mem-bytes-reuse-delta
  "Overwriting an entry adjusts usage by the script-size delta, not double-count."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 6 0))
          (small (bl.store:make-utxo-entry
                  :value 1 :height 1 :coinbase nil
                  :script-pubkey (make-array 10 :element-type '(unsigned-byte 8)))))
      (bl.store:coins-view-cache-add cache k (%sample-utxo-entry)) ; 25
      (bl.store:coins-view-cache-add cache k small :allow-overwrite t) ; 10
      (is (= (+ (%overhead) 10) (bl.store:view-mem-bytes cache))))))

(test coins-cache-mem-bytes-non-fresh-spend-keeps-overhead
  "A non-fresh spend frees the script bytes but the tombstone keeps the overhead."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 7 0)))
      (bl.store:with-coins-view-db (base path)
        (bl.store:coins-view-db-put base k (%sample-utxo-entry)))
      (bl.store:with-coins-view-db (base path)
        (let ((cache (bl.store:make-coins-view-cache base)))
          ;; A read pulls the base coin into the cache (non-fresh).
          (bl.store:coins-view-cache-get cache k)
          (is (= (+ (%overhead) 25) (bl.store:view-mem-bytes cache)))
          (bl.store:coins-view-cache-spend cache k)
          (is (= (%overhead) (bl.store:view-mem-bytes cache))))))))

(test coins-cache-mem-bytes-flush-resets
  "Flush clears the cache and resets usage to 0."
  (%with-tmp-cache (cache)
    (dotimes (i 5)
      (bl.store:coins-view-cache-add cache (%sample-utxo-key (1+ i) 0)
                                                 (%sample-utxo-entry)))
    (is (= (* 5 (+ (%overhead) 25)) (bl.store:view-mem-bytes cache)))
    (bl.store:coins-view-cache-flush cache)
    (is (= 0 (bl.store:view-mem-bytes cache)))))

(test large-coins-cache-threshold-matches-core
  "large-coins-cache-threshold = max(0.9*budget, budget-10MiB) (Core)."
  (let ((mib (* 1024 1024)))
    ;; 450 MiB budget: budget-10MiB (440) > 0.9*budget (405) -> 440 MiB.
    (is (= (* 440 mib) (bl::large-coins-cache-threshold (* 450 mib))))
    ;; 100 MiB budget: both terms equal 90 MiB.
    (is (= (* 90 mib) (bl::large-coins-cache-threshold (* 100 mib))))))

(test header-index-v1-file-still-loads
  "A v1-format header index (181-byte entries, no tx-count) still loads after
the v2 format bump; its entries get tx-count 0 for lazy backfill. A v1-load
regression would silently force a from-genesis resync on deploy."
  (let* ((tmp-dir (merge-pathnames "test-hidx-v1/" (uiop:temporary-directory)))
         (cs (bl.store:make-chain-state :base-path tmp-dir))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 1)
                  :timestamp 1231006505 :bits #x1d00ffff :nonce 0))
         (hash (bl.ser:block-header-hash header)))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (progn
           ;; Hand-assemble: magic + version 1 + count 1 + one v1 entry + CRC32.
           (let* ((data (flexi-streams:with-output-to-sequence (s)
                          (write-sequence
                           (map '(vector (unsigned-byte 8)) #'char-code "HIDX") s)
                          (bl.ser:write-uint32-le s 1) ; version
                          (bl.ser:write-uint32-le s 1) ; count
                          (write-sequence hash s)
                          (bl.ser:write-uint32-le s 7) ; height
                          (write-sequence
                           (bl.ser:serialize-block-header header) s)
                          (let ((cw (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))
                            (setf (aref cw 31) 42)                  ; chainwork 42 (BE)
                            (write-sequence cw s))
                          (write-byte 2 s)                          ; status :valid
                          (write-sequence (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0) s)))
                  (bytes (coerce data '(simple-array (unsigned-byte 8) (*)))))
             ;; The resolved path is Core's blocks/index/ on a fresh datadir,
             ;; whose directory does not exist yet.
             (ensure-directories-exist
              (bl.store::header-index-file-path cs))
             (with-open-file (out (bl.store::header-index-file-path cs)
                                  :direction :output :if-exists :supersede
                                  :element-type '(unsigned-byte 8))
               (write-sequence bytes out)
               (write-sequence (bl.store:compute-crc32 bytes) out)))
           (is-true (bl.store:load-header-index cs))
           (let ((entry (bl.store:get-block-index-entry cs hash)))
             (is (not (null entry)))
             (is (= 7 (bl.store:block-index-entry-height entry)))
             (is (= 42 (bl.store:block-index-entry-chain-work entry)))
             (is (= 0 (bl.store:block-index-entry-tx-count entry)))))
      (uiop:delete-directory-tree tmp-dir :validate t :if-does-not-exist :ignore))))

(test compute-utxo-set-hash-streams-instead-of-buffering
  "hash_serialized_3 must be computed incrementally. Buffering the whole set
and hashing it at the end needs memory proportional to the UTXO set: measured
at ~1.1 GB on testnet4's 14.2M coins, which killed a live node — the final
buffer doubling asked for 1,156,098,560 bytes with 632 MB left in a 6 GB heap
and the fail-fast debugger hook turned that into process exit. Mainnet's set is
an order of magnitude larger.

This pins the streamed digest against the buffer-then-hash construction it
replaced, so the consensus-visible value cannot drift while the memory profile
changes. The final control must FAIL to prove the comparison has teeth."
  (flet ((buffered (elements)
           ;; the original construction, kept here only as the oracle
           (let ((buf (bl.ser:make-byte-buf)))
             (dolist (e elements)
               (bl.ser:bb-write-bytes buf e))
             (bl.crypto:hash256
              (bl.ser:bb-finish buf))))
         (streamed (elements)
           (let ((digest (ironclad:make-digest :sha256)))
             (dolist (e elements) (ironclad:update-digest digest e))
             (bl.crypto:sha256 (ironclad:produce-digest digest)))))
    (let ((state (sb-ext:seed-random-state 20260816)))
      ;; empty set
      (is (equalp (buffered nil) (streamed nil)))
      ;; randomized multi-element sets, including sizes that straddle the
      ;; digest's internal 64-byte block boundary
      (dotimes (trial 25)
        (let ((elements (loop repeat (1+ (random 20 state))
                              collect (let* ((n (1+ (random 130 state)))
                                             (v (make-array n :element-type '(unsigned-byte 8))))
                                        (dotimes (i n)
                                          (setf (aref v i) (random 256 state)))
                                        v))))
          (is (equalp (buffered elements) (streamed elements)))))
      ;; control: the comparison must be able to fail
      (let ((a (list (make-array 3 :element-type '(unsigned-byte 8) :initial-element 1)))
            (b (list (make-array 3 :element-type '(unsigned-byte 8) :initial-element 2))))
        (is (not (equalp (streamed a) (streamed b)))
            "different coin sets must hash differently")))))

(test utxo-set-distinct-txids-counts-groups-without-collecting
  "Counting distinct txids must not hold every txid in memory — that was the
second unbounded accumulator on the gettxoutsetinfo path. Transition counting
is exact only because UTXO-SET-ITERATE delivers coins grouped per txid, so this
pins the count against a set-based oracle on data that would expose a grouping
assumption if it were wrong: multiple vouts per txid, vouts above 255 (where
LE-u32 key order diverges from numeric), and interleaved insertion order."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txids (loop for i below 8
                     collect (let ((v (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)))
                               (setf (aref v 0) i)
                               ;; vary a later byte too so lex order is not just index order
                               (setf (aref v 31) (- 255 i))
                               v))))
    ;; Insert in an order deliberately unlike the iteration order.
    (dolist (vout '(300 1 0 256 2))
      (dolist (txid (reverse txids))
        (bl.store:add-utxo
         utxo-set txid vout (+ 1000 vout)
         (make-array 1 :element-type '(unsigned-byte 8)) 1)))
    (let ((oracle (let ((seen (make-hash-table :test 'equalp)))
                    (bl.store:utxo-set-iterate
                     utxo-set (lambda (txid vout entry)
                                (declare (ignore vout entry))
                                (setf (gethash txid seen) t)))
                    (hash-table-count seen))))
      (is (= (length txids) oracle) "the oracle sees every txid")
      (is (= oracle (bl.store:utxo-set-distinct-txids utxo-set))
          "transition counting agrees with collecting")
      ;; control: the assertion must be able to fail
      (is (/= (1+ oracle) (bl.store:utxo-set-distinct-txids utxo-set))))))

(test load-state-distinguishes-corruption-from-absence
  "A present-but-unreadable chainstate.dat must NOT look like a first run.
Both returned NIL before, and the caller acted on NIL by silently starting from
genesis — replaying blocks whose coins are already in the UTXO set, which on
mainnet trips the BIP30 duplicate-txid check and leaves the node with no
best-valid-tip at all. The legacy pre-CRC format has no integrity check, so it
can only be trusted by exact size; any other size is corruption, not an older
version."
  (let* ((dir (merge-pathnames (format nil "bl-loadstate-~D/" (random 1000000))
                               #P"/tmp/"))
         (state (bl.store:make-chain-state :base-path dir))
         (path (bl.store:state-file-path state)))
    (ensure-directories-exist dir)
    (unwind-protect
         (flet ((write-bytes (n)
                  (with-open-file (s path :direction :output
                                          :element-type '(unsigned-byte 8)
                                          :if-exists :supersede
                                          :if-does-not-exist :create)
                    (dotimes (i n) (write-byte (mod i 256) s)))))
           ;; Control: absence is a legitimate first run, and must stay NIL.
           (when (probe-file path) (delete-file path))
           (is (null (bl.store:load-state state))
               "no file at all is a first run, not corruption")
           ;; A size no version recognizes: corruption.
           (write-bytes 41)
           (is (eq :corrupt (bl.store:load-state state))
               "a 41-byte file matches no format and must report corruption")
           (write-bytes 7)
           (is (eq :corrupt (bl.store:load-state state)))
           ;; A v3-sized file whose CRC cannot verify: corruption, not absence.
           (write-bytes 45)
           (is (eq :corrupt (bl.store:load-state state))
               "a v3-sized file with a bad CRC must report corruption")
           ;; Control: a legitimately-sized legacy file still loads, so the
           ;; check above rejects by integrity rather than rejecting everything.
           (write-bytes 40)
           (is (eq t (bl.store:load-state state))
               "a valid legacy-format file still loads"))
      (when (probe-file path) (ignore-errors (delete-file path)))
      (ignore-errors (uiop:delete-empty-directory dir)))))

(test coins-db-records-its-own-best-block-in-the-flush-batch
  "The coins DB must carry the block hash its UTXO state belongs to, written in
the SAME batch as the coin changes. Keeping that fact only in chainstate.dat
lets two independent records disagree, which is what turns an interrupted reorg
or a bad sector into a bricked chain index. Core keeps the pointer inside the
coins DB for exactly this reason (CCoinsViewDB::BatchWrite, txdb.cpp:100-159);
see docs/coins-db-best-block-plan.md."
  (let ((db-path (ensure-directories-exist
                  (merge-pathnames (format nil "bl-bestblock-~D/" (random 1000000))
                                   (uiop:temporary-directory)))))
    (let* ((base (bl.store:open-coins-view-db db-path))
           (cache (bl.store:make-coins-view-cache base))
           (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
      (unwind-protect
           (progn
             ;; Control: nothing recorded before the first flush that supplies it.
             (is (null (bl.store:coins-view-db-best-block base))
                 "a fresh coins DB has no best-block pointer")
             (bl.store:coin-view-add
              cache txid 0 5000 (make-array 1 :element-type '(unsigned-byte 8)) 1)
             ;; A flush WITHOUT a tip must not invent one.
             (bl.store:coins-view-cache-flush cache)
             (is (null (bl.store:coins-view-db-best-block base))
                 "a flush that does not know its tip leaves the pointer alone")
             ;; A flush WITH a tip records it alongside the coins.
             (bl.store:coin-view-add
              cache txid 1 6000 (make-array 1 :element-type '(unsigned-byte 8)) 1)
             (bl.store:coins-view-cache-flush cache :best-block tip)
             (is (equalp tip (bl.store:coins-view-db-best-block base))
                 "the tip is durable in the coins DB")
             ;; and the coins from that same batch are there too — the point is
             ;; that they commit together, so both halves must be observable.
             (is (not (null (bl.store:coin-view-get cache txid 1)))
                 "the coins written in that batch are present")
             ;; control: a different hash must not compare equal
             (is (not (equalp (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 3)
                              (bl.store:coins-view-db-best-block base)))))
        (bl.store:close-coins-view-db base)))))

(test utxo-iteration-survives-metadata-keys-that-sort-before-coins
  "The coin scan must be independent of where other key prefixes sort.

It used to seek to the first key and stop at the first non-'C' key, which is
only a correct scan while every other prefix sorts AFTER 'C'. Adding the
best-block key ('B', matching Core's DB_BEST_BLOCK) put a key BEFORE the coins,
so the scan terminated immediately and the entire UTXO set iterated as EMPTY —
silently. Nothing signalled: the set hash became the hash of no coins, the
total amount became zero, and assumeutxo validation failed with a hash mismatch
rather than anything naming the real cause.

The control is the point of this test: iterating must yield the same coins with
the metadata key present as without it."
  (let ((db-path (ensure-directories-exist
                  (merge-pathnames (format nil "bl-iterprefix-~D/" (random 1000000))
                                   (uiop:temporary-directory)))))
    (let* ((base (bl.store:open-coins-view-db db-path))
           (cache (bl.store:make-coins-view-cache base))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
           (script (make-array 1 :element-type '(unsigned-byte 8))))
      (unwind-protect
           (flet ((count-coins ()
                    (let ((n 0))
                      (bl.store:utxo-set-iterate
                       cache (lambda (txid vout entry)
                               (declare (ignore txid vout entry))
                               (incf n)))
                      n)))
             (dotimes (i 5)
               (let ((txid (make-array 32 :element-type '(unsigned-byte 8)
                                          :initial-element (+ 10 i))))
                 (bl.store:coin-view-add cache txid 0 (* 1000 (1+ i)) script 1)))
             ;; Baseline: no metadata key yet.
             (bl.store:coins-view-cache-flush cache)
             (let ((without-metadata (count-coins)))
               (is (= 5 without-metadata) "all coins iterate before any metadata key exists")
               ;; Now write a key that sorts BEFORE the coin prefix.
               (bl.store:coins-view-cache-flush cache :best-block tip)
               (is (equalp tip (bl.store:coins-view-db-best-block base))
                   "the metadata key really is present")
               (is (= without-metadata (count-coins))
                   "a key sorting before the coins must not truncate the scan")
               (is (plusp (bl.store:utxo-set-total-amount cache))
                   "and derived totals stay non-zero")))
        (bl.store:close-coins-view-db base)))))

(test coins-cache-best-block-moves-with-the-blocks-not-the-chain-tip
  "The coins view must track which block its state corresponds to and move that
pointer WITH the coins — Core does it inside ConnectBlock and DisconnectBlock
(validation.cpp:2651, :2242).

This is what makes the stored pointer honest. Reading the chain's tip at flush
time instead would stamp the wrong hash for the whole of a reorg's disconnect
phase, where the tip still names the block being rewound away from while these
coins have already moved back — and the startup consistency check would then
compare two copies of the same wrong answer and report agreement."
  (let ((db-path (ensure-directories-exist
                  (merge-pathnames (format nil "bl-bbtrack-~D/" (random 1000000))
                                   (uiop:temporary-directory)))))
    (let* ((base (bl.store:open-coins-view-db db-path))
           (cache (bl.store:make-coins-view-cache base))
           (parent (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
           (this-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
           (coinbase (bl.tests::%make-coinbase-tx
                      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                      5000
                      (make-array 1 :element-type '(unsigned-byte 8))))
           (block (bl.ser:make-bitcoin-block
                   :header (bl.ser:make-block-header
                            :version 1 :prev-block parent
                            :merkle-root (make-array 32 :element-type '(unsigned-byte 8))
                            :timestamp 0 :bits 0 :nonce 0
                            :cached-hash this-block)
                   :transactions (list coinbase))))
      (unwind-protect
           (progn
             ;; Control: nothing tracked before any block is applied.
             (is (null (bl.store:cvc-best-block cache))
                 "a fresh cache tracks no block")
             ;; Connect: the pointer becomes THIS block.
             (let ((spent (bl.store:apply-block-to-utxo-set cache block 1)))
               (declare (ignore spent))
               (is (equalp this-block (bl.store:cvc-best-block cache))
                   "applying a block moves the pointer to that block"))
             ;; A flush with no explicit hash stamps what the cache tracks.
             (bl.store:coins-view-cache-flush cache)
             (is (equalp this-block (bl.store:coins-view-db-best-block base))
                 "the flush stamps the cache's own pointer, unasked")
             ;; Disconnect: the pointer becomes the PARENT, which is the case the
             ;; chain tip would get wrong.
             (bl.store:disconnect-block-from-utxo-set cache block '())
             (is (equalp parent (bl.store:cvc-best-block cache))
                 "disconnecting moves the pointer back to the parent")
             (bl.store:coins-view-cache-flush cache)
             (is (equalp parent (bl.store:coins-view-db-best-block base))
                 "and a flush mid-rewind records the parent, not the old tip")
             ;; Control: the two hashes must be distinguishable, or the
             ;; assertions above could pass on any value.
             (is (not (equalp parent this-block))))
        (bl.store:close-coins-view-db base)))))

(test coins-cache-adopts-the-stored-best-block-on-open
  "A freshly-opened cache must adopt the pointer already on disk. Otherwise it
reports NIL until the first block-level mutation, and a flush in between — a
shutdown flush, say — would move coins while leaving the pointer behind."
  (let ((db-path (ensure-directories-exist
                  (merge-pathnames (format nil "bl-bbadopt-~D/" (random 1000000))
                                   (uiop:temporary-directory)))))
    (let* ((base (bl.store:open-coins-view-db db-path))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC)))
      (unwind-protect
           (let ((writer (bl.store:make-coins-view-cache base)))
             (bl.store:coins-view-cache-flush writer :best-block tip)
             (let ((reopened (bl.store:make-coins-view-cache base)))
               ;; Control: without adopting, a fresh cache knows nothing.
               (is (null (bl.store:cvc-best-block reopened)))
               (bl.store:coins-view-cache-load-best-block reopened)
               (is (equalp tip (bl.store:cvc-best-block reopened))
                   "the reopened cache adopts what is on disk")))
        (bl.store:close-coins-view-db base)))))

(test reconcile-moves-the-tip-record-to-where-the-coins-are
  "chainstate.dat must follow the coins, not the other way round.

The coins DB's pointer moves with the coins themselves, so when the two records
disagree the pointer is the fact and the tip record is the stale copy — and a
UTXO set cannot be reconstructed from a tip record, while the tip record is one
hash we can rewrite. This is the recovery that makes an interrupted reorg
survivable: the coins stop at a block boundary, the pointer names it, and
startup moves the record there so normal sync re-validates the gap.

It runs unconditionally, unlike the older in-transition recovery, because the
case that motivated it leaves no marker at all — an interrupted reorg whose
cache is afterwards flushed cleanly."
  (let* ((base (ensure-directories-exist
                (merge-pathnames (format nil "bl-reconcile-~D/" (random 1000000))
                                 (uiop:temporary-directory))))
         (chain-state (bl.store:init-chain-state base))
         (db (bl.store:open-coins-view-db
              (ensure-directories-exist (merge-pathnames "chainstate/" base))))
         (cache (bl.store:make-coins-view-cache db))
         (node (bl:make-node))
         (coins-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xC0))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xF1)))
    (unwind-protect
         (progn
           (setf (bl:node-chain-state node) chain-state
                 (bl.store:chain-state-coins-view chain-state) cache)
           ;; The chain believes it is at height 200; the coins are at 150.
           (dolist (pair (list (cons coins-hash 150) (cons tip-hash 200)))
             (bl.store:add-block-index-entry
              chain-state (bl.store:make-block-index-entry
                           :hash (car pair) :height (cdr pair)
                           :chain-work 0 :status :valid)))
           (bl.store:update-chain-tip chain-state tip-hash 200)
           ;; Control: with no pointer recorded there is nothing to reconcile.
           (is (eq :unrecorded (bl::reconcile-coins-db-best-block node)))
           (is (= 200 (bl.store:current-height chain-state))
               "and the tip is left alone")
           ;; Now record where the coins actually are.
           (bl.store:coins-view-cache-flush cache :best-block coins-hash)
           (is (eq :reconciled (bl::reconcile-coins-db-best-block node)))
           (is (= 150 (bl.store:current-height chain-state))
               "the tip record follows the coins")
           (is (equalp coins-hash (bl.store:best-block-hash chain-state)))
           ;; Idempotent: a second pass now agrees.
           (is (eq :match (bl::reconcile-coins-db-best-block node)))
           ;; A pointer naming a block we cannot place is not silently accepted.
           (bl.store:coins-view-cache-flush
            cache :best-block (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element #xEE))
           (is (eq :unresolvable (bl::reconcile-coins-db-best-block node))
               "an unplaceable UTXO set is reported, not guessed at"))
      (bl.store:close-coins-view-db db))))

(test ga9-txindex-startup-catch-up-is-wired
  "BUILD-TX-INDEX existed, was complete and was idempotent — and had NO CALLER
anywhere in the tree. So -txindex indexed only blocks connected AFTER startup:
enabling it on a synced node produced an index of 0 entries and
getrawtransaction answered -5 for every historical txid, which is the entire
purpose of the option. Observed live on testnet4 at height 149088.

Asserted structurally because the alternative is standing up a full node in a
unit test. The property that matters is that start-node actually calls it —
a complete, correct, unreachable function is exactly the shape of this bug."
  (let ((src (%node-source-text)))
    (is (search "(catch-up-index *node* (node-tx-index *node*))" src)
        "start-node must catch the txindex up over stored blocks, or -txindex
         indexes nothing historical")))

(test txospenderindex-startup-catch-up-is-wired
  "The same shape for -txospenderindex, found by the P2e-1 review: its only
catch-up caller was the assumeutxo-promotion rebind, so an existing node that
turned the flag on indexed nothing historical and gettxspendingprevout knew
only spends connected after the restart. Core starts every index's background
sync from init (init.cpp StartIndexBackgroundSync)."
  (let ((src (%node-source-text)))
    (is (search "(catch-up-index *node* (node-txospenderindex *node*))" src)
        "start-node must catch the txospenderindex up over stored blocks")))

(defun %txresume-chain (n)
  "A chain-state with an N-block active chain (heights 0..N-1) linked by
prev-entry, so GET-BLOCK-AT-HEIGHT can walk it. Returns (values state hashes)."
  (let ((cs (bl.store:make-chain-state))
        (hashes '())
        (prev nil))
    (dotimes (i n)
      (let* ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))
             (e (bl.store:make-block-index-entry
                 :hash h :height i :chain-work (* 10 (1+ i))
                 :status :valid :prev-entry prev)))
        (bl.store:add-block-index-entry cs e)
        (push h hashes)
        (setf prev e)))
    (setf (bl.store:chain-state-best-block-hash cs)
          (bl.store:block-index-entry-hash prev)
          (bl.store:chain-state-best-height cs) (1- n))
    (values cs (nreverse hashes))))

(test txindex-resume-height-skips-what-is-already-indexed
  "The catch-up used to re-read EVERY block from disk on every start just to ask
whether it was already indexed — 149k blocks and about nine minutes on the live
testnet4 node. txindex-set-best-block and txindex-best-block already existed for
exactly this and had NO callers, so nothing recorded progress."
  (let ((dir (merge-pathnames (format nil "txidx-resume-~D/" (get-universal-time))
                              (uiop:temporary-directory))))
    (multiple-value-bind (cs hashes) (%txresume-chain 5)
      (let ((txindex (bl.store:init-tx-index dir :enabled t)))
        (unwind-protect
             (progn
               ;; No marker: the whole chain must be scanned.
               (is (= 0 (bl.store::%txindex-resume-height txindex cs)))
               ;; Marker on the active chain at height 2: resume at 3.
               (bl.store:txindex-set-best-block txindex (third hashes))
               (is (= 3 (bl.store::%txindex-resume-height txindex cs)))
               ;; Marker at the tip: nothing left to scan.
               (bl.store:txindex-set-best-block txindex (fifth hashes))
               (is (= 5 (bl.store::%txindex-resume-height txindex cs)))
               ;; Marker naming a block we have never heard of: full rescan.
               (bl.store:txindex-set-best-block
                txindex (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 99))
               (is (= 0 (bl.store::%txindex-resume-height txindex cs))))
          (bl.store:close-tx-index txindex))))))

(test txindex-is-driven-through-the-node-index-list
  "The seam that was missing three times over: connect-block took the index
as an argument, and the networking path, the run-ibd activation and five
ibd.lisp sites each forgot it in turn, so a live node's index was maintained
ONLY by the startup catch-up. Since P2e-2 the txindex is one of NODE-INDEXES
and every connect, disconnect and catch-up reaches it through that list, so
the property to pin is membership: an enabled index is in the list, a
disabled one is not, and nothing in the tree passes an index to the chain."
  (let* ((dir (merge-pathnames (format nil "txidx-reach-~D/" (get-internal-real-time))
                               (uiop:temporary-directory)))
         (enabled (bl.store:init-tx-index dir :enabled t))
         (disabled (bl.store:init-tx-index dir :enabled nil)))
    (unwind-protect
         (progn
           (is (member enabled (bl:node-indexes (bl:make-node :tx-index enabled)))
               "an enabled txindex must be among the node's driven indexes")
           (is (null (bl:node-indexes (bl:make-node :tx-index disabled)))
               "a disabled txindex must not be driven")
           (is (null (bl:node-indexes (bl:make-node)))
               "no index, nothing driven"))
      (bl.store:close-tx-index enabled)))
  (let ((src (uiop:read-file-string
              (merge-pathnames "src/networking/protocol.lisp"
                               (asdf:system-source-directory :bitcoin-lisp)))))
    (is (null (search ":tx-index" src))
        "accept-downloaded-block must not thread an index argument; the
         connect hook reaches it through *node*")))

(test txindex-resume-reports-why-it-chose-a-full-rescan
  "The resume decision must be VISIBLE. A nine-minute startup that silently
rescans from genesis gives the log no way to say whether the marker was
missing, unknown, or off-chain -- which is the first question anyone asks."
  (let ((dir (merge-pathnames (format nil "txidx-why-~D/" (get-universal-time))
                              (uiop:temporary-directory))))
    (multiple-value-bind (cs hashes) (%txresume-chain 5)
      (let ((txindex (bl.store:init-tx-index dir :enabled t)))
        (unwind-protect
             (progn
               (is (eq :no-marker
                       (nth-value 1 (bl.store::%txindex-resume-height
                                     txindex cs))))
               (bl.store:txindex-set-best-block
                txindex (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 99))
               (is (eq :marker-not-in-index
                       (nth-value 1 (bl.store::%txindex-resume-height
                                     txindex cs))))
               (bl.store:txindex-set-best-block txindex (third hashes))
               (is (eq :resumed
                       (nth-value 1 (bl.store::%txindex-resume-height
                                     txindex cs))))
               ;; A block at a height the chain holds, but not THIS block.
               (let* ((fork-hash (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 201))
                      (fork (bl.store:make-block-index-entry
                             :hash fork-hash :height 2 :chain-work 30 :status :valid)))
                 (bl.store:add-block-index-entry cs fork)
                 (bl.store:txindex-set-best-block txindex fork-hash)
                 (is (eq :marker-off-chain
                         (nth-value 1 (bl.store::%txindex-resume-height
                                       txindex cs))))))
          (bl.store:close-tx-index txindex))))))

(test txindex-resume-refuses-a-marker-that-was-reorged-away
  "A marker alone is not enough. A reorg while the index was offline leaves
entries below it pointing at a branch that is no longer active; skipping those
heights would leave the stale locations in place forever. The marker is honoured
only when its block is STILL on the active chain at the height it claims."
  (let ((dir (merge-pathnames (format nil "txidx-reorg-~D/" (get-universal-time))
                              (uiop:temporary-directory))))
    (multiple-value-bind (cs hashes) (%txresume-chain 5)
      (let ((txindex (bl.store:init-tx-index dir :enabled t)))
        (unwind-protect
             (progn
               (bl.store:txindex-set-best-block txindex (third hashes))
               (is (= 3 (bl.store::%txindex-resume-height txindex cs)))
               ;; A competing block at the SAME height, now indexed but off-chain:
               ;; the height still exists, but it is not this block any more.
               (let* ((fork-hash (make-array 32 :element-type '(unsigned-byte 8)
                                                :initial-element 200))
                      (fork (bl.store:make-block-index-entry
                             :hash fork-hash :height 2 :chain-work 30
                             :status :valid)))
                 (bl.store:add-block-index-entry cs fork)
                 (bl.store:txindex-set-best-block txindex fork-hash)
                 (is (= 0 (bl.store::%txindex-resume-height txindex cs))
                     "an off-chain marker must force a full rescan")))
          (bl.store:close-tx-index txindex))))))

(test ga9-txindex-catch-up-is-idempotent
  "The catch-up runs unconditionally at every startup, so it must write nothing
when the index is already current — %txindex-block-indexed-p checks the block's
LAST transaction, which also re-points entries left stale by a reorg that
happened while the index was offline."
  (let* ((dir (merge-pathnames (format nil "txidx-idem-~D/" (get-universal-time))
                               (uiop:temporary-directory)))
         (txindex (bl.store:init-tx-index dir :enabled t)))
    (unwind-protect
         (progn
           (is (= 0 (bl.store:txindex-count txindex))
               "a fresh index is empty")
           ;; A LevelDB-backed index answers lookups without any in-memory map.
           (let ((txid (make-array 32 :element-type '(unsigned-byte 8)
                                      :initial-element 3))
                 (bh (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element 4)))
             (bl.store:txindex-add txindex txid bh 7)
             (let ((loc (bl.store:txindex-lookup txindex txid)))
               (is-true loc "the entry must be readable straight from the DB")
               (is (= 7 (bl.store:tx-location-tx-position loc)))
               (is (equalp bh (bl.store:tx-location-block-hash loc))))
             ;; Upsert: a re-mined transaction re-points rather than duplicating.
             (let ((bh2 (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 5)))
               (bl.store:txindex-add txindex txid bh2 1)
               (is (= 1 (bl.store:txindex-count txindex))
                   "upsert must not create a second entry")
               (is (equalp bh2 (bl.store:tx-location-block-hash
                                (bl.store:txindex-lookup txindex txid)))
                   "and the location must be the NEW block"))))
      (bl.store:close-tx-index txindex)
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))


(test fsync-parent-directory-targets-the-directory
  "fsync-parent-directory opens the directory a file lives in. Its
predecessor was a second FSYNC-DIRECTORY, defined in utxo.lisp and silently
replaced by flatfile.lisp's directory-taking one (same package, same name),
so every rename-into-place in utxo.lisp fsynced the file and never the
directory. The helper must accept a plain file path and a bare name."
  (let ((path (merge-pathnames "fsync-parent-probe.dat" (uiop:temporary-directory))))
    (with-open-file (o path :direction :output :if-exists :supersede
                            :element-type '(unsigned-byte 8))
      (write-byte 1 o))
    (unwind-protect
         (progn
           (finishes (bl.kv:fsync-parent-directory (namestring path)))
           (finishes (bl.kv:fsync-parent-directory "bare-name.dat"))
           (finishes (bl.kv:fsync-directory
                      (namestring (uiop:temporary-directory)))))
      (delete-file path))))

(test fsync-directory-reports-a-failure-instead-of-swallowing-it
  "A directory fsync that fails has to say so. It still may not break the write
it was protecting -- the file is renamed into place by then -- but returning a
silent NIL is how a node loses durability with nothing in the log to find it by."
  (flet ((fsync-log (dir)
           (let ((out (make-string-output-stream)))
             (let ((bl.log:*log-stream* out))
               (bl.kv:fsync-directory dir))
             (get-output-stream-string out))))
    (let ((quiet (fsync-log (namestring (uiop:temporary-directory)))))
      (is (string= "" quiet) "an fsync that succeeded logged ~S" quiet))
    (let ((complaint (fsync-log "/no-such-directory-for-the-fsync-test/")))
      (is-true (search "fsync" complaint)
               "a directory that cannot be opened logged ~S" complaint))))
