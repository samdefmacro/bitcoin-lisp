(in-package #:bitcoin-lisp.tests)

(in-suite :storage-tests)

;;;; Block store

(test get-block-treats-corrupt-file-as-absent-and-prunes
  "A truncated / corrupt block file must NOT raise out of get-block — before the
guard, read-bitcoin-block's raise escaped the reorg/download paths to the
sync-thread top level and killed it (a live-but-wedged zombie). get-block now
returns NIL (treated as absent) AND prunes the file so the normal download path
re-fetches it (store-block :supersede overwrites)."
  (let* ((dir (merge-pathnames "test-corrupt-block/" (uiop:temporary-directory)))
         (store (bitcoin-lisp.storage:init-block-store dir))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 1
              :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                               :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                 :hash zeros :index #xffffffff)
                               :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                                       :initial-element 0)
                               :sequence #xffffffff))
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                :value 5000000000
                                :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                           :initial-element #x51)))
              :lock-time 0))
         (hdr (bitcoin-lisp.serialization:make-block-header
               :version 1 :prev-block zeros :merkle-root zeros
               :timestamp 1700000000 :bits #x207fffff :nonce 0))
         (blk (bitcoin-lisp.serialization:make-bitcoin-block
               :header hdr :transactions (list tx))))
    (unwind-protect
         (let ((hash (bitcoin-lisp.storage:store-block store blk)))
           ;; Reads back fine while intact.
           (is-true (bitcoin-lisp.storage:get-block store hash))
           ;; Truncate the on-disk file to garbage so read-bitcoin-block raises.
           (let ((path (bitcoin-lisp.storage::block-file-path store hash)))
             (with-open-file (s path :direction :output :if-exists :supersede
                                     :element-type '(unsigned-byte 8))
               (write-sequence (make-array 3 :element-type '(unsigned-byte 8)
                                             :initial-contents '(1 2 3)) s))
             ;; get-block must NOT raise: returns NIL and prunes the file.
             (is (null (bitcoin-lisp.storage:get-block store hash)))
             (is (null (probe-file path))
                 "corrupt block file must be pruned so re-download can self-heal")))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test store-block-preserves-witness
  "store-block must persist witness data (BIP144) so blocks read back from disk
are witness-complete — needed to serve MSG_WITNESS_BLOCK to peers (the
serve-blocks fix) and to re-validate witness on reorg. Before the fix store-block
used the legacy serializer, which dropped witness."
  (let* ((dir (merge-pathnames "test-store-witness/" (uiop:temporary-directory)))
         (store (bitcoin-lisp.storage:init-block-store dir))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (prev (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (wtx (bitcoin-lisp.serialization:make-transaction
               :version 2
               :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                  :hash prev :index 0)
                                :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                :sequence #xffffffff))
               :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                 :value 1000
                                 :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                            :initial-element #x51)))
               :witness (vector (list (make-array 3 :element-type '(unsigned-byte 8)
                                                  :initial-contents '(1 2 3))))
               :lock-time 0))
         (hdr (bitcoin-lisp.serialization:make-block-header
               :version 1 :prev-block zeros :merkle-root zeros
               :timestamp 1700000000 :bits #x207fffff :nonce 0))
         (blk (bitcoin-lisp.serialization:make-bitcoin-block
               :header hdr :transactions (list wtx))))
    (is-true (bitcoin-lisp.serialization:transaction-has-witness-p wtx))
    (let* ((hash (bitcoin-lisp.storage:store-block store blk))
           (retrieved (bitcoin-lisp.storage:get-block store hash))
           (rtx (first (bitcoin-lisp.serialization:bitcoin-block-transactions retrieved))))
      (is-true (bitcoin-lisp.serialization:transaction-has-witness-p rtx)
               "retrieved block tx must retain witness data")
      (is (equalp (bitcoin-lisp.serialization:serialize-witness-transaction wtx)
                  (bitcoin-lisp.serialization:serialize-witness-transaction rtx))
          "round-tripped witness tx must be byte-identical"))
    (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))

;;;; UTXO Set Tests

(test utxo-set-add-and-get
  "Adding a UTXO should make it retrievable."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 50000000 script 100)
    (let ((entry (bitcoin-lisp.storage:get-utxo utxo-set txid 0)))
      (is (not (null entry)))
      (is (= 50000000 (bitcoin-lisp.storage:utxo-entry-value entry)))
      (is (= 100 (bitcoin-lisp.storage:utxo-entry-height entry)))
      (is (equalp script (bitcoin-lisp.storage:utxo-entry-script-pubkey entry))))))

(test utxo-set-remove
  "Removing a UTXO should make it no longer retrievable."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 25000000 script 50)
    (is (bitcoin-lisp.storage:utxo-exists-p utxo-set txid 0))
    (bitcoin-lisp.storage:remove-utxo utxo-set txid 0)
    (is (not (bitcoin-lisp.storage:utxo-exists-p utxo-set txid 0)))))

(test utxo-set-count
  "UTXO count should track additions and removals."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (is (= 0 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 1000 script 1)
    (is (= 1 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 2000 script 1)
    (is (= 2 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 3000 script 1)
    (is (= 3 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (bitcoin-lisp.storage:remove-utxo utxo-set txid1 0)
    (is (= 2 (bitcoin-lisp.storage:utxo-count utxo-set)))))

(test utxo-set-coinbase-flag
  "Coinbase UTXOs should be flagged correctly."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 5000000000 script 0 :coinbase t)
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 1000000 script 1 :coinbase nil)
    (is (bitcoin-lisp.storage:utxo-entry-coinbase
         (bitcoin-lisp.storage:get-utxo utxo-set txid1 0)))
    (is (not (bitcoin-lisp.storage:utxo-entry-coinbase
              (bitcoin-lisp.storage:get-utxo utxo-set txid2 0))))))

(test utxo-set-multiple-outputs-same-tx
  "Multiple outputs from the same transaction should be distinguishable."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 1000 script 10)
    (bitcoin-lisp.storage:add-utxo utxo-set txid 1 2000 script 10)
    (bitcoin-lisp.storage:add-utxo utxo-set txid 2 3000 script 10)
    (is (= 3 (bitcoin-lisp.storage:utxo-count utxo-set)))
    (is (= 1000 (bitcoin-lisp.storage:utxo-entry-value
                 (bitcoin-lisp.storage:get-utxo utxo-set txid 0))))
    (is (= 2000 (bitcoin-lisp.storage:utxo-entry-value
                 (bitcoin-lisp.storage:get-utxo utxo-set txid 1))))
    (is (= 3000 (bitcoin-lisp.storage:utxo-entry-value
                 (bitcoin-lisp.storage:get-utxo utxo-set txid 2))))))

;;;; Chain State Tests

(test chain-state-init
  "Chain state should initialize with genesis hash."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    (is (not (null (bitcoin-lisp.storage:best-block-hash state))))
    (is (= 0 (bitcoin-lisp.storage:current-height state)))))

(test chain-state-update-tip
  "Updating chain tip should change best block and height."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/"))
        (new-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)))
    (bitcoin-lisp.storage:update-chain-tip state new-hash 100)
    (is (equalp new-hash (bitcoin-lisp.storage:best-block-hash state)))
    (is (= 100 (bitcoin-lisp.storage:current-height state)))))

(test chain-state-block-index
  "Block index entries should be storable and retrievable."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/"))
        (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (let ((entry (bitcoin-lisp.storage:make-block-index-entry
                  :hash hash
                  :height 50
                  :chain-work 12345
                  :status :valid)))
      (bitcoin-lisp.storage:add-block-index-entry state entry)
      (let ((retrieved (bitcoin-lisp.storage:get-block-index-entry state hash)))
        (is (not (null retrieved)))
        (is (= 50 (bitcoin-lisp.storage:block-index-entry-height retrieved)))
        (is (= 12345 (bitcoin-lisp.storage:block-index-entry-chain-work retrieved)))
        (is (eq :valid (bitcoin-lisp.storage:block-index-entry-status retrieved)))))))

;;;; Chain Work Tests

(test bits-to-target-conversion
  "Bits to target conversion should match expected values."
  ;; Testnet genesis bits: 0x1d00ffff
  (let ((target (bitcoin-lisp.storage:bits-to-target #x1d00ffff)))
    ;; This should give a very large target (low difficulty)
    (is (> target 0))
    (is (< target (expt 2 256)))))

(test chain-work-calculation
  "Chain work calculation should accumulate correctly."
  (let ((work1 (bitcoin-lisp.storage:calculate-chain-work #x1d00ffff 0)))
    (is (> work1 0))
    (let ((work2 (bitcoin-lisp.storage:calculate-chain-work #x1d00ffff work1)))
      (is (> work2 work1))
      ;; Work should roughly double (same difficulty)
      (is (< (abs (- work2 (* 2 work1))) 1)))))

;;;; Block Locator Tests

(test block-locator-empty-chain
  "Block locator for empty chain should include genesis."
  (let ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    (let ((locator (bitcoin-lisp.storage:build-block-locator state)))
      (is (not (null locator)))
      ;; Should at least have genesis
      (is (>= (length locator) 1)))))

;;;; UTXO Set Iteration Tests

(test utxo-set-iterate-empty
  "Iterating empty UTXO set should not call callback."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (count 0))
    (bitcoin-lisp.storage:utxo-set-iterate
     utxo-set
     (lambda (txid vout entry)
       (declare (ignore txid vout entry))
       (incf count)))
    (is (= count 0))))

(test utxo-set-iterate-all-entries
  "Iterating UTXO set should visit all entries."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0))
        (visited nil))
    ;; Add 3 UTXOs
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 1000 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 2000 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 3000 script 2)
    ;; Iterate and collect
    (bitcoin-lisp.storage:utxo-set-iterate
     utxo-set
     (lambda (txid vout entry)
       (push (list txid vout (bitcoin-lisp.storage:utxo-entry-value entry)) visited)))
    ;; Should have visited all 3
    (is (= (length visited) 3))))

(test utxo-set-iterate-deterministic-order
  "UTXO iteration order should be deterministic across multiple calls."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0))
        (order1 nil)
        (order2 nil))
    ;; Add in non-sorted order
    (bitcoin-lisp.storage:add-utxo utxo-set txid-b 1 300 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid-a 0 100 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid-b 0 200 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid-a 1 150 script 1)
    ;; First iteration
    (bitcoin-lisp.storage:utxo-set-iterate
     utxo-set
     (lambda (txid vout entry)
       (declare (ignore entry))
       (push (cons (aref txid 0) vout) order1)))
    (setf order1 (nreverse order1))
    ;; Second iteration - should produce same order
    (bitcoin-lisp.storage:utxo-set-iterate
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
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Empty set
    (is (= (bitcoin-lisp.storage:utxo-set-total-amount utxo-set) 0))
    ;; Add UTXOs
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 100000000 script 1) ; 1 BTC
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 50000000 script 1)  ; 0.5 BTC
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 25000000 script 2)  ; 0.25 BTC
    ;; Total: 1.75 BTC = 175000000 satoshis
    (is (= (bitcoin-lisp.storage:utxo-set-total-amount utxo-set) 175000000))))

(test utxo-set-distinct-txids
  "Distinct txids should count unique transactions."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (txid3 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Empty set
    (is (= (bitcoin-lisp.storage:utxo-set-distinct-txids utxo-set) 0))
    ;; Add multiple outputs from same tx
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 1000 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 2000 script 1)
    (is (= (bitcoin-lisp.storage:utxo-set-distinct-txids utxo-set) 1))
    ;; Add from different txs
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 3000 script 2)
    (bitcoin-lisp.storage:add-utxo utxo-set txid3 0 4000 script 3)
    (is (= (bitcoin-lisp.storage:utxo-set-distinct-txids utxo-set) 3))))

(test compute-utxo-set-hash-empty
  "Hash of empty UTXO set should be consistent."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set)))
    (let ((hash1 (bitcoin-lisp.storage:compute-utxo-set-hash utxo-set))
          (hash2 (bitcoin-lisp.storage:compute-utxo-set-hash utxo-set)))
      ;; Should return same hash for same state
      (is (equalp hash1 hash2))
      ;; Should be 32 bytes
      (is (= (length hash1) 32)))))

(test compute-utxo-set-hash-deterministic
  "UTXO set hash should be deterministic on repeated calls."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    ;; Add UTXOs
    (bitcoin-lisp.storage:add-utxo utxo-set txid-a 0 1000 script 1)
    (bitcoin-lisp.storage:add-utxo utxo-set txid-b 0 2000 script 2)
    ;; Hash should be identical on repeated calls
    (let ((hash1 (bitcoin-lisp.storage:compute-utxo-set-hash utxo-set))
          (hash2 (bitcoin-lisp.storage:compute-utxo-set-hash utxo-set)))
      (is (equalp hash1 hash2))
      ;; Hash should change when UTXO set changes
      (bitcoin-lisp.storage:add-utxo utxo-set txid-a 1 500 script 1)
      (let ((hash3 (bitcoin-lisp.storage:compute-utxo-set-hash utxo-set)))
        (is (not (equalp hash1 hash3)))))))

;;;; Transaction Index Tests

(test txindex-init-and-close
  "Transaction index should initialize and close cleanly."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bitcoin-lisp.storage:init-tx-index test-dir)))
    (is (not (null txindex)))
    (is (bitcoin-lisp.storage:tx-index-enabled txindex))
    (bitcoin-lisp.storage:close-tx-index txindex)
    ;; Cleanup
    (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir)))))

(test txindex-add-and-lookup
  "Adding to txindex should make entry retrievable."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bitcoin-lisp.storage:init-tx-index test-dir))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (unwind-protect
        (progn
          ;; Add entry
          (bitcoin-lisp.storage:txindex-add txindex txid block-hash 5)
          ;; Lookup
          (let ((location (bitcoin-lisp.storage:txindex-lookup txindex txid)))
            (is (not (null location)))
            (is (equalp (bitcoin-lisp.storage:tx-location-block-hash location) block-hash))
            (is (= (bitcoin-lisp.storage:tx-location-tx-position location) 5))))
      ;; Cleanup
      (bitcoin-lisp.storage:close-tx-index txindex)
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-lookup-missing
  "Looking up missing txid should return nil."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bitcoin-lisp.storage:init-tx-index test-dir))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99)))
    (unwind-protect
        (is (null (bitcoin-lisp.storage:txindex-lookup txindex txid)))
      (bitcoin-lisp.storage:close-tx-index txindex)
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-remove
  "Removing from txindex should make entry no longer retrievable."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bitcoin-lisp.storage:init-tx-index test-dir))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4)))
    (unwind-protect
        (progn
          ;; Add then remove
          (bitcoin-lisp.storage:txindex-add txindex txid block-hash 0)
          (is (not (null (bitcoin-lisp.storage:txindex-lookup txindex txid))))
          (bitcoin-lisp.storage:txindex-remove txindex txid)
          (is (null (bitcoin-lisp.storage:txindex-lookup txindex txid))))
      (bitcoin-lisp.storage:close-tx-index txindex)
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-persistence
  "Transaction index should persist across close/reopen."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 6)))
    (unwind-protect
        (progn
          ;; First session: add entry
          (let ((txindex (bitcoin-lisp.storage:init-tx-index test-dir)))
            (bitcoin-lisp.storage:txindex-add txindex txid block-hash 10)
            (bitcoin-lisp.storage:close-tx-index txindex))
          ;; Second session: verify entry persisted
          (let ((txindex (bitcoin-lisp.storage:init-tx-index test-dir)))
            (unwind-protect
                (let ((location (bitcoin-lisp.storage:txindex-lookup txindex txid)))
                  (is (not (null location)))
                  (is (equalp (bitcoin-lisp.storage:tx-location-block-hash location) block-hash))
                  (is (= (bitcoin-lisp.storage:tx-location-tx-position location) 10)))
              (bitcoin-lisp.storage:close-tx-index txindex))))
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
          (let ((txindex (bitcoin-lisp.storage:init-tx-index test-dir)))
            (bitcoin-lisp.storage:txindex-add txindex txid block-a 1)
            (bitcoin-lisp.storage:txindex-add txindex txid block-b 3)
            ;; Live: the newest location wins; still a single distinct txid.
            (let ((loc (bitcoin-lisp.storage:txindex-lookup txindex txid)))
              (is (equalp block-b (bitcoin-lisp.storage:tx-location-block-hash loc)))
              (is (= 3 (bitcoin-lisp.storage:tx-location-tx-position loc))))
            (is (= 1 (bitcoin-lisp.storage:txindex-count txindex)))
            (bitcoin-lisp.storage:close-tx-index txindex))
          ;; Reopen: the file replay resolves to the newest location too.
          (let ((txindex (bitcoin-lisp.storage:init-tx-index test-dir)))
            (unwind-protect
                (let ((loc (bitcoin-lisp.storage:txindex-lookup txindex txid)))
                  (is (equalp block-b (bitcoin-lisp.storage:tx-location-block-hash loc)))
                  (is (= 3 (bitcoin-lisp.storage:tx-location-tx-position loc)))
                  (is (= 1 (bitcoin-lisp.storage:txindex-count txindex))))
              (bitcoin-lisp.storage:close-tx-index txindex))))
      (ignore-errors (delete-file (merge-pathnames "txindex.dat" test-dir))))))

(test txindex-multiple-entries
  "Transaction index should handle multiple entries."
  (let* ((test-dir (format nil "/tmp/btc-txindex-test-~A/" (get-universal-time)))
         (txindex (bitcoin-lisp.storage:init-tx-index test-dir))
         (block-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (unwind-protect
        (progn
          ;; Add multiple entries
          (dotimes (i 10)
            (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element i)))
              (bitcoin-lisp.storage:txindex-add txindex txid block-hash i)))
          ;; Verify all retrievable
          (dotimes (i 10)
            (let* ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element i))
                   (location (bitcoin-lisp.storage:txindex-lookup txindex txid)))
              (is (not (null location)))
              (is (= (bitcoin-lisp.storage:tx-location-tx-position location) i)))))
      (bitcoin-lisp.storage:close-tx-index txindex)
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
       (ignore-errors (bitcoin-lisp.storage:leveldb-destroy-db ,path-var))
       (ignore-errors
         (uiop:delete-directory-tree (pathname ,path-var)
                                     :validate t
                                     :if-does-not-exist :ignore)))))

(defmacro %with-tmp-leveldb ((db-var) &body body)
  "Open a fresh LevelDB at a tmp path; bind DB-VAR to the handle."
  (let ((path-var (gensym "PATH-")))
    `(%with-tmp-leveldb-path (,path-var)
       (bitcoin-lisp.storage:with-leveldb (,db-var ,path-var)
         ,@body))))

(test leveldb-put-get-round-trip
  "PUT then GET returns the value bytes verbatim."
  (%with-tmp-leveldb (db)
    (let ((k (make-array 3 :element-type '(unsigned-byte 8)
                           :initial-contents #(1 2 3)))
          (v (make-array 5 :element-type '(unsigned-byte 8)
                           :initial-contents #(10 20 30 40 50))))
      (bitcoin-lisp.storage:leveldb-put db k v)
      (is (equalp v (bitcoin-lisp.storage:leveldb-get db k))))))

(test leveldb-compact-preserves-data
  "leveldb-compact (full CompactRange) runs without error and leaves live keys
readable while deleted keys stay gone -- exercises the FFI binding end-to-end."
  (%with-tmp-leveldb (db)
    (flet ((b (n) (make-array 1 :element-type '(unsigned-byte 8)
                                :initial-contents (list n))))
      (dotimes (i 50) (bitcoin-lisp.storage:leveldb-put db (b i) (b (* 2 i))))
      (dotimes (i 25) (bitcoin-lisp.storage:leveldb-delete db (b i))) ; leave tombstones
      (bitcoin-lisp.storage:leveldb-compact db)
      ;; deleted keys are gone; surviving keys are intact after compaction
      (is (null (bitcoin-lisp.storage:leveldb-get db (b 0))))
      (is (null (bitcoin-lisp.storage:leveldb-get db (b 24))))
      (is (equalp (b 50) (bitcoin-lisp.storage:leveldb-get db (b 25))))
      (is (equalp (b 98) (bitcoin-lisp.storage:leveldb-get db (b 49)))))))

(test leveldb-get-missing
  "GET on an absent key returns NIL (not an error)."
  (%with-tmp-leveldb (db)
    (is (null (bitcoin-lisp.storage:leveldb-get
               db (make-array 1 :element-type '(unsigned-byte 8)
                                :initial-contents #(99)))))))

(test leveldb-delete
  "DELETE removes a previously put key."
  (%with-tmp-leveldb (db)
    (let ((k (make-array 2 :element-type '(unsigned-byte 8)
                           :initial-contents #(1 1)))
          (v (make-array 1 :element-type '(unsigned-byte 8)
                           :initial-contents #(42))))
      (bitcoin-lisp.storage:leveldb-put db k v)
      (is (equalp v (bitcoin-lisp.storage:leveldb-get db k)))
      (bitcoin-lisp.storage:leveldb-delete db k)
      (is (null (bitcoin-lisp.storage:leveldb-get db k))))))

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
      (bitcoin-lisp.storage:leveldb-put db k1 v1)
      (bitcoin-lisp.storage:with-leveldb-writebatch (b)
        (bitcoin-lisp.storage:leveldb-writebatch-delete b k1)
        (bitcoin-lisp.storage:leveldb-writebatch-put b k2 v2)
        (bitcoin-lisp.storage:leveldb-write db b))
      (is (null (bitcoin-lisp.storage:leveldb-get db k1)))
      (is (equalp v2 (bitcoin-lisp.storage:leveldb-get db k2))))))

(test leveldb-persistence-across-open-close
  "Data written in one open survives close + reopen."
  (%with-tmp-leveldb-path (path)
    (let ((k (make-array 4 :element-type '(unsigned-byte 8)
                           :initial-contents #(7 7 7 7)))
          (v (make-array 4 :element-type '(unsigned-byte 8)
                           :initial-contents #(8 8 8 8))))
      (bitcoin-lisp.storage:with-leveldb (db path)
        (bitcoin-lisp.storage:leveldb-put db k v))
      (bitcoin-lisp.storage:with-leveldb (db path)
        (is (equalp v (bitcoin-lisp.storage:leveldb-get db k)))))))

;;;; coins-view-db tests

(defmacro %with-tmp-coins-view ((view-var) &body body)
  "Open a fresh coins-view-db at a tmp path; bind VIEW-VAR."
  (let ((path-var (gensym "PATH-")))
    `(%with-tmp-leveldb-path (,path-var)
       (bitcoin-lisp.storage:with-coins-view-db (,view-var ,path-var)
         ,@body))))

(defun %sample-utxo-entry (&optional (value 50000000) (height 100))
  (bitcoin-lisp.storage:make-utxo-entry
   :value value
   :height height
   :coinbase nil
   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                 :initial-element #x76)))

(defun %sample-utxo-key (&optional (txid-element 1) (vout 0))
  (bitcoin-lisp.storage::make-utxo-key
   (make-array 32 :element-type '(unsigned-byte 8) :initial-element txid-element)
   vout))

(test coins-view-db-put-get-round-trip
  "Putting then getting a coin returns an equivalent utxo-entry."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 1 5))
          (e (%sample-utxo-entry 12345 99)))
      (bitcoin-lisp.storage:coins-view-db-put view k e)
      (let ((got (bitcoin-lisp.storage:coins-view-db-get view k)))
        (is (not (null got)))
        (is (= 12345 (bitcoin-lisp.storage:utxo-entry-value got)))
        (is (= 99 (bitcoin-lisp.storage:utxo-entry-height got)))
        (is (null (bitcoin-lisp.storage:utxo-entry-coinbase got)))
        (is (equalp (bitcoin-lisp.storage:utxo-entry-script-pubkey e)
                    (bitcoin-lisp.storage:utxo-entry-script-pubkey got)))))))

(test coins-view-db-get-missing
  "Getting an absent key returns NIL."
  (%with-tmp-coins-view (view)
    (is (null (bitcoin-lisp.storage:coins-view-db-get
               view (%sample-utxo-key 99 0))))))

(test coins-view-db-has-p
  "has-p reflects present/absent state."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 7 0)))
      (is (null (bitcoin-lisp.storage:coins-view-db-has-p view k)))
      (bitcoin-lisp.storage:coins-view-db-put view k (%sample-utxo-entry))
      (is (not (null (bitcoin-lisp.storage:coins-view-db-has-p view k)))))))

(test coins-view-db-erase
  "erase removes a previously-put coin."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 3 1))
          (e (%sample-utxo-entry)))
      (bitcoin-lisp.storage:coins-view-db-put view k e)
      (is (not (null (bitcoin-lisp.storage:coins-view-db-get view k))))
      (bitcoin-lisp.storage:coins-view-db-erase view k)
      (is (null (bitcoin-lisp.storage:coins-view-db-get view k))))))

(test coins-view-db-coinbase-flag-preserved
  "coinbase boolean round-trips correctly."
  (%with-tmp-coins-view (view)
    (let ((k (%sample-utxo-key 11 0))
          (e (bitcoin-lisp.storage:make-utxo-entry
              :value 5000000000
              :height 1
              :coinbase t
              :script-pubkey (make-array 0 :element-type '(unsigned-byte 8)))))
      (bitcoin-lisp.storage:coins-view-db-put view k e)
      (let ((got (bitcoin-lisp.storage:coins-view-db-get view k)))
        (is (eq t (bitcoin-lisp.storage:utxo-entry-coinbase got)))))))

(test coins-view-db-write-batch
  "A batch of put + erase ops applies atomically."
  (%with-tmp-coins-view (view)
    (let ((k1 (%sample-utxo-key 1 0))
          (k2 (%sample-utxo-key 2 0))
          (e1 (%sample-utxo-entry 100 10))
          (e2 (%sample-utxo-entry 200 20)))
      ;; Seed k1; then a batch erases k1 and adds k2.
      (bitcoin-lisp.storage:coins-view-db-put view k1 e1)
      (bitcoin-lisp.storage:coins-view-db-write-batch
       view (list (list :erase k1) (list :put k2 e2)))
      (is (null (bitcoin-lisp.storage:coins-view-db-get view k1)))
      (let ((got (bitcoin-lisp.storage:coins-view-db-get view k2)))
        (is (not (null got)))
        (is (= 200 (bitcoin-lisp.storage:utxo-entry-value got)))))))

(test coins-view-db-persistence-across-open-close
  "Coins written then closed are visible on reopen."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 5 7))
          (e (%sample-utxo-entry 999 42)))
      (bitcoin-lisp.storage:with-coins-view-db (view path)
        (bitcoin-lisp.storage:coins-view-db-put view k e))
      (bitcoin-lisp.storage:with-coins-view-db (view path)
        (let ((got (bitcoin-lisp.storage:coins-view-db-get view k)))
          (is (not (null got)))
          (is (= 999 (bitcoin-lisp.storage:utxo-entry-value got))))))))

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
       (bitcoin-lisp.storage:with-coins-view-db (,base-var ,path-var)
         (let ((,cache-var (bitcoin-lisp.storage:make-coins-view-cache ,base-var)))
           ,@body)))))

(test coins-view-cache-add-then-get
  "Add via cache; subsequent get returns the entry."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 1 0))
          (e (%sample-utxo-entry 42 7)))
      (bitcoin-lisp.storage:coins-view-cache-add cache k e)
      (let ((got (bitcoin-lisp.storage:coins-view-cache-get cache k)))
        (is (not (null got)))
        (is (= 42 (bitcoin-lisp.storage:utxo-entry-value got)))))))

(test coins-view-cache-pulls-from-base
  "Get on a key absent from cache but present in base falls through to base."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 2 0))
          (e (%sample-utxo-entry 999 10)))
      ;; First, populate the base view directly.
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (bitcoin-lisp.storage:coins-view-db-put base k e))
      ;; New cache over same base — should see the base entry.
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (let ((cache (bitcoin-lisp.storage:make-coins-view-cache base)))
          (let ((got (bitcoin-lisp.storage:coins-view-cache-get cache k)))
            (is (not (null got)))
            (is (= 999 (bitcoin-lisp.storage:utxo-entry-value got)))))))))

(test coins-view-cache-spend-marks-spent
  "Spend on a cached unspent coin returns T; subsequent get returns NIL."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 3 0))
          (e (%sample-utxo-entry)))
      (bitcoin-lisp.storage:coins-view-cache-add cache k e)
      (is (eq t (bitcoin-lisp.storage:coins-view-cache-spend cache k)))
      (is (null (bitcoin-lisp.storage:coins-view-cache-get cache k)))
      (is (null (bitcoin-lisp.storage:coins-view-cache-has-p cache k))))))

(test coins-view-cache-spend-fresh-drops-entry
  "Spending a FRESH (add-then-spend, never flushed) coin drops the
cache entry entirely — flush has nothing to do."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 4 0))
          (e (%sample-utxo-entry)))
      (bitcoin-lisp.storage:coins-view-cache-add cache k e)
      (is (= 1 (bitcoin-lisp.storage::cvc-fresh-count cache)))
      (is (= 1 (bitcoin-lisp.storage::cvc-dirty-count cache)))
      (bitcoin-lisp.storage:coins-view-cache-spend cache k)
      (is (= 0 (bitcoin-lisp.storage::cvc-fresh-count cache)))
      (is (= 0 (bitcoin-lisp.storage::cvc-dirty-count cache)))
      (is (= 0 (hash-table-count (bitcoin-lisp.storage::cvc-entries cache)))))))

(test coins-view-cache-spend-non-fresh-keeps-tombstone
  "Spending a coin that came from base leaves a NIL tombstone in
cache (so flush issues the erase). FRESH-count stays zero."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 5 0))
          (e (%sample-utxo-entry)))
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (bitcoin-lisp.storage:coins-view-db-put base k e))
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (let ((cache (bitcoin-lisp.storage:make-coins-view-cache base)))
          (bitcoin-lisp.storage:coins-view-cache-spend cache k)
          (is (= 1 (bitcoin-lisp.storage::cvc-dirty-count cache)))
          (is (= 0 (bitcoin-lisp.storage::cvc-fresh-count cache)))
          (is (= 1 (hash-table-count (bitcoin-lisp.storage::cvc-entries cache)))))))))

(test coins-view-cache-flush-writes-and-clears
  "Flush writes dirty entries to base, then clears the cache."
  (%with-tmp-leveldb-path (path)
    (let ((k1 (%sample-utxo-key 6 0))
          (k2 (%sample-utxo-key 7 0))
          (e1 (%sample-utxo-entry 100 1))
          (e2 (%sample-utxo-entry 200 2)))
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (let ((cache (bitcoin-lisp.storage:make-coins-view-cache base)))
          (bitcoin-lisp.storage:coins-view-cache-add cache k1 e1)
          (bitcoin-lisp.storage:coins-view-cache-add cache k2 e2)
          (let ((written (bitcoin-lisp.storage:coins-view-cache-flush cache)))
            (is (= 2 written)))
          ;; Cache is empty after flush.
          (is (= 0 (hash-table-count (bitcoin-lisp.storage::cvc-entries cache))))
          ;; Base now has both entries.
          (is (not (null (bitcoin-lisp.storage:coins-view-db-get base k1))))
          (is (not (null (bitcoin-lisp.storage:coins-view-db-get base k2)))))))))

(test coins-view-cache-flush-issues-erase
  "Flushing a spent (NIL) entry erases it from base."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 8 0))
          (e (%sample-utxo-entry)))
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (bitcoin-lisp.storage:coins-view-db-put base k e))
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (let ((cache (bitcoin-lisp.storage:make-coins-view-cache base)))
          (bitcoin-lisp.storage:coins-view-cache-spend cache k)
          (bitcoin-lisp.storage:coins-view-cache-flush cache)
          (is (null (bitcoin-lisp.storage:coins-view-db-get base k))))))))

(test coins-view-cache-add-overwrite-error
  "Adding to an already-unspent key without :allow-overwrite signals."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 9 0))
          (e (%sample-utxo-entry)))
      (bitcoin-lisp.storage:coins-view-cache-add cache k e)
      (signals error
        (bitcoin-lisp.storage:coins-view-cache-add cache k e)))))

(test coins-view-cache-add-overwrite-allowed
  ":allow-overwrite T silently overwrites (coinbase rewrite case)."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 10 0))
          (e1 (%sample-utxo-entry 100 1))
          (e2 (%sample-utxo-entry 200 2)))
      (bitcoin-lisp.storage:coins-view-cache-add cache k e1)
      (bitcoin-lisp.storage:coins-view-cache-add cache k e2 :allow-overwrite t)
      (is (= 200 (bitcoin-lisp.storage:utxo-entry-value
                  (bitcoin-lisp.storage:coins-view-cache-get cache k)))))))

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
  (let ((set (bitcoin-lisp.storage:make-utxo-set)))
    (dotimes (i count)
      (let ((txid (make-array 32 :element-type '(unsigned-byte 8)
                                 :initial-element (mod i 256)))
            (script (make-array 25 :element-type '(unsigned-byte 8)
                                   :initial-element #x76)))
        (bitcoin-lisp.storage:add-utxo set txid (mod i 4)
                                       (* 1000 (1+ i)) script (1+ i))))
    set))

(test migration-empty-set
  "Migrating an empty utxo-set yields an empty LevelDB but still marks complete."
  (%with-tmp-dat-and-leveldb (dat-path ldb-path)
    (let ((empty-set (bitcoin-lisp.storage:make-utxo-set)))
      (bitcoin-lisp.storage::save-utxo-set empty-set dat-path))
    (let ((written (bitcoin-lisp.storage:migrate-utxoset-dat-to-leveldb
                    dat-path ldb-path)))
      (is (= 0 written)))
    (is (eq t (bitcoin-lisp.storage:leveldb-utxo-migration-complete-p ldb-path)))))

(test migration-round-trip
  "After migration, every entry in the source set is retrievable from
the LevelDB via coins-view-db-get."
  (%with-tmp-dat-and-leveldb (dat-path ldb-path)
    (let* ((source (%populated-utxo-set 50)))
      (bitcoin-lisp.storage::save-utxo-set source dat-path)
      (let ((written (bitcoin-lisp.storage:migrate-utxoset-dat-to-leveldb
                      dat-path ldb-path)))
        (is (= 50 written)))
      ;; Verify equivalence: every (key, entry) in source is in LevelDB.
      (bitcoin-lisp.storage:with-coins-view-db (view ldb-path)
        (maphash (lambda (key src-entry)
                   (let ((dst-entry (bitcoin-lisp.storage:coins-view-db-get view key)))
                     (is (not (null dst-entry)))
                     (is (= (bitcoin-lisp.storage:utxo-entry-value src-entry)
                            (bitcoin-lisp.storage:utxo-entry-value dst-entry)))
                     (is (= (bitcoin-lisp.storage:utxo-entry-height src-entry)
                            (bitcoin-lisp.storage:utxo-entry-height dst-entry)))
                     (is (equalp (bitcoin-lisp.storage:utxo-entry-script-pubkey src-entry)
                                 (bitcoin-lisp.storage:utxo-entry-script-pubkey dst-entry)))))
                 (bitcoin-lisp.storage::utxo-set-entries source))))))

(test migration-marker-detection
  "leveldb-utxo-migration-complete-p returns NIL for an empty LevelDB
(never migrated) and T after a successful migration."
  (%with-tmp-leveldb-path (ldb-path)
    ;; Empty LevelDB — marker absent.
    (bitcoin-lisp.storage:with-leveldb (db ldb-path) db)
    (is (null (bitcoin-lisp.storage:leveldb-utxo-migration-complete-p ldb-path)))
    ;; Migrate an empty set; marker should now be present.
    (let ((dat-path (%tmp-dat-path)))
      (unwind-protect
           (progn
             (bitcoin-lisp.storage::save-utxo-set
              (bitcoin-lisp.storage:make-utxo-set) dat-path)
             (bitcoin-lisp.storage:migrate-utxoset-dat-to-leveldb dat-path ldb-path)
             (is (eq t (bitcoin-lisp.storage:leveldb-utxo-migration-complete-p
                        ldb-path))))
        (ignore-errors (delete-file dat-path))))))

(test migration-missing-source-signals
  "Migrating from a non-existent source path signals an error."
  (%with-tmp-leveldb-path (ldb-path)
    (signals error
      (bitcoin-lisp.storage:migrate-utxoset-dat-to-leveldb
       "/tmp/this-file-does-not-exist-12345.dat" ldb-path))))

(test migration-larger-set
  "Migration handles a multi-batch set (batch-size smaller than total)."
  (%with-tmp-dat-and-leveldb (dat-path ldb-path)
    (let ((source (%populated-utxo-set 250)))
      (bitcoin-lisp.storage::save-utxo-set source dat-path)
      ;; Force several batches by using a small batch-size.
      (let ((written (bitcoin-lisp.storage:migrate-utxoset-dat-to-leveldb
                      dat-path ldb-path :batch-size 32)))
        (is (= 250 written))))
    (is (eq t (bitcoin-lisp.storage:leveldb-utxo-migration-complete-p ldb-path)))))

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
      (bitcoin-lisp.storage:leveldb-put db k3 v)
      (bitcoin-lisp.storage:leveldb-put db k1 v)
      (bitcoin-lisp.storage:leveldb-put db k2 v)
      (bitcoin-lisp.storage:with-leveldb-iterator (it db)
        (bitcoin-lisp.storage:leveldb-iter-seek-to-first it)
        (is (bitcoin-lisp.storage:leveldb-iter-valid-p it))
        (is (equalp k1 (bitcoin-lisp.storage:leveldb-iter-key it)))
        (bitcoin-lisp.storage:leveldb-iter-next it)
        (is (equalp k2 (bitcoin-lisp.storage:leveldb-iter-key it)))
        (bitcoin-lisp.storage:leveldb-iter-next it)
        (is (equalp k3 (bitcoin-lisp.storage:leveldb-iter-key it)))
        (bitcoin-lisp.storage:leveldb-iter-next it)
        (is (not (bitcoin-lisp.storage:leveldb-iter-valid-p it)))))))

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
        (bitcoin-lisp.storage:leveldb-put db k v))
      (bitcoin-lisp.storage:with-leveldb-iterator (it db)
        (bitcoin-lisp.storage:leveldb-iter-seek it prefix)
        ;; First hit is kb (#(2 0)).
        (is (bitcoin-lisp.storage:leveldb-iter-valid-p it))
        (is (equalp kb (bitcoin-lisp.storage:leveldb-iter-key it)))
        (bitcoin-lisp.storage:leveldb-iter-next it)
        (is (equalp kc (bitcoin-lisp.storage:leveldb-iter-key it)))
        (bitcoin-lisp.storage:leveldb-iter-next it)
        ;; Next key is kd which leaves the prefix — caller is responsible
        ;; for stopping; the iterator itself remains valid.
        (is (equalp kd (bitcoin-lisp.storage:leveldb-iter-key it)))))))

(test leveldb-iterator-empty-db
  "Seek-to-first on an empty DB yields an invalid iterator immediately."
  (%with-tmp-leveldb (db)
    (bitcoin-lisp.storage:with-leveldb-iterator (it db)
      (bitcoin-lisp.storage:leveldb-iter-seek-to-first it)
      (is (not (bitcoin-lisp.storage:leveldb-iter-valid-p it))))))

(test leveldb-iterator-value-copy-out
  "Iterator key and value bytes are owned by the caller (survive next)."
  (%with-tmp-leveldb (db)
    (let ((k1 (make-array 1 :element-type '(unsigned-byte 8) :initial-element 1))
          (k2 (make-array 1 :element-type '(unsigned-byte 8) :initial-element 2))
          (v1 (make-array 3 :element-type '(unsigned-byte 8) :initial-contents #(10 11 12)))
          (v2 (make-array 3 :element-type '(unsigned-byte 8) :initial-contents #(20 21 22))))
      (bitcoin-lisp.storage:leveldb-put db k1 v1)
      (bitcoin-lisp.storage:leveldb-put db k2 v2)
      (bitcoin-lisp.storage:with-leveldb-iterator (it db)
        (bitcoin-lisp.storage:leveldb-iter-seek-to-first it)
        (let ((k-copy (bitcoin-lisp.storage:leveldb-iter-key it))
              (v-copy (bitcoin-lisp.storage:leveldb-iter-value it)))
          (bitcoin-lisp.storage:leveldb-iter-next it)
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
      (bitcoin-lisp.storage:coin-view-add cache txid 0
                                          12345 (%sample-script) 99)
      (let ((got (bitcoin-lisp.storage:coin-view-get cache txid 0)))
        (is (not (null got)))
        (is (= 12345 (bitcoin-lisp.storage:utxo-entry-value got)))
        (is (= 99 (bitcoin-lisp.storage:utxo-entry-height got)))))))

(test coin-view-has-p-reflects-spend
  (%with-tmp-cache (cache)
    (let ((txid (%sample-txid 8)))
      (bitcoin-lisp.storage:coin-view-add cache txid 0
                                          1 (%sample-script) 1)
      (is (bitcoin-lisp.storage:coin-view-has-p cache txid 0))
      (let ((prev (bitcoin-lisp.storage:coin-view-spend cache txid 0)))
        (is (not (null prev)))
        (is (= 1 (bitcoin-lisp.storage:utxo-entry-value prev))))
      (is (not (bitcoin-lisp.storage:coin-view-has-p cache txid 0)))
      (is (null (bitcoin-lisp.storage:coin-view-spend cache txid 0))))))

(test coin-view-any-utxo-for-txid-p-cache-hit
  "Returns T when only the cache has unspent outputs for TXID."
  (%with-tmp-cache (cache)
    (let ((txid (%sample-txid 9)))
      (bitcoin-lisp.storage:coin-view-add cache txid 0
                                          1 (%sample-script) 1)
      (is (bitcoin-lisp.storage:coin-view-any-utxo-for-txid-p cache txid)))))

(test coin-view-any-utxo-for-txid-p-base-hit
  "Returns T when only the base has unspent outputs for TXID — iterator
discovers them through the empty cache."
  (%with-tmp-leveldb-path (path)
    (let ((txid (%sample-txid 10)))
      ;; Pre-populate the base directly.
      (bitcoin-lisp.storage:with-coins-view-db (view path)
        (bitcoin-lisp.storage:coins-view-db-put
         view (bitcoin-lisp.storage::make-utxo-key txid 0) (%sample-utxo-entry)))
      (bitcoin-lisp.storage:with-coins-view-db (view path)
        (let ((cache (bitcoin-lisp.storage:make-coins-view-cache view)))
          (is (bitcoin-lisp.storage:coin-view-any-utxo-for-txid-p cache txid))
          ;; A different txid should miss.
          (is (not (bitcoin-lisp.storage:coin-view-any-utxo-for-txid-p
                    cache (%sample-txid 11)))))))))

(test coin-view-any-utxo-for-txid-p-cache-tombstone-supersedes-base
  "Base has the coin, but the cache tombstones it — must report absent."
  (%with-tmp-leveldb-path (path)
    (let ((txid (%sample-txid 12)))
      (bitcoin-lisp.storage:with-coins-view-db (view path)
        (bitcoin-lisp.storage:coins-view-db-put
         view (bitcoin-lisp.storage::make-utxo-key txid 0) (%sample-utxo-entry)))
      (bitcoin-lisp.storage:with-coins-view-db (view path)
        (let ((cache (bitcoin-lisp.storage:make-coins-view-cache view)))
          ;; Spend pulls the coin through cache then tombstones it.
          (is (not (null (bitcoin-lisp.storage:coin-view-spend cache txid 0))))
          (is (not (bitcoin-lisp.storage:coin-view-any-utxo-for-txid-p
                    cache txid))))))))

;;;; coin-view-apply-block / coin-view-disconnect-block round-trip

(defun %make-test-block (transactions)
  "Wrap TRANSACTIONS in a bitcoin-block with a stub header."
  (bitcoin-lisp.serialization:make-bitcoin-block
   :header (bitcoin-lisp.serialization:make-block-header
            :version 1
            :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
            :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
            :timestamp 0 :bits 0 :nonce 0
            :cached-hash (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element #xBB))
   :transactions transactions))

(defun %make-coinbase-tx (txid value script)
  (bitcoin-lisp.serialization:make-transaction
   :version 1
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output
                  (bitcoin-lisp.serialization:make-outpoint
                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                       :initial-element 0)
                   :index #xFFFFFFFF)
                  :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                            :initial-element 1)))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value value :script-pubkey script))
   :lock-time 0
   :cached-hash txid))

(defun %make-spending-tx (txid prev-txid prev-index value script)
  (bitcoin-lisp.serialization:make-transaction
   :version 1
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output
                  (bitcoin-lisp.serialization:make-outpoint
                   :hash prev-txid :index prev-index)
                  :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                            :initial-element 2)))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
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
      (bitcoin-lisp.storage:coin-view-add cache prev-txid 0
                                          9000000 script 5)
      (let* ((block (%make-test-block
                     (list (%make-coinbase-tx cb-txid 500000000 script)
                           (%make-spending-tx spend-txid prev-txid 0
                                              8000000 script))))
             (spent (bitcoin-lisp.storage:coin-view-apply-block cache block 10)))
        ;; Undo data captured the spent UTXO.
        (is (= 1 (length spent)))
        (is (equalp prev-txid (first (first spent))))
        (is (= 0 (second (first spent))))
        (is (= 9000000 (bitcoin-lisp.storage:utxo-entry-value
                        (third (first spent)))))
        ;; After apply: coinbase output + spending output present,
        ;; prev-txid:0 absent.
        (is (bitcoin-lisp.storage:coin-view-has-p cache cb-txid 0))
        (is (bitcoin-lisp.storage:coin-view-has-p cache spend-txid 0))
        (is (not (bitcoin-lisp.storage:coin-view-has-p cache prev-txid 0)))
        ;; Disconnect: undoes the block.
        (bitcoin-lisp.storage:coin-view-disconnect-block cache block spent)
        (is (not (bitcoin-lisp.storage:coin-view-has-p cache cb-txid 0)))
        (is (not (bitcoin-lisp.storage:coin-view-has-p cache spend-txid 0)))
        (let ((restored (bitcoin-lisp.storage:coin-view-get cache prev-txid 0)))
          (is (not (null restored)))
          (is (= 9000000 (bitcoin-lisp.storage:utxo-entry-value restored)))
          (is (= 5 (bitcoin-lisp.storage:utxo-entry-height restored))))))))

(test coin-view-apply-block-coinbase-only
  "A block with just a coinbase produces no undo data."
  (%with-tmp-cache (cache)
    (let* ((script (%sample-script))
           (cb-txid (%sample-txid #x03))
           (block (%make-test-block
                   (list (%make-coinbase-tx cb-txid 500000000 script)))))
      (let ((spent (bitcoin-lisp.storage:coin-view-apply-block cache block 1)))
        (is (null spent))
        (is (bitcoin-lisp.storage:coin-view-has-p cache cb-txid 0))))))

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
      (let ((spent (bitcoin-lisp.storage:coin-view-apply-block cache block 100)))
        (is (= 1 (length spent)))
        ;; After apply: cb-txid:0 is gone (spent intra-block).
        ;; intra-txid:0 is unspent.
        (is (not (bitcoin-lisp.storage:coin-view-has-p cache cb-txid 0)))
        (is (bitcoin-lisp.storage:coin-view-has-p cache intra-txid 0))
        ;; Now disconnect. After the fix, the cache must be empty
        ;; (no stale unspent entries).
        (bitcoin-lisp.storage:coin-view-disconnect-block cache block spent)
        (is (not (bitcoin-lisp.storage:coin-view-has-p cache cb-txid 0)))
        (is (not (bitcoin-lisp.storage:coin-view-has-p cache intra-txid 0)))
        ;; Critical: re-applying the same block must succeed. With the
        ;; old buggy order, cb-txid:0 was left in the cache as
        ;; unspent, so this would raise "refusing to overwrite unspent
        ;; coin" via the bip30 guard on coins-view-cache-add.
        (let ((spent2 (bitcoin-lisp.storage:coin-view-apply-block cache block 100)))
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
    (let ((set (bitcoin-lisp.storage:make-utxo-set))
          (txid (%sample-txid 42))
          (script (%sample-script)))
      ;; Same operation on both views.
      (bitcoin-lisp.storage:add-utxo set   txid 0 12345 script 99)
      (bitcoin-lisp.storage:add-utxo cache txid 0 12345 script 99)
      ;; Same observable result.
      (let ((from-set   (bitcoin-lisp.storage:get-utxo set   txid 0))
            (from-cache (bitcoin-lisp.storage:get-utxo cache txid 0)))
        (is (not (null from-set)))
        (is (not (null from-cache)))
        (is (= 12345 (bitcoin-lisp.storage:utxo-entry-value from-set)))
        (is (= 12345 (bitcoin-lisp.storage:utxo-entry-value from-cache)))))))

(test polymorphic-apply-block-utxo-set-and-cache-parity
  "apply-block-to-utxo-set / disconnect-block-from-utxo-set produce the
same undo data shape and end-state on utxo-set vs coins-view-cache."
  (%with-tmp-cache (cache)
    (let* ((set (bitcoin-lisp.storage:make-utxo-set))
           (script (%sample-script))
           (prev-txid (%sample-txid #xDD))
           (cb-txid (%sample-txid #x01))
           (spend-txid (%sample-txid #x02))
           (block (%make-test-block
                   (list (%make-coinbase-tx cb-txid 500000000 script)
                         (%make-spending-tx spend-txid prev-txid 0
                                            8000000 script)))))
      ;; Seed both views with the same prev UTXO.
      (bitcoin-lisp.storage:add-utxo set   prev-txid 0 9000000 script 5)
      (bitcoin-lisp.storage:add-utxo cache prev-txid 0 9000000 script 5)
      (let ((spent-set   (bitcoin-lisp.storage:apply-block-to-utxo-set set   block 10))
            (spent-cache (bitcoin-lisp.storage:apply-block-to-utxo-set cache block 10)))
        (is (= 1 (length spent-set)))
        (is (= 1 (length spent-cache)))
        ;; Undo data shape is identical (txid index entry).
        (is (equalp (first (first spent-set)) (first (first spent-cache))))
        (is (= (second (first spent-set)) (second (first spent-cache))))
        ;; End-state: outputs present, prev absent.
        (is (bitcoin-lisp.storage:utxo-exists-p set   cb-txid 0))
        (is (bitcoin-lisp.storage:utxo-exists-p cache cb-txid 0))
        (is (not (bitcoin-lisp.storage:utxo-exists-p set   prev-txid 0)))
        (is (not (bitcoin-lisp.storage:utxo-exists-p cache prev-txid 0)))
        ;; Round-trip back via disconnect.
        (bitcoin-lisp.storage:disconnect-block-from-utxo-set set   block spent-set)
        (bitcoin-lisp.storage:disconnect-block-from-utxo-set cache block spent-cache)
        (is (bitcoin-lisp.storage:utxo-exists-p set   prev-txid 0))
        (is (bitcoin-lisp.storage:utxo-exists-p cache prev-txid 0))))))

(test polymorphic-any-utxo-for-txid-p-parity
  (%with-tmp-cache (cache)
    (let ((set (bitcoin-lisp.storage:make-utxo-set))
          (txid (%sample-txid 7))
          (other (%sample-txid 8))
          (script (%sample-script)))
      (bitcoin-lisp.storage:add-utxo set   txid 0 1 script 1)
      (bitcoin-lisp.storage:add-utxo cache txid 0 1 script 1)
      (is (bitcoin-lisp.storage:any-utxo-for-txid-p set   txid))
      (is (bitcoin-lisp.storage:any-utxo-for-txid-p cache txid))
      (is (not (bitcoin-lisp.storage:any-utxo-for-txid-p set   other)))
      (is (not (bitcoin-lisp.storage:any-utxo-for-txid-p cache other))))))

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
    (bitcoin-lisp.storage:add-utxo view txid-a 0 100 script 1)
    (bitcoin-lisp.storage:add-utxo view txid-a 1 200 script 1)
    (bitcoin-lisp.storage:add-utxo view txid-b 0 300 script 1)
    (values txid-a txid-b script)))

(test polymorphic-utxo-set-iterate-parity
  "utxo-set-iterate emits the same (txid, vout, entry) sequence on
both views for the same seed data."
  (%with-tmp-cache (cache)
    (let ((set (bitcoin-lisp.storage:make-utxo-set))
          (set-emits '())
          (cache-emits '()))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (bitcoin-lisp.storage:utxo-set-iterate
       set
       (lambda (txid vout entry)
         (push (list (copy-seq txid) vout (bitcoin-lisp.storage:utxo-entry-value entry))
               set-emits)))
      (bitcoin-lisp.storage:utxo-set-iterate
       cache
       (lambda (txid vout entry)
         (push (list (copy-seq txid) vout (bitcoin-lisp.storage:utxo-entry-value entry))
               cache-emits)))
      (is (= 3 (length set-emits)))
      (is (= 3 (length cache-emits)))
      (is (equalp (nreverse set-emits) (nreverse cache-emits))))))

(test polymorphic-utxo-set-total-amount-parity
  (%with-tmp-cache (cache)
    (let ((set (bitcoin-lisp.storage:make-utxo-set)))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (is (= 600 (bitcoin-lisp.storage:utxo-set-total-amount set)))
      (is (= 600 (bitcoin-lisp.storage:utxo-set-total-amount cache))))))

(test polymorphic-utxo-set-distinct-txids-parity
  "Two outputs of txid-a + one of txid-b = 2 distinct txids."
  (%with-tmp-cache (cache)
    (let ((set (bitcoin-lisp.storage:make-utxo-set)))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (is (= 2 (bitcoin-lisp.storage:utxo-set-distinct-txids set)))
      (is (= 2 (bitcoin-lisp.storage:utxo-set-distinct-txids cache))))))

(test polymorphic-compute-utxo-set-hash-parity
  "The hash_serialized_3 digest is byte-identical across views."
  (%with-tmp-cache (cache)
    (let ((set (bitcoin-lisp.storage:make-utxo-set)))
      (%seed-three-coins set)
      (%seed-three-coins cache)
      (is (equalp (bitcoin-lisp.storage:compute-utxo-set-hash set)
                  (bitcoin-lisp.storage:compute-utxo-set-hash cache))))))

(test polymorphic-iterate-cache-flushes-first
  "Iterating a coins-view-cache flushes it as a side-effect — after
the call, cvc-entries is empty and the data is in the base."
  (%with-tmp-cache (cache)
    (%seed-three-coins cache)
    (is (= 3 (hash-table-count
              (bitcoin-lisp.storage::cvc-entries cache))))
    (bitcoin-lisp.storage:utxo-set-iterate
     cache (lambda (txid vout entry)
             (declare (ignore txid vout entry))))
    (is (zerop (hash-table-count
                (bitcoin-lisp.storage::cvc-entries cache))))))

(test polymorphic-iterate-cache-merges-flushed-base-and-recent-adds
  "After a partial flush, the next iterate still sees everything —
because iterate itself flushes again before walking the base."
  (%with-tmp-cache (cache)
    ;; First batch — flush manually.
    (bitcoin-lisp.storage:add-utxo cache (%sample-txid 1) 0 10 (%sample-script) 1)
    (bitcoin-lisp.storage:coins-view-cache-flush cache)
    ;; Second batch — leave dirty.
    (bitcoin-lisp.storage:add-utxo cache (%sample-txid 2) 0 20 (%sample-script) 2)
    (is (= 30 (bitcoin-lisp.storage:utxo-set-total-amount cache)))))

;;;; Coins-cache memory accounting (Bitcoin Core dbcache byte bound)

(defun %overhead () bitcoin-lisp.storage::+coins-cache-entry-overhead-bytes+)

(test coins-cache-mem-bytes-fresh-zero
  "A fresh cache reports 0 bytes; an empty utxo-set view also reports 0."
  (%with-tmp-cache (cache)
    (is (= 0 (bitcoin-lisp.storage:view-mem-bytes cache))))
  (is (= 0 (bitcoin-lisp.storage:view-mem-bytes (bitcoin-lisp.storage:make-utxo-set)))))

(test coins-cache-mem-bytes-add-rises
  "Each add raises usage by overhead + scriptPubKey length."
  (%with-tmp-cache (cache)
    (bitcoin-lisp.storage:coins-view-cache-add cache (%sample-utxo-key 1 0)
                                               (%sample-utxo-entry))     ; 25-byte script
    (is (= (+ (%overhead) 25) (bitcoin-lisp.storage:view-mem-bytes cache)))
    (bitcoin-lisp.storage:coins-view-cache-add cache (%sample-utxo-key 2 0)
                                               (%sample-utxo-entry))
    (is (= (* 2 (+ (%overhead) 25)) (bitcoin-lisp.storage:view-mem-bytes cache)))))

(test coins-cache-mem-bytes-spend-fresh-drops
  "Spending a fresh (in-cache-only) coin reclaims its full bytes."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 5 0)))
      (bitcoin-lisp.storage:coins-view-cache-add cache k (%sample-utxo-entry))
      (is (= (+ (%overhead) 25) (bitcoin-lisp.storage:view-mem-bytes cache)))
      (bitcoin-lisp.storage:coins-view-cache-spend cache k)
      (is (= 0 (bitcoin-lisp.storage:view-mem-bytes cache))))))

(test coins-cache-mem-bytes-reuse-delta
  "Overwriting an entry adjusts usage by the script-size delta, not double-count."
  (%with-tmp-cache (cache)
    (let ((k (%sample-utxo-key 6 0))
          (small (bitcoin-lisp.storage:make-utxo-entry
                  :value 1 :height 1 :coinbase nil
                  :script-pubkey (make-array 10 :element-type '(unsigned-byte 8)))))
      (bitcoin-lisp.storage:coins-view-cache-add cache k (%sample-utxo-entry)) ; 25
      (bitcoin-lisp.storage:coins-view-cache-add cache k small :allow-overwrite t) ; 10
      (is (= (+ (%overhead) 10) (bitcoin-lisp.storage:view-mem-bytes cache))))))

(test coins-cache-mem-bytes-non-fresh-spend-keeps-overhead
  "A non-fresh spend frees the script bytes but the tombstone keeps the overhead."
  (%with-tmp-leveldb-path (path)
    (let ((k (%sample-utxo-key 7 0)))
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (bitcoin-lisp.storage:coins-view-db-put base k (%sample-utxo-entry)))
      (bitcoin-lisp.storage:with-coins-view-db (base path)
        (let ((cache (bitcoin-lisp.storage:make-coins-view-cache base)))
          ;; A read pulls the base coin into the cache (non-fresh).
          (bitcoin-lisp.storage:coins-view-cache-get cache k)
          (is (= (+ (%overhead) 25) (bitcoin-lisp.storage:view-mem-bytes cache)))
          (bitcoin-lisp.storage:coins-view-cache-spend cache k)
          (is (= (%overhead) (bitcoin-lisp.storage:view-mem-bytes cache))))))))

(test coins-cache-mem-bytes-flush-resets
  "Flush clears the cache and resets usage to 0."
  (%with-tmp-cache (cache)
    (dotimes (i 5)
      (bitcoin-lisp.storage:coins-view-cache-add cache (%sample-utxo-key (1+ i) 0)
                                                 (%sample-utxo-entry)))
    (is (= (* 5 (+ (%overhead) 25)) (bitcoin-lisp.storage:view-mem-bytes cache)))
    (bitcoin-lisp.storage:coins-view-cache-flush cache)
    (is (= 0 (bitcoin-lisp.storage:view-mem-bytes cache)))))

(test large-coins-cache-threshold-matches-core
  "large-coins-cache-threshold = max(0.9*budget, budget-10MiB) (Core)."
  (let ((mib (* 1024 1024)))
    ;; 450 MiB budget: budget-10MiB (440) > 0.9*budget (405) -> 440 MiB.
    (is (= (* 440 mib) (bitcoin-lisp::large-coins-cache-threshold (* 450 mib))))
    ;; 100 MiB budget: both terms equal 90 MiB.
    (is (= (* 90 mib) (bitcoin-lisp::large-coins-cache-threshold (* 100 mib))))))

(test header-index-v1-file-still-loads
  "A v1-format header index (181-byte entries, no tx-count) still loads after
the v2 format bump; its entries get tx-count 0 for lazy backfill. A v1-load
regression would silently force a from-genesis resync on deploy."
  (let* ((tmp-dir (merge-pathnames "test-hidx-v1/" (uiop:temporary-directory)))
         (cs (bitcoin-lisp.storage:make-chain-state :base-path tmp-dir))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 0)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 1)
                  :timestamp 1231006505 :bits #x1d00ffff :nonce 0))
         (hash (bitcoin-lisp.serialization:block-header-hash header)))
    (ensure-directories-exist (merge-pathnames "dummy" tmp-dir))
    (unwind-protect
         (progn
           ;; Hand-assemble: magic + version 1 + count 1 + one v1 entry + CRC32.
           (let* ((data (flexi-streams:with-output-to-sequence (s)
                          (write-sequence
                           (map '(vector (unsigned-byte 8)) #'char-code "HIDX") s)
                          (bitcoin-lisp.serialization:write-uint32-le s 1) ; version
                          (bitcoin-lisp.serialization:write-uint32-le s 1) ; count
                          (write-sequence hash s)
                          (bitcoin-lisp.serialization:write-uint32-le s 7) ; height
                          (write-sequence
                           (bitcoin-lisp.serialization:serialize-block-header header) s)
                          (let ((cw (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))
                            (setf (aref cw 31) 42)                  ; chainwork 42 (BE)
                            (write-sequence cw s))
                          (write-byte 2 s)                          ; status :valid
                          (write-sequence (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0) s)))
                  (bytes (coerce data '(simple-array (unsigned-byte 8) (*)))))
             (with-open-file (out (bitcoin-lisp.storage::header-index-file-path cs)
                                  :direction :output :if-exists :supersede
                                  :element-type '(unsigned-byte 8))
               (write-sequence bytes out)
               (write-sequence (bitcoin-lisp.storage:compute-crc32 bytes) out)))
           (is-true (bitcoin-lisp.storage:load-header-index cs))
           (let ((entry (bitcoin-lisp.storage:get-block-index-entry cs hash)))
             (is (not (null entry)))
             (is (= 7 (bitcoin-lisp.storage:block-index-entry-height entry)))
             (is (= 42 (bitcoin-lisp.storage:block-index-entry-chain-work entry)))
             (is (= 0 (bitcoin-lisp.storage:block-index-entry-tx-count entry)))))
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
           (let ((buf (bitcoin-lisp.serialization:make-byte-buf)))
             (dolist (e elements)
               (bitcoin-lisp.serialization:bb-write-bytes buf e))
             (bitcoin-lisp.crypto:hash256
              (bitcoin-lisp.serialization:bb-finish buf))))
         (streamed (elements)
           (let ((digest (ironclad:make-digest :sha256)))
             (dolist (e elements) (ironclad:update-digest digest e))
             (bitcoin-lisp.crypto:sha256 (ironclad:produce-digest digest)))))
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
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
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
        (bitcoin-lisp.storage:add-utxo
         utxo-set txid vout (+ 1000 vout)
         (make-array 1 :element-type '(unsigned-byte 8)) 1)))
    (let ((oracle (let ((seen (make-hash-table :test 'equalp)))
                    (bitcoin-lisp.storage:utxo-set-iterate
                     utxo-set (lambda (txid vout entry)
                                (declare (ignore vout entry))
                                (setf (gethash txid seen) t)))
                    (hash-table-count seen))))
      (is (= (length txids) oracle) "the oracle sees every txid")
      (is (= oracle (bitcoin-lisp.storage:utxo-set-distinct-txids utxo-set))
          "transition counting agrees with collecting")
      ;; control: the assertion must be able to fail
      (is (/= (1+ oracle) (bitcoin-lisp.storage:utxo-set-distinct-txids utxo-set))))))

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
         (state (bitcoin-lisp.storage:make-chain-state :base-path dir))
         (path (bitcoin-lisp.storage::state-file-path state)))
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
           (is (null (bitcoin-lisp.storage:load-state state))
               "no file at all is a first run, not corruption")
           ;; A size no version recognizes: corruption.
           (write-bytes 41)
           (is (eq :corrupt (bitcoin-lisp.storage:load-state state))
               "a 41-byte file matches no format and must report corruption")
           (write-bytes 7)
           (is (eq :corrupt (bitcoin-lisp.storage:load-state state)))
           ;; A v3-sized file whose CRC cannot verify: corruption, not absence.
           (write-bytes 45)
           (is (eq :corrupt (bitcoin-lisp.storage:load-state state))
               "a v3-sized file with a bad CRC must report corruption")
           ;; Control: a legitimately-sized legacy file still loads, so the
           ;; check above rejects by integrity rather than rejecting everything.
           (write-bytes 40)
           (is (eq t (bitcoin-lisp.storage:load-state state))
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
    (let* ((base (bitcoin-lisp.storage:open-coins-view-db db-path))
           (cache (bitcoin-lisp.storage:make-coins-view-cache base))
           (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
      (unwind-protect
           (progn
             ;; Control: nothing recorded before the first flush that supplies it.
             (is (null (bitcoin-lisp.storage:coins-view-db-best-block base))
                 "a fresh coins DB has no best-block pointer")
             (bitcoin-lisp.storage:coin-view-add
              cache txid 0 5000 (make-array 1 :element-type '(unsigned-byte 8)) 1)
             ;; A flush WITHOUT a tip must not invent one.
             (bitcoin-lisp.storage:coins-view-cache-flush cache)
             (is (null (bitcoin-lisp.storage:coins-view-db-best-block base))
                 "a flush that does not know its tip leaves the pointer alone")
             ;; A flush WITH a tip records it alongside the coins.
             (bitcoin-lisp.storage:coin-view-add
              cache txid 1 6000 (make-array 1 :element-type '(unsigned-byte 8)) 1)
             (bitcoin-lisp.storage:coins-view-cache-flush cache :best-block tip)
             (is (equalp tip (bitcoin-lisp.storage:coins-view-db-best-block base))
                 "the tip is durable in the coins DB")
             ;; and the coins from that same batch are there too — the point is
             ;; that they commit together, so both halves must be observable.
             (is (not (null (bitcoin-lisp.storage:coin-view-get cache txid 1)))
                 "the coins written in that batch are present")
             ;; control: a different hash must not compare equal
             (is (not (equalp (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 3)
                              (bitcoin-lisp.storage:coins-view-db-best-block base)))))
        (bitcoin-lisp.storage:close-coins-view-db base)))))

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
    (let* ((base (bitcoin-lisp.storage:open-coins-view-db db-path))
           (cache (bitcoin-lisp.storage:make-coins-view-cache base))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
           (script (make-array 1 :element-type '(unsigned-byte 8))))
      (unwind-protect
           (flet ((count-coins ()
                    (let ((n 0))
                      (bitcoin-lisp.storage:utxo-set-iterate
                       cache (lambda (txid vout entry)
                               (declare (ignore txid vout entry))
                               (incf n)))
                      n)))
             (dotimes (i 5)
               (let ((txid (make-array 32 :element-type '(unsigned-byte 8)
                                          :initial-element (+ 10 i))))
                 (bitcoin-lisp.storage:coin-view-add cache txid 0 (* 1000 (1+ i)) script 1)))
             ;; Baseline: no metadata key yet.
             (bitcoin-lisp.storage:coins-view-cache-flush cache)
             (let ((without-metadata (count-coins)))
               (is (= 5 without-metadata) "all coins iterate before any metadata key exists")
               ;; Now write a key that sorts BEFORE the coin prefix.
               (bitcoin-lisp.storage:coins-view-cache-flush cache :best-block tip)
               (is (equalp tip (bitcoin-lisp.storage:coins-view-db-best-block base))
                   "the metadata key really is present")
               (is (= without-metadata (count-coins))
                   "a key sorting before the coins must not truncate the scan")
               (is (plusp (bitcoin-lisp.storage:utxo-set-total-amount cache))
                   "and derived totals stay non-zero")))
        (bitcoin-lisp.storage:close-coins-view-db base)))))

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
    (let* ((base (bitcoin-lisp.storage:open-coins-view-db db-path))
           (cache (bitcoin-lisp.storage:make-coins-view-cache base))
           (parent (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
           (this-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
           (coinbase (bitcoin-lisp.tests::%make-coinbase-tx
                      (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                      5000
                      (make-array 1 :element-type '(unsigned-byte 8))))
           (block (bitcoin-lisp.serialization:make-bitcoin-block
                   :header (bitcoin-lisp.serialization:make-block-header
                            :version 1 :prev-block parent
                            :merkle-root (make-array 32 :element-type '(unsigned-byte 8))
                            :timestamp 0 :bits 0 :nonce 0
                            :cached-hash this-block)
                   :transactions (list coinbase))))
      (unwind-protect
           (progn
             ;; Control: nothing tracked before any block is applied.
             (is (null (bitcoin-lisp.storage::cvc-best-block cache))
                 "a fresh cache tracks no block")
             ;; Connect: the pointer becomes THIS block.
             (let ((spent (bitcoin-lisp.storage:apply-block-to-utxo-set cache block 1)))
               (declare (ignore spent))
               (is (equalp this-block (bitcoin-lisp.storage::cvc-best-block cache))
                   "applying a block moves the pointer to that block"))
             ;; A flush with no explicit hash stamps what the cache tracks.
             (bitcoin-lisp.storage:coins-view-cache-flush cache)
             (is (equalp this-block (bitcoin-lisp.storage:coins-view-db-best-block base))
                 "the flush stamps the cache's own pointer, unasked")
             ;; Disconnect: the pointer becomes the PARENT, which is the case the
             ;; chain tip would get wrong.
             (bitcoin-lisp.storage:disconnect-block-from-utxo-set cache block '())
             (is (equalp parent (bitcoin-lisp.storage::cvc-best-block cache))
                 "disconnecting moves the pointer back to the parent")
             (bitcoin-lisp.storage:coins-view-cache-flush cache)
             (is (equalp parent (bitcoin-lisp.storage:coins-view-db-best-block base))
                 "and a flush mid-rewind records the parent, not the old tip")
             ;; Control: the two hashes must be distinguishable, or the
             ;; assertions above could pass on any value.
             (is (not (equalp parent this-block))))
        (bitcoin-lisp.storage:close-coins-view-db base)))))

(test coins-cache-adopts-the-stored-best-block-on-open
  "A freshly-opened cache must adopt the pointer already on disk. Otherwise it
reports NIL until the first block-level mutation, and a flush in between — a
shutdown flush, say — would move coins while leaving the pointer behind."
  (let ((db-path (ensure-directories-exist
                  (merge-pathnames (format nil "bl-bbadopt-~D/" (random 1000000))
                                   (uiop:temporary-directory)))))
    (let* ((base (bitcoin-lisp.storage:open-coins-view-db db-path))
           (tip (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xCC)))
      (unwind-protect
           (let ((writer (bitcoin-lisp.storage:make-coins-view-cache base)))
             (bitcoin-lisp.storage:coins-view-cache-flush writer :best-block tip)
             (let ((reopened (bitcoin-lisp.storage:make-coins-view-cache base)))
               ;; Control: without adopting, a fresh cache knows nothing.
               (is (null (bitcoin-lisp.storage::cvc-best-block reopened)))
               (bitcoin-lisp.storage:coins-view-cache-load-best-block reopened)
               (is (equalp tip (bitcoin-lisp.storage::cvc-best-block reopened))
                   "the reopened cache adopts what is on disk")))
        (bitcoin-lisp.storage:close-coins-view-db base)))))

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
         (chain-state (bitcoin-lisp.storage:init-chain-state base))
         (db (bitcoin-lisp.storage:open-coins-view-db
              (ensure-directories-exist (merge-pathnames "chainstate/" base))))
         (cache (bitcoin-lisp.storage:make-coins-view-cache db))
         (node (bitcoin-lisp::make-node))
         (coins-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xC0))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xF1)))
    (unwind-protect
         (progn
           (setf (bitcoin-lisp::node-chain-state node) chain-state
                 (bitcoin-lisp.storage:chain-state-coins-view chain-state) cache)
           ;; The chain believes it is at height 200; the coins are at 150.
           (dolist (pair (list (cons coins-hash 150) (cons tip-hash 200)))
             (bitcoin-lisp.storage:add-block-index-entry
              chain-state (bitcoin-lisp.storage:make-block-index-entry
                           :hash (car pair) :height (cdr pair)
                           :chain-work 0 :status :valid)))
           (bitcoin-lisp.storage:update-chain-tip chain-state tip-hash 200)
           ;; Control: with no pointer recorded there is nothing to reconcile.
           (is (eq :unrecorded (bitcoin-lisp::reconcile-coins-db-best-block node)))
           (is (= 200 (bitcoin-lisp.storage:current-height chain-state))
               "and the tip is left alone")
           ;; Now record where the coins actually are.
           (bitcoin-lisp.storage:coins-view-cache-flush cache :best-block coins-hash)
           (is (eq :reconciled (bitcoin-lisp::reconcile-coins-db-best-block node)))
           (is (= 150 (bitcoin-lisp.storage:current-height chain-state))
               "the tip record follows the coins")
           (is (equalp coins-hash (bitcoin-lisp.storage:best-block-hash chain-state)))
           ;; Idempotent: a second pass now agrees.
           (is (eq :match (bitcoin-lisp::reconcile-coins-db-best-block node)))
           ;; A pointer naming a block we cannot place is not silently accepted.
           (bitcoin-lisp.storage:coins-view-cache-flush
            cache :best-block (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element #xEE))
           (is (eq :unresolvable (bitcoin-lisp::reconcile-coins-db-best-block node))
               "an unplaceable UTXO set is reported, not guessed at"))
      (bitcoin-lisp.storage:close-coins-view-db db))))
