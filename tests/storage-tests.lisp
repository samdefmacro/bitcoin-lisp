(in-package #:bitcoin-lisp.tests)

(in-suite :storage-tests)

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
