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

(test txospenderindex-records-and-finds-a-spend
  "The whole point: given an outpoint, say which transaction spent it. The
locator is the (block hash, offset) pair the txindex already uses, so a lookup
can read the spending transaction back and confirm it."
  (let ((dir (%tsi-tmpdir "find")))
    (unwind-protect
         (let ((idx (bl.store:init-txospender-index dir)))
           (unwind-protect
                (multiple-value-bind (block spender) (%tsi-spending-block
                                                      (list (%tsi-outpoint #xA1 0)
                                                            (%tsi-outpoint #xA2 7)))
                  (declare (ignore spender))
                  (let ((hash (bl.ser:block-header-hash
                               (bl.ser:bitcoin-block-header block))))
                    ;; Two inputs, so two entries — and the coinbase is skipped.
                    (is (= 2 (bl.store:txospenderindex-add-block idx block hash)))
                    (let ((locs (bl.store:txospenderindex-locators
                                 idx (bl.ser:outpoint-hash
                                      (%tsi-outpoint #xA1 0))
                                 0)))
                      (is (= 1 (length locs)))
                      (is (equalp hash (car (first locs))))
                      ;; The offset is the spending transaction's position in the
                      ;; block, so it is past the coinbase.
                      (is (plusp (cdr (first locs)))))
                    ;; The vout is part of the key, so a different index of the
                    ;; same txid is a different outpoint.
                    (is (null (bl.store:txospenderindex-locators
                               idx (bl.ser:outpoint-hash
                                    (%tsi-outpoint #xA1 0))
                               1)))
                    ;; And an outpoint nothing spent is simply absent.
                    (is (null (bl.store:txospenderindex-locators
                               idx (bl.ser:outpoint-hash
                                    (%tsi-outpoint #xFF 0))
                               0)))))
             (bl.store:close-txospender-index idx)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

(test txospenderindex-reorg-erases-exactly-what-it-wrote
  "⚠️ The reason this index needs a disconnect hook when the others do not.

coinstatsindex and blockfilterindex key their records on HEIGHT, so a reconnect
overwrites a disconnected block's record and a stale one is never read. A
spender key carries no height. After a reorg the disconnected block is still on
disk and still spends the outpoint, so an entry left behind resolves to a
spending transaction from an ABANDONED chain — a wrong answer, not a stale one.

Core erases through CustomRemove and builds the same outpoint list for both
sides from the block alone, which is what makes the erase exact
(index/txospenderindex.cpp:110-139)."
  (let ((dir (%tsi-tmpdir "reorg")))
    (unwind-protect
         (let ((idx (bl.store:init-txospender-index dir)))
           (unwind-protect
                (let* ((block (%tsi-spending-block (list (%tsi-outpoint #xB1 0))))
                       (hash (bl.ser:block-header-hash
                              (bl.ser:bitcoin-block-header block)))
                       (txid (bl.ser:outpoint-hash (%tsi-outpoint #xB1 0))))
                  (bl.store:txospenderindex-add-block idx block hash)
                  (is (= 1 (length (bl.store:txospenderindex-locators idx txid 0))))
                  (is (= 1 (bl.store:txospenderindex-remove-block idx block hash)))
                  (is (null (bl.store:txospenderindex-locators idx txid 0))
                      "a disconnected block left its spender entries behind")
                  ;; Idempotent: erasing twice is not an error and does not
                  ;; resurrect anything.
                  (bl.store:txospenderindex-remove-block idx block hash)
                  (is (null (bl.store:txospenderindex-locators idx txid 0))))
             (bl.store:close-txospender-index idx)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

(test txospenderindex-salt-survives-a-reopen
  "⚠️ The salt must be STABLE for the life of the database. Every key is
hash(salt, outpoint), so regenerating it on reopen would silently orphan every
record already written and the index would answer `not found' for every output
it had already indexed — with no error anywhere. Core persists it for the same
reason (index/txospenderindex.cpp:66-70)."
  (let ((dir (%tsi-tmpdir "salt")))
    (unwind-protect
         (let (k0 k1)
           (let ((idx (bl.store:init-txospender-index dir)))
             (setf k0 (bl.store::txospender-index-k0 idx)
                   k1 (bl.store::txospender-index-k1 idx))
             (let* ((block (%tsi-spending-block (list (%tsi-outpoint #xC1 0))))
                    (hash (bl.ser:block-header-hash
                           (bl.ser:bitcoin-block-header block))))
               (bl.store:txospenderindex-add-block idx block hash))
             (bl.store:close-txospender-index idx))
           ;; A fresh salt would be astronomically unlikely to repeat, so equal
           ;; keys means it was read back rather than regenerated.
           (let ((idx (bl.store:init-txospender-index dir)))
             (unwind-protect
                  (progn
                    (is (= k0 (bl.store::txospender-index-k0 idx)))
                    (is (= k1 (bl.store::txospender-index-k1 idx)))
                    ;; And the record written before the reopen is still findable.
                    (is (= 1 (length (bl.store:txospenderindex-locators
                                      idx
                                      (bl.ser:outpoint-hash
                                       (%tsi-outpoint #xC1 0))
                                      0)))))
               (bl.store:close-txospender-index idx))))
      (ignore-errors (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

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
        (is (null (bl.store:txospenderindex-locators
                   idx (bl.ser:outpoint-hash (%tsi-outpoint #xE1 0)) 0)))
        (is (null (bl.store:txospenderindex-best-block idx)))
        (is (= -1 (bl.store:txospenderindex-height idx)))))))
