(in-package #:bitcoin-lisp.tests)

;;;; -dbcache split and LevelDB tuning (track C item 1)

(def-suite :db-cache-tests
  :description "Core's -dbcache split and the LevelDB block cache / bloom filter"
  :in :bitcoin-lisp-tests)

(in-suite :db-cache-tests)

(defun %mib (n) (floor n 1048576))

(test cache-split-is-core-s-arithmetic
  "Each index takes at most an EIGHTH OF WHAT IS LEFT, so the caps compound
rather than applying to the original total (CalculateCacheSizes,
node/caches.cpp:57-72, then kernel::CacheSizes). Worked through by hand for the
450 MiB default with txindex and two filter-style indexes:

  450      -> tx = min(450/8, 1024) = 56.25
  393.75   -> filter budget = min(393.75/8, 1024) = 49.22, /2 = 24.61 each
  344.53   -> block_tree = min(344.53/8, 2) = 2
  342.53   -> coins_db = min(342.53/2, 8) = 8
  334.53   -> coins"
  (let ((s (bitcoin-lisp.storage:calculate-cache-sizes
            (* 450 1024 1024) :tx-index t :filter-index-count 2)))
    (is (= 56 (%mib (bitcoin-lisp.storage:cache-sizes-tx-index s))))
    (is (= 24 (%mib (bitcoin-lisp.storage:cache-sizes-filter-index s))))
    (is (= 2 (%mib (bitcoin-lisp.storage:cache-sizes-block-tree-db s))))
    (is (= 8 (%mib (bitcoin-lisp.storage:cache-sizes-coins-db s))))
    (is (= 334 (%mib (bitcoin-lisp.storage:cache-sizes-coins s)))))
  ;; No indexes: everything past the two small DB caps is the coins cache.
  (let ((s (bitcoin-lisp.storage:calculate-cache-sizes (* 450 1024 1024))))
    (is (zerop (bitcoin-lisp.storage:cache-sizes-tx-index s)))
    (is (zerop (bitcoin-lisp.storage:cache-sizes-filter-index s)))
    (is (= 2 (%mib (bitcoin-lisp.storage:cache-sizes-block-tree-db s))))
    (is (= 8 (%mib (bitcoin-lisp.storage:cache-sizes-coins-db s))))
    ;; 450 - 2 (block tree) - 8 (coins db) = 440.
    (is (= 440 (%mib (bitcoin-lisp.storage:cache-sizes-coins s))))))

(test cache-split-never-overspends-or-goes-negative
  "The shares must sum to the budget and none may be negative, at every size —
including below Core's 4 MiB floor, where a naive split would hand the coins
cache a negative remainder."
  (dolist (mib '(4 8 16 100 450 1000 4000 16000))
    (dolist (indexes '(0 1 2 3))
      (dolist (tx '(nil t))
        (let* ((total (* mib 1024 1024))
               (s (bitcoin-lisp.storage:calculate-cache-sizes
                   total :tx-index tx :filter-index-count indexes))
               (parts (list (bitcoin-lisp.storage:cache-sizes-tx-index s)
                            (* indexes (bitcoin-lisp.storage:cache-sizes-filter-index s))
                            (bitcoin-lisp.storage:cache-sizes-block-tree-db s)
                            (bitcoin-lisp.storage:cache-sizes-coins-db s)
                            (bitcoin-lisp.storage:cache-sizes-coins s))))
          (is-true (every (lambda (p) (>= p 0)) parts)
                   "negative share at ~D MiB, ~D indexes, txindex ~A: ~S"
                   mib indexes tx parts)
          (is (<= (reduce #'+ parts) (max total bitcoin-lisp.storage::+min-db-cache-bytes+))
              "shares overspend the budget at ~D MiB, ~D indexes, txindex ~A"
              mib indexes tx)))))
  ;; Below the floor, Core clamps UP to MIN_DB_CACHE rather than dividing
  ;; something too small.
  (let ((s (bitcoin-lisp.storage:calculate-cache-sizes 1)))
    (is (plusp (bitcoin-lisp.storage:cache-sizes-coins s)))))

(test tuned-leveldb-open-round-trips-and-frees-its-cache
  "The block cache and the filter policy must outlive the database — leveldb_open
keeps the pointers the options carry — and must be destroyed after it closes, or
every index reopen leaks a whole cache. LEVELDB-CLOSE owns both halves of that."
  (let ((dir (merge-pathnames (format nil "bl-ldb-~D/" (get-internal-real-time))
                              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           (let ((db (bitcoin-lisp.storage:leveldb-open-tuned
                      dir :cache-bytes (* 8 1024 1024) :bloom-bits 10)))
             (is-true db)
             ;; The resources were registered against this handle.
             (is-true (gethash (cffi:pointer-address db)
                               bitcoin-lisp.storage::*leveldb-owned-resources*)
                      "the cache and filter were not recorded for freeing")
             (bitcoin-lisp.storage:leveldb-put db
                                               (map '(vector (unsigned-byte 8)) #'char-code "k")
                                               (map '(vector (unsigned-byte 8)) #'char-code "v"))
             (is (equalp (map '(vector (unsigned-byte 8)) #'char-code "v")
                         (bitcoin-lisp.storage:leveldb-get
                          db (map '(vector (unsigned-byte 8)) #'char-code "k"))))
             ;; A miss is what the bloom filter exists for; it must still be a
             ;; miss, not a false positive turned into a wrong value.
             (is-false (bitcoin-lisp.storage:leveldb-get
                        db (map '(vector (unsigned-byte 8)) #'char-code "absent")))
             (bitcoin-lisp.storage:leveldb-close db)
             (is-false (gethash (cffi:pointer-address db)
                                bitcoin-lisp.storage::*leveldb-owned-resources*)
                       "closing left the cache registered, so it leaked")))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore)))))

(test tuned-leveldb-open-without-a-cache-registers-nothing-to-free
  "cache-bytes 0 and bloom-bits 0 means leveldb's own defaults: nothing is
allocated, so nothing may be registered — a stale registry entry would be a
double free on the next handle that reused the address."
  (let ((dir (merge-pathnames (format nil "bl-ldb2-~D/" (get-internal-real-time))
                              (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (ensure-directories-exist dir)
           (let ((db (bitcoin-lisp.storage:leveldb-open-tuned
                      dir :cache-bytes 0 :bloom-bits 0)))
             (is-true db)
             (is-false (gethash (cffi:pointer-address db)
                                bitcoin-lisp.storage::*leveldb-owned-resources*))
             (bitcoin-lisp.storage:leveldb-close db)))
      (ignore-errors (uiop:delete-directory-tree dir :validate t
                                                    :if-does-not-exist :ignore)))))
