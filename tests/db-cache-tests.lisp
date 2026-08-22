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

;;;; Disconnect detectors and the FRESH rule (track C, §2.8)

(defun %dur-tx (&key (inputs '()) (outputs '((1000 #x51))) (marker 1))
  "A transaction spending INPUTS — a list of (txid index) — and paying OUTPUTS,
a list of (value script-byte). MARKER varies the txid."
  (bitcoin-lisp.serialization:make-transaction
   :version marker
   :inputs (coerce (loop for (txid index) in inputs
                         collect (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output
                                  (bitcoin-lisp.serialization:make-outpoint
                                   :hash txid :index index)
                                  :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                  :sequence #xFFFFFFFF))
                   'vector)
   :outputs (coerce (loop for (value byte) in outputs
                          collect (bitcoin-lisp.serialization:make-tx-out
                                   :value value
                                   :script-pubkey (coerce (vector byte)
                                                          '(simple-array (unsigned-byte 8) (*)))))
                    'vector)
   :lock-time 0))

(defun %dur-block (txs)
  (bitcoin-lisp.serialization:make-bitcoin-block
   :header (bitcoin-lisp.serialization:make-block-header)
   :transactions txs))

(defmacro %with-dur-cache ((cache) &body body)
  `(let ((path (merge-pathnames (format nil "bl-dur-~D/" (get-internal-real-time))
                                (uiop:temporary-directory))))
     (unwind-protect
          (bitcoin-lisp.storage:with-coins-view-db (base path)
            (let ((,cache (bitcoin-lisp.storage:make-coins-view-cache base)))
              ,@body))
       (ignore-errors (uiop:delete-directory-tree path :validate t
                                                       :if-does-not-exist :ignore)))))

(test disconnect-reports-an-output-that-does-not-match-the-block
  "Core requires every output it removes to be PRESENT and to match the block
exactly — value, script, height and coinbase flag — and calls any difference
\"transaction output mismatch\" (validation.cpp:2213-2219). We removed outputs
through a function that returns NIL silently, so a disconnect over a UTXO set
that disagreed with the block reported nothing and corrupted quietly."
  (%with-dur-cache (cache)
    (let* ((coinbase (%dur-tx :outputs '((5000 #x51)) :marker 1))
           (block (%dur-block (list coinbase))))
      ;; Clean: apply then disconnect.
      (let ((undo (bitcoin-lisp.storage:coin-view-apply-block cache block 7)))
        (is-true (bitcoin-lisp.storage:coin-view-disconnect-block
                  cache block undo :height 7)
                 "a matching disconnect was reported unclean"))
      ;; Absent: nothing was applied, so the output is already gone.
      (is-false (bitcoin-lisp.storage:coin-view-disconnect-block cache block '() :height 7)
                "a disconnect of an absent output was reported clean")
      ;; Present but WRONG: the stored coin disagrees with the block's output.
      (bitcoin-lisp.storage:coin-view-apply-block cache block 7)
      (let ((txid (bitcoin-lisp.serialization:transaction-hash coinbase)))
        (bitcoin-lisp.storage:coin-view-spend cache txid 0)
        (bitcoin-lisp.storage:coin-view-add
         cache txid 0 4999
         (coerce (vector #x51) '(simple-array (unsigned-byte 8) (*)))
         7 :coinbase t))
      (is-false (bitcoin-lisp.storage:coin-view-disconnect-block cache block '() :height 7)
                "a value mismatch was reported clean")
      ;; And a height mismatch, which is why HEIGHT is threaded down at all.
      (bitcoin-lisp.storage:coin-view-apply-block cache block 7)
      (is-false (bitcoin-lisp.storage:coin-view-disconnect-block
                 cache block '() :height 9)
                "a height mismatch was reported clean"))))

(test disconnect-reports-restoring-over-a-coin-that-is-already-there
  "Core checks HaveCoin BEFORE restoring an input and passes
possible_overwrite = !fClean — permissive about the operation, loud about the
observation (ApplyTxInUndo, validation.cpp:2146-2170). We passed
:allow-overwrite T unconditionally, which turned the guard off entirely."
  (%with-dur-cache (cache)
    (let* ((prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element #x77))
           (script (coerce (vector #x51) '(simple-array (unsigned-byte 8) (*))))
           (spender (%dur-tx :inputs (list (list prev-txid 0))
                             :outputs '((900 #x51)) :marker 2))
           (block (%dur-block (list (%dur-tx :outputs '((5000 #x51)) :marker 1)
                                    spender)))
           (entry (bitcoin-lisp.storage:make-utxo-entry
                   :value 1000 :script-pubkey script :height 3 :coinbase nil)))
      (bitcoin-lisp.storage:coin-view-apply-block cache block 7)
      ;; The coin the undo data restores is ALREADY present: an overwrite.
      (bitcoin-lisp.storage:coin-view-add cache prev-txid 0 1000 script 3)
      (is-false (bitcoin-lisp.storage:coin-view-disconnect-block
                 cache block (list (list prev-txid 0 entry)) :height 7)
                "restoring over a present coin was reported clean")
      ;; It still RESTORED it — Core does the add either way.
      (is-true (bitcoin-lisp.storage:get-utxo cache prev-txid 0)))))

(test fresh-is-never-set-when-an-overwrite-was-permitted
  "Core computes fresh ONLY inside `if (!possible_overwrite)` (coins.cpp:95-110)
and its comment names the hazard: a coin marked FRESH and then spent before the
flush is DROPPED from the cache, so its spentness never reaches the parent and
a real base row survives as UNSPENT. Silent UTXO corruption.

Both live callers take the overwrite path — :allow-overwrite is-coinbase for
outputs, and :allow-overwrite T for every restored input on disconnect — so
this was reachable on the reorg path, not a corner."
  (%with-dur-cache (cache)
    (let ((txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x22))
          (script (coerce (vector #x51) '(simple-array (unsigned-byte 8) (*)))))
      ;; Brand-new slot WITH overwrite permitted: not fresh.
      (bitcoin-lisp.storage:coin-view-add cache txid 0 1000 script 5
                                          :allow-overwrite t)
      (is (zerop (bitcoin-lisp.storage::cvc-fresh-count cache))
          "an overwrite-permitted add was marked FRESH")
      ;; Brand-new slot WITHOUT it: fresh, as before.
      (bitcoin-lisp.storage:coin-view-add cache txid 1 1000 script 5)
      (is (= 1 (bitcoin-lisp.storage::cvc-fresh-count cache))
          "a plain add stopped being FRESH"))))

(test coins-view-best-block-is-the-view-s-own-pointer
  "Reporting the chain TIP for a coins-view query is wrong partway through a
reorg's disconnect phase, where the tip still names the block being rewound away
from while the coins have already moved to its parent. Core reports
coins_view->GetBestBlock() (rpc/blockchain.cpp:1083), and it matters beyond
cosmetics: hash_serialized_3 IS the assumeutxo commitment, so hashing one set of
coins and labelling it with another block's hash commits to nothing."
  (%with-dur-cache (cache)
    ;; A fresh cache tracks no block yet.
    (is-false (bitcoin-lisp.storage:coins-view-best-block cache))
    (let* ((coinbase (%dur-tx :outputs '((5000 #x51)) :marker 1))
           (block (%dur-block (list coinbase)))
           (hash (bitcoin-lisp.serialization:block-header-hash
                  (bitcoin-lisp.serialization:bitcoin-block-header block))))
      ;; Applying a block moves the pointer to that block...
      (bitcoin-lisp.storage:apply-block-to-utxo-set cache block 7)
      (is (equalp hash (bitcoin-lisp.storage:coins-view-best-block cache)))
      ;; ...and disconnecting it moves the pointer to the PARENT, which is
      ;; precisely where it diverges from the chain tip.
      (bitcoin-lisp.storage:disconnect-block-from-utxo-set
       cache block '() :height 7)
      (is (equalp (bitcoin-lisp.serialization:block-header-prev-block
                   (bitcoin-lisp.serialization:bitcoin-block-header block))
                  (bitcoin-lisp.storage:coins-view-best-block cache))
          "the disconnect left the pointer on the block it rewound away from")))
  ;; A test-only utxo-set tracks nothing, so callers fall back to the tip.
  (is-false (bitcoin-lisp.storage:coins-view-best-block
             (bitcoin-lisp.storage:make-utxo-set))))

(test sig-cache-keys-are-salted
  "Core salts its signature-cache hasher with a random per-process nonce
(sigcache.cpp:25-32). Unsalted, the key is plain SHA256 over public data, so
anyone can compute the key for any (sighash, pubkey, signature) triple offline
— and an adversary who knows the keys can choose transactions whose entries
collide, or whose insertion order evicts the entries a validating node is about
to need."
  (let* ((sighash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2))
         (sig (make-array 71 :element-type '(unsigned-byte 8) :initial-element 3))
         (bitcoin-lisp.coalton.interop::*script-flags* nil)
         (under-salt-a
           (let ((bitcoin-lisp.coalton.interop::*sig-cache-salt*
                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA)))
             (bitcoin-lisp.coalton.interop::make-sig-cache-key #x45 sighash sig pubkey)))
         (under-salt-b
           (let ((bitcoin-lisp.coalton.interop::*sig-cache-salt*
                   (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB)))
             (bitcoin-lisp.coalton.interop::make-sig-cache-key #x45 sighash sig pubkey))))
    ;; The same triple keys differently under different salts — which is the
    ;; whole property.
    (is (not (equalp under-salt-a under-salt-b))
        "the salt does not reach the key: it is computable offline")
    ;; And the salt is 32 random bytes, not a constant someone can look up.
    (is (= 32 (length bitcoin-lisp.coalton.interop::*sig-cache-salt*)))
    (is (notevery (lambda (b) (= b (aref bitcoin-lisp.coalton.interop::*sig-cache-salt* 0)))
                  bitcoin-lisp.coalton.interop::*sig-cache-salt*)
        "the salt looks constant, not random"))
  ;; Determinism within one salt is what makes the cache a cache at all.
  (let ((sighash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
        (pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element 8))
        (sig (make-array 64 :element-type '(unsigned-byte 8) :initial-element 7)))
    (is (equalp (bitcoin-lisp.coalton.interop::make-sig-cache-key #x53 sighash sig pubkey)
                (bitcoin-lisp.coalton.interop::make-sig-cache-key #x53 sighash sig pubkey)))
    ;; ECDSA and Schnorr are distinct domains, as Core keeps them with
    ;; different padding.
    (is (not (equalp
              (bitcoin-lisp.coalton.interop::make-sig-cache-key #x45 sighash sig pubkey)
              (bitcoin-lisp.coalton.interop::make-sig-cache-key #x53 sighash sig pubkey))))))

(test sig-cache-still-keys-on-script-flags
  "Core does NOT key on script flags, because it validates the flag-dependent
signature ENCODING before consulting the cache. Ours does the opposite —
cached-verify-ecdsa passes :strict and :low-s into the verify, which runs only
on a MISS — so the flags in the key are what stops a signature cached under lax
flags from being reported valid under strict ones.

This test pins that dependency so the flags cannot be dropped as a
\"key-format cleanup\" without hoisting the encoding checks first. Doing one
without the other is a consensus bug."
  (let* ((sighash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))
         (pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element 5))
         (sig (make-array 71 :element-type '(unsigned-byte 8) :initial-element 6))
         (lax (let ((bitcoin-lisp.coalton.interop::*script-flags* nil))
                (bitcoin-lisp.coalton.interop::make-sig-cache-key #x45 sighash sig pubkey)))
         (strict (let ((bitcoin-lisp.coalton.interop::*script-flags* "DERSIG,LOW_S"))
                   (bitcoin-lisp.coalton.interop::make-sig-cache-key #x45 sighash sig pubkey))))
    (is (not (equalp lax strict))
        "the same signature keys identically under different script flags — a \
signature accepted under lax flags would be served from cache under strict ones")))
