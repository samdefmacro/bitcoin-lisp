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

(test script-execution-cache-keys-on-wtxid-and-flags
  "Core CheckInputScripts hashes the WTXID and the flags word into its salted
hasher (validation.cpp:2077) and short-circuits every input script on a hit.

Both halves of the key matter. The WTXID, not the txid, because the witness is
where the signatures live — keying on the txid would let a malleated copy hit
an entry earned by the original. And the FLAGS, unlike the signature cache,
because the entry means \"these scripts SUCCEEDED under these rules\" and the
rules change at soft-fork heights."
  (let ((wtxid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (wtxid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
    (flet ((key (wtxid flags)
             (bitcoin-lisp.coalton.interop::make-script-execution-cache-key
              wtxid flags)))
      (is (equalp (key wtxid-a "P2SH") (key wtxid-a "P2SH")))
      (is (not (equalp (key wtxid-a "P2SH") (key wtxid-b "P2SH")))
          "two transactions share a script-execution cache entry")
      (is (not (equalp (key wtxid-a "P2SH") (key wtxid-a "P2SH,TAPROOT")))
          "the same transaction keys identically under different script flags")
      ;; The flag string is length-prefixed, so a split cannot collide: "AB"+""
      ;; and "A"+"B" must not produce the same key.
      (is (not (equalp (key wtxid-a "AB") (key wtxid-a "A"))))
      ;; Salted, so the key is not computable offline.
      (let ((before (key wtxid-a "P2SH")))
        (let ((bitcoin-lisp.coalton.interop::*sig-cache-salt*
                (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
          (is (not (equalp before (key wtxid-a "P2SH")))))))))

(test script-execution-cache-short-circuits-a-second-pass
  "The point of the cache: a transaction verified once is not re-verified.
Asserted by counting INPUT script executions, because \"it returned T again\"
is equally true of a cache that never fires.

The flag sensitivity is asserted the same way, and is the half that matters
for correctness: a different flag set must re-run the scripts, or a
transaction that passed under pre-fork rules would be waved through after the
fork."
  (let ((tx (make-mempool-test-tx :input-id 55))
        (runs 0)
        (real (symbol-function 'bitcoin-lisp.validation::validate-input-script)))
    (unwind-protect
         (progn
           (setf (symbol-function 'bitcoin-lisp.validation::validate-input-script)
                 (lambda (&rest args) (declare (ignore args)) (incf runs) t))
           (bitcoin-lisp.coalton.interop::clear-script-execution-cache)
           (let ((utxo (bitcoin-lisp.storage:make-utxo-set))
                 (coins (make-hash-table :test 'equalp)))
             ;; A resolvable coin for the single input, so the walk reaches
             ;; validate-input-script at all.
             (let ((in (aref (bitcoin-lisp.serialization:transaction-inputs tx) 0)))
               (setf (gethash (cons (bitcoin-lisp.serialization:outpoint-hash
                                     (bitcoin-lisp.serialization:tx-in-previous-output in))
                                    (bitcoin-lisp.serialization:outpoint-index
                                     (bitcoin-lisp.serialization:tx-in-previous-output in)))
                              coins)
                     (bitcoin-lisp.storage:make-utxo-entry
                      :value 100000
                      :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))
                      :height 1 :coinbase nil)))
             (flet ((check (flags)
                      (bitcoin-lisp.validation:validate-transaction-scripts
                       tx utxo :extra-coins coins :flags flags)))
               (is-true (check "P2SH"))
               (is (= 1 runs) "the first pass must actually run the input")
               ;; Second pass, same flags: served from cache.
               (is-true (check "P2SH"))
               (is (= 1 runs)
                   "a second pass re-ran ~D input script(s)" (- runs 1))
               ;; Different flags: must re-run.
               (is-true (check "P2SH,TAPROOT"))
               (is (= 2 runs)
                   "a different flag set was served from cache")
               ;; And that result is cached under ITS flags.
               (is-true (check "P2SH,TAPROOT"))
               (is (= 2 runs)))))
      (setf (symbol-function 'bitcoin-lisp.validation::validate-input-script) real)
      (bitcoin-lisp.coalton.interop::clear-script-execution-cache))))

(test script-execution-cache-never-stores-a-partial-success
  "A transaction whose SECOND input fails must leave no entry — otherwise the
next pass short-circuits on the first input's success and accepts it."
  (let ((tx (make-mempool-test-tx :input-id 56))
        (real (symbol-function 'bitcoin-lisp.validation::validate-input-script)))
    (unwind-protect
         (progn
           (bitcoin-lisp.coalton.interop::clear-script-execution-cache)
           (setf (symbol-function 'bitcoin-lisp.validation::validate-input-script)
                 (lambda (&rest args) (declare (ignore args)) nil))
           (let ((utxo (bitcoin-lisp.storage:make-utxo-set))
                 (coins (make-hash-table :test 'equalp)))
             (let ((in (aref (bitcoin-lisp.serialization:transaction-inputs tx) 0)))
               (setf (gethash (cons (bitcoin-lisp.serialization:outpoint-hash
                                     (bitcoin-lisp.serialization:tx-in-previous-output in))
                                    (bitcoin-lisp.serialization:outpoint-index
                                     (bitcoin-lisp.serialization:tx-in-previous-output in)))
                              coins)
                     (bitcoin-lisp.storage:make-utxo-entry
                      :value 100000
                      :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))
                      :height 1 :coinbase nil)))
             (is-false (bitcoin-lisp.validation:validate-transaction-scripts
                        tx utxo :extra-coins coins :flags "P2SH"))
             ;; Nothing cached, so a later pass still runs the scripts — and
             ;; still fails.
             (is-false (bitcoin-lisp.coalton.interop::script-execution-cached-p
                        (bitcoin-lisp.coalton.interop::make-script-execution-cache-key
                         (bitcoin-lisp.serialization:transaction-wtxid tx) "P2SH"))
                       "a failed validation left a cache entry")))
      (setf (symbol-function 'bitcoin-lisp.validation::validate-input-script) real)
      (bitcoin-lisp.coalton.interop::clear-script-execution-cache))))

(test sig-cache-key-carries-no-script-flags
  "Core keys on sighash|pubkey|sig with NO script flags (ComputeEntryECDSA,
sigcache.cpp:39-43). Ours used to include them, because the flag-dependent
encoding checks ran INSIDE the cached verify — so the flags in the key were the
only thing stopping a signature cached under lax flags from being reported
valid under strict ones.

The checks are now hoisted above the lookup (CHECK-SIGNATURE-ENCODING in
CACHED-VERIFY-ECDSA), which is what makes the flag-free key correct. This
asserts the key format; SIG-CACHE-RESPECTS-FLAGS-VIA-HOISTED-ENCODING-CHECKS
asserts the property the key format now depends on. Neither is safe alone."
  (let* ((sighash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 4))
         (pubkey (make-array 33 :element-type '(unsigned-byte 8) :initial-element 5))
         (sig (make-array 71 :element-type '(unsigned-byte 8) :initial-element 6))
         (lax (let ((bitcoin-lisp.coalton.interop::*script-flags* nil))
                (bitcoin-lisp.coalton.interop::make-sig-cache-key #x45 sighash sig pubkey)))
         (strict (let ((bitcoin-lisp.coalton.interop::*script-flags* "DERSIG,LOW_S"))
                   (bitcoin-lisp.coalton.interop::make-sig-cache-key #x45 sighash sig pubkey))))
    (is (equalp lax strict)
        "the cache key still varies with the script flags")))

(test sig-cache-respects-flags-via-hoisted-encoding-checks
  "The consensus property the flag-free key rests on: a signature accepted
under LAX flags and cached must NOT be reported valid under STRICT ones.

Driven end to end through CACHED-VERIFY-ECDSA with a REAL signature, in the
order that matters — lax first, so the cache is primed, then strict. A test
that ran strict first would pass against a broken cache."
  (let* ((privkey (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (pubkey (bitcoin-lisp.crypto:derive-public-key privkey))
         (sighash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (der (bitcoin-lisp.crypto:sign-ecdsa privkey sighash)))
    (bitcoin-lisp.coalton.interop::clear-signature-cache)
    ;; A well-formed signature verifies and caches under either flag set.
    (is-true (bitcoin-lisp.coalton.interop::cached-verify-ecdsa sighash der pubkey))
    (is-true (bitcoin-lisp.coalton.interop::cached-verify-ecdsa
              sighash der pubkey :strict t :low-s t))
    ;; Now the case the key format used to protect: a signature that is fine
    ;; laxly and NOT fine strictly. A trailing byte makes it invalid DER while
    ;; leaving the lax parse intact.
    (let ((padded (concatenate '(simple-array (unsigned-byte 8) (*)) der #(0))))
      (bitcoin-lisp.coalton.interop::clear-signature-cache)
      ;; Lax: accepted, and now in the cache.
      (is-true (bitcoin-lisp.coalton.interop::cached-verify-ecdsa sighash padded pubkey)
               "the lax case must succeed or this test asserts nothing")
      ;; Strict: must be refused, cache hit or not.
      (multiple-value-bind (result status)
          (bitcoin-lisp.coalton.interop::cached-verify-ecdsa
           sighash padded pubkey :strict t)
        (is-false result
                  "a signature cached under lax flags was served under strict ones")
        (is-false status "a strict DER failure must report parse-failed")))
    ;; And the low-S half, which has the same shape: high-S is valid laxly and
    ;; refused under LOW_S. Core's CheckSignatureEncoding decides both.
    (multiple-value-bind (ok status)
        (bitcoin-lisp.crypto:check-signature-encoding der :strict t :low-s t)
      (is-true ok "the fixture signature is already low-S")
      (is-true status))))
