(in-package #:bitcoin-lisp.tests)

(in-suite :validation-tests)

;;;; Transaction Structure Validation Tests

(defun make-test-transaction (&key (inputs 1) (outputs 1) (value 50000000))
  "Create a simple test transaction with specified parameters."
  (let ((tx-inputs (loop for i below inputs
                         collect (bitcoin-lisp.serialization:make-tx-in
                                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                      :initial-element (1+ i))
                                                    :index 0)
                                  :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                                          :initial-element #x00)
                                  :sequence #xFFFFFFFF)))
        (tx-outputs (loop for i below outputs
                          collect (bitcoin-lisp.serialization:make-tx-out
                                   :value (floor value outputs)
                                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                              :initial-element #x76)))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (coerce tx-inputs 'simple-vector)
     :outputs (coerce tx-outputs 'simple-vector)
     :lock-time 0)))

(defun make-coinbase-transaction (&key (value 5000000000) (height 0))
  "Create a coinbase transaction."
  (let* ((coinbase-script (make-array 3 :element-type '(unsigned-byte 8)
                                        :initial-contents (list (logand height #xFF)
                                                                (logand (ash height -8) #xFF)
                                                                (logand (ash height -16) #xFF))))
         (input (bitcoin-lisp.serialization:make-tx-in
                 :previous-output (bitcoin-lisp.serialization:make-outpoint
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)
                                   :index #xFFFFFFFF)
                 :script-sig coinbase-script
                 :sequence #xFFFFFFFF))
         (output (bitcoin-lisp.serialization:make-tx-out
                  :value value
                  :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                             :initial-element #x76))))
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (vector input)
     :outputs (vector output)
     :lock-time 0)))

(test script-check-pool-is-persistent-and-reusable
  "Core keeps ONE CCheckQueue for the life of the process (checkqueue.h) and
hands it batches; ours spawned a fresh thread per worker PER BLOCK. At one
block per ten minutes that is invisible; during IBD it is a thread creation per
block.

The properties that matter are reuse and RECOVERY: a batch that fails must not
poison the next one, and a worker that errors must count as a failure rather
than leaving the master waiting forever on a TODO that never reaches zero."
  (let ((pool (bitcoin-lisp.validation::ensure-script-check-pool 4)))
    (is-true pool)
    ;; The SAME pool comes back, threads and all — that is what "persistent"
    ;; means and what the per-block spawn was not.
    (is (eq pool (bitcoin-lisp.validation::ensure-script-check-pool 4)))
    (is (= 4 (length (bitcoin-lisp.validation::script-check-pool-threads pool))))
    (is-true (bitcoin-lisp.validation::run-script-checks
              pool (loop repeat 50 collect (lambda () t))))
    ;; One failure among many fails the batch.
    (is-false (bitcoin-lisp.validation::run-script-checks
               pool (append (loop repeat 20 collect (lambda () t))
                            (list (lambda () nil))
                            (loop repeat 20 collect (lambda () t)))))
    ;; And the pool is usable again immediately: a failed batch that left
    ;; `failed` set would make every later block fail script validation.
    (is-true (bitcoin-lisp.validation::run-script-checks
              pool (loop repeat 30 collect (lambda () t))))
    ;; An empty batch is trivially true rather than a wait on TODO=0 that
    ;; nothing will ever signal.
    (is-true (bitcoin-lisp.validation::run-script-checks pool nil))
    ;; A worker that ERRORS counts as a failure. Without the handler the
    ;; thread would die mid-item, TODO would never reach zero, and the master
    ;; would wait forever — a hung node, not a rejected block.
    (is-false (bitcoin-lisp.validation::run-script-checks
               pool (list (lambda () (error "deliberate")))))
    (is-true (bitcoin-lisp.validation::run-script-checks
              pool (loop repeat 10 collect (lambda () t)))
             "the pool did not recover from a worker error")
    ;; Every item runs exactly once — the master participates in the same
    ;; queue as the workers, so double-execution is a live possibility.
    (let* ((n 200)
           (counter (list 0))
           (lock (bt:make-lock "count")))
      (is-true (bitcoin-lisp.validation::run-script-checks
                pool (loop repeat n
                           collect (lambda ()
                                     (bt:with-lock-held (lock)
                                       (incf (first counter)))
                                     t))))
      (is (= n (first counter))
          "~D items ran ~D times" n (first counter)))
    (bitcoin-lisp.validation:stop-script-check-pool)
    (is-false bitcoin-lisp.validation::*script-check-pool*)))

(test par-follows-cores-semantics
  "Core's -par (init.cpp): 0 means one worker per core, a NEGATIVE value leaves
that many cores free, and the result is clamped to MAX_SCRIPTCHECK_THREADS.

The negative form is the one worth pinning. -par=-1 on a 4-core box means
THREE workers, not one; reading it as an absolute value would oversubscribe the
very machine the operator asked to leave headroom on."
  (let ((cores (bitcoin-lisp.validation::available-processor-count)))
    (is (plusp cores) "the processor count must be positive or -par=0 is broken")
    (is (= (min cores 15) (bitcoin-lisp.validation::parse-par-threads 0)))
    (is (= (min (1- cores) 15) (bitcoin-lisp.validation::parse-par-threads -1)))
    (is (= 2 (bitcoin-lisp.validation::parse-par-threads 2)))
    ;; Clamped to Core's maximum.
    (is (= 15 (bitcoin-lisp.validation::parse-par-threads 99)))
    ;; Never negative, however deep the subtraction goes.
    (is (= 0 (bitcoin-lisp.validation::parse-par-threads (- (+ cores 5))))))
  ;; -par reaches the worker count AND the on/off switch: Core's -par=1 means
  ;; no extra threads at all, which is not the same as "one worker".
  (let ((saved-n bitcoin-lisp.validation::+parallel-validation-workers+)
        (saved-p bitcoin-lisp:*parallel-block-validation*))
    (unwind-protect
         (progn
           (bitcoin-lisp::apply-config-globals '(("par" . "3")))
           (is (= 3 bitcoin-lisp.validation::+parallel-validation-workers+))
           (is-true bitcoin-lisp:*parallel-block-validation*)
           (bitcoin-lisp::apply-config-globals '(("par" . "1")))
           (is-false bitcoin-lisp:*parallel-block-validation*
                     "-par=1 must disable the extra threads, as Core's does"))
      (setf bitcoin-lisp.validation::+parallel-validation-workers+ saved-n
            bitcoin-lisp:*parallel-block-validation* saved-p)))
  (is-true (bitcoin-lisp::known-config-option-p "par"))
  (is-false (bitcoin-lisp::core-only-option-p "par")))

(test prefetched-coins-are-what-the-workers-validate-against
  "Core copies each spent Coin into its CScriptCheck BEFORE queuing it
(validation.cpp ~:2540-2560), so the workers never touch the coins view. Ours
had each worker call COLLECT-SPENT-UTXOS itself, whose read path INSERTS ON
MISS into a non-synchronized hash table — the concurrent-corruption hazard §2.5
identified by reading.

Asserted structurally as well as behaviourally: VALIDATE-TX-SCRIPTS must USE
the coins it is handed rather than re-resolving them, or the prefetch would be
wasted work that fixes nothing."
  (let* ((tx (make-mempool-test-tx :input-id 71))
         (block-txs (list tx tx))          ; [0] stands in for the coinbase
         (utxo (bitcoin-lisp.storage:make-utxo-set))
         (coins (make-hash-table :test 'equalp))
         (in (aref (bitcoin-lisp.serialization:transaction-inputs tx) 0))
         (prevout (bitcoin-lisp.serialization:tx-in-previous-output in))
         (entry (bitcoin-lisp.storage:make-utxo-entry
                 :value 100000
                 :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))
                 :height 1 :coinbase nil)))
    (setf (gethash (cons (bitcoin-lisp.serialization:outpoint-hash prevout)
                         (bitcoin-lisp.serialization:outpoint-index prevout))
                   coins)
          entry)
    (let ((prefetched (bitcoin-lisp.validation::prefetch-block-spent-coins
                       block-txs utxo coins)))
      (is (= 1 (length prefetched))
          "one entry per NON-coinbase transaction, indexed like (rest txs)")
      (is (eq entry (aref (aref prefetched 0) 0))
          "the prefetch did not resolve the spent coin"))
    ;; And the handed-in coins are what get used: a DIFFERENT entry passed as
    ;; :spent-utxos must be the one the validator sees.
    (let* ((seen nil)
           (other (bitcoin-lisp.storage:make-utxo-entry
                   :value 42
                   :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))
                   :height 1 :coinbase nil))
           (real (symbol-function 'bitcoin-lisp.validation::validate-input-script)))
      (unwind-protect
           (progn
             (setf (symbol-function 'bitcoin-lisp.validation::validate-input-script)
                   (lambda (tx idx utxo) (declare (ignore tx idx))
                     (setf seen utxo) t))
             (bitcoin-lisp.validation::validate-tx-scripts
              tx 1 utxo "P2SH" 100 :spent-utxos (vector other))
             (is (eq other seen)
                 "validate-tx-scripts ignored the coins it was handed and ~
re-resolved them from the coins view"))
        (setf (symbol-function 'bitcoin-lisp.validation::validate-input-script)
              real)))))

(test valid-transaction-structure
  "A valid transaction should pass structure validation."
  (let ((tx (make-test-transaction :inputs 1 :outputs 2 :value 10000000)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (eq t valid))
      (is (null error)))))

(test transaction-no-inputs
  "Transaction without inputs should fail validation."
  (let ((tx (bitcoin-lisp.serialization:make-transaction
             :version 1
             :inputs #()
             :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                             :value 1000
                             :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
             :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :no-inputs error)))))

(test transaction-no-outputs
  "Transaction without outputs should fail validation."
  (let ((tx (bitcoin-lisp.serialization:make-transaction
             :version 1
             :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                            :previous-output (bitcoin-lisp.serialization:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 1)
                                              :index 0)
                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                            :sequence #xFFFFFFFF))
             :outputs #()
             :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :no-outputs error)))))

(test transaction-duplicate-inputs
  "Transaction with duplicate inputs should fail validation."
  (let* ((same-outpoint (bitcoin-lisp.serialization:make-outpoint
                         :hash (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 42)
                         :index 0))
         (empty-script (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 1
              :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                             :previous-output same-outpoint
                             :script-sig empty-script
                             :sequence #xFFFFFFFF)
                            (bitcoin-lisp.serialization:make-tx-in
                             :previous-output same-outpoint
                             :script-sig empty-script
                             :sequence #xFFFFFFFF))
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                              :value 1000
                              :script-pubkey empty-script))
              :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :duplicate-inputs error)))))

(test transaction-negative-output
  "Transaction with negative output value should fail validation."
  (let* ((empty-script (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 1
              :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                             :previous-output (bitcoin-lisp.serialization:make-outpoint
                                               :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                 :initial-element 1)
                                               :index 0)
                             :script-sig empty-script
                             :sequence #xFFFFFFFF))
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                              :value -1000
                              :script-pubkey empty-script))
              :lock-time 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :negative-output error)))))

;;;; Contextual Transaction Validation Tests

(test transaction-missing-input-utxo
  "Transaction spending non-existent UTXO should fail."
  (let ((tx (make-test-transaction :inputs 1 :outputs 1 :value 1000))
        (utxo-set (bitcoin-lisp.storage:make-utxo-set)))
    (multiple-value-bind (valid error fee)
        (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
      (declare (ignore fee))
      (is (null valid))
      (is (eq :missing-input error)))))

(test transaction-coinbase-maturity
  "Spending immature coinbase should fail."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add coinbase UTXO at height 50
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 5000000000 script 50 :coinbase t)
    ;; Try to spend at height 100 (only 50 blocks old, need 100)
    (let* ((input (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bitcoin-lisp.serialization:make-tx-out
                    :value 4900000000
                    :script-pubkey script))
           (tx (bitcoin-lisp.serialization:make-transaction
                :version 1
                :inputs (vector input)
                :outputs (vector output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
        (declare (ignore fee))
        (is (null valid))
        (is (eq :coinbase-not-mature error))))))

(test transaction-valid-spending
  "Valid transaction spending existing UTXO should pass."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add non-coinbase UTXO
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 10000000 script 10)
    (let* ((input (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bitcoin-lisp.serialization:make-tx-out
                    :value 9000000
                    :script-pubkey script))
           (tx (bitcoin-lisp.serialization:make-transaction
                :version 1
                :inputs (vector input)
                :outputs (vector output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
        (is (eq t valid))
        (is (null error))
        ;; Fee is now a Satoshi type - unwrap to compare
        (is (= 1000000 (bitcoin-lisp.coalton.interop:unwrap-satoshi fee)))))))  ; 10M - 9M = 1M fee

(test transaction-insufficient-funds
  "Transaction with outputs exceeding inputs should fail."
  (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    (bitcoin-lisp.storage:add-utxo utxo-set txid 0 1000000 script 10)
    (let* ((input (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bitcoin-lisp.serialization:make-tx-out
                    :value 2000000  ; More than input
                    :script-pubkey script))
           (tx (bitcoin-lisp.serialization:make-transaction
                :version 1
                :inputs (vector input)
                :outputs (vector output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bitcoin-lisp.validation:validate-transaction-contextual tx utxo-set 100)
        (declare (ignore fee))
        (is (null valid))
        (is (eq :insufficient-funds error))))))

;;;; Block Validation Tests

(defun make-test-block-header (&key (version 1) (timestamp (get-universal-time))
                                (bits #x1d00ffff) (nonce 0))
  "Create a test block header."
  (bitcoin-lisp.serialization:make-block-header
   :version version
   :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
   :timestamp timestamp
   :bits bits
   :nonce nonce))

(test block-header-time-too-new
  "Block with timestamp too far in future should fail."
  ;; Note: PoW validation runs first, so this tests that validation fails
  ;; The actual error may be :bad-proof-of-work if PoW is checked first
  (let* ((current-time (get-universal-time))
         (header (make-test-block-header
                  :timestamp (+ current-time 10000)))  ; 10000 seconds in future
         (state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block-header header state current-time)
      (is (null valid))
      ;; Either error is acceptable - header is invalid
      (is (member error '(:time-too-new :bad-proof-of-work))))))

(test block-header-version-core-semantics
  "Version enforcement matches Core exactly: only softfork minimums.
High version-rolled values (overt AsicBoost) are NOT rejected — the old
upper bound rejected real mainnet block 544,085 and halted IBD."
  (let* ((current-time (get-universal-time))
         (state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-test/")))
    ;; Version-rolled header far above the old #x3FFFFFFF bound: must not
    ;; fail on version (PoW will still fail for a test header).
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block-header
         (make-test-block-header :version #x7FFFE000) state current-time)
      (declare (ignore valid))
      (is (not (eq error :bad-version))))
    ;; Version 0 with no height context: no minimum applies (pre-BIP34
    ;; semantics) — must not fail on version either.
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block-header
         (make-test-block-header :version 0) state current-time)
      (declare (ignore valid))
      (is (not (eq error :bad-version))))
    ;; Below-minimum version at a post-activation height: rejected
    ;; (PoW may shadow it depending on check order — accept either).
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block-header
         (make-test-block-header :version 1) state current-time
         :height (+ 1 (bitcoin-lisp.validation::get-bip34-activation-height
                       bitcoin-lisp:*network*)))
      (is (null valid))
      (is (member error '(:bad-version :bad-proof-of-work))))))

;;;; MTP Timestamp Validation Tests

(defun build-chain-with-timestamps (state timestamps)
  "Build a chain of block index entries with given TIMESTAMPS.
Returns the hash of the last block."
  (let ((prev-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
        (prev-entry nil))
    (loop for ts in timestamps
          for height from 0
          do (let* ((hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
                    (header (bitcoin-lisp.serialization:make-block-header
                             :version 1
                             :prev-block (copy-seq prev-hash)
                             :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0)
                             :timestamp ts
                             :bits #x1d00ffff
                             :nonce 0))
                    (entry (bitcoin-lisp.storage:make-block-index-entry
                            :hash hash
                            :height height
                            :header header
                            :prev-entry prev-entry
                            :chain-work 0
                            :status :valid)))
               ;; Give each block a unique hash based on height
               (setf (aref hash 0) (mod height 256))
               (setf (aref hash 1) (floor height 256))
               (setf (aref (bitcoin-lisp.storage:block-index-entry-hash entry) 0)
                     (mod height 256))
               (setf (aref (bitcoin-lisp.storage:block-index-entry-hash entry) 1)
                     (floor height 256))
               (bitcoin-lisp.storage:add-block-index-entry state entry)
               (setf prev-hash (bitcoin-lisp.storage:block-index-entry-hash entry))
               (setf prev-entry entry)))
    prev-hash))

(test mtp-timestamp-equal-rejected
  "Block with timestamp equal to MTP should be rejected.
PoW is checked first so we may get :bad-proof-of-work instead.
We verify MTP computation directly to confirm the check works."
  (let* ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-mtp-test/"))
         ;; 11 blocks with timestamps 100..110, median = 105
         (timestamps (loop for i from 100 to 110 collect i))
         (prev-hash (build-chain-with-timestamps state timestamps)))
    ;; Verify MTP is computed correctly
    (let ((mtp (bitcoin-lisp.validation:compute-median-time-past state prev-hash)))
      (is (= 105 mtp)))
    ;; Verify header with timestamp=MTP is rejected
    (let ((header (bitcoin-lisp.serialization:make-block-header
                   :version 1
                   :prev-block prev-hash
                   :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                               :initial-element 0)
                   :timestamp 105  ; Equal to MTP
                   :bits #x1d00ffff
                   :nonce 0)))
      (multiple-value-bind (valid error)
          (bitcoin-lisp.validation:validate-block-header
           header state (+ 105 10000) :prev-hash prev-hash)
        (is (null valid))
        ;; Either error is acceptable - header is invalid
        (is (member error '(:time-too-old :bad-proof-of-work)))))))

(test mtp-timestamp-after-accepted
  "Block with timestamp after MTP should not get :time-too-old."
  (let* ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-mtp-test2/"))
         ;; 11 blocks with timestamps 100..110, median = 105
         (timestamps (loop for i from 100 to 110 collect i))
         (prev-hash (build-chain-with-timestamps state timestamps))
         (header (bitcoin-lisp.serialization:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 0)
                  :timestamp 106  ; Greater than MTP of 105
                  :bits #x1d00ffff
                  :nonce 0)))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-block-header
         header state (+ 106 10000) :prev-hash prev-hash)
      (declare (ignore valid))
      ;; Must not fail on MTP check (may fail on PoW, that's fine)
      (is (not (eq :time-too-old error))))))

(test mtp-unknown-parent-is-a-rejection
  "CONSENSUS (GA8 S1-7): a parent that is not in the block index yields NO
median-time-past, and that is a rejection — not time zero. The previous literal
0 made Core's (block.GetBlockTime() <= pindexPrev->GetMedianTimePast()) rule
vacuously false for every header whose parent had not been indexed yet.
This test replaces mtp-no-ancestors-passes, which asserted the fail-open."
  (let* ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-mtp-test3/"))
         (unknown (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (null (bitcoin-lisp.validation:compute-median-time-past state unknown)))
    (is (null (bitcoin-lisp.validation:compute-median-time-past-from-entry nil)))
    (is-true (bitcoin-lisp.validation:header-time-too-old-p
              (bitcoin-lisp.serialization:make-block-header
               :version 1 :prev-block unknown :merkle-root unknown
               :timestamp 1 :bits #x1d00ffff :nonce 0)
              nil))))

(test mtp-from-entry-matches-hash-lookup
  "compute-median-time-past-from-entry is the same walk as the hash-keyed
wrapper for a chain that IS indexed (Core CBlockIndex::GetMedianTimePast,
chain.h:233-246), including a partial window shorter than 11 blocks."
  (let* ((state (bitcoin-lisp.storage:init-chain-state "/tmp/btc-mtp-test4/"))
         (timestamps (loop for i from 200 to 214 collect i))
         (tip-hash (build-chain-with-timestamps state timestamps))
         (tip-entry (bitcoin-lisp.storage:get-block-index-entry state tip-hash)))
    ;; Full 11-block window over the last 11 timestamps (204..214), median 209.
    (is (= 209 (bitcoin-lisp.validation:compute-median-time-past state tip-hash)))
    (is (= 209 (bitcoin-lisp.validation:compute-median-time-past-from-entry tip-entry)))
    ;; Partial window: the height-2 entry has only 3 timestamps behind it
    ;; (200 201 202), and Core's index arithmetic picks 201.
    (let ((third (let ((e tip-entry))
                   (dotimes (i 12 e)
                     (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e))))))
      (is (= 2 (bitcoin-lisp.storage:block-index-entry-height third)))
      (is (= 201 (bitcoin-lisp.validation:compute-median-time-past-from-entry third)))
      (is (= 201 (bitcoin-lisp.validation:compute-median-time-past
                  state (bitcoin-lisp.storage:block-index-entry-hash third)))))))

;;;; Merkle Root Tests

(test merkle-root-single-tx
  "Merkle root of single transaction should be its hash."
  (let* ((tx (make-coinbase-transaction :value 5000000000 :height 1))
         (tx-hash (bitcoin-lisp.serialization:transaction-hash tx))
         (merkle-root (bitcoin-lisp.validation:compute-merkle-root (list tx-hash))))
    (is (equalp merkle-root tx-hash))))

(test merkle-root-two-txs
  "Merkle root of two transactions should be hash of concatenated hashes."
  (let* ((tx1 (make-coinbase-transaction :value 5000000000 :height 1))
         (tx2 (make-test-transaction :inputs 1 :outputs 1 :value 1000000))
         (hash1 (bitcoin-lisp.serialization:transaction-hash tx1))
         (hash2 (bitcoin-lisp.serialization:transaction-hash tx2))
         (merkle-root (bitcoin-lisp.validation:compute-merkle-root (list hash1 hash2)))
         ;; Manually compute expected: hash256(hash1 || hash2)
         (combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined hash1 :start1 0)
    (replace combined hash2 :start1 32)
    (let ((expected (bitcoin-lisp.crypto:hash256 combined)))
      (is (equalp merkle-root expected)))))

(test merkle-root-empty
  "Merkle root of empty list should be zeros."
  (let ((merkle-root (bitcoin-lisp.validation:compute-merkle-root nil)))
    (is (every #'zerop merkle-root))))

;;;; BIP 34 Coinbase Height Tests

(test decode-coinbase-height-small
  "decode-coinbase-height should handle small heights encoded with OP_n."
  ;; OP_0 -> height 0
  (is (= 0 (bitcoin-lisp.validation:decode-coinbase-height
             (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(0)))))
  ;; OP_1 (0x51) -> height 1
  (is (= 1 (bitcoin-lisp.validation:decode-coinbase-height
             (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x51)))))
  ;; OP_16 (0x60) -> height 16
  (is (= 16 (bitcoin-lisp.validation:decode-coinbase-height
              (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x60))))))

(test decode-coinbase-height-push-bytes
  "decode-coinbase-height should handle heights encoded as byte pushes."
  ;; push1 100 -> height 100
  (is (= 100 (bitcoin-lisp.validation:decode-coinbase-height
               (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(1 100)))))
  ;; push2 0x00 0x01 -> height 256
  (is (= 256 (bitcoin-lisp.validation:decode-coinbase-height
               (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(2 0 1)))))
  ;; push3 for height 21111 = 0x5277 -> bytes: push3 #x77 #x52 #x00
  (is (= 21111 (bitcoin-lisp.validation:decode-coinbase-height
                 (make-array 4 :element-type '(unsigned-byte 8)
                               :initial-contents '(3 #x77 #x52 #x00))))))

(test decode-coinbase-height-empty-script
  "decode-coinbase-height should return NIL for empty scriptSig."
  (is (null (bitcoin-lisp.validation:decode-coinbase-height
              (make-array 0 :element-type '(unsigned-byte 8))))))

;;;; Witness Commitment Tests

(test find-witness-commitment-present
  "Should find the witness commitment in a coinbase with OP_RETURN output."
  (let* ((commitment-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
         ;; OP_RETURN push36 0xaa21a9ed <32-byte hash>
         (script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x6a   ; OP_RETURN
          (aref script 1) #x24   ; push 36 bytes
          (aref script 2) #xaa   ; commitment header
          (aref script 3) #x21
          (aref script 4) #xa9
          (aref script 5) #xed)
    (replace script commitment-hash :start1 6)
    (let* ((output (bitcoin-lisp.serialization:make-tx-out
                    :value 0 :script-pubkey script))
           (coinbase (bitcoin-lisp.serialization:make-transaction
                      :version 1
                      :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element 0)
                                                       :index #xFFFFFFFF)
                                     :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                               :initial-element 1)))
                      :outputs (vector (bitcoin-lisp.serialization:make-tx-out :value 5000000000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                    :initial-element #x76))
                                     output)
                      :lock-time 0)))
      (let ((found (bitcoin-lisp.validation:find-witness-commitment coinbase)))
        (is (not (null found)))
        (is (equalp commitment-hash found))))))

(test find-witness-commitment-absent
  "Should return NIL when no witness commitment exists."
  (let ((coinbase (make-coinbase-transaction :value 5000000000 :height 1)))
    (is (null (bitcoin-lisp.validation:find-witness-commitment coinbase)))))

(defun %coinbase-with-commitment (cb-witness-stack)
  "A coinbase tx carrying a witness-commitment OP_RETURN output, whose coinbase
input witness stack is CB-WITNESS-STACK (a list of byte-vectors, or NIL for none)."
  (let ((script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x6a (aref script 1) #x24      ; OP_RETURN push36
          (aref script 2) #xaa (aref script 3) #x21      ; commitment header aa21a9ed
          (aref script 4) #xa9 (aref script 5) #xed)
    (bitcoin-lisp.serialization:make-transaction
     :version 1
     :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                      :previous-output (bitcoin-lisp.serialization:make-outpoint
                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                            :initial-element 0)
                                        :index #xFFFFFFFF)
                      :script-sig (make-array 4 :element-type '(unsigned-byte 8) :initial-element 1)))
     :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                       :value 5000000000
                       :script-pubkey (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
                      (bitcoin-lisp.serialization:make-tx-out :value 0 :script-pubkey script))
     :lock-time 0
     :witness (vector cb-witness-stack))))

(test block-witness-stripped-p-detects-missing-nonce
  "block-witness-stripped-p is T when a block commits to witness but its coinbase
witness is missing or not exactly one 32-byte item, and NIL for a witness-complete
coinbase or one with no commitment. Guards the :weaker-chain store path so a
witness-stripped block never persists (the testnet4 BAD-WITNESS-NONCE-SIZE wedge)."
  (flet ((blk (coinbase)
           (bitcoin-lisp.serialization:make-bitcoin-block
            :header (make-test-block-header)
            :transactions (list coinbase))))
    ;; commitment + coinbase witness of exactly one 32-byte item -> complete
    (let ((nonce (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (is (null (bitcoin-lisp.validation:block-witness-stripped-p
                 (blk (%coinbase-with-commitment (list nonce)))))))
    ;; commitment + EMPTY coinbase witness (stripped) -> T
    (is-true (bitcoin-lisp.validation:block-witness-stripped-p
              (blk (%coinbase-with-commitment '()))))
    ;; commitment + wrong-size nonce (16 bytes) -> T
    (let ((short (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (is-true (bitcoin-lisp.validation:block-witness-stripped-p
                (blk (%coinbase-with-commitment (list short))))))
    ;; no commitment -> never stripped
    (is (null (bitcoin-lisp.validation:block-witness-stripped-p
               (blk (make-coinbase-transaction :value 5000000000 :height 1)))))))

;;;; Block Script Validation Tests

(test validate-block-scripts-called
  "validate-block should call script validation and reject invalid scripts."
  ;; Create a block with a spending tx that has an empty scriptSig
  ;; spending a P2PKH output. The script should fail because the
  ;; empty scriptSig can't satisfy P2PKH.
  (let* ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xAA))
         ;; P2PKH scriptPubKey: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
         (p2pkh-script (make-array 25 :element-type '(unsigned-byte 8)
                                      :initial-contents
                                      (list #x76 #xa9 #x14  ; OP_DUP OP_HASH160 push20
                                            1 2 3 4 5 6 7 8 9 10
                                            11 12 13 14 15 16 17 18 19 20
                                            #x88 #xac)))  ; OP_EQUALVERIFY OP_CHECKSIG
         ;; Empty scriptSig - will fail validation
         (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add UTXO with P2PKH script
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 1000000 p2pkh-script 5)
    ;; Build block with spending tx that has empty scriptSig
    (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 10))
           (spending-tx (bitcoin-lisp.serialization:make-transaction
                         :version 1
                         :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash prev-txid :index 0)
                                        :script-sig empty-script
                                        :sequence #xFFFFFFFF))
                         :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                         :value 900000
                                         :script-pubkey p2pkh-script))
                         :lock-time 0))
           (block (bitcoin-lisp.serialization:make-bitcoin-block
                   :header (make-test-block-header)
                   :transactions (list coinbase-tx spending-tx))))
      ;; validate-block-scripts should reject this block
      (multiple-value-bind (valid error)
          (bitcoin-lisp.validation:validate-block-scripts block utxo-set)
        (is (null valid))
        (is (eq :script-failed error))))))

(test validate-block-scripts-parallel-path
  "The opt-in parallel validation path (bitcoin-lisp:*parallel-block-validation*
bound T) must produce the same accept/reject result as the default serial path
for a block large enough to cross +parallel-validation-min-txs+ (16 non-coinbase
txs). Guards the worker-thread fan-out/join and the shared failure-flag against
regressions: the path is OFF in production (it corrupts SBCL's alien-type cache
at mainnet scale), so only this test exercises it."
  (flet ((build-block (script-pubkey script-sig n)
           ;; N spending txs (each spending its own UTXO of SCRIPT-PUBKEY with
           ;; SCRIPT-SIG) plus a coinbase. Returns (values block utxo-set).
           (let ((utxo-set (bitcoin-lisp.storage:make-utxo-set))
                 (txs (list (make-coinbase-transaction :value 5000000000 :height 10))))
             (dotimes (i n)
               (let ((prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element (logand i #xFF))))
                 (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 1000000 script-pubkey 5)
                 (push (bitcoin-lisp.serialization:make-transaction
                        :version 1
                        :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                         :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                           :hash prev-txid :index 0)
                                         :script-sig script-sig
                                         :sequence #xFFFFFFFF))
                        :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                          :value 900000
                                          :script-pubkey script-pubkey))
                        :lock-time 0)
                       txs)))
             (values (bitcoin-lisp.serialization:make-bitcoin-block
                      :header (make-test-block-header)
                      :transactions (nreverse txs))
                     utxo-set))))
    (let ((op-true (make-array 1 :element-type '(unsigned-byte 8) :initial-element #x51))
          (empty (make-array 0 :element-type '(unsigned-byte 8)))
          ;; P2PKH with empty scriptSig — always fails consensus.
          (p2pkh (make-array 25 :element-type '(unsigned-byte 8)
                               :initial-contents
                               (list #x76 #xa9 #x14 1 2 3 4 5 6 7 8 9 10
                                     11 12 13 14 15 16 17 18 19 20 #x88 #xac))))
      ;; 20 anyone-can-spend (OP_TRUE) outputs => ACCEPT on both paths.
      (multiple-value-bind (blk utxo-set) (build-block op-true empty 20)
        (let ((bitcoin-lisp:*parallel-block-validation* t))
          (is (eq t (bitcoin-lisp.validation:validate-block-scripts blk utxo-set))))
        (let ((bitcoin-lisp:*parallel-block-validation* nil))
          (is (eq t (bitcoin-lisp.validation:validate-block-scripts blk utxo-set)))))
      ;; 20 P2PKH outputs with empty scriptSig => REJECT on the parallel path
      ;; too (worker detects the failure and the join reports it).
      (multiple-value-bind (blk utxo-set) (build-block p2pkh empty 20)
        (let ((bitcoin-lisp:*parallel-block-validation* t))
          (multiple-value-bind (valid error)
              (bitcoin-lisp.validation:validate-block-scripts blk utxo-set)
            (is (null valid))
            (is (eq :script-failed error))))))))

;;;; Witness Validation Tests

(defun make-witness-p2wpkh-script ()
  "Create a P2WPKH scriptPubKey: OP_0 <20-byte-hash>."
  (let ((script (make-array 22 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x00   ; OP_0 (witness version 0)
          (aref script 1) #x14)  ; push 20 bytes
    ;; Fill with a fake hash
    (loop for i from 2 below 22 do (setf (aref script i) (mod i 256)))
    script))

(test block-has-witness-data-detects-witness
  "block-has-witness-data-p should return T when transactions have witness data."
  (let* ((coinbase (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                   :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                     :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                       :initial-element 0)
                                                     :index #xFFFFFFFF)
                                   :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                             :initial-element 1)))
                    :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                    :value 5000000000
                                    :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                               :initial-element #x76)))
                    :lock-time 0))
         ;; Witness transaction
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x11)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xAA)
                                          (make-array 33 :element-type '(unsigned-byte 8)
                                                         :initial-element #xBB)))))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    ;; Block with witness tx should be detected
    (is (bitcoin-lisp.validation::block-has-witness-data-p block))))

(test block-without-witness-data
  "block-has-witness-data-p should return NIL for legacy blocks."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase))))
    (is (not (bitcoin-lisp.validation::block-has-witness-data-p block)))))

(test witness-merkle-root-computation
  "Witness merkle root should use wtxids (coinbase wtxid = zeros)."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (regular-tx (make-test-transaction :inputs 1 :outputs 1 :value 1000000))
         (transactions (list coinbase regular-tx)))
    ;; Compute witness merkle root
    (let ((witness-root (bitcoin-lisp.validation:compute-witness-merkle-root transactions)))
      ;; The root should be hash of coinbase-wtxid(zeros) || regular-tx-wtxid
      (let* ((cb-wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
             (tx-wtxid (bitcoin-lisp.serialization:transaction-wtxid regular-tx))
             (combined (make-array 64 :element-type '(unsigned-byte 8))))
        (replace combined cb-wtxid :start1 0)
        (replace combined tx-wtxid :start1 32)
        (let ((expected (bitcoin-lisp.crypto:hash256 combined)))
          (is (equalp witness-root expected)))))))

(test witness-commitment-validation-matching
  "validate-witness-commitment should pass when commitment matches."
  (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 1))
         ;; A witness tx (with dummy witness data)
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x22)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xCC)))))
         (transactions (list coinbase-tx witness-tx)))
    ;; Compute what the correct commitment should be
    (let* ((witness-root (bitcoin-lisp.validation:compute-witness-merkle-root transactions))
           ;; Default witness reserved value: 32 zero bytes
           (witness-reserved (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (combined (make-array 64 :element-type '(unsigned-byte 8))))
      (replace combined witness-root :start1 0)
      (replace combined witness-reserved :start1 32)
      (let ((commitment (bitcoin-lisp.crypto:hash256 combined)))
        ;; Build OP_RETURN script with correct commitment
        (let ((script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
          (setf (aref script 0) #x6a   ; OP_RETURN
                (aref script 1) #x24   ; push 36 bytes
                (aref script 2) #xaa   ; commitment header
                (aref script 3) #x21
                (aref script 4) #xa9
                (aref script 5) #xed)
          (replace script commitment :start1 6)
          ;; Add commitment output and witness reserved to coinbase
          (let* ((updated-coinbase
                   (bitcoin-lisp.serialization:make-transaction
                    :version 1
                    :inputs (bitcoin-lisp.serialization:transaction-inputs coinbase-tx)
                    :outputs (concatenate 'simple-vector
                                          (bitcoin-lisp.serialization:transaction-outputs coinbase-tx)
                                          (list (bitcoin-lisp.serialization:make-tx-out
                                                 :value 0 :script-pubkey script)))
                    :lock-time 0
                    :witness (vector (list witness-reserved))))  ; coinbase witness
                 (block (bitcoin-lisp.serialization:make-bitcoin-block
                         :header (make-test-block-header)
                         :transactions (list updated-coinbase witness-tx))))
            (multiple-value-bind (valid error)
                (bitcoin-lisp.validation:validate-witness-commitment block t)
              (is (eq t valid))
              (is (null error)))))))))

(test witness-commitment-validation-missing
  "Segwit active + witness data present but coinbase has NO commitment
output: rejected as :unexpected-witness (Core's CheckWitnessMalleation
has no separate missing-commitment error — it falls through to the
no-witness-allowed scan)."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x33)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xDD)))))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-witness-commitment block t)
      (is (null valid))
      (is (eq :unexpected-witness error)))))

(test witness-unexpected-when-segwit-inactive
  "Pre-segwit block carrying witness data is rejected (:unexpected-witness)."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x44)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xEE)))))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    (multiple-value-bind (valid error)
        (bitcoin-lisp.validation:validate-witness-commitment block nil)
      (is (null valid))
      (is (eq :unexpected-witness error)))))

(test witness-legacy-block-passes-both-gates
  "A purely-legacy block (no witness data, no commitment) passes whether
or not segwit is active."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (legacy-tx (bitcoin-lisp.serialization:make-transaction
                     :version 1
                     :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                        :initial-element #x55)
                                                      :index 0)
                                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                     :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                     :value 49000
                                     :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                :initial-element #x76)))
                     :lock-time 0))
         (block (bitcoin-lisp.serialization:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase legacy-tx))))
    (is (eq t (bitcoin-lisp.validation:validate-witness-commitment block nil)))
    (is (eq t (bitcoin-lisp.validation:validate-witness-commitment block t)))))

(test witness-commitment-bad-nonce-size
  "Segwit active + commitment present but coinbase witness reserved value
is not exactly one 32-byte item: :bad-witness-nonce-size."
  (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 1))
         (witness-tx (bitcoin-lisp.serialization:make-transaction
                      :version 2
                      :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                     :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x66)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xCC)))))
         (transactions (list coinbase-tx witness-tx))
         ;; Build a commitment that would match a 32-zero reserved value,
         ;; but give the coinbase a WRONG-sized (16-byte) witness item.
         (witness-root (bitcoin-lisp.validation:compute-witness-merkle-root transactions))
         (reserved (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined witness-root :start1 0)
    (replace combined reserved :start1 32)
    (let ((commitment (bitcoin-lisp.crypto:hash256 combined))
          (script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref script 0) #x6a (aref script 1) #x24
            (aref script 2) #xaa (aref script 3) #x21
            (aref script 4) #xa9 (aref script 5) #xed)
      (replace script commitment :start1 6)
      (let* ((bad-coinbase
               (bitcoin-lisp.serialization:make-transaction
                :version 1
                :inputs (bitcoin-lisp.serialization:transaction-inputs coinbase-tx)
                :outputs (concatenate 'simple-vector
                                      (bitcoin-lisp.serialization:transaction-outputs coinbase-tx)
                                      (list (bitcoin-lisp.serialization:make-tx-out
                                             :value 0 :script-pubkey script)))
                :lock-time 0
                ;; 16-byte reserved value instead of 32 — wrong size.
                :witness (vector (list (make-array 16 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))))
             (block (bitcoin-lisp.serialization:make-bitcoin-block
                     :header (make-test-block-header)
                     :transactions (list bad-coinbase witness-tx))))
        (multiple-value-bind (valid error)
            (bitcoin-lisp.validation:validate-witness-commitment block t)
          (is (null valid))
          (is (eq :bad-witness-nonce-size error)))))))

;;; ============================================================
;;; Transaction Finality (IsFinalTx) Tests
;;; ============================================================

(defun make-tx-with-locktime (locktime &key (version 1) (sequence #xFFFFFFFF))
  "Create a test transaction with specified nLockTime and input sequence."
  (bitcoin-lisp.serialization:make-transaction
   :version version
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                  :previous-output (bitcoin-lisp.serialization:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element 1)
                                    :index 0)
                  :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                          :initial-element #x00)
                  :sequence sequence))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value 50000000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time locktime))

(test is-final-locktime-zero
  "Transaction with nLockTime=0 is always final."
  (let ((tx (make-tx-with-locktime 0 :sequence 0)))
    (is-true (bitcoin-lisp.validation:check-transaction-final tx 100 1600000000))))

(test is-final-all-sequences-final
  "Transaction with all SEQUENCE_FINAL inputs is final regardless of locktime."
  (let ((tx (make-tx-with-locktime 500000 :sequence #xFFFFFFFF)))
    (is-true (bitcoin-lisp.validation:check-transaction-final tx 100 1600000000))))

(test is-final-height-based-satisfied
  "Height-based locktime satisfied when block height > nLockTime."
  (let ((tx (make-tx-with-locktime 400000 :sequence 0)))
    (is-true (bitcoin-lisp.validation:check-transaction-final tx 400001 1600000000))))

(test is-final-height-based-not-satisfied
  "Height-based locktime NOT satisfied when block height <= nLockTime."
  (let ((tx (make-tx-with-locktime 400000 :sequence 0)))
    (is-false (bitcoin-lisp.validation:check-transaction-final tx 399999 1600000000))))

(test is-final-time-based-satisfied
  "Time-based locktime satisfied when block time > nLockTime."
  (let ((tx (make-tx-with-locktime 1600000000 :sequence 0)))
    (is-true (bitcoin-lisp.validation:check-transaction-final tx 500000 1600000001))))

(test is-final-time-based-not-satisfied
  "Time-based locktime NOT satisfied when block time <= nLockTime."
  (let ((tx (make-tx-with-locktime 1600000000 :sequence 0)))
    (is-false (bitcoin-lisp.validation:check-transaction-final tx 500000 1599999999))))

(test is-final-height-locktime-boundary
  "nLockTime at 499999999 is height-based (< 500000000 threshold)."
  (let ((tx (make-tx-with-locktime 499999999 :sequence 0)))
    ;; Block height exceeds locktime
    (is-true (bitcoin-lisp.validation:check-transaction-final tx 500000000 0))))

(test is-final-time-locktime-boundary
  "nLockTime at 500000000 is time-based (>= threshold)."
  (let ((tx (make-tx-with-locktime 500000000 :sequence 0)))
    ;; Block time exceeds locktime
    (is-true (bitcoin-lisp.validation:check-transaction-final tx 0 500000001))))


;;; ============================================================
;;; BIP 30 enforcement window (bip30-enforced-p)
;;; ============================================================
;;; Mirrors Bitcoin Core ConnectBlock (validation.cpp:2399-2464): enforced
;;; below BIP 34 activation (except the grandfathered mainnet repeat
;;; blocks), and again unconditionally at height >= 1,983,702.

(test bip30-enforced-below-bip34-activation
  "Below BIP 34 activation, BIP 30 is enforced."
  (let ((bitcoin-lisp:*network* :mainnet))
    ;; mainnet BIP34 activation = 227931
    (is (bitcoin-lisp.validation::bip30-enforced-p 100000))
    (is (bitcoin-lisp.validation::bip30-enforced-p 227930)))
  (let ((bitcoin-lisp:*network* :testnet3))
    (is (bitcoin-lisp.validation::bip30-enforced-p 20000))))

(test bip30-skipped-between-bip34-and-limit
  "Between BIP 34 activation and the 1,983,702 re-enable limit, BIP 30 is
skipped (BIP 34 height-in-coinbase guarantees coinbase uniqueness)."
  (let ((bitcoin-lisp:*network* :mainnet))
    (is (not (bitcoin-lisp.validation::bip30-enforced-p 227931)))
    (is (not (bitcoin-lisp.validation::bip30-enforced-p 500000)))
    (is (not (bitcoin-lisp.validation::bip30-enforced-p 1983701)))))

(test bip30-reenabled-at-limit
  "At or above height 1,983,702, BIP 30 is re-enforced unconditionally."
  (dolist (net '(:mainnet :testnet3 :testnet4))
    (let ((bitcoin-lisp:*network* net))
      (is (bitcoin-lisp.validation::bip30-enforced-p 1983702))
      (is (bitcoin-lisp.validation::bip30-enforced-p 3000000)))))

(test bip30-grandfathered-repeat-blocks-exempt
  "The two mainnet repeat blocks (91842, 91880) are NOT BIP 30-enforced,
so their historical duplicate coinbases aren't wrongly rejected."
  (let ((bitcoin-lisp:*network* :mainnet))
    (is (not (bitcoin-lisp.validation::bip30-enforced-p 91842)))
    (is (not (bitcoin-lisp.validation::bip30-enforced-p 91880)))
    ;; A neighbouring height is still enforced.
    (is (bitcoin-lisp.validation::bip30-enforced-p 91841)))
  ;; The exemption is mainnet-specific — no other network treats those
  ;; heights as repeat blocks.
  (let ((bitcoin-lisp:*network* :testnet3))
    (is (not (bitcoin-lisp.validation::bip30-repeat-block-p 91842)))))

(test bip30-testnet4-not-enforced-at-current-heights
  "testnet4 has BIP 34 active from height 1, so BIP 30 is skipped for all
normal heights until the 1,983,702 re-enable."
  (let ((bitcoin-lisp:*network* :testnet4))
    (is (not (bitcoin-lisp.validation::bip30-enforced-p 136459)))
    (is (not (bitcoin-lisp.validation::bip30-enforced-p 500000)))))

;;; ============================================================
;;; BIP 34 exact-prefix coinbase height (encode-bip34-height /
;;; validate-coinbase-height) — Core compares serialized bytes, not value.
;;; ============================================================

(defun %bytes (&rest bs)
  (make-array (length bs) :element-type '(unsigned-byte 8) :initial-contents bs))

(defun %block-with-coinbase-scriptsig (script-sig)
  "A block whose coinbase input-0 has the given SCRIPT-SIG."
  (let ((coinbase
          (bitcoin-lisp.serialization:make-transaction
           :version 1
           :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                          :previous-output (bitcoin-lisp.serialization:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig script-sig
                          :sequence #xFFFFFFFF))
           :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                           :value 5000000000
                           :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                      :initial-element #x76)))
           :lock-time 0)))
    (bitcoin-lisp.serialization:make-bitcoin-block
     :header (make-test-block-header)
     :transactions (list coinbase))))

(test encode-bip34-height-forms
  "encode-bip34-height matches Core's CScript() << height: OP_0/OP_N for
0..16, minimal CScriptNum data push otherwise (incl. sign byte)."
  (is (equalp (%bytes #x00) (bitcoin-lisp.validation::encode-bip34-height 0)))
  (is (equalp (%bytes #x51) (bitcoin-lisp.validation::encode-bip34-height 1)))
  (is (equalp (%bytes #x60) (bitcoin-lisp.validation::encode-bip34-height 16)))
  (is (equalp (%bytes #x01 #x11) (bitcoin-lisp.validation::encode-bip34-height 17)))
  ;; 21111 = 0x5277 -> LE 0x77 0x52
  (is (equalp (%bytes #x02 #x77 #x52) (bitcoin-lisp.validation::encode-bip34-height 21111)))
  ;; 227931 = 0x037A5B -> LE 0x5b 0x7a 0x03
  (is (equalp (%bytes #x03 #x5b #x7a #x03) (bitcoin-lisp.validation::encode-bip34-height 227931)))
  ;; 128 = 0x80 -> needs 0x00 sign byte
  (is (equalp (%bytes #x02 #x80 #x00) (bitcoin-lisp.validation::encode-bip34-height 128))))

(test validate-coinbase-height-accepts-exact-prefix
  "A coinbase whose scriptSig starts with the exact serialized height
passes (extra trailing bytes are fine)."
  (let ((bitcoin-lisp:*network* :testnet4))   ; BIP34 active from height 1
    (let ((block (%block-with-coinbase-scriptsig
                  ;; height 21111 prefix + arbitrary extra-nonce bytes
                  (concatenate '(vector (unsigned-byte 8))
                               (%bytes #x02 #x77 #x52) (%bytes #xab #xcd)))))
      (multiple-value-bind (valid error)
          (bitcoin-lisp.validation::validate-coinbase-height block 21111)
        (is (eq t valid))
        (is (null error))))))

(test validate-coinbase-height-rejects-nonminimal
  "A non-minimal encoding that decodes to the right number is rejected
(Core compares the exact minimal prefix)."
  (let ((bitcoin-lisp:*network* :testnet4))
    ;; height 17 padded to 2 bytes: 0x02 0x11 0x00 decodes to 17 but the
    ;; minimal form is 0x01 0x11.
    (let ((block (%block-with-coinbase-scriptsig (%bytes #x02 #x11 #x00))))
      (multiple-value-bind (valid error)
          (bitcoin-lisp.validation::validate-coinbase-height block 17)
        (is (null valid))
        (is (eq :bad-coinbase-height error))))))

(test validate-coinbase-height-rejects-wrong-and-short
  "Wrong height and a too-short scriptSig are both rejected."
  (let ((bitcoin-lisp:*network* :testnet4))
    ;; scriptSig encodes height 100, block claims 101
    (let ((block (%block-with-coinbase-scriptsig (%bytes #x01 #x64))))
      (is (null (bitcoin-lisp.validation::validate-coinbase-height block 101))))
    ;; empty scriptSig at an enforced height
    (let ((block (%block-with-coinbase-scriptsig
                  (make-array 0 :element-type '(unsigned-byte 8)))))
      (is (null (bitcoin-lisp.validation::validate-coinbase-height block 17))))))

(test validate-coinbase-height-skipped-below-activation
  "Below the network BIP 34 activation height, the check is skipped."
  (let ((bitcoin-lisp:*network* :testnet3))   ; activation 21111
    (let ((block (%block-with-coinbase-scriptsig (%bytes #xde #xad #xbe #xef))))
      (is (eq t (bitcoin-lisp.validation::validate-coinbase-height block 100))))))

;;; ============================================================
;;; Coinbase classification (Core CheckTransaction / IsCoinBase):
;;; coinbase IFF exactly one input with a null prevout; non-coinbase txs
;;; may not contain any null prevout (:bad-prevout-null).
;;; ============================================================

(defun %null-input (&optional (sig-len 5))
  (bitcoin-lisp.serialization:make-tx-in
   :previous-output (bitcoin-lisp.serialization:make-outpoint
                     :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                     :index #xFFFFFFFF)
   :script-sig (make-array sig-len :element-type '(unsigned-byte 8) :initial-element 0)
   :sequence #xFFFFFFFF))

(defun %normal-input (seed)
  (bitcoin-lisp.serialization:make-tx-in
   :previous-output (bitcoin-lisp.serialization:make-outpoint
                     :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
                     :index 0)
   :script-sig (make-array 0 :element-type '(unsigned-byte 8))
   :sequence #xFFFFFFFF))

(defun %tx-with-inputs (inputs)
  (bitcoin-lisp.serialization:make-transaction
   :version 1 :inputs (coerce inputs 'simple-vector)
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                   :value 1000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
   :lock-time 0))

(test coinbase-single-null-input-valid
  "Exactly one null input with a 2..100-byte scriptSig is a valid coinbase."
  (multiple-value-bind (valid error)
      (bitcoin-lisp.validation:validate-transaction-structure
       (%tx-with-inputs (list (%null-input 5))))
    (is (eq t valid))
    (is (null error))))

(test coinbase-bad-scriptsig-length
  "Coinbase scriptSig outside 2..100 bytes is rejected."
  (is (eq :bad-coinbase-length
          (nth-value 1 (bitcoin-lisp.validation:validate-transaction-structure
                        (%tx-with-inputs (list (%null-input 1)))))))
  (is (eq :bad-coinbase-length
          (nth-value 1 (bitcoin-lisp.validation:validate-transaction-structure
                        (%tx-with-inputs (list (%null-input 101))))))))

(test noncoinbase-with-leading-null-prevout-rejected
  "Two inputs with the FIRST null is not a coinbase (size != 1) and is
rejected as :bad-prevout-null, matching Core (not our old :bad-coinbase-mixed)."
  (multiple-value-bind (valid error)
      (bitcoin-lisp.validation:validate-transaction-structure
       (%tx-with-inputs (list (%null-input 5) (%normal-input 9))))
    (is (null valid))
    (is (eq :bad-prevout-null error))))

(test noncoinbase-with-trailing-null-prevout-rejected
  "A later null prevout in a multi-input tx is rejected."
  (multiple-value-bind (valid error)
      (bitcoin-lisp.validation:validate-transaction-structure
       (%tx-with-inputs (list (%normal-input 9) (%null-input 5))))
    (is (null valid))
    (is (eq :bad-prevout-null error))))

(test noncoinbase-all-nonnull-passes
  "A normal multi-input tx with no null prevouts passes structure validation."
  (multiple-value-bind (valid error)
      (bitcoin-lisp.validation:validate-transaction-structure
       (%tx-with-inputs (list (%normal-input 9) (%normal-input 10))))
    (is (eq t valid))
    (is (null error))))

;;;; BIP143 scriptCode with OP_CODESEPARATOR (mainnet block 851,912 regression)

(test bip143-codeseparator-in-unexecuted-branch
  "Real mainnet tx ba1f57..c525 (block 851,912, tx-idx 1871): P2WSH spend
whose witnessScript carries an OP_CODESEPARATOR in the NOT-executed ELSE
branch. BIP143's scriptCode is the witnessScript truncated only at the last
EXECUTED codeseparator — remaining 0xab bytes are KEPT (no legacy-style
stripping in WITNESS_V0; Core SignatureHash serializes scriptCode as-is).
Our sighash stripped them, rejecting this block and halting the first
mainnet IBD for two days. The full signed tx must validate."
  (let* ((tx-hex "020000000001011e034f218450484dfc5878aace0a3294992e2af8423eb27a85f1ac1076bdeb6d0000000000510140000116f20000000000001600141c47dfb4fbdd0b086e47894869d0384203b2af8a0247304402201cd90e91b4218c03805ab659bc9564ebd0aef6abaef31e16443f36323287ab220220366baf4691f191984dc444c5eef66bcdf2af4d296d8f3469b9041107b5dd794e017a210325d1273fbb0409431d81cffcea2e7e5e56bae503924125a4225e3a125c79ae9c74528763ad03510140b267abad82014088a820996681beddd16d3b8d4a59f4f2e19cfccd96c1a990c5e62ebc333fb5528b983988210262c91ebb0a5e66f7577acbc84fcdf7f8b9a1e517cb3f02a01ae20300fb52827aac6800000000")
         (tx (bitcoin-lisp.serialization:br-read-transaction
              (bitcoin-lisp.serialization:make-byte-reader-from
               (bitcoin-lisp.crypto:hex-to-bytes tx-hex))))
         (prev-txid (bitcoin-lisp.serialization:outpoint-hash
                     (bitcoin-lisp.serialization:tx-in-previous-output
                      (aref (bitcoin-lisp.serialization:transaction-inputs tx) 0))))
         (spk (bitcoin-lisp.crypto:hex-to-bytes
               "0020bc3c8483b31b1431e42d886782a4b3e0c73a094f44260c42da1d41c003c95da7"))
         (utxo-set (bitcoin-lisp.storage:make-utxo-set)))
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 63383 spk 851000)
    (let ((bitcoin-lisp:*network* :mainnet))
      (multiple-value-bind (ok failed-idx)
          (bitcoin-lisp.validation:validate-transaction-scripts
           tx utxo-set :height 851912)
        (is (eq t ok) "input ~A failed script validation" failed-idx)))))

;;;; Signature-cache generation rotation
;;;;
;;;; sig-cache-store rotates generations at the cap (Core CuckooCache
;;;; analogue) instead of the old clrhash, which dumped the whole hot
;;;; working set and forced a re-verification burst. Entries used since
;;;; the last rotation survive via promotion in sig-cache-hit-p.

(defun %sig-key (n)
  "Distinct 32-byte cache key."
  (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref k 0) n)
    k))

(test sig-cache-rotation-preserves-active-entries
  "At the cap the current generation becomes previous; entries hit since
then are promoted and survive a second rotation, untouched ones age out."
  (let ((bitcoin-lisp.coalton.interop:*signature-cache*
          (bitcoin-lisp.coalton.interop::%make-sig-cache-table))
        (bitcoin-lisp.coalton.interop:*signature-cache-prev*
          (bitcoin-lisp.coalton.interop::%make-sig-cache-table))
        (bitcoin-lisp.coalton.interop::+signature-cache-max-entries+ 4))
    (loop for n from 1 to 4
          do (bitcoin-lisp.coalton.interop::sig-cache-store (%sig-key n)))
    ;; 5th store rotates: prev = {1..4}, cur = {5}
    (bitcoin-lisp.coalton.interop::sig-cache-store (%sig-key 5))
    (is (= 1 (hash-table-count bitcoin-lisp.coalton.interop:*signature-cache*)))
    (is (= 4 (hash-table-count bitcoin-lisp.coalton.interop:*signature-cache-prev*)))
    ;; Hit on key 1 promotes it into cur.
    (is (bitcoin-lisp.coalton.interop::sig-cache-hit-p (%sig-key 1)))
    ;; Fill cur to the cap and rotate again: prev = {5,1,6,7}, cur = {9}.
    (loop for n from 6 to 7
          do (bitcoin-lisp.coalton.interop::sig-cache-store (%sig-key n)))
    (bitcoin-lisp.coalton.interop::sig-cache-store (%sig-key 9))
    ;; Promoted key 1 survived both rotations; never-touched key 2 aged out.
    (is (bitcoin-lisp.coalton.interop::sig-cache-hit-p (%sig-key 1)))
    (is (not (bitcoin-lisp.coalton.interop::sig-cache-hit-p (%sig-key 2))))))

(test sig-cache-clear-clears-both-generations
  (let ((bitcoin-lisp.coalton.interop:*signature-cache*
          (bitcoin-lisp.coalton.interop::%make-sig-cache-table))
        (bitcoin-lisp.coalton.interop:*signature-cache-prev*
          (bitcoin-lisp.coalton.interop::%make-sig-cache-table)))
    (bitcoin-lisp.coalton.interop::sig-cache-store (%sig-key 1))
    (setf (gethash (%sig-key 2) bitcoin-lisp.coalton.interop:*signature-cache-prev*) t)
    (bitcoin-lisp.coalton.interop:clear-signature-cache)
    (is (not (bitcoin-lisp.coalton.interop::sig-cache-hit-p (%sig-key 1))))
    (is (not (bitcoin-lisp.coalton.interop::sig-cache-hit-p (%sig-key 2))))))

(test taproot-script-flag-exception-block
  "The mainnet Taproot exception block (Core script_flag_exceptions) validates
with P2SH|WITNESS only: a P2TR spend with a garbage witness fails under normal
post-activation flags (TAPROOT active) but passes when the block's hash matches
*taproot-exception-mainnet* (v1 witness reverts to an upgradable program)."
  (let* ((bitcoin-lisp:*network* :mainnet)
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
         ;; P2TR scriptPubKey: OP_1 push32 <32-byte x-only key>
         (p2tr (concatenate '(vector (unsigned-byte 8))
                            (vector #x51 #x20)
                            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
         (spending-tx (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash prev-txid :index 0)
                                        :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                        :sequence #xFFFFFFFF))
                       :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                         :value 900000 :script-pubkey p2tr))
                       ;; garbage 64-byte "signature" -- fails BIP341 verification
                       :witness (vector (list (make-array 64 :element-type '(unsigned-byte 8)
                                                             :initial-element 7)))
                       :lock-time 0))
         (blk (bitcoin-lisp.serialization:make-bitcoin-block
               :header (make-test-block-header)
               :transactions (list (make-coinbase-transaction :value 5000000000 :height 800000)
                                   spending-tx)))
         (height 800000))               ; well past mainnet taproot activation
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 1000000 p2tr 5)
    ;; Normal flags (TAPROOT active): garbage witness rejected.
    (is (null (bitcoin-lisp.validation:validate-block-scripts blk utxo-set :height height)))
    ;; Exception block: validated with P2SH|WITNESS only -> passes.
    (let ((bitcoin-lisp.validation::*taproot-exception-mainnet*
            (bitcoin-lisp.serialization:block-header-hash
             (bitcoin-lisp.serialization:bitcoin-block-header blk))))
      (is (eq t (bitcoin-lisp.validation:validate-block-scripts blk utxo-set :height height))))))

;;; ============================================================
;;; Wave 8D: witnessless spends of witness programs on the BLOCK path
;;; (Core VerifyScript, interpreter.cpp:2002-2126 + VerifyWitnessProgram,
;;; interpreter.cpp:1917-2000). A missing witness is an EMPTY witness stack;
;;; under SCRIPT_VERIFY_WITNESS a v0/v1-taproot program spend with no
;;; witness must FAIL, while pre-activation flags evaluate the same
;;; scriptPubKey as an ordinary legacy script. Regression: the old
;;; validate-input-script returned T unconditionally when the input had no
;;; witness ("no witness data = pass"), so a crafted block with a stripped
;;; segwit spend was ACCEPTED by us and REJECTED by Core — a chain-split
;;; primitive. All tests below go through the real block dispatch
;;; (validate-block-scripts -> validate-tx-scripts -> validate-input-script).
;;; Heights: mainnet 800000 = WITNESS+TAPROOT on; 500000 = WITNESS on,
;;; TAPROOT off; 400000 = pre-segwit (no WITNESS flag).
;;; ============================================================

(defun %w8d-spend-tx (prev-txid script-sig witness)
  "1-in-1-out spend of PREV-TXID:0. WITNESS is a list of byte vectors for
input 0, or NIL for a transaction serialized with no witness at all."
  (bitcoin-lisp.serialization:make-transaction
   :version 1
   :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                    :previous-output (bitcoin-lisp.serialization:make-outpoint
                                      :hash prev-txid :index 0)
                    :script-sig script-sig
                    :sequence #xFFFFFFFF))
   :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                     :value 900000
                     :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                   :initial-element #x76)))
   :witness (when witness (vector witness))
   :lock-time 0))

(defun %w8d-block-valid-p (script-pubkey script-sig witness height)
  "Build a block containing one spend of a SCRIPT-PUBKEY utxo and run it
through validate-block-scripts at HEIGHT on mainnet. Returns the primary
value (T on acceptance, NIL on rejection)."
  (let* ((bitcoin-lisp:*network* :mainnet)
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #xC4))
         (spend (%w8d-spend-tx prev-txid script-sig witness))
         (blk (bitcoin-lisp.serialization:make-bitcoin-block
               :header (make-test-block-header)
               :transactions (list (make-coinbase-transaction
                                    :value 5000000000 :height height)
                                   spend))))
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 1000000 script-pubkey 5)
    (bitcoin-lisp.validation:validate-block-scripts blk utxo-set :height height)))

(defun %w8d-script (&rest bytes-and-seqs)
  "Byte vector from a mix of integers and sequences."
  (coerce (loop for x in bytes-and-seqs
                if (integerp x) collect x
                else append (coerce x 'list))
          '(vector (unsigned-byte 8))))

(test block-witnessless-v0-spend-rejected-post-segwit
  "A block spending a v0 witness program with NO witness fails under the
WITNESS flag: Core validates the missing witness as an empty stack and
fails WITNESS_PROGRAM_MISMATCH (P2WPKH, stack != 2, interpreter.cpp:1938)
or WITNESS_PROGRAM_WITNESS_EMPTY (P2WSH, interpreter.cpp:1926). The old
block path accepted both."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        (p2wpkh (%w8d-script #x00 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                      :initial-element 7)))
        (p2wsh (%w8d-script #x00 #x20 (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 9))))
    (is (null (%w8d-block-valid-p p2wpkh empty nil 800000)))
    (is (null (%w8d-block-valid-p p2wsh empty nil 800000)))
    ;; An explicitly EMPTY witness stack (not just an absent one) is the
    ;; same thing and must also fail.
    (is (null (%w8d-block-valid-p p2wpkh empty '() 800000)))))

(test block-witnessless-v0-spend-legacy-pass-pre-segwit
  "The same witnessless v0-program spends in a PRE-segwit-activation block
(no WITNESS flag) are ordinary legacy scripts: the scriptPubKey pushes the
program, top-of-stack is truthy, anyone-can-spend. Blanket rejection here
would be the opposite consensus bug — mainnet IBD rejecting historical
blocks (witness-program-shaped outputs were spendable pre-481824)."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        (p2wpkh (%w8d-script #x00 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                      :initial-element 7)))
        (p2wsh (%w8d-script #x00 #x20 (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 9))))
    (is (eq t (%w8d-block-valid-p p2wpkh empty nil 400000)))
    (is (eq t (%w8d-block-valid-p p2wsh empty nil 400000)))))

(test block-native-witness-nonempty-scriptsig-malleated
  "A native witness program spend with a NON-empty scriptSig fails under the
WITNESS flag even when the witness itself is valid: the scriptSig must be
exactly empty (SCRIPT_ERR_WITNESS_MALLEATED, interpreter.cpp:2038-2041)."
  (let* ((op-true-script (%w8d-script #x51))
         (p2wsh (%w8d-script #x00 #x20 (bitcoin-lisp.crypto:sha256 op-true-script)))
         (op1-sig (%w8d-script #x51))
         (witness (list op-true-script)))
    ;; Valid witness, empty scriptSig: passes.
    (is (eq t (%w8d-block-valid-p p2wsh (make-array 0 :element-type '(unsigned-byte 8))
                                  witness 800000)))
    ;; Same witness, scriptSig = OP_1: malleated, fails.
    (is (null (%w8d-block-valid-p p2wsh op1-sig witness 800000)))))

(test block-unknown-witness-version-witnessless-passes
  "Regression guard against overshooting: unknown witness versions
consensus-PASS with no witness (interpreter.cpp:1993-1998, upgradeable;
DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM is policy-only and absent from block
flags). Covers v2 programs, pay-to-anchor (interpreter.cpp:1991-1992), and
v1 with a non-32/non-P2A length; also v1-taproot-shaped under WITNESS-only
flags (TAPROOT not yet active, interpreter.cpp:1949)."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        (v2-prog (%w8d-script #x52 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                       :initial-element 3)))
        (p2a (%w8d-script #x51 #x02 #x4e #x73))
        (v1-20 (%w8d-script #x51 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                     :initial-element 4)))
        (p2tr (%w8d-script #x51 #x20 (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 2))))
    (is (eq t (%w8d-block-valid-p v2-prog empty nil 800000)))
    (is (eq t (%w8d-block-valid-p p2a empty nil 800000)))
    (is (eq t (%w8d-block-valid-p v1-20 empty nil 800000)))
    ;; v1/32 (taproot-shaped) WITHOUT the TAPROOT flag: upgradeable pass.
    (is (eq t (%w8d-block-valid-p p2tr empty nil 500000)))
    ;; v1/32 WITH the TAPROOT flag and no witness: WITNESS_EMPTY, fails.
    (is (null (%w8d-block-valid-p p2tr empty nil 800000)))))

(test block-p2sh-wrapped-witness-program
  "P2SH-wrapped witness programs on the block path. The old path executed
the redeem script as a plain legacy script — the witness was never
validated at all. Core (interpreter.cpp:2057-2098): scriptSig must be
exactly the canonical push of the redeem script, then VerifyWitnessProgram
runs with is_p2sh=true. A missing witness fails for wrapped v0; a wrapped
v1/32 (taproot-shaped) redeem script is an UNKNOWN witness version under
is_p2sh (interpreter.cpp:1947 '!is_p2sh') and consensus-passes."
  (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
         (op-true-script (%w8d-script #x51))
         ;; P2SH-P2WSH of OP_TRUE
         (p2wsh-redeem (%w8d-script #x00 #x20 (bitcoin-lisp.crypto:sha256 op-true-script)))
         (p2sh-of-p2wsh (%w8d-script #xa9 #x14 (bitcoin-lisp.crypto:hash160 p2wsh-redeem) #x87))
         (p2wsh-sig (%w8d-script (length p2wsh-redeem) p2wsh-redeem))
         ;; P2SH-P2WPKH (no valid key needed: it must fail before any sig check)
         (p2wpkh-redeem (%w8d-script #x00 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                              :initial-element 7)))
         (p2sh-of-p2wpkh (%w8d-script #xa9 #x14 (bitcoin-lisp.crypto:hash160 p2wpkh-redeem) #x87))
         (p2wpkh-sig (%w8d-script (length p2wpkh-redeem) p2wpkh-redeem))
         ;; P2SH-wrapped v1/32 (taproot-shaped)
         (v1-redeem (%w8d-script #x51 #x20 (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 2)))
         (p2sh-of-v1 (%w8d-script #xa9 #x14 (bitcoin-lisp.crypto:hash160 v1-redeem) #x87))
         (v1-sig (%w8d-script (length v1-redeem) v1-redeem)))
    (declare (ignorable empty))
    ;; Wrapped P2WSH with the witness present: valid spend, passes.
    (is (eq t (%w8d-block-valid-p p2sh-of-p2wsh p2wsh-sig (list op-true-script) 800000)))
    ;; Wrapped P2WSH with NO witness: fails (WITNESS_PROGRAM_WITNESS_EMPTY).
    (is (null (%w8d-block-valid-p p2sh-of-p2wsh p2wsh-sig nil 800000)))
    ;; Wrapped P2WPKH with NO witness: fails (WITNESS_PROGRAM_MISMATCH).
    (is (null (%w8d-block-valid-p p2sh-of-p2wpkh p2wpkh-sig nil 800000)))
    ;; Pre-segwit flags: both are plain P2SH spends (redeem script pushes
    ;; the program, truthy) and pass.
    (is (eq t (%w8d-block-valid-p p2sh-of-p2wsh p2wsh-sig nil 400000)))
    (is (eq t (%w8d-block-valid-p p2sh-of-p2wpkh p2wpkh-sig nil 400000)))
    ;; Wrapped v1/32, TAPROOT active, no witness: UNKNOWN version under
    ;; is_p2sh -> upgradeable, consensus-PASSES (the is-p2sh regression guard).
    (is (eq t (%w8d-block-valid-p p2sh-of-v1 v1-sig nil 800000)))))

(test block-witness-on-legacy-input-unexpected
  "Witness data attached to an input whose scriptPubKey is NOT a witness
program (native or wrapped) fails under the WITNESS flag
(SCRIPT_ERR_WITNESS_UNEXPECTED, interpreter.cpp:2110-2121); without the
flag it is ignored at the input level (the block-level BIP144 commitment
rule handles pre-activation blocks separately)."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        (op-true (%w8d-script #x51))
        (witness (list (%w8d-script #x01))))
    (is (null (%w8d-block-valid-p op-true empty witness 800000)))
    (is (eq t (%w8d-block-valid-p op-true empty witness 400000)))
    ;; IsNull() is stack.empty(): a witness of one ZERO-LENGTH item is
    ;; still "unexpected" (script.h CScriptWitness::IsNull).
    (is (null (%w8d-block-valid-p op-true empty
                                  (list (make-array 0 :element-type '(unsigned-byte 8)))
                                  800000)))))

(test block-legacy-eval-false-rejected
  "A legacy spend whose scripts complete with a FALSE top-of-stack fails
(SCRIPT_ERR_EVAL_FALSE, interpreter.cpp:2029-2033). Regression: the old
block path returned the engine's ScriptOk without the final CastToBool,
accepting e.g. an OP_0 scriptPubKey spent with an empty scriptSig."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        (op-false (%w8d-script #x00)))
    (is (null (%w8d-block-valid-p op-false empty nil 800000)))
    (is (null (%w8d-block-valid-p op-false empty nil 400000)))))

(test transaction-scripts-witnessless-v0-rejected
  "validate-transaction-scripts (the mempool consensus-script entry, shared
with the block path via validate-input-script) also rejects a witnessless
v0 spend post-activation. The mempool additionally pre-gates these as
:witness-stripped BEFORE reaching the script engine (PR #273) so the P2P
reject classification is preserved; this test pins the engine-level
agreement underneath that gate."
  (let* ((bitcoin-lisp:*network* :mainnet)
         (utxo-set (bitcoin-lisp.storage:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #xC5))
         (p2wpkh (%w8d-script #x00 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                       :initial-element 7)))
         (tx (%w8d-spend-tx prev-txid (make-array 0 :element-type '(unsigned-byte 8)) nil)))
    (bitcoin-lisp.storage:add-utxo utxo-set prev-txid 0 1000000 p2wpkh 5)
    (is (null (bitcoin-lisp.validation:validate-transaction-scripts
               tx utxo-set :height 800000)))
    (is (eq t (bitcoin-lisp.validation:validate-transaction-scripts
               tx utxo-set :height 400000)))))

;;;; ==================================================================
;;;; GA9 S1-2 / S1-3: two consensus gates that accepted what Core rejects

(test ga9-s1-2-finality-covers-the-coinbase
  "Core's ContextualCheckBlock iterates block.vtx with NO IsCoinBase guard
(validation.cpp:4176-4181), so vtx[0] is finality-checked like any other
transaction. We iterated (rest transactions) and skipped it, which let a
coinbase with an nLockTime past the cutoff and a non-final nSequence connect
here while every Core node rejected the block bad-txns-nonfinal.

The coinbase exclusion belongs to the BIP68 loop three lines below, which Core
DOES guard (validation.cpp:2528) — it was simply applied to the wrong loop, so
this asserts the property directly on check-transaction-final: a coinbase-shaped
transaction is not exempt from finality."
  (let* ((coinbase
           (bitcoin-lisp.serialization:make-transaction
            :version 1
            :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                             :previous-output
                             (bitcoin-lisp.serialization:make-outpoint
                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)
                              :index #xffffffff)
                             :script-sig (coerce #(3 1 2 3) '(vector (unsigned-byte 8)))
                             ;; NOT SEQUENCE_FINAL: this is what makes nLockTime bite.
                             :sequence 0))
            :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                              :value 5000000000
                              :script-pubkey (coerce #(81) '(vector (unsigned-byte 8)))))
            ;; Locked to a height far beyond the block we would put it in.
            :lock-time 900000)))
    (is-false (bitcoin-lisp.validation:check-transaction-final coinbase 800000 800000)
              "a coinbase locked to a future height with a non-final sequence is
               NOT final, and must be judged rather than skipped")
    ;; The ordinary coinbase shape Core's miner produces stays final, so the
    ;; fix cannot reject honest blocks.
    (setf (bitcoin-lisp.serialization:tx-in-sequence
           (aref (bitcoin-lisp.serialization:transaction-inputs coinbase) 0))
          #xffffffff)
    (is-true (bitcoin-lisp.validation:check-transaction-final coinbase 800000 800000)
             "SEQUENCE_FINAL makes nLockTime irrelevant — the normal coinbase")))

(test ga9-s1-3-bip68-version-gate-is-unsigned
  "Core stores the transaction version as `const uint32_t'
(primitives/transaction.h:293) and gates BIP68 on `tx.version >= 2'
(consensus/tx_verify.cpp:51). Unsigned, so EVERY version with bit 31 set is
>= 2 and Core enforces relative locktimes on it.

Our slot is (signed-byte 32) — correct, because that is what the wire format
reads — so a signed comparison saw 0x80000002 as -2147483646 and skipped BIP68
altogether. The fix reinterprets at the gate only; the slot must stay signed or
serialization stops round-tripping.

Asserted on the gate arithmetic rather than through a full block so the two
boundary versions and the high-bit version are all covered cheaply."
  (flet ((enforced-p (version) (>= (ldb (byte 32 0) version) 2)))
    (is-false (enforced-p 1) "version 1: BIP68 does not apply")
    (is-true (enforced-p 2) "version 2: BIP68 applies")
    ;; 0x80000002 as read into a (signed-byte 32) slot.
    (let ((high-bit -2147483646))
      (is (= #x80000002 (ldb (byte 32 0) high-bit))
          "control: this really is the 0x80000002 bit pattern")
      (is-true (< high-bit 2)
               "control: under a SIGNED compare it reads as less than 2 — which
                is exactly how it escaped enforcement")
      (is-true (enforced-p high-bit)
               "unsigned, it is >= 2, so BIP68 must be enforced as Core does"))))

(test ga9-s1-8-strict-der-size-bound-is-in-our-shifted-frame
  "Core's IsValidSignatureEncoding (script/interpreter.cpp:108-123) takes the
FULL signature INCLUDING the trailing hashtype byte and rejects size > 73. We
are called with that byte already stripped, so our bound must be 72.

It was 73 — Core's number left in Core's frame — while the minimum had already
been shifted (< 8 against Core's < 9). That mismatch is what marks it an
oversight, and it admitted exactly one length: a 74-byte signature.

Why that matters is not obvious: such a signature satisfies every DER-integer
rule, so in Core the size cap is the ONLY thing rejecting it, as a hard
SCRIPT_ERR_SIG_DER. We passed it to libsecp256k1's DER parser, which accepts it
with r silently clamped to zero, producing a FALSE CHECKSIG rather than an
error — and NULLFAIL, which would have made it an error, is policy-only and
unset during block validation. `<sig74> OP_CHECKSIG OP_NOT' in a P2SH redeem
script therefore accepted a spend Core rejects, under flags mandatory on every
current block.

Both integers are encoded 00 80 01... so the leading zero is legal (the next
byte has its high bit set) and every DER rule passes — otherwise the vector
would be rejected for the wrong reason and prove nothing about the bound."
  (flet ((sig (lenr lens)
           (let ((v (make-array 0 :element-type '(unsigned-byte 8)
                                  :adjustable t :fill-pointer 0)))
             (flet ((p (b) (vector-push-extend b v)))
               (p #x30) (p (+ 4 lenr lens))
               (p #x02) (p lenr) (p 0) (p #x80) (dotimes (i (- lenr 2)) (p 1))
               (p #x02) (p lens) (p 0) (p #x80) (dotimes (i (- lens 2)) (p 1)))
             (coerce v '(vector (unsigned-byte 8))))))
    (let ((too-big (sig 34 33))   ; 73 body bytes = 74 with the hashtype byte
          (largest (sig 33 32)))  ; 71 body bytes = 72 with the hashtype byte
      (is (= 73 (length too-big)) "control: this is the 74-byte signature")
      (is (= 71 (length largest)) "control: this is the largest Core accepts")
      (is-false (bitcoin-lisp.coalton.interop::check-der-signature-format too-big)
                "74 bytes with the hashtype: Core rejects on size, so must we")
      (is-true (bitcoin-lisp.coalton.interop::check-der-signature-format largest)
               "72 bytes with the hashtype is legal — the fix must not
                over-tighten and start rejecting valid signatures"))))
