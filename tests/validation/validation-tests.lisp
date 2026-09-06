(in-package #:bitcoin-lisp.tests)

(in-suite :validation-tests)

;;;; Transaction Structure Validation Tests

(defun make-test-transaction (&key (inputs 1) (outputs 1) (value 50000000))
  "Create a simple test transaction with specified parameters."
  (let ((tx-inputs (loop for i below inputs
                         collect (bl.ser:make-tx-in
                                  :previous-output (bl.ser:make-outpoint
                                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                      :initial-element (1+ i))
                                                    :index 0)
                                  :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                                          :initial-element #x00)
                                  :sequence #xFFFFFFFF)))
        (tx-outputs (loop for i below outputs
                          collect (bl.ser:make-tx-out
                                   :value (floor value outputs)
                                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                              :initial-element #x76)))))
    (bl.ser:make-transaction
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
         (input (bl.ser:make-tx-in
                 :previous-output (bl.ser:make-outpoint
                                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)
                                   :index #xFFFFFFFF)
                 :script-sig coinbase-script
                 :sequence #xFFFFFFFF))
         (output (bl.ser:make-tx-out
                  :value value
                  :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                             :initial-element #x76))))
    (bl.ser:make-transaction
     :version 1
     :inputs (vector input)
     :outputs (vector output)
     :lock-time 0)))

(test activation-flushes-between-steps
  "Core flushes PERIODIC from ActivateBestChain (validation.cpp:3489). Ours did
not, and the coins cache therefore grew across every step and never drained:
*blocks-since-flush* is advanced ONLY by connect-block's tip-extension arm, so
reorg-connected blocks never triggered a periodic flush at all.

An unbounded cache on any long activation, which is a resource problem whatever
it costs in time. The SPEED effect is modest and worth not overselling: A/B on
the same offline reindex gave about 12%, not the order of magnitude the
per-step timings first suggested — most of the slowdown with height is
testnet4's own busy zone around 51,000-55,000.

The flush belongs BETWEEN steps, never inside PERFORM-REORG's connect loop,
which correctly refuses to flush because a rollback there rewinds in memory."
  (let ((src (with-open-file (in (merge-pathnames
                                  "src/validation/block.lisp"
                                  (asdf:system-source-directory :bitcoin-lisp)))
               (let ((text (make-string (file-length in))))
                 (subseq text 0 (read-sequence text in))))))
    (let ((activate (search "(defun activate-best-chain" src))
          (perform (search "(defun perform-reorg" src)))
      (is-true activate)
      (is-true perform)
      ;; The tip notification must be inside ACTIVATE-BEST-CHAIN, and the
      ;; periodic flush must be one of its subscribers.
      (let ((tip (search "notify-updated-block-tip" src :start2 activate)))
        (is-true tip "activate-best-chain no longer announces the tip between steps"))
      (is-true (member 'bl:maybe-periodic-flush (bl.vi:validation-hooks :updated-block-tip))
               "the periodic flush is no longer an :updated-block-tip hook")
      ;; And PERFORM-REORG's connect loop must still NOT flush — that refusal
      ;; is deliberate and load-bearing, so assert its note is still there.
      (is-true (search "deliberately NO maybe-critical-flush in this loop" src)
               "the connect loop's no-flush note is gone; if the flush was ~
added there, a crash mid-connect can roll forward onto a rejected branch"))))

(test activation-steps-are-bounded
  "PERFORM-REORG's connect loop never flushes — a rollback rewinds IN MEMORY, so
nothing lands until the whole call finishes. That makes an UNBOUNDED forward
activation the pathological case: reindexing a real testnet4 datadir asked for
134,922 blocks in one call and spent sixteen minutes at 97% CPU without writing
a coin or completing a step.

Core loops instead — each ActivateBestChainStep connects a bounded batch and
returns so the caller can flush. This asserts the step selection: far targets
are clipped to an ancestor, near ones are returned unchanged, and the clipped
target is always ON the target's own chain so a step is real progress rather
than a sideways move."
  (let* ((cs (bl.store:make-chain-state))
         (entries (make-array 3001))
         (prev nil))
    ;; A synthetic chain deep enough to exceed one step.
    (dotimes (h 3001)
      (let ((e (bl.store:make-block-index-entry
                :hash (let ((v (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 0)))
                        (setf (aref v 0) (ldb (byte 8 0) h)
                              (aref v 1) (ldb (byte 8 8) h))
                        v)
                :height h :chain-work h :status :valid :prev-entry prev)))
        (setf (aref entries h) e prev e)
        (bl.store:add-block-index-entry cs e)))
    (let ((tip (aref entries 0))
          (far (aref entries 3000)))
      ;; Far target: clipped to exactly one step above the tip.
      (let ((step (bl.val::%activation-step-target cs tip far)))
        (is (= bl.val::+activation-step-blocks+
               (bl.store:block-index-entry-height step))
            "a far target was not clipped to one step")
        ;; And it is genuinely an ancestor of the target, not some other entry
        ;; at that height — a step onto a different branch would be a reorg
        ;; away from where we are trying to go.
        (let ((walk far))
          (loop while (and walk (> (bl.store:block-index-entry-height walk)
                                   (bl.store:block-index-entry-height step)))
                do (setf walk (bl.store:block-index-entry-prev-entry walk)))
          (is (eq walk step) "the step target is not on the target's chain")))
      ;; Near target: returned unchanged, so a synced node pays nothing.
      (let ((near (aref entries 10)))
        (is (eq near (bl.val::%activation-step-target cs tip near))))
      ;; Exactly one step away is still the identity, not an off-by-one clip.
      (let ((exact (aref entries bl.val::+activation-step-blocks+)))
        (is (eq exact (bl.val::%activation-step-target cs tip exact))))
      ;; Stepping from a non-zero tip measures from THAT tip.
      (let* ((mid (aref entries 500))
             (step (bl.val::%activation-step-target cs mid far)))
        (is (= (+ 500 bl.val::+activation-step-blocks+)
               (bl.store:block-index-entry-height step)))))))

(test sync-loop-activates-from-disk-with-no-peers
  "With no peers the sync loop used to log \"No peers available\" and do
NOTHING else, so a node whose block index was complete but whose chainstate sat
at genesis could never catch up offline.

That is precisely the state a -reindex leaves behind, and with -connect=0 no
peer will ever arrive to trigger the activation. Core rebuilds entirely from
disk there — ActivateBestChain runs from startup, not only on an arriving
block. Measured against a real Core testnet4 datadir: 134,922 blocks indexed,
chainstate at height 0, and the node sat printing \"No peers available\" for as
long as it was left running.

The property is which CALL the no-peer branch makes, so it is asserted against
the source: a runtime assertion would need a full chain on disk."
  (let ((src (%node-source-text)))
    (let ((branch (search "No peers available, reconnecting" src)))
      (is-true branch "the no-peers branch is gone; this test needs rewriting")
      ;; The activation must come BEFORE the give-up-and-wait, or it never runs.
      (let ((activate (search "activate-best-chain" src :end2 branch :from-end t)))
        (is-true activate
                 "the no-peers branch no longer activates the chain from disk")
        (is (< activate branch))))))

(test script-check-pool-is-persistent-and-reusable
  "Core keeps ONE CCheckQueue for the life of the process (checkqueue.h) and
hands it batches; ours spawned a fresh thread per worker PER BLOCK. At one
block per ten minutes that is invisible; during IBD it is a thread creation per
block.

The properties that matter are reuse and RECOVERY: a batch that fails must not
poison the next one, and a worker that errors must count as a failure rather
than leaving the master waiting forever on a TODO that never reaches zero."
  (let ((pool (bl.val::ensure-script-check-pool 4)))
    (is-true pool)
    ;; The SAME pool comes back, threads and all — that is what "persistent"
    ;; means and what the per-block spawn was not.
    (is (eq pool (bl.val::ensure-script-check-pool 4)))
    (is (= 4 (length (bl.val::script-check-pool-threads pool))))
    (is-true (bl.val::run-script-checks
              pool (loop repeat 50 collect (lambda () t))))
    ;; One failure among many fails the batch.
    (is-false (bl.val::run-script-checks
               pool (append (loop repeat 20 collect (lambda () t))
                            (list (lambda () nil))
                            (loop repeat 20 collect (lambda () t)))))
    ;; And the pool is usable again immediately: a failed batch that left
    ;; `failed` set would make every later block fail script validation.
    (is-true (bl.val::run-script-checks
              pool (loop repeat 30 collect (lambda () t))))
    ;; An empty batch is trivially true rather than a wait on TODO=0 that
    ;; nothing will ever signal.
    (is-true (bl.val::run-script-checks pool nil))
    ;; A worker that ERRORS counts as a failure. Without the handler the
    ;; thread would die mid-item, TODO would never reach zero, and the master
    ;; would wait forever — a hung node, not a rejected block.
    (is-false (bl.val::run-script-checks
               pool (list (lambda () (error "deliberate")))))
    (is-true (bl.val::run-script-checks
              pool (loop repeat 10 collect (lambda () t)))
             "the pool did not recover from a worker error")
    ;; Every item runs exactly once — the master participates in the same
    ;; queue as the workers, so double-execution is a live possibility.
    (let* ((n 200)
           (counter (list 0))
           (lock (bt:make-lock "count")))
      (is-true (bl.val::run-script-checks
                pool (loop repeat n
                           collect (lambda ()
                                     (bt:with-lock-held (lock)
                                       (incf (first counter)))
                                     t))))
      (is (= n (first counter))
          "~D items ran ~D times" n (first counter)))
    (bl.val:stop-script-check-pool)
    (is-false bl.val::*script-check-pool*)))

(test par-follows-cores-semantics
  "Core's -par (init.cpp): 0 means one worker per core, a NEGATIVE value leaves
that many cores free, and the result is clamped to MAX_SCRIPTCHECK_THREADS.

The negative form is the one worth pinning. -par=-1 on a 4-core box means
THREE workers, not one; reading it as an absolute value would oversubscribe the
very machine the operator asked to leave headroom on."
  (let ((cores (bl.val::available-processor-count)))
    (is (plusp cores) "the processor count must be positive or -par=0 is broken")
    (is (= (min cores 15) (bl.val:parse-par-threads 0)))
    (is (= (min (1- cores) 15) (bl.val:parse-par-threads -1)))
    (is (= 2 (bl.val:parse-par-threads 2)))
    ;; Clamped to Core's maximum.
    (is (= 15 (bl.val:parse-par-threads 99)))
    ;; Never negative, however deep the subtraction goes.
    (is (= 0 (bl.val:parse-par-threads (- (+ cores 5))))))
  ;; -par reaches the worker count AND the on/off switch: Core's -par=1 means
  ;; no extra threads at all, which is not the same as "one worker".
  (let ((saved-n bl.val:*parallel-validation-workers*)
        (saved-p bl:*parallel-block-validation*))
    (unwind-protect
         (progn
           (bl::apply-config-globals '(("par" . "3")))
           (is (= 3 bl.val:*parallel-validation-workers*))
           (is-true bl:*parallel-block-validation*)
           (bl::apply-config-globals '(("par" . "1")))
           (is-false bl:*parallel-block-validation*
                     "-par=1 must disable the extra threads, as Core's does"))
      (setf bl.val:*parallel-validation-workers* saved-n
            bl:*parallel-block-validation* saved-p)))
  (is-true (bl:known-config-option-p "par"))
  (is-false (bl.cfg:core-only-option-p "par")))

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
         (utxo (bl.store:make-utxo-set))
         (coins (make-hash-table :test 'equalp))
         (in (aref (bl.ser:transaction-inputs tx) 0))
         (prevout (bl.ser:tx-in-previous-output in))
         (entry (bl.store:make-utxo-entry
                 :value 100000
                 :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))
                 :height 1 :coinbase nil)))
    (setf (gethash (cons (bl.ser:outpoint-hash prevout)
                         (bl.ser:outpoint-index prevout))
                   coins)
          entry)
    (let ((prefetched (bl.val::prefetch-block-spent-coins
                       block-txs utxo coins)))
      (is (= 1 (length prefetched))
          "one entry per NON-coinbase transaction, indexed like (rest txs)")
      (is (eq entry (aref (aref prefetched 0) 0))
          "the prefetch did not resolve the spent coin"))
    ;; And the handed-in coins are what get used: a DIFFERENT entry passed as
    ;; :spent-utxos must be the one the validator sees.
    (let* ((seen nil)
           (other (bl.store:make-utxo-entry
                   :value 42
                   :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))
                   :height 1 :coinbase nil))
           (real (symbol-function 'bl.val:validate-input-script)))
      (unwind-protect
           (progn
             (setf (symbol-function 'bl.val:validate-input-script)
                   (lambda (tx idx utxo) (declare (ignore tx idx))
                     (setf seen utxo) t))
             (bl.val::validate-tx-scripts
              tx 1 utxo "P2SH" 100 :spent-utxos (vector other))
             (is (eq other seen)
                 "validate-tx-scripts ignored the coins it was handed and ~
re-resolved them from the coins view"))
        (setf (symbol-function 'bl.val:validate-input-script)
              real)))))

(test valid-transaction-structure
  "A valid transaction should pass structure validation."
  (let ((tx (make-test-transaction :inputs 1 :outputs 2 :value 10000000)))
    (multiple-value-bind (valid error)
        (bl.val:validate-transaction-structure tx)
      (is (eq t valid))
      (is (null error)))))

(test transaction-no-inputs
  "Transaction without inputs should fail validation."
  (let ((tx (bl.ser:make-transaction
             :version 1
             :inputs #()
             :outputs (vector (bl.ser:make-tx-out
                             :value 1000
                             :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
             :lock-time 0)))
    (multiple-value-bind (valid error)
        (bl.val:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :no-inputs error)))))

(test transaction-oversize-beats-duplicate-inputs
  "CheckTransaction's consensus size limit, in Core's position.
Core rejects a transaction whose NON-WITNESS serialization times
WITNESS_SCALE_FACTOR exceeds MAX_BLOCK_WEIGHT (tx_check.cpp:17-20), and it
reaches that check BEFORE the duplicate-input check at :44. The distinction is
not academic: the only cheap way to build an oversize transaction is to repeat
one input, which is how mempool_accept.py:235 builds it, so a tree that checked
duplicates first would answer bad-txns-inputs-duplicate where Core answers
bad-txns-oversize and no reading of either tree would notice."
  (let* ((one-input (bl.ser:make-tx-in
                     :previous-output (bl.ser:make-outpoint
                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                            :initial-element 7)
                                       :index 0)
                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                     :sequence #xFFFFFFFF))
         ;; 41 bytes per input serialized; MAX_BLOCK_WEIGHT/4 = 1,000,000 bytes.
         (n (ceiling 1000000 41))
         (inputs (make-array n :initial-element one-input))
         (output (bl.ser:make-tx-out
                  :value 1000
                  :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
         (tx (bl.ser:make-transaction
              :version 1 :inputs inputs :outputs (vector output) :lock-time 0)))
    (multiple-value-bind (valid error)
        (bl.val:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :tx-oversize error)
          "an oversize transaction built from repeated inputs must report ~
oversize, as Core does, not duplicate inputs"))
    ;; Positive control: the same duplicate inputs UNDER the ceiling still
    ;; report duplicates, so the assertion above is about order, not about
    ;; having broken the duplicate check.
    (let ((small (bl.ser:make-transaction
                  :version 1
                  :inputs (vector one-input one-input)
                  :outputs (vector output)
                  :lock-time 0)))
      (is (eq :duplicate-inputs
              (nth-value 1 (bl.val:validate-transaction-structure small)))))))

(test tx-reject-reasons-cover-every-keyword
  "Every reject keyword a validation site can return has a Core string.
TX-REJECT-REASON-STRING falls back to the downcased keyword name, which is how
this codebase used to render ALL of them — a fallback that silently invents a
vocabulary Core does not speak. Rather than trust the table to stay complete,
scan the source for the keywords the sites actually return, the same way
RPC-ARG-CONVERSIONS-MATCH-CORE re-parses Core's client.cpp every battery."
  (let ((path (merge-pathnames "src/validation/transaction.lisp"
                               (asdf:system-source-directory :bitcoin-lisp)))
        (found '())
        (missing '()))
    (with-open-file (in path :if-does-not-exist nil)
      (is-true in "src/validation/transaction.lisp is unreadable")
      (when in
        (loop for line = (read-line in nil) while line
              do (let* ((composed (search "(values nil (list :" line))
                        (at (or composed (search "(values nil :" line))))
                   (when at
                     (let* ((start (+ at (length (if composed
                                                     "(values nil (list :"
                                                     "(values nil :"))))
                            (end (or (position-if-not
                                      (lambda (c) (or (alphanumericp c) (char= c #\-)))
                                      line :start start)
                                     (length line))))
                       (pushnew (intern (string-upcase (subseq line start end)) :keyword)
                                found)))))))
    ;; The scan must actually find things, or an empty result would pass.
    (is (> (length found) 20)
        "the scan found ~D keywords, which is too few to be the real set"
        (length found))
    (dolist (kw found)
      (unless (assoc kw bl.val:*tx-reject-reasons*)
        (push kw missing)))
    (is (null missing)
        "these reject keywords have no Core reject-reason string: ~{~A~^, ~}"
        missing)))

(test tx-reject-reason-strings-match-core
  "The renamings, spot-checked against the Core site each one cites.
These are the keywords whose downcased name is NOT Core's string, which is
exactly the set the old mechanical rendering got wrong."
  (flet ((r (kw) (bl.val:tx-reject-reason-string kw)))
    ;; validation.cpp PreChecks
    (is (string= "txn-already-in-mempool" (r :already-in-mempool)))
    (is (string= "txn-already-known" (r :already-known)))
    (is (string= "bad-txns-inputs-missingorspent" (r :missing-input)))
    (is (string= "coinbase" (r :coinbase-not-allowed)))
    ;; Core's casing, which a downcase destroys
    (is (string= "non-BIP68-final" (r :non-bip68-final)))
    ;; consensus/tx_check.cpp
    (is (string= "bad-txns-oversize" (r :tx-oversize)))
    (is (string= "bad-txns-vout-empty" (r :no-outputs)))
    (is (string= "bad-txns-inputs-duplicate" (r :duplicate-inputs)))
    (is (string= "bad-cb-length" (r :bad-coinbase-length)))
    ;; policy/policy.cpp IsStandardTx — note the two size rules are distinct
    (is (string= "version" (r :version-non-standard)))
    (is (string= "tx-size" (r :tx-weight-too-large)))
    (is (string= "scriptsig-size" (r :scriptsig-too-large)))
    (is (string= "scriptpubkey" (r :non-standard-output)))
    (is (string= "bare-multisig" (r :bare-multisig)))))

(test script-reject-reason-carries-core-s-script-error-string
  "Both script passes render Core's `<prefix> (<ScriptErrorString>)'.
Core builds the reason with
strprintf(\"mempool-script-verify-flag-failed (%s)\", ScriptErrorString(...))
(validation.cpp:2117-2119), so a client matching on the reason -- Core's own
functional suite among them -- reads the script error out of it. The two sites
return (KEYWORD SCRIPT-ERROR) and the renderer appends the message verbatim.
The sentences below are ScriptErrorString's own (script/script_error.cpp)."
  (flet ((r (reason) (bl.val:tx-reject-reason-string reason)))
    (is (string= "mempool-script-verify-flag-failed (Non-canonical DER signature)"
                 (r '(:mempool-script-verify-flag-failed :sig-der))))
    (is (string= "block-script-verify-flag-failed (Script failed an OP_CHECKSIGVERIFY operation)"
                 (r '(:block-script-verify-flag-failed :checksigverify))))
    (is (string= "mempool-script-verify-flag-failed (Using non-compressed keys in segwit)"
                 (r '(:mempool-script-verify-flag-failed :witness-pubkeytype))))
    ;; A pass that failed on something other than a script -- a coin we could
    ;; not resolve -- has no script error, and Core's own fallback is the
    ;; string \"unknown error\".
    (is (string= "mempool-script-verify-flag-failed (unknown error)"
                 (r '(:mempool-script-verify-flag-failed nil))))
    ;; Control: the bare keyword still renders the prefix alone, so the
    ;; parenthetical really comes from the second element.
    (is (string= "mempool-script-verify-flag-failed"
                 (r :mempool-script-verify-flag-failed)))))

(test transaction-no-outputs
  "Transaction without outputs should fail validation."
  (let ((tx (bl.ser:make-transaction
             :version 1
             :inputs (vector (bl.ser:make-tx-in
                            :previous-output (bl.ser:make-outpoint
                                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                :initial-element 1)
                                              :index 0)
                            :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                            :sequence #xFFFFFFFF))
             :outputs #()
             :lock-time 0)))
    (multiple-value-bind (valid error)
        (bl.val:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :no-outputs error)))))

(test transaction-duplicate-inputs
  "Transaction with duplicate inputs should fail validation."
  (let* ((same-outpoint (bl.ser:make-outpoint
                         :hash (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element 42)
                         :index 0))
         (empty-script (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bl.ser:make-transaction
              :version 1
              :inputs (vector (bl.ser:make-tx-in
                             :previous-output same-outpoint
                             :script-sig empty-script
                             :sequence #xFFFFFFFF)
                            (bl.ser:make-tx-in
                             :previous-output same-outpoint
                             :script-sig empty-script
                             :sequence #xFFFFFFFF))
              :outputs (vector (bl.ser:make-tx-out
                              :value 1000
                              :script-pubkey empty-script))
              :lock-time 0)))
    (multiple-value-bind (valid error)
        (bl.val:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :duplicate-inputs error)))))

(test transaction-negative-output
  "Transaction with negative output value should fail validation."
  (let* ((empty-script (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bl.ser:make-transaction
              :version 1
              :inputs (vector (bl.ser:make-tx-in
                             :previous-output (bl.ser:make-outpoint
                                               :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                 :initial-element 1)
                                               :index 0)
                             :script-sig empty-script
                             :sequence #xFFFFFFFF))
              :outputs (vector (bl.ser:make-tx-out
                              :value -1000
                              :script-pubkey empty-script))
              :lock-time 0)))
    (multiple-value-bind (valid error)
        (bl.val:validate-transaction-structure tx)
      (is (null valid))
      (is (eq :negative-output error)))))

;;;; Contextual Transaction Validation Tests

(test transaction-missing-input-utxo
  "Transaction spending non-existent UTXO should fail."
  (let ((tx (make-test-transaction :inputs 1 :outputs 1 :value 1000))
        (utxo-set (bl.store:make-utxo-set)))
    (multiple-value-bind (valid error fee)
        (bl.val:validate-transaction-contextual tx utxo-set 100)
      (declare (ignore fee))
      (is (null valid))
      (is (eq :missing-input error)))))

(test transaction-coinbase-maturity
  "Spending immature coinbase should fail."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add coinbase UTXO at height 50
    (bl.store:add-utxo utxo-set txid 0 5000000000 script 50 :coinbase t)
    ;; Try to spend at height 100 (only 50 blocks old, need 100)
    (let* ((input (bl.ser:make-tx-in
                   :previous-output (bl.ser:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bl.ser:make-tx-out
                    :value 4900000000
                    :script-pubkey script))
           (tx (bl.ser:make-transaction
                :version 1
                :inputs (vector input)
                :outputs (vector output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bl.val:validate-transaction-contextual tx utxo-set 100)
        (declare (ignore fee))
        (is (null valid))
        (is (eq :coinbase-not-mature error))))))

(test transaction-valid-spending
  "Valid transaction spending existing UTXO should pass."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    ;; Add non-coinbase UTXO
    (bl.store:add-utxo utxo-set txid 0 10000000 script 10)
    (let* ((input (bl.ser:make-tx-in
                   :previous-output (bl.ser:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bl.ser:make-tx-out
                    :value 9000000
                    :script-pubkey script))
           (tx (bl.ser:make-transaction
                :version 1
                :inputs (vector input)
                :outputs (vector output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bl.val:validate-transaction-contextual tx utxo-set 100)
        (is (eq t valid))
        (is (null error))
        ;; Fee is now a Satoshi type - unwrap to compare
        (is (= 1000000 (bl.interop:unwrap-satoshi fee)))))))  ; 10M - 9M = 1M fee

(test transaction-insufficient-funds
  "Transaction with outputs exceeding inputs should fail."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
        (empty-script (make-array 0 :element-type '(unsigned-byte 8))))
    (bl.store:add-utxo utxo-set txid 0 1000000 script 10)
    (let* ((input (bl.ser:make-tx-in
                   :previous-output (bl.ser:make-outpoint
                                     :hash txid
                                     :index 0)
                   :script-sig empty-script
                   :sequence #xFFFFFFFF))
           (output (bl.ser:make-tx-out
                    :value 2000000  ; More than input
                    :script-pubkey script))
           (tx (bl.ser:make-transaction
                :version 1
                :inputs (vector input)
                :outputs (vector output)
                :lock-time 0)))
      (multiple-value-bind (valid error fee)
          (bl.val:validate-transaction-contextual tx utxo-set 100)
        (declare (ignore fee))
        (is (null valid))
        (is (eq :insufficient-funds error))))))

;;;; MoneyRange, the three places Core asks for it on the INPUT side
;;;;
;;;; Core's CAmount is an int64 that wraps, so CheckTxInputs range-checks each
;;;; coin value and the running input sum (tx_verify.cpp:184-188) and the
;;;; derived fee (:202-209), and ConnectBlock range-checks the accumulated block
;;;; fee after every transaction (validation.cpp:2539-2544). Our Satoshi is an
;;;; unbounded Integer, so nothing here can overflow -- but the REJECTION is the
;;;; consensus rule, not the overflow it happens to prevent: an amount outside
;;;; MoneyRange must not be counted into a fee, and thence into the cap on what
;;;; a block's coinbase may pay itself. On a chain built from genesis the
;;;; output-side checks bound the supply inductively and none of these can fire;
;;;; what they add is a defence against a coins view seeded from elsewhere.

(defun %money-range-spend (prev-txid output-value)
  "A 1-in-1-out spend of PREV-TXID:0 paying OUTPUT-VALUE."
  (let ((script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.ser:make-transaction
     :version 1
     :inputs (vector (bl.ser:make-tx-in
                      :previous-output (bl.ser:make-outpoint :hash prev-txid :index 0)
                      :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                      :sequence #xFFFFFFFF))
     :outputs (vector (bl.ser:make-tx-out :value output-value :script-pubkey script))
     :lock-time 0)))

(test transaction-input-value-out-of-range
  "Core CheckTxInputs (tx_verify.cpp:184-188) rejects
bad-txns-inputvalues-outofrange when a spent coin's value, or the running sum of
them, leaves MoneyRange. Both the utxo-entry value slot and Core's CAmount are
signed 64-bit, so a coins view really can hold such a value."
  (let ((script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (flet ((err-of (coin-value)
             (let ((utxo-set (bl.store:make-utxo-set))
                   (txid (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element 1)))
               (bl.store:add-utxo utxo-set txid 0 coin-value script 10)
               (nth-value 1 (bl.val:validate-transaction-contextual
                             (%money-range-spend txid 1) utxo-set 100)))))
      (is (eq :input-values-out-of-range (err-of (* 3 bl.val:+max-money+))))
      (is (eq :input-values-out-of-range (err-of -1)))
      ;; Control: exactly MAX_MONEY is IN range (Core's MoneyRange is
      ;; inclusive), so the guard is a band and not a rejection of every large
      ;; coin.
      (is (null (err-of bl.val:+max-money+))))))

(test transaction-fee-out-of-range
  "The last statement of Core's CheckTxInputs (tx_verify.cpp:202-209): the
derived fee must be in MoneyRange. Core annotates its own guard as unreachable
GIVEN that CheckTransaction's output-side checks ran first -- so this test
reaches it the only way either implementation can, by calling CheckTxInputs
directly with an output value CheckTransaction would have refused."
  (let ((utxo-set (bl.store:make-utxo-set))
        (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
        (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
    (bl.store:add-utxo utxo-set txid 0 bl.val:+max-money+ script 10)
    ;; A negative output makes the fee MAX_MONEY + 1.
    (is (eq :fee-out-of-range
            (nth-value 1 (bl.val:validate-transaction-contextual
                          (%money-range-spend txid -1) utxo-set 100))))
    ;; Control: the same in-range coin with an ordinary output is accepted and
    ;; its fee reported, so the fixture is not simply unspendable.
    (multiple-value-bind (valid error fee)
        (bl.val:validate-transaction-contextual
         (%money-range-spend txid 1) utxo-set 100)
      (is-true valid)
      (is (null error))
      (is (= (1- bl.val:+max-money+) (bl.interop:unwrap-satoshi fee))))))

(test block-accumulated-fee-out-of-range
  "Core ConnectBlock (validation.cpp:2539-2544) range-checks the RUNNING fee sum
after every transaction, because that sum is what MAX-COINBASE-VALUE is derived
from: an out-of-range total would raise the cap on what the coinbase may pay
itself. Two transactions each paying a fee just under MAX_MONEY are individually
fine and together are not."
  (let* ((bl:*network* :mainnet)
         (height 800000)
         (chain-state (bl.store:make-chain-state))
         (utxo-set (bl.store:make-utxo-set))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
         (txids (loop for i below 2
                      collect (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element (+ 40 i)))))
    (dolist (txid txids)
      (bl.store:add-utxo utxo-set txid 0 bl.val:+max-money+ script 5))
    (flet ((verdict (spends)
             (let* ((txs (cons (bl.mining:build-coinbase-transaction
                                height 100000000
                                :script-pubkey script :segwit-active nil)
                               spends))
                    (blk (bl.ser:make-bitcoin-block
                          :header (bl.ser:make-block-header
                                   :version #x20000000
                                   :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                   :merkle-root (bl.val:compute-merkle-root
                                                 (mapcar #'bl.ser:transaction-hash txs))
                                   :timestamp 1700000000 :bits #x1d00ffff :nonce 0)
                          :transactions txs)))
               ;; The header and the input scripts are not what is under test;
               ;; the block is synthetic and unmined.
               (nth-value 1 (bl.val:validate-block
                             blk chain-state utxo-set height 1700000000
                             :skip-header t :skip-scripts t)))))
      ;; Control first: ONE such transaction leaves the running total in range,
      ;; so the block is accepted and the fixture is proven buildable.
      (is (null (verdict (list (%money-range-spend (first txids) 1)))))
      ;; Two of them do not.
      (is (eq :accumulated-fee-out-of-range
              (verdict (list (%money-range-spend (first txids) 1)
                             (%money-range-spend (second txids) 1))))))))

;;;; Block Validation Tests

(defun make-test-block-header (&key (version 1) (timestamp (get-universal-time))
                                (bits #x1d00ffff) (nonce 0))
  "Create a test block header."
  (bl.ser:make-block-header
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
         (state (bl.store:init-chain-state "/tmp/btc-test/")))
    (multiple-value-bind (valid error)
        (bl.val:validate-block-header header state current-time)
      (is (null valid))
      ;; Either error is acceptable - header is invalid
      (is (member error '(:time-too-new :bad-proof-of-work))))))

(test block-header-version-core-semantics
  "Version enforcement matches Core exactly: only softfork minimums.
High version-rolled values (overt AsicBoost) are NOT rejected — the old
upper bound rejected real mainnet block 544,085 and halted IBD."
  (let* ((current-time (get-universal-time))
         (state (bl.store:init-chain-state "/tmp/btc-test/")))
    ;; Version-rolled header far above the old #x3FFFFFFF bound: must not
    ;; fail on version (PoW will still fail for a test header).
    (multiple-value-bind (valid error)
        (bl.val:validate-block-header
         (make-test-block-header :version #x7FFFE000) state current-time)
      (declare (ignore valid))
      (is (not (eq error :bad-version))))
    ;; Version 0 with no height context: no minimum applies (pre-BIP34
    ;; semantics) — must not fail on version either.
    (multiple-value-bind (valid error)
        (bl.val:validate-block-header
         (make-test-block-header :version 0) state current-time)
      (declare (ignore valid))
      (is (not (eq error :bad-version))))
    ;; Below-minimum version at a post-activation height: rejected
    ;; (PoW may shadow it depending on check order — accept either).
    (multiple-value-bind (valid error)
        (bl.val:validate-block-header
         (make-test-block-header :version 1) state current-time
         :height (+ 1 (bl.val:get-bip34-activation-height
                       bl:*network*)))
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
                    (header (bl.ser:make-block-header
                             :version 1
                             :prev-block (copy-seq prev-hash)
                             :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0)
                             :timestamp ts
                             :bits #x1d00ffff
                             :nonce 0))
                    (entry (bl.store:make-block-index-entry
                            :hash hash
                            :height height
                            :header header
                            :prev-entry prev-entry
                            :chain-work 0
                            :status :valid)))
               ;; Give each block a unique hash based on height
               (setf (aref hash 0) (mod height 256))
               (setf (aref hash 1) (floor height 256))
               (setf (aref (bl.store:block-index-entry-hash entry) 0)
                     (mod height 256))
               (setf (aref (bl.store:block-index-entry-hash entry) 1)
                     (floor height 256))
               (bl.store:add-block-index-entry state entry)
               (setf prev-hash (bl.store:block-index-entry-hash entry))
               (setf prev-entry entry)))
    prev-hash))

(test mtp-timestamp-equal-rejected
  "Block with timestamp equal to MTP should be rejected.
PoW is checked first so we may get :bad-proof-of-work instead.
We verify MTP computation directly to confirm the check works."
  (let* ((state (bl.store:init-chain-state "/tmp/btc-mtp-test/"))
         ;; 11 blocks with timestamps 100..110, median = 105
         (timestamps (loop for i from 100 to 110 collect i))
         (prev-hash (build-chain-with-timestamps state timestamps)))
    ;; Verify MTP is computed correctly
    (let ((mtp (bl.val:compute-median-time-past state prev-hash)))
      (is (= 105 mtp)))
    ;; Verify header with timestamp=MTP is rejected
    (let ((header (bl.ser:make-block-header
                   :version 1
                   :prev-block prev-hash
                   :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                               :initial-element 0)
                   :timestamp 105  ; Equal to MTP
                   :bits #x1d00ffff
                   :nonce 0)))
      (multiple-value-bind (valid error)
          (bl.val:validate-block-header
           header state (+ 105 10000) :prev-hash prev-hash)
        (is (null valid))
        ;; Either error is acceptable - header is invalid
        (is (member error '(:time-too-old :bad-proof-of-work)))))))

(test mtp-timestamp-after-accepted
  "Block with timestamp after MTP should not get :time-too-old."
  (let* ((state (bl.store:init-chain-state "/tmp/btc-mtp-test2/"))
         ;; 11 blocks with timestamps 100..110, median = 105
         (timestamps (loop for i from 100 to 110 collect i))
         (prev-hash (build-chain-with-timestamps state timestamps))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block prev-hash
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element 0)
                  :timestamp 106  ; Greater than MTP of 105
                  :bits #x1d00ffff
                  :nonce 0)))
    (multiple-value-bind (valid error)
        (bl.val:validate-block-header
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
  (let* ((state (bl.store:init-chain-state "/tmp/btc-mtp-test3/"))
         (unknown (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (is (null (bl.val:compute-median-time-past state unknown)))
    (is (null (bl.val:compute-median-time-past-from-entry nil)))
    (is-true (bl.val:header-time-too-old-p
              (bl.ser:make-block-header
               :version 1 :prev-block unknown :merkle-root unknown
               :timestamp 1 :bits #x1d00ffff :nonce 0)
              nil))))

(test mtp-from-entry-matches-hash-lookup
  "compute-median-time-past-from-entry is the same walk as the hash-keyed
wrapper for a chain that IS indexed (Core CBlockIndex::GetMedianTimePast,
chain.h:233-246), including a partial window shorter than 11 blocks."
  (let* ((state (bl.store:init-chain-state "/tmp/btc-mtp-test4/"))
         (timestamps (loop for i from 200 to 214 collect i))
         (tip-hash (build-chain-with-timestamps state timestamps))
         (tip-entry (bl.store:get-block-index-entry state tip-hash)))
    ;; Full 11-block window over the last 11 timestamps (204..214), median 209.
    (is (= 209 (bl.val:compute-median-time-past state tip-hash)))
    (is (= 209 (bl.val:compute-median-time-past-from-entry tip-entry)))
    ;; Partial window: the height-2 entry has only 3 timestamps behind it
    ;; (200 201 202), and Core's index arithmetic picks 201.
    (let ((third (let ((e tip-entry))
                   (dotimes (i 12 e)
                     (setf e (bl.store:block-index-entry-prev-entry e))))))
      (is (= 2 (bl.store:block-index-entry-height third)))
      (is (= 201 (bl.val:compute-median-time-past-from-entry third)))
      (is (= 201 (bl.val:compute-median-time-past
                  state (bl.store:block-index-entry-hash third)))))))

;;;; Merkle Root Tests

(test merkle-root-single-tx
  "Merkle root of single transaction should be its hash."
  (let* ((tx (make-coinbase-transaction :value 5000000000 :height 1))
         (tx-hash (bl.ser:transaction-hash tx))
         (merkle-root (bl.val:compute-merkle-root (list tx-hash))))
    (is (equalp merkle-root tx-hash))))

(test merkle-root-two-txs
  "Merkle root of two transactions should be hash of concatenated hashes."
  (let* ((tx1 (make-coinbase-transaction :value 5000000000 :height 1))
         (tx2 (make-test-transaction :inputs 1 :outputs 1 :value 1000000))
         (hash1 (bl.ser:transaction-hash tx1))
         (hash2 (bl.ser:transaction-hash tx2))
         (merkle-root (bl.val:compute-merkle-root (list hash1 hash2)))
         ;; Manually compute expected: hash256(hash1 || hash2)
         (combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined hash1 :start1 0)
    (replace combined hash2 :start1 32)
    (let ((expected (bl.crypto:hash256 combined)))
      (is (equalp merkle-root expected)))))

(test merkle-root-empty
  "Merkle root of empty list should be zeros."
  (let ((merkle-root (bl.val:compute-merkle-root nil)))
    (is (every #'zerop merkle-root))))

;;;; BIP 34 Coinbase Height Tests

(test decode-coinbase-height-small
  "decode-coinbase-height should handle small heights encoded with OP_n."
  ;; OP_0 -> height 0
  (is (= 0 (bl.val:decode-coinbase-height
             (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(0)))))
  ;; OP_1 (0x51) -> height 1
  (is (= 1 (bl.val:decode-coinbase-height
             (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x51)))))
  ;; OP_16 (0x60) -> height 16
  (is (= 16 (bl.val:decode-coinbase-height
              (make-array 1 :element-type '(unsigned-byte 8) :initial-contents '(#x60))))))

(test decode-coinbase-height-push-bytes
  "decode-coinbase-height should handle heights encoded as byte pushes."
  ;; push1 100 -> height 100
  (is (= 100 (bl.val:decode-coinbase-height
               (make-array 2 :element-type '(unsigned-byte 8) :initial-contents '(1 100)))))
  ;; push2 0x00 0x01 -> height 256
  (is (= 256 (bl.val:decode-coinbase-height
               (make-array 3 :element-type '(unsigned-byte 8) :initial-contents '(2 0 1)))))
  ;; push3 for height 21111 = 0x5277 -> bytes: push3 #x77 #x52 #x00
  (is (= 21111 (bl.val:decode-coinbase-height
                 (make-array 4 :element-type '(unsigned-byte 8)
                               :initial-contents '(3 #x77 #x52 #x00))))))

(test decode-coinbase-height-empty-script
  "decode-coinbase-height should return NIL for empty scriptSig."
  (is (null (bl.val:decode-coinbase-height
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
    (let* ((output (bl.ser:make-tx-out
                    :value 0 :script-pubkey script))
           (coinbase (bl.ser:make-transaction
                      :version 1
                      :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element 0)
                                                       :index #xFFFFFFFF)
                                     :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                               :initial-element 1)))
                      :outputs (vector (bl.ser:make-tx-out :value 5000000000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                    :initial-element #x76))
                                     output)
                      :lock-time 0)))
      (let ((found (bl.val:find-witness-commitment coinbase)))
        (is (not (null found)))
        (is (equalp commitment-hash found))))))

(test find-witness-commitment-absent
  "Should return NIL when no witness commitment exists."
  (let ((coinbase (make-coinbase-transaction :value 5000000000 :height 1)))
    (is (null (bl.val:find-witness-commitment coinbase)))))

(defun %coinbase-with-commitment (cb-witness-stack)
  "A coinbase tx carrying a witness-commitment OP_RETURN output, whose coinbase
input witness stack is CB-WITNESS-STACK (a list of byte-vectors, or NIL for none)."
  (let ((script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref script 0) #x6a (aref script 1) #x24      ; OP_RETURN push36
          (aref script 2) #xaa (aref script 3) #x21      ; commitment header aa21a9ed
          (aref script 4) #xa9 (aref script 5) #xed)
    (bl.ser:make-transaction
     :version 1
     :inputs (vector (bl.ser:make-tx-in
                      :previous-output (bl.ser:make-outpoint
                                        :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                            :initial-element 0)
                                        :index #xFFFFFFFF)
                      :script-sig (make-array 4 :element-type '(unsigned-byte 8) :initial-element 1)))
     :outputs (vector (bl.ser:make-tx-out
                       :value 5000000000
                       :script-pubkey (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76))
                      (bl.ser:make-tx-out :value 0 :script-pubkey script))
     :lock-time 0
     :witness (vector cb-witness-stack))))

(test block-witness-stripped-p-detects-missing-nonce
  "block-witness-stripped-p is T when a block commits to witness but its coinbase
witness is missing or not exactly one 32-byte item, and NIL for a witness-complete
coinbase or one with no commitment. Guards the :weaker-chain store path so a
witness-stripped block never persists (the testnet4 BAD-WITNESS-NONCE-SIZE wedge)."
  (flet ((blk (coinbase)
           (bl.ser:make-bitcoin-block
            :header (make-test-block-header)
            :transactions (list coinbase))))
    ;; commitment + coinbase witness of exactly one 32-byte item -> complete
    (let ((nonce (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (is (null (bl.val:block-witness-stripped-p
                 (blk (%coinbase-with-commitment (list nonce)))))))
    ;; commitment + EMPTY coinbase witness (stripped) -> T
    (is-true (bl.val:block-witness-stripped-p
              (blk (%coinbase-with-commitment '()))))
    ;; commitment + wrong-size nonce (16 bytes) -> T
    (let ((short (make-array 16 :element-type '(unsigned-byte 8) :initial-element 0)))
      (is-true (bl.val:block-witness-stripped-p
                (blk (%coinbase-with-commitment (list short))))))
    ;; no commitment -> never stripped
    (is (null (bl.val:block-witness-stripped-p
               (blk (make-coinbase-transaction :value 5000000000 :height 1)))))))

;;;; Block Script Validation Tests

(test validate-block-scripts-called
  "validate-block should call script validation and reject invalid scripts."
  ;; Create a block with a spending tx that has an empty scriptSig
  ;; spending a P2PKH output. The script should fail because the
  ;; empty scriptSig can't satisfy P2PKH.
  (let* ((utxo-set (bl.store:make-utxo-set))
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
    (bl.store:add-utxo utxo-set prev-txid 0 1000000 p2pkh-script 5)
    ;; Build block with spending tx that has empty scriptSig
    (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 10))
           (spending-tx (bl.ser:make-transaction
                         :version 1
                         :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash prev-txid :index 0)
                                        :script-sig empty-script
                                        :sequence #xFFFFFFFF))
                         :outputs (vector (bl.ser:make-tx-out
                                         :value 900000
                                         :script-pubkey p2pkh-script))
                         :lock-time 0))
           (block (bl.ser:make-bitcoin-block
                   :header (make-test-block-header)
                   :transactions (list coinbase-tx spending-tx))))
      ;; validate-block-scripts should reject this block
      (multiple-value-bind (valid error)
          (bl.val:validate-block-scripts block utxo-set)
        (is (null valid))
        (is (eq :script-failed error))))))

(test validate-block-scripts-parallel-path
  "The opt-in parallel validation path (bl:*parallel-block-validation*
bound T) must produce the same accept/reject result as the default serial path
for a block large enough to cross +parallel-validation-min-txs+ (16 non-coinbase
txs). Guards the worker-thread fan-out/join and the shared failure-flag against
regressions: the path is OFF in production (it corrupts SBCL's alien-type cache
at mainnet scale), so only this test exercises it."
  (flet ((build-block (script-pubkey script-sig n)
           ;; N spending txs (each spending its own UTXO of SCRIPT-PUBKEY with
           ;; SCRIPT-SIG) plus a coinbase. Returns (values block utxo-set).
           (let ((utxo-set (bl.store:make-utxo-set))
                 (txs (list (make-coinbase-transaction :value 5000000000 :height 10))))
             (dotimes (i n)
               (let ((prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element (logand i #xFF))))
                 (bl.store:add-utxo utxo-set prev-txid 0 1000000 script-pubkey 5)
                 (push (bl.ser:make-transaction
                        :version 1
                        :inputs (vector (bl.ser:make-tx-in
                                         :previous-output (bl.ser:make-outpoint
                                                           :hash prev-txid :index 0)
                                         :script-sig script-sig
                                         :sequence #xFFFFFFFF))
                        :outputs (vector (bl.ser:make-tx-out
                                          :value 900000
                                          :script-pubkey script-pubkey))
                        :lock-time 0)
                       txs)))
             (values (bl.ser:make-bitcoin-block
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
        (let ((bl:*parallel-block-validation* t))
          (is (eq t (bl.val:validate-block-scripts blk utxo-set))))
        (let ((bl:*parallel-block-validation* nil))
          (is (eq t (bl.val:validate-block-scripts blk utxo-set)))))
      ;; 20 P2PKH outputs with empty scriptSig => REJECT on the parallel path
      ;; too (worker detects the failure and the join reports it).
      (multiple-value-bind (blk utxo-set) (build-block p2pkh empty 20)
        (let ((bl:*parallel-block-validation* t))
          (multiple-value-bind (valid error)
              (bl.val:validate-block-scripts blk utxo-set)
            (is (null valid))
            (is (eq :script-failed error))))))))

;;;; The script-execution cache on the BLOCK path
;;;
;;; Core's CheckInputScripts answers from the script-execution cache before it
;;; resolves a single coin -- `if (validation_cache.m_script_execution_cache.
;;; contains(hashCacheEntry, !cacheFullScriptStore)) return true;'
;;; (validation.cpp:2077-2081) -- over an entry that is
;;; SHA256(salt | wtxid | flags). ConnectBlock reaches it for every
;;; non-coinbase transaction with `fCacheResults = fJustCheck', whose comment
;;; states both halves of the contract: "Don't cache results if we're actually
;;; connecting blocks (still consult the cache, though)" (:2571).
;;;
;;; Ours read that cache only from the mempool path, so the entry the mempool
;;; wrote was read by nobody and every confirmed transaction was interpreted a
;;; second time.

(defvar *sec-spend-serial* 0
  "Serial number behind %SEC-SPEND-BLOCK's funding txid.")

(defun %sec-spend-block (script-pubkey script-sig height)
  "(values block utxo-set spend-tx flags): a block whose one non-coinbase
transaction spends a single SCRIPT-PUBKEY coin with SCRIPT-SIG, plus the flag
string the block's own hash and HEIGHT select.

Every call gets a FRESH funding txid, and so a fresh spend WTXID. The
script-execution cache is process-global, keyed by wtxid, and these tests
STORE into it -- including in their controls -- so a fixed txid would make the
test pass once per image and fail on the next run against its own leftovers."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (prev-txid (let ((h (make-array 32 :element-type '(unsigned-byte 8)
                                            :initial-element #xE1))
                          (n (incf *sec-spend-serial*)))
                      (dotimes (i 4 h)
                        (setf (aref h i) (ldb (byte 8 (* 8 i)) n)))))
         (spend (%w8d-spend-tx prev-txid script-sig nil))
         (blk (bl.ser:make-bitcoin-block
               :header (make-test-block-header)
               :transactions (list (make-coinbase-transaction
                                    :value 5000000000 :height height)
                                   spend))))
    (bl.store:add-utxo utxo-set prev-txid 0 1000000 script-pubkey 5)
    (values blk utxo-set spend
            (bl.val:block-script-flags
             (bl.ser:block-header-hash (bl.ser:bitcoin-block-header blk))
             height))))

(test block-scripts-consult-the-script-execution-cache
  "A transaction already verified under the block's exact flag set must not be
interpreted again -- Core returns true straight out of the cache. The block
path went to the interpreter unconditionally, so the cache the mempool's
consensus pass fills was never read and its own docstring claim (\"the
confirming block verifies again, so this turns the second pass into ONE
lookup\") did not hold.

Poisoning the cache is how Core's own txvalidationcache_tests prove the probe
runs: the block here is one an empty scriptSig can never satisfy, so an
acceptance can only have come from the entry. Two controls keep that from
being vacuous -- with no entry the block is rejected, and an entry stored
under a DIFFERENT flag string does not hit, since the flags are in the key."
  (let ((p2pkh (%w8d-script #x76 #xa9 #x14
                            (make-array 20 :element-type '(unsigned-byte 8)
                                           :initial-element 3)
                            #x88 #xac))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    ;; CONTROL: nothing cached, so the interpreter rejects it.
    (multiple-value-bind (blk utxo-set)
        (%sec-spend-block p2pkh empty 800000)
      (multiple-value-bind (valid error)
          (bl.val:validate-block-scripts blk utxo-set :height 800000)
        (is (null valid))
        (is (eq :script-failed error))))
    ;; CONTROL: an entry under other flags is a different key.
    (multiple-value-bind (blk utxo-set spend)
        (%sec-spend-block p2pkh empty 800000)
      (bl.interop:script-execution-cache-store
       (bl.interop:make-script-execution-cache-key
        (bl.ser:transaction-wtxid spend) "P2SH"))
      (is (null (bl.val:validate-block-scripts blk utxo-set :height 800000))))
    ;; THE assertion: the entry under the block's own flags is honoured.
    (multiple-value-bind (blk utxo-set spend flags)
        (%sec-spend-block p2pkh empty 800000)
      (bl.interop:script-execution-cache-store
       (bl.interop:make-script-execution-cache-key
        (bl.ser:transaction-wtxid spend) flags))
      (is (eq t (bl.val:validate-block-scripts blk utxo-set :height 800000))))))

(test block-scripts-do-not-populate-the-script-execution-cache
  "Connecting a block CONSULTS the cache and writes nothing into it: Core
passes `fCacheResults = fJustCheck' from ConnectBlock, so the insert at
validation.cpp:2124-2128 belongs to the mempool's consensus pass alone. A
block whose scripts genuinely pass must therefore leave no entry behind.
Control: the very same key is present the moment something stores it, so the
absence measured above is a real absence and not a mistyped key."
  (let ((op-true (make-array 1 :element-type '(unsigned-byte 8)
                               :initial-element #x51))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (multiple-value-bind (blk utxo-set spend flags)
        (%sec-spend-block op-true empty 800000)
      (let ((key (bl.interop:make-script-execution-cache-key
                  (bl.ser:transaction-wtxid spend) flags)))
        (is (eq t (bl.val:validate-block-scripts blk utxo-set :height 800000)))
        (is (null (bl.interop:script-execution-cached-p key)))
        ;; CONTROL: the key is the one the block path would have used.
        (bl.interop:script-execution-cache-store key)
        (is-true (bl.interop:script-execution-cached-p key))))))

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
  (let* ((coinbase (bl.ser:make-transaction
                    :version 1
                    :inputs (vector (bl.ser:make-tx-in
                                   :previous-output (bl.ser:make-outpoint
                                                     :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                       :initial-element 0)
                                                     :index #xFFFFFFFF)
                                   :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                             :initial-element 1)))
                    :outputs (vector (bl.ser:make-tx-out
                                    :value 5000000000
                                    :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                               :initial-element #x76)))
                    :lock-time 0))
         ;; Witness transaction
         (witness-tx (bl.ser:make-transaction
                      :version 2
                      :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x11)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bl.ser:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xAA)
                                          (make-array 33 :element-type '(unsigned-byte 8)
                                                         :initial-element #xBB)))))
         (block (bl.ser:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    ;; Block with witness tx should be detected
    (is (bl.val::block-has-witness-data-p block))))

(test block-without-witness-data
  "block-has-witness-data-p should return NIL for legacy blocks."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (block (bl.ser:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase))))
    (is (not (bl.val::block-has-witness-data-p block)))))

(test witness-merkle-root-computation
  "Witness merkle root should use wtxids (coinbase wtxid = zeros)."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (regular-tx (make-test-transaction :inputs 1 :outputs 1 :value 1000000))
         (transactions (list coinbase regular-tx)))
    ;; Compute witness merkle root
    (let ((witness-root (bl.val:compute-witness-merkle-root transactions)))
      ;; The root should be hash of coinbase-wtxid(zeros) || regular-tx-wtxid
      (let* ((cb-wtxid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
             (tx-wtxid (bl.ser:transaction-wtxid regular-tx))
             (combined (make-array 64 :element-type '(unsigned-byte 8))))
        (replace combined cb-wtxid :start1 0)
        (replace combined tx-wtxid :start1 32)
        (let ((expected (bl.crypto:hash256 combined)))
          (is (equalp witness-root expected)))))))

(test witness-commitment-validation-matching
  "validate-witness-commitment should pass when commitment matches."
  (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 1))
         ;; A witness tx (with dummy witness data)
         (witness-tx (bl.ser:make-transaction
                      :version 2
                      :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x22)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bl.ser:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xCC)))))
         (transactions (list coinbase-tx witness-tx)))
    ;; Compute what the correct commitment should be
    (let* ((witness-root (bl.val:compute-witness-merkle-root transactions))
           ;; Default witness reserved value: 32 zero bytes
           (witness-reserved (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
           (combined (make-array 64 :element-type '(unsigned-byte 8))))
      (replace combined witness-root :start1 0)
      (replace combined witness-reserved :start1 32)
      (let ((commitment (bl.crypto:hash256 combined)))
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
                   (bl.ser:make-transaction
                    :version 1
                    :inputs (bl.ser:transaction-inputs coinbase-tx)
                    :outputs (concatenate 'simple-vector
                                          (bl.ser:transaction-outputs coinbase-tx)
                                          (list (bl.ser:make-tx-out
                                                 :value 0 :script-pubkey script)))
                    :lock-time 0
                    :witness (vector (list witness-reserved))))  ; coinbase witness
                 (block (bl.ser:make-bitcoin-block
                         :header (make-test-block-header)
                         :transactions (list updated-coinbase witness-tx))))
            (multiple-value-bind (valid error)
                (bl.val:validate-witness-commitment block t)
              (is (eq t valid))
              (is (null error)))))))))

(test witness-commitment-validation-missing
  "Segwit active + witness data present but coinbase has NO commitment
output: rejected as :unexpected-witness (Core's CheckWitnessMalleation
has no separate missing-commitment error — it falls through to the
no-witness-allowed scan)."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (witness-tx (bl.ser:make-transaction
                      :version 2
                      :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x33)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bl.ser:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xDD)))))
         (block (bl.ser:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    (multiple-value-bind (valid error)
        (bl.val:validate-witness-commitment block t)
      (is (null valid))
      (is (eq :unexpected-witness error)))))

(test witness-unexpected-when-segwit-inactive
  "Pre-segwit block carrying witness data is rejected (:unexpected-witness)."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (witness-tx (bl.ser:make-transaction
                      :version 2
                      :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x44)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bl.ser:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xEE)))))
         (block (bl.ser:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase witness-tx))))
    (multiple-value-bind (valid error)
        (bl.val:validate-witness-commitment block nil)
      (is (null valid))
      (is (eq :unexpected-witness error)))))

(test witness-legacy-block-passes-both-gates
  "A purely-legacy block (no witness data, no commitment) passes whether
or not segwit is active."
  (let* ((coinbase (make-coinbase-transaction :value 5000000000 :height 1))
         (legacy-tx (bl.ser:make-transaction
                     :version 1
                     :inputs (vector (bl.ser:make-tx-in
                                    :previous-output (bl.ser:make-outpoint
                                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                        :initial-element #x55)
                                                      :index 0)
                                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                     :outputs (vector (bl.ser:make-tx-out
                                     :value 49000
                                     :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                :initial-element #x76)))
                     :lock-time 0))
         (block (bl.ser:make-bitcoin-block
                 :header (make-test-block-header)
                 :transactions (list coinbase legacy-tx))))
    (is (eq t (bl.val:validate-witness-commitment block nil)))
    (is (eq t (bl.val:validate-witness-commitment block t)))))

(test witness-commitment-bad-nonce-size
  "Segwit active + commitment present but coinbase witness reserved value
is not exactly one 32-byte item: :bad-witness-nonce-size."
  (let* ((coinbase-tx (make-coinbase-transaction :value 5000000000 :height 1))
         (witness-tx (bl.ser:make-transaction
                      :version 2
                      :inputs (vector (bl.ser:make-tx-in
                                     :previous-output (bl.ser:make-outpoint
                                                       :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                         :initial-element #x66)
                                                       :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))))
                      :outputs (vector (bl.ser:make-tx-out
                                      :value 49000
                                      :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                                 :initial-element #x76)))
                      :lock-time 0
                      :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8)
                                                         :initial-element #xCC)))))
         (transactions (list coinbase-tx witness-tx))
         ;; Build a commitment that would match a 32-zero reserved value,
         ;; but give the coinbase a WRONG-sized (16-byte) witness item.
         (witness-root (bl.val:compute-witness-merkle-root transactions))
         (reserved (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0))
         (combined (make-array 64 :element-type '(unsigned-byte 8))))
    (replace combined witness-root :start1 0)
    (replace combined reserved :start1 32)
    (let ((commitment (bl.crypto:hash256 combined))
          (script (make-array 38 :element-type '(unsigned-byte 8) :initial-element 0)))
      (setf (aref script 0) #x6a (aref script 1) #x24
            (aref script 2) #xaa (aref script 3) #x21
            (aref script 4) #xa9 (aref script 5) #xed)
      (replace script commitment :start1 6)
      (let* ((bad-coinbase
               (bl.ser:make-transaction
                :version 1
                :inputs (bl.ser:transaction-inputs coinbase-tx)
                :outputs (concatenate 'simple-vector
                                      (bl.ser:transaction-outputs coinbase-tx)
                                      (list (bl.ser:make-tx-out
                                             :value 0 :script-pubkey script)))
                :lock-time 0
                ;; 16-byte reserved value instead of 32 — wrong size.
                :witness (vector (list (make-array 16 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)))))
             (block (bl.ser:make-bitcoin-block
                     :header (make-test-block-header)
                     :transactions (list bad-coinbase witness-tx))))
        (multiple-value-bind (valid error)
            (bl.val:validate-witness-commitment block t)
          (is (null valid))
          (is (eq :bad-witness-nonce-size error)))))))

;;; ============================================================
;;; Transaction Finality (IsFinalTx) Tests
;;; ============================================================

(defun make-tx-with-locktime (locktime &key (version 1) (sequence #xFFFFFFFF))
  "Create a test transaction with specified nLockTime and input sequence."
  (bl.ser:make-transaction
   :version version
   :inputs (vector (bl.ser:make-tx-in
                  :previous-output (bl.ser:make-outpoint
                                    :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element 1)
                                    :index 0)
                  :script-sig (make-array 10 :element-type '(unsigned-byte 8)
                                          :initial-element #x00)
                  :sequence sequence))
   :outputs (vector (bl.ser:make-tx-out
                   :value 50000000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                              :initial-element #x76)))
   :lock-time locktime))

(test is-final-locktime-zero
  "Transaction with nLockTime=0 is always final."
  (let ((tx (make-tx-with-locktime 0 :sequence 0)))
    (is-true (bl.val:check-transaction-final tx 100 1600000000))))

(test is-final-all-sequences-final
  "Transaction with all SEQUENCE_FINAL inputs is final regardless of locktime."
  (let ((tx (make-tx-with-locktime 500000 :sequence #xFFFFFFFF)))
    (is-true (bl.val:check-transaction-final tx 100 1600000000))))

(test is-final-height-based-satisfied
  "Height-based locktime satisfied when block height > nLockTime."
  (let ((tx (make-tx-with-locktime 400000 :sequence 0)))
    (is-true (bl.val:check-transaction-final tx 400001 1600000000))))

(test is-final-height-based-not-satisfied
  "Height-based locktime NOT satisfied when block height <= nLockTime."
  (let ((tx (make-tx-with-locktime 400000 :sequence 0)))
    (is-false (bl.val:check-transaction-final tx 399999 1600000000))))

(test is-final-time-based-satisfied
  "Time-based locktime satisfied when block time > nLockTime."
  (let ((tx (make-tx-with-locktime 1600000000 :sequence 0)))
    (is-true (bl.val:check-transaction-final tx 500000 1600000001))))

(test is-final-time-based-not-satisfied
  "Time-based locktime NOT satisfied when block time <= nLockTime."
  (let ((tx (make-tx-with-locktime 1600000000 :sequence 0)))
    (is-false (bl.val:check-transaction-final tx 500000 1599999999))))

(test is-final-height-locktime-boundary
  "nLockTime at 499999999 is height-based (< 500000000 threshold)."
  (let ((tx (make-tx-with-locktime 499999999 :sequence 0)))
    ;; Block height exceeds locktime
    (is-true (bl.val:check-transaction-final tx 500000000 0))))

(test is-final-time-locktime-boundary
  "nLockTime at 500000000 is time-based (>= threshold)."
  (let ((tx (make-tx-with-locktime 500000000 :sequence 0)))
    ;; Block time exceeds locktime
    (is-true (bl.val:check-transaction-final tx 0 500000001))))


;;; ============================================================
;;; BIP 30 enforcement window (bip30-enforced-p)
;;; ============================================================
;;; Mirrors Bitcoin Core ConnectBlock (validation.cpp:2399-2464): enforced
;;; below BIP 34 activation (except the grandfathered mainnet repeat
;;; blocks), and again unconditionally at height >= 1,983,702.

(test bip30-enforced-below-bip34-activation
  "Below BIP 34 activation, BIP 30 is enforced."
  (let ((bl:*network* :mainnet))
    ;; mainnet BIP34 activation = 227931
    (is (bl.val::bip30-enforced-p 100000))
    (is (bl.val::bip30-enforced-p 227930)))
  (let ((bl:*network* :testnet3))
    (is (bl.val::bip30-enforced-p 20000))))

(test bip30-skipped-between-bip34-and-limit
  "Between BIP 34 activation and the 1,983,702 re-enable limit, BIP 30 is
skipped (BIP 34 height-in-coinbase guarantees coinbase uniqueness)."
  (let ((bl:*network* :mainnet))
    (is (not (bl.val::bip30-enforced-p 227931)))
    (is (not (bl.val::bip30-enforced-p 500000)))
    (is (not (bl.val::bip30-enforced-p 1983701)))))

(test bip30-reenabled-at-limit
  "At or above height 1,983,702, BIP 30 is re-enforced unconditionally."
  (dolist (net '(:mainnet :testnet3 :testnet4))
    (let ((bl:*network* net))
      (is (bl.val::bip30-enforced-p 1983702))
      (is (bl.val::bip30-enforced-p 3000000)))))

(test bip30-grandfathered-repeat-blocks-exempt
  "The two mainnet repeat blocks (91842, 91880) are NOT BIP 30-enforced,
so their historical duplicate coinbases aren't wrongly rejected."
  (let ((bl:*network* :mainnet))
    (is (not (bl.val::bip30-enforced-p 91842)))
    (is (not (bl.val::bip30-enforced-p 91880)))
    ;; A neighbouring height is still enforced.
    (is (bl.val::bip30-enforced-p 91841)))
  ;; The exemption is mainnet-specific — no other network treats those
  ;; heights as repeat blocks.
  (let ((bl:*network* :testnet3))
    (is (not (bl.val:bip30-repeat-block-p 91842)))))

(test bip30-testnet4-not-enforced-at-current-heights
  "testnet4 has BIP 34 active from height 1, so BIP 30 is skipped for all
normal heights until the 1,983,702 re-enable."
  (let ((bl:*network* :testnet4))
    (is (not (bl.val::bip30-enforced-p 136459)))
    (is (not (bl.val::bip30-enforced-p 500000)))))

;;; ============================================================
;;; BIP 34 exact-prefix coinbase height (encode-bip34-height /
;;; validate-coinbase-height) — Core compares serialized bytes, not value.
;;; ============================================================

(defun %block-with-coinbase-scriptsig (script-sig)
  "A block whose coinbase input-0 has the given SCRIPT-SIG."
  (let ((coinbase
          (bl.ser:make-transaction
           :version 1
           :inputs (vector (bl.ser:make-tx-in
                          :previous-output (bl.ser:make-outpoint
                                            :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                            :index #xFFFFFFFF)
                          :script-sig script-sig
                          :sequence #xFFFFFFFF))
           :outputs (vector (bl.ser:make-tx-out
                           :value 5000000000
                           :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                      :initial-element #x76)))
           :lock-time 0)))
    (bl.ser:make-bitcoin-block
     :header (make-test-block-header)
     :transactions (list coinbase))))

(test encode-bip34-height-forms
  "encode-bip34-height matches Core's CScript() << height: OP_0/OP_N for
0..16, minimal CScriptNum data push otherwise (incl. sign byte)."
  (is (equalp (%bytes #x00) (bl.val:encode-bip34-height 0)))
  (is (equalp (%bytes #x51) (bl.val:encode-bip34-height 1)))
  (is (equalp (%bytes #x60) (bl.val:encode-bip34-height 16)))
  (is (equalp (%bytes #x01 #x11) (bl.val:encode-bip34-height 17)))
  ;; 21111 = 0x5277 -> LE 0x77 0x52
  (is (equalp (%bytes #x02 #x77 #x52) (bl.val:encode-bip34-height 21111)))
  ;; 227931 = 0x037A5B -> LE 0x5b 0x7a 0x03
  (is (equalp (%bytes #x03 #x5b #x7a #x03) (bl.val:encode-bip34-height 227931)))
  ;; 128 = 0x80 -> needs 0x00 sign byte
  (is (equalp (%bytes #x02 #x80 #x00) (bl.val:encode-bip34-height 128))))

(test validate-coinbase-height-accepts-exact-prefix
  "A coinbase whose scriptSig starts with the exact serialized height
passes (extra trailing bytes are fine)."
  (let ((bl:*network* :testnet4))   ; BIP34 active from height 1
    (let ((block (%block-with-coinbase-scriptsig
                  ;; height 21111 prefix + arbitrary extra-nonce bytes
                  (concatenate '(vector (unsigned-byte 8))
                               (%bytes #x02 #x77 #x52) (%bytes #xab #xcd)))))
      (multiple-value-bind (valid error)
          (bl.val::validate-coinbase-height block 21111)
        (is (eq t valid))
        (is (null error))))))

(test validate-coinbase-height-rejects-nonminimal
  "A non-minimal encoding that decodes to the right number is rejected
(Core compares the exact minimal prefix)."
  (let ((bl:*network* :testnet4))
    ;; height 17 padded to 2 bytes: 0x02 0x11 0x00 decodes to 17 but the
    ;; minimal form is 0x01 0x11.
    (let ((block (%block-with-coinbase-scriptsig (%bytes #x02 #x11 #x00))))
      (multiple-value-bind (valid error)
          (bl.val::validate-coinbase-height block 17)
        (is (null valid))
        (is (eq :bad-coinbase-height error))))))

(test validate-coinbase-height-rejects-wrong-and-short
  "Wrong height and a too-short scriptSig are both rejected."
  (let ((bl:*network* :testnet4))
    ;; scriptSig encodes height 100, block claims 101
    (let ((block (%block-with-coinbase-scriptsig (%bytes #x01 #x64))))
      (is (null (bl.val::validate-coinbase-height block 101))))
    ;; empty scriptSig at an enforced height
    (let ((block (%block-with-coinbase-scriptsig
                  (make-array 0 :element-type '(unsigned-byte 8)))))
      (is (null (bl.val::validate-coinbase-height block 17))))))

(test validate-coinbase-height-skipped-below-activation
  "Below the network BIP 34 activation height, the check is skipped."
  (let ((bl:*network* :testnet3))   ; activation 21111
    (let ((block (%block-with-coinbase-scriptsig (%bytes #xde #xad #xbe #xef))))
      (is (eq t (bl.val::validate-coinbase-height block 100))))))

;;; ============================================================
;;; Coinbase classification (Core CheckTransaction / IsCoinBase):
;;; coinbase IFF exactly one input with a null prevout; non-coinbase txs
;;; may not contain any null prevout (:bad-prevout-null).
;;; ============================================================

(defun %null-input (&optional (sig-len 5))
  (bl.ser:make-tx-in
   :previous-output (bl.ser:make-outpoint
                     :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                     :index #xFFFFFFFF)
   :script-sig (make-array sig-len :element-type '(unsigned-byte 8) :initial-element 0)
   :sequence #xFFFFFFFF))

(defun %normal-input (seed)
  (bl.ser:make-tx-in
   :previous-output (bl.ser:make-outpoint
                     :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element seed)
                     :index 0)
   :script-sig (make-array 0 :element-type '(unsigned-byte 8))
   :sequence #xFFFFFFFF))

(defun %tx-with-inputs (inputs)
  (bl.ser:make-transaction
   :version 1 :inputs (coerce inputs 'simple-vector)
   :outputs (vector (bl.ser:make-tx-out
                   :value 1000
                   :script-pubkey (make-array 25 :element-type '(unsigned-byte 8) :initial-element #x76)))
   :lock-time 0))

(test coinbase-single-null-input-valid
  "Exactly one null input with a 2..100-byte scriptSig is a valid coinbase."
  (multiple-value-bind (valid error)
      (bl.val:validate-transaction-structure
       (%tx-with-inputs (list (%null-input 5))))
    (is (eq t valid))
    (is (null error))))

(test coinbase-bad-scriptsig-length
  "Coinbase scriptSig outside 2..100 bytes is rejected."
  (is (eq :bad-coinbase-length
          (nth-value 1 (bl.val:validate-transaction-structure
                        (%tx-with-inputs (list (%null-input 1)))))))
  (is (eq :bad-coinbase-length
          (nth-value 1 (bl.val:validate-transaction-structure
                        (%tx-with-inputs (list (%null-input 101))))))))

(test noncoinbase-with-leading-null-prevout-rejected
  "Two inputs with the FIRST null is not a coinbase (size != 1) and is
rejected as :bad-prevout-null, matching Core (not our old :bad-coinbase-mixed)."
  (multiple-value-bind (valid error)
      (bl.val:validate-transaction-structure
       (%tx-with-inputs (list (%null-input 5) (%normal-input 9))))
    (is (null valid))
    (is (eq :bad-prevout-null error))))

(test noncoinbase-with-trailing-null-prevout-rejected
  "A later null prevout in a multi-input tx is rejected."
  (multiple-value-bind (valid error)
      (bl.val:validate-transaction-structure
       (%tx-with-inputs (list (%normal-input 9) (%null-input 5))))
    (is (null valid))
    (is (eq :bad-prevout-null error))))

(test noncoinbase-all-nonnull-passes
  "A normal multi-input tx with no null prevouts passes structure validation."
  (multiple-value-bind (valid error)
      (bl.val:validate-transaction-structure
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
         (tx (bl.ser:br-read-transaction
              (bl.ser:make-byte-reader-from
               (bl.crypto:hex-to-bytes tx-hex))))
         (prev-txid (bl.ser:outpoint-hash
                     (bl.ser:tx-in-previous-output
                      (aref (bl.ser:transaction-inputs tx) 0))))
         (spk (bl.crypto:hex-to-bytes
               "0020bc3c8483b31b1431e42d886782a4b3e0c73a094f44260c42da1d41c003c95da7"))
         (utxo-set (bl.store:make-utxo-set)))
    (bl.store:add-utxo utxo-set prev-txid 0 63383 spk 851000)
    (let ((bl:*network* :mainnet))
      (multiple-value-bind (ok failed-idx)
          (bl.val:validate-transaction-scripts
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
  (let ((bl.interop:*signature-cache*
          (bl.interop::%make-sig-cache-table))
        (bl.interop:*signature-cache-prev*
          (bl.interop::%make-sig-cache-table))
        (bl.interop:*signature-cache-max-entries* 4))
    (loop for n from 1 to 4
          do (bl.interop::sig-cache-store (%sig-key n)))
    ;; 5th store rotates: prev = {1..4}, cur = {5}
    (bl.interop::sig-cache-store (%sig-key 5))
    (is (= 1 (hash-table-count bl.interop:*signature-cache*)))
    (is (= 4 (hash-table-count bl.interop:*signature-cache-prev*)))
    ;; Hit on key 1 promotes it into cur.
    (is (bl.interop::sig-cache-hit-p (%sig-key 1)))
    ;; Fill cur to the cap and rotate again: prev = {5,1,6,7}, cur = {9}.
    (loop for n from 6 to 7
          do (bl.interop::sig-cache-store (%sig-key n)))
    (bl.interop::sig-cache-store (%sig-key 9))
    ;; Promoted key 1 survived both rotations; never-touched key 2 aged out.
    (is (bl.interop::sig-cache-hit-p (%sig-key 1)))
    (is (not (bl.interop::sig-cache-hit-p (%sig-key 2))))))

(test sig-cache-clear-clears-both-generations
  (let ((bl.interop:*signature-cache*
          (bl.interop::%make-sig-cache-table))
        (bl.interop:*signature-cache-prev*
          (bl.interop::%make-sig-cache-table)))
    (bl.interop::sig-cache-store (%sig-key 1))
    (setf (gethash (%sig-key 2) bl.interop:*signature-cache-prev*) t)
    (bl.interop:clear-signature-cache)
    (is (not (bl.interop::sig-cache-hit-p (%sig-key 1))))
    (is (not (bl.interop::sig-cache-hit-p (%sig-key 2))))))

(test taproot-script-flag-exception-block
  "The mainnet Taproot exception block (Core script_flag_exceptions) validates
with P2SH|WITNESS only: a P2TR spend with a garbage witness fails under normal
post-activation flags (TAPROOT active) but passes when the block's hash matches
*taproot-exception-mainnet* (v1 witness reverts to an upgradable program)."
  (let* ((bl:*network* :mainnet)
         (utxo-set (bl.store:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element #xBB))
         ;; P2TR scriptPubKey: OP_1 push32 <32-byte x-only key>
         (p2tr (concatenate '(vector (unsigned-byte 8))
                            (vector #x51 #x20)
                            (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2)))
         (spending-tx (bl.ser:make-transaction
                       :version 1
                       :inputs (vector (bl.ser:make-tx-in
                                        :previous-output (bl.ser:make-outpoint
                                                          :hash prev-txid :index 0)
                                        :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                        :sequence #xFFFFFFFF))
                       :outputs (vector (bl.ser:make-tx-out
                                         :value 900000 :script-pubkey p2tr))
                       ;; garbage 64-byte "signature" -- fails BIP341 verification
                       :witness (vector (list (make-array 64 :element-type '(unsigned-byte 8)
                                                             :initial-element 7)))
                       :lock-time 0))
         (blk (bl.ser:make-bitcoin-block
               :header (make-test-block-header)
               :transactions (list (make-coinbase-transaction :value 5000000000 :height 800000)
                                   spending-tx)))
         (height 800000))               ; well past mainnet taproot activation
    (bl.store:add-utxo utxo-set prev-txid 0 1000000 p2tr 5)
    ;; Normal flags (TAPROOT active): garbage witness rejected.
    (is (null (bl.val:validate-block-scripts blk utxo-set :height height)))
    ;; Exception block: validated with P2SH|WITNESS only -> passes.
    (let ((bl.val::*taproot-exception-mainnet*
            (bl.ser:block-header-hash
             (bl.ser:bitcoin-block-header blk))))
      (is (eq t (bl.val:validate-block-scripts blk utxo-set :height height))))))

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
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash prev-txid :index 0)
                    :script-sig script-sig
                    :sequence #xFFFFFFFF))
   :outputs (vector (bl.ser:make-tx-out
                     :value 900000
                     :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                   :initial-element #x76)))
   :witness (when witness (vector witness))
   :lock-time 0))

(defun %w8d-block-valid-p (script-pubkey script-sig witness height)
  "Build a block containing one spend of a SCRIPT-PUBKEY utxo and run it
through validate-block-scripts at HEIGHT on mainnet. Returns the primary
value (T on acceptance, NIL on rejection)."
  (let* ((bl:*network* :mainnet)
         (utxo-set (bl.store:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #xC4))
         (spend (%w8d-spend-tx prev-txid script-sig witness))
         (blk (bl.ser:make-bitcoin-block
               :header (make-test-block-header)
               :transactions (list (make-coinbase-transaction
                                    :value 5000000000 :height height)
                                   spend))))
    (bl.store:add-utxo utxo-set prev-txid 0 1000000 script-pubkey 5)
    (bl.val:validate-block-scripts blk utxo-set :height height)))

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

(test block-witnessless-v0-spend-rejected-below-segwit-activation-too
  "The WITNESS flag is not height-gated, so this fails at 400,000 exactly as it
fails at 800,000.

This test asserted the opposite until the flags were aligned with Core, on the
reasoning that rejecting here would break mainnet IBD because
witness-program-shaped outputs were spendable before 481,824. That reasoning
describes the network rules of 2016, not how Core validates history today.
Core's GetBlockScriptFlags leaves P2SH+WITNESS+TAPROOT on for EVERY block and
says why in as many words (validation.cpp:2250-2257): `only one historical
block violated the P2SH rules ... For simplicity, always leave
P2SH+WITNESS+TAPROOT on except for the two violating blocks.' Mainnet history
is therefore already known to contain no such spend — if it did, Core would
need a third exception entry and every Core node would fail IBD.

Leaving WITNESS off below activation was the permissive half of a consensus
split: this spend is WITNESS_PROGRAM_WITNESS_EMPTY (P2WSH) or
WITNESS_PROGRAM_MISMATCH (P2WPKH) to Core and anyone-can-spend to us."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        (p2wpkh (%w8d-script #x00 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                      :initial-element 7)))
        (p2wsh (%w8d-script #x00 #x20 (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 9))))
    (is (null (%w8d-block-valid-p p2wpkh empty nil 400000)))
    (is (null (%w8d-block-valid-p p2wsh empty nil 400000)))
    ;; And at a height where not one deployment has activated.
    (is (null (%w8d-block-valid-p p2wsh empty nil 1)))))

(test block-native-witness-nonempty-scriptsig-malleated
  "A native witness program spend with a NON-empty scriptSig fails under the
WITNESS flag even when the witness itself is valid: the scriptSig must be
exactly empty (SCRIPT_ERR_WITNESS_MALLEATED, interpreter.cpp:2038-2041)."
  (let* ((op-true-script (%w8d-script #x51))
         (p2wsh (%w8d-script #x00 #x20 (bl.crypto:sha256 op-true-script)))
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
v1 with a non-32/non-P2A length."
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
    ;; v1/32 with no witness fails at EVERY height, because TAPROOT is not
    ;; height-gated: WITNESS_EMPTY (interpreter.cpp:1949).
    (is (null (%w8d-block-valid-p p2tr empty nil 800000)))
    (is (null (%w8d-block-valid-p p2tr empty nil 500000)))))

(test taproot-shaped-output-is-upgradeable-under-the-exception-blocks-flags
  "v1/32 with no witness is an upgradeable pass when TAPROOT is off
(interpreter.cpp:1948 returns success before the empty-stack check).

Core reaches that flag combination in exactly one way — the mainnet taproot
exception block, whose table entry is P2SH|WITNESS (chainparams.cpp:87-88) —
and never by height, so this drives the flags directly rather than pretending
some height produces them. It is the reason the exception exists: that block
contains a witness-v1 spend that fails full BIP341 verification."
  (let* ((bl:*network* :mainnet)
         (utxo-set (bl.store:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #xC6))
         (p2tr (%w8d-script #x51 #x20 (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 2)))
         (tx (%w8d-spend-tx prev-txid (make-array 0 :element-type '(unsigned-byte 8)) nil)))
    (bl.store:add-utxo utxo-set prev-txid 0 1000000 p2tr 5)
    ;; The exception block's own flag set: upgradeable, passes.
    (is (eq t (bl.val:validate-transaction-scripts
               tx utxo-set :height 692261
               :flags (bl.val:block-script-flags
                       bl.val::*taproot-exception-mainnet* 692261))))
    ;; Any other block at that height has TAPROOT on: rejected.
    (is (null (bl.val:validate-transaction-scripts
               tx utxo-set :height 692261
               :flags (bl.val:block-script-flags nil 692261))))))

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
         (p2wsh-redeem (%w8d-script #x00 #x20 (bl.crypto:sha256 op-true-script)))
         (p2sh-of-p2wsh (%w8d-script #xa9 #x14 (bl.crypto:hash160 p2wsh-redeem) #x87))
         (p2wsh-sig (%w8d-script (length p2wsh-redeem) p2wsh-redeem))
         ;; P2SH-P2WPKH (no valid key needed: it must fail before any sig check)
         (p2wpkh-redeem (%w8d-script #x00 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                              :initial-element 7)))
         (p2sh-of-p2wpkh (%w8d-script #xa9 #x14 (bl.crypto:hash160 p2wpkh-redeem) #x87))
         (p2wpkh-sig (%w8d-script (length p2wpkh-redeem) p2wpkh-redeem))
         ;; P2SH-wrapped v1/32 (taproot-shaped)
         (v1-redeem (%w8d-script #x51 #x20 (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 2)))
         (p2sh-of-v1 (%w8d-script #xa9 #x14 (bl.crypto:hash160 v1-redeem) #x87))
         (v1-sig (%w8d-script (length v1-redeem) v1-redeem)))
    (declare (ignorable empty))
    ;; Wrapped P2WSH with the witness present: valid spend, passes.
    (is (eq t (%w8d-block-valid-p p2sh-of-p2wsh p2wsh-sig (list op-true-script) 800000)))
    ;; Wrapped P2WSH with NO witness: fails (WITNESS_PROGRAM_WITNESS_EMPTY).
    (is (null (%w8d-block-valid-p p2sh-of-p2wsh p2wsh-sig nil 800000)))
    ;; Wrapped P2WPKH with NO witness: fails (WITNESS_PROGRAM_MISMATCH).
    (is (null (%w8d-block-valid-p p2sh-of-p2wpkh p2wpkh-sig nil 800000)))
    ;; Below segwit activation the answer is the SAME: WITNESS is not
    ;; height-gated, so a wrapped v0 with no witness fails there too.
    (is (null (%w8d-block-valid-p p2sh-of-p2wsh p2wsh-sig nil 400000)))
    (is (null (%w8d-block-valid-p p2sh-of-p2wpkh p2wpkh-sig nil 400000)))
    ;; Wrapped v1/32, TAPROOT active, no witness: UNKNOWN version under
    ;; is_p2sh -> upgradeable, consensus-PASSES (the is-p2sh regression guard).
    (is (eq t (%w8d-block-valid-p p2sh-of-v1 v1-sig nil 800000)))))

(test block-witness-on-legacy-input-unexpected
  "Witness data attached to an input whose scriptPubKey is NOT a witness
program (native or wrapped) fails under the WITNESS flag
(SCRIPT_ERR_WITNESS_UNEXPECTED, interpreter.cpp:2110-2121). WITNESS is on for
every block, so the height makes no difference."
  (let ((empty (make-array 0 :element-type '(unsigned-byte 8)))
        (op-true (%w8d-script #x51))
        (witness (list (%w8d-script #x01))))
    (is (null (%w8d-block-valid-p op-true empty witness 800000)))
    (is (null (%w8d-block-valid-p op-true empty witness 400000)))
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
:witness-stripped BEFORE reaching the script engine so the P2P
reject classification is preserved; this test pins the engine-level
agreement underneath that gate."
  (let* ((bl:*network* :mainnet)
         (utxo-set (bl.store:make-utxo-set))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #xC5))
         (p2wpkh (%w8d-script #x00 #x14 (make-array 20 :element-type '(unsigned-byte 8)
                                                       :initial-element 7)))
         (tx (%w8d-spend-tx prev-txid (make-array 0 :element-type '(unsigned-byte 8)) nil)))
    (bl.store:add-utxo utxo-set prev-txid 0 1000000 p2wpkh 5)
    (is (null (bl.val:validate-transaction-scripts
               tx utxo-set :height 800000)))
    ;; Same answer below segwit activation: WITNESS is not height-gated, and
    ;; on the mempool path Core does not even consult the height — it uses the
    ;; constant STANDARD_SCRIPT_VERIFY_FLAGS (policy/policy.h:118), which
    ;; contains WITNESS and TAPROOT unconditionally.
    (is (null (bl.val:validate-transaction-scripts
               tx utxo-set :height 400000)))))

(test bip16-exception-flags-run-the-scripts-they-do-not-skip-them
  "SCRIPT_VERIFY_NONE is a flag set, not a bypass. Under the two BIP16
exception blocks' entry (chainparams.cpp:85-86, :218-219) Core still executes
every script and still requires a true top-of-stack; it merely stops applying
P2SH — so the scriptSig's push of the redeem script and the scriptPubKey's
HASH160/EQUAL run as ordinary legacy opcodes.

`validate-block-scripts' used to return success for these blocks without
executing anything, which accepts blocks Core rejects."
  (let* ((bl:*network* :mainnet)
         (none (bl.val:block-script-flags
                bl.val::*bip16-exception-mainnet* 170060))
         (op-true (%w8d-script #x51))
         (op-false (%w8d-script #x00))
         (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (is (string= "" none))
    ;; The script-execution cache is keyed on (wtxid, flags), and the spent
    ;; scriptPubKey is deliberately NOT in that key — in production an outpoint
    ;; has exactly one scriptPubKey. Here the two cases differ ONLY in the
    ;; scriptPubKey, so they build a byte-identical transaction and the second
    ;; would silently inherit the first's verdict. Turn the cache off rather
    ;; than rely on picking a prevout no other test happens to use.
    (flet ((spends-p (spk sig)
             (let* ((bl.interop:*script-execution-cache-enabled* nil)
                    (utxo-set (bl.store:make-utxo-set))
                    (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                              :initial-element #xC7))
                    (tx (%w8d-spend-tx prev-txid sig nil)))
               (bl.store:add-utxo utxo-set prev-txid 0 1000000 spk 5)
               (bl.val:validate-transaction-scripts
                tx utxo-set :height 170060 :flags none))))
      ;; A satisfiable script still has to be satisfied.
      (is (eq t (spends-p op-true empty)))
      ;; And a false top-of-stack is still EVAL_FALSE, flags or no flags.
      (is (null (spends-p op-false empty))))))

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
           (bl.ser:make-transaction
            :version 1
            :inputs (vector (bl.ser:make-tx-in
                             :previous-output
                             (bl.ser:make-outpoint
                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)
                              :index #xffffffff)
                             :script-sig (coerce #(3 1 2 3) '(vector (unsigned-byte 8)))
                             ;; NOT SEQUENCE_FINAL: this is what makes nLockTime bite.
                             :sequence 0))
            :outputs (vector (bl.ser:make-tx-out
                              :value 5000000000
                              :script-pubkey (coerce #(81) '(vector (unsigned-byte 8)))))
            ;; Locked to a height far beyond the block we would put it in.
            :lock-time 900000)))
    (is-false (bl.val:check-transaction-final coinbase 800000 800000)
              "a coinbase locked to a future height with a non-final sequence is
               NOT final, and must be judged rather than skipped")
    ;; The ordinary coinbase shape Core's miner produces stays final, so the
    ;; fix cannot reject honest blocks.
    (setf (bl.ser:tx-in-sequence
           (aref (bl.ser:transaction-inputs coinbase) 0))
          #xffffffff)
    (is-true (bl.val:check-transaction-final coinbase 800000 800000)
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
      (is-false (bl.interop::check-der-signature-format too-big)
                "74 bytes with the hashtype: Core rejects on size, so must we")
      (is-true (bl.interop::check-der-signature-format largest)
               "72 bytes with the hashtype is legal — the fix must not
                over-tighten and start rejecting valid signatures"))))

;;;; ACCEPT-BLOCK-BODY -- Core AcceptBlock's pre-write gate

(test accept-block-body-is-the-gate-every-persist-path-runs
  "Core writes a block body in one place, AcceptBlock, and the two lines before
the write are CheckBlock and ContextualCheckBlock (validation.cpp:4381-4389).
ACCEPT-BLOCK-BODY is that pair, so every persist path can run it instead of
remembering both. It accepts an honest body; it rejects a forged one
(bad-txnmrklroot) without touching the honest header's index entry, a
consensus-invalid one (bad-cb-multiple) with the entry marked :invalid, and a
non-final coinbase -- which no context-free check can see, so that case is what
proves the CONTEXTUAL half runs here too."
  (with-network (:mainnet)
    (multiple-value-bind (cs utxo store genesis-hash)
        (make-activate-block-fixture "accept-block-body-gate")
      (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA4 2))
      (let* ((tip-entry (bl.store:get-block-index-entry
                         cs (bl.store:best-block-hash cs)))
             (tip-hash (bl.store:block-index-entry-hash tip-entry)))
        (destructuring-bind (honest-h forged-h consensus-h nonfinal-h)
            (make-test-chain-hashes #xB3 4)
          (let ((honest (make-reorg-test-block tip-hash honest-h 3))
                (forged (make-forged-body-block tip-hash forged-h 3))
                (consensus (make-two-coinbase-block tip-hash consensus-h 3))
                (nonfinal (make-reorg-test-block tip-hash nonfinal-h 3
                                                 :lock-time 500000
                                                 :sequence 0)))
            (dolist (row (list (list honest honest-h)
                               (list forged forged-h)
                               (list consensus consensus-h)
                               (list nonfinal nonfinal-h)))
              (bl.store:add-block-index-entry
               cs (bl.store:make-block-index-entry
                   :hash (second row) :height 3 :prev-entry tip-entry
                   :chain-work 900000 :status :header-valid
                   :header (bl.ser:bitcoin-block-header (first row)))))
            ;; Positive control: an honest body passes, so a rejection below is
            ;; the gate finding a defect and not the fixture being unbuildable.
            (is-true (bl.val:accept-block-body honest cs)
                     "the gate refused an honest body")
            ;; CheckBlock, mutation class: refused, honest header untouched.
            (is (eq :bad-merkle-root
                    (nth-value 1 (bl.val:accept-block-body forged cs)))
                "a forged body was accepted")
            (is (eq :header-valid
                    (bl.store:block-index-entry-status
                     (bl.store:get-block-index-entry cs forged-h)))
                "a mutated verdict poisoned the honest header (Core keeps
                 BLOCK_MUTATED off BLOCK_FAILED_VALID)")
            ;; CheckBlock, consensus class: refused AND the entry marked.
            (is (eq :multiple-coinbase
                    (nth-value 1 (bl.val:accept-block-body consensus cs)))
                "a two-coinbase body was accepted")
            (is (eq :invalid
                    (bl.store:block-index-entry-status
                     (bl.store:get-block-index-entry cs consensus-h)))
                "a consensus verdict did not mark the entry invalid")
            ;; ContextualCheckBlock: invisible to any context-free check.
            (is-true (bl.val:validate-block nonfinal cs utxo 3
                                            (bl.ser:get-unix-time)
                                            :context-free-only t)
                     "control: CheckBlock alone cannot see a non-final coinbase")
            (is (eq :non-final-tx
                    (nth-value 1 (bl.val:accept-block-body nonfinal cs)))
                "the gate skipped Core's ContextualCheckBlock half")))))))

(test activate-block-does-not-store-a-body-that-fails-the-gate
  "ACTIVATE-BLOCK's weaker-chain case stores a block without connecting it, and
did so with no CheckBlock at all -- the same hole as the two IBD persist paths,
reached instead from the relay and submitblock sides. It must now refuse."
  (with-network (:mainnet)
    (multiple-value-bind (cs utxo store genesis-hash)
        (make-activate-block-fixture "activate-block-gate")
      (build-and-connect cs store utxo genesis-hash (make-test-chain-hashes #xA5 2))
      (let ((genesis-entry (bl.store:get-block-index-entry cs genesis-hash)))
        (destructuring-bind (forged-h honest-h) (make-test-chain-hashes #xB4 2)
          (let ((forged (make-forged-body-block genesis-hash forged-h 1))
                (ok (make-reorg-test-block genesis-hash honest-h 1)))
            (dolist (row (list (list forged forged-h) (list ok honest-h)))
              (bl.store:add-block-index-entry
               cs (bl.store:make-block-index-entry
                   :hash (second row) :height 1 :prev-entry genesis-entry
                   :chain-work 50 :status :header-valid
                   :header (bl.ser:bitcoin-block-header (first row)))))
            (is (eq :bad-merkle-root
                    (nth-value 1 (bl.val:activate-block forged cs store utxo)))
                "activate-block accepted a forged weaker-chain body")
            (is-false (bl.store:block-exists-p store forged-h)
                      "a forged weaker-chain body reached disk")
            (is (eq :weaker-chain
                    (nth-value 1 (bl.val:activate-block ok cs store utxo)))
                "positive control: an honest weaker-chain body must be stored")
            (is-true (bl.store:block-exists-p store honest-h)
                     "positive control: the honest body did not reach disk")))))))
