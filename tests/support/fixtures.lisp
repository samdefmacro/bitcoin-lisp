(in-package #:bitcoin-lisp.test-support)

;;;; Temporary directories

(defun make-temp-directory (&optional (prefix "bl-test"))
  "A fresh, private directory under the system temporary directory,
PREFIX-<time>-<random>/, created and returned. The caller removes it;
WITH-TEMP-DIRECTORY does that on unwind. Never a fixed name: two test
processes on one machine would share it."
  (ensure-directories-exist
   (merge-pathnames (format nil "~A-~D-~D/" prefix (get-universal-time) (random 1000000))
                    (uiop:temporary-directory))))

(defmacro with-temp-directory ((var &optional (prefix "bl-test")) &body body)
  "Run BODY with VAR bound to a fresh temporary directory (MAKE-TEMP-DIRECTORY),
removed with everything in it afterwards. A data directory for a node under
test, a flat-file store, a snapshot dump -- and every START-RPC-SERVER call
needs one, because the .cookie written there is the credential when no
rpcuser/rpcpassword is configured."
  `(let ((,var (make-temp-directory ,prefix)))
     (unwind-protect (progn ,@body)
       (uiop:delete-directory-tree ,var :validate t :if-does-not-exist :ignore))))

;;;; The chain under test

(defmacro with-network ((network) &body body)
  "Run BODY with BL:*NETWORK* bound to NETWORK. For :REGTEST the proof-of-work
limit is bound to regtest's as well, so a #x207fffff target is valid and
synthetic headers reach the contextual checks; :MAINNET is what version-1
test blocks need to pass the BIP34 activation check (testnet4 activates
BIP34 at height 1)."
  (let ((n (gensym "NETWORK")))
    `(let* ((,n ,network)
            (bl:*network* ,n)
            (bl.store:*pow-limit-target*
              (if (eq ,n :regtest)
                  bl.store:+regtest-pow-limit-target+
                  bl.store:*pow-limit-target*)))
       ,@body)))

;;;; The minimal node

(defun make-test-node (&key (network :testnet3))
  "Create a node with minimal initialized state for testing."
  (let ((node (bl:make-node :network network)))
    ;; Initialize chain-state
    (setf (bl:node-chain-state node)
          (bl.store:make-chain-state))
    ;; Initialize UTXO set
    (setf (bl:node-utxo-set node)
          (bl.store:make-utxo-set))
    ;; Initialize mempool
    (setf (bl:node-mempool node)
          (bl.mp:make-mempool))
    node))

;;;; Reproducible randomness

(defun make-deterministic-rng (seed)
  "Deterministic xorshift64 PRNG closure: (funcall rng n) => [0, n). No
dependence on the global *random-state*, so runs are reproducible."
  (let ((state seed))
    (lambda (n)
      (setf state (ldb (byte 64 0) (logxor state (ash state 13))))
      (setf state (logxor state (ash state -7)))
      (setf state (ldb (byte 64 0) (logxor state (ash state 17))))
      (mod state n))))

;;;; The IBD context

(defmacro with-ibd-context (&body body)
  "Run BODY with BL.NET:*IBD-CONTEXT* bound to a fresh IBD context -- the
binding every headers-sync, block-download and reorg-through-IBD test opens
with; nineteen of them wrote the LET themselves."
  `(let ((bl.net:*ibd-context* (bl.net::make-ibd)))
     ,@body))

;;;; RPC errors

(defmacro signals-rpc-error ((&key code message exact-message) &body body)
  "Assert that BODY signals an RPC-ERROR carrying Core error CODE and/or a
message containing MESSAGE (or equal to EXACT-MESSAGE); BODY returning
normally is a failure. At least one check is required: the plain
(signals bl.rpc:rpc-error ...) accepts any RPC error, which is how a test
stays green when a type-check error preempts the check it was written for."
  (unless (or code message exact-message)
    (error "signals-rpc-error needs :code, :message or :exact-message -- a ~
bare form is (signals bl.rpc:rpc-error ...)"))
  (let ((e (gensym "E")))
    `(handler-case (progn ,@body
                          (fiveam:fail "expected an rpc-error~@[ with code ~D~]~@[ mentioning ~S~], got a normal return"
                                       ,code ,(or message exact-message)))
       (bl.rpc:rpc-error (,e)
         ,@(when code
             `((fiveam:is (= ,code (bl.rpc:rpc-error-code ,e))
                          "expected rpc-error code ~D, got ~D (~A)"
                          ,code (bl.rpc:rpc-error-code ,e) (bl.rpc:rpc-error-message ,e))))
         ,@(when message
             `((fiveam:is (search ,message (bl.rpc:rpc-error-message ,e))
                          "expected the rpc-error message to mention ~S, got ~S"
                          ,message (bl.rpc:rpc-error-message ,e))))
         ,@(when exact-message
             `((fiveam:is (string= ,exact-message (bl.rpc:rpc-error-message ,e))
                          "expected the rpc-error message ~S, got ~S"
                          ,exact-message (bl.rpc:rpc-error-message ,e))))))))

(defun rpc-error-code-of (thunk)
  "The rpc-error code THUNK signals, or NIL if it returns normally."
  (handler-case (progn (funcall thunk) nil)
    (bl.rpc:rpc-error (e) (bl.rpc:rpc-error-code e))))

;;;; Coins-view-cache white-box readers

;;; The cache's DIRTY/FRESH bookkeeping is internal to BL.STORE, and both
;;; tests/storage/ and tests/kv/ assert on it. Naming each accessor once here
;;; keeps those `::' out of the test files (the structural ratchet
;;; TEST-INTERNAL-REFERENCES-DO-NOT-GROW) and gives the assertions one
;;; vocabulary for the flags whose meaning is stated in coins-view-cache.lisp.

(defun coins-cache-entries (cache)
  "The cache's entry table, keyed by utxo-key. HASH-TABLE-COUNT it for the
cache's size, GETHASH a key out of it for one entry, MAPHASH it for all."
  (bl.store::cvc-entries cache))

(defun coins-cache-fresh-count (cache)
  "How many entries the cache counts as FRESH — absent from the base view, so
a spend may drop them outright instead of staging an erase."
  (bl.store::cvc-fresh-count cache))

(defun coins-cache-dirty-count (cache)
  "How many entries the cache counts as DIRTY — changed since the last write
to the base view."
  (bl.store::cvc-dirty-count cache))

(defun coins-cache-entry-fresh-p (entry)
  "Whether one cache entry carries the FRESH flag."
  (bl.store::ce-fresh entry))

(defun coins-cache-entry-dirty-p (entry)
  "Whether one cache entry carries the DIRTY flag."
  (bl.store::ce-dirty entry))
