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

(defun make-test-node ()
  "Create a node with minimal initialized state for testing."
  (let ((node (bl::make-node :network :testnet3)))
    ;; Initialize chain-state
    (setf (bl::node-chain-state node)
          (bl.store:make-chain-state))
    ;; Initialize UTXO set
    (setf (bl::node-utxo-set node)
          (bl.store:make-utxo-set))
    ;; Initialize mempool
    (setf (bl::node-mempool node)
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
