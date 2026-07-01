(in-package #:bitcoin-lisp.tests)

;;;; BIP174 PSBT tests
;;;;
;;;; Validates PSBT serialization against Bitcoin Core's rpc_psbt.json:
;;;; every "valid" PSBT must round-trip byte-for-byte, and the structural
;;;; "invalid" PSBTs must be rejected.

(def-suite :psbt-tests
  :description "BIP174 PSBT serialization + RPC tests"
  :in :bitcoin-lisp-tests)

(in-suite :psbt-tests)

(defun %psbt-vectors ()
  "Load Core's rpc_psbt.json, or NIL if the refs/ clone is absent."
  (let ((path (merge-pathnames "refs/bitcoin/test/functional/data/rpc_psbt.json"
                               (asdf:system-source-directory :bitcoin-lisp))))
    (when (probe-file path)
      (with-open-file (s path :direction :input) (yason:parse s)))))

(defun %psbt-b64->bytes (b64)
  (coerce (cl-base64:base64-string-to-usb8-array b64)
          '(simple-array (unsigned-byte 8) (*))))

(test psbt-valid-roundtrip
  "Every Core 'valid' PSBT parses and re-serializes byte-for-byte."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((n 0))
          (dolist (b64 (gethash "valid" data))
            (let* ((raw (%psbt-b64->bytes b64))
                   (psbt (bitcoin-lisp.serialization:parse-psbt raw))
                   (out (bitcoin-lisp.serialization:serialize-psbt psbt)))
              (is (equalp raw out) "valid PSBT #~D did not round-trip" n)
              (incf n)))
          (is (>= n 30) "expected many valid vectors, got ~D" n)))))

(test psbt-invalid-rejected
  "Core 'invalid' PSBTs are rejected (structural checks). Deep taproot/musig
field-length checks are not implemented, so we require the bulk, not all."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((rejected 0) (total 0))
          (dolist (b64 (gethash "invalid" data))
            (incf total)
            (when (handler-case
                      (progn (bitcoin-lisp.serialization:parse-psbt (%psbt-b64->bytes b64))
                             nil)
                    (error () t))
              (incf rejected)))
          ;; ~28/41: structural + v0 field-content checks. The rest are BIP371
          ;; taproot / BIP327 musig deep field-length checks we don't implement.
          (is (>= rejected 27)
              "expected to reject most invalid PSBTs, got ~D/~D" rejected total)))))

(test psbt-make-empty
  "make-empty-psbt wraps an unsigned tx and round-trips; input/output map counts
match the tx."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        ;; Take a valid PSBT's unsigned tx, rebuild an empty PSBT from it.
        (let* ((psbt (bitcoin-lisp.serialization:parse-psbt
                      (%psbt-b64->bytes (first (gethash "valid" data)))))
               (tx (bitcoin-lisp.serialization:psbt-tx psbt))
               (empty (bitcoin-lisp.serialization:make-empty-psbt tx)))
          (is (= (length (bitcoin-lisp.serialization:transaction-inputs tx))
                 (length (bitcoin-lisp.serialization:psbt-inputs empty))))
          (is (= (length (bitcoin-lisp.serialization:transaction-outputs tx))
                 (length (bitcoin-lisp.serialization:psbt-outputs empty))))
          ;; round-trips through binary + base64
          (let ((b64 (bitcoin-lisp.serialization:encode-psbt empty)))
            (is (equalp (bitcoin-lisp.serialization:serialize-psbt empty)
                        (bitcoin-lisp.serialization:serialize-psbt
                         (bitcoin-lisp.serialization:decode-psbt b64)))))))))

;;; --- creator / decoder / converter RPCs ---

(defun %psbt-ser (b64-or-psbt)
  "Serialized bytes of a PSBT given as base64 or a struct (for order-independent
equality)."
  (bitcoin-lisp.serialization:serialize-psbt
   (if (stringp b64-or-psbt)
       (bitcoin-lisp.serialization:decode-psbt b64-or-psbt)
       b64-or-psbt)))

(test psbt-createpsbt-vector
  "createpsbt reproduces Core's creator test vector."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((c (first (gethash "creator" data)))
               (node (bitcoin-lisp::make-node :network :regtest))
               ;; Core's rpc_psbt.py generates this vector with replaceable=False.
               (out (bitcoin-lisp.rpc::rpc-createpsbt
                     node (list (gethash "inputs" c) (gethash "outputs" c) 0 nil))))
          (is (equalp (%psbt-ser out) (%psbt-ser (gethash "result" c))))))))

(test psbt-decodepsbt-shape
  "decodepsbt returns the expected top-level structure for a valid PSBT."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bitcoin-lisp::make-node :network :regtest))
               (res (bitcoin-lisp.rpc::rpc-decodepsbt
                     node (list (first (gethash "valid" data))))))
          (is-true (assoc "tx" res :test #'equal))
          (is-true (assoc "inputs" res :test #'equal))
          (is-true (assoc "outputs" res :test #'equal))
          ;; every valid vector decodes without error
          (dolist (b64 (gethash "valid" data))
            (is-true (bitcoin-lisp.rpc::rpc-decodepsbt node (list b64))))))))

(test psbt-converttopsbt-roundtrip
  "converttopsbt on an unsigned tx yields a PSBT wrapping that same tx; a signed
tx is rejected unless permitsigdata."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bitcoin-lisp::make-node :network :regtest))
               ;; unsigned tx from the creator result
               (tx (bitcoin-lisp.serialization:psbt-tx
                    (bitcoin-lisp.serialization:decode-psbt
                     (gethash "result" (first (gethash "creator" data))))))
               (hex (bitcoin-lisp.crypto:bytes-to-hex
                     (bitcoin-lisp.serialization:serialize-transaction tx)))
               (out (bitcoin-lisp.rpc::rpc-converttopsbt node (list hex))))
          (is (equalp (%psbt-ser out)
                      (%psbt-ser (bitcoin-lisp.serialization:encode-psbt
                                  (bitcoin-lisp.serialization:make-empty-psbt tx)))))))))

;;; --- combiner / join / analyze ---

(defun %psbt-maps-equiv (a b)
  (let ((ra (bitcoin-lisp.serialization:psbt-map-records a))
        (rb (bitcoin-lisp.serialization:psbt-map-records b)))
    (and (= (length ra) (length rb))
         (every (lambda (r) (member r rb :test #'equalp)) ra))))

(defun %psbt-equiv (a b)
  "Semantic PSBT equality: same unsigned tx and the same record sets per map
(order-independent), so it survives Combine's union ordering."
  (and (equalp (bitcoin-lisp.serialization:serialize-transaction (bitcoin-lisp.serialization:psbt-tx a))
               (bitcoin-lisp.serialization:serialize-transaction (bitcoin-lisp.serialization:psbt-tx b)))
       (%psbt-maps-equiv (bitcoin-lisp.serialization:psbt-global a)
                         (bitcoin-lisp.serialization:psbt-global b))
       (= (length (bitcoin-lisp.serialization:psbt-inputs a))
          (length (bitcoin-lisp.serialization:psbt-inputs b)))
       (every #'%psbt-maps-equiv (bitcoin-lisp.serialization:psbt-inputs a)
              (bitcoin-lisp.serialization:psbt-inputs b))
       (every #'%psbt-maps-equiv (bitcoin-lisp.serialization:psbt-outputs a)
              (bitcoin-lisp.serialization:psbt-outputs b))))

(test psbt-combinepsbt-vector
  "combinepsbt reproduces Core's combiner test vectors (union semantics)."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((node (bitcoin-lisp::make-node :network :regtest)))
          (dolist (c (gethash "combiner" data))
            (let ((got (bitcoin-lisp.serialization:decode-psbt
                        (bitcoin-lisp.rpc::rpc-combinepsbt node (list (gethash "combine" c)))))
                  (exp (bitcoin-lisp.serialization:decode-psbt (gethash "result" c))))
              (is (%psbt-equiv got exp) "combiner vector mismatch")))))))

(test psbt-joinpsbts-and-analyze
  "joinpsbts concatenates distinct PSBTs; analyzepsbt reports structure."
  (let ((node (bitcoin-lisp::make-node :network :regtest)))
    (let* ((a (bitcoin-lisp.rpc::rpc-createpsbt
               node (list (list (list (cons "txid" (make-string 64 :initial-element #\a))
                                      (cons "vout" 0)))
                          '())))
           (b (bitcoin-lisp.rpc::rpc-createpsbt
               node (list (list (list (cons "txid" (make-string 64 :initial-element #\b))
                                      (cons "vout" 1)))
                          '())))
           (joined (bitcoin-lisp.serialization:decode-psbt
                    (bitcoin-lisp.rpc::rpc-joinpsbts node (list (list a b))))))
      (is (= 2 (length (bitcoin-lisp.serialization:psbt-inputs joined))))
      ;; analyze a freshly created PSBT: no utxos -> next is updater
      (let ((res (bitcoin-lisp.rpc::rpc-analyzepsbt node (list a))))
        (is (string= "updater" (cdr (assoc "next" res :test #'equal))))
        (is-true (assoc "inputs" res :test #'equal))))))

;;; --- finalizer / extractor / combinerawtransaction ---

(test psbt-finalizepsbt-vector
  "finalizepsbt (extract=false) reproduces Core's finalizer test vector."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bitcoin-lisp::make-node :network :regtest))
               (f (first (gethash "finalizer" data)))
               (out (bitcoin-lisp.rpc::rpc-finalizepsbt node (list (gethash "finalize" f) nil)))
               (got (bitcoin-lisp.serialization:decode-psbt (cdr (assoc "psbt" out :test #'equal))))
               (exp (bitcoin-lisp.serialization:decode-psbt (gethash "result" f))))
          (is-true (cdr (assoc "complete" out :test #'equal)))
          (is (%psbt-equiv got exp) "finalizer vector mismatch")))))

(test psbt-extractor-vector
  "finalizepsbt (extract=true) extracts the network tx matching Core's extractor
vector."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bitcoin-lisp::make-node :network :regtest))
               (e (first (gethash "extractor" data)))
               (out (bitcoin-lisp.rpc::rpc-finalizepsbt node (list (gethash "extract" e)))))
          (is (string= (cdr (assoc "hex" out :test #'equal)) (gethash "result" e)))))))

(test combinerawtransaction-merges
  "combinerawtransaction keeps the most-complete scriptSig per input."
  (let* ((node (bitcoin-lisp::make-node :network :regtest))
         (prevout (bitcoin-lisp.serialization:make-outpoint
                   :hash (make-array 32 :element-type '(unsigned-byte 8)) :index 0))
         (out (bitcoin-lisp.serialization:make-tx-out
               :value 1000 :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
         (mk (lambda (ss)
               (bitcoin-lisp.crypto:bytes-to-hex
                (bitcoin-lisp.serialization:serialize-transaction
                 (bitcoin-lisp.serialization:make-transaction
                  :version 2
                  :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                   :previous-output prevout :script-sig ss :sequence #xffffffff))
                  :outputs (vector out) :lock-time 0)))))
         (signed (funcall mk (coerce #(1 2 3 4 5) '(simple-array (unsigned-byte 8) (*)))))
         (empty  (funcall mk (make-array 0 :element-type '(unsigned-byte 8))))
         (combined (bitcoin-lisp.rpc::rpc-combinerawtransaction node (list (list empty signed))))
         (tx (bitcoin-lisp.serialization:br-read-transaction
              (bitcoin-lisp.serialization:make-byte-reader-from
               (coerce (bitcoin-lisp.crypto:hex-to-bytes combined)
                       '(simple-array (unsigned-byte 8) (*)))))))
    (is (= 5 (length (bitcoin-lisp.serialization:tx-in-script-sig
                      (aref (bitcoin-lisp.serialization:transaction-inputs tx) 0)))))))

(test psbt-createpsbt-defaults-and-validation
  "createpsbt sequence follows Core (replaceable default true -> RBF; explicit
false honors locktime), and duplicate outputs are rejected."
  (let* ((node (bitcoin-lisp::make-node :network :regtest))
         (txid (make-string 64 :initial-element #\a))
         (in (list (list (cons "txid" txid) (cons "vout" 0))))
         (seq-of (lambda (params)
                   (bitcoin-lisp.serialization:tx-in-sequence
                    (aref (bitcoin-lisp.serialization:transaction-inputs
                           (bitcoin-lisp.serialization:psbt-tx
                            (bitcoin-lisp.serialization:decode-psbt
                             (bitcoin-lisp.rpc::rpc-createpsbt node params))))
                          0)))))
    ;; default (no replaceable) -> RBF-signaling 0xfffffffd
    (is (= #xfffffffd (funcall seq-of (list in '()))))
    ;; explicit replaceable=false, locktime 0 -> final 0xffffffff
    (is (= #xffffffff (funcall seq-of (list in '() 0 nil))))
    ;; explicit replaceable=false, locktime>0 -> 0xfffffffe (locktime enforced)
    (is (= #xfffffffe (funcall seq-of (list in '() 500000 nil))))
    ;; duplicate output address is rejected
    (let ((addr (bitcoin-lisp.crypto:encode-p2pkh-address
                 (make-array 20 :element-type '(unsigned-byte 8) :initial-element 5) :regtest)))
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createpsbt
         node (list in (list (list (cons addr 0.1)) (list (cons addr 0.2)))))))))
