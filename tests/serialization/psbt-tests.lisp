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
  "Every Core 'valid' PSBT parses and re-serializes as Core's writer would:
byte-for-byte, except #6, which declares PSBT_GLOBAL_VERSION 0 AHEAD of the
unsigned transaction. Core writes its fields in a fixed order and a version
only when it is above 0 (psbt.h:1170-1191), so its bytes for #6 are the input
without that leading 01 fb 04 00000000 record."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((n 0))
          (dolist (b64 (gethash "valid" data))
            (let* ((raw (%psbt-b64->bytes b64))
                   (psbt (bl.ser:parse-psbt raw))
                   (out (bl.ser:serialize-psbt psbt))
                   (want (if (= n 6)
                             (concatenate '(vector (unsigned-byte 8))
                                          (subseq raw 0 5) (subseq raw 12))
                             raw)))
              (is (equalp want out) "valid PSBT #~D did not round-trip" n)
              (incf n)))
          (is (>= n 30) "expected many valid vectors, got ~D" n)))))

(test psbt-invalid-rejected
  "EVERY PSBT in Core's `invalid' list is rejected. rpc_psbt.py:813-815 asks
for exactly that -- each one is decodepsbt(-22, \"TX decode failed\") -- so a
vector we accept is one our decoder hands on to a consumer that has no reason
to doubt it.

Eleven of the forty-one used to get through: the BIP371 taproot field lengths
(Core psbt.h:691-790 for the input keytypes, :1022-1087 for the output ones)
and one output BIP32 keypath whose key is 32 bytes where a pubkey is 33 or 65.
The ceiling was written as `>= 30' and the eleven were described as checks we
do not implement.

The `valid' vectors are the control: they must still decode, so a length rule
written one byte too tight fails here rather than passing."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((accepted '()) (total 0))
          (dolist (b64 (gethash "invalid" data))
            (incf total)
            (unless (handler-case
                        (progn (bl.ser:parse-psbt (%psbt-b64->bytes b64))
                               nil)
                      (error () t))
              (push b64 accepted)))
          (is (null accepted)
              "~D of ~D invalid PSBTs decoded: ~S"
              (length accepted) total accepted)
          (dolist (b64 (gethash "valid" data))
            (is-true (bl.ser:parse-psbt (%psbt-b64->bytes b64))
                     "a valid PSBT no longer decodes: ~A" b64))))))

(test psbt-invalid-with-msg-carries-cores-sentence
  "EVERY PSBT in Core's `invalid_with_msg' list is refused with Core's own
sentence: rpc_psbt.py:816-818 asserts decodepsbt answers -22 \"TX decode
failed <msg>\" for each pair. The twenty exercise the BIP371 taproot
derivation and tree readers (psbt.h:755-768, :1036-1085) and the BIP373 MuSig2
readers (:203-256, :791-836, :1088-1095). Eighteen used to DECODE, and the
first died on an index past the end of the whole PSBT."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((n 0))
          (dolist (pair (gethash "invalid_with_msg" data))
            (let ((got (%psbt-parse-failure (%psbt-b64->bytes (first pair)))))
              (incf n)
              (is-true (and got (search (second pair) got))
                       "invalid_with_msg #~D: want ~S, got ~S"
                       n (second pair) got)))
          (is (= n 20) "expected Core's 20 invalid_with_msg vectors, got ~D" n)))))

(defun %psbt-hand-built-bytes (&key version (prevout-index 0))
  "A hand-built 1-in/1-out PSBT spending PREVOUT-INDEX of a previous
transaction that has exactly ONE output, carried as the input's
non_witness_utxo, plus (when VERSION) a PSBT_GLOBAL_VERSION record declaring
it. The defaults produce a PSBT Core accepts."
  (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
         (anyone (coerce #(#x51)          ; OP_TRUE
                         '(simple-array (unsigned-byte 8) (*))))
         (prev-tx (bl.ser:make-transaction
                   :version 1
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output
                                    (bl.ser:make-outpoint
                                     :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element 0)
                                     :index #xffffffff)
                                    :script-sig anyone
                                    :sequence #xffffffff))
                   :outputs (vector (bl.ser:make-tx-out :value 100000
                                                        :script-pubkey anyone))
                   :lock-time 0 :witness nil))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output
                               (bl.ser:make-outpoint
                                :hash (bl.ser:transaction-hash prev-tx)
                                :index prevout-index)
                               :script-sig empty
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out :value 90000
                                                   :script-pubkey anyone))
              :lock-time 0 :witness nil))
         (psbt (bl.ser:make-empty-psbt tx)))
    (when version
      (bl.ser:psbt-map-set (bl.ser:psbt-global psbt) bl.ser:+psbt-global-version+
                           empty
                           (coerce (vector version 0 0 0)
                                   '(simple-array (unsigned-byte 8) (*)))))
    (bl.ser:psbt-map-set (aref (bl.ser:psbt-inputs psbt) 0)
                         bl.ser:+psbt-in-non-witness-utxo+ empty
                         (bl.ser:serialize-transaction prev-tx))
    (bl.ser:serialize-psbt psbt)))

(defun %psbt-parse-failure (bytes)
  "The report of the error PARSE-PSBT signals on BYTES, or NIL when it parses."
  (handler-case (progn (bl.ser:parse-psbt bytes) nil)
    (error (e) (princ-to-string e))))

(test psbt-parser-enforces-core-global-map-checks
  "parse-psbt refuses an unsupported PSBT version and an outpoint index past
the end of the input's own non_witness_utxo (Core psbt.h:1322-1323 and
:1375-1377). The unmutated PSBT parses, so the rejections are the mutations."
  (is (null (%psbt-parse-failure (%psbt-hand-built-bytes))))
  (let ((bad-version (%psbt-parse-failure (%psbt-hand-built-bytes :version 2)))
        (bad-index (%psbt-parse-failure (%psbt-hand-built-bytes :prevout-index 5))))
    (is-true (and bad-version (search "Unsupported version number" bad-version))
             "expected Core's version message, got ~S" bad-version)
    (is-true (and bad-index
                  (search "Input specifies output index that does not exist"
                          bad-index))
             "expected Core's index message, got ~S" bad-index)))

(test psbt-make-empty
  "make-empty-psbt wraps an unsigned tx and round-trips; input/output map counts
match the tx."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        ;; Take a valid PSBT's unsigned tx, rebuild an empty PSBT from it.
        (let* ((psbt (bl.ser:parse-psbt
                      (%psbt-b64->bytes (first (gethash "valid" data)))))
               (tx (bl.ser:psbt-tx psbt))
               (empty (bl.ser:make-empty-psbt tx)))
          (is (= (length (bl.ser:transaction-inputs tx))
                 (length (bl.ser:psbt-inputs empty))))
          (is (= (length (bl.ser:transaction-outputs tx))
                 (length (bl.ser:psbt-outputs empty))))
          ;; round-trips through binary + base64
          (let ((b64 (bl.ser:encode-psbt empty)))
            (is (equalp (bl.ser:serialize-psbt empty)
                        (bl.ser:serialize-psbt
                         (bl.ser:decode-psbt b64)))))))))

;;; --- creator / decoder / converter RPCs ---

(defun %psbt-createpsbt (node params)
  "The createpsbt RPC (Core rawtransaction.cpp): named once so the seven
tests that drive the creator share one reach."
  (bl.wallet::rpc-createpsbt node params))

(defun %psbt-ser (b64-or-psbt)
  "Serialized bytes of a PSBT given as base64 or a struct (for order-independent
equality)."
  (bl.ser:serialize-psbt
   (if (stringp b64-or-psbt)
       (bl.ser:decode-psbt b64-or-psbt)
       b64-or-psbt)))

(test psbt-createpsbt-vector
  "createpsbt reproduces Core's creator test vector."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((c (first (gethash "creator" data)))
               (node (bl:make-node :network :regtest))
               ;; Core's rpc_psbt.py generates this vector with replaceable=False
               ;; (explicit false = the +json-false+ sentinel; a null would
               ;; take Core's default true and signal RBF).
               (out (%psbt-createpsbt
                     node (list (gethash "inputs" c) (gethash "outputs" c) 0
                                bl.rpc:+json-false+))))
          (is (equalp (%psbt-ser out) (%psbt-ser (gethash "result" c))))))))

(test psbt-createpsbt-is-core-construct-transaction
  "Core's createpsbt calls the SAME ConstructTransaction as
createrawtransaction (rpc/rawtransaction.cpp:1644 and :404, over
rawtransaction_util.cpp:147-171), with the same CreateTxDoc arguments
(rawtransaction.cpp:87-124): inputs, outputs, locktime, replaceable and
VERSION. Ours had a second, thinner copy of that function, and the three
differences below are what wallet_v3_txs.py:449-451 and
rpc_rawtransaction.py reach:

  - outputs as a DICTIONARY, which CreateTxDoc:104-105 accepts for
    compatibility alongside the array of objects. Ours demanded a list and
    answered -8 \"Invalid outputs\" to createpsbt(inputs=[], outputs={addr: 10}),
    which is the call at wallet_v3_txs.py:450;
  - the VERSION argument, absent entirely, so version=3 (TRUC) produced a
    version-2 transaction with silently different relay policy;
  - the locktime range and the explicit-replaceable contradiction check.

The amounts are Core's AmountFromValue now too, not a float multiplied by
1e8: createrawtransaction and createpsbt over the same arguments must give
the same bytes, which is the strongest form this assertion takes."
  ;; The empty inputs array reaches the handler as NIL here: createpsbt
  ;; already folds the top-level empty-array sentinel with POSITIONAL-ARRAY
  ;; (src/wallet/psbt.lisp), and rpc_psbt.py's own opening call pinned that.
  (let* ((node (bl:make-node :network :regtest))
         (addr "bcrt1qqurswpc8qurswpc8qurswpc8qurswpc8dxm0gk")
         (dict (let ((h (make-hash-table :test 'equal)))
                 (setf (gethash addr h) "10.00000000") h))
         (arr (list (let ((h (make-hash-table :test 'equal)))
                      (setf (gethash addr h) "10.00000000") h))))
    ;; wallet_v3_txs.py:450 verbatim in shape: no inputs, a dict of outputs.
    (let* ((b64 (%psbt-createpsbt node (list nil dict)))
           (tx (bl.ser:psbt-tx (bl.ser:decode-psbt b64))))
      (is (= 1 (length (bl.ser:transaction-outputs tx))))
      (is (= 1000000000 (bl.ser:tx-out-value
                         (aref (bl.ser:transaction-outputs tx) 0))))
      ;; wallet_v3_txs.py:451: version=3 reaches the transaction.
      (is (= 2 (bl.ser:transaction-version tx))))
    (let* ((b64 (%psbt-createpsbt node (list nil dict 0
                                             bl.rpc:+json-false+ 3)))
           (tx (bl.ser:psbt-tx (bl.ser:decode-psbt b64))))
      (is (= 3 (bl.ser:transaction-version tx))))
    ;; The array form and the dictionary form are the same transaction, and
    ;; both agree with createrawtransaction over the same arguments.
    (let ((from-dict (bl.ser:psbt-tx
                      (bl.ser:decode-psbt
                       (%psbt-createpsbt node (list nil dict 0
                                                    bl.rpc:+json-false+ 3)))))
          (from-arr (bl.ser:psbt-tx
                     (bl.ser:decode-psbt
                      (%psbt-createpsbt node (list nil arr 0
                                                   bl.rpc:+json-false+ 3)))))
          ;; Over the DISPATCHER the empty inputs array has to be the wire
          ;; spelling: `inputs' is RPCArg::Optional::NO (rawtransaction.cpp:90)
          ;; and Core's MatchesType refuses a null there (rpc/util.cpp:591-597).
          ;; The handler calls above pass NIL because that is what the
          ;; normalizer hands a handler for [].
          (raw (bl.rpc:dispatch-rpc-method
                node "createrawtransaction"
                (wire-params (list (vector) dict 0 bl.rpc:+json-false+ 3)))))
      (is (equalp (bl.ser:transaction-wire-bytes from-dict)
                  (bl.ser:transaction-wire-bytes from-arr)))
      (is (string= raw (bl.crypto:bytes-to-hex
                        (bl.ser:transaction-wire-bytes from-dict)))
          "createpsbt and createrawtransaction built different transactions"))
    ;; Core's own range checks, which the second copy did not have.
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of
            (lambda () (%psbt-createpsbt node (list nil dict 0
                                                    bl.rpc:+json-false+ 4)))))
        "version 4 was accepted")
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of
            (lambda () (%psbt-createpsbt node (list nil dict
                                                    #x100000000)))))
        "an out-of-range locktime was accepted")))

(test psbt-decodepsbt-shape
  "decodepsbt returns the expected top-level structure for a valid PSBT."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bl:make-node :network :regtest))
               (res (bl.wallet::rpc-decodepsbt
                     node (list (first (gethash "valid" data))))))
          (is-true (assoc "tx" res :test #'equal))
          (is-true (assoc "inputs" res :test #'equal))
          (is-true (assoc "outputs" res :test #'equal))
          ;; every valid vector decodes without error
          (dolist (b64 (gethash "valid" data))
            (is-true (bl.wallet::rpc-decodepsbt node (list b64))))))))

(test psbt-converttopsbt-roundtrip
  "converttopsbt on an unsigned tx yields a PSBT wrapping that same tx; a signed
tx is rejected unless permitsigdata."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bl:make-node :network :regtest))
               ;; unsigned tx from the creator result
               (tx (bl.ser:psbt-tx
                    (bl.ser:decode-psbt
                     (gethash "result" (first (gethash "creator" data))))))
               (hex (bl.crypto:bytes-to-hex
                     (bl.ser:serialize-transaction tx)))
               (out (bl.wallet::rpc-converttopsbt node (list hex))))
          (is (equalp (%psbt-ser out)
                      (%psbt-ser (bl.ser:encode-psbt
                                  (bl.ser:make-empty-psbt tx)))))))))

(defun %psbt-tx-with-input-0 (tx &key script-sig witness)
  "TX with SCRIPT-SIG on its first input, or WITNESS as its first input's
stack -- the two shapes Core's converttopsbt refuses."
  (let ((ins (map 'simple-vector
                  (lambda (in)
                    (bl.ser:make-tx-in
                     :previous-output (bl.ser:tx-in-previous-output in)
                     :script-sig (bl.ser:tx-in-script-sig in)
                     :sequence (bl.ser:tx-in-sequence in)))
                  (bl.ser:transaction-inputs tx))))
    (when script-sig
      (setf (bl.ser:tx-in-script-sig (aref ins 0)) script-sig))
    (bl.ser:make-transaction
     :version (bl.ser:transaction-version tx)
     :inputs ins
     :outputs (bl.ser:transaction-outputs tx)
     :lock-time (bl.ser:transaction-lock-time tx)
     :witness (when witness
                (let ((stacks (make-array (length ins) :initial-element nil)))
                  (setf (aref stacks 0) witness)
                  stacks)))))

(test psbt-converttopsbt-refuses-signature-data
  "converttopsbt answers Core's -22 and its own sentence for a transaction
that carries a scriptSig or a witness, and strips them under permitsigdata
(rpc/rawtransaction.cpp:1704-1711, rpc_psbt.py:676-684)."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bl:make-node :network :regtest))
               (tx (bl.ser:psbt-tx
                    (bl.ser:decode-psbt
                     (gethash "result" (first (gethash "creator" data))))))
               (hex (lambda (transaction)
                      (bl.crypto:bytes-to-hex
                       (bl.ser:transaction-wire-bytes transaction))))
               (sig-tx (%psbt-tx-with-input-0
                        tx :script-sig (bl.crypto:hex-to-bytes "0101")))
               (wit-tx (%psbt-tx-with-input-0
                        tx :witness (list (bl.crypto:hex-to-bytes "0101")))))
          ;; the same transaction without signature data converts: the control
          ;; that says the three refusals below are about the signature data.
          (is-true (bl.wallet::rpc-converttopsbt node (list (funcall hex tx))))
          (dolist (hexstring (list (funcall hex sig-tx) (funcall hex wit-tx)))
            (signals-rpc-error
                (:code bl.rpc:+rpc-deserialization-error+
                 :exact-message "Inputs must not have scriptSigs and scriptWitnesses")
              (bl.wallet::rpc-converttopsbt node (list hexstring)))
            (signals-rpc-error
                (:code bl.rpc:+rpc-deserialization-error+
                 :exact-message "Inputs must not have scriptSigs and scriptWitnesses")
              (bl.wallet::rpc-converttopsbt node (list hexstring bl.rpc:+json-false+))))
          ;; permitsigdata converts and strips
          (let ((converted (bl.ser:psbt-tx
                            (bl.ser:decode-psbt
                             (bl.wallet::rpc-converttopsbt
                              node (list (funcall hex sig-tx) t))))))
            (is (zerop (length (bl.ser:tx-in-script-sig
                                (aref (bl.ser:transaction-inputs converted) 0))))
                "permitsigdata left the scriptSig in place")
            (is (equalp (bl.ser:transaction-wire-bytes tx)
                        (bl.ser:transaction-wire-bytes converted))
                "the stripped transaction is not the unsigned one"))))))

;;; --- combiner / join / analyze ---

(defun %psbt-maps-equiv (a b)
  (let ((ra (bl.ser:psbt-map-records a))
        (rb (bl.ser:psbt-map-records b)))
    (and (= (length ra) (length rb))
         (every (lambda (r) (member r rb :test #'equalp)) ra))))

(defun %psbt-equiv (a b)
  "Semantic PSBT equality: same unsigned tx and the same record sets per map
(order-independent), so it survives Combine's union ordering."
  (and (equalp (bl.ser:serialize-transaction (bl.ser:psbt-tx a))
               (bl.ser:serialize-transaction (bl.ser:psbt-tx b)))
       (%psbt-maps-equiv (bl.ser:psbt-global a)
                         (bl.ser:psbt-global b))
       (= (length (bl.ser:psbt-inputs a))
          (length (bl.ser:psbt-inputs b)))
       (every #'%psbt-maps-equiv (bl.ser:psbt-inputs a)
              (bl.ser:psbt-inputs b))
       (every #'%psbt-maps-equiv (bl.ser:psbt-outputs a)
              (bl.ser:psbt-outputs b))))

(test psbt-combinepsbt-vector
  "combinepsbt reproduces Core's combiner test vectors (union semantics)."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((node (bl:make-node :network :regtest)))
          (dolist (c (gethash "combiner" data))
            (let ((got (bl.ser:decode-psbt
                        (bl.wallet::rpc-combinepsbt node (list (gethash "combine" c)))))
                  (exp (bl.ser:decode-psbt (gethash "result" c))))
              (is (%psbt-equiv got exp) "combiner vector mismatch")))))))

(test psbt-joinpsbts-and-analyze
  "joinpsbts concatenates distinct PSBTs; analyzepsbt reports structure."
  (let ((node (bl:make-node :network :regtest)))
    (let* ((a (%psbt-createpsbt
               node (list (list (list (cons "txid" (make-string 64 :initial-element #\a))
                                      (cons "vout" 0)))
                          '())))
           (b (%psbt-createpsbt
               node (list (list (list (cons "txid" (make-string 64 :initial-element #\b))
                                      (cons "vout" 1)))
                          '())))
           (joined (bl.ser:decode-psbt
                    (bl.wallet::rpc-joinpsbts node (list (list a b))))))
      (is (= 2 (length (bl.ser:psbt-inputs joined))))
      ;; analyze a freshly created PSBT: no utxos -> next is updater
      (let ((res (bl.wallet::rpc-analyzepsbt node (list a))))
        (is (string= "updater" (cdr (assoc "next" res :test #'equal))))
        (is-true (assoc "inputs" res :test #'equal))))))

;;; --- finalizer / extractor / combinerawtransaction ---

(test psbt-finalizepsbt-vector
  "finalizepsbt (extract=false) reproduces Core's finalizer test vector."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bl:make-node :network :regtest))
               (f (first (gethash "finalizer" data)))
               (out (bl.wallet::rpc-finalizepsbt
                     node (list (gethash "finalize" f)
                                bl.rpc:+json-false+)))
               (got (bl.ser:decode-psbt (cdr (assoc "psbt" out :test #'equal))))
               (exp (bl.ser:decode-psbt (gethash "result" f))))
          (is-true (cdr (assoc "complete" out :test #'equal)))
          (is (%psbt-equiv got exp) "finalizer vector mismatch")))))

(test psbt-extractor-vector
  "finalizepsbt (extract=true) extracts the network tx matching Core's extractor
vector."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let* ((node (bl:make-node :network :regtest))
               (e (first (gethash "extractor" data)))
               (out (bl.wallet::rpc-finalizepsbt node (list (gethash "extract" e)))))
          (is (string= (cdr (assoc "hex" out :test #'equal)) (gethash "result" e)))))))

(test combinerawtransaction-refuses-an-input-no-coin-answers-for
  "Core looks every input's coin up in the chainstate + mempool view BEFORE it
merges anything, and refuses a missing or already-spent one with
RPC_VERIFY_ERROR `Input not found or already spent' (rpc/rawtransaction.cpp:
637-653). rpc_createmultisig.py:158 reads it by combining the same pair of
partial transactions again once their input has been spent.

We never consulted a coin at all -- the merge was `keep the longest scriptSig',
which needs nothing from the chain -- so this node, which knows no coin
whatsoever, answered a transaction instead of the refusal. The merge itself is
COMBINERAWTRANSACTION-MERGES-THE-SIGNATURES-CORE-MERGES, which needs a chain."
  (let* ((node (bl:make-node :network :regtest))
         (prevout (bl.ser:make-outpoint
                   :hash (make-array 32 :element-type '(unsigned-byte 8)) :index 0))
         (out (bl.ser:make-tx-out
               :value 1000 :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
         (mk (lambda (ss)
               (bl.crypto:bytes-to-hex
                (bl.ser:serialize-transaction
                 (bl.ser:make-transaction
                  :version 2
                  :inputs (vector (bl.ser:make-tx-in
                                   :previous-output prevout :script-sig ss :sequence #xffffffff))
                  :outputs (vector out) :lock-time 0)))))
         (signed (funcall mk (coerce #(1 2 3 4 5) '(simple-array (unsigned-byte 8) (*)))))
         (empty  (funcall mk (make-array 0 :element-type '(unsigned-byte 8)))))
    (is (equal (cons -25 "Input not found or already spent")
               (rpc-error-of
                (lambda ()
                  (bl.wallet::rpc-combinerawtransaction
                   node (list (list empty signed)))))))))

(test combinerawtransaction-refuses-an-empty-array-the-way-core-does
  "Core builds one CMutableTransaction per element and only THEN refuses an
empty list, with RPC_DESERIALIZATION_ERROR \"Missing transactions\"
(rpc/rawtransaction.cpp:608-619) -- rpc_createmultisig.py:150, one line after
the -22 \"TX decode failed\" it also asks for. Ours answered -8 with a sentence
of its own making, which no client can match."
  (let ((node (bl:make-node :network :regtest)))
    (is (equal (cons -22 "Missing transactions")
               (rpc-error-of
                (lambda ()
                  (bl.rpc:dispatch-rpc-method node "combinerawtransaction"
                                              (wire-params (list (vector))))))))
    ;; :149's row is the control that the decode loop still runs first and
    ;; names the offending index.
    (is (equal (cons -22 "TX decode failed for tx 0. Make sure the tx has at least one input.")
               (rpc-error-of
                (lambda ()
                  (bl.rpc:dispatch-rpc-method node "combinerawtransaction"
                                              (wire-params (list (vector "00"))))))))))

;;; --- Wallet P5 SIGNER role -----------------------------------------------

(defun %psbt-partial-sigs (psbt)
  "Per-input sorted list of (pubkey-hex . sig-hex) partial signatures — the
funds-critical signer output, compared independent of metadata ordering."
  (loop for m across (bl.ser:psbt-inputs psbt)
        collect (sort (loop for (pk . sig)
                              in (bl.ser:psbt-map-collect
                                  m bl.ser:+psbt-in-partial-sig+)
                            collect (cons (bl.crypto:bytes-to-hex pk)
                                          (bl.crypto:bytes-to-hex sig)))
                      #'string< :key #'car)))

(defun %psbt-sign-with-wifs (psbt wifs)
  "Drive the wallet-P5 signer core (%psbt-coins-map + %psbt-record-signatures)
over PSBT with the WIF privkeys, recording partial sigs in place. This is exactly
the machinery walletprocesspsbt/descriptorprocesspsbt use, minus wallet/descriptor
key resolution — so it validates the signing dispatch against Core's vectors."
  (let ((keymap (make-hash-table :test 'equalp))
        (pubmap (make-hash-table :test 'equalp))
        (tr-keymap (make-hash-table :test 'equalp)))
    (dolist (wif wifs)
      (multiple-value-bind (sk compressed) (bl.crypto:wif-to-private-key wif)
        (let ((pub (bl.crypto:derive-public-key sk :compressed compressed)))
          (setf (gethash (bl.crypto:hash160 pub) keymap) (cons sk pub))
          (setf (gethash pub pubmap) sk))
        (let ((qx (bl.interop:compute-tweaked-pubkey
                   (bl.crypto:derive-xonly-pubkey sk))))
          (when qx (setf (gethash qx tr-keymap) sk)))))
    (let ((coins (bl.wallet::%psbt-coins-map psbt)))
      (bl.wallet::%psbt-record-signatures psbt coins keymap pubmap tr-keymap nil))
    psbt))

(test psbt-signer-vectors
  "The wallet-P5 signer core reproduces Core's rpc_psbt.json SIGNER partial
signatures byte-for-byte (bip32-origin metadata comes from the wallet and is not
compared). NOTE: requires the vendored rpc_psbt.json — runs at integration."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (let ((n 0))
          (dolist (e (gethash "signer" data))
            (let ((got (%psbt-sign-with-wifs
                        (bl.ser:decode-psbt (gethash "psbt" e))
                        (gethash "privkeys" e)))
                  (exp (bl.ser:decode-psbt (gethash "result" e))))
              (is (equal (%psbt-partial-sigs got) (%psbt-partial-sigs exp))
                  "signer vector #~D partial signatures mismatch" n)
              (incf n)))
          (is (>= n 5) "expected the signer vectors, got ~D" n)))))

(defun %psbt-spending (spk value &key (utxo t))
  "A 1-in/1-out v2 PSBT spending an output of SPK worth VALUE, carried as the
input's witness_utxo -- the smallest PSBT the signer path acts on. Without
UTXO the input names no spent output at all, which is what Core's
PSBTInputSignedAndVerified rejects before it verifies anything."
  (let* ((prevout (bl.ser:make-outpoint
                   :hash (make-array 32 :element-type '(unsigned-byte 8)
                                        :initial-element #x11)
                   :index 0))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output prevout
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out
                                :value (- value 1000) :script-pubkey spk))
              :lock-time 0))
         (psbt (bl.ser:make-empty-psbt tx))
         (bb (bl.ser:make-byte-buf)))
    (when utxo
      (bl.ser:bb-write-tx-out
       bb (bl.ser:make-tx-out :value value :script-pubkey spk))
      (bl.ser:psbt-map-set
       (aref (bl.ser:psbt-inputs psbt) 0)
       bl.ser:+psbt-in-witness-utxo+
       (make-array 0 :element-type '(unsigned-byte 8))
       (bl.ser:bb-finish bb)))
    psbt))

(test psbt-multisig-records-a-signature-for-every-held-key
  "GA11 42a8a239. Core's SignStep calls CreateSig for EVERY key of a MULTISIG
and caps only the stack push (script/sign.cpp:669-688); CreateSig records each
one in sigdata.signatures and PSBTInput::FromSignatureData copies that whole
map into partial_sigs (psbt.cpp:178). So a 2-of-3 P2WSH input signed by a
holder of ALL THREE keys carries THREE PSBT_IN_PARTIAL_SIG records for the
next cosigner, not two -- which is the workflow the Core comment exists for.

The two-key row is the control that the count follows the KEYS HELD and not
the threshold: it answers 2 both before and after the collector changed."
  (let* ((sks (loop for i from 0 below 3
                    collect (make-array 32 :element-type '(unsigned-byte 8)
                                           :initial-element (+ 21 i))))
         (wifs (mapcar (lambda (sk) (bl.crypto:private-key-to-wif
                                     sk :network :regtest :compressed t))
                       sks))
         (pks (mapcar (lambda (sk) (bl.crypto:derive-public-key sk :compressed t))
                      sks))
         (witscript (multisig-script 2 pks))
         (spk (concatenate '(simple-array (unsigned-byte 8) (*))
                           #(#x00 #x20) (bl.crypto:sha256 witscript))))
    (flet ((records-for (signing-wifs)
             (let ((psbt (%psbt-spending spk 100000)))
               (bl.ser:psbt-map-set
                (aref (bl.ser:psbt-inputs psbt) 0)
                bl.ser:+psbt-in-witness-script+
                (make-array 0 :element-type '(unsigned-byte 8))
                witscript)
               (length (first (%psbt-partial-sigs
                               (%psbt-sign-with-wifs psbt signing-wifs)))))))
      (is (= 3 (records-for wifs)))
      (is (= 2 (records-for (list (first wifs) (second wifs))))))))

(defun %psbt-process-with-descriptors (node psbt descriptors)
  "The descriptorprocesspsbt RPC over a psbt struct."
  (bl.wallet::rpc-descriptorprocesspsbt
   node (list (bl.ser:encode-psbt psbt) descriptors)))

(test descriptorprocesspsbt-wpkh-hermetic
  "descriptorprocesspsbt signs a P2WPKH input from a wpkh(WIF) descriptor and the
PSBT's own witness_utxo, completing into a network tx whose witness verifies
under the consensus script verifier. Runs WITHOUT vendored vectors."
  (let* ((node (bl:make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (wif (bl.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (pub (bl.crypto:derive-public-key sk :compressed t))
         (pkh (bl.crypto:hash160 pub))
         (spk (concatenate '(simple-array (unsigned-byte 8) (*))
                           #(#x00 #x14) pkh))
         (value 100000)
         (psbt (%psbt-spending spk value)))
    (let* ((result (%psbt-process-with-descriptors
                    node psbt (list (format nil "wpkh(~A)" wif))))
           (hex (cdr (assoc "hex" result :test #'equal))))
      (is (eq t (cdr (assoc "complete" result :test #'equal))))
      (is (stringp hex))
      (let* ((tx2 (bl.ser:parse-tx-payload
                   (bl.crypto:hex-to-bytes hex)))
             (witnesses (bl.ser:transaction-witness tx2)))
        ;; Witness = <sig> <pubkey>.
        (is (= 2 (length (aref witnesses 0))))
        (is (equalp pub (second (aref witnesses 0))))
        ;; Consensus script verification of the signed input.
        (let* ((utxo (bl.store:make-utxo-entry :value value :script-pubkey spk))
               (spent (vector utxo))
               (bl.interop:*script-flags*
                 bl.val:+standard-script-verify-flags+)
               (bl.interop:*precomputed-sighash*
                 (bl.interop:init-precomputed-sighash tx2 spent))
               (bl.interop:*current-spent-utxos* spent))
          (is-true (bl.val:validate-input-script tx2 0 (aref spent 0))))))))

(test descriptorprocesspsbt-p2sh-p2pk-agrees-with-the-in-place-signer
  "%PSBT-FINALIZE has always carried a P2SH-P2PK and a P2SH-P2PKH arm, but
nothing could reach them: the per-input signer refused both redeemScript shapes
with \"unsupported redeemScript type\", so no partial signature was ever
recorded for one. With the signer's redeemScript recursion in place (Core
ProduceSignature, sign.cpp:743-752) the two halves have to agree, and this
compares them over the SAME transaction: descriptorprocesspsbt's finalized
scriptSigs must be the very bytes signrawtransactionwithkey's in-place
%FINALIZE-INPUT-SIGNATURES builds. Both paths sign with RFC6979, so a
difference is a difference in assembly, not in nonce.

descriptorprocesspsbt's complete is Core's PSBTInputSignedAndVerified, so a
true there is already the script verification of what it assembled.

The spent outputs are carried as NON_WITNESS_UTXO, which is what a legacy P2SH
input needs and what makes the signature a legacy one."
  (let* ((node (bl:make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9))
         (wif (bl.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (pub (bl.crypto:derive-public-key sk :compressed t))
         (pkh (bl.crypto:hash160 pub))
         (rd-pk (concatenate '(simple-array (unsigned-byte 8) (*))
                             (vector (length pub)) pub #(#xac)))
         (rd-pkh (concatenate '(simple-array (unsigned-byte 8) (*))
                              #(#x76 #xa9 #x14) pkh #(#x88 #xac)))
         (spk-sh-pk (concatenate '(simple-array (unsigned-byte 8) (*))
                                 #(#xa9 #x14) (bl.crypto:hash160 rd-pk) #(#x87)))
         (spk-sh-pkh (concatenate '(simple-array (unsigned-byte 8) (*))
                                  #(#xa9 #x14) (bl.crypto:hash160 rd-pkh) #(#x87)))
         (value 100000)
         (empty (make-array 0 :element-type '(unsigned-byte 8)))
         ;; The funding transaction, carried whole so its txid authenticates
         ;; both spent outputs (Core psbt.cpp:76-88 prefers NON_WITNESS_UTXO).
         (funding (bl.ser:make-transaction
                   :version 2
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output
                                    (bl.ser:make-outpoint
                                     :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element #x11)
                                     :index 0)
                                    :script-sig empty :sequence #xffffffff))
                   :outputs (vector (bl.ser:make-tx-out :value value :script-pubkey spk-sh-pk)
                                    (bl.ser:make-tx-out :value value :script-pubkey spk-sh-pkh))
                   :lock-time 0))
         (ftxid (bl.ser:transaction-hash funding))
         (spend (bl.ser:make-transaction
                 :version 2
                 :inputs (vector (bl.ser:make-tx-in
                                  :previous-output (bl.ser:make-outpoint :hash ftxid :index 0)
                                  :script-sig empty :sequence #xffffffff)
                                 (bl.ser:make-tx-in
                                  :previous-output (bl.ser:make-outpoint :hash ftxid :index 1)
                                  :script-sig empty :sequence #xffffffff))
                 :outputs (vector (bl.ser:make-tx-out :value (- (* 2 value) 1000)
                                                      :script-pubkey rd-pkh))
                 :lock-time 0))
         (psbt (bl.ser:make-empty-psbt spend)))
    ;; The Updater's half: each input's spent transaction and redeemScript.
    (loop for i below 2
          for rd in (list rd-pk rd-pkh)
          do (let ((map (aref (bl.ser:psbt-inputs psbt) i)))
               (bl.ser:psbt-map-set map bl.ser:+psbt-in-non-witness-utxo+ empty
                                    (bl.ser:transaction-wire-bytes funding))
               (bl.ser:psbt-map-set map bl.ser:+psbt-in-redeem-script+ empty rd)))
    (let* ((from-psbt (%psbt-process-with-descriptors
                       node psbt (list (format nil "sh(pk(~A))" wif)
                                       (format nil "sh(pkh(~A))" wif))))
           (in-place
             (bl.rpc:dispatch-rpc-method
              node "signrawtransactionwithkey"
              (list (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction spend))
                    (list wif)
                    (loop for i below 2
                          for spk in (list spk-sh-pk spk-sh-pkh)
                          for rd in (list rd-pk rd-pkh)
                          collect (list (cons "txid" (bl.rpc:hash-to-hex ftxid))
                                        (cons "vout" i)
                                        (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk))
                                        (cons "amount" 0.001d0)
                                        (cons "redeemScript" (bl.crypto:bytes-to-hex rd))))))))
      (flet ((aval (key alist) (cdr (assoc key alist :test #'equal))))
        (is (eq t (aval "complete" from-psbt))
            "descriptorprocesspsbt reported ~S" from-psbt)
        (is (eq t (aval "complete" in-place))
            "signrawtransactionwithkey reported ~S" (aval "errors" in-place))
        (let ((a (aval "hex" from-psbt))
              (b (aval "hex" in-place)))
          (is-true (and (stringp a) (stringp b)))
          (when (and (stringp a) (stringp b))
            (let ((ins-a (bl.ser:transaction-inputs
                          (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes a))))
                  (ins-b (bl.ser:transaction-inputs
                          (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes b)))))
              (dotimes (j 2)
                (is (equalp (bl.ser:tx-in-script-sig (aref ins-a j))
                            (bl.ser:tx-in-script-sig (aref ins-b j)))
                    "input ~D: the PSBT finalizer and the in-place signer ~
disagree" j))
              ;; And the shape is Core's, not merely a shared one: <sig>
              ;; <redeem> for P2SH-P2PK, <sig> <pubkey> <redeem> for P2SH-P2PKH.
              (let ((ss (bl.ser:tx-in-script-sig (aref ins-a 0))))
                (is (equalp rd-pk (subseq ss (- (length ss) (length rd-pk))))))
              (let ((ss (bl.ser:tx-in-script-sig (aref ins-a 1))))
                (is (equalp rd-pkh (subseq ss (- (length ss) (length rd-pkh)))))
                (is-true (search pub ss))))))))))

(test descriptorprocesspsbt-signs-a-multipath-branch
  "descriptorprocesspsbt reaches EVERY descriptor a BIP389 string denotes, as
Core's EvalDescriptorStringOrObject does (rpc/util.cpp:1352-1362). The PSBT here
spends the SECOND branch's output, so a signer that only ever saw descs.at(0)
cannot complete it -- and before the parser owned multipath, the string was
refused outright with -5 `Multipath descriptors are not supported', which is the
offline-signer half of the finding.

The descriptor is unranged on both branches (a fixed final index), so the whole
answer is the branch choice."
  (let* ((node (bl:make-node :network :regtest))
         (seed (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
         (root (bl.crypto:bip32-master-key seed :network :regtest))
         (tprv (bl.crypto:bip32-serialize root))
         (multi (format nil "wpkh(~A/<0;1>/0)" tprv))
         (branch-1 (format nil "wpkh(~A/1/0)" tprv))
         (spk (first (bl.rpc::out-desc-expand
                      (bl.rpc:parse-descriptor branch-1 :regtest) 0)))
         (value 100000))
    ;; The two branches are different scripts, or the test would prove nothing.
    (is-false (equalp spk (first (bl.rpc::out-desc-expand
                                  (bl.rpc:parse-descriptor
                                   (format nil "wpkh(~A/0/0)" tprv) :regtest)
                                  0))))
    (let* ((result (%psbt-process-with-descriptors
                    node (%psbt-spending spk value) (list multi)))
           (hex (cdr (assoc "hex" result :test #'equal))))
      (is (eq t (cdr (assoc "complete" result :test #'equal)))
          "descriptorprocesspsbt did not complete the second branch's input")
      (is (stringp hex))
      ;; And the witness it built verifies under the consensus verifier.
      (let* ((tx2 (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes hex)))
             (utxo (bl.store:make-utxo-entry :value value :script-pubkey spk))
             (spent (vector utxo))
             (bl.interop:*script-flags* bl.val:+standard-script-verify-flags+)
             (bl.interop:*precomputed-sighash*
               (bl.interop:init-precomputed-sighash tx2 spent))
             (bl.interop:*current-spent-utxos* spent))
        (is-true (bl.val:validate-input-script tx2 0 (aref spent 0)))))))

(defun %psbt-add-partial-sig (psbt pubkey sighash-byte)
  "Put a foreign 71-byte ECDSA partial signature ending in SIGHASH-BYTE on the
PSBT's first input, keyed by PUBKEY -- a co-signer's contribution, from our
side indistinguishable from any other."
  (let ((sig (make-array 71 :element-type '(unsigned-byte 8) :initial-element #x30)))
    (setf (aref sig 70) sighash-byte)
    (bl.ser:psbt-map-set (aref (bl.ser:psbt-inputs psbt) 0)
                         bl.ser:+psbt-in-partial-sig+ pubkey sig)
    psbt))

(defun %psbt-add-tap-key-sig (psbt length)
  "Put a taproot key-path signature of LENGTH bytes on the PSBT's first input."
  (bl.ser:psbt-map-set (aref (bl.ser:psbt-inputs psbt) 0)
                       bl.ser:+psbt-in-tap-key-sig+
                       (make-array 0 :element-type '(unsigned-byte 8))
                       (make-array length :element-type '(unsigned-byte 8)
                                          :initial-element 9))
  psbt)

(defun %psbt-signer-result-of (psbt verify)
  "The {psbt, complete, hex?} object the process RPCs build. VERIFY is what
separates walletprocesspsbt from descriptorprocesspsbt."
  (bl.wallet::%psbt-signer-result psbt t verify))

(defun %psbt-with-final-scriptsig (psbt bytes)
  "Put BYTES on the PSBT's first input as its final scriptSig, the way a
counterparty hands back an input it claims to have finished."
  (bl.ser:psbt-map-set (aref (bl.ser:psbt-inputs psbt) 0)
                       bl.ser:+psbt-in-final-scriptsig+
                       (make-array 0 :element-type '(unsigned-byte 8))
                       (coerce bytes '(simple-array (unsigned-byte 8) (*))))
  psbt)

(test psbt-complete-requires-the-scripts-to-verify
  "walletprocesspsbt reports complete as the AND of PSBTInputSignedAndVerified
(wallet.cpp:2231-2235), which resolves the spent output -- false outright when
neither utxo record is there -- and runs VerifyScript over the final
scriptSig/scriptWitness under the standard flags (psbt.cpp:325-355). Answering
complete from `the finalizer assembled something` hands the caller a hex to
broadcast that the node will reject. descriptorprocesspsbt keeps Core's weaker
PSBTInputSigned test (rawtransaction.cpp:2060-2063), so the two answers differ
on the same PSBT."
  (let* ((node (bl:make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (wif (bl.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (pub (bl.crypto:derive-public-key sk :compressed t))
         (value 100000)
         (spk (concatenate '(simple-array (unsigned-byte 8) (*))
                           #(#x00 #x14) (bl.crypto:hash160 pub)))
         (op-1 #(#x51)))
    (flet ((field (result name) (cdr (assoc name result :test #'equal))))
      ;; A garbage final scriptSig, on an input that names no spent output at
      ;; all: Core returns false on the missing-UTXO branch alone.
      (let* ((no-utxo (%psbt-with-final-scriptsig
                       (%psbt-spending spk value :utxo nil) op-1))
             (verified (%psbt-signer-result-of no-utxo t)))
        (is (eq bl.rpc:+json-false+ (field verified "complete")))
        (is (null (field verified "hex")))
        ;; Same PSBT, descriptorprocesspsbt's weaker test: the field is there.
        (is (eq t (field (%psbt-signer-result-of no-utxo nil) "complete"))))
      ;; With the utxo present, the garbage scriptSig still cannot spend it.
      (let ((bad (%psbt-with-final-scriptsig (%psbt-spending spk value) op-1)))
        (is (eq bl.rpc:+json-false+
                (field (%psbt-signer-result-of bad t) "complete"))))
      ;; Control: a PSBT our own signer finalized verifies, so complete stands
      ;; and the hex comes back.
      (let* ((signed (bl.ser:decode-psbt
                      (field (%psbt-process-with-descriptors
                              node (%psbt-spending spk value)
                              (list (format nil "wpkh(~A)" wif)))
                             "psbt")))
             (result (%psbt-signer-result-of signed t)))
        (is (eq t (field result "complete")))
        (is (stringp (field result "hex")))))))

(test psbt-signing-refuses-a-foreign-sighash
  "Core SignPSBTInput checks every signature already on the input against the
sighash it is about to sign with (psbt.cpp:459-475) and both drive sites turn
a mismatch into a thrown SIGHASH_MISMATCH -- ProcessPSBT explicitly
(rawtransaction.cpp:203-204), FillPSBT by returning it. Co-signing next to a
signature that commits to other fields would lose the only signal an operator
gets that the other participants are not signing the same transaction."
  (let* ((node (bl:make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (wif (bl.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (descs (list (format nil "wpkh(~A)" wif)))
         (pub (bl.crypto:derive-public-key sk :compressed t))
         (other (bl.crypto:derive-public-key
                 (make-array 32 :element-type '(unsigned-byte 8)
                                :initial-element 2)
                 :compressed t))
         (value 100000)
         (spk (concatenate '(simple-array (unsigned-byte 8) (*))
                           #(#x00 #x14) (bl.crypto:hash160 pub)))
         (taproot-spk (concatenate '(simple-array (unsigned-byte 8) (*))
                                   #(#x51 #x20)
                                   (make-array 32 :element-type '(unsigned-byte 8)
                                                  :initial-element 3))))
    ;; ECDSA: the effective sighash is ALL, so a co-signer's SIGHASH_NONE
    ;; (0x02) signature aborts the call.
    (signals-rpc-error (:code -22
                        :exact-message
                        "Specified sighash value does not match value stored in PSBT")
      (%psbt-process-with-descriptors
       node (%psbt-add-partial-sig (%psbt-spending spk value) other #x02)
       descs))
    ;; Control: the same PSBT with a SIGHASH_ALL co-signature is processed.
    (is-true (%psbt-process-with-descriptors
              node (%psbt-add-partial-sig (%psbt-spending spk value) other #x01)
              descs))
    ;; Taproot under SIGHASH_DEFAULT: a key-path signature must be a bare 64
    ;; bytes; 65 means it carries a sighash byte, i.e. another type.
    (signals-rpc-error (:code -22
                        :exact-message
                        "Specified sighash value does not match value stored in PSBT")
      (%psbt-process-with-descriptors
       node (%psbt-add-tap-key-sig (%psbt-spending taproot-spk value) 65)
       descs))
    (is-true (%psbt-process-with-descriptors
              node (%psbt-add-tap-key-sig (%psbt-spending taproot-spk value) 64)
              descs))
    ;; Core's !m_tap_key_sig.empty() guard on that check (psbt.cpp:459-475) is
    ;; about a field that was never PRESENT: a record carrying a ZERO-length
    ;; signature never reaches it, because the deserializer refuses anything
    ;; under 64 bytes first (psbt.h:699-701). This case used to assert the
    ;; opposite and was pinning a divergence.
    (signals-rpc-error (:code -22
                        :exact-message
                        "TX decode failed PSBT taproot signature must be 64 or 65 bytes")
      (%psbt-process-with-descriptors
       node (%psbt-add-tap-key-sig (%psbt-spending taproot-spk value) 0)
       descs))
    ;; The absent case, which is the one the guard is for: no record at all.
    (is-true (%psbt-process-with-descriptors
              node (%psbt-spending taproot-spk value) descs))))

(test psbt-createpsbt-defaults-and-validation
  "createpsbt sequence follows Core (replaceable default true -> RBF; explicit
false honors locktime), and duplicate outputs are rejected."
  (let* ((node (bl:make-node :network :regtest))
         (txid (make-string 64 :initial-element #\a))
         (in (list (list (cons "txid" txid) (cons "vout" 0))))
         (seq-of (lambda (params)
                   (bl.ser:tx-in-sequence
                    (aref (bl.ser:transaction-inputs
                           (bl.ser:psbt-tx
                            (bl.ser:decode-psbt
                             (%psbt-createpsbt node params))))
                          0)))))
    ;; default (no replaceable) -> RBF-signaling 0xfffffffd
    (is (= #xfffffffd (funcall seq-of (list in '()))))
    ;; null replaceable = Core default (true) -> RBF
    (is (= #xfffffffd (funcall seq-of (list in '() 0 nil))))
    ;; explicit replaceable=false, locktime 0 -> final 0xffffffff
    (is (= #xffffffff (funcall seq-of
                               (list in '() 0 bl.rpc:+json-false+))))
    ;; explicit replaceable=false, locktime>0 -> 0xfffffffe (locktime enforced)
    (is (= #xfffffffe (funcall seq-of
                               (list in '() 500000
                                     bl.rpc:+json-false+))))
    ;; duplicate output address is rejected
    (let ((addr (bl.crypto:encode-p2pkh-address
                 (make-array 20 :element-type '(unsigned-byte 8) :initial-element 5) :regtest)))
      (signals bl.rpc:rpc-error
        (%psbt-createpsbt
         node (list in (list (list (cons addr 0.1)) (list (cons addr 0.2)))))))))

;;;; BIP371 taproot fields in decodepsbt (rawtransaction.cpp:1253-1314)

(defun %tap-bytes (n fill)
  (make-array n :element-type '(unsigned-byte 8) :initial-element fill))

(defun %tap-record (keytype keydata value)
  (cons (concatenate '(vector (unsigned-byte 8)) (vector keytype) keydata) value))

(test decodepsbt-reports-bip371-taproot-fields
  "The PSBT layer stores raw records, so a taproot PSBT round-tripped correctly
already — what was missing was the ability to SEE it, which is what a signer's
user needs before tr() script-path signing means anything.

Every field name and shape here is Core's (decodepsbt,
rawtransaction.cpp:1253-1314)."
  (let* ((xonly (%tap-bytes 32 #xAA))
         (leaf-hash (%tap-bytes 32 #xBB))
         (sig (%tap-bytes 64 #xCC))
         (control (%tap-bytes 33 #xDD))
         (script (coerce #(#x51) '(vector (unsigned-byte 8))))
         ;; PSBT_IN_TAP_LEAF_SCRIPT's value is <script><1-byte leaf version>.
         (leaf-value (concatenate '(vector (unsigned-byte 8)) script (vector #xc0)))
         (map (bl.ser:make-psbt-map
               :records
               (list (%tap-record bl.ser:+psbt-in-tap-key-sig+
                                  #() sig)
                     ;; keydata is <xonly><leaf hash>
                     (%tap-record bl.ser:+psbt-in-tap-script-sig+
                                  (concatenate '(vector (unsigned-byte 8)) xonly leaf-hash)
                                  sig)
                     ;; keydata is the control block
                     (%tap-record bl.ser:+psbt-in-tap-leaf-script+
                                  control leaf-value)
                     (%tap-record bl.ser:+psbt-in-tap-internal-key+
                                  #() xonly)
                     (%tap-record bl.ser:+psbt-in-tap-merkle-root+
                                  #() leaf-hash)
                     ;; <count><leaf hashes><fingerprint><path>
                     (%tap-record bl.ser:+psbt-in-tap-bip32+
                                  xonly
                                  (concatenate '(vector (unsigned-byte 8))
                                               (vector 1) leaf-hash
                                               (vector 1 2 3 4)
                                               (vector 0 0 0 #x80))))))
         (json (bl.wallet::%psbt-input-json map :regtest)))
    (flet ((f (k) (cdr (assoc k json :test #'string=))))
      (is (equal (bl.crypto:bytes-to-hex sig) (f "taproot_key_path_sig")))
      (is (equal (bl.crypto:bytes-to-hex xonly) (f "taproot_internal_key")))
      (is (equal (bl.crypto:bytes-to-hex leaf-hash) (f "taproot_merkle_root")))
      ;; script-path sigs split the keydata into pubkey + leaf hash.
      (let ((sps (elt (f "taproot_script_path_sigs") 0)))
        (is (equal (bl.crypto:bytes-to-hex xonly)
                   (cdr (assoc "pubkey" sps :test #'string=))))
        (is (equal (bl.crypto:bytes-to-hex leaf-hash)
                   (cdr (assoc "leaf_hash" sps :test #'string=))))
        (is (equal (bl.crypto:bytes-to-hex sig)
                   (cdr (assoc "sig" sps :test #'string=)))))
      ;; taproot_scripts splits the VALUE into script + trailing leaf version,
      ;; and lists the control block from the KEYDATA.
      (let ((ts (elt (f "taproot_scripts") 0)))
        (is (equal (bl.crypto:bytes-to-hex script)
                   (cdr (assoc "script" ts :test #'string=))))
        (is (eql #xc0 (cdr (assoc "leaf_ver" ts :test #'string=))))
        (is (equal (bl.crypto:bytes-to-hex control)
                   (elt (cdr (assoc "control_blocks" ts :test #'string=)) 0))))
      ;; taproot_bip32_derivs carries the leaf hashes AND the ordinary
      ;; fingerprint/path, which is what distinguishes it from bip32_derivs.
      (let ((d (elt (f "taproot_bip32_derivs") 0)))
        (is (equal (bl.crypto:bytes-to-hex xonly)
                   (cdr (assoc "pubkey" d :test #'string=))))
        (is (equal "01020304" (cdr (assoc "master_fingerprint" d :test #'string=))))
        (is (equal "m/0'" (cdr (assoc "path" d :test #'string=))))
        (is (equal (bl.crypto:bytes-to-hex leaf-hash)
                   (elt (cdr (assoc "leaf_hashes" d :test #'string=)) 0)))))))

(test decodepsbt-reports-taproot-output-fields
  "PSBT_OUT_TAP_TREE is a run of (depth, leaf_ver, script) tuples, and Core
expands them into one {depth, leaf_ver, script} object each
(rpc/rawtransaction.cpp:1425-1437). This test used to pin the whole blob as a
hex string, a shape no Core client reads."
  (let* ((xonly (%tap-bytes 32 #x11))
         (tree (coerce #(0 #xc0 1 #x51) '(simple-array (unsigned-byte 8) (*))))
         (map (bl.ser:make-psbt-map
               :records
               (list (%tap-record bl.ser:+psbt-out-tap-internal-key+
                                  #() xonly)
                     (%tap-record bl.ser:+psbt-out-tap-tree+
                                  #() tree)
                     (%tap-record bl.ser:+psbt-out-tap-bip32+
                                  xonly
                                  (concatenate '(vector (unsigned-byte 8))
                                               (vector 0) (vector 9 9 9 9))))))
         (json (bl.wallet::%psbt-output-json map)))
    (flet ((f (k) (cdr (assoc k json :test #'string=))))
      (is (equal (bl.crypto:bytes-to-hex xonly) (f "taproot_internal_key")))
      (is (equal '((("depth" . 0) ("leaf_ver" . #xc0) ("script" . "51")))
                 (f "taproot_tree")))
      (let ((d (elt (f "taproot_bip32_derivs") 0)))
        (is (equal "09090909" (cdr (assoc "master_fingerprint" d :test #'string=))))
        ;; A zero leaf-hash count is legal: the key is used for key-path only.
        (is (zerop (length (cdr (assoc "leaf_hashes" d :test #'string=)))))))))

(test decodepsbt-reports-bip373-musig2-fields
  "BIP373's MuSig2 records, so a signer's user can SEE what a PSBT asks of them.

DECODING only. A MuSig2 signing session needs nonce state this node does not
keep, and inventing one would be worse than useless: reusing a nonce across two
messages leaks the private key outright.

⚠️ The keydata LENGTH is the discriminator between a key-path record (66 bytes:
participant + aggregate) and a script-path one (98: plus the leaf hash). A
reader that ignores it files every script-path nonce under the key path."
  (let* ((agg (%tap-bytes 33 #x02))
         (p1 (%tap-bytes 33 #x03))
         (p2 (%tap-bytes 33 #x04))
         (leaf-hash (%tap-bytes 32 #xEE))
         (nonce (%tap-bytes 66 #xAA))
         (psig (%tap-bytes 32 #xBB))
         (cat (lambda (&rest vs)
                (apply #'concatenate '(vector (unsigned-byte 8)) vs)))
         (map (bl.ser:make-psbt-map
               :records
               (list (%tap-record
                      bl.ser:+psbt-in-musig2-participant-pubkeys+
                      agg (funcall cat p1 p2))
                     ;; Key path: no leaf hash.
                     (%tap-record bl.ser:+psbt-in-musig2-pub-nonce+
                                  (funcall cat p1 agg) nonce)
                     ;; Script path: leaf hash present.
                     (%tap-record bl.ser:+psbt-in-musig2-partial-sig+
                                  (funcall cat p2 agg leaf-hash) psig)))))
    (let* ((json (bl.wallet::%psbt-input-json map :mainnet))
           (parts (cdr (assoc "musig2_participant_pubkeys" json :test #'string=)))
           (nonces (cdr (assoc "musig2_pubnonces" json :test #'string=)))
           (sigs (cdr (assoc "musig2_partial_sigs" json :test #'string=))))
      (is-true parts "no musig2_participant_pubkeys in ~S" (mapcar #'car json))
      (is-true nonces "no musig2_pubnonces")
      (is-true sigs "no musig2_partial_sigs")
      (when (and parts nonces sigs)
        (let ((entry (first (coerce parts 'list))))
          (is (string= (bl.crypto:bytes-to-hex agg)
                       (cdr (assoc "aggregate_pubkey" entry :test #'string=))))
          (is (= 2 (length (coerce (cdr (assoc "participant_pubkeys" entry
                                               :test #'string=))
                                   'list)))
              "the participant list did not split into two 33-byte keys"))
        ;; The key-path nonce has NO leaf hash; the script-path sig has one.
        (let ((n (first (coerce nonces 'list)))
              (sg (first (coerce sigs 'list))))
          (is-false (assoc "leaf_hash" n :test #'string=)
                    "a key-path nonce reported a leaf hash")
          (is (string= (bl.crypto:bytes-to-hex leaf-hash)
                       (cdr (assoc "leaf_hash" sg :test #'string=)))
              "the script-path partial sig lost its leaf hash"))))))

(test empty-input-array-reaches-psbt-creators-as-nil
  "An empty JSON array arrives as the +JSON-EMPTY-ARRAY+ SENTINEL, not as NIL,
so a handler can tell `[]' from a missing argument (server.lisp:349). Passing
the sentinel through reaches code that expects a LIST and surfaces as RPC
-32603 Internal error.

`createpsbt([], {...})' and `walletcreatefundedpsbt([], {...})' both did that,
and the latter is the FIRST call rpc_psbt.py makes — so the sentinel took the
whole test out before it asserted anything."
  (let* ((addr "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw")
         (outputs (%ht addr 1)))
    ;; The sentinel must behave exactly like an omitted/empty input list.
    (let ((with-sentinel
            (handler-case
                (%psbt-createpsbt
                 (make-test-node)
                 (list bl.rpc::+json-empty-array+ outputs))
              (error (e) (format nil "ERR: ~A" e))))
          (with-nil
            (handler-case
                (%psbt-createpsbt (make-test-node) (list nil outputs))
              (error (e) (format nil "ERR: ~A" e)))))
      (is-true (stringp with-sentinel)
               "createpsbt([]) raised instead of building: ~A" with-sentinel)
      (is (equal with-nil with-sentinel)
          "createpsbt([]) and createpsbt(null) disagree"))))

;;;; --- SignPSBTInput's require_witness_sig (GA11 left-out) ---------------------

(defun %psbt-funded-spending (spk value)
  "Like %PSBT-SPENDING, but the input carries BOTH a witness_utxo and the
non_witness_utxo that authenticates it (a funding transaction whose txid the
prevout names). With the full previous transaction present Core's SignPSBTInput
takes its prevout from it and require_witness_sig stays false (psbt.cpp:419-427),
so this is the control that a signature the witness-only shape refuses is one the
signer can produce."
  (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
         (funding (bl.ser:make-transaction
                   :version 2
                   :inputs (vector (bl.ser:make-tx-in
                                    :previous-output
                                    (bl.ser:make-outpoint
                                     :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                          :initial-element #x22)
                                     :index 0)
                                    :script-sig empty :sequence #xffffffff))
                   :outputs (vector (bl.ser:make-tx-out :value value :script-pubkey spk))
                   :lock-time 0))
         (spend (bl.ser:make-transaction
                 :version 2
                 :inputs (vector (bl.ser:make-tx-in
                                  :previous-output
                                  (bl.ser:make-outpoint
                                   :hash (bl.ser:transaction-hash funding) :index 0)
                                  :script-sig empty :sequence #xffffffff))
                 :outputs (vector (bl.ser:make-tx-out
                                   :value (- value 1000) :script-pubkey spk))
                 :lock-time 0))
         (psbt (bl.ser:make-empty-psbt spend))
         (map (aref (bl.ser:psbt-inputs psbt) 0))
         (bb (bl.ser:make-byte-buf)))
    (bl.ser:bb-write-tx-out bb (bl.ser:make-tx-out :value value :script-pubkey spk))
    (bl.ser:psbt-map-set map bl.ser:+psbt-in-witness-utxo+ empty (bl.ser:bb-finish bb))
    (bl.ser:psbt-map-set map bl.ser:+psbt-in-non-witness-utxo+ empty
                         (bl.ser:transaction-wire-bytes funding))
    psbt))

(test descriptorprocesspsbt-refuses-a-legacy-signature-over-the-witness-utxo-alone
  "Core SignPSBTInput's require_witness_sig (psbt.cpp:428-435, :488): an input
whose only prevout source is the witness_utxo cannot authenticate a NON-witness
spend, so a legacy signature over it is refused (PSBTError::INCOMPLETE) and no
partial signature is recorded. This is the positive control for the predicate
that decides which signatures are witness ones: a P2PKH input carried by its
witness_utxo alone must stay unsigned, and the same input with the
non_witness_utxo attached must sign -- so the refusal is the gate, not the
signer."
  (let* ((node (bl:make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 33))
         (wif (bl.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (pub (bl.crypto:derive-public-key sk :compressed t))
         (spk (concatenate '(simple-array (unsigned-byte 8) (*))
                           #(#x76 #xa9 #x14) (bl.crypto:hash160 pub) #(#x88 #xac)))
         (descriptors (list (format nil "pkh(~A)" wif))))
    (let ((refused (%psbt-process-with-descriptors node (%psbt-spending spk 100000)
                                                   descriptors)))
      (is (eq yason:false (cdr (assoc "complete" refused :test #'equal)))
          "a legacy signature over the witness_utxo alone was accepted")
      (is (null (first (%psbt-partial-sigs
                        (bl.ser:decode-psbt (cdr (assoc "psbt" refused :test #'equal))))))
          "a partial signature was recorded for the refused legacy input"))
    (let ((signed (%psbt-process-with-descriptors node (%psbt-funded-spending spk 100000)
                                                  descriptors)))
      (is (eq t (cdr (assoc "complete" signed :test #'equal)))
          "control: the same P2PKH input does not sign with its non_witness_utxo"))))

;;; INPUT-SIG-WITNESS-P over a bare signature of KIND.
(defun %input-sig-kind-witness-p (kind)
  (bl.rpc:input-sig-witness-p (bl.rpc::%make-input-sig :kind kind)))

(test input-sig-witness-p-answers-for-every-kind
  "INPUT-SIG-WITNESS-P is an ECASE over the whole kind vocabulary
COMPUTE-INPUT-SIGNATURES produces, so a kind it does not know signals rather
than passing as a legacy signature. The partition is Core's: every kind whose
solution ProduceSignature marks sigdata.witness (script/sign.cpp:757-789) is
true, the six legacy shapes false, and the three kinds the hand-written list
left out -- the taproot script path and both miniscript wrappings -- are
witness ones."
  (flet ((witness-p (kind) (%input-sig-kind-witness-p kind)))
    (dolist (kind '(:p2pk :p2pkh :p2sh-p2pk :p2sh-p2pkh :multisig :p2sh-multisig))
      (is-false (witness-p kind) "~S is a legacy kind" kind))
    (dolist (kind '(:p2wpkh :p2sh-p2wpkh :p2wsh :p2sh-p2wsh :p2tr
                    :p2tr-script :p2wsh-miniscript :p2sh-p2wsh-miniscript))
      (is-true (witness-p kind) "~S is a witness kind" kind))
    (signals error (witness-p :not-a-kind))))

;;; The kinds COMPUTE-INPUT-SIGNATURES can build, read off its source: every
;;; keyword in the :KIND argument of a %MAKE-INPUT-SIG call in the file.
(defun %input-sig-kinds-in-source ()
  (let ((kinds '())
        (path (asdf:system-relative-pathname "bitcoin-lisp"
                                             "src/rpc/rawtransaction.lisp")))
    (labels ((keywords (form)
               (cond ((keywordp form) (pushnew form kinds))
                     ((consp form) (keywords (car form)) (keywords (cdr form)))))
             (walk (form)
               (when (consp form)
                 (when (and (symbolp (car form))
                            (string= (symbol-name (car form)) "%MAKE-INPUT-SIG"))
                   (loop for (key value) on (cdr form) by #'cddr
                         when (eq key :kind) do (keywords value)))
                 (loop for tail on form
                       while (consp tail)
                       do (walk (car tail))))))
      (with-open-file (in path)
        (let ((*package* (find-package :bl.rpc)))
          (loop for form = (read in nil in)
                until (eq form in)
                do (walk form)))))
    kinds))

(test input-sig-witness-p-covers-every-kind-the-signer-builds
  "Every kind COMPUTE-INPUT-SIGNATURES builds has an answer in
INPUT-SIG-WITNESS-P, read off the signer's own source so a new kind cannot be
left out of the ECASE unnoticed. :ANCHOR was: the P2A arm (Core SignStep
answers TxoutType::ANCHOR with an empty solution, script/sign.cpp:706-707)
builds an :ANCHOR sig, and the ECASE signalled on it, so descriptorprocesspsbt
over a PSBT holding a P2A input carried by its witness_utxo died with a case
failure. Core leaves sigdata.witness false for ANCHOR (none of the witness
branches at sign.cpp:757-789 names it) and SignPSBTInput answers INCOMPLETE
for it (psbt.cpp:488): the call succeeds and that input stays unsigned."
  (let ((kinds (%input-sig-kinds-in-source)))
    ;; Positive control: the sweep finds the signer's kinds, legacy and witness.
    (is-true (member :p2pkh kinds))
    (is-true (member :p2tr-script kinds))
    (is-true (member :anchor kinds))
    (dolist (kind kinds)
      (is (eq :answered
              (handler-case
                  (progn (%input-sig-kind-witness-p kind) :answered)
                (error () :signalled)))
          "INPUT-SIG-WITNESS-P has no answer for the signer's kind ~S" kind)))
  (is-false (handler-case (%input-sig-kind-witness-p :anchor)
              (error () :signalled))
            "an anchor is not a witness signature (sign.cpp:706-707, :757-789)")
  ;; End to end: a P2A input known only by its witness_utxo leaves the call
  ;; standing and the PSBT incomplete.
  (let* ((node (bl:make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 34))
         (wif (bl.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (p2a (coerce #(#x51 #x02 #x4e #x73) '(simple-array (unsigned-byte 8) (*))))
         (result (handler-case
                     (%psbt-process-with-descriptors
                      node (%psbt-spending p2a 240)
                      (list (format nil "wpkh(~A)" wif)))
                   (error (e) (princ-to-string e)))))
    (is (listp result) "descriptorprocesspsbt over a P2A input signalled: ~A" result)
    (when (listp result)
      (is (eq yason:false (cdr (assoc "complete" result :test #'equal)))))))

(test psbt-process-without-finalize-reports-the-psbt-it-returns
  "Core's two process RPCs read `complete' -- and the optional `hex' it gates
-- off the PSBT THEY RETURN. walletprocesspsbt computes it in FillPSBT over
psbtx itself (wallet.cpp:2231-2235) and descriptorprocesspsbt over psbtx in
its own loop (rawtransaction.cpp:2051-2071); both predicates start at
PSBTInputSigned, which asks for a final_scriptSig or final_scriptWitness
(psbt.cpp:320-323). With finalize=false the returned PSBT has neither, so
complete is false and the `hex' key is absent:

    processed_psbt = self.nodes[0].walletprocesspsbt(psbt=psbtx, finalize=False)
    assert \"hex\" not in processed_psbt            (rpc_psbt.py:480-481)

We answered from a finalized COPY, so an unfinalized PSBT came back with
complete=true and a hex -- a network transaction the returned PSBT cannot
produce. The caller's route to that hex is finalizepsbt, which is what
rpc_psbt.py:485 then calls, and it gives the same bytes."
  (let* ((node (bl:make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (wif (bl.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (pub (bl.crypto:derive-public-key sk :compressed t))
         (value 100000)
         (spk (concatenate '(simple-array (unsigned-byte 8) (*))
                           #(#x00 #x14) (bl.crypto:hash160 pub)))
         (descriptors (list (format nil "wpkh(~A)" wif))))
    (flet ((field (result name) (cdr (assoc name result :test #'equal)))
           (process (finalize)
             (bl.rpc:dispatch-rpc-method
              node "descriptorprocesspsbt"
              (wire-params
               (list (bl.ser:encode-psbt (%psbt-spending spk value))
                     descriptors nil t finalize)))))
      ;; Control: finalize=true completes and hands back the network tx.
      (let ((finalized (process t)))
        (is (eq t (field finalized "complete")))
        (is (stringp (field finalized "hex")))
        ;; finalize=false signs the same input and stops there.
        (let ((unfinalized (process bl.rpc:+json-false+)))
          (is (eq bl.rpc:+json-false+ (field unfinalized "complete"))
              "an unfinalized PSBT is not complete")
          (is (null (field unfinalized "hex"))
              "an unfinalized PSBT must carry no hex; got ~S"
              (field unfinalized "hex"))
          ;; It is signed, though: finalizepsbt turns it into the same bytes
          ;; the finalize=true call produced (rpc_psbt.py:485-493).
          (let ((final (bl.rpc:dispatch-rpc-method
                        node "finalizepsbt"
                        (wire-params (list (field unfinalized "psbt"))))))
            (is (eq t (field final "complete")))
            (is (equal (field finalized "hex") (field final "hex")))))))))

(test a-psbt-argument-that-is-not-one-is-cores-tx-decode-failed
  "Every RPC that takes a PSBT answers RPC_DESERIALIZATION_ERROR -22 with the
message \"TX decode failed <error>\" -- Core strprintfs that pair at each of
its DecodeBase64PSBT call sites (rpc/rawtransaction.cpp:1066-1067, :1593-1594,
:1930-1931 and wallet/rpc/spend.cpp:1618-1620), and the error is
DecodeBase64PSBT's own (psbt.cpp:607-616).

The case that pins it is a RAW TRANSACTION hex handed to walletprocesspsbt:
hex digits are legal base64, so the bytes decode and fail the PSBT magic
(rpc_psbt.py:668). We answered \"psbt decode failed: ...\", a sentence no Core
client can match."
  (with-wallet-chain-node (node "psbt-decode-arg" :wallet "w")
    (let ((rawtx (one-input-tx-hex (make-string 64 :initial-element #\4) 0
                                   (bl.crypto:hex-to-bytes "6a0474657374"))))
      (dolist (method '("decodepsbt" "analyzepsbt" "finalizepsbt"
                        "walletprocesspsbt"))
        (let ((answer (rpc-error-of
                       (lambda ()
                         (bl.rpc:dispatch-rpc-method node method (list rawtx))))))
          (is (equal -22 (car answer))
              "~A: expected -22, got ~S" method answer)
          (is (eql 0 (search "TX decode failed" (or (cdr answer) "")))
              "~A: expected Core's prefix, got ~S" method (cdr answer))))
      ;; Not-base64 at all takes the same route, with the same prefix.
      (let ((answer (rpc-error-of
                     (lambda ()
                       (bl.rpc:dispatch-rpc-method node "decodepsbt"
                                                   (list "not a psbt!!!"))))))
        (is (equal -22 (car answer)))
        (is (eql 0 (search "TX decode failed" (or (cdr answer) ""))))))))

(test walletprocesspsbt-updates-a-private-keys-disabled-wallet
  "Core gates walletprocesspsbt on the passphrase and on nothing else: `if
(sign) EnsureWalletIsUnlocked(*pwallet);' is the whole precondition
(wallet/rpc/spend.cpp:1625-1633). A private-keys-disabled wallet is a
legitimate caller -- it is the UPDATER half of the watch-only/offline split --
and FillPSBT simply signs nothing, because its SPKMs hold no keys.

We refused it with -4 \"Private keys are disabled for this wallet\" whenever
`sign' was true, which is the DEFAULT, so the watch-only wallet could not be
asked to fill in a PSBT at all."
  (with-wallet-chain-node (node "psbt-watchonly" :wallet "w")
    (let* ((psbt (bl.rpc:dispatch-rpc-method
                  node "createpsbt"
                  (list (wire-params
                         (list (let ((h (make-hash-table :test 'equal)))
                                 (setf (gethash "txid" h)
                                       (make-string 64 :initial-element #\1)
                                       (gethash "vout" h) 0)
                                 h)))
                        (wire-params
                         (list (let ((h (make-hash-table :test 'equal)))
                                 (setf (gethash (bl.rpc:dispatch-rpc-method
                                                 node "getnewaddress" '())
                                                h)
                                       0.001d0)
                                 h)))))))
      (bl.rpc:dispatch-rpc-method node "createwallet" (list "watch" t))
      (let ((bl.wallet::*rpc-wallet-name* "watch"))
        ;; sign defaults to TRUE; the answer is an updated PSBT, not a refusal.
        (let ((result (bl.rpc:dispatch-rpc-method node "walletprocesspsbt"
                                                  (list psbt))))
          (is (stringp (cdr (assoc "psbt" result :test #'string=))))
          (is (eq bl.rpc:+json-false+ (cdr (assoc "complete" result :test #'string=))))))))) 

(test bumpfee-options-are-cores-closed-set
  "bumpfee / psbtbumpfee run Core's RPCTypeCheckObj over their option block
with fAllowNull AND fStrict (wallet/rpc/spend.cpp:1049-1059), so a key that is
not one of the seven Core declares is -3 \"Unexpected key <k>\".

totalFee and feeRate are the two this exists for: both were bumpfee options
once and both were REMOVED, so a caller still passing one would otherwise have
it silently ignored and the transaction bumped by something else entirely
(wallet_bumpfee.py:126)."
  (with-wallet-chain-node (node "bumpfee-opts" :wallet "w")
    (let ((txid (make-string 64 :initial-element #\0)))
      (flet ((bump (method options)
               (rpc-error-of
                (lambda ()
                  (bl.rpc:dispatch-rpc-method
                   node method
                   (wire-params (list txid options)))))))
        (dolist (method '("bumpfee" "psbtbumpfee"))
          (dolist (key '("totalFee" "feeRate"))
            (let* ((options (let ((h (make-hash-table :test 'equal)))
                              (setf (gethash key h) 1000) h))
                   (answer (bump method options)))
              (is (equal -3 (car answer))
                  "~A ~A: expected -3, got ~S" method key answer)
              (is (string= (format nil "Unexpected key ~A" key) (or (cdr answer) ""))
                  "~A ~A: got ~S" method key (cdr answer)))))
        ;; Control: a key Core DOES declare is not refused here -- the call
        ;; fails later, on the txid, which is the -5/-8 of a wallet that has
        ;; never seen that transaction.
        (let* ((options (let ((h (make-hash-table :test 'equal)))
                          (setf (gethash "fee_rate" h) 10) h))
               (answer (bump "bumpfee" options)))
          (is (not (equal -3 (car answer)))
              "fee_rate must not be refused as an unexpected key: ~S" answer))
        ;; And a declared key of the WRONG type is Core's typed sentence, not
        ;; the unexpected-key one.
        (let* ((options (let ((h (make-hash-table :test 'equal)))
                          (setf (gethash "estimate_mode" h) 42) h))
               (answer (bump "bumpfee" options)))
          (is (equal -3 (car answer)))
          (is (search "is not of expected type string" (or (cdr answer) ""))
              "got ~S" (cdr answer)))))))

(test bumpfee-refuses-both-spellings-of-the-confirmation-target
  "confTarget and conf_target are the SAME bumpfee option under two spellings,
and Core refuses a call that sets both (wallet/rpc/spend.cpp:1062-1063), right
after the option block's RPCTypeCheckObj and before anything reads a target.
It matters because the deprecated spelling is the one Core takes when only it
is given (:1066), so a caller that sets both has stated two different targets
and cannot be told which one was used.

We read them as (or conf_target confTarget) with no refusal, so
bumpfee(txid, {confTarget: 123, conf_target: 456}) silently bumped at 456 --
wallet_bumpfee.py:162 asserts Core's -8 instead.

The two controls are each spelling ALONE: both must still reach the txid, so a
change that simply refused any call carrying confTarget would fail them."
  (with-wallet-chain-node (node "bumpfee-alias" :wallet "w")
    (let ((txid (make-string 64 :initial-element #\0)))
      (flet ((bump (method &rest kvs)
               (rpc-error-of
                (lambda ()
                  (bl.rpc:dispatch-rpc-method
                   node method
                   (wire-params
                    (list txid
                          (let ((h (make-hash-table :test 'equal)))
                            (loop for (k v) on kvs by #'cddr
                                  do (setf (gethash k h) v))
                            h))))))))
        (dolist (method '("bumpfee" "psbtbumpfee"))
          (let ((answer (bump method "confTarget" 123 "conf_target" 456)))
            (is (equal -8 (car answer))
                "~A: expected -8, got ~S" method answer)
            (is (string= "confTarget and conf_target options should not both be set. Use conf_target (confTarget is deprecated)."
                         (or (cdr answer) ""))
                "~A: got ~S" method (cdr answer))))
        ;; Controls: one spelling at a time is a legal call, so the answer
        ;; comes from the txid this wallet has never seen -- never the
        ;; sentence above.
        (dolist (key '("confTarget" "conf_target"))
          (let ((answer (bump "bumpfee" key 123)))
            (is (not (search "should not both be set" (or (cdr answer) "")))
                "~A alone must not be refused as a conflict: ~S" key answer)))))))

(test bumpfee-refuses-an-empty-outputs-array
  "bumpfee / psbtbumpfee: an `outputs' option given as [] is Core's -8
\"Invalid parameter, output argument cannot be an empty array\"
(wallet/rpc/spend.cpp:1073-1077), while outputs: null is simply not given.
A nested [] reaches a handler as NIL, the same as null, so the check never
fired and wallet_bumpfee.py:175 got no error at all. The request is parsed
from its JSON text here, because that is the only place the two differ."
  (with-wallet-chain-node (node "bumpfee-empty-outputs" :wallet "w")
    (flet ((bump (method outputs-json)
             (multiple-value-bind (kind m params)
                 (bl.rpc:parse-json-rpc-request
                  (format nil "{\"method\":\"~A\",\"params\":[\"~A\",{\"outputs\":~A}]}"
                          method (make-string 64 :initial-element #\0) outputs-json))
               (declare (ignore kind m))
               (rpc-error-of
                (lambda () (bl.rpc:dispatch-rpc-method node method params))))))
      (dolist (method '("bumpfee" "psbtbumpfee"))
        (let ((answer (bump method "[]")))
          (is (equal -8 (car answer)) "~A outputs []: ~S" method answer)
          (is (equal "Invalid parameter, output argument cannot be an empty array"
                     (cdr answer))
              "~A outputs []: ~S" method answer))
        ;; Control: null is absent, and the call goes on to fail on the txid.
        (let ((answer (bump method "null")))
          (is (not (equal "Invalid parameter, output argument cannot be an empty array"
                          (cdr answer)))
              "~A outputs null must not be the empty-array refusal: ~S"
              method answer))))))

(test walletprocesspsbt-answers-cores-signer-vectors-byte-for-byte
  "rpc_psbt.py:830-836 imports each signer vector's keys as combo()
descriptors and compares walletprocesspsbt's PSBT with Core's own bytes.
Core never writes the records it read: it parses them into typed fields and
writes those back in a fixed order, each keyed field in its container's order
(PSBTInput::Serialize, psbt.h:302-462) -- so a new partial signature (a
std::map<CKeyID, ...>) lands right after the utxos, before the sighash and the
scripts. We appended it after the bip32 derivations, and four of the six
vectors came back with the right records in the wrong order."
  (let ((data (%psbt-vectors)))
    (if (null data)
        (skip "refs/bitcoin rpc_psbt.json not present")
        (with-wallet-chain-node (node "signer-bytes")
          (flet ((rpc (wallet method &rest params)
                   (with-rpc-wallet (wallet)
                     (bl.rpc:dispatch-rpc-method node method params))))
            (loop for e in (gethash "signer" data)
                  for i from 0
                  do (let ((name (format nil "w~D" i)))
                       (rpc nil "createwallet" name)
                       (dolist (k (gethash "privkeys" e))
                         (let ((h (make-hash-table :test 'equal)))
                           (setf (gethash "desc" h)
                                 (bl.rpc:descriptor-add-checksum (format nil "combo(~A)" k))
                                 (gethash "timestamp" h) "now")
                           (rpc name "importdescriptors" (list h))))
                       (is (equal (gethash "result" e)
                                  (%aval "psbt" (rpc name "walletprocesspsbt"
                                                     (gethash "psbt" e) t "ALL")))
                           "signer vector #~D" i))))))))

(test bumpfee-original-change-index-out-of-range-is-cores-misc-error
  "original_change_index is read with getInt<uint32_t>
(wallet/rpc/spend.cpp:1083-1085). A number that is no whole uint32 makes
UniValue throw a plain std::runtime_error, which the server answers -1 \"JSON
integer out of range\" (univalue.h:138-149, rpc/server.cpp:512-515);
wallet_bumpfee.py:183 passes -1 and we answered -3 \"JSON value of type number
is not of expected type number\". A string stays the -3 type error (the
control)."
  (with-wallet-chain-node (node "bumpfee-change-index" :wallet "w")
    (let ((txid (make-string 64 :initial-element #\0)))
      (flet ((bump (value)
               (rpc-error-of
                (lambda ()
                  (bl.rpc:dispatch-rpc-method
                   node "bumpfee"
                   (wire-params (list txid (let ((h (make-hash-table :test 'equal)))
                                             (setf (gethash "original_change_index" h) value)
                                             h))))))))
        (is (equal '(-1 . "JSON integer out of range") (bump -1)))
        (is (equal '(-1 . "JSON integer out of range") (bump (expt 2 32))))
        (is (equal -3 (car (bump "x"))))))))
