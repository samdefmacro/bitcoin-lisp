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
                   (psbt (bl.ser:parse-psbt raw))
                   (out (bl.ser:serialize-psbt psbt)))
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
                      (progn (bl.ser:parse-psbt (%psbt-b64->bytes b64))
                             nil)
                    (error () t))
              (incf rejected)))
          ;; 30/41: structural + v0 field-content checks. The rest are BIP371
          ;; taproot / BIP327 musig deep field-length checks we don't implement.
          (is (>= rejected 30)
              "expected to reject most invalid PSBTs, got ~D/~D" rejected total)))))

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

(test combinerawtransaction-merges
  "combinerawtransaction keeps the most-complete scriptSig per input."
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
         (empty  (funcall mk (make-array 0 :element-type '(unsigned-byte 8))))
         (combined (bl.wallet::rpc-combinerawtransaction node (list (list empty signed))))
         (tx (bl.ser:br-read-transaction
              (bl.ser:make-byte-reader-from
               (coerce (bl.crypto:hex-to-bytes combined)
                       '(simple-array (unsigned-byte 8) (*)))))))
    (is (= 5 (length (bl.ser:tx-in-script-sig
                      (aref (bl.ser:transaction-inputs tx) 0)))))))

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
    ;; An EMPTY key-signature record is absent, not a zero-length signature:
    ;; Core guards the check with !m_tap_key_sig.empty().
    (is-true (%psbt-process-with-descriptors
              node (%psbt-add-tap-key-sig (%psbt-spending taproot-spk value) 0)
              descs))))

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
  "PSBT_OUT_TAP_TREE is one opaque blob of (depth, leaf_ver, script) tuples;
Core reports it as hex rather than expanding it, so we do the same rather than
inventing a shape a client would not recognise."
  (let* ((xonly (%tap-bytes 32 #x11))
         (tree (%tap-bytes 8 #x22))
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
      (is (equal (bl.crypto:bytes-to-hex tree) (f "taproot_tree")))
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
