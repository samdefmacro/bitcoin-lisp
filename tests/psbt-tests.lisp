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
               ;; Core's rpc_psbt.py generates this vector with replaceable=False
               ;; (explicit false = the +json-false+ sentinel; a null would
               ;; take Core's default true and signal RBF).
               (out (bitcoin-lisp.rpc::rpc-createpsbt
                     node (list (gethash "inputs" c) (gethash "outputs" c) 0
                                bitcoin-lisp.rpc:+json-false+))))
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
               (out (bitcoin-lisp.rpc::rpc-finalizepsbt
                     node (list (gethash "finalize" f)
                                bitcoin-lisp.rpc:+json-false+)))
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

;;; --- Wallet P5 SIGNER role -----------------------------------------------

(defun %psbt-partial-sigs (psbt)
  "Per-input sorted list of (pubkey-hex . sig-hex) partial signatures — the
funds-critical signer output, compared independent of metadata ordering."
  (loop for m across (bitcoin-lisp.serialization:psbt-inputs psbt)
        collect (sort (loop for (pk . sig)
                              in (bitcoin-lisp.serialization:psbt-map-collect
                                  m bitcoin-lisp.serialization:+psbt-in-partial-sig+)
                            collect (cons (bitcoin-lisp.crypto:bytes-to-hex pk)
                                          (bitcoin-lisp.crypto:bytes-to-hex sig)))
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
      (multiple-value-bind (sk compressed) (bitcoin-lisp.crypto:wif-to-private-key wif)
        (let ((pub (bitcoin-lisp.crypto:derive-public-key sk :compressed compressed)))
          (setf (gethash (bitcoin-lisp.crypto:hash160 pub) keymap) (cons sk pub))
          (setf (gethash pub pubmap) sk))
        (let ((qx (bitcoin-lisp.coalton.interop:compute-tweaked-pubkey
                   (bitcoin-lisp.crypto:derive-xonly-pubkey sk))))
          (when qx (setf (gethash qx tr-keymap) sk)))))
    (let ((coins (bitcoin-lisp.rpc::%psbt-coins-map psbt)))
      (bitcoin-lisp.rpc::%psbt-record-signatures psbt coins keymap pubmap tr-keymap nil))
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
                        (bitcoin-lisp.serialization:decode-psbt (gethash "psbt" e))
                        (gethash "privkeys" e)))
                  (exp (bitcoin-lisp.serialization:decode-psbt (gethash "result" e))))
              (is (equal (%psbt-partial-sigs got) (%psbt-partial-sigs exp))
                  "signer vector #~D partial signatures mismatch" n)
              (incf n)))
          (is (>= n 5) "expected the signer vectors, got ~D" n)))))

(test descriptorprocesspsbt-wpkh-hermetic
  "descriptorprocesspsbt signs a P2WPKH input from a wpkh(WIF) descriptor and the
PSBT's own witness_utxo, completing into a network tx whose witness verifies
under the consensus script verifier. Runs WITHOUT vendored vectors."
  (let* ((node (bitcoin-lisp::make-node :network :regtest))
         (sk (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (wif (bitcoin-lisp.crypto:private-key-to-wif sk :network :regtest :compressed t))
         (pub (bitcoin-lisp.crypto:derive-public-key sk :compressed t))
         (pkh (bitcoin-lisp.crypto:hash160 pub))
         (spk (concatenate '(simple-array (unsigned-byte 8) (*))
                           #(#x00 #x14) pkh))
         (value 100000)
         (prevout (bitcoin-lisp.serialization:make-outpoint
                   :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element #x11)
                   :index 0))
         (tx (bitcoin-lisp.serialization:make-transaction
              :version 2
              :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                               :previous-output prevout
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                :value (- value 1000) :script-pubkey spk))
              :lock-time 0))
         (psbt (bitcoin-lisp.serialization:make-empty-psbt tx)))
    ;; Provide the input's witness_utxo directly in the PSBT.
    (let ((bb (bitcoin-lisp.serialization:make-byte-buf)))
      (bitcoin-lisp.serialization:bb-write-tx-out
       bb (bitcoin-lisp.serialization:make-tx-out :value value :script-pubkey spk))
      (bitcoin-lisp.serialization:psbt-map-set
       (aref (bitcoin-lisp.serialization:psbt-inputs psbt) 0)
       bitcoin-lisp.serialization:+psbt-in-witness-utxo+
       (make-array 0 :element-type '(unsigned-byte 8))
       (bitcoin-lisp.serialization:bb-finish bb)))
    (let* ((b64 (bitcoin-lisp.serialization:encode-psbt psbt))
           (result (bitcoin-lisp.rpc::rpc-descriptorprocesspsbt
                    node (list b64 (list (format nil "wpkh(~A)" wif)))))
           (hex (cdr (assoc "hex" result :test #'equal))))
      (is (eq t (cdr (assoc "complete" result :test #'equal))))
      (is (stringp hex))
      (let* ((tx2 (bitcoin-lisp.serialization:parse-tx-payload
                   (bitcoin-lisp.crypto:hex-to-bytes hex)))
             (witnesses (bitcoin-lisp.serialization:transaction-witness tx2)))
        ;; Witness = <sig> <pubkey>.
        (is (= 2 (length (aref witnesses 0))))
        (is (equalp pub (second (aref witnesses 0))))
        ;; Consensus script verification of the signed input.
        (let* ((utxo (bitcoin-lisp.storage:make-utxo-entry :value value :script-pubkey spk))
               (spent (vector utxo))
               (bitcoin-lisp.coalton.interop:*script-flags*
                 bitcoin-lisp.validation:+standard-script-verify-flags+)
               (bitcoin-lisp.coalton.interop:*precomputed-sighash*
                 (bitcoin-lisp.coalton.interop:init-precomputed-sighash tx2 spent))
               (bitcoin-lisp.coalton.interop:*current-spent-utxos* spent))
          (is-true (bitcoin-lisp.validation:validate-input-script tx2 0 (aref spent 0))))))))

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
    ;; null replaceable = Core default (true) -> RBF
    (is (= #xfffffffd (funcall seq-of (list in '() 0 nil))))
    ;; explicit replaceable=false, locktime 0 -> final 0xffffffff
    (is (= #xffffffff (funcall seq-of
                               (list in '() 0 bitcoin-lisp.rpc:+json-false+))))
    ;; explicit replaceable=false, locktime>0 -> 0xfffffffe (locktime enforced)
    (is (= #xfffffffe (funcall seq-of
                               (list in '() 500000
                                     bitcoin-lisp.rpc:+json-false+))))
    ;; duplicate output address is rejected
    (let ((addr (bitcoin-lisp.crypto:encode-p2pkh-address
                 (make-array 20 :element-type '(unsigned-byte 8) :initial-element 5) :regtest)))
      (signals bitcoin-lisp.rpc::rpc-error
        (bitcoin-lisp.rpc::rpc-createpsbt
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
         (map (bitcoin-lisp.serialization:make-psbt-map
               :records
               (list (%tap-record bitcoin-lisp.serialization:+psbt-in-tap-key-sig+
                                  #() sig)
                     ;; keydata is <xonly><leaf hash>
                     (%tap-record bitcoin-lisp.serialization:+psbt-in-tap-script-sig+
                                  (concatenate '(vector (unsigned-byte 8)) xonly leaf-hash)
                                  sig)
                     ;; keydata is the control block
                     (%tap-record bitcoin-lisp.serialization:+psbt-in-tap-leaf-script+
                                  control leaf-value)
                     (%tap-record bitcoin-lisp.serialization:+psbt-in-tap-internal-key+
                                  #() xonly)
                     (%tap-record bitcoin-lisp.serialization:+psbt-in-tap-merkle-root+
                                  #() leaf-hash)
                     ;; <count><leaf hashes><fingerprint><path>
                     (%tap-record bitcoin-lisp.serialization:+psbt-in-tap-bip32+
                                  xonly
                                  (concatenate '(vector (unsigned-byte 8))
                                               (vector 1) leaf-hash
                                               (vector 1 2 3 4)
                                               (vector 0 0 0 #x80))))))
         (json (bitcoin-lisp.rpc::%psbt-input-json map :regtest)))
    (flet ((f (k) (cdr (assoc k json :test #'string=))))
      (is (equal (bitcoin-lisp.crypto:bytes-to-hex sig) (f "taproot_key_path_sig")))
      (is (equal (bitcoin-lisp.crypto:bytes-to-hex xonly) (f "taproot_internal_key")))
      (is (equal (bitcoin-lisp.crypto:bytes-to-hex leaf-hash) (f "taproot_merkle_root")))
      ;; script-path sigs split the keydata into pubkey + leaf hash.
      (let ((sps (elt (f "taproot_script_path_sigs") 0)))
        (is (equal (bitcoin-lisp.crypto:bytes-to-hex xonly)
                   (cdr (assoc "pubkey" sps :test #'string=))))
        (is (equal (bitcoin-lisp.crypto:bytes-to-hex leaf-hash)
                   (cdr (assoc "leaf_hash" sps :test #'string=))))
        (is (equal (bitcoin-lisp.crypto:bytes-to-hex sig)
                   (cdr (assoc "sig" sps :test #'string=)))))
      ;; taproot_scripts splits the VALUE into script + trailing leaf version,
      ;; and lists the control block from the KEYDATA.
      (let ((ts (elt (f "taproot_scripts") 0)))
        (is (equal (bitcoin-lisp.crypto:bytes-to-hex script)
                   (cdr (assoc "script" ts :test #'string=))))
        (is (eql #xc0 (cdr (assoc "leaf_ver" ts :test #'string=))))
        (is (equal (bitcoin-lisp.crypto:bytes-to-hex control)
                   (elt (cdr (assoc "control_blocks" ts :test #'string=)) 0))))
      ;; taproot_bip32_derivs carries the leaf hashes AND the ordinary
      ;; fingerprint/path, which is what distinguishes it from bip32_derivs.
      (let ((d (elt (f "taproot_bip32_derivs") 0)))
        (is (equal (bitcoin-lisp.crypto:bytes-to-hex xonly)
                   (cdr (assoc "pubkey" d :test #'string=))))
        (is (equal "01020304" (cdr (assoc "master_fingerprint" d :test #'string=))))
        (is (equal "m/0'" (cdr (assoc "path" d :test #'string=))))
        (is (equal (bitcoin-lisp.crypto:bytes-to-hex leaf-hash)
                   (elt (cdr (assoc "leaf_hashes" d :test #'string=)) 0)))))))

(test decodepsbt-reports-taproot-output-fields
  "PSBT_OUT_TAP_TREE is one opaque blob of (depth, leaf_ver, script) tuples;
Core reports it as hex rather than expanding it, so we do the same rather than
inventing a shape a client would not recognise."
  (let* ((xonly (%tap-bytes 32 #x11))
         (tree (%tap-bytes 8 #x22))
         (map (bitcoin-lisp.serialization:make-psbt-map
               :records
               (list (%tap-record bitcoin-lisp.serialization:+psbt-out-tap-internal-key+
                                  #() xonly)
                     (%tap-record bitcoin-lisp.serialization:+psbt-out-tap-tree+
                                  #() tree)
                     (%tap-record bitcoin-lisp.serialization:+psbt-out-tap-bip32+
                                  xonly
                                  (concatenate '(vector (unsigned-byte 8))
                                               (vector 0) (vector 9 9 9 9))))))
         (json (bitcoin-lisp.rpc::%psbt-output-json map)))
    (flet ((f (k) (cdr (assoc k json :test #'string=))))
      (is (equal (bitcoin-lisp.crypto:bytes-to-hex xonly) (f "taproot_internal_key")))
      (is (equal (bitcoin-lisp.crypto:bytes-to-hex tree) (f "taproot_tree")))
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
         (map (bitcoin-lisp.serialization:make-psbt-map
               :records
               (list (%tap-record
                      bitcoin-lisp.serialization:+psbt-in-musig2-participant-pubkeys+
                      agg (funcall cat p1 p2))
                     ;; Key path: no leaf hash.
                     (%tap-record bitcoin-lisp.serialization:+psbt-in-musig2-pub-nonce+
                                  (funcall cat p1 agg) nonce)
                     ;; Script path: leaf hash present.
                     (%tap-record bitcoin-lisp.serialization:+psbt-in-musig2-partial-sig+
                                  (funcall cat p2 agg leaf-hash) psig)))))
    (let* ((json (bitcoin-lisp.rpc::%psbt-input-json map :mainnet))
           (parts (cdr (assoc "musig2_participant_pubkeys" json :test #'string=)))
           (nonces (cdr (assoc "musig2_pubnonces" json :test #'string=)))
           (sigs (cdr (assoc "musig2_partial_sigs" json :test #'string=))))
      (is-true parts "no musig2_participant_pubkeys in ~S" (mapcar #'car json))
      (is-true nonces "no musig2_pubnonces")
      (is-true sigs "no musig2_partial_sigs")
      (when (and parts nonces sigs)
        (let ((entry (first (coerce parts 'list))))
          (is (string= (bitcoin-lisp.crypto:bytes-to-hex agg)
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
          (is (string= (bitcoin-lisp.crypto:bytes-to-hex leaf-hash)
                       (cdr (assoc "leaf_hash" sg :test #'string=)))
              "the script-path partial sig lost its leaf hash"))))))
