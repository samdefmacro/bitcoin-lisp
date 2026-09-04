(in-package #:bitcoin-lisp.wallet)

;;;; BIP174 PSBT RPCs
;;;;
;;;; createpsbt / converttopsbt / decodepsbt (creator + decoder),
;;;; combinepsbt / joinpsbts / utxoupdatepsbt / analyzepsbt (combiner/updater),
;;;; finalizepsbt (input finalizer + extractor), combinerawtransaction, and
;;;; the wallet-gated ones -- walletprocesspsbt, walletcreatefundedpsbt,
;;;; descriptorprocesspsbt. Core keeps the first group in rpc/rawtransaction.cpp
;;;; and the second in wallet/rpc/spend.cpp; the file lives with the wallet
;;;; because its signing and funding paths are the wallet's. Registration is
;;;; by name, so the no-wallet RPCs are available whether or not -wallet is on.
;;;;
;;;; The serialization lives in serialization/psbt.lisp; here we interpret the
;;;; raw records into JSON and drive the roles.

(defun %obj-pairs (obj)
  "The (key . value) pairs of a JSON object (alist or hash-table)."
  (cond ((hash-table-p obj)
         (loop for k being the hash-keys of obj using (hash-value v) collect (cons k v)))
        ((listp obj) obj)))

(defun %psbt-decode-arg (b64 &optional (what "psbt"))
  "Decode a base64 PSBT argument, mapping any failure to a deserialization error."
  (unless (stringp b64)
    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-deserialization-error+
                      :message (format nil "~A must be a base64 string" what)))
  (handler-case (bl.ser:decode-psbt b64)
    (bl.rpc:rpc-error (e) (error e))
    (error (e)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-deserialization-error+
                        :message (format nil "~A decode failed: ~A" what e)))))

;;; --- createpsbt ---

(defun %psbt-default-sequence (replaceable locktime)
  "Default nSequence for a createpsbt input, matching Core: replaceable (default
true) -> 0xfffffffd; explicit non-replaceable enforces the locktime -> 0xfffffffe
when locktime>0, else 0xffffffff."
  (cond (replaceable #xfffffffd)
        ((> locktime 0) #xfffffffe)
        (t #xffffffff)))

(defun %psbt-build-unsigned-tx (inputs outputs locktime replaceable network)
  "Build an unsigned transaction from RPC INPUTS/OUTPUTS (Core createpsbt shape)."
  (unless (listp inputs)
    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+ :message "Invalid inputs"))
  (let ((locktime (or locktime 0))
        (tx-outputs '())
        (seen-addrs (make-hash-table :test 'equal))
        (data-seen nil))
    (let ((tx-inputs
            (loop for inp in inputs
                  for txid = (bl.rpc:obj-get inp "txid")
                  for vout = (bl.rpc:obj-get inp "vout")
                  for seq = (or (bl.rpc:obj-get inp "sequence")
                                (%psbt-default-sequence replaceable locktime))
                  do (unless (bl.rpc:valid-hex-hash-p txid)
                       (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                         :message "Invalid input txid"))
                     (unless (and (integerp vout) (>= vout 0))
                       (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                         :message "Invalid input vout"))
                  collect (bl.ser:make-tx-in
                           :previous-output (bl.ser:make-outpoint
                                             :hash (bl.rpc:parse-hex-hash txid) :index vout)
                           :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                           :sequence seq))))
      (dolist (out (if (listp outputs) outputs
                       (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                         :message "Invalid outputs")))
        (dolist (pair (%obj-pairs out))
          (destructuring-bind (key . val) pair
            (if (string= key "data")
                (progn
                  (when data-seen
                    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                      :message "Duplicate key: data"))
                  (setf data-seen t)
                  (push (bl.ser:make-tx-out
                         :value 0
                         :script-pubkey (concatenate '(simple-array (unsigned-byte 8) (*))
                                                      #(#x6a) (bl.ser:script-push-data
                                                               (bl.crypto:hex-to-bytes val))))
                        tx-outputs))
                (multiple-value-bind (type spk) (bl.crypto:decode-address key network)
                  (unless type
                    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-address-or-key+
                                      :message (format nil "Invalid address: ~A" key)))
                  (when (gethash key seen-addrs)
                    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                      :message (format nil "Invalid parameter, duplicated address: ~A" key)))
                  (setf (gethash key seen-addrs) t)
                  (unless (and (numberp val) (<= 0 val 21000000))
                    (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-amount+ :message "Invalid amount"))
                  (push (bl.ser:make-tx-out
                         :value (round (* val 100000000)) :script-pubkey spk)
                        tx-outputs))))))
      (bl.ser:make-transaction
       :version 2
       :inputs (coerce tx-inputs 'simple-vector)
       :outputs (coerce (nreverse tx-outputs) 'simple-vector)
       :lock-time locktime))))

(bl.rpc:define-rpc "createpsbt" (node params)
  "Create a PSBT with no inputs/outputs metadata (Creator role).
PARAMS: (inputs outputs [locktime] [replaceable]). Mirrors Core createpsbt."
  ;; ⚠️ %POSITIONAL-ARRAY, not (first params): an empty JSON array arrives as
  ;; the +json-empty-array+ SENTINEL, not as NIL, so that a handler can tell
  ;; `[]' from a missing argument (server.lisp:349). Passing the sentinel on
  ;; reaches code expecting a LIST and surfaces as RPC -32603 Internal error —
  ;; which is what `createpsbt([], {...})' did, and rpc_psbt.py opens with it.
  (let ((tx (%psbt-build-unsigned-tx (bl.rpc:positional-array (first params))
                                     (second params)
                                     (or (third params) 0)
                                     (bl.rpc:positional-bool-or (fourth params) t)
                                     (bl.rpc:rpc-get-network node))))
    (bl.ser:encode-psbt
     (bl.ser:make-empty-psbt tx))))

;;; --- converttopsbt ---

(bl.rpc:define-rpc "converttopsbt" (node params)
  "Convert a raw transaction to a PSBT, stripping signatures.
PARAMS: (hexstring [permitsigdata] [iswitness]). Mirrors Core converttopsbt."
  (declare (ignore node))
  (let* ((hexstr (first params))
         (permitsigdata (bl.rpc:positional-bool (second params))))
    (unless (stringp hexstr)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+ :message "hexstring required"))
    (let ((tx (handler-case
                  (bl.ser:br-read-transaction
                   (bl.ser:make-byte-reader-from
                    (coerce (bl.crypto:hex-to-bytes hexstr)
                            '(simple-array (unsigned-byte 8) (*)))))
                (error () (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-deserialization-error+
                                            :message "TX decode failed")))))
      (let ((has-sig (or (bl.ser:transaction-has-witness-p tx)
                         (some (lambda (in) (plusp (length (bl.ser:tx-in-script-sig in))))
                               (bl.ser:transaction-inputs tx)))))
        (when (and has-sig (not permitsigdata))
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "Inputs must not have scriptSigs and scriptwitnesses. To convert anyway, permitsigdata must be set to true.")))
      (let ((stripped (bl.ser:make-transaction
                       :version (bl.ser:transaction-version tx)
                       :inputs (map 'simple-vector
                                    (lambda (in)
                                      (bl.ser:make-tx-in
                                       :previous-output (bl.ser:tx-in-previous-output in)
                                       :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                       :sequence (bl.ser:tx-in-sequence in)))
                                    (bl.ser:transaction-inputs tx))
                       :outputs (bl.ser:transaction-outputs tx)
                       :lock-time (bl.ser:transaction-lock-time tx)
                       :witness nil)))
        (bl.ser:encode-psbt
         (bl.ser:make-empty-psbt stripped))))))

;;; --- decodepsbt helpers ---

(defun %psbt-script-obj (script)
  `(("asm" . ,(bl.val:disassemble-script script))
    ("hex" . ,(bl.crypto:bytes-to-hex script))))

(defun %psbt-spk-obj (spk network)
  (let ((o `(("asm" . ,(bl.val:disassemble-script spk))
             ("hex" . ,(bl.crypto:bytes-to-hex spk))
             ("type" . ,(bl.val:script-type-name spk))))
        (addr (and network (bl.rpc:script->address spk network))))
    (if addr (append o `(("address" . ,addr))) o)))

(defun %psbt-keypath-json (pubkey value)
  "A bip32_derivs entry from a PUBKEY and a <fingerprint:4><path:4le*> VALUE."
  `(("pubkey" . ,(bl.crypto:bytes-to-hex pubkey))
    ("master_fingerprint" . ,(bl.crypto:bytes-to-hex (subseq value 0 4)))
    ("path" . ,(with-output-to-string (s)
                 (write-string "m" s)
                 (loop for i from 4 below (length value) by 4
                       for el = (loop for j below 4 sum (ash (aref value (+ i j)) (* 8 j)))
                       do (if (>= el #x80000000)
                              (format s "/~D'" (- el #x80000000))
                              (format s "/~D" el)))))))

(defun %psbt-sighash-name (n)
  (let ((base (logand n #x7f)) (acp (logtest n #x80)))
    (concatenate 'string
                 (case base (0 "DEFAULT") (1 "ALL") (2 "NONE") (3 "SINGLE")
                       (t (return-from %psbt-sighash-name (format nil "~D" n))))
                 (if acp "|ANYONECANPAY" ""))))

(defun %psbt-parse-witness-stack (value)
  (map 'list #'bl.crypto:bytes-to-hex
       (bl.ser:br-read-witness-stack
        (bl.ser:make-byte-reader-from value))))

(defun %psbt-input-prevout (map tx-in)
  "The TX-OUT this input spends, resolved from MAP's utxo fields, or NIL.
%PSBT-INPUT-SPK and %PSBT-INPUT-AMOUNT are the two halves of this one
resolution and must never disagree: any skew yields a script/amount pair that
never existed together on chain.
Core resolves the spent output from NON_WITNESS_UTXO FIRST and falls back to
WITNESS_UTXO only when it is absent (psbt.cpp:76-88), and decodepsbt does the
same -- assigning from witness_utxo then OVERWRITING from non_witness_utxo
before accumulating total_in (rawtransaction.cpp:1126-1149). The order is
deliberate: non_witness_utxo is AUTHENTICATED, because its txid is checked
against the outpoint, while witness_utxo is just a bare TxOut the sender
asserts.

We tested witness_utxo first, so with both present the UNAUTHENTICATED one won
-- in the coins map fed to signing, in %psbt-finalize, and in the fee reported
by decodepsbt and analyzepsbt. A counterparty could supply a truthful
non_witness_utxo (which our parser requires, so the PSBT looks well formed)
plus a witness_utxo repeating the real scriptPubKey with an UNDERSTATED value.
Because non_witness_utxo IS present, %psbt-require-witness-sig-p is false, so a
pkh() input gets a LEGACY signature -- and a legacy sighash does not commit to
the amount, so that signature is valid over the real, larger output. The
operator reviews a fabricated fee, signs, and the difference goes to the miner.
The stock wallet always creates a pkh() SPKM, so this is reachable by default.

The txid check is what makes the preference meaningful, so it is enforced here
rather than assumed."
  (let* ((nwu (bl.ser:psbt-map-find
               map bl.ser:+psbt-in-non-witness-utxo+))
         (prevout (bl.ser:tx-in-previous-output tx-in))
         (vout (bl.ser:outpoint-index prevout)))
    (or
     ;; Authenticated: the full previous transaction, whose txid must match
     ;; the outpoint (Core psbt.cpp:80-83 returns false when it does not).
     (when nwu
       (let ((prev (bl.ser:br-read-transaction
                    (bl.ser:make-byte-reader-from nwu))))
         (when (and (equalp (bl.ser:transaction-hash prev)
                            (bl.ser:outpoint-hash prevout))
                    (< vout (length (bl.ser:transaction-outputs prev))))
           (aref (bl.ser:transaction-outputs prev) vout))))
     ;; Fallback only: an unauthenticated bare TxOut.
     (let ((wu (bl.ser:psbt-map-find
                map bl.ser:+psbt-in-witness-utxo+)))
       (when wu
         (bl.ser:br-read-tx-out
          (bl.ser:make-byte-reader-from wu)))))))

(defun %psbt-input-amount (map tx-in)
  "The satoshi amount of the output spent by TX-IN, from MAP's utxo fields, or NIL."
  (let ((out (%psbt-input-prevout map tx-in)))
    (when out (bl.ser:tx-out-value out))))

(defun %psbt-taproot-input-fields (map add)
  "Report a PSBT input's BIP371 taproot records through ADD (Core decodepsbt,
rawtransaction.cpp:1253-1314).

Everything here was already carried on the wire — the PSBT layer stores raw
records, so a taproot PSBT round-tripped correctly before this. What was
missing was the ability to SEE it, which is what a signer's user needs before
tr() script-path signing means anything."
  (let ((ks (bl.ser:psbt-map-find
             map bl.ser:+psbt-in-tap-key-sig+)))
    (when ks (funcall add "taproot_key_path_sig"
                      (bl.crypto:bytes-to-hex ks))))
  ;; PSBT_IN_TAP_SCRIPT_SIG keydata is <32-byte xonly pubkey><32-byte leaf hash>.
  (let ((sigs (bl.ser:psbt-map-collect
               map bl.ser:+psbt-in-tap-script-sig+)))
    (when sigs
      (funcall add "taproot_script_path_sigs"
               (bl.rpc:json-array
                (loop for (keydata . sig) in sigs
                      when (>= (length keydata) 64)
                        collect `(("pubkey" . ,(bl.crypto:bytes-to-hex
                                                (subseq keydata 0 32)))
                                  ("leaf_hash" . ,(bl.crypto:bytes-to-hex
                                                   (subseq keydata 32 64)))
                                  ("sig" . ,(bl.crypto:bytes-to-hex sig))))))))
  ;; PSBT_IN_TAP_LEAF_SCRIPT keydata is the control block; the value is
  ;; <script><1-byte leaf version>. Core groups by (script, leaf_ver) and lists
  ;; every control block that reaches it.
  (let ((leaves (bl.ser:psbt-map-collect
                 map bl.ser:+psbt-in-tap-leaf-script+)))
    (when leaves
      (let ((groups '()))
        (loop for (control . value) in leaves
              when (plusp (length value))
                do (let* ((script (subseq value 0 (1- (length value))))
                          (leaf-ver (aref value (1- (length value))))
                          (key (cons (bl.crypto:bytes-to-hex script) leaf-ver))
                          (hit (assoc key groups :test #'equal)))
                     (if hit
                         (push (bl.crypto:bytes-to-hex control) (cdr hit))
                         (push (cons key (list (bl.crypto:bytes-to-hex control)))
                               groups))))
        (funcall add "taproot_scripts"
                 (bl.rpc:json-array
                  (loop for ((script-hex . leaf-ver) . controls) in (nreverse groups)
                        collect `(("script" . ,script-hex)
                                  ("leaf_ver" . ,leaf-ver)
                                  ("control_blocks"
                                   . ,(bl.rpc:json-array (nreverse controls))))))))))
  (let ((derivs (bl.ser:psbt-map-collect
                 map bl.ser:+psbt-in-tap-bip32+)))
    (when derivs
      (funcall add "taproot_bip32_derivs"
               (bl.rpc:json-array (mapcar (lambda (d) (%psbt-tap-bip32-json (car d) (cdr d)))
                                   derivs)))))
  (let ((tk (bl.ser:psbt-map-find
             map bl.ser:+psbt-in-tap-internal-key+)))
    (when tk (funcall add "taproot_internal_key"
                      (bl.crypto:bytes-to-hex tk))))
  (let ((mr (bl.ser:psbt-map-find
             map bl.ser:+psbt-in-tap-merkle-root+)))
    (when mr (funcall add "taproot_merkle_root"
                      (bl.crypto:bytes-to-hex mr))))
  (%psbt-musig2-json map add))

(defun %psbt-musig2-keydata-json (keydata)
  "The (participant, aggregate, leaf-hash) a MuSig2 nonce or partial-signature
keydata names, or NIL when it is malformed.

⚠️ The LEAF HASH is what says which spend path this belongs to: present for a
script path, absent for a key path (Core psbt.h:428-430). Its presence is
encoded only in the keydata LENGTH — 66 bytes or 98 — so a reader that ignores
the length attributes a script-path nonce to the key path."
  (let ((n (length keydata)))
    (when (or (= n 66) (= n 98))
      `(("participant_pubkey" . ,(bl.crypto:bytes-to-hex
                                  (subseq keydata 0 33)))
        ("aggregate_pubkey" . ,(bl.crypto:bytes-to-hex
                                (subseq keydata 33 66)))
        ,@(when (= n 98)
            `(("leaf_hash" . ,(bl.crypto:bytes-to-hex
                               (subseq keydata 66 98)))))))))

(defun %psbt-musig2-json (map add)
  "The BIP373 MuSig2 records of MAP, for decodepsbt.

DECODING only. A MuSig2 signing session needs nonce state this node does not
keep, and inventing one would be worse than useless: reusing a MuSig2 nonce
across two messages leaks the private key outright. What a signer's user needs
first is to SEE what a PSBT is asking of them, which is what this gives."
  ;; PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS: keydata is the aggregate, value is the
  ;; participants concatenated.
  (let ((parts (bl.ser:psbt-map-collect
                map bl.ser:+psbt-in-musig2-participant-pubkeys+)))
    (when parts
      (funcall add "musig2_participant_pubkeys"
               (bl.rpc:json-array
                (loop for (agg . value) in parts
                      when (and (= (length agg) 33)
                                (zerop (mod (length value) 33))
                                (plusp (length value)))
                        collect `(("aggregate_pubkey"
                                   . ,(bl.crypto:bytes-to-hex agg))
                                  ("participant_pubkeys"
                                   . ,(bl.rpc:json-array
                                       (loop for i from 0 below (length value) by 33
                                             collect (bl.crypto:bytes-to-hex
                                                      (subseq value i (+ i 33)))))))))))) 
  (let ((nonces (bl.ser:psbt-map-collect
                 map bl.ser:+psbt-in-musig2-pub-nonce+)))
    (when nonces
      (funcall add "musig2_pubnonces"
               (bl.rpc:json-array
                (loop for (keydata . value) in nonces
                      for parsed = (%psbt-musig2-keydata-json keydata)
                      when parsed
                        collect (append parsed
                                        `(("pubnonce"
                                           . ,(bl.crypto:bytes-to-hex value)))))))))
  (let ((psigs (bl.ser:psbt-map-collect
                map bl.ser:+psbt-in-musig2-partial-sig+)))
    (when psigs
      (funcall add "musig2_partial_sigs"
               (bl.rpc:json-array
                (loop for (keydata . value) in psigs
                      for parsed = (%psbt-musig2-keydata-json keydata)
                      when parsed
                        collect (append parsed
                                        `(("partial_sig"
                                           . ,(bl.crypto:bytes-to-hex value))))))))))

(defun %psbt-tap-bip32-json (xonly value)
  "One PSBT_*_TAP_BIP32_DERIVATION record: keydata is the 32-byte x-only
pubkey; the value is <compact-size count><32-byte leaf hash>*<4-byte
fingerprint><path>."
  (let* ((br (bl.ser:make-byte-reader-from value))
         (count (bl.ser:br-read-compact-size br))
         (leaves (loop repeat count
                       collect (bl.crypto:bytes-to-hex
                                (bl.ser:br-read-bytes br 32))))
         (rest (subseq value (bl.ser:br-pos br))))
    ;; %PSBT-KEYPATH-JSON already renders pubkey/fingerprint/path; the leaf
    ;; hashes are what BIP371 adds on top, so its output is reused rather than
    ;; re-derived.
    (append (%psbt-keypath-json xonly rest)
            `(("leaf_hashes" . ,(bl.rpc:json-array leaves))))))

(defun %psbt-input-json (map network)
  (let ((fields '()))
    (flet ((add (k v) (push (cons k v) fields)))
      (let ((nwu (bl.ser:psbt-map-find
                  map bl.ser:+psbt-in-non-witness-utxo+)))
        (when nwu
          (add "non_witness_utxo"
               (bl.rpc:tx-to-json (bl.ser:br-read-transaction
                            (bl.ser:make-byte-reader-from nwu))
                           network))))
      (let ((wu (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-witness-utxo+)))
        (when wu
          (let ((txout (bl.ser:br-read-tx-out
                        (bl.ser:make-byte-reader-from wu))))
            (add "witness_utxo"
                 `(("amount" . ,(/ (bl.ser:tx-out-value txout) 100000000.0d0))
                   ("scriptPubKey" . ,(%psbt-spk-obj (bl.ser:tx-out-script-pubkey txout)
                                                     network)))))))
      (let ((sigs (bl.ser:psbt-map-collect
                   map bl.ser:+psbt-in-partial-sig+)))
        (when sigs
          (add "partial_signatures"
               (loop for (pk . sig) in sigs
                     collect (cons (bl.crypto:bytes-to-hex pk)
                                   (bl.crypto:bytes-to-hex sig))))))
      (let ((sh (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-sighash+)))
        (when sh (add "sighash" (%psbt-sighash-name
                                 (loop for j below 4 sum (ash (aref sh j) (* 8 j)))))))
      (let ((rs (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-redeem-script+)))
        (when rs (add "redeem_script" (%psbt-script-obj rs))))
      (let ((ws (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-witness-script+)))
        (when ws (add "witness_script" (%psbt-script-obj ws))))
      (let ((keypaths (bl.ser:psbt-map-collect
                       map bl.ser:+psbt-in-bip32+)))
        (when keypaths
          (add "bip32_derivs"
               (loop for (pk . v) in keypaths collect (%psbt-keypath-json pk v)))))
      (let ((fs (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-final-scriptsig+)))
        (when fs (add "final_scriptSig" (%psbt-script-obj fs))))
      (let ((fw (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-final-scriptwitness+)))
        (when fw (add "final_scriptwitness" (%psbt-parse-witness-stack fw))))
      (%psbt-taproot-input-fields map #'add))
    (or (nreverse fields) (make-hash-table))))

(defun %psbt-output-json (map)
  (let ((fields '()))
    (flet ((add (k v) (push (cons k v) fields)))
      (let ((rs (bl.ser:psbt-map-find
                 map bl.ser:+psbt-out-redeem-script+)))
        (when rs (add "redeem_script" (%psbt-script-obj rs))))
      (let ((ws (bl.ser:psbt-map-find
                 map bl.ser:+psbt-out-witness-script+)))
        (when ws (add "witness_script" (%psbt-script-obj ws))))
      (let ((keypaths (bl.ser:psbt-map-collect
                       map bl.ser:+psbt-out-bip32+)))
        (when keypaths
          (add "bip32_derivs"
               (loop for (pk . v) in keypaths collect (%psbt-keypath-json pk v)))))
      (let ((tk (bl.ser:psbt-map-find
                 map bl.ser:+psbt-out-tap-internal-key+)))
        (when tk (add "taproot_internal_key" (bl.crypto:bytes-to-hex tk))))
      ;; PSBT_OUT_TAP_TREE is one opaque blob of (depth, leaf_ver, script)
      ;; tuples; Core reports it as hex rather than expanding it.
      (let ((tree (bl.ser:psbt-map-find
                   map bl.ser:+psbt-out-tap-tree+)))
        (when tree (add "taproot_tree" (bl.crypto:bytes-to-hex tree))))
      (let ((derivs (bl.ser:psbt-map-collect
                     map bl.ser:+psbt-out-tap-bip32+)))
        (when derivs
          (add "taproot_bip32_derivs"
               (bl.rpc:json-array (mapcar (lambda (d) (%psbt-tap-bip32-json (car d) (cdr d)))
                                   derivs))))))
    (or (nreverse fields) (make-hash-table))))

(bl.rpc:define-rpc "decodepsbt" (node params)
  "Decode a PSBT to JSON. PARAMS: (psbt). Mirrors Core decodepsbt."
  (let* ((network (bl.rpc:rpc-get-network node))
         (psbt (%psbt-decode-arg (first params)))
         (tx (bl.ser:psbt-tx psbt))
         (in-maps (bl.ser:psbt-inputs psbt))
         (out-maps (bl.ser:psbt-outputs psbt))
         (tx-ins (bl.ser:transaction-inputs tx))
         (result `(("tx" . ,(bl.rpc:tx-to-json tx network)))))
    ;; version
    (let ((ver (bl.ser:psbt-map-find
                (bl.ser:psbt-global psbt)
                bl.ser:+psbt-global-version+)))
      (when ver
        (setf result (append result
                             `(("psbt_version" . ,(loop for j below 4 sum (ash (aref ver j) (* 8 j)))))))))
    ;; inputs / outputs
    (setf result
          (append result
                  `(("inputs" . ,(loop for m across in-maps
                                       collect (%psbt-input-json m network)))
                    ("outputs" . ,(loop for m across out-maps
                                        collect (%psbt-output-json m))))))
    ;; fee (only if every input amount is known)
    (let ((in-total 0) (all t))
      (loop for m across in-maps for i from 0
            for amt = (%psbt-input-amount m (aref tx-ins i))
            do (if amt (incf in-total amt) (setf all nil)))
      (when all
        (let ((out-total (loop for o across (bl.ser:transaction-outputs tx)
                               sum (bl.ser:tx-out-value o))))
          (setf result (append result `(("fee" . ,(/ (- in-total out-total) 100000000.0d0))))))))
    result))

;;; --- combinepsbt / joinpsbts ---

(defun %psbt-merge-map! (dst src)
  "Add every record from SRC absent (by full key) from DST -- Core's Merge
(first PSBT wins on single-value conflicts, union on keyed fields). O(n+m) via a
key hash-set + a single append."
  (let ((seen (make-hash-table :test 'equalp))
        (new '()))
    (dolist (rec (bl.ser:psbt-map-records dst))
      (setf (gethash (car rec) seen) t))
    (dolist (rec (bl.ser:psbt-map-records src))
      (unless (gethash (car rec) seen)
        (setf (gethash (car rec) seen) t)
        (push rec new)))
    (when new
      (setf (bl.ser:psbt-map-records dst)
            (append (bl.ser:psbt-map-records dst) (nreverse new))))))

(bl.rpc:define-rpc "combinepsbt" (node params)
  "Combine PSBTs for the same unsigned tx into one. PARAMS: (txs). Mirrors Core."
  (declare (ignore node))
  (let ((b64s (bl.rpc:positional-array (first params))))
    (unless (and (listp b64s) (>= (length b64s) 1))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "txs must be an array of base64 PSBTs"))
    (let* ((psbts (mapcar #'%psbt-decode-arg b64s))
           (base (first psbts))
           (base-tx (bl.ser:serialize-transaction
                     (bl.ser:psbt-tx base))))
      (dolist (p (rest psbts))
        (unless (equalp base-tx (bl.ser:serialize-transaction
                                 (bl.ser:psbt-tx p)))
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "PSBTs not compatible (different transactions)"))
        (%psbt-merge-map! (bl.ser:psbt-global base)
                          (bl.ser:psbt-global p))
        (dotimes (i (length (bl.ser:psbt-inputs base)))
          (%psbt-merge-map! (aref (bl.ser:psbt-inputs base) i)
                            (aref (bl.ser:psbt-inputs p) i)))
        (dotimes (i (length (bl.ser:psbt-outputs base)))
          (%psbt-merge-map! (aref (bl.ser:psbt-outputs base) i)
                            (aref (bl.ser:psbt-outputs p) i))))
      (bl.ser:encode-psbt base))))

(bl.rpc:define-rpc "joinpsbts" (node params)
  "Join distinct PSBTs (different inputs/outputs) into one. PARAMS: (txs).
Mirrors Core joinpsbts (version=max, locktime=min, concatenated inputs/outputs;
we do not shuffle indices)."
  (declare (ignore node))
  (let ((b64s (bl.rpc:positional-array (first params))))
    (unless (and (listp b64s) (>= (length b64s) 2))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+ :message "At least two PSBTs are required"))
    (let ((psbts (mapcar #'%psbt-decode-arg b64s))
          (version 1) (locktime #xffffffff)
          (ins '()) (outs '()) (in-maps '()) (out-maps '())
          (seen (make-hash-table :test 'equalp))
          (merged-global (bl.ser:make-psbt-map)))
      (dolist (p psbts)
        (let ((tx (bl.ser:psbt-tx p)))
          (setf version (max version (bl.ser:transaction-version tx)))
          (setf locktime (min locktime (bl.ser:transaction-lock-time tx)))
          (loop for in across (bl.ser:transaction-inputs tx)
                for i from 0
                for op = (bl.ser:tx-in-previous-output in)
                for key = (bl.rpc:outpoint-key (bl.ser:outpoint-hash op)
                                         (bl.ser:outpoint-index op))
                do (when (gethash key seen)
                     (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                       :message "Input exists in multiple PSBTs"))
                   (setf (gethash key seen) t)
                   (push in ins)
                   (push (aref (bl.ser:psbt-inputs p) i) in-maps))
          (loop for out across (bl.ser:transaction-outputs tx)
                for i from 0
                do (push out outs)
                   (push (aref (bl.ser:psbt-outputs p) i) out-maps))
          (%psbt-merge-map! merged-global (bl.ser:psbt-global p))))
      (let* ((tx (bl.ser:make-transaction
                  :version version
                  :inputs (coerce (nreverse ins) 'simple-vector)
                  :outputs (coerce (nreverse outs) 'simple-vector)
                  :lock-time locktime))
             (result (bl.ser:make-empty-psbt tx)))
        (setf (bl.ser:psbt-inputs result)
              (coerce (nreverse in-maps) 'simple-vector))
        (setf (bl.ser:psbt-outputs result)
              (coerce (nreverse out-maps) 'simple-vector))
        ;; carry over non-tx global records (xpubs / version / proprietary)
        (dolist (rec (bl.ser:psbt-map-records merged-global))
          (unless (= (bl.ser:psbt-key-type (car rec))
                     bl.ser:+psbt-global-unsigned-tx+)
            (setf (bl.ser:psbt-map-records
                   (bl.ser:psbt-global result))
                  (append (bl.ser:psbt-map-records
                           (bl.ser:psbt-global result))
                          (list rec)))))
        (bl.ser:encode-psbt result)))))

;;; --- utxoupdatepsbt ---

(defun %psbt-witness-spk-p (spk)
  (member (bl.val:script-type-name spk)
          '("witness_v0_keyhash" "witness_v0_scripthash" "witness_v1_taproot")
          :test #'string=))

(bl.rpc:define-rpc "utxoupdatepsbt" (node params)
  "Fill in each input's witness_utxo from the node's UTXO set for witness
outputs. PARAMS: (psbt [descriptors]). Descriptors are not yet used (no
descriptor-based script solving); the UTXO-filling role is implemented.
Mirrors the no-key part of Core utxoupdatepsbt."
  (let* ((psbt (%psbt-decode-arg (first params)))
         (utxo-set (bl.rpc:rpc-get-utxo-set node))
         (tx (bl.ser:psbt-tx psbt)))
    (when utxo-set
      (loop for in across (bl.ser:transaction-inputs tx)
            for i from 0
            for map = (aref (bl.ser:psbt-inputs psbt) i)
            do (unless (or (bl.ser:psbt-map-find
                            map bl.ser:+psbt-in-witness-utxo+)
                           (bl.ser:psbt-map-find
                            map bl.ser:+psbt-in-non-witness-utxo+))
                 (let* ((op (bl.ser:tx-in-previous-output in))
                        (entry (bl.store:get-utxo
                                utxo-set
                                (bl.ser:outpoint-hash op)
                                (bl.ser:outpoint-index op))))
                   (when (and entry (%psbt-witness-spk-p
                                     (bl.store:utxo-entry-script-pubkey entry)))
                     (let ((bb (bl.ser:make-byte-buf)))
                       (bl.ser:bb-write-tx-out
                        bb (bl.ser:make-tx-out
                            :value (bl.store:utxo-entry-value entry)
                            :script-pubkey (bl.store:utxo-entry-script-pubkey entry)))
                       (bl.ser:psbt-map-set
                        map bl.ser:+psbt-in-witness-utxo+
                        (make-array 0 :element-type '(unsigned-byte 8))
                        (bl.ser:bb-finish bb))))))))
    (bl.ser:encode-psbt psbt)))

;;; --- analyzepsbt ---

(bl.rpc:define-rpc "analyzepsbt" (node params)
  "Analyze a PSBT: per-input has_utxo/is_final/next, overall next role, and the
fee when all input amounts are known. PARAMS: (psbt). Note: missing pubkey/sig
lists and vsize estimation are not computed (no script solving here)."
  (declare (ignore node))
  (let* ((psbt (%psbt-decode-arg (first params)))
         (tx (bl.ser:psbt-tx psbt))
         (order '("creator" "updater" "signer" "finalizer" "extractor"))
         (inputs-json '())
         (overall "extractor"))
    (flet ((rank (r) (position r order :test #'string=)))
      (loop for map across (bl.ser:psbt-inputs psbt)
            do (let* ((final (or (bl.ser:psbt-map-find
                                  map bl.ser:+psbt-in-final-scriptsig+)
                                 (bl.ser:psbt-map-find
                                  map bl.ser:+psbt-in-final-scriptwitness+)))
                      (has-utxo (or (bl.ser:psbt-map-find
                                     map bl.ser:+psbt-in-witness-utxo+)
                                    (bl.ser:psbt-map-find
                                     map bl.ser:+psbt-in-non-witness-utxo+)))
                      (has-sigs (bl.ser:psbt-map-collect
                                 map bl.ser:+psbt-in-partial-sig+))
                      (next (cond (final "extractor")
                                  ((not has-utxo) "updater")
                                  (has-sigs "finalizer")
                                  (t "signer"))))
                 (push `(("has_utxo" . ,(bl.rpc:json-bool has-utxo))
                         ("is_final" . ,(bl.rpc:json-bool final))
                         ("next" . ,next))
                       inputs-json)
                 (when (< (rank next) (rank overall)) (setf overall next)))))
    (let ((result `(("inputs" . ,(nreverse inputs-json))))
          (in-total 0) (all t))
      (loop for map across (bl.ser:psbt-inputs psbt)
            for i from 0
            for amt = (%psbt-input-amount map (aref (bl.ser:transaction-inputs tx) i))
            do (if amt (incf in-total amt) (setf all nil)))
      (when all
        (let ((out-total (loop for o across (bl.ser:transaction-outputs tx)
                               sum (bl.ser:tx-out-value o))))
          (setf result (append result `(("fee" . ,(/ (- in-total out-total) 100000000.0d0)))))))
      (append result `(("next" . ,overall))))))

;;; --- finalizepsbt (input finalizer + extractor) ---

(defun %psbt-concat (&rest arrays)
  (apply #'concatenate '(simple-array (unsigned-byte 8) (*)) arrays))

(defun %psbt-input-spk (map tx-in)
  "The scriptPubKey of the output spent by TX-IN, from MAP's utxo fields, or NIL.
Shares %PSBT-INPUT-PREVOUT with %PSBT-INPUT-AMOUNT so the script and the amount
can never come from different sources."
  (let ((out (%psbt-input-prevout map tx-in)))
    (when out (bl.ser:tx-out-script-pubkey out))))

(defun %psbt-sig-for (map pubkey)
  (cdr (assoc pubkey (bl.ser:psbt-map-collect
                      map bl.ser:+psbt-in-partial-sig+)
              :test #'equalp)))

(defun %psbt-first-sig (map)
  (first (bl.ser:psbt-map-collect
          map bl.ser:+psbt-in-partial-sig+)))

(defun %psbt-multisig-sigs (script map)
  "Ordered available signatures for the m-of-n multisig SCRIPT, or NIL if fewer
than m are present."
  (multiple-value-bind (m n pubkeys) (bl.rpc:parse-multisig script)
    (declare (ignore n))
    (when m
      (let ((ordered (loop for pk in pubkeys
                           for s = (%psbt-sig-for map pk)
                           when s collect s)))
        (when (>= (length ordered) m) (subseq ordered 0 m))))))

(defun %psbt-finalize (map spk)
  "Try to finalize the input MAP spending SPK. Returns (values scriptsig
witness-stack) on success (either may be nil/empty), or (values nil nil)."
  (let ((rs (bl.ser:psbt-map-find
             map bl.ser:+psbt-in-redeem-script+))
        (ws (bl.ser:psbt-map-find
             map bl.ser:+psbt-in-witness-script+))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (labels ((ms-witness (script)
               (let ((sigs (%psbt-multisig-sigs script map)))
                 (when sigs (append (list empty) sigs (list script)))))
             (ms-scriptsig (script)
               (let ((sigs (%psbt-multisig-sigs script map)))
                 (when sigs (apply #'%psbt-concat #(#x00)
                                   (mapcar #'bl.ser:script-push-data sigs))))))
      (case (bl.val:classify-script spk)
        (:pubkeyhash
         (let ((s (%psbt-first-sig map)))
           (when s (values (%psbt-concat (bl.ser:script-push-data (cdr s)) (bl.ser:script-push-data (car s))) nil))))
        (:pubkey
         (let ((s (%psbt-first-sig map)))
           (when s (values (bl.ser:script-push-data (cdr s)) nil))))
        (:witness-v0-keyhash
         (let ((s (%psbt-first-sig map)))
           (when s (values empty (list (cdr s) (car s))))))
        (:multisig
         (let ((ss (ms-scriptsig spk))) (when ss (values ss nil))))
        (:witness-v0-scripthash
         (when ws (let ((wit (ms-witness ws))) (when wit (values empty wit)))))
        (:witness-v1-taproot
         (let ((ks (bl.ser:psbt-map-find
                    map bl.ser:+psbt-in-tap-key-sig+)))
           (if ks
               ;; Key path: the whole witness is the one signature.
               (values empty (list ks))
               ;; Script path, assembled from the parts a PSBT stores rather
               ;; than from a witness nobody could have put there — Core's
               ;; PSBTInput::FillSignatureData + ProduceSignature.
               (let ((wit (%psbt-taproot-script-witness map)))
                 (when wit (values empty wit))))))
        (:scripthash
         (when rs
           (case (bl.val:classify-script rs)
             (:witness-v0-keyhash
              (let ((s (%psbt-first-sig map)))
                (when s (values (bl.ser:script-push-data rs) (list (cdr s) (car s))))))
             (:witness-v0-scripthash
              (when ws (let ((wit (ms-witness ws)))
                         (when wit (values (bl.ser:script-push-data rs) wit)))))
             (:multisig
              (let ((sigs (%psbt-multisig-sigs rs map)))
                (when sigs
                  (values (apply #'%psbt-concat #(#x00)
                                 (append (mapcar #'bl.ser:script-push-data sigs)
                                         (list (bl.ser:script-push-data rs))))
                          nil))))
             (:pubkeyhash            ; P2SH-P2PKH: <sig> <pubkey> <redeem>
              (let ((s (%psbt-first-sig map)))
                (when s (values (%psbt-concat (bl.ser:script-push-data (cdr s))
                                              (bl.ser:script-push-data (car s))
                                              (bl.ser:script-push-data rs))
                                nil))))
             (:pubkey               ; P2SH-P2PK: <sig> <redeem>
              (let ((s (%psbt-first-sig map)))
                (when s (values (%psbt-concat (bl.ser:script-push-data (cdr s)) (bl.ser:script-push-data rs)) nil))))
             (t (values nil nil)))))
        (t (values nil nil))))))

(defun %psbt-set-final (map scriptsig witness)
  "Record final scriptSig/scriptWitness on MAP and drop the now-obsolete signing
fields (partial sigs, sighash, redeem/witness scripts, derivations)."
  ;; A finalized input serializes only its utxo + final scripts: Core's input
  ;; Serialize gates partial sigs / sighash / redeem+witness scripts / key paths
  ;; behind "final scripts empty", so we drop those records here to match its
  ;; on-the-wire output (the utxo fields stay).
  (dolist (kt (list bl.ser:+psbt-in-partial-sig+
                    bl.ser:+psbt-in-sighash+
                    bl.ser:+psbt-in-redeem-script+
                    bl.ser:+psbt-in-witness-script+
                    bl.ser:+psbt-in-bip32+))
    (bl.ser:psbt-map-remove-type map kt))
  (when (and scriptsig (plusp (length scriptsig)))
    (bl.ser:psbt-map-set
     map bl.ser:+psbt-in-final-scriptsig+
     (make-array 0 :element-type '(unsigned-byte 8)) scriptsig))
  (when witness
    (let ((bb (bl.ser:make-byte-buf)))
      (bl.ser:bb-write-varint bb (length witness))
      (dolist (item witness)
        (bl.ser:bb-write-varint bb (length item))
        (when (plusp (length item)) (bl.ser:bb-write-bytes bb item)))
      (bl.ser:psbt-map-set
       map bl.ser:+psbt-in-final-scriptwitness+
       (make-array 0 :element-type '(unsigned-byte 8)) (bl.ser:bb-finish bb)))))

(defun %psbt-extract-tx (psbt)
  "The network transaction a finalized PSBT extracts to: the unsigned tx with
each input's final scriptSig / scriptWitness put back on it."
  (let* ((tx (bl.ser:psbt-tx psbt))
         (ins (bl.ser:transaction-inputs tx))
         (nin (length ins))
         (new-ins (make-array nin))
         (witnesses (make-array nin :initial-element nil))
         (any-witness nil))
    (dotimes (i nin)
      (let* ((map (aref (bl.ser:psbt-inputs psbt) i))
             (in (aref ins i))
             (ss (or (bl.ser:psbt-map-find
                      map bl.ser:+psbt-in-final-scriptsig+)
                     (make-array 0 :element-type '(unsigned-byte 8))))
             (fw (bl.ser:psbt-map-find
                  map bl.ser:+psbt-in-final-scriptwitness+)))
        (setf (aref new-ins i)
              (bl.ser:make-tx-in
               :previous-output (bl.ser:tx-in-previous-output in)
               :script-sig ss
               :sequence (bl.ser:tx-in-sequence in)))
        (when fw
          (setf any-witness t
                (aref witnesses i)
                (bl.ser:br-read-witness-stack
                 (bl.ser:make-byte-reader-from fw))))))
    (bl.ser:make-transaction
     :version (bl.ser:transaction-version tx)
     :inputs new-ins
     :outputs (bl.ser:transaction-outputs tx)
     :lock-time (bl.ser:transaction-lock-time tx)
     :witness (if any-witness witnesses nil))))

(defun %psbt-extract-hex (psbt)
  "Extract the fully-signed network transaction from a finalized PSBT as hex."
  (bl.crypto:bytes-to-hex
   (bl.ser:transaction-wire-bytes (%psbt-extract-tx psbt))))

(defun %psbt-inputs-signed-and-verified-p (psbt)
  "Core's `complete` in CWallet::FillPSBT (wallet.cpp:2231-2235): the AND of
PSBTInputSignedAndVerified (psbt.cpp:325-355) over every input. Each spent
output is resolved as Core resolves it -- non_witness_utxo first, with the
txid and prevout-index checks, then witness_utxo, and FALSE outright when
neither is present -- and the assembled final scriptSig / scriptWitness must
VERIFY against that output under the standard flags. That last step is what
separates this from `the finalizer produced some bytes`: a garbage
final_scriptSig, or a co-signer's malformed partial signature that our
finalizer still assembles, is caught here rather than handed back as a `hex`
the caller is invited to broadcast."
  (nth-value 0 (%verify-tx-scripts (%psbt-extract-tx psbt)
                                   (%psbt-coins-map psbt))))

(bl.rpc:define-rpc "finalizepsbt" (node params)
  "Finalize every input possible; if all are final and EXTRACT (default true),
return the network tx hex. PARAMS: (psbt [extract]). Mirrors Core finalizepsbt."
  (declare (ignore node))
  (let* ((psbt (%psbt-decode-arg (first params)))
         (extract (bl.rpc:positional-bool-or (second params) t))
         (tx (bl.ser:psbt-tx psbt))
         (ins (bl.ser:transaction-inputs tx))
         (complete t))
    (dotimes (i (length ins))
      (let ((map (aref (bl.ser:psbt-inputs psbt) i)))
        (if (or (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-final-scriptsig+)
                (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-final-scriptwitness+))
            nil                          ; already final
            (let ((spk (%psbt-input-spk map (aref ins i))))
              (multiple-value-bind (ss wit) (if spk (%psbt-finalize map spk) (values nil nil))
                (if (or (and ss (plusp (length ss))) wit)
                    (%psbt-set-final map ss wit)
                    (setf complete nil)))))))
    (if (and complete extract)
        `(("hex" . ,(%psbt-extract-hex psbt)) ("complete" . t))
        `(("psbt" . ,(bl.ser:encode-psbt psbt))
          ("complete" . ,(bl.rpc:json-bool complete))))))

;;; --- combinerawtransaction ---

(bl.rpc:define-rpc "combinerawtransaction" (node params)
  "Combine partially-signed raw transactions, taking the most-complete scriptSig
and witness per input (prevout script types come from the UTXO set / mempool).
PARAMS: (txs). Mirrors Core combinerawtransaction."
  (declare (ignore node))
  (let ((hexes (bl.rpc:positional-array (first params))))
    (unless (and (listp hexes) (>= (length hexes) 1))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "txs must be a non-empty array of hex transactions"))
    (let ((txs (mapcar (lambda (h)
                         (handler-case
                             (bl.ser:br-read-transaction
                              (bl.ser:make-byte-reader-from
                               (coerce (bl.crypto:hex-to-bytes h)
                                       '(simple-array (unsigned-byte 8) (*)))))
                           (error () (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-deserialization-error+
                                                       :message "TX decode failed"))))
                       hexes)))
      (let* ((base (first txs))
             (nin (length (bl.ser:transaction-inputs base)))
             (merged-ins (make-array nin))
             (witnesses (make-array nin :initial-element nil))
             (any-witness nil))
        (dolist (tx (rest txs))
          (unless (= (length (bl.ser:transaction-inputs tx)) nin)
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-deserialization-error+
                              :message "Input count mismatch between transactions")))
        (dotimes (i nin)
          (let ((best-ss (bl.ser:tx-in-script-sig
                          (aref (bl.ser:transaction-inputs base) i)))
                (best-wit nil)
                (in0 (aref (bl.ser:transaction-inputs base) i)))
            (dolist (tx txs)
              (let* ((in (aref (bl.ser:transaction-inputs tx) i))
                     (ss (bl.ser:tx-in-script-sig in))
                     (w (bl.rpc:tx-input-witness tx i)))
                (when (> (length ss) (length best-ss)) (setf best-ss ss))
                (when (and w (plusp (length w))
                           (or (null best-wit) (> (length w) (length best-wit))))
                  (setf best-wit w))))
            (when best-wit (setf any-witness t (aref witnesses i) best-wit))
            (setf (aref merged-ins i)
                  (bl.ser:make-tx-in
                   :previous-output (bl.ser:tx-in-previous-output in0)
                   :script-sig best-ss
                   :sequence (bl.ser:tx-in-sequence in0)))))
        (let ((merged (bl.ser:make-transaction
                       :version (bl.ser:transaction-version base)
                       :inputs merged-ins
                       :outputs (bl.ser:transaction-outputs base)
                       :lock-time (bl.ser:transaction-lock-time base)
                       :witness (if any-witness witnesses nil))))
          (bl.crypto:bytes-to-hex
           (bl.ser:transaction-wire-bytes merged)))))))

;;;; =====================================================================
;;;; Wallet P5 — PSBT SIGNER role: walletprocesspsbt, descriptorprocesspsbt,
;;;; walletcreatefundedpsbt (wallet/rpc/spend.cpp, rpc/rawtransaction.cpp) +
;;;; RBF fee-bump: bumpfee, psbtbumpfee (wallet/feebumper.cpp).
;;;; =====================================================================
;;;;
;;;; The signer REUSES the funds-critical sighash+sign dispatch factored out of
;;;; the in-place spend signer: %compute-input-signatures (rawtransaction.lisp) computes
;;;; the per-input partial signatures without finalizing, and the same key
;;;; resolution (%wallet-sign-maps / %sign-map-add-key!) resolves wallet or
;;;; descriptor keys. Prevouts are sourced from the PSBT's own witness_utxo /
;;;; non_witness_utxo; partial sigs are recorded as +psbt-in-partial-sig+
;;;; (ECDSA) / +psbt-in-tap-key-sig+ (taproot key path). Finalization is the
;;;; existing finalizepsbt machinery (%psbt-finalize / %psbt-set-final /
;;;; %psbt-extract-hex).

(defun %psbt-uint32-le (n)
  "N as a 4-byte little-endian vector (PSBT sighash / bip32 path element)."
  (let ((v (make-array 4 :element-type '(unsigned-byte 8))))
    (dotimes (i 4 v) (setf (aref v i) (ldb (byte 8 (* 8 i)) n)))))

(defun %psbt-bip32-value (fingerprint path)
  "The <fingerprint:4><path-element:4-LE>* value bytes of a bip32 derivation
record (inverse of %psbt-keypath-json's decode)."
  (apply #'%psbt-concat
         (coerce fingerprint '(simple-array (unsigned-byte 8) (*)))
         (mapcar #'%psbt-uint32-le path)))

;;; --- Sourcing prevouts + missing UTXOs ---

(defun %psbt-coins-map (psbt &optional wallet cc)
  "(txid . vout) -> (script-pubkey amount redeem witness-script) for every input
of PSBT whose prevout is known from its OWN witness_utxo / non_witness_utxo —
the coins map %compute-input-signatures / %wallet-sign-maps consume. redeem /
witness scripts come from the PSBT input map, else (when WALLET given) from the
wallet's known sub-scripts. Inputs with no UTXO are absent."
  (let ((tx (bl.ser:psbt-tx psbt))
        (coins (make-hash-table :test 'equalp)))
    (loop for map across (bl.ser:psbt-inputs psbt)
          for in across (bl.ser:transaction-inputs tx)
          for op = (bl.ser:tx-in-previous-output in)
          for spk = (%psbt-input-spk map in)
          do (when spk
               (let ((amount (%psbt-input-amount map in))
                     (redeem (bl.ser:psbt-map-find
                              map bl.ser:+psbt-in-redeem-script+))
                     (witness (bl.ser:psbt-map-find
                               map bl.ser:+psbt-in-witness-script+)))
                 (when (and wallet (or (null redeem) (null witness)))
                   (multiple-value-bind (wr ww) (%known-sub-scripts wallet cc spk)
                     (setf redeem (or redeem wr) witness (or witness ww))))
                 (setf (gethash (cons (bl.ser:outpoint-hash op)
                                      (bl.ser:outpoint-index op))
                                coins)
                       (list spk amount redeem witness)))))
    coins))

(defun %psbt-input-signed-p (map)
  "Core PSBTInputSigned (psbt.cpp:320-323): the input already carries a final
scriptSig or final scriptWitness, so a filler has nothing left to add.

Presence is deliberately all this asks, because presence is what Core's loops
skip on: CWallet::FillPSBT (wallet.cpp:2192-2194),
DescriptorScriptPubKeyMan::FillPSBT and ProcessPSBT
(rawtransaction.cpp:191-193) all step over an input whose final fields are
set, whatever they contain -- and an input carrying them short-circuits
FillSignatureData/ProduceSignature anyway. The predicate that VERIFIES is
%psbt-inputs-signed-and-verified-p, and it belongs where Core puts it: the
complete walletprocesspsbt reports."
  (or (bl.ser:psbt-map-find
       map bl.ser:+psbt-in-final-scriptsig+)
      (bl.ser:psbt-map-find
       map bl.ser:+psbt-in-final-scriptwitness+)))

(defun %psbt-fill-wallet-utxos (psbt wallet)
  "For inputs without a non_witness_utxo, add it from the wallet's full
previous transaction — Core FillPSBT (wallet.cpp:2201-2212). A witness_utxo
already present does NOT suppress it: the full transaction is what a hardware
signer needs to authenticate the amount of a segwit v0 input, and it is the
2020 fee-spoofing defence, since witness_utxo's amount is unauthenticated.
Already-signed inputs are skipped, as Core skips them (wallet.cpp:2192-2194).

Core drops these again afterwards where they are provably redundant
(RemoveUnnecessaryTransactions, psbt.cpp:514-549: every input segwit v1+ and
no ANYONECANPAY). We deliberately do NOT: that rule keys on the PSBT's
recorded sighash type, which Core writes for every input with a resolvable
UTXO but we write only where a signature succeeded — so on `sign=false`, or
for an input we hold no key for, the ANYONECANPAY guard could not fire and
the drop would destroy data Core keeps. Our PSBTs are therefore larger than
Core's for the taproot-only case; that is the safe direction. Settling the
sighash where Core settles it is the prerequisite for porting the drop."
  (let ((tx (bl.ser:psbt-tx psbt))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for map across (bl.ser:psbt-inputs psbt)
          for in across (bl.ser:transaction-inputs tx)
          for op = (bl.ser:tx-in-previous-output in)
          do (unless (or (%psbt-input-signed-p map)
                         (bl.ser:psbt-map-find
                          map bl.ser:+psbt-in-non-witness-utxo+))
               (let ((wtx (wallet-get-wallet-tx
                           wallet (bl.ser:outpoint-hash op))))
                 (when wtx
                   (bl.ser:psbt-map-set
                    map bl.ser:+psbt-in-non-witness-utxo+ empty
                    (bl.ser:transaction-wire-bytes
                     (wallet-tx-tx wtx)))))))))

(defun %psbt-fill-node-utxos (psbt node)
  "For witness inputs with no UTXO field, add witness_utxo from the node's UTXO
set (descriptorprocesspsbt updates segwit inputs from the UTXO set / mempool)."
  (let ((tx (bl.ser:psbt-tx psbt))
        (utxo-set (bl.rpc:rpc-get-utxo-set node)))
    (when utxo-set
      (loop for map across (bl.ser:psbt-inputs psbt)
            for in across (bl.ser:transaction-inputs tx)
            for op = (bl.ser:tx-in-previous-output in)
            do (unless (or (bl.ser:psbt-map-find
                            map bl.ser:+psbt-in-witness-utxo+)
                           (bl.ser:psbt-map-find
                            map bl.ser:+psbt-in-non-witness-utxo+))
                 (let ((entry (bl.store:get-utxo
                               utxo-set
                               (bl.ser:outpoint-hash op)
                               (bl.ser:outpoint-index op))))
                   (when (and entry (%psbt-witness-spk-p
                                     (bl.store:utxo-entry-script-pubkey entry)))
                     (let ((bb (bl.ser:make-byte-buf)))
                       (bl.ser:bb-write-tx-out
                        bb (bl.ser:make-tx-out
                            :value (bl.store:utxo-entry-value entry)
                            :script-pubkey (bl.store:utxo-entry-script-pubkey entry)))
                       (bl.ser:psbt-map-set
                        map bl.ser:+psbt-in-witness-utxo+
                        (make-array 0 :element-type '(unsigned-byte 8))
                        (bl.ser:bb-finish bb))))))))))

;;; --- Recording signatures + derivations ---

(defun %psbt-input-sighash-stored (map)
  (let ((sh (bl.ser:psbt-map-find
             map bl.ser:+psbt-in-sighash+)))
    (and sh (loop for j below 4 sum (ash (aref sh j) (* 8 j))))))

(defun %psbt-sighash-mismatch ()
  "Core PSBTError::SIGHASH_MISMATCH. Both drive sites abort the whole call
with it rather than skipping the input -- ProcessPSBT throws it explicitly
(rawtransaction.cpp:203-204, \"it is critical that the sighash to sign with
matches the PSBT's\") and DescriptorScriptPubKeyMan::FillPSBT returns
anything but OK/INCOMPLETE up through CWallet::FillPSBT to
walletprocesspsbt's JSONRPCPSBTError. rpc/util.cpp:379-405 maps it to
RPC_DESERIALIZATION_ERROR with common/messages.cpp:110-111's text."
  (error 'bl.rpc:rpc-error
         :code bl.rpc:+rpc-deserialization-error+
         :message "Specified sighash value does not match value stored in PSBT"))

(defun %psbt-check-existing-sighashes (map effective)
  "Core SignPSBTInput's \"Check all existing signatures use the sighash type\"
(psbt.cpp:459-475). Under SIGHASH_DEFAULT every taproot signature must be a
bare 64 bytes; otherwise every taproot signature is 65 bytes ending in the
sighash byte, and every ECDSA partial signature ends in it too.

This is the only signal an operator gets that a co-signer committed to
different transaction fields than the ones we are about to sign, which is why
Core aborts the call (its comment: \"For user safety\") instead of co-signing
next to the foreign signature."
  (flet ((tagged-p (sig)
           (and (plusp (length sig))
                (= (aref sig (1- (length sig))) effective)))
         (sigs (keytype)
           (mapcar #'cdr (bl.ser:psbt-map-collect map keytype))))
    (let* ((key-sig (bl.ser:psbt-map-find map bl.ser:+psbt-in-tap-key-sig+))
           ;; Core tests m_tap_key_sig with !empty(), so an empty record is
           ;; absent rather than a zero-length signature to reject.
           (tap-sigs (append (when (plusp (length key-sig)) (list key-sig))
                             (sigs bl.ser:+psbt-in-tap-script-sig+))))
      (if (zerop effective)
          (dolist (sig tap-sigs)
            (unless (= (length sig) 64) (%psbt-sighash-mismatch)))
          (progn
            (dolist (sig tap-sigs)
              (unless (and (= (length sig) 65) (tagged-p sig))
                (%psbt-sighash-mismatch)))
            (dolist (sig (sigs bl.ser:+psbt-in-partial-sig+))
              (unless (tagged-p sig) (%psbt-sighash-mismatch))))))))

(defun %psbt-effective-sighash (map spk user-sighash)
  "(values effective-byte record-p). Core SignPSBTInput: effective = USER
param, else SIGHASH_DEFAULT(0) for taproot / SIGHASH_ALL(1) otherwise; a stored
+psbt-in-sighash+ must match, and so must every signature already on the input.
RECORD-P is true when EFFECTIVE is non-default and must be written to the input
(taproot: != DEFAULT; else != DEFAULT and != ALL)."
  (let* ((taproot (eq (bl.val:classify-script spk)
                      :witness-v1-taproot))
         (eff (or user-sighash (if taproot #x00 #x01)))
         (stored (%psbt-input-sighash-stored map)))
    (when (and stored (/= stored eff))
      (%psbt-sighash-mismatch))
    (%psbt-check-existing-sighashes map eff)
    (values eff
            (if taproot (/= eff #x00) (and (/= eff #x00) (/= eff #x01))))))

(defun %input-sig-witness-p (sig)
  "True when the input-sig SIG is a segwit (witness) signature — the kinds for
which Core's ProduceSignature sets SignatureData.witness. Legacy kinds (:p2pkh,
:multisig, :p2sh-multisig) are false."
  (and (member (bl.rpc:input-sig-kind sig)
               '(:p2wpkh :p2tr :p2wsh :p2sh-p2wpkh :p2sh-p2wsh))
       t))

(defun %psbt-require-witness-sig-p (map)
  "Core SignPSBTInput's require_witness_sig: an input whose only prevout source is
the witness_utxo (no non_witness_utxo) can only be signed with a witness
signature — witness_utxo alone cannot authenticate a non-witness (legacy) spend,
so a legacy signature over it must be refused. True when witness_utxo is present
and non_witness_utxo is absent."
  (and (bl.ser:psbt-map-find
        map bl.ser:+psbt-in-witness-utxo+)
       (not (bl.ser:psbt-map-find
             map bl.ser:+psbt-in-non-witness-utxo+))))

(defun %psbt-taproot-script-witness (map)
  "The witness for a taproot SCRIPT-path spend assembled from MAP's
PSBT_IN_TAP_LEAF_SCRIPT and PSBT_IN_TAP_SCRIPT_SIG records, or NIL when no leaf
is fully signed.

A leaf is finalizable only when every key its script names has a signature, and
the only way to know how many that is -- without a tapscript miniscript parser
-- is to read the leaf script itself. So this counts the 32-byte pushes the
script contains and requires that many signatures for pk()/pkh(), or the
CHECKSIGADD threshold for multi_a(). A leaf we cannot read stays unfinalized,
which is the safe direction: an under-signed witness is an unspendable
transaction that reports itself complete.

Signature order follows the script, and the multi_a stack runs OPPOSITE to key
order -- see TR-LEAF-SATISFACTION, which derives why."
  (let ((leaves (bl.ser:psbt-map-collect
                 map bl.ser:+psbt-in-tap-leaf-script+))
        (sigs (bl.ser:psbt-map-collect
               map bl.ser:+psbt-in-tap-script-sig+))
        (best nil) (best-size nil))
    (dolist (leaf leaves best)
      (destructuring-bind (control . value) leaf
        (when (plusp (length value))
          (let* ((script (subseq value 0 (1- (length value))))
                 (leaf-hash (bl.crypto:tap-leaf-hash
                             (aref value (1- (length value))) script))
                 (satisfaction (%tapscript-satisfaction script leaf-hash sigs)))
            (when satisfaction
              (let* ((stack (append satisfaction (list script control)))
                     (size (reduce #'+ stack :key #'length)))
                (when (or (null best-size) (< size best-size))
                  (setf best stack best-size size))))))))))

(defun %tapscript-satisfaction (script leaf-hash sigs)
  "The witness elements satisfying the tapscript SCRIPT from SIGS -- a list of
(keydata . sig) where keydata is <32-byte xonly><32-byte leaf hash> -- or NIL.

Only the shapes our tr() grammar builds are recognised, the same set
TR-LEAF-SATISFACTION handles; anything else is left unfinalized."
  (flet ((sig-for (xonly)
           (cdr (find-if (lambda (rec)
                           (let ((kd (car rec)))
                             (and (>= (length kd) 64)
                                  (equalp (subseq kd 0 32) xonly)
                                  (equalp (subseq kd 32 64) leaf-hash))))
                         sigs))))
    (let ((n (length script)))
      (cond
        ;; <32> <x> CHECKSIG
        ((and (= n 34) (= (aref script 0) 32) (= (aref script 33) #xac))
         (let ((sig (sig-for (subseq script 1 33))))
           (when sig (list sig))))
        ;; DUP HASH160 <20> <h> EQUALVERIFY CHECKSIG -- the key is not in the
        ;; script, only its hash, so it has to come from the signature records.
        ((and (= n 25) (= (aref script 0) #x76) (= (aref script 1) #xa9)
              (= (aref script 2) 20) (= (aref script 23) #x88)
              (= (aref script 24) #xac))
         (let* ((hash (subseq script 3 23))
                (rec (find-if (lambda (r)
                                (let ((kd (car r)))
                                  (and (>= (length kd) 64)
                                       (equalp (subseq kd 32 64) leaf-hash)
                                       (equalp (bl.crypto:hash160
                                                (subseq kd 0 32))
                                               hash))))
                              sigs)))
           (when rec (list (cdr rec) (subseq (car rec) 0 32)))))
        ;; <x0> CHECKSIG (<xi> CHECKSIGADD)* <k> NUMEQUAL
        (t (%multi-a-satisfaction script #'sig-for))))))

(defun %multi-a-satisfaction (script sig-for)
  "Satisfy a multi_a tapscript from SIG-FOR, or NIL if SCRIPT is not one or
too few of its keys have signed."
  (let ((keys '()) (i 0) (n (length script)))
    (loop
      (unless (and (< (+ i 34) n) (= (aref script i) 32)) (return))
      (let ((op (aref script (+ i 33))))
        (unless (or (and (null keys) (= op #xac))
                    (and keys (= op #xba)))
          (return))
        (push (subseq script (1+ i) (+ i 33)) keys)
        (incf i 34)))
    (setf keys (nreverse keys))
    (when (and keys (< i n) (= (aref script (1- n)) #x9c))
      (let ((threshold (%script-num-value (subseq script i (1- n)))))
        (when threshold
          (let* ((empty (make-array 0 :element-type '(unsigned-byte 8)))
                 (taken 0)
                 (elements (loop for key in keys
                                 collect (let ((sig (and (< taken threshold)
                                                         (funcall sig-for key))))
                                           (cond (sig (incf taken) sig)
                                                 (t empty))))))
            (when (= taken threshold)
              (reverse elements))))))))

(defun %script-num-value (bytes)
  "The integer a %SCRIPT-NUM push encodes, or NIL if BYTES is not one."
  (cond ((and (= (length bytes) 1) (<= #x51 (aref bytes 0) #x60))
         (- (aref bytes 0) #x50))
        ((and (plusp (length bytes)) (= (aref bytes 0) (1- (length bytes))))
         (loop with v = 0
               for i from 1 below (length bytes)
               do (setf v (logior v (ash (aref bytes i) (* 8 (1- i)))))
               finally (return v)))))

(defun %psbt-record-present-p (map keytype keydata)
  "Whether MAP already holds a KEYTYPE record under exactly KEYDATA.
PSBT-MAP-FIND matches on the key TYPE alone, which is right for the singleton
fields and wrong for the taproot ones — a script-path input carries one
TAP_SCRIPT_SIG per (key, leaf) and one TAP_LEAF_SCRIPT per control block."
  (loop for (kd . nil) in (bl.ser:psbt-map-collect map keytype)
        thereis (equalp kd keydata)))

(defun %psbt-record-signatures (psbt coins keymap pubmap tr-keymap user-sighash
                                &optional tr-scripts)
  "Compute + record partial signatures on every non-final input of PSBT the key
maps can satisfy, sourcing prevouts from COINS. ECDSA partial sigs go into
+psbt-in-partial-sig+ (keyed by pubkey), taproot key-path sigs into
+psbt-in-tap-key-sig+; a non-default sighash into +psbt-in-sighash+, and the
P2SH/P2WSH sub-scripts revealed (needed for finalization). Never finalizes. A
key we do not hold (or an unsourceable prevout) leaves the input untouched."
  (let* ((tx (bl.ser:psbt-tx psbt))
         (inputs (bl.ser:transaction-inputs tx))
         (n (length inputs))
         (spent-utxos (bl.rpc:build-spent-utxos inputs coins))
         (bl.interop:*current-tx* tx)
         (bl.interop:*current-spent-utxos* spent-utxos)
         (precomp (bl.interop:init-precomputed-sighash tx spent-utxos))
         (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (dotimes (i n)
      (let* ((map (aref (bl.ser:psbt-inputs psbt) i))
             (in (aref inputs i))
             (op (bl.ser:tx-in-previous-output in))
             (prev (gethash (cons (bl.ser:outpoint-hash op)
                                  (bl.ser:outpoint-index op))
                            coins)))
        (unless (or (null prev)
                    (bl.ser:psbt-map-find
                     map bl.ser:+psbt-in-final-scriptsig+)
                    (bl.ser:psbt-map-find
                     map bl.ser:+psbt-in-final-scriptwitness+))
          (multiple-value-bind (eff record-p)
              (%psbt-effective-sighash map (first prev) user-sighash)
            (multiple-value-bind (sig err)
                (bl.rpc:compute-input-signatures tx i prev keymap pubmap tr-keymap
                                           (if (zerop eff) #x01 eff)
                                           precomp spent-utxos eff tr-scripts)
              ;; Core SignPSBTInput's require_witness_sig gate: never record a
              ;; legacy (non-witness) signature for an input sourced only from
              ;; the witness_utxo — Core refuses it (a witness_utxo cannot
              ;; authenticate a non-witness spend).
              (unless (or err
                          (and (%psbt-require-witness-sig-p map)
                               (not (%input-sig-witness-p sig))))
                (when (and (bl.rpc:input-sig-redeem sig)
                           (not (bl.ser:psbt-map-find
                                 map bl.ser:+psbt-in-redeem-script+)))
                  (bl.ser:psbt-map-set
                   map bl.ser:+psbt-in-redeem-script+ empty
                   (bl.rpc:input-sig-redeem sig)))
                (when (and (bl.rpc:input-sig-witness-script sig)
                           (not (bl.ser:psbt-map-find
                                 map bl.ser:+psbt-in-witness-script+)))
                  (bl.ser:psbt-map-set
                   map bl.ser:+psbt-in-witness-script+ empty
                   (bl.rpc:input-sig-witness-script sig)))
                (when record-p
                  (bl.ser:psbt-map-set
                   map bl.ser:+psbt-in-sighash+ empty
                   (%psbt-uint32-le eff)))
                ;; Core CreateSig reuses a signature already present for a key
                ;; (input.FillSignatureData loads existing partial_sigs) rather
                ;; than re-signing — so an input already signed by this pubkey
                ;; keeps its existing sig. Never overwrite one we already hold.
                (dolist (pair (bl.rpc:input-sig-ecdsa sig))
                  (unless (%psbt-sig-for map (car pair))
                    (bl.ser:psbt-map-set
                     map bl.ser:+psbt-in-partial-sig+
                     (car pair) (cdr pair))))
                (when (and (bl.rpc:input-sig-tap sig)
                           (not (bl.ser:psbt-map-find
                                 map bl.ser:+psbt-in-tap-key-sig+)))
                  (bl.ser:psbt-map-set
                   map bl.ser:+psbt-in-tap-key-sig+ empty
                   (bl.rpc:input-sig-tap sig)))
                ;; A taproot SCRIPT path is recorded in parts, never as the
                ;; finished witness: PSBT_IN_TAP_SCRIPT_SIG keyed by
                ;; <xonly><leaf hash>, plus the PSBT_IN_TAP_LEAF_SCRIPT the
                ;; next signer needs to reach the same leaf. Storing the
                ;; assembled stack instead would finalize the input and lock
                ;; every other participant out of a k-of-n leaf.
                (dolist (entry (bl.rpc:input-sig-tap-script-sigs sig))
                  (destructuring-bind (xonly leaf-hash tap-sig) entry
                    (let ((keydata (concatenate '(vector (unsigned-byte 8))
                                                xonly leaf-hash)))
                      (unless (%psbt-record-present-p
                               map bl.ser:+psbt-in-tap-script-sig+
                               keydata)
                        (bl.ser:psbt-map-set
                         map bl.ser:+psbt-in-tap-script-sig+
                         keydata tap-sig)))))
                (let ((leaf (bl.rpc:input-sig-tap-leaf sig)))
                  (when leaf
                    (destructuring-bind (script . control) leaf
                      (unless (%psbt-record-present-p
                               map bl.ser:+psbt-in-tap-leaf-script+
                               control)
                        (bl.ser:psbt-map-set
                         map bl.ser:+psbt-in-tap-leaf-script+
                         control
                         (concatenate '(vector (unsigned-byte 8))
                                      script
                                      (vector bl.rpc:+tapleaf-version-tapscript+)))))))))))))))

(defun %psbt-add-map-derivs (map spk pos pairs)
  "Add +psbt-in-bip32+ (ECDSA) / +psbt-in-tap-internal-key+ (taproot) records to
MAP for the (desc-key . pubkey) PAIRS expanded at POS for scriptPubKey SPK."
  (let ((taproot (eq (bl.val:classify-script spk)
                     :witness-v1-taproot))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for (key . pubkey) in pairs
          do (if taproot
                 (bl.ser:psbt-map-set
                  map bl.ser:+psbt-in-tap-internal-key+ empty
                  (bl.rpc:key-xonly-bytes pubkey))
                 (multiple-value-bind (fpr path) (%desc-key-origin-info key pubkey pos)
                   (bl.ser:psbt-map-set
                    map bl.ser:+psbt-in-bip32+ pubkey
                    (%psbt-bip32-value fpr path)))))))

(defun %psbt-add-wallet-input-derivs (psbt coins wallet)
  "Add input bip32 derivations / taproot internal keys for wallet-owned inputs
(Core FillPSBT bip32derivs). Metadata only — helps offline signers."
  (let ((tx (bl.ser:psbt-tx psbt)))
    (loop for map across (bl.ser:psbt-inputs psbt)
          for in across (bl.ser:transaction-inputs tx)
          for op = (bl.ser:tx-in-previous-output in)
          for entry = (gethash (cons (bl.ser:outpoint-hash op)
                                     (bl.ser:outpoint-index op))
                               coins)
          for spk = (and entry (first entry))
          do (when spk
               (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet spk)
                 (when spkm
                   (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
                     (declare (ignore scripts))
                     (%psbt-add-map-derivs map spk pos pairs))))))))

(defun %psbt-add-wallet-output-derivs (psbt wallet)
  "Add output bip32 derivations / redeem / witness scripts for wallet-owned
outputs so an offline signer can identify change (Core UpdatePSBTOutput)."
  (let ((tx (bl.ser:psbt-tx psbt))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for map across (bl.ser:psbt-outputs psbt)
          for out across (bl.ser:transaction-outputs tx)
          for spk = (bl.ser:tx-out-script-pubkey out)
          do (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet spk)
               (when spkm
                 (multiple-value-bind (redeem witness) (%spkm-sub-scripts spkm spk)
                   (when redeem
                     (bl.ser:psbt-map-set
                      map bl.ser:+psbt-out-redeem-script+ empty redeem))
                   (when witness
                     (bl.ser:psbt-map-set
                      map bl.ser:+psbt-out-witness-script+ empty witness)))
                 (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
                   (declare (ignore scripts))
                   (let ((taproot (eq (bl.val:classify-script spk)
                                      :witness-v1-taproot)))
                     (loop for (key . pubkey) in pairs
                           do (if taproot
                                  (bl.ser:psbt-map-set
                                   map bl.ser:+psbt-out-tap-internal-key+
                                   empty (bl.rpc:key-xonly-bytes pubkey))
                                  (multiple-value-bind (fpr path)
                                      (%desc-key-origin-info key pubkey pos)
                                    (bl.ser:psbt-map-set
                                     map bl.ser:+psbt-out-bip32+ pubkey
                                     (%psbt-bip32-value fpr path))))))))))))

;;; --- Completeness / extract ---

(defun %psbt-finalize-in-place (psbt)
  "Finalize every finalizable input of PSBT in place (finalizepsbt machinery).
Returns T when EVERY input is final."
  (let* ((tx (bl.ser:psbt-tx psbt))
         (ins (bl.ser:transaction-inputs tx))
         (complete t))
    (dotimes (i (length ins))
      (let ((map (aref (bl.ser:psbt-inputs psbt) i)))
        (if (or (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-final-scriptsig+)
                (bl.ser:psbt-map-find
                 map bl.ser:+psbt-in-final-scriptwitness+))
            nil
            (let ((spk (%psbt-input-spk map (aref ins i))))
              (multiple-value-bind (ss wit)
                  (if spk (%psbt-finalize map spk) (values nil nil))
                (if (or (and ss (plusp (length ss))) wit)
                    (%psbt-set-final map ss wit)
                    (setf complete nil)))))))
    complete))

(defun %psbt-copy (psbt)
  "A deep copy of PSBT via its serialization."
  (bl.ser:decode-psbt
   (bl.ser:encode-psbt psbt)))

(defun %psbt-signer-result (psbt finalize verify)
  "The {psbt, complete, hex?} object of walletprocesspsbt / descriptorprocesspsbt.
When FINALIZE, PSBT is finalized in place; completeness and the extracted hex
are computed from a finalized COPY either way.

VERIFY is the difference between Core's two callers. walletprocesspsbt reports
the AND of PSBTInputSignedAndVerified (wallet.cpp:2231-2235), so an input
counts only once its assembled scripts VERIFY against the spent output;
descriptorprocesspsbt reports the AND of PSBTInputSigned
(rawtransaction.cpp:2060-2063), where the final fields being present is
enough.

DIVERGENCE: Core computes both over the psbt it returns, so with
finalize=false its complete is false and no hex comes back. We answer from
the finalized copy, so the caller still learns whether the PSBT is ready."
  (when finalize (%psbt-finalize-in-place psbt))
  (let* ((trial (%psbt-copy psbt))
         (complete (and (%psbt-finalize-in-place trial)
                        (or (not verify)
                            (%psbt-inputs-signed-and-verified-p trial)))))
    (append `(("psbt" . ,(bl.ser:encode-psbt psbt))
              ("complete" . ,(bl.rpc:json-bool complete)))
            (when complete
              `(("hex" . ,(%psbt-extract-hex trial)))))))

;;; --- walletprocesspsbt (wallet/rpc/spend.cpp:1573) ---

(bl.rpc:define-rpc "walletprocesspsbt" (node params)
  "Update a PSBT with wallet input info and sign the inputs we can (Bitcoin Core
walletprocesspsbt). PARAMS: (psbt [sign] [sighashtype] [bip32derivs] [finalize]).
Returns {psbt, complete, hex?}."
  (let ((wallet (wallet-for-request node)))
    (bl.rpc:with-node-lock (node)
      (with-wallet-lock (wallet)
        (let* ((psbt (%psbt-decode-arg (first params)))
               (sign (bl.rpc:positional-bool-or (second params) t))
               (user-sighash (multiple-value-bind (byte default-p)
                                 (%wallet-sighash-byte (third params))
                               (if default-p nil byte)))
               (bip32derivs (bl.rpc:positional-bool-or (fourth params) t))
               (finalize (bl.rpc:positional-bool-or (fifth params) t)))
          (when (and sign (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+))
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                              :message "Error: Private keys are disabled for this wallet"))
          (when sign (wallet-ensure-unlocked wallet))
          (%psbt-fill-wallet-utxos psbt wallet)
          (let ((coins (%psbt-coins-map psbt wallet nil)))
            (when bip32derivs
              (%psbt-add-wallet-input-derivs psbt coins wallet)
              (%psbt-add-wallet-output-derivs psbt wallet))
            (when sign
              (multiple-value-bind (keymap pubmap tr-keymap tr-scripts)
                  (%wallet-sign-maps wallet (bl.ser:psbt-tx psbt) coins)
                (%psbt-record-signatures psbt coins keymap pubmap tr-keymap user-sighash
                                         tr-scripts)))
            (%psbt-signer-result psbt finalize t)))))))

;;; --- descriptorprocesspsbt (rpc/rawtransaction.cpp:1992) ---

(defun %psbt-descriptor-expansions (descs network)
  "script-pubkey -> (desc pos pairs) for every script the descriptor DESCS
produce over their ranges (EvalDescriptorStringOrObject: default [0,1000] ranged
/ [0,0] unranged). PAIRS are (desc-key . derived-pubkey) in expression order —
the input to %sign-map-add-key! and the derivations."
  (let ((table (make-hash-table :test 'equalp)))
    (unless (listp descs)
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                        :message "descriptors must be an array"))
    (dolist (d descs table)
      (multiple-value-bind (desc-str range)
          (cond ((stringp d) (values d nil))
                ((hash-table-p d) (values (gethash "desc" d) (gethash "range" d)))
                ((and (consp d) (consp (car d)))
                 (values (cdr (assoc "desc" d :test #'string=))
                         (cdr (assoc "range" d :test #'string=))))
                (t (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                                     :message "Descriptor needs to be provided in the object")))
        (unless (stringp desc-str)
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                            :message "Descriptor needs to be provided in the object"))
        (let ((desc (bl.rpc:parse-descriptor desc-str network)))
          (multiple-value-bind (low high)
              (cond ((not (bl.rpc:out-desc-ranged-p desc)) (values 0 0))
                    (range (bl.rpc:parse-descriptor-range range))
                    (t (values 0 1000)))
            (loop for pos from low to high
                  do (let ((cache (bl.rpc:make-descriptor-cache)))
                       (multiple-value-bind (scripts pubkeys)
                           (handler-case
                               (bl.rpc:out-desc-expand-with-provider desc pos nil cache)
                             (error () (values nil nil)))
                         (when scripts
                           (let ((pairs (mapcar #'cons (bl.rpc:out-desc-ordered-keys desc)
                                                pubkeys)))
                             (dolist (s scripts)
                               (unless (gethash s table)
                                 (setf (gethash s table) (list desc pos pairs)))))))))))))))

(defun %descriptor-sign-maps (expansions tx coins)
  "(values keymap pubmap tr-keymap) for the inputs of TX whose spent script is in
EXPANSIONS (script -> (desc pos pairs)); derives each key's private key from the
descriptor's own material (%desc-key-priv-at with no provider) and verifies it
through the shared %sign-map-add-key!."
  (let ((keymap (make-hash-table :test 'equalp))
        (pubmap (make-hash-table :test 'equalp))
        (tr-keymap (make-hash-table :test 'equalp)))
    (bl.ser:dovector
        (in (bl.ser:transaction-inputs tx))
      (let* ((op (bl.ser:tx-in-previous-output in))
             (entry (gethash (cons (bl.ser:outpoint-hash op)
                                   (bl.ser:outpoint-index op))
                             coins))
             (script (and entry (first entry)))
             (exp (and script (gethash script expansions))))
        (when exp
          (destructuring-bind (desc pos pairs) exp
            (declare (ignore desc))
            (loop for (key . pubkey) in pairs
                  for priv = (%desc-key-priv-at key pos nil)
                  do (when priv
                       (%sign-map-add-key! keymap pubmap tr-keymap
                                           key pubkey priv pos)))))))
    (values keymap pubmap tr-keymap)))

(defun %psbt-add-descriptor-input-derivs (psbt coins expansions)
  (let ((tx (bl.ser:psbt-tx psbt)))
    (loop for map across (bl.ser:psbt-inputs psbt)
          for in across (bl.ser:transaction-inputs tx)
          for op = (bl.ser:tx-in-previous-output in)
          for entry = (gethash (cons (bl.ser:outpoint-hash op)
                                     (bl.ser:outpoint-index op))
                               coins)
          for spk = (and entry (first entry))
          for exp = (and spk (gethash spk expansions))
          do (when exp
               (destructuring-bind (desc pos pairs) exp
                 (declare (ignore desc))
                 (%psbt-add-map-derivs map spk pos pairs))))))

(bl.rpc:define-rpc "descriptorprocesspsbt" (node params)
  "Update a PSBT's segwit inputs from output descriptors + the UTXO set, then
sign the inputs the descriptors can (Bitcoin Core descriptorprocesspsbt).
PARAMS: (psbt descriptors [sighashtype] [bip32derivs] [finalize])."
  (bl.rpc:with-node-lock (node)
    (let* ((network (bl.rpc:rpc-get-network node))
           (psbt (%psbt-decode-arg (first params)))
           (expansions (%psbt-descriptor-expansions (second params) network))
           (user-sighash (multiple-value-bind (byte default-p)
                             (%wallet-sighash-byte (third params))
                           (if default-p nil byte)))
           (bip32derivs (bl.rpc:positional-bool-or (fourth params) t))
           (finalize (bl.rpc:positional-bool-or (fifth params) t)))
      (%psbt-fill-node-utxos psbt node)
      (let ((coins (%psbt-coins-map psbt)))
        (when bip32derivs
          (%psbt-add-descriptor-input-derivs psbt coins expansions))
        (multiple-value-bind (keymap pubmap tr-keymap)
            (%descriptor-sign-maps expansions (bl.ser:psbt-tx psbt) coins)
          (%psbt-record-signatures psbt coins keymap pubmap tr-keymap user-sighash))
        (%psbt-signer-result psbt finalize nil)))))

;;; --- The PSBT-from-wallet path (shared by walletcreatefundedpsbt +
;;; psbtbumpfee): an UNSIGNED PSBT with UTXOs + bip32 derivations. ---

(defun %wallet-unsigned-psbt (node wallet tx bip32derivs)
  "Build an UNSIGNED PSBT for the wallet-funded TX: witness_utxo (+ non_witness_utxo
when the full previous tx is in the wallet) per input, plus, when BIP32DERIVS,
input/output bip32 derivations. Mirrors Core FillPSBT(sign=false)."
  (let* ((inputs (bl.ser:transaction-inputs tx))
         (psbt (bl.ser:make-empty-psbt tx))
         (coins (%wallet-input-coins node wallet tx))
         (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (dotimes (i (length inputs))
      (let* ((in (aref inputs i))
             (op (bl.ser:tx-in-previous-output in))
             (txid (bl.ser:outpoint-hash op))
             (vout (bl.ser:outpoint-index op))
             (entry (gethash (cons txid vout) coins))
             (map (aref (bl.ser:psbt-inputs psbt) i)))
        (when entry
          (bl.ser:psbt-map-set
           map bl.ser:+psbt-in-witness-utxo+ empty
           (%serialize-txout-bytes
            (bl.ser:make-tx-out
             :value (second entry) :script-pubkey (first entry))))
          (when (third entry)
            (bl.ser:psbt-map-set
             map bl.ser:+psbt-in-redeem-script+ empty (third entry)))
          (when (fourth entry)
            (bl.ser:psbt-map-set
             map bl.ser:+psbt-in-witness-script+ empty (fourth entry)))
          (let ((wtx (wallet-get-wallet-tx wallet txid)))
            (when wtx
              (bl.ser:psbt-map-set
               map bl.ser:+psbt-in-non-witness-utxo+ empty
               (bl.ser:transaction-wire-bytes (wallet-tx-tx wtx))))))))
    (when bip32derivs
      (%psbt-add-wallet-input-derivs psbt coins wallet)
      (%psbt-add-wallet-output-derivs psbt wallet))
    (bl.ser:encode-psbt psbt)))

;;; --- walletcreatefundedpsbt (wallet/rpc/spend.cpp:1657) ---

(bl.rpc:define-rpc "walletcreatefundedpsbt" (node params)
  "Create + fund a PSBT (Creator + Updater). PARAMS: (inputs outputs [locktime]
[options] [bip32derivs] [version]). Returns {psbt, fee, changepos}. JSON-object
outputs arrive as hash tables whose key order is not preserved; use the
array-of-objects form when output order matters."
  (let ((wallet (wallet-for-request node)))
    (bl.rpc:with-node-lock (node)
      (with-wallet-lock (wallet)
        (let* ((options (or (nth 3 params) '()))
               (version (let ((v (nth 5 params))) (if (integerp v) v 2)))
               (rbf (if (%opt-present-p options "replaceable")
                        (and (%opt options "replaceable") t)
                        *wallet-signal-rbf*))
               (locktime (or (nth 2 params) 0))
               ;; Same sentinel: walletcreatefundedpsbt([], ...) is the very
               ;; first call rpc_psbt.py makes.
               (inputs (%parse-rpc-inputs (or (bl.rpc:positional-array (first params)) '())))
               (bip32derivs (bl.rpc:positional-bool-or (nth 4 params) t))
               (cc (make-wcc :version version)))
          (unless (and (integerp locktime) (<= 0 locktime #xffffffff))
            (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+
                              :message "Invalid parameter, locktime out of range"))
          (multiple-value-bind (recipients keys)
              (bl.rpc:parse-outputs (wallet-network wallet) (second params))
            (%interpret-sffo (%opt options "subtractFeeFromOutputs") keys recipients)
            (%apply-rpc-inputs cc inputs rbf locktime)
            (setf (wcc-allow-other-inputs cc) (null inputs))
            (multiple-value-bind (change-position lock-unspents)
                (%parse-fund-options node wallet cc options recipients t)
              (declare (ignore lock-unspents))
              (setf (wcc-locktime cc) locktime)
              (multiple-value-bind (tx fee change-pos)
                  (%create-transaction node wallet recipients change-position cc nil)
                (unless tx
                  (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+ :message fee))
                `(("psbt" . ,(%wallet-unsigned-psbt node wallet tx bip32derivs))
                  ("fee" . ,(bl.rpc:satoshi->btc fee))
                  ("changepos" . ,(or change-pos -1)))))))))))

;;; --- feebumper (wallet/feebumper.cpp) ---

(defconstant +wallet-incremental-relay-fee-rate+ 5000
  "Core WALLET_INCREMENTAL_RELAY_FEE = 5000 sat/kvB — the conservative
incremental relay bump the wallet applies over the original feerate (future-
proofs against network incremental-fee changes the node may not know).")

(defun %output-is-change (wallet script)
  "Core wallet::OutputIsChange: SCRIPT is ours and has no (non-change) address
book entry."
  (and (wallet-is-mine wallet script)
       (not (nth-value 2 (wallet-find-address-book-entry
                          wallet (bl.rpc:script->address script (wallet-network wallet)))))))

(defun %all-inputs-mine (node wallet tx)
  "Core AllInputsMine: every input of TX spends a wallet-owned output."
  (block scan
    (bl.ser:dovector
        (in (bl.ser:transaction-inputs tx))
      (let* ((op (bl.ser:tx-in-previous-output in))
             (txout (%wallet-input-txout node wallet
                                         (bl.ser:outpoint-hash op)
                                         (bl.ser:outpoint-index op))))
        (unless (and txout (wallet-is-mine
                            wallet (bl.ser:tx-out-script-pubkey txout)))
          (return-from scan nil))))
    t))

(defun %wallet-has-spend (wallet tx)
  "Core CWallet::HasWalletSpend: a wallet tx spends one of TX's outputs."
  (let ((txid (bl.ser:transaction-hash tx)))
    (dotimes (n (length (bl.ser:transaction-outputs tx)) nil)
      (when (gethash (%wtx-outpoint-key txid n) (wallet-tx-spends wallet))
        (return t)))))

(defun %bump-precondition-checks (node wallet wtx require-mine)
  "Core feebumper::PreconditionChecks. Returns (values ok error-code error-msg).
Adds the task-mandated BIP125-replaceable requirement on the original tx."
  (let ((tx (wallet-tx-tx wtx))
        (mempool (bl:node-mempool node)))
    (cond
      ((%wallet-has-spend wallet tx)
       (values nil bl.rpc:+rpc-invalid-parameter+ "Transaction has descendants in the wallet"))
      ((and mempool (plusp (hash-table-count
                            (bl.mp:mempool-descendants
                             mempool (wallet-tx-txid wtx)))))
       (values nil bl.rpc:+rpc-invalid-parameter+ "Transaction has descendants in the mempool"))
      ((/= (wallet-tx-depth wallet wtx) 0)
       (values nil bl.rpc:+rpc-wallet-error+
               "Transaction has been mined, or is conflicted with a mined transaction"))
      ((assoc "replaced_by_txid" (wallet-tx-map-value wtx) :test #'string=)
       (values nil bl.rpc:+rpc-wallet-error+
               (format nil "Cannot bump transaction ~A which was already bumped by transaction ~A"
                       (bl.rpc:hash-to-hex (wallet-tx-txid wtx))
                       (cdr (assoc "replaced_by_txid" (wallet-tx-map-value wtx) :test #'string=)))))
      ((not (bl.mp:tx-signals-rbf-p tx))
       (values nil bl.rpc:+rpc-wallet-error+
               "Transaction is not BIP 125 replaceable"))
      ((and require-mine (not (%all-inputs-mine node wallet tx)))
       (values nil bl.rpc:+rpc-wallet-error+
               "Transaction contains inputs that don't belong to this wallet"))
      (t (values t nil nil)))))

(defun %bump-estimate-feerate (node wallet orig old-fee cc)
  "Core feebumper::EstimateFeeRate (sat/kvB): the original feerate + 1 sat/kvB +
max(node incremental, wallet incremental), floored at GetMinimumFeeRate."
  (declare (ignore wallet))
  (let* ((txsize (bl.ser:transaction-vsize orig))
         (base (if (plusp txsize) (floor (* old-fee 1000) txsize) 0))
         (feerate (+ base 1 (max bl.mp:*incremental-relay-fee-rate*
                                 +wallet-incremental-relay-fee-rate+)))
         (min-rate (%wallet-minimum-fee-rate node cc)))
    (max feerate min-rate)))

(defun %create-rate-bump (node wallet txid cc require-mine)
  "Core feebumper::CreateRateBumpTransaction (subset). Rebuilds a higher-feerate
replacement of the wallet tx TXID that re-spends all its inputs. Returns
(values new-tx old-fee new-fee) on success, or (values nil error-code error-msg).
Caller holds node + wallet locks."
  (let ((wtx (wallet-get-wallet-tx wallet txid)))
    (unless wtx
      (return-from %create-rate-bump
        (values nil bl.rpc:+rpc-invalid-address-or-key+ "Invalid or non-wallet transaction id")))
    (let* ((orig (wallet-tx-tx wtx))
           (inputs (bl.ser:transaction-inputs orig))
           (input-value 0))
      ;; Retrieve every input's coin; select it on the coin control (external
      ;; inputs get their txout preset). A spent input aborts.
      (bl.ser:dovector (in inputs)
        (let* ((op (bl.ser:tx-in-previous-output in))
               (thash (bl.ser:outpoint-hash op))
               (n (bl.ser:outpoint-index op))
               (txout (%wallet-input-txout node wallet thash n)))
          (unless txout
            (return-from %create-rate-bump
              (values nil bl.rpc:+rpc-misc-error+
                      (format nil "~A:~D is already spent" (bl.rpc:hash-to-hex thash) n))))
          (let ((preset (wcc-select cc thash n)))
            (unless (wallet-is-mine wallet (bl.ser:tx-out-script-pubkey txout))
              (setf (wcc-preset-txout preset) txout)))
          (incf input-value (bl.ser:tx-out-value txout))))
      ;; Preconditions.
      (multiple-value-bind (ok code msg)
          (%bump-precondition-checks node wallet wtx require-mine)
        (unless ok (return-from %create-rate-bump (values nil code msg))))
      (let* ((output-value (reduce #'+ (bl.ser:transaction-outputs orig)
                                   :key #'bl.ser:tx-out-value
                                   :initial-value 0))
             (old-fee (- input-value output-value))
             (network (wallet-network wallet))
             (recipients '()))
        ;; Recipients = original outputs; a single change output becomes destChange.
        (bl.ser:dovector
            (out (bl.ser:transaction-outputs orig))
          (let ((spk (bl.ser:tx-out-script-pubkey out)))
            (if (%output-is-change wallet spk)
                (setf (wcc-dest-change cc) spk)
                (push (bl.rpc:make-recipient :script spk
                                      :amount (bl.ser:tx-out-value out)
                                      :address (bl.rpc:script->address spk network))
                      recipients))))
        (setf recipients (nreverse recipients))
        (when (null recipients)
          (unless (wcc-dest-change cc)
            (return-from %create-rate-bump
              (values nil bl.rpc:+rpc-invalid-parameter+
                      "Unable to create transaction. Transaction must have at least one recipient")))
          (push (bl.rpc:make-recipient :script (wcc-dest-change cc) :amount output-value :sffo t
                                :address (bl.rpc:script->address (wcc-dest-change cc) network))
                recipients)
          (setf (wcc-dest-change cc) nil))
        ;; Feerate: user-provided (already on CC) or estimated from the old fee.
        (if (wcc-feerate cc)
            (setf (wcc-override-feerate cc) t)
            (setf (wcc-feerate cc) (%bump-estimate-feerate node wallet orig old-fee cc)
                  (wcc-override-feerate cc) t))
        ;; Re-spend all original inputs; may add more; no new unconfirmed inputs.
        (bl.ser:dovector (in inputs)
          (let ((op (bl.ser:tx-in-previous-output in)))
            (wcc-select cc (bl.ser:outpoint-hash op)
                        (bl.ser:outpoint-index op))))
        (setf (wcc-allow-other-inputs cc) t
              (wcc-min-depth cc) 1)
        (multiple-value-bind (new-tx new-fee) (%create-transaction node wallet recipients nil cc nil)
          (unless new-tx
            (return-from %create-rate-bump
              (values nil bl.rpc:+rpc-wallet-error+
                      (format nil "Unable to create transaction. ~A" new-fee))))
          ;; BIP125 rule 3/4 (feebumper::CheckFeeRate minTotalFee): the new total
          ;; fee must be at least the old fee plus one incremental relay fee over
          ;; the replacement's size, or the node's mempool will reject it. Enforce
          ;; it here so a too-low bump fails BEFORE we sign / mark the original
          ;; replaced (%create-transaction already caps at -maxtxfee).
          (let ((min-total (+ old-fee
                              (bl.rpc:feerate-fee bl.mp:*incremental-relay-fee-rate*
                                            (bl.ser:transaction-vsize new-tx)))))
            (when (< new-fee min-total)
              (return-from %create-rate-bump
                (values nil bl.rpc:+rpc-invalid-parameter+
                        (format nil "Insufficient total fee ~A, must be at least ~A (oldFee ~A + incrementalFee)"
                                (bl.rpc:format-money new-fee) (bl.rpc:format-money min-total)
                                (bl.rpc:format-money old-fee))))))
          (values new-tx old-fee new-fee))))))

(defun %bumpfee-options->cc (options cc)
  "Apply the bumpfee/psbtbumpfee OPTIONS (conf_target, fee_rate, replaceable,
estimate_mode) onto CC. Coin control already defaults to RBF-signaling."
  (when options
    (let ((replaceable (%opt options "replaceable")))
      (when (%opt-present-p options "replaceable")
        (setf (wcc-signal-bip125-rbf cc) (and replaceable t))))
    (let ((conf-target (or (%opt options "conf_target") (%opt options "confTarget"))))
      (%set-fee-estimate-mode cc conf-target (%opt options "estimate_mode")
                              (%opt options "fee_rate") nil)))
  cc)

(defun %bumpfee-helper (node params want-psbt)
  "Shared body of bumpfee / psbtbumpfee. PARAMS: (txid [options])."
  (let ((wallet (wallet-for-request node))
        (txid-hex (first params)))
    (unless (and (stringp txid-hex) (bl.rpc:valid-hex-hash-p txid-hex))
      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-invalid-parameter+ :message "txid must be a hex string"))
    (bl.rpc:with-node-lock (node)
      (with-wallet-lock (wallet)
        (when (and (not want-psbt)
                   (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+))
          (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                            :message "bumpfee is not available with wallets that have private keys disabled. Use psbtbumpfee instead."))
        ;; Core gates BOTH bumpfee and psbtbumpfee: building the
        ;; replacement needs the keypool and, for bumpfee, the signature.
        (wallet-ensure-unlocked wallet)
        (let ((txid (bl.rpc:parse-hex-hash txid-hex))
              (cc (make-wcc)))
          (setf (wcc-signal-bip125-rbf cc) t)   ; Core: default true, RBF replacement
          (%bumpfee-options->cc (second params) cc)
          (multiple-value-bind (mtx old-fee new-fee code msg)
              (%create-rate-bump node wallet txid cc (not want-psbt))
            (unless mtx
              (error 'bl.rpc:rpc-error :code code :message msg))
            (if want-psbt
                `(("psbt" . ,(%wallet-unsigned-psbt node wallet mtx t))
                  ("origfee" . ,(bl.rpc:satoshi->btc old-fee))
                  ("fee" . ,(bl.rpc:satoshi->btc new-fee))
                  ("errors" . ,#()))
                (progn
                  ;; Sign in place with the wallet keys, then verify.
                  (let ((coins (%wallet-input-coins node wallet mtx cc)))
                    (when (%wallet-sign-transaction wallet mtx coins)
                      (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+ :message "Can't sign transaction."))
                    (multiple-value-bind (verified bad) (%verify-tx-scripts mtx coins)
                      (unless verified
                        (error 'bl.rpc:rpc-error :code bl.rpc:+rpc-wallet-error+
                                          :message (format nil "Internal bug detected: bumped transaction fails script verification at input ~D" bad)))))
                  ;; Re-check preconditions, commit + broadcast, mark replaced.
                  (let ((old-wtx (wallet-get-wallet-tx wallet txid)))
                    (multiple-value-bind (ok code2 msg2)
                        (%bump-precondition-checks node wallet old-wtx nil)
                      (unless ok (error 'bl.rpc:rpc-error :code code2 :message msg2)))
                    (let ((new-txid (bl.ser:transaction-hash mtx)))
                      (%wallet-commit-transaction
                       node wallet mtx
                       (list (cons "replaces_txid" (bl.rpc:hash-to-hex txid))))
                      ;; MarkReplaced: record the bump on the original tx.
                      (setf (wallet-tx-map-value old-wtx)
                            (append (remove "replaced_by_txid" (wallet-tx-map-value old-wtx)
                                            :key #'car :test #'string=)
                                    (list (cons "replaced_by_txid" (bl.rpc:hash-to-hex new-txid)))))
                      `(("txid" . ,(bl.rpc:hash-to-hex new-txid))
                        ("origfee" . ,(bl.rpc:satoshi->btc old-fee))
                        ("fee" . ,(bl.rpc:satoshi->btc new-fee))
                        ("errors" . ,#()))))))))))))

(bl.rpc:define-rpc "bumpfee" (node params)
  "Bump the fee of an unconfirmed wallet transaction, signing + broadcasting the
replacement (Bitcoin Core bumpfee). PARAMS: (txid [options]). Returns
{txid, origfee, fee, errors}."
  (%bumpfee-helper node params nil))

(bl.rpc:define-rpc "psbtbumpfee" (node params)
  "Like bumpfee but return an UNSIGNED PSBT of the replacement instead of signing
and broadcasting (Bitcoin Core psbtbumpfee). PARAMS: (txid [options]). Returns
{psbt, origfee, fee, errors}."
  (%bumpfee-helper node params t))
