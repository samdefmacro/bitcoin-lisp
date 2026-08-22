(in-package #:bitcoin-lisp.rpc)

;;;; BIP174 PSBT RPCs (no-wallet subset)
;;;;
;;;; createpsbt / converttopsbt / decodepsbt (creator + decoder),
;;;; combinepsbt / joinpsbts / utxoupdatepsbt / analyzepsbt (combiner/updater),
;;;; finalizepsbt (input finalizer + extractor), and combinerawtransaction.
;;;; Wallet-gated signing RPCs (walletprocesspsbt, walletcreatefundedpsbt,
;;;; descriptorprocesspsbt) are out of scope -- this node has no wallet/keys.
;;;;
;;;; The serialization lives in serialization/psbt.lisp; here we interpret the
;;;; raw records into JSON and drive the roles.

(defun %obj-get (obj key)
  "Read KEY from a JSON object that arrived as either an alist (from tests /
JSON-RPC 1.x) or a hash-table (from yason)."
  (cond ((hash-table-p obj) (gethash key obj))
        ((listp obj) (cdr (assoc key obj :test #'string=)))))

(defun %obj-pairs (obj)
  "The (key . value) pairs of a JSON object (alist or hash-table)."
  (cond ((hash-table-p obj)
         (loop for k being the hash-keys of obj using (hash-value v) collect (cons k v)))
        ((listp obj) obj)
        (t nil)))

(defun %psbt-decode-arg (b64 &optional (what "psbt"))
  "Decode a base64 PSBT argument, mapping any failure to a deserialization error."
  (unless (stringp b64)
    (error 'rpc-error :code +rpc-deserialization-error+
                      :message (format nil "~A must be a base64 string" what)))
  (handler-case (bitcoin-lisp.serialization:decode-psbt b64)
    (rpc-error (e) (error e))
    (error (e)
      (error 'rpc-error :code +rpc-deserialization-error+
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
    (error 'rpc-error :code +rpc-invalid-parameter+ :message "Invalid inputs"))
  (let ((locktime (or locktime 0))
        (tx-outputs '())
        (seen-addrs (make-hash-table :test 'equal))
        (data-seen nil))
    (let ((tx-inputs
            (loop for inp in inputs
                  for txid = (%obj-get inp "txid")
                  for vout = (%obj-get inp "vout")
                  for seq = (or (%obj-get inp "sequence")
                                (%psbt-default-sequence replaceable locktime))
                  do (unless (valid-hex-hash-p txid)
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid input txid"))
                     (unless (and (integerp vout) (>= vout 0))
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid input vout"))
                  collect (bitcoin-lisp.serialization:make-tx-in
                           :previous-output (bitcoin-lisp.serialization:make-outpoint
                                             :hash (parse-hex-hash txid) :index vout)
                           :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                           :sequence seq))))
      (dolist (out (if (listp outputs) outputs
                       (error 'rpc-error :code +rpc-invalid-parameter+
                                         :message "Invalid outputs")))
        (dolist (pair (%obj-pairs out))
          (destructuring-bind (key . val) pair
            (if (string= key "data")
                (progn
                  (when data-seen
                    (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message "Duplicate key: data"))
                  (setf data-seen t)
                  (push (bitcoin-lisp.serialization:make-tx-out
                         :value 0
                         :script-pubkey (concatenate '(simple-array (unsigned-byte 8) (*))
                                                      #(#x6a) (%script-push
                                                               (bitcoin-lisp.crypto:hex-to-bytes val))))
                        tx-outputs))
                (multiple-value-bind (type spk) (bitcoin-lisp.crypto:decode-address key network)
                  (unless type
                    (error 'rpc-error :code +rpc-invalid-address-or-key+
                                      :message (format nil "Invalid address: ~A" key)))
                  (when (gethash key seen-addrs)
                    (error 'rpc-error :code +rpc-invalid-parameter+
                                      :message (format nil "Invalid parameter, duplicated address: ~A" key)))
                  (setf (gethash key seen-addrs) t)
                  (unless (and (numberp val) (<= 0 val 21000000))
                    (error 'rpc-error :code +rpc-invalid-amount+ :message "Invalid amount"))
                  (push (bitcoin-lisp.serialization:make-tx-out
                         :value (round (* val 100000000)) :script-pubkey spk)
                        tx-outputs))))))
      (bitcoin-lisp.serialization:make-transaction
       :version 2
       :inputs (coerce tx-inputs 'simple-vector)
       :outputs (coerce (nreverse tx-outputs) 'simple-vector)
       :lock-time locktime))))

(defun rpc-createpsbt (node params)
  "Create a PSBT with no inputs/outputs metadata (Creator role).
PARAMS: (inputs outputs [locktime] [replaceable]). Mirrors Core createpsbt."
  (let ((tx (%psbt-build-unsigned-tx (first params) (second params)
                                     (or (third params) 0)
                                     (%positional-bool-or (fourth params) t)
                                     (rpc-get-network node))))
    (bitcoin-lisp.serialization:encode-psbt
     (bitcoin-lisp.serialization:make-empty-psbt tx))))

;;; --- converttopsbt ---

(defun rpc-converttopsbt (node params)
  "Convert a raw transaction to a PSBT, stripping signatures.
PARAMS: (hexstring [permitsigdata] [iswitness]). Mirrors Core converttopsbt."
  (declare (ignore node))
  (let* ((hexstr (first params))
         (permitsigdata (%positional-bool (second params))))
    (unless (stringp hexstr)
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "hexstring required"))
    (let ((tx (handler-case
                  (bitcoin-lisp.serialization:br-read-transaction
                   (bitcoin-lisp.serialization:make-byte-reader-from
                    (coerce (bitcoin-lisp.crypto:hex-to-bytes hexstr)
                            '(simple-array (unsigned-byte 8) (*)))))
                (error () (error 'rpc-error :code +rpc-deserialization-error+
                                            :message "TX decode failed")))))
      (let ((has-sig (or (bitcoin-lisp.serialization:transaction-has-witness-p tx)
                         (some (lambda (in) (plusp (length (bitcoin-lisp.serialization:tx-in-script-sig in))))
                               (bitcoin-lisp.serialization:transaction-inputs tx)))))
        (when (and has-sig (not permitsigdata))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Inputs must not have scriptSigs and scriptwitnesses. To convert anyway, permitsigdata must be set to true.")))
      (let ((stripped (bitcoin-lisp.serialization:make-transaction
                       :version (bitcoin-lisp.serialization:transaction-version tx)
                       :inputs (map 'simple-vector
                                    (lambda (in)
                                      (bitcoin-lisp.serialization:make-tx-in
                                       :previous-output (bitcoin-lisp.serialization:tx-in-previous-output in)
                                       :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                       :sequence (bitcoin-lisp.serialization:tx-in-sequence in)))
                                    (bitcoin-lisp.serialization:transaction-inputs tx))
                       :outputs (bitcoin-lisp.serialization:transaction-outputs tx)
                       :lock-time (bitcoin-lisp.serialization:transaction-lock-time tx)
                       :witness nil)))
        (bitcoin-lisp.serialization:encode-psbt
         (bitcoin-lisp.serialization:make-empty-psbt stripped))))))

;;; --- decodepsbt helpers ---

(defun %psbt-script-obj (script)
  `(("asm" . ,(bitcoin-lisp.validation:disassemble-script script))
    ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex script))))

(defun %psbt-spk-obj (spk network)
  (let ((o `(("asm" . ,(bitcoin-lisp.validation:disassemble-script spk))
             ("hex" . ,(bitcoin-lisp.crypto:bytes-to-hex spk))
             ("type" . ,(%script-type spk))))
        (addr (and network (%script->address spk network))))
    (if addr (append o `(("address" . ,addr))) o)))

(defun %psbt-keypath-json (pubkey value)
  "A bip32_derivs entry from a PUBKEY and a <fingerprint:4><path:4le*> VALUE."
  `(("pubkey" . ,(bitcoin-lisp.crypto:bytes-to-hex pubkey))
    ("master_fingerprint" . ,(bitcoin-lisp.crypto:bytes-to-hex (subseq value 0 4)))
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
  (map 'list #'bitcoin-lisp.crypto:bytes-to-hex
       (bitcoin-lisp.serialization:br-read-witness-stack
        (bitcoin-lisp.serialization:make-byte-reader-from value))))

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
  (let* ((nwu (bitcoin-lisp.serialization:psbt-map-find
               map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+))
         (prevout (bitcoin-lisp.serialization:tx-in-previous-output tx-in))
         (vout (bitcoin-lisp.serialization:outpoint-index prevout)))
    (or
     ;; Authenticated: the full previous transaction, whose txid must match
     ;; the outpoint (Core psbt.cpp:80-83 returns false when it does not).
     (when nwu
       (let ((prev (bitcoin-lisp.serialization:br-read-transaction
                    (bitcoin-lisp.serialization:make-byte-reader-from nwu))))
         (when (and (equalp (bitcoin-lisp.serialization:transaction-hash prev)
                            (bitcoin-lisp.serialization:outpoint-hash prevout))
                    (< vout (length (bitcoin-lisp.serialization:transaction-outputs prev))))
           (aref (bitcoin-lisp.serialization:transaction-outputs prev) vout))))
     ;; Fallback only: an unauthenticated bare TxOut.
     (let ((wu (bitcoin-lisp.serialization:psbt-map-find
                map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)))
       (when wu
         (bitcoin-lisp.serialization:br-read-tx-out
          (bitcoin-lisp.serialization:make-byte-reader-from wu)))))))

(defun %psbt-input-amount (map tx-in)
  "The satoshi amount of the output spent by TX-IN, from MAP's utxo fields, or NIL."
  (let ((out (%psbt-input-prevout map tx-in)))
    (when out (bitcoin-lisp.serialization:tx-out-value out))))

(defun %psbt-taproot-input-fields (map add)
  "Report a PSBT input's BIP371 taproot records through ADD (Core decodepsbt,
rawtransaction.cpp:1253-1314).

Everything here was already carried on the wire — the PSBT layer stores raw
records, so a taproot PSBT round-tripped correctly before this. What was
missing was the ability to SEE it, which is what a signer's user needs before
tr() script-path signing means anything."
  (let ((ks (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-tap-key-sig+)))
    (when ks (funcall add "taproot_key_path_sig"
                      (bitcoin-lisp.crypto:bytes-to-hex ks))))
  ;; PSBT_IN_TAP_SCRIPT_SIG keydata is <32-byte xonly pubkey><32-byte leaf hash>.
  (let ((sigs (bitcoin-lisp.serialization:psbt-map-collect
               map bitcoin-lisp.serialization:+psbt-in-tap-script-sig+)))
    (when sigs
      (funcall add "taproot_script_path_sigs"
               (json-array
                (loop for (keydata . sig) in sigs
                      when (>= (length keydata) 64)
                        collect `(("pubkey" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                                (subseq keydata 0 32)))
                                  ("leaf_hash" . ,(bitcoin-lisp.crypto:bytes-to-hex
                                                   (subseq keydata 32 64)))
                                  ("sig" . ,(bitcoin-lisp.crypto:bytes-to-hex sig))))))))
  ;; PSBT_IN_TAP_LEAF_SCRIPT keydata is the control block; the value is
  ;; <script><1-byte leaf version>. Core groups by (script, leaf_ver) and lists
  ;; every control block that reaches it.
  (let ((leaves (bitcoin-lisp.serialization:psbt-map-collect
                 map bitcoin-lisp.serialization:+psbt-in-tap-leaf-script+)))
    (when leaves
      (let ((groups '()))
        (loop for (control . value) in leaves
              when (plusp (length value))
                do (let* ((script (subseq value 0 (1- (length value))))
                          (leaf-ver (aref value (1- (length value))))
                          (key (cons (bitcoin-lisp.crypto:bytes-to-hex script) leaf-ver))
                          (hit (assoc key groups :test #'equal)))
                     (if hit
                         (push (bitcoin-lisp.crypto:bytes-to-hex control) (cdr hit))
                         (push (cons key (list (bitcoin-lisp.crypto:bytes-to-hex control)))
                               groups))))
        (funcall add "taproot_scripts"
                 (json-array
                  (loop for ((script-hex . leaf-ver) . controls) in (nreverse groups)
                        collect `(("script" . ,script-hex)
                                  ("leaf_ver" . ,leaf-ver)
                                  ("control_blocks"
                                   . ,(json-array (nreverse controls))))))))))
  (let ((derivs (bitcoin-lisp.serialization:psbt-map-collect
                 map bitcoin-lisp.serialization:+psbt-in-tap-bip32+)))
    (when derivs
      (funcall add "taproot_bip32_derivs"
               (json-array (mapcar (lambda (d) (%psbt-tap-bip32-json (car d) (cdr d)))
                                   derivs)))))
  (let ((tk (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-tap-internal-key+)))
    (when tk (funcall add "taproot_internal_key"
                      (bitcoin-lisp.crypto:bytes-to-hex tk))))
  (let ((mr (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-tap-merkle-root+)))
    (when mr (funcall add "taproot_merkle_root"
                      (bitcoin-lisp.crypto:bytes-to-hex mr)))))

(defun %psbt-tap-bip32-json (xonly value)
  "One PSBT_*_TAP_BIP32_DERIVATION record: keydata is the 32-byte x-only
pubkey; the value is <compact-size count><32-byte leaf hash>*<4-byte
fingerprint><path>."
  (let* ((br (bitcoin-lisp.serialization:make-byte-reader-from value))
         (count (bitcoin-lisp.serialization:br-read-compact-size br))
         (leaves (loop repeat count
                       collect (bitcoin-lisp.crypto:bytes-to-hex
                                (bitcoin-lisp.serialization:br-read-bytes br 32))))
         (rest (subseq value (bitcoin-lisp.serialization::br-pos br))))
    ;; %PSBT-KEYPATH-JSON already renders pubkey/fingerprint/path; the leaf
    ;; hashes are what BIP371 adds on top, so its output is reused rather than
    ;; re-derived.
    (append (%psbt-keypath-json xonly rest)
            `(("leaf_hashes" . ,(json-array leaves))))))

(defun %psbt-input-json (map network)
  (let ((fields '()))
    (flet ((add (k v) (push (cons k v) fields)))
      (let ((nwu (bitcoin-lisp.serialization:psbt-map-find
                  map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+)))
        (when nwu
          (add "non_witness_utxo"
               (tx-to-json (bitcoin-lisp.serialization:br-read-transaction
                            (bitcoin-lisp.serialization:make-byte-reader-from nwu))
                           network))))
      (let ((wu (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)))
        (when wu
          (let ((txout (bitcoin-lisp.serialization:br-read-tx-out
                        (bitcoin-lisp.serialization:make-byte-reader-from wu))))
            (add "witness_utxo"
                 `(("amount" . ,(/ (bitcoin-lisp.serialization:tx-out-value txout) 100000000.0d0))
                   ("scriptPubKey" . ,(%psbt-spk-obj (bitcoin-lisp.serialization:tx-out-script-pubkey txout)
                                                     network)))))))
      (let ((sigs (bitcoin-lisp.serialization:psbt-map-collect
                   map bitcoin-lisp.serialization:+psbt-in-partial-sig+)))
        (when sigs
          (add "partial_signatures"
               (loop for (pk . sig) in sigs
                     collect (cons (bitcoin-lisp.crypto:bytes-to-hex pk)
                                   (bitcoin-lisp.crypto:bytes-to-hex sig))))))
      (let ((sh (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-sighash+)))
        (when sh (add "sighash" (%psbt-sighash-name
                                 (loop for j below 4 sum (ash (aref sh j) (* 8 j)))))))
      (let ((rs (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-redeem-script+)))
        (when rs (add "redeem_script" (%psbt-script-obj rs))))
      (let ((ws (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-witness-script+)))
        (when ws (add "witness_script" (%psbt-script-obj ws))))
      (let ((keypaths (bitcoin-lisp.serialization:psbt-map-collect
                       map bitcoin-lisp.serialization:+psbt-in-bip32+)))
        (when keypaths
          (add "bip32_derivs"
               (loop for (pk . v) in keypaths collect (%psbt-keypath-json pk v)))))
      (let ((fs (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)))
        (when fs (add "final_scriptSig" (%psbt-script-obj fs))))
      (let ((fw (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+)))
        (when fw (add "final_scriptwitness" (%psbt-parse-witness-stack fw))))
      (%psbt-taproot-input-fields map #'add))
    (or (nreverse fields) (make-hash-table))))

(defun %psbt-output-json (map)
  (let ((fields '()))
    (flet ((add (k v) (push (cons k v) fields)))
      (let ((rs (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-out-redeem-script+)))
        (when rs (add "redeem_script" (%psbt-script-obj rs))))
      (let ((ws (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-out-witness-script+)))
        (when ws (add "witness_script" (%psbt-script-obj ws))))
      (let ((keypaths (bitcoin-lisp.serialization:psbt-map-collect
                       map bitcoin-lisp.serialization:+psbt-out-bip32+)))
        (when keypaths
          (add "bip32_derivs"
               (loop for (pk . v) in keypaths collect (%psbt-keypath-json pk v)))))
      (let ((tk (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-out-tap-internal-key+)))
        (when tk (add "taproot_internal_key" (bitcoin-lisp.crypto:bytes-to-hex tk))))
      ;; PSBT_OUT_TAP_TREE is one opaque blob of (depth, leaf_ver, script)
      ;; tuples; Core reports it as hex rather than expanding it.
      (let ((tree (bitcoin-lisp.serialization:psbt-map-find
                   map bitcoin-lisp.serialization:+psbt-out-tap-tree+)))
        (when tree (add "taproot_tree" (bitcoin-lisp.crypto:bytes-to-hex tree))))
      (let ((derivs (bitcoin-lisp.serialization:psbt-map-collect
                     map bitcoin-lisp.serialization:+psbt-out-tap-bip32+)))
        (when derivs
          (add "taproot_bip32_derivs"
               (json-array (mapcar (lambda (d) (%psbt-tap-bip32-json (car d) (cdr d)))
                                   derivs))))))
    (or (nreverse fields) (make-hash-table))))

(defun rpc-decodepsbt (node params)
  "Decode a PSBT to JSON. PARAMS: (psbt). Mirrors Core decodepsbt."
  (let* ((network (rpc-get-network node))
         (psbt (%psbt-decode-arg (first params)))
         (tx (bitcoin-lisp.serialization:psbt-tx psbt))
         (in-maps (bitcoin-lisp.serialization:psbt-inputs psbt))
         (out-maps (bitcoin-lisp.serialization:psbt-outputs psbt))
         (tx-ins (bitcoin-lisp.serialization:transaction-inputs tx))
         (result `(("tx" . ,(tx-to-json tx network)))))
    ;; version
    (let ((ver (bitcoin-lisp.serialization:psbt-map-find
                (bitcoin-lisp.serialization:psbt-global psbt)
                bitcoin-lisp.serialization:+psbt-global-version+)))
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
        (let ((out-total (loop for o across (bitcoin-lisp.serialization:transaction-outputs tx)
                               sum (bitcoin-lisp.serialization:tx-out-value o))))
          (setf result (append result `(("fee" . ,(/ (- in-total out-total) 100000000.0d0))))))))
    result))

;;; --- combinepsbt / joinpsbts ---

(defun %psbt-merge-map! (dst src)
  "Add every record from SRC absent (by full key) from DST -- Core's Merge
(first PSBT wins on single-value conflicts, union on keyed fields). O(n+m) via a
key hash-set + a single append."
  (let ((seen (make-hash-table :test 'equalp))
        (new '()))
    (dolist (rec (bitcoin-lisp.serialization:psbt-map-records dst))
      (setf (gethash (car rec) seen) t))
    (dolist (rec (bitcoin-lisp.serialization:psbt-map-records src))
      (unless (gethash (car rec) seen)
        (setf (gethash (car rec) seen) t)
        (push rec new)))
    (when new
      (setf (bitcoin-lisp.serialization:psbt-map-records dst)
            (append (bitcoin-lisp.serialization:psbt-map-records dst) (nreverse new))))))

(defun rpc-combinepsbt (node params)
  "Combine PSBTs for the same unsigned tx into one. PARAMS: (txs). Mirrors Core."
  (declare (ignore node))
  (let ((b64s (first params)))
    (unless (and (listp b64s) (>= (length b64s) 1))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "txs must be an array of base64 PSBTs"))
    (let* ((psbts (mapcar #'%psbt-decode-arg b64s))
           (base (first psbts))
           (base-tx (bitcoin-lisp.serialization:serialize-transaction
                     (bitcoin-lisp.serialization:psbt-tx base))))
      (dolist (p (rest psbts))
        (unless (equalp base-tx (bitcoin-lisp.serialization:serialize-transaction
                                 (bitcoin-lisp.serialization:psbt-tx p)))
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "PSBTs not compatible (different transactions)"))
        (%psbt-merge-map! (bitcoin-lisp.serialization:psbt-global base)
                          (bitcoin-lisp.serialization:psbt-global p))
        (dotimes (i (length (bitcoin-lisp.serialization:psbt-inputs base)))
          (%psbt-merge-map! (aref (bitcoin-lisp.serialization:psbt-inputs base) i)
                            (aref (bitcoin-lisp.serialization:psbt-inputs p) i)))
        (dotimes (i (length (bitcoin-lisp.serialization:psbt-outputs base)))
          (%psbt-merge-map! (aref (bitcoin-lisp.serialization:psbt-outputs base) i)
                            (aref (bitcoin-lisp.serialization:psbt-outputs p) i))))
      (bitcoin-lisp.serialization:encode-psbt base))))

(defun rpc-joinpsbts (node params)
  "Join distinct PSBTs (different inputs/outputs) into one. PARAMS: (txs).
Mirrors Core joinpsbts (version=max, locktime=min, concatenated inputs/outputs;
we do not shuffle indices)."
  (declare (ignore node))
  (let ((b64s (first params)))
    (unless (and (listp b64s) (>= (length b64s) 2))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "At least two PSBTs are required"))
    (let ((psbts (mapcar #'%psbt-decode-arg b64s))
          (version 1) (locktime #xffffffff)
          (ins '()) (outs '()) (in-maps '()) (out-maps '())
          (seen (make-hash-table :test 'equalp))
          (merged-global (bitcoin-lisp.serialization:make-psbt-map)))
      (dolist (p psbts)
        (let ((tx (bitcoin-lisp.serialization:psbt-tx p)))
          (setf version (max version (bitcoin-lisp.serialization:transaction-version tx)))
          (setf locktime (min locktime (bitcoin-lisp.serialization:transaction-lock-time tx)))
          (loop for in across (bitcoin-lisp.serialization:transaction-inputs tx)
                for i from 0
                for op = (bitcoin-lisp.serialization:tx-in-previous-output in)
                for key = (%outpoint-key (bitcoin-lisp.serialization:outpoint-hash op)
                                         (bitcoin-lisp.serialization:outpoint-index op))
                do (when (gethash key seen)
                     (error 'rpc-error :code +rpc-invalid-parameter+
                                       :message "Input exists in multiple PSBTs"))
                   (setf (gethash key seen) t)
                   (push in ins)
                   (push (aref (bitcoin-lisp.serialization:psbt-inputs p) i) in-maps))
          (loop for out across (bitcoin-lisp.serialization:transaction-outputs tx)
                for i from 0
                do (push out outs)
                   (push (aref (bitcoin-lisp.serialization:psbt-outputs p) i) out-maps))
          (%psbt-merge-map! merged-global (bitcoin-lisp.serialization:psbt-global p))))
      (let* ((tx (bitcoin-lisp.serialization:make-transaction
                  :version version
                  :inputs (coerce (nreverse ins) 'simple-vector)
                  :outputs (coerce (nreverse outs) 'simple-vector)
                  :lock-time locktime))
             (result (bitcoin-lisp.serialization:make-empty-psbt tx)))
        (setf (bitcoin-lisp.serialization:psbt-inputs result)
              (coerce (nreverse in-maps) 'simple-vector))
        (setf (bitcoin-lisp.serialization:psbt-outputs result)
              (coerce (nreverse out-maps) 'simple-vector))
        ;; carry over non-tx global records (xpubs / version / proprietary)
        (dolist (rec (bitcoin-lisp.serialization:psbt-map-records merged-global))
          (unless (= (bitcoin-lisp.serialization:psbt-key-type (car rec))
                     bitcoin-lisp.serialization:+psbt-global-unsigned-tx+)
            (setf (bitcoin-lisp.serialization:psbt-map-records
                   (bitcoin-lisp.serialization:psbt-global result))
                  (append (bitcoin-lisp.serialization:psbt-map-records
                           (bitcoin-lisp.serialization:psbt-global result))
                          (list rec)))))
        (bitcoin-lisp.serialization:encode-psbt result)))))

;;; --- utxoupdatepsbt ---

(defun %psbt-witness-spk-p (spk)
  (member (%script-type spk)
          '("witness_v0_keyhash" "witness_v0_scripthash" "witness_v1_taproot")
          :test #'string=))

(defun rpc-utxoupdatepsbt (node params)
  "Fill in each input's witness_utxo from the node's UTXO set for witness
outputs. PARAMS: (psbt [descriptors]). Descriptors are not yet used (no
descriptor-based script solving); the UTXO-filling role is implemented.
Mirrors the no-key part of Core utxoupdatepsbt."
  (let* ((psbt (%psbt-decode-arg (first params)))
         (utxo-set (rpc-get-utxo-set node))
         (tx (bitcoin-lisp.serialization:psbt-tx psbt)))
    (when utxo-set
      (loop for in across (bitcoin-lisp.serialization:transaction-inputs tx)
            for i from 0
            for map = (aref (bitcoin-lisp.serialization:psbt-inputs psbt) i)
            do (unless (or (bitcoin-lisp.serialization:psbt-map-find
                            map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)
                           (bitcoin-lisp.serialization:psbt-map-find
                            map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+))
                 (let* ((op (bitcoin-lisp.serialization:tx-in-previous-output in))
                        (entry (bitcoin-lisp.storage:get-utxo
                                utxo-set
                                (bitcoin-lisp.serialization:outpoint-hash op)
                                (bitcoin-lisp.serialization:outpoint-index op))))
                   (when (and entry (%psbt-witness-spk-p
                                     (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)))
                     (let ((bb (bitcoin-lisp.serialization:make-byte-buf)))
                       (bitcoin-lisp.serialization:bb-write-tx-out
                        bb (bitcoin-lisp.serialization:make-tx-out
                            :value (bitcoin-lisp.storage:utxo-entry-value entry)
                            :script-pubkey (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)))
                       (bitcoin-lisp.serialization:psbt-map-set
                        map bitcoin-lisp.serialization:+psbt-in-witness-utxo+
                        (make-array 0 :element-type '(unsigned-byte 8))
                        (bitcoin-lisp.serialization:bb-finish bb))))))))
    (bitcoin-lisp.serialization:encode-psbt psbt)))

;;; --- analyzepsbt ---

(defun rpc-analyzepsbt (node params)
  "Analyze a PSBT: per-input has_utxo/is_final/next, overall next role, and the
fee when all input amounts are known. PARAMS: (psbt). Note: missing pubkey/sig
lists and vsize estimation are not computed (no script solving here)."
  (declare (ignore node))
  (let* ((psbt (%psbt-decode-arg (first params)))
         (tx (bitcoin-lisp.serialization:psbt-tx psbt))
         (order '("creator" "updater" "signer" "finalizer" "extractor"))
         (inputs-json '())
         (overall "extractor"))
    (flet ((rank (r) (position r order :test #'string=)))
      (loop for map across (bitcoin-lisp.serialization:psbt-inputs psbt)
            do (let* ((final (or (bitcoin-lisp.serialization:psbt-map-find
                                  map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)
                                 (bitcoin-lisp.serialization:psbt-map-find
                                  map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+)))
                      (has-utxo (or (bitcoin-lisp.serialization:psbt-map-find
                                     map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)
                                    (bitcoin-lisp.serialization:psbt-map-find
                                     map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+)))
                      (has-sigs (bitcoin-lisp.serialization:psbt-map-collect
                                 map bitcoin-lisp.serialization:+psbt-in-partial-sig+))
                      (next (cond (final "extractor")
                                  ((not has-utxo) "updater")
                                  (has-sigs "finalizer")
                                  (t "signer"))))
                 (push `(("has_utxo" . ,(json-bool has-utxo))
                         ("is_final" . ,(json-bool final))
                         ("next" . ,next))
                       inputs-json)
                 (when (< (rank next) (rank overall)) (setf overall next)))))
    (let ((result `(("inputs" . ,(nreverse inputs-json))))
          (in-total 0) (all t))
      (loop for map across (bitcoin-lisp.serialization:psbt-inputs psbt)
            for i from 0
            for amt = (%psbt-input-amount map (aref (bitcoin-lisp.serialization:transaction-inputs tx) i))
            do (if amt (incf in-total amt) (setf all nil)))
      (when all
        (let ((out-total (loop for o across (bitcoin-lisp.serialization:transaction-outputs tx)
                               sum (bitcoin-lisp.serialization:tx-out-value o))))
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
    (when out (bitcoin-lisp.serialization:tx-out-script-pubkey out))))

(defun %psbt-sig-for (map pubkey)
  (cdr (assoc pubkey (bitcoin-lisp.serialization:psbt-map-collect
                      map bitcoin-lisp.serialization:+psbt-in-partial-sig+)
              :test #'equalp)))

(defun %psbt-first-sig (map)
  (first (bitcoin-lisp.serialization:psbt-map-collect
          map bitcoin-lisp.serialization:+psbt-in-partial-sig+)))

(defun %psbt-multisig-sigs (script map)
  "Ordered available signatures for the m-of-n multisig SCRIPT, or NIL if fewer
than m are present."
  (multiple-value-bind (m n pubkeys) (%parse-multisig script)
    (declare (ignore n))
    (when m
      (let ((ordered (loop for pk in pubkeys
                           for s = (%psbt-sig-for map pk)
                           when s collect s)))
        (when (>= (length ordered) m) (subseq ordered 0 m))))))

(defun %psbt-finalize (map spk)
  "Try to finalize the input MAP spending SPK. Returns (values scriptsig
witness-stack) on success (either may be nil/empty), or (values nil nil)."
  (let ((rs (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-redeem-script+))
        (ws (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-witness-script+))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (labels ((ms-witness (script)
               (let ((sigs (%psbt-multisig-sigs script map)))
                 (when sigs (append (list empty) sigs (list script)))))
             (ms-scriptsig (script)
               (let ((sigs (%psbt-multisig-sigs script map)))
                 (when sigs (apply #'%psbt-concat #(#x00)
                                   (mapcar #'%script-push sigs))))))
      (case (bitcoin-lisp.validation:classify-script spk)
        (:pubkeyhash
         (let ((s (%psbt-first-sig map)))
           (when s (values (%psbt-concat (%script-push (cdr s)) (%script-push (car s))) nil))))
        (:pubkey
         (let ((s (%psbt-first-sig map)))
           (when s (values (%script-push (cdr s)) nil))))
        (:witness-v0-keyhash
         (let ((s (%psbt-first-sig map)))
           (when s (values empty (list (cdr s) (car s))))))
        (:multisig
         (let ((ss (ms-scriptsig spk))) (when ss (values ss nil))))
        (:witness-v0-scripthash
         (when ws (let ((wit (ms-witness ws))) (when wit (values empty wit)))))
        (:witness-v1-taproot
         (let ((ks (bitcoin-lisp.serialization:psbt-map-find
                    map bitcoin-lisp.serialization:+psbt-in-tap-key-sig+)))
           (when ks (values empty (list ks)))))
        (:scripthash
         (when rs
           (case (bitcoin-lisp.validation:classify-script rs)
             (:witness-v0-keyhash
              (let ((s (%psbt-first-sig map)))
                (when s (values (%script-push rs) (list (cdr s) (car s))))))
             (:witness-v0-scripthash
              (when ws (let ((wit (ms-witness ws)))
                         (when wit (values (%script-push rs) wit)))))
             (:multisig
              (let ((sigs (%psbt-multisig-sigs rs map)))
                (when sigs
                  (values (apply #'%psbt-concat #(#x00)
                                 (append (mapcar #'%script-push sigs)
                                         (list (%script-push rs))))
                          nil))))
             (:pubkeyhash            ; P2SH-P2PKH: <sig> <pubkey> <redeem>
              (let ((s (%psbt-first-sig map)))
                (when s (values (%psbt-concat (%script-push (cdr s))
                                              (%script-push (car s))
                                              (%script-push rs))
                                nil))))
             (:pubkey               ; P2SH-P2PK: <sig> <redeem>
              (let ((s (%psbt-first-sig map)))
                (when s (values (%psbt-concat (%script-push (cdr s)) (%script-push rs)) nil))))
             (t (values nil nil)))))
        (t (values nil nil))))))

(defun %psbt-set-final (map scriptsig witness)
  "Record final scriptSig/scriptWitness on MAP and drop the now-obsolete signing
fields (partial sigs, sighash, redeem/witness scripts, derivations)."
  ;; A finalized input serializes only its utxo + final scripts: Core's input
  ;; Serialize gates partial sigs / sighash / redeem+witness scripts / key paths
  ;; behind "final scripts empty", so we drop those records here to match its
  ;; on-the-wire output (the utxo fields stay).
  (dolist (kt (list bitcoin-lisp.serialization:+psbt-in-partial-sig+
                    bitcoin-lisp.serialization:+psbt-in-sighash+
                    bitcoin-lisp.serialization:+psbt-in-redeem-script+
                    bitcoin-lisp.serialization:+psbt-in-witness-script+
                    bitcoin-lisp.serialization:+psbt-in-bip32+))
    (bitcoin-lisp.serialization:psbt-map-remove-type map kt))
  (when (and scriptsig (plusp (length scriptsig)))
    (bitcoin-lisp.serialization:psbt-map-set
     map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+
     (make-array 0 :element-type '(unsigned-byte 8)) scriptsig))
  (when witness
    (let ((bb (bitcoin-lisp.serialization:make-byte-buf)))
      (bitcoin-lisp.serialization:bb-write-varint bb (length witness))
      (dolist (item witness)
        (bitcoin-lisp.serialization:bb-write-varint bb (length item))
        (when (plusp (length item)) (bitcoin-lisp.serialization:bb-write-bytes bb item)))
      (bitcoin-lisp.serialization:psbt-map-set
       map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+
       (make-array 0 :element-type '(unsigned-byte 8)) (bitcoin-lisp.serialization:bb-finish bb)))))

(defun %psbt-extract-hex (psbt)
  "Extract the fully-signed network transaction from a finalized PSBT as hex."
  (let* ((tx (bitcoin-lisp.serialization:psbt-tx psbt))
         (ins (bitcoin-lisp.serialization:transaction-inputs tx))
         (nin (length ins))
         (new-ins (make-array nin))
         (witnesses (make-array nin :initial-element nil))
         (any-witness nil))
    (dotimes (i nin)
      (let* ((map (aref (bitcoin-lisp.serialization:psbt-inputs psbt) i))
             (in (aref ins i))
             (ss (or (bitcoin-lisp.serialization:psbt-map-find
                      map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)
                     (make-array 0 :element-type '(unsigned-byte 8))))
             (fw (bitcoin-lisp.serialization:psbt-map-find
                  map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+)))
        (setf (aref new-ins i)
              (bitcoin-lisp.serialization:make-tx-in
               :previous-output (bitcoin-lisp.serialization:tx-in-previous-output in)
               :script-sig ss
               :sequence (bitcoin-lisp.serialization:tx-in-sequence in)))
        (when fw
          (setf any-witness t
                (aref witnesses i)
                (bitcoin-lisp.serialization:br-read-witness-stack
                 (bitcoin-lisp.serialization:make-byte-reader-from fw))))))
    (let ((final-tx (bitcoin-lisp.serialization:make-transaction
                     :version (bitcoin-lisp.serialization:transaction-version tx)
                     :inputs new-ins
                     :outputs (bitcoin-lisp.serialization:transaction-outputs tx)
                     :lock-time (bitcoin-lisp.serialization:transaction-lock-time tx)
                     :witness (if any-witness witnesses nil))))
      (bitcoin-lisp.crypto:bytes-to-hex
       (bitcoin-lisp.serialization:transaction-wire-bytes final-tx)))))

(defun rpc-finalizepsbt (node params)
  "Finalize every input possible; if all are final and EXTRACT (default true),
return the network tx hex. PARAMS: (psbt [extract]). Mirrors Core finalizepsbt."
  (declare (ignore node))
  (let* ((psbt (%psbt-decode-arg (first params)))
         (extract (%positional-bool-or (second params) t))
         (tx (bitcoin-lisp.serialization:psbt-tx psbt))
         (ins (bitcoin-lisp.serialization:transaction-inputs tx))
         (complete t))
    (dotimes (i (length ins))
      (let ((map (aref (bitcoin-lisp.serialization:psbt-inputs psbt) i)))
        (if (or (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)
                (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+))
            nil                          ; already final
            (let ((spk (%psbt-input-spk map (aref ins i))))
              (multiple-value-bind (ss wit) (if spk (%psbt-finalize map spk) (values nil nil))
                (if (or (and ss (plusp (length ss))) wit)
                    (%psbt-set-final map ss wit)
                    (setf complete nil)))))))
    (if (and complete extract)
        `(("hex" . ,(%psbt-extract-hex psbt)) ("complete" . t))
        `(("psbt" . ,(bitcoin-lisp.serialization:encode-psbt psbt))
          ("complete" . ,(json-bool complete))))))

;;; --- combinerawtransaction ---

(defun rpc-combinerawtransaction (node params)
  "Combine partially-signed raw transactions, taking the most-complete scriptSig
and witness per input (prevout script types come from the UTXO set / mempool).
PARAMS: (txs). Mirrors Core combinerawtransaction."
  (declare (ignore node))
  (let ((hexes (first params)))
    (unless (and (listp hexes) (>= (length hexes) 1))
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "txs must be a non-empty array of hex transactions"))
    (let ((txs (mapcar (lambda (h)
                         (handler-case
                             (bitcoin-lisp.serialization:br-read-transaction
                              (bitcoin-lisp.serialization:make-byte-reader-from
                               (coerce (bitcoin-lisp.crypto:hex-to-bytes h)
                                       '(simple-array (unsigned-byte 8) (*)))))
                           (error () (error 'rpc-error :code +rpc-deserialization-error+
                                                       :message "TX decode failed"))))
                       hexes)))
      (let* ((base (first txs))
             (nin (length (bitcoin-lisp.serialization:transaction-inputs base)))
             (merged-ins (make-array nin))
             (witnesses (make-array nin :initial-element nil))
             (any-witness nil))
        (dolist (tx (rest txs))
          (unless (= (length (bitcoin-lisp.serialization:transaction-inputs tx)) nin)
            (error 'rpc-error :code +rpc-deserialization-error+
                              :message "Input count mismatch between transactions")))
        (dotimes (i nin)
          (let ((best-ss (bitcoin-lisp.serialization:tx-in-script-sig
                          (aref (bitcoin-lisp.serialization:transaction-inputs base) i)))
                (best-wit nil)
                (in0 (aref (bitcoin-lisp.serialization:transaction-inputs base) i)))
            (dolist (tx txs)
              (let* ((in (aref (bitcoin-lisp.serialization:transaction-inputs tx) i))
                     (ss (bitcoin-lisp.serialization:tx-in-script-sig in))
                     (w (%tx-input-witness tx i)))
                (when (> (length ss) (length best-ss)) (setf best-ss ss))
                (when (and w (plusp (length w))
                           (or (null best-wit) (> (length w) (length best-wit))))
                  (setf best-wit w))))
            (when best-wit (setf any-witness t (aref witnesses i) best-wit))
            (setf (aref merged-ins i)
                  (bitcoin-lisp.serialization:make-tx-in
                   :previous-output (bitcoin-lisp.serialization:tx-in-previous-output in0)
                   :script-sig best-ss
                   :sequence (bitcoin-lisp.serialization:tx-in-sequence in0)))))
        (let ((merged (bitcoin-lisp.serialization:make-transaction
                       :version (bitcoin-lisp.serialization:transaction-version base)
                       :inputs merged-ins
                       :outputs (bitcoin-lisp.serialization:transaction-outputs base)
                       :lock-time (bitcoin-lisp.serialization:transaction-lock-time base)
                       :witness (if any-witness witnesses nil))))
          (bitcoin-lisp.crypto:bytes-to-hex
           (bitcoin-lisp.serialization:transaction-wire-bytes merged)))))))

;;;; =====================================================================
;;;; Wallet P5 — PSBT SIGNER role: walletprocesspsbt, descriptorprocesspsbt,
;;;; walletcreatefundedpsbt (wallet/rpc/spend.cpp, rpc/rawtransaction.cpp) +
;;;; RBF fee-bump: bumpfee, psbtbumpfee (wallet/feebumper.cpp).
;;;; =====================================================================
;;;;
;;;; The signer REUSES the funds-critical sighash+sign dispatch factored out of
;;;; the in-place spend signer: %compute-input-signatures (methods.lisp) computes
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
  (let ((tx (bitcoin-lisp.serialization:psbt-tx psbt))
        (coins (make-hash-table :test 'equalp)))
    (loop for map across (bitcoin-lisp.serialization:psbt-inputs psbt)
          for in across (bitcoin-lisp.serialization:transaction-inputs tx)
          for op = (bitcoin-lisp.serialization:tx-in-previous-output in)
          for spk = (%psbt-input-spk map in)
          do (when spk
               (let ((amount (%psbt-input-amount map in))
                     (redeem (bitcoin-lisp.serialization:psbt-map-find
                              map bitcoin-lisp.serialization:+psbt-in-redeem-script+))
                     (witness (bitcoin-lisp.serialization:psbt-map-find
                               map bitcoin-lisp.serialization:+psbt-in-witness-script+)))
                 (when (and wallet (or (null redeem) (null witness)))
                   (multiple-value-bind (wr ww) (%known-sub-scripts wallet cc spk)
                     (setf redeem (or redeem wr) witness (or witness ww))))
                 (setf (gethash (cons (bitcoin-lisp.serialization:outpoint-hash op)
                                      (bitcoin-lisp.serialization:outpoint-index op))
                                coins)
                       (list spk amount redeem witness)))))
    coins))

(defun %psbt-input-signed-p (map)
  "Core PSBTInputSigned (psbt.h): the input already carries a final scriptSig
or final scriptWitness, so a filler has nothing left to add."
  (or (bitcoin-lisp.serialization:psbt-map-find
       map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)
      (bitcoin-lisp.serialization:psbt-map-find
       map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+)))

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
  (let ((tx (bitcoin-lisp.serialization:psbt-tx psbt))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for map across (bitcoin-lisp.serialization:psbt-inputs psbt)
          for in across (bitcoin-lisp.serialization:transaction-inputs tx)
          for op = (bitcoin-lisp.serialization:tx-in-previous-output in)
          do (unless (or (%psbt-input-signed-p map)
                         (bitcoin-lisp.serialization:psbt-map-find
                          map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+))
               (let ((wtx (wallet-get-wallet-tx
                           wallet (bitcoin-lisp.serialization:outpoint-hash op))))
                 (when wtx
                   (bitcoin-lisp.serialization:psbt-map-set
                    map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+ empty
                    (bitcoin-lisp.serialization:transaction-wire-bytes
                     (wallet-tx-tx wtx)))))))))

(defun %psbt-fill-node-utxos (psbt node)
  "For witness inputs with no UTXO field, add witness_utxo from the node's UTXO
set (descriptorprocesspsbt updates segwit inputs from the UTXO set / mempool)."
  (let ((tx (bitcoin-lisp.serialization:psbt-tx psbt))
        (utxo-set (rpc-get-utxo-set node)))
    (when utxo-set
      (loop for map across (bitcoin-lisp.serialization:psbt-inputs psbt)
            for in across (bitcoin-lisp.serialization:transaction-inputs tx)
            for op = (bitcoin-lisp.serialization:tx-in-previous-output in)
            do (unless (or (bitcoin-lisp.serialization:psbt-map-find
                            map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)
                           (bitcoin-lisp.serialization:psbt-map-find
                            map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+))
                 (let ((entry (bitcoin-lisp.storage:get-utxo
                               utxo-set
                               (bitcoin-lisp.serialization:outpoint-hash op)
                               (bitcoin-lisp.serialization:outpoint-index op))))
                   (when (and entry (%psbt-witness-spk-p
                                     (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)))
                     (let ((bb (bitcoin-lisp.serialization:make-byte-buf)))
                       (bitcoin-lisp.serialization:bb-write-tx-out
                        bb (bitcoin-lisp.serialization:make-tx-out
                            :value (bitcoin-lisp.storage:utxo-entry-value entry)
                            :script-pubkey (bitcoin-lisp.storage:utxo-entry-script-pubkey entry)))
                       (bitcoin-lisp.serialization:psbt-map-set
                        map bitcoin-lisp.serialization:+psbt-in-witness-utxo+
                        (make-array 0 :element-type '(unsigned-byte 8))
                        (bitcoin-lisp.serialization:bb-finish bb))))))))))

;;; --- Recording signatures + derivations ---

(defun %psbt-input-sighash-stored (map)
  (let ((sh (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-sighash+)))
    (and sh (loop for j below 4 sum (ash (aref sh j) (* 8 j))))))

(defun %psbt-effective-sighash (spk user-sighash stored-sighash)
  "(values effective-byte record-p error). Core SignPSBTInput: effective = USER
param, else SIGHASH_DEFAULT(0) for taproot / SIGHASH_ALL(1) otherwise; a stored
+psbt-in-sighash+ must match. RECORD-P is true when EFFECTIVE is non-default and
must be written to the input (taproot: != DEFAULT; else != DEFAULT and != ALL)."
  (let* ((taproot (eq (bitcoin-lisp.validation:classify-script spk)
                      :witness-v1-taproot))
         (eff (or user-sighash (if taproot #x00 #x01))))
    (when (and stored-sighash (/= stored-sighash eff))
      (return-from %psbt-effective-sighash
        (values nil nil "Specified sighash and sighash in PSBT do not match.")))
    (values eff
            (if taproot (/= eff #x00) (and (/= eff #x00) (/= eff #x01)))
            nil)))

(defun %input-sig-witness-p (sig)
  "True when the input-sig SIG is a segwit (witness) signature — the kinds for
which Core's ProduceSignature sets SignatureData.witness. Legacy kinds (:p2pkh,
:multisig, :p2sh-multisig) are false."
  (and (member (input-sig-kind sig)
               '(:p2wpkh :p2tr :p2wsh :p2sh-p2wpkh :p2sh-p2wsh))
       t))

(defun %psbt-require-witness-sig-p (map)
  "Core SignPSBTInput's require_witness_sig: an input whose only prevout source is
the witness_utxo (no non_witness_utxo) can only be signed with a witness
signature — witness_utxo alone cannot authenticate a non-witness (legacy) spend,
so a legacy signature over it must be refused. True when witness_utxo is present
and non_witness_utxo is absent."
  (and (bitcoin-lisp.serialization:psbt-map-find
        map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)
       (not (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+))))

(defun %psbt-record-signatures (psbt coins keymap pubmap tr-keymap user-sighash)
  "Compute + record partial signatures on every non-final input of PSBT the key
maps can satisfy, sourcing prevouts from COINS. ECDSA partial sigs go into
+psbt-in-partial-sig+ (keyed by pubkey), taproot key-path sigs into
+psbt-in-tap-key-sig+; a non-default sighash into +psbt-in-sighash+, and the
P2SH/P2WSH sub-scripts revealed (needed for finalization). Never finalizes. A
key we do not hold (or an unsourceable prevout) leaves the input untouched."
  (let* ((tx (bitcoin-lisp.serialization:psbt-tx psbt))
         (inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (n (length inputs))
         (spent-utxos (%build-spent-utxos inputs coins))
         (bitcoin-lisp.coalton.interop::*current-tx* tx)
         (bitcoin-lisp.coalton.interop::*current-spent-utxos* spent-utxos)
         (precomp (bitcoin-lisp.coalton.interop::init-precomputed-sighash tx spent-utxos))
         (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (dotimes (i n)
      (let* ((map (aref (bitcoin-lisp.serialization:psbt-inputs psbt) i))
             (in (aref inputs i))
             (op (bitcoin-lisp.serialization:tx-in-previous-output in))
             (prev (gethash (cons (bitcoin-lisp.serialization:outpoint-hash op)
                                  (bitcoin-lisp.serialization:outpoint-index op))
                            coins)))
        (unless (or (null prev)
                    (bitcoin-lisp.serialization:psbt-map-find
                     map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)
                    (bitcoin-lisp.serialization:psbt-map-find
                     map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+))
          (multiple-value-bind (eff record-p sherr)
              (%psbt-effective-sighash (first prev) user-sighash
                                       (%psbt-input-sighash-stored map))
            (unless sherr
              (multiple-value-bind (sig err)
                  (%compute-input-signatures tx i prev keymap pubmap tr-keymap
                                             (if (zerop eff) #x01 eff)
                                             precomp spent-utxos eff)
                ;; Core SignPSBTInput's require_witness_sig gate: never record a
                ;; legacy (non-witness) signature for an input sourced only from
                ;; the witness_utxo — Core refuses it (a witness_utxo cannot
                ;; authenticate a non-witness spend).
                (unless (or err
                            (and (%psbt-require-witness-sig-p map)
                                 (not (%input-sig-witness-p sig))))
                  (when (and (input-sig-redeem sig)
                             (not (bitcoin-lisp.serialization:psbt-map-find
                                   map bitcoin-lisp.serialization:+psbt-in-redeem-script+)))
                    (bitcoin-lisp.serialization:psbt-map-set
                     map bitcoin-lisp.serialization:+psbt-in-redeem-script+ empty
                     (input-sig-redeem sig)))
                  (when (and (input-sig-witness-script sig)
                             (not (bitcoin-lisp.serialization:psbt-map-find
                                   map bitcoin-lisp.serialization:+psbt-in-witness-script+)))
                    (bitcoin-lisp.serialization:psbt-map-set
                     map bitcoin-lisp.serialization:+psbt-in-witness-script+ empty
                     (input-sig-witness-script sig)))
                  (when record-p
                    (bitcoin-lisp.serialization:psbt-map-set
                     map bitcoin-lisp.serialization:+psbt-in-sighash+ empty
                     (%psbt-uint32-le eff)))
                  ;; Core CreateSig reuses a signature already present for a key
                  ;; (input.FillSignatureData loads existing partial_sigs) rather
                  ;; than re-signing — so an input already signed by this pubkey
                  ;; keeps its existing sig. Never overwrite one we already hold.
                  (dolist (pair (input-sig-ecdsa sig))
                    (unless (%psbt-sig-for map (car pair))
                      (bitcoin-lisp.serialization:psbt-map-set
                       map bitcoin-lisp.serialization:+psbt-in-partial-sig+
                       (car pair) (cdr pair))))
                  (when (and (input-sig-tap sig)
                             (not (bitcoin-lisp.serialization:psbt-map-find
                                   map bitcoin-lisp.serialization:+psbt-in-tap-key-sig+)))
                    (bitcoin-lisp.serialization:psbt-map-set
                     map bitcoin-lisp.serialization:+psbt-in-tap-key-sig+ empty
                     (input-sig-tap sig))))))))))))

(defun %psbt-add-map-derivs (map spk pos pairs)
  "Add +psbt-in-bip32+ (ECDSA) / +psbt-in-tap-internal-key+ (taproot) records to
MAP for the (desc-key . pubkey) PAIRS expanded at POS for scriptPubKey SPK."
  (let ((taproot (eq (bitcoin-lisp.validation:classify-script spk)
                     :witness-v1-taproot))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for (key . pubkey) in pairs
          do (if taproot
                 (bitcoin-lisp.serialization:psbt-map-set
                  map bitcoin-lisp.serialization:+psbt-in-tap-internal-key+ empty
                  (%key-xonly-bytes pubkey))
                 (multiple-value-bind (fpr path) (%desc-key-origin-info key pubkey pos)
                   (bitcoin-lisp.serialization:psbt-map-set
                    map bitcoin-lisp.serialization:+psbt-in-bip32+ pubkey
                    (%psbt-bip32-value fpr path)))))))

(defun %psbt-add-wallet-input-derivs (psbt coins wallet)
  "Add input bip32 derivations / taproot internal keys for wallet-owned inputs
(Core FillPSBT bip32derivs). Metadata only — helps offline signers."
  (let ((tx (bitcoin-lisp.serialization:psbt-tx psbt)))
    (loop for map across (bitcoin-lisp.serialization:psbt-inputs psbt)
          for in across (bitcoin-lisp.serialization:transaction-inputs tx)
          for op = (bitcoin-lisp.serialization:tx-in-previous-output in)
          for entry = (gethash (cons (bitcoin-lisp.serialization:outpoint-hash op)
                                     (bitcoin-lisp.serialization:outpoint-index op))
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
  (let ((tx (bitcoin-lisp.serialization:psbt-tx psbt))
        (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (loop for map across (bitcoin-lisp.serialization:psbt-outputs psbt)
          for out across (bitcoin-lisp.serialization:transaction-outputs tx)
          for spk = (bitcoin-lisp.serialization:tx-out-script-pubkey out)
          do (multiple-value-bind (spkm pos) (%wallet-owning-spkm wallet spk)
               (when spkm
                 (multiple-value-bind (redeem witness) (%spkm-sub-scripts spkm spk)
                   (when redeem
                     (bitcoin-lisp.serialization:psbt-map-set
                      map bitcoin-lisp.serialization:+psbt-out-redeem-script+ empty redeem))
                   (when witness
                     (bitcoin-lisp.serialization:psbt-map-set
                      map bitcoin-lisp.serialization:+psbt-out-witness-script+ empty witness)))
                 (multiple-value-bind (scripts pairs) (%spkm-expansion-pairs spkm pos)
                   (declare (ignore scripts))
                   (let ((taproot (eq (bitcoin-lisp.validation:classify-script spk)
                                      :witness-v1-taproot)))
                     (loop for (key . pubkey) in pairs
                           do (if taproot
                                  (bitcoin-lisp.serialization:psbt-map-set
                                   map bitcoin-lisp.serialization:+psbt-out-tap-internal-key+
                                   empty (%key-xonly-bytes pubkey))
                                  (multiple-value-bind (fpr path)
                                      (%desc-key-origin-info key pubkey pos)
                                    (bitcoin-lisp.serialization:psbt-map-set
                                     map bitcoin-lisp.serialization:+psbt-out-bip32+ pubkey
                                     (%psbt-bip32-value fpr path))))))))))))

;;; --- Completeness / extract ---

(defun %psbt-finalize-in-place (psbt)
  "Finalize every finalizable input of PSBT in place (finalizepsbt machinery).
Returns T when EVERY input is final."
  (let* ((tx (bitcoin-lisp.serialization:psbt-tx psbt))
         (ins (bitcoin-lisp.serialization:transaction-inputs tx))
         (complete t))
    (dotimes (i (length ins))
      (let ((map (aref (bitcoin-lisp.serialization:psbt-inputs psbt) i)))
        (if (or (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-final-scriptsig+)
                (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-final-scriptwitness+))
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
  (bitcoin-lisp.serialization:decode-psbt
   (bitcoin-lisp.serialization:encode-psbt psbt)))

(defun %psbt-signer-result (psbt finalize)
  "The {psbt, complete, hex?} object of walletprocesspsbt / descriptorprocesspsbt.
When FINALIZE, PSBT is finalized in place; completeness + the extracted hex are
computed from a finalized COPY either way (Core returns the network tx whenever
every input can be finalized, even without finalize=true)."
  (when finalize (%psbt-finalize-in-place psbt))
  (let* ((trial (%psbt-copy psbt))
         (complete (%psbt-finalize-in-place trial)))
    (append `(("psbt" . ,(bitcoin-lisp.serialization:encode-psbt psbt))
              ("complete" . ,(json-bool complete)))
            (when complete
              `(("hex" . ,(%psbt-extract-hex trial)))))))

;;; --- walletprocesspsbt (wallet/rpc/spend.cpp:1573) ---

(defun rpc-walletprocesspsbt (node params)
  "Update a PSBT with wallet input info and sign the inputs we can (Bitcoin Core
walletprocesspsbt). PARAMS: (psbt [sign] [sighashtype] [bip32derivs] [finalize]).
Returns {psbt, complete, hex?}."
  (let ((wallet (wallet-for-request node)))
    (with-node-lock (node)
      (with-wallet-lock (wallet)
        (let* ((psbt (%psbt-decode-arg (first params)))
               (sign (%positional-bool-or (second params) t))
               (user-sighash (multiple-value-bind (byte default-p)
                                 (%wallet-sighash-byte (third params))
                               (if default-p nil byte)))
               (bip32derivs (%positional-bool-or (fourth params) t))
               (finalize (%positional-bool-or (fifth params) t)))
          (when (and sign (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+))
            (error 'rpc-error :code +rpc-wallet-error+
                              :message "Error: Private keys are disabled for this wallet"))
          (when sign (wallet-ensure-unlocked wallet))
          (%psbt-fill-wallet-utxos psbt wallet)
          (let ((coins (%psbt-coins-map psbt wallet nil)))
            (when bip32derivs
              (%psbt-add-wallet-input-derivs psbt coins wallet)
              (%psbt-add-wallet-output-derivs psbt wallet))
            (when sign
              (multiple-value-bind (keymap pubmap tr-keymap)
                  (%wallet-sign-maps wallet (bitcoin-lisp.serialization:psbt-tx psbt) coins)
                (%psbt-record-signatures psbt coins keymap pubmap tr-keymap user-sighash)))
            (%psbt-signer-result psbt finalize)))))))

;;; --- descriptorprocesspsbt (rpc/rawtransaction.cpp:1992) ---

(defun %psbt-descriptor-expansions (descs network)
  "script-pubkey -> (desc pos pairs) for every script the descriptor DESCS
produce over their ranges (EvalDescriptorStringOrObject: default [0,1000] ranged
/ [0,0] unranged). PAIRS are (desc-key . derived-pubkey) in expression order —
the input to %sign-map-add-key! and the derivations."
  (let ((table (make-hash-table :test 'equalp)))
    (unless (listp descs)
      (error 'rpc-error :code +rpc-invalid-parameter+
                        :message "descriptors must be an array"))
    (dolist (d descs table)
      (multiple-value-bind (desc-str range)
          (cond ((stringp d) (values d nil))
                ((hash-table-p d) (values (gethash "desc" d) (gethash "range" d)))
                ((and (consp d) (consp (car d)))
                 (values (cdr (assoc "desc" d :test #'string=))
                         (cdr (assoc "range" d :test #'string=))))
                (t (error 'rpc-error :code +rpc-invalid-parameter+
                                     :message "Descriptor needs to be provided in the object")))
        (unless (stringp desc-str)
          (error 'rpc-error :code +rpc-invalid-parameter+
                            :message "Descriptor needs to be provided in the object"))
        (let ((desc (parse-descriptor desc-str network)))
          (multiple-value-bind (low high)
              (cond ((not (out-desc-ranged-p desc)) (values 0 0))
                    (range (%parse-descriptor-range range))
                    (t (values 0 1000)))
            (loop for pos from low to high
                  do (let ((cache (make-descriptor-cache)))
                       (multiple-value-bind (scripts pubkeys)
                           (handler-case
                               (out-desc-expand-with-provider desc pos nil cache)
                             (error () (values nil nil)))
                         (when scripts
                           (let ((pairs (mapcar #'cons (out-desc-ordered-keys desc)
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
    (bitcoin-lisp.serialization:dovector
        (in (bitcoin-lisp.serialization:transaction-inputs tx))
      (let* ((op (bitcoin-lisp.serialization:tx-in-previous-output in))
             (entry (gethash (cons (bitcoin-lisp.serialization:outpoint-hash op)
                                   (bitcoin-lisp.serialization:outpoint-index op))
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
  (let ((tx (bitcoin-lisp.serialization:psbt-tx psbt)))
    (loop for map across (bitcoin-lisp.serialization:psbt-inputs psbt)
          for in across (bitcoin-lisp.serialization:transaction-inputs tx)
          for op = (bitcoin-lisp.serialization:tx-in-previous-output in)
          for entry = (gethash (cons (bitcoin-lisp.serialization:outpoint-hash op)
                                     (bitcoin-lisp.serialization:outpoint-index op))
                               coins)
          for spk = (and entry (first entry))
          for exp = (and spk (gethash spk expansions))
          do (when exp
               (destructuring-bind (desc pos pairs) exp
                 (declare (ignore desc))
                 (%psbt-add-map-derivs map spk pos pairs))))))

(defun rpc-descriptorprocesspsbt (node params)
  "Update a PSBT's segwit inputs from output descriptors + the UTXO set, then
sign the inputs the descriptors can (Bitcoin Core descriptorprocesspsbt).
PARAMS: (psbt descriptors [sighashtype] [bip32derivs] [finalize])."
  (with-node-lock (node)
    (let* ((network (rpc-get-network node))
           (psbt (%psbt-decode-arg (first params)))
           (expansions (%psbt-descriptor-expansions (second params) network))
           (user-sighash (multiple-value-bind (byte default-p)
                             (%wallet-sighash-byte (third params))
                           (if default-p nil byte)))
           (bip32derivs (%positional-bool-or (fourth params) t))
           (finalize (%positional-bool-or (fifth params) t)))
      (%psbt-fill-node-utxos psbt node)
      (let ((coins (%psbt-coins-map psbt)))
        (when bip32derivs
          (%psbt-add-descriptor-input-derivs psbt coins expansions))
        (multiple-value-bind (keymap pubmap tr-keymap)
            (%descriptor-sign-maps expansions (bitcoin-lisp.serialization:psbt-tx psbt) coins)
          (%psbt-record-signatures psbt coins keymap pubmap tr-keymap user-sighash))
        (%psbt-signer-result psbt finalize)))))

;;; --- The PSBT-from-wallet path (shared by walletcreatefundedpsbt +
;;; psbtbumpfee): an UNSIGNED PSBT with UTXOs + bip32 derivations. ---

(defun %wallet-unsigned-psbt (node wallet tx bip32derivs)
  "Build an UNSIGNED PSBT for the wallet-funded TX: witness_utxo (+ non_witness_utxo
when the full previous tx is in the wallet) per input, plus, when BIP32DERIVS,
input/output bip32 derivations. Mirrors Core FillPSBT(sign=false)."
  (let* ((inputs (bitcoin-lisp.serialization:transaction-inputs tx))
         (psbt (bitcoin-lisp.serialization:make-empty-psbt tx))
         (coins (%wallet-input-coins node wallet tx))
         (empty (make-array 0 :element-type '(unsigned-byte 8))))
    (dotimes (i (length inputs))
      (let* ((in (aref inputs i))
             (op (bitcoin-lisp.serialization:tx-in-previous-output in))
             (txid (bitcoin-lisp.serialization:outpoint-hash op))
             (vout (bitcoin-lisp.serialization:outpoint-index op))
             (entry (gethash (cons txid vout) coins))
             (map (aref (bitcoin-lisp.serialization:psbt-inputs psbt) i)))
        (when entry
          (bitcoin-lisp.serialization:psbt-map-set
           map bitcoin-lisp.serialization:+psbt-in-witness-utxo+ empty
           (%serialize-txout-bytes
            (bitcoin-lisp.serialization:make-tx-out
             :value (second entry) :script-pubkey (first entry))))
          (when (third entry)
            (bitcoin-lisp.serialization:psbt-map-set
             map bitcoin-lisp.serialization:+psbt-in-redeem-script+ empty (third entry)))
          (when (fourth entry)
            (bitcoin-lisp.serialization:psbt-map-set
             map bitcoin-lisp.serialization:+psbt-in-witness-script+ empty (fourth entry)))
          (let ((wtx (wallet-get-wallet-tx wallet txid)))
            (when wtx
              (bitcoin-lisp.serialization:psbt-map-set
               map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+ empty
               (bitcoin-lisp.serialization:transaction-wire-bytes (wallet-tx-tx wtx))))))))
    (when bip32derivs
      (%psbt-add-wallet-input-derivs psbt coins wallet)
      (%psbt-add-wallet-output-derivs psbt wallet))
    (bitcoin-lisp.serialization:encode-psbt psbt)))

;;; --- walletcreatefundedpsbt (wallet/rpc/spend.cpp:1657) ---

(defun rpc-walletcreatefundedpsbt (node params)
  "Create + fund a PSBT (Creator + Updater). PARAMS: (inputs outputs [locktime]
[options] [bip32derivs] [version]). Returns {psbt, fee, changepos}. JSON-object
outputs arrive as hash tables whose key order is not preserved; use the
array-of-objects form when output order matters."
  (let ((wallet (wallet-for-request node)))
    (with-node-lock (node)
      (with-wallet-lock (wallet)
        (let* ((options (or (nth 3 params) '()))
               (version (let ((v (nth 5 params))) (if (integerp v) v 2)))
               (rbf (if (%opt-present-p options "replaceable")
                        (and (%opt options "replaceable") t)
                        *wallet-signal-rbf*))
               (locktime (or (nth 2 params) 0))
               (inputs (%parse-rpc-inputs (or (first params) '())))
               (bip32derivs (%positional-bool-or (nth 4 params) t))
               (cc (make-wcc :version version)))
          (unless (and (integerp locktime) (<= 0 locktime #xffffffff))
            (error 'rpc-error :code +rpc-invalid-parameter+
                              :message "Invalid parameter, locktime out of range"))
          (multiple-value-bind (recipients keys)
              (%parse-outputs (wallet-network wallet) (second params))
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
                  (error 'rpc-error :code +rpc-wallet-error+ :message fee))
                `(("psbt" . ,(%wallet-unsigned-psbt node wallet tx bip32derivs))
                  ("fee" . ,(%btc fee))
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
                          wallet (%script->address script (wallet-network wallet)))))))

(defun %all-inputs-mine (node wallet tx)
  "Core AllInputsMine: every input of TX spends a wallet-owned output."
  (block scan
    (bitcoin-lisp.serialization:dovector
        (in (bitcoin-lisp.serialization:transaction-inputs tx))
      (let* ((op (bitcoin-lisp.serialization:tx-in-previous-output in))
             (txout (%wallet-input-txout node wallet
                                         (bitcoin-lisp.serialization:outpoint-hash op)
                                         (bitcoin-lisp.serialization:outpoint-index op))))
        (unless (and txout (wallet-is-mine
                            wallet (bitcoin-lisp.serialization:tx-out-script-pubkey txout)))
          (return-from scan nil))))
    t))

(defun %wallet-has-spend (wallet tx)
  "Core CWallet::HasWalletSpend: a wallet tx spends one of TX's outputs."
  (let ((txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (dotimes (n (length (bitcoin-lisp.serialization:transaction-outputs tx)) nil)
      (when (gethash (%wtx-outpoint-key txid n) (wallet-tx-spends wallet))
        (return t)))))

(defun %bump-precondition-checks (node wallet wtx require-mine)
  "Core feebumper::PreconditionChecks. Returns (values ok error-code error-msg).
Adds the task-mandated BIP125-replaceable requirement on the original tx."
  (let ((tx (wallet-tx-tx wtx))
        (mempool (bitcoin-lisp::node-mempool node)))
    (cond
      ((%wallet-has-spend wallet tx)
       (values nil +rpc-invalid-parameter+ "Transaction has descendants in the wallet"))
      ((and mempool (plusp (hash-table-count
                            (bitcoin-lisp.mempool:mempool-descendants
                             mempool (wallet-tx-txid wtx)))))
       (values nil +rpc-invalid-parameter+ "Transaction has descendants in the mempool"))
      ((/= (wallet-tx-depth wallet wtx) 0)
       (values nil +rpc-wallet-error+
               "Transaction has been mined, or is conflicted with a mined transaction"))
      ((assoc "replaced_by_txid" (wallet-tx-map-value wtx) :test #'string=)
       (values nil +rpc-wallet-error+
               (format nil "Cannot bump transaction ~A which was already bumped by transaction ~A"
                       (hash-to-hex (wallet-tx-txid wtx))
                       (cdr (assoc "replaced_by_txid" (wallet-tx-map-value wtx) :test #'string=)))))
      ((not (bitcoin-lisp.mempool:tx-signals-rbf-p tx))
       (values nil +rpc-wallet-error+
               "Transaction is not BIP 125 replaceable"))
      ((and require-mine (not (%all-inputs-mine node wallet tx)))
       (values nil +rpc-wallet-error+
               "Transaction contains inputs that don't belong to this wallet"))
      (t (values t nil nil)))))

(defun %bump-estimate-feerate (node wallet orig old-fee cc)
  "Core feebumper::EstimateFeeRate (sat/kvB): the original feerate + 1 sat/kvB +
max(node incremental, wallet incremental), floored at GetMinimumFeeRate."
  (declare (ignore wallet))
  (let* ((txsize (bitcoin-lisp.serialization:transaction-vsize orig))
         (base (if (plusp txsize) (floor (* old-fee 1000) txsize) 0))
         (feerate (+ base 1 (max bitcoin-lisp.mempool::+incremental-relay-fee-rate+
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
        (values nil +rpc-invalid-address-or-key+ "Invalid or non-wallet transaction id")))
    (let* ((orig (wallet-tx-tx wtx))
           (inputs (bitcoin-lisp.serialization:transaction-inputs orig))
           (input-value 0))
      ;; Retrieve every input's coin; select it on the coin control (external
      ;; inputs get their txout preset). A spent input aborts.
      (bitcoin-lisp.serialization:dovector (in inputs)
        (let* ((op (bitcoin-lisp.serialization:tx-in-previous-output in))
               (thash (bitcoin-lisp.serialization:outpoint-hash op))
               (n (bitcoin-lisp.serialization:outpoint-index op))
               (txout (%wallet-input-txout node wallet thash n)))
          (unless txout
            (return-from %create-rate-bump
              (values nil +rpc-misc-error+
                      (format nil "~A:~D is already spent" (hash-to-hex thash) n))))
          (let ((preset (wcc-select cc thash n)))
            (unless (wallet-is-mine wallet (bitcoin-lisp.serialization:tx-out-script-pubkey txout))
              (setf (wcc-preset-txout preset) txout)))
          (incf input-value (bitcoin-lisp.serialization:tx-out-value txout))))
      ;; Preconditions.
      (multiple-value-bind (ok code msg)
          (%bump-precondition-checks node wallet wtx require-mine)
        (unless ok (return-from %create-rate-bump (values nil code msg))))
      (let* ((output-value (reduce #'+ (bitcoin-lisp.serialization:transaction-outputs orig)
                                   :key #'bitcoin-lisp.serialization:tx-out-value
                                   :initial-value 0))
             (old-fee (- input-value output-value))
             (network (wallet-network wallet))
             (recipients '()))
        ;; Recipients = original outputs; a single change output becomes destChange.
        (bitcoin-lisp.serialization:dovector
            (out (bitcoin-lisp.serialization:transaction-outputs orig))
          (let ((spk (bitcoin-lisp.serialization:tx-out-script-pubkey out)))
            (if (%output-is-change wallet spk)
                (setf (wcc-dest-change cc) spk)
                (push (make-recipient :script spk
                                      :amount (bitcoin-lisp.serialization:tx-out-value out)
                                      :address (%script->address spk network))
                      recipients))))
        (setf recipients (nreverse recipients))
        (when (null recipients)
          (unless (wcc-dest-change cc)
            (return-from %create-rate-bump
              (values nil +rpc-invalid-parameter+
                      "Unable to create transaction. Transaction must have at least one recipient")))
          (push (make-recipient :script (wcc-dest-change cc) :amount output-value :sffo t
                                :address (%script->address (wcc-dest-change cc) network))
                recipients)
          (setf (wcc-dest-change cc) nil))
        ;; Feerate: user-provided (already on CC) or estimated from the old fee.
        (if (wcc-feerate cc)
            (setf (wcc-override-feerate cc) t)
            (setf (wcc-feerate cc) (%bump-estimate-feerate node wallet orig old-fee cc)
                  (wcc-override-feerate cc) t))
        ;; Re-spend all original inputs; may add more; no new unconfirmed inputs.
        (bitcoin-lisp.serialization:dovector (in inputs)
          (let ((op (bitcoin-lisp.serialization:tx-in-previous-output in)))
            (wcc-select cc (bitcoin-lisp.serialization:outpoint-hash op)
                        (bitcoin-lisp.serialization:outpoint-index op))))
        (setf (wcc-allow-other-inputs cc) t
              (wcc-min-depth cc) 1)
        (multiple-value-bind (new-tx new-fee) (%create-transaction node wallet recipients nil cc nil)
          (unless new-tx
            (return-from %create-rate-bump
              (values nil +rpc-wallet-error+
                      (format nil "Unable to create transaction. ~A" new-fee))))
          ;; BIP125 rule 3/4 (feebumper::CheckFeeRate minTotalFee): the new total
          ;; fee must be at least the old fee plus one incremental relay fee over
          ;; the replacement's size, or the node's mempool will reject it. Enforce
          ;; it here so a too-low bump fails BEFORE we sign / mark the original
          ;; replaced (%create-transaction already caps at -maxtxfee).
          (let ((min-total (+ old-fee
                              (%feerate-fee bitcoin-lisp.mempool::+incremental-relay-fee-rate+
                                            (bitcoin-lisp.serialization:transaction-vsize new-tx)))))
            (when (< new-fee min-total)
              (return-from %create-rate-bump
                (values nil +rpc-invalid-parameter+
                        (format nil "Insufficient total fee ~A, must be at least ~A (oldFee ~A + incrementalFee)"
                                (%format-money new-fee) (%format-money min-total)
                                (%format-money old-fee))))))
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
    (unless (and (stringp txid-hex) (valid-hex-hash-p txid-hex))
      (error 'rpc-error :code +rpc-invalid-parameter+ :message "txid must be a hex string"))
    (with-node-lock (node)
      (with-wallet-lock (wallet)
        (when (and (not want-psbt)
                   (wallet-flag-set-p wallet +wallet-flag-disable-private-keys+))
          (error 'rpc-error :code +rpc-wallet-error+
                            :message "bumpfee is not available with wallets that have private keys disabled. Use psbtbumpfee instead."))
        ;; Core gates BOTH bumpfee and psbtbumpfee: building the
        ;; replacement needs the keypool and, for bumpfee, the signature.
        (wallet-ensure-unlocked wallet)
        (let ((txid (parse-hex-hash txid-hex))
              (cc (make-wcc)))
          (setf (wcc-signal-bip125-rbf cc) t)   ; Core: default true, RBF replacement
          (%bumpfee-options->cc (second params) cc)
          (multiple-value-bind (mtx old-fee new-fee code msg)
              (%create-rate-bump node wallet txid cc (not want-psbt))
            (unless mtx
              (error 'rpc-error :code code :message msg))
            (if want-psbt
                `(("psbt" . ,(%wallet-unsigned-psbt node wallet mtx t))
                  ("origfee" . ,(%btc old-fee))
                  ("fee" . ,(%btc new-fee))
                  ("errors" . ,#()))
                (progn
                  ;; Sign in place with the wallet keys, then verify.
                  (let ((coins (%wallet-input-coins node wallet mtx cc)))
                    (when (%wallet-sign-transaction wallet mtx coins)
                      (error 'rpc-error :code +rpc-wallet-error+ :message "Can't sign transaction."))
                    (multiple-value-bind (verified bad) (%verify-tx-scripts mtx coins)
                      (unless verified
                        (error 'rpc-error :code +rpc-wallet-error+
                                          :message (format nil "Internal bug detected: bumped transaction fails script verification at input ~D" bad)))))
                  ;; Re-check preconditions, commit + broadcast, mark replaced.
                  (let ((old-wtx (wallet-get-wallet-tx wallet txid)))
                    (multiple-value-bind (ok code2 msg2)
                        (%bump-precondition-checks node wallet old-wtx nil)
                      (unless ok (error 'rpc-error :code code2 :message msg2)))
                    (let ((new-txid (bitcoin-lisp.serialization:transaction-hash mtx)))
                      (%wallet-commit-transaction
                       node wallet mtx
                       (list (cons "replaces_txid" (hash-to-hex txid))))
                      ;; MarkReplaced: record the bump on the original tx.
                      (setf (wallet-tx-map-value old-wtx)
                            (append (remove "replaced_by_txid" (wallet-tx-map-value old-wtx)
                                            :key #'car :test #'string=)
                                    (list (cons "replaced_by_txid" (hash-to-hex new-txid)))))
                      `(("txid" . ,(hash-to-hex new-txid))
                        ("origfee" . ,(%btc old-fee))
                        ("fee" . ,(%btc new-fee))
                        ("errors" . ,#()))))))))))))

(defun rpc-bumpfee (node params)
  "Bump the fee of an unconfirmed wallet transaction, signing + broadcasting the
replacement (Bitcoin Core bumpfee). PARAMS: (txid [options]). Returns
{txid, origfee, fee, errors}."
  (%bumpfee-helper node params nil))

(defun rpc-psbtbumpfee (node params)
  "Like bumpfee but return an UNSIGNED PSBT of the replacement instead of signing
and broadcasting (Bitcoin Core psbtbumpfee). PARAMS: (txid [options]). Returns
{psbt, origfee, fee, errors}."
  (%bumpfee-helper node params t))
