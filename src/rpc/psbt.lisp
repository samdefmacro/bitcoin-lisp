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
                                     (if (>= (length params) 4) (fourth params) t)
                                     (rpc-get-network node))))
    (bitcoin-lisp.serialization:encode-psbt
     (bitcoin-lisp.serialization:make-empty-psbt tx))))

;;; --- converttopsbt ---

(defun rpc-converttopsbt (node params)
  "Convert a raw transaction to a PSBT, stripping signatures.
PARAMS: (hexstring [permitsigdata] [iswitness]). Mirrors Core converttopsbt."
  (declare (ignore node))
  (let* ((hexstr (first params))
         (permitsigdata (if (>= (length params) 2) (second params) nil)))
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

(defun %psbt-input-amount (map tx-in)
  "The satoshi amount of the output spent by TX-IN, from MAP's utxo fields, or NIL."
  (let ((wu (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)))
    (if wu
        (bitcoin-lisp.serialization:tx-out-value
         (bitcoin-lisp.serialization:br-read-tx-out
          (bitcoin-lisp.serialization:make-byte-reader-from wu)))
        (let ((nwu (bitcoin-lisp.serialization:psbt-map-find
                    map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+)))
          (when nwu
            (let ((prev (bitcoin-lisp.serialization:br-read-transaction
                         (bitcoin-lisp.serialization:make-byte-reader-from nwu)))
                  (vout (bitcoin-lisp.serialization:outpoint-index
                         (bitcoin-lisp.serialization:tx-in-previous-output tx-in))))
              (when (< vout (length (bitcoin-lisp.serialization:transaction-outputs prev)))
                (bitcoin-lisp.serialization:tx-out-value
                 (aref (bitcoin-lisp.serialization:transaction-outputs prev) vout)))))))))

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
      (let ((tk (bitcoin-lisp.serialization:psbt-map-find
                 map bitcoin-lisp.serialization:+psbt-in-tap-internal-key+)))
        (when tk (add "taproot_internal_key" (bitcoin-lisp.crypto:bytes-to-hex tk)))))
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
        (when tk (add "taproot_internal_key" (bitcoin-lisp.crypto:bytes-to-hex tk)))))
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
  "The scriptPubKey of the output spent by TX-IN, from MAP's utxo fields, or NIL."
  (let ((wu (bitcoin-lisp.serialization:psbt-map-find
             map bitcoin-lisp.serialization:+psbt-in-witness-utxo+)))
    (if wu
        (bitcoin-lisp.serialization:tx-out-script-pubkey
         (bitcoin-lisp.serialization:br-read-tx-out
          (bitcoin-lisp.serialization:make-byte-reader-from wu)))
        (let ((nwu (bitcoin-lisp.serialization:psbt-map-find
                    map bitcoin-lisp.serialization:+psbt-in-non-witness-utxo+)))
          (when nwu
            (let ((prev (bitcoin-lisp.serialization:br-read-transaction
                         (bitcoin-lisp.serialization:make-byte-reader-from nwu)))
                  (vout (bitcoin-lisp.serialization:outpoint-index
                         (bitcoin-lisp.serialization:tx-in-previous-output tx-in))))
              (when (< vout (length (bitcoin-lisp.serialization:transaction-outputs prev)))
                (bitcoin-lisp.serialization:tx-out-script-pubkey
                 (aref (bitcoin-lisp.serialization:transaction-outputs prev) vout)))))))))

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
         (extract (if (>= (length params) 2) (second params) t))
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
