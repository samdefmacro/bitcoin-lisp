(in-package #:bitcoin-lisp.tools)

;;;; bitcoin-tx (Core src/bitcoin-tx.cpp): build or modify a transaction from
;;;; the command line, offline. `bitcoin-tx [options] <hex-tx> [commands]' or
;;;; `bitcoin-tx [options] -create [commands]'; each command is NAME=VALUE and
;;;; they apply left to right. Output is the hex, the txid (-txid) or
;;;; TxToUniv's object (-json).
;;;;
;;;; Core's own expected outputs for 102 invocations are
;;;; test/functional/data/util/bitcoin-util-test.json, which tool_utils.py
;;;; replays byte for byte and tests/tools/ replays in-process; the error
;;;; strings below are the ones that corpus matches on.

(define-condition bitcoin-tx-error (error)
  ((message :initarg :message :reader bitcoin-tx-error-message))
  (:report (lambda (c s) (write-string (bitcoin-tx-error-message c) s)))
  (:documentation "A std::runtime_error inside CommandLineRawTx: printed as
\"error: <message>\" and exit code 1."))

(defun %tx-fail (control &rest args)
  (error 'bitcoin-tx-error :message (apply #'format nil control args)))

(defconstant +tx-max-standard-version+ 3
  "Core TX_MAX_STANDARD_VERSION (policy/policy.h).")

(defconstant +max-bip125-rbf-sequence+ #xfffffffd
  "Core MAX_BIP125_RBF_SEQUENCE (util/rbf.h).")

(defconstant +max-money+ 2100000000000000
  "Core MAX_MONEY (consensus/amount.h).")

;;; --- Core's number parsers ---

(defun %to-u32 (text)
  "Core ToIntegral<uint32_t> (util/strencodings.h): the WHOLE of TEXT as a
base-10 uint32 -- no sign, no whitespace, no trailing junk -- or NIL."
  (and (plusp (length text))
       (every (lambda (c) (char<= #\0 c #\9)) text)
       (let ((n (parse-integer text)))
         (and (<= n #xffffffff) n))))

(defun %trim-and-parse-u32 (text message)
  "Core TrimAndParse<uint32_t> (bitcoin-tx.cpp:241-249): TEXT without its
surrounding whitespace, or MESSAGE and the UNtrimmed text quoted."
  (or (%to-u32 (string-trim +core-whitespace+
                            text))
      (%tx-fail "~A '~A'" message text)))

(defun %parse-money (text)
  "Core ParseMoney (util/moneystr.cpp:43-84) as satoshis, or NIL: whitespace
around the number is trimmed, then digits, an optional point and at most
eight more digits, at most ten whole digits, and MoneyRange."
  (let* ((s (string-trim +core-whitespace+ text))
         (dot (position #\. s))
         (whole (subseq s 0 (or dot (length s))))
         (fraction (if dot (subseq s (1+ dot)) "")))
    (flet ((digits-p (x) (every (lambda (c) (char<= #\0 c #\9)) x)))
      (when (and (plusp (length s)) (digits-p whole) (digits-p fraction)
                 (<= (length fraction) 8) (<= (length whole) 10))
        (let ((value (+ (* (if (plusp (length whole)) (parse-integer whole) 0)
                           100000000)
                        (if (plusp (length fraction))
                            (* (parse-integer fraction) (expt 10 (- 8 (length fraction))))
                            0))))
          (and (<= 0 value +max-money+) value))))))

(defun %output-value (text)
  "Core ExtractAndValidateValue (bitcoin-tx.cpp:196-203)."
  (or (%parse-money text) (%tx-fail "invalid TX output value")))

(defun %split-colon (text)
  "Core SplitString(text, ':'): every field, empty ones included."
  (uiop:split-string text :separator ":"))

;;; --- Output scripts ---

(defun %u8-vector (sequence)
  (coerce sequence '(simple-array (unsigned-byte 8) (*))))

(defun %p2sh-script (script)
  "GetScriptForDestination(ScriptHash(script)): OP_HASH160 <hash160> OP_EQUAL."
  (%u8-vector (concatenate 'vector #(#xa9 #x14) (bl.crypto:hash160 script) #(#x87))))

(defun %p2wsh-script (script)
  "GetScriptForDestination(WitnessV0ScriptHash(script)): OP_0 <sha256>."
  (%u8-vector (concatenate 'vector #(#x00 #x20) (bl.crypto:sha256 script))))

(defun %p2wpkh-script (pubkey)
  "GetScriptForDestination(WitnessV0KeyHash(pubkey)): OP_0 <hash160>."
  (%u8-vector (concatenate 'vector #(#x00 #x14) (bl.crypto:hash160 pubkey))))

(defun %parse-pubkey (hex)
  "CPubKey(ParseHex(hex)) that IsFullyValid, or \"invalid TX output pubkey\"."
  (let ((bytes (and (%hex-p hex) (bl.crypto:hex-to-bytes hex))))
    (unless (and bytes (bl.crypto:public-key-valid-p bytes))
      (%tx-fail "invalid TX output pubkey"))
    (%u8-vector bytes)))

(defun %flags (parts count)
  "The W / S flags of an output command whose PARTS has COUNT fields when the
flags are present: (values segwit script-hash)."
  (if (= (length parts) count)
      (let ((flags (car (last parts))))
        (values (find #\W flags) (find #\S flags)))
      (values nil nil)))

(defun %wrap-p2sh (script)
  "The S flag: the redeemScript cap (MAX_SCRIPT_ELEMENT_SIZE), then P2SH."
  (when (> (length script) 520)
    (%tx-fail "redeemScript exceeds size limit: ~D > 520" (length script)))
  (%p2sh-script script))

;;; --- The mutations (bitcoin-tx.cpp:205-507) ---

(defun %add-output (tx value script)
  (setf (bl.ser:transaction-outputs tx)
        (concatenate 'simple-vector (bl.ser:transaction-outputs tx)
                     (vector (bl.ser:make-tx-out :value value :script-pubkey (%u8-vector script))))))

(defun %mutate-version (tx value)
  "MutateTxVersion (:205-212)."
  (let ((v (%to-u32 value)))
    (unless (and v (<= 1 v +tx-max-standard-version+))
      (%tx-fail "Invalid TX version requested: '~A'" value))
    (setf (bl.ser:transaction-version tx) v)))

(defun %mutate-locktime (tx value)
  "MutateTxLocktime (:214-221)."
  (setf (bl.ser:transaction-lock-time tx)
        (or (%to-u32 value) (%tx-fail "Invalid TX locktime requested: '~A'" value))))

(defun %mutate-rbf (tx value)
  "MutateTxRBFOptIn (:223-239): MAX_BIP125_RBF_SEQUENCE on input VALUE, or on
every input when VALUE is empty, never raising a lower sequence."
  (let ((inputs (bl.ser:transaction-inputs tx))
        (idx (%to-u32 value)))
    (when (and (string/= value "") (or (null idx) (>= idx (length inputs))))
      (%tx-fail "Invalid TX input index '~A'" value))
    (loop for input across inputs
          for i from 0
          when (and (or (string= value "") (= i idx))
                    (> (bl.ser:tx-in-sequence input) +max-bip125-rbf-sequence+))
            do (setf (bl.ser:tx-in-sequence input) +max-bip125-rbf-sequence+))))

(defun %mutate-add-input (tx value)
  "MutateTxAddInput (:251-282)."
  (let ((parts (%split-colon value)))
    (when (< (length parts) 2)
      (%tx-fail "TX input missing separator"))
    (unless (bl.rpc:valid-hex-hash-p (first parts))
      (%tx-fail "invalid TX input txid"))
    ;; maxVout = MAX_BLOCK_WEIGHT / (WITNESS_SCALE_FACTOR * minTxOutSz 9).
    (let ((vout (%to-u32 (second parts))))
      (unless (and vout (<= vout (floor 4000000 (* 4 9))))
        (%tx-fail "invalid TX input vout '~A'" (second parts)))
      (let ((sequence (if (> (length parts) 2)
                          (%trim-and-parse-u32 (third parts) "invalid TX sequence id")
                          #xffffffff)))
        (setf (bl.ser:transaction-inputs tx)
              (concatenate 'simple-vector (bl.ser:transaction-inputs tx)
                           (vector (bl.ser:make-tx-in
                                    :previous-output (bl.ser:make-outpoint
                                                      :hash (bl.rpc:parse-hex-hash (first parts))
                                                      :index vout)
                                    :script-sig (%u8-vector #())
                                    :sequence sequence))))
        (when (bl.ser:transaction-witness tx)
          (setf (bl.ser:transaction-witness tx)
                (concatenate 'simple-vector (bl.ser:transaction-witness tx) (vector '()))))))))

(defun %mutate-add-out-addr (tx value network)
  "MutateTxAddOutAddr (:284-305)."
  (let ((parts (%split-colon value)))
    (unless (= (length parts) 2)
      (%tx-fail "TX output missing or too many separators"))
    (let ((amount (%output-value (first parts)))
          (script (nth-value 1 (bl.crypto:decode-address (second parts) network))))
      (unless script (%tx-fail "invalid TX output address"))
      (%add-output tx amount script))))

(defun %mutate-add-out-pubkey (tx value)
  "MutateTxAddOutPubKey (:307-347)."
  (let ((parts (%split-colon value)))
    (unless (<= 2 (length parts) 3)
      (%tx-fail "TX output missing or too many separators"))
    (let* ((amount (%output-value (first parts)))
           (pubkey (%parse-pubkey (second parts)))
           (script (%u8-vector (concatenate 'vector (bl.ser:script-push-data pubkey) #(#xac)))))
      (multiple-value-bind (segwit script-hash) (%flags parts 3)
        (when segwit
          (unless (= (length pubkey) 33)
            (%tx-fail "Uncompressed pubkeys are not useable for SegWit outputs"))
          (setf script (%p2wpkh-script pubkey)))
        (when script-hash
          (setf script (%p2sh-script script))))
      (%add-output tx amount script))))

(defun %multisig-script (required pubkeys)
  "GetScriptForMultisig (script/solver.cpp): OP_m <keys> OP_n
OP_CHECKMULTISIG, the counts as push_int64."
  (%u8-vector (concatenate 'vector
                        (%push-int64 required)
                        (apply #'concatenate 'vector (mapcar #'bl.ser:script-push-data pubkeys))
                        (%push-int64 (length pubkeys))
                        #(#xae))))

(defun %mutate-add-out-multisig (tx value)
  "MutateTxAddOutMultiSig (:349-417)."
  (let ((parts (%split-colon value)))
    (when (< (length parts) 3)
      (%tx-fail "Not enough multisig parameters"))
    (let* ((amount (%output-value (first parts)))
           (required (%trim-and-parse-u32 (second parts) "invalid multisig required number"))
           (numkeys (%trim-and-parse-u32 (third parts) "invalid multisig total number")))
      (when (< (length parts) (+ numkeys 3))
        (%tx-fail "incorrect number of multisig pubkeys"))
      (unless (and (<= 1 required 20) (<= 1 numkeys 20) (>= numkeys required))
        (%tx-fail "multisig parameter mismatch. Required ~D of ~Dsignatures." required numkeys))
      (let ((pubkeys (loop for pos from 1 to numkeys
                           collect (%parse-pubkey (nth (+ pos 2) parts))))
            (segwit nil) (script-hash nil))
        (cond ((= (length parts) (+ numkeys 4))
               (let ((flags (car (last parts))))
                 (setf segwit (find #\W flags) script-hash (find #\S flags))))
              ((> (length parts) (+ numkeys 4))
               (%tx-fail "Too many parameters")))
        (let ((script (%multisig-script required pubkeys)))
          (when segwit
            (unless (every (lambda (k) (= (length k) 33)) pubkeys)
              (%tx-fail "Uncompressed pubkeys are not useable for SegWit outputs"))
            (setf script (%p2wsh-script script)))
          (when script-hash
            (setf script (%wrap-p2sh script)))
          (%add-output tx amount script))))))

(defun %mutate-add-out-data (tx value)
  "MutateTxAddOutData (:419-448): [VALUE:]DATA as OP_RETURN <data>."
  (let ((pos (position #\: value))
        (amount 0))
    (when (eql pos 0)
      (%tx-fail "TX output value not specified"))
    (when pos
      (setf amount (%output-value (subseq value 0 pos))))
    (let ((data (subseq value (if pos (1+ pos) 0))))
      (unless (%hex-p data)
        (%tx-fail "invalid TX output data"))
      (%add-output tx amount
                   (concatenate 'vector #(#x6a)
                                (bl.ser:script-push-data (%u8-vector (bl.crypto:hex-to-bytes data))))))))

(defun %mutate-add-out-script (tx value)
  "MutateTxAddOutScript (:450-491)."
  (let ((parts (%split-colon value)))
    (when (< (length parts) 2)
      (%tx-fail "TX output missing separator"))
    (let ((amount (%output-value (first parts)))
          (script (handler-case (parse-script-asm (second parts))
                    (script-asm-error (e) (%tx-fail "~A" e)))))
      (multiple-value-bind (segwit script-hash) (%flags parts 3)
        (when (> (length script) 10000)
          (%tx-fail "script exceeds size limit: ~D > 10000" (length script)))
        (when segwit (setf script (%p2wsh-script script)))
        (when script-hash (setf script (%wrap-p2sh script))))
      (%add-output tx amount script))))

(defun %mutate-delete (tx value inputs-p)
  "MutateTxDelInput / MutateTxDelOutput (:493-509)."
  (let* ((items (if inputs-p (bl.ser:transaction-inputs tx) (bl.ser:transaction-outputs tx)))
         (idx (%to-u32 value)))
    (unless (and idx (< idx (length items)))
      (%tx-fail "Invalid TX ~:[output~;input~] index '~A'" inputs-p value))
    (flet ((drop (v) (concatenate 'simple-vector (subseq v 0 idx) (subseq v (1+ idx)))))
      (if inputs-p
          (progn (setf (bl.ser:transaction-inputs tx) (drop items))
                 (when (bl.ser:transaction-witness tx)
                   (setf (bl.ser:transaction-witness tx) (drop (bl.ser:transaction-witness tx)))))
          (setf (bl.ser:transaction-outputs tx) (drop items))))))

;;; --- Registers (bitcoin-tx.cpp:132-194) ---

(defun %register-set-json (registers key text)
  "RegisterSetJson: KEY := TEXT read as JSON, or \"Cannot parse JSON for key\"."
  (let ((value (handler-case
                   (let ((yason:*parse-object-as* :alist)
                         (yason:*parse-json-booleans-as-symbols* t))
                     (with-input-from-string (in text)
                       (prog1 (yason:parse in)
                         ;; UniValue::read takes the WHOLE text.
                         (when (peek-char t in nil nil)
                           (%tx-fail "Cannot parse JSON for key ~A" key)))))
                 (error () (%tx-fail "Cannot parse JSON for key ~A" key)))))
    (setf (gethash key registers) value)))

(defun %register-split (value message)
  (let ((pos (position #\: value)))
    (when (or (null pos) (zerop pos) (= pos (1- (length value))))
      (%tx-fail "~A" message))
    (values (subseq value 0 pos) (subseq value (1+ pos)))))

(defun %register-set (registers value)
  "RegisterSet (:143-157): set=NAME:JSON."
  (multiple-value-bind (key json) (%register-split value "Register input requires NAME:VALUE")
    (%register-set-json registers key json)))

(defun %register-load (registers value)
  "RegisterLoad (:159-194): load=NAME:FILENAME, the file read as JSON."
  (multiple-value-bind (key filename) (%register-split value "Register load requires NAME:FILENAME")
    (let ((text (handler-case (uiop:read-file-string filename)
                  (error () (%tx-fail "Cannot open file ~A" filename)))))
      (%register-set-json registers key text))))

;;; --- sign=SIGHASH (bitcoin-tx.cpp:511-676) ---

(defparameter +sighash-options+
  '(("DEFAULT" . #x00) ("ALL" . #x01) ("NONE" . #x02) ("SINGLE" . #x03)
    ("ALL|ANYONECANPAY" . #x81) ("NONE|ANYONECANPAY" . #x82)
    ("SINGLE|ANYONECANPAY" . #x83))
  "Core sighashOptions (bitcoin-tx.cpp:511-524).")

(defun %tx-amount (value)
  "bitcoin-tx's own AmountFromValue (:541-551): the RPC layer's parse, with
its error texts (the same three sentences) as this tool's errors."
  (handler-case (bl.rpc:amount-from-value value)
    (bl.rpc:rpc-error (e) (%tx-fail "~A" (bl.rpc:rpc-error-message e)))))

(defun %json-string-p (value) (stringp value))

(defun %key-maps (wifs network)
  "The three lookups BL.RPC:SIGN-TX-INPUTS reads, from the privatekeys
register: hash160(pubkey) -> (priv . pub), pubkey -> priv, and the tweaked
taproot output key -> priv. Each key must be a string DecodeSecret accepts
for NETWORK (:572-580)."
  (let ((keymap (bl.bytes:make-octets-hash-table))
        (pubmap (bl.bytes:make-octets-hash-table))
        (tr-keymap (bl.bytes:make-octets-hash-table))
        (prefix (bl.chain:chain-params-base58-secret-prefix
                 (bl.chain:find-chain-params network))))
    (dolist (wif (if (listp wifs) wifs (list wifs)))
      (unless (%json-string-p wif) (%tx-fail "privatekey not a std::string"))
      (multiple-value-bind (sk compressed version) (bl.crypto:wif-to-private-key wif)
        (unless (and sk (= version prefix)) (%tx-fail "privatekey not valid"))
        (let ((pub (bl.crypto:derive-public-key sk :compressed compressed)))
          (setf (gethash (bl.crypto:hash160 pub) keymap) (cons sk pub)
                (gethash pub pubmap) sk))
        (let ((qx (bl.interop:compute-tweaked-pubkey (bl.crypto:derive-xonly-pubkey sk))))
          (when qx (setf (gethash qx tr-keymap) sk)))))
    (values keymap pubmap tr-keymap)))

(defun %prevtx-coins (prevtxs)
  "The prevtxs register as BL.RPC:SIGN-TX-INPUTS's PREVMAP, checked as Core
checks it (:584-640) and in its order. An entry with no amount is worth
MAX_MONEY, as Core's Coin is, and its entry carries a fifth element,
:DEFAULTED, which the Missing-amount check reads (the signer reads four)."
  (let ((coins (bl.rpc:make-coins-map)))
    (dolist (prev (if (listp prevtxs) prevtxs (list prevtxs)))
      (unless (%alist-object-p prev) (%tx-fail "expected prevtxs internal object"))
      (flet ((field (name) (cdr (assoc name prev :test #'string=))))
        (unless (and (stringp (field "txid")) (numberp (field "vout"))
                     (stringp (field "scriptPubKey")))
          (%tx-fail "prevtxs internal object typecheck fail"))
        (unless (bl.rpc:valid-hex-hash-p (field "txid"))
          (%tx-fail "txid must be hexadecimal string (not '~A')" (field "txid")))
        (let ((vout (field "vout")))
          (unless (integerp vout) (%tx-fail "JSON integer out of range"))
          (when (minusp vout) (%tx-fail "vout cannot be negative"))
          (let* ((spk-hex (field "scriptPubKey"))
                 (spk (if (%hex-p spk-hex)
                          (%u8-vector (bl.crypto:hex-to-bytes spk-hex))
                          (%tx-fail "scriptPubKey must be hexadecimal string (not '~A')" spk-hex)))
                 (key (cons (bl.rpc:parse-hex-hash (field "txid")) vout))
                 (known (gethash key coins))
                 (type (bl.val:classify-script spk))
                 (redeem nil) (witness nil))
            (when (and known (not (equalp (first known) spk)))
              (%tx-fail "Previous output scriptPubKey mismatch:~%~A~%vs:~%~A"
                        (bl.val:disassemble-script (first known))
                        (bl.val:disassemble-script spk)))
            ;; A redeemScript goes into the keystore for a P2SH or P2WSH
            ;; output (:627-634); here it lands where the signer looks.
            (when (and (member type '(:scripthash :witness-v0-scripthash))
                       (assoc "redeemScript" prev :test #'string=))
              (let* ((rs-hex (field "redeemScript"))
                     (rs (if (and (stringp rs-hex) (%hex-p rs-hex))
                             (%u8-vector (bl.crypto:hex-to-bytes rs-hex))
                             (%tx-fail "redeemScript must be hexadecimal string (not '~A')"
                                       (if (stringp rs-hex) rs-hex "")))))
                (if (eq type :scripthash) (setf redeem rs) (setf witness rs))))
            (setf (gethash key coins)
                  (if (assoc "amount" prev :test #'string=)
                      (list spk (%tx-amount (field "amount")) redeem witness)
                      (list spk +max-money+ redeem witness :defaulted)))))))
    coins))

(defun %mutate-sign (tx value registers network)
  "MutateTxSign (:553-676): sign every input the privatekeys and prevtxs
registers can satisfy, in place; an input they cannot is left as it is."
  (let ((hash-type (if (string= value "")
                       #x01
                       (or (cdr (assoc value +sighash-options+ :test #'string=))
                           (%tx-fail "unknown sighash flag/sign option")))))
    (multiple-value-bind (keys keys-p) (gethash "privatekeys" registers)
      (unless keys-p (%tx-fail "privatekeys register variable must be set."))
      (multiple-value-bind (keymap pubmap tr-keymap) (%key-maps keys network)
        (multiple-value-bind (prevtxs prevtxs-p) (gethash "prevtxs" registers)
          (unless prevtxs-p (%tx-fail "prevtxs register variable must be set."))
          (let ((coins (%prevtx-coins prevtxs)))
            ;; Only sign SIGHASH_SINGLE where there is a corresponding output
            ;; (:660-662): the other inputs are simply not offered.
            (when (= (logand hash-type (lognot #x80)) #x03)
              (loop for input across (bl.ser:transaction-inputs tx)
                    for i from 0
                    when (>= i (length (bl.ser:transaction-outputs tx)))
                      do (let ((op (bl.ser:tx-in-previous-output input)))
                           (remhash (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op))
                                    coins))))
            (bl.rpc:sign-tx-inputs tx coins keymap pubmap tr-keymap
                                   (if (zerop hash-type) #x01 hash-type))
            ;; A segwit signature over MAX_MONEY verifies against nothing
            ;; (:664-666).
            (let ((witness (bl.ser:transaction-witness tx)))
              (loop for input across (bl.ser:transaction-inputs tx)
                    for i from 0
                    for op = (bl.ser:tx-in-previous-output input)
                    for key = (cons (bl.ser:outpoint-hash op) (bl.ser:outpoint-index op))
                    when (and (fifth (gethash key coins)) witness (aref witness i))
                      do (%tx-fail "Missing amount for CTxOut with scriptPubKey=~A"
                                   (bl.crypto:bytes-to-hex (first (gethash key coins))))))))))))

;;; --- The command line (bitcoin-tx.cpp:678-885) ---

(defun %mutate-tx (tx command value registers network)
  "MutateTx (:678-731): one NAME=VALUE command."
  (let ((name command))
    (cond ((string= name "nversion") (%mutate-version tx value))
          ((string= name "locktime") (%mutate-locktime tx value))
          ((string= name "replaceable") (%mutate-rbf tx value))
          ((string= name "delin") (%mutate-delete tx value t))
          ((string= name "in") (%mutate-add-input tx value))
          ((string= name "delout") (%mutate-delete tx value nil))
          ((string= name "outaddr") (%mutate-add-out-addr tx value network))
          ((string= name "outpubkey") (%mutate-add-out-pubkey tx value))
          ((string= name "outmultisig") (%mutate-add-out-multisig tx value))
          ((string= name "outscript") (%mutate-add-out-script tx value))
          ((string= name "outdata") (%mutate-add-out-data tx value))
          ((string= name "sign") (%mutate-sign tx value registers network))
          ((string= name "load") (%register-load registers value))
          ((string= name "set") (%register-set registers value))
          (t (%tx-fail "unknown command")))
    (bl.ser:invalidate-transaction-caches tx)))

(defun %output-tx (tx args network out)
  "OutputTx (:733-765): -json, -txid, or the hex."
  (cond ((tool-bool-arg args "json")
         (format out "~A~%" (univalue-write (bl.rpc:tx-to-json tx network) 4)))
        ((tool-bool-arg args "txid")
         (format out "~A~%" (bl.rpc:hash-to-hex (bl.ser:transaction-hash tx))))
        (t
         (format out "~A~%" (bl.crypto:bytes-to-hex (bl.ser:transaction-wire-bytes tx))))))

(defun %read-stdin-tx (stdin)
  "readStdin (:767-784): all of STDIN, whitespace-trimmed."
  (string-trim +core-whitespace+
               (with-output-to-string (s)
                 (loop for line = (read-line stdin nil nil)
                       while line do (write-line line s)))))

(defun %command-line-raw-tx (argv args network stdin out)
  "CommandLineRawTx (:786-848) after the switches: the transaction, then each
command in order, then the output. Signals BITCOIN-TX-ERROR."
  ;; Skip switches; a lone "-" is stdin, not a switch.
  (let ((rest (loop for tail on argv
                    while (and (> (length (car tail)) 1) (char= (char (car tail) 0) #\-))
                    finally (return tail)))
        (registers (make-hash-table :test 'equal))
        (tx (bl.ser:make-transaction :version 2)))
    (unless (tool-bool-arg args "create")
      (when (null rest) (%tx-fail "too few parameters"))
      (let ((hex (if (string= (first rest) "-") (%read-stdin-tx stdin) (first rest))))
        (setf tx (or (bl.rpc:decode-hex-tx hex)
                     (%tx-fail "invalid transaction encoding")))
        (setf rest (rest rest))))
    (dolist (arg rest)
      (let ((eq-pos (position #\= arg)))
        (%mutate-tx tx (if eq-pos (subseq arg 0 eq-pos) arg)
                    (if eq-pos (subseq arg (1+ eq-pos)) "")
                    registers network)))
    (%output-tx tx args network out)))

(defun %bitcoin-tx-usage (args out)
  "AppInitRawTx's help / -version text (:95-125)."
  (write-string (tool-version-banner "bitcoin-tx") out)
  (if (tool-bool-arg args "version")
      (write-string (tool-license-info) out)
      (format out "~%The bitcoin-tx tool is used for creating and modifying bitcoin ~
transactions.~%~%bitcoin-tx can be used with \"<hex-tx> [commands]\" to update a ~
hex-encoded bitcoin transaction, or with \"-create [commands]\" to create a ~
hex-encoded bitcoin transaction.~%~%~
Usage: bitcoin-tx [options] <hex-tx> [commands]~%~
or:    bitcoin-tx [options] -create [commands]~%~%")))

(defun run-bitcoin-tx (argv &key (stdin *standard-input*) (out *standard-output*)
                                 (err *error-output*))
  "Core bitcoin-tx's main (bitcoin-tx.cpp:850-885) over ARGV, the arguments
after the program name: write what Core writes to OUT and ERR, read the
transaction from STDIN when it is given as \"-\", and return Core's exit
code."
  (multiple-value-bind (args error)
      (parse-tool-args argv :options '("version" "create" "json" "txid"))
    (unless args
      (format err "Error parsing command line arguments: ~A~%" error)
      (return-from run-bitcoin-tx 1))
    (let ((network (handler-case (tool-args-network args)
                     (error (e)
                       (format err "Error: ~A~%" e)
                       (return-from run-bitcoin-tx 1)))))
      (when (or (null argv) (tool-help-requested-p args) (tool-bool-arg args "version"))
        (%bitcoin-tx-usage args out)
        (when (null argv)
          (format err "Error: too few parameters~%")
          (return-from run-bitcoin-tx 1))
        (return-from run-bitcoin-tx 0))
      (handler-case
          (progn (%command-line-raw-tx argv args network stdin out) 0)
        (bitcoin-tx-error (e)
          (format err "error: ~A~%" e)
          1)))))
