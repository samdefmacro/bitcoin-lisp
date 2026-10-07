(in-package #:bitcoin-lisp.tests)

;;;; Core's RPC targets at the pin: fuzz/parse_univalue.cpp, and fuzz/rpc.cpp
;;;; at the end of the file.

(def-suite :fuzz-rpc-tests :in :bitcoin-lisp-tests
  :description "Core fuzz parse_univalue.cpp and rpc.cpp targets")

(in-suite :fuzz-rpc-tests)

(defun %json-corpus (fdp)
  "A JSON value of the shapes RPC arguments take: strings of hex and of hash
length, numbers written every way JSON allows, arrays and objects of them."
  (labels ((value (depth)
             (call-one-of fdp
               (format nil "\"~A\"" (bl.crypto:bytes-to-hex (consume-bytes fdp (pick-value-in-array fdp '(0 1 20 32 33)))))
               (format nil "\"~A\"" (pick-value-in-array fdp '("ALL" "NONE|ANYONECANPAY" "all" "DEFAULT" "0.1" "1e-8" "-1" "21000001")))
               (format nil "~A~D~A~A" (pick-value-in-array fdp '("" "-")) (consume-integral fdp :u32)
                       (pick-value-in-array fdp '("" ".5" ".00000001" ".123456789"))
                       (pick-value-in-array fdp '("" "e-8" "e3" "E+2")))
               (pick-value-in-array fdp '("null" "true" "false" "[]" "{}"))
               (if (< depth 2)
                   (format nil "[~{~A~^,~}]" (loop repeat (consume-integral-in-range fdp 0 3) collect (value (1+ depth))))
                   "0")
               (if (< depth 2)
                   (format nil "{~{\"k~D\":~A~^,~}}"
                           (loop for i below (consume-integral-in-range fdp 0 2) append (list i (value (1+ depth)))))
                   "1"))))
    (%octets-of-string (value 0))))

(define-fuzz-target parse-univalue
    (buffer :core "parse_univalue.cpp:18-95" :iterations 10000 :max-len 200
            :corpus #'%json-corpus)
  "Any text an RPC client sends as an argument: the request either fails to
parse with Core's error or yields a value that ParseHashV, ParseHexV,
ParseSighashString, AmountFromValue and ParseDescriptorRange each accept or
refuse with an RPC error -- nothing else escapes (Core catches only UniValue
and runtime_error there)."
  (let ((text (map 'string #'code-char buffer)))
    (multiple-value-bind (kind method params)
        (handler-case (bl.rpc:parse-json-rpc-request
                       (format nil "{\"method\":\"fuzz\",\"params\":[~A]}" text))
          (bl.rpc:rpc-error () (fuzz-reject)))
      (declare (ignore method))
      (fuzz-assert (eq (fuzz-sabotage kind) :single) "a request object parsed as ~S" kind)
      (let ((value (first params)))
        (macrolet ((refusable (form) `(handler-case ,form (bl.rpc:rpc-error () nil))))
          (refusable (bl.rpc:parse-hash-v value "A"))
          (refusable (bl.rpc:parse-hash-v value text))
          (refusable (bl.rpc:parse-hex-v value "A"))
          (refusable (bl.rpc:parse-hex-v value text))
          (when (or (null value) (stringp value))
            (refusable (bl.rpc:parse-sighash-type value)))
          (refusable (bl.rpc:amount-from-value value))
          (refusable (bl.rpc:amount-from-value value 3))
          (refusable (bl.rpc:parse-descriptor-range value)))))))

;;; --- rpc.cpp: rpc ------------------------------------------------------------
;;;
;;; Core src/test/fuzz/rpc.cpp at the pin: a command from its
;;; RPC_COMMANDS_SAFE_FOR_FUZZING list, called with up to 100 arguments each
;;; built as a string of one of Core's shapes -- text, base64, hex, a bool, a
;;; range, an integer, a float, an address, a uint160 or uint256, base32,
;;; base58(check), a hex block, header or transaction, a base64 PSBT, a WIF
;;; key, a pubkey -- or an array of them, converted as bitcoin-cli converts
;;; arguments (RPCConvertValues) and executed. The only refusal is a JSON-RPC
;;; error; an `Internal bug detected' is Core's assertion. Ours: the
;;; arguments through BL.CLI:RPC-CONVERT-VALUES, the request through
;;; PARSE-JSON-RPC-REQUEST, the call through DISPATCH-RPC-METHOD on the
;;; process_message fixture node; anything but an RPC-ERROR escaping the
;;; call is the bug.
;;;
;;; The waitforblock family waits on an RPC server our fixture does not stop
;;; (Core's returns at once because IsRPCRunning() is false there), and
;;; `logging' reconfigures the process's log categories for every suite after
;;; this one; those four are left out.

(defparameter +rpc-commands-safe-for-fuzzing+
  '("abortprivatebroadcast" "analyzepsbt" "clearbanned" "combinepsbt" "combinerawtransaction"
    "converttopsbt" "createmultisig" "createpsbt" "createrawtransaction" "decodepsbt"
    "decoderawtransaction" "decodescript" "deriveaddresses" "descriptorprocesspsbt" "disconnectnode"
    "echo" "echojson" "estimaterawfee" "estimatesmartfee" "finalizepsbt" "generate" "generateblock"
    "getaddednodeinfo" "getaddrmaninfo" "getbestblockhash" "getblock" "getblockchaininfo"
    "getblockcount" "getblockfilter" "getblockfrompeer" "getblockhash" "getblockheader"
    "getblockstats" "getblocktemplate" "getchaintips" "getchainstates" "getchaintxstats"
    "getconnectioncount" "getdeploymentinfo" "getdescriptoractivity" "getdescriptorinfo"
    "getdifficulty" "getindexinfo" "getmemoryinfo" "getmempoolancestors" "getmempooldescendants"
    "getmempoolentry" "getmempoolfeeratediagram" "getmempoolcluster" "getmempoolinfo"
    "getmininginfo" "getnettotals" "getnetworkhashps" "getnetworkinfo" "getnodeaddresses"
    "getorphantxs" "getpeerinfo" "getprioritisedtransactions" "getprivatebroadcastinfo"
    "getrawaddrman" "getrawmempool" "getrawtransaction" "getrpcinfo" "gettxout" "gettxoutsetinfo"
    "gettxspendingprevout" "help" "invalidateblock" "joinpsbts" "mockscheduler" "ping"
    "preciousblock" "prioritisetransaction" "pruneblockchain" "reconsiderblock" "scanblocks"
    "scantxoutset" "sendmsgtopeer" "sendrawtransaction" "setmocktime" "setnetworkactive"
    "signmessagewithprivkey" "signrawtransactionwithkey" "submitblock" "submitheader"
    "submitpackage" "syncwithvalidationinterfacequeue" "testmempoolaccept" "uptime"
    "utxoupdatepsbt" "validateaddress" "verifychain" "verifymessage" "verifytxoutproof")
  "Core RPC_COMMANDS_SAFE_FOR_FUZZING (rpc.cpp:62-160) less waitforblock,
waitforblockheight, waitfornewblock and logging (see above).")

(defun %rpc-fuzz-text (fdp)
  (map 'string #'code-char (consume-random-length-byte-vector fdp 4096)))

(defun %rpc-scalar-argument (fdp)
  "Core ConsumeScalarRPCArgument (rpc.cpp:180-305), or NIL for its
good_data = false."
  (call-one-of fdp
    (%rpc-fuzz-text fdp)
    (bl.ser:encode-base64 (consume-random-length-byte-vector fdp 4096))
    (bl.crypto:bytes-to-hex (consume-random-length-byte-vector fdp 4096))
    (if (consume-bool fdp) "true" "false")
    (format nil "[~D,~D]" (consume-integral fdp :i64) (consume-integral fdp :i64))
    (format nil "~D" (consume-integral fdp :i64))
    (format nil "~D" (consume-integral fdp :u64))
    (format nil "~,6F" (consume-floating-point-in-range fdp -1d12 1d12))
    (bl.crypto:encode-p2pkh-address (consume-uint160 fdp) :regtest)
    (bl.crypto:bytes-to-hex (consume-uint160 fdp))
    (bl.crypto:bytes-to-hex (consume-uint256 fdp))
    (bl.net:base32-encode (consume-random-length-byte-vector fdp 4096))
    (bl.crypto:base58-encode (consume-random-length-byte-vector fdp 64))
    (let ((b (consume-random-length-byte-vector fdp 64)))
      (if (plusp (length b)) (bl.crypto:base58check-encode (aref b 0) (subseq b 1)) nil))
    (bl.crypto:bytes-to-hex (bl.ser:serialize-witness-block (consume-block fdp)))
    (bl.crypto:bytes-to-hex (bl.ser:serialize-block-header (consume-block-header fdp)))
    (let ((tx (consume-transaction fdp :max-num-in 3 :max-num-out 3)))
      (bl.crypto:bytes-to-hex (if (consume-bool fdp)
                                  (bl.ser:serialize-witness-transaction tx)
                                  (bl.ser:serialize-transaction tx))))
    (bl.ser:encode-psbt (bl.ser:make-empty-psbt (consume-transaction fdp :max-num-in 2 :max-num-out 2)))
    (let ((key (%consume-private-key fdp))) (and key (bl.crypto:private-key-to-wif key :network :regtest)))
    (let ((key (%consume-private-key fdp))) (and key (bl.crypto:bytes-to-hex (bl.crypto:derive-public-key key))))))

(defun %rpc-argument (fdp)
  "Core ConsumeRPCArgument (rpc.cpp:318-321): a scalar, or an array of them
written as [\"a\",\"b\"]. NIL for Core's good_data = false."
  (if (consume-bool fdp)
      (%rpc-scalar-argument fdp)
      (let ((items (loop repeat (consume-integral-in-range fdp 0 4)
                         collect (or (%rpc-scalar-argument fdp) (return-from %rpc-argument nil)))))
        (format nil "[\"~{~A~^\",\"~}\"]" items))))

(define-fuzz-target rpc
    (buffer :core "rpc.cpp:357-390" :iterations 250 :max-len 1200)
  "Any of Core's fuzz-safe RPCs, called with arguments of any of its shapes,
answers or refuses with an RPC error; nothing else escapes."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (method (pick-value-in-array fdp +rpc-commands-safe-for-fuzzing+))
         (arguments (loop repeat (consume-integral-in-range fdp 0 6)
                          collect (or (%rpc-argument fdp) (fuzz-reject))))
         (params (handler-case
                     (nth-value 2 (bl.rpc:parse-json-rpc-request
                                   (format nil "{\"method\":~S,\"params\":~A}" method
                                           (bl.cli:uv-write (bl.cli:rpc-convert-values method arguments)))))
                   ;; RPCConvertValues' runtime_error: Core returns.
                   (error () (fuzz-reject)))))
    (with-fuzz-p2p-node (p2p)
      (let ((outcome (handler-case (progn (bl.rpc:dispatch-rpc-method (fp-node p2p) method params) :answered)
                       (bl.rpc:rpc-error () :refused))))
        (fuzz-assert (member (fuzz-sabotage outcome) '(:answered :refused))
                     "~A ~S answered ~S" method arguments outcome)))))
