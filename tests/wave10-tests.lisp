(in-package #:bitcoin-lisp.tests)

;;; Wave 10: RPC/config polish tests
;;;
;;; - JSON boolean correctness (false vs null) across RPC results
;;; - RPC error-code parity with Bitcoin Core (protocol.h RPCErrorCode)
;;; - HTTP layer: 1.x error->status mapping, 2.0 always-200, notification
;;;   detection, 32 MiB body cap
;;; - BIP64 /rest/getutxos (json + binary forms, checkmempool, limits)
;;; - gettxout include_mempool
;;; - Config wires (-assumevalid/-minimumchainwork/-mempoolexpiry/... )
;;; - ArgsManager-parity argument handling (unknown args, precedence)
;;; - banlist.json persistence + periodic peers.dat dump cadence

(def-suite :wave10-tests
  :description "Wave 10 RPC/config polish"
  :in :bitcoin-lisp-tests)

(in-suite :wave10-tests)

(defun wave10-rpc-code (thunk)
  "Funcall THUNK; return the rpc-error code it signals, or NIL if none."
  (handler-case (progn (funcall thunk) nil)
    (bitcoin-lisp.rpc::rpc-error (e) (bitcoin-lisp.rpc::rpc-error-code e))))

(defun wave10-encode (result)
  "Encode an RPC result alist exactly like the server does."
  (with-output-to-string (s)
    (yason:encode (bitcoin-lisp.rpc::rpc-result->json result) s)))

;;; ---------------------------------------------------------------------
;;; A. JSON booleans
;;; ---------------------------------------------------------------------

(test wave10-json-bool-helper
  "json-bool maps generalized booleans to T / the yason false literal, and
yason renders the literal as JSON false (not null)."
  (is (eq t (bitcoin-lisp.rpc:json-bool 42)))
  (is (eq t (bitcoin-lisp.rpc:json-bool '(:truthy))))
  (is (eq bitcoin-lisp.rpc:+json-false+ (bitcoin-lisp.rpc:json-bool nil)))
  (is (string= "false" (with-output-to-string (s)
                         (yason:encode bitcoin-lisp.rpc:+json-false+ s))))
  ;; rpc-result->json passes the literal through inside objects and arrays.
  (is (string= "{\"a\":false}" (wave10-encode '(("a" . yason:false)))))
  (is (string= "[false,true,null]"
               (wave10-encode (list 'yason:false t nil)))))

(test wave10-boolean-fields-encode-false-not-null
  "Always-present Core booleans render as false on an empty node:
getblockchaininfo (initialblockdownload/pruned), getnetworkinfo
(networkactive is true here; localrelay honest), getmempoolinfo (loaded
true), gettxout coinbase, testmempoolaccept allowed — spot-checked through
the real yason pipeline."
  (let* ((node (make-test-node))
         (chain (wave10-encode (bitcoin-lisp.rpc::rpc-getblockchaininfo node nil))))
    (is (search "\"initialblockdownload\":false" chain))
    (is (search "\"pruned\":false" chain))
    (is (not (search "\"pruned\":null" chain)))
    (let ((net (wave10-encode (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil))))
      ;; network-active defaults to T on a fresh node struct.
      (is (search "\"networkactive\":true" net))
      ;; localrelay is a real boolean either way — never null.
      (is (or (search "\"localrelay\":true" net)
              (search "\"localrelay\":false" net)))
      ;; subversion comes from the shared user-agent variable (slash-free
      ;; probe: yason may escape '/').
      (is (search "bitcoin-lisp:0.1.0" net)))
    (let ((mem (wave10-encode (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil))))
      (is (search "\"loaded\":true" mem))
      (is (search "\"permitbaremultisig\":" mem)))))

(test wave10-getaddednodeinfo-connected-false
  "getaddednodeinfo reports connected:false (not null) for an added but
unconnected peer."
  (let ((node (make-test-node)))
    (bitcoin-lisp.rpc::rpc-addnode node (list "192.0.2.10:48333" "add"))
    (let* ((r (bitcoin-lisp.rpc::rpc-getaddednodeinfo node nil))
           (row (first r)))
      (is (eq 'yason:false (cdr (assoc "connected" row :test #'string=))))
      (is (search "\"connected\":false" (wave10-encode r))))))

(test wave10-scan-abort-bare-booleans
  "scantxoutset/scanblocks abort with no scan running return JSON false."
  (is (eq 'yason:false (bitcoin-lisp.rpc::rpc-scantxoutset
                        (make-test-node) (list "abort"))))
  (is (eq 'yason:false (bitcoin-lisp.rpc::rpc-scanblocks
                        (make-test-node) (list "abort")))))

(test wave10-setnetworkactive-bare-boolean
  "setnetworkactive returns the new state as a bare JSON boolean."
  (let ((node (make-test-node)))
    (is (eq 'yason:false (bitcoin-lisp.rpc::rpc-setnetworkactive node (list nil))))
    (is (eq t (bitcoin-lisp.rpc::rpc-setnetworkactive node (list t))))))

(test wave10-mempool-entry-unbroadcast-real
  "The mempool entry's unbroadcast field reflects the actual unbroadcast set
(was hardcoded null)."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (tx (make-mempool-test-tx :input-id 71))
         (txid (bitcoin-lisp.serialization:transaction-hash tx)))
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                 mempool txid (make-mempool-entry-for-tx tx))))
    (let ((fields (bitcoin-lisp.rpc::rpc-getmempoolentry
                   node (list (bitcoin-lisp.rpc::hash-to-hex txid)))))
      (is (eq 'yason:false (cdr (assoc "unbroadcast" fields :test #'string=)))))
    (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
    (let ((fields (bitcoin-lisp.rpc::rpc-getmempoolentry
                   node (list (bitcoin-lisp.rpc::hash-to-hex txid)))))
      (is (eq t (cdr (assoc "unbroadcast" fields :test #'string=)))))))

;;; ---------------------------------------------------------------------
;;; B. Error-code parity
;;; ---------------------------------------------------------------------

(test wave10-not-found-errors-are-minus-5
  "Block/tx lookups that fail on well-formed input throw -5
RPC_INVALID_ADDRESS_OR_KEY, like Core (was -1)."
  (let ((node (make-test-node))
        (hash (make-string 64 :initial-element #\a)))
    (is (= -5 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-getblock node (list hash))))))
    (is (= -5 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-getblockheader node (list hash))))))
    (is (= -5 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-getmempoolentry node (list hash))))))
    (is (= -5 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-getmempoolancestors node (list hash))))))))

(test wave10-disconnectnode-minus-29
  "disconnectnode on an unknown peer throws -29 RPC_CLIENT_NODE_NOT_CONNECTED
with Core's message."
  (handler-case
      (progn (bitcoin-lisp.rpc::rpc-disconnectnode (make-test-node) (list "203.0.113.9"))
             (fail "expected rpc-error"))
    (bitcoin-lisp.rpc::rpc-error (e)
      (is (= -29 (bitcoin-lisp.rpc::rpc-error-code e)))
      (is (string= "Node not found in connected nodes"
                   (bitcoin-lisp.rpc::rpc-error-message e))))))

(test wave10-setban-error-codes
  "setban: invalid address -30; double-add -23; unban of a never-banned
address -30; absolute past timestamp -8 (Core net.cpp:766-812)."
  (let ((bitcoin-lisp.networking:*banlist-path* nil)
        (node (make-test-node)))
    (unwind-protect
         (progn
           ;; hostnames / garbage are not bannable addresses
           (is (= -30 (wave10-rpc-code
                       (lambda () (bitcoin-lisp.rpc::rpc-setban
                                   node (list "not-an-ip" "add"))))))
           (is (null (bitcoin-lisp.rpc::rpc-setban node (list "198.51.100.7" "add"))))
           (is (= -23 (wave10-rpc-code
                       (lambda () (bitcoin-lisp.rpc::rpc-setban
                                   node (list "198.51.100.7" "add"))))))
           (is (= -8 (wave10-rpc-code
                      (lambda () (bitcoin-lisp.rpc::rpc-setban
                                  node (list "192.0.2.44" "add" 12345 t))))))
           (is (null (bitcoin-lisp.rpc::rpc-setban node (list "198.51.100.7" "remove"))))
           (is (= -30 (wave10-rpc-code
                       (lambda () (bitcoin-lisp.rpc::rpc-setban
                                   node (list "198.51.100.7" "remove")))))))
      (bitcoin-lisp.networking:clear-ban-list))))

(test wave10-deserialization-errors-are-minus-22
  "submitblock/testmempoolaccept/submitpackage decode failures throw -22
RPC_DESERIALIZATION_ERROR (whole call — no per-tx allowed:false rows)."
  (let ((node (make-test-node)))
    (is (= -22 (wave10-rpc-code
                (lambda () (bitcoin-lisp.rpc::rpc-submitblock node (list "zz"))))))
    (is (= -22 (wave10-rpc-code
                (lambda () (bitcoin-lisp.rpc::rpc-submitblock node (list ""))))))
    (is (= -22 (wave10-rpc-code
                (lambda () (bitcoin-lisp.rpc::rpc-testmempoolaccept
                            node (list (list "nothex!")))))))
    (is (= -22 (wave10-rpc-code
                (lambda () (bitcoin-lisp.rpc::rpc-submitpackage
                            node (list (list "nothex!" "alsonot")))))))))

(test wave10-testmempoolaccept-count-limits
  "testmempoolaccept enforces Core's 1..25 batch bound with -8."
  (let ((node (make-test-node)))
    (is (= -8 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-testmempoolaccept node (list '()))))))
    (is (= -8 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-testmempoolaccept
                           node (list (make-list 26 :initial-element "00")))))))))

(test wave10-misc-error-code-parity
  "generatetoaddress bad address -5; prioritisetransaction bad txid -8;
signmessagewithprivkey bad WIF -5; getblockfilter malformed hash -8."
  (let ((node (make-test-node)))
    (is (= -5 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-generatetoaddress
                           node (list 1 "notanaddress"))))))
    (is (= -8 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-prioritisetransaction
                           node (list "nothex" 0 1000))))))
    (is (= -5 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-signmessagewithprivkey
                           node (list "notawif" "msg"))))))
    (is (= -8 (wave10-rpc-code
               (lambda () (bitcoin-lisp.rpc::rpc-getblockfilter
                           node (list "shorthex"))))))))

(test wave10-verifymessage-error-codes
  "verifymessage: undecodable address -5 'Invalid address'; a decodable
non-P2PKH (bech32) address -3 'Address does not refer to key'."
  (let ((node (make-test-node)))
    (handler-case
        (progn (bitcoin-lisp.rpc::rpc-verifymessage
                node (list "not-an-address" "AAAA" "m"))
               (fail "expected rpc-error"))
      (bitcoin-lisp.rpc::rpc-error (e)
        (is (= -5 (bitcoin-lisp.rpc::rpc-error-code e)))
        (is (string= "Invalid address" (bitcoin-lisp.rpc::rpc-error-message e)))))
    (handler-case
        (progn (bitcoin-lisp.rpc::rpc-verifymessage
                node (list "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx" "AAAA" "m"))
               (fail "expected rpc-error"))
      (bitcoin-lisp.rpc::rpc-error (e)
        (is (= -3 (bitcoin-lisp.rpc::rpc-error-code e)))
        (is (string= "Address does not refer to key"
                     (bitcoin-lisp.rpc::rpc-error-message e)))))))

(test wave10-getblocktemplate-mainnet-gates
  "getblocktemplate on MAINNET with no peers throws -9 (Core's
!isTestChain() gate); test networks skip the gate entirely."
  (let ((node (bitcoin-lisp::make-node :network :mainnet)))
    (handler-case
        (progn (bitcoin-lisp.rpc::rpc-getblocktemplate node nil)
               (fail "expected rpc-error"))
      (bitcoin-lisp.rpc::rpc-error (e)
        (is (= -9 (bitcoin-lisp.rpc::rpc-error-code e)))
        (is (string= "Bitcoin is not connected!"
                     (bitcoin-lisp.rpc::rpc-error-message e)))))))

(test wave10-method-not-found
  "Unknown methods throw -32601 with Core's exact message."
  (bitcoin-lisp.rpc::register-all-methods)
  (handler-case
      (progn (bitcoin-lisp.rpc::dispatch-rpc-method nil "nosuchmethod" '())
             (fail "expected rpc-error"))
    (bitcoin-lisp.rpc::rpc-error (e)
      (is (= -32601 (bitcoin-lisp.rpc::rpc-error-code e)))
      (is (string= "Method not found" (bitcoin-lisp.rpc::rpc-error-message e))))))

;;; ---------------------------------------------------------------------
;;; HTTP layer
;;; ---------------------------------------------------------------------

(test wave10-http-status-mapping
  "JSON-RPC 1.x error responses map -32600->400, -32601->404, else 500;
2.0 responses are always 200 (Core httprpc.cpp JSONErrorReply)."
  (is (= 400 (bitcoin-lisp.rpc::rpc-error-http-status -32600)))
  (is (= 404 (bitcoin-lisp.rpc::rpc-error-http-status -32601)))
  (is (= 500 (bitcoin-lisp.rpc::rpc-error-http-status -5)))
  (is (= 500 (bitcoin-lisp.rpc::rpc-error-http-status -1)))
  (is (= 500 (bitcoin-lisp.rpc::rpc-error-http-status -32700)))
  (let ((ok (bitcoin-lisp.rpc::make-rpc-response 1 1 :v1))
        (nf (bitcoin-lisp.rpc::make-rpc-error-response -32601 "Method not found" 1 :v1))
        (misc (bitcoin-lisp.rpc::make-rpc-error-response -1 "x" 1 :v1)))
    (is (= 200 (bitcoin-lisp.rpc::rpc-response-http-status ok :v1)))
    (is (= 200 (bitcoin-lisp.rpc::rpc-response-http-status ok :v2)))
    (is (= 404 (bitcoin-lisp.rpc::rpc-response-http-status nf :v1)))
    (is (= 200 (bitcoin-lisp.rpc::rpc-response-http-status nf :v2)))
    (is (= 500 (bitcoin-lisp.rpc::rpc-response-http-status misc :v1)))))

(test wave10-jsonrpc-version-and-notification-detection
  "parse-json-rpc-request reports :v2 only for jsonrpc:\"2.0\" and
distinguishes an absent id (notification -> 204) from id:null."
  (multiple-value-bind (type method params id version id-present)
      (bitcoin-lisp.rpc::parse-json-rpc-request
       "{\"jsonrpc\":\"2.0\",\"method\":\"m\"}")
    (declare (ignore method params id))
    (is (eq type :single))
    (is (eq version :v2))
    (is (null id-present)))
  (multiple-value-bind (type method params id version id-present)
      (bitcoin-lisp.rpc::parse-json-rpc-request
       "{\"jsonrpc\":\"2.0\",\"method\":\"m\",\"id\":null}")
    (declare (ignore method params id))
    (is (eq type :single))
    (is (eq version :v2))
    (is (eq t id-present)))
  (multiple-value-bind (type method params id version id-present)
      (bitcoin-lisp.rpc::parse-json-rpc-request
       "{\"method\":\"m\",\"id\":7}")
    (declare (ignore method params))
    (is (eq type :single))
    (is (= 7 id))
    (is (eq version :v1))
    (is (eq t id-present))))

(test wave10-invalid-request-not-parse-error
  "A parseable body with a missing method is -32600 INVALID_REQUEST, not
-32700 PARSE_ERROR (previously swallowed by the outer handler)."
  (handler-case
      (progn (bitcoin-lisp.rpc::parse-json-rpc-request "{\"id\":1}")
             (fail "expected rpc-error"))
    (bitcoin-lisp.rpc::rpc-error (e)
      (is (= -32600 (bitcoin-lisp.rpc::rpc-error-code e)))))
  (handler-case
      (progn (bitcoin-lisp.rpc::parse-json-rpc-request "not json")
             (fail "expected rpc-error"))
    (bitcoin-lisp.rpc::rpc-error (e)
      (is (= -32700 (bitcoin-lisp.rpc::rpc-error-code e))))))

;;; ---------------------------------------------------------------------
;;; D. gettxout include_mempool
;;; ---------------------------------------------------------------------

(test wave10-gettxout-include-mempool-spend
  "A confirmed coin spent by a mempool tx is hidden by default and visible
with include_mempool=false (Core mempool.isSpent path)."
  (let* ((node (make-test-node))
         (utxo (bitcoin-lisp::node-utxo-set node))
         (mempool (bitcoin-lisp::node-mempool node))
         (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 42))
         (spk (bitcoin-lisp.crypto:hex-to-bytes
               "76a914000000000000000000000000000000000000000088ac")))
    (bitcoin-lisp.storage:add-utxo utxo funding 0 100000000 spk 0)
    (let ((hex (bitcoin-lisp.rpc::hash-to-hex funding)))
      ;; Visible while nothing spends it.
      (is (consp (bitcoin-lisp.rpc::rpc-gettxout node (list hex 0))))
      ;; A mempool tx spending funding:0 hides it under include_mempool.
      (let* ((spender (bitcoin-lisp.serialization:make-transaction
                       :version 1
                       :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                        :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                          :hash funding :index 0)
                                        :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                                                  :initial-element 0)
                                        :sequence #xFFFFFFFF))
                       :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                         :value 99990000 :script-pubkey spk))
                       :lock-time 0))
             (spender-txid (bitcoin-lisp.serialization:transaction-hash spender)))
        (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                     mempool spender-txid (make-mempool-entry-for-tx spender))))
        (is (null (bitcoin-lisp.rpc::rpc-gettxout node (list hex 0))))
        (is (null (bitcoin-lisp.rpc::rpc-gettxout node (list hex 0 t))))
        (is (consp (bitcoin-lisp.rpc::rpc-gettxout
                    node (list hex 0 bitcoin-lisp.rpc:+json-false+))))
        ;; null include_mempool = Core default true (spent view).
        (is (null (bitcoin-lisp.rpc::rpc-gettxout node (list hex 0 nil))))
        ;; The SPENDER's own output is visible via the mempool view with 0
        ;; confirmations and coinbase:false.
        (let ((r (bitcoin-lisp.rpc::rpc-gettxout
                  node (list (bitcoin-lisp.rpc::hash-to-hex spender-txid) 0))))
          (is (consp r))
          (is (= 0 (cdr (assoc "confirmations" r :test #'string=))))
          (is (eq 'yason:false (cdr (assoc "coinbase" r :test #'string=))))
          ;; ... and invisible without the mempool (explicit false).
          (is (null (bitcoin-lisp.rpc::rpc-gettxout
                     node (list (bitcoin-lisp.rpc::hash-to-hex spender-txid) 0
                                bitcoin-lisp.rpc:+json-false+)))))))))

;;; ---------------------------------------------------------------------
;;; E. BIP64 /rest/getutxos
;;; ---------------------------------------------------------------------

(defun wave10-getutxos-node ()
  "A test node with one spendable coin; returns (values node txid-hex spk)."
  (let* ((node (make-test-node))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (spk (bitcoin-lisp.crypto:hex-to-bytes
               "76a914111111111111111111111111111111111111111188ac")))
    (bitcoin-lisp.storage:add-utxo
     (bitcoin-lisp::node-utxo-set node) txid 0 250000000 spk 0)
    (values node (bitcoin-lisp.rpc::hash-to-hex txid) spk)))

(test wave10-getutxos-json-bitmap
  "BIP64 json: two outpoints (hit, miss) -> bitmap \"10\", one utxo with
height/value/scriptPubKey (Core interface_rest.py expectations)."
  (multiple-value-bind (node txid-hex spk) (wave10-getutxos-node)
    (let* ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (miss (make-string 64 :initial-element #\e))
           (body (bitcoin-lisp.rpc::rest-handle
                  node (format nil "/rest/getutxos/~A-0/~A-1.json" txid-hex miss)))
           (parsed (yason:parse body)))
      (is (= 200 (hunchentoot:return-code*)))
      (is (string= "10" (gethash "bitmap" parsed)))
      (let ((utxos (gethash "utxos" parsed)))
        (is (= 1 (length utxos)))
        (let ((u (first utxos)))
          (is (= 0 (gethash "height" u)))
          (is (= 5/2 (rational (gethash "value" u))))
          (let ((spk-obj (gethash "scriptPubKey" u)))
            (is (string= (bitcoin-lisp.crypto:bytes-to-hex spk)
                         (gethash "hex" spk-obj)))
            (is (string= "pubkeyhash" (gethash "type" spk-obj)))))))))

(test wave10-getutxos-binary-layout
  "BIP64 .bin: u32 LE height | 32-byte tip hash | CompactSize+bitmap |
CompactSize(n) | per coin u32 dummy 0, u32 LE height, i64 LE value,
CompactSize+spk (Core rest.cpp:56-68,1034-1043)."
  (multiple-value-bind (node txid-hex spk) (wave10-getutxos-node)
    (let* ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (bytes (bitcoin-lisp.rpc::rest-handle
                   node (format nil "/rest/getutxos/~A-0.bin" txid-hex))))
      (is (= 200 (hunchentoot:return-code*)))
      (is (typep bytes '(vector (unsigned-byte 8))))
      (is (= (+ 4 32 2 1 (+ 4 4 8 1 (length spk))) (length bytes)))
      ;; height 0 LE
      (is (equalp #(0 0 0 0) (subseq bytes 0 4)))
      ;; bitmap: 1 byte, first outpoint hit -> LSB set
      (is (= 1 (aref bytes 36)))
      (is (= #x01 (aref bytes 37)))
      ;; one coin follows
      (is (= 1 (aref bytes 38)))
      ;; u32 version dummy 0
      (is (equalp #(0 0 0 0) (subseq bytes 39 43)))
      ;; coin height 0
      (is (equalp #(0 0 0 0) (subseq bytes 43 47)))
      ;; value 250000000 LE over 8 bytes
      (is (= 250000000
             (loop for i from 0 below 8
                   sum (ash (aref bytes (+ 47 i)) (* 8 i)))))
      ;; spk length + bytes
      (is (= (length spk) (aref bytes 55)))
      (is (equalp spk (subseq bytes 56))))))

(test wave10-getutxos-checkmempool
  "checkmempool: a coin spent by a mempool tx drops out of the checkmempool
view but stays in the plain view; a mempool-created coin appears only in the
checkmempool view at MEMPOOL_HEIGHT (Core rest.cpp CCoinsViewMemPool)."
  (multiple-value-bind (node txid-hex spk) (wave10-getutxos-node)
    (let* ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (mempool (bitcoin-lisp::node-mempool node))
           (funding (bitcoin-lisp.rpc::parse-hex-hash txid-hex))
           (spender (bitcoin-lisp.serialization:make-transaction
                     :version 1
                     :inputs (vector (bitcoin-lisp.serialization:make-tx-in
                                      :previous-output (bitcoin-lisp.serialization:make-outpoint
                                                        :hash funding :index 0)
                                      :script-sig (make-array 1 :element-type '(unsigned-byte 8)
                                                                :initial-element 0)
                                      :sequence #xFFFFFFFF))
                     :outputs (vector (bitcoin-lisp.serialization:make-tx-out
                                       :value 249990000 :script-pubkey spk))
                     :lock-time 0))
           (spender-hex (bitcoin-lisp.rpc::hash-to-hex
                         (bitcoin-lisp.serialization:transaction-hash spender))))
      (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                   mempool (bitcoin-lisp.serialization:transaction-hash spender)
                   (make-mempool-entry-for-tx spender))))
      ;; Plain view: funding coin still there.
      (let ((parsed (yason:parse (bitcoin-lisp.rpc::rest-handle
                                  node (format nil "/rest/getutxos/~A-0.json" txid-hex)))))
        (is (string= "1" (gethash "bitmap" parsed))))
      ;; checkmempool: hidden.
      (let ((parsed (yason:parse (bitcoin-lisp.rpc::rest-handle
                                  node (format nil "/rest/getutxos/checkmempool/~A-0.json"
                                               txid-hex)))))
        (is (string= "0" (gethash "bitmap" parsed))))
      ;; Mempool-created coin: only via checkmempool, at MEMPOOL_HEIGHT.
      (let ((parsed (yason:parse (bitcoin-lisp.rpc::rest-handle
                                  node (format nil "/rest/getutxos/~A-0.json" spender-hex)))))
        (is (string= "0" (gethash "bitmap" parsed))))
      (let* ((parsed (yason:parse (bitcoin-lisp.rpc::rest-handle
                                   node (format nil "/rest/getutxos/checkmempool/~A-0.json"
                                                spender-hex))))
             (utxos (gethash "utxos" parsed)))
        (is (string= "1" (gethash "bitmap" parsed)))
        (is (= 1 (length utxos)))
        (is (= 2147483647 (gethash "height" (first utxos))))))))

(test wave10-getutxos-limits-and-parse-errors
  "BIP64 error paths: >15 outpoints, malformed outpoints, empty request,
unknown output format (Core rest.cpp:919-947)."
  (let ((node (make-test-node))
        (hunchentoot:*reply* (make-instance 'hunchentoot:reply))
        (txid (make-string 64 :initial-element #\d)))
    (flet ((status () (hunchentoot:return-code*)))
      ;; 16 outpoints -> 400 max exceeded
      (let ((body (with-output-to-string (s)
                    (dotimes (i 16) (format s "/~A-~D" txid i)))))
        (let ((resp (bitcoin-lisp.rpc::rest-handle
                     node (format nil "/rest/getutxos~A.json" body))))
          (is (= 400 (status)))
          (is (search "max outpoints exceeded" resp))))
      ;; malformed vout (sign / junk / missing)
      (bitcoin-lisp.rpc::rest-handle node (format nil "/rest/getutxos/~A-+1.json" txid))
      (is (= 400 (status)))
      (bitcoin-lisp.rpc::rest-handle node (format nil "/rest/getutxos/~A-1x.json" txid))
      (is (= 400 (status)))
      (bitcoin-lisp.rpc::rest-handle node (format nil "/rest/getutxos/~A-.json" txid))
      (is (= 400 (status)))
      ;; short txid
      (bitcoin-lisp.rpc::rest-handle node "/rest/getutxos/abcd-0.json")
      (is (= 400 (status)))
      ;; empty request
      (bitcoin-lisp.rpc::rest-handle node "/rest/getutxos/.json")
      (is (= 400 (status)))
      ;; unknown format -> Core's 404 "output format not found"
      (let ((resp (bitcoin-lisp.rpc::rest-handle
                   node (format nil "/rest/getutxos/~A-0.xml" txid))))
        (is (= 404 (status)))
        (is (search "output format not found" resp))))))

;;; ---------------------------------------------------------------------
;;; F. Config wires
;;; ---------------------------------------------------------------------

(test wave10-conf-parse-money
  "conf-parse-money follows Core ParseMoney: BTC decimal string -> satoshis;
malformed/negative/9-decimals/oversized -> NIL."
  (is (= 100000000 (bitcoin-lisp::conf-parse-money "1")))
  (is (= 1000 (bitcoin-lisp::conf-parse-money "0.00001")))
  (is (= 1 (bitcoin-lisp::conf-parse-money "0.00000001")))
  (is (= 123456789 (bitcoin-lisp::conf-parse-money "1.23456789")))
  (is (null (bitcoin-lisp::conf-parse-money "x")))
  (is (null (bitcoin-lisp::conf-parse-money "-1")))
  (is (null (bitcoin-lisp::conf-parse-money "0.000000001")))  ; 9 decimals
  (is (null (bitcoin-lisp::conf-parse-money "")))
  (is (null (bitcoin-lisp::conf-parse-money "22000000.00000001")))) ; > MAX_MONEY

(test wave10-conf-parse-user-hex
  "conf-parse-user-hex follows uint256::FromUserHex: optional 0x, up to 64
hex digits, left-padded; junk/overlong -> NIL."
  (let ((z (bitcoin-lisp::conf-parse-user-hex "0")))
    (is (= 32 (length z)))
    (is (every #'zerop z)))
  (let ((v (bitcoin-lisp::conf-parse-user-hex "0xabcd")))
    (is (= #xab (aref v 30)))
    (is (= #xcd (aref v 31)))
    (is (every #'zerop (subseq v 0 30))))
  (is (null (bitcoin-lisp::conf-parse-user-hex "zz")))
  (is (null (bitcoin-lisp::conf-parse-user-hex (make-string 65 :initial-element #\a)))))

(test wave10-config-wires-globals
  "apply-config-globals wires -assumevalid/-minimumchainwork/-mempoolexpiry/
-minrelaytxfee/-blockmintxfee/-bantime/-dnsseed/-fixedseeds/-stopatheight/
-uacomment/-externalip onto their process globals."
  (let ((bitcoin-lisp:*assumevalid-override* :unset)
        (bitcoin-lisp:*minimum-chain-work-override* nil)
        (bitcoin-lisp.mempool:*mempool-expiry-hours* 336)
        (bitcoin-lisp.mempool:*min-relay-fee-rate* 100)
        (bitcoin-lisp.mining:*block-min-tx-fee-rate* 1)
        (bitcoin-lisp.networking:*default-ban-time-seconds* 86400)
        (bitcoin-lisp:*dns-seed-enabled* t)
        (bitcoin-lisp:*fixed-seeds-enabled* t)
        (bitcoin-lisp:*stop-at-height* 0)
        (bitcoin-lisp.serialization:*user-agent* "/bitcoin-lisp:0.1.0/")
        (bitcoin-lisp.networking:*external-ips* '())
        ;; reachability tail scratch state
        (bitcoin-lisp.networking:*reachable-networks* '())
        (bitcoin-lisp.networking:*onlynet-networks* '())
        (bitcoin-lisp.networking:*cjdns-reachable* nil)
        (bitcoin-lisp.networking:*proxy* nil)
        (bitcoin-lisp.networking:*onion-proxy* nil)
        (bitcoin-lisp.networking:*onion-proxy-explicit* nil))
    ;; -assumevalid=<hash>: stored in WIRE order (display reversed)
    (bitcoin-lisp::apply-config-globals '(("assumevalid" . "0xabcd")))
    (is (= #xcd (aref bitcoin-lisp:*assumevalid-override* 0)))
    (is (= #xab (aref bitcoin-lisp:*assumevalid-override* 1)))
    ;; -assumevalid=0 disables
    (bitcoin-lisp::apply-config-globals '(("assumevalid" . "0")))
    (is (null bitcoin-lisp:*assumevalid-override*))
    (signals error (bitcoin-lisp::apply-config-globals '(("assumevalid" . "nothex"))))
    ;; -minimumchainwork
    (bitcoin-lisp::apply-config-globals '(("minimumchainwork" . "0x1234")))
    (is (= #x1234 bitcoin-lisp:*minimum-chain-work-override*))
    (signals error (bitcoin-lisp::apply-config-globals '(("minimumchainwork" . "junk"))))
    ;; -mempoolexpiry / -minrelaytxfee / -blockmintxfee / -bantime
    (bitcoin-lisp::apply-config-globals '(("mempoolexpiry" . "24")))
    (is (= 24 bitcoin-lisp.mempool:*mempool-expiry-hours*))
    (bitcoin-lisp::apply-config-globals '(("minrelaytxfee" . "0.00002")))
    (is (= 2000 bitcoin-lisp.mempool:*min-relay-fee-rate*))
    ;; the mempool built AFTER the wire uses the new floor
    (is (= 2000 (bitcoin-lisp.mempool::mempool-min-fee-rate
                 (bitcoin-lisp.mempool:make-mempool))))
    (signals error (bitcoin-lisp::apply-config-globals '(("minrelaytxfee" . "junk"))))
    (bitcoin-lisp::apply-config-globals '(("blockmintxfee" . "0.00005")))
    (is (= 5000 bitcoin-lisp.mining:*block-min-tx-fee-rate*))
    (bitcoin-lisp::apply-config-globals '(("bantime" . "3600")))
    (is (= 3600 bitcoin-lisp.networking:*default-ban-time-seconds*))
    ;; -dnsseed=0 / -fixedseeds=0 / -stopatheight
    (bitcoin-lisp::apply-config-globals '(("dnsseed" . "0") ("fixedseeds" . "0")
                                          ("stopatheight" . "12345")))
    (is (null bitcoin-lisp:*dns-seed-enabled*))
    (is (null bitcoin-lisp:*fixed-seeds-enabled*))
    (is (= 12345 bitcoin-lisp:*stop-at-height*))
    ;; -uacomment (repeatable, BIP14)
    (bitcoin-lisp::apply-config-globals '(("uacomment" . "alpha") ("uacomment" . "beta")))
    (is (string= "/bitcoin-lisp:0.1.0(alpha; beta)/"
                 bitcoin-lisp.serialization:*user-agent*))
    (signals error (bitcoin-lisp::apply-config-globals '(("uacomment" . "bad(char)"))))
    (signals error (bitcoin-lisp::apply-config-globals
                    (list (cons "uacomment" (make-string 300 :initial-element #\a)))))
    ;; -externalip collected raw
    (bitcoin-lisp::apply-config-globals '(("externalip" . "203.0.113.5")
                                          ("externalip" . "198.51.100.6")))
    (is (= 2 (length bitcoin-lisp.networking:*external-ips*)))))

(test wave10-format-subversion
  "FormatSubVersion parity (Core clientversion.cpp:67-72) + sanitizer."
  (is (string= "/bitcoin-lisp:0.1.0/" (bitcoin-lisp:format-subversion '())))
  (is (string= "/bitcoin-lisp:0.1.0(a; b)/" (bitcoin-lisp:format-subversion '("a" "b"))))
  (is-true (bitcoin-lisp:ua-comment-safe-p "Safe comment .,;-_?@ 123"))
  (is-false (bitcoin-lisp:ua-comment-safe-p "bad(char)")))

(test wave10-mempool-expiry-wire-effective
  "mempool-expire honors *mempool-expiry-hours* (Core -mempoolexpiry)."
  (let ((bitcoin-lisp.mempool:*mempool-expiry-hours* 1)
        (mempool (bitcoin-lisp.mempool:make-mempool))
        (tx (make-mempool-test-tx :input-id 81)))
    ;; entry-time 1000000 (helper default) is far older than 1h before now.
    (is (eq :ok (bitcoin-lisp.mempool:mempool-add
                 mempool (bitcoin-lisp.serialization:transaction-hash tx)
                 (make-mempool-entry-for-tx tx))))
    (is (= 1 (bitcoin-lisp.mempool:mempool-expire mempool)))
    (is (zerop (bitcoin-lisp.mempool:mempool-count mempool)))))

(test wave10-plist-wires
  "config-alist->start-node-plist: -port (validated), -networkactive,
-rest, repeatable -addnode."
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("port" . "12345") ("networkactive" . "0") ("rest" . "1")
                  ("addnode" . "192.0.2.1:8333") ("addnode" . "198.51.100.2"))
                :testnet4)))
    (is (= 12345 (getf plist :port)))
    (is (null (getf plist :network-active)))
    (is (eq t (getf plist :rest)))
    (is (equal '("192.0.2.1:8333" "198.51.100.2") (getf plist :addnode))))
  (signals error (bitcoin-lisp::config-alist->start-node-plist
                  '(("port" . "0")) :testnet4))
  (signals error (bitcoin-lisp::config-alist->start-node-plist
                  '(("port" . "70000")) :testnet4)))

(test wave10-listen-port-override
  "listen-port honors *p2p-port-override* and falls back to the network
default; the dial default (network-port) is never affected."
  (let ((bitcoin-lisp::*p2p-port-override* nil))
    (is (= 48333 (bitcoin-lisp:listen-port :testnet4)))
    (setf bitcoin-lisp::*p2p-port-override* 15555)
    (is (= 15555 (bitcoin-lisp:listen-port :testnet4)))
    (is (= 48333 (bitcoin-lisp:network-port :testnet4)))))

;;; ---------------------------------------------------------------------
;;; G. Argument handling
;;; ---------------------------------------------------------------------

(test wave10-unknown-cli-arg-errors
  "Unknown command-line options and positional tokens are startup errors
(Core ArgsManager::ParseParameters); known options and -no variants pass."
  (finishes (bitcoin-lisp:check-cli-args '("-txindex" "-dbcache=100" "-nolisten"
                                           "-chain=main" "-" "--")))
  (signals error (bitcoin-lisp:check-cli-args '("-bogusopt")))
  (signals error (bitcoin-lisp:check-cli-args '("-bogusopt=1")))
  (signals error (bitcoin-lisp:check-cli-args '("positional")))
  ;; new wave-10 options are recognized
  (finishes (bitcoin-lisp:check-cli-args
             '("-assumevalid=0" "-minimumchainwork=0x00" "-mempoolexpiry=1"
               "-port=1234" "-dnsseed=0" "-nofixedseeds" "-externalip=1.2.3.4"
               "-addnode=x:1" "-bantime=60" "-uacomment=hi" "-blockmintxfee=0.0001"
               "-minrelaytxfee=0.0001" "-stopatheight=5" "-networkactive=0" "-rest"))))

(test wave10-unknown-config-file-keys-warn-only
  "Unknown config-FILE keys are reported for warning, never an error
(Core ReadConfigFiles with ignore_invalid_keys)."
  (is (equal '("frobnicate")
             (bitcoin-lisp:unknown-config-file-keys
              '(("txindex" . "1") ("frobnicate" . "9") ("rest" . "0")))))
  (is (null (bitcoin-lisp:unknown-config-file-keys '(("dbcache" . "100"))))))

(test wave10-repeated-arg-precedence
  "Repeated command-line args: LAST wins; repeatable options keep every
occurrence in order; config-file repeats: FIRST wins; CLI beats config."
  ;; CLI scalar: last occurrence wins
  (let ((a (bitcoin-lisp::parse-cli-args '("-dbcache=100" "-dbcache=200"))))
    (is (string= "200" (cdr (assoc "dbcache" a :test #'string=))))
    (is (= 1 (count "dbcache" a :key #'car :test #'string=))))
  ;; repeatable: all kept, in order
  (let ((a (bitcoin-lisp::parse-cli-args '("-onlynet=ipv4" "-onlynet=ipv6"))))
    (is (equal '("ipv4" "ipv6")
               (loop for (k . v) in a when (string= k "onlynet") collect v))))
  ;; config file scalar: first occurrence wins
  (let ((c (bitcoin-lisp::parse-bitcoin-conf
            (format nil "dbcache=1~%dbcache=2~%"))))
    (is (string= "1" (cdr (assoc "dbcache" c :test #'string=)))))
  ;; CLI over config (merged = cli ++ conf)
  (let* ((cli (bitcoin-lisp::parse-cli-args '("-dbcache=100" "-dbcache=200")))
         (conf (bitcoin-lisp::parse-bitcoin-conf (format nil "dbcache=1~%")))
         (merged (append cli conf)))
    (is (string= "200" (cdr (assoc "dbcache" merged :test #'string=))))))

;;; ---------------------------------------------------------------------
;;; H. Persistence/ops
;;; ---------------------------------------------------------------------

(test wave10-banlist-roundtrip
  "banlist.json: bans persist across a simulated restart; expired entries
are swept at load (Core BanMan LoadBanlist/SweepBanned)."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames (format nil "wave10-banlist-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (path (merge-pathnames "banlist.json" dir))
         (bitcoin-lisp.networking:*banlist-path* path))
    (unwind-protect
         (progn
           (bitcoin-lisp.networking:ban-address "203.0.113.77" 3600)
           (bitcoin-lisp.networking:ban-address "198.51.100.88" 3600)
           (is (probe-file path))
           ;; Simulated restart: wipe memory, reload.
           (clrhash bitcoin-lisp.networking:*banned-peers*)
           (is (not (bitcoin-lisp.networking:peer-banned-p "203.0.113.77")))
           (is (= 2 (bitcoin-lisp.networking:load-banlist)))
           (is (bitcoin-lisp.networking:peer-banned-p "203.0.113.77"))
           (is (bitcoin-lisp.networking:peer-banned-p "198.51.100.88"))
           ;; unban dumps immediately: reload sees 1.
           (bitcoin-lisp.networking:unban-address "203.0.113.77")
           (clrhash bitcoin-lisp.networking:*banned-peers*)
           (is (= 1 (bitcoin-lisp.networking:load-banlist)))
           ;; Expired entries are swept at load.
           (with-open-file (out path :direction :output :if-exists :supersede)
             (write-string "{\"banned_nets\":[{\"version\":1,\"ban_created\":0,\"banned_until\":5,\"address\":\"192.0.2.66\"}]}" out))
           (clrhash bitcoin-lisp.networking:*banned-peers*)
           (is (= 0 (bitcoin-lisp.networking:load-banlist)))
           (is (not (bitcoin-lisp.networking:peer-banned-p "192.0.2.66"))))
      (clrhash bitcoin-lisp.networking:*banned-peers*)
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test wave10-peers-dump-cadence
  "maybe-dump-peer-addresses writes peers.dat on the 15-minute cadence and
not before (Core DumpAddresses every DUMP_PEERS_INTERVAL)."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames (format nil "wave10-peersdump-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (node (bitcoin-lisp::make-node :network :testnet4))
         (bitcoin-lisp::*last-peers-dump-time* 0))
    (setf (bitcoin-lisp::node-data-directory node) dir)
    (setf (bitcoin-lisp::node-address-book node)
          (bitcoin-lisp.networking:make-address-book))
    (unwind-protect
         (progn
           ;; Stale timestamp -> dump fires and the file appears.
           (is (eq t (bitcoin-lisp::maybe-dump-peer-addresses node)))
           (is (probe-file (bitcoin-lisp.networking:peers-dat-path dir)))
           ;; Fresh timestamp -> cadence gate holds.
           (is (null (bitcoin-lisp::maybe-dump-peer-addresses node))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test wave10-stop-at-height-guards
  "maybe-stop-at-height: disabled (0) or below-target heights never trigger;
no node running -> no trigger."
  (let ((bitcoin-lisp:*stop-at-height* 0)
        (bitcoin-lisp::*stop-at-height-triggered* nil)
        (bitcoin-lisp:*node* nil))
    (is (null (bitcoin-lisp:maybe-stop-at-height 100))))
  (let ((bitcoin-lisp:*stop-at-height* 50)
        (bitcoin-lisp::*stop-at-height-triggered* nil)
        (bitcoin-lisp:*node* nil))
    (is (null (bitcoin-lisp:maybe-stop-at-height 49)))
    (is (null (bitcoin-lisp:maybe-stop-at-height 50))) ; no node -> no trigger
    (is (null bitcoin-lisp::*stop-at-height-triggered*))))

(test wave10-check-disk-space
  "check-disk-space: plenty of space passes; an absurd additional-bytes
requirement fails; unreadable paths fail open."
  (is-true (bitcoin-lisp::check-disk-space (uiop:temporary-directory)))
  (is-false (bitcoin-lisp::check-disk-space (uiop:temporary-directory)
                                            (* 1024 1024 1024 1024 1024)))
  ;; Nonexistent directory: df fails -> fail-open T.
  (is-true (bitcoin-lisp::check-disk-space "/nonexistent/wave10/path/")))
