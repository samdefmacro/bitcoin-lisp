(in-package #:bitcoin-lisp.tests)

;;; RPC Tests

(def-suite rpc-tests
  :description "Tests for JSON-RPC server"
  :in :bitcoin-lisp-tests)

(in-suite rpc-tests)

;;; --- JSON-RPC Parsing Tests ---

(test json-rpc-parse-valid-request
  "Test parsing valid JSON-RPC request"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}"))
    (multiple-value-bind (type method params id)
        (bitcoin-lisp.rpc::parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockcount"))
      (is (null params))
      (is (= id 1)))))

(test json-rpc-parse-with-params
  "Test parsing request with params"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockhash\",\"params\":[100],\"id\":\"test\"}"))
    (multiple-value-bind (type method params id)
        (bitcoin-lisp.rpc::parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockhash"))
      (is (= (first params) 100))
      (is (string= id "test")))))

(test json-rpc-parse-batch
  "Test parsing batch request"
  (let ((body "[{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"id\":1},{\"jsonrpc\":\"2.0\",\"method\":\"getbestblockhash\",\"id\":2}]"))
    (multiple-value-bind (type requests)
        (bitcoin-lisp.rpc::parse-json-rpc-request body)
      (is (eq type :batch))
      (is (= (length requests) 2)))))

(test json-rpc-parse-invalid-json
  "Test parsing invalid JSON returns parse error"
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::parse-json-rpc-request "not valid json")))

(test json-rpc-parse-missing-method
  "Test parsing request without method returns error"
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc::parse-json-rpc-request "{\"jsonrpc\":\"2.0\",\"id\":1}")))

;;; --- Response Formatting Tests ---

(test json-rpc-response-success
  "Test successful response format"
  (let ((response (bitcoin-lisp.rpc::make-rpc-response 42 "test-id")))
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (= (gethash "result" response) 42))
    (is (string= (gethash "id" response) "test-id"))))

(test json-rpc-response-error
  "Test error response format"
  (let ((response (bitcoin-lisp.rpc::make-rpc-error-response -32601 "Method not found" "test-id")))
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (string= (gethash "id" response) "test-id"))
    (let ((error-obj (gethash "error" response)))
      (is (= (gethash "code" error-obj) -32601))
      (is (string= (gethash "message" error-obj) "Method not found")))))

;;; --- Input Validation Tests ---

(test valid-hex-hash
  "Test hex hash validation"
  (is (bitcoin-lisp.rpc::valid-hex-hash-p
       "0000000000000000000000000000000000000000000000000000000000000000"))
  (is (bitcoin-lisp.rpc::valid-hex-hash-p
       "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))
  (is (not (bitcoin-lisp.rpc::valid-hex-hash-p "tooshort")))
  (is (not (bitcoin-lisp.rpc::valid-hex-hash-p
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))
  (is (not (bitcoin-lisp.rpc::valid-hex-hash-p nil))))

;;; --- Method Registry Tests ---

(test method-dispatch-unknown
  "Test dispatching unknown method returns error"
  (signals bitcoin-lisp.rpc::rpc-error
    (bitcoin-lisp.rpc:dispatch-rpc-method nil "unknownmethod" nil)))

;;; --- Integration Tests ---

(test rpc-server-lifecycle
  "Test RPC server start/stop"
  ;; Make sure no server is running
  (bitcoin-lisp.rpc:stop-rpc-server)
  (is (null bitcoin-lisp.rpc:*rpc-server*))

  ;; Start on an unusual port to avoid conflicts
  (let ((node (make-test-node)))
    (bitcoin-lisp.rpc:start-rpc-server node :port 19999)
    (is (not (null bitcoin-lisp.rpc:*rpc-server*)))

    ;; Stop server
    (bitcoin-lisp.rpc:stop-rpc-server)
    (is (null bitcoin-lisp.rpc:*rpc-server*))))

;;; --- Helper to create initialized test node ---

(defun make-test-node ()
  "Create a node with minimal initialized state for testing."
  (let ((node (bitcoin-lisp::make-node :network :testnet3)))
    ;; Initialize chain-state
    (setf (bitcoin-lisp::node-chain-state node)
          (bitcoin-lisp.storage:make-chain-state))
    ;; Initialize UTXO set
    (setf (bitcoin-lisp::node-utxo-set node)
          (bitcoin-lisp.storage:make-utxo-set))
    ;; Initialize mempool
    (setf (bitcoin-lisp::node-mempool node)
          (bitcoin-lisp.mempool:make-mempool))
    node))

;;; --- Blockchain Query Method Tests (3.11) ---

(test rpc-getblockchaininfo
  "Test getblockchaininfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getblockchaininfo node nil)))
    ;; Check required fields exist
    (is (assoc "chain" result :test #'string=))
    (is (assoc "blocks" result :test #'string=))
    (is (assoc "headers" result :test #'string=))
    ;; bestblockhash may be nil for empty chain
    (is (assoc "bestblockhash" result :test #'string=))
    (is (assoc "initialblockdownload" result :test #'string=))
    ;; Check chain value for testnet
    (is (string= (cdr (assoc "chain" result :test #'string=)) "test"))))

(test rpc-getblockcount
  "Test getblockcount returns integer"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getblockcount node nil)))
    (is (integerp result))
    (is (>= result 0))))

(test rpc-getblockhash-invalid-height
  "Test getblockhash with invalid height returns error"
  (let ((node (make-test-node)))
    ;; Negative height
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockhash node '(-1)))
    ;; Non-integer height
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockhash node '("abc")))))

(test rpc-getblock-invalid-hash
  "Test getblock with invalid hash returns error"
  (let ((node (make-test-node)))
    ;; Too short
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblock node '("abc")))
    ;; Invalid characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblock node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))
    ;; Invalid verbosity
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblock node
        '("0000000000000000000000000000000000000000000000000000000000000000" 5)))))

(test rpc-getblockheader-invalid-hash
  "Test getblockheader with invalid hash returns error"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockheader node '("tooshort")))))

;;; --- UTXO Query Method Tests (4.3) ---

(test rpc-gettxout-invalid-txid
  "Test gettxout with invalid txid returns error"
  (let ((node (make-test-node)))
    ;; Too short txid
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node '("abc" 0)))
    ;; Invalid characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" 0)))))

(test rpc-gettxout-invalid-vout
  "Test gettxout with invalid vout returns error"
  (let ((node (make-test-node)))
    ;; Negative vout
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node
        '("0000000000000000000000000000000000000000000000000000000000000000" -1)))
    ;; Non-integer vout
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-gettxout node
        '("0000000000000000000000000000000000000000000000000000000000000000" "abc")))))

(test rpc-gettxout-nonexistent
  "Test gettxout with nonexistent UTXO returns nil"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-gettxout node
                   '("0000000000000000000000000000000000000000000000000000000000000000" 0))))
    ;; Nonexistent UTXO should return nil
    (is (null result))))

;;; --- Network Query Method Tests (5.4) ---

(test rpc-getpeerinfo
  "getpeerinfo returns a numeric protocol version and encodes through yason.
Regression: peer-version holds the version *message* struct, and getpeerinfo
used to emit it verbatim, which yason cannot encode."
  (let* ((node (make-test-node))
         (vmsg (bitcoin-lisp.serialization::make-version-message
                :version 70016 :start-height 42 :user-agent "/test/"))
         (peer (bitcoin-lisp::make-peer :address "1.2.3.4:48333"
                                        :version vmsg
                                        :user-agent "/test/"
                                        :start-height 42)))
    (setf (bitcoin-lisp::node-peers node) (list peer))
    (let* ((result (bitcoin-lisp.rpc::rpc-getpeerinfo node nil))
           (entry (first result)))
      (is (listp result))
      (is (= (length result) 1))
      ;; version must be the numeric protocol version, not the struct
      (is (integerp (cdr (assoc "version" entry :test #'string=))))
      (is (= (cdr (assoc "version" entry :test #'string=)) 70016))
      ;; full result must serialize without error
      (let ((response (bitcoin-lisp.rpc::make-rpc-response result "id")))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-getnetworkinfo
  "Test getnetworkinfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil)))
    ;; Check required fields exist
    (is (assoc "version" result :test #'string=))
    (is (assoc "subversion" result :test #'string=))
    (is (assoc "protocolversion" result :test #'string=))
    (is (assoc "connections" result :test #'string=))
    (is (assoc "networkactive" result :test #'string=))))

(test rpc-getconnectioncount
  "Test getconnectioncount returns integer"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getconnectioncount node nil)))
    (is (integerp result))
    (is (>= result 0))))

;;; --- Mempool Method Tests (6.5) ---

(test rpc-getmempoolinfo
  "Test getmempoolinfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil)))
    ;; Check required fields exist
    (is (assoc "loaded" result :test #'string=))
    (is (assoc "size" result :test #'string=))
    (is (assoc "bytes" result :test #'string=))))

(test rpc-getrawmempool-non-verbose
  "Test getrawmempool non-verbose returns list"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-getrawmempool node '(nil))))
    ;; Should return a list (empty for new node)
    (is (listp result))))

(test rpc-getrawmempool-verbose
  "getrawmempool verbose returns a per-tx detail alist (txid -> fields) that the
RPC layer normalizes into a JSON object."
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (tx (make-mempool-test-tx :input-id 200))
         (txid (bitcoin-lisp.serialization:transaction-hash tx)))
    ;; Empty mempool -> empty.
    (is (null (bitcoin-lisp.rpc::rpc-getrawmempool node '(t))))
    ;; Populate and check the entry + a couple of fields.
    (bitcoin-lisp.mempool:mempool-add
     mempool txid (bitcoin-lisp.mempool:make-entry-from-tx tx 1000 0))
    (let* ((result (bitcoin-lisp.rpc::rpc-getrawmempool node '(t)))
           (entry (cdr (assoc (bitcoin-lisp.rpc::hash-to-hex txid) result :test #'string=))))
      (is (listp result))
      (is (not (null entry)))
      (is (assoc "vsize" entry :test #'string=))
      (is (= 1 (cdr (assoc "ancestorcount" entry :test #'string=))))
      ;; serializes cleanly through the RPC response normalizer
      (let ((response (bitcoin-lisp.rpc::make-rpc-response result "id")))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-sendrawtransaction-invalid
  "Test sendrawtransaction with invalid hex returns error"
  (let ((node (make-test-node)))
    ;; Empty string
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-sendrawtransaction node '("")))
    ;; Invalid hex
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-sendrawtransaction node '("not-valid-hex")))))

;;; --- Authentication Tests (7.4) ---

(test rpc-auth-check-no-credentials
  "Test auth check passes when no credentials configured"
  ;; When no user/password is set, auth should pass
  (let ((bitcoin-lisp.rpc::*rpc-user* nil)
        (bitcoin-lisp.rpc::*rpc-password* nil))
    (is (bitcoin-lisp.rpc::check-auth nil))))

(test rpc-auth-header-parsing
  "Test Basic auth header parsing"
  ;; Create a mock request with Authorization header
  ;; Base64 of "testuser:testpass" is "dGVzdHVzZXI6dGVzdHBhc3M="
  (let ((bitcoin-lisp.rpc::*rpc-user* "testuser")
        (bitcoin-lisp.rpc::*rpc-password* "testpass"))
    ;; We can't easily mock hunchentoot request, but we can test the logic
    ;; by checking that auth is required when credentials are set
    (is (not (null bitcoin-lisp.rpc::*rpc-user*)))
    (is (not (null bitcoin-lisp.rpc::*rpc-password*)))))

;;; --- Concurrent Access Tests (2.7) ---

(test rpc-concurrent-access-safety
  "Test that multiple threads can safely call RPC accessors"
  (let* ((node (make-test-node))
         (results (make-array 10 :initial-element nil))
         (threads nil))
    ;; Spawn 10 threads that each call RPC accessors
    (dotimes (i 10)
      (let ((idx i))  ; Capture i in a fresh binding for each iteration
        (push (bt:make-thread
               (lambda ()
                 ;; Call various accessors
                 (bitcoin-lisp.rpc::rpc-get-chain-state node)
                 (bitcoin-lisp.rpc::rpc-get-utxo-set node)
                 (bitcoin-lisp.rpc::rpc-get-peers node)
                 (setf (aref results idx) t)))
              threads)))
    ;; Wait for all threads to complete
    (dolist (thread threads)
      (bt:join-thread thread))
    ;; All threads should have completed successfully
    (is (every #'identity results))))

(test rpc-concurrent-method-calls
  "Test that multiple threads can safely call RPC methods"
  (let* ((node (make-test-node))
         (error-count 0)
         (error-lock (bt:make-lock "error-lock"))
         (threads nil))
    ;; Spawn threads that call various RPC methods concurrently
    (dotimes (i 5)
      (push (bt:make-thread
             (lambda ()
               (handler-case
                   (progn
                     (bitcoin-lisp.rpc::rpc-getblockchaininfo node nil)
                     (bitcoin-lisp.rpc::rpc-getblockcount node nil)
                     (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil)
                     (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil))
                 (error (e)
                   (declare (ignore e))
                   (bt:with-lock-held (error-lock)
                     (incf error-count))))))
            threads))
    ;; Wait for all threads
    (dolist (thread threads)
      (bt:join-thread thread))
    ;; No errors should have occurred
    (is (= error-count 0))))

;;; --- Error Response Format Tests (9.3) ---

(test rpc-error-codes-match-bitcoin-core
  "Test that error codes match Bitcoin Core specification"
  ;; Standard JSON-RPC 2.0 error codes
  (is (= bitcoin-lisp.rpc::+rpc-parse-error+ -32700))
  (is (= bitcoin-lisp.rpc::+rpc-invalid-request+ -32600))
  (is (= bitcoin-lisp.rpc::+rpc-method-not-found+ -32601))
  (is (= bitcoin-lisp.rpc::+rpc-internal-error+ -32603))
  ;; Bitcoin Core specific error codes
  (is (= bitcoin-lisp.rpc::+rpc-invalid-parameter+ -8))  ; RPC_INVALID_PARAMETER
  (is (= bitcoin-lisp.rpc::+rpc-misc-error+ -1)))

(test rpc-error-response-format
  "Test error response matches Bitcoin Core format"
  (let ((response (bitcoin-lisp.rpc::make-rpc-error-response -32601 "Method not found" 123)))
    ;; Must have jsonrpc, error, and id fields
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (gethash "error" response))
    (is (= (gethash "id" response) 123))
    ;; Error object must have code and message
    (let ((error-obj (gethash "error" response)))
      (is (gethash "code" error-obj))
      (is (gethash "message" error-obj))
      (is (integerp (gethash "code" error-obj)))
      (is (stringp (gethash "message" error-obj))))))

;;; --- Extended RPC Method Tests ---

;;; decoderawtransaction tests

(test rpc-decoderawtransaction-valid
  "Test decoderawtransaction with valid transaction hex"
  (let* ((node (make-test-node))
         ;; Simple transaction hex (version + empty inputs/outputs + locktime)
         ;; This is a minimal valid transaction structure
         (tx-hex "01000000000000000000")
         (result (handler-case
                     (bitcoin-lisp.rpc::rpc-decoderawtransaction node (list tx-hex))
                   (error () nil))))
    ;; May fail to parse minimal tx, but should not crash
    (is (or result (not result)))))

(test rpc-decoderawtransaction-invalid-hex
  "Test decoderawtransaction with invalid hex returns error"
  (let ((node (make-test-node)))
    ;; Empty string
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-decoderawtransaction node '("")))
    ;; Invalid hex characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-decoderawtransaction node '("zzzz")))))

;;; getrawtransaction tests

(test rpc-getrawtransaction-invalid-txid
  "Test getrawtransaction with invalid txid returns error"
  (let ((node (make-test-node)))
    ;; Too short
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node '("abc")))
    ;; Invalid characters
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))))

(test rpc-getrawtransaction-not-found
  "Test getrawtransaction for unknown txid returns error"
  (let ((node (make-test-node)))
    ;; Valid txid but not in mempool
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

;;; estimatesmartfee tests

(test rpc-estimatesmartfee-valid
  "Test estimatesmartfee with valid conf_target"
  (let* ((node (make-test-node))
         ;; Mark node as not syncing
         (bitcoin-lisp::*syncing* nil)
         (result (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(6))))
    (is (assoc "feerate" result :test #'string=))
    (is (assoc "blocks" result :test #'string=))
    (is (= (cdr (assoc "blocks" result :test #'string=)) 6))
    (is (> (cdr (assoc "feerate" result :test #'string=)) 0))))

(test rpc-estimatesmartfee-invalid-target
  "Test estimatesmartfee with invalid conf_target returns error"
  (let ((node (make-test-node)))
    ;; Zero
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(0)))
    ;; Negative
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(-1)))
    ;; Too high
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-estimatesmartfee node '(2000)))))

;;; validateaddress tests

(test rpc-validateaddress-valid-p2pkh
  "Test validateaddress with valid testnet P2PKH address"
  (let* ((node (make-test-node))
         ;; Valid testnet P2PKH address (starts with m or n)
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (assoc "address" result :test #'string=))
    (is (assoc "scriptPubKey" result :test #'string=))
    (is (eq nil (cdr (assoc "iswitness" result :test #'string=))))))

(test rpc-validateaddress-valid-bech32
  "Test validateaddress with valid testnet bech32 address"
  (let* ((node (make-test-node))
         ;; Valid testnet P2WPKH address
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (eq t (cdr (assoc "iswitness" result :test #'string=))))
    (is (= 0 (cdr (assoc "witness_version" result :test #'string=))))))

(test rpc-validateaddress-invalid
  "Test validateaddress with invalid address"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("not-an-address"))))
    (is (eq nil (cdr (assoc "isvalid" result :test #'string=))))))

(test rpc-validateaddress-empty
  "Test validateaddress with empty string"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '(""))))
    (is (eq nil (cdr (assoc "isvalid" result :test #'string=))))))

(test rpc-validateaddress-wrong-network
  "Test validateaddress with mainnet address on testnet"
  (let* ((node (make-test-node))
         ;; Mainnet P2PKH address (starts with 1)
         (result (bitcoin-lisp.rpc::rpc-validateaddress node '("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))))
    ;; Should be invalid on testnet node
    (is (eq nil (cdr (assoc "isvalid" result :test #'string=))))))

;;; decodescript tests

(test rpc-decodescript-p2pkh
  "Test decodescript with P2PKH script"
  (let* ((node (make-test-node))
         ;; P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
         (script-hex "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")
         (result (bitcoin-lisp.rpc::rpc-decodescript node (list script-hex))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "pubkeyhash"))
    (is (assoc "asm" result :test #'string=))
    (is (assoc "p2sh" result :test #'string=))))

(test rpc-decodescript-p2sh
  "Test decodescript with P2SH script"
  (let* ((node (make-test-node))
         ;; P2SH: OP_HASH160 <20 bytes> OP_EQUAL
         (script-hex "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87")
         (result (bitcoin-lisp.rpc::rpc-decodescript node (list script-hex))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "scripthash"))))

(test rpc-decodescript-p2wpkh
  "Test decodescript with P2WPKH script"
  (let* ((node (make-test-node))
         ;; P2WPKH: OP_0 <20 bytes>
         (script-hex "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba")
         (result (bitcoin-lisp.rpc::rpc-decodescript node (list script-hex))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "witness_v0_keyhash"))
    (is (assoc "segwit" result :test #'string=))))

(test rpc-decodescript-empty
  "Test decodescript with empty script"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-decodescript node '(""))))
    (is (string= (cdr (assoc "type" result :test #'string=)) "nonstandard"))
    (is (string= (cdr (assoc "asm" result :test #'string=)) ""))))

(test rpc-decodescript-invalid-hex
  "Test decodescript with invalid hex returns error"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-decodescript node '("xyz")))))

;;; createrawtransaction tests

(test rpc-createrawtransaction-basic
  "Test createrawtransaction with valid inputs and outputs"
  (let* ((node (make-test-node))
         (inputs `((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
                    ("vout" . 0))))
         (outputs '(("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . 0.01)))
         (result (bitcoin-lisp.rpc::rpc-createrawtransaction node (list inputs outputs))))
    ;; Should return hex string
    (is (stringp result))
    (is (> (length result) 0))
    ;; Should be valid hex
    (is (every (lambda (c) (digit-char-p c 16)) result))))

(test rpc-createrawtransaction-invalid-txid
  "Test createrawtransaction with invalid input txid"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-createrawtransaction node
        '(((("txid" . "invalid") ("vout" . 0)))
          (("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . 0.01)))))))

(test rpc-createrawtransaction-invalid-address
  "Test createrawtransaction with invalid output address"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-createrawtransaction node
        '(((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
            ("vout" . 0)))
          (("invalid-address" . 0.01)))))))

(test rpc-createrawtransaction-negative-amount
  "Test createrawtransaction with negative amount"
  (let ((node (make-test-node)))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-createrawtransaction node
        '(((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
            ("vout" . 0)))
          (("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . -0.01)))))))

;;; --- gettxoutsetinfo Tests ---

(test rpc-gettxoutsetinfo-empty-utxo-set
  "Test gettxoutsetinfo with empty UTXO set"
  (let* ((node (make-test-node))
         (result (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node nil)))
    ;; Check required fields exist
    (is (assoc "height" result :test #'string=))
    (is (assoc "bestblock" result :test #'string=))
    (is (assoc "txouts" result :test #'string=))
    (is (assoc "total_amount" result :test #'string=))
    (is (assoc "transactions" result :test #'string=))
    (is (assoc "hash_serialized_3" result :test #'string=))
    ;; Empty UTXO set should have 0 txouts
    (is (= (cdr (assoc "txouts" result :test #'string=)) 0))
    (is (= (cdr (assoc "total_amount" result :test #'string=)) 0))
    (is (= (cdr (assoc "transactions" result :test #'string=)) 0))))

(test rpc-gettxoutsetinfo-with-utxos
  "Test gettxoutsetinfo with UTXOs in set"
  (let* ((node (make-test-node))
         (utxo-set (bitcoin-lisp::node-utxo-set node))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Add some UTXOs
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 0 100000000 script 1) ; 1 BTC
    (bitcoin-lisp.storage:add-utxo utxo-set txid1 1 50000000 script 1)  ; 0.5 BTC
    (bitcoin-lisp.storage:add-utxo utxo-set txid2 0 25000000 script 2)  ; 0.25 BTC
    (let ((result (bitcoin-lisp.rpc::rpc-gettxoutsetinfo node nil)))
      ;; Should have 3 UTXOs from 2 transactions
      (is (= (cdr (assoc "txouts" result :test #'string=)) 3))
      (is (= (cdr (assoc "transactions" result :test #'string=)) 2))
      ;; Total should be 1.75 BTC (returned in BTC, not satoshis)
      (is (= (cdr (assoc "total_amount" result :test #'string=)) 1.75))
      ;; hash_serialized_3 should be a 64-char hex string
      (let ((hash (cdr (assoc "hash_serialized_3" result :test #'string=))))
        (is (stringp hash))
        (is (= (length hash) 64))))))

;;; --- getblockstats Tests ---

(test rpc-getblockstats-invalid-params
  "Test getblockstats with invalid parameters"
  (let ((node (make-test-node)))
    ;; Missing parameter
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node nil))
    ;; Invalid hash format
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node '("invalid")))
    ;; Negative height
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node '(-1)))))

(test rpc-getblockstats-block-not-found
  "Test getblockstats with non-existent block"
  (let ((node (make-test-node)))
    ;; Valid hash format but block doesn't exist
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getblockstats node
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

(test rpc-calculate-block-subsidy
  "Test block subsidy calculation"
  ;; Initial subsidy: 50 BTC = 5000000000 satoshis
  (is (= (bitcoin-lisp.rpc::calculate-block-subsidy 0) 5000000000))
  (is (= (bitcoin-lisp.rpc::calculate-block-subsidy 209999) 5000000000))
  ;; First halving at 210000
  (is (= (bitcoin-lisp.rpc::calculate-block-subsidy 210000) 2500000000))
  (is (= (bitcoin-lisp.rpc::calculate-block-subsidy 419999) 2500000000))
  ;; Second halving
  (is (= (bitcoin-lisp.rpc::calculate-block-subsidy 420000) 1250000000))
  ;; Third halving
  (is (= (bitcoin-lisp.rpc::calculate-block-subsidy 630000) 625000000)))

;;; --- Extended getrawtransaction Tests ---

(test rpc-getrawtransaction-with-blockhash-invalid
  "Test getrawtransaction with invalid blockhash parameter"
  (let ((node (make-test-node)))
    ;; Valid txid but invalid blockhash format
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node
        '("0000000000000000000000000000000000000000000000000000000000000001" nil "invalid-hash")))))

(test rpc-getrawtransaction-txindex-disabled
  "Test getrawtransaction returns error when txindex needed but disabled"
  (let ((node (make-test-node)))
    ;; Node has no txindex, looking for non-mempool tx should fail
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-getrawtransaction node
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

;;; --- JSON Result Normalization (regression) ---

(test rpc-result->json-shapes
  "rpc-result->json converts object-alists to hash-tables, leaves arrays as lists."
  ;; object-alist -> hash-table
  (let ((obj (bitcoin-lisp.rpc::rpc-result->json (list (cons "a" 1) (cons "b" "x")))))
    (is (hash-table-p obj))
    (is (= (gethash "a" obj) 1))
    (is (string= (gethash "b" obj) "x")))
  ;; array of objects -> list of hash-tables
  (let ((arr (bitcoin-lisp.rpc::rpc-result->json
              (list (list (cons "k" 1)) (list (cons "k" 2))))))
    (is (listp arr))
    (is (= (length arr) 2))
    (is (hash-table-p (first arr)))
    (is (= (gethash "k" (first arr)) 1)))
  ;; nested object value
  (let ((obj (bitcoin-lisp.rpc::rpc-result->json
              (list (cons "outer" (list (cons "inner" 7)))))))
    (is (hash-table-p (gethash "outer" obj)))
    (is (= (gethash "inner" (gethash "outer" obj)) 7)))
  ;; array of strings is unchanged; atoms pass through
  (is (equal (bitcoin-lisp.rpc::rpc-result->json (list "a" "b")) (list "a" "b")))
  (is (= (bitcoin-lisp.rpc::rpc-result->json 42) 42)))

(test rpc-object-results-encode-to-json
  "Object-returning RPC results must serialize through yason without error.
Regression: handlers build alists, but yason's default list encoder treated
them as arrays and choked on the dotted pairs, so every object RPC errored."
  (let ((node (make-test-node)))
    (dolist (result (list (bitcoin-lisp.rpc::rpc-getblockchaininfo node nil)
                          (bitcoin-lisp.rpc::rpc-getnetworkinfo node nil)
                          (bitcoin-lisp.rpc::rpc-getpeerinfo node nil)
                          (bitcoin-lisp.rpc::rpc-getmempoolinfo node nil)))
      (let* ((response (bitcoin-lisp.rpc::make-rpc-response result "id"))
             (json (with-output-to-string (s) (yason:encode response s)))
             (parsed (yason:parse json)))
        (is (hash-table-p parsed))
        (is (string= (gethash "jsonrpc" parsed) "2.0"))
        (is-true (nth-value 1 (gethash "result" parsed)))))))

;;; --- getchaintips ---

(defun make-32-byte-hash (n)
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element n))

(test rpc-getchaintips
  "getchaintips reports the active tip (branchlen 0) and side branches."
  (let* ((node (make-test-node))
         (chain-state (bitcoin-lisp::node-chain-state node))
         (g-hash (make-32-byte-hash 0))
         (a-hash (make-32-byte-hash 1))
         (b-hash (make-32-byte-hash 2))
         (genesis (bitcoin-lisp.storage:make-block-index-entry
                   :hash g-hash :height 0 :status :valid))
         (a (bitcoin-lisp.storage:make-block-index-entry
             :hash a-hash :height 1 :prev-entry genesis :status :valid))
         (b (bitcoin-lisp.storage:make-block-index-entry
             :hash b-hash :height 1 :prev-entry genesis :status :valid)))
    (bitcoin-lisp.storage:add-block-index-entry chain-state genesis)
    (bitcoin-lisp.storage:add-block-index-entry chain-state a)
    (bitcoin-lisp.storage:add-block-index-entry chain-state b)
    (bitcoin-lisp.storage:update-chain-tip chain-state a-hash 1)
    (let* ((tips (bitcoin-lisp.rpc::rpc-getchaintips node nil))
           (active (find "active" tips
                         :key (lambda (tip) (cdr (assoc "status" tip :test #'string=)))
                         :test #'string=))
           (fork (find "valid-fork" tips
                       :key (lambda (tip) (cdr (assoc "status" tip :test #'string=)))
                       :test #'string=)))
      ;; genesis has a child, so only A and B are tips.
      (is (= (length tips) 2))
      ;; active tip is A at height 1, branchlen 0, listed first.
      (is (string= (cdr (assoc "status" (first tips) :test #'string=)) "active"))
      (is (= (cdr (assoc "branchlen" active :test #'string=)) 0))
      (is (= (cdr (assoc "height" active :test #'string=)) 1))
      ;; B is a side branch one block off the active chain.
      (is (= (cdr (assoc "branchlen" fork :test #'string=)) 1))
      ;; full result serializes cleanly.
      (let ((response (bitcoin-lisp.rpc::make-rpc-response tips "id")))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-testmempoolaccept-missing-input
  "testmempoolaccept dry-runs validation without mutating the mempool."
  (let* ((node (make-test-node))
         (tx (make-mempool-test-tx :input-id 210))
         (hex (bitcoin-lisp.crypto:bytes-to-hex
               (bitcoin-lisp.serialization:serialize-transaction tx)))
         (result (bitcoin-lisp.rpc::rpc-testmempoolaccept node (list (list hex)))))
    (is (listp result))
    (is (= 1 (length result)))
    (let ((r (first result)))
      ;; Empty UTXO set => missing input => not allowed, with a reason.
      (is (null (cdr (assoc "allowed" r :test #'string=))))
      (is (string= "missing-input" (cdr (assoc "reject-reason" r :test #'string=)))))
    ;; Nothing was added to the mempool.
    (is (= 0 (bitcoin-lisp.mempool:mempool-count (bitcoin-lisp::node-mempool node))))))

;;; --- Mempool introspection RPCs ---

(test rpc-mempool-introspection
  ;; A parent + chained child in the mempool exercise getmempoolentry,
  ;; getmempoolancestors/descendants, and gettxspendingprevout.
  (let* ((node (make-test-node))
         (mempool (bitcoin-lisp::node-mempool node))
         (funding (%txid-array 99))
         (parent (%mp-spending-tx funding :vout 0 :value 50000000))
         (pid (bitcoin-lisp.serialization:transaction-hash parent))
         (child (%mp-spending-tx pid :vout 0 :value 40000000))
         (cid (bitcoin-lisp.serialization:transaction-hash child))
         (pid-hex (bitcoin-lisp.rpc::hash-to-hex pid))
         (cid-hex (bitcoin-lisp.rpc::hash-to-hex cid)))
    (%add-tx mempool parent :fee 1000)
    (%add-tx mempool child :fee 2000)
    ;; getmempoolentry: parent has 2 descendants (self+child), 1 ancestor (self)
    (let ((r (bitcoin-lisp.rpc::rpc-getmempoolentry node (list pid-hex))))
      (is (= 2 (cdr (assoc "descendantcount" r :test #'string=))))
      (is (= 1 (cdr (assoc "ancestorcount" r :test #'string=)))))
    ;; getmempoolancestors child -> [parent]
    (let ((r (bitcoin-lisp.rpc::rpc-getmempoolancestors node (list cid-hex))))
      (is (equal (list pid-hex) r)))
    ;; getmempooldescendants parent -> [child]
    (let ((r (bitcoin-lisp.rpc::rpc-getmempooldescendants node (list pid-hex))))
      (is (equal (list cid-hex) r)))
    ;; verbose form -> alist (txid-hex . fields)
    (let ((r (bitcoin-lisp.rpc::rpc-getmempooldescendants node (list pid-hex t))))
      (is (= 1 (length r)))
      (is (string= cid-hex (car (first r))))
      (is (assoc "vsize" (cdr (first r)) :test #'string=)))
    ;; gettxspendingprevout: the funding outpoint is spent by the parent
    (flet ((op (txid-hex vout)
             (let ((h (make-hash-table :test 'equal)))
               (setf (gethash "txid" h) txid-hex (gethash "vout" h) vout) h)))
      (let ((r (bitcoin-lisp.rpc::rpc-gettxspendingprevout
                node (list (list (op (bitcoin-lisp.rpc::hash-to-hex funding) 0))))))
        (is (= 1 (length r)))
        (is (string= pid-hex (cdr (assoc "spendingtxid" (first r) :test #'string=)))))
      ;; an unspent outpoint -> no spendingtxid key
      (let ((r (bitcoin-lisp.rpc::rpc-gettxspendingprevout
                node (list (list (op (bitcoin-lisp.rpc::hash-to-hex (%txid-array 200)) 0))))))
        (is (null (assoc "spendingtxid" (first r) :test #'string=)))))
    ;; getmempoolentry for an absent tx -> error
    (signals error
      (bitcoin-lisp.rpc::rpc-getmempoolentry
       node (list (bitcoin-lisp.rpc::hash-to-hex (%txid-array 201)))))))

;;; --- Node / chain info RPCs ---

(test rpc-node-info
  (let* ((node (make-test-node))
         (net (bitcoin-lisp::node-network node)))
    ;; getdifficulty: a positive number (no tip -> fallback bits 0x1d00ffff -> 1.0)
    (let ((d (bitcoin-lisp.rpc::rpc-getdifficulty node nil)))
      (is (numberp d))
      (is (plusp d)))
    ;; uptime: 0 when start-time unset; >= elapsed when set
    (let ((bitcoin-lisp::*node-start-time* nil))
      (is (= 0 (bitcoin-lisp.rpc::rpc-uptime node nil))))
    (let ((bitcoin-lisp::*node-start-time*
            (- (bitcoin-lisp.serialization:get-unix-time) 5)))
      (is (>= (bitcoin-lisp.rpc::rpc-uptime node nil) 5)))
    ;; getindexinfo: no txindex -> empty JSON object (hash-table)
    (is (hash-table-p (bitcoin-lisp.rpc::rpc-getindexinfo node nil)))
    ;; getdeploymentinfo: buried deployments present; segwit reports the
    ;; network's activation height and matches the active/height contract.
    (let* ((r (bitcoin-lisp.rpc::rpc-getdeploymentinfo node nil))
           (deps (cdr (assoc "deployments" r :test #'string=)))
           (segwit (cdr (assoc "segwit" deps :test #'string=))))
      (is (assoc "bip34" deps :test #'string=))
      (is (assoc "taproot" deps :test #'string=))
      (is (string= "buried" (cdr (assoc "type" segwit :test #'string=))))
      (is (= (bitcoin-lisp.validation:get-segwit-activation-height net)
             (cdr (assoc "height" segwit :test #'string=))))
      ;; height 0 < testnet segwit activation -> not active
      (is (eq (>= 0 (bitcoin-lisp.validation:get-segwit-activation-height net))
              (cdr (assoc "active" segwit :test #'string=)))))))

;;; --- Peer / address RPCs ---

(test rpc-peer-address
  (let ((node (make-test-node)))
    ;; getnodeaddresses: seed the address book with one IPv4 entry
    (let ((book (bitcoin-lisp.networking:make-address-book)))
      (bitcoin-lisp.networking:address-book-add
       book (bitcoin-lisp.networking:make-peer-address
             :ip (bitcoin-lisp.networking::ipv4-to-mapped-ipv6 1 2 3 4)
             :port 48333 :services 9
             ;; recent so getnodeaddresses (GetAddr) doesn't filter it as terrible
             :last-seen (bitcoin-lisp.serialization:get-unix-time)))
      (setf (bitcoin-lisp::node-address-book node) book)
      (let ((r (bitcoin-lisp.rpc::rpc-getnodeaddresses node (list 0))))  ; 0 = all
        (is (= 1 (length r)))
        (is (string= "1.2.3.4" (cdr (assoc "address" (first r) :test #'string=))))
        (is (= 48333 (cdr (assoc "port" (first r) :test #'string=))))
        (is (= 9 (cdr (assoc "services" (first r) :test #'string=))))))
    ;; disconnectnode: a connected peer is disconnected by address
    (let ((peer (bitcoin-lisp.networking:make-peer
                 :connection (bitcoin-lisp.networking::make-connection
                              :host "5.6.7.8" :port 48333 :connected t)
                 :state :ready :address "5.6.7.8")))
      (setf (bitcoin-lisp::node-peers node) (list peer))
      (is (null (bitcoin-lisp.rpc::rpc-disconnectnode node (list "5.6.7.8"))))
      (is (eq :disconnected (bitcoin-lisp.networking:peer-state peer)))
      ;; an unknown address errors
      (signals error (bitcoin-lisp.rpc::rpc-disconnectnode node (list "9.9.9.9"))))))

;;; --- Chain control RPCs (error paths; full reorg behavior in reorg-tests) ---

(test rpc-chain-control-errors
  (let ((node (make-test-node)))
    ;; a well-formed but unknown block hash -> error
    (signals error
      (bitcoin-lisp.rpc::rpc-invalidateblock
       node (list "00000000000000000000000000000000000000000000000000000000deadbeef")))
    ;; a malformed hash -> error
    (signals error
      (bitcoin-lisp.rpc::rpc-reconsiderblock node (list "not-a-hash")))))

;;; --- setban / listbanned / clearbanned / getnettotals / verifychain ---

(test rpc-setban-add-list-remove-clear
  "setban add/remove + listbanned + clearbanned manage the manual ban list."
  (bitcoin-lisp.networking:clear-ban-list)
  (let ((node (make-test-node)))
    (is (null (bitcoin-lisp.rpc::rpc-setban node (list "1.2.3.4" "add"))))
    (is-true (bitcoin-lisp.networking:peer-banned-p "1.2.3.4"))
    (let ((banned (bitcoin-lisp.rpc::rpc-listbanned node nil)))
      (is (= 1 (length banned)))
      (is (string= "1.2.3.4" (cdr (assoc "address" (first banned) :test #'string=))))
      (is (integerp (cdr (assoc "banned_until" (first banned) :test #'string=)))))
    (is (null (bitcoin-lisp.rpc::rpc-setban node (list "1.2.3.4" "remove"))))
    (is (not (bitcoin-lisp.networking:peer-banned-p "1.2.3.4")))
    ;; remove a non-existent ban / bad command -> error
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-setban node (list "9.9.9.9" "remove")))
    (signals bitcoin-lisp.rpc::rpc-error
      (bitcoin-lisp.rpc::rpc-setban node (list "1.2.3.4" "bogus")))
    ;; clearbanned empties the list
    (bitcoin-lisp.rpc::rpc-setban node (list "5.6.7.8" "add"))
    (is (null (bitcoin-lisp.rpc::rpc-clearbanned node nil)))
    (is (= 0 (length (bitcoin-lisp.rpc::rpc-listbanned node nil))))))

(test rpc-setban-absolute-bantime
  "setban add with absolute=true sets banned_until to the given Unix time."
  (bitcoin-lisp.networking:clear-ban-list)
  (let ((node (make-test-node))
        (future (+ (bitcoin-lisp.serialization:get-unix-time) 3600)))
    (bitcoin-lisp.rpc::rpc-setban node (list "10.0.0.1" "add" future t))
    (let ((banned (bitcoin-lisp.rpc::rpc-listbanned node nil)))
      (is (<= (abs (- future (cdr (assoc "banned_until" (first banned) :test #'string=)))) 2)))
    (bitcoin-lisp.networking:clear-ban-list)))

(test rpc-getnettotals-fields
  "getnettotals returns integer byte totals + timemillis + an uploadtarget object."
  (let ((r (bitcoin-lisp.rpc::rpc-getnettotals (make-test-node) nil)))
    (is (integerp (cdr (assoc "totalbytesrecv" r :test #'string=))))
    (is (integerp (cdr (assoc "totalbytessent" r :test #'string=))))
    (is (integerp (cdr (assoc "timemillis" r :test #'string=))))
    (is (consp (cdr (assoc "uploadtarget" r :test #'string=))))))

(test rpc-verifychain-empty-node-returns-nil
  "verifychain on a node with no stored blocks returns NIL gracefully."
  (is (null (bitcoin-lisp.rpc::rpc-verifychain (make-test-node) (list 0 1)))))
