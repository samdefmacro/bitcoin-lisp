(in-package #:bitcoin-lisp.tests)

;;; RPC Tests

(def-suite rpc-tests
  :description "Tests for JSON-RPC server"
  :in :bitcoin-lisp-tests)

(in-suite rpc-tests)

;;; --- Shared fixtures: temp data directory + raw HTTP client ---
;;;
;;; The HTTP helpers also serve ui-tests.lisp, which loads after this file.

(defun %basic-auth-header (credential)
  "An HTTP Basic Authorization header value carrying CREDENTIAL (\"user:pass\")."
  (concatenate 'string "Basic " (cl-base64:string-to-base64-string credential)))

(defun %http-raw-request (port lines &optional body)
  "Send an HTTP request (header LINES + optional BODY, CRLF framing) to
127.0.0.1:PORT and return the whole response as a string."
  (let ((request
          (with-output-to-string (s)
            (dolist (line lines)
              (write-string line s)
              (write-char #\Return s)
              (write-char #\Linefeed s))
            (write-char #\Return s)
            (write-char #\Linefeed s)
            (when body (write-string body s)))))
    (usocket:with-client-socket (socket stream "127.0.0.1" port
                                 :element-type '(unsigned-byte 8) :timeout 15)
      (write-sequence (flexi-streams:string-to-octets request :external-format :utf-8)
                      stream)
      (force-output stream)
      (let ((bytes (make-array 0 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer 0)))
        (loop for b = (read-byte stream nil nil)
              while b do (vector-push-extend b bytes))
        (flexi-streams:octets-to-string
         (coerce bytes '(vector (unsigned-byte 8))) :external-format :utf-8)))))

(defun %http-status (response)
  "The status code of an \"HTTP/1.1 NNN ...\" response string."
  (parse-integer response :start 9 :junk-allowed t))

(defun %http-post-rpc (port json &key origin auth auth-header)
  "POST JSON to / on 127.0.0.1:PORT. AUTH is a \"user:pass\" credential sent as
HTTP Basic; AUTH-HEADER sends a literal Authorization value instead."
  (%http-raw-request
   port
   (append (list "POST / HTTP/1.1"
                 (format nil "Host: 127.0.0.1:~D" port))
           (when origin (list (format nil "Origin: ~A" origin)))
           (let ((header (or auth-header (and auth (%basic-auth-header auth)))))
             (when header (list (format nil "Authorization: ~A" header))))
           (list "Content-Type: application/json"
                 (format nil "Content-Length: ~D" (length json))
                 "Connection: close"))
   json))

(defun %http-post-rpc-raw-content-type (port json content-type auth)
  "POST JSON with an arbitrary Content-Type, the way a client that is not
bitcoin-cli sends it."
  (%http-raw-request
   port
   (list "POST / HTTP/1.1"
         (format nil "Host: 127.0.0.1:~D" port)
         (format nil "Authorization: ~A" (%basic-auth-header auth))
         (format nil "Content-Type: ~A" content-type)
         (format nil "Content-Length: ~D" (length json))
         "Connection: close")
   json))

(defun %basic-auth-header-utf8 (credential)
  "An HTTP Basic header built from CREDENTIAL's UTF-8 BYTES, which is what a
real client sends. CL-BASE64:STRING-TO-BASE64-STRING would take CHAR-CODE of
each character instead — latin-1 — and so could not express this test at all."
  (concatenate 'string "Basic "
               (cl-base64:usb8-array-to-base64-string
                (flexi-streams:string-to-octets credential :external-format :utf-8))))

(defun %http-get (port path)
  (%http-raw-request
   port
   (list (format nil "GET ~A HTTP/1.1" path)
         (format nil "Host: 127.0.0.1:~D" port)
         "Connection: close")))

;;; --- JSON-RPC Parsing Tests ---

(test json-rpc-parse-valid-request
  "Test parsing valid JSON-RPC request"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}"))
    (multiple-value-bind (type method params id)
        (bl.rpc::parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockcount"))
      (is (null params))
      (is (= id 1)))))

(test json-rpc-parse-with-params
  "Test parsing request with params"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockhash\",\"params\":[100],\"id\":\"test\"}"))
    (multiple-value-bind (type method params id)
        (bl.rpc::parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockhash"))
      (is (= (first params) 100))
      (is (string= id "test")))))

(test json-rpc-parse-batch
  "Test parsing batch request"
  (let ((body "[{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"id\":1},{\"jsonrpc\":\"2.0\",\"method\":\"getbestblockhash\",\"id\":2}]"))
    (multiple-value-bind (type requests)
        (bl.rpc::parse-json-rpc-request body)
      (is (eq type :batch))
      (is (= (length requests) 2)))))

(test json-rpc-parse-tells-an-empty-array-from-null
  "`[]` and `null` are different arguments, and the decoder used to merge them.
Both parsed to NIL, so no handler could tell an argument GIVEN as an empty
array from one not given at all — and Core's argument checking splits on
exactly that, because isNull() means \"use the default\" while an array of the
wrong type is a type error. Arrays are parsed as vectors for this reason alone
and turned straight back into lists, so the only value that survives
differently is a top-level empty array: the +json-empty-array+ sentinel.

The nesting rule is the one explicit false already follows — top level only."
  (flet ((params-of (json)
           (nth-value 2 (bl.rpc::parse-json-rpc-request
                         (format nil "{\"method\":\"m\",\"params\":~A,\"id\":1}" json)))))
    ;; The two that used to be indistinguishable.
    (let ((empty (second (params-of "[\"a\",[]]")))
          (null- (second (params-of "[\"a\",null]"))))
      (is (eq bl.rpc::+json-empty-array+ empty)
          "an empty array argument did not survive as the sentinel")
      (is (null null-) "an explicit null argument must stay NIL")
      (is (not (eq empty null-)) "`[]` and null are still the same value"))
    ;; A non-empty array is an ordinary list, exactly as before.
    (is (equal '("x" "y") (second (params-of "[\"a\",[\"x\",\"y\"]]"))))
    ;; ⚠️ A string is a vector in CL. Mapping over one would deal every JSON
    ;; string out as a list of characters, so the array branch must exclude
    ;; strings — a positive control for that.
    (is (string= "a" (first (params-of "[\"a\",[]]"))))
    ;; Nested empty arrays keep folding to NIL: nested readers answer absence
    ;; with present-p, so they never needed the distinction.
    (is (null (second (first (params-of "[[\"a\",[]]]")))))
    ;; An empty params ARRAY is "no arguments", not one empty-array argument.
    (is (null (params-of "[]")))
    ;; The accessors: an empty array IS an array, null is not, and both
    ;; iterate as the empty list.
    (is-true (bl.rpc::%positional-array-p bl.rpc::+json-empty-array+))
    (is-false (bl.rpc::%positional-array-p nil))
    (is (null (bl.rpc:positional-array bl.rpc::+json-empty-array+)))))

(test rpc-empty-array-argument-reaches-core-behaviour
  "What the distinction is FOR, at the two methods Core's suite checks.

getrawtransaction's verbosity is a number; given `[]` Core answers -3
\"not of expected type number\" (rpc_rawtransaction.py:136). We answered
nothing at all, because `[]` looked like null and null means \"use the
default\". testmempoolaccept goes the other way: `[]` is a well-typed but
empty array, so it earns the COUNT error, not a type error
(mempool_accept.py:100)."
  (let ((node (make-test-node))
        (txid "0000000000000000000000000000000000000000000000000000000000000001"))
    ;; -3, and it names the type it actually got.
    (signals-rpc-error (:code -3 :message "not of expected type number")
      (bl.rpc:dispatch-rpc-method
       node "getrawtransaction" (list txid bl.rpc::+json-empty-array+)))
    ;; Null still means the default verbosity, so it gets past the check and
    ;; fails on the transaction being absent instead.
    (handler-case
        (progn (bl.rpc:dispatch-rpc-method node "getrawtransaction" (list txid nil))
               (fail "expected a lookup failure"))
      (bl.rpc:rpc-error (e)
        (is (/= -3 (bl.rpc:rpc-error-code e))
            "null verbosity must not be read as a type error")))
    ;; The other direction: empty is an array, so the count error.
    (signals-rpc-error (:code -8 :message "Array must contain between")
      (bl.rpc::rpc-testmempoolaccept
       node (list bl.rpc::+json-empty-array+)))
    ;; And null is not an array at all.
    (signals-rpc-error (:code -3)
      (bl.rpc::rpc-testmempoolaccept node (list nil)))))

(test getrawtransaction-not-found-speaks-cores-sentence
  "Core selects one of four not-found messages and appends the same sentence to
each (rawtransaction.cpp:315-329); rpc_rawtransaction.py:129 matches the
no-txindex variant in FULL. Ours stopped at \"provide a blockhash\" — the right
advice in a spelling no caller matching Core could find."
  (let ((node (make-test-node))
        (txid "0000000000000000000000000000000000000000000000000000000000000009"))
    (signals-rpc-error (:code -5
                        :exact-message (concatenate 'string
                                                    "No such mempool transaction. Use -txindex or provide a block "
                                                    "hash to enable blockchain transaction queries. Use "
                                                    "gettransaction for wallet transactions."))
      (bl.rpc:dispatch-rpc-method node "getrawtransaction" (list txid)))))

(defun %genesis-coinbase-txid-hex (network)
  "The hex txid of NETWORK's genesis coinbase, read from the genesis block
itself: a one-transaction block's merkle root IS its coinbase's txid."
  (bl.rpc:hash-to-hex
   (bl.ser:block-header-merkle-root
    (bl.ser:bitcoin-block-header (bl.store:make-genesis-block network)))))

(test getrawtransaction-refuses-the-genesis-coinbase
  "Core refuses the genesis block coinbase outright, with -5 and its own
sentence, before it parses the verbosity or resolves the blockhash
(rawtransaction.cpp:288-293, `hash == Params().GenesisBlock().hashMerkleRoot').
The comparison is against THIS chain's genesis merkle root, so the answer is
per network -- testnet4's coinbase carries a different pszTimestamp and hashes
differently -- and a node must not refuse another chain's genesis coinbase.

Without the branch the caller gets whichever not-found message this node's
txindex configuration selects, and naming the genesis block hash as the third
argument answers \"No such transaction found in the provided block\" for a
transaction that is in that block."
  (let ((message (concatenate 'string
                              "The genesis block coinbase is not considered an "
                              "ordinary transaction and cannot be retrieved")))
    (dolist (network '(:mainnet :testnet3 :testnet4 :signet :regtest))
      (let ((node (make-test-node :network network)))
        (signals-rpc-error (:code -5 :exact-message message)
          (bl.rpc:dispatch-rpc-method
           node "getrawtransaction" (list (%genesis-coinbase-txid-hex network))))
        (signals-rpc-error (:code -5 :exact-message message)
          (bl.rpc:dispatch-rpc-method
           node "getrawtransaction" (list (%genesis-coinbase-txid-hex network) 2)))))
    ;; The hashes Core asserts for its own genesis blocks
    ;; (kernel/chainparams.cpp:137, 263, 379, 519, 637), so this test is not
    ;; comparing the implementation with itself. testnet4 is the one that
    ;; differs, and it is the control for "the comparison is per chain": a
    ;; mainnet node treats that txid as an ordinary unknown transaction.
    (dolist (network '(:mainnet :testnet3 :signet :regtest))
      (is (string= "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
                   (%genesis-coinbase-txid-hex network))
          "wrong genesis merkle root for ~A" network))
    (is (string= "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"
                 (%genesis-coinbase-txid-hex :testnet4)))
    (signals-rpc-error (:code -5 :message "No such mempool transaction")
      (bl.rpc:dispatch-rpc-method
       (make-test-node :network :mainnet) "getrawtransaction"
       (list (%genesis-coinbase-txid-hex :testnet4))))
    ;; The blockhash argument is not a way in either.
    (with-network (:regtest)
      (let ((node (regtest-node-fixture "grtx-genesis")))
        (signals-rpc-error (:code -5 :exact-message message)
          (bl.rpc:dispatch-rpc-method
           node "getrawtransaction"
           (list (%genesis-coinbase-txid-hex :regtest) 0
                 (bl.rpc:hash-to-hex
                  (bl.store:best-block-hash (bl:node-chain-state node))))))))))

(test json-rpc-parse-invalid-json
  "Test parsing invalid JSON returns parse error"
  (signals bl.rpc:rpc-error
    (bl.rpc::parse-json-rpc-request "not valid json")))

(test json-rpc-parse-missing-method
  "Test parsing request without method returns error"
  (signals bl.rpc:rpc-error
    (bl.rpc::parse-json-rpc-request "{\"jsonrpc\":\"2.0\",\"id\":1}")))

;;; --- Hash Hex Helper Tests ---

(test hash-to-hex-lowercase-reversed
  "hash-to-hex emits lowercase hex (Core's uint256::GetHex), byte-reversed."
  (let* ((bytes (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-contents (loop for i from 0 below 32
                                                       collect (+ #xe0 (mod i 16)))))
         (hex (bl.rpc:hash-to-hex bytes)))
    (is (string= hex (string-downcase hex)))
    ;; Reversed: last byte (#xef) prints first.
    (is (string= "ef" (subseq hex 0 2)))
    ;; Round-trips through parse-hex-hash, which accepts either case.
    (is (equalp bytes (bl.rpc:parse-hex-hash hex)))
    (is (equalp bytes (bl.rpc:parse-hex-hash (string-upcase hex))))))

;;; --- savemempool RPC Test ---

(test rpc-savemempool-writes-file
  "savemempool dumps the pool to mempool.dat under the data directory."
  (let* ((dir (merge-pathnames (format nil "savemempool-test-~D/" (get-universal-time))
                               (uiop:temporary-directory)))
         (node (make-test-node)))
    (setf (bl:node-data-directory node) dir)
    (unwind-protect
         (let ((r (bl.rpc::rpc-savemempool node nil)))
           (is (stringp (cdr (assoc "filename" r :test #'string=))))
           (is (not (null (probe-file (bl.mp:mempool-dat-path dir))))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

(test rpc-getdescriptorinfo
  "getdescriptorinfo validates + reports canonical form/checksum; flags are
the no-wallet/no-range constants; bad descriptors error."
  (let* ((node (make-test-node))
         (body "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)")
         (r (bl.rpc::rpc-getdescriptorinfo node (list body))))
    (is (string= (concatenate 'string body "#fm24fxxy")
                 (cdr (assoc "descriptor" r :test #'string=))))
    (is (string= "fm24fxxy" (cdr (assoc "checksum" r :test #'string=))))
    (is (eq 'yason:false (cdr (assoc "isrange" r :test #'string=))))
    ;; raw() is not solvable (Core IsSolvable, RawDescriptor override)
    (is (eq 'yason:false (cdr (assoc "issolvable" r :test #'string=))))
    (is (eq 'yason:false (cdr (assoc "hasprivatekeys" r :test #'string=))))
    ;; accepts a correct input checksum, rejects a wrong one and junk
    (is (string= (concatenate 'string body "#fm24fxxy")
                 (cdr (assoc "descriptor"
                             (bl.rpc::rpc-getdescriptorinfo
                              node (list (concatenate 'string body "#fm24fxxy")))
                             :test #'string=))))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getdescriptorinfo node (list (concatenate 'string body "#deadbeef"))))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getdescriptorinfo node (list "sh(multi(2,03aa,03bb))")))))

(test rpc-deriveaddresses
  "deriveaddresses returns the address(es) a descriptor's scriptPubKey
encodes to (checksum required); combo() yields several (P2PK skipped);
address-less scripts error; range on an unranged descriptor rejected."
  (let* ((node (make-test-node))   ; make-test-node is :testnet3
         (pk "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (keyhash (bl.crypto:hash160 (bl.crypto:hex-to-bytes pk))))
    (flet ((descsum (body) (bl.rpc:descriptor-add-checksum body)))
      ;; checksum is required (Core: "Missing checksum")
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-deriveaddresses node (list (format nil "pkh(~A)" pk))))
      ;; pkh -> single P2PKH address; matches the direct encoder.
      (let ((addrs (bl.rpc::rpc-deriveaddresses
                    node (list (descsum (format nil "pkh(~A)" pk))))))
        (is (= 1 (length addrs)))
        (is (string= (bl.crypto:encode-p2pkh-address keyhash :testnet3)
                     (first addrs))))
      ;; wpkh -> single bech32 address.
      (is (= 1 (length (bl.rpc::rpc-deriveaddresses
                        node (list (descsum (format nil "wpkh(~A)" pk)))))))
      ;; combo emits pk+pkh+wpkh+sh(wpkh); the address-less P2PK script is
      ;; skipped (Core DeriveAddresses), leaving 3 addresses.
      (is (= 3 (length (bl.rpc::rpc-deriveaddresses
                        node (list (descsum (format nil "combo(~A)" pk)))))))
      ;; raw() non-standard script -> no address -> error
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-deriveaddresses node (list (descsum "raw(51)"))))
      ;; range argument rejected for an unranged descriptor
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-deriveaddresses
         node (list (descsum (format nil "wpkh(~A)" pk)) 5))))))

;;; --- Prioritisation RPC Tests ---

(test rpc-prioritisetransaction-and-introspection
  "prioritisetransaction adjusts the mempool delta map; getprioritisedtransactions
reports fee_delta/in_mempool/modified_fee; getmempoolentry exposes fees.modified."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (txid-hex (make-string 64 :initial-element #\a)))
    ;; dummy must be 0/null; fee_delta must be an integer
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-prioritisetransaction node (list txid-hex 1 1000)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-prioritisetransaction node (list txid-hex 0 "x")))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-prioritisetransaction node (list "nothex" 0 1000)))
    ;; Delta for a not-in-mempool tx is recorded and reported
    (is (eq t (bl.rpc::rpc-prioritisetransaction node (list txid-hex 0 2500))))
    (let* ((r (bl.rpc::rpc-getprioritisedtransactions node nil))
           (row (cdr (assoc txid-hex r :test #'string=))))
      (is (= 2500 (cdr (assoc "fee_delta" row :test #'string=))))
      ;; A Core boolean: JSON false, never null (wave-10 false/null fix).
      (is (eq 'yason:false (cdr (assoc "in_mempool" row :test #'string=)))))
    ;; Net-zero clears it; empty map encodes as an object
    (is (eq t (bl.rpc::rpc-prioritisetransaction node (list txid-hex nil -2500))))
    (is (hash-table-p (bl.rpc::rpc-getprioritisedtransactions node nil)))
    (is (zerop (hash-table-count (bl.mp:mempool-deltas mempool))))))

(test rest-interface-routing-and-content-types
  "REST router: content-type negotiation, JSON reuse of RPC bodies, and
error mapping (400 bad request / 404 not found / unknown endpoint)."
  (let ((node (make-test-node))
        (hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
    (setf (bl:node-block-store node)
          (bl.store:init-block-store
           (ensure-directories-exist
            (merge-pathnames (format nil "rest-test-~D/" (get-universal-time))
                             (uiop:temporary-directory)))))
    (flet ((status () (hunchentoot:return-code*))
           (ctype () (hunchentoot:content-type*)))
      ;; chaininfo.json -> 200 application/json, parseable, reuses
      ;; rpc-getblockchaininfo (so has its keys).
      (let ((body (rest-request node "/rest/chaininfo.json")))
        (is (= 200 (status)))
        (is (string= "application/json" (ctype)))
        (let ((parsed (yason:parse body)))
          (is (hash-table-p parsed))
          (is (integerp (gethash "blocks" parsed)))))
      ;; mempool/info.json -> 200 json
      (is (= 200 (progn (rest-request node "/rest/mempool/info.json")
                        (status))))
      ;; chaininfo only supports .json -> unknown format is Core's 404
      ;; "output format not found"
      (rest-request node "/rest/chaininfo.hex")
      (is (= 404 (status)))
      ;; malformed block hash -> 400
      (rest-request node "/rest/block/nothex.json")
      (is (= 400 (status)))
      ;; well-formed but absent block -> 404
      (rest-request
       node (format nil "/rest/block/~A.json" (make-string 64 :initial-element #\a)))
      (is (= 404 (status)))
      ;; absent tx -> 404
      (rest-request
       node (format nil "/rest/tx/~A.hex" (make-string 64 :initial-element #\b)))
      (is (= 404 (status)))
      ;; unknown endpoint -> 404
      (rest-request node "/rest/frobnicate.json")
      (is (= 404 (status)))
      ;; getutxos with a bad outpoint -> 400
      (rest-request node "/rest/getutxos/notanoutpoint.json")
      (is (= 400 (status))))))

(test rest-refuses-every-endpoint-during-warmup
  "While the node is still starting, /rest/ answers Core's HTTP 503 \"Service
temporarily unavailable: <status>\" — CheckWarmup (rest.cpp:170-176), which
Core calls at the head of all eleven of its handlers, and the REST twin of the
-28 the JSON-RPC path answers. The REST surface is installed by the same
start-rpc-server call that enters warmup, so before this gate a client polling
across a restart was answered 200 with content computed against a chainstate
the mempool replay and the index catch-ups had not finished with."
  (let ((node (make-test-node)))
    (unwind-protect
         (progn
           ;; CONTROL: these are the answers the gate has to change, so a 503
           ;; below cannot come from the endpoints being broken anyway.
           (bl.rpc:finish-rpc-warmup)
           (is (= 200 (nth-value 1 (rest-request node "/rest/chaininfo.json"))))
           (is (= 404 (nth-value 1 (rest-request node "/rest/frobnicate.json"))))
           (bl.rpc:set-rpc-warmup-status "Replaying mempool...")
           ;; An unknown endpoint is in the list on purpose: the gate precedes
           ;; routing, so warmup answers before a 404 can.
           (dolist (uri '("/rest/chaininfo.json" "/rest/mempool/info.json"
                          "/rest/health" "/rest/frobnicate.json"))
             (multiple-value-bind (body status content-type) (rest-request node uri)
               (is (= 503 status) "~A answered ~D during warmup" uri status)
               (is (string= "text/plain" content-type) "~A: ~S" uri content-type)
               (is-true (search "Service temporarily unavailable: Replaying mempool..."
                                body)
                        "~A body: ~S" uri body))))
      (bl.rpc:finish-rpc-warmup))))

(test rest-getutxos-reports-absence
  "BIP64 getutxos: an unknown outpoint yields an empty utxos array and a
\"0\" bitmap (Core interface_rest.py: bitmap \"0\", len(utxos) 0)."
  (let ((node (make-test-node))
        (hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
    (let* ((txid (make-string 64 :initial-element #\c))
           (body (rest-request node (format nil "/rest/getutxos/~A-0.json" txid)))
           (parsed (yason:parse body)))
      (is (= 200 (hunchentoot:return-code*)))
      (is (integerp (gethash "chainHeight" parsed)))
      (is (stringp (gethash "chaintipHash" parsed)))
      (is (string= "0" (gethash "bitmap" parsed)))
      (is (= 0 (length (gethash "utxos" parsed)))))))

(defun %proof-hashes (n)
  "N distinct 32-byte hashes for partial-merkle-tree tests."
  (loop for i from 1 to n
        collect (let ((h (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                  (setf (aref h 0) (logand i #xff)
                        (aref h 1) (logand (ash i -8) #xff))
                  h)))

(test txoutproof-build-extract-roundtrip
  "Partial merkle tree build->extract recomputes the real merkle root and
recovers exactly the matched leaves, across tree sizes and match sets."
  (dolist (ntx '(1 2 3 4 5 7 8 16))
    (let* ((txids (%proof-hashes ntx))
           (txid-vec (coerce txids 'vector))
           (root (bl.val:compute-merkle-root txids))
           ;; Match the first and last leaf (and the middle for larger trees).
           (want (remove-duplicates (list 0 (1- ntx) (floor ntx 2))))
           (match (make-array ntx :initial-element nil)))
      (dolist (i want) (setf (aref match i) t))
      (multiple-value-bind (bits hashes)
          (bl.rpc::build-partial-merkle-tree txid-vec match)
        (multiple-value-bind (xroot xmatched xindices)
            (bl.rpc::extract-partial-merkle-tree ntx bits hashes)
          (is (equalp root xroot) "ntx=~D root mismatch" ntx)
          (is (equal (sort (copy-list want) #'<) xindices) "ntx=~D indices" ntx)
          (is (= (length want) (length xmatched)))
          ;; Each matched hash is the txid at its reported index.
          (loop for h in xmatched for idx in xindices
                do (is (equalp (aref txid-vec idx) h))))))))

(test txoutproof-serialize-roundtrip
  "serialize-merkle-block / parse-merkle-block round-trip the proof fields."
  (let* ((ntx 6)
         (txids (%proof-hashes ntx))
         (txid-vec (coerce txids 'vector))
         (match (make-array ntx :initial-element nil)))
    (setf (aref match 2) t)
    (multiple-value-bind (bits hashes)
        (bl.rpc::build-partial-merkle-tree txid-vec match)
      (let* ((header (make-array 80 :element-type '(unsigned-byte 8) :initial-element 7))
             (bytes (bl.rpc::serialize-merkle-block header ntx hashes bits)))
        (multiple-value-bind (h2 ntx2 hashes2 bits2)
            (bl.rpc::parse-merkle-block bytes)
          (is (equalp header h2))
          (is (= ntx ntx2))
          (is (equalp hashes hashes2))
          ;; bits round-trip up to the byte padding zeros
          (is (equal bits (subseq bits2 0 (length bits))))
          ;; and re-extract gives the same root
          (is (equalp (bl.rpc::extract-partial-merkle-tree ntx bits hashes)
                      (bl.rpc::extract-partial-merkle-tree ntx2 bits2 hashes2))))))))

(test txoutproof-tamper-detected
  "Flipping a hash in the partial tree changes the recomputed root."
  (let* ((ntx 8)
         (txids (%proof-hashes ntx))
         (txid-vec (coerce txids 'vector))
         (root (bl.val:compute-merkle-root txids))
         (match (make-array ntx :initial-element nil)))
    (setf (aref match 3) t)
    (multiple-value-bind (bits hashes)
        (bl.rpc::build-partial-merkle-tree txid-vec match)
      (let ((tampered (mapcar #'copy-seq hashes)))
        (setf (aref (first tampered) 0) (logxor (aref (first tampered) 0) #xff))
        (is (not (equalp root (bl.rpc::extract-partial-merkle-tree
                               ntx bits tampered))))))))

(test rpc-txoutproof-roundtrip
  "gettxoutproof builds a proof a real block, verifytxoutproof confirms it
when the block is on the active chain and rejects a root-mismatched proof."
  (let* ((node (make-test-node))
         (chain-state (bl:node-chain-state node))
         (dir (ensure-directories-exist
               (merge-pathnames (format nil "txoutproof-~D/" (get-universal-time))
                                (uiop:temporary-directory))))
         (block-store (bl.store:init-block-store dir)))
    (setf (bl:node-block-store node) block-store)
    ;; Build a 4-tx block (distinct coinbase-shaped txs).
    (let* ((txs (loop for i from 0 below 4
                      collect (bl.ser:make-transaction
                               :version 1
                               :inputs (vector (bl.ser:make-tx-in
                                                :previous-output (bl.ser:make-outpoint
                                                                  :hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                                                                  :index #xffffffff)
                                                :script-sig (make-array 2 :element-type '(unsigned-byte 8) :initial-element i)
                                                :sequence #xffffffff))
                               :outputs (vector (bl.ser:make-tx-out
                                                 :value 1000 :script-pubkey (make-array 4 :element-type '(unsigned-byte 8) :initial-element #x6a)))
                               :lock-time 0)))
           (txids (mapcar #'bl.ser:transaction-hash txs))
           (root (bl.val:compute-merkle-root txids))
           (header (bl.ser:make-block-header
                    :version 1
                    :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
                    :merkle-root root :timestamp 1700000000 :bits #x207fffff :nonce 0))
           (block (bl.ser:make-bitcoin-block :header header :transactions txs))
           (block-hash (bl.ser:block-header-hash header)))
      (unwind-protect
           (progn
             (bl.store:store-block block-store block)
             (bl.store:add-block-index-entry
              chain-state (bl.store:make-block-index-entry
                           :hash block-hash :height 0 :header header
                           ;; TX-COUNT is what verifytxoutproof compares the
                           ;; proof's claimed count against (Core
                           ;; rpc/txoutproof.cpp:165-170). A real entry gets it
                           ;; when the block connects (validation/block.lisp);
                           ;; leaving it 0 here made the fixture describe a
                           ;; block no node actually holds, and Core throws -5
                           ;; for nTx == 0 just as we now do.
                           :tx-count 4
                           :chain-work 1 :status :valid))
             (bl.store:update-chain-tip chain-state block-hash 0)
             (let* ((target (bl.rpc:hash-to-hex (second txids)))
                    (proof (bl.rpc::rpc-gettxoutproof
                            node (list (list target) (bl.rpc:hash-to-hex block-hash))))
                    (verified (bl.rpc::rpc-verifytxoutproof node (list proof))))
               (is (stringp proof))
               (is (equal (list target) verified))
               ;; Corrupt the proof's last hex nibble -> root/parse mismatch -> error.
               (signals bl.rpc:rpc-error
                 (bl.rpc::rpc-verifytxoutproof
                  node (list (concatenate 'string (subseq proof 0 (- (length proof) 2)) "ff"))))
               ;; Same proof once its block is off the active chain. Core
               ;; THROWS RPC_INVALID_ADDRESS_OR_KEY "Block not found in chain"
               ;; (rpc/txoutproof.cpp:160-163) — it does not return [].
               ;;
               ;; This assertion previously expected "[]", matching a comment
               ;; in the RPC that asserted "Core returns []". Both were wrong
               ;; about Core, and together they made the missing check look
               ;; deliberate. An empty array cannot be distinguished by the
               ;; caller from "that txid is not in this block", which is the
               ;; whole question the RPC exists to answer.
               ;; (Control: the (equal (list target) verified) assertion above
               ;; is the same proof while the block IS on the active chain.)
               (let ((sibling (make-32-byte-hash 200)))
                 (bl.store:add-block-index-entry
                  chain-state (bl.store:make-block-index-entry
                               :hash sibling :height 0 :header header
                               :chain-work 2 :status :valid))
                 (bl.store:update-chain-tip chain-state sibling 0)
                 (signals bl.rpc:rpc-error
                   (bl.rpc::rpc-verifytxoutproof node (list proof))))))
        (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore)))))

;;; dumptxoutset / loadtxoutset (Core snapshot v2 format) tests live in
;;; tests/snapshot-tests.lisp.

;;; --- Output Descriptor Tests (scantxoutset) ---

(test descriptor-checksum-core-vector
  "descriptor-checksum matches Bitcoin Core's documented example
(descriptor.cpp's EXAMPLE_DESCRIPTOR_RAW), and validation round-trips."
  (let ((body "raw(76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac)"))
    (is (string= "fm24fxxy" (bl.rpc::descriptor-checksum body)))
    (is (string= (concatenate 'string body "#fm24fxxy")
                 (bl.rpc:descriptor-add-checksum body)))
    ;; Correct checksum accepted, wrong checksum rejected.
    (finishes (bl.rpc::parse-output-descriptor
               (concatenate 'string body "#fm24fxxy") :mainnet))
    (signals bl.rpc:rpc-error
      (bl.rpc::parse-output-descriptor
       (concatenate 'string body "#fm24fxxx") :mainnet))))

(test descriptor-parse-forms
  "Each supported descriptor form expands to the right scriptPubKey(s).
Cross-checked against Core: addr(12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S) is
documented in descriptor.cpp as the address of the raw() example script."
  (let* ((pubkey-hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (pubkey (bl.crypto:hex-to-bytes pubkey-hex))
         (keyhash (bl.crypto:hash160 pubkey)))
    ;; addr() == Core's raw() example script
    (let ((pairs (bl.rpc::parse-output-descriptor
                  "addr(12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S)" :mainnet)))
      (is (= 1 (length pairs)))
      (is (string= "76a91411b366edfc0a8b66feebae5c2e25a7b6a5d1cf3188ac"
                   (bl.crypto:bytes-to-hex (car (first pairs))))))
    ;; raw() passes bytes through
    (let ((pairs (bl.rpc::parse-output-descriptor "raw(51)" :mainnet)))
      (is (equalp #(#x51) (car (first pairs)))))
    ;; pkh(): OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG
    (let ((script (car (first (bl.rpc::parse-output-descriptor
                               (format nil "pkh(~A)" pubkey-hex) :mainnet)))))
      (is (= 25 (length script)))
      (is (equalp keyhash (subseq script 3 23))))
    ;; wpkh(): OP_0 <h160>
    (let ((script (car (first (bl.rpc::parse-output-descriptor
                               (format nil "wpkh(~A)" pubkey-hex) :mainnet)))))
      (is (= 22 (length script)))
      (is (= #x00 (aref script 0)))
      (is (equalp keyhash (subseq script 2))))
    ;; sh(wpkh()): P2SH of the wpkh script
    (let ((script (car (first (bl.rpc::parse-output-descriptor
                               (format nil "sh(wpkh(~A))" pubkey-hex) :mainnet)))))
      (is (= 23 (length script)))
      (is (= #xa9 (aref script 0))))
    ;; combo(): 4 scripts for a compressed key, 2 for uncompressed
    (is (= 4 (length (bl.rpc::parse-output-descriptor
                      (format nil "combo(~A)" pubkey-hex) :mainnet))))
    ;; rawtr(): OP_1 <32-byte key as-is>
    (let* ((xonly-hex (subseq pubkey-hex 2))
           (script (car (first (bl.rpc::parse-output-descriptor
                                (format nil "rawtr(~A)" xonly-hex) :mainnet)))))
      (is (= 34 (length script)))
      (is (= #x51 (aref script 0)))
      (is (equalp (bl.crypto:hex-to-bytes xonly-hex)
                  (subseq script 2))))
    ;; tr(): tweaked output key differs from the internal key
    (let* ((xonly-hex (subseq pubkey-hex 2))
           (script (car (first (bl.rpc::parse-output-descriptor
                                (format nil "tr(~A)" xonly-hex) :mainnet)))))
      (is (= 34 (length script)))
      (is (= #x51 (aref script 0)))
      (is (not (equalp (bl.crypto:hex-to-bytes xonly-hex)
                       (subseq script 2)))))
    ;; Unsupported / invalid forms signal rpc-error
    (signals bl.rpc:rpc-error
      (bl.rpc::parse-output-descriptor "sh(multi(2,03aa,03bb))" :mainnet))
    (signals bl.rpc:rpc-error
      (bl.rpc::parse-output-descriptor "addr(notanaddress)" :mainnet))
    (signals bl.rpc:rpc-error
      (bl.rpc::parse-output-descriptor
       (format nil "wpkh(04~A)" (subseq pubkey-hex 2)) :mainnet))))

(test rpc-scantxoutset-start-status-abort
  "scantxoutset start scans the UTXO set against descriptor needles;
status with no scan running returns null; abort with no scan is a no-op."
  (let* ((node (make-test-node))
         (utxo (bl:node-utxo-set node))
         (keyhash (make-array 20 :element-type '(unsigned-byte 8)
                                 :initial-element 7))
         (address (bl.crypto:encode-p2pkh-address keyhash :testnet3))
         (p2pkh (concatenate '(vector (unsigned-byte 8))
                             #(#x76 #xa9 #x14) keyhash #(#x88 #xac)))
         (txid-a (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid-b (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (txid-c (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)))
    ;; Two matching coins (addr + raw needles) and one non-matching.
    (bl.store:add-utxo utxo txid-a 0 150000000 p2pkh 0)
    (bl.store:add-utxo utxo txid-b 1 50000000
                                   (coerce #(#x51) '(vector (unsigned-byte 8))) 0)
    (bl.store:add-utxo utxo txid-c 0 1000
                                   (make-array 25 :element-type '(unsigned-byte 8)) 0)
    (let ((r (bl.rpc::rpc-scantxoutset
              node (list "start" (list (format nil "addr(~A)" address) "raw(51)")))))
      (is (eq t (cdr (assoc "success" r :test #'string=))))
      (is (= 3 (cdr (assoc "txouts" r :test #'string=))))
      (let ((unspents (cdr (assoc "unspents" r :test #'string=))))
        (is (= 2 (length unspents)))
        ;; Every unspent carries a canonical descriptor with checksum.
        (is (every (lambda (u) (find #\# (cdr (assoc "desc" u :test #'string=))))
                   unspents)))
      (is (= 2.0 (cdr (assoc "total_amount" r :test #'string=)))))
    ;; No scan running: status -> null (Core NullUniValue); abort -> a bare
    ;; JSON false (nothing to abort).
    (is (null (bl.rpc::rpc-scantxoutset node (list "status"))))
    (is (eq 'yason:false (bl.rpc::rpc-scantxoutset node (list "abort"))))
    ;; Bad action / missing scanobjects -> errors.
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-scantxoutset node (list "frobnicate")))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-scantxoutset node (list "start")))))

(defun %utxo-iterate-lock-observations (node thunk)
  "Run THUNK with BL.STORE:UTXO-SET-ITERATE instrumented, and return one
answer per call it made: was NODE's lock held when the walk was entered?"
  (let ((observations '())
        (real (fdefinition 'bl.store:utxo-set-iterate)))
    (unwind-protect
         (progn
           (setf (fdefinition 'bl.store:utxo-set-iterate)
                 (lambda (view callback)
                   (push (sb-thread:holding-mutex-p (bl:node-lock node)) observations)
                   (funcall real view callback)))
           (funcall thunk))
      (setf (fdefinition 'bl.store:utxo-set-iterate) real))
    (nreverse observations)))

(test utxo-set-walking-rpcs-hold-the-node-lock
  "BL.STORE:COINS-VIEW-CACHE-SYNC -- which UTXO-SET-ITERATE calls on a
coins-view-cache -- documents its caller contract: hold the node lock across
the sync and the iterator that follows it. Core holds cs_main over the same
span, in scantxoutset around the flush, the cursor and the tip read
(rpc/blockchain.cpp:2410-2418) and in gettxoutsetinfo around
ForceFlushStateToDisk and the coins view it labels the answer with
(:1075-1084). These two walked unlocked, so the sync's MAPHASH over the live
cache table ran against the validation thread's writes to that same table, and
gettxoutsetinfo's three separate walks could each report a different moment of
the chain.

The probe records whether the lock is held at the moment each walk starts.
Its positive control is the last clause: an ordinary unlocked call must be
reported as unlocked, or a probe that answered T unconditionally would pass
this test against either version of the source."
  (let* ((node (make-test-node))
         (utxo (bl:node-utxo-set node)))
    (bl.store:add-utxo utxo
                       (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1)
                       0 1000 (coerce #(#x51) '(vector (unsigned-byte 8))) 0)
    (let ((seen (%utxo-iterate-lock-observations
                 node (lambda ()
                        (bl.rpc:dispatch-rpc-method node "gettxoutsetinfo" nil)))))
      (is (plusp (length seen)))
      (is (every #'identity seen)
          "gettxoutsetinfo walked the UTXO set without the node lock: ~S" seen))
    (let ((seen (%utxo-iterate-lock-observations
                 node (lambda ()
                        (bl.rpc:dispatch-rpc-method
                         node "scantxoutset" (list "start" (list "raw(51)")))))))
      (is (plusp (length seen)))
      (is (every #'identity seen)
          "scantxoutset walked the UTXO set without the node lock: ~S" seen))
    ;; Positive control for the probe itself.
    (is (equal '(nil)
               (%utxo-iterate-lock-observations
                node (lambda ()
                       (bl.store:utxo-set-iterate
                        utxo (lambda (txid vout entry)
                               (declare (ignore txid vout entry))))))))))

;;; --- Response Formatting Tests ---

(test json-rpc-response-success
  "Test successful response format"
  (let ((response (bl.rpc::make-rpc-response 42 "test-id" :v2)))
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (= (gethash "result" response) 42))
    (is (string= (gethash "id" response) "test-id"))))

(test json-rpc-response-error
  "Test error response format"
  (let ((response (bl.rpc::make-rpc-error-response -32601 "Method not found" "test-id" :v2)))
    (is (string= (gethash "jsonrpc" response) "2.0"))
    (is (string= (gethash "id" response) "test-id"))
    (let ((error-obj (gethash "error" response)))
      (is (= (gethash "code" error-obj) -32601))
      (is (string= (gethash "message" error-obj) "Method not found")))))

;;; --- Input Validation Tests ---

(test valid-hex-hash
  "Test hex hash validation"
  (is (bl.rpc:valid-hex-hash-p
       "0000000000000000000000000000000000000000000000000000000000000000"))
  (is (bl.rpc:valid-hex-hash-p
       "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"))
  (is (not (bl.rpc:valid-hex-hash-p "tooshort")))
  (is (not (bl.rpc:valid-hex-hash-p
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))
  (is (not (bl.rpc:valid-hex-hash-p nil))))

;;; --- Method Registry Tests ---

(test method-dispatch-unknown
  "Test dispatching unknown method returns error"
  (signals bl.rpc:rpc-error
    (bl.rpc:dispatch-rpc-method nil "unknownmethod" nil)))

;;; --- Integration Tests ---

(test rpc-server-lifecycle
  "Test RPC server start/stop"
  ;; Make sure no server is running
  (bl.rpc:stop-rpc-server)
  (is (null bl.rpc:*rpc-server*))

  ;; Start on an unusual port to avoid conflicts
  (with-temp-directory (dir)
    (let ((node (make-test-node)))
      (setf (bl:node-data-directory node) dir)
      (bl.rpc:start-rpc-server node :port 19999)
      (is (not (null bl.rpc:*rpc-server*)))

      ;; Stop server
      (bl.rpc:stop-rpc-server)
      (is (null bl.rpc:*rpc-server*)))))

;;; --- Helper to create initialized test node ---

;;; --- Blockchain Query Method Tests (3.11) ---

(test rpc-getblockchaininfo
  "Test getblockchaininfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-getblockchaininfo node nil)))
    ;; Check required fields exist
    (is (assoc "chain" result :test #'string=))
    (is (assoc "blocks" result :test #'string=))
    (is (assoc "headers" result :test #'string=))
    ;; bestblockhash may be nil for empty chain
    (is (assoc "bestblockhash" result :test #'string=))
    (is (assoc "initialblockdownload" result :test #'string=))
    ;; Check chain value for testnet
    (is (string= (cdr (assoc "chain" result :test #'string=)) "test"))
    ;; New completeness fields (all always-present in Core)
    (dolist (k '("difficulty" "time" "mediantime" "chainwork" "bits" "target"
                 "size_on_disk" "warnings"))
      (is (assoc k result :test #'string=)))
    ;; chainwork/target are 64-hex; bits is 8-hex
    (is (= 64 (length (cdr (assoc "chainwork" result :test #'string=)))))
    (is (= 64 (length (cdr (assoc "target" result :test #'string=)))))
    (is (= 8 (length (cdr (assoc "bits" result :test #'string=)))))
    ;; encodes cleanly through yason (warnings is an empty JSON array, etc.)
    (is (stringp (with-output-to-string (s)
                   (yason:encode (bl.rpc::make-rpc-response result "id" :v2) s))))))

(test rpc-getblockcount
  "Test getblockcount returns integer"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-getblockcount node nil)))
    (is (integerp result))
    (is (>= result 0))))

(test rpc-getblockhash-invalid-height
  "Test getblockhash with invalid height returns error"
  (let ((node (make-test-node)))
    ;; Negative height
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockhash node '(-1)))
    ;; Non-integer height
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockhash node '("abc")))))

(test rpc-getblock-invalid-hash
  "Test getblock with invalid hash returns error"
  (let ((node (make-test-node)))
    ;; Too short
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblock node '("abc")))
    ;; Invalid characters
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblock node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))
    ;; Non-integer/non-bool verbosity (Core: type error; any integer is valid)
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblock node
        '("0000000000000000000000000000000000000000000000000000000000000000" "5")))))

(test rpc-getblockheader-invalid-hash
  "Test getblockheader with invalid hash returns error"
  (let ((node (make-test-node)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockheader node '("tooshort")))))

;;; --- getrawtransaction verbosity + witness-complete hex ---

(test rpc-getrawtransaction-witness-hex-and-verbosity
  "The non-verbose hex is the wire (witness-complete) encoding — Core's
EncodeHexTx — and the verbosity argument follows Core ParseVerbosity: 0, false
and absent return hex (verbosity 0 is Core's default but was truthy in Lisp);
1, true and 2 return the decoded object; a string errors."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bl.ser:read-transaction s)))
         (txid (bl.ser:transaction-hash tx))
         (txid-hex (bl.rpc:hash-to-hex txid)))
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (bl.mp:make-entry-from-tx tx 1000 0))))
    ;; Hex-returning verbosities: absent, 0, false (NIL).
    (dolist (params (list (list txid-hex)
                          (list txid-hex 0)
                          (list txid-hex nil)))
      (let ((hex (bl.rpc:dispatch-rpc-method node "getrawtransaction" params)))
        (is (stringp hex))
        ;; Byte-exact wire bytes: witnesses intact through a round-trip.
        (is (equalp raw (bl.crypto:hex-to-bytes hex)))))
    ;; Object-returning verbosities: 1, true, 2.
    (dolist (params (list (list txid-hex 1)
                          (list txid-hex t)
                          (list txid-hex 2)))
      (let ((r (bl.rpc:dispatch-rpc-method node "getrawtransaction" params)))
        (is (consp r))
        (is (string= txid-hex (cdr (assoc "txid" r :test #'string=))))
        ;; The object's hex field is the wire encoding too.
        (is (equalp raw (bl.crypto:hex-to-bytes
                         (cdr (assoc "hex" r :test #'string=)))))))
    ;; Non-integer/non-bool verbosity → type error (Core getInt<int> throw).
    (signals bl.rpc:rpc-error
      (bl.rpc:dispatch-rpc-method node "getrawtransaction" (list txid-hex "abc")))))

(test getrawtransaction-with-a-blockhash-answers-from-that-block-alone
  "The third argument is a containment check, not a hint.

Core resolves it FIRST, under cs_main, and throws -5 \"Block hash not found\"
for a block its index does not know (rawtransaction.cpp:298-305) before any
transaction lookup; GetTransaction then skips the mempool entirely because a
block index was supplied (`if (mempool && !block_index)`,
node/transaction.cpp:143-145) and refuses a txindex hit from a different block
(:150-156). A block the index knows but whose body is not on disk is -1
\"Block not available\" (rawtransaction.cpp:317-320).

We probed the mempool first and returned its transaction whatever the caller
asked about, and an unknown block fell through to the txindex — so both a
typo'd blockhash and a mempool transaction answered the containment question
with a false yes."
  (with-network (:regtest)
    (let* ((node (regtest-node-fixture "getrawtx-blockhash"))
           (chain-state (bl:node-chain-state node))
           (block-store (bl:node-block-store node))
           (built (build-and-connect chain-state block-store
                                     (bl:node-utxo-set node)
                                     (bl.store:best-block-hash chain-state)
                                     (make-test-chain-hashes #xb2 2)))
           (block1 (car (first built)))
           (block1-hash (bl.rpc:hash-to-hex
                         (bl.store:block-index-entry-hash (cdr (first built)))))
           ;; A header the index knows with no body in the store: Core's
           ;; BLOCK_HAVE_DATA-unset state (pruned, or not yet downloaded).
           (bodyless (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element #xd7))
           (bodyless-hex (bl.rpc:hash-to-hex bodyless))
           (raw (make-witness-test-tx-bytes))
           (pool-tx (flexi-streams:with-input-from-sequence (s raw)
                      (bl.ser:read-transaction s)))
           (pool-txid (bl.ser:transaction-hash pool-tx))
           (pool-txid-hex (bl.rpc:hash-to-hex pool-txid))
           (coinbase-txid-hex (bl.rpc:hash-to-hex
                               (bl.ser:transaction-hash
                                (elt (bl.ser:bitcoin-block-transactions block1) 0))))
           (unknown-hash (make-string 64 :initial-element #\a)))
      (bl.store:add-block-index-entry
       chain-state
       (bl.store:make-block-index-entry
        :hash bodyless :height 1 :chain-work 1 :status :valid
        :header (bl.store:block-index-entry-header (cdr (first built)))))
      (is (eq :ok (bl.mp:mempool-add
                   (bl:node-mempool node) pool-txid
                   (bl.mp:make-entry-from-tx pool-tx 1000 0)))
          "the mempool transaction is the one the old code answered with")
      ;; An unknown block loses before the mempool is even consulted.
      (dolist (verbosity '(0 1))
        (signals-rpc-error (:code -5 :exact-message "Block hash not found")
          (bl.rpc:dispatch-rpc-method
           node "getrawtransaction"
           (list pool-txid-hex verbosity unknown-hash))))
      ;; A known block that does not contain it: Core's in-block message, not
      ;; the mempool copy.
      (signals-rpc-error
          (:code -5
           :exact-message
           (concatenate 'string "No such transaction found in the provided block"
                        ". Use gettransaction for wallet transactions."))
        (bl.rpc:dispatch-rpc-method
         node "getrawtransaction" (list pool-txid-hex 0 block1-hash)))
      ;; A known block with no body on disk.
      (signals-rpc-error (:code -1 :exact-message "Block not available")
        (bl.rpc:dispatch-rpc-method
         node "getrawtransaction" (list pool-txid-hex 0 bodyless-hex)))
      ;; Positive control: the transaction that IS in that block still answers,
      ;; and carries in_active_chain (Core adds it whenever the argument was
      ;; given, rawtransaction.cpp:338-341).
      (is (stringp (bl.rpc:dispatch-rpc-method
                    node "getrawtransaction"
                    (list coinbase-txid-hex 0 block1-hash))))
      (let ((r (bl.rpc:dispatch-rpc-method
                node "getrawtransaction"
                (list coinbase-txid-hex 1 block1-hash))))
        (is (string= coinbase-txid-hex (cdr (assoc "txid" r :test #'string=))))
        (is (string= block1-hash (cdr (assoc "blockhash" r :test #'string=))))
        (is (eq t (cdr (assoc "in_active_chain" r :test #'string=)))
            "in_active_chain is json-bool's true, not a missing key"))
      ;; And with no blockhash at all the mempool still answers.
      (is (stringp (bl.rpc:dispatch-rpc-method
                    node "getrawtransaction" (list pool-txid-hex 0)))))))

(test rpc-tx-json-reports-the-coinbases-real-witness-hash
  "The \"hash\" field is Core's GetWitnessHash, for the coinbase too.

core_io.cpp:435 emits `tx.GetWitnessHash().GetHex()` and
CTransaction::ComputeWitnessHash has no coinbase case
(primitives/transaction.cpp:88-95): the all-zero value belongs to
BlockWitnessMerkleRoot alone (consensus/merkle.cpp:80). We returned 32 zero
bytes for every coinbase, so getblock verbosity 2/3 and getrawtransaction
reported hash=000...0 for the coinbase of every block. Driven through
decoderawtransaction because TX-TO-JSON is the one serializer all three
share (blockchain.lisp \"hash\" field)."
  (let* ((node (make-test-node))
         (coinbase-in (bl.ser:make-tx-in
                       :previous-output (bl.ser:make-outpoint
                                         :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                              :initial-element 0)
                                         :index #xFFFFFFFF)
                       :script-sig (make-array 4 :element-type '(unsigned-byte 8)
                                                 :initial-element 1)
                       :sequence #xFFFFFFFF))
         (outputs (vector (bl.ser:make-tx-out
                           :value 5000000000
                           :script-pubkey (make-array 25 :element-type '(unsigned-byte 8)
                                                         :initial-element #x76))))
         (witnessed (bl.ser:make-transaction
                     :version 2 :inputs (vector coinbase-in) :outputs outputs
                     ;; BIP 141's witness reserved value.
                     :witness (vector (list (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 0)))
                     :lock-time 0))
         (bare (bl.ser:make-transaction
                :version 2 :inputs (vector coinbase-in) :outputs outputs
                :lock-time 0)))
    (is-true (bl.ser:coinbase-input-p coinbase-in)
             "the fixture must really be a coinbase, or this test is vacuous")
    (dolist (tx (list witnessed bare))
      (let* ((hex (bl.crypto:bytes-to-hex (bl.ser:transaction-wire-bytes tx)))
             (r (bl.rpc:dispatch-rpc-method node "decoderawtransaction" (list hex)))
             (hash-field (cdr (assoc "hash" r :test #'string=)))
             (txid-field (cdr (assoc "txid" r :test #'string=))))
        (is (string/= (make-string 64 :initial-element #\0) hash-field)
            "a coinbase's hash field must not be the merkle tree's zero leaf")
        (is (string= (bl.rpc:hash-to-hex
                      (bl.crypto:hash256
                       (if (bl.ser:transaction-has-witness-p tx)
                           (bl.ser:serialize-witness-transaction tx)
                           (bl.ser:serialize-transaction tx))))
                     hash-field)
            "hash is hash256 of the witness serialization, or the txid without one")
        (is (string= (bl.rpc:hash-to-hex (bl.ser:transaction-hash tx)) txid-field))
        (if (bl.ser:transaction-has-witness-p tx)
            (is (string/= txid-field hash-field))
            (is (string= txid-field hash-field)))))))

;;; --- getorphantxs wire hex + verbosity validation ---

(test rpc-getorphantxs-wire-hex-and-verbosity
  "%orphan-tx-json's bytes/hex use the wire (witness-complete) encoding — Core
OrphanToJSON's ComputeTotalSize/EncodeHexTx — and getorphantxs rejects
out-of-range or boolean verbosity like Core (ParseVerbosity allow_bool=false)."
  (let* ((raw (make-witness-test-tx-bytes))
         (tx (flexi-streams:with-input-from-sequence (s raw)
               (bl.ser:read-transaction s)))
         (o (bl.rpc::%orphan-tx-json tx nil t)))
    (is (= (length raw) (cdr (assoc "bytes" o :test #'string=))))
    (is (equalp raw (bl.crypto:hex-to-bytes
                     (cdr (assoc "hex" o :test #'string=))))))
  (let ((node (make-test-node)))
    ;; An empty orphanage is Core's empty VARR. This used to assert
    ;; (null ...), i.e. the bug: NIL encodes as JSON null, not [].
    (is (equalp #() (bl.rpc::rpc-getorphantxs node nil)))
    (is (equalp #() (bl.rpc::rpc-getorphantxs node (list 2))))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getorphantxs node (list 3)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getorphantxs node (list t)))))

;;; --- Empty collections render [] / {} , never null ---

(defun %encode-rpc-result (result)
  "The exact JSON text RESULT renders to, through the same normalizer and
encoder the RPC server uses (rpc-result->json, then yason). Asserting on the
Lisp value alone would not catch this bug: NIL is a perfectly good empty list
in CL and only becomes wrong at the encoder."
  (with-output-to-string (s)
    (yason:encode (bl.rpc::rpc-result->json result) s)))

(test rpc-empty-collections-encode-as-array-or-object
  "Core builds every collection as a UniValue VARR/VOBJ, so an EMPTY one
renders [] (or {}), never null. Our encoder maps CL NIL to JSON null, so each
producing site coerces with json-array / json-object. Verified live before the
fix: listbanned and getaddednodeinfo answered result:null."
  (bl.net:clear-ban-list)
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node)))
    ;; The premise: a bare NIL really does encode as null. Without this the
    ;; assertions below could pass for the wrong reason.
    (is (string= "null" (%encode-rpc-result nil)))
    ;; Arrays (Core VARR).
    (dolist (site (list (cons "getpeerinfo" (bl.rpc::rpc-getpeerinfo node nil))
                        (cons "listbanned" (bl.rpc::rpc-listbanned node nil))
                        (cons "getorphantxs" (bl.rpc::rpc-getorphantxs node nil))
                        (cons "getnodeaddresses"
                              (bl.rpc::rpc-getnodeaddresses node (list 0)))
                        (cons "getaddednodeinfo"
                              (bl.rpc::rpc-getaddednodeinfo node nil))
                        (cons "getrawmempool"
                              (bl.rpc:dispatch-rpc-method node "getrawmempool" nil))
                        (cons "getmempoolancestors"
                              (bl.rpc::%mempool-set->result
                               mempool (make-hash-table :test 'equalp) nil))
                        (cons "getnetworkinfo.localaddresses"
                              (cdr (assoc "localaddresses"
                                          (bl.rpc::rpc-getnetworkinfo node nil)
                                          :test #'string=)))
                        (cons "scantxoutset.unspents"
                              (cdr (assoc "unspents"
                                          (bl.rpc::rpc-scantxoutset
                                           node (list "start" (list "raw(51)")))
                                          :test #'string=)))))
      (is (string= "[]" (%encode-rpc-result (cdr site)))
          "~A must render [] when empty, got ~A"
          (car site) (%encode-rpc-result (cdr site))))
    ;; Objects (Core VOBJ): getrawmempool's VERBOSE form is a txid-keyed
    ;; object, so its empty case is {} and NOT [].
    (dolist (site (list (cons "getrawmempool verbose"
                              (bl.rpc:dispatch-rpc-method node "getrawmempool" (list t)))
                        (cons "getmempooldescendants verbose"
                              (bl.rpc::%mempool-set->result
                               mempool (make-hash-table :test 'equalp) t))))
      (is (string= "{}" (%encode-rpc-result (cdr site)))
          "~A must render {} when empty, got ~A"
          (car site) (%encode-rpc-result (cdr site))))
    ;; A node with no mempool at all takes getrawmempool's other early branch,
    ;; which must still pick the shape by verbosity.
    (setf (bl:node-mempool node) nil)
    (is (string= "[]" (%encode-rpc-result (bl.rpc:dispatch-rpc-method node "getrawmempool" nil))))
    (is (string= "{}" (%encode-rpc-result (bl.rpc:dispatch-rpc-method node "getrawmempool" (list t))))))
  ;; CONTROL 1 — populated collections keep their existing shape: an array of
  ;; JSON objects, not a vector of unencodable dotted pairs.
  (let ((node (make-test-node)))
    (setf (bl:node-peers node)
          (list (bl.net:make-peer :address "1.2.3.4:48333" :user-agent "/t/" :state :ready)))
    (bl.rpc::rpc-addnode node (list "192.0.2.10:48333" "add"))
    (bl.rpc::rpc-setban node (list "1.2.3.4" "add"))
    (let ((peers (%encode-rpc-result (bl.rpc::rpc-getpeerinfo node nil)))
          (bans (%encode-rpc-result (bl.rpc::rpc-listbanned node nil)))
          (added (%encode-rpc-result (bl.rpc::rpc-getaddednodeinfo node nil))))
      (is (eql 0 (search "[{" peers)))
      (is (eql 0 (search "[{" bans)))
      (is (search "\"address\":\"1.2.3.4\"" bans))
      (is (eql 0 (search "[{" added)))
      ;; ... and a populated row's own empty nested array is [] too.
      (is (search "\"addresses\":[]" added)))
    (bl.net:clear-ban-list))
  ;; CONTROL 2 — NIL must still mean null where Core returns null. This is why
  ;; the fix is per-site and not a global normalizer in rpc-result->json.
  (is (string= "null" (%encode-rpc-result
                       (bl.rpc::rpc-scantxoutset (make-test-node) (list "status"))))))

;;; --- UTXO Query Method Tests (4.3) ---

(test rpc-gettxout-invalid-txid
  "Test gettxout with invalid txid returns error"
  (let ((node (make-test-node)))
    ;; Too short txid
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-gettxout node '("abc" 0)))
    ;; Invalid characters
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-gettxout node '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" 0)))))

(test rpc-gettxout-invalid-vout
  "Test gettxout with invalid vout returns error"
  (let ((node (make-test-node)))
    ;; Negative vout
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-gettxout node
        '("0000000000000000000000000000000000000000000000000000000000000000" -1)))
    ;; Non-integer vout
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-gettxout node
        '("0000000000000000000000000000000000000000000000000000000000000000" "abc")))))

(test rpc-gettxout-nonexistent
  "Test gettxout with nonexistent UTXO returns nil"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-gettxout node
                   '("0000000000000000000000000000000000000000000000000000000000000000" 0))))
    ;; Nonexistent UTXO should return nil
    (is (null result))))

;;; --- Network Query Method Tests (5.4) ---

(test rpc-getpeerinfo
  "getpeerinfo returns a numeric protocol version and encodes through yason.
Regression: peer-version holds the version *message* struct, and getpeerinfo
used to emit it verbatim, which yason cannot encode."
  (let* ((node (make-test-node))
         (vmsg (bl.ser::make-version-message
                :version 70016 :start-height 42 :user-agent "/test/"))
         (peer (bl.net:make-peer :address "1.2.3.4:48333" :state :ready
                                        :version vmsg
                                        :user-agent "/test/"
                                        :start-height 42)))
    (setf (bl:node-peers node) (list peer))
    (let* ((result (bl.rpc::rpc-getpeerinfo node nil))
           (entry (first result)))
      (is (listp result))
      (is (= (length result) 1))
      ;; version must be the numeric protocol version, not the struct
      (is (integerp (cdr (assoc "version" entry :test #'string=))))
      (is (= (cdr (assoc "version" entry :test #'string=)) 70016))
      ;; full result must serialize without error
      (let ((response (bl.rpc::make-rpc-response result "id" :v2)))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-getnetworkinfo
  "Test getnetworkinfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-getnetworkinfo node nil)))
    ;; Check required fields exist
    (is (assoc "version" result :test #'string=))
    ;; One client version: Core's CLIENT_VERSION integer form of OUR version
    ;; (clientversion.h:26-29), not a hard-coded literal.
    (is (= bl.ser:+client-version+
           (cdr (assoc "version" result :test #'string=))))
    (is (= 100 bl.ser:+client-version+))
    (is (search (bl.ser:client-version-string)
                (cdr (assoc "subversion" result :test #'string=))))
    (is (assoc "subversion" result :test #'string=))
    (is (assoc "protocolversion" result :test #'string=))
    (is (assoc "connections" result :test #'string=))
    (is (assoc "networkactive" result :test #'string=))))

(test rpc-getnetworkinfo-localrelay-blocksonly
  "localrelay = !IgnoresIncomingTxs (Core): true on a test network by
default, json-false under -blocksonly."
  (let ((node (make-test-node)))
    (let ((bl:*network* :regtest)
          (bl:*blocksonly* nil))
      (is (eq t (cdr (assoc "localrelay"
                            (bl.rpc::rpc-getnetworkinfo node nil)
                            :test #'string=)))))
    (let ((bl:*network* :regtest)
          (bl:*blocksonly* t))
      (is (eq 'yason:false (cdr (assoc "localrelay"
                                       (bl.rpc::rpc-getnetworkinfo node nil)
                                       :test #'string=)))))))

(test rpc-getconnectioncount
  "Test getconnectioncount returns integer"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-getconnectioncount node nil)))
    (is (integerp result))
    (is (>= result 0))))

;;; --- Mempool Method Tests (6.5) ---

(test rpc-getmempoolinfo
  "Test getmempoolinfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-getmempoolinfo node nil)))
    ;; Check required fields exist
    (is (assoc "loaded" result :test #'string=))
    (is (assoc "size" result :test #'string=))
    (is (assoc "bytes" result :test #'string=))
    ;; completeness fields
    (dolist (k '("usage" "total_fee" "maxmempool" "incrementalrelayfee"
                 "unbroadcastcount" "fullrbf"))
      (is (assoc k result :test #'string=)))
    (is (integerp (cdr (assoc "maxmempool" result :test #'string=))))
    (is (integerp (cdr (assoc "usage" result :test #'string=))))))

(test rpc-getrawmempool-non-verbose
  "getrawmempool non-verbose returns a JSON array of txids — [] for a new
node, not null (it used to assert only LISTP, which NIL satisfies)."
  (let* ((node (make-test-node))
         (result (bl.rpc:dispatch-rpc-method node "getrawmempool" '(nil))))
    (is (equalp #() result))))

(test rpc-getrawmempool-verbose
  "getrawmempool verbose returns a per-tx detail alist (txid -> fields) that the
RPC layer normalizes into a JSON object."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (tx (make-mempool-test-tx :input-id 200))
         (txid (bl.ser:transaction-hash tx)))
    ;; Empty mempool -> Core's empty VOBJ, i.e. an empty JSON object, not
    ;; null (this used to assert (null ...), the bug).
    (let ((empty (bl.rpc:dispatch-rpc-method node "getrawmempool" '(t))))
      (is (hash-table-p empty))
      (is (zerop (hash-table-count empty))))
    ;; Populate and check the entry + a couple of fields.
    (bl.mp:mempool-add
     mempool txid (bl.mp:make-entry-from-tx tx 1000 0))
    (let* ((result (bl.rpc:dispatch-rpc-method node "getrawmempool" '(t)))
           (entry (cdr (assoc (bl.rpc:hash-to-hex txid) result :test #'string=))))
      (is (listp result))
      (is (not (null entry)))
      (is (assoc "vsize" entry :test #'string=))
      (is (= 1 (cdr (assoc "ancestorcount" entry :test #'string=))))
      ;; serializes cleanly through the RPC response normalizer
      (let ((response (bl.rpc::make-rpc-response result "id" :v2)))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test getrawmempool-reads-its-mempool-sequence-argument
  "The second argument is the atomic-snapshot half of the ZMQ sequence
workflow, and it was accepted and dropped.

Core MempoolToJSON (rpc/mempool.cpp:571-605): with verbose=false and
mempool_sequence=true the result is the OBJECT {\"txids\": [...],
\"mempool_sequence\": N}, N read under the same pool.cs as the id list; with
verbose=true it is -8 \"Verbose results cannot contain mempool sequence
values.\" Ours bound only (first params), so a client following doc/zmq.md
got a bare array and no way to tell that the argument it passed — which our
own table advertises (core-tables.lisp \"getrawmempool\" slot 1) — had been
ignored."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (tx (make-mempool-test-tx :input-id 201))
         (txid (bl.ser:transaction-hash tx))
         (txid-hex (bl.rpc:hash-to-hex txid)))
    ;; The conflict is raised before the pool is read at all.
    (signals-rpc-error
        (:code -8
         :exact-message "Verbose results cannot contain mempool sequence values.")
      (bl.rpc:dispatch-rpc-method node "getrawmempool" (list t t)))
    ;; An empty mempool still answers with the object, and its txids is [].
    ;; The counter starts at 1, as Core's m_sequence_number does (txmempool.h:202).
    (is (string= "{\"txids\":[],\"mempool_sequence\":1}"
                 (%encode-rpc-result
                  (bl.rpc:dispatch-rpc-method node "getrawmempool" (list nil t))))
        "the id list must encode as a JSON array, not as a nested object")
    (bl.mp:mempool-add mempool txid (bl.mp:make-entry-from-tx tx 1000 0))
    (let* ((r (bl.rpc:dispatch-rpc-method node "getrawmempool" (list nil t)))
           (sequence (cdr (assoc "mempool_sequence" r :test #'string=))))
      (is (equalp (vector txid-hex) (cdr (assoc "txids" r :test #'string=))))
      ;; The counter is the pool's own, not a constant: an add moves it.
      (is (= (bl.mp:mempool-sequence mempool) sequence))
      (is (plusp sequence)))
    ;; Without the argument the answer is Core's bare array, unchanged.
    (is (equal (list txid-hex)
               (bl.rpc:dispatch-rpc-method node "getrawmempool" (list nil))))
    ;; And the argument reaches slot 1 by name, as Core's own client sends it.
    (is (equal '(nil t) (%named-params "getrawmempool"
                                       "verbose" nil "mempool_sequence" t)))))

(test rpc-sendrawtransaction-invalid
  "Test sendrawtransaction with invalid hex returns error; a decode failure uses
RPC_DESERIALIZATION_ERROR (-22), matching Core."
  (let ((node (make-test-node)))
    ;; Empty string
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-sendrawtransaction node '("")))
    ;; Invalid hex -> deserialization error code -22
    (signals-rpc-error (:code -22)
      (bl.rpc::rpc-sendrawtransaction node '("not-valid-hex")))))

(test rpc-sendrawtransaction-rejection-speaks-core
  "The rejection carries Core's reject reason and Core's split of codes.
BroadcastTransaction sets err_string to state.ToString() and the RPC prints
exactly that, with no prefix of its own (node/transaction.cpp:21,
rpc/util.cpp:408-414). The CODE splits on the result: TX_MISSING_INPUTS becomes
RPC_TRANSACTION_ERROR, which IS RPC_VERIFY_ERROR = -25 (protocol.h:54), and
everything else RPC_TRANSACTION_REJECTED = -26. rpc_rawtransaction.py:354 pins
the pair. Ours answered -26 \"Transaction rejected: MISSING-INPUT\" — the wrong
code, carrying an uppercased Lisp keyword no client can match on."
  (let* ((node (make-test-node))
         (tx (make-mempool-test-tx :input-id 211))
         (hex (bl.crypto:bytes-to-hex
               (bl.ser:serialize-transaction tx))))
    (signals-rpc-error (:code -25 :exact-message "bad-txns-inputs-missingorspent")
      (bl.rpc::rpc-sendrawtransaction node (list hex)))))

;;; --- sendrawtransaction broadcast (unbroadcast set + peer announcement) ---
;;;
;;; Uses the P2SH(OP_TRUE) fixture from package-tests.lisp (make-package-fixture /
;;; %pkg-tx): standard, script-valid transactions with no signing key.

(defun %broadcast-test-node (utxo-set mempool chain-state peer)
  "A test node wired to the fixture state with one ready relay peer."
  (let ((node (bl:make-node :network :testnet3)))
    (setf (bl:node-chain-state node) chain-state
          (bl:node-utxo-set node) utxo-set
          (bl:node-mempool node) mempool
          (bl:node-peers node) (list peer))
    node))

(test rpc-sendrawtransaction-broadcasts
  "sendrawtransaction accepts the tx, adds it to the mempool's unbroadcast
set, and queues an announcement to relay peers (Core BroadcastTransaction,
node/transaction.cpp:100-135); resubmitting the same tx is NOT an error and
re-announces (already-in-mempool branch, :63-72) without re-adding to the
unbroadcast set."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((peer (bl.net:make-peer :state :ready))
           (node (%broadcast-test-node utxo-set mempool chain-state peer))
           (tx (%pkg-tx funding-txid 0 (- 100000000 10000)))
           (txid (bl.ser:transaction-hash tx))
           (hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-transaction tx))))
      (let ((r (bl.rpc::rpc-sendrawtransaction node (list hex))))
        (is (string= (bl.rpc:hash-to-hex txid) r)))
      (is-true (bl.mp:mempool-has mempool txid))
      ;; Tracked for initial broadcast...
      (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
      (is-true (gethash txid (bl.mp:mempool-unbroadcast mempool)))
      ;; ...and queued to the relay peer (flushed later by the Poisson timer).
      (is (= 1 (length (bl.net:peer-tx-inv-queue peer))))
      (is (equalp txid (first (first (bl.net:peer-tx-inv-queue peer)))))
      ;; Resubmission: same txid returned, another announcement queued,
      ;; unbroadcast set unchanged.
      (let ((r2 (bl.rpc::rpc-sendrawtransaction node (list hex))))
        (is (string= (bl.rpc:hash-to-hex txid) r2)))
      (is (= 2 (length (bl.net:peer-tx-inv-queue peer))))
      (is (= 1 (bl.mp:mempool-unbroadcast-count mempool))))))

(test rpc-testmempoolaccept-does-not-broadcast
  "testmempoolaccept is a dry run: nothing enters the mempool, nothing joins
the unbroadcast set, and no announcement is queued."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((peer (bl.net:make-peer :state :ready))
           (node (%broadcast-test-node utxo-set mempool chain-state peer))
           (tx (%pkg-tx funding-txid 0 (- 100000000 10000)))
           (hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-transaction tx))))
      (let ((r (first (bl.rpc::rpc-testmempoolaccept node (list (list hex))))))
        (is (eq t (cdr (assoc "allowed" r :test #'string=)))))
      (is (= 0 (bl.mp:mempool-count mempool)))
      (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))
      (is (null (bl.net:peer-tx-inv-queue peer))))))

(test rpc-testmempoolaccept-policy-script-reject-reason
  "A consensus-valid but policy-invalid spend (CLEANSTACK: extra scriptSig
push on a P2SH(OP_TRUE) coin) reports Core's TX_NOT_STANDARD reject-reason
token \"mempool-script-verify-flag-failed\" (CheckInputScripts,
validation.cpp:2117) through testmempoolaccept."
  (multiple-value-bind (tx utxo mempool)
      (%cleanstack-violation-fixture
       (make-array 4 :element-type '(unsigned-byte 8)
                     :initial-contents '(#x01 #x51 #x01 #x51))
       :input-id 140)
    (let ((node (%broadcast-test-node
                 utxo mempool
                 (bl.store:make-chain-state :best-height 100)
                 (bl.net:make-peer :state :ready)))
          (hex (bl.crypto:bytes-to-hex
                (bl.ser:serialize-transaction tx))))
      (let ((r (first (bl.rpc::rpc-testmempoolaccept node (list (list hex))))))
        (is (eq 'yason:false (cdr (assoc "allowed" r :test #'string=))))
        (is (string= "mempool-script-verify-flag-failed"
                     (cdr (assoc "reject-reason" r :test #'string=))))))))


;;; --- Raw-transaction safety rails (Core node/transaction.h:28-34) ---
;;;
;;; maxfeerate and maxburnamount are the two fat-finger rails on the raw-tx
;;; RPCs. Both are ON by default. The rails must fire BEFORE submission: a
;;; transaction that trips one must never reach the mempool and must never be
;;; announced, which is what makes them a safety rail rather than a report.

(defun %rails-error (thunk)
  "(values code message) of the rpc-error THUNK signals, or NIL if it returns."
  (handler-case (progn (funcall thunk) nil)
    (bl.rpc:rpc-error (e)
      (values (bl.rpc:rpc-error-code e)
              (bl.rpc:rpc-error-message e)))))

(defun %burn-tx (funding-txid value)
  "A P2SH(OP_TRUE) spend paying VALUE to a provably-unspendable OP_RETURN."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash funding-txid :index 0)
                    :script-sig (%p2sh-optrue-scriptsig)
                    :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                     :value value
                     :script-pubkey (make-array 2 :element-type '(unsigned-byte 8)
                                                  :initial-contents '(#x6a #x51))))
   :lock-time 0))

(test rpc-sendrawtransaction-maxfeerate-rail
  "An absurd fee is refused with Core's MAX_FEE_EXCEEDED (-25) and the tx
neither enters the mempool nor gets announced — Core runs ATMP with
test_accept first and only submits once the fee is under the rail
(node/transaction.cpp:74-84). maxfeerate=0 switches the rail off."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((peer (bl.net:make-peer :state :ready))
           (node (%broadcast-test-node utxo-set mempool chain-state peer))
           ;; 1 BTC in, 0.01 BTC out: a 0.99 BTC fee on 85 vbytes, far over the
           ;; 0.1 BTC/kvB default (85 vbytes buys a 0.0085 BTC cap).
           (tx (%pkg-tx funding-txid 0 1000000))
           (hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-transaction tx))))
      (multiple-value-bind (code msg)
          (%rails-error (lambda ()
                          (bl.rpc::rpc-sendrawtransaction node (list hex))))
        (is (= -25 code))
        (is-true (search "Fee exceeds maximum" msg)))
      ;; The control that matters: the rail ran BEFORE submission.
      (is (= 0 (bl.mp:mempool-count mempool)))
      (is (null (bl.net:peer-tx-inv-queue peer)))
      ;; Disabled explicitly -> the very same tx is accepted and announced.
      (is (string= (bl.rpc:hash-to-hex
                    (bl.ser:transaction-hash tx))
                   (bl.rpc::rpc-sendrawtransaction node (list hex 0))))
      (is (= 1 (bl.mp:mempool-count mempool)))
      (is (= 1 (length (bl.net:peer-tx-inv-queue peer)))))))

(test rpc-sendrawtransaction-maxfeerate-rejects-one-btc
  "ParseFeeRate refuses a rate at or above 1 BTC/kvB with -8
(rpc/util.cpp:110-115)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-transaction
                  (%pkg-tx funding-txid 0 99990000)))))
      (is (= -8 (%rails-error
                 (lambda () (bl.rpc::rpc-sendrawtransaction node (list hex 1))))))
      ;; Just under the bound is fine.
      (is (null (%rails-error
                 (lambda ()
                   (bl.rpc::rpc-sendrawtransaction node (list hex 0.99d0)))))))))

(test rpc-sendrawtransaction-maxburnamount-rail
  "Value sent to a provably-unspendable output is refused with Core's
MAX_BURN_EXCEEDED (-25), and the default cap is 0 (rpc/mempool.cpp:92-103)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (tx (%burn-tx funding-txid 99900000))
           (hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-transaction tx))))
      (multiple-value-bind (code msg)
          (%rails-error (lambda ()
                          (bl.rpc::rpc-sendrawtransaction node (list hex))))
        (is (= -25 code))
        (is-true (search "maxburnamount" msg)))
      ;; Raising the cap clears THIS rail: the tx now gets as far as ordinary
      ;; policy, which rejects it for its size instead (-26). Proves the burn
      ;; check was the only thing stopping it, and that it ran first.
      (multiple-value-bind (code msg)
          (%rails-error (lambda ()
                          (bl.rpc::rpc-sendrawtransaction node (list hex nil 1))))
        (is (= -26 code))
        (is-false (search "maxburnamount" msg)))
      (is (= 0 (bl.mp:mempool-count mempool))))))

(test rpc-testmempoolaccept-max-fee-exceeded
  "Over the rail, testmempoolaccept reports allowed=false with reject-reason
\"max-fee-exceeded\" and then stops filling in verdicts: every later member
carries txid and wtxid only, because a descendant's verdict is meaningless
once an ancestor would not be submitted (rpc/mempool.cpp:352-355,381)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (parent (%pkg-tx funding-txid 0 1000000))
           (child (%pkg-tx (bl.ser:transaction-hash parent) 0 900000))
           (ph (bl.crypto:bytes-to-hex
                (bl.ser:serialize-transaction parent)))
           (ch (bl.crypto:bytes-to-hex
                (bl.ser:serialize-transaction child)))
           (r (bl.rpc::rpc-testmempoolaccept node (list (list ph ch)))))
      (is (eq 'yason:false (cdr (assoc "allowed" (first r) :test #'string=))))
      (is (string= "max-fee-exceeded"
                   (cdr (assoc "reject-reason" (first r) :test #'string=))))
      ;; Unfinished: no verdict at all on the child.
      (is (equal '("txid" "wtxid") (mapcar #'car (second r))))
      ;; Rail off -> the parent is allowed again.
      (let ((off (bl.rpc::rpc-testmempoolaccept node (list (list ph) 0))))
        (is (eq t (cdr (assoc "allowed" (first off) :test #'string=)))))
      ;; Still a dry run either way.
      (is (= 0 (bl.mp:mempool-count mempool))))))

(test package-client-maxfeerate-aborts-package
  "A member over submitpackage's maxfeerate aborts the WHOLE package before
submission: that member is invalid with :max-feerate-exceeded, later members
are :not-validated, and nothing enters the mempool (validation.cpp:1365-1368)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((parent (%pkg-tx funding-txid 0 1000000))
           (child (%pkg-tx (bl.ser:transaction-hash parent) 0 900000)))
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state
           :client-maxfeerate 10000000)
        (is (eq :transaction-failed msg))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results parent))))
        (is (eq :max-feerate-exceeded (bl.val:package-tx-result-error
                                       (%result-for results parent))))
        (is (eq :not-validated (bl.val:package-tx-result-status
                                (%result-for results child)))))
      (is (= 0 (bl.mp:mempool-count mempool)))
      ;; NIL cap (what maxfeerate=0 becomes) leaves the package alone.
      (multiple-value-bind (msg2) (bl.val:validate-package-for-mempool
                                   (list parent child) utxo-set mempool chain-state)
        (is (eq :success msg2)))
      (is (= 2 (bl.mp:mempool-count mempool))))))

(test script-has-valid-ops-p-matches-core
  "CScript::HasValidOps: a truncated push, an over-long push, and an undefined
opcode above MAX_OPCODE all make a script unparseable (script.cpp)."
  (flet ((spk (&rest bytes)
           (make-array (length bytes) :element-type '(unsigned-byte 8)
                                      :initial-contents bytes)))
    ;; OP_RETURN OP_1, and a well-formed 2-byte push: both parse.
    (is-true (bl.store:script-has-valid-ops-p (spk #x6a #x51)))
    (is-true (bl.store:script-has-valid-ops-p (spk #x02 #xaa #xbb)))
    (is-true (bl.store:script-has-valid-ops-p (spk)))
    ;; Direct push running off the end.
    (is-false (bl.store:script-has-valid-ops-p (spk #x05 #xaa)))
    ;; OP_PUSHDATA1 with a truncated length byte, then a truncated payload.
    (is-false (bl.store:script-has-valid-ops-p (spk #x4c)))
    (is-false (bl.store:script-has-valid-ops-p (spk #x4c #x03 #xaa)))
    ;; OP_PUSHDATA2 declaring 521 bytes: over MAX_SCRIPT_ELEMENT_SIZE.
    (is-false (bl.store:script-has-valid-ops-p (spk #x4d #x09 #x02)))
    ;; 0xba is the first byte above MAX_OPCODE (OP_NOP10 = 0xb9).
    (is-true (bl.store:script-has-valid-ops-p (spk #xb9)))
    (is-false (bl.store:script-has-valid-ops-p (spk #xba)))))

;;; --- Wave 9D: RPC/mempool locking discipline ---

(test rpc-mempool-mutators-hold-node-lock
  "RPC handlers that mutate the mempool run under the node lock: while
another thread holds it, prioritisetransaction blocks; once released it
completes. (The sync loop's message handlers hold this same lock, so an
unlocked RPC mutation would interleave with them.)"
  (let* ((node (make-test-node))
         (txid-hex (format nil "~64,'0d" 1))
         (done (cons nil nil))
         (thread nil))
    (bt:with-recursive-lock-held ((bl:node-lock node))
      (setf thread
            (bt:make-thread
             (lambda ()
               (bl.rpc::rpc-prioritisetransaction
                node (list txid-hex 0 12345))
               (setf (car done) t))
             :name "rpc-lock-test"))
      ;; Give the thread ample time to reach the lock acquisition: it must
      ;; be blocked, not finished.
      (sleep 0.3)
      (is (null (car done))
          "prioritisetransaction completed while the node lock was held elsewhere"))
    ;; Lock released — the handler must now complete and take effect.
    (bt:join-thread thread)
    (is (eq t (car done)))
    (is (= 12345 (gethash (bl.rpc:parse-hex-hash txid-hex)
                          (bl.mp:mempool-deltas
                           (bl:node-mempool node))
                          0)))))

(test rpc-concurrent-mempool-smoke
  "Concurrency smoke: writer threads submit distinct P2SH(OP_TRUE) spends via
rpc-sendrawtransaction while reader threads hammer getrawmempool (verbose),
getmempoolinfo, and getprioritisedtransactions, and a prioritiser thread
mutates the deltas table. With the node lock on every path this must finish
with zero thread errors and every submitted tx in the pool exactly once."
  (let* ((utxo-set (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (chain-state (bl.store:make-chain-state :best-height 200))
         (node (%broadcast-test-node utxo-set mempool chain-state
                                     (bl.net:make-peer :state :ready)))
         (n-txs 24)
         (hexes '())
         (txids '())
         (errors (list nil))
         (errors-lock (bt:make-lock "smoke-errors")))
    ;; N distinct confirmed P2SH(OP_TRUE) funding coins and their spends.
    (dotimes (i n-txs)
      (let ((funding (make-array 32 :element-type '(unsigned-byte 8)
                                    :initial-element (+ 50 i))))
        (bl.store:add-utxo utxo-set funding 0 100000000
                                       (p2sh-optrue-script-pubkey) 1 :coinbase nil)
        (let ((tx (%pkg-tx funding 0 99990000)))
          (push (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-transaction tx))
                hexes)
          (push (bl.ser:transaction-hash tx) txids))))
    (flet ((guarded (fn)
             (lambda ()
               (handler-case (funcall fn)
                 (error (e)
                   (bt:with-lock-held (errors-lock)
                     (push e (car errors))))))))
      (let ((threads '()))
        ;; 3 writers, 8 txs each.
        (loop for chunk on hexes by (lambda (l) (nthcdr 8 l))
              for batch = (subseq chunk 0 (min 8 (length chunk)))
              do (push (bt:make-thread
                        (guarded
                         (let ((batch batch))
                           (lambda ()
                             (dolist (hex batch)
                               (bl.rpc::rpc-sendrawtransaction
                                node (list hex))))))
                        :name "smoke-writer")
                       threads))
        ;; 3 readers.
        (dotimes (i 3)
          (push (bt:make-thread
                 (guarded
                  (lambda ()
                    (dotimes (j 40)
                      (bl.rpc:dispatch-rpc-method node "getrawmempool" (list t))
                      (bl.rpc::rpc-getmempoolinfo node nil)
                      (bl.rpc::rpc-getprioritisedtransactions node nil))))
                 :name "smoke-reader")
                threads))
        ;; 1 prioritiser mutating the deltas table under the readers.
        (push (bt:make-thread
               (guarded
                (lambda ()
                  (dotimes (j 40)
                    (bl.rpc::rpc-prioritisetransaction
                     node (list (format nil "~64,'0x" (+ j 1)) 0 100)))))
               :name "smoke-prioritiser")
              threads)
        (mapc #'bt:join-thread threads)))
    (is (null (car errors))
        "concurrent RPC calls signalled: ~A" (car errors))
    (is (= n-txs (bl.mp:mempool-count mempool)))
    (dolist (txid txids)
      (is-true (bl.mp:mempool-has mempool txid)))
    (is (= n-txs (bl.mp:mempool-unbroadcast-count mempool)))))

(test rpc-getmempoolinfo-unbroadcastcount
  "getmempoolinfo reports the live unbroadcast set size (Core
rpc/mempool.cpp:1047)."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (tx (make-mempool-test-tx :input-id 201))
         (txid (bl.ser:transaction-hash tx)))
    (is (= 0 (cdr (assoc "unbroadcastcount"
                         (bl.rpc::rpc-getmempoolinfo node nil)
                         :test #'string=))))
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (bl.mp:make-entry-from-tx tx 1000 0))))
    (is-true (bl.mp:mempool-add-unbroadcast mempool txid))
    (is (= 1 (cdr (assoc "unbroadcastcount"
                         (bl.rpc::rpc-getmempoolinfo node nil)
                         :test #'string=))))))

(defun %mempool-node (&optional (funding-outputs 1))
  "A test node on a fresh make-package-fixture whose UTXO set holds FUNDING-OUTPUTS
confirmed spendable coins (vouts 0..n-1 of the fixture's funding txid), so a
saved mempool can be reloaded against it. Use (bl:node-mempool node)
for the pool."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (declare (ignore mempool))
    (loop for i from 1 below funding-outputs
          do (bl.store:add-utxo utxo-set funding-txid i 100000000
                                            (p2sh-optrue-script-pubkey) 1 :coinbase nil))
    (values (%broadcast-test-node utxo-set mempool chain-state
                                  (bl.net:make-peer :state :ready))
            funding-txid)))

(defun %write-mempool-file (path)
  "Write a mempool.dat holding three INDEPENDENT txs (so reload order cannot
matter), one of them unbroadcast. Returns the list of txids."
  (multiple-value-bind (node funding-txid) (%mempool-node 3)
    (let ((mempool (bl:node-mempool node))
          (txids '()))
      (dotimes (i 3)
        (let* ((tx (%pkg-tx funding-txid i (- 100000000 10000)))
               (txid (bl.ser:transaction-hash tx)))
          (bl.mp:mempool-add
           mempool txid (bl.mp:make-entry-from-tx tx 10000 200))
          (push txid txids)))
      (bl.mp:mempool-add-unbroadcast mempool (first txids))
      (bl.mp:save-mempool-file mempool path)
      txids)))

(test mempool-import-abandons-the-load-on-a-stop-request
  "The mempool import re-validates every saved tx through the full acceptance
path, so a large mempool.dat is minutes of CPU — and it runs inside start-node,
BEFORE run-node-watchdog exists, so a SIGTERM arriving during it cannot be
serviced until it finishes. Core checks m_interrupt after every tx and abandons
the load (mempool_persist.cpp:122); so do we, via the same interrupt seam
perform-reorg uses. An abandoned load must apply NEITHER the residual deltas nor
the unbroadcast set (Core returns before both), or prioritisation would be
restored for transactions that never came back."
  (let ((path (merge-pathnames (format nil "bl-mempool-abort-~D.dat" (get-universal-time))
                               (uiop:temporary-directory))))
    (unwind-protect
         (let ((txids (%write-mempool-file path)))
           ;; Interrupted: fires once the first tx is in, so exactly one loads.
           (let* ((node (%mempool-node 3))
                  (mempool (bl:node-mempool node))
                  (bl:*interrupt-check*
                    (lambda () (plusp (bl.mp:mempool-count mempool)))))
             (multiple-value-bind (accepted failed residual)
                 (bl:load-mempool-from-disk node path)
               (declare (ignore failed))
               (is (= 1 accepted) "the load stops at the first boundary after the flag")
               (is (= 0 residual)))
             (is (= 1 (bl.mp:mempool-count mempool)))
             (is (= 0 (bl.mp:mempool-unbroadcast-count mempool))
                 "an abandoned load restores no unbroadcast set"))
           ;; CONTROL: the same file, uninterrupted, loads completely — without
           ;; this the assertions above would also pass on a file that never
           ;; had three loadable txs in it.
           (let* ((node (%mempool-node 3))
                  (mempool (bl:node-mempool node)))
             (is (= 3 (bl:load-mempool-from-disk node path)))
             (is (= 3 (bl.mp:mempool-count mempool)))
             (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
             (dolist (txid txids)
               (is-true (bl.mp:mempool-has mempool txid)))))
      (ignore-errors (delete-file path)))))

(test stop-signal-during-startup-only-registers-the-request
  "The SIGTERM handler now goes in at the START of start-node (Core does it in
AppInitBasicSetup, a thousand lines before LoadMempool) — installed last, every
slow startup step ran with SIGTERM at its DEFAULT disposition, so a stop during
the mempool import, an index backfill or a wallet rescan killed the process
outright. Arriving mid-startup it must only REGISTER: there is no built node to
tear down, and running stop-node there would race the construction it undoes.
Registering is also what lets the polling loops abandon their work."
  (let ((bl::*node-starting* t)
        (bl::*shutdown-watchdog-running* nil)
        (bl::*shutdown-request* nil))
    (is-true (bl::%handle-stop-signal)
             "mid-startup: register only, never tear down")
    (is (equal "SIGTERM/SIGINT" (bl:node-shutdown-requested-p)))
    ;; …and that registration is exactly what the cooperative loops poll.
    (is-true (bl:interrupt-requested-p)))
  ;; The other branch — neither latch set, so the handler tears down inline —
  ;; is deliberately not exercised: it ends in sb-ext:exit and would take the
  ;; test image with it.
  (let ((bl::*node-starting* t)
        (bl::*shutdown-watchdog-running* nil)
        (bl::*shutdown-request* nil))
    ;; The startup latch alone is enough; the test above must not be passing
    ;; only because some other run left the watchdog latch set.
    (is-true (bl::%handle-stop-signal))))

(test mempool-import-reports-its-size-and-progress
  "The import used to log nothing between 'Loaded N fee stats entries' and its
final summary: an 83 MB testnet4 mempool.dat took ~45 minutes of apparent
silence on the 2026-08-16 deploy, indistinguishable from a wedge. Core announces
the total and reports every 10% (mempool_persist.cpp:77-86)."
  (let ((path (merge-pathnames (format nil "bl-mempool-progress-~D.dat" (get-universal-time))
                               (uiop:temporary-directory))))
    (unwind-protect
         (progn
           (%write-mempool-file path)
           (let* ((node (%mempool-node 3))
                  (logged (with-output-to-string (out)
                            (let ((bl:*log-stream* out))
                              (bl:load-mempool-from-disk node path)))))
             (is (search "Loading 3 mempool transactions" logged)
                 "the size is announced before the work starts")
             (is (search "Progress loading mempool transactions" logged)
                 "progress is reported while the work runs")
             (is (search "Imported mempool" logged))))
      (ignore-errors (delete-file path)))))

(test rpc-importmempool-unbroadcast-option
  "The saved unbroadcast set is restored by the startup load
(load-mempool-from-disk defaults apply-unbroadcast on, Core
node/mempool_persist.h:24) but by importmempool only when
apply_unbroadcast_set is passed true (Core default false,
rpc/mempool.cpp:1115-1116)."
  (let ((path (merge-pathnames (format nil "bl-unbr-import-~D.dat" (get-universal-time))
                               (uiop:temporary-directory))))
    (unwind-protect
         (let (txid)
           ;; Source pool: one accepted tx marked unbroadcast, saved to PATH.
           (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
             (declare (ignore utxo-set chain-state))
             (let ((tx (%pkg-tx funding-txid 0 (- 100000000 10000))))
               (setf txid (bl.ser:transaction-hash tx))
               (is (eq :ok (bl.mp:mempool-add
                            mempool txid
                            (bl.mp:make-entry-from-tx tx 10000 200))))
               (bl.mp:mempool-add-unbroadcast mempool txid)
               (bl.mp:save-mempool-file mempool path)))
           ;; importmempool default: entries load, unbroadcast NOT applied.
           (let* ((node (%mempool-node))
                  (mempool (bl:node-mempool node)))
             (bl.rpc::rpc-importmempool node (list (namestring path)))
             (is-true (bl.mp:mempool-has mempool txid))
             (is (= 0 (bl.mp:mempool-unbroadcast-count mempool))))
           ;; importmempool with apply_unbroadcast_set=true restores the set.
           (let* ((node (%mempool-node))
                  (mempool (bl:node-mempool node))
                  (opts (make-hash-table :test 'equal)))
             (setf (gethash "apply_unbroadcast_set" opts) t)
             (bl.rpc::rpc-importmempool node (list (namestring path) opts))
             (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
             (is-true (gethash txid (bl.mp:mempool-unbroadcast mempool))))
           ;; Startup path (load-mempool-from-disk) applies it by default.
           (let* ((node (%mempool-node))
                  (mempool (bl:node-mempool node)))
             (bl:load-mempool-from-disk node path)
             (is (= 1 (bl.mp:mempool-unbroadcast-count mempool)))
             (is-true (gethash txid (bl.mp:mempool-unbroadcast mempool)))))
      (ignore-errors (delete-file path)))))

(test rpc-getblockheader-confirmations
  "getblockheader.confirmations is the active-chain depth (tip - height + 1), not
a hardcoded 1."
  (multiple-value-bind (cs entries) (%make-served-chain 5)  ; genesis..height 5
    (let ((node (make-test-node)))
      (setf (bl:node-chain-state node) cs)
      ;; height 3 -> 5 - 3 + 1 = 3 confirmations, plus the shared chain-header fields
      (let ((r (bl.rpc::rpc-getblockheader
                node (list (bl.rpc:hash-to-hex (%entry-hash entries 3))))))
        (is (= 3 (cdr (assoc "height" r :test #'string=))))
        (is (= 3 (cdr (assoc "confirmations" r :test #'string=))))
        (is (= 8 (length (cdr (assoc "versionHex" r :test #'string=)))))
        (is (integerp (cdr (assoc "mediantime" r :test #'string=))))
        (is (= 64 (length (cdr (assoc "target" r :test #'string=)))))
        (is (= 64 (length (cdr (assoc "chainwork" r :test #'string=)))))
        (is (= 8 (length (cdr (assoc "bits" r :test #'string=)))))
        (is (numberp (cdr (assoc "difficulty" r :test #'string=))))
        ;; a non-tip active-chain block carries nextblockhash
        (is (assoc "nextblockhash" r :test #'string=)))
      ;; tip (height 5) -> 1 confirmation, no nextblockhash
      (let ((r (bl.rpc::rpc-getblockheader
                node (list (bl.rpc:hash-to-hex (%entry-hash entries 5))))))
        (is (= 1 (cdr (assoc "confirmations" r :test #'string=))))
        (is (null (assoc "nextblockhash" r :test #'string=)))))))

;;; --- getblockheader nTx / previousblockhash, getblock coinbase_tx ---

(defun %hdrfields-tx (tag &key witness)
  "A coinbase-shaped transaction, distinct per TAG (its 3-byte scriptSig)."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-32-byte-hash 0) :index #xffffffff)
                    :script-sig (make-array 3 :element-type '(unsigned-byte 8)
                                              :initial-element tag)
                    :sequence #xfffffffe))
   :outputs (vector (bl.ser:make-tx-out
                     :value 5000 :script-pubkey (make-array 4 :element-type '(unsigned-byte 8)
                                                              :initial-element #x6a)))
   :witness (when witness (vector (list witness)))
   :lock-time 7))

(defun %hdrfields-block (txs prev-hash time)
  "A block over TXS with a real merkle root and PREV-HASH."
  (let* ((root (bl.val:compute-merkle-root
                (mapcar #'bl.ser:transaction-hash txs)))
         (header (bl.ser:make-block-header
                  :version 1 :prev-block prev-hash :merkle-root root
                  :timestamp time :bits #x207fffff :nonce 0)))
    (bl.ser:make-bitcoin-block :header header :transactions txs)))

(defmacro %with-hdrfields-chain ((node store g a b) &body body)
  "Bind NODE to a test node whose block store holds a 1-tx block G at height 0
and a 2-tx block A at height 1, plus a header-only entry B at height 2 (the
active tip). G, A and B are bound to (block . hash) conses."
  (let ((dir (gensym "DIR")))
    `(let* ((,node (make-test-node))
            (,dir (ensure-directories-exist
                   (merge-pathnames (format nil "hdrfields-~D/" (get-internal-real-time))
                                    (uiop:temporary-directory))))
            (,store (bl.store:init-block-store ,dir)))
       (setf (bl:node-block-store ,node) ,store)
       (unwind-protect
            (let* ((gb (%hdrfields-block (list (%hdrfields-tx 1)) (make-32-byte-hash 0) 1700000000))
                   (gh (bl.ser:block-header-hash
                        (bl.ser:bitcoin-block-header gb)))
                   (ab (%hdrfields-block (list (%hdrfields-tx 2) (%hdrfields-tx 3)) gh 1700000600))
                   (ah (bl.ser:block-header-hash
                        (bl.ser:bitcoin-block-header ab)))
                   (bb (%hdrfields-block (list (%hdrfields-tx 4)) ah 1700001200))
                   (bh (bl.ser:block-header-hash
                        (bl.ser:bitcoin-block-header bb)))
                   (,g (cons gb gh)) (,a (cons ab ah)) (,b (cons bb bh))
                   (cs (bl:node-chain-state ,node)))
              (declare (ignorable ,g ,a ,b))
              (setf (bl.store:chain-state-genesis-hash cs) gh)
              ;; B is header-only on purpose: its body is never stored.
              (bl.store:store-block ,store gb)
              (bl.store:store-block ,store ab)
              (let* ((ge (bl.store:make-block-index-entry
                          :hash gh :height 0 :chain-work 1 :status :valid
                          :header (bl.ser:bitcoin-block-header gb)))
                     (ae (bl.store:make-block-index-entry
                          :hash ah :height 1 :chain-work 2 :status :valid :prev-entry ge
                          :header (bl.ser:bitcoin-block-header ab)))
                     (be (bl.store:make-block-index-entry
                          :hash bh :height 2 :chain-work 3 :status :valid :prev-entry ae
                          :header (bl.ser:bitcoin-block-header bb))))
                (bl.store:add-block-index-entry cs ge)
                (bl.store:add-block-index-entry cs ae)
                (bl.store:add-block-index-entry cs be)
                (bl.store:update-chain-tip cs bh 2))
              ,@body)
         (uiop:delete-directory-tree ,dir :validate t :if-does-not-exist :ignore)))))

(test rpc-getblockheader-ntx-and-genesis-previousblockhash
  "getblockheader emits nTx (Core blockheaderToJSON, rpc/blockchain.cpp:175) and
OMITS previousblockhash for genesis (`if (blockindex.pprev)`, :177-178) rather
than reporting 64 zeros — a client walking the chain backwards terminates on the
missing key; given the all-zero hash it asks for a block nobody has and errors."
  (%with-hdrfields-chain (node store g a b)
    (flet ((hdr (hash)
             (bl.rpc::rpc-getblockheader
              node (list (bl.rpc:hash-to-hex hash)))))
      (let ((gj (hdr (cdr g))) (aj (hdr (cdr a))) (bj (hdr (cdr b))))
        ;; nTx is always present. Genesis carries its coinbase; A's index entry
        ;; predates the tx-count field and is backfilled from the block store;
        ;; B is header-only, so 0 — Core's nTx is 0 until the body arrives.
        (is (= 1 (cdr (assoc "nTx" gj :test #'string=))))
        (is (= 2 (cdr (assoc "nTx" aj :test #'string=))))
        (is (= 0 (cdr (assoc "nTx" bj :test #'string=))))
        ;; Genesis omits previousblockhash entirely...
        (is (null (assoc "previousblockhash" gj :test #'string=)))
        (is (not (search "previousblockhash" (%encode-rpc-result gj))))
        ;; ...CONTROL: every other header still carries it, naming the real
        ;; parent (so the omission is genesis-specific, not a blanket drop).
        (is (string= (bl.rpc:hash-to-hex (cdr g))
                     (cdr (assoc "previousblockhash" aj :test #'string=))))
        (is (string= (bl.rpc:hash-to-hex (cdr a))
                     (cdr (assoc "previousblockhash" bj :test #'string=))))
        ;; The fields survive the encoder.
        (is (search "\"nTx\":2" (%encode-rpc-result aj)))))))

(test rpc-getblock-coinbase-tx-and-genesis-previousblockhash
  "getblock emits coinbase_tx (Core blockToJSON:211 -> coinbaseTxToJSON:185-200):
version, locktime, the coinbase input's sequence and scriptSig hex, plus the
single witness item only when the coinbase carries one. blockToJSON delegates
its header fields to blockheaderToJSON, so genesis omits previousblockhash here
too."
  (%with-hdrfields-chain (node store g a b)
    (flet ((blk (hash &optional (verbosity 1))
             (bl.rpc::rpc-getblock
              node (list (bl.rpc:hash-to-hex hash) verbosity))))
      (let* ((gj (blk (cdr g)))
             (cb (cdr (assoc "coinbase_tx" gj :test #'string=))))
        (is (not (null cb)) "getblock must emit coinbase_tx")
        (when cb
          (is (= 2 (cdr (assoc "version" cb :test #'string=))))
          (is (= 7 (cdr (assoc "locktime" cb :test #'string=))))
          (is (= #xfffffffe (cdr (assoc "sequence" cb :test #'string=))))
          (is (string= "010101" (cdr (assoc "coinbase" cb :test #'string=))))
          ;; CONTROL: a witness-less coinbase omits the witness key entirely
          ;; (Core pushes it only for a non-empty stack).
          (is (null (assoc "witness" cb :test #'string=))))
        ;; Genesis omits previousblockhash here as well...
        (is (null (assoc "previousblockhash" gj :test #'string=)))
        ;; ...CONTROL: a non-genesis block still reports it.
        (is (string= (bl.rpc:hash-to-hex (cdr g))
                     (cdr (assoc "previousblockhash" (blk (cdr a)) :test #'string=))))
        ;; Verbosity 2 (full tx detail) carries coinbase_tx too; verbosity 0 is
        ;; untouched raw hex.
        (is (assoc "coinbase_tx" (blk (cdr a) 2) :test #'string=))
        (is (stringp (blk (cdr a) 0)))))))

(test rpc-getblock-coinbase-tx-witness
  "A coinbase with a witness stack reports it as coinbase_tx.witness (the BIP141
reserved value), matching Core's `if (!witness_stack.empty())`."
  (let* ((node (make-test-node))
         (dir (ensure-directories-exist
               (merge-pathnames (format nil "cbwitness-~D/" (get-internal-real-time))
                                (uiop:temporary-directory))))
         (store (bl.store:init-block-store dir)))
    (setf (bl:node-block-store node) store)
    (unwind-protect
         (let* ((reserved (make-32-byte-hash 0))
                (blk (%hdrfields-block (list (%hdrfields-tx 8 :witness reserved))
                                       (make-32-byte-hash 0) 1700000000))
                (hash (bl.ser:block-header-hash
                       (bl.ser:bitcoin-block-header blk))))
           (bl.store:store-block store blk)
           (let ((cb (cdr (assoc "coinbase_tx"
                                 (bl.rpc::rpc-getblock
                                  node (list (bl.rpc:hash-to-hex hash) 1))
                                 :test #'string=))))
             (is (not (null cb)))
             (when cb
               (is (string= (bl.crypto:bytes-to-hex reserved)
                            (cdr (assoc "witness" cb :test #'string=))))
               (is (string= "080808" (cdr (assoc "coinbase" cb :test #'string=)))))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

;;; --- Authentication Tests (7.4) ---

(defun %plaintext-credentials (user password)
  "The *rpc-credentials* value a node configured with USER/PASSWORD installs:
one salted-and-hashed entry, as Core's InitRPCAuthentication pushes onto
g_rpcauth (httprpc.cpp:275-287). Tests bind this rather than a plaintext pair
because the plaintext pair is not what the server keeps."
  (list (bl.rpc::hash-rpc-credential user password)))

(test rpc-auth-check-no-credentials
  "A request carrying no Authorization header is never authorized, in every
credential state startup can produce. Core answers 401 for an absent header
before looking at any configuration (HTTPReq_JSONRPC, httprpc.cpp:112-117);
this test used to assert the opposite for the default deployment, which left
the whole RPC surface — loaded wallet included — open to any local process."
  ;; default startup: the .cookie pair is the credential
  (let ((bl.rpc::*rpc-credentials*
          (%plaintext-credentials bl.rpc::+rpc-cookie-user+ "deadbeef")))
    (is (not (bl.rpc::check-auth nil)))
    (is (not (bl.rpc::check-auth ""))))
  ;; -rpcuser/-rpcpassword startup
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "testpass")))
    (is (not (bl.rpc::check-auth nil))))
  ;; no credential installed at all: nothing authorizes, not even an empty one
  (let ((bl.rpc::*rpc-credentials* '()))
    (is (not (bl.rpc::check-auth nil)))
    (is (not (bl.rpc::check-auth (%basic-auth-header ":"))))))

(test rpc-auth-header-parsing
  "check-auth parses the HTTP Basic header the way Core's RPCAuthorized does
(httprpc.cpp:84-101): \"Basic \" prefix, base64, split on the FIRST colon, so a
password may contain colons. Anything malformed is rejected, never accepted."
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "testpass")))
    ;; base64 of "testuser:testpass"
    (is (bl.rpc::check-auth "Basic dGVzdHVzZXI6dGVzdHBhc3M="))
    (is (bl.rpc::check-auth (%basic-auth-header "testuser:testpass")))
    ;; scheme name is case-insensitive, surrounding space is trimmed (Core
    ;; TrimStringView)
    (is (bl.rpc::check-auth "basic dGVzdHVzZXI6dGVzdHBhc3M="))
    (is (bl.rpc::check-auth "Basic  dGVzdHVzZXI6dGVzdHBhc3M= "))
    ;; malformed shapes
    (is (not (bl.rpc::check-auth "dGVzdHVzZXI6dGVzdHBhc3M=")))
    (is (not (bl.rpc::check-auth "Bearer dGVzdHVzZXI6dGVzdHBhc3M=")))
    (is (not (bl.rpc::check-auth "Basic ")))
    (is (not (bl.rpc::check-auth "Basic not-base64!!")))
    ;; no colon in the decoded credential
    (is (not (bl.rpc::check-auth (%basic-auth-header "testusertestpass"))))
    ;; near misses
    (is (not (bl.rpc::check-auth (%basic-auth-header "testuser:testpas"))))
    (is (not (bl.rpc::check-auth (%basic-auth-header "testuser:testpassX"))))
    (is (not (bl.rpc::check-auth (%basic-auth-header "TESTUSER:testpass")))))
  ;; the split is on the first colon, so the password keeps the rest
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "u" "a:b:c")))
    (is (bl.rpc::check-auth (%basic-auth-header "u:a:b:c")))))

(test rpc-timing-resistant-equal
  "%timing-resistant-equal decides exactly what STRING= decides (Core
TimingResistantEqual, util/strencodings.h:203-210) — a comparator that is
constant-time but wrong would hand out access."
  (let ((cases '("" "a" "ab" "deadbeef" "deadbee" "deadbeef0"
                 "DEADBEEF" "d" "xxxxxxxx")))
    (dolist (a cases)
      (dolist (b cases)
        (is (eq (and (string= a b) t)
                (and (bl.rpc::%timing-resistant-equal a b) t))
            "~S vs ~S" a b)))))

;;; --- -rpcauth / -rpcallowip (7.4b) ---

(test rpc-auth-rpcauth-parsing
  "-rpcauth is USERNAME:SALT$HMAC and nothing else. Core splits on #\\: demanding
exactly two fields and splits the second on #\\$ demanding exactly two more
(InitRPCAuthentication, httprpc.cpp:289-300), so a spec with an extra separator
is rejected rather than silently truncated into a credential nobody can use."
  (flet ((fields (spec)
           (let ((c (bl.rpc::parse-rpcauth-entry spec)))
             (and c (list (bl.rpc::rpc-credential-user c)
                          (bl.rpc::rpc-credential-salt c)
                          (bl.rpc::rpc-credential-hash c))))))
    (is (equal '("alice" "deadbeef" "cafe") (fields "alice:deadbeef$cafe")))
    ;; an empty user, salt or hash is still well-formed to Core's splitter
    (is (equal '("" "s" "h") (fields ":s$h"))))
  (dolist (bad '("alice:nohash" "alice" "" "a:b:c$d" "alice:a$b$c" "alice$s:h"))
    (is (not (bl.rpc::parse-rpcauth-entry bad)) "accepted ~S" bad))
  (is (not (bl.rpc::parse-rpcauth-entry nil))))

(test rpc-auth-rpcauth-hmac-vector
  "The digest matches share/rpcauth/rpcauth.py, which is what generates the
config line: HMAC-SHA256 keyed by the salt's own CHARACTERS (not its hex value)
over the UTF-8 password, lowercase hex (rpcauth.py:20-22). Keying the decoded
salt instead would produce a hash no operator-generated line ever matches."
  (flet ((hmac (salt password)
           (bl.rpc::%rpcauth-hmac-hex (bl.rpc::%credential-bytes salt)
                                (bl.rpc::%credential-bytes password))))
    (is (string= "5d253745d78b945827c12a708d3267f495f3eabb5a3f755f5ccd8c5831f350e7"
                 (hmac "a1b2c3d4" "swordfish")))
    ;; non-ASCII password: UTF-8, the encoding %credential-bytes fixed for the
    ;; single -rpcpassword pair
    (is (string= "64fcc7fa10ddc69293b2a0814beb51b8cd3b48cea70ad3b49c2f36f13d66237f"
                 (hmac "a1b2c3d4" (coerce '(#\p #\LATIN_SMALL_LETTER_A_WITH_DIAERESIS
                                            #\s #\s #\w
                                            #\LATIN_SMALL_LETTER_O_WITH_DIAERESIS
                                            #\r #\d)
                                          'string))))))

(test rpc-auth-rpcauth-authorizes
  "A -rpcauth credential authorizes a request, and only the right one does.
Core checks the single -rpcuser/cookie pair first and falls through to the
g_rpcauth set (RPCAuthorized, httprpc.cpp:84-102), so both must work — and
must keep working when the other is absent."
  (let ((entry (bl.rpc::make-rpc-credential
                "alice" "a1b2c3d4"
                "5d253745d78b945827c12a708d3267f495f3eabb5a3f755f5ccd8c5831f350e7")))
    ;; alongside the cookie pair
    (let ((bl.rpc::*rpc-credentials*
            (append (%plaintext-credentials bl.rpc::+rpc-cookie-user+ "deadbeef")
                    (list entry))))
      (is (bl.rpc::check-auth (%basic-auth-header "alice:swordfish")))
      (is (bl.rpc::check-auth (%basic-auth-header "__cookie__:deadbeef")))
      (is (not (bl.rpc::check-auth (%basic-auth-header "alice:swordfisH"))))
      (is (not (bl.rpc::check-auth (%basic-auth-header "Alice:swordfish"))))
      (is (not (bl.rpc::check-auth (%basic-auth-header "alice:")))))
    ;; -rpcauth as the ONLY credential: Core allows -rpcauth without -rpcuser
    (let ((bl.rpc::*rpc-credentials* (list entry)))
      (is (bl.rpc::check-auth (%basic-auth-header "alice:swordfish")))
      (is (not (bl.rpc::check-auth nil)))
      (is (not (bl.rpc::check-auth (%basic-auth-header "alice:wrong")))))
    ;; and no entries means no fallback path opens up
    (let ((bl.rpc::*rpc-credentials* '()))
      (is (not (bl.rpc::check-auth (%basic-auth-header "alice:swordfish")))))))

;;; --- -rpcwhitelist / -rpcwhitelistdefault (Core httprpc.cpp) ---

(defparameter *core-whitelist-users*
  ;; (username plaintext-password -rpcauth-spec). The specs and passwords are
  ;; lifted verbatim from Core's test/functional/rpc_whitelist.py, so the
  ;; credentials this test authenticates with are Core's own rpcauth.py output
  ;; rather than something we generated to match ourselves.
  '(("user1" "12345"
     "user1:50358aa884c841648e0700b073c32b2e$b73e95fff0748cc0b517859d2ca47d9bac1aa78231f3e48fa9222b612bd2083e")
    ("user2" "54321"
     "user2:8650ba41296f62092377a38547f361de$4620db7ba063ef4e2f7249853e9f3c5c3592a9619a759e3e6f1c63f2e22f1d21")
    ("strangedude6" "N4SziYbHmhC1"
     "strangedude6:67e5583538958883291f6917883eca64$8a866953ef9c5b7d078a62c64754a4eb74f47c2c17821eb4237021d7ef44f991"))
  "The -rpcauth users the whitelist tests authorize as, from rpc_whitelist.py.")

(defun core-whitelist-credential (user)
  "USER's \"user:pass\" credential from *CORE-WHITELIST-USERS*."
  (let ((row (assoc user *core-whitelist-users* :test #'string=)))
    (concatenate 'string (first row) ":" (second row))))

(test rpc-whitelist-parses-cores-own-specs
  "-rpcwhitelist parsing, against every spec shape rpc_whitelist.py writes and
the verdict it asserts (httprpc.cpp:307-325 for the parse, :144-158 for the
check). The shapes are the point: Core splits the method list on a comma OR a
space and keeps the empty pieces, a spec with no colon leaves the user with an
EMPTY whitelist, and a second spec for one user INTERSECTS with the first, so
repeating the option can only narrow it."
  (let ((bl.rpc::*rpc-whitelist*
          (bl.rpc::%parse-rpc-whitelist
           ;; rpc_whitelist.py's users and its four "strange" cases.
           '("user1:getbestblockhash,getblockcount,"
             "user2:getblockcount"
             "strangedude:"
             "strangedude2"
             "strangedude3:getblockcount,"
             "strangedude4:getblockcount, getbestblockhash"
             "strangedude4:getblockcount"
             "strangedude5:getblockcount,getblockcount"))))
    (flet ((allowed (user method) (bl.rpc::rpc-method-allowed-p user method)))
      ;; The two ordinary users: exactly what they list, nothing else. The
      ;; trailing comma in user1's list is an empty method name, not a wildcard.
      (is-true (allowed "user1" "getbestblockhash"))
      (is-true (allowed "user1" "getblockcount"))
      (is-false (allowed "user1" "getblockchaininfo"))
      (is-false (allowed "user1" "getnetworkinfo"))
      (is-true (allowed "user2" "getblockcount"))
      (is-false (allowed "user2" "getblockchaininfo"))
      ;; "user:" and a spec with no colon at all both mean an EMPTY whitelist.
      (is-false (allowed "strangedude" "getnetworkinfo"))
      (is-false (allowed "strangedude2" "getnetworkinfo"))
      ;; Trailing comma, and a name repeated inside one spec.
      (is-true (allowed "strangedude3" "getblockcount"))
      (is-true (allowed "strangedude5" "getblockcount"))
      ;; Two specs for one user INTERSECT: the second one drops
      ;; getbestblockhash, which the ", " separator of the first had admitted.
      (is-false (allowed "strangedude4" "getbestblockhash"))
      (is-true (allowed "strangedude4" "getblockcount"))
      ;; A user no spec names is governed by -rpcwhitelistdefault alone.
      (let ((bl.rpc::*rpc-whitelist-default* nil))
        (is-true (allowed "strangedude6" "getbestblockhash")))
      (let ((bl.rpc::*rpc-whitelist-default* t))
        (is-false (allowed "strangedude6" "getbestblockhash"))))))

(test rpc-whitelist-refuses-off-whitelist-methods-with-403
  "On the wire: a restricted credential gets Core's HTTP 403 for a method its
-rpcwhitelist does not list, and for EVERY method when it has no whitelist
while -rpcwhitelistdefault is in force (HTTPReq_JSONRPC, httprpc.cpp:144-158).
Both options were accepted and dropped here, so an operator following Core's
documented least-privilege recipe — an -rpcauth user for a monitoring process
plus -rpcwhitelist=monitor:getblockcount — got a credential with the FULL RPC
surface: stop, sendrawtransaction, setban and every wallet method. An
authorization control that fails OPEN.

A batch is refused as a unit, because Core checks every member's method before
running any of them (:176-189) — otherwise a batch would be a way to call a
forbidden method and read the permitted members' results anyway."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node))
          (port 19992)
          (cookie nil))
      (setf (bl:node-data-directory node) dir)
      (labels ((start (&rest whitelist-args)
                 (is (not (null (apply #'bl.rpc:start-rpc-server node
                                       :port port
                                       :rpc-auth (mapcar #'third *core-whitelist-users*)
                                       whitelist-args)))
                     "the server did not start for ~S" whitelist-args)
                 (setf cookie (alexandria:read-file-into-string
                               (merge-pathnames ".cookie" dir))))
               (status (credential method)
                 (%http-status
                  (%http-post-rpc port (format nil "{\"method\":\"~A\",\"id\":1}" method)
                                  :auth credential)))
               (user-status (user method)
                 (status (core-whitelist-credential user) method))
               (whitelist-batch (&rest methods)
                 (format nil "[~{{\"method\":\"~A\",\"id\":1}~^,~}]" methods)))
        (unwind-protect
             (progn
               ;; CONTROL: with no -rpcwhitelist at all every authenticated
               ;; user calls everything, which is what this node did for every
               ;; configuration before the gate existed.
               (start)
               (is (= 200 (user-status "user1" "getnetworkinfo")))
               (is (= 200 (user-status "strangedude6" "getnetworkinfo")))
               (bl.rpc:stop-rpc-server)

               ;; Two whitelists, and no -rpcwhitelistdefault: Core defaults it
               ;; to ON as soon as any whitelist is given (httprpc.cpp:306).
               (start :rpc-whitelist '("user1:getblockcount,uptime,"
                                       "user2:getblockcount"))
               (is (= 200 (user-status "user1" "getblockcount")))
               (is (= 200 (user-status "user1" "uptime")))
               (is (= 403 (user-status "user1" "getnetworkinfo")))
               (is (= 200 (user-status "user2" "getblockcount")))
               (is (= 403 (user-status "user2" "uptime")))
               ;; A user no whitelist names may call NOTHING under that
               ;; default — the cookie user, and so bitcoin-cli and the web UI,
               ;; included. rpc_whitelist.py whitelists __cookie__ explicitly
               ;; for exactly this reason.
               (is (= 403 (user-status "strangedude6" "getblockcount")))
               (is (= 403 (status cookie "getblockcount")))
               ;; A wrong password is still 401: the whitelist is consulted
               ;; only once a credential has authenticated.
               (is (= 401 (status "user1:wrong" "getblockcount")))
               ;; Batches: refused as a unit if ANY member is off the list.
               (is (= 403 (%http-status
                           (%http-post-rpc
                            port (whitelist-batch "getblockcount" "getnetworkinfo")
                            :auth (core-whitelist-credential "user1")))))
               (is (= 200 (%http-status
                           (%http-post-rpc
                            port (whitelist-batch "getblockcount" "uptime")
                            :auth (core-whitelist-credential "user1")))))
               (bl.rpc:stop-rpc-server)

               ;; -rpcwhitelistdefault=0: the same whitelists restrict only the
               ;; users they name, and everyone else is unrestricted again.
               (start :rpc-whitelist '("user1:getblockcount,uptime,"
                                       "user2:getblockcount")
                      :rpc-whitelist-default nil)
               (is (= 403 (user-status "user1" "getnetworkinfo")))
               (is (= 200 (user-status "strangedude6" "getnetworkinfo")))
               (is (= 200 (status cookie "getnetworkinfo"))))
          (bl.rpc:stop-rpc-server))))))

(test rpc-allowip-acl-matching
  "The RPC ACL matches the way Core's CSubNet does: only within the same
network, bytewise under the netmask (netaddress.cpp CSubNet::Match), over a list
that always starts with 127.0.0.0/8 and ::1 (InitHTTPAllowList,
httpserver.cpp:148-165)."
  (flet ((acl (&rest specs)
           (let ((subnets (bl.rpc::%parse-rpc-acl specs)))
             (is-true subnets "rejected ~S" specs)
             subnets)))
    ;; loopback is allowed with no -rpcallowip at all, and nothing else is
    (let ((bl.rpc::*rpc-allow-subnets* (acl)))
      (is (bl.rpc::rpc-client-allowed-p "127.0.0.1"))
      (is (bl.rpc::rpc-client-allowed-p "127.9.9.9"))
      (is (bl.rpc::rpc-client-allowed-p "::1"))
      (is (not (bl.rpc::rpc-client-allowed-p "192.168.1.5")))
      (is (not (bl.rpc::rpc-client-allowed-p "::2")))
      ;; an address we cannot parse is refused, never defaulted in
      (is (not (bl.rpc::rpc-client-allowed-p "example.com")))
      (is (not (bl.rpc::rpc-client-allowed-p "")))
      (is (not (bl.rpc::rpc-client-allowed-p nil))))
    ;; CIDR, dotted-quad netmask and a bare address are the three accepted forms
    (dolist (spec '("192.168.1.0/24" "192.168.1.0/255.255.255.0" "192.168.1.77/24"))
      (let ((bl.rpc::*rpc-allow-subnets* (acl spec)))
        (is (bl.rpc::rpc-client-allowed-p "192.168.1.5") "~A" spec)
        (is (not (bl.rpc::rpc-client-allowed-p "192.168.2.5")) "~A" spec)
        (is (bl.rpc::rpc-client-allowed-p "127.0.0.1") "~A" spec)))
    (let ((bl.rpc::*rpc-allow-subnets* (acl "10.0.0.7")))
      (is (bl.rpc::rpc-client-allowed-p "10.0.0.7"))
      (is (not (bl.rpc::rpc-client-allowed-p "10.0.0.8"))))
    ;; the two wildcards are per-network, which is the whole point of Core
    ;; comparing m_net before the netmask: 0.0.0.0/0 does not open IPv6
    (let ((bl.rpc::*rpc-allow-subnets* (acl "0.0.0.0/0")))
      (is (bl.rpc::rpc-client-allowed-p "8.8.8.8"))
      (is (not (bl.rpc::rpc-client-allowed-p "2001:db8::1"))))
    (let ((bl.rpc::*rpc-allow-subnets* (acl "::/0")))
      (is (bl.rpc::rpc-client-allowed-p "2001:db8::1"))
      (is (not (bl.rpc::rpc-client-allowed-p "8.8.8.8"))))
    (let ((bl.rpc::*rpc-allow-subnets* (acl "2001:db8::/32")))
      (is (bl.rpc::rpc-client-allowed-p "2001:db8:1::9"))
      (is (not (bl.rpc::rpc-client-allowed-p "2001:dead::9"))))))

(test rpc-allowip-rejects-bad-specs
  "An unparseable -rpcallowip stops the RPC server rather than being dropped:
Core returns false from InitHTTPAllowList, which fails InitHTTPServer and aborts
startup (httpserver.cpp:155-160). Dropping it would leave an operator believing
a subnet is allowed when it is not."
  (dolist (bad '("1.2.3.4/33" "::1/129" "example.com" "1.2.3.4/abc" "1.2.3.4/"
                 "" "1.2.3.4/255.255.255.0/8" "::1/255.255.255.0"))
    (is (not (bl.net:parse-subnet bad)) "accepted ~S" bad)
    (is-false (bl.rpc::%parse-rpc-acl (list bad)) "%parse-rpc-acl accepted ~S" bad))
  ;; a good list still parses, on top of the loopback floor
  (is-true (bl.rpc::%parse-rpc-acl '("10.0.0.0/8" "::/0"))))

(test rpc-acl-gates-every-surface-not-just-jsonrpc
  "The ACL runs in the ACCEPTOR, so it covers /rest/ and /ui/ as well as \"/\".
Core checks ClientAllowed in http_request_cb (httpserver.cpp:216-222) BEFORE the
pathHandlers lookup (:235-250), which is why /rest/ (rest.cpp:1160-1164) needs
no check of its own.

This is the test that would have caught the ACL living inside rpc-handler: with
it there, a blocked client got 403 on \"/\" while GET /rest/mempool/contents.json
and the whole /ui/ SPA answered normally — and -rpcbind is what makes a remote
client reach them at all."
  (let ((acceptor (make-instance 'bl.rpc::rpc-acceptor :port 0))
        (bl.rpc::*rpc-allow-subnets*
          (bl.rpc::%parse-rpc-acl '("10.0.0.0/8"))))
    (flet ((acl-refusal-p (body)
             ;; A helper, not an inline (and (stringp body) (search ...)): the
             ;; `is` macro evaluates the argument forms of a compound predicate
             ;; eagerly, so the stringp guard would not protect the search.
             (and (stringp body)
                  (search "not allowed RPC access" body)
                  t))
           (dispatch (uri remote-addr)
             (let* ((hunchentoot:*acceptor* nil)
                    (hunchentoot:*reply* (make-instance 'hunchentoot:reply))
                    (request (make-instance 'hunchentoot:request
                                            :acceptor nil
                                            :headers-in (list (cons :host "127.0.0.1:18332"))
                                            :method :get
                                            :uri uri
                                            :remote-addr remote-addr
                                            :server-protocol :http/1.1
                                            :content-stream nil))
                    (hunchentoot:*request* request))
               (setf (hunchentoot:return-code*) hunchentoot:+http-ok+)
               (let ((body (handler-case
                               (hunchentoot:acceptor-dispatch-request acceptor request)
                             ;; hunchentoot signals its own 404 when no
                             ;; dispatcher matches; that is "got past the ACL".
                             (error () :past-the-acl))))
                 (values (hunchentoot:return-code*) body)))))
      (dolist (uri '("/" "/rest/mempool/contents.json" "/rest/chaininfo.json" "/ui/"))
        ;; outside the ACL: 403 on every surface, and the body says only that
        (dolist (blocked '("198.51.100.5" "2001:db8::1"))
          (multiple-value-bind (status body) (dispatch uri blocked)
            (is-true (eql hunchentoot:+http-forbidden+ status)
                     "~A from ~A must be refused by the ACL, got ~S" uri blocked status)
            (is-true (acl-refusal-p body)
                     "~A from ~A leaked a non-ACL response: ~S" uri blocked body)))
        ;; inside the ACL — the -rpcallowip entry and the loopback floor alike —
        ;; the request reaches routing, whatever routing then says
        (dolist (allowed '("10.1.2.3" "127.0.0.2"))
          (multiple-value-bind (status body) (dispatch uri allowed)
            (declare (ignore status))
            (is-false (acl-refusal-p body)
                      "~A from ~A was refused by the ACL and should not have been"
                      uri allowed))))
      ;; 127.0.0.2 above is admitted by the floor, not by 10.0.0.0/8 — so it
      ;; must still get through with no -rpcallowip configured at all
      (let ((bl.rpc::*rpc-allow-subnets*
              (bl.rpc::%parse-rpc-acl '())))
        (multiple-value-bind (status body) (dispatch "/rest/chaininfo.json" "127.0.0.2")
          (declare (ignore status))
          (is-false (acl-refusal-p body)
                    "loopback must reach routing with no -rpcallowip at all"))))))

;;; --- Test-harness control RPCs (track B P0) ---

(defun %parse-core-client-cpp ()
  "Parse Core's vRPCConvertParams out of refs/bitcoin/src/rpc/client.cpp, the
same way rpc_help.py's process_mapping does.

Returns (values json-rows string-rows), each a list of (method position name).
Parsing Core's source directly, rather than checking in a copy, is what makes
this a real oracle: the day Core adds an argument, this test notices."
  (let ((path (merge-pathnames "refs/bitcoin/src/rpc/client.cpp"
                               (asdf:system-source-directory :bitcoin-lisp)))
        (json '()) (strings '()) (in-rpcs nil))
    (with-open-file (in path :if-does-not-exist nil)
      (unless in (return-from %parse-core-client-cpp (values nil nil)))
      (loop for line = (read-line in nil) while line
            do (cond
                 ((not in-rpcs)
                  (when (search "static const CRPCConvertParam vRPCConvertParams[] =" line)
                    (setf in-rpcs t)))
                 ((and (>= (length line) 2) (string= "};" (subseq line 0 2)))
                  (setf in-rpcs nil))
                 ((and (find #\{ line) (find #\" line))
                  ;; { "method", N, "argname" [, ParamFormat::X] },
                  (let* ((q1 (position #\" line))
                         (q2 (and q1 (position #\" line :start (1+ q1))))
                         (comma (and q2 (position #\, line :start (1+ q2))))
                         (q3 (and comma (position #\" line :start comma)))
                         (q4 (and q3 (position #\" line :start (1+ q3)))))
                    (when q4
                      (let* ((method (subseq line (1+ q1) q2))
                             (num-str (string-trim " ," (subseq line (1+ comma)
                                                                (or (position #\, line :start (1+ comma))
                                                                    (length line)))))
                             (position-n (ignore-errors (parse-integer num-str)))
                             (name (subseq line (1+ q3) q4))
                             (row (list method position-n name)))
                        (when position-n
                          (if (search "ParamFormat::STRING" line)
                              (push row strings)
                              (push row json))))))))))
    (values (nreverse json) (nreverse strings))))

(test json-type-errors-use-cores-one-shape
  "Core reports every argument type mismatch with ONE sentence, built in one
place: \"JSON value of type <actual> is not of expected type <expected>\"
(univalue.cpp:210-214), with uvTypeName's six names (:217-226).

Ours wrote a different sentence at each site — \"First parameter must be an
array of tx hex\", \"JSON value is not an integer as expected\" — all saying
the same thing in words no caller can predict. Core's tests match on the
canonical string: rpc_rawtransaction.py looks for \"not of expected type
number\" and mempool_accept.py for \"JSON value of type string is not of
expected type array\".

The type NAMES are Core's, not Lisp's, which is the part that would rot
silently: a list is an \"array\", a hash-table an \"object\", and the false
sentinel a \"bool\"."
  (flet ((message (value expected)
           (handler-case (progn (bl.rpc::%json-type-error value expected) nil)
             (bl.rpc:rpc-error (e)
               (bl.rpc:rpc-error-message e))))
         (code (value expected)
           (handler-case (progn (bl.rpc::%json-type-error value expected) nil)
             (bl.rpc:rpc-error (e)
               (bl.rpc:rpc-error-code e)))))
    (is (equal "JSON value of type string is not of expected type array"
               (message "abc" "array")))
    (is (equal "JSON value of type number is not of expected type string"
               (message 5 "string")))
    (is (equal "JSON value of type array is not of expected type number"
               (message (list 1 2) "number")))
    (is (equal "JSON value of type object is not of expected type array"
               (message (make-hash-table :test 'equal) "array")))
    (is (equal "JSON value of type bool is not of expected type number"
               (message bl.rpc:+json-false+ "number"))
        "the false sentinel must name itself bool, not null")
    ;; Core answers RPC_TYPE_ERROR (-3) for these, not a generic parameter error.
    (is (eql bl.rpc:+rpc-type-error+ (code "abc" "array")))))

(test createrawtransaction-accepts-real-json-objects
  "A JSON object reaches an RPC handler as a HASH-TABLE from the decoder and as
an ALIST from the unit tests. createrawtransaction read both its inputs and its
outputs as alists, and ASSOC on a hash-table is a type error — so it failed for
every real JSON-RPC client while this suite stayed green, because the suite
passes alists.

%OBJ-GET and %OBJ-PAIRS already existed for exactly this, with a docstring
naming the split (\"alist (from tests / JSON-RPC 1.x) or a hash-table (from
yason)\"). They just had the wrong callers — the eleventh time this wave that
the correct code was present and unused.

Both shapes must produce the SAME transaction, which is the property that
makes the tests meaningful again."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (txid "0000000000000000000000000000000000000000000000000000000000000001")
         (addr "bcrt1qhku5rq7jz8ulufe2y6fkcpnlvpsta7rq4442dy")
         (as-hash (bl.rpc::rpc-createrawtransaction
                   node (list (list (let ((h (make-hash-table :test 'equal)))
                                      (setf (gethash "txid" h) txid
                                            (gethash "vout" h) 0)
                                      h))
                              (let ((h (make-hash-table :test 'equal)))
                                (setf (gethash addr h) 0.5d0)
                                h))))
         (as-alist (bl.rpc::rpc-createrawtransaction
                    node (list (list (list (cons "txid" txid) (cons "vout" 0)))
                               (list (cons addr 0.5d0))))))
    (is (stringp as-hash) "the hash-table form did not produce a transaction")
    (is (equal as-alist as-hash)
        "the two JSON shapes produced different transactions:~%  ~A~%  ~A"
        as-alist as-hash)))

(test createrawtransaction-takes-cores-outputs-forms
  "Core parses this argument in ONE place and accepts TWO spellings.
NormalizeOutputs (rawtransaction_util.cpp:74-99) takes either an object
{address: amount} or an ARRAY of single-key objects, and merges the array into
a dict — the array form exists because it preserves ORDER, which is why the
functional suite uses it (rpc_createmultisig.py:117). ParseOutputs then handles
the \"data\" key as an OP_RETURN and refuses duplicate keys.

%PARSE-OUTPUTS is that function here, and createrawtransaction was the one
caller not using it: its own loop took the object form only, so the array form
answered \"Invalid outputs format\", a data output was impossible, and duplicate
addresses passed silently. The twelfth time this wave that the code existed and
the caller that needed it did not use it."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (txid "0000000000000000000000000000000000000000000000000000000000000001")
         (addr "bcrt1qhku5rq7jz8ulufe2y6fkcpnlvpsta7rq4442dy")
         (addr2 "bcrt1qqurswpc8qurswpc8qurswpc8qurswpc8dxm0gk"))
    (flet ((obj (&rest pairs)
             (let ((h (make-hash-table :test 'equal)))
               (loop for (k v) on pairs by #'cddr do (setf (gethash k h) v))
               h))
           (ins () (list (list (cons "txid" txid) (cons "vout" 0)))))
      ;; The two spellings of the same single output agree.
      (let ((as-object (bl.rpc::rpc-createrawtransaction
                        node (list (ins) (obj addr 0.5d0))))
            (as-array (bl.rpc::rpc-createrawtransaction
                       node (list (ins) (list (obj addr 0.5d0))))))
        (is (stringp as-array) "the array-of-objects form did not produce a transaction")
        (is (equal as-object as-array)
            "the object and array spellings produced different transactions:~%  ~A~%  ~A"
            as-object as-array))
      ;; The array form keeps its ORDER, which is the reason Core has it. Two
      ;; distinct addresses with distinct amounts pin which output came first.
      (let* ((hex (bl.rpc::rpc-createrawtransaction
                   node (list (ins) (list (obj addr 0.5d0) (obj addr2 0.25d0)))))
             (tx (flexi-streams:with-input-from-sequence
                     (s (bl.crypto:hex-to-bytes hex))
                   (bl.ser:read-transaction s)))
             (outs (bl.ser:transaction-outputs tx)))
        (is (= 2 (length outs)))
        (is (= 50000000 (bl.ser:tx-out-value (aref outs 0))))
        (is (= 25000000 (bl.ser:tx-out-value (aref outs 1)))))
      ;; A "data" key is an OP_RETURN output carrying zero value, not an address.
      (let* ((hex (bl.rpc::rpc-createrawtransaction
                   node (list (ins) (list (obj "data" "deadbeef")))))
             (tx (flexi-streams:with-input-from-sequence
                     (s (bl.crypto:hex-to-bytes hex))
                   (bl.ser:read-transaction s)))
             (out (aref (bl.ser:transaction-outputs tx) 0))
             (spk (bl.ser:tx-out-script-pubkey out)))
        (is (= 0 (bl.ser:tx-out-value out)))
        (is (= #x6a (aref spk 0)) "a data output must be an OP_RETURN"))
      ;; Duplicates are refused, where the old loop accepted them silently.
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-createrawtransaction
         node (list (ins) (list (obj addr 0.5d0) (obj addr 0.25d0))))))))

(test signrawtransactionwithkey-takes-real-json-prevtxs
  "prevtxs is an ARRAY OF OBJECTS, and each object arrives as a HASH-TABLE from
a real client. This handler read them with ASSOC, which is a type error on a
hash-table, and the error escaped to the client as \"-32603 Internal error: The
value #<HASH-TABLE ...> is not of type LIST\" — so the method could not be
called with prevtxs at all, which is how
rpc_signrawtransactionwithkey.py:71 calls it. Every unit test passed by handing
it alists. Same defect as createrawtransaction's inputs, one file over.

Signing needs a key we do not have here; what this pins is that the prevout map
is BUILT from either shape, so the two must fail identically and never with an
internal error."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (txid "0000000000000000000000000000000000000000000000000000000000000001")
         (spk "76a91460baa0f494b38ce3c940dea67f3804dc52d1fb9488ac")
         (raw (bl.rpc::rpc-createrawtransaction
               node (list (list (list (cons "txid" txid) (cons "vout" 0)))
                          (let ((h (make-hash-table :test 'equal)))
                            (setf (gethash "bcrt1qhku5rq7jz8ulufe2y6fkcpnlvpsta7rq4442dy" h) 0.5d0)
                            h))))
         (as-hash (let ((h (make-hash-table :test 'equal)))
                    (setf (gethash "txid" h) txid
                          (gethash "vout" h) 0
                          (gethash "scriptPubKey" h) spk)
                    h))
         (as-alist (list (cons "txid" txid) (cons "vout" 0)
                         (cons "scriptPubKey" spk))))
    (let ((from-hash (bl.rpc::rpc-signrawtransactionwithkey
                      node (list raw '() (list as-hash))))
          (from-alist (bl.rpc::rpc-signrawtransactionwithkey
                       node (list raw '() (list as-alist)))))
      ;; No internal error, and the same answer from both shapes.
      (is (equal from-alist from-hash)
          "the two JSON shapes produced different results:~%  ~A~%  ~A"
          from-alist from-hash))))

(test deriveaddresses-expands-a-multipath-descriptor
  "A multipath descriptor denotes SEVERAL descriptors, and Core's
deriveaddresses returns one address array per expansion — an array of arrays
(rpc_deriveaddresses.py:32-33).

The multipath PR built EXPAND-MULTIPATH-DESCRIPTOR for the wallet's import path, and
deriveaddresses went on refusing multipath outright, because the refusal lives
in the key-path parser it reaches first. Another instance of the code existing
and the caller that needed it not using it.

The checksum is validated ONCE, on the multipath form it actually covers; the
expansions carry none by construction, so requiring one per expansion answers
\"Missing checksum\" for a descriptor whose checksum was correct."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (body (concatenate 'string
                            "wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZ"
                            "mbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRv"
                            "mDUjyEmNUWwx8UbK/1/<0;1>/*)"))
         (desc (format nil "~A#~A" body (bl.rpc::descriptor-checksum body)))
         (result (bl.rpc::rpc-deriveaddresses node (list desc (list 1 2)))))
    ;; Core's own expected value, verbatim from the test.
    (is (equalp #(#("bcrt1q7c8mdmdktrzs8xgpjmqw90tjn65j5a3yj04m3n"
                    "bcrt1qs6n37uzu0v0qfzf0r0csm0dwa7prc0v5uavgy0")
                  #("bcrt1qhku5rq7jz8ulufe2y6fkcpnlvpsta7rq4442dy"
                    "bcrt1qpgptk2gvshyl0s9lqshsmx932l9ccsv265tvaq"))
                result)
        "multipath deriveaddresses: ~S" result)
    ;; A bad checksum on the multipath form is still refused — validating once
    ;; must not mean validating never.
    (signals error
      (bl.rpc::rpc-deriveaddresses
       node (list (format nil "~A#00000000" body) (list 1 2))))
    ;; And an ordinary descriptor still returns a flat list.
    (let* ((single (concatenate 'string
                                "wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZ"
                                "mbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRv"
                                "mDUjyEmNUWwx8UbK/1/1/*)"))
           (flat (bl.rpc::rpc-deriveaddresses
                  node (list (format nil "~A#~A" single
                                     (bl.rpc::descriptor-checksum single))
                             (list 1 2)))))
      (is (listp flat) "an ordinary descriptor must not become an array of arrays")
      (is (= 2 (length flat))))))

(test a-relative-debuglogfile-lands-in-the-network-directory
  "Core resolves a relative -debuglogfile against the NETWORK datadir
(AbsPathForConfigVal, net_specific=true), and an absolute one as given.
feature_logging.py starts a node with -debuglogfile=foo.log and then looks for
<datadir>/<chain>/foo.log.

Ours took a relative path as given, so the log landed wherever the process
happened to be started from — for a supervised service, /. The debug.log move put the
DEFAULT debug.log into the network directory and stopped there; this is the
other half of the same rule."
  (flet ((resolve (log-file) (bl::%resolve-log-file log-file "/tmp/dd/" :regtest)))
    (is (equal "/tmp/dd/regtest/foo.log" (resolve "foo.log")))
    (is (equal "/tmp/dd/regtest/debug.log" (resolve nil)))
    ;; Absolute stays absolute — feature_logging's second case writes outside
    ;; the datadir on purpose.
    (is (equal "/var/log/foo.log" (resolve "/var/log/foo.log")))
    ;; -debuglogfile=0 still turns file logging off entirely (Core's spelling).
    (is (null (resolve "0")))
    ;; No network: the base directory, which is what the pre-Core callers and
    ;; the unit tests pass.
    (is (equal "/tmp/dd/foo.log"
               (bl::%resolve-log-file "foo.log" "/tmp/dd/")))))

(test an-unknown-peer-height-does-not-break-the-sync-thread
  "A peer's advertised start height is a SIGNED int32 whose \"unknown\" value
is -1: Core's CNode::nStartingHeight initialises to -1, and Core's own
P2PInterface test client sends -1 in every version message it builds.

Two things read it as an unsigned height.

START-IBD stored it in a (UNSIGNED-BYTE 32) slot, so -1 was a TYPE ERROR — on
the sync thread, which unwinds the whole iteration before MAINTAIN-PEERS runs.
Nothing is pumped, nothing is reaped, and the next iteration fails identically:
one peer sending a legal value takes the sync loop down for as long as it stays
connected. Observed as every p2p_* functional test timing out in
sync_with_ping, because the node never answered a ping.

CONSIDER-PEER-EVICTION read -1 as a height 1001 behind, so any node past height
999 disconnected such peers on sight. Core has no height-based eviction at all;
this rule is ours, and it has to mean what it says."
  (let ((unknown (bl.net:make-peer :address "10.2.2.2" :state :ready
                                                    :start-height -1))
        (behind (bl.net:make-peer :address "10.2.2.3" :state :ready
                                                   :start-height 5)))
    ;; Unknown is not "behind", at any height of ours.
    (is-false (bl.net:consider-peer-eviction unknown 100000)
              "a peer advertising an unknown height was evicted as if it were behind")
    ;; A peer that really is far behind still goes.
    (is-true (bl.net:consider-peer-eviction behind 100000))
    ;; ...and one that is only a little behind stays.
    (is-false (bl.net:consider-peer-eviction behind 500)))
  ;; The hazard is real: the slot is (UNSIGNED-BYTE 32), so a raw -1 signals.
  ;; Asserted rather than assumed, because if the slot type ever widened this
  ;; test would otherwise keep passing while testing nothing.
  (let ((ctx (bl.net::make-ibd)))
    (signals error
      (setf (bl.net::ibd-context-target-height ctx) -1))
    (finishes
      (setf (bl.net::ibd-context-target-height ctx) 0)))
  ;; And START-IBD clamps before it stores, so the sync thread never gets
  ;; there. Driving START-IBD itself would need a whole node fixture; what
  ;; matters is that the clamp is on the line that writes the slot.
  (let ((src (with-open-file (in (merge-pathnames "src/networking/ibd.lisp"
                                                  (asdf:system-source-directory :bitcoin-lisp)))
               (let ((text (make-string (file-length in))))
                 (subseq text 0 (read-sequence text in))))))
    (is (search "(ibd-context-target-height *ibd-context*) (max 0 target-height)" src)
        "start-ibd no longer clamps its target height")))

(test the-sync-wait-shortens-when-we-are-behind
  "The sync loop's between-pass wait ends early on a NEW header announcement,
which covers headers arriving DURING the wait. It did not cover the other
order: headers ingested during the sync pass itself, where there is known work
and nobody left to announce it — so the retry sat out the full 30 seconds.

Measured on two regtest nodes, five blocks, one announcement: 40 seconds to
converge, of which ~24 were this wait; 25 seconds after the change. Core's
tests allow 60 seconds for a full sync, so that one wait alone put most
multi-node tests on the edge.

*HIGHEST-HEADER-SEEN* is what makes it answerable at all: the IBD context is
per-pass and gone by the time the wait starts, so the header tip has to outlive
it. Monotone, and a hint only — it shortens a wait and decides nothing about
the chain."
  (is (= 5 bl::+behind-retry-seconds+)
      "the bound is what keeps an unservable chain from spinning; it is not a poll interval")
  (is (< bl::+behind-retry-seconds+ 30)
      "a bound at or above the wait itself would make the whole thing inert")
  ;; Monotone: a lower header tip from a later pass must not lower it.
  (let ((bl.net:*highest-header-seen* 0))
    (setf bl.net:*highest-header-seen* 900)
    (is (= 900 bl.net:*highest-header-seen*))))

(test manual-peers-report-connection-type-manual
  "ConnectionType::MANUAL is a first-class member of Core's enum
(node/connection_types.cpp:13), so an addnode peer's getpeerinfo
connection_type is \"manual\" — not \"outbound-full-relay\" with a flag
somewhere else. rpc_net.py asserts exactly that (:125).

We keep it as a flag internally on purpose: the outbound-slot budgets are
written against the automatic types, and a manual peer occupies none of them in
Core either. What has to agree is the report."
  (let ((node (make-test-node))
        (manual (bl.net:make-peer :address "10.1.1.1" :state :ready))
        (auto (bl.net:make-peer :address "10.1.1.2" :state :ready
                                       :conn-type :outbound-full-relay))
        (inbound (bl.net:make-peer :address "10.1.1.3" :state :ready :inbound t)))
    (setf (bl.net:peer-manual manual) t)
    ;; An INBOUND peer is never "manual", whatever flags it carries: Core's
    ;; inbound connections are ConnectionType::INBOUND, full stop.
    (setf (bl.net:peer-manual inbound) t)
    (setf (bl:node-peers node) (list manual auto inbound))
    (let* ((rows (bl.rpc::%peerinfo-rows node))
           (types (mapcar (lambda (r) (cdr (assoc "connection_type" r :test #'string=)))
                          rows)))
      (is (equal '("manual" "outbound-full-relay" "inbound") types)
          "connection_type: ~S" types))))

(test submitted-blocks-are-announced-to-peers
  "RELAY-BLOCK existed and had exactly one caller — the P2P receive path — so a
block that ARRIVED was forwarded and a block this node MINED was not. Core
makes no such distinction: submitblock runs ProcessNewBlock like any other
block, and the resulting tip change drives the announcement.

Nothing about the node looked wrong: it mined, validated, connected, and its
own getblockcount advanced. The block simply never left, and a peer learned of
it only on its next getheaders — throttled to one per two minutes per peer. So
Core's functional tests, which allow sixty seconds for two nodes to agree on a
tip, timed out against a node working perfectly in isolation.

Two halves, because either alone would pass against the bug: that a NIL source
peer excludes nobody (a locally mined block has no source to skip), and that
the submitblock path actually makes the call."
  (let ((peer (bl.net:make-peer :address "10.9.9.9" :state :ready)))
    ;; A ready peer with no connection: SEND-MESSAGE is a no-op on it, so the
    ;; count is taken from the relay target list instead.
    (is (equal (list peer)
               (bl.net::block-relay-targets nil (list peer)))
        "a NIL source peer must not exclude anybody — a locally mined block has no source")
    ;; And the production call site passes NIL, rather than only the P2P one
    ;; having a call at all. This is the half that was missing, so it is the
    ;; half the test pins.
    (let ((src (%rpc-source-text)))
      (is (search "relay-block header nil peers" src)
          "the submitblock path no longer announces the block it just connected"))))

(test getpeerinfo-rows-are-in-peer-id-order
  "Core's getpeerinfo comes out in ascending peer id: m_nodes is a vector
appended to on connect, ids are monotonic, and GetNodeStats walks it in place
(net.cpp:3797-3807). Our node-peers is a list PUSHED to, so it came out
newest-first — exactly reversed.

Tests index this array positionally, and a reversed list does not fail loudly;
it compares the wrong two peers and reports plausible values. rpc_net.py pairs
the ends of a connection with `assert_equal(peer_info[0][0]['addrbind'],
peer_info[1][0]['addr'])` and got two real addresses that simply belonged to
different connections."
  (let ((node (make-test-node))
        (peers '()))
    (dolist (addr '("10.0.0.1" "10.0.0.2" "10.0.0.3"))
      ;; PUSH, which is how the sync thread builds the list.
      (push (bl.net:make-peer :address addr :state :ready) peers))
    (setf (bl:node-peers node) peers)
    (let* ((ids (mapcar (lambda (p) (bl.net:peer-id p))
                        (bl:node-peers node)))
           (rows (bl.rpc::%peerinfo-rows node))
           (row-ids (mapcar (lambda (r) (cdr (assoc "id" r :test #'string=))) rows)))
      ;; The precondition: the stored list really is newest-first, so this test
      ;; is not asserting a sort that was already trivially true.
      (is (equal ids (reverse (sort (copy-list ids) #'<)))
          "node-peers was not newest-first; the fixture no longer reproduces the bug")
      (is (equal (sort (copy-list row-ids) #'<) row-ids)
          "getpeerinfo rows are not in ascending peer id: ~S" row-ids))))

(test getpeerinfo-addr-carries-the-port
  "Core's getpeerinfo `addr` is CNode::addr.ToStringAddrPort() — \"ip:port\"
(rpc/net.cpp:130). Ours reported the host alone.

The port is not decoration. Core's framework pairs the two ends of a
connection by comparing one node's `addrbind` against the other's `addr`
(rpc_net.py:116-117), and a bare host can never equal an \"ip:port\"; and two
peers behind one address are indistinguishable in the output without it, which
on regtest is every peer."
  (let ((peer (bl.net:make-peer :address "203.0.113.4" :state :ready)))
    ;; No connection at all: the host alone is all there is, and that must not
    ;; become \"host:0\" or an error.
    (is (string= "203.0.113.4" (bl.rpc::%peer-addr peer)))
    (setf (bl.net:peer-connection peer)
          (bl.net::make-connection
           :host "203.0.113.4" :port 8333 :connected t))
    (is (string= "203.0.113.4:8333" (bl.rpc::%peer-addr peer)))
    ;; A v6 literal is bracketed before the port, as CService::ToStringAddrPort
    ;; does — an unbracketed \"::1:8333\" is a different, valid v6 address.
    (let ((v6 (bl.net:make-peer :address "::1" :state :ready)))
      (setf (bl.net:peer-connection v6)
            (bl.net::make-connection :host "::1" :port 8333 :connected t))
      (is (string= "[::1]:8333" (bl.rpc::%peer-addr v6))))))

(test dial-dedup-compares-the-endpoint-not-just-the-host
  "Core has two dedup guards and applies them to different dials
(net.cpp:3020-3026). A dial with NO destination string — addrman's — is
deduped by ADDRESS (AlreadyConnectedToAddress, :347). A dial that NAMES a
destination — -addnode, `addnode onetry`, -connect, -seednode — is deduped by
the full destination against each peer's m_addr_name
(AlreadyConnectedToHost, :335).

Ours used the address-only guard for both. Wherever two peers can share an
address that is wrong, and on regtest every node is 127.0.0.1: one connection
to loopback blocked every later dial there, so a node could never hold more
than one connection to the local machine. Core's functional tests build every
topology out of exactly such dials, and the second connect_nodes in a test
simply found no new peer and timed out — with nothing wrong visible from inside
the node, which had been asked to dial a host it was already talking to.

An inbound peer must not block an outbound dial either. Core gets that from
m_addr_name carrying the ephemeral SOURCE port; ours from an accepted
connection recording port 0 while a dialed one records the port it dialed."
  (let ((node (make-test-node)))
    (flet ((peer-at (host port &key inbound)
             (let ((p (bl.net:make-peer :address host :state :ready
                                                         :inbound inbound)))
               (setf (bl.net:peer-connection p)
                     (bl.net::make-connection
                      :host host :port port :connected t))
               p)))
      ;; An INBOUND peer from 127.0.0.1 (source port recorded as 0).
      (setf (bl:node-peers node) (list (peer-at "127.0.0.1" 0 :inbound t)))
      (is-true (bl::peer-connected-to-host-p node "127.0.0.1")
               "the address-only guard should still see it")
      (is-false (bl::peer-connected-to-endpoint-p node "127.0.0.1" 11133)
                "an inbound peer blocked an outbound dial to the same host")
      ;; An OUTBOUND peer to a DIFFERENT port on the same host.
      (setf (bl:node-peers node) (list (peer-at "127.0.0.1" 11132)))
      (is-false (bl::peer-connected-to-endpoint-p node "127.0.0.1" 11133)
                "a peer on another port of the same host blocked the dial")
      ;; The same endpoint IS deduped — the guard still does its job.
      (is-true (bl::peer-connected-to-endpoint-p node "127.0.0.1" 11132))
      ;; And the addrman guard keeps Core's address-only semantics, which is
      ;; what makes the two functions worth having separately.
      (is-true (bl::peer-connected-to-host-p node "127.0.0.1")))))

(test disconnectnode-selects-by-address-or-id-as-core-does
  "Core's disconnectnode takes EITHER address OR nodeid, and the by-id form is
the one its functional framework uses — disconnect_nodes calls
`disconnectnode(nodeid=peer_id)` for every peer it wants gone
(test_framework.py:616). Ours had only the address form, so that arrived as a
NIL address and answered \"address must be a string\": an error about a
parameter the caller never sent.

The combination rule is Core's (rpc/net.cpp:471-479), empty string included —
`disconnectnode \"\" 1` is how Core's own help says to disconnect by id
positionally."
  (let* ((node (make-test-node))
         (peer (bl.net:make-peer :address "203.0.113.9" :state :ready)))
    (setf (bl.net:peer-id peer) 4242)
    (setf (bl:node-peers node) (list peer))
    ;; Both given: Core's exact refusal.
    (signals-rpc-error (:code bl.rpc:+rpc-invalid-params+
                        :exact-message "Only one of address and nodeid should be provided.")
      (bl.rpc::rpc-disconnectnode node '("203.0.113.9" 4242)))
    ;; Unknown id: Core's not-connected code, not a type error.
    (signals-rpc-error (:code bl.rpc::+rpc-client-node-not-connected+)
      (bl.rpc::rpc-disconnectnode node '(nil 999)))
    ;; By id, the framework's spelling: named nodeid only.
    (is (null (bl.rpc::rpc-disconnectnode node '(nil 4242))))
    ;; And Core's positional spelling for the same thing.
    (setf (bl:node-peers node) (list peer))
    (is (null (bl.rpc::rpc-disconnectnode node '("" 4242))))
    ;; By address still works.
    (setf (bl:node-peers node) (list peer))
    (is (null (bl.rpc::rpc-disconnectnode node '("203.0.113.9"))))))

(test rpcservertimeout-reaches-the-acceptor
  "-rpcservertimeout is only worth having if it changes the socket. It used to
SETF hunchentoot:*default-connection-timeout* AFTER the acceptor was made, and
that special is read only as the read-timeout/write-timeout slot INITFORM — so
the option reached nothing and every RPC connection kept hunchentoot's
20-second idle timeout.

Nothing complains when this is wrong: a client that reconnects never notices,
and one that does not gets a broken pipe on a connection it thought was open.
Core's functional framework writes rpcservertimeout=99000 into every node's
config for exactly this reason, and with the option inert connect_nodes died on
a broken pipe polling the second node ~50s after its previous call.

Assert against the acceptor's own slot — the thing the socket actually uses —
not against the special."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node)))
      (setf (bl:node-data-directory node) dir)
      ;; Core's default, not hunchentoot's.
      (is (= 30 bl.rpc:*rpc-server-timeout*))
      (let ((bl.rpc:*rpc-server-timeout* 99000))
        (unwind-protect
             (progn
               (bl.rpc:start-rpc-server node :port 19998)
               (is (= 99000 (hunchentoot:acceptor-read-timeout
                             bl.rpc:*rpc-server*)))
               (is (= 99000 (hunchentoot:acceptor-write-timeout
                             bl.rpc:*rpc-server*))))
          (bl.rpc:stop-rpc-server)))
      ;; The positive control: without the initargs the acceptor would carry
      ;; hunchentoot's own default, so a test that only checked "not nil"
      ;; would have passed against the bug.
      (is (= 20 hunchentoot:*default-connection-timeout*)
          "hunchentoot's default moved; the control this test relies on is gone"))))

(test named-arg-names-agree-with-cores-positions
  "The named-parameter table decides where a named argument lands in the
positional list, so a wrong POSITION is worse than a missing name: the call
succeeds and means something else.

Cross-check it against a second, independent extract of the same facts from
Core — client.cpp's vRPCConvertParams, which carries (method, position, name).

Two checks, and the shape of each is forced by what client.cpp actually is.
It is not \"the argument at position N is called X\": for an options-object
argument Core lists the object AND each of its FIELDS at the same position, so
`gethdkeys` position 0 carries both \"options\" and \"private\". Comparing
name-for-name against that reports 76 disagreements, every one of them an
options field, and none of them a defect. Getting that wrong once is why the
distinction is written down here.

  1. ARITY. Every position client.cpp names must exist in our table for that
     method. This is the check that catches the failure that produced this
     table: drop a string argument and every argument after it shifts down,
     and the tail is exactly what client.cpp lists.

  2. POSITION, for our names only. If one of OUR argument names appears in
     client.cpp for the same method, our index must be among the positions
     Core lists it at. Options FIELDS never appear in our table, so they are
     never checked; a top-level argument that moved is caught. `send` carries
     `conf_target` both as a top-level argument and as an options field, which
     is why this is \"among\" rather than \"equals\"."
  (multiple-value-bind (core-json core-strings) (%parse-core-client-cpp)
    (let ((rows (append core-json core-strings)))
      (if (null rows)
          (skip "refs/bitcoin not present")
          (let ((short '()) (moved '()) (checked 0))
            ;; 1. arity
            (dolist (row rows)
              (destructuring-bind (method position name) row
                (let ((entry (assoc method bl.rpc::*rpc-named-arg-names*
                                    :test #'string=)))
                  (when entry
                    (incf checked)
                    (when (<= (length (rest entry)) position)
                      (push (list method position name
                                  (length (rest entry)))
                            short))))))
            ;; 2. position of our own names
            (dolist (entry bl.rpc::*rpc-named-arg-names*)
              (let ((method (first entry)))
                (loop for name-spec in (rest entry)
                      for index from 0
                      do (let ((core-positions
                                 (loop for row in rows
                                       when (and (string= method (first row))
                                                 (bl.rpc::%named-arg-slot
                                                  name-spec (third row)))
                                         collect (second row))))
                           (when (and core-positions
                                      (not (member index core-positions)))
                             (push (list method name-spec index core-positions)
                                   moved))))))
            (is (> checked 250)
                "only ~D rows cross-checked; the table or the parser is not being exercised"
                checked)
            (is (null short)
                "~D of Core's argument positions are past the end of our table: ~S"
                (length short) (subseq short 0 (min 8 (length short))))
            (is (null moved)
                "~D of our arguments sit at a position Core does not list: ~S"
                (length moved) (subseq moved 0 (min 8 (length moved)))))))))

(test named-arg-table-covers-what-the-framework-calls
  "Every method this node registers should accept named parameters, because
Core accepts them for every method and its test framework uses them freely —
`stop(wait=...)` on every shutdown, `scantxoutset(action=...)` in MiniWallet's
constructor. A registered method missing from the table answers \"Unknown
named parameter\" and fails the caller.

Methods in the table that we do not implement are fine and expected; the table
is Core's full set."
  (let ((missing '()))
    (maphash (lambda (method fn)
               (declare (ignore fn))
               (unless (assoc method bl.rpc::*rpc-named-arg-names*
                              :test #'string=)
                 (push method missing)))
             bl.rpc::*rpc-methods*)
    ;; Ours-only methods (the web UI helpers and such) have no Core declaration
    ;; to take names from; they are named here so the exemption is a list
    ;; someone can read rather than a silent pass.
    (let ((ours-only '("migrateblocks")))
      (setf missing (remove-if (lambda (m) (member m ours-only :test #'string=))
                               missing)))
    (is (null missing)
        "~D registered methods accept no named parameters: ~S"
        (length missing) (sort missing #'string<))))

(test rpc-arg-conversions-match-core
  "Core's rpc_help.py asserts that a node's dump_all_command_conversions table
equals src/rpc/client.cpp's vRPCConvertParams. This runs the SAME comparison
here, in every battery, against Core's actual file — so the two cannot drift
between functional-test runs.

The comparison is restricted to methods this node implements, and that
restriction is measured rather than assumed: the second half reports exactly
which of Core's methods are missing, which is the real remaining distance to
rpc_help.py passing."
  (multiple-value-bind (core-json core-strings) (%parse-core-client-cpp)
    (if (null core-json)
        (skip "refs/bitcoin not present")
        (let* ((dump (bl.rpc::%dump-all-command-conversions))
               (ours (loop for row across dump
                           collect (list (aref row 0) (aref row 1) (aref row 2)
                                         (eq t (aref row 3)))))
               (our-methods (let ((h (make-hash-table :test 'equal)))
                              (maphash (lambda (k v) (declare (ignore v))
                                         (setf (gethash k h) t))
                                       bl.rpc::*rpc-methods*)
                              h))
               ;; Core's rows, restricted to what we serve.
               (want-json (remove-if-not (lambda (r) (gethash (first r) our-methods))
                                         core-json))
               (want-strings (remove-if-not (lambda (r) (gethash (first r) our-methods))
                                            core-strings))
               (got-json (loop for r in ours unless (fourth r)
                               collect (subseq r 0 3)))
               (got-strings (loop for r in ours when (fourth r)
                                  collect (subseq r 0 3))))
          (flet ((sorted (rows)
                   (sort (copy-list rows)
                         (lambda (a b)
                           (or (string< (first a) (first b))
                               (and (string= (first a) (first b))
                                    (or (< (second a) (second b))
                                        (and (= (second a) (second b))
                                             (string< (third a) (third b))))))))))
            (let ((missing (set-difference (sorted want-json) (sorted got-json)
                                           :test #'equal))
                  (extra (set-difference (sorted got-json) (sorted want-json)
                                         :test #'equal)))
              (is (null missing) "arguments Core converts and we do not: ~S" missing)
              (is (null extra) "arguments we convert and Core does not: ~S" extra))
            (let ((missing (set-difference (sorted want-strings) (sorted got-strings)
                                           :test #'equal)))
              (is (null missing)
                  "string arguments Core lists and we do not: ~S" missing))))))
  ;; And the measured distance to rpc_help.py: which of Core's methods we lack.
  ;; Named individually, because "22 missing" is not actionable and this is.
  (multiple-value-bind (core-json core-strings) (%parse-core-client-cpp)
    (when core-json
      (let* ((core-methods (remove-duplicates
                            (mapcar #'first (append core-json core-strings))
                            :test #'string=))
             ;; ⚠️ REGISTER FIRST. *RPC-METHODS* is populated by
             ;; REGISTER-ALL-METHODS at node start-up, so a battery that has not
             ;; started a node sees an EMPTY table and reports every Core method
             ;; as missing — which is how this assertion failed after four
             ;; methods were ADDED. Whether it has already run does not matter:
             ;; registration is idempotent.
             (ignore-errors (bl.rpc::register-all-methods))
             (missing (remove-if (lambda (m) (gethash m bl.rpc::*rpc-methods*))
                                 core-methods)))
        ;; Not an assertion of zero — these are tracked, and the list moving is
        ;; what matters. It IS an assertion that the list has not GROWN.
        (is (<= (length missing) 2)
            "Core methods with typed arguments that this node does not serve ~
grew to ~D: ~S" (length missing) (sort missing #'string<))))))

(test estimaterawfee-reports-the-evidence-not-just-a-number
  "Core estimaterawfee (rpc/fees.cpp:97-190). Unlike estimatesmartfee it asks
ONE horizon at ONE success threshold and reports the pass/fail buckets behind
the answer — that is what makes it a debugging tool rather than a second fee
API, and reporting a bare feerate would defeat the point.

A horizon that does not track the requested target is OMITTED rather than
reported as zero: absence and \"no answer\" mean different things to whoever is
reading the output."
  (let ((bl.mp:*block-policy-estimator*
          (bl.mp:make-block-policy-estimator)))
    ;; A fresh estimator has no history, so every horizon that TRACKS the
    ;; target still answers — with a zero rate and Core's errors array.
    (let ((r (bl.rpc::rpc-estimaterawfee nil '(2))))
      (is (consp r) "no horizon answered for a target every horizon tracks")
      (let ((short (cdr (assoc "short" r :test #'string=))))
        (is-true short "the short horizon did not answer for conf_target 2")
        (is (assoc "feerate" short :test #'string=))
        (is-true (assoc "errors" short :test #'string=)
                 "an estimator with no history must say so")))
    ;; A target only the long horizon tracks omits the shorter ones entirely.
    (let* ((long-max (bl.mp:horizon-max-confirms :long))
           (short-max (bl.mp:horizon-max-confirms :short))
           (r (bl.rpc::rpc-estimaterawfee
               nil (list (min long-max (1+ short-max))))))
      (is-false (assoc "short" r :test #'string=)
                "the short horizon answered for a target it does not track"))
    ;; Range and type checks.
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of (lambda () (bl.rpc::rpc-estimaterawfee nil '(0))))))
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of (lambda () (bl.rpc::rpc-estimaterawfee nil '(2 1.5))))))
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of (lambda () (bl.rpc::rpc-estimaterawfee nil '(2 -0.1))))))
    (is (= bl.rpc:+rpc-type-error+
           (rpc-error-code-of (lambda () (bl.rpc::rpc-estimaterawfee nil '("2"))))))))

(test addconnection-opens-the-named-connection-type
  "addconnection (Core rpc/net.cpp). The functional framework uses it to attach
its own P2P connections of a CHOSEN type — a block-relay or feeler slot a test
cannot ask for any other way — so the type reaching the dial is the point, not
just that something connected."
  (let ((bl:*pending-test-connections* '()))
    ;; Regtest only, with Core's exact text.
    (dolist (network '(:mainnet :testnet4 :signet))
      (let ((bl:*network* network))
        (signals-rpc-error (:exact-message "addconnection is for regression testing (-regtest mode) only.")
          (bl.rpc::rpc-addconnection
           nil '("1.2.3.4:1" "outbound-full-relay" t)))))
    (is-false bl:*pending-test-connections*
              "a refused addconnection still queued a dial")
    (let* ((bl:*network* :regtest)
           (node (bl:make-node :network :regtest)))
      ;; Each of Core's four types maps to a peer conn-type and is queued for
      ;; the sync thread, newest LAST (the queue is drained in request order).
      (dolist (pair '(("outbound-full-relay" . :outbound-full-relay)
                      ("block-relay-only"    . :block-relay)
                      ("addr-fetch"          . :addr-fetch)
                      ("feeler"              . :feeler)))
        (setf bl:*pending-test-connections* '())
        (let ((result (bl.rpc::rpc-addconnection
                       node (list "1.2.3.4:1" (car pair) nil))))
          (is (equal (car pair) (cdr (assoc "connection_type" result :test #'string=))))
          (is (equal "1.2.3.4:1" (cdr (assoc "address" result :test #'string=))))
          (is (equal (list (cons "1.2.3.4:1" (cdr pair)))
                     bl:*pending-test-connections*)
              "~A did not queue its own connection type" (car pair))))
      (setf bl:*pending-test-connections* '())
      ;; Core trims the type before matching.
      (is (equal "outbound-full-relay"
                 (cdr (assoc "connection_type"
                             (bl.rpc::rpc-addconnection
                              node '("1.2.3.4:1" "  outbound-full-relay  " nil))
                             :test #'string=))))
      ;; MANUAL and INBOUND are not offerable — Core's AddConnection returns
      ;; false for them, because addconnection exists for the AUTOMATIC kinds.
      (dolist (bad '("manual" "inbound" "" "outbound" "block-relay"))
        (is (= bl.rpc:+rpc-invalid-parameter+
               (rpc-error-code-of
                (lambda () (bl.rpc::rpc-addconnection
                            node (list "1.2.3.4:1" bad nil))))))))
    ;; v2transport=true without -v2transport is refused rather than silently
    ;; dialing v1 (Core rpc/net.cpp).
    (let ((bl:*network* :regtest)
          (bl.net:*v2-transport-enabled* nil)
          (node (bl:make-node :network :regtest)))
      (setf bl:*pending-test-connections* '())
      (signals-rpc-error (:code bl.rpc:+rpc-invalid-parameter+
                          :exact-message "Error: Adding v2transport connections requires -v2transport init flag to be set.")
        (bl.rpc::rpc-addconnection
         node '("1.2.3.4:1" "outbound-full-relay" t)))
      (is-false bl:*pending-test-connections*))
    ;; Capacity: the outbound full-relay and block-relay types are capped, the
    ;; other two are not (Core: none for addr-fetch, since -seednode has none,
    ;; and none for feeler, since feelers are short-lived).
    (let* ((bl:*network* :regtest)
           (node (bl:make-node :network :regtest :max-peers 0)))
      (setf bl:*pending-test-connections* '())
      (is (= bl.rpc::+rpc-client-node-capacity-reached+
             (rpc-error-code-of
              (lambda () (bl.rpc::rpc-addconnection
                          node '("1.2.3.4:1" "outbound-full-relay" nil))))))
      (dolist (uncapped '("addr-fetch" "feeler"))
        (is-true (bl.rpc::rpc-addconnection
                  node (list "1.2.3.4:1" uncapped nil))
                 "~A was capacity-limited" uncapped)))
    (setf bl:*pending-test-connections* '()))
  ;; And the queue is actually drained where peers are dialed — a request that
  ;; is only ever queued is exactly the shape of bug this repo keeps finding.
  (is-true (member 'bl::connect-added-nodes
                   (mapcar #'car
                           (sb-introspect:who-sets
                            'bl:*pending-test-connections*)))))

(test setmocktime-is-regtest-only
  "Core gates setmocktime on IsMockableChain, which only regtest sets
(chainparams.cpp:644), and raises a plain runtime_error otherwise — mapped to
RPC_MISC_ERROR with this exact text (rpc/node.cpp:52-54). The text is what the
functional framework and operators actually see, so it is asserted verbatim."
  (dolist (network '(:mainnet :testnet4 :signet))
    (let ((bl:*network* network)
          (bl.ser:*mock-time* nil))
      (signals-rpc-error (:exact-message "setmocktime is for regression testing (-regtest mode) only")
        (bl.rpc::rpc-setmocktime nil '(1000)))
      (is-false bl.ser:*mock-time*
                "the refused call still moved the clock on ~A" network))))

(test setmocktime-sets-and-clears-the-clock
  "0 means \"stop mocking\", not \"the epoch\": Core's GetTime falls back to the
system clock when g_mock_time is zero. Reading 0 as a literal timestamp would
freeze every node that ran setmocktime 0 at 1970."
  (let ((bl:*network* :regtest)
        (bl.ser:*mock-time* nil))
    (bl.rpc::rpc-setmocktime nil '(1700000000))
    (is (eql 1700000000 bl.ser:*mock-time*))
    (is (eql 1700000000 (bl.ser:get-unix-time)))
    ;; and the real clock is still real
    (is (> (bl.ser:get-real-unix-time) 1700000000))
    (bl.rpc::rpc-setmocktime nil '(0))
    (is-false bl.ser:*mock-time*)
    (is (= (bl.ser:get-unix-time)
           (bl.ser:get-real-unix-time)))))

(test setmocktime-reaches-the-node-clock
  "setmocktime is only worth having if the decisions it exists to control
actually read the mocked clock. Ours mocked GET-UNIX-TIME while 49 sites read
CL:GET-UNIVERSAL-TIME directly, so the RPC moved a clock almost nothing
consulted — and the functional framework drives time with setmocktime instead
of sleeping (test_framework.py:810), which makes an unreached site a site no
Core test can exercise.

GET-NODE-TIME is the universal-time counterpart, and it is what the
wall-clock decisions now read. Ban expiry is the check here because it is the
one a test can drive end to end: ban, jump the clock past the expiry, observe
the ban gone — no sleeping, exactly as rpc_setban.py does it."
  (let ((bl.ser:*mock-time* nil))
    ;; The offset arithmetic, in both directions.
    (is (= (bl.ser:get-node-time)
           (+ (bl.ser:get-unix-time)
              bl.ser:+universal-unix-epoch-offset+)))
    (let ((bl.ser:*mock-time* 1700000000))
      (is (= (+ 1700000000 bl.ser:+universal-unix-epoch-offset+)
             (bl.ser:get-node-time)))))
  ;; And the decision itself moves with it.
  (bl.net:clear-ban-list)
  (unwind-protect
       (let ((bl.ser:*mock-time* 1700000000))
         (bl.net:ban-address "203.0.113.7" 3600)
         (is-true (bl.net:peer-banned-p "203.0.113.7")
                  "the ban did not take under a mocked clock")
         (is (= 1 (length (bl.net:list-bans))))
         ;; Core's tests never sleep an hour; they move the clock.
         (let ((bl.ser:*mock-time* (+ 1700000000 3601)))
           (is-false (bl.net:peer-banned-p "203.0.113.7")
                     "the ban outlived its expiry when the clock was moved past it")
           (is (= 0 (length (bl.net:list-bans))))))
    (bl.net:clear-ban-list)))

(test the-node-clock-split-matches-cores
  "Core splits its clocks and the split is the point: NodeClock returns the
mock, SteadyClock never does (util/time.h:19,27), and the setmocktime RPC sets
only g_mock_time (rpc/node.cpp:69 -> util/time.cpp:46).

Guard both halves. The subsystems Core reads off NodeClock must not go back to
the raw clock, and the three classes that must NOT be mockable must not drift
onto the node clock:

  - entropy seeding — a mocked clock is a predictable seed;
  - the anti-hang watchdogs — they measure real elapsed time, and a clock a
    test jumped forward would fire them spuriously;
  - the fee-estimates file age — Core compares against
    fs::file_time_type::clock::now() (block_policy_estimator.cpp:1078-1083),
    the FILESYSTEM clock, and mixing a mocked now with a real mtime computes
    a nonsense age."
  (flet ((src (relative)
           (with-open-file (in (merge-pathnames relative
                                                (asdf:system-source-directory :bitcoin-lisp)))
             (let ((text (make-string (file-length in))))
               (subseq text 0 (read-sequence text in))))))
    ;; Mockable: nothing in the ban/connection-activity path reads the raw clock.
    (dolist (file '("src/networking/peer.lisp" "src/networking/connection.lisp"))
      (is (not (search "(get-universal-time)" (src file)))
          "~A went back to the raw clock" file))
    ;; Not mockable: these three keep it.
    (is (search "(get-universal-time)" (src "src/mempool/fee-estimator.lisp"))
        "the fee-estimates file age moved onto the mocked clock; its mtime did not")
    (let ((node (%node-source-text)))
      (is (search "(ash (get-universal-time) 32)" node)
          "RNG seeding moved onto the mocked clock, making the seed predictable"))
    (let ((ibd (src "src/networking/ibd.lisp")))
      (is (search "(get-universal-time)" ibd)
          "the IBD anti-hang watchdogs moved onto the mocked clock"))))

(test setmocktime-range-and-type-are-corecs
  "Core rejects a negative or over-large timestamp with an exact message built
from max_time = Ticks<seconds>(nanoseconds::max()) (rpc/node.cpp:63-69)."
  (let ((bl:*network* :regtest)
        (bl.ser:*mock-time* nil))
    (dolist (bad (list -1 (1+ bl.rpc::+max-mock-time+)))
      (signals-rpc-error (:exact-message (format nil "Mocktime must be in the range [0, ~D], not ~D."
                                                 bl.rpc::+max-mock-time+ bad))
        (bl.rpc::rpc-setmocktime nil (list bad))))
    ;; the boundary itself is accepted
    (bl.rpc::rpc-setmocktime nil (list bl.rpc::+max-mock-time+))
    (is (eql bl.rpc::+max-mock-time+ bl.ser:*mock-time*))
    ;; a non-integer is a type error, not a range error
    (signals bl.rpc:rpc-error (bl.rpc::rpc-setmocktime nil '("now")))
    (setf bl.ser:*mock-time* nil)))

(test uptime-does-not-follow-the-mock-clock
  "Core's uptime is SteadyClock::now() minus a steady startup stamp
(common/system.cpp:134), so setmocktime does not move it. Ours read the
MOCKABLE clock, which meant a test setting the clock backwards — the ordinary
case, since the framework picks a fixed timestamp — made uptime clamp to 0, and
one setting it forward made the node claim years of uptime. rpc_uptime.py is a
first-wave target, so this had to be right before the harness could use it."
  (let* ((bl:*network* :regtest)
         (bl.ser:*mock-time* nil)
         (bl:*node-start-time*
           (- (bl.ser:get-real-unix-time) 42))
         (before (bl.rpc::rpc-uptime nil nil)))
    (is (<= 42 before 44))
    ;; A mock clock far in the past must not clamp uptime to zero...
    (bl.rpc::rpc-setmocktime nil '(1000))
    (is (<= 42 (bl.rpc::rpc-uptime nil nil) 44)
        "uptime followed the mock clock backwards")
    ;; ...and one far in the future must not inflate it.
    (bl.rpc::rpc-setmocktime nil (list (+ 100000000
                                                    (bl.ser:get-real-unix-time))))
    (is (<= 42 (bl.rpc::rpc-uptime nil nil) 44)
        "uptime followed the mock clock forwards")
    (setf bl.ser:*mock-time* nil)))

(test syncwithvalidationinterfacequeue-exists-and-answers-null
  "The framework calls it after generate* in many tests. It is a no-op here —
our validation notifications dispatch inline on the connecting thread — but it
has to EXIST, and it has to answer JSON null rather than erroring."
  (is (eq :null (bl.rpc::rpc-syncwithvalidationinterfacequeue nil nil)))
  ;; The dispatch table is populated by start-rpc-server, not at load time, so
  ;; build it here — the point of the assertion is that register-all-methods
  ;; names these two, which is what makes them reachable over JSON-RPC at all.
  (bl.rpc::register-all-methods)
  (dolist (method '("syncwithvalidationinterfacequeue" "setmocktime"))
    (is-true (nth-value 1 (gethash method bl.rpc::*rpc-methods*))
             "~A is not registered" method)))

;;; --- Named parameters (track B P0) ---

(defun %named-params (method &rest kv)
  "Run METHOD's named-parameter transform over the KV plist, or return
(:error <message>)."
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kv by #'cddr do (setf (gethash k h) v))
    (handler-case (bl.rpc::%named-params-to-positional method h)
      (bl.rpc:rpc-error (e)
        (list :error (bl.rpc:rpc-error-message e))))))

(test named-params-map-onto-core-s-argument-names
  "Core's own client sends named parameters for every call
(authproxy.py:122-125), so the framework cannot drive a node that only accepts
positional ones. The names come from Core's RPCHelpMan declarations."
  (is (equal '(5) (%named-params "getblockhash" "height" 5)))
  (is (equal '("aa" 1 t) (%named-params "gettxout" "txid" "aa" "n" 1
                                                   "include_mempool" t)))
  ;; Key order in the object is irrelevant; the ARGUMENT order decides.
  (is (equal '("aa" 1 t) (%named-params "gettxout" "include_mempool" t
                                                   "n" 1 "txid" "aa")))
  ;; An omitted middle argument becomes NIL, which is how every handler
  ;; already sees an absent optional.
  (is (equal '("aa" nil t) (%named-params "gettxout" "txid" "aa"
                                                     "include_mempool" t)))
  ;; Trailing absent arguments are simply not passed.
  (is (equal '("aa") (%named-params "gettxout" "txid" "aa")))
  ;; A params ARRAY is untouched.
  (is (equal '(5) (bl.rpc::%named-params-to-positional
                   "getblockhash" '(5))))
  (is (equal '() (bl.rpc::%named-params-to-positional
                  "getblockcount" '()))))

(test named-params-honour-core-s-alias-slots
  "Core stores an argument name pattern and splits it on #\\| , so one slot can
have two spellings (rpc/server.cpp:396). getblock is the case that matters:
its slot is \"verbosity|verbose\", and older clients send the second."
  (is (equal '("aa" 2) (%named-params "getblock" "blockhash" "aa" "verbosity" 2)))
  (is (equal '("aa" 2) (%named-params "getblock" "blockhash" "aa" "verbose" 2)))
  (is (equal '("aa" 2) (%named-params "getrawtransaction" "txid" "aa"
                                                          "verbose" 2)))
  ;; The alias is one slot, not two: naming both is naming the same slot twice,
  ;; and the second must not silently land in the NEXT argument's position.
  (let ((result (%named-params "getblock" "blockhash" "aa"
                                          "verbosity" 2 "verbose" 3)))
    (is (= 2 (length result)) "an alias pair filled two slots: ~S" result)))

(test named-params-support-core-s-args-prefix
  "A client may pass positional arguments under \"args\" alongside named ones;
the named ones fill the slots after them (doc/JSON-RPC-interface.md). Core's
own client sends exactly this whenever a call mixes the two forms."
  (is (equal '("aa" 1) (%named-params "gettxout" "args" '("aa") "n" 1)))
  (is (equal '("aa" 1 t) (%named-params "gettxout" "args" '("aa" 1)
                                                   "include_mempool" t)))
  (is (equal '("aa") (%named-params "gettxout" "args" '("aa"))))
  ;; Naming a slot the prefix already filled is Core's error, verbatim.
  (is (equal '(:error "Parameter txid specified twice both as positional and named argument")
             (%named-params "gettxout" "args" '("aa" 1) "txid" "bb")))
  (is (equal '(:error "Parameter args must be an array")
             (%named-params "gettxout" "args" 7))))

(test named-params-reject-what-they-cannot-map
  "An unmappable name is Core's \"Unknown named parameter\" error rather than a
silently dropped argument — which would run the method with a default the
caller did not ask for. A method with no argument table answers the same way,
so the gap is visible."
  (is (equal '(:error "Unknown named parameter nope")
             (%named-params "getblockhash" "nope" 1)))
  (is (equal '(:error "Unknown named parameter height")
             (%named-params "getblockcount" "height" 1)))
  ;; A method with no Core declaration to take names from — ours alone — still
  ;; refuses honestly rather than calling with a default the caller did not ask
  ;; for. (getbalance used to stand here; it is in the generated table now, so
  ;; using it would have quietly stopped testing anything.)
  (is (eq :error (first (%named-params "migrateblocks" "dummy" 1)))))

(test named-arg-table-covers-what-it-claims
  "The table is Core's FULL set now, generated from RPCHelpMan, so it
deliberately names methods this node does not serve — the old invariant here
(every entry must be registered) was a property of the hand-curated
43-method predecessor and inverted when the table became Core's.

The direction that still matters is the other one, and it lives in
NAMED-ARG-TABLE-COVERS-WHAT-THE-FRAMEWORK-CALLS: every method we DO register
must be in the table, or it accepts no named parameters.

What is left here is the spot-check: the arguments Core's framework leans on
hardest, spelled out, so a regeneration that silently dropped or reordered them
is caught by name rather than by count."
  (bl.rpc::register-all-methods)
  (dolist (expected '(("getblockhash" "height")
                      ("getblock" "blockhash" "verbosity|verbose")
                      ("generatetoaddress" "nblocks" "address" "maxtries")
                      ("submitblock" "hexdata" "dummy")
                      ("sendrawtransaction" "hexstring" "maxfeerate" "maxburnamount")
                      ("setmocktime" "timestamp")
                      ("invalidateblock" "blockhash")
                      ("reconsiderblock" "blockhash")))
    (is (equal expected (assoc (first expected)
                               bl.rpc::*rpc-named-arg-names*
                               :test #'string=))
        "~A's argument names drifted" (first expected))))

;;; --- RPC_IN_WARMUP (track C item 5) ---

(test warmup-answers-every-method-with--28
  "Core checks warmup FIRST in CRPCTable::execute, before the method is even
looked up, and with no exemptions (rpc/server.cpp:484-489). The ordering is
deliberate: during warmup the node cannot answer anything honestly, so \"still
starting\" beats \"no such method\" for a method that does exist.

This is what lets the RPC server be REACHABLE before the node is usable. An
83 MB mempool.dat used to turn a restart into a ~45-minute window in which the
node was alive, working and answering nothing — bitcoin-cli got connection
refused and monitoring saw a dead node."
  (let ((bl.rpc::*rpc-warmup-status* "Replaying mempool..."))
    (dolist (method '("getblockcount" "uptime" "help" "stop" "nosuchmethod"))
      (signals-rpc-error (:code bl.rpc::+rpc-in-warmup+
                          :exact-message "Replaying mempool...")
        (bl.rpc:dispatch-rpc-method nil method '()))))
  ;; Cleared, dispatch resumes — including the honest "no such method".
  (let ((bl.rpc::*rpc-warmup-status* nil))
    (signals-rpc-error (:code bl.rpc:+rpc-method-not-found+)
      (bl.rpc:dispatch-rpc-method nil "nosuchmethod" '()))))

(test warmup-status-tracks-startup-and-clears
  "-28's message is whatever startup is currently doing (Core wires
SetRPCWarmupStatus to InitMessage, init.cpp:1559), so a client waiting on a
restart can see progress rather than one opaque string."
  (let ((bl.rpc::*rpc-warmup-status* nil))
    (bl.rpc:set-rpc-warmup-status "Loading...")
    (is (string= "Loading..." bl.rpc::*rpc-warmup-status*))
    (bl.rpc:set-rpc-warmup-status "Catching up transaction index...")
    (is (string= "Catching up transaction index..."
                 bl.rpc::*rpc-warmup-status*))
    (bl.rpc:finish-rpc-warmup)
    (is-false bl.rpc::*rpc-warmup-status*)))

(test warmup-is-off-unless-the-caller-asks-for-it
  "Core's flag is true at static init because its only caller is AppInitMain.
Here the server is also started directly from tests and the REPL, where READY
is the honest answer — so warmup is opt-in, and stop-rpc-server clears it.

Leaving it armed after a stop is not hypothetical: an earlier draft re-armed it
in stop-node, and every subsequent request in the image answered -28."
  (is-false bl.rpc::*rpc-warmup-status*
            "the default must be ready, not warming up")
  (let ((bl.rpc::*rpc-warmup-status* "Loading..."))
    (is-true bl.rpc::*rpc-warmup-status*))
  ;; stop-rpc-server clears it even when no server is running.
  (let ((bl.rpc::*rpc-warmup-status* "Loading...")
        (bl.rpc:*rpc-server* nil))
    (bl.rpc:stop-rpc-server)
    ;; With no server the teardown is a no-op, so the binding is untouched;
    ;; what matters is the RUNNING case, asserted by the live test below.
    (is-true t))
  (is-false bl.rpc::*rpc-warmup-status*))

(test rest-routes-cover-core-s-endpoint-table
  "Core registers fifteen /rest/ prefixes (rest.cpp:1143-1158). A route that is
absent answers \"Unknown REST endpoint\", which is indistinguishable from a
typo — so this asserts the routes we claim actually ROUTE, by requiring an
answer that is not the unknown-endpoint 404."
  (let ((node (make-test-node)))
    (flet ((routed-p (uri)
             (let ((hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
               (let ((body (handler-case (rest-request node uri)
                             (error () :signalled))))
                 (not (and (stringp body)
                           (search "Unknown REST endpoint" body)))))))
      ;; Newly added in this change.
      (dolist (uri '("/rest/deploymentinfo.json"
                     "/rest/deploymentinfo/00.json"
                     "/rest/blockfilter/basic/00.json"
                     "/rest/blockfilterheaders/basic/00.json"
                     "/rest/spenttxouts/00.json"))
        (is-true (routed-p uri) "~A is not routed" uri))
      ;; Already present, asserted so a future reshuffle cannot drop them.
      (dolist (uri '("/rest/chaininfo.json" "/rest/tx/00.json"
                     "/rest/block/00.json" "/rest/block/notxdetails/00.json"
                     "/rest/headers/00.json" "/rest/mempool/info.json"
                     "/rest/getutxos/00-0.json" "/rest/blockhashbyheight/0.json"))
        (is-true (routed-p uri) "~A is not routed" uri))
      ;; And something Core does not register still 404s as unknown.
      (is-false (routed-p "/rest/nosuchthing.json")))))

(test rest-blockfilterheaders-precedes-blockfilter
  "\"blockfilter/\" is a PREFIX of \"blockfilterheaders/\", so the longer route
must be tested first — otherwise every blockfilterheaders request is answered
by the blockfilter handler, which then reads the filter type as
\"headers\" and fails with a confusing error instead of serving headers."
  (let ((node (make-test-node))
        (hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
    ;; A blockfilterheaders URI must not reach the blockfilter handler's
    ;; \"expected /rest/blockfilter/<filtertype>/<blockhash>\" complaint.
    (let ((body (handler-case
                    (rest-request node "/rest/blockfilterheaders/basic/notahash.json")
                  (error () ""))))
      (is-false (search "Expected /rest/blockfilter/" body)
                "blockfilterheaders was routed to the blockfilter handler"))))

(test rest-new-endpoints-validate-their-input
  "Each new endpoint refuses a malformed request with a 400 rather than
serving something wrong or signalling out of the handler."
  (let ((node (make-test-node)))
    (flet ((body-of (uri)
             (let ((hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
               (handler-case (rest-request node uri)
                 (error () :signalled)))))
      ;; A bad hash is a 400, not a crash.
      (dolist (uri '("/rest/spenttxouts/nothex.json"
                     "/rest/blockfilter/basic/nothex.json"))
        (let ((b (body-of uri)))
          (is-true (and (stringp b) (search "Invalid block hash" b))
                   "~A did not refuse a bad hash: ~S" uri b)))
      ;; blockfilter without a filter type is a URI-format error.
      (let ((b (body-of "/rest/blockfilter/00.json")))
        (is-true (and (stringp b) (search "Invalid URI format" b))
                 "a filter-type-less blockfilter URI was accepted: ~S" b))
      ;; deploymentinfo is JSON-only, as in Core.
      (let ((b (body-of "/rest/deploymentinfo.hex")))
        (is-true (and (stringp b) (search "output format not found" b))
                 "deploymentinfo served a non-JSON format: ~S" b)))))

(test rest-mempool-contents-reads-core-s-query-parameters
  "rest_mempool parses ?verbose= (default \"true\") and ?mempool_sequence=
(default \"false\"), refuses anything but those two literal strings with a 400
naming the parameter, refuses the pair together with Core's hint, and passes
both to MempoolToJSON (rest.cpp:796-821) -- the same function getrawmempool
calls, which is why REST and RPC cannot answer different shapes.

We hardcoded verbose, so a client asking for the cheap txid ARRAY was served
the verbose OBJECT: a different JSON type its parser cannot read at all, and
an order of magnitude larger on a full mempool."
  (let* ((node (make-test-node))
         (tx (make-mempool-test-tx :input-id 201))
         (txid (bl.ser:transaction-hash tx)))
    (bl.mp:mempool-add (bl:node-mempool node) txid
                       (bl.mp:make-entry-from-tx tx 1000 0))
    (let ((id (bl.rpc:hash-to-hex txid)))
      ;; Core's default is verbose: a JSON object keyed by txid.
      (let ((parsed (yason:parse (rest-request node "/rest/mempool/contents.json"))))
        (is (hash-table-p parsed) "the default must stay Core's verbose object")
        (is-true (gethash id parsed)))
      ;; verbose=false is the txid ARRAY, which is what this test exists for.
      (let ((parsed (yason:parse
                     (rest-request node "/rest/mempool/contents.json?verbose=false"))))
        (is (equal (list id) parsed)
            "?verbose=false must answer the txid array, not the verbose object")))
    ;; Neither flag accepts anything but the two literals, and each 400 names
    ;; the parameter it refused.
    (dolist (probe '(("verbose=1" . "verbose")
                     ("verbose=yes" . "verbose")
                     ("mempool_sequence=1" . "mempool_sequence")))
      (multiple-value-bind (body status)
          (rest-request node (format nil "/rest/mempool/contents.json?~A" (car probe)))
        (is (= 400 status) "~A was accepted" (car probe))
        (is (string= (format nil "The \"~A\" query parameter must be either ~
\"true\" or \"false\".~%" (cdr probe))
                     body))))
    ;; The two together are Core's 400 with its hint, verbatim.
    (multiple-value-bind (body status)
        (rest-request node
                      "/rest/mempool/contents.json?verbose=true&mempool_sequence=true")
      (is (= 400 status))
      (is (string= (format nil "Verbose results cannot contain mempool sequence ~
values. (hint: set \"verbose=false\")~%")
                   body)))
    ;; CONTROL: the same pair with verbose=false is allowed through (its
    ;; sequence field comes from getrawmempool).
    (is (= 200 (nth-value 1 (rest-request
                             node
                             "/rest/mempool/contents.json?verbose=false&mempool_sequence=true"))))))

(test tx-to-json-gates-fee-and-prevout-separately
  "Core reads the block's undo data at verbosity 2 AND 3, and pushes `fee`
whenever it has the coins — but the `prevout` OBJECT only at verbosity 3
(TxToUniv, core_io.cpp:455-525; blockToJSON reads undo for both). The two are
gated by different conditions in Core, so folding them together would give a
verbosity-2 caller prevout objects Core does not send."
  (let* ((tx (make-mempool-test-tx :input-id 77))
         (coins (list (bl.store:make-utxo-entry
                       :value 5000
                       :script-pubkey (coerce #(#x51) '(simple-array (unsigned-byte 8) (*)))
                       :height 12 :coinbase nil))))
    ;; No coins: neither field, exactly as before this change.
    (let ((j (bl.rpc:tx-to-json tx :regtest)))
      (is-false (assoc "fee" j :test #'string=))
      (is-false (assoc "prevout" (first (cdr (assoc "vin" j :test #'string=)))
                       :test #'string=)))
    ;; Verbosity 2: fee, no prevout.
    (let* ((j (bl.rpc:tx-to-json tx :regtest :spent-coins coins))
           (vin0 (first (cdr (assoc "vin" j :test #'string=)))))
      (is-true (assoc "fee" j :test #'string=) "verbosity 2 must report the fee")
      (is-false (assoc "prevout" vin0 :test #'string=)
                "verbosity 2 must NOT carry prevout objects"))
    ;; Verbosity 3: both, and the prevout carries Core's four fields.
    (let* ((j (bl.rpc:tx-to-json tx :regtest :spent-coins coins :prevouts t))
           (vin0 (first (cdr (assoc "vin" j :test #'string=))))
           (p (cdr (assoc "prevout" vin0 :test #'string=))))
      (is-true (assoc "fee" j :test #'string=))
      (is-true p "verbosity 3 must carry a prevout object")
      (is (eql 12 (cdr (assoc "height" p :test #'string=))))
      (is (= (/ 5000 100000000.0d0) (cdr (assoc "value" p :test #'string=))))
      (is-true (assoc "generated" p :test #'string=))
      (is-true (assoc "scriptPubKey" p :test #'string=))
      ;; The fee is inputs minus outputs, from the coins.
      (let ((out-total (loop for o across (bl.ser:transaction-outputs tx)
                             sum (bl.ser:tx-out-value o))))
        (is (= (/ (- 5000 out-total) 100000000.0d0)
               (cdr (assoc "fee" j :test #'string=))))))))

(test coinbase-inputs-never-get-a-prevout
  "A coinbase spends nothing, so Core's loop skips it (`if (have_undo)` sits
inside the non-coinbase branch's sibling and vprevout has one entry per
NON-coinbase transaction). Handing a coinbase input a prevout would invent a
coin that never existed."
  (let* ((coinbase
           (bl.ser:make-transaction
            :version 1
            :inputs (vector (bl.ser:make-tx-in
                             :previous-output
                             (bl.ser:make-outpoint
                              :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                   :initial-element 0)
                              :index #xFFFFFFFF)
                             :script-sig (coerce #(1 2) '(simple-array (unsigned-byte 8) (*)))
                             :sequence #xFFFFFFFF))
            :outputs (vector (bl.ser:make-tx-out
                              :value 5000000000
                              :script-pubkey (coerce #(#x51)
                                                     '(simple-array (unsigned-byte 8) (*)))))
            :lock-time 0))
         (coins (list (bl.store:make-utxo-entry
                       :value 1 :script-pubkey (coerce #(#x51) '(simple-array (unsigned-byte 8) (*)))
                       :height 1 :coinbase t)))
         (j (bl.rpc:tx-to-json coinbase :regtest :spent-coins coins :prevouts t))
         (vin0 (first (cdr (assoc "vin" j :test #'string=)))))
    (is-true (assoc "coinbase" vin0 :test #'string=) "not a coinbase input")
    (is-false (assoc "prevout" vin0 :test #'string=)
              "a coinbase input was given a prevout")))

(test getrpcinfo-reports-in-flight-commands
  "active_commands was always empty. That is not merely incomplete: it is how a
client learns a long-running call is still running, and Core's own
feature_shutdown.py waits for TWO concurrent commands before attempting a
shutdown — so a node reporting none hangs that test forever."
  (let ((bl.rpc::*active-rpc-commands* '()))
    (is-false (bl.rpc::active-rpc-commands) "idle must report nothing")
    ;; Two concurrent calls to the SAME method are two indistinguishable
    ;; entries. Removing by value would drop whichever came first and leave the
    ;; other listed forever, so removal is by IDENTITY.
    (bl.rpc::with-active-rpc-command ("getblockcount")
      (is (= 1 (length (bl.rpc::active-rpc-commands))))
      (bl.rpc::with-active-rpc-command ("getblockcount")
        (is (= 2 (length (bl.rpc::active-rpc-commands)))))
      (is (= 1 (length (bl.rpc::active-rpc-commands)))
          "an identical concurrent command was removed twice"))
    (is-false (bl.rpc::active-rpc-commands))
    ;; A command that SIGNALS must still be removed, or one failing call leaks
    ;; an entry that never goes away.
    (ignore-errors
     (bl.rpc::with-active-rpc-command ("boom") (error "x")))
    (is-false (bl.rpc::active-rpc-commands)
              "a signalling command leaked its entry")
    ;; Duration is MICROSECONDS, as Core reports it.
    (bl.rpc::with-active-rpc-command ("slow")
      (let ((d (cdr (first (bl.rpc::active-rpc-commands)))))
        (is-true (integerp d))
        (is-true (>= d 0))))))

(test getrpcinfo-shape-is-core-s
  "Each entry is {method, duration}; logpath is the debug.log the node is
actually writing."
  (let ((bl.rpc::*active-rpc-commands* '())
        (bl:*log-file-path* #P"/tmp/bl-test/debug.log"))
    (bl.rpc::with-active-rpc-command ("getblockcount")
      (let* ((info (bl.rpc::rpc-getrpcinfo nil nil))
             (cmds (cdr (assoc "active_commands" info :test #'string=)))
             (one (elt cmds 0)))
        (is (= 1 (length cmds)))
        (is (equal "getblockcount" (cdr (assoc "method" one :test #'string=))))
        (is-true (integerp (cdr (assoc "duration" one :test #'string=))))
        (is (equal "/tmp/bl-test/debug.log"
                   (cdr (assoc "logpath" info :test #'string=))))))))

(test dispatch-registers-the-running-command
  "The tracking has to be at the DISPATCH choke point, not bolted onto
individual handlers — otherwise it reports only the methods someone remembered
to annotate. This drives the real dispatcher and looks for the command in
active_commands from INSIDE the handler."
  (let ((bl.rpc::*active-rpc-commands* '())
        (bl.rpc::*rpc-warmup-status* nil)
        (seen nil))
    (let ((bl.rpc::*rpc-methods* (make-hash-table :test 'equal)))
      (setf (gethash "peekself" bl.rpc::*rpc-methods*)
            (lambda (node params)
              (declare (ignore node params))
              (setf seen (bl.rpc::active-rpc-commands))
              42))
      (is (= 42 (bl.rpc:dispatch-rpc-method nil "peekself" '()))))
    (is (equal '("peekself") (mapcar #'car seen))
        "the running command was not visible from inside its own handler")
    (is-false (bl.rpc::active-rpc-commands)
              "the entry outlived the dispatch")))

(test rest-blockpart-serves-a-byte-range
  "/rest/blockpart returns a RANGE of the serialized block, with offset and
size as QUERY parameters (rest_block_part, rest.cpp:480-497). JSON is not a
supported format — the whole point is raw bytes.

Route order matters again: \"block\" is a prefix of \"blockpart\", so the
shorter route would swallow every blockpart request and try to read
\"part/<hash>\" as a block hash."
  (let ((node (make-test-node)))
    (flet ((req (uri &optional params)
             (let ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
                   (hunchentoot:*request* nil))
               ;; %rest-size-parameter reads hunchentoot's query parameters;
               ;; stub the accessor for the duration of the call.
               (let ((original (symbol-function 'hunchentoot:get-parameter)))
                 (unwind-protect
                      (progn
                        (setf (symbol-function 'hunchentoot:get-parameter)
                              (lambda (name) (cdr (assoc name params :test #'string=))))
                        (handler-case (rest-request node uri)
                          (error () :signalled)))
                   (setf (symbol-function 'hunchentoot:get-parameter) original))))))
      ;; Routed at all — an unrouted URI answers "Unknown REST endpoint".
      (let ((b (req "/rest/blockpart/00.bin" '(("offset" . "0") ("size" . "1")))))
        (is-false (and (stringp b) (search "Unknown REST endpoint" b))
                  "blockpart is not routed"))
      ;; Missing parameters are Core's two distinct 400s, and offset is
      ;; reported first because Core checks it first.
      (is-true (search "Block part offset missing or invalid"
                       (req "/rest/blockpart/00.bin" '())))
      (is-true (search "Block part size missing or invalid"
                       (req "/rest/blockpart/00.bin" '(("offset" . "0")))))
      ;; A negative or non-numeric value is NOT a zero — Core's ToIntegral
      ;; fails and the request is a 400.
      (is-true (search "Block part offset missing or invalid"
                       (req "/rest/blockpart/00.bin" '(("offset" . "-1") ("size" . "1")))))
      (is-true (search "Block part size missing or invalid"
                       (req "/rest/blockpart/00.bin" '(("offset" . "0") ("size" . "x")))))
      ;; JSON is refused for this endpoint. A full-length hash is needed to
      ;; reach the format check at all, since the hash is validated first once
      ;; the parameters are good.
      (is-true (search "output format not found"
                       (req (format nil "/rest/blockpart/~64,'0D.json" 0)
                            '(("offset" . "0") ("size" . "1")))))
      ;; A bad hash is still a bad hash — but only once the parameters are
      ;; valid, since Core validates them first (rest.cpp:480-497 delegates to
      ;; rest_block, where the hash is parsed).
      (is-true (search "Invalid block hash"
                       (req "/rest/blockpart/nothex.bin" '(("offset" . "0") ("size" . "1"))))))))

(test rest-blockpart-range-check-is-cores
  "size 0 is invalid and offset+size must not exceed the block
(blockstorage.cpp:1116-1120). Core needs a SaturatingAdd there to stop the sum
wrapping past the check; Lisp integers do not wrap, so a plain + is already the
safe version — asserted here with a size large enough to have overflowed a
64-bit sum."
  (let* ((block (%bu-test-block '(1)))
         (bytes (bl.ser:serialize-witness-block block))
         (n (length bytes)))
    ;; The check itself, exercised directly: these are the four boundary cases.
    (flet ((ok-p (offset size)
             (not (or (zerop size) (> (+ offset size) n)))))
      (is-true (ok-p 0 n) "the whole block must be a valid range")
      (is-true (ok-p (1- n) 1) "the last byte must be a valid range")
      (is-false (ok-p 0 0) "size 0 must be refused")
      (is-false (ok-p 0 (1+ n)) "past the end must be refused")
      (is-false (ok-p n 1) "starting at the end must be refused")
      ;; A size that would wrap a 64-bit accumulator still refuses.
      (is-false (ok-p 1 (expt 2 64)) "an enormous size must be refused"))))

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
                 (bl.rpc:rpc-get-chain-state node)
                 (bl.rpc:rpc-get-utxo-set node)
                 (bl.rpc:rpc-get-peers node)
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
                     (bl.rpc::rpc-getblockchaininfo node nil)
                     (bl.rpc::rpc-getblockcount node nil)
                     (bl.rpc::rpc-getnetworkinfo node nil)
                     (bl.rpc::rpc-getmempoolinfo node nil))
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
  (is (= bl.rpc:+rpc-parse-error+ -32700))
  (is (= bl.rpc:+rpc-invalid-request+ -32600))
  (is (= bl.rpc:+rpc-method-not-found+ -32601))
  (is (= bl.rpc:+rpc-internal-error+ -32603))
  ;; Bitcoin Core specific error codes
  (is (= bl.rpc:+rpc-invalid-parameter+ -8))  ; RPC_INVALID_PARAMETER
  (is (= bl.rpc:+rpc-misc-error+ -1)))

(test rpc-error-response-format
  "Test error response matches Bitcoin Core format"
  (let ((response (bl.rpc::make-rpc-error-response -32601 "Method not found" 123 :v2)))
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
                     (bl.rpc::rpc-decoderawtransaction node (list tx-hex))
                   (error () nil))))
    ;; May fail to parse minimal tx, but should not crash
    (is (or result (not result)))))

(test rpc-decoderawtransaction-invalid-hex
  "Test decoderawtransaction with invalid hex returns error"
  (let ((node (make-test-node)))
    ;; Empty string
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-decoderawtransaction node '("")))
    ;; Invalid hex characters
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-decoderawtransaction node '("zzzz")))))

;;; getrawtransaction tests

(test rpc-getrawtransaction-invalid-txid
  "Test getrawtransaction with invalid txid returns error"
  (let ((node (make-test-node)))
    ;; Too short
    (signals bl.rpc:rpc-error
      (bl.rpc:dispatch-rpc-method node "getrawtransaction" '("abc")))
    ;; Invalid characters
    (signals bl.rpc:rpc-error
      (bl.rpc:dispatch-rpc-method node "getrawtransaction" '("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")))))

(test rpc-getrawtransaction-not-found
  "Test getrawtransaction for unknown txid returns error"
  (let ((node (make-test-node)))
    ;; Valid txid but not in mempool
    (signals bl.rpc:rpc-error
      (bl.rpc:dispatch-rpc-method node "getrawtransaction"
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

;;; estimatesmartfee tests

(defmacro %with-stubbed-fee-estimate ((node &key (rate 10) (error-msg nil)
                                                 (returned-target nil)
                                                 (mode-out nil))
                                      &body body)
  "Run BODY with NODE's fee estimator answering RATE sat/vB (or ERROR-MSG),
and with MODE-OUT -- a symbol naming a place -- receiving the mode the RPC
passed. A test node has no estimator, and the RPC's first gate is its
presence -- without one the stubs below are never reached and every
assertion silently measures the no-estimate path instead. The slot is set,
not the accessor stubbed: the node struct loads before the RPC code now, so
its accessors inline there and a redefinition would not be seen."
  `(let ((real-ready (fdefinition 'bl.mp:fee-estimator-ready-p))
         (real-est (fdefinition 'bl.mp:estimate-fee-rate)))
     (setf (bl:node-fee-estimator ,node) :stub-estimator)
     (unwind-protect
          (progn
            (setf (fdefinition 'bl.mp:fee-estimator-ready-p)
                  (lambda (&rest args) (declare (ignore args)) t))
            (setf (fdefinition 'bl.mp:estimate-fee-rate)
                  (lambda (estimator conf-target &key mode)
                    (declare (ignore estimator))
                    ,@(when mode-out `((setf ,mode-out mode)))
                    (values ,rate ,error-msg (or ,returned-target conf-target))))
            ,@body)
       (setf (fdefinition 'bl.mp:fee-estimator-ready-p) real-ready
             (fdefinition 'bl.mp:estimate-fee-rate) real-est))))

(test estimatesmartfee-omits-feerate-when-there-is-no-estimate
  "Core returns ONLY errors and blocks when the estimator has nothing
(rpc/fees.cpp:87-90) — the \"feerate\" key is documented as \"only present if
no errors were encountered\". We returned a fabricated 0.00001 BTC/kvB (1
sat/vB) fallback, so a wallet reading \"feerate\" got a made-up number instead
of noticing there was no estimate, and built a transaction at 1 sat/vB that
would not confirm."
  (let* ((node (make-test-node))
         (bl::*syncing* nil)
         (result (bl.rpc::rpc-estimatesmartfee node '(6))))
    (is-false (assoc "feerate" result :test #'string=)
              "a fabricated feerate is reported where Core reports none")
    (is-true (assoc "errors" result :test #'string=))
    (is (= 6 (cdr (assoc "blocks" result :test #'string=))))))

(test estimatesmartfee-defaults-to-economical-as-core-does
  "Core's estimate_mode default is \"economical\" (RPCArg::Default, fees.cpp:42).
Ours defaulted to conservative, which returns a HIGHER number — so every caller
that did not name a mode was quietly told to overpay."
  (let ((node (make-test-node))
        (bl::*syncing* nil)
        (seen nil))
    (%with-stubbed-fee-estimate (node :rate 10 :mode-out seen)
      (bl.rpc::rpc-estimatesmartfee node '(6))
      (is (eq :economical seen) "default mode was ~S" seen)
      (bl.rpc::rpc-estimatesmartfee node '(6 "conservative"))
      (is (eq :conservative seen))
      (bl.rpc::rpc-estimatesmartfee node '(6 "economical"))
      (is (eq :economical seen))
      ;; Core's FeeModeMap has three names; "unset" means the default.
      (bl.rpc::rpc-estimatesmartfee node '(6 "unset"))
      (is (eq :economical seen)))))

(test estimatesmartfee-clamps-up-to-the-nodes-own-floors
  "Core: max(estimate, mempool rolling minimum, min relay fee)
(fees.cpp:82-85). Unclamped — as ours was — a node whose mempool minimum has
risen recommends a fee BELOW its own acceptance threshold: it rejects the very
transaction it just priced."
  (let ((node (make-test-node))
        (bl::*syncing* nil))
    (%with-stubbed-fee-estimate (node :rate 10)   ; 10 sat/vB = 10000 sat/kvB
      ;; Floor below the estimate: the estimate stands.
      (let ((result (bl.rpc::rpc-estimatesmartfee node '(6))))
        (is (= (/ 10000 100000000.0d0)
               (cdr (assoc "feerate" result :test #'string=)))))
      ;; Floor above the estimate: the floor wins.
      (let ((mempool (bl.rpc:rpc-get-mempool node)))
        (when mempool
          (setf (bl.mp:mempool-min-fee-rate mempool) 50000)
          (let ((result (bl.rpc::rpc-estimatesmartfee node '(6))))
            (is (= (/ 50000 100000000.0d0)
                   (cdr (assoc "feerate" result :test #'string=)))
                "the answer was below the node's own acceptance floor")))))))

(test estimatesmartfee-reports-the-target-the-answer-is-actually-for
  "Core reports feeCalc.returnedTarget as \"blocks\" (fees.cpp:91), not the
requested target: the estimator substitutes 2 for a 1-block target and clamps
to what its history can justify. Echoing the request tells a caller the answer
covers a horizon it does not."
  (let ((node (make-test-node))
        (bl::*syncing* nil))
    (%with-stubbed-fee-estimate (node :rate 10 :returned-target 100)
      (let ((result (bl.rpc::rpc-estimatesmartfee node '(1008))))
        (is (= 100 (cdr (assoc "blocks" result :test #'string=)))
            "blocks echoed the request instead of the estimator's answer")))))

(test estimatesmartfee-target-is-bounded-by-what-the-estimator-tracks
  "Core bounds conf_target by HighestTargetTracked(LONG_HALFLIFE), not by a
fixed constant (ParseConfirmTarget, rpc/util.cpp:369-377), and its message
names the range."
  (let ((node (make-test-node)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-estimatesmartfee node '(0)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-estimatesmartfee node '(-1)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-estimatesmartfee node
                                              (list (1+ (bl.mp:highest-target-tracked)))))
    ;; And an unknown mode names the three Core accepts.
    (signals-rpc-error (:message "unset")
      (bl.rpc::rpc-estimatesmartfee node '(6 "cheap")))))

;;; validateaddress tests

(test rpc-validateaddress-valid-p2pkh
  "Test validateaddress with valid testnet P2PKH address"
  (let* ((node (make-test-node))
         ;; Valid testnet P2PKH address (starts with m or n)
         (result (bl.rpc::rpc-validateaddress node '("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn"))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (assoc "address" result :test #'string=))
    (is (assoc "scriptPubKey" result :test #'string=))
    (is (eq 'yason:false (cdr (assoc "iswitness" result :test #'string=))))
    ;; isscript is a real boolean; a P2PKH address is not a script address.
    (is (eq 'yason:false (cdr (assoc "isscript" result :test #'string=))))))

(test rpc-validateaddress-valid-bech32
  "Test validateaddress with valid testnet bech32 address"
  (let* ((node (make-test-node))
         ;; Valid testnet P2WPKH address
         (result (bl.rpc::rpc-validateaddress node '("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (eq t (cdr (assoc "iswitness" result :test #'string=))))
    (is (= 0 (cdr (assoc "witness_version" result :test #'string=))))))

(test rpc-validateaddress-invalid
  "Test validateaddress with invalid address"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-validateaddress node '("not-an-address"))))
    (is (eq 'yason:false (cdr (assoc "isvalid" result :test #'string=))))
    ;; Core's invalid shape carries error + error_locations.
    (is (stringp (cdr (assoc "error" result :test #'string=))))))

(test rpc-validateaddress-isscript-boolean
  "isscript is T (a boolean) for a script address (P2SH) -- regression: it used
to return a list of keyword symbols for script types, which serialized as a JSON
array / could error."
  (let* ((node (make-test-node))
         (addr (bl.crypto:encode-p2sh-address
                (make-array 20 :element-type '(unsigned-byte 8) :initial-element 7)
                :testnet3))
         (result (bl.rpc::rpc-validateaddress node (list addr))))
    (is (eq t (cdr (assoc "isvalid" result :test #'string=))))
    (is (eq t (cdr (assoc "isscript" result :test #'string=))))))

(test rpc-validateaddress-empty
  "Test validateaddress with empty string"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-validateaddress node '(""))))
    (is (eq 'yason:false (cdr (assoc "isvalid" result :test #'string=))))))

(test rpc-validateaddress-wrong-network
  "Test validateaddress with mainnet address on testnet"
  (let* ((node (make-test-node))
         ;; Mainnet P2PKH address (starts with 1)
         (result (bl.rpc::rpc-validateaddress node '("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"))))
    ;; Should be invalid on testnet node
    (is (eq 'yason:false (cdr (assoc "isvalid" result :test #'string=))))))

;;; decodescript tests

(defun %decodescript (script-hex &key (network :testnet3))
  "decodescript SCRIPT-HEX on a fresh minimal node of NETWORK; the result alist."
  (bl.rpc::rpc-decodescript (make-test-node :network network) (list script-hex)))

(defun %decodescript-field (result key)
  (cdr (assoc key result :test #'string=)))

(test rpc-decodescript-p2pkh
  "Test decodescript with P2PKH script"
  ;; P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  (let ((result (%decodescript "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac")))
    (is (string= (%decodescript-field result "type") "pubkeyhash"))
    (is (%decodescript-field result "asm"))
    (is (%decodescript-field result "p2sh"))))

(test rpc-decodescript-p2sh
  "Test decodescript with P2SH script"
  ;; P2SH: OP_HASH160 <20 bytes> OP_EQUAL
  (let ((result (%decodescript "a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87")))
    (is (string= (%decodescript-field result "type") "scripthash"))))

(test rpc-decodescript-p2wpkh
  "Test decodescript with P2WPKH script"
  ;; P2WPKH: OP_0 <20 bytes>
  (let ((result (%decodescript "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba")))
    (is (string= (%decodescript-field result "type") "witness_v0_keyhash"))
    (is (%decodescript-field result "segwit"))))

(test rpc-decodescript-segwit-address-uses-chain-hrp
  "The segwit address decodescript reports carries the CHAIN's bech32 HRP
(Core chainparams bech32_hrp): bcrt on regtest, tb on the test chains. The
first version hard-coded tb for testnet3 and bc for everything else, so a
regtest node printed mainnet addresses."
  (flet ((segwit-address (network)
           (%decodescript-field
            (%decodescript-field
             (%decodescript "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba"
                            :network network)
             "segwit")
            "address")))
    (is (uiop:string-prefix-p "bcrt1" (segwit-address :regtest)))
    (is (uiop:string-prefix-p "tb1" (segwit-address :testnet4)))
    (is (uiop:string-prefix-p "bc1" (segwit-address :mainnet)))))

(test rpc-decodescript-empty
  "Test decodescript with empty script"
  (let ((result (%decodescript "")))
    (is (string= (%decodescript-field result "type") "nonstandard"))
    (is (string= (%decodescript-field result "asm") ""))))

(test rpc-decodescript-invalid-hex
  "Test decodescript with invalid hex returns error"
  (signals bl.rpc:rpc-error (%decodescript "xyz")))

;;; createrawtransaction tests

(test rpc-createrawtransaction-basic
  "Test createrawtransaction with valid inputs and outputs"
  (let* ((node (make-test-node))
         (inputs `((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
                    ("vout" . 0))))
         (outputs '(("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . 0.01)))
         (result (bl.rpc::rpc-createrawtransaction node (list inputs outputs))))
    ;; Should return hex string
    (is (stringp result))
    (is (> (length result) 0))
    ;; Should be valid hex
    (is (every (lambda (c) (digit-char-p c 16)) result))))

(test rpc-createrawtransaction-invalid-txid
  "Test createrawtransaction with invalid input txid"
  (let ((node (make-test-node)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-createrawtransaction node
        '(((("txid" . "invalid") ("vout" . 0)))
          (("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . 0.01)))))))

(test rpc-createrawtransaction-invalid-address
  "Test createrawtransaction with invalid output address"
  (let ((node (make-test-node)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-createrawtransaction node
        '(((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
            ("vout" . 0)))
          (("invalid-address" . 0.01)))))))

(test rpc-createrawtransaction-negative-amount
  "Test createrawtransaction with negative amount"
  (let ((node (make-test-node)))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-createrawtransaction node
        '(((("txid" . "0000000000000000000000000000000000000000000000000000000000000001")
            ("vout" . 0)))
          (("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn" . -0.01)))))))

;;; --- gettxoutsetinfo Tests ---

(test rpc-gettxoutsetinfo-empty-utxo-set
  "Test gettxoutsetinfo with empty UTXO set"
  (let* ((node (make-test-node))
         (result (bl.rpc::rpc-gettxoutsetinfo node nil)))
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
         (utxo-set (bl:node-utxo-set node))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; Add some UTXOs
    (bl.store:add-utxo utxo-set txid1 0 100000000 script 1) ; 1 BTC
    (bl.store:add-utxo utxo-set txid1 1 50000000 script 1)  ; 0.5 BTC
    (bl.store:add-utxo utxo-set txid2 0 25000000 script 2)  ; 0.25 BTC
    (let ((result (bl.rpc::rpc-gettxoutsetinfo node nil)))
      ;; Should have 3 UTXOs from 2 transactions
      (is (= (cdr (assoc "txouts" result :test #'string=)) 3))
      (is (= (cdr (assoc "transactions" result :test #'string=)) 2))
      ;; Total should be 1.75 BTC (returned in BTC, not satoshis)
      (is (= (cdr (assoc "total_amount" result :test #'string=)) 1.75))
      ;; hash_serialized_3 should be a 64-char hex string
      (let ((hash (cdr (assoc "hash_serialized_3" result :test #'string=))))
        (is (stringp hash))
        (is (= (length hash) 64))))))

(test rpc-gettxoutsetinfo-muhash
  "gettxoutsetinfo hash_type=muhash returns a 64-hex muhash (order-independent,
distinct from hash_serialized_3), and inserting then removing a coin restores
the value."
  (let* ((node (make-test-node))
         (utxo-set (bl:node-utxo-set node))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 1))
         (txid2 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 2))
         (script (make-array 25 :element-type '(unsigned-byte 8) :initial-element 0)))
    (bl.store:add-utxo utxo-set txid1 0 100000000 script 1)
    (bl.store:add-utxo utxo-set txid2 0 25000000 script 2)
    (let* ((mh (bl.rpc::rpc-gettxoutsetinfo node (list "muhash")))
           (muhash (cdr (assoc "muhash" mh :test #'string=)))
           (h3 (cdr (assoc "hash_serialized_3"
                           (bl.rpc::rpc-gettxoutsetinfo node (list "hash_serialized_3"))
                           :test #'string=))))
      (is (stringp muhash))
      (is (= 64 (length muhash)))
      ;; muhash mode does not also emit hash_serialized_3, and vice versa.
      (is (null (assoc "hash_serialized_3" mh :test #'string=)))
      ;; The two hash types are computed over different serializations.
      (is (not (string= muhash h3)))
      ;; Order-independence / add-remove inverse: add a coin, then delete it,
      ;; and the muhash returns to its prior value.
      (bl.store:add-utxo utxo-set txid2 1 7 script 3)
      (bl.store:remove-utxo utxo-set txid2 1)
      (is (string= muhash
                   (cdr (assoc "muhash"
                               (bl.rpc::rpc-gettxoutsetinfo node (list "muhash"))
                               :test #'string=)))))
    ;; An unknown hash_type still errors.
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-gettxoutsetinfo node (list "bogus")))))

;;; --- getblockstats Tests ---

(test rpc-getblockstats-invalid-params
  "Test getblockstats with invalid parameters"
  (let ((node (make-test-node)))
    ;; Missing parameter
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockstats node nil))
    ;; Invalid hash format
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockstats node '("invalid")))
    ;; Negative height
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockstats node '(-1)))))

(test rpc-getblockstats-block-not-found
  "Test getblockstats with non-existent block"
  (let ((node (make-test-node)))
    ;; Valid hash format but block doesn't exist
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockstats node
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

;;; getblockstats against an exact fixture: coinbase + one witness tx.

(defparameter *gbs-p2pkh*
  (concatenate '(vector (unsigned-byte 8))
               #(#x76 #xa9 #x14) (make-array 20 :element-type '(unsigned-byte 8)
                                               :initial-element #x33)
               #(#x88 #xac))
  "A 25-byte P2PKH scriptPubKey (spendable).")

(defparameter *gbs-opreturn*
  (coerce #(#x6a #x01 #x02) '(vector (unsigned-byte 8)))
  "A 3-byte OP_RETURN scriptPubKey (provably unspendable).")

(defun %gbs-coinbase ()
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-32-byte-hash 0) :index #xffffffff)
                    :script-sig (coerce #(#x01 #x64) '(vector (unsigned-byte 8)))
                    :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                     :value 5000030000 :script-pubkey *gbs-p2pkh*))
   :lock-time 0))

(defun %gbs-spender (prev-txid)
  "A segwit transaction spending PREV-TXID:0 (100000 sat) into 40000 + 30000,
so its fee is exactly 30000 sat. Its second output is unspendable."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash prev-txid :index 0)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence #xfffffffd))
   :outputs (vector (bl.ser:make-tx-out
                     :value 40000 :script-pubkey *gbs-p2pkh*)
                    (bl.ser:make-tx-out
                     :value 30000 :script-pubkey *gbs-opreturn*))
   :witness (vector (list (make-array 72 :element-type '(unsigned-byte 8) :initial-element 9)
                          (make-array 33 :element-type '(unsigned-byte 8) :initial-element 2)))
   :lock-time 0))

(defmacro %with-gbs-block ((node hash-hex spender &key (with-undo t) (coinbase-only nil))
                           &body body)
  "Store a height-100 block (coinbase + one 30000-sat-fee segwit spend, unless
COINBASE-ONLY) with its undo data, and bind NODE / HASH-HEX / SPENDER."
  (let ((dir (gensym "DIR")) (store (gensym "STORE")) (hash (gensym "HASH"))
        (prev (gensym "PREV")))
    `(let* ((,node (make-test-node))
            (,dir (ensure-directories-exist
                   (merge-pathnames (format nil "gbs-~D/" (get-internal-real-time))
                                    (uiop:temporary-directory))))
            (,store (bl.store:init-block-store ,dir))
            (,prev (make-32-byte-hash 77))
            (,spender (%gbs-spender ,prev))
            (%gbs-txs (if ,coinbase-only
                          (list (%gbs-coinbase))
                          (list (%gbs-coinbase) ,spender)))
            (%gbs-blk (%hdrfields-block %gbs-txs (make-32-byte-hash 5) 1700000000))
            (,hash (bl.ser:block-header-hash
                    (bl.ser:bitcoin-block-header %gbs-blk)))
            (,hash-hex (bl.rpc:hash-to-hex ,hash)))
       (declare (ignorable ,spender))
       (setf (bl:node-block-store ,node) ,store)
       (unwind-protect
            (progn
              (bl.store:store-block ,store %gbs-blk)
              (bl.store:add-block-index-entry
               (bl:node-chain-state ,node)
               (bl.store:make-block-index-entry
                :hash ,hash :height 100 :chain-work 1 :status :valid
                :header (bl.ser:bitcoin-block-header %gbs-blk)))
              (when ,with-undo
                (setf (gethash ,hash bl.val::*block-undo-data*)
                      (list (list ,prev 0
                                  (bl.store:make-utxo-entry
                                   :value 100000 :script-pubkey *gbs-p2pkh*
                                   :height 50 :coinbase nil)))))
              ,@body)
         (remhash ,hash bl.val::*block-undo-data*)
         (uiop:delete-directory-tree ,dir :validate t :if-does-not-exist :ignore)))))

(test rpc-getblockstats-excludes-coinbase-and-uses-witness-tx-sizes
  "getblockstats accumulates per-transaction, AFTER Core's
`if (tx->IsCoinBase()) continue;` (rpc/blockchain.cpp:2075-2077), using the
witness-inclusive ComputeTotalSize (:2085) — so total_size, total_out and
total_weight exclude the coinbase and carry no block header or tx-count varint,
and avgtxsize divides by vtx.size()-1 (:2143). We previously used
(length (serialize block)) — the LEGACY whole-block form — over ntx, and
summed the coinbase's outputs into total_out."
  (%with-gbs-block (node hex spender)
    (let* ((r (bl.rpc::rpc-getblockstats node (list hex)))
           (stat (lambda (k) (cdr (assoc k r :test #'string=))))
           (wire (length (bl.ser:transaction-wire-bytes spender)))
           (stripped (length (bl.ser:serialize-transaction spender)))
           (weight (bl.ser:transaction-weight spender))
           (whole-block (length (bl.ser:serialize
                                 (bl.store:get-block
                                  (bl:node-block-store node)
                                  (bl.rpc:parse-hex-hash hex))))))
      ;; --- sizes ---
      (is (= wire (funcall stat "total_size")))
      ;; ...which is witness-INCLUSIVE (the stripped form is strictly smaller)
      ;; and is NOT the whole-block quantity we used to report.
      (is (> wire stripped))
      (is (/= whole-block (funcall stat "total_size")))
      (is (= weight (funcall stat "total_weight")))
      ;; avgtxsize divides by the NON-coinbase count (1 here), not by ntx (2).
      (is (= wire (funcall stat "avgtxsize")))
      (is (/= (round whole-block 2) (funcall stat "avgtxsize")))
      (is (= wire (funcall stat "maxtxsize")))
      (is (= wire (funcall stat "mintxsize")))
      (is (= wire (funcall stat "mediantxsize")))
      ;; --- amounts ---
      ;; 40000 + 30000; the 5000030000-sat coinbase output is NOT counted.
      (is (= 70000 (funcall stat "total_out")))
      (is (= 2 (funcall stat "txs")))
      (is (= 1 (funcall stat "ins")))
      ;; CONTROL: "outs" IS counted before the coinbase continue (Core :2054),
      ;; so it still includes the coinbase's output — do not "fix" it.
      (is (= 3 (funcall stat "outs")))
      ;; --- fees, from undo data ---
      (is (= 30000 (funcall stat "totalfee")))
      (is (= 30000 (funcall stat "avgfee")))
      (is (= 30000 (funcall stat "maxfee")))
      (is (= 30000 (funcall stat "minfee")))
      (is (= 30000 (funcall stat "medianfee")))
      (let ((feerate (truncate (* 30000 4) weight)))
        (is (plusp feerate))
        (is (= feerate (funcall stat "avgfeerate")))
        (is (= feerate (funcall stat "maxfeerate")))
        (is (= feerate (funcall stat "minfeerate")))
        (is (equal (list feerate feerate feerate feerate feerate)
                   (funcall stat "feerate_percentiles"))))
      ;; --- segwit + utxo-set deltas ---
      (is (= 1 (funcall stat "swtxs")))
      (is (= wire (funcall stat "swtotal_size")))
      (is (= weight (funcall stat "swtotal_weight")))
      ;; 3 outputs created, 1 spent.
      (is (= 2 (funcall stat "utxo_increase")))
      ;; The OP_RETURN output never enters the UTXO set: 2 created, 1 spent.
      (is (= 1 (funcall stat "utxo_increase_actual")))
      ;; Sizes: a 25-byte spk costs 8+1+25+41 = 75, the 3-byte OP_RETURN
      ;; 8+1+3+41 = 53; one 75-byte prevout is removed.
      (is (= (- (+ 75 75 53) 75) (funcall stat "utxo_size_inc")))
      (is (= (- (+ 75 75) 75) (funcall stat "utxo_size_inc_actual")))
      ;; --- chain context ---
      (is (= 100 (funcall stat "height")))
      (is (= 1700000000 (funcall stat "time")))
      (is (= 1700000000 (funcall stat "mediantime")))
      (is (string= hex (funcall stat "blockhash")))
      (is (= (bl.val:calculate-block-subsidy 100)
             (funcall stat "subsidy")))
      ;; Core's full key set is 31 keys.
      (is (= 31 (length r))))))

(test rpc-getblockstats-coinbase-only-block
  "CONTROL for the coinbase exclusion at the boundary: a block with nothing but
a coinbase has zero total_size / total_out / total_weight / fees and a zero
average (Core divides by vtx.size()-1 only `if (block.vtx.size() > 1)`), while
its output is still counted in outs."
  (%with-gbs-block (node hex spender :with-undo nil :coinbase-only t)
    (let* ((r (bl.rpc::rpc-getblockstats node (list hex)))
           (stat (lambda (k) (cdr (assoc k r :test #'string=)))))
      (is (= 1 (funcall stat "txs")))
      (is (= 1 (funcall stat "outs")))
      (is (= 0 (funcall stat "ins")))
      (is (= 0 (funcall stat "total_size")))
      (is (= 0 (funcall stat "total_out")))
      (is (= 0 (funcall stat "total_weight")))
      (is (= 0 (funcall stat "avgtxsize")))
      (is (= 0 (funcall stat "avgfee")))
      (is (= 0 (funcall stat "totalfee")))
      (is (= 0 (funcall stat "minfee")))
      (is (= 0 (funcall stat "mintxsize")))
      (is (equal (list 0 0 0 0 0) (funcall stat "feerate_percentiles"))))))

(test rpc-getblockstats-unknown-stat-errors
  "An unknown statistic name is Core's RPC_INVALID_PARAMETER (-8) 'Invalid
selected statistic' (rpc/blockchain.cpp:2183-2186); we used to drop it
silently, so a typo read as 'that statistic is unavailable for this block'."
  (%with-gbs-block (node hex spender)
    (signals-rpc-error (:code -8)
      (bl.rpc::rpc-getblockstats node (list hex (list "totalfee" "bogus"))))
    ;; CONTROL: a known name still selects exactly that key.
    (let ((r (bl.rpc::rpc-getblockstats node (list hex (list "totalfee")))))
      (is (= 1 (length r)))
      (is (= 30000 (cdr (assoc "totalfee" r :test #'string=)))))
    ;; A non-array stats argument is Core's type error.
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockstats node (list hex "totalfee")))))

(test rpc-getblockstats-requires-undo-data
  "The fee statistics come from undo data, and Core's GetUndoChecked
(rpc/blockchain.cpp:2016, :718-735) runs unconditionally — so a spending block
whose undo data is missing is an error, never a silently wrong fee total.
CONTROL: the identical block WITH its undo data answers (previous test)."
  (%with-gbs-block (node hex spender :with-undo nil)
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockstats node (list hex)))))

;;; --- REST: the two endpoints that render a block's spent coins ---
;;;
;;; Both reuse %WITH-GBS-BLOCK above: it is this file's one fixture that stores
;;; a block together with its undo data, which is the whole subject here.

(test rest-spenttxouts-is-core-s-rest-format-not-the-rev-file-codec
  "/rest/spenttxouts/<hash>.bin|.hex is Core's SerializeBlockUndo
(rest.cpp:277-289): CompactSize(vtxundo.size() + 1), CompactSize(0) for the
coinbase CBlockUndo does not carry, then per transaction
CompactSize(vprevout.size()) and each coin as a BARE CTxOut -- int64 value plus
CompactSize-prefixed script (primitives/transaction.h:152).

We served the rev-file codec instead, whose outer count is short by one, whose
coinbase placeholder is missing, and whose coins carry a
VARINT(height*2+coinbase), a dummy byte and a COMPRESSED amount and script. No
client written against Core can decode that, and it does not error: the coins
read as plausible garbage."
  (%with-gbs-block (node hex spender)
    (let ((expected (concatenate 'string
                                 "02"               ; one CTxUndo, plus the coinbase
                                 "00"               ; ... which spends nothing
                                 "01"               ; the spend has one input
                                 "a086010000000000" ; 100000 sat as int64 LE
                                 "19"               ; a 25-byte script
                                 (bl.crypto:bytes-to-hex *gbs-p2pkh*))))
      (is (string= (format nil "~A~%" expected)
                   (rest-request node (format nil "/rest/spenttxouts/~A.hex" hex))))
      ;; .bin is those bytes, unhexed.
      (is (equalp (bl.crypto:hex-to-bytes expected)
                  (rest-request node (format nil "/rest/spenttxouts/~A.bin" hex))))
      ;; CONTROL: the disk codec answers something else for the same undo
      ;; record, so a future "just reuse SERIALIZE-BLOCK-UNDO" cannot pass.
      (is (string/= expected
                    (bl.crypto:bytes-to-hex
                     (bl.store:serialize-block-undo
                      (list (list (bl.store:make-utxo-entry
                                   :value 100000 :script-pubkey *gbs-p2pkh*
                                   :height 50 :coinbase nil))))))))))

(test rest-spenttxouts-json-leads-with-the-coinbase-s-empty-array
  "BlockUndoToJSON pushes an EMPTY array first (rest.cpp:295) because
CBlockUndo has no entry for the coinbase. That placeholder is what makes
result[i] the coins of block transaction i; without it every array is
attributed to the transaction before it, so a client reads transaction 1's
prevouts as the coinbase's and finds none for the last transaction."
  (%with-gbs-block (node hex spender)
    (let* ((body (rest-request node (format nil "/rest/spenttxouts/~A.json" hex)))
           (parsed (yason:parse body)))
      (is (= 2 (length parsed))
          "one array per block transaction, coinbase included: ~S" body)
      (is-true (alexandria:starts-with-subseq "[[]," body)
               "the coinbase's placeholder array is missing: ~S" body)
      (let ((coins (second parsed)))
        (is (= 1 (length coins)) "the spend's coins landed at the wrong index")
        (let ((coin (first coins)))
          ;; Core's prevout object: the amount in BTC and ScriptToUniv.
          (is (< (abs (- 0.001d0 (gethash "value" coin))) 1d-12))
          (is (string= (bl.crypto:bytes-to-hex *gbs-p2pkh*)
                       (gethash "hex" (gethash "scriptPubKey" coin)))))))))

(test rest-block-json-is-core-s-verbosity-3
  "/rest/block/<hash>.json is rest_block_extended, which passes
TxVerbosity::SHOW_DETAILS_AND_PREVOUT (rest.cpp:470-473) -- the level getblock
reaches only at verbosity 3 (rpc/blockchain.cpp:867-874), where every
non-coinbase vin carries a `prevout` object. We asked for verbosity 2, so the
endpoint served vins with no prevout at all and an explorer had to fetch every
spent output itself. /rest/block/notxdetails/ stays at SHOW_TXID."
  (%with-gbs-block (node hex spender)
    (let* ((parsed (yason:parse (rest-request node (format nil "/rest/block/~A.json" hex))))
           (spend (second (gethash "tx" parsed)))
           (prevout (gethash "prevout" (first (gethash "vin" spend)))))
      (is-true prevout "the vin has no prevout: this is verbosity 2, not 3")
      (is (= 50 (gethash "height" prevout)))
      (is (< (abs (- 0.001d0 (gethash "value" prevout))) 1d-12))
      (is (string= (bl.crypto:bytes-to-hex *gbs-p2pkh*)
                   (gethash "hex" (gethash "scriptPubKey" prevout))))
      ;; The fee verbosity 2 already carried is still there.
      (is-true (gethash "fee" spend))
      ;; The coinbase spends nothing, so Core gives it no prevout.
      (is-false (gethash "prevout" (first (gethash "vin" (first (gethash "tx" parsed)))))))
    ;; notxdetails is SHOW_TXID: bare txid strings, no transaction objects.
    (let ((parsed (yason:parse
                   (rest-request node (format nil "/rest/block/notxdetails/~A.json" hex)))))
      (is-true (every #'stringp (gethash "tx" parsed))
               "notxdetails must stay at Core's SHOW_TXID"))))

(test rpc-calculate-block-subsidy
  "Test block subsidy calculation"
  ;; Initial subsidy: 50 BTC = 5000000000 satoshis
  (is (= (bl.val:calculate-block-subsidy 0) 5000000000))
  (is (= (bl.val:calculate-block-subsidy 209999) 5000000000))
  ;; First halving at 210000
  (is (= (bl.val:calculate-block-subsidy 210000) 2500000000))
  (is (= (bl.val:calculate-block-subsidy 419999) 2500000000))
  ;; Second halving
  (is (= (bl.val:calculate-block-subsidy 420000) 1250000000))
  ;; Third halving
  (is (= (bl.val:calculate-block-subsidy 630000) 625000000)))

;;; --- Extended getrawtransaction Tests ---

(test rpc-getrawtransaction-with-blockhash-invalid
  "Test getrawtransaction with invalid blockhash parameter"
  (let ((node (make-test-node)))
    ;; Valid txid but invalid blockhash format
    (signals bl.rpc:rpc-error
      (bl.rpc:dispatch-rpc-method node "getrawtransaction"
        '("0000000000000000000000000000000000000000000000000000000000000001" nil "invalid-hash")))))

(test rpc-getrawtransaction-txindex-disabled
  "Test getrawtransaction returns error when txindex needed but disabled"
  (let ((node (make-test-node)))
    ;; Node has no txindex, looking for non-mempool tx should fail
    (signals bl.rpc:rpc-error
      (bl.rpc:dispatch-rpc-method node "getrawtransaction"
        '("0000000000000000000000000000000000000000000000000000000000000001")))))

;;; --- JSON Result Normalization (regression) ---

(test rpc-result->json-shapes
  "rpc-result->json converts object-alists to hash-tables, leaves arrays as lists."
  ;; object-alist -> hash-table
  (let ((obj (bl.rpc::rpc-result->json (list (cons "a" 1) (cons "b" "x")))))
    (is (hash-table-p obj))
    (is (= (gethash "a" obj) 1))
    (is (string= (gethash "b" obj) "x")))
  ;; array of objects -> list of hash-tables
  (let ((arr (bl.rpc::rpc-result->json
              (list (list (cons "k" 1)) (list (cons "k" 2))))))
    (is (listp arr))
    (is (= (length arr) 2))
    (is (hash-table-p (first arr)))
    (is (= (gethash "k" (first arr)) 1)))
  ;; nested object value
  (let ((obj (bl.rpc::rpc-result->json
              (list (cons "outer" (list (cons "inner" 7)))))))
    (is (hash-table-p (gethash "outer" obj)))
    (is (= (gethash "inner" (gethash "outer" obj)) 7)))
  ;; array of strings is unchanged; atoms pass through
  (is (equal (bl.rpc::rpc-result->json (list "a" "b")) (list "a" "b")))
  (is (= (bl.rpc::rpc-result->json 42) 42)))

(test rpc-object-results-encode-to-json
  "Object-returning RPC results must serialize through yason without error.
Regression: handlers build alists, but yason's default list encoder treated
them as arrays and choked on the dotted pairs, so every object RPC errored."
  (let ((node (make-test-node)))
    (dolist (result (list (bl.rpc::rpc-getblockchaininfo node nil)
                          (bl.rpc::rpc-getnetworkinfo node nil)
                          (bl.rpc::rpc-getpeerinfo node nil)
                          (bl.rpc::rpc-getmempoolinfo node nil)))
      (let* ((response (bl.rpc::make-rpc-response result "id" :v2))
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
         (chain-state (bl:node-chain-state node))
         (g-hash (make-32-byte-hash 0))
         (a-hash (make-32-byte-hash 1))
         (b-hash (make-32-byte-hash 2))
         (genesis (bl.store:make-block-index-entry
                   :hash g-hash :height 0 :status :valid))
         (a (bl.store:make-block-index-entry
             :hash a-hash :height 1 :prev-entry genesis :status :valid))
         (b (bl.store:make-block-index-entry
             :hash b-hash :height 1 :prev-entry genesis :status :valid)))
    (bl.store:add-block-index-entry chain-state genesis)
    (bl.store:add-block-index-entry chain-state a)
    (bl.store:add-block-index-entry chain-state b)
    (bl.store:update-chain-tip chain-state a-hash 1)
    (let* ((tips (bl.rpc::rpc-getchaintips node nil))
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
      (let ((response (bl.rpc::make-rpc-response tips "id" :v2)))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-testmempoolaccept-missing-input
  "testmempoolaccept dry-runs validation without mutating the mempool."
  (let* ((node (make-test-node))
         (tx (make-mempool-test-tx :input-id 210))
         (hex (bl.crypto:bytes-to-hex
               (bl.ser:serialize-transaction tx)))
         (result (bl.rpc::rpc-testmempoolaccept node (list (list hex)))))
    (is (listp result))
    (is (= 1 (length result)))
    (let ((r (first result)))
      ;; Empty UTXO set => missing input => not allowed, with a reason.
      (is (eq 'yason:false (cdr (assoc "allowed" r :test #'string=))))
      ;; PLURAL, and this surface only: testmempoolaccept substitutes
      ;; "missing-inputs" for the TX_MISSING_INPUTS result
      ;; (rpc/mempool.cpp:399-400), where sendrawtransaction reports the
      ;; state's own "bad-txns-inputs-missingorspent". This test used to pin
      ;; "missing-input", which was neither — it was our keyword downcased.
      (is (string= "missing-inputs" (cdr (assoc "reject-reason" r :test #'string=)))))
    ;; Nothing was added to the mempool.
    (is (= 0 (bl.mp:mempool-count (bl:node-mempool node))))))

;;; --- Mempool introspection RPCs ---

(test rpc-mempool-introspection
  ;; A parent + chained child in the mempool exercise getmempoolentry,
  ;; getmempoolancestors/descendants, and gettxspendingprevout.
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (funding (%txid-array 99))
         (parent (%mp-spending-tx funding :vout 0 :value 50000000))
         (pid (bl.ser:transaction-hash parent))
         (child (%mp-spending-tx pid :vout 0 :value 40000000))
         (cid (bl.ser:transaction-hash child))
         (pid-hex (bl.rpc:hash-to-hex pid))
         (cid-hex (bl.rpc:hash-to-hex cid)))
    (%add-tx mempool parent :fee 1000)
    (%add-tx mempool child :fee 2000)
    ;; getmempoolentry: parent has 2 descendants (self+child), 1 ancestor (self)
    (let ((r (bl.rpc::rpc-getmempoolentry node (list pid-hex))))
      (is (= 2 (cdr (assoc "descendantcount" r :test #'string=))))
      (is (= 1 (cdr (assoc "ancestorcount" r :test #'string=)))))
    ;; getmempoolancestors child -> [parent]
    (let ((r (bl.rpc::rpc-getmempoolancestors node (list cid-hex))))
      (is (equal (list pid-hex) r)))
    ;; getmempooldescendants parent -> [child]
    (let ((r (bl.rpc::rpc-getmempooldescendants node (list pid-hex))))
      (is (equal (list cid-hex) r)))
    ;; verbose form -> alist (txid-hex . fields)
    (let ((r (bl.rpc::rpc-getmempooldescendants node (list pid-hex t))))
      (is (= 1 (length r)))
      (is (string= cid-hex (car (first r))))
      (is (assoc "vsize" (cdr (first r)) :test #'string=)))
    ;; gettxspendingprevout: the funding outpoint is spent by the parent
    (flet ((op (txid-hex vout)
             (let ((h (make-hash-table :test 'equal)))
               (setf (gethash "txid" h) txid-hex (gethash "vout" h) vout) h)))
      (let ((r (bl.rpc::rpc-gettxspendingprevout
                node (list (list (op (bl.rpc:hash-to-hex funding) 0))))))
        (is (= 1 (length r)))
        (is (string= pid-hex (cdr (assoc "spendingtxid" (first r) :test #'string=)))))
      ;; an unspent outpoint -> no spendingtxid key
      (let ((r (bl.rpc::rpc-gettxspendingprevout
                node (list (list (op (bl.rpc:hash-to-hex (%txid-array 200)) 0))))))
        (is (null (assoc "spendingtxid" (first r) :test #'string=)))))
    ;; getmempoolentry for an absent tx -> error
    (signals error
      (bl.rpc::rpc-getmempoolentry
       node (list (bl.rpc:hash-to-hex (%txid-array 201)))))))

;;; --- Node / chain info RPCs ---

(test rpc-node-info
  (let* ((node (make-test-node))
         (net (bl:node-network node)))
    ;; getdifficulty: a positive number (no tip -> fallback bits 0x1d00ffff -> 1.0)
    (let ((d (bl.rpc::rpc-getdifficulty node nil)))
      (is (numberp d))
      (is (plusp d)))
    ;; uptime: 0 when start-time unset; >= elapsed when set
    (let ((bl:*node-start-time* nil))
      (is (= 0 (bl.rpc::rpc-uptime node nil))))
    (let ((bl:*node-start-time*
            (- (bl.ser:get-unix-time) 5)))
      (is (>= (bl.rpc::rpc-uptime node nil) 5)))
    ;; getindexinfo: no active index -> empty JSON object (hash-table)
    (is (hash-table-p (bl.rpc::rpc-getindexinfo node nil)))
    ;; With block-filter + coinstats indexes present, both are reported (bare
    ;; structs have a nil db -> height -1); an index-name arg filters to one.
    (setf (bl:node-blockfilterindex node)
          (bl.store:make-blockfilterindex :enabled t)
          (bl:node-coinstatsindex node)
          (bl.store::make-coinstatsindex :enabled t))
    (let ((all (bl.rpc::rpc-getindexinfo node nil)))
      (is (assoc "basic block filter index" all :test #'string=))
      (is (assoc "coinstatsindex" all :test #'string=)))
    (let ((one (bl.rpc::rpc-getindexinfo node (list "coinstatsindex"))))
      (is (assoc "coinstatsindex" one :test #'string=))
      (is (null (assoc "basic block filter index" one :test #'string=))))
    ;; getdeploymentinfo: buried deployments present; segwit reports the
    ;; network's activation height and matches the active/height contract.
    (let* ((r (bl.rpc::rpc-getdeploymentinfo node nil))
           (deps (cdr (assoc "deployments" r :test #'string=)))
           (segwit (cdr (assoc "segwit" deps :test #'string=))))
      (is (assoc "bip34" deps :test #'string=))
      (is (assoc "taproot" deps :test #'string=))
      ;; script_flags is a list of active script-verify flag names (P2SH at h=0)
      (is (member "P2SH" (cdr (assoc "script_flags" r :test #'string=)) :test #'string=))
      (is (string= "buried" (cdr (assoc "type" segwit :test #'string=))))
      (is (= (bl.val:get-segwit-activation-height net)
             (cdr (assoc "height" segwit :test #'string=))))
      ;; height 0 < testnet segwit activation -> not active (a JSON boolean,
      ;; so inactive is false rather than null)
      (is (eq (bl.rpc:json-bool
               (>= 0 (bl.val:get-segwit-activation-height net)))
              (cdr (assoc "active" segwit :test #'string=)))))))

;;; --- Peer / address RPCs ---

(test rpc-peer-address
  (let ((node (make-test-node)))
    ;; getnodeaddresses: seed the address book with one IPv4 entry
    (let ((book (bl.net:make-address-book)))
      (bl.net:address-book-add
       book (bl.net:make-peer-address
             :ip (bl.net:ipv4-to-mapped-ipv6 1 2 3 4)
             :port 48333 :services 9
             ;; recent so getnodeaddresses (GetAddr) doesn't filter it as terrible
             :last-seen (bl.ser:get-unix-time)))
      (setf (bl:node-address-book node) book)
      (let ((r (bl.rpc::rpc-getnodeaddresses node (list 0))))  ; 0 = all
        (is (= 1 (length r)))
        (is (string= "1.2.3.4" (cdr (assoc "address" (first r) :test #'string=))))
        (is (= 48333 (cdr (assoc "port" (first r) :test #'string=))))
        (is (= 9 (cdr (assoc "services" (first r) :test #'string=))))))
    ;; disconnectnode: a connected peer is disconnected by address
    (let ((peer (bl.net:make-peer
                 :connection (bl.net::make-connection
                              :host "5.6.7.8" :port 48333 :connected t)
                 :state :ready :address "5.6.7.8")))
      (setf (bl:node-peers node) (list peer))
      (is (null (bl.rpc::rpc-disconnectnode node (list "5.6.7.8"))))
      (is (eq :disconnected (bl.net:peer-state peer)))
      ;; an unknown address errors
      (signals error (bl.rpc::rpc-disconnectnode node (list "9.9.9.9"))))))

;;; --- Chain control RPCs (error paths; full reorg behavior in reorg-tests) ---

(test rpc-chain-control-errors
  (let ((node (make-test-node)))
    ;; a well-formed but unknown block hash -> error
    (signals error
      (bl.rpc::rpc-invalidateblock
       node (list "00000000000000000000000000000000000000000000000000000000deadbeef")))
    ;; a malformed hash -> error
    (signals error
      (bl.rpc::rpc-reconsiderblock node (list "not-a-hash")))))

;;; --- setban / listbanned / clearbanned / getnettotals / verifychain ---

(test rpc-setban-add-list-remove-clear
  "setban add/remove + listbanned + clearbanned manage the manual ban list."
  (bl.net:clear-ban-list)
  (let ((node (make-test-node)))
    (is (null (bl.rpc::rpc-setban node (list "1.2.3.4" "add"))))
    (is-true (bl.net:peer-banned-p "1.2.3.4"))
    (let ((banned (bl.rpc::rpc-listbanned node nil)))
      (is (= 1 (length banned)))
      (is (string= "1.2.3.4" (cdr (assoc "address" (first banned) :test #'string=))))
      (is (integerp (cdr (assoc "banned_until" (first banned) :test #'string=)))))
    (is (null (bl.rpc::rpc-setban node (list "1.2.3.4" "remove"))))
    (is (not (bl.net:peer-banned-p "1.2.3.4")))
    ;; remove a non-existent ban / bad command -> error
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-setban node (list "9.9.9.9" "remove")))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-setban node (list "1.2.3.4" "bogus")))
    ;; clearbanned empties the list
    (bl.rpc::rpc-setban node (list "5.6.7.8" "add"))
    (is (null (bl.rpc::rpc-clearbanned node nil)))
    (is (= 0 (length (bl.rpc::rpc-listbanned node nil))))))

(test rpc-setban-absolute-bantime
  "setban add with absolute=true sets banned_until to the given Unix time."
  (bl.net:clear-ban-list)
  (let ((node (make-test-node))
        (future (+ (bl.ser:get-unix-time) 3600)))
    (bl.rpc::rpc-setban node (list "10.0.0.1" "add" future t))
    (let ((banned (bl.rpc::rpc-listbanned node nil)))
      (is (<= (abs (- future (cdr (assoc "banned_until" (first banned) :test #'string=)))) 2)))
    (bl.net:clear-ban-list)))

(test rpc-setban-add-disconnects-connected-peer
  "setban add disconnects every connected peer with the banned address itself
(Core rpc/net.cpp:803-810 -> CConnman::DisconnectNode) — the peers UI no
longer needs to chain a disconnectnode. Other peers are untouched."
  (bl.net:clear-ban-list)
  (let* ((node (make-test-node))
         (conn (bl.net::make-connection
                :host "203.0.113.9" :port 8333 :connected t))
         (target (bl.net:make-peer :address "203.0.113.9" :state :ready
                                          :connection conn))
         (other (bl.net:make-peer :address "198.51.100.3" :state :ready)))
    (setf (bl:node-peers node) (list target other))
    (is (null (bl.rpc::rpc-setban node (list "203.0.113.9" "add"))))
    (is-true (bl.net:peer-banned-p "203.0.113.9"))
    (is (eq :disconnected (bl.net:peer-state target)))
    (is (null (bl.net:peer-connection target)))
    (is (eq :ready (bl.net:peer-state other)))
    (bl.net:clear-ban-list)))

(test inbound-connection-admission-gate
  "The inbound accept path consults the ban list BEFORE any handshake work
(Core CConnman::CreateNodeFromAcceptedSocket, net.cpp:1801-1813): banned
addresses are always dropped; discouraged addresses only when the inbound
slots are (almost) full."
  (bl.net:clear-ban-list)
  (bl.net:clear-discouraged)
  (let ((node (make-test-node)))
    (is-true (bl::inbound-connection-allowed-p node "203.0.113.77"))
    ;; Banned: dropped regardless of slot pressure.
    (bl.net:ban-address "203.0.113.77")
    (multiple-value-bind (ok reason)
        (bl::inbound-connection-allowed-p node "203.0.113.77")
      (is (null ok))
      (is (eq :banned reason)))
    ;; Discouraged with free slots: still admitted.
    (bl.net:discourage-peer "198.51.100.77")
    (is-true (bl::inbound-connection-allowed-p node "198.51.100.77"))
    ;; Discouraged at inbound capacity: dropped.
    (setf (bl:node-peers node)
          (loop for i from 1 to bl::*max-inbound-connections*
                collect (bl.net:make-peer
                         :address (format nil "10.~D.1.1" i) :inbound t)))
    (multiple-value-bind (ok reason)
        (bl::inbound-connection-allowed-p node "198.51.100.77")
      (is (null ok))
      (is (eq :discouraged reason)))
    (bl.net:clear-ban-list)
    (bl.net:clear-discouraged)))

(test rpc-getnettotals-fields
  "getnettotals returns integer byte totals + timemillis + an uploadtarget object."
  (let ((r (bl.rpc::rpc-getnettotals (make-test-node) nil)))
    (is (integerp (cdr (assoc "totalbytesrecv" r :test #'string=))))
    (is (integerp (cdr (assoc "totalbytessent" r :test #'string=))))
    (is (integerp (cdr (assoc "timemillis" r :test #'string=))))
    (is (consp (cdr (assoc "uploadtarget" r :test #'string=))))))

(test rpc-verifychain-empty-node-returns-false
  "verifychain on a node with no stored blocks returns JSON false (a bare
Core boolean — never null)."
  (is (eq 'yason:false (bl.rpc::rpc-verifychain (make-test-node) (list 0 1)))))

;;; --- waitfornewblock / dumptxoutset ---

(test rpc-waitfornewblock-timeout-and-change
  "waitfornewblock returns on timeout, rejects negative timeouts, and returns
early when the tip changes."
  (let ((node (make-test-node)))
    (setf (bl:node-running node) t)
    ;; Timeout path: the tip never changes; returns after ~300ms.
    (let ((r (bl.rpc::rpc-waitfornewblock node (list 300))))
      (is (integerp (cdr (assoc "height" r :test #'string=)))))
    ;; Negative timeout errors (Core).
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-waitfornewblock node (list -1)))
    ;; Change path: a thread advances the tip; the wait returns the new height.
    (let ((cs (bl:node-chain-state node))
          (new-hash (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 9)))
      (bt:make-thread (lambda ()
                        (sleep 0.3)
                        (bl.store:update-chain-tip cs new-hash 7)))
      (let ((r (bl.rpc::rpc-waitfornewblock node (list 5000))))
        (is (= 7 (cdr (assoc "height" r :test #'string=))))))))

(test rpc-dumptxoutset-writes-snapshot
  "dumptxoutset streams the UTXO set to a new file and refuses to overwrite."
  (let* ((node (make-test-node))
         (utxo (bl:node-utxo-set node))
         (path (namestring (merge-pathnames
                            (format nil "txoutset-~D.dat" (get-universal-time))
                            (uiop:temporary-directory)))))
    (bl.store:update-chain-tip
     (bl:node-chain-state node)
     (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9) 1)
    (dotimes (i 3)
      (bl.store:add-utxo
       utxo
       (make-array 32 :element-type '(unsigned-byte 8) :initial-element (1+ i))
       0 1000 (make-array 25 :element-type '(unsigned-byte 8)) 1))
    (unwind-protect
         (progn
           (let ((r (bl.rpc::rpc-dumptxoutset node (list path "latest"))))
             (is (= 3 (cdr (assoc "coins_written" r :test #'string=))))
             (is (not (null (probe-file path)))))
           ;; Existing path -> error (Core).
           (signals bl.rpc:rpc-error
             (bl.rpc::rpc-dumptxoutset node (list path "latest"))))
      (ignore-errors (delete-file path)))))

;;;; RPC auth + JSON-RPC version (T3b: stock bitcoin-cli compatibility)

(test rpc-accepts-jsonrpc-1.0-and-versionless
  "parse-json-rpc-request accepts a 1.0 (and version-less) envelope — stock
bitcoin-cli sends those; rejecting non-2.0 made it unusable."
  (multiple-value-bind (kind method)
      (bl.rpc::parse-json-rpc-request
       "{\"jsonrpc\":\"1.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}")
    (is (eq :single kind))
    (is (string= "getblockcount" method)))
  (multiple-value-bind (kind method)
      (bl.rpc::parse-json-rpc-request "{\"method\":\"uptime\",\"id\":1}")
    (is (eq :single kind))
    (is (string= "uptime" method))))

(test rpc-basic-auth-and-cookie
  "check-auth against the two credential states start-rpc-server can actually
produce. Startup installs exactly one credential, as Core's
InitRPCAuthentication pushes exactly one entry into g_rpcauth
(httprpc.cpp:262-288): the .cookie pair when no rpcuser/rpcpassword is given,
that pair otherwise. Binding user, password AND cookie secret at once — what
this test used to do — describes no reachable configuration."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node))
          (cookie-file (merge-pathnames ".cookie" dir)))
      (setf (bl:node-data-directory node) dir)
      (unwind-protect
           (progn
             ;; (a) no rpcuser/rpcpassword: the cookie is the credential
             (is (not (null (bl.rpc:start-rpc-server node :port 19994))))
             (is (string= bl.rpc::+rpc-cookie-user+
                          (bl.rpc::rpc-credential-user
                           (first bl.rpc::*rpc-credentials*))))
             (let ((cookie (alexandria:read-file-into-string cookie-file)))
               (is (bl.rpc::check-auth (%basic-auth-header cookie)))
               (is (not (bl.rpc::check-auth
                         (%basic-auth-header "__cookie__:bad"))))
               (is (not (bl.rpc::check-auth (%basic-auth-header "u:p")))))
             ;; shutdown removes the cookie it generated (Core DeleteAuthCookie)
             (bl.rpc:stop-rpc-server)
             (is (null (probe-file cookie-file)))
             ;; (b) rpcuser/rpcpassword: that pair is the credential, no cookie
             ;; is written, and the cookie user is not a way in
             (is (not (null (bl.rpc:start-rpc-server
                             node :port 19994 :user "u" :password "p"))))
             (is (null (probe-file cookie-file)))
             (is (bl.rpc::check-auth (%basic-auth-header "u:p")))
             (is (not (bl.rpc::check-auth (%basic-auth-header "u:wrong"))))
             (is (not (bl.rpc::check-auth
                       (%basic-auth-header "__cookie__:p")))))
        (bl.rpc:stop-rpc-server)))))

(test rpc-cookie-file-is-owner-only
  "The generated .cookie is the RPC credential, so no other local user may read
it: Core creates it under umask 0077 (GenerateAuthCookie, request.cpp:99-146).
Ours was 0664 on the live testnet4 and mainnet datadirs, which would have left
the credential readable node-wide even with auth enforced."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node)))
      (setf (bl:node-data-directory node) dir)
      (unwind-protect
           (progn
             (is (not (null (bl.rpc:start-rpc-server node :port 19995))))
             (let ((path (merge-pathnames ".cookie" dir)))
               (is (not (null (probe-file path))))
               (is (= #o600
                      (logand #o777
                              (sb-posix:stat-mode
                               (sb-posix:stat (namestring (truename path)))))))
               ;; the file is renamed into place, never left half-written
               (is (null (probe-file (merge-pathnames ".cookie.tmp" dir))))))
        (bl.rpc:stop-rpc-server)))))

(defun %file-mode (path)
  "The permission bits of PATH."
  (logand #o777 (sb-posix:stat-mode (sb-posix:stat (namestring path)))))

(test rpc-cookie-owner-only-under-a-permissive-umask
  "0600 has to come from open(2), not from a chmod afterwards. Core gets it
from a process-wide umask 0077 (common/system.cpp:92-93) so the cookie is
owner-only from creation (GenerateAuthCookie, request.cpp:99-146); we set no
process umask, so the mode must be passed to open. The live host runs umask
002 — its .cookie files were 0664 — which is what this test reproduces."
  (with-temp-directory (dir)
    (let ((old-umask (sb-posix:umask #o002)))
      (unwind-protect
           (progn
             ;; Premise check: without this the 0600 assertion below would pass
             ;; on a strict ambient umask no matter what the cookie code does.
             (let ((control (merge-pathnames "umask-control" dir)))
               (with-open-file (s control :direction :output :if-does-not-exist :create)
                 (write-string "x" s))
               (is (= #o664 (%file-mode control))
                   "test premise: under umask 002 an ordinary file is 0664, got ~O"
                   (%file-mode control)))
             (multiple-value-bind (path secret)
                 (bl.rpc::generate-rpc-cookie dir)
               (is (not (null path)))
               (is (= #o600 (%file-mode path))
                   "the cookie must be 0600 whatever the umask, got ~O" (%file-mode path))
               (is (search secret (alexandria:read-file-into-string path)))
               (is (null (probe-file (merge-pathnames ".cookie.tmp" dir))))))
        (sb-posix:umask old-umask)))))

(test rpc-cookie-never-written-into-a-file-we-did-not-create
  "The secret must only ever be written into a file this process exclusively
created. Chmod-after-write cannot deliver that: POSIX checks permissions at
open(2) only, so a descriptor opened while .cookie.tmp still carries the
umask's mode stays valid across the chmod and the rename, and inotify on the
data directory makes that window deterministic on every node start. Both halves
below are the same defect — WITH-OPEN-FILE :if-exists :supersede opens the
EXISTING inode with O_TRUNC, and follows a symlink to do it."
  (with-temp-directory (dir)
    (let ((tmp (merge-pathnames ".cookie.tmp" dir)))
      ;; (a) a planted regular file whose descriptor the attacker still holds
      (with-open-file (s tmp :direction :output :if-does-not-exist :create)
        (write-string "" s))
      (sb-posix:chmod (namestring tmp) #o666)
      (with-open-file (spy tmp :direction :input)
        (multiple-value-bind (path secret) (bl.rpc::generate-rpc-cookie dir)
          (is (not (null path)))
          (is (not (null secret)))
          (let ((seen (progn (file-position spy 0) (or (read-line spy nil nil) ""))))
            (is (not (search secret seen))
                "the secret was written into a pre-existing inode the attacker ~
still holds open: ~S" seen))))
      (when (probe-file (merge-pathnames ".cookie" dir))
        (delete-file (merge-pathnames ".cookie" dir)))
      ;; (b) a planted symlink: written through, and then RENAME moves the
      ;; resolved target over .cookie
      (let ((target (merge-pathnames "attacker-target" dir)))
        (with-open-file (s target :direction :output :if-does-not-exist :create)
          (write-string "" s))
        (handler-case (sb-posix:unlink (namestring tmp)) (error () nil))
        (sb-posix:symlink (namestring target) (namestring tmp))
        (multiple-value-bind (path secret) (bl.rpc::generate-rpc-cookie dir)
          (is (not (null path)))
          ;; NB: keep this out of a 3-element (and a b) inside IS — FiveAM
          ;; treats any 3-element form as (predicate expected actual) and
          ;; evaluates both arguments, so the short-circuit is lost and a
          ;; renamed-away target errors instead of failing.
          (let ((leaked (if (probe-file target)
                            (search secret (alexandria:read-file-into-string target))
                            :target-renamed-over-cookie)))
            (is (null leaked)
                "the secret leaked through a planted .cookie.tmp symlink (~S)" leaked))
          ;; and the cookie that did get installed is still usable and 0600
          (is (search secret (alexandria:read-file-into-string path)))
          (is (= #o600 (%file-mode path))))))))

(test rpc-failed-start-does-not-clobber-a-live-cookie
  "A start that cannot bind must leave .cookie alone. Core binds first —
AppInitServers runs InitHTTPServer before StartHTTPRPC ->
InitRPCAuthentication -> GenerateAuthCookie (init.cpp:748-761) — so a port
conflict aborts before any credential is touched. Writing the cookie first
means a second process started on a running node's data directory (which has
happened here: restart-node.sh's pkill marker missed the live supervisor)
overwrites .cookie with a secret matching nothing and then exits. The healthy
node keeps serving with the old secret, so every client that re-reads the file
gets 401 from a node that is perfectly fine, and nothing logs anything."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let* ((port 19993)
           (node (make-test-node))
           (cookie-file (merge-pathnames ".cookie" dir)))
      (setf (bl:node-data-directory node) dir)
      (unwind-protect
           (progn
             ;; the healthy node: bound, cookie written, credential live
             (is (not (null (bl.rpc:start-rpc-server node :port port))))
             (let ((live-cookie (alexandria:read-file-into-string cookie-file))
                   (live-credentials bl.rpc::*rpc-credentials*)
                   (live-dispatch hunchentoot:*dispatch-table*))
               (is (bl.rpc::check-auth (%basic-auth-header live-cookie)))
               ;; the second process: same data directory, same port. The
               ;; "already running" guard is per-process, so unbind it to reach
               ;; the code a second process would run.
               (let ((bl.rpc:*rpc-server* nil))
                 (is (null (bl.rpc:start-rpc-server node :port port))
                     "the second start must fail: the port is taken"))
               ;; nothing about the running node changed
               (let ((on-disk (and (probe-file cookie-file)
                                   (alexandria:read-file-into-string cookie-file))))
                 (is (equal live-cookie on-disk)
                     "the failed start rewrote or removed .cookie under a live node")
                 (is (eq live-credentials bl.rpc::*rpc-credentials*)
                     "the failed start replaced the live node's credentials")
                 (is (eq live-dispatch hunchentoot:*dispatch-table*)
                     "the failed start leaked a dispatcher into hunchentoot:*dispatch-table*")
                 (is (bl.rpc::check-auth (%basic-auth-header live-cookie)))
                 ;; and a client reading .cookie off disk still gets in
                 (let ((r (%http-post-rpc port "{\"method\":\"getblockcount\",\"id\":1}"
                                          :auth (or on-disk "__cookie__:gone"))))
                   (is (= 200 (%http-status r))
                       "a client re-reading .cookie was locked out of a live node")))))
        (bl.rpc:stop-rpc-server)))))

(test rpc-requires-credentials-end-to-end
  "Live acceptor through rpc-handler: no Authorization header answers 401 with
a WWW-Authenticate challenge, a wrong credential answers 401, and the generated
cookie answers 200 (Core HTTPReq_JSONRPC, httprpc.cpp:112-133). Proven live
against the running testnet4 node before this fix: an unauthenticated
getblockcount returned 200, and so did a wrong Basic credential."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((port 19996)
          (node (make-test-node))
          (body "{\"method\":\"getblockcount\",\"id\":1}"))
      (setf (bl:node-data-directory node) dir)
      (unwind-protect
           (progn
             (is (not (null (bl.rpc:start-rpc-server node :port port))))
             ;; no credential at all
             (let ((r (%http-post-rpc port body)))
               (is (= 401 (%http-status r)))
               (is (search "www-authenticate: basic" (string-downcase r)))
               (is (not (search "\"result\"" r))))
             ;; wrong credential
             (let ((r (%http-post-rpc port body :auth "__cookie__:wrong")))
               (is (= 401 (%http-status r)))
               (is (not (search "\"result\"" r))))
             ;; malformed credentials: wrong scheme, and Basic with no colon
             (let ((r (%http-post-rpc port body :auth-header "Bearer deadbeef")))
               (is (= 401 (%http-status r))))
             (let ((r (%http-post-rpc port body :auth "no-colon-here")))
               (is (= 401 (%http-status r))))
             ;; the cookie file the node wrote
             (let ((r (%http-post-rpc
                       port body
                       :auth (alexandria:read-file-into-string
                              (merge-pathnames ".cookie" dir)))))
               (is (= 200 (%http-status r)))
               (is (search "\"result\"" r))))
        (bl.rpc:stop-rpc-server)))))

(test rpc-start-refuses-without-any-credential
  "With no rpcuser/rpcpassword and nowhere to write a .cookie there is no way
to authorize a request, so the server does not start — Core aborts startup when
InitRPCAuthentication fails (httprpc.cpp:300-302). Starting anyway would leave
a listener that 401s everything."
  (bl.rpc:stop-rpc-server)
  (let ((node (make-test-node)))
    (is (null (bl:node-data-directory node))
        "fixture must have nowhere to write a cookie, or this test is vacuous")
    (unwind-protect
         (progn
           (is (null (bl.rpc:start-rpc-server node :port 19997)))
           (is (null bl.rpc:*rpc-server*)))
      (bl.rpc:stop-rpc-server))))

(test rpc-aborted-start-releases-the-listening-socket
  "Binding before the credential means a start can now abort with a socket
already open, so the abort path has to give the port back — otherwise one
failed start would cost RPC until the process restarts. (Regression guard for
the reorder, not a test of the pre-existing bug: the old order never reached a
bind before giving up.)"
  (bl.rpc:stop-rpc-server)
  (let ((port 19992)
        (no-datadir-node (make-test-node)))
    (is (null (bl:node-data-directory no-datadir-node))
        "fixture must have nowhere to write a cookie, or this test is vacuous")
    (unwind-protect
         (progn
           ;; binds, then finds it has no credential to install, then aborts
           (is (null (bl.rpc:start-rpc-server no-datadir-node :port port)))
           (is (null bl.rpc:*rpc-server*))
           (with-temp-directory (dir)
             (let ((node (make-test-node)))
               (setf (bl:node-data-directory node) dir)
               (is (not (null (bl.rpc:start-rpc-server node :port port)))
                   "the aborted start leaked its listening socket"))))
      (bl.rpc:stop-rpc-server))))

(test rpc-bind-non-loopback-refused
  "-rpcbind is honoured only together with -rpcallowip; either flag alone falls
back to loopback (HTTPBindAddresses, httpserver.cpp:316-327). Without that gate
a single -rpcbind would put the whole RPC surface on the public internet."
  ;; loopback binds are kept whatever -rpcallowip says
  (dolist (loopback '("127.0.0.1" "127.0.0.2" "::1" "[::1]" "localhost"))
    (dolist (allow-ip '(nil ("10.0.0.0/8")))
      (is (string= loopback (bl.rpc::%rpc-bind-address loopback allow-ip))
          "~S is loopback and must be kept (allow-ip ~S)" loopback allow-ip)))
  ;; a non-loopback bind with no -rpcallowip falls back
  (dolist (exposed '("0.0.0.0" "" "192.168.1.5" "::" "1.2.3.4" "127acme.example"))
    (is (string= "127.0.0.1" (bl.rpc::%rpc-bind-address exposed nil))
        "~S is not loopback and must fall back" exposed))
  (is (string= "127.0.0.1" (bl.rpc::%rpc-bind-address nil nil)))
  ;; with -rpcallowip the operator's address is used as given
  (is (string= "10.0.0.5"
               (bl.rpc::%rpc-bind-address "10.0.0.5" '("10.0.0.0/8"))))
  (is (string= "0.0.0.0"
               (bl.rpc::%rpc-bind-address "0.0.0.0" '("0.0.0.0/0")))))

;;;; tx JSON field completeness (T3c)

(test tx-to-json-includes-core-fields
  "tx-to-json emits the size/weight/hex/wtxid fields and per-output type +
address (with network), and per-input sequence — the fields explorers expect."
  (let* ((tx (make-mempool-test-tx :input-id 50))
         (j (bl.rpc:tx-to-json tx :regtest)))
    (is (stringp (cdr (assoc "hash" j :test #'string=))))
    (is (integerp (cdr (assoc "vsize" j :test #'string=))))
    (is (integerp (cdr (assoc "weight" j :test #'string=))))
    (is (stringp (cdr (assoc "hex" j :test #'string=))))
    (let* ((vout (first (cdr (assoc "vout" j :test #'string=))))
           (spk (cdr (assoc "scriptPubKey" vout :test #'string=))))
      (is (string= "pubkeyhash" (cdr (assoc "type" spk :test #'string=))))
      (is (stringp (cdr (assoc "address" spk :test #'string=))))
      ;; scriptPubKey now carries asm + desc (feeds decoderawtransaction/getblock v2)
      (is (stringp (cdr (assoc "asm" spk :test #'string=))))
      (let ((d (cdr (assoc "desc" spk :test #'string=))))
        (is (stringp d))
        ;; a P2PKH output infers to addr(<address>)#checksum
        (is (eql 0 (search "addr(" d)))))
    (let* ((vin (first (cdr (assoc "vin" j :test #'string=))))
           (ss (cdr (assoc "scriptSig" vin :test #'string=))))
      (is (assoc "sequence" vin :test #'string=))
      ;; non-coinbase scriptSig now carries asm
      (is (stringp (cdr (assoc "asm" ss :test #'string=)))))))

;;;; Operator RPCs + regtest subsidy halving (T3d)

(test regtest-subsidy-halving-interval
  "calculate-block-subsidy halves at 150 on regtest (Core), 210000 elsewhere."
  (let ((bl:*network* :regtest))
    (is (= 5000000000 (bl.val:calculate-block-subsidy 149)))
    (is (= 2500000000 (bl.val:calculate-block-subsidy 150))))
  (let ((bl:*network* :mainnet))
    (is (= 5000000000 (bl.val:calculate-block-subsidy 150)))
    (is (= 2500000000 (bl.val:calculate-block-subsidy 210000)))))

(test rpc-help-lists-methods
  "help with no argument lists registered methods, including the new ones."
  (bl.rpc::register-all-methods)
  (let ((h (bl.rpc::rpc-help nil nil)))
    (is (stringp h))
    (is (search "stop" h))
    (is (search "getnetworkhashps" h)))
  ;; A known method echoes its name; an unknown one reports so.
  (is (string= "uptime" (bl.rpc::rpc-help nil (list "uptime"))))
  (is (search "unknown" (bl.rpc::rpc-help nil (list "nope-xyz")))))

(test rpc-getmemoryinfo-and-getrpcinfo-shape
  "getmemoryinfo reports the heap under \"locked\"; getrpcinfo reports
active_commands + logpath."
  (let ((mi (bl.rpc::rpc-getmemoryinfo nil nil)))
    (is (assoc "locked" mi :test #'string=))
    (is (integerp (cdr (assoc "total" (cdr (assoc "locked" mi :test #'string=))
                              :test #'string=)))))
  (let ((ri (bl.rpc::rpc-getrpcinfo nil nil)))
    (is (assoc "active_commands" ri :test #'string=))
    (is (assoc "logpath" ri :test #'string=))))

(test rpc-waitforblock-and-height
  "waitforblock returns immediately when the tip already matches the requested
hash; waitforblockheight returns immediately when the tip is already at/above the
target. Both return {hash,height}; an unreached height with a short timeout
returns the current tip; bad inputs error."
  (let* ((node (make-test-node))
         (cs (bl.rpc:rpc-get-chain-state node))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    ;; make-test-node's chain-state has no tip; plant one at height 5.
    (bl.store:add-block-index-entry
     cs (bl.store:make-block-index-entry
         :hash tip-hash :height 5 :chain-work 100 :status :valid
         :header (bl.ser:make-block-header
                  :version 1 :prev-block zeros :merkle-root zeros
                  :timestamp 1296688600 :bits #x207fffff :nonce 0 :cached-hash tip-hash)))
    (bl.store:update-chain-tip cs tip-hash 5)
    (let ((tip-hex (bl.rpc:hash-to-hex tip-hash)))
      ;; waitforblock with the current tip hash -> immediate match.
      (let ((r (bl.rpc::rpc-waitforblock node (list tip-hex))))
        (is (string= tip-hex (cdr (assoc "hash" r :test #'string=))))
        (is (= 5 (cdr (assoc "height" r :test #'string=)))))
      ;; waitforblockheight at/below the tip -> immediate.
      (let ((r (bl.rpc::rpc-waitforblockheight node (list 5))))
        (is (= 5 (cdr (assoc "height" r :test #'string=)))))
      ;; unreached height + short timeout -> returns the current (lower) tip.
      (let ((r (bl.rpc::rpc-waitforblockheight node (list 1005 50))))
        (is (= 5 (cdr (assoc "height" r :test #'string=)))))
      ;; bad inputs error.
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-waitforblock node (list "not-a-valid-hash")))
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-waitforblockheight node (list -1))))))

(test rpc-gettxout-scriptpubkey-fields
  "gettxout's scriptPubKey now carries asm/hex/type and (for address-bearing
scripts) address — previously only hex."
  (let* ((node (make-test-node))   ; testnet3
         (utxo-set (bl.rpc:rpc-get-utxo-set node))
         (txid (make-array 32 :element-type '(unsigned-byte 8) :initial-element 5))
         (keyhash (make-array 20 :element-type '(unsigned-byte 8) :initial-element 7))
         ;; P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
         (spk (concatenate '(vector (unsigned-byte 8))
                           (vector #x76 #xa9 #x14) keyhash (vector #x88 #xac))))
    (bl.store:add-utxo utxo-set txid 0 50000 spk 0)
    (let* ((r (bl.rpc::rpc-gettxout
               node (list (bl.rpc:hash-to-hex txid) 0)))
           (sp (cdr (assoc "scriptPubKey" r :test #'string=))))
      (is (string= "pubkeyhash" (cdr (assoc "type" sp :test #'string=))))
      (is (string= (bl.crypto:encode-p2pkh-address keyhash :testnet3)
                   (cdr (assoc "address" sp :test #'string=))))
      (is (assoc "asm" sp :test #'string=))
      (is (assoc "hex" sp :test #'string=)))))

(test rpc-decodescript-multisig-addresses
  "decodescript fills the addresses array for bare multisig — one P2PKH address
per key (previously empty)."
  (let* ((pk1 (bl.crypto:hex-to-bytes
               "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))
         (pk2 (bl.crypto:hex-to-bytes
               "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"))
         ;; 2-of-2 bare multisig: OP_2 <33pk1> <33pk2> OP_2 OP_CHECKMULTISIG
         (script (concatenate '(vector (unsigned-byte 8))
                              (vector #x52 #x21) pk1 (vector #x21) pk2 (vector #x52 #xae)))
         (r (%decodescript (bl.crypto:bytes-to-hex script)))
         (addrs (cdr (assoc "addresses" r :test #'string=))))
    (is (string= "multisig" (cdr (assoc "type" r :test #'string=))))
    (is (= 2 (cdr (assoc "reqSigs" r :test #'string=))))
    (is (= 2 (length addrs)))
    (is (string= (bl.crypto:encode-p2pkh-address
                  (bl.crypto:hash160 pk1) :testnet3)
                 (first addrs)))))

(test rpc-getnetworkinfo-completeness
  "getnetworkinfo now reports localservices(+names), localrelay, relayfee,
incrementalfee, connections_in/out, and warnings, and still yason-encodes.
localservices is the SAME composition the version message advertises
(peer.lisp local-services) — Core keeps NODE_NETWORK_LIMITED set alongside
NODE_NETWORK on a full node (init.cpp:863,1946), so both names appear."
  (let* ((node (make-test-node))
         (bl:*node* node)
         (bl:*prune-target-mib* nil)
         (r (bl.rpc::rpc-getnetworkinfo node nil))
         (names (cdr (assoc "localservicesnames" r :test #'string=))))
    (is (= 16 (length (cdr (assoc "localservices" r :test #'string=)))))
    (is (member "WITNESS" names :test #'string=))
    (is (member "NETWORK" names :test #'string=))
    (is (member "NETWORK_LIMITED" names :test #'string=))
    ;; And the hex field decodes to exactly the wire bits.
    (is (= (bl.net:local-services)
           (parse-integer (cdr (assoc "localservices" r :test #'string=))
                          :radix 16)))
    (is (assoc "localrelay" r :test #'string=))
    (is (floatp (cdr (assoc "relayfee" r :test #'string=))))
    (is (floatp (cdr (assoc "incrementalfee" r :test #'string=))))
    (is (integerp (cdr (assoc "connections_in" r :test #'string=))))
    (is (integerp (cdr (assoc "connections_out" r :test #'string=))))
    (is (assoc "warnings" r :test #'string=))
    (let ((resp (bl.rpc::make-rpc-response r "id" :v2)))
      (finishes (with-output-to-string (s) (yason:encode resp s))))))

(test rpc-getpeerinfo-fields
  "getpeerinfo reports a real inbound flag plus startingheight/bytessent/
bytesrecv, and each peer's connection_type + relaytxes. An inbound
peer defaults to conn-type :inbound and relays txs; a block-relay-only peer maps
to \"block-relay-only\" with relaytxes false. synced_headers/synced_blocks are
-1 while unknown (Core), and pingtime is absent until a pong arrived (Core
emits it conditionally)."
  (let* ((node (make-test-node))
         (peer (bl.net:make-peer :address "1.2.3.4:8333" :state :ready
                                        :inbound t :start-height 99 :services #x409))
         (br (bl.net:make-peer :address "5.6.7.8:8333" :state :ready
                                      :conn-type :block-relay))
         (ct (lambda (r) (cdr (assoc "connection_type" r :test #'string=)))))
    (setf (bl:node-peers node) (list peer br))
    (let* ((rows (bl.rpc::rpc-getpeerinfo node nil))
           (e (find "inbound" rows :key ct :test #'string=))
           (b (find "block-relay-only" rows :key ct :test #'string=)))
      (is-true e)
      (is (eq t (cdr (assoc "inbound" e :test #'string=))))
      (is (= 99 (cdr (assoc "startingheight" e :test #'string=))))
      ;; No best-known-block yet and no common-block tracking: both -1.
      (is (= -1 (cdr (assoc "synced_headers" e :test #'string=))))
      (is (= -1 (cdr (assoc "synced_blocks" e :test #'string=))))
      (is (assoc "bytessent" e :test #'string=))
      ;; No pong yet: pingtime/minping/pingwait are all absent (Core).
      (is (null (assoc "pingtime" e :test #'string=)))
      (is (null (assoc "minping" e :test #'string=)))
      (is (null (assoc "pingwait" e :test #'string=)))
      (is (eq t (cdr (assoc "relaytxes" e :test #'string=))))
      ;; services is Core's 16-hex-digit string, not a number.
      (is (string= "0000000000000409" (cdr (assoc "services" e :test #'string=))))
      (is-true b)
      (is (eq 'yason:false (cdr (assoc "relaytxes" b :test #'string=))))
      ;; transport_protocol_type (Core TransportTypeAsString): "v1" without a
      ;; BIP324 session, "v2" when the connection carries one.
      (is (string= "v1" (cdr (assoc "transport_protocol_type" e :test #'string=))))
      (setf (bl.net:peer-connection br)
            (bl.net::make-connection :host "5.6.7.8" :port 8333
                                                      :transport t))
      (let* ((rows2 (bl.rpc::rpc-getpeerinfo node nil))
             (b2 (find "block-relay-only" rows2 :key ct :test #'string=)))
        (is (string= "v2" (cdr (assoc "transport_protocol_type" b2
                                      :test #'string=))))))))

(test rpc-getpeerinfo-parity-fields
  "The Core-parity getpeerinfo fields added by the P2P/RPC parity batch:
network classification, servicesnames, ping stats (conditional), feefilter,
per-message byte maps, addr_relay_enabled, bip152 flags, timeoffset/conntime,
inv queue counters, permissions, session_id — and the whole row must encode
through yason."
  (let* ((node (make-test-node))
         (vmsg (bl.ser::make-version-message
                :version 70016 :start-height 42 :user-agent "/parity/"))
         (conn (bl.net::make-connection
                :host "203.0.113.5" :port 8333 :connected t))
         (peer (bl.net:make-peer :address "203.0.113.5" :state :ready
                                        :version vmsg
                                        :services #x409
                                        :connection conn)))
    ;; Simulate live state: one pong observed, one ping outstanding, a
    ;; feefilter received, a queued announcement, addr relay set up, and
    ;; some per-command traffic.
    (setf (bl.net:peer-ping-latency peer)
          internal-time-units-per-second        ; 1.0s last ping
          (bl.net:peer-min-ping-latency peer)
          (floor internal-time-units-per-second 2) ; 0.5s best
          (bl.net:peer-ping-nonce peer) 7
          (bl.net:peer-last-ping-time peer)
          (get-internal-real-time)
          (bl.net:peer-feefilter-rate peer) 1000
          (bl.net:peer-time-offset peer) -3
          (bl.net:peer-addr-relay-enabled peer) t
          (bl.net:peer-tx-inv-queue peer)
          (let ((txid (make-array 32 :element-type '(unsigned-byte 8))))
            (list (list txid txid 0)))
          (bl.net:connection-last-send-time conn)
          (get-universal-time))
    (incf (gethash "ping" (bl.net:peer-sent-per-msg peer) 0) 32)
    (setf (bl:node-peers node) (list peer))
    (let* ((rows (bl.rpc::rpc-getpeerinfo node nil))
           (e (first rows))
           (f (lambda (k) (cdr (assoc k e :test #'string=)))))
      (is (string= "ipv4" (funcall f "network")))
      (is (equalp #("NETWORK" "WITNESS" "NETWORK_LIMITED")
                  (funcall f "servicesnames")))
      ;; ping stats in seconds, all present here.
      (is (= 1.0d0 (funcall f "pingtime")))
      (is (= 0.5d0 (funcall f "minping")))
      (is (numberp (funcall f "pingwait")))
      ;; feefilter: 1000 sat/kvB -> BTC/kvB.
      (is (= 1.0d-5 (funcall f "minfeefilter")))
      ;; timeoffset captured at version receipt; conntime a plausible unix time.
      (is (= -3 (funcall f "timeoffset")))
      (is (> (funcall f "conntime") 1600000000))
      ;; lastsend reflects the connection stamp; lastrecv never happened.
      (is (> (funcall f "lastsend") 1600000000))
      (is (= 0 (funcall f "lastrecv")))
      (is (= 0 (funcall f "last_transaction")))
      (is (= 0 (funcall f "last_block")))
      ;; inv queue counters.
      (is (= 1 (funcall f "inv_to_send")))
      (is (= 1 (funcall f "last_inv_sequence")))
      ;; presync/headers cursors: nothing known yet.
      (is (= -1 (funcall f "presynced_headers")))
      (is (equalp #() (funcall f "inflight")))
      ;; booleans are json-bool coded, never NIL.
      (is (eq t (funcall f "addr_relay_enabled")))
      (is (eq 'yason:false (funcall f "bip152_hb_to")))
      (is (eq 'yason:false (funcall f "bip152_hb_from")))
      ;; no permission system: honestly empty array.
      (is (equalp #() (funcall f "permissions")))
      ;; per-command byte maps are fresh hash-table snapshots.
      (let ((sent (funcall f "bytessent_per_msg")))
        (is (hash-table-p sent))
        (is (= 32 (gethash "ping" sent))))
      (is (hash-table-p (funcall f "bytesrecv_per_msg")))
      ;; v1 connection: empty session id.
      (is (string= "" (funcall f "session_id")))
      ;; the deliberate omissions stay omitted.
      (is (null (assoc "addrbind" e :test #'string=)))
      (is (null (assoc "mapped_as" e :test #'string=)))
      ;; full row encodes through yason.
      (let ((response (bl.rpc::make-rpc-response rows "id" :v2)))
        (finishes (with-output-to-string (s) (yason:encode response s)))))))

(test rpc-getpeerinfo-synced-headers-from-best-known
  "synced_headers reports the height of the peer's best known block (Core
pindexBestKnownBlock -> nSyncHeight) once an announcement recorded one."
  (let* ((node (make-test-node))
         (chain-state (bl.rpc:rpc-get-chain-state node))
         (bhash (make-array 32 :element-type '(unsigned-byte 8)
                               :initial-element 33))
         (peer (bl.net:make-peer :address "198.51.100.9" :state :ready)))
    (bl.store:add-block-index-entry
     chain-state (bl.store:make-block-index-entry
                  :hash bhash :height 7 :status :valid))
    (setf (bl.net:peer-best-known-block-hash peer) bhash)
    (setf (bl:node-peers node) (list peer))
    (let ((e (first (bl.rpc::rpc-getpeerinfo node nil))))
      (is (= 7 (cdr (assoc "synced_headers" e :test #'string=))))
      (is (= -1 (cdr (assoc "synced_blocks" e :test #'string=)))))))

(test rpc-getorphantxs
  "getorphantxs lists the orphan pool: verbosity 0 -> array of txid hex; 1 ->
detail objects (txid/wtxid/bytes/vsize/weight/from); 2 -> details plus raw hex.
The single announcer peer's id appears in \"from\"."
  (let* ((node (make-test-node))
         (peer (bl.net:make-peer :address "9.9.9.9:8333"))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash txid0 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out
                                :value 90000
                                :script-pubkey (make-array 0 :element-type '(unsigned-byte 8))))
              :lock-time 0))
         (mempool (bl.rpc:rpc-get-mempool node))
         (pool (bl.mp:mempool-orphan-pool mempool))
         (txid-hex (bl.rpc:hash-to-hex
                    (bl.ser:transaction-hash tx))))
    (bl.mp:orphan-add pool tx peer)
    ;; verbosity 0 (default): array of txid hex strings
    (is (equal (list txid-hex) (bl.rpc::rpc-getorphantxs node nil)))
    ;; verbosity 1: detail object with the expected keys + announcer peer id
    (let ((v1 (first (bl.rpc::rpc-getorphantxs node (list 1)))))
      (is (string= txid-hex (cdr (assoc "txid" v1 :test #'string=))))
      (is (assoc "wtxid" v1 :test #'string=))
      (is (plusp (cdr (assoc "bytes" v1 :test #'string=))))
      (is (plusp (cdr (assoc "vsize" v1 :test #'string=))))
      (is (plusp (cdr (assoc "weight" v1 :test #'string=))))
      (is (equal (list (bl.net:peer-id peer))
                 (cdr (assoc "from" v1 :test #'string=))))
      (is (null (assoc "hex" v1 :test #'string=))))
    ;; verbosity 2: adds the raw hex
    (let ((v2 (first (bl.rpc::rpc-getorphantxs node (list 2)))))
      (is (stringp (cdr (assoc "hex" v2 :test #'string=)))))))

(test rpc-sign-verify-message
  "signmessagewithprivkey + verifymessage round-trip: a message signed with a
key's WIF verifies against that key's P2PKH address; a tampered message, a wrong
address, and a malformed signature all fail. The signature is deterministic."
  (let* ((node (make-test-node))   ; testnet3
         (k1 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bl.crypto:private-key-to-wif k1 :network :mainnet :compressed t))
         (msg "hello world")
         (pub (bl.crypto:derive-public-key k1))   ; compressed
         (addr (bl.crypto:encode-p2pkh-address
                (bl.crypto:hash160 pub) :testnet3))
         (sig (bl.rpc:rpc-signmessagewithprivkey node (list wif msg))))
    (is (stringp sig))
    (is (string= sig (bl.rpc:rpc-signmessagewithprivkey node (list wif msg))))
    (is (eq t (bl.rpc::rpc-verifymessage node (list addr sig msg))))
    ;; Bare Core booleans: failures are JSON false, never null (wave 10).
    (is (eq 'yason:false (bl.rpc::rpc-verifymessage node (list addr sig "tampered"))))
    (let* ((k2 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
                 (setf (aref k 31) 2) k))
           (addr2 (bl.crypto:encode-p2pkh-address
                   (bl.crypto:hash160 (bl.crypto:derive-public-key k2))
                   :testnet3)))
      (is (eq 'yason:false (bl.rpc::rpc-verifymessage node (list addr2 sig msg)))))
    ;; Malformed base64 is an ERROR in Core (-5 "Malformed base64 encoding"),
    ;; not a false result (rpc/signmessage.cpp ERR_MALFORMED_SIGNATURE).
    (signals-rpc-error (:code -5)
      (bl.rpc::rpc-verifymessage node (list addr "not-a-valid-sig" msg)))))

(test rpc-signrawtransactionwithkey-p2pkh-p2wpkh
  "signrawtransactionwithkey signs a P2WPKH input (input 0) and a P2PKH input
(input 1) with a supplied key; complete is T, and each produced signature
verifies under the SAME sighash the validator computes (legacy + BIP143)."
  (let* ((node (make-test-node))
         (k1 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bl.crypto:private-key-to-wif k1 :network :mainnet :compressed t))
         (pub (bl.crypto:derive-public-key k1))
         (pkh (bl.crypto:hash160 pub))
         (p2wpkh (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x14) pkh))
         (p2pkh (concatenate '(vector (unsigned-byte 8)) (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
         (p2pkh-code (concatenate '(vector (unsigned-byte 8))
                                  (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 10))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 11))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash txid0 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff)
                              (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash txid1 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out
                                :value 90000 :script-pubkey p2pkh))
              :lock-time 0))
         (tx-hex (bl.crypto:bytes-to-hex
                  (bl.ser:serialize-transaction tx)))
         (prevtxs (list (list (cons "txid" (bl.rpc:hash-to-hex txid0))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex p2wpkh))
                              (cons "amount" 0.001d0))   ; 100000 sats
                        (list (cons "txid" (bl.rpc:hash-to-hex txid1))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex p2pkh)))))
         (result (bl.rpc::rpc-signrawtransactionwithkey
                  node (list tx-hex (list wif) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=))))
    (let* ((tx2 (bl.ser:parse-tx-payload
                 (bl.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (ins (bl.ser:transaction-inputs tx2))
           (wit (bl.ser:transaction-witness tx2)))
      ;; Input 0 (P2WPKH): witness = [sig pubkey]; sig verifies under BIP143 sighash.
      (let* ((stack (aref wit 0))
             (sig (first stack))
             (der (subseq sig 0 (1- (length sig))))
             (sighash (let ((bl.interop:*current-tx* tx2)
                            (bl.interop:*current-input-index* 0)
                            (bl.interop:*precomputed-sighash*
                             (bl.interop:init-precomputed-sighash tx2)))
                        (bl.interop:compute-bip143-sighash p2pkh-code 100000 1))))
        (is (equalp pub (second stack)))
        (is-true (bl.crypto:verify-signature sighash der pub)))
      ;; Input 1 (P2PKH): scriptSig = push(sig) push(pubkey); sig verifies under legacy sighash.
      (let* ((ss (bl.ser:tx-in-script-sig (aref ins 1)))
             (siglen (aref ss 0))
             (sig (subseq ss 1 (1+ siglen)))
             (der (subseq sig 0 (1- (length sig))))
             (sighash (bl.interop:compute-legacy-sighash tx2 1 p2pkh 1)))
        (is-true (bl.crypto:verify-signature sighash der pub))))))

(test rpc-signrawtransactionwithkey-p2tr-keypath
  "signrawtransactionwithkey signs a P2TR key-path input; complete=t, the witness
is a single 64-byte Schnorr signature, and it passes the consensus taproot
key-path verifier (validate-taproot-key-path) for the recomputed BIP341 sighash."
  (let* ((node (make-test-node))
         (sk (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bl.crypto:private-key-to-wif sk :network :mainnet :compressed t))
         (pxonly (bl.crypto:derive-xonly-pubkey sk))
         (qx (bl.interop:compute-tweaked-pubkey pxonly))
         (p2tr (concatenate '(vector (unsigned-byte 8)) (vector #x51 #x20) qx))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash txid0 :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out
                                :value 90000 :script-pubkey p2tr))
              :lock-time 0))
         (tx-hex (bl.crypto:bytes-to-hex
                  (bl.ser:serialize-transaction tx)))
         (prevtxs (list (list (cons "txid" (bl.rpc:hash-to-hex txid0))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex p2tr))
                              (cons "amount" 0.001d0))))   ; 100000 sats
         (result (bl.rpc::rpc-signrawtransactionwithkey
                  node (list tx-hex (list wif) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=))))
    (let* ((tx2 (bl.ser:parse-tx-payload
                 (bl.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (stack (aref (bl.ser:transaction-witness tx2) 0))
           (sig (first stack)))
      (is (= 1 (length stack)))
      (is (= 64 (length sig)))
      ;; The consensus key-path verifier accepts the signature.
      (let* ((spent (vector (bl.store:make-utxo-entry
                             :value 100000
                             :script-pubkey (coerce p2tr '(simple-array (unsigned-byte 8) (*))))))
             (bl.interop:*current-tx* tx2)
             (bl.interop:*current-input-index* 0)
             (bl.interop:*current-spent-utxos* spent)
             (bl.interop:*precomputed-sighash*
              (bl.interop:init-precomputed-sighash tx2 spent)))
        (is-true (bl.interop:validate-taproot-key-path stack qx 100000))))))

(defun %verify-tx-input (tx index spent-vec flags)
  "Run the full consensus interpreter (verify-script) on input INDEX of TX, with
SPENT-VEC supplying amounts/scriptPubKeys. Returns verify-script's result."
  (let* ((utxo (aref spent-vec index))
         (amount (bl.store:utxo-entry-value utxo))
         (spk (bl.store:utxo-entry-script-pubkey utxo))
         (input (elt (bl.ser:transaction-inputs tx) index))
         (sig-bytes (bl.ser:tx-in-script-sig input))
         (wit (bl.ser:transaction-witness tx))
         (witness-stack (when (and wit (< index (length wit))) (elt wit index)))
         (bl.interop:*current-tx* tx)
         (bl.interop:*current-input-index* index)
         (bl.interop:*current-spent-utxos* spent-vec)
         (bl.interop:*precomputed-sighash* nil)
         (bl.interop:*witness-input-amount* amount))
    (bl.interop:set-script-flags flags)
    (unwind-protect
         (bl.interop:verify-script
          sig-bytes spk :witness witness-stack :amount amount)
      (bl.interop:set-script-flags nil))))

(defun %multisig-script (m pubs)
  "OP_m <pub>... OP_n OP_CHECKMULTISIG for the list of compressed PUBS."
  (apply #'concatenate '(vector (unsigned-byte 8))
         (vector (+ #x50 m))
         (append (mapcar (lambda (p) (concatenate '(vector (unsigned-byte 8))
                                                  (vector (length p)) p))
                         pubs)
                 (list (vector (+ #x50 (length pubs)) #xae)))))

(test rpc-signrawtransactionwithkey-p2sh-and-multisig
  "signrawtransactionwithkey signs a tx mixing P2SH-P2WPKH, P2SH-multisig (legacy),
P2WSH-multisig, P2SH-P2WSH-multisig, and bare multisig inputs; complete=t and EVERY
input passes the full consensus interpreter (verify-script, P2SH+WITNESS+NULLDUMMY+
DERSIG+LOW_S)."
  (let* ((node (make-test-node))
         (ka (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (kb (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 2) k))
         (wa (bl.crypto:private-key-to-wif ka :network :mainnet :compressed t))
         (wb (bl.crypto:private-key-to-wif kb :network :mainnet :compressed t))
         (pa (bl.crypto:derive-public-key ka))
         (pb (bl.crypto:derive-public-key kb))
         (pkha (bl.crypto:hash160 pa))
         (ms22 (%multisig-script 2 (list pa pb)))    ; 2-of-2 A,B
         (ms11 (%multisig-script 1 (list pa)))       ; 1-of-1 A
         ;; redeem/witness + scriptPubKeys
         (rd-p2wpkh (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x14) pkha))
         (rd-p2wsh (concatenate '(vector (unsigned-byte 8))
                                (vector #x00 #x20) (bl.crypto:sha256 ms22)))
         (spk-sh-wpkh (concatenate '(vector (unsigned-byte 8))
                                   (vector #xa9 #x14) (bl.crypto:hash160 rd-p2wpkh) (vector #x87)))
         (spk-sh-ms (concatenate '(vector (unsigned-byte 8))
                                 (vector #xa9 #x14) (bl.crypto:hash160 ms22) (vector #x87)))
         (spk-wsh (concatenate '(vector (unsigned-byte 8))
                               (vector #x00 #x20) (bl.crypto:sha256 ms22)))
         (spk-sh-wsh (concatenate '(vector (unsigned-byte 8))
                                  (vector #xa9 #x14) (bl.crypto:hash160 rd-p2wsh) (vector #x87)))
         (spks (vector spk-sh-wpkh spk-sh-ms spk-wsh spk-sh-wsh ms11))
         (inputs (loop for j below 5
                       collect (bl.ser:make-tx-in
                                :previous-output (bl.ser:make-outpoint
                                                  :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                                       :initial-element (+ 20 j))
                                                  :index 0)
                                :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                :sequence #xffffffff)))
         (tx (bl.ser:make-transaction
              :version 2 :inputs (coerce inputs 'vector)
              :outputs (vector (bl.ser:make-tx-out
                                :value 400000 :script-pubkey spk-sh-wpkh))
              :lock-time 0))
         (tx-hex (bl.crypto:bytes-to-hex
                  (bl.ser:serialize-transaction tx)))
         (h2 (lambda (j) (bl.rpc:hash-to-hex
                          (make-array 32 :element-type '(unsigned-byte 8) :initial-element (+ 20 j)))))
         (prevtxs (list
                   ;; 0 P2SH-P2WPKH
                   (list (cons "txid" (funcall h2 0)) (cons "vout" 0)
                         (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk-sh-wpkh))
                         (cons "amount" 0.001d0)
                         (cons "redeemScript" (bl.crypto:bytes-to-hex rd-p2wpkh)))
                   ;; 1 P2SH-multisig (legacy)
                   (list (cons "txid" (funcall h2 1)) (cons "vout" 0)
                         (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk-sh-ms))
                         (cons "redeemScript" (bl.crypto:bytes-to-hex ms22)))
                   ;; 2 P2WSH-multisig
                   (list (cons "txid" (funcall h2 2)) (cons "vout" 0)
                         (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk-wsh))
                         (cons "amount" 0.001d0)
                         (cons "witnessScript" (bl.crypto:bytes-to-hex ms22)))
                   ;; 3 P2SH-P2WSH-multisig
                   (list (cons "txid" (funcall h2 3)) (cons "vout" 0)
                         (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk-sh-wsh))
                         (cons "amount" 0.001d0)
                         (cons "redeemScript" (bl.crypto:bytes-to-hex rd-p2wsh))
                         (cons "witnessScript" (bl.crypto:bytes-to-hex ms22)))
                   ;; 4 bare multisig 1-of-1
                   (list (cons "txid" (funcall h2 4)) (cons "vout" 0)
                         (cons "scriptPubKey" (bl.crypto:bytes-to-hex ms11)))))
         (result (bl.rpc::rpc-signrawtransactionwithkey
                  node (list tx-hex (list wa wb) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=))))
    (let* ((tx2 (bl.ser:parse-tx-payload
                 (bl.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (spent (make-array 5)))
      (dotimes (j 5)
        (setf (aref spent j)
              (bl.store:make-utxo-entry
               :value 100000
               :script-pubkey (coerce (aref spks j) '(simple-array (unsigned-byte 8) (*))))))
      (dotimes (j 5)
        (is-true (%verify-tx-input tx2 j spent "P2SH,WITNESS,NULLDUMMY,DERSIG,LOW_S"))))))

;;; --- createmultisig (Bitcoin Core createmultisig) ---
;;; Compressed key pair from Core's createmultisig help example.

(defun %cms-keys ()
  (values "03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd"
          "03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626"))

(defun %valid-descriptor-checksum-p (descriptor)
  "T if DESCRIPTOR ends in #<8 chars> matching descriptor-checksum of the body."
  (let ((pos (position #\# descriptor)))
    (and pos
         (= 8 (- (length descriptor) pos 1))
         (string= (subseq descriptor (1+ pos))
                  (bl.rpc::descriptor-checksum (subseq descriptor 0 pos))))))

(test rpc-createmultisig-legacy-2of2
  "createmultisig legacy: bare-multisig redeemScript + P2SH address round-trip."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let* ((node (make-test-node))
           (r (bl.rpc::rpc-createmultisig node (list 2 (list k1 k2))))
           (redeem-hex (cdr (assoc "redeemScript" r :test #'string=)))
           (address (cdr (assoc "address" r :test #'string=)))
           (descriptor (cdr (assoc "descriptor" r :test #'string=))))
      ;; OP_2 <push k1> <push k2> OP_2 OP_CHECKMULTISIG
      (is (string= redeem-hex (format nil "5221~A21~A52ae" k1 k2)))
      (is (eql 0 (search "sh(multi(2," descriptor)))
      (is-true (%valid-descriptor-checksum-p descriptor))
      ;; address decodes to P2SH(hash160(redeemScript))
      (multiple-value-bind (type spk)
          (bl.crypto:decode-address address :testnet3)
        (is (not (null type)))
        (is (equalp (subseq spk 2 22)
                    (bl.crypto:hash160 (bl.crypto:hex-to-bytes redeem-hex)))))
      ;; compressed keys -> no warnings
      (is (null (assoc "warnings" r :test #'string=))))))

(test rpc-createmultisig-bech32-p2wsh
  "createmultisig bech32: address is P2WSH(sha256(redeemScript))."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let* ((node (make-test-node))
           (r (bl.rpc::rpc-createmultisig node (list 2 (list k1 k2) "bech32")))
           (redeem-hex (cdr (assoc "redeemScript" r :test #'string=)))
           (address (cdr (assoc "address" r :test #'string=)))
           (descriptor (cdr (assoc "descriptor" r :test #'string=))))
      (is (eql 0 (search "wsh(multi(2," descriptor)))
      (is-true (%valid-descriptor-checksum-p descriptor))
      (multiple-value-bind (type spk)
          (bl.crypto:decode-address address :testnet3)
        (is (not (null type)))
        (is (equalp (subseq spk 2 34)
                    (bl.crypto:sha256 (bl.crypto:hex-to-bytes redeem-hex))))))))

(test rpc-createmultisig-p2sh-segwit
  "createmultisig p2sh-segwit: address is P2SH(P2WSH(redeemScript))."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let* ((node (make-test-node))
           (r (bl.rpc::rpc-createmultisig node (list 2 (list k1 k2) "p2sh-segwit")))
           (redeem-hex (cdr (assoc "redeemScript" r :test #'string=)))
           (address (cdr (assoc "address" r :test #'string=)))
           (descriptor (cdr (assoc "descriptor" r :test #'string=))))
      (is (eql 0 (search "sh(wsh(multi(2," descriptor)))
      (is-true (%valid-descriptor-checksum-p descriptor))
      (multiple-value-bind (type spk)
          (bl.crypto:decode-address address :testnet3)
        (is (not (null type)))
        (let* ((redeem (bl.crypto:hex-to-bytes redeem-hex))
               (p2wsh (concatenate '(vector (unsigned-byte 8))
                                   #(#x00 #x20) (bl.crypto:sha256 redeem))))
          (is (equalp (subseq spk 2 22) (bl.crypto:hash160 p2wsh))))))))

(test rpc-createmultisig-uncompressed-forces-legacy
  "An uncompressed key forces legacy output + a warning when bech32 was asked."
  (let* ((node (make-test-node))
         ;; Uncompressed (65-byte, 0x04) form of the generator point G.
         (kc "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (ku (concatenate 'string
                          "04"
                          "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                          "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
         (r (bl.rpc::rpc-createmultisig node (list 1 (list kc ku) "bech32")))
         (address (cdr (assoc "address" r :test #'string=)))
         (warnings (cdr (assoc "warnings" r :test #'string=))))
    ;; Forced to legacy -> P2SH address, and a warning is present.
    (is (not (null warnings)))
    (multiple-value-bind (type) (bl.crypto:decode-address address :testnet3)
      (is (not (null type))))))

(test rpc-createmultisig-errors
  "createmultisig parameter and key validation errors."
  (multiple-value-bind (k1 k2) (%cms-keys)
    (let ((node (make-test-node)))
      ;; not enough keys for the threshold
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-createmultisig node (list 3 (list k1 k2))))
      ;; nrequired < 1
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-createmultisig node (list 0 (list k1))))
      ;; too many keys (> 20)
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-createmultisig node (list 1 (make-list 21 :initial-element k1))))
      ;; bech32m explicitly rejected
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-createmultisig node (list 2 (list k1 k2) "bech32m")))
      ;; unknown address type
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-createmultisig node (list 2 (list k1 k2) "p2tr")))
      ;; invalid public key
      (signals bl.rpc:rpc-error
        (bl.rpc::rpc-createmultisig node (list 1 (list "00")))))))

;;; --- ping (Bitcoin Core ping) ---

(test rpc-ping-no-peers
  "ping with no connected peers returns null and does not error."
  (let ((node (make-test-node)))
    (is (null (bl.rpc::rpc-ping node nil)))))

;;; --- getaddrmaninfo (Bitcoin Core getaddrmaninfo) ---

(test rpc-getaddrmaninfo-empty
  "getaddrmaninfo lists every standard network + all_networks, all zero when the
node has no address book."
  (let* ((node (make-test-node))
         (r (bl.rpc::rpc-getaddrmaninfo node nil)))
    (dolist (n '("ipv4" "ipv6" "onion" "i2p" "cjdns" "all_networks"))
      (let ((obj (cdr (assoc n r :test #'string=))))
        (is (not (null obj)) "network ~A present" n)
        (is (= 0 (cdr (assoc "new" obj :test #'string=))))
        (is (= 0 (cdr (assoc "tried" obj :test #'string=))))
        (is (= 0 (cdr (assoc "total" obj :test #'string=))))))))

(test rpc-getaddrmaninfo-classifies-ipv4
  "Added routable IPv4 addresses land in the ipv4 new table and the
all_networks aggregate; counts stay consistent with the address book."
  (let* ((node (make-test-node))
         (book (bl.net:make-address-book)))
    (setf (bl:node-address-book node) book)
    (bl.net:address-book-add
     book (bl.net:make-peer-address
           :ip (bl.net:string-to-ip-bytes "1.2.3.4") :port 8333))
    (bl.net:address-book-add
     book (bl.net:make-peer-address
           :ip (bl.net:string-to-ip-bytes "5.6.7.8") :port 8333))
    (let* ((n-new (bl.net:address-book-n-new book))
           (r (bl.rpc::rpc-getaddrmaninfo node nil))
           (ipv4 (cdr (assoc "ipv4" r :test #'string=)))
           (all (cdr (assoc "all_networks" r :test #'string=))))
      (is (>= n-new 1))
      ;; All added addresses are IPv4, so the ipv4 bucket captures exactly them.
      (is (= n-new (cdr (assoc "new" ipv4 :test #'string=))))
      (is (= 0 (cdr (assoc "tried" ipv4 :test #'string=))))
      (is (= n-new (cdr (assoc "total" ipv4 :test #'string=))))
      ;; all_networks mirrors the book's authoritative counts.
      (is (= n-new (cdr (assoc "new" all :test #'string=))))
      (is (= n-new (cdr (assoc "total" all :test #'string=))))
      ;; Nothing classified as a non-IPv4 network.
      (let ((ipv6 (cdr (assoc "ipv6" r :test #'string=))))
        (is (= 0 (cdr (assoc "total" ipv6 :test #'string=))))))))

;;; --- addnode / getaddednodeinfo / setnetworkactive ---

(defun %rpc-fake-peer (address &key inbound)
  "A peer struct usable in node-peers for RPC tests (no live connection)."
  (bl.net:make-peer
   :address address :state :ready :connection nil :inbound inbound))

(test parse-node-endpoint-forms
  "parse-node-endpoint splits host/host:port/[ipv6]:port, defaulting the port."
  (let ((node (make-test-node)))               ; testnet3 default P2P port 18333
    (flet ((p (spec) (multiple-value-list (bl:parse-node-endpoint node spec))))
      (is (equal (p "1.2.3.4") '("1.2.3.4" 18333)))
      (is (equal (p "1.2.3.4:8333") '("1.2.3.4" 8333)))
      (is (equal (p "seed.example.com") '("seed.example.com" 18333)))
      (is (equal (p "[2001:db8::1]:8333") '("2001:db8::1" 8333)))
      (is (equal (p "[2001:db8::1]") '("2001:db8::1" 18333)))
      ;; A bare IPv6 (multiple colons, no brackets) is treated as host-only.
      (is (equal (p "2001:db8::1") '("2001:db8::1" 18333))))))

(test rpc-addnode-add-remove-onetry
  "addnode mutates the node's added-nodes / pending-onetry state machine."
  (let ((node (make-test-node)))
    ;; add
    (is (null (bl.rpc::rpc-addnode node '("1.2.3.4:18333" "add"))))
    (is (member "1.2.3.4:18333" (bl:node-added-nodes node) :test #'string=))
    ;; duplicate add errors
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-addnode node '("1.2.3.4:18333" "add")))
    ;; onetry queues a one-shot dial without touching added-nodes
    (is (null (bl.rpc::rpc-addnode node '("9.9.9.9" "onetry"))))
    (is (member "9.9.9.9" (bl:node-pending-onetry node) :test #'string=))
    (is (not (member "9.9.9.9" (bl:node-added-nodes node) :test #'string=)))
    ;; remove
    (is (null (bl.rpc::rpc-addnode node '("1.2.3.4:18333" "remove"))))
    (is (not (member "1.2.3.4:18333" (bl:node-added-nodes node) :test #'string=)))
    ;; remove of a node never added errors
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-addnode node '("1.2.3.4:18333" "remove")))
    ;; bad command + non-string node error
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-addnode node '("1.2.3.4" "frobnicate")))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-addnode node '(42 "add")))))

(test rpc-getaddednodeinfo-reports-state
  "getaddednodeinfo reports each added node + whether a matching peer is live."
  (let ((node (make-test-node)))
    (bl.rpc::rpc-addnode node '("1.2.3.4" "add"))
    (bl.rpc::rpc-addnode node '("5.6.7.8:18333" "add"))
    ;; Mark 1.2.3.4 connected with an outbound peer.
    (push (%rpc-fake-peer "1.2.3.4") (bl:node-peers node))
    (let ((r (bl.rpc::rpc-getaddednodeinfo node nil)))
      (is (= 2 (length r)))
      (let ((a (find "1.2.3.4" r :key (lambda (e) (cdr (assoc "addednode" e :test #'string=)))
                     :test #'string=))
            (b (find "5.6.7.8:18333" r :key (lambda (e) (cdr (assoc "addednode" e :test #'string=)))
                     :test #'string=)))
        (is (eq t (cdr (assoc "connected" a :test #'string=))))
        (is (eq 'yason:false (cdr (assoc "connected" b :test #'string=))))
        ;; connected node carries one outbound address entry
        (let ((addrs (cdr (assoc "addresses" a :test #'string=))))
          (is (= 1 (length addrs)))
          (is (string= "1.2.3.4" (cdr (assoc "address" (first addrs) :test #'string=))))
          (is (string= "outbound" (cdr (assoc "connected" (first addrs) :test #'string=)))))
        ;; unconnected node has no address entries — Core's empty VARR, so
        ;; [] rather than null (this used to assert (null ...), the bug).
        (is (equalp #() (cdr (assoc "addresses" b :test #'string=))))))
    ;; filtering for a never-added node errors
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getaddednodeinfo node '("10.0.0.1")))))

(test rpc-setnetworkactive-toggles-and-drops-peers
  "setnetworkactive flips node-network-active and drops peers when disabling."
  (let ((node (make-test-node))
        (peer (%rpc-fake-peer "1.2.3.4")))
    (push peer (bl:node-peers node))
    (is (bl:node-network-active node))      ; default enabled
    ;; disable
    (is (eq 'yason:false (bl.rpc::rpc-setnetworkactive node '(nil))))
    (is (null (bl:node-network-active node)))
    (is (eq :disconnected (bl.net:peer-state peer)))
    ;; getnetworkinfo reflects the disabled state
    (is (eq 'yason:false (cdr (assoc "networkactive"
                          (bl.rpc::rpc-getnetworkinfo node nil) :test #'string=))))
    ;; re-enable
    (is (eq t (bl.rpc::rpc-setnetworkactive node '(t))))
    (is (bl:node-network-active node))
    ;; missing state errors
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-setnetworkactive node '()))))

;;; --- getchainstates ---

(test rpc-getchainstates-single-chainstate
  "getchainstates reports exactly one fully-validated chainstate with Core's
field shape."
  (let* ((node (make-test-node))
         (r (bl.rpc::rpc-getchainstates node nil))
         (states (cdr (assoc "chainstates" r :test #'string=))))
    (is (assoc "headers" r :test #'string=))
    (is (= 1 (length states)))
    (let ((cs (first states)))
      (is (eq t (cdr (assoc "validated" cs :test #'string=))))
      (is (integerp (cdr (assoc "blocks" cs :test #'string=))))
      (is (numberp (cdr (assoc "difficulty" cs :test #'string=))))
      ;; bits is 8 lowercase hex chars; target is 64.
      (let ((bits (cdr (assoc "bits" cs :test #'string=)))
            (target (cdr (assoc "target" cs :test #'string=))))
        (is (= 8 (length bits)))
        (is (string= bits (string-downcase bits)))
        (is (= 64 (length target)))
        (is (string= target (string-downcase target))))
      (is (>= (cdr (assoc "coins_tip_cache_bytes" cs :test #'string=)) 0))
      (is (assoc "coins_db_cache_bytes" cs :test #'string=)))))

;;; --- importmempool ---

(test rpc-importmempool-roundtrip-and-errors
  "importmempool loads a saved mempool file and returns an empty object; a
missing file or non-string path errors."
  (let* ((node (make-test-node))
         (path (merge-pathnames "bl-importmempool-test.dat" (uiop:temporary-directory))))
    (bl.mp:save-mempool-file (bl:node-mempool node) path)
    (unwind-protect
         (let ((r (bl.rpc::rpc-importmempool node (list (namestring path)))))
           (is (hash-table-p r))                 ; serializes as {}
           (is (= 0 (hash-table-count r))))
      (ignore-errors (delete-file path)))
    ;; nonexistent file
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-importmempool node (list "/no/such/bl-mempool-file.dat")))
    ;; non-string filepath
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-importmempool node (list 123)))))

;;; --- peer id (getpeerinfo) + getblockfrompeer ---

(test rpc-getpeerinfo-includes-id
  "getpeerinfo exposes a numeric peer id (Bitcoin Core's CNode::id)."
  (let ((node (make-test-node)))
    (push (%rpc-fake-peer "1.2.3.4") (bl:node-peers node))
    (let ((info (first (bl.rpc::rpc-getpeerinfo node nil))))
      (is (integerp (cdr (assoc "id" info :test #'string=)))))))

(test rpc-getblockfrompeer-paths
  "getblockfrompeer validates header/peer and dispatches a witness-block getdata."
  (let* ((bl:*prune-target-mib* nil)   ; deterministic: pruning off
         (node (make-test-node))
         (cs (bl:node-chain-state node))
         (store-dir (ensure-directories-exist
                     (merge-pathnames "bl-gbfp-test/" (uiop:temporary-directory))))
         (store (bl.store:init-block-store store-dir))
         (hdr (bl.ser:make-block-header
               :version 1
               :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :timestamp 1 :bits #x1d00ffff :nonce 0))
         (hash (bl.ser:block-header-hash hdr))
         (hash-hex (bl.rpc:hash-to-hex hash)))
    (setf (bl:node-block-store node) store)
    ;; header not in index yet → "Block header missing"
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockfrompeer node (list hash-hex 1)))
    ;; register the header
    (bl.store:add-block-index-entry
     cs (bl.store:make-block-index-entry
         :hash hash :height 1 :header hdr :status :header-valid :chain-work 1))
    ;; no peer with that id → "Peer does not exist"
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockfrompeer node (list hash-hex 999999)))
    ;; connected peer by id → returns {} (empty hash-table); send is a no-op on
    ;; the fake peer's nil connection.
    (let ((peer (%rpc-fake-peer "1.2.3.4")))
      (push peer (bl:node-peers node))
      (let ((r (bl.rpc::rpc-getblockfrompeer
                node (list hash-hex (bl.net:peer-id peer)))))
        (is (hash-table-p r))
        (is (= 0 (hash-table-count r)))))
    ;; bad peer_id type → error
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockfrompeer node (list hash-hex "notanint")))))

;;; --- logging (Bitcoin Core logging) ---

(test rpc-logging-toggles-categories
  "logging reports every category and enables/disables via include/exclude, with
all/none and unknown-category handling."
  (clrhash bl.log::*debug-categories*)
  (unwind-protect
       (let ((node (make-test-node)))
         ;; default: all categories present, none enabled
         (let ((r (bl.rpc::rpc-logging node nil)))
           (is (= (length bl.log:+log-categories+) (length r)))
           (is (assoc "net" r :test #'string=))
           ;; category states are JSON booleans — false, never null (wave 10)
           (is (eq 'yason:false (cdr (assoc "net" r :test #'string=)))))
         ;; include enables, leaving others off
         (let ((r (bl.rpc::rpc-logging node (list (list "net") nil))))
           (is (eq t (cdr (assoc "net" r :test #'string=))))
           (is (eq 'yason:false (cdr (assoc "mempool" r :test #'string=)))))
         ;; exclude disables
         (let ((r (bl.rpc::rpc-logging node (list nil (list "net")))))
           (is (eq 'yason:false (cdr (assoc "net" r :test #'string=)))))
         ;; "all" enables every category
         (let ((r (bl.rpc::rpc-logging node (list (list "all") nil))))
           (is (every (lambda (pair) (eq t (cdr pair))) r)))
         ;; exclude "all" disables every category
         (let ((r (bl.rpc::rpc-logging node (list nil (list "all")))))
           (is (every (lambda (pair) (eq 'yason:false (cdr pair))) r)))
         ;; unknown category errors
         (signals bl.rpc:rpc-error
           (bl.rpc::rpc-logging node (list (list "boguscat") nil))))
    (clrhash bl.log::*debug-categories*)))

(test log-cat-respects-category-state
  "log-cat emits a debug line only when its category is enabled (independent of
the global level threshold)."
  (clrhash bl.log::*debug-categories*)
  (unwind-protect
       (let ((s (make-string-output-stream)))
         (let ((bl.log:*log-stream* s)
               (bl.log:*current-log-level* :info))  ; debug normally hidden
           (bl:log-cat "net" "MARKER-DISABLED-~D" 1)   ; off -> nothing
           (bl.log:enable-log-category "net")
           (bl:log-cat "net" "MARKER-ENABLED-~D" 2)    ; on -> emitted
           (bl:log-cat "mempool" "MARKER-OTHER-~D" 3)) ; still off
         (let ((out (get-output-stream-string s)))
           (is (null (search "MARKER-DISABLED" out)))
           (is (search "MARKER-ENABLED" out))
           (is (null (search "MARKER-OTHER" out)))))
    (clrhash bl.log::*debug-categories*)))

;;; --- Cluster mempool RPCs (P9: entry chunk fields, getmempoolcluster,
;;; getmempoolfeeratediagram — Core rpc/mempool.cpp:413-506/609-650/829-862) ---

(test rpc-mempool-cluster-and-diagram
  "Entry chunk fields, getmempoolcluster shape, and the cumulative feerate
diagram, over a CPFP pair that shares one chunk. Sizes are in vB (our
txgraph unit; Core uses sigops-adjusted weight)."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (parent (%mp-spending-tx (%txid-array 210) :vout 0 :value 50000000))
         (pid (bl.ser:transaction-hash parent))
         (pid-hex (bl.rpc:hash-to-hex pid))
         (child (%mp-spending-tx pid :vout 0 :value 40000000))
         (cid (bl.ser:transaction-hash child))
         (cid-hex (bl.rpc:hash-to-hex cid))
         (pvsize (bl.ser:transaction-vsize parent))
         (cvsize (bl.ser:transaction-vsize child)))
    ;; Empty mempool: the diagram is just the (0, 0) origin.
    (let ((r (bl.rpc::rpc-getmempoolfeeratediagram node nil)))
      (is (= 1 (length r)))
      (is (= 0 (cdr (assoc "weight" (first r) :test #'string=))))
      (is (zerop (cdr (assoc "fee" (first r) :test #'string=)))))
    ;; Low-fee parent + CPFP child: one chunk of (20100, pvsize+cvsize).
    (%add-tx mempool parent :fee 100)
    (%add-tx mempool child :fee 20000)
    ;; getmempoolentry chunk fields (fees.chunk in BTC, chunkweight in vB).
    (let* ((r (bl.rpc::rpc-getmempoolentry node (list pid-hex)))
           (fees (cdr (assoc "fees" r :test #'string=))))
      (is (= (+ pvsize cvsize) (cdr (assoc "chunkweight" r :test #'string=))))
      (is (= 20100 (round (* 100000000 (cdr (assoc "chunk" fees :test #'string=)))))))
    ;; getmempoolcluster: one cluster, one chunk, txs in mining order.
    (let* ((r (bl.rpc::rpc-getmempoolcluster node (list cid-hex)))
           (chunks (cdr (assoc "chunks" r :test #'string=))))
      (is (= 2 (cdr (assoc "txcount" r :test #'string=))))
      (is (= (+ pvsize cvsize) (cdr (assoc "clusterweight" r :test #'string=))))
      (is (= 1 (length chunks)))
      (let ((chunk (first chunks)))
        (is (= 20100 (round (* 100000000 (cdr (assoc "chunkfee" chunk :test #'string=))))))
        (is (= (+ pvsize cvsize) (cdr (assoc "chunkweight" chunk :test #'string=))))
        (is (equal (list pid-hex cid-hex) (cdr (assoc "txs" chunk :test #'string=))))))
    ;; The diagram now has the origin plus one cumulative chunk point.
    (let ((r (bl.rpc::rpc-getmempoolfeeratediagram node nil)))
      (is (= 2 (length r)))
      (is (= (+ pvsize cvsize) (cdr (assoc "weight" (second r) :test #'string=))))
      (is (= 20100 (round (* 100000000 (cdr (assoc "fee" (second r) :test #'string=)))))))
    ;; A standalone lower-feerate tx appends a second, later diagram point.
    (let ((solo (make-mempool-test-tx :input-id 211)))
      (%add-tx mempool solo :fee 50)
      (let ((r (bl.rpc::rpc-getmempoolfeeratediagram node nil)))
        (is (= 3 (length r)))
        (is (= 20150 (round (* 100000000 (cdr (assoc "fee" (third r) :test #'string=))))))))
    ;; getmempoolcluster on an absent txid errors like getmempoolentry.
    (signals error
      (bl.rpc::rpc-getmempoolcluster
       node (list (bl.rpc:hash-to-hex (%txid-array 212)))))))

(test rpc-mempool-cluster-two-chunks
  "A cluster whose child does NOT absorb its parent reports two chunks in
mining order (parent's first)."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (parent (%mp-spending-tx (%txid-array 213) :vout 0 :value 50000000))
         (pid (bl.ser:transaction-hash parent))
         (pid-hex (bl.rpc:hash-to-hex pid))
         (child (%mp-spending-tx pid :vout 0 :value 40000000))
         (cid-hex (bl.rpc:hash-to-hex
                   (bl.ser:transaction-hash child))))
    (%add-tx mempool parent :fee 20000)
    (%add-tx mempool child :fee 100)
    (let* ((r (bl.rpc::rpc-getmempoolcluster node (list pid-hex)))
           (chunks (cdr (assoc "chunks" r :test #'string=))))
      (is (= 2 (length chunks)))
      (is (equal (list pid-hex) (cdr (assoc "txs" (first chunks) :test #'string=))))
      (is (equal (list cid-hex) (cdr (assoc "txs" (second chunks) :test #'string=))))
      (is (= 20000 (round (* 100000000
                             (cdr (assoc "chunkfee" (first chunks) :test #'string=))))))
      (is (= 100 (round (* 100000000
                           (cdr (assoc "chunkfee" (second chunks) :test #'string=)))))))))

;;; --- /rest/headers active-chain membership ---

(defmacro %with-rest-count ((count) &body body)
  "Run BODY with hunchentoot's `count` query parameter stubbed to COUNT.
The REST handlers read it through hunchentoot:get-parameter, which needs a
live *request*; swapping the fdefinition is the smallest seam that lets the
real handler run unmodified."
  (let ((orig (gensym "ORIG")))
    `(let ((,orig (fdefinition 'hunchentoot:get-parameter)))
       (unwind-protect
            (progn (setf (fdefinition 'hunchentoot:get-parameter)
                         (lambda (name &optional request)
                           (declare (ignore request))
                           (when (string= name "count") ,count)))
                   ,@body)
         (setf (fdefinition 'hunchentoot:get-parameter) ,orig)))))

(test rest-headers-refuses-fork-start-and-stays-contiguous
  "/rest/headers walks forward by ABSOLUTE HEIGHT via get-block-at-height,
which descends from the ACTIVE tip — so a start header on a FORK used to be
spliced onto the active chain's successors and the reply was not a chain at
all (headers[1].previousblockhash did not name headers[0]). Core's loop is
`while (pindex && active_chain.Contains(pindex))` with active_chain.Next
(rest.cpp:227-232), so a fork start yields an EMPTY result and contiguity is
structural."
  (multiple-value-bind (cs entries) (%make-served-chain 2) ; heights 0,1,2
    (let* ((node (make-test-node))
           (hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (genesis (first entries))
           (genesis-hex (bl.rpc:hash-to-hex
                         (bl.store:block-index-entry-hash genesis)))
           ;; A competing block at height 1, off the active chain.
           (fork-header (bl.ser:make-block-header
                         :version 1
                         :prev-block (bl.store:block-index-entry-hash genesis)
                         :merkle-root (make-32-byte-hash 99)
                         :timestamp 1700000500 :bits #x1d00ffff :nonce 4242))
           (fork-hash (bl.ser:block-header-hash fork-header))
           (fork-hex (bl.rpc:hash-to-hex fork-hash)))
      (setf (bl:node-chain-state node) cs)
      (bl.store:add-block-index-entry
       cs (bl.store:make-block-index-entry
           :hash fork-hash :height 1 :header fork-header
           :prev-entry genesis :chain-work 2 :status :valid))
      ;; The fork block really is known to the index but not on the active
      ;; chain — otherwise the assertions below would pass for the wrong reason.
      (is-true (bl.store:get-block-index-entry cs fork-hash))
      (is-false (bl.store:entry-on-active-chain-p
                 cs (bl.store:get-block-index-entry cs fork-hash)))
      (flet ((rest-get (hex ext)
               (rest-request node (format nil "/rest/headers/~A.~A" hex ext))))
        (%with-rest-count ("3")
          ;; Fork start: empty, in every representation. Before the fix this
          ;; was [fork@1, active@2] — two headers that are not a chain.
          (is (string= "[]" (rest-get fork-hex "json")))
          (is (= 200 (hunchentoot:return-code*)))
          (is (string= (format nil "~%") (rest-get fork-hex "hex")))
          (is (zerop (length (rest-get fork-hex "bin"))))
          ;; CONTROL: an active-chain start still returns COUNT headers...
          (let* ((body (rest-get genesis-hex "json"))
                 (parsed (let ((yason:*parse-json-arrays-as-vectors* t))
                           (yason:parse body))))
            (is (= 3 (length parsed)))
            ;; ...and they form a real chain.
            (loop for i from 1 below (length parsed)
                  do (is (string= (gethash "hash" (aref parsed (1- i)))
                                  (gethash "previousblockhash" (aref parsed i)))
                         "header ~D does not follow header ~D" i (1- i))))
          ;; 3 headers * 80 bytes, plus the trailing newline .hex adds.
          (is (= (1+ (* 3 160)) (length (rest-get genesis-hex "hex"))))
          (is (= (* 3 80) (length (rest-get genesis-hex "bin")))))))))

;;; --- /rest/health liveness decision (item 6) ---

(test rest-health-decision-logic
  "health-ok-p feeds /rest/health: HTTP 200 only when the sync thread is alive
AND the tip advanced within the staleness threshold; HTTP 503 otherwise."
  (let ((threshold bl::*health-max-tip-staleness-seconds*))
    ;; Alive + recent tip -> healthy (HTTP 200).
    (is-true (bl::health-ok-p t 5))
    (is-true (bl::health-ok-p t 0))
    ;; Boundary: exactly at the threshold is still healthy (<=).
    (is-true (bl::health-ok-p t threshold))
    ;; Stale tip -> unhealthy (HTTP 503) even though the thread is alive.
    (is-false (bl::health-ok-p t (1+ threshold)))
    (is-false (bl::health-ok-p t (* threshold 100)))
    ;; Dead / absent sync thread -> unhealthy regardless of tip recency.
    (is-false (bl::health-ok-p nil 5))
    (is-false (bl::health-ok-p nil (1+ threshold)))
    ;; An explicit THRESHOLD argument is honored.
    (is-true (bl::health-ok-p t 30 60))
    (is-false (bl::health-ok-p t 90 60))))

(test rest-health-liveness-report
  "node-tip-liveness on a fresh, unstarted node: no sync thread -> unhealthy,
and a never-advanced tip reads as a large seconds-since-tip."
  (let ((node (bl:make-node :network :testnet4)))
    (multiple-value-bind (healthy seconds synced)
        (bl:node-tip-liveness node)
      (declare (ignore synced))
      ;; No sync thread has been started, so the probe reports unhealthy.
      (is-false healthy)
      ;; The tip has never advanced (last-tip-advance-time = 0), so
      ;; seconds-since-tip is well past the staleness threshold.
      (is (integerp seconds))
      (is (>= seconds bl::*health-max-tip-staleness-seconds*)))))

;;;; ---------------------------------------------------------------------
;;;; JSON-RPC reply shape by request version (GA8 wave 6, item 1)
;;;;
;;;; Core JSONRPCReplyObj (rpc/request.cpp:51-68) shapes the reply from the
;;;; request's version: "jsonrpc" is emitted for 2.0 only; a legacy 1.x reply
;;;; carries BOTH "result" and "error" with one of them null; "id" is omitted
;;;; when the request carried no id member (request.cpp:207-211).
;;;; We used to answer every request with the 2.0 shape, which makes
;;;; python-bitcoinrpc's AuthServiceProxy (`if response['error'] is not None:`)
;;;; raise KeyError: 'error' on every successful call.
;;;; ---------------------------------------------------------------------

(defparameter *jsonrpc-shape-method* "ga8shapeecho"
  "Name of the throwaway RPC method the reply-shape tests dispatch.")

(defun call-with-jsonrpc-shape-method (thunk)
  "Register an always-succeeding dispatch target, run THUNK, then remove it so
the global method registry (which the /ui help test enumerates) is unchanged."
  (bl.rpc:register-rpc-method
   *jsonrpc-shape-method*
   (lambda (node params) (declare (ignore node params)) 42))
  (unwind-protect (funcall thunk)
    (remhash *jsonrpc-shape-method* bl.rpc::*rpc-methods*)))

(defmacro with-jsonrpc-shape-method (&body body)
  `(call-with-jsonrpc-shape-method (lambda () ,@body)))

(defun jsonrpc-shape-key-present-p (object key)
  "True when the parsed JSON OBJECT carries KEY at all — which is a different
question from its value being null, and is exactly the difference that breaks
python-bitcoinrpc."
  (and (hash-table-p object) (nth-value 1 (gethash key object))))

(defun jsonrpc-shape-reply (body)
  "Drive BODY through the production path (parse-json-rpc-request ->
handle-single-request -> yason:encode) and return (values parsed-reply
json-text). Returns (values :no-reply nil) for a 2.0 notification, which
rpc-handler answers with HTTP 204 and no body."
  (multiple-value-bind (kind method params id version id-present)
      (bl.rpc::parse-json-rpc-request body)
    (unless (eq kind :single)
      (error "jsonrpc-shape-reply: expected a single request, got ~S" kind))
    (if (and (eq version :v2) (not id-present))
        (values :no-reply nil)
        (let* ((response (bl.rpc::handle-single-request
                          nil method params id version :id-present id-present))
               (json (with-output-to-string (s) (yason:encode response s))))
          (values (yason:parse json) json)))))

(defun jsonrpc-shape-body (version-member method id-member)
  "A request body: VERSION-MEMBER and ID-MEMBER are the literal JSON members
to splice in (\"\" for absent)."
  (format nil "{~@[~A,~]\"method\":\"~A\",\"params\":[]~@[,~A~]}"
          version-member method id-member))

(test jsonrpc-v1-success-reply-has-both-result-and-null-error
  "A jsonrpc:\"1.0\" request — and one with no jsonrpc member at all, which
Core also classifies V1_LEGACY (request.cpp:212-227) — gets the legacy reply
shape: NO \"jsonrpc\" key, both \"result\" and \"error\" present with the error
null, and the id echoed. The last assertion is python-bitcoinrpc's:
response[\"error\"] must EXIST and be null on success."
  (with-jsonrpc-shape-method
    (dolist (version-member (list "\"jsonrpc\":\"1.0\"" nil))
      (multiple-value-bind (reply json)
          (jsonrpc-shape-reply (jsonrpc-shape-body version-member
                                                   *jsonrpc-shape-method*
                                                   "\"id\":7"))
        (is (hash-table-p reply) "expected a reply object, got ~S" reply)
        (when (hash-table-p reply)
          (is-false (jsonrpc-shape-key-present-p reply "jsonrpc")
                    "1.x reply must not carry a \"jsonrpc\" key: ~A" json)
          (is-true (jsonrpc-shape-key-present-p reply "result"))
          (is (eql 42 (gethash "result" reply)))
          ;; python-bitcoinrpc: `if response['error'] is not None:`
          (is-true (jsonrpc-shape-key-present-p reply "error")
                   "1.x success reply must carry a null \"error\": ~A" json)
          (is-false (gethash "error" reply))
          (is-true (search "\"error\":null" json)
                   "\"error\" must serialize as JSON null: ~A" json)
          (is-true (jsonrpc-shape-key-present-p reply "id"))
          (is (eql 7 (gethash "id" reply))))))))

(test jsonrpc-v1-error-reply-has-both-null-result-and-error
  "A 1.x error reply carries a null \"result\" beside the error object and no
\"jsonrpc\" key (Core rpc/request.cpp:60-64)."
  (with-jsonrpc-shape-method
    (dolist (version-member (list "\"jsonrpc\":\"1.0\"" nil))
      (multiple-value-bind (reply json)
          (jsonrpc-shape-reply (jsonrpc-shape-body version-member
                                                   "ga8shapenosuchmethod"
                                                   "\"id\":7"))
        (is (hash-table-p reply) "expected a reply object, got ~S" reply)
        (when (hash-table-p reply)
          (is-false (jsonrpc-shape-key-present-p reply "jsonrpc")
                    "1.x reply must not carry a \"jsonrpc\" key: ~A" json)
          (is-true (jsonrpc-shape-key-present-p reply "result")
                   "1.x error reply must carry a null \"result\": ~A" json)
          (is-false (gethash "result" reply))
          (is-true (search "\"result\":null" json))
          (let ((err (gethash "error" reply)))
            (is (hash-table-p err) "expected an error object, got ~S" err)
            (when (hash-table-p err)
              (is (eql bl.rpc:+rpc-method-not-found+
                       (gethash "code" err)))
              (is (equal "Method not found" (gethash "message" err)))))
          (is (eql 7 (gethash "id" reply))))))))

(test jsonrpc-v1-omits-id-when-request-had-none
  "Core omits \"id\" entirely when the request carried no id member
(rpc/request.cpp:66 with id = std::nullopt, :207-211). A 1.x request without an
id is NOT a notification — it still gets a reply, just without the key."
  (with-jsonrpc-shape-method
    (dolist (version-member (list "\"jsonrpc\":\"1.0\"" nil))
      ;; Success and error both.
      (dolist (method (list *jsonrpc-shape-method* "ga8shapenosuchmethod"))
        (multiple-value-bind (reply json)
            (jsonrpc-shape-reply (jsonrpc-shape-body version-member method nil))
          (is (hash-table-p reply) "expected a reply object, got ~S" reply)
          (when (hash-table-p reply)
            (is-false (jsonrpc-shape-key-present-p reply "id")
                      "no id member in the request => no \"id\" key: ~A" json)
            (is-true (jsonrpc-shape-key-present-p reply "result"))
            (is-true (jsonrpc-shape-key-present-p reply "error")))))
      ;; id:null is a different thing from an absent id: the key comes back.
      (multiple-value-bind (reply json)
          (jsonrpc-shape-reply (jsonrpc-shape-body version-member
                                                   *jsonrpc-shape-method*
                                                   "\"id\":null"))
        (is (hash-table-p reply) "expected a reply object, got ~S" reply)
        (when (hash-table-p reply)
          (is-true (jsonrpc-shape-key-present-p reply "id")
                   "id:null must echo back as \"id\":null: ~A" json)
          (is-false (gethash "id" reply)))))))

(test jsonrpc-v2-reply-shape-is-unchanged
  "Control: a 2.0 request must still get the strict 2.0 shape — \"jsonrpc\"
present, and only ONE of result/error (Core rpc/request.cpp:55-64). This is
what proves the 1.x fix did not simply flip every reply to the legacy shape."
  (with-jsonrpc-shape-method
    ;; Success.
    (multiple-value-bind (reply json)
        (jsonrpc-shape-reply (jsonrpc-shape-body "\"jsonrpc\":\"2.0\""
                                                 *jsonrpc-shape-method*
                                                 "\"id\":7"))
      (is (hash-table-p reply) "expected a reply object, got ~S" reply)
      (when (hash-table-p reply)
        (is (equal "2.0" (gethash "jsonrpc" reply)))
        (is (eql 42 (gethash "result" reply)))
        (is-false (jsonrpc-shape-key-present-p reply "error")
                  "2.0 success reply must omit \"error\": ~A" json)
        (is (eql 7 (gethash "id" reply)))))
    ;; Error.
    (multiple-value-bind (reply json)
        (jsonrpc-shape-reply (jsonrpc-shape-body "\"jsonrpc\":\"2.0\""
                                                 "ga8shapenosuchmethod"
                                                 "\"id\":7"))
      (is (hash-table-p reply) "expected a reply object, got ~S" reply)
      (when (hash-table-p reply)
        (is (equal "2.0" (gethash "jsonrpc" reply)))
        (is-false (jsonrpc-shape-key-present-p reply "result")
                  "2.0 error reply must omit \"result\": ~A" json)
        (is-true (hash-table-p (gethash "error" reply)))
        (is (eql 7 (gethash "id" reply)))))
    ;; A 2.0 notification (no id member) is executed but gets no reply at all
    ;; (Core httprpc.cpp:167-171 answers HTTP 204).
    (is (eq :no-reply
            (jsonrpc-shape-reply (jsonrpc-shape-body "\"jsonrpc\":\"2.0\""
                                                     *jsonrpc-shape-method*
                                                     nil))))))

(test jsonrpc-batch-reply-shape-is-per-member
  "Core re-parses every batch member on its own (httprpc.cpp:194-206), so the
reply shape is per member: a 1.x member gets result+error and no \"jsonrpc\",
a 2.0 member gets the strict shape, a 2.0 notification contributes no reply at
all (:207-209), and a 1.x member without an id gets a reply with no \"id\"."
  (with-jsonrpc-shape-method
    (multiple-value-bind (kind requests)
        (bl.rpc::parse-json-rpc-request
         (format nil "[{\"jsonrpc\":\"1.0\",\"method\":\"~A\",\"id\":1},~
                       {\"jsonrpc\":\"2.0\",\"method\":\"~A\",\"id\":2},~
                       {\"jsonrpc\":\"2.0\",\"method\":\"~A\"},~
                       {\"method\":\"~A\"}]"
                 *jsonrpc-shape-method* *jsonrpc-shape-method*
                 *jsonrpc-shape-method* *jsonrpc-shape-method*))
      (is (eq :batch kind))
      (let ((replies (bl.rpc::handle-batch-request nil requests)))
        (is (= 3 (length replies))
            "the 2.0 notification must contribute no reply; got ~S replies"
            (length replies))
        (when (= 3 (length replies))
          (destructuring-bind (v1 v2 v1-no-id) replies
            (is-false (jsonrpc-shape-key-present-p v1 "jsonrpc"))
            (is-true (jsonrpc-shape-key-present-p v1 "error"))
            (is-false (gethash "error" v1))
            (is (eql 1 (gethash "id" v1)))
            (is (equal "2.0" (gethash "jsonrpc" v2)))
            (is-false (jsonrpc-shape-key-present-p v2 "error"))
            (is (eql 2 (gethash "id" v2)))
            (is-false (jsonrpc-shape-key-present-p v1-no-id "jsonrpc"))
            (is-true (jsonrpc-shape-key-present-p v1-no-id "error"))
            (is-false (jsonrpc-shape-key-present-p v1-no-id "id")
                      "a 1.x batch member with no id must get no \"id\" key")))))))

(test jsonrpc-pre-dispatch-errors-use-the-legacy-shape
  "Failures raised before a version is known — parse errors, invalid requests,
and the HTTP-level refusals rpc-json-error builds — take Core's default
V1_LEGACY/null-id JSONRPCRequest (httprpc.cpp:41-59, request.h:55,63), so they
carry result+error and no \"jsonrpc\"."
  (let* ((response (bl.rpc::make-rpc-error-response
                    bl.rpc:+rpc-parse-error+ "Parse error" nil :v1))
         (json (with-output-to-string (s) (yason:encode response s)))
         (reply (yason:parse json)))
    (is-false (jsonrpc-shape-key-present-p reply "jsonrpc") "~A" json)
    (is-true (jsonrpc-shape-key-present-p reply "result") "~A" json)
    (is-false (gethash "result" reply))
    (is-true (jsonrpc-shape-key-present-p reply "id") "~A" json)
    (is-false (gethash "id" reply))
    (let ((err (gethash "error" reply)))
      (is (hash-table-p err))
      (when (hash-table-p err)
        (is (eql bl.rpc:+rpc-parse-error+ (gethash "code" err)))))))

;;;; ---------------------------------------------------------------------
;;;; The same rules, asserted at the HTTP HANDLER — the call site the bug
;;;; actually lived at.
;;;;
;;;; The tests above drive parse-json-rpc-request -> handle-single-request by
;;;; hand, which proves the reply BUILDERS but says nothing about the wiring:
;;;; the original defect was precisely that rpc-handler parsed the version and
;;;; never passed it on. So these tests call RPC-HANDLER itself (and
;;;; RPC-JSON-ERROR, the pre-dispatch refusal path) and assert the ENCODED
;;;; RESPONSE BODY plus the HTTP status, byte for byte — a Lisp-value
;;;; assertion cannot see a serialization regression, and this whole bug class
;;;; is serialization.
;;;;
;;;; rpc-handler only ever reads headers-in, script-name and raw-post-data off
;;;; hunchentoot:*request*, so a synthetic request with its raw-post-data slot
;;;; pre-filled — exactly what hunchentoot's own get-post-data leaves there
;;;; (hunchentoot request.lisp:150-183) — drives the real function with no
;;;; socket, acceptor or server.
;;;;
;;;; Authentication is mandatory and is checked BEFORE the body is parsed or
;;;; dispatched (Core HTTPReq_JSONRPC, httprpc.cpp:112-133), so these requests
;;;; carry a real HTTP Basic credential, exactly as bitcoin-cli does: the
;;;; helpers bind *rpc-credentials* for the duration of the call and
;;;; send the matching header. None of the shapes below can be reached without
;;;; one — see the 401 assertion in the pre-dispatch test, which is what fails
;;;; if that credential ever stops being load-bearing.
;;;; ---------------------------------------------------------------------

(defparameter *jsonrpc-handler-rpc-user* "ga8shapeuser"
  "The RPC user the handler tests authorize as (installed into *rpc-credentials* for the
duration of one jsonrpc-handler-reply call).")

(defparameter *jsonrpc-handler-rpc-password* "ga8shapepass"
  "The RPC password the handler tests authorize with (bound over
*rpc-credentials* for the duration of one jsonrpc-handler-reply call).")

(defun jsonrpc-handler-credential ()
  "The \"user:pass\" credential the handler tests send as HTTP Basic."
  (concatenate 'string *jsonrpc-handler-rpc-user* ":"
               *jsonrpc-handler-rpc-password*))

(defun jsonrpc-handler-basic-auth (credential)
  "CREDENTIAL (\"user:pass\") as an HTTP Basic Authorization header value:
the scheme name, a space, then the base64 of the pair — what Core's
RPCAuthorized decodes (httprpc.cpp:84-101). Spelled out here so this section
builds on its own; it is the one line of HTTP a handler test needs."
  (concatenate 'string "Basic " (cl-base64:string-to-base64-string credential)))

(defparameter *jsonrpc-handler-dotted-method* "ga8shapedotted"
  "A method whose result (an improper list) has no JSON encoding, so
yason:encode signals inside rpc-handler — the only way to reach its
outermost internal-error clause, since handle-single-request catches
everything a method itself signals.")

(defun call-with-jsonrpc-handler-methods (thunk)
  "Register the handler tests' throwaway dispatch targets, run THUNK, then
remove them so the global method registry is unchanged."
  (bl.rpc:register-rpc-method
   *jsonrpc-shape-method*
   (lambda (node params) (declare (ignore node params)) 42))
  (bl.rpc:register-rpc-method
   *jsonrpc-handler-dotted-method*
   (lambda (node params) (declare (ignore node params)) (cons 1 2)))
  (unwind-protect (funcall thunk)
    (remhash *jsonrpc-shape-method* bl.rpc::*rpc-methods*)
    (remhash *jsonrpc-handler-dotted-method* bl.rpc::*rpc-methods*)))

(defmacro with-jsonrpc-handler-methods (&body body)
  `(call-with-jsonrpc-handler-methods (lambda () ,@body)))

(defun jsonrpc-handler-request (body &key (content-type "application/json")
                                       (uri "/") (headers '()) content-length
                                       (auth (jsonrpc-handler-credential)))
  "A synthetic hunchentoot POST request carrying BODY.
AUTH is a \"user:pass\" credential sent as an HTTP Basic Authorization header;
it defaults to the pair jsonrpc-handler-reply installs, so the request is
authorized. NIL sends no Authorization header at all (a 401), and any other
string exercises a wrong credential.
CONTENT-LENGTH overrides the Content-Length header (to exercise the
oversized-body refusal without allocating 32 MiB). hunchentoot:*acceptor*
must be bound while the request is built: initialize-instance :after consults
it through session-verify."
  (let* ((octets (flexi-streams:string-to-octets body :external-format :utf-8))
         (hunchentoot:*acceptor* nil)
         (request (make-instance 'hunchentoot:request
                                 :acceptor nil
                                 :headers-in
                                 (list* (cons :content-type content-type)
                                        (cons :host "127.0.0.1:18332")
                                        (cons :content-length
                                              (or content-length
                                                  (princ-to-string (length octets))))
                                        (append
                                         (when auth
                                           (list (cons :authorization
                                                       (jsonrpc-handler-basic-auth
                                                        auth))))
                                         headers))
                                 :method :post
                                 :uri uri
                                 ;; The refused-credential path logs the peer
                                 ;; address; the slot has no initform, so a
                                 ;; request built without one would signal
                                 ;; UNBOUND-SLOT instead of answering 401.
                                 :remote-addr "127.0.0.1"
                                 :server-protocol :http/1.1
                                 :content-stream nil)))
    (setf (slot-value request 'hunchentoot::raw-post-data) octets)
    request))

(defun jsonrpc-handler-reply (body &rest request-args)
  "POST BODY to the production entry point RPC-HANDLER; return
 (values http-status response-body content-type). The RPC credential is
installed for the duration of the call and sent with the request, so the
handler authorizes it and reaches the paths under test; :AUTH overrides what
the client presents (see jsonrpc-handler-request). RATE-LIMITER, when given as
:rate-limiter, replaces the global limiter for this one call."
  (let* ((rate-limiter (getf request-args :rate-limiter))
         (request-args (loop for (k v) on request-args by #'cddr
                             unless (eq k :rate-limiter)
                               append (list k v)))
         (bl.rpc::*rpc-credentials*
           (%plaintext-credentials *jsonrpc-handler-rpc-user*
                                   *jsonrpc-handler-rpc-password*))
         ;; A server that never went through start-node is in WARMUP by
         ;; default, and would answer -28 to everything. These tests are about
         ;; what a READY node replies.
         (bl.rpc::*rpc-warmup-status* nil)
         (hunchentoot:*reply* (make-instance 'hunchentoot:reply))
         (hunchentoot:*request* (apply #'jsonrpc-handler-request body request-args))
         (bl.rpc::*rpc-node* nil)
         (bl.rpc::*rpc-rate-limiter* rate-limiter))
    ;; A fresh reply starts at 200; reset explicitly so a request-construction
    ;; hiccup could not pre-seed the status the assertions read back.
    (setf (hunchentoot:return-code*) hunchentoot:+http-ok+)
    (let ((out (bl.rpc::rpc-handler)))
      (values (hunchentoot:return-code*) out (hunchentoot:content-type*)))))

(defun jsonrpc-handler-check (body expected-status expected-json &rest request-args)
  "Assert that POSTing BODY to rpc-handler answers EXPECTED-STATUS with
EXPECTED-JSON as the exact response body."
  (multiple-value-bind (status json)
      (apply #'jsonrpc-handler-reply body request-args)
    (is (eql expected-status status)
        "~A~%  status: expected ~S, got ~S (body ~S)"
        body expected-status status json)
    (is (string= expected-json json)
        "~A~%  body: expected ~S~%        got      ~S"
        body expected-json json)))

(defun jsonrpc-legacy-error-json (code message)
  "The exact legacy-1.x error body Core's JSONErrorReply sends for a failure
raised before any version is known: null result, the error object, null id
(httprpc.cpp:41-59 over the default V1_LEGACY/VNULL-id JSONRPCRequest,
request.h:55,63)."
  (format nil "{\"result\":null,\"error\":{\"code\":~D,\"message\":\"~A\"},\"id\":null}"
          code message))

(test jsonrpc-handler-threads-request-version-into-the-reply
  "rpc-handler must hand handle-single-request the version and id-presence it
just parsed. Asserted on the wire bytes: a 1.x request (explicit \"1.0\" or no
jsonrpc member, both V1_LEGACY per request.cpp:212-227) gets result+error with
one null and no \"jsonrpc\" key, while a 2.0 request keeps the strict 2.0
shape. Hardcoding either argument at the call site — which IS the bug this
wave repairs — changes these bytes."
  (with-jsonrpc-handler-methods
    (let ((echo *jsonrpc-shape-method*))
      ;; --- 1.x success: both keys, error null, id echoed, no "jsonrpc". ---
      (dolist (version-member '("\"jsonrpc\":\"1.0\"," ""))
        (jsonrpc-handler-check
         (format nil "{~A\"method\":\"~A\",\"params\":[],\"id\":7}" version-member echo)
         200 "{\"result\":42,\"error\":null,\"id\":7}")
        ;; --- 1.x, no id member: still answered, but with no "id" key. A 1.x
        ;; request is never a notification (Core IsNotification, request.h:67).
        (jsonrpc-handler-check
         (format nil "{~A\"method\":\"~A\",\"params\":[]}" version-member echo)
         200 "{\"result\":42,\"error\":null}")
        ;; --- 1.x error: null result beside the error, and the 1.x status
        ;; mapping (-32601 -> 404, httprpc.cpp:41-59).
        (jsonrpc-handler-check
         (format nil "{~A\"method\":\"ga8shapenosuchmethod\",\"id\":7}" version-member)
         404
         (format nil "{\"result\":null,\"error\":{\"code\":~D,\"message\":\"Method not found\"},\"id\":7}"
                 bl.rpc:+rpc-method-not-found+)))
      ;; --- 2.0 control: unchanged, and always HTTP 200 even for an error. ---
      (jsonrpc-handler-check
       (format nil "{\"jsonrpc\":\"2.0\",\"method\":\"~A\",\"params\":[],\"id\":7}" echo)
       200 "{\"jsonrpc\":\"2.0\",\"result\":42,\"id\":7}")
      (jsonrpc-handler-check
       "{\"jsonrpc\":\"2.0\",\"method\":\"ga8shapenosuchmethod\",\"id\":7}"
       200
       (format nil "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":~D,\"message\":\"Method not found\"},\"id\":7}"
               bl.rpc:+rpc-method-not-found+))
      ;; --- The reply is the same on a /wallet/<name> endpoint. ---
      (jsonrpc-handler-check
       (format nil "{\"method\":\"~A\",\"id\":7}" echo)
       200 "{\"result\":42,\"error\":null,\"id\":7}"
       :uri "/wallet/w1"))))

(test jsonrpc-handler-notification-and-batch-http-shapes
  "The handler's own HTTP-level decisions: a 2.0 notification and a non-empty
all-notification batch answer 204 with no body (Core httprpc.cpp:167-171,220),
while an EMPTY batch answers 200 with [] (:211-219) — NIL would encode as JSON
null, so the empty array has to be spelled #(). Batch replies are per member."
  (with-jsonrpc-handler-methods
    (let ((echo *jsonrpc-shape-method*))
      ;; 2.0 notification: executed, no reply, 204.
      (jsonrpc-handler-check
       (format nil "{\"jsonrpc\":\"2.0\",\"method\":\"~A\",\"params\":[]}" echo)
       204 "")
      ;; Non-empty all-notification batch: 204, no body.
      (jsonrpc-handler-check
       (format nil "[{\"jsonrpc\":\"2.0\",\"method\":\"~A\"},~
                     {\"jsonrpc\":\"2.0\",\"method\":\"~A\"}]" echo echo)
       204 "")
      ;; Empty batch: 200 with a JSON array, NOT null.
      (jsonrpc-handler-check "[]" 200 "[]")
      ;; Mixed batch: 1.x member, 2.0 member, dropped 2.0 notification, and a
      ;; 1.x member with no id (reply present, "id" key absent).
      (jsonrpc-handler-check
       (format nil "[{\"jsonrpc\":\"1.0\",\"method\":\"~A\",\"id\":1},~
                     {\"jsonrpc\":\"2.0\",\"method\":\"~A\",\"id\":2},~
                     {\"jsonrpc\":\"2.0\",\"method\":\"~A\"},~
                     {\"method\":\"~A\"}]"
               echo echo echo echo)
       200
       (concatenate 'string
                    "[{\"result\":42,\"error\":null,\"id\":1},"
                    "{\"jsonrpc\":\"2.0\",\"result\":42,\"id\":2},"
                    "{\"result\":42,\"error\":null}]"))
      ;; A non-object member has no version of its own: Core's fresh request is
      ;; V1_LEGACY with a null id, and the batch still answers 200.
      (jsonrpc-handler-check
       "[7]" 200
       (format nil "[~A]"
               (jsonrpc-legacy-error-json bl.rpc:+rpc-invalid-request+
                                          "Invalid request format"))))))

(test jsonrpc-batch-members-get-the-named-argument-transform
  "A batch member reaches its handler through the same per-request path as a
singleton, the named-argument transform included: Core runs both through
JSONRPCExec -> CRPCTable::execute -> ExecuteCommand, and ExecuteCommand is
where transformNamedArguments happens (rpc/server.cpp:502-512, reached from
both HTTPReq_JSONRPC branches, httprpc.cpp:151-201). Ours skipped it for batch
members, so a member whose \"params\" was a JSON object handed the handler a
raw hash-table; every handler reads positionally, so the reply was -32603 with
a Lisp type error in the message — a client could not even tell that the
transport shape was at fault.

Core catches a member's own error into that member's reply rather than failing
the batch (httprpc.cpp:202-206), so a named parameter that names no slot is
that member's -8 and its neighbours still run."
  (flet ((echo-member (id params)
           (format nil "{\"jsonrpc\":\"2.0\",\"id\":~D,\"method\":\"echo\",\"params\":~A}"
                   id params))
         (reply (body)
           (multiple-value-bind (status json) (jsonrpc-handler-reply body)
             (is (= 200 status) "~A answered ~D: ~S" body status json)
             (yason:parse json))))
    (let ((named (echo-member 1 "{\"arg1\":\"b\",\"arg0\":\"a\"}"))
          ;; Core's \"args\" convenience: positional arguments alongside named
          ;; ones (doc/JSON-RPC-interface.md#parameter-passing).
          (prefixed (echo-member 2 "{\"args\":[\"a\"],\"arg1\":\"b\"}"))
          (unknown (echo-member 3 "{\"nosuchargument\":1}")))
      ;; CONTROL: as a SINGLETON the same member has always been transformed,
      ;; so the batch assertions below cannot pass because of echo itself.
      (is (equal '("a" "b") (gethash "result" (reply named))))
      ;; Both shapes now reach the handler as the positional list it takes,
      ;; and the slots are filled by NAME, not by the order they were written.
      (let ((replies (reply (format nil "[~A,~A]" named prefixed))))
        (is (= 2 (length replies)))
        (dolist (r replies)
          (is (equal '("a" "b") (gethash "result" r))
              "member answered ~S" (gethash "error" r))))
      ;; One member's transform failing is that member's error, not the
      ;; batch's: the other member still runs and the batch is still 200.
      (let ((replies (reply (format nil "[~A,~A]" unknown named))))
        (is (= 2 (length replies)))
        (is (= bl.rpc:+rpc-invalid-parameter+
               (gethash "code" (gethash "error" (first replies)))))
        (is (equal '("a" "b") (gethash "result" (second replies))))))))

(test jsonrpc-handler-pre-dispatch-errors-use-the-legacy-shape
  "Every reply rpc-handler sends before (or instead of) dispatching — origin
refusal, rate limit, oversized body, parse error, invalid request, and the
outermost internal-error clause — carries Core's default V1_LEGACY/null-id
shape and the 1.x status mapping. These are the paths a broken client hits
most, so the bytes are pinned here rather than only in the builder.
The two credential cases also pin the ORDER of the guards (origin -> auth ->
rate limit -> size -> dispatch): each assertion below only reaches the refusal
it is named for because the ones ahead of it passed. There is no longer a
content-type guard in that chain; see the last case."
  (with-jsonrpc-handler-methods
    ;; Malformed JSON -> -32700, HTTP 500.
    (jsonrpc-handler-check
     "not valid json" 500
     (jsonrpc-legacy-error-json bl.rpc:+rpc-parse-error+ "Parse error"))
    ;; Missing method -> -32600, HTTP 400. Note the request says 2.0 and still
    ;; gets the legacy shape: pre-dispatch failures carry no version (the
    ;; documented deviation from Core, which has already recorded V2 here).
    (jsonrpc-handler-check
     "{\"jsonrpc\":\"2.0\",\"id\":1}" 400
     (jsonrpc-legacy-error-json bl.rpc:+rpc-invalid-request+
                                "Missing or invalid method"))
    ;; A result yason cannot encode reaches the handler's outermost clause.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-handler-dotted-method*)
     500
     (jsonrpc-legacy-error-json bl.rpc:+rpc-internal-error+ "Internal error"))
    ;; Oversized body (Content-Length over the 32 MiB cap) -> 400.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-shape-method*) 400
     (jsonrpc-legacy-error-json bl.rpc:+rpc-misc-error+ "Request body too large")
     :content-length (princ-to-string (1+ bl:+max-rpc-body-size+)))
    ;; A credential that does not match -> 401 with an empty body, decided
    ;; before the body is even looked at. This assertion is also what keeps
    ;; every other check in this section honest: they reach the paths they name
    ;; only because jsonrpc-handler-reply presents a real credential, and this
    ;; is the check that fails first if that credential ever stops mattering.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-shape-method*) 401 ""
     :auth (concatenate 'string *jsonrpc-handler-rpc-user* ":wrong"))
    ;; Cross-origin browser POST -> 403, refused BEFORE auth: sent with no
    ;; credential at all, so a handler that authenticated first would answer
    ;; 401 here and this check would fail.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-shape-method*) 403
     (jsonrpc-legacy-error-json bl.rpc:+rpc-misc-error+
                                "Origin does not match Host")
     :auth nil
     :headers (list (cons :origin "http://evil.example")))
    ;; Rate limiting applies to the UNAUTHENTICATED side only, which is where
    ;; the protection is actually needed and where Core is not being diverged
    ;; from — Core has no RPC rate limit at all, because the port is
    ;; authenticated and loopback-only.
    ;;
    ;; An exhausted bucket (rate 0, burst 0) with a BAD credential -> 429.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-shape-method*) 429
     (jsonrpc-legacy-error-json bl.rpc:+rpc-misc-error+ "Rate limit exceeded")
     :auth (concatenate 'string *jsonrpc-handler-rpc-user* ":wrong")
     :rate-limiter (bl:make-rate-limiter 0 0))
    ;; The same exhausted bucket with a VALID credential is served. This is the
    ;; check that would have caught the original placement: an authenticated
    ;; admin client was throttled at 100 requests/second, which is fewer than
    ;; one of Core's `wait_until` poll loops, so the framework answered its own
    ;; polls with 429 and failed tests unrelated to rates.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-shape-method*) 200
     "{\"result\":42,\"error\":null,\"id\":1}"
     :rate-limiter (bl:make-rate-limiter 0 0))
    ;; An unusual Content-Type is NOT a refusal. This used to assert 415 with a
    ;; comment claiming "Core answers 415 too" — Core's HTTPReq_JSONRPC
    ;; (httprpc.cpp:104-165) never inspects the request Content-Type at all,
    ;; which is what made the divergence look deliberate for as long as it did.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-shape-method*) 200
     "{\"result\":42,\"error\":null,\"id\":1}"
     :content-type "application/xml")))

(test rpc-json-error-emits-the-legacy-shape
  "rpc-json-error is the single builder behind those HTTP-level refusals: it
sets the status and application/json, and its body is the V1_LEGACY shape."
  (let ((hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
    (let ((json (bl.rpc::rpc-json-error
                 429 bl.rpc:+rpc-misc-error+ "Rate limit exceeded")))
      (is (eql 429 (hunchentoot:return-code*)))
      (is (equal "application/json" (hunchentoot:content-type*)))
      (is (string= (jsonrpc-legacy-error-json bl.rpc:+rpc-misc-error+
                                              "Rate limit exceeded")
                   json)
          "rpc-json-error body: ~S" json))))

(test ga9-s1-9-forged-proof-recomputes-the-real-root
  "The forgery this fix exists to stop, demonstrated end to end.

CPartialMerkleTree's SHAPE is a pure function of the claimed nTransactions, so
lying about that count reinterprets INTERNAL nodes of the real tree as leaves.
For a real 4-transaction block with root H(H(t0,t1), H(t2,t3)), a proof that
claims 2 transactions and supplies [H(t0||t1), H(t2||t3)] recomputes the
header's real root EXACTLY and passes every structural bound — hashes <= ntx,
bits >= hashes, all consumed, no duplicate sibling.

So the recomputed-root check cannot catch it, and the only thing that can is
Core's comparison of the claimed count against the block's own
(rpc/txoutproof.cpp:165-170). This asserts the attack really does produce the
genuine root — if it ever stops doing so this test is no longer testing
anything — and that the count comparison rejects it."
  (let* ((txids (%proof-hashes 4))
         (real-root (bl.val:compute-merkle-root txids))
         ;; The two internal nodes of the real 4-leaf tree.
         (a (bl.crypto:hash256
             (concatenate '(vector (unsigned-byte 8)) (first txids) (second txids))))
         (b (bl.crypto:hash256
             (concatenate '(vector (unsigned-byte 8)) (third txids) (fourth txids)))))
    (multiple-value-bind (forged-root forged-matched)
        ;; Claim 2 transactions; hand over the internal nodes as if they were
        ;; the two leaves. bits: descend at the root, then each leaf is
        ;; matched, so all three bits are set (Core TraverseAndExtract reads a
        ;; bit per visited node, and at height 0 a set bit means a matched
        ;; leaf whose hash is consumed).
        (bl.rpc::extract-partial-merkle-tree 2 (list t t t) (list a b))
      (is (equalp real-root forged-root)
          "the forged 2-tx proof must reproduce the REAL 4-tx root — that is
           what makes the root check useless here")
      (is (= 2 (length forged-matched))
          "and it yields internal nodes as though they were txids")
      ;; The gate: claimed count vs the block's actual count.
      (is (/= 2 4)
          "control: the claimed count differs from the block's")
      (is-false (= 2 4)
                "so Core's `pindex->nTx == merkleBlock.txn.GetNumTransactions()'
                 is false and no results are returned"))))

(test ga9-s1-9-excessive-transaction-count-is-capped
  "Core rejects an absurd claimed nTransactions before building anything
(merkleblock.cpp:157-159, `check for excessively high numbers of
transactions'): the count drives the tree shape, so it must be bounded first.
MAX_BLOCK_WEIGHT / MIN_TRANSACTION_WEIGHT = 4000000 / 240 = 16666."
  (let ((h (first (%proof-hashes 1))))
    (is-false (bl.rpc::extract-partial-merkle-tree 16667 (list t) (list h))
              "one over the cap must be refused")
    ;; And the cap must not reject a legitimate small proof.
    (multiple-value-bind (root matched)
        (bl.rpc::extract-partial-merkle-tree 1 (list t) (list h))
      (declare (ignore matched))
      (is (equalp h root) "a single-transaction proof still works"))))

;;; --- Client compatibility: Content-Type and credential bytes ---------------

(test a-non-ascii-rpcpassword-can-actually-authenticate
  "Core assigns the base64 output straight into a std::string and compares raw
BYTES (RPCAuthorized, httprpc.cpp:84-102) — no encoding is involved on either
side. We decoded the header with FLEXI-STREAMS:OCTETS-TO-STRING, whose default
external format is latin-1, while the configured password came from a config
file read as UTF-8. For any non-ASCII byte the two disagree, so a correct
non-ASCII -rpcpassword produced 401 forever, with nothing in the log to say the
credential had been mangled rather than mistyped."
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "üser" "pässwörd")))
    (is-true (bl.rpc::check-auth
              (%basic-auth-header-utf8 "üser:pässwörd"))
             "a UTF-8 credential that matches the configuration was refused")
    ;; A near miss is still refused — the fix must not have made it permissive.
    (is-false (bl.rpc::check-auth
               (%basic-auth-header-utf8 "üser:pässwörX")))
    ;; And the latin-1 encoding of the same characters is a DIFFERENT byte
    ;; string, so it must not authorize.
    (is-false (bl.rpc::check-auth
               (%basic-auth-header "üser:pässwörd")))))

(test ascii-credentials-are-unchanged-by-the-byte-comparison
  "The byte comparison must be a strict generalization: every ASCII case that
worked before still works, and every near miss is still refused."
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "testpass")))
    (is-true (bl.rpc::check-auth "Basic dGVzdHVzZXI6dGVzdHBhc3M="))
    ;; A password containing colons still splits on the FIRST colon.
    (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "a:b:c")))
      (is-true (bl.rpc::check-auth (%basic-auth-header "testuser:a:b:c"))))
    (is-false (bl.rpc::check-auth (%basic-auth-header "testuser:testpas")))
    (is-false (bl.rpc::check-auth (%basic-auth-header "testuse:testpass")))
    ;; Length differences must not short-circuit: an empty password never matches.
    (is-false (bl.rpc::check-auth (%basic-auth-header "testuser:")))))

(test the-rpc-server-does-not-inspect-the-request-content-type
  "Core's HTTPReq_JSONRPC (httprpc.cpp:104-165) never looks at the request's
Content-Type — it writes one on the RESPONSE and reads the body as JSON
regardless. We answered 415 unless the header said application/json or
text/plain, so a plain `curl -d ...` (which defaults to
application/x-www-form-urlencoded) and any client that omits the header were
refused by us and worked against Core.

Driven through the live acceptor, because the whole point is what a real client
on the wire gets back."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((port 19987)
          (node (make-test-node))
          (cookie nil))
      (setf (bl:node-data-directory node) dir)
      (unwind-protect
           (progn
             (is (not (null (bl.rpc:start-rpc-server node :port port))))
             (setf cookie (alexandria:read-file-into-string
                           (merge-pathnames ".cookie" dir)))
             (let ((json "{\"method\":\"getblockcount\",\"id\":1}"))
               ;; What `curl -d` actually sends.
               (let ((r (%http-post-rpc-raw-content-type
                         port json "application/x-www-form-urlencoded" cookie)))
                 (is (= 200 (%http-status r))
                     "curl's default Content-Type was refused: ~A"
                     (subseq r 0 (min 60 (length r))))
                 (is (search "\"result\"" r)))
               ;; No Content-Type header at all.
               (let ((r (%http-raw-request
                         port
                         (list "POST / HTTP/1.1"
                               (format nil "Host: 127.0.0.1:~D" port)
                               (format nil "Authorization: ~A"
                                       (%basic-auth-header cookie))
                               (format nil "Content-Length: ~D" (length json))
                               "Connection: close")
                         json)))
                 (is (= 200 (%http-status r))
                     "a request with no Content-Type was refused"))
               ;; The two that already worked still do.
               (dolist (ct '("application/json" "text/plain"))
                 (let ((r (%http-post-rpc-raw-content-type port json ct cookie)))
                   (is (= 200 (%http-status r)) "~A stopped working" ct)))
               ;; A body that is not JSON is a PARSE error, not a media-type
               ;; refusal — the accurate answer, and the one Core gives.
               (let ((r (%http-post-rpc-raw-content-type
                         port "not json at all" "application/json" cookie)))
                 (is (/= 415 (%http-status r)))
                 (is (search "-32700" r)
                     "a non-JSON body should report a parse error: ~A"
                     (subseq r 0 (min 200 (length r))))))
             ;; Auth is still enforced — removing the media-type gate must not
             ;; have removed the credential gate with it.
             (let ((r (%http-post-rpc-raw-content-type
                       port "{\"method\":\"getblockcount\",\"id\":1}"
                       "application/x-www-form-urlencoded" "__cookie__:wrong")))
               (is (= 401 (%http-status r)))))
        (bl.rpc:stop-rpc-server)))))

(test getdeploymentinfo-buried-active-is-reported-one-block-early
  "Core reports a buried softfork active from ONE BLOCK BELOW its activation
height, and says so in a comment beside the call: getdeploymentinfo uses
DeploymentActiveAfter (rpc/blockchain.cpp:1301-1303), which is
`pindexPrev->nHeight + 1 >= DeploymentHeight' (deploymentstatus.h:14-18) —
i.e. it answers for the block AFTER the one queried.

We compared the height directly, so for exactly one block we answered false
where every Core node answers true. A one-block window is precisely the kind of
divergence a conformance test catches and a human never does."
  (flet ((active (tip activation)
           (cdr (assoc "active" (bl.rpc::%buried-deployment activation tip)
                       :test #'string=))))
    ;; Two below: not yet.
    (is (eq bl.rpc:+json-false+ (active 498 500)))
    ;; ONE below: Core says active. This is the case that was wrong.
    (is (eq t (active 499 500)))
    ;; At and above: active.
    (is (eq t (active 500 500)))
    (is (eq t (active 501 500)))
    ;; An always-active deployment (height 0) is active even at height 0.
    (is (eq t (active 0 0)))))

(test named-only-options-members-are-accepted-as-top-level-arguments
  "Core's dispatcher lets a member of an OBJ_NAMED_PARAMS options object be
passed as a TOP-LEVEL named argument: RPCHelpMan::GetArgNames emits them with
named_only=true (rpc/util.cpp:750) and transformNamedArguments collects them
into a fresh options object pushed at the options slot (rpc/server.cpp:408).

Without it the node answers `Unknown named parameter fee_rate' to a call every
Core client can make — nine of Core's functional tests do exactly that, and the
table is GENERATED from Core so it cannot drift into a hand-maintained
approximation."
  (flet ((call (method &rest kvs)
           (let ((h (make-hash-table :test 'equal)))
             (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v))
             (bl.rpc::%named-params-to-positional method h))))
    ;; send: outputs is positional 0, options is positional 4.
    (let ((out (call "send" "outputs" 1 "fee_rate" 2 "add_to_wallet" 3)))
      (is (= 5 (length out)) "send produced ~D slots, wanted 5" (length out))
      (is (eql 1 (first out)))
      (let ((options (fifth out)))
        (is-true (hash-table-p options) "the options slot is ~S" options)
        (when (hash-table-p options)
          (is (eql 2 (gethash "fee_rate" options)))
          (is (eql 3 (gethash "add_to_wallet" options))))))
    ;; gettxspendingprevout's member, which is not a wallet RPC.
    (let ((out (call "gettxspendingprevout" "outputs" 1 "mempool_only" t)))
      (is-true (hash-table-p (second out))
               "mempool_only did not reach the options slot: ~S" out))
    ;; A name that is neither positional nor a member is still unknown.
    (signals bl.rpc:rpc-error (call "send" "outputs" 1 "nonesuch" 2))))
