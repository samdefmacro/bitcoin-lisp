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

(defmacro %with-rpc-threads ((n) &body body)
  "Run BODY with -rpcthreads bound to N and the worker semaphore reset, so the
bound is rebuilt from N rather than inherited from an earlier test. One reach
per internal instead of one per binding."
  `(let ((bl.rpc:*rpc-threads* ,n)
         (bl.rpc::*rpc-worker-semaphore* nil)
         (bl.rpc::*rpc-worker-permits* nil))
     ,@body))

(defun %rpc-worker-semaphore ()
  "The worker semaphore for the current -rpcthreads, or NIL when unbounded."
  (bl.rpc::rpc-worker-semaphore))

(defun %getmemoryinfo (params)
  "getmemoryinfo through the exported dispatcher: the same door a client comes
through, so the argument normalisation and Core's declared-type gate are part
of what these tests exercise."
  (bl.rpc:dispatch-rpc-method nil "getmemoryinfo" params))

(defun %authorized-user (header)
  "The user CHECK-AUTH authorizes HEADER for, or NIL -- Core's RPCAuthorized
(httprpc.cpp:84-101). One reach for the whole file: the auth suites below ask
this question forty-three times, and forty-three package-internal names is
forty-three chances for one of them to drift."
  (bl.rpc::check-auth header))

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

(defun %testmempoolaccept (node hexes &rest rest)
  "testmempoolaccept through its handler, for HEXES and any trailing positional
arguments. One reach for the whole file: the handler is internal to BL.RPC
(only DISPATCH-RPC-METHOD is exported) and eight tests drive it."
  (bl.rpc::rpc-testmempoolaccept node (cons hexes rest)))

(test json-rpc-parse-valid-request
  "Test parsing valid JSON-RPC request"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}"))
    (multiple-value-bind (type method params id)
        (bl.rpc:parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockcount"))
      (is (null params))
      (is (= id 1)))))

(test json-rpc-parse-with-params
  "Test parsing request with params"
  (let ((body "{\"jsonrpc\":\"2.0\",\"method\":\"getblockhash\",\"params\":[100],\"id\":\"test\"}"))
    (multiple-value-bind (type method params id)
        (bl.rpc:parse-json-rpc-request body)
      (is (eq type :single))
      (is (string= method "getblockhash"))
      (is (= (first params) 100))
      (is (string= id "test")))))

(test json-rpc-parse-batch
  "Test parsing batch request"
  (let ((body "[{\"jsonrpc\":\"2.0\",\"method\":\"getblockcount\",\"id\":1},{\"jsonrpc\":\"2.0\",\"method\":\"getbestblockhash\",\"id\":2}]"))
    (multiple-value-bind (type requests)
        (bl.rpc:parse-json-rpc-request body)
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
           (nth-value 2 (bl.rpc:parse-json-rpc-request
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
      (%testmempoolaccept node bl.rpc::+json-empty-array+))
    ;; And null is not an array at all.
    (signals-rpc-error (:code -3)
      (%testmempoolaccept node nil))))

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
    (bl.rpc:parse-json-rpc-request "not valid json")))

(test json-rpc-parse-missing-method
  "Test parsing request without method returns error"
  (signals bl.rpc:rpc-error
    (bl.rpc:parse-json-rpc-request "{\"jsonrpc\":\"2.0\",\"id\":1}")))

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

(test rpc-savemempool-reports-a-dump-it-could-not-write
  "savemempool answers -1 `Unable to dump mempool to disk' when the dump
cannot be written, and the temp file it writes through is Core's own
`<mempool.dat>.new'.

Core's DumpMempool opens dump_path + \".new\" and returns false if it cannot
(node/mempool_persist.cpp:175-179), catching every later failure the same way
(:225-229); savemempool turns that false into RPC_MISC_ERROR `Unable to dump
mempool to disk'. mempool_persist.py:194 drives exactly this by making a
DIRECTORY at mempool.dat.new -- which only blocks the dump if our temp file
carries Core's name, so the name is part of the contract and not an internal
detail. Ours wrote through a .tmp of its own and let the error escape."
  (with-temp-directory (dir "bl-savemempool")
    (let ((node (make-test-node))
          (dat (bl.mp:mempool-dat-path dir)))
      (setf (bl:node-data-directory node) dir)
      ;; Control: with nothing in the way the dump succeeds and leaves the
      ;; temp file renamed away.
      (let ((r (bl.rpc:dispatch-rpc-method node "savemempool" nil)))
        (is (stringp (cdr (assoc "filename" r :test #'string=)))))
      (is (not (null (probe-file dat))))
      ;; Core's name, built the way Core builds it -- MAKE-PATHNAME with a
      ;; :type carrying a dot escapes it and names a different file.
      (let ((dotnew (pathname (concatenate 'string (namestring dat) ".new"))))
        (is (null (probe-file dotnew))
            "the temp file is renamed over the target, not left behind")
        ;; And nothing ELSE is left behind either -- the rename is the only
        ;; thing that puts the dump in place.
        (is (equal (list (file-namestring dat))
                   (mapcar #'file-namestring (directory (merge-pathnames "*.*" dir))))
            "the data directory holds mempool.dat and nothing else")
        ;; A directory at Core's temp path blocks the dump.
        (ensure-directories-exist
         (make-pathname :directory (append (pathname-directory dotnew)
                                           (list (file-namestring dotnew)))))
        (signals-rpc-error (:code -1 :exact-message "Unable to dump mempool to disk")
          (bl.rpc:dispatch-rpc-method node "savemempool" nil))))))

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

(defun %deriveaddresses (node params)
  "The deriveaddresses handler, reached once for the suite."
  (bl.rpc::rpc-deriveaddresses node params))

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
        (%deriveaddresses node (list (format nil "pkh(~A)" pk))))
      ;; pkh -> single P2PKH address; matches the direct encoder.
      (let ((addrs (%deriveaddresses
                    node (list (descsum (format nil "pkh(~A)" pk))))))
        (is (= 1 (length addrs)))
        (is (string= (bl.crypto:encode-p2pkh-address keyhash :testnet3)
                     (first addrs))))
      ;; wpkh -> single bech32 address.
      (is (= 1 (length (%deriveaddresses
                        node (list (descsum (format nil "wpkh(~A)" pk)))))))
      ;; combo emits pk+pkh+wpkh+sh(wpkh); the address-less P2PK script is
      ;; skipped (Core DeriveAddresses), leaving 3 addresses.
      (is (= 3 (length (%deriveaddresses
                        node (list (descsum (format nil "combo(~A)" pk)))))))
      ;; raw() non-standard script -> no address -> error
      (signals bl.rpc:rpc-error
        (%deriveaddresses node (list (descsum "raw(51)"))))
      ;; range argument rejected for an unranged descriptor
      (signals bl.rpc:rpc-error
        (%deriveaddresses
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

(test rpc-prioritisetransaction-cannot-split-the-mempool-from-the-txgraph
  "An out-of-int64 fee_delta is refused before any state moves, and in-range
deltas whose sum leaves int64 saturate instead of type-erroring halfway
through, so the entry's modified fee and the txgraph's fee for it can never
end up disagreeing.

Core reads the parameter as UniValue::getInt<int64_t> before touching the
mempool and answers -1 \"JSON integer out of range\" (rpc/mining.cpp:526,
univalue.h:139-149, rpc/server.cpp:512-516, asserted by rpc_net.py:362), and
PrioritiseTransaction saturates both mapDeltas and the entry's modified fee
through SaturatingAdd (txmempool.cpp:630-655, kernel/mempool_entry.h:125-128,
util/overflow.h:42-58)."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (tx (make-mempool-test-tx :input-id 77))
         (txid (bl.ser:transaction-hash tx))
         (hex (bl.rpc:hash-to-hex txid))
         (int64-max (1- (ash 1 63)))
         (int64-min (- (ash 1 63))))
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid
                 (bl.mp:make-entry-from-tx tx 10000 0 :entry-time 1000000))))
    (labels ((entry-fee ()
               (bl.mp:mempool-entry-modified-fee (bl.mp:mempool-get mempool txid)))
             (graph-fee ()
               (bl.mp:feefrac-fee
                (bl.mp:txgraph-get-individual-feerate
                 (bl.mp:mempool-graph mempool)
                 (bl.mp:mempool-entry-graph-handle
                  (bl.mp:mempool-get mempool txid)))))
             (delta ()
               (gethash txid (bl.mp:mempool-deltas mempool)))
             (prioritise (amount)
               (bl.rpc:dispatch-rpc-method node "prioritisetransaction"
                                           (list hex 0 amount))))
      (is (= 10000 (entry-fee)))
      (is (= 10000 (graph-fee)))
      ;; Positive control: an ordinary delta moves all three together.
      (is (eq t (prioritise 1000)))
      (is (= 11000 (entry-fee)))
      (is (= 11000 (graph-fee)))
      (is (= 1000 (delta)))
      ;; An out-of-int64 literal is refused, with Core's code and text, and
      ;; nothing moved.
      (let ((raised (handler-case (progn (prioritise (ash 1 70)) nil)
                      (bl.rpc:rpc-error (e) e))))
        (is-true raised)
        (is (= -1 (bl.rpc:rpc-error-code raised)))
        (is (string= "JSON integer out of range"
                     (bl.rpc:rpc-error-message raised))))
      (is (= 11000 (entry-fee)))
      (is (= 11000 (graph-fee)))
      (is (= 1000 (delta)))
      (is (= 1 (hash-table-count (bl.mp:mempool-deltas mempool))))
      ;; The entry is not poisoned: an ordinary call still works afterwards.
      (is (eq t (prioritise 100)))
      (is (= 11100 (entry-fee)))
      (is (= 11100 (graph-fee)))
      (is (= 1100 (delta)))
      ;; An in-range delta whose SUM leaves int64 saturates on both sides.
      (is (eq t (prioritise int64-max)))
      (is (= int64-max (entry-fee)))
      (is (= int64-max (graph-fee)))
      (is (= int64-max (delta)))
      ;; A net-zero accumulated delta is dropped, and the two fee views stay
      ;; equal across that too.
      (is (eq t (prioritise (- int64-max))))
      (is-false (delta))
      (is (zerop (entry-fee)))
      (is (zerop (graph-fee)))
      ;; Two more of the same saturate at the negative bound.
      (is (eq t (prioritise (- int64-max))))
      (is (eq t (prioritise (- int64-max))))
      (is (= int64-min (entry-fee)))
      (is (= int64-min (graph-fee)))
      (is (= int64-min (delta))))))

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
            (bl.rpc:extract-partial-merkle-tree ntx bits hashes)
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
            (bl.rpc:parse-merkle-block bytes)
          (is (equalp header h2))
          (is (= ntx ntx2))
          (is (equalp hashes hashes2))
          ;; bits round-trip up to the byte padding zeros
          (is (equal bits (subseq bits2 0 (length bits))))
          ;; and re-extract gives the same root
          (is (equalp (bl.rpc:extract-partial-merkle-tree ntx bits hashes)
                      (bl.rpc:extract-partial-merkle-tree ntx2 bits2 hashes2))))))))

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
        (is (not (equalp root (bl.rpc:extract-partial-merkle-tree
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
      (is (= 2 (btc-amount (cdr (assoc "total_amount" r :test #'string=))))))
    ;; No scan running: status -> null (Core NullUniValue); abort -> a bare
    ;; JSON false (nothing to abort).
    (is (null (bl.rpc::rpc-scantxoutset node (list "status"))))
    (is (eq 'yason:false (bl.rpc::rpc-scantxoutset node (list "abort"))))
    ;; Bad action / missing scanobjects -> errors.
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-scantxoutset node (list "frobnicate")))
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-scantxoutset node (list "start")))))

(test scantxoutset-reports-the-descriptor-inferred-from-each-match
  "Core reports, per matched output, the descriptor INFERRED from that output's
script -- `InferDescriptor(script, provider)->ToString()\', with the provider
Expand has just filled in (rpc/blockchain.cpp:2395-2401). So a ranged combo()
answers pkh([origin]<pubkey>)#checksum for the P2PKH output it produced at
that index, naming the key and its derivation path. Ours reported the ranged
expression the scan was started with -- the same string for every match, and
the one string that says nothing about which output was found.

The vectors are rpc_scantxoutset.py:116 byte for byte: the same tprv, the same
0h/0h/* path, the same two expected descriptors including their checksums."
  (let* ((bl:*network* :regtest)
         (node (make-test-node :network :regtest))
         (utxo (bl:node-utxo-set node))
         (desc "combo(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK/0h/0h/*)")
         (expected
           '("pkh([0c5f9a1e/0h/0h/0]026dbd8b2315f296d36e6b6920b1579ca75569464875c7ebe869b536a7d9503c8c)#rthll0rg"
             "pkh([0c5f9a1e/0h/0h/1]033e6f25d76c00bedb3a8993c7d5739ee806397f0529b1b31dda31ef890f19a60c)#mcjajulr")))
    (flet ((p2pkh-of (pubkey-hex)
             (concatenate '(vector (unsigned-byte 8))
                          #(#x76 #xa9 #x14)
                          (bl.crypto:hash160 (bl.crypto:hex-to-bytes pubkey-hex))
                          #(#x88 #xac))))
      ;; One coin per derivation index, paying the pkh() arm of combo().
      (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 1)
                         0 100000
                         (p2pkh-of "026dbd8b2315f296d36e6b6920b1579ca75569464875c7ebe869b536a7d9503c8c")
                         0)
      (bl.store:add-utxo utxo (make-array 32 :element-type '(unsigned-byte 8)
                                             :initial-element 2)
                         0 200000
                         (p2pkh-of "033e6f25d76c00bedb3a8993c7d5739ee806397f0529b1b31dda31ef890f19a60c")
                         0))
    (let* ((r (bl.rpc:dispatch-rpc-method
               node "scantxoutset"
               (wire-params (list "start"
                                  (vector (let ((h (make-hash-table :test 'equal)))
                                            (setf (gethash "desc" h) desc
                                                  (gethash "range" h) 1)
                                            h))))))
           (descs (sort (mapcar (lambda (u) (cdr (assoc "desc" u :test #'string=)))
                                (coerce (cdr (assoc "unspents" r :test #'string=)) 'list))
                        #'string<)))
      (is (equal expected descs)
          "each match must report ITS OWN expanded descriptor; got ~S" descs))))

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

(defun %json-token (value)
  "The JSON text VALUE encodes as -- the number token itself for an amount or
a Core-spelled float, so a test can assert the spelling and not just the
value."
  (with-output-to-string (out) (yason:encode value out)))

(defun %rpc-wire-error (node method params)
  "(code . message) of the rpc-error METHOD signals for PARAMS, or NIL when it
returns. PARAMS goes through the request normalizer, so the top-level
sentinels are the ones a wire caller produces."
  (rpc-error-of
   (lambda ()
     (bl.rpc:dispatch-rpc-method node method (wire-params params)))))

(test hash-arguments-answer-core-parse-hash-v
  "Every hash-valued RPC argument answers Core's ParseHashV sentence, naming
the argument Core names (rpc/util.cpp:117-125).

Core has TWO failure sentences and this tree had eleven, one per call site
(\"Invalid block hash\", \"Invalid txid\", \"blockhash must be a hex
string\", \"blockhash must be a hex string of length 64\", ...), so none of
Core's eight functional assertions could match any of them. The rows below
are the (method, argument, code, message) tuples Core produces; the last two
are the controls that a WELL-FORMED but unknown hash still answers -5, so a
regression in either direction shows up."
  (let ((node (make-test-node))
        (zeros (make-string 64 :initial-element #\0))
        (non-hex (concatenate 'string "zzz" (make-string 61 :initial-element #\0))))
    (dolist (row
             (list
              ;; blockchain.cpp:639 getblockheader -> "hash"
              (list "getblockheader" (list "nonsense") -8
                    "hash must be of length 64 (not 8, for 'nonsense')")
              (list "getblockheader" (list non-hex) -8
                    (format nil "hash must be hexadecimal string (not '~A')" non-hex))
              ;; blockchain.cpp:842 getblock -> "blockhash"
              (list "getblock" (list "1234") -8
                    "blockhash must be of length 64 (not 4, for '1234')")
              ;; blockchain.cpp:541 getblockfrompeer -> "blockhash"
              (list "getblockfrompeer" (list "1234" 0) -8
                    "blockhash must be of length 64 (not 4, for '1234')")
              ;; blockchain.cpp:1828 getchaintxstats -> "blockhash", and it is
              ;; reached BEFORE the index lookup, so this is -8 and not -5.
              (list "getchaintxstats" (list 10 "0") -8
                    "blockhash must be of length 64 (not 1, for '0')")
              (list "getchaintxstats" (list 10 non-hex) -8
                    (format nil "blockhash must be hexadecimal string (not '~A')" non-hex))
              ;; blockchain.cpp:1224 gettxout -> "txid"
              (list "gettxout" (list "foo" 0) -8
                    "txid must be of length 64 (not 3, for 'foo')")
              ;; blockchain.cpp:1732 invalidateblock -> "blockhash"
              (list "invalidateblock" (list "foo") -8
                    "blockhash must be of length 64 (not 3, for 'foo')")
              ;; blockchain.cpp:2955 getblockfilter -> "blockhash"
              (list "getblockfilter" (list "foo") -8
                    "blockhash must be of length 64 (not 3, for 'foo')")
              ;; blockchain.cpp:1519 getdeploymentinfo -> "blockhash"
              (list "getdeploymentinfo" (list "foo") -8
                    "blockhash must be of length 64 (not 3, for 'foo')")
              ;; mempool.cpp:880 getmempoolentry -> "txid"
              (list "getmempoolentry" (list "foo") -8
                    "txid must be of length 64 (not 3, for 'foo')")
              ;; mining.cpp:524 prioritisetransaction -> "txid"
              (list "prioritisetransaction" (list "foo" 0 100) -8
                    "txid must be of length 64 (not 3, for 'foo')")
              ;; txoutproof.cpp:52,63 gettxoutproof -> "txid" / "blockhash"
              (list "gettxoutproof" (list (list (subseq zeros 0 32))) -8
                    (format nil "txid must be of length 64 (not 32, for '~A')"
                            (subseq zeros 0 32)))
              (list "gettxoutproof" (list (list zeros) (subseq zeros 0 32)) -8
                    (format nil "blockhash must be of length 64 (not 32, for '~A')"
                            (subseq zeros 0 32)))
              ;; rawtransaction.cpp:287,300 getrawtransaction names its
              ;; arguments by POSITION.
              (list "getrawtransaction" (list "foo") -8
                    "parameter 1 must be of length 64 (not 3, for 'foo')")
              (list "getrawtransaction" (list zeros t "foobar") -8
                    "parameter 3 must be of length 64 (not 6, for 'foobar')")
              ;; rawtransaction_util.cpp:38 AddInputs -> "txid"
              (list "createrawtransaction"
                    ;; #() and not (list): an empty JSON array, since both of
                    ;; createrawtransaction's arrays are RPCArg::Optional::NO
                    ;; and a null in one is a type error before ParseHashV.
                    (list (list (list (cons "txid" "foo") (cons "vout" 0)))
                          #())
                    -8 "txid must be of length 64 (not 3, for 'foo')")
              ;; rawtransaction_util.cpp:113 ParseOutputs -> ParseHexV "Data",
              ;; the wallet_send.py:277 sentence.
              (list "createrawtransaction"
                    (list #() (list (cons "data" "Hello World")))
                    -8 "Data must be hexadecimal string (not 'Hello World')")
              ;; A non-string never reaches ParseHashV: the declared-type
              ;; gate refuses it first, exactly as Core's does.
              (list "getblockheader" (list 5) -3
                    (format nil "Wrong type passed:~%{~%    \"Position 1 (blockhash)\": ~
\"JSON value of type number is not of expected type string\"~%}"))
              ;; Controls: a well-formed unknown hash is still -5.
              (list "getblockheader" (list zeros) -5 "Block not found")
              (list "getchaintxstats" (list 10 zeros) -5 "Block not found")))
      (destructuring-bind (method params code message) row
        (let ((got (%rpc-wire-error node method params)))
          (is (equal (cons code message) got)
              "~A ~S answered ~S, Core answers ~S"
              method params got (cons code message)))))))

(test parse-fixed-point-is-cores
  "PARSE-FIXED-POINT reproduces every vector in Core's test_ParseFixedPoint
(test/util_tests.cpp:935-1007), at 8 decimals and at the 3 a sat/vB fee rate
uses. The rejections carry the whole rule: no leading zero run, no bare
'.1' or trailing '1.', no trailing garbage, a scale that must land in
[0,18) once the decimals are added, and Core's UPPER_BOUND of 10^18-1
rather than 2^63-1."
  (dolist (row '(("0" 8 0) ("1" 8 100000000) ("0.0" 8 0)
                 ("-0.1" 8 -10000000) ("1.1" 8 110000000)
                 ("1.10000000000000000" 8 110000000)
                 ("1.1e1" 8 1100000000) ("1.1e-1" 8 11000000)
                 ("1000" 8 100000000000) ("-1000" 8 -100000000000)
                 ("0.00000001" 8 1) ("0.0000000100000000" 8 1)
                 ("-0.00000001" 8 -1)
                 ("1000000000.00000001" 8 100000000000000001)
                 ("9999999999.99999999" 8 999999999999999999)
                 ("-9999999999.99999999" 8 -999999999999999999)
                 ("" 8 nil) ("-" 8 nil) ("a-1000" 8 nil) ("-a1000" 8 nil)
                 ("-1000a" 8 nil) ("-01000" 8 nil) ("00.1" 8 nil)
                 (".1" 8 nil) ("--0.1" 8 nil)
                 ("0.000000001" 8 nil) ("-0.000000001" 8 nil)
                 ("0.00000001000000001" 8 nil)
                 ("-10000000000.00000000" 8 nil) ("10000000000.00000000" 8 nil)
                 ("-10000000000.00000001" 8 nil) ("10000000000.00000001" 8 nil)
                 ("-10000000000.00000009" 8 nil) ("10000000000.00000009" 8 nil)
                 ("-99999999999.99999999" 8 nil) ("99999909999.09999999" 8 nil)
                 ("92233720368.54775807" 8 nil) ("92233720368.54775808" 8 nil)
                 ("-92233720368.54775808" 8 nil) ("-92233720368.54775809" 8 nil)
                 ("1.1e" 8 nil) ("1.1e-" 8 nil) ("1." 8 nil)
                 ("0.001" 3 1) ("0.0009" 3 nil) ("31.00100001" 3 nil)
                 ("31.0011" 3 nil) ("31.99999999" 3 nil)
                 ("31.999999999999999999999" 3 nil)))
    (destructuring-bind (text decimals expected) row
      (let ((got (bl.rpc::parse-fixed-point text decimals)))
        (is (equal expected got)
            "ParseFixedPoint(~S, ~D) is ~S in Core, ~S here"
            text decimals expected got)))))

(test amount-from-value-is-cores
  "AMOUNT-FROM-VALUE reproduces Core's rpc_parse_monetary_values
(test/rpc_tests.cpp:280-312), and its number path agrees with its string
path because Core's does: UniValue keeps a number's source text and
AmountFromValue parses THAT.

The split between the two messages is Core's and is asserted, not just the
code: text whose SCALE does not fit is \"Invalid amount\" (1e-9,
10000000000, 92233720368.54775808 -- the last two look like range errors and
are not), while text that parses to a value outside [0, MAX_MONEY] is
\"Amount out of range\" (-1, 21000001)."
  (dolist (row (list (list "-0.00000001" "Amount out of range")
                     (list "0" 0) (list "0.00000000" 0) (list "0.00000001" 1)
                     (list "0.17622195" 17622195) (list "0.5" 50000000)
                     (list "0.50000000" 50000000) (list "0.89898989" 89898989)
                     (list "1.00000000" 100000000)
                     (list "20999999.9999999" 2099999999999990)
                     (list "20999999.99999999" 2099999999999999)
                     (list "1e-8" 1) (list "0.1e-7" 1) (list "0.01e-6" 1)
                     (list "0.00000000000000000000000000000000000001e+30" 1)
                     (list "10000000000000000000000000000000000000000000000000000000000000000e-64"
                           100000000)
                     (list "1e-9" "Invalid amount")
                     (list "0.000000019" "Invalid amount")
                     (list "0.00000001000000" 1)
                     (list "19e-9" "Invalid amount")
                     (list "0.19e-6" 19)
                     (list ".19e-6" "Invalid amount")
                     (list "92233720368.54775808" "Invalid amount")
                     (list "1e+11" "Invalid amount")
                     (list "1e11" "Invalid amount")
                     (list "93e+9" "Invalid amount")
                     ;; Spellings the hand-rolled parser used to accept, and
                     ;; Core does not: a leading zero run.
                     (list "01" "Invalid amount")
                     (list "00.1" "Invalid amount")
                     (list "000" "Invalid amount")
                     ;; The number path, through the same parser.
                     (list 1 100000000) (list 0 0)
                     (list 21000000 2100000000000000)
                     (list 21000001 "Amount out of range")
                     (list -1 "Amount out of range")
                     (list 10000000000 "Invalid amount")
                     (list 0.1d0 10000000) (list 1.0d0 100000000)
                     (list 1d-8 1) (list 1d-9 "Invalid amount")
                     (list -1.0d0 "Amount out of range")
                     (list 1/2 50000000)
                     (list t "Amount is not a number or string")
                     (list nil "Amount is not a number or string")))
    (destructuring-bind (value expected) row
      (let ((got (handler-case (bl.rpc:amount-from-value value)
                   (bl.rpc:rpc-error (e) (bl.rpc:rpc-error-message e)))))
        (is (equal expected got)
            "AmountFromValue(~S) is ~S in Core, ~S here" value expected got)))))

(test amounts-encode-as-cores-number-token
  "Every BTC amount encodes as the JSON number token Core's ValueFromAmount
writes (core_io.cpp:286-296): sign, quotient, '.', and exactly eight decimal
digits -- 1.00000000, not the 1.0 a float printer chooses, and 0.00000001,
not 1.0e-8.

Asserted on the ENCODED TEXT, because that is the whole divergence: the
VALUES agreed the entire time, and Core's functional tests read these fields
as Decimal, which is exactly why they could not see it."
  (dolist (row '((0 "0.00000000") (1 "0.00000001") (1000 "0.00001000")
                 (10000000 "0.10000000") (100000000 "1.00000000")
                 (12345678 "0.12345678") (99999999 "0.99999999")
                 (5000000000 "50.00000000")
                 (2099999999999999 "20999999.99999999")
                 (2100000000000000 "21000000.00000000")
                 (-1 "-0.00000001") (-1000 "-0.00001000")
                 (-5000000000 "-50.00000000")))
    (destructuring-bind (satoshis text) row
      (let ((encoded (with-output-to-string (out)
                       (yason:encode (bl.rpc:satoshi->btc satoshis) out))))
        (is (string= text encoded)
            "~D satoshis encode as ~S, Core writes ~S" satoshis encoded text))))
  ;; A whole reply, so the token is not quoted and not re-wrapped on the way
  ;; through rpc-result->json.
  (let ((json (rpc-result-json
               (list (cons "amount" (bl.rpc:satoshi->btc 100000000))
                     (cons "fee" (bl.rpc:satoshi->btc -1))))))
    (is (search "\"amount\":1.00000000" json) "amount token: ~A" json)
    (is (search "\"fee\":-0.00000001" json) "fee token: ~A" json)
    (is-false (search "\"1.00000000\"" json)
              "the amount was quoted as a string: ~A" json))
  ;; Positive control for the assertion above: a double in the same slot is
  ;; what the tree used to emit, and it does NOT match Core's spelling.
  (let ((double-json (with-output-to-string (out)
                       (yason:encode (/ 100000000 100000000.0d0) out))))
    (is (string/= "1.00000000" double-json)
        "the float path already spells amounts Core's way, so this test is vacuous")))

(test rpc-arguments-run-cores-declared-type-gate
  "GA11 be96017b. Core checks every DECLARED argument type once, before the
handler body, and reports ALL the mismatches at once: RPCHelpMan::HandleRequest
walks m_args calling RPCArg::MatchesType, collects each failure under
\"Position N (name)\" and throws one RPC_TYPE_ERROR whose message is
\"Wrong type passed:\\n\" plus that object at indent 4 (rpc/util.cpp:647-657,
:899-910).

There was no gate here at all. A handler read its arguments and whatever went
wrong first was the answer, so getblockhash(\"foo\") was -8 \"Invalid height
parameter\" and getchaintxstats('') reached the block index -- a different
sentence per handler for the one thing Core says the same way everywhere --
while the two handlers that DID answer -3 reported only the FIRST offending
position.

The first row is rpc_blockchain.py:496-506 byte for byte."
  (let ((node (make-test-node)))
    (is (equal (cons -3 (format nil "Wrong type passed:~%{~%    ~
\"Position 1 (nblocks)\": \"JSON value of type string is not of expected type number\",~%    ~
\"Position 2 (height)\": \"JSON value of type array is not of expected type number\"~%}"))
               (%rpc-wire-error node "getnetworkhashps" (list "a" (vector))))
        "the two-position getnetworkhashps text is not Core's")
    ;; One position, and the inner sentence rpc_blockchain.py:311 matches on.
    (let ((answer (%rpc-wire-error node "getchaintxstats" (list ""))))
      (is (= -3 (car answer)))
      (is (search "JSON value of type string is not of expected type number"
                  (cdr answer))))
    ;; The sentinels: an explicit false is a bool and a top-level [] an array,
    ;; not the truthy atoms they are in Lisp.
    (is (search "JSON value of type bool is not of expected type number"
                (cdr (%rpc-wire-error node "getblockhash"
                                      (list bl.rpc:+json-false+)))))
    (is (search "JSON value of type array is not of expected type string"
                (cdr (%rpc-wire-error node "getblockheader" (list (vector))))))
    ;; A null argument passes where Core's MatchesType lets one through, which
    ;; is an OPTIONAL declared slot (rpc/util.cpp:591-597): help's one argument
    ;; is optional, so an explicit null there is accepted.
    (is (null (%rpc-wire-error node "help" (list nil))))
    ;; In a REQUIRED slot it is not: MatchesType returns false and the position
    ;; is reported like any other type mismatch. Ours let every null through,
    ;; so validateaddress(None) reached the handler and answered normally --
    ;; rpc_invalid_address_message.py:105 asks for the -3.
    (let ((answer (%rpc-wire-error node "validateaddress" (list nil))))
      (is (eql -3 (car answer)))
      (is-true (search "JSON value of type null is not of expected type string"
                       (cdr answer))))
    ;; and a null a caller did NOT pass is still not a null: the trailing
    ;; optional arguments of getblock stay omitted rather than becoming
    ;; explicit nulls at a required position.
    (is (equal (cons -5 "Block not found")
               (%rpc-wire-error node "getblock"
                                (list (make-string 64 :initial-element #\0)))))
    ;; skip_type_check positions are not gated: getblock takes a BOOL
    ;; verbosity (blockchain.cpp:771-772), so this reaches the handler and
    ;; fails its lookup instead.
    (is (equal (cons -5 "Block not found")
               (%rpc-wire-error node "getblock"
                                (list (make-string 64 :initial-element #\0) t))))
    ;; Positive controls: correctly typed calls are not refused by the gate.
    (is (null (%rpc-wire-error node "getnetworkhashps" (list 120 -1))))
    (is (null (%rpc-wire-error node "help" (list "getblockcount"))))))

(test getchaintxstats-txrate-is-a-double-spelled-as-core-spells-one
  "Core pushes `double(window_tx_count) / nTimeDiff\' and UniValue::setFloat
writes a double with setprecision(16) (rpc/blockchain.cpp:1868,
univalue.cpp:74-82), so one transaction every ten minutes is the token
0.001666666666666667. Ours divided by a SINGLE-float -- (float x) is single in
Common Lisp -- and let the Lisp printer spell the result, so the field read
0.0016666667: rpc_blockchain.py:333 multiplies txrate by 600 and rounds to ten
places, and got 1.0000000242 where Core gets 1.

The chain is the synthetic 600-second ladder, the spacing Core\'s own test
mines at, and every entry carries one transaction. The two other fields are
asserted alongside it, because they are the numerator and denominator the
token has to be the quotient of -- without them a right-looking spelling of
the wrong division would pass."
  (let ((node (make-test-node)))
    (multiple-value-bind (cs tip) (make-versionbits-chain-with-tip 200)
      (declare (ignore tip))
      (maphash (lambda (h e)
                 (declare (ignore h))
                 (setf (bl.store:block-index-entry-tx-count e) 1))
               (bl.store:chain-state-block-index cs))
      (setf (bl:node-chain-state node) cs)
      (let ((stats (bl.rpc:dispatch-rpc-method
                    node "getchaintxstats" (wire-params (list 1)))))
        (flet ((field (name) (cdr (assoc name stats :test #'string=))))
          (is (equal 1 (field "window_tx_count")))
          (is (equal 600 (field "window_interval"))
              "the ladder is ten minutes a block, as Core\'s test mines it")
          (is (equal "0.001666666666666667" (json-number-token (field "txrate")))
              "txrate is a double spelled with sixteen significant digits"))))))

(test rpc-call-with-the-wrong-number-of-arguments-is-the-help-text
  "Core gates the argument COUNT before it gates their types and before the
handler body: RPCHelpMan::HandleRequest throws the help text when
IsValidNumArgs(request.params.size()) is false (rpc/util.cpp:644), which is
`num_required_args <= n <= m_args.size()\' -- num_required_args being the
position AFTER the last RPCArg::Optional::NO argument, not the count of
required ones (:733-745). HelpResult is a plain std::runtime_error that only
the `help\' method catches (rpc/server.cpp:94), so an ordinary call lands in
ExecuteCommand's catch-all: RPC_MISC_ERROR (-1) with the help text as the
message (:514-515).

This node ignored extra positional arguments entirely and let a missing
required one reach the handler as NIL. Core's own tests assert the -1 by
looking for the method name inside the message
(rpc_rawtransaction.py:255-259, rpc_estimatefee.py:21-22, rpc_help.py:126),
and the message here is the first line of that help text -- all of it this
node has, since no method carries Core's description and result sections.

Named-argument requests need no separate gate: %REQUEST-PARAMS runs the
transform to positional before DISPATCH-RPC-METHOD sees the parameters at
all, which is the order Core reaches transformNamedArguments in
(rpc/server.cpp:506-509)."
  (let ((node (make-test-node))
        (zeros (make-string 64 :initial-element #\0)))
    (flet ((answer (method &rest params)
             (%rpc-wire-error node method params)))
      ;; The message is the whole help DOCUMENT, which OPENS with the usage
      ;; line: Core throws HelpResult, i.e. RPCHelpMan::ToString()
      ;; (rpc/util.cpp:644,733-745), and rpc_invalid_address_message.py:103
      ;; looks for a method's DESCRIPTION in the -1 a no-argument call gets.
      (flet ((refusal-opens-with (usage answer)
               (and (consp answer)
                    (eql -1 (car answer))
                    (eql 0 (search (format nil "~A~%" usage) (cdr answer))))))
        ;; One argument too many, for a method that declares none and for one
        ;; that declares a single optional one. The second is rpc_help.py:126.
        (is-true (refusal-opens-with "uptime" (answer "uptime" 1)))
        (is-true (refusal-opens-with "help ( \"command\" )" (answer "help" "a" "b")))
        ;; Too few: the one required argument of getblockhash.
        (is-true (refusal-opens-with "getblockhash height" (answer "getblockhash")))
        ;; An OPTIONAL argument before a required one still has to be passed --
        ;; prioritisetransaction's `dummy\' sits between txid and fee_delta, so
        ;; two arguments are too few even though only two are required.
        (is-true (refusal-opens-with "prioritisetransaction \"txid\" ( dummy ) fee_delta"
                                     (answer "prioritisetransaction" zeros 0)))
        ;; and it carries the description, which is the half a client needs and
        ;; the half this used to drop.
        (is-true (search "Return the hash of block at given height."
                         (cdr (answer "getblockhash")))))
      ;; Positive controls. Exactly the maximum still RUNS: help answers with
      ;; that method's document, which OPENS with its usage line (Core
      ;; RPCHelpMan::ToString, rpc/util.cpp:773-793).
      (is (null (answer "help" "getblockcount")))
      (is (eql 0 (search (format nil "getblockcount~%~%")
                         (bl.rpc:dispatch-rpc-method
                          node "help" (wire-params (list "getblockcount"))))))
      ;; Trailing optional arguments may still be omitted, all of them.
      (is (null (answer "help")))
      (is (null (answer "getrawmempool")))
      (is (null (answer "uptime")))
      ;; A method this node registers and Core does not declare has no row and
      ;; is not gated: migrateblocks takes two arguments and a third reaches
      ;; the handler, which answers for its own first one. STRUCTURAL-TESTS
      ;; pins that set to migrateblocks alone.
      (is (equal (cons -8 "nblocks must be a positive integer")
                 (answer "migrateblocks" 0 0 0))))))

(test rpc-usage-line-spells-a-structured-argument-as-core-does
  "A usage line renders an ARR or OBJ argument as its INNER arguments --
`[scanobjects,...]', `{\"rollback\":n,...}' -- or as the oneline_description
its declaration overrides that with, which is Core's RPCArg::ToString(oneline)
(rpc/util.cpp:1249-1291) and RPCArg::ToStringObj (:1209-1245).

These lines were the argument's bare NAME, so the help text Core's arity error
carries was shorter than Core's for every method taking a list or an object:
rpc_scantxoutset.py:133 calls scantxoutset with no arguments and looks for
`scantxoutset \"action\" ( [scanobjects,...] )' inside the -1, and read
`scantxoutset \"action\" ( scanobjects )'.

A HIDDEN argument ends the line where Core ends it (`if (arg.m_opts.hidden)
break', rpc/util.cpp:778): stop's `wait' is declared hidden, so its summary is
the bare method name even though the argument is still accepted."
  (let ((node (make-test-node)))
    (flet ((answer (method &rest params)
             ;; The arity error carries the whole help DOCUMENT, as Core's
             ;; does; the usage line is its first line.
             (let ((message (cdr (%rpc-wire-error node method params))))
               (subseq message 0 (or (position #\Newline message)
                                     (length message))))))
      (is (equal "scantxoutset \"action\" ( [scanobjects,...] )"
                 (answer "scantxoutset")))
      (is (equal (concatenate 'string "scanblocks \"action\" ( [scanobjects,...] "
                              "start_height stop_height \"filtertype\" options )")
                 (answer "scanblocks")))
      (is (equal (concatenate 'string "createrawtransaction "
                              "[{\"txid\":\"hex\",\"vout\":n,\"sequence\":n},...] "
                              "[{\"address\":amount,...},{\"data\":\"hex\"},...] "
                              "( locktime replaceable version )")
                 (answer "createrawtransaction")))
      (is (equal "dumptxoutset \"path\" ( \"type\" {\"rollback\":n,...} )"
                 (answer "dumptxoutset")))
      ;; getblockstats' `stats' is an ARR whose declaration overrides the
      ;; rendering with the plain word (rpc/blockchain.cpp:1951).
      (is (equal "getblockstats hash_or_height ( stats )"
                 (answer "getblockstats")))
      (is (equal "stop" (answer "stop" 1 2)))
      ;; The unstructured lines the suite already pins are unchanged.
      (is (equal "getblockhash height" (answer "getblockhash")))
      (is (equal "help ( \"command\" )" (answer "help" "a" "b"))))))

(test rpc-arg-types-table-agrees-with-the-names-table
  "Both generated tables come from the same RPCHelpMan declarations
(scripts/gen-rpc-arg-names.py), so a method's type row can never be longer
than its name row -- if it were, the gate would report \"Position N (argN)\"
for an argument Core has a name for."
  (let ((rows 0))
    (dolist (row bl.rpc::*rpc-arg-types*)
      (let ((names (cdr (assoc (first row) bl.rpc::*rpc-named-arg-names*
                               :test #'string=))))
        (incf rows)
        (is (<= (length (rest row)) (length names))
            "~A declares ~D types and ~D names"
            (first row) (length (rest row)) (length names))))
    ;; The table is data generated from Core; a build that lost it would make
    ;; the gate silently vacuous, so the count itself is asserted.
    (is (<= 130 rows) "only ~D methods carry declared argument types" rows)))

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
  (rpc-result-json result))

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
                        (cons "listbanned" (call-listbanned node))
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
    (call-setban node (list "1.2.3.4" "add"))
    (let ((peers (%encode-rpc-result (bl.rpc::rpc-getpeerinfo node nil)))
          (bans (%encode-rpc-result (call-listbanned node)))
          (added (%encode-rpc-result (bl.rpc::rpc-getaddednodeinfo node nil))))
      (is (eql 0 (search "[{" peers)))
      (is (eql 0 (search "[{" bans)))
      ;; Core keys the ban list by CSubNet, so a bare address is listed as the
      ;; /32 containing it (CSubNet::ToString, netaddress.cpp:1047-1080).
      (is (search "\"address\":\"1.2.3.4/32\"" bans))
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


(test getnetworkinfo-lists-core-s-networks-and-their-proxies
  "Core GetNetworksInfo (rpc/net.cpp:614-631): ipv4, ipv6, onion, i2p and cjdns,
in that order, each with limited/reachable and the proxy that reaches it --
-proxy for ipv4, ipv6 and cjdns, the onion proxy for onion, -i2psam for i2p.
bitcoin-cli -getinfo prints its Proxies line from these (bitcoin-cli.cpp:1123-1139)
and interface_bitcoin_cli.py:238 expects `127.0.0.1:9050 (ipv4, ipv6, onion,
cjdns), 127.0.0.1:7656 (i2p)'. The list used to be one entry named after the
chain, with no proxy at all."
  (let* ((bl.net:*proxy* (bl.net:make-proxy :host "127.0.0.1" :port 9050))
         (bl.net:*onion-proxy* bl.net:*proxy*)
         (bl.net:*i2p-sam-proxy* "127.0.0.1:7656")
         (bl.net:*reachable-networks* '(:ipv4 :ipv6 :torv3))
         (networks (cdr (assoc "networks" (bl.rpc:dispatch-rpc-method (make-test-node) "getnetworkinfo" nil)
                               :test #'string=))))
    (flet ((field (entry key) (cdr (assoc key entry :test #'string=))))
      (is (equal '("ipv4" "ipv6" "onion" "i2p" "cjdns")
                 (mapcar (lambda (e) (field e "name")) networks)))
      (is (equal '("127.0.0.1:9050" "127.0.0.1:9050" "127.0.0.1:9050" "127.0.0.1:7656" "127.0.0.1:9050")
                 (mapcar (lambda (e) (field e "proxy")) networks)))
      (is (equal (list t t t nil nil)
                 (mapcar (lambda (e) (eq t (field e "reachable"))) networks)))
      (is (equal (list nil nil nil t t)
                 (mapcar (lambda (e) (eq t (field e "limited"))) networks)))))
  ;; Without a proxy every proxy is the empty string, as in Core.
  (let* ((bl.net:*proxy* nil) (bl.net:*onion-proxy* nil) (bl.net:*i2p-sam-proxy* nil)
         (networks (cdr (assoc "networks" (bl.rpc:dispatch-rpc-method (make-test-node) "getnetworkinfo" nil)
                               :test #'string=))))
    (is (every (lambda (e) (equal "" (cdr (assoc "proxy" e :test #'string=)))) networks))
    (is (= 5 (length networks)))))

(test rpc-getnetworkinfo-counts-live-peers-only
  "connections / connections_in / connections_out count the peers getpeerinfo
lists. Core counts m_nodes (GetNodeCount, net.cpp:3769-3781) and erases a
closed connection from it on the next socket round (DisconnectNodes,
net.cpp:1909-1939); ours keeps a :disconnected peer in node-peers until the
sync cycle reaps it, and getnetworkinfo counted it while getpeerinfo did not
-- the framework's disconnect_p2ps waits on the one and check_node_connections
reads the other (p2p_add_connections.py:73)."
  (let ((node (make-test-node)))
    (setf (bl:node-peers node)
          (list (bl.net:make-peer :address "10.0.0.1" :state :ready :inbound nil)
                (bl.net:make-peer :address "10.0.0.2" :state :ready :inbound t)
                (bl.net:make-peer :address "10.0.0.3" :state :disconnected :inbound nil)))
    (let ((result (bl.rpc:dispatch-rpc-method node "getnetworkinfo" '())))
      (flet ((field (name) (cdr (assoc name result :test #'string=))))
        (is (= 2 (field "connections")) "a :disconnected peer is not a connection")
        (is (= 1 (field "connections_in")))
        (is (= 1 (field "connections_out")))))))
(test getnetworkinfo-lists-the-local-address-table
  "getnetworkinfo's localaddresses is mapLocalHost, one {address, port, score}
per entry in the map's address order (rpc/net.cpp:721-733). Both
feature_bind_port tests read nothing else. Ours answered a constant empty
array whatever -externalip, a Tor onion service or a bind had added."
  (let ((node (make-test-node))
        (saved (bl.net:local-addresses)))
    (unwind-protect
         (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6)))
           (bl.net:clear-local-addresses)
           (bl.net:add-local :ipv4 (bl.net:ipv4-to-mapped-ipv6 2 2 2 2) 30006
                             bl.net:+local-manual+)
           (bl.net:add-local :ipv4 (bl.net:ipv4-to-mapped-ipv6 1 1 1 1) 31001
                             bl.net:+local-manual+)
           (let ((rows (cdr (assoc "localaddresses"
                                   (bl.rpc:dispatch-rpc-method node "getnetworkinfo" '())
                                   :test #'string=))))
             (flet ((field (row name) (cdr (assoc name row :test #'string=))))
               (is (= 2 (length rows)))
               (is (equal '("1.1.1.1" "2.2.2.2")
                          (mapcar (lambda (r) (field r "address")) rows))
                   "rows come in the map's address order")
               (is (equal '(31001 30006) (mapcar (lambda (r) (field r "port")) rows)))
               (is (equal (list bl.net:+local-manual+ bl.net:+local-manual+)
                          (mapcar (lambda (r) (field r "score")) rows))))))
      (bl.net:clear-local-addresses)
      (dolist (la saved)
        (bl.net:add-local (bl.net:local-address-network la)
                          (bl.net:local-address-bytes la)
                          (bl.net:local-address-port la)
                          bl.net:+local-manual+)))))

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

(test rpc-getconnectioncount-counts-live-peers-only
  "getconnectioncount is GetNodeCount(ConnectionDirection::Both) over m_nodes
 (rpc/net.cpp:79, net.cpp:3769-3781), and DisconnectNodes erases a closed
connection from m_nodes on the next socket round (net.cpp:1909-1939). Ours
kept a :disconnected peer in node-peers until the sync cycle reaped it, so
p2p_nobloomfilter_messages.py:31 -- which asserts 0 as soon as its peer's
socket closes -- read 1. ping walks the same list."
  (let ((node (make-test-node)))
    (setf (bl:node-peers node)
          (list (bl.net:make-peer :address "10.0.0.1" :state :ready :inbound t)
                (bl.net:make-peer :address "10.0.0.2" :state :disconnected
                                  :inbound t)))
    (is (= 1 (bl.rpc:dispatch-rpc-method node "getconnectioncount" '()))
        "a :disconnected peer is not a connection")
    (setf (bl:node-peers node)
          (list (bl.net:make-peer :address "10.0.0.2" :state :disconnected
                                  :inbound t)))
    (is (= 0 (bl.rpc:dispatch-rpc-method node "getconnectioncount" '()))
        "the last peer's disconnection leaves no connections")))

;;; --- Mempool Method Tests (6.5) ---

(test rpc-getmempoolinfo
  "Test getmempoolinfo returns expected fields"
  (let* ((node (make-test-node))
         (result (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil)))
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

(test createrawtransaction-accepts-an-empty-outputs-array
  "Core's outputs argument goes through get_array() (NormalizeOutputs,
rawtransaction_util.cpp:81), which accepts an EMPTY array and then walks no
keys, so createrawtransaction([], []) builds a transaction with no outputs
rather than erroring -- rpc_rawtransaction.py:295 calls it for exactly that
backwards compatibility. A top-level `[]' arrives here as the truthy
empty-array sentinel, which is not a list, so the type-error arm this batch
gave the argument would have claimed an array is not an array."
  (let ((node (make-test-node)))
    (flet ((create (outputs)
             (bl.rpc:dispatch-rpc-method
              node "createrawtransaction"
              (wire-params (list (vector) outputs)))))
      (is-true (stringp (create (vector)))
               "an empty outputs ARRAY must build a transaction")
      (is-true (stringp (create (make-hash-table :test 'equal)))
               "and so must an empty outputs OBJECT")
      ;; Control: a string is still Core's type error, which is what the
      ;; sentinel arm must not swallow.
      (is (equal (list -3   ; Core RPC_TYPE_ERROR, protocol.h
                       "JSON value of type string is not of expected type array")
                 (multiple-value-list (%rails-error (lambda () (create "foo")))))))))

(test rpc-getmempoolinfo-reports-cores-policy-fields
  "getmempoolinfo's last four fields (rpc/mempool.cpp:1050-1053):
maxdatacarriersize, limitclustercount, limitclustersize and optimal. Every
one of them was missing, which is a KeyError to a client that reads it --
mempool_datacarrier.py:57 and mempool_cluster.py:319 both do.

maxdatacarriersize is max_datacarrier_bytes.value_or(0), so -datacarrier=0
answers 0 rather than the unused byte budget (mempool_args.cpp:94-98)."
  (let* ((node (make-test-node))
         (result (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil))
         (get (lambda (k) (cdr (assoc k result :test #'string=)))))
    (is (= bl:*max-datacarrier-bytes* (funcall get "maxdatacarriersize")))
    (is (= bl.mp:*cluster-count-limit* (funcall get "limitclustercount")))
    (is (= bl.mp:*cluster-size-limit* (funcall get "limitclustersize")))
    (is (eq t (funcall get "optimal")))
    ;; A node that relays no OP_RETURN reports 0, not its byte budget.
    (let ((bl:*accept-datacarrier* nil))
      (is (zerop (cdr (assoc "maxdatacarriersize"
                             (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil)
                             :test #'string=)))))
    ;; The cluster fields come from THIS pool, not from the globals: a pool
    ;; built under other limits reports its own.
    (let* ((bl.mp:*cluster-count-limit* 7)
           (bl.mp:*cluster-size-limit* 12345)
           (other (bl.mp:make-mempool))
           (other-node (make-test-node)))
      (setf (bl:node-mempool other-node) other)
      (let ((r (bl.rpc:dispatch-rpc-method other-node "getmempoolinfo" nil)))
        (is (= 7 (cdr (assoc "limitclustercount" r :test #'string=))))
        (is (= 12345 (cdr (assoc "limitclustersize" r :test #'string=))))))))

(test rpc-mempool-entry-depends-and-spentby-are-arrays
  "Core builds `depends' and `spentby' as UniValue VARRs (entryToJSON,
rpc/mempool.cpp:494-506), so an entry at the end of a chain answers [] and
never null. We emitted the CL empty list, which yason writes as null, and
mempool_packages.py:108 compares the last entry's spentby with []."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (funding (%txid-array 77))
         (parent (make-spending-test-tx funding :vout 0 :value 50000000))
         (pid (bl.ser:transaction-hash parent))
         (child (make-spending-test-tx pid :vout 0 :value 40000000))
         (cid (bl.ser:transaction-hash child)))
    (%add-tx mempool parent :fee 1000)
    (%add-tx mempool child :fee 2000)
    (let ((p (bl.rpc::rpc-getmempoolentry node (list (bl.rpc:hash-to-hex pid))))
          (c (bl.rpc::rpc-getmempoolentry node (list (bl.rpc:hash-to-hex cid)))))
      ;; The parent has no unconfirmed parents and the child no unconfirmed
      ;; children: both empty, and both must still be arrays.
      (is (equalp #() (cdr (assoc "depends" p :test #'string=))))
      (is (equalp #() (cdr (assoc "spentby" c :test #'string=))))
      ;; Control: the populated direction is a plain list of hex ids, which
      ;; is what makes the empty case the only one JSON-ARRAY changes.
      (is (equal (list (bl.rpc:hash-to-hex pid))
                 (cdr (assoc "depends" c :test #'string=))))
      (is (equal (list (bl.rpc:hash-to-hex cid))
                 (cdr (assoc "spentby" p :test #'string=)))))))

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
;;; pkg-tx): standard, script-valid transactions with no signing key.

(defun %broadcast-test-node (utxo-set mempool chain-state peer)
  "A test node wired to the fixture state with one ready relay peer."
  (let ((node (bl:make-node :network :testnet3)))
    (setf (bl:node-chain-state node) chain-state
          (bl:node-utxo-set node) utxo-set
          (bl:node-mempool node) mempool
          (bl:node-peers node) (list peer))
    node))

(test rpc-sendrawtransaction-resubmits-nothing-that-is-already-there
  "Core looks the transaction up by TXID before validating anything
(node/transaction.cpp:63-72). Finding it, BroadcastTransaction does not
resubmit -- it only re-announces, and with the POOL entry's wtxid, because
that is the witness this node can serve. The lookup is by txid on purpose, so
a submission whose witness differs from the pooled one takes the same branch:
mempool_accept_wtxid.py:82 sends exactly that and expects the txid back, not
an error.

This node asked VALIDATE-TRANSACTION-FOR-MEMPOOL instead and took the branch
only for its :already-in-mempool verdict, so the different-witness case fell
through to the generic rejection and threw -26
txn-same-nonwitness-data-in-mempool."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((peer (bl.net:make-peer :state :ready))
           (node (%broadcast-test-node utxo-set mempool chain-state peer))
           (tx (pkg-tx funding-txid 0 (- 100000000 10000)))
           (txid (bl.ser:transaction-hash tx))
           (hex (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx))))
      (flet ((send (h) (bl.rpc:dispatch-rpc-method
                        node "sendrawtransaction" (wire-params (list h)))))
        (is (string= (bl.rpc:hash-to-hex txid) (send hex)))
        (is-true (bl.mp:mempool-has mempool txid))
        ;; The same transaction again: the txid, not an error, and the pool is
        ;; untouched.
        (is (string= (bl.rpc:hash-to-hex txid) (send hex)))
      (is (= 1 (bl.mp:mempool-count mempool)))
      ;; A DIFFERENT witness over the same non-witness data. The pooled entry
      ;; is the one that stays; the caller still gets the txid.
      ;; The hex must carry the witness, so TRANSACTION-WIRE-BYTES rather
      ;; than SERIALIZE-TRANSACTION, which writes the legacy form and would
      ;; hand the RPC the SAME transaction back.
      (let* ((other (bl.ser:make-transaction
                     :version (bl.ser:transaction-version tx)
                     :inputs (bl.ser:transaction-inputs tx)
                     :outputs (bl.ser:transaction-outputs tx)
                     :witness (vector (list (make-array 3 :element-type '(unsigned-byte 8)
                                                          :initial-element 7)))
                     :lock-time (bl.ser:transaction-lock-time tx)))
             (other-hex (bl.crypto:bytes-to-hex (bl.ser:transaction-wire-bytes other)))
             ;; The control is about what the RPC DECODES, not about the
             ;; object built here.
             (decoded (bl.bytes:with-byte-reader
                          (r (bl.crypto:hex-to-bytes other-hex))
                        (bl.ser:br-read-transaction r))))
        (is (equalp txid (bl.ser:transaction-hash decoded))
            "control: the second submission must share the pooled txid")
        (is-false (equalp (bl.ser:transaction-wtxid tx)
                          (bl.ser:transaction-wtxid decoded))
                  "control: and differ in wtxid")
        (is (string= (bl.rpc:hash-to-hex txid) (send other-hex)))
        (is (= 1 (bl.mp:mempool-count mempool)))
        ;; The pooled entry is untouched: it is still the witness this node
        ;; can serve.
        (is (equalp (bl.ser:transaction-wtxid tx)
                    (bl.mp:mempool-entry-wtxid (bl.mp:mempool-get mempool txid)))))))))

(test rpc-sendrawtransaction-rejection-speaks-cores-vocabulary
  "A rejection raised by the INSERTION step -- after every check passed --
must report Core's own reject reason like any other. BroadcastTransaction
sets err_string to state.ToString() and the RPC prints exactly that
(node/transaction.cpp:21, rpc/util.cpp:408-414); this node wrapped the
keyword in a prefix of its own -- Mempool rejection: TOO-LARGE-CLUSTER -- so
mempool_updatefromblock.py:192 and mempool_truc.py:238, which both look for
Core's too-large-cluster in the -26 message, saw a word that is in no Bitcoin
implementation.

The cluster-count limit is the reachable one: build the pool with a limit of
1 so a child of an in-pool parent is the transaction the changeset refuses
(validation.cpp:1020-1022)."
  (let* ((bl.mp:*cluster-count-limit* 1)
         (utxo-set (bl.store:make-utxo-set))
         (mempool (bl.mp:make-mempool))
         (chain-state (bl.store:make-chain-state :best-height 200))
         (funding (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))
    (bl.store:add-utxo utxo-set funding 0 100000000
                       (p2sh-optrue-script-pubkey) 1 :coinbase nil)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (parent (pkg-tx funding 0 (- 100000000 10000)))
           (child (pkg-tx (bl.ser:transaction-hash parent) 0
                           (- 100000000 20000))))
      (bl.rpc::rpc-sendrawtransaction
       node (list (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction parent))))
      (is-true (bl.mp:mempool-has mempool (bl.ser:transaction-hash parent))
               "the fixture's parent did not enter the pool")
      (multiple-value-bind (code message)
          (%rails-error
           (lambda ()
             (bl.rpc::rpc-sendrawtransaction
              node (list (bl.crypto:bytes-to-hex
                          (bl.ser:serialize-transaction child))))))
        (is (eql bl.rpc::+rpc-transaction-rejected+ code))
        (is (string= "too-large-cluster" message))))))

(test rpc-sendrawtransaction-broadcasts
  "sendrawtransaction accepts the tx, adds it to the mempool's unbroadcast
set, and queues an announcement to relay peers (Core BroadcastTransaction,
node/transaction.cpp:100-135); resubmitting the same tx is NOT an error and
re-announces (already-in-mempool branch, :63-72) without re-adding to the
unbroadcast set."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((peer (bl.net:make-peer :state :ready))
           (node (%broadcast-test-node utxo-set mempool chain-state peer))
           (tx (pkg-tx funding-txid 0 (- 100000000 10000)))
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
           (tx (pkg-tx funding-txid 0 (- 100000000 10000)))
           (hex (bl.crypto:bytes-to-hex
                 (bl.ser:serialize-transaction tx))))
      (let ((r (first (%testmempoolaccept node (list hex)))))
        (is (eq t (cdr (assoc "allowed" r :test #'string=)))))
      (is (= 0 (bl.mp:mempool-count mempool)))
      (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))
      (is (null (bl.net:peer-tx-inv-queue peer))))))

(test rpc-testmempoolaccept-policy-script-reject-reason
  "A consensus-valid but policy-invalid spend (CLEANSTACK: extra scriptSig
push on a P2SH(OP_TRUE) coin) reports Core's TX_NOT_STANDARD reject-reason
token \"mempool-script-verify-flag-failed\" through testmempoolaccept, with
Core's ScriptErrorString parenthetical naming the flag that rejected --
strprintf(\"mempool-script-verify-flag-failed (%s)\", ScriptErrorString(...)),
CheckInputScripts, validation.cpp:2117."
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
      (let* ((r (first (%testmempoolaccept node (list hex))))
             (details (cdr (assoc "reject-details" r :test #'string=))))
        (is (eq 'yason:false (cdr (assoc "allowed" r :test #'string=))))
        (is (string= "mempool-script-verify-flag-failed (Stack size must be exactly one after execution)"
                     (cdr (assoc "reject-reason" r :test #'string=))))
        ;; reject-details is state.ToString(): the reason, then the debug
        ;; message CScriptCheck built for the failing input
        ;; (rpc/mempool.cpp:400-401, validation.cpp:2018). rpc_packages.py:123
        ;; compares the whole sentence, input index and outpoint included.
        (is-true (stringp details))
        (is (eql 0 (search "mempool-script-verify-flag-failed (Stack size must be exactly one after execution), "
                           (or details ""))))
        (is (search (format nil "input 0 of ~A (wtxid ~A), spending "
                            (bl.rpc:hash-to-hex (bl.ser:transaction-hash tx))
                            (bl.rpc:hash-to-hex (bl.ser:transaction-wtxid tx)))
                    (or details "")))))))

(test rpc-testmempoolaccept-reject-details-is-cores-second-field
  "Core reports the rejection TWICE and differently: `reject-reason' is
state.GetRejectReason(), the token, and `reject-details' is state.ToString(),
the token plus whatever debug message this particular rejection built
(rpc/mempool.cpp:396-402). feature_rbf.py:112 reads both off one RBF
rejection: the reason must be exactly `insufficient fee' while the details
carry the amounts. A verdict with no debug message reports the token for
both, which is what mempool_accept_wtxid.py:59 asserts.

A missing input is the one case with NEITHER field pair: Core substitutes its
own `missing-inputs' for the reason and emits no details at all (:398-399)."
  (let ((rbf (list :rbf-insufficient-fee
                   "rejecting replacement ab, not enough additional fees to relay; 0.00 < 0.00000011")))
    (is (string= "insufficient fee" (bl.val:tx-reject-reason-only rbf)))
    (is (string= "insufficient fee, rejecting replacement ab, not enough additional fees to relay; 0.00 < 0.00000011"
                 (bl.val:tx-reject-reason-string rbf))))
  (multiple-value-bind (tx utxo mempool)
      (%cleanstack-violation-fixture
       (make-array 4 :element-type '(unsigned-byte 8)
                     :initial-contents '(#x01 #x51 #x01 #x51))
       :input-id 141)
    (declare (ignore tx))
    (let* ((node (%broadcast-test-node
                  utxo mempool
                  (bl.store:make-chain-state :best-height 100)
                  (bl.net:make-peer :state :ready)))
           ;; A transaction whose input nothing funds: missing-inputs, the one
           ;; rejection Core answers with a reason and NO details.
           (orphan (bl.ser:make-transaction
                    :version 2
                    :inputs (vector (bl.ser:make-tx-in
                                     :previous-output
                                     (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 199)
                                      :index 0)
                                     :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                                     :sequence #xffffffff))
                    :outputs (vector (bl.ser:make-tx-out
                                      :value 1000
                                      :script-pubkey
                                      ;; OP_RETURN with an 8-byte payload, so
                                      ;; the transaction clears Core's 65-byte
                                      ;; non-witness minimum and the rejection
                                      ;; under test is the missing input.
                                      (make-array 10 :element-type '(unsigned-byte 8)
                                                     :initial-contents
                                                     '(#x6a #x08 1 2 3 4 5 6 7 8))))
                    :lock-time 0))
           (r (first (%testmempoolaccept
                      node
                      (list (bl.crypto:bytes-to-hex
                             (bl.ser:serialize-transaction orphan)))))))
      (is (string= "missing-inputs" (cdr (assoc "reject-reason" r :test #'string=))))
      (is-false (assoc "reject-details" r :test #'string=)))))


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
                    :script-sig (p2sh-optrue-scriptsig)
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
           (tx (pkg-tx funding-txid 0 1000000))
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
                  (pkg-tx funding-txid 0 99990000)))))
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

(test testmempoolaccept-leaves-the-rest-blank-when-a-precheck-fails
  "Core validates a package in two passes: PreChecks for every member, then
PolicyScriptChecks for every member, filling in a member's result only once it
has passed the second (validation.cpp:1444-1474, :1533-1551). It returns at the
first failure of either, and rpc/mempool.cpp:352-395 emits txid and wtxid alone
for every member with no result. So WHICH pass failed decides what the caller
is told about the others:

  a PreChecks failure -- missing inputs here -- leaves every other member
  blank, because none of them has a result yet (rpc_packages.py:106-111);
  a script failure leaves the members BEFORE it in full (:118-120).

Ours validated each member to completion in turn and emitted a full verdict for
every one it reached, so an otherwise valid package with one garbage member
came back with three complete answers Core does not give -- answers about
transactions whose signatures Core deliberately never checked."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    ;; Two more confirmed outputs, so the good members are independent.
    (dolist (index '(1 2))
      (bl.store:add-utxo utxo-set funding-txid index 100000000
                         (p2sh-optrue-script-pubkey) 1 :coinbase nil))
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (good (loop for index from 0 below 3
                       collect (pkg-tx funding-txid index 99999000)))
           (garbage (pkg-tx (make-array 32 :element-type '(unsigned-byte 8)
                                            :initial-element 0)
                             5 1000))
           (bad-script (let ((tx (pkg-tx funding-txid 0 99999000)))
                         (setf (bl.ser:tx-in-script-sig
                                (aref (bl.ser:transaction-inputs tx) 0))
                               (make-array 0 :element-type '(unsigned-byte 8)))
                         tx)))
      (flet ((hex (tx) (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx)))
             (keys (row) (mapcar #'car row))
             (aval (row key) (cdr (assoc key row :test #'string=))))
        ;; Every member on its own is accepted, so the blanks below are the
        ;; package rule and not three broken transactions.
        (let ((solo (%testmempoolaccept node (mapcar #'hex good))))
          (is (equal '(t t t) (mapcar (lambda (r) (aval r "allowed")) solo))))
        ;; The garbage member's inputs are missing: a PreChecks failure.
        (let ((r (%testmempoolaccept
                  node (append (mapcar #'hex good) (list (hex garbage))))))
          (is (= 4 (length r)))
          (is (equal '(("txid" "wtxid") ("txid" "wtxid") ("txid" "wtxid"))
                     (mapcar #'keys (subseq r 0 3)))
              "a member Core never finished validating came back with a verdict")
          (is (eq 'yason:false (aval (fourth r) "allowed")))
          (is (string= "missing-inputs" (aval (fourth r) "reject-reason"))))
        ;; A script failure is the other pass: the member before it keeps its
        ;; full result.
        (let ((r (%testmempoolaccept
                  node (list (hex (second good)) (hex bad-script)))))
          (is (= 2 (length r)))
          (is (eq t (aval (first r) "allowed"))
              "a member Core had already finished lost its verdict")
          (is (eq 'yason:false (aval (second r) "allowed")))
          (is (search "mempool-script-verify-flag-failed"
                      (aval (second r) "reject-reason"))))
        ;; Still a dry run.
        (is (= 0 (bl.mp:mempool-count mempool)))))))

(test rpc-testmempoolaccept-max-fee-exceeded
  "Over the rail, testmempoolaccept reports allowed=false with reject-reason
\"max-fee-exceeded\" and then stops filling in verdicts: every later member
carries txid and wtxid only, because a descendant's verdict is meaningless
once an ancestor would not be submitted (rpc/mempool.cpp:352-355,381)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (parent (pkg-tx funding-txid 0 1000000))
           (child (pkg-tx (bl.ser:transaction-hash parent) 0 900000))
           (ph (bl.crypto:bytes-to-hex
                (bl.ser:serialize-transaction parent)))
           (ch (bl.crypto:bytes-to-hex
                (bl.ser:serialize-transaction child)))
           (r (%testmempoolaccept node (list ph ch))))
      (is (eq 'yason:false (cdr (assoc "allowed" (first r) :test #'string=))))
      (is (string= "max-fee-exceeded"
                   (cdr (assoc "reject-reason" (first r) :test #'string=))))
      ;; Unfinished: no verdict at all on the child.
      (is (equal '("txid" "wtxid") (mapcar #'car (second r))))
      ;; Rail off -> the parent is allowed again.
      (let ((off (%testmempoolaccept node (list ph) 0)))
        (is (eq t (cdr (assoc "allowed" (first off) :test #'string=)))))
      ;; Still a dry run either way.
      (is (= 0 (bl.mp:mempool-count mempool))))))

(test testmempoolaccept-validates-a-package-as-a-package
  "More than one transaction is a PACKAGE, and Core validates it as one: the
members share a coin view, so a child spending a parent that is in the same
call — and nowhere else — is answered on its merits (validation.cpp:1473,
m_viewmempool.PackageAddTransaction; rpc/mempool.cpp:343-346 routes anything
longer than one transaction to ProcessNewPackage with test_accept).

We validated each member independently against the mempool alone, so the
child of an unconfirmed parent came back `missing-inputs' — the one answer a
caller uses this RPC to avoid. Fee policy stays INDIVIDUAL here
(m_package_feerates is false for PackageTestAccept, validation.cpp:509), so
each member reports its own effective feerate over its own wtxid and a package
answer equals the members' individual answers (rpc_packages.py:100)."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (parent (pkg-tx funding-txid 0 99990000))
           (child (pkg-tx (bl.ser:transaction-hash parent) 0 99980000)))
      (flet ((hex (tx) (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx)))
             (aval (row key) (cdr (assoc key row :test #'string=))))
        (let ((r (%testmempoolaccept node (list (hex parent) (hex child)))))
          (is (= 2 (length r)))
          (is (eq t (aval (first r) "allowed")))
          (is (eq t (aval (second r) "allowed"))
              "the child of an in-package parent was judged without it")
          ;; Each member's fees are its own: the effective feerate covers one
          ;; wtxid, not the package's.
          (is (equal (list (bl.crypto:bytes-to-hex
                            (bl.crypto:reverse-bytes
                             (bl.ser:transaction-wtxid child))))
                     (coerce (cdr (assoc "effective-includes"
                                         (aval (second r) "fees")
                                         :test #'string=))
                             'list)))
          (is (plusp (aval (second r) "vsize"))))
        ;; Still a dry run.
        (is (= 0 (bl.mp:mempool-count mempool)))))))

(test testmempoolaccept-reports-the-packages-own-verdict
  "The context-free package rules judge the PACKAGE, not a member: Core states
them in the PackageValidationState as PCKG_POLICY and rpc/mempool.cpp:360-362
prints that state on EVERY row as `package-error', with no member reporting an
`allowed' at all (IsWellFormedPackage, policy/packages.cpp:84-114;
rpc_packages.py:149, :254-263, :312-317).

Ours had no package phase, so a package Core refuses to look at came back with
three ordinary per-transaction verdicts — and a reversed chain, whose child
Core never validates, came back as `missing-inputs'."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (bl.store:add-utxo utxo-set funding-txid 1 100000000
                       (p2sh-optrue-script-pubkey) 1 :coinbase nil)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (parent (pkg-tx funding-txid 0 99990000))
           (child (pkg-tx (bl.ser:transaction-hash parent) 0 99980000))
           ;; Same coin, different value: a second transaction that conflicts
           ;; with PARENT inside the package.
           (rival (pkg-tx funding-txid 0 99980000)))
      (flet ((hex (tx) (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx)))
             (errors (rows)
               (mapcar (lambda (row)
                         (cdr (assoc "package-error" row :test #'string=)))
                       rows))
             (allowed (rows)
               (remove nil (mapcar (lambda (row)
                                     (assoc "allowed" row :test #'string=))
                                   rows))))
        (let ((dup (%testmempoolaccept node (list (hex parent) (hex parent)))))
          (is (equal '("package-contains-duplicates" "package-contains-duplicates")
                     (errors dup)))
          (is (null (allowed dup))
              "a member of a package Core never validated carried a verdict"))
        (let ((unsorted (%testmempoolaccept node (list (hex child) (hex parent)))))
          (is (equal '("package-not-sorted" "package-not-sorted")
                     (errors unsorted)))
          (is (null (allowed unsorted))))
        (let ((conflicting (%testmempoolaccept node (list (hex parent) (hex rival)))))
          (is (equal '("conflict-in-package" "conflict-in-package")
                     (errors conflicting)))
          (is (null (allowed conflicting))))
        ;; A well-formed package has no package-error at all.
        (let ((ok (%testmempoolaccept node (list (hex parent) (hex child)))))
          (is (equal '(nil nil) (errors ok))))
        (is (= 0 (bl.mp:mempool-count mempool)))))))

(test testmempoolaccept-allows-no-replacement-inside-a-package
  "ATMPArgs::PackageTestAccept sets m_allow_replacement FALSE
(validation.cpp:505), so a package member that conflicts with a mempool
transaction is rejected outright — `bip125-replacement-disallowed',
validation.cpp:839 — however good a BIP125 replacement it would be on its own.
The same transaction asked about ALONE goes through ProcessTransaction, where
replacement is allowed, and is accepted: rpc_packages.py:318-326 asserts both
halves, and mempool_package_rbf.py:110 reads the package half.

We validated every member as a single transaction, so testmempoolaccept said a
package was acceptable on the strength of a replacement nobody had asked it to
make."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (bl.store:add-utxo utxo-set funding-txid 1 100000000
                       (p2sh-optrue-script-pubkey) 1 :coinbase nil)
    (let* ((node (%broadcast-test-node utxo-set mempool chain-state
                                       (bl.net:make-peer :state :ready)))
           (original (pkg-tx funding-txid 0 99990000 :sequence #xfffffffd))
           (replacement (pkg-tx funding-txid 0 99950000))
           (independent (pkg-tx funding-txid 1 99990000)))
      (flet ((hex (tx) (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx)))
             (aval (row key) (cdr (assoc key row :test #'string=))))
        (bl.rpc:dispatch-rpc-method node "sendrawtransaction"
                                    (wire-params (list (hex original))))
        (is (= 1 (bl.mp:mempool-count mempool)))
        ;; Alone: a perfectly good replacement.
        (let ((solo (%testmempoolaccept node (list (hex replacement)))))
          (is (eq t (aval (first solo) "allowed"))))
        ;; In a package: refused, with Core's reason and its details, and the
        ;; member Core never finished stays blank.
        (let ((pkg (%testmempoolaccept node (list (hex independent)
                                                  (hex replacement)))))
          (is (equal '("txid" "wtxid") (mapcar #'car (first pkg))))
          (is (eq 'yason:false (aval (second pkg) "allowed")))
          (is (string= "bip125-replacement-disallowed"
                       (aval (second pkg) "reject-reason")))
          (is (string= "bip125-replacement-disallowed"
                       (aval (second pkg) "reject-details"))))
        ;; The original is untouched: this is a dry run either way.
        (is (= 1 (bl.mp:mempool-count mempool)))))))

(test package-client-maxfeerate-aborts-package
  "A member over submitpackage's maxfeerate fails in PreChecks
(validation.cpp:1365-1368) like any TX_MEMPOOL_POLICY verdict: the package
phase is skipped, but AcceptPackage goes on judging the later members on
their own (:1694-1708), so the child reports its own missing inputs -- it was
a :not-validated placeholder here, and rpc_packages.py:447 reads
bad-txns-inputs-missingorspent -- and nothing enters the mempool."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((parent (pkg-tx funding-txid 0 1000000))
           (child (pkg-tx (bl.ser:transaction-hash parent) 0 900000)))
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state
           :client-maxfeerate 10000000)
        ;; The first failing member's verdict, as for any per-tx failure;
        ;; package_msg is still "transaction failed".
        (is (eq :max-feerate-exceeded msg))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results parent))))
        (is (eq :max-feerate-exceeded (bl.val:package-tx-result-error
                                       (%result-for results parent))))
        (is (eq :invalid (bl.val:package-tx-result-status
                          (%result-for results child))))
        (is (eq :missing-input (bl.val:tx-reject-keyword
                                (bl.val:package-tx-result-error
                                 (%result-for results child))))))
      (is (= 0 (bl.mp:mempool-count mempool)))
      ;; NIL cap (what maxfeerate=0 becomes) leaves the package alone.
      (multiple-value-bind (msg2) (bl.val:validate-package-for-mempool
                                   (list parent child) utxo-set mempool chain-state)
        (is (eq :success msg2)))
      (is (= 2 (bl.mp:mempool-count mempool))))))

(test package-client-maxfeerate-applies-in-the-package-phase
  "maxfeerate is a PreChecks rule (validation.cpp:1365-1368), so it applies in
the package phase too, where a child that could only be judged beside its
parent meets it: rpc_packages.py:472-478 pairs a parent below the floor with
a child over the cap, and reads `max feerate exceeded' on the child while the
parent keeps its own fee verdict. Ours checked the cap in the individual pass
alone, so the package phase admitted both."
  (multiple-value-bind (utxo-set mempool chain-state funding-txid) (make-package-fixture)
    (let* ((parent (pkg-tx funding-txid 0 100000000))          ; zero fee
           (child (pkg-tx (bl.ser:transaction-hash parent) 0 99000000)))
      (multiple-value-bind (msg results)
          (bl.val:validate-package-for-mempool
           (list parent child) utxo-set mempool chain-state
           :client-maxfeerate 100000)
        (declare (ignore msg))
        (is (eq :max-feerate-exceeded (bl.val:package-tx-result-error
                                       (%result-for results child))))
        (is (not (eq :max-feerate-exceeded
                     (bl.val:package-tx-result-error
                      (%result-for results parent))))))
      (is (= 0 (bl.mp:mempool-count mempool))))))

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
        (let ((tx (pkg-tx funding 0 99990000)))
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
                      (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil)
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
                         (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil)
                         :test #'string=))))
    (is (eq :ok (bl.mp:mempool-add
                 mempool txid (bl.mp:make-entry-from-tx tx 1000 0))))
    (is-true (bl.mp:mempool-add-unbroadcast mempool txid))
    (is (= 1 (cdr (assoc "unbroadcastcount"
                         (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil)
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
matter), one of them unbroadcast. Returns the list of txids.

The entries are stamped with the current time, as a real dump's are: the
reload runs the full acceptance path, and that path now runs Core's
LimitMempoolSize, so an entry dated at the epoch would be expired the moment
it came back."
  (multiple-value-bind (node funding-txid) (%mempool-node 3)
    (let ((mempool (bl:node-mempool node))
          (txids '()))
      (dotimes (i 3)
        (let* ((tx (pkg-tx funding-txid i (- 100000000 10000)))
               (txid (bl.ser:transaction-hash tx)))
          (bl.mp:mempool-add
           mempool txid (bl.mp:make-entry-from-tx
                         tx 10000 200 :entry-time (bl.ser:get-unix-time)))
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

(test a-mempool-dat-without-the-unbroadcast-set-keeps-what-it-loaded
  "Core 0.20.1 writes a version-1 mempool.dat that ENDS after the fee-delta map:
the unbroadcast set arrived in 0.21. Core's LoadMempool accepts each
transaction as it reads it, so when the read of the missing set throws, the
transactions are already in the pool and stay there; the load reports failure
and the node carries on (node/mempool_persist.cpp:105-145).
mempool_compatibility.py:64 moves such a file under a new node and asserts the
old node's transaction is in its mempool. Ours parsed the whole file before
accepting anything, so the missing tail threw every transaction away."
  (let ((path (merge-pathnames (format nil "bl-mempool-v0201-~D.dat" (get-universal-time))
                               (uiop:temporary-directory))))
    (unwind-protect
         (let ((txids (let ((bl.mp:*persist-mempool-v1* t))
                        (%write-mempool-file path))))
           ;; Cut the unbroadcast set off: a compact-size 1 and one txid. What
           ;; is left is byte for byte the layout 0.20.1 writes.
           (let ((bytes (with-open-file (in path :element-type '(unsigned-byte 8))
                          (let ((v (make-array (file-length in)
                                               :element-type '(unsigned-byte 8))))
                            (read-sequence v in)
                            v))))
             (is (= 1 (aref bytes (- (length bytes) 33)))
                 "the fixture's last 33 bytes are not the one-txid unbroadcast set")
             (with-open-file (out path :direction :output :if-exists :supersede
                                       :element-type '(unsigned-byte 8))
               (write-sequence bytes out :end (- (length bytes) 33))))
           (let* ((node (%mempool-node 3))
                  (mempool (bl:node-mempool node))
                  (result :unset)
                  (logged (with-output-to-string (out)
                            (let ((bl:*log-stream* out))
                              (setf result (bl:load-mempool-from-disk node path))))))
             (is (= 3 (bl.mp:mempool-count mempool))
                 "the transactions read before the missing tail are kept")
             (dolist (txid txids)
               (is-true (bl.mp:mempool-has mempool txid)))
             (is (= 0 (bl.mp:mempool-unbroadcast-count mempool)))
             (is (null result) "the load still reports that the file was short")
             (is (search "Failed to deserialize mempool data on file" logged))))
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
             (let ((tx (pkg-tx funding-txid 0 (- 100000000 10000))))
               (setf txid (bl.ser:transaction-hash tx))
               ;; A current entry time, as a real dump carries: the startup
               ;; load keeps the saved time (use_current_time defaults off)
               ;; and now skips anything already past -mempoolexpiry.
               (is (eq :ok (bl.mp:mempool-add
                            mempool txid
                            (bl.mp:make-entry-from-tx
                             tx 10000 200
                             :entry-time (bl.ser:get-unix-time)))))
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
           ;; getblock reads bodies through the index (Core LookupBlockIndex
           ;; before GetRawBlockChecked): a body the index does not know is
           ;; -5 Block not found, so the header goes in as a real block's would.
           (bl.store:add-block-index-entry
            (bl:node-chain-state node)
            (bl.store:make-block-index-entry :hash hash :height 1 :chain-work 2
                                             :status :valid
                                             :header (bl.ser:bitcoin-block-header blk)))
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
    (is (not (%authorized-user nil)))
    (is (not (%authorized-user ""))))
  ;; -rpcuser/-rpcpassword startup
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "testpass")))
    (is (not (%authorized-user nil))))
  ;; no credential installed at all: nothing authorizes, not even an empty one
  (let ((bl.rpc::*rpc-credentials* '()))
    (is (not (%authorized-user nil)))
    (is (not (%authorized-user (%basic-auth-header ":"))))))

(test rpc-auth-header-parsing
  "check-auth parses the HTTP Basic header the way Core's RPCAuthorized does
(httprpc.cpp:84-101): \"Basic \" prefix, base64, split on the FIRST colon, so a
password may contain colons. Anything malformed is rejected, never accepted."
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "testpass")))
    ;; base64 of "testuser:testpass"
    (is (%authorized-user "Basic dGVzdHVzZXI6dGVzdHBhc3M="))
    (is (%authorized-user (%basic-auth-header "testuser:testpass")))
    ;; scheme name is case-insensitive, surrounding space is trimmed (Core
    ;; TrimStringView)
    (is (%authorized-user "basic dGVzdHVzZXI6dGVzdHBhc3M="))
    (is (%authorized-user "Basic  dGVzdHVzZXI6dGVzdHBhc3M= "))
    ;; malformed shapes
    (is (not (%authorized-user "dGVzdHVzZXI6dGVzdHBhc3M=")))
    (is (not (%authorized-user "Bearer dGVzdHVzZXI6dGVzdHBhc3M=")))
    (is (not (%authorized-user "Basic ")))
    (is (not (%authorized-user "Basic not-base64!!")))
    ;; no colon in the decoded credential
    (is (not (%authorized-user (%basic-auth-header "testusertestpass"))))
    ;; near misses
    (is (not (%authorized-user (%basic-auth-header "testuser:testpas"))))
    (is (not (%authorized-user (%basic-auth-header "testuser:testpassX"))))
    (is (not (%authorized-user (%basic-auth-header "TESTUSER:testpass")))))
  ;; the split is on the first colon, so the password keeps the rest
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "u" "a:b:c")))
    (is (%authorized-user (%basic-auth-header "u:a:b:c")))))

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



(test rpc-server-with-the-cookie-file-disabled
  "With *rpc-cookie-file* :disabled (-norpccookiefile) the server starts on the
-rpcauth users alone, writes no .cookie, and logs Core's line (httprpc.cpp:
261-262, rpc/request.cpp:115). Control: the default writes the cookie."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node))
          (port 19989)
          (rpcauth (mapcar #'third *core-whitelist-users*)))
      (setf (bl:node-data-directory node) dir)
      (let ((lines (capture-log-lines
                    (lambda ()
                      (let ((bl.rpc:*rpc-cookie-file* :disabled))
                        (is-true (bl.rpc:start-rpc-server node :port port :rpc-auth rpcauth)
                                 "the server starts without a cookie file"))))))
        (is (null (probe-file (merge-pathnames ".cookie" dir)))
            "no cookie file is written when it is disabled")
        (is-true (find "RPC authentication cookie file generation is disabled."
                       lines :test #'search)
                 "Core's log line for the disabled cookie"))
      (bl.rpc:stop-rpc-server)
      ;; Control: the default writes the cookie.
      (let ((bl.rpc:*rpc-cookie-file* nil))
        (is-true (bl.rpc:start-rpc-server node :port port :rpc-auth rpcauth))
        (is-true (probe-file (merge-pathnames ".cookie" dir))
                 "control: with the default, the cookie is written"))
      (bl.rpc:stop-rpc-server))))

(test an-empty-rpcpassword-still-gets-a-cookie
  "Core's InitRPCAuthentication asks one question -- is -rpcpassword non-empty
(httprpc.cpp:245)? -rpcuser alone does not answer it, so a node started with
`-rpcuser=x -rpcpassword=' generates the .cookie and logs `Using random cookie
authentication.'. Asking instead whether both were SUPPLIED left
feature_config_args.py:255's node with no cookie and an empty password, and the
framework reported `Unable to connect to bitcoind after 60s'."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node))
          (port 19991))
      (setf (bl:node-data-directory node) dir)
      (let ((bl.rpc:*rpc-cookie-file* nil))
        (let ((lines (capture-log-lines
                      (lambda ()
                        (is-true (bl.rpc:start-rpc-server
                                  node :port port
                                       :user "secret-rpcuser" :password ""))))))
          (is-true (probe-file (merge-pathnames ".cookie" dir))
                   "an empty -rpcpassword means cookie authentication")
          (is-true (find "Using random cookie authentication." lines :test #'search)
                   "Core's line for the cookie branch"))
        (bl.rpc:stop-rpc-server)
        (ignore-errors (delete-file (merge-pathnames ".cookie" dir)))
        ;; Control: a real password takes Core's other branch and writes none.
        (let ((lines (capture-log-lines
                      (lambda ()
                        (is-true (bl.rpc:start-rpc-server
                                  node :port port
                                       :user "u" :password "p"))))))
          (is (null (probe-file (merge-pathnames ".cookie" dir)))
              "control: a non-empty -rpcpassword writes no cookie")
          (is-true (find "Using rpcuser/rpcpassword authentication." lines :test #'search)
                   "Core's line for the password branch"))
        (bl.rpc:stop-rpc-server)))))

(test rpcthreads-bounds-running-requests-not-open-connections
  "Core's -rpcthreads sizes the HTTP WORKER POOL (httpserver.cpp:411-421): one
event loop accepts, and an idle keep-alive connection costs no worker. Handing
the number to hunchentoot's taskmaster as :max-thread-count bounded
CONNECTIONS instead, and that taskmaster -- with no :max-accept-count -- stops
accepting once they are all held.

Core's own framework writes `rpcthreads=2' into every node's bitcoin.conf
(test_framework/util.py:562), so the framework's persistent JSON-RPC
connection plus ONE response whose body a test had not read yet wedged the
whole HTTP port until the idle timeout. interface_rest.py hung on its third
request (`GET /rest/tx/abc.json') and timed out the test.

So: the acceptor must carry no connection cap, and the bound must be a
semaphore taken around request execution."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node))
          (port 19993))
      (setf (bl:node-data-directory node) dir)
      (%with-rpc-threads (2)
        (unwind-protect
             (progn
               (is-true (bl.rpc:start-rpc-server node :port port))
               (let* ((taskmaster (hunchentoot::acceptor-taskmaster
                                   bl.rpc:*rpc-server*))
                      (threads (hunchentoot:taskmaster-max-thread-count taskmaster))
                      (accepts (hunchentoot:taskmaster-max-accept-count taskmaster)))
                 (is (or (null threads) (> threads bl.rpc:*rpc-threads*))
                     "the accept loop must not be capped at -rpcthreads (~S)" threads)
                 (is (or (null threads) accepts)
                     "a capped taskmaster must REFUSE, not block: ~S/~S"
                     threads accepts)))
          (bl.rpc:stop-rpc-server)))
      ;; The bound itself is real: two permits, and the third caller waits.
      (%with-rpc-threads (2)
        (let ((semaphore (%rpc-worker-semaphore)))
          (is-true semaphore "a semaphore exists when -rpcthreads is set")
          (is-true (bt:wait-on-semaphore semaphore :timeout 1))
          (is-true (bt:wait-on-semaphore semaphore :timeout 1))
          (is (null (bt:wait-on-semaphore semaphore :timeout 0.2))
              "the third request waits, as Core's third worker request does")
          (bt:signal-semaphore semaphore)
          (bt:signal-semaphore semaphore)))
      ;; Unset means unbounded, as before.
      (%with-rpc-threads (nil)
        (is (null (%rpc-worker-semaphore))
            "no -rpcthreads, no bound")))))

(test rpcworkqueue-refuses-a-request-once-that-many-are-waiting
  "Core -rpcworkqueue (g_max_queue_depth, httpserver.cpp:419): with every
worker busy and that many requests already queued, http_request_cb answers
the next one 503 `Work queue depth exceeded' instead of queueing it
(:255-258). interface_rpc.py:229-240 restarts with -rpcworkqueue=1
-rpcthreads=1 and loops waitfornewblock calls from three threads until
bitcoin-cli prints `error: Server response: Work queue depth exceeded'.

The option was accepted and ignored: every request waited on the worker
semaphore however many were waiting already, so that loop never ended. Here
the one worker permit is held, two requests arrive, and exactly one of them --
whichever is second -- must come back 503 at once; the other waits for the
permit and is served when it is released."
  (bl.rpc:stop-rpc-server)
  (let ((saved-threads bl.rpc:*rpc-threads*)
        (saved-queue bl.rpc:*rpc-work-queue*)
        (port 19984)
        (lock (bt:make-lock))
        (results '())
        (callers '())
        (semaphore nil))
    (with-temp-directory (dir)
      (let ((node (make-test-node)))
        (setf (bl:node-data-directory node) dir)
        (unwind-protect
             (progn
               ;; Globals, not bindings: the acceptor's threads read them.
               (setf bl.rpc:*rpc-threads* 1
                     bl.rpc:*rpc-work-queue* 1
                     semaphore (%rpc-worker-semaphore))
               (is-true (bl.rpc:start-rpc-server node :port port))
               ;; The one worker is busy.
               (is-true (bt:wait-on-semaphore semaphore :timeout 5))
               (dotimes (i 2)
                 (push (bt:make-thread
                        (lambda ()
                          (let ((r (handler-case
                                       (%http-post-rpc
                                        port "{\"method\":\"getblockcount\",\"id\":1}")
                                     (error (e) (format nil "error: ~A" e)))))
                            (bt:with-lock-held (lock) (push r results))))
                        :name "rpcworkqueue-test-caller")
                       callers))
               (let ((first-back (loop repeat 200
                                       for r = (bt:with-lock-held (lock) (first results))
                                       when r return r
                                       do (sleep 0.05))))
                 (is (eql 503 (and first-back (%http-status first-back)))
                     "with the worker busy and one request queued, another was not refused: ~S"
                     first-back)
                 (is-true (and first-back (search "Work queue depth exceeded" first-back))
                          "the 503 does not carry Core's body: ~S" first-back)))
          (when semaphore (bt:signal-semaphore semaphore))
          (mapc #'bt:join-thread callers)
          (bl.rpc:stop-rpc-server)
          (setf bl.rpc:*rpc-threads* saved-threads
                bl.rpc:*rpc-work-queue* saved-queue))
        ;; The queued one was served once the worker came free.
        (is (= 2 (length results)))
        (is (= 1 (count 503 results :key #'%http-status))
            "exactly one request is refused: ~S" results)))))

(test json-rpc-claims-only-the-paths-core-registers
  "Core registers the JSON-RPC handler at the EXACT path `/' and at the prefix
`/wallet/' (httprpc.cpp:338-341). A path no handler claims gets 404
(httpserver.cpp:287); 405 is reserved for an unknown HTTP METHOD (:225-230).

Ours was a bare prefix dispatcher on `/', which matches every path there is,
so `GET /xxxx' reached the JSON-RPC handler and came back 405 --
interface_http.py:100 asserts 404."
  (flet ((claimed (path)
           (let ((hunchentoot:*acceptor* (make-instance 'hunchentoot:acceptor)))
             (and (funcall (bl.rpc::make-json-rpc-dispatcher)
                           (make-instance 'hunchentoot:request
                                          :uri path
                                          :acceptor hunchentoot:*acceptor*
                                          :headers-in nil
                                          :method :get
                                          :server-protocol :http/1.1))
                  t))))
    (is-true (claimed "/") "Core's exact `/'")
    (is-true (claimed "/wallet/w1") "Core's `/wallet/' prefix")
    (is (null (claimed "/xxxxxxxxxx"))
        "an unclaimed path must fall through to 404")
    (is (null (claimed "/rest/tx/abc.json"))
        "the REST surface is not the JSON-RPC one")
    (is (null (claimed "/walletfoo"))
        "`/wallet' without the separator is not the wallet endpoint")))

(test oversized-request-headers-are-refused-as-core-refuses-them
  "Core hands libevent MAX_HEADERS_SIZE = 8192 (httpserver.cpp:51, :409), so a
request whose start line and headers exceed it is answered 400 before any
handler sees it. interface_http.py sends a 1,000-character URI (404, no
handler claims it) and then a 10,000-character one (400). With no cap the
second was a 404 too, and nothing bounded how much one unauthenticated
request could make this process buffer."
  (flet ((size (uri &optional (headers '((:authorization . "Basic abc"))))
           (let ((hunchentoot:*acceptor* (make-instance 'hunchentoot:acceptor)))
             (bl.rpc::%request-headers-size
              (make-instance 'hunchentoot:request
                             :uri uri
                             :acceptor hunchentoot:*acceptor*
                             :headers-in headers
                             :method :get
                             :server-protocol :http/1.1)))))
    (let ((cap bl.rpc::+max-http-headers-size+))
      (is (= 8192 cap) "Core's MAX_HEADERS_SIZE")
      (is (<= (size (format nil "/~A" (make-string 1000 :initial-element #\x))) cap)
          "a 1,000-character URI is under Core's cap")
      (is (> (size (format nil "/~A" (make-string 10000 :initial-element #\x))) cap)
          "a 10,000-character URI is over it")
      ;; The headers count too, not only the URI.
      (is (> (size "/" (list (cons :authorization
                                   (make-string 9000 :initial-element #\a))))
             cap)
          "one huge header is over it as well"))))

(test the-jsonrpc-version-field-is-validated-as-core-validates-it
  "Core accepts an absent/null `jsonrpc', the string \"1.0\" (V1_LEGACY) and
\"2.0\" (V2), and refuses everything else with -32600: `jsonrpc field must be
a string' for a non-string, `JSON-RPC version not supported' for another
version (rpc/request.cpp:215-230). We called every unrecognised value :V1 and
answered it, so a client asking for a protocol this server does not speak got
a reply shaped like a different one. interface_rpc.py:177, :204 and :207 send
\"2.1\", 2 and \"3.0\" and compare the whole error object."
  (flet ((version-of (marker &optional (present t))
           (let ((req (make-hash-table :test 'equal)))
             (when present (setf (gethash "jsonrpc" req) marker))
             (handler-case (bl.rpc::request-json-version req)
               (bl.rpc:rpc-error (e)
                 (list (bl.rpc:rpc-error-code e) (bl.rpc:rpc-error-message e)))))))
    (is (eq :v1 (version-of nil nil)) "absent is V1_LEGACY")
    (is (eq :v1 (version-of nil)) "null is V1_LEGACY")
    (is (eq :v1 (version-of "1.0")) "\"1.0\" is V1_LEGACY")
    (is (eq :v2 (version-of "2.0")) "\"2.0\" is V2")
    (is (equal (list bl.rpc:+rpc-invalid-request+ "jsonrpc field must be a string")
               (version-of 2))
        "a non-string jsonrpc")
    (is (equal (list bl.rpc:+rpc-invalid-request+ "JSON-RPC version not supported")
               (version-of "2.1"))
        "an unrecognised version")
    (is (equal (list bl.rpc:+rpc-invalid-request+ "JSON-RPC version not supported")
               (version-of "3.0"))
        "another unrecognised version")
    ;; \"1.1\" is NOT a jsonrpc marker Core knows; the framework sends it in a
    ;; \"version\" member, which this function never reads.
    (is (equal (list bl.rpc:+rpc-invalid-request+ "JSON-RPC version not supported")
               (version-of "1.1"))
        "\"1.1\" as a jsonrpc marker is refused, as Core refuses it")))

(test the-logging-rpc-answers-alphabetically-and-says-so-in-its-help
  "Core's logging RPC walks LOG_CATEGORIES_BY_STR, a std::map keyed by the
category NAME (logging.cpp:172, :278-286), so the object comes back sorted --
rpc_misc.py:87-88 asserts `list(node.logging()) == sorted(node.logging())'.
Ours answered in declaration order, so a client rendering the object as given
showed an arbitrary one. `help logging' carries the same list as a sentence
(:90-93)."
  (let* ((answer (bl.rpc:dispatch-rpc-method nil "logging" '()))
         (names (mapcar #'car answer)))
    (is (equal names (sort (copy-list names) #'string<))
        "the categories must come back alphabetical; got ~S" names)
    (is (= (length names) (length bl.log:+log-categories+))
        "every category is reported")
    (let ((help (bl.rpc:dispatch-rpc-method nil "help" (list "logging"))))
      (is (search (format nil "valid logging categories are: ~{~A~^, ~}" names)
                  help)
          "help logging must carry the same list, in the same order"))))

(test echoipc-echoes-its-argument
  "Core's echoipc round-trips the string through a spawned bitcoin-node in a
multiprocess build and through interfaces::MakeEcho() otherwise
(rpc/node.cpp:313-345) -- the identity either way for a single-process node.
It was not registered at all, so rpc_misc.py:96 could not call it and
rpc_help.py:110 failed this node for a method client.cpp lists and the server
does not serve."
  (is (equal "hello" (bl.rpc:dispatch-rpc-method nil "echoipc" (list "hello"))))
  ;; Hidden, like Core's (registered under the \"hidden\" category), so a bare
  ;; `help' does not list it while `help echoipc' still answers.
  (is-true (bl.rpc::rpc-method-hidden-p "echoipc"))
  (is (null (search "echoipc"
                    (bl.rpc:dispatch-rpc-method nil "help" '()))))
  ;; And it appears in the conversion dump, which is what rpc_help.py reads.
  (is-true (find-if (lambda (row) (string= (aref row 0) "echoipc"))
                    (bl.rpc::%dump-all-command-conversions))))

(test getmemoryinfo-reports-chunks-of-the-heap-it-has
  "Core's `locked' object describes its mlock()ed LockedPool
(support/lockedpool.h:57-64) and rpc_misc.py:61-62 asserts chunks_used and
chunks_free are both above zero. This node has no locked pool -- the same
secrets live in the ordinary heap -- so it reports that heap counted in the
units the field names mean: allocation granules, which is what a chunk IS for
Core's arena. Reporting a constant 0 failed the assertion AND told a caller
watching for allocator pressure nothing."
  ;; Core's MODE argument (rpc/node.cpp:733-760): "stats" is the default,
  ;; "mallocinfo" takes the #else arm on a runtime without glibc's malloc_info,
  ;; and anything else names itself. We ignored the argument and answered the
  ;; stats object to every value, including rpc_misc.py:73's typo.
  (is (equal (%getmemoryinfo nil)
             (%getmemoryinfo (list "stats")))
      "stats is the default")
  (is (equal (cons -8 "mallocinfo mode not available")
             (rpc-error-of (lambda () (%getmemoryinfo (list "mallocinfo"))))))
  (is (equal (cons -8 "unknown mode foobar")
             (rpc-error-of (lambda () (%getmemoryinfo (list "foobar"))))))
  (let* ((info (%getmemoryinfo nil))
         (locked (cdr (assoc "locked" info :test #'string=)))
         (used (cdr (assoc "used" locked :test #'string=)))
         (free (cdr (assoc "free" locked :test #'string=)))
         (total (cdr (assoc "total" locked :test #'string=)))
         (chunks-used (cdr (assoc "chunks_used" locked :test #'string=)))
         (chunks-free (cdr (assoc "chunks_free" locked :test #'string=))))
    (is (= total (+ used free)) "used + free = total, as rpc_misc.py:63 asserts")
    (is (plusp chunks-used) "chunks_used must be above zero")
    (is (plusp chunks-free) "chunks_free must be above zero")
    ;; They are the heap in granules, not decoration: derived from the same
    ;; byte counts the object already reports.
    (let ((granule bl.rpc::+heap-chunk-bytes+))
      (is (= chunks-used (ceiling used granule)))
      (is (= chunks-free (floor free granule))))
    ;; `locked' stays 0: nothing here is mlock()ed and saying otherwise would
    ;; be a security claim this node cannot make.
    (is (zerop (cdr (assoc "locked" locked :test #'string=))))))

(test echojson-is-string-typed-where-cores-helpman-declares-it
  "Core's two argument tables disagree about exactly one method: client.cpp
lists echojson's arg0..arg9 as convertible, while the RPCHelpMan declares them
STR with skip_type_check (rpc/node.cpp:286-295), so dumpArgMap -- which is what
`help dump_all_command_conversions' answers -- reports them string-typed.
rpc_help.py:72 drops echojson from the CLIENT side and compares the rest, so a
node that answers from the client side alone fails on those ten rows and
nothing else."
  (let ((rows (loop for row across (bl.rpc::%dump-all-command-conversions)
                    when (string= (aref row 0) "echojson") collect row)))
    (is (= 10 (length rows)) "all ten arguments are reported")
    (dolist (row rows)
      (is (eq t (aref row 3))
          "~A arg ~D must be reported string-typed" (aref row 0) (aref row 1)))))

(test a-json-rpc-reply-ends-in-a-newline-and-carries-cores-id
  "Two shape details of a JSON-RPC reply that clients compare whole.

Core appends a NEWLINE to every reply (httprpc.cpp:55 and :229);
interface_http.py:179 compares the body byte for byte, and a client reading
line-delimited replies off a kept-alive connection needs the terminator.

And the `id' key is present only once the request object has been looked at.
Core's JSONRPCRequest::id starts as a PRESENT null (request.h:55) and parse()
replaces it with std::nullopt when the object has no id member -- BEFORE the
version and method checks (request.cpp:206-211, `Parse id now so errors from
here on will have the id'). So a body that never parsed as JSON answers
`\"id\": null', while `{\"jsonrpc\": 2, \"method\": ...}' answers with no id key
at all: interface_rpc.py:189 and :204 compare those two objects whole."
  (let ((reply (bl.rpc::%write-json-reply
                (bl.rpc::make-rpc-error-response -32700 "Parse error" nil :v1))))
    (is (char= #\Newline (char reply (1- (length reply))))
        "the reply must end in a newline; got ~S" reply)
    (is (search "\"error\"" reply)))
  ;; The id fields as the parser leaves them.
  (flet ((parse (body)
           (let ((bl.rpc::*request-id* nil)
                 (bl.rpc::*request-id-present* t))
             (ignore-errors (bl.rpc:parse-json-rpc-request body))
             (list bl.rpc::*request-id* bl.rpc::*request-id-present*))))
    ;; Never parsed as JSON: Core's initial present-null survives.
    (is (equal '(nil t) (parse "not json"))
        "a parse error keeps the initial present null id")
    ;; Parsed, no id member: the key is dropped before the version is judged.
    (is (equal '(nil nil) (parse "{\"jsonrpc\":2,\"method\":\"getblockcount\"}"))
        "an object with no id member drops the key")
    ;; Parsed with an id: it is carried into whatever error follows.
    (is (equal '(7 t) (parse "{\"jsonrpc\":\"2.1\",\"id\":7,\"method\":\"getblockcount\"}"))
        "the id is carried into the version error")))

(test init-message-lines-are-cores
  "Core's non-GUI build logs every uiInterface.InitMessage as `init message:
<text>` (noui.cpp:56) and the functional framework waits on those lines
(feature_init.py: `Verifying blocks`, `Starting network threads`;
rpc_users.py:127: `Done loading`, which is also how it knows a node started
with -norpccookiefile is up). Ours logged none of them."
  (let ((lines (capture-log-lines (lambda () (bl:init-message "Done loading")))))
    (is-true (find "init message: Done loading" lines :test #'search)
             "the line reads exactly as Core's"))
  (is-true (fboundp 'bl:init-message)))

(test a-header-only-block-is-not-available-not-not-found
  "Core answers a body request for a header the index holds but never got the
body of with -1 `Block not available (not fully downloaded)` (GetBlockChecked
over CheckBlockDataAvailability, rpc/blockchain.cpp:671-700), and keeps -5
`Block not found` for a hash the index does not know. Ours said -5 for both,
so rpc_getblockfrompeer.py:61 and rpc_getblockstats.py:188, which ask about a
headers-only tip, read the wrong code and text. gettxoutproof reads a body the
same way (txoutproof.cpp:103)."
  (with-network (:regtest)
   (let* ((node (regtest-node-fixture "header-only"))
         (cs (bl:node-chain-state node))
         (header (bl.ser:make-block-header
                  :version 1
                  :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)
                  :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8)
                  :timestamp 1 :bits #x207fffff :nonce 0))
         (hash (bl.ser:block-header-hash header))
         (hex (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash)))
         (unknown (make-string 64 :initial-element #\1))
         (not-available (cons -1 "Block not available (not fully downloaded)")))
    (bl.store:add-block-index-entry
     cs (bl.store:make-block-index-entry :hash hash :height 1 :header header
                                         :chain-work 2 :status :header-valid))
    (is (equal not-available (%rpc-wire-error node "getblock" (list hex))))
    (is (equal not-available (%rpc-wire-error node "getblockstats" (list hex))))
    (is (equal not-available
               (%rpc-wire-error node "gettxoutproof" (list (list unknown) hex))))
    ;; Control: an unknown hash is still -5 Block not found.
    (is (equal (cons -5 "Block not found") (%rpc-wire-error node "getblock" (list unknown))))
    (is (equal (cons -5 "Block not found") (%rpc-wire-error node "getblockstats" (list unknown)))))))

(test a-block-the-index-placed-but-cannot-read-is-not-found-on-disk
  "Core's GetBlockChecked asks two questions in order: CheckBlockDataAvailability
reads BLOCK_HAVE_DATA off the index, and only when that PASSES does ReadBlock
run -- a read that fails there is -1 `Block not found on disk'
(rpc/blockchain.cpp:686-698), a different answer from the two availability
ones. Core reaches it when a prune races the read; rpc_getblockstats.py:192
reaches it by renaming blk00000.dat away, and an operator reaches it with a
damaged or half-restored blocks directory. Ours had no such answer: every
unreadable body was `Block not available (not fully downloaded)', which says
the node never had it.

Our index entry records the flat-file POSITION rather than a HAVE_DATA bit, so
the read runs first and its failure is classified by whether a position was
recorded. The two entries below differ in exactly that."
  (with-network (:regtest)
    (let* ((node (regtest-node-fixture "no-body-on-disk"))
           (cs (bl:node-chain-state node))
           (mk (lambda (fill height)
                 (let* ((header (bl.ser:make-block-header
                                 :version 1
                                 :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                            :initial-element fill)
                                 :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                             :initial-element fill)
                                 :timestamp 1 :bits #x207fffff :nonce 0))
                        (hash (bl.ser:block-header-hash header)))
                   (values header hash
                           (bl.crypto:bytes-to-hex (bl.crypto:reverse-bytes hash))
                           height)))))
      (multiple-value-bind (placed-header placed-hash placed-hex) (funcall mk 21 1)
        (multiple-value-bind (bare-header bare-hash bare-hex) (funcall mk 22 1)
          (declare (ignore bare-hash))
          ;; Placed: the index says where the body is, and it is not there.
          (bl.store:add-block-index-entry
           cs (bl.store:make-block-index-entry
               :hash placed-hash :height 1 :header placed-header :chain-work 2
               :status :valid :file 0 :data-pos 8))
          (is (equal (cons -1 "Block not found on disk")
                     (%rpc-wire-error node "getblock" (list placed-hex))))
          (is (equal (cons -1 "Block not found on disk")
                     (%rpc-wire-error node "getblockstats" (list placed-hex))))
          ;; Control: an entry with no recorded position is still the
          ;; headers-only answer, and an unknown hash still -5.
          (bl.store:add-block-index-entry
           cs (bl.store:make-block-index-entry
               :hash (bl.ser:block-header-hash bare-header) :height 1
               :header bare-header :chain-work 2 :status :header-valid))
          (is (equal (cons -1 "Block not available (not fully downloaded)")
                     (%rpc-wire-error node "getblock" (list bare-hex))))
          (is (equal (cons -5 "Block not found")
                     (%rpc-wire-error node "getblock"
                                      (list (make-string 64 :initial-element #\3))))))))))

(test verificationprogress-is-core-s-estimate-not-a-sync-flag
  "Core's verificationprogress is GuessVerificationProgress of the active tip
(rpc/blockchain.cpp:1421 -> validation.cpp:5522-5556): the chain's transaction
count at that block over the same count extrapolated to now at the chain's
measured transaction rate, capped at 1.0. getchainstates reports the same
figure per chainstate (:3474).

Ours was `(if syncing 0.0 1.0)' -- read off the flag that says whether a sync
THREAD is running. That answers 0.0 for a fully synced node whose background
pass happens to be awake, and 1.0 for a node one block past genesis between
passes; it is the number every wallet and operator uses to decide whether this
node can be trusted yet."
  (with-network (:regtest)
    (let* ((node (regtest-node-fixture "verifprog"))
           (cs (bl:node-chain-state node))
           (addr (bl.crypto:encode-p2pkh-address
                  (make-array 20 :element-type '(unsigned-byte 8) :initial-element 4)
                  :regtest)))
      (bl.rpc:dispatch-rpc-method node "generatetoaddress" (list 5 addr))
      ;; The flag the old answer was read off, set the wrong way round: a node
      ;; sitting on its own tip is fully verified whatever a thread is doing.
      (setf (bl:node-syncing node) t)
      (let ((p (cdr (assoc "verificationprogress"
                           (bl.rpc::rpc-getblockchaininfo node nil)
                           :test #'string=))))
        (is (typep p 'double-float))
        (is (= 1.0d0 p)
            "a node at its own tip reported ~S while a sync pass was running" p))
      ;; And a block BELOW the best header is a fraction, not a flag. Regtest's
      ;; chainTxData has tx_count 0 and a deliberately non-zero rate
      ;; (kernel/chainparams.cpp:669), so the estimate is
      ;; count / (count + elapsed * rate) with elapsed taken from the height
      ;; gap -- strictly between 0 and 1 for any block behind the tip.
      (flet ((progress (entry)
               (bl.rpc::%guess-verification-progress
                cs entry (bl:node-block-store node) :regtest)))
        (let ((p-low (progress (bl.store:get-block-at-height cs 1))))
          (is (< 0d0 p-low) "a block below the tip reported no progress at all")
          (is (< p-low 1d0) "a block below the tip reported full verification"))
        (is (= 1.0d0 (progress (bl.store:get-block-index-entry
                                cs (bl.store:best-block-hash cs)))))
        ;; A block with no chain transaction count -- no entry at all here --
        ;; is 0.0, which is Core's answer rather than a made-up figure.
        (is (= 0.0d0 (progress nil)))))))

(test gettxoutproof-finds-the-block-through-an-unspent-output
  "Without a blockhash Core looks for an unspent output of any given txid in
the coins view and takes the block at that coin's height (txoutproof.cpp:
71-80, AccessByTxid), then the txindex, and only then answers -5
`Transaction not yet in block` (:88-91). Ours demanded a blockhash or a txindex
(-8 `Need a blockhash`), so rpc_txoutproof.py:37 never got Core's answer. The
coinbase of a freshly mined block has an unspent output, so its proof comes
back with no blockhash and no txindex; a txid with no coin gets Core's text."
  (with-network (:regtest)
    (let* ((node (regtest-node-fixture "txoutproof-utxo"))
           (hashes (generate-regtest-blocks node 1))
           (block (bl.rpc:dispatch-rpc-method node "getblock" (list (first hashes))))
           (coinbase (first (cdr (assoc "tx" block :test #'string=)))))
      (is (stringp coinbase) "control: the mined block reports its coinbase txid")
      (is (stringp (bl.rpc:dispatch-rpc-method node "gettxoutproof" (list (list coinbase))))
          "the proof is found through the coinbase's unspent output, no blockhash given")
      (is (equal (cons -5 "Transaction not yet in block")
                 (%rpc-wire-error node "gettxoutproof"
                                  (list (list (make-string 64 :initial-element #\2)))))))))

(test gettxoutproof-reads-its-txids-as-cores-set
  "gettxoutproof's argument is a std::set<Txid> in Core, and three of
rpc_txoutproof.py's rows read it as one: an empty array is -8 \"Parameter
'txids' cannot be empty\" (:86), a repeated txid is -8 \"Invalid parameter,
duplicated txid: <hex>\" (:88), and a set whose members do not all live in the
one block Core ends up reading is -5 \"Not all transactions found in specified
or retrieved block\" (:84). The last sentence says `or retrieved' because the
block may be one Core found for itself from a coin or the txindex rather than
one the caller named (txoutproof.cpp:46-56, :109-118).

Ours had a sentence of its own for each: \"txids must be a non-empty array\",
no duplicate check at all (the second copy simply re-flagged the same leaf),
and \"Not all txids found in the specified block\" raised on the FIRST missing
txid rather than on the count."
  (with-network (:regtest)
    (let* ((node (regtest-node-fixture "txoutproof-set"))
           (hashes (generate-regtest-blocks node 2))
           (cb (mapcar (lambda (h)
                         (first (cdr (assoc "tx"
                                            (bl.rpc:dispatch-rpc-method
                                             node "getblock" (list h))
                                            :test #'string=))))
                       hashes)))
      (is (= 2 (length cb)) "control: two blocks, two coinbase txids")
      (is (equal (cons -8 "Parameter 'txids' cannot be empty")
                 (%rpc-wire-error node "gettxoutproof" (list (vector)))))
      (is (equal (cons -8 (format nil "Invalid parameter, duplicated txid: ~A"
                                  (first cb)))
                 (%rpc-wire-error node "gettxoutproof"
                                  (list (list (first cb) (first cb))))))
      (is (equal (cons -5 "Not all transactions found in specified or retrieved block")
                 (%rpc-wire-error node "gettxoutproof" (list cb))))
      ;; Control: one of them alone still proves, so the count check is not
      ;; refusing everything.
      (is (stringp (bl.rpc:dispatch-rpc-method node "gettxoutproof"
                                               (list (list (first cb)))))))))

(test rpc-start-failure-is-an-init-error
  "Core's AppInitMain turns a false from AppInitServers into
InitError(\"Unable to start HTTP server. See debug log for details.\")
(init.cpp:1559-1561): a malformed -rpcauth, a bad -rpcallowip or a port in use
ends the process with that line on stderr and exit status 1, which is what the
functional framework's assert_start_raises_init_error waits sixty seconds for.
Ours logged the cause and carried on without an RPC server. Control: the same
start with a well-formed -rpcauth returns the acceptor."
  (bl.rpc:stop-rpc-server)
  (with-temp-directory (dir)
    (let ((node (make-test-node))
          (port 19991))
      (setf (bl:node-data-directory node) dir)
      (flet ((start (rpc-auth)
               (apply #'bl:start-rpc-early node port "127.0.0.1" t nil nil rpc-auth
                      (list nil nil nil nil :regtest nil t nil nil))))
        (handler-case
            (progn (start '("foo")) (fail "a malformed -rpcauth must refuse to start"))
          (bl.err:init-error (e)
            (is (string= "Unable to start HTTP server. See debug log for details."
                         (princ-to-string e)))))
        (let ((server (start (mapcar #'third *core-whitelist-users*))))
          (is-true server "control: a well-formed -rpcauth starts the server")
          (bl.rpc:stop-rpc-server))))))
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
      (is (%authorized-user (%basic-auth-header "alice:swordfish")))
      (is (%authorized-user (%basic-auth-header "__cookie__:deadbeef")))
      (is (not (%authorized-user (%basic-auth-header "alice:swordfisH"))))
      (is (not (%authorized-user (%basic-auth-header "Alice:swordfish"))))
      (is (not (%authorized-user (%basic-auth-header "alice:")))))
    ;; -rpcauth as the ONLY credential: Core allows -rpcauth without -rpcuser
    (let ((bl.rpc::*rpc-credentials* (list entry)))
      (is (%authorized-user (%basic-auth-header "alice:swordfish")))
      (is (not (%authorized-user nil)))
      (is (not (%authorized-user (%basic-auth-header "alice:wrong")))))
    ;; and no entries means no fallback path opens up
    (let ((bl.rpc::*rpc-credentials* '()))
      (is (not (%authorized-user (%basic-auth-header "alice:swordfish")))))))

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
           (handler-case (progn (bl.rpc:json-type-error value expected) nil)
             (bl.rpc:rpc-error (e)
               (bl.rpc:rpc-error-message e))))
         (code (value expected)
           (handler-case (progn (bl.rpc:json-type-error value expected) nil)
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

(test jsonrpc-keeps-a-duplicated-object-key-for-the-handler-to-judge
  "Core's UniValue does not deduplicate: an object is a vector of key/value
pairs, reading pushes every member, and getKeys() hands the handler all of
them in order (univalue). So a body with a repeated key is a WELL-FORMED
request, and the duplicate is the HANDLER's to judge -- ParseOutputs answers
-8 \"Invalid parameter, duplicated address: <addr>\" for a repeated address
and -8 \"Invalid parameter, duplicate key: data\" for a second data output
(rawtransaction_util.cpp:107-127). rpc_rawtransaction.py:300-302 sends both
through multidict and reads those two messages.

Our parser refused the whole body with -32700 Parse error, which says the
bytes were not JSON -- they were -- and hid the answer the caller asked for."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (addr "bcrt1qhku5rq7jz8ulufe2y6fkcpnlvpsta7rq4442dy"))
    (flet ((params-of (outputs)
             (multiple-value-bind (kind method params)
                 (bl.rpc:parse-json-rpc-request
                  (format nil "{\"method\":\"createrawtransaction\",\"params\":[[],~A],\"id\":1}"
                          outputs))
               (is (eq :single kind))
               (is (string= "createrawtransaction" method))
               params)))
      (flet ((create (outputs)
               (bl.rpc:dispatch-rpc-method node "createrawtransaction"
                                           (params-of outputs))))
        ;; A repeated address: the request parses, and the handler answers.
        (multiple-value-bind (code msg)
            (%rails-error
             (lambda () (create (format nil "{\"~A\":1,\"~A\":1}" addr addr))))
          (is (eql -8 code) "a well-formed body with a repeated key was refused")
          (is (string= (format nil "Invalid parameter, duplicated address: ~A" addr)
                       msg)))
        ;; A repeated data output has its own message, and it is NOT the
        ;; address one: "data" is not an address.
        (multiple-value-bind (code msg)
            (%rails-error (lambda () (create "{\"data\":\"aa\",\"data\":\"bb\"}")))
          (is (eql -8 code))
          (is (string= "Invalid parameter, duplicate key: data" msg)))
        ;; The array spelling of the same two, which never went through the
        ;; parser's object path, answers identically.
        (multiple-value-bind (code msg)
            (%rails-error (lambda () (create "[{\"data\":\"aa\"},{\"data\":\"bb\"}]")))
          (is (eql -8 code))
          (is (string= "Invalid parameter, duplicate key: data" msg)))
        ;; A body with no duplicate is untouched: objects are still hash
        ;; tables, so nothing downstream of the parser changed shape.
        (is (hash-table-p (second (params-of (format nil "{\"~A\":1}" addr)))))
        (is (stringp (create (format nil "{\"~A\":1}" addr))))))))

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

(test signrawtransactionwithkey-refuses-a-bad-wif-as-an-invalid-key
  "Core's DecodeSecret failure is RPC_INVALID_ADDRESS_OR_KEY -- the code every
bad key or address gets -- and not the -8 an out-of-range argument gets
(rpc/rawtransaction.cpp:748-752). Ours answered -8, so
rpc_signrawtransactionwithkey.py:138, which passes privkeys=[\"123\"] and asks
for -5 `Invalid private key\', read -8.

Core decodes the TRANSACTION before it looks at any key (:740-743), so a bad
key alongside bad hex is still the -22 decode failure; both rows are Core's
own, in Core's order. The control is that a well-formed WIF for a key the
transaction does not need is accepted and the call returns."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (txid "0000000000000000000000000000000000000000000000000000000000000001")
         (spk (bl.crypto:hex-to-bytes
               "76a91460baa0f494b38ce3c940dea67f3804dc52d1fb9488ac"))
         (raw (one-input-tx-hex txid 0 spk))
         ;; A regtest WIF for the all-ones secret: well-formed, and unrelated
         ;; to the output above.
         (good-wif (bl.crypto:private-key-to-wif
                    (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 1)
                    :network :regtest)))
    (is (equal (cons -5 "Invalid private key")
               (%rpc-wire-error node "signrawtransactionwithkey"
                                (list raw (vector "123"))))
        "a WIF that does not decode is Core's -5 Invalid private key")
    (is (equal (cons -22 "TX decode failed. Make sure the tx has at least one input.")
               (%rpc-wire-error node "signrawtransactionwithkey"
                                (list (concatenate 'string raw "00")
                                      (vector "123"))))
        "and the transaction is decoded first, so bad hex wins")
    ;; Control: a well-formed WIF is not refused.
    (is (null (%rpc-wire-error node "signrawtransactionwithkey"
                               (list raw (vector good-wif))))
        "a well-formed WIF is accepted")))

(test signrawtransactionwithkey-refuses-a-malformed-prevtxs-entry-in-cores-words
  "Core ParsePrevouts (rpc/rawtransaction_util.cpp:190-310) refuses every
malformed prevtxs entry with a specific code and sentence; this handler
SKIPPED any entry that was not a well-formed {txid, vout, scriptPubKey}
triple, signed without it, and reported the input as lacking a prevtx. Every
row below is one Core branch, in Core's order of checks:
  - a non-object entry, -22 (:197);
  - RPCTypeCheckObj over scriptPubKey/txid/vout -- a std::map, so the keys
    are checked in SORTED order -- \"Missing <key>\" and the type sentence,
    both -3 (rpc/util.cpp:56-68);
  - ParseHashO txid and ParseHexO scriptPubKey, -8 in ParseHashV's words,
    and getInt<int> on a vout that is no whole int32, whose plain
    std::runtime_error is -1 rather than -3 (rpc/server.cpp:512-515);
  - a negative vout, -22 (:213);
  - a scriptPubKey that disagrees with the coin already known for the
    outpoint -- here the previous entry -- -22 with both scripts' asm (:221);
  - and, since this RPC hands Core a keystore, the redeemScript/witnessScript
    rules for a P2SH or P2WSH output (:241-305): type-checked, at least one
    present, consistent with each other, and matching the scriptPubKey.
Positive controls: a well-formed P2PKH entry and a P2SH entry whose
redeemScript hashes to the output are not refused."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (txid (format nil "~64,'0D" 1))
         (spk-hex "76a91460baa0f494b38ce3c940dea67f3804dc52d1fb9488ac")
         (spk (bl.crypto:hex-to-bytes spk-hex))
         (wpkh-hex "001460baa0f494b38ce3c940dea67f3804dc52d1fb94")
         (op-true (bl.crypto:hex-to-bytes "51"))
         (p2sh-of-true (bl.crypto:bytes-to-hex
                        (concatenate '(vector (unsigned-byte 8))
                                     #(#xa9 #x14) (bl.crypto:hash160 op-true) #(#x87))))
         (p2sh-zeros (format nil "a914~40,'0D87" 0))
         (p2wsh-zeros (format nil "0020~64,'0D" 0))
         (raw (one-input-tx-hex txid 0 spk)))
    (flet ((answer (&rest entries)
             (%rpc-wire-error node "signrawtransactionwithkey"
                              (list raw (vector) entries)))
           (entry (&rest kvs)
             (loop for (k v) on kvs by #'cddr collect (cons k v))))
      (is (equal (cons -22 "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}")
                 (answer "abc")))
      (is (equal (cons -22 "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}")
                 (answer 5)))
      ;; RPCTypeCheckObj: sorted keys, so scriptPubKey is missed first.
      (is (equal (cons -3 "Missing scriptPubKey") (answer (entry "txid" txid "vout" 0))))
      (is (equal (cons -3 "Missing txid") (answer (entry "scriptPubKey" spk-hex "vout" 0))))
      (is (equal (cons -3 "Missing vout") (answer (entry "scriptPubKey" spk-hex "txid" txid))))
      (is (equal (cons -3 "JSON value of type number for field txid is not of expected type string")
                 (answer (entry "txid" 5 "vout" 0 "scriptPubKey" spk-hex))))
      (is (equal (cons -3 "JSON value of type string for field vout is not of expected type number")
                 (answer (entry "txid" txid "vout" "0" "scriptPubKey" spk-hex))))
      ;; ParseHashO / getInt / ParseHexO, in that order.
      (let ((zs (make-string 64 :initial-element #\z)))
        (is (equal (cons -8 (format nil "txid must be hexadecimal string (not '~A')" zs))
                   (answer (entry "txid" zs "vout" 0 "scriptPubKey" spk-hex)))))
      (is (equal (cons -1 "JSON integer out of range")
                 (answer (entry "txid" txid "vout" 1.5d0 "scriptPubKey" spk-hex))))
      (is (equal (cons -22 "vout cannot be negative")
                 (answer (entry "txid" txid "vout" -1 "scriptPubKey" spk-hex))))
      (is (equal (cons -8 "scriptPubKey must be hexadecimal string (not 'zz')")
                 (answer (entry "txid" txid "vout" 0 "scriptPubKey" "zz"))))
      ;; Two entries for one outpoint that disagree: Core's message carries
      ;; both scripts as asm.
      (is (equal (cons -22 (format nil "Previous output scriptPubKey mismatch:~%~
OP_DUP OP_HASH160 60baa0f494b38ce3c940dea67f3804dc52d1fb94 OP_EQUALVERIFY OP_CHECKSIG~%~
vs:~%0 60baa0f494b38ce3c940dea67f3804dc52d1fb94"))
                 (answer (entry "txid" txid "vout" 0 "scriptPubKey" spk-hex)
                         (entry "txid" txid "vout" 0 "scriptPubKey" wpkh-hex))))
      ;; The keystore branch: P2SH and P2WSH outputs need their script.
      (is (equal (cons -8 "Missing redeemScript/witnessScript")
                 (answer (entry "txid" txid "vout" 0 "scriptPubKey" p2sh-zeros))))
      (is (equal (cons -3 "JSON value of type number for field redeemScript is not of expected type string")
                 (answer (entry "txid" txid "vout" 0 "scriptPubKey" p2sh-zeros
                                "redeemScript" 5))))
      (is (equal (cons -8 "redeemScript does not correspond to witnessScript")
                 (answer (entry "txid" txid "vout" 0 "scriptPubKey" p2sh-zeros
                                "redeemScript" "51" "witnessScript" "52"))))
      (is (equal (cons -8 "redeemScript/witnessScript does not match scriptPubKey")
                 (answer (entry "txid" txid "vout" 0 "scriptPubKey" p2sh-zeros
                                "redeemScript" "51"))))
      (is (equal (cons -8 "redeemScript/witnessScript does not match scriptPubKey")
                 (answer (entry "txid" txid "vout" 0 "scriptPubKey" p2wsh-zeros
                                "witnessScript" "51"))))
      ;; Positive controls.
      (is (null (answer (entry "txid" txid "vout" 0 "scriptPubKey" spk-hex))))
      (is (null (answer (entry "txid" txid "vout" 0 "scriptPubKey" p2sh-of-true
                               "redeemScript" "51")))))))

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
         (result (%deriveaddresses node (list desc (list 1 2)))))
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
      (%deriveaddresses
       node (list (format nil "~A#00000000" body) (list 1 2))))
    ;; And an ordinary descriptor still returns a flat list.
    (let* ((single (concatenate 'string
                                "wpkh(tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZ"
                                "mbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRv"
                                "mDUjyEmNUWwx8UbK/1/1/*)"))
           (flat (%deriveaddresses
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
999 disconnected such peers on sight -- the second reader, and the reason the
whole rule is now gone (see HEIGHT-BASED-EVICTION-IS-GONE). What remains here
is the sync thread's half."
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
connection_type is \"manual\" -- rpc_net.py asserts exactly that (:125) -- and
its \"permissions\" are the ones Core stores on the CNode: an outbound
connection starts from NetPermissionFlags::None and consults the OUTGOING
whitelist ranges only when it is MANUAL (net.cpp:510-512), so a `,out' range
shows up on the manual peer and not on the automatic one inside it."
  (let ((node (make-test-node))
        (manual (bl.net:make-peer :address "10.1.1.1" :state :ready
                                  :conn-type :manual))
        (auto (bl.net:make-peer :address "10.1.1.2" :state :ready
                                :conn-type :outbound-full-relay))
        (inbound (bl.net:make-peer :address "10.1.1.3" :state :ready :inbound t))
        (bl.net:*whitelist-entries*
          (list (bl.net:parse-whitelist-entry "noban,out@10.0.0.0/8")))
        (bl.net:*whitebind-flags* 0))
    (setf (bl:node-peers node) (list manual auto inbound))
    (let* ((rows (bl.rpc::%peerinfo-rows node))
           (field (lambda (name)
                    (mapcar (lambda (r) (cdr (assoc name r :test #'string=)))
                            rows))))
      (is (equal '("manual" "outbound-full-relay" "inbound")
                 (funcall field "connection_type"))
          "connection_type: ~S" (funcall field "connection_type"))
      (is (equalp '(#("noban" "download") #() #())
                  (funcall field "permissions"))
          "permissions: ~S" (funcall field "permissions")))))

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
    ;; Core's UpdatedBlockTip queues the new tip on EVERY peer -- it excludes
    ;; nobody, not even the one that delivered the block
    ;; (net_processing.cpp:2180-2188). What stops it being announced back is
    ;; PeerHasHeader at flush time: delivering a block sets that peer's
    ;; best-known block to it. A locally mined block has no source at all.
    (bl.net:queue-block-announcement peer (make-array 32 :element-type '(unsigned-byte 8)
                                                         :initial-element 0))
    (is-true (bl.net:peer-blocks-for-headers-relay peer)
             "every peer is queued, source or not")
    ;; And the production announcement is the :updated-block-tip hook, the one
    ;; path every connect shares -- submitblock, the P2P handler and the
    ;; block-download drain alike.
    (let ((src (project-source-text "src/node/peers.lisp")))
      (is (search "define-validation-hook :updated-block-tip announce-block-tip" src)
          "the new-tip announcement hook is gone")
      (is (search "(bl.net:queue-block-announcement peer hash)" src)
          "the hook must QUEUE, leaving the message to the flush"))))

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
               ;; Core's rows, restricted to what we serve -- and without
               ;; echojson, the one method where Core's own two tables
               ;; disagree: client.cpp lists its arguments as convertible while
               ;; the RPCHelpMan declares them STR (rpc/node.cpp:286-295), so
               ;; dumpArgMap reports them string-typed. rpc_help.py:72 drops it
               ;; from the client side for exactly this reason; keeping it here
               ;; would pin our table to the side Core's own test ignores.
               (comparable (lambda (r) (and (gethash (first r) our-methods)
                                            (not (string= (first r) "echojson")))))
               (want-json (remove-if-not comparable core-json))
               (want-strings (remove-if-not comparable core-strings))
               (got-json (loop for r in ours
                               unless (or (fourth r) (string= (first r) "echojson"))
                                 collect (subseq r 0 3)))
               (got-strings (loop for r in ours
                                  when (and (fourth r)
                                            (not (string= (first r) "echojson")))
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
        ;; Zero since migratewallet was registered: every method Core lists
        ;; with a typed argument is served here. The ceiling was 2 while this
        ;; was a distance being closed; it is now the invariant rpc_help.py
        ;; :110 asserts, so a method dropping out is a failure.
        (is (null missing)
            "Core methods with typed arguments that this node does not serve: ~S"
            (sort missing #'string<))))))

(defun %erf (&rest params)
  "estimaterawfee with PARAMS. One reach for the whole file."
  (bl.rpc::rpc-estimaterawfee nil params))

(defun %erf-horizon (name &rest params)
  "One horizon object of the estimaterawfee answer for PARAMS."
  (cdr (assoc name (apply #'%erf params) :test #'string=)))

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
    (let ((r (%erf 2)))
      (is (consp r) "no horizon answered for a target every horizon tracks")
      (let ((short (cdr (assoc "short" r :test #'string=))))
        (is-true short "the short horizon did not answer for conf_target 2")
        ;; No feerate key at all: CFeeRate(0) is the sentinel, not a fee.
        ;; The full key set is ESTIMATERAWFEE-HORIZON-OBJECT-IS-CORES-TWO-BRANCHES.
        (is-false (assoc "feerate" short :test #'string=))
        (is-true (assoc "errors" short :test #'string=)
                 "an estimator with no history must say so")))
    ;; A target only the long horizon tracks omits the shorter ones entirely.
    (let* ((long-max (bl.mp:horizon-max-confirms :long))
           (short-max (bl.mp:horizon-max-confirms :short))
           (r (%erf (min long-max (1+ short-max)))))
      (is-false (assoc "short" r :test #'string=)
                "the short horizon answered for a target it does not track"))
    ;; Range and type checks.
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of (lambda () (%erf 0)))))
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of (lambda () (%erf 2 1.5)))))
    (is (= bl.rpc:+rpc-invalid-parameter+
           (rpc-error-code-of (lambda () (%erf 2 -0.1)))))
    (is (= bl.rpc:+rpc-type-error+
           (rpc-error-code-of (lambda () (%erf "2")))))))

(defun %erf-txid (n)
  "A distinct 32-byte txid for the estimator fixture."
  (let ((bytes (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (dotimes (i 4 bytes)
      (setf (aref bytes i) (ldb (byte 8 (* 8 i)) n)))))

(defun %erf-driven-estimator (&key (blocks 60) (per-block 40))
  "An estimator with enough confirmed history for every horizon to answer:
PER-BLOCK transactions at two feerates enter at each height and all confirm in
the next block."
  (let ((estimator (bl.mp:make-block-policy-estimator))
        (n 0))
    (loop for height from 1 to blocks
          do (let ((txids '()))
               (dotimes (i per-block)
                 (let ((txid (%erf-txid (incf n))))
                   (bpe-add-tx estimator txid height
                               (if (evenp i) 10000d0 25000d0))
                   (push txid txids)))
               (bpe-add-block estimator (1+ height) (nreverse txids))))
    estimator))

(defun %erf-keys (horizon-object)
  (mapcar #'car horizon-object))

(test estimaterawfee-horizon-object-is-cores-two-branches
  "GA11 63b42740. Core builds each horizon object in TWO branches keyed on
CFeeRate(0), estimateRawFee's error sentinel (rpc/fees.cpp:196-211):

  - an answer: feerate, decay, scale, pass, and fail only when the fail
    bucket's start is not -1;
  - no answer: decay, scale, fail, errors -- and NO feerate key.

decay and scale are declared WITHOUT /*optional=*/true (fees.cpp:120-121) and
Core re-checks the returned object against that declaration whenever
-rpcdoccheck is set, which the functional framework sets in every node's
config (test_framework/util.py:561) -- so both are in every horizon object a
Core test ever sees. Both were missing here, from BOTH branches, while the
no-answer branch reported (\"feerate\" 0.0) -- a fee of zero where Core says it
has no estimate -- omitted the fail bucket, and shortened the errors sentence.

The KEY SET is what is asserted, in order, because that is the whole finding."
  (let ((bl.mp:*block-policy-estimator* (bl.mp:make-block-policy-estimator)))
    (let ((short (%erf-horizon "short" 2)))
      (is (equal '("decay" "scale" "fail" "errors") (%erf-keys short))
          "no-answer horizon keys: ~S" (%erf-keys short))
      (is (equalp #("Insufficient data or no feerate found which meets threshold")
                  (cdr (assoc "errors" short :test #'string=))))
      ;; Core materialises the DEFAULT EstimatorBucket here: -1/-1 and zeros.
      (let ((fail (cdr (assoc "fail" short :test #'string=))))
        (is (equal '("startrange" "endrange" "withintarget" "totalconfirmed"
                     "inmempool" "leftmempool")
                   (%erf-keys fail)))
        (is (string= "-1" (%json-token (cdr (assoc "startrange" fail :test #'string=)))))
        (is (string= "0" (%json-token (cdr (assoc "inmempool" fail :test #'string=))))))))
  ;; The answering branch: feerate first, decay and scale next, pass, and no
  ;; fail because every bucket passed.
  (let ((bl.mp:*block-policy-estimator* (%erf-driven-estimator)))
    (let ((short (%erf-horizon "short" 2)))
      (is (equal '("feerate" "decay" "scale" "pass") (%erf-keys short))
          "answering horizon keys: ~S" (%erf-keys short))
      (is (plusp (btc-amount (cdr (assoc "feerate" short :test #'string=)))))))
  ;; A recorded fail bucket IS reported alongside pass; the sentinel is a
  ;; comparison against -1, not a null check.
  (let ((with-fail (bl.rpc::%raw-fee-horizon-json
                    10000 (list :pass (list :start 1 :end 2)
                                :fail (list :start 3 :end 4)
                                :decay 0.9d0 :scale 2))))
    (is (equal '("feerate" "decay" "scale" "pass" "fail") (%erf-keys with-fail))))
  ;; The INF_FEERATE bucket boundary is 1e99: Core's round() keeps a double
  ;; and UniValue writes 1e+99, where CL's ROUND gives a 99-digit integer.
  (let* ((object (bl.rpc::%raw-fee-horizon-json
                  10000 (list :pass (list :start 0 :end 1d99)
                              :decay 0.9d0 :scale 2)))
         (pass (cdr (assoc "pass" object :test #'string=))))
    (is (string= "1e+99" (%json-token (cdr (assoc "endrange" pass :test #'string=)))))))


(test addconnection-capacity-ignores-disconnected-peers
  "Core's AddConnection counts m_nodes (net.cpp:1894-1897), from which a closed
connection has already been erased (DisconnectNodes, :1909-1939). Ours kept a
:disconnected peer in node-peers until the sync cycle reaped it and counted it
toward the outbound cap, so after the framework closed all of node0's
connections the next addconnection was refused as `Already at capacity` for
a whole cycle (p2p_add_connections.py:78). Control: a live peer still counts."
  (let* ((bl:*network* :regtest)
         (node (bl:make-node :network :regtest))
         (bl:*pending-test-connections* '()))
    (setf (bl:node-max-peers node) 1)
    (push (bl.net:make-peer :address "10.0.0.5" :state :disconnected
                            :conn-type :outbound-full-relay)
          (bl:node-peers node))
    (is (= 0 (bl:peers-of-conn-type node :outbound-full-relay))
        "a closed connection is not a connection")
    (is-true (bl.rpc:dispatch-rpc-method node "addconnection"
                                         (list "1.2.3.4:1" "outbound-full-relay" bl.rpc:+json-false+))
             "the slot the closed connection held is free")
    (push (bl.net:make-peer :address "10.0.0.6" :state :ready
                            :conn-type :outbound-full-relay)
          (bl:node-peers node))
    (is (= 1 (bl:peers-of-conn-type node :outbound-full-relay)) "control: a live peer counts")
    (is (= bl.rpc::+rpc-client-node-capacity-reached+
           (rpc-error-code-of
            (lambda () (bl.rpc:dispatch-rpc-method
                        node "addconnection" (list "1.2.3.4:2" "outbound-full-relay" bl.rpc:+json-false+)))))
        "control: a live peer fills the one slot")))
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
  (is-true (member 'bl::dial-queued-nodes
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

(test named-params-refuse-a-repeated-key
  "Core puts every member of a named-params object into a map and refuses a key
that is already there, before it looks at a single name (rpc/server.cpp:374-382).
bitcoin-cli -named sends exactly that when an explicit args= meets positional
arguments -- pushKVEnd appends a second args (rpc/client.cpp:509-514) -- and
interface_bitcoin_cli.py:130 expects the refusal. The body used to reach the
transform as an alist that was taken for a POSITIONAL list, so the answer was
whatever the first handler made of it."
  (signals-rpc-error (:code -8 :exact-message "Parameter args specified multiple times")
    (bl.rpc:parse-json-rpc-request
     "{\"method\":\"echo\",\"params\":{\"args\":\"[0,1,2,3]\",\"args\":[\"4\",\"5\",\"6\"]},\"id\":1}"))
  (signals-rpc-error (:code -8 :exact-message "Parameter arg1 specified multiple times")
    (bl.rpc:parse-json-rpc-request
     "{\"method\":\"echo\",\"params\":{\"arg0\":\"a\",\"arg1\":\"b\",\"arg1\":\"c\"},\"id\":1}"))
  ;; The positive control: the same request with the key once is answered.
  (is (equal '("0" "1") (nth-value 2 (bl.rpc:parse-json-rpc-request
                                     "{\"method\":\"echo\",\"params\":{\"args\":[\"0\",\"1\"]},\"id\":1}")))))

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

(test rest-getutxos-answers-an-empty-list-not-null
  "A /rest/getutxos query whose every outpoint is spent (or unknown) has no
utxos at all, and Core answers `\"utxos\": []' -- rest.cpp builds a UniValue
VARR and pushes nothing into it. NIL encodes as JSON null here, so ours
answered `\"utxos\": null' and interface_rest.py:148 took len() of None."
  (let ((node (make-test-node))
        (zeros (make-string 64 :initial-element #\0)))
    (let* ((hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (body (rest-request node (format nil "/rest/getutxos/~A-0.json" zeros)))
           (parsed (yason:parse body)))
      (is (equal '() (gethash "utxos" parsed))
          "an all-spent query must carry an empty ARRAY; got ~S" body)
      ;; yason parses [] and null both to NIL, so the bytes are the assertion.
      (is-true (search "\"utxos\":[]" (remove #\Space body))
               "the JSON must read [] and not null; got ~S" body)
      (is (equal "0" (gethash "bitmap" parsed))))))

(test rest-errors-are-worded-as-core-words-them
  "Core's RESTERR sentences name the value they could not use: `Invalid hash:
<str>' (rest.cpp:213, :331, :401, :636, :846), `<str> not found' (:341, :415,
:658, :858), `Invalid height: <str>' (:1099), `Block height out of range'
(:1110) and `Header count is invalid or out of acceptable range (1-2000):
<str>' (:208, :527).

Ours were generic -- `Invalid txid', `Invalid block hash', `Block not found',
`Invalid count' -- so interface_rest.py:123 read `Invalid txid' where it
compares the whole line against `Invalid hash: abc'."
  (let ((node (make-test-node)))
    (flet ((body-of (uri)
             (let ((hunchentoot:*reply* (make-instance 'hunchentoot:reply)))
               (handler-case (rest-request node uri)
                 (error (e) (princ-to-string e))))))
      (dolist (row '(("/rest/tx/abc.json" "Invalid hash: abc")
                     ("/rest/block/abc.json" "Invalid hash: abc")
                     ("/rest/headers/abc.json" "Invalid hash: abc")
                     ("/rest/spenttxouts/abc.json" "Invalid hash: abc")
                     ("/rest/blockhashbyheight/abc.json" "Invalid height: abc")))
        (destructuring-bind (uri expected) row
          (let ((b (body-of uri)))
            (is-true (and (stringp b) (search expected b))
                     "~A: wanted ~S, got ~S" uri expected b))))
      ;; A well-formed hash nothing knows is "<hash> not found", naming it.
      (let* ((zeros (make-string 64 :initial-element #\0))
             (b (body-of (format nil "/rest/tx/~A.json" zeros))))
        (is-true (and (stringp b) (search (format nil "~A not found" zeros) b))
                 "an unknown txid must be named: ~S" b))
      ;; A height past the tip is Core's own sentence, not "Block not found".
      (let ((b (body-of "/rest/blockhashbyheight/999999.json")))
        (is-true (and (stringp b) (search "Block height out of range" b))
                 "a height past the tip: ~S" b))
      ;; The count range, with the value as it arrived.
      (let ((b (body-of (format nil "/rest/headers/~A.json?count=0"
                                (make-string 64 :initial-element #\0)))))
        (is-true (and (stringp b)
                      (search "Header count is invalid or out of acceptable range (1-2000): 0" b))
                 "count=0: ~S" b)))))

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
          ;; Core's sentence names the value it could not parse
          ;; (rest.cpp:331, :636): "Invalid hash: nothex".
          (is-true (and (stringp b) (search "Invalid hash: nothex" b))
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
      (is (= (/ 5000 100000000) (btc-amount (cdr (assoc "value" p :test #'string=)))))
      (is-true (assoc "generated" p :test #'string=))
      (is-true (assoc "scriptPubKey" p :test #'string=))
      ;; The fee is inputs minus outputs, from the coins.
      (let ((out-total (loop for o across (bl.ser:transaction-outputs tx)
                             sum (bl.ser:tx-out-value o))))
        (is (= (/ (- 5000 out-total) 100000000)
               (btc-amount (cdr (assoc "fee" j :test #'string=)))))))))

(defun %spk-object-keys (object)
  (mapcar #'car object))

(defun %tx-spending-and-paying-to (spk)
  "A one-input, one-output transaction whose OUTPUT script is SPK, so the
prevout object and the vout object are built from the same bytes."
  (bl.ser:make-transaction
   :version 1
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element 9)
                                      :index 0)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence #xFFFFFFFF))
   :outputs (vector (bl.ser:make-tx-out :value 4000 :script-pubkey spk))
   :lock-time 0))

(test prevout-and-vout-render-the-same-scriptpubkey-object
  "Core renders every scriptPubKey through ONE helper: TxToUniv calls
ScriptToUniv identically for the verbosity-3 prevout (core_io.cpp:480) and for
every vout (:506), both with include_hex and include_address, so the two
objects carry the same keys in the same order. Two hand-written copies had
drifted -- the prevout's had lost `desc', which Core's ScriptPubKeyDoc
(rpc/util.cpp:1390-1398) documents as always present, so a client reading the
field uniformly got a key error on the prevout half only.

The asymmetry, not the presence of one key, is what this asserts. Plus the one
asymmetry Core DOES have inside the helper: the address is suppressed for
TxoutType::PUBKEY (core_io.cpp:423) even though ExtractDestination succeeds."
  (flet ((objects (spk)
           (let* ((tx (%tx-spending-and-paying-to spk))
                  (coins (list (bl.store:make-utxo-entry
                                :value 5000 :script-pubkey spk
                                :height 7 :coinbase nil)))
                  (j (bl.rpc:tx-to-json tx :regtest :spent-coins coins
                                                    :prevouts t))
                  (vin0 (first (cdr (assoc "vin" j :test #'string=))))
                  (vout0 (first (cdr (assoc "vout" j :test #'string=)))))
             (values (cdr (assoc "scriptPubKey"
                                 (cdr (assoc "prevout" vin0 :test #'string=))
                                 :test #'string=))
                     (cdr (assoc "scriptPubKey" vout0 :test #'string=))))))
    (let ((p2wpkh (bl.crypto:hex-to-bytes
                   "0014aae5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5")))
      (multiple-value-bind (prevout vout) (objects p2wpkh)
        (is (equal (%spk-object-keys vout) (%spk-object-keys prevout))
            "prevout keys ~S, vout keys ~S"
            (%spk-object-keys prevout) (%spk-object-keys vout))
        (is (equal '("asm" "desc" "hex" "address" "type")
                   (%spk-object-keys vout))
            "ScriptToUniv's key order")
        (is (string= (cdr (assoc "desc" vout :test #'string=))
                     (cdr (assoc "desc" prevout :test #'string=))))))
    ;; The bare-pubkey control: no address on either side, and a desc on both.
    (let ((p2pk (bl.crypto:hex-to-bytes
                 "2103a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bdac")))
      (multiple-value-bind (prevout vout) (objects p2pk)
        (is (equal (%spk-object-keys vout) (%spk-object-keys prevout)))
        (is (equal '("asm" "desc" "hex" "type") (%spk-object-keys vout))
            "Core suppresses the address for TxoutType::PUBKEY")
        (is-true (assoc "desc" prevout :test #'string=))))))

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
      (is-true (search "Invalid hash: nothex"
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
                     (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil))
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
;;;
;;; The decoder is Core's DecodeTx (core_io.cpp:156-233): the SAME bytes are
;;; read twice, once witness-serialized and once legacy, a reading counts only
;;; when it consumes all of them, and CheckTxScriptsSanity breaks the tie.

(defparameter +decode-legacy-1-in-1-out+
  "020000000100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff010000000000000000066a040001020300000000"
  "A plain 66-byte legacy transaction, one input and one OP_RETURN output.")

(defparameter +decode-legacy-only-1-out+
  "0200000000010000000000000000066a040001020300000000"
  "25 bytes that decode DIFFERENTLY under the two serializations: the extended
reading is 0 inputs with a witness flag and no witness data, which Core rejects
as a Superfluous witness record, and the legacy reading is 0 inputs / 1 output
consuming every byte. Core answers the legacy one, txid fc4e265b...")

(defparameter +decode-legacy-only-2-out+
  "0200000000020000000000000000066a04000102030000000000000000066a040001020300000000"
  "The same shape with two outputs, so the byte after the empty vin is 0x02.
The witness reading cannot use it; the legacy reading consumes the lot.")

(defun decode-raw-tx (hex &rest more)
  "decoderawtransaction over the wire: HEX plus any further positional
arguments, through the dispatcher and the request normalizer."
  (bl.rpc:dispatch-rpc-method
   (make-test-node :network :regtest) "decoderawtransaction"
   (wire-params (cons hex more))))

(defun decode-raw-tx-field (hex key &rest more)
  (cdr (assoc key (apply #'decode-raw-tx hex more) :test #'string=)))

(test decoderawtransaction-reports-the-version-unsigned-and-coinbase-per-transaction
  "Two things TxToUniv decides that ours decided differently, both found by
the differential lane against bitcoin-tx (tests/rpc/core-binary-differential-tests.lisp)
over Core's own sighash.json and tx_valid.json vectors:

- the version is CTransaction::version, a uint32_t (primitives/transaction.h:293),
  pushed as it is (core_io.cpp:436): 0xce56a2fe is 3461784318, not the
  -833182978 we printed -- 276 of Core's 672 vector transactions have the top
  bit set;
- \"coinbase\" replaces txid/vout/scriptSig for every input of a COINBASE
  TRANSACTION -- one input with a null prevout, tx.IsCoinBase()
  (core_io.cpp:454) -- and never for an input of an ordinary transaction that
  merely names the null outpoint, which ours rendered as a coinbase input."
  (is (= 3461784318
         (decode-raw-tx-field
          "fea256ce01272d125e577c0a09570a71366898280dda279b021000db1325f27edda41a53460100000002ab53c752c21c013c2b3a01000000000000000000"
          "version")))
  (let* ((vin (decode-raw-tx-field
               "010000000200010000000000000000000000000000000000000000000000000000000000000000000000ffffffff0000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff010000000000000000015100000000"
               "vin"))
         (second-in (second vin)))
    (is (= 2 (length vin)))
    (is (null (assoc "coinbase" second-in :test #'string=))
        "an ordinary transaction has no coinbase input")
    (is (string= (make-string 64 :initial-element #\0)
                 (cdr (assoc "txid" second-in :test #'string=))))
    (is (eql 4294967295 (cdr (assoc "vout" second-in :test #'string=)))))
  ;; Control: a real coinbase transaction still reports its input as one.
  (let ((coinbase (bl.store:make-genesis-block :regtest)))
    (is (assoc "coinbase"
               (first (decode-raw-tx-field
                       (bl.crypto:bytes-to-hex
                        (bl.ser:transaction-wire-bytes
                         (first (bl.ser:bitcoin-block-transactions coinbase))))
                       "vin"))
               :test #'string=))))

(test rpc-decoderawtransaction-refuses-trailing-bytes
  "Core's DecodeTx ignores any serialization that does not consume the WHOLE
input (core_io.cpp:180), so a valid transaction hex with extra bytes is -22 and
not a transaction. We decoded the prefix and echoed back a DIFFERENT, shorter
transaction whose txid does not mention the bytes the caller sent -- a client
round-tripping through decoderawtransaction to identify a transaction before
broadcasting identified the wrong one."
  (is (string= "f00c3ac7ff076b25a54a87c2b155dcac778cf242459f773c1d85ebc46cdf9381"
               (decode-raw-tx-field +decode-legacy-1-in-1-out+ "txid"))
      "positive control: the transaction without trailing bytes still decodes")
  (is (= 66 (decode-raw-tx-field +decode-legacy-1-in-1-out+ "size")))
  (dolist (tail (list "deadbeef" (make-string 128 :initial-element #\0)))
    (let ((e (handler-case
                 (progn (decode-raw-tx
                         (concatenate 'string +decode-legacy-1-in-1-out+ tail))
                        nil)
               (bl.rpc:rpc-error (e) e))))
      (is-true e "~D trailing bytes accepted" (floor (length tail) 2))
      (when e
        (is (= -22 (bl.rpc:rpc-error-code e)))
        (is (string= "TX decode failed" (bl.rpc:rpc-error-message e)))))))

(test rpc-decoderawtransaction-reads-both-serializations
  "A hex string that is only valid under the LEGACY serialization is Core's
answer, not an error and not a different transaction. Ours committed to the
witness branch on a leading 0x00 and could not go back: the 25-byte vector came
out as 0 inputs / 0 outputs, 10 bytes, with 15 bytes silently dropped and a
txid belonging to no transaction the caller sent, and the two-output one was
refused outright with `Invalid witness flag byte: 2'."
  (is (string= "fc4e265bd5a8cc618d3beccb6e68f72d8bedd686b426c77e27326212f7d03227"
               (decode-raw-tx-field +decode-legacy-only-1-out+ "txid")))
  (is (= 25 (decode-raw-tx-field +decode-legacy-only-1-out+ "size")))
  (is (= 0 (length (decode-raw-tx-field +decode-legacy-only-1-out+ "vin"))))
  (is (= 1 (length (decode-raw-tx-field +decode-legacy-only-1-out+ "vout"))))
  (is (string= "ee096f9a7e05e7ec97287df87ff74433948f62c013750b32d01ef3f734702b12"
               (decode-raw-tx-field +decode-legacy-only-2-out+ "txid")))
  (is (= 2 (length (decode-raw-tx-field +decode-legacy-only-2-out+ "vout")))))

(test rpc-decoderawtransaction-honours-iswitness
  "The second argument picks the serialization (rpc/rawtransaction.cpp:435-436):
absent, both are tried; true, only the witness reading; false, only the legacy
one. It was accepted and IGNORED -- true and false returned the identical
object."
  ;; Absent and false both reach the legacy reading.
  (is (string= "fc4e265bd5a8cc618d3beccb6e68f72d8bedd686b426c77e27326212f7d03227"
               (decode-raw-tx-field +decode-legacy-only-1-out+ "txid")))
  (is (string= "fc4e265bd5a8cc618d3beccb6e68f72d8bedd686b426c77e27326212f7d03227"
               (decode-raw-tx-field +decode-legacy-only-1-out+ "txid"
                                    bl.rpc:+json-false+)))
  ;; iswitness true forbids the legacy reading, and the witness reading of
  ;; these bytes fails.
  (let ((e (handler-case
               (progn (decode-raw-tx +decode-legacy-only-1-out+ t) nil)
             (bl.rpc:rpc-error (e) e))))
    (is-true e "iswitness=true still decoded a legacy-only transaction")
    (when e (is (= -22 (bl.rpc:rpc-error-code e)))))
  ;; Positive control the other way: the ordinary transaction decodes under
  ;; either flag, so the assertion above is about the SERIALIZATION and not
  ;; about the argument being rejected out of hand.
  (is (string= "f00c3ac7ff076b25a54a87c2b155dcac778cf242459f773c1d85ebc46cdf9381"
               (decode-raw-tx-field +decode-legacy-1-in-1-out+ "txid" t)))
  (is (string= "f00c3ac7ff076b25a54a87c2b155dcac778cf242459f773c1d85ebc46cdf9381"
               (decode-raw-tx-field +decode-legacy-1-in-1-out+ "txid"
                                    bl.rpc:+json-false+))))

(test rpc-decoderawtransaction-refuses-a-superfluous-witness-record
  "Core throws `Superfluous witness record' for a witness-FLAGGED transaction
whose witness stacks are all empty (primitives/transaction.h:220-222). We
accepted it, so the same transaction had two spellings on the wire and the one
Core refuses re-serialized here as the other."
  (let* ((legacy +decode-legacy-1-in-1-out+)
         ;; The same bytes with the 0x0001 marker spliced in after the version
         ;; and one EMPTY witness stack (0x00) before the locktime.
         (marked (concatenate 'string (subseq legacy 0 8) "0001" (subseq legacy 8)))
         (superfluous (concatenate 'string
                                   (subseq marked 0 (- (length marked) 8))
                                   "00"
                                   (subseq marked (- (length marked) 8)))))
    (is (string= "f00c3ac7ff076b25a54a87c2b155dcac778cf242459f773c1d85ebc46cdf9381"
                 (decode-raw-tx-field legacy "txid"))
        "positive control: the plain legacy serialization must decode")
    (signals bl.rpc:rpc-error (decode-raw-tx superfluous))))

(test rpc-decoderawtransaction-invalid-hex
  "Test decoderawtransaction with invalid hex returns error"
  ;; Empty string
  (signals bl.rpc:rpc-error (decode-raw-tx ""))
  ;; Invalid hex characters
  (signals bl.rpc:rpc-error (decode-raw-tx "zzzz")))

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
  "Run BODY with ESTIMATE-FEE-RATE answering RATE sat/vB (or ERROR-MSG), and
with MODE-OUT -- a symbol naming a place -- receiving the mode the RPC passed.
NODE is bound so callers keep reading as before; the RPC no longer consults
the node's fee estimator at all, because Core's estimatesmartfee consults the
policy estimator and nothing else."
  (declare (ignorable node))
  `(let ((real-est (fdefinition 'bl.mp:estimate-fee-rate)))
     (unwind-protect
          (progn
            (setf (fdefinition 'bl.mp:estimate-fee-rate)
                  (lambda (conf-target &key mode)
                    ,@(when mode-out `((setf ,mode-out mode)))
                    (values ,rate ,error-msg (or ,returned-target conf-target))))
            ,@body)
       (setf (fdefinition 'bl.mp:estimate-fee-rate) real-est))))

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

(test estimatesmartfee-reports-no-estimate-over-a-block-percentile
  "The survey's exact scenario: an EMPTY policy estimator and twelve blocks of
percentile history at a median of 7 sat/vB. estimatesmartfee returned
{feerate: 7.0e-5, blocks: 2} -- a number derived from what miners happened to
include, indistinguishable from a real estimate, so a wallet reading it never
falls back to its own -fallbackfee. Core answers the errors array
(feature_fee_estimation.py:332,413)."
  (let* ((node (make-test-node))
         (bl::*syncing* nil)
         (bl.mp:*block-policy-estimator* (bl.mp:make-block-policy-estimator))
         (legacy (bl.mp:make-fee-estimator)))
    (dotimes (i 12)
      (bl.mp:fee-estimator-add-stats
       legacy (bl.mp:make-block-fee-stats
               :height (+ 100 i) :median-rate 7 :low-rate 3
               :high-rate 20 :tx-count 100)))
    (setf (bl:node-fee-estimator node) legacy)
    (is (= 12 (bl.mp:fee-estimator-entry-count legacy))
        "positive control: the percentile history the fallback read is there")
    (is (= 0 (bl.mp:bpe-estimate-smart-fee bl.mp:*block-policy-estimator* 2))
        "positive control: the policy estimator has no answer")
    (dolist (target '(2 6))
      (let ((result (bl.rpc:dispatch-rpc-method node "estimatesmartfee"
                                                (list target))))
        (is-false (assoc "feerate" result :test #'string=)
                  "target ~D reported a block-percentile feerate" target)
        (is (= target (cdr (assoc "blocks" result :test #'string=))))
        (is (equalp #("Insufficient data or no feerate found")
                    (cdr (assoc "errors" result :test #'string=))))))))

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
        (is (= (/ 10000 100000000)
               (btc-amount (cdr (assoc "feerate" result :test #'string=))))))
      ;; Floor above the estimate: the floor wins.
      (let ((mempool (bl.rpc:rpc-get-mempool node)))
        (when mempool
          (setf (bl.mp:mempool-min-fee-rate mempool) 50000)
          (let ((result (bl.rpc::rpc-estimatesmartfee node '(6))))
            (is (= (/ 50000 100000000)
                   (btc-amount (cdr (assoc "feerate" result :test #'string=))))
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
;;;
;;; The oracle is Bitcoin Core's own: test/functional/rpc_decodescript.py and
;;; the object-for-object corpus in its data/rpc_decodescript.json.

(defun %decodescript (script-hex &key (network :testnet3))
  "decodescript SCRIPT-HEX on a fresh minimal node of NETWORK, through the
exported dispatcher; the result alist."
  (bl.rpc:dispatch-rpc-method (make-test-node :network network)
                              "decodescript" (list script-hex)))

(defun %decodescript-field (result key)
  (cdr (assoc key result :test #'string=)))

(defun %decodescript-flat (result &optional (prefix ""))
  "RESULT as a flat (\"key\" . \"value\") list, the nested segwit object under
`segwit.\' keys, so a vector can pin the WHOLE object -- no field missing and
none extra."
  (loop for (key . value) in result
        append (if (and (consp value) (consp (first value))
                        (stringp (car (first value))))
                   (%decodescript-flat value (concatenate 'string prefix key "."))
                   (list (cons (concatenate 'string prefix key)
                               (princ-to-string value))))))

(defparameter +core-decodescript-vectors+
  '(
    ("5120eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
     ("asm" . "1 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
     ("address" . "bcrt1pamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhqz6nvlh")
     ("desc" . "rawtr(eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee)#jk7c6kys")
     ("type" . "witness_v1_taproot"))
    ("5102eeee"
     ("asm" . "1 -28398")
     ("address" . "bcrt1pamhqk96edn")
     ("desc" . "addr(bcrt1pamhqk96edn)#vkh8uj5a")
     ("type" . "witness_unknown"))
    ("0020eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
     ("asm" . "0 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
     ("address" . "bcrt1qamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhqgdn98t")
     ("desc" . "addr(bcrt1qamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhwamhqgdn98t)#afaecevx")
     ("type" . "witness_v0_scripthash")
     ("p2sh" . "2MwGk8mw1GBP6U9D5X8gTvgvXpuknmAK3fo"))
    ("a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87"
     ("asm" . "OP_HASH160 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee OP_EQUAL")
     ("address" . "2NF2b3KS8xXb9XHvbRMXdZh8s5g92rUZHtp")
     ("desc" . "addr(2NF2b3KS8xXb9XHvbRMXdZh8s5g92rUZHtp)#ywfcpmh9")
     ("type" . "scripthash"))
    ("6a00"
     ("asm" . "OP_RETURN 0")
     ("desc" . "raw(6a00)#ncfmkl43")
     ("type" . "nulldata"))
    ("6aee"
     ("asm" . "OP_RETURN OP_UNKNOWN")
     ("desc" . "raw(6aee)#vsyzgqdt")
     ("type" . "nonstandard"))
    ("6a02ee"
     ("asm" . "OP_RETURN [error]")
     ("desc" . "raw(6a02ee)#gvdwnlzl")
     ("type" . "nonstandard"))
    ("02eeee"
     ("asm" . "-28398")
     ("desc" . "raw(02eeee)#5xzck7pr")
     ("type" . "nonstandard")
     ("p2sh" . "2N34iiGoUUkVSPiaaTFpJjB1FR9TXQu3PGM")
     ("segwit.asm" . "0 96c2368fc30514a438a8bd909f93c49a1549d77198ccbdb792043b666cb24f42")
     ("segwit.desc" . "addr(bcrt1qjmprdr7rq522gw9ghkgfly7yng25n4m3nrxtmdujqsakvm9jfapqk795l5)#5akkdska")
     ("segwit.hex" . "002096c2368fc30514a438a8bd909f93c49a1549d77198ccbdb792043b666cb24f42")
     ("segwit.address" . "bcrt1qjmprdr7rq522gw9ghkgfly7yng25n4m3nrxtmdujqsakvm9jfapqk795l5")
     ("segwit.type" . "witness_v0_scripthash")
     ("segwit.p2sh-segwit" . "2MtoejEictTQ6XtmHYzoYttt35Ec6krqFKN"))
    ("ba"
     ("asm" . "OP_CHECKSIGADD")
     ("desc" . "raw(ba)#yy0eg44l")
     ("type" . "nonstandard"))
    ("50"
     ("asm" . "OP_RESERVED")
     ("desc" . "raw(50)#a7tu03xf")
     ("type" . "nonstandard")))
  "Bitcoin Core test/functional/data/rpc_decodescript.json verbatim, the nested
segwit object flattened under `segwit.\' keys. Core drives these on a REGTEST
node and compares the whole object, so this pins every field, its value and the
ABSENCE of the ones Core does not emit.")

(test rpc-decodescript-matches-cores-object-corpus
  "Every object in Core's data/rpc_decodescript.json, field for field --
including the bare taproot output's rawtr() desc, which is InferDescriptor's
typed arm for a P2TR program that parses as an x-only key."
  (loop for (hex . expected) in +core-decodescript-vectors+
        for actual = (%decodescript-flat (%decodescript hex :network :regtest))
        do (loop for (key . want) in expected
                 for got = (assoc key actual :test #'string=)
                 do (is-true got "~A: no ~A field" hex key)
                    (is (string= want (cdr got))
                        "~A ~A: ~S, Core says ~S" hex key (cdr got) want))
           (loop for (key . value) in actual
                 do (is-true (assoc key expected :test #'string=)
                             "~A: extra field ~A = ~S that Core does not emit"
                             hex key value))))

(test infer-descriptor-answers-cores-typed-descriptors-before-addr
  "Core's InferScript (descriptor.cpp:2691-2831) tries the TYPED inferences
BEFORE ExtractDestination, and three of them need no key material: a bare
pubkey is pk(), a bare multisig is multi(), and a taproot output whose program
is a fully valid x-only key is rawtr(). Only after those does Core reach
addr(), and raw() last.

The `desc' field is what a wallet import or an indexer keys on, so answering
addr()/raw() for all three lost the key and the threshold Core reports. Driven
through decodescript, which is one of the surfaces that emits the field."
  ;; Core descriptor_tests.cpp:1149-1157, the four CheckInferDescriptor
  ;; vectors that need no signing provider. Two of them are the CONTROLS: a
  ;; hybrid key has no descriptor (InferPubkey refuses header 06/07) and must
  ;; stay raw(), and an addressable script must stay addr(), so a change that
  ;; simply always emits a typed descriptor cannot pass.
  (let ((hybrid "069228de6902abb4f541791f6d7f925b10e2078ccb1298856e5ea5cc5fd667f930eac37a00cc07f9a91ef3c2d17bf7a17db04552ff90ac312a5b8b4caca6c97aa4")
        (uncompressed "04032540df1d3c7070a8ab3a9cdd304dfc7fd1e6541369c53c4c3310b2537d91059afc8b8e7673eb812a32978dabb78c40f2e423f7757dca61d11838c7aeeb5220")
        (compressed "03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd")
        (compressed2 "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659")
        ;; The BIP340 test-vector key: a point on the curve, so IsFullyValid.
        (xonly "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"))
    (flet ((desc (hex) (let ((d (%decodescript-field
                                 (%decodescript hex :network :mainnet) "desc")))
                         ;; The checksum is asserted by the Core object corpus;
                         ;; here the body is what InferScript decides.
                         (subseq d 0 (position #\# d)))))
      (is (string= (format nil "raw(41~Aac)" hybrid)
                   (desc (format nil "41~Aac" hybrid)))
          "a hybrid key has no descriptor (descriptor_tests.cpp:1149)")
      (is (string= "addr(17P7ge56F2QcdHxxRBa2NyzmejFggPwBJ9)"
                   (desc "76a91445ff7c2327866472639d507334a9a00119dfd32688ac"))
          "an addressable script is still addr() (descriptor_tests.cpp:1151)")
      (is (string= (format nil "pk(~A)" uncompressed)
                   (desc (format nil "41~Aac" uncompressed)))
          "descriptor_tests.cpp:1157")
      (is (string= (format nil "pk(~A)" compressed)
                   (desc (format nil "21~Aac" compressed))))
      (is (string= (format nil "multi(1,~A,~A)" compressed compressed2)
                   (desc (format nil "5121~A21~A52ae" compressed compressed2))))
      (is (string= (format nil "rawtr(~A)" xonly)
                   (desc (format nil "5120~A" xonly))))
      ;; A v1 program that is NOT a point on the curve keeps falling through
      ;; to its address, because Core builds RawTRDescriptor only for a key
      ;; that IsFullyValid.
      ;; BIP340 test vector 5, "public key not on the curve".
      (let ((off-curve "eefdea4cd0b44a0ebd1f1a9e9c6b4d5eddf7d33bb75c6a3f8fbb62b4e0e02e8f"))
        (is (eql 0 (search "addr(" (desc (format nil "5120~A" off-curve))))
            "an invalid x-only key must not become rawtr()")))))

(test rpc-decodescript-wraps-only-what-core-wraps
  "can_wrap (rpc/rawtransaction.cpp:496-526). The p2sh field used to be emitted
UNCONDITIONALLY, so decodescript handed out a P2SH address wrapping an
OP_RETURN (unspendable), one wrapping another P2SH and one wrapping a taproot
output (spendable by anyone holding the redeem script). Core refuses all of
them by type, and refuses any script that does not parse, is unspendable, or
carries OP_CHECKSIGADD or an OP_SUCCESS."
  (flet ((p2sh (hex) (%decodescript-field (%decodescript hex :network :regtest) "p2sh")))
    ;; Refused by type.
    (is-false (p2sh "6a0401020304") "P2SH wrapper for an OP_RETURN")
    (is-false (p2sh "a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87") "P2SH of a P2SH")
    (is-false (p2sh "5120eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
              "P2SH of a taproot output")
    (is-false (p2sh "5102eeee") "P2SH of an unknown witness version")
    (is-false (p2sh "51024e73") "P2SH of the anchor output")
    ;; Refused by the tail checks.
    (is-false (p2sh "ba") "OP_CHECKSIGADD")
    (is-false (p2sh "50") "OP_RESERVED is an OP_SUCCESS")
    (is-false (p2sh "6aee") "an unparseable script")
    ;; Allowed: the positive control, without which every assertion above
    ;; would pass on a handler that emitted no p2sh at all.
    (is-true (p2sh "02eeee") "a plain nonstandard script must still be wrapped")
    (is-true (p2sh "0014eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
             "P2SH-P2WPKH must still be offered")
    (is-true (p2sh "76a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee88ac")
             "P2SH of a P2PKH must still be offered")))

(test rpc-decodescript-segwit-object-follows-can-wrap-p2wsh
  "can_wrap_P2WSH (rpc/rawtransaction.cpp:533-570) and the exact strings
rpc_decodescript.py:66-160 asserts. The segwit object used to carry an address
alone, and to appear for the witness programs (where Core suppresses it) while
missing for P2PK, P2PKH and multisig (where Core produces it)."
  (let* ((pubkey "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2")
         (pkh "5dd1d3a048119c27b28293056724d9522f26d945")
         (uncompressed "04b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb25e01fc8fde47c96c98a4f3a8123e33a38a50cf9025cc8c4494a518f991792bb7")
         (multisig (concatenate 'string "52" "21" pubkey "21" pubkey "21" pubkey "53ae")))
    (flet ((segwit (hex key)
             (%decodescript-field
              (%decodescript-field (%decodescript hex :network :regtest) "segwit")
              key)))
      ;; P2PK is translated to P2WPKH over hash160 of the key (:70-72).
      (is (string= (concatenate 'string "0 " pkh)
                   (segwit (concatenate 'string "21" pubkey "ac") "asm")))
      ;; P2PKH is translated to P2WPKH over the hash it already carries (:80-82).
      (is (string= "witness_v0_keyhash"
                   (segwit (concatenate 'string "76a914" pkh "88ac") "type")))
      (is (string= (concatenate 'string "0 " pkh)
                   (segwit (concatenate 'string "76a914" pkh "88ac") "asm")))
      ;; Anything else is P2WSH over the script (:95-99).
      (is (string= "witness_v0_scripthash" (segwit multisig "type")))
      (is (string= (concatenate 'string "0 " (bl.crypto:bytes-to-hex
                                              (bl.crypto:sha256
                                               (bl.crypto:hex-to-bytes multisig))))
                   (segwit multisig "asm")))
      ;; The nested object is a full ScriptToUniv, not an address on its own.
      (is-true (segwit multisig "hex"))
      (is-true (segwit multisig "desc"))
      (is-true (segwit multisig "address"))
      (is-true (segwit multisig "p2sh-segwit")))
    (flet ((has-segwit (hex)
             (and (%decodescript-field (%decodescript hex :network :regtest) "segwit") t)))
      ;; An uncompressed key can never be spent under BIP143 (:141-159).
      (is-false (has-segwit (concatenate 'string "41" uncompressed "ac"))
                "P2PK with an uncompressed key")
      (is-false (has-segwit (concatenate 'string "52" "21" pubkey "41" uncompressed "52ae"))
                "multisig with an uncompressed key")
      ;; Segwit scripts do not nest (:104, :167-186).
      (is-false (has-segwit "a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87") "P2SH")
      (is-false (has-segwit "0014eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") "P2WPKH")
      (is-false (has-segwit "0020eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                "P2WSH")
      (is-false (has-segwit "5120eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                "P2TR")
      ;; Positive control for the four above.
      (is-true (has-segwit (concatenate 'string "21" pubkey "ac"))
               "a compressed P2PK must still get a segwit object"))))

(test rpc-decodescript-drops-the-pre-v22-fields
  "reqSigs and the plural addresses were removed from Core in v22; every
consumer written against a current Core reads the singular `address\' and
`desc\'. Both were emitted here for multisig, pubkeyhash and scripthash, and
neither desc nor the singular address ever was."
  (let* ((pubkey "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2")
         (multisig (concatenate 'string "52" "21" pubkey "21" pubkey "21" pubkey "53ae")))
    (dolist (hex (list multisig
                       "76a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee88ac"
                       "a914eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee87"))
      (let ((result (%decodescript hex :network :regtest)))
        (is-false (%decodescript-field result "reqSigs") "~A still reports reqSigs" hex)
        (is-false (%decodescript-field result "addresses")
                  "~A still reports the plural addresses" hex)
        (is-true (%decodescript-field result "desc") "~A reports no desc" hex)))
    ;; The singular address, and NOT for a bare pubkey (Core's ScriptToUniv
    ;; excludes PUBKEY by name, core_io.cpp:424).
    (is (string= "mp52VuXfTKhzYpuR3jLvPEYYUCWt84J7D5"
                 (%decodescript-field
                  (%decodescript "76a9145dd1d3a048119c27b28293056724d9522f26d94588ac"
                                 :network :regtest)
                  "address")))
    (is-false (%decodescript-field
               (%decodescript (concatenate 'string "21" pubkey "ac") :network :regtest)
               "address")
              "a bare pubkey has no address")))

(test rpc-decodescript-reports-the-anchor-address
  "rpc_decodescript.py:189-198: the P2A output is `1 29518\' and its address is
bcrt1pfeesnyr2tx. We reported neither -- no address at all, and a P2SH wrapper
Core refuses to print."
  (let ((result (%decodescript "51024e73" :network :regtest)))
    (is (string= "anchor" (%decodescript-field result "type")))
    (is (string= "1 29518" (%decodescript-field result "asm")))
    (is (string= "bcrt1pfeesnyr2tx" (%decodescript-field result "address")))))

(test rpc-decodescript-segwit-address-uses-chain-hrp
  "The bech32 addresses decodescript reports carry the CHAIN's HRP (Core
chainparams bech32_hrp): bcrt on regtest, tb on the test chains. The first
version hard-coded tb for testnet3 and bc for everything else, so a regtest
node printed mainnet addresses."
  (flet ((address (network)
           (%decodescript-field
            (%decodescript "001489abcdefabbaabbaabbaabbaabbaabbaabbaabba"
                           :network network)
            "address")))
    (is (uiop:string-prefix-p "bcrt1" (address :regtest)))
    (is (uiop:string-prefix-p "tb1" (address :testnet4)))
    (is (uiop:string-prefix-p "bc1" (address :mainnet)))))

(test rpc-decodescript-empty
  "An empty script is valid and is not special-cased: it classifies as
nonstandard, so Core wraps it like any other nonstandard script."
  (let ((result (%decodescript "" :network :regtest)))
    (is (string= (%decodescript-field result "type") "nonstandard"))
    (is (string= (%decodescript-field result "asm") ""))
    (is (string= "raw()#58lrscpx" (%decodescript-field result "desc")))
    (is-true (%decodescript-field result "p2sh"))
    (is-true (%decodescript-field result "segwit"))))

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

(defparameter +crt-txid+
  "0000000000000000000000000000000000000000000000000000000000000001"
  "A syntactically valid outpoint hash for the createrawtransaction vectors.")

(defun create-raw-tx (&rest params)
  "createrawtransaction over the wire: PARAMS positionally, through the
dispatcher and the request normalizer, so an empty array arrives as the
sentinel and an explicit false as the false one."
  (bl.rpc:dispatch-rpc-method
   (make-test-node :network :regtest) "createrawtransaction"
   (wire-params params)))

(defun crt-one-input (&key (sequence nil sequence-p))
  (list (append (list (cons "txid" +crt-txid+) (cons "vout" 0))
                (when sequence-p (list (cons "sequence" sequence))))))

(defparameter +crt-data-output+ (list (cons "data" "00010203")))

(defun crt-sequences (hex)
  "The nSequence of every input of the transaction HEX encodes."
  (map 'list #'bl.ser:tx-in-sequence
       (bl.ser:transaction-inputs (bl.rpc:decode-hex-tx hex))))

(defun crt-version (hex)
  (bl.ser:transaction-version (bl.rpc:decode-hex-tx hex)))

(test rpc-createrawtransaction-replaceable-defaults-to-true
  "AddInputs computes nSequence as MAX_BIP125_RBF_SEQUENCE whenever
`rbf.value_or(true)' (rpc/rawtransaction_util.cpp:47-56), and
createrawtransaction leaves rbf as std::nullopt when the argument is absent --
so 0xfffffffd is the DEFAULT. Only an explicit false falls through to
0xfffffffe when a locktime is set, else 0xffffffff.

Every one of these was 0xffffffff, which is the sharp end: an all-final
transaction makes its own nLockTime unenforceable, so a caller who asked for a
timelocked transaction got one that can be mined immediately -- with the
locktime present in the serialization, which is what made it convincing."
  (is (equal '(#xfffffffd) (crt-sequences
                            (create-raw-tx (crt-one-input) +crt-data-output+))))
  (is (equal '(#xfffffffd) (crt-sequences
                            (create-raw-tx (crt-one-input) +crt-data-output+ 500))))
  (is (equal '(#xfffffffd) (crt-sequences
                            (create-raw-tx (crt-one-input) +crt-data-output+ 0 t))))
  ;; Explicit false, no locktime: final.
  (is (equal '(#xffffffff)
             (crt-sequences (create-raw-tx (crt-one-input) +crt-data-output+ 0
                                           bl.rpc:+json-false+))))
  ;; Explicit false WITH a locktime: non-final, so the locktime still bites.
  (let ((hex (create-raw-tx (crt-one-input) +crt-data-output+ 500
                            bl.rpc:+json-false+)))
    (is (equal '(#xfffffffe) (crt-sequences hex)))
    (is (= 500 (bl.ser:transaction-lock-time (bl.rpc:decode-hex-tx hex)))))
  ;; A sequence named in the input object still wins (Core :57-66).
  (is (equal '(#x12345678)
             (crt-sequences (create-raw-tx (crt-one-input :sequence #x12345678)
                                           +crt-data-output+))))
  ;; The out-of-range cases are RPC-CREATERAWTRANSACTION-SEQUENCE-RANGE below.
  (signals bl.rpc:rpc-error
    (create-raw-tx (crt-one-input :sequence #x100000000) +crt-data-output+)))

(test rpc-createrawtransaction-sequence-range
  "GA11 ce1283b3. Core's AddInputs reads a per-input sequence only when it
isNum(), widens it to int64_t and refuses anything outside
[0, CTxIn::SEQUENCE_FINAL] with \"Invalid parameter, sequence number is out of
range\" BEFORE it builds the CTxIn (rawtransaction_util.cpp:57-66).

Without that check the value reached (make-tx-in :sequence ...), whose slot is
declared (unsigned-byte 32), and the raw SB-KERNEL::TYPE-ERROR came out of the
request boundary as -32603 \"Internal error\" -- a caller's out-of-range
argument reported as a node fault. The rows are rpc_rawtransaction.py:276-289
verbatim, both rejections and both round-trips."
  (dolist (invalid '(-1 4294967296))
    (is (equal (cons -8 "Invalid parameter, sequence number is out of range")
               (rpc-error-of
                (lambda ()
                  (create-raw-tx (crt-one-input :sequence invalid)
                                 +crt-data-output+))))
        "sequence ~D was not refused the way Core refuses it" invalid))
  (dolist (valid '(1000 4294967294))
    (is (equal (list valid)
               (crt-sequences (create-raw-tx (crt-one-input :sequence valid)
                                             +crt-data-output+)))
        "sequence ~D did not round-trip" valid))
  ;; A non-integer sequence is not a Lisp type error either.
  (is (equal (cons -8 "Invalid parameter, sequence number is out of range")
             (rpc-error-of
              (lambda ()
                (create-raw-tx (crt-one-input :sequence "foo")
                               +crt-data-output+))))))

(test createrawtransaction-inputs-entry-is-read-as-an-object-first
  "Core's AddInputs reads each `inputs' entry through input.get_obj()
(rawtransaction_util.cpp:37) BEFORE it looks for any key, so an entry that is
not an object is UniValue's own type error naming the type it got:
rpc_rawtransaction.py:267 asks createrawtransaction([\"foo\"], {}) for `JSON
value of type string is not of expected type object'.

Ours went straight to the key lookup, which answers nothing for a string, so
the diagnostic blamed the missing txid and reported the type of THAT -- `JSON
value of type null is not of expected type string', which is the answer Core
gives one line later (:268) for an entry that IS an object and simply has no
txid. Both rows are asserted here: the second is the control that the new gate
did not swallow the case it must let through."
  (is (equal (cons -3 "JSON value of type string is not of expected type object")
             (rpc-error-of (lambda () (create-raw-tx (list "foo") +crt-data-output+)))))
  (is (equal (cons -3 "JSON value of type number is not of expected type object")
             (rpc-error-of (lambda () (create-raw-tx (list 7) +crt-data-output+)))))
  (is (equal (cons -3 "JSON value of type null is not of expected type string")
             (rpc-error-of
              (lambda ()
                (create-raw-tx (list (make-hash-table :test 'equal))
                               +crt-data-output+)))))
  ;; And a well-formed entry still builds the transaction.
  (is (equal '(#xfffffffd)
             (crt-sequences (create-raw-tx (crt-one-input) +crt-data-output+)))))

(test rpc-createrawtransaction-takes-a-version
  "ConstructTransaction takes a version, defaulting to DEFAULT_RAWTX_VERSION =
2 and refused outside TX_MIN_STANDARD_VERSION..TX_MAX_STANDARD_VERSION = 1..3
(rawtransaction_util.cpp:157-161, policy.h:151-152). The argument was
discarded, so a caller asking for version 3 (TRUC, with materially different
relay policy) was handed a v2 transaction and told nothing."
  (is (= 2 (crt-version (create-raw-tx (crt-one-input) +crt-data-output+))))
  (is (= 1 (crt-version (create-raw-tx (crt-one-input) +crt-data-output+ 0 nil 1))))
  (is (= 3 (crt-version (create-raw-tx (crt-one-input) +crt-data-output+ 0 nil 3))))
  (dolist (bad '(0 4 99 -1))
    (let ((e (handler-case
                 (progn (create-raw-tx (crt-one-input) +crt-data-output+ 0 nil bad) nil)
               (bl.rpc:rpc-error (e) e))))
      (is-true e "version ~D accepted" bad)
      (when e
        (is (= -8 (bl.rpc:rpc-error-code e)))
        (is (string= "Invalid parameter, version out of range(1~3)"
                     (bl.rpc:rpc-error-message e))
            "version ~D: wrong message" bad)))))

(test rpc-createrawtransaction-refuses-contradicting-sequences
  "ConstructTransaction's last check (:167-169): an EXPLICIT replaceable=true
whose supplied sequences do not signal opt-in is a contradiction, not a silent
override. This is the reason Core keeps rbf as an optional rather than a bool."
  (let ((e (handler-case
               (progn (create-raw-tx (crt-one-input :sequence #xffffffff)
                                     +crt-data-output+ 0 t)
                      nil)
             (bl.rpc:rpc-error (e) e))))
    (is-true e "a final sequence with replaceable=true was accepted")
    (when e
      (is (= -8 (bl.rpc:rpc-error-code e)))
      (is (string= "Invalid parameter combination: Sequence number(s) contradict replaceable option"
                   (bl.rpc:rpc-error-message e)))))
  ;; Not an error when replaceable was merely OMITTED, which is the whole
  ;; point of the optional -- and not an error for a signalling sequence.
  (is (equal '(#xffffffff)
             (crt-sequences (create-raw-tx (crt-one-input :sequence #xffffffff)
                                           +crt-data-output+))))
  (is (equal '(#xfffffffd)
             (crt-sequences (create-raw-tx (crt-one-input :sequence #xfffffffd)
                                           +crt-data-output+ 0 t)))))

(test rpc-createrawtransaction-accepts-zero-inputs
  "AddInputs treats a null or empty inputs array as zero inputs and loops zero
times (rawtransaction_util.cpp:25-33); ConstructTransaction imposes no minimum.
createrawtransaction([], {...}) is the standard way to build an unsigned
funding template and appears at 33 call sites across Core's functional tests.
The handler opened with a length check, so BOTH spellings were a hard -8
`Invalid inputs' -- and because the check ran before the outputs were parsed,
every outputs diagnostic rpc_rawtransaction.py:293-302 drives through an empty
inputs array answered that same wrong message."
  (let ((hex (create-raw-tx #() +crt-data-output+)))
    (is (= 0 (length (bl.ser:transaction-inputs (bl.rpc:decode-hex-tx hex)))))
    (is (= 1 (length (bl.ser:transaction-outputs (bl.rpc:decode-hex-tx hex))))))
  ;; A null is NOT the empty array over the wire: `inputs\' is
  ;; RPCArg::Optional::NO (rawtransaction.cpp:90), so Core\'s MatchesType
  ;; refuses a null there before AddInputs -- whose own null branch is
  ;; reachable only from C++ callers -- and answers the same -3 as any other
  ;; wrong type.
  (let ((e (handler-case (progn (create-raw-tx nil +crt-data-output+) nil)
             (bl.rpc:rpc-error (e) e))))
    (is-true e "an explicit null inputs array was accepted")
    (when e (is (= -3 (bl.rpc:rpc-error-code e)))))
  ;; Anything that is not an array is Core's -3 type error.
  (dolist (bad (list "nope" 7))
    (let ((e (handler-case (progn (create-raw-tx bad +crt-data-output+) nil)
               (bl.rpc:rpc-error (e) e))))
      (is-true e "~S accepted as an inputs array" bad)
      (when e (is (= -3 (bl.rpc:rpc-error-code e))))))
  ;; The outputs diagnostics, now reachable (rpc_rawtransaction.py:293-302).
  (flet ((outputs-error (outputs)
           (handler-case (progn (create-raw-tx #() outputs) nil)
             (bl.rpc:rpc-error (e) (bl.rpc:rpc-error-message e)))))
    (is (string= "Data must be hexadecimal string (not 'zz')"
                 (outputs-error (list (cons "data" "zz")))))
    (is (string= "Invalid Bitcoin address: nosuchaddress"
                 (outputs-error (list (cons "nosuchaddress" 1)))))
    (is (string= "Amount out of range"
                 (outputs-error (list (cons "mp52VuXfTKhzYpuR3jLvPEYYUCWt84J7D5" -1)))))
    (is (string= "Invalid parameter, duplicated address: mp52VuXfTKhzYpuR3jLvPEYYUCWt84J7D5"
                 (outputs-error
                  (list (list (cons "mp52VuXfTKhzYpuR3jLvPEYYUCWt84J7D5" 1))
                        (list (cons "mp52VuXfTKhzYpuR3jLvPEYYUCWt84J7D5" 1))))))))

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
    (is (= (btc-amount (cdr (assoc "total_amount" result :test #'string=))) 0))
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
      (is (= (btc-amount (cdr (assoc "total_amount" result :test #'string=))) 7/4))
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
                          (bl.rpc:dispatch-rpc-method node "getmempoolinfo" nil)))
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
         (result (%testmempoolaccept node (list hex))))
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
         (parent (make-spending-test-tx funding :vout 0 :value 50000000))
         (pid (bl.ser:transaction-hash parent))
         (child (make-spending-test-tx pid :vout 0 :value 40000000))
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

(test rpc-gettxspendingprevout-objects-are-closed-sets
  "gettxspendingprevout refuses a key nobody asked for, in both of its object
arguments. Core runs RPCTypeCheckObj with fStrict over the options object
(rpc/mempool.cpp:944-949) and over EACH {txid, vout} entry
(rpc/mempool.cpp:964-968), so an unexpected key is -3 `Unexpected key <k>' and
a txid given as a number is -3 `JSON value of type number for field txid is
not of expected type string' -- the entry check runs before ParseHashO, which
is why the type error is the one reported. We accepted both silently
(rpc_gettxspendingprevout.py:111)."
  (let* ((node (make-test-node))
         (txid-hex (bl.rpc:hash-to-hex (%txid-array 99))))
    (flet ((obj (&rest kvs)
             (let ((h (make-hash-table :test 'equal)))
               (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v))
               h)))
      ;; Control: the well-formed call answers, so a rejection below is the
      ;; strict check and not a broken fixture.
      (is (= 1 (length (bl.rpc:dispatch-rpc-method
                        node "gettxspendingprevout" (list (list (obj "txid" txid-hex "vout" 0)))))))
      (signals-rpc-error (:code -3 :exact-message "Unexpected key unknown")
        (bl.rpc:dispatch-rpc-method
         node "gettxspendingprevout" (list (list (obj "txid" txid-hex "vout" 1 "unknown" 42)))))
      (signals-rpc-error
          (:code -3 :exact-message
           "JSON value of type number for field txid is not of expected type string")
        (bl.rpc:dispatch-rpc-method
         node "gettxspendingprevout" (list (list (obj "txid" 42 "vout" 0)))))
      (signals-rpc-error (:code -3 :exact-message "Missing vout")
        (bl.rpc:dispatch-rpc-method
         node "gettxspendingprevout" (list (list (obj "txid" txid-hex)))))
      ;; The options object is strict too, and null-tolerant: an absent
      ;; mempool_only is fine, an unknown one is not.
      (is (= 1 (length (bl.rpc:dispatch-rpc-method
                        node "gettxspendingprevout" (list (list (obj "txid" txid-hex "vout" 0))
                                   (obj "mempool_only" t))))))
      (signals-rpc-error (:code -3 :exact-message "Unexpected key mempoolonly")
        (bl.rpc:dispatch-rpc-method
         node "gettxspendingprevout" (list (list (obj "txid" txid-hex "vout" 0))
                    (obj "mempoolonly" t)))))))

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
  "invalidateblock / reconsiderblock / preciousblock all look the hash up in
the block index first and answer RPC_INVALID_ADDRESS_OR_KEY `Block not found'
when it is not there (rpc/blockchain.cpp:1679, :1702, :1746); every other
failure is RPC_DATABASE_ERROR carrying the validation state's string (:1687,
:1713, :1758). Ours answered -1 with the reason keyword downcased, so an
unknown block came back as -1 `block-not-found' where
rpc_invalidateblock.py:140 asks for -5 `Block not found'. A malformed hash is
ParseHashV's -8, before the lookup."
  (let ((node (make-test-node))
        (unknown "00000000000000000000000000000000000000000000000000000000deadbeef"))
    (dolist (method '("invalidateblock" "reconsiderblock" "preciousblock"))
      (is (equal (cons -5 "Block not found")
                 (%rpc-wire-error node method (list unknown)))
          "~A on an unknown hash is Core's -5 Block not found" method)
      ;; Control: a malformed hash never reaches the index lookup.
      (is (equal -8 (car (%rpc-wire-error node method (list "not-a-hash"))))
          "~A on a malformed hash is still ParseHashV's -8" method))))

;;; --- setban / listbanned / clearbanned / getnettotals / verifychain ---

(test rpc-setban-add-list-remove-clear
  "setban add/remove + listbanned + clearbanned manage the manual ban list."
  (bl.net:clear-ban-list)
  (let ((node (make-test-node)))
    (is (null (call-setban node (list "1.2.3.4" "add"))))
    (is-true (bl.net:peer-banned-p "1.2.3.4"))
    (let ((banned (call-listbanned node)))
      (is (= 1 (length banned)))
      ;; Core lists the CSubNet, so a bare address appears as its /32.
      (is (string= "1.2.3.4/32" (cdr (assoc "address" (first banned) :test #'string=))))
      (is (integerp (cdr (assoc "banned_until" (first banned) :test #'string=)))))
    (is (null (call-setban node (list "1.2.3.4" "remove"))))
    (is (not (bl.net:peer-banned-p "1.2.3.4")))
    ;; remove a non-existent ban / bad command -> error
    (signals bl.rpc:rpc-error
      (call-setban node (list "9.9.9.9" "remove")))
    (signals bl.rpc:rpc-error
      (call-setban node (list "1.2.3.4" "bogus")))
    ;; clearbanned empties the list
    (call-setban node (list "5.6.7.8" "add"))
    (is (null (call-clearbanned node)))
    (is (= 0 (length (call-listbanned node))))))

(test disconnectnode-matches-the-address-getpeerinfo-printed
  "Core's DisconnectNode(string) matches CNode::m_addr_name
(net.cpp:3809-3820), which for an accepted connection is the same
\"ip:port\" getpeerinfo reports as `addr'. That round trip is the whole API:
p2p_disconnect_ban.py:131-133 reads getpeerinfo()[0]['addr'] and hands it
straight back to disconnectnode. Ours compared the bare HOST, so the address
it had just printed came back -29 `Node not found in connected nodes'.

The bare host keeps working -- it is what this node's own UI passes -- and
the control is that a string matching neither is still -29."
  (let* ((node (make-test-node))
         (srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
           (let* ((port (usocket:get-local-port srv))
                  (client (usocket:socket-connect "127.0.0.1" port
                                                  :element-type '(unsigned-byte 8)))
                  (conn (bl.net::make-connection
                         :socket client :host "127.0.0.1" :port port :connected t))
                  (peer (bl.net:make-peer :address "127.0.0.1" :state :ready
                                          :connection conn)))
             (setf (bl:node-peers node) (list peer))
             (let ((printed (cdr (assoc "addr" (first (bl.rpc::rpc-getpeerinfo node nil))
                                        :test #'string=))))
               (is-true (search ":" printed)
                        "getpeerinfo prints ip:port, as Core's does")
               ;; A string matching neither form is Core's -29.
               (signals bl.rpc:rpc-error
                 (bl.rpc::rpc-disconnectnode node (list "221B Baker Street" nil)))
               ;; The printed address finds the peer.
               (is (null (bl.rpc::rpc-disconnectnode node (list printed nil))))
               (is (eq :disconnected (bl.net:peer-state peer))))
             (ignore-errors (usocket:socket-close client)))
        (bl.net:close-listener srv)))))

(test rpc-setban-bans-a-subnet-and-reports-its-duration
  "Two things rpc_setban.py and p2p_disconnect_ban.py ask for that the ban list
could not answer while it was a flat address -> expiry map.

SUBNETS: Core's ban list is keyed by CSubNet (banman.h:60), so `-setban
127.0.0.0/24' is one entry that COVERS 127.0.0.1 -- IsBanned(CNetAddr) walks
every range (banman.cpp:89-102) -- while Unban is an exact erase of the range
(:144-152) and re-banning a covered ADDRESS is refused with -23
(p2p_disconnect_ban.py:52). Ours refused subnet syntax outright.

BAN_DURATION: Core's CBanEntry keeps the CREATION time and listbanned reports
banned_until - created (rpc/net.cpp:854-858). Ours wrote a hardcoded 0 for the
creation time, so the field could not exist; rpc_setban.py:75 restarts with
-bantime=1234 and reads it back."
  (bl.net:clear-ban-list)
  (let ((node (make-test-node)))
    (is (null (call-setban node (list "127.0.0.0/24" "add" 1234))))
    (let ((banned (call-listbanned node)))
      (is (= 1 (length banned)))
      (is (string= "127.0.0.0/24"
                   (cdr (assoc "address" (first banned) :test #'string=))))
      (is (= 1234 (cdr (assoc "ban_duration" (first banned) :test #'string=))))
      (is (<= 0 (cdr (assoc "time_remaining" (first banned) :test #'string=)) 1234)))
    ;; The range covers every address in it...
    (is-true (bl.net:peer-banned-p "127.0.0.1"))
    (is-true (bl.net:peer-banned-p "127.0.0.255"))
    ;; ...and nothing outside it (the control: /24, not /16).
    (is-false (bl.net:peer-banned-p "127.0.1.1"))
    ;; Re-banning a COVERED address is Core's -23, because setban asks
    ;; IsBanned(CNetAddr) for an argument with no slash.
    (signals bl.rpc:rpc-error (call-setban node (list "127.0.0.1" "add")))
    ;; A narrower range is a DIFFERENT entry, so it is not already banned.
    (is (null (call-setban node (list "127.0.0.0/25" "add"))))
    (is (= 2 (length (call-listbanned node))))
    ;; Unban is exact: the covered address was never its own entry.
    (signals bl.rpc:rpc-error (call-setban node (list "127.0.0.1" "remove")))
    (is (null (call-setban node (list "127.0.0.0/24" "remove"))))
    (is (= 1 (length (call-listbanned node))))
    ;; An unparseable range is still -30.
    (signals bl.rpc:rpc-error (call-setban node (list "127.0.0.0/33" "add")))
    ;; Core's m_banned is a std::map keyed by CSubNet, so listbanned comes out
    ;; in CSubNet order -- network first, then address, then netmask
    ;; (netaddress.cpp:1090-1093, :608-611). p2p_disconnect_ban.py:83 reads a
    ;; row BY INDEX, so an unordered list fails on the wrong entry.
    (bl.net:clear-ban-list)
    (dolist (spec '("127.0.0.0/32" "127.0.0.0/24"
                    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
                    "192.168.0.1"))
      (call-setban node (list spec "add")))
    (is (equal '("127.0.0.0/24" "127.0.0.0/32" "192.168.0.1/32"
                 "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion")
               (mapcar (lambda (row) (cdr (assoc "address" row :test #'string=)))
                       (call-listbanned node)))
        "IPv4 before onion, and the wider netmask before the narrower")
    (bl.net:clear-ban-list)))

(test rpc-setban-absolute-bantime
  "setban add with absolute=true sets banned_until to the given Unix time."
  (bl.net:clear-ban-list)
  (let ((node (make-test-node))
        (future (+ (bl.ser:get-unix-time) 3600)))
    (call-setban node (list "10.0.0.1" "add" future t))
    (let ((banned (call-listbanned node)))
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
    (is (null (call-setban node (list "203.0.113.9" "add"))))
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

(test rpc-verifychain-empty-node-returns-true
  "verifychain on a node with no stored blocks returns a bare boolean, never
null -- and the boolean is TRUE: Core's VerifyDB short-circuits to SUCCESS
when the chain has no tip or the tip is genesis (validation.cpp:4651), so
there is nothing to disagree about. The false answers this RPC can give are
pinned in :verifydb-tests, over a chainstate that really does disagree with
its blocks."
  (is (eq t (bl.rpc::rpc-verifychain (make-test-node) (list 0 1)))))

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
      (bl.rpc:parse-json-rpc-request
       "{\"jsonrpc\":\"1.0\",\"method\":\"getblockcount\",\"params\":[],\"id\":1}")
    (is (eq :single kind))
    (is (string= "getblockcount" method)))
  (multiple-value-bind (kind method)
      (bl.rpc:parse-json-rpc-request "{\"method\":\"uptime\",\"id\":1}")
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
               (is (%authorized-user (%basic-auth-header cookie)))
               (is (not (%authorized-user
                         (%basic-auth-header "__cookie__:bad"))))
               (is (not (%authorized-user (%basic-auth-header "u:p")))))
             ;; shutdown removes the cookie it generated (Core DeleteAuthCookie)
             (bl.rpc:stop-rpc-server)
             (is (null (probe-file cookie-file)))
             ;; (b) rpcuser/rpcpassword: that pair is the credential, no cookie
             ;; is written, and the cookie user is not a way in
             (is (not (null (bl.rpc:start-rpc-server
                             node :port 19994 :user "u" :password "p"))))
             (is (null (probe-file cookie-file)))
             (is (%authorized-user (%basic-auth-header "u:p")))
             (is (not (%authorized-user (%basic-auth-header "u:wrong"))))
             (is (not (%authorized-user
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
        (ignore-errors (delete-file (merge-pathnames ".cookie" dir))))
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
               (is (%authorized-user (%basic-auth-header live-cookie)))
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
                 (is (%authorized-user (%basic-auth-header live-cookie)))
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
a single -rpcbind would put the whole RPC surface on the public internet.

The fallback is BOTH loopback addresses, ::1 first and then 127.0.0.1
(httpserver.cpp:320-321). Binding only the IPv4 one, as this node did, leaves a
client that resolves `localhost' to ::1 unable to reach a node that is running:
rpc_bind.py:46 compares the process's bound sockets against the pair."
  (flet ((binds (bind allow-ip &optional supplied-p)
           (bl.rpc::%rpc-bind-addresses bind allow-ip supplied-p)))
    ;; A loopback bind the operator ASKED for is used as given, whatever
    ;; -rpcallowip says.
    (dolist (loopback '("127.0.0.1" "127.0.0.2" "::1" "[::1]" "localhost"))
      (dolist (allow-ip '(nil ("10.0.0.0/8")))
        (is (equal (list loopback) (binds loopback allow-ip t))
            "~S is loopback and must be kept (allow-ip ~S)" loopback allow-ip)))
    ;; No -rpcbind at all: the default pair, in Core's order.
    (is (equal '("::1" "127.0.0.1") (binds "127.0.0.1" nil)))
    (is (equal '("::1" "127.0.0.1") (binds "127.0.0.1" '("10.0.0.0/8"))))
    (is (equal '("::1" "127.0.0.1") (binds nil nil)))
    ;; A non-loopback bind with no -rpcallowip is ignored, and the fallback is
    ;; the same pair -- not the address that was asked for.
    (dolist (exposed '("0.0.0.0" "" "192.168.1.5" "::" "1.2.3.4" "127acme.example"))
      (is (equal '("::1" "127.0.0.1") (binds exposed nil t))
          "~S is not loopback and must fall back" exposed))
    ;; with -rpcallowip the operator's address is used as given
    (is (equal '("10.0.0.5") (binds "10.0.0.5" '("10.0.0.0/8") t)))
    (is (equal '("0.0.0.0") (binds "0.0.0.0" '("0.0.0.0/0") t)))))

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
  ;; A known method answers with its document, which opens on its usage line
  ;; (Core RPCHelpMan::ToString); an unknown one reports so.
  (is (eql 0 (search (format nil "uptime~%~%") (bl.rpc::rpc-help nil (list "uptime")))))
  (is (search "unknown" (bl.rpc::rpc-help nil (list "nope-xyz")))))

(test rpc-getmemoryinfo-and-getrpcinfo-shape
  "getmemoryinfo reports the heap under \"locked\"; getrpcinfo reports
active_commands + logpath."
  (let ((mi (%getmemoryinfo nil)))
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

(test rpc-decodescript-bare-multisig
  "Bare multisig, the whole object Core prints (rpc_decodescript.py:88-99):
the asm with its m and n as DECIMALS, type multisig, no address (multisig has
no destination), and the P2WSH translation. This test asserted the pre-v22
reqSigs / addresses pair, which Core removed."
  (let* ((pk1 "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
         (pk2 "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
         (hex (concatenate 'string "52" "21" pk1 "21" pk2 "52ae"))
         (r (%decodescript hex :network :regtest)))
    (is (string= "multisig" (%decodescript-field r "type")))
    (is (string= (format nil "2 ~A ~A 2 OP_CHECKMULTISIG" pk1 pk2)
                 (%decodescript-field r "asm")))
    (is-false (%decodescript-field r "address") "multisig has no destination")
    (is (string= "witness_v0_scripthash"
                 (%decodescript-field
                  (%decodescript-field r "segwit") "type")))))

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
    ;; Amounts, so number TOKENS carrying Core's ValueFromAmount spelling.
    (is (plusp (btc-amount (cdr (assoc "relayfee" r :test #'string=)))))
    (is (plusp (btc-amount (cdr (assoc "incrementalfee" r :test #'string=)))))
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
      ;; relaytxes is read off Peer::TxRelay, which Core only creates in the
      ;; VERSION handler (net_processing.cpp:3681-3696); this peer has sent
      ;; none, so GetNodeStateStats reports false (:1826) -- as it does for the
      ;; block-relay peer below, for the other reason. RPC-GETPEERINFO-PARITY-
      ;; FIELDS holds the true arm, on a peer that did send a version. This
      ;; asserted true until 2026-09-18, when a peer with no version first
      ;; reached getpeerinfo (it is published at accept now, rpc_net.py:137).
      (is (eq 'yason:false (cdr (assoc "relaytxes" e :test #'string=))))
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
    (setf (bl:node-peers node)
          ;; Two peers, because `network' is a classification and one address
          ;; exercises one arm of it: 203.0.113.0/24 is RFC5737 documentation
          ;; space, which Core's GetNetClass calls NET_UNROUTABLE, while
          ;; 8.8.8.8 is the ipv4 arm. This asserted "ipv4" for the
          ;; documentation address until 2026-09-18, because the renderer asked
          ;; addrman's DIAL predicate -- which keeps those ranges routable for
          ;; regtest on purpose -- rather than Core's routability.
          (list peer (bl.net:make-peer :address "8.8.8.8" :state :ready)))
    (let* ((rows (bl.rpc::rpc-getpeerinfo node nil))
           (row-for (lambda (addr)
                      (find addr rows :test #'search
                            :key (lambda (r)
                                   (cdr (assoc "addr" r :test #'string=))))))
           (e (funcall row-for "203.0.113.5"))
           (f (lambda (k) (cdr (assoc k e :test #'string=)))))
      (is (string= "not_publicly_routable" (funcall f "network"))
          "RFC5737 documentation space is not a publicly routable network")
      (is (string= "ipv4"
                   (cdr (assoc "network" (funcall row-for "8.8.8.8")
                               :test #'string=)))
          "control: a globally routable address is still ipv4")
      (is (equalp #("NETWORK" "WITNESS" "NETWORK_LIMITED")
                  (funcall f "servicesnames")))
      ;; ping stats in seconds, all present here.
      (is (= 1.0d0 (funcall f "pingtime")))
      (is (= 0.5d0 (funcall f "minping")))
      (is (numberp (funcall f "pingwait")))
      ;; feefilter: 1000 sat/kvB -> BTC/kvB.
      (is (= 1/100000 (btc-amount (funcall f "minfeefilter"))))
      ;; timeoffset captured at version receipt; conntime a plausible unix time.
      (is (= -3 (funcall f "timeoffset")))
      (is (> (funcall f "conntime") 1600000000))
      ;; lastsend reflects the connection stamp; lastrecv never happened.
      (is (> (funcall f "lastsend") 1600000000))
      (is (= 0 (funcall f "lastrecv")))
      (is (= 0 (funcall f "last_transaction")))
      (is (= 0 (funcall f "last_block")))
      ;; inv queue counters, and the true arm of relaytxes: this peer DID send
      ;; a version whose fRelay is set, so it has a Peer::TxRelay and all three
      ;; report the peer's own values rather than Core's no-object zeroes.
      (is (eq t (funcall f "relaytxes")))
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
    ;; Malformed base64 is an ERROR in Core, not a false result, and its code
    ;; is RPC_TYPE_ERROR: ERR_MALFORMED_SIGNATURE is grouped with
    ;; ERR_ADDRESS_NO_KEY and not with the undecodable address
    ;; (rpc/signmessage.cpp:41-57). We answered -5
    ;; (rpc_signmessagewithprivkey.py:59).
    (signals-rpc-error (:code -3 :exact-message "Malformed base64 encoding")
      (bl.rpc:dispatch-rpc-method node "verifymessage"
                                  (list addr "not-a-valid-sig" msg)))))

(test rpc-verifymessage-p2sh-address-is-not-a-key
  "verifymessage refuses a P2SH address with Core's -3 `Address does not refer
to key' instead of answering false. Core's MessageVerify asks DecodeDestination
for a PKHash and a script hash is not one (common/signmessage.cpp:57-68); a
P2SH address base58-decodes to the same TWENTY bytes a P2PKH address does, so
checking only the payload LENGTH let sh(wpkh(K)) reach the verify path and
compare the script hash against the recovered key's hash160
(rpc_signmessagewithprivkey.py:44)."
  (let* ((node (make-test-node))   ; testnet3
         (k1 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 7) k))
         (wif (bl.crypto:private-key-to-wif k1 :network :mainnet :compressed t))
         (msg "This is just a test message")
         (pub (bl.crypto:derive-public-key k1))
         (p2pkh (bl.crypto:encode-p2pkh-address (bl.crypto:hash160 pub) :testnet3))
         ;; sh(wpkh(K)): the P2SH address of the key's P2WPKH redeemScript.
         (redeem (concatenate '(vector (unsigned-byte 8))
                              #(#x00 #x14) (bl.crypto:hash160 pub)))
         (p2sh (bl.crypto:encode-p2sh-address (bl.crypto:hash160 redeem) :testnet3))
         (sig (bl.rpc:rpc-signmessagewithprivkey node (list wif msg))))
    ;; Control: the SAME key's P2PKH address still verifies true.
    (is (eq t (bl.rpc:dispatch-rpc-method node "verifymessage" (list p2pkh sig msg))))
    (signals-rpc-error (:code -3 :exact-message "Address does not refer to key")
      (bl.rpc:dispatch-rpc-method node "verifymessage" (list p2sh sig msg)))))

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

(test rpc-signrawtransactionwithkey-bare-p2pk
  "signrawtransactionwithkey signs a BARE P2PK input (input 0) from the supplied
WIF, with a P2PKH input of the SAME key (input 1) alongside as the control that
would fail with it. Core answers TxoutType::PUBKEY as SignStep's first case
(sign.cpp:643-647): the scriptPubKey already carries the key, so the scriptSig is
the signature ALONE where P2PKH's is the signature and the key.

The control is what stops a regression passing vacuously: before this arm
existed the SAME call returned complete=false with \"unsupported scriptPubKey
type pubkey\" for input 0 while input 1 signed, so the two halves disagreeing is
the whole finding."
  (let* ((node (make-test-node))
         (k1 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bl.crypto:private-key-to-wif k1 :network :mainnet :compressed t))
         (pub (bl.crypto:derive-public-key k1))
         (pkh (bl.crypto:hash160 pub))
         (p2pk (concatenate '(vector (unsigned-byte 8))
                            (vector (length pub)) pub (vector #xac)))
         (p2pkh (concatenate '(vector (unsigned-byte 8))
                             (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 20))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21))
         (empty (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint :hash txid0 :index 0)
                               :script-sig empty :sequence #xffffffff)
                              (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint :hash txid1 :index 0)
                               :script-sig empty :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out :value 90000 :script-pubkey p2pkh))
              :lock-time 0))
         (prevtxs (list (list (cons "txid" (bl.rpc:hash-to-hex txid0))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex p2pk)))
                        (list (cons "txid" (bl.rpc:hash-to-hex txid1))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex p2pkh)))))
         (result (bl.rpc:dispatch-rpc-method
                  node "signrawtransactionwithkey"
                  (list (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx))
                        (list wif) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=)))
        "signer reported ~S" (cdr (assoc "errors" result :test #'string=)))
    (let* ((tx2 (bl.ser:parse-tx-payload
                 (bl.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (ins (bl.ser:transaction-inputs tx2)))
      ;; Input 0 (bare P2PK): scriptSig = push(sig), and NOTHING else.
      (let* ((ss (bl.ser:tx-in-script-sig (aref ins 0)))
             (siglen (aref ss 0))
             (sig (subseq ss 1 (1+ siglen)))
             (der (subseq sig 0 (1- (length sig))))
             (sighash (bl.interop:compute-legacy-sighash tx2 0 p2pk 1)))
        (is (= (length ss) (1+ siglen))
            "P2PK scriptSig carries ~D bytes past the signature; Core pushes the ~
signature alone" (- (length ss) 1 siglen))
        (is-true (bl.crypto:verify-signature sighash der pub)))
      ;; Input 1 (P2PKH control): scriptSig = push(sig) push(pubkey).
      (let* ((ss (bl.ser:tx-in-script-sig (aref ins 1)))
             (siglen (aref ss 0))
             (sig (subseq ss 1 (1+ siglen)))
             (der (subseq sig 0 (1- (length sig))))
             (sighash (bl.interop:compute-legacy-sighash tx2 1 p2pkh 1)))
        (is (equalp pub (subseq ss (+ 2 siglen))))
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
         (ms22 (multisig-script 2 (list pa pb)))    ; 2-of-2 A,B
         (ms11 (multisig-script 1 (list pa)))       ; 1-of-1 A
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

;;; --- Multisig signature collection vs the m-of-n cap (GA11 42a8a239) ---

(defun %p2wsh-multisig-signing (m n held-indices)
  "Sign one P2WSH bare m-of-n input whose signer holds exactly the keys at
HELD-INDICES (0-based positions in the witnessScript's pubkey order), and
report both halves of Core's SignStep split.

Returns (values ecdsa-pairs witness verified-p pubkeys): the pairs
COMPUTE-INPUT-SIGNATURES collected, the witness stack the SHIPPED
signrawtransactionwithkey assembled from them, and the consensus
interpreter's verdict on that witness -- the only evidence that a change to
either half still spends."
  (let* ((node (make-test-node))
         (sks (loop for i from 0 below n
                    collect (let ((k (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)))
                              (setf (aref k 31) (+ 11 i))
                              k)))
         (pks (mapcar #'bl.crypto:derive-public-key sks))
         (witscript (multisig-script m pks))
         (spk (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x20)
                           (bl.crypto:sha256 witscript)))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #xC3))
         (amount 100000)
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash prev-txid :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out :value 90000 :script-pubkey spk))
              :lock-time 0))
         (pubmap (make-hash-table :test 'equalp))
         (pairs nil))
    (dolist (i held-indices)
      (setf (gethash (nth i pks) pubmap) (nth i sks)))
    ;; The collection half, read straight off the input-sig.
    (let ((bl.interop:*current-tx* tx))
      (multiple-value-bind (sig err)
          (bl.rpc:compute-input-signatures
           tx 0 (list spk amount nil witscript)
           (make-hash-table :test 'equalp) pubmap
           (make-hash-table :test 'equalp) #x01 nil nil)
        (when err (error "compute-input-signatures: ~A" err))
        (setf pairs (bl.rpc:input-sig-ecdsa sig))))
    ;; The assembly half, through the shipped RPC.
    (let* ((result (bl.rpc:dispatch-rpc-method
                    node "signrawtransactionwithkey"
                    (list (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx))
                          (loop for i in held-indices
                                collect (bl.crypto:private-key-to-wif
                                         (nth i sks) :network :mainnet :compressed t))
                          (list (list (cons "txid" (bl.rpc:hash-to-hex prev-txid))
                                      (cons "vout" 0)
                                      (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk))
                                      (cons "amount" (/ amount 1d8))
                                      (cons "witnessScript"
                                            (bl.crypto:bytes-to-hex witscript)))))))
           (errors (cdr (assoc "errors" result :test #'string=)))
           (signed (bl.ser:parse-tx-payload
                    (bl.crypto:hex-to-bytes
                     (cdr (assoc "hex" result :test #'string=)))))
           (spent (vector (bl.store:make-utxo-entry
                           :value amount
                           :script-pubkey
                           (coerce spk '(simple-array (unsigned-byte 8) (*)))))))
      (when errors
        (error "signrawtransactionwithkey: ~S" errors))
      (values pairs
              (coerce (aref (bl.ser:transaction-witness signed) 0) 'list)
              (%verify-tx-input signed 0 spent
                                "P2SH,WITNESS,NULLDUMMY,DERSIG,LOW_S")
              pks))))

(test multisig-signing-collects-every-held-key-and-pushes-only-m
  "GA11 42a8a239. Core's SignStep MULTISIG case calls CreateSig for EVERY key
in vSolutions and caps only the STACK push at required+1 (script/sign.cpp:
669-688), with the comment that it must always call CreateSig so that
sigdata carries all possible signature/pubkey pairs for further PSBT
processing. Ours stopped COLLECTING at the m-th key, so walletprocesspsbt
recorded m PSBT_IN_PARTIAL_SIG records where Core records k, and a
not-yet-finalized PSBT handed to further cosigners carried fewer spares than
Core would have put there.

The two halves are asserted separately, in Core's numbers:
  - the collection: a 2-of-3 whose signer holds ALL THREE keys yields 3 pairs;
  - the cap: the shipped signer's witness is still the CHECKMULTISIG dummy,
    exactly 2 signatures and the witnessScript, and the consensus interpreter
    accepts it.

The k = m rows are the control that the collector was never the cap: a
2-of-3 holding keys 2 and 3 (not 1) yields 2 pairs both before and after, and
its witness must still verify -- a fix that removed the cap without moving it
into the finalizer would push three signatures at a 2-of-3 and fail there."
  ;; k > m: three held keys, Core collects three.
  (multiple-value-bind (pairs witness verified pks)
      (%p2wsh-multisig-signing 2 3 '(0 1 2))
    (is (= 3 (length pairs)))
    (is (equalp (list (first pks) (second pks) (third pks))
                (mapcar #'car pairs)))
    ;; The stack is capped where Core caps it: dummy + 2 sigs + witnessScript.
    (is (= 4 (length witness)))
    (is (zerop (length (first witness))))
    (is-true verified)
    ;; And the two signatures pushed are the FIRST TWO in pubkey order, the
    ;; bytes the in-place spend path produced before the collector changed.
    (is (equalp (cdr (first pairs)) (second witness)))
    (is (equalp (cdr (second pairs)) (third witness))))
  ;; k = m, and not the first m keys: unchanged, and still spendable.
  (multiple-value-bind (pairs witness verified pks)
      (%p2wsh-multisig-signing 2 3 '(1 2))
    (is (= 2 (length pairs)))
    (is (equalp (list (second pks) (third pks)) (mapcar #'car pairs)))
    (is (= 4 (length witness)))
    (is-true verified))
  ;; k < m is still a threshold failure, reported by the shipped signer.
  (is (search "multisig needs 2 sigs, have 1"
              (handler-case (progn (%p2wsh-multisig-signing 2 3 '(0)) "no error")
                (error (e) (princ-to-string e))))))

(test multisig-signing-carries-a-cosigners-signature-through
  "Two wallets finish a 2-of-3 P2WSH between them, which is the whole point of
an m-of-n: the first pass writes what it has, the second reads it back and
completes it.

Core does this in two halves. SignTransaction runs DataFromTransaction before
ProduceSignature and calls UpdateInput with whatever came out
(script/sign.cpp:729-745), so a partially signed input is WRITTEN into the
transaction -- SignStep pads the short stack to required + 1 with empty
elements (:684-687) rather than abandoning it. And CreateSig returns a
signature already present in sigdata instead of making a new one (:559-566),
so the cosigner's work is carried through rather than replaced.

We had neither: a stack short of the threshold was discarded, so the first
pass emitted an input with no witness at all, and the second pass rebuilt
that input from nothing. A 2-of-3 could be signed by a wallet holding two
keys and by nobody else (wallet_importdescriptors.py:583)."
  (let* ((node (make-test-node))
         (sks (loop for i from 0 below 3
                    collect (let ((k (make-array 32 :element-type '(unsigned-byte 8)
                                                    :initial-element 0)))
                              (setf (aref k 31) (+ 41 i))
                              k)))
         (pks (mapcar #'bl.crypto:derive-public-key sks))
         (witscript (multisig-script 2 pks))
         (spk (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x20)
                           (bl.crypto:sha256 witscript)))
         (prev-txid (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #xD4))
         (amount 100000)
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash prev-txid :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out :value 90000 :script-pubkey spk))
              :lock-time 0))
         (prevtxs (list (list (cons "txid" (bl.rpc:hash-to-hex prev-txid))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk))
                              (cons "amount" (/ amount 1d8))
                              (cons "witnessScript" (bl.crypto:bytes-to-hex witscript)))))
         (spent (vector (bl.store:make-utxo-entry
                         :value amount
                         :script-pubkey
                         (coerce spk '(simple-array (unsigned-byte 8) (*)))))))
    (flet ((sign-with (hex index)
             (bl.rpc:dispatch-rpc-method
              node "signrawtransactionwithkey"
              (list hex
                    (list (bl.crypto:private-key-to-wif
                           (nth index sks) :network :mainnet :compressed t))
                    prevtxs)))
           (field (result name) (cdr (assoc name result :test #'string=))))
      (let* ((first-pass (sign-with (bl.crypto:bytes-to-hex
                                     (bl.ser:serialize-transaction tx))
                                    0))
             (partial-hex (field first-pass "hex"))
             (partial (bl.ser:parse-tx-payload (bl.crypto:hex-to-bytes partial-hex)))
             ;; Read defensively: with the partial input dropped there is no
             ;; witness vector at all, and the assertions below have to be
             ;; able to SAY that rather than die reading it.
             (partial-witness (let ((w (bl.ser:transaction-witness partial)))
                                (if (and w (plusp (length w)))
                                    (coerce (aref w 0) 'list)
                                    '()))))
        (is (eq 'yason:false (field first-pass "complete"))
            "one key of a 2-of-3 cannot complete it")
        ;; The partial input is in the hex, padded the way Core pads it:
        ;; dummy, the one signature, an empty placeholder, the witnessScript.
        (is (= 4 (length partial-witness))
            "the partial witness was dropped instead of written")
        (is (equal '(0 t 0 t)
                   (list (length (or (first partial-witness) #()))
                         (and (plusp (length (or (second partial-witness) #()))) t)
                         (length (or (third partial-witness) #()))
                         (and (equalp witscript (fourth partial-witness)) t)))
            "the padded stack is not dummy / signature / placeholder / script")
        ;; The second cosigner reads that signature back and finishes it.
        (let* ((second-pass (sign-with partial-hex 1))
               (signed (bl.ser:parse-tx-payload
                        (bl.crypto:hex-to-bytes (field second-pass "hex"))))
               (final (let ((w (bl.ser:transaction-witness signed)))
                        (if (and w (plusp (length w)))
                            (coerce (aref w 0) 'list)
                            '()))))
          (is (eq t (field second-pass "complete"))
              "the second key did not complete the input: ~S"
              (field second-pass "errors"))
          (is (= 4 (length final)))
          ;; The first cosigner's signature survived verbatim, in pubkey order.
          (is (equalp (second partial-witness) (second final))
              "the first signature was replaced instead of carried through")
          (is (plusp (length (or (third final) #()))))
          (is-true (%verify-tx-input signed 0 spent
                                     "P2SH,WITNESS,NULLDUMMY,DERSIG,LOW_S")
                   "the completed witness does not spend"))))))

(defun %direct-pushes (script)
  "The data elements of SCRIPT when it is nothing but direct pushes (an opcode
byte of 1..75 followed by that many bytes), which is what Core's PushAll emits
for a scriptSig of the shapes below. Signals rather than returning a short list
when a byte is not such a push, so a malformed scriptSig cannot read as a
correct one with fewer elements."
  (let ((out '()) (i 0) (n (length script)))
    (loop while (< i n)
          do (let ((len (aref script i)))
               (assert (<= 1 len 75) ()
                       "not a direct push at offset ~D of ~D: opcode ~2,'0X" i n len)
               (assert (<= (+ i 1 len) n) ()
                       "push at offset ~D runs past the end of the script" i)
               (push (subseq script (1+ i) (+ i 1 len)) out)
               (incf i (1+ len))))
    (nreverse out)))

(test rpc-signrawtransactionwithkey-p2sh-p2pk
  "signrawtransactionwithkey signs a P2SH(P2PK) input (input 0), with a
P2SH(P2PKH) input of the same key (input 1) alongside as the control that would
fail with it.

Core reaches both by ONE step: ProduceSignature answers SCRIPTHASH by taking
the redeemScript out of the first SignStep's result and calling SignStep AGAIN
on it (sign.cpp:743-752), which lands on the very PUBKEY (sign.cpp:643-647) and
PUBKEYHASH (:648-660) cases a bare script uses; the redeemScript is then
appended to the result and the whole thing pushed (:790-795). So the scriptSig
is the bare shape's pushes followed by the redeemScript: <sig> <redeem> for
P2SH-P2PK and <sig> <pubkey> <redeem> for P2SH-P2PKH, and the signature is over
the REDEEM script as the subscript, never over the scriptPubKey.

Before the redeem recursion existed this call answered complete=false with
\"Input 0: unsupported redeemScript type\" and the same for input 1 -- the P2SH
arm knew only its three segwit/multisig shapes -- so a sh(pk(K)) coin, which
importdescriptors accepts and the wallet counts, could not be spent at all."
  (let* ((node (make-test-node))
         (k1 (let ((k (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
               (setf (aref k 31) 1) k))
         (wif (bl.crypto:private-key-to-wif k1 :network :mainnet :compressed t))
         (pub (bl.crypto:derive-public-key k1))
         (pkh (bl.crypto:hash160 pub))
         (rd-pk (concatenate '(vector (unsigned-byte 8))
                             (vector (length pub)) pub (vector #xac)))
         (rd-pkh (concatenate '(vector (unsigned-byte 8))
                              (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
         (spk-sh-pk (concatenate '(vector (unsigned-byte 8))
                                 (vector #xa9 #x14) (bl.crypto:hash160 rd-pk)
                                 (vector #x87)))
         (spk-sh-pkh (concatenate '(vector (unsigned-byte 8))
                                  (vector #xa9 #x14) (bl.crypto:hash160 rd-pkh)
                                  (vector #x87)))
         (spks (vector spk-sh-pk spk-sh-pkh))
         (txid0 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 30))
         (txid1 (make-array 32 :element-type '(unsigned-byte 8) :initial-element 31))
         (empty (make-array 0 :element-type '(unsigned-byte 8)))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint :hash txid0 :index 0)
                               :script-sig empty :sequence #xffffffff)
                              (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint :hash txid1 :index 0)
                               :script-sig empty :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out :value 190000 :script-pubkey rd-pkh))
              :lock-time 0))
         (prevtxs (list (list (cons "txid" (bl.rpc:hash-to-hex txid0))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk-sh-pk))
                              (cons "amount" 0.001d0)
                              (cons "redeemScript" (bl.crypto:bytes-to-hex rd-pk)))
                        (list (cons "txid" (bl.rpc:hash-to-hex txid1))
                              (cons "vout" 0)
                              (cons "scriptPubKey" (bl.crypto:bytes-to-hex spk-sh-pkh))
                              (cons "amount" 0.001d0)
                              (cons "redeemScript" (bl.crypto:bytes-to-hex rd-pkh)))))
         (result (bl.rpc:dispatch-rpc-method
                  node "signrawtransactionwithkey"
                  (list (bl.crypto:bytes-to-hex (bl.ser:serialize-transaction tx))
                        (list wif) prevtxs))))
    (is (eq t (cdr (assoc "complete" result :test #'string=)))
        "signer reported ~S" (cdr (assoc "errors" result :test #'string=)))
    (let* ((tx2 (bl.ser:parse-tx-payload
                 (bl.crypto:hex-to-bytes (cdr (assoc "hex" result :test #'string=)))))
           (ins (bl.ser:transaction-inputs tx2))
           (spent (make-array 2)))
      (dotimes (j 2)
        (setf (aref spent j)
              (bl.store:make-utxo-entry
               :value 100000
               :script-pubkey (coerce (aref spks j)
                                      '(simple-array (unsigned-byte 8) (*))))))
      ;; Both inputs pass the full consensus interpreter, which is the only
      ;; statement that means the coin moved.
      (dotimes (j 2)
        (is-true (%verify-tx-input tx2 j spent "P2SH,WITNESS,NULLDUMMY,DERSIG,LOW_S")
                 "input ~D does not verify" j))
      ;; Input 0 (P2SH-P2PK): <sig> <redeemScript>, and nothing else.
      (let* ((pushes (%direct-pushes (bl.ser:tx-in-script-sig (aref ins 0))))
             (sig (first pushes)))
        (is (= 2 (length pushes))
            "P2SH-P2PK scriptSig carries ~D pushes, Core's is the signature and ~
the redeemScript" (length pushes))
        (is (equalp rd-pk (second pushes)))
        (is-true (and sig
                      (bl.crypto:verify-signature
                       (bl.interop:compute-legacy-sighash tx2 0 rd-pk 1)
                       (subseq sig 0 (1- (length sig)))
                       pub))
                 "the P2SH-P2PK signature is not over the redeemScript"))
      ;; Input 1 (P2SH-P2PKH control): <sig> <pubkey> <redeemScript>.
      (let* ((pushes (%direct-pushes (bl.ser:tx-in-script-sig (aref ins 1))))
             (sig (first pushes)))
        (is (= 3 (length pushes))
            "P2SH-P2PKH scriptSig carries ~D pushes, Core's is the signature, ~
the pubkey and the redeemScript" (length pushes))
        (is (equalp pub (second pushes)))
        (is (equalp rd-pkh (third pushes)))
        (is-true (and sig
                      (bl.crypto:verify-signature
                       (bl.interop:compute-legacy-sighash tx2 1 rd-pkh 1)
                       (subseq sig 0 (1- (length sig)))
                       pub))
                 "the P2SH-P2PKH signature is not over the redeemScript")))))

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

(test rpc-addnode-refuses-an-equivalent-numeric-address
  "Core CConnman::AddNode (net.cpp:3732-3744) compares LookupNumeric results,
so a second spelling of an added address is `already added' too: 127.1 is
127.0.0.1 in inet_aton notation (rpc_net.py:252-255). A hostname and a
different port stay distinct."
  (let ((node (make-test-node)))                 ; default P2P port 18333
    (flet ((add (spec) (bl.rpc:dispatch-rpc-method node "addnode" (list spec "add")))
           (code (thunk) (handler-case (progn (funcall thunk) nil)
                           (bl.rpc:rpc-error (e) (bl.rpc:rpc-error-code e)))))
      (add "127.0.0.1:18444")
      (is (eql -23 (code (lambda () (add "127.1:18444")))))
      (is (eql -23 (code (lambda () (add "0x7f.0.0.1:18444")))))
      (add "10.0.0.1")
      (is (eql -23 (code (lambda () (add "10.1:18333")))))
      ;; Not the same endpoint: another port, or an out-of-range short form.
      (is (null (code (lambda () (add "127.1:18445")))))
      (is (null (code (lambda () (add "127.256.1:18444")))))
      (is (equal '("127.0.0.1:18444" "10.0.0.1" "127.1:18445" "127.256.1:18444")
                 (bl:node-added-nodes node)))
      ;; An unknown command is Core's runtime_error carrying the help text,
      ;; i.e. -1 (rpc/net.cpp:339-342, rpc_net.py:273).
      (handler-case (progn (bl.rpc:dispatch-rpc-method node "addnode" (list "1.2.3.4" "abc"))
                           (fail "an unknown command must be refused"))
        (bl.rpc:rpc-error (e)
          (is (eql -1 (bl.rpc:rpc-error-code e)))
          (is (search "addnode \"node\" \"command\"" (bl.rpc:rpc-error-message e))))))))

(test getnetworkinfo-lists-the-local-addresses
  "Core's getnetworkinfo reports mapLocalHost as localaddresses, one
{address, port, score} per entry (rpc/net.cpp:721-733);
p2p_addr_selfannouncement.py:103 reads the -externalip port from it. Ours
always answered []."
  (let ((node (make-test-node)))
    (bl.net:clear-local-addresses)
    (unwind-protect
         (multiple-value-bind (net bytes) (bl.net:parse-network-address "42.42.42.42")
           (bl.net:add-local net bytes 18444 bl.net:+local-manual+)
           (let ((la (cdr (assoc "localaddresses"
                                 (bl.rpc:dispatch-rpc-method node "getnetworkinfo" nil)
                                 :test #'string=))))
             (is (= 1 (length la)))
             (let ((rec (elt la 0)))
               (is (equal "42.42.42.42" (cdr (assoc "address" rec :test #'string=))))
               (is (eql 18444 (cdr (assoc "port" rec :test #'string=))))
               (is (eql bl.net:+local-manual+ (cdr (assoc "score" rec :test #'string=)))))))
      (bl.net:clear-local-addresses))))

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

(defvar *gbfp-header-nonce* 0
  "Serial number for RPC-GETBLOCKFROMPEER-PATHS's header. The successful call
leaves an outstanding fetch request for that block -- nothing consumes one
except the body arriving, which never does here -- so a fixed header would make
the second run in one image find the first run's request already registered.")

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
               :timestamp 1 :bits #x1d00ffff
               :nonce (incf *gbfp-header-nonce*)))
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
    ;; the fake peer's nil connection. The peer advertises NODE_WITNESS, as a
    ;; peer that handshook with a segwit node does -- Core's FetchBlock refuses
    ;; one that does not (net_processing.cpp:1971).
    (let ((peer (%rpc-fake-peer "1.2.3.4")))
      (setf (bl.net:peer-services peer) bl.ser:+node-witness+)
      (push peer (bl:node-peers node))
      (is-false (bl.net:fetch-block-requested-p hash)
                "control: nothing is outstanding before the call")
      (let ((r (bl.rpc::rpc-getblockfrompeer
                node (list hash-hex (bl.net:peer-id peer)))))
        (is (hash-table-p r))
        (is (= 0 (hash-table-count r))))
      ;; Core marks the block in flight before sending the getdata
      ;; (FetchBlock -> BlockRequested, net_processing.cpp:1976-1979), and that
      ;; is what makes fRequested true when the body arrives -- without which a
      ;; body for a block the node has connected and since PRUNED is dropped by
      ;; AcceptBlock's unrequested arm (validation.cpp:4369), the case its own
      ;; comment at :4363 names. Ours sent a bare getdata and recorded nothing.
      (is-true (bl.net:fetch-block-requested-p hash)
               "getblockfrompeer recorded no request, so the body would be dropped"))
    ;; bad peer_id type → error
    (signals bl.rpc:rpc-error
      (bl.rpc::rpc-getblockfrompeer node (list hash-hex "notanint")))))

(test rpc-getblockchaininfo-initialblockdownload-is-the-tip-age-verdict
  "getblockchaininfo's initialblockdownload is Core's
chainman.IsInitialBlockDownload() (rpc/blockchain.cpp:1422), the latched verdict
of UpdateIBDStatus: true while the tip has less than the network's minimum
chain work OR is older than -maxtipage (validation.cpp:3314-3320,
CChain::IsTipRecent, chain.h:431-437). It used to report NODE-SYNCING, a flag
that is true only WHILE a sync pass is running, so a node whose tip was a week
old answered false the moment the pass ended and -maxtipage changed nothing
that could be observed (feature_maxtipage.py:39)."
  (let* ((bl:*network* :regtest)        ; minimum chain work 0
         (bl.net:*cached-is-ibd* t)     ; bound: the latch is process-global
         (bl.net:*max-tip-age-seconds* (* 24 60 60))
         (node (make-test-node))
         (cs (bl:node-chain-state node)))
    (flet ((set-tip (age-seconds)
             (let* ((hdr (bl.ser:make-block-header
                          :version 1
                          :prev-block (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element 0)
                          :merkle-root (make-array 32 :element-type '(unsigned-byte 8)
                                                      :initial-element 0)
                          :timestamp (- (bl.ser:get-unix-time) age-seconds)
                          :bits #x207fffff :nonce 0))
                    (hash (bl.ser:block-header-hash hdr)))
               (bl.store:add-block-index-entry
                cs (bl.store:make-block-index-entry
                    :hash hash :height 1 :header hdr :status :valid :chain-work 1))
               (setf (bl.store:chain-state-best-block-hash cs) hash
                     (bl.store:chain-state-best-height cs) 1)))
           (ibd ()
             (cdr (assoc "initialblockdownload"
                         (bl.rpc:dispatch-rpc-method node "getblockchaininfo" nil)
                         :test #'string=))))
      ;; A tip older than -maxtipage keeps the node in IBD.
      (set-tip (+ (* 24 60 60) 5))
      (is (eq t (ibd)))
      ;; And it stays in IBD however many times it is asked -- the latch only
      ;; falls, it is not re-derived per call.
      (is (eq t (ibd)))
      ;; A tip inside the window leaves IBD.
      (set-tip (- (* 24 60 60) 60))
      (is (eq 'yason:false (ibd)))
      ;; Latched: an old tip after the flip does NOT put the node back in IBD
      ;; (Core's m_cached_is_ibd never flips back, validation.cpp:3316).
      (set-tip (* 7 24 60 60))
      (is (eq 'yason:false (ibd))))))

(test rpc-getblockfrompeer-refuses-a-pre-segwit-peer
  "getblockfrompeer refuses a peer that does not advertise NODE_WITNESS with
Core's -1 `Pre-SegWit peer'. FetchBlock tests CanServeWitnesses right after the
peer lookup (net_processing.cpp:1970-1971) because the getdata it would send
asks for MSG_WITNESS_BLOCK, which such a peer does not answer, and the bare
MSG_BLOCK it could answer returns the witness-stripped serialization -- a block
that can never pass script validation. We sent the request anyway
(rpc_getblockfrompeer.py:88)."
  (let* ((bl:*prune-target-mib* nil)
         (node (make-test-node))
         (cs (bl:node-chain-state node))
         (hdr (bl.ser:make-block-header
               :version 1
               :prev-block (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :merkle-root (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)
               :timestamp 1 :bits #x1d00ffff :nonce 0))
         (hash (bl.ser:block-header-hash hdr))
         (hash-hex (bl.rpc:hash-to-hex hash))
         (witness-peer (%rpc-fake-peer "1.2.3.4"))
         (legacy-peer (%rpc-fake-peer "5.6.7.8")))
    (bl.store:add-block-index-entry
     cs (bl.store:make-block-index-entry
         :hash hash :height 1 :header hdr :status :header-valid :chain-work 1))
    (setf (bl.net:peer-services witness-peer)
          (logior bl.ser:+node-network+ bl.ser:+node-witness+))
    ;; Core's NODE_WITNESS bit is the only one that matters here: a peer
    ;; advertising NODE_NETWORK alone is pre-segwit.
    (setf (bl.net:peer-services legacy-peer) bl.ser:+node-network+)
    (push witness-peer (bl:node-peers node))
    (push legacy-peer (bl:node-peers node))
    ;; Control: the witness peer is served.
    (is (hash-table-p (bl.rpc:dispatch-rpc-method
                       node "getblockfrompeer"
                       (list hash-hex (bl.net:peer-id witness-peer)))))
    (signals-rpc-error (:code -1 :exact-message "Pre-SegWit peer")
      (bl.rpc:dispatch-rpc-method
       node "getblockfrompeer" (list hash-hex (bl.net:peer-id legacy-peer))))))

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
diagram, over a CPFP pair that shares one chunk. The chunk sizes are Core's
sigops-adjusted WEIGHT, which is the txgraph's unit on both sides and what
Core reports here without converting (rpc/mempool.cpp:461-463, :523-525,
:641-643); \"vsize\" and the ancestor/descendant sizes stay virtual bytes."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (parent (make-spending-test-tx (%txid-array 210) :vout 0 :value 50000000))
         (pid (bl.ser:transaction-hash parent))
         (pid-hex (bl.rpc:hash-to-hex pid))
         (child (make-spending-test-tx pid :vout 0 :value 40000000))
         (cid (bl.ser:transaction-hash child))
         (cid-hex (bl.rpc:hash-to-hex cid))
         (pweight (bl.ser:transaction-weight parent))
         (cweight (bl.ser:transaction-weight child)))
    ;; Empty mempool: the diagram is just the (0, 0) origin.
    (let ((r (bl.rpc::rpc-getmempoolfeeratediagram node nil)))
      (is (= 1 (length r)))
      (is (= 0 (cdr (assoc "weight" (first r) :test #'string=))))
      (is (zerop (btc-amount (cdr (assoc "fee" (first r) :test #'string=))))))
    ;; Low-fee parent + CPFP child: one chunk of (20100, pweight+cweight).
    (%add-tx mempool parent :fee 100)
    (%add-tx mempool child :fee 20000)
    ;; getmempoolentry chunk fields (fees.chunk in BTC, chunkweight in WU).
    (let* ((r (bl.rpc::rpc-getmempoolentry node (list pid-hex)))
           (fees (cdr (assoc "fees" r :test #'string=))))
      (is (= (+ pweight cweight) (cdr (assoc "chunkweight" r :test #'string=))))
      (is (= 20100 (* 100000000 (btc-amount (cdr (assoc "chunk" fees :test #'string=)))))))
    ;; getmempoolcluster: one cluster, one chunk, txs in mining order.
    (let* ((r (bl.rpc::rpc-getmempoolcluster node (list cid-hex)))
           (chunks (cdr (assoc "chunks" r :test #'string=))))
      (is (= 2 (cdr (assoc "txcount" r :test #'string=))))
      (is (= (+ pweight cweight) (cdr (assoc "clusterweight" r :test #'string=))))
      (is (= 1 (length chunks)))
      (let ((chunk (first chunks)))
        (is (= 20100 (* 100000000 (btc-amount (cdr (assoc "chunkfee" chunk :test #'string=))))))
        (is (= (+ pweight cweight) (cdr (assoc "chunkweight" chunk :test #'string=))))
        (is (equal (list pid-hex cid-hex) (cdr (assoc "txs" chunk :test #'string=))))))
    ;; The diagram now has the origin plus one cumulative chunk point.
    (let ((r (bl.rpc::rpc-getmempoolfeeratediagram node nil)))
      (is (= 2 (length r)))
      (is (= (+ pweight cweight) (cdr (assoc "weight" (second r) :test #'string=))))
      (is (= 20100 (* 100000000 (btc-amount (cdr (assoc "fee" (second r) :test #'string=)))))))
    ;; A standalone lower-feerate tx appends a second, later diagram point.
    (let ((solo (make-mempool-test-tx :input-id 211)))
      (%add-tx mempool solo :fee 50)
      (let ((r (bl.rpc::rpc-getmempoolfeeratediagram node nil)))
        (is (= 3 (length r)))
        (is (= 20150 (* 100000000 (btc-amount (cdr (assoc "fee" (third r) :test #'string=))))))))
    ;; getmempoolcluster on an absent txid errors like getmempoolentry.
    (signals error
      (bl.rpc::rpc-getmempoolcluster
       node (list (bl.rpc:hash-to-hex (%txid-array 212)))))))

(test rpc-mempool-cluster-two-chunks
  "A cluster whose child does NOT absorb its parent reports two chunks in
mining order (parent's first)."
  (let* ((node (make-test-node))
         (mempool (bl:node-mempool node))
         (parent (make-spending-test-tx (%txid-array 213) :vout 0 :value 50000000))
         (pid (bl.ser:transaction-hash parent))
         (pid-hex (bl.rpc:hash-to-hex pid))
         (child (make-spending-test-tx pid :vout 0 :value 40000000))
         (cid-hex (bl.rpc:hash-to-hex
                   (bl.ser:transaction-hash child))))
    (%add-tx mempool parent :fee 20000)
    (%add-tx mempool child :fee 100)
    (let* ((r (bl.rpc::rpc-getmempoolcluster node (list pid-hex)))
           (chunks (cdr (assoc "chunks" r :test #'string=))))
      (is (= 2 (length chunks)))
      (is (equal (list pid-hex) (cdr (assoc "txs" (first chunks) :test #'string=))))
      (is (equal (list cid-hex) (cdr (assoc "txs" (second chunks) :test #'string=))))
      (is (= 20000 (* 100000000
                      (btc-amount (cdr (assoc "chunkfee" (first chunks) :test #'string=))))))
      (is (= 100 (* 100000000
                    (btc-amount (cdr (assoc "chunkfee" (second chunks) :test #'string=)))))))))

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

(test rest-headers-answers-an-unknown-hash-with-an-empty-result
  "A well-formed hash the index does not know is 200 with an empty result, not
a 404: Core's LookupBlockIndex answers nullptr, the loop in rest_headers never
runs, and the empty header vector goes out with HTTP_OK (rest.cpp:225-247).
rest_headers has no not-found path at all. Ours answered 404 by a documented
divergence, so interface_rest.py:231 read 404 where it compares against [] --
and a fork header, which is equally unanswerable, already returned 200 [].

The count check still comes FIRST, as Core's does, so an out-of-range count on
an unknown hash is the count's own 400."
  (multiple-value-bind (cs entries) (%make-served-chain 2)
    (declare (ignore entries))
    (let* ((node (make-test-node))
           (hunchentoot:*reply* (make-instance 'hunchentoot:reply))
           (unknown (make-string 64 :initial-element #\1)))
      (setf (bl:node-chain-state node) cs)
      (is-false (bl.store:get-block-index-entry
                 cs (bl.rpc:parse-hex-hash unknown))
                "the fixture knows the hash this test calls unknown")
      (flet ((rest-get (ext)
               (rest-request node (format nil "/rest/headers/~A.~A" unknown ext))))
        (%with-rest-count ("1")
          (is (string= "[]" (rest-get "json")))
          (is (= 200 (hunchentoot:return-code*)))
          (is (string= (format nil "~%") (rest-get "hex")))
          (is (= 200 (hunchentoot:return-code*)))
          (is (zerop (length (rest-get "bin"))))
          (is (= 200 (hunchentoot:return-code*))))
        ;; The count is still judged before the lookup.
        (%with-rest-count ("0")
          (let ((body (rest-get "json")))
            (is-true (search "Header count is invalid" body)
                     "an unknown hash swallowed the count complaint: ~S" body)))))))

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
      (bl.rpc:parse-json-rpc-request body)
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

(test every-rpc-call-is-logged-under-cores-rpc-category
  "Core writes one debug line per call, in JSONRPCRequest::parse the moment
the method name is read and BEFORE the parameters are
(rpc/request.cpp:240-243): ThreadRPCServer method=<m> user=<u>, under the rpc
category. Writing it at parse time rather than at return time is the whole
point of the line for mining_getblocktemplate_longpoll.py:26, which waits for
it while a longpoll getblocktemplate is still parked. We logged nothing at
all.

Core sanitizes the method name (SanitizeString), which matters because the
name is caller-supplied and a newline in it would write a debug.log line of
the caller's choosing."
  (let ((bl.log:*current-log-level* :debug))
    (bl.log:enable-log-category "rpc")
    (unwind-protect
         (let ((lines (capture-log-lines
                       (lambda ()
                         (ignore-errors
                          (jsonrpc-shape-reply
                           (jsonrpc-shape-body nil "uptime" "\"id\":1")))))))
           (is-true (find "ThreadRPCServer method=uptime" lines :test #'search)
                    "no per-call rpc log line: ~S" lines)
           ;; The category tag Core prints for a categorized debug line.
           (is-true (find "[rpc]" lines :test #'search)))
      (bl.log:disable-log-category "rpc"))))

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
        (bl.rpc:parse-json-rpc-request
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

(defparameter *jsonrpc-stack-eating-method* "ga11stackeater"
  "A method whose handler recurses without a base case, so it raises SBCL's
CONTROL-STACK-EXHAUSTED -- a STORAGE-CONDITION, and NOT an ERROR.")

(defun jsonrpc-eat-the-control-stack (n)
  "Recurse until the control stack is gone. Not tail-recursive on purpose:
the caller's frame has to survive the call, or this is a loop."
  (1+ (jsonrpc-eat-the-control-stack (1+ n))))

(defun call-with-jsonrpc-handler-methods (thunk)
  "Register the handler tests' throwaway dispatch targets, run THUNK, then
remove them so the global method registry is unchanged."
  (bl.rpc:register-rpc-method
   *jsonrpc-shape-method*
   (lambda (node params) (declare (ignore node params)) 42))
  (bl.rpc:register-rpc-method
   *jsonrpc-handler-dotted-method*
   (lambda (node params) (declare (ignore node params)) (cons 1 2)))
  ;; A handler that raises SBCL's CONTROL-STACK-EXHAUSTED, which is a
  ;; STORAGE-CONDITION and NOT an ERROR.
  (bl.rpc:register-rpc-method
   *jsonrpc-stack-eating-method*
   (lambda (node params)
     (declare (ignore node params))
     (jsonrpc-eat-the-control-stack 0)))
  (unwind-protect (funcall thunk)
    (dolist (method (list *jsonrpc-shape-method*
                          *jsonrpc-handler-dotted-method*
                          *jsonrpc-stack-eating-method*))
      (remhash method bl.rpc::*rpc-methods*))))

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
    (setf (slot-value request 'hunchentoot:raw-post-data) octets)
    request))

(defun jsonrpc-handler-reply (body &rest request-args)
  "POST BODY to the production entry point RPC-HANDLER; return
 (values http-status response-body content-type). The RPC credential is
installed for the duration of the call and sent with the request, so the
handler authorizes it and reaches the paths under test; :AUTH overrides what
the client presents (see jsonrpc-handler-request). RATE-LIMITER, when given as
:rate-limiter, replaces the global limiter for this one call, and NODE, when
given as :node, is the node the dispatched method receives -- the shape tests
need none and pass NIL, a method that reads the chain or the network needs one."
  (let* ((rate-limiter (getf request-args :rate-limiter))
         (node (getf request-args :node))
         (request-args (loop for (k v) on request-args by #'cddr
                             unless (member k '(:rate-limiter :node))
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
         (bl.rpc::*rpc-node* node)
         (bl.rpc::*rpc-rate-limiter* rate-limiter))
    ;; A fresh reply starts at 200; reset explicitly so a request-construction
    ;; hiccup could not pre-seed the status the assertions read back.
    (setf (hunchentoot:return-code*) hunchentoot:+http-ok+)
    (let ((out (bl.rpc::rpc-handler)))
      (values (hunchentoot:return-code*) out (hunchentoot:content-type*)))))

(defun jsonrpc-handler-check (body expected-status expected-json &rest request-args)
  "Assert that POSTing BODY to rpc-handler answers EXPECTED-STATUS with
EXPECTED-JSON as the exact response body.

Core terminates every JSON-RPC reply with a NEWLINE (httprpc.cpp:55, :229), so
that byte is asserted here once and stripped before the JSON is compared --
the callers all name the JSON they expect, not its terminator. An EMPTY body
(the 204 and 403 answers) carries no newline."
  (multiple-value-bind (status json)
      (apply #'jsonrpc-handler-reply body request-args)
    (is (eql expected-status status)
        "~A~%  status: expected ~S, got ~S (body ~S)"
        body expected-status status json)
    (when (plusp (length json))
      (is (char= #\Newline (char json (1- (length json))))
          "~A~%  body must end in Core's newline; got ~S" body json)
      (setf json (string-right-trim '(#\Newline) json)))
    (is (string= expected-json json)
        "~A~%  body: expected ~S~%        got      ~S"
        body expected-json json)))

(defun jsonrpc-legacy-error-json (code message &key (id "null"))
  "The exact legacy-1.x error body Core's JSONErrorReply sends for a failure
raised before any version is known: null result, the error object, and the id
(httprpc.cpp:41-59 over the default V1_LEGACY/VNULL-id JSONRPCRequest,
request.h:55,63).

ID is that field as JSON, or NIL for a request object that PARSED and carried
no \"id\" member -- Core's parse() replaces the initial present null with
std::nullopt before it judges the version or the method (request.cpp:206-211),
so the key is absent from those replies and present, null, from a body that
never parsed at all."
  (if id
      (format nil "{\"result\":null,\"error\":{\"code\":~D,\"message\":\"~A\"},\"id\":~A}"
              code message id)
      (format nil "{\"result\":null,\"error\":{\"code\":~D,\"message\":\"~A\"}}"
              code message)))

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
    ;; The ID, though, IS carried: Core parses it before it judges the version
    ;; or the method, `so errors from here on will have the id'
    ;; (rpc/request.cpp:206-211).
    (jsonrpc-handler-check
     "{\"jsonrpc\":\"2.0\",\"id\":1}" 400
     (jsonrpc-legacy-error-json bl.rpc:+rpc-invalid-request+
                                "Missing method" :id "1"))
    ;; The same failure with NO id member: the key is dropped entirely, which
    ;; is what interface_rpc.py:204 compares against.
    (jsonrpc-handler-check
     "{\"jsonrpc\":\"2.0\"}" 400
     (jsonrpc-legacy-error-json bl.rpc:+rpc-invalid-request+
                                "Missing method" :id nil))
    ;; A "method" that is present but not a string is Core's OTHER sentence
    ;; (rpc/request.cpp:236-237).
    (jsonrpc-handler-check
     "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":7}" 400
     (jsonrpc-legacy-error-json bl.rpc:+rpc-invalid-request+
                                "Method must be a string" :id "1"))
    ;; A result yason cannot encode reaches the handler's outermost clause.
    (jsonrpc-handler-check
     (format nil "{\"method\":\"~A\",\"id\":1}" *jsonrpc-handler-dotted-method*)
     500
     (jsonrpc-legacy-error-json bl.rpc:+rpc-internal-error+ "Internal error"
                                :id "1"))
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
      (is (string= (format nil "~A~%"
                           (jsonrpc-legacy-error-json bl.rpc:+rpc-misc-error+
                                                      "Rate limit exceeded"))
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
        (bl.rpc:extract-partial-merkle-tree 2 (list t t t) (list a b))
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
    (is-false (bl.rpc:extract-partial-merkle-tree 16667 (list t) (list h))
              "one over the cap must be refused")
    ;; And the cap must not reject a legitimate small proof.
    (multiple-value-bind (root matched)
        (bl.rpc:extract-partial-merkle-tree 1 (list t) (list h))
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
    (is-true (%authorized-user
              (%basic-auth-header-utf8 "üser:pässwörd"))
             "a UTF-8 credential that matches the configuration was refused")
    ;; A near miss is still refused — the fix must not have made it permissive.
    (is-false (%authorized-user
               (%basic-auth-header-utf8 "üser:pässwörX")))
    ;; And the latin-1 encoding of the same characters is a DIFFERENT byte
    ;; string, so it must not authorize.
    (is-false (%authorized-user
               (%basic-auth-header "üser:pässwörd")))))

(test ascii-credentials-are-unchanged-by-the-byte-comparison
  "The byte comparison must be a strict generalization: every ASCII case that
worked before still works, and every near miss is still refused."
  (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "testpass")))
    (is-true (%authorized-user "Basic dGVzdHVzZXI6dGVzdHBhc3M="))
    ;; A password containing colons still splits on the FIRST colon.
    (let ((bl.rpc::*rpc-credentials* (%plaintext-credentials "testuser" "a:b:c")))
      (is-true (%authorized-user (%basic-auth-header "testuser:a:b:c"))))
    (is-false (%authorized-user (%basic-auth-header "testuser:testpas")))
    (is-false (%authorized-user (%basic-auth-header "testuse:testpass")))
    ;; Length differences must not short-circuit: an empty password never matches.
    (is-false (%authorized-user (%basic-auth-header "testuser:")))))

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
    ;; send: outputs is positional 0, options is positional 4. `fee_rate' is
    ;; BOTH a member and positional 3, and Core's GetArgNames reaches the
    ;; positional one first, so it fills that slot; Core's own handler is what
    ;; then pushes it into the options object
    ;; (InterpretFeeEstimationInstructions, wallet/rpc/spend.cpp:44-62).
    (let ((out (call "send" "outputs" 1 "fee_rate" 2 "add_to_wallet" 3)))
      (is (= 5 (length out)) "send produced ~D slots, wanted 5" (length out))
      (is (eql 1 (first out)))
      (is (eql 2 (fourth out)) "fee_rate belongs in its positional slot: ~S" out)
      (let ((options (fifth out)))
        (is-true (hash-table-p options) "the options slot is ~S" options)
        (when (hash-table-p options)
          (is (eql 3 (gethash "add_to_wallet" options))))))
    ;; gettxspendingprevout's member, which is not a wallet RPC.
    (let ((out (call "gettxspendingprevout" "outputs" 1 "mempool_only" t)))
      (is-true (hash-table-p (second out))
               "mempool_only did not reach the options slot: ~S" out))
    ;; A name that is neither positional nor a member is still unknown.
    (signals bl.rpc:rpc-error (call "send" "outputs" 1 "nonesuch" 2))))

(test named-only-members-are-cores-direct-inner-arguments
  "GetArgNames walks the OBJ_NAMED_PARAMS argument's OWN m_inner and goes no
deeper (rpc/util.cpp:745-757), so the named-only set is exactly its direct
members -- every one of them, including those Core splices in from a helper
with Cat<> (FundTxDoc's conf_target, estimate_mode, replaceable,
solving_data), and none of the members OF a member (subtractFeeFromOutputs'
vout_index, input_weights' txid/vout/weight).

Our table had both errors at once: it carried the nested names and dropped
every camelCase one, so walletcreatefundedpsbt(feeRate=..., subtractFeeFrom
Outputs=[0]) -- wallet_keypool.py:165 -- answered `Unknown named parameter
feeRate' while fundrawtransaction(txid=...) was quietly swallowed.

Two ordering rules come with it, and both were wrong before:

  - a name that is BOTH a member and a positional argument belongs to
    whichever comes first in GetArgNames. send and sendall declare
    conf_target, estimate_mode and fee_rate in both places (Core marks the
    members .also_positional) and the positional slot is earlier, so
    sendall(conf_target=6) fills the slot rather than the options object.
  - the options object is pushed at the OBJ_NAMED_PARAMS slot, which is not
    always called \"options\": listunspent's is \"query_options\", so a
    lookup by name found no slot and dropped the collected members in
    silence."
  (flet ((call (method &rest kvs)
           (let ((h (make-hash-table :test 'equal)))
             (loop for (k v) on kvs by #'cddr do (setf (gethash k h) v))
             (bl.rpc::%named-params-to-positional method h))))
    ;; wallet_keypool.py:165's call: both camelCase members reach the options
    ;; slot, which is positional 3.
    (let* ((out (call "walletcreatefundedpsbt" "inputs" (vector) "outputs" (vector)
                      "feeRate" 1/10000 "subtractFeeFromOutputs" (vector 0)))
           (options (nth 3 out)))
      (is (= 4 (length out)))
      (is-true (hash-table-p options) "the options slot is ~S" options)
      (when (hash-table-p options)
        (is (eql 1/10000 (gethash "feeRate" options)))
        (is (equalp (vector 0) (gethash "subtractFeeFromOutputs" options)))))
    ;; A member Core splices in from FundTxDoc.
    (let ((out (call "walletcreatefundedpsbt" "inputs" (vector) "outputs" (vector)
                     "solving_data" 7)))
      (is (eql 7 (and (hash-table-p (nth 3 out))
                      (gethash "solving_data" (nth 3 out))))))
    ;; Positional beats member where Core's order puts it first.
    (let ((out (call "sendall" "recipients" (vector "x") "conf_target" 6 "send_max" t)))
      (is (eql 6 (second out)) "conf_target belongs in its positional slot: ~S" out)
      (is-true (and (hash-table-p (fifth out))
                    (gethash "send_max" (fifth out)))))
    ;; listunspent's options slot is query_options, positional 4.
    (let ((out (call "listunspent" "minconf" 1 "minimumAmount" 5)))
      (is (eql 1 (first out)))
      (is (eql 5 (and (hash-table-p (nth 4 out))
                      (gethash "minimumAmount" (nth 4 out))))))
    ;; A member OF a member is not a named-only argument.
    (signals bl.rpc:rpc-error
      (call "walletcreatefundedpsbt" "inputs" (vector) "vout_index" 0))
    (signals bl.rpc:rpc-error
      (call "fundrawtransaction" "hexstring" "00" "txid" "ff"))))

;;;; --- The request boundary against an attacker-chosen tree depth ----------

(defparameter *jsonrpc-deep-leaf-wrappers* 30000
  "How deep the boundary test nests the miniscript leaf it posts.

A tapscript leaf may be 329,482 script bytes and `n:' costs one of them, so
this is a 30 kB descriptor -- three orders of magnitude under the RPC body
limit -- carrying a 30,000-node tree. On this image the recursive walkers it
used to reach died somewhere past 15,000.")

(defun jsonrpc-deep-tr-descriptor (wrappers)
  "tr(K,{n...n:1}) whose leaf nests WRAPPERS `n:' wrappers. The key is the
generator point's x coordinate, so the descriptor is well-formed and only the
leaf is unusual."
  (format nil "tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,~A:1)"
          (make-string wrappers :initial-element #\n)))

(test jsonrpc-answers-a-deeply-nested-descriptor-instead-of-losing-the-worker
  "One authenticated getdescriptorinfo used to kill the HTTP worker thread.

The descriptor parses in milliseconds -- Core's Parse is a state machine and so
is ours -- and then every walk over the resulting tree recursed: ToScript,
ToString, the ops/stack/witness calculations, the duplicate-key check, the
satisfier and FindInsaneSub. At this depth they raised
SB-KERNEL::CONTROL-STACK-EXHAUSTED, which is a STORAGE-CONDITION and NOT an
ERROR, so neither the (error (e) ...) clause in HANDLE-SINGLE-REQUEST nor the
one in RPC-HANDLER saw it and the caller got no reply at all.

The answer this asserts is Core's, not merely `some error': tapscript has no
201-op limit to exceed (miniscript.h:1566), the exec stack stays at 1, and
every subexpression of the chain is sane -- so IsSane fails on the ROOT alone,
for the one reason `1' gives it, and FindInsaneSub blames nothing below it."
  (let* ((descriptor (jsonrpc-deep-tr-descriptor *jsonrpc-deep-leaf-wrappers*))
         (body (format nil
                       "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getdescriptorinfo\",\"params\":[\"~A\"]}"
                       descriptor)))
    (multiple-value-bind (status json)
        (jsonrpc-handler-reply body :node (make-test-node))
      (is (eql hunchentoot:+http-ok+ status)
          "a 2.0 request always answers 200, even for an error (~S)" status)
      (let* ((reply (yason:parse json))
             (err (and (hash-table-p reply) (gethash "error" reply))))
        (is-true (hash-table-p err) "expected a JSON-RPC error object, got ~S" err)
        (when (hash-table-p err)
          (is (eql bl.rpc:+rpc-invalid-address-or-key+ (gethash "code" err)))
          (let ((message (gethash "message" err)))
            (is-true (stringp message))
            (when (stringp message)
              (is-true (search "is not sane: witnesses without signature exist"
                               message)
                       "unexpected message tail: ~S"
                       (subseq message (max 0 (- (length message) 80)))))))))))

(test jsonrpc-a-storage-condition-answers-the-caller-and-the-server-serves-on
  "A STORAGE-CONDITION is a SERIOUS-CONDITION and not an ERROR (probed on SBCL
2.6.5: (subtypep 'storage-condition 'error) is NIL), so every `(error (e) ...)'
clause on the request path stepped straight over one. The worker thread died
holding the connection, and the caller waited for a reply that was never going
to come.

Two halves, and the second is the point: the connection gets a JSON-RPC error
object, AND the same server answers the very next request normally -- which is
what says the thread survived rather than being replaced.

The message is asserted exactly because it is what distinguishes the clause
under test: the ordinary error clause formats the CONDITION (its report text),
the storage clause formats its TYPE. A blanket handler would print neither."
  (with-jsonrpc-handler-methods
    (multiple-value-bind (status json)
        (jsonrpc-handler-reply
         (format nil "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"~A\",\"params\":[]}"
                 *jsonrpc-stack-eating-method*))
      (is (eql hunchentoot:+http-ok+ status))
      (let* ((reply (yason:parse json))
             (err (and (hash-table-p reply) (gethash "error" reply))))
        (is-true (hash-table-p err) "expected an error object, got ~S" json)
        (when (hash-table-p err)
          (is (eql bl.rpc:+rpc-internal-error+ (gethash "code" err)))
          (is (string= "Internal error: CONTROL-STACK-EXHAUSTED"
                       (gethash "message" err))))))
    ;; ... and the next request is served as if nothing had happened.
    (multiple-value-bind (status json)
        (jsonrpc-handler-reply
         (format nil "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"~A\",\"params\":[]}"
                 *jsonrpc-shape-method*))
      (is (eql hunchentoot:+http-ok+ status))
      (let ((reply (yason:parse json)))
        (is (eql 42 (and (hash-table-p reply) (gethash "result" reply)))
            "the server stopped serving after the storage condition: ~S"
            json)))))

;;; --- getblockchaininfo's pruning fields ------------------------------------

(test sighash-strings-are-cores-seven-and-nothing-else
  "Core's SighashFromStr is a MAP of seven strings, not a search
(core_io.cpp:265-281): the match is case-sensitive and admits no substring,
and the refusal quotes the offending string. Ours upcased the argument and
looked for ALL / NONE / SINGLE / ANYONECANPAY as substrings, so it accepted
`all', `sighash_all' and anything else that happened to contain one of the
four words -- and said `Invalid sighashtype' instead of Core's sentence.
rpc_signrawtransactionwithkey.py:132 passes sighashtype=\"all\" and asks for
-8 with that sentence."
  (is (= 1 (bl.rpc:parse-sighash-type nil)) "absent means ALL")
  (dolist (row '(("DEFAULT" . 0) ("ALL" . 1) ("ALL|ANYONECANPAY" . #x81)
                 ("NONE" . 2) ("NONE|ANYONECANPAY" . #x82)
                 ("SINGLE" . 3) ("SINGLE|ANYONECANPAY" . #x83)))
    (is (= (cdr row) (bl.rpc:parse-sighash-type (car row)))
        "~A must be ~2,'0X" (car row) (cdr row)))
  (dolist (bad '("all" "None" "SIGHASH_ALL" "ALL|anyonecanpay" "" "ALLX"))
    (is (equal (cons -8 (format nil "'~A' is not a valid sighash parameter." bad))
               (rpc-error-of (lambda () (bl.rpc:parse-sighash-type bad))))
        "~S must be refused by name" bad)))

(test gettxoutsetinfo-by-height-needs-the-index-in-cores-words
  "Without -coinstatsindex, asking gettxoutsetinfo for a specific height is
-8 \"Querying specific block heights requires coinstatsindex\"
(rpc/blockchain.cpp:1088). Ours said \"Querying by block height/hash requires
-coinstatsindex\" -- the same refusal in different words, which
feature_coinstatsindex.py:112 reads back verbatim."
  (with-network (:regtest)
    (let ((node (regtest-node-fixture "gettxoutsetinfo-height")))
      (generate-regtest-blocks node 2)
      (is (equal '(-8 . "Querying specific block heights requires coinstatsindex")
                 (rpc-error-of
                  (lambda ()
                    (bl.rpc:dispatch-rpc-method node "gettxoutsetinfo"
                                                (wire-params (list "muhash" 1))))))))))

(test dumptxoutset-names-the-file-it-could-not-open
  "Core opens PATH.incomplete immediately after the already-exists check and
BEFORE the temporary rollback, and reports a failure as -8 \"Couldn't open
file <temppath> for writing.\" (rpc/blockchain.cpp:3123-3129). Ours first
opened it inside the streaming pass, so a path whose directory does not exist
escaped the RPC layer as an internal error -- and only after the chain had
been rolled back. rpc_dumptxoutset.py:66-68 asks for that sentence."
  (with-network (:regtest)
    (let* ((node (regtest-node-fixture "dumptxoutset-open"))
           (bad (namestring (merge-pathnames "no-such-directory-zz/snapshot.dat"
                                             (uiop:temporary-directory)))))
      (is (equal (cons -8 (format nil "Couldn't open file ~A.incomplete for writing." bad))
                 (rpc-error-of
                  (lambda ()
                    (bl.rpc:dispatch-rpc-method node "dumptxoutset"
                                                (wire-params (list bad "latest"))))))))))

(test getchaintips-always-reports-the-active-tip
  "Core's getchaintips is not `every index entry with no child': a candidate
tip is a block NOT on the active chain that no other off-chain block builds
on, and the active tip is then added unconditionally -- \"Always report the
currently active tip\" (rpc/blockchain.cpp:1587-1612). Ours dropped the
active tip the moment a submitted header extended it.

The order is Core's CompareBlocksByHeight (:1576-1580), height DESCENDING
with no special place for the active tip -- so a headers-only branch above
the tip comes first. rpc_getchaintips.py:79-84 asserts both: three tips after
a two-header chain is submitted on top of the active tip, and tips[0] being
the headers-only one."
  (with-network (:regtest)
    (let* ((node (regtest-node-fixture "chaintips-active"))
           (cs (bl:node-chain-state node)))
      (generate-regtest-blocks node 3)
      (flet ((header-hex (b)
               (bl.crypto:bytes-to-hex
                (bl.ser:serialize-block-header (bl.ser:bitcoin-block-header b))))
             (tips ()
               (bl.rpc:dispatch-rpc-method node "getchaintips" (wire-params '())))
             (field (row name) (cdr (assoc name row :test #'string=))))
        (is (= 1 (length (tips))) "one tip before anything is submitted")
        ;; Two headers extending the active tip, neither with a body.
        (let ((b1 (bl.mining:assemble-full-block
                   cs (bl:node-mempool node)
                   :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
          (bl.mining:mine-block b1)
          (bl.rpc:dispatch-rpc-method node "submitheader" (list (header-hex b1)))
          (let ((b2 (bl.mining:assemble-full-block
                     cs (bl:node-mempool node)
                     :coinbase-script-pubkey (p2sh-optrue-script-pubkey))))
            (setf (bl.ser:block-header-prev-block (bl.ser:bitcoin-block-header b2))
                  (bl.ser:block-header-hash (bl.ser:bitcoin-block-header b1))
                  (bl.ser:block-header-timestamp (bl.ser:bitcoin-block-header b2))
                  (1+ (bl.ser:block-header-timestamp (bl.ser:bitcoin-block-header b1)))
                  (bl.ser:block-header-cached-hash (bl.ser:bitcoin-block-header b2)) nil)
            (bl.mining:mine-block b2)
            (bl.rpc:dispatch-rpc-method node "submitheader" (list (header-hex b2))))
          (let ((rows (tips)))
            (is (= 2 (length rows))
                "the active tip is still reported although a header extends it")
            (is (equal '(5 "headers-only" 2)
                       (list (field (first rows) "height")
                             (field (first rows) "status")
                             (field (first rows) "branchlen")))
                "height descending: the headers-only branch comes first")
            (is (equal '(3 "active" 0)
                       (list (field (second rows) "height")
                             (field (second rows) "status")
                             (field (second rows) "branchlen"))))))))))

(test pruneheight-is-the-lowest-block-still-on-disk
  "Core's `pruneheight' -- and the value pruneblockchain returns -- is
GetFirstStoredBlock(tip)->nHeight, the height of the lowest block whose body
is still there (rpc/blockchain.cpp:1426-1428 and :1671-1673). Ours reported
one past the highest height DELETED, which is the same number only once
something has actually been deleted: on a node that has pruned nothing the
horizon reads 0 and we answered 1, while genesis is plainly on disk.
rpc_blockchain.py:202 asserts the 0."
  (with-network (:regtest)
    (let ((node (regtest-node-fixture "pruneheight")))
      (let ((bl:*prune-target-mib* 1))
        (let ((info (bl.rpc:dispatch-rpc-method node "getblockchaininfo"
                                                (wire-params '()))))
          (is (= 0 (cdr (assoc "pruneheight" info :test #'string=)))
              "a node that has pruned nothing still has genesis"))
        (generate-regtest-blocks node 3)
        (let ((info (bl.rpc:dispatch-rpc-method node "getblockchaininfo"
                                                (wire-params '()))))
          (is (= 0 (cdr (assoc "pruneheight" info :test #'string=)))
              "and still does after three more blocks"))))))

(test getblockchaininfo-names-a-prune-target-only-when-pruning-is-automatic
  "Core's getblockchaininfo adds pruneheight and automatic_pruning whenever
pruning is on, and prune_target_size ONLY inside `if (automatic_pruning)'
(rpc/blockchain.cpp:1426-1434; the field is declared /*optional=*/true at
:1388). A manually pruned node (-prune=1) has no target at all, so answering
0 is not the same as answering nothing: rpc_blockchain.py:161 compares the
whole key set of such a node against ['pruneheight', 'automatic_pruning']
plus the always-present keys."
  (let ((node (make-test-node)))
    (flet ((chain-info ()
             (bl.rpc:dispatch-rpc-method node "getblockchaininfo" (wire-params '()))))
      (flet ((info-keys () (mapcar #'car (chain-info)))
             (info-value (key) (cdr (assoc key (chain-info) :test #'string=))))
      ;; -prune=1 is Core's PRUNE_TARGET_MANUAL.
      (let ((bl:*prune-target-mib* 1))
        (let ((keys (info-keys)))
          (is-true (member "pruneheight" keys :test #'string=))
          (is-true (member "automatic_pruning" keys :test #'string=))
          (is-false (member "prune_target_size" keys :test #'string=)
                    "manual pruning must report no prune_target_size; keys were ~S"
                    keys)))
      ;; An automatic target IS reported, in bytes.
      (let ((bl:*prune-target-mib* 550))
        (is-true (member "prune_target_size" (info-keys) :test #'string=))
        (is (= (* 550 1048576) (info-value "prune_target_size"))))
      ;; Pruning off: none of the three keys.
      (let ((bl:*prune-target-mib* nil))
        (let ((keys (info-keys)))
          (is-false (member "pruneheight" keys :test #'string=))
          (is-false (member "automatic_pruning" keys :test #'string=))
          (is-false (member "prune_target_size" keys :test #'string=))))))))

;;; --- echo's internal-bug trigger -------------------------------------------

(test echo-answers-cores-internal-bug-report-for-the-arg9-trigger
  "Core's echo and echojson are one RPCHelpMan (rpc/node.cpp:277-311) whose
body opens with

    if (request.params[9].isStr()) {
        CHECK_NONFATAL(request.params[9].get_str() != \"trigger_internal_bug\");
    }

The NonFatalCheckError that raises becomes an RPC_MISC_ERROR (-1) carrying
StrFormatInternalBug's text (rpc/server.cpp:514-516, util/check.cpp:18-25).
rpc_misc.py:32-45 calls echo(arg9=\"trigger_internal_bug\") and accepts only
two answers: the node dies, or the error arrives with code -1 and
`Internal bug detected: <the condition's source text>' in its message. A node
that echoed the string back gave neither, and the test's next line is
`assert False'."
  (let ((node (make-test-node)))
    (flet ((args (arg9)
             (wire-params (list nil nil nil nil nil nil nil nil nil arg9))))
      ;; Every other argument, arg9 included, is still echoed unchanged --
      ;; and as an ARRAY, because Core answers `return request.params;' (a
      ;; UniValue VARR). A no-argument call is therefore [] and not null,
      ;; which rpc_named_arguments.py:28 asserts: assert_equal(node.echo(), []).
      (dolist (method '("echo" "echojson"))
        (is (equalp (coerce (list nil nil nil nil nil nil nil nil nil "harmless")
                            'vector)
                    (bl.rpc:dispatch-rpc-method node method (args "harmless"))))
        (is (equalp #() (bl.rpc:dispatch-rpc-method
                         node method (wire-params (list))))
            "~A with no arguments must answer [], not null" method))
      ;; Both names carry the trigger, because Core builds both from one body.
      (dolist (method '("echo" "echojson"))
        (let ((err (rpc-error-of
                    (lambda ()
                      (bl.rpc:dispatch-rpc-method
                       node method (args "trigger_internal_bug"))))))
          (is-true err "~A echoed the trigger back instead of reporting a bug"
                   method)
          (when err
            (is (= bl.rpc:+rpc-misc-error+ (car err))
                "~A reported code ~D, Core reports RPC_MISC_ERROR" method (car err))
            (is-true
             (search "Internal bug detected: request.params[9].get_str() != \"trigger_internal_bug\""
                     (cdr err))
             "~A's message was ~S" method (cdr err))
            (is-true (search "Please report this issue here:" (cdr err)))))))))

;;; --- help: one method's document, and Core's hidden category ---------------

(test help-answers-a-methods-document-and-hides-cores-hidden-category
  "Core's CRPCTable::help (rpc/server.cpp:295-330) answers `help <name>' with
that method's RPCHelpMan::ToString -- the usage line, a blank line, then the
description (rpc/util.cpp:773-793) -- and leaves the methods it files under
the category \"hidden\" out of the bare listing while still answering for
them by name (:310-311).

Two of Core's own tests read exactly that:

  rpc_named_arguments.py:21  assert h.startswith('getblockchaininfo\\n')
  rpc_orphans.py:152-153     assert 'getorphantxs' not in node.help()
                             assert 'unknown command: getorphantxs' not in
                                    node.help('getorphantxs')

Answering the bare method name satisfied neither: no newline, and every
hidden method listed."
  (let ((node (make-test-node)))
    (flet ((help (&rest params)
             (bl.rpc:dispatch-rpc-method node "help" (wire-params params))))
      ;; A method's document opens with `<name>\n\n' and carries its prose.
      (let ((text (help "getblockchaininfo")))
        (is (eql 0 (search (format nil "getblockchaininfo~%~%") text))
            "help getblockchaininfo began ~S" (subseq text 0 (min 60 (length text)))))
      ;; The usage line carries the declared arguments, as Core's does.
      (is (eql 0 (search (format nil "getblockhash height~%~%") (help "getblockhash"))))
      ;; An unknown command is unchanged (rpc_help.py:133).
      (is (string= "help: unknown command: foo" (help "foo")))
      ;; The listing omits Core's hidden category but keeps ordinary methods,
      ;; and `help <name>' still answers for a hidden one.
      (let ((listing (help)))
        (is-false (search "getorphantxs" listing)
                  "a hidden method must not appear in the bare listing")
        (is-false (search "setmocktime" listing))
        (is-false (search "invalidateblock" listing))
        (is-true (search "getblockchaininfo" listing))
        (is-true (search "getblockcount" listing)))
      (dolist (hidden '("getorphantxs" "setmocktime" "invalidateblock"))
        (let ((text (help hidden)))
          (is-false (search "unknown command" text)
                    "help ~A answered ~S" hidden text)
          (is (eql 0 (search hidden text))))))))

(test help-lists-usage-lines-under-cores-category-headings
  "CRPCTable::help sorts the commands by `category + name', prints
`== ' + Capitalize(category) + ` ==' whenever the category changes -- with a
blank line before every heading but the first -- writes ONE line per command
(the first line of its help, i.e. its usage line), and drops the closing
newline (rpc/server.cpp:69-115). rpc_help.py:139-149 reads the headings back
as `[line[3:-3] for line in help().splitlines() if line.startswith('==')]'
and compares them with the sorted component list.

Ours listed one bare method name per line and no headings at all, so that
comprehension produced []."
  (let* ((node (make-test-node))
         (listing (bl.rpc:dispatch-rpc-method node "help" (wire-params '())))
         (lines (uiop:split-string listing :separator (string #\Newline)))
         (titles (loop for l in lines
                       when (and (> (length l) 4)
                                 (string= "== " (subseq l 0 3)))
                         collect (subseq l 3 (- (length l) 3)))))
    ;; The headings rpc_help.py wants, in its own order (sorted).
    (is (equal '("Blockchain" "Control" "Mining" "Network" "Rawtransactions"
                 "Util" "Wallet" "Zmq")
               titles)
        "help's category headings were ~S" titles)
    ;; No trailing newline: splitlines() must not report an empty last line.
    (is (string/= "" (car (last lines)))
        "the listing ends in a newline")
    ;; A blank line before every heading but the first.
    (loop for (prev this) on lines
          while this
          do (when (and prev (> (length this) 2) (string= "== " (subseq this 0 3)))
               (is (string= "" prev)
                   "no blank line before the heading ~S" this)))
    ;; Every other line is a method's USAGE line, so its first token is the
    ;; method name -- which is what rpc_help.py's dump_help() splits off.
    (let ((names (loop for l in lines
                       unless (or (string= "" l)
                                  (and (> (length l) 2) (string= "== " (subseq l 0 3))))
                         collect (first (uiop:split-string l :separator " ")))))
      (is (= (length names) (length (remove-duplicates names :test #'string=)))
          "a method is listed twice")
      (is-true (member "getblockchaininfo" names :test #'string=))
      ;; getblockhash carries its declared argument, as Core's usage line does.
      (is-true (member "getblockhash height" lines :test #'string=)
               "the listing does not carry usage lines")
      ;; Core's hidden category is still absent.
      (dolist (hidden '("getorphantxs" "setmocktime" "invalidateblock"))
        (is-false (member hidden names :test #'string=)
                  "~A was listed" hidden)))))

(test help-listing-covers-every-registered-method
  "Every method this node registers must carry a category, or it lands under
an empty heading and invents a `==  ==' title rpc_help.py would read back.
Core has a row for all but one of ours; that one is named in
*RPC-LOCAL-CATEGORIES* so a NEW method cannot default into the listing
silently.

The category table is generated from Core (scripts/gen-rpc-categories.py) and
the hidden list comes from the same rows, so this also pins that the two
agree: a method Core files under \"hidden\" must be hidden here."
  (bl.rpc::register-all-methods)
  (let ((uncategorized '())
        (disagreeing '()))
    (maphash (lambda (name handler)
               (declare (ignore handler))
               (let ((category (bl.rpc::rpc-method-category name)))
                 (when (or (null category) (string= category ""))
                   (push name uncategorized))
                 (when (and category
                            (not (eq (and (string= category "hidden") t)
                                     (bl.rpc::rpc-method-hidden-p name))))
                   (push name disagreeing))))
             bl.rpc::*rpc-methods*)
    (is (null uncategorized)
        "~D registered methods carry no category: ~S"
        (length uncategorized) uncategorized)
    (is (null disagreeing)
        "the category table and the hidden list disagree about: ~S"
        disagreeing)))

(test getpeerinfo-help-names-the-networks-it-can-report
  "Core documents getpeerinfo's `network' field with the list it generates
from the Network enum itself (rpc/net.cpp:137):

    {RPCResult::Type::STR, \"network\",
     \"Network (\" + Join(GetNetworkNames(/*append_unroutable=*/true), \", \")
     + \")\"}

and rpc_net.py:131 greps the rendered help for that parenthesised list:

    assert \"(ipv4, ipv6, onion, i2p, cjdns, not_publicly_routable)\" in
           self.nodes[0].help(\"getpeerinfo\")

It is a check on the node, not on prose: the same NETWORK-NAMES list is what
getaddrmaninfo enumerates, so a network this node learns to speak cannot
appear in one and not the other."
  (let* ((node (make-test-node))
         (text (bl.rpc:dispatch-rpc-method
                node "help" (wire-params (list "getpeerinfo")))))
    (is (eql 0 (search (format nil "getpeerinfo~%~%") text)))
    (is-true (search "(ipv4, ipv6, onion, i2p, cjdns, not_publicly_routable)" text)
             "getpeerinfo's help did not name the networks: ~S" text)
    ;; The same list drives getaddrmaninfo's per-network counts, so the help
    ;; cannot drift from what the node reports.
    (let ((counts (bl.rpc:dispatch-rpc-method
                   node "getaddrmaninfo" (wire-params '()))))
      (dolist (name '("ipv4" "ipv6" "onion" "i2p" "cjdns"))
        (is-true (assoc name counts :test #'string=)
                 "getaddrmaninfo reports no ~A row" name))
      ;; not_publicly_routable is documented but never counted, as in Core.
      (is-false (assoc "not_publicly_routable" counts :test #'string=)))
    ;; getnetworkinfo is the OTHER caller of the same list, and it takes it
    ;; WITHOUT the unroutable name: its `networks' array is one object per
    ;; routable network (Core rpc/net.cpp:735, Join(GetNetworkNames())).
    ;; rpc_net.py:243 greps its help for that shorter list, which was absent.
    (let ((text (bl.rpc:dispatch-rpc-method
                 node "help" (wire-params (list "getnetworkinfo")))))
      (is-true (search "(ipv4, ipv6, onion, i2p, cjdns)" text)
               "getnetworkinfo's help did not name the networks: ~S" text)
      (is-false (search "not_publicly_routable" text)
                "and it must not name the unroutable one"))))

;;; --- signrawtransactionwithkey over a pay-to-anchor input -------------------

(test signrawtransactionwithkey-signs-a-pay-to-anchor-input-with-nothing
  "A pay-to-anchor output (OP_1 <0x4e73>) is spent with an empty scriptSig and
an empty witness: Core's SignStep answers it `return true;' with an EMPTY
result (sign.cpp:706-707), ProduceSignature reaches none of its witness
branches for TxoutType::ANCHOR so the stack is cleared and PushAll({}) is the
scriptSig (:782-796), and VerifyScript passes on the interpreter's own anchor
carve-out (interpreter.cpp:1990-1991). SIGNING ONE SUCCEEDS AND CHANGES
NOTHING -- it takes no key and needs none, which is the point of the output
type.

Ours fell through to the unsupported-scriptPubKey-type arm and reported an
error for an input nothing was wrong with:

    spending_tx_signed = self.nodes[0].signrawtransactionwithkey(spending_tx, [], [])
    assert 'errors' not in signed_tx                       (rpc_signrawtransactionwithkey.py:57)
    assert_equal(spending_tx, spending_tx_signed[\"hex\"])   (:108)

both reached with NO keys and NO prevtxs at all (:98-108)."
  (let* ((node (make-test-node))
         (anchor-spk (coerce #(#x51 #x02 #x4e #x73)
                             '(simple-array (unsigned-byte 8) (*))))
         (prev-hash (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element #x11))
         (tx (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output (bl.ser:make-outpoint
                                                 :hash prev-hash :index 0)
                               :script-sig (make-array 0 :element-type
                                                       '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out
                                :value 99000 :script-pubkey anchor-spk))
              :lock-time 0))
         (hex (bl.crypto:bytes-to-hex (bl.ser:transaction-wire-bytes tx)))
         (prevtx (list (cons "txid" (bl.rpc:hash-to-hex prev-hash))
                       (cons "vout" 0)
                       (cons "scriptPubKey" (bl.crypto:bytes-to-hex anchor-spk))
                       ;; The amount as a client sends one, in BTC.
                       (cons "amount" "0.00100000")))
         (result (bl.rpc:dispatch-rpc-method
                  node "signrawtransactionwithkey"
                  ;; An empty privkeys ARRAY, not a null: `privkeys' is
                  ;; RPCArg::Optional::NO (rawtransaction.cpp:683), so the
                  ;; wire spelling of "no keys" is [] and a null is a type
                  ;; error. #() is what WIRE-PARAMS turns into the sentinel.
                  (wire-params (list hex #() (list prevtx))))))
    (flet ((field (name) (cdr (assoc name result :test #'string=))))
      (is (eq t (field "complete"))
          "a P2A input needs no key, so signing it is complete")
      (is-false (assoc "errors" result :test #'string=)
                "Core omits `errors' entirely when there are none; got ~S"
                (field "errors"))
      ;; Signing a P2A prevout is a no-op, so the bytes are unchanged.
      (is (string= hex (field "hex"))))))

;;; --- decodescript's segwit descriptor ---------------------------------------

(test decodescript-infers-the-wsh-miniscript-core-infers
  "Core's decodescript files the script it was handed in a FlatSigningProvider
under the P2WSH program it derives from it --
`provider.scripts[CScriptID(script)] = script' (rpc/rawtransaction.cpp:571) --
and hands that provider to ScriptToUniv for the segwit object (:574). So
InferDescriptor recurses INTO the witness program (descriptor.cpp:2755-2762)
and, in P2WSH context, reaches the miniscript arm: a sane node becomes a
MiniscriptDescriptor (:2805-2818).

Ours passed no provider, so every segwit object read addr(<the program's own
address>) -- true, and much less than Core says. rpc_decodescript.py's three
miniscript vectors (:280-287) are the exact difference: two that infer, and
one that does NOT (an uncompressed key inside a P2WSH is not a valid
miniscript key), which is the control that the arm is not simply naming
everything wsh()."
  (let ((node (make-test-node :network :regtest)))
    (flet ((segwit-desc (hex)
             (let ((result (bl.rpc:dispatch-rpc-method
                            node "decodescript" (wire-params (list hex)))))
               (cdr (assoc "desc" (cdr (assoc "segwit" result :test #'string=))
                           :test #'string=)))))
      ;; Miniscript-compatible offered HTLC (rpc_decodescript.py:280-281).
      (is (string= "wsh(and_v(and_v(v:hash160(ffffffffffffffffffffffffffffffffffffffff),v:pk(0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)),older(1)))#gm8xz4fl"
                   (segwit-desc "82012088a914ffffffffffffffffffffffffffffffffffffffff88210250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0ad51b2")))
      ;; The SAME shape with a key that is not on the curve: not a miniscript,
      ;; so Core falls back to the program's address (:283-284).
      (is (string= "addr(bcrt1q73qyfypp47hvgnkjqnav0j3k2lq3v76wg22dk8tmwuz5sfgv66xsvxg6uu)#9p3q328s"
                   (segwit-desc "82012088a914ffffffffffffffffffffffffffffffffffffffff882102ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffacb2")))
      ;; A miniscript bigger than the 520-byte P2SH limit still infers, because
      ;; the P2WSH ceiling is the one that applies (:285-287).
      (is (string= "wsh(or_d(multi(11,020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b67817261,02675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af99,02896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d48,029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c,02a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc4010,031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb,03079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b,03111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2,0318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa0840174,03230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de1,035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a6,03bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c,03cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d17546,03d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d424828,03ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a),and_v(v:older(4032),multi(2,03aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79,0291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807,0386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb))))#7jwwklk4"
                   (segwit-desc "5b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc401021031c41fdbcebe17bec8d49816e00ca1b5ac34766b91c9f2ac37d39c63e5e008afb2103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5fae736402c00fb269522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb53ae68")))
      ;; Control: the TOP-level `desc' is still the no-provider answer -- raw()
      ;; for a nonstandard script, as Core's is.
      (let ((result (bl.rpc:dispatch-rpc-method
                     node "decodescript"
                     (wire-params
                      (list "82012088a914ffffffffffffffffffffffffffffffffffffffff88210250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0ad51b2")))))
        (is (eql 0 (search "raw(" (cdr (assoc "desc" result :test #'string=)))))))))

(test signing-in-place-drops-every-cache-measured-before-the-signature
  "A transaction memoizes its txid, its wtxid and its weight, and the in-place
signer (SIGN-TX-INPUTS, shared by signrawtransactionwithkey and the wallet)
writes scriptSigs and witnesses into the very object that carries those memos.
Bitcoin Core cannot reach this: CTransaction is immutable and caches at
construction, and everything that CHANGES a transaction works on a
CMutableTransaction, which caches nothing (primitives/transaction.h:395-420 vs
:329-341). So every value measured before signing has to be dropped at the
mutation.

Two shapes, because they go stale differently: a LEGACY input's scriptSig is
part of the txid, and a segwit input's witness is part of the weight and the
wtxid alone. wallet_spend_unconfirmed.py:333 is what this cost -- a fee-bump
priced at its target reported 66.6 sat/vB against 60, because the floor check
had asked the unsigned replacement its vsize."
  (let* ((k (let ((b (make-array 32 :element-type '(unsigned-byte 8)
                                   :initial-element 0)))
              (setf (aref b 31) 7) b))
         (pub (bl.crypto:derive-public-key k))
         (pkh (bl.crypto:hash160 pub))
         (p2pkh (concatenate '(vector (unsigned-byte 8))
                             (vector #x76 #xa9 #x14) pkh (vector #x88 #xac)))
         (p2wpkh (concatenate '(vector (unsigned-byte 8)) (vector #x00 #x14) pkh)))
    (flet ((unsigned-tx (prev-byte)
             (bl.ser:make-transaction
              :version 2
              :inputs (vector (bl.ser:make-tx-in
                               :previous-output
                               (bl.ser:make-outpoint
                                :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                     :initial-element prev-byte)
                                :index 0)
                               :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                               :sequence #xffffffff))
              :outputs (vector (bl.ser:make-tx-out :value 90000 :script-pubkey p2pkh))
              :lock-time 0))
           (sign (tx spk)
             (let ((prevmap (make-hash-table :test (quote equalp)))
                   (keymap (make-hash-table :test (quote equalp)))
                   (pubmap (make-hash-table :test (quote equalp)))
                   (tr-keymap (make-hash-table :test (quote equalp)))
                   (op (bl.ser:tx-in-previous-output
                        (aref (bl.ser:transaction-inputs tx) 0))))
               (setf (gethash (cons (bl.ser:outpoint-hash op) 0) prevmap)
                     (list spk 100000 nil nil)
                     (gethash (bl.crypto:hash160 pub) keymap) (cons k pub)
                     (gethash pub pubmap) k)
               (bl.rpc:sign-tx-inputs tx prevmap keymap pubmap tr-keymap 1))))
      ;; --- legacy P2PKH: the scriptSig is part of the txid ---
      (let* ((tx (unsigned-tx 21))
             (weight-before (bl.ser:transaction-weight tx))
             (txid-before (bl.ser:transaction-hash tx))
             (wtxid-before (bl.ser:transaction-wtxid tx)))
        (is (null (sign tx p2pkh)))
        (is (plusp (length (bl.ser:tx-in-script-sig
                            (aref (bl.ser:transaction-inputs tx) 0))))
            "control: the signer wrote a scriptSig")
        ;; The memos must agree with the bytes the object now holds.
        (is (= (* 4 (length (bl.ser:serialize-transaction tx)))
               (bl.ser:transaction-weight tx)))
        (is (equalp (bl.crypto:hash256 (bl.ser:serialize-transaction tx))
                    (bl.ser:transaction-hash tx)))
        (is (equalp (bl.ser:transaction-hash tx) (bl.ser:transaction-wtxid tx)))
        (is (/= weight-before (bl.ser:transaction-weight tx)))
        (is (not (equalp txid-before (bl.ser:transaction-hash tx))))
        (is (not (equalp wtxid-before (bl.ser:transaction-wtxid tx)))))
      ;; --- P2WPKH: the witness is part of the weight and the wtxid ---
      (let* ((tx (unsigned-tx 22))
             (weight-before (bl.ser:transaction-weight tx))
             (txid-before (bl.ser:transaction-hash tx))
             (wtxid-before (bl.ser:transaction-wtxid tx)))
        (is (null (sign tx p2wpkh)))
        (is-true (bl.ser:transaction-has-witness-p tx)
                 "control: the signer installed a witness")
        (is (= (+ (* 3 (length (bl.ser:serialize-transaction tx)))
                  (length (bl.ser:serialize-witness-transaction tx)))
               (bl.ser:transaction-weight tx)))
        (is (equalp (bl.crypto:hash256 (bl.ser:serialize-witness-transaction tx))
                    (bl.ser:transaction-wtxid tx)))
        (is (/= weight-before (bl.ser:transaction-weight tx)))
        ;; A segwit spend's TXID does not move -- its scriptSig stayed empty.
        (is (equalp txid-before (bl.ser:transaction-hash tx)))
        (is (not (equalp wtxid-before (bl.ser:transaction-wtxid tx)))))
      ;; The helper every mutation site calls, asserted LAST so a pre-fix
      ;; control reports the behavioural failures above and not this.
      (let ((tx (unsigned-tx 23)))
        (bl.ser:transaction-weight tx)
        (bl.ser:transaction-hash tx)
        (bl.ser:transaction-wtxid tx)
        (setf (bl.ser:tx-in-script-sig (aref (bl.ser:transaction-inputs tx) 0))
              (make-array 5 :element-type '(unsigned-byte 8) :initial-element 1))
        (bl.ser:invalidate-transaction-caches tx)
        (is (= (* 4 (length (bl.ser:serialize-transaction tx)))
               (bl.ser:transaction-weight tx)))
        (is (equalp (bl.crypto:hash256 (bl.ser:serialize-transaction tx))
                    (bl.ser:transaction-hash tx)))
        (is (equalp (bl.ser:transaction-hash tx)
                    (bl.ser:transaction-wtxid tx)))))))

(test a-transaction-with-no-inputs-decodes-to-an-empty-vin-array
  "Core's TxToUniv builds vin and vout as UniValue::VARR and pushes each entry
into it (core_io.cpp:455-525), so a transaction with NO inputs decodes to
`\"vin\": []'. A zero-input transaction is an ordinary argument, not a
malformed one: createrawtransaction([], {...}) is the standard way to start a
raw transaction, and wallet_fundrawtransaction.py:731-736 decodes an
OP_RETURN-only template and asks len(dec_tx['vin']).

Ours rendered the empty list as JSON `null', which is not a length."
  (let* ((node (make-test-node :network :regtest))
         ;; The OP_RETURN template of wallet_fundrawtransaction.py:731:
         ;; version 1, no inputs, one 0-value OP_RETURN "test" output.
         (hex "0100000000010000000000000000066a047465737400000000")
         (decoded (bl.rpc:dispatch-rpc-method node "decoderawtransaction"
                                              (wire-params (list hex))))
         (vin (cdr (assoc "vin" decoded :test #'string=)))
         (vout (cdr (assoc "vout" decoded :test #'string=))))
    (is (zerop (length vin)) "vin must be an empty sequence, got ~S" vin)
    (is (not (null vin)) "vin must be an empty ARRAY, not JSON null")
    (is (= 1 (length vout)))
    ;; The control: a transaction WITH an input still decodes its inputs.
    (let* ((with-input (bl.rpc:dispatch-rpc-method
                        node "decoderawtransaction"
                        (wire-params
                         (list (one-input-tx-hex
                                (make-string 64 :initial-element #\3) 0
                                (bl.crypto:hex-to-bytes "6a0474657374"))))))
           (ins (cdr (assoc "vin" with-input :test #'string=))))
      (is (= 1 (length ins))))))
