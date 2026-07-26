(in-package #:bitcoin-lisp.rpc)

;;; JSON-RPC 2.0 Server
;;;
;;; Implements Bitcoin Core-compatible RPC interface over HTTP.

;;; --- Error Codes ---

(defconstant +rpc-parse-error+ -32700)
(defconstant +rpc-invalid-request+ -32600)
(defconstant +rpc-method-not-found+ -32601)
(defconstant +rpc-invalid-params+ -32602)
(defconstant +rpc-internal-error+ -32603)
(defconstant +rpc-misc-error+ -1)
(defconstant +rpc-type-error+ -3)
(defconstant +rpc-invalid-address-or-key+ -5)
(defconstant +rpc-invalid-parameter+ -8)
(defconstant +rpc-client-not-connected+ -9)
(defconstant +rpc-client-in-initial-download+ -10)
(defconstant +rpc-deserialization-error+ -22)
(defconstant +rpc-client-node-already-added+ -23)
(defconstant +rpc-client-node-not-added+ -24)
(defconstant +rpc-verify-error+ -25)
(defconstant +rpc-transaction-rejected+ -26)
(defconstant +rpc-verify-already-in-utxo-set+ -27)
(defconstant +rpc-client-node-not-connected+ -29)
(defconstant +rpc-client-invalid-ip-or-subnet+ -30)
(defconstant +rpc-method-deprecated+ -32)
(defconstant +rpc-client-mempool-disabled+ -33)

;;; --- RPC Error Condition ---

(define-condition rpc-error (error)
  ((code :initarg :code :reader rpc-error-code)
   (message :initarg :message :reader rpc-error-message)
   (data :initarg :data :initform nil :reader rpc-error-data))
  (:report (lambda (c s)
             (format s "RPC Error ~A: ~A" (rpc-error-code c) (rpc-error-message c)))))

;;; --- Method Registry ---

(defvar *rpc-methods* (make-hash-table :test 'equal)
  "Registry mapping method names to handler functions.")

(defun register-rpc-method (name handler)
  "Register an RPC method handler."
  (setf (gethash name *rpc-methods*) handler))

(defun dispatch-rpc-method (node method params)
  "Dispatch to the appropriate method handler."
  (let ((handler (gethash method *rpc-methods*)))
    (unless handler
      ;; Core's exact message (server.cpp:499) — no method-name suffix.
      (error 'rpc-error :code +rpc-method-not-found+
                        :message "Method not found"))
    (funcall handler node params)))

;;; --- Register All Methods ---

(defun register-all-methods ()
  "Register all RPC methods."
  ;; Blockchain
  (register-rpc-method "getblockchaininfo" #'rpc-getblockchaininfo)
  (register-rpc-method "getbestblockhash" #'rpc-getbestblockhash)
  (register-rpc-method "getblockcount" #'rpc-getblockcount)
  (register-rpc-method "getblockhash" #'rpc-getblockhash)
  (register-rpc-method "getblock" #'rpc-getblock)
  (register-rpc-method "getblockheader" #'rpc-getblockheader)
  (register-rpc-method "getchaintips" #'rpc-getchaintips)
  (register-rpc-method "scantxoutset" #'rpc-scantxoutset)
  (register-rpc-method "getblockfilter" #'rpc-getblockfilter)
  (register-rpc-method "scanblocks" #'rpc-scanblocks)
  (register-rpc-method "getdescriptoractivity" #'rpc-getdescriptoractivity)
  (register-rpc-method "createpsbt" #'rpc-createpsbt)
  (register-rpc-method "converttopsbt" #'rpc-converttopsbt)
  (register-rpc-method "decodepsbt" #'rpc-decodepsbt)
  (register-rpc-method "combinepsbt" #'rpc-combinepsbt)
  (register-rpc-method "joinpsbts" #'rpc-joinpsbts)
  (register-rpc-method "utxoupdatepsbt" #'rpc-utxoupdatepsbt)
  (register-rpc-method "analyzepsbt" #'rpc-analyzepsbt)
  (register-rpc-method "finalizepsbt" #'rpc-finalizepsbt)
  (register-rpc-method "descriptorprocesspsbt" #'rpc-descriptorprocesspsbt)
  (register-rpc-method "combinerawtransaction" #'rpc-combinerawtransaction)
  (register-rpc-method "gettxoutproof" #'rpc-gettxoutproof)
  (register-rpc-method "verifytxoutproof" #'rpc-verifytxoutproof)
  (register-rpc-method "getdescriptorinfo" #'rpc-getdescriptorinfo)
  (register-rpc-method "deriveaddresses" #'rpc-deriveaddresses)
  ;; UTXO
  (register-rpc-method "gettxout" #'rpc-gettxout)
  ;; Network
  (register-rpc-method "getpeerinfo" #'rpc-getpeerinfo)
  (register-rpc-method "getnetworkinfo" #'rpc-getnetworkinfo)
  (register-rpc-method "getconnectioncount" #'rpc-getconnectioncount)
  (register-rpc-method "ping" #'rpc-ping)
  ;; Mempool
  (register-rpc-method "getmempoolinfo" #'rpc-getmempoolinfo)
  (register-rpc-method "getrawmempool" #'rpc-getrawmempool)
  (register-rpc-method "getorphantxs" #'rpc-getorphantxs)
  (register-rpc-method "getmempoolentry" #'rpc-getmempoolentry)
  (register-rpc-method "prioritisetransaction" #'rpc-prioritisetransaction)
  (register-rpc-method "getprioritisedtransactions" #'rpc-getprioritisedtransactions)
  (register-rpc-method "savemempool" #'rpc-savemempool)
  (register-rpc-method "importmempool" #'rpc-importmempool)
  (register-rpc-method "getmempoolancestors" #'rpc-getmempoolancestors)
  (register-rpc-method "getmempooldescendants" #'rpc-getmempooldescendants)
  ;; Cluster mempool (Core rpc/mempool.cpp:1516 getmempoolcluster, :1519
  ;; getmempoolfeeratediagram — the latter hidden in Core's help).
  (register-rpc-method "getmempoolcluster" #'rpc-getmempoolcluster)
  (register-rpc-method "getmempoolfeeratediagram" #'rpc-getmempoolfeeratediagram)
  (register-rpc-method "gettxspendingprevout" #'rpc-gettxspendingprevout)
  ;; Node / chain info methods
  (register-rpc-method "getdifficulty" #'rpc-getdifficulty)
  (register-rpc-method "uptime" #'rpc-uptime)
  (register-rpc-method "getindexinfo" #'rpc-getindexinfo)
  (register-rpc-method "getdeploymentinfo" #'rpc-getdeploymentinfo)
  (register-rpc-method "getchainstates" #'rpc-getchainstates)
  ;; Operator / control methods
  (register-rpc-method "stop" #'rpc-stop)
  (register-rpc-method "help" #'rpc-help)
  (register-rpc-method "getrpcinfo" #'rpc-getrpcinfo)
  (register-rpc-method "getmemoryinfo" #'rpc-getmemoryinfo)
  (register-rpc-method "getnetworkhashps" #'rpc-getnetworkhashps)
  (register-rpc-method "logging" #'rpc-logging)
  ;; Peer / address methods
  (register-rpc-method "getnodeaddresses" #'rpc-getnodeaddresses)
  (register-rpc-method "getaddrmaninfo" #'rpc-getaddrmaninfo)
  (register-rpc-method "addnode" #'rpc-addnode)
  (register-rpc-method "getaddednodeinfo" #'rpc-getaddednodeinfo)
  (register-rpc-method "setnetworkactive" #'rpc-setnetworkactive)
  (register-rpc-method "getblockfrompeer" #'rpc-getblockfrompeer)
  (register-rpc-method "disconnectnode" #'rpc-disconnectnode)
  (register-rpc-method "getnettotals" #'rpc-getnettotals)
  ;; Manual ban management
  (register-rpc-method "setban" #'rpc-setban)
  (register-rpc-method "listbanned" #'rpc-listbanned)
  (register-rpc-method "clearbanned" #'rpc-clearbanned)
  ;; Chain verification
  (register-rpc-method "verifychain" #'rpc-verifychain)
  (register-rpc-method "getchaintxstats" #'rpc-getchaintxstats)
  (register-rpc-method "waitfornewblock" #'rpc-waitfornewblock)
  (register-rpc-method "waitforblock" #'rpc-waitforblock)
  (register-rpc-method "waitforblockheight" #'rpc-waitforblockheight)
  (register-rpc-method "dumptxoutset" #'rpc-dumptxoutset)
  (register-rpc-method "loadtxoutset" #'rpc-loadtxoutset)
  ;; Chain control methods
  (register-rpc-method "invalidateblock" #'rpc-invalidateblock)
  (register-rpc-method "reconsiderblock" #'rpc-reconsiderblock)
  (register-rpc-method "preciousblock" #'rpc-preciousblock)
  (register-rpc-method "sendrawtransaction" #'rpc-sendrawtransaction)
  (register-rpc-method "testmempoolaccept" #'rpc-testmempoolaccept)
  (register-rpc-method "submitpackage" #'rpc-submitpackage)
  ;; Mining methods
  (register-rpc-method "getblocktemplate" #'rpc-getblocktemplate)
  (register-rpc-method "getmininginfo" #'rpc-getmininginfo)
  (register-rpc-method "submitblock" #'rpc-submitblock)
  (register-rpc-method "submitheader" #'rpc-submitheader)
  (register-rpc-method "generatetoaddress" #'rpc-generatetoaddress)
  (register-rpc-method "generatetodescriptor" #'rpc-generatetodescriptor)
  (register-rpc-method "generateblock" #'rpc-generateblock)
  ;; Raw transaction methods
  (register-rpc-method "decoderawtransaction" #'rpc-decoderawtransaction)
  (register-rpc-method "getrawtransaction" #'rpc-getrawtransaction)
  (register-rpc-method "createrawtransaction" #'rpc-createrawtransaction)
  ;; Utility methods
  (register-rpc-method "estimatesmartfee" #'rpc-estimatesmartfee)
  (register-rpc-method "validateaddress" #'rpc-validateaddress)
  (register-rpc-method "createmultisig" #'rpc-createmultisig)
  (register-rpc-method "decodescript" #'rpc-decodescript)
  (register-rpc-method "signmessagewithprivkey" #'rpc-signmessagewithprivkey)
  (register-rpc-method "verifymessage" #'rpc-verifymessage)
  (register-rpc-method "signrawtransactionwithkey" #'rpc-signrawtransactionwithkey)
  ;; UTXO set statistics
  (register-rpc-method "gettxoutsetinfo" #'rpc-gettxoutsetinfo)
  ;; Block statistics
  (register-rpc-method "getblockstats" #'rpc-getblockstats)
  ;; Pruning
  (register-rpc-method "pruneblockchain" #'rpc-pruneblockchain)
  ;; Wallet (wallet P1; handlers reject with method-not-found when the node
  ;; runs without wallet support, matching a no-wallet Core build)
  (register-rpc-method "createwallet" #'rpc-createwallet)
  (register-rpc-method "loadwallet" #'rpc-loadwallet)
  (register-rpc-method "unloadwallet" #'rpc-unloadwallet)
  (register-rpc-method "listwallets" #'rpc-listwallets)
  (register-rpc-method "listwalletdir" #'rpc-listwalletdir)
  (register-rpc-method "getwalletinfo" #'rpc-getwalletinfo)
  (register-rpc-method "getnewaddress" #'rpc-getnewaddress)
  (register-rpc-method "getrawchangeaddress" #'rpc-getrawchangeaddress)
  (register-rpc-method "listdescriptors" #'rpc-listdescriptors)
  (register-rpc-method "importdescriptors" #'rpc-importdescriptors)
  ;; Wallet chain tracking (wallet P2)
  (register-rpc-method "gettransaction" #'rpc-gettransaction)
  (register-rpc-method "listtransactions" #'rpc-listtransactions)
  (register-rpc-method "listsinceblock" #'rpc-listsinceblock)
  (register-rpc-method "rescanblockchain" #'rpc-rescanblockchain)
  (register-rpc-method "abortrescan" #'rpc-abortrescan)
  ;; Wallet balances & coins (wallet P3)
  (register-rpc-method "getbalance" #'rpc-getbalance)
  (register-rpc-method "getbalances" #'rpc-getbalances)
  (register-rpc-method "listunspent" #'rpc-listunspent)
  (register-rpc-method "lockunspent" #'rpc-lockunspent)
  (register-rpc-method "listlockunspent" #'rpc-listlockunspent)
  (register-rpc-method "getaddressinfo" #'rpc-getaddressinfo)
  (register-rpc-method "setlabel" #'rpc-setlabel)
  (register-rpc-method "getaddressesbylabel" #'rpc-getaddressesbylabel)
  (register-rpc-method "listlabels" #'rpc-listlabels)
  (register-rpc-method "abandontransaction" #'rpc-abandontransaction)
  ;; Wallet read/aggregation (wallet P7)
  (register-rpc-method "signmessage" #'rpc-signmessage)
  (register-rpc-method "getreceivedbyaddress" #'rpc-getreceivedbyaddress)
  (register-rpc-method "getreceivedbylabel" #'rpc-getreceivedbylabel)
  (register-rpc-method "listreceivedbyaddress" #'rpc-listreceivedbyaddress)
  (register-rpc-method "listreceivedbylabel" #'rpc-listreceivedbylabel)
  (register-rpc-method "keypoolrefill" #'rpc-keypoolrefill)
  (register-rpc-method "simulaterawtransaction" #'rpc-simulaterawtransaction)
  (register-rpc-method "listaddressgroupings" #'rpc-listaddressgroupings)
  ;; Wallet spending (wallet P4)
  (register-rpc-method "sendtoaddress" #'rpc-sendtoaddress)
  (register-rpc-method "sendmany" #'rpc-sendmany)
  (register-rpc-method "send" #'rpc-send)
  (register-rpc-method "sendall" #'rpc-sendall)
  (register-rpc-method "fundrawtransaction" #'rpc-fundrawtransaction)
  (register-rpc-method "signrawtransactionwithwallet" #'rpc-signrawtransactionwithwallet)
  ;; Wallet PSBT signer + RBF fee-bump (wallet P5)
  (register-rpc-method "walletprocesspsbt" #'rpc-walletprocesspsbt)
  (register-rpc-method "walletcreatefundedpsbt" #'rpc-walletcreatefundedpsbt)
  (register-rpc-method "bumpfee" #'rpc-bumpfee)
  (register-rpc-method "psbtbumpfee" #'rpc-psbtbumpfee))

;;; --- JSON-RPC Request/Response Handling ---

(defun %normalize-json-value (value top-level)
  "Boolean normalization of a parsed request value (booleans arrive as
'yason:true / 'yason:false from the symbols parse mode): true -> T
everywhere; false -> the +json-false+ sentinel when TOP-LEVEL (a direct
positional parameter — handlers read those through %positional-bool so
explicit false, null, and omitted are distinguishable, Core's isNull
semantics), NIL inside nested arrays/objects (the historical folding —
object readers distinguish absence via present-p). Hash tables are
normalized in place; lists are rebuilt."
  (cond ((eq value 'yason:true) t)
        ((eq value 'yason:false) (if top-level +json-false+ nil))
        ((hash-table-p value)
         (maphash (lambda (key v)
                    (setf (gethash key value) (%normalize-json-value v nil)))
                  value)
         value)
        ((and (consp value) (rpc-proper-list-p value))
         (mapcar (lambda (v) (%normalize-json-value v nil)) value))
        (t value)))

(defun %normalize-rpc-params (params)
  "Normalize a request's params: positional (array) params keep explicit
false as the +json-false+ sentinel at top level; named-params objects are
normalized as nested values."
  (if (and (consp params) (rpc-proper-list-p params))
      (mapcar (lambda (v) (%normalize-json-value v t)) params)
      (%normalize-json-value params nil)))

(defun request-json-version (request)
  "The JSON-RPC version of one parsed request object REQUEST (a hash-table):
:V2 only for the exact marker jsonrpc:\"2.0\", else :V1 — an absent member,
\"1.0\" or \"1.1\" all mean legacy 1.x, which is Core's V1_LEGACY default
(JSONRPCRequest::parse, rpc/request.cpp:212-227)."
  (if (equal (gethash "jsonrpc" request) "2.0") :v2 :v1))

(defun parse-json-rpc-request (body)
  "Parse JSON-RPC request body. Returns (values :single method params id
version id-present-p) or (values :batch requests). VERSION is :v2 when the
request carries jsonrpc:\"2.0\", else :v1 (absent/1.0/1.1 — Core JSONRPCRequest
::parse's V1_LEGACY); ID-PRESENT-P distinguishes a V2 notification (no id
member at all) from id:null. Signals rpc-error on malformed input.
Booleans are parsed as symbols and normalized via %normalize-rpc-params so
top-level positional false survives as the +json-false+ sentinel."
  (handler-case
      (let ((json (let ((yason:*parse-json-booleans-as-symbols* t))
                    (yason:parse body))))
        (cond
          ;; Batch request (array)
          ((listp json)
           (values :batch json))
          ;; Single request (object)
          ((hash-table-p json)
           (let ((method (gethash "method" json))
                 (params (gethash "params" json))
                 (version (request-json-version json)))
             ;; Accept any/absent "jsonrpc" version: bitcoin-cli sends 1.0 (or
             ;; omits it) on older builds and 2.0 on newer; Core doesn't
             ;; validate it. Rejecting non-2.0 made stock bitcoin-cli unusable.
             (unless (stringp method)
               (error 'rpc-error :code +rpc-invalid-request+
                                 :message "Missing or invalid method"))
             (multiple-value-bind (id id-present) (gethash "id" json)
               (values :single method (%normalize-rpc-params (or params '()))
                       id version
                       (and id-present t)))))
          (t
           (error 'rpc-error :code +rpc-invalid-request+
                             :message "Invalid request format"))))
    ;; Our own -32600 invalid-request errors must pass through unchanged;
    ;; only a genuine JSON parse failure is -32700 (previously the outer
    ;; clause swallowed them into "Parse error").
    (rpc-error (e) (error e))
    (error (e)
      (declare (ignore e))
      (error 'rpc-error :code +rpc-parse-error+
                        :message "Parse error"))))

(defun rpc-proper-list-p (x)
  "True if X is a proper (nil-terminated) list."
  (loop for tail = x then (cdr tail)
        while (consp tail)
        finally (return (null tail))))

(defun rpc-object-alist-p (x)
  "True if X is a non-empty proper list whose every element is a (string-key . value)
cons — i.e. an alist that should serialize as a JSON object. A list whose elements
are themselves lists/alists (e.g. an array of objects) is NOT an object-alist."
  (and (consp x)
       (rpc-proper-list-p x)
       (every (lambda (e) (and (consp e) (stringp (car e)))) x)))

(defun rpc-result->json (x)
  "Normalize an RPC handler result for yason: object-alists become hash-tables
(JSON objects), other proper lists become arrays (recursing into elements), and
atoms pass through unchanged. RPC methods build results as alists, but yason's
default list encoder treats every list as an array and chokes on the dotted
pairs — so without this every object-returning RPC errors out."
  (cond
    ((rpc-object-alist-p x)
     (let ((ht (make-hash-table :test 'equal)))
       (dolist (pair x ht)
         (setf (gethash (car pair) ht) (rpc-result->json (cdr pair))))))
    ((and (consp x) (rpc-proper-list-p x))
     (mapcar #'rpc-result->json x))
    (t x)))

(defun %make-rpc-reply (result error-obj id version id-present)
  "Assemble a JSON-RPC reply the way Core's JSONRPCReplyObj does
(rpc/request.cpp:51-68) — the one place that knows how a reply's shape depends
on the request's VERSION (:v1 or :v2):
- the \"jsonrpc\" key is emitted for :V2 ONLY (:55);
- a legacy 1.x reply carries BOTH \"result\" and \"error\", one of them null
  (:57-64). python-bitcoinrpc's AuthServiceProxy does
  `if response['error'] is not None:` and so raises KeyError: 'error' on every
  successful call against a reply that omits it. NIL encodes as JSON null;
- \"id\" is omitted entirely when the request carried no id member (:66,
  id = std::nullopt at request.cpp:207-211) — that is ID-PRESENT NIL.
ERROR-OBJ NIL means success. Anything other than :V2 is treated as legacy 1.x,
matching Core's V1_LEGACY default for a request with no \"jsonrpc\" member."
  (let ((response (make-hash-table :test 'equal))
        (v2 (eq version :v2)))
    (when v2
      (setf (gethash "jsonrpc" response) "2.0"))
    (cond ((null error-obj)
           (setf (gethash "result" response) result)
           (unless v2
             (setf (gethash "error" response) nil)))
          (t
           (unless v2
             (setf (gethash "result" response) nil))
           (setf (gethash "error" response) error-obj)))
    (when id-present
      (setf (gethash "id" response) id))
    response))

(defun make-rpc-response (result id version &key (id-present t))
  "Create a successful JSON-RPC response for a request of VERSION (:v1 or :v2);
see %MAKE-RPC-REPLY for the version-dependent shape."
  (%make-rpc-reply (rpc-result->json result) nil id version id-present))

(defun make-rpc-error-response (code message id version &key data (id-present t))
  "Create an error JSON-RPC response for a request of VERSION (:v1 or :v2);
see %MAKE-RPC-REPLY for the version-dependent shape."
  (let ((error-obj (make-hash-table :test 'equal)))
    (setf (gethash "code" error-obj) code)
    (setf (gethash "message" error-obj) message)
    (when data
      (setf (gethash "data" error-obj) (rpc-result->json data)))
    (%make-rpc-reply nil error-obj id version id-present)))

(defun handle-single-request (node method params id version &key (id-present t))
  "Handle a single RPC request. VERSION and ID-PRESENT come from the parsed
request and shape the reply (see MAKE-RPC-RESPONSE)."
  (handler-case
      (let ((result (dispatch-rpc-method node method params)))
        (make-rpc-response result id version :id-present id-present))
    (rpc-error (e)
      (make-rpc-error-response (rpc-error-code e)
                               (rpc-error-message e)
                               id version
                               :data (rpc-error-data e)
                               :id-present id-present))
    (error (e)
      (bitcoin-lisp::node-log :error "RPC internal error: ~A" e)
      (make-rpc-error-response +rpc-internal-error+
                               (format nil "Internal error: ~A" e)
                               id version
                               :id-present id-present))))

(defun handle-batch-request (node requests)
  "Handle a batch of RPC requests, returning the list of replies to send.
Core re-parses every batch member on its own (httprpc.cpp:194-206), so version
and id-presence are PER MEMBER; a 2.0 notification (no id member) is executed
but contributes no reply at all (:207-209)."
  (let ((responses '()))
    (dolist (req requests (nreverse responses))
      (if (hash-table-p req)
          (let ((method (gethash "method" req))
                (params (%normalize-rpc-params
                         (or (gethash "params" req) '())))
                (version (request-json-version req)))
            (multiple-value-bind (id id-present) (gethash "id" req)
              (let ((response
                      (if (stringp method)
                          (handle-single-request node method params id version
                                                 :id-present id-present)
                          (make-rpc-error-response +rpc-invalid-request+
                                                   "Missing or invalid method"
                                                   id version
                                                   :id-present id-present))))
                (unless (and (eq version :v2) (not id-present))
                  (push response responses)))))
          ;; A non-object member has no version of its own; Core's default is
          ;; V1_LEGACY with a null id.
          (push (make-rpc-error-response +rpc-invalid-request+
                                         "Invalid request format"
                                         nil :v1)
                responses)))))

;;; --- HTTP Server ---

(defvar *rpc-server* nil
  "The running RPC server instance.")

(defvar *rpc-node* nil
  "The node instance for RPC handlers.")

(defvar *rpc-user* nil
  "RPC authentication username (nil = no configured user/password auth).")

(defvar *rpc-password* nil
  "RPC authentication password.")

(defparameter +rpc-cookie-user+ "__cookie__"
  "Username in the .cookie file (Bitcoin Core convention).")

(defvar *rpc-cookie-path* nil
  "Path of the .cookie file this process generated, so shutdown can remove it
(Core's g_generated_cookie / DeleteAuthCookie, request.cpp:167-177). NIL when
the credential came from -rpcuser/-rpcpassword instead.")

(defun %write-cookie-file (namestring contents)
  "Create NAMESTRING owner-only and write CONTENTS into it. The file must not
exist and must not be a symlink, and it is 0600 from creation — never for one
instant a mode the process umask chose.

Core gets this from a process-wide umask 0077 (common/system.cpp:92-93), so its
cookie is 0600 at open(2) and fs::permissions is only ever called for an
explicit -rpccookieperms (request.cpp:99-146). We do not set a process umask, so
the mode has to come from open(2) itself: creating the file under the ambient
umask and chmod-ing afterwards leaves the secret world-readable while it is
being written (the live host runs umask 002 — its cookies were 0664), and POSIX
checks permissions only at open, so an fd opened in that window stays valid
across the chmod and the rename.

O_EXCL also means the secret is never written into a file we did not create:
:if-exists :supersede opens the EXISTING inode with O_TRUNC (verified on SBCL
2.6.5), so a planted .cookie.tmp — or a hard link to one — receives the secret,
and O_NOFOLLOW additionally refuses a planted symlink, which would otherwise be
written through and then renamed target-and-all over .cookie."
  (let ((fd (sb-posix:open namestring
                           (logior sb-posix:o-wronly sb-posix:o-creat
                                   sb-posix:o-excl sb-posix:o-nofollow)
                           #o600))
        (stream nil))
    (unwind-protect
         (progn
           ;; open(2) applies mode & ~umask, so the file is never MORE
           ;; permissive than 0600; fchmod on our own fd (no path, no race)
           ;; pins it to exactly 0600 even under a umask that strips owner bits.
           (sb-posix:fchmod fd #o600)
           (setf stream (sb-sys:make-fd-stream fd :output t :external-format :utf-8
                                                  :name "rpc-cookie"))
           (write-string contents stream)
           (finish-output stream))
      ;; CLOSE on an fd-stream closes the fd, so close exactly one of them.
      (if stream (close stream) (sb-posix:close fd)))))

(defun generate-rpc-cookie (data-directory)
  "Write <data-directory>/.cookie as \"__cookie__:<random>\" and return
(values path secret), or NIL on failure. The file is the RPC credential, so it
is created owner-only and is never reachable under any other name — Core
creates it under umask 0077 (request.cpp:99-146)."
  (handler-case
      (let* ((secret (ironclad:byte-array-to-hex-string (ironclad:random-data 32)))
             (path (merge-pathnames ".cookie" data-directory))
             (tmp (merge-pathnames ".cookie.tmp" data-directory)))
        (ensure-directories-exist path)
        ;; A .cookie.tmp left behind by a crash would make the exclusive create
        ;; below fail on every later start; unlink drops the name (and a
        ;; symlink itself, never its target). Losing the race to a file planted
        ;; between the unlink and the open just fails the open, which aborts
        ;; cookie generation instead of writing the secret somewhere chosen.
        (handler-case (sb-posix:unlink (namestring tmp)) (error () nil))
        (%write-cookie-file (namestring tmp)
                            (format nil "~A:~A" +rpc-cookie-user+ secret))
        ;; Rename the file we exclusively created — not (truename tmp), which
        ;; would resolve a symlink and move its target over .cookie.
        (sb-posix:rename (namestring tmp) (namestring path))
        (values path secret))
    (error (e)
      (bitcoin-lisp::node-log :warn "Could not write RPC cookie: ~A" e)
      nil)))

(defun delete-rpc-cookie ()
  "Remove the .cookie file this process generated (Core DeleteAuthCookie,
request.cpp:167-177). A cookie we did not write is left alone."
  (when *rpc-cookie-path*
    (handler-case
        (when (probe-file *rpc-cookie-path*)
          (delete-file *rpc-cookie-path*))
      (error (e)
        (bitcoin-lisp::node-log :warn "Could not remove RPC cookie ~A: ~A"
                                *rpc-cookie-path* e)))
    (setf *rpc-cookie-path* nil)))

(defun %timing-resistant-equal (a b)
  "STRING= over A and B in time that does not depend on how many characters
matched (Core TimingResistantEqual, util/strencodings.h:203-210) — a plain
comparison of an attacker-supplied credential leaks its correct prefix."
  (declare (type string a b))
  (let ((la (length a))
        (lb (length b)))
    (if (zerop lb)
        (zerop la)
        (let ((accumulator (logxor la lb)))
          (dotimes (i la)
            (setf accumulator
                  (logior accumulator
                          (logxor (char-code (char a i))
                                  (char-code (char b (mod i lb)))))))
          (zerop accumulator)))))

(defvar *rpc-dispatcher* nil
  "The RPC dispatcher function (for cleanup on stop).")

(defvar *rest-dispatcher* nil
  "The REST /rest/ dispatcher function (for cleanup on stop).")

;;; --- RPC Rate Limiting ---

(defvar *rpc-rate-limiter* nil
  "Global RPC rate limiter (token bucket). Thread-safe via *rpc-rate-limiter-lock*.")

(defvar *rpc-rate-limiter-lock* (bt:make-lock "rpc-rate-limiter")
  "Lock for thread-safe access to *rpc-rate-limiter*.")

(defun init-rpc-rate-limiter ()
  "Initialize the global RPC rate limiter from configuration."
  (let ((config bitcoin-lisp:*rpc-rate-limit*))
    (setf *rpc-rate-limiter*
          (bitcoin-lisp:make-rate-limiter (car config) (cdr config)))))

(defun rpc-rate-limit-check ()
  "Check if the RPC request is within rate limits (thread-safe).
Returns T if allowed, NIL if rate limited."
  (when *rpc-rate-limiter*
    (bt:with-lock-held (*rpc-rate-limiter-lock*)
      (return-from rpc-rate-limit-check
        (bitcoin-lisp:token-bucket-allow-p *rpc-rate-limiter*))))
  t)

(defun rpc-origin-allowed-p (origin host)
  "T unless ORIGIN (the Origin request header, or NIL when absent) names a
different authority than HOST (the request's Host header). Browsers attach
Origin to cross-site POSTs but never let a page forge it, so an alien value
(including \"null\") is a hostile web page driving the user's browser at our
RPC port — rejected before auth (docs/gui-plan.md §2/§4). Non-browser
clients (bitcoin-cli, curl) send no Origin at all and always pass."
  (or (null origin)
      (let* ((origin (string-trim '(#\Space #\Tab) origin))
             (scheme-end (search "://" origin)))
        (and scheme-end host
             (string-equal (subseq origin (+ scheme-end 3))
                           (string-trim '(#\Space #\Tab) host))))))

(defun check-auth (auth-header)
  "T when AUTH-HEADER — the request's Authorization header, NIL when it carried
none — is an HTTP Basic credential matching the RPC user and password. Those
are the -rpcuser/-rpcpassword pair when configured and the generated .cookie
pair otherwise, so every request needs a credential: Core answers 401 for an
absent header and for a non-matching one alike (HTTPReq_JSONRPC,
httprpc.cpp:112-133). The cookie file is the local access boundary."
  (and (stringp auth-header)
       *rpc-user* *rpc-password*
       (> (length auth-header) 6)
       (string-equal (subseq auth-header 0 6) "Basic ")
       (handler-case
           (let* ((decoded (flexi-streams:octets-to-string
                            (cl-base64:base64-string-to-usb8-array
                             (string-trim '(#\Space #\Tab)
                                          (subseq auth-header 6)))))
                  (colon-pos (position #\: decoded)))
             (when colon-pos
               (and (%timing-resistant-equal (subseq decoded 0 colon-pos)
                                             *rpc-user*)
                    (%timing-resistant-equal (subseq decoded (1+ colon-pos))
                                             *rpc-password*))))
         (error () nil))))

(defun rpc-json-error (http-status code message)
  "Return a JSON-RPC error response string with the given HTTP status.
These are pre-dispatch HTTP-level refusals (origin, rate limit, body size), so
no request version has been parsed: Core's JSONRPCRequest starts out
V1_LEGACY with a null id (request.h:55,63), which is the shape used here."
  (setf (hunchentoot:return-code*) http-status)
  (setf (hunchentoot:content-type*) "application/json")
  (with-output-to-string (s)
    (yason:encode (make-rpc-error-response code message nil :v1) s)))

(defun rpc-error-http-status (code)
  "HTTP status for a JSON-RPC 1.x error response (Core JSONErrorReply,
httprpc.cpp:41-59): -32600 -> 400, -32601 -> 404, everything else -> 500.
JSON-RPC 2.0 requests never use this — they always answer HTTP 200 with the
error in the body (httprpc.cpp:160-164)."
  (cond ((= code +rpc-invalid-request+) hunchentoot:+http-bad-request+)
        ((= code +rpc-method-not-found+) hunchentoot:+http-not-found+)
        (t hunchentoot:+http-internal-server-error+)))

(defun rpc-response-http-status (response version)
  "The HTTP status to send with a single JSON-RPC RESPONSE hash-table:
200 for success or any :V2 request; the Core 1.x mapping otherwise.
A :V1 success carries an \"error\" key whose value is null, so the test below
must stay a value test (NIL = success), not a key-presence test."
  (let ((err (gethash "error" response)))
    (if (or (null err) (eq version :v2))
        hunchentoot:+http-ok+
        (rpc-error-http-status (gethash "code" err)))))

(defun rpc-handler ()
  "Handle incoming RPC requests."
  (let ((request hunchentoot:*request*))
    ;; Reject cross-origin browser POSTs BEFORE auth (rpc-origin-allowed-p).
    (unless (rpc-origin-allowed-p (hunchentoot:header-in :origin request)
                                  (hunchentoot:header-in :host request))
      (return-from rpc-handler
        (rpc-json-error hunchentoot:+http-forbidden+ +rpc-misc-error+
                        "Origin does not match Host")))

    ;; Check authentication
    (let ((auth-header (hunchentoot:header-in :authorization request)))
      (unless (check-auth auth-header)
        ;; Core deters brute-forcing with a 250ms pause, but only once a
        ;; credential has actually been offered: a request with no
        ;; Authorization header is answered immediately (httprpc.cpp:112-133).
        (when auth-header
          (bitcoin-lisp::node-log :warn "RPC incorrect password attempt from ~A"
                                  (hunchentoot:remote-addr request))
          (sleep 0.25))
        (setf (hunchentoot:return-code*) hunchentoot:+http-authorization-required+)
        (setf (hunchentoot:header-out :www-authenticate) "Basic realm=\"bitcoin-lisp\"")
        (return-from rpc-handler "")))

    ;; Check rate limit
    (unless (rpc-rate-limit-check)
      (return-from rpc-handler
        (rpc-json-error 429 +rpc-misc-error+ "Rate limit exceeded")))

    ;; Check body size limit: 32 MiB (Core evhttp_set_max_body_size(MAX_SIZE),
    ;; httpserver.cpp:410). libevent answers an oversized body with 400.
    (let* ((content-length-str (hunchentoot:header-in :content-length request))
           (content-length (and content-length-str
                                (parse-integer content-length-str :junk-allowed t))))
      (when (and content-length
                 (> content-length bitcoin-lisp:+max-rpc-body-size+))
        (return-from rpc-handler
          (rpc-json-error hunchentoot:+http-bad-request+ +rpc-misc-error+
                          "Request body too large"))))

    ;; Check Content-Type
    (let ((content-type (hunchentoot:header-in :content-type request)))
      (unless (and content-type
                   (or (search "application/json" content-type)
                       (search "text/plain" content-type))) ; bitcoin-cli uses text/plain
        (setf (hunchentoot:return-code*) hunchentoot:+http-unsupported-media-type+)
        (return-from rpc-handler "")))

    ;; Process request. A /wallet/<name> endpoint routes wallet RPCs to that
    ;; wallet (Core httprpc.cpp:340 registers the same handler under
    ;; /wallet/); non-wallet methods ignore the binding.
    (setf (hunchentoot:content-type*) "application/json")
    (let ((*rpc-wallet-name* (wallet-name-from-uri (hunchentoot:script-name*)))
          (body (hunchentoot:raw-post-data :force-text t)))
      ;; Post-read body size check (in case Content-Length was absent or wrong)
      (when (and body (> (length body) bitcoin-lisp:+max-rpc-body-size+))
        (return-from rpc-handler
          (rpc-json-error hunchentoot:+http-bad-request+ +rpc-misc-error+
                          "Request body too large")))
      (handler-case
          (multiple-value-bind (request-type method-or-batch params id version id-present)
              (parse-json-rpc-request body)
            (case request-type
              (:single
               (let ((response (handle-single-request *rpc-node* method-or-batch
                                                      params id version
                                                      :id-present id-present)))
                 ;; A JSON-RPC 2.0 notification (no id member) answers 204
                 ;; with no body after executing (Core httprpc.cpp:169);
                 ;; otherwise the 1.x error->status mapping applies
                 ;; (rpc-response-http-status; 2.0 is always 200).
                 (cond
                   ((and (eq version :v2) (not id-present))
                    (setf (hunchentoot:return-code*) hunchentoot:+http-no-content+)
                    "")
                   (t
                    (setf (hunchentoot:return-code*)
                          (rpc-response-http-status response version))
                    (with-output-to-string (s)
                      (yason:encode response s))))))
              (:batch
               ;; Batches always answer HTTP 200 (Core httprpc.cpp:196-206),
               ;; except a non-empty all-notification batch, which answers 204
               ;; with no body (:220). An EMPTY batch keeps answering [] for
               ;; backwards compatibility (:211-219) — note NIL encodes as JSON
               ;; null, so the empty array must be spelled #().
               (let ((responses (handle-batch-request *rpc-node* method-or-batch)))
                 (cond
                   ((and (null responses) method-or-batch)
                    (setf (hunchentoot:return-code*) hunchentoot:+http-no-content+)
                    "")
                   (t
                    (with-output-to-string (s)
                      (yason:encode (or responses #()) s))))))))
        (rpc-error (e)
          ;; Body-level failures (parse error -32700, invalid request -32600)
          ;; have no version context; Core treats them as 1.x — both for the
          ;; status mapping (parse error -> 500, invalid request -> 400) and
          ;; for the reply shape, since JSONErrorReply passes the still-default
          ;; V1_LEGACY/null-id JSONRPCRequest (httprpc.cpp:41-59).
          (setf (hunchentoot:return-code*)
                (rpc-error-http-status (rpc-error-code e)))
          (with-output-to-string (s)
            (yason:encode (make-rpc-error-response (rpc-error-code e)
                                                   (rpc-error-message e)
                                                   nil :v1)
                          s)))
        (error (e)
          (bitcoin-lisp::node-log :error "RPC handler error: ~A" e)
          (setf (hunchentoot:return-code*) hunchentoot:+http-internal-server-error+)
          (with-output-to-string (s)
            (yason:encode (make-rpc-error-response +rpc-internal-error+
                                                   "Internal error"
                                                   nil :v1)
                          s)))))))

(defun rpc-dispatch-handler ()
  "Dispatch handler for hunchentoot. Only handles POST requests."
  (if (eq (hunchentoot:request-method*) :post)
      (rpc-handler)
      (progn
        (setf (hunchentoot:return-code*) hunchentoot:+http-method-not-allowed+)
        "")))

(defun rpc-bind-loopback-p (address)
  "T when ADDRESS names a loopback interface. NIL and \"\" mean bind-any and
are not loopback."
  (and (stringp address)
       (let ((a (string-trim '(#\Space #\Tab #\[ #\]) address)))
         (or (string-equal a "localhost")
             (string= a "::1")
             (and (> (length a) 4) (string= (subseq a 0 4) "127."))))))

(defun %rpc-bind-address (bind)
  "The address the RPC acceptor may bind to. Core ignores -rpcbind unless
-rpcallowip is also given, falling back to loopback rather than letting one
flag expose the RPC port (HTTPBindAddresses, httpserver.cpp:316-327). We have
no -rpcallowip, so every non-loopback bind is refused the same way."
  (if (rpc-bind-loopback-p bind)
      bind
      (progn
        (bitcoin-lisp::node-log
         :warn "-rpcbind=~A ignored: this node has no -rpcallowip, so the RPC ~
port stays on 127.0.0.1 rather than accepting connections from anywhere"
         (or bind "<any>"))
        "127.0.0.1")))

(defun %install-rpc-credential (node user password)
  "Install the single credential check-auth authorizes against and return T, or
log and return NIL when there is none. Exactly one credential reaches the
handler, as in Core's InitRPCAuthentication (httprpc.cpp:240-288): the cookie
pair unless -rpcuser/-rpcpassword is configured.

Callers must have bound the listening socket first — this writes .cookie, and
.cookie is the live credential of whatever node owns the data directory."
  (if (and user password)
      (progn
        (setf *rpc-user* user *rpc-password* password *rpc-cookie-path* nil)
        t)
      (multiple-value-bind (path secret)
          (let ((data-directory (and node (bitcoin-lisp::node-data-directory node))))
            (if data-directory (generate-rpc-cookie data-directory) (values nil nil)))
        (cond (path
               (setf *rpc-user* +rpc-cookie-user+ *rpc-password* secret
                     *rpc-cookie-path* path)
               t)
              (t
               (bitcoin-lisp::node-log
                :error "RPC server not started: no -rpcuser/-rpcpassword and the ~
.cookie file could not be written, so no request could be authorized")
               nil)))))

(defun start-rpc-server (node &key port (bind "127.0.0.1")
                                   user password
                                   rest-enabled
                                   ui-enabled ui-directory)
  "Start the RPC server.
PORT defaults to 18332 for testnet, 8332 for mainnet.
Every request must carry a credential: the USER/PASSWORD pair when configured,
otherwise the .cookie file generated in the node's data directory. Without
either the server does not start, as Core aborts startup when
InitRPCAuthentication fails (httprpc.cpp:300-302).
REST-ENABLED registers the Core-style /rest/ GET surface; like Core, the
REST interface is OFF unless -rest is given (DEFAULT_REST_ENABLE = false,
init.cpp:153,758 — previously we registered it unconditionally).
UI-ENABLED registers the /ui/ web UI dispatcher (gui-plan P0); UI-DIRECTORY
overrides the asset directory (default: the repo's ui/, see ui.lisp)."
  (let ((port (or port (bitcoin-lisp:network-rpc-port bitcoin-lisp:*network*))))
    (when *rpc-server*
      (bitcoin-lisp::node-log :warn "RPC server already running")
      (return-from start-rpc-server nil))
    (setf bind (%rpc-bind-address bind))

    ;; Bind the listening socket BEFORE touching any credential, the order Core
    ;; uses: AppInitServers calls InitHTTPServer (which binds) and only then
    ;; StartHTTPRPC -> InitRPCAuthentication -> GenerateAuthCookie
    ;; (init.cpp:748-761), so a port conflict aborts before .cookie is written.
    ;;
    ;; Generating the cookie first is not a cosmetic difference: a second
    ;; process started on a running node's data directory would overwrite
    ;; .cookie with a secret matching nothing, then fail to bind and exit. The
    ;; healthy node keeps serving with the old secret it holds in memory, so
    ;; bitcoin-cli, the /ui/ SPA and every monitoring script that re-reads the
    ;; file get 401 from a node that is perfectly fine — and the surviving
    ;; process logs nothing, because nothing happened to it. (This has already
    ;; happened here: restart-node.sh's pkill marker did not match the live
    ;; supervisor and left two processes on one data directory.)
    ;;
    ;; Installing the credential after the bind is safe: until *rpc-user* is
    ;; set check-auth returns NIL for every header, and the dispatchers are
    ;; pushed last, so nothing can reach the handler at all in that window.
    (let ((acceptor nil)
          (listening nil)
          (credential-installed nil)
          (pushed '()))
      (flet ((abort-start ()
               ;; Undo only what THIS attempt did. A failure before the
               ;; credential was installed must leave *rpc-user*, *rpc-password*
               ;; and *rpc-cookie-path* alone: in a second process they are NIL,
               ;; and in this one they may belong to a server already running.
               (dolist (d pushed)
                 (setf hunchentoot:*dispatch-table*
                       (remove d hunchentoot:*dispatch-table*)))
               (when pushed
                 (setf *rpc-dispatcher* nil *rest-dispatcher* nil
                       *ui-dispatcher* nil *ui-enabled* nil *ui-directory* nil))
               (when listening
                 (handler-case (hunchentoot:stop acceptor) (error () nil)))
               (when credential-installed
                 (delete-rpc-cookie)
                 (setf *rpc-user* nil *rpc-password* nil *rpc-cookie-path* nil))
               nil))
        (handler-case
            (progn
              (setf acceptor (make-instance 'hunchentoot:easy-acceptor
                                            :port port
                                            :address bind))
              (hunchentoot:start acceptor)
              (setf listening t)

              ;; Bound. Now install the one credential the handler authorizes
              ;; against (Core InitRPCAuthentication, httprpc.cpp:240-288).
              (unless (%install-rpc-credential node user password)
                (return-from start-rpc-server (abort-start)))
              (setf credential-installed t)

              ;; Register methods
              (register-all-methods)

              ;; Initialize RPC rate limiter
              (init-rpc-rate-limiter)

              ;; Set globals for handler
              (setf *rpc-node* node)

              ;; Dispatchers go in LAST: pushing them into the global
              ;; hunchentoot:*dispatch-table* is the step that makes requests
              ;; reachable, and a failed start must not leak them (it used to
              ;; leave *rpc-dispatcher* in the table when the bind threw).
              (let ((dispatcher (hunchentoot:create-prefix-dispatcher "/" 'rpc-dispatch-handler)))
                (setf *rpc-dispatcher* dispatcher)
                (push dispatcher pushed)
                (push dispatcher hunchentoot:*dispatch-table*))
              ;; REST GET surface under /rest/ — pushed AFTER the "/" dispatcher
              ;; so it sits at the front of the list and matches first. Only when
              ;; -rest is given (Core StartREST gate, init.cpp:758).
              (when rest-enabled
                (bitcoin-lisp::node-log :info "REST interface enabled at /rest/")
                (let ((rest-dispatcher (hunchentoot:create-prefix-dispatcher
                                        "/rest/" 'rest-dispatch-handler)))
                  (setf *rest-dispatcher* rest-dispatcher)
                  (push rest-dispatcher pushed)
                  (push rest-dispatcher hunchentoot:*dispatch-table*)))
              ;; Web UI static assets under /ui/ (gui-plan P0). Registered only
              ;; when enabled — a disabled UI leaves no handler at all.
              (setf *ui-enabled* (and ui-enabled t)
                    *ui-directory* (and ui-directory
                                        (uiop:ensure-directory-pathname ui-directory)))
              (when *ui-enabled*
                (let ((dir (ui-directory)))
                  (if (and dir (probe-file dir))
                      (bitcoin-lisp::node-log :info "Web UI enabled at /ui/ (serving ~A)" dir)
                      (bitcoin-lisp::node-log
                       :warn "Web UI enabled but asset directory ~A is missing — /ui/ will 404" dir)))
                (let ((ui-dispatcher (make-ui-dispatcher)))
                  (setf *ui-dispatcher* ui-dispatcher)
                  (push ui-dispatcher pushed)
                  (push ui-dispatcher hunchentoot:*dispatch-table*)))

              (setf *rpc-server* acceptor)
              (bitcoin-lisp::node-log :info "RPC server started on ~A:~A" bind port)
              acceptor)
          (usocket:address-in-use-error ()
            (bitcoin-lisp::node-log :error "RPC port ~A already in use, continuing without RPC" port)
            (abort-start))
          (error (e)
            (bitcoin-lisp::node-log :error "Failed to start RPC server: ~A" e)
            (abort-start)))))))

(defun stop-rpc-server ()
  "Stop the RPC server."
  (when *rpc-server*
    (handler-case
        (progn
          (hunchentoot:stop *rpc-server*)
          (bitcoin-lisp::node-log :info "RPC server stopped"))
      (error (e)
        (bitcoin-lisp::node-log :warn "Error stopping RPC server: ~A" e)))
    ;; Remove dispatcher from dispatch table to prevent accumulation
    (when *rpc-dispatcher*
      (setf hunchentoot:*dispatch-table*
            (remove *rpc-dispatcher* hunchentoot:*dispatch-table*)))
    (when *rest-dispatcher*
      (setf hunchentoot:*dispatch-table*
            (remove *rest-dispatcher* hunchentoot:*dispatch-table*)))
    (when *ui-dispatcher*
      (setf hunchentoot:*dispatch-table*
            (remove *ui-dispatcher* hunchentoot:*dispatch-table*)))
    (delete-rpc-cookie)
    (setf *rpc-server* nil)
    (setf *rpc-node* nil)
    (setf *rpc-user* nil)
    (setf *rpc-password* nil)
    (setf *rpc-dispatcher* nil)
    (setf *rest-dispatcher* nil)
    (setf *ui-dispatcher* nil)
    (setf *ui-enabled* nil)
    (setf *ui-directory* nil)
    (setf *rpc-rate-limiter* nil)))
