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
                 (version (if (equal (gethash "jsonrpc" json) "2.0") :v2 :v1)))
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

(defun make-rpc-response (result id)
  "Create a successful JSON-RPC response."
  (let ((response (make-hash-table :test 'equal)))
    (setf (gethash "jsonrpc" response) "2.0")
    (setf (gethash "result" response) (rpc-result->json result))
    (setf (gethash "id" response) id)
    response))

(defun make-rpc-error-response (code message id &optional data)
  "Create an error JSON-RPC response."
  (let ((response (make-hash-table :test 'equal))
        (error-obj (make-hash-table :test 'equal)))
    (setf (gethash "code" error-obj) code)
    (setf (gethash "message" error-obj) message)
    (when data
      (setf (gethash "data" error-obj) (rpc-result->json data)))
    (setf (gethash "jsonrpc" response) "2.0")
    (setf (gethash "error" response) error-obj)
    (setf (gethash "id" response) id)
    response))

(defun handle-single-request (node method params id)
  "Handle a single RPC request."
  (handler-case
      (let ((result (dispatch-rpc-method node method params)))
        (make-rpc-response result id))
    (rpc-error (e)
      (make-rpc-error-response (rpc-error-code e)
                               (rpc-error-message e)
                               id
                               (rpc-error-data e)))
    (error (e)
      (bitcoin-lisp::node-log :error "RPC internal error: ~A" e)
      (make-rpc-error-response +rpc-internal-error+
                               (format nil "Internal error: ~A" e)
                               id))))

(defun handle-batch-request (node requests)
  "Handle a batch of RPC requests."
  (mapcar (lambda (req)
            (if (hash-table-p req)
                (let ((method (gethash "method" req))
                      (params (%normalize-rpc-params
                               (or (gethash "params" req) '())))
                      (id (gethash "id" req)))
                  (if (stringp method)
                      (handle-single-request node method params id)
                      (make-rpc-error-response +rpc-invalid-request+
                                               "Missing or invalid method"
                                               id)))
                (make-rpc-error-response +rpc-invalid-request+
                                         "Invalid request format"
                                         nil)))
          requests))

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

(defvar *rpc-cookie-secret* nil
  "Random secret written to .cookie when no rpcuser/password is configured, so
stock bitcoin-cli (which always sends credentials) can authenticate.")

(defun generate-rpc-cookie (data-directory)
  "Write <data-directory>/.cookie as \"__cookie__:<random>\" and remember the
secret. Mirrors Bitcoin Core's cookie auth for clients that need credentials."
  (handler-case
      (let* ((secret (ironclad:byte-array-to-hex-string (ironclad:random-data 32)))
             (path (merge-pathnames ".cookie" data-directory)))
        (setf *rpc-cookie-secret* secret)
        (ensure-directories-exist path)
        (with-open-file (s path :direction :output :if-exists :supersede
                                :if-does-not-exist :create)
          (format s "~A:~A" +rpc-cookie-user+ secret))
        path)
    (error (e)
      (bitcoin-lisp::node-log :warn "Could not write RPC cookie: ~A" e)
      nil)))

(defun %basic-auth-matches-p (auth-header)
  "T if the HTTP Basic AUTH-HEADER matches the configured user/password or the
generated cookie credential."
  (and (stringp auth-header)
       (> (length auth-header) 6)
       (string-equal (subseq auth-header 0 6) "Basic ")
       (handler-case
           (let* ((decoded (flexi-streams:octets-to-string
                            (cl-base64:base64-string-to-usb8-array
                             (subseq auth-header 6))))
                  (colon-pos (position #\: decoded)))
             (when colon-pos
               (let ((user (subseq decoded 0 colon-pos))
                     (pass (subseq decoded (1+ colon-pos))))
                 (or (and *rpc-user* *rpc-password*
                          (string= user *rpc-user*) (string= pass *rpc-password*))
                     (and *rpc-cookie-secret*
                          (string= user +rpc-cookie-user+)
                          (string= pass *rpc-cookie-secret*))))))
         (error () nil))))

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

(defun check-auth (request)
  "Authorize an RPC request.
- With rpcuser/password configured, require a matching HTTP Basic credential
  (or the cookie). This also fixes a prior bug where a *mismatched* credential
  fell through and was accepted.
- With nothing configured, allow open local RPC (our nodes bind 127.0.0.1) — a
  .cookie is still written so stock bitcoin-cli, which always sends
  credentials, authenticates; existing unauthenticated local clients keep
  working."
  (if (and *rpc-user* *rpc-password*)
      (%basic-auth-matches-p (hunchentoot:header-in :authorization request))
      t))

(defun rpc-json-error (http-status code message)
  "Return a JSON-RPC error response string with the given HTTP status."
  (setf (hunchentoot:return-code*) http-status)
  (setf (hunchentoot:content-type*) "application/json")
  (with-output-to-string (s)
    (yason:encode (make-rpc-error-response code message nil) s)))

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
200 for success or any :V2 request; the Core 1.x mapping otherwise."
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
    (unless (check-auth request)
      (setf (hunchentoot:return-code*) hunchentoot:+http-authorization-required+)
      (setf (hunchentoot:header-out :www-authenticate) "Basic realm=\"bitcoin-lisp\"")
      (return-from rpc-handler ""))

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
                                                      params id)))
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
               ;; Batches always answer HTTP 200 (Core httprpc.cpp:196-206).
               (let ((response (handle-batch-request *rpc-node* method-or-batch)))
                 (with-output-to-string (s)
                   (yason:encode response s))))))
        (rpc-error (e)
          ;; Body-level failures (parse error -32700, invalid request -32600)
          ;; have no version context; Core treats them as 1.x and maps the
          ;; status accordingly (parse error -> 500, invalid request -> 400).
          (setf (hunchentoot:return-code*)
                (rpc-error-http-status (rpc-error-code e)))
          (with-output-to-string (s)
            (yason:encode (make-rpc-error-response (rpc-error-code e)
                                                   (rpc-error-message e)
                                                   nil)
                          s)))
        (error (e)
          (bitcoin-lisp::node-log :error "RPC handler error: ~A" e)
          (setf (hunchentoot:return-code*) hunchentoot:+http-internal-server-error+)
          (with-output-to-string (s)
            (yason:encode (make-rpc-error-response +rpc-internal-error+
                                                   "Internal error"
                                                   nil)
                          s)))))))

(defun rpc-dispatch-handler ()
  "Dispatch handler for hunchentoot. Only handles POST requests."
  (if (eq (hunchentoot:request-method*) :post)
      (rpc-handler)
      (progn
        (setf (hunchentoot:return-code*) hunchentoot:+http-method-not-allowed+)
        "")))

(defun start-rpc-server (node &key port (bind "127.0.0.1")
                                   user password
                                   rest-enabled
                                   ui-enabled ui-directory)
  "Start the RPC server.
PORT defaults to 18332 for testnet, 8332 for mainnet.
REST-ENABLED registers the Core-style /rest/ GET surface; like Core, the
REST interface is OFF unless -rest is given (DEFAULT_REST_ENABLE = false,
init.cpp:153,758 — previously we registered it unconditionally).
UI-ENABLED registers the /ui/ web UI dispatcher (gui-plan P0); UI-DIRECTORY
overrides the asset directory (default: the repo's ui/, see ui.lisp)."
  (let ((port (or port (bitcoin-lisp:network-rpc-port bitcoin-lisp:*network*))))
    (when *rpc-server*
      (bitcoin-lisp::node-log :warn "RPC server already running")
      (return-from start-rpc-server nil))

    ;; Register methods
    (register-all-methods)

    ;; Initialize RPC rate limiter
    (init-rpc-rate-limiter)

    ;; Set globals for handler
    (setf *rpc-node* node)
    (setf *rpc-user* user)
    (setf *rpc-password* password)
    ;; When no user/password is configured, write a .cookie so stock bitcoin-cli
    ;; can authenticate (Bitcoin Core behavior). With a configured password,
    ;; clients use that and no cookie is written.
    (setf *rpc-cookie-secret* nil)
    (unless (and user password)
      (when (and node (bitcoin-lisp::node-data-directory node))
        (generate-rpc-cookie (bitcoin-lisp::node-data-directory node))))

    ;; Create and start server
    (handler-case
        (let ((acceptor (make-instance 'hunchentoot:easy-acceptor
                                       :port port
                                       :address bind)))
          ;; Create and save dispatcher for cleanup
          (let ((dispatcher (hunchentoot:create-prefix-dispatcher "/" 'rpc-dispatch-handler)))
            (setf *rpc-dispatcher* dispatcher)
            (push dispatcher hunchentoot:*dispatch-table*))
          ;; REST GET surface under /rest/ — pushed AFTER the "/" dispatcher
          ;; so it sits at the front of the list and matches first. Only when
          ;; -rest is given (Core StartREST gate, init.cpp:758).
          (when rest-enabled
            (bitcoin-lisp::node-log :info "REST interface enabled at /rest/")
            (let ((rest-dispatcher (hunchentoot:create-prefix-dispatcher
                                    "/rest/" 'rest-dispatch-handler)))
              (setf *rest-dispatcher* rest-dispatcher)
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
              (push ui-dispatcher hunchentoot:*dispatch-table*)))

          (hunchentoot:start acceptor)
          (setf *rpc-server* acceptor)
          (bitcoin-lisp::node-log :info "RPC server started on ~A:~A" bind port)
          acceptor)
      (usocket:address-in-use-error ()
        (bitcoin-lisp::node-log :error "RPC port ~A already in use, continuing without RPC" port)
        nil)
      (error (e)
        (bitcoin-lisp::node-log :error "Failed to start RPC server: ~A" e)
        nil))))

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
