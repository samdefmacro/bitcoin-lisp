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
(defconstant +rpc-invalid-address-or-key+ -5)
(defconstant +rpc-invalid-parameter+ -8)
(defconstant +rpc-client-node-already-added+ -23)
(defconstant +rpc-client-node-not-added+ -24)
(defconstant +rpc-verify-error+ -25)
(defconstant +rpc-transaction-rejected+ -26)
(defconstant +rpc-verify-already-in-utxo-set+ -27)

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
      (error 'rpc-error :code +rpc-method-not-found+
                        :message (format nil "Method not found: ~A" method)))
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
  (register-rpc-method "pruneblockchain" #'rpc-pruneblockchain))

;;; --- JSON-RPC Request/Response Handling ---

(defun parse-json-rpc-request (body)
  "Parse JSON-RPC request body. Returns (method params id) or signals error."
  (handler-case
      (let ((json (yason:parse body)))
        (cond
          ;; Batch request (array)
          ((listp json)
           (values :batch json))
          ;; Single request (object)
          ((hash-table-p json)
           (let ((method (gethash "method" json))
                 (params (gethash "params" json))
                 (id (gethash "id" json)))
             ;; Accept any/absent "jsonrpc" version: bitcoin-cli sends 1.0 (or
             ;; omits it) on older builds and 2.0 on newer; Core doesn't
             ;; validate it. Rejecting non-2.0 made stock bitcoin-cli unusable.
             (unless (stringp method)
               (error 'rpc-error :code +rpc-invalid-request+
                                 :message "Missing or invalid method"))
             (values :single method (or params '()) id)))
          (t
           (error 'rpc-error :code +rpc-invalid-request+
                             :message "Invalid request format"))))
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
                      (params (or (gethash "params" req) '()))
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

(defun rpc-handler ()
  "Handle incoming RPC requests."
  (let ((request hunchentoot:*request*))
    ;; Check authentication
    (unless (check-auth request)
      (setf (hunchentoot:return-code*) hunchentoot:+http-authorization-required+)
      (setf (hunchentoot:header-out :www-authenticate) "Basic realm=\"bitcoin-lisp\"")
      (return-from rpc-handler ""))

    ;; Check rate limit
    (unless (rpc-rate-limit-check)
      (return-from rpc-handler
        (rpc-json-error 429 +rpc-misc-error+ "Rate limit exceeded")))

    ;; Check body size limit
    (let* ((content-length-str (hunchentoot:header-in :content-length request))
           (content-length (and content-length-str
                                (parse-integer content-length-str :junk-allowed t))))
      (when (and content-length
                 (> content-length bitcoin-lisp:+max-rpc-body-size+))
        (return-from rpc-handler
          (rpc-json-error 413 +rpc-misc-error+ "Request body too large"))))

    ;; Check Content-Type
    (let ((content-type (hunchentoot:header-in :content-type request)))
      (unless (and content-type
                   (or (search "application/json" content-type)
                       (search "text/plain" content-type))) ; bitcoin-cli uses text/plain
        (setf (hunchentoot:return-code*) hunchentoot:+http-unsupported-media-type+)
        (return-from rpc-handler "")))

    ;; Process request
    (setf (hunchentoot:content-type*) "application/json")
    (let ((body (hunchentoot:raw-post-data :force-text t)))
      ;; Post-read body size check (in case Content-Length was absent or wrong)
      (when (and body (> (length body) bitcoin-lisp:+max-rpc-body-size+))
        (return-from rpc-handler
          (rpc-json-error 413 +rpc-misc-error+ "Request body too large")))
      (handler-case
          (multiple-value-bind (request-type method-or-batch params id)
              (parse-json-rpc-request body)
            (let ((response
                    (case request-type
                      (:single
                       (handle-single-request *rpc-node* method-or-batch params id))
                      (:batch
                       (handle-batch-request *rpc-node* method-or-batch)))))
              (with-output-to-string (s)
                (yason:encode response s))))
        (rpc-error (e)
          (with-output-to-string (s)
            (yason:encode (make-rpc-error-response (rpc-error-code e)
                                                   (rpc-error-message e)
                                                   nil)
                          s)))
        (error (e)
          (bitcoin-lisp::node-log :error "RPC handler error: ~A" e)
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
                                   user password)
  "Start the RPC server.
PORT defaults to 18332 for testnet, 8332 for mainnet."
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
          ;; so it sits at the front of the list and matches first.
          (let ((rest-dispatcher (hunchentoot:create-prefix-dispatcher
                                  "/rest/" 'rest-dispatch-handler)))
            (setf *rest-dispatcher* rest-dispatcher)
            (push rest-dispatcher hunchentoot:*dispatch-table*))

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
    (setf *rpc-server* nil)
    (setf *rpc-node* nil)
    (setf *rpc-user* nil)
    (setf *rpc-password* nil)
    (setf *rpc-dispatcher* nil)
    (setf *rest-dispatcher* nil)
    (setf *rpc-rate-limiter* nil)))
