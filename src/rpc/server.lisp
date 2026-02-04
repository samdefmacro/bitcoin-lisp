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
  ;; UTXO
  (register-rpc-method "gettxout" #'rpc-gettxout)
  ;; Network
  (register-rpc-method "getpeerinfo" #'rpc-getpeerinfo)
  (register-rpc-method "getnetworkinfo" #'rpc-getnetworkinfo)
  (register-rpc-method "getconnectioncount" #'rpc-getconnectioncount)
  ;; Mempool
  (register-rpc-method "getmempoolinfo" #'rpc-getmempoolinfo)
  (register-rpc-method "getrawmempool" #'rpc-getrawmempool)
  (register-rpc-method "sendrawtransaction" #'rpc-sendrawtransaction)
  ;; Raw transaction methods
  (register-rpc-method "decoderawtransaction" #'rpc-decoderawtransaction)
  (register-rpc-method "getrawtransaction" #'rpc-getrawtransaction)
  (register-rpc-method "createrawtransaction" #'rpc-createrawtransaction)
  ;; Utility methods
  (register-rpc-method "estimatesmartfee" #'rpc-estimatesmartfee)
  (register-rpc-method "validateaddress" #'rpc-validateaddress)
  (register-rpc-method "decodescript" #'rpc-decodescript)
  ;; UTXO set statistics
  (register-rpc-method "gettxoutsetinfo" #'rpc-gettxoutsetinfo)
  ;; Block statistics
  (register-rpc-method "getblockstats" #'rpc-getblockstats))

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
           (let ((jsonrpc (gethash "jsonrpc" json))
                 (method (gethash "method" json))
                 (params (gethash "params" json))
                 (id (gethash "id" json)))
             (unless (equal jsonrpc "2.0")
               (error 'rpc-error :code +rpc-invalid-request+
                                 :message "Invalid JSON-RPC version"))
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

(defun make-rpc-response (result id)
  "Create a successful JSON-RPC response."
  (let ((response (make-hash-table :test 'equal)))
    (setf (gethash "jsonrpc" response) "2.0")
    (setf (gethash "result" response) result)
    (setf (gethash "id" response) id)
    response))

(defun make-rpc-error-response (code message id &optional data)
  "Create an error JSON-RPC response."
  (let ((response (make-hash-table :test 'equal))
        (error-obj (make-hash-table :test 'equal)))
    (setf (gethash "code" error-obj) code)
    (setf (gethash "message" error-obj) message)
    (when data
      (setf (gethash "data" error-obj) data))
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
  "RPC authentication username (nil = no auth).")

(defvar *rpc-password* nil
  "RPC authentication password.")

(defvar *rpc-dispatcher* nil
  "The RPC dispatcher function (for cleanup on stop).")

(defun check-auth (request)
  "Check HTTP Basic authentication. Returns t if valid or auth disabled."
  (when (and *rpc-user* *rpc-password*)
    (let ((auth-header (hunchentoot:header-in :authorization request)))
      (unless auth-header
        (return-from check-auth nil))
      (unless (and (> (length auth-header) 6)
                   (string-equal (subseq auth-header 0 6) "Basic "))
        (return-from check-auth nil))
      (handler-case
          (let* ((encoded (subseq auth-header 6))
                 (decoded (flexi-streams:octets-to-string
                           (cl-base64:base64-string-to-usb8-array encoded)))
                 (colon-pos (position #\: decoded)))
            (when colon-pos
              (let ((user (subseq decoded 0 colon-pos))
                    (pass (subseq decoded (1+ colon-pos))))
                (and (string= user *rpc-user*)
                     (string= pass *rpc-password*)))))
        (error () nil))))
  t)

(defun rpc-handler ()
  "Handle incoming RPC requests."
  (let ((request hunchentoot:*request*))
    ;; Check authentication
    (unless (check-auth request)
      (setf (hunchentoot:return-code*) hunchentoot:+http-authorization-required+)
      (setf (hunchentoot:header-out :www-authenticate) "Basic realm=\"bitcoin-lisp\"")
      (return-from rpc-handler ""))

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

    ;; Set globals for handler
    (setf *rpc-node* node)
    (setf *rpc-user* user)
    (setf *rpc-password* password)

    ;; Create and start server
    (handler-case
        (let ((acceptor (make-instance 'hunchentoot:easy-acceptor
                                       :port port
                                       :address bind)))
          ;; Create and save dispatcher for cleanup
          (let ((dispatcher (hunchentoot:create-prefix-dispatcher "/" 'rpc-dispatch-handler)))
            (setf *rpc-dispatcher* dispatcher)
            (push dispatcher hunchentoot:*dispatch-table*))

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
    (setf *rpc-server* nil)
    (setf *rpc-node* nil)
    (setf *rpc-user* nil)
    (setf *rpc-password* nil)
    (setf *rpc-dispatcher* nil)))
