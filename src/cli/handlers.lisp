(in-package #:bitcoin-lisp.cli)

;;;; The request handlers (Core bitcoin-cli.cpp BaseRequestHandler and its
;;;; five subclasses)
;;;
;;; Each turns the command line into a JSON-RPC request (a single object or a
;;; batch array) and the server's reply back into one reply object, the shape
;;; CommandLineRPC reads `result' and `error' from. -getinfo, -netinfo,
;;; -addrinfo and -generate are client-side compositions of ordinary RPCs, so
;;; the server needs nothing of its own for them.

(defgeneric prepare-request (handler method args)
  (:documentation "Core PrepareRequest: the request UniValue for METHOD and
the string ARGS."))

(defgeneric process-reply (handler reply)
  (:documentation "Core ProcessReply: the reply object CommandLineRPC reads."))

(defun json-rpc-request (method params id)
  "Core JSONRPCRequestObj (rpc/request.cpp:41-49)."
  (uv-obj "method" method "params" params "id" (uv-num id) "jsonrpc" "2.0"))

(defun json-rpc-reply (result)
  "Core JSONRPCReplyObj(result, null, 1, V2): a success reply."
  (uv-obj "jsonrpc" "2.0" "result" result "id" (uv-num 1)))

(defun process-batch-reply (in)
  "Core JSONRPCProcessBatchReply (rpc/request.cpp:179-197): the members of the
batch array placed by their id; a slot no member names stays :NULL."
  (unless (and (consp in) (eq (car in) :arr))
    (cli-error "Batch must be an array"))
  (let ((batch (make-array (length (cdr in)) :initial-element :null)))
    (dolist (rec (cdr in) batch)
      (unless (and (consp rec) (eq (car rec) :obj))
        (cli-error "Batch member must be an object"))
      (let ((id (uv-get-int (uv-get rec "id"))))
        (unless (< -1 id (length batch))
          (cli-error "Batch member id is larger than batch size"))
        (setf (aref batch id) rec)))))

;;; --- The default handler ---

(defclass default-handler () ())

(defmethod prepare-request ((h default-handler) method args)
  (json-rpc-request method
                    (if (cli-bool-arg "named" nil)
                        (rpc-convert-named-values method args)
                        (rpc-convert-values method args))
                    1))

(defmethod process-reply ((h default-handler) reply)
  (%uv-expect reply :obj)
  reply)

;;; --- -generate (GenerateToAddressRequestHandler) ---

(defclass generate-handler ()
  ((address :initform nil :accessor generate-address)))

(defmethod prepare-request ((h generate-handler) method args)
  (declare (ignore method))
  (setf (generate-address h) (second args))
  (json-rpc-request "generatetoaddress" (rpc-convert-values "generatetoaddress" args) 1))

(defmethod process-reply ((h generate-handler) reply)
  (%uv-expect reply :obj)
  (json-rpc-reply (uv-obj "address" (generate-address h)
                          "blocks" (uv-get reply "result"))))

;;; --- -addrinfo (AddrinfoRequestHandler) ---

(defparameter *networks*
  #("not_publicly_routable" "ipv4" "ipv6" "onion" "i2p" "cjdns" "internal")
  "Core NETWORKS (bitcoin-cli.cpp:62), GetNetworkName's names by id.")

(defparameter *network-short-names*
  #("npr" "ipv4" "ipv6" "onion" "i2p" "cjdns" "int"))

(defun network-id (name) (position name *networks* :test #'string=))

(defclass addrinfo-handler () ())

(defmethod prepare-request ((h addrinfo-handler) method args)
  (declare (ignore method))
  (when args (cli-error "-addrinfo takes no arguments"))
  (json-rpc-request "getnodeaddresses" (rpc-convert-values "getnodeaddresses" '("0")) 1))

(defmethod process-reply ((h addrinfo-handler) reply)
  (if (not (uv-null-p (uv-get reply "error")))
      reply
      (let ((nodes (uv-values (uv-get reply "result")))
            (counts (make-array (length *networks*) :initial-element 0)))
        (when (and nodes (uv-null-p (uv-get (first nodes) "network")))
          (cli-error "-addrinfo requires bitcoind server to be running v22.0 and up"))
        (dolist (node nodes)
          (let ((id (network-id (uv-get-str (uv-get node "network")))))
            (when id (incf (aref counts id)))))
        (let ((middle (loop for i from 1 below (1- (length *networks*)) collect i)))
          (json-rpc-reply
           (uv-obj "addresses_known"
                   (cons :obj
                         (append (loop for i in middle
                                       collect (cons (aref *networks* i) (uv-num (aref counts i))))
                                 (list (cons "total"
                                             (uv-num (loop for i in middle
                                                           sum (aref counts i)))))))))))))

;;; --- -getinfo (GetinfoRequestHandler) ---

(defclass getinfo-handler () ())

(defmethod prepare-request ((h getinfo-handler) method args)
  (declare (ignore method))
  (when args (cli-error "-getinfo takes no arguments"))
  (uv-arr (json-rpc-request "getnetworkinfo" :null 0)
          (json-rpc-request "getblockchaininfo" :null 1)
          (json-rpc-request "getwalletinfo" :null 2)
          (json-rpc-request "getbalances" :null 3)))

(defmethod process-reply ((h getinfo-handler) batch-in)
  (let* ((batch (process-batch-reply batch-in))
         (net (uv-get (aref batch 0) "result"))
         (chain (uv-get (aref batch 1) "result"))
         (wallet (uv-get (aref batch 2) "result"))
         (balances (uv-get (aref batch 3) "result")))
    ;; Errors in the first two are fatal; the wallet calls may fail when there
    ;; is no wallet (bitcoin-cli.cpp:338-345).
    (cond ((not (uv-null-p (uv-get (aref batch 0) "error"))) (aref batch 0))
          ((not (uv-null-p (uv-get (aref batch 1) "error"))) (aref batch 1))
          (t
           (json-rpc-reply
            (cons :obj
                  (append
                   (list (cons "version" (uv-get net "version"))
                         (cons "blocks" (uv-get chain "blocks"))
                         (cons "headers" (uv-get chain "headers"))
                         (cons "verificationprogress" (uv-get chain "verificationprogress"))
                         (cons "timeoffset" (uv-get net "timeoffset"))
                         (cons "connections" (uv-obj "in" (uv-get net "connections_in")
                                                     "out" (uv-get net "connections_out")
                                                     "total" (uv-get net "connections")))
                         (cons "networks" (uv-get net "networks"))
                         (cons "difficulty" (uv-get chain "difficulty"))
                         (cons "chain" (uv-get chain "chain")))
                   (unless (uv-null-p wallet)
                     (append (list (cons "has_wallet" :true)
                                   (cons "keypoolsize" (uv-get wallet "keypoolsize"))
                                   (cons "walletname" (uv-get wallet "walletname")))
                             (unless (uv-null-p (uv-get wallet "unlocked_until"))
                               (list (cons "unlocked_until" (uv-get wallet "unlocked_until"))))))
                   (unless (uv-null-p balances)
                     (list (cons "balance" (uv-get (uv-get balances "mine") "trusted"))))
                   (list (cons "relayfee" (uv-get net "relayfee"))
                         (cons "warnings" (uv-get net "warnings"))))))))))

(defun %progress-bar (progress)
  "Core GetProgressBar: a 5% step bar of U+2592 filled and U+2591 empty cells."
  (if (or (< progress 0) (> progress 1))
      ""
      (with-output-to-string (out)
        (loop for i from 0 while (< i (/ progress 0.05d0)) do (write-char (code-char #x2592) out))
        (loop for i from 0 while (< i (/ (- 1 progress) 0.05d0)) do (write-char (code-char #x2591) out)))))

(defun %getinfo-colors (colorize)
  (if colorize
      (flet ((esc (n) (format nil "~C[~Am" (code-char 27) n)))
        (list :reset (esc 0) :green (esc 32) :blue (esc 34) :yellow (esc 33)
              :magenta (esc 35) :cyan (esc 36)))
      (list :reset "" :green "" :blue "" :yellow "" :magenta "" :cyan "")))

(defun %getinfo-colorize-p ()
  "Core ParseGetInfoResult's -color rule: colour when stdout is a terminal
unless -color says otherwise; an unknown value is an error."
  (let ((color (cli-arg "color" "auto")))
    (cond ((string= color "always") t)
          ((string= color "never") nil)
          ((string= color "auto") (stdout-terminal-p))
          (t (cli-error "Invalid value for -color option. Valid values: always, auto, never.")))))

(defun stdout-terminal-p ()
  (ignore-errors (interactive-stream-p sb-sys:*stdout*)))

(defun %getinfo-proxies (networks)
  "The Proxies line: each distinct proxy in first-seen order, with the
networks it serves."
  (let ((order nil) (table nil))
    (dolist (network (if (uv-null-p networks) nil (uv-values networks)))
      (let ((proxy (uv-val-str (uv-get network "proxy"))))
        (when (plusp (length proxy))
          (unless (assoc proxy table :test #'string=)
            (push proxy order)
            (push (list proxy) table))
          (push (uv-val-str (uv-get network "name"))
                (cdr (assoc proxy table :test #'string=))))))
    (if order
        (format nil "~{~A~^, ~}"
                (loop for proxy in (nreverse order)
                      collect (format nil "~A (~{~A~^, ~})" proxy
                                      (reverse (cdr (assoc proxy table :test #'string=))))))
        "n/a")))

(defun %getinfo-wallet-lines (result c out)
  (unless (uv-null-p (uv-get result "has_wallet"))
    (let ((name (uv-val-str (uv-get result "walletname"))))
      (format out "~AWallet: ~A~A~%" (getf c :magenta) (if (string= name "") "\"\"" name) (getf c :reset)))
    (format out "Keypool size: ~A~%" (uv-val-str (uv-get result "keypoolsize")))
    (unless (uv-null-p (uv-get result "unlocked_until"))
      (format out "Unlocked until: ~A~%" (uv-val-str (uv-get result "unlocked_until")))))
  (unless (uv-null-p (uv-get result "balance"))
    (format out "~ABalance:~A ~A~%~%" (getf c :cyan) (getf c :reset)
            (uv-val-str (uv-get result "balance"))))
  (let ((balances (uv-get result "balances")))
    (unless (uv-null-p balances)
      (format out "~ABalances~A~%" (getf c :cyan) (getf c :reset))
      (let ((width (reduce #'max (mapcar (lambda (k) (length (uv-val-str (uv-get balances k))))
                                         (uv-keys balances))
                           :initial-value 10)))
        (dolist (wallet (uv-keys balances))
          (format out "~v@A ~A~%" width (uv-val-str (uv-get balances wallet))
                  (if (string= wallet "") "\"\"" wallet))))
      (terpri out))))

(defun parse-getinfo-result (result)
  "Core ParseGetInfoResult (bitcoin-cli.cpp:1062-1178): the -getinfo object as
the human-readable text bitcoin-cli prints. RESULT is returned as it is when
it carries an error."
  (if (not (uv-null-p (uv-get result "error")))
      result
      (let* ((c (%getinfo-colors (%getinfo-colorize-p)))
             (progress (uv-get-real (uv-get result "verificationprogress")))
             (bar (if (< progress 0.99d0) (concatenate 'string (%progress-bar progress) " ") ""))
             (conns (uv-get result "connections"))
             (warnings (uv-val-str (uv-get result "warnings"))))
        (with-output-to-string (out)
          (format out "~AChain: ~A~A~%" (getf c :blue) (uv-val-str (uv-get result "chain")) (getf c :reset))
          (format out "Blocks: ~A~%" (uv-val-str (uv-get result "blocks")))
          (format out "Headers: ~A~%" (uv-val-str (uv-get result "headers")))
          (format out "Verification progress: ~A~,4F%~%" bar (* progress 100))
          (format out "Difficulty: ~A~%~%" (uv-val-str (uv-get result "difficulty")))
          (format out "~ANetwork: in ~A, out ~A, total ~A~A~%" (getf c :green)
                  (uv-val-str (uv-get conns "in")) (uv-val-str (uv-get conns "out"))
                  (uv-val-str (uv-get conns "total")) (getf c :reset))
          (format out "Version: ~A~%" (uv-val-str (uv-get result "version")))
          (format out "Time offset (s): ~A~%" (uv-val-str (uv-get result "timeoffset")))
          (format out "Proxies: ~A~%" (%getinfo-proxies (uv-get result "networks")))
          (format out "Min tx relay fee rate (BTC/kvB): ~A~%~%" (uv-val-str (uv-get result "relayfee")))
          (%getinfo-wallet-lines result c out)
          (format out "~AWarnings:~A ~A" (getf c :yellow) (getf c :reset)
                  (if (string= warnings "") "(none)" warnings))))))
