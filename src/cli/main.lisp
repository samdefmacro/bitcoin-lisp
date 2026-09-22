(in-package #:bitcoin-lisp.cli)

;;;; bitcoin-cli's main (Core bitcoin-cli.cpp CallRPC, ConnectAndCallRPC,
;;;; CommandLineRPC, AppInitRPC, MAIN_FUNCTION)
;;;
;;; RUN-CLI is the whole program as a function of argv and stdin: it returns
;;; what goes to stdout, what goes to stderr and the exit status, and CLI-MAIN
;;; only writes them out. The exit status is Core's: 0, EXIT_FAILURE (1) for
;;; every client-side error, and the ABSOLUTE VALUE of the RPC error code for
;;; a reply that carries one -- which the framework reads back from stderr
;;; (`error code: -8' / `error message:'), not from the status.

(define-condition cli-connection-failed (error)
  ((message :initarg :message :reader cli-connection-failed-message))
  (:report (lambda (c s) (write-string (cli-connection-failed-message c) s)))
  (:documentation "Core CConnectionFailed: no reply, or the server still in
warmup. The one failure -rpcwait retries."))

(defconstant +rpc-in-warmup+ -28)
(defconstant +rpc-wallet-not-specified+ -19)
(defconstant +default-http-client-timeout+ 900)

(defun %to-uint16 (s)
  "Core ToIntegral<uint16_t>: all digits (a sign is not a digit) and in range."
  (and (plusp (length s)) (every #'digit-char-p s)
       (let ((n (parse-integer s))) (and (<= n 65535) n))))

(defun split-rpc-host-port (in)
  "Core SplitHostPort (util/strencodings.cpp:72-96): (VALUES host port valid-p).
A `:' is a port separator when it follows `]' or is the only one; the port
must be 1..65535, and PORT is 0 when there was none."
  (let* ((colon (position #\: in :from-end t))
         (bracketed (and colon (plusp colon) (char= (char in 0) #\[)
                         (char= (char in (1- colon)) #\])))
         (multi (and colon (plusp colon) (position #\: in :end colon)))
         (port 0) (valid nil))
    (if (and colon (or (zerop colon) bracketed (not multi)))
        (let ((n (%to-uint16 (subseq in (1+ colon)))))
          (when n
            (setf in (subseq in 0 colon) port n valid (/= n 0))))
        (setf valid t))
    (values (if (and (plusp (length in)) (char= (char in 0) #\[)
                     (char= (char in (1- (length in))) #\]))
                (subseq in 1 (1- (length in)))
                in)
            port valid)))

(defun %rpc-host-port ()
  "CallRPC's port preference (bitcoin-cli.cpp:797-834): -rpcport, then a port
in -rpcconnect, then the chain's default. (VALUES host port warning)."
  (let ((port (bl.chain:network-rpc-port *cli-network*))
        (connect (cli-arg "rpcconnect" "127.0.0.1"))
        (warning nil))
    (multiple-value-bind (host connect-port valid) (split-rpc-host-port connect)
      (unless valid (cli-error "Invalid port provided in -rpcconnect: ~A" connect))
      (when (/= connect-port 0) (setf port connect-port))
      (let ((rpcport (cli-arg "rpcport")))
        (when rpcport
          (let ((n (or (%to-uint16 rpcport) 0)))
            (when (zerop n) (cli-error "Invalid port provided in -rpcport: ~A" rpcport))
            (setf port n)
            (when (/= connect-port 0)
              (setf warning (format nil "Warning: Port specified in both -rpcconnect and -rpcport. Using -rpcport ~D" port))))))
      (values host port warning))))

(defvar *cli-stderr-prefix* nil
  "Lines CallRPC writes to stderr on its own (the -rpcport warning), in order.")

(defun %check-http-status (status body failed-cookie)
  (cond ((= status 401)
         (if failed-cookie
             (cli-error "Could not locate RPC credentials. No authentication cookie could be found, and RPC password is not set.  See -rpcpassword and -stdinrpcpass.  Configuration file: (~A)"
                    (if *cli-config-path* (uiop:native-namestring *cli-config-path*) ""))
             (cli-error "Authorization failed: Incorrect rpcuser or rpcpassword")))
        ((= status 503) (cli-error "Server response: ~A" body))
        ((and (>= status 400) (not (member status '(400 404 500))))
         (cli-error "server returned HTTP error ~D" status))
        ((string= body "") (cli-error "no response from server"))))

(defun call-rpc (handler method args &optional wallet)
  "Core CallRPC: one HTTP exchange, its failures in Core's words, and the
HANDLER's reply."
  (multiple-value-bind (host port warning) (%rpc-host-port)
    (when warning (push warning *cli-stderr-prefix*))
    (let* ((timeout (cli-int-arg "rpcclienttimeout" +default-http-client-timeout+))
           (failed-cookie nil)
           (userpass (if (string= (cli-arg "rpcpassword" "") "")
                         (multiple-value-bind (cookie ok) (read-auth-cookie)
                           (unless ok (setf failed-cookie t))
                           cookie)
                         (format nil "~A:~A" (cli-arg "rpcuser" "") (cli-arg "rpcpassword" ""))))
           (request (format nil "~A~%" (uv-write (prepare-request handler method args))))
           (endpoint (if wallet (format nil "/wallet/~A" (uri-encode wallet)) "/")))
      (multiple-value-bind (status body)
          (handler-case
              (funcall *cli-transport* host port endpoint
                       (list (cons "Connection" "close")
                             (cons "Content-Type" "application/json")
                             (cons "Authorization"
                                   (format nil "Basic ~A"
                                           (cl-base64:usb8-array-to-base64-string
                                            (sb-ext:string-to-octets userpass :external-format :utf-8)))))
                       request (and (plusp timeout) timeout))
            (cli-transport-failure (e)
              (let ((code (cli-transport-failure-code e)))
                (error 'cli-connection-failed
                       :message (format nil "Could not connect to the server ~A:~D~@[ (error code ~D - \"~A\")~]~%~%Make sure the bitcoind server is running and that you are connecting to the correct RPC port.~%Use \"bitcoin-cli -help\" for more info."
                                        host port (and (/= code -1) code) (http-error-string code))))))
        (%check-http-status status body failed-cookie)
        (let ((reply (handler-case (uv-read body)
                       (json-parse-failure () (cli-error "couldn't parse reply from server")))))
          (process-reply handler reply))))))

(defun connect-and-call-rpc (handler method args &optional wallet)
  "Core ConnectAndCallRPC: CALL-RPC, retried every second under -rpcwait while
the server cannot be reached or is warming up, until -rpcwaittimeout (0 is
forever). A connection failure that ends the attempt is reported as a
`timeout on transient error', with or without -rpcwait, as in Core."
  (let* ((wait (cli-bool-arg "rpcwait" nil))
         (timeout (cli-int-arg "rpcwaittimeout" 0))
         (deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second))))
    (loop
      (handler-case
          (let ((response (call-rpc handler method args wallet)))
            (when wait
              (let ((err (uv-get response "error")))
                (when (and (not (uv-null-p err))
                           (eql (ignore-errors (uv-get-int (uv-get err "code"))) +rpc-in-warmup+))
                  (error 'cli-connection-failed :message "server in warmup"))))
            (return response))
        (cli-connection-failed (e)
          (if (and wait (or (<= timeout 0) (< (get-internal-real-time) deadline)))
              (sleep 1)
              (cli-error "timeout on transient error: ~A" (cli-connection-failed-message e))))))))

(defun parse-error-reply (err)
  "Core ParseError: (VALUES text exit-code) for an RPC error object."
  (if (and (consp err) (eq (car err) :obj))
      (let ((code (uv-get err "code"))
            (msg (uv-get err "message")))
        (values (with-output-to-string (out)
                  (unless (uv-null-p code)
                    (format out "error code: ~A~%" (uv-val-str code)))
                  (when (stringp msg)
                    (format out "error message:~%~A" msg))
                  (when (and (eq (%uv-type code) :num)
                             (eql (ignore-errors (uv-get-int code)) +rpc-wallet-not-specified+))
                    (write-string " Or for the CLI, specify the \"-rpcwallet=<walletname>\" option before the command (run \"bitcoin-cli -h\" for help or \"bitcoin-cli listwallets\" to see which wallets are currently loaded)." out)))
                (abs (uv-get-int code))))
      (values (format nil "error: ~A" (uv-write err))
              (abs (uv-get-int (uv-get err "code"))))))

(defun rpc-wallet-name ()
  "Core RpcWalletName: -rpcwallet, or NIL when absent or negated."
  (unless (cli-arg-negated-p "rpcwallet") (cli-arg "rpcwallet")))

(defun get-wallet-balances (result)
  "Core GetWalletBalances: with more than one wallet loaded, each one's
trusted balance appended to the -getinfo RESULT under \"balances\"."
  (let* ((h (make-instance 'default-handler))
         (listwallets (connect-and-call-rpc h "listwallets" nil)))
    (if (or (not (uv-null-p (uv-get listwallets "error")))
            (<= (length (uv-values (uv-get listwallets "result"))) 1))
        result
        (append result
                (list (cons "balances"
                            (cons :obj
                                  (loop for name in (uv-values (uv-get listwallets "result"))
                                        collect (cons name
                                                      (uv-get (uv-get (uv-get (connect-and-call-rpc h "getbalances" nil name)
                                                                              "result")
                                                                      "mine")
                                                              "trusted"))))))))))

(defun set-generate-to-address-args (address args)
  "Core SetGenerateToAddressArgs: nblocks and maxtries around ADDRESS."
  (when (> (length args) 2) (cli-error "too many arguments (maximum 2 for nblocks and maxtries)"))
  (cond ((null args) (setf args (list "1")))
        ((string= (first args) "0")
         (cli-error "the first argument (number of blocks to generate, default: 1) must be an integer value greater than zero")))
  (list* (first args) address (rest args)))

(defun %read-stdin-line (stdin what)
  (or (read-line stdin nil nil)
      (cli-error "~A specified but failed to read from standard input" what)))

(defun %command-args (args stdin)
  "The -stdinrpcpass / -stdinwalletpassphrase / -stdin half of CommandLineRPC."
  (when (cli-bool-arg "stdinrpcpass" nil)
    (push (cons "rpcpassword" (%read-stdin-line stdin "-stdinrpcpass")) *cli-settings*))
  (when (cli-bool-arg "stdinwalletpassphrase" nil)
    (unless (and args (uiop:string-prefix-p "walletpassphrase" (first args)))
      (cli-error "-stdinwalletpassphrase is only applicable for walletpassphrase(change)"))
    (setf args (list* (first args) (%read-stdin-line stdin "-stdinwalletpassphrase") (rest args))))
  (when (cli-bool-arg "stdin" nil)
    (setf args (append args (loop for line = (read-line stdin nil nil) while line collect line))))
  args)

(defun %check-multiple-cli-commands ()
  "Core CheckMultipleCLIArgs."
  (let ((found (remove-if-not #'cli-arg-set-p *cli-commands*)))
    (when (> (length found) 1)
      (cli-error "Only one of ~{-~A~^, ~} may be specified." found))))

(defun command-line-rpc (args stdin)
  "Core CommandLineRPC: (VALUES text exit-code); TEXT goes to stdout on 0 and
to stderr otherwise."
  (handler-case
      (let ((args (%command-args args stdin))
            (handler nil) (method nil))
        (%check-multiple-cli-commands)
        (cond ((cli-bool-arg "getinfo" nil) (setf handler (make-instance 'getinfo-handler)))
              ((cli-bool-arg "netinfo" nil)
               (when (and args (member (first args) '("h" "help") :test #'string=))
                 (return-from command-line-rpc (values *netinfo-help* 0)))
               (setf handler (make-instance 'netinfo-handler)))
              ((cli-bool-arg "generate" nil)
               (let* ((reply (connect-and-call-rpc (make-instance 'default-handler)
                                                   "getnewaddress" nil (rpc-wallet-name)))
                      (err (uv-get reply "error")))
                 (unless (uv-null-p err)
                   (return-from command-line-rpc (parse-error-reply err)))
                 (setf args (set-generate-to-address-args (uv-get-str (uv-get reply "result")) args)
                       handler (make-instance 'generate-handler))))
              ((cli-bool-arg "addrinfo" nil) (setf handler (make-instance 'addrinfo-handler)))
              (t (setf handler (make-instance 'default-handler))
                 (unless args (cli-error "too few parameters (need at least command)"))
                 (setf method (pop args))))
        (let* ((wallet (rpc-wallet-name))
               (reply (connect-and-call-rpc handler method args wallet))
               (result (uv-get reply "result"))
               (err (uv-get reply "error")))
          (if (uv-null-p err)
              (progn
                (when (cli-bool-arg "getinfo" nil)
                  (unless wallet (setf result (get-wallet-balances result)))
                  (setf result (parse-getinfo-result result)))
                (values (cond ((uv-null-p result) "")
                              ((stringp result) result)
                              (t (uv-write result 2)))
                        0))
              (parse-error-reply err))))
    (error (e) (values (format nil "error: ~A" e) 1))))

;;; --- AppInitRPC and main ---

(defun %usage-text ()
  (format nil "~A RPC client version v~A~%~%~
The bitcoin-cli utility provides a command line interface to interact with a ~A RPC server.~%~%~
It can be used to query network information, manage wallets, create or broadcast transactions, and control the ~A server.~%~%~
Use the \"help\" command to list all commands. Use \"help <command>\" to show help for that command.~%~
The -named option allows you to specify parameters using the key=value format, eliminating the need to pass unused positional parameters.~%~%~
Usage: bitcoin-cli [options] <command> [params]~%~
or:    bitcoin-cli [options] -named <command> [name=value]...~%~
or:    bitcoin-cli [options] help~%~
or:    bitcoin-cli [options] help <command>~%~%~%~A"
          bl.cfg:+client-name+ (bl.ser:client-version-string)
          bl.cfg:+client-name+ bl.cfg:+client-name+ *cli-help-options*))

(defun %version-text ()
  (format nil "~A RPC client version v~A~%Copyright (C) 2009-2026 The Bitcoin Core developers and the ~A authors~%~%~
Please contribute if you find ~A useful. Visit <https://github.com/samdefmacro/bitcoin-lisp> for further information about the software.~%~%~
This is experimental software.~%~
Distributed under the MIT software license, see the accompanying file COPYING or <https://opensource.org/license/MIT>~%"
          bl.cfg:+client-name+ (bl.ser:client-version-string) bl.cfg:+client-name+
          bl.cfg:+client-name+))

(defun run-cli (args &key (stdin (make-string-input-stream "")))
  "The whole of bitcoin-cli for ARGS (argv without the program name), reading
STDIN: (VALUES stdout-text stderr-text exit-code), each text complete with its
final newline."
  (let ((*cli-settings* nil) (*cli-negated* nil) (*cli-network* :mainnet)
        (*cli-datadir* nil) (*cli-config-path* nil) (*cli-stderr-prefix* nil))
    (handler-case
        (multiple-value-bind (rows command-args) (parse-cli-command-line args)
          (setf *cli-settings* (%merge (list (cons :command-line rows))))
          (when (or (null args)
                    (some #'cli-arg-set-p '("?" "h" "help"))
                    (cli-bool-arg "version" nil))
            (return-from run-cli
              (values (if (cli-bool-arg "version" nil) (%version-text) (%usage-text))
                      (if args "" (format nil "Error: too few parameters~%"))
                      (if args 0 1))))
          (load-cli-settings rows)
          (multiple-value-bind (text code) (command-line-rpc command-args stdin)
            (let ((stderr-lines (format nil "~{~A~%~}" (reverse *cli-stderr-prefix*))))
              (cond ((string= text "") (values "" stderr-lines code))
                    ((zerop code) (values (format nil "~A~%" text) stderr-lines code))
                    (t (values "" (format nil "~A~A~%" stderr-lines text) code))))))
      (cli-init-error (e) (values "" (format nil "~A~%" e) 1)))))

(defun cli-main ()
  "Toplevel of bitcoin-cli: RUN-CLI over the process's argv and stdin, its
texts written out and its code the exit status."
  (sb-ext:disable-debugger)
  (multiple-value-bind (out err code)
      (handler-case (run-cli (rest sb-ext:*posix-argv*) :stdin *standard-input*)
        (error (e) (values "" (format nil "EXCEPTION: ~A~%" e) 1)))
    (write-string out *standard-output*)
    (finish-output *standard-output*)
    (write-string err *error-output*)
    (finish-output *error-output*)
    (sb-ext:exit :code code :abort t)))

(defun cli-program-name-p (argv0)
  "T when ARGV0, the name the process was started under, is bitcoin-cli: the
node executable is linked into build/bin under both of Core's names, and this
is how it knows which program it is (NODE-MAIN)."
  (let ((slash (position #\/ argv0 :from-end t)))
    (string= (if slash (subseq argv0 (1+ slash)) argv0) "bitcoin-cli")))
