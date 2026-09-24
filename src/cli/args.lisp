(in-package #:bitcoin-lisp.cli)

;;;; bitcoin-cli's options, its config file and its chain
;;;; (Core bitcoin-cli.cpp SetupCliArgs / AppInitRPC, common/args.cpp
;;;; ParseParameters, common/config.cpp ReadConfigFiles)
;;;
;;; The client reads the SAME bitcoin.conf the node reads, through the same
;;; ArgsManager, but with its own option table: every node option in the file
;;; is an unknown key to it and is dropped (ReadConfigFiles is called with
;;; ignore_invalid_keys=true), while an unknown option on ITS command line is
;;; a hard `Invalid parameter'. The config layer's parsers do the reading and
;;; the merging here, run over this table by binding bl.cfg:*config-options*
;;; -- the node's table is never touched, so a node option cannot leak into
;;; the client or the client's -rpcwait into the node.

(defparameter *cli-option-names*
  '("?" "h" "help" "version" "conf" "datadir" "generate" "addrinfo" "getinfo"
    "netinfo" "chain" "regtest" "testactivationheight" "testnet" "testnet4"
    "vbparams" "signet" "signetchallenge" "signetseednode" "color" "named"
    "rpcclienttimeout" "rpcconnect" "rpccookiefile" "rpcpassword" "rpcport"
    "rpcuser" "rpcwait" "rpcwaittimeout" "rpcwallet" "stdin" "stdinrpcpass"
    "stdinwalletpassphrase")
  "Every option SetupCliArgs registers (bitcoin-cli.cpp:73-119), with
SetupHelpOptions' -help/-h/-? and SetupChainParamsBaseOptions' chain options
 (chainparamsbase.cpp:14-26). -includeconf is NOT among them, so the client
drops an includeconf line like any other node key and reads one file.")

(defparameter *cli-disallow-negation*
  '("datadir" "signetchallenge" "signetseednode" "color" "rpcwaittimeout")
  "The options registered with ArgsManager::DISALLOW_NEGATION.")

(defparameter *cli-network-only* '("rpcport")
  "The options registered with ArgsManager::NETWORK_ONLY: -rpcport alone
 (bitcoin-cli.cpp:111), so a default-section rpcport= is ignored off mainnet.")

(defparameter *cli-commands* '("addrinfo" "generate" "getinfo" "netinfo")
  "OptionsCategory::CLI_COMMANDS, in the std::map order CheckMultipleCLIArgs
lists them in.")

(defun %cli-option-table ()
  (loop for name in *cli-option-names*
        collect (bl.cfg:make-config-option
                 :name name :network-only (and (member name *cli-network-only*
                                                       :test #'string=)
                                               t))))

(define-condition cli-init-error (error)
  ((message :initarg :message :reader cli-init-error-message))
  (:report (lambda (c s) (write-string (cli-init-error-message c) s)))
  (:documentation "An AppInitRPC failure: MESSAGE is the whole line Core
prints to stderr before returning EXIT_FAILURE."))

(defun %init-error (fmt &rest args)
  (error 'cli-init-error :message (apply #'format nil fmt args)))

;;; --- The command line (Core ArgsManager::ParseParameters) ---

(defun %switch-p (arg) (and (plusp (length arg)) (char= (char arg 0) #\-)))

(defun parse-cli-command-line (args)
  "Core ParseParameters over ARGS (argv without the program name). Returns
 (VALUES rows command-args): ROWS are the settings rows (name string-value
json) of the options, COMMAND-ARGS what CommandLineRPC reads after skipping
every leading switch. The options end at the first token that is not a switch
or at a lone `-'. Keys are case-sensitive and lose one or two leading dashes,
as off WIN32 in Core; an unknown key, a `section.' key or a forbidden
negation is Core's error text."
  (let ((rows nil))
    (loop for arg in args
          until (or (string= arg "-") (not (%switch-p arg)))
          do (let* ((eq-pos (position #\= arg))
                    (key (subseq arg 0 eq-pos))
                    (value (and eq-pos (subseq arg (1+ eq-pos)))))
               (when (and (> (length key) 1) (char= (char key 1) #\-))
                 (setf key (subseq key 1)))
               (setf key (subseq key 1))
               (multiple-value-bind (name string-value json section)
                   (bl.cfg:interpret-arg key value)
                 (unless (and (string= section "")
                              (member name *cli-option-names* :test #'string=))
                   (%init-error "Error parsing command line arguments: Invalid parameter ~A" arg))
                 (when (and (string= json "false")
                            (member name *cli-disallow-negation* :test #'string=))
                   (%init-error "Error parsing command line arguments: Negating of -~A is meaningless and therefore forbidden" name))
                 (push (list name string-value json) rows))))
    (values (nreverse rows) (member-if-not #'%switch-p args))))

;;; --- The merged settings the client reads ---

(defvar *cli-settings* nil
  "The merged (name . value) alist of the running invocation.")

(defvar *cli-negated* nil
  "The names Core's IsArgNegated answers T for.")

(defvar *cli-network* :mainnet
  "The chain the invocation selected (Core BaseParams()).")

(defvar *cli-datadir* nil
  "The base data directory, a directory pathname.")

(defvar *cli-config-path* nil
  "The config file ReadConfigFiles resolved, or NIL under -noconf.")

(defun %merge (sources)
  (let ((bl.cfg:*config-options* (%cli-option-table)))
    (bl.cfg:merged-config-alist sources *cli-network*)))

(defun cli-arg (name &optional default)
  "Core GetArg: the winning value of NAME, or DEFAULT."
  (let ((cell (assoc name *cli-settings* :test #'string=)))
    (if cell (cdr cell) default)))

(defun cli-arg-set-p (name)
  "Core IsArgSet: NAME has a value or a negation."
  (and (assoc name *cli-settings* :test #'string=) t))

(defun cli-arg-negated-p (name)
  (and (member name *cli-negated* :test #'string=) t))

(defun cli-bool-arg (name default)
  "Core GetBoolArg."
  (let ((v (cli-arg name)))
    (if v (bl.cfg:conf-parse-bool v) default)))

(defun cli-int-arg (name default)
  "Core GetIntArg: LocaleIndependentAtoi of the value."
  (let ((v (cli-arg name)))
    (if v (bl.cfg:locale-independent-atoi v) default)))

;;; --- Data directory and config file (Core common/args.cpp, config.cpp) ---


(defun %datadir-arg ()
  (let ((d (cli-arg "datadir")))
    (and d (plusp (length d)) d)))

(defun %check-datadir (format-string)
  "Core CheckDataDirOption: a named -datadir must be an existing directory."
  (let ((d (%datadir-arg)))
    (when (and d (not (uiop:directory-exists-p
                          (uiop:parse-native-namestring d :ensure-directory t))))
      (%init-error format-string d))))

(defun %base-datadir ()
  (uiop:ensure-directory-pathname
   (let ((d (%datadir-arg)))
     (if d
         (merge-pathnames (uiop:parse-native-namestring d :ensure-directory t)
                          (uiop:getcwd))
         ;; The node's own default (BL.CFG:DEFAULT-DATA-DIRECTORY), so a
         ;; client with no -datadir finds the node's cookie.
         (bl.cfg:default-data-directory)))))

(defun %net-datadir ()
  "Core GetDataDirNet: the base data directory plus the chain's subdirectory."
  (let ((sub (bl.chain:chain-params-data-subdirectory
              (bl.chain:find-chain-params *cli-network*))))
    (if sub (merge-pathnames sub *cli-datadir*) *cli-datadir*)))

(defun %cli-abs-path (path net-specific)
  "Core AbsPathForConfigVal: an absolute PATH as it is, a relative one joined
onto the base or the network data directory."
  (if (uiop:absolute-pathname-p (uiop:parse-native-namestring path))
      (uiop:parse-native-namestring path)
      (merge-pathnames (uiop:parse-native-namestring path) (if net-specific (%net-datadir) *cli-datadir*))))

(defun %config-rows ()
  "Core ReadConfigFiles' file half for the client: the rows of bitcoin.conf
 (or -conf), keys the client does not know dropped. NIL when there is no
file to read."
  (setf *cli-config-path*
        (unless (cli-arg-negated-p "conf")
          (let ((conf (cli-arg "conf")))
            (%cli-abs-path (if (and conf (plusp (length conf))) conf "bitcoin.conf")
                                      nil))))
  (let ((path *cli-config-path*))
    (when path
      (when (uiop:directory-exists-p (uiop:ensure-directory-pathname path))
        (%init-error "Error reading configuration file: Config file \"~A\" is a directory."
                     (namestring path)))
      (cond ((probe-file path)
             (let ((rows (handler-case (bl.cfg:conf-settings-rows
                                        (uiop:read-file-string path))
                           (bl.cfg:config-parse-error (e)
                             (%init-error "~A" e)))))
               (dolist (row rows)
                 ;; IsConfSupported (config.cpp:79-83) runs before the key is
                 ;; looked up, so `conf=' is refused though -conf is known.
                 (when (string= (second row) "conf")
                   (%init-error "Error reading configuration file: conf cannot be set in the configuration file; use includeconf= if you want to include additional config files")))
               (remove-if-not (lambda (row) (member (second row) *cli-option-names*
                                                    :test #'string=))
                              rows)))
            ((cli-arg-set-p "conf")
             (%init-error "Error reading configuration file: specified config file \"~A\" could not be opened."
                          (namestring path)))))))

(defun %resolve-chain (cli-rows conf-rows)
  "Core GetChainType: the chain selectors on the command line and in the
config file's DEFAULT section only (args.cpp:825-829)."
  (let ((alist (append (reverse (loop for (name value) in cli-rows collect (cons name value)))
                       (loop for (section name value) in conf-rows
                             when (string= section "") collect (cons name value)))))
    (handler-case (bl.cfg:resolve-network-from-config alist)
      (bl.err:config-error (e) (%init-error "Error: ~A" e)))))

(defun load-cli-settings (cli-rows)
  "AppInitRPC after the help check: the datadir check, ReadConfigFiles and
SelectBaseParams, in Core's order and words. Sets the *CLI-...* specials."
  (setf *cli-network* :mainnet
        *cli-settings* (%merge (list (cons :command-line cli-rows))))
  (%check-datadir "Error: Specified data directory \"~A\" does not exist.")
  (setf *cli-datadir* (%base-datadir))
  (let* ((conf-rows (%config-rows))
         (network (%resolve-chain cli-rows conf-rows))
         (want (bl.chain:chain-params-core-name (bl.chain:find-chain-params network))))
    (flet ((of-section (name)
             (loop for (section . row) in conf-rows
                   when (string= section name) collect row)))
      (setf *cli-network* network)
      (multiple-value-bind (merged negated)
          (%merge (list (cons :command-line cli-rows)
                        (cons :network-section (of-section want))
                        (cons :default-section (of-section ""))))
        (setf *cli-settings* merged *cli-negated* negated))
      ;; A datadir= line in the file moves the data directory (config.cpp:216-221).
      (%check-datadir "Error reading configuration file: specified data directory \"~A\" does not exist.")
      (setf *cli-datadir* (%base-datadir)))))

(defun read-auth-cookie ()
  "Core GetAuthCookie (rpc/request.cpp:148-165): (VALUES user:pass ok-p).
-norpccookiefile is success with no credentials; a missing file is failure;
otherwise the file's first line."
  (if (cli-arg-negated-p "rpccookiefile")
      (values "" t)
      (let* ((arg (cli-arg "rpccookiefile"))
             (path (%cli-abs-path (if (and arg (plusp (length arg))) arg ".cookie")
                                             t)))
        (if (and (probe-file path)
                 (not (uiop:directory-exists-p (uiop:ensure-directory-pathname path))))
            (with-open-file (in path :external-format :utf-8)
              (values (or (read-line in nil nil) "") t))
            (values "" nil)))))

(defparameter *cli-help-options*
  (format nil "~{~A~%~}"
          '("Options:"
            ""
            "  -?"
            "       Print this help message and exit (also -h or -?)"
            ""
            "  -color=<when>"
            "       Color setting for CLI output (default: auto). Valid values: always, auto"
            "       (add color codes when standard output is connected to a terminal and OS"
            "       is not WIN32), never. Only applies to the output of -getinfo."
            ""
            "  -conf=<file>"
            "       Specify configuration file. Relative paths will be prefixed by datadir"
            "       location. (default: bitcoin.conf)"
            ""
            "  -datadir=<dir>"
            "       Specify data directory"
            ""
            "  -named"
            "       Pass named instead of positional arguments (default: false)"
            ""
            "  -rpcclienttimeout=<n>"
            "       Timeout in seconds during HTTP requests, or 0 for no timeout. (default: 900)"
            ""
            "  -rpcconnect=<ip>"
            "       Send commands to node running on <ip> (default: 127.0.0.1)"
            ""
            "  -rpccookiefile=<loc>"
            "       Location of the auth cookie. Relative paths will be prefixed by a"
            "       net-specific datadir location. (default: data dir)"
            ""
            "  -rpcpassword=<pw>"
            "       Password for JSON-RPC connections"
            ""
            "  -rpcport=<port>"
            "       Connect to JSON-RPC on <port> (default: 8332, testnet: 18332, testnet4:"
            "       48332, signet: 38332, regtest: 18443)"
            ""
            "  -rpcuser=<user>"
            "       Username for JSON-RPC connections"
            ""
            "  -rpcwait"
            "       Wait for RPC server to start"
            ""
            "  -rpcwaittimeout=<n>"
            "       Timeout in seconds to wait for the RPC server to start, or 0 for no"
            "       timeout. (default: 0)"
            ""
            "  -rpcwallet=<walletname>"
            "       Send RPC for non-default wallet on RPC server (needs to exactly match"
            "       corresponding -wallet option passed to bitcoind). This changes the RPC"
            "       endpoint used, e.g. http://127.0.0.1:8332/wallet/<walletname>"
            ""
            "  -stdin"
            "       Read extra arguments from standard input, one per line until EOF/Ctrl-D"
            "       (recommended for sensitive information such as passphrases). When"
            "       combined with -stdinrpcpass, the first line from standard input is used"
            "       for the RPC password."
            ""
            "  -stdinrpcpass"
            "       Read RPC password from standard input as a single line. When combined"
            "       with -stdin, the first line from standard input is used for the RPC"
            "       password. When combined with -stdinwalletpassphrase, -stdinrpcpass"
            "       consumes the first line, and -stdinwalletpassphrase consumes the second."
            ""
            "  -stdinwalletpassphrase"
            "       Read wallet passphrase from standard input as a single line. When"
            "       combined with -stdin, the first line from standard input is used for the"
            "       wallet passphrase."
            ""
            "  -version"
            "       Print version and exit"
            ""
            "Chain selection options:"
            ""
            "  -chain=<chain>"
            "       Use the chain <chain> (default: main). Allowed values: main, test,"
            "       testnet4, signet, regtest"
            ""
            "  -signet"
            "       Use the signet chain. Equivalent to -chain=signet."
            ""
            "  -testnet"
            "       Use the testnet3 chain. Equivalent to -chain=test."
            ""
            "  -testnet4"
            "       Use the testnet4 chain. Equivalent to -chain=testnet4."
            ""
            "CLI Commands:"
            ""
            "  -addrinfo"
            "       Get the number of addresses known to the node, per network and total,"
            "       after filtering for quality and recency."
            ""
            "  -generate"
            "       Generate blocks, equivalent to RPC getnewaddress followed by RPC"
            "       generatetoaddress. Optional positional integer arguments are number of"
            "       blocks to generate (default: 1) and maximum iterations to try (default:"
            "       1000000). Example: bitcoin-cli -generate 4 1000"
            ""
            "  -getinfo"
            "       Get general information from the remote server."
            ""
            "  -netinfo"
            "       Get network peer connection information from the remote server. An"
            "       optional argument from 0 to 4 can be passed for different peers"
            "       listings (default: 0). Pass \"help\" (or \"h\") for detailed help"
            "       documentation."))
  "The option listing -help prints after the usage (Core GetHelpMessage over
SetupCliArgs' table, abridged to the options a user reaches for).")
