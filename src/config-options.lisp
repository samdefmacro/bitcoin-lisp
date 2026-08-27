(in-package #:bitcoin-lisp)

;;;; The option table (Core ArgsManager::AddArg, init.cpp / common/args.cpp)
;;;
;;; One DEFINE-OPTION per option bitcoind accepts. The table answers the
;;; questions the rest of config.lisp used to answer from four separate
;;; lists that had drifted apart (two options were in two of them at once):
;;; is this name known at all (CHECK-CLI-ARGS), does every occurrence count
;;; (PARSE-CLI-ARGS, Core GetArgs), which start-node keyword does it feed
;;; and how is the value parsed (CONFIG-ALIST->START-NODE-PLIST), and is it
;;; accepted-but-unimplemented (SUPPLIED-CORE-ONLY-OPTIONS).
;;;
;;; :KEY is the start-node keyword a scalar option feeds (its LAST command
;;; line occurrence wins, Core GetArg); :COLLECT the keyword under which every
;;; occurrence is gathered into a list (Core GetArgs); :REPEATABLE says the
;;; parser must keep every occurrence at all. :KIND is where the value is
;;; consumed when it is not a start-node keyword: :GLOBAL by
;;; APPLY-CONFIG-GLOBALS or START-NODE-FROM-ARGS straight from the merged
;;; alist, :SELECTOR by the network / entry-point logic, :CORE-ONLY nowhere.

(defstruct (config-option (:constructor %make-config-option))
  (name "" :type string)
  (key nil :type (or null keyword))
  (type nil :type (or null keyword))       ; :string :bool :int :loglevel-global
  (collect nil :type (or null keyword))
  (repeatable nil :type boolean)
  (kind :start-node :type keyword)
  (core nil :type (or null string)))       ; Core reference, documentation only

(defparameter *config-options* '()
  "Every registered option, in definition order (the order the scalar scan
walks, which is what lets a later alias -- -debuglogfile after -logfile --
win when both are given). DEFPARAMETER, so reloading this file rebuilds the
list in file order; the in-place replacement in REGISTER-CONFIG-OPTION is
for a single re-evaluated form.")

(defun register-config-option (option)
  "Add OPTION to *CONFIG-OPTIONS*, replacing an earlier definition of the
same name in place so a warm reload never duplicates a row."
  (let ((cell (member (config-option-name option) *config-options*
                      :key #'config-option-name :test #'string=)))
    (if cell
        (setf (car cell) option)
        (setf *config-options* (append *config-options* (list option))))
    option))

(define-condition option-definition-error (program-error)
  ((name :initarg :name :reader option-definition-error-name)
   (detail :initarg :detail :reader option-definition-error-detail))
  (:report (lambda (c stream)
             (format stream "define-option ~A: ~A"
                     (option-definition-error-name c)
                     (option-definition-error-detail c))))
  (:documentation "A DEFINE-OPTION form that contradicts itself, signalled
at macroexpansion time."))

(defmacro define-option (name &key key type collect repeatable (kind nil kind-p) core)
  "Register the option NAME (lower-case, as it appears after the dash).
KEY/TYPE: the start-node keyword and value type of a scalar option; COLLECT:
the keyword under which every occurrence is listed (implies REPEATABLE);
KIND defaults to :START-NODE when KEY or COLLECT is given, :GLOBAL otherwise."
  (check-type name string)
  (when (and collect (not repeatable))
    (error 'option-definition-error :name name
                                    :detail "a :collect option must be :repeatable"))
  (when (and key (null type))
    (error 'option-definition-error :name name
                                    :detail "a :key option needs a :type"))
  `(register-config-option
    (%make-config-option :name ,name :key ,key :type ,type :collect ,collect
                         :repeatable ,(and repeatable t)
                         :kind ,(if kind-p kind (if (or key collect) :start-node :global))
                         :core ,core)))

(defmacro define-core-only-options (&rest names)
  "Register NAMES as options bitcoind accepts that this node recognises but
does NOT implement. They exist so an unknown-option HARD ERROR does not stop
a node started with an ordinary Core command line -- Core's functional test
framework passes -logtimemicros, -logthreadnames, -logsourcelocations,
-debugexclude and -loglevel to EVERY node it starts (test_node.py:68-108),
and 128 more flags across individual tests. Accepting is not implementing:
SUPPLIED-CORE-ONLY-OPTIONS reports which of these an operator actually
passed so startup can say so out loud."
  `(progn ,@(loop for n in names
                  collect `(define-option ,n :kind :core-only))))

(defun find-config-option (name)
  "The registered option called NAME (lower-case, no dashes), or NIL."
  (find name *config-options* :key #'config-option-name :test #'string=))

(defun config-option-repeatable-p (name)
  "T when every occurrence of NAME is meaningful (Core GetArgs list-options);
all other repeated command-line options collapse to their LAST occurrence
(Core GetArg on the command line takes span.end()[-1], settings.cpp:193 -- a
repeated config-FILE key instead keeps the FIRST, which parse-bitcoin-conf's
in-order alist gives assoc for free)."
  (let ((o (find-config-option name)))
    (and o (config-option-repeatable o))))

(defun core-only-option-p (name)
  "T when NAME is an option bitcoind accepts and we do not implement."
  (let ((o (find-config-option (string-downcase name))))
    (and o (eq (config-option-kind o) :core-only))))

(defun scalar-key-options ()
  "The options that feed a start-node keyword from their last occurrence, in
definition order."
  (remove-if-not #'config-option-key *config-options*))

(defun collected-key-options ()
  "The options whose every occurrence is listed under a start-node keyword."
  (remove-if-not #'config-option-collect *config-options*))

;;; --- Network selection and entry-point specials -------------------------
;;; Handled before and around the spec scan (RESOLVE-NETWORK-FROM-CONFIG,
;;; ARGS->START-NODE-PLIST, START-NODE-FROM-ARGS).

(define-option "regtest" :kind :selector)
(define-option "signet" :kind :selector)
(define-option "testnet4" :kind :selector)
(define-option "testnet" :kind :selector)
(define-option "chain" :kind :selector)
;; -server enables RPC on the network default port when no -rpcport is given.
(define-option "server" :kind :selector)
(define-option "conf" :kind :selector)
(define-option "includeconf" :kind :selector)
(define-option "settings" :kind :selector)

;;; --- Scalar start-node options (Core GetArg: last occurrence wins) --------

(define-option "datadir" :key :data-directory :type :string)
(define-option "txindex" :key :txindex :type :bool)
(define-option "blockfilterindex" :key :blockfilterindex :type :bool)
(define-option "coinstatsindex" :key :coinstatsindex :type :bool)
(define-option "txospenderindex" :key :txospenderindex :type :bool)
(define-option "prune" :key :prune :type :int)
(define-option "dbcache" :key :dbcache-mib :type :int)
;; Core's -mocktime: the startup form of the setmocktime RPC, for tests that
;; need a fixed clock before the first RPC can be made.
(define-option "mocktime" :key :mocktime :type :int)
(define-option "logtimemicros" :key :log-time-micros :type :bool)
;; -blocknotify: one command, %s replaced by the new best block's hash.
(define-option "blocknotify" :key :block-notify :type :string)
(define-option "logthreadnames" :key :log-thread-names :type :bool)
(define-option "maxconnections" :key :max-connections :type :int)
(define-option "rpcport" :key :rpc-port :type :int)
(define-option "rpcbind" :key :rpc-bind :type :string)
(define-option "rpcuser" :key :rpc-user :type :string)
(define-option "rpcpassword" :key :rpc-password :type :string)
(define-option "listen" :key :listen :type :bool)
;; -bind is scanned for its LAST occurrence into :listen-bind (the single
;; address we actually bind); every occurrence is also kept, so a multi-bind
;; command line is reported rather than silently reduced
;; (CONFIG-ALIST->START-NODE-PLIST re-derives the address from all of them).
(define-option "bind" :key :listen-bind :type :string :repeatable t)
(define-option "listenonion" :key :listen-onion :type :bool)
(define-option "torcontrol" :key :tor-control :type :string)
(define-option "torpassword" :key :tor-password :type :string)
(define-option "v2transport" :key :v2transport :type :bool)
(define-option "reindexchainstate" :key :reindex-chainstate :type :bool)
(define-option "reindex-chainstate" :key :reindex-chainstate :type :bool)
(define-option "forcecompactdb" :key :force-compact-db :type :bool)
(define-option "peerblockfilters" :key :peer-block-filters :type :bool)
(define-option "txreconciliation" :key :tx-reconciliation :type :bool)
(define-option "webui" :key :webui :type :bool)
(define-option "webuipath" :key :webui-path :type :string)
(define-option "webuiopen" :key :webui-open :type :bool)
;; -wallet is deliberately NOT a scalar :bool option. It is Core's list of
;; wallets to LOAD (read with GetArgs, wallet/load.cpp:81), collected into
;; :WALLET-NAMES; the subsystem switch is -disablewallet. As a :bool row,
;; `-nowallet` -- which Core defines as "load no wallets" -- turned the whole
;; wallet RPC surface off, and wallet_multiwallet.py starts a node with
;; exactly that and then calls wallet RPCs on it. Core's -disablewallet is
;; the negation of our -wallet; it is inverted where the plist is assembled,
;; since the spec scan has no notion of a flag that means the opposite of
;; its key.
(define-option "disablewallet" :key :disable-wallet :type :bool)
(define-option "logfile" :key :log-file :type :string)
;; -asmap=<file>: ASN-based netgroup bucketing. A relative path hangs off the
;; datadir, as Core's does.
(define-option "asmap" :key :asmap :type :string)
;; -migratedatadir: move a pre-Core datadir to Core's layout at startup,
;; before any database is opened. No Core counterpart -- Core has only ever
;; had this layout, so it has never needed a migration.
(define-option "migratedatadir" :key :migrate-datadir :type :bool)
;; -pid: a supervisor's handle on this process. -nopid parses to "0", which
;; PID-FILE-PATH reads as Core reads IsArgNegated.
(define-option "pid" :key :pid-file :type :string)
;; -printtoconsole: Core defaults it to (not -daemon); we never daemonize, so
;; ours defaults on and this is the way to turn it off.
(define-option "printtoconsole" :key :console-log :type :bool)
;; Core's own spelling of -logfile; -debuglogfile=0 disables it. Defined
;; after -logfile so it wins when both are given.
(define-option "debuglogfile" :key :log-file :type :string)
;; The SCALAR reading still feeds :LOG-LEVEL, the global threshold. It has to
;; tolerate the <category>:<level> form, which is not a global level at all
;; and is applied from :LOG-LEVEL-SPECS instead -- otherwise a bare
;; `-loglevel=net:debug` would be rejected as an invalid global level, which
;; is how this option was broken for that form entirely. Core reads it with
;; GetArgs, so a command line can carry a global level AND per-category ones
;; (init/common.cpp:62-75): every occurrence is also collected.
(define-option "loglevel" :key :log-level :type :loglevel-global
                          :collect :log-level-specs :repeatable t)
(define-option "logratelimit" :key :log-rate-limit :type :bool)
(define-option "flatblockfiles" :key :flat-block-files :type :bool)
(define-option "reindex" :key :reindex :type :bool)
(define-option "port" :key :port :type :int)
(define-option "networkactive" :key :network-active :type :bool)
(define-option "rest" :key :rest :type :bool)
(define-option "blocksonly" :key :blocksonly :type :bool)
(define-option "acceptstalefeeestimates" :key :accept-stale-fee-estimates :type :bool)
(define-option "sync" :key :sync :type :bool)

;;; --- Repeatable start-node options (Core GetArgs: every occurrence) -------
;;; Each is validated where it is used, not here.

;; -addnode (m_added_node_params, init.cpp:2107).
(define-option "addnode" :collect :addnode :repeatable t)
;; -rpcauth (g_rpcauth, httprpc.cpp:289), -rpcallowip (rpc_allow_subnets,
;; httpserver.cpp:153).
(define-option "rpcauth" :collect :rpc-auth :repeatable t)
(define-option "rpcallowip" :collect :rpc-allow-ip :repeatable t)
(define-option "testactivationheight" :collect :test-activation-heights :repeatable t)
;; -debug: categories; also raises the log level (see the plist assembly).
(define-option "debug" :collect :debug-categories :repeatable t)
(define-option "debugexclude" :collect :debug-exclude :repeatable t)
;; Core reads both with GetArgs, so every occurrence runs (init.cpp:257-265
;; joins them all).
(define-option "shutdownnotify" :collect :shutdown-notify :repeatable t)
(define-option "startupnotify" :collect :startup-notify :repeatable t)
;; -connect: Core reads it with GetArgs and dials every one as a MANUAL
;; connection (net.cpp ThreadOpenConnections).
(define-option "connect" :collect :connect-nodes :repeatable t)
;; -seednode: Core reads it with GetArgs into connOptions.vSeedNodes
;; (init.cpp:2212).
(define-option "seednode" :collect :seednode :repeatable t)
;; -loadblock: every file is imported, in the order given (init.cpp:2022,
;; ImportBlocks).
(define-option "loadblock" :collect :load-block :repeatable t)
;; -wallet=<name>: every name is loaded at startup, alongside the ones
;; settings.json records (wallet/load.cpp:81, chain.getSettingsList).
(define-option "wallet" :collect :wallet-names :repeatable t)
;; -whitelist / -whitebind: Core reads both with GetArgs (init.cpp).
(define-option "whitelist" :collect :whitelist :repeatable t)
(define-option "whitebind" :collect :whitebind :repeatable t)

;;; --- Process-global options -----------------------------------------------
;;; Read by name from the merged alist: APPLY-CONFIG-GLOBALS for the policy,
;;; consensus and networking specials, START-NODE-FROM-ARGS for the RPC and
;;; wallet knobs.

(define-option "datacarrier")
(define-option "datacarriersize")
(define-option "permitbaremultisig")
(define-option "limitclustercount")
(define-option "limitclustersize")
(define-option "signetchallenge")
(define-option "proxy")
(define-option "onion")
(define-option "proxyrandomize")
(define-option "onlynet" :repeatable t)
(define-option "cjdnsreachable")
(define-option "assumevalid")
(define-option "minimumchainwork")
(define-option "mempoolexpiry")
(define-option "maxmempool")
(define-option "minrelaytxfee")
(define-option "blockmintxfee")
(define-option "blockmaxweight")
(define-option "blockreservedweight")
(define-option "maxtxfee")
(define-option "fallbackfee")
(define-option "bantime")
(define-option "uacomment" :repeatable t)
(define-option "dustrelayfee")
(define-option "incrementalrelayfee")
(define-option "bytespersigop")
(define-option "maxtipage")
(define-option "maxsigcachesize")
(define-option "fastprune")
(define-option "blocksxor")
(define-option "peertimeout")
(define-option "maxsendbuffer")
(define-option "maxuploadtarget")
(define-option "rpccookiefile")
(define-option "rpccookieperms")
(define-option "rpcthreads")
(define-option "rpcservertimeout")
(define-option "mintxfee")
(define-option "discardfee")
(define-option "consolidatefeerate")
(define-option "maxapsfee")
(define-option "txconfirmtarget")
(define-option "walletrbf")
(define-option "spendzeroconfchange")
(define-option "walletrejectlongchains")
(define-option "keypool")
(define-option "walletdir")
(define-option "walletnotify")
(define-option "dnsseed")
(define-option "fixedseeds")
(define-option "forcednsseed")
(define-option "acceptnonstdtxn")
(define-option "par")
(define-option "whitelistrelay")
(define-option "whitelistforcerelay")
(define-option "stopatheight")
(define-option "externalip" :repeatable t)

;; -zmqpub<topic>[hwm]: collected by ZMQ-SPECS-FROM-CONFIG, since each topic
;; contributes two options and they produce a list of publishers rather than
;; a start-node keyword.
(dolist (topic '("hashblock" "hashtx" "rawblock" "rawtx" "sequence"))
  (register-config-option
   (%make-config-option :name (format nil "zmqpub~A" topic) :kind :global))
  (register-config-option
   (%make-config-option :name (format nil "zmqpub~Ahwm" topic) :kind :global)))

;;; --- Accepted, not implemented ---------------------------------------------
;;; Extracted from Core's AddArg registrations (init.cpp, common/args.cpp,
;;; init/common.cpp, chainparamsbase.cpp, the wallet/index/zmq/rpc modules).

(define-core-only-options
  "addresstype" "alertnotify" "allowignoredconf"
  "avoidpartialspends" "blockreconstructionextratxn"
  "blocksdir" "blockversion" "capturemessages"
  "changetype" "checkaddrman" "checkblockindex" "checkblocks" "checklevel"
  "checkmempool" "checkpoints" "daemon"
  "daemonwait" "dbbatchsize" "deprecatedrpc"
  "discover" "dns"
  "help" "i2pacceptincoming" "i2psam"
  "ipcbind" "limitancestorcount" "limitancestorsize"
  "limitdescendantcount" "limitdescendantsize" "logips"
  "loglevelalways" "logsourcelocations"
  "logtimestamps" "maxreceivebuffer"
  "natpmp" "peerbloomfilters" "persistmempool"
  "persistmempoolv1" "printpriority"
  "privatebroadcast" "rpcdoccheck"
  "rpcwhitelist" "rpcwhitelistdefault"
  "rpcworkqueue" "shrinkdebugfile"
  "signer" "signetseednode"
  "stopafterblockimport" "test" "timeout"
  "unsafesqlitesync" "vbparams"
  "version" "walletbroadcast" "walletcrosschain")
