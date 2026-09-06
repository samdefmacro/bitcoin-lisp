(in-package #:bitcoin-lisp)

;; A (re)load of this file rebuilds the whole table in file order: order is
;; load-bearing (a later alias wins the scalar scan; APPLY-OPTION-GLOBALS
;; walks it), and a row deleted from the file must not linger in the image.
(setf *config-options* '())

;;;; The option table (Core ArgsManager::AddArg, init.cpp / common/args.cpp)
;;;
;;; One DEFINE-OPTION per option bitcoind accepts; the mechanism and the
;;; questions the table answers are in src/config/registry.lisp. Rows with
;;; :KEY / :COLLECT feed start-node keywords; rows with :GLOBAL / :APPLY set
;;; process-global specials from APPLY-CONFIG-GLOBALS; :KIND :SELECTOR rows
;;; are consumed by the network / entry-point logic and :CORE-ONLY rows
;;; nowhere. Options whose effect depends on ANOTHER option (Core init.cpp
;;; Step 2 "parameter interactions") keep their present-case row here and
;;; their soft-set / consistency half in APPLY-PARAMETER-INTERACTIONS.

;;; A row marked :NETWORK-ONLY carries Core's ArgsManager::NETWORK_ONLY flag:
;;; a value in a shared bitcoin.conf's DEFAULT section is ignored off mainnet
;;; and, if it is the only place the option is set, the node refuses to start
;;; (init.cpp:944-951). bitcoind registers exactly eight -- -addnode
;;; (init.cpp:539), -bind (:548), -connect (:550), -port (:575), -rpcbind
;;; (:708), -rpcport (:713), -wallet and -walletdir (wallet/init.cpp:71,73).

;;; A row marked :SENSITIVE carries Core's ArgsManager::SENSITIVE flag: the
;;; VALUE is a secret, so the startup arg log prints `****` in its place
;;; (logArgsPrefix, common/args.cpp:883). bitcoind tags exactly four --
;;; -torpassword (init.cpp:602), -rpcauth (:707), -rpcpassword (:712) and
;;; -rpcuser (:716); nothing else in the tree, the wallet included. Tagging
;;; more is not free: feature_config_args.py asserts that -rpcbind and
;;; -rpcallowip are logged UNMASKED.

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
;; -blocksdir: the volume the blk/rev/xor bulk goes on (Core
;; ArgsManager::GetBlocksDirPath, common/args.cpp:286-309). The block INDEX
;; stays in the datadir, as Core's does (init.cpp:1140).
(define-option "blocksdir" :key :blocks-directory :type :string)
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
(define-option "rpcport" :key :rpc-port :type :int :network-only t)
(define-option "rpcbind" :key :rpc-bind :type :string :network-only t)
(define-option "rpcuser" :key :rpc-user :type :string :sensitive t)
(define-option "rpcpassword" :key :rpc-password :type :string :sensitive t)
;; -rpcwhitelistdefault: what a user named by no -rpcwhitelist may call. Core
;; reads it with GetBoolArg and DEFAULTS it to "any -rpcwhitelist was given"
;; (httprpc.cpp:306), so the absent case is not the same as =0 -- START-NODE
;; keeps them apart with an :UNSET default and START-RPC-SERVER derives it.
(define-option "rpcwhitelistdefault" :key :rpc-whitelist-default :type :bool)
(define-option "listen" :key :listen :type :bool)
;; -bind is scanned for its LAST occurrence into :listen-bind (the single
;; address we actually bind); every occurrence is also kept, so a multi-bind
;; command line is reported rather than silently reduced
;; (CONFIG-ALIST->START-NODE-PLIST re-derives the address from all of them).
(define-option "bind" :key :listen-bind :type :string :repeatable t :network-only t)
(define-option "listenonion" :key :listen-onion :type :bool)
(define-option "torcontrol" :key :tor-control :type :string)
(define-option "torpassword" :key :tor-password :type :string :sensitive t)
(define-option "v2transport" :key :v2transport :type :bool)
;; -checkblocks / -checklevel: how much of the block database VerifyDB
;; compares against the UTXO set at startup (Core init.cpp:1388-1389, read
;; with GetIntArg, defaults DEFAULT_CHECKBLOCKS 6 and DEFAULT_CHECKLEVEL 3).
;; Left unset they take those defaults; SET, either of them also makes Core's
;; require_full_verification true, so a run that had to skip level 3 for want
;; of dbcache is a startup failure instead of a warning.
(define-option "checkblocks" :key :check-blocks :type :int)
(define-option "checklevel" :key :check-level :type :int)
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
(define-option "port" :key :port :type :int :network-only t)
(define-option "networkactive" :key :network-active :type :bool)
(define-option "rest" :key :rest :type :bool)
(define-option "blocksonly" :key :blocksonly :type :bool)
;; -persistmempool: Core ShouldPersistMempool (node/mempool_persist_args.cpp:13,
;; DEFAULT_PERSIST_MEMPOOL = true) gates BOTH the startup replay and the
;; shutdown dump. -persistmempoolv1 selects the older version-1 dump layout
;; (node/mempool_args.cpp:106). Start-node keywords rather than :GLOBAL rows so
;; an omitted option restores the default on every start.
(define-option "persistmempool" :key :persist-mempool :type :bool)
(define-option "persistmempoolv1" :key :persist-mempool-v1 :type :bool)
(define-option "acceptstalefeeestimates" :key :accept-stale-fee-estimates :type :bool)
(define-option "sync" :key :sync :type :bool)

;;; --- Repeatable start-node options (Core GetArgs: every occurrence) -------
;;; Each is validated where it is used, not here.

;; -addnode (m_added_node_params, init.cpp:2107).
(define-option "addnode" :collect :addnode :repeatable t :network-only t)
;; -rpcauth (g_rpcauth, httprpc.cpp:289), -rpcallowip (rpc_allow_subnets,
;; httpserver.cpp:153).
(define-option "rpcauth" :collect :rpc-auth :repeatable t :sensitive t)
(define-option "rpcallowip" :collect :rpc-allow-ip :repeatable t)
;; -rpcwhitelist=<user>:<method>,... (g_rpc_whitelist, httprpc.cpp:307-325):
;; read with GetArgs, and Core INTERSECTS the specs given for one user, so
;; every occurrence has to reach the server. It is not SENSITIVE in Core (only
;; -rpcauth, -rpcuser, -rpcpassword and -torpassword are), and it names no
;; per-chain resource, so it is not NETWORK-ONLY either.
(define-option "rpcwhitelist" :collect :rpc-whitelist :repeatable t)
(define-option "testactivationheight" :collect :test-activation-heights :repeatable t)
;; -vbparams=deployment:start:end[:min_activation_height]: Core reads it with
;; GetArgs, so every occurrence counts and the last one for a deployment wins
;; (chainparams.cpp:68-106). Regtest only -- ReadRegTestArgs is called for no
;; other chain -- and parsed in %INIT-PARAMETERS, which knows the network.
(define-option "vbparams" :collect :vbparams :repeatable t)
;; -test=<option>: Core reads it with GetArgs, so it is a LIST, and every
;; value is a separate test-only switch (common/args.cpp:743-747
;; TEST_OPTIONS_DOC). Regtest only; validated in %INIT-PARAMETERS, which
;; knows the network.
(define-option "test" :collect :test-options :repeatable t)
;; -debug: categories; also raises the log level (see the plist assembly).
(define-option "debug" :collect :debug-categories :repeatable t)
(define-option "debugexclude" :collect :debug-exclude :repeatable t)
;; -shrinkdebugfile: whether the log file is scrolled to its last 10 MB at
;; startup (Core init/common.cpp:108-113). Its DEFAULT is derived from
;; -debug -- DefaultShrinkDebugFile() is `m_categories == BCLog::NONE'
;; (logging.cpp:167-170) -- so START-NODE has to tell "not given" from "=0";
;; the keyword defaults to :UNSET and %INIT-LOGGING derives the rest.
(define-option "shrinkdebugfile" :key :shrink-debug-file :type :bool)
;; Core reads both with GetArgs, so every occurrence runs (init.cpp:257-265
;; joins them all).
(define-option "shutdownnotify" :collect :shutdown-notify :repeatable t)
(define-option "startupnotify" :collect :startup-notify :repeatable t)
;; -connect: Core reads it with GetArgs and dials every one as a MANUAL
;; connection (net.cpp ThreadOpenConnections).
(define-option "connect" :collect :connect-nodes :repeatable t :network-only t)
;; -seednode: Core reads it with GetArgs into connOptions.vSeedNodes
;; (init.cpp:2212).
(define-option "seednode" :collect :seednode :repeatable t)
;; -loadblock: every file is imported, in the order given (init.cpp:2022,
;; ImportBlocks).
(define-option "loadblock" :collect :load-block :repeatable t)
;; -wallet=<name>: every name is loaded at startup, alongside the ones
;; settings.json records (wallet/load.cpp:81, chain.getSettingsList).
(define-option "wallet" :collect :wallet-names :repeatable t :network-only t)
;; -whitelist / -whitebind: Core reads both with GetArgs (init.cpp).
(define-option "whitelist" :collect :whitelist :repeatable t)
(define-option "whitebind" :collect :whitebind :repeatable t)

;;; --- Process-global options -----------------------------------------------
;;; Applied by APPLY-CONFIG-GLOBALS: a :GLOBAL row sets its special to the
;;; parsed value when the option is present; an :APPLY row's function gets
;;; the parsed value (the raw string without a :TYPE). PARSE-OPTION-VALUE
;;; owns the shared error texts ("Invalid amount for -x=v", "Invalid value
;;; for -x=v (must be a positive integer)"); a row whose text Core words
;;; differently keeps its own. The RPC and wallet knobs at the end are read
;;; by name in START-NODE-FROM-ARGS.

(define-option "datacarrier" :type :bool :global *accept-datacarrier*)
(define-option "datacarriersize" :type :int :global *max-datacarrier-bytes*)
(define-option "permitbaremultisig" :type :bool :global *permit-bare-multisig*)
;; Cluster mempool limits: -limitclustercount (transactions, hard-capped at
;; 64) and -limitclustersize (kvB) bound every connected component of
;; unconfirmed transactions (Core mempool_args.cpp:35-37 + the cap check at
;; :110-112, init.cpp:658-659). Read by make-mempool, which is created after
;; this runs at startup.
(define-option "limitclustercount" :type :int
  :apply (lambda (n)
           (unless (<= 1 n 64)
             (config-error "limitclustercount must be between 1 and 64"))
           (setf bl.mp:*cluster-count-limit* n)))
(define-option "limitclustersize" :type :int
  :apply (lambda (kvb)
           (unless (plusp kvb)
             (config-error "limitclustersize must be a positive number of kvB"))
           (setf bl.mp:*cluster-size-limit* (* kvb 1000))))
;; -signetchallenge: a custom signet block-challenge script, and
;; -signetseednode: the DNS/peer seeds that REPLACE the chain's own
;; (Core reads it with GetArgs, so it is a list -- chainparams.cpp:27-29).
;; Both are consumed by APPLY-PARAMETER-INTERACTIONS, which instantiates the
;; :signet chain from them the way Core's SigNetParams constructor does; the
;; challenge also lands here because the block-solution check reads it.
(define-option "signetchallenge" :type :hex :global bl.val:*signet-challenge*)
(define-option "signetseednode" :repeatable t)
;; -proxy / -onion / -proxyrandomize / -onlynet / -cjdnsreachable form one
;; interaction (each reads the others): APPLY-PARAMETER-INTERACTIONS.
(define-option "proxy")
(define-option "onion")
(define-option "proxyrandomize")
(define-option "onlynet" :repeatable t)
(define-option "cjdnsreachable")
;; -assumevalid: a block hash (up to 64 hex digits, Core FromUserHex
;; left-pads) below which block scripts are assumed valid, or 0 to disable
;; the skip entirely (Core chainstatemanager_args.cpp:40-46). Stored in WIRE
;; byte order (the block-index key form).
(define-option "assumevalid"
  :apply (lambda (v)
           (let ((display (conf-parse-user-hex v)))
             (unless display
               (config-error "Invalid assumevalid block hash specified (~A), must be up to 64 hex digits (or 0 to disable)" v))
             (setf *assumevalid-override*
                   (if (every #'zerop display)
                       nil                     ; assumevalid=0: always verify
                       (bl.crypto:reverse-bytes display))))))
;; -minimumchainwork: hex work floor overriding the per-network
;; nMinimumChainWork (Core chainstatemanager_args.cpp:32-38).
(define-option "minimumchainwork"
  :apply (lambda (v)
           (let ((display (conf-parse-user-hex v)))
             (unless display
               (config-error "Invalid minimum work specified (~A), must be up to 64 hex digits" v))
             (setf *minimum-chain-work-override*
                   (loop with acc = 0
                         for b across display
                         do (setf acc (+ (ash acc 8) b))
                         finally (return acc))))))
;; -mempoolexpiry: hours before an untouched mempool entry is dropped (Core
;; mempool_args.cpp:57, default DEFAULT_MEMPOOL_EXPIRY_HOURS 336).
(define-option "mempoolexpiry" :type :int :global bl.mp:*mempool-expiry-hours*)
;; -maxmempool: megabytes of mempool MEMORY usage (Core mempool_args.cpp,
;; DEFAULT_MAX_MEMPOOL_SIZE_MB = 300). Read by make-mempool. Under
;; -blocksonly Core soft-sets it to 5 MB -- the absent case, in
;; APPLY-PARAMETER-INTERACTIONS.
(define-option "maxmempool"
  :apply (lambda (v)
           (let ((mb (conf-parse-int v)))
             (when (minusp mb)
               (config-error "Invalid value for -maxmempool=~A" v))
             (setf bl.mp:*max-mempool-bytes* (* mb 1000 1000)))))
;; -minrelaytxfee: BTC/kvB (Core ParseMoney, mempool_args.cpp:69-81). Read
;; at MAKE-MEMPOOL time like the cluster limits.
(define-option "minrelaytxfee" :type :money :global bl.mp:*min-relay-fee-rate*)
;; -blockmintxfee: BTC/kvB floor for block-template selection (Core
;; miner.cpp:102-104, default DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB).
(define-option "blockmintxfee" :type :money :global bl.mining:*block-min-tx-fee-rate*)
;; -blockmaxweight / -blockreservedweight: block-template SELECTION budgets
;; (Core init.cpp:1079-1093). Neither relaxes consensus -- a block we build
;; is still validated against +max-block-weight+ like any other -- so the
;; only checks are Core's: never above the consensus maximum, and never
;; reserve less than MINIMUM_BLOCK_RESERVED_WEIGHT, which could not fit a
;; header plus a realistic coinbase.
(define-option "blockmaxweight" :type :int
  :apply (lambda (w)
           (when (> w bl.val:+max-block-weight+)
             (config-error "Specified -blockmaxweight (~D) exceeds consensus maximum block weight (~D)"
                    w bl.val:+max-block-weight+))
           (setf bl.mining:*block-max-weight* w)))
(define-option "blockreservedweight" :type :int
  :apply (lambda (w)
           (when (> w bl.val:+max-block-weight+)
             (config-error "Specified -blockreservedweight (~D) exceeds consensus maximum block weight (~D)"
                    w bl.val:+max-block-weight+))
           (when (< w bl.mining:+minimum-block-reserved-weight+)
             (config-error "Specified -blockreservedweight (~D) is lower than minimum safety value of (~D)"
                    w bl.mining:+minimum-block-reserved-weight+))
           (setf bl.mining:*block-reserved-weight* w)))
;; -blockversion: override the template's computed nVersion. Core reads it
;; with GetIntArg inside CreateNewBlock and applies it on MineBlocksOnDemand()
;; chains only (node/miner.cpp:141-145), so the value is stored here and the
;; regtest gate lives at the use site, as Core's does.
(define-option "blockversion" :type :int :global bl.mining:*block-version-override*)
;; -maxtxfee: BTC, absolute cap on any wallet tx fee (Core init: BTC via
;; ParseMoney, default DEFAULT_TRANSACTION_MAXFEE = 0.1 BTC).
(define-option "maxtxfee" :type :money :global *wallet-max-tx-fee*)
;; -fallbackfee: BTC/kvB used when fee estimation has no data (Core
;; wallet.cpp:3005-3014); 0 keeps the fallback disabled.
(define-option "fallbackfee" :type :money :global *wallet-fallback-fee*)
;; -bantime: default setban duration in seconds (Core banman.h:19
;; DEFAULT_MISBEHAVING_BANTIME = 86400, applied when setban gets no time).
(define-option "bantime" :type :int :global bl.net:*default-ban-time-seconds*)
;; -uacomment (repeatable): BIP14 subversion comments. Unsafe characters or
;; an over-long result are init ERRORS (Core init.cpp:1676-1686).
(define-option "uacomment" :repeatable t
  :apply (lambda (comments)
           (dolist (cmt comments)
             (unless (ua-comment-safe-p cmt)
               (config-error "User Agent comment (~A) contains unsafe characters." cmt)))
           (when comments
             (let ((subversion (bl.ser:subversion-with-build-rev comments)))
               (when (> (length subversion) +max-subversion-length+)
                 (config-error "Total length of network version string (~D) exceeds maximum length (~D). Reduce the number or size of uacomments."
                        (length subversion) +max-subversion-length+))
               (setf bl.ser:*user-agent* subversion)))))
;; -dustrelayfee: BTC/kvB below which an output is dust (Core
;; DUST_RELAY_TX_FEE). Relay policy, not consensus, which is why the value it
;; sets is a DEFPARAMETER rather than a DEFCONSTANT.
(define-option "dustrelayfee" :type :money :global bl.val:*dust-relay-fee-rate*)
;; -incrementalrelayfee: BTC/kvB a replacement must beat the original by
;; (Core DEFAULT_INCREMENTAL_RELAY_FEE).
(define-option "incrementalrelayfee" :type :money :global bl.mp:*incremental-relay-fee-rate*)
;; -bytespersigop: equivalent bytes charged per weighted sigop (Core
;; DEFAULT_BYTES_PER_SIGOP, policy.h:49).
(define-option "bytespersigop" :type :int :min 1 :global bl.mp:*bytes-per-sigop*)
;; -maxtipage: how old the tip may be before the node still calls itself in
;; IBD (Core DEFAULT_MAX_TIP_AGE, kernel/chainstatemanager_opts.h:24).
(define-option "maxtipage" :type :int :min 0 :global bl.net:*max-tip-age-seconds*)
;; -maxsigcachesize: MiB of signature cache (Core's knob is bytes split
;; across two caches; ours is one, counted in ENTRIES). A cache entry is a
;; 32-byte key, which is what Core's CuckooCache element is too, so the
;; conversion is bytes/32 -- the real heap cost is higher because a Lisp hash
;; table is not a cuckoo table, and the option is a bound on entries rather
;; than a promise about memory.
(define-option "maxsigcachesize" :type :int :min 1
  :apply (lambda (n)
           (setf bl.interop:*signature-cache-max-entries*
                 (max 1 (floor (* n 1024 1024) 32)))))
;; -fastprune: tiny block files so a pruning test can produce many of them
;; without mining a real chain (Core blockstorage.cpp:857-862). Test-only.
(define-option "fastprune" :type :bool :global bl.store:*fast-prune*)
;; -blocksxor: obfuscate blocksdir contents (Core DEFAULT_XOR_BLOCKSDIR).
(define-option "blocksxor" :type :bool :global bl.store:*blocks-xor*)
;; -peertimeout: seconds a peer has to complete the version handshake (Core
;; DEFAULT_PEER_CONNECT_TIMEOUT, net.h:87).
(define-option "peertimeout" :type :int :min 1 :global *handshake-timeout-seconds*)
;; -maxsendbuffer: per-connection cap on buffered unsent bytes. Core's value
;; is in KILOBYTES and it multiplies by 1000, not 1024 (init.cpp:2105,
;; DEFAULT_MAXSENDBUFFER = 1000 -> 1,000,000 bytes).
(define-option "maxsendbuffer" :type :int :min 1
  :apply (lambda (n) (setf bl.net:*max-send-buffer-bytes* (* n 1000))))
;; -maxuploadtarget: the 24h outbound budget. Core parses it with
;; ParseByteUnits defaulting to M, so a bare number is MEBIbytes -- reading it
;; as bytes would silence the option on every ordinary command line.
(define-option "maxuploadtarget" :type :byte-units :global bl.net:*max-upload-target*)
;; RPC server and wallet knobs, read by name in START-NODE-FROM-ARGS.
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
;; -walletcrosschain: allow loading a wallet whose stored best-block locator
;; belongs to a DIFFERENT chain (Core wallet/init.cpp:82,
;; DEFAULT_WALLETCROSSCHAIN = false). Accepting and ignoring it made us behave
;; as if it were permanently on.
(define-option "walletcrosschain")
;; -allowignoredconf: downgrade the shadowed-bitcoin.conf refusal
;; (CHECK-IGNORED-CONFIG-FILE, Core common/init.cpp:65-95) to a warning. Read by
;; name in START-NODE-FROM-ARGS, like the RPC knobs above.
(define-option "allowignoredconf")
;; -walletbroadcast: Core fBroadcastTransactions (DEFAULT_WALLETBROADCAST =
;; true, wallet.cpp:3068). A start-node keyword rather than a :GLOBAL row so
;; every run starts from the default, and because -blocksonly soft-sets it in
;; CONFIG-ALIST->START-NODE-PLIST where the other soft-set keywords are decided.
(define-option "walletbroadcast" :key :wallet-broadcast :type :bool)
(define-option "keypool")
(define-option "walletdir" :network-only t)
(define-option "walletnotify")
;; -dnsseed / -fixedseeds: peer-discovery source gates (Core net.h:96-97).
;; -dnsseed's soft-set half (-connect, -maxconnections<=0, a -onlynet with
;; no clearnet) is in APPLY-PARAMETER-INTERACTIONS.
(define-option "dnsseed" :type :bool :global *dns-seed-enabled*)
(define-option "fixedseeds" :type :bool :global *fixed-seeds-enabled*)
;; -forcednsseed: query the DNS seeds even with a full address book. It does
;; NOT override -dnsseed=0, which is Core's precedence too.
(define-option "forcednsseed" :type :bool :global *force-dns-seed*)
;; -acceptnonstdtxn: relay and mine transactions this node would otherwise
;; refuse as non-standard. Core REFUSES TO START with it on a non-test chain
;; (mempool_args.cpp:102-104); an error here, not a warning, because a
;; mainnet node quietly relaying non-standard transactions has its
;; transactions dropped by every peer and does not find out.
(define-option "acceptnonstdtxn" :type :bool
  :apply (lambda (accept)
           (when (and accept (member *network* '(:mainnet)))
             (config-error "acceptnonstdtxn is not currently supported for ~(~A~) chain"
                    *network*))
           (setf bl.val:*require-standard* (not accept))))
;; -par: how many script-check worker threads. Core's semantics -- 0 means
;; one per core, a NEGATIVE value leaves that many cores free, and the
;; result is clamped to MAX_SCRIPTCHECK_THREADS. Reading the negative form
;; as an absolute value would oversubscribe the very box the operator asked
;; to leave headroom on.
(define-option "par" :type :int
  :apply (lambda (v)
           (let ((n (bl.val:parse-par-threads v)))
             (setf bl.val:*parallel-validation-workers* n)
             ;; Core: -par=1 means no extra threads at all.
             (setf *parallel-block-validation* (> n 1)))))
;; -whitelistrelay / -whitelistforcerelay (Core net_permissions.h:20-22).
(define-option "whitelistrelay" :type :bool :global bl.net:*whitelist-relay*)
(define-option "whitelistforcerelay" :type :bool :global bl.net:*whitelist-force-relay*)
;; -stopatheight: shut down once the tip reaches this height (Core
;; kernel_notifications.cpp:61-66).
(define-option "stopatheight" :type :int :global *stop-at-height*)
;; -externalip (repeatable): addresses to advertise as our own (Core
;; init.cpp:1803-1808, AddLocal LOCAL_MANUAL). Raw strings here; start-node
;; resolves them once the network (and thus the listen port) is known, and
;; errors on unparseable input like Core's ResolveErrMsg. Always applied, so
;; an absent option leaves an empty list, not a previous run's.
(define-option "externalip" :repeatable t
  :apply (lambda (ips) (setf bl.net:*external-ips* ips)))

;; -zmqpub<topic>[hwm]: collected by ZMQ-SPECS-FROM-CONFIG, since each topic
;; contributes two options and they produce a list of publishers rather than
;; a start-node keyword.
(dolist (topic '("hashblock" "hashtx" "rawblock" "rawtx" "sequence"))
  (register-config-option
   (make-config-option :name (format nil "zmqpub~A" topic) :kind :global))
  (register-config-option
   (make-config-option :name (format nil "zmqpub~Ahwm" topic) :kind :global)))

;;; --- Accepted, not implemented ---------------------------------------------
;;; Extracted from Core's AddArg registrations (init.cpp, common/args.cpp,
;;; init/common.cpp, chainparamsbase.cpp, the wallet/index/zmq/rpc modules).

(define-core-only-options
  "addresstype" "alertnotify"
  "avoidpartialspends" "blockreconstructionextratxn"
  "capturemessages"
  "changetype" "checkaddrman" "checkblockindex"
  "checkmempool" "checkpoints" "daemon"
  "daemonwait" "dbbatchsize" "deprecatedrpc"
  "discover" "dns"
  "help" "i2pacceptincoming" "i2psam"
  "ipcbind" "limitancestorcount" "limitancestorsize"
  "limitdescendantcount" "limitdescendantsize" "logips"
  "loglevelalways" "logsourcelocations"
  "logtimestamps" "maxreceivebuffer"
  "natpmp" "peerbloomfilters" "printpriority"
  "privatebroadcast" "rpcdoccheck"
  "rpcworkqueue"
  "signer"
  "stopafterblockimport" "timeout"
  "unsafesqlitesync"
  "version")
